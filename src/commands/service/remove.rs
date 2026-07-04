use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;
use bootroot::trust_bootstrap::remove_managed_profile_block;

use super::{
    MANAGED_PROFILE_BEGIN_PREFIX, MANAGED_PROFILE_END_PREFIX, OPENBAO_SERVICE_CONFIG_DIR,
    REMOTE_BOOTSTRAP_DIR, SERVICE_SECRET_DIR,
};
use crate::cli::args::ServiceRemoveArgs;
use crate::cli::prompt::Prompt;
use crate::commands::constants::SERVICE_KV_BASE;
use crate::commands::dns_alias::reconcile_dns_aliases;
use crate::commands::openbao_auth::{authenticate_openbao_client, resolve_runtime_auth};
use crate::commands::trust::SERVICE_TRUST_KV_SUFFIX;
use crate::i18n::Messages;
use crate::state::{DeliveryMode, ServiceEntry, StateFile};

/// KV path suffix for the per-service EAB material. Mirrors
/// `write_service_kv_secrets` in `service/secrets.rs`.
const KV_EAB_SUFFIX: &str = "eab";
/// KV path suffix for the per-service HTTP-01 responder HMAC.
const KV_HTTP_RESPONDER_HMAC_SUFFIX: &str = "http_responder_hmac";
/// KV path suffix for the per-service `secret_id` (written only for
/// `remote-bootstrap` services by `sync_service_kv_bundle`).
const KV_SECRET_ID_SUFFIX: &str = "secret_id";

/// On-disk artifacts eligible for deletion under `--delete-artifacts`.
struct ArtifactPlan {
    dirs: Vec<PathBuf>,
    files: Vec<PathBuf>,
    agent_config: PathBuf,
}

/// Tracks whether any resource in the teardown failed so the entry is
/// kept for a safe re-run.
#[derive(Default)]
struct TeardownReport {
    any_failed: bool,
}

impl TeardownReport {
    /// Prints and records the outcome of a single resource deletion.
    ///
    /// `Ok(true)` means the resource was removed, `Ok(false)` that it was
    /// already absent (idempotent re-run), and `Err` that the deletion
    /// failed — in which case the entry is retained.
    fn record(&mut self, label: &str, result: Result<bool>, messages: &Messages) {
        match result {
            Ok(true) => println!("{}", messages.service_remove_resource_removed(label)),
            Ok(false) => println!("{}", messages.service_remove_resource_absent(label)),
            Err(err) => {
                eprintln!(
                    "{}",
                    messages.service_remove_resource_failed(label, &err.to_string())
                );
                self.any_failed = true;
            }
        }
    }
}

/// Deregisters a service: tears down its `OpenBao` `AppRole`, policy, and
/// per-service KV paths, refreshes the responder's HTTP-01 alias set, and
/// finally removes the `state.json` entry.
pub(crate) async fn run_service_remove(
    args: &ServiceRemoveArgs,
    messages: &Messages,
) -> Result<()> {
    let state_path = StateFile::default_path();
    let mut state = load_state_or_missing(&state_path, messages)?;
    let entry = require_service_entry(&state, &args.service_name, messages)?;

    let kv_paths = service_kv_paths(&entry);
    let artifacts = if args.delete_artifacts {
        Some(build_artifact_plan(&state, &entry))
    } else {
        None
    };

    print_remove_plan(&entry, &kv_paths, artifacts.as_ref(), messages);

    if args.dry_run {
        println!("{}", messages.service_remove_dry_run());
        return Ok(());
    }

    if !args.yes {
        if !std::io::stdin().is_terminal() {
            anyhow::bail!(messages.service_remove_requires_yes(&args.service_name));
        }
        if !confirm_removal(&args.service_name, messages)? {
            println!("{}", messages.service_remove_aborted(&args.service_name));
            return Ok(());
        }
    }

    let auth = resolve_runtime_auth(&args.runtime_auth, true, messages)?;
    let mut client = OpenBaoClient::with_local_trust(&state.openbao_url, state.secrets_dir())
        .with_context(|| messages.error_openbao_client_create_failed())?;
    authenticate_openbao_client(&mut client, &auth, messages).await?;

    let mut report = TeardownReport::default();

    // Remote cleanup FIRST — the AppRole, policy, and KV deletions must
    // all complete before the state.json entry is dropped, so a partial
    // failure leaves the stored role/policy names available for a re-run.
    for path in &kv_paths {
        let result = delete_kv_if_present(&client, &state.kv_mount, path).await;
        report.record(&format!("KV {path}"), result, messages);
    }
    let approle_result = delete_approle_if_present(&client, &entry.approle.role_name).await;
    report.record(
        &format!("AppRole {}", entry.approle.role_name),
        approle_result,
        messages,
    );
    let policy_result = delete_policy_if_present(&client, &entry.approle.policy_name).await;
    report.record(
        &format!("policy {}", entry.approle.policy_name),
        policy_result,
        messages,
    );

    // On-disk artifacts (opt-in). These are local, but a failure here
    // also keeps the entry so a re-run can retry.
    if let Some(plan) = artifacts.as_ref() {
        for dir in &plan.dirs {
            let result = delete_dir_if_present(dir);
            report.record(&format!("directory {}", dir.display()), result, messages);
        }
        for file in &plan.files {
            let result = delete_file_if_present(file);
            report.record(&format!("file {}", file.display()), result, messages);
        }
        let strip_result = strip_managed_profile(&plan.agent_config, &entry.service_name);
        report.record(
            &format!("managed profile block in {}", plan.agent_config.display()),
            strip_result,
            messages,
        );
    }

    if report.any_failed {
        anyhow::bail!(messages.service_remove_partial_failure(&args.service_name));
    }

    // Everything torn down cleanly — now drop the entry LAST and persist.
    remove_entry_and_persist(&mut state, &state_path, &args.service_name, messages)?;

    // Refresh the responder's alias set from the post-removal state so
    // the removed service's HTTP-01 alias is dropped, even when the
    // resulting alias set is empty.
    reconcile_dns_aliases(&state, messages)?;

    println!("{}", messages.service_remove_success(&args.service_name));
    Ok(())
}

/// Loads `state.json`, bailing with `error_state_missing` when the file
/// is absent (mirrors `run_service_update`).
fn load_state_or_missing(state_path: &Path, messages: &Messages) -> Result<StateFile> {
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    StateFile::load(state_path).with_context(|| messages.error_parse_state_failed())
}

/// Returns a clone of the named service entry, bailing with
/// `error_service_not_found` when it is not registered.
fn require_service_entry(
    state: &StateFile,
    service_name: &str,
    messages: &Messages,
) -> Result<ServiceEntry> {
    state
        .services
        .get(service_name)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(service_name)))
}

/// Drops the service entry from `state.json` and persists it. Called
/// last, after all remote and on-disk teardown completes, so a partial
/// failure keeps the entry (and its stored role/policy names) available
/// for a re-run.
fn remove_entry_and_persist(
    state: &mut StateFile,
    state_path: &Path,
    service_name: &str,
    messages: &Messages,
) -> Result<()> {
    state.services.remove(service_name);
    state
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())
}

/// Builds the exact per-service KV paths written by `service add`.
fn service_kv_paths(entry: &ServiceEntry) -> Vec<String> {
    let base = format!("{SERVICE_KV_BASE}/{}", entry.service_name);
    let mut paths = vec![
        format!("{base}/{KV_EAB_SUFFIX}"),
        format!("{base}/{KV_HTTP_RESPONDER_HMAC_SUFFIX}"),
        format!("{base}/{SERVICE_TRUST_KV_SUFFIX}"),
    ];
    if matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap) {
        paths.push(format!("{base}/{KV_SECRET_ID_SUFFIX}"));
    }
    paths
}

fn build_artifact_plan(state: &StateFile, entry: &ServiceEntry) -> ArtifactPlan {
    let secrets_dir = state.secrets_dir();
    let dirs = vec![
        secrets_dir
            .join(SERVICE_SECRET_DIR)
            .join(&entry.service_name),
        secrets_dir
            .join(OPENBAO_SERVICE_CONFIG_DIR)
            .join(&entry.service_name),
        secrets_dir
            .join(REMOTE_BOOTSTRAP_DIR)
            .join(&entry.service_name),
    ];
    let files = vec![entry.cert_path.clone(), entry.key_path.clone()];
    ArtifactPlan {
        dirs,
        files,
        agent_config: entry.agent_config_path.clone(),
    }
}

fn print_remove_plan(
    entry: &ServiceEntry,
    kv_paths: &[String],
    artifacts: Option<&ArtifactPlan>,
    messages: &Messages,
) {
    println!(
        "{}",
        messages.service_remove_plan_header(&entry.service_name)
    );
    println!(
        "{}",
        messages.service_remove_plan_approle(&entry.approle.role_name)
    );
    println!(
        "{}",
        messages.service_remove_plan_policy(&entry.approle.policy_name)
    );
    for path in kv_paths {
        println!("{}", messages.service_remove_plan_kv(path));
    }
    match artifacts {
        Some(plan) => {
            for dir in &plan.dirs {
                println!(
                    "{}",
                    messages.service_remove_plan_artifact(&dir.display().to_string())
                );
            }
            for file in &plan.files {
                println!(
                    "{}",
                    messages.service_remove_plan_artifact(&file.display().to_string())
                );
            }
            println!(
                "{}",
                messages.service_remove_plan_agent_config(&plan.agent_config.display().to_string())
            );
        }
        None => println!("{}", messages.service_remove_plan_artifacts_preserved()),
    }
}

fn confirm_removal(service_name: &str, messages: &Messages) -> Result<bool> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout();
    let mut prompt = Prompt::new(&mut input, &mut output, messages);
    let label = messages.service_remove_confirm_prompt(service_name);
    let answer = prompt.prompt_text(&format!("{label} [y/N]"), Some("N"))?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

async fn delete_kv_if_present(client: &OpenBaoClient, mount: &str, path: &str) -> Result<bool> {
    if client.kv_exists(mount, path).await? {
        client.delete_kv(mount, path).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn delete_approle_if_present(client: &OpenBaoClient, role_name: &str) -> Result<bool> {
    if client.approle_exists(role_name).await? {
        client.delete_approle(role_name).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

async fn delete_policy_if_present(client: &OpenBaoClient, policy_name: &str) -> Result<bool> {
    if client.policy_exists(policy_name).await? {
        client.delete_policy(policy_name).await?;
        Ok(true)
    } else {
        Ok(false)
    }
}

fn delete_dir_if_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            std::fs::remove_dir_all(path)
                .with_context(|| format!("Failed to remove directory {}", path.display()))?;
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

fn delete_file_if_present(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => {
            std::fs::remove_file(path)
                .with_context(|| format!("Failed to remove file {}", path.display()))?;
            Ok(true)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

/// Strips bootroot's managed profile block from `agent.toml` in place.
///
/// Returns `Ok(true)` when a block was present and removed, `Ok(false)`
/// when the file is absent or carries no managed block (idempotent
/// re-run). The operator-owned file itself is never deleted.
fn strip_managed_profile(path: &Path, service_name: &str) -> Result<bool> {
    let current = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => {
            return Err(err).with_context(|| format!("Failed to read {}", path.display()));
        }
    };
    let next = remove_managed_profile_block(
        &current,
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        service_name,
    );
    if next == current {
        return Ok(false);
    }
    std::fs::write(path, next).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;
    use crate::i18n::test_messages;
    use crate::state::{DeployType, ServiceEntry, ServiceRoleEntry};

    fn sample_state() -> StateFile {
        StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::default(),
            approles: BTreeMap::default(),
            services: BTreeMap::default(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: BTreeMap::default(),
        }
    }

    fn sample_entry(name: &str, delivery_mode: DeliveryMode) -> ServiceEntry {
        ServiceEntry {
            service_name: name.to_string(),
            deploy_type: DeployType::Docker,
            delivery_mode,
            hostname: "host1".to_string(),
            domain: "example.com".to_string(),
            agent_config_path: PathBuf::from("/etc/agent.toml"),
            cert_path: PathBuf::from("/certs/cert.pem"),
            key_path: PathBuf::from("/certs/key.pem"),
            instance_id: Some("001".to_string()),
            container_name: Some("ctr".to_string()),
            notes: None,
            post_renew_hooks: Vec::new(),
            approle: ServiceRoleEntry {
                role_name: "bootroot-service-svc".to_string(),
                role_id: "rid".to_string(),
                secret_id_path: PathBuf::from("/s"),
                policy_name: "bootroot-service-svc".to_string(),
                secret_id_ttl: None,
                secret_id_wrap_ttl: None,
                token_bound_cidrs: None,
            },
            agent_email: None,
            agent_server: None,
            agent_responder_url: None,
            cert_group_gid: None,
        }
    }

    #[test]
    fn load_state_or_missing_bails_when_absent() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let state_path = dir.path().join("state.json");
        let err = load_state_or_missing(&state_path, &messages).expect_err("must bail");
        assert_eq!(err.to_string(), messages.error_state_missing());
    }

    #[test]
    fn require_service_entry_not_found_bails() {
        let messages = test_messages();
        let state = sample_state();
        let err = require_service_entry(&state, "missing", &messages).expect_err("must bail");
        assert_eq!(err.to_string(), messages.error_service_not_found("missing"));
    }

    #[test]
    fn require_service_entry_returns_registered_entry() {
        let messages = test_messages();
        let mut state = sample_state();
        state.services.insert(
            "svc".to_string(),
            sample_entry("svc", DeliveryMode::LocalFile),
        );
        let entry = require_service_entry(&state, "svc", &messages).expect("found");
        assert_eq!(entry.service_name, "svc");
    }

    #[test]
    fn remove_entry_and_persist_drops_entry_from_state_file() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let state_path = dir.path().join("state.json");
        let mut state = sample_state();
        state.services.insert(
            "svc".to_string(),
            sample_entry("svc", DeliveryMode::LocalFile),
        );
        state.services.insert(
            "keep".to_string(),
            sample_entry("keep", DeliveryMode::LocalFile),
        );
        state.save(&state_path).expect("save");

        remove_entry_and_persist(&mut state, &state_path, "svc", &messages).expect("remove");
        assert!(!state.services.contains_key("svc"));

        let reloaded = StateFile::load(&state_path).expect("reload");
        assert!(
            !reloaded.services.contains_key("svc"),
            "removed entry must not survive on disk"
        );
        assert!(
            reloaded.services.contains_key("keep"),
            "other services must be preserved"
        );
    }

    #[test]
    fn service_kv_paths_local_file_omits_secret_id() {
        let entry = sample_entry("svc", DeliveryMode::LocalFile);
        let paths = service_kv_paths(&entry);
        assert_eq!(
            paths,
            vec![
                "bootroot/services/svc/eab".to_string(),
                "bootroot/services/svc/http_responder_hmac".to_string(),
                "bootroot/services/svc/trust".to_string(),
            ]
        );
    }

    #[test]
    fn service_kv_paths_remote_bootstrap_includes_secret_id() {
        let entry = sample_entry("svc", DeliveryMode::RemoteBootstrap);
        let paths = service_kv_paths(&entry);
        assert!(paths.contains(&"bootroot/services/svc/secret_id".to_string()));
        assert_eq!(paths.len(), 4);
    }

    #[test]
    fn delete_dir_if_present_reports_absent_then_removed() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("svc");
        assert!(!delete_dir_if_present(&target).expect("absent ok"));
        std::fs::create_dir(&target).expect("create");
        std::fs::write(target.join("f"), b"x").expect("write");
        assert!(delete_dir_if_present(&target).expect("removed ok"));
        assert!(!target.exists());
        // Idempotent re-run.
        assert!(!delete_dir_if_present(&target).expect("absent again"));
    }

    #[test]
    fn delete_file_if_present_reports_absent_then_removed() {
        let dir = tempdir().expect("tempdir");
        let target = dir.path().join("cert.pem");
        assert!(!delete_file_if_present(&target).expect("absent ok"));
        std::fs::write(&target, b"x").expect("write");
        assert!(delete_file_if_present(&target).expect("removed ok"));
        assert!(!delete_file_if_present(&target).expect("absent again"));
    }

    #[test]
    fn strip_managed_profile_removes_block_and_is_idempotent() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("agent.toml");
        let block = bootroot::trust_bootstrap::render_managed_profile_block(
            MANAGED_PROFILE_BEGIN_PREFIX,
            MANAGED_PROFILE_END_PREFIX,
            "svc",
            "001",
            "host1",
            Path::new("/certs/cert.pem"),
            Path::new("/certs/key.pem"),
            None,
        );
        let contents = bootroot::trust_bootstrap::upsert_managed_profile_block(
            "email = \"a@b.c\"\n",
            MANAGED_PROFILE_BEGIN_PREFIX,
            MANAGED_PROFILE_END_PREFIX,
            "svc",
            &block,
        );
        std::fs::write(&path, &contents).expect("write");

        assert!(strip_managed_profile(&path, "svc").expect("strip ok"));
        let after = std::fs::read_to_string(&path).expect("read");
        assert!(!after.contains("[[profiles]]"));
        assert!(after.contains("email = \"a@b.c\""));

        // Idempotent: the file still exists, no block, returns false.
        assert!(!strip_managed_profile(&path, "svc").expect("strip idempotent"));
        assert!(path.exists());
    }

    #[test]
    fn strip_managed_profile_absent_file_is_noop() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("missing.toml");
        assert!(!strip_managed_profile(&path, "svc").expect("absent ok"));
    }
}
