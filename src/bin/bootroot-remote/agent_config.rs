use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use bootroot::fs_util;
use bootroot::trust_bootstrap::{
    AgentConfigBaselineParams, REMOTE_BOOTSTRAP_PROFILE_MARKERS,
    apply_agent_config_baseline_defaults, build_trust_updates as build_shared_trust_updates,
    render_managed_profile_block as render_profile, strip_foreign_managed_profiles,
    upsert_managed_profile_block as upsert_shared_managed_profile_block,
};
use tokio::fs;

use super::io::PulledSecrets;
use super::summary::{ApplyItemSummary, ApplyStatus};
use super::{
    HookFailurePolicy, Locale, MANAGED_PROFILE_BEGIN_PREFIX, MANAGED_PROFILE_END_PREFIX,
    ResolvedBootstrapArgs, localized,
};

struct ProfilePaths {
    cert_path: PathBuf,
    key_path: PathBuf,
}

// This function intentionally centralizes agent config mutation flow so
// per-item status/error mapping remains consistent for summary JSON contracts.
#[allow(clippy::too_many_lines)]
pub(super) async fn apply_agent_config_updates(
    args: &ResolvedBootstrapArgs,
    pulled: &PulledSecrets,
    lang: Locale,
) -> (ApplyItemSummary, ApplyItemSummary) {
    let profile_paths = resolve_profile_paths(args);
    let agent_config = match fs::read_to_string(&args.agent_config_path).await {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            let message = localized(
                lang,
                &format!(
                    "agent config read failed ({}): {err}",
                    args.agent_config_path.display()
                ),
                &format!(
                    "agent.toml 읽기 실패 ({}): {err}",
                    args.agent_config_path.display()
                ),
            );
            return (
                ApplyItemSummary::failed(message.clone()),
                ApplyItemSummary::failed(message),
            );
        }
    };
    // Strip any managed profile block the local-file path left for this
    // service on a prior delivery mode, before any table is appended. Done
    // on the raw file so the strip stays contained to the intended
    // `[[profiles]]` block (the end marker floats past tables added later,
    // and the `[trust]` collateral it may carry is re-synced below).
    // Without this, a local→remote transition would append a duplicate
    // block for the service (#662).
    let agent_config = strip_foreign_managed_profiles(
        &agent_config,
        REMOTE_BOOTSTRAP_PROFILE_MARKERS,
        &args.service_name,
    );
    // Backfill any baseline fields missing from a pre-existing agent.toml
    // (and seed a fresh file from the same baseline).  Without this step,
    // an operator who passed `--agent-server` / `--agent-responder-url`
    // at service-add time would see those artifact values silently
    // dropped whenever the remote target already had an agent.toml that
    // lacked those fields — the original #549 footgun, re-exposed on the
    // remote-bootstrap path.
    let baseline_applied = match apply_agent_config_baseline_defaults(
        &agent_config,
        &AgentConfigBaselineParams {
            email: &args.agent_email,
            server: &args.agent_server,
            domain: &args.agent_domain,
            http_responder_url: &args.agent_responder_url,
        },
    ) {
        Ok(output) => output,
        Err(err) => {
            let msg = format!("agent config TOML parse error: {err}");
            return (
                ApplyItemSummary::failed(msg.clone()),
                ApplyItemSummary::failed(msg),
            );
        }
    };
    // Explicit overrides carried through from the upstream
    // `bootroot service add --agent-*` flags win over any value already
    // in the pre-existing file, so operators can re-bake a changed ACME
    // topology from state without hand-editing the target.  When the
    // artifact did not carry an override (direct-CLI path or no flag at
    // service-add time), we leave the pre-existing value alone.
    let override_applied = match apply_agent_overrides(
        &baseline_applied,
        args.agent_email_override.as_deref(),
        args.agent_server_override.as_deref(),
        args.agent_responder_url_override.as_deref(),
    ) {
        Ok(output) => output,
        Err(err) => {
            let msg = format!("agent config TOML parse error: {err}");
            return (
                ApplyItemSummary::failed(msg.clone()),
                ApplyItemSummary::failed(msg),
            );
        }
    };
    let acme_pairs = vec![("http_responder_hmac", pulled.responder_hmac.clone())];
    let hmac_updated =
        match bootroot::toml_util::upsert_section_keys(&override_applied, "acme", &acme_pairs) {
            Ok(output) => output,
            Err(err) => {
                let msg = format!("agent config TOML parse error: {err}");
                return (
                    ApplyItemSummary::failed(msg.clone()),
                    ApplyItemSummary::failed(msg),
                );
            }
        };
    let trust_pairs = build_trust_updates(&pulled.trusted_ca_sha256, &args.ca_bundle_path);
    let trust_updated =
        match bootroot::toml_util::upsert_section_keys(&hmac_updated, "trust", &trust_pairs) {
            Ok(output) => output,
            Err(err) => {
                let msg = format!("agent config TOML parse error: {err}");
                return (
                    ApplyItemSummary::failed(msg.clone()),
                    ApplyItemSummary::failed(msg),
                );
            }
        };
    let openbao_pairs = build_openbao_updates(args, &trust_updated);
    let openbao_updated =
        match bootroot::toml_util::upsert_section_keys(&trust_updated, "openbao", &openbao_pairs) {
            Ok(output) => output,
            Err(err) => {
                let msg = format!("agent config TOML parse error: {err}");
                return (
                    ApplyItemSummary::failed(msg.clone()),
                    ApplyItemSummary::failed(msg),
                );
            }
        };
    let profile_block = render_managed_profile_block(
        &args.service_name,
        args.profile_instance_id
            .as_deref()
            .expect("validate_bootstrap_args requires profile_instance_id"),
        &args.profile_hostname,
        &profile_paths.cert_path,
        &profile_paths.key_path,
        args.cert_group_gid,
    );
    let profile_block = inject_hooks_into_profile_block(&profile_block, args);
    let with_profile =
        upsert_managed_profile_block(&openbao_updated, &args.service_name, &profile_block);

    let responder_changed = hmac_updated != override_applied;
    let trust_changed = trust_updated != hmac_updated;

    let mut responder_hmac_status = ApplyItemSummary::applied(if responder_changed {
        ApplyStatus::Applied
    } else {
        ApplyStatus::Unchanged
    });
    let mut trust_sync_status = ApplyItemSummary::applied(if trust_changed {
        ApplyStatus::Applied
    } else {
        ApplyStatus::Unchanged
    });

    if with_profile != agent_config {
        if let Some(parent) = args.agent_config_path.parent()
            && let Err(err) = fs_util::ensure_secrets_dir(parent).await
        {
            let message = localized(
                lang,
                &format!(
                    "agent config parent mkdir failed ({}): {err}",
                    parent.display()
                ),
                &format!(
                    "agent.toml 상위 디렉터리 생성 실패 ({}): {err}",
                    parent.display()
                ),
            );
            return (
                ApplyItemSummary::failed(message.clone()),
                ApplyItemSummary::failed(message),
            );
        }
        if let Err(err) = fs::write(&args.agent_config_path, &with_profile).await {
            let message = localized(
                lang,
                &format!(
                    "agent config write failed ({}): {err}",
                    args.agent_config_path.display()
                ),
                &format!(
                    "agent.toml 쓰기 실패 ({}): {err}",
                    args.agent_config_path.display()
                ),
            );
            if responder_changed {
                responder_hmac_status = ApplyItemSummary::failed(message.clone());
            }
            if trust_changed {
                trust_sync_status = ApplyItemSummary::failed(message);
            }
            return (responder_hmac_status, trust_sync_status);
        }
        if let Err(err) = fs_util::set_key_permissions(&args.agent_config_path).await {
            let message = localized(
                lang,
                &format!(
                    "agent config chmod failed ({}): {err}",
                    args.agent_config_path.display()
                ),
                &format!(
                    "agent.toml 권한 설정 실패 ({}): {err}",
                    args.agent_config_path.display()
                ),
            );
            if responder_changed {
                responder_hmac_status = ApplyItemSummary::failed(message.clone());
            }
            if trust_changed {
                trust_sync_status = ApplyItemSummary::failed(message);
            }
            return (responder_hmac_status, trust_sync_status);
        }
    }

    (responder_hmac_status, trust_sync_status)
}

fn resolve_profile_paths(args: &ResolvedBootstrapArgs) -> ProfilePaths {
    let fallback_dir = args
        .agent_config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("certs");
    let cert_path = args
        .profile_cert_path
        .clone()
        .unwrap_or_else(|| fallback_dir.join(format!("{}.crt", args.service_name)));
    let key_path = args
        .profile_key_path
        .clone()
        .unwrap_or_else(|| fallback_dir.join(format!("{}.key", args.service_name)));
    ProfilePaths {
        cert_path,
        key_path,
    }
}

fn inject_hooks_into_profile_block(block: &str, args: &ResolvedBootstrapArgs) -> String {
    let Some(command) = args.post_renew_command.as_deref() else {
        return block.to_string();
    };
    let timeout_secs = args.post_renew_timeout_secs.unwrap_or(30);
    let on_failure = match args.post_renew_on_failure {
        Some(HookFailurePolicy::Stop) => "stop",
        _ => "continue",
    };
    let mut hook_toml = String::from("\n[[profiles.hooks.post_renew.success]]\n");
    let _ = writeln!(
        hook_toml,
        "command = {}",
        bootroot::toml_util::toml_encode_string(command)
    );
    if !args.post_renew_arg.is_empty() {
        let formatted_args = args
            .post_renew_arg
            .iter()
            .map(|a| bootroot::toml_util::toml_encode_string(a))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(hook_toml, "args = [{formatted_args}]");
    }
    let _ = writeln!(hook_toml, "timeout_secs = {timeout_secs}");
    let _ = writeln!(hook_toml, "on_failure = \"{on_failure}\"");

    if let Some(end_pos) = block.rfind(MANAGED_PROFILE_END_PREFIX) {
        let mut result = block[..end_pos].to_string();
        result.push_str(&hook_toml);
        result.push_str(&block[end_pos..]);
        result
    } else {
        let mut result = block.to_string();
        result.push_str(&hook_toml);
        result
    }
}

fn apply_agent_overrides(
    contents: &str,
    email: Option<&str>,
    server: Option<&str>,
    http_responder_url: Option<&str>,
) -> Result<String> {
    let mut next = contents.to_string();
    if let Some(email) = email {
        next = bootroot::toml_util::upsert_top_level_keys(&next, &[("email", email.to_string())])?;
    }
    if let Some(server) = server {
        next =
            bootroot::toml_util::upsert_top_level_keys(&next, &[("server", server.to_string())])?;
    }
    if let Some(responder_url) = http_responder_url {
        next = bootroot::toml_util::upsert_section_keys(
            &next,
            "acme",
            &[("http_responder_url", responder_url.to_string())],
        )?;
    }
    Ok(next)
}

fn render_managed_profile_block(
    service_name: &str,
    instance_id: &str,
    hostname: &str,
    cert_path: &Path,
    key_path: &Path,
    cert_group_gid: Option<u32>,
) -> String {
    render_profile(
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        service_name,
        instance_id,
        hostname,
        cert_path,
        key_path,
        cert_group_gid,
    )
}

fn upsert_managed_profile_block(contents: &str, service_name: &str, replacement: &str) -> String {
    upsert_shared_managed_profile_block(
        contents,
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        service_name,
        replacement,
    )
}

fn build_trust_updates(
    fingerprints: &[String],
    ca_bundle_path: &Path,
) -> Vec<(&'static str, String)> {
    build_shared_trust_updates(fingerprints, ca_bundle_path)
}

/// Builds the `[openbao]` key-value pairs that `bootroot-remote bootstrap`
/// upserts into `agent.toml`. This provisions the fast-poll loop on every
/// remote-bootstrap host so `bootroot rotate force-reissue` has a
/// guaranteed consumer — otherwise the control-plane KV write would land
/// in a section nobody reads. Connection-level fields are always
/// refreshed. A stable absolute `state_path` adjacent to `agent.toml` is
/// provisioned only when the operator has not already set one — the
/// in-tree default is a bare relative filename resolved against the
/// agent process cwd, which is unsafe under systemd-style supervisors
/// where the cwd can change or be unwritable. Operator-tuned
/// `fast_poll_interval` or `state_path` entries are preserved.
fn build_openbao_updates(
    args: &ResolvedBootstrapArgs,
    current_contents: &str,
) -> Vec<(&'static str, String)> {
    let mut pairs = vec![
        ("url", args.openbao_url.clone()),
        ("kv_mount", args.kv_mount.clone()),
        ("role_id_path", args.role_id_path.display().to_string()),
        ("secret_id_path", args.secret_id_path.display().to_string()),
        ("ca_bundle_path", args.ca_bundle_path.display().to_string()),
    ];
    // A non-loopback plaintext URL fails config validation without the
    // explicit opt-in, so upsert it whenever we write such a URL. Loopback
    // plaintext and https:// never need it, so it is not emitted there.
    if bootroot::config::openbao_url_is_non_loopback_plaintext(&args.openbao_url) {
        pairs.push(("allow_plaintext_http", "true".to_string()));
    }
    // Provision an absolute `state_path` when either (a) the key is
    // missing, or (b) the existing value is relative. Case (b) catches
    // operator-edited configs that left a relative `state_path` — whether
    // the default relative filename that was never made absolute or a
    // hand-entered relative value — so rerunning `bootroot-remote bootstrap`
    // must be able to repair them, otherwise the validation hint
    // pointing operators at bootstrap would be misleading.
    if needs_absolute_state_path_provisioning(current_contents)
        && let Some(path) = default_state_path_for(args)
    {
        pairs.push(("state_path", path));
    }
    pairs
}

fn needs_absolute_state_path_provisioning(contents: &str) -> bool {
    let Ok(doc) = contents.parse::<toml_edit::DocumentMut>() else {
        return true;
    };
    let Some(table) = doc.get("openbao").and_then(toml_edit::Item::as_table) else {
        return true;
    };
    let Some(item) = table.get("state_path") else {
        return true;
    };
    let Some(value) = item.as_str() else {
        // A non-string `state_path` is malformed; overwrite with the
        // provisioned absolute default rather than leaving it invalid.
        return true;
    };
    !Path::new(value).is_absolute()
}

/// Returns an absolute `state_path` adjacent to `agent.toml` when the
/// agent config path is absolute, or `None` when it is relative. A
/// relative agent config path would yield an equally-cwd-dependent
/// state path, which is exactly what this provisioning is meant to
/// avoid; leaving `state_path` unset lets the existing validation
/// surface the issue instead of silently entrenching a fragile path.
///
/// The basename is keyed by `service_name` so that per-service agent
/// configs sharing one directory (the supported multi-service-per-host
/// layout) resolve to distinct state files instead of contending over a
/// single shared `bootroot-agent-state.json`.
fn default_state_path_for(args: &ResolvedBootstrapArgs) -> Option<String> {
    let parent = args.agent_config_path.parent()?;
    if !parent.is_absolute() {
        return None;
    }
    Some(
        parent
            .join(state_path_basename(&args.service_name))
            .display()
            .to_string(),
    )
}

/// Derives the per-service fast-poll state filename.
///
/// `service_name` is a validated DNS label on the bootstrap path
/// (`validate_service_name` → `validate_dns_label`), so it contains only
/// letters, digits, and hyphens and can never introduce a path separator
/// or `..`. The `debug_assert!` pins that invariant: the produced value
/// is always a plain basename, never a traversal.
fn state_path_basename(service_name: &str) -> String {
    debug_assert!(
        !service_name.is_empty()
            && !service_name.contains(['/', '\\'])
            && !service_name.contains(".."),
        "service_name must be a validated DNS label, got {service_name:?}"
    );
    format!("bootroot-agent-state-{service_name}.json")
}

/// A group of sibling agent configs that resolve to the same absolute
/// fast-poll `state_path`. Two `bootroot-agent` processes sharing one
/// state file race on the fast-poll `FastPollState`, each periodically
/// reverting the other's progress (version-gating thrash, lost
/// reissue-completion tracking).
pub(super) struct StatePathCollision {
    pub(super) state_path: PathBuf,
    pub(super) configs: Vec<PathBuf>,
}

/// Scans sibling `*.toml` configs in `dir` and returns each set of two or
/// more configs whose `[openbao].state_path` resolves to the same absolute
/// path.
///
/// This compares the resolved `state_path` across sibling configs — the
/// well-defined collision signal — rather than inspecting the on-disk
/// state file, which carries no service-ownership metadata. Unreadable,
/// unparseable, and files without an `[openbao].state_path` are skipped:
/// this is a best-effort defense-in-depth warning, never a hard failure.
pub(super) fn detect_state_path_collisions(dir: &Path) -> Vec<StatePathCollision> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut configs: Vec<PathBuf> = entries
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    configs.sort_unstable();

    let mut by_state: std::collections::BTreeMap<PathBuf, Vec<PathBuf>> =
        std::collections::BTreeMap::new();
    for config in configs {
        let Ok(contents) = std::fs::read_to_string(&config) else {
            continue;
        };
        if let Some(state_path) = resolve_config_state_path(&config, &contents) {
            by_state.entry(state_path).or_default().push(config);
        }
    }

    by_state
        .into_iter()
        .filter(|(_, configs)| configs.len() >= 2)
        .map(|(state_path, configs)| StatePathCollision {
            state_path,
            configs,
        })
        .collect()
}

/// Resolves the absolute fast-poll `state_path` declared by a single agent
/// config, or `None` when the config has no `[openbao].state_path`. A
/// relative `state_path` is resolved against the config file's parent
/// directory so that sibling configs sharing a directory compare on equal
/// footing. The result is lexically normalized so that configs whose
/// `state_path`s differ only by redundant `.`/`..` spellings still group
/// together.
fn resolve_config_state_path(config_path: &Path, contents: &str) -> Option<PathBuf> {
    let doc = contents.parse::<toml_edit::DocumentMut>().ok()?;
    let state_path = doc
        .get("openbao")
        .and_then(toml_edit::Item::as_table)?
        .get("state_path")?
        .as_str()?;
    let state_path = Path::new(state_path);
    let resolved = if state_path.is_absolute() {
        state_path.to_path_buf()
    } else {
        config_path.parent()?.join(state_path)
    };
    Some(normalize_lexically(&resolved))
}

/// Collapses `.` and `..` components lexically, without touching the
/// filesystem. Two configs whose `state_path`s resolve to the same file but
/// spell it differently (e.g. `config/state.json` vs `config/./state.json`
/// vs `config/sub/../state.json`) must group together for collision
/// detection. `std::fs::canonicalize` cannot be used because the state file
/// need not exist yet, so this normalizes purely lexically.
fn normalize_lexically(path: &Path) -> PathBuf {
    use std::path::Component;

    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => match normalized.components().next_back() {
                Some(Component::Normal(_)) => {
                    normalized.pop();
                }
                // The root's parent is the root; drop a leading `..`.
                Some(Component::RootDir | Component::Prefix(_)) => {}
                _ => normalized.push(component.as_os_str()),
            },
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::OutputFormat;

    #[test]
    fn upsert_toml_section_keys_updates_existing_section() {
        let input = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let output = bootroot::toml_util::upsert_section_keys(
            input,
            "acme",
            &[("http_responder_hmac", "new".to_string())],
        )
        .unwrap();
        assert!(output.contains("http_responder_hmac = \"new\""));
    }

    /// local-file → remote-bootstrap transition: `bootroot-remote
    /// bootstrap` runs over an `agent.toml` that already carries a
    /// `bootroot managed profile` block. Stripping foreign blocks before
    /// upserting the remote block must leave exactly one `[[profiles]]`,
    /// not a duplicate (#662).
    #[test]
    fn remote_bootstrap_strips_pre_existing_local_block() {
        let local_block = render_profile(
            bootroot::trust_bootstrap::LOCAL_FILE_PROFILE_MARKERS.begin_prefix,
            bootroot::trust_bootstrap::LOCAL_FILE_PROFILE_MARKERS.end_prefix,
            "giganto",
            "001",
            "node-01",
            Path::new("/etc/bootroot-agent/certs/giganto.crt"),
            Path::new("/etc/bootroot-agent/certs/giganto.key"),
            None,
        );
        let existing = format!("email = \"admin@example.com\"\n\n{local_block}\n");

        let stripped =
            strip_foreign_managed_profiles(&existing, REMOTE_BOOTSTRAP_PROFILE_MARKERS, "giganto");
        let remote_block = render_managed_profile_block(
            "giganto",
            "001",
            "node-01",
            Path::new("/etc/bootroot-agent/certs/giganto.crt"),
            Path::new("/etc/bootroot-agent/certs/giganto.key"),
            None,
        );
        let updated = upsert_managed_profile_block(&stripped, "giganto", &remote_block);

        assert_eq!(
            updated.matches("[[profiles]]").count(),
            1,
            "exactly one profile block must remain: {updated}"
        );
        assert!(
            !updated.contains(bootroot::trust_bootstrap::LOCAL_FILE_PROFILE_MARKERS.begin_prefix),
            "the stale local-file block must be stripped: {updated}"
        );
        assert!(
            updated.contains(REMOTE_BOOTSTRAP_PROFILE_MARKERS.begin_prefix),
            "the remote marker must be present: {updated}"
        );
    }

    #[test]
    fn upsert_toml_section_keys_adds_new_section() {
        let input = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let updates = build_trust_updates(&["a".repeat(64)], Path::new("certs/ca.pem"));
        let output = bootroot::toml_util::upsert_section_keys(input, "trust", &updates).unwrap();
        assert!(output.contains("[trust]"));
        assert!(output.contains("ca_bundle_path = \"certs/ca.pem\""));
        assert!(output.contains("trusted_ca_sha256 = ["));
    }

    fn test_bootstrap_args() -> ResolvedBootstrapArgs {
        ResolvedBootstrapArgs {
            openbao_url: "https://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            service_name: "edge-proxy".to_string(),
            role_id_path: PathBuf::from("/tmp/role_id"),
            secret_id_path: PathBuf::from("/tmp/secrets/services/edge-proxy/secret_id"),
            eab_file_path: PathBuf::from("/tmp/eab.json"),
            agent_config_path: PathBuf::from("/tmp/agent.toml"),
            agent_email: "admin@example.com".to_string(),
            agent_server: "https://localhost:9443".to_string(),
            agent_domain: "example.com".to_string(),
            agent_responder_url: "http://localhost:8080".to_string(),
            agent_email_override: None,
            agent_server_override: None,
            agent_responder_url_override: None,
            profile_hostname: "localhost".to_string(),
            profile_instance_id: Some("001".to_string()),
            profile_cert_path: None,
            profile_key_path: None,
            ca_bundle_path: PathBuf::from("/tmp/ca-bundle.pem"),
            ca_bundle_pem: None,
            trusted_ca_sha256: Vec::new(),
            post_renew_command: None,
            post_renew_arg: Vec::new(),
            post_renew_timeout_secs: None,
            post_renew_on_failure: None,
            output: OutputFormat::Text,
            wrap_token: None,
            wrap_expires_at: None,
            cert_group_gid: None,
        }
    }

    #[test]
    fn build_openbao_updates_covers_connection_fields() {
        let args = test_bootstrap_args();
        let pairs = build_openbao_updates(&args, "");
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            keys,
            vec![
                "url",
                "kv_mount",
                "role_id_path",
                "secret_id_path",
                "ca_bundle_path",
                "state_path",
            ]
        );
    }

    #[test]
    fn build_openbao_updates_emits_opt_in_for_non_loopback_plaintext() {
        let mut args = test_bootstrap_args();
        args.openbao_url = "http://10.0.0.5:8200".to_string();
        let pairs = build_openbao_updates(&args, "");
        assert!(
            pairs
                .iter()
                .any(|(k, v)| *k == "allow_plaintext_http" && v == "true"),
            "non-loopback plaintext must upsert the opt-in: {pairs:?}"
        );
        let output = bootroot::toml_util::upsert_section_keys("", "openbao", &pairs).unwrap();
        assert!(output.contains("allow_plaintext_http = true"), "{output}");
    }

    #[test]
    fn build_openbao_updates_omits_opt_in_for_loopback_plaintext() {
        let mut args = test_bootstrap_args();
        args.openbao_url = "http://127.0.0.1:8200".to_string();
        let pairs = build_openbao_updates(&args, "");
        assert!(
            !pairs.iter().any(|(k, _)| *k == "allow_plaintext_http"),
            "loopback plaintext must not emit the opt-in: {pairs:?}"
        );
    }

    #[test]
    fn build_openbao_updates_omits_opt_in_for_https() {
        let mut args = test_bootstrap_args();
        args.openbao_url = "https://openbao.example:8200".to_string();
        let pairs = build_openbao_updates(&args, "");
        assert!(
            !pairs.iter().any(|(k, _)| *k == "allow_plaintext_http"),
            "https must not emit the opt-in: {pairs:?}"
        );
    }

    #[test]
    fn build_openbao_updates_render_upserts_into_empty_config() {
        let args = test_bootstrap_args();
        let pairs = build_openbao_updates(&args, "");
        let output = bootroot::toml_util::upsert_section_keys("", "openbao", &pairs).unwrap();
        assert!(output.contains("[openbao]"), "{output}");
        assert!(
            output.contains("url = \"https://localhost:8200\""),
            "{output}"
        );
        assert!(output.contains("kv_mount = \"secret\""), "{output}");
        assert!(
            output.contains("role_id_path = \"/tmp/role_id\""),
            "{output}"
        );
        assert!(
            output.contains("secret_id_path = \"/tmp/secrets/services/edge-proxy/secret_id\""),
            "{output}"
        );
        assert!(
            output.contains("ca_bundle_path = \"/tmp/ca-bundle.pem\""),
            "{output}"
        );
    }

    #[test]
    fn build_openbao_updates_provisions_absolute_state_path_when_missing() {
        // Agent config has [openbao] but no state_path — bootstrap must
        // provision an absolute path adjacent to agent.toml so the
        // fast-poll restart-persistence guarantee does not depend on
        // the agent process cwd. This is the no-state_path case
        // flagged in Round 5 review.
        let args = test_bootstrap_args();
        let input = "[openbao]\nurl = \"https://stale:8200\"\n";
        let pairs = build_openbao_updates(&args, input);
        let state_path_pair = pairs
            .iter()
            .find(|(k, _)| *k == "state_path")
            .expect("state_path must be provisioned when missing");
        let rendered = &state_path_pair.1;
        assert!(
            std::path::Path::new(rendered).is_absolute(),
            "state_path should be absolute: {rendered}"
        );
        assert_eq!(rendered, "/tmp/bootroot-agent-state-edge-proxy.json");

        let output = bootroot::toml_util::upsert_section_keys(input, "openbao", &pairs).unwrap();
        assert!(
            output.contains("state_path = \"/tmp/bootroot-agent-state-edge-proxy.json\""),
            "{output}"
        );
    }

    #[test]
    fn build_openbao_updates_skips_state_path_when_agent_config_relative() {
        // If agent_config_path is relative, derive-and-provision would
        // produce a cwd-relative state_path, which is the failure mode
        // we're avoiding. Leave state_path unset so validation surfaces
        // the issue rather than entrenching a fragile path.
        let mut args = test_bootstrap_args();
        args.agent_config_path = PathBuf::from("agent.toml");
        let pairs = build_openbao_updates(&args, "");
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert!(
            !keys.contains(&"state_path"),
            "state_path must not be provisioned when agent_config_path is relative: {keys:?}"
        );
    }

    /// End-to-end regression test for Round 6: a bootstrap run where
    /// `agent_config_path` is relative must not produce a valid config.
    /// `build_openbao_updates` deliberately skips provisioning
    /// `state_path` in that case to avoid entrenching a cwd-relative
    /// path; the config layer then falls back to a cwd-relative default,
    /// which `validate_openbao_settings` must reject. Before the
    /// validation guardrail, the resulting config would load and run
    /// with an unsafe state file.
    #[test]
    fn config_built_from_relative_agent_config_path_fails_validation() {
        let mut args = test_bootstrap_args();
        args.agent_config_path = PathBuf::from("agent.toml");
        // Round out the remaining required-field surface so the only
        // thing under test is the state_path absolute-path invariant.
        let pairs = build_openbao_updates(&args, "");
        let rendered = bootroot::toml_util::upsert_section_keys("", "openbao", &pairs).unwrap();
        assert!(
            !rendered.contains("state_path"),
            "bootstrap must skip state_path when agent_config_path is relative: {rendered}"
        );

        let config = format!(
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"

            {rendered}
            "#
        );

        let tmp = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::fs::write(tmp.path(), config).unwrap();
        let settings = bootroot::config::Settings::new(Some(tmp.path().to_path_buf())).unwrap();
        let err = settings
            .validate()
            .expect_err("validation must reject cwd-relative state_path");
        let msg = err.to_string();
        assert!(msg.contains("openbao.state_path"), "{msg}");
        assert!(msg.contains("absolute"), "{msg}");
    }

    #[test]
    fn build_openbao_updates_preserves_operator_tuned_keys() {
        let args = test_bootstrap_args();
        let input = "[openbao]\n\
            url = \"https://stale:8200\"\n\
            fast_poll_interval = \"5s\"\n\
            state_path = \"/var/lib/bootroot/custom-state.json\"\n";
        let output = bootroot::toml_util::upsert_section_keys(
            input,
            "openbao",
            &build_openbao_updates(&args, input),
        )
        .unwrap();
        // Connection fields are overwritten with fresh bootstrap values.
        assert!(
            output.contains("url = \"https://localhost:8200\""),
            "{output}"
        );
        // Operator-tuned keys stay untouched.
        assert!(output.contains("fast_poll_interval = \"5s\""), "{output}");
        assert!(
            output.contains("state_path = \"/var/lib/bootroot/custom-state.json\""),
            "{output}"
        );
    }

    #[test]
    fn build_openbao_updates_repairs_relative_state_path() {
        // Round 8 regression: a config may already carry a
        // relative `state_path` (e.g. the in-tree default filename, or
        // an operator edit). Rerunning `bootroot-remote bootstrap` must
        // repair it in place, otherwise the validation hint pointing
        // operators at bootstrap is misleading.
        let args = test_bootstrap_args();
        let input = "[openbao]\n\
            url = \"https://stale:8200\"\n\
            state_path = \"bootroot-agent-state.json\"\n";
        let pairs = build_openbao_updates(&args, input);
        let state_path_pair = pairs
            .iter()
            .find(|(k, _)| *k == "state_path")
            .expect("state_path must be repaired when existing value is relative");
        assert!(
            std::path::Path::new(&state_path_pair.1).is_absolute(),
            "state_path should be absolute after repair: {}",
            state_path_pair.1
        );
        let output = bootroot::toml_util::upsert_section_keys(input, "openbao", &pairs).unwrap();
        assert!(
            output.contains("state_path = \"/tmp/bootroot-agent-state-edge-proxy.json\""),
            "{output}"
        );
        assert!(
            !output.contains("state_path = \"bootroot-agent-state.json\""),
            "relative value must be replaced, not kept alongside the absolute one: {output}"
        );
    }

    #[test]
    fn default_state_path_for_is_service_keyed_and_unique_per_service() {
        // Two distinct services bootstrapped into the same directory must
        // resolve to distinct state_paths so their fast-poll agents do not
        // race on one shared state file (issue #687, constraint 2).
        let mut args_a = test_bootstrap_args();
        args_a.service_name = "giganto".to_string();
        args_a.agent_config_path = PathBuf::from("/opt/bootroot-closed/config/giganto.toml");

        let mut args_b = test_bootstrap_args();
        args_b.service_name = "edge-proxy".to_string();
        args_b.agent_config_path = PathBuf::from("/opt/bootroot-closed/config/edge-proxy.toml");

        let state_a = default_state_path_for(&args_a).expect("absolute config yields state_path");
        let state_b = default_state_path_for(&args_b).expect("absolute config yields state_path");

        assert_eq!(
            state_a,
            "/opt/bootroot-closed/config/bootroot-agent-state-giganto.json"
        );
        assert_eq!(
            state_b,
            "/opt/bootroot-closed/config/bootroot-agent-state-edge-proxy.json"
        );
        assert_ne!(
            state_a, state_b,
            "distinct services in one directory must not collide"
        );
    }

    #[test]
    fn build_openbao_updates_preserves_existing_absolute_state_path() {
        // Idempotency guarantee: a deployment already carries an absolute
        // state_path, so re-running bootstrap must leave it exactly as-is
        // (issue #687 acceptance criteria).
        let args = test_bootstrap_args();
        let input = "[openbao]\n\
            url = \"https://stale:8200\"\n\
            state_path = \"/var/lib/bootroot/existing-state.json\"\n";
        let pairs = build_openbao_updates(&args, input);
        assert!(
            !pairs.iter().any(|(k, _)| *k == "state_path"),
            "an existing absolute state_path must be preserved, not re-provisioned: {pairs:?}"
        );
    }

    #[test]
    fn state_path_basename_is_a_plain_filename_for_valid_dns_labels() {
        // validate_service_name restricts service_name to a DNS label, so
        // the derived basename can never contain a path separator or `..`.
        for service in ["a", "giganto", "edge-proxy", "svc-01", &"x".repeat(63)] {
            let basename = state_path_basename(service);
            assert!(
                !basename.contains('/') && !basename.contains('\\') && !basename.contains(".."),
                "basename must be a plain filename: {basename}"
            );
            assert_eq!(Path::new(&basename).components().count(), 1, "{basename}");
            assert_eq!(basename, format!("bootroot-agent-state-{service}.json"));
        }
    }

    #[test]
    fn detect_state_path_collisions_flags_shared_absolute_state_path() {
        // Two sibling managed configs pinned to the same absolute
        // state_path must be reported (issue #687, collision detection).
        let dir = tempfile::tempdir().unwrap();
        let shared = "/var/lib/bootroot/shared-state.json";
        std::fs::write(
            dir.path().join("giganto.toml"),
            format!("[openbao]\nstate_path = \"{shared}\"\n"),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("edge-proxy.toml"),
            format!("[openbao]\nstate_path = \"{shared}\"\n"),
        )
        .unwrap();

        let collisions = detect_state_path_collisions(dir.path());
        assert_eq!(collisions.len(), 1, "one collision group expected");
        let collision = collisions.first().expect("collision present");
        assert_eq!(collision.state_path, Path::new(shared));
        assert_eq!(collision.configs.len(), 2);
    }

    #[test]
    fn detect_state_path_collisions_ignores_distinct_state_paths() {
        // Distinct (service-keyed) state_paths are the healthy layout and
        // must not trigger a warning.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("giganto.toml"),
            "[openbao]\nstate_path = \"/var/lib/bootroot/bootroot-agent-state-giganto.json\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("edge-proxy.toml"),
            "[openbao]\nstate_path = \"/var/lib/bootroot/bootroot-agent-state-edge-proxy.json\"\n",
        )
        .unwrap();

        assert!(
            detect_state_path_collisions(dir.path()).is_empty(),
            "distinct state_paths must not be reported as a collision"
        );
    }

    #[test]
    fn detect_state_path_collisions_flags_shared_relative_state_path() {
        // Sibling configs both carrying the same relative default filename
        // resolve to the same directory-relative path and must collide.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("giganto.toml"),
            "[openbao]\nstate_path = \"bootroot-agent-state.json\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("edge-proxy.toml"),
            "[openbao]\nstate_path = \"bootroot-agent-state.json\"\n",
        )
        .unwrap();

        let collisions = detect_state_path_collisions(dir.path());
        assert_eq!(collisions.len(), 1, "shared relative filename must collide");
    }

    #[test]
    fn detect_state_path_collisions_flags_mixed_spelling_of_same_path() {
        // Configs that resolve to the same file but spell it differently
        // (redundant `.`/`..` components) must still collide: both agents
        // open the same file even though the raw strings differ.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("giganto.toml"),
            "[openbao]\nstate_path = \"/opt/bootroot/config/bootroot-agent-state.json\"\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("edge-proxy.toml"),
            "[openbao]\nstate_path = \"/opt/bootroot/config/./sub/../bootroot-agent-state.json\"\n",
        )
        .unwrap();

        let collisions = detect_state_path_collisions(dir.path());
        assert_eq!(
            collisions.len(),
            1,
            "mixed-spelling paths resolving to one file must collide"
        );
        let collision = collisions.first().expect("collision present");
        assert_eq!(
            collision.state_path,
            Path::new("/opt/bootroot/config/bootroot-agent-state.json")
        );
        assert_eq!(collision.configs.len(), 2);
    }

    #[test]
    fn inject_hooks_escapes_control_characters() {
        let mut args = test_bootstrap_args();
        args.post_renew_command = Some("echo\nnext".to_string());
        args.post_renew_arg = vec!["line1\tline2".to_string()];
        args.post_renew_timeout_secs = Some(10);

        let prefix = MANAGED_PROFILE_BEGIN_PREFIX;
        let suffix = MANAGED_PROFILE_END_PREFIX;
        let block = format!(
            "{prefix} edge-proxy\n[[profiles]]\nservice_name = \"edge-proxy\"\n{suffix} edge-proxy\n",
        );
        let result = inject_hooks_into_profile_block(&block, &args);

        // Extract just the hook section and parse it as TOML.
        let wrapped = format!(
            "[profiles]\n[profiles.hooks]\n[profiles.hooks.post_renew]{}",
            result[result
                .find("\n[[profiles.hooks.post_renew.success]]")
                .expect("hook header must exist")..]
                .split(MANAGED_PROFILE_END_PREFIX)
                .next()
                .unwrap()
        );
        let doc: toml_edit::DocumentMut = wrapped
            .parse()
            .expect("rendered hook TOML with control chars must be parseable");

        let success = doc["profiles"]["hooks"]["post_renew"]["success"]
            .as_array_of_tables()
            .expect("success must be an array of tables");
        let hook = success.get(0).expect("must have one hook entry");
        assert_eq!(
            hook["command"].as_str().unwrap(),
            "echo\nnext",
            "command must round-trip through TOML"
        );
        let args_arr = hook["args"].as_array().expect("args must be an array");
        assert_eq!(args_arr.get(0).unwrap().as_str().unwrap(), "line1\tline2");
    }

    /// Regression for the Round 5 review: when `bootroot-remote bootstrap`
    /// runs against a remote target whose pre-existing `agent.toml` is
    /// missing `email` / `server` / `[acme].http_responder_url`, the
    /// artifact-carried override values (persisted by the upstream
    /// `bootroot service add --agent-*` invocation) must be baked into
    /// the rendered output so the KV re-render loop stops reverting to
    /// bootroot-agent's compiled-in defaults.  Before the fix, the
    /// existing-file branch read the file verbatim and only upserted
    /// `[trust]` / `acme.http_responder_hmac` / the managed profile.
    #[test]
    fn existing_agent_config_backfills_overrides_from_artifact() {
        const OVERRIDE_EMAIL: &str = "ops@example.org";
        const OVERRIDE_SERVER: &str = "https://step-ca.example.org:9443/acme/acme/directory";
        const OVERRIDE_RESPONDER: &str = "http://responder.internal:18080";

        // Operator-authored `agent.toml` already on the remote target
        // that lacks the topology fields — a partially populated config
        // that bootstrap must backfill from the artifact overrides.
        let pre_existing =
            "domain = \"existing.domain\"\n\n[acme]\nhttp_responder_hmac = \"prior-hmac\"\n";

        let mut args = test_bootstrap_args();
        args.agent_email = OVERRIDE_EMAIL.to_string();
        args.agent_server = OVERRIDE_SERVER.to_string();
        args.agent_responder_url = OVERRIDE_RESPONDER.to_string();
        args.agent_email_override = Some(OVERRIDE_EMAIL.to_string());
        args.agent_server_override = Some(OVERRIDE_SERVER.to_string());
        args.agent_responder_url_override = Some(OVERRIDE_RESPONDER.to_string());

        // Mirror the in-memory mutation pipeline of
        // `apply_agent_config_updates` (the I/O parts are factored out
        // so this pure test remains stable across writer rewrites).
        let backfilled = apply_agent_config_baseline_defaults(
            pre_existing,
            &AgentConfigBaselineParams {
                email: &args.agent_email,
                server: &args.agent_server,
                domain: &args.agent_domain,
                http_responder_url: &args.agent_responder_url,
            },
        )
        .unwrap();
        let overridden = apply_agent_overrides(
            &backfilled,
            args.agent_email_override.as_deref(),
            args.agent_server_override.as_deref(),
            args.agent_responder_url_override.as_deref(),
        )
        .unwrap();
        let with_hmac = bootroot::toml_util::upsert_section_keys(
            &overridden,
            "acme",
            &[("http_responder_hmac", "new-hmac".to_string())],
        )
        .unwrap();

        assert!(
            with_hmac.contains(&format!("email = \"{OVERRIDE_EMAIL}\"")),
            "existing agent.toml must pick up artifact email: {with_hmac}"
        );
        assert!(
            with_hmac.contains(&format!("server = \"{OVERRIDE_SERVER}\"")),
            "existing agent.toml must pick up artifact server: {with_hmac}"
        );
        assert!(
            with_hmac.contains(&format!("http_responder_url = \"{OVERRIDE_RESPONDER}\"")),
            "existing agent.toml must pick up artifact responder: {with_hmac}"
        );
        assert!(
            with_hmac.contains("directory_fetch_attempts = 10"),
            "existing agent.toml must backfill [acme] retry tunables: {with_hmac}"
        );
        assert!(
            with_hmac.contains("http_responder_timeout_secs = 5"),
            "existing agent.toml must backfill [acme] timeout tunables: {with_hmac}"
        );
        assert!(
            !with_hmac.contains("prior-hmac"),
            "hmac must be rotated by the upsert: {with_hmac}"
        );
    }

    /// Companion regression for Round 5: when no override flows in from
    /// the artifact (`agent_*_override == None`, e.g. the upstream
    /// service-add did not pass `--agent-*`), operator-customised
    /// `server` / `email` / `http_responder_url` values in the existing
    /// `agent.toml` must survive untouched — the backfill path is
    /// "insert if missing", never "clobber".
    #[test]
    fn existing_agent_config_preserves_operator_values_when_no_override() {
        const OPERATOR_EMAIL: &str = "admin@acme.example";
        const OPERATOR_SERVER: &str = "https://step-ca.acme.example:8443/acme/acme/directory";
        const OPERATOR_RESPONDER: &str = "http://responder.acme.example:7000";

        let pre_existing = format!(
            "email = \"{OPERATOR_EMAIL}\"\n\
             server = \"{OPERATOR_SERVER}\"\n\
             domain = \"trusted.domain\"\n\n\
             [acme]\n\
             http_responder_url = \"{OPERATOR_RESPONDER}\"\n\
             http_responder_hmac = \"prior-hmac\"\n"
        );

        let args = test_bootstrap_args();
        assert!(
            args.agent_email_override.is_none(),
            "test precondition: default args have no override"
        );

        let backfilled = apply_agent_config_baseline_defaults(
            &pre_existing,
            &AgentConfigBaselineParams {
                email: &args.agent_email,
                server: &args.agent_server,
                domain: &args.agent_domain,
                http_responder_url: &args.agent_responder_url,
            },
        )
        .unwrap();
        let overridden = apply_agent_overrides(
            &backfilled,
            args.agent_email_override.as_deref(),
            args.agent_server_override.as_deref(),
            args.agent_responder_url_override.as_deref(),
        )
        .unwrap();

        assert!(
            overridden.contains(&format!("email = \"{OPERATOR_EMAIL}\"")),
            "operator email must survive backfill: {overridden}"
        );
        assert!(
            overridden.contains(&format!("server = \"{OPERATOR_SERVER}\"")),
            "operator server must survive backfill: {overridden}"
        );
        assert!(
            overridden.contains(&format!("http_responder_url = \"{OPERATOR_RESPONDER}\"")),
            "operator responder must survive backfill: {overridden}"
        );
        assert!(
            !overridden.contains(&args.agent_server),
            "backfill must not introduce the localhost default server: {overridden}"
        );
    }
}
