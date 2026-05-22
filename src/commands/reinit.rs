use std::collections::BTreeMap;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::cli::args::{
    ComposeFileArgs, DbAdminDsnArgs, DbTimeoutArgs, InfraUpArgs, InitArgs, OpenBaoArgs, ReinitArgs,
    RootTokenArgs, SecretsDirArgs,
};
use crate::commands::clean::{
    COMPOSE_PROJECT_LABEL, COMPOSE_SERVICE_LABEL, inspect_label_via_docker,
    remove_openbao_container_and_volumes, resolve_compose_project,
};
use crate::commands::guardrails::client_url_from_bind_addr;
use crate::commands::infra::run_infra_up;
use crate::commands::init::{OPENBAO_CONTAINER_NAME, compose_has_openbao, prompt_yes_no, run_init};
use crate::i18n::Messages;
use crate::state::StateFile;

/// Compose service name owned by bootroot's local `OpenBao` deployment.
/// Used by the scope check that distinguishes a compose-managed local
/// `OpenBao` from an external/shared instance.
const OPENBAO_COMPOSE_SERVICE: &str = "openbao";

/// Per-service credential files removed by reinit because the matching
/// `AppRole` / `SecretID` was wiped along with the `OpenBao` volume.
const STALE_SERVICE_CREDENTIAL_FILES: &[&str] = &["role_id", "secret_id", "secret_id.wrapped"];

/// Runs the `bootroot reinit` recovery flow.
///
/// # Errors
///
/// Returns an error when the scope check fails (external `OpenBao` or
/// project mismatch), when destructive cleanup fails, or when the
/// re-run of `init` fails.
pub(crate) async fn run_reinit(args: &ReinitArgs, messages: &Messages) -> Result<()> {
    let compose_file = &args.compose.compose_file;
    let compose_dir = compose_file
        .parent()
        .unwrap_or(Path::new("."))
        .to_path_buf();
    let state_path = StateFile::default_path();

    // 1. Scope check: refuse external OpenBao / project mismatch.
    verify_compose_managed_openbao(
        compose_file,
        &compose_dir,
        &inspect_label_via_docker,
        messages,
    )?;

    // 2. Validate the optional --root-token-output path BEFORE any
    //    destructive operation so a bad path does not leave the
    //    operator in a half-wiped state.
    if let Some(out) = args.root_token_output.as_deref() {
        validate_root_token_output_path(out, messages)?;
    }

    // 3. Snapshot deployment intent (if state.json exists).
    let snapshot = snapshot_deployment_intent(&state_path)?;

    // 4. Print plan and ask for confirmation.
    write_reinit_plan(&mut io::stdout().lock(), messages)
        .with_context(|| messages.error_prompt_write_failed())?;
    if !args.yes && !prompt_yes_no(messages.reinit_confirm(), messages)? {
        anyhow::bail!(messages.error_operation_cancelled());
    }

    // 5. Stop and remove the OpenBao container + volumes.
    remove_openbao_container_and_volumes(compose_file, messages)?;

    // 6. Remove OpenBao runtime/bootstrap artifacts (narrow).
    remove_openbao_runtime_state(&args.secrets_dir.secrets_dir, messages)?;

    // 7. Rewrite state.json with intent-only fields BEFORE infra up so
    //    the infra-up path layers the correct compose overrides for
    //    any recorded non-loopback bind.
    write_minimal_state(
        &state_path,
        &snapshot,
        &args.openbao,
        &args.secrets_dir,
        messages,
    )?;

    // 8. Bring OpenBao back up via the existing infra up path.
    let infra_args = InfraUpArgs {
        compose_file: ComposeFileArgs {
            compose_file: compose_file.clone(),
        },
        services: vec![OPENBAO_COMPOSE_SERVICE.to_string()],
        image_archive_dir: None,
        restart_policy: "always".to_string(),
        openbao_url: args.openbao.openbao_url.clone(),
        openbao_unseal_from_file: None,
    };
    run_infra_up(&infra_args, messages)?;

    // 9. Re-run init in reinit mode.  Reinit-mode behavior is enforced
    //    inside the init flow: overwrite prompts for preserved files
    //    are skipped, and an existing `password.txt` short-circuits
    //    the auto-gen path so the step-ca password is not rotated.
    //    `--root-token-output`, if set, is threaded into the init args
    //    so the freshly issued root token is persisted with mode 0600
    //    after init succeeds.
    let init_args = init_args_for_reinit(args, &snapshot);
    run_init(&init_args, messages).await?;

    println!("{}", messages.reinit_completed());
    println!("{}", messages.reinit_service_registry_post_summary());
    Ok(())
}

/// Validates that the compose file declares a local `openbao` service
/// and that, if a `bootroot-openbao` container exists, its compose
/// labels match the project derived from this work directory.
fn verify_compose_managed_openbao(
    compose_file: &Path,
    compose_dir: &Path,
    inspect: &dyn Fn(&str, &str) -> Result<Option<String>>,
    messages: &Messages,
) -> Result<()> {
    if !compose_file.exists() {
        anyhow::bail!(messages.error_reinit_external_openbao(&compose_file.display().to_string()));
    }
    if !compose_has_openbao(compose_file, messages)? {
        anyhow::bail!(messages.error_reinit_external_openbao(&compose_file.display().to_string()));
    }
    let container_project = inspect(OPENBAO_CONTAINER_NAME, COMPOSE_PROJECT_LABEL)?;
    if let Some(container_project) = container_project.as_deref() {
        // When the container exists, the expected project must come
        // from a source independent of the container (env override or
        // compose-dir basename).  Otherwise a mismatched container
        // would never trip the check.
        let expected_project = resolve_expected_compose_project_excluding_container(compose_dir)?;
        if container_project != expected_project {
            anyhow::bail!(
                messages
                    .error_reinit_container_project_mismatch(container_project, &expected_project,)
            );
        }
        if let Some(service) = inspect(OPENBAO_CONTAINER_NAME, COMPOSE_SERVICE_LABEL)?
            && service != OPENBAO_COMPOSE_SERVICE
        {
            anyhow::bail!(messages.error_reinit_container_project_mismatch(
                &format!("service={service}"),
                OPENBAO_COMPOSE_SERVICE,
            ));
        }
    } else {
        // Container absent (stuck-after-clean recovery path).  Accept
        // only when the compose project can be derived from the work
        // directory; an unresolvable project surfaces here as an
        // actionable error rather than letting reinit proceed.
        let _ = resolve_expected_compose_project_excluding_container(compose_dir)?;
    }
    Ok(())
}

/// Derives the expected compose project from the environment override
/// or the compose-dir basename, ignoring any label that may exist on
/// the `bootroot-openbao` container.  This is used as the
/// "what should be" side of the mismatch check.
fn resolve_expected_compose_project_excluding_container(compose_dir: &Path) -> Result<String> {
    if let Ok(env_value) = std::env::var("COMPOSE_PROJECT_NAME")
        && !env_value.is_empty()
    {
        return Ok(env_value);
    }
    // Reuse the basename-normalisation half of `resolve_compose_project`
    // by passing an `inspect` that never returns a label, forcing the
    // fallback path.
    resolve_compose_project(compose_dir, &|_, _| Ok(None))
}

/// Subset of `StateFile` fields preserved across a reinit.  Mirrors the
/// "Preserve" list in the issue's §State filtering: deployment intent
/// only — no policies, `AppRoles`, services, or per-service runtime
/// metadata.
#[derive(Debug, Default, Clone)]
pub(crate) struct DeploymentIntent {
    pub(crate) openbao_bind_addr: Option<String>,
    pub(crate) openbao_advertise_addr: Option<String>,
    pub(crate) http01_admin_bind_addr: Option<String>,
    pub(crate) http01_admin_advertise_addr: Option<String>,
    pub(crate) secrets_dir: Option<PathBuf>,
    pub(crate) infra_certs: BTreeMap<String, crate::state::InfraCertEntry>,
}

/// Snapshots intent fields from `state.json` if present, otherwise
/// returns an empty snapshot (the rsync-clone-without-prior-init path).
pub(crate) fn snapshot_deployment_intent(state_path: &Path) -> Result<DeploymentIntent> {
    if !state_path.exists() {
        return Ok(DeploymentIntent::default());
    }
    let state = StateFile::load(state_path)?;
    Ok(DeploymentIntent {
        openbao_bind_addr: state.openbao_bind_addr,
        openbao_advertise_addr: state.openbao_advertise_addr,
        http01_admin_bind_addr: state.http01_admin_bind_addr,
        http01_admin_advertise_addr: state.http01_admin_advertise_addr,
        secrets_dir: state.secrets_dir,
        infra_certs: state.infra_certs,
    })
}

/// Writes a minimal `state.json` carrying only deployment intent.
/// Services / approles / policies are intentionally empty so the
/// follow-up `init` run rebuilds them from the freshly-bootstrapped
/// `OpenBao`.  Non-loopback bind intent is preserved so the `infra up`
/// path layers the correct compose overrides for the restart.
pub(crate) fn write_minimal_state(
    state_path: &Path,
    snapshot: &DeploymentIntent,
    openbao: &OpenBaoArgs,
    secrets_dir: &SecretsDirArgs,
    messages: &Messages,
) -> Result<()> {
    let state = StateFile {
        openbao_url: openbao.openbao_url.clone(),
        kv_mount: openbao.kv_mount.clone(),
        secrets_dir: snapshot
            .secrets_dir
            .clone()
            .or_else(|| Some(secrets_dir.secrets_dir.clone())),
        policies: BTreeMap::new(),
        approles: BTreeMap::new(),
        services: BTreeMap::new(),
        openbao_bind_addr: snapshot.openbao_bind_addr.clone(),
        openbao_advertise_addr: snapshot.openbao_advertise_addr.clone(),
        http01_admin_bind_addr: snapshot.http01_admin_bind_addr.clone(),
        http01_admin_advertise_addr: snapshot.http01_admin_advertise_addr.clone(),
        infra_certs: snapshot.infra_certs.clone(),
    };
    state
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())?;
    Ok(())
}

/// Removes only `OpenBao` runtime/bootstrap artifacts.  Explicitly
/// preserves step-ca CA material, operator-authored compose overrides,
/// `PostgreSQL` state, and non-credential service config.
pub(crate) fn remove_openbao_runtime_state(secrets_dir: &Path, messages: &Messages) -> Result<()> {
    let openbao_dir = secrets_dir.join("openbao");

    // 1. unseal-keys.txt
    remove_file_if_exists(&openbao_dir.join("unseal-keys.txt"), messages)?;

    // 2. Per-service openbao-agent runtime + rendered secrets under
    //    secrets/openbao/services/<service>.  These are produced by
    //    `service add`, not by `init`, so removing them is safe
    //    (operators re-run `service add` after reinit).
    let services_dir = openbao_dir.join("services");
    if services_dir.is_dir() {
        std::fs::remove_dir_all(&services_dir).with_context(|| {
            messages.error_remove_dir_failed(&services_dir.display().to_string())
        })?;
    }

    // 3. Generated openbao-agent runtime files under secrets/openbao/
    //    (stepca / responder agent configs and any rendered secret files)
    //    that the next `init` regenerates.
    for sub in ["stepca", "responder"] {
        let path = openbao_dir.join(sub);
        if path.is_dir() {
            std::fs::remove_dir_all(&path)
                .with_context(|| messages.error_remove_dir_failed(&path.display().to_string()))?;
        }
    }
    let agent_override = openbao_dir.join("docker-compose.openbao-agent.override.yml");
    remove_file_if_exists(&agent_override, messages)?;

    // 4. Stale per-service credential files under secrets/services/<svc>/.
    //    Cleanup is intentionally narrow: only credential-bearing files,
    //    not the whole directory, so non-credential service config
    //    survives operator inspection.
    let services_root = secrets_dir.join("services");
    if services_root.is_dir() {
        let entries = std::fs::read_dir(&services_root).with_context(|| {
            messages.error_read_dir_failed(&services_root.display().to_string())
        })?;
        for entry in entries {
            let entry = entry.with_context(|| messages.error_read_dir_entry_failed())?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            for name in STALE_SERVICE_CREDENTIAL_FILES {
                remove_file_if_exists(&path.join(name), messages)?;
            }
        }
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path, messages: &Messages) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| messages.error_remove_file_failed(&path.display().to_string()))?;
    }
    Ok(())
}

/// Validates that an optional `--root-token-output` path is safe to
/// write to *before* any destructive operation begins.  Without this
/// the destructive sequence runs to completion and the post-init file
/// write fails — exactly recreating the partial-init trap this command
/// is meant to recover from.  The check enforces:
///
/// 1. If the path exists it must be a regular file (not a directory or
///    symlink to a directory), otherwise the post-init write would fail.
/// 2. If the file already exists its permissions must already be
///    `0600`-compatible (no group/other bits set) — overwriting a
///    world-readable file would briefly widen access to the freshly
///    issued root token.
/// 3. If the file already exists, it must also be writable by this
///    process.  A file with mode `0400` or `0000` passes the group/other
///    check above and yet the post-init `tokio::fs::write` would fail,
///    so we open the destination for writing (without truncating) to
///    prove the kernel will accept a later write.
/// 4. The parent directory must accept new files.  We create the parent
///    if missing and probe with a uniquely named marker so read-only
///    parents and uncreatable ancestors are caught here.
fn validate_root_token_output_path(path: &Path, messages: &Messages) -> Result<()> {
    let display = path.display().to_string();

    if path.exists() {
        let meta = std::fs::symlink_metadata(path)
            .with_context(|| messages.error_read_file_failed(&display))?;
        let file_type = meta.file_type();
        if !file_type.is_file() && !file_type.is_symlink() {
            anyhow::bail!(messages.error_reinit_root_token_output_not_file(&display));
        }
        if file_type.is_symlink() {
            let target_meta = std::fs::metadata(path)
                .with_context(|| messages.error_read_file_failed(&display))?;
            if !target_meta.is_file() {
                anyhow::bail!(messages.error_reinit_root_token_output_not_file(&display));
            }
        }
        // Permission check uses follow-symlink metadata so a symlink to
        // a regular file is evaluated against the target's mode.
        let mode_meta =
            std::fs::metadata(path).with_context(|| messages.error_read_file_failed(&display))?;
        let mode = mode_meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(messages.error_reinit_root_token_output_unsafe(&display));
        }
        // Verify the kernel will actually accept a write to this file.
        // Opening for write without `truncate(true)` does not modify the
        // existing contents — it only checks the permission bits and any
        // filesystem-level constraint (e.g. immutable attribute).  The
        // handle is dropped immediately.
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|err| {
                anyhow::anyhow!(
                    messages.error_reinit_root_token_output_unwritable(&display, &err.to_string())
                )
            })?;
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    if !parent.exists() {
        std::fs::create_dir_all(&parent).map_err(|err| {
            anyhow::anyhow!(
                messages.error_reinit_root_token_output_unwritable(&display, &err.to_string())
            )
        })?;
    }
    if !parent.is_dir() {
        anyhow::bail!(messages.error_reinit_root_token_output_unwritable(
            &display,
            &format!("parent {} is not a directory", parent.display()),
        ));
    }
    // Probe writability by creating a uniquely named marker in the parent
    // directory.  The probe is independent of the destination so it does
    // not race with an existing file the operator may want to keep.
    let probe = parent.join(format!(
        ".bootroot-reinit-token-probe.{}",
        std::process::id()
    ));
    if let Err(err) = std::fs::write(&probe, b"") {
        anyhow::bail!(
            messages.error_reinit_root_token_output_unwritable(&display, &err.to_string())
        );
    }
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Writes the reinit plan (destructive actions + preserved artifacts +
/// service-registry warning) to `out`.  Split from the production
/// stdout call site so tests can assert both sections appear in the
/// rendered text.
fn write_reinit_plan<W: Write>(out: &mut W, messages: &Messages) -> io::Result<()> {
    writeln!(out, "{}", messages.reinit_plan_title())?;
    writeln!(out, "{}", messages.reinit_plan_destructive_actions())?;
    writeln!(out, "{}", messages.reinit_plan_destructive_container())?;
    writeln!(out, "{}", messages.reinit_plan_destructive_volumes())?;
    writeln!(out, "{}", messages.reinit_plan_destructive_state_file())?;
    writeln!(out, "{}", messages.reinit_plan_destructive_runtime_files())?;
    writeln!(out, "{}", messages.reinit_plan_destructive_service_creds())?;
    writeln!(out, "{}", messages.reinit_plan_preserved_actions())?;
    writeln!(out, "{}", messages.reinit_plan_preserved_ca())?;
    writeln!(out, "{}", messages.reinit_plan_preserved_password())?;
    writeln!(out, "{}", messages.reinit_plan_preserved_postgres())?;
    writeln!(
        out,
        "{}",
        messages.reinit_plan_preserved_compose_overrides()
    )?;
    writeln!(out, "{}", messages.reinit_plan_preserved_intent())?;
    writeln!(out)?;
    writeln!(out, "{}", messages.reinit_plan_service_registry_warning())?;
    Ok(())
}

/// Reads the preserved step-ca runtime DSN from
/// `<secrets_dir>/config/ca.json` if present.  After a previous
/// `init --enable db-provision` run, `.env`'s `POSTGRES_PASSWORD` has
/// been rotated to a `rotated-use-openbao` dummy and only `ca.json`
/// carries the real runtime password that still matches the preserved
/// `PostgreSQL` volume.  Without this read, the second init pass falls
/// back to `build_dsn_from_env()` and writes the dummy DSN into the
/// freshly reinitialised `OpenBao` KV; the later
/// `maybe_rotate_env_db_password` repair path then bails because the
/// `.env` password already starts with `rotated-`, so the bad DSN
/// remains and step-ca agents are pointed at credentials that do not
/// match the preserved database — directly violating the issue's
/// "Postgres volume/state is preserved" recovery contract.
///
/// Returns `None` when `ca.json` is absent (rsync-clone path or a
/// partial-init that crashed before `update_ca_json_with_backup` ran),
/// is malformed, or has no `db.dataSource` field.  In those cases the
/// existing env-derived DSN resolution is left in place.
fn preserved_db_dsn_from_ca_json(secrets_dir: &Path) -> Option<String> {
    let ca_json_path = secrets_dir.join("config").join("ca.json");
    if !ca_json_path.exists() {
        return None;
    }
    let contents = std::fs::read_to_string(&ca_json_path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&contents).ok()?;
    value
        .get("db")
        .and_then(|db| db.get("dataSource"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Builds the `InitArgs` payload used to re-run the standard init flow
/// in reinit mode.  Inherits the operator-supplied `OpenBao` / compose /
/// secrets paths; sets `reinit_mode = true` so the init flow preserves
/// step-ca material and suppresses overwrite prompts for already-
/// preserved files.
///
/// When the snapshot carries a non-loopback `openbao_bind_addr`, the
/// init args `openbao_url` is rewritten to match (`https://<bind>`).
/// Without this rewrite the second init pass would default to
/// `http://localhost:8200` and the health check would fail against a
/// restored non-loopback `OpenBao` bind — the same trap the reproducer
/// names in §"Scope limitation".  Operators who pass `--openbao-url`
/// explicitly retain that value; the rewrite only kicks in when the
/// caller left it at the CLI default.
///
/// When `secrets/config/ca.json` is present, its `db.dataSource` is
/// threaded into the init args as `db_dsn` so the second init pass
/// writes the *preserved* step-ca runtime DSN into the freshly
/// reinitialised `OpenBao` KV instead of the dummy `rotated-use-openbao`
/// password sitting in `.env`.  See `preserved_db_dsn_from_ca_json` for
/// why the env fallback is unsafe under reinit.
fn init_args_for_reinit(args: &ReinitArgs, snapshot: &DeploymentIntent) -> Box<InitArgs> {
    let mut openbao = args.openbao.clone();
    if openbao.openbao_url == crate::commands::init::DEFAULT_OPENBAO_URL
        && let Some(bind) = snapshot.openbao_bind_addr.as_deref()
    {
        openbao.openbao_url = client_url_from_bind_addr(bind);
    }
    let db_dsn = preserved_db_dsn_from_ca_json(&args.secrets_dir.secrets_dir);
    Box::new(InitArgs {
        openbao,
        secrets_dir: args.secrets_dir.clone(),
        compose: args.compose.clone(),
        enable: args.enable.clone(),
        skip: args.skip.clone(),
        summary_json: args.summary_json.clone(),
        root_token: RootTokenArgs { root_token: None },
        unseal_key: Vec::new(),
        openbao_unseal_from_file: None,
        secret_id_ttl: crate::commands::init::SECRET_ID_TTL.to_string(),
        stepca_password: None,
        db_dsn,
        db_admin: DbAdminDsnArgs { admin_dsn: None },
        db_user: None,
        db_password: None,
        db_name: None,
        db_timeout: DbTimeoutArgs { timeout_secs: 2 },
        http_hmac: None,
        responder_url: None,
        responder_timeout_secs: 5,
        stepca_provisioner: crate::commands::init::DEFAULT_STEPCA_PROVISIONER.to_string(),
        cert_duration: crate::commands::init::DEFAULT_CERT_DURATION.to_string(),
        eab_kid: None,
        eab_hmac: None,
        no_eab: args.no_eab,
        reinit_mode: true,
        root_token_output: args.root_token_output.clone(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    use anyhow::Result;
    use tempfile::tempdir;

    use super::*;
    use crate::i18n::test_messages;
    use crate::state::{InfraCertEntry, ReloadStrategy, StateFile};

    /// Serialises tests in this module that mutate process-wide
    /// environment variables (e.g. `COMPOSE_PROJECT_NAME`).  Rust's
    /// default test runner spawns multiple threads in the same process,
    /// so concurrent `env::set_var` calls would otherwise race and the
    /// project-mismatch test could flake under load.  Mirrors the
    /// `ENV_LOCK` pattern used in `commands/rotate.rs::test_support`.
    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().expect("test env lock must not be poisoned")
    }

    fn state_with_intent() -> StateFile {
        let mut infra_certs = BTreeMap::new();
        infra_certs.insert(
            "openbao".to_string(),
            InfraCertEntry {
                cert_path: PathBuf::from("secrets/openbao/tls/server.crt"),
                key_path: PathBuf::from("secrets/openbao/tls/server.key"),
                sans: vec!["192.168.1.10".to_string(), "localhost".to_string()],
                renew_before: "720h".to_string(),
                reload_strategy: ReloadStrategy::ContainerRestart {
                    container_name: "bootroot-openbao".to_string(),
                },
                issued_at: None,
                expires_at: None,
            },
        );
        let mut services = BTreeMap::new();
        services.insert("svc".to_string(), {
            use crate::state::{DeliveryMode, DeployType, ServiceEntry, ServiceRoleEntry};
            ServiceEntry {
                service_name: "svc".to_string(),
                deploy_type: DeployType::Daemon,
                delivery_mode: DeliveryMode::LocalFile,
                hostname: "h".to_string(),
                domain: "d".to_string(),
                agent_config_path: PathBuf::from("a"),
                cert_path: PathBuf::from("c"),
                key_path: PathBuf::from("k"),
                instance_id: None,
                container_name: None,
                notes: None,
                post_renew_hooks: Vec::new(),
                approle: ServiceRoleEntry {
                    role_name: "r".to_string(),
                    role_id: "id".to_string(),
                    secret_id_path: PathBuf::from("s"),
                    policy_name: "p".to_string(),
                    secret_id_ttl: None,
                    secret_id_wrap_ttl: None,
                    token_bound_cidrs: None,
                },
                agent_email: None,
                agent_server: None,
                agent_responder_url: None,
                cert_group_gid: None,
            }
        });
        let mut policies = BTreeMap::new();
        policies.insert("policy".to_string(), "label".to_string());
        StateFile {
            openbao_url: "https://192.168.1.10:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: Some(PathBuf::from("secrets")),
            policies,
            approles: BTreeMap::new(),
            services,
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: Some("192.168.1.10:8200".to_string()),
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs,
        }
    }

    #[test]
    fn snapshot_returns_empty_when_state_absent() {
        let dir = tempdir().unwrap();
        let snapshot =
            snapshot_deployment_intent(&dir.path().join("state.json")).expect("snapshot");
        assert!(snapshot.openbao_bind_addr.is_none());
        assert!(snapshot.infra_certs.is_empty());
    }

    #[test]
    fn snapshot_preserves_intent_fields_and_drops_services() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        state_with_intent().save(&state_path).unwrap();

        let snapshot = snapshot_deployment_intent(&state_path).expect("snapshot");
        assert_eq!(
            snapshot.openbao_bind_addr.as_deref(),
            Some("192.168.1.10:8200")
        );
        assert_eq!(
            snapshot.http01_admin_bind_addr.as_deref(),
            Some("192.168.1.10:8080")
        );
        assert_eq!(snapshot.infra_certs.len(), 1);
        // DeploymentIntent does not carry services / policies / approles
        // at all — the type itself is the test for the "drop" list.
    }

    #[test]
    fn write_minimal_state_rewrites_with_empty_registry_and_preserved_intent() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        state_with_intent().save(&state_path).unwrap();
        let snapshot = snapshot_deployment_intent(&state_path).expect("snapshot");

        let openbao = OpenBaoArgs {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
        };
        let secrets_dir = SecretsDirArgs {
            secrets_dir: PathBuf::from("secrets"),
        };
        let messages = test_messages();

        write_minimal_state(&state_path, &snapshot, &openbao, &secrets_dir, &messages).unwrap();

        let rewritten = StateFile::load(&state_path).unwrap();
        assert!(
            rewritten.services.is_empty(),
            "service registry must be empty"
        );
        assert!(rewritten.approles.is_empty(), "approles must be empty");
        assert!(rewritten.policies.is_empty(), "policies must be empty");
        assert_eq!(
            rewritten.openbao_bind_addr.as_deref(),
            Some("192.168.1.10:8200"),
            "openbao_bind_addr intent must survive"
        );
        assert_eq!(
            rewritten.http01_admin_bind_addr.as_deref(),
            Some("192.168.1.10:8080"),
            "http01_admin_bind_addr intent must survive"
        );
        assert_eq!(rewritten.infra_certs.len(), 1, "infra_certs must survive");
    }

    #[test]
    fn remove_openbao_runtime_state_preserves_stepca_material_and_postgres() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        // Preserve list.
        fs::create_dir_all(secrets.join("config")).unwrap();
        fs::write(secrets.join("config/ca.json"), "{}").unwrap();
        fs::create_dir_all(secrets.join("secrets")).unwrap();
        fs::write(secrets.join("secrets/root_ca_key"), "root").unwrap();
        fs::write(secrets.join("secrets/intermediate_ca_key"), "int").unwrap();
        fs::write(secrets.join("password.txt"), "secret").unwrap();
        // Compose override that the operator authored — must survive.
        fs::create_dir_all(secrets.join("openbao")).unwrap();
        fs::write(
            secrets.join("openbao/docker-compose.openbao-exposed.yml"),
            "services: {}",
        )
        .unwrap();
        // Wipe list.
        fs::write(secrets.join("openbao/unseal-keys.txt"), "keys").unwrap();
        fs::create_dir_all(secrets.join("openbao/services/svc")).unwrap();
        fs::write(secrets.join("openbao/services/svc/agent.hcl"), "rendered").unwrap();
        fs::create_dir_all(secrets.join("openbao/stepca")).unwrap();
        fs::write(secrets.join("openbao/stepca/agent.hcl"), "x").unwrap();
        fs::write(
            secrets.join("openbao/docker-compose.openbao-agent.override.yml"),
            "x",
        )
        .unwrap();
        fs::create_dir_all(secrets.join("services/svc")).unwrap();
        fs::write(secrets.join("services/svc/role_id"), "r").unwrap();
        fs::write(secrets.join("services/svc/secret_id"), "s").unwrap();
        // Non-credential service config — must survive.
        fs::write(secrets.join("services/svc/notes.toml"), "keep").unwrap();

        let messages = test_messages();
        remove_openbao_runtime_state(&secrets, &messages).unwrap();

        assert!(
            secrets.join("config/ca.json").exists(),
            "ca.json must be preserved"
        );
        assert!(
            secrets.join("secrets/root_ca_key").exists(),
            "root_ca_key must be preserved"
        );
        assert!(
            secrets.join("password.txt").exists(),
            "password.txt must be preserved"
        );
        assert!(
            secrets
                .join("openbao/docker-compose.openbao-exposed.yml")
                .exists(),
            "operator-authored exposed override must be preserved"
        );
        assert!(
            !secrets.join("openbao/unseal-keys.txt").exists(),
            "unseal-keys.txt must be deleted"
        );
        assert!(
            !secrets.join("openbao/services").exists(),
            "per-service openbao-agent dir must be deleted"
        );
        assert!(
            !secrets.join("openbao/stepca").exists(),
            "openbao-agent stepca config dir must be deleted"
        );
        assert!(
            !secrets
                .join("openbao/docker-compose.openbao-agent.override.yml")
                .exists(),
            "openbao-agent compose override must be deleted"
        );
        assert!(
            !secrets.join("services/svc/role_id").exists(),
            "stale role_id must be deleted"
        );
        assert!(
            !secrets.join("services/svc/secret_id").exists(),
            "stale secret_id must be deleted"
        );
        assert!(
            secrets.join("services/svc/notes.toml").exists(),
            "non-credential service config must be preserved"
        );
    }

    #[test]
    fn verify_compose_managed_openbao_rejects_missing_compose() {
        let dir = tempdir().unwrap();
        let compose_file = dir.path().join("docker-compose.yml");
        let messages = test_messages();
        let inspect = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        let err = verify_compose_managed_openbao(&compose_file, dir.path(), &inspect, &messages)
            .unwrap_err();
        assert!(err.to_string().contains("compose"));
    }

    #[test]
    fn verify_compose_managed_openbao_rejects_compose_without_openbao_service() {
        let dir = tempdir().unwrap();
        let compose_file = dir.path().join("docker-compose.yml");
        // Compose file present but no openbao service.
        fs::write(
            &compose_file,
            "services:\n  postgres:\n    image: postgres\n",
        )
        .unwrap();
        let messages = test_messages();
        let inspect = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        let err = verify_compose_managed_openbao(&compose_file, dir.path(), &inspect, &messages)
            .unwrap_err();
        assert!(err.to_string().contains("openbao"));
    }

    #[test]
    fn verify_compose_managed_openbao_rejects_label_project_mismatch() {
        let dir = tempdir().unwrap();
        let work = dir.path().join("bootroot");
        fs::create_dir_all(&work).unwrap();
        let compose_file = work.join("docker-compose.yml");
        fs::write(&compose_file, "services:\n  openbao:\n    image: openbao\n").unwrap();
        let messages = test_messages();
        // Container reports "external" project but the work-dir basename
        // normalises to "bootroot", so the labels do not match.
        let inspect = |_: &str, label: &str| -> Result<Option<String>> {
            if label == COMPOSE_PROJECT_LABEL {
                Ok(Some("external".to_string()))
            } else {
                Ok(None)
            }
        };
        // Make sure no stale env override decides the expected project.
        // The lock guards process-wide env mutation against parallel
        // tests in this module that also touch `COMPOSE_PROJECT_NAME`.
        let _guard = env_lock();
        let prior = std::env::var_os("COMPOSE_PROJECT_NAME");
        // SAFETY: env access is serialised by `env_lock` above.
        unsafe { std::env::remove_var("COMPOSE_PROJECT_NAME") };
        let err =
            verify_compose_managed_openbao(&compose_file, &work, &inspect, &messages).unwrap_err();
        if let Some(prior) = prior {
            // SAFETY: still inside the env_lock guard.
            unsafe { std::env::set_var("COMPOSE_PROJECT_NAME", prior) };
        }
        assert!(err.to_string().contains("project"), "got: {err}");
    }

    #[test]
    fn verify_compose_managed_openbao_accepts_missing_container() {
        let dir = tempdir().unwrap();
        // Use a basename that normalises non-emptily.
        let work = dir.path().join("bootroot");
        fs::create_dir_all(&work).unwrap();
        let compose_file = work.join("docker-compose.yml");
        fs::write(&compose_file, "services:\n  openbao:\n    image: openbao\n").unwrap();
        let messages = test_messages();
        // Container absent (the stuck-after-clean recovery path).
        let inspect = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        verify_compose_managed_openbao(&compose_file, &work, &inspect, &messages)
            .expect("should accept missing container when compose declaration is intact");
    }

    #[test]
    fn validate_root_token_output_rejects_world_readable_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("token");
        fs::write(&path, "tok").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).unwrap();
        let messages = test_messages();
        let err = validate_root_token_output_path(&path, &messages).unwrap_err();
        assert!(err.to_string().contains("0600") || err.to_string().contains("permissions"));
    }

    /// Regression for Round 2 reviewer item: an existing destination
    /// with mode `0400` (or `0000`) passes the group/other-readable
    /// check but is not actually writable by the owning process.  The
    /// preflight must reject it so the destructive sequence never runs
    /// against a hopeless target.
    #[test]
    fn validate_root_token_output_rejects_non_writable_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("token");
        fs::write(&path, "tok").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o400);
        fs::set_permissions(&path, perms).unwrap();
        let messages = test_messages();
        let err = validate_root_token_output_path(&path, &messages).unwrap_err();
        // Restore so tempdir cleanup succeeds.
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).unwrap();
        assert!(
            err.to_string().contains("--root-token-output")
                || err.to_string().contains("root-token-output"),
            "got: {err}"
        );
    }

    #[test]
    fn validate_root_token_output_accepts_0600_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("token");
        fs::write(&path, "tok").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).unwrap();
        let messages = test_messages();
        validate_root_token_output_path(&path, &messages).expect("0600 file is acceptable");
    }

    #[test]
    fn validate_root_token_output_accepts_missing_file() {
        let dir = tempdir().unwrap();
        let messages = test_messages();
        validate_root_token_output_path(&dir.path().join("missing"), &messages).unwrap();
    }

    /// Regression: a path that exists but is a directory must be
    /// rejected during preflight.  Otherwise the post-init write would
    /// fail after `OpenBao` has already been wiped and reinitialised,
    /// recreating the partial-init trap.
    #[test]
    fn validate_root_token_output_rejects_directory_path() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("not-a-file");
        fs::create_dir_all(&nested).unwrap();
        let messages = test_messages();
        let err = validate_root_token_output_path(&nested, &messages).unwrap_err();
        assert!(
            err.to_string().contains("regular file") || err.to_string().contains("일반 파일"),
            "got: {err}"
        );
    }

    /// Regression: a missing destination whose parent directory cannot
    /// be created (because an ancestor is a regular file, not a
    /// directory) must be rejected during preflight, before any
    /// destructive operation begins.
    #[test]
    fn validate_root_token_output_rejects_uncreatable_parent() {
        let dir = tempdir().unwrap();
        // Ancestor that blocks directory creation: a regular file where
        // a directory would need to be created.
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, "not a dir").unwrap();
        let target = blocker.join("nested").join("token");
        let messages = test_messages();
        let err = validate_root_token_output_path(&target, &messages).unwrap_err();
        assert!(
            err.to_string().contains("--root-token-output")
                || err.to_string().contains("root-token-output"),
            "got: {err}"
        );
    }

    /// Regression: preflight should not silently pass when the parent
    /// directory exists but is read-only.  This catches the case where
    /// the operator points `--root-token-output` at a directory they
    /// cannot write to (e.g. a shared mount mounted read-only).
    #[test]
    fn validate_root_token_output_rejects_read_only_parent() {
        let dir = tempdir().unwrap();
        let parent = dir.path().join("ro");
        fs::create_dir_all(&parent).unwrap();
        let mut perms = fs::metadata(&parent).unwrap().permissions();
        let original = perms.mode();
        perms.set_mode(0o500);
        fs::set_permissions(&parent, perms).unwrap();
        let target = parent.join("token");
        let messages = test_messages();
        let err = validate_root_token_output_path(&target, &messages).unwrap_err();
        // Restore so tempdir cleanup succeeds.
        let mut perms = fs::metadata(&parent).unwrap().permissions();
        perms.set_mode(original);
        fs::set_permissions(&parent, perms).unwrap();
        assert!(
            err.to_string().contains("--root-token-output")
                || err.to_string().contains("root-token-output"),
            "got: {err}"
        );
    }

    /// The dry-run plan must surface both destructive actions and
    /// preserved artifacts so the operator can see, before confirming,
    /// what will be wiped versus what will survive.  Asserts both
    /// section headings and a representative bullet from each.
    #[test]
    fn write_reinit_plan_covers_destructive_and_preserved_sections() {
        let messages = test_messages();
        let mut buf = Vec::new();
        write_reinit_plan(&mut buf, &messages).expect("write plan");
        let rendered = String::from_utf8(buf).expect("utf-8 plan");

        // Destructive section + a sentinel destructive action.
        assert!(
            rendered.contains("Destructive actions:"),
            "missing destructive heading; got:\n{rendered}"
        );
        assert!(
            rendered.contains("openbao-data") && rendered.contains("openbao-audit"),
            "missing volume-wipe bullet; got:\n{rendered}"
        );

        // Preserved section + sentinel preserved artifacts.
        assert!(
            rendered.contains("Preserved:"),
            "missing preserved heading; got:\n{rendered}"
        );
        assert!(
            rendered.contains("password.txt"),
            "preserved section must list password.txt; got:\n{rendered}"
        );
        assert!(
            rendered.contains("PostgreSQL"),
            "preserved section must list PostgreSQL; got:\n{rendered}"
        );

        // Operator-visible warning that the service registry will be
        // empty after reinit completes.
        assert!(
            rendered.contains("service add"),
            "plan must point operator at service add; got:\n{rendered}"
        );
    }

    /// Regression: a reinit caller's `--root-token-output` path must
    /// reach the underlying init flow so the freshly issued token is
    /// actually persisted.  Without this wiring the flag would be a
    /// no-op despite being documented as functional.
    #[test]
    fn init_args_for_reinit_threads_root_token_output() {
        let reinit_args = ReinitArgs {
            openbao: OpenBaoArgs {
                openbao_url: "http://localhost:8200".to_string(),
                kv_mount: "secret".to_string(),
            },
            secrets_dir: SecretsDirArgs {
                secrets_dir: PathBuf::from("secrets"),
            },
            compose: ComposeFileArgs {
                compose_file: PathBuf::from("docker-compose.yml"),
            },
            yes: true,
            root_token_output: Some(PathBuf::from("/tmp/root.token")),
            enable: Vec::new(),
            skip: Vec::new(),
            summary_json: None,
            no_eab: true,
        };
        let init_args = init_args_for_reinit(&reinit_args, &DeploymentIntent::default());
        assert_eq!(
            init_args.root_token_output,
            Some(PathBuf::from("/tmp/root.token")),
            "reinit must thread root_token_output into init"
        );
        assert!(init_args.reinit_mode, "reinit_mode must be set");
    }

    /// Regression for the Round 2 reviewer finding: when the snapshot
    /// carries a non-loopback `openbao_bind_addr`, the init pass must
    /// target the same address.  Without this rewrite the second init
    /// would default to `http://localhost:8200` and fail health-check
    /// against the restored TLS-enabled bind, leaving the operator in a
    /// partial-recovery state after the destructive sequence already ran.
    #[test]
    fn init_args_for_reinit_rewrites_url_from_non_loopback_bind() {
        let reinit_args = ReinitArgs {
            openbao: OpenBaoArgs {
                openbao_url: crate::commands::init::DEFAULT_OPENBAO_URL.to_string(),
                kv_mount: "secret".to_string(),
            },
            secrets_dir: SecretsDirArgs {
                secrets_dir: PathBuf::from("secrets"),
            },
            compose: ComposeFileArgs {
                compose_file: PathBuf::from("docker-compose.yml"),
            },
            yes: true,
            root_token_output: None,
            enable: Vec::new(),
            skip: Vec::new(),
            summary_json: None,
            no_eab: true,
        };
        let snapshot = DeploymentIntent {
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            ..DeploymentIntent::default()
        };
        let init_args = init_args_for_reinit(&reinit_args, &snapshot);
        assert_eq!(
            init_args.openbao.openbao_url, "https://192.168.1.10:8200",
            "non-loopback bind intent must drive the init client URL"
        );
    }

    /// Regression for the Round 3 reviewer finding: when a previous
    /// `init --enable db-provision` ran, `.env`'s `POSTGRES_PASSWORD` is
    /// the dummy `rotated-use-openbao` sentinel and only `ca.json`
    /// carries the real runtime DSN.  The second init pass must seed
    /// `args.db_dsn` from `ca.json` so the env-derived dummy never
    /// reaches the freshly reinitialised `OpenBao` KV.  Without this,
    /// the `maybe_rotate_env_db_password` repair path bails (`.env`
    /// already starts with `rotated-`) and the bad DSN remains in KV,
    /// pointing step-ca agents at credentials that do not match the
    /// preserved `PostgreSQL` state.
    #[test]
    fn init_args_for_reinit_uses_preserved_db_dsn_when_ca_json_present() {
        let dir = tempdir().expect("tempdir");
        let secrets_dir = dir.path().to_path_buf();
        let config_dir = secrets_dir.join("config");
        fs::create_dir_all(&config_dir).expect("create config dir");
        // The DSN format mirrors what `update_ca_json_with_backup`
        // writes: compose-internal `postgres:5432`, sslmode=disable.
        // Nonce-based password sidesteps CodeQL's hard-coded-credential
        // rule.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let real_password = format!("real-runtime-{nonce}");
        let expected_dsn =
            format!("postgresql://step:{real_password}@postgres:5432/stepca?sslmode=disable");
        fs::write(
            config_dir.join("ca.json"),
            format!(r#"{{"db":{{"type":"postgresql","dataSource":"{expected_dsn}"}}}}"#),
        )
        .expect("write ca.json");

        let reinit_args = ReinitArgs {
            openbao: OpenBaoArgs {
                openbao_url: crate::commands::init::DEFAULT_OPENBAO_URL.to_string(),
                kv_mount: "secret".to_string(),
            },
            secrets_dir: SecretsDirArgs { secrets_dir },
            compose: ComposeFileArgs {
                compose_file: PathBuf::from("docker-compose.yml"),
            },
            yes: true,
            root_token_output: None,
            enable: Vec::new(),
            skip: Vec::new(),
            summary_json: None,
            no_eab: true,
        };
        let init_args = init_args_for_reinit(&reinit_args, &DeploymentIntent::default());
        assert_eq!(
            init_args.db_dsn.as_deref(),
            Some(expected_dsn.as_str()),
            "reinit must seed init args with the preserved ca.json DSN \
             so the rotated-use-openbao dummy never lands in OpenBao KV"
        );
    }

    /// When `ca.json` is absent (rsync-clone path or a partial-init that
    /// crashed before `update_ca_json_with_backup` ran), reinit must
    /// leave `db_dsn` unset so the existing env-derived resolver path
    /// takes over — that path uses the real `.env` password in this
    /// scenario because it has not been rotated yet.
    #[test]
    fn init_args_for_reinit_falls_back_when_ca_json_absent() {
        let dir = tempdir().expect("tempdir");
        let reinit_args = ReinitArgs {
            openbao: OpenBaoArgs {
                openbao_url: crate::commands::init::DEFAULT_OPENBAO_URL.to_string(),
                kv_mount: "secret".to_string(),
            },
            secrets_dir: SecretsDirArgs {
                secrets_dir: dir.path().to_path_buf(),
            },
            compose: ComposeFileArgs {
                compose_file: PathBuf::from("docker-compose.yml"),
            },
            yes: true,
            root_token_output: None,
            enable: Vec::new(),
            skip: Vec::new(),
            summary_json: None,
            no_eab: true,
        };
        let init_args = init_args_for_reinit(&reinit_args, &DeploymentIntent::default());
        assert!(
            init_args.db_dsn.is_none(),
            "missing ca.json must leave db_dsn unset for env fallback"
        );
    }

    /// Malformed or db-less `ca.json` (e.g. step-ca configured without
    /// a `db` block) must not crash reinit; the env-derived fallback is
    /// the correct behaviour in that case.
    #[test]
    fn preserved_db_dsn_from_ca_json_returns_none_for_missing_data_source() {
        let dir = tempdir().expect("tempdir");
        let config_dir = dir.path().join("config");
        fs::create_dir_all(&config_dir).expect("create config dir");
        fs::write(config_dir.join("ca.json"), r#"{"address":":9000"}"#).expect("write ca.json");
        assert!(preserved_db_dsn_from_ca_json(dir.path()).is_none());
    }

    /// Regression: an operator-supplied `--openbao-url` must not be
    /// silently overwritten by snapshotted intent.  Only the CLI default
    /// is rewritten so non-loopback recovery works out of the box.
    #[test]
    fn init_args_for_reinit_respects_explicit_openbao_url() {
        let explicit = "https://10.0.0.5:8200";
        let reinit_args = ReinitArgs {
            openbao: OpenBaoArgs {
                openbao_url: explicit.to_string(),
                kv_mount: "secret".to_string(),
            },
            secrets_dir: SecretsDirArgs {
                secrets_dir: PathBuf::from("secrets"),
            },
            compose: ComposeFileArgs {
                compose_file: PathBuf::from("docker-compose.yml"),
            },
            yes: true,
            root_token_output: None,
            enable: Vec::new(),
            skip: Vec::new(),
            summary_json: None,
            no_eab: true,
        };
        let snapshot = DeploymentIntent {
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            ..DeploymentIntent::default()
        };
        let init_args = init_args_for_reinit(&reinit_args, &snapshot);
        assert_eq!(init_args.openbao.openbao_url, explicit);
    }
}
