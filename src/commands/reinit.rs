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
    COMPOSE_PROJECT_LABEL, COMPOSE_SERVICE_LABEL, container_exists_via_docker,
    inspect_label_via_docker, remove_openbao_container_and_volumes, resolve_compose_project,
};
use crate::commands::compose_file::compose_file_dir;
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

/// Every fixed file `step ca init` writes into a step-ca tree (paths
/// relative to `secrets_dir`).  The reinit preflight refuses the
/// fresh-CA rebuild path when `password.txt` is missing and *any* of
/// these is still preserved on disk: an encrypted key locks the
/// operator out cryptographically if a fresh password is silently
/// generated, and any other surviving file derails the second init
/// pass because `ensure_step_ca_initialized` only short-circuits when
/// all three of `config/ca.json`, `secrets/root_ca_key`, and
/// `secrets/intermediate_ca_key` exist — otherwise `step ca init` runs
/// into a tree that already contains one of its targets and exits
/// non-zero on TTY-bound overwrite confirmation.  Keeping the list
/// aligned with what `step ca init` actually writes is what makes the
/// fresh-CA rebuild path atomic.
const STEP_CA_INIT_ARTIFACTS: &[&str] = &[
    "config/ca.json",
    "config/defaults.json",
    "certs/root_ca.crt",
    "certs/intermediate_ca.crt",
    "secrets/root_ca_key",
    "secrets/intermediate_ca_key",
];

/// Runs the `bootroot reinit` recovery flow.
///
/// # Errors
///
/// Returns an error when the scope check fails (external `OpenBao` or
/// project mismatch), when destructive cleanup fails, or when the
/// re-run of `init` fails.
pub(crate) async fn run_reinit(args: &ReinitArgs, messages: &Messages) -> Result<()> {
    let compose_file = &args.compose.compose_file;
    let compose_dir = compose_file_dir(compose_file);
    let state_path = StateFile::default_path();

    // 1. Refuse any operator-supplied `--openbao-url` that differs from
    //    the CLI default.  This is purely args-derived so it runs before
    //    any docker call.  The compose-label scope check that follows
    //    only proves the local compose declaration / container labels
    //    match; it does NOT prove the URL later threaded into `run_init`
    //    points at that compose-managed service.  Honouring an arbitrary
    //    URL would let `reinit --openbao-url https://shared-openbao.example`
    //    wipe local OpenBao state and then operate on an external
    //    endpoint — directly violating the issue's §Scope limitation.
    //    Legitimate non-loopback recovery does not need this flag: the
    //    init pass URL is derived from the snapshotted `openbao_bind_addr`
    //    in `init_args_for_reinit` when present.
    reject_explicit_openbao_url(&args.openbao.openbao_url, messages)?;

    // 2. Scope check: refuse external OpenBao / project mismatch.
    verify_compose_managed_openbao(
        compose_file,
        &compose_dir,
        &container_exists_via_docker,
        &inspect_label_via_docker,
        messages,
    )?;

    // 3. Validate the optional --root-token-output path BEFORE any
    //    destructive operation so a bad path does not leave the
    //    operator in a half-wiped state.
    if let Some(out) = args.root_token_output.as_deref() {
        validate_root_token_output_path(out, messages)?;
    }

    // 4. Same preflight for the optional `--summary-json` destination.
    //    `InitSummary` carries `root_token` + `unseal_keys`, so the JSON
    //    write is the only recovery channel for those secrets when
    //    `--enable show-secrets` is not set.  A bad summary path failing
    //    *after* OpenBao has been reinitialised but *before*
    //    `print_init_summary` / `--root-token-output` / `maybe_save_unseal_keys`
    //    run would recreate the partial-init trap this command is meant
    //    to recover from, via a different output channel.
    if let Some(out) = args.summary_json.as_deref() {
        validate_summary_json_output_path(out, messages)?;
    }

    // 5. Snapshot deployment intent (if state.json exists).
    let snapshot = snapshot_deployment_intent(&state_path)?;

    // 6. Derive the effective `secrets_dir` from the snapshot.  When
    //    `state.json` records a non-default `secrets_dir` (e.g. the
    //    previous init ran with `--secrets-dir custom`) the snapshot
    //    wins over the CLI default so cleanup, the preserved-DSN /
    //    password reads under the init pass, the second init pass'
    //    `args.secrets_dir`, and the rewritten `state.json.secrets_dir`
    //    all target the same tree without requiring the operator to
    //    rediscover and re-pass `--secrets-dir` on every recovery.
    let effective_secrets_dir = effective_secrets_dir(args, &snapshot);

    // 6.5. Refuse to start when `password.txt` is missing but the
    //      preserved step-ca CA material is still present.  The CA keys
    //      are encrypted with the original password, so generating a
    //      fresh one under `reinit_mode` (`resolve_init_secrets`'s
    //      missing-`password.txt` auto-gen branch) would leave the
    //      deployment with a `password.txt` that cannot unlock the
    //      preserved root/intermediate keys.  Any later
    //      `step certificate create --ca-password-file
    //      /home/step/password.txt` path would then fail with an
    //      undecryptable key.  Running this before the destructive
    //      OpenBao wipe keeps the operator's CA material recoverable
    //      from backup; an operator who has already lost the password
    //      can remove the CA material to opt into a fresh CA.  When
    //      both `password.txt` and the CA material are absent, fresh
    //      password generation is safe because `step ca init` will
    //      create matching material on the second init pass.
    verify_stepca_password_recoverable(&effective_secrets_dir, messages)?;

    // 7. Print plan and ask for confirmation.
    write_reinit_plan(
        &mut io::stdout().lock(),
        &snapshot,
        &effective_secrets_dir,
        messages,
    )
    .with_context(|| messages.error_prompt_write_failed())?;
    if !args.yes && !prompt_yes_no(messages.reinit_confirm(), messages)? {
        anyhow::bail!(messages.error_operation_cancelled());
    }

    // 8. Stop and remove the OpenBao container + volumes.
    remove_openbao_container_and_volumes(compose_file, messages)?;

    // 9. Remove OpenBao runtime/bootstrap artifacts (narrow).
    remove_openbao_runtime_state(&effective_secrets_dir, messages)?;

    // 10. Rewrite state.json with intent-only fields BEFORE infra up so
    //     the infra-up path layers the correct compose overrides for
    //     any recorded non-loopback bind.
    write_minimal_state(
        &state_path,
        &snapshot,
        &args.openbao,
        &effective_secrets_dir,
        messages,
    )?;

    // 11. Bring OpenBao back up via the existing infra up path.
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
    run_infra_up(&infra_args, messages).await?;

    // 12. Re-run init in reinit mode.  Reinit-mode behavior is enforced
    //     inside the init flow: overwrite prompts for preserved files
    //     are skipped, and an existing `password.txt` short-circuits
    //     the auto-gen path so the step-ca password is not rotated.
    //     `--root-token-output`, if set, is threaded into the init args
    //     so the freshly issued root token is persisted with mode 0600
    //     after init succeeds.
    let init_args = init_args_for_reinit(args, &snapshot, &effective_secrets_dir);
    run_init(&init_args, messages).await?;

    println!("{}", messages.reinit_completed());
    println!("{}", messages.reinit_service_registry_post_summary());
    println!("{}", messages.hint_reinit_reload_style());
    Ok(())
}

/// Refuses to start reinit when `password.txt` is missing but any file
/// `step ca init` would write (see `STEP_CA_INIT_ARTIFACTS`) is still
/// preserved.  See the caller's preflight comment in `run_reinit` for
/// the rationale: under `reinit_mode`, `resolve_init_secrets` would
/// otherwise auto-generate a fresh step-ca password without the
/// operator opting into the global `auto-generate` feature.  Two
/// distinct failure modes follow when an artifact is preserved:
///
/// - An encrypted CA key (`secrets/root_ca_key`,
///   `secrets/intermediate_ca_key`) is encrypted with the original
///   password, so the freshly generated password written to
///   `password.txt` / `OpenBao` KV cannot unlock it; any later
///   `step certificate create --ca-password-file
///   /home/step/password.txt` path (e.g. the `OpenBao` / HTTP-01 TLS
///   issuance flows) fails with an undecryptable key.
/// - Any other preserved file (`config/ca.json`,
///   `config/defaults.json`, `certs/root_ca.crt`,
///   `certs/intermediate_ca.crt`) does not lock anyone out
///   cryptographically, but `ensure_step_ca_initialized` only
///   short-circuits when all three of `config/ca.json`,
///   `secrets/root_ca_key`, and `secrets/intermediate_ca_key` exist
///   (`stepca_setup.rs:239-244`), so the second init pass otherwise
///   runs `step ca init` into a tree that already contains one of its
///   targets.  Empirically `smallstep/step-ca step ca init` against a
///   tree populated with any of those files generates fresh cert/key
///   material and then exits non-zero with `open /dev/tty failed: no
///   such device or address` — recreating the partial-init trap after
///   `OpenBao` has already been wiped.
///
/// Requiring the operator to either restore `password.txt` or remove
/// every preserved step-ca artifact before retrying keeps reinit
/// atomic and surfaces the recovery choice up front rather than
/// mid-flow.
///
/// Running this before the destructive `OpenBao` wipe leaves the
/// operator's CA material recoverable from backup.  When both
/// `password.txt` and every step-ca artifact are absent, this
/// preflight is a no-op because the second init pass will run
/// `step ca init` and generate matching material from scratch.
pub(crate) fn verify_stepca_password_recoverable(
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let password_path = secrets_dir.join("password.txt");
    if password_path.exists() {
        return Ok(());
    }
    // Reinit's fresh-CA rebuild path requires a clean step-ca tree —
    // every fixed target `step ca init` writes must be absent, not just
    // the three files used by the "already initialized" skip check.
    let preserved: Vec<PathBuf> = STEP_CA_INIT_ARTIFACTS
        .iter()
        .map(|rel| secrets_dir.join(rel))
        .filter(|path| path.exists())
        .collect();
    if preserved.is_empty() {
        return Ok(());
    }
    let preserved_paths = preserved
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        messages.error_reinit_stepca_password_missing_with_ca_material(
            &password_path.display().to_string(),
            &secrets_dir.display().to_string(),
            &preserved_paths,
        )
    );
}

/// Rejects an operator-supplied `--openbao-url` that differs from the
/// CLI default.  See the caller's preflight comment in `run_reinit` for
/// the threat model: an arbitrary URL would let reinit wipe local
/// `OpenBao` state and then operate on an external endpoint.
pub(crate) fn reject_explicit_openbao_url(openbao_url: &str, messages: &Messages) -> Result<()> {
    if openbao_url != crate::commands::init::DEFAULT_OPENBAO_URL {
        anyhow::bail!(messages.error_reinit_explicit_openbao_url(openbao_url));
    }
    Ok(())
}

/// Validates that the compose file declares a local `openbao` service
/// and that, if a `bootroot-openbao` container exists, BOTH compose
/// labels are present and match the project derived from this work
/// directory and the expected `openbao` service.
///
/// The existence check is intentionally separate from the label read
/// because `inspect_label_via_docker` collapses "container missing"
/// and "container exists but label unset" into the same `Ok(None)`.
/// A container that exists but is missing one of the compose labels
/// must NOT be collapsed into the stuck-after-`clean --openbao-only`
/// recovery path; treating it that way would let reinit wipe an
/// `OpenBao` whose provenance cannot be proven to belong to this work
/// directory's compose project.  See the issue's §Scope limitation.
fn verify_compose_managed_openbao(
    compose_file: &Path,
    compose_dir: &Path,
    container_exists: &dyn Fn(&str) -> Result<bool>,
    inspect: &dyn Fn(&str, &str) -> Result<Option<String>>,
    messages: &Messages,
) -> Result<()> {
    if !compose_file.exists() {
        anyhow::bail!(messages.error_reinit_external_openbao(&compose_file.display().to_string()));
    }
    if !compose_has_openbao(compose_file, messages)? {
        anyhow::bail!(messages.error_reinit_external_openbao(&compose_file.display().to_string()));
    }
    if container_exists(OPENBAO_CONTAINER_NAME)? {
        // When the container exists, the expected project must come
        // from a source independent of the container (env override or
        // compose-dir basename).  Otherwise a mismatched container
        // would never trip the check.
        let expected_project = resolve_expected_compose_project_excluding_container(compose_dir)?;
        let container_project = inspect(OPENBAO_CONTAINER_NAME, COMPOSE_PROJECT_LABEL)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    messages.error_reinit_container_missing_compose_label(COMPOSE_PROJECT_LABEL)
                )
            })?;
        if container_project != expected_project {
            anyhow::bail!(
                messages.error_reinit_container_project_mismatch(
                    &container_project,
                    &expected_project,
                )
            );
        }
        let container_service = inspect(OPENBAO_CONTAINER_NAME, COMPOSE_SERVICE_LABEL)?
            .ok_or_else(|| {
                anyhow::anyhow!(
                    messages.error_reinit_container_missing_compose_label(COMPOSE_SERVICE_LABEL)
                )
            })?;
        if container_service != OPENBAO_COMPOSE_SERVICE {
            anyhow::bail!(messages.error_reinit_container_project_mismatch(
                &format!("service={container_service}"),
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
    pub(crate) stepca_bind_addr: Option<String>,
    pub(crate) stepca_advertise_addr: Option<String>,
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
        stepca_bind_addr: state.stepca_bind_addr,
        stepca_advertise_addr: state.stepca_advertise_addr,
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
    effective_secrets_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let state = StateFile {
        openbao_url: openbao.openbao_url.clone(),
        kv_mount: openbao.kv_mount.clone(),
        secrets_dir: Some(effective_secrets_dir.to_path_buf()),
        policies: BTreeMap::new(),
        approles: BTreeMap::new(),
        services: BTreeMap::new(),
        openbao_bind_addr: snapshot.openbao_bind_addr.clone(),
        openbao_advertise_addr: snapshot.openbao_advertise_addr.clone(),
        http01_admin_bind_addr: snapshot.http01_admin_bind_addr.clone(),
        http01_admin_advertise_addr: snapshot.http01_admin_advertise_addr.clone(),
        stepca_bind_addr: snapshot.stepca_bind_addr.clone(),
        stepca_advertise_addr: snapshot.stepca_advertise_addr.clone(),
        infra_certs: snapshot.infra_certs.clone(),
    };
    state
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())?;
    Ok(())
}

/// Returns the effective `secrets_dir` reinit operates on.  When
/// `state.json` recorded a `secrets_dir` (e.g. the previous init ran
/// with a non-default `--secrets-dir`), the snapshot wins over the CLI
/// default so a recovery does not silently target the wrong tree.  When
/// no snapshot is present (the rsync-clone path or a fresh tree), the
/// CLI value is used directly.
pub(crate) fn effective_secrets_dir(args: &ReinitArgs, snapshot: &DeploymentIntent) -> PathBuf {
    snapshot
        .secrets_dir
        .clone()
        .unwrap_or_else(|| args.secrets_dir.secrets_dir.clone())
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
pub(crate) fn validate_root_token_output_path(path: &Path, messages: &Messages) -> Result<()> {
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

/// Validates that the optional `--summary-json` destination is safe to
/// write to *before* any destructive operation begins.  Without this
/// preflight, a bad summary path failing inside `write_init_summary_json`
/// would short-circuit `run_init`'s post-init flow — meaning
/// `print_init_summary`, `--root-token-output`, and the automatic
/// unseal-key save under reinit mode would all be skipped after `OpenBao`
/// has already been reinitialised.  That is the exact partial-init trap
/// `reinit` is supposed to recover from, just through a different
/// explicit output channel.
///
/// Mirrors `validate_root_token_output_path`.  The summary JSON carries
/// the freshly issued root token and unseal keys (see `InitSummary`), so
/// it must be written with the same atomic restricted-permission write
/// discipline as `--root-token-output`.  In particular, existing
/// world-/group-readable destinations are rejected here: even though
/// `write_init_summary_json` re-applies `0600` after the write, the
/// content lands in the pre-existing file's permission bits first, and
/// a `0644` destination would briefly expose root token + unseal keys
/// to other users on the host between the write and the chmod.
pub(crate) fn validate_summary_json_output_path(path: &Path, messages: &Messages) -> Result<()> {
    let display = path.display().to_string();

    if path.exists() {
        let meta = std::fs::symlink_metadata(path)
            .with_context(|| messages.error_read_file_failed(&display))?;
        let file_type = meta.file_type();
        if !file_type.is_file() && !file_type.is_symlink() {
            anyhow::bail!(messages.error_reinit_summary_json_not_file(&display));
        }
        if file_type.is_symlink() {
            let target_meta = std::fs::metadata(path)
                .with_context(|| messages.error_read_file_failed(&display))?;
            if !target_meta.is_file() {
                anyhow::bail!(messages.error_reinit_summary_json_not_file(&display));
            }
        }
        // Permission check uses follow-symlink metadata so a symlink to
        // a regular file is evaluated against the target's mode.
        let mode_meta =
            std::fs::metadata(path).with_context(|| messages.error_read_file_failed(&display))?;
        let mode = mode_meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            anyhow::bail!(messages.error_reinit_summary_json_unsafe(&display));
        }
        // Probe writability the same way `validate_root_token_output_path`
        // does: open for write without `truncate(true)` so the existing
        // contents are not modified, just to prove the kernel will accept
        // a later write.  Catches mode `0400`, immutable attributes, etc.
        std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|err| {
                anyhow::anyhow!(
                    messages.error_reinit_summary_json_unwritable(&display, &err.to_string())
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
                messages.error_reinit_summary_json_unwritable(&display, &err.to_string())
            )
        })?;
    }
    if !parent.is_dir() {
        anyhow::bail!(messages.error_reinit_summary_json_unwritable(
            &display,
            &format!("parent {} is not a directory", parent.display()),
        ));
    }
    let probe = parent.join(format!(
        ".bootroot-reinit-summary-probe.{}",
        std::process::id()
    ));
    if let Err(err) = std::fs::write(&probe, b"") {
        anyhow::bail!(messages.error_reinit_summary_json_unwritable(&display, &err.to_string()));
    }
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

/// Writes the reinit plan (destructive actions + preserved artifacts +
/// snapshotted intent values + service-registry warning) to `out`.
/// Snapshot-aware so the operator can see, before confirming, exactly
/// which secrets tree, `OpenBao` / HTTP-01 bind, and infra-cert entries
/// the reinit will operate on.  Split from the production stdout call
/// site so tests can assert each section appears in the rendered text.
// Sequential plan rendering — one writeln per preserved-intent line.
#[allow(clippy::too_many_lines)]
fn write_reinit_plan<W: Write>(
    out: &mut W,
    snapshot: &DeploymentIntent,
    effective_secrets_dir: &Path,
    messages: &Messages,
) -> io::Result<()> {
    let secrets_display = effective_secrets_dir.display().to_string();
    writeln!(out, "{}", messages.reinit_plan_title())?;
    writeln!(out, "{}", messages.reinit_plan_destructive_actions())?;
    writeln!(out, "{}", messages.reinit_plan_destructive_container())?;
    writeln!(out, "{}", messages.reinit_plan_destructive_volumes())?;
    writeln!(out, "{}", messages.reinit_plan_destructive_state_file())?;
    writeln!(
        out,
        "{}",
        messages.reinit_plan_destructive_runtime_files(&secrets_display)
    )?;
    writeln!(
        out,
        "{}",
        messages.reinit_plan_destructive_service_creds(&secrets_display)
    )?;
    writeln!(out, "{}", messages.reinit_plan_preserved_actions())?;
    writeln!(
        out,
        "{}",
        messages.reinit_plan_preserved_ca(&secrets_display)
    )?;
    writeln!(
        out,
        "{}",
        messages.reinit_plan_preserved_password(&secrets_display)
    )?;
    writeln!(out, "{}", messages.reinit_plan_preserved_postgres())?;
    writeln!(
        out,
        "{}",
        messages.reinit_plan_preserved_compose_overrides(&secrets_display)
    )?;
    writeln!(out, "{}", messages.reinit_plan_preserved_intent())?;

    writeln!(out)?;
    writeln!(out, "{}", messages.reinit_plan_preserved_intent_section())?;
    writeln!(
        out,
        "{}",
        messages.reinit_plan_preserved_intent_secrets_dir(&secrets_display)
    )?;
    let has_extra_intent = snapshot.openbao_bind_addr.is_some()
        || snapshot.openbao_advertise_addr.is_some()
        || snapshot.http01_admin_bind_addr.is_some()
        || snapshot.http01_admin_advertise_addr.is_some()
        || snapshot.stepca_bind_addr.is_some()
        || snapshot.stepca_advertise_addr.is_some()
        || !snapshot.infra_certs.is_empty();
    if let Some(bind) = snapshot.openbao_bind_addr.as_deref() {
        writeln!(
            out,
            "{}",
            messages.reinit_plan_preserved_intent_openbao_bind(bind)
        )?;
    }
    if let Some(addr) = snapshot.openbao_advertise_addr.as_deref() {
        writeln!(
            out,
            "{}",
            messages.reinit_plan_preserved_intent_openbao_advertise(addr)
        )?;
    }
    if let Some(addr) = snapshot.http01_admin_bind_addr.as_deref() {
        writeln!(
            out,
            "{}",
            messages.reinit_plan_preserved_intent_http01_bind(addr)
        )?;
    }
    if let Some(addr) = snapshot.http01_admin_advertise_addr.as_deref() {
        writeln!(
            out,
            "{}",
            messages.reinit_plan_preserved_intent_http01_advertise(addr)
        )?;
    }
    if let Some(addr) = snapshot.stepca_bind_addr.as_deref() {
        writeln!(
            out,
            "{}",
            messages.reinit_plan_preserved_intent_stepca_bind(addr)
        )?;
    }
    if let Some(addr) = snapshot.stepca_advertise_addr.as_deref() {
        writeln!(
            out,
            "{}",
            messages.reinit_plan_preserved_intent_stepca_advertise(addr)
        )?;
    }
    if !snapshot.infra_certs.is_empty() {
        writeln!(
            out,
            "{}",
            messages.reinit_plan_preserved_intent_infra_certs(snapshot.infra_certs.len())
        )?;
    }
    if !has_extra_intent {
        writeln!(out, "{}", messages.reinit_plan_preserved_intent_none())?;
    }

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
    let value = read_ca_json(secrets_dir)?;
    value
        .get("db")
        .and_then(|db| db.get("dataSource"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
}

/// Reads `<secrets_dir>/config/ca.json` once for the `preserved_*`
/// helpers below.  Returns `None` when the file is absent or malformed
/// so callers fall back to their CLI/default values.
fn read_ca_json(secrets_dir: &Path) -> Option<serde_json::Value> {
    let ca_json_path = secrets_dir.join("config").join("ca.json");
    if !ca_json_path.exists() {
        return None;
    }
    let contents = std::fs::read_to_string(&ca_json_path).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Returns the first ACME provisioner name recorded in the preserved
/// `ca.json`, if any.  Reinit reuses this so a deployment initialized
/// with `bootroot init --stepca-provisioner <custom>` does not get
/// silently reset to the default `acme` name on the second init pass
/// (which would make `update_ca_json_with_backup`'s lookup by name
/// fail and abort the recovery after `OpenBao` was already wiped).
///
/// Accepts both the on-disk shape (`authority.provisioners`) and the
/// flat `provisioners` shape emitted by older `step ca init` builds,
/// matching `set_acme_cert_duration`'s discovery logic.
fn preserved_stepca_provisioner_from_ca_json(secrets_dir: &Path) -> Option<String> {
    let value = read_ca_json(secrets_dir)?;
    locate_provisioners(&value)?.iter().find_map(|p| {
        let is_acme = p
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|t| t.eq_ignore_ascii_case("ACME"));
        if !is_acme {
            return None;
        }
        p.get("name")
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    })
}

/// Returns `claims.defaultTLSCertDuration` of the first ACME
/// provisioner in the preserved `ca.json`, if any.  Reinit uses this
/// so a deployment initialized with a non-default `--cert-duration`
/// keeps that value on the second init pass rather than silently
/// snapping back to `DEFAULT_CERT_DURATION`.
fn preserved_cert_duration_from_ca_json(secrets_dir: &Path) -> Option<String> {
    let value = read_ca_json(secrets_dir)?;
    locate_provisioners(&value)?.iter().find_map(|p| {
        let is_acme = p
            .get("type")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|t| t.eq_ignore_ascii_case("ACME"));
        if !is_acme {
            return None;
        }
        p.get("claims")
            .and_then(|c| c.get("defaultTLSCertDuration"))
            .and_then(serde_json::Value::as_str)
            .map(str::to_string)
    })
}

fn locate_provisioners(value: &serde_json::Value) -> Option<&Vec<serde_json::Value>> {
    if let Some(authority) = value.get("authority")
        && let Some(arr) = authority
            .get("provisioners")
            .and_then(serde_json::Value::as_array)
    {
        return Some(arr);
    }
    value
        .get("provisioners")
        .and_then(serde_json::Value::as_array)
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
///
/// Likewise, the ACME provisioner name and `defaultTLSCertDuration`
/// recorded in the preserved `ca.json` win over the CLI defaults.
/// `update_ca_json_with_backup` later looks the provisioner up by
/// name when patching `db.dataSource` / `claims.defaultTLSCertDuration`,
/// so a deployment initialised with `--stepca-provisioner <custom>` or
/// `--cert-duration <custom>` would otherwise fail (mismatched name) or
/// be silently reset on every reinit.  See
/// `preserved_stepca_provisioner_from_ca_json` and
/// `preserved_cert_duration_from_ca_json`.
fn init_args_for_reinit(
    args: &ReinitArgs,
    snapshot: &DeploymentIntent,
    effective_secrets_dir: &Path,
) -> Box<InitArgs> {
    let mut openbao = args.openbao.clone();
    if openbao.openbao_url == crate::commands::init::DEFAULT_OPENBAO_URL
        && let Some(bind) = snapshot.openbao_bind_addr.as_deref()
    {
        openbao.openbao_url = client_url_from_bind_addr(bind);
    }
    let db_dsn = preserved_db_dsn_from_ca_json(effective_secrets_dir);
    let stepca_provisioner = preserved_stepca_provisioner_from_ca_json(effective_secrets_dir)
        .unwrap_or_else(|| crate::commands::init::DEFAULT_STEPCA_PROVISIONER.to_string());
    let cert_duration = preserved_cert_duration_from_ca_json(effective_secrets_dir)
        .unwrap_or_else(|| crate::commands::init::DEFAULT_CERT_DURATION.to_string());
    Box::new(InitArgs {
        openbao,
        secrets_dir: SecretsDirArgs {
            secrets_dir: effective_secrets_dir.to_path_buf(),
        },
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
        stepca_provisioner,
        cert_duration,
        eab_kid: None,
        eab_hmac: None,
        no_eab: args.no_eab,
        save_unseal_keys: false,
        no_save_unseal_keys: false,
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
            stepca_bind_addr: Some("192.168.1.10:9000".to_string()),
            stepca_advertise_addr: None,
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
        assert_eq!(
            snapshot.stepca_bind_addr.as_deref(),
            Some("192.168.1.10:9000")
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
        let effective = PathBuf::from("secrets");
        let messages = test_messages();

        write_minimal_state(&state_path, &snapshot, &openbao, &effective, &messages).unwrap();

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
        assert_eq!(
            rewritten.stepca_bind_addr.as_deref(),
            Some("192.168.1.10:9000"),
            "stepca_bind_addr intent must survive"
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
        let container_exists = |_: &str| -> Result<bool> { Ok(false) };
        let inspect = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        let err = verify_compose_managed_openbao(
            &compose_file,
            dir.path(),
            &container_exists,
            &inspect,
            &messages,
        )
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
        let container_exists = |_: &str| -> Result<bool> { Ok(false) };
        let inspect = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        let err = verify_compose_managed_openbao(
            &compose_file,
            dir.path(),
            &container_exists,
            &inspect,
            &messages,
        )
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
        let container_exists = |_: &str| -> Result<bool> { Ok(true) };
        let inspect = |_: &str, label: &str| -> Result<Option<String>> {
            if label == COMPOSE_PROJECT_LABEL {
                Ok(Some("external".to_string()))
            } else if label == COMPOSE_SERVICE_LABEL {
                Ok(Some(OPENBAO_COMPOSE_SERVICE.to_string()))
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
        let err = verify_compose_managed_openbao(
            &compose_file,
            &work,
            &container_exists,
            &inspect,
            &messages,
        )
        .unwrap_err();
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
        let container_exists = |_: &str| -> Result<bool> { Ok(false) };
        let inspect = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        verify_compose_managed_openbao(
            &compose_file,
            &work,
            &container_exists,
            &inspect,
            &messages,
        )
        .expect("should accept missing container when compose declaration is intact");
    }

    /// Regression for Round 9 reviewer item: an existing
    /// `bootroot-openbao` container that lacks the compose project label
    /// must NOT be collapsed into the "container absent" recovery path.
    /// Previously `inspect_label_via_docker` returned `Ok(None)` for both
    /// the missing-container and missing-label cases, and the verifier
    /// fell through to the stuck-after-clean acceptance branch.
    #[test]
    fn verify_compose_managed_openbao_rejects_existing_container_with_missing_project_label() {
        let dir = tempdir().unwrap();
        let work = dir.path().join("bootroot");
        fs::create_dir_all(&work).unwrap();
        let compose_file = work.join("docker-compose.yml");
        fs::write(&compose_file, "services:\n  openbao:\n    image: openbao\n").unwrap();
        let messages = test_messages();
        let container_exists = |_: &str| -> Result<bool> { Ok(true) };
        // No compose labels at all (container was started outside compose).
        let inspect = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        let err = verify_compose_managed_openbao(
            &compose_file,
            &work,
            &container_exists,
            &inspect,
            &messages,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(COMPOSE_PROJECT_LABEL),
            "got: {err}"
        );
    }

    /// Regression for Round 9 reviewer item: an existing container that
    /// carries a matching project label but is missing the service label
    /// must also be rejected.  Previously the verifier only rejected a
    /// *present non-`openbao`* service label and accepted an absent one.
    #[test]
    fn verify_compose_managed_openbao_rejects_existing_container_with_missing_service_label() {
        let dir = tempdir().unwrap();
        let work = dir.path().join("bootroot");
        fs::create_dir_all(&work).unwrap();
        let compose_file = work.join("docker-compose.yml");
        fs::write(&compose_file, "services:\n  openbao:\n    image: openbao\n").unwrap();
        let messages = test_messages();
        let container_exists = |_: &str| -> Result<bool> { Ok(true) };
        // Project label matches the work-dir basename, but the service
        // label is unset.
        let inspect = |_: &str, label: &str| -> Result<Option<String>> {
            if label == COMPOSE_PROJECT_LABEL {
                Ok(Some("bootroot".to_string()))
            } else {
                Ok(None)
            }
        };
        let _guard = env_lock();
        let prior = std::env::var_os("COMPOSE_PROJECT_NAME");
        // SAFETY: env access is serialised by `env_lock` above.
        unsafe { std::env::remove_var("COMPOSE_PROJECT_NAME") };
        let result = verify_compose_managed_openbao(
            &compose_file,
            &work,
            &container_exists,
            &inspect,
            &messages,
        );
        if let Some(prior) = prior {
            // SAFETY: still inside the env_lock guard.
            unsafe { std::env::set_var("COMPOSE_PROJECT_NAME", prior) };
        }
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains(COMPOSE_SERVICE_LABEL),
            "got: {err}"
        );
    }

    /// Positive case for Round 9: an existing container with both
    /// compose labels matching the expected project + service is
    /// accepted.
    #[test]
    fn verify_compose_managed_openbao_accepts_existing_container_with_matching_labels() {
        let dir = tempdir().unwrap();
        let work = dir.path().join("bootroot");
        fs::create_dir_all(&work).unwrap();
        let compose_file = work.join("docker-compose.yml");
        fs::write(&compose_file, "services:\n  openbao:\n    image: openbao\n").unwrap();
        let messages = test_messages();
        let container_exists = |_: &str| -> Result<bool> { Ok(true) };
        let inspect = |_: &str, label: &str| -> Result<Option<String>> {
            if label == COMPOSE_PROJECT_LABEL {
                Ok(Some("bootroot".to_string()))
            } else if label == COMPOSE_SERVICE_LABEL {
                Ok(Some(OPENBAO_COMPOSE_SERVICE.to_string()))
            } else {
                Ok(None)
            }
        };
        let _guard = env_lock();
        let prior = std::env::var_os("COMPOSE_PROJECT_NAME");
        // SAFETY: env access is serialised by `env_lock` above.
        unsafe { std::env::remove_var("COMPOSE_PROJECT_NAME") };
        let result = verify_compose_managed_openbao(
            &compose_file,
            &work,
            &container_exists,
            &inspect,
            &messages,
        );
        if let Some(prior) = prior {
            // SAFETY: still inside the env_lock guard.
            unsafe { std::env::set_var("COMPOSE_PROJECT_NAME", prior) };
        }
        result.expect("should accept existing container with matching compose labels");
    }

    /// Regression for #611: when `--compose-file` is the default
    /// relative `docker-compose.yml`, `run_reinit` derives `compose_dir`
    /// via [`compose_file_dir`].  The verifier must accept that
    /// `compose_dir` and complete its scope check without surfacing
    /// `could not derive compose project name from `.  Exercises the
    /// container-absent branch (the stuck-after-`clean --openbao-only`
    /// recovery path) with CWD pointed at a tempdir holding a valid
    /// compose declaration.
    #[test]
    fn verify_compose_managed_openbao_accepts_default_relative_compose_file() {
        let _guard = env_lock();
        let prior_env = std::env::var_os("COMPOSE_PROJECT_NAME");
        // SAFETY: env access is serialised by `env_lock` above.
        unsafe { std::env::remove_var("COMPOSE_PROJECT_NAME") };

        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("docker-compose.yml"),
            "services:\n  openbao:\n    image: openbao\n",
        )
        .unwrap();
        let original_cwd = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let compose_file = PathBuf::from("docker-compose.yml");
        let compose_dir = compose_file_dir(&compose_file);
        let messages = test_messages();
        let container_exists = |_: &str| -> Result<bool> { Ok(false) };
        let inspect = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        let result = verify_compose_managed_openbao(
            &compose_file,
            &compose_dir,
            &container_exists,
            &inspect,
            &messages,
        );

        std::env::set_current_dir(&original_cwd).unwrap();
        if let Some(prior) = prior_env {
            // SAFETY: still inside the env_lock guard.
            unsafe { std::env::set_var("COMPOSE_PROJECT_NAME", prior) };
        }

        result.expect("default relative --compose-file must not break the scope check");
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

    /// Regression for Round 6 reviewer item: when `--summary-json`
    /// points at an unwritable destination (existing file with mode
    /// `0400`), the preflight must catch it before the destructive
    /// sequence runs.  Otherwise the post-init `write_init_summary_json`
    /// fails after `OpenBao` has already been reinitialised, and the
    /// early-return short-circuits `print_init_summary`,
    /// `--root-token-output`, and `maybe_save_unseal_keys` — recreating
    /// the partial-init trap through a different output channel.
    #[test]
    fn validate_summary_json_rejects_non_writable_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("summary.json");
        fs::write(&path, "{}").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o400);
        fs::set_permissions(&path, perms).unwrap();
        let messages = test_messages();
        let err = validate_summary_json_output_path(&path, &messages).unwrap_err();
        // Restore so tempdir cleanup succeeds.
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).unwrap();
        assert!(
            err.to_string().contains("--summary-json") || err.to_string().contains("summary-json"),
            "got: {err}"
        );
    }

    /// Regression for Round 7 reviewer item: the summary JSON carries
    /// the freshly issued root token and unseal keys, so an existing
    /// world-/group-readable destination must be rejected at preflight.
    /// Letting `write_init_summary_json` proceed against a `0644` file
    /// would briefly leave the secret payload world-readable on disk
    /// between the write and the post-write chmod.
    #[test]
    fn validate_summary_json_rejects_world_readable_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("summary.json");
        fs::write(&path, "{}").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o644);
        fs::set_permissions(&path, perms).unwrap();
        let messages = test_messages();
        let err = validate_summary_json_output_path(&path, &messages).unwrap_err();
        // Restore so tempdir cleanup succeeds.
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).unwrap();
        assert!(
            err.to_string().contains("--summary-json") || err.to_string().contains("summary-json"),
            "got: {err}"
        );
    }

    /// A `0600` existing summary file is acceptable: the destination
    /// already meets the no-group/no-other-readable bar that
    /// `write_init_summary_json`'s atomic write maintains.
    #[test]
    fn validate_summary_json_accepts_owner_only_existing_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("summary.json");
        fs::write(&path, "{}").unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms).unwrap();
        let messages = test_messages();
        validate_summary_json_output_path(&path, &messages)
            .expect("0600 existing summary file is acceptable");
    }

    /// A missing destination is acceptable as long as the parent
    /// directory can accept a new file.  Mirrors
    /// `validate_root_token_output_accepts_missing_file`.
    #[test]
    fn validate_summary_json_accepts_missing_file() {
        let dir = tempdir().unwrap();
        let messages = test_messages();
        validate_summary_json_output_path(&dir.path().join("summary.json"), &messages).unwrap();
    }

    /// Regression: a path that exists but is a directory must be
    /// rejected.  Otherwise `write_init_summary_json` would fail after
    /// the destructive sequence has already run.
    #[test]
    fn validate_summary_json_rejects_directory_path() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("not-a-file");
        fs::create_dir_all(&nested).unwrap();
        let messages = test_messages();
        let err = validate_summary_json_output_path(&nested, &messages).unwrap_err();
        assert!(
            err.to_string().contains("regular file") || err.to_string().contains("일반 파일"),
            "got: {err}"
        );
    }

    /// Regression: a missing destination whose parent cannot be created
    /// (because an ancestor is a regular file, not a directory) must be
    /// rejected during preflight.
    #[test]
    fn validate_summary_json_rejects_uncreatable_parent() {
        let dir = tempdir().unwrap();
        let blocker = dir.path().join("blocker");
        fs::write(&blocker, "not a dir").unwrap();
        let target = blocker.join("nested").join("summary.json");
        let messages = test_messages();
        let err = validate_summary_json_output_path(&target, &messages).unwrap_err();
        assert!(
            err.to_string().contains("--summary-json") || err.to_string().contains("summary-json"),
            "got: {err}"
        );
    }

    /// Regression: read-only parent directories must surface as a
    /// preflight failure, not a post-destructive write failure.
    #[test]
    fn validate_summary_json_rejects_read_only_parent() {
        let dir = tempdir().unwrap();
        let parent = dir.path().join("ro");
        fs::create_dir_all(&parent).unwrap();
        let mut perms = fs::metadata(&parent).unwrap().permissions();
        let original = perms.mode();
        perms.set_mode(0o500);
        fs::set_permissions(&parent, perms).unwrap();
        let target = parent.join("summary.json");
        let messages = test_messages();
        let err = validate_summary_json_output_path(&target, &messages).unwrap_err();
        let mut perms = fs::metadata(&parent).unwrap().permissions();
        perms.set_mode(original);
        fs::set_permissions(&parent, perms).unwrap();
        assert!(
            err.to_string().contains("--summary-json") || err.to_string().contains("summary-json"),
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
        let snapshot = DeploymentIntent::default();
        write_reinit_plan(&mut buf, &snapshot, Path::new("secrets"), &messages)
            .expect("write plan");
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

        // Snapshot-aware preserved intent section.
        assert!(
            rendered.contains("Preserved deployment intent"),
            "plan must include preserved intent section; got:\n{rendered}"
        );
        assert!(
            rendered.contains("secrets_dir: secrets"),
            "preserved intent must echo the effective secrets_dir; got:\n{rendered}"
        );

        // Operator-visible warning that the service registry will be
        // empty after reinit completes.
        assert!(
            rendered.contains("service add"),
            "plan must point operator at service add; got:\n{rendered}"
        );
    }

    /// Regression for Round 4 reviewer item: the plan must echo the
    /// actual snapshotted intent values (non-loopback bind addresses,
    /// infra-cert entries, custom `secrets_dir`) so the operator can
    /// verify what will survive *before* the destructive sequence runs.
    /// Without this, the operator only sees the categorical preserved
    /// list and has to trust that the snapshot is being read correctly.
    #[test]
    fn write_reinit_plan_echoes_snapshotted_intent_values() {
        let messages = test_messages();
        let mut buf = Vec::new();
        let snapshot = DeploymentIntent {
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: Some("192.168.1.10:8200".to_string()),
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            stepca_bind_addr: Some("192.168.1.10:9000".to_string()),
            stepca_advertise_addr: None,
            secrets_dir: Some(PathBuf::from("secrets-custom")),
            infra_certs: {
                let mut m = BTreeMap::new();
                m.insert(
                    "openbao".to_string(),
                    InfraCertEntry {
                        cert_path: PathBuf::from("c"),
                        key_path: PathBuf::from("k"),
                        sans: vec!["192.168.1.10".to_string()],
                        renew_before: "720h".to_string(),
                        reload_strategy: ReloadStrategy::ContainerRestart {
                            container_name: "bootroot-openbao".to_string(),
                        },
                        issued_at: None,
                        expires_at: None,
                    },
                );
                m
            },
        };
        write_reinit_plan(&mut buf, &snapshot, Path::new("secrets-custom"), &messages)
            .expect("write plan");
        let rendered = String::from_utf8(buf).expect("utf-8 plan");

        // Effective secrets_dir threaded through the destructive +
        // preserved bullets and echoed in the intent section.
        assert!(
            rendered.contains("secrets-custom/openbao/unseal-keys.txt"),
            "destructive runtime-files bullet must use the effective secrets_dir; got:\n{rendered}"
        );
        assert!(
            rendered.contains("secrets-custom/config/ca.json"),
            "preserved CA bullet must use the effective secrets_dir; got:\n{rendered}"
        );
        assert!(
            rendered.contains("secrets-custom/password.txt"),
            "preserved password bullet must use the effective secrets_dir; got:\n{rendered}"
        );
        assert!(
            rendered.contains("secrets_dir: secrets-custom"),
            "intent section must echo the effective secrets_dir; got:\n{rendered}"
        );
        assert!(
            rendered.contains("openbao_bind_addr: 192.168.1.10:8200"),
            "intent section must echo openbao_bind_addr; got:\n{rendered}"
        );
        assert!(
            rendered.contains("http01_admin_bind_addr: 192.168.1.10:8080"),
            "intent section must echo http01_admin_bind_addr; got:\n{rendered}"
        );
        assert!(
            rendered.contains("stepca_bind_addr: 192.168.1.10:9000"),
            "intent section must echo stepca_bind_addr; got:\n{rendered}"
        );
        assert!(
            rendered.contains("infra_certs: 1"),
            "intent section must echo infra_certs count; got:\n{rendered}"
        );
        // The advertise fields were None so they must NOT appear.
        assert!(
            !rendered.contains("http01_admin_advertise_addr"),
            "absent intent fields must not appear; got:\n{rendered}"
        );
        assert!(
            !rendered.contains("stepca_advertise_addr"),
            "absent intent fields must not appear; got:\n{rendered}"
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
        let init_args = init_args_for_reinit(
            &reinit_args,
            &DeploymentIntent::default(),
            &reinit_args.secrets_dir.secrets_dir,
        );
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
        let init_args = init_args_for_reinit(
            &reinit_args,
            &snapshot,
            &reinit_args.secrets_dir.secrets_dir,
        );
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
        let init_args = init_args_for_reinit(
            &reinit_args,
            &DeploymentIntent::default(),
            &reinit_args.secrets_dir.secrets_dir,
        );
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
        let init_args = init_args_for_reinit(
            &reinit_args,
            &DeploymentIntent::default(),
            &reinit_args.secrets_dir.secrets_dir,
        );
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

    /// Regression for Round 5 reviewer item: a deployment initialised
    /// with `bootroot init --stepca-provisioner <custom>` records that
    /// provisioner name in `ca.json`.  Reinit's second init pass must
    /// derive it from the preserved file rather than defaulting to
    /// `acme`, otherwise `update_ca_json_with_backup`'s lookup-by-name
    /// path bails (`ca.json does not contain an ACME provisioner named
    /// "acme"`) after `OpenBao` has already been wiped.  Similarly the
    /// preserved `defaultTLSCertDuration` must win over the CLI default
    /// so a non-default `--cert-duration` is not silently snapped back.
    #[test]
    fn init_args_for_reinit_uses_preserved_stepca_provisioner_and_cert_duration_from_ca_json() {
        let dir = tempdir().expect("tempdir");
        let secrets_dir = dir.path().to_path_buf();
        let config_dir = secrets_dir.join("config");
        fs::create_dir_all(&config_dir).expect("create config dir");
        fs::write(
            config_dir.join("ca.json"),
            r#"{
                "authority":{"provisioners":[
                    {"type":"JWK","name":"admin"},
                    {"type":"ACME","name":"acme-custom","claims":{"defaultTLSCertDuration":"72h"}}
                ]},
                "db":{"type":"postgresql","dataSource":"postgresql://u:p@h:5432/d?sslmode=disable"}
            }"#,
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
        let init_args = init_args_for_reinit(
            &reinit_args,
            &DeploymentIntent::default(),
            &reinit_args.secrets_dir.secrets_dir,
        );
        assert_eq!(
            init_args.stepca_provisioner,
            "acme-custom",
            "reinit must derive the ACME provisioner name from the \
             preserved ca.json, not default to {default:?}",
            default = crate::commands::init::DEFAULT_STEPCA_PROVISIONER
        );
        assert_eq!(
            init_args.cert_duration,
            "72h",
            "reinit must derive defaultTLSCertDuration from the preserved \
             ca.json, not default to {default:?}",
            default = crate::commands::init::DEFAULT_CERT_DURATION
        );
    }

    /// Falls back to CLI defaults when `ca.json` is absent (rsync-clone
    /// path or pre-`update_ca_json_with_backup` crash) so reinit still
    /// works against a fresh tree.
    #[test]
    fn init_args_for_reinit_falls_back_to_default_stepca_settings_when_ca_json_absent() {
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
        let init_args = init_args_for_reinit(
            &reinit_args,
            &DeploymentIntent::default(),
            &reinit_args.secrets_dir.secrets_dir,
        );
        assert_eq!(
            init_args.stepca_provisioner,
            crate::commands::init::DEFAULT_STEPCA_PROVISIONER
        );
        assert_eq!(
            init_args.cert_duration,
            crate::commands::init::DEFAULT_CERT_DURATION
        );
    }

    /// Even when `ca.json` exists but has no ACME provisioner (or no
    /// `defaultTLSCertDuration` claim), the CLI defaults must apply
    /// instead of an empty/zero value reaching `update_ca_json_with_backup`.
    #[test]
    fn preserved_stepca_settings_from_ca_json_return_none_when_no_acme() {
        let dir = tempdir().expect("tempdir");
        let config_dir = dir.path().join("config");
        fs::create_dir_all(&config_dir).expect("create config dir");
        fs::write(
            config_dir.join("ca.json"),
            r#"{"authority":{"provisioners":[{"type":"JWK","name":"admin"}]}}"#,
        )
        .expect("write ca.json");
        assert!(preserved_stepca_provisioner_from_ca_json(dir.path()).is_none());
        assert!(preserved_cert_duration_from_ca_json(dir.path()).is_none());
    }

    /// Regression for Round 6 reviewer item: an operator-supplied
    /// `--openbao-url` that differs from the CLI default must be
    /// rejected before any docker call so reinit cannot wipe local
    /// `OpenBao` state and then operate on an external endpoint.
    /// Legitimate non-loopback recovery does not need this flag — the
    /// init pass URL is derived from the snapshotted bind in
    /// `init_args_for_reinit`.
    #[test]
    fn reject_explicit_openbao_url_blocks_non_default_url() {
        let messages = test_messages();
        let err =
            reject_explicit_openbao_url("https://shared-openbao.example", &messages).unwrap_err();
        assert!(
            err.to_string().contains("shared-openbao.example"),
            "got: {err}"
        );
        assert!(
            err.to_string().contains("--openbao-url") || err.to_string().contains("openbao-url"),
            "got: {err}"
        );
    }

    /// Even a non-loopback URL that *could* be the local compose bind
    /// (e.g. `https://192.168.1.10:8200`) must be rejected from the CLI
    /// surface — the snapshot-driven rewrite in `init_args_for_reinit`
    /// is the only sanctioned channel for non-loopback init-pass URLs.
    /// Otherwise the operator could bypass the compose-label scope check
    /// by passing a URL that *happens* to match an external service on
    /// the same subnet.
    #[test]
    fn reject_explicit_openbao_url_blocks_non_loopback_explicit_value() {
        let messages = test_messages();
        reject_explicit_openbao_url("https://192.168.1.10:8200", &messages)
            .expect_err("any non-default URL must be rejected, even private-subnet ones");
    }

    /// The CLI default must pass through so the documented `bootroot reinit`
    /// invocation (no `--openbao-url`) keeps working.
    #[test]
    fn reject_explicit_openbao_url_accepts_cli_default() {
        let messages = test_messages();
        reject_explicit_openbao_url(crate::commands::init::DEFAULT_OPENBAO_URL, &messages)
            .expect("CLI default URL must be accepted");
    }

    /// Regression for Round 4 reviewer item: when `state.json` snapshots
    /// a non-default `secrets_dir` (e.g. the previous init ran with
    /// `--secrets-dir secrets-custom`), the documented `bootroot reinit`
    /// invocation without `--secrets-dir` must still operate on that
    /// tree.  The effective dir drives the cleanup path
    /// (`remove_openbao_runtime_state`), the `ca.json` read in
    /// `init_args_for_reinit`, the second init pass'
    /// `args.secrets_dir.secrets_dir`, and the rewritten
    /// `state.json.secrets_dir`.  Otherwise stale `OpenBao` runtime files
    /// or service credentials remain in the real tree, the preserved DSN
    /// is missed, and `password.txt` preservation does not apply.
    #[test]
    fn effective_secrets_dir_prefers_snapshot_over_cli_default() {
        let reinit_args = ReinitArgs {
            openbao: OpenBaoArgs {
                openbao_url: crate::commands::init::DEFAULT_OPENBAO_URL.to_string(),
                kv_mount: "secret".to_string(),
            },
            secrets_dir: SecretsDirArgs {
                // CLI default `secrets` — operator did not re-pass the
                // custom value on the reinit invocation.
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
            secrets_dir: Some(PathBuf::from("secrets-custom")),
            ..DeploymentIntent::default()
        };
        let effective = effective_secrets_dir(&reinit_args, &snapshot);
        assert_eq!(effective, PathBuf::from("secrets-custom"));
    }

    /// Snapshot-driven `secrets_dir` must thread into `InitArgs`, so the
    /// second init pass reads `password.txt` / `ca.json` from the right
    /// tree and writes the rewritten `state.json.secrets_dir` back to
    /// that tree (not the CLI default).
    #[test]
    fn init_args_for_reinit_uses_snapshotted_secrets_dir_and_preserved_dsn() {
        let dir = tempdir().expect("tempdir");
        let snapshot_secrets = dir.path().join("secrets-custom");
        let config_dir = snapshot_secrets.join("config");
        fs::create_dir_all(&config_dir).expect("create config dir");
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
            // CLI default `secrets` (no `--secrets-dir` flag).  An empty
            // `secrets/config/ca.json` is intentionally NOT created in
            // the CLI-default tree — the test asserts that the resolver
            // reads from the snapshot dir, not the CLI default.
            secrets_dir: SecretsDirArgs {
                secrets_dir: dir.path().join("secrets"),
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
            secrets_dir: Some(snapshot_secrets.clone()),
            ..DeploymentIntent::default()
        };
        let effective = effective_secrets_dir(&reinit_args, &snapshot);
        assert_eq!(effective, snapshot_secrets);

        let init_args = init_args_for_reinit(&reinit_args, &snapshot, &effective);
        assert_eq!(
            init_args.secrets_dir.secrets_dir, snapshot_secrets,
            "init args must carry the snapshotted secrets_dir so the \
             second init pass operates on the right tree"
        );
        assert_eq!(
            init_args.db_dsn.as_deref(),
            Some(expected_dsn.as_str()),
            "preserved DSN must be read from the snapshotted secrets_dir"
        );
    }

    /// Regression for Round 1 (#601) reviewer item: when `password.txt`
    /// is missing but the preserved step-ca CA material is still on disk,
    /// the second init pass would auto-generate a fresh password and
    /// write it to `password.txt` / `OpenBao` KV — but that new password
    /// cannot unlock the preserved root/intermediate keys.  The
    /// preflight must bail BEFORE the destructive `OpenBao` wipe so the
    /// operator's CA material remains recoverable from backup.
    #[test]
    fn verify_stepca_password_recoverable_rejects_missing_password_with_root_key_present() {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path();
        fs::create_dir_all(secrets.join("config")).expect("config dir");
        fs::create_dir_all(secrets.join("secrets")).expect("secrets dir");
        fs::write(secrets.join("config/ca.json"), "{}").expect("ca.json");
        fs::write(secrets.join("secrets/root_ca_key"), "encrypted-key").expect("root_ca_key");
        // No password.txt and no intermediate_ca_key — root key alone is
        // already enough to make password rotation destructive.
        assert!(!secrets.join("password.txt").exists());

        let messages = test_messages();
        let err = verify_stepca_password_recoverable(secrets, &messages).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("password.txt") || msg.contains("CA material"),
            "got: {msg}"
        );
    }

    /// Companion to the root-key case: an intermediate key alone is
    /// equally destructive because step-ca's HTTP-01 issuance path uses
    /// it.  The preflight rejects either preserved key when the password
    /// is gone, not only the both-keys-present case.
    #[test]
    fn verify_stepca_password_recoverable_rejects_missing_password_with_intermediate_key_present() {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path();
        fs::create_dir_all(secrets.join("config")).expect("config dir");
        fs::create_dir_all(secrets.join("secrets")).expect("secrets dir");
        fs::write(secrets.join("config/ca.json"), "{}").expect("ca.json");
        fs::write(secrets.join("secrets/intermediate_ca_key"), "encrypted-key")
            .expect("intermediate_ca_key");
        assert!(!secrets.join("password.txt").exists());

        let messages = test_messages();
        let err = verify_stepca_password_recoverable(secrets, &messages).unwrap_err();
        assert!(
            err.to_string().contains("intermediate_ca_key") || err.to_string().contains("ca.json"),
            "got: {err}"
        );
    }

    /// Regression: when both `password.txt` and the CA material are
    /// absent (the rsync-clone-without-CA path or a fresh tree), the
    /// second init pass will `step ca init` from scratch and the
    /// auto-generated password will encrypt the new CA — so the
    /// preflight must not bail.  This is the case the existing
    /// `secrets.rs` regression test
    /// (`resolve_init_secrets_auto_generates_stepca_password_when_missing_in_reinit_mode`)
    /// already covers at the resolver boundary; the preflight just
    /// needs to leave it alone.
    #[test]
    fn verify_stepca_password_recoverable_accepts_missing_password_without_ca_material() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        verify_stepca_password_recoverable(dir.path(), &messages)
            .expect("no CA material → fresh-CA recovery is safe");
    }

    /// Regression for Round 2 (#601) reviewer item: preserved key
    /// material without `ca.json` must still trip the preflight.  The
    /// previous predicate required `ca.json` *and* a key file, which
    /// silently let `reinit --yes` proceed when `ca.json` was missing
    /// but `root_ca_key` (or `intermediate_ca_key`) was preserved.
    /// `ensure_step_ca_initialized` only short-circuits when all three
    /// files exist, so the second init pass would attempt `step ca init`
    /// into a tree that still contains encrypted key material — either
    /// overwriting it or failing mid-flow after the destructive
    /// `OpenBao` wipe.
    #[test]
    fn verify_stepca_password_recoverable_rejects_missing_password_with_root_key_only() {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path();
        fs::create_dir_all(secrets.join("secrets")).expect("secrets dir");
        fs::write(secrets.join("secrets/root_ca_key"), "encrypted-key").expect("root_ca_key");
        assert!(!secrets.join("password.txt").exists());
        assert!(!secrets.join("config/ca.json").exists());

        let messages = test_messages();
        let err = verify_stepca_password_recoverable(secrets, &messages).unwrap_err();
        assert!(err.to_string().contains("root_ca_key"), "got: {err}");
    }

    /// Companion: an intermediate key without `ca.json` is equally
    /// blocking.  Same reasoning as the root-key-only case.
    #[test]
    fn verify_stepca_password_recoverable_rejects_missing_password_with_intermediate_key_only() {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path();
        fs::create_dir_all(secrets.join("secrets")).expect("secrets dir");
        fs::write(secrets.join("secrets/intermediate_ca_key"), "encrypted-key")
            .expect("intermediate_ca_key");
        assert!(!secrets.join("password.txt").exists());
        assert!(!secrets.join("config/ca.json").exists());

        let messages = test_messages();
        let err = verify_stepca_password_recoverable(secrets, &messages).unwrap_err();
        assert!(
            err.to_string().contains("intermediate_ca_key"),
            "got: {err}"
        );
    }

    /// Regression for Round 3 (#601) reviewer item: a stale
    /// `config/ca.json` without either CA key is also blocking, even
    /// though it does not lock the operator out cryptographically.
    /// `ensure_step_ca_initialized` only short-circuits when all three
    /// step-ca artifacts exist, so when `ca.json` alone is preserved
    /// the second init pass would attempt `step ca init` into a tree
    /// that already contains the config target.  Empirically that
    /// generates fresh cert/key files and then exits non-zero with
    /// `open /dev/tty failed`, recreating the partial-init trap after
    /// `OpenBao` has already been wiped.  The preflight must refuse
    /// before any destructive operation runs so the operator can
    /// remove the stale `ca.json` (or restore `password.txt`) and
    /// retry against an atomic reinit.
    #[test]
    fn verify_stepca_password_recoverable_rejects_missing_password_with_ca_json_only() {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path();
        fs::create_dir_all(secrets.join("config")).expect("config dir");
        fs::write(secrets.join("config/ca.json"), "{}").expect("ca.json");
        assert!(!secrets.join("password.txt").exists());
        assert!(!secrets.join("secrets/root_ca_key").exists());
        assert!(!secrets.join("secrets/intermediate_ca_key").exists());

        let messages = test_messages();
        let err = verify_stepca_password_recoverable(secrets, &messages).unwrap_err();
        assert!(err.to_string().contains("ca.json"), "got: {err}");
    }

    /// Regression for Round 4 (#601) reviewer item: `step ca init`
    /// also writes `certs/root_ca.crt`, `certs/intermediate_ca.crt`,
    /// and `config/defaults.json`.  The Round 3 predicate only keyed
    /// off the three files used by `ensure_step_ca_initialized`'s
    /// short-circuit, so a stale `certs/root_ca.crt` (or any of the
    /// other writes) left the preflight accepting reinit even though
    /// the second init pass's `step ca init` would still fail mid-flow
    /// with `open /dev/tty failed` after the destructive `OpenBao`
    /// wipe.  The preflight must refuse for every file `step ca init`
    /// would touch.
    #[test]
    fn verify_stepca_password_recoverable_rejects_missing_password_with_root_cert_only() {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path();
        fs::create_dir_all(secrets.join("certs")).expect("certs dir");
        fs::write(secrets.join("certs/root_ca.crt"), "stale-cert").expect("root_ca.crt");
        assert!(!secrets.join("password.txt").exists());

        let messages = test_messages();
        let err = verify_stepca_password_recoverable(secrets, &messages).unwrap_err();
        assert!(err.to_string().contains("root_ca.crt"), "got: {err}");
    }

    /// Companion: a stale `certs/intermediate_ca.crt` alone is also
    /// blocking — same reasoning as the root-cert-only case.
    #[test]
    fn verify_stepca_password_recoverable_rejects_missing_password_with_intermediate_cert_only() {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path();
        fs::create_dir_all(secrets.join("certs")).expect("certs dir");
        fs::write(secrets.join("certs/intermediate_ca.crt"), "stale-cert")
            .expect("intermediate_ca.crt");
        assert!(!secrets.join("password.txt").exists());

        let messages = test_messages();
        let err = verify_stepca_password_recoverable(secrets, &messages).unwrap_err();
        assert!(
            err.to_string().contains("intermediate_ca.crt"),
            "got: {err}"
        );
    }

    /// Companion: a stale `config/defaults.json` alone is also
    /// blocking.  `step ca init` writes it unconditionally, and the
    /// reviewer's reproduction shows it triggers the same TTY-bound
    /// overwrite failure when present alone.
    #[test]
    fn verify_stepca_password_recoverable_rejects_missing_password_with_defaults_json_only() {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path();
        fs::create_dir_all(secrets.join("config")).expect("config dir");
        fs::write(secrets.join("config/defaults.json"), "{}").expect("defaults.json");
        assert!(!secrets.join("password.txt").exists());

        let messages = test_messages();
        let err = verify_stepca_password_recoverable(secrets, &messages).unwrap_err();
        assert!(err.to_string().contains("defaults.json"), "got: {err}");
    }

    /// When `password.txt` is present, the preflight accepts the
    /// preserved CA material — the existing
    /// `resolve_init_secrets`-level preserve-password fast-path handles
    /// it correctly.
    #[test]
    fn verify_stepca_password_recoverable_accepts_password_with_ca_material() {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path();
        fs::create_dir_all(secrets.join("config")).expect("config dir");
        fs::create_dir_all(secrets.join("secrets")).expect("secrets dir");
        fs::write(secrets.join("config/ca.json"), "{}").expect("ca.json");
        fs::write(secrets.join("secrets/root_ca_key"), "encrypted-key").expect("root_ca_key");
        fs::write(secrets.join("secrets/intermediate_ca_key"), "encrypted-key")
            .expect("intermediate_ca_key");
        fs::write(secrets.join("password.txt"), "preserved-secret").expect("password.txt");
        let messages = test_messages();
        verify_stepca_password_recoverable(secrets, &messages)
            .expect("present password.txt + preserved CA material is the normal recovery path");
    }

    /// The rewritten `state.json` must record the snapshotted (or
    /// CLI-default fallback) `secrets_dir` so a subsequent reinit on the
    /// same tree does not silently regress to the CLI default.
    #[test]
    fn write_minimal_state_preserves_snapshotted_secrets_dir() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        state_with_intent().save(&state_path).unwrap();
        let snapshot = DeploymentIntent {
            secrets_dir: Some(PathBuf::from("secrets-custom")),
            ..DeploymentIntent::default()
        };
        let openbao = OpenBaoArgs {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
        };
        let messages = test_messages();
        write_minimal_state(
            &state_path,
            &snapshot,
            &openbao,
            Path::new("secrets-custom"),
            &messages,
        )
        .unwrap();
        let rewritten = StateFile::load(&state_path).unwrap();
        assert_eq!(
            rewritten.secrets_dir.as_deref(),
            Some(Path::new("secrets-custom")),
            "minimal state.json must record the snapshotted secrets_dir"
        );
    }
}
