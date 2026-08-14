use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io::IsTerminal;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::db::parse_db_dsn;
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;

use super::super::paths::{compose_has_responder, resolve_responder_url};
use super::super::types::{
    AppRoleLabel, DbCheckStatus, InitPlan, InitSummary, OpenBaoConfigResult,
};
use super::InitRollback;
use super::RollbackFile;
use super::database::{PostgresEnv, check_db_connectivity, resolve_db_dsn_for_init};
use super::http01_admin_tls::{
    build_http01_admin_tls_sans, issue_http01_admin_tls_cert, record_http01_admin_infra_cert,
};
use super::openbao_setup::{
    apply_openbao_agent_compose_override, bootstrap_openbao, configure_openbao,
    setup_openbao_agents, validate_rotate_bound_cidrs, validate_secret_id_ttl,
    write_ca_trust_fingerprints_with_retry,
};
use super::openbao_tls::{
    build_openbao_tls_sans, issue_openbao_tls_cert, record_openbao_infra_cert,
    write_openbao_hcl_with_tls,
};
use super::openbao_transition::{OpenBaoTlsTransition, UnsealKeyInputs};
use super::prompts::{confirm_overwrite, should_confirm};
use super::responder_setup::{
    apply_responder_compose_override, verify_responder, write_responder_compose_override,
    write_responder_files,
};
use super::secrets::{maybe_register_eab, resolve_init_secrets};
use super::stepca_setup::{
    CA_JSON_FILE_MODE, ensure_step_ca_initialized, reconcile_ca_json_dns_names,
    resolve_stepca_ca_dns_names, restart_stepca_openbao_agent, snapshot_stepca_ca_json_template,
    update_ca_json_with_backup, write_password_file_with_backup, write_stepca_templates,
};
use crate::cli::args::{InitArgs, InitFeature};
use crate::cli::output::{print_init_plan, print_init_summary};
use crate::commands::compose_file::compose_file_dir;
use crate::commands::compose_project::ComposeIdentity;
use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::container_name::BootrootContainer;
use crate::commands::guardrails::{
    client_url_from_bind_addr, ensure_all_services_localhost_binding, validate_http01_admin_tls,
    validate_http01_override_binding, validate_http01_override_scope,
    validate_openbao_override_binding, validate_openbao_override_scope, validate_openbao_tls,
};
use crate::commands::infra::{
    ensure_init_prereqs_ready, has_http01_admin_bind_intent, has_openbao_bind_intent,
    resolve_stepca_exposed_override, run_compose,
};
use crate::commands::init::{
    HTTP01_ADMIN_TLS_CERT_REL_PATH, HTTP01_ADMIN_TLS_KEY_REL_PATH,
    HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_HCL_PATH,
    OPENBAO_TLS_CERT_PATH, OPENBAO_TLS_KEY_PATH, RESPONDER_CONFIG_DIR, RESPONDER_CONFIG_NAME,
};
use crate::commands::openbao_unseal::unseal_keys_path;
use crate::commands::openbao_url::{OPENBAO_HOST_PORT_ENV, effective_openbao_url_with_env};
use crate::i18n::Messages;
use crate::state::StateFile;

/// Mode for the two operator-facing secret files `init` can be asked to
/// write, `--summary-json` and `--root-token-output`. Both carry root
/// credentials, so both are operator-only.
const SECRET_OUTPUT_FILE_MODE: u32 = 0o600;

/// Returns `args` with `openbao_url` rewritten to the endpoint the
/// configured `OpenBao` host port publishes, borrowing them unchanged
/// when the CLI value already names it.
///
/// Only the port is derived: `infra install` resets `OpenBao` to
/// plaintext loopback even when a non-loopback bind intent is recorded,
/// and `run_init_inner`'s own bind-intent-gated branch takes over once
/// the TLS certificate has been issued.
fn args_with_effective_openbao_url(args: &InitArgs) -> Cow<'_, InitArgs> {
    args_with_effective_openbao_url_with_env(
        args,
        std::env::var(OPENBAO_HOST_PORT_ENV).ok().as_deref(),
    )
}

/// [`args_with_effective_openbao_url`] with the `OPENBAO_HOST_PORT`
/// value supplied by the caller instead of read from the process
/// environment.
fn args_with_effective_openbao_url_with_env<'a>(
    args: &'a InitArgs,
    host_port_env: Option<&str>,
) -> Cow<'a, InitArgs> {
    let compose_dir = compose_file_dir(&args.compose.compose_file);
    let url = effective_openbao_url_with_env(
        &args.openbao.openbao_url,
        &compose_dir,
        None,
        host_port_env,
    );
    if url == args.openbao.openbao_url {
        return Cow::Borrowed(args);
    }
    let mut resolved = args.clone();
    resolved.openbao.openbao_url = url;
    Cow::Owned(resolved)
}

pub(crate) async fn run_init(args: &InitArgs, messages: &Messages) -> Result<()> {
    // Point the whole init flow at the OpenBao host port the compose
    // stack actually publishes.  The first client below is built before
    // any `state.json` value is consulted, so without this a second
    // bootroot instance on the same host would health-check — and then
    // initialise against — the first instance's OpenBao.  An
    // operator-supplied `--openbao-url` is left untouched, as is the
    // later bind-intent-gated rewrite in `run_init_inner`.
    let resolved = args_with_effective_openbao_url(args);
    let args = resolved.as_ref();

    if let Some(warning) = validate_secret_id_ttl(&args.secret_id_ttl, messages)? {
        eprintln!("{warning}");
    }
    validate_rotate_bound_cidrs(&args.rotate_bound_cidrs, messages)?;
    bootroot::config::validate_cert_duration_vs_default_renew_before(&args.cert_duration)?;
    eprintln!("{}", messages.hint_secret_id_ttl_rotation_cadence());

    // Validate optional secret-bearing output destinations *before* any
    // OpenBao work begins.  Both files are written only after
    // `run_init_inner` returns: an unwritable destination would otherwise
    // fail post-init, after OpenBao has been initialised but before
    // `print_init_summary` / `maybe_save_unseal_keys` run, recreating
    // the partial-init trap with the freshly issued root token and
    // unseal keys captured nowhere.  Reinit already gates the same paths
    // at its own preflight; this mirrors that for the direct `init`
    // surface.  Critical for `--no-save-unseal-keys`, whose only capture
    // channel is the summary JSON, but the same ordering issue applies
    // to `--save-unseal-keys` and to bare `--summary-json`/`--root-token-output`.
    if let Some(out) = args.summary_json.as_deref() {
        crate::commands::reinit::validate_summary_json_output_path(out, messages)?;
    }
    if let Some(out) = args.root_token_output.as_deref() {
        crate::commands::reinit::validate_root_token_output_path(out, messages)?;
    }

    ensure_all_services_localhost_binding(&args.compose.compose_file, messages)?;

    // Check whether a non-loopback OpenBao bind intent is stored in
    // state.  TLS is validated inside `run_init_inner` (after
    // `ensure_step_ca_initialized`) so that failures trigger rollback.
    let state_path = StateFile::default_path();
    let bind_intent = has_openbao_bind_intent(&state_path)?;

    // Only check openbao + postgres; step-ca may not be bootstrapped yet.
    ensure_init_prereqs_ready(&args.compose.compose_file, messages)?;

    let mut client =
        OpenBaoClient::with_local_trust(&args.openbao.openbao_url, &args.secrets_dir.secrets_dir)
            .with_context(|| messages.error_openbao_client_create_failed())?;
    client
        .health_check()
        .await
        .with_context(|| messages.error_openbao_health_check_failed())?;

    // §5a: detect a partial-init OpenBao state and emit an actionable
    // diagnostic instead of bubbling up the opaque 403 the caller would
    // get when bootstrap_openbao tries to authenticate without a usable
    // root token. A previous `init` that failed mid-flight rolls back
    // its in-flight artefacts but leaves OpenBao initialised in its
    // volume; the next `init` cannot authenticate.
    diagnose_partial_init(&client, args, messages).await?;

    let mut rollback = InitRollback::default();
    let result = run_init_inner(&mut client, args, messages, &mut rollback, bind_intent).await;

    match result {
        Ok(summary) => {
            if let Some(summary_json) = args.summary_json.as_deref() {
                write_init_summary_json(summary_json, &summary).await?;
            }
            // Print the summary *before* attempting the optional
            // root-token file write so a write failure does not hide the
            // freshly issued root token from the operator's terminal —
            // OpenBao has already been initialised at this point and a
            // lost token would force another reinit cycle.
            print_init_summary(&summary, messages);
            if let Some(root_token_path) = args.root_token_output.as_deref()
                && let Err(err) = write_root_token_file(root_token_path, &summary.root_token).await
            {
                // Surface the freshly issued root token on stderr in
                // cleartext.  Init has just completed against a brand
                // new OpenBao, so without this channel the operator
                // would have only the masked summary above (the
                // `display_secret` helper hides the token unless
                // `--enable show-secrets` was set) and would have to
                // run another `reinit` cycle to recover access.
                eprintln!(
                    "{}",
                    messages.error_reinit_root_token_persist_failed(
                        &root_token_path.display().to_string(),
                        &err.to_string(),
                        &summary.root_token,
                    )
                );
                return Err(err);
            }

            // Prompt to save unseal keys if they were just generated.
            // Under reinit mode the operator already authorized the
            // destructive flow at the `reinit` level; the issue
            // acceptance criteria require `reinit --yes` to write the
            // fresh keys automatically with no further interaction.
            if summary.init_response && !summary.unseal_keys.is_empty() {
                let decision = if args.reinit_mode || args.save_unseal_keys {
                    SaveUnsealKeysDecision::Save
                } else if args.no_save_unseal_keys {
                    SaveUnsealKeysDecision::DoNotSave
                } else {
                    SaveUnsealKeysDecision::Prompt
                };
                maybe_save_unseal_keys(
                    &args.secrets_dir.secrets_dir,
                    &summary.unseal_keys,
                    decision,
                    messages,
                )
                .await?;
            }

            Ok(())
        }
        Err(err) => {
            eprintln!("{}", messages.init_failed_rollback());
            rollback
                .rollback(&client, &args.openbao.kv_mount, messages)
                .await;
            Err(err)
        }
    }
}

/// Aborts with operator guidance when the target `OpenBao` is already
/// initialised but neither `--root-token` nor `OPENBAO_ROOT_TOKEN` is
/// set. Bootstrapping past this state would fail with `403 permission
/// denied` from the first authenticated call; the diagnostic names the
/// three recovery paths (re-supply token, `clean --openbao-only`, or
/// manual operator action). See issue #588 §5.
async fn diagnose_partial_init(
    client: &OpenBaoClient,
    args: &InitArgs,
    messages: &Messages,
) -> Result<()> {
    let initialized = client.is_initialized().await.with_context(|| {
        "failed to query OpenBao /sys/init while diagnosing partial-init state".to_string()
    })?;
    if !initialized {
        return Ok(());
    }
    let token_supplied = args
        .root_token
        .root_token
        .as_deref()
        .is_some_and(|t| !t.is_empty());
    if token_supplied {
        return Ok(());
    }
    anyhow::bail!(messages.error_init_partial_openbao_state(&args.openbao.openbao_url));
}

/// Writes the init summary JSON to `path` atomically with mode `0600`.
///
/// The summary carries the freshly issued root token and unseal keys
/// (see `InitSummary`).  A naive `tokio::fs::write` followed by
/// `set_key_permissions` would briefly expose those secrets:
/// 1. A newly created file picks up the process umask first (commonly
///    `0644`) and is only chmodded to `0600` after the secrets land on
///    disk.
/// 2. An existing destination's pre-write mode is preserved by the
///    write — overwriting a `0644` file leaves it world-readable while
///    the secret-bearing JSON is on disk, until the subsequent chmod.
///
/// The write goes through [`fs_util::atomic_write_blocking`], which
/// stages the JSON in a temporary file in the same directory born
/// `0600`, flushes it, sets the mode there, and only then `rename`s it
/// over the destination.  The secrets therefore never touch the
/// destination inode at all, so neither hazard above has a window: the
/// published file is `0600` from the instant the name points at it.
///
/// The pre-write tightening of an existing destination is kept.  It
/// guards what the rename cannot — an older summary, with older
/// credentials in it, sitting world-readable at the path right now.
/// Renaming a fresh inode over it does not narrow that file during the
/// write.  `validate_summary_json_output_path` rejects such a
/// destination on both the `init` and the `reinit` path, but it runs
/// before `OpenBao` is touched: the whole of init happens between that
/// judgement and this write, and a file appearing or being widened in
/// that window is exactly what this narrows.
///
/// The containing directory is flushed after the rename, inside
/// `atomic_write_blocking`.  This file is written once during `init`
/// and read by an operator afterwards, possibly as the only record of
/// credentials that cannot be re-derived, so it is worth the disk round
/// trip that makes the published name survive a power loss.
///
/// A symlinked destination is resolved first
/// ([`fs_util::resolve_symlink_destination`]), so the rename lands on
/// the link's target the way the truncating write's `O_TRUNC` did.
/// Renaming over the link instead would leave the operator without
/// their link and the target holding the previous run's credentials.
async fn write_init_summary_json(path: &Path, summary: &InitSummary) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    let payload = serde_json::to_string_pretty(summary)?;
    let path_buf = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let dest = fs_util::resolve_symlink_destination(&path_buf)?;
        tighten_existing_secret_file(&dest)?;
        fs_util::atomic_write_blocking(&dest, payload.as_bytes(), SECRET_OUTPUT_FILE_MODE)
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking for summary json write failed: {e}"))??;
    Ok(())
}

/// Narrows an existing destination to `0600` before a secret is written
/// over it.  A no-op when nothing is there, which is the usual case.
///
/// The staged write that follows replaces the path with a fresh inode,
/// so this is not about the bytes being written — it is about the ones
/// already at the path.  A summary or token file left behind by an
/// earlier run at a wider mode stays readable for as long as it takes
/// the new one to be produced, and that file holds credentials too.
fn tighten_existing_secret_file(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if !path.exists() {
        return Ok(());
    }
    std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(SECRET_OUTPUT_FILE_MODE),
    )
    .with_context(|| {
        format!(
            "Failed to set mode {SECRET_OUTPUT_FILE_MODE:o} on the existing {}",
            path.display()
        )
    })
}

/// Persists the freshly generated `OpenBao` root token to `path` with
/// mode `0600`.  Invoked only when the operator passes
/// `bootroot reinit --root-token-output <path>`; persistent root token
/// files are not recommended for production and the surrounding code
/// validates the destination path before any destructive work begins.
///
/// Written exactly as the init summary is, through
/// [`fs_util::atomic_write_blocking`]: the token is staged in a
/// temporary file in the same directory born `0600`, flushed, moded,
/// and `rename`d over the destination.  So a freshly minted root token
/// never exists on disk at the process umask's default permissions
/// (commonly `0644`), and never at the destination name in a partial
/// state.  An existing destination is tightened first, for the older
/// token that may still be sitting in it — see
/// [`tighten_existing_secret_file`].
///
/// The containing directory is flushed after the rename, inside
/// `atomic_write_blocking`.  The token is written once and read by an
/// operator afterwards; losing the published name to a power loss
/// means losing the only copy of a credential `reinit` will not mint
/// again, which is worth a disk round trip on a once-per-init write.
///
/// A symlinked destination is resolved first, as it is for the summary
/// JSON — `validate_root_token_output_path` accepts a link to a regular
/// file on purpose, so the token has to reach the file that preflight
/// judged and not replace the link that named it.
async fn write_root_token_file(path: &Path, token: &str) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    let path_buf = path.to_path_buf();
    let token = token.to_string();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let dest = fs_util::resolve_symlink_destination(&path_buf)?;
        tighten_existing_secret_file(&dest)?;
        fs_util::atomic_write_blocking(&dest, token.as_bytes(), SECRET_OUTPUT_FILE_MODE)
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking for root token write failed: {e}"))??;
    Ok(())
}

/// One of the confirmations init asks before it starts writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreflightPrompt {
    OverwritePassword,
    OverwriteCaJson,
    OverwriteState,
    DbProvision,
}

impl PreflightPrompt {
    fn message(self, messages: &Messages) -> &str {
        match self {
            Self::OverwritePassword => messages.prompt_confirm_overwrite_password(),
            Self::OverwriteCaJson => messages.prompt_confirm_overwrite_ca_json(),
            Self::OverwriteState => messages.prompt_confirm_overwrite_state(),
            Self::DbProvision => messages.prompt_confirm_db_provision(),
        }
    }
}

/// Decides which pre-flight confirmations `run_init_inner` must ask, in
/// the order it asks them.
///
/// Each prompt is gated on its own condition (file existence for the
/// three overwrite prompts, the `db-provision` feature for the fourth)
/// and answered non-interactively by its own flag alone, so no flag
/// implies another.  Under reinit mode the operator has already
/// authorized destructive recovery at the `reinit` level, and reinit
/// explicitly preserves `password.txt`, `ca.json`, and the
/// (just-rewritten) `state.json` — suppressing all four keeps
/// `reinit --yes` non-interactive.
fn preflight_prompts(args: &InitArgs, plan: &InitPlan) -> Vec<PreflightPrompt> {
    let reinit = args.reinit_mode;
    [
        (
            PreflightPrompt::OverwritePassword,
            plan.overwrite_password,
            args.overwrite_password,
        ),
        (
            PreflightPrompt::OverwriteCaJson,
            plan.overwrite_ca_json,
            args.overwrite_ca_json,
        ),
        (
            PreflightPrompt::OverwriteState,
            plan.overwrite_state,
            args.overwrite_state,
        ),
        (
            PreflightPrompt::DbProvision,
            args.has_feature(InitFeature::DbProvision),
            args.confirm_db_provision,
        ),
    ]
    .into_iter()
    .filter(|&(_, condition, confirmed)| should_confirm(condition, confirmed, reinit))
    .map(|(prompt, _, _)| prompt)
    .collect()
}

#[allow(clippy::too_many_lines)]
// Keep init flow in one place to preserve ordering across subsystems.
async fn run_init_inner(
    client: &mut OpenBaoClient,
    args: &InitArgs,
    messages: &Messages,
    rollback: &mut InitRollback,
    bind_intent: bool,
) -> Result<InitSummary> {
    let bootstrap = bootstrap_openbao(client, args, messages).await?;
    let overwrite_password = args.secrets_dir.secrets_dir.join("password.txt").exists();
    let overwrite_ca_json = args
        .secrets_dir
        .secrets_dir
        .join("config")
        .join("ca.json")
        .exists();
    let overwrite_state = StateFile::default_path().exists();
    let plan = InitPlan {
        openbao_url: args.openbao.openbao_url.clone(),
        kv_mount: args.openbao.kv_mount.clone(),
        secrets_dir: args.secrets_dir.secrets_dir.clone(),
        overwrite_password,
        overwrite_ca_json,
        overwrite_state,
    };
    print_init_plan(&plan, messages);
    for prompt in preflight_prompts(args, &plan) {
        confirm_overwrite(prompt.message(messages), messages)?;
    }

    let compose_dir = crate::commands::compose_file::compose_file_dir(&args.compose.compose_file);
    let compose_dir = compose_dir.as_path();

    // `init` has no identity flag: the project comes from the `.env`
    // `infra install` left beside the compose file (or an exported
    // `COMPOSE_PROJECT_NAME`), so it acts on the stack it was pointed at.
    //
    // Resolved before `.env` is loaded into the process environment, so
    // that `init` resolves from exactly what `status` and `clean` see.
    // Several sub-steps below re-resolve the project after that load —
    // the agent-sidecar and responder overrides, the `OpenBao` TLS
    // recreate, the DB-password rotation and rollback — so they must all
    // reach the same answer. `load_dotenv_into_env` skips
    // `COMPOSE_PROJECT_NAME` for exactly that reason; see its doc
    // comment.
    let identity = ComposeIdentity::resolve(&args.compose.compose_file, None, messages)?;

    // Load .env into the process environment so that
    // `build_admin_dsn_from_env()` and `build_dsn_from_env()` can discover
    // the temporary POSTGRES_PASSWORD written by `infra install`.
    crate::commands::dotenv::load_dotenv_into_env(&compose_dir.join(".env"), messages)?;

    // Read after the `.env` load above, which is what puts the
    // `PostgreSQL` credentials `infra install` generated into the
    // process environment.
    let postgres_env = PostgresEnv::from_process_env();
    let (db_dsn, db_dsn_normalization, admin_dsn_for_kv) =
        resolve_db_dsn_for_init(args, compose_dir, &postgres_env, messages).await?;
    let mut secrets = resolve_init_secrets(args, messages, db_dsn)?;
    let db_info = parse_db_dsn(&secrets.db_dsn)
        .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
    let db_check = if args.has_feature(InitFeature::DbCheck) {
        check_db_connectivity(
            &db_info,
            &secrets.db_dsn,
            args.db_timeout.timeout_secs,
            messages,
        )
        .await?;
        DbCheckStatus::Ok
    } else {
        DbCheckStatus::Skipped
    };

    let OpenBaoConfigResult {
        role_outputs,
        approles,
    } = configure_openbao(client, args, &secrets, rollback, messages).await?;

    // Persist the admin DSN bootroot used to provision the runtime
    // role/database. `rotate db` reads this with the operator/root
    // token at rotate time so the operator no longer has to pass
    // `--db-admin-dsn` on every rotation. The KV path carries strictly
    // higher privilege than `PATH_STEPCA_DB`; the existing step-ca
    // runtime and infra agent policies must not include it.
    if let Some(admin_dsn) = admin_dsn_for_kv.as_deref() {
        if !client
            .kv_exists(&args.openbao.kv_mount, super::super::PATH_STEPCA_DB_ADMIN)
            .await
            .with_context(|| messages.error_openbao_kv_exists_failed())?
        {
            rollback
                .written_kv_paths
                .push(super::super::PATH_STEPCA_DB_ADMIN.to_string());
        }
        client
            .write_kv(
                &args.openbao.kv_mount,
                super::super::PATH_STEPCA_DB_ADMIN,
                serde_json::json!({ "value": admin_dsn }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }

    let secrets_dir = args.secrets_dir.secrets_dir.clone();

    // Write password.txt first - step-ca init needs it.
    rollback.password_backup = Some(
        write_password_file_with_backup(&secrets_dir, &secrets.stepca_password, messages).await?,
    );

    // Bootstrap step-ca if not already initialized. This creates ca.json
    // and keys inside secrets/config/ and secrets/secrets/.  Must run
    // before update_ca_json_with_backup and write_stepca_templates, which
    // both read ca.json.
    //
    // The compose step-ca service runs as root (the custom Dockerfile
    // does not set USER) and has `restart: always`.  Once ca.json
    // appears, the service's next restart attempt succeeds and may
    // create files (e.g. DB state) as root inside the secrets mount.
    // If that happens before `fix_secrets_permissions` runs, the
    // chmod fails with EPERM.  Stop the compose service before init
    // to close the race; it is restarted after ca.json is patched.
    let will_init_stepca = !secrets_dir.join("config").join("ca.json").exists();
    if will_init_stepca {
        let compose_str = args.compose.compose_file.to_string_lossy();
        let stop = identity.compose(&[&compose_str], None, &["stop", "step-ca"]);
        let _ = run_compose(&stop, "docker compose stop step-ca", messages);
    }
    // step-ca's own serving certificate must carry the address
    // `--stepca-bind` publishes it on, otherwise an off-host consumer
    // reaching the ACME directory by that address fails hostname
    // verification even though the bind, the trust anchor and the
    // HTTP-01 responder are all correct (issue #733).  The recorded
    // bind intent is the same one `resolve_stepca_exposed_override`
    // below consumes; deriving the name set here covers both the fresh
    // `step ca init --dns` path and the already-initialized path, which
    // reconciles `ca.json` instead.
    let stepca_dns_names = resolve_stepca_ca_dns_names(
        &StateFile::default_path(),
        &identity.container(BootrootContainer::StepCa),
    )?;
    let step_ca_result = ensure_step_ca_initialized(&secrets_dir, &stepca_dns_names, messages)?;
    if step_ca_result == super::super::types::StepCaInitResult::Initialized {
        // Fix ownership: step-ca init may create files with different
        // ownership.  Re-apply correct perms before anything reads them.
        fix_secrets_permissions(&secrets_dir).await?;
    }

    // Reconciles the `db` section, the ACME provisioner's cert duration
    // and the top-level `dnsNames`.  Runs before `write_stepca_templates`
    // so the generated `ca.json.ctmpl` is built from the patched document
    // (notably `db.type`).
    let ca_json_update = update_ca_json_with_backup(
        &secrets_dir,
        &secrets.db_dsn,
        &args.cert_duration,
        &args.stepca_provisioner,
        &stepca_dns_names,
        messages,
    )
    .await?;
    let stepca_dns_names_changed = ca_json_update.dns_names_changed;
    rollback.ca_json_backup = Some(ca_json_update.rollback);

    // The templates are written here — before step-ca is restarted —
    // because on an already-initialized system the step-ca OpenBao Agent
    // sidecar is already running and re-renders ca.json from the
    // *previous* `ca.json.ctmpl` every render interval.  Regenerating the
    // template first, then restarting the sidecar onto it, then
    // re-asserting the on-disk file is the only ordering in which no
    // render can put the stale name set back, and step-ca is restarted
    // last so it reads the settled document (issue #733).
    //
    // Snapshot the template before it is regenerated: `ca.json` is
    // co-owned with the sidecar, so `rollback.ca_json_backup` is only
    // durable if the template it is re-rendered from is restored with it.
    rollback.stepca_ca_json_template_backup =
        Some(snapshot_stepca_ca_json_template(&secrets_dir, messages).await?);
    let stepca_templates = write_stepca_templates(
        &secrets_dir,
        &args.openbao.kv_mount,
        &args.cert_duration,
        &args.stepca_provisioner,
        &stepca_dns_names,
        messages,
    )
    .await?;

    if stepca_dns_names_changed {
        // On a fresh install the sidecar does not exist yet (and
        // `step ca init --dns` already produced the right name set, so
        // this branch is normally not taken there).  `docker restart`
        // returns only once the old process is gone, so the re-assert
        // below cannot race a render from it.
        //
        // Record the restart before performing it so that a rollback
        // triggered by a later failure restarts the sidecar back onto the
        // template it restores, even if the restart itself half-succeeded.
        rollback.stepca_agent_restarted = true;
        restart_stepca_openbao_agent(
            &identity.container(BootrootContainer::OpenBaoAgentStepCa),
            rollback.docker(),
        );
        reconcile_ca_json_dns_names(&secrets_dir, &stepca_dns_names, messages).await?;
    }

    if step_ca_result == super::super::types::StepCaInitResult::Initialized
        || stepca_dns_names_changed
    {
        // Restart step-ca after ca.json is patched with the DB DSN so it
        // loads the fully configured file on first boot.
        //
        // The `dnsNames` arm covers the already-initialized CA: step-ca
        // derives its serving leaf from `dnsNames` at boot and keeps it
        // in memory, so a restart — not a re-run of `step ca init`,
        // which would replace the root and intermediate keys — is what
        // makes `infra install --stepca-bind` followed by `init` repair
        // an installed system.  Gating on the change keeps a repeat
        // `init` with the same recorded intent restart-free.
        let compose_str = args.compose.compose_file.to_string_lossy();
        let restart = identity.compose(&[&compose_str], None, &["restart", "step-ca"]);
        let _ = run_compose(&restart, "docker compose restart step-ca", messages);
    }
    // Apply the step-ca exposed override when a bind intent is stored.
    // `infra install --stepca-bind` records the intent and writes the
    // override but starts step-ca on the base compose file (loopback
    // publish); init is the next lifecycle command, so without this
    // step the documented fresh path `infra install --stepca-bind` ->
    // `init` would leave the ACME directory unreachable from remote
    // nodes until a separate `infra up`.  Unlike the OpenBao / HTTP-01
    // admin overrides below there is no TLS gate to sequence around —
    // step-ca always terminates TLS — so the override applies as soon
    // as the stored intent validates.  `--no-deps` is load-bearing for
    // the same reason as the responder invocation below: this compose
    // file set does not include the openbao / http01 overrides, so
    // compose must not touch the dependency containers with a merged
    // config that would drop their non-loopback publishes.
    if let Some(stepca_override) =
        resolve_stepca_exposed_override(&StateFile::default_path(), compose_dir, messages)?
    {
        let compose_str = args.compose.compose_file.to_string_lossy();
        let override_str = stepca_override.to_string_lossy();
        let up = identity.compose(
            &[&compose_str, &override_str],
            None,
            &["up", "-d", "--no-deps", "step-ca"],
        );
        run_compose(&up, "docker compose up -d step-ca (exposed)", messages)?;
    }
    let compose_has_responder = compose_has_responder(&args.compose.compose_file, messages)?;
    let responder_tls_enabled =
        compose_has_responder && has_http01_admin_bind_intent(&StateFile::default_path())?;
    // Backup the responder config before writing the TLS-enabled
    // version so that rollback can restore it and restart the
    // responder on loopback without TLS.
    if responder_tls_enabled {
        let config_path = secrets_dir
            .join(RESPONDER_CONFIG_DIR)
            .join(RESPONDER_CONFIG_NAME);
        rollback.responder_config_backup = Some(RollbackFile {
            path: config_path.clone(),
            original: if config_path.exists() {
                Some(std::fs::read_to_string(&config_path)?)
            } else {
                None
            },
        });
        rollback.compose_file = Some(args.compose.compose_file.clone());
    }
    let responder_paths = write_responder_files(
        &secrets_dir,
        &args.openbao.kv_mount,
        &secrets.http_hmac,
        responder_tls_enabled,
        messages,
    )
    .await?;
    let responder_compose_override = write_responder_compose_override(
        &args.compose.compose_file,
        &secrets_dir,
        &responder_paths.config_path,
        responder_tls_enabled,
        messages,
    )
    .await?;
    // `bind_intent` is true exactly for a non-loopback OpenBao bind,
    // which mandates `--openbao-tls-required` and later triggers the
    // OpenBao TLS transition below.  Thread it in so the infra agents
    // are generated to speak TLS (https + CA trust) and their
    // `docker compose up` is deferred to the post-TLS-transition phase.
    let openbao_agent_paths = setup_openbao_agents(
        &args.compose.compose_file,
        &secrets_dir,
        &args.openbao.openbao_url,
        &role_outputs,
        &stepca_templates,
        &responder_paths.template_path,
        bind_intent,
        messages,
    )
    .await?;
    // Issue the HTTP-01 admin TLS certificate before starting the
    // responder so that cert files exist when TLS is enabled in the
    // config.  When TLS is active, apply the config mount and the
    // non-loopback port binding override in a single restart so that
    // the admin API transitions from loopback-only/plain-HTTP to
    // non-loopback/TLS atomically.
    if responder_tls_enabled {
        let state_path = StateFile::default_path();
        let state = StateFile::load(&state_path)?;
        let bind_addr = state
            .http01_admin_bind_addr
            .as_deref()
            .expect("responder_tls_enabled implies http01_admin_bind_addr is Some");
        let sans = build_http01_admin_tls_sans(
            bind_addr,
            state.http01_admin_advertise_addr.as_deref(),
            &identity.container(BootrootContainer::Http01),
        );
        let san_refs: Vec<&str> = sans.iter().map(String::as_str).collect();
        issue_http01_admin_tls_cert(&secrets_dir, &san_refs, rollback.docker(), messages)?;
        // Track TLS artifacts for rollback cleanup.
        rollback
            .tls_artifacts
            .push(secrets_dir.join(HTTP01_ADMIN_TLS_CERT_REL_PATH));
        rollback
            .tls_artifacts
            .push(secrets_dir.join(HTTP01_ADMIN_TLS_KEY_REL_PATH));
    }
    if let Some(override_path) = responder_compose_override.as_ref() {
        if responder_tls_enabled {
            // Track the config override so rollback can restart the
            // responder with its config mount but without the exposed
            // port override.
            rollback.responder_compose_override = Some(override_path.clone());
            let exposed_override = validate_http01_exposed_override_for_init(
                compose_dir,
                &StateFile::default_path(),
                &secrets_dir,
                messages,
            )?;
            let compose_str = args.compose.compose_file.to_string_lossy();
            let config_override_str = override_path.to_string_lossy();
            let exposed_override_str = exposed_override.to_string_lossy();
            // `--no-deps` is load-bearing here for the same reason as
            // `apply_responder_compose_override` and
            // `apply_openbao_agent_compose_override`: this compose
            // invocation does not include the `openbao-exposed`
            // override, so without it compose would recreate the
            // openbao dependency to the merged config and drop its
            // non-loopback host-port publish.  Reinit-recovery's
            // second init pass would then lose access to the bind URL
            // mid-flow.
            let up = identity.compose(
                &[&compose_str, &config_override_str, &exposed_override_str],
                None,
                &["up", "-d", "--no-deps", RESPONDER_SERVICE_NAME],
            );
            run_compose(
                &up,
                "docker compose up -d responder (tls + exposed)",
                messages,
            )?;
        } else {
            apply_responder_compose_override(&args.compose.compose_file, override_path, messages)?;
        }
    }
    let _trust_changed = write_ca_trust_fingerprints_with_retry(
        client,
        &args.openbao.kv_mount,
        &secrets_dir,
        rollback,
        messages,
    )
    .await?;
    let responder_url = resolve_responder_url(
        args,
        compose_has_responder,
        &identity.container(BootrootContainer::Http01),
    )?;
    let responder_check = verify_responder(
        responder_url.as_deref(),
        args,
        messages,
        &secrets,
        &secrets_dir,
    )
    .await?;
    let eab_update = maybe_register_eab(client, args, messages, rollback, &secrets).await?;
    if let Some(eab) = eab_update {
        secrets.eab = Some(eab);
    }

    write_state_file(
        &args.openbao.openbao_url,
        &args.openbao.kv_mount,
        approles,
        &args.secrets_dir.secrets_dir,
        &args.rotate_bound_cidrs,
        &args.secret_id_ttl,
        messages,
    )
    .await?;

    // Rotate the temporary POSTGRES_PASSWORD from .env (written by
    // `infra install`) before building the summary so that the emitted
    // DB DSN reflects the real, post-rotation password.
    let effective_db_dsn = maybe_rotate_env_db_password(
        &args.compose.compose_file,
        &args.openbao.kv_mount,
        client,
        &args.secrets_dir.secrets_dir,
        messages,
    )
    .await?
    .unwrap_or(secrets.db_dsn);

    // Issue the OpenBao TLS certificate, write the TLS-enabled HCL,
    // validate TLS, and apply the non-loopback compose override —
    // all inside the rollback envelope so that failures trigger
    // rollback.  The cert is issued here (not earlier) because
    // `ensure_step_ca_initialized` creates the CA keys above.
    //
    // Validation is keyed off `StateFile` intent, not override file
    // existence — a missing override with recorded intent is an error.
    let effective_openbao_url = if bind_intent {
        let state_path = StateFile::default_path();
        let override_path = compose_dir
            .join("secrets")
            .join("openbao")
            .join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME);
        if !override_path.exists() {
            anyhow::bail!(messages.error_openbao_override_file_missing());
        }
        let mut state = StateFile::load(&state_path)?;
        let bind_addr = state
            .openbao_bind_addr
            .clone()
            .expect("bind_intent is true so openbao_bind_addr must be Some");

        // Backup openbao.hcl and record the compose file so that
        // rollback can restore plaintext HCL and restart OpenBao.
        let hcl_path = compose_dir.join(OPENBAO_HCL_PATH);
        rollback.hcl_backup = Some(RollbackFile {
            path: hcl_path.clone(),
            original: if hcl_path.exists() {
                Some(std::fs::read_to_string(&hcl_path)?)
            } else {
                None
            },
        });
        rollback.compose_file = Some(args.compose.compose_file.clone());

        // Issue the TLS server certificate and rewrite openbao.hcl.
        let openbao_container = identity.container(BootrootContainer::OpenBao);
        let sans = build_openbao_tls_sans(
            &bind_addr,
            state.openbao_advertise_addr.as_deref(),
            &openbao_container,
        );
        let san_refs: Vec<&str> = sans.iter().map(String::as_str).collect();
        issue_openbao_tls_cert(
            compose_dir,
            &args.secrets_dir.secrets_dir,
            &san_refs,
            rollback.docker(),
            messages,
        )?;

        // Track TLS artifacts for rollback cleanup.
        rollback
            .tls_artifacts
            .push(compose_dir.join(OPENBAO_TLS_CERT_PATH));
        rollback
            .tls_artifacts
            .push(compose_dir.join(OPENBAO_TLS_KEY_PATH));

        write_openbao_hcl_with_tls(compose_dir, messages)?;

        // Record the infra cert entry in state so the rotation
        // pipeline can renew it.
        record_openbao_infra_cert(&mut state, compose_dir, sans, &openbao_container);

        validate_openbao_override_scope(&override_path, messages)?;
        validate_openbao_override_binding(&override_path, &bind_addr, messages)?;
        validate_openbao_tls(compose_dir, &args.secrets_dir.secrets_dir, messages)?;

        // The URL that is about to be recorded, and therefore the URL
        // the listener has to answer on.  Always derived from bind_addr
        // (which maps wildcards to loopback via
        // `client_url_from_bind_addr`) so that local commands
        // (auto-unseal, service, rotate) never depend on the external
        // advertise address being hairpin-reachable.  The advertise
        // address is consumed separately by remote bootstrap artifact
        // generation.
        let https_url = client_url_from_bind_addr(&bind_addr);

        // Recreate OpenBao onto the rewritten HCL, confirm the listener
        // really answers over TLS at that URL, and unseal it.  All three
        // are one unit: `openbao.hcl` is bind-mounted, so a plain
        // `up -d` reloads nothing unless the compose configuration
        // changed; the recreate that does reload it brings the
        // Shamir-sealed vault back sealed; and only a TLS request to the
        // live listener proves the transition actually happened
        // (issue #737).
        //
        // `rollback.openbao_recreated` is flipped from inside the
        // transition, at the moment the recreate is dispatched: a
        // failure in the probe or the unseal must roll the container
        // back to the base compose file, while a failure in the
        // availability pre-check — which runs before any Docker call —
        // must leave the running OpenBao alone.
        let transition = OpenBaoTlsTransition::new(
            &args.compose.compose_file,
            &override_path,
            &https_url,
            &args.secrets_dir.secrets_dir,
        );
        transition
            .run(
                &UnsealKeyInputs {
                    in_memory: &bootstrap.unseal_keys,
                    explicit_file: args.openbao_unseal_from_file.as_deref(),
                    default_file: unseal_keys_path(&args.secrets_dir.secrets_dir),
                    interactive: std::io::stdin().is_terminal(),
                },
                &mut rollback.openbao_recreated,
                messages,
            )
            .await?;

        // Persist the CN-side HTTPS URL and infra_certs entry now that
        // the live listener has answered an OpenBao API request over
        // TLS at exactly this URL and the vault is unsealed.  A
        // listener still serving plaintext never reaches this line: the
        // probe above fails and the run rolls back on the plaintext URL
        // `write_state_file` already recorded.
        //
        // Snapshot the pre-TLS `state.json` (still the plaintext URL,
        // no infra cert entries) before persisting the HTTPS URL, so
        // rollback can restore it if the deferred agent apply below or
        // any later fallible step fails after OpenBao has been recreated
        // on plaintext.
        rollback.state_backup = Some(RollbackFile {
            path: state_path.clone(),
            original: if state_path.exists() {
                Some(std::fs::read_to_string(&state_path)?)
            } else {
                None
            },
        });
        state.openbao_url = https_url;
        state
            .save_async(&state_path)
            .await
            .with_context(|| messages.error_serialize_state_failed())?;

        // Phase 2 of the infra-agent bring-up: OpenBao now serves TLS,
        // so apply the deferred agent override to start (and let the two
        // infra agents authenticate over) HTTPS.  `setup_openbao_agents`
        // generated their files/override in TLS form but skipped this
        // `docker compose up` while OpenBao was still plaintext.
        if let Some(override_path) = openbao_agent_paths.compose_override_path.as_ref() {
            // Register the override for rollback *before* applying it so
            // that even a partial `docker compose up` (one agent started,
            // the other not) is torn down when a failure triggers
            // rollback.
            rollback.openbao_agent_compose_override = Some(override_path.clone());
            apply_openbao_agent_compose_override(
                &args.compose.compose_file,
                override_path,
                messages,
            )?;
        }
        state.openbao_url
    } else {
        args.openbao.openbao_url.clone()
    };

    // Record the HTTP-01 admin TLS certificate in infra_certs so the
    // rotation pipeline can renew it.  Deferred to after all fallible
    // phases (DB password rotation, OpenBao TLS) so that a failure
    // in those phases does not leave a stale entry that would trigger
    // renewal against a rolled-back deployment.
    if responder_tls_enabled {
        let state_path = StateFile::default_path();
        let mut state = StateFile::load(&state_path)?;
        let bind_addr = state
            .http01_admin_bind_addr
            .clone()
            .expect("responder_tls_enabled implies http01_admin_bind_addr is Some");
        let responder_container = identity.container(BootrootContainer::Http01);
        let sans = build_http01_admin_tls_sans(
            &bind_addr,
            state.http01_admin_advertise_addr.as_deref(),
            &responder_container,
        );
        record_http01_admin_infra_cert(&mut state, &secrets_dir, sans, &responder_container);
        state
            .save_async(&state_path)
            .await
            .with_context(|| messages.error_serialize_state_failed())?;
    }

    Ok(InitSummary {
        openbao_url: effective_openbao_url,
        kv_mount: args.openbao.kv_mount.clone(),
        secrets_dir: args.secrets_dir.secrets_dir.clone(),
        show_secrets: args.has_feature(InitFeature::ShowSecrets),
        init_response: bootstrap.init_response.is_some(),
        root_token: bootstrap.root_token,
        unseal_keys: bootstrap.unseal_keys,
        approles: role_outputs,
        stepca_password: secrets.stepca_password,
        db_dsn: effective_db_dsn,
        db_dsn_host_original: db_dsn_normalization.original_host,
        db_dsn_host_effective: db_dsn_normalization.effective_host,
        http_hmac: secrets.http_hmac,
        eab: secrets.eab,
        step_ca_result,
        responder_check,
        responder_url,
        responder_template_path: responder_paths.template_path,
        responder_config_path: responder_paths.config_path,
        openbao_agent_stepca_config_path: openbao_agent_paths.stepca_agent_config,
        openbao_agent_responder_config_path: openbao_agent_paths.responder_agent_config,
        openbao_agent_override_path: openbao_agent_paths.compose_override_path,
        db_check,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SaveUnsealKeysDecision {
    /// Neither flag set and not in reinit mode — ask the operator.
    Prompt,
    /// `reinit_mode` or `--save-unseal-keys` — write to disk without
    /// prompting.
    Save,
    /// `--no-save-unseal-keys` — skip persistence AND suppress the
    /// cleartext-echo fallback (operator has captured the keys via
    /// `--summary-json`, which clap enforces at parse time).
    DoNotSave,
}

async fn maybe_save_unseal_keys(
    secrets_dir: &Path,
    keys: &[String],
    decision: SaveUnsealKeysDecision,
    messages: &Messages,
) -> Result<()> {
    use super::prompts::prompt_yes_no;
    let save = match decision {
        SaveUnsealKeysDecision::Save => true,
        SaveUnsealKeysDecision::DoNotSave => false,
        SaveUnsealKeysDecision::Prompt => {
            match prompt_yes_no(messages.prompt_save_unseal_keys(), messages) {
                Ok(answer) => answer,
                Err(err) => {
                    // The prompt could not be answered — stdin is at EOF, or
                    // the read failed.  This runs outside the rollback
                    // envelope with OpenBao already initialised and unsealed,
                    // and the keys exist nowhere else yet, so echo them
                    // before failing: the run still exits nonzero, but the
                    // operator's last capture channel stays open instead of
                    // recreating the partial-init trap the comment in
                    // `run_init` describes.
                    echo_unseal_keys_cleartext(keys, messages);
                    return Err(err);
                }
            }
        }
    };
    if save {
        let path =
            crate::commands::openbao_unseal::save_unseal_keys(secrets_dir, keys, messages).await?;
        println!(
            "{}",
            messages.openbao_unseal_keys_saved(&path.display().to_string())
        );
    } else if matches!(decision, SaveUnsealKeysDecision::Prompt) {
        // User declined saving at the prompt — display the keys in
        // cleartext so they can be copied for manual safekeeping.  Under
        // `--no-save-unseal-keys` the keys are already captured in the
        // 0600 summary JSON (clap enforces `requires = "summary_json"`),
        // so echoing them here would leak into CI logs — skip it.
        echo_unseal_keys_cleartext(keys, messages);
    }
    Ok(())
}

/// Displays the unseal keys in cleartext, one line per key, so the
/// operator can copy them for manual safekeeping.
///
/// Shared by the declined branch and the unanswerable-prompt branch of
/// `maybe_save_unseal_keys` so both emit exactly the same thing.
fn echo_unseal_keys_cleartext(keys: &[String], messages: &Messages) {
    eprintln!("{}", messages.openbao_unseal_keys_not_saved_warning());
    for line in unseal_key_echo_lines(keys, messages) {
        println!("{line}");
    }
}

/// Formats one cleartext line per unseal key, in key order.
fn unseal_key_echo_lines(keys: &[String], messages: &Messages) -> Vec<String> {
    keys.iter()
        .enumerate()
        .map(|(idx, key)| messages.summary_unseal_key(idx + 1, key))
        .collect()
}

/// Rotates the temporary `POSTGRES_PASSWORD` from `.env` and returns
/// the new DSN on success, or `None` if rotation was skipped.
#[allow(clippy::too_many_lines)]
async fn maybe_rotate_env_db_password(
    compose_file: &Path,
    kv_mount: &str,
    client: &OpenBaoClient,
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<Option<String>> {
    use crate::commands::dotenv::{read_dotenv, update_dotenv_key_async};
    use crate::commands::init::{PATH_STEPCA_DB, PATH_STEPCA_DB_ADMIN};

    // Docker Compose reads .env from the compose file's directory.
    let compose_dir = crate::commands::compose_file::compose_file_dir(compose_file);
    let env_path = compose_dir.join(".env");
    if !env_path.exists() {
        return Ok(None);
    }

    let Ok(env_map) = read_dotenv(&env_path, messages) else {
        return Ok(None);
    };

    let Some(env_file_password) = env_map.get("POSTGRES_PASSWORD") else {
        return Ok(None);
    };

    // If the password looks like it was already rotated, skip.
    if env_file_password.starts_with("rotated-") {
        return Ok(None);
    }

    // Docker Compose prefers process environment over .env when both
    // are present.  Use the same source so the admin DSN connects
    // with the password PostgreSQL was actually started with.
    let temp_password = std::env::var("POSTGRES_PASSWORD")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env_file_password.clone());

    // Read the current DB DSN from ca.json (if it exists).
    let ca_json_path = secrets_dir.join("config").join("ca.json");
    if !ca_json_path.exists() {
        return Ok(None);
    }
    let Ok(ca_json_contents) = tokio::fs::read_to_string(&ca_json_path).await else {
        return Ok(None);
    };
    let Ok(value) = serde_json::from_str::<serde_json::Value>(&ca_json_contents) else {
        return Ok(None);
    };
    let current_dsn = match value
        .get("db")
        .and_then(|db| db.get("dataSource"))
        .and_then(|ds| ds.as_str())
    {
        Some(dsn) => dsn.to_string(),
        None => return Ok(None),
    };

    // Parse current DSN, generate new password, rotate.
    let Ok(parsed) = bootroot::db::parse_db_dsn(&current_dsn) else {
        return Ok(None);
    };

    let new_password = bootroot::utils::generate_secret(crate::commands::init::SECRET_BYTES)
        .with_context(|| messages.error_generate_secret_failed())?;

    // Resolve the host-published Postgres port from the compose dir's
    // env/.env (same precedence Docker Compose itself uses for the
    // `${POSTGRES_HOST_PORT:-5433}` mapping). Do NOT reuse `parsed.port`
    // from `ca.json`: that DSN was rewritten through `for_compose_runtime`
    // and therefore always carries the *compose-internal* 5432, which is
    // not reachable from the host. After the §4c default move from 5432
    // to 5433, hard-coding `parsed.port` makes this admin connection
    // attempt the wrong host port on a default install and silently skip
    // the `.env` password rotation via the warning path below.
    let host_port = bootroot::db::resolve_postgres_host_port(&compose_dir);
    let admin_dsn = bootroot::db::build_db_dsn(
        "step",
        &temp_password,
        "localhost",
        host_port,
        "postgres",
        Some("disable"),
    );

    let user_clone = parsed.user.clone();
    let password_clone = new_password.clone();
    let database_clone = parsed.database.clone();
    let admin_dsn_clone = admin_dsn.clone();
    let timeout = std::time::Duration::from_secs(5);

    let provision_result = tokio::task::spawn_blocking(move || {
        bootroot::db::provision_db_sync(
            &admin_dsn_clone,
            &user_clone,
            &password_clone,
            &database_clone,
            timeout,
        )
    })
    .await;

    if provision_result.is_err() || matches!(&provision_result, Ok(Err(_))) {
        eprintln!("{}", messages.warning_db_password_rotation_skipped());
        return Ok(None);
    }

    // Rebuild with the new password then route through `for_compose_runtime`
    // so this write site shares the single translation layer with `init`'s
    // initial DSN build and `rotate db`'s rebuilt DSN. Routing through the
    // helper also self-heals a previously-corrupted stored DSN regardless of
    // whether the prior write was correct.
    let rebuilt_dsn = bootroot::db::build_db_dsn(
        &parsed.user,
        &new_password,
        &parsed.host,
        parsed.port,
        &parsed.database,
        parsed.sslmode.as_deref(),
    );
    let new_dsn = bootroot::db::for_compose_runtime(&rebuilt_dsn)
        .with_context(|| messages.error_invalid_db_dsn())?;

    // Write new DSN to OpenBao KV.
    client
        .write_kv(
            kv_mount,
            PATH_STEPCA_DB,
            serde_json::json!({ "value": new_dsn }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;

    // Same-role topology (admin DSN's user equals the runtime user that
    // was just ALTERed): the persisted KV admin DSN at
    // `bootroot/stepca/db_admin` now carries the pre-ALTER password and
    // would fail authentication on the next `rotate db` (the automatic
    // §2 path). Mirror the rewrite that `rotate db` performs at
    // `src/commands/rotate/db.rs:91`: read the persisted admin DSN, and
    // if its user matches the runtime user just rotated here, write back
    // the same DSN with the post-ALTER password (host/port preserved).
    if let Some(rebuilt_admin_dsn) =
        rebuilt_admin_dsn_for_kv(client, kv_mount, &parsed.user, &new_password).await?
    {
        let _ = client
            .write_kv(
                kv_mount,
                PATH_STEPCA_DB_ADMIN,
                serde_json::json!({ "value": rebuilt_admin_dsn }),
            )
            .await;
    }

    // Patch ca.json directly so step-ca uses the new password on next
    // restart.  The OpenBao Agent template will eventually overwrite
    // this, but patching now avoids a window where step-ca would boot
    // with the old (now-invalid) password.
    //
    // Published by rename at the mode the file already carries, so a
    // step-ca boot or an agent render landing here reads the previous
    // document or the whole new one rather than half of either. The
    // directory is not flushed: this patch exists only to bridge until
    // the sidecar re-renders `ca.json` from its template, which is what
    // recovers it if a crash loses the entry.
    //
    // The result stays discarded, as it was: the KV write above is what
    // makes the new DSN authoritative, so a failure to pre-patch the
    // rendered file is a missed optimisation, not a failed rotation.
    if let Ok(mut doc) = serde_json::from_str::<serde_json::Value>(&ca_json_contents) {
        doc["db"]["dataSource"] = serde_json::Value::String(new_dsn.clone());
        if let Ok(updated) = serde_json::to_string_pretty(&doc) {
            let mode = fs_util::preserved_mode(&ca_json_path, CA_JSON_FILE_MODE);
            let _ = fs_util::atomic_replace(&ca_json_path, updated.as_bytes(), mode).await;
        }
    }

    // Overwrite .env with a dummy password so docker compose doesn't error.
    // Through the async entry point: this is the one async caller of the
    // `.env` writer, and that writer now flushes.
    update_dotenv_key_async(
        &env_path,
        "POSTGRES_PASSWORD",
        "rotated-use-openbao",
        messages,
    )
    .await?;

    // Restart step-ca to pick up the new DSN from the patched ca.json.
    let identity = ComposeIdentity::resolve(compose_file, None, messages)?;
    let compose_str = compose_file.to_string_lossy();
    let restart = identity.compose(&[&compose_str], None, &["restart", "step-ca"]);
    let _ = run_compose(&restart, "docker compose restart step-ca", messages);

    Ok(Some(new_dsn))
}

/// Reads `bootroot/stepca/db_admin` and, when its user matches the
/// runtime user just rotated, returns the same DSN rebuilt with
/// `new_password` (host/port preserved). Returns `None` when the path
/// is absent, unreadable, malformed, or when the persisted admin user
/// is distinct from the runtime user (no rewrite needed).
///
/// Errors from KV reads are swallowed because this is a best-effort
/// post-rotation sync: the primary work (rotating the runtime DSN) has
/// already succeeded, and a stale admin DSN at most forces the operator
/// to pass `--db-admin-dsn` once on the next `rotate db`.
async fn rebuilt_admin_dsn_for_kv(
    client: &OpenBaoClient,
    kv_mount: &str,
    runtime_user: &str,
    new_password: &str,
) -> Result<Option<String>> {
    use crate::commands::init::PATH_STEPCA_DB_ADMIN;

    let exists = client
        .kv_exists(kv_mount, PATH_STEPCA_DB_ADMIN)
        .await
        .unwrap_or(false);
    if !exists {
        return Ok(None);
    }
    let Ok(value) = client.read_kv(kv_mount, PATH_STEPCA_DB_ADMIN).await else {
        return Ok(None);
    };
    let Some(current) = value.get("value").and_then(|v| v.as_str()) else {
        return Ok(None);
    };
    let Ok(parsed) = bootroot::db::parse_db_dsn(current) else {
        return Ok(None);
    };
    if parsed.user != runtime_user {
        return Ok(None);
    }
    Ok(Some(bootroot::db::effective_admin_dsn_for_kv(
        current,
        runtime_user,
        new_password,
    )?))
}

/// Normalises file and directory modes under the secrets directory to
/// the expected 0700 (directories) / 0600 (key material) values.
///
/// This adjusts modes only; it does not change ownership. Every `step`
/// helper container already runs as the secrets-directory owner, so the
/// material it creates is host-owned and needs only its modes tightened.
async fn fix_secrets_permissions(secrets_dir: &Path) -> Result<()> {
    fix_permissions_recursive(secrets_dir).await
}

async fn fix_permissions_recursive(dir: &Path) -> Result<()> {
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.is_dir() {
            fs_util::ensure_secrets_dir(&path).await?;
            Box::pin(fix_permissions_recursive(&path)).await?;
        } else if path.is_file() {
            fs_util::set_key_permissions(&path).await?;
        }
    }
    Ok(())
}

/// Async because the state write is: publishing `state.json` costs
/// three disk round trips, which `StateFile::save_async` keeps off the
/// runtime thread `run_init_inner` runs on.
pub(super) async fn write_state_file(
    openbao_url: &str,
    kv_mount: &str,
    approles: BTreeMap<String, String>,
    secrets_dir: &Path,
    rotate_bound_cidrs: &[String],
    rotate_secret_id_ttl: &str,
    messages: &Messages,
) -> Result<()> {
    write_state_file_to(
        &StateFile::default_path(),
        openbao_url,
        kv_mount,
        approles,
        secrets_dir,
        rotate_bound_cidrs,
        rotate_secret_id_ttl,
        messages,
    )
    .await
}

/// Inner implementation that accepts an explicit state-file path for
/// testability.
#[allow(clippy::too_many_arguments)] // init-time state snapshot: every value is a distinct flag
async fn write_state_file_to(
    state_path: &Path,
    openbao_url: &str,
    kv_mount: &str,
    approles: BTreeMap<String, String>,
    secrets_dir: &Path,
    rotate_bound_cidrs: &[String],
    rotate_secret_id_ttl: &str,
    messages: &Messages,
) -> Result<()> {
    let (
        existing_services,
        existing_openbao_bind_addr,
        existing_openbao_advertise_addr,
        existing_http01_admin_bind_addr,
        existing_http01_admin_advertise_addr,
        existing_stepca_bind_addr,
        existing_stepca_advertise_addr,
        existing_infra_certs,
        existing_last_secret_id_rotation,
    ) = if state_path.exists() {
        let state = StateFile::load(state_path)?;
        (
            state.services,
            state.openbao_bind_addr,
            state.openbao_advertise_addr,
            state.http01_admin_bind_addr,
            state.http01_admin_advertise_addr,
            state.stepca_bind_addr,
            state.stepca_advertise_addr,
            state.infra_certs,
            state.last_secret_id_rotation,
        )
    } else {
        (
            BTreeMap::new(),
            None,
            None,
            None,
            None,
            None,
            None,
            BTreeMap::new(),
            None,
        )
    };

    // The CIDR binding is authoritative per init run (opt-in): the flag
    // binds both rotate credentials, its absence records no binding —
    // matching the credentials this run actually minted.
    let mut rotate_bound_cidrs_map = BTreeMap::new();
    if !rotate_bound_cidrs.is_empty() {
        for label in [AppRoleLabel::RuntimeRotate, AppRoleLabel::InfraRotate] {
            rotate_bound_cidrs_map.insert(label.to_string(), rotate_bound_cidrs.to_vec());
        }
    }

    let policy_map = AppRoleLabel::policy_map();
    let state = StateFile {
        openbao_url: openbao_url.to_string(),
        kv_mount: kv_mount.to_string(),
        secrets_dir: Some(secrets_dir.to_path_buf()),
        policies: policy_map,
        approles,
        services: existing_services,
        openbao_bind_addr: existing_openbao_bind_addr,
        openbao_advertise_addr: existing_openbao_advertise_addr,
        http01_admin_bind_addr: existing_http01_admin_bind_addr,
        http01_admin_advertise_addr: existing_http01_admin_advertise_addr,
        stepca_bind_addr: existing_stepca_bind_addr,
        stepca_advertise_addr: existing_stepca_advertise_addr,
        infra_certs: existing_infra_certs,
        rotate_bound_cidrs: rotate_bound_cidrs_map,
        rotate_secret_id_ttl: Some(rotate_secret_id_ttl.to_string()),
        last_secret_id_rotation: existing_last_secret_id_rotation,
    };
    state
        .save_async(state_path)
        .await
        .with_context(|| messages.error_serialize_state_failed())?;
    Ok(())
}

/// Validates the HTTP-01 exposed compose override before applying it.
///
/// Mirrors the `OpenBao` override validation in the same init flow:
/// fails early if the override file is missing or its binding does not
/// match the state-recorded intent.
fn validate_http01_exposed_override_for_init(
    compose_dir: &Path,
    state_path: &Path,
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<std::path::PathBuf> {
    let override_path = compose_dir
        .join("secrets")
        .join("responder")
        .join(HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME);
    if !override_path.exists() {
        anyhow::bail!(messages.error_http01_admin_override_file_missing());
    }
    let state = StateFile::load(state_path)?;
    let bind_addr = state
        .http01_admin_bind_addr
        .as_deref()
        .expect("caller verified responder_tls_enabled");
    validate_http01_override_scope(&override_path, messages)?;
    validate_http01_override_binding(&override_path, bind_addr, messages)?;
    validate_http01_admin_tls(secrets_dir, messages)?;
    Ok(override_path)
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{default_init_args, test_messages};
    use super::*;

    /// Every pre-flight condition an `InitPlan` can carry, so
    /// `plan_with(ALL_ARTIFACTS)` reads as "all three files exist".
    const ALL_ARTIFACTS: &[PreflightPrompt] = &[
        PreflightPrompt::OverwritePassword,
        PreflightPrompt::OverwriteCaJson,
        PreflightPrompt::OverwriteState,
    ];

    /// Builds a plan whose overwrite conditions hold for exactly the
    /// artifacts in `existing`, naming each condition rather than
    /// relying on the reader to track positional booleans.
    fn plan_with(existing: &[PreflightPrompt]) -> InitPlan {
        InitPlan {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: std::path::PathBuf::from("secrets"),
            overwrite_password: existing.contains(&PreflightPrompt::OverwritePassword),
            overwrite_ca_json: existing.contains(&PreflightPrompt::OverwriteCaJson),
            overwrite_state: existing.contains(&PreflightPrompt::OverwriteState),
        }
    }

    /// Nothing on disk and no `db-provision`: the pre-flight block asks
    /// nothing, whatever the new flags say.
    #[test]
    fn preflight_prompts_asks_nothing_when_no_condition_holds() {
        let args = default_init_args();
        assert!(preflight_prompts(&args, &plan_with(&[])).is_empty());

        // Closes #735: a flag whose condition does not hold is a silent
        // no-op, not an error and not a behaviour change.
        let mut args = default_init_args();
        args.overwrite_password = true;
        args.overwrite_ca_json = true;
        args.overwrite_state = true;
        args.confirm_db_provision = true;
        assert!(preflight_prompts(&args, &plan_with(&[])).is_empty());
    }

    /// Every condition holds and no flag answers it: all four prompts
    /// fire, in the order init has always asked them.
    #[test]
    fn preflight_prompts_asks_all_four_without_flags() {
        let mut args = default_init_args();
        args.enable.push(InitFeature::DbProvision);
        assert_eq!(
            preflight_prompts(&args, &plan_with(ALL_ARTIFACTS)),
            vec![
                PreflightPrompt::OverwritePassword,
                PreflightPrompt::OverwriteCaJson,
                PreflightPrompt::OverwriteState,
                PreflightPrompt::DbProvision,
            ]
        );
    }

    /// Closes #735: each flag suppresses exactly its own prompt, so a
    /// caller that sets one still gets asked about the other three.
    #[test]
    fn preflight_prompts_flags_suppress_only_their_own_prompt() {
        let plan = plan_with(ALL_ARTIFACTS);
        let all = [
            PreflightPrompt::OverwritePassword,
            PreflightPrompt::OverwriteCaJson,
            PreflightPrompt::OverwriteState,
            PreflightPrompt::DbProvision,
        ];

        for suppressed in all {
            let mut args = default_init_args();
            args.enable.push(InitFeature::DbProvision);
            match suppressed {
                PreflightPrompt::OverwritePassword => args.overwrite_password = true,
                PreflightPrompt::OverwriteCaJson => args.overwrite_ca_json = true,
                PreflightPrompt::OverwriteState => args.overwrite_state = true,
                PreflightPrompt::DbProvision => args.confirm_db_provision = true,
            }
            let expected: Vec<_> = all.iter().copied().filter(|&p| p != suppressed).collect();
            assert_eq!(
                preflight_prompts(&args, &plan),
                expected,
                "{suppressed:?} must suppress only its own prompt"
            );
        }
    }

    /// Closes #735: the whole pre-flight block clears with every
    /// condition holding once all four flags are set, which is what lets
    /// an automated install run `init` with stdin closed.
    #[test]
    fn preflight_prompts_all_flags_clear_every_prompt() {
        let mut args = default_init_args();
        args.enable.push(InitFeature::DbProvision);
        args.overwrite_password = true;
        args.overwrite_ca_json = true;
        args.overwrite_state = true;
        args.confirm_db_provision = true;
        assert!(
            preflight_prompts(&args, &plan_with(ALL_ARTIFACTS)).is_empty(),
            "all four flags together must leave no prompt to read from stdin"
        );
    }

    /// Closes #735: the three overwrite flags alone do not answer the
    /// db-provision confirmation, and `--confirm-db-provision` alone does
    /// not answer any overwrite prompt.
    #[test]
    fn preflight_prompts_overwrite_and_db_provision_flags_stay_disjoint() {
        let plan = plan_with(ALL_ARTIFACTS);

        let mut args = default_init_args();
        args.enable.push(InitFeature::DbProvision);
        args.overwrite_password = true;
        args.overwrite_ca_json = true;
        args.overwrite_state = true;
        assert_eq!(
            preflight_prompts(&args, &plan),
            vec![PreflightPrompt::DbProvision],
            "the overwrite flags must not answer the db-provision confirmation"
        );

        let mut args = default_init_args();
        args.enable.push(InitFeature::DbProvision);
        args.confirm_db_provision = true;
        assert_eq!(
            preflight_prompts(&args, &plan),
            vec![
                PreflightPrompt::OverwritePassword,
                PreflightPrompt::OverwriteCaJson,
                PreflightPrompt::OverwriteState,
            ],
            "--confirm-db-provision must not answer any overwrite prompt"
        );
    }

    /// The db-provision confirmation is gated on the feature, not on any
    /// file: `--confirm-db-provision` alone never enables it.
    #[test]
    fn preflight_prompts_db_provision_follows_the_feature() {
        let plan = plan_with(&[]);

        let args = default_init_args();
        assert!(preflight_prompts(&args, &plan).is_empty());

        let mut args = default_init_args();
        args.enable.push(InitFeature::DbProvision);
        assert_eq!(
            preflight_prompts(&args, &plan),
            vec![PreflightPrompt::DbProvision]
        );

        args.confirm_db_provision = true;
        assert!(preflight_prompts(&args, &plan).is_empty());
    }

    /// `--reinit-mode` suppresses all four prompts on its own, so
    /// `reinit --yes` stays non-interactive without the new flags.
    #[test]
    fn preflight_prompts_reinit_mode_suppresses_everything() {
        let mut args = default_init_args();
        args.enable.push(InitFeature::DbProvision);
        args.reinit_mode = true;
        assert!(preflight_prompts(&args, &plan_with(ALL_ARTIFACTS)).is_empty());
    }

    /// Each prompt renders its own message, so the loop in
    /// `run_init_inner` cannot ask about the wrong file.
    #[test]
    fn preflight_prompt_messages_are_distinct() {
        let messages = test_messages();
        let rendered = [
            PreflightPrompt::OverwritePassword.message(&messages),
            PreflightPrompt::OverwriteCaJson.message(&messages),
            PreflightPrompt::OverwriteState.message(&messages),
            PreflightPrompt::DbProvision.message(&messages),
        ];
        assert_eq!(
            rendered
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            rendered.len(),
            "each pre-flight prompt must render its own message"
        );
    }

    /// Closes #588 §5a: when `OpenBao` is already initialised but no
    /// usable root token is supplied, `init` must abort with the
    /// three-recovery-paths diagnostic instead of bubbling up the
    /// opaque `403 permission denied` from the first authenticated
    /// call.
    #[tokio::test]
    async fn diagnose_partial_init_bails_when_initialized_without_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/init"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"initialized":true}"#))
            .mount(&server)
            .await;

        let client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        let mut args = default_init_args();
        args.openbao.openbao_url = server.uri();
        args.root_token.root_token = None;
        let messages = test_messages();
        let err = diagnose_partial_init(&client, &args, &messages)
            .await
            .expect_err("must bail");
        let msg = err.to_string();
        assert!(msg.contains(&server.uri()), "diagnostic must name the URL");
        assert!(
            msg.contains("--root-token") && msg.contains("--openbao-only"),
            "diagnostic must name the recovery options, got: {msg}"
        );
    }

    /// Closes #731: `init` builds its first `OpenBaoClient` before any
    /// `state.json` value is consulted, so the CLI default has to pick
    /// up a non-default `OPENBAO_HOST_PORT` from the compose
    /// directory's `.env`.  Without this a second bootroot instance on
    /// the same host would initialise against the first one's `OpenBao`.
    #[test]
    fn init_args_follow_the_configured_openbao_host_port() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18200\n").expect("write .env");
        let mut args = default_init_args();
        args.compose.compose_file = dir.path().join("docker-compose.yml");
        let resolved = args_with_effective_openbao_url_with_env(&args, None);
        assert_eq!(resolved.openbao.openbao_url, "http://localhost:18200");
        let from_env = args_with_effective_openbao_url_with_env(&args, Some("18201"));
        assert_eq!(
            from_env.openbao.openbao_url, "http://localhost:18201",
            "the process environment outranks the compose `.env`"
        );
    }

    /// Closes #731: an operator-supplied `--openbao-url` is used
    /// verbatim, and the unchanged case borrows instead of cloning.
    #[test]
    fn init_args_keep_an_explicit_openbao_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18200\n").expect("write .env");
        let mut args = default_init_args();
        args.compose.compose_file = dir.path().join("docker-compose.yml");
        args.openbao.openbao_url = "https://openbao.internal:8200".to_string();
        let resolved = args_with_effective_openbao_url_with_env(&args, None);
        assert_eq!(
            resolved.openbao.openbao_url,
            "https://openbao.internal:8200"
        );
        assert!(
            matches!(resolved, Cow::Borrowed(_)),
            "an unchanged URL must not clone the args"
        );
    }

    /// Token supplied → preflight returns Ok and bootstrap proceeds.
    #[tokio::test]
    async fn diagnose_partial_init_passes_when_token_supplied() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/init"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"initialized":true}"#))
            .mount(&server)
            .await;

        let client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        let mut args = default_init_args();
        args.openbao.openbao_url = server.uri();
        args.root_token.root_token = Some("hvs.fake".to_string());
        diagnose_partial_init(&client, &args, &test_messages())
            .await
            .expect("token supplied path must succeed");
    }

    /// Uninitialised `OpenBao` → preflight returns Ok regardless of
    /// token state (this is a fresh install, the normal path).
    #[tokio::test]
    async fn diagnose_partial_init_passes_when_not_initialized() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/sys/init"))
            .respond_with(ResponseTemplate::new(200).set_body_string(r#"{"initialized":false}"#))
            .mount(&server)
            .await;

        let client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        let mut args = default_init_args();
        args.openbao.openbao_url = server.uri();
        args.root_token.root_token = None;
        diagnose_partial_init(&client, &args, &test_messages())
            .await
            .expect("uninitialized path must succeed");
    }

    /// Regression: `bootroot reinit --yes` must persist new unseal keys
    /// automatically without prompting.  `maybe_save_unseal_keys` is the
    /// only path that writes `secrets/openbao/unseal-keys.txt` during
    /// init; if the `auto_save` arg does not bypass the prompt the
    /// recovery flow will stall on `stdin` and the keys will be lost.
    #[tokio::test]
    async fn maybe_save_unseal_keys_auto_save_writes_without_prompting() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let keys = vec!["key-1".to_string(), "key-2".to_string()];
        let messages = test_messages();
        maybe_save_unseal_keys(&secrets, &keys, SaveUnsealKeysDecision::Save, &messages)
            .await
            .expect("auto-save must not prompt");
        let path = secrets.join("openbao").join("unseal-keys.txt");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("key-1") && body.contains("key-2"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "unseal keys file must be 0600, got {mode:o}");
    }

    /// `SaveUnsealKeysDecision::Save` (driven by `--save-unseal-keys`)
    /// writes the on-disk unseal-keys file with mode `0600` and skips
    /// the prompt, matching the reinit-mode write path.
    #[tokio::test]
    async fn maybe_save_unseal_keys_save_decision_writes_without_prompting() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let keys = vec!["key-a".to_string(), "key-b".to_string()];
        let messages = test_messages();
        maybe_save_unseal_keys(&secrets, &keys, SaveUnsealKeysDecision::Save, &messages)
            .await
            .expect("--save-unseal-keys decision must not prompt");
        let path = secrets.join("openbao").join("unseal-keys.txt");
        let body = std::fs::read_to_string(&path).unwrap();
        assert!(body.contains("key-a") && body.contains("key-b"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "unseal keys file must be 0600, got {mode:o}");
    }

    /// `SaveUnsealKeysDecision::DoNotSave` (driven by
    /// `--no-save-unseal-keys`) must skip the prompt AND skip the
    /// on-disk write.  Operators that pass `--no-save-unseal-keys` rely
    /// on `--summary-json` to capture the keys; the canonical
    /// `<secrets_dir>/openbao/unseal-keys.txt` must not appear.
    #[tokio::test]
    async fn maybe_save_unseal_keys_do_not_save_skips_write() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        let keys = vec!["key-x".to_string(), "key-y".to_string()];
        let messages = test_messages();
        maybe_save_unseal_keys(
            &secrets,
            &keys,
            SaveUnsealKeysDecision::DoNotSave,
            &messages,
        )
        .await
        .expect("--no-save-unseal-keys decision must not prompt");
        let path = secrets.join("openbao").join("unseal-keys.txt");
        assert!(
            !path.exists(),
            "--no-save-unseal-keys must not write {}",
            path.display()
        );
    }

    /// The cleartext echo is one shared path, so the declined branch and
    /// the branch that fails on an unanswerable prompt hand the operator
    /// the same thing: one line per key, in key order.
    #[test]
    fn unseal_key_echo_lines_emits_one_line_per_key() {
        let messages = test_messages();
        let keys = vec!["key-1".to_string(), "key-2".to_string()];
        let lines = unseal_key_echo_lines(&keys, &messages);
        assert_eq!(lines.len(), keys.len());
        for (idx, key) in keys.iter().enumerate() {
            let line = lines.get(idx).expect("one line per key");
            assert!(line.contains(key), "line {idx} must carry its key: {line}");
            assert!(
                line.contains(&(idx + 1).to_string()),
                "line {idx} must be numbered from 1: {line}"
            );
        }
        assert!(unseal_key_echo_lines(&[], &messages).is_empty());
    }

    /// `write_root_token_file` persists the token with mode `0600`.
    /// Reinit's `--root-token-output` reaches the operator via this
    /// helper; tightening the permission contract here guards against
    /// regressions that would leak a freshly minted root token to other
    /// users on the host.
    #[tokio::test]
    async fn write_root_token_file_persists_with_restricted_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("root.token");
        write_root_token_file(&path, "hvs.fake-token")
            .await
            .expect("write");
        let body = std::fs::read_to_string(&path).unwrap();
        assert_eq!(body, "hvs.fake-token");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "root token file must be 0600, got {mode:o}");
    }

    /// Regression for Round 5 reviewer item: `write_root_token_file`
    /// must open the destination with `OpenOptionsExt::mode(0o600)` so
    /// a freshly minted root token never exists on disk with permissions
    /// derived from the process umask (commonly `0644`) between create
    /// and chmod.  Set a permissive umask, write the file, and assert
    /// it lands with `0600` — under the previous `tokio::fs::write` +
    /// post-write chmod path this would (briefly) be `0644`.
    #[tokio::test]
    async fn write_root_token_file_creates_with_0600_under_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;

        // SAFETY: `umask` is a libc thread-local syscall.  We restore
        // it before the test returns so concurrent tests are unaffected.
        let prev = unsafe { libc::umask(0) };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let res = write_root_token_file(&path, "hvs.fake-token").await;
        unsafe { libc::umask(prev) };
        res.expect("write");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "root token file must be created atomically with 0600 under any umask, got {mode:o}"
        );
    }

    /// Closes #603 Reviewer Round 1: `run_init` must validate
    /// `--summary-json` *before* any `OpenBao` work begins.  Without this,
    /// a bad summary destination would fail inside
    /// `write_init_summary_json` after `run_init_inner` succeeds, leaving
    /// the freshly issued root token + unseal keys captured nowhere —
    /// the exact partial-init trap `--no-save-unseal-keys` is designed
    /// to avoid via the summary-json recovery channel.  The validator is
    /// the same one reinit uses; this test asserts it fires from the
    /// init surface too.
    #[tokio::test]
    async fn run_init_rejects_bad_summary_json_before_any_work() {
        let dir = tempfile::tempdir().unwrap();
        // A directory standing in for the summary-json path: any write
        // attempt would fail, but the preflight catches it first.
        let bad_path = dir.path().join("not-a-file");
        std::fs::create_dir_all(&bad_path).unwrap();

        let mut args = default_init_args();
        args.summary_json = Some(bad_path.clone());
        // Point compose_file at a non-existent path so that if the
        // preflight did NOT fire first, the test would fail with a
        // different (compose-file) error.  The summary-json validator
        // runs earlier and emits its own diagnostic.
        args.compose.compose_file = dir.path().join("does-not-exist.yml");

        let err = run_init(&args, &test_messages())
            .await
            .expect_err("bad --summary-json must be rejected at preflight");
        let msg = err.to_string();
        assert!(
            msg.contains(&bad_path.display().to_string()) || msg.to_lowercase().contains("summary"),
            "preflight error must reference the summary-json path or label, got: {msg}",
        );
    }

    /// Same guarantee for `--root-token-output`: the preflight must fire
    /// before any `OpenBao` work so a bad token-output destination cannot
    /// fail post-init with the freshly issued root token already minted.
    #[tokio::test]
    async fn run_init_rejects_bad_root_token_output_before_any_work() {
        let dir = tempfile::tempdir().unwrap();
        let bad_path = dir.path().join("not-a-file");
        std::fs::create_dir_all(&bad_path).unwrap();

        let mut args = default_init_args();
        args.root_token_output = Some(bad_path.clone());
        args.compose.compose_file = dir.path().join("does-not-exist.yml");

        let err = run_init(&args, &test_messages())
            .await
            .expect_err("bad --root-token-output must be rejected at preflight");
        let msg = err.to_string();
        assert!(
            msg.contains(&bad_path.display().to_string())
                || msg.to_lowercase().contains("root token")
                || msg.to_lowercase().contains("root-token"),
            "preflight error must reference the root-token-output path or label, got: {msg}",
        );
    }

    /// Regression: `write_state_file_to` must propagate an error when an
    /// existing state file is corrupted, not silently replace it with a
    /// fresh state (which would erase stored `openbao_bind_addr`).
    #[tokio::test]
    async fn write_state_file_errors_on_corrupted_state() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        std::fs::write(&state_path, "NOT VALID JSON").unwrap();
        let result = write_state_file_to(
            &state_path,
            "http://localhost:8200",
            "secret",
            BTreeMap::new(),
            Path::new("secrets"),
            &[],
            "24h",
            &messages,
        )
        .await;
        assert!(
            result.is_err(),
            "corrupted state file must be a hard error, not silently replaced"
        );
    }

    /// `write_state_file_to` preserves `openbao_bind_addr` from an
    /// existing, valid state file.
    #[tokio::test]
    async fn write_state_file_preserves_bind_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let existing = crate::state::StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
        };
        existing.save(&state_path).unwrap();
        write_state_file_to(
            &state_path,
            "http://localhost:8200",
            "secret",
            BTreeMap::new(),
            Path::new("secrets"),
            &[],
            "24h",
            &messages,
        )
        .await
        .unwrap();
        let reloaded = crate::state::StateFile::load(&state_path).unwrap();
        assert_eq!(
            reloaded.openbao_bind_addr.as_deref(),
            Some("192.168.1.10:8200"),
            "openbao_bind_addr must survive a state rewrite during init"
        );
    }

    /// `write_state_file_to` records the rotate-credential fields
    /// (#672): the operator-supplied CIDR binding for both rotate
    /// labels, the rotate roles' `secret_id` TTL (the dead-man
    /// threshold source), and preserves a previously recorded
    /// rotation-success timestamp across an init re-run.
    #[tokio::test]
    async fn write_state_file_records_rotate_fields_and_preserves_timestamp() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let existing = crate::state::StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            last_secret_id_rotation: Some("2026-07-01T00:00:00Z".to_string()),
            ..Default::default()
        };
        existing.save(&state_path).unwrap();
        write_state_file_to(
            &state_path,
            "http://localhost:8200",
            "secret",
            BTreeMap::new(),
            Path::new("secrets"),
            &["10.0.0.5/32".to_string()],
            "48h",
            &messages,
        )
        .await
        .unwrap();
        let reloaded = crate::state::StateFile::load(&state_path).unwrap();
        for label in ["runtime_rotate", "infra_rotate"] {
            assert_eq!(
                reloaded.rotate_bound_cidrs.get(label).map(Vec::as_slice),
                Some(["10.0.0.5/32".to_string()].as_slice()),
                "the CIDR binding must be recorded for {label}"
            );
        }
        assert_eq!(reloaded.rotate_secret_id_ttl.as_deref(), Some("48h"));
        assert_eq!(
            reloaded.last_secret_id_rotation.as_deref(),
            Some("2026-07-01T00:00:00Z"),
            "the dead-man timestamp must survive an init re-run"
        );

        // Opt-in semantics: an init run without the flag records no
        // binding (matching the unbound credentials it minted).
        write_state_file_to(
            &state_path,
            "http://localhost:8200",
            "secret",
            BTreeMap::new(),
            Path::new("secrets"),
            &[],
            "24h",
            &messages,
        )
        .await
        .unwrap();
        let reloaded = crate::state::StateFile::load(&state_path).unwrap();
        assert!(
            reloaded.rotate_bound_cidrs.is_empty(),
            "omitting --rotate-bound-cidrs must clear the recorded binding"
        );
    }

    /// `write_state_file_to` preserves `stepca_bind_addr` /
    /// `stepca_advertise_addr` from an existing, valid state file so
    /// that an `init` re-run does not erase the step-ca exposure intent.
    #[tokio::test]
    async fn write_state_file_preserves_stepca_bind_intent() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let state_path = dir.path().join("state.json");
        let existing = crate::state::StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            stepca_bind_addr: Some("0.0.0.0:9000".to_string()),
            stepca_advertise_addr: Some("192.168.1.10:9000".to_string()),
            infra_certs: BTreeMap::new(),
            ..Default::default()
        };
        existing.save(&state_path).unwrap();
        write_state_file_to(
            &state_path,
            "http://localhost:8200",
            "secret",
            BTreeMap::new(),
            Path::new("secrets"),
            &[],
            "24h",
            &messages,
        )
        .await
        .unwrap();
        let reloaded = crate::state::StateFile::load(&state_path).unwrap();
        assert_eq!(
            reloaded.stepca_bind_addr.as_deref(),
            Some("0.0.0.0:9000"),
            "stepca_bind_addr must survive a state rewrite during init"
        );
        assert_eq!(
            reloaded.stepca_advertise_addr.as_deref(),
            Some("192.168.1.10:9000"),
            "stepca_advertise_addr must survive a state rewrite during init"
        );
    }

    /// Regression: `validate_http01_exposed_override_for_init` must reject
    /// a missing override file instead of letting docker compose fail with
    /// an opaque error.
    #[test]
    fn validate_http01_override_rejects_missing_file() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let compose_dir = dir.path();
        let state_path = compose_dir.join("state.json");
        let state = crate::state::StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
        };
        state.save(&state_path).unwrap();
        let result = validate_http01_exposed_override_for_init(
            compose_dir,
            &state_path,
            &compose_dir.join("secrets"),
            &messages,
        );
        assert!(
            result.is_err(),
            "missing override file must be a hard error"
        );
    }

    /// Regression: `validate_http01_exposed_override_for_init` must reject
    /// an override whose port binding does not match the state-recorded
    /// bind intent.
    #[test]
    fn validate_http01_override_rejects_mismatched_binding() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let compose_dir = dir.path();
        // Write override for one address.
        crate::commands::guardrails::write_http01_exposed_override(
            compose_dir,
            "192.168.1.10:8080",
            &messages,
        )
        .unwrap();
        // Record a different bind intent in state.
        let state_path = compose_dir.join("state.json");
        let state = crate::state::StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("10.0.0.5:8080".to_string()),
            http01_admin_advertise_addr: None,
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
        };
        state.save(&state_path).unwrap();
        let result = validate_http01_exposed_override_for_init(
            compose_dir,
            &state_path,
            &compose_dir.join("secrets"),
            &messages,
        );
        assert!(
            result.is_err(),
            "mismatched override binding must be a hard error"
        );
    }

    /// Regression: when the compose file does not contain the
    /// `bootroot-http01` service but state records a bind intent,
    /// `responder_tls_enabled` must be false so that init does not
    /// issue a cert or register an infra-cert entry for a
    /// nonexistent container.
    #[test]
    fn responder_tls_disabled_when_compose_lacks_responder() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        // Compose file without the responder service.
        let compose_path = dir.path().join("docker-compose.yml");
        std::fs::write(&compose_path, "services:\n  openbao:\n    image: openbao\n").unwrap();
        // State file with bind intent recorded.
        let state_path = dir.path().join("state.json");
        let state = crate::state::StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
        };
        state.save(&state_path).unwrap();
        let has_responder = compose_has_responder(&compose_path, &messages).unwrap();
        let bind_intent = has_http01_admin_bind_intent(&state_path).unwrap();
        let responder_tls_enabled = has_responder && bind_intent;
        assert!(
            !has_responder,
            "compose without bootroot-http01 must report no responder"
        );
        assert!(
            bind_intent,
            "state with http01_admin_bind_addr must report bind intent"
        );
        assert!(
            !responder_tls_enabled,
            "responder TLS must be disabled when compose lacks the responder service"
        );
    }

    /// Closes #588 Round 5 (b): when `init`'s post-bootstrap password
    /// rotation runs against the same-role topology (admin user equals
    /// the runtime user just rotated), the persisted KV admin DSN at
    /// `bootroot/stepca/db_admin` must be rewritten with the new
    /// password — otherwise the next `rotate db` (no `--db-admin-dsn`)
    /// reads stale credentials and fails authentication, defeating the
    /// automatic §2 path.
    #[tokio::test]
    async fn rebuilt_admin_dsn_for_kv_rebuilds_for_same_role() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Nonce-based test fixtures sidestep CodeQL's
        // `rust/hard-coded-cryptographic-value` and `cleartext-logging`
        // rules (the values are generated per run and have no relation
        // to a real credential).
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let old = format!("old-{nonce}");
        let new = format!("new-{nonce}");
        let token = format!("hvs.fake-{nonce}");
        let persisted_dsn =
            format!("postgresql://step:{old}@postgres:5432/postgres?sslmode=disable");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/metadata/bootroot/stepca/db_admin"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
        let body = serde_json::json!({
            "data": {
                "data": { "value": persisted_dsn },
                "metadata": {"version": 1},
            },
        });
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/bootroot/stepca/db_admin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token(token);

        let rebuilt = rebuilt_admin_dsn_for_kv(&client, "secret", "step", &new)
            .await
            .expect("rebuilt_admin_dsn_for_kv must succeed for same-role topology")
            .expect("must return Some when persisted user matches runtime user");
        assert_eq!(
            rebuilt,
            format!("postgresql://step:{new}@postgres:5432/postgres?sslmode=disable"),
            "host/port preserved (compose-internal form), only password swapped"
        );
    }

    /// Distinct-role topology (admin user `step`, runtime user `stepca`):
    /// `provision_db_sync` only `ALTER`ed the runtime user, so the persisted
    /// admin DSN is still valid and KV must NOT be rewritten.
    #[tokio::test]
    async fn rebuilt_admin_dsn_for_kv_returns_none_for_distinct_role() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // Nonce-based fixtures — see the sibling same-role test.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let admin_pw = format!("admin-{nonce}");
        let new = format!("new-{nonce}");
        let token = format!("hvs.fake-{nonce}");
        let persisted_dsn =
            format!("postgresql://step:{admin_pw}@postgres:5432/postgres?sslmode=disable");

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/metadata/bootroot/stepca/db_admin"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{}"))
            .mount(&server)
            .await;
        let body = serde_json::json!({
            "data": {
                "data": { "value": persisted_dsn },
                "metadata": {"version": 1},
            },
        });
        Mock::given(method("GET"))
            .and(path("/v1/secret/data/bootroot/stepca/db_admin"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token(token);

        let rebuilt = rebuilt_admin_dsn_for_kv(&client, "secret", "stepca", &new)
            .await
            .expect("rebuilt_admin_dsn_for_kv must succeed for distinct-role topology");
        // Avoid `{rebuilt:?}` in the panic message: CodeQL's
        // `rust/cleartext-logging` rule treats Debug-formatting an
        // `Option<DSN>` (whose inner String can contain a password) into
        // a panic stream as writing a credential to a log. Keep the
        // assertion presence-only.
        assert!(
            rebuilt.is_none(),
            "distinct-role topology must not rewrite KV"
        );
    }

    /// Absent KV path → return None (operator-supplied DSN install where
    /// `init` never persisted `bootroot/stepca/db_admin`).
    #[tokio::test]
    async fn rebuilt_admin_dsn_for_kv_returns_none_when_path_absent() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 404 on metadata → kv_exists returns Ok(false).
        Mock::given(method("GET"))
            .and(path("/v1/secret/metadata/bootroot/stepca/db_admin"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        // Nonce-based fixtures — see the sibling same-role test.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let new = format!("new-{nonce}");
        let token = format!("hvs.fake-{nonce}");

        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token(token);

        let rebuilt = rebuilt_admin_dsn_for_kv(&client, "secret", "step", &new)
            .await
            .expect("rebuilt_admin_dsn_for_kv must succeed when KV path is absent");
        assert!(rebuilt.is_none(), "absent KV path must yield None");
    }

    /// The token arrives by rename from a staged temporary, so the
    /// destination name never points at a partially written credential.
    /// A changed inode is what separates that from the truncate-in-place
    /// open this replaced.
    #[tokio::test]
    async fn write_root_token_file_publishes_a_new_inode_at_0600() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("root-token.txt");
        write_root_token_file(&path, "hvs.first")
            .await
            .expect("first token write");
        let first_inode = std::fs::metadata(&path).expect("stat").ino();

        write_root_token_file(&path, "hvs.second")
            .await
            .expect("second token write");

        assert_eq!(std::fs::read_to_string(&path).expect("read"), "hvs.second");
        assert_ne!(std::fs::metadata(&path).expect("stat").ino(), first_inode);
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, SECRET_OUTPUT_FILE_MODE);
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("root-token.txt")],
            "the staged temporary must not survive the publish"
        );
    }

    /// The destination is created when the parent exists but the file
    /// does not — the pre-write tightening must not trip over a missing
    /// path.
    #[tokio::test]
    async fn write_root_token_file_creates_a_missing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nested").join("root-token.txt");
        write_root_token_file(&path, "hvs.only")
            .await
            .expect("token write into a fresh directory");
        assert_eq!(std::fs::read_to_string(&path).expect("read"), "hvs.only");
    }

    /// A destination an earlier run left world-readable is replaced at
    /// `0600`, both halves of the write pulling their weight: the
    /// tightening narrows the old token sitting there, and the staged
    /// publish gives the new one a fresh inode that was never wider
    /// than `0600`. `init` reaches this writer with no preflight, so
    /// the wide destination is not a case only `reinit` can rule out.
    #[tokio::test]
    async fn write_root_token_file_replaces_a_world_readable_destination() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("root-token.txt");
        std::fs::write(&path, "hvs.stale").expect("seed the destination");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let stale_inode = std::fs::metadata(&path).expect("stat").ino();

        write_root_token_file(&path, "hvs.fresh")
            .await
            .expect("token write over a world-readable destination");

        assert_eq!(std::fs::read_to_string(&path).expect("read"), "hvs.fresh");
        let meta = std::fs::metadata(&path).expect("stat");
        assert_eq!(meta.permissions().mode() & 0o777, SECRET_OUTPUT_FILE_MODE);
        assert_ne!(meta.ino(), stale_inode, "the publish must be a rename");
    }

    /// A symlinked destination delivers the token to the link's target,
    /// which is what `validate_root_token_output_path` accepts a link to
    /// a regular file *for*. Renaming over the link would leave the
    /// operator without their link and the target holding the previous
    /// run's token — a silent loss, since the write reports success.
    #[tokio::test]
    async fn write_root_token_file_writes_through_a_symlinked_destination() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&real_dir).expect("mkdir");
        let target = real_dir.join("token.txt");
        std::fs::write(&target, "hvs.stale").expect("seed the target");
        let link = dir.path().join("root-token.txt");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        write_root_token_file(&link, "hvs.fresh")
            .await
            .expect("token write through a symlink");

        assert!(
            std::fs::symlink_metadata(&link)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the operator's link must survive the write"
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("read"),
            "hvs.fresh",
            "the token must reach the link's target"
        );
        let mode = std::fs::metadata(&target)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, SECRET_OUTPUT_FILE_MODE);
    }

    /// A link whose target does not exist yet is still where the
    /// operator wants the token: the truncating write this replaced
    /// created the target through the link, so the staged write creates
    /// it too. Publishing at the link's own name instead would destroy
    /// the link and leave a root token in a directory nobody chose.
    #[tokio::test]
    async fn write_root_token_file_creates_a_dangling_symlink_target() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("secure").join("token.txt");
        std::fs::create_dir(dir.path().join("secure")).expect("mkdir");
        let link = dir.path().join("root-token.txt");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        write_root_token_file(&link, "hvs.dangling")
            .await
            .expect("token write over a dangling link");

        assert!(
            std::fs::symlink_metadata(&link)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the operator's link must survive the write"
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("read"),
            "hvs.dangling"
        );
        let mode = std::fs::metadata(&target)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, SECRET_OUTPUT_FILE_MODE);
    }

    /// A destination whose links form a cycle has no target to deliver
    /// to, and every name in the loop is a link. The truncating write
    /// this replaced failed with `ELOOP`; the staged write fails too,
    /// rather than renaming the token over the operator's link and
    /// reporting success.
    #[tokio::test]
    async fn write_root_token_file_refuses_a_symlink_cycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = dir.path().join("root-token.txt");
        let b = dir.path().join("other.txt");
        std::os::unix::fs::symlink(&b, &a).expect("symlink");
        std::os::unix::fs::symlink(&a, &b).expect("symlink");

        let err = write_root_token_file(&a, "hvs.looped")
            .await
            .expect_err("a cyclic destination must not be published");
        assert!(
            format!("{err:#}").contains("Too many levels of symbolic links"),
            "unexpected error: {err:#}"
        );
        for link in [&a, &b] {
            assert!(
                std::fs::symlink_metadata(link)
                    .expect("stat")
                    .file_type()
                    .is_symlink(),
                "{} was replaced by the write",
                link.display()
            );
        }
    }

    /// The summary JSON carries the same credentials, and refuses the
    /// same destination for the same reason.
    #[tokio::test]
    async fn write_init_summary_json_refuses_a_symlink_cycle() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = dir.path().join("summary.json");
        let b = dir.path().join("other.json");
        std::os::unix::fs::symlink(&b, &a).expect("symlink");
        std::os::unix::fs::symlink(&a, &b).expect("symlink");

        let err = write_init_summary_json(&a, &summary_with_token("hvs.looped"))
            .await
            .expect_err("a cyclic destination must not be published");
        assert!(
            format!("{err:#}").contains("Too many levels of symbolic links"),
            "unexpected error: {err:#}"
        );
        assert!(
            std::fs::symlink_metadata(&a)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the operator's link was replaced by the write"
        );
    }

    /// An older summary or token file left world-readable is narrowed
    /// before the replacement is produced. The rename cannot do this:
    /// it publishes a fresh inode and leaves the old one readable for
    /// as long as it takes to write the new one.
    #[test]
    fn tighten_existing_secret_file_narrows_a_world_readable_destination() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("summary.json");
        std::fs::write(&path, "{}").expect("seed the destination");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        tighten_existing_secret_file(&path).expect("tighten");

        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, SECRET_OUTPUT_FILE_MODE);
    }

    #[test]
    fn tighten_existing_secret_file_ignores_a_missing_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        tighten_existing_secret_file(&dir.path().join("absent.json"))
            .expect("a missing destination is not an error");
    }

    /// The other secret-bearing `init` output. It shares
    /// `write_root_token_file`'s staging, tightening and symlink
    /// resolution, and carries the same credentials plus the unseal
    /// keys, so it is pinned in its own right rather than by
    /// resemblance to the token writer.
    fn summary_with_token(root_token: &str) -> InitSummary {
        use super::super::super::types::{ResponderCheck, StepCaInitResult};

        InitSummary {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: std::path::PathBuf::from("secrets"),
            show_secrets: false,
            init_response: true,
            root_token: root_token.to_string(),
            unseal_keys: vec!["unseal-one".to_string()],
            approles: Vec::new(),
            stepca_password: "pw".to_string(),
            db_dsn: String::new(),
            db_dsn_host_original: String::new(),
            db_dsn_host_effective: String::new(),
            http_hmac: "hmac".to_string(),
            eab: None,
            step_ca_result: StepCaInitResult::Skipped,
            responder_check: ResponderCheck::Skipped,
            responder_url: None,
            responder_template_path: std::path::PathBuf::from("responder.tmpl"),
            responder_config_path: std::path::PathBuf::from("responder.toml"),
            openbao_agent_stepca_config_path: std::path::PathBuf::from("agent-stepca.hcl"),
            openbao_agent_responder_config_path: std::path::PathBuf::from("agent-responder.hcl"),
            openbao_agent_override_path: None,
            db_check: DbCheckStatus::Skipped,
        }
    }

    /// The summary is published by rename at `0600` over a destination
    /// an earlier run left world-readable: the tightening narrows the
    /// old credentials sitting there, and the fresh inode the rename
    /// installs was never wider than `0600`.
    #[tokio::test]
    async fn write_init_summary_json_replaces_a_world_readable_destination_at_0600() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("summary.json");
        std::fs::write(&path, "{\"stale\":true}").expect("seed the destination");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let stale_inode = std::fs::metadata(&path).expect("stat").ino();

        write_init_summary_json(&path, &summary_with_token("hvs.fresh"))
            .await
            .expect("summary write over a world-readable destination");

        let written = std::fs::read_to_string(&path).expect("read");
        assert!(written.contains("hvs.fresh"), "got: {written}");
        let meta = std::fs::metadata(&path).expect("stat");
        assert_eq!(meta.permissions().mode() & 0o777, SECRET_OUTPUT_FILE_MODE);
        assert_ne!(meta.ino(), stale_inode, "the publish must be a rename");
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .expect("read_dir")
            .map(|e| e.expect("entry").file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("summary.json")],
            "the staged temporary must not survive the publish"
        );
    }

    /// As for the token: the summary reaches the link's target and the
    /// operator's link survives. Renaming over the link would leave the
    /// target holding the previous run's credentials while the write
    /// reported success.
    #[tokio::test]
    async fn write_init_summary_json_writes_through_a_symlinked_destination() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let real_dir = dir.path().join("real");
        std::fs::create_dir(&real_dir).expect("mkdir");
        let target = real_dir.join("summary.json");
        std::fs::write(&target, "{\"stale\":true}").expect("seed the target");
        let link = dir.path().join("summary.json");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        write_init_summary_json(&link, &summary_with_token("hvs.through-link"))
            .await
            .expect("summary write through a symlink");

        assert!(
            std::fs::symlink_metadata(&link)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the operator's link must survive the write"
        );
        let written = std::fs::read_to_string(&target).expect("read");
        assert!(written.contains("hvs.through-link"), "got: {written}");
        let mode = std::fs::metadata(&target)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, SECRET_OUTPUT_FILE_MODE);
    }

    /// A link whose target does not exist yet is still where the
    /// operator wants the summary, exactly as for the token file.
    #[tokio::test]
    async fn write_init_summary_json_creates_a_dangling_symlink_target() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir(dir.path().join("secure")).expect("mkdir");
        let target = dir.path().join("secure").join("summary.json");
        let link = dir.path().join("summary.json");
        std::os::unix::fs::symlink(&target, &link).expect("symlink");

        write_init_summary_json(&link, &summary_with_token("hvs.dangling"))
            .await
            .expect("summary write over a dangling link");

        assert!(
            std::fs::symlink_metadata(&link)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the operator's link must survive the write"
        );
        let written = std::fs::read_to_string(&target).expect("read");
        assert!(written.contains("hvs.dangling"), "got: {written}");
        let mode = std::fs::metadata(&target)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, SECRET_OUTPUT_FILE_MODE);
    }
}
