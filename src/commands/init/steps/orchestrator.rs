use std::collections::BTreeMap;
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
use super::database::{check_db_connectivity, resolve_db_dsn_for_init};
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
use super::prompts::confirm_overwrite;
use super::responder_setup::{
    apply_responder_compose_override, verify_responder, write_responder_compose_override,
    write_responder_files,
};
use super::secrets::{maybe_register_eab, resolve_init_secrets};
use super::stepca_setup::{
    ensure_step_ca_initialized, update_ca_json_with_backup, write_password_file_with_backup,
    write_stepca_templates,
};
use crate::cli::args::{InitArgs, InitFeature};
use crate::cli::output::{print_init_plan, print_init_summary};
use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::guardrails::{
    client_url_from_bind_addr, ensure_all_services_localhost_binding, validate_http01_admin_tls,
    validate_http01_override_binding, validate_http01_override_scope,
    validate_openbao_override_binding, validate_openbao_override_scope, validate_openbao_tls,
};
use crate::commands::infra::{
    ensure_init_prereqs_ready, has_http01_admin_bind_intent, has_openbao_bind_intent,
    resolve_stepca_exposed_override, run_docker,
};
use crate::commands::init::{
    HTTP01_ADMIN_TLS_CERT_REL_PATH, HTTP01_ADMIN_TLS_KEY_REL_PATH,
    HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_HCL_PATH,
    OPENBAO_TLS_CERT_PATH, OPENBAO_TLS_KEY_PATH, RESPONDER_CONFIG_DIR, RESPONDER_CONFIG_NAME,
};
use crate::i18n::Messages;
use crate::state::StateFile;

pub(crate) async fn run_init(args: &InitArgs, messages: &Messages) -> Result<()> {
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
/// The same atomic-create discipline used by `write_root_token_file` is
/// applied here: `OpenOptionsExt::mode(0o600)` ensures new files are
/// born `0600`, and an explicit `set_permissions(0o600)` immediately
/// after the write also restricts any pre-existing destination before
/// `write_all` so the secrets never touch a wider-mode file.  Reinit's
/// preflight (`validate_summary_json_output_path`) additionally
/// rejects world-/group-readable existing destinations, but this write
/// path is deliberately defensive — `--summary-json` may be invoked
/// from the `init` flow (not just `reinit`) where no preflight runs.
async fn write_init_summary_json(path: &Path, summary: &InitSummary) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    let payload = serde_json::to_string_pretty(summary)?;
    let path_buf = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // Tighten an existing destination's permissions before any
        // secret content is written.  No-op for missing files.  The
        // `OpenOptions::mode` below covers the missing-file case so
        // the file is born `0600`.
        if path_buf.exists() {
            std::fs::set_permissions(&path_buf, std::fs::Permissions::from_mode(0o600))?;
        }
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path_buf)?;
        file.write_all(payload.as_bytes())?;
        file.sync_all()?;
        // Re-assert permissions in case an existing file's mode
        // changed between the pre-write set and the open call (e.g.
        // unusual filesystem semantics).
        std::fs::set_permissions(&path_buf, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking for summary json write failed: {e}"))??;
    Ok(())
}

/// Persists the freshly generated `OpenBao` root token to `path` with
/// mode `0600`.  Invoked only when the operator passes
/// `bootroot reinit --root-token-output <path>`; persistent root token
/// files are not recommended for production and the surrounding code
/// validates the destination path before any destructive work begins.
///
/// The file is created via `OpenOptionsExt::mode(0o600)` so a freshly
/// minted root token never exists on disk with the process umask's
/// default permissions (commonly `0644`) between creation and a
/// subsequent `chmod` call.  Per-process umask still applies, so an
/// explicit `set_permissions` follows for the existing-file case where
/// `OpenOptionsExt::mode` is a no-op on POSIX.
async fn write_root_token_file(path: &Path, token: &str) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent).await?;
    }
    let path_buf = path.to_path_buf();
    let token = token.to_string();
    tokio::task::spawn_blocking(move || -> std::io::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&path_buf)?;
        file.write_all(token.as_bytes())?;
        file.sync_all()?;
        std::fs::set_permissions(&path_buf, std::fs::Permissions::from_mode(0o600))?;
        Ok(())
    })
    .await
    .map_err(|e| anyhow::anyhow!("spawn_blocking for root token write failed: {e}"))??;
    Ok(())
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
    // Under reinit mode the operator has already authorized destructive
    // recovery at the `reinit` level, and reinit explicitly preserves
    // `password.txt`, `ca.json`, and the (just-rewritten) `state.json`.
    // Skipping these prompts keeps `reinit --yes` non-interactive.
    if !args.reinit_mode {
        if overwrite_password {
            confirm_overwrite(messages.prompt_confirm_overwrite_password(), messages)?;
        }
        if overwrite_ca_json {
            confirm_overwrite(messages.prompt_confirm_overwrite_ca_json(), messages)?;
        }
        if overwrite_state {
            confirm_overwrite(messages.prompt_confirm_overwrite_state(), messages)?;
        }
        if args.has_feature(InitFeature::DbProvision) {
            confirm_overwrite(messages.prompt_confirm_db_provision(), messages)?;
        }
    }

    // Load .env into the process environment so that
    // `build_admin_dsn_from_env()` and `build_dsn_from_env()` can discover
    // the temporary POSTGRES_PASSWORD written by `infra install`.
    let compose_dir = crate::commands::compose_file::compose_file_dir(&args.compose.compose_file);
    let compose_dir = compose_dir.as_path();
    crate::commands::dotenv::load_dotenv_into_env(&compose_dir.join(".env"), messages)?;

    let (db_dsn, db_dsn_normalization, admin_dsn_for_kv) =
        resolve_db_dsn_for_init(args, compose_dir, messages).await?;
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
        let stop_args = ["compose", "-f", &*compose_str, "stop", "step-ca"];
        let _ = run_docker(&stop_args, "docker compose stop step-ca", messages);
    }
    let step_ca_result = ensure_step_ca_initialized(&secrets_dir, messages)?;
    if step_ca_result == super::super::types::StepCaInitResult::Initialized {
        // Fix ownership: step-ca init may create files with different
        // ownership.  Re-apply correct perms before anything reads them.
        fix_secrets_permissions(&secrets_dir).await?;
    }

    rollback.ca_json_backup = Some(
        update_ca_json_with_backup(
            &secrets_dir,
            &secrets.db_dsn,
            &args.cert_duration,
            &args.stepca_provisioner,
            messages,
        )
        .await?,
    );

    if step_ca_result == super::super::types::StepCaInitResult::Initialized {
        // Restart step-ca after ca.json is patched with the DB DSN so it
        // loads the fully configured file on first boot.
        let compose_str = args.compose.compose_file.to_string_lossy();
        let restart_args = ["compose", "-f", &*compose_str, "restart", "step-ca"];
        let _ = run_docker(&restart_args, "docker compose restart step-ca", messages);
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
        let up_args = [
            "compose",
            "-f",
            &*compose_str,
            "-f",
            &*override_str,
            "up",
            "-d",
            "--no-deps",
            "step-ca",
        ];
        run_docker(&up_args, "docker compose up -d step-ca (exposed)", messages)?;
    }
    let stepca_templates = write_stepca_templates(
        &secrets_dir,
        &args.openbao.kv_mount,
        &args.cert_duration,
        &args.stepca_provisioner,
        messages,
    )
    .await?;
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
        let sans =
            build_http01_admin_tls_sans(bind_addr, state.http01_admin_advertise_addr.as_deref());
        let san_refs: Vec<&str> = sans.iter().map(String::as_str).collect();
        issue_http01_admin_tls_cert(&secrets_dir, &san_refs, messages)?;
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
            let up_args = [
                "compose",
                "-f",
                &*compose_str,
                "-f",
                &*config_override_str,
                "-f",
                &*exposed_override_str,
                "up",
                "-d",
                "--no-deps",
                RESPONDER_SERVICE_NAME,
            ];
            run_docker(
                &up_args,
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
    let responder_url = resolve_responder_url(args, compose_has_responder)?;
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
    )?;

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
        let sans = build_openbao_tls_sans(&bind_addr, state.openbao_advertise_addr.as_deref());
        let san_refs: Vec<&str> = sans.iter().map(String::as_str).collect();
        issue_openbao_tls_cert(
            compose_dir,
            &args.secrets_dir.secrets_dir,
            &san_refs,
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
        record_openbao_infra_cert(&mut state, compose_dir, sans);

        validate_openbao_override_scope(&override_path, messages)?;
        validate_openbao_override_binding(&override_path, &bind_addr, messages)?;
        validate_openbao_tls(compose_dir, &args.secrets_dir.secrets_dir, messages)?;
        let compose_str = args.compose.compose_file.to_string_lossy();
        let override_str = override_path.to_string_lossy();
        let up_args = [
            "compose",
            "-f",
            &*compose_str,
            "-f",
            &*override_str,
            "up",
            "-d",
            "openbao",
        ];
        run_docker(&up_args, "docker compose up -d openbao", messages)?;

        // Persist the CN-side HTTPS URL and infra_certs entry now
        // that TLS is validated and the non-loopback override is
        // applied.  Always derive from bind_addr (which maps
        // wildcards to loopback via `client_url_from_bind_addr`)
        // so that local commands (auto-unseal, service, rotate)
        // never depend on the external advertise address being
        // hairpin-reachable.  The advertise address is consumed
        // separately by remote bootstrap artifact generation.
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
        state.openbao_url = client_url_from_bind_addr(&bind_addr);
        state
            .save(&state_path)
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
        let sans =
            build_http01_admin_tls_sans(&bind_addr, state.http01_admin_advertise_addr.as_deref());
        record_http01_admin_infra_cert(&mut state, &secrets_dir, sans);
        state
            .save(&state_path)
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
            prompt_yes_no(messages.prompt_save_unseal_keys(), messages)?
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
        eprintln!("{}", messages.openbao_unseal_keys_not_saved_warning());
        for (idx, key) in keys.iter().enumerate() {
            println!("{}", messages.summary_unseal_key(idx + 1, key));
        }
    }
    Ok(())
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
    use crate::commands::dotenv::{read_dotenv, update_dotenv_key};
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
    if let Ok(mut doc) = serde_json::from_str::<serde_json::Value>(&ca_json_contents) {
        doc["db"]["dataSource"] = serde_json::Value::String(new_dsn.clone());
        if let Ok(updated) = serde_json::to_string_pretty(&doc) {
            let _ = tokio::fs::write(&ca_json_path, updated).await;
        }
    }

    // Overwrite .env with a dummy password so docker compose doesn't error.
    update_dotenv_key(
        &env_path,
        "POSTGRES_PASSWORD",
        "rotated-use-openbao",
        messages,
    )?;

    // Restart step-ca to pick up the new DSN from the patched ca.json.
    let compose_str = compose_file.to_string_lossy();
    let restart_args = ["compose", "-f", &*compose_str, "restart", "step-ca"];
    let _ = run_docker(&restart_args, "docker compose restart step-ca", messages);

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

/// Fixes file ownership and permissions in the secrets directory after
/// `step ca init` which runs as root inside Docker.
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

pub(super) fn write_state_file(
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
}

/// Inner implementation that accepts an explicit state-file path for
/// testability.
#[allow(clippy::too_many_arguments)] // init-time state snapshot: every value is a distinct flag
fn write_state_file_to(
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
        .save(state_path)
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
    #[test]
    fn write_state_file_errors_on_corrupted_state() {
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
        );
        assert!(
            result.is_err(),
            "corrupted state file must be a hard error, not silently replaced"
        );
    }

    /// `write_state_file_to` preserves `openbao_bind_addr` from an
    /// existing, valid state file.
    #[test]
    fn write_state_file_preserves_bind_addr() {
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
    #[test]
    fn write_state_file_records_rotate_fields_and_preserves_timestamp() {
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
    #[test]
    fn write_state_file_preserves_stepca_bind_intent() {
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
}
