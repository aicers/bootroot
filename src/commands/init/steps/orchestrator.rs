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
    bootstrap_openbao, configure_openbao, setup_openbao_agents, validate_secret_id_ttl,
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
    ensure_init_prereqs_ready, has_http01_admin_bind_intent, has_openbao_bind_intent, run_docker,
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
    eprintln!("{}", messages.hint_secret_id_ttl_rotation_cadence());

    ensure_all_services_localhost_binding(&args.compose.compose_file, messages)?;

    // Check whether a non-loopback OpenBao bind intent is stored in
    // state.  TLS is validated inside `run_init_inner` (after
    // `ensure_step_ca_initialized`) so that failures trigger rollback.
    let state_path = StateFile::default_path();
    let bind_intent = has_openbao_bind_intent(&state_path)?;

    // Only check openbao + postgres; step-ca may not be bootstrapped yet.
    ensure_init_prereqs_ready(&args.compose.compose_file, messages)?;

    let mut client = OpenBaoClient::new(&args.openbao.openbao_url)
        .with_context(|| messages.error_openbao_client_create_failed())?;
    client
        .health_check()
        .await
        .with_context(|| messages.error_openbao_health_check_failed())?;

    let mut rollback = InitRollback::default();
    let result = run_init_inner(&mut client, args, messages, &mut rollback, bind_intent).await;

    match result {
        Ok(summary) => {
            if let Some(summary_json) = args.summary_json.as_deref() {
                write_init_summary_json(summary_json, &summary).await?;
            }
            print_init_summary(&summary, messages);

            // Prompt to save unseal keys if they were just generated.
            if summary.init_response && !summary.unseal_keys.is_empty() {
                maybe_save_unseal_keys(
                    &args.secrets_dir.secrets_dir,
                    &summary.unseal_keys,
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

async fn write_init_summary_json(path: &Path, summary: &InitSummary) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let payload = serde_json::to_string_pretty(summary)?;
    tokio::fs::write(path, payload).await?;
    fs_util::set_key_permissions(path).await?;
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

    // Load .env into the process environment so that
    // `build_admin_dsn_from_env()` and `build_dsn_from_env()` can discover
    // the temporary POSTGRES_PASSWORD written by `infra install`.
    let compose_dir = args.compose.compose_file.parent().unwrap_or(Path::new("."));
    crate::commands::dotenv::load_dotenv_into_env(&compose_dir.join(".env"), messages)?;

    let (db_dsn, db_dsn_normalization) = resolve_db_dsn_for_init(args, messages).await?;
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

    let secrets_dir = args.secrets_dir.secrets_dir.clone();

    // Write password.txt first - step-ca init needs it.
    rollback.password_backup = Some(
        write_password_file_with_backup(&secrets_dir, &secrets.stepca_password, messages).await?,
    );

    // Bootstrap step-ca if not already initialized. This creates ca.json
    // and keys inside secrets/config/ and secrets/secrets/.  Must run
    // before update_ca_json_with_backup and write_stepca_templates, which
    // both read ca.json.
    let step_ca_result = ensure_step_ca_initialized(&secrets_dir, messages)?;
    if step_ca_result == super::super::types::StepCaInitResult::Initialized {
        // Fix ownership: step-ca init may create files with different
        // ownership.  Re-apply correct perms before anything reads them.
        fix_secrets_permissions(&secrets_dir).await?;
    }

    rollback.ca_json_backup =
        Some(update_ca_json_with_backup(&secrets_dir, &secrets.db_dsn, messages).await?);

    if step_ca_result == super::super::types::StepCaInitResult::Initialized {
        // Restart step-ca after ca.json is patched with the DB DSN so it
        // loads the fully configured file on first boot.
        let compose_str = args.compose.compose_file.to_string_lossy();
        let restart_args = ["compose", "-f", &*compose_str, "restart", "step-ca"];
        let _ = run_docker(&restart_args, "docker compose restart step-ca", messages);
    }
    let stepca_templates =
        write_stepca_templates(&secrets_dir, &args.openbao.kv_mount, messages).await?;
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
    let openbao_agent_paths = setup_openbao_agents(
        &args.compose.compose_file,
        &secrets_dir,
        &args.openbao.openbao_url,
        &role_outputs,
        &stepca_templates,
        &responder_paths.template_path,
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
        state.openbao_url = client_url_from_bind_addr(&bind_addr);
        state
            .save(&state_path)
            .with_context(|| messages.error_serialize_state_failed())?;
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

async fn maybe_save_unseal_keys(
    secrets_dir: &Path,
    keys: &[String],
    messages: &Messages,
) -> Result<()> {
    use super::prompts::prompt_yes_no;
    if prompt_yes_no(messages.prompt_save_unseal_keys(), messages)? {
        let path =
            crate::commands::openbao_unseal::save_unseal_keys(secrets_dir, keys, messages).await?;
        println!(
            "{}",
            messages.openbao_unseal_keys_saved(&path.display().to_string())
        );
    } else {
        // User declined saving — display the keys in cleartext so they
        // can be copied for manual safekeeping.
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
    use crate::commands::init::PATH_STEPCA_DB;

    // Docker Compose reads .env from the compose file's directory.
    let compose_dir = compose_file.parent().unwrap_or(Path::new("."));
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

    let admin_dsn = bootroot::db::build_db_dsn(
        "step",
        &temp_password,
        "localhost",
        parsed.port,
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

    let new_dsn = bootroot::db::build_db_dsn(
        &parsed.user,
        &new_password,
        &parsed.host,
        parsed.port,
        &parsed.database,
        parsed.sslmode.as_deref(),
    );

    // Write new DSN to OpenBao KV.
    client
        .write_kv(
            kv_mount,
            PATH_STEPCA_DB,
            serde_json::json!({ "value": new_dsn }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;

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
    messages: &Messages,
) -> Result<()> {
    write_state_file_to(
        &StateFile::default_path(),
        openbao_url,
        kv_mount,
        approles,
        secrets_dir,
        messages,
    )
}

/// Inner implementation that accepts an explicit state-file path for
/// testability.
fn write_state_file_to(
    state_path: &Path,
    openbao_url: &str,
    kv_mount: &str,
    approles: BTreeMap<String, String>,
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let (
        existing_services,
        existing_openbao_bind_addr,
        existing_openbao_advertise_addr,
        existing_http01_admin_bind_addr,
        existing_http01_admin_advertise_addr,
        existing_infra_certs,
    ) = if state_path.exists() {
        let state = StateFile::load(state_path)?;
        (
            state.services,
            state.openbao_bind_addr,
            state.openbao_advertise_addr,
            state.http01_admin_bind_addr,
            state.http01_admin_advertise_addr,
            state.infra_certs,
        )
    } else {
        (BTreeMap::new(), None, None, None, None, BTreeMap::new())
    };

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
        infra_certs: existing_infra_certs,
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
    use super::*;

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
            infra_certs: BTreeMap::new(),
        };
        existing.save(&state_path).unwrap();
        write_state_file_to(
            &state_path,
            "http://localhost:8200",
            "secret",
            BTreeMap::new(),
            Path::new("secrets"),
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
            infra_certs: BTreeMap::new(),
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
            infra_certs: BTreeMap::new(),
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
            infra_certs: BTreeMap::new(),
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
}
