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
use super::database::{check_db_connectivity, resolve_db_dsn_for_init};
use super::openbao_setup::{
    bootstrap_openbao, configure_openbao, setup_openbao_agents,
    write_ca_trust_fingerprints_with_retry,
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
use crate::commands::guardrails::ensure_postgres_localhost_binding;
use crate::commands::infra::ensure_infra_ready;
use crate::i18n::Messages;
use crate::state::StateFile;

pub(crate) async fn run_init(args: &InitArgs, messages: &Messages) -> Result<()> {
    ensure_postgres_localhost_binding(&args.compose.compose_file, messages)?;
    ensure_infra_ready(&args.compose.compose_file, messages)?;

    let mut client = OpenBaoClient::new(&args.openbao.openbao_url)
        .with_context(|| messages.error_openbao_client_create_failed())?;
    client
        .health_check()
        .await
        .with_context(|| messages.error_openbao_health_check_failed())?;

    let mut rollback = InitRollback::default();
    let result = run_init_inner(&mut client, args, messages, &mut rollback).await;

    match result {
        Ok(summary) => {
            if let Some(summary_json) = args.summary_json.as_deref() {
                write_init_summary_json(summary_json, &summary).await?;
            }
            print_init_summary(&summary, messages);
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
    rollback.password_backup = Some(
        write_password_file_with_backup(&secrets_dir, &secrets.stepca_password, messages).await?,
    );
    rollback.ca_json_backup =
        Some(update_ca_json_with_backup(&secrets_dir, &secrets.db_dsn, messages).await?);
    let stepca_templates =
        write_stepca_templates(&secrets_dir, &args.openbao.kv_mount, messages).await?;
    let responder_paths = write_responder_files(
        &secrets_dir,
        &args.openbao.kv_mount,
        &secrets.http_hmac,
        messages,
    )
    .await?;
    let responder_compose_override = write_responder_compose_override(
        &args.compose.compose_file,
        &secrets_dir,
        &responder_paths.config_path,
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
    if let Some(override_path) = responder_compose_override.as_ref() {
        apply_responder_compose_override(&args.compose.compose_file, override_path, messages)?;
    }

    let step_ca_result = ensure_step_ca_initialized(&secrets_dir, messages)?;
    let _trust_changed = write_ca_trust_fingerprints_with_retry(
        client,
        &args.openbao.kv_mount,
        &secrets_dir,
        rollback,
        messages,
    )
    .await?;
    let compose_has_responder = compose_has_responder(&args.compose.compose_file, messages)?;
    let responder_url = resolve_responder_url(args, compose_has_responder);
    let responder_check =
        verify_responder(responder_url.as_deref(), args, messages, &secrets).await?;
    let eab_update = maybe_register_eab(client, args, messages, rollback, &secrets).await?;
    if let Some(eab) = eab_update {
        secrets.eab = Some(eab);
    }

    write_state_file(
        &args.openbao.openbao_url,
        &args.openbao.kv_mount,
        &approles,
        &args.secrets_dir.secrets_dir,
        messages,
    )?;

    Ok(InitSummary {
        openbao_url: args.openbao.openbao_url.clone(),
        kv_mount: args.openbao.kv_mount.clone(),
        secrets_dir: args.secrets_dir.secrets_dir.clone(),
        show_secrets: args.has_feature(InitFeature::ShowSecrets),
        init_response: bootstrap.init_response.is_some(),
        root_token: bootstrap.root_token,
        unseal_keys: bootstrap.unseal_keys,
        approles: role_outputs,
        stepca_password: secrets.stepca_password,
        db_dsn: secrets.db_dsn,
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

pub(super) fn write_state_file(
    openbao_url: &str,
    kv_mount: &str,
    approles: &BTreeMap<String, String>,
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let state_path = StateFile::default_path();
    let existing_services = if state_path.exists() {
        StateFile::load(&state_path)
            .map(|state| state.services)
            .unwrap_or_default()
    } else {
        BTreeMap::new()
    };
    let policy_map = AppRoleLabel::policy_map();
    let state = StateFile {
        openbao_url: openbao_url.to_string(),
        kv_mount: kv_mount.to_string(),
        secrets_dir: Some(secrets_dir.to_path_buf()),
        policies: policy_map,
        approles: approles
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        services: existing_services,
    };
    state
        .save(&state_path)
        .with_context(|| messages.error_serialize_state_failed())?;
    Ok(())
}
