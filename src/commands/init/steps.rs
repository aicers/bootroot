use std::collections::BTreeMap;
use std::env;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::acme::responder_client;
use bootroot::db::{
    DbDsn, build_db_dsn, check_auth_sync, check_tcp, parse_db_dsn, provision_db_sync,
    validate_db_identifier,
};
use bootroot::fs_util;
use bootroot::openbao::{InitResponse, OpenBaoClient};
use reqwest::StatusCode;
use ring::digest;
use x509_parser::pem::parse_x509_pem;

use super::constants::openbao_constants::{
    APPROLE_BOOTROOT_AGENT, APPROLE_BOOTROOT_RESPONDER, APPROLE_BOOTROOT_STEPCA,
    INIT_SECRET_SHARES, INIT_SECRET_THRESHOLD, PATH_AGENT_EAB, PATH_CA_TRUST, PATH_RESPONDER_HMAC,
    PATH_STEPCA_DB, PATH_STEPCA_PASSWORD, POLICY_BOOTROOT_AGENT, POLICY_BOOTROOT_RESPONDER,
    POLICY_BOOTROOT_STEPCA, SECRET_ID_TTL, TOKEN_TTL,
};
use super::constants::{
    CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME, CA_TRUST_KEY,
    DEFAULT_CA_ADDRESS, DEFAULT_CA_DNS, DEFAULT_CA_NAME, DEFAULT_CA_PROVISIONER, DEFAULT_DB_NAME,
    DEFAULT_DB_USER, DEFAULT_EAB_ENDPOINT_PATH, DEFAULT_RESPONDER_TOKEN_TTL_SECS,
    OPENBAO_AGENT_COMPOSE_OVERRIDE_NAME, OPENBAO_AGENT_CONFIG_NAME, OPENBAO_AGENT_DIR,
    OPENBAO_AGENT_RESPONDER_DIR, OPENBAO_AGENT_RESPONDER_SERVICE, OPENBAO_AGENT_ROLE_ID_NAME,
    OPENBAO_AGENT_SECRET_ID_NAME, OPENBAO_AGENT_STEPCA_DIR, OPENBAO_AGENT_STEPCA_SERVICE,
    RESPONDER_COMPOSE_OVERRIDE_NAME, RESPONDER_CONFIG_DIR, RESPONDER_CONFIG_NAME,
    RESPONDER_TEMPLATE_DIR, RESPONDER_TEMPLATE_NAME, SECRET_BYTES, STEPCA_CA_JSON_TEMPLATE_NAME,
    STEPCA_PASSWORD_TEMPLATE_NAME,
};
use super::paths::{
    OpenBaoAgentPaths, ResponderPaths, StepCaTemplatePaths, compose_has_openbao,
    compose_has_responder, resolve_openbao_agent_addr, resolve_responder_url, to_container_path,
};
use super::types::{
    AppRoleOutput, DbCheckStatus, EabCredentials, InitPlan, InitSummary, ResponderCheck,
    StepCaInitResult,
};
use crate::cli::args::InitArgs;
use crate::cli::output::{print_init_plan, print_init_summary};
use crate::commands::guardrails::{ensure_postgres_localhost_binding, is_single_host_db_host};
use crate::commands::infra::{ensure_infra_ready, run_docker};
use crate::commands::openbao_unseal::read_unseal_keys_from_file;
use crate::i18n::Messages;
use crate::state::{DeliveryMode, StateFile, SyncApplyStatus};

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
    if args.db_provision {
        confirm_overwrite(messages.prompt_confirm_db_provision(), messages)?;
    }

    let (db_dsn, db_dsn_normalization) = resolve_db_dsn_for_init(args, messages).await?;
    let mut secrets = resolve_init_secrets(args, messages, db_dsn)?;
    let db_info = parse_db_dsn(&secrets.db_dsn)
        .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
    let db_check = if args.db_check {
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

    let (role_outputs, _policies, approles) =
        configure_openbao(client, args, &secrets, rollback, messages).await?;

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
    let trust_changed = write_ca_trust_fingerprints_with_retry(
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
    if trust_changed {
        mark_remote_trust_sync_pending(messages)?;
    }

    Ok(InitSummary {
        openbao_url: args.openbao.openbao_url.clone(),
        kv_mount: args.openbao.kv_mount.clone(),
        secrets_dir: args.secrets_dir.secrets_dir.clone(),
        show_secrets: args.show_secrets,
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

struct InitBootstrap {
    init_response: Option<InitResponse>,
    root_token: String,
    unseal_keys: Vec<String>,
}

struct InitSecrets {
    stepca_password: String,
    db_dsn: String,
    http_hmac: String,
    eab: Option<EabCredentials>,
}

#[derive(Debug, Clone)]
struct DbDsnNormalization {
    original_host: String,
    effective_host: String,
}

const DB_COMPOSE_HOST: &str = "postgres";

#[derive(serde::Deserialize)]
struct EabAutoResponse {
    #[serde(alias = "keyId", alias = "kid")]
    kid: String,
    #[serde(alias = "hmacKey", alias = "hmac")]
    hmac: String,
}

async fn write_responder_files(
    secrets_dir: &Path,
    kv_mount: &str,
    hmac: &str,
    messages: &Messages,
) -> Result<ResponderPaths> {
    let templates_dir = secrets_dir.join(RESPONDER_TEMPLATE_DIR);
    fs_util::ensure_secrets_dir(&templates_dir).await?;
    let responder_dir = secrets_dir.join(RESPONDER_CONFIG_DIR);
    fs_util::ensure_secrets_dir(&responder_dir).await?;

    let template_path = templates_dir.join(RESPONDER_TEMPLATE_NAME);
    let template = build_responder_template(kv_mount);
    tokio::fs::write(&template_path, template)
        .await
        .with_context(|| messages.error_write_file_failed(&template_path.display().to_string()))?;
    fs_util::set_key_permissions(&template_path).await?;

    let config_path = responder_dir.join(RESPONDER_CONFIG_NAME);
    let config = build_responder_config(hmac);
    tokio::fs::write(&config_path, config)
        .await
        .with_context(|| messages.error_write_file_failed(&config_path.display().to_string()))?;
    fs_util::set_key_permissions(&config_path).await?;

    Ok(ResponderPaths {
        template_path,
        config_path,
    })
}

async fn write_stepca_templates(
    secrets_dir: &Path,
    kv_mount: &str,
    messages: &Messages,
) -> Result<StepCaTemplatePaths> {
    let templates_dir = secrets_dir.join(RESPONDER_TEMPLATE_DIR);
    fs_util::ensure_secrets_dir(&templates_dir).await?;

    let password_template_path = templates_dir.join(STEPCA_PASSWORD_TEMPLATE_NAME);
    let password_template = build_password_template(kv_mount);
    tokio::fs::write(&password_template_path, password_template)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&password_template_path.display().to_string())
        })?;
    fs_util::set_key_permissions(&password_template_path).await?;

    let ca_json_path = secrets_dir.join("config").join("ca.json");
    let ca_json_contents = tokio::fs::read_to_string(&ca_json_path)
        .await
        .with_context(|| messages.error_read_file_failed(&ca_json_path.display().to_string()))?;
    let ca_json_template = build_ca_json_template(&ca_json_contents, kv_mount, messages)?;
    let ca_json_template_path = templates_dir.join(STEPCA_CA_JSON_TEMPLATE_NAME);
    tokio::fs::write(&ca_json_template_path, ca_json_template)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&ca_json_template_path.display().to_string())
        })?;
    fs_util::set_key_permissions(&ca_json_template_path).await?;

    Ok(StepCaTemplatePaths {
        password_template_path,
        ca_json_template_path,
    })
}

fn build_responder_template(kv_mount: &str) -> String {
    format!(
        r#"# HTTP-01 responder config (OpenBao Agent template)

listen_addr = "0.0.0.0:80"
admin_addr = "0.0.0.0:8080"
hmac_secret = "{{{{ with secret "{kv_mount}/data/{PATH_RESPONDER_HMAC}" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}"
token_ttl_secs = 300
cleanup_interval_secs = 30
max_skew_secs = 60
"#
    )
}

fn build_password_template(kv_mount: &str) -> String {
    format!(
        r#"{{{{ with secret "{kv_mount}/data/{PATH_STEPCA_PASSWORD}" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}"#
    )
}

fn build_ca_json_template(contents: &str, kv_mount: &str, messages: &Messages) -> Result<String> {
    let mut value: serde_json::Value =
        serde_json::from_str(contents).context(messages.error_parse_ca_json_failed())?;
    let db = value
        .get_mut("db")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    let data_source = db
        .get_mut("dataSource")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    *data_source = serde_json::Value::String(format!(
        "{{{{ with secret \"{kv_mount}/data/{PATH_STEPCA_DB}\" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}"
    ));
    serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())
}

fn build_responder_config(hmac: &str) -> String {
    format!(
        r#"# HTTP-01 responder config (rendered)

listen_addr = "0.0.0.0:80"
admin_addr = "0.0.0.0:8080"
hmac_secret = "{hmac}"
token_ttl_secs = 300
cleanup_interval_secs = 30
max_skew_secs = 60
"#
    )
}

async fn write_openbao_agent_files(
    secrets_dir: &Path,
    openbao_addr: &str,
    role_outputs: &[AppRoleOutput],
    stepca_templates: &StepCaTemplatePaths,
    responder_template: &Path,
    messages: &Messages,
) -> Result<OpenBaoAgentPaths> {
    let base_dir = secrets_dir.join(OPENBAO_AGENT_DIR);
    fs_util::ensure_secrets_dir(&base_dir).await?;
    let stepca_dir = base_dir.join(OPENBAO_AGENT_STEPCA_DIR);
    let responder_dir = base_dir.join(OPENBAO_AGENT_RESPONDER_DIR);
    fs_util::ensure_secrets_dir(&stepca_dir).await?;
    fs_util::ensure_secrets_dir(&responder_dir).await?;

    let stepca_role = find_role_output(role_outputs, "stepca", messages)?;
    let responder_role = find_role_output(role_outputs, "responder", messages)?;

    let stepca_role_id_path = stepca_dir.join(OPENBAO_AGENT_ROLE_ID_NAME);
    let stepca_secret_id_path = stepca_dir.join(OPENBAO_AGENT_SECRET_ID_NAME);
    tokio::fs::write(&stepca_role_id_path, &stepca_role.role_id)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&stepca_role_id_path.display().to_string())
        })?;
    tokio::fs::write(&stepca_secret_id_path, &stepca_role.secret_id)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&stepca_secret_id_path.display().to_string())
        })?;
    fs_util::set_key_permissions(&stepca_role_id_path).await?;
    fs_util::set_key_permissions(&stepca_secret_id_path).await?;

    let responder_role_id_path = responder_dir.join(OPENBAO_AGENT_ROLE_ID_NAME);
    let responder_secret_id_path = responder_dir.join(OPENBAO_AGENT_SECRET_ID_NAME);
    tokio::fs::write(&responder_role_id_path, &responder_role.role_id)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&responder_role_id_path.display().to_string())
        })?;
    tokio::fs::write(&responder_secret_id_path, &responder_role.secret_id)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&responder_secret_id_path.display().to_string())
        })?;
    fs_util::set_key_permissions(&responder_role_id_path).await?;
    fs_util::set_key_permissions(&responder_secret_id_path).await?;

    let stepca_agent_config = stepca_dir.join(OPENBAO_AGENT_CONFIG_NAME);
    let responder_agent_config = responder_dir.join(OPENBAO_AGENT_CONFIG_NAME);
    let password_template = to_container_path(
        secrets_dir,
        &stepca_templates.password_template_path,
        messages,
    )?;
    let ca_json_template = to_container_path(
        secrets_dir,
        &stepca_templates.ca_json_template_path,
        messages,
    )?;
    let responder_template = to_container_path(secrets_dir, responder_template, messages)?;
    let password_output =
        to_container_path(secrets_dir, &secrets_dir.join("password.txt"), messages)?;
    let ca_json_output = to_container_path(
        secrets_dir,
        &secrets_dir.join("config").join("ca.json"),
        messages,
    )?;
    let responder_output = to_container_path(
        secrets_dir,
        &secrets_dir.join("responder").join("responder.toml"),
        messages,
    )?;
    let stepca_config = build_openbao_agent_config(
        openbao_addr,
        "/openbao/secrets/openbao/stepca/role_id",
        "/openbao/secrets/openbao/stepca/secret_id",
        &[
            (password_template, password_output),
            (ca_json_template, ca_json_output),
        ],
    );
    let responder_config = build_openbao_agent_config(
        openbao_addr,
        "/openbao/secrets/openbao/responder/role_id",
        "/openbao/secrets/openbao/responder/secret_id",
        &[(responder_template, responder_output)],
    );
    tokio::fs::write(&stepca_agent_config, stepca_config)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&stepca_agent_config.display().to_string())
        })?;
    tokio::fs::write(&responder_agent_config, responder_config)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&responder_agent_config.display().to_string())
        })?;
    fs_util::set_key_permissions(&stepca_agent_config).await?;
    fs_util::set_key_permissions(&responder_agent_config).await?;

    Ok(OpenBaoAgentPaths {
        stepca_agent_config,
        responder_agent_config,
        compose_override_path: None,
    })
}

async fn setup_openbao_agents(
    compose_file: &Path,
    secrets_dir: &Path,
    openbao_url: &str,
    role_outputs: &[AppRoleOutput],
    stepca_templates: &StepCaTemplatePaths,
    responder_template: &Path,
    messages: &Messages,
) -> Result<OpenBaoAgentPaths> {
    let compose_has_openbao = compose_has_openbao(compose_file, messages)?;
    let openbao_agent_addr = resolve_openbao_agent_addr(openbao_url, compose_has_openbao);
    let mut openbao_agent_paths = write_openbao_agent_files(
        secrets_dir,
        &openbao_agent_addr,
        role_outputs,
        stepca_templates,
        responder_template,
        messages,
    )
    .await?;
    let openbao_agent_override = write_openbao_agent_compose_override(
        compose_file,
        secrets_dir,
        &openbao_agent_addr,
        messages,
    )
    .await?;
    openbao_agent_paths
        .compose_override_path
        .clone_from(&openbao_agent_override);
    if let Some(override_path) = openbao_agent_override.as_ref() {
        apply_openbao_agent_compose_override(compose_file, override_path, messages)?;
    }
    Ok(openbao_agent_paths)
}

fn build_openbao_agent_config(
    openbao_addr: &str,
    role_id_path: &str,
    secret_id_path: &str,
    templates: &[(String, String)],
) -> String {
    let mut config = format!(
        r#"vault {{
  address = "{openbao_addr}"
}}

auto_auth {{
  method "approle" {{
    config = {{
      role_id_file_path = "{role_id_path}"
      secret_id_file_path = "{secret_id_path}"
    }}
  }}
  sink "file" {{
    config = {{
      path = "/openbao/secrets/openbao/token"
    }}
  }}
}}
"#
    );
    for (source_path, destination_path) in templates {
        use std::fmt::Write as _;
        write!(
            &mut config,
            r#"
template {{
  source = "{source_path}"
  destination = "{destination_path}"
  perms = "0600"
}}
"#
        )
        .expect("write template");
    }
    config
}

async fn write_responder_compose_override(
    compose_file: &Path,
    secrets_dir: &Path,
    config_path: &Path,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    if !compose_has_responder(compose_file, messages)? {
        return Ok(None);
    }
    let responder_dir = secrets_dir.join(RESPONDER_CONFIG_DIR);
    fs_util::ensure_secrets_dir(&responder_dir).await?;
    let override_path = responder_dir.join(RESPONDER_COMPOSE_OVERRIDE_NAME);
    let config_path = std::fs::canonicalize(config_path)
        .with_context(|| messages.error_resolve_path_failed(&config_path.display().to_string()))?;
    let contents = format!(
        r#"version: "3.8"
services:
  bootroot-http01:
    volumes:
      - {path}:/app/responder.toml:ro
"#,
        path = config_path.display()
    );
    tokio::fs::write(&override_path, contents)
        .await
        .with_context(|| messages.error_write_file_failed(&override_path.display().to_string()))?;
    Ok(Some(override_path))
}

async fn write_openbao_agent_compose_override(
    compose_file: &Path,
    secrets_dir: &Path,
    openbao_addr: &str,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    let agent_dir = secrets_dir.join(OPENBAO_AGENT_DIR);
    fs_util::ensure_secrets_dir(&agent_dir).await?;
    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let override_path = agent_dir.join(OPENBAO_AGENT_COMPOSE_OVERRIDE_NAME);
    let depends_on = if compose_has_openbao(compose_file, messages)? {
        "    depends_on:\n      - openbao\n"
    } else {
        ""
    };
    let contents = format!(
        r#"version: "3.8"
services:
  {stepca_service}:
    image: openbao/openbao:latest
    container_name: bootroot-openbao-agent-stepca
    restart: always
    command: ["agent", "-config=/openbao/secrets/openbao/stepca/agent.hcl"]
{depends_on}    environment:
      - VAULT_ADDR={openbao_addr}
    volumes:
      - {secrets_path}:/openbao/secrets
  {responder_service}:
    image: openbao/openbao:latest
    container_name: bootroot-openbao-agent-responder
    restart: always
    command: ["agent", "-config=/openbao/secrets/openbao/responder/agent.hcl"]
{depends_on}    environment:
      - VAULT_ADDR={openbao_addr}
    volumes:
      - {secrets_path}:/openbao/secrets
"#,
        stepca_service = OPENBAO_AGENT_STEPCA_SERVICE,
        responder_service = OPENBAO_AGENT_RESPONDER_SERVICE,
        depends_on = depends_on,
        openbao_addr = openbao_addr,
        secrets_path = mount_root.display()
    );
    tokio::fs::write(&override_path, contents)
        .await
        .with_context(|| messages.error_write_file_failed(&override_path.display().to_string()))?;
    Ok(Some(override_path))
}

fn apply_responder_compose_override(
    compose_file: &Path,
    override_path: &Path,
    messages: &Messages,
) -> Result<()> {
    let args = [
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "-f".to_string(),
        override_path.to_string_lossy().to_string(),
        "up".to_string(),
        "-d".to_string(),
        "bootroot-http01".to_string(),
    ];
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run_docker(&args_ref, "docker compose responder override", messages)?;
    Ok(())
}

fn apply_openbao_agent_compose_override(
    compose_file: &Path,
    override_path: &Path,
    messages: &Messages,
) -> Result<()> {
    let args = [
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "-f".to_string(),
        override_path.to_string_lossy().to_string(),
        "up".to_string(),
        "-d".to_string(),
        OPENBAO_AGENT_STEPCA_SERVICE.to_string(),
        OPENBAO_AGENT_RESPONDER_SERVICE.to_string(),
    ];
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run_docker(&args_ref, "docker compose openbao agent override", messages)?;
    Ok(())
}

async fn bootstrap_openbao(
    client: &mut OpenBaoClient,
    args: &InitArgs,
    messages: &Messages,
) -> Result<InitBootstrap> {
    let (init_response, mut root_token, mut unseal_keys) =
        ensure_openbao_initialized(client, args, messages).await?;

    let seal_status = client
        .seal_status()
        .await
        .with_context(|| messages.error_openbao_seal_status_failed())?;
    if seal_status.sealed {
        if unseal_keys.is_empty() {
            if let Some(path) = args.openbao_unseal_from_file.as_deref() {
                println!("{}", messages.warning_openbao_unseal_from_file());
                let prompt =
                    messages.prompt_openbao_unseal_from_file_confirm(&path.display().to_string());
                confirm_overwrite(&prompt, messages)?;
                unseal_keys = read_unseal_keys_from_file(path, messages)?;
            } else {
                unseal_keys = prompt_unseal_keys(seal_status.t, messages)?;
            }
        }
        unseal_openbao(client, &unseal_keys, messages).await?;
    }

    if root_token.is_none() {
        root_token = Some(prompt_text(messages.prompt_openbao_root_token(), messages)?);
    }
    let root_token =
        root_token.ok_or_else(|| anyhow::anyhow!(messages.error_openbao_root_token_required()))?;

    client.set_token(root_token.clone());

    Ok(InitBootstrap {
        init_response,
        root_token,
        unseal_keys,
    })
}

fn resolve_init_secrets(
    args: &InitArgs,
    messages: &Messages,
    db_dsn: String,
) -> Result<InitSecrets> {
    let stepca_password = resolve_secret(
        messages.prompt_stepca_password(),
        args.stepca_password.clone(),
        args.auto_generate,
        messages,
    )?;
    let http_hmac = resolve_secret(
        messages.prompt_http_hmac(),
        args.http_hmac.clone(),
        args.auto_generate,
        messages,
    )?;
    let eab = resolve_eab(args, messages)?;

    Ok(InitSecrets {
        stepca_password,
        db_dsn,
        http_hmac,
        eab,
    })
}

async fn configure_openbao(
    client: &OpenBaoClient,
    args: &InitArgs,
    secrets: &InitSecrets,
    rollback: &mut InitRollback,
    messages: &Messages,
) -> Result<(
    Vec<AppRoleOutput>,
    BTreeMap<String, String>,
    BTreeMap<String, String>,
)> {
    client
        .ensure_kv_v2(&args.openbao.kv_mount)
        .await
        .with_context(|| messages.error_openbao_kv_mount_failed())?;
    client
        .ensure_approle_auth()
        .await
        .with_context(|| messages.error_openbao_approle_auth_failed())?;

    let policies = build_policy_map(&args.openbao.kv_mount);
    for (name, policy) in &policies {
        if !client
            .policy_exists(name)
            .await
            .with_context(|| messages.error_openbao_policy_exists_failed())?
        {
            rollback.created_policies.push(name.clone());
        }
        client
            .write_policy(name, policy)
            .await
            .with_context(|| messages.error_openbao_policy_write_failed())?;
    }

    let approles = build_approle_map();
    for (label, role_name) in &approles {
        let policy_name = match label.as_str() {
            "bootroot_agent" => POLICY_BOOTROOT_AGENT,
            "responder" => POLICY_BOOTROOT_RESPONDER,
            "stepca" => POLICY_BOOTROOT_STEPCA,
            _ => continue,
        };
        if !client
            .approle_exists(role_name)
            .await
            .with_context(|| messages.error_openbao_approle_exists_failed())?
        {
            rollback.created_approles.push(role_name.clone());
        }
        client
            .create_approle(
                role_name,
                &[policy_name.to_string()],
                TOKEN_TTL,
                SECRET_ID_TTL,
                true,
            )
            .await
            .with_context(|| messages.error_openbao_approle_create_failed())?;
    }

    let mut role_outputs = Vec::new();
    for (label, role_name) in &approles {
        let role_id = client
            .read_role_id(role_name)
            .await
            .with_context(|| messages.error_openbao_role_id_failed())?;
        let secret_id = client
            .create_secret_id(role_name)
            .await
            .with_context(|| messages.error_openbao_secret_id_failed())?;
        role_outputs.push(AppRoleOutput {
            label: label.clone(),
            role_name: role_name.clone(),
            role_id,
            secret_id,
        });
    }

    let mut kv_paths = vec![PATH_STEPCA_PASSWORD, PATH_STEPCA_DB, PATH_RESPONDER_HMAC];
    if secrets.eab.is_some() {
        kv_paths.push(PATH_AGENT_EAB);
    }
    for path in kv_paths {
        if !client
            .kv_exists(&args.openbao.kv_mount, path)
            .await
            .with_context(|| messages.error_openbao_kv_exists_failed())?
        {
            rollback.written_kv_paths.push(path.to_string());
        }
    }

    write_openbao_secrets_with_retry(client, &args.openbao.kv_mount, secrets, messages).await?;

    Ok((role_outputs, policies, approles))
}

async fn write_openbao_secrets_with_retry(
    client: &OpenBaoClient,
    kv_mount: &str,
    secrets: &InitSecrets,
    messages: &Messages,
) -> Result<()> {
    let attempt = write_openbao_secrets(
        client,
        kv_mount,
        &secrets.stepca_password,
        &secrets.db_dsn,
        &secrets.http_hmac,
        secrets.eab.as_ref(),
        messages,
    )
    .await;
    if let Err(err) = attempt {
        let message = err.to_string();
        if message.contains("No secret engine mount") {
            client
                .ensure_kv_v2(kv_mount)
                .await
                .with_context(|| messages.error_openbao_kv_mount_failed())?;
            write_openbao_secrets(
                client,
                kv_mount,
                &secrets.stepca_password,
                &secrets.db_dsn,
                &secrets.http_hmac,
                secrets.eab.as_ref(),
                messages,
            )
            .await?;
        } else {
            return Err(err);
        }
    }
    Ok(())
}

async fn write_ca_trust_fingerprints_with_retry(
    client: &OpenBaoClient,
    kv_mount: &str,
    secrets_dir: &Path,
    rollback: &mut InitRollback,
    messages: &Messages,
) -> Result<bool> {
    let fingerprints = compute_ca_fingerprints(secrets_dir, messages).await?;
    let ca_bundle_pem = compute_ca_bundle_pem(secrets_dir, messages).await?;
    let kv_exists = client
        .kv_exists(kv_mount, PATH_CA_TRUST)
        .await
        .with_context(|| messages.error_openbao_kv_exists_failed())?;
    if !kv_exists {
        rollback.written_kv_paths.push(PATH_CA_TRUST.to_string());
    }
    let current_trust = if kv_exists {
        Some(
            client
                .read_kv(kv_mount, PATH_CA_TRUST)
                .await
                .with_context(|| messages.error_openbao_kv_read_failed())?,
        )
    } else {
        None
    };
    let changed = trust_payload_changed(current_trust.as_ref(), &fingerprints, &ca_bundle_pem);
    let attempt = client
        .write_kv(
            kv_mount,
            PATH_CA_TRUST,
            serde_json::json!({ CA_TRUST_KEY: fingerprints, "ca_bundle_pem": ca_bundle_pem }),
        )
        .await;
    if let Err(err) = attempt {
        let message = err.to_string();
        if message.contains("No secret engine mount") {
            client
                .ensure_kv_v2(kv_mount)
                .await
                .with_context(|| messages.error_openbao_kv_mount_failed())?;
            client
                .write_kv(
                    kv_mount,
                    PATH_CA_TRUST,
                    serde_json::json!({ CA_TRUST_KEY: fingerprints, "ca_bundle_pem": ca_bundle_pem }),
                )
                .await
                .with_context(|| messages.error_openbao_kv_write_failed())?;
        } else {
            return Err(err).with_context(|| messages.error_openbao_kv_write_failed());
        }
    }
    Ok(changed)
}

async fn compute_ca_fingerprints(secrets_dir: &Path, messages: &Messages) -> Result<Vec<String>> {
    let certs_dir = secrets_dir.join(CA_CERTS_DIR);
    let root_path = certs_dir.join(CA_ROOT_CERT_FILENAME);
    let intermediate_path = certs_dir.join(CA_INTERMEDIATE_CERT_FILENAME);
    let root = read_ca_cert_fingerprint(&root_path, messages).await?;
    let intermediate = read_ca_cert_fingerprint(&intermediate_path, messages).await?;
    Ok(vec![root, intermediate])
}

async fn compute_ca_bundle_pem(secrets_dir: &Path, messages: &Messages) -> Result<String> {
    let certs_dir = secrets_dir.join(CA_CERTS_DIR);
    let root_path = certs_dir.join(CA_ROOT_CERT_FILENAME);
    let intermediate_path = certs_dir.join(CA_INTERMEDIATE_CERT_FILENAME);
    let root = tokio::fs::read_to_string(&root_path)
        .await
        .with_context(|| messages.error_read_file_failed(&root_path.display().to_string()))?;
    let intermediate = tokio::fs::read_to_string(&intermediate_path)
        .await
        .with_context(|| {
            messages.error_read_file_failed(&intermediate_path.display().to_string())
        })?;
    Ok(format!("{root}{intermediate}"))
}

fn trust_payload_changed(
    current: Option<&serde_json::Value>,
    fingerprints: &[String],
    ca_bundle_pem: &str,
) -> bool {
    let Some(current) = current else {
        return true;
    };
    let current_fingerprints = current
        .get(CA_TRUST_KEY)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        });
    let current_bundle = current
        .get("ca_bundle_pem")
        .and_then(serde_json::Value::as_str);
    current_fingerprints.as_deref() != Some(fingerprints) || current_bundle != Some(ca_bundle_pem)
}

async fn read_ca_cert_fingerprint(path: &Path, messages: &Messages) -> Result<String> {
    if !path.exists() {
        anyhow::bail!(messages.error_ca_cert_missing(&path.display().to_string()));
    }
    let contents = tokio::fs::read(path)
        .await
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let (_, pem) = parse_x509_pem(&contents).map_err(|_| {
        anyhow::anyhow!(messages.error_ca_cert_parse_failed(&path.display().to_string()))
    })?;
    if pem.label != "CERTIFICATE" {
        anyhow::bail!(messages.error_ca_cert_parse_failed(&path.display().to_string()));
    }
    Ok(sha256_hex(&pem.contents))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, bytes);
    let mut output = String::with_capacity(64);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

async fn ensure_openbao_initialized(
    client: &OpenBaoClient,
    args: &InitArgs,
    messages: &Messages,
) -> Result<(Option<InitResponse>, Option<String>, Vec<String>)> {
    let initialized = client
        .is_initialized()
        .await
        .with_context(|| messages.error_openbao_init_status_failed())?;
    if initialized {
        return Ok((
            None,
            args.root_token.root_token.clone(),
            args.unseal_key.clone(),
        ));
    }

    let response = client
        .init(INIT_SECRET_SHARES, INIT_SECRET_THRESHOLD)
        .await
        .with_context(|| messages.error_openbao_init_failed())?;
    let root_token = response.root_token.clone();
    let keys = if response.keys.is_empty() {
        response.keys_base64.clone()
    } else {
        response.keys.clone()
    };
    Ok((Some(response), Some(root_token), keys))
}

async fn unseal_openbao(
    client: &OpenBaoClient,
    keys: &[String],
    messages: &Messages,
) -> Result<()> {
    for key in keys {
        let status = client
            .unseal(key)
            .await
            .with_context(|| messages.error_openbao_unseal_failed())?;
        if !status.sealed {
            return Ok(());
        }
    }
    let status = client
        .seal_status()
        .await
        .with_context(|| messages.error_openbao_seal_status_failed())?;
    if status.sealed {
        anyhow::bail!(messages.error_openbao_sealed());
    }
    Ok(())
}

fn prompt_unseal_keys(threshold: Option<u32>, messages: &Messages) -> Result<Vec<String>> {
    let count = match threshold {
        Some(value) if value > 0 => value,
        _ => {
            let input = prompt_text(messages.prompt_unseal_threshold(), messages)?;
            input
                .parse::<u32>()
                .context(messages.error_invalid_unseal_threshold())?
        }
    };
    let mut keys = Vec::with_capacity(count as usize);
    for index in 1..=count {
        let key = prompt_text(&messages.prompt_unseal_key(index, count), messages)?;
        keys.push(key);
    }
    Ok(keys)
}

fn prompt_text(prompt: &str, messages: &Messages) -> Result<String> {
    use std::io::{self, Write};
    // codeql[rust/cleartext-logging]: prompt text is non-secret UI output.
    print!("{prompt}");
    io::stdout()
        .flush()
        .with_context(|| messages.error_prompt_flush_failed())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .with_context(|| messages.error_prompt_read_failed())?;
    Ok(input.trim().to_string())
}

fn prompt_text_with_default(prompt: &str, default: &str, messages: &Messages) -> Result<String> {
    let input = prompt_text(prompt, messages)?;
    if input.trim().is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

fn prompt_yes_no(prompt: &str, messages: &Messages) -> Result<bool> {
    let input = prompt_text(prompt, messages)?;
    let trimmed = input.trim().to_ascii_lowercase();
    Ok(trimmed == "y" || trimmed == "yes")
}

fn confirm_overwrite(prompt: &str, messages: &Messages) -> Result<()> {
    if prompt_yes_no(prompt, messages)? {
        return Ok(());
    }
    anyhow::bail!(messages.error_operation_cancelled());
}

fn resolve_secret(
    label: &str,
    value: Option<String>,
    auto_generate: bool,
    messages: &Messages,
) -> Result<String> {
    if let Some(value) = value {
        return Ok(value);
    }
    if auto_generate {
        return generate_secret(messages);
    }
    prompt_text(&format!("{label}: "), messages)
}

fn resolve_eab(args: &InitArgs, messages: &Messages) -> Result<Option<EabCredentials>> {
    match (&args.eab_kid, &args.eab_hmac) {
        (Some(kid), Some(hmac)) => Ok(Some(EabCredentials {
            kid: kid.clone(),
            hmac: hmac.clone(),
        })),
        (None, None) => Ok(None),
        _ => anyhow::bail!(messages.error_eab_requires_both()),
    }
}

async fn verify_responder(
    responder_url: Option<&str>,
    args: &InitArgs,
    messages: &Messages,
    secrets: &InitSecrets,
) -> Result<ResponderCheck> {
    if args.skip_responder_check {
        return Ok(ResponderCheck::Skipped);
    }
    let Some(responder_url) = responder_url else {
        return Ok(ResponderCheck::Skipped);
    };
    responder_client::register_http01_token_with(
        responder_url,
        &secrets.http_hmac,
        args.responder_timeout_secs,
        "bootroot-init-check",
        "bootroot-init-check.key",
        DEFAULT_RESPONDER_TOKEN_TTL_SECS,
    )
    .await
    .with_context(|| messages.error_responder_check_failed())?;
    Ok(ResponderCheck::Ok)
}

fn find_role_output<'a>(
    role_outputs: &'a [AppRoleOutput],
    label: &str,
    messages: &Messages,
) -> Result<&'a AppRoleOutput> {
    role_outputs
        .iter()
        .find(|output| output.label == label)
        .ok_or_else(|| anyhow::anyhow!(messages.error_openbao_role_output_missing(label)))
}

async fn check_db_connectivity(
    db: &DbDsn,
    dsn: &str,
    timeout_secs: u64,
    messages: &Messages,
) -> Result<()> {
    let timeout = Duration::from_secs(timeout_secs);
    check_tcp(&db.host, db.port, timeout)
        .await
        .with_context(|| messages.error_db_check_failed())?;
    let dsn_value = dsn.to_string();
    tokio::task::spawn_blocking(move || check_auth_sync(&dsn_value, timeout))
        .await
        .with_context(|| messages.error_db_auth_task_failed())?
        .with_context(|| messages.error_db_auth_failed())?;
    Ok(())
}

async fn maybe_register_eab(
    client: &OpenBaoClient,
    args: &InitArgs,
    messages: &Messages,
    rollback: &mut InitRollback,
    secrets: &InitSecrets,
) -> Result<Option<EabCredentials>> {
    if secrets.eab.is_some() {
        return Ok(None);
    }
    if args.eab_auto {
        let credentials = issue_eab_via_stepca(args, messages)
            .await
            .with_context(|| messages.error_eab_auto_failed())?;
        register_eab_secret(
            client,
            &args.openbao.kv_mount,
            rollback,
            &credentials,
            messages,
        )
        .await?;
        return Ok(Some(credentials));
    }
    if !prompt_yes_no(messages.prompt_eab_register_now(), messages)? {
        return Ok(None);
    }
    if prompt_yes_no(messages.prompt_eab_auto_now(), messages)? {
        let credentials = issue_eab_via_stepca(args, messages)
            .await
            .with_context(|| messages.error_eab_auto_failed())?;
        register_eab_secret(
            client,
            &args.openbao.kv_mount,
            rollback,
            &credentials,
            messages,
        )
        .await?;
        return Ok(Some(credentials));
    }
    println!("{}", messages.eab_prompt_instructions());
    let kid = prompt_text(messages.prompt_eab_kid(), messages)?;
    let hmac = prompt_text(messages.prompt_eab_hmac(), messages)?;
    let credentials = EabCredentials { kid, hmac };
    register_eab_secret(
        client,
        &args.openbao.kv_mount,
        rollback,
        &credentials,
        messages,
    )
    .await?;
    Ok(Some(credentials))
}

async fn register_eab_secret(
    client: &OpenBaoClient,
    kv_mount: &str,
    rollback: &mut InitRollback,
    credentials: &EabCredentials,
    messages: &Messages,
) -> Result<()> {
    if !client
        .kv_exists(kv_mount, PATH_AGENT_EAB)
        .await
        .with_context(|| messages.error_openbao_kv_exists_failed())?
    {
        rollback.written_kv_paths.push(PATH_AGENT_EAB.to_string());
    }
    client
        .write_kv(
            kv_mount,
            PATH_AGENT_EAB,
            serde_json::json!({ "kid": credentials.kid, "hmac": credentials.hmac }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    Ok(())
}

async fn issue_eab_via_stepca(args: &InitArgs, messages: &Messages) -> Result<EabCredentials> {
    let base = args.stepca_url.trim_end_matches('/');
    let provisioner = args.stepca_provisioner.trim();
    let endpoint = format!("{base}/acme/{provisioner}/{DEFAULT_EAB_ENDPOINT_PATH}");
    let client = reqwest::Client::new();

    let response = client
        .post(&endpoint)
        .send()
        .await
        .with_context(|| messages.error_eab_request_failed())?;
    let response = if response.status() == StatusCode::METHOD_NOT_ALLOWED {
        client
            .get(&endpoint)
            .send()
            .await
            .with_context(|| messages.error_eab_request_failed())?
    } else {
        response
    };
    let response = response
        .error_for_status()
        .with_context(|| messages.error_eab_request_failed())?;

    let payload: EabAutoResponse = response
        .json()
        .await
        .with_context(|| messages.error_eab_response_parse_failed())?;
    Ok(EabCredentials {
        kid: payload.kid,
        hmac: payload.hmac,
    })
}

fn normalize_db_host_for_compose_runtime(host: &str, messages: &Messages) -> Result<String> {
    if host.eq_ignore_ascii_case(DB_COMPOSE_HOST) {
        return Ok(DB_COMPOSE_HOST.to_string());
    }
    if host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1" {
        return Ok(DB_COMPOSE_HOST.to_string());
    }
    if is_single_host_db_host(host) {
        return Ok(host.to_string());
    }
    anyhow::bail!(messages.error_db_host_compose_runtime(host, DB_COMPOSE_HOST));
}

async fn resolve_db_dsn_for_init(
    args: &InitArgs,
    messages: &Messages,
) -> Result<(String, DbDsnNormalization)> {
    if args.db_provision && args.db_dsn.is_some() {
        anyhow::bail!(messages.error_db_provision_conflict());
    }
    if args.db_provision {
        let inputs = resolve_db_provision_inputs(args, messages)?;
        let admin = parse_db_dsn(&inputs.admin_dsn)
            .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
        let effective_host = normalize_db_host_for_compose_runtime(&admin.host, messages)?;
        let dsn = build_db_dsn(
            &inputs.db_user,
            &inputs.db_password,
            &effective_host,
            admin.port,
            &inputs.db_name,
            admin.sslmode.as_deref(),
        );
        let timeout = Duration::from_secs(args.db_timeout.timeout_secs);
        tokio::task::spawn_blocking(move || {
            provision_db_sync(
                &inputs.admin_dsn,
                &inputs.db_user,
                &inputs.db_password,
                &inputs.db_name,
                timeout,
            )
        })
        .await
        .with_context(|| messages.error_db_provision_task_failed())??;
        return Ok((
            dsn,
            DbDsnNormalization {
                original_host: admin.host,
                effective_host,
            },
        ));
    }
    let dsn = resolve_db_dsn(args, messages)?;
    let parsed =
        parse_db_dsn(&dsn).map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
    let effective_host = normalize_db_host_for_compose_runtime(&parsed.host, messages)?;
    let effective_dsn = if parsed.host == effective_host {
        dsn
    } else {
        build_db_dsn(
            &parsed.user,
            &parsed.password,
            &effective_host,
            parsed.port,
            &parsed.database,
            parsed.sslmode.as_deref(),
        )
    };
    Ok((
        effective_dsn,
        DbDsnNormalization {
            original_host: parsed.host,
            effective_host,
        },
    ))
}

#[derive(Debug)]
struct DbProvisionInputs {
    admin_dsn: String,
    db_user: String,
    db_password: String,
    db_name: String,
}

fn resolve_db_provision_inputs(args: &InitArgs, messages: &Messages) -> Result<DbProvisionInputs> {
    let admin_dsn = if let Some(value) = args.db_admin.admin_dsn.clone() {
        value
    } else if let Some(value) = build_admin_dsn_from_env() {
        value
    } else {
        prompt_text(&format!("{}: ", messages.prompt_db_admin_dsn()), messages)?
    };
    let default_db_name = args
        .db_name
        .clone()
        .or_else(|| env::var("POSTGRES_DB").ok())
        .unwrap_or_else(|| DEFAULT_DB_NAME.to_string());
    let db_user = if let Some(value) = args.db_user.clone() {
        value
    } else {
        let prompt = format!("{} [{}]: ", messages.prompt_db_user(), DEFAULT_DB_USER);
        prompt_text_with_default(&prompt, DEFAULT_DB_USER, messages)?
    };
    let db_name = if let Some(value) = args.db_name.clone() {
        value
    } else {
        let prompt = format!("{} [{}]: ", messages.prompt_db_name(), default_db_name);
        prompt_text_with_default(&prompt, &default_db_name, messages)?
    };
    let db_password = if let Some(value) = args.db_password.clone() {
        value
    } else if args.auto_generate {
        generate_secret(messages)?
    } else {
        prompt_text(&format!("{}: ", messages.prompt_db_password()), messages)?
    };

    validate_db_identifier(&db_user)
        .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_identifier(&db_user)))?;
    validate_db_identifier(&db_name)
        .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_identifier(&db_name)))?;

    Ok(DbProvisionInputs {
        admin_dsn,
        db_user,
        db_password,
        db_name,
    })
}

fn build_admin_dsn_from_env() -> Option<String> {
    let Ok(user) = env::var("POSTGRES_USER") else {
        return None;
    };
    let Ok(password) = env::var("POSTGRES_PASSWORD") else {
        return None;
    };
    let host = env::var("POSTGRES_HOST").unwrap_or_else(|_| "postgres".to_string());
    let port = env::var("POSTGRES_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(5432);
    let db = env::var("POSTGRES_DB").unwrap_or_else(|_| "postgres".to_string());
    let sslmode = env::var("POSTGRES_SSLMODE").ok();
    Some(build_db_dsn(
        &user,
        &password,
        &host,
        port,
        &db,
        sslmode.as_deref(),
    ))
}

fn resolve_db_dsn(args: &InitArgs, messages: &Messages) -> Result<String> {
    if let Some(dsn) = args.db_dsn.clone() {
        return Ok(dsn);
    }
    if let Some(dsn) = build_dsn_from_env() {
        return Ok(dsn);
    }
    prompt_text(&format!("{}: ", messages.prompt_db_dsn()), messages)
}

fn build_dsn_from_env() -> Option<String> {
    let Ok(user) = env::var("POSTGRES_USER") else {
        return None;
    };
    let Ok(password) = env::var("POSTGRES_PASSWORD") else {
        return None;
    };
    let Ok(db) = env::var("POSTGRES_DB") else {
        return None;
    };
    let host = env::var("POSTGRES_HOST").unwrap_or_else(|_| "postgres".to_string());
    let port = env::var("POSTGRES_PORT").unwrap_or_else(|_| "5432".to_string());
    let dsn = format!("postgresql://{user}:{password}@{host}:{port}/{db}?sslmode=disable");
    Some(dsn)
}

fn generate_secret(messages: &Messages) -> Result<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::{SecureRandom, SystemRandom};

    let mut buffer = vec![0u8; SECRET_BYTES];
    let rng = SystemRandom::new();
    rng.fill(&mut buffer)
        .map_err(|_| anyhow::anyhow!(messages.error_generate_secret_failed()))?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

fn build_policy_map(kv_mount: &str) -> BTreeMap<String, String> {
    let mut policies = BTreeMap::new();
    policies.insert(
        POLICY_BOOTROOT_AGENT.to_string(),
        format!(
            r#"path "{kv_mount}/data/{PATH_AGENT_EAB}" {{
  capabilities = ["read"]
}}
path "{kv_mount}/data/{PATH_RESPONDER_HMAC}" {{
  capabilities = ["read"]
}}
"#
        ),
    );
    policies.insert(
        POLICY_BOOTROOT_RESPONDER.to_string(),
        format!(
            r#"path "{kv_mount}/data/{PATH_RESPONDER_HMAC}" {{
  capabilities = ["read"]
}}
"#
        ),
    );
    policies.insert(
        POLICY_BOOTROOT_STEPCA.to_string(),
        format!(
            r#"path "{kv_mount}/data/{PATH_STEPCA_PASSWORD}" {{
  capabilities = ["read"]
}}
path "{kv_mount}/data/{PATH_STEPCA_DB}" {{
  capabilities = ["read"]
}}
"#
        ),
    );
    policies
}

fn build_approle_map() -> BTreeMap<String, String> {
    let mut approles = BTreeMap::new();
    approles.insert(
        "bootroot_agent".to_string(),
        APPROLE_BOOTROOT_AGENT.to_string(),
    );
    approles.insert(
        "responder".to_string(),
        APPROLE_BOOTROOT_RESPONDER.to_string(),
    );
    approles.insert("stepca".to_string(), APPROLE_BOOTROOT_STEPCA.to_string());
    approles
}

async fn write_openbao_secrets(
    client: &OpenBaoClient,
    kv_mount: &str,
    stepca_password: &str,
    db_dsn: &str,
    http_hmac: &str,
    eab: Option<&EabCredentials>,
    messages: &Messages,
) -> Result<()> {
    client
        .write_kv(
            kv_mount,
            PATH_STEPCA_PASSWORD,
            serde_json::json!({ "value": stepca_password }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    client
        .write_kv(
            kv_mount,
            PATH_STEPCA_DB,
            serde_json::json!({ "dsn": db_dsn }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    client
        .write_kv(
            kv_mount,
            PATH_RESPONDER_HMAC,
            serde_json::json!({ "value": http_hmac }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    if let Some(eab) = eab {
        client
            .write_kv(
                kv_mount,
                PATH_AGENT_EAB,
                serde_json::json!({ "kid": eab.kid, "hmac": eab.hmac }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }
    Ok(())
}

async fn write_password_file_with_backup(
    secrets_dir: &Path,
    password: &str,
    messages: &Messages,
) -> Result<RollbackFile> {
    fs_util::ensure_secrets_dir(secrets_dir).await?;
    let password_path = secrets_dir.join("password.txt");
    let original = match tokio::fs::read_to_string(&password_path).await {
        Ok(contents) => Some(contents),
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| {
                messages.error_read_file_failed(&password_path.display().to_string())
            });
        }
    };
    tokio::fs::write(&password_path, password)
        .await
        .with_context(|| messages.error_write_file_failed(&password_path.display().to_string()))?;
    fs_util::set_key_permissions(&password_path).await?;
    Ok(RollbackFile {
        path: password_path,
        original,
    })
}

async fn update_ca_json_with_backup(
    secrets_dir: &Path,
    db_dsn: &str,
    messages: &Messages,
) -> Result<RollbackFile> {
    let path = secrets_dir.join("config").join("ca.json");
    let contents = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&contents).context(messages.error_parse_ca_json_failed())?;
    value["db"]["type"] = serde_json::Value::String("postgresql".to_string());
    value["db"]["dataSource"] = serde_json::Value::String(db_dsn.to_string());
    let updated =
        serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())?;
    tokio::fs::write(&path, updated)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(RollbackFile {
        path,
        original: Some(contents),
    })
}

fn ensure_step_ca_initialized(secrets_dir: &Path, messages: &Messages) -> Result<StepCaInitResult> {
    let config_path = secrets_dir.join("config").join("ca.json");
    let ca_key = secrets_dir.join("secrets").join("root_ca_key");
    let intermediate_key = secrets_dir.join("secrets").join("intermediate_ca_key");
    if config_path.exists() && ca_key.exists() && intermediate_key.exists() {
        return Ok(StepCaInitResult::Skipped);
    }

    let password_path = secrets_dir.join("password.txt");
    if !password_path.exists() {
        anyhow::bail!(messages.error_stepca_password_missing(&password_path.display().to_string()));
    }
    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let mount = format!("{}:/home/step", mount_root.display());
    let args = vec![
        "run".to_string(),
        "--user".to_string(),
        "root".to_string(),
        "--rm".to_string(),
        "-v".to_string(),
        mount,
        "smallstep/step-ca".to_string(),
        "step".to_string(),
        "ca".to_string(),
        "init".to_string(),
        "--name".to_string(),
        DEFAULT_CA_NAME.to_string(),
        "--provisioner".to_string(),
        DEFAULT_CA_PROVISIONER.to_string(),
        "--dns".to_string(),
        DEFAULT_CA_DNS.to_string(),
        "--address".to_string(),
        DEFAULT_CA_ADDRESS.to_string(),
        "--password-file".to_string(),
        "/home/step/password.txt".to_string(),
        "--provisioner-password-file".to_string(),
        "/home/step/password.txt".to_string(),
        "--acme".to_string(),
    ];
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run_docker(&args_ref, "docker step-ca init", messages)?;
    Ok(StepCaInitResult::Initialized)
}

fn write_state_file(
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
    let policy_map = [
        (
            "bootroot_agent".to_string(),
            POLICY_BOOTROOT_AGENT.to_string(),
        ),
        (
            "responder".to_string(),
            POLICY_BOOTROOT_RESPONDER.to_string(),
        ),
        ("stepca".to_string(), POLICY_BOOTROOT_STEPCA.to_string()),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
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

fn mark_remote_trust_sync_pending(messages: &Messages) -> Result<()> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        return Ok(());
    }
    mark_remote_trust_sync_pending_at_path(&state_path, messages)?;
    Ok(())
}

fn mark_remote_trust_sync_pending_at_path(state_path: &Path, messages: &Messages) -> Result<bool> {
    let mut state =
        StateFile::load(state_path).with_context(|| messages.error_parse_state_failed())?;
    let mut changed = false;
    for entry in state
        .services
        .values_mut()
        .filter(|entry| matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap))
    {
        if entry.sync_status.trust_sync != SyncApplyStatus::Pending {
            entry.sync_status.trust_sync = SyncApplyStatus::Pending;
            changed = true;
        }
    }
    if changed {
        state
            .save(state_path)
            .with_context(|| messages.error_serialize_state_failed())?;
    }
    Ok(changed)
}

#[derive(Debug)]
struct RollbackFile {
    path: PathBuf,
    original: Option<String>,
}

#[derive(Default)]
struct InitRollback {
    created_policies: Vec<String>,
    created_approles: Vec<String>,
    written_kv_paths: Vec<String>,
    password_backup: Option<RollbackFile>,
    ca_json_backup: Option<RollbackFile>,
}

impl InitRollback {
    async fn rollback(&self, client: &OpenBaoClient, kv_mount: &str, messages: &Messages) {
        for path in &self.written_kv_paths {
            if let Err(err) = client.delete_kv(kv_mount, path).await {
                eprintln!(
                    "{}: {path}: {err}",
                    messages.error_openbao_kv_delete_failed()
                );
            }
        }
        for role in &self.created_approles {
            if let Err(err) = client.delete_approle(role).await {
                eprintln!("Rollback: failed to delete AppRole {role}: {err}");
            }
        }
        for policy in &self.created_policies {
            if let Err(err) = client.delete_policy(policy).await {
                eprintln!("Rollback: failed to delete policy {policy}: {err}");
            }
        }
        if let Some(file) = &self.password_backup
            && let Err(err) = rollback_file(file, messages)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
        }
        if let Some(file) = &self.ca_json_backup
            && let Err(err) = rollback_file(file, messages)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
        }
    }
}

fn rollback_file(file: &RollbackFile, messages: &Messages) -> Result<()> {
    if let Some(contents) = &file.original {
        std::fs::write(&file.path, contents).with_context(|| {
            messages.error_restore_file_failed(&file.path.display().to_string())
        })?;
    } else if file.path.exists() {
        std::fs::remove_file(&file.path)
            .with_context(|| messages.error_remove_file_failed(&file.path.display().to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use tempfile::tempdir;

    use super::super::constants::{
        DEFAULT_RESPONDER_ADMIN_URL, DEFAULT_STEPCA_PROVISIONER, DEFAULT_STEPCA_URL,
    };
    use super::*;
    use crate::i18n::Messages;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    fn default_init_args() -> InitArgs {
        InitArgs {
            openbao: crate::cli::args::OpenBaoArgs {
                openbao_url: "http://localhost:8200".to_string(),
                kv_mount: "secret".to_string(),
            },
            secrets_dir: crate::cli::args::SecretsDirArgs {
                secrets_dir: PathBuf::from("secrets"),
            },
            compose: crate::cli::args::ComposeFileArgs {
                compose_file: PathBuf::from("docker-compose.yml"),
            },
            auto_generate: false,
            show_secrets: false,
            root_token: crate::cli::args::RootTokenArgs { root_token: None },
            unseal_key: Vec::new(),
            openbao_unseal_from_file: None,
            stepca_password: None,
            db_dsn: None,
            db_provision: false,
            db_admin: crate::cli::args::DbAdminDsnArgs { admin_dsn: None },
            db_user: None,
            db_password: None,
            db_name: None,
            db_check: false,
            db_timeout: crate::cli::args::DbTimeoutArgs { timeout_secs: 2 },
            http_hmac: None,
            responder_url: None,
            skip_responder_check: false,
            responder_timeout_secs: 5,
            eab_auto: false,
            stepca_url: DEFAULT_STEPCA_URL.to_string(),
            stepca_provisioner: DEFAULT_STEPCA_PROVISIONER.to_string(),
            eab_kid: None,
            eab_hmac: None,
        }
    }

    fn test_messages() -> Messages {
        Messages::new("en").expect("valid language")
    }

    #[test]
    fn test_resolve_secret_prefers_value() {
        let messages = test_messages();
        let value = resolve_secret(
            "step-ca password",
            Some("value".to_string()),
            false,
            &messages,
        )
        .unwrap();
        assert_eq!(value, "value");
    }

    #[test]
    fn test_compute_ca_fingerprints_reads_cert_files() {
        let dir = tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        let certs_dir = secrets_dir.join(CA_CERTS_DIR);
        fs::create_dir_all(&certs_dir).expect("create certs");

        let root = test_cert_pem("root.example");
        let intermediate = test_cert_pem("intermediate.example");
        fs::write(certs_dir.join(CA_ROOT_CERT_FILENAME), root).expect("write root cert");
        fs::write(certs_dir.join(CA_INTERMEDIATE_CERT_FILENAME), intermediate)
            .expect("write intermediate cert");

        let messages = test_messages();
        let fingerprints = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(compute_ca_fingerprints(&secrets_dir, &messages))
            .expect("compute fingerprints");
        assert_eq!(fingerprints.len(), 2);
        for fingerprint in fingerprints {
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.chars().all(|ch| ch.is_ascii_hexdigit()));
        }
    }

    fn test_cert_pem(common_name: &str) -> String {
        let mut params =
            rcgen::CertificateParams::new(vec![common_name.to_string()]).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key).expect("self signed");
        cert.pem()
    }

    #[test]
    fn test_resolve_secret_auto_generates() {
        let messages = test_messages();
        let value = resolve_secret("HTTP-01 HMAC", None, true, &messages).unwrap();
        assert!(!value.is_empty());
    }

    #[test]
    fn test_resolve_db_dsn_prefers_cli() {
        let _guard = env_lock();
        // SAFETY: tests run single-threaded for this scope; vars are restored below.
        unsafe {
            env::set_var("POSTGRES_USER", "envuser");
            env::set_var("POSTGRES_PASSWORD", "envpass");
            env::set_var("POSTGRES_DB", "envdb");
        }
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://cliuser:clipass@localhost/db".to_string());
        let dsn = resolve_db_dsn(&args, &test_messages()).unwrap();
        unsafe {
            env::remove_var("POSTGRES_USER");
            env::remove_var("POSTGRES_PASSWORD");
            env::remove_var("POSTGRES_DB");
        }
        assert_eq!(dsn, "postgresql://cliuser:clipass@localhost/db");
    }

    #[test]
    fn test_resolve_db_dsn_for_init_rejects_remote_host() {
        let _guard = env_lock();
        let mut args = default_init_args();
        args.db_dsn =
            Some("postgresql://user:pass@db.internal:5432/stepca?sslmode=disable".to_string());

        let err = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(&args, &test_messages()))
            .expect_err("remote db host should fail single-host guardrail");
        assert!(
            err.to_string()
                .contains("not reachable from step-ca container")
        );
    }

    #[test]
    fn test_resolve_db_dsn_for_init_normalizes_localhost_to_postgres() {
        let _guard = env_lock();
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://user:pass@localhost:5432/stepca".to_string());

        let (dsn, normalization) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(&args, &test_messages()))
            .expect("dsn should resolve");
        assert_eq!(
            dsn,
            "postgresql://user:pass@postgres:5432/stepca?sslmode=disable"
        );
        assert_eq!(normalization.original_host, "localhost");
        assert_eq!(normalization.effective_host, "postgres");
    }

    #[test]
    fn test_resolve_db_dsn_for_init_keeps_postgres_host() {
        let _guard = env_lock();
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://user:pass@postgres:5432/stepca".to_string());

        let (dsn, normalization) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(&args, &test_messages()))
            .expect("dsn should resolve");
        assert_eq!(dsn, "postgresql://user:pass@postgres:5432/stepca");
        assert_eq!(normalization.original_host, "postgres");
        assert_eq!(normalization.effective_host, "postgres");
    }

    #[test]
    fn test_normalize_db_host_for_compose_runtime_localhost() {
        let normalized =
            normalize_db_host_for_compose_runtime("127.0.0.1", &test_messages()).unwrap();
        assert_eq!(normalized, "postgres");
    }

    #[test]
    fn test_resolve_db_dsn_uses_env() {
        let _guard = env_lock();
        // SAFETY: tests run single-threaded for this scope; vars are restored below.
        unsafe {
            env::set_var("POSTGRES_USER", "step");
            env::set_var("POSTGRES_PASSWORD", "secret");
            env::set_var("POSTGRES_DB", "stepca");
            env::set_var("POSTGRES_HOST", "postgres");
            env::set_var("POSTGRES_PORT", "5432");
        }
        let args = default_init_args();
        let dsn = resolve_db_dsn(&args, &test_messages()).unwrap();
        unsafe {
            env::remove_var("POSTGRES_USER");
            env::remove_var("POSTGRES_PASSWORD");
            env::remove_var("POSTGRES_DB");
            env::remove_var("POSTGRES_HOST");
            env::remove_var("POSTGRES_PORT");
        }
        assert_eq!(
            dsn,
            "postgresql://step:secret@postgres:5432/stepca?sslmode=disable"
        );
    }

    #[test]
    fn test_resolve_db_provision_inputs_with_args() {
        let _guard = env_lock();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let admin_password = format!("admin-{nonce}");
        let db_password = format!("step-{nonce}");
        let mut args = default_init_args();
        args.db_provision = true;
        args.db_admin.admin_dsn = Some(format!(
            "postgresql://admin:{admin_password}@localhost:5432/postgres?sslmode=disable"
        ));
        args.db_user = Some("stepuser".to_string());
        args.db_password = Some(db_password.clone());
        args.db_name = Some("stepdb".to_string());

        let inputs = resolve_db_provision_inputs(&args, &test_messages()).unwrap();
        assert_eq!(
            inputs.admin_dsn,
            format!("postgresql://admin:{admin_password}@localhost:5432/postgres?sslmode=disable")
        );
        assert_eq!(inputs.db_user, "stepuser");
        assert_eq!(inputs.db_password, db_password);
        assert_eq!(inputs.db_name, "stepdb");
    }

    #[test]
    fn test_resolve_db_provision_inputs_rejects_invalid_identifier() {
        let _guard = env_lock();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let admin_password = format!("admin-{nonce}");
        let db_password = format!("step-{nonce}");
        let mut args = default_init_args();
        args.db_provision = true;
        args.db_admin.admin_dsn = Some(format!(
            "postgresql://admin:{admin_password}@localhost:5432/postgres?sslmode=disable"
        ));
        args.db_user = Some("bad-name".to_string());
        args.db_password = Some(db_password);
        args.db_name = Some("stepdb".to_string());

        let err = resolve_db_provision_inputs(&args, &test_messages()).unwrap_err();
        assert!(err.to_string().contains("Invalid DB identifier"));
    }

    #[test]
    fn test_resolve_db_dsn_for_init_rejects_conflict() {
        let _guard = env_lock();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let admin_password = format!("admin-{nonce}");
        let db_password = format!("step-{nonce}");
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://user:pass@localhost/db".to_string());
        args.db_provision = true;
        args.db_admin.admin_dsn = Some(format!(
            "postgresql://admin:{admin_password}@localhost:5432/postgres?sslmode=disable"
        ));
        args.db_user = Some("stepuser".to_string());
        args.db_password = Some(db_password);
        args.db_name = Some("stepdb".to_string());

        let err = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(&args, &test_messages()))
            .unwrap_err();
        assert!(err.to_string().contains("db-provision"));
    }

    #[test]
    fn test_resolve_responder_url_skips_when_missing() {
        let temp_dir = tempdir().unwrap();
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").unwrap();
        let mut args = default_init_args();
        args.compose.compose_file = compose_file;

        let compose_has_responder =
            compose_has_responder(&args.compose.compose_file, &test_messages())
                .expect("compose check");
        let responder_url = resolve_responder_url(&args, compose_has_responder);
        assert!(responder_url.is_none());
    }

    #[test]
    fn test_resolve_responder_url_uses_default_when_present() {
        let temp_dir = tempdir().unwrap();
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(
            &compose_file,
            r"
services:
  bootroot-http01:
    image: bootroot-http01-responder:latest
",
        )
        .unwrap();
        let mut args = default_init_args();
        args.compose.compose_file = compose_file;

        let compose_has_responder =
            compose_has_responder(&args.compose.compose_file, &test_messages())
                .expect("compose check");
        let responder_url = resolve_responder_url(&args, compose_has_responder);
        assert_eq!(responder_url.as_deref(), Some(DEFAULT_RESPONDER_ADMIN_URL));
    }

    #[test]
    fn test_step_ca_init_skips_when_files_present() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(secrets_dir.join("config")).unwrap();
        fs::create_dir_all(secrets_dir.join("secrets")).unwrap();
        fs::write(
            secrets_dir.join("config").join("ca.json"),
            r#"{"db":{"type":"","dataSource":""}}"#,
        )
        .unwrap();
        fs::write(secrets_dir.join("secrets").join("root_ca_key"), "").unwrap();
        fs::write(secrets_dir.join("secrets").join("intermediate_ca_key"), "").unwrap();

        let result = ensure_step_ca_initialized(&secrets_dir, &test_messages()).unwrap();
        assert_eq!(result, StepCaInitResult::Skipped);
    }

    #[tokio::test]
    async fn test_write_responder_files_writes_template_and_config() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");

        let messages = test_messages();
        let paths = write_responder_files(&secrets_dir, "secret", "hmac-123", &messages)
            .await
            .unwrap();
        let template = fs::read_to_string(&paths.template_path).unwrap();
        let config = fs::read_to_string(&paths.config_path).unwrap();

        assert!(template.contains("secret/data/bootroot/responder/hmac"));
        assert!(config.contains("hmac-123"));
    }

    #[tokio::test]
    async fn test_write_responder_compose_override_skips_when_missing_service() {
        let temp_dir = tempdir().unwrap();
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").unwrap();

        let secrets_dir = temp_dir.path().join("secrets");
        let messages = test_messages();
        let paths = write_responder_files(&secrets_dir, "secret", "hmac-123", &messages)
            .await
            .unwrap();

        let override_path = write_responder_compose_override(
            &compose_file,
            &secrets_dir,
            &paths.config_path,
            &messages,
        )
        .await
        .unwrap();

        assert!(override_path.is_none());
    }

    #[tokio::test]
    async fn test_write_responder_compose_override_writes_mount() {
        let temp_dir = tempdir().unwrap();
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(
            &compose_file,
            r"
services:
  bootroot-http01:
    image: bootroot-http01-responder:latest
",
        )
        .unwrap();

        let secrets_dir = temp_dir.path().join("secrets");
        let messages = test_messages();
        let paths = write_responder_files(&secrets_dir, "secret", "hmac-123", &messages)
            .await
            .unwrap();

        let override_path = write_responder_compose_override(
            &compose_file,
            &secrets_dir,
            &paths.config_path,
            &messages,
        )
        .await
        .unwrap()
        .expect("override path");
        let contents = fs::read_to_string(&override_path).unwrap();
        let config_path = std::fs::canonicalize(&paths.config_path).unwrap();

        assert!(contents.contains("bootroot-http01"));
        assert!(contents.contains(&config_path.display().to_string()));
    }

    #[test]
    fn test_resolve_openbao_agent_addr_replaces_localhost() {
        let addr = resolve_openbao_agent_addr("http://localhost:8200", true);
        assert_eq!(addr, "http://openbao:8200");
    }

    #[test]
    fn test_resolve_openbao_agent_addr_keeps_remote() {
        let addr = resolve_openbao_agent_addr("http://openbao:8200", true);
        assert_eq!(addr, "http://openbao:8200");
    }

    #[tokio::test]
    async fn test_write_stepca_templates_writes_templates() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(secrets_dir.join("config")).unwrap();
        fs::write(
            secrets_dir.join("config").join("ca.json"),
            r#"{"db":{"type":"postgresql","dataSource":"old"}}"#,
        )
        .unwrap();

        let messages = test_messages();
        let paths = write_stepca_templates(&secrets_dir, "secret", &messages)
            .await
            .unwrap();
        let password_template = fs::read_to_string(&paths.password_template_path).unwrap();
        let ca_json_template = fs::read_to_string(&paths.ca_json_template_path).unwrap();

        assert!(password_template.contains("secret/data/bootroot/stepca/password"));
        assert!(ca_json_template.contains("secret/data/bootroot/stepca/db"));
    }

    #[tokio::test]
    async fn test_write_openbao_agent_files_writes_configs() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(secrets_dir.join("config")).unwrap();
        fs::write(
            secrets_dir.join("config").join("ca.json"),
            r#"{"db":{"type":"postgresql","dataSource":"old"}}"#,
        )
        .unwrap();

        let messages = test_messages();
        let stepca_templates = write_stepca_templates(&secrets_dir, "secret", &messages)
            .await
            .unwrap();
        let responder_paths = write_responder_files(&secrets_dir, "secret", "hmac-123", &messages)
            .await
            .unwrap();

        let role_outputs = vec![
            AppRoleOutput {
                label: "stepca".to_string(),
                role_name: "bootroot-stepca-role".to_string(),
                role_id: "stepca-role-id".to_string(),
                secret_id: "stepca-secret-id".to_string(),
            },
            AppRoleOutput {
                label: "responder".to_string(),
                role_name: "bootroot-responder-role".to_string(),
                role_id: "responder-role-id".to_string(),
                secret_id: "responder-secret-id".to_string(),
            },
        ];

        let paths = write_openbao_agent_files(
            &secrets_dir,
            "http://openbao:8200",
            &role_outputs,
            &stepca_templates,
            &responder_paths.template_path,
            &messages,
        )
        .await
        .unwrap();
        let stepca_config = fs::read_to_string(&paths.stepca_agent_config).unwrap();
        let responder_config = fs::read_to_string(&paths.responder_agent_config).unwrap();

        assert!(stepca_config.contains("role_id_file_path"));
        assert!(stepca_config.contains("password.txt.ctmpl"));
        assert!(responder_config.contains("responder.toml.ctmpl"));
    }

    #[tokio::test]
    async fn test_write_openbao_agent_compose_override_writes_services() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(
            &compose_file,
            r"
services:
  openbao:
    image: openbao/openbao:latest
",
        )
        .unwrap();

        let override_path = write_openbao_agent_compose_override(
            &compose_file,
            &secrets_dir,
            "http://openbao:8200",
            &test_messages(),
        )
        .await
        .unwrap()
        .expect("override path");
        let contents = fs::read_to_string(&override_path).unwrap();

        assert!(contents.contains("openbao-agent-stepca"));
        assert!(contents.contains("openbao-agent-responder"));
        assert!(contents.contains(&secrets_dir.display().to_string()));
    }

    #[test]
    fn test_step_ca_init_requires_password_when_missing_files() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();

        let err = ensure_step_ca_initialized(&secrets_dir, &test_messages()).unwrap_err();
        assert!(err.to_string().contains("step-ca password file not found"));
    }

    #[test]
    fn test_build_policy_map_contains_paths() {
        let policies = build_policy_map("secret");
        let agent_policy = policies.get(POLICY_BOOTROOT_AGENT).unwrap();
        assert!(agent_policy.contains("secret/data/bootroot/agent/eab"));
        assert!(agent_policy.contains("secret/data/bootroot/responder/hmac"));
    }

    #[test]
    fn test_trust_payload_changed_detects_changes() {
        let fingerprints = vec!["a".repeat(64), "b".repeat(64)];
        let bundle = "bundle-pem";
        assert!(trust_payload_changed(None, &fingerprints, bundle));

        let current = serde_json::json!({
            CA_TRUST_KEY: fingerprints,
            "ca_bundle_pem": bundle,
        });
        assert!(!trust_payload_changed(
            Some(&current),
            &["a".repeat(64), "b".repeat(64)],
            "bundle-pem"
        ));
        assert!(trust_payload_changed(
            Some(&current),
            &["c".repeat(64), "d".repeat(64)],
            "bundle-pem"
        ));
        assert!(trust_payload_changed(
            Some(&current),
            &["a".repeat(64), "b".repeat(64)],
            "bundle-pem-updated"
        ));
    }

    #[test]
    fn test_mark_remote_trust_sync_pending_at_path_updates_remote_only() {
        let temp_dir = tempdir().expect("tempdir");
        let state_path = temp_dir.path().join("state.json");
        let state = serde_json::json!({
            "openbao_url": "http://localhost:8200",
            "kv_mount": "secret",
            "secrets_dir": "secrets",
            "policies": {},
            "approles": {},
            "services": {
                "remote-service": {
                    "service_name": "remote-service",
                    "deploy_type": "daemon",
                    "delivery_mode": "remote-bootstrap",
                    "sync_status": {
                        "secret_id": "none",
                        "eab": "none",
                        "responder_hmac": "none",
                        "trust_sync": "applied"
                    },
                    "hostname": "edge-node-01",
                    "domain": "trusted.domain",
                    "agent_config_path": "agent.toml",
                    "cert_path": "certs/remote.crt",
                    "key_path": "certs/remote.key",
                    "instance_id": "001",
                    "container_name": null,
                    "notes": null,
                    "approle": {
                        "role_name": "bootroot-service-remote-service",
                        "role_id": "role-id-remote",
                        "secret_id_path": "secrets/services/remote-service/secret_id",
                        "policy_name": "bootroot-service-remote-service"
                    }
                },
                "local-service": {
                    "service_name": "local-service",
                    "deploy_type": "daemon",
                    "delivery_mode": "local-file",
                    "sync_status": {
                        "secret_id": "none",
                        "eab": "none",
                        "responder_hmac": "none",
                        "trust_sync": "applied"
                    },
                    "hostname": "edge-node-02",
                    "domain": "trusted.domain",
                    "agent_config_path": "agent-local.toml",
                    "cert_path": "certs/local.crt",
                    "key_path": "certs/local.key",
                    "instance_id": "002",
                    "container_name": null,
                    "notes": null,
                    "approle": {
                        "role_name": "bootroot-service-local-service",
                        "role_id": "role-id-local",
                        "secret_id_path": "secrets/services/local-service/secret_id",
                        "policy_name": "bootroot-service-local-service"
                    }
                }
            }
        });
        fs::write(
            &state_path,
            serde_json::to_string_pretty(&state).expect("serialize state"),
        )
        .expect("write state");

        let changed = mark_remote_trust_sync_pending_at_path(&state_path, &test_messages())
            .expect("mark remote pending");
        assert!(changed);

        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
                .expect("parse state");
        assert_eq!(
            updated["services"]["remote-service"]["sync_status"]["trust_sync"],
            "pending"
        );
        assert_eq!(
            updated["services"]["local-service"]["sync_status"]["trust_sync"],
            "applied"
        );
    }
}
