use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;

use super::constants::{
    OPENBAO_AGENT_COMPOSE_OVERRIDE_NAME, OPENBAO_AGENT_CONFIG_NAME, OPENBAO_AGENT_DIR,
    OPENBAO_AGENT_RESPONDER_DIR, OPENBAO_AGENT_RESPONDER_SERVICE, OPENBAO_AGENT_ROLE_ID_NAME,
    OPENBAO_AGENT_SECRET_ID_NAME, OPENBAO_AGENT_STEPCA_DIR, OPENBAO_AGENT_STEPCA_SERVICE,
    RESPONDER_COMPOSE_OVERRIDE_NAME, RESPONDER_CONFIG_DIR, RESPONDER_CONFIG_NAME,
    RESPONDER_TEMPLATE_DIR, RESPONDER_TEMPLATE_NAME, STEPCA_CA_JSON_TEMPLATE_NAME,
    STEPCA_PASSWORD_TEMPLATE_NAME,
};
use super::templates::{
    build_ca_json_template, build_password_template, build_responder_config,
    build_responder_template,
};
use super::{AppRoleOutput, OpenBaoAgentPaths, ResponderPaths, StepCaTemplatePaths};
use crate::commands::infra::run_docker;
use crate::i18n::Messages;

pub(super) async fn write_responder_files(
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

pub(super) async fn write_stepca_templates(
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

pub(super) async fn write_openbao_agent_files(
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

    let stepca_role = super::find_role_output(role_outputs, "stepca", messages)?;
    let responder_role = super::find_role_output(role_outputs, "responder", messages)?;

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

pub(super) async fn write_responder_compose_override(
    compose_file: &Path,
    secrets_dir: &Path,
    config_path: &Path,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    if !super::compose_has_responder(compose_file, messages)? {
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

pub(super) async fn write_openbao_agent_compose_override(
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
    let depends_on = if super::compose_has_openbao(compose_file, messages)? {
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

pub(super) fn to_container_path(
    secrets_dir: &Path,
    path: &Path,
    messages: &Messages,
) -> Result<String> {
    let relative = path
        .strip_prefix(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&path.display().to_string()))?;
    Ok(format!("/openbao/secrets/{}", relative.to_string_lossy()))
}

pub(super) fn apply_responder_compose_override(
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

pub(super) fn apply_openbao_agent_compose_override(
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

pub(super) fn build_openbao_agent_config(
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
