use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;
use bootroot::openbao::SecretIdOptions;

use super::super::constants::openbao_constants::{
    INIT_SECRET_SHARES, INIT_SECRET_THRESHOLD, MAX_SECRET_ID_TTL, PATH_AGENT_EAB, PATH_CA_TRUST,
    PATH_RESPONDER_HMAC, PATH_STEPCA_DB, PATH_STEPCA_PASSWORD, POLICY_BOOTROOT_AGENT,
    POLICY_BOOTROOT_RESPONDER, POLICY_BOOTROOT_RUNTIME_ROTATE, POLICY_BOOTROOT_RUNTIME_SERVICE_ADD,
    POLICY_BOOTROOT_STEPCA, RECOMMENDED_SECRET_ID_TTL, TOKEN_TTL,
};
use super::super::constants::{
    OPENBAO_AGENT_COMPOSE_OVERRIDE_NAME, OPENBAO_AGENT_CONFIG_NAME, OPENBAO_AGENT_DIR,
    OPENBAO_AGENT_RESPONDER_DIR, OPENBAO_AGENT_RESPONDER_SERVICE, OPENBAO_AGENT_ROLE_ID_NAME,
    OPENBAO_AGENT_SECRET_ID_NAME, OPENBAO_AGENT_STEPCA_DIR, OPENBAO_AGENT_STEPCA_SERVICE,
};
use super::super::paths::{
    OpenBaoAgentPaths, StepCaTemplatePaths, compose_has_openbao, resolve_openbao_agent_addr,
    to_container_path,
};
use super::super::types::{AppRoleLabel, AppRoleOutput, EabCredentials, OpenBaoConfigResult};
use super::ca_certs::{compute_ca_bundle_pem, compute_ca_fingerprints};
use super::prompts::{confirm_overwrite, prompt_text, prompt_unseal_keys};
use super::{InitBootstrap, InitRollback, InitSecrets};
use crate::cli::args::InitArgs;
use crate::commands::constants::CA_TRUST_KEY;
use crate::commands::infra::run_docker;
use crate::commands::openbao_unseal::read_unseal_keys_from_file;
use crate::i18n::Messages;

const INIT_AGENT_TOKEN_PATH: &str = "/openbao/secrets/openbao/token";

pub(super) async fn bootstrap_openbao(
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

async fn ensure_openbao_initialized(
    client: &OpenBaoClient,
    args: &InitArgs,
    messages: &Messages,
) -> Result<(
    Option<bootroot::openbao::InitResponse>,
    Option<String>,
    Vec<String>,
)> {
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

pub(super) async fn configure_openbao(
    client: &OpenBaoClient,
    args: &InitArgs,
    secrets: &InitSecrets,
    rollback: &mut InitRollback,
    messages: &Messages,
) -> Result<OpenBaoConfigResult> {
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

    for &label in AppRoleLabel::all() {
        let role_name = label.role_name();
        let policy_name = label.policy_name();
        if !client
            .approle_exists(role_name)
            .await
            .with_context(|| messages.error_openbao_approle_exists_failed())?
        {
            rollback.created_approles.push(role_name.to_string());
        }
        client
            .create_approle(
                role_name,
                &[policy_name],
                TOKEN_TTL,
                &args.secret_id_ttl,
                true,
            )
            .await
            .with_context(|| messages.error_openbao_approle_create_failed())?;
    }

    let mut role_outputs = Vec::new();
    let default_opts = SecretIdOptions::default();
    for &label in AppRoleLabel::all() {
        let role_name = label.role_name();
        let role_id = client
            .read_role_id(role_name)
            .await
            .with_context(|| messages.error_openbao_role_id_failed())?;
        let secret_id = client
            .create_secret_id(role_name, &default_opts)
            .await
            .with_context(|| messages.error_openbao_secret_id_failed())?;
        role_outputs.push(AppRoleOutput {
            label,
            role_name: role_name.to_string(),
            role_id,
            secret_id,
        });
    }
    let approles = AppRoleLabel::approle_map();

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

    Ok(OpenBaoConfigResult {
        role_outputs,
        approles,
    })
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

pub(super) async fn write_ca_trust_fingerprints_with_retry(
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
    let changed = super::ca_certs::trust_payload_changed(
        current_trust.as_ref(),
        &fingerprints,
        &ca_bundle_pem,
    );
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

/// Parses an OpenBao-style duration string into seconds.
///
/// Accepts formats: `"30s"`, `"10m"`, `"24h"`, or bare seconds `"3600"`.
fn parse_ttl_to_secs(ttl: &str) -> Option<u64> {
    let ttl = ttl.trim();
    if ttl.is_empty() {
        return None;
    }
    if let Some(h) = ttl.strip_suffix('h') {
        return h.parse::<u64>().ok().and_then(|v| v.checked_mul(3600));
    }
    if let Some(m) = ttl.strip_suffix('m') {
        return m.parse::<u64>().ok().and_then(|v| v.checked_mul(60));
    }
    if let Some(s) = ttl.strip_suffix('s') {
        return s.parse::<u64>().ok();
    }
    ttl.parse::<u64>().ok()
}

/// Validates the `--secret-id-ttl` value against hard maximum and
/// recommended thresholds.
///
/// Returns `Ok(Some(warning))` when the value exceeds the recommended
/// threshold but is still within the hard maximum, `Ok(None)` when the
/// value is within both limits, or `Err` when the value is invalid or
/// exceeds the hard maximum.
pub(crate) fn validate_secret_id_ttl(ttl: &str, messages: &Messages) -> Result<Option<String>> {
    let secs = parse_ttl_to_secs(ttl)
        .ok_or_else(|| anyhow::anyhow!(messages.error_secret_id_ttl_invalid(ttl)))?;
    let max_secs =
        parse_ttl_to_secs(MAX_SECRET_ID_TTL).expect("MAX_SECRET_ID_TTL must be a valid duration");
    if secs > max_secs {
        anyhow::bail!(messages.error_secret_id_ttl_exceeds_max(ttl, MAX_SECRET_ID_TTL));
    }
    let recommended_secs = parse_ttl_to_secs(RECOMMENDED_SECRET_ID_TTL)
        .expect("RECOMMENDED_SECRET_ID_TTL must be a valid duration");
    if secs > recommended_secs {
        return Ok(Some(messages.warning_secret_id_ttl_exceeds_recommended(
            ttl,
            RECOMMENDED_SECRET_ID_TTL,
        )));
    }
    Ok(None)
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
    policies.insert(
        POLICY_BOOTROOT_RUNTIME_SERVICE_ADD.to_string(),
        format!(
            r#"path "sys/policies/acl/bootroot-service-*" {{
  capabilities = ["create", "update", "read"]
}}
path "auth/approle/role/bootroot-service-*" {{
  capabilities = ["create", "update", "read"]
}}
path "auth/approle/role/bootroot-service-*/role-id" {{
  capabilities = ["read"]
}}
path "auth/approle/role/bootroot-service-*/secret-id" {{
  capabilities = ["create", "update"]
}}
path "{kv_mount}/data/{PATH_AGENT_EAB}" {{
  capabilities = ["read"]
}}
path "{kv_mount}/data/{PATH_RESPONDER_HMAC}" {{
  capabilities = ["read"]
}}
path "{kv_mount}/data/{PATH_CA_TRUST}" {{
  capabilities = ["read"]
}}
path "{kv_mount}/metadata/{PATH_CA_TRUST}" {{
  capabilities = ["read"]
}}
path "{kv_mount}/data/bootroot/services/*" {{
  capabilities = ["create", "update", "read"]
}}
"#
        ),
    );
    policies.insert(
        POLICY_BOOTROOT_RUNTIME_ROTATE.to_string(),
        format!(
            r#"path "{kv_mount}/data/{PATH_STEPCA_PASSWORD}" {{
  capabilities = ["create", "update", "read"]
}}
path "{kv_mount}/data/{PATH_STEPCA_DB}" {{
  capabilities = ["create", "update", "read"]
}}
path "{kv_mount}/data/{PATH_AGENT_EAB}" {{
  capabilities = ["create", "update", "read"]
}}
path "{kv_mount}/data/{PATH_RESPONDER_HMAC}" {{
  capabilities = ["create", "update", "read"]
}}
path "{kv_mount}/data/{PATH_CA_TRUST}" {{
  capabilities = ["create", "update", "read"]
}}
path "{kv_mount}/metadata/{PATH_CA_TRUST}" {{
  capabilities = ["read"]
}}
path "{kv_mount}/data/bootroot/services/*" {{
  capabilities = ["create", "update", "read"]
}}
path "auth/approle/role/bootroot-service-*" {{
  capabilities = ["create", "update", "read"]
}}
path "auth/approle/role/bootroot-service-*/role-id" {{
  capabilities = ["read"]
}}
path "auth/approle/role/bootroot-service-*/secret-id" {{
  capabilities = ["create", "update"]
}}
"#
        ),
    );
    policies
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
            serde_json::json!({ "value": db_dsn }),
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

pub(super) async fn setup_openbao_agents(
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

    let stepca_role = find_role_output(role_outputs, AppRoleLabel::Stepca, messages)?;
    let responder_role = find_role_output(role_outputs, AppRoleLabel::Responder, messages)?;

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
    let mount = "/openbao/secrets";
    let password_template =
        to_container_path(secrets_dir, &stepca_templates.password_template_path, mount)?;
    let ca_json_template =
        to_container_path(secrets_dir, &stepca_templates.ca_json_template_path, mount)?;
    let responder_template = to_container_path(secrets_dir, responder_template, mount)?;
    let password_output = to_container_path(secrets_dir, &secrets_dir.join("password.txt"), mount)?;
    let ca_json_output = to_container_path(
        secrets_dir,
        &secrets_dir.join("config").join("ca.json"),
        mount,
    )?;
    let responder_output = to_container_path(
        secrets_dir,
        &secrets_dir.join("responder").join("responder.toml"),
        mount,
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

fn build_openbao_agent_config(
    openbao_addr: &str,
    role_id_path: &str,
    secret_id_path: &str,
    templates: &[(String, String)],
) -> String {
    let tpl_refs: Vec<(&str, &str)> = templates
        .iter()
        .map(|(s, d)| (s.as_str(), d.as_str()))
        .collect();
    bootroot::openbao::build_agent_config(
        openbao_addr,
        role_id_path,
        secret_id_path,
        INIT_AGENT_TOKEN_PATH,
        None,
        bootroot::openbao::STATIC_SECRET_RENDER_INTERVAL,
        &tpl_refs,
    )
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
    let meta = std::fs::metadata(&mount_root)
        .with_context(|| messages.error_resolve_path_failed(&mount_root.display().to_string()))?;
    let user = {
        use std::os::unix::fs::MetadataExt;
        format!("{}:{}", meta.uid(), meta.gid())
    };
    let contents = format!(
        r#"version: "3.8"
services:
  {stepca_service}:
    image: openbao/openbao:latest
    container_name: bootroot-openbao-agent-stepca
    user: "{user}"
    restart: always
    command: ["agent", "-config=/openbao/secrets/openbao/stepca/agent.hcl"]
{depends_on}    environment:
      - VAULT_ADDR={openbao_addr}
    volumes:
      - {secrets_path}:/openbao/secrets
  {responder_service}:
    image: openbao/openbao:latest
    container_name: bootroot-openbao-agent-responder
    user: "{user}"
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
        secrets_path = mount_root.display(),
        user = user
    );
    tokio::fs::write(&override_path, contents)
        .await
        .with_context(|| messages.error_write_file_failed(&override_path.display().to_string()))?;
    Ok(Some(override_path))
}

pub(super) fn apply_openbao_agent_compose_override(
    compose_file: &Path,
    override_path: &Path,
    messages: &Messages,
) -> Result<()> {
    let compose_str = compose_file.to_string_lossy();
    let override_str = override_path.to_string_lossy();
    let args = [
        "compose",
        "-f",
        &*compose_str,
        "-f",
        &*override_str,
        "up",
        "-d",
        OPENBAO_AGENT_STEPCA_SERVICE,
        OPENBAO_AGENT_RESPONDER_SERVICE,
    ];
    run_docker(&args, "docker compose openbao agent override", messages)?;
    Ok(())
}

pub(super) fn find_role_output<'a>(
    role_outputs: &'a [AppRoleOutput],
    label: AppRoleLabel,
    messages: &Messages,
) -> Result<&'a AppRoleOutput> {
    role_outputs
        .iter()
        .find(|output| output.label == label)
        .ok_or_else(|| {
            anyhow::anyhow!(messages.error_openbao_role_output_missing(&label.to_string()))
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::super::super::constants::openbao_constants::{
        POLICY_BOOTROOT_AGENT, POLICY_BOOTROOT_RUNTIME_ROTATE, POLICY_BOOTROOT_RUNTIME_SERVICE_ADD,
    };
    use super::super::super::paths::resolve_openbao_agent_addr;
    use super::super::super::types::{AppRoleLabel, AppRoleOutput};
    use super::super::responder_setup::write_responder_files;
    use super::super::stepca_setup::write_stepca_templates;
    use super::super::test_support::test_messages;
    use super::*;

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
                label: AppRoleLabel::Stepca,
                role_name: "bootroot-stepca-role".to_string(),
                role_id: "stepca-role-id".to_string(),
                secret_id: "stepca-secret-id".to_string(),
            },
            AppRoleOutput {
                label: AppRoleLabel::Responder,
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
        assert!(
            contents.contains("user:"),
            "compose override must set user for infra OBA containers"
        );
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

    #[test]
    fn test_build_policy_map_contains_paths() {
        let policies = build_policy_map("secret");
        let agent_policy = policies.get(POLICY_BOOTROOT_AGENT).unwrap();
        let service_add_policy = policies.get(POLICY_BOOTROOT_RUNTIME_SERVICE_ADD).unwrap();
        let rotate_policy = policies.get(POLICY_BOOTROOT_RUNTIME_ROTATE).unwrap();
        assert!(agent_policy.contains("secret/data/bootroot/agent/eab"));
        assert!(agent_policy.contains("secret/data/bootroot/responder/hmac"));
        assert!(service_add_policy.contains("sys/policies/acl/bootroot-service-*"));
        assert!(service_add_policy.contains("auth/approle/role/bootroot-service-*/secret-id"));
        assert!(service_add_policy.contains("secret/metadata/bootroot/ca"));
        assert!(rotate_policy.contains("secret/data/bootroot/stepca/password"));
        assert!(rotate_policy.contains("secret/data/bootroot/services/*"));
        assert!(rotate_policy.contains("auth/approle/role/bootroot-service-*"));
        assert!(rotate_policy.contains("auth/approle/role/bootroot-service-*/secret-id"));
        assert!(rotate_policy.contains("secret/data/bootroot/ca"));
        assert!(rotate_policy.contains("secret/metadata/bootroot/ca"));
    }

    #[test]
    fn test_build_openbao_agent_config_includes_template_config() {
        let config = build_openbao_agent_config(
            "http://openbao:8200",
            "/openbao/secrets/openbao/stepca/role_id",
            "/openbao/secrets/openbao/stepca/secret_id",
            &[(
                "/openbao/templates/password.ctmpl".to_string(),
                "/openbao/secrets/password.txt".to_string(),
            )],
        );
        assert!(
            config.contains("template_config"),
            "config should contain template_config block"
        );
        assert!(
            config.contains("static_secret_render_interval = \"30s\""),
            "config should set static_secret_render_interval to 30s"
        );
        assert!(
            config.contains("vault {"),
            "config should contain vault block"
        );
        assert!(
            config.contains("auto_auth {"),
            "config should contain auto_auth block"
        );
        assert!(
            config.contains("template {"),
            "config should contain template block"
        );
    }

    #[test]
    fn test_parse_ttl_to_secs_hours() {
        assert_eq!(parse_ttl_to_secs("24h"), Some(86400));
        assert_eq!(parse_ttl_to_secs("168h"), Some(604_800));
    }

    #[test]
    fn test_parse_ttl_to_secs_minutes() {
        assert_eq!(parse_ttl_to_secs("30m"), Some(1800));
    }

    #[test]
    fn test_parse_ttl_to_secs_seconds() {
        assert_eq!(parse_ttl_to_secs("3600s"), Some(3600));
        assert_eq!(parse_ttl_to_secs("3600"), Some(3600));
    }

    #[test]
    fn test_parse_ttl_to_secs_invalid() {
        assert_eq!(parse_ttl_to_secs(""), None);
        assert_eq!(parse_ttl_to_secs("abc"), None);
    }

    #[test]
    fn test_validate_secret_id_ttl_default_passes() {
        let messages = test_messages();
        assert!(validate_secret_id_ttl("24h", &messages).is_ok());
    }

    #[test]
    fn test_validate_secret_id_ttl_exceeds_max_fails() {
        let messages = test_messages();
        assert!(validate_secret_id_ttl("200h", &messages).is_err());
    }

    #[test]
    fn test_validate_secret_id_ttl_exceeds_recommended_passes_with_warning() {
        let messages = test_messages();
        // 72h > 48h recommended but < 168h max → Ok with warning
        let warning = validate_secret_id_ttl("72h", &messages)
            .expect("should succeed")
            .expect("should return a warning");
        assert!(
            warning.contains("72h"),
            "warning should mention the supplied value"
        );
        assert!(
            warning.contains(RECOMMENDED_SECRET_ID_TTL),
            "warning should mention the recommended threshold"
        );
    }

    #[test]
    fn test_validate_secret_id_ttl_within_recommended_has_no_warning() {
        let messages = test_messages();
        let warning = validate_secret_id_ttl("24h", &messages).expect("should succeed");
        assert!(warning.is_none(), "no warning expected for 24h");
    }

    #[test]
    fn test_validate_secret_id_ttl_invalid_fails() {
        let messages = test_messages();
        assert!(validate_secret_id_ttl("not-a-duration", &messages).is_err());
    }

    #[test]
    fn test_validate_secret_id_ttl_overflow_fails() {
        let messages = test_messages();
        // A huge hours value that would overflow u64 when multiplied by 3600
        assert!(validate_secret_id_ttl("99999999999999999999h", &messages).is_err());
    }

    #[test]
    fn test_parse_ttl_to_secs_overflow_returns_none() {
        assert_eq!(parse_ttl_to_secs("99999999999999999999h"), None);
        assert_eq!(parse_ttl_to_secs("99999999999999999999m"), None);
    }
}
