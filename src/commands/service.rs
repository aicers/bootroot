use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;
use tokio::fs;

use crate::cli::args::{ServiceAddArgs, ServiceInfoArgs};
use crate::cli::output::{
    ServiceAddPlan, print_service_add_plan, print_service_add_summary, print_service_info_summary,
};
use crate::cli::prompt::Prompt;
use crate::commands::init::{PATH_CA_TRUST, SECRET_ID_TTL, TOKEN_TTL};
use crate::i18n::Messages;
use crate::state::{
    DeliveryMode, DeployType, ServiceEntry, ServiceRoleEntry, ServiceSyncStatus, StateFile,
};
const SERVICE_ROLE_PREFIX: &str = "bootroot-service-";
const SERVICE_KV_BASE: &str = "bootroot/services";
const SERVICE_SECRET_DIR: &str = "services";
const SERVICE_ROLE_ID_FILENAME: &str = "role_id";
const SERVICE_SECRET_ID_FILENAME: &str = "secret_id";
const CA_TRUST_KEY: &str = "trusted_ca_sha256";

pub(crate) async fn run_service_add(args: &ServiceAddArgs, messages: &Messages) -> Result<()> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let mut state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;

    let resolved = resolve_service_add_args(args, messages)?;
    if state.services.contains_key(&resolved.service_name) {
        anyhow::bail!(messages.error_service_duplicate(&resolved.service_name));
    }

    validate_service_add(&resolved, messages)?;

    let agent_config = resolved.agent_config.display().to_string();
    let cert_path = resolved.cert_path.display().to_string();
    let key_path = resolved.key_path.display().to_string();
    let plan = ServiceAddPlan {
        service_name: &resolved.service_name,
        deploy_type: resolved.deploy_type,
        delivery_mode: resolved.delivery_mode,
        hostname: &resolved.hostname,
        domain: &resolved.domain,
        agent_config: &agent_config,
        cert_path: &cert_path,
        key_path: &key_path,
        instance_id: resolved.instance_id.as_deref(),
        container_name: resolved.container_name.as_deref(),
        notes: resolved.notes.as_deref(),
    };
    print_service_add_plan(&plan, messages);

    let root_token = resolved.root_token.clone();

    let mut client = OpenBaoClient::new(&state.openbao_url)
        .with_context(|| messages.error_openbao_client_create_failed())?;
    client.set_token(root_token);
    client
        .ensure_approle_auth()
        .await
        .with_context(|| messages.error_openbao_approle_auth_failed())?;

    let trusted_ca_sha256 =
        read_trusted_ca_fingerprints(&client, &state.kv_mount, messages).await?;
    let approle = ensure_service_approle(&client, &state, &resolved.service_name, messages).await?;
    let secrets_dir = state.secrets_dir();
    write_role_id_file(
        &secrets_dir,
        &resolved.service_name,
        &approle.role_id,
        messages,
    )
    .await?;
    let secret_id_path = write_secret_id_file(
        &secrets_dir,
        &resolved.service_name,
        &approle.secret_id,
        messages,
    )
    .await?;

    let entry = ServiceEntry {
        service_name: resolved.service_name.clone(),
        deploy_type: resolved.deploy_type,
        delivery_mode: resolved.delivery_mode,
        sync_status: ServiceSyncStatus::default(),
        hostname: resolved.hostname.clone(),
        domain: resolved.domain.clone(),
        agent_config_path: resolved.agent_config.clone(),
        cert_path: resolved.cert_path.clone(),
        key_path: resolved.key_path.clone(),
        instance_id: resolved.instance_id.clone(),
        container_name: resolved.container_name.clone(),
        notes: resolved.notes.clone(),
        approle: ServiceRoleEntry {
            role_name: approle.role_name,
            role_id: approle.role_id,
            secret_id_path: secret_id_path.clone(),
            policy_name: approle.policy_name,
        },
    };

    state
        .services
        .insert(resolved.service_name.clone(), entry.clone());
    state
        .save(&state_path)
        .with_context(|| messages.error_serialize_state_failed())?;

    print_service_add_summary(
        &entry,
        &secret_id_path,
        trusted_ca_sha256.as_deref(),
        messages,
    );
    Ok(())
}

pub(crate) fn run_service_info(args: &ServiceInfoArgs, messages: &Messages) -> Result<()> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;
    let entry = state
        .services
        .get(&args.service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(&args.service_name)))?;
    print_service_info_summary(entry, messages);
    Ok(())
}

fn validate_service_add(args: &ResolvedServiceAdd, messages: &Messages) -> Result<()> {
    if args.service_name.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    if args.hostname.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    if args.domain.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    if args.instance_id.as_deref().unwrap_or_default().is_empty() {
        anyhow::bail!(messages.error_service_instance_id_required());
    }
    if matches!(args.deploy_type, DeployType::Docker)
        && args
            .container_name
            .as_deref()
            .unwrap_or_default()
            .is_empty()
    {
        anyhow::bail!(messages.error_service_container_name_required());
    }
    Ok(())
}

fn build_service_policy(kv_mount: &str, service_name: &str) -> String {
    let base = format!("{SERVICE_KV_BASE}/{service_name}");
    format!(
        r#"path "{kv_mount}/data/{base}/*" {{
  capabilities = ["read"]
}}
path "{kv_mount}/metadata/{base}/*" {{
  capabilities = ["list"]
}}
"#
    )
}

async fn write_secret_id_file(
    secrets_dir: &Path,
    service_name: &str,
    secret_id: &str,
    messages: &Messages,
) -> Result<PathBuf> {
    let service_dir = secrets_dir.join(SERVICE_SECRET_DIR).join(service_name);
    fs_util::ensure_secrets_dir(&service_dir).await?;
    let secret_path = service_dir.join(SERVICE_SECRET_ID_FILENAME);
    fs::write(&secret_path, secret_id)
        .await
        .with_context(|| messages.error_write_file_failed(&secret_path.display().to_string()))?;
    fs_util::set_key_permissions(&secret_path).await?;
    Ok(secret_path)
}

async fn write_role_id_file(
    secrets_dir: &Path,
    service_name: &str,
    role_id: &str,
    messages: &Messages,
) -> Result<PathBuf> {
    let service_dir = secrets_dir.join(SERVICE_SECRET_DIR).join(service_name);
    fs_util::ensure_secrets_dir(&service_dir).await?;
    let role_path = service_dir.join(SERVICE_ROLE_ID_FILENAME);
    fs::write(&role_path, role_id)
        .await
        .with_context(|| messages.error_write_file_failed(&role_path.display().to_string()))?;
    fs_util::set_key_permissions(&role_path).await?;
    Ok(role_path)
}

struct ServiceAppRoleMaterialized {
    role_name: String,
    role_id: String,
    secret_id: String,
    policy_name: String,
}

async fn ensure_service_approle(
    client: &OpenBaoClient,
    state: &StateFile,
    service_name: &str,
    messages: &Messages,
) -> Result<ServiceAppRoleMaterialized> {
    let policy_name = service_policy_name(service_name);
    let policy = build_service_policy(&state.kv_mount, service_name);
    client
        .write_policy(&policy_name, &policy)
        .await
        .with_context(|| messages.error_openbao_policy_write_failed())?;

    let role_name = service_role_name(service_name);
    client
        .create_approle(
            &role_name,
            std::slice::from_ref(&policy_name),
            TOKEN_TTL,
            SECRET_ID_TTL,
            true,
        )
        .await
        .with_context(|| messages.error_openbao_approle_create_failed())?;
    let role_id = client
        .read_role_id(&role_name)
        .await
        .with_context(|| messages.error_openbao_role_id_failed())?;
    let secret_id = client
        .create_secret_id(&role_name)
        .await
        .with_context(|| messages.error_openbao_secret_id_failed())?;
    Ok(ServiceAppRoleMaterialized {
        role_name,
        role_id,
        secret_id,
        policy_name,
    })
}

fn service_role_name(service_name: &str) -> String {
    format!("{SERVICE_ROLE_PREFIX}{service_name}")
}

fn service_policy_name(service_name: &str) -> String {
    format!("{SERVICE_ROLE_PREFIX}{service_name}")
}

#[derive(Debug)]
pub(crate) struct ResolvedServiceAdd {
    pub(crate) service_name: String,
    pub(crate) deploy_type: DeployType,
    pub(crate) delivery_mode: DeliveryMode,
    pub(crate) hostname: String,
    pub(crate) domain: String,
    pub(crate) agent_config: PathBuf,
    pub(crate) cert_path: PathBuf,
    pub(crate) key_path: PathBuf,
    pub(crate) instance_id: Option<String>,
    pub(crate) container_name: Option<String>,
    pub(crate) root_token: String,
    pub(crate) notes: Option<String>,
}

fn resolve_service_add_args(
    args: &ServiceAddArgs,
    messages: &Messages,
) -> Result<ResolvedServiceAdd> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut prompt = Prompt::new(&mut input, &mut output, messages);

    let service_name = match args.service_name.clone() {
        Some(value) => value,
        None => prompt.prompt_with_validation(messages.prompt_service_name(), None, |value| {
            ensure_non_empty(value, messages)
        })?,
    };

    let deploy_type = match args.deploy_type {
        Some(value) => value,
        None => prompt.prompt_with_validation(
            messages.prompt_deploy_type(),
            Some("daemon"),
            |value| parse_deploy_type(value, messages),
        )?,
    };
    let delivery_mode = args.delivery_mode.unwrap_or_default();

    let hostname = match args.hostname.clone() {
        Some(value) => value,
        None => prompt.prompt_with_validation(messages.prompt_hostname(), None, |value| {
            ensure_non_empty(value, messages)
        })?,
    };

    let domain = match args.domain.clone() {
        Some(value) => value,
        None => prompt.prompt_with_validation(messages.prompt_domain(), None, |value| {
            ensure_non_empty(value, messages)
        })?,
    };

    let agent_config = resolve_path(
        args.agent_config.clone(),
        messages.prompt_agent_config(),
        &mut prompt,
        true,
        messages,
    )?;

    let cert_path = resolve_path(
        args.cert_path.clone(),
        messages.prompt_cert_path(),
        &mut prompt,
        false,
        messages,
    )?;

    let key_path = resolve_path(
        args.key_path.clone(),
        messages.prompt_key_path(),
        &mut prompt,
        false,
        messages,
    )?;

    let instance_id = match args.instance_id.clone() {
        Some(value) => value,
        None => prompt.prompt_with_validation(messages.prompt_instance_id(), None, |value| {
            ensure_non_empty(value, messages)
        })?,
    };
    let container_name = match deploy_type {
        DeployType::Daemon => None,
        DeployType::Docker => Some(match args.container_name.clone() {
            Some(value) => value,
            None => {
                prompt.prompt_with_validation(messages.prompt_container_name(), None, |value| {
                    ensure_non_empty(value, messages)
                })?
            }
        }),
    };

    let root_token = if let Some(value) = args.root_token.root_token.clone() {
        value
    } else {
        let label = messages.prompt_openbao_root_token().trim_end_matches(": ");
        prompt.prompt_with_validation(label, None, |value| ensure_non_empty(value, messages))?
    };

    Ok(ResolvedServiceAdd {
        service_name,
        deploy_type,
        delivery_mode,
        hostname,
        domain,
        agent_config,
        cert_path,
        key_path,
        instance_id: Some(instance_id),
        container_name,
        root_token,
        notes: args.notes.clone(),
    })
}

fn ensure_non_empty(value: &str, messages: &Messages) -> Result<String> {
    if value.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    Ok(value.trim().to_string())
}

fn parse_deploy_type(value: &str, messages: &Messages) -> Result<DeployType> {
    match value.trim().to_ascii_lowercase().as_str() {
        "daemon" => Ok(DeployType::Daemon),
        "docker" => Ok(DeployType::Docker),
        _ => anyhow::bail!(messages.error_invalid_deploy_type()),
    }
}

fn resolve_path(
    value: Option<PathBuf>,
    label: &str,
    prompt: &mut Prompt<'_>,
    must_exist: bool,
    messages: &Messages,
) -> Result<PathBuf> {
    let path = match value {
        Some(path) => path,
        None => prompt.prompt_with_validation(label, None, |input| {
            let candidate = PathBuf::from(input);
            validate_path(&candidate, must_exist, messages)?;
            Ok(candidate)
        })?,
    };
    validate_path(&path, must_exist, messages)?;
    Ok(path)
}

fn validate_path(path: &Path, must_exist: bool, messages: &Messages) -> Result<()> {
    if must_exist && !path.exists() {
        anyhow::bail!(messages.error_path_not_found(&path.display().to_string()));
    }
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(messages.error_parent_not_found(&path.display().to_string()))
    })?;
    if !parent.as_os_str().is_empty() && !parent.exists() {
        anyhow::bail!(messages.error_parent_not_found(&parent.display().to_string()));
    }
    Ok(())
}

async fn read_trusted_ca_fingerprints(
    client: &OpenBaoClient,
    kv_mount: &str,
    messages: &Messages,
) -> Result<Option<Vec<String>>> {
    if !client
        .kv_exists(kv_mount, PATH_CA_TRUST)
        .await
        .with_context(|| messages.error_openbao_kv_exists_failed())?
    {
        return Ok(None);
    }
    let data = client
        .read_kv(kv_mount, PATH_CA_TRUST)
        .await
        .with_context(|| messages.error_openbao_kv_read_failed())?;
    let value = data
        .get(CA_TRUST_KEY)
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_trust_missing(CA_TRUST_KEY)))?;
    let fingerprints = parse_trusted_ca_list(value, messages)?;
    if fingerprints.is_empty() {
        anyhow::bail!(messages.error_ca_trust_empty());
    }
    Ok(Some(fingerprints))
}

fn parse_trusted_ca_list(value: &serde_json::Value, messages: &Messages) -> Result<Vec<String>> {
    let items = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_trust_invalid()))?;
    let mut fingerprints = Vec::with_capacity(items.len());
    for item in items {
        let fingerprint = item
            .as_str()
            .ok_or_else(|| anyhow::anyhow!(messages.error_ca_trust_invalid()))?;
        if !is_valid_sha256_fingerprint(fingerprint) {
            anyhow::bail!(messages.error_ca_trust_invalid());
        }
        fingerprints.push(fingerprint.to_string());
    }
    Ok(fingerprints)
}

fn is_valid_sha256_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Messages;

    fn test_messages() -> Messages {
        Messages::new("en").expect("valid language")
    }

    #[test]
    fn test_parse_trusted_ca_list_accepts_valid() {
        let messages = test_messages();
        let value = serde_json::json!(["a".repeat(64), "b".repeat(64)]);
        let parsed = parse_trusted_ca_list(&value, &messages).expect("parse list");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], "a".repeat(64));
        assert_eq!(parsed[1], "b".repeat(64));
    }

    #[test]
    fn test_parse_trusted_ca_list_rejects_non_array() {
        let messages = test_messages();
        let value = serde_json::json!("not-array");
        let err = parse_trusted_ca_list(&value, &messages).unwrap_err();
        assert!(err.to_string().contains("OpenBao CA trust data"));
    }

    #[test]
    fn test_parse_trusted_ca_list_rejects_invalid_fingerprint() {
        let messages = test_messages();
        let value = serde_json::json!(["not-hex"]);
        let err = parse_trusted_ca_list(&value, &messages).unwrap_err();
        assert!(err.to_string().contains("OpenBao CA trust data"));
    }
}
