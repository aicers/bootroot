use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use bootroot::fs_util;
use tokio::fs;

use super::resolve::ResolvedServiceAdd;
use super::{
    DEFAULT_AGENT_EMAIL, DEFAULT_AGENT_RESPONDER_URL, DEFAULT_AGENT_SERVER,
    OPENBAO_AGENT_CONFIG_FILENAME, OPENBAO_AGENT_TEMPLATE_FILENAME, OPENBAO_AGENT_TOKEN_FILENAME,
    OPENBAO_SERVICE_CONFIG_DIR, REMOTE_BOOTSTRAP_DIR, REMOTE_BOOTSTRAP_FILENAME,
    RemoteBootstrapResult, SERVICE_ROLE_ID_FILENAME,
};
use crate::i18n::Messages;
use crate::state::{ServiceEntry, StateFile};

#[derive(serde::Serialize)]
struct RemoteBootstrapArtifact {
    openbao_url: String,
    kv_mount: String,
    service_name: String,
    role_id_path: String,
    secret_id_path: String,
    eab_file_path: String,
    agent_config_path: String,
    ca_bundle_path: String,
    openbao_agent_config_path: String,
    openbao_agent_template_path: String,
    openbao_agent_token_path: String,
    agent_email: String,
    agent_server: String,
    agent_domain: String,
    agent_responder_url: String,
    profile_hostname: String,
    profile_instance_id: String,
    profile_cert_path: String,
    profile_key_path: String,
}

pub(super) async fn write_remote_bootstrap_artifact(
    state: &StateFile,
    secrets_dir: &Path,
    resolved: &ResolvedServiceAdd,
    secret_id_path: &Path,
    messages: &Messages,
) -> Result<RemoteBootstrapResult> {
    let role_id_path = secret_id_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(SERVICE_ROLE_ID_FILENAME);
    let eab_path = secret_id_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("eab.json");
    let ca_bundle_path = resolved
        .cert_path
        .parent()
        .unwrap_or(Path::new("certs"))
        .join("ca-bundle.pem");
    let (openbao_agent_config_path, openbao_agent_template_path, openbao_agent_token_path) =
        remote_openbao_agent_paths(secret_id_path, &resolved.service_name);

    let artifact = RemoteBootstrapArtifact {
        openbao_url: state.openbao_url.clone(),
        kv_mount: state.kv_mount.clone(),
        service_name: resolved.service_name.clone(),
        role_id_path: role_id_path.display().to_string(),
        secret_id_path: secret_id_path.display().to_string(),
        eab_file_path: eab_path.display().to_string(),
        agent_config_path: resolved.agent_config.display().to_string(),
        ca_bundle_path: ca_bundle_path.display().to_string(),
        openbao_agent_config_path: openbao_agent_config_path.display().to_string(),
        openbao_agent_template_path: openbao_agent_template_path.display().to_string(),
        openbao_agent_token_path: openbao_agent_token_path.display().to_string(),
        agent_email: DEFAULT_AGENT_EMAIL.to_string(),
        agent_server: DEFAULT_AGENT_SERVER.to_string(),
        agent_domain: resolved.domain.clone(),
        agent_responder_url: DEFAULT_AGENT_RESPONDER_URL.to_string(),
        profile_hostname: resolved.hostname.clone(),
        profile_instance_id: resolved.instance_id.clone().unwrap_or_default(),
        profile_cert_path: resolved.cert_path.display().to_string(),
        profile_key_path: resolved.key_path.display().to_string(),
    };
    let artifact_dir = secrets_dir
        .join(REMOTE_BOOTSTRAP_DIR)
        .join(&resolved.service_name);
    fs_util::ensure_secrets_dir(&artifact_dir).await?;
    let artifact_path = artifact_dir.join(REMOTE_BOOTSTRAP_FILENAME);
    let payload = serde_json::to_string_pretty(&artifact)
        .with_context(|| "Failed to serialize remote bootstrap artifact".to_string())?;
    fs::write(&artifact_path, payload)
        .await
        .with_context(|| messages.error_write_file_failed(&artifact_path.display().to_string()))?;
    fs_util::set_key_permissions(&artifact_path).await?;

    let remote_run_command = render_remote_run_command(&artifact);
    Ok(RemoteBootstrapResult {
        bootstrap_file: artifact_path.display().to_string(),
        remote_run_command,
    })
}

pub(super) async fn write_remote_bootstrap_artifact_from_entry(
    state: &StateFile,
    secrets_dir: &Path,
    entry: &ServiceEntry,
    messages: &Messages,
) -> Result<RemoteBootstrapResult> {
    let secret_id_path = entry.approle.secret_id_path.clone();
    let role_id_path = secret_id_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(SERVICE_ROLE_ID_FILENAME);
    let eab_path = secret_id_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("eab.json");
    let ca_bundle_path = entry
        .cert_path
        .parent()
        .unwrap_or(Path::new("certs"))
        .join("ca-bundle.pem");
    let (openbao_agent_config_path, openbao_agent_template_path, openbao_agent_token_path) =
        remote_openbao_agent_paths(&secret_id_path, &entry.service_name);
    let artifact = RemoteBootstrapArtifact {
        openbao_url: state.openbao_url.clone(),
        kv_mount: state.kv_mount.clone(),
        service_name: entry.service_name.clone(),
        role_id_path: role_id_path.display().to_string(),
        secret_id_path: secret_id_path.display().to_string(),
        eab_file_path: eab_path.display().to_string(),
        agent_config_path: entry.agent_config_path.display().to_string(),
        ca_bundle_path: ca_bundle_path.display().to_string(),
        openbao_agent_config_path: openbao_agent_config_path.display().to_string(),
        openbao_agent_template_path: openbao_agent_template_path.display().to_string(),
        openbao_agent_token_path: openbao_agent_token_path.display().to_string(),
        agent_email: DEFAULT_AGENT_EMAIL.to_string(),
        agent_server: DEFAULT_AGENT_SERVER.to_string(),
        agent_domain: entry.domain.clone(),
        agent_responder_url: DEFAULT_AGENT_RESPONDER_URL.to_string(),
        profile_hostname: entry.hostname.clone(),
        profile_instance_id: entry.instance_id.clone().unwrap_or_default(),
        profile_cert_path: entry.cert_path.display().to_string(),
        profile_key_path: entry.key_path.display().to_string(),
    };
    write_remote_bootstrap_artifact_file(
        secrets_dir,
        entry.service_name.as_str(),
        &artifact,
        messages,
    )
    .await
}

async fn write_remote_bootstrap_artifact_file(
    secrets_dir: &Path,
    service_name: &str,
    artifact: &RemoteBootstrapArtifact,
    messages: &Messages,
) -> Result<RemoteBootstrapResult> {
    let artifact_dir = secrets_dir.join(REMOTE_BOOTSTRAP_DIR).join(service_name);
    fs_util::ensure_secrets_dir(&artifact_dir).await?;
    let artifact_path = artifact_dir.join(REMOTE_BOOTSTRAP_FILENAME);
    let payload = serde_json::to_string_pretty(artifact)
        .with_context(|| "Failed to serialize remote bootstrap artifact".to_string())?;
    fs::write(&artifact_path, payload)
        .await
        .with_context(|| messages.error_write_file_failed(&artifact_path.display().to_string()))?;
    fs_util::set_key_permissions(&artifact_path).await?;
    let remote_run_command = render_remote_run_command(artifact);
    Ok(RemoteBootstrapResult {
        bootstrap_file: artifact_path.display().to_string(),
        remote_run_command,
    })
}

fn render_remote_run_command(artifact: &RemoteBootstrapArtifact) -> String {
    format!(
        "bootroot-remote bootstrap --openbao-url '{}' --kv-mount '{}' --service-name '{}' --role-id-path '{}' --secret-id-path '{}' --eab-file-path '{}' --agent-config-path '{}' --agent-email '{}' --agent-server '{}' --agent-domain '{}' --agent-responder-url '{}' --profile-hostname '{}' --profile-instance-id '{}' --profile-cert-path '{}' --profile-key-path '{}' --ca-bundle-path '{}' --output json",
        artifact.openbao_url,
        artifact.kv_mount,
        artifact.service_name,
        artifact.role_id_path,
        artifact.secret_id_path,
        artifact.eab_file_path,
        artifact.agent_config_path,
        artifact.agent_email,
        artifact.agent_server,
        artifact.agent_domain,
        artifact.agent_responder_url,
        artifact.profile_hostname,
        artifact.profile_instance_id,
        artifact.profile_cert_path,
        artifact.profile_key_path,
        artifact.ca_bundle_path,
    )
}

fn remote_openbao_agent_paths(
    secret_id_path: &Path,
    service_name: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let secret_service_dir = secret_id_path.parent().unwrap_or_else(|| Path::new("."));
    let services_dir = secret_service_dir
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let secrets_dir = services_dir.parent().unwrap_or_else(|| Path::new("."));
    let openbao_service_dir = secrets_dir
        .join(OPENBAO_SERVICE_CONFIG_DIR)
        .join(service_name);
    (
        openbao_service_dir.join(OPENBAO_AGENT_CONFIG_FILENAME),
        openbao_service_dir.join(OPENBAO_AGENT_TEMPLATE_FILENAME),
        openbao_service_dir.join(OPENBAO_AGENT_TOKEN_FILENAME),
    )
}
