use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;
use tokio::fs;

use crate::cli::args::{ServiceAddArgs, ServiceInfoArgs, ServiceSyncStatusArgs};
use crate::cli::output::{
    ServiceAddAppliedPaths, ServiceAddPlan, ServiceAddRemoteBootstrap, ServiceAddSummaryOptions,
    print_service_add_plan, print_service_add_summary, print_service_info_summary,
};
use crate::cli::prompt::Prompt;
use crate::commands::init::{PATH_CA_TRUST, SECRET_ID_TTL, TOKEN_TTL};
use crate::i18n::Messages;
use crate::state::{
    DeliveryMode, DeployType, ServiceEntry, ServiceRoleEntry, ServiceSyncStatus, StateFile,
    SyncApplyStatus,
};
const SERVICE_ROLE_PREFIX: &str = "bootroot-service-";
const SERVICE_KV_BASE: &str = "bootroot/services";
const SERVICE_SECRET_DIR: &str = "services";
const SERVICE_ROLE_ID_FILENAME: &str = "role_id";
const SERVICE_SECRET_ID_FILENAME: &str = "secret_id";
const OPENBAO_SERVICE_CONFIG_DIR: &str = "openbao/services";
const OPENBAO_AGENT_CONFIG_FILENAME: &str = "agent.hcl";
const OPENBAO_AGENT_TEMPLATE_FILENAME: &str = "agent.toml.ctmpl";
const OPENBAO_AGENT_TOKEN_FILENAME: &str = "token";
const REMOTE_BOOTSTRAP_DIR: &str = "remote-bootstrap/services";
const REMOTE_BOOTSTRAP_FILENAME: &str = "bootstrap.json";
const CA_TRUST_KEY: &str = "trusted_ca_sha256";
const MANAGED_PROFILE_BEGIN_PREFIX: &str = "# BEGIN bootroot managed profile:";
const MANAGED_PROFILE_END_PREFIX: &str = "# END bootroot managed profile:";

pub(crate) async fn run_service_add(args: &ServiceAddArgs, messages: &Messages) -> Result<()> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let mut state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;

    let preview = args.dry_run || args.print_only;
    let resolved = resolve_service_add_args(args, messages, preview)?;
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

    if preview {
        run_service_add_preview(&state, &resolved, messages);
        return Ok(());
    }

    run_service_add_apply(&mut state, &state_path, &resolved, messages).await
}

fn run_service_add_preview(state: &StateFile, resolved: &ResolvedServiceAdd, messages: &Messages) {
    let preview_entry = build_preview_service_entry(resolved, state);
    let preview_secret_id_path = state
        .secrets_dir()
        .join(SERVICE_SECRET_DIR)
        .join(&resolved.service_name)
        .join(SERVICE_SECRET_ID_FILENAME);
    print_service_add_summary(
        &preview_entry,
        &preview_secret_id_path,
        ServiceAddSummaryOptions {
            applied: None,
            remote: None,
            trusted_ca_sha256: None,
            show_snippets: true,
            note: Some(messages.service_summary_preview_mode()),
        },
        messages,
    );
}

async fn run_service_add_apply(
    state: &mut StateFile,
    state_path: &Path,
    resolved: &ResolvedServiceAdd,
    messages: &Messages,
) -> Result<()> {
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
    let approle = ensure_service_approle(&client, state, &resolved.service_name, messages).await?;
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
    let applied = if matches!(resolved.delivery_mode, DeliveryMode::LocalFile) {
        Some(apply_local_service_configs(&secrets_dir, resolved, &secret_id_path, messages).await?)
    } else {
        None
    };
    let remote_bootstrap = if matches!(resolved.delivery_mode, DeliveryMode::RemoteBootstrap) {
        Some(
            write_remote_bootstrap_artifact(
                state,
                &secrets_dir,
                resolved,
                &secret_id_path,
                messages,
            )
            .await?,
        )
    } else {
        None
    };

    let entry = ServiceEntry {
        service_name: resolved.service_name.clone(),
        deploy_type: resolved.deploy_type,
        delivery_mode: resolved.delivery_mode,
        sync_status: initial_sync_status(resolved.delivery_mode),
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
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())?;

    print_service_add_summary(
        &entry,
        &secret_id_path,
        ServiceAddSummaryOptions {
            applied: applied.as_ref().map(|result| ServiceAddAppliedPaths {
                agent_config: &result.agent_config,
                openbao_agent_config: &result.openbao_agent_config,
                openbao_agent_template: &result.openbao_agent_template,
            }),
            remote: remote_bootstrap
                .as_ref()
                .map(|result| ServiceAddRemoteBootstrap {
                    bootstrap_file: &result.bootstrap_file,
                    remote_run_command: &result.remote_run_command,
                    control_sync_command: &result.control_sync_command,
                }),
            trusted_ca_sha256: trusted_ca_sha256.as_deref(),
            show_snippets: false,
            note: Some(messages.service_summary_print_only_hint()),
        },
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

pub(crate) fn run_service_sync_status(
    args: &ServiceSyncStatusArgs,
    messages: &Messages,
) -> Result<()> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let mut state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;
    let service_name = args.service_name.clone();
    let summary_contents = std::fs::read_to_string(&args.summary_json).with_context(|| {
        messages.error_read_file_failed(&args.summary_json.display().to_string())
    })?;
    let summary: RemoteApplySummary = serde_json::from_str(&summary_contents)
        .context("Failed to parse remote sync summary JSON")?;
    let secret_id_status = map_remote_status(&summary.secret_id.status)?;
    let eab_status = map_remote_status(&summary.eab.status)?;
    let responder_hmac_status = map_remote_status(&summary.responder_hmac.status)?;
    let trust_sync_status = map_remote_status(&summary.trust_sync.status)?;

    {
        let entry = state
            .services
            .get_mut(&service_name)
            .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(&service_name)))?;
        entry.sync_status.secret_id = secret_id_status;
        entry.sync_status.eab = eab_status;
        entry.sync_status.responder_hmac = responder_hmac_status;
        entry.sync_status.trust_sync = trust_sync_status;
    }

    state
        .save(&state_path)
        .with_context(|| messages.error_serialize_state_failed())?;

    println!("{}", messages.service_sync_status_summary_title());
    println!("{}", messages.service_sync_status_service(&service_name));
    println!(
        "{}",
        messages.service_sync_status_item("secret_id", secret_id_status.as_str())
    );
    println!(
        "{}",
        messages.service_sync_status_item("eab", eab_status.as_str())
    );
    println!(
        "{}",
        messages.service_sync_status_item("responder_hmac", responder_hmac_status.as_str())
    );
    println!(
        "{}",
        messages.service_sync_status_item("trust_sync", trust_sync_status.as_str())
    );
    Ok(())
}

#[derive(Debug, serde::Deserialize)]
struct RemoteApplySummary {
    secret_id: RemoteApplyItem,
    eab: RemoteApplyItem,
    responder_hmac: RemoteApplyItem,
    trust_sync: RemoteApplyItem,
}

#[derive(Debug, serde::Deserialize)]
struct RemoteApplyItem {
    status: String,
}

fn map_remote_status(value: &str) -> Result<SyncApplyStatus> {
    match value {
        "applied" | "unchanged" => Ok(SyncApplyStatus::Applied),
        "failed" => Ok(SyncApplyStatus::Failed),
        "none" => Ok(SyncApplyStatus::None),
        "pending" => Ok(SyncApplyStatus::Pending),
        "expired" => Ok(SyncApplyStatus::Expired),
        _ => anyhow::bail!("Unsupported remote sync status: {value}"),
    }
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

struct LocalApplyResult {
    agent_config: String,
    openbao_agent_config: String,
    openbao_agent_template: String,
}

struct RemoteBootstrapResult {
    bootstrap_file: String,
    remote_run_command: String,
    control_sync_command: String,
}

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
}

async fn apply_local_service_configs(
    secrets_dir: &Path,
    resolved: &ResolvedServiceAdd,
    secret_id_path: &Path,
    messages: &Messages,
) -> Result<LocalApplyResult> {
    let profile = render_managed_profile_block(resolved);
    let current = if resolved.agent_config.exists() {
        fs::read_to_string(&resolved.agent_config)
            .await
            .with_context(|| {
                messages.error_read_file_failed(&resolved.agent_config.display().to_string())
            })?
    } else {
        String::new()
    };
    let next = upsert_managed_profile(&current, &resolved.service_name, &profile);
    fs::write(&resolved.agent_config, &next)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&resolved.agent_config.display().to_string())
        })?;
    fs_util::set_key_permissions(&resolved.agent_config).await?;

    let openbao_service_dir = secrets_dir
        .join(OPENBAO_SERVICE_CONFIG_DIR)
        .join(&resolved.service_name);
    fs_util::ensure_secrets_dir(&openbao_service_dir).await?;

    let template_path = openbao_service_dir.join(OPENBAO_AGENT_TEMPLATE_FILENAME);
    fs::write(&template_path, next)
        .await
        .with_context(|| messages.error_write_file_failed(&template_path.display().to_string()))?;
    fs_util::set_key_permissions(&template_path).await?;

    let role_id_path = secret_id_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(SERVICE_ROLE_ID_FILENAME);
    let token_path = openbao_service_dir.join(OPENBAO_AGENT_TOKEN_FILENAME);
    let agent_config_path = openbao_service_dir.join(OPENBAO_AGENT_CONFIG_FILENAME);
    let agent_hcl = render_openbao_agent_config(
        &role_id_path,
        secret_id_path,
        &token_path,
        &template_path,
        &resolved.agent_config,
    );
    fs::write(&agent_config_path, agent_hcl)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&agent_config_path.display().to_string())
        })?;
    fs_util::set_key_permissions(&agent_config_path).await?;

    Ok(LocalApplyResult {
        agent_config: resolved.agent_config.display().to_string(),
        openbao_agent_config: agent_config_path.display().to_string(),
        openbao_agent_template: template_path.display().to_string(),
    })
}

fn render_managed_profile_block(args: &ResolvedServiceAdd) -> String {
    let instance_id = args.instance_id.as_deref().unwrap_or_default();
    let mut lines = Vec::new();
    lines.push(format!(
        "{MANAGED_PROFILE_BEGIN_PREFIX} {}",
        args.service_name
    ));
    lines.push("[[profiles]]".to_string());
    lines.push(format!("service_name = \"{}\"", args.service_name));
    lines.push(format!("instance_id = \"{instance_id}\""));
    lines.push(format!("hostname = \"{}\"", args.hostname));
    lines.push(String::new());
    lines.push("[profiles.paths]".to_string());
    lines.push(format!("cert = \"{}\"", args.cert_path.display()));
    lines.push(format!("key = \"{}\"", args.key_path.display()));
    lines.push(format!(
        "{MANAGED_PROFILE_END_PREFIX} {}",
        args.service_name
    ));
    format!("{}\n", lines.join("\n"))
}

fn upsert_managed_profile(contents: &str, service_name: &str, replacement: &str) -> String {
    let begin_marker = format!("{MANAGED_PROFILE_BEGIN_PREFIX} {service_name}");
    let end_marker = format!("{MANAGED_PROFILE_END_PREFIX} {service_name}");
    if let Some(begin) = contents.find(&begin_marker)
        && let Some(end_relative) = contents[begin..].find(&end_marker)
    {
        let end = begin + end_relative + end_marker.len();
        let suffix = contents[end..]
            .strip_prefix('\n')
            .unwrap_or(&contents[end..]);
        let mut updated = String::new();
        updated.push_str(&contents[..begin]);
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(replacement);
        if !suffix.is_empty() && !replacement.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(suffix);
        return updated;
    }

    let mut updated = contents.trim_end().to_string();
    if !updated.is_empty() {
        updated.push_str("\n\n");
    }
    updated.push_str(replacement);
    updated
}

fn render_openbao_agent_config(
    role_id_path: &Path,
    secret_id_path: &Path,
    token_path: &Path,
    template_path: &Path,
    destination_path: &Path,
) -> String {
    format!(
        r#"auto_auth {{
  method "approle" {{
    mount_path = "auth/approle"
    config = {{
      role_id_file_path = "{role_id_path}"
      secret_id_file_path = "{secret_id_path}"
    }}
  }}
  sink "file" {{
    config = {{
      path = "{token_path}"
    }}
  }}
}}

template {{
  source = "{template_path}"
  destination = "{destination_path}"
  perms = "0600"
}}
"#,
        role_id_path = role_id_path.display(),
        secret_id_path = secret_id_path.display(),
        token_path = token_path.display(),
        template_path = template_path.display(),
        destination_path = destination_path.display(),
    )
}

async fn write_remote_bootstrap_artifact(
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

    let artifact = RemoteBootstrapArtifact {
        openbao_url: state.openbao_url.clone(),
        kv_mount: state.kv_mount.clone(),
        service_name: resolved.service_name.clone(),
        role_id_path: role_id_path.display().to_string(),
        secret_id_path: secret_id_path.display().to_string(),
        eab_file_path: eab_path.display().to_string(),
        agent_config_path: resolved.agent_config.display().to_string(),
        ca_bundle_path: ca_bundle_path.display().to_string(),
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

    let remote_summary_path = format!("{}-remote-summary.json", resolved.service_name);
    let remote_run_command = format!(
        "bootroot-remote --openbao-url '{}' --kv-mount '{}' --service-name '{}' --role-id-path '{}' --secret-id-path '{}' --eab-file-path '{}' --agent-config-path '{}' --ca-bundle-path '{}' --output json > {}",
        artifact.openbao_url,
        artifact.kv_mount,
        artifact.service_name,
        artifact.role_id_path,
        artifact.secret_id_path,
        artifact.eab_file_path,
        artifact.agent_config_path,
        artifact.ca_bundle_path,
        remote_summary_path
    );
    let control_sync_command = format!(
        "bootroot service sync-status --service-name '{}' --summary-json '{}'",
        resolved.service_name, remote_summary_path
    );
    Ok(RemoteBootstrapResult {
        bootstrap_file: artifact_path.display().to_string(),
        remote_run_command,
        control_sync_command,
    })
}

fn initial_sync_status(delivery_mode: DeliveryMode) -> ServiceSyncStatus {
    match delivery_mode {
        DeliveryMode::LocalFile => ServiceSyncStatus::default(),
        DeliveryMode::RemoteBootstrap => ServiceSyncStatus {
            secret_id: SyncApplyStatus::Pending,
            eab: SyncApplyStatus::Pending,
            responder_hmac: SyncApplyStatus::Pending,
            trust_sync: SyncApplyStatus::Pending,
        },
    }
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

fn build_preview_service_entry(resolved: &ResolvedServiceAdd, state: &StateFile) -> ServiceEntry {
    let preview_secret_id_path = state
        .secrets_dir()
        .join(SERVICE_SECRET_DIR)
        .join(&resolved.service_name)
        .join(SERVICE_SECRET_ID_FILENAME);
    ServiceEntry {
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
            role_name: service_role_name(&resolved.service_name),
            role_id: "dry-run".to_string(),
            secret_id_path: preview_secret_id_path,
            policy_name: service_policy_name(&resolved.service_name),
        },
    }
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
    preview: bool,
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
        matches!(delivery_mode, DeliveryMode::RemoteBootstrap),
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

    let root_token = if preview {
        String::new()
    } else if let Some(value) = args.root_token.root_token.clone() {
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

    #[test]
    fn test_upsert_managed_profile_is_idempotent() {
        let args = ResolvedServiceAdd {
            service_name: "edge-proxy".to_string(),
            deploy_type: DeployType::Daemon,
            delivery_mode: DeliveryMode::LocalFile,
            hostname: "edge-node-01".to_string(),
            domain: "trusted.domain".to_string(),
            agent_config: PathBuf::from("agent.toml"),
            cert_path: PathBuf::from("certs/edge-proxy.crt"),
            key_path: PathBuf::from("certs/edge-proxy.key"),
            instance_id: Some("001".to_string()),
            container_name: None,
            root_token: "root".to_string(),
            notes: None,
        };
        let block = render_managed_profile_block(&args);
        let once = upsert_managed_profile("", "edge-proxy", &block);
        let twice = upsert_managed_profile(&once, "edge-proxy", &block);
        assert_eq!(once, twice);
    }

    #[test]
    fn test_map_remote_status_treats_unchanged_as_applied() {
        let status = map_remote_status("unchanged").expect("map status");
        assert_eq!(status, SyncApplyStatus::Applied);
    }
}
