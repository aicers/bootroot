use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;
use tokio::fs;

use crate::cli::args::{ServiceAddArgs, ServiceInfoArgs};
use crate::cli::output::{
    ServiceAddAppliedPaths, ServiceAddPlan, ServiceAddRemoteBootstrap, ServiceAddSummaryOptions,
    print_service_add_plan, print_service_add_summary, print_service_info_summary,
};
use crate::cli::prompt::Prompt;
use crate::commands::init::{
    PATH_AGENT_EAB, PATH_CA_TRUST, PATH_RESPONDER_HMAC, SECRET_ID_TTL, TOKEN_TTL,
};
use crate::commands::openbao_auth::{
    RuntimeAuthResolved, authenticate_openbao_client, resolve_runtime_auth,
    resolve_runtime_auth_optional,
};
use crate::i18n::Messages;
use crate::state::{DeliveryMode, DeployType, ServiceEntry, ServiceRoleEntry, StateFile};
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
const SERVICE_SECRET_ID_KEY: &str = "secret_id";
const SERVICE_EAB_KID_KEY: &str = "kid";
const SERVICE_EAB_HMAC_KEY: &str = "hmac";
const SERVICE_RESPONDER_HMAC_KEY: &str = "hmac";
const SERVICE_CA_BUNDLE_PEM_KEY: &str = "ca_bundle_pem";
const DEFAULT_AGENT_EMAIL: &str = "admin@example.com";
const DEFAULT_AGENT_SERVER: &str = "https://localhost:9000/acme/acme/directory";
const DEFAULT_AGENT_RESPONDER_URL: &str = "http://127.0.0.1:8080";

pub(crate) async fn run_service_add(args: &ServiceAddArgs, messages: &Messages) -> Result<()> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let mut state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;

    let preview = args.dry_run || args.print_only;
    let resolved = resolve_service_add_args(args, messages, preview)?;

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

    if let Some(existing) = state.services.get(&resolved.service_name).cloned() {
        if is_idempotent_remote_rerun(&existing, &resolved) {
            return run_service_add_remote_idempotent(&state, &existing, messages).await;
        }
        anyhow::bail!(messages.error_service_duplicate(&resolved.service_name));
    }

    if preview {
        run_service_add_preview(&state, &resolved, messages).await;
        return Ok(());
    }

    run_service_add_apply(&mut state, &state_path, &resolved, messages).await
}

async fn run_service_add_preview(
    state: &StateFile,
    resolved: &ResolvedServiceAdd,
    messages: &Messages,
) {
    let preview_entry = build_preview_service_entry(resolved, state);
    let preview_secret_id_path = state
        .secrets_dir()
        .join(SERVICE_SECRET_DIR)
        .join(&resolved.service_name)
        .join(SERVICE_SECRET_ID_FILENAME);
    let mut note = messages.service_summary_preview_mode().to_string();
    let mut trusted_ca_sha256: Option<Vec<String>> = None;
    let Some(auth) = resolved.runtime_auth.as_ref() else {
        note.push('\n');
        note.push_str(messages.service_summary_preview_trust_skipped_no_token());
        print_service_add_summary(
            &preview_entry,
            &preview_secret_id_path,
            ServiceAddSummaryOptions {
                applied: None,
                remote: None,
                trusted_ca_sha256: None,
                show_snippets: true,
                note: Some(note),
            },
            messages,
        );
        return;
    };
    {
        let mut client = match OpenBaoClient::new(&state.openbao_url)
            .with_context(|| messages.error_openbao_client_create_failed())
        {
            Ok(client) => client,
            Err(err) => {
                note.push('\n');
                note.push_str(
                    &messages.service_summary_preview_trust_lookup_failed(err.to_string().as_str()),
                );
                print_service_add_summary(
                    &preview_entry,
                    &preview_secret_id_path,
                    ServiceAddSummaryOptions {
                        applied: None,
                        remote: None,
                        trusted_ca_sha256: None,
                        show_snippets: true,
                        note: Some(note),
                    },
                    messages,
                );
                return;
            }
        };
        match authenticate_openbao_client(&mut client, auth, messages).await {
            Ok(()) => match read_ca_trust_material(&client, &state.kv_mount, messages).await {
                Ok(Some(material)) => trusted_ca_sha256 = Some(material.trusted_ca_sha256),
                Ok(None) => {
                    note.push('\n');
                    note.push_str(messages.service_summary_preview_trust_not_found());
                }
                Err(err) => {
                    note.push('\n');
                    note.push_str(
                        &messages
                            .service_summary_preview_trust_lookup_failed(err.to_string().as_str()),
                    );
                }
            },
            Err(err) => {
                note.push('\n');
                note.push_str(
                    &messages.service_summary_preview_trust_lookup_failed(err.to_string().as_str()),
                );
            }
        }
    }
    print_service_add_summary(
        &preview_entry,
        &preview_secret_id_path,
        ServiceAddSummaryOptions {
            applied: None,
            remote: None,
            trusted_ca_sha256: trusted_ca_sha256.as_deref(),
            show_snippets: true,
            note: Some(note),
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
    let auth = resolved
        .runtime_auth
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("OpenBao auth is required"))?;

    let mut client = OpenBaoClient::new(&state.openbao_url)
        .with_context(|| messages.error_openbao_client_create_failed())?;
    authenticate_openbao_client(&mut client, auth, messages).await?;

    let ca_trust_material = read_ca_trust_material(&client, &state.kv_mount, messages).await?;
    let trusted_ca_sha256 = ca_trust_material
        .as_ref()
        .map(|material| material.trusted_ca_sha256.as_slice());
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
    sync_remote_service_bundle_if_needed(&client, state, resolved, &approle.secret_id, messages)
        .await?;

    let applied = if matches!(resolved.delivery_mode, DeliveryMode::LocalFile) {
        Some(
            apply_local_service_configs(
                &secrets_dir,
                resolved,
                &secret_id_path,
                ca_trust_material.as_ref(),
                messages,
            )
            .await?,
        )
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

    let entry = build_service_entry(resolved, approle, &secret_id_path);

    state
        .services
        .insert(resolved.service_name.clone(), entry.clone());
    state
        .save(state_path)
        .with_context(|| messages.error_serialize_state_failed())?;

    print_service_add_apply_summary(
        &entry,
        &secret_id_path,
        applied.as_ref(),
        remote_bootstrap.as_ref(),
        trusted_ca_sha256,
        messages,
    );
    Ok(())
}

fn build_service_entry(
    resolved: &ResolvedServiceAdd,
    approle: ServiceAppRoleMaterialized,
    secret_id_path: &Path,
) -> ServiceEntry {
    ServiceEntry {
        service_name: resolved.service_name.clone(),
        deploy_type: resolved.deploy_type,
        delivery_mode: resolved.delivery_mode,
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
            secret_id_path: secret_id_path.to_path_buf(),
            policy_name: approle.policy_name,
        },
    }
}

fn print_service_add_apply_summary(
    entry: &ServiceEntry,
    secret_id_path: &Path,
    applied: Option<&LocalApplyResult>,
    remote_bootstrap: Option<&RemoteBootstrapResult>,
    trusted_ca_sha256: Option<&[String]>,
    messages: &Messages,
) {
    print_service_add_summary(
        entry,
        secret_id_path,
        ServiceAddSummaryOptions {
            applied: applied.map(|result| ServiceAddAppliedPaths {
                agent_config: &result.agent_config,
                openbao_agent_config: &result.openbao_agent_config,
                openbao_agent_template: &result.openbao_agent_template,
            }),
            remote: remote_bootstrap.map(|result| ServiceAddRemoteBootstrap {
                bootstrap_file: &result.bootstrap_file,
                remote_run_command: &result.remote_run_command,
            }),
            trusted_ca_sha256,
            show_snippets: true,
            note: None,
        },
        messages,
    );
}

async fn sync_remote_service_bundle_if_needed(
    client: &OpenBaoClient,
    state: &StateFile,
    resolved: &ResolvedServiceAdd,
    secret_id: &str,
    messages: &Messages,
) -> Result<()> {
    if !matches!(resolved.delivery_mode, DeliveryMode::RemoteBootstrap) {
        return Ok(());
    }
    let material = read_remote_sync_material(client, &state.kv_mount, messages).await?;
    write_remote_service_sync_bundle(
        client,
        &state.kv_mount,
        &resolved.service_name,
        secret_id,
        &material,
        messages,
    )
    .await
}

async fn run_service_add_remote_idempotent(
    state: &StateFile,
    entry: &ServiceEntry,
    messages: &Messages,
) -> Result<()> {
    let secrets_dir = state.secrets_dir();
    let remote_bootstrap =
        write_remote_bootstrap_artifact_from_entry(state, &secrets_dir, entry, messages).await?;
    print_service_add_summary(
        entry,
        &entry.approle.secret_id_path,
        ServiceAddSummaryOptions {
            applied: None,
            remote: Some(ServiceAddRemoteBootstrap {
                bootstrap_file: &remote_bootstrap.bootstrap_file,
                remote_run_command: &remote_bootstrap.remote_run_command,
            }),
            trusted_ca_sha256: None,
            show_snippets: true,
            note: Some(
                messages
                    .service_summary_remote_idempotent_hint()
                    .to_string(),
            ),
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

struct RemoteSyncMaterial {
    eab_kid: String,
    eab_hmac: String,
    responder_hmac: String,
    trusted_ca_sha256: Vec<String>,
    ca_bundle_pem: Option<String>,
}

struct CaTrustMaterial {
    trusted_ca_sha256: Vec<String>,
    ca_bundle_pem: Option<String>,
}

async fn apply_local_service_configs(
    secrets_dir: &Path,
    resolved: &ResolvedServiceAdd,
    secret_id_path: &Path,
    ca_trust_material: Option<&CaTrustMaterial>,
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
    let with_profile = upsert_managed_profile(&current, &resolved.service_name, &profile);
    let mut next = with_profile;
    if let Some(material) = ca_trust_material {
        let ca_bundle_path = resolved
            .cert_path
            .parent()
            .unwrap_or(Path::new("certs"))
            .join("ca-bundle.pem");
        let trust_updates = build_trust_updates(&material.trusted_ca_sha256, &ca_bundle_path);
        next = upsert_toml_section_keys(&next, "trust", &trust_updates);
        if let Some(bundle_pem) = material.ca_bundle_pem.as_deref() {
            write_local_ca_bundle(&ca_bundle_path, bundle_pem, messages).await?;
        }
    }
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
    fs::write(&template_path, &next)
        .await
        .with_context(|| messages.error_write_file_failed(&template_path.display().to_string()))?;
    fs_util::set_key_permissions(&template_path).await?;

    let role_id_path = secret_id_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(SERVICE_ROLE_ID_FILENAME);
    let token_path = openbao_service_dir.join(OPENBAO_AGENT_TOKEN_FILENAME);
    if !token_path.exists() {
        fs::write(&token_path, "")
            .await
            .with_context(|| messages.error_write_file_failed(&token_path.display().to_string()))?;
    }
    fs_util::set_key_permissions(&token_path).await?;
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

async fn write_local_ca_bundle(path: &Path, bundle_pem: &str, messages: &Messages) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs_util::ensure_secrets_dir(parent).await?;
    }
    let contents = if bundle_pem.ends_with('\n') {
        bundle_pem.to_string()
    } else {
        format!("{bundle_pem}\n")
    };
    fs::write(path, contents)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    fs_util::set_key_permissions(path).await?;
    Ok(())
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

fn build_trust_updates(
    fingerprints: &[String],
    ca_bundle_path: &Path,
) -> Vec<(&'static str, String)> {
    vec![
        ("ca_bundle_path", ca_bundle_path.display().to_string()),
        (
            CA_TRUST_KEY,
            format!(
                "[{}]",
                fingerprints
                    .iter()
                    .map(|value| format!("\"{value}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ),
    ]
}

fn upsert_toml_section_keys(contents: &str, section: &str, pairs: &[(&str, String)]) -> String {
    let mut output = String::new();
    let mut section_found = false;
    let mut in_section = false;
    let mut seen_keys = std::collections::BTreeSet::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if is_section_header(trimmed) {
            if in_section {
                output.push_str(&render_missing_keys(pairs, &seen_keys));
            }
            in_section = trimmed == format!("[{section}]");
            if in_section {
                section_found = true;
                seen_keys.clear();
            }
            output.push_str(line);
            output.push('\n');
            continue;
        }

        if in_section
            && let Some((key, indent)) = parse_key_line(line, pairs)
            && let Some(value) = pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.as_str())
        {
            output.push_str(&format_key_line(&indent, key, value));
            seen_keys.insert(key.to_string());
            continue;
        }

        output.push_str(line);
        output.push('\n');
    }

    if in_section {
        output.push_str(&render_missing_keys(pairs, &seen_keys));
    }

    if !section_found {
        if !output.ends_with('\n') {
            output.push('\n');
        }
        output.push('[');
        output.push_str(section);
        output.push_str("]\n");
        for (key, value) in pairs {
            output.push_str(&format_key_line("", key, value));
        }
    }

    output
}

fn is_section_header(line: &str) -> bool {
    line.starts_with('[') && line.ends_with(']')
}

fn parse_key_line<'a>(line: &'a str, pairs: &[(&'a str, String)]) -> Option<(&'a str, String)> {
    for (key, _) in pairs {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&format!("{key} =")) || trimmed.starts_with(&format!("{key}=")) {
            let indent = line
                .chars()
                .take_while(|ch| ch.is_whitespace())
                .collect::<String>();
            return Some((key, indent));
        }
    }
    None
}

fn format_key_line(indent: &str, key: &str, value: &str) -> String {
    let rendered = if value.starts_with('[') {
        value.to_string()
    } else {
        format!("\"{value}\"")
    };
    format!("{indent}{key} = {rendered}\n")
}

fn render_missing_keys(
    pairs: &[(&str, String)],
    seen_keys: &std::collections::BTreeSet<String>,
) -> String {
    let mut extra = String::new();
    for (key, value) in pairs {
        if !seen_keys.contains(*key) {
            extra.push_str(&format_key_line("", key, value));
        }
    }
    extra
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

fn is_idempotent_remote_rerun(entry: &ServiceEntry, resolved: &ResolvedServiceAdd) -> bool {
    matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap)
        && matches!(resolved.delivery_mode, DeliveryMode::RemoteBootstrap)
        && entry.deploy_type == resolved.deploy_type
        && entry.hostname == resolved.hostname
        && entry.domain == resolved.domain
        && entry.agent_config_path == resolved.agent_config
        && entry.cert_path == resolved.cert_path
        && entry.key_path == resolved.key_path
        && entry.instance_id == resolved.instance_id
        && entry.container_name == resolved.container_name
        && entry.notes == resolved.notes
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

async fn write_remote_bootstrap_artifact_from_entry(
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

fn read_required_string(
    value: &serde_json::Value,
    key: &str,
    missing_message: &str,
) -> Result<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!(missing_message.to_string()))
}

async fn read_remote_sync_material(
    client: &OpenBaoClient,
    kv_mount: &str,
    messages: &Messages,
) -> Result<RemoteSyncMaterial> {
    let eab = client
        .read_kv(kv_mount, PATH_AGENT_EAB)
        .await
        .with_context(|| {
            format!(
                "{} ({PATH_AGENT_EAB})",
                messages.error_openbao_kv_read_failed()
            )
        })?;
    let responder_hmac = client
        .read_kv(kv_mount, PATH_RESPONDER_HMAC)
        .await
        .with_context(|| {
            format!(
                "{} ({PATH_RESPONDER_HMAC})",
                messages.error_openbao_kv_read_failed()
            )
        })?;
    let trust = client
        .read_kv(kv_mount, PATH_CA_TRUST)
        .await
        .with_context(|| {
            format!(
                "{} ({PATH_CA_TRUST})",
                messages.error_openbao_kv_read_failed()
            )
        })?;
    let trusted_ca_sha256 = parse_trusted_ca_list(
        trust
            .get(CA_TRUST_KEY)
            .ok_or_else(|| anyhow::anyhow!(messages.error_ca_trust_missing(CA_TRUST_KEY)))?,
        messages,
    )?;
    if trusted_ca_sha256.is_empty() {
        anyhow::bail!(messages.error_ca_trust_empty());
    }
    Ok(RemoteSyncMaterial {
        eab_kid: read_required_string(
            &eab,
            SERVICE_EAB_KID_KEY,
            "OpenBao EAB data missing key: kid",
        )?,
        eab_hmac: read_required_string(
            &eab,
            SERVICE_EAB_HMAC_KEY,
            "OpenBao EAB data missing key: hmac",
        )?,
        responder_hmac: read_required_string(
            &responder_hmac,
            "value",
            "OpenBao responder HMAC data missing key: value",
        )?,
        trusted_ca_sha256,
        ca_bundle_pem: trust
            .get(SERVICE_CA_BUNDLE_PEM_KEY)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
    })
}

async fn write_remote_service_sync_bundle(
    client: &OpenBaoClient,
    kv_mount: &str,
    service_name: &str,
    secret_id: &str,
    material: &RemoteSyncMaterial,
    messages: &Messages,
) -> Result<()> {
    let base = format!("{SERVICE_KV_BASE}/{service_name}");
    client
        .write_kv(
            kv_mount,
            &format!("{base}/secret_id"),
            serde_json::json!({ SERVICE_SECRET_ID_KEY: secret_id }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    client
        .write_kv(
            kv_mount,
            &format!("{base}/eab"),
            serde_json::json!({
                SERVICE_EAB_KID_KEY: &material.eab_kid,
                SERVICE_EAB_HMAC_KEY: &material.eab_hmac,
            }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    client
        .write_kv(
            kv_mount,
            &format!("{base}/http_responder_hmac"),
            serde_json::json!({ SERVICE_RESPONDER_HMAC_KEY: &material.responder_hmac }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    let mut trust_payload = serde_json::json!({
        CA_TRUST_KEY: &material.trusted_ca_sha256,
    });
    if let Some(bundle) = material.ca_bundle_pem.as_deref() {
        trust_payload[SERVICE_CA_BUNDLE_PEM_KEY] = serde_json::Value::String(bundle.to_string());
    }
    client
        .write_kv(kv_mount, &format!("{base}/trust"), trust_payload)
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    Ok(())
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
    pub(crate) runtime_auth: Option<RuntimeAuthResolved>,
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
        false,
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

    let runtime_auth = if preview {
        resolve_runtime_auth_optional(&args.runtime_auth)?
    } else {
        Some(resolve_runtime_auth(&args.runtime_auth, true, messages)?)
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
        runtime_auth,
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

async fn read_ca_trust_material(
    client: &OpenBaoClient,
    kv_mount: &str,
    messages: &Messages,
) -> Result<Option<CaTrustMaterial>> {
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
    let ca_bundle_pem = data
        .get(SERVICE_CA_BUNDLE_PEM_KEY)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    Ok(Some(CaTrustMaterial {
        trusted_ca_sha256: fingerprints,
        ca_bundle_pem,
    }))
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
            runtime_auth: None,
            notes: None,
        };
        let block = render_managed_profile_block(&args);
        let once = upsert_managed_profile("", "edge-proxy", &block);
        let twice = upsert_managed_profile(&once, "edge-proxy", &block);
        assert_eq!(once, twice);
    }

    #[test]
    fn test_upsert_toml_section_keys_adds_and_updates_trust_section_idempotently() {
        let updates = build_trust_updates(
            &["a".repeat(64), "b".repeat(64)],
            Path::new("certs/ca-bundle.pem"),
        );
        let original = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let once = upsert_toml_section_keys(original, "trust", &updates);
        let twice = upsert_toml_section_keys(&once, "trust", &updates);

        assert_eq!(once, twice);
        assert!(once.contains("[trust]"));
        assert!(once.contains("ca_bundle_path = \"certs/ca-bundle.pem\""));
        assert!(once.contains("trusted_ca_sha256 = ["));
    }

    #[test]
    fn test_upsert_toml_section_keys_preserves_existing_unmanaged_lines() {
        let updates = vec![("ca_bundle_path", "certs/ca.pem".to_string())];
        let original = "[trust]\nextra = true\n";
        let output = upsert_toml_section_keys(original, "trust", &updates);

        assert!(output.contains("extra = true"));
        assert!(output.contains("ca_bundle_path = \"certs/ca.pem\""));
    }
}
