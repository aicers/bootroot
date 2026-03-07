mod approle;
mod local_config;
mod remote_bootstrap;
mod resolve;
mod secrets;

use std::path::Path;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use crate::cli::args::{ServiceAddArgs, ServiceInfoArgs};
use crate::cli::output::{
    ServiceAddAppliedPaths, ServiceAddPlan, ServiceAddRemoteBootstrap, ServiceAddSummaryOptions,
    print_service_add_plan, print_service_add_summary, print_service_info_summary,
};
use crate::commands::openbao_auth::authenticate_openbao_client;
use crate::i18n::Messages;
use crate::state::{DeliveryMode, ServiceEntry, ServiceRoleEntry, StateFile};

pub(super) const SERVICE_ROLE_PREFIX: &str = "bootroot-service-";
pub(super) const SERVICE_SECRET_DIR: &str = "services";
pub(super) const SERVICE_ROLE_ID_FILENAME: &str = "role_id";
pub(super) const SERVICE_SECRET_ID_FILENAME: &str = "secret_id";
pub(super) const OPENBAO_SERVICE_CONFIG_DIR: &str = "openbao/services";
pub(super) const OPENBAO_AGENT_CONFIG_FILENAME: &str = "agent.hcl";
pub(super) const OPENBAO_AGENT_TEMPLATE_FILENAME: &str = "agent.toml.ctmpl";
pub(super) const OPENBAO_AGENT_TOKEN_FILENAME: &str = "token";
pub(super) const REMOTE_BOOTSTRAP_DIR: &str = "remote-bootstrap/services";
pub(super) const REMOTE_BOOTSTRAP_FILENAME: &str = "bootstrap.json";
pub(super) const MANAGED_PROFILE_BEGIN_PREFIX: &str = "# BEGIN bootroot managed profile:";
pub(super) const MANAGED_PROFILE_END_PREFIX: &str = "# END bootroot managed profile:";
pub(super) const SERVICE_CA_BUNDLE_PEM_KEY: &str = "ca_bundle_pem";
pub(super) const DEFAULT_AGENT_EMAIL: &str = "admin@example.com";
pub(super) const DEFAULT_AGENT_SERVER: &str = "https://localhost:9000/acme/acme/directory";
pub(super) const DEFAULT_AGENT_RESPONDER_URL: &str = "http://127.0.0.1:8080";
pub(super) const SIDECAR_STATIC_SECRET_RENDER_INTERVAL: &str = "30s";

pub(super) struct ServiceAppRoleMaterialized {
    pub(super) role_name: String,
    pub(super) role_id: String,
    pub(super) secret_id: String,
    pub(super) policy_name: String,
}

pub(super) struct LocalApplyResult {
    agent_config: String,
    openbao_agent_config: String,
    openbao_agent_template: String,
}

pub(super) struct RemoteBootstrapResult {
    bootstrap_file: String,
    remote_run_command: String,
}

pub(super) struct ServiceSyncMaterial {
    pub(super) eab_kid: Option<String>,
    pub(super) eab_hmac: Option<String>,
    pub(super) responder_hmac: String,
    pub(super) trusted_ca_sha256: Vec<String>,
    pub(super) ca_bundle_pem: Option<String>,
}

pub(super) struct CaTrustMaterial {
    pub(super) trusted_ca_sha256: Vec<String>,
    pub(super) ca_bundle_pem: Option<String>,
}

pub(crate) use resolve::ResolvedServiceAdd;

pub(crate) async fn run_service_add(args: &ServiceAddArgs, messages: &Messages) -> Result<()> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let mut state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;

    let preview = args.dry_run || args.print_only;
    let resolved = resolve::resolve_service_add_args(args, messages, preview)?;

    resolve::validate_service_add(&resolved, messages)?;

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
            Ok(()) => {
                match secrets::read_ca_trust_material(&client, &state.kv_mount, messages).await {
                    Ok(Some(material)) => trusted_ca_sha256 = Some(material.trusted_ca_sha256),
                    Ok(None) => {
                        note.push('\n');
                        note.push_str(messages.service_summary_preview_trust_not_found());
                    }
                    Err(err) => {
                        note.push('\n');
                        note.push_str(
                            &messages.service_summary_preview_trust_lookup_failed(
                                err.to_string().as_str(),
                            ),
                        );
                    }
                }
            }
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

    let ca_trust_material =
        secrets::read_ca_trust_material(&client, &state.kv_mount, messages).await?;
    let trusted_ca_sha256 = ca_trust_material
        .as_ref()
        .map(|material| material.trusted_ca_sha256.as_slice());
    let approle_result =
        approle::ensure_service_approle(&client, state, &resolved.service_name, messages).await?;
    let secrets_dir = state.secrets_dir();
    approle::write_role_id_file(
        secrets_dir,
        &resolved.service_name,
        &approle_result.role_id,
        messages,
    )
    .await?;
    let secret_id_path = approle::write_secret_id_file(
        secrets_dir,
        &resolved.service_name,
        &approle_result.secret_id,
        messages,
    )
    .await?;
    secrets::sync_service_kv_bundle(
        &client,
        state,
        resolved,
        &approle_result.secret_id,
        messages,
    )
    .await?;

    let applied = if matches!(resolved.delivery_mode, DeliveryMode::LocalFile) {
        Some(
            local_config::apply_local_service_configs(
                secrets_dir,
                resolved,
                &secret_id_path,
                ca_trust_material.as_ref(),
                &state.kv_mount,
                &state.openbao_url,
                messages,
            )
            .await?,
        )
    } else {
        None
    };
    let remote_bootstrap_result = if matches!(resolved.delivery_mode, DeliveryMode::RemoteBootstrap)
    {
        Some(
            remote_bootstrap::write_remote_bootstrap_artifact(
                state,
                secrets_dir,
                resolved,
                &secret_id_path,
                messages,
            )
            .await?,
        )
    } else {
        None
    };

    let entry = build_service_entry(resolved, approle_result, &secret_id_path);

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
        remote_bootstrap_result.as_ref(),
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

async fn run_service_add_remote_idempotent(
    state: &StateFile,
    entry: &ServiceEntry,
    messages: &Messages,
) -> Result<()> {
    let secrets_dir = state.secrets_dir();
    let remote_bootstrap = remote_bootstrap::write_remote_bootstrap_artifact_from_entry(
        state,
        secrets_dir,
        entry,
        messages,
    )
    .await?;
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
            role_name: approle::service_role_name(&resolved.service_name),
            role_id: "dry-run".to_string(),
            secret_id_path: preview_secret_id_path,
            policy_name: approle::service_policy_name(&resolved.service_name),
        },
    }
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
