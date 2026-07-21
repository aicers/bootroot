mod approle;
mod local_config;
mod remote_bootstrap;
mod remove;
pub(crate) mod resolve;
mod secrets;

use std::path::Path;

use anyhow::{Context, Result};
use bootroot::openbao::{OpenBaoClient, SecretIdOptions};

use crate::cli::args::{ServiceAddArgs, ServiceInfoArgs, ServiceUpdateArgs};
use crate::cli::output::{
    ServiceAddAppliedPaths, ServiceAddPlan, ServiceAddRemoteBootstrap, ServiceAddSummaryOptions,
    print_service_add_plan, print_service_add_summary, print_service_info_summary,
};
use crate::commands::constants::DEFAULT_SECRET_ID_WRAP_TTL;
use crate::commands::dns_alias::register_dns_alias;
use crate::commands::init::validate_secret_id_ttl;
use crate::commands::openbao_auth::authenticate_openbao_client;
use crate::i18n::Messages;
use crate::state::{DeliveryMode, ServiceEntry, ServiceRoleEntry, StateFile};

pub(super) const SERVICE_ROLE_PREFIX: &str = "bootroot-service-";
pub(super) const SERVICE_SECRET_DIR: &str = "services";
pub(super) const SERVICE_ROLE_ID_FILENAME: &str = "role_id";
pub(super) const SERVICE_SECRET_ID_FILENAME: &str = "secret_id";
pub(crate) const SERVICE_EAB_FILENAME: &str = "eab.json";
pub(super) const REMOTE_BOOTSTRAP_DIR: &str = "remote-bootstrap/services";
pub(super) const REMOTE_BOOTSTRAP_FILENAME: &str = "bootstrap.json";
pub(super) const MANAGED_PROFILE_BEGIN_PREFIX: &str =
    bootroot::trust_bootstrap::LOCAL_FILE_PROFILE_MARKERS.begin_prefix;
pub(super) const MANAGED_PROFILE_END_PREFIX: &str =
    bootroot::trust_bootstrap::LOCAL_FILE_PROFILE_MARKERS.end_prefix;
pub(super) const DEFAULT_AGENT_EMAIL: &str = "admin@example.com";
pub(super) const DEFAULT_AGENT_SERVER: &str = "https://localhost:9000/acme/acme/directory";
pub(super) const DEFAULT_AGENT_RESPONDER_URL: &str = "http://127.0.0.1:8080";

/// Derives a service's `eab.json` path (adjacent to its `secret_id`),
/// matching what `apply_local_service_configs` provisions.  Every
/// local `bootroot-agent` invocation (the documented daemon run
/// command and the `verify` oneshot) must pass this path via
/// `--eab-file`; the file lives outside `agent.toml`, so an
/// invocation that omits the flag silently attempts open enrollment.
pub(crate) fn service_eab_file_path(secret_id_path: &Path) -> std::path::PathBuf {
    secret_id_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(SERVICE_EAB_FILENAME)
}

/// Returns the default secrets-tree `secret_id` location for a service,
/// used when the operator did not pass `--secret-id-path`.
fn default_service_secret_id_path(secrets_dir: &Path, service_name: &str) -> std::path::PathBuf {
    secrets_dir
        .join(SERVICE_SECRET_DIR)
        .join(service_name)
        .join(SERVICE_SECRET_ID_FILENAME)
}

/// Resolves the effective `secret_id` path for a service: the operator's
/// absolute `--secret-id-path` override when supplied, otherwise the
/// default under `<secrets_dir>/services/<svc>/`. This single value is
/// the source of truth persisted to `entry.approle.secret_id_path`.
fn resolved_secret_id_path(
    resolved: &ResolvedServiceAdd,
    secrets_dir: &Path,
) -> std::path::PathBuf {
    resolved
        .secret_id_path_override
        .clone()
        .unwrap_or_else(|| default_service_secret_id_path(secrets_dir, &resolved.service_name))
}

/// Derives the sibling `role_id` path for a resolved `secret_id` path.
fn role_id_sibling_path(secret_id_path: &Path) -> std::path::PathBuf {
    secret_id_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(SERVICE_ROLE_ID_FILENAME)
}

/// Reports whether two local agent-config paths name the same file.
/// Paths resolved by this binary are stored absolute and lexically
/// normalized, so a literal comparison covers equivalent spellings;
/// the canonicalizing fallback additionally resolves symlinks for
/// files that exist, so a symlinked spelling of a registered config
/// cannot bypass the one-config-per-service guard.
fn same_agent_config_file(registered: &Path, candidate: &Path) -> bool {
    if registered == candidate {
        return true;
    }
    match (
        std::fs::canonicalize(registered),
        std::fs::canonicalize(candidate),
    ) {
        (Ok(registered), Ok(candidate)) => registered == candidate,
        _ => false,
    }
}

/// Resolves an operator-supplied ACME account email to the concrete
/// value embedded in the `agent.toml` baseline / the remote-bootstrap
/// artifact.  Falls back to [`DEFAULT_AGENT_EMAIL`] when the operator
/// did not pass `--agent-email` on `service add`.
pub(super) fn effective_agent_email(value: Option<&str>) -> &str {
    value.unwrap_or(DEFAULT_AGENT_EMAIL)
}

/// Resolves an operator-supplied ACME directory URL to the concrete
/// value embedded in the baseline.  Falls back to
/// [`DEFAULT_AGENT_SERVER`].
pub(super) fn effective_agent_server(value: Option<&str>) -> &str {
    value.unwrap_or(DEFAULT_AGENT_SERVER)
}

/// Resolves an operator-supplied HTTP-01 responder admin URL to the
/// concrete value embedded in the baseline.  Falls back to
/// [`DEFAULT_AGENT_RESPONDER_URL`].
pub(super) fn effective_agent_responder_url(value: Option<&str>) -> &str {
    value.unwrap_or(DEFAULT_AGENT_RESPONDER_URL)
}
pub(super) use bootroot::trust_bootstrap::CA_BUNDLE_PEM_KEY as SERVICE_CA_BUNDLE_PEM_KEY;

pub(super) struct ServiceAppRoleMaterialized {
    pub(super) role_name: String,
    pub(super) role_id: String,
    pub(super) secret_id: String,
    pub(super) policy_name: String,
}

pub(super) struct LocalApplyResult {
    agent_config: String,
    eab_file: String,
}

pub(super) struct RemoteBootstrapResult {
    bootstrap_file: String,
    remote_run_command: String,
    wrapped: bool,
}

pub(super) struct ServiceSyncMaterial {
    pub(super) eab_kid: Option<String>,
    pub(super) eab_hmac: Option<String>,
    pub(super) responder_hmac: String,
    pub(super) trusted_ca_sha256: Vec<String>,
    pub(super) ca_bundle_pem: String,
}

pub(super) struct CaTrustMaterial {
    pub(super) trusted_ca_sha256: Vec<String>,
}

pub(crate) use remove::run_service_remove;
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
    resolve::validate_secret_id_path_override(
        resolved.secret_id_path_override.as_deref(),
        state.secrets_dir(),
        messages,
    )?;

    if let Some(ref ttl) = resolved.secret_id_ttl {
        if let Some(warning) = validate_secret_id_ttl(ttl, messages)? {
            eprintln!("{warning}");
        }
        eprintln!("{}", messages.hint_secret_id_ttl_rotation_cadence());
    }

    let agent_config = resolved.agent_config.display().to_string();
    let cert_path = resolved.cert_path.display().to_string();
    let key_path = resolved.key_path.display().to_string();
    let plan = ServiceAddPlan {
        service_name: &resolved.service_name,
        delivery_mode: resolved.delivery_mode,
        hostname: &resolved.hostname,
        domain: &resolved.domain,
        agent_config: &agent_config,
        cert_path: &cert_path,
        key_path: &key_path,
        instance_id: resolved.instance_id.as_deref(),
        notes: resolved.notes.as_deref(),
        post_renew_hooks: &resolved.post_renew_hooks,
    };
    print_service_add_plan(&plan, messages);

    if let Some(existing) = state.services.get(&resolved.service_name).cloned() {
        if is_idempotent_remote_rerun(&existing, &resolved) {
            return run_service_add_remote_idempotent(&state, &existing, &resolved, messages).await;
        }
        if is_policy_only_mismatch(&existing, &resolved) {
            anyhow::bail!(messages.error_service_policy_mismatch());
        }
        anyhow::bail!(messages.error_service_duplicate(&resolved.service_name));
    }

    // One `agent.toml` serves exactly one distinct local-file service:
    // the top-level `[openbao]` section holds a single AppRole identity,
    // so a second service writing the same file would overwrite the
    // first service's `role_id`/`secret_id`/`state_path` and break its
    // KV reads under per-service policies. Multiple `[[profiles]]` are
    // reserved for instances of the *same* service.
    if matches!(resolved.delivery_mode, DeliveryMode::LocalFile) {
        if let Some(conflict) = state.services.values().find(|entry| {
            matches!(entry.delivery_mode, DeliveryMode::LocalFile)
                && same_agent_config_file(&entry.agent_config_path, &resolved.agent_config)
        }) {
            anyhow::bail!(messages.error_service_agent_config_conflict(
                &resolved.agent_config.display().to_string(),
                &conflict.service_name,
            ));
        }
        // The state check alone misses a service removed without
        // `--strip-config` / `--delete-artifacts`: its entry is gone but
        // its managed profile block survives in the file, and the agent
        // groups and fast-polls every profile in the config — the stale
        // service would run under the new service's AppRole identity.
        // Inspect the target file itself for another service's block.
        if resolved.agent_config.exists() {
            let contents = std::fs::read_to_string(&resolved.agent_config).with_context(|| {
                messages.error_read_file_failed(&resolved.agent_config.display().to_string())
            })?;
            if let Some(stale) = bootroot::trust_bootstrap::find_foreign_managed_profile_service(
                &contents,
                &resolved.service_name,
            ) {
                anyhow::bail!(messages.error_service_agent_config_stale_profile(
                    &resolved.agent_config.display().to_string(),
                    &stale,
                ));
            }
        }
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
    let preview_secret_id_path = resolved_secret_id_path(resolved, state.secrets_dir());
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
        let mut client =
            match OpenBaoClient::with_local_trust(&state.openbao_url, state.secrets_dir())
                .with_context(|| messages.error_openbao_client_create_failed())
            {
                Ok(client) => client,
                Err(err) => {
                    note.push('\n');
                    note.push_str(
                        &messages
                            .service_summary_preview_trust_lookup_failed(err.to_string().as_str()),
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

    let mut client = OpenBaoClient::with_local_trust(&state.openbao_url, state.secrets_dir())
        .with_context(|| messages.error_openbao_client_create_failed())?;
    authenticate_openbao_client(&mut client, auth, messages).await?;

    let secret_id_options = build_secret_id_options(resolved);
    let wrap_ttl = resolve::effective_wrap_ttl(resolved.secret_id_wrap_ttl.as_deref());
    let approle_result = approle::ensure_service_approle(
        &client,
        state,
        &resolved.service_name,
        &secret_id_options,
        wrap_ttl,
        messages,
    )
    .await?;
    let secrets_dir = state.secrets_dir();
    // The resolved `secret_id` path is the single source of truth for
    // this add: the origin writes, the local config renderer, and the
    // persisted state entry all use this same in-memory value (the state
    // entry does not exist yet, so nothing reads it "from state"). For an
    // operator `--secret-id-path` override it is the absolute path,
    // agent-owned outside the secrets tree; otherwise the default under
    // `<secrets_dir>/services/<svc>/`.
    let is_override = resolved.secret_id_path_override.is_some();
    let secret_id_path = resolved_secret_id_path(resolved, secrets_dir);
    let role_id_path = role_id_sibling_path(&secret_id_path);
    approle::write_role_id_file(
        &role_id_path,
        &approle_result.role_id,
        is_override,
        messages,
    )
    .await?;
    approle::write_secret_id_file(
        &secret_id_path,
        &approle_result.secret_id,
        is_override,
        messages,
    )
    .await?;
    let service_sync_material = secrets::sync_service_kv_bundle(
        &client,
        state,
        resolved,
        &approle_result.secret_id,
        messages,
    )
    .await?;
    let trusted_ca_sha256 = Some(service_sync_material.trusted_ca_sha256.as_slice());

    let applied = if matches!(resolved.delivery_mode, DeliveryMode::LocalFile) {
        Some(
            local_config::apply_local_service_configs(
                secrets_dir,
                resolved,
                &secret_id_path,
                &service_sync_material,
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
        let artifact_wrap_info = create_artifact_wrap_info(&client, resolved, messages).await?;
        Some(
            remote_bootstrap::write_remote_bootstrap_artifact(
                state,
                secrets_dir,
                resolved,
                &secret_id_path,
                artifact_wrap_info.as_ref(),
                &service_sync_material.ca_bundle_pem,
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

    register_dns_alias(state, messages)?;

    print_service_add_apply_summary(
        &entry,
        &secret_id_path,
        applied.as_ref(),
        remote_bootstrap_result.as_ref(),
        trusted_ca_sha256,
        messages,
    );
    print_consumer_reload_hint(std::iter::once(&entry), messages);
    Ok(())
}

fn build_service_entry_from_role(
    resolved: &ResolvedServiceAdd,
    approle: ServiceRoleEntry,
) -> ServiceEntry {
    ServiceEntry {
        service_name: resolved.service_name.clone(),
        delivery_mode: resolved.delivery_mode,
        hostname: resolved.hostname.clone(),
        domain: resolved.domain.clone(),
        agent_config_path: resolved.agent_config.clone(),
        cert_path: resolved.cert_path.clone(),
        key_path: resolved.key_path.clone(),
        instance_id: resolved.instance_id.clone(),
        notes: resolved.notes.clone(),
        post_renew_hooks: resolved.post_renew_hooks.clone(),
        approle,
        agent_email: resolved.agent_email.clone(),
        agent_server: resolved.agent_server.clone(),
        agent_responder_url: resolved.agent_responder_url.clone(),
        cert_group_gid: resolved.cert_group_gid,
    }
}

fn build_service_entry(
    resolved: &ResolvedServiceAdd,
    approle: ServiceAppRoleMaterialized,
    secret_id_path: &Path,
) -> ServiceEntry {
    build_service_entry_from_role(
        resolved,
        ServiceRoleEntry {
            role_name: approle.role_name,
            role_id: approle.role_id,
            secret_id_path: secret_id_path.to_path_buf(),
            policy_name: approle.policy_name,
            secret_id_ttl: resolved.secret_id_ttl.clone(),
            secret_id_wrap_ttl: resolved.secret_id_wrap_ttl.clone(),
            token_bound_cidrs: resolved.token_bound_cidrs.clone(),
        },
    )
}

/// Creates a wrap-only `secret_id` for the bootstrap artifact when
/// wrapping is enabled. Returns `None` when wrapping is disabled.
async fn create_artifact_wrap_info(
    client: &OpenBaoClient,
    resolved: &ResolvedServiceAdd,
    messages: &Messages,
) -> Result<Option<remote_bootstrap::ArtifactWrapInfo>> {
    let wrap_ttl = resolve::effective_wrap_ttl(resolved.secret_id_wrap_ttl.as_deref());
    let Some(ttl) = wrap_ttl else {
        return Ok(None);
    };
    let role_name = approle::service_role_name(&resolved.service_name);
    let secret_id_options = build_secret_id_options(resolved);
    let wrap_info = client
        .create_secret_id_wrap_only(&role_name, &secret_id_options, ttl)
        .await
        .with_context(|| messages.error_openbao_secret_id_failed())?;
    Ok(Some(remote_bootstrap::ArtifactWrapInfo::from_wrap_info(
        &wrap_info,
    )))
}

fn build_secret_id_options(resolved: &ResolvedServiceAdd) -> SecretIdOptions {
    SecretIdOptions {
        ttl: resolved.secret_id_ttl.clone(),
        num_uses: Some(0),
        metadata: None,
        token_bound_cidrs: resolved.token_bound_cidrs.clone(),
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
                eab_file: &result.eab_file,
            }),
            remote: remote_bootstrap.map(|result| ServiceAddRemoteBootstrap {
                bootstrap_file: &result.bootstrap_file,
                remote_run_command: &result.remote_run_command,
                wrapped: result.wrapped,
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
    resolved: &ResolvedServiceAdd,
    messages: &Messages,
) -> Result<()> {
    let secrets_dir = state.secrets_dir();
    let mut client = OpenBaoClient::with_local_trust(&state.openbao_url, secrets_dir)
        .with_context(|| messages.error_openbao_client_create_failed())?;
    let auth = resolved
        .runtime_auth
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("OpenBao auth is required"))?;
    crate::commands::openbao_auth::authenticate_openbao_client(&mut client, auth, messages).await?;
    // Re-apply the service policy so pre-existing services pick up the reissue
    // path write grant needed for `rotate force-reissue --wait` completion.
    approle::reapply_service_policy(&client, state, &entry.service_name, messages).await?;
    let ca_bundle_pem = secrets::read_ca_bundle_pem(&client, &state.kv_mount, messages).await?;
    let wrap_ttl = resolve::effective_wrap_ttl(entry.approle.secret_id_wrap_ttl.as_deref());
    let artifact_wrap_info = if let Some(ttl) = wrap_ttl {
        let secret_id_options = build_secret_id_options(resolved);
        let wrap_info = client
            .create_secret_id_wrap_only(&entry.approle.role_name, &secret_id_options, ttl)
            .await
            .with_context(|| messages.error_openbao_secret_id_failed())?;
        Some(remote_bootstrap::ArtifactWrapInfo::from_wrap_info(
            &wrap_info,
        ))
    } else {
        None
    };
    let remote_bootstrap = remote_bootstrap::write_remote_bootstrap_artifact_from_entry(
        state,
        secrets_dir,
        entry,
        artifact_wrap_info.as_ref(),
        &ca_bundle_pem,
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
                wrapped: remote_bootstrap.wrapped,
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

const INHERIT_SENTINEL: &str = "inherit";

#[allow(clippy::too_many_lines)]
pub(crate) fn run_service_update(args: &ServiceUpdateArgs, messages: &Messages) -> Result<()> {
    let hook_inputs = resolve::PostRenewHookInputs {
        reload_style: args.reload_style,
        reload_target: args.reload_target.as_deref(),
        post_renew_command: args.post_renew_command.as_deref(),
        post_renew_arg: &args.post_renew_arg,
        post_renew_timeout_secs: args.post_renew_timeout_secs,
        post_renew_on_failure: args.post_renew_on_failure,
    };
    let hooks_supplied = hook_inputs.any_flag_set();

    if args.secret_id_ttl.is_none()
        && args.secret_id_wrap_ttl.is_none()
        && !args.no_wrap
        && args.rn_cidrs.is_empty()
        && args.cert_group.is_none()
        && !hooks_supplied
    {
        anyhow::bail!(messages.error_service_update_no_flags());
    }

    let new_hooks = if hooks_supplied {
        Some(resolve::resolve_post_renew_hooks_from_parts(&hook_inputs)?)
    } else {
        None
    };

    let state_path = StateFile::default_path();
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let mut state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;

    let entry = state
        .services
        .get_mut(&args.service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(&args.service_name)))?;

    let mut changes: Vec<String> = Vec::new();

    let mut explicit_ttl_set = false;
    if let Some(ref new_ttl) = args.secret_id_ttl {
        let old_value = entry.approle.secret_id_ttl.clone();
        if new_ttl.eq_ignore_ascii_case(INHERIT_SENTINEL) {
            entry.approle.secret_id_ttl = None;
        } else {
            if let Some(warning) = validate_secret_id_ttl(new_ttl, messages)? {
                eprintln!("{warning}");
            }
            explicit_ttl_set = true;
            entry.approle.secret_id_ttl = Some(new_ttl.clone());
        }
        if old_value != entry.approle.secret_id_ttl {
            changes.push(messages.service_update_field_changed(
                "secret_id_ttl",
                &display_policy_value(old_value.as_deref(), messages),
                &display_policy_value(entry.approle.secret_id_ttl.as_deref(), messages),
            ));
        }
    }

    if args.no_wrap {
        let old_value = entry.approle.secret_id_wrap_ttl.clone();
        entry.approle.secret_id_wrap_ttl = Some("0".to_string());
        if old_value != entry.approle.secret_id_wrap_ttl {
            changes.push(messages.service_update_field_changed(
                "secret_id_wrap_ttl",
                &display_wrap_ttl(old_value.as_deref(), messages),
                &display_wrap_ttl(entry.approle.secret_id_wrap_ttl.as_deref(), messages),
            ));
        }
    } else if let Some(ref new_wrap_ttl) = args.secret_id_wrap_ttl {
        let old_value = entry.approle.secret_id_wrap_ttl.clone();
        if new_wrap_ttl.eq_ignore_ascii_case(INHERIT_SENTINEL) {
            entry.approle.secret_id_wrap_ttl = None;
        } else {
            entry.approle.secret_id_wrap_ttl = Some(new_wrap_ttl.clone());
        }
        if old_value != entry.approle.secret_id_wrap_ttl {
            changes.push(messages.service_update_field_changed(
                "secret_id_wrap_ttl",
                &display_wrap_ttl(old_value.as_deref(), messages),
                &display_wrap_ttl(entry.approle.secret_id_wrap_ttl.as_deref(), messages),
            ));
        }
    }

    if !args.rn_cidrs.is_empty() {
        resolve::validate_rn_cidrs(&args.rn_cidrs, messages)?;
        let old_value = entry.approle.token_bound_cidrs.clone();
        if args.rn_cidrs.len() == 1 && args.rn_cidrs.first().map(String::as_str) == Some("clear") {
            entry.approle.token_bound_cidrs = None;
        } else {
            entry.approle.token_bound_cidrs = Some(args.rn_cidrs.clone());
        }
        if old_value != entry.approle.token_bound_cidrs {
            let old_display = old_value.as_deref().map_or_else(
                || messages.policy_label_inherit().to_string(),
                |v| v.join(", "),
            );
            let new_display = entry.approle.token_bound_cidrs.as_deref().map_or_else(
                || messages.policy_label_inherit().to_string(),
                |v| v.join(", "),
            );
            changes.push(messages.service_update_field_changed(
                "token_bound_cidrs",
                &old_display,
                &new_display,
            ));
        }
    }

    // `cert_group_supplied` triggers a re-render of the managed
    // agent.toml profile block (local-file) or the operator warning
    // (remote-bootstrap) on every invocation that passes `--cert-group`,
    // even when the requested gid matches what is already in state. This
    // is the repair path for the split-brain class of bug called out in
    // the issue #593 review: a previous attempt may have saved state but
    // failed to re-render the managed profile, and a re-run with the
    // same flag must be able to drive the on-disk profile back into sync
    // rather than being short-circuited by the no-change early return.
    let mut redeploy_hint: Option<CertGroupRedeployHint> = None;
    let cert_group_supplied = args.cert_group.is_some();
    if let Some(ref raw) = args.cert_group {
        let old_value = entry.cert_group_gid;
        let new_value = parse_cert_group_for_update(raw, entry.delivery_mode)?;
        entry.cert_group_gid = new_value;
        if old_value != new_value {
            changes.push(messages.service_update_field_changed(
                "cert_group_gid",
                &display_cert_group(old_value),
                &display_cert_group(new_value),
            ));
        }
        redeploy_hint = Some(CertGroupRedeployHint {
            delivery_mode: entry.delivery_mode,
            service_name: args.service_name.clone(),
        });
    }

    let mut hooks_changed = false;
    if let Some(new_hooks) = new_hooks {
        let old_hooks = entry.post_renew_hooks.clone();
        if old_hooks != new_hooks {
            entry.post_renew_hooks = new_hooks;
            changes.push(messages.service_update_field_changed(
                "post_renew_hooks",
                &display_post_renew_hooks(&old_hooks, messages),
                &display_post_renew_hooks(&entry.post_renew_hooks, messages),
            ));
            hooks_changed = true;
        }
    }

    if explicit_ttl_set {
        eprintln!("{}", messages.hint_secret_id_ttl_rotation_cadence());
    }

    if changes.is_empty() && !cert_group_supplied {
        println!("{}", messages.service_update_no_changes());
        return Ok(());
    }

    // Snapshot the entry without holding the borrow on `state` past the
    // re-render / save.
    let entry_snapshot = state.services.get(&args.service_name).cloned();

    // Re-render the managed agent.toml block BEFORE persisting state.
    // If the re-render fails, state.json stays unchanged so a re-run of
    // the same `service update --cert-group ...` will still see the old
    // value as the source of truth and re-trigger the re-render rather
    // than short-circuiting on `changes.is_empty()`. This is the
    // atomicity half of the issue #593 review's split-brain fix; the
    // `cert_group_supplied`-driven re-render-on-every-invocation above
    // is the retry half.
    //
    // Hook-only updates (issue #614) follow the same path: a
    // local-file profile must be rewritten so the new
    // `[[profiles.hooks.post_renew.success]]` entries take effect on
    // the next agent reload / renewal.
    let needs_local_rerender = matches!(
        entry_snapshot.as_ref().map(|e| e.delivery_mode),
        Some(DeliveryMode::LocalFile)
    ) && (matches!(
        redeploy_hint.as_ref().map(|h| h.delivery_mode),
        Some(DeliveryMode::LocalFile)
    ) || hooks_changed);
    if needs_local_rerender && let Some(entry) = entry_snapshot.as_ref() {
        rerender_local_managed_profile(entry)?;
    }

    state
        .save(&state_path)
        .with_context(|| messages.error_serialize_state_failed())?;

    if let (Some(hint), Some(_)) = (redeploy_hint.as_ref(), entry_snapshot.as_ref())
        && matches!(hint.delivery_mode, DeliveryMode::RemoteBootstrap)
    {
        // Persisting the gid in state.json alone is not enough for
        // remote-bootstrap services — the remote agent reads from
        // the bootstrap-rendered `agent.toml` on disk, and `service
        // add` is the path that re-emits the artifact. Print a
        // loud follow-up so the next rotation actually picks up
        // the new policy.
        eprintln!(
            "warning: --cert-group changed for remote-bootstrap service {}.\n\
             Re-emit the bootstrap artifact with `bootroot service add` \
             and re-run `bootroot-remote bootstrap --artifact <path>` on \
             the remote agent host so the new cert_group_gid lands in the \
             remote agent.toml.",
            hint.service_name,
        );
    }

    if hooks_changed
        && let Some(entry) = entry_snapshot.as_ref()
        && matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap)
    {
        eprintln!(
            "warning: post-renew hooks changed for remote-bootstrap service {}.\n\
             Re-emit the bootstrap artifact with `bootroot service add` \
             and re-run `bootroot-remote bootstrap --artifact <path>` on \
             the remote agent host so the new hooks land in the remote \
             agent.toml.",
            args.service_name,
        );
    }

    if changes.is_empty() {
        // `--cert-group` was supplied with the value already in state;
        // we re-rendered the managed profile defensively but had no
        // policy mutation to report.
        println!("{}", messages.service_update_no_changes());
        return Ok(());
    }

    println!("{}", messages.service_update_summary());
    println!("{}", messages.service_summary_kind(&args.service_name));
    for change in &changes {
        println!("{change}");
    }
    println!("{}", messages.service_update_rotate_hint());

    Ok(())
}

struct CertGroupRedeployHint {
    delivery_mode: DeliveryMode,
    service_name: String,
}

fn parse_cert_group_for_update(raw: &str, delivery_mode: DeliveryMode) -> Result<Option<u32>> {
    let trimmed = raw.trim();
    if trimmed.eq_ignore_ascii_case("clear") {
        return Ok(None);
    }
    let gid = match delivery_mode {
        DeliveryMode::LocalFile => bootroot::cert_group::parse_cert_group_local(trimmed)
            .map_err(|err| anyhow::anyhow!("{err}"))?,
        DeliveryMode::RemoteBootstrap => bootroot::cert_group::parse_cert_group_remote(trimmed)
            .map_err(|err| anyhow::anyhow!("{err}"))?,
    };
    if matches!(delivery_mode, DeliveryMode::LocalFile) {
        bootroot::cert_group::validate_local_gid_membership(gid)
            .map_err(|err| anyhow::anyhow!("{err}"))?;
    }
    Ok(Some(gid))
}

fn display_cert_group(value: Option<u32>) -> String {
    match value {
        Some(gid) => gid.to_string(),
        None => "unset".to_string(),
    }
}

pub(crate) fn display_post_renew_hooks(
    hooks: &[crate::state::PostRenewHookEntry],
    messages: &Messages,
) -> String {
    if hooks.is_empty() {
        return messages.service_update_hook_value_none().to_string();
    }
    hooks
        .iter()
        .map(crate::cli::output::format_hook)
        .collect::<Vec<_>>()
        .join("; ")
}

/// Prints the per-service "post-renew hook status" hint used by
/// `service add`, `rotate ca-key` (phase 5), and `rotate force-reissue`
/// to make the in-FD pitfall (issue #614) visible. For each affected
/// service that lacks a hook, the operator gets a single-line
/// remediation pointer to `service update --reload-style ...`.
pub(crate) fn print_consumer_reload_hint<'a, I>(services: I, messages: &Messages)
where
    I: IntoIterator<Item = &'a ServiceEntry>,
{
    let entries: Vec<&ServiceEntry> = services.into_iter().collect();
    if entries.is_empty() {
        return;
    }
    println!("{}", messages.hint_consumer_reload_required());
    let mut any_without_hook = false;
    for entry in &entries {
        if entry.post_renew_hooks.is_empty() {
            println!(
                "{}",
                messages.hint_consumer_reload_service_without_hook(&entry.service_name)
            );
            any_without_hook = true;
        } else {
            let summary = display_post_renew_hooks(&entry.post_renew_hooks, messages);
            println!(
                "{}",
                messages.hint_consumer_reload_service_with_hook(&entry.service_name, &summary)
            );
        }
    }
    if any_without_hook {
        println!("{}", messages.hint_consumer_reload_remediation());
    }
}

/// Re-renders just the managed profile block of the local
/// `agent.toml` for the given entry. Used by `service update --cert-
/// group ...` so the next agent restart and the next rotation pick up
/// the new `cert_group_gid` line without requiring a full `service add`
/// re-run.
fn rerender_local_managed_profile(entry: &ServiceEntry) -> Result<()> {
    let agent_config_path = &entry.agent_config_path;
    if !agent_config_path.exists() {
        anyhow::bail!(
            "agent config {} not found — re-run `bootroot service add` to generate it",
            agent_config_path.display()
        );
    }
    let current = std::fs::read_to_string(agent_config_path)
        .with_context(|| format!("Failed to read {}", agent_config_path.display()))?;
    let block = bootroot::trust_bootstrap::render_managed_profile_block(
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        &entry.service_name,
        entry.instance_id.as_deref().unwrap_or_default(),
        &entry.hostname,
        &entry.cert_path,
        &entry.key_path,
        entry.cert_group_gid,
    );
    let block = inject_hooks_into_managed_profile_block(&block, &entry.post_renew_hooks);
    // `service add` writes `[trust]` inside the managed-block markers, so
    // the whole-span replacement below would drop it and leave the agent
    // unable to verify a private CA. Snapshot it from the pre-replacement
    // file and re-apply it afterwards. This path is deliberately offline
    // (no KV handle), so we carry the existing table over verbatim rather
    // than re-deriving fingerprints. A keyed upsert updates the table in
    // place wherever it sits, so a `[trust]` already outside the markers
    // is not duplicated; a file with no `[trust]` keeps none.
    let trust_pairs = bootroot::toml_util::section_pairs(&current, "trust")?;
    let next = bootroot::trust_bootstrap::upsert_managed_profile_block(
        &current,
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        &entry.service_name,
        &block,
    );
    let next = if let Some(pairs) = trust_pairs {
        let updates: Vec<(&str, String)> =
            pairs.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
        bootroot::toml_util::upsert_section_keys(&next, "trust", &updates)?
    } else {
        next
    };
    std::fs::write(agent_config_path, next)
        .with_context(|| format!("Failed to write {}", agent_config_path.display()))?;
    Ok(())
}

fn inject_hooks_into_managed_profile_block(
    block: &str,
    hooks: &[crate::state::PostRenewHookEntry],
) -> String {
    use std::fmt::Write as _;
    if hooks.is_empty() {
        return block.to_string();
    }
    let mut hooks_toml = String::new();
    for hook in hooks {
        hooks_toml.push_str("\n[[profiles.hooks.post_renew.success]]\n");
        let _ = writeln!(
            hooks_toml,
            "command = {}",
            bootroot::toml_util::toml_encode_string(&hook.command)
        );
        if !hook.args.is_empty() {
            let formatted = hook
                .args
                .iter()
                .map(|a| bootroot::toml_util::toml_encode_string(a))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(hooks_toml, "args = [{formatted}]");
        }
        let _ = writeln!(hooks_toml, "timeout_secs = {}", hook.timeout_secs);
        let _ = writeln!(hooks_toml, "on_failure = \"{}\"", hook.on_failure);
    }
    if let Some(end_pos) = block.rfind(MANAGED_PROFILE_END_PREFIX) {
        let mut result = block[..end_pos].to_string();
        result.push_str(&hooks_toml);
        result.push_str(&block[end_pos..]);
        result
    } else {
        let mut result = block.to_string();
        result.push_str(&hooks_toml);
        result
    }
}

pub(crate) fn display_policy_value(value: Option<&str>, messages: &Messages) -> String {
    match value {
        Some(v) => v.to_string(),
        None => messages.policy_label_inherit().to_string(),
    }
}

pub(crate) fn display_wrap_ttl(value: Option<&str>, messages: &Messages) -> String {
    match value {
        Some("0") => messages.policy_label_disabled().to_string(),
        Some(v) => v.to_string(),
        None => messages.policy_label_default_wrap_ttl(DEFAULT_SECRET_ID_WRAP_TTL),
    }
}

fn build_preview_service_entry(resolved: &ResolvedServiceAdd, state: &StateFile) -> ServiceEntry {
    let preview_secret_id_path = resolved_secret_id_path(resolved, state.secrets_dir());
    build_service_entry_from_role(
        resolved,
        ServiceRoleEntry {
            role_name: approle::service_role_name(&resolved.service_name),
            role_id: "dry-run".to_string(),
            secret_id_path: preview_secret_id_path,
            policy_name: approle::service_policy_name(&resolved.service_name),
            secret_id_ttl: resolved.secret_id_ttl.clone(),
            secret_id_wrap_ttl: resolved.secret_id_wrap_ttl.clone(),
            token_bound_cidrs: resolved.token_bound_cidrs.clone(),
        },
    )
}

fn non_policy_fields_match(entry: &ServiceEntry, resolved: &ResolvedServiceAdd) -> bool {
    matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap)
        && matches!(resolved.delivery_mode, DeliveryMode::RemoteBootstrap)
        && entry.hostname == resolved.hostname
        && entry.domain == resolved.domain
        && entry.agent_config_path == resolved.agent_config
        && entry.cert_path == resolved.cert_path
        && entry.key_path == resolved.key_path
        && entry.instance_id == resolved.instance_id
        && entry.notes == resolved.notes
        && entry.post_renew_hooks == resolved.post_renew_hooks
        && entry.agent_email == resolved.agent_email
        && entry.agent_server == resolved.agent_server
        && entry.agent_responder_url == resolved.agent_responder_url
        && entry.cert_group_gid == resolved.cert_group_gid
}

fn policy_fields_match(entry: &ServiceEntry, resolved: &ResolvedServiceAdd) -> bool {
    entry.approle.secret_id_ttl == resolved.secret_id_ttl
        && entry.approle.secret_id_wrap_ttl == resolved.secret_id_wrap_ttl
        && entry.approle.token_bound_cidrs == resolved.token_bound_cidrs
}

fn is_idempotent_remote_rerun(entry: &ServiceEntry, resolved: &ResolvedServiceAdd) -> bool {
    non_policy_fields_match(entry, resolved) && policy_fields_match(entry, resolved)
}

fn is_policy_only_mismatch(entry: &ServiceEntry, resolved: &ResolvedServiceAdd) -> bool {
    non_policy_fields_match(entry, resolved) && !policy_fields_match(entry, resolved)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::resolve::ResolvedServiceAdd;
    use super::{
        ServiceAppRoleMaterialized, build_secret_id_options, build_service_entry,
        build_service_entry_from_role, display_policy_value, display_wrap_ttl,
        is_idempotent_remote_rerun, is_policy_only_mismatch, non_policy_fields_match,
        policy_fields_match,
    };
    use crate::i18n::Messages;
    use crate::state::{DeliveryMode, ServiceEntry, ServiceRoleEntry};

    fn sample_resolved() -> ResolvedServiceAdd {
        ResolvedServiceAdd {
            service_name: "test-svc".to_string(),
            delivery_mode: DeliveryMode::LocalFile,
            hostname: "host1".to_string(),
            domain: "example.com".to_string(),
            agent_config: PathBuf::from("/etc/agent.toml"),
            cert_path: PathBuf::from("/certs/cert.pem"),
            key_path: PathBuf::from("/certs/key.pem"),
            instance_id: Some("inst-1".to_string()),
            runtime_auth: None,
            notes: Some("test note".to_string()),
            post_renew_hooks: Vec::new(),
            secret_id_ttl: None,
            secret_id_wrap_ttl: None,
            token_bound_cidrs: None,
            agent_email: None,
            agent_server: None,
            agent_responder_url: None,
            cert_group_gid: None,
            secret_id_path_override: None,
        }
    }

    fn assert_common_fields(entry: &ServiceEntry, resolved: &ResolvedServiceAdd) {
        assert_eq!(entry.service_name, resolved.service_name);
        assert_eq!(entry.delivery_mode, resolved.delivery_mode);
        assert_eq!(entry.hostname, resolved.hostname);
        assert_eq!(entry.domain, resolved.domain);
        assert_eq!(entry.agent_config_path, resolved.agent_config);
        assert_eq!(entry.cert_path, resolved.cert_path);
        assert_eq!(entry.key_path, resolved.key_path);
        assert_eq!(entry.instance_id, resolved.instance_id);
        assert_eq!(entry.notes, resolved.notes);
        assert_eq!(entry.post_renew_hooks, resolved.post_renew_hooks);
        assert_eq!(entry.agent_email, resolved.agent_email);
        assert_eq!(entry.agent_server, resolved.agent_server);
        assert_eq!(entry.agent_responder_url, resolved.agent_responder_url);
        assert_eq!(entry.cert_group_gid, resolved.cert_group_gid);
    }

    #[test]
    fn build_service_entry_from_role_sets_all_fields() {
        let resolved = sample_resolved();
        let role = ServiceRoleEntry {
            role_name: "role-a".to_string(),
            role_id: "rid-a".to_string(),
            secret_id_path: PathBuf::from("/secrets/a"),
            policy_name: "policy-a".to_string(),
            secret_id_ttl: None,
            secret_id_wrap_ttl: None,
            token_bound_cidrs: None,
        };
        let entry = build_service_entry_from_role(&resolved, role);

        assert_common_fields(&entry, &resolved);
        assert_eq!(entry.approle.role_name, "role-a");
        assert_eq!(entry.approle.role_id, "rid-a");
        assert_eq!(entry.approle.secret_id_path, PathBuf::from("/secrets/a"));
        assert_eq!(entry.approle.policy_name, "policy-a");
    }

    #[test]
    fn build_service_entry_delegates_to_common_helper() {
        let resolved = sample_resolved();
        let materialized = ServiceAppRoleMaterialized {
            role_name: "mat-role".to_string(),
            role_id: "mat-rid".to_string(),
            secret_id: "unused-in-entry".to_string(),
            policy_name: "mat-policy".to_string(),
        };
        let secret_id_path = PathBuf::from("/secrets/mat");
        let entry = build_service_entry(&resolved, materialized, &secret_id_path);

        assert_common_fields(&entry, &resolved);
        assert_eq!(entry.approle.role_name, "mat-role");
        assert_eq!(entry.approle.role_id, "mat-rid");
        assert_eq!(entry.approle.secret_id_path, secret_id_path);
        assert_eq!(entry.approle.policy_name, "mat-policy");
    }

    #[test]
    fn build_service_entry_from_role_with_none_optional_fields() {
        let mut resolved = sample_resolved();
        resolved.instance_id = None;
        resolved.notes = None;

        let role = ServiceRoleEntry {
            role_name: "r".to_string(),
            role_id: "id".to_string(),
            secret_id_path: PathBuf::from("/s"),
            policy_name: "p".to_string(),
            secret_id_ttl: None,
            secret_id_wrap_ttl: None,
            token_bound_cidrs: None,
        };
        let entry = build_service_entry_from_role(&resolved, role);

        assert_common_fields(&entry, &resolved);
        assert!(entry.instance_id.is_none());
        assert!(entry.notes.is_none());
    }

    fn sample_entry_from_resolved(resolved: &ResolvedServiceAdd) -> ServiceEntry {
        build_service_entry_from_role(
            resolved,
            ServiceRoleEntry {
                role_name: "role".to_string(),
                role_id: "rid".to_string(),
                secret_id_path: PathBuf::from("/s"),
                policy_name: "policy".to_string(),
                secret_id_ttl: resolved.secret_id_ttl.clone(),
                secret_id_wrap_ttl: resolved.secret_id_wrap_ttl.clone(),
                token_bound_cidrs: resolved.token_bound_cidrs.clone(),
            },
        )
    }

    #[test]
    fn build_service_entry_persists_secret_id_policy_fields() {
        let mut resolved = sample_resolved();
        resolved.secret_id_ttl = Some("1h".to_string());
        resolved.secret_id_wrap_ttl = Some("10m".to_string());

        let materialized = ServiceAppRoleMaterialized {
            role_name: "r".to_string(),
            role_id: "id".to_string(),
            secret_id: "sid".to_string(),
            policy_name: "p".to_string(),
        };
        let entry = build_service_entry(&resolved, materialized, &PathBuf::from("/s"));

        assert_eq!(entry.approle.secret_id_ttl.as_deref(), Some("1h"));
        assert_eq!(entry.approle.secret_id_wrap_ttl.as_deref(), Some("10m"));
    }

    #[test]
    fn build_secret_id_options_maps_resolved_fields() {
        let mut resolved = sample_resolved();
        resolved.secret_id_ttl = Some("2h".to_string());

        let opts = build_secret_id_options(&resolved);
        assert_eq!(opts.ttl.as_deref(), Some("2h"));
        assert_eq!(opts.num_uses, Some(0));
        assert!(opts.metadata.is_none());
    }

    #[test]
    fn build_secret_id_options_always_unlimited() {
        let resolved = sample_resolved();
        let opts = build_secret_id_options(&resolved);
        assert!(opts.ttl.is_none());
        assert_eq!(opts.num_uses, Some(0));
    }

    #[test]
    fn policy_fields_match_identical() {
        let resolved = sample_resolved();
        let entry = sample_entry_from_resolved(&resolved);
        assert!(policy_fields_match(&entry, &resolved));
    }

    #[test]
    fn policy_fields_match_differs_on_ttl() {
        let resolved = sample_resolved();
        let mut entry = sample_entry_from_resolved(&resolved);
        entry.approle.secret_id_ttl = Some("999h".to_string());
        assert!(!policy_fields_match(&entry, &resolved));
    }

    #[test]
    fn policy_fields_match_differs_on_wrap_ttl() {
        let resolved = sample_resolved();
        let mut entry = sample_entry_from_resolved(&resolved);
        entry.approle.secret_id_wrap_ttl = Some("0".to_string());
        assert!(!policy_fields_match(&entry, &resolved));
    }

    #[test]
    fn non_policy_fields_match_requires_remote_bootstrap() {
        let mut resolved = sample_resolved();
        resolved.delivery_mode = DeliveryMode::RemoteBootstrap;
        let mut entry = sample_entry_from_resolved(&resolved);
        // Both are remote-bootstrap → match
        assert!(non_policy_fields_match(&entry, &resolved));
        // Entry is local-file → no match
        entry.delivery_mode = DeliveryMode::LocalFile;
        assert!(!non_policy_fields_match(&entry, &resolved));
    }

    #[test]
    fn is_idempotent_remote_rerun_true_when_all_match() {
        let mut resolved = sample_resolved();
        resolved.delivery_mode = DeliveryMode::RemoteBootstrap;
        let entry = sample_entry_from_resolved(&resolved);
        assert!(is_idempotent_remote_rerun(&entry, &resolved));
    }

    #[test]
    fn is_idempotent_remote_rerun_false_when_policy_differs() {
        let mut resolved = sample_resolved();
        resolved.delivery_mode = DeliveryMode::RemoteBootstrap;
        let mut entry = sample_entry_from_resolved(&resolved);
        entry.approle.secret_id_wrap_ttl = Some("0".to_string());
        assert!(!is_idempotent_remote_rerun(&entry, &resolved));
    }

    /// Guards the Round 3 regression from issue #549: the stored
    /// `agent_*` values on `ServiceEntry` are the source of truth for
    /// `remote-bootstrap` reruns.  A rerun that would silently flip the
    /// persisted topology — either dropping an operator's previous
    /// override (stored `Some(X)` vs. new `None`) or introducing a new
    /// one (stored `None` vs. new `Some(Y)`), or simply disagreeing
    /// (stored `Some(X)` vs. new `Some(Y)`) — must not be treated as
    /// idempotent.  `run_service_add` then falls through to the
    /// `error_service_duplicate` bail, so the operator has to remove
    /// the service with `bootroot service remove` and re-add it rather
    /// than silently re-rendering the agent config over an
    /// inconsistent definition.
    #[test]
    fn is_idempotent_remote_rerun_false_when_agent_overrides_differ() {
        let mut resolved = sample_resolved();
        resolved.delivery_mode = DeliveryMode::RemoteBootstrap;
        // Baseline: both sides have `None` (operator never supplied
        // `--agent-*`).  This is the idempotent case.
        let baseline_entry = sample_entry_from_resolved(&resolved);
        assert!(is_idempotent_remote_rerun(&baseline_entry, &resolved));

        // Entry stored an explicit override; rerun omits the flag
        // (resolved.agent_server == None).  Must NOT be idempotent.
        let mut entry_with_override = sample_entry_from_resolved(&resolved);
        entry_with_override.agent_server =
            Some("https://step-ca.example.org:9443/acme/acme/directory".to_string());
        assert!(!is_idempotent_remote_rerun(&entry_with_override, &resolved));

        // Entry stored no override; rerun introduces one.  Must NOT be
        // idempotent — would silently change the generated artifact.
        let mut resolved_with_override = sample_resolved();
        resolved_with_override.delivery_mode = DeliveryMode::RemoteBootstrap;
        resolved_with_override.agent_responder_url =
            Some("http://responder.internal:18080".to_string());
        assert!(!is_idempotent_remote_rerun(
            &baseline_entry,
            &resolved_with_override
        ));

        // Entry and rerun both have overrides, but they disagree.
        let mut entry_a = sample_entry_from_resolved(&resolved);
        entry_a.agent_email = Some("ops@example.org".to_string());
        let mut resolved_b = sample_resolved();
        resolved_b.delivery_mode = DeliveryMode::RemoteBootstrap;
        resolved_b.agent_email = Some("other@example.org".to_string());
        assert!(!is_idempotent_remote_rerun(&entry_a, &resolved_b));
    }

    #[test]
    fn is_policy_only_mismatch_true_when_only_policy_differs() {
        let mut resolved = sample_resolved();
        resolved.delivery_mode = DeliveryMode::RemoteBootstrap;
        let mut entry = sample_entry_from_resolved(&resolved);
        entry.approle.secret_id_wrap_ttl = Some("0".to_string());
        assert!(is_policy_only_mismatch(&entry, &resolved));
    }

    #[test]
    fn is_policy_only_mismatch_false_when_non_policy_also_differs() {
        let mut resolved = sample_resolved();
        resolved.delivery_mode = DeliveryMode::RemoteBootstrap;
        let mut entry = sample_entry_from_resolved(&resolved);
        entry.approle.secret_id_wrap_ttl = Some("0".to_string());
        entry.hostname = "different".to_string();
        assert!(!is_policy_only_mismatch(&entry, &resolved));
    }

    #[test]
    fn is_policy_only_mismatch_false_when_all_match() {
        let mut resolved = sample_resolved();
        resolved.delivery_mode = DeliveryMode::RemoteBootstrap;
        let entry = sample_entry_from_resolved(&resolved);
        assert!(!is_policy_only_mismatch(&entry, &resolved));
    }

    #[test]
    fn display_policy_value_none_shows_inherit() {
        let messages = Messages::new("en").unwrap();
        assert_eq!(display_policy_value(None, &messages), "inherit");
    }

    #[test]
    fn display_policy_value_some_shows_value() {
        let messages = Messages::new("en").unwrap();
        assert_eq!(display_policy_value(Some("1h"), &messages), "1h");
    }

    #[test]
    fn display_wrap_ttl_none_shows_default() {
        let messages = Messages::new("en").unwrap();
        assert_eq!(display_wrap_ttl(None, &messages), "30m (default)");
    }

    #[test]
    fn display_wrap_ttl_zero_shows_disabled() {
        let messages = Messages::new("en").unwrap();
        assert_eq!(display_wrap_ttl(Some("0"), &messages), "disabled");
    }

    #[test]
    fn display_wrap_ttl_explicit_shows_value() {
        let messages = Messages::new("en").unwrap();
        assert_eq!(display_wrap_ttl(Some("10m"), &messages), "10m");
    }

    #[test]
    fn build_secret_id_options_includes_token_bound_cidrs() {
        let mut resolved = sample_resolved();
        resolved.token_bound_cidrs = Some(vec!["10.0.0.0/24".to_string()]);

        let opts = build_secret_id_options(&resolved);
        assert_eq!(
            opts.token_bound_cidrs.as_deref(),
            Some(["10.0.0.0/24".to_string()].as_slice())
        );
    }

    #[test]
    fn build_secret_id_options_omits_cidrs_when_none() {
        let resolved = sample_resolved();
        let opts = build_secret_id_options(&resolved);
        assert!(opts.token_bound_cidrs.is_none());
    }

    #[test]
    fn policy_fields_match_differs_on_token_bound_cidrs() {
        let resolved = sample_resolved();
        let mut entry = sample_entry_from_resolved(&resolved);
        entry.approle.token_bound_cidrs = Some(vec!["10.0.0.0/8".to_string()]);
        assert!(!policy_fields_match(&entry, &resolved));
    }

    #[test]
    fn policy_fields_match_with_matching_cidrs() {
        let mut resolved = sample_resolved();
        resolved.token_bound_cidrs = Some(vec!["10.0.0.0/24".to_string()]);
        let entry = sample_entry_from_resolved(&resolved);
        assert!(policy_fields_match(&entry, &resolved));
    }
}
