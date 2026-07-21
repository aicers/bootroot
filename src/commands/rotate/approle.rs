use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::{OpenBaoClient, SecretIdOptions};

use super::helpers::{confirm_action, restart_container, write_secret_id_atomic};
use super::{
    OPENBAO_AGENT_RESPONDER_CONTAINER, OPENBAO_AGENT_STEPCA_CONTAINER, ROLE_ID_FILENAME,
    RotateContext,
};
use crate::cli::args::{InfraRoleTarget, RotateAppRoleSecretIdArgs};
use crate::cli::output::display_secret;
use crate::commands::constants::{SERVICE_KV_BASE, SERVICE_SECRET_ID_KEY};
use crate::commands::init::{
    APPROLE_BOOTROOT_INFRA_ROTATE, APPROLE_BOOTROOT_RESPONDER, APPROLE_BOOTROOT_STEPCA,
    AppRoleLabel, OPENBAO_AGENT_DIR, OPENBAO_AGENT_RESPONDER_DIR, OPENBAO_AGENT_ROLE_ID_NAME,
    OPENBAO_AGENT_SECRET_ID_NAME, OPENBAO_AGENT_STEPCA_DIR, POLICY_BOOTROOT_INFRA_ROTATE,
    ROTATE_SELF_MINT_NUM_USES, SECRET_ID_TTL, TOKEN_TTL, infra_rotate_policy,
    validate_rotate_bound_cidrs,
};
use crate::commands::openbao_auth::RuntimeAuthResolved;
use crate::commands::service::resolve::effective_wrap_ttl;
use crate::i18n::Messages;
use crate::state::{DeliveryMode, ServiceEntry};

/// How the invocation authenticated, as far as the self-mint step needs
/// to know: root-token runs perform no self-mint (a root run has no
/// "own credential" to extend), and `secret_id_file` is `Some` only
/// when the `AppRole` `secret_id` was resolved from
/// `--approle-secret-id-file` — the file the self-mint step replaces.
pub(super) struct RotateAuthContext<'a> {
    pub(super) runtime_auth: &'a RuntimeAuthResolved,
    pub(super) secret_id_file: Option<&'a Path>,
}

/// What the root-token provisioning run does with the recorded CIDR
/// binding for the infra-rotate credential.
#[derive(Clone, Copy)]
enum CidrBindingAction<'a> {
    /// No flag given: re-apply the state-recorded binding (if any), so
    /// a recovery run does not silently drop a hardening the operator
    /// opted into.
    Keep,
    /// `--rotate-bound-cidrs`: record the new binding and apply it.
    Set(&'a [String]),
    /// `--clear-rotate-bound-cidrs`: remove the recorded binding and
    /// mint unbound — the recovery path for a bad recorded CIDR.
    Clear,
}

pub(super) async fn rotate_approle_secret_id(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateAppRoleSecretIdArgs,
    auto_confirm: bool,
    auth: &RotateAuthContext<'_>,
    show_secrets: bool,
    messages: &Messages,
) -> Result<()> {
    let is_root_auth = matches!(auth.runtime_auth, RuntimeAuthResolved::RootToken(_));
    if !args.rotate_bound_cidrs.is_empty() {
        // clap already couples the flag to --infra; the auth mode is
        // only known at runtime. Rejecting (instead of ignoring) keeps a
        // mistyped provisioning run from silently minting an unbound
        // credential.
        if !is_root_auth {
            anyhow::bail!(messages.error_rotate_bound_cidrs_requires_provisioning());
        }
        validate_rotate_bound_cidrs(&args.rotate_bound_cidrs, messages)?;
    }
    if args.clear_rotate_bound_cidrs && !is_root_auth {
        anyhow::bail!(messages.error_clear_rotate_bound_cidrs_requires_provisioning());
    }

    let own_label = if let Some(target) = args.infra {
        let root_provision = is_root_auth.then(|| {
            if args.clear_rotate_bound_cidrs {
                CidrBindingAction::Clear
            } else if args.rotate_bound_cidrs.is_empty() {
                CidrBindingAction::Keep
            } else {
                CidrBindingAction::Set(&args.rotate_bound_cidrs)
            }
        });
        rotate_infra_approle_secret_id(
            ctx,
            client,
            target,
            auto_confirm,
            root_provision,
            show_secrets,
            messages,
        )
        .await?;
        AppRoleLabel::InfraRotate
    } else if args.all_services {
        rotate_all_service_approle_secret_ids(ctx, client, auto_confirm, messages).await?;
        AppRoleLabel::RuntimeRotate
    } else {
        let service_name = args.service_name.as_deref().ok_or_else(|| {
            // clap's ArgGroup guarantees one selector is present; guard for
            // callers that construct the args directly.
            anyhow::anyhow!(messages.error_value_required())
        })?;
        rotate_service_approle_secret_id(ctx, client, service_name, auto_confirm, messages).await?;
        AppRoleLabel::RuntimeRotate
    };

    // Mint-own-last (#672): only after every target of this invocation
    // succeeded, and only for runs authenticated as the rotate AppRole
    // itself. Re-minting the rotate credentials under root auth is the
    // break-glass recovery procedure, not this step.
    if let RuntimeAuthResolved::AppRole { role_id, .. } = auth.runtime_auth {
        self_mint_own_secret_id(
            ctx,
            client,
            own_label,
            role_id,
            auth.secret_id_file,
            messages,
        )
        .await?;
    }

    // Dead-man record point (#672): written on every successful
    // invocation — batch, single-service, and infra alike — and only
    // after the self-mint above, so a failed self-mint cannot suppress
    // the stale-rotation warning in `bootroot status`.
    record_rotation_success(ctx, messages)?;
    Ok(())
}

/// Records the RFC 3339 timestamp of a fully successful
/// `approle-secret-id` invocation in `state.json`. A scheduler that
/// silently stops firing produces no failure log of its own, so this
/// timestamp is the only signal `bootroot status` can watch.
fn record_rotation_success(ctx: &mut RotateContext, messages: &Messages) -> Result<()> {
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .context("Failed to format the rotation-success timestamp")?;
    ctx.state.last_secret_id_rotation = Some(now);
    ctx.state
        .save(&ctx.state_file)
        .with_context(|| messages.error_serialize_state_failed())?;
    Ok(())
}

/// Re-mints the credential this invocation authenticated with and
/// atomically replaces the scheduler's credential file (mint-own-last,
/// issue #672).
///
/// The fresh `secret_id` is minted with the recorded CIDR binding and
/// the [`ROTATE_SELF_MINT_NUM_USES`] cap, then verified with a login
/// *before* the file is replaced. Multiple `secret_id`s are
/// concurrently valid and the old one is never eagerly revoked, so any
/// failure — mint, verification, or a crash before the file write —
/// self-heals: the next run logs in with the old, still-valid
/// credential and retries, and the orphaned mint expires by TTL.
async fn self_mint_own_secret_id(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    label: AppRoleLabel,
    role_id: &str,
    secret_id_file: Option<&Path>,
    messages: &Messages,
) -> Result<()> {
    let role_name = label.role_name();
    let Some(secret_id_path) = secret_id_file else {
        // Inline/env-supplied credentials leave no file to replace. A
        // prominent warning — never a silent no-op — keeps the operator
        // aware that the credential they authenticated with still
        // expires at its TTL.
        eprintln!("{}", messages.warning_self_mint_skipped_non_file(role_name));
        return Ok(());
    };
    let token_bound_cidrs = ctx
        .state
        .rotate_bound_cidrs
        .get(&label.to_string())
        .cloned();
    let options = SecretIdOptions {
        ttl: None,
        num_uses: Some(ROTATE_SELF_MINT_NUM_USES),
        metadata: None,
        token_bound_cidrs,
    };
    let new_secret_id = client
        .create_secret_id(role_name, &options)
        .await
        .with_context(|| messages.error_self_mint_failed(role_name))?;
    // Unlike the service flow, verification is unconditional even under
    // a CIDR binding: the binding names this very host, so a failed
    // login means the binding (or the credential) is wrong and the
    // working file must not be replaced.
    client
        .login_approle(role_id, &new_secret_id)
        .await
        .with_context(|| messages.error_self_mint_verify_failed(role_name))?;
    write_secret_id_atomic(secret_id_path, &new_secret_id, messages).await?;
    // The path argument of the summary line is the credential file
    // path, not the secret value.
    println!(
        "{}",
        messages.rotate_summary_self_mint(
            role_name,
            ROTATE_SELF_MINT_NUM_USES,
            &secret_id_path.display().to_string()
        )
    );
    println!("{}", messages.rotate_summary_self_mint_login_ok(role_name));
    Ok(())
}

/// Per-service facts the caller needs to print an accurate summary:
/// CIDR-bound targets skip the login verification.
struct ServiceRotationReport {
    secret_id_path: String,
    login_verified: bool,
}

async fn rotate_service_approle_secret_id(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    service_name: &str,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(
        &messages.prompt_rotate_approle_secret_id(service_name),
        auto_confirm,
        messages,
    )?;

    let report = rotate_service_secret_id_once(ctx, client, service_name, messages).await?;

    println!("{}", messages.rotate_summary_title());
    // CodeQL flags this as cleartext-logging, but the second argument is
    // `secret_id_path` (a file path), not the secret_id value. Dismiss as false positive.
    println!(
        "{}",
        messages.rotate_summary_approle_secret_id(service_name, &report.secret_id_path)
    );
    if report.login_verified {
        println!("{}", messages.rotate_summary_approle_login_ok(service_name));
    }
    Ok(())
}

/// Rotates every registered service `secret_id` in one invocation so a
/// single scheduled job stays in sync with the registry. One failing
/// target must not leave the remaining targets unrotated: failures are
/// collected, reported per target, and turned into a single non-zero
/// exit at the end.
async fn rotate_all_service_approle_secret_ids(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    let service_names: Vec<String> = ctx.state.services.keys().cloned().collect();
    if service_names.is_empty() {
        println!("{}", messages.rotate_all_no_services());
        return Ok(());
    }
    confirm_action(
        &messages.prompt_rotate_all_approle_secret_ids(service_names.len()),
        auto_confirm,
        messages,
    )?;

    let mut outcomes = Vec::with_capacity(service_names.len());
    for service_name in &service_names {
        let outcome = rotate_service_secret_id_once(ctx, client, service_name, messages).await;
        outcomes.push((service_name.as_str(), outcome));
    }

    println!("{}", messages.rotate_summary_title());
    let mut failed_names = Vec::new();
    for (service_name, outcome) in &outcomes {
        match outcome {
            // The second argument is the secret_id file path, not the secret value.
            Ok(report) => println!(
                "{}",
                messages.rotate_summary_approle_secret_id(service_name, &report.secret_id_path)
            ),
            Err(error) => {
                println!(
                    "{}",
                    messages.rotate_all_target_failed(service_name, &format!("{error:#}"))
                );
                failed_names.push(*service_name);
            }
        }
    }
    let total = outcomes.len();
    let failed = failed_names.len();
    println!(
        "{}",
        messages.rotate_all_result(total - failed, failed, total)
    );
    if !failed_names.is_empty() {
        anyhow::bail!(messages.error_rotate_all_partial_failure(
            failed,
            total,
            &failed_names.join(", ")
        ));
    }
    Ok(())
}

async fn rotate_service_secret_id_once(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    service_name: &str,
    messages: &Messages,
) -> Result<ServiceRotationReport> {
    let entry = ctx
        .state
        .services
        .get(service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(service_name)))?
        .clone();
    let is_remote = matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap);
    if !is_remote {
        ensure_role_id_file(&entry, ctx.state.secrets_dir(), client, messages).await?;
    }
    let secret_id_options = SecretIdOptions {
        ttl: entry.approle.secret_id_ttl.clone(),
        num_uses: Some(0),
        metadata: None,
        token_bound_cidrs: entry.approle.token_bound_cidrs.clone(),
    };
    let wrap_ttl = effective_wrap_ttl(entry.approle.secret_id_wrap_ttl.as_deref());
    let new_secret_id = match wrap_ttl {
        Some(ttl) => {
            client
                .create_secret_id_wrapped(&entry.approle.role_name, &secret_id_options, ttl)
                .await
        }
        None => {
            client
                .create_secret_id(&entry.approle.role_name, &secret_id_options)
                .await
        }
    }
    .with_context(|| messages.error_service_secret_id_mint_failed(service_name))?;
    // The direct local `secret_id` file write is all that is needed: the
    // agent's fast-poll loop re-reads the `secret_id` file on every
    // AppRole re-login, so no process signal or sidecar reload follows.
    if !is_remote {
        write_service_secret_id_file(
            &entry.approle.secret_id_path,
            &new_secret_id,
            ctx.state.secrets_dir(),
            messages,
        )
        .await?;
    }
    let has_cidr_binding = entry.approle.token_bound_cidrs.is_some();
    if !has_cidr_binding {
        client
            .login_approle(&entry.approle.role_id, &new_secret_id)
            .await
            .with_context(|| messages.error_openbao_approle_login_failed())?;
    }
    if is_remote {
        write_remote_service_secret_id(
            client,
            &ctx.kv_mount,
            service_name,
            &new_secret_id,
            messages,
        )
        .await?;
    }
    Ok(ServiceRotationReport {
        secret_id_path: entry.approle.secret_id_path.display().to_string(),
        login_verified: !has_cidr_binding,
    })
}

fn infra_role_name(target: InfraRoleTarget) -> &'static str {
    match target {
        InfraRoleTarget::Stepca => APPROLE_BOOTROOT_STEPCA,
        InfraRoleTarget::Responder => APPROLE_BOOTROOT_RESPONDER,
    }
}

fn infra_agent_dir(ctx: &RotateContext, target: InfraRoleTarget) -> PathBuf {
    let agent_dir = match target {
        InfraRoleTarget::Stepca => OPENBAO_AGENT_STEPCA_DIR,
        InfraRoleTarget::Responder => OPENBAO_AGENT_RESPONDER_DIR,
    };
    ctx.paths
        .secrets_dir()
        .join(OPENBAO_AGENT_DIR)
        .join(agent_dir)
}

fn infra_agent_container(target: InfraRoleTarget) -> &'static str {
    match target {
        InfraRoleTarget::Stepca => OPENBAO_AGENT_STEPCA_CONTAINER,
        InfraRoleTarget::Responder => OPENBAO_AGENT_RESPONDER_CONTAINER,
    }
}

/// Rotates one infra role's `secret_id`. `root_provision` is `Some`
/// exactly when the run is root-authenticated: the provisioning step
/// below runs with the given CIDR-binding action.
async fn rotate_infra_approle_secret_id(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    target: InfraRoleTarget,
    auto_confirm: bool,
    root_provision: Option<CidrBindingAction<'_>>,
    show_secrets: bool,
    messages: &Messages,
) -> Result<()> {
    let role_name = infra_role_name(target);
    confirm_action(
        &messages.prompt_rotate_infra_approle_secret_id(role_name),
        auto_confirm,
        messages,
    )?;

    // Upgrade path: deployments initialized before the dedicated
    // infra-rotate credential existed can provision it by running this
    // command with the root token. The provisioning is idempotent, so
    // re-running recovers a partial earlier attempt and reissues the
    // operator credential. AppRole-authenticated runs skip this entirely
    // (single-auth model: the resolved credential is the only one the
    // command ever uses).
    if let Some(binding) = root_provision {
        provision_infra_rotate_role(ctx, client, binding, show_secrets, messages).await?;
    }

    let agent_dir = infra_agent_dir(ctx, target);
    let secret_id_path = agent_dir.join(OPENBAO_AGENT_SECRET_ID_NAME);
    let role_id = ensure_infra_role_id_file(&agent_dir, role_name, client, messages).await?;

    let secret_id_options = SecretIdOptions {
        ttl: None,
        num_uses: Some(0),
        metadata: None,
        token_bound_cidrs: None,
    };
    let new_secret_id = client
        .create_secret_id(role_name, &secret_id_options)
        .await
        .with_context(|| messages.error_infra_secret_id_mint_failed(role_name))?;
    write_secret_id_atomic(&secret_id_path, &new_secret_id, messages).await?;
    let container = infra_agent_container(target);
    restart_container(container, messages)?;
    // The infra roles carry no CIDR binding, so the post-rotation login
    // verification is unconditional (unlike the service flow).
    client
        .login_approle(&role_id, &new_secret_id)
        .await
        .with_context(|| messages.error_openbao_approle_login_failed())?;

    println!("{}", messages.rotate_summary_title());
    // The second argument is the secret_id file path, not the secret value.
    println!(
        "{}",
        messages.rotate_summary_infra_approle_secret_id(
            role_name,
            &secret_id_path.display().to_string()
        )
    );
    println!(
        "{}",
        messages.rotate_summary_infra_agent_restarted(container)
    );
    println!(
        "{}",
        messages.rotate_summary_infra_approle_login_ok(role_name)
    );
    Ok(())
}

/// Reads the infra agent's on-disk `role_id`, backfilling the file from
/// `OpenBao` when it is missing (mirrors the service flow's
/// `ensure_role_id_file`).
async fn ensure_infra_role_id_file(
    agent_dir: &Path,
    role_name: &str,
    client: &OpenBaoClient,
    messages: &Messages,
) -> Result<String> {
    let role_id_path = agent_dir.join(OPENBAO_AGENT_ROLE_ID_NAME);
    if let Ok(existing) = tokio::fs::read_to_string(&role_id_path).await {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let role_id = client
        .read_role_id(role_name)
        .await
        .with_context(|| messages.error_openbao_role_id_failed())?;
    fs_util::ensure_secrets_dir(agent_dir).await?;
    tokio::fs::write(&role_id_path, &role_id)
        .await
        .with_context(|| messages.error_write_file_failed(&role_id_path.display().to_string()))?;
    fs_util::set_key_permissions(&role_id_path).await?;
    Ok(role_id)
}

/// Ensures the `bootroot-infra-rotate` policy and `AppRole` are present
/// and current, backfills missing `state.json` entries, and prints a
/// freshly minted operator credential (masked unless `--show-secrets`).
///
/// Every step is idempotent (`write_policy` and `create_approle` are
/// create-or-update), so a partial earlier provisioning — role created
/// but policy/state/credential lost before the run completed — is
/// recovered by simply re-running the root-token path. A fresh
/// `secret_id` is minted on every run, which also serves as the recovery
/// path for a lost operator credential.
///
/// [`CidrBindingAction::Set`] replaces the state-recorded CIDR binding
/// for the infra-rotate credential, [`CidrBindingAction::Keep`] keeps
/// the recorded binding (printed, so a recovery run is never surprised
/// by it), and [`CidrBindingAction::Clear`] removes it. The minted
/// operator credential carries the effective binding.
async fn provision_infra_rotate_role(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    binding: CidrBindingAction<'_>,
    show_secrets: bool,
    messages: &Messages,
) -> Result<()> {
    client
        .write_policy(POLICY_BOOTROOT_INFRA_ROTATE, &infra_rotate_policy())
        .await
        .with_context(|| messages.error_openbao_policy_write_failed())?;
    // Preserve the secret_id TTL chosen at `init --secret-id-ttl`:
    // recreating the role with the default would silently shorten the
    // live credential's lifetime while `bootroot status` keeps deriving
    // its stale threshold from the recorded value.
    let secret_id_ttl = ctx
        .state
        .rotate_secret_id_ttl
        .as_deref()
        .unwrap_or(SECRET_ID_TTL);
    client
        .create_approle(
            APPROLE_BOOTROOT_INFRA_ROTATE,
            &[POLICY_BOOTROOT_INFRA_ROTATE],
            TOKEN_TTL,
            secret_id_ttl,
            true,
        )
        .await
        .with_context(|| messages.error_openbao_approle_create_failed())?;
    let role_id = client
        .read_role_id(APPROLE_BOOTROOT_INFRA_ROTATE)
        .await
        .with_context(|| messages.error_openbao_role_id_failed())?;

    let label = AppRoleLabel::InfraRotate.to_string();
    let effective_cidrs = match binding {
        CidrBindingAction::Set(cidrs) => Some(cidrs.to_vec()),
        CidrBindingAction::Keep => ctx.state.rotate_bound_cidrs.get(&label).cloned(),
        CidrBindingAction::Clear => None,
    };
    let secret_id_options = SecretIdOptions {
        token_bound_cidrs: effective_cidrs.clone(),
        ..SecretIdOptions::default()
    };
    let secret_id = client
        .create_secret_id(APPROLE_BOOTROOT_INFRA_ROTATE, &secret_id_options)
        .await
        .with_context(|| messages.error_openbao_secret_id_failed())?;

    let prev_approle = ctx
        .state
        .approles
        .insert(label.clone(), APPROLE_BOOTROOT_INFRA_ROTATE.to_string());
    let prev_policy = ctx
        .state
        .policies
        .insert(label.clone(), POLICY_BOOTROOT_INFRA_ROTATE.to_string());
    let mut state_changed = prev_approle.as_deref() != Some(APPROLE_BOOTROOT_INFRA_ROTATE)
        || prev_policy.as_deref() != Some(POLICY_BOOTROOT_INFRA_ROTATE);
    match binding {
        CidrBindingAction::Set(cidrs) => {
            let prev_cidrs = ctx.state.rotate_bound_cidrs.insert(label, cidrs.to_vec());
            state_changed |= prev_cidrs.as_deref() != Some(cidrs);
        }
        CidrBindingAction::Clear => {
            state_changed |= ctx.state.rotate_bound_cidrs.remove(&label).is_some();
        }
        CidrBindingAction::Keep => {}
    }
    if state_changed {
        ctx.state
            .save(&ctx.state_file)
            .with_context(|| messages.error_serialize_state_failed())?;
    }

    println!(
        "{}",
        messages.rotate_infra_provisioned_role(
            APPROLE_BOOTROOT_INFRA_ROTATE,
            POLICY_BOOTROOT_INFRA_ROTATE
        )
    );
    print_cidr_binding_decision(binding, effective_cidrs.as_deref(), messages);
    println!(
        "{}",
        messages.rotate_infra_provisioned_role_id(APPROLE_BOOTROOT_INFRA_ROTATE, &role_id)
    );
    println!(
        "{}",
        messages.rotate_infra_provisioned_secret_id(
            APPROLE_BOOTROOT_INFRA_ROTATE,
            &display_secret(&secret_id, show_secrets)
        )
    );
    Ok(())
}

/// Surfaces the provisioning run's CIDR-binding decision so a recovery
/// run without the flag is never surprised by a silently re-applied
/// (or bad) binding.
fn print_cidr_binding_decision(
    binding: CidrBindingAction<'_>,
    effective_cidrs: Option<&[String]>,
    messages: &Messages,
) {
    match binding {
        CidrBindingAction::Keep => {
            if let Some(cidrs) = effective_cidrs {
                println!(
                    "{}",
                    messages.rotate_infra_cidr_binding_kept(
                        APPROLE_BOOTROOT_INFRA_ROTATE,
                        &cidrs.join(", ")
                    )
                );
            }
        }
        CidrBindingAction::Clear => {
            println!(
                "{}",
                messages.rotate_infra_cidr_binding_cleared(APPROLE_BOOTROOT_INFRA_ROTATE)
            );
        }
        CidrBindingAction::Set(_) => {}
    }
}

/// Recreates a service's `role_id` file from `OpenBao` when it is
/// missing (a no-op when it is already present).
///
/// The file location follows the configured `secret_id_path`: for the
/// default secrets-tree layout bootroot owns the directory, so it is
/// created via `ensure_secrets_dir` and the recreated `role_id` is
/// root-owned `0600`, unchanged. For a relocated (`--secret-id-path`
/// override) path the directory is operator-provisioned and agent-owned
/// outside the secrets tree: the recovery must **not** create, chmod, or
/// chown that directory (`ensure_secrets_dir` would re-mode it), so it
/// requires the parent to already exist and writes an agent-owned
/// `0600` file chowned to the parent owner — otherwise a later recovery
/// would re-break the non-root agent with a root-owned `role_id`.
async fn ensure_role_id_file(
    entry: &ServiceEntry,
    secrets_dir: &Path,
    client: &OpenBaoClient,
    messages: &Messages,
) -> Result<()> {
    let service_dir = entry
        .approle
        .secret_id_path
        .parent()
        .unwrap_or(Path::new("."));
    let role_id_path = service_dir.join(ROLE_ID_FILENAME);
    if role_id_path.exists() {
        return Ok(());
    }
    let role_id = client
        .read_role_id(&entry.approle.role_name)
        .await
        .with_context(|| messages.error_openbao_role_id_failed())?;
    // Classify by whether the credential path resolves inside the
    // root-owned secrets tree; an override always resolves outside it.
    let is_override =
        !fs_util::path_is_within(&entry.approle.secret_id_path, secrets_dir).unwrap_or(true);
    if is_override {
        fs_util::create_owned_credential_noclobber(&role_id_path, role_id.as_bytes())
            .await
            .with_context(|| {
                messages.error_write_file_failed(&role_id_path.display().to_string())
            })?;
    } else {
        fs_util::ensure_secrets_dir(service_dir).await?;
        tokio::fs::write(&role_id_path, role_id)
            .await
            .with_context(|| {
                messages.error_write_file_failed(&role_id_path.display().to_string())
            })?;
        fs_util::set_key_permissions(&role_id_path).await?;
    }
    Ok(())
}

/// Rewrites a local-file service's `secret_id` in place during rotation.
///
/// For the default secrets-tree location `write_secret_id_atomic`
/// re-asserts the directory via `ensure_secrets_dir` before the atomic
/// write. For a relocated (`--secret-id-path` override) path the
/// directory is operator-provisioned and agent-owned, so it must **not**
/// be re-moded: the write goes straight through `atomic_write`, which
/// preserves the existing (agent) uid/gid and re-applies mode `0600`.
async fn write_service_secret_id_file(
    secret_id_path: &Path,
    secret_id: &str,
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let is_override = !fs_util::path_is_within(secret_id_path, secrets_dir).unwrap_or(true);
    if is_override {
        fs_util::atomic_write(secret_id_path, secret_id.as_bytes(), fs_util::KEY_FILE_MODE)
            .await
            .with_context(|| {
                messages.error_write_file_failed(&secret_id_path.display().to_string())
            })?;
    } else {
        write_secret_id_atomic(secret_id_path, secret_id, messages).await?;
    }
    Ok(())
}

async fn write_remote_service_secret_id(
    client: &OpenBaoClient,
    kv_mount: &str,
    service_name: &str,
    secret_id: &str,
    messages: &Messages,
) -> Result<()> {
    client
        .write_kv(
            kv_mount,
            &format!("{SERVICE_KV_BASE}/{service_name}/secret_id"),
            serde_json::json!({ SERVICE_SECRET_ID_KEY: secret_id }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::super::test_support::{
        ScopedEnvVar, TEST_DOCKER_ARGS_ENV, env_lock, path_with_prepend, test_messages,
        write_fake_docker_script,
    };
    use super::*;
    use crate::state::{ServiceRoleEntry, StateFile};

    const RUNTIME_ROTATE_ROLE: &str = "bootroot-runtime-rotate-role";

    fn make_ctx(dir: &std::path::Path) -> RotateContext {
        RotateContext {
            openbao_url: String::new(),
            kv_mount: "secret".to_string(),
            compose_file: PathBuf::new(),
            state: StateFile {
                openbao_url: String::new(),
                kv_mount: "secret".to_string(),
                secrets_dir: None,
                policies: BTreeMap::new(),
                approles: BTreeMap::new(),
                services: BTreeMap::new(),
                openbao_bind_addr: None,
                openbao_advertise_addr: None,
                http01_admin_bind_addr: None,
                http01_admin_advertise_addr: None,
                stepca_bind_addr: None,
                stepca_advertise_addr: None,
                infra_certs: BTreeMap::new(),
                ..Default::default()
            },
            paths: super::super::StatePaths::new(dir.join("secrets")),
            state_dir: dir.to_path_buf(),
            state_file: dir.join("state.json"),
        }
    }

    fn service_role_name(name: &str) -> String {
        format!("bootroot-service-{name}-role")
    }

    fn make_service_entry(
        base: &std::path::Path,
        name: &str,
        delivery_mode: DeliveryMode,
    ) -> ServiceEntry {
        ServiceEntry {
            service_name: name.to_string(),
            delivery_mode,
            hostname: "h".to_string(),
            domain: "d.com".to_string(),
            agent_config_path: base.join(name).join("agent.hcl"),
            cert_path: base.join(name).join("cert.pem"),
            key_path: base.join(name).join("key.pem"),
            instance_id: None,
            notes: None,
            post_renew_hooks: vec![],
            approle: ServiceRoleEntry {
                role_name: service_role_name(name),
                role_id: format!("{name}-role-id"),
                secret_id_path: base.join(name).join("secret_id"),
                policy_name: "p".to_string(),
                secret_id_ttl: None,
                // Disable response wrapping so the plain secret-id
                // endpoint mocks match.
                secret_id_wrap_ttl: Some("0".to_string()),
                token_bound_cidrs: None,
            },
            agent_email: None,
            agent_server: None,
            agent_responder_url: None,
            cert_group_gid: None,
        }
    }

    /// Registers a local-file service in the context, pre-creating the
    /// service dir and `role_id` file so rotation skips the `OpenBao`
    /// role-id backfill.
    fn insert_local_service(ctx: &mut RotateContext, base: &std::path::Path, name: &str) {
        let entry = make_service_entry(base, name, DeliveryMode::LocalFile);
        let service_dir = entry
            .approle
            .secret_id_path
            .parent()
            .expect("service secret_id path has a parent")
            .to_path_buf();
        fs::create_dir_all(&service_dir).expect("create service dir");
        fs::write(
            service_dir.join(ROLE_ID_FILENAME),
            format!("{name}-role-id"),
        )
        .expect("write role_id");
        ctx.state.services.insert(name.to_string(), entry);
    }

    fn mount_secret_id_mock(role: &str) -> Mock {
        Mock::given(method("POST"))
            .and(path(format!("/v1/auth/approle/role/{role}/secret-id")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "secret_id": "fresh-secret-id" }
            })))
    }

    fn mount_login_mock() -> Mock {
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "auth": { "client_token": "verified-token" }
            })))
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn rotate_infra_writes_secret_id_restarts_agent_and_verifies_login() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        mount_secret_id_mock(APPROLE_BOOTROOT_STEPCA)
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock().expect(1).mount(&server).await;

        let mut ctx = make_ctx(dir.path());
        let stepca_dir = ctx
            .paths
            .secrets_dir()
            .join(OPENBAO_AGENT_DIR)
            .join(OPENBAO_AGENT_STEPCA_DIR);
        fs::create_dir_all(&stepca_dir).expect("create agent dir");
        fs::write(
            stepca_dir.join(OPENBAO_AGENT_ROLE_ID_NAME),
            "stepca-role-id\n",
        )
        .expect("write role_id");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("scoped-token".to_string());
        let messages = test_messages();
        rotate_infra_approle_secret_id(
            &mut ctx,
            &client,
            InfraRoleTarget::Stepca,
            true,
            None,
            false,
            &messages,
        )
        .await
        .expect("infra rotation should succeed");

        let secret_id_path = stepca_dir.join(OPENBAO_AGENT_SECRET_ID_NAME);
        let contents = fs::read_to_string(&secret_id_path).expect("read secret_id");
        assert_eq!(contents, "fresh-secret-id");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&secret_id_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let logged = fs::read_to_string(&args_log).expect("read docker args");
        let args: Vec<&str> = logged.lines().collect();
        assert_eq!(args, vec!["restart", OPENBAO_AGENT_STEPCA_CONTAINER]);
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn rotate_infra_backfills_missing_role_id_file() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_RESPONDER}/role-id"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "role_id": "responder-role-id" }
            })))
            .expect(1)
            .mount(&server)
            .await;
        mount_secret_id_mock(APPROLE_BOOTROOT_RESPONDER)
            .mount(&server)
            .await;
        mount_login_mock().mount(&server).await;

        let mut ctx = make_ctx(dir.path());
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("scoped-token".to_string());
        let messages = test_messages();
        rotate_infra_approle_secret_id(
            &mut ctx,
            &client,
            InfraRoleTarget::Responder,
            true,
            None,
            false,
            &messages,
        )
        .await
        .expect("infra rotation should succeed");

        let responder_dir = ctx
            .paths
            .secrets_dir()
            .join(OPENBAO_AGENT_DIR)
            .join(OPENBAO_AGENT_RESPONDER_DIR);
        let role_id = fs::read_to_string(responder_dir.join(OPENBAO_AGENT_ROLE_ID_NAME))
            .expect("role_id backfilled");
        assert_eq!(role_id, "responder-role-id");
        let logged = fs::read_to_string(&args_log).expect("read docker args");
        let args: Vec<&str> = logged.lines().collect();
        assert_eq!(args, vec!["restart", OPENBAO_AGENT_RESPONDER_CONTAINER]);
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn rotate_infra_permission_denied_hints_at_infra_credential() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_STEPCA}/secret-id"
            )))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(r#"{"errors":["permission denied"]}"#),
            )
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        let stepca_dir = ctx
            .paths
            .secrets_dir()
            .join(OPENBAO_AGENT_DIR)
            .join(OPENBAO_AGENT_STEPCA_DIR);
        fs::create_dir_all(&stepca_dir).expect("create agent dir");
        fs::write(
            stepca_dir.join(OPENBAO_AGENT_ROLE_ID_NAME),
            "stepca-role-id",
        )
        .expect("write role_id");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("runtime-rotate-token".to_string());
        let messages = test_messages();
        let err = rotate_infra_approle_secret_id(
            &mut ctx,
            &client,
            InfraRoleTarget::Stepca,
            true,
            None,
            false,
            &messages,
        )
        .await
        .expect_err("permission denied must fail the rotation");

        let msg = format!("{err:#}");
        assert!(
            msg.contains(APPROLE_BOOTROOT_INFRA_ROTATE),
            "error must name the expected credential, got: {msg}"
        );
        assert!(
            !stepca_dir.join(OPENBAO_AGENT_SECRET_ID_NAME).exists(),
            "secret_id file must not be touched on mint failure"
        );
        assert!(
            !args_log.exists(),
            "the infra OpenBao Agent must not be restarted on mint failure"
        );
    }

    // Because every provisioning step is an unconditional
    // create-or-update (no exists gate), this same path also recovers a
    // partial earlier attempt: role created in OpenBao but state entries
    // or the operator credential lost before the run completed.
    #[tokio::test]
    async fn provision_infra_rotate_role_creates_policy_role_and_saves_state() {
        let dir = tempdir().expect("tempdir");
        let server = MockServer::start().await;
        mount_provisioning_mocks(&server).await;

        let mut ctx = make_ctx(dir.path());
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let messages = test_messages();
        provision_infra_rotate_role(&mut ctx, &client, CidrBindingAction::Keep, false, &messages)
            .await
            .expect("provisioning should succeed");

        assert_eq!(
            ctx.state.approles.get("infra_rotate").map(String::as_str),
            Some(APPROLE_BOOTROOT_INFRA_ROTATE)
        );
        assert_eq!(
            ctx.state.policies.get("infra_rotate").map(String::as_str),
            Some(POLICY_BOOTROOT_INFRA_ROTATE)
        );
        let saved = fs::read_to_string(&ctx.state_file).expect("state.json saved");
        assert!(saved.contains(APPROLE_BOOTROOT_INFRA_ROTATE));
    }

    /// Mounts the full set of provisioning mocks: policy write, role
    /// create-or-update, `role_id` read, and `secret_id` mint — each
    /// expected exactly once.
    async fn mount_provisioning_mocks(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/sys/policies/acl/{POLICY_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}/role-id"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "role_id": "infra-rotate-role-id" }
            })))
            .expect(1)
            .mount(server)
            .await;
        mount_secret_id_mock(APPROLE_BOOTROOT_INFRA_ROTATE)
            .expect(1)
            .mount(server)
            .await;
    }

    // A fully provisioned deployment still gets the policy/role
    // refreshed and a fresh operator credential, but state.json is not
    // rewritten when its entries are already current.
    #[tokio::test]
    async fn provision_infra_rotate_role_skips_state_save_when_entries_current() {
        let dir = tempdir().expect("tempdir");
        let server = MockServer::start().await;
        mount_provisioning_mocks(&server).await;

        let mut ctx = make_ctx(dir.path());
        let label = AppRoleLabel::InfraRotate.to_string();
        ctx.state
            .approles
            .insert(label.clone(), APPROLE_BOOTROOT_INFRA_ROTATE.to_string());
        ctx.state
            .policies
            .insert(label, POLICY_BOOTROOT_INFRA_ROTATE.to_string());
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let messages = test_messages();
        provision_infra_rotate_role(&mut ctx, &client, CidrBindingAction::Keep, false, &messages)
            .await
            .expect("re-provisioning must succeed on a current deployment");

        assert!(
            !ctx.state_file.exists(),
            "state.json must not be rewritten when its entries are already current"
        );
    }

    /// Mounts a role-id read for the given role name.
    fn mount_role_id_mock(role: &str, role_id: &str) -> Mock {
        Mock::given(method("GET"))
            .and(path(format!("/v1/auth/approle/role/{role}/role-id")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "role_id": role_id }
            })))
    }

    /// A relocated (`--secret-id-path` override) service that is missing
    /// its `role_id` must have it recreated **agent-owned** in the
    /// operator-provisioned directory, without re-moding that directory
    /// (no `ensure_secrets_dir`), or a later recovery re-breaks the agent.
    #[tokio::test]
    async fn ensure_role_id_file_override_recreates_without_remoding_parent() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let secrets_dir = dir.path().join("secrets");
        let agent_dir = dir.path().join("agent").join("svc");
        fs::create_dir_all(&agent_dir).expect("create agent dir");
        // Operator-provisioned dir mode; the override recovery must not
        // touch it (ensure_secrets_dir would force it to 0700).
        fs::set_permissions(&agent_dir, std::fs::Permissions::from_mode(0o755))
            .expect("set agent dir mode");

        let server = MockServer::start().await;
        mount_role_id_mock(&service_role_name("svc"), "svc-role-id")
            .expect(1)
            .mount(&server)
            .await;

        let mut entry = make_service_entry(dir.path(), "svc", DeliveryMode::LocalFile);
        entry.approle.secret_id_path = agent_dir.join("secret_id");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("scoped-token".to_string());
        let messages = test_messages();
        ensure_role_id_file(&entry, &secrets_dir, &client, &messages)
            .await
            .expect("override role_id recovery should succeed");

        let role_id_path = agent_dir.join(ROLE_ID_FILENAME);
        assert_eq!(
            fs::read_to_string(&role_id_path).expect("role_id written"),
            "svc-role-id"
        );
        assert_eq!(
            fs::metadata(&role_id_path).unwrap().permissions().mode() & 0o777,
            0o600,
            "recreated role_id must be 0600"
        );
        assert_eq!(
            fs::metadata(&agent_dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "override recovery must not re-mode the operator directory"
        );
    }

    /// The default (secrets-tree) recovery keeps creating the directory
    /// via `ensure_secrets_dir` and writing a root-owned `0600` file.
    #[tokio::test]
    async fn ensure_role_id_file_default_creates_secrets_tree() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let secrets_dir = dir.path().join("secrets");
        let service_dir = secrets_dir.join("services").join("svc");

        let server = MockServer::start().await;
        mount_role_id_mock(&service_role_name("svc"), "svc-role-id")
            .expect(1)
            .mount(&server)
            .await;

        let mut entry = make_service_entry(dir.path(), "svc", DeliveryMode::LocalFile);
        entry.approle.secret_id_path = service_dir.join("secret_id");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("scoped-token".to_string());
        let messages = test_messages();
        ensure_role_id_file(&entry, &secrets_dir, &client, &messages)
            .await
            .expect("default role_id recovery should succeed");

        let role_id_path = service_dir.join(ROLE_ID_FILENAME);
        assert_eq!(
            fs::read_to_string(&role_id_path).expect("role_id written"),
            "svc-role-id"
        );
        assert_eq!(
            fs::metadata(&service_dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "default recovery creates the secrets tree 0700"
        );
    }

    /// Rotating a relocated `secret_id` writes it to the configured
    /// location, preserves the existing (agent) uid/gid at `0600`, and
    /// must not re-mode the operator-owned directory. Gated on a
    /// supplementary gid, like the other ownership tests.
    #[tokio::test]
    async fn write_service_secret_id_file_override_preserves_owner_and_parent_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let Some(gid) = bootroot::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().expect("tempdir");
        let secrets_dir = dir.path().join("secrets");
        let agent_dir = dir.path().join("agent").join("svc");
        fs::create_dir_all(&agent_dir).expect("create agent dir");
        fs::set_permissions(&agent_dir, std::fs::Permissions::from_mode(0o750))
            .expect("set agent dir mode");
        let secret_id_path = agent_dir.join("secret_id");
        fs::write(&secret_id_path, "old").expect("seed secret_id");
        std::os::unix::fs::chown(&secret_id_path, None, Some(gid))
            .expect("test process must be able to chgrp the seeded secret_id");
        let messages = test_messages();

        write_service_secret_id_file(&secret_id_path, "new", &secrets_dir, &messages)
            .await
            .expect("override secret_id rotation should succeed");

        assert_eq!(fs::read_to_string(&secret_id_path).unwrap(), "new");
        let meta = fs::metadata(&secret_id_path).unwrap();
        assert_eq!(meta.gid(), gid, "rotation must preserve the agent gid");
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        assert_eq!(
            fs::metadata(&agent_dir).unwrap().permissions().mode() & 0o777,
            0o750,
            "rotation must not re-mode the operator directory"
        );
    }

    /// The default (secrets-tree) rotation still (re)creates the service
    /// directory `0700` via `ensure_secrets_dir`.
    #[tokio::test]
    async fn write_service_secret_id_file_default_creates_secrets_tree() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let secrets_dir = dir.path().join("secrets");
        let service_dir = secrets_dir.join("services").join("svc");
        let secret_id_path = service_dir.join("secret_id");
        let messages = test_messages();

        write_service_secret_id_file(&secret_id_path, "sid", &secrets_dir, &messages)
            .await
            .expect("default secret_id rotation should succeed");

        assert_eq!(fs::read_to_string(&secret_id_path).unwrap(), "sid");
        assert_eq!(
            fs::metadata(&service_dir).unwrap().permissions().mode() & 0o777,
            0o700,
        );
    }

    #[tokio::test]
    async fn rotate_all_services_empty_registry_is_noop_success() {
        let dir = tempdir().expect("tempdir");
        let ctx = make_ctx(dir.path());
        // No OpenBao requests may happen; an unroutable URL makes any
        // accidental call fail loudly.
        let mut client = OpenBaoClient::new("http://127.0.0.1:1").expect("client");
        client.set_token("scoped-token".to_string());
        let messages = test_messages();
        rotate_all_service_approle_secret_ids(&ctx, &client, true, &messages)
            .await
            .expect("an empty service registry must be a no-op success");
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn rotate_all_services_rotates_local_and_remote_targets() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        mount_secret_id_mock(&service_role_name("alpha"))
            .expect(1)
            .mount(&server)
            .await;
        mount_secret_id_mock(&service_role_name("beta"))
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock().expect(2).mount(&server).await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/secret/data/{SERVICE_KV_BASE}/beta/secret_id"
            )))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        insert_local_service(&mut ctx, dir.path(), "alpha");
        ctx.state.services.insert(
            "beta".to_string(),
            make_service_entry(dir.path(), "beta", DeliveryMode::RemoteBootstrap),
        );

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("scoped-token".to_string());
        let messages = test_messages();
        rotate_all_service_approle_secret_ids(&ctx, &client, true, &messages)
            .await
            .expect("batch rotation should succeed");

        let local_secret = fs::read_to_string(dir.path().join("alpha").join("secret_id"))
            .expect("local secret_id written");
        assert_eq!(local_secret, "fresh-secret-id");
        assert!(
            !dir.path().join("beta").join("secret_id").exists(),
            "remote-bootstrap targets must not get a local secret_id file"
        );
        assert!(
            !args_log.exists(),
            "service secret_id rotation must not invoke docker: the local \
             agent's fast-poll loop re-reads the secret_id file on re-login"
        );
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn rotate_all_services_continues_after_per_target_failure() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{}/secret-id",
                service_role_name("alpha")
            )))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(r#"{"errors":["permission denied"]}"#),
            )
            .expect(1)
            .mount(&server)
            .await;
        mount_secret_id_mock(&service_role_name("beta"))
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock().expect(1).mount(&server).await;

        let mut ctx = make_ctx(dir.path());
        insert_local_service(&mut ctx, dir.path(), "alpha");
        insert_local_service(&mut ctx, dir.path(), "beta");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("scoped-token".to_string());
        let messages = test_messages();
        let err = rotate_all_service_approle_secret_ids(&ctx, &client, true, &messages)
            .await
            .expect_err("a partial failure must produce a non-zero exit");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("alpha"),
            "the error must name the failed service, got: {msg}"
        );
        assert!(
            !msg.contains("beta"),
            "the error must not list services that rotated successfully, got: {msg}"
        );
        assert!(
            !dir.path().join("alpha").join("secret_id").exists(),
            "the failed target's secret_id file must not be touched"
        );
        let beta_secret = fs::read_to_string(dir.path().join("beta").join("secret_id"))
            .expect("the remaining target must still be rotated");
        assert_eq!(beta_secret, "fresh-secret-id");
        assert!(
            !args_log.exists(),
            "service secret_id rotation must not invoke docker: the local \
             agent's fast-poll loop re-reads the secret_id file on re-login"
        );
    }

    fn approle_args(
        service_name: Option<&str>,
        all_services: bool,
        infra: Option<InfraRoleTarget>,
    ) -> RotateAppRoleSecretIdArgs {
        RotateAppRoleSecretIdArgs {
            service_name: service_name.map(str::to_string),
            all_services,
            infra,
            rotate_bound_cidrs: Vec::new(),
            clear_rotate_bound_cidrs: false,
        }
    }

    fn approle_auth<'a>(
        role_id: &str,
        secret_id: &str,
        secret_id_file: Option<&'a Path>,
    ) -> (RuntimeAuthResolved, Option<&'a Path>) {
        (
            RuntimeAuthResolved::AppRole {
                role_id: role_id.to_string(),
                secret_id: secret_id.to_string(),
            },
            secret_id_file,
        )
    }

    /// Mounts a self-mint mock for the given rotate role that requires
    /// the `num_uses` cap in the request body — the sizing-rule
    /// assertion lives in the request matcher itself.
    fn mount_self_mint_mock(role: &str, secret_id: &str) -> Mock {
        Mock::given(method("POST"))
            .and(path(format!("/v1/auth/approle/role/{role}/secret-id")))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "num_uses": ROTATE_SELF_MINT_NUM_USES,
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "secret_id": secret_id }
            })))
    }

    fn mount_login_mock_for(role_id: &str, secret_id: &str, status: u16) -> Mock {
        let response = if status == 200 {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "auth": { "client_token": "verified-token" }
            }))
        } else {
            ResponseTemplate::new(status).set_body_string(r#"{"errors":["permission denied"]}"#)
        };
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "role_id": role_id,
                "secret_id": secret_id,
            })))
            .respond_with(response)
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn self_mint_replaces_credential_file_after_successful_run() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        mount_secret_id_mock(&service_role_name("alpha"))
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock_for("alpha-role-id", "fresh-secret-id", 200)
            .expect(1)
            .mount(&server)
            .await;
        mount_self_mint_mock(RUNTIME_ROTATE_ROLE, "self-minted-secret")
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock_for("rr-role-id", "self-minted-secret", 200)
            .expect(1)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        insert_local_service(&mut ctx, dir.path(), "alpha");
        let credential_path = dir.path().join("rotate-cred").join("secret_id");
        fs::create_dir_all(credential_path.parent().expect("parent")).expect("create cred dir");
        fs::write(&credential_path, "old-rotate-secret").expect("seed credential file");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("runtime-rotate-token".to_string());
        let messages = test_messages();
        let (runtime_auth, secret_id_file) =
            approle_auth("rr-role-id", "old-rotate-secret", Some(&credential_path));
        let auth = RotateAuthContext {
            runtime_auth: &runtime_auth,
            secret_id_file,
        };
        rotate_approle_secret_id(
            &mut ctx,
            &client,
            &approle_args(Some("alpha"), false, None),
            true,
            &auth,
            false,
            &messages,
        )
        .await
        .expect("rotation with self-mint should succeed");

        let replaced = fs::read_to_string(&credential_path).expect("read credential file");
        assert_eq!(
            replaced, "self-minted-secret",
            "the scheduler's credential file must hold the fresh self-minted secret_id"
        );
        assert_eq!(
            ctx.state
                .last_secret_id_rotation
                .as_deref()
                .map(str::is_empty),
            Some(false),
            "the dead-man timestamp must be recorded on success"
        );
        let saved = fs::read_to_string(&ctx.state_file).expect("state.json saved");
        assert!(
            saved.contains("last_secret_id_rotation"),
            "state.json must persist the dead-man timestamp"
        );
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn self_mint_skipped_with_warning_when_auth_not_file_based() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        mount_secret_id_mock(&service_role_name("alpha"))
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock().expect(1).mount(&server).await;
        // The self-mint endpoint must never be hit without a file to
        // replace (defined non-file-auth behavior: warn and skip).
        mount_self_mint_mock(RUNTIME_ROTATE_ROLE, "self-minted-secret")
            .expect(0)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        insert_local_service(&mut ctx, dir.path(), "alpha");
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("runtime-rotate-token".to_string());
        let messages = test_messages();
        let (runtime_auth, secret_id_file) = approle_auth("rr-role-id", "inline-secret", None);
        let auth = RotateAuthContext {
            runtime_auth: &runtime_auth,
            secret_id_file,
        };
        rotate_approle_secret_id(
            &mut ctx,
            &client,
            &approle_args(Some("alpha"), false, None),
            true,
            &auth,
            false,
            &messages,
        )
        .await
        .expect("non-file auth must warn and skip the self-mint, not fail");
        assert!(
            ctx.state.last_secret_id_rotation.is_some(),
            "the dead-man timestamp is still recorded"
        );
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn no_self_mint_under_root_auth() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        mount_secret_id_mock(&service_role_name("alpha"))
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock().expect(1).mount(&server).await;
        mount_self_mint_mock(RUNTIME_ROTATE_ROLE, "self-minted-secret")
            .expect(0)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        insert_local_service(&mut ctx, dir.path(), "alpha");
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let messages = test_messages();
        let runtime_auth = RuntimeAuthResolved::RootToken("root-token".to_string());
        let auth = RotateAuthContext {
            runtime_auth: &runtime_auth,
            secret_id_file: None,
        };
        rotate_approle_secret_id(
            &mut ctx,
            &client,
            &approle_args(Some("alpha"), false, None),
            true,
            &auth,
            false,
            &messages,
        )
        .await
        .expect("root-auth rotation succeeds without a self-mint");
        assert!(
            ctx.state.last_secret_id_rotation.is_some(),
            "the dead-man timestamp is recorded for root-auth runs too"
        );
    }

    // Mint-own-last ordering: a failed target must abort the invocation
    // before the self-mint and before the dead-man record point.
    #[tokio::test]
    async fn self_mint_and_record_skipped_when_target_fails() {
        let dir = tempdir().expect("tempdir");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{}/secret-id",
                service_role_name("alpha")
            )))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(r#"{"errors":["permission denied"]}"#),
            )
            .mount(&server)
            .await;
        mount_self_mint_mock(RUNTIME_ROTATE_ROLE, "self-minted-secret")
            .expect(0)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        insert_local_service(&mut ctx, dir.path(), "alpha");
        let credential_path = dir.path().join("rotate-cred").join("secret_id");
        fs::create_dir_all(credential_path.parent().expect("parent")).expect("create cred dir");
        fs::write(&credential_path, "old-rotate-secret").expect("seed credential file");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("runtime-rotate-token".to_string());
        let messages = test_messages();
        let (runtime_auth, secret_id_file) =
            approle_auth("rr-role-id", "old-rotate-secret", Some(&credential_path));
        let auth = RotateAuthContext {
            runtime_auth: &runtime_auth,
            secret_id_file,
        };
        rotate_approle_secret_id(
            &mut ctx,
            &client,
            &approle_args(Some("alpha"), false, None),
            true,
            &auth,
            false,
            &messages,
        )
        .await
        .expect_err("a failed target must fail the invocation");

        assert_eq!(
            fs::read_to_string(&credential_path).expect("read credential file"),
            "old-rotate-secret",
            "the credential file must be untouched when a target fails"
        );
        assert!(
            ctx.state.last_secret_id_rotation.is_none(),
            "the dead-man timestamp must not be recorded on failure"
        );
        assert!(
            !ctx.state_file.exists(),
            "state.json must not be written on failure"
        );
    }

    // Crash-safety (no eager revocation): a self-minted credential that
    // fails its login verification must not replace the working file —
    // the old secret_id stays valid until TTL, so the next run
    // self-heals.
    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn self_mint_verify_failure_keeps_old_credential_file() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        mount_secret_id_mock(&service_role_name("alpha"))
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock_for("alpha-role-id", "fresh-secret-id", 200)
            .expect(1)
            .mount(&server)
            .await;
        mount_self_mint_mock(RUNTIME_ROTATE_ROLE, "self-minted-secret")
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock_for("rr-role-id", "self-minted-secret", 403)
            .expect(1)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        insert_local_service(&mut ctx, dir.path(), "alpha");
        let credential_path = dir.path().join("rotate-cred").join("secret_id");
        fs::create_dir_all(credential_path.parent().expect("parent")).expect("create cred dir");
        fs::write(&credential_path, "old-rotate-secret").expect("seed credential file");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("runtime-rotate-token".to_string());
        let messages = test_messages();
        let (runtime_auth, secret_id_file) =
            approle_auth("rr-role-id", "old-rotate-secret", Some(&credential_path));
        let auth = RotateAuthContext {
            runtime_auth: &runtime_auth,
            secret_id_file,
        };
        let err = rotate_approle_secret_id(
            &mut ctx,
            &client,
            &approle_args(Some("alpha"), false, None),
            true,
            &auth,
            false,
            &messages,
        )
        .await
        .expect_err("a failed self-mint verification must fail the invocation");

        let msg = format!("{err:#}");
        assert!(
            msg.contains(RUNTIME_ROTATE_ROLE),
            "error must name the rotate credential, got: {msg}"
        );
        assert_eq!(
            fs::read_to_string(&credential_path).expect("read credential file"),
            "old-rotate-secret",
            "the working credential file must not be replaced by an unverified secret_id"
        );
        assert!(
            ctx.state.last_secret_id_rotation.is_none(),
            "the dead-man timestamp must not be recorded when the self-mint fails"
        );
        assert!(
            !ctx.state_file.exists(),
            "state.json must not be written when the self-mint fails"
        );
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn self_mint_applies_recorded_cidr_binding() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        mount_secret_id_mock(&service_role_name("alpha"))
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock_for("alpha-role-id", "fresh-secret-id", 200)
            .expect(1)
            .mount(&server)
            .await;
        // The self-mint request must carry the state-recorded binding.
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{RUNTIME_ROTATE_ROLE}/secret-id"
            )))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "num_uses": ROTATE_SELF_MINT_NUM_USES,
                "token_bound_cidrs": ["10.0.0.5/32"],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "secret_id": "self-minted-secret" }
            })))
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock_for("rr-role-id", "self-minted-secret", 200)
            .expect(1)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        insert_local_service(&mut ctx, dir.path(), "alpha");
        ctx.state.rotate_bound_cidrs.insert(
            AppRoleLabel::RuntimeRotate.to_string(),
            vec!["10.0.0.5/32".to_string()],
        );
        let credential_path = dir.path().join("rotate-cred").join("secret_id");
        fs::create_dir_all(credential_path.parent().expect("parent")).expect("create cred dir");
        fs::write(&credential_path, "old-rotate-secret").expect("seed credential file");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("runtime-rotate-token".to_string());
        let messages = test_messages();
        let (runtime_auth, secret_id_file) =
            approle_auth("rr-role-id", "old-rotate-secret", Some(&credential_path));
        let auth = RotateAuthContext {
            runtime_auth: &runtime_auth,
            secret_id_file,
        };
        rotate_approle_secret_id(
            &mut ctx,
            &client,
            &approle_args(Some("alpha"), false, None),
            true,
            &auth,
            false,
            &messages,
        )
        .await
        .expect("CIDR-bound self-mint should succeed");
        assert_eq!(
            fs::read_to_string(&credential_path).expect("read credential file"),
            "self-minted-secret"
        );
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn infra_invocation_self_mints_the_infra_rotate_credential() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        mount_secret_id_mock(APPROLE_BOOTROOT_STEPCA)
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock_for("stepca-role-id", "fresh-secret-id", 200)
            .expect(1)
            .mount(&server)
            .await;
        mount_self_mint_mock(APPROLE_BOOTROOT_INFRA_ROTATE, "self-minted-infra")
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock_for("ir-role-id", "self-minted-infra", 200)
            .expect(1)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        let stepca_dir = ctx
            .paths
            .secrets_dir()
            .join(OPENBAO_AGENT_DIR)
            .join(OPENBAO_AGENT_STEPCA_DIR);
        fs::create_dir_all(&stepca_dir).expect("create agent dir");
        fs::write(
            stepca_dir.join(OPENBAO_AGENT_ROLE_ID_NAME),
            "stepca-role-id",
        )
        .expect("write role_id");
        let credential_path = dir.path().join("infra-rotate-cred").join("secret_id");
        fs::create_dir_all(credential_path.parent().expect("parent")).expect("create cred dir");
        fs::write(&credential_path, "old-infra-rotate-secret").expect("seed credential file");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("infra-rotate-token".to_string());
        let messages = test_messages();
        let (runtime_auth, secret_id_file) = approle_auth(
            "ir-role-id",
            "old-infra-rotate-secret",
            Some(&credential_path),
        );
        let auth = RotateAuthContext {
            runtime_auth: &runtime_auth,
            secret_id_file,
        };
        rotate_approle_secret_id(
            &mut ctx,
            &client,
            &approle_args(None, false, Some(InfraRoleTarget::Stepca)),
            true,
            &auth,
            false,
            &messages,
        )
        .await
        .expect("infra rotation with self-mint should succeed");

        // The next `--infra responder` invocation reads this file at
        // startup and authenticates with the fresh credential.
        assert_eq!(
            fs::read_to_string(&credential_path).expect("read credential file"),
            "self-minted-infra"
        );
    }

    #[tokio::test]
    async fn rotate_bound_cidrs_rejected_without_root_auth() {
        let dir = tempdir().expect("tempdir");
        let mut ctx = make_ctx(dir.path());
        // No OpenBao requests may happen; an unroutable URL makes any
        // accidental call fail loudly.
        let mut client = OpenBaoClient::new("http://127.0.0.1:1").expect("client");
        client.set_token("infra-rotate-token".to_string());
        let messages = test_messages();
        let (runtime_auth, secret_id_file) = approle_auth("ir-role-id", "secret", None);
        let auth = RotateAuthContext {
            runtime_auth: &runtime_auth,
            secret_id_file,
        };
        let mut args = approle_args(None, false, Some(InfraRoleTarget::Stepca));
        args.rotate_bound_cidrs = vec!["10.0.0.5/32".to_string()];
        let err = rotate_approle_secret_id(&mut ctx, &client, &args, true, &auth, false, &messages)
            .await
            .expect_err("--rotate-bound-cidrs without root auth must be rejected");
        assert!(
            format!("{err:#}").contains("--rotate-bound-cidrs"),
            "error must name the flag: {err:#}"
        );
    }

    #[tokio::test]
    async fn provision_records_cidr_binding_and_mints_bound_credential() {
        let dir = tempdir().expect("tempdir");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/sys/policies/acl/{POLICY_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}/role-id"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "role_id": "infra-rotate-role-id" }
            })))
            .mount(&server)
            .await;
        // The provision mint must carry the operator-supplied binding
        // (and no num_uses cap: root-mint fallback deployments consume
        // many logins per credential).
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}/secret-id"
            )))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "token_bound_cidrs": ["10.0.0.5/32"],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "secret_id": "operator-secret" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let messages = test_messages();
        let cidrs = vec!["10.0.0.5/32".to_string()];
        provision_infra_rotate_role(
            &mut ctx,
            &client,
            CidrBindingAction::Set(&cidrs),
            false,
            &messages,
        )
        .await
        .expect("provisioning with CIDR binding should succeed");

        assert_eq!(
            ctx.state
                .rotate_bound_cidrs
                .get("infra_rotate")
                .map(Vec::as_slice),
            Some(cidrs.as_slice()),
            "the binding must be recorded for subsequent self-mints"
        );
        let saved = fs::read_to_string(&ctx.state_file).expect("state.json saved");
        assert!(saved.contains("10.0.0.5/32"));
    }

    #[tokio::test]
    async fn provision_without_flag_keeps_recorded_cidr_binding() {
        let dir = tempdir().expect("tempdir");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/sys/policies/acl/{POLICY_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}/role-id"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "role_id": "infra-rotate-role-id" }
            })))
            .mount(&server)
            .await;
        // Recovery run without the flag: the recorded binding still
        // applies to the freshly minted operator credential.
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}/secret-id"
            )))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "token_bound_cidrs": ["10.0.0.5/32"],
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "secret_id": "operator-secret" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        let label = AppRoleLabel::InfraRotate.to_string();
        ctx.state
            .approles
            .insert(label.clone(), APPROLE_BOOTROOT_INFRA_ROTATE.to_string());
        ctx.state
            .policies
            .insert(label.clone(), POLICY_BOOTROOT_INFRA_ROTATE.to_string());
        ctx.state
            .rotate_bound_cidrs
            .insert(label, vec!["10.0.0.5/32".to_string()]);
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let messages = test_messages();
        provision_infra_rotate_role(&mut ctx, &client, CidrBindingAction::Keep, false, &messages)
            .await
            .expect("recovery provisioning without the flag should succeed");
        assert!(
            !ctx.state_file.exists(),
            "state.json must not be rewritten when nothing changed"
        );
    }

    // Recovery from a bad recorded CIDR: --clear-rotate-bound-cidrs
    // removes the recorded binding and mints the operator credential
    // unbound, so subsequent self-mints are unbound too.
    #[tokio::test]
    async fn provision_clear_flag_removes_recorded_binding_and_mints_unbound() {
        let dir = tempdir().expect("tempdir");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/sys/policies/acl/{POLICY_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}/role-id"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "role_id": "infra-rotate-role-id" }
            })))
            .mount(&server)
            .await;
        // The mint must carry no token_bound_cidrs despite the recorded
        // binding: the empty JSON body is the unbound assertion.
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}/secret-id"
            )))
            .and(wiremock::matchers::body_json(serde_json::json!({})))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "secret_id": "operator-secret" }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        let label = AppRoleLabel::InfraRotate.to_string();
        ctx.state
            .approles
            .insert(label.clone(), APPROLE_BOOTROOT_INFRA_ROTATE.to_string());
        ctx.state
            .policies
            .insert(label.clone(), POLICY_BOOTROOT_INFRA_ROTATE.to_string());
        ctx.state
            .rotate_bound_cidrs
            .insert(label, vec!["192.0.2.9/32".to_string()]);
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let messages = test_messages();
        provision_infra_rotate_role(
            &mut ctx,
            &client,
            CidrBindingAction::Clear,
            false,
            &messages,
        )
        .await
        .expect("clearing the recorded binding should succeed");

        assert!(
            !ctx.state.rotate_bound_cidrs.contains_key("infra_rotate"),
            "the recorded binding must be removed from state"
        );
        let saved = fs::read_to_string(&ctx.state_file).expect("state.json saved");
        assert!(
            !saved.contains("192.0.2.9/32"),
            "the cleared binding must not survive in state.json"
        );
    }

    // The provisioning path must not reset the infra-rotate role's
    // secret_id TTL to the default: a deployment initialized with
    // `--secret-id-ttl 48h` keeps that TTL across a root-token
    // provisioning or recovery run, matching the threshold `bootroot
    // status` derives from state.rotate_secret_id_ttl.
    #[tokio::test]
    async fn provision_preserves_recorded_secret_id_ttl() {
        let dir = tempdir().expect("tempdir");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/sys/policies/acl/{POLICY_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}"
            )))
            .and(wiremock::matchers::body_json(serde_json::json!({
                "token_policies": [POLICY_BOOTROOT_INFRA_ROTATE],
                "token_ttl": TOKEN_TTL,
                "token_max_ttl": TOKEN_TTL,
                "token_renewable": true,
                "secret_id_ttl": "48h",
            })))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}/role-id"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "role_id": "infra-rotate-role-id" }
            })))
            .mount(&server)
            .await;
        mount_secret_id_mock(APPROLE_BOOTROOT_INFRA_ROTATE)
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        ctx.state.rotate_secret_id_ttl = Some("48h".to_string());
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let messages = test_messages();
        provision_infra_rotate_role(&mut ctx, &client, CidrBindingAction::Keep, false, &messages)
            .await
            .expect("provisioning must keep the recorded secret_id TTL");
    }

    #[tokio::test]
    async fn clear_rotate_bound_cidrs_rejected_without_root_auth() {
        let dir = tempdir().expect("tempdir");
        let mut ctx = make_ctx(dir.path());
        // No OpenBao requests may happen; an unroutable URL makes any
        // accidental call fail loudly.
        let mut client = OpenBaoClient::new("http://127.0.0.1:1").expect("client");
        client.set_token("infra-rotate-token".to_string());
        let messages = test_messages();
        let (runtime_auth, secret_id_file) = approle_auth("ir-role-id", "secret", None);
        let auth = RotateAuthContext {
            runtime_auth: &runtime_auth,
            secret_id_file,
        };
        let mut args = approle_args(None, false, Some(InfraRoleTarget::Stepca));
        args.clear_rotate_bound_cidrs = true;
        let err = rotate_approle_secret_id(&mut ctx, &client, &args, true, &auth, false, &messages)
            .await
            .expect_err("--clear-rotate-bound-cidrs without root auth must be rejected");
        assert!(
            format!("{err:#}").contains("--clear-rotate-bound-cidrs"),
            "error must name the flag: {err:#}"
        );
    }

    #[tokio::test]
    async fn rotate_service_permission_denied_names_runtime_rotate_credential() {
        let dir = tempdir().expect("tempdir");
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{}/secret-id",
                service_role_name("alpha")
            )))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(r#"{"errors":["permission denied"]}"#),
            )
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        insert_local_service(&mut ctx, dir.path(), "alpha");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("infra-rotate-token".to_string());
        let messages = test_messages();
        let err = rotate_service_approle_secret_id(&ctx, &client, "alpha", true, &messages)
            .await
            .expect_err("permission denied must fail the rotation");

        let msg = format!("{err:#}");
        assert!(
            msg.contains(RUNTIME_ROTATE_ROLE),
            "error must name the expected credential, got: {msg}"
        );
    }
}
