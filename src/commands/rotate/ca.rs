use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::helpers::{
    confirm_action, ensure_file_exists, openbao_agent_container_name, restart_compose_service,
    signal_bootroot_agent, try_restart_container,
};
use super::{
    INTERMEDIATE_CA_COMMON_NAME, OPENBAO_AGENT_RESPONDER_CONTAINER, OPENBAO_AGENT_STEPCA_CONTAINER,
    ROOT_CA_COMMON_NAME, RotateContext,
};
use crate::cli::args::{RotateCaKeyArgs, RotateForceReissueArgs, RotateSkipPhase};
use crate::commands::infra::run_docker;
use crate::commands::init::{
    compute_ca_bundle_pem, compute_ca_fingerprints, read_ca_cert_fingerprint,
};
use crate::commands::trust::{
    self, RotationMode, RotationState, create_rotation_state, delete_rotation_state,
    load_rotation_state, update_rotation_state,
};
use crate::i18n::Messages;
use crate::state::DeliveryMode;

// Phases 0–7 form a single logical workflow; splitting would harm readability.
#[allow(clippy::too_many_lines)]
pub(super) async fn rotate_ca_key(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateCaKeyArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    // Phase 0 — Pre-flight
    ensure_file_exists(&ctx.paths.root_cert(), messages)?;
    ensure_file_exists(&ctx.paths.intermediate_cert(), messages)?;
    ensure_file_exists(&ctx.paths.stepca_intermediate_key(), messages)?;
    ensure_file_exists(&ctx.paths.stepca_password(), messages)?;
    if args.full {
        ensure_file_exists(&ctx.paths.stepca_root_key(), messages)?;
    }

    let root_fp = read_ca_cert_fingerprint(&ctx.paths.root_cert(), messages).await?;
    let current_inter_fp =
        read_ca_cert_fingerprint(&ctx.paths.intermediate_cert(), messages).await?;

    println!(
        "{}",
        messages.rotate_ca_key_current_fingerprints(&root_fp, &current_inter_fp)
    );

    if args.full {
        println!("{}", messages.rotate_ca_key_full_checklist());
    }

    let expected_mode = if args.full {
        RotationMode::Full
    } else {
        RotationMode::IntermediateOnly
    };

    let mut start_phase: u8 = 0;
    let mut rot_state = if let Some(state) = load_rotation_state(&ctx.state_dir, messages)? {
        if state.mode != expected_mode {
            let mode_str = if state.mode == RotationMode::Full {
                "full"
            } else {
                "intermediate-only"
            };
            anyhow::bail!(messages.error_rotation_mode_mismatch(mode_str));
        }
        println!(
            "{}",
            messages.rotate_ca_key_resuming(&state.phase.to_string())
        );
        start_phase = state.phase;
        state
    } else {
        if ctx.paths.intermediate_cert_bak().exists() || ctx.paths.intermediate_key_bak().exists() {
            eprintln!("{}", messages.warning_stale_backup());
        }
        if args.full && (ctx.paths.root_cert_bak().exists() || ctx.paths.root_key_bak().exists()) {
            eprintln!("{}", messages.warning_stale_backup());
        }
        let prompt = if args.full {
            messages.prompt_rotate_ca_key_full(&root_fp, &current_inter_fp)
        } else {
            messages.prompt_rotate_ca_key(&root_fp, &current_inter_fp)
        };
        confirm_action(prompt.as_str(), auto_confirm, messages)?;
        RotationState {
            mode: expected_mode,
            started_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            old_root_fp: root_fp.clone(),
            new_root_fp: root_fp,
            old_intermediate_fp: current_inter_fp,
            new_intermediate_fp: String::new(),
            phase: 0,
        }
    };

    // Phase 1 — Backup
    if start_phase < 1 {
        println!("{}", messages.rotate_ca_key_phase_backup());
        if rot_state.mode == RotationMode::Full {
            backup_file(&ctx.paths.root_cert(), &ctx.paths.root_cert_bak(), messages)?;
            backup_file(
                &ctx.paths.stepca_root_key(),
                &ctx.paths.root_key_bak(),
                messages,
            )?;
        }
        backup_file(
            &ctx.paths.intermediate_cert(),
            &ctx.paths.intermediate_cert_bak(),
            messages,
        )?;
        backup_file(
            &ctx.paths.stepca_intermediate_key(),
            &ctx.paths.intermediate_key_bak(),
            messages,
        )?;
        rot_state.phase = 1;
        if start_phase == 0 && rot_state.new_intermediate_fp.is_empty() {
            create_rotation_state(&ctx.state_dir, &rot_state, messages)?;
        } else {
            update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
        }
    } else {
        println!("{}", messages.rotate_ca_key_phase_skipped("1"));
    }

    // Phase 2 — Generate new key pair(s)
    if start_phase < 2 {
        if rot_state.mode == RotationMode::Full {
            // Phase 2a — Generate new root CA
            println!("{}", messages.rotate_ca_key_phase_generate_root());
            let pre_root_fp = read_ca_cert_fingerprint(&ctx.paths.root_cert(), messages).await?;
            if pre_root_fp != rot_state.old_root_fp && !rot_state.old_root_fp.is_empty() {
                rot_state.new_root_fp = pre_root_fp;
            } else {
                generate_new_root(ctx, messages)?;
                rot_state.new_root_fp =
                    read_ca_cert_fingerprint(&ctx.paths.root_cert(), messages).await?;
            }
        }

        // Phase 2b — Generate new intermediate CA (signed by current root on disk)
        println!("{}", messages.rotate_ca_key_phase_generate());
        let pre_fp = read_ca_cert_fingerprint(&ctx.paths.intermediate_cert(), messages).await?;
        if pre_fp != rot_state.old_intermediate_fp && !rot_state.old_intermediate_fp.is_empty() {
            rot_state.new_intermediate_fp = pre_fp;
        } else {
            generate_new_intermediate(ctx, messages)?;
            let new_fp = read_ca_cert_fingerprint(&ctx.paths.intermediate_cert(), messages).await?;
            rot_state.new_intermediate_fp = new_fp;
        }

        rot_state.phase = 2;
        update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
    } else {
        println!("{}", messages.rotate_ca_key_phase_skipped("2"));
    }

    // Phase 3 — Distribute transitional trust (additive)
    if start_phase < 3 {
        println!("{}", messages.rotate_ca_key_phase_trust_additive());

        let transitional_fps = if rot_state.mode == RotationMode::Full {
            vec![
                rot_state.old_root_fp.clone(),
                rot_state.old_intermediate_fp.clone(),
                rot_state.new_root_fp.clone(),
                rot_state.new_intermediate_fp.clone(),
            ]
        } else {
            vec![
                rot_state.old_root_fp.clone(),
                rot_state.old_intermediate_fp.clone(),
                rot_state.new_intermediate_fp.clone(),
            ]
        };
        let ca_bundle_pem = compute_ca_bundle_pem(ctx.paths.secrets_dir(), messages).await?;
        trust::write_trust_to_openbao(
            client,
            &ctx.kv_mount,
            &ctx.state.services,
            &transitional_fps,
            &ca_bundle_pem,
            messages,
        )
        .await?;

        restart_openbao_agent_sidecars(ctx, messages);

        rot_state.phase = 3;
        update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
    } else {
        println!("{}", messages.rotate_ca_key_phase_skipped("3"));
    }

    // Phase 4 — Restart step-ca
    if start_phase < 4 {
        println!("{}", messages.rotate_ca_key_phase_restart_stepca());
        restart_compose_service(&ctx.compose_file, "step-ca", messages)?;

        rot_state.phase = 4;
        update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
    } else {
        println!("{}", messages.rotate_ca_key_phase_skipped("4"));
    }

    // Phase 5 — Re-issue service certificates
    if start_phase < 5 && !args.skip.contains(&RotateSkipPhase::Reissue) {
        println!("{}", messages.rotate_ca_key_phase_reissue());

        let new_inter_cert_path = ctx.paths.intermediate_cert();
        for entry in ctx.state.services.values() {
            let cert_path = &entry.cert_path;
            if cert_path.exists()
                && cert_issued_by_new_intermediate(cert_path, &new_inter_cert_path, messages)
                    .unwrap_or(false)
            {
                println!(
                    "{}",
                    messages.rotate_ca_key_skip_migrated(&entry.service_name)
                );
                continue;
            }

            if matches!(entry.delivery_mode, DeliveryMode::LocalFile) {
                let _ = fs::remove_file(cert_path);
                let _ = fs::remove_file(&entry.key_path);
                signal_bootroot_agent(entry, messages)?;
            } else {
                println!(
                    "{}",
                    messages.rotate_ca_key_reissue_remote_hint(&entry.service_name)
                );
            }
        }

        rot_state.phase = 5;
        update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
    } else if start_phase < 5 {
        println!("{}", messages.rotate_ca_key_phase_skipped("5"));
    }

    // Phase 6 — Finalize trust (subtractive)
    if start_phase < 6 && !args.skip.contains(&RotateSkipPhase::Finalize) {
        println!("{}", messages.rotate_ca_key_phase_finalize());

        let new_inter_cert_path = ctx.paths.intermediate_cert();
        let mut unmigrated = Vec::new();
        for entry in ctx.state.services.values() {
            if matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap) {
                continue;
            }
            let cert_path = &entry.cert_path;
            match cert_issued_by_new_intermediate(cert_path, &new_inter_cert_path, messages) {
                Ok(true) => {}
                _ => unmigrated.push(entry.service_name.clone()),
            }
        }

        if !unmigrated.is_empty() {
            let list = unmigrated.join(", ");
            if !args.force {
                anyhow::bail!(messages.rotate_ca_key_finalize_blocked(&list));
            }
            if rot_state.mode == RotationMode::Full {
                eprintln!("{}", messages.warning_force_finalize_full(&list));
            } else {
                eprintln!("{}", messages.warning_force_finalize());
            }
            if !auto_confirm {
                confirm_action(
                    messages.rotate_ca_key_finalize_blocked(&list).as_str(),
                    false,
                    messages,
                )?;
            }
        }

        let final_fps = vec![
            rot_state.new_root_fp.clone(),
            rot_state.new_intermediate_fp.clone(),
        ];
        let ca_bundle_pem = compute_ca_bundle_pem(ctx.paths.secrets_dir(), messages).await?;
        trust::write_trust_to_openbao(
            client,
            &ctx.kv_mount,
            &ctx.state.services,
            &final_fps,
            &ca_bundle_pem,
            messages,
        )
        .await?;

        rot_state.phase = 6;
        update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
    } else if start_phase < 6 {
        println!("{}", messages.rotate_ca_key_phase_skipped("6"));
    }

    // Phase 7 — Cleanup
    println!("{}", messages.rotate_ca_key_phase_cleanup());
    if args.cleanup {
        let _ = fs::remove_file(ctx.paths.intermediate_cert_bak());
        let _ = fs::remove_file(ctx.paths.intermediate_key_bak());
        if rot_state.mode == RotationMode::Full {
            let _ = fs::remove_file(ctx.paths.root_cert_bak());
            let _ = fs::remove_file(ctx.paths.root_key_bak());
        }
    }
    delete_rotation_state(&ctx.state_dir, messages)?;

    if rot_state.mode == RotationMode::Full {
        println!(
            "{}",
            messages.rotate_ca_key_complete_full(
                &rot_state.old_root_fp,
                &rot_state.new_root_fp,
                &rot_state.old_intermediate_fp,
                &rot_state.new_intermediate_fp,
            )
        );
    } else {
        println!(
            "{}",
            messages.rotate_ca_key_complete(
                &rot_state.old_intermediate_fp,
                &rot_state.new_intermediate_fp,
            )
        );
    }

    Ok(())
}

fn generate_new_root(ctx: &RotateContext, messages: &Messages) -> Result<()> {
    let mount_root = fs::canonicalize(ctx.paths.secrets_dir()).with_context(|| {
        messages.error_resolve_path_failed(&ctx.paths.secrets_dir().display().to_string())
    })?;
    let mount = format!("{}:/home/step", mount_root.display());
    let args = vec![
        "run",
        "--user",
        "root",
        "--rm",
        "-v",
        &mount,
        "smallstep/step-ca",
        "step",
        "certificate",
        "create",
        ROOT_CA_COMMON_NAME,
        "/home/step/certs/root_ca.crt",
        "/home/step/secrets/root_ca_key",
        "--profile",
        "root-ca",
        "--password-file",
        "/home/step/password.txt",
        "--force",
    ];
    run_docker(&args, "docker step certificate create (root)", messages)?;
    Ok(())
}

fn generate_new_intermediate(ctx: &RotateContext, messages: &Messages) -> Result<()> {
    let mount_root = fs::canonicalize(ctx.paths.secrets_dir()).with_context(|| {
        messages.error_resolve_path_failed(&ctx.paths.secrets_dir().display().to_string())
    })?;
    let mount = format!("{}:/home/step", mount_root.display());
    let args = vec![
        "run",
        "--user",
        "root",
        "--rm",
        "-v",
        &mount,
        "smallstep/step-ca",
        "step",
        "certificate",
        "create",
        INTERMEDIATE_CA_COMMON_NAME,
        "/home/step/certs/intermediate_ca.crt",
        "/home/step/secrets/intermediate_ca_key",
        "--profile",
        "intermediate-ca",
        "--ca",
        "/home/step/certs/root_ca.crt",
        "--ca-key",
        "/home/step/secrets/root_ca_key",
        "--password-file",
        "/home/step/password.txt",
        "--ca-password-file",
        "/home/step/password.txt",
        "--force",
    ];
    run_docker(&args, "docker step certificate create", messages)?;
    Ok(())
}

fn backup_file(src: &Path, dst: &Path, messages: &Messages) -> Result<()> {
    if dst.exists() {
        return Ok(());
    }
    fs::copy(src, dst)
        .with_context(|| messages.error_write_file_failed(&dst.display().to_string()))?;
    Ok(())
}

fn restart_openbao_agent_sidecars(ctx: &RotateContext, _messages: &Messages) {
    for entry in ctx.state.services.values() {
        if !matches!(entry.delivery_mode, DeliveryMode::LocalFile) {
            continue;
        }
        let container = openbao_agent_container_name(&entry.service_name);
        let _ = try_restart_container(&container);
    }
    let _ = try_restart_container(OPENBAO_AGENT_STEPCA_CONTAINER);
    let _ = try_restart_container(OPENBAO_AGENT_RESPONDER_CONTAINER);
}

/// Checks whether a leaf certificate was issued by the new intermediate CA
/// by comparing the leaf's Issuer DN with the intermediate's Subject DN.
fn cert_issued_by_new_intermediate(
    cert_path: &Path,
    new_inter_cert_path: &Path,
    messages: &Messages,
) -> Result<bool> {
    use x509_parser::pem::parse_x509_pem;

    let leaf_display = cert_path.display().to_string();
    let leaf_pem_bytes =
        fs::read(cert_path).with_context(|| messages.error_read_file_failed(&leaf_display))?;
    let (_, leaf_pem) = parse_x509_pem(&leaf_pem_bytes).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            messages.error_parse_cert_failed(&leaf_display, &format!("{e:?}"))
        )
    })?;
    let leaf_cert = leaf_pem.parse_x509().map_err(|e| {
        anyhow::anyhow!(
            "{}",
            messages.error_parse_cert_failed(&leaf_display, &format!("{e:?}"))
        )
    })?;

    let inter_display = new_inter_cert_path.display().to_string();
    let inter_pem_bytes = fs::read(new_inter_cert_path)
        .with_context(|| messages.error_read_file_failed(&inter_display))?;
    let (_, inter_pem) = parse_x509_pem(&inter_pem_bytes).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            messages.error_parse_cert_failed(&inter_display, &format!("{e:?}"))
        )
    })?;
    let inter_cert = inter_pem.parse_x509().map_err(|e| {
        anyhow::anyhow!(
            "{}",
            messages.error_parse_cert_failed(&inter_display, &format!("{e:?}"))
        )
    })?;

    Ok(leaf_cert.issuer() == inter_cert.subject())
}

pub(super) async fn rotate_trust_sync(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(messages.prompt_rotate_trust_sync(), auto_confirm, messages)?;

    if crate::commands::trust::rotation_in_progress(&ctx.state_dir) {
        eprintln!("{}", messages.warning_rotation_in_progress());
        anyhow::bail!(messages.error_trust_sync_blocked_by_rotation());
    }

    let secrets_dir = ctx.paths.secrets_dir();
    let fingerprints = compute_ca_fingerprints(secrets_dir, messages).await?;
    let ca_bundle_pem = compute_ca_bundle_pem(secrets_dir, messages).await?;

    crate::commands::trust::write_trust_to_openbao(
        client,
        &ctx.kv_mount,
        &ctx.state.services,
        &fingerprints,
        &ca_bundle_pem,
        messages,
    )
    .await?;

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_trust_sync_global(&fingerprints.join(", "))
    );
    for entry in ctx.state.services.values() {
        println!(
            "{}",
            messages.rotate_summary_trust_sync_service(&entry.service_name)
        );
    }
    Ok(())
}

pub(super) async fn rotate_force_reissue(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateForceReissueArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    let entry = ctx
        .state
        .services
        .get(&args.service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(&args.service_name)))?
        .clone();

    let prompt = if matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap) {
        messages.prompt_rotate_force_reissue_remote(&args.service_name)
    } else {
        messages.prompt_rotate_force_reissue(&args.service_name)
    };
    confirm_action(&prompt, auto_confirm, messages)?;

    if matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap) {
        return rotate_force_reissue_remote(ctx, client, args, messages).await;
    }

    let cert_path = &entry.cert_path;
    let key_path = &entry.key_path;
    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_path);

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_force_reissue_deleted(
            &args.service_name,
            &cert_path.display().to_string(),
            &key_path.display().to_string(),
        )
    );
    signal_bootroot_agent(&entry, messages)?;
    println!(
        "{}",
        messages.rotate_summary_force_reissue_local_signal(&args.service_name)
    );
    Ok(())
}

async fn rotate_force_reissue_remote(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    args: &RotateForceReissueArgs,
    messages: &Messages,
) -> Result<()> {
    use bootroot::trust_bootstrap::{
        REISSUE_REQUESTED_AT_KEY, REISSUE_REQUESTER_KEY, SERVICE_KV_BASE, SERVICE_REISSUE_KV_SUFFIX,
    };
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    let wait_timeout = humantime::parse_duration(&args.wait_timeout)
        .with_context(|| format!("invalid --wait-timeout value: {}", args.wait_timeout))?;

    let requester = args
        .requester
        .clone()
        .or_else(|| std::env::var("USER").ok())
        .or_else(|| std::env::var("LOGNAME").ok())
        .unwrap_or_else(|| "unknown".to_string());

    let requested_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .context("Failed to format requested_at timestamp")?;

    let kv_path = format!(
        "{SERVICE_KV_BASE}/{}/{SERVICE_REISSUE_KV_SUFFIX}",
        args.service_name
    );

    // Capture the version assigned by *this* POST directly from the
    // response body. A follow-up GET would race with the agent's own
    // completion write: if the agent observes, renews, and writes back
    // before the CLI's readback, the GET would report version N+1 and
    // `--wait` would then compare `completed_version (N) >= N+1` and
    // hang forever.
    let request_version = client
        .write_kv_with_version(
            &ctx.kv_mount,
            &kv_path,
            serde_json::json!({
                REISSUE_REQUESTED_AT_KEY: requested_at,
                REISSUE_REQUESTER_KEY: requester,
            }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_force_reissue_requested(&args.service_name, &requested_at)
    );
    println!(
        "{}",
        messages.rotate_summary_force_reissue_will_apply(&args.service_name)
    );

    if !args.wait {
        return Ok(());
    }

    match wait_for_remote_completion(
        client,
        &ctx.kv_mount,
        &kv_path,
        request_version,
        &requested_at,
        wait_timeout,
    )
    .await
    {
        Ok(outcome) => {
            // Prefer the `requested_at` stored in the KV payload over
            // the local variable: the KV read is the authoritative
            // source of what the agent applied, and it keeps the
            // elapsed calculation coherent if a subsequent forced
            // reissue wrote a newer request while --wait was polling.
            let requested_for_elapsed = outcome.requested_at.as_deref().unwrap_or(&requested_at);
            let elapsed = format_reissue_elapsed(requested_for_elapsed, &outcome.completed_at);
            println!(
                "{}",
                messages.rotate_summary_force_reissue_completed(
                    &args.service_name,
                    &outcome.completed_at,
                    &elapsed,
                )
            );
            Ok(())
        }
        Err(WaitError::Timeout) => {
            println!(
                "{}",
                messages.rotate_summary_force_reissue_wait_timeout(
                    &args.service_name,
                    &args.wait_timeout,
                )
            );
            Ok(())
        }
        Err(WaitError::Other(err)) => Err(err),
    }
}

enum WaitError {
    Timeout,
    Other(anyhow::Error),
}

struct WaitOutcome {
    completed_at: String,
    requested_at: Option<String>,
}

/// Formats the end-to-end latency between `requested_at` and
/// `completed_at` (both RFC3339) as a human-readable duration. Falls
/// back to "unknown" when either timestamp cannot be parsed or the
/// completion precedes the request (host-clock skew), so the operator
/// still gets a completion confirmation without a misleading negative
/// or wildly out-of-range duration.
fn format_reissue_elapsed(requested_at: &str, completed_at: &str) -> String {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    let Ok(requested) = OffsetDateTime::parse(requested_at, &Rfc3339) else {
        return "unknown".to_string();
    };
    let Ok(completed) = OffsetDateTime::parse(completed_at, &Rfc3339) else {
        return "unknown".to_string();
    };
    let diff = completed - requested;
    let secs = diff.whole_seconds();
    if secs < 0 {
        return "unknown".to_string();
    }
    let Ok(secs_u64) = u64::try_from(secs) else {
        return "unknown".to_string();
    };
    humantime::format_duration(std::time::Duration::from_secs(secs_u64)).to_string()
}

async fn wait_for_remote_completion(
    client: &OpenBaoClient,
    kv_mount: &str,
    kv_path: &str,
    request_version: Option<u64>,
    requested_at: &str,
    wait_timeout: std::time::Duration,
) -> std::result::Result<WaitOutcome, WaitError> {
    use bootroot::trust_bootstrap::{
        REISSUE_COMPLETED_AT_KEY, REISSUE_COMPLETED_VERSION_KEY, REISSUE_REQUESTED_AT_KEY,
    };

    const POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

    let deadline = tokio::time::Instant::now() + wait_timeout;
    loop {
        match client.try_read_kv_with_version(kv_mount, kv_path).await {
            Ok(Some(read)) => {
                if let Some(obj) = read.data.as_object() {
                    let completed_version = obj
                        .get(REISSUE_COMPLETED_VERSION_KEY)
                        .and_then(serde_json::Value::as_u64);
                    let completed_at = obj
                        .get(REISSUE_COMPLETED_AT_KEY)
                        .and_then(serde_json::Value::as_str);
                    let payload_requested_at = obj
                        .get(REISSUE_REQUESTED_AT_KEY)
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string);
                    if let (Some(completed_at), Some(completed_version)) =
                        (completed_at, completed_version)
                    {
                        let matches_request =
                            request_version.is_none_or(|requested| completed_version >= requested);
                        if matches_request {
                            return Ok(WaitOutcome {
                                completed_at: completed_at.to_string(),
                                requested_at: payload_requested_at,
                            });
                        }
                    } else if let Some(completed_at) = completed_at
                        && request_version.is_none()
                        && completed_at >= requested_at
                    {
                        return Ok(WaitOutcome {
                            completed_at: completed_at.to_string(),
                            requested_at: payload_requested_at,
                        });
                    }
                }
            }
            Ok(None) => {}
            Err(err) => return Err(WaitError::Other(err)),
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(WaitError::Timeout);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::super::test_support::test_messages;
    use super::*;

    #[test]
    fn format_reissue_elapsed_reports_seconds_difference() {
        let elapsed = format_reissue_elapsed("2026-04-19T12:34:56Z", "2026-04-19T12:35:10Z");
        assert_eq!(elapsed, "14s");
    }

    #[test]
    fn format_reissue_elapsed_handles_multi_minute_gap() {
        let elapsed = format_reissue_elapsed("2026-04-19T12:30:00Z", "2026-04-19T12:32:07Z");
        assert_eq!(elapsed, "2m 7s");
    }

    #[test]
    fn format_reissue_elapsed_returns_unknown_on_parse_failure() {
        let elapsed = format_reissue_elapsed("not-a-timestamp", "2026-04-19T12:35:10Z");
        assert_eq!(elapsed, "unknown");
    }

    #[test]
    fn format_reissue_elapsed_returns_unknown_when_completion_precedes_request() {
        let elapsed = format_reissue_elapsed("2026-04-19T12:35:10Z", "2026-04-19T12:34:56Z");
        assert_eq!(elapsed, "unknown");
    }

    #[test]
    fn cert_issued_by_self_signed_matches() {
        use rcgen::{CertificateParams, DnType, Issuer, KeyPair};

        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(vec!["Test CA".to_string()]).expect("ca params");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params
            .clone()
            .self_signed(&ca_key)
            .expect("self-signed CA");
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["leaf.example.com".to_string()]).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "leaf.example.com");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_issuer)
            .expect("signed leaf");

        let ca_path = dir.path().join("ca.crt");
        let leaf_path = dir.path().join("leaf.crt");
        fs::write(&ca_path, ca_cert.pem()).expect("write ca cert");
        fs::write(&leaf_path, leaf_cert.pem()).expect("write leaf cert");

        assert!(
            cert_issued_by_new_intermediate(&leaf_path, &ca_path, &messages).expect("check issuer"),
            "leaf should be recognized as issued by the CA"
        );
    }

    #[test]
    fn cert_issued_by_different_ca_does_not_match() {
        use rcgen::{CertificateParams, DnType, Issuer, KeyPair};

        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        let ca1_key = KeyPair::generate().expect("ca1 key");
        let mut ca1_params =
            CertificateParams::new(vec!["CA One".to_string()]).expect("ca1 params");
        ca1_params
            .distinguished_name
            .push(DnType::CommonName, "CA One");
        ca1_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca1_issuer = Issuer::new(ca1_params, ca1_key);

        let ca2_key = KeyPair::generate().expect("ca2 key");
        let mut ca2_params =
            CertificateParams::new(vec!["CA Two".to_string()]).expect("ca2 params");
        ca2_params
            .distinguished_name
            .push(DnType::CommonName, "CA Two");
        ca2_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca2_cert = ca2_params.self_signed(&ca2_key).expect("self-signed CA2");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["leaf.example.com".to_string()]).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "leaf.example.com");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca1_issuer)
            .expect("signed leaf");

        let ca2_path = dir.path().join("ca2.crt");
        let leaf_path = dir.path().join("leaf.crt");
        fs::write(&ca2_path, ca2_cert.pem()).expect("write ca2 cert");
        fs::write(&leaf_path, leaf_cert.pem()).expect("write leaf cert");

        assert!(
            !cert_issued_by_new_intermediate(&leaf_path, &ca2_path, &messages)
                .expect("check issuer"),
            "leaf should NOT be recognized as issued by a different CA"
        );
    }

    #[test]
    fn cert_issued_by_invalid_pem_returns_error() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        let bad_cert = dir.path().join("bad.crt");
        let good_cert = dir.path().join("good.crt");
        fs::write(&bad_cert, "NOT A PEM FILE").expect("write bad cert");
        fs::write(&good_cert, "ALSO NOT PEM").expect("write good cert");

        let result = cert_issued_by_new_intermediate(&bad_cert, &good_cert, &messages);
        assert!(result.is_err(), "invalid PEM should return error");
    }

    #[test]
    fn cert_issued_by_missing_file_returns_error() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        let missing = dir.path().join("nonexistent.crt");
        let also_missing = dir.path().join("also_missing.crt");

        let result = cert_issued_by_new_intermediate(&missing, &also_missing, &messages);
        assert!(result.is_err(), "missing file should return error");
    }
}
