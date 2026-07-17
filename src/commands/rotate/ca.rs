use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::helpers::{
    confirm_action, ensure_file_exists, restart_compose_service, signal_bootroot_agent,
    try_restart_container,
};
use super::{
    INTERMEDIATE_CA_COMMON_NAME, OPENBAO_AGENT_RESPONDER_CONTAINER, OPENBAO_AGENT_STEPCA_CONTAINER,
    ROOT_CA_COMMON_NAME, RotateContext, RotateOutcome,
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
use crate::state::{DeliveryMode, ServiceEntry};

/// Cadence shared by `--wait` polling for both `remote-bootstrap` (KV
/// payload) and `local-file` (cert on disk) delivery so operators see
/// identical behaviour from `--wait-timeout`.
const REISSUE_WAIT_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(2);

// Phases 0–7 form a single logical workflow; splitting would harm readability.
#[allow(clippy::too_many_lines)]
pub(super) async fn rotate_ca_key(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateCaKeyArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    // Converge secrets ownership before touching any key material. A host
    // that rotated (or ran the documented manual init) before this change
    // can carry root-owned keys the invoking user cannot even read, which
    // would fail the host-side Phase 1 backup below. The sweep repairs
    // that in place and is a no-op when ownership is already correct.
    crate::commands::infra::sweep_secrets_ownership(
        &ctx.compose_file,
        ctx.paths.secrets_dir(),
        messages,
    )?;

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
        // The live certs already hold the new generation (Phase 2), so
        // `compute_ca_bundle_pem` would publish a new-generation-only
        // bundle against the transitional pin list above and every
        // `bootroot verify` run mid-rotation would fail its fingerprint
        // check. Include the Phase-1 backups so the bundle carries both
        // generations, matching the pins.
        let mut bundle_sources = vec![ctx.paths.root_cert()];
        if rot_state.mode == RotationMode::Full {
            bundle_sources.push(ctx.paths.root_cert_bak());
        }
        bundle_sources.push(ctx.paths.intermediate_cert_bak());
        bundle_sources.push(ctx.paths.intermediate_cert());
        let ca_bundle_pem = concat_unique_ca_certs(&bundle_sources, messages).await?;
        trust::write_trust_to_openbao(
            client,
            &ctx.kv_mount,
            &ctx.state.services,
            &transitional_fps,
            &ca_bundle_pem,
            messages,
        )
        .await?;

        restart_infra_openbao_agents();

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
        let mut reissued_local: Vec<&ServiceEntry> = Vec::new();
        for entry in ctx.state.services.values() {
            match classify_phase5_action(entry, &new_inter_cert_path, messages) {
                Phase5Action::SkipMigrated => {
                    println!(
                        "{}",
                        messages.rotate_ca_key_skip_migrated(&entry.service_name)
                    );
                }
                Phase5Action::LocalReissue => {
                    let _ = fs::remove_file(&entry.cert_path);
                    let _ = fs::remove_file(&entry.key_path);
                    signal_bootroot_agent(entry, messages)?;
                    reissued_local.push(entry);
                }
                Phase5Action::RemoteHint => {
                    println!(
                        "{}",
                        messages.rotate_ca_key_reissue_remote_hint(&entry.service_name)
                    );
                }
            }
        }

        crate::commands::service::print_consumer_reload_hint(
            reissued_local.iter().copied(),
            messages,
        );

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

        // Without a restart the infra OpenBao Agents keep serving the
        // Phase-3 transitional pin list (which still includes the
        // retired intermediate) for up to the 30s static-secret render
        // interval. Service agents converge on their own via fast-poll.
        restart_infra_openbao_agents();

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

/// Concatenates the given CA certificate files into a PEM bundle,
/// skipping duplicates by DER SHA-256 (first occurrence wins). Phase 3
/// uses this to publish a transitional bundle that contains both CA
/// generations, so the rendered `ca-bundle.pem` satisfies every
/// fingerprint in the transitional pin list. Missing files are an
/// error: silently omitting a source would republish a bundle that no
/// longer covers the pins.
async fn concat_unique_ca_certs(
    paths: &[std::path::PathBuf],
    messages: &Messages,
) -> Result<String> {
    let mut bundle = String::new();
    let mut seen: Vec<String> = Vec::new();
    for path in paths {
        let fingerprint = read_ca_cert_fingerprint(path, messages).await?;
        if seen.contains(&fingerprint) {
            continue;
        }
        seen.push(fingerprint);
        let pem = tokio::fs::read_to_string(path)
            .await
            .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
        bundle.push_str(&pem);
        if !bundle.ends_with('\n') {
            bundle.push('\n');
        }
    }
    Ok(bundle)
}

/// Resolves the `--user <uid>:<gid>` value for a `step` helper container
/// from the owner of `secrets_dir`. Every `step` subcommand bootroot runs
/// against `secrets/` runs as that owner so the material it writes matches
/// the host ownership kept by the `OpenBao` Agent sidecars — never `root`.
fn owner_user_arg(secrets_dir: &Path, messages: &Messages) -> Result<String> {
    let meta = fs::metadata(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    Ok(format!("{}:{}", meta.uid(), meta.gid()))
}

/// Builds the `docker run` argv that regenerates the root CA as the
/// secrets-directory owner. Kept pure so tests can assert it carries
/// `--user <uid>:<gid>` rather than `--user root`.
fn generate_root_docker_args(mount: &str, user_arg: &str) -> Vec<String> {
    [
        "run",
        "--user",
        user_arg,
        "--rm",
        "-v",
        mount,
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
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Builds the `docker run` argv that regenerates the intermediate CA as
/// the secrets-directory owner. Kept pure so tests can assert it carries
/// `--user <uid>:<gid>` rather than `--user root`.
fn generate_intermediate_docker_args(mount: &str, user_arg: &str) -> Vec<String> {
    [
        "run",
        "--user",
        user_arg,
        "--rm",
        "-v",
        mount,
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
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

fn generate_new_root(ctx: &RotateContext, messages: &Messages) -> Result<()> {
    let secrets_dir = ctx.paths.secrets_dir();
    let mount_root = fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let mount = format!("{}:/home/step", mount_root.display());
    let user_arg = owner_user_arg(secrets_dir, messages)?;
    let args = generate_root_docker_args(&mount, &user_arg);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_docker(&arg_refs, "docker step certificate create (root)", messages)?;
    Ok(())
}

fn generate_new_intermediate(ctx: &RotateContext, messages: &Messages) -> Result<()> {
    let secrets_dir = ctx.paths.secrets_dir();
    let mount_root = fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let mount = format!("{}:/home/step", mount_root.display());
    let user_arg = owner_user_arg(secrets_dir, messages)?;
    let args = generate_intermediate_docker_args(&mount, &user_arg);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_docker(&arg_refs, "docker step certificate create", messages)?;
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

/// Restarts the infrastructure `OpenBao` Agents (step-ca / responder) so
/// they re-render their KV templates against the updated trust bundle.
/// Per-service trust propagation is fast-poll's job: each local
/// host-daemon `bootroot-agent` observes the KV trust update on its next
/// fast-poll cycle, so no per-service restart happens here.
fn restart_infra_openbao_agents() {
    let _ = try_restart_container(OPENBAO_AGENT_STEPCA_CONTAINER);
    let _ = try_restart_container(OPENBAO_AGENT_RESPONDER_CONTAINER);
}

/// Outcome for one service entry during phase-5 reissue. Decoupled from
/// the side-effecting loop so the consumer-reload hint can be exercised
/// from tests without invoking real signal/filesystem operations.
#[derive(Debug, PartialEq, Eq)]
enum Phase5Action {
    /// Service already presents a cert issued by the new intermediate
    /// (e.g., resumed rotation, partial manual migration). Nothing to
    /// reissue and the service should NOT appear in the consumer-reload
    /// hint.
    SkipMigrated,
    /// Local-file delivery service whose cert needs to be wiped and
    /// re-signaled. Goes into the consumer-reload hint.
    LocalReissue,
    /// Remote-bootstrap delivery service. Operator gets a remote hint
    /// but the consumer-reload hint targets local-file consumers only.
    RemoteHint,
}

fn classify_phase5_action(
    entry: &ServiceEntry,
    new_inter_cert_path: &Path,
    messages: &Messages,
) -> Phase5Action {
    if entry.cert_path.exists()
        && cert_issued_by_new_intermediate(&entry.cert_path, new_inter_cert_path, messages)
            .unwrap_or(false)
    {
        return Phase5Action::SkipMigrated;
    }
    if matches!(entry.delivery_mode, DeliveryMode::LocalFile) {
        Phase5Action::LocalReissue
    } else {
        Phase5Action::RemoteHint
    }
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
) -> Result<RotateOutcome> {
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

    rotate_force_reissue_local(args, &entry, messages).await
}

async fn rotate_force_reissue_local(
    args: &RotateForceReissueArgs,
    entry: &ServiceEntry,
    messages: &Messages,
) -> Result<RotateOutcome> {
    let cert_path = &entry.cert_path;
    let key_path = &entry.key_path;

    // Capture the current cert signal *before* delete + signal so the wait
    // path can detect the agent's rewrite even if the agent races us and
    // produces a fresh cert with the same mtime resolution as the old one.
    let before = read_cert_signal(cert_path);

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
    signal_bootroot_agent(entry, messages)?;
    println!(
        "{}",
        messages.rotate_summary_force_reissue_local_signal(&args.service_name)
    );
    crate::commands::service::print_consumer_reload_hint(std::iter::once(entry), messages);

    if !args.wait {
        return Ok(RotateOutcome::Completed);
    }

    let wait_timeout = humantime::parse_duration(&args.wait_timeout)
        .with_context(|| format!("invalid --wait-timeout value: {}", args.wait_timeout))?;
    let started_at = time::OffsetDateTime::now_utc();

    match wait_for_local_completion(cert_path, before.as_ref(), wait_timeout).await {
        Ok(_after) => {
            let completed_at = time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "unknown".to_string());
            let started_at = started_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "unknown".to_string());
            let elapsed = format_reissue_elapsed(&started_at, &completed_at);
            println!(
                "{}",
                messages.rotate_summary_force_reissue_completed(
                    &args.service_name,
                    &completed_at,
                    &elapsed,
                )
            );
            Ok(RotateOutcome::Completed)
        }
        Err(WaitError::Timeout) => {
            println!(
                "{}",
                messages.rotate_summary_force_reissue_wait_timeout(
                    &args.service_name,
                    &args.wait_timeout,
                )
            );
            Ok(RotateOutcome::WaitTimedOut)
        }
        Err(WaitError::Other(err)) => Err(err),
    }
}

async fn rotate_force_reissue_remote(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    args: &RotateForceReissueArgs,
    messages: &Messages,
) -> Result<RotateOutcome> {
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
        return Ok(RotateOutcome::Completed);
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
            Ok(RotateOutcome::Completed)
        }
        Err(WaitError::Timeout) => {
            println!(
                "{}",
                messages.rotate_summary_force_reissue_wait_timeout(
                    &args.service_name,
                    &args.wait_timeout,
                )
            );
            Ok(RotateOutcome::WaitTimedOut)
        }
        Err(WaitError::Other(err)) => Err(err),
    }
}

#[derive(Debug)]
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
        tokio::time::sleep(REISSUE_WAIT_POLL_INTERVAL).await;
    }
}

/// Snapshot used to detect a `local-file` cert rewrite under `--wait`.
///
/// Serial-only equality is the success signal; mtime is captured as a
/// tiebreaker only because sub-second resolution varies by filesystem and
/// can collide across short polling intervals.
#[derive(Debug, Clone)]
struct CertSignal {
    serial: Option<String>,
    mtime: Option<std::time::SystemTime>,
}

/// Reads `(serial, mtime)` for an existing cert path. Missing files map to
/// `None` for both fields so the post-delete poll treats any new readable
/// cert as success. Errors during parse degrade gracefully to "no
/// captured serial" so the polling path can still detect a rewrite via
/// mtime/file-presence.
fn read_cert_signal(cert_path: &Path) -> Option<CertSignal> {
    let metadata = fs::metadata(cert_path).ok()?;
    let mtime = metadata.modified().ok();
    let serial = read_cert_serial(cert_path).ok();
    Some(CertSignal { serial, mtime })
}

fn read_cert_serial(cert_path: &Path) -> Result<String> {
    use x509_parser::pem::parse_x509_pem;

    let bytes = fs::read(cert_path)
        .with_context(|| format!("Failed to read cert file: {}", cert_path.display()))?;
    let (_, pem) = parse_x509_pem(&bytes).map_err(|err| {
        anyhow::anyhow!(
            "Failed to parse cert PEM ({}): {err:?}",
            cert_path.display()
        )
    })?;
    let cert = pem.parse_x509().map_err(|err| {
        anyhow::anyhow!("Failed to parse cert ({}): {err:?}", cert_path.display())
    })?;
    Ok(format!("{:X}", cert.tbs_certificate.serial))
}

async fn wait_for_local_completion(
    cert_path: &Path,
    before: Option<&CertSignal>,
    wait_timeout: std::time::Duration,
) -> std::result::Result<CertSignal, WaitError> {
    let deadline = tokio::time::Instant::now() + wait_timeout;
    loop {
        if let Some(after) = read_cert_signal(cert_path) {
            let serial_changed = match (
                before.and_then(|b| b.serial.as_ref()),
                after.serial.as_ref(),
            ) {
                (None, Some(_)) => true,
                (Some(prev), Some(curr)) => prev != curr,
                _ => false,
            };
            if serial_changed {
                return Ok(after);
            }
            // Mtime tiebreaker for the rare case where the agent reissues
            // with an identical serial but a freshly written file (e.g.
            // some CA-key rotation paths). Sub-second mtime precision is
            // filesystem-dependent so this is intentionally a fallback,
            // not the primary signal — we require strictly newer mtime
            // and a still-parseable post-rewrite cert.
            let same_serial = matches!(
                (
                    before.and_then(|b| b.serial.as_ref()),
                    after.serial.as_ref(),
                ),
                (Some(prev), Some(curr)) if prev == curr,
            );
            let mtime_strictly_advanced = matches!(
                (before.and_then(|b| b.mtime), after.mtime),
                (Some(prev), Some(curr)) if curr > prev,
            );
            if same_serial && mtime_strictly_advanced {
                return Ok(after);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(WaitError::Timeout);
        }
        tokio::time::sleep(REISSUE_WAIT_POLL_INTERVAL).await;
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::super::test_support::test_messages;
    use super::*;

    /// Phase 3 must publish a bundle covering both CA generations: the
    /// transitional pin list still trusts the old intermediate, so a
    /// bundle missing it makes every mid-rotation `bootroot verify`
    /// fail its fingerprint-subset check.
    #[tokio::test]
    async fn concat_unique_ca_certs_includes_every_generation() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let (_, root_pem) = build_issuer("Root CA");
        let (_, old_inter_pem) = build_issuer("Old Intermediate CA");
        let (_, new_inter_pem) = build_issuer("New Intermediate CA");

        let root = dir.path().join("root_ca.crt");
        let old_inter = dir.path().join("intermediate_ca.crt.bak");
        let new_inter = dir.path().join("intermediate_ca.crt");
        fs::write(&root, &root_pem).expect("write root");
        fs::write(&old_inter, &old_inter_pem).expect("write old intermediate");
        fs::write(&new_inter, &new_inter_pem).expect("write new intermediate");

        let bundle = concat_unique_ca_certs(&[root, old_inter, new_inter], &messages)
            .await
            .expect("bundle");

        assert!(bundle.contains(root_pem.trim()));
        assert!(bundle.contains(old_inter_pem.trim()));
        assert!(bundle.contains(new_inter_pem.trim()));
    }

    /// An intermediate-only resume can hand the same certificate in
    /// twice (e.g. the backup equals the live cert when Phase 2 found
    /// the new intermediate already in place); the bundle must contain
    /// each certificate once.
    #[tokio::test]
    async fn concat_unique_ca_certs_dedupes_by_fingerprint() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let (_, root_pem) = build_issuer("Root CA");
        let (_, inter_pem) = build_issuer("Intermediate CA");

        let root = dir.path().join("root_ca.crt");
        let inter = dir.path().join("intermediate_ca.crt");
        let inter_bak = dir.path().join("intermediate_ca.crt.bak");
        fs::write(&root, &root_pem).expect("write root");
        fs::write(&inter, &inter_pem).expect("write intermediate");
        fs::write(&inter_bak, &inter_pem).expect("write intermediate backup");

        let bundle = concat_unique_ca_certs(&[root, inter_bak, inter], &messages)
            .await
            .expect("bundle");

        assert_eq!(bundle.matches("BEGIN CERTIFICATE").count(), 2);
        assert!(bundle.contains(root_pem.trim()));
        assert!(bundle.contains(inter_pem.trim()));
    }

    /// A missing source file must fail the Phase-3 bundle build instead
    /// of silently publishing a bundle that no longer covers the
    /// transitional pins.
    #[tokio::test]
    async fn concat_unique_ca_certs_errors_on_missing_source() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let (_, root_pem) = build_issuer("Root CA");

        let root = dir.path().join("root_ca.crt");
        fs::write(&root, &root_pem).expect("write root");
        let missing = dir.path().join("intermediate_ca.crt.bak");

        let result = concat_unique_ca_certs(&[root, missing], &messages).await;
        assert!(result.is_err());
    }

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

    fn write_self_signed_cert(path: &Path, cn: &str) -> String {
        use rcgen::{CertificateParams, DnType, KeyPair};
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(vec![cn.to_string()]).expect("params");
        params.distinguished_name.push(DnType::CommonName, cn);
        let cert = params.self_signed(&key).expect("self signed");
        let pem = cert.pem();
        fs::write(path, &pem).expect("write cert");
        read_cert_serial(path).expect("read serial")
    }

    #[test]
    fn read_cert_serial_returns_uppercase_hex() {
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("leaf.crt");
        let serial = write_self_signed_cert(&cert_path, "leaf.example");
        assert!(!serial.is_empty(), "serial must be parsed");
        assert!(
            serial.chars().all(|c| c.is_ascii_hexdigit()),
            "serial must be ASCII hex"
        );
        assert!(
            serial.chars().all(|c| !c.is_ascii_lowercase()),
            "serial must be uppercase hex"
        );
    }

    #[tokio::test]
    async fn wait_for_local_completion_returns_immediately_when_serial_already_changed() {
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("leaf.crt");
        let serial1 = write_self_signed_cert(&cert_path, "leaf-one.example");
        let before = read_cert_signal(&cert_path);
        assert_eq!(
            before.as_ref().and_then(|s| s.serial.clone()),
            Some(serial1)
        );

        let new_serial = write_self_signed_cert(&cert_path, "leaf-two.example");
        let result = wait_for_local_completion(
            &cert_path,
            before.as_ref(),
            std::time::Duration::from_secs(5),
        )
        .await;
        let signal = result.expect("wait should succeed when serial already changed");
        assert_eq!(signal.serial.as_deref(), Some(new_serial.as_str()));
    }

    #[tokio::test]
    async fn wait_for_local_completion_succeeds_when_starting_with_no_cert() {
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("leaf.crt");
        let before = read_cert_signal(&cert_path);
        assert!(before.is_none(), "no cert before");

        let _serial = write_self_signed_cert(&cert_path, "fresh.example");
        let result = wait_for_local_completion(
            &cert_path,
            before.as_ref(),
            std::time::Duration::from_secs(5),
        )
        .await;
        let signal = result.expect("wait should succeed once a cert appears");
        assert!(signal.serial.is_some(), "must observe a serial");
    }

    #[tokio::test]
    async fn wait_for_local_completion_times_out_when_unchanged() {
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("leaf.crt");
        let _serial = write_self_signed_cert(&cert_path, "stable.example");
        let before = read_cert_signal(&cert_path);

        let result = wait_for_local_completion(
            &cert_path,
            before.as_ref(),
            std::time::Duration::from_millis(50),
        )
        .await;
        assert!(matches!(result, Err(WaitError::Timeout)));
    }

    /// Mtime tiebreaker: serial is identical (rare reissue case) but the
    /// file was rewritten with a strictly newer mtime. The wait must
    /// detect the rewrite via mtime rather than time out.
    #[tokio::test]
    async fn wait_for_local_completion_uses_mtime_tiebreaker_for_same_serial() {
        let dir = tempdir().expect("tempdir");
        let cert_path = dir.path().join("leaf.crt");

        // Synthesise a "before" signal whose serial matches what the
        // post-rewrite file will have, but whose mtime is strictly older.
        let serial = write_self_signed_cert(&cert_path, "leaf-pre.example");
        let raw = fs::read(&cert_path).expect("read cert");

        let older_mtime = std::time::SystemTime::now() - std::time::Duration::from_mins(1);
        let before = Some(CertSignal {
            serial: Some(serial.clone()),
            mtime: Some(older_mtime),
        });

        // Rewrite the file in place to advance mtime while keeping the
        // exact serial bytes intact.
        std::thread::sleep(std::time::Duration::from_millis(10));
        fs::write(&cert_path, &raw).expect("rewrite cert");

        let result = wait_for_local_completion(
            &cert_path,
            before.as_ref(),
            std::time::Duration::from_secs(5),
        )
        .await;
        let signal = result.expect("mtime tiebreaker should succeed");
        assert_eq!(signal.serial.as_deref(), Some(serial.as_str()));
    }

    fn make_local_file_entry(name: &str, cert_path: std::path::PathBuf) -> ServiceEntry {
        use std::path::PathBuf;

        use crate::state::ServiceRoleEntry;

        ServiceEntry {
            service_name: name.to_string(),
            delivery_mode: DeliveryMode::LocalFile,
            hostname: "h".to_string(),
            domain: "d.example".to_string(),
            agent_config_path: PathBuf::from("agent.toml"),
            cert_path,
            key_path: PathBuf::from("key.pem"),
            instance_id: None,
            notes: None,
            post_renew_hooks: vec![],
            approle: ServiceRoleEntry {
                role_name: "r".to_string(),
                role_id: "id".to_string(),
                secret_id_path: PathBuf::from("s"),
                policy_name: "p".to_string(),
                secret_id_ttl: None,
                secret_id_wrap_ttl: None,
                token_bound_cidrs: None,
            },
            agent_email: None,
            agent_server: None,
            agent_responder_url: None,
            cert_group_gid: None,
        }
    }

    fn build_issuer(cn: &str) -> (rcgen::Issuer<'static, rcgen::KeyPair>, String) {
        use rcgen::{CertificateParams, DnType, Issuer, KeyPair};

        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(vec![cn.to_string()]).expect("ca params");
        params.distinguished_name.push(DnType::CommonName, cn);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let cert = params.clone().self_signed(&key).expect("self-signed CA");
        (Issuer::new(params, key), cert.pem())
    }

    fn sign_leaf_with(cn: &str, issuer: &rcgen::Issuer<'static, rcgen::KeyPair>) -> String {
        use rcgen::{CertificateParams, DnType, KeyPair};

        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(vec![cn.to_string()]).expect("leaf params");
        params.distinguished_name.push(DnType::CommonName, cn);
        params.signed_by(&key, issuer).expect("sign leaf").pem()
    }

    /// The root-CA regeneration container must run as the secrets-directory
    /// owner, so the `--user` value is the resolved `uid:gid` and never
    /// `root` — otherwise the regenerated key would land root-owned.
    #[test]
    fn generate_root_docker_args_run_as_owner_not_root() {
        let args = generate_root_docker_args("/host/secrets:/home/step", "1000:1000");
        let user_pos = args
            .iter()
            .position(|a| a == "--user")
            .expect("--user present");
        assert_eq!(
            args.get(user_pos + 1).map(String::as_str),
            Some("1000:1000")
        );
        assert!(!args.iter().any(|a| a == "root"));
    }

    /// The intermediate-CA regeneration container must likewise run as the
    /// secrets-directory owner rather than `root`.
    #[test]
    fn generate_intermediate_docker_args_run_as_owner_not_root() {
        let args = generate_intermediate_docker_args("/host/secrets:/home/step", "1000:1000");
        let user_pos = args
            .iter()
            .position(|a| a == "--user")
            .expect("--user present");
        assert_eq!(
            args.get(user_pos + 1).map(String::as_str),
            Some("1000:1000")
        );
        assert!(!args.iter().any(|a| a == "root"));
    }

    /// `owner_user_arg` resolves the `uid:gid` from the secrets directory
    /// owner. In tests that is the invoking user, which is not root.
    #[test]
    fn owner_user_arg_resolves_directory_owner() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let user_arg = owner_user_arg(dir.path(), &messages).expect("owner uid:gid");
        assert!(user_arg.contains(':'));
        assert_ne!(user_arg, "root");
    }

    /// Regression for issue #619: in a mixed registry where one service
    /// still presents a cert from the old intermediate and another has
    /// already been migrated, only the unmigrated service should be
    /// classified for local reissue (and therefore make it into the
    /// consumer-reload hint).
    #[test]
    fn phase5_classifies_only_unmigrated_local_services_for_reissue() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        // Build two intermediates: "old" and "new". A leaf signed by
        // the new one should be SkipMigrated; a leaf signed by the old
        // one should be LocalReissue.
        let (old_issuer, _old_inter_pem) = build_issuer("Old Intermediate");
        let (new_issuer, new_inter_pem) = build_issuer("New Intermediate");

        let new_inter_path = dir.path().join("new_intermediate.crt");
        fs::write(&new_inter_path, &new_inter_pem).expect("write new intermediate");

        let unmigrated_cert = dir.path().join("svc_old.crt");
        fs::write(
            &unmigrated_cert,
            sign_leaf_with("svc-old.example", &old_issuer),
        )
        .expect("write old leaf");
        let migrated_cert = dir.path().join("svc_new.crt");
        fs::write(
            &migrated_cert,
            sign_leaf_with("svc-new.example", &new_issuer),
        )
        .expect("write new leaf");

        let unmigrated = make_local_file_entry("svc-old", unmigrated_cert);
        let migrated = make_local_file_entry("svc-new", migrated_cert);

        assert_eq!(
            classify_phase5_action(&unmigrated, &new_inter_path, &messages),
            Phase5Action::LocalReissue,
            "service still on the old intermediate must be reissued"
        );
        assert_eq!(
            classify_phase5_action(&migrated, &new_inter_path, &messages),
            Phase5Action::SkipMigrated,
            "service already on the new intermediate must be skipped"
        );

        // Simulate the phase-5 loop's hint-collection step and verify
        // only the unmigrated entry would be passed to the
        // consumer-reload hint.
        let registry = [&unmigrated, &migrated];
        let reissued: Vec<&ServiceEntry> = registry
            .iter()
            .copied()
            .filter(|entry| {
                matches!(
                    classify_phase5_action(entry, &new_inter_path, &messages),
                    Phase5Action::LocalReissue
                )
            })
            .collect();
        assert_eq!(reissued.len(), 1);
        assert_eq!(reissued[0].service_name, "svc-old");
    }
}
