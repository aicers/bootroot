//! A full CA rotation that stages its new generation
//! (`--pause-before-step-ca`).
//!
//! Phase 2 builds the new root and intermediate at staging paths beside
//! the live files, so the live paths — the only ones step-ca's `ca.json`
//! names — keep the old generation until Phase 4. A step-ca restarted
//! while the rotation is paused after Phase 3 therefore still issues
//! under the old root. Phase 4 removes step-ca, moves the staged files
//! into place, issues `PostgreSQL`'s certificate under the new
//! intermediate, verifies the result and only then starts step-ca again.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};
use bootroot::fs_util::SecretsTree;

use super::super::{RotateContext, STEP_CA_HELPER_IMAGE, StatePaths};
use super::{
    STAGED_CA_TARGETS, generate_new_intermediate, generate_new_root, reissue_postgres_tls_cert,
    step_helper_mount_and_user,
};
use crate::commands::compose_file::compose_file_dir;
use crate::commands::compose_project::ComposeIdentity;
use crate::commands::container_name::BootrootContainer;
use crate::commands::infra::{
    resolve_stepca_exposed_override, run_compose_with_exec, run_docker_with_exec,
    stepca_up_compose_files,
};
use crate::commands::init::{
    POSTGRES_INFRA_CERT_KEY, POSTGRES_TLS_CERT_PATH, fingerprint_ca_cert, to_container_path,
};
use crate::commands::trust::{RotationState, update_rotation_state_async};
use crate::i18n::Messages;

/// The phase a staged rotation pauses after.
const PAUSE_PHASE: u8 = 3;
/// The compose service a staged Phase 4 removes and recreates.
const STEPCA_SERVICE: &str = "step-ca";
/// Where the `step` helper container sees `secrets/`.
const STEP_HELPER_MOUNT: &str = "/home/step";
/// The step-ca password file, as the helper container sees it.
const STEP_HELPER_PASSWORD_FILE: &str = "/home/step/password.txt";

/// What a run does with the rotation state it found, decided before it
/// changes anything.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum StagingDecision {
    /// No rotation is in progress: start one, staged when
    /// `--pause-before-step-ca` is given.
    Start { staged: bool },
    /// Resume the recorded rotation. A staged one given the flag again
    /// pauses after Phase 3; without the flag it runs to the end.
    Resume,
    /// Paused after Phase 3 and given the flag again: print the pause
    /// output and change nothing.
    RepeatPause,
}

/// Decides what a run does with `state` given whether it was asked to
/// pause before step-ca.
///
/// The mode was checked before this: a state of the other mode never
/// reaches here.
///
/// # Errors
///
/// With `pause` given, returns an error for a rotation that can no longer
/// be paused there: one at Phase 4 or later, which has switched step-ca;
/// one started without staging, whose new generation is already live; and
/// a staged one whose Phase 4 has already begun.
pub(super) fn decide_staging(
    state: Option<&RotationState>,
    pause: bool,
    messages: &Messages,
) -> Result<StagingDecision> {
    let Some(state) = state else {
        return Ok(StagingDecision::Start { staged: pause });
    };
    if !pause {
        return Ok(StagingDecision::Resume);
    }
    let phase = state.phase.to_string();
    if state.phase > PAUSE_PHASE {
        anyhow::bail!(messages.error_rotation_pause_stepca_switched(&phase));
    }
    if !state.staged {
        anyhow::bail!(messages.error_rotation_pause_not_staged(&phase));
    }
    if state.phase == PAUSE_PHASE && state.phase4_started {
        anyhow::bail!(messages.error_rotation_pause_phase4_started());
    }
    if state.phase == PAUSE_PHASE {
        return Ok(StagingDecision::RepeatPause);
    }
    Ok(StagingDecision::Resume)
}

/// Returns what a run prints when it pauses before step-ca: the staged
/// new root's path, its SHA-256 DER fingerprint in lowercase hex, its
/// PEM, and the command that continues the rotation.
///
/// # Errors
///
/// Returns an error when the staged root cannot be read or parsed, or is
/// not the new root the rotation state records.
pub(super) async fn pause_notice(
    ctx: &RotateContext,
    state: &RotationState,
    messages: &Messages,
) -> Result<String> {
    let path = ctx.paths.root_cert_staged();
    let read_path = path.clone();
    let read_messages = messages.clone();
    let contents = ctx
        .secrets
        .run(move |tree| {
            read_in(tree, &read_path).with_context(|| {
                read_messages.error_read_file_failed(&read_path.display().to_string())
            })
        })
        .await?;
    let fingerprint = fingerprint_ca_cert(&contents, &path, messages)?;
    // Absolute, so the operator can copy the file from wherever they
    // read the output; `state.json` may record a relative secrets dir.
    let display = std::path::absolute(&path)
        .unwrap_or_else(|_| path.clone())
        .display()
        .to_string();
    if fingerprint != state.new_root_fp {
        anyhow::bail!(messages.error_staged_cert_not_new(
            &display,
            &state.new_root_fp,
            &fingerprint
        ));
    }
    let pem =
        String::from_utf8(contents).with_context(|| messages.error_read_file_failed(&display))?;
    Ok(messages.rotate_ca_key_paused_before_stepca(&display, &fingerprint, pem.trim_end()))
}

/// The certificates Phase 3 of a staged rotation bundles: the new
/// generation from the staging paths and the old one from the live
/// paths, in the order an unstaged rotation bundles them.
pub(super) fn phase3_bundle_sources(paths: &StatePaths) -> Vec<PathBuf> {
    vec![
        paths.root_cert_staged(),
        paths.root_cert(),
        paths.intermediate_cert(),
        paths.intermediate_cert_staged(),
    ]
}

/// Phase 2 of a staged rotation: the new root (2a) and the new
/// intermediate signed by it (2b), at the staging paths, with the new
/// fingerprints read from there into `state`.
///
/// A resumed rotation keeps a staged root whose certificate and key are
/// both present and whose certificate is not the old root, and a staged
/// intermediate likewise when the root was kept and the intermediate is
/// signed by it. A new rotation always generates, overwriting whatever an
/// abandoned one left at the staging paths.
///
/// # Errors
///
/// Returns an error when a generation fails, a staged file cannot be
/// read, or the staged intermediate is not signed by the staged root or
/// is signed by the old one.
pub(super) async fn generate_staged_generation(
    ctx: &RotateContext,
    state: &mut RotationState,
    resumed: bool,
    messages: &Messages,
) -> Result<()> {
    let paths = &ctx.paths;

    println!("{}", messages.rotate_ca_key_phase_generate_root_staged());
    let keep_root = resumed
        && staged_pair_present(ctx, &paths.root_cert_staged(), &paths.root_key_staged()).await?
        && read_fingerprint(ctx, &paths.root_cert_staged(), messages).await? != state.old_root_fp;
    if !keep_root {
        generate_new_root(ctx, &STAGED_CA_TARGETS, messages)?;
    }
    state.new_root_fp = read_fingerprint(ctx, &paths.root_cert_staged(), messages).await?;

    println!("{}", messages.rotate_ca_key_phase_generate_staged());
    let keep_intermediate = keep_root
        && staged_pair_present(
            ctx,
            &paths.intermediate_cert_staged(),
            &paths.intermediate_key_staged(),
        )
        .await?
        && read_fingerprint(ctx, &paths.intermediate_cert_staged(), messages).await?
            != state.old_intermediate_fp
        && cert_signed_by(
            &read_cert(ctx, &paths.intermediate_cert_staged(), messages).await?,
            &read_cert(ctx, &paths.root_cert_staged(), messages).await?,
        )?;
    if !keep_intermediate {
        generate_new_intermediate(ctx, &STAGED_CA_TARGETS, messages)?;
    }
    state.new_intermediate_fp =
        read_fingerprint(ctx, &paths.intermediate_cert_staged(), messages).await?;

    check_staged_chain(ctx, messages).await
}

/// Holds the staged intermediate to the staged new root: signed by it,
/// and not by the old root still at the live path.
async fn check_staged_chain(ctx: &RotateContext, messages: &Messages) -> Result<()> {
    let paths = &ctx.paths;
    let intermediate = read_cert(ctx, &paths.intermediate_cert_staged(), messages).await?;
    let new_root = read_cert(ctx, &paths.root_cert_staged(), messages).await?;
    let old_root = read_cert(ctx, &paths.root_cert(), messages).await?;
    let intermediate_display = paths.intermediate_cert_staged().display().to_string();
    if !cert_signed_by(&intermediate, &new_root)? {
        anyhow::bail!(messages.error_staged_chain_not_new_root(
            &intermediate_display,
            &paths.root_cert_staged().display().to_string(),
        ));
    }
    if cert_signed_by(&intermediate, &old_root)? {
        anyhow::bail!(messages.error_staged_chain_old_root(
            &intermediate_display,
            &paths.root_cert().display().to_string(),
        ));
    }
    Ok(())
}

/// The operations of a staged Phase 4 that reach Docker, separated from
/// the moves and checks around them so the order can be driven in a test
/// without a Docker daemon.
pub(super) trait StepCaSwitch {
    /// Returns the restart policy step-ca's container carries now, or
    /// `None` when there is no such container.
    fn current_restart_policy(&self) -> Result<Option<String>>;
    /// Stops and removes step-ca's container. Succeeds when there is
    /// none.
    fn remove_stepca(&self) -> Result<()>;
    /// Issues `PostgreSQL`'s TLS certificate under the live intermediate
    /// and reloads the server.
    fn reissue_postgres(&self) -> Result<()>;
    /// Returns the DER `SubjectPublicKeyInfo` of the encrypted CA key at
    /// `key`, below the secrets directory.
    fn public_key_der(&self, key: &Path) -> Result<Vec<u8>>;
    /// Recreates and starts step-ca, then applies `restart_policy` to it
    /// when there is one.
    fn start_stepca(&self, restart_policy: Option<&str>) -> Result<()>;
}

/// [`StepCaSwitch`] against the install's Docker Compose project.
pub(super) struct DockerStepCaSwitch<'a> {
    ctx: &'a RotateContext,
    identity: ComposeIdentity,
    compose_file: String,
    stepca_override: Option<String>,
    messages: &'a Messages,
}

impl<'a> DockerStepCaSwitch<'a> {
    /// Resolves the compose identity and the compose files the step-ca
    /// recreate needs, so a missing or mismatched step-ca override stops
    /// Phase 4 before anything is removed.
    ///
    /// # Errors
    ///
    /// Returns an error when the identity cannot be resolved, or when
    /// `state.json` records a `--stepca-bind` whose override file is
    /// missing or does not match it.
    pub(super) fn prepare(ctx: &'a RotateContext, messages: &'a Messages) -> Result<Self> {
        let identity = ComposeIdentity::resolve(&ctx.compose_file, None, messages)?;
        let stepca_override = resolve_stepca_exposed_override(
            &ctx.state_file,
            &compose_file_dir(&ctx.compose_file),
            messages,
        )?
        .map(|path| path.to_string_lossy().into_owned());
        Ok(Self {
            ctx,
            identity,
            compose_file: ctx.compose_file.to_string_lossy().into_owned(),
            stepca_override,
            messages,
        })
    }

    /// The compose files the recreate passes: those `infra up` passes for
    /// step-ca.
    fn up_files(&self) -> Vec<&str> {
        stepca_up_compose_files(&self.compose_file, self.stepca_override.as_deref())
    }

    fn container(&self) -> String {
        self.identity.container(BootrootContainer::StepCa)
    }

    fn docker_output(&self, args: &[&str]) -> Result<std::process::Output> {
        ProcessCommand::new(&self.ctx.docker)
            .args(args)
            .output()
            .with_context(|| self.messages.error_command_run_failed("docker"))
    }
}

impl StepCaSwitch for DockerStepCaSwitch<'_> {
    fn current_restart_policy(&self) -> Result<Option<String>> {
        let container = self.container();
        let output = self.docker_output(&[
            "inspect",
            "--format",
            "{{.HostConfig.RestartPolicy.Name}} {{.HostConfig.RestartPolicy.MaximumRetryCount}}",
            &container,
        ])?;
        if !output.status.success() {
            return Ok(None);
        }
        Ok(restart_policy_from_inspect(&String::from_utf8_lossy(
            &output.stdout,
        )))
    }

    fn remove_stepca(&self) -> Result<()> {
        let invocation =
            self.identity
                .compose(&[&self.compose_file], None, &["rm", "-sf", STEPCA_SERVICE]);
        run_compose_with_exec(
            &invocation,
            "docker compose rm -sf step-ca",
            &self.ctx.docker,
            self.messages,
        )
    }

    fn reissue_postgres(&self) -> Result<()> {
        reissue_postgres_tls_cert(
            &self.ctx.state,
            &compose_file_dir(&self.ctx.compose_file),
            self.ctx.paths.secrets_dir(),
            &self.ctx.docker,
            self.messages,
        )
    }

    fn public_key_der(&self, key: &Path) -> Result<Vec<u8>> {
        let (mount, user_arg) = step_helper_mount_and_user(self.ctx, self.messages)?;
        let container_key =
            to_container_path(self.ctx.paths.secrets_dir(), key, STEP_HELPER_MOUNT)?;
        let args = key_public_docker_args(&mount, &user_arg, &container_key);
        let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let output = self.docker_output(&arg_refs)?;
        if !output.status.success() {
            anyhow::bail!(
                self.messages
                    .error_docker_command_failed(&String::from_utf8_lossy(&output.stderr))
            );
        }
        public_key_der_from_pem(&output.stdout).with_context(|| {
            self.messages
                .error_step_public_key_unreadable(&key.display().to_string())
        })
    }

    fn start_stepca(&self, restart_policy: Option<&str>) -> Result<()> {
        let invocation = self.identity.compose(
            &self.up_files(),
            None,
            &["up", "-d", "--no-deps", STEPCA_SERVICE],
        );
        run_compose_with_exec(
            &invocation,
            "docker compose up -d --no-deps step-ca",
            &self.ctx.docker,
            self.messages,
        )?;
        // The policy `infra up --restart-policy` applied, put back the
        // way `infra up` applies it, so the recreated container does not
        // fall back to the compose file's `restart:`.
        if let Some(policy) = restart_policy {
            let container = self.container();
            run_docker_with_exec(
                &["update", "--restart", policy, &container],
                "docker update",
                &self.ctx.docker,
                self.messages,
            )?;
        }
        Ok(())
    }
}

/// Turns the `<name> <maximum retry count>` that `docker inspect` prints
/// for a restart policy back into the value `docker update --restart`
/// takes, so an `on-failure:N` that `infra up --restart-policy` set keeps
/// its retry limit. Returns `None` when nothing is printed.
///
/// An empty name, which a daemon may print for a container created with
/// no policy, is Docker's `no`; the count after it is never taken for the
/// name.
fn restart_policy_from_inspect(output: &str) -> Option<String> {
    let line = output.trim_end_matches(['\r', '\n']);
    if line.trim().is_empty() {
        return None;
    }
    let (name, count) = line.split_once(' ').unwrap_or((line, ""));
    let name = match name.trim() {
        "" => "no",
        name => name,
    };
    match count.trim().parse::<u32>().ok() {
        Some(count) if name == "on-failure" && count > 0 => Some(format!("{name}:{count}")),
        _ => Some(name.to_string()),
    }
}

/// Builds the `docker run` argv that prints the public key of the
/// encrypted CA key at `container_key` as the secrets-directory owner.
fn key_public_docker_args(mount: &str, user_arg: &str, container_key: &str) -> Vec<String> {
    [
        "run",
        "--user",
        user_arg,
        "--rm",
        "-v",
        mount,
        STEP_CA_HELPER_IMAGE,
        "step",
        "crypto",
        "key",
        "public",
        container_key,
        "--password-file",
        STEP_HELPER_PASSWORD_FILE,
    ]
    .into_iter()
    .map(str::to_string)
    .collect()
}

/// Decodes the `PUBLIC KEY` PEM `step crypto key public` prints.
fn public_key_der_from_pem(output: &[u8]) -> Result<Vec<u8>> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(output)
        .map_err(|err| anyhow::anyhow!("not a PEM block: {err:?}"))?;
    anyhow::ensure!(
        pem.label == "PUBLIC KEY",
        "unexpected PEM label {}",
        pem.label
    );
    Ok(pem.contents)
}

/// One file Phase 4 moves into place: from its staging path to its live
/// path, in the same directory. A certificate carries the fingerprint the
/// rotation state records for it, which the file has to have on either
/// side of the move.
#[derive(Debug, Clone)]
pub(super) struct StagedMove {
    pub(super) staged: PathBuf,
    pub(super) live: PathBuf,
    pub(super) expected_fp: Option<String>,
}

/// The four moves of a staged Phase 4, in their order: root certificate,
/// root key, intermediate key, intermediate certificate.
///
/// The intermediate key goes before its certificate so that, in every
/// state between two moves, the live intermediate pair is either the old
/// pair — old-generation issuance — or a new key with the old certificate,
/// which step-ca cannot issue verifiable certificates with. The new pair
/// exists only once the last move is done.
pub(super) fn staged_moves(paths: &StatePaths, state: &RotationState) -> [StagedMove; 4] {
    [
        StagedMove {
            staged: paths.root_cert_staged(),
            live: paths.root_cert(),
            expected_fp: Some(state.new_root_fp.clone()),
        },
        StagedMove {
            staged: paths.root_key_staged(),
            live: paths.stepca_root_key(),
            expected_fp: None,
        },
        StagedMove {
            staged: paths.intermediate_key_staged(),
            live: paths.stepca_intermediate_key(),
            expected_fp: None,
        },
        StagedMove {
            staged: paths.intermediate_cert_staged(),
            live: paths.intermediate_cert(),
            expected_fp: Some(state.new_intermediate_fp.clone()),
        },
    ]
}

/// Phase 4 of a staged rotation, up to and including step-ca's start.
///
/// 1. Records `phase4_started`, with step-ca's current restart policy,
///    before the first change, so an interruption from here on is told
///    apart from a rotation paused after Phase 3. The policy is read
///    while none is recorded, and kept once it is.
/// 2. Stops and removes step-ca, so nothing — not even its `restart:
///    always` after a host or daemon restart — runs it on a mixed
///    generation.
/// 3. Moves the four staged files into place ([`staged_moves`]).
/// 4. Issues `PostgreSQL`'s TLS certificate under the new intermediate
///    unless the one on disk already is, as step-ca's `verify-full`
///    connection checks it against the single live root.
/// 5. Verifies the live generation and `PostgreSQL`'s certificate, and
///    only then starts step-ca with the recorded restart policy.
///
/// Every step repeats safely, so a resume after an interruption anywhere
/// runs this again from the top.
///
/// # Errors
///
/// Returns an error when any step fails. A verification failure leaves
/// step-ca absent.
pub(super) async fn switch_to_staged_generation(
    ctx: &RotateContext,
    state: &mut RotationState,
    ops: &dyn StepCaSwitch,
    messages: &Messages,
) -> Result<()> {
    // Read again on a resume that recorded none: the container a failed
    // removal left behind still carries the policy.
    let mut record = !state.phase4_started;
    if state.stepca_restart_policy.is_none()
        && let Some(policy) = ops.current_restart_policy()?
    {
        state.stepca_restart_policy = Some(policy);
        record = true;
    }
    if record {
        state.phase4_started = true;
        update_rotation_state_async(&ctx.state_dir, state, messages).await?;
    }

    println!("{}", messages.rotate_ca_key_stepca_removing());
    ops.remove_stepca()?;

    for staged_move in staged_moves(&ctx.paths, state) {
        let messages_for_task = messages.clone();
        let moved = ctx
            .secrets
            .run(move |tree| move_staged_file(tree, &staged_move, &messages_for_task))
            .await?;
        println!("{moved}");
    }

    if let Some(cert) = postgres_cert_path(ctx)
        && !issued_by_live_intermediate(ctx, &cert, messages).await
    {
        println!(
            "{}",
            messages.rotate_ca_key_postgres_reissue_new_generation()
        );
        ops.reissue_postgres()?;
    }

    verify_live_generation(ctx, state, ops, messages)
        .await
        .context(messages.error_stepca_switch_verification_failed())?;

    println!("{}", messages.rotate_ca_key_stepca_starting());
    ops.start_stepca(state.stepca_restart_policy.as_deref())
}

/// Moves one staged file into place by a rename within its directory and
/// flushes the directory, so a resume finds the move it reported. Returns
/// the line to print. Blocking.
///
/// A staged file that is absent counts as moved already; a certificate
/// must then be at its live path with the recorded fingerprint. A staged
/// certificate that is present must have it too, before it is moved.
///
/// # Errors
///
/// Returns an error when a certificate is not the recorded one, or a
/// read, the rename or the flush fails.
pub(super) fn move_staged_file(
    tree: &SecretsTree,
    staged_move: &StagedMove,
    messages: &Messages,
) -> Result<String> {
    let staged_display = staged_move.staged.display().to_string();
    let live_display = staged_move.live.display().to_string();
    if !present_in(tree, &staged_move.staged)
        .with_context(|| messages.error_read_file_failed(&staged_display))?
    {
        if let Some(expected) = &staged_move.expected_fp {
            check_fingerprint_in(tree, &staged_move.live, expected, messages)?;
        }
        return Ok(messages.rotate_ca_key_staged_already_moved(&staged_display));
    }
    if let Some(expected) = &staged_move.expected_fp {
        check_fingerprint_in(tree, &staged_move.staged, expected, messages)?;
    }
    rename_in(tree, &staged_move.staged, &staged_move.live)
        .with_context(|| messages.error_write_file_failed(&live_display))?;
    if let Some(dir) = staged_move.live.parent() {
        sync_dir_in(tree, dir)
            .with_context(|| messages.error_write_file_failed(&dir.display().to_string()))?;
    }
    Ok(messages.rotate_ca_key_staged_moved(&staged_display, &live_display))
}

/// Fails unless the certificate at `path` has the fingerprint `expected`.
fn check_fingerprint_in(
    tree: &SecretsTree,
    path: &Path,
    expected: &str,
    messages: &Messages,
) -> Result<()> {
    let display = path.display().to_string();
    let contents =
        read_in(tree, path).with_context(|| messages.error_read_file_failed(&display))?;
    let actual = fingerprint_ca_cert(&contents, path, messages)?;
    if actual != expected {
        anyhow::bail!(messages.error_staged_cert_not_new(&display, expected, &actual));
    }
    Ok(())
}

/// Holds the live generation to the rotation state before step-ca may
/// start on it: both certificates are the recorded new ones, the
/// intermediate is signed by the root, each key is its certificate's, and
/// `PostgreSQL`'s certificate, where `state.json` records one, is issued
/// by the new intermediate.
async fn verify_live_generation(
    ctx: &RotateContext,
    state: &RotationState,
    ops: &dyn StepCaSwitch,
    messages: &Messages,
) -> Result<()> {
    let paths = &ctx.paths;
    let root_path = paths.root_cert();
    let intermediate_path = paths.intermediate_cert();
    for (path, expected) in [
        (&root_path, &state.new_root_fp),
        (&intermediate_path, &state.new_intermediate_fp),
    ] {
        let actual = read_fingerprint(ctx, path, messages).await?;
        if actual != *expected {
            anyhow::bail!(messages.error_staged_cert_not_new(
                &path.display().to_string(),
                expected,
                &actual
            ));
        }
    }

    let root = read_cert(ctx, &root_path, messages).await?;
    let intermediate = read_cert(ctx, &intermediate_path, messages).await?;
    if !cert_signed_by(&intermediate, &root)? {
        anyhow::bail!(messages.error_staged_chain_not_new_root(
            &intermediate_path.display().to_string(),
            &root_path.display().to_string(),
        ));
    }

    for (key, cert_path, cert) in [
        (paths.stepca_root_key(), &root_path, &root),
        (
            paths.stepca_intermediate_key(),
            &intermediate_path,
            &intermediate,
        ),
    ] {
        let public = ops.public_key_der(&key)?;
        if public != subject_public_key_der(cert)? {
            anyhow::bail!(messages.error_staged_key_mismatch(
                &key.display().to_string(),
                &cert_path.display().to_string(),
            ));
        }
    }

    if let Some(cert) = postgres_cert_path(ctx)
        && !issued_by_live_intermediate(ctx, &cert, messages).await
    {
        anyhow::bail!(messages.error_postgres_cert_not_new_generation(
            &cert.display().to_string(),
            &intermediate_path.display().to_string(),
        ));
    }
    Ok(())
}

/// Where `PostgreSQL`'s TLS certificate is, when `state.json` records
/// one — the path [`reissue_postgres_tls_cert`] writes.
fn postgres_cert_path(ctx: &RotateContext) -> Option<PathBuf> {
    ctx.state
        .infra_certs
        .contains_key(POSTGRES_INFRA_CERT_KEY)
        .then(|| compose_file_dir(&ctx.compose_file).join(POSTGRES_TLS_CERT_PATH))
}

/// Whether the certificate at `cert` is issued by the live intermediate.
/// A certificate that cannot be read or parsed is not.
async fn issued_by_live_intermediate(
    ctx: &RotateContext,
    cert: &Path,
    messages: &Messages,
) -> bool {
    let Ok(intermediate) = read_cert(ctx, &ctx.paths.intermediate_cert(), messages).await else {
        return false;
    };
    let Ok(leaf_pem) = fs::read(cert) else {
        return false;
    };
    let Ok(leaf) = cert_der_from_pem(&leaf_pem, cert, messages) else {
        return false;
    };
    cert_signed_by(&leaf, &intermediate).unwrap_or(false)
}

/// Whether both files of a staged pair are present.
async fn staged_pair_present(ctx: &RotateContext, cert: &Path, key: &Path) -> Result<bool> {
    let cert = cert.to_path_buf();
    let key = key.to_path_buf();
    ctx.secrets
        .run(move |tree| Ok(present_in(tree, &cert)? && present_in(tree, &key)?))
        .await
}

/// The fingerprint of the certificate at `path`, read through the tree.
async fn read_fingerprint(ctx: &RotateContext, path: &Path, messages: &Messages) -> Result<String> {
    let path = path.to_path_buf();
    let messages = messages.clone();
    ctx.secrets
        .run(move |tree| {
            let contents = read_in(tree, &path)
                .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
            fingerprint_ca_cert(&contents, &path, &messages)
        })
        .await
}

/// The DER of the certificate at `path`, read through the tree.
async fn read_cert(ctx: &RotateContext, path: &Path, messages: &Messages) -> Result<Vec<u8>> {
    let path = path.to_path_buf();
    let messages = messages.clone();
    ctx.secrets
        .run(move |tree| {
            let contents = read_in(tree, &path)
                .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
            cert_der_from_pem(&contents, &path, &messages)
        })
        .await
}

/// Decodes one PEM certificate.
fn cert_der_from_pem(contents: &[u8], path: &Path, messages: &Messages) -> Result<Vec<u8>> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(contents).map_err(|_| {
        anyhow::anyhow!(messages.error_ca_cert_parse_failed(&path.display().to_string()))
    })?;
    if pem.label != "CERTIFICATE" {
        anyhow::bail!(messages.error_ca_cert_parse_failed(&path.display().to_string()));
    }
    Ok(pem.contents)
}

/// Whether `child` names `issuer` as its issuer and its signature
/// verifies under `issuer`'s key. Every generation's root has the same
/// name, so the signature is what tells them apart.
pub(super) fn cert_signed_by(child: &[u8], issuer: &[u8]) -> Result<bool> {
    let (_, child) = x509_parser::parse_x509_certificate(child)
        .map_err(|err| anyhow::anyhow!("certificate does not parse: {err:?}"))?;
    let (_, issuer) = x509_parser::parse_x509_certificate(issuer)
        .map_err(|err| anyhow::anyhow!("certificate does not parse: {err:?}"))?;
    Ok(child.issuer() == issuer.subject()
        && child.verify_signature(Some(issuer.public_key())).is_ok())
}

/// The DER `SubjectPublicKeyInfo` of a certificate.
fn subject_public_key_der(cert: &[u8]) -> Result<Vec<u8>> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert)
        .map_err(|err| anyhow::anyhow!("certificate does not parse: {err:?}"))?;
    Ok(cert.public_key().raw.to_vec())
}

/// Reads `path` through a rooted `tree`, by path otherwise. Blocking.
fn read_in(tree: &SecretsTree, path: &Path) -> std::io::Result<Vec<u8>> {
    if tree.is_rooted() {
        tree.read(path)
    } else {
        fs::read(path)
    }
}

/// Whether anything is at `path`, read without following it. Blocking.
fn present_in(tree: &SecretsTree, path: &Path) -> std::io::Result<bool> {
    if tree.is_rooted() {
        return Ok(tree.entry_kind(path)?.is_some());
    }
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// Renames `from` to `to` through a rooted `tree`, by path otherwise.
/// Blocking.
fn rename_in(tree: &SecretsTree, from: &Path, to: &Path) -> std::io::Result<()> {
    if tree.is_rooted() {
        tree.rename(from, to)
    } else {
        fs::rename(from, to)
    }
}

/// Flushes the directory at `dir` through a rooted `tree`, by path
/// otherwise. Blocking.
fn sync_dir_in(tree: &SecretsTree, dir: &Path) -> std::io::Result<()> {
    if tree.is_rooted() {
        tree.sync_dir(dir)
    } else {
        fs::File::open(dir)?.sync_all()
    }
}

#[cfg(test)]
mod tests;
