//! The bootroot-internal credential's rotation and recovery paths.
//!
//! Three call sites drive this module, and each one does exactly one
//! thing:
//!
//! - **Full-rotation Phase 3** writes the additive trust set — old
//!   root, old intermediate, new root, new intermediate — into the
//!   dedicated private bundle and the internal config's pins. It
//!   changes no entry, no leaf and no stored fingerprint, and it does
//!   not reload the internal agent: Phase 5 does, once the tail below
//!   has made the credential it would load one the new root recognises.
//! - **The mandatory tail after full-rotation Phase 4**, which runs
//!   after step-ca restarts and before Phase 4 is recorded. It replaces
//!   the `auth/cert` entry, the leaf material and the stored root
//!   fingerprint under explicit root-token authority, while *keeping*
//!   the Phase-3 additive trust set. It leaves the reload to Phase 5,
//!   which removes the endpoint's surface leaves and reloads the agent
//!   once, or to Phase 5's skip when `--skip reissue` is given.
//!   `--skip reissue` cannot skip the tail itself, and a failure retains
//!   the pre-Phase-4 state so a resume repeats restart and repair.
//! - **Full-rotation Phase 6** narrows the bundle and the pins to the
//!   finalized new-root/new-intermediate pair — only after the existing
//!   finalization checks pass, and before Phase 6 is recorded. Skipped
//!   finalization keeps the additive set.
//!
//! An intermediate-only rotation reaches none of them. The entry is
//! pinned to the internal leaf itself, and `OpenBao` accepts a pinned
//! leaf whether or not its issuer is still the active intermediate; the
//! root, which the config's pins and the bundle are anchored on, is not
//! replaced either. So the entry, the material, the config and the
//! bundle are all still correct and are left untouched.
//!
//! `bootroot rotate registrar-internal-credential` reuses the tail as
//! its whole body. It replaces the leaf — signing a new one offline
//! against the intermediate key — together with the entry pinned to it.
//! Without `--force` it acts when the material is incomplete, when the
//! root changed, when the entry is not pinned to the published leaf (an
//! installation from before the entry was pinned, above all), or when
//! the leaf is within [`RENEWAL_WINDOW`] of expiry. It never re-runs
//! install and never touches a service credential.
//!
//! `rotate responder-hmac` and `rotate eab-clear` reach the internal
//! config too, through [`check_internal_config_change`] and
//! [`apply_internal_config_change`]. The config carries no `[openbao]`
//! section and polls nothing, so the fast-poll loop that carries those
//! two values to every other agent never reaches the endpoint daemon:
//! the rotation rewrites the one key itself and reloads the daemon.
//!
//! # The config lock
//!
//! Every rotation-time writer of the internal config — Phases 3 and 6,
//! the repair, and the two rotations above — holds
//! [`InternalConfigLock`] from reading the value it will write until it
//! has published it. Two rotations can overlap (scheduled rotation units
//! run on timers), and each of those writers is a read–modify–write an
//! atomic rename does not make atomic: a repair that read the responder
//! HMAC from `OpenBao` before a responder-HMAC rotation and published
//! after it would put the old value back. `bootroot init` does not take
//! it; running a rotation during `init` is not supported.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::eab::EabCredentials;
use bootroot::openbao::OpenBaoClient;
use bootroot::registrar::internal::{
    AGENT_CONFIG_FILE, CA_BUNDLE_FILE, CERT_AUTH_MOUNT, CERT_AUTH_ROLE, InternalPaths,
    MaterialStatus, capture_members, first_certificate_der, leaf_not_after, load_material,
    material_status, remove_internal_eab, require_https, require_root_authority,
    upsert_internal_responder_hmac, upsert_internal_trust,
};
use bootroot::secret::HmacSecret;
use bootroot::{cert_group, fs_util};

use super::RotateContext;
use super::helpers::signal_internal_registrar_agent;
use crate::commands::init::registrar_internal::{
    RegistrarInternalContext, RegistrarInternalInputs, RegistrarInternalIntent, StagedInternal,
    converge_internal_auth, current_internal_config, discard_snapshot, internal_acme_server,
    internal_responder_url, issue_internal_material, publish_internal_set, staging_dir,
    verify_internal_login,
};
use crate::commands::init::{
    DEFAULT_STEPCA_PROVISIONER, PATH_AGENT_EAB, PATH_RESPONDER_HMAC,
    POLICY_BOOTROOT_REGISTRAR_INTERNAL, compute_ca_bundle_pem, read_ca_cert_fingerprint,
};
use crate::commands::trust::RotationMode;
use crate::i18n::Messages;

/// The lock file, beside the internal config, that every rotation-time
/// writer of the config holds.
///
/// A name to lock and never a record: it holds no data, it is not a
/// member of the internal set, and it is never removed, because
/// unlinking it would hand the next two writers a different inode each
/// and serialize neither.
const INTERNAL_CONFIG_LOCK_FILE: &str = "agent.toml.lock";

/// The mode the lock file is created at. Nothing reads it; the
/// descriptor is the lock.
const INTERNAL_CONFIG_LOCK_MODE: u32 = 0o600;

/// How close to its `notAfter` the internal leaf may come before
/// `bootroot rotate registrar-internal-credential` replaces it without
/// `--force`.
///
/// Nothing renews the leaf unattended, so this is not a renewal lead
/// time a timer acts on: it is what makes the one operator command
/// sufficient for a leaf nearing the end of its ten years.
const RENEWAL_WINDOW: time::Duration = time::Duration::days(30);

/// The recovery a failed internal-config update after the `OpenBao`
/// writes names: the new value is already the source of truth, so either
/// re-running the rotation or re-rendering the config from `OpenBao`
/// converges the file on it.
const INTERNAL_CONFIG_RECOVERY: &str = "the new value is already in OpenBao; re-run this \
     rotation, or run `bootroot rotate registrar-internal-credential --force` to re-render \
     the file from OpenBao";

/// Exclusive hold on the internal config's lock, released when dropped.
///
/// The guard unlocks on drop, so a rotation that fails mid-update
/// strands nothing and a copy of the descriptor in a child another
/// thread has forked and not yet `exec`ed cannot keep the lock held;
/// the kernel still releases the lock of a rotation that is killed
/// without running `drop`.
pub(super) struct InternalConfigLock {
    /// The open lock file, holding the lock; unlocked on drop.
    file: File,
}

impl Drop for InternalConfigLock {
    fn drop(&mut self) {
        // `flock` belongs to the open file description, which a child
        // forked by another thread shares until its `exec`; closing our
        // descriptor alone would leave the lock held through that copy.
        // An error is discarded: the descriptor closes next, and the
        // kernel releases the lock once no copy remains.
        let _ = self.file.unlock();
    }
}

/// Takes the internal config's lock, waiting for whichever rotation
/// holds it.
///
/// The wait is unbounded on purpose: the holder is another rotation's
/// read–modify–write, and the lock is released by the kernel if it
/// dies, so there is no stale lock to time out of. The blocking acquire
/// runs on a blocking thread so the runtime keeps running.
///
/// A host whose internal directory is gone — a repair rebuilding it —
/// gets the directory created with the mode its publication would give
/// it, since the lock has to live somewhere.
///
/// # Errors
///
/// Returns an error naming the config the lock guards when the directory
/// cannot be created, when the lock file cannot be opened, or when the
/// lock cannot be taken.
pub(super) async fn acquire_internal_config_lock(secrets_dir: &Path) -> Result<InternalConfigLock> {
    let paths = InternalPaths::new(secrets_dir);
    if !tokio::fs::try_exists(paths.dir()).await.unwrap_or(false) {
        fs_util::ensure_secrets_dir(paths.dir())
            .await
            .with_context(|| {
                format!(
                    "creating {} to take the lock on the bootroot-internal config at {} in",
                    paths.dir().display(),
                    paths.agent_config().display()
                )
            })?;
    }
    let lock_path = paths.dir().join(INTERNAL_CONFIG_LOCK_FILE);
    tokio::task::spawn_blocking(move || lock_internal_config_blocking(&lock_path))
        .await
        .context("the bootroot-internal config lock task panicked")
        .and_then(|locked| locked)
        .with_context(|| {
            format!(
                "locking the bootroot-internal config at {} for update",
                paths.agent_config().display()
            )
        })
}

/// The blocking half of [`acquire_internal_config_lock`].
fn lock_internal_config_blocking(lock_path: &Path) -> Result<InternalConfigLock> {
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(INTERNAL_CONFIG_LOCK_MODE)
        .open(lock_path)
        .with_context(|| {
            format!(
                "opening the bootroot-internal config lock {}",
                lock_path.display()
            )
        })?;
    file.lock().with_context(|| {
        format!(
            "waiting for the bootroot-internal config lock {}",
            lock_path.display()
        )
    })?;
    Ok(InternalConfigLock { file })
}

/// One change a rotation makes to the internal config, applied to the
/// file as it is when the change is made.
///
/// Carried as the change rather than as precomputed file contents, so
/// the contents published are always computed from the file read under
/// the lock and never from an earlier read another writer has since
/// moved past.
#[derive(Clone, Copy)]
pub(super) enum InternalConfigChange<'a> {
    /// Sets `[acme].http_responder_hmac`.
    SetResponderHmac(&'a HmacSecret),
    /// Removes the `[eab]` table.
    RemoveEab,
}

impl InternalConfigChange<'_> {
    /// Applies the change to `contents`, returning `None` when there is
    /// nothing to change.
    ///
    /// A parse failure is reported without its source: the parser's
    /// message quotes the offending line, and this file carries the
    /// responder HMAC and the EAB HMAC. Any other refusal — an `acme`
    /// that is not a table — quotes nothing from the file and is kept.
    fn apply(self, contents: &str, config_path: &Path) -> Result<Option<String>> {
        let applied = match self {
            Self::SetResponderHmac(hmac) => {
                upsert_internal_responder_hmac(contents, hmac).map(Some)
            }
            Self::RemoveEab => remove_internal_eab(contents),
        };
        applied.map_err(|err| {
            if err.downcast_ref::<toml_edit::TomlError>().is_some() {
                anyhow::anyhow!(
                    "the bootroot-internal config at {} does not parse as TOML",
                    config_path.display()
                )
            } else {
                err.context(format!(
                    "the bootroot-internal config at {} cannot take this change",
                    config_path.display()
                ))
            }
        })
    }
}

/// What [`check_internal_config_change`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InternalConfigCheck {
    /// The host has no internal config; the rotation leaves it alone.
    Absent,
    /// The config is readable and the change applies to it.
    Applicable,
    /// The config is readable and already carries the change — an
    /// `eab-clear` over a config with no `[eab]` table.
    Unchanged,
}

impl InternalConfigCheck {
    /// Reports whether the host carries an internal config, and so
    /// whether the rotation takes the lock and applies its change.
    pub(super) fn found(self) -> bool {
        self != Self::Absent
    }
}

/// Decides, before a rotation's first `OpenBao` write, whether the
/// internal config is one it can update.
///
/// A check only: the rewrite is computed to prove it can be, and then
/// discarded. What is published is computed again under the lock by
/// [`apply_internal_config_change`], from the file as it is then.
///
/// # Errors
///
/// Returns an error naming the file when it exists but cannot be read —
/// including the permission error an unprivileged invocation gets on
/// this `root:root` `0600` file — or does not parse as TOML. The
/// rotation has written nothing at that point, and proceeding would
/// leave the endpoint daemon on the old value.
pub(super) async fn check_internal_config_change(
    secrets_dir: &Path,
    change: InternalConfigChange<'_>,
) -> Result<InternalConfigCheck> {
    let config_path = InternalPaths::new(secrets_dir).agent_config();
    let contents = match tokio::fs::read_to_string(&config_path).await {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(InternalConfigCheck::Absent);
        }
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!(
                "reading the bootroot-internal config at {}; this rotation must rewrite that \
                 file and reload the registrar endpoint daemon, so re-run it with enough \
                 privilege to rewrite it (as root). Nothing has been written",
                config_path.display()
            )));
        }
    };
    let rewritten = change.apply(&contents, &config_path).map_err(|err| {
        err.context(
            "this rotation must rewrite the bootroot-internal config and cannot; nothing has \
             been written",
        )
    })?;
    Ok(if rewritten.is_some() {
        InternalConfigCheck::Applicable
    } else {
        InternalConfigCheck::Unchanged
    })
}

/// Re-reads the internal config and applies `change` to what it read.
///
/// The pure half of [`apply_internal_config_change`], and the step the
/// lock exists for: it runs only with the lock held, so the file it
/// reads is the one the publication replaces.
///
/// # Errors
///
/// Returns an error when the config has disappeared since the check,
/// cannot be read, or no longer parses.
async fn rewrite_internal_config(
    config_path: &Path,
    change: InternalConfigChange<'_>,
    _lock: &InternalConfigLock,
) -> Result<Option<String>> {
    let contents = tokio::fs::read_to_string(config_path)
        .await
        .with_context(|| {
            format!(
                "re-reading the bootroot-internal config at {}",
                config_path.display()
            )
        })?;
    change.apply(&contents, config_path)
}

/// Publishes a rewritten internal config, root-owned at `0600`.
///
/// One file, one rename: an agent reading it sees the whole previous
/// version or the whole new one, and there is no second file to hold
/// in step with it, so no snapshot or restore.
async fn publish_internal_config(config_path: &Path, contents: &str) -> Result<()> {
    // Root-owned unconditionally, exactly as `write_trust_pair`: this
    // is one of the protected files, and a rotation must not be the
    // publication that hands it to the invoking user.
    fs_util::atomic_write_fixed_owner(
        fs_util::Destination::bootroot_owned(config_path),
        contents.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
        fs_util::FixedOwner::root(),
    )
    .await
    .with_context(|| {
        format!(
            "writing the bootroot-internal config at {}",
            config_path.display()
        )
    })
}

/// Applies `change` to the internal config and reloads the endpoint
/// daemon, with the lock already held by the caller.
///
/// Re-reads the file under the lock, applies the change to what it
/// read, publishes the result and signals the daemon. A change that
/// leaves the file as it is publishes nothing and signals nothing.
///
/// Reports whether it published.
///
/// # Errors
///
/// Returns an error naming the file, and the recovery, when the file
/// cannot be re-read or re-parsed, cannot be published, or the daemon
/// cannot be signalled. The rotation's `OpenBao` writes have landed by
/// then, so the error is reported rather than rolled back.
pub(super) async fn apply_internal_config_change(
    secrets_dir: &Path,
    change: InternalConfigChange<'_>,
    lock: &InternalConfigLock,
    messages: &Messages,
) -> Result<bool> {
    let config_path = InternalPaths::new(secrets_dir).agent_config();
    async {
        let Some(next) = rewrite_internal_config(&config_path, change, lock).await? else {
            return Ok(false);
        };
        publish_internal_config(&config_path, &next).await?;
        signal_internal_registrar_agent(secrets_dir, messages)?;
        Ok::<_, anyhow::Error>(true)
    }
    .await
    .with_context(|| {
        format!(
            "updating the bootroot-internal config at {}: {INTERNAL_CONFIG_RECOVERY}",
            config_path.display()
        )
    })
}

/// The path of the internal config below `secrets_dir`, for the
/// rotations' summaries.
pub(super) fn internal_config_path(secrets_dir: &Path) -> PathBuf {
    InternalPaths::new(secrets_dir).agent_config()
}

/// The trust set the internal bundle and the internal config's pins must
/// carry.
///
/// The same values the rotation publishes to `OpenBao` KV for ordinary
/// services — additive in Phases 3–4, narrowed in Phase 6 — so the
/// internal identity is never on a different generation from the fleet.
#[derive(Debug, Clone)]
pub(super) struct InternalTrustState {
    /// The fingerprints the config pins.
    pub(super) fingerprints: Vec<String>,
    /// The PEM bundle those fingerprints cover.
    pub(super) bundle_pem: String,
}

/// Whether a credential replacement reloads the internal daemon itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum InternalReload {
    /// Signal the daemon once the replacement is published.
    Signal,
    /// Leave the reload to a later step of the same run, which signals
    /// the daemon itself.
    ///
    /// The tail after Phase 4 uses this when Phase 5 follows on an
    /// endpoint host: Phase 5 removes the surface material and signals
    /// the daemon, and a reload started here could still be running when
    /// that removal lands. The invocation it starts would then read a
    /// leaf that is no longer there when it arms renewal, and end the
    /// daemon, leaving Phase 5's own signal nothing to reach. Phase 5's
    /// one reload picks up the replaced credential as well.
    Deferred,
}

/// Reports whether this host carries a bootroot-internal credential.
///
/// A host without one — every host but a bootroot registrar host —
/// reaches none of the rotation work below. A *partial* set is reported
/// as present, so a rotation repairs it rather than silently skipping a
/// host whose credential is half there.
pub(super) fn internal_credential_present(secrets_dir: &Path) -> bool {
    !matches!(
        material_status(&InternalPaths::new(secrets_dir)),
        MaterialStatus::Absent
    )
}

/// Reports whether a rotation in `mode` has internal work to do on this
/// host.
///
/// The gate every internal rotation call site is written behind, so the
/// two halves of the condition are stated once. An intermediate-only
/// rotation is excluded whatever the host carries: the `auth/cert` entry
/// is pinned to the leaf itself and goes on accepting it under a new
/// intermediate, and the root is not replaced, so the entry, the leaf,
/// the config and the bundle are all still correct and rewriting them
/// would be a change to artifacts the rotation is specified to leave
/// alone.
pub(super) fn internal_rotation_applies(mode: &RotationMode, secrets_dir: &Path) -> bool {
    *mode == RotationMode::Full && internal_credential_present(secrets_dir)
}

/// Publishes a trust set into the dedicated bundle and the internal
/// config's pins, then reloads the internal agent.
///
/// Both files are published by rename, so an agent reading either while
/// this runs sees the whole previous version or the whole new one.
///
/// # Errors
///
/// Returns an error when the config is missing or unparseable, when
/// either file cannot be published, or when the reload signal fails for
/// a reason other than "no such process".
pub(super) async fn publish_internal_trust(
    secrets_dir: &Path,
    trust: &InternalTrustState,
    messages: &Messages,
) -> Result<()> {
    write_internal_trust(secrets_dir, trust, messages).await?;
    signal_internal_registrar_agent(secrets_dir, messages)
}

/// Writes the trust set without signalling.
///
/// Split from [`publish_internal_trust`] so the two halves are separable:
/// the write is what a test can assert, and the signal is a `pkill` that
/// has nothing to match in one. Phase 3 calls it on its own, because a
/// reload there would start an invocation that refuses to run.
///
/// The bundle and the pins are **one** update. Each file publishes
/// atomically on its own, but a Phase-3 or Phase-6 run that replaced one
/// and failed on the other would leave the pair describing two different
/// generations — a bundle the pins do not cover — with the phase
/// unrecorded and nothing registered to undo it. So the pair is captured
/// first and put back on any failure, exactly as the credential set's
/// publication does, and the rewritten config is computed before either
/// file is touched so an unparseable one fails with the pair still
/// intact.
///
/// # Errors
///
/// Returns an error when the config is missing or unparseable, when the
/// pair cannot be captured, or when either file cannot be published. In
/// the last case the previous pair has been restored, or the failure to
/// restore it is reported beside the failure that caused it.
pub(super) async fn write_internal_trust(
    secrets_dir: &Path,
    trust: &InternalTrustState,
    messages: &Messages,
) -> Result<()> {
    let paths = InternalPaths::new(secrets_dir);
    let config_path = paths.agent_config();
    // Held from before the read until after the rename or the restore,
    // so a responder-HMAC or EAB rotation's rewrite cannot land between
    // them and be put back by this one. Released as it drops, on every
    // path out.
    let _lock = acquire_internal_config_lock(secrets_dir).await?;
    let current = tokio::fs::read_to_string(&config_path)
        .await
        .with_context(|| messages.error_read_file_failed(&config_path.display().to_string()))?;
    let next = upsert_internal_trust(&current, &paths, &trust.fingerprints)?;

    let snapshot = capture_members(&paths, &[AGENT_CONFIG_FILE, CA_BUNDLE_FILE])
        .await
        .context("capturing the bootroot-internal trust pair the rotation replaces")?;
    if let Err(err) = write_trust_pair(&paths, &trust.bundle_pem, &next, messages).await {
        if let Err(restore_err) = snapshot.restore().await {
            eprintln!(
                "Warning: the bootroot-internal trust pair could not be fully restored after \
                 a failed rotation: {restore_err}; the previous files are kept at {}",
                snapshot.dir().display()
            );
            return Err(err);
        }
        discard_snapshot(snapshot).await;
        return Err(err);
    }
    discard_snapshot(snapshot).await;
    Ok(())
}

/// Publishes the config and then the bundle, with no undo of its own.
///
/// Split out so [`write_internal_trust`] can hold the prior pair around
/// both renames rather than around each one.
async fn write_trust_pair(
    paths: &InternalPaths,
    bundle_pem: &str,
    config: &str,
    messages: &Messages,
) -> Result<()> {
    let config_path = paths.agent_config();
    // Root-owned unconditionally: this writer is reached only where the
    // internal credential set is present, and that set is what makes a
    // host a registrar host. There is no endpoint-enabled conditional
    // to consult here, and a rotation must not be the publication that
    // hands the config's trust pins to the invoking user.
    fs_util::atomic_write_fixed_owner(
        fs_util::Destination::bootroot_owned(&config_path),
        config.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
        fs_util::FixedOwner::root(),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&config_path.display().to_string()))?;

    fs_util::write_ca_bundle(
        &paths.ca_bundle(),
        bundle_pem,
        cert_group::CertGroupPolicy::none(),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&paths.ca_bundle().display().to_string()))
}

/// Confirms the internal bundle and config still carry `expected`.
///
/// The Phase-4 tail runs this before it replaces anything: a host whose
/// Phase-3 publication did not land must not have its credential
/// reissued against a trust set the daemon is not on.
///
/// # Errors
///
/// Returns an error when the config cannot be read, or when its pins
/// differ from `expected`.
pub(super) fn ensure_internal_trust_is(
    secrets_dir: &Path,
    expected: &[String],
    messages: &Messages,
) -> Result<()> {
    let paths = InternalPaths::new(secrets_dir);
    let config_path = paths.agent_config();
    let settings = bootroot::config::Settings::from_file(Some(config_path.clone()))
        .with_context(|| messages.error_read_file_failed(&config_path.display().to_string()))?;
    if settings.trust.trusted_ca_sha256 == expected {
        return Ok(());
    }
    anyhow::bail!(
        "the bootroot-internal config at {} does not carry the transitional trust set; \
         re-run the rotation from Phase 3",
        config_path.display()
    )
}

/// Replaces the `auth/cert` entry, the leaf material and the stored root
/// fingerprint, keeping whatever trust set `trust` names.
///
/// Runs under explicit root-token authority: the token is checked with
/// a self-lookup *before* anything is mutated, so an `AppRole` or any
/// other non-root token is refused with a typed error rather than
/// discovered half-way through by a 403.
///
/// `reload` says whether the internal daemon is signalled once the
/// replacement is published, or left for a later step to reload.
///
/// # Errors
///
/// Returns an error when the token does not carry `root`, when the
/// recorded `OpenBao` URL is plaintext, when the endpoint predicate is
/// absent, when the replacement leaf cannot be signed, when any file
/// cannot be published, or when a requested reload signal fails for a
/// reason other than "no such process".
pub(super) async fn repair_internal_credential(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    trust: &InternalTrustState,
    reload: InternalReload,
    messages: &Messages,
) -> Result<()> {
    require_root_authority(client).await?;
    // A host that carries this credential runs `OpenBao` over TLS, because
    // the credential authenticates at `auth/cert` and nothing else can.
    // A recorded `http://` URL means the listener transition never
    // completed, and republishing material against it would leave a
    // credential that cannot log in — so refuse before anything is
    // written, with the same typed error the load path uses.
    require_https(&ctx.openbao_url)?;

    // Held from before the responder HMAC and the EAB are read out of
    // `OpenBao` until the set carrying them is published — across the
    // signing in between, which is the point: the values this
    // republishes are the ones it read, so a responder-HMAC or EAB
    // rotation either finishes before the read or waits for the
    // publication.
    let _lock = acquire_internal_config_lock(ctx.paths.secrets_dir()).await?;
    let context = repair_context(ctx, client, messages).await?;
    replace_internal_credential(client, &context, &ctx.openbao_url, trust, reload, messages).await
}

/// The body of a repair, past the two refusals.
///
/// Separated from [`repair_internal_credential`] so the ordering below
/// can be driven in a test without a TLS listener: everything up to the
/// convergence is reachable over a plain-HTTP mock, because none of it
/// authenticates with the credential.
///
/// # Errors
///
/// Returns an error when the replacement leaf cannot be signed, when the
/// `auth/cert` entry cannot be converged, when the replacement cannot
/// log in, or when any file cannot be published.
async fn replace_internal_credential(
    client: &OpenBaoClient,
    context: &RegistrarInternalContext,
    openbao_url: &str,
    trust: &InternalTrustState,
    reload: InternalReload,
    messages: &Messages,
) -> Result<()> {
    let inputs = context.inputs();

    // The replacement is staged **before** anything in `OpenBao`
    // changes. The convergence below pins the entry to the staged leaf,
    // so it could not run first in any case — and a host that cannot
    // sign (no Docker, no intermediate key, no `password.txt`) fails
    // here with the entry, and so the credential the internal daemon is
    // still using, exactly as they were.
    //
    // The publication carries `trust`, not the active generation the
    // signing staged: the Phase-4 tail replaces the credential while
    // the fleet is still on the additive set, and a repair mid-rotation
    // has to restore that same set.
    //
    // A repair runs outside `init`'s rollback envelope, so the staging
    // directory has no undo registered for it. It holds an unpublished
    // private key, so a failed repair sweeps it here rather than leaving
    // it beside the credential until the next successful run happens to
    // overwrite it.
    let staged = match issue_internal_material(&inputs, messages).await {
        Ok(staged) => staged.with_trust(trust.fingerprints.clone(), trust.bundle_pem.clone()),
        Err(err) => {
            sweep_staging(&context.secrets_dir).await;
            return Err(err);
        }
    };

    // Captured before the convergence and put back if anything after it
    // fails, so the auth artifacts and the material move together:
    // either the host ends on the new set, or it ends on the set it
    // started with. Both members are captured, because the convergence
    // rewrites both: `init` puts both back and a repair needs the same
    // symmetry, or a failed `--force` run would restore the entry and
    // leave a policy it replaced.
    let prior = match PriorInternalAuth::capture(client).await {
        Ok(prior) => prior,
        Err(err) => {
            sweep_staging(&context.secrets_dir).await;
            return Err(err);
        }
    };

    if let Err(err) = converge_and_publish(client, &staged, &inputs, openbao_url, messages).await {
        prior.restore(client).await;
        sweep_staging(&context.secrets_dir).await;
        return Err(err);
    }
    match reload {
        InternalReload::Signal => signal_internal_registrar_agent(&context.secrets_dir, messages),
        InternalReload::Deferred => Ok(()),
    }
}

/// Pins the `auth/cert` entry to the staged leaf, proves that leaf logs
/// in against it, and publishes the set.
///
/// One unit, because its caller undoes it as one: the login is what
/// makes the new entry and the new leaf provably a pair, and the
/// publication is what makes that pair the host's.
///
/// # Errors
///
/// Returns an error when the convergence, the login or the publication
/// fails.
async fn converge_and_publish(
    client: &OpenBaoClient,
    staged: &StagedInternal,
    inputs: &RegistrarInternalInputs<'_>,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
    // A repair runs outside a rollback envelope, so the mount flag has
    // nothing to undo by: an `auth/cert` backend a repair enables is
    // left enabled, which is the state a working credential needs and
    // the state the next repair converges on regardless.
    let mut mounted_now = false;
    converge_internal_auth(client, inputs, staged.leaf_pem()?, &mut mounted_now).await?;
    verify_internal_login(staged, openbao_url).await?;
    publish_internal_set(staged, inputs, messages).await
}

/// The `auth/cert` artifacts a repair is about to rewrite, exactly as
/// it found them.
///
/// `converge_internal_auth` rewrites the policy *and* the entry
/// unconditionally, so a repair that captures only one of them puts only
/// one of them back. On a host whose policy this repair did not create —
/// one written by an older release, or widened by hand — a failed
/// `bootroot rotate registrar-internal-credential --force` would then
/// restore the entry and leave that policy permanently replaced. Both
/// members are captured together and restored together for that reason.
///
/// A repair runs outside `init`'s rollback envelope, so this is the
/// whole undo: there is no `InitRollback` behind it to catch what is
/// missed here.
struct PriorInternalAuth {
    /// The trusted entry's body, or `None` when the host had none.
    entry: Option<serde_json::Value>,
    /// The exact-allowlist policy's body, or `None` when the host had
    /// none.
    policy: Option<String>,
}

impl PriorInternalAuth {
    /// Reads both artifacts before anything is written.
    ///
    /// A lookup that does not answer is not read as "absent" — that
    /// would register a deletion for an artifact the host depends on —
    /// so it fails the repair here, with nothing yet changed in
    /// `OpenBao`.
    ///
    /// # Errors
    ///
    /// Returns an error when either lookup fails for a reason other than
    /// a clean not-found.
    async fn capture(client: &OpenBaoClient) -> Result<Self> {
        let entry = client
            .read_cert_auth_entry(CERT_AUTH_MOUNT, CERT_AUTH_ROLE)
            .await
            .context("reading the bootroot-registrar-internal cert auth entry")?;
        let policy = client
            .read_policy(POLICY_BOOTROOT_REGISTRAR_INTERNAL)
            .await
            .context("reading the bootroot-registrar-internal policy")?;
        Ok(Self { entry, policy })
    }

    /// Puts both artifacts back the way a failed repair found them.
    ///
    /// In the reverse of the order the convergence writes them — entry
    /// first, then the policy it names — so the window in which the
    /// entry points at a policy body this run wrote is closed before the
    /// policy itself moves.
    async fn restore(&self, client: &OpenBaoClient) {
        restore_cert_auth_entry(client, self.entry.as_ref()).await;
        restore_internal_policy(client, self.policy.as_deref()).await;
    }
}

/// Puts the `auth/cert` entry back the way a failed repair found it.
///
/// Best effort and never fatal: the repair has already failed, and an
/// error raised here would displace the one that matters. What it must
/// not do is stay silent — an entry left pinned to a leaf that is not
/// the one on disk is exactly the state that stops the internal daemon
/// authenticating, so a restore that does not land is reported with the
/// command that repairs it.
async fn restore_cert_auth_entry(client: &OpenBaoClient, prior: Option<&serde_json::Value>) {
    let outcome = match prior {
        Some(entry) => {
            client
                .write_cert_auth_entry_raw(CERT_AUTH_MOUNT, CERT_AUTH_ROLE, entry)
                .await
        }
        // Nothing was there, so nothing is left behind: a repair on a
        // host whose entry had been removed puts it back to removed.
        None => client
            .delete_cert_auth_entry(CERT_AUTH_MOUNT, CERT_AUTH_ROLE)
            .await
            .or_else(|err| {
                // A delete of an entry the convergence never got as far
                // as creating is not a failure to report.
                if err.to_string().contains("404") {
                    Ok(())
                } else {
                    Err(err)
                }
            }),
    };
    if let Err(err) = outcome {
        eprintln!(
            "Warning: the bootroot-registrar-internal cert auth entry could not be restored \
             after a failed repair: {err}; re-run \
             `bootroot rotate registrar-internal-credential --force`"
        );
    }
}

/// Puts the exact-allowlist policy back the way a failed repair found
/// it.
///
/// Best effort and never fatal, for the same reason as the entry above:
/// the repair has already failed, and an error raised here would
/// displace the one that matters. Silence is what it must not be — a
/// policy left on this run's body is an authority change nothing
/// recorded, so a restore that does not land is reported with the
/// command that repairs it.
async fn restore_internal_policy(client: &OpenBaoClient, prior: Option<&str>) {
    let outcome = match prior {
        Some(body) => {
            client
                .write_policy(POLICY_BOOTROOT_REGISTRAR_INTERNAL, body)
                .await
        }
        // Nothing was there, so nothing is left behind: a repair on a
        // host whose policy had been removed puts it back to removed.
        None => client
            .delete_policy(POLICY_BOOTROOT_REGISTRAR_INTERNAL)
            .await
            .or_else(|err| {
                // A delete of a policy the convergence never got as far
                // as writing is not a failure to report.
                if err.to_string().contains("404") {
                    Ok(())
                } else {
                    Err(err)
                }
            }),
    };
    if let Err(err) = outcome {
        eprintln!(
            "Warning: the bootroot-registrar-internal policy could not be restored after a \
             failed repair: {err}; re-run \
             `bootroot rotate registrar-internal-credential --force`"
        );
    }
}

/// Removes the staging directory a failed repair left behind.
///
/// Best effort and never fatal: the repair has already failed, and the
/// error a sweep would add would displace the one that matters. A
/// directory that survives is reported so the unpublished key it holds
/// is not silent.
async fn sweep_staging(secrets_dir: &Path) {
    let staging = staging_dir(&InternalPaths::new(secrets_dir));
    if !staging.exists() {
        return;
    }
    if let Err(err) = tokio::fs::remove_dir_all(&staging).await {
        eprintln!(
            "Warning: failed to remove the staging directory {}: {err}",
            staging.display()
        );
    }
}

/// Builds the repair's context from the recorded state, the existing
/// generated config and — for the responder HMAC and the EAB the
/// republished config carries — the root-token client.
///
/// The existing config is the record of the values `init` chose (the
/// ACME directory, the contact email, the responder URL), so a repair
/// keeps them. A host whose config was lost falls back to the same
/// defaults `init` used, and reads the responder HMAC and the EAB out of
/// `OpenBao` rather than inventing them.
///
/// The config is also the only record of the operator's `[registrar]`
/// and `[registrar_endpoint]` tables, which only `init` takes from the
/// operator. It is read strictly, whole, and first: a config that
/// exists but cannot be read or does not parse as the daemon's settings
/// refuses the repair before anything is signed, converged or
/// published, rather than letting the republication drop the
/// endpoint's configuration. The fallbacks are for an absent config
/// only, never for one that is present and unreadable.
async fn repair_context(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    messages: &Messages,
) -> Result<RegistrarInternalContext> {
    let recorded = ctx
        .state
        .registrar_endpoint
        .as_ref()
        .filter(|recorded| recorded.enabled)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "state.json records no enabled registrar endpoint, so this host has no \
                 bootroot-internal credential to repair"
            )
        })?;
    let intent = RegistrarInternalIntent {
        domain: recorded.domain.clone(),
        host: recorded.host.clone(),
    };
    let secrets_dir = ctx.paths.secrets_dir().to_path_buf();
    let paths = InternalPaths::new(&secrets_dir);
    let (existing, endpoint_tables) = match current_internal_config(&paths, messages).await? {
        Some(current) => (Some(current.settings), current.endpoint_tables),
        None => (None, None),
    };
    // Only reached when the generated config is gone: the config is the
    // record of what `init` chose, and a repair keeps it. The fallbacks
    // below rebuild those endpoints through the same derivation `init`
    // used — the recorded step-ca and responder bind addresses when
    // there are any, which replace the loopback publications, and
    // otherwise this install's own published loopback ports — rather
    // than from the compose defaults, which on a host that moved its
    // ports name nothing, and on a co-located host name another
    // instance. The provisioner is not recorded, so the fallback
    // enrols against the default one.
    let compose_dir = crate::commands::compose_file::compose_file_dir(&ctx.compose_file);

    let responder_hmac = read_kv_string(client, &ctx.kv_mount, PATH_RESPONDER_HMAC, "value")
        .await?
        .map(HmacSecret::new)
        .or_else(|| {
            existing
                .as_ref()
                .map(|settings| settings.acme.http_responder_hmac.clone())
        })
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the HTTP-01 responder HMAC is neither in OpenBao nor in the \
                 bootroot-internal config; repair it with `bootroot rotate responder-hmac` first"
            )
        })?;

    let eab = read_eab(client, &ctx.kv_mount).await?;

    Ok(RegistrarInternalContext {
        intent,
        secrets_dir,
        docker: ctx.docker.clone(),
        kv_mount: ctx.kv_mount.clone(),
        acme_server: existing.as_ref().map_or_else(
            || {
                internal_acme_server(
                    DEFAULT_STEPCA_PROVISIONER,
                    ctx.state.stepca_bind_addr.as_deref(),
                    &compose_dir,
                )
            },
            |settings| settings.server.clone(),
        ),
        email: existing.as_ref().map_or_else(
            || crate::commands::service::DEFAULT_AGENT_EMAIL.to_string(),
            |settings| settings.email.clone(),
        ),
        responder_url: existing.as_ref().map_or_else(
            || internal_responder_url(ctx.state.http01_admin_bind_addr.as_deref(), &compose_dir),
            |settings| settings.acme.http_responder_url.clone(),
        ),
        responder_hmac,
        eab,
        endpoint_tables,
    })
}

/// Reads one string field out of a KV record, treating an absent record
/// as `None`.
async fn read_kv_string(
    client: &OpenBaoClient,
    kv_mount: &str,
    path: &str,
    field: &str,
) -> Result<Option<String>> {
    let Some(value) = client
        .try_read_kv(kv_mount, path)
        .await
        .with_context(|| format!("reading {kv_mount}/{path}"))?
    else {
        return Ok(None);
    };
    Ok(value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string))
}

/// Reads the deployment's agent EAB, treating an absent or cleared
/// record as "no EAB".
async fn read_eab(client: &OpenBaoClient, kv_mount: &str) -> Result<Option<EabCredentials>> {
    let Some(value) = client
        .try_read_kv(kv_mount, PATH_AGENT_EAB)
        .await
        .with_context(|| format!("reading {kv_mount}/{PATH_AGENT_EAB}"))?
    else {
        return Ok(None);
    };
    let kid = value.get("kid").and_then(serde_json::Value::as_str);
    let hmac = value.get("hmac").and_then(serde_json::Value::as_str);
    match (kid, hmac) {
        (Some(kid), Some(hmac)) if !kid.is_empty() && !hmac.is_empty() => {
            Ok(Some(EabCredentials {
                kid: kid.to_string(),
                hmac: HmacSecret::new(hmac.to_string()),
            }))
        }
        _ => Ok(None),
    }
}

/// The finalized trust set: the active root and intermediate on disk.
///
/// # Errors
///
/// Returns an error when either CA certificate cannot be read.
pub(super) async fn finalized_trust(
    secrets_dir: &Path,
    root_fp: &str,
    intermediate_fp: &str,
    messages: &Messages,
) -> Result<InternalTrustState> {
    Ok(InternalTrustState {
        fingerprints: vec![root_fp.to_string(), intermediate_fp.to_string()],
        bundle_pem: compute_ca_bundle_pem(secrets_dir, messages).await?,
    })
}

/// Reads the fingerprint of the root currently on disk.
///
/// # Errors
///
/// Returns an error when the root certificate cannot be read or parsed.
pub(super) async fn active_root_fingerprint(
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<String> {
    read_ca_cert_fingerprint(
        &secrets_dir
            .join(crate::commands::init::CA_CERTS_DIR)
            .join(crate::commands::init::CA_ROOT_CERT_FILENAME),
        messages,
    )
    .await
}

/// Reports whether the stored root fingerprint still matches the active
/// root, without touching `OpenBao`.
///
/// # Errors
///
/// Returns an error when the material cannot be loaded or the active
/// root cannot be read.
pub(super) async fn stored_root_matches_active(
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<bool> {
    let material = load_material(&InternalPaths::new(secrets_dir))?;
    let active = active_root_fingerprint(secrets_dir, messages).await?;
    Ok(material.root_fingerprint.eq_ignore_ascii_case(&active))
}

/// The phase at which a full rotation has narrowed trust back to the
/// finalized generation.
///
/// Below it the rotation is still on the additive set, so a recovery run
/// mid-rotation must restore that set rather than the finalized one — a
/// credential narrowed early would stop trusting the generation the rest
/// of the fleet is still on.
const FINALIZED_PHASE: u8 = 6;

/// Resolves the trust state a repair must restore from the recorded
/// rotation state.
///
/// An unfinished full rotation is on the additive
/// old-root/old-intermediate/new-root/new-intermediate set; everything
/// else — no rotation in progress, an intermediate-only rotation, a
/// finished one — is on the finalized active generation.
///
/// # Errors
///
/// Returns an error when the rotation state or the CA material cannot be
/// read.
pub(super) async fn trust_state_for_repair(
    ctx: &RotateContext,
    messages: &Messages,
) -> Result<InternalTrustState> {
    let recorded = crate::commands::trust::load_rotation_state(&ctx.state_dir, messages)?;
    if let Some(state) = recorded
        && state.mode == crate::commands::trust::RotationMode::Full
        && state.phase < FINALIZED_PHASE
    {
        return Ok(InternalTrustState {
            fingerprints: vec![
                state.old_root_fp.clone(),
                state.old_intermediate_fp.clone(),
                state.new_root_fp.clone(),
                state.new_intermediate_fp.clone(),
            ],
            bundle_pem: super::ca::concat_unique_ca_certs_for_repair(ctx, messages).await?,
        });
    }
    let root_fp = active_root_fingerprint(ctx.paths.secrets_dir(), messages).await?;
    let intermediate_fp =
        read_ca_cert_fingerprint(&ctx.paths.intermediate_cert(), messages).await?;
    finalized_trust(
        ctx.paths.secrets_dir(),
        &root_fp,
        &intermediate_fp,
        messages,
    )
    .await
}

/// Reports whether the credential needs nothing done to it, which is
/// when a run without `--force` stops.
///
/// All of these hold, and each one failing alone makes the run proceed
/// exactly as with `--force`:
///
/// - the material is present and its stored root fingerprint is the
///   active root's;
/// - the `auth/cert` entry exists and its `certificate` is exactly the
///   published leaf — one certificate, the same DER. An entry that does
///   not parse, that names a CA (the shape every installation had before
///   the entry was pinned) or that names any other certificate is a
///   mismatch, and replacing it is how such an installation migrates;
/// - the published leaf's `notAfter` is more than [`RENEWAL_WINDOW`]
///   after `now`.
///
/// The two local conditions are read first, so the entry is only read
/// when the answer depends on it.
///
/// # Errors
///
/// Returns an error when the entry cannot be read. A lookup that did not
/// answer is not "up to date": reporting it as such would leave an
/// unmigrated entry in place behind a message saying nothing needs
/// doing.
async fn internal_credential_up_to_date(
    secrets_dir: &Path,
    client: &OpenBaoClient,
    now: time::OffsetDateTime,
    messages: &Messages,
) -> Result<bool> {
    let paths = InternalPaths::new(secrets_dir);
    if !matches!(material_status(&paths), MaterialStatus::Present)
        || !stored_root_matches_active(secrets_dir, messages)
            .await
            .unwrap_or(false)
    {
        return Ok(false);
    }
    // Loaded a moment ago by the root comparison; a set that stopped
    // loading in between is one to replace.
    let Ok(material) = load_material(&paths) else {
        return Ok(false);
    };
    let chain_path = paths.chain();
    let Ok(leaf_der) = first_certificate_der(&chain_path, &material.chain) else {
        return Ok(false);
    };
    match leaf_not_after(&chain_path, &material.chain) {
        Ok(not_after) if not_after - RENEWAL_WINDOW > now => {}
        _ => return Ok(false),
    }

    let entry = client
        .read_cert_auth_entry(CERT_AUTH_MOUNT, CERT_AUTH_ROLE)
        .await
        .context("reading the bootroot-registrar-internal cert auth entry")?;
    Ok(entry
        .as_ref()
        .and_then(|entry| entry.get("certificate"))
        .and_then(serde_json::Value::as_str)
        .is_some_and(|pinned| entry_is_pinned_to(pinned, &leaf_der)))
}

/// Reports whether an entry's `certificate` is the one leaf whose DER is
/// `leaf_der`, and nothing else.
///
/// One certificate exactly: an entry that carries the leaf followed by
/// anything else is not the shape this crate writes.
fn entry_is_pinned_to(pinned: &str, leaf_der: &[u8]) -> bool {
    let mut certificates = x509_parser::pem::Pem::iter_from_buffer(pinned.as_bytes());
    let Some(Ok(first)) = certificates.next() else {
        return false;
    };
    first.label == "CERTIFICATE" && first.contents == leaf_der && certificates.next().is_none()
}

/// Repairs the bootroot-internal credential on operator demand.
///
/// The command form of the Phase-4 tail: the same root-authority check,
/// the same entry/leaf/fingerprint replacement, and the same trust
/// publication — but with the trust state derived from whatever the
/// recorded rotation state says is current rather than from a rotation
/// this process is running.
///
/// # Errors
///
/// Returns an error when the token is not root-authorized, when this
/// host records no enabled registrar endpoint, or when any step of the
/// repair fails.
pub(super) async fn rotate_registrar_internal_credential(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    args: &crate::cli::args::RotateRegistrarInternalArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    // The authority check runs first, before the credential is even
    // read: an AppRole token must be refused without having learned
    // anything about the host's internal state.
    require_root_authority(client).await?;

    let secrets_dir = ctx.paths.secrets_dir().to_path_buf();
    if !args.force
        && internal_credential_up_to_date(
            &secrets_dir,
            client,
            time::OffsetDateTime::now_utc(),
            messages,
        )
        .await?
    {
        println!("{}", messages.rotate_registrar_internal_up_to_date());
        return Ok(());
    }

    super::helpers::confirm_action(
        messages.prompt_rotate_registrar_internal(),
        auto_confirm,
        messages,
    )?;

    let trust = trust_state_for_repair(ctx, messages).await?;
    repair_internal_credential(ctx, client, &trust, InternalReload::Signal, messages).await?;
    println!("{}", messages.rotate_registrar_internal_complete());
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use bootroot::fs_util::current_process_euid;
    use bootroot::registrar::internal::{
        AGENT_CONFIG_FILE, InternalAgentConfigParams, render_internal_agent_config,
    };
    use tempfile::TempDir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    use super::{
        CERT_AUTH_MOUNT, CERT_AUTH_ROLE, INTERNAL_CONFIG_LOCK_FILE, InternalConfigChange,
        InternalConfigCheck, InternalPaths, InternalReload, InternalTrustState,
        POLICY_BOOTROOT_REGISTRAR_INTERNAL, PriorInternalAuth, RegistrarInternalContext,
        RotationMode, acquire_internal_config_lock, apply_internal_config_change,
        check_internal_config_change, converge_internal_auth, ensure_internal_trust_is,
        internal_credential_present, internal_credential_up_to_date, internal_rotation_applies,
        publish_internal_config, repair_internal_credential, replace_internal_credential,
        restore_cert_auth_entry, rewrite_internal_config, rotate_registrar_internal_credential,
        staging_dir, sweep_staging, upsert_internal_trust, write_internal_trust, write_trust_pair,
    };
    use crate::commands::init::DEFAULT_STEPCA_PROVISIONER;
    use crate::commands::init::registrar_internal::test_fixtures::{
        TestLeaf, TestPki, write_signing_fake_docker,
    };
    use crate::commands::init::registrar_internal::{internal_acme_server, internal_responder_url};
    use crate::i18n::test_messages;

    const ROOT_FP: &str = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900";
    const OLD_ROOT_FP: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const OLD_INT_FP: &str = "2222222222222222222222222222222222222222222222222222222222222222";
    const NEW_INT_FP: &str = "3333333333333333333333333333333333333333333333333333333333333333";

    fn bundle_pem(label: &str) -> String {
        format!("-----BEGIN CERTIFICATE-----\n{label}\n-----END CERTIFICATE-----\n")
    }

    /// A host carrying the whole set, written directly rather than
    /// through `publish_material`.
    ///
    /// The production publisher establishes `root:root` on every
    /// protected file and fails when it cannot, which is the subject of
    /// the tests below rather than something a fixture running as an
    /// ordinary user can drive. The bytes are what the rotation reads,
    /// so writing them here changes nothing the tests assert on.
    fn provisioned_host() -> (TempDir, InternalPaths) {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(paths.dir()).expect("the internal directory");
        std::fs::write(
            paths.key(),
            "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n",
        )
        .expect("key");
        std::fs::write(paths.chain(), bundle_pem("TEVBRg")).expect("chain");
        std::fs::write(paths.acme_account(), "{\"account_key_pkcs8\":\"QUJD\"}")
            .expect("account key");
        std::fs::write(paths.root_fingerprint(), format!("{ROOT_FP}\n")).expect("fingerprint");
        std::fs::write(paths.ca_bundle(), bundle_pem("Uk9PVA")).expect("bundle");
        std::fs::write(
            paths.agent_config(),
            render_internal_agent_config(
                &paths,
                &InternalAgentConfigParams {
                    email: "ops@example.internal",
                    server: "https://localhost:9000/acme/acme/directory",
                    domain: "example.internal",
                    hostname: "bootroot-01",
                    responder_url: "http://127.0.0.1:8080",
                    responder_hmac: &"hmac".into(),
                    eab_kid: None,
                    eab_hmac: None,
                    trusted_ca_sha256: &[ROOT_FP.to_string()],
                    endpoint_tables: None,
                },
            ),
        )
        .expect("config");
        (dir, paths)
    }

    /// The repair inputs every test below drives, pointed at a
    /// provisioned host's secrets directory.
    ///
    /// The ACME and responder endpoints are unreachable on purpose: the
    /// replacement leaf is signed offline, so nothing here dials either,
    /// and a repair that did would fail rather than pass.
    fn repair_inputs(secrets_dir: &std::path::Path) -> RegistrarInternalContext {
        RegistrarInternalContext {
            intent: super::RegistrarInternalIntent {
                domain: "example.internal".to_string(),
                host: "bootroot-01".to_string(),
            },
            secrets_dir: secrets_dir.to_path_buf(),
            // Never a real `docker`: a test that reaches the signing
            // supplies a fake, and one that does not must not start a
            // container by accident.
            docker: std::path::PathBuf::from("/nonexistent/docker"),
            kv_mount: "secret".to_string(),
            acme_server: "https://127.0.0.1:1/acme/acme/directory".to_string(),
            email: "ops@example.internal".to_string(),
            responder_url: "http://127.0.0.1:1".to_string(),
            responder_hmac: "hmac".into(),
            eab: None,
            endpoint_tables: None,
        }
    }

    /// A policy body deliberately unlike the one this crate writes, so
    /// a restore that reproduces it cannot be a convergence that
    /// happened to land on the same text.
    const PRIOR_POLICY: &str = "path \"secret/data/legacy\" {\n  capabilities = [\"read\"]\n}\n";

    /// The `auth/cert` entry a host is carrying before a repair runs.
    fn prior_entry() -> serde_json::Value {
        serde_json::json!({
            "certificate": "-----BEGIN CERTIFICATE-----\nT0xE\n-----END CERTIFICATE-----\n",
            "allowed_dns_sans": ["001.bootroot-registrar-internal.bootroot-01.example.internal"],
            "token_policies": ["bootroot-registrar-internal"],
            "token_no_default_policy": true,
            "token_ttl": 3600,
        })
    }

    /// Every body written to the policy and the entry, in order.
    struct ConvergeWrites {
        policies: Arc<Mutex<Vec<String>>>,
        entries: Arc<Mutex<Vec<serde_json::Value>>>,
    }

    /// An `OpenBao` already carrying the cert backend, a distinct policy
    /// and a distinct entry, recording every write over them.
    async fn converge_mock_server() -> (MockServer, ConvergeWrites) {
        let policy_path = format!("/v1/sys/policies/acl/{POLICY_BOOTROOT_REGISTRAR_INTERNAL}");
        let entry_path = format!("/v1/auth/{CERT_AUTH_MOUNT}/certs/{CERT_AUTH_ROLE}");
        let server = MockServer::start().await;
        // The backend is already enabled, so the convergence goes
        // straight to the two writes this fixture is about.
        Mock::given(method("GET"))
            .and(path("/v1/sys/auth"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "cert/": { "type": "cert" } }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(policy_path.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "policy": PRIOR_POLICY }
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(entry_path.clone()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(serde_json::json!({ "data": prior_entry() })),
            )
            .mount(&server)
            .await;

        let policies: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let policy_sink = Arc::clone(&policies);
        Mock::given(method("POST"))
            .and(path(policy_path))
            .respond_with(move |request: &Request| {
                let body: serde_json::Value = serde_json::from_slice(&request.body).expect("json");
                policy_sink.lock().expect("capture").push(
                    body.get("policy")
                        .and_then(serde_json::Value::as_str)
                        .expect("a policy body")
                        .to_string(),
                );
                ResponseTemplate::new(204)
            })
            .mount(&server)
            .await;
        let entries: Arc<Mutex<Vec<serde_json::Value>>> = Arc::new(Mutex::new(Vec::new()));
        let entry_sink = Arc::clone(&entries);
        Mock::given(method("POST"))
            .and(path(entry_path))
            .respond_with(move |request: &Request| {
                entry_sink
                    .lock()
                    .expect("capture")
                    .push(serde_json::from_slice(&request.body).expect("json"));
                ResponseTemplate::new(204)
            })
            .mount(&server)
            .await;
        (server, ConvergeWrites { policies, entries })
    }

    /// Every host but a bootroot registrar host has no internal
    /// credential, and every rotation phase below is gated on this.
    #[tokio::test]
    async fn presence_gates_every_rotation_phase() {
        let empty = TempDir::new().expect("tempdir");
        assert!(!internal_credential_present(empty.path()));

        let (dir, paths) = provisioned_host();
        assert!(internal_credential_present(dir.path()));

        // A partial set counts as present, so a rotation repairs it
        // rather than silently skipping the host.
        std::fs::remove_file(paths.key()).expect("remove");
        assert!(internal_credential_present(dir.path()));
    }

    /// An intermediate-only rotation leaves every internal artifact
    /// alone, on a provisioned host as much as on a bare one.
    ///
    /// The `auth/cert` entry is pinned to the leaf itself, which it goes
    /// on accepting under a new intermediate, and the root is not
    /// replaced — so the entry, the leaf, the stored fingerprint, the
    /// config's pins and the private bundle are all still correct. Phase 3, the Phase-4 tail and Phase 6 are each
    /// written behind this predicate, so a host that carries a working
    /// credential must still select no internal work in that mode.
    #[tokio::test]
    async fn an_intermediate_only_rotation_selects_no_internal_work() {
        let (dir, _paths) = provisioned_host();
        assert!(
            internal_credential_present(dir.path()),
            "the fixture must be a provisioned host, or this proves nothing"
        );

        assert!(
            !internal_rotation_applies(&RotationMode::IntermediateOnly, dir.path()),
            "an intermediate-only rotation must not touch internal artifacts"
        );
        assert!(
            internal_rotation_applies(&RotationMode::Full, dir.path()),
            "a full rotation on a provisioned host must select the internal work"
        );

        // The other half of the gate: a full rotation on an ordinary
        // host still selects nothing.
        let bare = TempDir::new().expect("tempdir");
        assert!(!internal_rotation_applies(&RotationMode::Full, bare.path()));
        assert!(!internal_rotation_applies(
            &RotationMode::IntermediateOnly,
            bare.path()
        ));
    }

    /// Phase 3 is root-only, and a host it cannot publish on keeps the
    /// pair it was carrying.
    ///
    /// The config is one of the five protected files, so the phase
    /// establishes `root:root` on it or publishes nothing: an
    /// unprivileged process must not be able to leave the trust pins —
    /// the CA every later renewal is checked against — in a file it
    /// owns. The refusal is reached while capturing the pair, which is
    /// before either final name is touched.
    #[tokio::test]
    async fn publishing_trust_is_root_only_and_leaves_the_pair_it_found() {
        assert_ne!(
            current_process_euid(),
            0,
            "this test asserts what an unprivileged process cannot do, so it must not be root"
        );
        let (dir, paths) = provisioned_host();
        let bundle_before = std::fs::read_to_string(paths.ca_bundle()).expect("bundle");
        let config_before = std::fs::read_to_string(paths.agent_config()).expect("config");

        let additive = InternalTrustState {
            fingerprints: vec![
                OLD_ROOT_FP.to_string(),
                OLD_INT_FP.to_string(),
                ROOT_FP.to_string(),
                NEW_INT_FP.to_string(),
            ],
            bundle_pem: bundle_pem("QURESVRJVkU"),
        };
        let err = write_internal_trust(dir.path(), &additive, &test_messages())
            .await
            .expect_err("an unprivileged process cannot publish the protected config");
        let report = format!("{err:#}");
        assert!(
            report.contains(AGENT_CONFIG_FILE) && report.contains("root-owned"),
            "the refusal must name the root-ownership requirement and the file: {report}"
        );

        assert_eq!(
            std::fs::read_to_string(paths.ca_bundle()).expect("bundle"),
            bundle_before,
            "neither member moves when the pair cannot be published"
        );
        assert_eq!(
            std::fs::read_to_string(paths.agent_config()).expect("config"),
            config_before,
            "the pins must not be left on a generation the bundle is not on"
        );
        assert!(
            !paths.dir().join(".prior").exists(),
            "a capture that could not complete leaves no partial snapshot"
        );
    }

    /// A repair never runs against a plaintext `OpenBao` URL. A host
    /// that carries this credential runs `OpenBao` over TLS, so an
    /// `http://` URL means the listener transition never completed;
    /// republishing material against it would leave a credential that
    /// cannot log in. The refusal is typed, names TLS, and lands before
    /// a single file is rewritten.
    #[tokio::test]
    async fn a_repair_over_plaintext_is_refused_before_anything_is_written() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "policies": ["root"] }
            })))
            .mount(&server)
            .await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let (dir, paths) = provisioned_host();
        let before = std::fs::read_to_string(paths.agent_config()).expect("config");
        let ctx = super::RotateContext {
            openbao_url: "http://127.0.0.1:8200".to_string(),
            kv_mount: "secret".to_string(),
            compose_file: dir.path().join("docker-compose.yml"),
            state: crate::state::StateFile::default(),
            paths: crate::commands::rotate::StatePaths::new(dir.path().to_path_buf()),
            state_dir: dir.path().to_path_buf(),
            state_file: dir.path().join("state.json"),
            docker: std::path::PathBuf::from(crate::commands::compose_project::DOCKER_BIN),
        };
        let err = repair_internal_credential(
            &ctx,
            &client,
            &InternalTrustState {
                fingerprints: vec![ROOT_FP.to_string()],
                bundle_pem: bundle_pem("Uk9PVA"),
            },
            InternalReload::Signal,
            &test_messages(),
        )
        .await
        .expect_err("a plaintext OpenBao URL must be refused");
        assert!(
            err.to_string().contains("certificate login requires TLS"),
            "{err}"
        );
        assert_eq!(
            std::fs::read_to_string(paths.agent_config()).expect("config"),
            before,
            "nothing may be rewritten before the refusal"
        );
    }

    /// The context a repair runs in, over an HTTPS `OpenBao` URL and a
    /// host whose recorded predicate is enabled.
    fn endpoint_ctx(dir: &std::path::Path) -> super::RotateContext {
        super::RotateContext {
            openbao_url: "https://127.0.0.1:8200".to_string(),
            kv_mount: "secret".to_string(),
            compose_file: dir.join("docker-compose.yml"),
            state: crate::state::StateFile {
                registrar_endpoint: Some(crate::state::RegistrarEndpointState {
                    enabled: true,
                    domain: "example.internal".to_string(),
                    host: "bootroot-01".to_string(),
                }),
                ..crate::state::StateFile::default()
            },
            paths: crate::commands::rotate::StatePaths::new(dir.to_path_buf()),
            state_dir: dir.to_path_buf(),
            state_file: dir.join("state.json"),
            docker: std::path::PathBuf::from(crate::commands::compose_project::DOCKER_BIN),
        }
    }

    /// Rewrites a provisioned host's config to carry the operator's two
    /// tables, as an endpoint-enabled `init` publishes it, and returns
    /// the bytes written.
    fn with_endpoint_tables(paths: &InternalPaths) -> String {
        let tables = bootroot::registrar::internal::EndpointTables::extract(
            &crate::commands::init::registrar_internal::endpoint_agent_config(
                "rate_limit_admission_burst = 7\n",
            ),
        )
        .expect("parses");
        let config = render_internal_agent_config(
            paths,
            &InternalAgentConfigParams {
                email: "ops@example.internal",
                server: "https://localhost:9000/acme/acme/directory",
                domain: "example.internal",
                hostname: "bootroot-01",
                responder_url: "http://127.0.0.1:8080",
                responder_hmac: &"hmac".into(),
                eab_kid: None,
                eab_hmac: None,
                trusted_ca_sha256: &[ROOT_FP.to_string()],
                endpoint_tables: Some(&tables),
            },
        );
        std::fs::write(paths.agent_config(), &config).expect("config");
        config
    }

    /// Parses a config's two operator tables the way the daemon does.
    fn endpoint_tables_of(
        config: &str,
    ) -> (
        bootroot::config::RegistrarSettings,
        bootroot::config::RegistrarEndpointSettings,
    ) {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join(AGENT_CONFIG_FILE);
        std::fs::write(&path, config).expect("write");
        let settings = bootroot::config::Settings::from_file(Some(path)).expect("deserializes");
        (settings.registrar, settings.registrar_endpoint)
    }

    /// Every repair — the `rotate ca-key` Phase-4 tail and
    /// `rotate registrar-internal-credential` both reach the
    /// republication through [`repair_internal_credential`] — carries
    /// the operator's `[registrar]` and `[registrar_endpoint]` over from
    /// the config it replaces, and republishes a config whose tables
    /// parse equal to it. A config without them carries none.
    #[tokio::test]
    async fn a_repair_republishes_the_tables_it_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/secret/data/{}",
                crate::commands::init::PATH_RESPONDER_HMAC
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "data": { "value": "hmac" } }
            })))
            .mount(&server)
            .await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let (dir, paths) = provisioned_host();
        let before = with_endpoint_tables(&paths);
        let context = super::repair_context(&endpoint_ctx(dir.path()), &client, &test_messages())
            .await
            .expect("the repair context builds");
        let republished = render_internal_agent_config(
            &paths,
            &InternalAgentConfigParams {
                email: &context.email,
                server: &context.acme_server,
                domain: &context.intent.domain,
                hostname: &context.intent.host,
                responder_url: &context.responder_url,
                responder_hmac: &context.responder_hmac,
                eab_kid: None,
                eab_hmac: None,
                trusted_ca_sha256: &[ROOT_FP.to_string()],
                endpoint_tables: context.endpoint_tables.as_ref(),
            },
        );
        assert_eq!(
            endpoint_tables_of(&republished),
            endpoint_tables_of(&before)
        );
        assert_eq!(republished, before, "nothing else moved either");

        let (plain_dir, _plain_paths) = provisioned_host();
        let context =
            super::repair_context(&endpoint_ctx(plain_dir.path()), &client, &test_messages())
                .await
                .expect("the repair context builds");
        assert!(
            context.endpoint_tables.is_none(),
            "a config without the tables carries none"
        );
    }

    /// A repair on a host whose config is gone rebuilds the two
    /// endpoints through the derivation `init` used, for the default
    /// provisioner the repair enrols against. On a host that published
    /// step-ca and the responder on routable binds, that is the binds —
    /// not loopback addresses nothing listens on — and on a host that
    /// recorded none it is loopback on the published ports, as before.
    #[tokio::test]
    async fn a_repair_without_a_config_derives_the_endpoints_init_would() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/secret/data/{}",
                crate::commands::init::PATH_RESPONDER_HMAC
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "data": { "value": "hmac" } }
            })))
            .mount(&server)
            .await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let binds = [
            (None, None),
            (Some("192.168.1.10:9443"), Some("192.168.1.10:8443")),
            (Some("0.0.0.0:9443"), Some("0.0.0.0:8443")),
        ];
        for (stepca_bind, http01_bind) in binds {
            let (dir, paths) = provisioned_host();
            std::fs::remove_file(paths.agent_config()).expect("the config is gone");
            let mut ctx = endpoint_ctx(dir.path());
            ctx.state.stepca_bind_addr = stepca_bind.map(str::to_string);
            ctx.state.http01_admin_bind_addr = http01_bind.map(str::to_string);

            let context = super::repair_context(&ctx, &client, &test_messages())
                .await
                .expect("the repair context builds");
            let compose_dir = crate::commands::compose_file::compose_file_dir(&ctx.compose_file);
            assert_eq!(
                context.acme_server,
                internal_acme_server(DEFAULT_STEPCA_PROVISIONER, stepca_bind, &compose_dir),
                "step-ca bind {stepca_bind:?}"
            );
            assert_eq!(
                context.responder_url,
                internal_responder_url(http01_bind, &compose_dir),
                "responder bind {http01_bind:?}"
            );
        }
    }

    /// Renders a provisioned host's config broken in one particular way.
    type ConfigBreak = fn(&InternalPaths) -> String;

    /// A config that exists but cannot be parsed refuses the repair
    /// before anything is read from or written to `OpenBao` or disk:
    /// publishing over it would silently drop the endpoint's
    /// configuration. That holds for a file that is not TOML and for a
    /// TOML file the daemon cannot deserialize — here a bad value
    /// outside the two tables, which the repair would otherwise have
    /// read around and replaced with its fallbacks.
    #[tokio::test]
    async fn an_unparseable_config_refuses_the_repair_before_anything_moves() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "policies": ["root"] }
            })))
            .mount(&server)
            .await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let not_toml = |_: &InternalPaths| "[registrar\nstate_file = \"/x\"\n".to_string();
        let bad_value = |paths: &InternalPaths| {
            let config = with_endpoint_tables(paths);
            let broken = config.replacen("poll_attempts = 15", "poll_attempts = \"bad\"", 1);
            assert_ne!(broken, config, "the fixture edits the rendered value");
            broken
        };
        let cases: [(&str, ConfigBreak); 2] = [
            ("not TOML", not_toml),
            ("an undeserializable value", bad_value),
        ];
        for (case, broken) in cases {
            let (dir, paths) = provisioned_host();
            std::fs::write(paths.agent_config(), broken(&paths)).expect("an unparseable config");
            let before: Vec<(std::path::PathBuf, Vec<u8>)> = paths
                .all()
                .into_iter()
                .map(|member| {
                    let bytes = std::fs::read(&member).expect("member");
                    (member, bytes)
                })
                .collect();

            let err = repair_internal_credential(
                &endpoint_ctx(dir.path()),
                &client,
                &InternalTrustState {
                    fingerprints: vec![ROOT_FP.to_string()],
                    bundle_pem: bundle_pem("Uk9PVA"),
                },
                InternalReload::Signal,
                &test_messages(),
            )
            .await
            .expect_err("an unparseable config refuses the repair");
            assert!(
                err.to_string()
                    .contains(&paths.agent_config().display().to_string()),
                "{case}: the refusal names the file: {err}"
            );
            for (member, bytes) in before {
                assert_eq!(
                    std::fs::read(&member).expect("member"),
                    bytes,
                    "{case}: {} must be left as it was",
                    member.display()
                );
            }
            assert!(!staging_dir(&paths).exists(), "{case}: nothing was staged");
        }
        let requests = server.received_requests().await.expect("recording");
        assert!(
            requests
                .iter()
                .all(|request| request.url.path() == "/v1/auth/token/lookup-self"),
            "only the authority check reached OpenBao: {requests:?}"
        );
    }

    /// A repair runs outside `init`'s rollback envelope, so a failure
    /// after the leaf was staged has nothing registered to undo it. The
    /// staging directory holds an unpublished private key, so the repair
    /// sweeps it itself rather than leaving it beside the credential.
    #[tokio::test]
    async fn a_failed_repair_sweeps_its_staging_directory() {
        let (dir, paths) = provisioned_host();
        let staging = staging_dir(&paths);
        std::fs::create_dir_all(&staging).expect("staging");
        std::fs::write(staging.join("key.pem"), "STAGED KEY").expect("staged key");

        sweep_staging(dir.path()).await;
        assert!(!staging.exists(), "the staged key must not survive");
        // The published credential is untouched by the sweep.
        assert!(paths.key().exists());
        assert!(paths.agent_config().exists());

        // A host that never reached the staging stage is a no-op.
        sweep_staging(dir.path()).await;
        assert!(!staging.exists());
    }

    /// The trust-pair writer selects the root-owned config writer
    /// itself, independently of the material publisher `init` reaches.
    ///
    /// Called directly, past the capture Phase 3 takes first, so the
    /// selection this writer makes is what fails rather than the
    /// snapshot's. It is unconditional: this writer is reached only
    /// where the internal credential set is present, and that set is
    /// what makes the host a registrar host.
    ///
    /// The config publishes before the bundle, so the refusal also
    /// leaves the bundle on the generation the pins still name.
    #[tokio::test]
    async fn the_trust_pair_writer_selects_the_root_owned_config_writer() {
        assert_ne!(
            current_process_euid(),
            0,
            "this test asserts what an unprivileged process cannot do, so it must not be root"
        );
        let (_dir, paths) = provisioned_host();
        let bundle_before = std::fs::read_to_string(paths.ca_bundle()).expect("bundle");
        let config_before = std::fs::read_to_string(paths.agent_config()).expect("config");

        let err = write_trust_pair(
            &paths,
            &bundle_pem("QURESVRJVkU"),
            "email = \"ops@example.internal\"\n",
            &test_messages(),
        )
        .await
        .expect_err("the config cannot be published by an unprivileged process");
        let report = format!("{err:#}");
        assert!(
            report.contains(AGENT_CONFIG_FILE) && report.contains("root-owned"),
            "the refusal must name the root-ownership requirement and the file: {report}"
        );

        assert_eq!(
            std::fs::read_to_string(paths.agent_config()).expect("config"),
            config_before,
            "the config must be left exactly as it was found"
        );
        assert_eq!(
            std::fs::read_to_string(paths.ca_bundle()).expect("bundle"),
            bundle_before,
            "the bundle must not move ahead of the pins"
        );
    }

    /// A config that cannot be rewritten fails before the bundle is
    /// touched at all.
    ///
    /// The cheapest half of the same guarantee: the rewritten config is
    /// computed first, so an unparseable one costs nothing and leaves
    /// both members exactly as they were.
    #[tokio::test]
    async fn an_unparseable_config_fails_before_the_bundle_moves() {
        let (dir, paths) = provisioned_host();
        std::fs::write(paths.agent_config(), "trust = [[[\n").expect("write");
        let bundle_before = std::fs::read_to_string(paths.ca_bundle()).expect("bundle");

        write_internal_trust(
            dir.path(),
            &InternalTrustState {
                fingerprints: vec![OLD_ROOT_FP.to_string()],
                bundle_pem: bundle_pem("QURESVRJVkU"),
            },
            &test_messages(),
        )
        .await
        .expect_err("an unparseable config must fail the publication");

        assert_eq!(
            std::fs::read_to_string(paths.ca_bundle()).expect("bundle"),
            bundle_before,
            "the bundle must not move ahead of the pins"
        );
    }

    /// A repair has its replacement in hand before it touches the entry
    /// the running credential authenticates against.
    ///
    /// The convergence pins the `auth/cert` entry to the staged leaf, so
    /// a leaf that could not be signed — no Docker, no intermediate key,
    /// no `password.txt` — must leave the entry, and with it the
    /// credential the daemon is still using, exactly as it was. A
    /// signing failure reaches no `OpenBao` request at all.
    #[tokio::test]
    async fn a_signing_failure_reaches_no_cert_auth_write() {
        use wiremock::MockServer;

        let server = MockServer::start().await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        // The CA is in place, so what fails is the signing helper.
        let (dir, paths) = provisioned_host();
        TestPki::new().write_ca(dir.path());
        let failing = dir.path().join("failing-docker");
        crate::test_support::write_executable(&failing, b"#!/bin/sh\nexit 1\n");
        let mut context = repair_inputs(dir.path());
        context.docker = failing;

        replace_internal_credential(
            &client,
            &context,
            &server.uri(),
            &InternalTrustState {
                fingerprints: vec![ROOT_FP.to_string()],
                bundle_pem: bundle_pem("Uk9PVA"),
            },
            InternalReload::Signal,
            &test_messages(),
        )
        .await
        .expect_err("the repair fails when the leaf cannot be signed");

        let seen = server
            .received_requests()
            .await
            .expect("the mock records every request");
        assert!(
            seen.is_empty(),
            "nothing in OpenBao may be touched before the replacement exists: {:?}",
            seen.iter()
                .map(|request| request.url.path().to_string())
                .collect::<Vec<_>>()
        );
        assert!(
            !staging_dir(&paths).exists(),
            "the unpublished key must not survive a failed repair"
        );
    }

    /// A repair that fails after the entry changed puts the entry back.
    ///
    /// The entry and the material move as one: either the host ends on
    /// the new pair, or on the pair it started with. An entry left
    /// pinned to a leaf that is not the one on disk is the one state
    /// that stops the internal daemon authenticating, so the captured body
    /// goes back verbatim — and a host whose entry did not exist before
    /// gets it removed again.
    #[tokio::test]
    async fn a_failed_repair_puts_the_previous_cert_auth_entry_back() {
        use std::sync::{Arc, Mutex};

        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, Request, ResponseTemplate};

        let entry_path = format!(
            "/v1/auth/{}/certs/{}",
            bootroot::registrar::internal::CERT_AUTH_MOUNT,
            bootroot::registrar::internal::CERT_AUTH_ROLE
        );

        let server = MockServer::start().await;
        let captured: Arc<Mutex<Option<serde_json::Value>>> = Arc::new(Mutex::new(None));
        let sink = Arc::clone(&captured);
        Mock::given(method("POST"))
            .and(path(entry_path.clone()))
            .respond_with(move |request: &Request| {
                *sink.lock().expect("capture") =
                    Some(serde_json::from_slice(&request.body).expect("json"));
                ResponseTemplate::new(204)
            })
            .mount(&server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(entry_path))
            .respond_with(ResponseTemplate::new(204))
            .mount(&server)
            .await;

        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let prior = serde_json::json!({
            "certificate": "-----BEGIN CERTIFICATE-----\nT0xE\n-----END CERTIFICATE-----\n",
            "allowed_dns_sans": ["001.bootroot-registrar-internal.bootroot-01.example.internal"],
            "token_policies": ["bootroot-registrar-internal"],
            "token_no_default_policy": true,
            "token_ttl": 3600,
        });
        restore_cert_auth_entry(&client, Some(&prior)).await;
        assert_eq!(
            captured.lock().expect("capture").clone().expect("a body"),
            prior,
            "the captured entry goes back exactly as it was read"
        );

        // A host that had no entry before ends with none.
        restore_cert_auth_entry(&client, None).await;
        let deletes = server
            .received_requests()
            .await
            .expect("recorded")
            .into_iter()
            .filter(|request| request.method == wiremock::http::Method::DELETE)
            .count();
        assert_eq!(deletes, 1, "an absent entry is restored by removing it");
    }

    /// A repair that fails after the convergence puts the *policy* back
    /// too, not just the entry.
    ///
    /// `converge_internal_auth` rewrites the exact-allowlist policy and
    /// the trusted entry in one breath, so an undo covering only the
    /// entry leaves an authority change nothing recorded: a host whose
    /// policy this run did not create — an older release's body, or one
    /// widened by hand — would come out of a failed `--force` repair
    /// permanently on this run's body. `init` puts both back; this
    /// proves the repair, which runs outside `init`'s rollback envelope
    /// and is therefore its own whole undo, does too.
    #[tokio::test]
    async fn a_failed_repair_puts_the_previous_policy_back_as_well() {
        let (server, writes) = converge_mock_server().await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let (dir, _paths) = provisioned_host();
        let context = repair_inputs(dir.path());

        // What a repair does around a login or a publication that
        // failed: capture, converge, put back what it found.
        let prior = PriorInternalAuth::capture(&client)
            .await
            .expect("both artifacts are readable");
        let mut mounted_now = false;
        let leaf = bundle_pem("TkVXTEVBRg");
        converge_internal_auth(&client, &context.inputs(), &leaf, &mut mounted_now)
            .await
            .expect("the convergence writes both artifacts");
        prior.restore(&client).await;

        let entries = writes.entries.lock().expect("capture").clone();
        assert_eq!(
            entries.first().and_then(|entry| entry.get("certificate")),
            Some(&serde_json::Value::String(leaf)),
            "the convergence pins the entry to the leaf it was handed"
        );

        let policies = writes.policies.lock().expect("capture").clone();
        assert_eq!(
            policies.len(),
            2,
            "the convergence writes the policy and the restore puts it back: {policies:?}"
        );
        assert_ne!(
            policies.first().expect("the converged body"),
            PRIOR_POLICY,
            "the convergence really does replace the pre-existing policy"
        );
        assert_eq!(
            policies.last().expect("the restored body"),
            PRIOR_POLICY,
            "the policy the repair found goes back exactly as it was read"
        );
        assert_eq!(
            writes.entries.lock().expect("capture").last(),
            Some(&prior_entry()),
            "the entry is still restored alongside it"
        );
    }

    /// The whole repair, over a host that already carries a credential:
    /// the replacement is signed offline, the entry is pinned to the
    /// staged leaf and only the leaf, and — the login proof failing, as
    /// it does over this plain-HTTP mock — the entry and the policy the
    /// repair found go back verbatim, the published files are untouched
    /// and no staging directory is left.
    #[tokio::test]
    async fn a_failure_after_the_entry_write_restores_what_the_repair_found() {
        let (server, writes) = converge_mock_server().await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let (dir, paths) = provisioned_host();
        let pki = TestPki::new();
        pki.write_ca(dir.path());
        let leaf = pki.fresh_leaf();
        let args_log = dir.path().join("docker_args.log");
        let mut context = repair_inputs(dir.path());
        context.docker = write_signing_fake_docker(dir.path(), &args_log, &leaf);
        let before: Vec<Vec<u8>> = paths
            .all()
            .iter()
            .map(|member| std::fs::read(member).expect("member"))
            .collect();

        let err = replace_internal_credential(
            &client,
            &context,
            &server.uri(),
            &InternalTrustState {
                fingerprints: vec![ROOT_FP.to_string()],
                bundle_pem: bundle_pem("Uk9PVA"),
            },
            InternalReload::Signal,
            &test_messages(),
        )
        .await
        .expect_err("the login proof cannot succeed over plaintext");
        assert!(
            format!("{err:#}").contains("certificate login requires TLS"),
            "the repair got as far as the login proof: {err:#}"
        );

        let log = std::fs::read_to_string(&args_log).expect("the helper ran");
        assert!(
            log.contains("certificate create") && log.contains("--not-after 87600h"),
            "the replacement was signed offline: {log}"
        );

        let entries = writes.entries.lock().expect("capture").clone();
        assert_eq!(entries.len(), 2, "the convergence, then the restore");
        assert_eq!(
            entries[0]["certificate"], leaf.cert_pem,
            "the entry is pinned to the staged leaf alone, not its chain"
        );
        assert_eq!(entries[1], prior_entry(), "the entry goes back verbatim");
        let policies = writes.policies.lock().expect("capture").clone();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[1], PRIOR_POLICY, "the policy goes back verbatim");

        let after: Vec<Vec<u8>> = paths
            .all()
            .iter()
            .map(|member| std::fs::read(member).expect("member"))
            .collect();
        assert_eq!(after, before, "the published set was never touched");
        assert!(
            !staging_dir(&paths).exists(),
            "the unpublished key must not survive a failed repair"
        );
    }

    /// A host the up-to-date predicate can be driven over: a real CA,
    /// and a published set whose leaf is `leaf` under that CA.
    fn pinned_host(pki: &TestPki, leaf: &TestLeaf) -> (TempDir, InternalPaths) {
        let (dir, paths) = provisioned_host();
        pki.write_ca(dir.path());
        std::fs::write(
            paths.chain(),
            format!("{}{}", leaf.cert_pem, pki.intermediate_pem),
        )
        .expect("chain");
        std::fs::write(
            paths.root_fingerprint(),
            format!(
                "{}\n",
                bootroot::registrar::internal::active_root_fingerprint(dir.path())
                    .expect("the active root")
            ),
        )
        .expect("fingerprint");
        (dir, paths)
    }

    /// An `OpenBao` whose entry read answers `response`, counting the
    /// reads.
    async fn entry_read_server(response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/auth/{CERT_AUTH_MOUNT}/certs/{CERT_AUTH_ROLE}"
            )))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    fn entry_with(certificate: &str) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "certificate": certificate, "display_name": CERT_AUTH_ROLE }
        }))
    }

    async fn up_to_date(dir: &TempDir, server: &MockServer) -> anyhow::Result<bool> {
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        internal_credential_up_to_date(
            dir.path(),
            &client,
            time::OffsetDateTime::now_utc(),
            &test_messages(),
        )
        .await
    }

    /// All three conditions holding is the one case a run without
    /// `--force` stops at: the material is present under the active
    /// root, the entry is pinned to exactly the published leaf, and the
    /// leaf is more than thirty days from expiry.
    #[tokio::test]
    async fn a_pinned_current_credential_is_up_to_date() {
        let pki = TestPki::new();
        let leaf = pki.fresh_leaf();
        let (dir, _paths) = pinned_host(&pki, &leaf);
        let server = entry_read_server(entry_with(&leaf.cert_pem)).await;
        assert!(up_to_date(&dir, &server).await.expect("the entry is read"));

        // `OpenBao` hands the PEM back as it likes; what is compared is
        // the certificate, not its spelling.
        let respelt = format!("\n{}\n\n", leaf.cert_pem.trim_end());
        let server = entry_read_server(entry_with(&respelt)).await;
        assert!(up_to_date(&dir, &server).await.expect("the entry is read"));
    }

    /// The material failing alone: a set that is incomplete, or one
    /// whose stored root is not the active root, is replaced — and the
    /// entry is not even read to decide it.
    #[tokio::test]
    async fn incomplete_or_superseded_material_is_not_up_to_date() {
        let pki = TestPki::new();
        let leaf = pki.fresh_leaf();

        let (dir, paths) = pinned_host(&pki, &leaf);
        std::fs::remove_file(paths.key()).expect("remove the key");
        let server = entry_read_server(entry_with(&leaf.cert_pem)).await;
        assert!(!up_to_date(&dir, &server).await.expect("no read is needed"));
        assert!(
            server
                .received_requests()
                .await
                .expect("recording")
                .is_empty()
        );

        let (dir, paths) = pinned_host(&pki, &leaf);
        std::fs::write(paths.root_fingerprint(), format!("{OLD_ROOT_FP}\n")).expect("stale");
        let server = entry_read_server(entry_with(&leaf.cert_pem)).await;
        assert!(!up_to_date(&dir, &server).await.expect("no read is needed"));
        assert!(
            server
                .received_requests()
                .await
                .expect("recording")
                .is_empty()
        );
    }

    /// The entry failing alone. An installation from before the entry
    /// was pinned holds the root CA there, and replacing it is how that
    /// installation migrates; an absent entry, another leaf of the same
    /// CA, the leaf followed by its intermediate and an entry that does
    /// not parse are all mismatches too.
    #[tokio::test]
    async fn an_entry_that_is_not_the_published_leaf_is_not_up_to_date() {
        let pki = TestPki::new();
        let leaf = pki.fresh_leaf();
        let (dir, _paths) = pinned_host(&pki, &leaf);
        let other = pki.fresh_leaf();
        let with_intermediate = format!("{}{}", leaf.cert_pem, pki.intermediate_pem);
        let cases: [(&str, ResponseTemplate); 7] = [
            ("the root CA (the old shape)", entry_with(&pki.root_pem)),
            ("the intermediate CA", entry_with(&pki.intermediate_pem)),
            ("another leaf of the same CA", entry_with(&other.cert_pem)),
            (
                "the leaf and its intermediate",
                entry_with(&with_intermediate),
            ),
            ("not a certificate", entry_with("not a certificate")),
            (
                "no certificate field",
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "data": {} })),
            ),
            ("no entry", ResponseTemplate::new(404)),
        ];
        for (case, response) in cases {
            let server = entry_read_server(response).await;
            assert!(
                !up_to_date(&dir, &server).await.expect("the entry is read"),
                "{case}"
            );
        }
    }

    /// The expiry failing alone: a leaf within thirty days of its
    /// `notAfter` — or past it — is replaced, though the entry is pinned
    /// to it and the root is current. One just outside the window is
    /// left alone.
    #[tokio::test]
    async fn a_leaf_within_thirty_days_of_expiry_is_not_up_to_date() {
        let pki = TestPki::new();
        let now = time::OffsetDateTime::now_utc();
        for (days, expected) in [(-1, false), (29, false), (31, true)] {
            let leaf = pki.leaf(now + time::Duration::days(days));
            let (dir, _paths) = pinned_host(&pki, &leaf);
            let server = entry_read_server(entry_with(&leaf.cert_pem)).await;
            assert_eq!(
                up_to_date(&dir, &server).await.expect("the entry is read"),
                expected,
                "a leaf {days} days from expiry"
            );
        }
    }

    /// An entry read that did not answer is an error. Reporting it as
    /// "up to date" would leave an unmigrated entry in place behind a
    /// message saying nothing needs doing.
    #[tokio::test]
    async fn an_entry_read_failure_is_an_error_and_not_up_to_date() {
        let pki = TestPki::new();
        let leaf = pki.fresh_leaf();
        let (dir, _paths) = pinned_host(&pki, &leaf);
        let server = entry_read_server(ResponseTemplate::new(500).set_body_string("boom")).await;
        let err = up_to_date(&dir, &server)
            .await
            .expect_err("a failed read is not an answer");
        assert!(format!("{err:#}").contains("cert auth entry"), "{err:#}");
    }

    /// The command itself: without `--force` it stops on a host whose
    /// three conditions hold, having written nothing, and fails rather
    /// than stopping when the entry cannot be read.
    #[tokio::test]
    async fn the_command_stops_only_on_an_up_to_date_host() {
        let pki = TestPki::new();
        let leaf = pki.fresh_leaf();
        let (dir, _paths) = pinned_host(&pki, &leaf);
        let args = crate::cli::args::RotateRegistrarInternalArgs { force: false };

        for (case, response, stops) in [
            ("a pinned entry", entry_with(&leaf.cert_pem), true),
            (
                "an unreadable entry",
                ResponseTemplate::new(500).set_body_string("boom"),
                false,
            ),
        ] {
            let server = entry_read_server(response).await;
            Mock::given(method("GET"))
                .and(path("/v1/auth/token/lookup-self"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": { "policies": ["root"] }
                })))
                .mount(&server)
                .await;
            let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
            client.set_token("root-token".to_string());
            let outcome = rotate_registrar_internal_credential(
                &endpoint_ctx(dir.path()),
                &client,
                &args,
                true,
                &test_messages(),
            )
            .await;
            assert_eq!(outcome.is_ok(), stops, "{case}");
            let requests = server.received_requests().await.expect("recording");
            assert!(
                requests
                    .iter()
                    .all(|request| request.method == wiremock::http::Method::GET),
                "nothing is written either way"
            );
        }
    }

    /// The Phase-4 tail refuses to replace anything on a host whose
    /// Phase-3 publication did not land.
    #[tokio::test]
    async fn the_tail_refuses_a_host_that_is_not_on_the_additive_set() {
        let (dir, _paths) = provisioned_host();
        let additive = vec![
            OLD_ROOT_FP.to_string(),
            OLD_INT_FP.to_string(),
            ROOT_FP.to_string(),
            NEW_INT_FP.to_string(),
        ];
        let err = ensure_internal_trust_is(dir.path(), &additive, &test_messages())
            .expect_err("a stale config must be refused");
        assert!(err.to_string().contains("Phase 3"), "{err}");

        // Written directly, because the publication Phase 3 performs is
        // root-only: what this half asserts is the *reader*, which is
        // what the tail gates on.
        let paths = InternalPaths::new(dir.path());
        std::fs::write(
            paths.agent_config(),
            upsert_internal_trust(
                &std::fs::read_to_string(paths.agent_config()).expect("config"),
                &paths,
                &additive,
            )
            .expect("the additive pins"),
        )
        .expect("config");
        ensure_internal_trust_is(dir.path(), &additive, &test_messages())
            .expect("the additive set is now in place");
    }

    /// An HMAC no test output may ever carry.
    const ROTATED_HMAC: &str = "rotated-hmac-that-must-not-appear";

    /// Reports whether nobody holds the internal config lock, without
    /// waiting.
    ///
    /// `flock` belongs to the open file description, so a hold on
    /// another descriptor in this process refuses this one exactly as
    /// another process's would. A lock the probe takes is given back
    /// with `unlock` before it returns, so that a child another test
    /// thread forks cannot carry it into the next step. Test-only: the
    /// answer is stale the moment it is returned.
    fn lock_is_free(paths: &InternalPaths) -> bool {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(paths.dir().join(INTERNAL_CONFIG_LOCK_FILE))
            .expect("open the lock file");
        let free = file.try_lock().is_ok();
        if free {
            let _ = file.unlock();
        }
        free
    }

    /// A copy of the guard's descriptor — what a child forked by another
    /// thread holds until its `exec` — does not keep the lock held once
    /// the guard is dropped.
    #[tokio::test]
    async fn a_descriptor_copy_does_not_keep_a_dropped_lock_held() {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        let held = acquire_internal_config_lock(dir.path())
            .await
            .expect("take the lock");
        let copy = held.file.try_clone().expect("duplicate the descriptor");

        drop(held);

        assert!(
            lock_is_free(&paths),
            "dropping the guard releases the lock despite the copy"
        );
        drop(copy);
    }

    /// The four answers the pre-write check gives, one per kind of
    /// host.
    #[tokio::test]
    async fn the_check_tells_the_four_kinds_of_host_apart() {
        let hmac = bootroot::secret::HmacSecret::from(ROTATED_HMAC);
        let set_hmac = InternalConfigChange::SetResponderHmac(&hmac);

        let bare = TempDir::new().expect("tempdir");
        for change in [set_hmac, InternalConfigChange::RemoveEab] {
            assert_eq!(
                check_internal_config_change(bare.path(), change)
                    .await
                    .expect("an absent config is not an error"),
                InternalConfigCheck::Absent
            );
        }
        assert!(
            !InternalPaths::new(bare.path()).dir().exists(),
            "the check creates nothing on a host without the registrar"
        );

        let (dir, paths) = provisioned_host();
        assert_eq!(
            check_internal_config_change(dir.path(), set_hmac)
                .await
                .expect("readable"),
            InternalConfigCheck::Applicable
        );
        assert_eq!(
            check_internal_config_change(dir.path(), InternalConfigChange::RemoveEab)
                .await
                .expect("readable"),
            InternalConfigCheck::Unchanged,
            "the fixture renders no [eab], so eab-clear has nothing to change"
        );
        let with_eab = format!(
            "{}\n[eab]\nkid = \"kid-1\"\nhmac = \"eab-hmac\"\n",
            std::fs::read_to_string(paths.agent_config()).expect("config")
        );
        std::fs::write(paths.agent_config(), with_eab).expect("config");
        assert_eq!(
            check_internal_config_change(dir.path(), InternalConfigChange::RemoveEab)
                .await
                .expect("readable"),
            InternalConfigCheck::Applicable
        );

        // The parser's own message quotes the offending line, and the
        // line here carries the old HMAC: the refusal names the file and
        // nothing from inside it.
        std::fs::write(
            paths.agent_config(),
            "[acme\nhttp_responder_hmac = \"old-hmac-that-must-not-appear\"\n",
        )
        .expect("config");
        for change in [set_hmac, InternalConfigChange::RemoveEab] {
            let report = format!(
                "{:#}",
                check_internal_config_change(dir.path(), change)
                    .await
                    .expect_err("an unparseable config is refused")
            );
            assert!(
                report.contains(&paths.agent_config().display().to_string()),
                "the refusal names the file: {report}"
            );
            assert!(
                !report.contains("old-hmac-that-must-not-appear") && !report.contains(ROTATED_HMAC),
                "no HMAC reaches the refusal: {report}"
            );
        }
        assert!(
            !paths.dir().join(INTERNAL_CONFIG_LOCK_FILE).exists(),
            "the check takes no lock"
        );
    }

    /// An `[acme]` spelled as an inline table is one the check finds
    /// applicable and the rewrite under the lock carries the new HMAC
    /// into; an `acme` that is not a table refuses the rotation before
    /// its first write rather than letting it report a rewrite it did
    /// not make.
    #[tokio::test]
    async fn the_check_and_the_rewrite_reach_an_inline_acme() {
        let hmac = bootroot::secret::HmacSecret::from(ROTATED_HMAC);
        let set_hmac = InternalConfigChange::SetResponderHmac(&hmac);
        let (dir, paths) = provisioned_host();
        let mut doc: toml_edit::DocumentMut = std::fs::read_to_string(paths.agent_config())
            .expect("config")
            .parse()
            .expect("valid TOML");
        let acme = doc
            .remove("acme")
            .and_then(|item| item.into_table().ok())
            .expect("the [acme] table");
        doc.insert(
            "acme",
            toml_edit::Item::Value(toml_edit::Value::InlineTable(acme.into_inline_table())),
        );
        std::fs::write(paths.agent_config(), doc.to_string()).expect("config");

        assert_eq!(
            check_internal_config_change(dir.path(), set_hmac)
                .await
                .expect("readable"),
            InternalConfigCheck::Applicable
        );
        let lock = acquire_internal_config_lock(dir.path())
            .await
            .expect("the lock");
        let rewritten = rewrite_internal_config(&paths.agent_config(), set_hmac, &lock)
            .await
            .expect("the rewrite")
            .expect("the HMAC changes the file");
        std::fs::write(paths.agent_config(), rewritten).expect("config");
        assert_eq!(
            bootroot::registrar::internal::load_internal_config(&paths)
                .expect("loads")
                .acme
                .http_responder_hmac
                .expose(),
            ROTATED_HMAC
        );
        drop(lock);

        std::fs::write(paths.agent_config(), "acme = \"old-hmac-in-a-string\"\n").expect("config");
        let report = format!(
            "{:#}",
            check_internal_config_change(dir.path(), set_hmac)
                .await
                .expect_err("a non-table acme is refused")
        );
        assert!(
            report.contains(&paths.agent_config().display().to_string())
                && report.contains("must be a table")
                && report.contains("nothing has been written"),
            "{report}"
        );
        assert!(
            !report.contains("old-hmac-in-a-string") && !report.contains(ROTATED_HMAC),
            "{report}"
        );
    }

    /// A lock that cannot be taken fails naming the config it guards,
    /// not only the lock file beside it.
    #[tokio::test]
    async fn a_lock_failure_names_the_internal_config() {
        let (dir, paths) = provisioned_host();
        // A directory where the lock file goes cannot be opened as one.
        std::fs::create_dir(paths.dir().join(INTERNAL_CONFIG_LOCK_FILE)).expect("mkdir");
        let err = acquire_internal_config_lock(dir.path())
            .await
            .err()
            .expect("the lock cannot be taken");
        let report = format!("{err:#}");
        // The lock file's path starts with the config's, so the config
        // is looked for as a path of its own, not as a prefix.
        assert!(
            report.contains(&format!(
                "bootroot-internal config at {} for update",
                paths.agent_config().display()
            )) && report.contains(INTERNAL_CONFIG_LOCK_FILE),
            "{report}"
        );
    }

    /// A config the invoking user cannot read — the permission error a
    /// non-root run gets on the `root:root` `0600` file — refuses the
    /// rotation with an error that names the file and asks for root.
    #[tokio::test]
    async fn an_unreadable_config_refuses_the_rotation_and_asks_for_root() {
        use std::os::unix::fs::PermissionsExt;

        assert_ne!(
            current_process_euid(),
            0,
            "root reads a 0000 file, so this test must not run as root"
        );
        let (dir, paths) = provisioned_host();
        std::fs::set_permissions(paths.agent_config(), std::fs::Permissions::from_mode(0o000))
            .expect("chmod");
        let err = check_internal_config_change(dir.path(), InternalConfigChange::RemoveEab)
            .await
            .expect_err("an unreadable config is refused");
        let report = format!("{err:#}");
        assert!(
            report.contains(&paths.agent_config().display().to_string())
                && report.contains("as root")
                && report.contains("Nothing has been written"),
            "{report}"
        );
    }

    /// An apply waits for the lock before it reads, so a `[trust]`
    /// change another writer publishes while holding it survives the
    /// apply's rewrite.
    ///
    /// The pure re-read-and-apply step is what is driven: the publish
    /// after it is root-only, which the test below covers. The result is
    /// the proof — a rewrite computed from a read taken before the lock
    /// was released could not carry the `[trust]` edit made under it.
    #[tokio::test]
    async fn an_apply_reads_only_once_the_lock_is_released() {
        let (dir, paths) = provisioned_host();
        let secrets_dir = dir.path().to_path_buf();
        let held = acquire_internal_config_lock(&secrets_dir)
            .await
            .expect("the test takes the lock");

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let config_path = paths.agent_config();
        let applying = tokio::spawn(async move {
            let hmac = bootroot::secret::HmacSecret::from(ROTATED_HMAC);
            let _ = started_tx.send(());
            let lock = acquire_internal_config_lock(&secrets_dir)
                .await
                .expect("the apply takes the lock");
            rewrite_internal_config(
                &config_path,
                InternalConfigChange::SetResponderHmac(&hmac),
                &lock,
            )
            .await
        });
        started_rx.await.expect("the apply started");
        tokio::task::yield_now().await;
        assert!(!applying.is_finished(), "the apply waits for the lock");

        // What `rotate ca-key` Phase 3 does under the lock.
        let additive = vec![OLD_ROOT_FP.to_string(), ROOT_FP.to_string()];
        std::fs::write(
            paths.agent_config(),
            upsert_internal_trust(
                &std::fs::read_to_string(paths.agent_config()).expect("config"),
                &paths,
                &additive,
            )
            .expect("the additive pins"),
        )
        .expect("config");
        drop(held);

        let rewritten = applying
            .await
            .expect("the apply task")
            .expect("the rewrite")
            .expect("the HMAC changes the file");
        let settings = {
            std::fs::write(paths.agent_config(), &rewritten).expect("config");
            bootroot::registrar::internal::load_internal_config(&paths).expect("loads")
        };
        assert_eq!(
            settings.trust.trusted_ca_sha256, additive,
            "the [trust] change made under the lock survives"
        );
        assert_eq!(settings.acme.http_responder_hmac.expose(), ROTATED_HMAC);
    }

    /// The new writer's publication is root-only, exactly like
    /// `write_trust_pair`: an unprivileged run fails naming the file and
    /// the ownership requirement, and leaves the bytes it found.
    #[tokio::test]
    async fn publishing_the_internal_config_is_root_only() {
        assert_ne!(
            current_process_euid(),
            0,
            "this test asserts what an unprivileged process cannot do, so it must not be root"
        );
        let (_dir, paths) = provisioned_host();
        let before = std::fs::read(paths.agent_config()).expect("config");

        let err = publish_internal_config(&paths.agent_config(), "email = \"x\"\n")
            .await
            .expect_err("an unprivileged process cannot publish the protected config");
        let report = format!("{err:#}");
        assert!(
            report.contains(AGENT_CONFIG_FILE) && report.contains("root-owned"),
            "the refusal must name the root-ownership requirement and the file: {report}"
        );
        assert_eq!(std::fs::read(paths.agent_config()).expect("config"), before);
    }

    /// An apply whose publication fails reports the file and the
    /// recovery, carries no HMAC, and leaves the file and the lock as a
    /// later run needs them.
    #[tokio::test]
    async fn a_failed_apply_names_the_recovery_and_releases_the_lock() {
        assert_ne!(
            current_process_euid(),
            0,
            "this test asserts what an unprivileged process cannot do, so it must not be root"
        );
        let (dir, paths) = provisioned_host();
        let before = std::fs::read(paths.agent_config()).expect("config");
        let hmac = bootroot::secret::HmacSecret::from(ROTATED_HMAC);

        let outcome = {
            let lock = acquire_internal_config_lock(dir.path())
                .await
                .expect("the lock");
            assert!(!lock_is_free(&paths), "held while the apply runs");
            apply_internal_config_change(
                dir.path(),
                InternalConfigChange::SetResponderHmac(&hmac),
                &lock,
                &test_messages(),
            )
            .await
        };
        let report = format!("{:#}", outcome.expect_err("the publication is root-only"));
        assert!(
            report.contains(&paths.agent_config().display().to_string())
                && report.contains("root-owned")
                && report.contains("re-run this rotation")
                && report.contains("bootroot rotate registrar-internal-credential --force"),
            "{report}"
        );
        assert!(!report.contains(ROTATED_HMAC), "{report}");
        assert_eq!(std::fs::read(paths.agent_config()).expect("config"), before);
        assert!(lock_is_free(&paths), "a failed apply leaves the lock free");
    }

    /// An `eab-clear` apply over a config with no `[eab]` publishes
    /// nothing: same bytes, same inode, no signal to send.
    #[tokio::test]
    async fn an_eab_apply_over_a_config_without_eab_writes_nothing() {
        use std::os::unix::fs::MetadataExt;

        let (dir, paths) = provisioned_host();
        let before = std::fs::read(paths.agent_config()).expect("config");
        let inode = std::fs::metadata(paths.agent_config()).expect("meta").ino();

        let lock = acquire_internal_config_lock(dir.path())
            .await
            .expect("the lock");
        let published = apply_internal_config_change(
            dir.path(),
            InternalConfigChange::RemoveEab,
            &lock,
            &test_messages(),
        )
        .await
        .expect("nothing to change is a success, even unprivileged");
        assert!(!published);
        assert_eq!(std::fs::read(paths.agent_config()).expect("config"), before);
        assert_eq!(
            std::fs::metadata(paths.agent_config()).expect("meta").ino(),
            inode
        );
    }

    /// A config that disappeared between the check and the apply fails
    /// the apply naming the file.
    #[tokio::test]
    async fn an_apply_over_a_vanished_config_names_the_file() {
        let (dir, paths) = provisioned_host();
        let lock = acquire_internal_config_lock(dir.path())
            .await
            .expect("the lock");
        std::fs::remove_file(paths.agent_config()).expect("remove");
        let err = apply_internal_config_change(
            dir.path(),
            InternalConfigChange::RemoveEab,
            &lock,
            &test_messages(),
        )
        .await
        .expect_err("a vanished config fails the apply");
        assert!(
            format!("{err:#}").contains(&paths.agent_config().display().to_string()),
            "{err:#}"
        );
    }

    /// Phase 3's writer holds the lock across its read–modify–write and
    /// releases it on the way out, failure included.
    #[tokio::test]
    async fn the_trust_writer_waits_for_and_releases_the_lock() {
        let (dir, paths) = provisioned_host();
        let held = acquire_internal_config_lock(dir.path())
            .await
            .expect("the test takes the lock");
        let secrets_dir = dir.path().to_path_buf();
        let writing = tokio::spawn(async move {
            write_internal_trust(
                &secrets_dir,
                &InternalTrustState {
                    fingerprints: vec![OLD_ROOT_FP.to_string()],
                    bundle_pem: bundle_pem("QURESVRJVkU"),
                },
                &test_messages(),
            )
            .await
        });
        tokio::task::yield_now().await;
        assert!(!writing.is_finished(), "the writer waits for the lock");
        drop(held);
        // Unprivileged, so the root-only publication fails; what is
        // asserted is that the failure released the lock.
        let _ = writing.await.expect("the writer task");
        assert!(
            lock_is_free(&paths),
            "the writer's failure released the lock"
        );
    }

    /// A repair holds the lock from before it reads `OpenBao`: while a
    /// responder-HMAC or EAB rotation holds it, the repair sends no read
    /// of the responder HMAC, and once it is released the read arrives.
    #[tokio::test]
    async fn a_repair_reads_openbao_only_once_the_lock_is_released() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let released = Arc::new(AtomicBool::new(false));
        let (seen_tx, mut seen_rx) = tokio::sync::mpsc::unbounded_channel::<bool>();
        let (authority_tx, mut authority_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .respond_with(move |_: &Request| {
                let _ = authority_tx.send(());
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": { "policies": ["root"] }
                }))
            })
            .mount(&server)
            .await;
        let flag = Arc::clone(&released);
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/secret/data/{}",
                crate::commands::init::PATH_RESPONDER_HMAC
            )))
            .respond_with(move |_: &Request| {
                // Whether the rotation had released the lock when this
                // read arrived — the ordering under test.
                let _ = seen_tx.send(flag.load(Ordering::SeqCst));
                ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "data": { "data": { "value": "hmac" } }
                }))
            })
            .mount(&server)
            .await;
        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());

        let (dir, paths) = provisioned_host();
        let held = acquire_internal_config_lock(dir.path())
            .await
            .expect("the rotation holds the lock");

        let ctx = endpoint_ctx(dir.path());
        let repairing = tokio::spawn(async move {
            repair_internal_credential(
                &ctx,
                &client,
                &InternalTrustState {
                    fingerprints: vec![ROOT_FP.to_string()],
                    bundle_pem: bundle_pem("Uk9PVA"),
                },
                InternalReload::Signal,
                &test_messages(),
            )
            .await
        });
        authority_rx
            .recv()
            .await
            .expect("the repair passed its authority check");
        // Bounding a negative observation, not synchronizing: with the
        // lock held the read must not arrive at all, and a repair that
        // did not wait would send it straight after the check above.
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), seen_rx.recv())
                .await
                .is_err(),
            "the repair read the responder HMAC while the rotation held the lock"
        );

        released.store(true, Ordering::SeqCst);
        drop(held);
        assert_eq!(
            seen_rx.recv().await,
            Some(true),
            "the repair reads the responder HMAC once the lock is released, and not before"
        );
        // No CA material below the secrets directory, so the repair
        // then fails at issuance; the lock goes with it.
        repairing
            .await
            .expect("the repair task")
            .expect_err("issuance fails without CA material");
        assert!(lock_is_free(&paths), "the failed repair released the lock");
    }
}
