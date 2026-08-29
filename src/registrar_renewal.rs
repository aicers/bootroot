//! Renewal of the registrar surface's two leaves, on the daemon's own
//! loop.
//!
//! [`crate::registrar_certs`] mints both leaves once, at start, and
//! leaves a usable pair alone. Both expire. This module is what keeps
//! them valid afterwards: one daemon-owned adapter, created only where
//! the endpoint is enabled, owning both leaves, taking the daemon's
//! shutdown signal and joined with the daemon's other tasks.
//!
//! # What a pass does, and in what order
//!
//! Nothing on the live paths until everything that can fail has already
//! succeeded. For a leaf that is due:
//!
//! 1. **Issue off-live.** The same outbound ACME path start-time
//!    issuance runs, under the same bootroot-internal credential, but
//!    stopped before publication — the chain, the candidate certificate
//!    and a fresh key come back as values. Nothing is written at
//!    `[registrar_endpoint]`'s paths and nothing at
//!    `[trust] ca_bundle_path`.
//! 2. **Validate the candidate.** Its key is the leaf's; a client
//!    candidate carries the reserved registrar client SAN and
//!    recognises to the same instance, host and domain as the name the
//!    plan composed; a server candidate carries the exact endpoint SAN
//!    and chains to an anchor already in the endpoint pin file. An
//!    invalid or unpinned candidate is a refusal, not a repair: it is
//!    discarded and no live or active state changes.
//! 3. **Stage the merged bundle.** The bytes `[trust] ca_bundle_path`
//!    *would* hold — the existing bundle's pinned certificates plus the
//!    candidate's chain — computed but not written.
//! 4. **Build the next configuration.** A complete
//!    [`rustls::ServerConfig`], from the candidate server pair when
//!    that is the leaf being renewed and from the live server pair when
//!    it is not, and from the staged bundle in either case. The
//!    incoming client verifier is rebuilt here, from the post-merge
//!    bundle's pinned subset and from nothing else.
//! 5. **Snapshot, then publish.** The affected live paths' bytes, modes
//!    and ownership are captured, then the merged bundle is replaced
//!    atomically and the certificate and key are written through the
//!    established two-rename contract.
//! 6. **Exchange the active configuration.** Only after every live
//!    write succeeded, and infallibly, because the replacement was
//!    built in step 4. The socket is not rebound, no signal is sent,
//!    and connections and handshakes already in flight keep the
//!    configuration they started with.
//!
//! A publication that fails restores every live path whose write may
//! have started, leaves the old configuration installed, records the
//! failure and lets the next tick try again. A rollback that itself
//! fails is recorded as what it is — both errors, and no claim that the
//! files were restored.
//!
//! # What it deliberately does not do
//!
//! It never rewrites the endpoint pin file and never adds a leaf
//! fingerprint to it: the pin file decides whether a *replacement server
//! leaf* is safe for pinned callers, and a renewal that could edit it
//! would be deciding that about itself. It never repairs the
//! bootroot-internal credential and imposes no ordering on a CA
//! rotation — a tick that reaches a leaf while that credential cannot
//! authenticate records an ordinary failed issuance and retries. It
//! reads no `role_id` and no `secret_id`, and never uses the per-service
//! ACME renewal path.
//!
//! # The accessor
//!
//! [`RegistrarCertRenewalState`] is the whole of this module's
//! interface to anything else in the process: per leaf, the observed
//! `notAfter`, the outcome of the last attempt, and when that attempt
//! ran. It is written on this loop's own tick and nowhere else, and
//! nothing here puts anything on the wire.

use std::collections::BTreeMap;
use std::future::Future;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use anyhow::{Context as _, Result};
use rustls::pki_types::{CertificateDer, UnixTime};
use time::OffsetDateTime;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::cert_group::{CERT_FILE_MODE, CertGroupPolicy, KEY_FILE_MODE_DEFAULT};
use crate::config::Settings;
use crate::fs_util::{Destination, FixedOwner, StagedMode};
use crate::registrar::endpoint::ActivatedEndpoint;
use crate::registrar::endpoint::tls::build_server_config_from_staged;
use crate::registrar::endpoint_pin::{
    self, EndpointPinError, EndpointVerifyRejection, RegistrarEndpointVerifier,
};
use crate::registrar::internal::{InternalPaths, load_internal_config};
use crate::registrar::{
    recognize_registrar_client_name, recognize_registrar_endpoint_name, single_dns_san,
};
use crate::registrar_certs::{
    SurfaceAcmeInputs, SurfaceLeaf, SurfacePairPaths, SurfacePlan, issue_surface_pair_material,
    read_acme_inputs, resolve_surface_plan,
};
use crate::{daemon, fs_util, tls, utils};

/// The basename the candidate certificate is staged under, inside the
/// attempt's private working directory.
const CANDIDATE_CERT_FILE: &str = "candidate.crt";

/// The basename the candidate key is staged under.
const CANDIDATE_KEY_FILE: &str = "candidate.key";

/// The prefix the attempt's private working directory is created with,
/// so an operator who finds one knows what left it.
const ARTIFACT_DIR_PREFIX: &str = "bootroot-registrar-renewal.";

// ---------------------------------------------------------------------
// The accessor
// ---------------------------------------------------------------------

/// How the last renewal attempt for one leaf ended.
///
/// "No attempt yet" is a state of its own rather than an absent
/// outcome: it is what initialization records, and it is the only one
/// of the three that carries no timestamp.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RenewalAttempt {
    /// Initialization observed the leaf and nothing has been attempted
    /// since. Reached without an `OpenBao` request or a CA request.
    NeverAttempted,
    /// The last attempt issued, validated and published a replacement,
    /// and exchanged the active configuration.
    Succeeded,
    /// The last attempt failed, and the leaf still holds whatever it
    /// held before. Every ordinary issuance, publication, rollback,
    /// authentication and pin-file refusal lands here.
    Failed {
        /// What went wrong, rendered for an operator.
        reason: String,
    },
}

/// What the accessor holds about one leaf.
///
/// These three values are exactly what the reporting sibling publishes,
/// so they are written here and read there. Until that sibling lands
/// nothing outside a test reads them, and they carry the same
/// justification [`RegistrarCertRenewalState::leaf`] records: a reader
/// that re-derived a lifetime from disk is the thing this seam exists
/// to forbid.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) struct LeafRenewalState {
    /// The `notAfter` of the certificate currently at the leaf's
    /// configured path. Replaced by a success and retained by a failure.
    pub(crate) not_after: OffsetDateTime,
    /// How the last attempt ended.
    pub(crate) attempt: RenewalAttempt,
    /// When that attempt ran, absent while nothing has been attempted.
    pub(crate) attempted_at: Option<OffsetDateTime>,
}

/// The one place a registrar leaf's lifetime and last outcome are
/// discovered.
///
/// Written on the renewal loop's own tick, never on a request path, and
/// never recomputed from disk by a reader: a member that stat'ed and
/// parsed a certificate per request would put filesystem work behind an
/// endpoint a caller can drive.
#[derive(Clone, Default)]
pub(crate) struct RegistrarCertRenewalState {
    inner: Arc<Mutex<BTreeMap<SurfaceLeaf, LeafRenewalState>>>,
}

impl RegistrarCertRenewalState {
    /// Records a leaf's observed `notAfter` with no attempt behind it.
    ///
    /// The one write that is not an attempt: it reads a certificate that
    /// is already on disk and contacts neither `OpenBao` nor the CA.
    pub(crate) fn initialize(&self, leaf: SurfaceLeaf, not_after: OffsetDateTime) {
        self.with(|entries| {
            entries.insert(
                leaf,
                LeafRenewalState {
                    not_after,
                    attempt: RenewalAttempt::NeverAttempted,
                    attempted_at: None,
                },
            );
        });
    }

    /// Records a successful attempt: the new `notAfter`, and when it ran.
    ///
    /// Creates the entry when initialization could not read the
    /// certificate that was there — that leaf has no lifetime to retain
    /// and no entry, and this attempt has just given it one. Every other
    /// write updates in place.
    pub(crate) fn record_success(
        &self,
        leaf: SurfaceLeaf,
        not_after: OffsetDateTime,
        at: OffsetDateTime,
    ) {
        self.with(|entries| {
            entries.insert(
                leaf,
                LeafRenewalState {
                    not_after,
                    attempt: RenewalAttempt::Succeeded,
                    attempted_at: Some(at),
                },
            );
        });
    }

    /// Records a failed attempt, retaining the `notAfter` already there.
    ///
    /// The leaf is still valid until that `notAfter`, and the whole
    /// point of recording the failure while it is is that the window
    /// between the two is the only interval in which anything can be
    /// repaired quietly.
    ///
    /// A leaf with no entry gets none here: the entry's whole content is
    /// a lifetime a failure retains, and a failed attempt has no
    /// lifetime to put in one.
    pub(crate) fn record_failure(&self, leaf: SurfaceLeaf, reason: &str, at: OffsetDateTime) {
        self.with(|entries| {
            if let Some(entry) = entries.get_mut(&leaf) {
                entry.attempt = RenewalAttempt::Failed {
                    reason: reason.to_string(),
                };
                entry.attempted_at = Some(at);
            }
        });
    }

    /// Returns one leaf's state, or `None` where the endpoint is
    /// disabled and no entry was ever made.
    ///
    /// The read side of the accessor. Its consumer — the reporting
    /// sibling that publishes these three values in the endpoint health
    /// container — is a separate issue, so nothing outside a test reads
    /// it yet. It exists now because the accessor is the whole interface
    /// between the two, and a reader that had to re-derive a lifetime
    /// from disk is exactly what that seam forbids.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn leaf(&self, leaf: SurfaceLeaf) -> Option<LeafRenewalState> {
        self.with(|entries| entries.get(&leaf).cloned())
    }

    /// How many leaves have entries. Two on an enabled endpoint, zero
    /// on a disabled one.
    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.with(|entries| entries.len())
    }

    /// Runs `body` under the lock.
    ///
    /// A poisoned lock recovers the guard rather than panicking: a panic
    /// elsewhere must not make the daemon's certificate state
    /// unreadable, and every value behind the lock is replaced wholesale.
    fn with<T>(&self, body: impl FnOnce(&mut BTreeMap<SurfaceLeaf, LeafRenewalState>) -> T) -> T {
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        body(&mut guard)
    }
}

impl std::fmt::Debug for RegistrarCertRenewalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrarCertRenewalState")
            .field("leaves", &self.len())
            .finish()
    }
}

// ---------------------------------------------------------------------
// Candidate validation
// ---------------------------------------------------------------------

/// Why a freshly issued candidate is not publishable.
///
/// Every variant is a refusal that changes nothing: the candidate is
/// discarded, the live pair, the live bundle, the active configuration
/// and the pin file are all left exactly as they were, and the accessor
/// records the reason against a retained `notAfter`.
#[derive(Debug, thiserror::Error)]
pub(crate) enum CandidateRejection {
    /// The issued certificate or key does not parse, or the key is of a
    /// type this build cannot sign with.
    #[error("the issued candidate does not parse as a certificate and a usable private key")]
    Malformed,
    /// The fresh key is not the candidate leaf's.
    #[error("the issued candidate's private key is not the key of the leaf beside it")]
    KeyMismatched,
    /// The candidate does not carry exactly one DNS SAN equal to the
    /// reserved name this pair runs under.
    #[error(
        "the issued candidate's subject alternative name is {found:?} rather than the reserved \
         name {expected}"
    )]
    SanMismatched {
        /// The name the plan composed for this pair.
        expected: String,
        /// What the candidate carried, when it carried one DNS SAN.
        found: Option<String>,
    },
    /// The SAN is the reserved name but does not recognise as the
    /// registrar identity it has to be in the configured domain.
    #[error("the issued candidate's subject alternative name is not recognised: {source}")]
    Unrecognised {
        /// Which rule the name broke.
        #[source]
        source: crate::registrar::RegistrarIdentityError,
    },
    /// The endpoint pin file could not be read or parsed, so no server
    /// candidate can be judged safe for a pinned caller.
    #[error("the endpoint pin file could not be read: {source}")]
    PinFileUnusable {
        /// What the pin loader reported.
        #[source]
        source: EndpointPinError,
    },
    /// The server candidate does not chain to any anchor the pin file
    /// already names, so every pinned caller would refuse it.
    #[error(
        "the issued server candidate does not chain to an anchor in the endpoint pin file at \
         {}: {source}",
        .pin_file.display()
    )]
    Unpinned {
        /// The pin file the anchor set came from. It is never rewritten.
        pin_file: PathBuf,
        /// The rejection a pinned caller's own verifier produced.
        #[source]
        source: EndpointVerifyRejection,
    },
}

/// Holds a candidate to every rule that decides whether it may replace
/// live material.
///
/// Runs before any live write, over bytes alone. `pin_file` is consulted
/// for a server candidate and only to read it: the anchor set it names
/// is the deployment's, and a renewal that could add its own leaf to it
/// would be pinning itself.
pub(crate) fn validate_candidate(
    leaf: SurfaceLeaf,
    cert_pem: &[u8],
    key_pem: &[u8],
    expected_name: &str,
    domain: &str,
    pin_file: &Path,
) -> Result<(), CandidateRejection> {
    tls::install_crypto_provider();

    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CandidateRejection::Malformed)?;
    let candidate = chain.first().ok_or(CandidateRejection::Malformed)?;

    // The key is key material, so nothing below quotes a byte of it.
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem))
        .ok()
        .flatten()
        .ok_or(CandidateRejection::Malformed)?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|_| CandidateRejection::Malformed)?;
    if !tls::cert_key_matches(candidate, signing_key.as_ref()) {
        return Err(CandidateRejection::KeyMismatched);
    }

    let san = single_dns_san(candidate.as_ref()).ok();
    let expected = expected_name.to_ascii_lowercase();
    if san.as_deref() != Some(expected.as_str()) {
        return Err(CandidateRejection::SanMismatched {
            expected,
            found: san,
        });
    }
    let name = expected;

    match leaf {
        // The client leaf keeps the identity the registrar already
        // authenticates as. The name equality above proves the three
        // labels are unchanged; this proves they are still the labels
        // the rule admits, in the configured domain.
        SurfaceLeaf::RegistrarClient => {
            recognize_registrar_client_name(&name, domain)
                .map_err(|source| CandidateRejection::Unrecognised { source })?;
        }
        SurfaceLeaf::EndpointServer => {
            recognize_registrar_endpoint_name(&name, domain)
                .map_err(|source| CandidateRejection::Unrecognised { source })?;
            // The pinned caller's own rule, run against the replacement
            // before it is published. A server leaf under an anchor the
            // pin file does not name is one every correctly pinned
            // caller would refuse, and publishing it would take the
            // endpoint off the air with no local symptom.
            let pins = endpoint_pin::load_anchor_pins(pin_file)
                .map_err(|source| CandidateRejection::PinFileUnusable { source })?;
            let verifier = RegistrarEndpointVerifier::new(pins.into_iter().collect(), &name)
                .map_err(|source| CandidateRejection::PinFileUnusable { source })?;
            verifier
                .verify(
                    candidate,
                    chain.get(1..).unwrap_or_default(),
                    UnixTime::now(),
                )
                .map_err(|source| CandidateRejection::Unpinned {
                    pin_file: pin_file.to_path_buf(),
                    source,
                })?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Private artifacts, and the restore snapshots
// ---------------------------------------------------------------------

/// The private working directory one attempt creates and removes.
///
/// Everything an attempt writes outside the live paths lives here: the
/// candidate certificate and key, and the snapshot of each live file the
/// publication may replace. The directory is `0700` and is removed on
/// every exit — issuance failure, validation refusal, publication
/// failure, rollback failure and TLS-swap alike — by
/// [`Artifacts::close`] on the ordinary paths and by `TempDir`'s own
/// `Drop` on an unwind.
struct Artifacts {
    dir: tempfile::TempDir,
}

impl Artifacts {
    /// Creates the directory beside `neighbour`, which is a live path
    /// this attempt will write, so the artifacts share its filesystem
    /// and its access control.
    fn create(neighbour: &Path) -> Result<Self> {
        let parent = neighbour.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "{} has no parent directory to stage renewal artifacts in",
                neighbour.display()
            )
        })?;
        let dir = tempfile::Builder::new()
            .prefix(ARTIFACT_DIR_PREFIX)
            .tempdir_in(parent)
            .with_context(|| {
                format!(
                    "creating the private renewal working directory below {}",
                    parent.display()
                )
            })?;
        Ok(Self { dir })
    }

    /// Writes one artifact with the mode the finished file it stands for
    /// requires, and returns its path.
    ///
    /// The mode is established as the file is created rather than
    /// afterwards: a candidate key that is world-readable for the width
    /// of one `set_permissions` is a key that leaked.
    fn write(&self, name: &str, contents: &[u8], mode: u32) -> Result<PathBuf> {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt as _;

        let path = self.dir.path().join(name);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .with_context(|| format!("creating the renewal artifact at {}", path.display()))?;
        file.write_all(contents)
            .with_context(|| format!("writing the renewal artifact at {}", path.display()))?;
        Ok(path)
    }

    /// Removes the directory and everything in it, reporting a failure
    /// rather than swallowing it.
    fn close(self) -> Result<()> {
        self.dir
            .close()
            .context("removing the private renewal working directory")
    }
}

/// One live path's prior state, captured before the first live write.
///
/// The bytes are held in a private artifact rather than in memory, the
/// mode and the ownership beside it, so a restore puts back exactly what
/// was there and not merely something with the same contents. An absent
/// path is captured as absent, and restoring one removes whatever the
/// publication put there.
pub(crate) struct Snapshot {
    /// The live path this snapshot restores.
    path: PathBuf,
    /// The file that was there, or `None` when the path was absent.
    prior: Option<PriorFile>,
}

/// What was at a live path, and how it was owned.
struct PriorFile {
    /// The private copy of the bytes.
    artifact: PathBuf,
    /// The mode the file carried.
    mode: u32,
    /// The uid that owned it.
    uid: u32,
    /// The gid that owned it.
    gid: u32,
}

impl Snapshot {
    /// Captures `path` into `artifacts` under the artifact basename
    /// `name`.
    ///
    /// # Errors
    ///
    /// Returns an error when the file exists and cannot be read or
    /// stat'ed, or when the artifact cannot be written. Reaching one of
    /// those before the first live write is what keeps a publication
    /// from starting without a way back.
    fn capture(path: &Path, name: &str, artifacts: &Artifacts) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self {
                    path: path.to_path_buf(),
                    prior: None,
                });
            }
            Err(err) => {
                return Err(anyhow::Error::new(err).context(format!(
                    "reading {} to capture a rollback snapshot",
                    path.display()
                )));
            }
        };
        let metadata = std::fs::metadata(path).with_context(|| {
            format!(
                "reading the mode and ownership of {} to capture a rollback snapshot",
                path.display()
            )
        })?;
        let mode = metadata.mode() & 0o7777;
        // The snapshot is private whatever the file it copies is: it
        // sits in a `0700` directory a rollback reads and nothing else,
        // and a copy of a key at any wider mode is a second key file.
        let artifact = artifacts.write(name, &bytes, KEY_FILE_MODE_DEFAULT)?;
        Ok(Self {
            path: path.to_path_buf(),
            prior: Some(PriorFile {
                artifact,
                mode,
                uid: metadata.uid(),
                gid: metadata.gid(),
            }),
        })
    }

    /// The live path this snapshot restores.
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

// ---------------------------------------------------------------------
// The live writes, behind a seam a test can fail
// ---------------------------------------------------------------------

/// One live write in flight.
type LiveWrite<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// The three live writes a publication performs.
///
/// A trait rather than three direct calls so a test can fail exactly one
/// of them — the bundle write, the pair write, or the rollback — and
/// assert what the daemon does about it, without corrupting a
/// filesystem to get there.
pub(crate) trait LivePaths: Send + Sync {
    /// Replaces the merged CA bundle atomically.
    fn write_bundle<'a>(&'a self, path: &'a Path, contents: &'a str) -> LiveWrite<'a>;

    /// Writes the certificate and then the key, through the established
    /// two-rename contract.
    fn write_pair<'a>(
        &'a self,
        cert_path: &'a Path,
        key_path: &'a Path,
        cert_pem: &'a str,
        key_pem: &'a str,
    ) -> LiveWrite<'a>;

    /// Puts one captured snapshot back: its bytes, its mode and its
    /// ownership, or its absence.
    fn restore<'a>(&'a self, snapshot: &'a Snapshot) -> LiveWrite<'a>;
}

/// The production writer: the crate's existing publication paths and
/// nothing else.
pub(crate) struct FilesystemPaths {
    policy: CertGroupPolicy,
}

impl FilesystemPaths {
    /// The policy both surface leaves are issued under: root-owned
    /// material with no cert group, exactly as start-time issuance
    /// publishes them.
    pub(crate) fn new() -> Self {
        Self {
            policy: CertGroupPolicy::none(),
        }
    }
}

impl LivePaths for FilesystemPaths {
    fn write_bundle<'a>(&'a self, path: &'a Path, contents: &'a str) -> LiveWrite<'a> {
        Box::pin(async move { fs_util::write_ca_bundle(path, contents, self.policy).await })
    }

    fn write_pair<'a>(
        &'a self,
        cert_path: &'a Path,
        key_path: &'a Path,
        cert_pem: &'a str,
        key_pem: &'a str,
    ) -> LiveWrite<'a> {
        Box::pin(async move {
            fs_util::write_cert_and_key(cert_path, key_path, cert_pem, key_pem, self.policy).await
        })
    }

    fn restore<'a>(&'a self, snapshot: &'a Snapshot) -> LiveWrite<'a> {
        Box::pin(async move {
            let Some(prior) = snapshot.prior.as_ref() else {
                // The path was absent when the snapshot was taken, so
                // restoring it means removing whatever the publication
                // put there. An already-absent path is the state asked
                // for and not a failure.
                match tokio::fs::remove_file(&snapshot.path).await {
                    Ok(()) => return Ok(()),
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
                    Err(err) => {
                        return Err(anyhow::Error::new(err).context(format!(
                            "removing {} to restore the absence a snapshot captured",
                            snapshot.path.display()
                        )));
                    }
                }
            };
            let bytes = tokio::fs::read(&prior.artifact).await.with_context(|| {
                format!(
                    "reading the rollback snapshot of {}",
                    snapshot.path.display()
                )
            })?;
            fs_util::atomic_write_fixed_owner(
                Destination::bootroot_owned(&snapshot.path),
                &bytes,
                StagedMode::Policy(prior.mode),
                FixedOwner::restored(prior.uid, prior.gid),
            )
            .await
            .with_context(|| format!("restoring {} from its snapshot", snapshot.path.display()))
        })
    }
}

// ---------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------

/// The cadence and the retry budget one adapter runs under.
///
/// Every value comes from the rendered internal agent configuration's
/// sole profile. There is no second scheduler, no lead-time constant of
/// this module's own and no second retry policy.
#[derive(Debug, Clone)]
pub(crate) struct RenewalCadence {
    /// How long between passes, before jitter.
    pub(crate) check_interval: Duration,
    /// How much either side of that interval a pass may fall.
    pub(crate) check_jitter: Duration,
    /// How far ahead of `notAfter` a leaf becomes due.
    pub(crate) renew_before: Duration,
    /// The issuance backoff, in seconds per retry.
    pub(crate) retry_backoff: Vec<u64>,
}

impl RenewalCadence {
    /// Reads the cadence off the rendered internal agent config.
    ///
    /// # Errors
    ///
    /// Returns an error when that config is absent, unparseable or
    /// fails the loader's invariants, or when it carries no profile.
    pub(crate) fn from_internal_config(secrets_dir: &Path) -> Result<Self> {
        let paths = InternalPaths::new(secrets_dir);
        let internal = load_internal_config(&paths).with_context(|| {
            format!(
                "reading the registrar renewal cadence from the rendered internal agent config \
                 at {}",
                paths.agent_config().display()
            )
        })?;
        let profile = internal.profiles.first().ok_or_else(|| {
            anyhow::anyhow!(
                "the rendered internal agent config at {} carries no profile to take the \
                 renewal cadence from",
                paths.agent_config().display()
            )
        })?;
        Ok(Self {
            check_interval: profile.daemon.check_interval,
            check_jitter: profile.daemon.check_jitter,
            renew_before: profile.daemon.renew_before,
            retry_backoff: internal.retry.backoff_secs.clone(),
        })
    }
}

/// The daemon-owned adapter that keeps both registrar leaves valid.
///
/// One per daemon invocation, and only where the endpoint is enabled.
pub(crate) struct RegistrarCertRenewal {
    settings: Arc<Settings>,
    plan: SurfacePlan,
    endpoint: Arc<ActivatedEndpoint>,
    state: RegistrarCertRenewalState,
    cadence: RenewalCadence,
    insecure_mode: bool,
    live: Box<dyn LivePaths>,
}

impl RegistrarCertRenewal {
    /// Resolves the plan, reads the cadence and initializes the
    /// accessor from the certificates already on disk.
    ///
    /// Initialization is not an attempt: it reads each enabled leaf's
    /// valid certificate, records its `notAfter` against
    /// [`RenewalAttempt::NeverAttempted`] with no timestamp, and
    /// contacts neither `OpenBao` nor the CA. A leaf whose certificate
    /// cannot be read or parsed gets no entry and is left to the first
    /// pass, which finds it due and issues a replacement — start-time
    /// issuance has already ensured usable material, so reaching that is
    /// a file that changed underneath the daemon.
    ///
    /// # Errors
    ///
    /// Returns an error when the deployment state file, the rendered
    /// internal agent config or the configured material paths cannot be
    /// resolved.
    pub(crate) async fn prepare(
        settings: Arc<Settings>,
        endpoint: Arc<ActivatedEndpoint>,
        insecure_mode: bool,
    ) -> Result<Self> {
        let plan = resolve_surface_plan(&settings)
            .context("resolving the registrar surface renewal plan")?;
        let cadence = RenewalCadence::from_internal_config(&plan.secrets_dir)?;
        Ok(Self::assemble(settings, plan, endpoint, cadence, insecure_mode).await)
    }

    /// Initializes the accessor and assembles the adapter around an
    /// already-resolved plan and cadence.
    ///
    /// Split from [`RegistrarCertRenewal::prepare`] so a test drives the
    /// production initialization, pass and publication paths over a plan
    /// it wrote under `tempfile::tempdir()`, without a deployment state
    /// file to resolve them from.
    async fn assemble(
        settings: Arc<Settings>,
        plan: SurfacePlan,
        endpoint: Arc<ActivatedEndpoint>,
        cadence: RenewalCadence,
        insecure_mode: bool,
    ) -> Self {
        let state = RegistrarCertRenewalState::default();
        for pair in &plan.pairs {
            match observed_not_after(&pair.cert_path).await {
                Ok(not_after) => state.initialize(pair.leaf, not_after),
                Err(err) => warn!(
                    "Registrar renewal could not read {} at {} to record its lifetime ({err:#}); \
                     the first pass will treat it as due.",
                    pair.leaf.label(),
                    pair.cert_path.display()
                ),
            }
        }
        Self {
            settings,
            plan,
            endpoint,
            state,
            cadence,
            insecure_mode,
            live: Box::new(FilesystemPaths::new()),
        }
    }

    /// The assembly step alone, for a test that has its own plan.
    #[cfg(test)]
    pub(crate) async fn for_test(
        settings: Arc<Settings>,
        plan: SurfacePlan,
        endpoint: Arc<ActivatedEndpoint>,
        cadence: RenewalCadence,
    ) -> Self {
        Self::assemble(settings, plan, endpoint, cadence, false).await
    }

    /// Returns the accessor this adapter writes.
    ///
    /// Handed to the reporting sibling when it lands; until then only a
    /// test reads it, for the same reason [`RegistrarCertRenewalState::leaf`]
    /// records.
    #[allow(dead_code)]
    pub(crate) fn state(&self) -> RegistrarCertRenewalState {
        self.state.clone()
    }

    /// Replaces the live-write seam, so a test can fail one of the three
    /// writes a publication performs.
    #[cfg(test)]
    pub(crate) fn with_live_paths(mut self, live: Box<dyn LivePaths>) -> Self {
        self.live = live;
        self
    }

    /// Runs an immediate first pass, then one per jittered interval,
    /// until the daemon's shutdown signal arrives.
    ///
    /// The same shape the per-profile loop has, over the same cadence
    /// values, so there is one scheduling idiom in the daemon and not
    /// two. A pass never ends the loop: an issuance that failed, a
    /// candidate that was refused and a publication that was rolled back
    /// are all recorded and retried on the next tick.
    ///
    /// # Errors
    ///
    /// Reserved for a failure that ends the adapter itself; there is
    /// none today, so this returns `Ok` once shutdown is observed.
    pub(crate) async fn run(self, mut shutdown: watch::Receiver<bool>) -> Result<()> {
        info!(
            "Registrar certificate renewal enabled. check_interval={:?}, renew_before={:?}, \
             check_jitter={:?}",
            self.cadence.check_interval, self.cadence.renew_before, self.cadence.check_jitter
        );
        let mut first_tick = true;
        loop {
            if *shutdown.borrow_and_update() {
                break;
            }
            let delay = if first_tick {
                first_tick = false;
                Duration::from_secs(0)
            } else {
                utils::jittered_delay(self.cadence.check_interval, self.cadence.check_jitter)
            };
            tokio::select! {
                _ = shutdown.changed() => break,
                () = tokio::time::sleep(delay) => self.run_pass().await,
            }
        }
        info!("Shutdown signal received. Exiting registrar certificate renewal.");
        Ok(())
    }

    /// Runs one pass over both leaves.
    ///
    /// Eligibility is decided per leaf and the two are independent: one
    /// being due is never a reason to replace the other. The `OpenBao`
    /// reads that supply the ACME inputs happen only once a leaf is
    /// actually due, so a pass that finds nothing to do makes no
    /// `OpenBao` and no CA request at all.
    pub(crate) async fn run_pass(&self) {
        let mut due = Vec::with_capacity(self.plan.pairs.len());
        for pair in &self.plan.pairs {
            match daemon::should_renew_certificate(
                &pair.cert_path,
                &self.settings.trust,
                self.cadence.renew_before,
            )
            .await
            {
                Ok(true) => due.push(pair.clone()),
                Ok(false) => debug!(
                    "Registrar renewal: {} at {} is still valid.",
                    pair.leaf.label(),
                    pair.cert_path.display()
                ),
                // Not an attempt, so it supplies the accessor with
                // nothing: the certificate could not be read or parsed,
                // which is a fact about this pass rather than about an
                // issuance that was tried and failed. The daemon's own
                // per-profile tick reports its eligibility failures the
                // same way and keeps ticking.
                Err(err) => error!(
                    "Registrar renewal could not decide whether {} at {} is due: {err:#}",
                    pair.leaf.label(),
                    pair.cert_path.display()
                ),
            }
        }
        if due.is_empty() {
            return;
        }

        // Read only now, and once for however many leaves are due. A
        // failure here is an ordinary failed attempt for each of them —
        // including the credential's own refusal inside a trust-rotation
        // window, which the rotation's mandatory tail repairs and this
        // tick neither orders nor works around.
        let inputs = match read_acme_inputs(
            &self.plan.secrets_dir,
            &self.plan.openbao_url,
            &self.plan.kv_mount,
        )
        .await
        {
            Ok(inputs) => inputs,
            Err(err) => {
                let reason = format!("{err:#}");
                for pair in &due {
                    self.record_failure(pair.leaf, &reason);
                }
                return;
            }
        };

        for pair in &due {
            if let Err(err) = self.renew_leaf(pair, &inputs).await {
                self.record_failure(pair.leaf, &format!("{err:#}"));
            }
        }
    }

    /// Issues, validates, stages, publishes and exchanges one leaf.
    ///
    /// Every step that can fail happens before the first live write, and
    /// the one step after the last live write cannot fail.
    async fn renew_leaf(&self, pair: &SurfacePairPaths, inputs: &SurfaceAcmeInputs) -> Result<()> {
        let material = self.issue_with_retry(pair, inputs).await?;
        self.renew_leaf_with_material(pair, material).await
    }

    /// Everything after the issuance: the private working directory, the
    /// validation, the publication transaction, the cleanup and the
    /// state write.
    ///
    /// Split at exactly the point the ACME exchange ends, so a test
    /// drives the whole publication path over material it minted itself
    /// without a CA to reach.
    async fn renew_leaf_with_material(
        &self,
        pair: &SurfacePairPaths,
        material: crate::acme::IssuedMaterial,
    ) -> Result<()> {
        let artifacts = Artifacts::create(&pair.key_path)?;
        let outcome = self.publish_candidate(pair, &material, &artifacts).await;
        // Removed on every exit, whatever the outcome was, and the
        // removal's own failure is reported rather than hidden.
        let cleanup = artifacts.close();
        let outcome = match (outcome, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(err), Ok(())) | (Ok(()), Err(err)) => Err(err),
            (Err(err), Err(cleanup)) => Err(err.context(format!(
                "and the private renewal artifacts could not be removed: {cleanup:#}"
            ))),
        };
        outcome?;

        let not_after = observed_not_after(&pair.cert_path).await?;
        self.state
            .record_success(pair.leaf, not_after, OffsetDateTime::now_utc());
        info!(
            "Registrar renewal replaced {} at {}; the next handshake uses it.",
            pair.leaf.label(),
            pair.cert_path.display()
        );
        Ok(())
    }

    /// Runs the off-live issuance under the internal config's retry
    /// budget.
    ///
    /// The budget is the internal profile's own, not a second policy:
    /// the backoff list is read off its rendered configuration and
    /// driven through the same helper the per-profile loop drives.
    async fn issue_with_retry(
        &self,
        pair: &SurfacePairPaths,
        inputs: &SurfaceAcmeInputs,
    ) -> Result<crate::acme::IssuedMaterial> {
        let produced: Mutex<Option<crate::acme::IssuedMaterial>> = Mutex::new(None);
        utils::retry_with_backoff_and_sleep(
            || async {
                let material = issue_surface_pair_material(
                    &self.settings,
                    pair,
                    &self.plan.host,
                    inputs,
                    self.insecure_mode,
                )
                .await?;
                // The guard is taken and dropped inside this statement;
                // nothing holds it across an `.await`.
                *produced.lock().unwrap_or_else(PoisonError::into_inner) = Some(material);
                Ok(())
            },
            |delay| tokio::time::sleep(delay),
            |attempt, err| {
                error!(
                    "Registrar renewal of {} failed (attempt {attempt}): {err:#}",
                    pair.leaf.label()
                );
            },
            &self.cadence.retry_backoff,
        )
        .await?;
        produced
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "the registrar renewal of {} reported success without producing material",
                    pair.leaf.label()
                )
            })
    }

    /// Validates the candidate, builds the whole replacement, and
    /// publishes it as a recoverable transaction.
    async fn publish_candidate(
        &self,
        pair: &SurfacePairPaths,
        material: &crate::acme::IssuedMaterial,
        artifacts: &Artifacts,
    ) -> Result<()> {
        let pin_file = self.pin_file();
        validate_candidate(
            pair.leaf,
            material.cert_pem.as_bytes(),
            material.key_pem.as_bytes(),
            &pair.name,
            &self.settings.domain,
            &pin_file,
        )?;

        let bundle_path = self
            .settings
            .trust
            .ca_bundle_path
            .as_deref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "trust.ca_bundle_path is unset, so the incoming client verifier has no anchor \
                 set to be rebuilt from and no registrar leaf can be published"
                )
            })?;
        let staged_bundle = self.stage_bundle(bundle_path, &material.chain)?;

        // The candidate on disk, at the modes the finished files
        // require, so the configuration is built from exactly the bytes
        // that will be published.
        let candidate_cert = artifacts.write(
            CANDIDATE_CERT_FILE,
            material.cert_pem.as_bytes(),
            CERT_FILE_MODE,
        )?;
        let candidate_key = artifacts.write(
            CANDIDATE_KEY_FILE,
            material.key_pem.as_bytes(),
            KEY_FILE_MODE_DEFAULT,
        )?;

        // The whole replacement, before any live path changes. When the
        // client leaf is the one being renewed the server pair is the
        // live one, unchanged — but the verifier is still rebuilt,
        // because the staged bundle is what decides who may connect.
        let (server_cert, server_key) = match pair.leaf {
            SurfaceLeaf::EndpointServer => (candidate_cert.clone(), candidate_key.clone()),
            SurfaceLeaf::RegistrarClient => self.live_server_pair()?,
        };
        let (next_config, next_resolver) = build_server_config_from_staged(
            &server_cert,
            &server_key,
            bundle_path,
            staged_bundle.as_bytes(),
            &self.settings.trust.trusted_ca_sha256,
            &self.settings.domain,
        )
        .with_context(|| {
            format!(
                "building the registrar endpoint's next TLS configuration for the renewal of {}",
                pair.leaf.label()
            )
        })?;

        // Only now, with nothing left that can fail before a write.
        let bundle_snapshot = Snapshot::capture(bundle_path, "bundle.snapshot", artifacts)?;
        let cert_snapshot = Snapshot::capture(&pair.cert_path, "cert.snapshot", artifacts)?;
        let key_snapshot = Snapshot::capture(&pair.key_path, "key.snapshot", artifacts)?;

        if let Err(err) = self.live.write_bundle(bundle_path, &staged_bundle).await {
            return Err(self.roll_back(err, &[&bundle_snapshot]).await);
        }
        if let Err(err) = self
            .live
            .write_pair(
                &pair.cert_path,
                &pair.key_path,
                &material.cert_pem,
                &material.key_pem,
            )
            .await
        {
            return Err(self
                .roll_back(err, &[&bundle_snapshot, &cert_snapshot, &key_snapshot])
                .await);
        }

        // Infallible, and last. The replacement was built above, so
        // there is nothing here that can leave the endpoint holding new
        // files behind an old configuration.
        self.endpoint.swap_active_tls(next_config, next_resolver);
        Ok(())
    }

    /// Restores every live path whose publication may have started, and
    /// reports what actually happened.
    ///
    /// A rollback that succeeds says so. A rollback that fails does not
    /// claim the files were restored: both errors travel out together,
    /// the active configuration stays as it was, and a later tick
    /// retries.
    async fn roll_back(
        &self,
        publication: anyhow::Error,
        snapshots: &[&Snapshot],
    ) -> anyhow::Error {
        let mut failures = Vec::new();
        for snapshot in snapshots {
            if let Err(err) = self.live.restore(snapshot).await {
                failures.push(format!("{}: {err:#}", snapshot.path().display()));
            }
        }
        if failures.is_empty() {
            return publication.context(
                "the registrar renewal publication failed and every live path it may have \
                 written was restored from its snapshot",
            );
        }
        publication.context(format!(
            "the registrar renewal publication failed AND the rollback did not restore {}; the \
             live material is in a mixed state and the endpoint is still serving its previous \
             configuration",
            failures.join("; ")
        ))
    }

    /// Computes the bytes the merged bundle would hold, without writing
    /// them.
    ///
    /// The candidate's chain is held to `trust.trusted_ca_sha256` first,
    /// so a chain carrying an unpinned issuer is refused before anything
    /// is staged, and the merge keeps only the existing bundle's pinned
    /// certificates — the same rule the ordinary publication applies,
    /// reached through the same two helpers rather than restated.
    fn stage_bundle(&self, bundle_path: &Path, chain: &[Vec<u8>]) -> Result<String> {
        if chain.is_empty() {
            anyhow::bail!(
                "the issued candidate carried no issuer chain, so {} could not be staged and \
                 the incoming client verifier could not be rebuilt",
                bundle_path.display()
            );
        }
        crate::acme::verify_chain_fingerprints(chain, &self.settings.trust.trusted_ca_sha256)?;
        let existing = match std::fs::read(bundle_path) {
            Ok(bytes) => Some(bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => {
                return Err(anyhow::Error::new(err).context(format!(
                    "refusing to replace the unreadable CA bundle at {}",
                    bundle_path.display()
                )));
            }
        };
        Ok(crate::acme::merge_ca_bundle(
            existing.as_deref(),
            chain,
            &self.settings.trust.trusted_ca_sha256,
        ))
    }

    /// The live server pair, for a pass renewing only the client leaf.
    fn live_server_pair(&self) -> Result<(PathBuf, PathBuf)> {
        self.plan
            .pairs
            .iter()
            .find(|pair| pair.leaf == SurfaceLeaf::EndpointServer)
            .map(|pair| (pair.cert_path.clone(), pair.key_path.clone()))
            .ok_or_else(|| {
                anyhow::anyhow!("the registrar surface plan carries no endpoint server pair")
            })
    }

    /// The endpoint pin file, beside the configured client certificate.
    ///
    /// Read to judge a server candidate and never written.
    fn pin_file(&self) -> PathBuf {
        let client_cert = self
            .plan
            .pairs
            .iter()
            .find(|pair| pair.leaf == SurfaceLeaf::RegistrarClient)
            .map_or_else(PathBuf::new, |pair| pair.cert_path.clone());
        endpoint_pin::anchor_pin_path_for_client_certificate(&client_cert)
    }

    /// Records a failed attempt and says so in the log.
    fn record_failure(&self, leaf: SurfaceLeaf, reason: &str) {
        error!("Registrar renewal of {} failed: {reason}", leaf.label());
        self.state
            .record_failure(leaf, reason, OffsetDateTime::now_utc());
    }
}

/// Reads the `notAfter` of the certificate at `path`.
///
/// # Errors
///
/// Returns an error when the file cannot be read or does not parse as a
/// PEM certificate.
async fn observed_not_after(path: &Path) -> Result<OffsetDateTime> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading {} to observe its lifetime", path.display()))?;
    daemon::parse_cert_not_after(&bytes)
        .with_context(|| format!("parsing the certificate at {}", path.display()))
}

#[cfg(test)]
mod tests;
