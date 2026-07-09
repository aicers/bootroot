//! Remote-bootstrap force-reissue fast-poll loop.
//!
//! When the agent is configured with an `[openbao]` section, this module
//! authenticates to `OpenBao` via `AppRole` and polls the per-service
//! `reissue` KV path. When it observes a version number newer than the
//! one it last acted on, it triggers an immediate ACME renewal for the
//! matching profile and writes `completed_at` / `completed_version` back
//! to the KV payload so the control plane's `rotate force-reissue --wait`
//! can observe end-to-end latency.
//!
//! This lives outside the normal `check_interval` cadence so operator
//! force-reissue requests propagate within tens of seconds rather than
//! waiting up to an hour for the periodic check tick.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::fs;
use tokio::sync::{Mutex, Semaphore, watch};
use tracing::{debug, error, info, warn};

use crate::cert_group::CertGroupPolicy;
use crate::kv_payload::{
    EabPayload, TrustPayload, parse_eab_payload, parse_responder_hmac, parse_secret_id,
    parse_trust_payload,
};
use crate::openbao::{KvReadWithVersion, OpenBaoClient};
use crate::trust_bootstrap::{
    ACME_SECTION, REISSUE_COMPLETED_AT_KEY, REISSUE_COMPLETED_VERSION_KEY,
    REISSUE_REQUESTED_AT_KEY, REISSUE_REQUESTER_KEY, SERVICE_EAB_KV_SUFFIX, SERVICE_KV_BASE,
    SERVICE_REISSUE_KV_SUFFIX, SERVICE_RESPONDER_HMAC_KV_SUFFIX, SERVICE_SECRET_ID_KV_SUFFIX,
    SERVICE_TRUST_KV_SUFFIX, build_responder_hmac_updates, build_trust_updates,
};
use crate::{config, eab, fs_util, toml_util};

/// Minimum retry cadence when the initial `AppRole` login fails, so a
/// transient startup error does not hot-loop against `OpenBao`.
const LOGIN_RETRY_FLOOR: Duration = Duration::from_secs(5);

/// Reports whether a `ReadError` message indicates the client needs a
/// fresh `AppRole` login before the next tick. Centralised here so the
/// heuristic covers every token-related failure mode — both the explicit
/// "token is not set" state produced by the client when no login has
/// succeeded yet, and the server-side auth rejections seen when a token
/// has expired or been revoked mid-run.
fn read_error_requires_relogin(error: &str) -> bool {
    error.contains("permission denied")
        || error.contains("403")
        || error.contains("missing client token")
        || error.contains("token is not set")
}

/// Logs the outcomes of a trust or `secret_id` poll tick, escalating a
/// token-related read failure to a re-login on the next tick (mirroring the
/// reissue poll's handling). `kind` is `"trust"` or `"secret_id"`.
fn log_poll_outcomes(kind: &str, outcomes: &[PollApplyOutcome], needs_relogin: &mut bool) {
    for outcome in outcomes {
        match outcome {
            PollApplyOutcome::NoData { service } => {
                debug!("Service '{service}': no {kind} entry in KV.");
            }
            PollApplyOutcome::UpToDate { service, version } => {
                debug!("Service '{service}': {kind} version {version} already applied.");
            }
            PollApplyOutcome::ReadError { service, error } => {
                warn!("Service '{service}': fast-poll {kind} KV read failed: {error}");
                if read_error_requires_relogin(error) {
                    *needs_relogin = true;
                }
            }
            PollApplyOutcome::Applied { service, version } => {
                info!("Service '{service}': fast-poll applied {kind} update v{version}");
            }
            PollApplyOutcome::ApplyError {
                service,
                version,
                error,
            } => {
                error!("Service '{service}': fast-poll failed to apply {kind} v{version}: {error}");
            }
            PollApplyOutcome::Malformed {
                service,
                version,
                error,
            } => {
                warn!(
                    "Service '{service}': fast-poll {kind} v{version} payload malformed: {error} (skipped)"
                );
            }
        }
    }
}

/// On-disk record of the highest KV version the agent has already acted
/// on, per service, plus any completion writes that succeeded as
/// renewals but failed to be acknowledged back to `OpenBao`. Missing
/// entries in `last_reissue_seen_version` mean "never seen a reissue
/// request".
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub(crate) struct FastPollState {
    #[serde(default)]
    pub(crate) last_reissue_seen_version: BTreeMap<String, u64>,
    /// Completion writes that should be retried on subsequent ticks
    /// because the previous attempt to write `completed_at` back to
    /// `OpenBao` failed even though the renewal itself succeeded. Keyed
    /// by service name so a later tick can resume exactly the version
    /// we already applied. Entries are dropped when a newer reissue
    /// request supersedes them or when the request is removed from KV.
    #[serde(default)]
    pub(crate) pending_completion_writes: BTreeMap<String, PendingCompletion>,
    /// Partial per-profile progress for a fan-out that did not complete
    /// in a single tick. When a service has multiple profiles and one
    /// renewal fails, the profiles that already succeeded are recorded
    /// here so the next tick only retries the failed sibling(s) instead
    /// of forcing another renewal on the profiles that already ran.
    /// Entries are dropped when the KV request is superseded by a newer
    /// version or removed from KV.
    #[serde(default)]
    pub(crate) in_flight_renewals: BTreeMap<String, InFlightRenewal>,
    /// Highest KV version of the per-service `trust` path already applied
    /// to `agent.toml` + the CA bundle. Missing entries mean "never
    /// applied a trust update", so the first sighting applies the current
    /// KV trust to disk (idempotent when it already matches).
    #[serde(default)]
    pub(crate) last_trust_seen_version: BTreeMap<String, u64>,
    /// Highest KV version of the per-service `secret_id` path already
    /// written to the `AppRole` `secret_id` file on disk. Missing entries
    /// mean "never refreshed", so the first sighting writes the current KV
    /// `secret_id` (idempotent when it already matches).
    #[serde(default)]
    pub(crate) last_secret_id_seen_version: BTreeMap<String, u64>,
    /// Highest KV version of the per-service `http_responder_hmac` path
    /// already upserted into `[acme].http_responder_hmac` in `agent.toml`.
    /// Missing entries mean "never refreshed", so the first sighting writes
    /// the current KV HMAC (idempotent when it already matches).
    #[serde(default)]
    pub(crate) last_responder_hmac_seen_version: BTreeMap<String, u64>,
    /// Highest KV version of the per-service `eab` path already applied to the
    /// on-disk `eab.json` + the in-memory `default_eab`. Missing entries mean
    /// "never refreshed", so the first sighting applies the current KV EAB
    /// (idempotent when it already matches).
    #[serde(default)]
    pub(crate) last_eab_seen_version: BTreeMap<String, u64>,
}

/// Partial fan-out progress for a fast-poll-triggered renewal that
/// spans more than one tick. Persisted so a flaky sibling does not
/// trigger repeated forced renewals on the profiles that already
/// succeeded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InFlightRenewal {
    pub(crate) version: u64,
    #[serde(default)]
    pub(crate) completed_profiles: BTreeSet<String>,
}

/// A renewal that succeeded but whose completion write back to
/// `OpenBao` has not yet been acknowledged. Persisted so a transient
/// KV-write failure does not strand `--wait` callers forever.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PendingCompletion {
    pub(crate) version: u64,
    pub(crate) completed_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) requested_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) requester: Option<String>,
}

impl FastPollState {
    /// Loads the state file, returning an empty default when it does not exist.
    pub(crate) async fn load(path: &Path) -> Result<Self> {
        match fs::read_to_string(path).await {
            Ok(body) if body.trim().is_empty() => Ok(Self::default()),
            Ok(body) => serde_json::from_str(&body).with_context(|| {
                format!("Failed to parse fast-poll state file at {}", path.display())
            }),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(err) => Err(anyhow::anyhow!(
                "Failed to read fast-poll state file {}: {err}",
                path.display()
            )),
        }
    }

    /// Persists the state file atomically via a `<path>.tmp` rename.
    pub(crate) async fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).await.with_context(|| {
                format!(
                    "Failed to create parent directory for fast-poll state: {}",
                    parent.display()
                )
            })?;
        }
        let tmp_path: PathBuf = {
            let mut os = path.as_os_str().to_owned();
            os.push(".tmp");
            PathBuf::from(os)
        };
        let body =
            serde_json::to_string_pretty(self).context("Failed to serialize fast-poll state")?;
        fs::write(&tmp_path, body).await.with_context(|| {
            format!(
                "Failed to write fast-poll state tmp file at {}",
                tmp_path.display()
            )
        })?;
        fs::rename(&tmp_path, path).await.with_context(|| {
            format!(
                "Failed to rename {} -> {}",
                tmp_path.display(),
                path.display()
            )
        })?;
        Ok(())
    }
}

/// External dependencies of the fast-poll loop; abstracted so the tick
/// logic can be unit-tested against deterministic fakes without touching
/// `OpenBao` or the real ACME client.
pub(crate) trait FastPollHooks: Send + Sync {
    fn read_kv_version(
        &self,
        kv_mount: &str,
        kv_path: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Option<KvReadWithVersion>>> + Send + '_>>;

    fn write_kv(
        &self,
        kv_mount: &str,
        kv_path: &str,
        data: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    fn trigger_renewal(
        &self,
        profile_label: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Writes the new CA bundle for `service` and upserts the `[trust]`
    /// section (`ca_bundle_path`, `trusted_ca_sha256`) into `agent.toml`.
    /// The daemon's per-attempt config reload consumes the result on the
    /// next renewal.
    fn apply_trust(
        &self,
        service: &str,
        payload: &TrustPayload,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Writes the rotated `AppRole` `secret_id` for `service` to the
    /// on-disk `secret_id` file atomically so the next re-login picks up
    /// the fresh credential.
    fn apply_secret_id(
        &self,
        service: &str,
        secret_id: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Upserts the rotated HTTP-01 responder HMAC for `service` into
    /// `[acme].http_responder_hmac` in `agent.toml` atomically. The
    /// daemon's per-attempt config reload consumes the result on the next
    /// renewal.
    fn apply_responder_hmac(
        &self,
        service: &str,
        hmac: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;

    /// Applies a rotated or cleared EAB for `service`: writes (populated) or
    /// removes (clear) the on-disk `eab.json` and updates the in-memory
    /// `default_eab` so the next renewal binds with the new EAB, or without
    /// one. Durable-first: the on-disk write precedes the in-memory update so
    /// a restart reloads a value consistent with the running process.
    fn apply_eab(
        &self,
        service: &str,
        payload: &EabPayload,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>>;
}

/// Decides whether an observed KV read should trigger a renewal, and
/// extracts the relevant bits (request timestamp, new version) from the
/// payload. Pure logic, so it is unit-testable without any IO.
///
/// A KV v2 path at `<SERVICE_KV_BASE>/<service>/<SERVICE_REISSUE_KV_SUFFIX>`
/// alternates between two payload shapes: the operator's request
/// (`requested_at` / `requester`) and the agent's completion ack
/// (`completed_at` / `completed_version`). Both are writes, and every
/// write advances the KV metadata version, so keying purely off
/// `observed.version > last_seen_version` would mistake the agent's
/// own ack for a new request and fire a spurious renewal on every tick.
/// A payload carrying `completed_version` is therefore treated as an
/// already-serviced request, not a new one.
#[must_use]
pub(crate) fn evaluate_observation(
    observed: &KvReadWithVersion,
    last_seen_version: Option<u64>,
) -> Option<ReissueObservation> {
    let completed_version = observed
        .data
        .as_object()
        .and_then(|obj| obj.get(REISSUE_COMPLETED_VERSION_KEY))
        .and_then(serde_json::Value::as_u64);
    if completed_version.is_some() {
        return None;
    }
    if last_seen_version.is_some_and(|seen| observed.version <= seen) {
        return None;
    }
    let requested_at = observed
        .data
        .as_object()
        .and_then(|obj| obj.get(REISSUE_REQUESTED_AT_KEY))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let requester = observed
        .data
        .as_object()
        .and_then(|obj| obj.get(REISSUE_REQUESTER_KEY))
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    Some(ReissueObservation {
        version: observed.version,
        requested_at,
        requester,
    })
}

/// Parsed observation produced by [`evaluate_observation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReissueObservation {
    pub(crate) version: u64,
    pub(crate) requested_at: Option<String>,
    pub(crate) requester: Option<String>,
}

/// Builds the completed-payload sent back to `OpenBao` after the agent
/// finishes a triggered renewal successfully.
#[must_use]
pub(crate) fn build_completed_payload(
    observation: &ReissueObservation,
    completed_at: &str,
) -> serde_json::Value {
    let mut payload = serde_json::Map::new();
    if let Some(requested_at) = &observation.requested_at {
        payload.insert(
            REISSUE_REQUESTED_AT_KEY.to_string(),
            serde_json::Value::String(requested_at.clone()),
        );
    }
    if let Some(requester) = &observation.requester {
        payload.insert(
            REISSUE_REQUESTER_KEY.to_string(),
            serde_json::Value::String(requester.clone()),
        );
    }
    payload.insert(
        REISSUE_COMPLETED_AT_KEY.to_string(),
        serde_json::Value::String(completed_at.to_string()),
    );
    payload.insert(
        REISSUE_COMPLETED_VERSION_KEY.to_string(),
        serde_json::Value::Number(observation.version.into()),
    );
    serde_json::Value::Object(payload)
}

/// Builds the KV path `<SERVICE_KV_BASE>/<service>/<SERVICE_REISSUE_KV_SUFFIX>`.
#[must_use]
pub(crate) fn reissue_kv_path(service_name: &str) -> String {
    format!("{SERVICE_KV_BASE}/{service_name}/{SERVICE_REISSUE_KV_SUFFIX}")
}

/// Builds the KV path `<SERVICE_KV_BASE>/<service>/<SERVICE_TRUST_KV_SUFFIX>`.
#[must_use]
pub(crate) fn trust_kv_path(service_name: &str) -> String {
    format!("{SERVICE_KV_BASE}/{service_name}/{SERVICE_TRUST_KV_SUFFIX}")
}

/// Builds the KV path `<SERVICE_KV_BASE>/<service>/<SERVICE_SECRET_ID_KV_SUFFIX>`.
#[must_use]
pub(crate) fn secret_id_kv_path(service_name: &str) -> String {
    format!("{SERVICE_KV_BASE}/{service_name}/{SERVICE_SECRET_ID_KV_SUFFIX}")
}

/// Builds the KV path `<SERVICE_KV_BASE>/<service>/<SERVICE_RESPONDER_HMAC_KV_SUFFIX>`.
#[must_use]
pub(crate) fn responder_hmac_kv_path(service_name: &str) -> String {
    format!("{SERVICE_KV_BASE}/{service_name}/{SERVICE_RESPONDER_HMAC_KV_SUFFIX}")
}

/// Builds the KV path `<SERVICE_KV_BASE>/<service>/<SERVICE_EAB_KV_SUFFIX>`.
#[must_use]
pub(crate) fn eab_kv_path(service_name: &str) -> String {
    format!("{SERVICE_KV_BASE}/{service_name}/{SERVICE_EAB_KV_SUFFIX}")
}

/// Reports whether an observed KV version is newer than the last one the
/// agent acted on. Unlike the reissue path, the `trust` and `secret_id`
/// paths are only ever written by the control plane (the agent never
/// writes back), so a plain `observed > last_seen` gate is exact — there
/// is no self-ack version to skip. A missing `last_seen` fires on first
/// sighting, applying the current KV value to disk (idempotent).
#[must_use]
fn version_advanced(observed_version: u64, last_seen: Option<u64>) -> bool {
    last_seen.is_none_or(|seen| observed_version > seen)
}

/// Outcome of a single per-service trust or `secret_id` poll probe. Shared
/// by both polls since their version-gated apply lifecycle is identical;
/// the loop tags each with its poll kind when logging.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PollApplyOutcome {
    /// The KV path holds no entry for this service (404).
    NoData { service: String },
    /// The observed version was already applied — nothing to do.
    UpToDate { service: String, version: u64 },
    /// The KV read failed; may indicate the token needs re-login.
    ReadError { service: String, error: String },
    /// A new version was applied to disk successfully.
    Applied { service: String, version: u64 },
    /// A new version was observed but applying it to disk failed.
    ApplyError {
        service: String,
        version: u64,
        error: String,
    },
    /// A new version was observed but its payload failed validation. The
    /// version is not advanced, so a corrected control-plane write (a
    /// newer version) is retried.
    Malformed {
        service: String,
        version: u64,
        error: String,
    },
}

/// Runs a single trust poll tick: for each unique service, reads the
/// per-service `trust` KV path, and on a newer version writes the CA
/// bundle + upserts the `agent.toml` `[trust]` section via the hook.
/// Version-gated and idempotent in steady state.
pub(crate) async fn run_trust_poll_tick<H: FastPollHooks + ?Sized>(
    hooks: &H,
    kv_mount: &str,
    services: &[(String, Vec<String>)],
    state: &mut FastPollState,
) -> (Vec<PollApplyOutcome>, bool) {
    let mut outcomes = Vec::with_capacity(services.len());
    let mut state_changed = false;

    for (service_name, _profiles) in services {
        let kv_path = trust_kv_path(service_name);
        let read = match hooks.read_kv_version(kv_mount, &kv_path).await {
            Ok(Some(read)) => read,
            Ok(None) => {
                outcomes.push(PollApplyOutcome::NoData {
                    service: service_name.clone(),
                });
                continue;
            }
            Err(err) => {
                outcomes.push(PollApplyOutcome::ReadError {
                    service: service_name.clone(),
                    error: format!("{err:#}"),
                });
                continue;
            }
        };

        let last_seen = state.last_trust_seen_version.get(service_name).copied();
        if !version_advanced(read.version, last_seen) {
            outcomes.push(PollApplyOutcome::UpToDate {
                service: service_name.clone(),
                version: read.version,
            });
            continue;
        }

        let payload = match parse_trust_payload(&read.data) {
            Ok(payload) => payload,
            Err(err) => {
                outcomes.push(PollApplyOutcome::Malformed {
                    service: service_name.clone(),
                    version: read.version,
                    error: format!("{err:#}"),
                });
                continue;
            }
        };

        match hooks.apply_trust(service_name, &payload).await {
            Ok(()) => {
                state
                    .last_trust_seen_version
                    .insert(service_name.clone(), read.version);
                state_changed = true;
                outcomes.push(PollApplyOutcome::Applied {
                    service: service_name.clone(),
                    version: read.version,
                });
            }
            Err(err) => {
                outcomes.push(PollApplyOutcome::ApplyError {
                    service: service_name.clone(),
                    version: read.version,
                    error: format!("{err:#}"),
                });
            }
        }
    }

    (outcomes, state_changed)
}

/// Runs a single `secret_id` poll tick: for each unique service, reads the
/// per-service `secret_id` KV path, and on a newer version writes the
/// rotated credential to the on-disk `secret_id` file via the hook so the
/// next `AppRole` re-login uses it. Version-gated and idempotent.
pub(crate) async fn run_secret_id_poll_tick<H: FastPollHooks + ?Sized>(
    hooks: &H,
    kv_mount: &str,
    services: &[(String, Vec<String>)],
    state: &mut FastPollState,
) -> (Vec<PollApplyOutcome>, bool) {
    let mut outcomes = Vec::with_capacity(services.len());
    let mut state_changed = false;

    for (service_name, _profiles) in services {
        let kv_path = secret_id_kv_path(service_name);
        let read = match hooks.read_kv_version(kv_mount, &kv_path).await {
            Ok(Some(read)) => read,
            Ok(None) => {
                outcomes.push(PollApplyOutcome::NoData {
                    service: service_name.clone(),
                });
                continue;
            }
            Err(err) => {
                outcomes.push(PollApplyOutcome::ReadError {
                    service: service_name.clone(),
                    error: format!("{err:#}"),
                });
                continue;
            }
        };

        let last_seen = state.last_secret_id_seen_version.get(service_name).copied();
        if !version_advanced(read.version, last_seen) {
            outcomes.push(PollApplyOutcome::UpToDate {
                service: service_name.clone(),
                version: read.version,
            });
            continue;
        }

        let secret_id = match parse_secret_id(&read.data) {
            Ok(secret_id) => secret_id,
            Err(err) => {
                outcomes.push(PollApplyOutcome::Malformed {
                    service: service_name.clone(),
                    version: read.version,
                    error: format!("{err:#}"),
                });
                continue;
            }
        };

        match hooks.apply_secret_id(service_name, &secret_id).await {
            Ok(()) => {
                state
                    .last_secret_id_seen_version
                    .insert(service_name.clone(), read.version);
                state_changed = true;
                outcomes.push(PollApplyOutcome::Applied {
                    service: service_name.clone(),
                    version: read.version,
                });
            }
            Err(err) => {
                outcomes.push(PollApplyOutcome::ApplyError {
                    service: service_name.clone(),
                    version: read.version,
                    error: format!("{err:#}"),
                });
            }
        }
    }

    (outcomes, state_changed)
}

/// Runs a single `http_responder_hmac` poll tick: for each unique service,
/// reads the per-service `http_responder_hmac` KV path, and on a newer
/// version upserts `[acme].http_responder_hmac` into the running `agent.toml`
/// via the hook so the next ACME renewal authenticates to the responder with
/// the fresh HMAC. Version-gated and idempotent.
pub(crate) async fn run_responder_hmac_poll_tick<H: FastPollHooks + ?Sized>(
    hooks: &H,
    kv_mount: &str,
    services: &[(String, Vec<String>)],
    state: &mut FastPollState,
) -> (Vec<PollApplyOutcome>, bool) {
    let mut outcomes = Vec::with_capacity(services.len());
    let mut state_changed = false;

    for (service_name, _profiles) in services {
        let kv_path = responder_hmac_kv_path(service_name);
        let read = match hooks.read_kv_version(kv_mount, &kv_path).await {
            Ok(Some(read)) => read,
            Ok(None) => {
                outcomes.push(PollApplyOutcome::NoData {
                    service: service_name.clone(),
                });
                continue;
            }
            Err(err) => {
                outcomes.push(PollApplyOutcome::ReadError {
                    service: service_name.clone(),
                    error: format!("{err:#}"),
                });
                continue;
            }
        };

        let last_seen = state
            .last_responder_hmac_seen_version
            .get(service_name)
            .copied();
        if !version_advanced(read.version, last_seen) {
            outcomes.push(PollApplyOutcome::UpToDate {
                service: service_name.clone(),
                version: read.version,
            });
            continue;
        }

        let hmac = match parse_responder_hmac(&read.data) {
            Ok(hmac) => hmac,
            Err(err) => {
                outcomes.push(PollApplyOutcome::Malformed {
                    service: service_name.clone(),
                    version: read.version,
                    error: format!("{err:#}"),
                });
                continue;
            }
        };

        match hooks.apply_responder_hmac(service_name, &hmac).await {
            Ok(()) => {
                state
                    .last_responder_hmac_seen_version
                    .insert(service_name.clone(), read.version);
                state_changed = true;
                outcomes.push(PollApplyOutcome::Applied {
                    service: service_name.clone(),
                    version: read.version,
                });
            }
            Err(err) => {
                outcomes.push(PollApplyOutcome::ApplyError {
                    service: service_name.clone(),
                    version: read.version,
                    error: format!("{err:#}"),
                });
            }
        }
    }

    (outcomes, state_changed)
}

/// Runs a single `eab` poll tick: for each unique service, reads the
/// per-service `eab` KV path, and on a newer version applies it via the hook —
/// writing `eab.json` + refreshing the in-memory `default_eab` for a populated
/// payload, or removing `eab.json` + clearing `default_eab` for the explicit
/// clear shape. Version-gated and idempotent in steady state.
///
/// Only meaningful when EAB is sourced from `--eab-file` (the remote-bootstrap
/// artifact); the caller gates this tick out entirely when the operator pinned
/// EAB via explicit `--eab-*` CLI values.
pub(crate) async fn run_eab_poll_tick<H: FastPollHooks + ?Sized>(
    hooks: &H,
    kv_mount: &str,
    services: &[(String, Vec<String>)],
    state: &mut FastPollState,
) -> (Vec<PollApplyOutcome>, bool) {
    let mut outcomes = Vec::with_capacity(services.len());
    let mut state_changed = false;

    for (service_name, _profiles) in services {
        let kv_path = eab_kv_path(service_name);
        let read = match hooks.read_kv_version(kv_mount, &kv_path).await {
            Ok(Some(read)) => read,
            Ok(None) => {
                outcomes.push(PollApplyOutcome::NoData {
                    service: service_name.clone(),
                });
                continue;
            }
            Err(err) => {
                outcomes.push(PollApplyOutcome::ReadError {
                    service: service_name.clone(),
                    error: format!("{err:#}"),
                });
                continue;
            }
        };

        let last_seen = state.last_eab_seen_version.get(service_name).copied();
        if !version_advanced(read.version, last_seen) {
            outcomes.push(PollApplyOutcome::UpToDate {
                service: service_name.clone(),
                version: read.version,
            });
            continue;
        }

        let payload = match parse_eab_payload(&read.data) {
            Ok(payload) => payload,
            Err(err) => {
                outcomes.push(PollApplyOutcome::Malformed {
                    service: service_name.clone(),
                    version: read.version,
                    error: format!("{err:#}"),
                });
                continue;
            }
        };

        match hooks.apply_eab(service_name, &payload).await {
            Ok(()) => {
                state
                    .last_eab_seen_version
                    .insert(service_name.clone(), read.version);
                state_changed = true;
                outcomes.push(PollApplyOutcome::Applied {
                    service: service_name.clone(),
                    version: read.version,
                });
            }
            Err(err) => {
                outcomes.push(PollApplyOutcome::ApplyError {
                    service: service_name.clone(),
                    version: read.version,
                    error: format!("{err:#}"),
                });
            }
        }
    }

    (outcomes, state_changed)
}

/// Resolves the [`CertGroupPolicy`] backing a service's CA bundle write.
///
/// `cert_group_gid` is a per-profile field but the CA bundle is
/// per-service, so when a service's profiles disagree on the gid there is
/// no single correct owner. The conservative rule is to refuse rather than
/// silently pick one: require every profile of the service to share the
/// same `cert_group_gid`.
///
/// # Errors
///
/// Returns an error when the service's profiles declare more than one
/// distinct `cert_group_gid`.
fn resolve_service_cert_group_policy(
    settings: &config::Settings,
    service: &str,
) -> Result<CertGroupPolicy> {
    let mut gids: BTreeSet<Option<u32>> = BTreeSet::new();
    for profile in &settings.profiles {
        if profile.service_name == service {
            gids.insert(profile.cert_group_gid);
        }
    }
    if gids.len() > 1 {
        anyhow::bail!(
            "Service '{service}' profiles disagree on cert_group_gid; \
             refusing to pick one for the CA bundle"
        );
    }
    Ok(match gids.into_iter().next().flatten() {
        Some(gid) => CertGroupPolicy::with_gid(gid),
        None => CertGroupPolicy::none(),
    })
}

/// Result of a single fast-poll tick: the per-service outcomes plus
/// whether the in-memory `FastPollState` was mutated (so the caller
/// knows it should persist).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FastPollTickReport {
    pub(crate) outcomes: Vec<FastPollTickOutcome>,
    pub(crate) state_changed: bool,
}

/// Runs a single fast-poll tick: reads KV once per unique service,
/// fans renewals out across every profile that shares that service,
/// retries any pending completion write left over from a previous
/// tick, and writes back a completion marker only when every profile
/// has been renewed. Exposed via a trait so the real `OpenBao` client
/// and renewal trigger stay injectable for tests.
// The per-service state machine (read → pending-retry → fan-out →
// completion-write) is short enough on each branch but accumulates
// past clippy's default 100-line cap. Splitting it would obscure the
// single linear lifecycle for reviewers.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run_fast_poll_tick<H: FastPollHooks + ?Sized>(
    hooks: &H,
    kv_mount: &str,
    services: &[(String, Vec<String>)],
    state: &mut FastPollState,
) -> FastPollTickReport {
    let mut outcomes = Vec::with_capacity(services.len());
    let mut state_changed = false;

    for (service_name, profile_labels) in services {
        let kv_path = reissue_kv_path(service_name);
        let observation = match hooks.read_kv_version(kv_mount, &kv_path).await {
            Ok(Some(read)) => read,
            Ok(None) => {
                if state
                    .pending_completion_writes
                    .remove(service_name)
                    .is_some()
                {
                    state_changed = true;
                }
                if state.in_flight_renewals.remove(service_name).is_some() {
                    state_changed = true;
                }
                outcomes.push(FastPollTickOutcome::NoRequest {
                    service: service_name.clone(),
                });
                continue;
            }
            Err(err) => {
                outcomes.push(FastPollTickOutcome::ReadError {
                    service: service_name.clone(),
                    error: format!("{err:#}"),
                });
                continue;
            }
        };

        // Step 1: if a previous tick succeeded the renewal but failed
        // the completion write, retry just the write while the request
        // version in KV still matches what we already applied.
        if let Some(pending) = state.pending_completion_writes.get(service_name).cloned() {
            if observation.version == pending.version {
                let pending_obs = ReissueObservation {
                    version: pending.version,
                    requested_at: pending.requested_at.clone(),
                    requester: pending.requester.clone(),
                };
                let payload = build_completed_payload(&pending_obs, &pending.completed_at);
                match hooks.write_kv(kv_mount, &kv_path, payload).await {
                    Ok(()) => {
                        state.pending_completion_writes.remove(service_name);
                        state_changed = true;
                        outcomes.push(FastPollTickOutcome::CompletedWriteRetried {
                            service: service_name.clone(),
                            version: pending.version,
                            completed_at: pending.completed_at,
                        });
                    }
                    Err(err) => {
                        outcomes.push(FastPollTickOutcome::CompletedWriteError {
                            service: service_name.clone(),
                            version: pending.version,
                            error: format!("{err:#}"),
                        });
                    }
                }
                continue;
            }
            // A newer request superseded the pending one — drop the
            // stale entry. The newer request is processed below and
            // any new write failure will install a fresh pending.
            state.pending_completion_writes.remove(service_name);
            state_changed = true;
        }

        let last_seen = state.last_reissue_seen_version.get(service_name).copied();
        let Some(observed) = evaluate_observation(&observation, last_seen) else {
            // No newer request in KV — but an in-flight fan-out from a
            // previous tick is tied to a specific version, so drop it
            // if it does not match what we just read.
            if let Some(existing) = state.in_flight_renewals.get(service_name)
                && existing.version != observation.version
            {
                state.in_flight_renewals.remove(service_name);
                state_changed = true;
            }
            outcomes.push(FastPollTickOutcome::UpToDate {
                service: service_name.clone(),
                version: observation.version,
            });
            continue;
        };

        // Step 2a: resume any partial fan-out from a previous tick. If
        // the recorded in-flight targets the same version, skip the
        // profiles that already completed; otherwise drop the stale
        // entry and start a fresh fan-out for the new version.
        let mut completed_profiles: BTreeSet<String> = BTreeSet::new();
        if let Some(existing) = state.in_flight_renewals.get(service_name) {
            if existing.version == observed.version {
                completed_profiles = existing.completed_profiles.clone();
            } else {
                state.in_flight_renewals.remove(service_name);
                state_changed = true;
            }
        }

        info!(
            "Service '{}': fast-poll observed reissue version {} (last seen {:?}), fanning out to {} profile(s) ({} already completed)",
            service_name,
            observed.version,
            last_seen,
            profile_labels.len(),
            completed_profiles.len(),
        );

        // Step 2b: fan out to every profile that has not yet succeeded
        // for this version. Only when every profile renews successfully
        // do we mark the version consumed; otherwise we persist the
        // progress so the next tick retries just the failed profiles
        // against the same version instead of forcing another renewal
        // on the siblings that already ran.
        let mut any_failed = false;
        for profile_label in profile_labels {
            if completed_profiles.contains(profile_label) {
                continue;
            }
            match hooks.trigger_renewal(profile_label).await {
                Ok(()) => {
                    completed_profiles.insert(profile_label.clone());
                }
                Err(err) => {
                    any_failed = true;
                    outcomes.push(FastPollTickOutcome::RenewError {
                        service: service_name.clone(),
                        profile: profile_label.clone(),
                        error: format!("{err:#}"),
                    });
                }
            }
        }
        if any_failed {
            // Persist partial progress only when at least one profile
            // has succeeded; otherwise we would churn the state file on
            // every tick of a service whose only profile keeps failing.
            if !completed_profiles.is_empty() {
                state.in_flight_renewals.insert(
                    service_name.clone(),
                    InFlightRenewal {
                        version: observed.version,
                        completed_profiles,
                    },
                );
                state_changed = true;
            }
            continue;
        }

        // Every profile for this version has succeeded — the fan-out
        // is resolved, drop any lingering in-flight record. The
        // success paths below all set `state_changed = true` when they
        // advance `last_reissue_seen_version`, so we do not need to
        // set it here just for this removal.
        state.in_flight_renewals.remove(service_name);

        let completed_at = match OffsetDateTime::now_utc().format(&Rfc3339) {
            Ok(value) => value,
            Err(err) => {
                // Completion write impossible without a timestamp;
                // record the new version anyway so we don't re-trigger
                // renewals next tick. The completion ack will be lost
                // for this version, but a future request will recover.
                state
                    .last_reissue_seen_version
                    .insert(service_name.clone(), observed.version);
                state_changed = true;
                outcomes.push(FastPollTickOutcome::CompletedWriteError {
                    service: service_name.clone(),
                    version: observed.version,
                    error: format!("Failed to format completed_at: {err}"),
                });
                continue;
            }
        };
        let payload = build_completed_payload(&observed, &completed_at);
        let write_result = hooks.write_kv(kv_mount, &kv_path, payload).await;

        // Renewals succeeded — the version is consumed regardless of
        // whether the completion write went through. The pending entry
        // (added on failure) lets the next tick retry just the write.
        state
            .last_reissue_seen_version
            .insert(service_name.clone(), observed.version);
        state_changed = true;
        match write_result {
            Ok(()) => {
                outcomes.push(FastPollTickOutcome::Applied {
                    service: service_name.clone(),
                    version: observed.version,
                    completed_at,
                });
            }
            Err(err) => {
                state.pending_completion_writes.insert(
                    service_name.clone(),
                    PendingCompletion {
                        version: observed.version,
                        completed_at: completed_at.clone(),
                        requested_at: observed.requested_at.clone(),
                        requester: observed.requester.clone(),
                    },
                );
                outcomes.push(FastPollTickOutcome::AppliedPendingWrite {
                    service: service_name.clone(),
                    version: observed.version,
                    completed_at,
                    error: format!("{err:#}"),
                });
            }
        }
    }
    FastPollTickReport {
        outcomes,
        state_changed,
    }
}

/// Combined outcome of [`run_hmac_refresh_then_reissue`]: the
/// responder-HMAC poll results plus the reissue tick report.
pub(crate) struct HmacRefreshReissueOutcome {
    pub(crate) responder_hmac_outcomes: Vec<PollApplyOutcome>,
    pub(crate) responder_hmac_changed: bool,
    pub(crate) report: FastPollTickReport,
}

/// Refreshes the responder HMAC and then runs the reissue tick, in that
/// order.
///
/// The ordering is load-bearing: a force-reissue request visible in the
/// same KV snapshot fans out to a renewal, and the issuance path reloads
/// `agent.toml` on every attempt (`src/daemon.rs`). If the reissue ran
/// first, that renewal would reload a config still carrying the stale
/// `[acme].http_responder_hmac` and authenticate to the responder with
/// the old secret — the exact failure this refresh exists to prevent
/// once the responder has restarted on the new value. Writing the fresh
/// HMAC to disk before triggering the reissue closes that same-tick race.
///
/// Trust and `secret_id` refreshes deliberately stay in the loop body
/// after this call: they gate this loop's own `OpenBao` connection, not the
/// issuance config, so their ordering relative to the reissue tick does
/// not affect renewal authentication.
pub(crate) async fn run_hmac_refresh_then_reissue<H: FastPollHooks + ?Sized>(
    hooks: &H,
    kv_mount: &str,
    services: &[(String, Vec<String>)],
    state: &mut FastPollState,
) -> HmacRefreshReissueOutcome {
    let (responder_hmac_outcomes, responder_hmac_changed) =
        run_responder_hmac_poll_tick(hooks, kv_mount, services, state).await;
    let report = run_fast_poll_tick(hooks, kv_mount, services, state).await;
    HmacRefreshReissueOutcome {
        responder_hmac_outcomes,
        responder_hmac_changed,
        report,
    }
}

/// Outcome of a single per-service fast-poll probe. The daemon logs
/// these and tests assert on them directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FastPollTickOutcome {
    NoRequest {
        service: String,
    },
    UpToDate {
        service: String,
        version: u64,
    },
    ReadError {
        service: String,
        error: String,
    },
    Applied {
        service: String,
        version: u64,
        completed_at: String,
    },
    /// Renewal succeeded but the completion write to KV failed; the
    /// version is consumed and the write is queued for retry on the
    /// next tick via [`FastPollState::pending_completion_writes`].
    AppliedPendingWrite {
        service: String,
        version: u64,
        completed_at: String,
        error: String,
    },
    /// A pending completion write from a prior tick succeeded.
    CompletedWriteRetried {
        service: String,
        version: u64,
        completed_at: String,
    },
    RenewError {
        service: String,
        profile: String,
        error: String,
    },
    /// A completion write — either the original or a retry — failed.
    /// The renewal itself already succeeded.
    CompletedWriteError {
        service: String,
        version: u64,
        error: String,
    },
}

/// The on-disk `eab.json` path plus the sender half of the shared
/// `default_eab` watch channel the remote fast-poll loop uses to persist and
/// publish an EAB refresh.
///
/// Present only when EAB is sourced from `--eab-file` (the remote-bootstrap
/// artifact). When the agent was started with explicit `--eab-*` CLI values
/// the operator has pinned EAB out of band, so the daemon passes `None` and
/// the fast-poll loop never overrides it.
pub(crate) struct EabRefreshHandle {
    /// On-disk `eab.json` path (`--eab-file`) written on a populated refresh
    /// and removed on a clear.
    pub(crate) path: PathBuf,
    /// Publishes the refreshed value into the shared `default_eab` so running
    /// renewals read it without a restart.
    pub(crate) sender: watch::Sender<Option<eab::EabCredentials>>,
}

/// Attaches an [`OpenBaoClient`] + renewal trigger to the generic
/// [`FastPollHooks`] trait so the daemon can drive [`run_fast_poll_tick`]
/// against live infrastructure.
pub(crate) struct LiveFastPollHooks<F> {
    pub(crate) client: Arc<Mutex<OpenBaoClient>>,
    pub(crate) trigger: F,
    /// Settings snapshot used to resolve the `[trust].ca_bundle_path` and
    /// the per-service `cert_group_gid` policy when applying trust.
    pub(crate) settings: Arc<config::Settings>,
    /// Resolved `agent.toml` path rewritten by the trust apply.
    pub(crate) config_path: PathBuf,
    /// Resolved `AppRole` `secret_id` file rewritten by the `secret_id` apply.
    pub(crate) secret_id_path: PathBuf,
    /// EAB refresh target, present only when EAB is sourced from `--eab-file`.
    pub(crate) eab_refresh: Option<EabRefreshHandle>,
}

/// Writes the CA bundle and upserts the `agent.toml` `[trust]` section for a
/// trust update observed on the fast-poll loop.
///
/// The CA bundle goes through [`fs_util::write_ca_bundle`] (`0o644` +
/// cert-group gid policy) so it stays world-readable and cert-group
/// consistent like the renewal-time bundle; the `agent.toml` rewrite goes
/// through [`fs_util::atomic_write`] at `0o600` (the #613-safe writer) so a
/// crash cannot leave the daemon's hot-read config half-written. The
/// `upsert_section_keys` round-trip preserves operator-tuned sections.
async fn apply_trust_to_disk(
    settings: &config::Settings,
    config_path: &Path,
    service: &str,
    payload: &TrustPayload,
) -> Result<()> {
    let ca_bundle_path = settings.trust.ca_bundle_path.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "Cannot apply trust for service '{service}': [trust].ca_bundle_path is not configured"
        )
    })?;
    let policy = resolve_service_cert_group_policy(settings, service)?;
    fs_util::write_ca_bundle(ca_bundle_path, &payload.ca_bundle_pem, policy)
        .await
        .with_context(|| format!("Failed to write CA bundle to {}", ca_bundle_path.display()))?;

    let current = fs::read_to_string(config_path)
        .await
        .with_context(|| format!("Failed to read agent config at {}", config_path.display()))?;
    let trust_updates = build_trust_updates(&payload.trusted_ca_sha256, ca_bundle_path);
    let updated = toml_util::upsert_section_keys(&current, "trust", &trust_updates)
        .context("Failed to upsert [trust] section into agent config")?;
    fs_util::atomic_write(config_path, updated.as_bytes(), fs_util::KEY_FILE_MODE)
        .await
        .with_context(|| format!("Failed to write agent config to {}", config_path.display()))?;
    Ok(())
}

/// Upserts `[acme].http_responder_hmac` in `agent.toml` for a responder-HMAC
/// update observed on the fast-poll loop.
///
/// The rewrite goes through [`fs_util::atomic_write`] at `0o600` (the
/// #613-safe writer) so a crash cannot leave the daemon's hot-read config
/// half-written; the `upsert_section_keys` round-trip preserves
/// operator-tuned sections. The daemon's per-attempt config reload consumes
/// the new HMAC on the next renewal.
async fn apply_responder_hmac_to_disk(config_path: &Path, hmac: &str) -> Result<()> {
    let current = fs::read_to_string(config_path)
        .await
        .with_context(|| format!("Failed to read agent config at {}", config_path.display()))?;
    let hmac_updates = build_responder_hmac_updates(hmac);
    let updated = toml_util::upsert_section_keys(&current, ACME_SECTION, &hmac_updates)
        .context("Failed to upsert [acme] responder HMAC into agent config")?;
    fs_util::atomic_write(config_path, updated.as_bytes(), fs_util::KEY_FILE_MODE)
        .await
        .with_context(|| format!("Failed to write agent config to {}", config_path.display()))?;
    Ok(())
}

/// Applies a rotated or cleared EAB observed on the fast-poll loop.
///
/// Durable-first ordering: the on-disk `eab.json` is written (populated) or
/// removed (clear) *before* the in-memory `default_eab` is updated, so a crash
/// between the two leaves the on-disk state ahead of — never behind — the
/// running process, and the version is only advanced by the caller when this
/// returns `Ok`. The `default_eab` update goes through the shared `watch`
/// sender so both the periodic-check and force-reissue paths read the current
/// value at their next issuance without a restart.
async fn apply_eab_to_state(handle: &EabRefreshHandle, payload: &EabPayload) -> Result<()> {
    match payload {
        EabPayload::Populated { kid, hmac } => {
            eab::write_eab_file(&handle.path, kid, hmac)
                .await
                .with_context(|| {
                    format!("Failed to write eab.json to {}", handle.path.display())
                })?;
            handle.sender.send_replace(Some(eab::EabCredentials {
                kid: kid.clone(),
                hmac: hmac.clone(),
            }));
        }
        EabPayload::Clear => {
            eab::remove_eab_file(&handle.path).await.with_context(|| {
                format!("Failed to remove eab.json at {}", handle.path.display())
            })?;
            handle.sender.send_replace(None);
        }
    }
    Ok(())
}

impl<F, Fut> FastPollHooks for LiveFastPollHooks<F>
where
    F: Fn(String) -> Fut + Send + Sync,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    fn read_kv_version(
        &self,
        kv_mount: &str,
        kv_path: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<Option<KvReadWithVersion>>> + Send + '_>>
    {
        let client = Arc::clone(&self.client);
        let kv_mount = kv_mount.to_string();
        let kv_path = kv_path.to_string();
        Box::pin(async move {
            let guard = client.lock().await;
            guard.try_read_kv_with_version(&kv_mount, &kv_path).await
        })
    }

    fn write_kv(
        &self,
        kv_mount: &str,
        kv_path: &str,
        data: serde_json::Value,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let client = Arc::clone(&self.client);
        let kv_mount = kv_mount.to_string();
        let kv_path = kv_path.to_string();
        Box::pin(async move {
            let guard = client.lock().await;
            guard.write_kv(&kv_mount, &kv_path, data).await
        })
    }

    fn trigger_renewal(
        &self,
        profile_label: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let fut = (self.trigger)(profile_label.to_string());
        Box::pin(fut)
    }

    fn apply_trust(
        &self,
        service: &str,
        payload: &TrustPayload,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let settings = Arc::clone(&self.settings);
        let config_path = self.config_path.clone();
        let service = service.to_string();
        let payload = payload.clone();
        Box::pin(
            async move { apply_trust_to_disk(&settings, &config_path, &service, &payload).await },
        )
    }

    fn apply_secret_id(
        &self,
        _service: &str,
        secret_id: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let secret_id_path = self.secret_id_path.clone();
        // Match the trailing-newline convention of the bootstrap writer so
        // a first-sighting re-write is byte-identical; `login()` trims on
        // read either way.
        let body = format!("{secret_id}\n");
        Box::pin(async move {
            fs_util::atomic_write(&secret_id_path, body.as_bytes(), fs_util::KEY_FILE_MODE)
                .await
                .with_context(|| {
                    format!("Failed to write secret_id to {}", secret_id_path.display())
                })
        })
    }

    fn apply_responder_hmac(
        &self,
        _service: &str,
        hmac: &str,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let config_path = self.config_path.clone();
        let hmac = hmac.to_string();
        Box::pin(async move { apply_responder_hmac_to_disk(&config_path, &hmac).await })
    }

    fn apply_eab(
        &self,
        _service: &str,
        payload: &EabPayload,
    ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
        let payload = payload.clone();
        Box::pin(async move {
            // Only reachable when the loop enabled the EAB poll, which it does
            // only with an `--eab-file` source (so `eab_refresh` is `Some`).
            let handle = self.eab_refresh.as_ref().ok_or_else(|| {
                anyhow::anyhow!("EAB refresh requested but no --eab-file source is configured")
            })?;
            apply_eab_to_state(handle, &payload).await
        })
    }
}

/// Spawns the long-running fast-poll loop. Returns immediately when the
/// settings do not declare an `[openbao]` section, leaving behaviour
/// identical to the pre-#548 daemon.
// The loop composes setup (client, state load, login) with per-tick
// observation handling; splitting into helpers would obscure the single
// lifecycle for reviewers.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run_fast_poll_loop(
    settings: Arc<config::Settings>,
    config_path: PathBuf,
    eab_refresh: Option<EabRefreshHandle>,
    semaphore: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
    renew_fn: impl Fn(config::DaemonProfileSettings, Arc<Semaphore>) -> BoxRenew + Send + Sync + 'static,
) -> Result<()> {
    let Some(openbao) = settings.openbao.clone() else {
        info!("No [openbao] section configured; fast-poll loop disabled.");
        return Ok(());
    };
    if settings.profiles.is_empty() {
        info!("No profiles configured; fast-poll loop disabled.");
        return Ok(());
    }

    // Group profiles by service so that a single reissue request
    // fans out to every profile sharing that service. Bootroot allows
    // multiple instances of the same service on one host (see
    // docs/en/concepts.md), and the rotate command publishes one KV
    // request per service, not per profile.
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for profile in &settings.profiles {
        let label = config::profile_domain(&settings, profile);
        grouped
            .entry(profile.service_name.clone())
            .or_default()
            .push(label);
    }
    let services: Vec<(String, Vec<String>)> = grouped.into_iter().collect();

    info!(
        "Fast-poll enabled: interval={:?}, services={}, profiles={}",
        openbao.fast_poll_interval,
        services.len(),
        settings.profiles.len(),
    );

    // Item #695: a non-loopback plaintext OpenBao URL validates only with
    // the explicit `allow_plaintext_http` opt-in. Surface one prominent
    // startup warning so operators cannot forget that AppRole credentials
    // and every delivered secret cross the network unencrypted.
    if config::openbao_url_is_non_loopback_plaintext(&openbao.url) {
        warn!(
            "OpenBao URL {} is a non-loopback plaintext http:// endpoint (allow_plaintext_http \
             is set): AppRole role_id/secret_id and all delivered secrets (secret_id, responder \
             HMAC, EAB) cross the network UNENCRYPTED. Use https:// in production.",
            openbao.url
        );
    }

    let mut state = match FastPollState::load(&openbao.state_path).await {
        Ok(state) => state,
        Err(err) => {
            warn!(
                "Failed to load fast-poll state ({}): {err:#}. Starting with an empty map.",
                openbao.state_path.display()
            );
            FastPollState::default()
        }
    };

    // Share the OpenBaoClient across hooks and re-login helpers. At
    // startup the pins come from the config snapshot; the post-trust-apply
    // rebuild below re-reads them from the freshly written agent.toml.
    let client = build_openbao_client(&openbao, &settings.trust.trusted_ca_sha256)?;
    let client = Arc::new(Mutex::new(client));
    if let Err(err) = login(&client, &openbao).await {
        warn!("Initial OpenBao AppRole login failed: {err:#}. Will retry on the next tick.");
    }

    // Retain a copy of the config path for the client rebuild's pin
    // re-read; the canonical copy is moved into the hooks below.
    let config_path_for_rebuild = config_path.clone();

    // The EAB poll runs only when EAB is sourced from `--eab-file`; a
    // CLI-pinned EAB gets `None` here so fast-poll never overrides the
    // operator's out-of-band value.
    let refresh_eab = eab_refresh.is_some();

    let renew_fn = Arc::new(renew_fn);
    let settings_for_hooks = Arc::clone(&settings);
    let settings_for_apply = Arc::clone(&settings);
    let semaphore_for_hooks = Arc::clone(&semaphore);
    let renew_fn_for_hooks = Arc::clone(&renew_fn);
    let hooks = LiveFastPollHooks {
        client: Arc::clone(&client),
        settings: settings_for_apply,
        config_path,
        secret_id_path: openbao.secret_id_path.clone(),
        eab_refresh,
        trigger: move |profile_label: String| {
            let settings = Arc::clone(&settings_for_hooks);
            let semaphore = Arc::clone(&semaphore_for_hooks);
            let renew_fn = Arc::clone(&renew_fn_for_hooks);
            async move {
                let profile = settings
                    .profiles
                    .iter()
                    .find(|p| config::profile_domain(&settings, p) == profile_label)
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "Profile '{profile_label}' vanished from settings during fast-poll"
                        )
                    })?
                    .clone();
                renew_fn(profile, semaphore).await
            }
        },
    };

    loop {
        if *shutdown.borrow() {
            info!("Shutdown received; exiting fast-poll loop.");
            break;
        }

        let mut needs_relogin = false;

        // Refresh EAB BEFORE the reissue tick. EAB lives in the in-memory
        // `default_eab` (read at issuance time), not `agent.toml`, so applying
        // it first means a reissue request visible in the same KV snapshot
        // fans out to a renewal that already reads the fresh (or cleared) EAB.
        // Gated on `refresh_eab`: skipped entirely when EAB is CLI-pinned.
        let mut eab_changed = false;
        if refresh_eab {
            let (eab_outcomes, changed) =
                run_eab_poll_tick(&hooks, &openbao.kv_mount, &services, &mut state).await;
            log_poll_outcomes("eab", &eab_outcomes, &mut needs_relogin);
            eab_changed = changed;
        }

        // Refresh the responder HMAC BEFORE running the reissue tick. A
        // reissue request visible in the same KV snapshot triggers a
        // renewal that reloads `agent.toml` per attempt, so the fresh
        // `[acme].http_responder_hmac` must land on disk first — otherwise
        // that first renewal authenticates to the responder with the stale
        // secret. `run_hmac_refresh_then_reissue` fixes this ordering in
        // one place; see its doc comment.
        let HmacRefreshReissueOutcome {
            responder_hmac_outcomes,
            responder_hmac_changed,
            report,
        } = run_hmac_refresh_then_reissue(&hooks, &openbao.kv_mount, &services, &mut state).await;
        log_poll_outcomes(
            "responder_hmac",
            &responder_hmac_outcomes,
            &mut needs_relogin,
        );

        for outcome in &report.outcomes {
            match outcome {
                FastPollTickOutcome::NoRequest { service } => {
                    debug!("Service '{service}': no pending reissue request.");
                }
                FastPollTickOutcome::UpToDate { service, version } => {
                    debug!("Service '{service}': reissue version {version} already applied.");
                }
                FastPollTickOutcome::ReadError { service, error } => {
                    warn!("Service '{service}': fast-poll KV read failed: {error}");
                    if read_error_requires_relogin(error) {
                        needs_relogin = true;
                    }
                }
                FastPollTickOutcome::RenewError {
                    service,
                    profile,
                    error,
                } => {
                    error!(
                        "Service '{service}' / profile '{profile}': fast-poll-triggered renewal failed: {error}"
                    );
                }
                FastPollTickOutcome::CompletedWriteError {
                    service,
                    version,
                    error,
                } => {
                    warn!(
                        "Service '{service}': failed to write completed_at v{version} back to KV: {error} (will retry on next tick)"
                    );
                }
                FastPollTickOutcome::CompletedWriteRetried {
                    service,
                    version,
                    completed_at,
                } => {
                    info!(
                        "Service '{service}': fast-poll completion write retry succeeded for v{version} (completed_at {completed_at})"
                    );
                }
                FastPollTickOutcome::Applied {
                    service,
                    version,
                    completed_at,
                } => {
                    info!(
                        "Service '{service}': fast-poll applied reissue v{version} at {completed_at}"
                    );
                }
                FastPollTickOutcome::AppliedPendingWrite {
                    service,
                    version,
                    completed_at,
                    error,
                } => {
                    warn!(
                        "Service '{service}': fast-poll applied reissue v{version} at {completed_at} but completion write failed: {error} (queued for retry)"
                    );
                }
            }
        }

        // Trust and secret_id polls ride on the same self-authenticated
        // client: a trust rotation propagates the new anchors + bundle, and
        // a secret_id rotation refreshes the credential this very loop
        // re-authenticates with (keeping it alive past secret_id_ttl).
        // Snapshot the trust versions before the poll advances them: a
        // failed HTTPS client rebuild below must be able to roll the version
        // back so the next tick retries (see the rebuild block). Only
        // `https://` rebuilds the client, so skip the clone otherwise.
        let rebuild_client_on_trust = config::openbao_url_is_https(&openbao.url);
        let trust_versions_before = if rebuild_client_on_trust {
            state.last_trust_seen_version.clone()
        } else {
            BTreeMap::new()
        };

        let (trust_outcomes, trust_changed) =
            run_trust_poll_tick(&hooks, &openbao.kv_mount, &services, &mut state).await;
        log_poll_outcomes("trust", &trust_outcomes, &mut needs_relogin);

        let (secret_id_outcomes, secret_id_changed) =
            run_secret_id_poll_tick(&hooks, &openbao.kv_mount, &services, &mut state).await;
        log_poll_outcomes("secret_id", &secret_id_outcomes, &mut needs_relogin);

        // A trust apply rewrites the on-disk CA bundle, and in the
        // remote-bootstrap model `[openbao].ca_bundle_path` and
        // `[trust].ca_bundle_path` are the same file, so that write can move
        // the very anchors this loop trusts for its own OpenBao connection.
        // The in-memory client's root set is frozen at construction
        // (`OpenBaoClient::with_pem_trust` holds a fixed `reqwest::Client`),
        // so without a rebuild the loop would keep the stale roots and, once
        // the old anchor is retired and the endpoint presents a cert under
        // the new signer, fail every subsequent HTTPS read/re-login —
        // defeating zero-touch trust rotation for the loop that must keep
        // polling. Rebuild from the refreshed bundle and re-login. Only the
        // `https://` client anchors trust, so a plaintext endpoint needs no
        // rebuild.
        //
        // Rebuild BEFORE persisting the advanced trust version.
        // `parse_trust_payload` now validates the bundle's PEM structure and
        // fingerprint consistency pre-apply, but the root-store construction
        // that actually anchors this channel's TLS still happens here in
        // `build_openbao_client`. If the bundle is unreadable after the write,
        // rejected by rustls, or the freshly applied pins cannot be recovered,
        // the version must NOT stay marked applied — otherwise the poll reports
        // `UpToDate` forever, never retries the rebuild, and the loop is
        // stranded on stale roots once the old anchor is retired. On a rebuild
        // failure, roll the version back so the next tick re-applies and
        // rebuilds. A re-login failure after a *successful* rebuild is
        // different: the new roots are already in the client, so we keep the
        // advanced version and just retry the login.
        let mut trust_applied = trust_changed;
        if trust_changed && rebuild_client_on_trust {
            let rebuilt_ok = rebuild_client_after_trust_apply(
                &client,
                &openbao,
                &config_path_for_rebuild,
                &mut needs_relogin,
            )
            .await;
            trust_applied = reconcile_trust_rebuild(&mut state, trust_versions_before, rebuilt_ok);
        }

        if (report.state_changed
            || trust_applied
            || secret_id_changed
            || responder_hmac_changed
            || eab_changed)
            && let Err(err) = state.save(&openbao.state_path).await
        {
            error!(
                "Failed to persist fast-poll state to {}: {err:#}",
                openbao.state_path.display()
            );
        }

        let mut sleep_for = openbao.fast_poll_interval;
        if needs_relogin {
            if let Err(err) = login(&client, &openbao).await {
                warn!("OpenBao AppRole re-login failed: {err:#}");
            }
            // A failed login is nearly always an OpenBao-side problem
            // (sealed, network blip, expired AppRole). Back off so we do
            // not hot-loop against it even when an operator has tuned
            // fast_poll_interval below the retry floor.
            sleep_for = sleep_for.max(LOGIN_RETRY_FLOOR);
        }
        tokio::select! {
            _ = shutdown.changed() => {
                info!("Shutdown received; exiting fast-poll loop.");
                break;
            }
            () = tokio::time::sleep(sleep_for) => {}
        }
    }

    Ok(())
}

pub(crate) type BoxRenew = std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + 'static>>;

/// Reconciles the fast-poll state after a post-trust-change HTTPS client
/// rebuild. When the rebuild succeeded the advanced trust version stands;
/// when it failed the version is rolled back to `versions_before` so the
/// next tick retries the apply and rebuild rather than reporting the
/// stale-root client as up to date. Returns whether the advanced trust
/// version should be persisted.
fn reconcile_trust_rebuild(
    state: &mut FastPollState,
    versions_before: BTreeMap<String, u64>,
    rebuilt_ok: bool,
) -> bool {
    if rebuilt_ok {
        return true;
    }
    state.last_trust_seen_version = versions_before;
    false
}

/// Rebuilds the fast-poll `OpenBaoClient` after a trust apply, swaps it into
/// `client`, and re-logs in. Returns whether the rebuild succeeded so the
/// caller can roll the advanced trust version back on failure.
///
/// Pins the rebuilt client to the FRESHLY applied anchors re-read from
/// `config_path`, never a startup snapshot: a rotation that lands a new CA +
/// new pins in KV has just written both to `agent.toml`, so the pins are read
/// back from there. Stale startup pins would strand the client on the retired
/// CA and defeat zero-touch rotation. Recovering the pins CAN fail (unreadable
/// / unparseable config, or no pins written) — that is treated as a rebuild
/// failure so the caller rolls the version back rather than silently rebuilding
/// unpinned, which would downgrade the channel from pinned to bundle-anchored
/// trust while reporting the rotation as applied.
///
/// A re-login failure after a *successful* rebuild still returns `true` (the
/// new roots are already swapped in) and sets `needs_relogin` so the caller
/// retries the login on the next tick.
async fn rebuild_client_after_trust_apply(
    client: &Arc<Mutex<OpenBaoClient>>,
    openbao: &config::OpenBaoSettings,
    config_path: &Path,
    needs_relogin: &mut bool,
) -> bool {
    let rebuild_pins = match read_trust_pins_from_config(config_path).await {
        Ok(pins) => pins,
        Err(err) => {
            warn!(
                "Failed to recover the freshly applied trust pins after a trust update: {err:#}. Rolling back the applied trust version so the next tick retries rather than rebuilding with unpinned bundle-anchored trust."
            );
            return false;
        }
    };
    let rebuilt = match build_openbao_client(openbao, &rebuild_pins) {
        Ok(rebuilt) => rebuilt,
        Err(err) => {
            warn!(
                "Failed to rebuild OpenBao client after a trust update: {err:#}. Rolling back the applied trust version so the next tick retries the apply and rebuild."
            );
            return false;
        }
    };
    *client.lock().await = rebuilt;
    if let Err(err) = login(client, openbao).await {
        warn!(
            "OpenBao re-login after CA bundle rebuild failed: {err:#}. Will retry on the next tick."
        );
        *needs_relogin = true;
    } else {
        info!("Rebuilt OpenBao client from the refreshed CA bundle after a trust update.");
    }
    true
}

/// Builds the fast-poll `OpenBaoClient`, anchoring an `https://` endpoint
/// to the on-disk CA bundle and restricting its trust anchors to `pins`
/// (`trusted_ca_sha256`) when non-empty. An empty pin set keeps the prior
/// bundle-anchored behavior. A plaintext endpoint ignores `pins` (there is
/// no TLS to anchor).
///
/// The pins the caller passes matter: at startup they come from the config
/// snapshot, but on the post-trust-apply rebuild they MUST come from the
/// freshly applied trust (see `read_trust_pins_from_config`) so a rotation
/// that swaps the CA also swaps the pins — a stale startup snapshot would
/// strand the rebuilt client on the retired CA and defeat zero-touch
/// rotation (issue #695).
fn build_openbao_client(
    openbao: &config::OpenBaoSettings,
    pins: &[String],
) -> Result<OpenBaoClient> {
    if config::openbao_url_is_https(&openbao.url) {
        let ca_bundle_path = openbao
            .ca_bundle_path
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("openbao.ca_bundle_path is required for https://"))?;
        let pem = std::fs::read_to_string(ca_bundle_path).with_context(|| {
            format!(
                "Failed to read openbao.ca_bundle_path at {}",
                ca_bundle_path.display()
            )
        })?;
        OpenBaoClient::with_pem_trust(&openbao.url, &pem, pins)
            .context("Failed to build OpenBao client with CA bundle")
    } else {
        OpenBaoClient::new(&openbao.url).context("Failed to build OpenBao client")
    }
}

/// Reads the current `[trust].trusted_ca_sha256` pins from the on-disk
/// `agent.toml` to pin the post-trust-apply client rebuild to the freshly
/// written anchors rather than the startup snapshot.
///
/// This is only called after a trust apply succeeded, and every trust
/// payload that applies carries a non-empty `trusted_ca_sha256`
/// (`parse_trust_payload` rejects an empty pin set), so the just-written
/// config MUST expose a non-empty pin array. Any failure to recover it —
/// unreadable file, unparseable TOML, or a missing / non-array / empty
/// `trusted_ca_sha256` — is therefore an error, NOT a silent fall back to
/// an empty (bundle-anchored) pin set: swallowing it would let a rotation
/// downgrade "trust only the pinned anchors" to "trust every CA in the
/// bundle" while still persisting the version as applied. The caller rolls
/// the trust version back on `Err` so the next tick retries the apply and
/// rebuild (issue #695).
///
/// # Errors
///
/// Returns an error when the config cannot be read or parsed, or when it
/// carries no usable `[trust].trusted_ca_sha256` pins.
async fn read_trust_pins_from_config(config_path: &Path) -> Result<Vec<String>> {
    let contents = fs::read_to_string(config_path).await.with_context(|| {
        format!(
            "Failed to read agent config for trust pins at {}",
            config_path.display()
        )
    })?;
    let doc = contents
        .parse::<toml_edit::DocumentMut>()
        .with_context(|| format!("Failed to parse agent config at {}", config_path.display()))?;
    let pins: Vec<String> = doc
        .get("trust")
        .and_then(|trust| trust.get("trusted_ca_sha256"))
        .and_then(toml_edit::Item::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|value| value.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    if pins.is_empty() {
        anyhow::bail!(
            "agent config at {} has no [trust].trusted_ca_sha256 pins after a trust apply",
            config_path.display()
        );
    }
    Ok(pins)
}

async fn login(
    client: &Arc<Mutex<OpenBaoClient>>,
    openbao: &config::OpenBaoSettings,
) -> Result<()> {
    let role_id = read_trimmed(&openbao.role_id_path)
        .await
        .with_context(|| format!("Failed to read {}", openbao.role_id_path.display()))?;
    let secret_id = read_trimmed(&openbao.secret_id_path)
        .await
        .with_context(|| format!("Failed to read {}", openbao.secret_id_path.display()))?;
    let token = {
        let guard = client.lock().await;
        guard.login_approle(&role_id, &secret_id).await?
    };
    client.lock().await.set_token(token);
    Ok(())
}

async fn read_trimmed(path: &Path) -> Result<String> {
    let body = fs::read_to_string(path).await?;
    Ok(body.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reissue_kv_path_formats_as_documented() {
        assert_eq!(
            reissue_kv_path("edge-proxy"),
            "bootroot/services/edge-proxy/reissue",
        );
    }

    // Reviewer round 9: after a failed initial `login()`, the next tick's
    // read surfaces "OpenBao token is not set" from `require_token()`.
    // The relogin heuristic previously only matched server-side auth
    // rejections, so the loop never rearmed login and fast-poll went
    // permanently silent until a process restart. Keep this set in sync
    // with every token-related error message the agent can observe.
    #[test]
    fn read_error_requires_relogin_detects_missing_token() {
        assert!(read_error_requires_relogin("OpenBao token is not set"));
        assert!(read_error_requires_relogin(
            "OpenBao API error (403): permission denied"
        ));
        assert!(read_error_requires_relogin(
            "OpenBao API error (400): missing client token"
        ));
        assert!(!read_error_requires_relogin(
            "connection refused (os error 61)"
        ));
        assert!(!read_error_requires_relogin(
            "OpenBao API error (500): internal server error"
        ));
    }

    #[test]
    fn evaluate_observation_fires_when_version_is_new() {
        let observation = KvReadWithVersion {
            version: 5,
            data: serde_json::json!({
                "requested_at": "2026-04-19T12:34:56Z",
                "requester": "alice",
            }),
        };
        let result = evaluate_observation(&observation, Some(4));
        assert_eq!(
            result,
            Some(ReissueObservation {
                version: 5,
                requested_at: Some("2026-04-19T12:34:56Z".to_string()),
                requester: Some("alice".to_string()),
            })
        );
    }

    #[test]
    fn evaluate_observation_returns_none_when_version_seen() {
        let observation = KvReadWithVersion {
            version: 3,
            data: serde_json::json!({}),
        };
        assert!(evaluate_observation(&observation, Some(3)).is_none());
        assert!(evaluate_observation(&observation, Some(4)).is_none());
    }

    #[test]
    fn evaluate_observation_fires_on_first_sighting() {
        let observation = KvReadWithVersion {
            version: 1,
            data: serde_json::json!({}),
        };
        let result = evaluate_observation(&observation, None);
        assert_eq!(result.as_ref().map(|o| o.version), Some(1));
    }

    // Reviewer round 7: the agent's own completion write advances the
    // KV metadata version from N to N+1 and carries `completed_version
    // = N` in the payload. The previous read path keyed purely off
    // `metadata.version > last_seen`, so it would mistake the ack for
    // a new request and force a renewal on every subsequent tick.
    #[test]
    fn evaluate_observation_ignores_agent_completion_ack() {
        let observation = KvReadWithVersion {
            version: 6,
            data: serde_json::json!({
                "requested_at": "2026-04-19T12:34:56Z",
                "requester": "alice",
                "completed_at": "2026-04-19T12:35:10Z",
                "completed_version": 5,
            }),
        };
        assert!(evaluate_observation(&observation, Some(5)).is_none());
        // Stays None even when state is empty (e.g. state file lost),
        // so a past completion does not retroactively re-fire.
        assert!(evaluate_observation(&observation, None).is_none());
    }

    #[test]
    fn build_completed_payload_preserves_request_fields() {
        let observation = ReissueObservation {
            version: 7,
            requested_at: Some("2026-04-19T12:34:56Z".to_string()),
            requester: Some("alice".to_string()),
        };
        let payload = build_completed_payload(&observation, "2026-04-19T12:35:10Z");
        let obj = payload.as_object().expect("payload is an object");
        assert_eq!(
            obj.get(REISSUE_REQUESTED_AT_KEY).and_then(|v| v.as_str()),
            Some("2026-04-19T12:34:56Z"),
        );
        assert_eq!(
            obj.get(REISSUE_REQUESTER_KEY).and_then(|v| v.as_str()),
            Some("alice"),
        );
        assert_eq!(
            obj.get(REISSUE_COMPLETED_AT_KEY).and_then(|v| v.as_str()),
            Some("2026-04-19T12:35:10Z"),
        );
        assert_eq!(
            obj.get(REISSUE_COMPLETED_VERSION_KEY)
                .and_then(serde_json::Value::as_u64),
            Some(7),
        );
    }

    #[tokio::test]
    async fn fast_poll_state_load_missing_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.json");
        let state = FastPollState::load(&path).await.unwrap();
        assert!(state.last_reissue_seen_version.is_empty());
    }

    #[tokio::test]
    async fn fast_poll_state_round_trip_persists_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = FastPollState::default();
        state
            .last_reissue_seen_version
            .insert("edge-proxy".to_string(), 7);
        state.save(&path).await.unwrap();
        let loaded = FastPollState::load(&path).await.unwrap();
        assert_eq!(loaded.last_reissue_seen_version.get("edge-proxy"), Some(&7));
    }

    struct FakeHooks {
        read: std::sync::Mutex<Vec<Result<Option<KvReadWithVersion>>>>,
        writes: std::sync::Mutex<Vec<(String, serde_json::Value)>>,
        renew_calls: std::sync::Mutex<Vec<String>>,
        // Per-call write outcomes consumed in order. When the queue is
        // empty the write succeeds. Each `false` triggers one failure.
        write_outcomes: std::sync::Mutex<Vec<bool>>,
        // Profile labels that should fail when their renewal is
        // requested. All others succeed.
        failing_profiles: std::sync::Mutex<std::collections::HashSet<String>>,
        // Recorded trust / secret_id / responder_hmac applies for the
        // poll-tick tests.
        trust_applies: std::sync::Mutex<Vec<(String, TrustPayload)>>,
        secret_id_applies: std::sync::Mutex<Vec<(String, String)>>,
        responder_hmac_applies: std::sync::Mutex<Vec<(String, String)>>,
        eab_applies: std::sync::Mutex<Vec<(String, EabPayload)>>,
        // Chronological log of ordering-sensitive hook calls
        // ("apply_responder_hmac:<svc>", "renew:<profile>") so tests can
        // assert the responder-HMAC write lands before the reissue-triggered
        // renewal within a single tick.
        op_log: std::sync::Mutex<Vec<String>>,
        // When true, every apply_trust / apply_secret_id / apply_responder_hmac
        // call fails.
        fail_applies: std::sync::atomic::AtomicBool,
    }

    impl FakeHooks {
        fn new(reads: Vec<Result<Option<KvReadWithVersion>>>) -> Self {
            Self {
                read: std::sync::Mutex::new(reads),
                writes: std::sync::Mutex::new(Vec::new()),
                renew_calls: std::sync::Mutex::new(Vec::new()),
                write_outcomes: std::sync::Mutex::new(Vec::new()),
                failing_profiles: std::sync::Mutex::new(std::collections::HashSet::new()),
                trust_applies: std::sync::Mutex::new(Vec::new()),
                secret_id_applies: std::sync::Mutex::new(Vec::new()),
                responder_hmac_applies: std::sync::Mutex::new(Vec::new()),
                eab_applies: std::sync::Mutex::new(Vec::new()),
                op_log: std::sync::Mutex::new(Vec::new()),
                fail_applies: std::sync::atomic::AtomicBool::new(false),
            }
        }

        fn fail_applies(self) -> Self {
            self.fail_applies
                .store(true, std::sync::atomic::Ordering::SeqCst);
            self
        }

        fn fail_renewals_for(self, profiles: &[&str]) -> Self {
            let mut set = self.failing_profiles.lock().unwrap();
            for p in profiles {
                set.insert((*p).to_string());
            }
            drop(set);
            self
        }

        fn fail_writes(self, outcomes: Vec<bool>) -> Self {
            *self.write_outcomes.lock().unwrap() = outcomes;
            self
        }
    }

    impl FastPollHooks for FakeHooks {
        fn read_kv_version(
            &self,
            _kv_mount: &str,
            _kv_path: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Option<KvReadWithVersion>>> + Send + '_>>
        {
            let next = self.read.lock().unwrap().pop().unwrap_or_else(|| Ok(None));
            Box::pin(async move { next })
        }

        fn write_kv(
            &self,
            _kv_mount: &str,
            kv_path: &str,
            data: serde_json::Value,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            self.writes
                .lock()
                .unwrap()
                .push((kv_path.to_string(), data));
            // Consume one element from write_outcomes (FIFO). `true`
            // (or empty queue) = success, `false` = simulated failure.
            let succeed = {
                let mut q = self.write_outcomes.lock().unwrap();
                if q.is_empty() { true } else { q.remove(0) }
            };
            Box::pin(async move {
                if succeed {
                    Ok(())
                } else {
                    anyhow::bail!("simulated KV write failure")
                }
            })
        }

        fn trigger_renewal(
            &self,
            profile_label: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            self.renew_calls
                .lock()
                .unwrap()
                .push(profile_label.to_string());
            self.op_log
                .lock()
                .unwrap()
                .push(format!("renew:{profile_label}"));
            let fail = self
                .failing_profiles
                .lock()
                .unwrap()
                .contains(profile_label);
            Box::pin(async move {
                if fail {
                    anyhow::bail!("simulated renewal failure");
                }
                Ok(())
            })
        }

        fn apply_trust(
            &self,
            service: &str,
            payload: &TrustPayload,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            self.trust_applies
                .lock()
                .unwrap()
                .push((service.to_string(), payload.clone()));
            let fail = self.fail_applies.load(std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if fail {
                    anyhow::bail!("simulated trust apply failure");
                }
                Ok(())
            })
        }

        fn apply_secret_id(
            &self,
            service: &str,
            secret_id: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            self.secret_id_applies
                .lock()
                .unwrap()
                .push((service.to_string(), secret_id.to_string()));
            let fail = self.fail_applies.load(std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if fail {
                    anyhow::bail!("simulated secret_id apply failure");
                }
                Ok(())
            })
        }

        fn apply_responder_hmac(
            &self,
            service: &str,
            hmac: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            self.responder_hmac_applies
                .lock()
                .unwrap()
                .push((service.to_string(), hmac.to_string()));
            self.op_log
                .lock()
                .unwrap()
                .push(format!("apply_responder_hmac:{service}"));
            let fail = self.fail_applies.load(std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if fail {
                    anyhow::bail!("simulated responder_hmac apply failure");
                }
                Ok(())
            })
        }

        fn apply_eab(
            &self,
            service: &str,
            payload: &EabPayload,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            self.eab_applies
                .lock()
                .unwrap()
                .push((service.to_string(), payload.clone()));
            let fail = self.fail_applies.load(std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                if fail {
                    anyhow::bail!("simulated eab apply failure");
                }
                Ok(())
            })
        }
    }

    fn services_single(service: &str, profile: &str) -> Vec<(String, Vec<String>)> {
        vec![(service.to_string(), vec![profile.to_string()])]
    }

    #[tokio::test]
    async fn tick_fires_renewal_on_new_version() {
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 2,
            data: serde_json::json!({
                "requested_at": "2026-04-19T12:34:56Z",
                "requester": "alice",
            }),
        }))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert_eq!(report.outcomes.len(), 1);
        assert!(report.state_changed);
        match &report.outcomes[0] {
            FastPollTickOutcome::Applied {
                service, version, ..
            } => {
                assert_eq!(service, "edge-proxy");
                assert_eq!(*version, 2);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
        assert_eq!(state.last_reissue_seen_version.get("edge-proxy"), Some(&2),);
        assert!(state.pending_completion_writes.is_empty());
        assert_eq!(hooks.renew_calls.lock().unwrap().len(), 1);
        let writes = hooks.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, "bootroot/services/edge-proxy/reissue");
        let body = writes[0].1.as_object().unwrap();
        assert_eq!(
            body.get(REISSUE_COMPLETED_VERSION_KEY)
                .and_then(serde_json::Value::as_u64),
            Some(2)
        );
    }

    #[tokio::test]
    async fn tick_skips_when_version_already_applied() {
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 5,
            data: serde_json::json!({}),
        }))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();
        state
            .last_reissue_seen_version
            .insert("edge-proxy".to_string(), 5);

        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(matches!(
            report.outcomes[0],
            FastPollTickOutcome::UpToDate { .. }
        ));
        assert!(!report.state_changed);
        assert!(hooks.renew_calls.lock().unwrap().is_empty());
        assert!(hooks.writes.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn tick_returns_no_request_when_kv_missing() {
        let hooks = FakeHooks::new(vec![Ok(None)]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(matches!(
            report.outcomes[0],
            FastPollTickOutcome::NoRequest { .. }
        ));
        assert!(!report.state_changed);
        assert!(hooks.renew_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn tick_does_not_advance_state_when_renewal_fails() {
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 2,
            data: serde_json::json!({}),
        }))])
        .fail_renewals_for(&["edge-proxy-domain"]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(matches!(
            report.outcomes[0],
            FastPollTickOutcome::RenewError { .. }
        ));
        assert!(!report.state_changed);
        assert!(state.last_reissue_seen_version.is_empty());
        assert!(state.pending_completion_writes.is_empty());
        assert!(hooks.writes.lock().unwrap().is_empty());
    }

    // Reviewer round 1, item 1: a service with multiple profiles must
    // fan the renewal out to every matching profile before the version
    // is marked consumed. The previous implementation deduped by
    // service_name only, so sibling profiles silently kept their old
    // certificate.
    #[tokio::test]
    async fn tick_fans_renewal_out_to_all_profiles_sharing_a_service() {
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 4,
            data: serde_json::json!({
                "requested_at": "2026-04-19T12:34:56Z",
                "requester": "alice",
            }),
        }))]);
        let services: Vec<(String, Vec<String>)> = vec![(
            "edge-proxy".to_string(),
            vec![
                "001.edge-proxy.host-a.example".to_string(),
                "002.edge-proxy.host-a.example".to_string(),
                "003.edge-proxy.host-a.example".to_string(),
            ],
        )];
        let mut state = FastPollState::default();

        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        // All three profiles received a renewal trigger.
        let calls = hooks.renew_calls.lock().unwrap().clone();
        assert_eq!(calls.len(), 3);
        assert!(calls.contains(&"001.edge-proxy.host-a.example".to_string()));
        assert!(calls.contains(&"002.edge-proxy.host-a.example".to_string()));
        assert!(calls.contains(&"003.edge-proxy.host-a.example".to_string()));
        assert!(matches!(
            report.outcomes[0],
            FastPollTickOutcome::Applied { .. }
        ));
        assert_eq!(state.last_reissue_seen_version.get("edge-proxy"), Some(&4));
    }

    // If any profile in a fan-out fails, the version must NOT be
    // marked consumed: the next tick has to retry the failed profile
    // against the same KV version. The profiles that already succeeded
    // are recorded as in-flight progress so they are NOT re-triggered
    // on the retry tick.
    #[tokio::test]
    async fn tick_holds_state_when_any_profile_in_fan_out_fails() {
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 2,
            data: serde_json::json!({}),
        }))])
        .fail_renewals_for(&["002.edge-proxy.host-a.example"]);
        let services: Vec<(String, Vec<String>)> = vec![(
            "edge-proxy".to_string(),
            vec![
                "001.edge-proxy.host-a.example".to_string(),
                "002.edge-proxy.host-a.example".to_string(),
            ],
        )];
        let mut state = FastPollState::default();

        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        // Both profiles attempted, one failed.
        assert_eq!(hooks.renew_calls.lock().unwrap().len(), 2);
        assert!(report.outcomes.iter().any(|o| matches!(
            o,
            FastPollTickOutcome::RenewError { profile, .. }
                if profile == "002.edge-proxy.host-a.example"
        )));
        // Version is NOT consumed, no completion write performed.
        assert!(state.last_reissue_seen_version.is_empty());
        assert!(state.pending_completion_writes.is_empty());
        assert!(hooks.writes.lock().unwrap().is_empty());
        // But the profile that DID succeed is recorded so it won't be
        // re-triggered on the retry tick.
        let in_flight = state
            .in_flight_renewals
            .get("edge-proxy")
            .expect("in-flight progress recorded");
        assert_eq!(in_flight.version, 2);
        assert!(
            in_flight
                .completed_profiles
                .contains("001.edge-proxy.host-a.example")
        );
        assert!(
            !in_flight
                .completed_profiles
                .contains("002.edge-proxy.host-a.example")
        );
        // Persisting the progress requires a state save.
        assert!(report.state_changed);
    }

    // Reviewer round 2, item 2: on a retry tick the agent must only
    // re-trigger the profile(s) that failed previously, NOT force a
    // second renewal on the sibling profiles that already succeeded.
    #[tokio::test]
    async fn tick_skips_completed_profiles_on_retry_tick() {
        let services: Vec<(String, Vec<String>)> = vec![(
            "edge-proxy".to_string(),
            vec![
                "001.edge-proxy.host-a.example".to_string(),
                "002.edge-proxy.host-a.example".to_string(),
                "003.edge-proxy.host-a.example".to_string(),
            ],
        )];
        let mut state = FastPollState::default();

        // Tick 1: profile "002" fails; "001" and "003" succeed.
        let hooks1 = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 11,
            data: serde_json::json!({
                "requested_at": "2026-04-19T12:34:56Z",
                "requester": "alice",
            }),
        }))])
        .fail_renewals_for(&["002.edge-proxy.host-a.example"]);
        let _ = run_fast_poll_tick(&hooks1, "secret", &services, &mut state).await;
        assert_eq!(hooks1.renew_calls.lock().unwrap().len(), 3);
        let in_flight = state
            .in_flight_renewals
            .get("edge-proxy")
            .expect("in-flight after first tick");
        assert_eq!(in_flight.completed_profiles.len(), 2);

        // Tick 2: KV still shows version 11, "002" is no longer failing.
        // Only "002" should be triggered — "001" and "003" already
        // succeeded in tick 1 and must not be reissued.
        let hooks2 = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 11,
            data: serde_json::json!({
                "requested_at": "2026-04-19T12:34:56Z",
                "requester": "alice",
            }),
        }))]);
        let report = run_fast_poll_tick(&hooks2, "secret", &services, &mut state).await;

        let calls = hooks2.renew_calls.lock().unwrap().clone();
        assert_eq!(
            calls,
            vec!["002.edge-proxy.host-a.example".to_string()],
            "only the previously-failed profile should be retried"
        );
        assert!(matches!(
            report.outcomes[0],
            FastPollTickOutcome::Applied { version: 11, .. }
        ));
        assert_eq!(state.last_reissue_seen_version.get("edge-proxy"), Some(&11));
        assert!(state.in_flight_renewals.is_empty());
    }

    // A newer KV version while an in-flight fan-out is still partially
    // complete must drop the stale per-profile progress and start a
    // fresh fan-out for the new version.
    #[tokio::test]
    async fn tick_drops_in_flight_when_superseded_by_newer_version() {
        let services: Vec<(String, Vec<String>)> = vec![(
            "edge-proxy".to_string(),
            vec![
                "001.edge-proxy.host-a.example".to_string(),
                "002.edge-proxy.host-a.example".to_string(),
            ],
        )];
        let mut state = FastPollState::default();
        let mut progress = BTreeSet::new();
        progress.insert("001.edge-proxy.host-a.example".to_string());
        state.in_flight_renewals.insert(
            "edge-proxy".to_string(),
            InFlightRenewal {
                version: 5,
                completed_profiles: progress,
            },
        );

        // A newer request (version 6) supersedes the half-finished
        // fan-out for version 5: both profiles should be triggered.
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 6,
            data: serde_json::json!({}),
        }))]);
        let _ = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert_eq!(hooks.renew_calls.lock().unwrap().len(), 2);
        assert_eq!(state.last_reissue_seen_version.get("edge-proxy"), Some(&6));
        assert!(state.in_flight_renewals.is_empty());
    }

    // Reviewer round 1, item 2: a transient KV write failure must not
    // strand `--wait` callers. The next tick must retry just the
    // completion write while the KV version is unchanged.
    #[tokio::test]
    async fn tick_retries_pending_completion_write_on_subsequent_tick() {
        // Tick 1: read returns version 7, renewal succeeds, KV write
        // fails. State should record the version as applied AND store
        // a pending completion entry.
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 7,
            data: serde_json::json!({
                "requested_at": "2026-04-19T12:34:56Z",
                "requester": "alice",
            }),
        }))])
        .fail_writes(vec![false]); // first write fails
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(matches!(
            report.outcomes[0],
            FastPollTickOutcome::AppliedPendingWrite { version: 7, .. }
        ));
        assert!(report.state_changed);
        assert_eq!(state.last_reissue_seen_version.get("edge-proxy"), Some(&7));
        let pending = state
            .pending_completion_writes
            .get("edge-proxy")
            .expect("pending entry recorded");
        assert_eq!(pending.version, 7);

        // Tick 2: KV still returns version 7, no new request. The
        // hooks should NOT re-trigger renewal — they should retry
        // just the completion write, and this time it succeeds.
        let hooks2 = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 7,
            data: serde_json::json!({
                "requested_at": "2026-04-19T12:34:56Z",
                "requester": "alice",
            }),
        }))]);

        let report2 = run_fast_poll_tick(&hooks2, "secret", &services, &mut state).await;

        // No renewal call this tick — write retry only.
        assert!(hooks2.renew_calls.lock().unwrap().is_empty());
        assert!(matches!(
            report2.outcomes[0],
            FastPollTickOutcome::CompletedWriteRetried { version: 7, .. }
        ));
        assert!(report2.state_changed);
        assert!(state.pending_completion_writes.is_empty());

        let writes = hooks2.writes.lock().unwrap();
        assert_eq!(writes.len(), 1);
        let body = writes[0].1.as_object().unwrap();
        assert_eq!(
            body.get(REISSUE_COMPLETED_VERSION_KEY)
                .and_then(serde_json::Value::as_u64),
            Some(7)
        );
        assert_eq!(
            body.get(REISSUE_REQUESTER_KEY).and_then(|v| v.as_str()),
            Some("alice"),
        );
    }

    // If a newer reissue request arrives before the pending write was
    // ever drained, drop the stale pending and process the new
    // request as usual. The old `--wait` caller is gone by then.
    #[tokio::test]
    async fn tick_drops_stale_pending_when_superseded_by_newer_version() {
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();
        state
            .last_reissue_seen_version
            .insert("edge-proxy".to_string(), 3);
        state.pending_completion_writes.insert(
            "edge-proxy".to_string(),
            PendingCompletion {
                version: 3,
                completed_at: "2026-04-19T12:00:00Z".to_string(),
                requested_at: Some("2026-04-19T11:59:00Z".to_string()),
                requester: Some("alice".to_string()),
            },
        );

        // Newer KV version (4) supersedes the pending v3.
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 4,
            data: serde_json::json!({
                "requested_at": "2026-04-19T13:00:00Z",
                "requester": "bob",
            }),
        }))]);

        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        // Stale pending dropped, new version applied.
        assert!(state.pending_completion_writes.is_empty());
        assert_eq!(state.last_reissue_seen_version.get("edge-proxy"), Some(&4));
        assert!(
            report
                .outcomes
                .iter()
                .any(|o| matches!(o, FastPollTickOutcome::Applied { version: 4, .. }))
        );
    }

    // If the reissue request is removed from KV entirely (e.g. cleanup
    // by an operator) any lingering pending should be cleared.
    #[tokio::test]
    async fn tick_clears_pending_when_kv_request_disappears() {
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();
        state.pending_completion_writes.insert(
            "edge-proxy".to_string(),
            PendingCompletion {
                version: 9,
                completed_at: "2026-04-19T12:00:00Z".to_string(),
                requested_at: None,
                requester: None,
            },
        );

        let hooks = FakeHooks::new(vec![Ok(None)]);
        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(state.pending_completion_writes.is_empty());
        assert!(report.state_changed);
        assert!(matches!(
            report.outcomes[0],
            FastPollTickOutcome::NoRequest { .. }
        ));
    }

    // A pending write that fails again on retry must remain queued so
    // the next tick keeps trying.
    #[tokio::test]
    async fn tick_keeps_pending_when_completion_write_retry_also_fails() {
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();
        state
            .last_reissue_seen_version
            .insert("edge-proxy".to_string(), 5);
        state.pending_completion_writes.insert(
            "edge-proxy".to_string(),
            PendingCompletion {
                version: 5,
                completed_at: "2026-04-19T12:00:00Z".to_string(),
                requested_at: Some("2026-04-19T11:59:00Z".to_string()),
                requester: Some("alice".to_string()),
            },
        );

        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 5,
            data: serde_json::json!({}),
        }))])
        .fail_writes(vec![false]);

        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(state.pending_completion_writes.contains_key("edge-proxy"));
        assert!(!report.state_changed);
        assert!(matches!(
            report.outcomes[0],
            FastPollTickOutcome::CompletedWriteError { version: 5, .. }
        ));
        assert!(hooks.renew_calls.lock().unwrap().is_empty());
    }

    // Reviewer round 7 end-to-end: after tick 1 applied request N, the
    // agent's own completion write bumps KV metadata to N+1 (payload
    // now carries `completed_version = N`). The next tick must stay
    // `UpToDate` — no spurious renewal, no state mutation, no second
    // completion write — even though `metadata.version (N+1)` exceeds
    // `last_reissue_seen_version (N)`.
    #[tokio::test]
    async fn tick_stays_up_to_date_when_metadata_advanced_by_own_completion_ack() {
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();
        state
            .last_reissue_seen_version
            .insert("edge-proxy".to_string(), 5);

        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 6,
            data: serde_json::json!({
                "requested_at": "2026-04-19T12:34:56Z",
                "requester": "alice",
                "completed_at": "2026-04-19T12:35:10Z",
                "completed_version": 5,
            }),
        }))]);

        let report = run_fast_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(matches!(
            report.outcomes[0],
            FastPollTickOutcome::UpToDate { version: 6, .. }
        ));
        assert!(!report.state_changed);
        assert!(hooks.renew_calls.lock().unwrap().is_empty());
        assert!(hooks.writes.lock().unwrap().is_empty());
        assert_eq!(state.last_reissue_seen_version.get("edge-proxy"), Some(&5));
    }

    #[tokio::test]
    async fn fast_poll_state_round_trip_persists_pending_completion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = FastPollState::default();
        state
            .last_reissue_seen_version
            .insert("edge-proxy".to_string(), 7);
        state.pending_completion_writes.insert(
            "edge-proxy".to_string(),
            PendingCompletion {
                version: 7,
                completed_at: "2026-04-19T12:00:00Z".to_string(),
                requested_at: Some("2026-04-19T11:59:00Z".to_string()),
                requester: Some("alice".to_string()),
            },
        );
        state.save(&path).await.unwrap();

        let loaded = FastPollState::load(&path).await.unwrap();
        let pending = loaded
            .pending_completion_writes
            .get("edge-proxy")
            .expect("pending persisted");
        assert_eq!(pending.version, 7);
        assert_eq!(pending.completed_at, "2026-04-19T12:00:00Z");
        assert_eq!(pending.requester.as_deref(), Some("alice"));
    }

    /// Generates a self-signed CA certificate, returning its PEM and the
    /// lowercase hex SHA-256 of its DER (the `trusted_ca_sha256` form).
    fn generate_ca_cert() -> (String, String) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        let key = KeyPair::generate().expect("generate CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, "Bootroot Test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-signed cert");
        let fingerprint = crate::tls::sha256_hex(cert.der().as_ref());
        (cert.pem(), fingerprint)
    }

    /// Builds a structurally valid trust payload: a two-certificate bundle
    /// whose members' fingerprints are exactly the pinned list, so it
    /// passes `parse_trust_payload`'s consistency check.
    fn valid_trust_bundle() -> (Vec<String>, String) {
        let (pem_a, fp_a) = generate_ca_cert();
        let (pem_b, fp_b) = generate_ca_cert();
        (vec![fp_a, fp_b], format!("{pem_a}{pem_b}"))
    }

    fn trust_read(version: u64) -> KvReadWithVersion {
        let (fingerprints, ca_bundle_pem) = valid_trust_bundle();
        KvReadWithVersion {
            version,
            data: serde_json::json!({
                "trusted_ca_sha256": fingerprints,
                "ca_bundle_pem": ca_bundle_pem,
            }),
        }
    }

    #[test]
    fn kv_path_helpers_format_as_documented() {
        assert_eq!(
            trust_kv_path("edge-proxy"),
            "bootroot/services/edge-proxy/trust"
        );
        assert_eq!(
            secret_id_kv_path("edge-proxy"),
            "bootroot/services/edge-proxy/secret_id"
        );
        assert_eq!(
            responder_hmac_kv_path("edge-proxy"),
            "bootroot/services/edge-proxy/http_responder_hmac"
        );
        assert_eq!(
            eab_kv_path("edge-proxy"),
            "bootroot/services/edge-proxy/eab"
        );
    }

    #[tokio::test]
    async fn trust_poll_applies_on_new_version() {
        let hooks = FakeHooks::new(vec![Ok(Some(trust_read(3)))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_trust_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Applied { version: 3, .. }
        ));
        assert_eq!(state.last_trust_seen_version.get("edge-proxy"), Some(&3));
        let applies = hooks.trust_applies.lock().unwrap();
        assert_eq!(applies.len(), 1);
        assert_eq!(applies[0].0, "edge-proxy");
        assert_eq!(applies[0].1.trusted_ca_sha256.len(), 2);
    }

    #[tokio::test]
    async fn trust_poll_is_idempotent_when_version_unchanged() {
        let hooks = FakeHooks::new(vec![Ok(Some(trust_read(3)))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();
        state
            .last_trust_seen_version
            .insert("edge-proxy".to_string(), 3);

        let (outcomes, changed) =
            run_trust_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::UpToDate { version: 3, .. }
        ));
        assert!(hooks.trust_applies.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn trust_poll_fires_on_first_sighting() {
        let hooks = FakeHooks::new(vec![Ok(Some(trust_read(1)))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_trust_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Applied { version: 1, .. }
        ));
    }

    #[tokio::test]
    async fn trust_poll_skips_malformed_payload_without_advancing() {
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 4,
            // Missing ca_bundle_pem.
            data: serde_json::json!({ "trusted_ca_sha256": ["a".repeat(64)] }),
        }))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_trust_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Malformed { version: 4, .. }
        ));
        assert!(state.last_trust_seen_version.is_empty());
        assert!(hooks.trust_applies.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn trust_poll_does_not_advance_when_apply_fails() {
        let hooks = FakeHooks::new(vec![Ok(Some(trust_read(2)))]).fail_applies();
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_trust_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::ApplyError { version: 2, .. }
        ));
        assert!(state.last_trust_seen_version.is_empty());
    }

    #[tokio::test]
    async fn trust_poll_reports_no_data_when_kv_missing() {
        let hooks = FakeHooks::new(vec![Ok(None)]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_trust_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(outcomes[0], PollApplyOutcome::NoData { .. }));
    }

    fn secret_id_read(version: u64, value: &str) -> KvReadWithVersion {
        KvReadWithVersion {
            version,
            data: serde_json::json!({ "secret_id": value }),
        }
    }

    #[tokio::test]
    async fn secret_id_poll_applies_on_new_version() {
        let hooks = FakeHooks::new(vec![Ok(Some(secret_id_read(2, "fresh-secret")))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_secret_id_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Applied { version: 2, .. }
        ));
        assert_eq!(
            state.last_secret_id_seen_version.get("edge-proxy"),
            Some(&2)
        );
        let applies = hooks.secret_id_applies.lock().unwrap();
        assert_eq!(applies.len(), 1);
        assert_eq!(
            applies[0],
            ("edge-proxy".to_string(), "fresh-secret".to_string())
        );
    }

    #[tokio::test]
    async fn secret_id_poll_is_idempotent_when_version_unchanged() {
        let hooks = FakeHooks::new(vec![Ok(Some(secret_id_read(2, "fresh-secret")))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();
        state
            .last_secret_id_seen_version
            .insert("edge-proxy".to_string(), 2);

        let (outcomes, changed) =
            run_secret_id_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::UpToDate { version: 2, .. }
        ));
        assert!(hooks.secret_id_applies.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn secret_id_poll_skips_malformed_payload_without_advancing() {
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 5,
            data: serde_json::json!({ "other": "x" }),
        }))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_secret_id_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Malformed { version: 5, .. }
        ));
        assert!(state.last_secret_id_seen_version.is_empty());
        assert!(hooks.secret_id_applies.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn secret_id_poll_does_not_advance_when_apply_fails() {
        let hooks = FakeHooks::new(vec![Ok(Some(secret_id_read(3, "fresh")))]).fail_applies();
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_secret_id_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::ApplyError { version: 3, .. }
        ));
        assert!(state.last_secret_id_seen_version.is_empty());
    }

    fn responder_hmac_read(version: u64, value: &str) -> KvReadWithVersion {
        KvReadWithVersion {
            version,
            data: serde_json::json!({ "hmac": value }),
        }
    }

    #[tokio::test]
    async fn responder_hmac_poll_applies_on_new_version() {
        let hooks = FakeHooks::new(vec![Ok(Some(responder_hmac_read(2, "fresh-hmac")))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_responder_hmac_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Applied { version: 2, .. }
        ));
        assert_eq!(
            state.last_responder_hmac_seen_version.get("edge-proxy"),
            Some(&2)
        );
        let applies = hooks.responder_hmac_applies.lock().unwrap();
        assert_eq!(applies.len(), 1);
        assert_eq!(
            applies[0],
            ("edge-proxy".to_string(), "fresh-hmac".to_string())
        );
    }

    #[tokio::test]
    async fn responder_hmac_poll_is_idempotent_when_version_unchanged() {
        let hooks = FakeHooks::new(vec![Ok(Some(responder_hmac_read(2, "fresh-hmac")))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();
        state
            .last_responder_hmac_seen_version
            .insert("edge-proxy".to_string(), 2);

        let (outcomes, changed) =
            run_responder_hmac_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::UpToDate { version: 2, .. }
        ));
        assert!(hooks.responder_hmac_applies.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn responder_hmac_poll_skips_malformed_payload_without_advancing() {
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 5,
            data: serde_json::json!({ "other": "x" }),
        }))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_responder_hmac_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Malformed { version: 5, .. }
        ));
        assert!(state.last_responder_hmac_seen_version.is_empty());
        assert!(hooks.responder_hmac_applies.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn responder_hmac_poll_does_not_advance_when_apply_fails() {
        let hooks = FakeHooks::new(vec![Ok(Some(responder_hmac_read(3, "fresh")))]).fail_applies();
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_responder_hmac_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::ApplyError { version: 3, .. }
        ));
        assert!(state.last_responder_hmac_seen_version.is_empty());
    }

    #[tokio::test]
    async fn responder_hmac_poll_fires_on_first_sighting() {
        let hooks = FakeHooks::new(vec![Ok(Some(responder_hmac_read(1, "hmac-v1")))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) =
            run_responder_hmac_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Applied { version: 1, .. }
        ));
    }

    fn eab_read(version: u64, kid: &str, hmac: &str) -> KvReadWithVersion {
        KvReadWithVersion {
            version,
            data: serde_json::json!({ "kid": kid, "hmac": hmac }),
        }
    }

    #[tokio::test]
    async fn eab_poll_applies_populated_on_new_version() {
        let hooks = FakeHooks::new(vec![Ok(Some(eab_read(2, "kid-1", "hmac-1")))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) = run_eab_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Applied { version: 2, .. }
        ));
        assert_eq!(state.last_eab_seen_version.get("edge-proxy"), Some(&2));
        let applies = hooks.eab_applies.lock().unwrap();
        assert_eq!(applies.len(), 1);
        assert_eq!(applies[0].0, "edge-proxy");
        assert_eq!(
            applies[0].1,
            EabPayload::Populated {
                kid: "kid-1".to_string(),
                hmac: "hmac-1".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn eab_poll_applies_clear_on_new_version() {
        let hooks = FakeHooks::new(vec![Ok(Some(eab_read(3, "", "")))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) = run_eab_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Applied { version: 3, .. }
        ));
        assert_eq!(state.last_eab_seen_version.get("edge-proxy"), Some(&3));
        let applies = hooks.eab_applies.lock().unwrap();
        assert_eq!(applies[0].1, EabPayload::Clear);
    }

    #[tokio::test]
    async fn eab_poll_is_idempotent_when_version_unchanged() {
        let hooks = FakeHooks::new(vec![Ok(Some(eab_read(2, "kid-1", "hmac-1")))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();
        state
            .last_eab_seen_version
            .insert("edge-proxy".to_string(), 2);

        let (outcomes, changed) = run_eab_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::UpToDate { version: 2, .. }
        ));
        assert!(hooks.eab_applies.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn eab_poll_skips_malformed_partial_payload_without_advancing() {
        // Partial shape (kid without hmac) must be rejected, not treated as a
        // clear, and the version must not advance so a corrected control-plane
        // write is retried.
        let hooks = FakeHooks::new(vec![Ok(Some(KvReadWithVersion {
            version: 5,
            data: serde_json::json!({ "kid": "kid-1", "hmac": "" }),
        }))]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) = run_eab_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Malformed { version: 5, .. }
        ));
        assert!(state.last_eab_seen_version.is_empty());
        assert!(hooks.eab_applies.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn eab_poll_does_not_advance_when_apply_fails() {
        let hooks = FakeHooks::new(vec![Ok(Some(eab_read(3, "kid-1", "hmac-1")))]).fail_applies();
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) = run_eab_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::ApplyError { version: 3, .. }
        ));
        assert!(state.last_eab_seen_version.is_empty());
    }

    #[tokio::test]
    async fn eab_poll_reports_no_data_when_kv_missing() {
        let hooks = FakeHooks::new(vec![Ok(None)]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let (outcomes, changed) = run_eab_poll_tick(&hooks, "secret", &services, &mut state).await;

        assert!(!changed);
        assert!(matches!(outcomes[0], PollApplyOutcome::NoData { .. }));
    }

    /// End-to-end apply: a populated payload writes `eab.json` (loadable back
    /// through `--eab-file`) and publishes the value into the shared
    /// `default_eab`; the subsequent clear removes the file and clears the
    /// in-memory value so `resolve_profile_eab` returns `None`.
    #[tokio::test]
    async fn apply_eab_to_state_writes_then_clears_file_and_memory() {
        use crate::profile::resolve_profile_eab;

        let dir = tempfile::tempdir().unwrap();
        let eab_path = dir.path().join("eab.json");
        let (tx, rx) = watch::channel(None);
        let handle = EabRefreshHandle {
            path: eab_path.clone(),
            sender: tx,
        };
        let shared = eab::SharedEab::from_receiver(rx);

        // Build a profile with no per-profile EAB so resolution falls through
        // to `default_eab`.
        let profile = eab_test_profile();

        apply_eab_to_state(
            &handle,
            &EabPayload::Populated {
                kid: "kid-1".to_string(),
                hmac: "hmac-1".to_string(),
            },
        )
        .await
        .expect("apply populated");

        assert!(eab_path.exists());
        let on_disk = eab::load_credentials(None, None, Some(eab_path.clone()))
            .await
            .expect("load")
            .expect("credentials present");
        assert_eq!(on_disk.kid, "kid-1");
        let resolved = resolve_profile_eab(&profile, shared.current()).expect("resolved eab");
        assert_eq!(resolved.kid, "kid-1");
        assert_eq!(resolved.hmac, "hmac-1");

        apply_eab_to_state(&handle, &EabPayload::Clear)
            .await
            .expect("apply clear");

        assert!(!eab_path.exists());
        assert!(shared.current().is_none());
        assert!(resolve_profile_eab(&profile, shared.current()).is_none());
    }

    fn eab_test_profile() -> config::DaemonProfileSettings {
        config::DaemonProfileSettings {
            service_name: "edge-proxy".to_string(),
            instance_id: "001".to_string(),
            hostname: "edge-node-01".to_string(),
            paths: config::Paths {
                cert: PathBuf::from("cert.pem"),
                key: PathBuf::from("key.pem"),
            },
            daemon: config::DaemonRuntimeSettings {
                check_interval: Duration::from_hours(1),
                renew_before: Duration::from_hours(1),
                check_jitter: Duration::from_secs(0),
            },
            retry: None,
            hooks: config::HookSettings::default(),
            eab: None,
            cert_group_gid: None,
        }
    }

    #[tokio::test]
    async fn hmac_refresh_lands_before_reissue_renewal_in_same_tick() {
        // Both a new responder-HMAC version and a pending reissue are
        // visible in the same KV snapshot. `read_kv_version` pops from the
        // end, so the HMAC read (consumed first, by the responder-HMAC
        // poll) is last; the reissue read (consumed by the reissue tick)
        // is first.
        let reissue_read = KvReadWithVersion {
            version: 5,
            data: serde_json::json!({
                "requested_at": "2026-04-19T12:34:56Z",
                "requester": "alice",
            }),
        };
        let hooks = FakeHooks::new(vec![
            Ok(Some(reissue_read)),
            Ok(Some(responder_hmac_read(2, "fresh-hmac"))),
        ]);
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();

        let outcome = run_hmac_refresh_then_reissue(&hooks, "secret", &services, &mut state).await;

        assert!(outcome.responder_hmac_changed);
        assert!(matches!(
            outcome.responder_hmac_outcomes[0],
            PollApplyOutcome::Applied { version: 2, .. }
        ));
        assert_eq!(hooks.renew_calls.lock().unwrap().len(), 1);

        // The HMAC write must be recorded strictly before the renewal so
        // the reissue's per-attempt `agent.toml` reload sees the fresh
        // secret.
        let op_log = hooks.op_log.lock().unwrap().clone();
        let apply_idx = op_log
            .iter()
            .position(|op| op == "apply_responder_hmac:edge-proxy")
            .expect("responder HMAC apply recorded");
        let renew_idx = op_log
            .iter()
            .position(|op| op == "renew:edge-proxy-domain")
            .expect("reissue renewal recorded");
        assert!(
            apply_idx < renew_idx,
            "responder HMAC must be applied before the reissue renewal, got {op_log:?}"
        );
    }

    #[tokio::test]
    async fn apply_responder_hmac_to_disk_upserts_acme_key() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agent.toml");
        std::fs::write(
            &config_path,
            "email = \"a@b.c\"\n\n[acme]\nhttp_responder_url = \"http://r\"\nhttp_responder_hmac = \"old\"\n",
        )
        .unwrap();

        apply_responder_hmac_to_disk(&config_path, "new-hmac")
            .await
            .expect("apply responder hmac");

        let updated = std::fs::read_to_string(&config_path).unwrap();
        assert!(updated.contains("http_responder_hmac = \"new-hmac\""));
        assert!(!updated.contains("\"old\""));
        // Operator-tuned keys/sections preserved.
        assert!(updated.contains("email = \"a@b.c\""));
        assert!(updated.contains("http_responder_url = \"http://r\""));
        let config_mode = std::fs::metadata(&config_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(config_mode, 0o600);
    }

    #[tokio::test]
    async fn poll_read_error_flags_relogin_for_token_failures() {
        let mut needs_relogin = false;
        let outcomes = vec![PollApplyOutcome::ReadError {
            service: "edge-proxy".to_string(),
            error: "OpenBao token is not set".to_string(),
        }];
        log_poll_outcomes("trust", &outcomes, &mut needs_relogin);
        assert!(needs_relogin);
    }

    #[test]
    fn reconcile_trust_rebuild_keeps_version_on_success() {
        let mut state = FastPollState::default();
        state
            .last_trust_seen_version
            .insert("edge-proxy".to_string(), 5);
        let before = state.last_trust_seen_version.clone();

        let persist = reconcile_trust_rebuild(&mut state, before, true);

        assert!(persist);
        assert_eq!(state.last_trust_seen_version.get("edge-proxy"), Some(&5));
    }

    #[test]
    fn reconcile_trust_rebuild_rolls_back_version_on_failure() {
        // Simulate a tick where the trust poll advanced the version from the
        // prior value (2) to a new one (5) but the client rebuild failed
        // (e.g. malformed `ca_bundle_pem` that only fails PEM/root-store
        // validation, which `parse_trust_payload` does not perform). The
        // version must roll back so the next tick retries rather than
        // reporting `UpToDate` and stranding on stale roots.
        let mut before = BTreeMap::new();
        before.insert("edge-proxy".to_string(), 2u64);
        let mut state = FastPollState::default();
        state
            .last_trust_seen_version
            .insert("edge-proxy".to_string(), 5);

        let persist = reconcile_trust_rebuild(&mut state, before, false);

        assert!(!persist);
        assert_eq!(state.last_trust_seen_version.get("edge-proxy"), Some(&2));
    }

    #[test]
    fn reconcile_trust_rebuild_rolls_back_first_ever_version_on_failure() {
        // First trust apply on a fresh agent (no prior version): a failed
        // rebuild must clear the entry entirely so the next tick retries.
        let mut state = FastPollState::default();
        state
            .last_trust_seen_version
            .insert("edge-proxy".to_string(), 1);

        let persist = reconcile_trust_rebuild(&mut state, BTreeMap::new(), false);

        assert!(!persist);
        assert!(state.last_trust_seen_version.is_empty());
    }

    #[tokio::test]
    async fn fast_poll_state_round_trip_persists_trust_and_secret_id_versions() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let mut state = FastPollState::default();
        state
            .last_trust_seen_version
            .insert("edge-proxy".to_string(), 4);
        state
            .last_secret_id_seen_version
            .insert("edge-proxy".to_string(), 9);
        state
            .last_responder_hmac_seen_version
            .insert("edge-proxy".to_string(), 6);
        state.save(&path).await.unwrap();

        let loaded = FastPollState::load(&path).await.unwrap();
        assert_eq!(loaded.last_trust_seen_version.get("edge-proxy"), Some(&4));
        assert_eq!(
            loaded.last_secret_id_seen_version.get("edge-proxy"),
            Some(&9)
        );
        assert_eq!(
            loaded.last_responder_hmac_seen_version.get("edge-proxy"),
            Some(&6)
        );
    }

    #[tokio::test]
    async fn apply_trust_to_disk_writes_bundle_and_upserts_trust_section() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        let config_path = dir.path().join("agent.toml");
        std::fs::write(
            &config_path,
            "email = \"a@b.c\"\n\n[acme]\nhttp_responder_url = \"http://r\"\n",
        )
        .unwrap();

        let mut settings = test_settings("edge-proxy");
        settings.trust.ca_bundle_path = Some(bundle_path.clone());

        let payload = TrustPayload {
            trusted_ca_sha256: vec!["a".repeat(64)],
            ca_bundle_pem: "-----BEGIN CERTIFICATE-----\npem\n-----END CERTIFICATE-----\n"
                .to_string(),
        };

        apply_trust_to_disk(&settings, &config_path, "edge-proxy", &payload)
            .await
            .expect("apply trust");

        // Bundle written world-readable (0o644).
        let bundle = std::fs::read_to_string(&bundle_path).unwrap();
        assert!(bundle.contains("BEGIN CERTIFICATE"));
        let bundle_mode = std::fs::metadata(&bundle_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(bundle_mode, 0o644);

        // Config gets a [trust] section but keeps operator-tuned sections.
        let updated = std::fs::read_to_string(&config_path).unwrap();
        assert!(updated.contains("[trust]"));
        assert!(updated.contains(&"a".repeat(64)));
        assert!(updated.contains("email = \"a@b.c\""));
        assert!(updated.contains("http_responder_url = \"http://r\""));
        let config_mode = std::fs::metadata(&config_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(config_mode, 0o600);
    }

    /// Trust-poll hook whose `apply_trust` performs the real on-disk write
    /// (`apply_trust_to_disk`). Used by the no-disk-write regression test so
    /// that if a malformed payload ever reached the apply stage the seeded
    /// files would visibly change. Only `read_kv_version` and `apply_trust`
    /// are exercised by `run_trust_poll_tick`; the rest are unreachable.
    struct DiskWritingTrustHooks {
        reads: std::sync::Mutex<std::collections::VecDeque<Result<Option<KvReadWithVersion>>>>,
        settings: config::Settings,
        config_path: PathBuf,
        applied: std::sync::atomic::AtomicUsize,
    }

    impl FastPollHooks for DiskWritingTrustHooks {
        fn read_kv_version(
            &self,
            _kv_mount: &str,
            _kv_path: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<Option<KvReadWithVersion>>> + Send + '_>>
        {
            let next = self.reads.lock().unwrap().pop_front().unwrap_or(Ok(None));
            Box::pin(async move { next })
        }

        fn apply_trust(
            &self,
            service: &str,
            payload: &TrustPayload,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            self.applied
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let settings = self.settings.clone();
            let config_path = self.config_path.clone();
            let service = service.to_string();
            let payload = payload.clone();
            Box::pin(async move {
                apply_trust_to_disk(&settings, &config_path, &service, &payload).await
            })
        }

        fn write_kv(
            &self,
            _: &str,
            _: &str,
            _: serde_json::Value,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            unreachable!("write_kv not used by trust poll")
        }

        fn trigger_renewal(
            &self,
            _: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            unreachable!("trigger_renewal not used by trust poll")
        }

        fn apply_secret_id(
            &self,
            _: &str,
            _: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            unreachable!("apply_secret_id not used by trust poll")
        }

        fn apply_responder_hmac(
            &self,
            _: &str,
            _: &str,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            unreachable!("apply_responder_hmac not used by trust poll")
        }

        fn apply_eab(
            &self,
            _: &str,
            _: &EabPayload,
        ) -> std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + '_>> {
            unreachable!("apply_eab not used by trust poll")
        }
    }

    /// Regression for issue #695 item 2: a malformed trust KV payload
    /// (non-PEM garbage, empty-certificate bundle, or a fingerprint absent
    /// from the bundle) is classified `Malformed` by the pre-apply parse
    /// gate, so `apply_trust` is never invoked, neither the CA bundle file
    /// nor `agent.toml` changes on disk, and `last_trust_seen_version` does
    /// not advance. This gate is scheme-independent: because `trust_changed`
    /// stays false, the loop's HTTPS rebuild/version-reconcile block is
    /// never entered, so both the pre-fix HTTPS failure (bundle poisoned,
    /// then version rolled back) and the pre-fix plaintext failure (bundle
    /// poisoned, version advanced with no retry) are prevented. A
    /// subsequent corrected payload applies normally.
    // Exercises three malformed shapes plus the corrected-payload recovery
    // in one place so the no-disk-write invariant is asserted together.
    #[allow(clippy::too_many_lines)]
    #[tokio::test]
    async fn malformed_trust_payload_never_reaches_disk() {
        let (good_fingerprints, good_bundle) = valid_trust_bundle();
        let valid_fingerprint = good_fingerprints.first().expect("fingerprint").clone();

        let malformed_cases = [
            // Non-PEM garbage bundle.
            serde_json::json!({
                "trusted_ca_sha256": [valid_fingerprint.clone()],
                "ca_bundle_pem": "not a certificate",
            }),
            // Syntactically valid PEM carrying no CERTIFICATE entries.
            serde_json::json!({
                "trusted_ca_sha256": [valid_fingerprint.clone()],
                "ca_bundle_pem": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
            }),
            // Well-formed but unrelated fingerprint not present in the bundle.
            serde_json::json!({
                "trusted_ca_sha256": ["a".repeat(64)],
                "ca_bundle_pem": good_bundle.clone(),
            }),
        ];

        for malformed in malformed_cases {
            let dir = tempfile::tempdir().unwrap();
            let bundle_path = dir.path().join("ca-bundle.pem");
            let config_path = dir.path().join("agent.toml");
            let original_bundle =
                "-----BEGIN CERTIFICATE-----\nORIGINAL\n-----END CERTIFICATE-----\n";
            let original_config = "email = \"a@b.c\"\n\n[acme]\nurl = \"http://r\"\n";
            std::fs::write(&bundle_path, original_bundle).unwrap();
            std::fs::write(&config_path, original_config).unwrap();

            let mut settings = test_settings("edge-proxy");
            settings.trust.ca_bundle_path = Some(bundle_path.clone());

            let hooks = DiskWritingTrustHooks {
                reads: std::sync::Mutex::new(std::collections::VecDeque::from(vec![Ok(Some(
                    KvReadWithVersion {
                        version: 5,
                        data: malformed.clone(),
                    },
                ))])),
                settings,
                config_path: config_path.clone(),
                applied: std::sync::atomic::AtomicUsize::new(0),
            };
            let services = services_single("edge-proxy", "edge-proxy-domain");
            let mut state = FastPollState::default();

            let (outcomes, changed) =
                run_trust_poll_tick(&hooks, "secret", &services, &mut state).await;

            assert!(!changed, "malformed payload must not change state");
            assert!(
                matches!(outcomes[0], PollApplyOutcome::Malformed { version: 5, .. }),
                "expected Malformed, got {:?}",
                outcomes[0]
            );
            assert_eq!(
                hooks.applied.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "apply_trust must never run for a malformed payload"
            );
            assert!(state.last_trust_seen_version.is_empty());
            assert_eq!(
                std::fs::read_to_string(&bundle_path).unwrap(),
                original_bundle,
                "CA bundle must be byte-identical"
            );
            assert_eq!(
                std::fs::read_to_string(&config_path).unwrap(),
                original_config,
                "agent.toml must be byte-identical"
            );
        }

        // A corrected payload applies normally against fresh state.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        let config_path = dir.path().join("agent.toml");
        std::fs::write(&bundle_path, "seed").unwrap();
        std::fs::write(&config_path, "email = \"a@b.c\"\n").unwrap();
        let mut settings = test_settings("edge-proxy");
        settings.trust.ca_bundle_path = Some(bundle_path.clone());
        let hooks = DiskWritingTrustHooks {
            reads: std::sync::Mutex::new(std::collections::VecDeque::from(vec![Ok(Some(
                KvReadWithVersion {
                    version: 6,
                    data: serde_json::json!({
                        "trusted_ca_sha256": good_fingerprints,
                        "ca_bundle_pem": good_bundle,
                    }),
                },
            ))])),
            settings,
            config_path: config_path.clone(),
            applied: std::sync::atomic::AtomicUsize::new(0),
        };
        let services = services_single("edge-proxy", "edge-proxy-domain");
        let mut state = FastPollState::default();
        let (outcomes, changed) =
            run_trust_poll_tick(&hooks, "secret", &services, &mut state).await;
        assert!(changed);
        assert!(matches!(
            outcomes[0],
            PollApplyOutcome::Applied { version: 6, .. }
        ));
        assert_eq!(state.last_trust_seen_version.get("edge-proxy"), Some(&6));
        assert!(
            std::fs::read_to_string(&bundle_path)
                .unwrap()
                .contains("BEGIN CERTIFICATE")
        );
    }

    #[tokio::test]
    async fn apply_trust_to_disk_errors_when_no_ca_bundle_path() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agent.toml");
        std::fs::write(&config_path, "email = \"a@b.c\"\n").unwrap();
        let settings = test_settings("edge-proxy");
        let payload = TrustPayload {
            trusted_ca_sha256: vec!["a".repeat(64)],
            ca_bundle_pem: "pem".to_string(),
        };
        assert!(
            apply_trust_to_disk(&settings, &config_path, "edge-proxy", &payload)
                .await
                .is_err()
        );
    }

    #[test]
    fn resolve_service_cert_group_policy_errors_on_disagreement() {
        let mut settings = test_settings("edge-proxy");
        // Two profiles for the same service disagree on cert_group_gid.
        let mut second = settings.profiles[0].clone();
        second.instance_id = "002".to_string();
        second.cert_group_gid = Some(5001);
        settings.profiles[0].cert_group_gid = Some(6001);
        settings.profiles.push(second);
        assert!(resolve_service_cert_group_policy(&settings, "edge-proxy").is_err());
    }

    #[test]
    fn resolve_service_cert_group_policy_uses_shared_gid() {
        let mut settings = test_settings("edge-proxy");
        settings.profiles[0].cert_group_gid = Some(5001);
        let policy = resolve_service_cert_group_policy(&settings, "edge-proxy").unwrap();
        assert_eq!(policy, CertGroupPolicy::with_gid(5001));
    }

    /// Builds a minimal [`config::Settings`] with one profile for `service`.
    fn test_settings(service: &str) -> config::Settings {
        let toml = format!(
            "email = \"a@b.c\"\n\
             server = \"https://ca.example/acme/directory\"\n\
             domain = \"example.internal\"\n\n\
             [[profiles]]\n\
             service_name = \"{service}\"\n\
             instance_id = \"001\"\n\
             hostname = \"node-01\"\n\n\
             [profiles.paths]\n\
             cert = \"/tmp/cert.pem\"\n\
             key = \"/tmp/key.pem\"\n"
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        std::fs::write(&path, toml).unwrap();
        config::Settings::new(Some(path)).expect("build settings")
    }
}

#[cfg(test)]
mod pin_rotation_tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    struct TestCa {
        pem: String,
        fingerprint: String,
        issuer: Issuer<'static, KeyPair>,
    }

    fn generate_ca(common_name: &str) -> TestCa {
        let key = KeyPair::generate().expect("generate CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-signed CA");
        let pem = cert.pem();
        let fingerprint = crate::tls::sha256_hex(cert.der().as_ref());
        let issuer = Issuer::new(params, key);
        TestCa {
            pem,
            fingerprint,
            issuer,
        }
    }

    fn sign_server_leaf(ca: &TestCa) -> (Vec<u8>, Vec<u8>) {
        let key = KeyPair::generate().expect("generate server key");
        let mut params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params.is_ca = IsCa::NoCa;
        let cert = params
            .signed_by(&key, &ca.issuer)
            .expect("signed server cert");
        (cert.der().to_vec(), key.serialize_der())
    }

    async fn start_tls_server(cert_der: Vec<u8>, key_der: Vec<u8>) -> u16 {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = CertificateDer::from(cert_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server TLS config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 4096];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        port
    }

    fn openbao_settings(url: &str, bundle_path: &Path) -> config::OpenBaoSettings {
        config::OpenBaoSettings {
            url: url.to_string(),
            allow_plaintext_http: false,
            kv_mount: "secret".to_string(),
            role_id_path: PathBuf::from("/unused/role_id"),
            secret_id_path: PathBuf::from("/unused/secret_id"),
            ca_bundle_path: Some(bundle_path.to_path_buf()),
            fast_poll_interval: Duration::from_secs(5),
            state_path: PathBuf::from("/unused/state.json"),
        }
    }

    /// Item #695: with non-empty pins the fast-poll HTTPS client rejects an
    /// endpoint whose chain does not terminate at a pinned CA, and the
    /// post-trust-apply rebuild pins to the FRESHLY applied anchors read from
    /// `agent.toml` — not the startup snapshot. This drives the production
    /// rebuild decision (`rebuild_client_after_trust_apply`, the same helper
    /// the fast-poll loop calls) rather than re-reading the pins by hand: the
    /// loop starts holding a client pinned to the retired CA, the endpoint is
    /// rotated to a new CA, and the helper must swap in a client that reaches
    /// it. The final assertion fails if the rebuild reuses the stale startup
    /// snapshot instead of the freshly written pin.
    #[tokio::test]
    async fn rebuild_pins_to_freshly_applied_anchors_not_startup_snapshot() {
        let ca_old = generate_ca("Old Root CA");
        let ca_new = generate_ca("New Root CA");

        // The rotated endpoint presents a leaf signed by the NEW CA.
        let (leaf_der, leaf_key) = sign_server_leaf(&ca_new);
        let port = start_tls_server(leaf_der, leaf_key).await;
        let url = format!("https://localhost:{port}");

        // The on-disk bundle carries BOTH anchors; the pin set decides
        // which is a usable trust anchor for this channel.
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        std::fs::write(&bundle_path, format!("{}{}", ca_old.pem, ca_new.pem)).unwrap();
        let openbao = openbao_settings(&url, &bundle_path);

        // The loop starts holding a client pinned to the STARTUP snapshot
        // (old CA); it cannot reach the rotated endpoint.
        let client = Arc::new(Mutex::new(
            build_openbao_client(&openbao, std::slice::from_ref(&ca_old.fingerprint))
                .expect("build startup-pinned client"),
        ));
        assert!(
            client.lock().await.health_check().await.is_err(),
            "the startup-pinned client (retired CA) must reject the rotated endpoint"
        );

        // Rotation has just rewritten agent.toml with the NEW pin. Drive the
        // production rebuild helper: it MUST re-read the fresh pin from
        // agent.toml, not reuse the startup snapshot. If it reused the stale
        // snapshot the swapped-in client would still be pinned to the old CA
        // and the health check below would fail.
        let config_path = dir.path().join("agent.toml");
        std::fs::write(
            &config_path,
            format!(
                "[trust]\ntrusted_ca_sha256 = [\"{}\"]\n",
                ca_new.fingerprint
            ),
        )
        .unwrap();

        let mut needs_relogin = false;
        let rebuilt_ok =
            rebuild_client_after_trust_apply(&client, &openbao, &config_path, &mut needs_relogin)
                .await;
        assert!(
            rebuilt_ok,
            "recovering the freshly applied pins and rebuilding must succeed"
        );
        // The stalled/empty test endpoint cannot satisfy an AppRole login, so
        // the post-rebuild re-login is expected to fail and rearm relogin —
        // the rebuild itself still succeeded because the roots were swapped in
        // before the login attempt.
        assert!(
            needs_relogin,
            "a failed post-rebuild re-login must rearm relogin"
        );
        assert!(
            client.lock().await.health_check().await.is_ok(),
            "after the rebuild the swapped-in client must reach the rotated endpoint using the freshly applied pin (fails if the rebuild reused the startup snapshot)"
        );
    }

    /// Item #695 fail-closed guard: when `agent.toml` carries no
    /// `[trust].trusted_ca_sha256` after a trust apply, the production rebuild
    /// helper must return `false` so the caller rolls the trust version back,
    /// rather than silently rebuilding with unpinned bundle-anchored trust.
    #[tokio::test]
    async fn rebuild_fails_closed_when_fresh_pins_unrecoverable() {
        let ca = generate_ca("Root CA");
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        std::fs::write(&bundle_path, &ca.pem).unwrap();
        let openbao = openbao_settings("https://localhost:8200", &bundle_path);
        let client = Arc::new(Mutex::new(
            build_openbao_client(&openbao, std::slice::from_ref(&ca.fingerprint))
                .expect("build client"),
        ));

        // A config with no [trust].trusted_ca_sha256 is an unrecoverable pin
        // read after an apply, not an unpinned deployment.
        let config_path = dir.path().join("agent.toml");
        std::fs::write(&config_path, "email = \"a@b.c\"\n").unwrap();

        let mut needs_relogin = false;
        let rebuilt_ok =
            rebuild_client_after_trust_apply(&client, &openbao, &config_path, &mut needs_relogin)
                .await;
        assert!(
            !rebuilt_ok,
            "unrecoverable fresh pins must fail the rebuild closed so the version rolls back"
        );
    }

    #[tokio::test]
    async fn read_trust_pins_from_config_errs_when_pins_absent() {
        // A config with no [trust].trusted_ca_sha256 must NOT silently
        // recover an empty (bundle-anchored) pin set: since every applied
        // trust payload carries non-empty pins, an empty read here means a
        // rotation would downgrade pinned trust. The reader errors so the
        // caller rolls the trust version back instead.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("agent.toml");
        std::fs::write(&config_path, "email = \"a@b.c\"\n").unwrap();
        assert!(read_trust_pins_from_config(&config_path).await.is_err());
    }

    #[tokio::test]
    async fn read_trust_pins_from_config_errs_when_unreadable() {
        // A missing config file is a recovery failure, not an unpinned
        // deployment.
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("does-not-exist.toml");
        assert!(read_trust_pins_from_config(&config_path).await.is_err());
    }
}
