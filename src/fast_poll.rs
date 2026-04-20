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

use crate::openbao::{KvReadWithVersion, OpenBaoClient};
use crate::trust_bootstrap::{
    REISSUE_COMPLETED_AT_KEY, REISSUE_COMPLETED_VERSION_KEY, REISSUE_REQUESTED_AT_KEY,
    REISSUE_REQUESTER_KEY, SERVICE_KV_BASE, SERVICE_REISSUE_KV_SUFFIX,
};
use crate::{config, eab};

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

/// Attaches an [`OpenBaoClient`] + renewal trigger to the generic
/// [`FastPollHooks`] trait so the daemon can drive [`run_fast_poll_tick`]
/// against live infrastructure.
pub(crate) struct LiveFastPollHooks<F> {
    pub(crate) client: Arc<Mutex<OpenBaoClient>>,
    pub(crate) trigger: F,
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
    default_eab: Option<eab::EabCredentials>,
    semaphore: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
    renew_fn: impl Fn(
        config::DaemonProfileSettings,
        Option<eab::EabCredentials>,
        Arc<Semaphore>,
    ) -> BoxRenew
    + Send
    + Sync
    + 'static,
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

    // Share the OpenBaoClient across hooks and re-login helpers.
    let client = build_openbao_client(&openbao)?;
    let client = Arc::new(Mutex::new(client));
    if let Err(err) = login(&client, &openbao).await {
        warn!("Initial OpenBao AppRole login failed: {err:#}. Will retry on the next tick.");
    }

    let renew_fn = Arc::new(renew_fn);
    let settings_for_hooks = Arc::clone(&settings);
    let default_eab_for_hooks = default_eab.clone();
    let semaphore_for_hooks = Arc::clone(&semaphore);
    let renew_fn_for_hooks = Arc::clone(&renew_fn);
    let hooks = LiveFastPollHooks {
        client: Arc::clone(&client),
        trigger: move |profile_label: String| {
            let settings = Arc::clone(&settings_for_hooks);
            let default_eab = default_eab_for_hooks.clone();
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
                renew_fn(profile, default_eab, semaphore).await
            }
        },
    };

    loop {
        if *shutdown.borrow() {
            info!("Shutdown received; exiting fast-poll loop.");
            break;
        }

        let report = run_fast_poll_tick(&hooks, &openbao.kv_mount, &services, &mut state).await;
        let mut needs_relogin = false;
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

        if report.state_changed
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

fn build_openbao_client(openbao: &config::OpenBaoSettings) -> Result<OpenBaoClient> {
    if openbao.url.starts_with("https://") {
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
        OpenBaoClient::with_pem_trust(&openbao.url, &pem, &[])
            .context("Failed to build OpenBao client with CA bundle")
    } else {
        OpenBaoClient::new(&openbao.url).context("Failed to build OpenBao client")
    }
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
    }

    impl FakeHooks {
        fn new(reads: Vec<Result<Option<KvReadWithVersion>>>) -> Self {
            Self {
                read: std::sync::Mutex::new(reads),
                writes: std::sync::Mutex::new(Vec::new()),
                renew_calls: std::sync::Mutex::new(Vec::new()),
                write_outcomes: std::sync::Mutex::new(Vec::new()),
                failing_profiles: std::sync::Mutex::new(std::collections::HashSet::new()),
            }
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
}
