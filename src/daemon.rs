use std::collections::BTreeMap;
use std::future::Future;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt as _;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::sync::PoisonError;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

// Used by the deployment state file's reader and by the Linux-only
// registrar handler build below, the two fallible compositions in this
// module.
use anyhow::Context as _;
use tokio::sync::{Mutex as TokioMutex, Semaphore, watch};
use tracing::{error, info, warn};

#[cfg(target_os = "linux")]
use crate::registrar::AuditStoreMountGate;
use crate::registrar::RegistrarEndpoint;
use crate::{acme, cert_chain, config, eab, fast_poll, hooks, profile, utils};

const DEFAULT_AGENT_CONFIG_PATH: &str = "agent.toml";

/// The watch-based stop signal one daemon invocation is shut down
/// through.
///
/// It exists because a `SIGHUP` reload used to be an `abort()` on the
/// daemon task, and an abort is not a shutdown: it drops whatever the
/// task owned at whichever `.await` each part of it had reached. That
/// was survivable while the daemon owned only renewal loops. It is not
/// survivable now that it may own the registrar endpoint, whose accept
/// task and connection fleet have to stop accepting, drain, and be
/// joined — in that order — before the invocation they belong to is
/// joined.
///
/// So the signal is the caller's, not the daemon's. `bootroot-agent`
/// holds it across the reload loop and asks for a stop; the daemon's own
/// `SIGTERM`/`Ctrl-C` handler feeds the same channel, so process
/// shutdown and reload are one path with one set of guarantees rather
/// than two.
#[derive(Clone, Debug)]
pub struct DaemonShutdown {
    sender: Arc<watch::Sender<bool>>,
    receiver: watch::Receiver<bool>,
}

impl DaemonShutdown {
    /// Creates a fresh, un-triggered stop signal.
    #[must_use]
    pub fn new() -> Self {
        let (sender, receiver) = watch::channel(false);
        Self {
            sender: Arc::new(sender),
            receiver,
        }
    }

    /// Asks every task holding a receiver to stop.
    ///
    /// Idempotent, and safe to call after the daemon has already
    /// finished: the sender is held alive by this handle, so there is no
    /// closed-channel case to handle.
    pub fn stop(&self) {
        let _ = self.sender.send(true);
    }

    /// Returns a receiver for a task that wants to watch the signal.
    #[must_use]
    pub fn receiver(&self) -> watch::Receiver<bool> {
        self.receiver.clone()
    }

    /// Resolves once a stop has been asked for, including when it was
    /// asked for before this call.
    pub async fn stopped(&self) {
        let mut receiver = self.receiver.clone();
        loop {
            if *receiver.borrow_and_update() {
                return;
            }
            if receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Default for DaemonShutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone)]
struct IssuanceRuntime {
    config_path: PathBuf,
    insecure_mode: bool,
    cli_overrides: config::CliOverrides,
}

/// Per-profile single-flight registry.
///
/// Serialises issuance for a given profile across the periodic check loop
/// and the fast-poll force-reissue path. Without this the two triggers
/// could both observe an old certificate on disk and race to the ACME
/// server: the fast-poll path acquires the shared concurrency semaphore
/// and starts issuing, while a periodic tick that lands around the same
/// moment sees the pre-rotation cert via `should_renew()`, concludes
/// "needs renewal", and queues a second issuance once a semaphore permit
/// frees up. The lock is held across the whole decision-and-issue span
/// so the periodic path re-reads the cert *after* acquisition and sees
/// the freshly-rotated copy a force-reissue has already written.
pub(crate) struct ProfileLocks {
    map: StdMutex<BTreeMap<String, Arc<TokioMutex<()>>>>,
}

impl ProfileLocks {
    pub(crate) fn new() -> Self {
        Self {
            map: StdMutex::new(BTreeMap::new()),
        }
    }

    /// Returns the per-profile mutex, creating it on first access.
    pub(crate) fn for_profile(&self, profile_label: &str) -> Arc<TokioMutex<()>> {
        let mut guard = self
            .map
            .lock()
            .expect("ProfileLocks registry mutex poisoned");
        Arc::clone(
            guard
                .entry(profile_label.to_string())
                .or_insert_with(|| Arc::new(TokioMutex::new(()))),
        )
    }
}

impl Default for ProfileLocks {
    fn default() -> Self {
        Self::new()
    }
}

/// Everything one daemon invocation is given.
///
/// A struct rather than an argument list because the reload loop builds
/// most of it afresh per invocation and carries two members —
/// [`DaemonInvocation::shutdown`] and
/// [`DaemonInvocation::registrar_endpoint`] — *across* invocations
/// unchanged. Naming them at the call site is what makes that split
/// visible.
pub struct DaemonInvocation {
    /// The settings this invocation runs under.
    pub settings: Arc<config::Settings>,
    /// The EAB credentials in force at startup, if any.
    pub default_eab: Option<eab::EabCredentials>,
    /// The `--eab-file` path the fast-poll loop refreshes EAB through.
    pub eab_refresh_path: Option<PathBuf>,
    /// The agent config path, for reload-driven rewrites.
    pub config_path: Option<PathBuf>,
    /// Whether certificate verification is relaxed for local testing.
    pub insecure_mode: bool,
    /// CLI overrides that must survive a config reload.
    pub cli_overrides: config::CliOverrides,
    /// The stop signal, held by the caller across reloads.
    pub shutdown: DaemonShutdown,
    /// The activated registrar endpoint, held by the caller across
    /// reloads so its socket inode survives one.
    pub registrar_endpoint: RegistrarEndpoint,
}

/// Runs the agent daemon loop for all profiles.
///
/// # Errors
/// Returns an error if issuance or shutdown handling fails.
// The daemon composes lifecycle-owned services in one place; extracting the
// registrar maintenance wiring would make shutdown ownership less visible.
#[allow(clippy::too_many_lines)]
pub(crate) async fn run_daemon(invocation: DaemonInvocation) -> anyhow::Result<()> {
    let DaemonInvocation {
        settings,
        default_eab,
        eab_refresh_path,
        config_path,
        insecure_mode,
        cli_overrides,
        shutdown,
        registrar_endpoint,
    } = invocation;
    let max_concurrent = profile::max_concurrent_issuances(&settings)?;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));

    #[cfg(target_os = "linux")]
    let registrar_service = resolve_registrar_service(&registrar_endpoint, &settings).await?;
    #[cfg(not(target_os = "linux"))]
    let _ = &registrar_endpoint;
    let profile_locks = Arc::new(ProfileLocks::new());
    let shutdown_rx = shutdown.receiver();
    let runtime = IssuanceRuntime {
        config_path: resolve_config_path(config_path.as_deref()),
        insecure_mode,
        cli_overrides,
    };

    // `default_eab` becomes shared, live-readable state: both the periodic
    // check loop and the fast-poll force-reissue path read the current value
    // at issuance time, and the fast-poll loop updates it in place when it
    // observes a newer `eab` KV version. The sender is handed to the fast-poll
    // loop only when EAB is sourced from `--eab-file` (`eab_refresh_path` is
    // `Some`); otherwise it is dropped and the value stays fixed at startup.
    let (eab_tx, eab_rx) = watch::channel(default_eab);
    let shared_eab = eab::SharedEab::from_receiver(eab_rx);

    let shutdown_handle = spawn_shutdown_watcher(shutdown);

    let mut handles = Vec::new();

    #[cfg(target_os = "linux")]
    let registrar_maintenance = if let Some((endpoint, built)) = registrar_service {
        let BuiltRegistrarHandler {
            handler,
            maintenance,
        } = built;
        // Before the accept task, deliberately: the adapter initializes
        // the per-leaf renewal state from the certificates start-time
        // issuance has already made usable, and that reading happens
        // before the endpoint begins serving.
        spawn_registrar_cert_renewal(
            &mut handles,
            &settings,
            Arc::clone(&endpoint),
            insecure_mode,
            &shutdown_rx,
        )
        .await;
        spawn_registrar_endpoint(
            &mut handles,
            endpoint,
            handler,
            maintenance
                .as_ref()
                .map(|maintenance| Arc::clone(&maintenance.coalescing)),
            &shutdown_rx,
        );
        maintenance
    } else {
        None
    };
    #[cfg(not(target_os = "linux"))]
    let registrar_maintenance = None;
    spawn_openbao_audit_rotation(&mut handles, &settings, &shutdown_rx, registrar_maintenance);
    for profile in settings.profiles.clone() {
        let settings = Arc::clone(&settings);
        let semaphore = Arc::clone(&semaphore);
        let profile_locks = Arc::clone(&profile_locks);
        let shutdown_rx = shutdown_rx.clone();
        let shared_eab = shared_eab.clone();
        let runtime = runtime.clone();

        handles.push(tokio::spawn(async move {
            run_profile_daemon(
                settings,
                profile,
                shared_eab,
                semaphore,
                profile_locks,
                shutdown_rx,
                runtime,
            )
            .await
        }));
    }

    if settings.openbao.is_some() {
        let settings_for_loop = Arc::clone(&settings);
        let settings_for_renew = Arc::clone(&settings);
        let shared_eab_for_renew = shared_eab.clone();
        let semaphore_for_fast = Arc::clone(&semaphore);
        let profile_locks_for_fast = Arc::clone(&profile_locks);
        let shutdown_rx_fast = shutdown_rx.clone();
        let config_path_for_fast = runtime.config_path.clone();
        let runtime_for_renew = runtime.clone();
        let eab_refresh = eab_refresh_path.map(|path| fast_poll::EabRefreshHandle {
            path,
            sender: eab_tx,
        });
        handles.push(tokio::spawn(async move {
            let renew = move |profile: config::DaemonProfileSettings,
                              semaphore: Arc<Semaphore>|
                  -> fast_poll::BoxRenew {
                let settings = Arc::clone(&settings_for_renew);
                let profile_locks = Arc::clone(&profile_locks_for_fast);
                let runtime = runtime_for_renew.clone();
                let shared_eab = shared_eab_for_renew.clone();
                Box::pin(async move {
                    force_renew_profile(
                        &settings,
                        &profile,
                        shared_eab.current(),
                        semaphore,
                        &profile_locks,
                        &runtime,
                    )
                    .await
                })
            };
            fast_poll::run_fast_poll_loop(
                settings_for_loop,
                config_path_for_fast,
                eab_refresh,
                semaphore_for_fast,
                shutdown_rx_fast,
                renew,
            )
            .await
        }));
    }

    let _ = shutdown_handle.await;
    collect_task_results(handles, "daemon").await
}

/// Spawns the task that ends this invocation.
///
/// The process signal and the caller's stop are the same stop: either
/// one arriving ends this task, which then sets the watch, so a
/// `SIGHUP`-driven reload and a `SIGTERM` converge on one shutdown path
/// with one set of guarantees rather than two.
fn spawn_shutdown_watcher(shutdown: DaemonShutdown) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        tokio::select! {
            result = wait_for_shutdown() => {
                if let Err(err) = result {
                    error!("Shutdown signal handler error: {err}");
                }
            }
            () = shutdown.stopped() => {}
        }
        shutdown.stop();
    })
}

/// The default secrets directory `bootroot init` records nothing for.
///
/// The CLI resolves an absent `secrets_dir` member to this same name
/// through `StateFile::secrets_dir` (`src/state.rs`). That constant is
/// in the binary crate and this is the library, so the value is restated
/// here rather than reached for across the boundary. A test in that
/// crate fails if `StateFile`'s fallback ever stops being this name.
const DEFAULT_STATE_SECRETS_DIR: &str = "secrets";

/// The three members the daemon reads out of the deployment's
/// `state.json`, and nothing else about that file.
///
/// `bootroot init` records the `OpenBao` URL, the KV mount and the
/// secrets directory there, and `StateFile` — the type that owns the
/// whole inventory — is a module of the **binary** crate, unreachable
/// from the library where `run_daemon`, the endpoint and the verb layer
/// live. So this projection crosses that boundary and makes exactly
/// these three member names a contract between the two binaries; every
/// other member is deliberately tolerated and ignored, so the CLI's
/// inventory can grow a field without breaking a daemon that never looks
/// at it.
///
/// It derives [`serde::Deserialize`] and **not** `Serialize` on purpose:
/// a serializer here is how a later edit comes to write an operator's
/// state file back out with three fields and lose the rest.
#[derive(Debug, serde::Deserialize)]
pub(crate) struct RegistrarStateProjection {
    /// The URL `bootroot init` recorded for this deployment's
    /// `OpenBao`. Must be `https://`.
    #[serde(default)]
    pub(crate) openbao_url: String,
    /// The KV v2 mount every registrar path is written under.
    #[serde(default)]
    pub(crate) kv_mount: String,
    /// The recorded secrets directory, absent on a deployment that never
    /// passed `--secrets-dir`.
    #[serde(default)]
    pub(crate) secrets_dir: Option<PathBuf>,
}

/// Reads the three members the registrar surface needs out of the
/// `state.json` that `[registrar] state_file` names.
///
/// Every way this can fail names itself: which key, which path and which
/// member was at fault.
///
/// # Errors
///
/// Returns an error when the file cannot be read, is not JSON, carries
/// an absent or empty `openbao_url` or `kv_mount`, or carries an
/// `openbao_url` that is not `https://`.
pub(crate) fn read_registrar_state(state_file: &Path) -> anyhow::Result<RegistrarStateProjection> {
    let bytes = std::fs::read(state_file).with_context(|| {
        format!(
            "reading the deployment state file registrar.state_file names at {}",
            state_file.display()
        )
    })?;
    let state: RegistrarStateProjection = serde_json::from_slice(&bytes).with_context(|| {
        format!(
            "parsing the deployment state file registrar.state_file names at {}",
            state_file.display()
        )
    })?;
    if state.openbao_url.trim().is_empty() {
        anyhow::bail!(
            "the deployment state file at {} carries no openbao_url; the registrar endpoint has \
             no other source for it",
            state_file.display()
        );
    }
    if state.kv_mount.trim().is_empty() {
        anyhow::bail!(
            "the deployment state file at {} carries no kv_mount; the registrar endpoint has no \
             other source for it",
            state_file.display()
        );
    }
    if !config::openbao_url_is_https(&state.openbao_url) {
        anyhow::bail!(
            "the openbao_url recorded in the deployment state file at {} is not https://; the \
             registrar's privileged credential authenticates by client certificate and refuses \
             a plaintext URL",
            state_file.display()
        );
    }
    Ok(state)
}

/// Resolves the secrets directory the recorded state names.
///
/// A relative value — including the `secrets` default, which is what a
/// host that never passed `--secrets-dir` has — resolves against the
/// **state file's own directory**, never against the process working
/// directory: `state_file` is absolute, `bootroot init` writes
/// `state.json` and `secrets/` side by side in the directory it is run
/// from, and a daemon started by a socket unit has no working directory
/// worth resolving against.
pub(crate) fn resolve_secrets_dir(state_file: &Path, recorded: Option<&Path>) -> PathBuf {
    let recorded = recorded.unwrap_or_else(|| Path::new(DEFAULT_STATE_SECRETS_DIR));
    if recorded.is_absolute() {
        return recorded.to_path_buf();
    }
    match state_file.parent() {
        Some(parent) => parent.join(recorded),
        None => recorded.to_path_buf(),
    }
}

/// Renders a configured duration as the `<n>s` form `OpenBao` parses.
///
/// Validation has already held every one of these to a whole number of
/// seconds, so nothing is truncated here.
#[cfg(target_os = "linux")]
fn openbao_duration(value: Duration) -> String {
    format!("{}s", value.as_secs())
}

/// Builds the fixed per-issuance `secret_id` options the verb layer is
/// constructed with.
///
/// `metadata` is deliberately not exposed and is fixed to `None`.
/// `OpenBao` echoes metadata back on lookup, and bootroot's own record
/// of who asked for what is the audit trail this daemon writes; a
/// second, operator-typed, unvalidated one attached to every issued
/// `secret_id` is not a knob this endpoint grows. `ttl` is absent unless
/// `secret_id_ttl` is set, which leaves the role-level TTL governing.
#[cfg(target_os = "linux")]
fn registrar_secret_id_options(
    registrar: &config::RegistrarSettings,
) -> crate::openbao::SecretIdOptions {
    crate::openbao::SecretIdOptions {
        ttl: registrar.secret_id_ttl.map(openbao_duration),
        num_uses: Some(registrar.secret_id_num_uses),
        metadata: None,
        token_bound_cidrs: registrar.secret_id_token_bound_cidrs.clone(),
    }
}

/// Builds the production registrar request handler from one
/// invocation's settings.
///
/// The fallible half of the handler's construction, and the crate's only
/// call site of `RegistrarVerbs::internal`. Everything it opens — the
/// rendered provisioning config, the deployment state file, the audit
/// record store, the internal credential — is opened here and only here,
/// so a host whose endpoint is disabled never touches any of them.
///
/// Called before anything is spawned, so a failure fails the whole
/// invocation rather than leaving the socket adopted with no accept
/// task: a systemd-activated socket with nobody accepting turns every
/// caller into a hang, which is strictly worse than a failed start.
///
/// # Errors
///
/// Returns an error naming the dependency at fault: an absent
/// `registrar.state_file`, a state file that cannot be read or parsed or
/// whose recorded members are unusable, a resolved secrets directory
/// that does not exist, an unreadable deployment root, a provisioning
/// config that is absent or fails its digest gate, a `max_wrap_ttl` that
/// is not a grantable ceiling, an audit store that cannot be opened, and
/// an absent, invalid or stale internal credential.
#[cfg(target_os = "linux")]
// This is the one fallible composition of registrar dependencies.
#[allow(clippy::too_many_lines)]
pub(crate) async fn build_registrar_handler(
    settings: &config::Settings,
) -> anyhow::Result<BuiltRegistrarHandler> {
    use crate::registrar::audit::{AuditRecordStore, AuditStoreSettings};
    use crate::registrar::config::RegistrarConfig;
    use crate::registrar::endpoint::production::ProductionHandler;
    use crate::registrar::endpoint::protocol::{LimiterHealth, RegistrarHealth};
    use crate::registrar::internal::{InternalCredential, active_root_fingerprint};
    use crate::registrar::verbs::coalescing::CoalescingLimitedInvocationSink;
    use crate::registrar::verbs::limiter::{
        CountingLimitedInvocationSink, VerbRateLimiter, VerbRateLimiterSettings,
    };
    use crate::registrar::verbs::wrap_ttl::WrapTtlPolicy;
    use crate::registrar::verbs::{InternalVerbsSource, RegistrarVerbs};

    let registrar = &settings.registrar;
    let state_file = registrar.state_file.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "registrar.state_file is required when registrar_endpoint.enabled is true, and no \
             value was configured"
        )
    })?;
    let state = read_registrar_state(state_file)?;
    let secrets_dir = resolve_secrets_dir(state_file, state.secrets_dir.as_deref());
    if !secrets_dir.is_dir() {
        anyhow::bail!(
            "the secrets directory the deployment state file at {} resolves to, {}, is not a \
             directory",
            state_file.display(),
            secrets_dir.display()
        );
    }
    let active_root = active_root_fingerprint(&secrets_dir).with_context(|| {
        format!(
            "reading the deployment's active root fingerprint below {}",
            secrets_dir.display()
        )
    })?;

    let provisioning =
        RegistrarConfig::load(&registrar.provisioning_config_path).with_context(|| {
            format!(
                "loading the rendered registrar config registrar.provisioning_config_path names \
                 at {}",
                registrar.provisioning_config_path.display()
            )
        })?;

    let maximum = time::Duration::try_from(registrar.max_wrap_ttl).map_err(|_| {
        anyhow::anyhow!("registrar.max_wrap_ttl is outside the range a duration can carry")
    })?;
    let wrap_ttl_policy = WrapTtlPolicy::new(maximum)
        .map_err(|refusal| anyhow::anyhow!("registrar.max_wrap_ttl is unusable: {refusal}"))?;

    // The credential is loaded before the audit store on purpose, in
    // cost order: an absent, invalid or superseded credential is settled
    // without creating or touching the audit trail. It is loaded rather
    // than borrowed from the verbs because `RegistrarVerbs` builds its
    // privileged client inside itself and exposes neither it nor the
    // credential, and the anchor read needs one of its own.
    let credential = InternalCredential::load(&secrets_dir, &state.openbao_url, &active_root)
        .context("loading the bootroot-internal credential for the CA-anchor read")?;

    let audit_store_settings = AuditStoreSettings {
        dir: registrar.audit_record_dir.clone(),
        max_file_bytes: registrar.audit_max_file_bytes,
        max_retained_files: registrar.audit_max_retained_files,
    };
    #[cfg(test)]
    let audit_store = if registrar.open_audit_store_as_test_user {
        AuditRecordStore::open_for_tests(audit_store_settings).await
    } else {
        AuditRecordStore::open(audit_store_settings).await
    };
    #[cfg(not(test))]
    let audit_store = AuditRecordStore::open(audit_store_settings).await;
    let audit_store = audit_store.with_context(|| {
        format!(
            "opening the registrar audit record store at {}",
            registrar.audit_record_dir.display()
        )
    })?;

    let secret_id_options = registrar_secret_id_options(registrar);

    // The shipped counting sink rather than the no-op one: its two
    // counters are what an operator surface reads to tell a stalled
    // bring-up from a flood of malformed input, and they cost two
    // atomics. The limiter keeps its own handle on the sink, so nothing
    // here has to retain one for the counters to accumulate.
    let counts = Arc::new(CountingLimitedInvocationSink::new());
    let coalescing = Arc::new(CoalescingLimitedInvocationSink::new(
        Arc::clone(&counts),
        audit_store.clone(),
        registrar.rate_limit_coalesce_window_seconds,
    ));
    let limiter =
        VerbRateLimiter::new(VerbRateLimiterSettings::from(registrar), coalescing.clone());

    let verbs = RegistrarVerbs::internal(&InternalVerbsSource {
        secrets_dir: &secrets_dir,
        openbao_url: &state.openbao_url,
        active_root_fingerprint: &active_root,
        kv_mount: &state.kv_mount,
        config: &provisioning,
        secret_id_options: &secret_id_options,
        token_ttl: &openbao_duration(registrar.role_token_ttl),
        secret_id_ttl: &openbao_duration(registrar.role_secret_id_ttl),
        wrap_ttl_policy: &wrap_ttl_policy,
        audit_store: &audit_store,
        limiter: &limiter,
    })
    .context("building the registrar verb service from the bootroot-internal credential")?;

    let health = Arc::new(StdMutex::new(RegistrarHealth {
        limiter: LimiterHealth {
            limited_predecision_refusal: 0,
            limited_admission: 0,
        },
    }));
    Ok(BuiltRegistrarHandler {
        handler: Arc::new(ProductionHandler::with_health(
            verbs,
            credential,
            state.kv_mount,
            health.clone(),
        )),
        maintenance: Some(RegistrarMaintenance {
            coalescing,
            health,
            counts,
        }),
    })
}

#[cfg(target_os = "linux")]
pub(crate) struct BuiltRegistrarHandler {
    handler: Arc<dyn crate::registrar::endpoint::handler::RegistrarRequestHandler>,
    maintenance: Option<RegistrarMaintenance>,
}

/// State refreshed together on the daemon's existing maintenance cadence.
#[cfg(target_os = "linux")]
struct RegistrarMaintenance {
    coalescing: Arc<crate::registrar::verbs::coalescing::CoalescingLimitedInvocationSink>,
    health: Arc<StdMutex<crate::registrar::endpoint::protocol::RegistrarHealth>>,
    counts: Arc<crate::registrar::verbs::limiter::CountingLimitedInvocationSink>,
}

/// Copies the limiter's process-lifetime counters into the shared snapshot.
#[cfg(target_os = "linux")]
pub(crate) fn refresh_registrar_health(
    health: &Arc<StdMutex<crate::registrar::endpoint::protocol::RegistrarHealth>>,
    counts: &crate::registrar::verbs::limiter::CountingLimitedInvocationSink,
) {
    let mut snapshot = health.lock().unwrap_or_else(PoisonError::into_inner);
    snapshot.limiter.limited_predecision_refusal =
        counts.count(crate::registrar::verbs::limiter::LimiterBucket::PredecisionRefusal);
    snapshot.limiter.limited_admission =
        counts.count(crate::registrar::verbs::limiter::LimiterBucket::Admission);
}

/// The adopted endpoint and the handler that will answer on it, or
/// `None` when the endpoint is disabled.
#[cfg(target_os = "linux")]
type RegistrarService = Option<(
    Arc<crate::registrar::endpoint::ActivatedEndpoint>,
    BuiltRegistrarHandler,
)>;

/// Resolves the registrar endpoint's accept-task dependencies for one
/// invocation.
///
/// Called from `run_daemon` **before** it spawns anything, so the `?`
/// here fails the whole invocation rather than leaving the socket
/// adopted with no accept task: a systemd-activated socket with nobody
/// accepting turns every caller into a hang, which is strictly worse
/// than a failed start. An operator who enabled the endpoint and whose
/// provisioning config, state file, internal credential or audit store
/// is not in place therefore gets a loud, named startup failure.
///
/// Nothing is built when the endpoint is disabled: no provisioning
/// config is loaded, no audit store opened, no state file read and no
/// credential constructed.
///
/// # Errors
///
/// Returns whatever [`build_registrar_handler`] could not resolve.
///
/// An absent filesystem audit-store mount is the deliberate exception: it
/// installs a refusing handler so the adopted socket remains answered while
/// the daemon's renewal duties continue. Every other handler dependency
/// failure still stops the invocation.
#[cfg(target_os = "linux")]
async fn resolve_registrar_service(
    registrar_endpoint: &RegistrarEndpoint,
    settings: &config::Settings,
) -> anyhow::Result<RegistrarService> {
    match registrar_endpoint.activated() {
        Some(endpoint) => {
            let gate = registrar_endpoint
                .audit_store_mount_gate(&settings.registrar, audit_store_is_mount_point)
                .expect("an active endpoint always carries an audit-store gate");
            let built =
                resolve_registrar_handler_for_gate(gate, || build_registrar_handler(settings))
                    .await?;
            Ok(Some((endpoint, built)))
        }
        None => Ok(None),
    }
}

/// Selects the handler for one active endpoint after its mount verdict.
///
/// An unmounted filesystem store is intentionally resolved without invoking
/// `build_handler`: opening that handler's audit store would manufacture the
/// directory the endpoint must refuse over.
#[cfg(target_os = "linux")]
async fn resolve_registrar_handler_for_gate<F, Fut>(
    gate: &AuditStoreMountGate,
    build_handler: F,
) -> anyhow::Result<BuiltRegistrarHandler>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = anyhow::Result<BuiltRegistrarHandler>>,
{
    if gate.requires_mount() && !gate.mounted() {
        let audit_store_dir = gate.store_dir().to_path_buf();
        let mount_unit = audit_store_mount_unit_name(&audit_store_dir);
        let messages = crate::daemon_messages::DaemonMessages::from_environment();
        if gate.take_startup_diagnostic() {
            warn!(
                audit_store = %audit_store_dir.display(),
                mount_unit = mount_unit.as_str(),
                "{}", messages.audit_store_not_mounted_at_start()
            );
        }
        return Ok(BuiltRegistrarHandler {
            handler: Arc::new(crate::registrar::endpoint::refusing::RefusingHandler::new(
                audit_store_dir,
                mount_unit,
                messages,
            )),
            maintenance: None,
        });
    }
    build_handler().await
}

/// Reports whether `store_dir` is a mount point by comparing device ids.
///
/// Failure to read either directory fails the endpoint closed: it is not
/// evidence that the configured filesystem store is mounted, and this path
/// must not create it merely to find out.
#[cfg(target_os = "linux")]
fn audit_store_is_mount_point(store_dir: &Path) -> bool {
    let Some(parent) = store_dir.parent() else {
        return false;
    };
    let Ok(store) = std::fs::metadata(store_dir) else {
        return false;
    };
    let Ok(parent) = std::fs::metadata(parent) else {
        return false;
    };
    has_distinct_device_ids(store.dev(), parent.dev())
}

/// Compares the two metadata values the mount-point predicate needs.
#[cfg(target_os = "linux")]
const fn has_distinct_device_ids(store_device: u64, parent_device: u64) -> bool {
    store_device != parent_device
}

/// Returns the systemd mount unit name derived from the mount point.
#[cfg(target_os = "linux")]
fn audit_store_mount_unit_name(store_dir: &Path) -> String {
    format!("{}.mount", systemd_escape_path(store_dir))
}

/// Spells a mount point the way `systemd-escape --path` does.
#[cfg(target_os = "linux")]
fn systemd_escape_path(store_dir: &Path) -> String {
    let components: Vec<&[u8]> = store_dir
        .as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty() && *component != b".")
        .collect();
    if components.is_empty() {
        return "-".to_string();
    }

    let mut escaped = String::new();
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            escaped.push('-');
        }
        for byte in *component {
            if byte.is_ascii_alphanumeric() || matches!(*byte, b':' | b'_' | b'.') {
                escaped.push(char::from(*byte));
            } else {
                use std::fmt::Write as _;
                write!(escaped, "\\x{byte:02x}").expect("writing a String cannot fail");
            }
        }
    }
    if let Some(rest) = escaped.strip_prefix('.') {
        format!("\\x2e{rest}")
    } else {
        escaped
    }
}

/// Spawns the registrar endpoint's accept task, when one is active.
///
/// The handle joins the same `handles` vector every profile task does,
/// and [`collect_task_results`] awaits all of them before the daemon
/// invocation returns. That ordering is the guarantee: the endpoint has
/// stopped accepting, drained or aborted its connections and joined
/// every one of them by the time the reload loop joins the invocation.
///
/// The handler is a parameter rather than something the endpoint
/// carries, so the accept task cannot be spawned without one — a
/// signature rather than a runtime invariant, which is why "never accept
/// a connection without a handler behind it" needs no slot, no lock and
/// no interior mutability.
///
/// On a non-Linux target the endpoint is not compiled at all, and an
/// enabled setting has already been refused by configuration validation.
#[cfg(target_os = "linux")]
fn spawn_registrar_endpoint(
    handles: &mut Vec<tokio::task::JoinHandle<anyhow::Result<()>>>,
    endpoint: Arc<crate::registrar::endpoint::ActivatedEndpoint>,
    request_handler: Arc<dyn crate::registrar::endpoint::handler::RegistrarRequestHandler>,
    coalescing: Option<Arc<crate::registrar::verbs::coalescing::CoalescingLimitedInvocationSink>>,
    shutdown_rx: &watch::Receiver<bool>,
) {
    let shutdown_rx = shutdown_rx.clone();
    handles.push(tokio::spawn(async move {
        let result =
            crate::registrar::endpoint::serve::run(endpoint, request_handler, shutdown_rx).await;
        // `run` drains every accepted connection before it returns. Flushing
        // here therefore includes limited invocations from requests that were
        // already in flight when shutdown began.
        if let Some(coalescing) = coalescing {
            coalescing.flush();
        }
        result
    }));
}

/// Spawns the adapter that keeps the registrar surface's two leaves
/// valid, when the endpoint is enabled.
///
/// Called with the endpoint already activated and *before* the accept
/// task is spawned, so the per-leaf renewal state is initialized from
/// the certificates start-time issuance ensured, and is initialized
/// before the endpoint serves anything. The handle joins with every
/// other daemon task, and the adapter takes the same shutdown watch.
///
/// A preparation that fails is logged and not a refused start: the
/// endpoint is already up on material that is usable today, and taking
/// it down because renewal could not be armed would turn a future
/// problem into an immediate outage. Nothing is renewed until the next
/// daemon start in that case, which is what the error line says.
///
/// Where the endpoint is disabled this is never reached at all: no
/// adapter, no state entry, no renewal work, no `OpenBao` request and no
/// CA request.
#[cfg(target_os = "linux")]
async fn spawn_registrar_cert_renewal(
    handles: &mut Vec<tokio::task::JoinHandle<anyhow::Result<()>>>,
    settings: &Arc<config::Settings>,
    endpoint: Arc<crate::registrar::endpoint::ActivatedEndpoint>,
    insecure_mode: bool,
    shutdown_rx: &watch::Receiver<bool>,
) {
    let renewal = match crate::registrar_renewal::RegistrarCertRenewal::prepare(
        Arc::clone(settings),
        endpoint,
        insecure_mode,
    )
    .await
    {
        Ok(renewal) => renewal,
        Err(err) => {
            error!(
                "Registrar certificate renewal could not be armed, so neither registrar leaf \
                 will be renewed under this daemon: {err:#}"
            );
            return;
        }
    };
    let shutdown_rx = shutdown_rx.clone();
    handles.push(tokio::spawn(renewal.run(shutdown_rx)));
}

/// Spawns the task that rotates `OpenBao`'s file audit device, when
/// this host is one whose device the daemon owns.
///
/// The predicate is exactly `[registrar_endpoint] enabled = true` and
/// nothing else — not the socket, not the unit pair, not whether the
/// store directory exists. Where it does not hold, `/openbao/audit` is
/// still backed by the `openbao-audit` named volume, nothing on the
/// host is there to rotate, and no task is spawned at all.
///
/// The device's directory is derived through
/// [`crate::registrar::audit_store::openbao_dir`] rather than by
/// joining a subdirectory name on by hand: a second spelling is a
/// second directory waiting to happen.
///
/// The handle joins the same `handles` vector every other daemon task
/// uses, so [`collect_task_results`] observes it. It is deliberately not
/// hung off the per-profile check loop: that interval is per-profile,
/// jittered and operator-configurable up to hours, while the device is a
/// single global object.
fn spawn_openbao_audit_rotation(
    handles: &mut Vec<tokio::task::JoinHandle<anyhow::Result<()>>>,
    settings: &config::Settings,
    shutdown_rx: &watch::Receiver<bool>,
    #[cfg(target_os = "linux")] registrar_maintenance: Option<RegistrarMaintenance>,
    #[cfg(not(target_os = "linux"))] _registrar_maintenance: Option<()>,
) {
    if !settings.registrar_endpoint.enabled {
        return;
    }
    let registrar = &settings.registrar;
    let rotation = crate::registrar::openbao_audit::OpenBaoAuditRotation::new(
        crate::registrar::audit_store::openbao_dir(&registrar.audit_store_dir),
        registrar.openbao_audit_max_file_bytes,
        registrar.openbao_audit_max_retained_files,
    );
    let shutdown_rx = shutdown_rx.clone();
    #[cfg(target_os = "linux")]
    if let Some(maintenance) = registrar_maintenance {
        handles.push(tokio::spawn(
            crate::registrar::openbao_audit::run_rotation_loop_with_maintenance(
                rotation,
                crate::registrar::openbao_audit::ROTATION_INTERVAL,
                shutdown_rx,
                move || {
                    maintenance.coalescing.maintain();
                    refresh_registrar_health(&maintenance.health, &maintenance.counts);
                },
            ),
        ));
        return;
    }
    handles.push(tokio::spawn(
        crate::registrar::openbao_audit::run_rotation_loop(
            rotation,
            crate::registrar::openbao_audit::ROTATION_INTERVAL,
            shutdown_rx,
        ),
    ));
}

async fn run_profile_daemon(
    settings: Arc<config::Settings>,
    profile: config::DaemonProfileSettings,
    shared_eab: eab::SharedEab,
    semaphore: Arc<Semaphore>,
    profile_locks: Arc<ProfileLocks>,
    mut shutdown: watch::Receiver<bool>,
    runtime: IssuanceRuntime,
) -> anyhow::Result<()> {
    let check_interval = profile.daemon.check_interval;
    let renew_before = profile.daemon.renew_before;
    let check_jitter = profile.daemon.check_jitter;
    let profile_label = config::profile_domain(&settings, &profile);

    info!(
        "Profile '{}' daemon enabled. check_interval={:?}, renew_before={:?}, check_jitter={:?}",
        profile_label, check_interval, renew_before, check_jitter
    );

    let mut first_tick = true;
    loop {
        if *shutdown.borrow() {
            info!(
                "Shutdown signal received. Exiting profile '{}'.",
                profile_label
            );
            break;
        }

        let delay = if first_tick {
            first_tick = false;
            Duration::from_secs(0)
        } else {
            utils::jittered_delay(check_interval, check_jitter)
        };

        tokio::select! {
            _ = shutdown.changed() => {
                info!("Shutdown signal received. Exiting profile '{}'.", profile_label);
                break;
            }
            () = tokio::time::sleep(delay) => {
                check_and_renew_profile(
                    &settings,
                    &profile,
                    shared_eab.current(),
                    Arc::clone(&semaphore),
                    &profile_locks,
                    renew_before,
                    &runtime,
                )
                .await?;
            }
        }
    }

    Ok(())
}

/// Runs a single issuance pass for all profiles.
///
/// # Errors
/// Returns an error if any profile issuance fails.
pub(crate) async fn run_oneshot(
    settings: Arc<config::Settings>,
    default_eab: Option<eab::EabCredentials>,
    config_path: Option<PathBuf>,
    insecure_mode: bool,
) -> anyhow::Result<()> {
    let max_concurrent = profile::max_concurrent_issuances(&settings)?;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let runtime = IssuanceRuntime {
        config_path: resolve_config_path(config_path.as_deref()),
        insecure_mode,
        cli_overrides: config::CliOverrides::default(),
    };
    let mut handles = Vec::new();

    for profile in settings.profiles.clone() {
        let settings = Arc::clone(&settings);
        let semaphore = Arc::clone(&semaphore);
        let default_eab = default_eab.clone();
        let runtime = runtime.clone();

        handles.push(tokio::spawn(async move {
            run_profile_oneshot(settings, profile, default_eab, semaphore, runtime).await
        }));
    }

    collect_task_results(handles, "oneshot").await
}

/// Collects results from spawned task handles, logging errors and
/// returning the first observed failure.
async fn collect_task_results(
    handles: Vec<tokio::task::JoinHandle<anyhow::Result<()>>>,
    label: &str,
) -> anyhow::Result<()> {
    let mut first_error = None;
    for handle in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                error!("Profile {label} failed: {err}");
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
            Err(err) => {
                error!("Profile {label} task join error: {err}");
                if first_error.is_none() {
                    first_error = Some(anyhow::anyhow!("Profile {label} task join error: {err}"));
                }
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

/// The bootroot-internal profile's fail-closed precondition, checked
/// before every issuance the daemon starts.
///
/// A no-op for every other profile. For the internal one it compares the
/// stored root fingerprint with the deployment's active root and refuses
/// on a mismatch, so a leaf that falls due between a full rotation's
/// Phase 3 and its post-Phase-4 repair is not reissued under a root the
/// `auth/cert` entry no longer trusts. Nothing about it is a second
/// scheduler: the refusal is reported through the same post-renew
/// failure hooks an issuance failure takes, and the caller decides
/// whether that ends the run or only this tick.
async fn refuse_stale_internal_root(
    settings: &config::Settings,
    profile: &config::DaemonProfileSettings,
    profile_label: &str,
) -> Option<anyhow::Error> {
    let err = crate::registrar::internal::check_renewal_allowed(profile).err()?;
    error!(
        "Profile '{}' issuance refused before any ACME request: {err}",
        profile_label
    );
    let result = Err(anyhow::Error::new(err));
    if let Err(hook_err) = handle_issuance_result(&result, settings, profile, profile_label).await {
        error!(
            "Post-renew failure hooks failed for '{}': {hook_err}",
            profile_label
        );
    }
    result.err()
}

async fn run_profile_oneshot(
    settings: Arc<config::Settings>,
    profile: config::DaemonProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    semaphore: Arc<Semaphore>,
    runtime: IssuanceRuntime,
) -> anyhow::Result<()> {
    let profile_label = config::profile_domain(&settings, &profile);
    if let Some(err) = refuse_stale_internal_root(&settings, &profile, &profile_label).await {
        return Err(err);
    }

    let _permit = semaphore.acquire().await?;
    let profile_eab = profile::resolve_profile_eab(&profile, default_eab);

    let result =
        acme::issue_certificate(&settings, &profile, profile_eab, runtime.insecure_mode).await;
    handle_issuance_result(&result, &settings, &profile, &profile_label).await?;
    result
}

/// Dispatches post-issuance hooks based on the issuance outcome.
async fn handle_issuance_result(
    result: &anyhow::Result<()>,
    settings: &config::Settings,
    profile: &config::DaemonProfileSettings,
    profile_label: &str,
) -> anyhow::Result<()> {
    match result {
        Ok(()) => {
            if let Err(err) =
                hooks::run_post_renew_hooks(settings, profile, hooks::HookStatus::Success, None)
                    .await
            {
                error!(
                    "Post-renew success hooks failed for '{}': {err}",
                    profile_label
                );
            }
        }
        Err(err) => {
            if let Err(hook_err) = hooks::run_post_renew_hooks(
                settings,
                profile,
                hooks::HookStatus::Failure,
                Some(err.to_string()),
            )
            .await
            {
                error!(
                    "Post-renew failure hooks failed for '{}': {hook_err}",
                    profile_label
                );
            }
        }
    }
    Ok(())
}

async fn issue_with_retry(
    settings: &config::Settings,
    profile: &config::DaemonProfileSettings,
    eab: Option<eab::EabCredentials>,
    runtime: &IssuanceRuntime,
) -> anyhow::Result<()> {
    let backoff = select_retry_backoff(settings, profile);
    let profile_domain = config::profile_domain(settings, profile);
    let config_path_owned = runtime.config_path.clone();
    let cli_overrides = runtime.cli_overrides.clone();
    let insecure_mode = runtime.insecure_mode;
    let fallback = (settings.clone(), profile.clone());
    issue_with_retry_inner(
        || {
            let path = config_path_owned.clone();
            let domain = profile_domain.clone();
            let eab = eab.clone();
            let overrides = cli_overrides.clone();
            let fallback = fallback.clone();
            async move {
                let (fresh, fresh_profile) =
                    reload_profile_or_fallback(&path, &overrides, &domain, fallback);
                let fresh_eab = profile::resolve_profile_eab(&fresh_profile, eab);
                acme::issue_certificate(&fresh, &fresh_profile, fresh_eab, insecure_mode).await
            }
        },
        |duration| tokio::time::sleep(duration),
        backoff,
    )
    .await
}

/// Reloads `agent.toml` for a single retry attempt and locates the
/// target profile. Falls back to the supplied in-memory pair when the
/// reload fails or the profile is absent from the reloaded file.
///
/// The fallback no longer stands in for an unhardened `agent.toml`
/// writer. Every writer this crate controls now publishes the file by
/// rename from a temporary — `service::local_config` and the
/// `service update` and `service remove --strip-config` editors beside
/// it, `bootroot-remote bootstrap`'s apply, `apply_local_service_configs`
/// through [`crate::fs_util::atomic_write`], and the three `fast_poll`
/// appliers — so none of them can leave a partial file for this reload
/// to read.
///
/// Two cases remain, and neither is a bootroot writer losing a race.
/// An operator editing the file in place with a truncating editor is
/// still observable half-written, and bootroot has no say in that. And
/// the profile can be genuinely absent rather than momentarily
/// unobservable, since `service remove --strip-config` deletes the
/// managed block outright; there the fallback keeps the in-flight
/// attempt running on the profile it started with rather than failing
/// on a configuration change made mid-attempt.
///
/// Treating both as transient and reusing the prior in-memory profile
/// keeps the retry budget available for genuine ACME failures, while
/// still honouring `#303`'s intent of picking up freshly-rendered KV
/// values whenever the reload does land on a coherent file.
fn reload_profile_or_fallback(
    config_path: &Path,
    overrides: &config::CliOverrides,
    profile_domain: &str,
    fallback: (config::Settings, config::DaemonProfileSettings),
) -> (config::Settings, config::DaemonProfileSettings) {
    match config::Settings::new(Some(config_path.to_path_buf())) {
        Ok(mut fresh) => {
            fresh.apply_overrides(overrides);
            if let Some(matched) = fresh
                .profiles
                .iter()
                .find(|p| config::profile_domain(&fresh, p) == profile_domain)
                .cloned()
            {
                (fresh, matched)
            } else {
                tracing::warn!(
                    "Profile '{profile_domain}' missing from reloaded agent config; \
                     using previously-loaded profile for this attempt"
                );
                fallback
            }
        }
        Err(err) => {
            tracing::warn!(
                "Failed to reload agent config while renewing '{profile_domain}' ({err}); \
                 using previously-loaded profile for this attempt"
            );
            fallback
        }
    }
}

fn select_retry_backoff<'a>(
    settings: &'a config::Settings,
    profile: &'a config::DaemonProfileSettings,
) -> &'a [u64] {
    profile
        .retry
        .as_ref()
        .map_or(settings.retry.backoff_secs.as_slice(), |retry| {
            retry.backoff_secs.as_slice()
        })
}

/// Issues a certificate with retry and backoff.
///
/// # Errors
/// Returns an error if all retries fail.
pub(crate) async fn issue_with_retry_inner<IssueFn, IssueFut, SleepFn, SleepFut>(
    mut issue_fn: IssueFn,
    mut sleep_fn: SleepFn,
    delays: &[u64],
) -> anyhow::Result<()>
where
    IssueFn: FnMut() -> IssueFut,
    IssueFut: Future<Output = anyhow::Result<()>>,
    SleepFn: FnMut(Duration) -> SleepFut,
    SleepFut: Future<Output = ()>,
{
    let result = utils::retry_with_backoff_and_sleep(
        &mut issue_fn,
        &mut sleep_fn,
        |attempt, err| {
            error!("Certificate issuance failed (attempt {}): {err}", attempt);
        },
        delays,
    )
    .await;
    if result.is_ok() {
        info!("Certificate issuance succeeded.");
    }
    result
}

/// Determines whether a certificate should be renewed.
///
/// Returns `true` when the on-disk leaf is missing, near expiry, or no
/// longer chains to the configured CA bundle. The chain check is the
/// load-bearing addition for issue #627: a destructive trust-anchor
/// rotation (`bootroot clean` + re-`init`, operator-side key swap, or
/// `bootroot rotate ca-key --skip reissue`) leaves a still-time-valid
/// leaf signed by the *previous* intermediate while `service add`
/// already replaced the bundle with the new generation's root +
/// intermediate. Without the chain check the agent treats that leaf as
/// fine and consumers see `UNABLE_TO_VERIFY_LEAF_SIGNATURE` for the
/// full remaining 24h of leaf validity.
///
/// `[trust].ca_bundle_path` not configured means the operator opted
/// out of bundle management entirely; in that case only the expiry
/// gate runs.
///
/// # Errors
/// Returns an error if the certificate cannot be parsed or read for
/// reasons other than `NotFound`. Chain-verification failures or a
/// missing/unreadable bundle force a reissue rather than abort the
/// renewal loop.
pub(crate) async fn should_renew(
    profile: &config::DaemonProfileSettings,
    trust: &config::TrustSettings,
    renew_before: Duration,
) -> anyhow::Result<bool> {
    should_renew_certificate(&profile.paths.cert, trust, renew_before).await
}

/// The same rule, over a certificate path alone.
///
/// Split out so the registrar surface's two leaves — which have no
/// `[[profiles]]` entry and never will — are judged by this predicate
/// rather than by a second one written beside it. The lead-time gate,
/// the chain-drift gate and the `ca_bundle_path`-unconfigured opt-out
/// are all this function's, so there is one eligibility rule in the
/// daemon and not two.
///
/// # Errors
///
/// Returns an error if the certificate cannot be parsed or read for
/// reasons other than `NotFound`. Chain-verification failures or a
/// missing/unreadable bundle force a reissue rather than abort the
/// renewal loop.
pub(crate) async fn should_renew_certificate(
    cert_path: &Path,
    trust: &config::TrustSettings,
    renew_before: Duration,
) -> anyhow::Result<bool> {
    let cert_bytes = match tokio::fs::read(cert_path).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            info!("Certificate file not found. Issuing a new certificate.");
            return Ok(true);
        }
        Err(err) => {
            return Err(anyhow::anyhow!(
                "Failed to read certificate file {}: {err}",
                cert_path.display()
            ));
        }
    };

    let not_after = parse_cert_not_after(&cert_bytes)?;

    let renew_before = time::Duration::try_from(renew_before)
        .map_err(|_| anyhow::anyhow!("renew_before duration is too large"))?;
    let now = time::OffsetDateTime::now_utc();
    let renew_at = now + renew_before;

    if not_after <= renew_at {
        return Ok(true);
    }

    if let Some(bundle_path) = trust.ca_bundle_path.as_ref() {
        match tokio::fs::read(bundle_path).await {
            Ok(bundle_bytes) => match cert_chain::leaf_chains_to_bundle(&cert_bytes, &bundle_bytes)
            {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        "Certificate at {} no longer chains to CA bundle at {}; reissuing.",
                        cert_path.display(),
                        bundle_path.display()
                    );
                    return Ok(true);
                }
                Err(err) => {
                    warn!(
                        "Chain verification of {} against {} failed ({err}); reissuing.",
                        cert_path.display(),
                        bundle_path.display()
                    );
                    return Ok(true);
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                warn!(
                    "CA bundle at {} is missing; reissuing to repopulate.",
                    bundle_path.display()
                );
                return Ok(true);
            }
            Err(err) => {
                warn!(
                    "Failed to read CA bundle at {} ({err}); reissuing.",
                    bundle_path.display()
                );
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Parses the certificate expiration timestamp.
///
/// # Errors
/// Returns an error if the certificate cannot be parsed.
pub(crate) fn parse_cert_not_after(cert_bytes: &[u8]) -> anyhow::Result<time::OffsetDateTime> {
    let pem = x509_parser::pem::parse_x509_pem(cert_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM certificate: {e}"))?
        .1;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse X509 certificate: {e}"))?;
    Ok(cert.validity().not_after.to_datetime())
}

/// Renews a profile unconditionally, bypassing the `should_renew` expiry
/// check used by the periodic loop. Used by the fast-poll force-reissue
/// path: an operator-initiated reissue must actually rotate the cert
/// even when it is nowhere near expiry.
///
/// Acquires the per-profile lock *before* the shared concurrency
/// semaphore so a concurrent periodic tick on the same profile cannot
/// sneak a second issuance in once this function releases its permit
/// but before the rotated cert lands on disk.
async fn force_renew_profile(
    settings: &config::Settings,
    profile: &config::DaemonProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    semaphore: Arc<Semaphore>,
    profile_locks: &ProfileLocks,
    runtime: &IssuanceRuntime,
) -> anyhow::Result<()> {
    let profile_label = config::profile_domain(settings, profile);
    let lock = profile_locks.for_profile(&profile_label);
    let _profile_guard = lock.lock().await;
    if let Some(err) = refuse_stale_internal_root(settings, profile, &profile_label).await {
        return Err(err);
    }
    info!(
        "Profile '{}' force-reissue requested. Starting ACME issuance...",
        profile_label
    );
    let _permit = semaphore.acquire().await?;
    let profile_eab = profile::resolve_profile_eab(profile, default_eab);
    let result = issue_with_retry(settings, profile, profile_eab, runtime).await;
    if let Err(err) = &result {
        error!(
            "Profile '{}' force-reissue failed after retries: {err}",
            profile_label
        );
    }
    handle_issuance_result(&result, settings, profile, &profile_label).await?;
    result
}

async fn check_and_renew_profile(
    settings: &config::Settings,
    profile: &config::DaemonProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    semaphore: Arc<Semaphore>,
    profile_locks: &ProfileLocks,
    renew_before: Duration,
    runtime: &IssuanceRuntime,
) -> anyhow::Result<()> {
    let profile_label = config::profile_domain(settings, profile);
    tracing::debug!("Profile '{}' checking renewal status...", profile_label);

    // Hold the per-profile lock across the decision *and* issuance so a
    // fast-poll force-reissue that is already in flight serialises with
    // this tick. When that force-reissue is the one that landed first,
    // `should_renew` re-reads the rotated cert once we acquire the lock
    // and returns false, skipping a redundant second issuance.
    let lock = profile_locks.for_profile(&profile_label);
    let _profile_guard = lock.lock().await;

    let needs_renewal = match should_renew(profile, &settings.trust, renew_before).await {
        Ok(val) => val,
        Err(err) => {
            error!("Profile '{}' renewal check failed: {err}", profile_label);
            return Ok(());
        }
    };

    if !needs_renewal {
        tracing::debug!("Profile '{}' certificate still valid.", profile_label);
        return Ok(());
    }

    if refuse_stale_internal_root(settings, profile, &profile_label)
        .await
        .is_some()
    {
        // The credential is repairable and the repair is another
        // process's job, so the loop keeps ticking rather than ending:
        // the tick after `bootroot rotate registrar-internal-credential`
        // — or after a full rotation's post-Phase-4 tail — renews
        // normally.
        return Ok(());
    }

    info!(
        "Profile '{}' renewal required. Starting ACME issuance...",
        profile_label
    );
    let _permit = semaphore.acquire().await?;
    let profile_eab = profile::resolve_profile_eab(profile, default_eab);
    let result = issue_with_retry(settings, profile, profile_eab, runtime).await;
    if let Err(err) = &result {
        error!(
            "Profile '{}' renewal failed after retries: {err}",
            profile_label
        );
    }
    handle_issuance_result(&result, settings, profile, &profile_label).await?;
    Ok(())
}

fn resolve_config_path(config_path: Option<&Path>) -> PathBuf {
    config_path.map_or_else(
        || PathBuf::from(DEFAULT_AGENT_CONFIG_PATH),
        Path::to_path_buf,
    )
}

async fn wait_for_shutdown() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut term = signal(SignalKind::terminate())
            .map_err(|e| anyhow::anyhow!("Failed to install SIGTERM handler: {e}"))?;

        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|e| anyhow::anyhow!("Failed to listen for Ctrl+C: {e}"))?;
            }
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to listen for Ctrl+C: {e}"))?;
    }

    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod registrar_handler_tests;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::config::{
        AcmeSettings, DaemonRuntimeSettings, Paths, RetrySettings, SchedulerSettings,
    };

    const TEST_DOMAIN: &str = "example.com";
    const THIRTY_DAYS_SECS: u64 = 30 * 24 * 60 * 60;
    const TEST_DELAYS: [u64; 3] = [1, 2, 3];
    const TEST_JITTER_SECS: u64 = 10;
    const TEST_BASE_SECS: u64 = 60;
    const TEST_SEED_NS: i128 = 123_456_789;

    fn build_profile(cert_path: PathBuf) -> config::DaemonProfileSettings {
        config::DaemonProfileSettings {
            registration_id: "edge-proxy".to_string(),
            service_name: "edge-proxy".to_string(),
            instance_id: "001".to_string(),
            hostname: "edge-node-01".to_string(),
            paths: Paths {
                cert: cert_path,
                key: PathBuf::from("unused.key"),
            },
            daemon: DaemonRuntimeSettings {
                check_interval: Duration::from_hours(1),
                renew_before: Duration::from_hours(16),
                check_jitter: Duration::from_secs(0),
            },
            retry: None,
            hooks: config::HookSettings::default(),
            eab: None,
            cert_group_gid: None,
        }
    }

    fn build_settings(backoff: Vec<u64>) -> config::Settings {
        config::Settings {
            email: "test@example.com".to_string(),
            server: "https://example.com/acme/directory".to_string(),
            domain: "trusted.domain".to_string(),
            eab: None,
            acme: AcmeSettings {
                directory_fetch_attempts: 10,
                directory_fetch_base_delay_secs: 1,
                directory_fetch_max_delay_secs: 10,
                poll_attempts: 15,
                poll_interval_secs: 2,
                account_key_path: None,
                http_responder_url: "http://localhost:8080".to_string(),
                http_responder_hmac: "dev-hmac".into(),
                http_responder_timeout_secs: 5,
                http_responder_token_ttl_secs: 300,
            },
            retry: RetrySettings {
                backoff_secs: backoff,
            },
            trust: config::TrustSettings::default(),
            scheduler: SchedulerSettings {
                max_concurrent_issuances: 1,
            },
            profiles: Vec::new(),
            openbao: None,
            registrar_endpoint: config::RegistrarEndpointSettings::default(),
            registrar: config::RegistrarSettings::default(),
        }
    }

    fn write_cert(cert_path: &PathBuf, not_after: time::OffsetDateTime) {
        let mut params = rcgen::CertificateParams::new(vec![TEST_DOMAIN.to_string()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = not_after;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        fs::write(cert_path, cert.pem()).unwrap();
    }

    struct TestCa {
        root_cert: rcgen::Certificate,
        intermediate_cert: rcgen::Certificate,
        intermediate_issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    fn build_test_ca(label: &str) -> TestCa {
        let root_key = rcgen::KeyPair::generate().unwrap();
        let mut root_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        root_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        root_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("{label}-root"));
        root_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let root_cert = root_params.self_signed(&root_key).unwrap();
        let root_issuer = rcgen::Issuer::new(root_params, root_key);

        let intermediate_key = rcgen::KeyPair::generate().unwrap();
        let mut int_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        int_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        int_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, format!("{label}-intermediate"));
        int_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let intermediate_cert = int_params
            .signed_by(&intermediate_key, &root_issuer)
            .unwrap();
        let intermediate_issuer = rcgen::Issuer::new(int_params, intermediate_key);

        TestCa {
            root_cert,
            intermediate_cert,
            intermediate_issuer,
        }
    }

    fn sign_test_leaf(common_name: &str, ca: &TestCa) -> String {
        let mut params = rcgen::CertificateParams::new(vec![common_name.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(90);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = params
            .signed_by(&leaf_key, &ca.intermediate_issuer)
            .unwrap();
        leaf.pem()
    }

    fn test_bundle_pem(ca: &TestCa) -> String {
        format!("{}{}", ca.root_cert.pem(), ca.intermediate_cert.pem())
    }

    /// The bootroot-internal profile is renewed by the **ordinary**
    /// loop. A second, test-only profile in the same generated config
    /// proves it: both are enumerated, both resolve the same configured
    /// tick, lead time and jitter, both select the same retry backoff
    /// through `select_retry_backoff`, and both carry the same
    /// failure-hook set. Nothing here is registrar-specific, and that is
    /// the assertion.
    #[test]
    fn the_generated_internal_config_gives_both_profiles_one_loop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, internal_config_with_second_profile(dir.path())).unwrap();
        let settings = config::Settings::from_file(Some(path)).unwrap();

        assert_eq!(settings.profiles.len(), 2);
        let internal = &settings.profiles[0];
        let companion = &settings.profiles[1];
        assert_eq!(internal.service_name, "bootroot-registrar-internal");
        assert_ne!(internal.registration_id, companion.registration_id);

        for profile in &settings.profiles {
            assert_eq!(profile.daemon.check_interval, Duration::from_hours(2));
            assert_eq!(profile.daemon.renew_before, Duration::from_hours(24));
            assert_eq!(profile.daemon.check_jitter, Duration::from_secs(30));
            // The generated `[retry]` is the deployment's; neither
            // profile overrides it, so both resolve the same backoff
            // through the one selector the daemon uses.
            assert_eq!(profile.retry.as_ref().map(|r| r.backoff_secs.clone()), None);
            assert_eq!(
                select_retry_backoff(&settings, profile),
                settings.retry.backoff_secs.as_slice()
            );
            let failure = &profile.hooks.post_renew.failure;
            assert_eq!(failure.len(), 1);
            assert_eq!(failure[0].command, "/bin/true");
        }
    }

    /// The internal profile renews on expiry **and** on private-bundle
    /// drift, because the generated config always sets
    /// `[trust].ca_bundle_path`. The second profile in the same config
    /// reaches the same answer through the same predicate.
    #[tokio::test]
    async fn both_profiles_renew_on_expiry_and_on_private_bundle_drift() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        let generation = build_test_ca("gen1");
        fs::write(&bundle_path, test_bundle_pem(&generation)).unwrap();
        let trust = config::TrustSettings {
            ca_bundle_path: Some(bundle_path.clone()),
            trusted_ca_sha256: Vec::new(),
        };
        let lead = Duration::from_secs(THIRTY_DAYS_SECS);

        for (index, name) in ["internal", "companion"].iter().enumerate() {
            let cert_path = dir.path().join(format!("{name}.pem"));

            // Fresh leaf under the bundle's own CA: no renewal.
            fs::write(&cert_path, sign_test_leaf(name, &generation)).unwrap();
            let profile = build_profile(cert_path.clone());
            assert!(
                !should_renew(&profile, &trust, lead).await.unwrap(),
                "{name} ({index}) should not renew while current"
            );

            // Expiry.
            write_cert(
                &cert_path,
                time::OffsetDateTime::now_utc() + time::Duration::days(1),
            );
            assert!(
                should_renew(&profile, &trust, lead).await.unwrap(),
                "{name} ({index}) should renew on expiry"
            );

            // Private-bundle drift: the bundle moved to a generation the
            // leaf does not chain to.
            fs::write(&cert_path, sign_test_leaf(name, &generation)).unwrap();
            fs::write(&bundle_path, test_bundle_pem(&build_test_ca("gen2"))).unwrap();
            assert!(
                should_renew(&profile, &trust, lead).await.unwrap(),
                "{name} ({index}) should renew on private-bundle drift"
            );
            fs::write(&bundle_path, test_bundle_pem(&generation)).unwrap();
        }
    }

    /// A fixture that removes `ca_bundle_path` stays expiry-only: the
    /// drift arm of the generic predicate is reached only when a bundle
    /// is configured, which is why the internal config always sets one.
    #[tokio::test]
    async fn an_unconfigured_bundle_leaves_the_predicate_expiry_only() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let generation = build_test_ca("gen1");
        fs::write(&cert_path, sign_test_leaf("svc", &generation)).unwrap();
        let profile = build_profile(cert_path.clone());
        let trust = config::TrustSettings::default();
        assert!(trust.ca_bundle_path.is_none());
        let lead = Duration::from_secs(THIRTY_DAYS_SECS);

        // A drifted bundle exists on disk but is not configured, so it
        // cannot make the predicate fire.
        fs::write(
            dir.path().join("ca-bundle.pem"),
            test_bundle_pem(&build_test_ca("gen2")),
        )
        .unwrap();
        assert!(!should_renew(&profile, &trust, lead).await.unwrap());

        write_cert(
            &cert_path,
            time::OffsetDateTime::now_utc() + time::Duration::days(1),
        );
        assert!(should_renew(&profile, &trust, lead).await.unwrap());
    }

    /// Writes a host caught in a full rotation's Phase-3 window: the
    /// deployment root is already the new one, the private bundle
    /// carries the additive set so the leaf still chains to it, and the
    /// stored fingerprint deliberately still names the old root, as it
    /// does until the tail after Phase 4. The leaf is a day from expiry,
    /// so the ordinary predicate says renew.
    ///
    /// Returns the stale fingerprint and the file the profile's
    /// post-renew failure hook records its reason in.
    fn write_mid_rotation_internal_host(
        secrets: &std::path::Path,
        paths: &crate::registrar::internal::InternalPaths,
        acme_url: &str,
    ) -> (String, PathBuf) {
        let old = build_test_ca("old");
        let new = build_test_ca("new");
        let certs = secrets.join("certs");
        fs::create_dir_all(&certs).unwrap();
        fs::write(certs.join("root_ca.crt"), new.root_cert.pem()).unwrap();
        let stale_fp = crate::tls::sha256_hex(old.root_cert.der().as_ref());
        let active_fp = crate::tls::sha256_hex(new.root_cert.der().as_ref());
        assert_ne!(stale_fp, active_fp);

        fs::create_dir_all(paths.dir()).unwrap();
        let signing_key = rcgen::KeyPair::generate().unwrap();
        let mut params =
            rcgen::CertificateParams::new(vec!["001.bootroot-registrar-internal".to_string()])
                .unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(80);
        params.not_after = now + time::Duration::days(1);
        let leaf = params
            .signed_by(&signing_key, &old.intermediate_issuer)
            .unwrap();
        fs::write(paths.chain(), leaf.pem()).unwrap();
        fs::write(paths.key(), signing_key.serialize_pem()).unwrap();

        // A real account key: a placeholder is rejected before the first
        // request is made, which would let the "no ACME request"
        // assertion pass even with the guard gone.
        let account_pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        fs::write(
            paths.acme_account(),
            serde_json::to_vec(&serde_json::json!({
                "account_key_pkcs8": base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    account_pkcs8.as_ref(),
                ),
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(paths.root_fingerprint(), format!("{stale_fp}\n")).unwrap();
        fs::write(
            paths.ca_bundle(),
            format!("{}{}", test_bundle_pem(&old), test_bundle_pem(&new)),
        )
        .unwrap();

        // The profile's ordinary post-renew failure hook is the only
        // reporting path a refusal takes, and what it is handed is what
        // separates "refused before ACME" from "tried ACME and failed".
        let reason_path = secrets.join("failure-reason");
        let hook = format!(
            "\n[[profiles.hooks.post_renew.failure]]\ncommand = \"/bin/sh\"\n\
             args = [\"-c\", \"printf %s \\\"$RENEW_ERROR\\\" > {}\"]\n",
            reason_path.display()
        );
        let config = crate::registrar::internal::render_internal_agent_config(
            paths,
            &crate::registrar::internal::InternalAgentConfigParams {
                email: "ops@example.internal",
                server: acme_url,
                domain: TEST_DOMAIN,
                hostname: "bootroot-01",
                responder_url: "http://127.0.0.1:8080",
                responder_hmac: &"hmac".into(),
                eab_kid: None,
                eab_hmac: None,
                trusted_ca_sha256: &[stale_fp.clone(), active_fp],
            },
        );
        fs::write(paths.agent_config(), format!("{config}{hook}")).unwrap();
        (stale_fp, reason_path)
    }

    /// The fail-closed guard, end to end through the ordinary loop.
    ///
    /// The tick is due — `should_renew` says so — and must still make no
    /// ACME request and leave the chain and the key exactly as it found
    /// them, because a leaf reissued inside the Phase-3 window would be
    /// chained to a root the `auth/cert` entry does not yet trust.
    #[tokio::test]
    async fn a_stale_stored_root_stops_the_internal_tick_before_any_acme_request() {
        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path();
        let paths = crate::registrar::internal::InternalPaths::new(secrets);

        // A stand-in for step-ca that never answers: the assertion is
        // that nothing ever *connects* to it, and a non-blocking accept
        // says so without waiting. The URL is `https://` because the
        // ACME client refuses a plaintext directory before it dials,
        // which would make the assertion pass for the wrong reason.
        let acme = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        acme.set_nonblocking(true).unwrap();
        let acme_url = format!("https://{}/acme/acme/directory", acme.local_addr().unwrap());

        let (stale_fp, reason_path) = write_mid_rotation_internal_host(secrets, &paths, &acme_url);

        let settings = config::Settings::from_file(Some(paths.agent_config())).unwrap();
        let profile = settings.profiles.first().unwrap();
        let lead = Duration::from_secs(THIRTY_DAYS_SECS);
        assert!(
            should_renew(profile, &settings.trust, lead).await.unwrap(),
            "the fixture must actually be due for renewal"
        );

        let chain_before = fs::read(paths.chain()).unwrap();
        let key_before = fs::read(paths.key()).unwrap();

        check_and_renew_profile(
            &settings,
            profile,
            None,
            Arc::new(Semaphore::new(1)),
            &ProfileLocks::new(),
            lead,
            &IssuanceRuntime {
                config_path: paths.agent_config(),
                insecure_mode: false,
                cli_overrides: config::CliOverrides::default(),
            },
        )
        .await
        .expect("a refused tick is not a daemon failure; the loop keeps ticking");

        assert!(
            matches!(
                acme.accept().map_err(|err| err.kind()),
                Err(std::io::ErrorKind::WouldBlock)
            ),
            "the tick must not have reached the ACME directory"
        );
        assert_eq!(fs::read(paths.chain()).unwrap(), chain_before);
        assert_eq!(fs::read(paths.key()).unwrap(), key_before);

        let reason = fs::read_to_string(&reason_path)
            .expect("the ordinary failure hook must have reported the refusal");
        assert!(
            reason.contains(&stale_fp)
                && reason.contains("bootroot rotate registrar-internal-credential"),
            "the refusal must be the typed repair-required one, got: {reason}"
        );
    }

    /// The generated internal config with a second, test-only profile
    /// appended — the fixture the two tests above share.
    fn internal_config_with_second_profile(dir: &std::path::Path) -> String {
        let paths = crate::registrar::internal::InternalPaths::new(dir);
        let base = crate::registrar::internal::render_internal_agent_config(
            &paths,
            &crate::registrar::internal::InternalAgentConfigParams {
                email: "ops@example.internal",
                server: "https://localhost:9000/acme/acme/directory",
                domain: TEST_DOMAIN,
                hostname: "bootroot-01",
                responder_url: "http://127.0.0.1:8080",
                responder_hmac: &"hmac".into(),
                eab_kid: None,
                eab_hmac: None,
                trusted_ca_sha256: &[],
            },
        );
        let loop_settings = "\n[profiles.daemon]\ncheck_interval = \"2h\"\nrenew_before = \"24h\"\ncheck_jitter = \"30s\"\n\n[[profiles.hooks.post_renew.failure]]\ncommand = \"/bin/true\"\n";
        format!(
            "{base}{loop_settings}\n\
             [[profiles]]\nregistration_id = \"companion\"\nservice_name = \"companion\"\n\
             instance_id = \"001\"\nhostname = \"bootroot-01\"\n\
             \n[profiles.paths]\ncert = \"{cert}\"\nkey = \"{key}\"\n{loop_settings}",
            cert = dir.join("companion.pem").display(),
            key = dir.join("companion.key").display(),
        )
    }

    #[test]
    fn test_select_retry_backoff_uses_profile_override() {
        let settings = build_settings(vec![5, 10, 30]);
        let mut profile = build_profile(PathBuf::from("unused.pem"));
        profile.retry = Some(RetrySettings {
            backoff_secs: vec![1, 2],
        });

        let selected = select_retry_backoff(&settings, &profile);

        assert_eq!(selected, profile.retry.as_ref().unwrap().backoff_secs);
    }

    #[test]
    fn test_select_retry_backoff_falls_back_to_global() {
        let settings = build_settings(vec![5, 10, 30]);
        let profile = build_profile(PathBuf::from("unused.pem"));

        let selected = select_retry_backoff(&settings, &profile);

        assert_eq!(selected, settings.retry.backoff_secs);
    }

    #[test]
    fn test_resolve_config_path_uses_default_when_none() {
        let resolved = resolve_config_path(None);
        assert_eq!(resolved, PathBuf::from(DEFAULT_AGENT_CONFIG_PATH));
    }

    #[test]
    fn test_resolve_config_path_prefers_provided_path() {
        let provided = PathBuf::from("/tmp/custom-agent.toml");
        let resolved = resolve_config_path(Some(&provided));
        assert_eq!(resolved, provided);
    }

    #[test]
    fn test_jittered_delay_zero_jitter_returns_base() {
        let base = Duration::from_secs(TEST_BASE_SECS);
        let jitter = Duration::from_secs(0);

        let delay = crate::utils::jittered_delay_with_seed(base, jitter, TEST_SEED_NS);

        assert_eq!(delay, base);
    }

    #[test]
    fn test_jittered_delay_bounds() {
        let base = Duration::from_secs(TEST_BASE_SECS);
        let jitter = Duration::from_secs(TEST_JITTER_SECS);
        let delay = crate::utils::jittered_delay_with_seed(base, jitter, TEST_SEED_NS);

        let min = base.saturating_sub(jitter);
        let max = base + jitter;

        assert!(delay >= min);
        assert!(delay <= max);
    }

    #[test]
    fn test_jittered_delay_minimum_floor() {
        let base = Duration::from_secs(2);
        let jitter = Duration::from_secs(10);
        let delay = crate::utils::jittered_delay_with_seed(base, jitter, 0);

        let min =
            Duration::from_nanos(u64::try_from(crate::utils::MIN_JITTER_DELAY_NANOS).unwrap());
        let max = base + jitter;

        assert!(delay >= min);
        assert!(delay <= max);
    }

    #[tokio::test]
    async fn test_should_renew_when_missing_cert() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("missing.pem");
        let profile = build_profile(cert_path);

        let renew = should_renew(
            &profile,
            &config::TrustSettings::default(),
            Duration::from_mins(1),
        )
        .await
        .unwrap();

        assert!(renew);
    }

    #[tokio::test]
    async fn test_should_renew_when_far_from_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("valid.pem");
        let profile = build_profile(cert_path.clone());

        let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(90);
        write_cert(&cert_path, not_after);

        let renew = should_renew(
            &profile,
            &config::TrustSettings::default(),
            Duration::from_secs(THIRTY_DAYS_SECS),
        )
        .await
        .unwrap();

        assert!(!renew);
    }

    #[tokio::test]
    async fn test_should_renew_when_near_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("expiring.pem");
        let profile = build_profile(cert_path.clone());

        let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(1);
        write_cert(&cert_path, not_after);

        let renew = should_renew(
            &profile,
            &config::TrustSettings::default(),
            Duration::from_secs(THIRTY_DAYS_SECS),
        )
        .await
        .unwrap();

        assert!(renew);
    }

    #[tokio::test]
    async fn test_should_renew_invalid_pem_errors() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("invalid.pem");
        fs::write(&cert_path, "not a cert").unwrap();
        let profile = build_profile(cert_path);

        let err = should_renew(
            &profile,
            &config::TrustSettings::default(),
            Duration::from_secs(THIRTY_DAYS_SECS),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("Failed to parse PEM certificate"));
    }

    #[test]
    fn test_parse_cert_not_after() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("parse.pem");
        let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(10);
        write_cert(&cert_path, not_after);
        let cert_bytes = fs::read(cert_path).unwrap();

        let parsed = parse_cert_not_after(&cert_bytes).unwrap();

        assert_eq!(parsed.unix_timestamp(), not_after.unix_timestamp());
    }

    /// Regression for issue #627: when `[trust].ca_bundle_path` is
    /// configured, a time-valid leaf whose signer is no longer in the
    /// bundle (the post-`init`-rotation state) must force a reissue.
    #[tokio::test]
    async fn test_should_renew_when_leaf_does_not_chain_to_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let bundle_path = dir.path().join("ca-bundle.pem");

        let old_ca = build_test_ca("gen1");
        let new_ca = build_test_ca("gen2");
        let leaf_pem = sign_test_leaf("svc.example", &old_ca);
        fs::write(&cert_path, &leaf_pem).unwrap();
        fs::write(&bundle_path, test_bundle_pem(&new_ca)).unwrap();

        let profile = build_profile(cert_path);
        let trust = config::TrustSettings {
            ca_bundle_path: Some(bundle_path),
            trusted_ca_sha256: Vec::new(),
        };

        let renew = should_renew(&profile, &trust, Duration::from_secs(THIRTY_DAYS_SECS))
            .await
            .unwrap();

        assert!(
            renew,
            "leaf signed by previous intermediate must trigger renewal"
        );
    }

    /// Healthy state: leaf chains to the current bundle and is far
    /// from expiry. The chain check must not force a needless reissue.
    #[tokio::test]
    async fn test_should_renew_skips_when_leaf_chains_to_bundle() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let bundle_path = dir.path().join("ca-bundle.pem");

        let ca = build_test_ca("gen1");
        let leaf_pem = sign_test_leaf("svc.example", &ca);
        fs::write(&cert_path, &leaf_pem).unwrap();
        fs::write(&bundle_path, test_bundle_pem(&ca)).unwrap();

        let profile = build_profile(cert_path);
        let trust = config::TrustSettings {
            ca_bundle_path: Some(bundle_path),
            trusted_ca_sha256: Vec::new(),
        };

        let renew = should_renew(&profile, &trust, Duration::from_secs(THIRTY_DAYS_SECS))
            .await
            .unwrap();

        assert!(!renew);
    }

    /// A configured-but-missing bundle is a broken state; the agent
    /// must reissue so `write_merged_ca_bundle` lays down a fresh
    /// bundle alongside the new leaf.
    #[tokio::test]
    async fn test_should_renew_when_bundle_missing() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let bundle_path = dir.path().join("missing-bundle.pem");

        let ca = build_test_ca("gen1");
        fs::write(&cert_path, sign_test_leaf("svc.example", &ca)).unwrap();

        let profile = build_profile(cert_path);
        let trust = config::TrustSettings {
            ca_bundle_path: Some(bundle_path),
            trusted_ca_sha256: Vec::new(),
        };

        let renew = should_renew(&profile, &trust, Duration::from_secs(THIRTY_DAYS_SECS))
            .await
            .unwrap();

        assert!(renew);
    }

    #[tokio::test]
    async fn test_should_renew_rejects_large_duration() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("valid.pem");
        let profile = build_profile(cert_path.clone());

        let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(90);
        write_cert(&cert_path, not_after);

        let err = should_renew(&profile, &config::TrustSettings::default(), Duration::MAX)
            .await
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("renew_before duration is too large")
        );
    }

    #[tokio::test]
    async fn test_issue_with_retry_succeeds_after_retries() {
        let attempts = Arc::new(Mutex::new(0usize));
        let sleeps = Arc::new(Mutex::new(Vec::new()));

        let attempts_issue = Arc::clone(&attempts);
        let issue_fn = move || {
            let attempts_inner = Arc::clone(&attempts_issue);
            async move {
                let mut guard = attempts_inner.lock().unwrap();
                *guard += 1;
                if *guard < 3 {
                    anyhow::bail!("transient failure");
                }
                Ok(())
            }
        };

        let sleeps_log = Arc::clone(&sleeps);
        let sleep_fn = move |duration: Duration| {
            let sleeps_inner = Arc::clone(&sleeps_log);
            async move {
                sleeps_inner.lock().unwrap().push(duration);
            }
        };

        let ok = issue_with_retry_inner(issue_fn, sleep_fn, &TEST_DELAYS).await;

        assert!(ok.is_ok());
        assert_eq!(*attempts.lock().unwrap(), 3);
        assert_eq!(
            *sleeps.lock().unwrap(),
            vec![Duration::from_secs(1), Duration::from_secs(2)]
        );
    }

    #[tokio::test]
    async fn test_issue_with_retry_gives_up() {
        let attempts = Arc::new(Mutex::new(0usize));
        let sleeps = Arc::new(Mutex::new(Vec::new()));

        let attempts_issue = Arc::clone(&attempts);
        let issue_fn = move || {
            let attempts_inner = Arc::clone(&attempts_issue);
            async move {
                let mut guard = attempts_inner.lock().unwrap();
                *guard += 1;
                anyhow::bail!("persistent failure");
            }
        };

        let sleeps_log = Arc::clone(&sleeps);
        let sleep_fn = move |duration: Duration| {
            let sleeps_inner = Arc::clone(&sleeps_log);
            async move {
                sleeps_inner.lock().unwrap().push(duration);
            }
        };

        let ok = issue_with_retry_inner(issue_fn, sleep_fn, &TEST_DELAYS).await;

        assert!(ok.is_err());
        assert_eq!(*attempts.lock().unwrap(), TEST_DELAYS.len() + 1);
        assert_eq!(
            *sleeps.lock().unwrap(),
            TEST_DELAYS
                .iter()
                .copied()
                .map(Duration::from_secs)
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_collect_task_results_returns_ok_when_all_succeed() {
        let handles = vec![
            tokio::spawn(async { Ok(()) }),
            tokio::spawn(async { Ok(()) }),
        ];

        let result = collect_task_results(handles, "test").await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_collect_task_results_returns_first_error() {
        let handles: Vec<tokio::task::JoinHandle<anyhow::Result<()>>> = vec![
            tokio::spawn(async { anyhow::bail!("first failure") }),
            tokio::spawn(async { anyhow::bail!("second failure") }),
        ];

        let result = collect_task_results(handles, "test").await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("first failure"));
    }

    #[tokio::test]
    async fn profile_locks_serialise_same_profile() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let locks = Arc::new(ProfileLocks::new());
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));
        let profile = "edge-proxy";

        let mut handles = Vec::new();
        for _ in 0..5 {
            let locks = Arc::clone(&locks);
            let in_flight = Arc::clone(&in_flight);
            let max_in_flight = Arc::clone(&max_in_flight);
            handles.push(tokio::spawn(async move {
                let lock = locks.for_profile(profile);
                let _guard = lock.lock().await;
                let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_in_flight.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(max_in_flight.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn profile_locks_allow_different_profiles_concurrently() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let locks = Arc::new(ProfileLocks::new());
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for i in 0..4 {
            let locks = Arc::clone(&locks);
            let in_flight = Arc::clone(&in_flight);
            let max_in_flight = Arc::clone(&max_in_flight);
            let label = format!("profile-{i}");
            handles.push(tokio::spawn(async move {
                let lock = locks.for_profile(&label);
                let _guard = lock.lock().await;
                let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_in_flight.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(40)).await;
                in_flight.fetch_sub(1, Ordering::SeqCst);
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        assert!(max_in_flight.load(Ordering::SeqCst) >= 2);
    }

    // Reviewer round 10: when the fast-poll force-reissue path is renewing
    // a profile at the same moment a periodic `check_interval` tick fires,
    // the old code let both paths issue — the periodic path decided
    // "needs renewal" from the pre-rotation cert on disk before acquiring
    // the shared semaphore. The per-profile lock now forces the periodic
    // tick to wait for the in-flight force-reissue, re-read the rotated
    // cert, and skip the redundant issuance.
    #[tokio::test]
    async fn profile_lock_blocks_double_issuance_when_force_and_periodic_race() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        // Initial cert is close enough to expiry that `should_renew`
        // would fire if called right now.
        write_cert(
            &cert_path,
            time::OffsetDateTime::now_utc() + time::Duration::days(1),
        );
        let profile = build_profile(cert_path.clone());
        let profile_label = config::profile_domain(&build_settings(vec![]), &profile);
        let renew_before = Duration::from_secs(THIRTY_DAYS_SECS);

        let locks = Arc::new(ProfileLocks::new());
        let issue_count = Arc::new(AtomicUsize::new(0));

        // Force path: grab the lock first, pretend to issue (we rotate
        // the cert on disk by writing a fresh one), then release.
        let force = {
            let locks = Arc::clone(&locks);
            let issue_count = Arc::clone(&issue_count);
            let profile_label = profile_label.clone();
            let cert_path = cert_path.clone();
            tokio::spawn(async move {
                let lock = locks.for_profile(&profile_label);
                let _guard = lock.lock().await;
                // Ensure the periodic task has time to queue behind us.
                tokio::time::sleep(Duration::from_millis(50)).await;
                write_cert(
                    &cert_path,
                    time::OffsetDateTime::now_utc() + time::Duration::days(90),
                );
                issue_count.fetch_add(1, Ordering::SeqCst);
            })
        };

        // Periodic path: runs the same lock-then-check-then-issue flow
        // used by `check_and_renew_profile`. It must observe the rotated
        // cert once the force path releases and skip issuance.
        let periodic = {
            let locks = Arc::clone(&locks);
            let issue_count = Arc::clone(&issue_count);
            let profile_label = profile_label.clone();
            let profile = profile.clone();
            tokio::spawn(async move {
                // Give the force task a head start on grabbing the lock.
                tokio::time::sleep(Duration::from_millis(10)).await;
                let lock = locks.for_profile(&profile_label);
                let _guard = lock.lock().await;
                let needs = should_renew(&profile, &config::TrustSettings::default(), renew_before)
                    .await
                    .expect("should_renew reads the cert");
                if needs {
                    issue_count.fetch_add(1, Ordering::SeqCst);
                }
            })
        };

        force.await.unwrap();
        periodic.await.unwrap();

        assert_eq!(
            issue_count.load(Ordering::SeqCst),
            1,
            "only the force path should have issued; periodic must observe the rotated cert under the lock and skip",
        );
    }

    fn fallback_pair() -> (config::Settings, config::DaemonProfileSettings) {
        let mut settings = build_settings(vec![5, 10]);
        settings.domain = "trusted.domain".to_string();
        settings.email = "fallback@example.com".to_string();
        let profile = build_profile(PathBuf::from("/tmp/fallback.pem"));
        (settings, profile)
    }

    fn write_agent_toml_with_profile(file: &Path, email: &str) {
        let body = format!(
            r#"
domain = "trusted.domain"
email = "{email}"
[acme]
http_responder_url = "http://localhost:8080"
http_responder_hmac = "dev-hmac"

[[profiles]]
registration_id = "edge-proxy"
service_name = "edge-proxy"
instance_id = "001"
hostname = "edge-node-01"

[profiles.paths]
cert = "certs/edge-proxy-a.pem"
key = "certs/edge-proxy-a.key"
"#
        );
        fs::write(file, body).unwrap();
    }

    fn write_agent_toml_without_profile(file: &Path) {
        let body = r#"
domain = "trusted.domain"
email = "reloaded@example.com"
[acme]
http_responder_url = "http://localhost:8080"
http_responder_hmac = "dev-hmac"
"#;
        fs::write(file, body).unwrap();
    }

    /// When the reloaded config contains the target profile, the fresh
    /// values must win — this preserves the original intent of #303
    /// (pick up freshly-rendered KV values across retries).
    #[test]
    fn reload_profile_or_fallback_uses_fresh_when_profile_present() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        write_agent_toml_with_profile(&path, "reloaded@example.com");
        let (fallback_settings, fallback_profile) = fallback_pair();
        let domain = config::profile_domain(&fallback_settings, &fallback_profile);

        let (settings, _profile) = reload_profile_or_fallback(
            &path,
            &config::CliOverrides::default(),
            &domain,
            (fallback_settings.clone(), fallback_profile.clone()),
        );

        assert_eq!(settings.email, "reloaded@example.com");
        assert_ne!(settings.email, fallback_settings.email);
    }

    /// When the reloaded file is coherent but the named profile is
    /// missing (the race observed in #613), the fallback pair must be
    /// returned so the retry consumes ACME work rather than the retry
    /// budget against a transient file race.
    #[test]
    fn reload_profile_or_fallback_uses_fallback_when_profile_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        write_agent_toml_without_profile(&path);
        let (fallback_settings, fallback_profile) = fallback_pair();
        let domain = config::profile_domain(&fallback_settings, &fallback_profile);

        let (settings, profile) = reload_profile_or_fallback(
            &path,
            &config::CliOverrides::default(),
            &domain,
            (fallback_settings.clone(), fallback_profile.clone()),
        );

        assert_eq!(settings.email, fallback_settings.email);
        assert_eq!(profile.service_name, fallback_profile.service_name);
        assert_eq!(profile.instance_id, fallback_profile.instance_id);
    }

    /// The rotation task's predicate is exactly `[registrar_endpoint]
    /// enabled`: on a host where it is not true nothing is spawned at
    /// all, and the three `[registrar]` rotation keys are inert.
    #[test]
    fn the_openbao_audit_rotation_task_is_spawned_only_behind_the_endpoint_gate() {
        let (_, shutdown_rx) = watch::channel(false);

        let mut settings = build_settings(vec![1]);
        assert!(
            !settings.registrar_endpoint.enabled,
            "an absent [registrar_endpoint] table parses as disabled"
        );
        let mut handles = Vec::new();
        spawn_openbao_audit_rotation(&mut handles, &settings, &shutdown_rx, None);
        assert!(handles.is_empty(), "a disabled endpoint spawns no task");

        settings.registrar_endpoint.enabled = true;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let guard = runtime.enter();
        spawn_openbao_audit_rotation(&mut handles, &settings, &shutdown_rx, None);
        assert_eq!(handles.len(), 1, "an enabled endpoint spawns exactly one");
        drop(guard);
        for handle in handles {
            handle.abort();
        }
    }

    /// When the reload itself fails — corrupt TOML, mid-truncate
    /// reader, etc. — the fallback pair must be returned for the same
    /// retry-budget reason.
    #[test]
    fn reload_profile_or_fallback_uses_fallback_when_reload_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.toml");
        fs::write(&path, "this = = = is not valid toml").unwrap();
        let (fallback_settings, fallback_profile) = fallback_pair();
        let domain = config::profile_domain(&fallback_settings, &fallback_profile);

        let (settings, profile) = reload_profile_or_fallback(
            &path,
            &config::CliOverrides::default(),
            &domain,
            (fallback_settings.clone(), fallback_profile.clone()),
        );

        assert_eq!(settings.email, fallback_settings.email);
        assert_eq!(profile.service_name, fallback_profile.service_name);
    }
}
