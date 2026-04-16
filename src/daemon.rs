use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, watch};
use tracing::{error, info};

use crate::{acme, config, eab, hooks, profile, utils};

const DEFAULT_AGENT_CONFIG_PATH: &str = "agent.toml";

#[derive(Clone)]
struct IssuanceRuntime {
    config_path: PathBuf,
    insecure_mode: bool,
    cli_overrides: config::CliOverrides,
}

/// Runs the agent daemon loop for all profiles.
///
/// # Errors
/// Returns an error if issuance or shutdown handling fails.
pub(crate) async fn run_daemon(
    settings: Arc<config::Settings>,
    default_eab: Option<eab::EabCredentials>,
    config_path: Option<PathBuf>,
    insecure_mode: bool,
    cli_overrides: config::CliOverrides,
) -> anyhow::Result<()> {
    let max_concurrent = profile::max_concurrent_issuances(&settings)?;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let runtime = IssuanceRuntime {
        config_path: resolve_config_path(config_path.as_deref()),
        insecure_mode,
        cli_overrides,
    };

    let shutdown_handle = tokio::spawn(async move {
        if let Err(err) = wait_for_shutdown().await {
            error!("Shutdown signal handler error: {err}");
        }
        let _ = shutdown_tx.send(true);
    });

    let mut handles = Vec::new();
    for profile in settings.profiles.clone() {
        let settings = Arc::clone(&settings);
        let semaphore = Arc::clone(&semaphore);
        let shutdown_rx = shutdown_rx.clone();
        let default_eab = default_eab.clone();
        let runtime = runtime.clone();

        handles.push(tokio::spawn(async move {
            run_profile_daemon(
                settings,
                profile,
                default_eab,
                semaphore,
                shutdown_rx,
                runtime,
            )
            .await
        }));
    }

    let _ = shutdown_handle.await;
    collect_task_results(handles, "daemon").await
}

async fn run_profile_daemon(
    settings: Arc<config::Settings>,
    profile: config::DaemonProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    semaphore: Arc<Semaphore>,
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
                    default_eab.clone(),
                    Arc::clone(&semaphore),
                    renew_before,
                    &profile_label,
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

async fn run_profile_oneshot(
    settings: Arc<config::Settings>,
    profile: config::DaemonProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    semaphore: Arc<Semaphore>,
    runtime: IssuanceRuntime,
) -> anyhow::Result<()> {
    let _permit = semaphore.acquire().await?;
    let profile_eab = profile::resolve_profile_eab(&profile, default_eab);
    let profile_label = config::profile_domain(&settings, &profile);

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
    issue_with_retry_inner(
        || {
            let path = config_path_owned.clone();
            let domain = profile_domain.clone();
            let eab = eab.clone();
            let overrides = cli_overrides.clone();
            async move {
                let mut fresh = config::Settings::new(Some(path))?;
                fresh.apply_overrides(&overrides);
                let fresh_profile = fresh
                    .profiles
                    .iter()
                    .find(|p| config::profile_domain(&fresh, p) == domain)
                    .ok_or_else(|| {
                        anyhow::anyhow!("Profile '{domain}' not found in reloaded config")
                    })?
                    .clone();
                let fresh_eab = profile::resolve_profile_eab(&fresh_profile, eab);
                acme::issue_certificate(&fresh, &fresh_profile, fresh_eab, insecure_mode).await
            }
        },
        |duration| tokio::time::sleep(duration),
        backoff,
    )
    .await
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
/// # Errors
/// Returns an error if the certificate cannot be parsed or read.
pub(crate) async fn should_renew(
    profile: &config::DaemonProfileSettings,
    renew_before: Duration,
) -> anyhow::Result<bool> {
    let cert_bytes = match tokio::fs::read(&profile.paths.cert).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            info!("Certificate file not found. Issuing a new certificate.");
            return Ok(true);
        }
        Err(err) => {
            return Err(anyhow::anyhow!(
                "Failed to read certificate file {}: {err}",
                profile.paths.cert.display()
            ));
        }
    };

    let not_after = parse_cert_not_after(&cert_bytes)?;

    let renew_before = time::Duration::try_from(renew_before)
        .map_err(|_| anyhow::anyhow!("renew_before duration is too large"))?;
    let now = time::OffsetDateTime::now_utc();
    let renew_at = now + renew_before;

    Ok(not_after <= renew_at)
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

async fn check_and_renew_profile(
    settings: &config::Settings,
    profile: &config::DaemonProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    semaphore: Arc<Semaphore>,
    renew_before: Duration,
    profile_label: &str,
    runtime: &IssuanceRuntime,
) -> anyhow::Result<()> {
    tracing::debug!("Profile '{}' checking renewal status...", profile_label);

    let needs_renewal = match should_renew(profile, renew_before).await {
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
    handle_issuance_result(&result, settings, profile, profile_label).await?;
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
                http_responder_url: "http://localhost:8080".to_string(),
                http_responder_hmac: "dev-hmac".to_string(),
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

        let renew = should_renew(&profile, Duration::from_mins(1))
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

        let renew = should_renew(&profile, Duration::from_secs(THIRTY_DAYS_SECS))
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

        let renew = should_renew(&profile, Duration::from_secs(THIRTY_DAYS_SECS))
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

        let err = should_renew(&profile, Duration::from_secs(THIRTY_DAYS_SECS))
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

    #[tokio::test]
    async fn test_should_renew_rejects_large_duration() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("valid.pem");
        let profile = build_profile(cert_path.clone());

        let not_after = time::OffsetDateTime::now_utc() + time::Duration::days(90);
        write_cert(&cert_path, not_after);

        let err = should_renew(&profile, Duration::MAX).await.unwrap_err();

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
        assert_eq!(*attempts.lock().unwrap(), 3);
        assert_eq!(
            *sleeps.lock().unwrap(),
            vec![Duration::from_secs(1), Duration::from_secs(2)]
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
}
