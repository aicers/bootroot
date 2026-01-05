use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Semaphore, watch};
use tracing::{error, info};

use crate::{acme, config, eab, hooks};

const DAEMON_CHECK_INTERVAL_KEY: &str = "daemon.check_interval";
const DAEMON_RENEW_BEFORE_KEY: &str = "daemon.renew_before";
const DAEMON_CHECK_JITTER_KEY: &str = "daemon.check_jitter";
pub(crate) const MIN_DAEMON_CHECK_DELAY_NANOS: i128 = 1_000_000_000;

pub(crate) async fn run_daemon(
    settings: Arc<config::Settings>,
    default_eab: Option<eab::EabCredentials>,
    challenges: Arc<Mutex<HashMap<String, String>>>,
) -> anyhow::Result<()> {
    let max_concurrent = max_concurrent_issuances(&settings)?;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

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
        let challenges = challenges.clone();
        let default_eab = default_eab.clone();

        handles.push(tokio::spawn(async move {
            run_profile_daemon(
                settings,
                profile,
                default_eab,
                challenges,
                semaphore,
                shutdown_rx,
            )
            .await
        }));
    }

    let _ = shutdown_handle.await;
    for handle in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => error!("Profile daemon exited with error: {err}"),
            Err(err) => error!("Profile daemon task join error: {err}"),
        }
    }

    Ok(())
}

async fn run_profile_daemon(
    settings: Arc<config::Settings>,
    profile: config::ProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    challenges: Arc<Mutex<HashMap<String, String>>>,
    semaphore: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let check_interval =
        parse_duration_setting(&profile.daemon.check_interval, DAEMON_CHECK_INTERVAL_KEY)?;
    let renew_before =
        parse_duration_setting(&profile.daemon.renew_before, DAEMON_RENEW_BEFORE_KEY)?;
    let check_jitter =
        parse_duration_setting(&profile.daemon.check_jitter, DAEMON_CHECK_JITTER_KEY)?;
    let uri_san = if profile.uri_san_enabled {
        Some(build_spiffe_uri(&settings, &profile))
    } else {
        None
    };

    info!(
        "Profile '{}' daemon enabled. check_interval={:?}, renew_before={:?}, check_jitter={:?}",
        profile.name, check_interval, renew_before, check_jitter
    );

    let mut first_tick = true;
    loop {
        if *shutdown.borrow() {
            info!(
                "Shutdown signal received. Exiting profile '{}'.",
                profile.name
            );
            break;
        }

        let delay = if first_tick {
            first_tick = false;
            Duration::from_secs(0)
        } else {
            jittered_delay(check_interval, check_jitter)
        };

        tokio::select! {
            _ = shutdown.changed() => {
                info!("Shutdown signal received. Exiting profile '{}'.", profile.name);
                break;
            }
            () = tokio::time::sleep(delay) => {
                tracing::debug!("Profile '{}' checking renewal status...", profile.name);
                match should_renew(&profile, renew_before).await {
                    Ok(true) => {
                        info!("Profile '{}' renewal required. Starting ACME issuance...", profile.name);
                        let _permit = semaphore.acquire().await?;
                        let profile_eab = resolve_profile_eab(&profile, default_eab.clone());
                        match issue_with_retry(
                            &settings,
                            &profile,
                            profile_eab,
                            challenges.clone(),
                            uri_san.as_deref(),
                        )
                        .await
                        {
                            Ok(()) => {
                                if let Err(err) = hooks::run_post_renew_hooks(
                                    &settings,
                                    &profile,
                                    hooks::HookStatus::Success,
                                    None,
                                )
                                .await
                                {
                                    error!("Post-renew success hooks failed for '{}': {err}", profile.name);
                                }
                            }
                            Err(err) => {
                                error!("Profile '{}' renewal failed after retries: {err}", profile.name);
                                if let Err(hook_err) = hooks::run_post_renew_hooks(
                                    &settings,
                                    &profile,
                                    hooks::HookStatus::Failure,
                                    Some(err.to_string()),
                                )
                                .await
                                {
                                    error!("Post-renew failure hooks failed for '{}': {hook_err}", profile.name);
                                }
                            }
                        }
                    }
                    Ok(false) => {
                        tracing::debug!("Profile '{}' certificate still valid.", profile.name);
                    }
                    Err(err) => {
                        error!("Profile '{}' renewal check failed: {err}", profile.name);
                    }
                }
            }
        }
    }

    Ok(())
}

pub(crate) async fn run_oneshot(
    settings: Arc<config::Settings>,
    default_eab: Option<eab::EabCredentials>,
    challenges: Arc<Mutex<HashMap<String, String>>>,
) -> anyhow::Result<()> {
    let max_concurrent = max_concurrent_issuances(&settings)?;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut handles = Vec::new();

    for profile in settings.profiles.clone() {
        let settings = Arc::clone(&settings);
        let challenges = challenges.clone();
        let semaphore = Arc::clone(&semaphore);
        let default_eab = default_eab.clone();

        handles.push(tokio::spawn(async move {
            run_profile_oneshot(settings, profile, default_eab, challenges, semaphore).await
        }));
    }

    let mut first_error = None;
    for handle in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                error!("Profile oneshot failed: {err}");
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
            Err(err) => {
                error!("Profile oneshot task join error: {err}");
                if first_error.is_none() {
                    first_error = Some(anyhow::anyhow!("Profile task join error: {err}"));
                }
            }
        }
    }

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(())
    }
}

async fn run_profile_oneshot(
    settings: Arc<config::Settings>,
    profile: config::ProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    challenges: Arc<Mutex<HashMap<String, String>>>,
    semaphore: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let _permit = semaphore.acquire().await?;
    let uri_san = if profile.uri_san_enabled {
        Some(build_spiffe_uri(&settings, &profile))
    } else {
        None
    };
    let profile_eab = resolve_profile_eab(&profile, default_eab);

    match acme::issue_certificate(
        &settings,
        &profile,
        profile_eab,
        challenges,
        uri_san.as_deref(),
    )
    .await
    {
        Ok(()) => {
            if let Err(err) =
                hooks::run_post_renew_hooks(&settings, &profile, hooks::HookStatus::Success, None)
                    .await
            {
                error!(
                    "Post-renew success hooks failed for '{}': {err}",
                    profile.name
                );
            }
            Ok(())
        }
        Err(err) => {
            if let Err(hook_err) = hooks::run_post_renew_hooks(
                &settings,
                &profile,
                hooks::HookStatus::Failure,
                Some(err.to_string()),
            )
            .await
            {
                error!(
                    "Post-renew failure hooks failed for '{}': {hook_err}",
                    profile.name
                );
            }
            Err(err)
        }
    }
}

async fn issue_with_retry(
    settings: &config::Settings,
    profile: &config::ProfileSettings,
    eab: Option<eab::EabCredentials>,
    challenges: Arc<Mutex<HashMap<String, String>>>,
    uri_san: Option<&str>,
) -> anyhow::Result<()> {
    let backoff = profile
        .retry
        .as_ref()
        .map_or(settings.retry.backoff_secs.as_slice(), |retry| {
            retry.backoff_secs.as_slice()
        });
    issue_with_retry_inner(
        || acme::issue_certificate(settings, profile, eab.clone(), challenges.clone(), uri_san),
        |duration| tokio::time::sleep(duration),
        backoff,
    )
    .await
}

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
    if delays.is_empty() {
        return issue_fn().await;
    }

    let mut last_err = None;
    for (attempt, delay) in delays.iter().enumerate() {
        match issue_fn().await {
            Ok(()) => {
                info!("Certificate issuance succeeded.");
                return Ok(());
            }
            Err(err) => {
                error!(
                    "Certificate issuance failed (attempt {}): {err}",
                    attempt + 1
                );
                last_err = Some(err);
                if attempt + 1 < delays.len() {
                    sleep_fn(Duration::from_secs(*delay)).await;
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Certificate issuance failed")))
}

pub(crate) fn build_spiffe_uri(
    settings: &config::Settings,
    profile: &config::ProfileSettings,
) -> String {
    format!(
        "spiffe://{}/{}/{}/{}",
        settings.spiffe_trust_domain, profile.hostname, profile.daemon_name, profile.instance_id
    )
}

pub(crate) fn resolve_profile_eab(
    profile: &config::ProfileSettings,
    default_eab: Option<eab::EabCredentials>,
) -> Option<eab::EabCredentials> {
    profile.eab.as_ref().map(to_eab_credentials).or(default_eab)
}

pub(crate) fn to_eab_credentials(eab: &config::Eab) -> eab::EabCredentials {
    eab::EabCredentials {
        kid: eab.kid.clone(),
        hmac: eab.hmac.clone(),
    }
}

pub(crate) fn max_concurrent_issuances(settings: &config::Settings) -> anyhow::Result<usize> {
    usize::try_from(settings.scheduler.max_concurrent_issuances).map_err(|_| {
        anyhow::anyhow!("scheduler.max_concurrent_issuances is too large for this platform")
    })
}

pub(crate) async fn should_renew(
    profile: &config::ProfileSettings,
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

pub(crate) fn parse_cert_not_after(cert_bytes: &[u8]) -> anyhow::Result<time::OffsetDateTime> {
    let pem = x509_parser::pem::parse_x509_pem(cert_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM certificate: {e}"))?
        .1;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse X509 certificate: {e}"))?;
    Ok(cert.validity().not_after.to_datetime())
}

pub(crate) fn parse_duration_setting(value: &str, label: &str) -> anyhow::Result<Duration> {
    humantime::parse_duration(value)
        .map_err(|e| anyhow::anyhow!("Invalid {label} value '{value}': {e}"))
}

fn jittered_delay(base: Duration, jitter: Duration) -> Duration {
    let now_ns = time::OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .max(0);
    jittered_delay_with_seed(base, jitter, now_ns)
}

pub(crate) fn jittered_delay_with_seed(base: Duration, jitter: Duration, now_ns: i128) -> Duration {
    let jitter_ns = i128::try_from(jitter.as_nanos()).unwrap_or(i128::MAX);
    if jitter_ns == 0 {
        return base;
    }

    let base_ns = i128::try_from(base.as_nanos()).unwrap_or(i128::MAX);
    let span = jitter_ns.saturating_mul(2).saturating_add(1);
    let offset = (now_ns % span) - jitter_ns;
    let adjusted = (base_ns + offset).max(MIN_DAEMON_CHECK_DELAY_NANOS);
    let adjusted = adjusted.min(i128::from(u64::MAX));
    let adjusted = u64::try_from(adjusted).unwrap_or(u64::MAX);

    Duration::from_nanos(adjusted)
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
