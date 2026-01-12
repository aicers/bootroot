use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Semaphore, watch};
use tracing::{error, info};

use crate::{acme, config, eab, hooks, profile};
pub const MIN_DAEMON_CHECK_DELAY_NANOS: i128 = 1_000_000_000;

/// Runs the agent daemon loop for all profiles.
///
/// # Errors
/// Returns an error if issuance or shutdown handling fails.
pub async fn run_daemon(
    settings: Arc<config::Settings>,
    default_eab: Option<eab::EabCredentials>,
) -> anyhow::Result<()> {
    let max_concurrent = profile::max_concurrent_issuances(&settings)?;
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
        let default_eab = default_eab.clone();

        handles.push(tokio::spawn(async move {
            run_profile_daemon(settings, profile, default_eab, semaphore, shutdown_rx).await
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
    semaphore: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
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
            jittered_delay(check_interval, check_jitter)
        };

        tokio::select! {
            _ = shutdown.changed() => {
                info!("Shutdown signal received. Exiting profile '{}'.", profile_label);
                break;
            }
            () = tokio::time::sleep(delay) => {
                tracing::debug!("Profile '{}' checking renewal status...", profile_label);
                match should_renew(&profile, renew_before).await {
                    Ok(true) => {
                        info!(
                            "Profile '{}' renewal required. Starting ACME issuance...",
                            profile_label
                        );
                        let _permit = semaphore.acquire().await?;
                        let profile_eab = profile::resolve_profile_eab(&profile, default_eab.clone());
                        match issue_with_retry(&settings, &profile, profile_eab).await
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
                                    error!(
                                        "Post-renew success hooks failed for '{}': {err}",
                                        profile_label
                                    );
                                }
                            }
                            Err(err) => {
                                error!(
                                    "Profile '{}' renewal failed after retries: {err}",
                                    profile_label
                                );
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
                                        profile_label
                                    );
                                }
                            }
                        }
                    }
                    Ok(false) => {
                        tracing::debug!("Profile '{}' certificate still valid.", profile_label);
                    }
                    Err(err) => {
                        error!("Profile '{}' renewal check failed: {err}", profile_label);
                    }
                }
            }
        }
    }

    Ok(())
}

/// Runs a single issuance pass for all profiles.
///
/// # Errors
/// Returns an error if any profile issuance fails.
pub async fn run_oneshot(
    settings: Arc<config::Settings>,
    default_eab: Option<eab::EabCredentials>,
) -> anyhow::Result<()> {
    let max_concurrent = profile::max_concurrent_issuances(&settings)?;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut handles = Vec::new();

    for profile in settings.profiles.clone() {
        let settings = Arc::clone(&settings);
        let semaphore = Arc::clone(&semaphore);
        let default_eab = default_eab.clone();

        handles.push(tokio::spawn(async move {
            run_profile_oneshot(settings, profile, default_eab, semaphore).await
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
    semaphore: Arc<Semaphore>,
) -> anyhow::Result<()> {
    let _permit = semaphore.acquire().await?;
    let profile_eab = profile::resolve_profile_eab(&profile, default_eab);
    let profile_label = config::profile_domain(&settings, &profile);

    match acme::issue_certificate(&settings, &profile, profile_eab).await {
        Ok(()) => {
            if let Err(err) =
                hooks::run_post_renew_hooks(&settings, &profile, hooks::HookStatus::Success, None)
                    .await
            {
                error!(
                    "Post-renew success hooks failed for '{}': {err}",
                    profile_label
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
                    profile_label
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
) -> anyhow::Result<()> {
    let backoff = select_retry_backoff(settings, profile);
    issue_with_retry_inner(
        || acme::issue_certificate(settings, profile, eab.clone()),
        |duration| tokio::time::sleep(duration),
        backoff,
    )
    .await
}

fn select_retry_backoff<'a>(
    settings: &'a config::Settings,
    profile: &'a config::ProfileSettings,
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
pub async fn issue_with_retry_inner<IssueFn, IssueFut, SleepFn, SleepFut>(
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

/// Determines whether a certificate should be renewed.
///
/// # Errors
/// Returns an error if the certificate cannot be parsed or read.
pub async fn should_renew(
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

/// Parses the certificate expiration timestamp.
///
/// # Errors
/// Returns an error if the certificate cannot be parsed.
pub fn parse_cert_not_after(cert_bytes: &[u8]) -> anyhow::Result<time::OffsetDateTime> {
    let pem = x509_parser::pem::parse_x509_pem(cert_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM certificate: {e}"))?
        .1;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse X509 certificate: {e}"))?;
    Ok(cert.validity().not_after.to_datetime())
}

fn jittered_delay(base: Duration, jitter: Duration) -> Duration {
    let now_ns = time::OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .max(0);
    jittered_delay_with_seed(base, jitter, now_ns)
}

#[must_use]
pub fn jittered_delay_with_seed(base: Duration, jitter: Duration, now_ns: i128) -> Duration {
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::config::{AcmeSettings, DaemonSettings, Paths, RetrySettings, SchedulerSettings};

    fn build_profile() -> config::ProfileSettings {
        config::ProfileSettings {
            service_name: "edge-proxy".to_string(),
            instance_id: "001".to_string(),
            hostname: "edge-node-01".to_string(),
            paths: Paths {
                cert: PathBuf::from("unused.pem"),
                key: PathBuf::from("unused.key"),
            },
            daemon: DaemonSettings {
                check_interval: Duration::from_secs(60 * 60),
                renew_before: Duration::from_secs(720 * 60 * 60),
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
            scheduler: SchedulerSettings {
                max_concurrent_issuances: 1,
            },
            profiles: Vec::new(),
        }
    }

    #[test]
    fn test_select_retry_backoff_uses_profile_override() {
        let settings = build_settings(vec![5, 10, 30]);
        let mut profile = build_profile();
        profile.retry = Some(RetrySettings {
            backoff_secs: vec![1, 2],
        });

        let selected = select_retry_backoff(&settings, &profile);

        assert_eq!(selected, profile.retry.as_ref().unwrap().backoff_secs);
    }

    #[test]
    fn test_select_retry_backoff_falls_back_to_global() {
        let settings = build_settings(vec![5, 10, 30]);
        let profile = build_profile();

        let selected = select_retry_backoff(&settings, &profile);

        assert_eq!(selected, settings.retry.backoff_secs);
    }
}
