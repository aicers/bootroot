use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::{Mutex, Semaphore, watch};
use tracing::{error, info};

pub mod acme;
pub mod config;
pub mod eab;
pub mod hooks;

const DAEMON_CHECK_INTERVAL_KEY: &str = "daemon.check_interval";
const DAEMON_RENEW_BEFORE_KEY: &str = "daemon.renew_before";
const DAEMON_CHECK_JITTER_KEY: &str = "daemon.check_jitter";
const MIN_DAEMON_CHECK_DELAY_NANOS: i128 = 1_000_000_000;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to configuration file (default: agent.toml)
    #[arg(long, short)]
    config: Option<PathBuf>,

    /// Support email address
    #[arg(long)]
    email: Option<String>,

    /// ACME Directory URL
    #[arg(long)]
    ca_url: Option<String>,

    /// EAB Key ID (optional, overrides file/config)
    #[arg(long = "eab-kid")]
    eab_kid: Option<String>,

    /// EAB HMAC Key (optional, overrides file/config)
    #[arg(long = "eab-hmac")]
    eab_hmac: Option<String>,

    /// Path to EAB JSON file (optional)
    #[arg(long = "eab-file")]
    eab_file: Option<PathBuf>,

    /// Run once and exit (disable daemon loop)
    #[arg(long)]
    oneshot: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    info!("Starting Bootroot Agent (Rust)");

    // 1. Load Settings
    let mut settings = config::Settings::new(args.config.clone())?;

    // 2. Override Config with CLI Args
    settings.merge_with_args(&args);
    settings.validate()?;

    // 3. Resolve EAB Credentials
    // Priority: CLI Args > Config File
    let cli_eab = eab::load_credentials(
        args.eab_kid.clone(),
        args.eab_hmac.clone(),
        args.eab_file.clone(),
    )
    .await?;

    let final_eab = cli_eab.or_else(|| settings.eab.as_ref().map(to_eab_credentials));

    info!("Loaded {} profile(s).", settings.profiles.len());
    info!("CA URL: {}", settings.server);

    if let Some(ref creds) = final_eab {
        info!("Using EAB Credentials for Key ID: {}", creds.kid);
    } else {
        info!("No EAB credentials provided. Attempting open enrollment.");
    }

    let challenges = Arc::new(Mutex::new(HashMap::new()));
    let _challenge_server =
        acme::start_http01_server(challenges.clone(), settings.acme.http_challenge_port);

    let settings = Arc::new(settings);

    // 4. Run ACME Flow
    if args.oneshot {
        match run_oneshot(Arc::clone(&settings), final_eab, challenges).await {
            Ok(()) => info!("Successfully issued certificate!"),
            Err(e) => {
                error!("Failed to issue certificate: {:?}", e);
                std::process::exit(1);
            }
        }
    } else {
        run_daemon(settings, final_eab, challenges).await?;
    }

    Ok(())
}

async fn run_daemon(
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

async fn run_oneshot(
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

async fn issue_with_retry_inner<IssueFn, IssueFut, SleepFn, SleepFut>(
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

fn build_spiffe_uri(settings: &config::Settings, profile: &config::ProfileSettings) -> String {
    format!(
        "spiffe://{}/{}/{}/{}",
        settings.spiffe_trust_domain, profile.hostname, profile.daemon_name, profile.instance_id
    )
}

fn resolve_profile_eab(
    profile: &config::ProfileSettings,
    default_eab: Option<eab::EabCredentials>,
) -> Option<eab::EabCredentials> {
    profile.eab.as_ref().map(to_eab_credentials).or(default_eab)
}

fn to_eab_credentials(eab: &config::Eab) -> eab::EabCredentials {
    eab::EabCredentials {
        kid: eab.kid.clone(),
        hmac: eab.hmac.clone(),
    }
}

fn max_concurrent_issuances(settings: &config::Settings) -> anyhow::Result<usize> {
    usize::try_from(settings.scheduler.max_concurrent_issuances).map_err(|_| {
        anyhow::anyhow!("scheduler.max_concurrent_issuances is too large for this platform")
    })
}

async fn should_renew(
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

fn parse_cert_not_after(cert_bytes: &[u8]) -> anyhow::Result<time::OffsetDateTime> {
    let pem = x509_parser::pem::parse_x509_pem(cert_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM certificate: {e}"))?
        .1;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse X509 certificate: {e}"))?;
    Ok(cert.validity().not_after.to_datetime())
}

fn parse_duration_setting(value: &str, label: &str) -> anyhow::Result<Duration> {
    humantime::parse_duration(value)
        .map_err(|e| anyhow::anyhow!("Invalid {label} value '{value}': {e}"))
}

fn jittered_delay(base: Duration, jitter: Duration) -> Duration {
    let now_ns = time::OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .max(0);
    jittered_delay_with_seed(base, jitter, now_ns)
}

fn jittered_delay_with_seed(base: Duration, jitter: Duration, now_ns: i128) -> Duration {
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
    use std::fs;
    use std::sync::Mutex;

    use rcgen::CertificateParams;
    use tempfile::tempdir;
    use time::OffsetDateTime;

    use super::*;

    const TEST_DOMAIN: &str = "example.com";
    const TEST_KEY_PATH: &str = "unused.key";
    const TEST_TRUST_DOMAIN: &str = "trusted.domain";
    const THIRTY_DAYS_SECS: u64 = 30 * 24 * 60 * 60;
    const VALID_DURATION_LABEL: &str = "daemon.check_interval";
    const TEST_DELAYS: [u64; 3] = [1, 2, 3];
    const TEST_JITTER_SECS: u64 = 10;
    const TEST_BASE_SECS: u64 = 60;
    const TEST_SEED_NS: i128 = 123_456_789;

    fn build_profile(cert_path: PathBuf) -> config::ProfileSettings {
        config::ProfileSettings {
            name: "edge-proxy-a".to_string(),
            daemon_name: "edge-proxy".to_string(),
            instance_id: "001".to_string(),
            hostname: "edge-node-01".to_string(),
            uri_san_enabled: true,
            domains: vec![TEST_DOMAIN.to_string()],
            paths: config::Paths {
                cert: cert_path,
                key: PathBuf::from(TEST_KEY_PATH),
            },
            daemon: config::DaemonSettings {
                check_interval: "1h".to_string(),
                renew_before: "720h".to_string(),
                check_jitter: "0s".to_string(),
            },
            retry: None,
            hooks: config::HookSettings::default(),
            eab: None,
        }
    }

    fn build_settings(profiles: Vec<config::ProfileSettings>) -> config::Settings {
        config::Settings {
            email: "test@example.com".to_string(),
            server: "https://example.com/acme/directory".to_string(),
            spiffe_trust_domain: TEST_TRUST_DOMAIN.to_string(),
            eab: None,
            acme: config::AcmeSettings {
                http_challenge_port: 80,
                directory_fetch_attempts: 10,
                directory_fetch_base_delay_secs: 1,
                directory_fetch_max_delay_secs: 10,
                poll_attempts: 15,
                poll_interval_secs: 2,
            },
            retry: config::RetrySettings {
                backoff_secs: vec![1, 2, 3],
            },
            scheduler: config::SchedulerSettings {
                max_concurrent_issuances: 3,
            },
            profiles,
        }
    }

    fn write_cert(cert_path: &PathBuf, not_after: OffsetDateTime) {
        let mut params = CertificateParams::new(vec![TEST_DOMAIN.to_string()]).unwrap();
        let now = OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = not_after;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        fs::write(cert_path, cert.pem()).unwrap();
    }

    #[test]
    fn test_parse_duration_setting_valid() {
        let duration = parse_duration_setting("15m", VALID_DURATION_LABEL).unwrap();
        assert_eq!(duration, Duration::from_secs(15 * 60));
    }

    #[test]
    fn test_parse_duration_setting_invalid() {
        let err = parse_duration_setting("nope", VALID_DURATION_LABEL).unwrap_err();
        assert!(
            err.to_string()
                .contains("Invalid daemon.check_interval value")
        );
    }

    #[test]
    fn test_build_spiffe_uri_formats_path() {
        let profile = build_profile(PathBuf::from("unused.pem"));
        let settings = build_settings(vec![profile.clone()]);

        let uri = build_spiffe_uri(&settings, &profile);

        assert_eq!(uri, "spiffe://trusted.domain/edge-node-01/edge-proxy/001");
    }

    #[test]
    fn test_resolve_profile_eab_prefers_profile() {
        let profile_eab = config::Eab {
            kid: "profile".to_string(),
            hmac: "profile-hmac".to_string(),
        };
        let profile = config::ProfileSettings {
            eab: Some(profile_eab),
            ..build_profile(PathBuf::from("unused.pem"))
        };

        let default_eab = Some(eab::EabCredentials {
            kid: "default".to_string(),
            hmac: "default-hmac".to_string(),
        });

        let resolved = resolve_profile_eab(&profile, default_eab).unwrap();

        assert_eq!(resolved.kid, "profile");
    }

    #[test]
    fn test_max_concurrent_issuances_rejects_large_value() {
        let settings = config::Settings {
            scheduler: config::SchedulerSettings {
                max_concurrent_issuances: u64::MAX,
            },
            ..build_settings(vec![build_profile(PathBuf::from("unused.pem"))])
        };

        let result = max_concurrent_issuances(&settings);

        let max_usize_u64 = u64::try_from(usize::MAX).unwrap_or(u64::MAX);
        if max_usize_u64 == u64::MAX {
            assert!(result.is_ok());
        } else {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("max_concurrent_issuances")
            );
        }
    }

    #[test]
    fn test_jittered_delay_zero_jitter_returns_base() {
        let base = Duration::from_secs(TEST_BASE_SECS);
        let jitter = Duration::from_secs(0);

        let delay = jittered_delay_with_seed(base, jitter, TEST_SEED_NS);

        assert_eq!(delay, base);
    }

    #[test]
    fn test_jittered_delay_bounds() {
        let base = Duration::from_secs(TEST_BASE_SECS);
        let jitter = Duration::from_secs(TEST_JITTER_SECS);
        let delay = jittered_delay_with_seed(base, jitter, TEST_SEED_NS);

        let min = base.saturating_sub(jitter);
        let max = base + jitter;

        assert!(delay >= min);
        assert!(delay <= max);
    }

    #[test]
    fn test_jittered_delay_minimum_floor() {
        let base = Duration::from_secs(2);
        let jitter = Duration::from_secs(10);
        let delay = jittered_delay_with_seed(base, jitter, 0);

        let min = Duration::from_nanos(u64::try_from(MIN_DAEMON_CHECK_DELAY_NANOS).unwrap());
        let max = base + jitter;

        assert!(delay >= min);
        assert!(delay <= max);
    }

    #[tokio::test]
    async fn test_should_renew_when_missing_cert() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("missing.pem");
        let profile = build_profile(cert_path);

        let renew = should_renew(&profile, Duration::from_secs(60))
            .await
            .unwrap();

        assert!(renew);
    }

    #[tokio::test]
    async fn test_should_renew_when_far_from_expiry() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("valid.pem");
        let profile = build_profile(cert_path.clone());

        let not_after = OffsetDateTime::now_utc() + time::Duration::days(90);
        write_cert(&cert_path, not_after);

        let renew = should_renew(&profile, Duration::from_secs(THIRTY_DAYS_SECS))
            .await
            .unwrap();

        assert!(!renew);
    }

    #[tokio::test]
    async fn test_should_renew_when_near_expiry() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("expiring.pem");
        let profile = build_profile(cert_path.clone());

        let not_after = OffsetDateTime::now_utc() + time::Duration::days(1);
        write_cert(&cert_path, not_after);

        let renew = should_renew(&profile, Duration::from_secs(THIRTY_DAYS_SECS))
            .await
            .unwrap();

        assert!(renew);
    }

    #[tokio::test]
    async fn test_should_renew_invalid_pem_errors() {
        let dir = tempdir().unwrap();
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
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("parse.pem");
        let not_after = OffsetDateTime::now_utc() + time::Duration::days(10);
        write_cert(&cert_path, not_after);
        let cert_bytes = fs::read(cert_path).unwrap();

        let parsed = parse_cert_not_after(&cert_bytes).unwrap();

        assert_eq!(parsed.unix_timestamp(), not_after.unix_timestamp());
    }

    #[tokio::test]
    async fn test_should_renew_rejects_large_duration() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("valid.pem");
        let profile = build_profile(cert_path.clone());

        let not_after = OffsetDateTime::now_utc() + time::Duration::days(90);
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
}
