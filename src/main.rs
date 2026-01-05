use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use tokio::sync::Mutex;
use tracing::{error, info};

pub mod acme;
pub mod config;
pub mod eab;

const DAEMON_CHECK_INTERVAL_KEY: &str = "daemon.check_interval";
const DAEMON_RENEW_BEFORE_KEY: &str = "daemon.renew_before";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to configuration file (default: agent.toml)
    #[arg(long, short)]
    config: Option<PathBuf>,

    /// Support email address
    #[arg(long)]
    email: Option<String>,

    /// Domain to request certificate for
    #[arg(long)]
    domain: Option<String>,

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

    /// Path to save the certificate
    #[arg(long)]
    cert_path: Option<PathBuf>,

    /// Path to save the private key
    #[arg(long)]
    key_path: Option<PathBuf>,

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

    let final_eab = cli_eab.or_else(|| {
        settings
            .eab
            .as_ref()
            .map(|cfg_eab| crate::eab::EabCredentials {
                kid: cfg_eab.kid.clone(),
                hmac: cfg_eab.hmac.clone(),
            })
    });

    info!("Target Domains: {:?}", settings.domains);
    info!("CA URL: {}", settings.server);

    if let Some(ref creds) = final_eab {
        info!("Using EAB Credentials for Key ID: {}", creds.kid);
    } else {
        info!("No EAB credentials provided. Attempting open enrollment.");
    }

    let challenges = Arc::new(Mutex::new(HashMap::new()));
    let _challenge_server =
        acme::start_http01_server(challenges.clone(), settings.acme.http_challenge_port);

    // 4. Run ACME Flow
    if args.oneshot {
        match acme::issue_certificate(&settings, final_eab, challenges).await {
            Ok(()) => info!("Successfully issued certificate!"),
            Err(e) => {
                error!("Failed to issue certificate: {:?}", e);
                std::process::exit(1);
            }
        }
    } else {
        run_daemon(&settings, final_eab, challenges).await?;
    }

    Ok(())
}

async fn run_daemon(
    settings: &config::Settings,
    eab: Option<eab::EabCredentials>,
    challenges: Arc<Mutex<HashMap<String, String>>>,
) -> anyhow::Result<()> {
    let check_interval =
        parse_duration_setting(&settings.daemon.check_interval, DAEMON_CHECK_INTERVAL_KEY)?;
    let renew_before =
        parse_duration_setting(&settings.daemon.renew_before, DAEMON_RENEW_BEFORE_KEY)?;

    info!(
        "Daemon mode enabled. check_interval={:?}, renew_before={:?}",
        check_interval, renew_before
    );

    let mut ticker = tokio::time::interval(check_interval);
    let mut shutdown = Box::pin(wait_for_shutdown());

    loop {
        tokio::select! {
            result = &mut shutdown => {
                if let Err(err) = result {
                    error!("Shutdown signal handler error: {err}");
                }
                info!("Shutdown signal received. Exiting daemon loop.");
                break;
            }
            _ = ticker.tick() => {
                tracing::debug!("Checking certificate renewal status...");
                match should_renew(settings, renew_before).await {
                    Ok(true) => {
                        info!("Renewal required. Starting ACME issuance...");
                        if !issue_with_retry(settings, eab.clone(), challenges.clone()).await {
                            error!("Renewal failed after retries. Will try again on next interval.");
                        }
                    }
                    Ok(false) => {
                        tracing::debug!("Certificate is still valid. No renewal needed.");
                    }
                    Err(err) => {
                        error!("Failed to evaluate renewal status: {err}");
                    }
                }
            }
        }
    }

    Ok(())
}

async fn issue_with_retry(
    settings: &config::Settings,
    eab: Option<eab::EabCredentials>,
    challenges: Arc<Mutex<HashMap<String, String>>>,
) -> bool {
    issue_with_retry_inner(
        || acme::issue_certificate(settings, eab.clone(), challenges.clone()),
        |duration| tokio::time::sleep(duration),
        &settings.retry.backoff_secs,
    )
    .await
}

async fn issue_with_retry_inner<IssueFn, IssueFut, SleepFn, SleepFut>(
    mut issue_fn: IssueFn,
    mut sleep_fn: SleepFn,
    delays: &[u64],
) -> bool
where
    IssueFn: FnMut() -> IssueFut,
    IssueFut: Future<Output = anyhow::Result<()>>,
    SleepFn: FnMut(Duration) -> SleepFut,
    SleepFut: Future<Output = ()>,
{
    for (attempt, delay) in delays.iter().enumerate() {
        match issue_fn().await {
            Ok(()) => {
                info!("Certificate issuance succeeded.");
                return true;
            }
            Err(err) => {
                error!(
                    "Certificate issuance failed (attempt {}): {err}",
                    attempt + 1
                );
                if attempt + 1 < delays.len() {
                    sleep_fn(Duration::from_secs(*delay)).await;
                }
            }
        }
    }

    false
}

async fn should_renew(settings: &config::Settings, renew_before: Duration) -> anyhow::Result<bool> {
    let cert_bytes = match tokio::fs::read(&settings.paths.cert).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            info!("Certificate file not found. Issuing a new certificate.");
            return Ok(true);
        }
        Err(err) => {
            return Err(anyhow::anyhow!(
                "Failed to read certificate file {}: {err}",
                settings.paths.cert.display()
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
    const TEST_SERVER_URL: &str = "https://example.com/acme/directory";
    const TEST_KEY_PATH: &str = "unused.key";
    const THIRTY_DAYS_SECS: u64 = 30 * 24 * 60 * 60;
    const VALID_DURATION_LABEL: &str = "daemon.check_interval";
    const TEST_DELAYS: [u64; 3] = [1, 2, 3];

    fn build_settings(cert_path: PathBuf) -> config::Settings {
        config::Settings {
            email: "test@example.com".to_string(),
            domains: vec![TEST_DOMAIN.to_string()],
            server: TEST_SERVER_URL.to_string(),
            paths: config::Paths {
                cert: cert_path,
                key: PathBuf::from(TEST_KEY_PATH),
            },
            eab: None,
            daemon: config::DaemonSettings {
                check_interval: "1h".to_string(),
                renew_before: "720h".to_string(),
            },
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

    #[tokio::test]
    async fn test_should_renew_when_missing_cert() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("missing.pem");
        let settings = build_settings(cert_path);

        let renew = should_renew(&settings, Duration::from_secs(60))
            .await
            .unwrap();

        assert!(renew);
    }

    #[tokio::test]
    async fn test_should_renew_when_far_from_expiry() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("valid.pem");
        let settings = build_settings(cert_path.clone());

        let not_after = OffsetDateTime::now_utc() + time::Duration::days(90);
        write_cert(&cert_path, not_after);

        let renew = should_renew(&settings, Duration::from_secs(THIRTY_DAYS_SECS))
            .await
            .unwrap();

        assert!(!renew);
    }

    #[tokio::test]
    async fn test_should_renew_when_near_expiry() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("expiring.pem");
        let settings = build_settings(cert_path.clone());

        let not_after = OffsetDateTime::now_utc() + time::Duration::days(1);
        write_cert(&cert_path, not_after);

        let renew = should_renew(&settings, Duration::from_secs(THIRTY_DAYS_SECS))
            .await
            .unwrap();

        assert!(renew);
    }

    #[tokio::test]
    async fn test_should_renew_invalid_pem_errors() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("invalid.pem");
        fs::write(&cert_path, "not a cert").unwrap();
        let settings = build_settings(cert_path);

        let err = should_renew(&settings, Duration::from_secs(THIRTY_DAYS_SECS))
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
        let settings = build_settings(cert_path.clone());

        let not_after = OffsetDateTime::now_utc() + time::Duration::days(90);
        write_cert(&cert_path, not_after);

        let err = should_renew(&settings, Duration::MAX).await.unwrap_err();

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

        assert!(ok);
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

        assert!(!ok);
        assert_eq!(*attempts.lock().unwrap(), 3);
        assert_eq!(
            *sleeps.lock().unwrap(),
            vec![Duration::from_secs(1), Duration::from_secs(2)]
        );
    }
}
