use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::Mutex;
use tracing::{error, info};

pub mod acme;
pub mod config;
pub mod daemon;
pub mod eab;
pub mod hooks;
pub mod profile;

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

    let final_eab = cli_eab.or_else(|| settings.eab.as_ref().map(profile::to_eab_credentials));

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
        match daemon::run_oneshot(Arc::clone(&settings), final_eab, challenges).await {
            Ok(()) => info!("Successfully issued certificate!"),
            Err(e) => {
                error!("Failed to issue certificate: {:?}", e);
                std::process::exit(1);
            }
        }
    } else {
        daemon::run_daemon(settings, final_eab, challenges).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use rcgen::CertificateParams;
    use tempfile::tempdir;
    use time::OffsetDateTime;

    use super::{config, daemon, eab, profile};

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
        let duration = daemon::parse_duration_setting("15m", VALID_DURATION_LABEL).unwrap();
        assert_eq!(duration, Duration::from_secs(15 * 60));
    }

    #[test]
    fn test_parse_duration_setting_invalid() {
        let err = daemon::parse_duration_setting("nope", VALID_DURATION_LABEL).unwrap_err();
        assert!(
            err.to_string()
                .contains("Invalid daemon.check_interval value")
        );
    }

    #[test]
    fn test_build_spiffe_uri_formats_path() {
        let profile = build_profile(PathBuf::from("unused.pem"));
        let settings = build_settings(vec![profile.clone()]);

        let uri = profile::build_spiffe_uri(&settings, &profile);

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

        let resolved = profile::resolve_profile_eab(&profile, default_eab).unwrap();

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

        let result = profile::max_concurrent_issuances(&settings);

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

        let delay = daemon::jittered_delay_with_seed(base, jitter, TEST_SEED_NS);

        assert_eq!(delay, base);
    }

    #[test]
    fn test_jittered_delay_bounds() {
        let base = Duration::from_secs(TEST_BASE_SECS);
        let jitter = Duration::from_secs(TEST_JITTER_SECS);
        let delay = daemon::jittered_delay_with_seed(base, jitter, TEST_SEED_NS);

        let min = base.saturating_sub(jitter);
        let max = base + jitter;

        assert!(delay >= min);
        assert!(delay <= max);
    }

    #[test]
    fn test_jittered_delay_minimum_floor() {
        let base = Duration::from_secs(2);
        let jitter = Duration::from_secs(10);
        let delay = daemon::jittered_delay_with_seed(base, jitter, 0);

        let min =
            Duration::from_nanos(u64::try_from(daemon::MIN_DAEMON_CHECK_DELAY_NANOS).unwrap());
        let max = base + jitter;

        assert!(delay >= min);
        assert!(delay <= max);
    }

    #[tokio::test]
    async fn test_should_renew_when_missing_cert() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("missing.pem");
        let profile = build_profile(cert_path);

        let renew = daemon::should_renew(&profile, Duration::from_secs(60))
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

        let renew = daemon::should_renew(&profile, Duration::from_secs(THIRTY_DAYS_SECS))
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

        let renew = daemon::should_renew(&profile, Duration::from_secs(THIRTY_DAYS_SECS))
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

        let err = daemon::should_renew(&profile, Duration::from_secs(THIRTY_DAYS_SECS))
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

        let parsed = daemon::parse_cert_not_after(&cert_bytes).unwrap();

        assert_eq!(parsed.unix_timestamp(), not_after.unix_timestamp());
    }

    #[tokio::test]
    async fn test_should_renew_rejects_large_duration() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("valid.pem");
        let profile = build_profile(cert_path.clone());

        let not_after = OffsetDateTime::now_utc() + time::Duration::days(90);
        write_cert(&cert_path, not_after);

        let err = daemon::should_renew(&profile, Duration::MAX)
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

        let ok = daemon::issue_with_retry_inner(issue_fn, sleep_fn, &TEST_DELAYS).await;

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

        let ok = daemon::issue_with_retry_inner(issue_fn, sleep_fn, &TEST_DELAYS).await;

        assert!(ok.is_err());
        assert_eq!(*attempts.lock().unwrap(), 3);
        assert_eq!(
            *sleeps.lock().unwrap(),
            vec![Duration::from_secs(1), Duration::from_secs(2)]
        );
    }
}
