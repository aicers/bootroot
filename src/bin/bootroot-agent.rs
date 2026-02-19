use std::sync::Arc;

use bootroot::{Args, config, daemon, eab, profile};
use clap::Parser;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    info!("Starting Bootroot Agent (Rust)");

    if args.oneshot {
        let (settings, final_eab) = load_settings(&args).await?;
        match daemon::run_oneshot(
            Arc::new(settings),
            final_eab,
            args.config.clone(),
            args.insecure,
        )
        .await
        {
            Ok(()) => info!("Successfully issued certificate!"),
            Err(err) => {
                error!("Failed to issue certificate: {err:?}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    let mut pending = None;
    #[cfg(unix)]
    let mut hup = signal(SignalKind::hangup())?;
    loop {
        let (settings, final_eab) = match pending.take() {
            Some(value) => value,
            None => load_settings(&args).await?,
        };
        log_settings(&settings, final_eab.as_ref());
        let settings = Arc::new(settings);
        let mut task = tokio::spawn(daemon::run_daemon(
            Arc::clone(&settings),
            final_eab,
            args.config.clone(),
            args.insecure,
        ));
        #[cfg(unix)]
        loop {
            tokio::select! {
                result = &mut task => return handle_daemon_result(result),
                _ = hup.recv() => {
                    match load_settings(&args).await {
                        Ok((settings, final_eab)) => {
                            info!("Reload signal received. Restarting daemon with new config.");
                            pending = Some((settings, final_eab));
                            task.abort();
                            let _ = task.await;
                            break;
                        }
                        Err(err) => {
                            error!("Reload failed: {err}");
                        }
                    }
                }
            }
        }
        #[cfg(not(unix))]
        {
            return handle_daemon_result(task.await);
        }
    }
}

async fn load_settings(
    args: &Args,
) -> anyhow::Result<(config::Settings, Option<eab::EabCredentials>)> {
    let mut settings = config::Settings::new(args.config.clone())?;
    settings.merge_with_args(args);
    settings.validate()?;

    let cli_eab = eab::load_credentials(
        args.eab_kid.clone(),
        args.eab_hmac.clone(),
        args.eab_file.clone(),
    )
    .await?;
    let final_eab = cli_eab.or_else(|| settings.eab.as_ref().map(profile::to_eab_credentials));
    Ok((settings, final_eab))
}

fn log_settings(settings: &config::Settings, final_eab: Option<&eab::EabCredentials>) {
    info!("Loaded {} profile(s).", settings.profiles.len());
    info!("CA URL: {}", settings.server);

    if let Some(creds) = final_eab {
        info!("Using EAB Credentials for Key ID: {}", creds.kid);
    } else {
        info!("No EAB credentials provided. Attempting open enrollment.");
    }
}

fn handle_daemon_result(
    result: Result<anyhow::Result<()>, tokio::task::JoinError>,
) -> anyhow::Result<()> {
    match result {
        Ok(inner) => inner,
        Err(err) => {
            if err.is_cancelled() {
                Ok(())
            } else {
                Err(err.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bootroot::{config, daemon, eab, profile};
    use rcgen::CertificateParams;
    use tempfile::tempdir;
    use time::OffsetDateTime;

    const TEST_DOMAIN: &str = "example.com";
    const TEST_KEY_PATH: &str = "unused.key";
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
            paths: config::Paths {
                cert: cert_path,
                key: PathBuf::from(TEST_KEY_PATH),
            },
            daemon: config::DaemonRuntimeSettings {
                check_interval: Duration::from_secs(60 * 60),
                renew_before: Duration::from_secs(720 * 60 * 60),
                check_jitter: Duration::from_secs(0),
            },
            retry: None,
            hooks: config::HookSettings::default(),
            eab: None,
        }
    }

    fn build_settings(profiles: Vec<config::DaemonProfileSettings>) -> config::Settings {
        config::Settings {
            email: "test@example.com".to_string(),
            server: "https://example.com/acme/directory".to_string(),
            domain: TEST_DOMAIN.to_string(),
            eab: None,
            acme: config::AcmeSettings {
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
            retry: config::RetrySettings {
                backoff_secs: vec![1, 2, 3],
            },
            trust: config::TrustSettings::default(),
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
    fn test_resolve_profile_eab_prefers_profile() {
        let profile_eab = config::Eab {
            kid: "profile".to_string(),
            hmac: "profile-hmac".to_string(),
        };
        let profile = config::DaemonProfileSettings {
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
