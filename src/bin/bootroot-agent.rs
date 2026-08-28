use std::sync::Arc;

use bootroot::config::CliOverrides;
use bootroot::{
    Args, DaemonInvocation, DaemonShutdown, RegistrarEndpoint, config, eab,
    ensure_registrar_surface_certificates, profile, run_daemon, run_oneshot,
};
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
        match run_oneshot(
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

    let cli_overrides = CliOverrides::from(&args);
    // EAB source precedence is CLI `--eab-kid`/`--eab-hmac` (explicit) →
    // `--eab-file` (`eab.json`) → agent.toml `[eab]`. Fast-poll EAB refresh is
    // meaningful only for the `--eab-file` remote-bootstrap artifact: when both
    // CLI values are set the operator has pinned EAB out of band, so refresh
    // must be a no-op and never override them. `args` is fixed for the process
    // lifetime, so this holds across HUP reloads too.
    let eab_cli_pinned = args.eab_kid.is_some() && args.eab_hmac.is_some();
    let eab_refresh_path = if eab_cli_pinned {
        None
    } else {
        args.eab_file.clone()
    };
    #[cfg(unix)]
    let mut hup = signal(SignalKind::hangup())?;

    // The activation contract is consumed here, once, above the reload
    // loop and before any daemon task exists. `LISTEN_PID` and
    // `LISTEN_FDS` are read exactly once and never again; the process
    // environment is not mutated, not even to clear them, because a
    // Tokio runtime is already running and `set_var`/`remove_var` are
    // unsound the moment another thread may read. The endpoint's
    // enablement is therefore fixed for the process lifetime, and every
    // later reload is held to the value captured here.
    let (initial_settings, initial_eab) = load_settings(&args).await?;
    let registrar_endpoint_settings = initial_settings.registrar_endpoint.clone();
    let registrar_audit_settings = initial_settings.registrar.clone();
    // Above activation on purpose: the endpoint's TLS loader reads the
    // server pair the moment `activate` runs, so the material it finds
    // has to be material this call has already ensured. On a host where
    // the endpoint is disabled this does nothing at all — no path
    // created, nothing asked of the CA or of OpenBao.
    ensure_registrar_surface_certificates(&initial_settings, args.insecure).await?;
    let registrar_endpoint = RegistrarEndpoint::activate(&initial_settings)?;
    let mut pending = Some((initial_settings, initial_eab));

    loop {
        let (settings, final_eab) = match pending.take() {
            Some(value) => value,
            None => load_settings(&args).await?,
        };
        log_settings(&settings, final_eab.as_ref());
        let settings = Arc::new(settings);
        let shutdown = DaemonShutdown::new();
        let mut task = tokio::spawn(run_daemon(DaemonInvocation {
            settings: Arc::clone(&settings),
            default_eab: final_eab,
            eab_refresh_path: eab_refresh_path.clone(),
            config_path: args.config.clone(),
            insecure_mode: args.insecure,
            cli_overrides: cli_overrides.clone(),
            shutdown: shutdown.clone(),
            registrar_endpoint: registrar_endpoint.clone(),
        }));
        #[cfg(unix)]
        loop {
            tokio::select! {
                result = &mut task => return handle_daemon_result(result),
                _ = hup.recv() => {
                    match load_settings(&args).await {
                        Ok((settings, final_eab)) => {
                            if let Err(err) = config::check_registrar_endpoint_reload(
                                &registrar_endpoint_settings,
                                &settings.registrar_endpoint,
                            ) {
                                error!("Reload rejected: {err}");
                                continue;
                            }
                            if registrar_endpoint_settings.enabled
                                && let Err(err) = config::check_registrar_audit_store_reload(
                                    &registrar_audit_settings,
                                    &settings.registrar,
                                )
                            {
                                error!("Reload rejected: {err}");
                                continue;
                            }
                            info!("Reload signal received. Restarting daemon with new config.");
                            pending = Some((settings, final_eab));
                            // A coordinated stop, never an abort: the
                            // daemon may own the registrar endpoint,
                            // whose accept task and connection fleet
                            // have to stop accepting, drain and be
                            // joined before this invocation is joined.
                            shutdown.stop();
                            report_stopped_invocation((&mut task).await);
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

/// Reports how the invocation a reload stopped actually ended.
///
/// The reload now *joins* that invocation instead of aborting it, so its
/// result is a real one: a profile that failed on the way out, or a task
/// that panicked, says so here instead of vanishing into the restart.
fn report_stopped_invocation(result: Result<anyhow::Result<()>, tokio::task::JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => error!("The daemon invocation being reloaded ended with an error: {err}"),
        Err(err) => error!("The daemon invocation being reloaded failed to join: {err}"),
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
    use std::path::PathBuf;
    use std::time::Duration;

    use bootroot::{config, eab, profile};

    const TEST_KEY_PATH: &str = "unused.key";

    fn build_profile(cert_path: PathBuf) -> config::DaemonProfileSettings {
        config::DaemonProfileSettings {
            registration_id: "edge-proxy".to_string(),
            service_name: "edge-proxy".to_string(),
            instance_id: "001".to_string(),
            hostname: "edge-node-01".to_string(),
            paths: config::Paths {
                cert: cert_path,
                key: PathBuf::from(TEST_KEY_PATH),
            },
            daemon: config::DaemonRuntimeSettings {
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

    fn build_settings(profiles: Vec<config::DaemonProfileSettings>) -> config::Settings {
        config::Settings {
            email: "test@example.com".to_string(),
            server: "https://example.com/acme/directory".to_string(),
            domain: "example.com".to_string(),
            eab: None,
            acme: config::AcmeSettings {
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
            retry: config::RetrySettings {
                backoff_secs: vec![1, 2, 3],
            },
            trust: config::TrustSettings::default(),
            scheduler: config::SchedulerSettings {
                max_concurrent_issuances: 3,
            },
            profiles,
            openbao: None,
            registrar_endpoint: config::RegistrarEndpointSettings::default(),
            registrar: config::RegistrarSettings::default(),
        }
    }

    #[test]
    fn test_resolve_profile_eab_prefers_profile() {
        let profile_eab = config::Eab {
            kid: "profile".to_string(),
            hmac: "profile-hmac".into(),
        };
        let profile = config::DaemonProfileSettings {
            eab: Some(profile_eab),
            ..build_profile(PathBuf::from("unused.pem"))
        };

        let default_eab = Some(eab::EabCredentials {
            kid: "default".to_string(),
            hmac: "default-hmac".into(),
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
}
