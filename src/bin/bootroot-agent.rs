use std::process::ExitCode;
use std::sync::Arc;

use bootroot::config::CliOverrides;
use bootroot::fs_util::SecretsTree;
use bootroot::logging::{self, LogDestination};
use bootroot::registrar::internal::{internal_config_anchor, load_daemon_config_in};
use bootroot::{
    Args, DaemonInvocation, DaemonShutdown, RegistrarEndpoint,
    audit_store_reload_rejection_message, config, eab, ensure_registrar_surface_certificates,
    profile, refresh_registrar_surface_after_reload, run_daemon, run_oneshot,
};
use clap::Parser;
use clap::error::ErrorKind;
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tracing::{error, info};

/// clap's exit status for a refused command line.
const USAGE_ERROR_EXIT: u8 = 2;

#[tokio::main]
async fn main() -> ExitCode {
    bootroot::tls::install_crypto_provider();
    // Before anything that can fail, so that under the journal every
    // start-up error is an entry at its own priority rather than plain
    // text the journal would store at priority 6.
    let destination = logging::init(std::env::var_os(logging::JOURNAL_STREAM_VAR).as_deref());

    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(err) => return refuse_args(&err, destination),
    };
    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            match destination {
                LogDestination::Journal => error!("{err:#}"),
                // What the standard library prints for an error `main`
                // returns.
                LogDestination::Other => eprintln!("Error: {err:?}"),
            }
            ExitCode::FAILURE
        }
    }
}

/// Reports a command line clap refused, or the help or version it was
/// asked for, and returns the status to exit with.
fn refuse_args(err: &clap::Error, destination: LogDestination) -> ExitCode {
    match destination {
        LogDestination::Journal => match err.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                // Output the operator asked for, printed as clap prints
                // it; clap's own `exit` ignores a failure to print too.
                let _ = err.print();
                ExitCode::SUCCESS
            }
            _ => {
                error!("{}", err.render().to_string().trim_end());
                ExitCode::from(USAGE_ERROR_EXIT)
            }
        },
        LogDestination::Other => err.exit(),
    }
}

async fn run(args: Args) -> anyhow::Result<()> {
    info!("Starting Bootroot Agent (Rust)");

    if args.oneshot {
        // The handle served the reads `load_settings` made; the one-shot
        // pass issues the service profiles alone, whose files are
        // operator-named.
        let (settings, final_eab, _secrets_tree) = load_settings(&args).await?;
        match run_oneshot(Arc::new(settings), final_eab).await {
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
    let (initial_settings, initial_eab, initial_tree) = load_settings(&args).await?;
    let registrar_endpoint_settings = initial_settings.registrar_endpoint.clone();
    let registrar_audit_settings = initial_settings.registrar.clone();
    // Above activation on purpose: the endpoint's TLS loader reads the
    // server pair the moment `activate` runs, so the material it finds
    // has to be material this call has already ensured. On a host where
    // the endpoint is disabled this does nothing at all — no path
    // created, nothing asked of the CA or of OpenBao.
    ensure_registrar_surface_certificates(&initial_settings, initial_tree.as_ref()).await?;
    let registrar_endpoint = RegistrarEndpoint::activate(&initial_settings)?;
    let mut pending = Some((initial_settings, initial_eab, initial_tree));
    // The first invocation's issuance ran above, before activation. Every
    // later one was begun by a reload and runs it here instead, then
    // swaps the endpoint onto whatever is now on disk: a CA rotation
    // removes the surface material and reloads this process to have it
    // re-issued under the new generation, and narrows the `[trust]` pins
    // the client verifier is built from.
    let mut reloaded = false;

    loop {
        let (settings, final_eab, secrets_tree) = match pending.take() {
            Some(value) => value,
            None => load_settings(&args).await?,
        };
        if reloaded {
            refresh_registrar_surface_after_reload(
                &settings,
                &registrar_endpoint,
                secrets_tree.as_ref(),
            )
            .await;
        }
        reloaded = true;
        log_settings(&settings, final_eab.as_ref());
        let settings = Arc::new(settings);
        let shutdown = DaemonShutdown::new();
        let mut task = tokio::spawn(run_daemon(DaemonInvocation {
            settings: Arc::clone(&settings),
            default_eab: final_eab,
            eab_refresh_path: eab_refresh_path.clone(),
            config_path: args.config.clone(),
            cli_overrides: cli_overrides.clone(),
            shutdown: shutdown.clone(),
            registrar_endpoint: registrar_endpoint.clone(),
            secrets_tree,
        }));
        #[cfg(unix)]
        loop {
            tokio::select! {
                result = &mut task => return handle_daemon_result(result),
                _ = hup.recv() => {
                    match load_settings(&args).await {
                        Ok((settings, final_eab, secrets_tree)) => {
                            if let Err(err) = config::check_registrar_endpoint_reload(
                                &registrar_endpoint_settings,
                                &settings.registrar_endpoint,
                            ) {
                                error!("Reload rejected: {err}");
                                continue;
                            }
                            // Localized, and narrower than the endpoint
                            // guard above: only a reload that would detach
                            // the filesystem mount verdict this process took
                            // at start is refused. A `directory` daemon
                            // reloading another `directory` configuration
                            // reaches none of this.
                            if registrar_endpoint_settings.enabled
                                && let Err(rejection) =
                                    config::check_registrar_audit_store_reload(
                                        &registrar_audit_settings,
                                        &settings.registrar,
                                    )
                            {
                                error!("{}", audit_store_reload_rejection_message(&rejection));
                                continue;
                            }
                            info!("Reload signal received. Restarting daemon with new config.");
                            pending = Some((settings, final_eab, secrets_tree));
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

/// The settings one load produced, the EAB in force, and the handle on
/// the secrets directory the load opened, if any.
type LoadedSettings = (
    config::Settings,
    Option<eab::EabCredentials>,
    Option<Arc<SecretsTree>>,
);

/// Loads `--config`, and `--eab-file` beside it, for one invocation.
///
/// Run at start, for every invocation a reload begins and on every
/// `SIGHUP`, and opens at most one handle on a secrets directory each
/// time, decided from paths alone:
///
/// - When `--config` is spelled `<anchor>/registrar-internal/agent.toml`
///   — the registrar endpoint daemon — the handle is opened on that
///   anchor before the file is read. When it is rooted (this process is
///   root and another account owns the directory) the config is read
///   through it, parsed with the same `BOOTROOT_*` overlay, and must
///   describe the internal profile at the fixed layout below that anchor
///   with no `[openbao]` table; otherwise the load fails naming
///   `--config`.
/// - Otherwise, once the config is parsed, when its `[openbao]
///   secret_id_path` is a local-file service's default
///   `<anchor>/services/<id>/secret_id`, the handle is opened on that
///   anchor before `--eab-file` is read.
///
/// An `--eab-file` below a rooted handle's anchor is read through it.
/// Every other case reads exactly as it always has.
async fn load_settings(args: &Args) -> anyhow::Result<LoadedSettings> {
    load_settings_with(args, HandleOpening::AsTheProcessRuns).await
}

/// How [`load_settings_with`] opens a handle on a secrets directory.
#[derive(Clone, Copy)]
enum HandleOpening {
    /// [`SecretsTree::open_shared`]: rooted exactly when this process is
    /// root and another account owns the directory.
    AsTheProcessRuns,
    /// [`SecretsTree::open_rooted_for_tests`], so an unprivileged test
    /// drives the rooted load.
    #[cfg(test)]
    ForcedRooted,
}

impl HandleOpening {
    async fn open(self, anchor: &std::path::Path) -> anyhow::Result<Arc<SecretsTree>> {
        match self {
            Self::AsTheProcessRuns => SecretsTree::open_shared(anchor).await,
            #[cfg(test)]
            Self::ForcedRooted => SecretsTree::open_rooted_for_tests(anchor).map(Arc::new),
        }
    }
}

/// [`load_settings`] with the way its handle is opened chosen by the
/// caller.
async fn load_settings_with(args: &Args, opening: HandleOpening) -> anyhow::Result<LoadedSettings> {
    let config_anchor = args.config.as_deref().and_then(internal_config_anchor);
    let mut secrets_tree = match config_anchor {
        Some(anchor) => Some(opening.open(anchor).await?),
        None => None,
    };
    let mut settings = match (secrets_tree.as_ref(), args.config.clone()) {
        (Some(tree), Some(config_path)) if tree.is_rooted() => {
            tree.run(move |tree| {
                load_daemon_config_in(tree, &config_path).map_err(anyhow::Error::from)
            })
            .await?
        }
        _ => config::Settings::new(args.config.clone())?,
    };
    settings.merge_with_args(args);
    settings.validate()?;

    if secrets_tree.is_none()
        && let Some(anchor) = settings
            .openbao
            .as_ref()
            .and_then(|openbao| config::service_secrets_anchor(&openbao.secret_id_path))
    {
        secrets_tree = Some(opening.open(anchor).await?);
    }

    let cli_eab = match secrets_tree.as_ref() {
        Some(tree) => {
            eab::load_credentials_in(
                tree,
                args.eab_kid.clone(),
                args.eab_hmac.clone(),
                args.eab_file.clone(),
            )
            .await?
        }
        None => {
            eab::load_credentials(
                args.eab_kid.clone(),
                args.eab_hmac.clone(),
                args.eab_file.clone(),
            )
            .await?
        }
    };
    let final_eab = cli_eab.or_else(|| settings.eab.as_ref().map(profile::to_eab_credentials));
    Ok((settings, final_eab, secrets_tree))
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
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use bootroot::registrar::internal::{
        InternalAgentConfigParams, InternalPaths, render_internal_agent_config,
    };
    use bootroot::{config, eab, profile};

    use super::{HandleOpening, load_settings_with};

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
            cert_owner_uid: None,
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

    /// A `secrets/` and a sibling `outside/` in a `tempdir`.
    struct Tree {
        dir: tempfile::TempDir,
        secrets: PathBuf,
        outside: PathBuf,
    }

    impl Tree {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let secrets = dir.path().join("secrets");
            let outside = dir.path().join("outside");
            std::fs::create_dir_all(secrets.join("registrar-internal")).expect("mkdir");
            std::fs::create_dir_all(&outside).expect("mkdir");
            Self {
                dir,
                secrets,
                outside,
            }
        }

        fn internal_config(&self) -> PathBuf {
            self.secrets.join("registrar-internal").join("agent.toml")
        }

        fn write_internal_config(&self, extra: &str) {
            let rendered = render_internal_agent_config(
                &InternalPaths::new(&self.secrets),
                &InternalAgentConfigParams {
                    email: "ops@example.internal",
                    server: "https://127.0.0.1:1/acme/acme/directory",
                    domain: "example.internal",
                    hostname: "host-a",
                    responder_url: "http://127.0.0.1:1",
                    responder_hmac: &"hmac".into(),
                    eab_kid: None,
                    eab_hmac: None,
                    trusted_ca_sha256: &["a".repeat(64)],
                    endpoint_tables: None,
                },
            );
            std::fs::write(self.internal_config(), format!("{rendered}{extra}"))
                .expect("write the internal config");
        }

        /// A local-file service's agent config at the default layout,
        /// its `[openbao]` naming `services/svc/`.
        fn write_service_config(&self, secret_id: &Path) -> PathBuf {
            let path = self.dir.path().join("agent.toml");
            std::fs::write(
                &path,
                format!(
                    "domain = \"example.internal\"\n\
                     [acme]\nhttp_responder_hmac = \"hmac\"\n\
                     [openbao]\nurl = \"http://127.0.0.1:8200\"\n\
                     role_id_path = \"{role}\"\nsecret_id_path = \"{secret}\"\n\
                     state_path = \"{state}\"\n\n\
                     [[profiles]]\nregistration_id = \"svc\"\nservice_name = \"svc\"\n\
                     instance_id = \"001\"\nhostname = \"node-01\"\n\n\
                     [profiles.paths]\ncert = \"{cert}\"\nkey = \"{key}\"\n",
                    role = self.secrets.join("services/svc/role_id").display(),
                    secret = secret_id.display(),
                    state = self.dir.path().join("state.json").display(),
                    cert = self.dir.path().join("svc.pem").display(),
                    key = self.dir.path().join("svc.key").display(),
                ),
            )
            .expect("write the service config");
            path
        }
    }

    fn args(extra: &[&str]) -> bootroot::Args {
        use clap::Parser as _;

        bootroot::Args::parse_from(std::iter::once("bootroot-agent").chain(extra.iter().copied()))
    }

    fn arg(path: &Path) -> String {
        path.display().to_string()
    }

    /// A `--config` of any other shape opens no handle and loads as it
    /// always has.
    #[tokio::test]
    async fn a_config_of_another_shape_opens_no_handle() {
        let tree = Tree::new();
        let config = tree.write_service_config(&tree.dir.path().join("operator/secret_id"));
        let (settings, _, handle) = load_settings_with(
            &args(&["--config", &arg(&config)]),
            HandleOpening::ForcedRooted,
        )
        .await
        .expect("the config loads");
        assert!(handle.is_none());
        assert_eq!(settings.profiles.len(), 1);
    }

    /// The daemon's own `--config` opens a handle on its anchor; as an
    /// unprivileged process over its own tree it is path-based and the
    /// config loads as before.
    #[tokio::test]
    async fn the_daemon_config_opens_a_handle_on_its_anchor() {
        let tree = Tree::new();
        tree.write_internal_config("");
        let config_arg = arg(&tree.internal_config());
        let (settings, _, handle) = load_settings_with(
            &args(&["--config", &config_arg]),
            HandleOpening::AsTheProcessRuns,
        )
        .await
        .expect("the config loads");
        let handle = handle.expect("a handle");
        assert_eq!(handle.anchor(), tree.secrets.as_path());
        assert!(!handle.is_rooted());
        let (rooted, _, rooted_handle) = load_settings_with(
            &args(&["--config", &config_arg]),
            HandleOpening::ForcedRooted,
        )
        .await
        .expect("the rooted load");
        assert!(rooted_handle.expect("a handle").is_rooted());
        assert_eq!(format!("{rooted:?}"), format!("{settings:?}"));
    }

    /// A rooted load that meets a link at `registrar-internal`, or a
    /// config with an `[openbao]` table, fails — what a start reports
    /// and a `SIGHUP` reload logs as `Reload failed`, keeping the
    /// invocation it has.
    #[tokio::test]
    async fn a_refused_daemon_config_fails_the_load() {
        let tree = Tree::new();
        tree.write_internal_config(&format!(
            "\n[openbao]\nurl = \"http://127.0.0.1:8200\"\nrole_id_path = \"{r}\"\n\
             secret_id_path = \"{s}\"\nstate_path = \"{t}\"\n",
            r = tree.dir.path().join("role_id").display(),
            s = tree.dir.path().join("secret_id").display(),
            t = tree.dir.path().join("state.json").display(),
        ));
        let config_arg = arg(&tree.internal_config());
        let Err(err) = load_settings_with(
            &args(&["--config", &config_arg]),
            HandleOpening::ForcedRooted,
        )
        .await
        else {
            panic!("an [openbao] table is refused");
        };
        assert!(format!("{err:#}").contains("[openbao]"));

        tree.write_internal_config("");
        let internal = tree.secrets.join("registrar-internal");
        std::fs::rename(&internal, tree.dir.path().join("aside")).expect("move aside");
        std::fs::rename(tree.dir.path().join("aside"), tree.outside.join("moved"))
            .expect("move out");
        std::os::unix::fs::symlink(tree.outside.join("moved"), &internal).expect("link");
        let Err(err) = load_settings_with(
            &args(&["--config", &config_arg]),
            HandleOpening::ForcedRooted,
        )
        .await
        else {
            panic!("a linked registrar-internal is refused");
        };
        assert!(format!("{err:#}").contains(&internal.display().to_string()));
    }

    /// A local-file service at the default layout opens a handle on its
    /// secrets directory, and a rooted one reads `--eab-file` through it:
    /// a link at `eab.json` fails the load naming it.
    #[tokio::test]
    async fn a_default_layout_service_reads_its_eab_file_through_the_handle() {
        let tree = Tree::new();
        let service = tree.secrets.join("services/svc");
        std::fs::create_dir_all(&service).expect("mkdir");
        let config = tree.write_service_config(&service.join("secret_id"));
        let eab = service.join("eab.json");
        std::fs::write(&eab, r#"{"kid":"kid-in","hmac":"hmac-in"}"#).expect("eab");
        let argv = ["--config", &arg(&config), "--eab-file", &arg(&eab)].map(str::to_owned);
        let argv: Vec<&str> = argv.iter().map(String::as_str).collect();

        let (_, loaded, handle) = load_settings_with(&args(&argv), HandleOpening::ForcedRooted)
            .await
            .expect("the load");
        assert_eq!(loaded.expect("credentials").kid, "kid-in");
        assert_eq!(handle.expect("a handle").anchor(), tree.secrets.as_path());

        std::fs::write(
            tree.outside.join("eab.json"),
            r#"{"kid":"kid-out","hmac":"hmac-out"}"#,
        )
        .expect("outside eab");
        std::fs::remove_file(&eab).expect("remove");
        std::os::unix::fs::symlink(tree.outside.join("eab.json"), &eab).expect("link");
        let Err(err) = load_settings_with(&args(&argv), HandleOpening::ForcedRooted).await else {
            panic!("a linked eab.json is refused");
        };
        assert!(format!("{err:#}").contains(&eab.display().to_string()));
    }

    /// A `secret_id_path` override opens no handle.
    #[tokio::test]
    async fn an_overridden_secret_id_path_opens_no_handle() {
        let tree = Tree::new();
        let config = tree.write_service_config(&tree.secrets.join("elsewhere/svc/secret_id"));
        let (_, _, handle) = load_settings_with(
            &args(&["--config", &arg(&config)]),
            HandleOpening::ForcedRooted,
        )
        .await
        .expect("the load");
        assert!(handle.is_none());
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
