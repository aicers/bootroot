use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

use super::RotateContext;
use super::helpers::{confirm_action, try_restart_container};
use crate::commands::compose_file::compose_file_dir;
use crate::commands::compose_project::ComposeIdentity;
use crate::commands::container_name::BootrootContainer;
use crate::commands::init::{
    HTTP01_ADMIN_INFRA_CERT_KEY, OPENBAO_INFRA_CERT_KEY, OPENBAO_TLS_CERT_PATH,
    reissue_http01_admin_tls_cert, reissue_openbao_tls_cert,
};
use crate::i18n::Messages;
use crate::state::{InfraCertEntry, ReloadStrategy};

/// Signal that reloads the `OpenBao` listener certificate in place.
///
/// A restart would bring the container back sealed (Shamir seal, master
/// key in memory) and the rotate path never unseals; `SIGHUP` re-reads
/// the listener cert without a restart. See issue #727.
const OPENBAO_RELOAD_SIGNAL: &str = "SIGHUP";
/// Bounded deadline for the post-reload `OpenBao` TLS verification probe.
///
/// `SIGHUP` reloads the listener certificate near-instantly, so this
/// mainly absorbs I/O and scheduling latency while staying short enough
/// that a genuinely stale or unreachable listener fails promptly.
const OPENBAO_PROBE_DEADLINE: Duration = Duration::from_secs(8);
/// Interval between probe attempts while the reload lands.
const OPENBAO_PROBE_INTERVAL: Duration = Duration::from_millis(400);
/// Per-attempt bound on the probe's TCP connect and TLS handshake.
const OPENBAO_PROBE_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(3);

/// Renews all infrastructure certificates registered in
/// `StateFile::infra_certs`.
///
/// Iterates the map, re-issues each certificate, replaces the files,
/// and invokes the entry's reload strategy.  New certificate types
/// (e.g. #515 http01 admin) register by adding an arm to
/// [`dispatch_reissue`] — the loop body does not need to change.
pub(super) async fn rotate_infra_certs(
    ctx: &mut RotateContext,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    if ctx.state.infra_certs.is_empty() {
        println!("{}", messages.rotate_infra_tls_no_entries());
        return Ok(());
    }

    confirm_action(messages.prompt_rotate_infra_tls(), auto_confirm, messages)?;

    let state_file = ctx.state_file.clone();
    let compose_dir = compose_file_dir(&ctx.compose_file);
    // Both the SAN fallbacks and the reload strategies name containers,
    // so they follow the recorded instance rather than a fixed literal.
    let identity = ComposeIdentity::resolve(&ctx.compose_file, None, messages)?;
    let openbao_container = identity.container(BootrootContainer::OpenBao);
    let responder_container = identity.container(BootrootContainer::Http01);

    let entries: Vec<(String, InfraCertEntry)> = ctx
        .state
        .infra_certs
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    for (name, entry) in &entries {
        dispatch_reissue(
            name,
            &compose_dir,
            ctx.paths.secrets_dir(),
            entry,
            &ContainerNames {
                openbao: &openbao_container,
                responder: &responder_container,
            },
            &ctx.docker,
            messages,
        )
        .with_context(|| messages.error_infra_tls_renew_failed(name))?;

        // Resolve the reload strategy in code, not from the stored entry:
        // an already-initialized host (or a reinit that carried the
        // snapshot forward) may still record `ContainerRestart` for the
        // `openbao` key, which reseals the vault. See issue #727.
        let strategy = resolve_reload_strategy(name, entry, &openbao_container);

        if let Some(state_entry) = ctx.state.infra_certs.get_mut(name) {
            state_entry.issued_at = Some(
                time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            );
            // Normalize the persisted strategy so a stale `ContainerRestart`
            // converges to the signal after one run.
            state_entry.reload_strategy = strategy.clone();
        }

        println!("{}", messages.info_infra_tls_renewed(name));

        println!("{}", messages.info_infra_tls_reload(&strategy.to_string()));
        execute_reload_strategy(&strategy, &ctx.docker)?;

        // A delivered-but-ignored signal leaves no trace, so confirm the
        // renewed leaf is actually served before the run reports success.
        if name == OPENBAO_INFRA_CERT_KEY {
            let cert_path = compose_dir.join(OPENBAO_TLS_CERT_PATH);
            verify_openbao_tls_swap(
                &ctx.state.openbao_url,
                &cert_path,
                name,
                OPENBAO_PROBE_DEADLINE,
                OPENBAO_PROBE_INTERVAL,
                messages,
            )
            .await?;
            println!("{}", messages.info_infra_tls_verified(name));
        }
    }

    ctx.state
        .save(&state_file)
        .with_context(|| messages.error_serialize_state_failed())?;

    Ok(())
}

/// Resolves the effective reload strategy for a known infra-cert key.
///
/// The `openbao` key always resolves to a `SIGHUP` signal regardless of
/// what the entry recorded, so a host whose `state.json` still carries
/// `ContainerRestart` never reseals its vault on rotation. Other keys
/// keep the strategy the entry recorded.
fn resolve_reload_strategy(
    name: &str,
    entry: &InfraCertEntry,
    openbao_container: &str,
) -> ReloadStrategy {
    match name {
        OPENBAO_INFRA_CERT_KEY => ReloadStrategy::ContainerSignal {
            container_name: openbao_container.to_string(),
            signal: OPENBAO_RELOAD_SIGNAL.to_string(),
        },
        _ => entry.reload_strategy.clone(),
    }
}

/// The container names an infra-cert re-issuance needs, resolved once
/// from the install identity rather than per dispatch arm.
struct ContainerNames<'a> {
    openbao: &'a str,
    responder: &'a str,
}

/// Dispatches certificate re-issuance by infra-cert key.
///
/// Each infrastructure certificate type registers an arm here.
/// Unknown keys surface as errors through the standard rotation
/// error path.
fn dispatch_reissue(
    name: &str,
    compose_dir: &Path,
    secrets_dir: &Path,
    entry: &InfraCertEntry,
    containers: &ContainerNames<'_>,
    docker: &Path,
    messages: &Messages,
) -> Result<()> {
    match name {
        OPENBAO_INFRA_CERT_KEY => reissue_openbao_tls_cert(
            compose_dir,
            secrets_dir,
            entry,
            containers.openbao,
            docker,
            messages,
        ),
        HTTP01_ADMIN_INFRA_CERT_KEY => reissue_http01_admin_tls_cert(
            secrets_dir,
            entry,
            containers.responder,
            docker,
            messages,
        ),
        _ => bail!("Unknown infra cert key: {name}"),
    }
}

/// Executes a reload strategy after certificate renewal.
///
/// `docker` reaches the signal arm only.  The restart arm goes through
/// [`try_restart_container`], which no test drives and which is shared
/// with a `&dyn Fn` seam in `rotate::ca`; giving it an executable would
/// change that callback type for no caller.
fn execute_reload_strategy(strategy: &ReloadStrategy, docker: &Path) -> Result<()> {
    match strategy {
        ReloadStrategy::ContainerRestart { container_name } => {
            try_restart_container(container_name)
                .with_context(|| format!("Failed to restart container {container_name}"))?;
        }
        ReloadStrategy::ContainerSignal {
            container_name,
            signal,
        } => {
            try_signal_container(container_name, signal, docker)
                .with_context(|| format!("Failed to signal container {container_name}"))?;
        }
    }
    Ok(())
}

/// Sends a signal to a Docker container via `docker kill -s`.
fn try_signal_container(container: &str, signal: &str, docker: &Path) -> Result<()> {
    let status = std::process::Command::new(docker)
        .args(["kill", "-s", signal, container])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        anyhow::bail!("container {container} not found or signal failed");
    }
    Ok(())
}

/// Confirms the `OpenBao` listener now serves the certificate just
/// written to `cert_path` after the reload signal.
///
/// Opens an unauthenticated TLS connection to the **state-resident**
/// listener URL (`ctx.state.openbao_url`, never the override-merged
/// context value, so `--openbao-url` cannot steer the probe), reads the
/// leaf the peer presents, and compares its SHA-256 fingerprint against
/// the local file. The handshake accepts any certificate — it
/// establishes identity for a byte comparison, not trust — so no chain
/// building, hostname validation, token, or authenticated call is
/// involved. Retries within [`OPENBAO_PROBE_DEADLINE`], then fails with
/// a message that distinguishes an unreachable listener from a served
/// leaf that never matched.
async fn verify_openbao_tls_swap(
    state_url: &str,
    cert_path: &Path,
    entry_name: &str,
    deadline: Duration,
    interval: Duration,
    messages: &Messages,
) -> Result<()> {
    let (host, port) = parse_https_authority(state_url)
        .ok_or_else(|| anyhow!(messages.error_infra_tls_openbao_url_not_https(state_url)))?;

    let expected = leaf_fingerprint_from_pem(cert_path, messages)?;

    match wait_for_served_leaf(&host, port, expected.as_ref(), deadline, interval).await {
        ProbeOutcome::Matched => Ok(()),
        ProbeOutcome::Mismatch => bail!(messages.error_infra_tls_probe_mismatch(entry_name)),
        ProbeOutcome::Unreachable => {
            bail!(messages.error_infra_tls_probe_unreachable(entry_name, &format!("{host}:{port}")))
        }
    }
}

/// Outcome of polling the `OpenBao` listener for the renewed leaf.
#[derive(Debug, PartialEq, Eq)]
enum ProbeOutcome {
    /// The served leaf matched the expected fingerprint.
    Matched,
    /// A handshake completed at least once but the served leaf never
    /// matched within the deadline.
    Mismatch,
    /// No handshake ever completed within the deadline.
    Unreachable,
}

/// Polls the listener until the served leaf matches `expected_fp` or the
/// deadline expires.
///
/// Distinguishes a listener that was never reachable from one that
/// stayed reachable while serving a non-matching leaf, so the caller can
/// emit the right diagnostic.
async fn wait_for_served_leaf(
    host: &str,
    port: u16,
    expected_fp: &[u8],
    deadline: Duration,
    interval: Duration,
) -> ProbeOutcome {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert))
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));

    let end = tokio::time::Instant::now() + deadline;
    let mut ever_connected = false;
    loop {
        if let Ok(served) = probe_served_leaf(&connector, host, port).await {
            ever_connected = true;
            if fingerprint(&served).as_ref() == expected_fp {
                return ProbeOutcome::Matched;
            }
        }
        if tokio::time::Instant::now() >= end {
            break;
        }
        tokio::time::sleep(interval).await;
    }

    if ever_connected {
        ProbeOutcome::Mismatch
    } else {
        ProbeOutcome::Unreachable
    }
}

/// Parses the host and port from an `https://host:port` state URL.
///
/// Returns `None` when the URL is not `https` or carries no explicit
/// port. Handles bracketed IPv6 authorities (`[::1]:8200`).
fn parse_https_authority(url: &str) -> Option<(String, u16)> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    if let Some(after_bracket) = authority.strip_prefix('[') {
        let (host, port_part) = after_bracket.split_once(']')?;
        let port = port_part.strip_prefix(':')?.parse().ok()?;
        Some((host.to_string(), port))
    } else {
        let (host, port_str) = authority.rsplit_once(':')?;
        let port = port_str.parse().ok()?;
        Some((host.to_string(), port))
    }
}

/// Opens one TLS connection and returns the DER of the leaf the peer
/// presents.
async fn probe_served_leaf(
    connector: &tokio_rustls::TlsConnector,
    host: &str,
    port: u16,
) -> Result<Vec<u8>> {
    let stream = tokio::time::timeout(
        OPENBAO_PROBE_ATTEMPT_TIMEOUT,
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .context("OpenBao TLS probe TCP connect timed out")??;
    let server_name =
        ServerName::try_from(host.to_string()).context("OpenBao TLS probe server name invalid")?;
    let tls = tokio::time::timeout(
        OPENBAO_PROBE_ATTEMPT_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    .context("OpenBao TLS probe handshake timed out")??;
    let leaf = tls
        .get_ref()
        .1
        .peer_certificates()
        .and_then(<[CertificateDer<'_>]>::first)
        .ok_or_else(|| anyhow!("OpenBao TLS probe peer presented no certificate"))?;
    Ok(leaf.as_ref().to_vec())
}

/// Reads the first PEM certificate from `cert_path` and returns its
/// SHA-256 fingerprint over the DER encoding.
fn leaf_fingerprint_from_pem(
    cert_path: &Path,
    messages: &Messages,
) -> Result<ring::digest::Digest> {
    let pem = std::fs::read(cert_path)
        .with_context(|| messages.error_read_file_failed(&cert_path.display().to_string()))?;
    let mut reader = BufReader::new(pem.as_slice());
    let leaf = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or_else(|| anyhow!("no certificate found in {}", cert_path.display()))?
        .with_context(|| messages.error_read_file_failed(&cert_path.display().to_string()))?;
    Ok(fingerprint(leaf.as_ref()))
}

/// Computes the SHA-256 fingerprint of a DER-encoded certificate.
fn fingerprint(der: &[u8]) -> ring::digest::Digest {
    ring::digest::digest(&ring::digest::SHA256, der)
}

/// TLS verifier that accepts any certificate.
///
/// The verification probe only needs the peer's leaf bytes to compare
/// against a locally written file, so the handshake result is used
/// solely for that byte comparison — never to establish trust. Chain
/// building and hostname validation are intentionally bypassed and must
/// not become a dependency of this path.
#[derive(Debug)]
struct AcceptAnyServerCert;

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::super::test_support::{
        decode_fake_docker_log, test_messages, write_self_contained_fake_docker,
    };
    use super::*;
    use crate::cli::args::{
        AuthMode, ComposeFileArgs, OpenBaoOverrideArgs, RotateArgs, RotateCommand,
        RotateInfraCertArgs, RuntimeAuthArgs, SecretsDirOverrideArgs,
    };
    use crate::commands::constants::RESPONDER_SERVICE_NAME;
    use crate::commands::init::{
        HTTP01_ADMIN_INFRA_CERT_KEY, HTTP01_ADMIN_TLS_CERT_REL_PATH,
        HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE, HTTP01_ADMIN_TLS_KEY_REL_PATH,
        OPENBAO_INFRA_CERT_KEY, OPENBAO_TLS_CERT_PATH, OPENBAO_TLS_DEFAULT_RENEW_BEFORE,
        OPENBAO_TLS_KEY_PATH,
    };
    use crate::commands::rotate::{run_rotate, run_rotate_with_exec};
    use crate::state::StateFile;

    /// The `OpenBao` container name a default install renders.
    const DEFAULT_OPENBAO_CONTAINER: &str = "bootroot-openbao";

    fn make_openbao_infra_entry(compose_dir: &std::path::Path) -> InfraCertEntry {
        InfraCertEntry {
            cert_path: compose_dir.join(OPENBAO_TLS_CERT_PATH),
            key_path: compose_dir.join(OPENBAO_TLS_KEY_PATH),
            sans: vec![
                "openbao.internal".to_string(),
                "localhost".to_string(),
                "bootroot-openbao".to_string(),
            ],
            renew_before: OPENBAO_TLS_DEFAULT_RENEW_BEFORE.to_string(),
            reload_strategy: ReloadStrategy::ContainerRestart {
                container_name: DEFAULT_OPENBAO_CONTAINER.to_string(),
            },
            issued_at: None,
            expires_at: None,
        }
    }

    /// Self-signed certificate material for the in-process TLS stub.
    struct TestCert {
        cert_pem: String,
        key_pem: String,
        cert_der: Vec<u8>,
        key_der: Vec<u8>,
    }

    fn generate_test_cert(common_name: &str) -> TestCert {
        use rcgen::{CertificateParams, DnType, KeyPair};
        let key = KeyPair::generate().expect("generate key");
        let mut params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        let cert = params.self_signed(&key).expect("self-signed cert");
        TestCert {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }

    /// Starts an in-process rustls TLS listener on `127.0.0.1:0` that
    /// serves `cert_der`/`key_der` and completes the handshake. Returns
    /// the bound port. Mirrors the stub pattern in
    /// `tests/e2e_multi_host_tls.rs`.
    async fn start_tls_server(cert_der: Vec<u8>, key_der: Vec<u8>) -> u16 {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::TlsAcceptor;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = CertificateDer::from(cert_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("stub server config");
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind stub listener");
        let port = listener.local_addr().expect("stub addr").port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let _ = acceptor.accept(stream).await;
                });
            }
        });
        port
    }

    /// Exercises `run_rotate(RotateCommand::InfraCert)` end-to-end for an
    /// `openbao` entry whose recorded strategy is the stale
    /// `ContainerRestart`.
    ///
    /// Proves the whole fix on the success path: `InfraCert` dispatches
    /// without any authenticated `OpenBao` bootstrap (a reachable stub
    /// that only completes a TLS handshake would make an auth attempt
    /// fail), the container is signalled (`docker kill -s SIGHUP`) and
    /// never restarted, the post-reload probe confirms the served leaf,
    /// the persisted entry is normalized to the signal strategy, and the
    /// refreshed `issued_at` lands in the non-default state filename
    /// (`custom.json`).
    // The verbose `RotateArgs`/`StateFile` literals plus the end-to-end
    // assertions push this past the line cap; splitting it would obscure
    // the single scenario it pins.
    #[allow(clippy::too_many_lines)]
    #[test]
    fn run_rotate_infra_cert_signals_and_verifies_openbao() {
        let dir = tempfile::tempdir().expect("tempdir");
        let messages = test_messages();

        let fake_docker = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake_docker, &args_log);

        let compose_dir = dir.path().join("compose");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("secrets dir");

        // The fake docker no-ops the `step certificate create` call, so
        // this pre-written real PEM survives the reissue and the stub
        // listener serves the very same bytes back to the probe.
        let cert = generate_test_cert("openbao.internal");
        let tls_dir = compose_dir.join("openbao").join("tls");
        fs::create_dir_all(&tls_dir).expect("tls dir");
        fs::write(tls_dir.join("server.crt"), &cert.cert_pem).expect("write cert");
        fs::write(tls_dir.join("server.key"), &cert.key_pem).expect("write key");

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let port = rt.block_on(start_tls_server(
            cert.cert_der.clone(),
            cert.key_der.clone(),
        ));

        // The entry deliberately records `ContainerRestart` to prove the
        // rotate path resolves and normalizes to the signal in code.
        let mut infra_certs = BTreeMap::new();
        infra_certs.insert(
            OPENBAO_INFRA_CERT_KEY.to_string(),
            make_openbao_infra_entry(&compose_dir),
        );

        let state = StateFile {
            openbao_url: format!("https://127.0.0.1:{port}"),
            kv_mount: String::new(),
            secrets_dir: Some(secrets_dir.clone()),
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs,
            ..Default::default()
        };

        // Write state under a non-default filename to verify that the
        // full state-file path propagates through `RotateContext`.
        let state_file = dir.path().join("custom.json");
        state.save(&state_file).expect("write state");

        let args = RotateArgs {
            command: RotateCommand::InfraCert(RotateInfraCertArgs {}),
            state_file: Some(state_file.clone()),
            compose: ComposeFileArgs {
                compose_file: compose_dir.join("docker-compose.yml"),
            },
            openbao: OpenBaoOverrideArgs {
                openbao_url: None,
                kv_mount: None,
            },
            secrets_dir: SecretsDirOverrideArgs {
                secrets_dir: Some(secrets_dir),
            },
            runtime_auth: RuntimeAuthArgs {
                auth_mode: AuthMode::Auto,
                root_token: None,
                root_token_file: None,
                approle_role_id: None,
                approle_secret_id: None,
                approle_role_id_file: None,
                approle_secret_id_file: None,
            },
            yes: true,
            show_secrets: false,
        };

        rt.block_on(run_rotate_with_exec(&args, &fake_docker, &messages))
            .expect("run_rotate(InfraCert) must succeed and verify the swap");

        // The updated state must have been written back to the
        // custom-named file (not a hardcoded `state.json`).
        let reloaded = StateFile::load(&state_file).expect("custom state file must be readable");
        let entry = reloaded
            .infra_certs
            .get(OPENBAO_INFRA_CERT_KEY)
            .expect("openbao entry must still exist");
        assert!(
            entry.issued_at.is_some(),
            "issued_at must be updated after renewal"
        );
        // The stale ContainerRestart must be normalized to the signal.
        assert_eq!(
            entry.reload_strategy,
            ReloadStrategy::ContainerSignal {
                container_name: DEFAULT_OPENBAO_CONTAINER.to_string(),
                signal: "SIGHUP".to_string(),
            },
            "state must record the signal strategy after normalization"
        );

        // No `state.json` sibling should have been created.
        assert!(
            !dir.path().join("state.json").exists(),
            "state must not be written to hardcoded state.json"
        );

        // The fake keeps every invocation, so the reload signal is
        // pinned as one whole argv rather than as bytes anywhere in the
        // log, and the restart check now covers the entire run.
        let invocations = decode_fake_docker_log(&args_log);
        assert!(
            invocations.contains(&vec![
                "kill".to_string(),
                "-s".to_string(),
                "SIGHUP".to_string(),
                DEFAULT_OPENBAO_CONTAINER.to_string(),
            ]),
            "the reload must be kill -s SIGHUP against the openbao container, got: {invocations:?}"
        );
        assert!(
            !invocations.iter().flatten().any(|arg| arg == "restart"),
            "openbao entry must never trigger docker restart, got: {invocations:?}"
        );
    }

    /// The negative half of the original bypass test: with an unreachable
    /// state URL the mandatory probe fails, and the failure must be the
    /// probe's *reach* failure — proving `InfraCert` still dispatched
    /// past reissue and signalling before any authenticated `OpenBao` work.
    #[test]
    fn run_rotate_infra_cert_fails_when_probe_unreachable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let messages = test_messages();

        let fake_docker = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake_docker, &args_log);

        let compose_dir = dir.path().join("compose");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("secrets dir");

        // A real PEM so the fingerprint read succeeds and the failure is
        // attributable to the probe reach, not a cert-parse error.
        let cert = generate_test_cert("openbao.internal");
        let tls_dir = compose_dir.join("openbao").join("tls");
        fs::create_dir_all(&tls_dir).expect("tls dir");
        fs::write(tls_dir.join("server.crt"), &cert.cert_pem).expect("write cert");
        fs::write(tls_dir.join("server.key"), &cert.key_pem).expect("write key");

        let mut infra_certs = BTreeMap::new();
        infra_certs.insert(
            OPENBAO_INFRA_CERT_KEY.to_string(),
            make_openbao_infra_entry(&compose_dir),
        );

        let state = StateFile {
            // RFC 5737 TEST-NET, port 1 — nothing listens here.
            openbao_url: "https://192.0.2.1:1".to_string(),
            kv_mount: String::new(),
            secrets_dir: Some(secrets_dir.clone()),
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs,
            ..Default::default()
        };

        let state_file = dir.path().join("custom.json");
        state.save(&state_file).expect("write state");

        let args = RotateArgs {
            command: RotateCommand::InfraCert(RotateInfraCertArgs {}),
            state_file: Some(state_file.clone()),
            compose: ComposeFileArgs {
                compose_file: compose_dir.join("docker-compose.yml"),
            },
            openbao: OpenBaoOverrideArgs {
                openbao_url: None,
                kv_mount: None,
            },
            secrets_dir: SecretsDirOverrideArgs {
                secrets_dir: Some(secrets_dir),
            },
            runtime_auth: RuntimeAuthArgs {
                auth_mode: AuthMode::Auto,
                root_token: None,
                root_token_file: None,
                approle_role_id: None,
                approle_secret_id: None,
                approle_role_id_file: None,
                approle_secret_id_file: None,
            },
            yes: true,
            show_secrets: false,
        };

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        let err = rt
            .block_on(run_rotate_with_exec(&args, &fake_docker, &messages))
            .expect_err("unreachable probe target must fail the command");
        let chain = format!("{err:#}");
        assert!(
            chain.contains("could not reach the OpenBao listener"),
            "failure must be the probe reach error, got: {chain}"
        );
        assert!(
            !chain.contains("health check"),
            "failure must not be an OpenBao health-check error, got: {chain}"
        );

        // The reload signal (`kill`) must have run before the probe, so
        // the container was never restarted.
        let invocations = decode_fake_docker_log(&args_log);
        assert!(
            !invocations.iter().flatten().any(|arg| arg == "restart"),
            "openbao entry must never trigger docker restart, got: {invocations:?}"
        );
    }

    fn make_http01_admin_infra_entry(secrets_dir: &std::path::Path) -> InfraCertEntry {
        InfraCertEntry {
            cert_path: secrets_dir.join(HTTP01_ADMIN_TLS_CERT_REL_PATH),
            key_path: secrets_dir.join(HTTP01_ADMIN_TLS_KEY_REL_PATH),
            sans: vec![
                "responder.internal".to_string(),
                "localhost".to_string(),
                RESPONDER_SERVICE_NAME.to_string(),
            ],
            renew_before: HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE.to_string(),
            reload_strategy: ReloadStrategy::ContainerSignal {
                container_name: RESPONDER_SERVICE_NAME.to_string(),
                signal: "SIGHUP".to_string(),
            },
            issued_at: None,
            expires_at: None,
        }
    }

    /// Exercises `run_rotate(RotateCommand::InfraCert)` with an
    /// HTTP-01 admin entry that uses `ContainerSignal` reload.
    ///
    /// Verifies the `dispatch_reissue` arm for
    /// `HTTP01_ADMIN_INFRA_CERT_KEY` and the `execute_reload_strategy`
    /// path for `ContainerSignal`.
    #[test]
    fn run_rotate_infra_cert_renews_http01_admin_tls() {
        let dir = tempfile::tempdir().expect("tempdir");
        let messages = test_messages();

        let fake_docker = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake_docker, &args_log);

        let compose_dir = dir.path().join("compose");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("secrets dir");

        // Pre-create cert/key files so `set_key_permissions_sync`
        // succeeds after the fake docker "issues" the cert.
        let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
        fs::create_dir_all(&tls_dir).expect("tls dir");
        fs::write(tls_dir.join("server.crt"), "fake-cert").expect("write cert");
        fs::write(tls_dir.join("server.key"), "fake-key").expect("write key");

        let mut infra_certs = BTreeMap::new();
        infra_certs.insert(
            HTTP01_ADMIN_INFRA_CERT_KEY.to_string(),
            make_http01_admin_infra_entry(&secrets_dir),
        );

        let state = StateFile {
            openbao_url: "https://192.0.2.1:1".to_string(),
            kv_mount: String::new(),
            secrets_dir: Some(secrets_dir.clone()),
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs,
            ..Default::default()
        };

        let state_file = dir.path().join("state.json");
        state.save(&state_file).expect("write state");

        let args = RotateArgs {
            command: RotateCommand::InfraCert(RotateInfraCertArgs {}),
            state_file: Some(state_file.clone()),
            compose: ComposeFileArgs {
                compose_file: compose_dir.join("docker-compose.yml"),
            },
            openbao: OpenBaoOverrideArgs {
                openbao_url: None,
                kv_mount: None,
            },
            secrets_dir: SecretsDirOverrideArgs {
                secrets_dir: Some(secrets_dir),
            },
            runtime_auth: RuntimeAuthArgs {
                auth_mode: AuthMode::Auto,
                root_token: None,
                root_token_file: None,
                approle_role_id: None,
                approle_secret_id: None,
                approle_role_id_file: None,
                approle_secret_id_file: None,
            },
            yes: true,
            show_secrets: false,
        };

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(run_rotate_with_exec(&args, &fake_docker, &messages))
            .expect("run_rotate(InfraCert) must succeed for http01 admin entry");

        let reloaded = StateFile::load(&state_file).expect("state file must be readable");
        let entry = reloaded
            .infra_certs
            .get(HTTP01_ADMIN_INFRA_CERT_KEY)
            .expect("http01 admin entry must still exist");
        assert!(
            entry.issued_at.is_some(),
            "issued_at must be updated after renewal"
        );

        // Verify the fake docker received a `kill -s SIGHUP` command
        // (the ContainerSignal reload strategy).
        let invocations = decode_fake_docker_log(&args_log);
        assert!(
            invocations.contains(&vec![
                "kill".to_string(),
                "-s".to_string(),
                "SIGHUP".to_string(),
                RESPONDER_SERVICE_NAME.to_string(),
            ]),
            "docker must have been called with kill -s SIGHUP, got: {invocations:?}"
        );
        // The HTTP-01 admin entry gets no post-reload verification, so no
        // openbao_url is consulted and no probe runs.
    }

    /// The `openbao` key's strategy is resolved in code rather than read
    /// from the entry, so it has to name *this* install's container
    /// while keeping the signal variant a restart would break (#727).
    #[test]
    fn openbao_reload_strategy_names_the_instance_container() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut entry = make_openbao_infra_entry(dir.path());
        // Deliberately stale: an older `state.json` may still record a
        // restart against the default instance's container.
        entry.reload_strategy = ReloadStrategy::ContainerRestart {
            container_name: DEFAULT_OPENBAO_CONTAINER.to_string(),
        };
        let strategy = resolve_reload_strategy(OPENBAO_INFRA_CERT_KEY, &entry, "insight-openbao");
        assert_eq!(
            strategy,
            ReloadStrategy::ContainerSignal {
                container_name: "insight-openbao".to_string(),
                signal: OPENBAO_RELOAD_SIGNAL.to_string(),
            }
        );
        assert_eq!(
            strategy.to_string(),
            "container_signal(insight-openbao, SIGHUP)"
        );
    }

    /// Every other key keeps the strategy its entry recorded, which is
    /// where the http01 admin container name comes from.
    #[test]
    fn non_openbao_reload_strategy_is_taken_from_the_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut entry = make_http01_admin_infra_entry(dir.path());
        entry.reload_strategy = ReloadStrategy::ContainerSignal {
            container_name: "insight-http01".to_string(),
            signal: "SIGHUP".to_string(),
        };
        let strategy =
            resolve_reload_strategy(HTTP01_ADMIN_INFRA_CERT_KEY, &entry, "insight-openbao");
        assert_eq!(
            strategy.to_string(),
            "container_signal(insight-http01, SIGHUP)"
        );
    }

    /// The seam at the signal spawn: `execute_reload_strategy` kills the
    /// container with whichever program its caller named, which in the
    /// flow is `ctx.docker`.  The signal therefore has to reach the
    /// instance's own responder container, not a co-located install's.
    ///
    /// The test mutates nothing process-global — no `PATH` edit, no
    /// variable set, no lock — because the fake carries its own
    /// argv-log path in its script text.
    #[test]
    fn container_signal_runs_the_supplied_executable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        execute_reload_strategy(
            &ReloadStrategy::ContainerSignal {
                container_name: "insight-http01".to_string(),
                signal: "SIGHUP".to_string(),
            },
            &fake,
        )
        .expect("signalling must succeed against the supplied executable");

        assert_eq!(
            decode_fake_docker_log(&args_log),
            [["kill", "-s", "SIGHUP", "insight-http01"]],
            "the supplied executable must have received the unchanged argv"
        );
    }

    /// An empty `infra_certs` map is a no-op: the command prints the
    /// no-entries message and exits 0 without prompting or invoking
    /// Docker.
    #[test]
    fn run_rotate_infra_cert_empty_map_is_noop() {
        let dir = tempfile::tempdir().expect("tempdir");
        let messages = test_messages();

        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("secrets dir");

        let state = StateFile {
            openbao_url: "https://192.0.2.1:1".to_string(),
            kv_mount: String::new(),
            secrets_dir: Some(secrets_dir.clone()),
            infra_certs: BTreeMap::new(),
            ..Default::default()
        };
        let state_file = dir.path().join("state.json");
        state.save(&state_file).expect("write state");

        let args = RotateArgs {
            command: RotateCommand::InfraCert(RotateInfraCertArgs {}),
            state_file: Some(state_file),
            compose: ComposeFileArgs {
                compose_file: dir.path().join("docker-compose.yml"),
            },
            openbao: OpenBaoOverrideArgs {
                openbao_url: None,
                kv_mount: None,
            },
            secrets_dir: SecretsDirOverrideArgs {
                secrets_dir: Some(secrets_dir),
            },
            runtime_auth: RuntimeAuthArgs {
                auth_mode: AuthMode::Auto,
                root_token: None,
                root_token_file: None,
                approle_role_id: None,
                approle_secret_id: None,
                approle_role_id_file: None,
                approle_secret_id_file: None,
            },
            // `--yes` is false to prove the no-op returns before the
            // confirmation prompt (it never blocks on stdin).
            yes: false,
            show_secrets: false,
        };

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(run_rotate(&args, &messages))
            .expect("empty infra_certs must be a successful no-op");
    }

    /// A served leaf matching the freshly written certificate file makes
    /// the probe succeed.
    #[tokio::test]
    async fn probe_succeeds_when_served_leaf_matches_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let messages = test_messages();
        let cert = generate_test_cert("openbao.internal");
        let cert_path = dir.path().join("server.crt");
        fs::write(&cert_path, &cert.cert_pem).expect("write cert");

        let port = start_tls_server(cert.cert_der.clone(), cert.key_der.clone()).await;
        let url = format!("https://127.0.0.1:{port}");

        verify_openbao_tls_swap(
            &url,
            &cert_path,
            OPENBAO_INFRA_CERT_KEY,
            Duration::from_secs(3),
            Duration::from_millis(100),
            &messages,
        )
        .await
        .expect("served leaf matches the written file");
    }

    /// A listener that keeps serving a different leaf for the whole
    /// deadline fails with a message that names the entry.
    #[tokio::test]
    async fn probe_errors_when_served_leaf_differs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let messages = test_messages();
        let served = generate_test_cert("served-cert");
        let written = generate_test_cert("written-cert");
        let cert_path = dir.path().join("server.crt");
        fs::write(&cert_path, &written.cert_pem).expect("write cert");

        let port = start_tls_server(served.cert_der.clone(), served.key_der.clone()).await;
        let url = format!("https://127.0.0.1:{port}");

        let err = verify_openbao_tls_swap(
            &url,
            &cert_path,
            OPENBAO_INFRA_CERT_KEY,
            Duration::from_millis(600),
            Duration::from_millis(100),
            &messages,
        )
        .await
        .expect_err("mismatched served leaf must fail");
        let msg = err.to_string();
        assert!(
            msg.contains(OPENBAO_INFRA_CERT_KEY),
            "mismatch error must name the entry, got: {msg}"
        );
        assert!(
            msg.contains("still serves the previous certificate"),
            "expected the mismatch message, got: {msg}"
        );
    }

    /// Nothing listening on the target yields a distinguishable reach
    /// error rather than a mismatch.
    #[tokio::test]
    async fn probe_errors_when_listener_unreachable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let messages = test_messages();
        let cert = generate_test_cert("openbao.internal");
        let cert_path = dir.path().join("server.crt");
        fs::write(&cert_path, &cert.cert_pem).expect("write cert");

        // Bind then immediately drop to obtain a port with no listener.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind for free port");
        let port = listener.local_addr().expect("addr").port();
        drop(listener);
        let url = format!("https://127.0.0.1:{port}");

        let err = verify_openbao_tls_swap(
            &url,
            &cert_path,
            OPENBAO_INFRA_CERT_KEY,
            Duration::from_millis(600),
            Duration::from_millis(100),
            &messages,
        )
        .await
        .expect_err("unreachable listener must fail");
        let msg = err.to_string();
        assert!(
            msg.contains(OPENBAO_INFRA_CERT_KEY),
            "reach error must name the entry, got: {msg}"
        );
        assert!(
            msg.contains("could not reach the OpenBao listener"),
            "expected the reach message, got: {msg}"
        );
    }

    /// A non-`https` state URL while an openbao entry is present is an
    /// internally inconsistent state and must fail loudly.
    #[tokio::test]
    async fn probe_errors_when_state_url_not_https() {
        let dir = tempfile::tempdir().expect("tempdir");
        let messages = test_messages();
        let cert = generate_test_cert("openbao.internal");
        let cert_path = dir.path().join("server.crt");
        fs::write(&cert_path, &cert.cert_pem).expect("write cert");

        let err = verify_openbao_tls_swap(
            "http://127.0.0.1:8200",
            &cert_path,
            OPENBAO_INFRA_CERT_KEY,
            Duration::from_millis(200),
            Duration::from_millis(50),
            &messages,
        )
        .await
        .expect_err("non-https state URL must fail");
        assert!(
            err.to_string().contains("not a usable https URL"),
            "expected the not-https message, got: {err}"
        );
    }

    #[test]
    fn parse_https_authority_handles_ipv4_ipv6_and_rejects_http() {
        assert_eq!(
            parse_https_authority("https://127.0.0.1:8200"),
            Some(("127.0.0.1".to_string(), 8200))
        );
        assert_eq!(
            parse_https_authority("https://[::1]:8200"),
            Some(("::1".to_string(), 8200))
        );
        assert_eq!(parse_https_authority("http://127.0.0.1:8200"), None);
        assert_eq!(parse_https_authority("https://127.0.0.1"), None);
    }
}
