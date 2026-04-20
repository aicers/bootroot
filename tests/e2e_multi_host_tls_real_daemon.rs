//! Real-daemon multi-host TLS acceptance test for the RN → CN control-plane.
//!
//! Complements [`e2e_multi_host_tls.rs`] by swapping the in-process rustls
//! `OpenBao` mock for a fully-provisioned, TLS-enabled real `openbao`
//! daemon (run via `docker`).  The RN side consumes a production-style
//! `bootstrap.json` artifact that carries a response-wrapped `secret_id`:
//! bootstrap first unwraps that token over TLS, then logs in via
//! `AppRole`, pulls per-service KV, persists the CA bundle, and drives
//! an HTTP-01 admin registration against a TLS responder — all anchored
//! to the artifact-embedded CA.
//!
//! This file covers the three scenarios from #521 end-to-end against the
//! real daemon.  All three reuse the same fully-provisioned-daemon /
//! bootstrap-artifact path, varying only the presented certificates and
//! trust inputs per scenario:
//!
//! 1. Happy path — real unwrap + login + KV pull over TLS, then http01
//!    registration and a public `.well-known/acme-challenge/…` fetch.
//! 2. System-trust rejection — the real daemon is fully provisioned and
//!    issues a real wrap token packaged into the artifact, but its cert
//!    (and the responder's) is signed by a CA that is NOT the artifact
//!    anchor.  Bootstrap must reject the handshake even though a
//!    positive-trust probe rooted at the same CA succeeds; http01
//!    registration against the artifact anchor must also reject.
//! 3. Pin-enforced rejection — the real daemon is fully provisioned with
//!    a combined step-ca + system-ca trust bundle and a step-ca pin in
//!    `/trust`.  Bootstrap unwraps, logs in, and persists the bundle and
//!    pin into `agent.toml`.  The responder presents a system-ca-signed
//!    cert whose chain is valid under the combined bundle; the step-ca
//!    pin rejects the handshake, and removing the pin accepts the same
//!    chain, isolating the rejection to the pin.
//!
//! # Docker dependency
//!
//! These tests require the `docker` CLI and the `openbao/openbao` image on
//! the host.  If `docker` is unavailable, each test prints a message and
//! exits successfully so the file is safe to include in `cargo test`
//! invocations on machines without Docker.

#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use bootroot::acme::responder_client::{
    ResponderTrust, register_http01_token, register_http01_token_with,
};
use bootroot::config::Settings;
use bootroot::openbao::{OpenBaoClient, SecretIdOptions};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType};
use serde_json::json;
use tempfile::{TempDir, tempdir};
use tokio::time::sleep;

const SERVICE_NAME: &str = "edge-proxy";
const HOSTNAME: &str = "edge-node-02";
const DOMAIN: &str = "trusted.domain";
const INSTANCE_ID: &str = "101";
const KV_MOUNT: &str = "secret";
const HMAC_SECRET: &str = "real-daemon-multi-host-tls-hmac";
const STARTUP_RETRIES: usize = 50;
const STARTUP_DELAY: Duration = Duration::from_millis(100);
const TEST_TTL_SECS: u64 = 60;
const WRAP_TTL: &str = "300s";
const OPENBAO_IMAGE: &str = "openbao/openbao:latest";
const OPENBAO_READY_TIMEOUT: Duration = Duration::from_mins(1);
const OPENBAO_POLL_INTERVAL: Duration = Duration::from_millis(250);
const RESPONDER_BIND_ATTEMPTS: u32 = 4;

// ---------------------------------------------------------------------------
// TLS fixtures
// ---------------------------------------------------------------------------

struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
    der: Vec<u8>,
}

#[allow(clippy::struct_field_names)] // explicit _pem suffix disambiguates from DER variants
struct SignedCert {
    cert_pem: String,
    key_pem: String,
    issuer_pem: String,
}

fn server_chain_pem(cert: &SignedCert) -> String {
    format!("{}{}", cert.cert_pem, cert.issuer_pem)
}

impl TestCa {
    fn generate(common_name: &str) -> Self {
        let key = KeyPair::generate().expect("generate CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("CA cert params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.clone().self_signed(&key).expect("self-signed CA");
        let pem = cert.pem();
        let der = cert.der().to_vec();
        Self {
            issuer: Issuer::new(params, key),
            pem,
            der,
        }
    }

    fn sha256_fingerprint(&self) -> String {
        use std::fmt::Write as _;
        let digest = ring::digest::digest(&ring::digest::SHA256, &self.der);
        let mut hex = String::with_capacity(64);
        for byte in digest.as_ref() {
            write!(hex, "{byte:02x}").expect("hex write");
        }
        hex
    }

    fn sign_server_cert(&self, sans: &[&str]) -> SignedCert {
        let key = KeyPair::generate().expect("generate server key");
        let san_strings: Vec<String> = sans.iter().map(|s| (*s).to_string()).collect();
        let mut params = CertificateParams::new(san_strings.clone()).expect("server cert params");
        // rcgen::CertificateParams::new accepts Vec<String> for SANs, but
        // also allow explicit IP SANs for addresses that are not DNS names.
        params.subject_alt_names = sans
            .iter()
            .map(|s| {
                s.parse::<std::net::IpAddr>().map_or_else(
                    |_| SanType::DnsName((*s).try_into().expect("valid DNS SAN")),
                    SanType::IpAddress,
                )
            })
            .collect();
        params
            .distinguished_name
            .push(DnType::CommonName, sans.first().copied().unwrap_or("leaf"));
        params.is_ca = IsCa::NoCa;
        let cert = params
            .signed_by(&key, &self.issuer)
            .expect("sign server cert");
        SignedCert {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            issuer_pem: self.pem.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// Docker OpenBao fixture
// ---------------------------------------------------------------------------

fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|s| s.success())
}

fn unique_container_name(label: &str) -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    let pid = std::process::id();
    format!("bootroot-test-openbao-{label}-{pid}-{nanos}")
}

/// Reserves an ephemeral localhost port by binding `127.0.0.1:0` and
/// immediately dropping the listener.  There is an inherent TOCTOU between
/// releasing the listener here and the child process re-binding the same
/// address; `docker -p 127.0.0.1:<port>:8200` fails fast on conflict and
/// the caller retries with a fresh port.
fn reserve_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").port()
}

fn reserve_socket_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").to_string()
}

/// A TLS-enabled real `openbao` daemon running inside a docker container.
///
/// The container mounts a tempdir containing the HCL config and the TLS
/// cert/key.  The container is deleted on drop.
struct DockerOpenBao {
    container_name: String,
    port: u16,
    _tempdir: TempDir,
}

impl DockerOpenBao {
    fn spawn(label: &str, server_chain_pem: &str, server_key_pem: &str) -> anyhow::Result<Self> {
        if !docker_available() {
            anyhow::bail!("docker CLI not available on this host");
        }
        let tempdir = tempdir()?;
        let config_dir = tempdir.path().join("config");
        let tls_dir = tempdir.path().join("tls");
        fs::create_dir_all(&config_dir)?;
        fs::create_dir_all(&tls_dir)?;

        let cert_path = tls_dir.join("server.pem");
        let key_path = tls_dir.join("server-key.pem");
        fs::write(&cert_path, server_chain_pem)?;
        fs::write(&key_path, server_key_pem)?;
        // openbao runs as a non-root user inside the container; make the
        // TLS material world-readable so the container can load it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&cert_path, fs::Permissions::from_mode(0o644))?;
            fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))?;
        }

        let hcl = "storage \"inmem\" {}\n\
            listener \"tcp\" {\n  \
              address = \"0.0.0.0:8200\"\n  \
              tls_cert_file = \"/openbao/tls/server.pem\"\n  \
              tls_key_file = \"/openbao/tls/server-key.pem\"\n\
            }\n\
            disable_mlock = true\n\
            ui = false\n";
        let hcl_path = config_dir.join("openbao.hcl");
        fs::write(&hcl_path, hcl)?;

        // Retry loop handles ephemeral-port collisions between
        // `reserve_port()` dropping the listener and the `docker` child
        // re-binding the same address.
        let mut last_err: Option<String> = None;
        for attempt in 0..RESPONDER_BIND_ATTEMPTS {
            let port = reserve_port();
            let container_name = unique_container_name(label);
            let status = Command::new("docker")
                .args([
                    "run",
                    "-d",
                    "--rm",
                    "--name",
                    &container_name,
                    "-p",
                    &format!("127.0.0.1:{port}:8200"),
                    "-v",
                    &format!("{}:/openbao/config:ro", config_dir.display()),
                    "-v",
                    &format!("{}:/openbao/tls:ro", tls_dir.display()),
                    OPENBAO_IMAGE,
                    "server",
                    "-config=/openbao/config/openbao.hcl",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .output();
            match status {
                Ok(output) if output.status.success() => {
                    return Ok(Self {
                        container_name,
                        port,
                        _tempdir: tempdir,
                    });
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                    eprintln!("docker run attempt {} failed: {stderr}", attempt + 1);
                    last_err = Some(stderr);
                }
                Err(err) => {
                    last_err = Some(err.to_string());
                }
            }
        }
        anyhow::bail!(
            "failed to start openbao container after {RESPONDER_BIND_ATTEMPTS} attempts: \
             {last_err:?}"
        );
    }

    fn base_url(&self) -> String {
        format!("https://localhost:{}", self.port)
    }
}

impl Drop for DockerOpenBao {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["rm", "-f", &self.container_name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Polls `sys/seal-status` until the daemon accepts TLS connections.
async fn wait_for_openbao_tls(url: &str, ca_pem: &str) -> anyhow::Result<()> {
    let deadline = Instant::now() + OPENBAO_READY_TIMEOUT;
    let mut last_err: Option<String> = None;
    while Instant::now() < deadline {
        if let Ok(client) = OpenBaoClient::with_pem_trust(url, ca_pem, &[]) {
            match client.seal_status().await {
                Ok(_) => return Ok(()),
                Err(err) => last_err = Some(err.to_string()),
            }
        }
        sleep(OPENBAO_POLL_INTERVAL).await;
    }
    anyhow::bail!(
        "openbao TLS did not become reachable at {url} within {OPENBAO_READY_TIMEOUT:?}: \
         {last_err:?}"
    );
}

/// Materials produced by provisioning the daemon: a wrap token whose
/// unwrap yields a usable `secret_id`, plus the `role_id` the RN writes
/// onto disk before bootstrap runs.
struct ProvisionedOpenBao {
    role_id: String,
    wrap_token: String,
    wrap_expires_at: String,
    trust_kv_pem: String,
    trust_sha256: String,
}

/// Initialises, unseals, and provisions a real openbao daemon with the
/// KV paths and `AppRole` the RN bootstrap flow reads.  Returns the
/// materials needed to assemble a production-style `bootstrap.json`.
async fn provision_openbao(
    url: &str,
    ca_pem: &str,
    extra_trust_ca_pem: &str,
    step_ca_sha256: &str,
) -> anyhow::Result<ProvisionedOpenBao> {
    let mut client = OpenBaoClient::with_pem_trust(url, ca_pem, &[])?;

    if !client.is_initialized().await? {
        let init = client.init(1, 1).await?;
        let unseal_key = init
            .keys
            .first()
            .ok_or_else(|| anyhow::anyhow!("openbao init returned no unseal keys"))?;
        let status = client.unseal(unseal_key).await?;
        if status.sealed {
            anyhow::bail!("openbao remained sealed after unseal");
        }
        client.set_token(init.root_token);
    }

    client.ensure_kv_v2(KV_MOUNT).await?;
    client.ensure_approle_auth().await?;

    let policy_name = format!("bootroot-{SERVICE_NAME}");
    let policy = format!(
        "path \"{KV_MOUNT}/data/bootroot/services/{SERVICE_NAME}/*\" {{\n  \
         capabilities = [\"read\"]\n\
         }}\n"
    );
    client.write_policy(&policy_name, &policy).await?;

    client
        .create_approle(SERVICE_NAME, &[policy_name.as_str()], "1h", "1h", false)
        .await?;
    let role_id = client.read_role_id(SERVICE_NAME).await?;

    // Secret_id used to re-login on *subsequent* bootstraps — stored in
    // KV so `pull_secrets` finds it after the initial AppRole login.
    let future_secret_id = client
        .create_secret_id(SERVICE_NAME, &SecretIdOptions::default())
        .await?;

    // KV seeds for the service.
    client
        .write_kv(
            KV_MOUNT,
            &format!("bootroot/services/{SERVICE_NAME}/secret_id"),
            json!({ "secret_id": future_secret_id }),
        )
        .await?;
    client
        .write_kv(
            KV_MOUNT,
            &format!("bootroot/services/{SERVICE_NAME}/eab"),
            json!({ "kid": "tls-kid", "hmac": "tls-hmac" }),
        )
        .await?;
    client
        .write_kv(
            KV_MOUNT,
            &format!("bootroot/services/{SERVICE_NAME}/http_responder_hmac"),
            json!({ "hmac": HMAC_SECRET }),
        )
        .await?;
    let trust_kv_pem = format!("{ca_pem}{extra_trust_ca_pem}");
    client
        .write_kv(
            KV_MOUNT,
            &format!("bootroot/services/{SERVICE_NAME}/trust"),
            json!({
                "trusted_ca_sha256": [step_ca_sha256],
                "ca_bundle_pem": trust_kv_pem,
            }),
        )
        .await?;

    // Fresh secret_id wrapped for delivery in the bootstrap artifact.
    let wrap_info = client
        .create_secret_id_wrap_only(SERVICE_NAME, &SecretIdOptions::default(), WRAP_TTL)
        .await?;
    let wrap_expires_at = {
        use time::format_description::well_known::Rfc3339;
        use time::{Duration as TimeDuration, OffsetDateTime};
        OffsetDateTime::parse(&wrap_info.creation_time, &Rfc3339)
            .ok()
            .and_then(|created| {
                i64::try_from(wrap_info.ttl)
                    .ok()
                    .and_then(|secs| created.checked_add(TimeDuration::seconds(secs)))
            })
            .and_then(|dt| dt.format(&Rfc3339).ok())
            .unwrap_or_else(|| wrap_info.creation_time.clone())
    };

    Ok(ProvisionedOpenBao {
        role_id,
        wrap_token: wrap_info.token,
        wrap_expires_at,
        trust_kv_pem,
        trust_sha256: step_ca_sha256.to_string(),
    })
}

// ---------------------------------------------------------------------------
// Service-node / responder fixtures (shared shape with e2e_multi_host_tls.rs)
// ---------------------------------------------------------------------------

struct ServiceNode {
    _temp: TempDir,
    service_dir: PathBuf,
}

impl ServiceNode {
    fn prepare(role_id: &str) -> Self {
        let temp = tempdir().expect("create tempdir");
        let service_dir = temp.path().join("rn-node");
        fs::create_dir_all(
            service_dir
                .join("secrets")
                .join("services")
                .join(SERVICE_NAME),
        )
        .expect("create service secret dir");
        fs::create_dir_all(service_dir.join("certs")).expect("create certs dir");
        fs::create_dir_all(
            service_dir
                .join("secrets")
                .join("openbao")
                .join("services")
                .join(SERVICE_NAME),
        )
        .expect("create openbao agent dir");
        let role_id_path = service_dir
            .join("secrets")
            .join("services")
            .join(SERVICE_NAME)
            .join("role_id");
        fs::write(&role_id_path, role_id).expect("write role_id");
        Self {
            _temp: temp,
            service_dir,
        }
    }

    fn service_dir(&self) -> &Path {
        &self.service_dir
    }

    fn ca_bundle_path(&self) -> PathBuf {
        self.service_dir.join("certs").join("ca-bundle.pem")
    }
}

#[allow(clippy::too_many_arguments)] // mirrors the RemoteBootstrapArtifact shape
fn bootstrap_artifact(
    service_node: &ServiceNode,
    openbao_url: &str,
    ca_bundle_pem: &str,
    agent_responder_url: &str,
    wrap_token: &str,
    wrap_expires_at: &str,
) -> serde_json::Value {
    let service_secrets = service_node
        .service_dir()
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME);
    let openbao_agent_dir = service_node
        .service_dir()
        .join("secrets")
        .join("openbao")
        .join("services")
        .join(SERVICE_NAME);
    json!({
        "schema_version": 3,
        "openbao_url": openbao_url,
        "kv_mount": KV_MOUNT,
        "service_name": SERVICE_NAME,
        "role_id_path": service_secrets.join("role_id").to_string_lossy(),
        "secret_id_path": service_secrets.join("secret_id").to_string_lossy(),
        "eab_file_path": service_secrets.join("eab.json").to_string_lossy(),
        "agent_config_path": service_node.service_dir().join("agent.toml").to_string_lossy(),
        "ca_bundle_path": service_node.ca_bundle_path().to_string_lossy(),
        "ca_bundle_pem": ca_bundle_pem,
        "openbao_agent_config_path": openbao_agent_dir.join("agent.hcl").to_string_lossy(),
        "openbao_agent_template_path": openbao_agent_dir.join("agent.toml.ctmpl").to_string_lossy(),
        "openbao_agent_token_path": openbao_agent_dir.join("token").to_string_lossy(),
        "agent_email": "admin@example.com",
        "agent_server": "https://localhost:9000/acme/acme/directory",
        "agent_domain": DOMAIN,
        "agent_responder_url": agent_responder_url,
        "profile_hostname": HOSTNAME,
        "profile_instance_id": INSTANCE_ID,
        "profile_cert_path": service_node.service_dir().join("certs").join("edge-proxy.crt").to_string_lossy(),
        "profile_key_path": service_node.service_dir().join("certs").join("edge-proxy.key").to_string_lossy(),
        "wrap_token": wrap_token,
        "wrap_expires_at": wrap_expires_at,
    })
}

async fn run_remote_bootstrap(
    service_node: &ServiceNode,
    artifact_path: &Path,
    system_trust_pem_path: Option<&Path>,
) -> std::process::Output {
    let mut cmd = tokio::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"));
    cmd.current_dir(service_node.service_dir())
        .arg("bootstrap")
        .arg("--artifact")
        .arg(artifact_path);
    if let Some(path) = system_trust_pem_path {
        cmd.env("SSL_CERT_FILE", path);
        cmd.env("SSL_CERT_DIR", "/var/empty");
    }
    cmd.output().await.expect("run bootroot-remote")
}

struct ResponderProcess {
    child: Child,
}

impl ResponderProcess {
    fn spawn(config_path: &Path) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_bootroot-http01-responder"))
            .args(["--config", config_path.to_string_lossy().as_ref()])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bootroot-http01-responder");
        Self { child }
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().expect("poll responder")
    }

    fn take_stderr(&mut self) -> String {
        let Some(mut stderr) = self.child.stderr.take() else {
            return String::new();
        };
        let mut output = String::new();
        let _ = stderr.read_to_string(&mut output);
        output
    }
}

impl Drop for ResponderProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_responder_config(
    config_path: &Path,
    listen_addr: &str,
    admin_addr: &str,
    cert_path: &Path,
    key_path: &Path,
) {
    let contents = format!(
        "listen_addr = \"{listen_addr}\"\n\
         admin_addr = \"{admin_addr}\"\n\
         hmac_secret = \"{HMAC_SECRET}\"\n\
         token_ttl_secs = 300\n\
         max_token_ttl_secs = 900\n\
         cleanup_interval_secs = 30\n\
         max_skew_secs = 60\n\
         admin_rate_limit_requests = 300\n\
         admin_rate_limit_window_secs = 60\n\
         admin_body_limit_bytes = 8192\n\
         tls_cert_path = \"{cert}\"\n\
         tls_key_path = \"{key}\"\n",
        cert = cert_path.to_string_lossy(),
        key = key_path.to_string_lossy(),
    );
    fs::write(config_path, contents).expect("write responder config");
}

enum ReadyOutcome {
    Ready,
    BindConflict(String),
    Failure(String),
}

fn is_bind_conflict(stderr: &str) -> bool {
    stderr.contains("Address already in use")
        || stderr.contains("address in use")
        || stderr.contains("EADDRINUSE")
        || stderr.contains("os error 48")
        || stderr.contains("os error 98")
}

async fn wait_for_tls_responder_outcome(
    responder: &mut ResponderProcess,
    admin_base_url: &str,
    probe: &reqwest::Client,
) -> ReadyOutcome {
    for _ in 0..STARTUP_RETRIES {
        if let Some(status) = responder.try_wait() {
            let stderr = responder.take_stderr();
            if is_bind_conflict(&stderr) {
                return ReadyOutcome::BindConflict(stderr);
            }
            return ReadyOutcome::Failure(format!(
                "responder exited early with {status}: {stderr}"
            ));
        }
        if probe
            .get(format!("{admin_base_url}/admin/http01"))
            .send()
            .await
            .is_ok()
        {
            return ReadyOutcome::Ready;
        }
        sleep(STARTUP_DELAY).await;
    }
    ReadyOutcome::Failure("TLS responder did not become ready".to_string())
}

async fn spawn_responder_tls_retrying(
    responder_temp: &Path,
    cert_path: &Path,
    key_path: &Path,
    probe_root_pem: &str,
) -> (ResponderProcess, String, String, String) {
    let config_path = responder_temp.join("responder.toml");
    let mut last_failure = String::new();
    for attempt in 0..RESPONDER_BIND_ATTEMPTS {
        let listen_addr = reserve_socket_addr();
        let admin_addr = reserve_socket_addr();
        write_responder_config(&config_path, &listen_addr, &admin_addr, cert_path, key_path);
        let mut responder = ResponderProcess::spawn(&config_path);
        let admin_port: u16 = admin_addr
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .expect("parse admin port");
        let admin_base_url = format!("https://localhost:{admin_port}");
        let probe = build_probe_client(probe_root_pem, admin_port);
        match wait_for_tls_responder_outcome(&mut responder, &admin_base_url, &probe).await {
            ReadyOutcome::Ready => return (responder, listen_addr, admin_addr, admin_base_url),
            ReadyOutcome::BindConflict(stderr) => {
                eprintln!(
                    "responder bind conflict on attempt {} of {RESPONDER_BIND_ATTEMPTS}: {stderr}",
                    attempt + 1,
                );
                last_failure = stderr;
            }
            ReadyOutcome::Failure(msg) => panic!("{msg}"),
        }
    }
    panic!(
        "responder failed to bind a reserved port after {RESPONDER_BIND_ATTEMPTS} attempts: \
         {last_failure}"
    );
}

/// Builds a reqwest client that trusts only `root_pem` and routes
/// `localhost` to the given admin port so the server cert's SAN matches.
fn build_probe_client(root_pem: &str, admin_port: u16) -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut root_store = rustls::RootCertStore::empty();
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(root_pem.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .expect("parse probe root PEM");
    for cert in certs {
        root_store.add(cert).expect("add root cert");
    }
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .resolve(
            "localhost",
            format!("127.0.0.1:{admin_port}")
                .parse()
                .expect("parse probe socket addr"),
        )
        .build()
        .expect("build probe client")
}

/// Positive proof that a server on `127.0.0.1:port` presents a chain
/// that validates under `trusted_pem` alone.
async fn assert_cert_chain_valid_under_trust(trusted_pem: &str, port: u16) {
    let client = build_probe_client(trusted_pem, port);
    let url = format!("https://localhost:{port}/v1/sys/health");
    let response = client
        .get(&url)
        .send()
        .await
        .expect("TLS handshake must succeed when system CA is trusted");
    let _ = response.status();
}

static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

fn load_settings_from_bootstrap_output(agent_config_path: &Path) -> Settings {
    let _guard = ENV_LOCK.lock().expect("env lock not poisoned");
    let saved: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(k, _)| k.to_str().is_some_and(|key| key.starts_with("BOOTROOT_")))
        .collect();
    for (key, _) in &saved {
        // SAFETY: tests hold ENV_LOCK while mutating process environment.
        unsafe {
            std::env::remove_var(key);
        }
    }
    let result = Settings::new(Some(agent_config_path.to_path_buf()));
    for (key, value) in &saved {
        // SAFETY: tests hold ENV_LOCK while mutating process environment.
        unsafe {
            std::env::set_var(key, value);
        }
    }
    let mut settings = result.expect("load agent.toml");
    settings.acme.http_responder_token_ttl_secs = TEST_TTL_SECS;
    settings
}

async fn register_http01_via_settings(settings: &Settings) -> anyhow::Result<()> {
    register_http01_token(settings, "e2e-real-token", "e2e-real-token.key").await
}

async fn register_http01_with_trust(
    admin_base_url: &str,
    ca_pem: &str,
    ca_pins: &[String],
) -> anyhow::Result<()> {
    let trust = ResponderTrust { ca_pem, ca_pins };
    register_http01_token_with(
        admin_base_url,
        HMAC_SECRET,
        5,
        "e2e-real-token",
        "e2e-real-token.key",
        TEST_TTL_SECS,
        Some(&trust),
    )
    .await
}

async fn verify_registered_token_served(listen_addr: &str) -> String {
    let url = format!("http://{listen_addr}/.well-known/acme-challenge/e2e-real-token");
    for _ in 0..STARTUP_RETRIES {
        if let Ok(resp) = reqwest::get(&url).await
            && resp.status().is_success()
        {
            return resp.text().await.unwrap_or_default();
        }
        sleep(STARTUP_DELAY).await;
    }
    panic!("challenge response never became available at {url}");
}

/// Skip a test when docker is unavailable on the host.  Emits a visible
/// message so CI logs surface the skip reason.
fn skip_without_docker(test_name: &str) -> bool {
    if docker_available() {
        return false;
    }
    eprintln!(
        "[{test_name}] SKIP: docker CLI not available; this test requires docker + openbao image"
    );
    true
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Real-daemon happy path.  Exercises the entire RN → CN control-plane
/// flow: a production-style `bootstrap.json` artifact carrying a wrap
/// token is handed to `bootroot-remote bootstrap`, which unwraps it over
/// TLS against a fully-provisioned `openbao` daemon, logs in, pulls KV,
/// persists the trust material, and — via `register_http01_token` from
/// the loaded `agent.toml` — drives an HTTP-01 admin registration.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_real_daemon_multi_host_tls_happy_path() {
    if skip_without_docker("test_real_daemon_multi_host_tls_happy_path") {
        return;
    }

    let step_ca = TestCa::generate("Bootroot Step CA");
    let extra_trust_ca = TestCa::generate("Extra Trust Bundle CA");

    let openbao_cert = step_ca.sign_server_cert(&["localhost", "127.0.0.1"]);
    let bao = DockerOpenBao::spawn(
        "happy",
        &server_chain_pem(&openbao_cert),
        &openbao_cert.key_pem,
    )
    .expect("spawn openbao docker container");
    let openbao_url = bao.base_url();
    wait_for_openbao_tls(&openbao_url, &step_ca.pem)
        .await
        .expect("openbao TLS ready");

    let provisioned = provision_openbao(
        &openbao_url,
        &step_ca.pem,
        &extra_trust_ca.pem,
        &step_ca.sha256_fingerprint(),
    )
    .await
    .expect("provision openbao");

    // Responder: present cert signed by step-ca (the artifact anchor).
    let responder_temp = tempdir().expect("responder tempdir");
    let responder_cert = step_ca.sign_server_cert(&["localhost"]);
    let responder_cert_path = responder_temp.path().join("responder.cert.pem");
    let responder_key_path = responder_temp.path().join("responder.key.pem");
    fs::write(&responder_cert_path, server_chain_pem(&responder_cert))
        .expect("write responder cert");
    fs::write(&responder_key_path, &responder_cert.key_pem).expect("write responder key");

    let (_responder, listen_addr, _admin_addr, admin_base_url) = spawn_responder_tls_retrying(
        responder_temp.path(),
        &responder_cert_path,
        &responder_key_path,
        &step_ca.pem,
    )
    .await;

    let service_node = ServiceNode::prepare(&provisioned.role_id);
    let artifact = bootstrap_artifact(
        &service_node,
        &openbao_url,
        &step_ca.pem,
        &admin_base_url,
        &provisioned.wrap_token,
        &provisioned.wrap_expires_at,
    );

    // Acceptance assertion (a): artifact contains wrap_token / expiry.
    let artifact_str = serde_json::to_string_pretty(&artifact).expect("serialize artifact");
    assert!(
        artifact_str.contains("\"wrap_token\""),
        "artifact must contain wrap_token"
    );
    assert!(
        artifact_str.contains("\"wrap_expires_at\""),
        "artifact must contain wrap_expires_at"
    );
    let artifact_path = service_node.service_dir().join("bootstrap.json");
    fs::write(&artifact_path, &artifact_str).expect("write artifact");

    // Acceptance assertion (b): secret_id only materialises on RN *after*
    // bootstrap runs (mirrors e2e_remote_happy_path.rs:691-693).
    let secret_id_path = service_node
        .service_dir()
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("secret_id");
    assert!(
        !secret_id_path.exists(),
        "secret_id must not exist before bootstrap runs"
    );

    let output = run_remote_bootstrap(&service_node, &artifact_path, None).await;
    assert!(
        output.status.success(),
        "bootstrap must succeed over TLS with the artifact CA: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        secret_id_path.exists(),
        "secret_id must be written after unwrap"
    );
    let written_secret = fs::read_to_string(&secret_id_path).expect("read secret_id");
    assert!(
        !written_secret.trim().is_empty(),
        "unwrapped secret_id must be non-empty"
    );

    // Verify that bootstrap persisted the TLS-protected /trust read.
    let ca_bundle_on_disk = service_node.ca_bundle_path();
    let persisted_bundle =
        fs::read_to_string(&ca_bundle_on_disk).expect("read persisted CA bundle");
    assert_eq!(
        persisted_bundle, provisioned.trust_kv_pem,
        "bootstrap must persist the OpenBao /trust PEM verbatim"
    );
    assert_ne!(
        persisted_bundle, step_ca.pem,
        "persisted bundle must differ from the artifact seed"
    );
    let agent_toml_path = service_node.service_dir().join("agent.toml");
    let persisted_agent_toml =
        fs::read_to_string(&agent_toml_path).expect("read persisted agent.toml");
    assert!(
        persisted_agent_toml.contains(&provisioned.trust_sha256),
        "bootstrap must persist the OpenBao-supplied SHA-256 pin in agent.toml"
    );

    let settings = load_settings_from_bootstrap_output(&agent_toml_path);
    assert_eq!(
        settings.acme.http_responder_url, admin_base_url,
        "agent.toml must carry the bootstrap-supplied responder URL"
    );
    assert_eq!(
        settings.acme.http_responder_hmac, HMAC_SECRET,
        "agent.toml must carry the bootstrap-supplied responder HMAC"
    );
    assert_eq!(
        settings.trust.ca_bundle_path.as_deref(),
        Some(ca_bundle_on_disk.as_path()),
        "agent.toml must point trust.ca_bundle_path at the bootstrap-written bundle"
    );
    assert_eq!(
        settings.trust.trusted_ca_sha256,
        vec![provisioned.trust_sha256.clone()],
        "agent.toml must carry the OpenBao-supplied SHA-256 pin"
    );

    register_http01_via_settings(&settings)
        .await
        .expect("register http01 token over TLS via agent.toml the bootstrap produced");

    let body = verify_registered_token_served(&listen_addr).await;
    assert_eq!(body, "e2e-real-token.key");
}

/// Real-daemon system-trust rejection.  Reuses the same provisioning
/// path as the happy case — the openbao daemon is fully initialised,
/// unsealed, `AppRole`-configured, KV-seeded, and hands back a real
/// wrap token packaged into `bootstrap.json`.  The ONLY variation is
/// the presented certificate: both the daemon and the responder serve
/// certs signed by `system_ca`, which is installed into the RN
/// process's `SSL_CERT_FILE` / `SSL_CERT_DIR`, while the artifact
/// anchor is `step_ca`.  A positive rustls probe rooted at `system_ca`
/// confirms the cert is chain-valid under the "system-trusted" root;
/// bootstrap — which only consults the artifact anchor — must reject
/// the handshake before ever unwrapping the token.  The http01 admin
/// registration, invoked with the artifact anchor alone, must also
/// reject against the same system-trusted chain.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_real_daemon_multi_host_tls_rejects_system_trusted_non_artifact_ca() {
    if skip_without_docker("test_real_daemon_multi_host_tls_rejects_system_trusted_non_artifact_ca")
    {
        return;
    }

    let step_ca = TestCa::generate("Bootroot Step CA");
    let system_ca = TestCa::generate("System Trusted CA");

    // Openbao cert signed by system_ca; the artifact anchor is step_ca.
    let openbao_cert = system_ca.sign_server_cert(&["localhost", "127.0.0.1"]);
    let bao = DockerOpenBao::spawn(
        "system-trust",
        &server_chain_pem(&openbao_cert),
        &openbao_cert.key_pem,
    )
    .expect("spawn openbao docker container");
    let openbao_url = bao.base_url();
    wait_for_openbao_tls(&openbao_url, &system_ca.pem)
        .await
        .expect("openbao TLS ready under system CA trust");

    // Fully provision the real daemon.  The provisioning client trusts
    // system_ca (the daemon's actual CA), so init/unseal/AppRole/KV
    // all succeed and a real wrap token is issued — identical shape to
    // the happy-path fixture.
    let provisioned = provision_openbao(
        &openbao_url,
        &system_ca.pem,
        &step_ca.pem,
        &system_ca.sha256_fingerprint(),
    )
    .await
    .expect("provision openbao");

    // Responder cert also signed by system_ca; both CN halves are valid
    // under the "system-trusted" root but not under the artifact anchor.
    let responder_temp = tempdir().expect("responder tempdir");
    let responder_cert = system_ca.sign_server_cert(&["localhost"]);
    let responder_cert_path = responder_temp.path().join("responder.cert.pem");
    let responder_key_path = responder_temp.path().join("responder.key.pem");
    fs::write(&responder_cert_path, server_chain_pem(&responder_cert))
        .expect("write responder cert");
    fs::write(&responder_key_path, &responder_cert.key_pem).expect("write responder key");

    let (_responder, _listen_addr, _admin_addr, admin_base_url) = spawn_responder_tls_retrying(
        responder_temp.path(),
        &responder_cert_path,
        &responder_key_path,
        &system_ca.pem,
    )
    .await;

    let service_node = ServiceNode::prepare(&provisioned.role_id);
    let system_ca_pem_path = service_node.service_dir().join("system-ca.pem");
    fs::write(&system_ca_pem_path, &system_ca.pem).expect("write system CA");

    // Production-shaped artifact carrying the real wrap token from the
    // provisioned daemon; the trust anchor is step_ca (NOT the daemon's
    // actual CA), so the RN's unwrap TLS handshake must reject.
    let artifact = bootstrap_artifact(
        &service_node,
        &openbao_url,
        &step_ca.pem,
        &admin_base_url,
        &provisioned.wrap_token,
        &provisioned.wrap_expires_at,
    );
    let artifact_str = serde_json::to_string_pretty(&artifact).expect("serialize artifact");
    assert!(
        artifact_str.contains("\"wrap_token\""),
        "artifact must contain wrap_token"
    );
    assert!(
        artifact_str.contains("\"wrap_expires_at\""),
        "artifact must contain wrap_expires_at"
    );
    let artifact_path = service_node.service_dir().join("bootstrap.json");
    fs::write(&artifact_path, &artifact_str).expect("write artifact");

    // secret_id must not exist before bootstrap; since bootstrap will
    // reject the TLS handshake, it must ALSO not exist after.
    let secret_id_path = service_node
        .service_dir()
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("secret_id");
    assert!(
        !secret_id_path.exists(),
        "secret_id must not exist before bootstrap runs"
    );

    // Positive half: a rustls client rooted at system_ca completes a
    // real TLS handshake against the same daemon, establishing that
    // the cert IS chain-valid under the "system-trusted" CA.
    assert_cert_chain_valid_under_trust(&system_ca.pem, bao.port).await;

    let output =
        run_remote_bootstrap(&service_node, &artifact_path, Some(&system_ca_pem_path)).await;
    assert!(
        !output.status.success(),
        "bootstrap must reject a server cert signed only by the system CA"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("TLS")
            || stderr.contains("certificate")
            || stderr.contains("invalid peer certificate")
            || stderr.contains("unknown issuer")
            || stderr.contains("unwrap")
            || stderr.contains("request failed"),
        "expected TLS rejection, got: {stderr}"
    );
    assert!(
        !secret_id_path.exists(),
        "secret_id must not materialise when bootstrap rejects the handshake"
    );

    // http01 control-plane path: invoked with the artifact anchor alone
    // against the system-trusted responder chain.  Handshake must reject
    // for the same reason — refusal to consult OS roots.
    let err = register_http01_with_trust(&admin_base_url, &step_ca.pem, &[])
        .await
        .expect_err("http01 registration must reject the system-trusted cert");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to register HTTP-01 token") || msg.contains("certificate"),
        "expected TLS failure from responder client, got: {msg}"
    );
}

/// Real-daemon pin rejection.  Reuses the same provisioning /
/// bootstrap-artifact path as the happy case: the openbao daemon is
/// fully initialised with a step-ca-signed cert and the `/trust` KV
/// is seeded with a combined step-ca + system-ca bundle plus a
/// SHA-256 pin on step-ca.  The RN runs `bootroot-remote bootstrap`,
/// which unwraps over TLS, logs in, pulls per-service KV including
/// `/trust`, and persists the combined bundle and pin into
/// `agent.toml`.  The responder — spawned after bootstrap, pointed
/// at by the artifact — presents a `system_ca`-signed cert.  When
/// http01 registration is driven from the bootstrap-produced
/// `agent.toml`, the chain validates under the combined bundle but
/// the pin on step-ca rejects.  Removing the pin accepts the same
/// chain, isolating the rejection to the pin.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_real_daemon_multi_host_tls_pin_rejects_non_pinned_chain() {
    if skip_without_docker("test_real_daemon_multi_host_tls_pin_rejects_non_pinned_chain") {
        return;
    }

    let step_ca = TestCa::generate("Bootroot Step CA");
    let system_ca = TestCa::generate("System Trusted CA");

    // Openbao presents a step-ca-signed cert so bootstrap can unwrap
    // and log in successfully; the artifact anchor is also step-ca.
    let openbao_cert = step_ca.sign_server_cert(&["localhost", "127.0.0.1"]);
    let bao = DockerOpenBao::spawn(
        "pin",
        &server_chain_pem(&openbao_cert),
        &openbao_cert.key_pem,
    )
    .expect("spawn openbao docker container");
    let openbao_url = bao.base_url();
    wait_for_openbao_tls(&openbao_url, &step_ca.pem)
        .await
        .expect("openbao TLS ready");

    // Provision the real daemon.  `/trust` carries the combined
    // step-ca + system-ca bundle and a pin on step-ca.  Bootstrap
    // will persist both into agent.toml.
    let provisioned = provision_openbao(
        &openbao_url,
        &step_ca.pem,
        &system_ca.pem,
        &step_ca.sha256_fingerprint(),
    )
    .await
    .expect("provision openbao");

    // Responder presents a system_ca-signed cert.  The probe trusts
    // system_ca so readiness succeeds (proving chain validity).
    let responder_temp = tempdir().expect("responder tempdir");
    let responder_cert = system_ca.sign_server_cert(&["localhost"]);
    let responder_cert_path = responder_temp.path().join("responder.cert.pem");
    let responder_key_path = responder_temp.path().join("responder.key.pem");
    fs::write(&responder_cert_path, server_chain_pem(&responder_cert))
        .expect("write responder cert");
    fs::write(&responder_key_path, &responder_cert.key_pem).expect("write responder key");

    let (_responder, _listen_addr, _admin_addr, admin_base_url) = spawn_responder_tls_retrying(
        responder_temp.path(),
        &responder_cert_path,
        &responder_key_path,
        &system_ca.pem,
    )
    .await;

    let service_node = ServiceNode::prepare(&provisioned.role_id);
    let artifact = bootstrap_artifact(
        &service_node,
        &openbao_url,
        &step_ca.pem,
        &admin_base_url,
        &provisioned.wrap_token,
        &provisioned.wrap_expires_at,
    );
    let artifact_str = serde_json::to_string_pretty(&artifact).expect("serialize artifact");
    let artifact_path = service_node.service_dir().join("bootstrap.json");
    fs::write(&artifact_path, &artifact_str).expect("write artifact");

    let secret_id_path = service_node
        .service_dir()
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("secret_id");
    assert!(
        !secret_id_path.exists(),
        "secret_id must not exist before bootstrap runs"
    );

    // Bootstrap must succeed: daemon cert is step-ca-signed, matching
    // the artifact anchor.  The combined trust bundle and the step-ca
    // pin land in agent.toml via the `/trust` KV read.
    let output = run_remote_bootstrap(&service_node, &artifact_path, None).await;
    assert!(
        output.status.success(),
        "bootstrap must succeed when daemon cert matches the artifact anchor: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        secret_id_path.exists(),
        "secret_id must be written after unwrap"
    );

    let agent_toml_path = service_node.service_dir().join("agent.toml");
    let settings = load_settings_from_bootstrap_output(&agent_toml_path);
    assert_eq!(
        settings.trust.trusted_ca_sha256,
        vec![provisioned.trust_sha256.clone()],
        "bootstrap must persist the step-ca pin from /trust"
    );
    let persisted_bundle =
        fs::read_to_string(service_node.ca_bundle_path()).expect("read persisted CA bundle");
    assert_eq!(
        persisted_bundle, provisioned.trust_kv_pem,
        "persisted trust bundle must combine step-ca and system-ca from /trust"
    );

    // http01 registration driven by the bootstrap-produced agent.toml:
    // the chain validates under the combined bundle, but the pin on
    // step-ca rejects the system-ca-signed responder cert.
    let err = register_http01_via_settings(&settings)
        .await
        .expect_err("pin mismatch must reject even when chain validates");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to register HTTP-01 token") || msg.contains("certificate"),
        "expected TLS failure from responder client, got: {msg}"
    );

    // Sanity check: without the pin, the same chain is accepted.
    register_http01_with_trust(&admin_base_url, &provisioned.trust_kv_pem, &[])
        .await
        .expect("without a pin, a chain-valid cert is accepted");
}
