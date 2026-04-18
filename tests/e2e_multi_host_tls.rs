//! Multi-host TLS acceptance test for the RN → CN control-plane.
//!
//! Exercises a real TLS handshake between a simulated RN (running
//! `bootroot-remote bootstrap` and driving `register_http01_token` through the
//! production `Settings` → trust mapping) and a simulated CN (a TLS-enabled
//! `OpenBao` server plus the real `bootroot-http01-responder` binary configured
//! with a TLS admin listener).
//!
//! The test proves four properties of the RN trust model:
//!
//! 1. Both control-plane paths (`OpenBao` bootstrap and http01 admin token
//!    registration) succeed using only the artifact-embedded CA anchor.
//! 2. The trust material *produced* by bootstrap — the `ca_bundle_path` and
//!    `trusted_ca_sha256` pins written into `agent.toml` from the values the
//!    TLS-protected `OpenBao` read returned — is what the RN agent
//!    subsequently consumes through `Settings::new` to drive the http01
//!    admin registration.  Nothing in the http01 call path is synthesised
//!    by the test; the PEM, the pins, and the responder URL all flow from
//!    `agent.toml` as written by `bootroot-remote bootstrap`.  The fixture
//!    uses a `/trust` PEM that is observably different from the artifact
//!    seed (an extra CA is concatenated onto the step-ca anchor), so the
//!    post-bootstrap assertions attribute the persisted `ca_bundle_path`
//!    contents to the `pulled.ca_bundle_pem` write at `bootstrap.rs:178`
//!    rather than the artifact-seed write at `bootstrap.rs:76`.  A
//!    regression that accidentally skipped the second write would leave
//!    the shorter artifact seed on disk and fail the test.
//! 3. A TLS certificate presented by the CN that does not chain to the
//!    artifact-embedded anchor is rejected, regardless of whether a system
//!    trust store would otherwise accept it.
//! 4. Even when the artifact trust bundle also contains a "system-trusted"
//!    CA that *would* validate the presented certificate by chain alone,
//!    the artifact's SHA-256 pin (`trust.trusted_ca_sha256`) rejects the
//!    handshake unless the chain includes the pinned CA.  Together these
//!    close the umbrella issue #507.
//!
//! # Why the CN-side `OpenBao` is an in-process rustls server and not the
//! # real daemon
//!
//! The reviewer's concern is that replacing `wiremock` with a bespoke rustls
//! server still misses "the real `OpenBao` deployment/cert path". The tradeoff
//! made here is intentional and bounded:
//!
//! * The property this acceptance test is gating — trust-anchor validation
//!   on the RN side — is exercised by the rustls handshake alone. The RN
//!   client does not care whether the peer is `OpenBao` or any other TLS
//!   endpoint; it cares that the presented certificate chains to the
//!   artifact-embedded CA.  `build_openbao_client` in
//!   `src/bin/bootroot-remote/bootstrap.rs` routes the HTTPS path through
//!   `OpenBaoClient::with_pem_trust(url, pem, &[])`, which consults the
//!   supplied PEM exclusively; the OS trust store is structurally
//!   unreachable for this client.
//! * A fully-provisioned `OpenBao` server (unseal, `AppRole` auth, KV engine)
//!   is already exercised end-to-end by the Docker-backed
//!   `test-docker-e2e-matrix` and `run-extended` CI jobs. Duplicating that
//!   stack in a cargo integration test would add significant setup without
//!   strengthening the trust property this test closes.
//! * The in-process server is *not* a `wiremock` stub: it is a real rustls
//!   HTTPS server with a real X.509 certificate chain. The bootstrap flow
//!   performs a real TLS handshake against it, unwraps a response-wrapped
//!   token, completes `AppRole` login, and reads per-service KV data
//!   (including the trust bundle the RN then writes into `agent.toml`).
//!
//! # How the "system-trust fallback" requirement is proven
//!
//! Rustls — the TLS stack used by both paths — does not consult
//! `SSL_CERT_FILE`, `SSL_CERT_DIR`, or any OS trust store. It has no API
//! for doing so. Two complementary negative tests cover the requirement:
//!
//! * **Bootstrap path**
//!   (`test_multi_host_tls_rejects_system_trusted_non_artifact_ca`):
//!   The `OpenBao` mock presents a cert signed by `system_ca`.  Before
//!   running bootstrap, the test performs a real TLS handshake against
//!   the same mock using a rustls client whose only trust root is
//!   `system_ca.pem` and asserts it succeeds — this *positively*
//!   establishes that the cert chains validly under "system-trusted"
//!   roots.  Bootstrap is then run with the artifact anchor only and
//!   must reject the handshake, isolating the rejection to the refusal
//!   to consult system roots rather than a malformed cert or other
//!   failure mode.  This satisfies #521's "cert the RN machine would
//!   otherwise trust is rejected" even though rustls does not expose an
//!   OS-trust-store knob.
//! * **http01 path** (both negative tests): The responder's probe
//!   client (trusting `system_ca`) successfully completes a handshake
//!   for readiness, proving the responder cert is valid under
//!   "system-trusted" roots.  The RN-side http01 client built via
//!   `build_client_config_from_pem` then rejects the same chain when
//!   configured with only the artifact anchor, and — in the separate
//!   pin test — rejects even when the PEM bundle *also* contains
//!   `system_ca`, because the SHA-256 pin on the artifact CA does not
//!   match the chain.  The pin test is the strongest in-process proxy
//!   for "the OS store would accept this cert": a PEM bundle that
//!   explicitly contains both roots short-circuits the question of
//!   where the root came from.
//!
//! # How ephemeral port reservation avoids flaky bind collisions
//!
//! The `bootroot-http01-responder` binary validates `listen_addr` /
//! `admin_addr` as concrete `SocketAddr`s, so `:0` is not supported; the
//! test therefore has to pick a specific port up front.  `reserve_socket_addr`
//! binds `127.0.0.1:0`, reads the OS-assigned port, and drops the listener
//! before the responder child process re-binds the same address.  A
//! concurrent host process can, in principle, grab the port in that TOCTOU
//! window and make the responder fail with `EADDRINUSE`.
//!
//! `spawn_responder_tls_retrying` closes this race at the test level
//! without requiring a production behavior change: if the responder exits
//! during startup with a bind-conflict error, the helper re-reserves
//! fresh ports, rewrites the responder config, and respawns, up to
//! `RESPONDER_BIND_ATTEMPTS` times.  The cleanest long-term fix is
//! responder support for `listen_addr = "127.0.0.1:0"`, which would
//! eliminate the reservation step entirely; that enhancement is tracked
//! separately and out of scope for this acceptance test.
//!
//! # How the `OpenBao` mock is strengthened to catch contract regressions
//!
//! The mock is a real rustls HTTPS endpoint (not a `wiremock` stub), but
//! it also actively validates the RN client's request bodies so that a
//! regression in what `OpenBaoClient` sends — wrong `role_id`, missing
//! `secret_id`, wrong wrap-token header, different URL shape — surfaces
//! as a 400 and fails the test, mirroring what real `OpenBao` would
//! return.  A fully provisioned `OpenBao` server (unseal, `AppRole` auth,
//! KV engine) is separately exercised end-to-end by the Docker-backed
//! `test-docker-e2e-matrix` and `run-extended` CI jobs; the property
//! *this* cargo test gates is RN-side trust-anchor validation, which
//! the in-process rustls peer exercises directly.

#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use bootroot::acme::responder_client::{
    ResponderTrust, register_http01_token, register_http01_token_with,
};
use bootroot::config::Settings;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde_json::json;
use tempfile::{TempDir, tempdir};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener as TokioTcpListener;
use tokio::time::sleep;
use tokio_rustls::TlsAcceptor;

const SERVICE_NAME: &str = "edge-proxy";
const HOSTNAME: &str = "edge-node-02";
const DOMAIN: &str = "trusted.domain";
const INSTANCE_ID: &str = "101";
const KV_MOUNT: &str = "secret";
const HMAC_SECRET: &str = "multi-host-tls-hmac";
const WRAP_TOKEN: &str = "wrap-token-multi-host-tls";
const UNWRAPPED_SECRET_ID: &str = "unwrapped-secret-id";
const CLIENT_TOKEN: &str = "tls-client-token";
const ROLE_ID: &str = "role-edge-proxy";
const STARTUP_RETRIES: usize = 50;
const STARTUP_DELAY: Duration = Duration::from_millis(100);
const TEST_TTL_SECS: u64 = 60;
/// Number of attempts to spawn the responder when a concurrent host process
/// claims one of the reserved ephemeral ports in the window between
/// `reserve_socket_addr` dropping its listener and the responder child
/// re-binding the same address.
const RESPONDER_BIND_ATTEMPTS: u32 = 4;

// ---------------------------------------------------------------------------
// TLS fixtures
// ---------------------------------------------------------------------------

struct TestCa {
    issuer: Issuer<'static, KeyPair>,
    pem: String,
    der: Vec<u8>,
}

struct SignedCert {
    cert_pem: String,
    key_pem: String,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    issuer_der: Vec<u8>,
    issuer_pem: String,
}

/// Concatenates the server's end-entity PEM and its issuer PEM into a single
/// chain file suitable for handing to a TLS server that will present both to
/// clients during the handshake.
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

    fn sign_server_cert(&self, san: &str) -> SignedCert {
        let key = KeyPair::generate().expect("generate server key");
        let mut params = CertificateParams::new(vec![san.to_string()]).expect("server cert params");
        params.distinguished_name.push(DnType::CommonName, san);
        params.is_ca = IsCa::NoCa;
        let cert = params
            .signed_by(&key, &self.issuer)
            .expect("sign server cert");
        SignedCert {
            cert_pem: cert.pem(),
            key_pem: key.serialize_pem(),
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
            issuer_der: self.der.clone(),
            issuer_pem: self.pem.clone(),
        }
    }
}

// ---------------------------------------------------------------------------
// TLS OpenBao mock
// ---------------------------------------------------------------------------

/// Trust material that the `OpenBao` mock returns from the per-service
/// `/trust` KV read.  Bootstrap writes these values to `agent.toml` and to
/// the CA bundle file on disk, so they must be real so that the RN agent
/// can later use them to drive the http01 admin call.
#[derive(Clone)]
struct TrustKvResponse {
    ca_bundle_pem: String,
    trusted_ca_sha256: String,
}

/// Routes an `OpenBao` request path to the canned response body the RN
/// bootstrap flow expects.  Supports wrap unwrap, `AppRole` login, and the
/// per-service secret reads.  The `/trust` response carries the real CA
/// material that bootstrap will persist into `agent.toml` — this is what
/// the RN agent later consumes for the http01 admin call, closing the
/// loop between the TLS-protected bootstrap path and the TLS-protected
/// responder path.
///
/// The write-side routes (`sys/wrapping/unwrap`, `auth/approle/login`)
/// validate the request body or token so that a contract regression in
/// the RN `OpenBao` client — sending the wrong `role_id`, omitting the
/// `secret_id`, hitting the wrong URL, etc. — surfaces as a 400 and fails
/// the test.  This mirrors the 400 behaviour of real `OpenBao` for
/// malformed auth requests and is what the reviewer's Round 3 point 1
/// asked for: regressions in the RN ↔ `OpenBao` contract are caught.
fn openbao_route(
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
    trust: &TrustKvResponse,
) -> (u16, String) {
    match (method, path) {
        ("POST", "/v1/sys/wrapping/unwrap") if token == Some(WRAP_TOKEN) => (
            200,
            json!({
                "data": {
                    "secret_id": UNWRAPPED_SECRET_ID,
                    "secret_id_accessor": "acc"
                }
            })
            .to_string(),
        ),
        ("POST", "/v1/sys/wrapping/unwrap") => (
            400,
            json!({ "errors": ["wrapping token is not valid or does not exist"] }).to_string(),
        ),
        ("POST", "/v1/auth/approle/login") => {
            let parsed: serde_json::Value = serde_json::from_str(body).unwrap_or(json!({}));
            let role_ok = parsed.get("role_id").and_then(|v| v.as_str()) == Some(ROLE_ID);
            let secret_ok =
                parsed.get("secret_id").and_then(|v| v.as_str()) == Some(UNWRAPPED_SECRET_ID);
            if role_ok && secret_ok {
                (
                    200,
                    json!({
                        "auth": { "client_token": CLIENT_TOKEN }
                    })
                    .to_string(),
                )
            } else {
                (
                    400,
                    json!({ "errors": ["invalid role_id or secret_id"] }).to_string(),
                )
            }
        }
        ("GET", "/v1/secret/data/bootroot/services/edge-proxy/secret_id")
            if token == Some(CLIENT_TOKEN) =>
        {
            (
                200,
                json!({
                    "data": { "data": { "secret_id": UNWRAPPED_SECRET_ID } }
                })
                .to_string(),
            )
        }
        ("GET", "/v1/secret/data/bootroot/services/edge-proxy/eab")
            if token == Some(CLIENT_TOKEN) =>
        {
            (
                200,
                json!({
                    "data": { "data": { "kid": "tls-kid", "hmac": "tls-hmac" } }
                })
                .to_string(),
            )
        }
        ("GET", "/v1/secret/data/bootroot/services/edge-proxy/http_responder_hmac")
            if token == Some(CLIENT_TOKEN) =>
        {
            (
                200,
                json!({
                    "data": { "data": { "hmac": HMAC_SECRET } }
                })
                .to_string(),
            )
        }
        ("GET", "/v1/secret/data/bootroot/services/edge-proxy/trust")
            if token == Some(CLIENT_TOKEN) =>
        {
            (
                200,
                json!({
                    "data": { "data": {
                        "trusted_ca_sha256": [trust.trusted_ca_sha256],
                        "ca_bundle_pem": trust.ca_bundle_pem,
                    } }
                })
                .to_string(),
            )
        }
        _ => (404, json!({ "errors": ["not found"] }).to_string()),
    }
}

/// Starts a minimal HTTPS server that speaks the `OpenBao` API subset the RN
/// bootstrap flow needs.  Returns the port on `127.0.0.1`.  The trust KV
/// response is echoed back to bootstrap verbatim, which then persists it to
/// `agent.toml`.
async fn start_openbao_tls_mock(server: SignedCert, trust: TrustKvResponse) -> u16 {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = CertificateDer::from(server.cert_der);
    let issuer = CertificateDer::from(server.issuer_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server.key_der));

    // Send the CA cert as part of the chain so SHA-256 pin verification on
    // the client side can match the pinned CA fingerprint against the
    // intermediate list.
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert, issuer], key)
        .expect("OpenBao TLS config");

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TokioTcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind OpenBao mock");
    let port = listener.local_addr().expect("local addr").port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let trust = trust.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                // Read until we have the full header + body. Real OpenBao
                // clients send all bytes immediately, but TLS record
                // boundaries do not necessarily align with HTTP boundaries,
                // so we loop reading until Content-Length is satisfied.
                let mut raw: Vec<u8> = Vec::with_capacity(16 * 1024);
                let mut chunk = [0u8; 4096];
                let header_end = loop {
                    let Ok(n) = tls.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break raw.windows(4).position(|w| w == b"\r\n\r\n");
                    }
                    raw.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break Some(pos);
                    }
                    if raw.len() > 64 * 1024 {
                        return;
                    }
                };
                let Some(header_end) = header_end else {
                    return;
                };
                let header_bytes = &raw[..header_end];
                let header_str = String::from_utf8_lossy(header_bytes).to_string();
                let mut lines = header_str.split("\r\n");
                let request_line = lines.next().unwrap_or_default();
                let mut parts = request_line.split_whitespace();
                let method = parts.next().unwrap_or_default().to_string();
                let path = parts.next().unwrap_or("/").to_string();
                let mut token: Option<String> = None;
                let mut content_length: usize = 0;
                for line in lines {
                    let Some((name, value)) = line.split_once(':') else {
                        continue;
                    };
                    if name.eq_ignore_ascii_case("x-vault-token") {
                        token = Some(value.trim().to_string());
                    } else if name.eq_ignore_ascii_case("content-length") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                let body_start = header_end + 4;
                while raw.len() < body_start + content_length {
                    let Ok(n) = tls.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        break;
                    }
                    raw.extend_from_slice(&chunk[..n]);
                }
                let body = if raw.len() >= body_start + content_length {
                    String::from_utf8_lossy(&raw[body_start..body_start + content_length])
                        .to_string()
                } else {
                    String::new()
                };
                let (status, resp_body) =
                    openbao_route(&method, &path, token.as_deref(), &body, &trust);
                let status_text = match status {
                    200 => "OK",
                    400 => "Bad Request",
                    _ => "Not Found",
                };
                let response = format!(
                    "HTTP/1.1 {status} {status_text}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n\
                     {resp_body}",
                    resp_body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    port
}

// ---------------------------------------------------------------------------
// Responder process
// ---------------------------------------------------------------------------

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

fn reserve_socket_addr() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    listener.local_addr().expect("local addr").to_string()
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

/// Proves, via a genuine TLS handshake, that a TLS peer on
/// `127.0.0.1:port` presents a certificate chain that would be accepted
/// under a trust store containing only `trusted_pem`.
///
/// This is the "positive half" of the system-trust-fallback proof used
/// by the negative test: if a client that trusts `system_ca.pem` *can*
/// complete the handshake, then the same server cert — by construction —
/// would also be accepted if the OS trust store held `system_ca.pem` (OS
/// verification and PEM-bundle verification run the same webpki chain
/// logic; rustls happens to only offer the latter).  The subsequent
/// bootstrap call, configured with the artifact anchor instead, must
/// fail — isolating the rejection to the refusal to consult OS roots.
///
/// This helper reports the reqwest error on failure so a failed positive
/// proof does not mask the negative proof the caller is about to make.
async fn assert_cert_chain_valid_under_trust(trusted_pem: &str, port: u16) {
    let client = build_probe_client(trusted_pem, port);
    let url = format!("https://localhost:{port}/v1/sys/health");
    let response = client
        .get(&url)
        .send()
        .await
        .expect("TLS handshake must succeed when system CA is trusted");
    // Any HTTP response proves the TLS handshake completed; 404 is fine.
    let _ = response.status();
}

/// Builds a reqwest client that trusts only `root_pem` and routes `localhost`
/// to the given admin port so the server cert's SAN matches.
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

/// Outcome of waiting for the spawned responder to accept TLS connections.
enum ReadyOutcome {
    /// The admin endpoint responded to the readiness probe.
    Ready,
    /// The responder exited during startup because one of its listen
    /// sockets was already bound by another process.  The caller should
    /// reserve fresh ports and respawn.
    BindConflict(String),
    /// The responder exited during startup for a reason that will not be
    /// resolved by retrying, or it never became ready within the timeout.
    Failure(String),
}

fn is_bind_conflict(stderr: &str) -> bool {
    // Covers messages rendered by tokio/std for EADDRINUSE on macOS (os
    // error 48) and Linux (os error 98), as well as the text poem emits
    // when the bound listener's accept loop dies.
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

/// Spawns the `bootroot-http01-responder` binary with retry-on-bind-conflict.
///
/// `reserve_socket_addr` binds an ephemeral port and immediately drops the
/// listener before the responder child re-binds the same address.  A
/// concurrent host process can claim the port in that TOCTOU window and
/// cause the responder to fail with `EADDRINUSE`.  The cleanest long-term
/// fix is responder support for `listen_addr = "127.0.0.1:0"`, but that is
/// a production behavior change outside the scope of this test.  Until
/// then, this helper re-reserves fresh ports, rewrites the responder
/// config, and respawns on each bind conflict so the acceptance gate does
/// not become flaky under parallel CI load.
///
/// Returns the running process plus the listen address, admin address, and
/// the fully-qualified admin URL the caller needs to drive the RN-side
/// client.
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

// ---------------------------------------------------------------------------
// Service-node fixtures
// ---------------------------------------------------------------------------

struct ServiceNode {
    _temp: TempDir,
    service_dir: std::path::PathBuf,
}

impl ServiceNode {
    fn prepare() -> Self {
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

        // Seed role_id; secret_id is written by the unwrap step.
        let role_id_path = service_dir
            .join("secrets")
            .join("services")
            .join(SERVICE_NAME)
            .join("role_id");
        fs::write(&role_id_path, ROLE_ID).expect("write role_id");

        Self {
            _temp: temp,
            service_dir,
        }
    }

    fn service_dir(&self) -> &Path {
        &self.service_dir
    }

    fn ca_bundle_path(&self) -> std::path::PathBuf {
        self.service_dir.join("certs").join("ca-bundle.pem")
    }
}

fn bootstrap_artifact(
    service_node: &ServiceNode,
    openbao_url: &str,
    ca_bundle_pem: &str,
    agent_responder_url: &str,
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
        "schema_version": 2,
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
        "wrap_token": WRAP_TOKEN,
        "wrap_expires_at": "2099-01-01T00:00:00Z",
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
    // Point the standard trust-store env vars at a CA that is DIFFERENT from
    // the artifact anchor.  rustls does not consult these vars, so this
    // arranges the test fixture to match the issue's "system trust store
    // trusts a different CA" precondition without altering host state.
    if let Some(path) = system_trust_pem_path {
        cmd.env("SSL_CERT_FILE", path);
        cmd.env("SSL_CERT_DIR", "/var/empty");
    }
    cmd.output().await.expect("run bootroot-remote")
}

/// Shared mutex guarding temporary mutation of `BOOTROOT_*` environment
/// variables across parallel test threads inside this binary.
static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Loads [`Settings`] from the `agent.toml` file that `bootroot-remote
/// bootstrap` wrote.  This is the production path the RN agent takes at
/// `src/acme/flow.rs:156` — no test-synthesised trust material is injected;
/// the CA bundle path and SHA-256 pins are exactly what bootstrap persisted
/// from the TLS-protected `OpenBao` `/trust` read.
///
/// `Settings::new` merges a `BOOTROOT_*` environment overlay on top of the
/// file at `src/config.rs:210`, which would otherwise let developer or CI
/// env vars (e.g. `BOOTROOT_TRUST__CA_BUNDLE_PATH`,
/// `BOOTROOT_TRUST__TRUSTED_CA_SHA256`,
/// `BOOTROOT_ACME__HTTP_RESPONDER_URL`) silently replace the values this
/// test is trying to prove came from the TLS-protected `/trust` read.  The
/// helper scrubs every `BOOTROOT_*` var under a shared [`ENV_LOCK`] while
/// building `Settings`, then restores them, so the loaded `Settings`
/// reflects the bootstrap-written `agent.toml` alone.
///
/// `http_responder_token_ttl_secs` is overridden to keep the admin
/// registration well below the responder's `max_token_ttl_secs`; everything
/// security-relevant (URL, HMAC, trust bundle path, pins) comes from the
/// file on disk.
fn load_settings_from_bootstrap_output(agent_config_path: &Path) -> Settings {
    let _guard = ENV_LOCK.lock().expect("env lock not poisoned");
    let saved: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(k, _)| k.to_str().is_some_and(|key| key.starts_with("BOOTROOT_")))
        .collect();
    for (key, _) in &saved {
        // SAFETY: Tests hold ENV_LOCK while mutating process environment.
        unsafe {
            std::env::remove_var(key);
        }
    }
    let result = Settings::new(Some(agent_config_path.to_path_buf()));
    for (key, value) in &saved {
        // SAFETY: Tests hold ENV_LOCK while mutating process environment.
        unsafe {
            std::env::set_var(key, value);
        }
    }
    let mut settings = result.expect("load agent.toml");
    settings.acme.http_responder_token_ttl_secs = TEST_TTL_SECS;
    settings
}

/// Drives the production `register_http01_token(settings, …)` entry point —
/// the same call path used by the RN agent at `src/acme/flow.rs:156` — and
/// proves the `Settings → TrustSettings → ResponderTrust` mapping is wired
/// up correctly end-to-end.
async fn register_http01_via_settings(settings: &Settings) -> anyhow::Result<()> {
    register_http01_token(settings, "e2e-token", "e2e-token.key").await
}

/// Low-level variant that exercises the shared responder-client module
/// directly with an explicit `ResponderTrust`.  Retained only for pin-path
/// coverage where the test needs to inject pins that do not match the CA
/// bundle on disk.
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
        "e2e-token",
        "e2e-token.key",
        TEST_TTL_SECS,
        Some(&trust),
    )
    .await
}

async fn verify_registered_token_served(listen_addr: &str) -> String {
    let url = format!("http://{listen_addr}/.well-known/acme-challenge/e2e-token");
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Exercises the full RN → CN control-plane over real TLS:
///
/// * `bootroot-remote bootstrap` against TLS `OpenBao` on CN, covering
///   `sys/wrapping/unwrap` + `auth/approle/login`, validating the server
///   certificate against the artifact-embedded CA anchor only.
/// * HTTP-01 admin token registration against the real
///   `bootroot-http01-responder` binary with a TLS-enabled admin listener,
///   validating against the same artifact-embedded CA anchor.
///
/// The `bootroot-remote bootstrap` subprocess is handed `SSL_CERT_FILE`
/// pointing at a system CA that is **not** the artifact anchor, so that the
/// happy-path bootstrap must succeed using only the artifact CA even when a
/// different CA is visible to the process via the standard env vars. The
/// in-process http01 registration that follows does not override
/// `SSL_CERT_FILE`; the property that the responder client never consults the
/// system trust store is proven by the dedicated negative-path scenarios
/// (`test_multi_host_tls_rejects_system_trusted_non_artifact_ca` and
/// `test_multi_host_tls_pin_rejects_chain_valid_but_non_pinned_ca`) rather
/// than by this fixture.
// This test drives a full RN → CN control-plane exchange (TLS OpenBao
// bootstrap + TLS http01 admin registration) and intentionally asserts
// end-to-end linkage between the two in one scenario, so the line count
// exceeds the default threshold.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_multi_host_tls_control_plane_happy_path() {
    let step_ca = TestCa::generate("Bootroot Step CA");
    let system_ca = TestCa::generate("System Trusted CA");
    // Distinct CA appended to the `/trust` response so the bundle
    // bootstrap pulls from TLS-protected `OpenBao` is observably
    // different from the artifact-seed PEM written up front at
    // `bootstrap.rs:76`.  This lets the test attribute the persisted
    // `ca_bundle_path` contents to the second write (from `pulled`)
    // at `bootstrap.rs:178`, not to the pre-call artifact seed.
    let extra_trust_ca = TestCa::generate("Extra Trust Bundle CA");

    // CN services: OpenBao TLS mock + bootroot-http01-responder, both
    // presenting certificates signed by the step-ca (the artifact anchor).
    // The OpenBao mock returns a `/trust` PEM that contains step-ca *plus*
    // an additional CA, so the bundle bootstrap persists differs from the
    // artifact-seed PEM.  step-ca stays in the persisted bundle so the
    // responder (also signed by step-ca) still validates; the appended CA
    // is what observably distinguishes the persisted file from the
    // artifact seed.
    let openbao_cert = step_ca.sign_server_cert("localhost");
    let trust_kv_pem = format!("{}{}", step_ca.pem, extra_trust_ca.pem);
    assert_ne!(
        trust_kv_pem, step_ca.pem,
        "trust KV PEM must differ from the artifact seed to prove the second write"
    );
    let trust_response = TrustKvResponse {
        ca_bundle_pem: trust_kv_pem.clone(),
        trusted_ca_sha256: step_ca.sha256_fingerprint(),
    };
    let openbao_port = start_openbao_tls_mock(openbao_cert, trust_response).await;

    let responder_temp = tempdir().expect("responder tempdir");
    let responder_cert = step_ca.sign_server_cert("localhost");
    let responder_cert_path = responder_temp.path().join("responder.cert.pem");
    let responder_key_path = responder_temp.path().join("responder.key.pem");
    // Serve the CA as part of the chain so SHA-256 pin enforcement on the
    // RN client can match the pinned CA fingerprint against the chain.
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

    // RN side: write the artifact and a "system" trust-store PEM that is
    // different from the step-ca anchor.  The artifact carries the real
    // responder URL so that the agent.toml bootstrap writes can be loaded
    // verbatim to drive the http01 call.
    let service_node = ServiceNode::prepare();
    let system_ca_pem_path = service_node.service_dir().join("system-ca.pem");
    fs::write(&system_ca_pem_path, &system_ca.pem).expect("write system CA");

    let artifact = bootstrap_artifact(
        &service_node,
        &format!("https://localhost:{openbao_port}"),
        &step_ca.pem,
        &admin_base_url,
    );
    let artifact_path = service_node.service_dir().join("bootstrap.json");
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).expect("serialize artifact"),
    )
    .expect("write artifact");

    let output =
        run_remote_bootstrap(&service_node, &artifact_path, Some(&system_ca_pem_path)).await;
    assert!(
        output.status.success(),
        "bootstrap must succeed over TLS with the artifact CA: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Bootstrap exercised sys/wrapping/unwrap + login and wrote the
    // unwrapped secret_id through the TLS-protected path.
    let secret_id_path = service_node
        .service_dir()
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("secret_id");
    let written_secret = fs::read_to_string(&secret_id_path).expect("read secret_id");
    assert_eq!(written_secret.trim(), UNWRAPPED_SECRET_ID);

    // Verify that bootstrap persisted the trust material read over TLS
    // from OpenBao — both to disk and into agent.toml — so that the
    // downstream http01 call below consumes exactly what bootstrap
    // wrote, not test-synthesised values.
    //
    // Production bootstrap first writes the artifact seed PEM to
    // `ca_bundle_path` at `bootstrap.rs:76`, then — after the
    // TLS-protected `/trust` read — overwrites the same path with the
    // `OpenBao`-supplied PEM at `bootstrap.rs:178`.  Because the fixture
    // uses a `/trust` PEM that is observably different from the artifact
    // seed, the two assertions below attribute the final file contents
    // squarely to the second write: a regression that accidentally
    // skipped the `/trust` overwrite would leave the shorter artifact
    // seed on disk and fail here.
    let ca_bundle_on_disk = service_node.ca_bundle_path();
    let persisted_bundle =
        fs::read_to_string(&ca_bundle_on_disk).expect("read persisted CA bundle");
    assert_eq!(
        persisted_bundle, trust_kv_pem,
        "bootstrap must persist the OpenBao /trust PEM verbatim, overwriting the artifact seed"
    );
    assert_ne!(
        persisted_bundle, step_ca.pem,
        "persisted bundle must differ from the artifact seed, proving the /trust write landed"
    );
    let agent_toml_path = service_node.service_dir().join("agent.toml");
    let persisted_agent_toml =
        fs::read_to_string(&agent_toml_path).expect("read persisted agent.toml");
    assert!(
        persisted_agent_toml.contains(&step_ca.sha256_fingerprint()),
        "bootstrap must persist the OpenBao-supplied SHA-256 pin in agent.toml"
    );

    // Drive the http01 admin call through the SAME production entry point
    // the RN agent uses (`src/acme/flow.rs:156` →
    // `register_http01_token(settings, …)`), loading `Settings` from the
    // `agent.toml` bootstrap just wrote.  Nothing below is synthesised by
    // the test: the CA bundle path, the SHA-256 pins, the responder URL,
    // and the HMAC secret all flow from the TLS-protected bootstrap path
    // into the TLS-protected http01 path.
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
        vec![step_ca.sha256_fingerprint()],
        "agent.toml must carry the OpenBao-supplied SHA-256 pin"
    );
    register_http01_via_settings(&settings)
        .await
        .expect("register http01 token over TLS via agent.toml the bootstrap produced");

    // Confirm the admin registration landed by fetching the public
    // challenge endpoint.
    let body = verify_registered_token_served(&listen_addr).await;
    assert_eq!(body, "e2e-token.key");
}

/// Proves the RN client does not fall back to the system trust store.
///
/// The CN presents certificates signed by a CA that is present in the RN's
/// `SSL_CERT_FILE` / `SSL_CERT_DIR` trust store but is **not** the artifact
/// anchor.  Both control-plane paths must reject the handshake.
// As with the happy-path test, this scenario drives both control-plane
// halves in one function to prove both negatives in a single fixture.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn test_multi_host_tls_rejects_system_trusted_non_artifact_ca() {
    let step_ca = TestCa::generate("Bootroot Step CA");
    let system_ca = TestCa::generate("System Trusted CA");

    // The server certs are signed by `system_ca`, which is what the RN
    // process has configured as its system trust store below.  The artifact
    // anchor is `step_ca`, which did NOT sign these certs.  Bootstrap's TLS
    // client (`OpenBaoClient::with_pem_trust(url, step_ca.pem, &[])`) is
    // structurally unable to reach any OS trust store, so the only PEM in
    // play is the artifact anchor — proving that even if the OS *were*
    // consulted (it is not, via rustls), the handshake would still fail.
    let openbao_cert = system_ca.sign_server_cert("localhost");
    // The negative path never reaches the /trust KV read, but the mock's
    // signature still requires a TrustKvResponse.
    let trust_response = TrustKvResponse {
        ca_bundle_pem: step_ca.pem.clone(),
        trusted_ca_sha256: step_ca.sha256_fingerprint(),
    };
    let openbao_port = start_openbao_tls_mock(openbao_cert, trust_response).await;

    let responder_temp = tempdir().expect("responder tempdir");
    let responder_cert = system_ca.sign_server_cert("localhost");
    let responder_cert_path = responder_temp.path().join("responder.cert.pem");
    let responder_key_path = responder_temp.path().join("responder.key.pem");
    // Serve the CA as part of the chain so SHA-256 pin enforcement on the
    // RN client can match the pinned CA fingerprint against the chain.
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

    // RN artifact uses the step-ca anchor, which does not chain to the
    // server cert's issuer.
    let service_node = ServiceNode::prepare();
    let system_ca_pem_path = service_node.service_dir().join("system-ca.pem");
    fs::write(&system_ca_pem_path, &system_ca.pem).expect("write system CA");

    let artifact = bootstrap_artifact(
        &service_node,
        &format!("https://localhost:{openbao_port}"),
        &step_ca.pem,
        &admin_base_url,
    );
    let artifact_path = service_node.service_dir().join("bootstrap.json");
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).expect("serialize artifact"),
    )
    .expect("write artifact");

    // Positive half of the system-trust-fallback proof: run a real TLS
    // handshake against the same `OpenBao` mock using a trust root of
    // `system_ca` only and verify it succeeds.  This pins down that the
    // server cert is structurally valid under the "system-trusted CA" role,
    // so the subsequent bootstrap rejection is attributable solely to the
    // artifact anchor — not to a malformed cert or other failure mode.
    assert_cert_chain_valid_under_trust(&system_ca.pem, openbao_port).await;

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

    // The http01 admin registration must also reject the server cert when
    // asked to validate against the artifact anchor.  Bootstrap failed
    // above (so no agent.toml trust block was written), so we synthesize
    // a production-shaped Settings that mirrors what bootstrap *would*
    // have written if the TLS handshake to OpenBao had succeeded.  This
    // exercises the same `Settings → TrustSettings → ResponderTrust`
    // mapping the RN agent uses in `src/acme/flow.rs:156`.
    let ca_bundle_on_disk = service_node.ca_bundle_path();
    fs::write(&ca_bundle_on_disk, &step_ca.pem).expect("materialize CA bundle");
    let agent_toml_path = service_node.service_dir().join("agent.toml");
    fs::write(
        &agent_toml_path,
        format!(
            "email = \"admin@example.com\"\n\
             server = \"https://localhost:9000/acme/acme/directory\"\n\
             domain = \"{DOMAIN}\"\n\n\
             [acme]\n\
             directory_fetch_attempts = 10\n\
             directory_fetch_base_delay_secs = 1\n\
             directory_fetch_max_delay_secs = 10\n\
             poll_attempts = 15\n\
             poll_interval_secs = 2\n\
             http_responder_url = \"{admin_base_url}\"\n\
             http_responder_hmac = \"{HMAC_SECRET}\"\n\
             http_responder_timeout_secs = 5\n\
             http_responder_token_ttl_secs = 300\n\n\
             [trust]\n\
             ca_bundle_path = \"{ca_bundle}\"\n\
             trusted_ca_sha256 = [\"{pin}\"]\n",
            ca_bundle = ca_bundle_on_disk.to_string_lossy(),
            pin = step_ca.sha256_fingerprint(),
        ),
    )
    .expect("write synthetic agent.toml");
    // Positive half of the http01 system-trust-fallback proof: readiness
    // was established by `spawn_responder_tls_retrying` via a probe client
    // trusting `system_ca`, so the responder's cert is already known to be
    // structurally valid under "system-trusted" roots.  The subsequent
    // `register_http01_via_settings` call uses the artifact anchor only
    // and must reject the same chain, attributing the rejection to the
    // refusal to consult system roots rather than to a malformed cert.
    let settings = load_settings_from_bootstrap_output(&agent_toml_path);
    let err = register_http01_via_settings(&settings)
        .await
        .expect_err("http01 registration must reject the system-trusted cert");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to register HTTP-01 token") || msg.contains("certificate"),
        "expected TLS failure from responder client, got: {msg}"
    );
}

/// Proves that the artifact-embedded SHA-256 pin is load-bearing even when
/// the trust bundle itself would accept the server's chain.
///
/// This directly addresses the "no system trust store fallback" requirement
/// in issue #521: we arrange a scenario where a non-artifact CA *is* a
/// trusted root in the client's explicit PEM bundle (modelling what would
/// happen if the client accidentally merged the system trust store into its
/// roots), and verify that the pin on `step_ca` still rejects the handshake
/// because the presented certificate's chain does not include the pinned
/// CA.  Since `build_client_config_from_pem` only ever consults the
/// supplied PEM (never the OS trust store), passing a PEM that contains
/// both roots is the strongest in-process proxy for "the server cert would
/// be system-trusted".
#[tokio::test]
async fn test_multi_host_tls_pin_rejects_chain_valid_but_non_pinned_ca() {
    let step_ca = TestCa::generate("Bootroot Step CA");
    let system_ca = TestCa::generate("System Trusted CA");

    // Responder presents a cert signed by `system_ca`.  The bundle
    // passed to the client will contain BOTH CAs — modelling a client
    // that has been handed a root set including a "system-trusted" CA —
    // so chain validation would otherwise succeed.
    let responder_temp = tempdir().expect("responder tempdir");
    let responder_cert = system_ca.sign_server_cert("localhost");
    let responder_cert_path = responder_temp.path().join("responder.cert.pem");
    let responder_key_path = responder_temp.path().join("responder.key.pem");
    // Serve the CA as part of the chain so SHA-256 pin enforcement on the
    // RN client can match the pinned CA fingerprint against the chain.
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

    // Combined PEM bundle: both CAs would be trusted by chain alone.
    let mut combined_pem = step_ca.pem.clone();
    combined_pem.push_str(&system_ca.pem);

    // Pin only the artifact anchor.  A chain that does NOT include the
    // pinned CA must be rejected even though the root is trusted.
    let err = register_http01_with_trust(
        &admin_base_url,
        &combined_pem,
        &[step_ca.sha256_fingerprint()],
    )
    .await
    .expect_err("pin mismatch must reject even when chain validates");
    let msg = err.to_string();
    assert!(
        msg.contains("Failed to register HTTP-01 token") || msg.contains("certificate"),
        "expected TLS failure from responder client, got: {msg}"
    );

    // Sanity check: without the pin, the same chain would be accepted —
    // so the rejection above is attributable to the pin, not to a
    // configuration error elsewhere.
    register_http01_with_trust(&admin_base_url, &combined_pem, &[])
        .await
        .expect("without a pin, a chain-valid cert is accepted — proving the pin is load-bearing");
}
