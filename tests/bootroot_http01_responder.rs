use std::fs;
use std::io::{ErrorKind, Read};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bootroot::acme::http01_protocol::{HEADER_SIGNATURE, HEADER_TIMESTAMP, Http01HmacSigner};
use reqwest::StatusCode;
use serde_json::json;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, timeout};

const ADMIN_PATH: &str = "/admin/http01";
const CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge";
const STARTUP_RETRIES: usize = 50;
const STARTUP_DELAY: Duration = Duration::from_millis(100);
const TEST_TTL_SECS: u64 = 60;
/// Number of attempts to spawn the responder when a concurrent host process
/// claims one of the reserved ephemeral ports in the window between
/// `reserve_socket_addr` dropping its listener and the responder child
/// re-binding the same address.
const RESPONDER_BIND_ATTEMPTS: u32 = 4;
/// Bound on one raw exchange with the challenge listener. The responder
/// closes the connection after the response only when asked to, so a
/// request that forgot `Connection: close` runs into this instead of
/// hanging the test.
const RAW_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(5);
/// A name nothing resolves: the responder must answer for it without
/// trying to.
const UNALIASED_NAME: &str = "001.unaliased.host.invalid";

#[derive(Default)]
struct ResponderConfigOverrides {
    token_ttl_secs: Option<u64>,
    max_token_ttl_secs: Option<u64>,
    admin_rate_limit_requests: Option<u64>,
    admin_rate_limit_window_secs: Option<u64>,
    admin_body_limit_bytes: Option<u64>,
    tls_cert_path: Option<String>,
    tls_key_path: Option<String>,
}

#[tokio::test]
async fn test_http01_responder_serves_registered_token() {
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("responder.toml");
    let (_responder, listen_addr, admin_addr) =
        spawn_responder_retrying(&config_path, |path, listen, admin| {
            write_responder_config(path, listen, admin, "initial-secret");
        })
        .await;
    let challenge_base_url = format!("http://{listen_addr}");
    let admin_base_url = format!("http://{admin_addr}");

    let response = register_token(
        &admin_base_url,
        "initial-secret",
        "token-1",
        "token-1.key",
        TEST_TTL_SECS,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let challenge = fetch_challenge(&challenge_base_url, "token-1").await;
    assert_eq!(challenge.status(), StatusCode::OK);
    assert_eq!(
        challenge.text().await.expect("read challenge response"),
        "token-1.key"
    );
}

#[tokio::test]
async fn test_http01_responder_clamps_requested_ttl_to_server_max() {
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("responder.toml");
    let overrides = ResponderConfigOverrides {
        token_ttl_secs: Some(1),
        max_token_ttl_secs: Some(1),
        ..ResponderConfigOverrides::default()
    };
    let (_responder, listen_addr, admin_addr) =
        spawn_responder_retrying(&config_path, |path, listen, admin| {
            write_responder_config_with_overrides(
                path,
                listen,
                admin,
                "initial-secret",
                &overrides,
            );
        })
        .await;
    let challenge_base_url = format!("http://{listen_addr}");
    let admin_base_url = format!("http://{admin_addr}");

    let response = register_token(
        &admin_base_url,
        "initial-secret",
        "token-clamped",
        "token-clamped.key",
        TEST_TTL_SECS,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    sleep(Duration::from_secs(2)).await;

    let challenge = fetch_challenge(&challenge_base_url, "token-clamped").await;
    assert_eq!(challenge.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_http01_responder_rate_limits_admin_registrations() {
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("responder.toml");
    let overrides = ResponderConfigOverrides {
        admin_rate_limit_requests: Some(1),
        admin_rate_limit_window_secs: Some(60),
        ..ResponderConfigOverrides::default()
    };
    let (_responder, _listen_addr, admin_addr) =
        spawn_responder_retrying(&config_path, |path, listen, admin| {
            write_responder_config_with_overrides(
                path,
                listen,
                admin,
                "initial-secret",
                &overrides,
            );
        })
        .await;
    let admin_base_url = format!("http://{admin_addr}");

    let first = register_token(
        &admin_base_url,
        "initial-secret",
        "token-rate-limit-1",
        "token-rate-limit-1.key",
        TEST_TTL_SECS,
    )
    .await;
    assert_eq!(first.status(), StatusCode::OK);

    let second = register_token(
        &admin_base_url,
        "initial-secret",
        "token-rate-limit-2",
        "token-rate-limit-2.key",
        TEST_TTL_SECS,
    )
    .await;
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_http01_responder_rejects_large_admin_payloads() {
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("responder.toml");
    let overrides = ResponderConfigOverrides {
        admin_body_limit_bytes: Some(64),
        ..ResponderConfigOverrides::default()
    };
    let (_responder, _listen_addr, admin_addr) =
        spawn_responder_retrying(&config_path, |path, listen, admin| {
            write_responder_config_with_overrides(
                path,
                listen,
                admin,
                "initial-secret",
                &overrides,
            );
        })
        .await;
    let admin_base_url = format!("http://{admin_addr}");

    let response = reqwest::Client::new()
        .post(format!("{admin_base_url}{ADMIN_PATH}"))
        .header("content-type", "application/json")
        .body(
            r#"{"token":"token-large","key_authorization":"token-large.key.token-large.key","ttl_secs":60}"#,
        )
        .send()
        .await
        .expect("send oversized register request");

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[cfg(unix)]
#[tokio::test]
async fn test_http01_responder_reloads_hmac_secret_on_sighup() {
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("responder.toml");
    let (mut responder, listen_addr, admin_addr) =
        spawn_responder_retrying(&config_path, |path, listen, admin| {
            write_responder_config(path, listen, admin, "old-secret");
        })
        .await;
    let challenge_base_url = format!("http://{listen_addr}");
    let admin_base_url = format!("http://{admin_addr}");

    write_responder_config(&config_path, &listen_addr, &admin_addr, "new-secret");
    send_sighup(responder.pid());

    let accepted_token =
        wait_for_reload(&mut responder, &admin_base_url, "old-secret", "new-secret").await;
    let challenge = fetch_challenge(&challenge_base_url, &accepted_token).await;
    assert_eq!(challenge.status(), StatusCode::OK);
    assert_eq!(
        challenge.text().await.expect("read challenge response"),
        format!("{accepted_token}.key")
    );
}

// step-ca reaches the responder as an HTTP proxy (`HTTP_PROXY` on the
// `step-ca` compose service), so the three tests below put on the wire
// what a proxy client sends: a request line in absolute form, and
// `CONNECT`. They pin what that design rests on — the responder answers
// a challenge by path alone whatever name the URI carries, and it has no
// outbound path, so it is not an open proxy. A change that gives the
// responder an HTTP client must keep them passing.

#[tokio::test]
async fn test_http01_responder_serves_absolute_form_challenge_request() {
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("responder.toml");
    let (_responder, listen_addr, admin_addr) =
        spawn_responder_retrying(&config_path, |path, listen, admin| {
            write_responder_config(path, listen, admin, "initial-secret");
        })
        .await;
    let admin_base_url = format!("http://{admin_addr}");

    let response = register_token(
        &admin_base_url,
        "initial-secret",
        "token-proxied",
        "token-proxied.key",
        TEST_TTL_SECS,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let (status, body) = raw_exchange(
        &listen_addr,
        &raw_request(
            "GET",
            &format!("http://{UNALIASED_NAME}{CHALLENGE_PATH_PREFIX}/token-proxied"),
            UNALIASED_NAME,
        ),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body, "token-proxied.key");
}

#[tokio::test]
async fn test_http01_responder_forwards_no_absolute_form_request() {
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("responder.toml");
    let (_responder, listen_addr, _admin_addr) =
        spawn_responder_retrying(&config_path, |path, listen, admin| {
            write_responder_config(path, listen, admin, "initial-secret");
        })
        .await;
    let decoy = Decoy::bind();
    let authority = decoy.authority();

    // The two bodies differ in case (the router's not-found and the
    // handler's), so the status is what is asserted.
    for path in [
        "/secret".to_string(),
        format!("{CHALLENGE_PATH_PREFIX}/token-never-registered"),
    ] {
        let (status, _body) = raw_exchange(
            &listen_addr,
            &raw_request("GET", &format!("http://{authority}{path}"), &authority),
        )
        .await;
        assert_eq!(status, 404, "absolute-form GET of {path}");
    }
    decoy.assert_no_pending_connection();
}

#[tokio::test]
async fn test_http01_responder_refuses_connect() {
    let temp_dir = tempdir().expect("create temp dir");
    let config_path = temp_dir.path().join("responder.toml");
    let (_responder, listen_addr, _admin_addr) =
        spawn_responder_retrying(&config_path, |path, listen, admin| {
            write_responder_config(path, listen, admin, "initial-secret");
        })
        .await;
    let decoy = Decoy::bind();
    let authority = decoy.authority();

    let (status, _body) = raw_exchange(
        &listen_addr,
        &raw_request("CONNECT", &authority, &authority),
    )
    .await;
    assert_eq!(status, 404);
    decoy.assert_no_pending_connection();
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

    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().expect("poll responder process")
    }

    fn take_stderr(&mut self) -> String {
        let Some(mut stderr) = self.child.stderr.take() else {
            return String::new();
        };
        let mut output = String::new();
        stderr
            .read_to_string(&mut output)
            .expect("read responder stderr");
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
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener
        .local_addr()
        .expect("read listener address")
        .to_string()
}

/// Builds a bodiless HTTP/1.1 request with the request target written
/// exactly as given. `Connection: close` is not optional: without it the
/// responder keeps the connection open after the response and
/// [`raw_exchange`] never sees the end of the stream.
fn raw_request(method: &str, target: &str, host: &str) -> String {
    format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
}

/// Writes `request` to the challenge listener as it stands and returns
/// the response's status code and body. `reqwest` cannot stand in here:
/// it always sends origin form to a server it is not told is a proxy,
/// and the request line is what these tests are about.
async fn raw_exchange(listen_addr: &str, request: &str) -> (u16, String) {
    let exchange = async {
        let mut stream = TcpStream::connect(listen_addr)
            .await
            .expect("connect to challenge listener");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write raw request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read raw response");
        response
    };
    let response = timeout(RAW_EXCHANGE_TIMEOUT, exchange)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "the responder held the connection open for {RAW_EXCHANGE_TIMEOUT:?} after: \
                 {request:?}"
            )
        });
    let response = String::from_utf8(response).expect("response is UTF-8");
    let (head, body) = response
        .split_once("\r\n\r\n")
        .unwrap_or_else(|| panic!("response has no header terminator: {response:?}"));
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap_or_else(|| panic!("response has no status code: {head:?}"));
    (status, body.to_string())
}

/// A loopback listener standing in for whatever a proxied request names.
/// Nothing is expected to connect to it: a connection is the responder
/// forwarding.
struct Decoy {
    listener: TcpListener,
}

impl Decoy {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind decoy listener");
        listener
            .set_nonblocking(true)
            .expect("set decoy listener non-blocking");
        Self { listener }
    }

    fn authority(&self) -> String {
        self.listener
            .local_addr()
            .expect("read decoy address")
            .to_string()
    }

    fn assert_no_pending_connection(&self) {
        match self.listener.accept() {
            Ok((_stream, peer)) => panic!("the responder forwarded a connection from {peer}"),
            Err(err) => assert_eq!(
                err.kind(),
                ErrorKind::WouldBlock,
                "decoy accept failed for a reason other than having nothing pending: {err}"
            ),
        }
    }
}

fn write_responder_config(config_path: &Path, listen_addr: &str, admin_addr: &str, secret: &str) {
    write_responder_config_with_overrides(
        config_path,
        listen_addr,
        admin_addr,
        secret,
        &ResponderConfigOverrides::default(),
    );
}

fn write_responder_config_with_overrides(
    config_path: &Path,
    listen_addr: &str,
    admin_addr: &str,
    secret: &str,
    overrides: &ResponderConfigOverrides,
) {
    let mut contents = format!(
        "listen_addr = \"{listen_addr}\"\n\
admin_addr = \"{admin_addr}\"\n\
hmac_secret = \"{secret}\"\n\
token_ttl_secs = {token_ttl_secs}\n\
max_token_ttl_secs = {max_token_ttl_secs}\n\
cleanup_interval_secs = 30\n\
max_skew_secs = 60\n\
admin_rate_limit_requests = {admin_rate_limit_requests}\n\
admin_rate_limit_window_secs = {admin_rate_limit_window_secs}\n\
admin_body_limit_bytes = {admin_body_limit_bytes}\n",
        token_ttl_secs = overrides.token_ttl_secs.unwrap_or(300),
        max_token_ttl_secs = overrides.max_token_ttl_secs.unwrap_or(900),
        admin_rate_limit_requests = overrides.admin_rate_limit_requests.unwrap_or(300),
        admin_rate_limit_window_secs = overrides.admin_rate_limit_window_secs.unwrap_or(60),
        admin_body_limit_bytes = overrides.admin_body_limit_bytes.unwrap_or(8 * 1024),
    );
    if let Some(ref cert_path) = overrides.tls_cert_path {
        use std::fmt::Write;
        writeln!(contents, "tls_cert_path = \"{cert_path}\"").expect("append tls_cert_path");
    }
    if let Some(ref key_path) = overrides.tls_key_path {
        use std::fmt::Write;
        writeln!(contents, "tls_key_path = \"{key_path}\"").expect("append tls_key_path");
    }
    fs::write(config_path, contents).expect("write responder config");
}

fn sign_request(
    secret: &str,
    token: &str,
    key_authorization: &str,
    ttl_secs: u64,
) -> (i64, String) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System time must be after UNIX_EPOCH")
        .as_secs();
    let timestamp = i64::try_from(timestamp).expect("System time must fit in i64");
    let signer = Http01HmacSigner::new(secret);
    let signature = signer.sign_request(timestamp, token, key_authorization, ttl_secs);
    (timestamp, signature)
}

/// Outcome of waiting for the spawned responder to become ready.
enum ReadyOutcome {
    Ready,
    /// The responder exited during startup because one of its listen
    /// sockets was already bound by another process.  The caller should
    /// reserve fresh ports and respawn.
    BindConflict(String),
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

async fn try_wait_for_ready(
    responder: &mut ResponderProcess,
    challenge_base_url: &str,
    admin_base_url: &str,
) -> ReadyOutcome {
    let challenge_url = format!("{challenge_base_url}{CHALLENGE_PATH_PREFIX}/health-check");
    let admin_url = format!("{admin_base_url}{ADMIN_PATH}");

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

        let challenge_ready = match reqwest::get(&challenge_url).await {
            Ok(response) => {
                matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::OK)
            }
            Err(_) => false,
        };

        if challenge_ready && reqwest::Client::new().get(&admin_url).send().await.is_ok() {
            return ReadyOutcome::Ready;
        }

        sleep(STARTUP_DELAY).await;
    }

    ReadyOutcome::Failure("responder did not become ready".to_string())
}

/// Reserves fresh ports, writes the responder config with the provided
/// `config_writer` closure, spawns the responder, and waits for it to
/// become ready.  Retries on bind conflict so that a concurrent host
/// process stealing a reserved port does not flake the test under CI
/// parallel load.
async fn spawn_responder_retrying<F>(
    config_path: &Path,
    config_writer: F,
) -> (ResponderProcess, String, String)
where
    F: Fn(&Path, &str, &str),
{
    let mut last_failure = String::new();
    for attempt in 0..RESPONDER_BIND_ATTEMPTS {
        let listen_addr = reserve_socket_addr();
        let admin_addr = reserve_socket_addr();
        config_writer(config_path, &listen_addr, &admin_addr);
        let mut responder = ResponderProcess::spawn(config_path);
        let challenge_base_url = format!("http://{listen_addr}");
        let admin_base_url = format!("http://{admin_addr}");
        match try_wait_for_ready(&mut responder, &challenge_base_url, &admin_base_url).await {
            ReadyOutcome::Ready => return (responder, listen_addr, admin_addr),
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

async fn register_token(
    admin_base_url: &str,
    secret: &str,
    token: &str,
    key_authorization: &str,
    ttl_secs: u64,
) -> reqwest::Response {
    let (timestamp, signature) = sign_request(secret, token, key_authorization, ttl_secs);

    reqwest::Client::new()
        .post(format!("{admin_base_url}{ADMIN_PATH}"))
        .header(HEADER_TIMESTAMP, timestamp.to_string())
        .header(HEADER_SIGNATURE, signature)
        .json(&json!({
            "token": token,
            "key_authorization": key_authorization,
            "ttl_secs": ttl_secs
        }))
        .send()
        .await
        .expect("send register request")
}

async fn fetch_challenge(challenge_base_url: &str, token: &str) -> reqwest::Response {
    reqwest::get(format!(
        "{challenge_base_url}{CHALLENGE_PATH_PREFIX}/{token}"
    ))
    .await
    .expect("fetch challenge response")
}

#[cfg(unix)]
async fn wait_for_reload(
    responder: &mut ResponderProcess,
    admin_base_url: &str,
    old_secret: &str,
    new_secret: &str,
) -> String {
    for attempt in 0..STARTUP_RETRIES {
        if let Some(status) = responder.try_wait() {
            let stderr = responder.take_stderr();
            panic!("responder exited during reload with {status}: {stderr}");
        }

        let rejected_token = format!("rejected-{attempt}");
        let rejected_key = format!("{rejected_token}.key");
        let rejected = register_token(
            admin_base_url,
            old_secret,
            &rejected_token,
            &rejected_key,
            TEST_TTL_SECS,
        )
        .await;

        if rejected.status() == StatusCode::UNAUTHORIZED {
            let accepted_token = format!("accepted-{attempt}");
            let accepted_key = format!("{accepted_token}.key");
            let accepted = register_token(
                admin_base_url,
                new_secret,
                &accepted_token,
                &accepted_key,
                TEST_TTL_SECS,
            )
            .await;
            if accepted.status() == StatusCode::OK {
                return accepted_token;
            }
        }

        sleep(STARTUP_DELAY).await;
    }

    panic!("responder did not reload the updated HMAC secret");
}

#[cfg(unix)]
fn send_sighup(pid: u32) {
    let pid = i32::try_from(pid).expect("child pid must fit in i32");
    // SAFETY: The pid comes from a live child process spawned by this test.
    let result = unsafe { libc::kill(pid, libc::SIGHUP) };
    assert_eq!(result, 0, "SIGHUP should be delivered");
}

// ---------------------------------------------------------------------------
// TLS test helpers
// ---------------------------------------------------------------------------

struct CertPair {
    cert: String,
    key: String,
    root: String,
}

fn generate_ca_signed_cert_pair(san: &str) -> CertPair {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(vec!["root.test".to_string()]).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Test Root CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.clone().self_signed(&ca_key).expect("self signed");
    let root_pem = ca_cert.pem();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let server_key = KeyPair::generate().expect("server key");
    let mut server_params = CertificateParams::new(vec![san.to_string()]).expect("server params");
    server_params
        .distinguished_name
        .push(DnType::CommonName, san);
    let server_cert = server_params
        .signed_by(&server_key, &ca_issuer)
        .expect("signed");

    CertPair {
        cert: server_cert.pem(),
        key: server_key.serialize_pem(),
        root: root_pem,
    }
}

fn build_tls_client(root_pem: &str) -> reqwest::Client {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let root_store = {
        let mut store = rustls::RootCertStore::empty();
        let certs: Vec<_> =
            rustls_pemfile::certs(&mut std::io::BufReader::new(root_pem.as_bytes()))
                .collect::<Result<Vec<_>, _>>()
                .expect("parse root PEM");
        for cert in certs {
            store.add(cert).expect("add root cert");
        }
        store
    };
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .resolve(
            "localhost",
            "127.0.0.1:0".parse().expect("parse socket addr"),
        )
        .build()
        .expect("build TLS client")
}

async fn try_wait_for_tls_ready(
    responder: &mut ResponderProcess,
    admin_url: &str,
    client: &reqwest::Client,
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

        match client.get(format!("{admin_url}{ADMIN_PATH}")).send().await {
            Ok(_) => return ReadyOutcome::Ready,
            Err(_) => sleep(STARTUP_DELAY).await,
        }
    }
    ReadyOutcome::Failure("TLS responder did not become ready".to_string())
}

/// TLS variant of `spawn_responder_retrying`.  Reserves fresh ports,
/// writes the responder config, spawns the responder, and probes the
/// TLS admin endpoint with `client` until it accepts connections.
/// Retries on bind conflict.
async fn spawn_responder_tls_retrying<F>(
    config_path: &Path,
    client: &reqwest::Client,
    config_writer: F,
) -> (ResponderProcess, String, String, String)
where
    F: Fn(&Path, &str, &str),
{
    let mut last_failure = String::new();
    for attempt in 0..RESPONDER_BIND_ATTEMPTS {
        let listen_addr = reserve_socket_addr();
        let admin_addr = reserve_socket_addr();
        config_writer(config_path, &listen_addr, &admin_addr);
        let mut responder = ResponderProcess::spawn(config_path);
        let admin_port = admin_addr
            .split(':')
            .next_back()
            .expect("admin port present");
        let admin_base_url = format!("https://localhost:{admin_port}");
        match try_wait_for_tls_ready(&mut responder, &admin_base_url, client).await {
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

async fn register_token_with_client(
    client: &reqwest::Client,
    admin_base_url: &str,
    secret: &str,
    token: &str,
    key_authorization: &str,
    ttl_secs: u64,
) -> reqwest::Response {
    let (timestamp, signature) = sign_request(secret, token, key_authorization, ttl_secs);

    client
        .post(format!("{admin_base_url}{ADMIN_PATH}"))
        .header(HEADER_TIMESTAMP, timestamp.to_string())
        .header(HEADER_SIGNATURE, signature)
        .json(&json!({
            "token": token,
            "key_authorization": key_authorization,
            "ttl_secs": ttl_secs
        }))
        .send()
        .await
        .expect("send register request")
}

// ---------------------------------------------------------------------------
// TLS integration tests
// ---------------------------------------------------------------------------

#[cfg(unix)]
#[tokio::test]
async fn test_http01_responder_serves_admin_api_over_tls() {
    let temp_dir = tempdir().expect("create temp dir");
    let pair = generate_ca_signed_cert_pair("localhost");
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&cert_path, &pair.cert).expect("write cert");
    fs::write(&key_path, &pair.key).expect("write key");

    let config_path = temp_dir.path().join("responder.toml");
    let overrides = ResponderConfigOverrides {
        tls_cert_path: Some(cert_path.to_string_lossy().into_owned()),
        tls_key_path: Some(key_path.to_string_lossy().into_owned()),
        ..ResponderConfigOverrides::default()
    };
    let client = build_tls_client(&pair.root);
    let (_responder, listen_addr, _admin_addr, admin_base_url) =
        spawn_responder_tls_retrying(&config_path, &client, |path, listen, admin| {
            write_responder_config_with_overrides(path, listen, admin, "tls-secret", &overrides);
        })
        .await;

    let response = register_token_with_client(
        &client,
        &admin_base_url,
        "tls-secret",
        "tls-token",
        "tls-token.key",
        TEST_TTL_SECS,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    let challenge_base_url = format!("http://{listen_addr}");
    let challenge = fetch_challenge(&challenge_base_url, "tls-token").await;
    assert_eq!(challenge.status(), StatusCode::OK);
    assert_eq!(
        challenge.text().await.expect("read challenge response"),
        "tls-token.key"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_http01_responder_reloads_tls_cert_on_sighup() {
    let temp_dir = tempdir().expect("create temp dir");
    let pair1 = generate_ca_signed_cert_pair("localhost");
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&cert_path, &pair1.cert).expect("write cert");
    fs::write(&key_path, &pair1.key).expect("write key");

    let config_path = temp_dir.path().join("responder.toml");
    let overrides = ResponderConfigOverrides {
        tls_cert_path: Some(cert_path.to_string_lossy().into_owned()),
        tls_key_path: Some(key_path.to_string_lossy().into_owned()),
        ..ResponderConfigOverrides::default()
    };
    let client1 = build_tls_client(&pair1.root);
    let (mut responder, _listen_addr, _admin_addr, admin_base_url) =
        spawn_responder_tls_retrying(&config_path, &client1, |path, listen, admin| {
            write_responder_config_with_overrides(path, listen, admin, "reload-secret", &overrides);
        })
        .await;

    // Swap cert+key on disk with a cert from a different CA.
    let pair2 = generate_ca_signed_cert_pair("localhost");
    fs::write(&cert_path, &pair2.cert).expect("write new cert");
    fs::write(&key_path, &pair2.key).expect("write new key");

    send_sighup(responder.pid());

    // Build a client that trusts the new CA.
    let client2 = build_tls_client(&pair2.root);

    // Poll until the responder picks up the new cert.  The client trusts
    // only the new CA, so connection errors are expected until the resolver
    // swaps.
    let mut swapped = false;
    for _ in 0..STARTUP_RETRIES {
        if let Some(status) = responder.try_wait() {
            let stderr = responder.take_stderr();
            panic!("responder exited during reload with {status}: {stderr}");
        }

        let (timestamp, signature) = sign_request(
            "reload-secret",
            "reload-tok",
            "reload-tok.key",
            TEST_TTL_SECS,
        );
        let result = client2
            .post(format!("{admin_base_url}{ADMIN_PATH}"))
            .header(HEADER_TIMESTAMP, timestamp.to_string())
            .header(HEADER_SIGNATURE, &signature)
            .json(&json!({
                "token": "reload-tok",
                "key_authorization": "reload-tok.key",
                "ttl_secs": TEST_TTL_SECS
            }))
            .send()
            .await;
        match result {
            Ok(r) if r.status() == StatusCode::OK => {
                swapped = true;
                break;
            }
            _ => sleep(STARTUP_DELAY).await,
        }
    }
    assert!(
        swapped,
        "responder did not pick up the new TLS cert after SIGHUP"
    );
}
