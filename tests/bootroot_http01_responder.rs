use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bootroot::acme::http01_protocol::{HEADER_SIGNATURE, HEADER_TIMESTAMP, Http01HmacSigner};
use reqwest::StatusCode;
use serde_json::json;
use tempfile::tempdir;
use tokio::time::sleep;

const ADMIN_PATH: &str = "/admin/http01";
const CHALLENGE_PATH_PREFIX: &str = "/.well-known/acme-challenge";
const STARTUP_RETRIES: usize = 50;
const STARTUP_DELAY: Duration = Duration::from_millis(100);
const TEST_TTL_SECS: u64 = 60;

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
    let listen_addr = reserve_socket_addr();
    let admin_addr = reserve_socket_addr();
    let config_path = temp_dir.path().join("responder.toml");
    write_responder_config(&config_path, &listen_addr, &admin_addr, "initial-secret");

    let mut responder = ResponderProcess::spawn(&config_path);
    let challenge_base_url = format!("http://{listen_addr}");
    let admin_base_url = format!("http://{admin_addr}");
    wait_for_ready(&mut responder, &challenge_base_url, &admin_base_url).await;

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
    let listen_addr = reserve_socket_addr();
    let admin_addr = reserve_socket_addr();
    let config_path = temp_dir.path().join("responder.toml");
    write_responder_config_with_overrides(
        &config_path,
        &listen_addr,
        &admin_addr,
        "initial-secret",
        &ResponderConfigOverrides {
            token_ttl_secs: Some(1),
            max_token_ttl_secs: Some(1),
            ..ResponderConfigOverrides::default()
        },
    );

    let mut responder = ResponderProcess::spawn(&config_path);
    let challenge_base_url = format!("http://{listen_addr}");
    let admin_base_url = format!("http://{admin_addr}");
    wait_for_ready(&mut responder, &challenge_base_url, &admin_base_url).await;

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
    let listen_addr = reserve_socket_addr();
    let admin_addr = reserve_socket_addr();
    let config_path = temp_dir.path().join("responder.toml");
    write_responder_config_with_overrides(
        &config_path,
        &listen_addr,
        &admin_addr,
        "initial-secret",
        &ResponderConfigOverrides {
            admin_rate_limit_requests: Some(1),
            admin_rate_limit_window_secs: Some(60),
            ..ResponderConfigOverrides::default()
        },
    );

    let mut responder = ResponderProcess::spawn(&config_path);
    let challenge_base_url = format!("http://{listen_addr}");
    let admin_base_url = format!("http://{admin_addr}");
    wait_for_ready(&mut responder, &challenge_base_url, &admin_base_url).await;

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
    let listen_addr = reserve_socket_addr();
    let admin_addr = reserve_socket_addr();
    let config_path = temp_dir.path().join("responder.toml");
    write_responder_config_with_overrides(
        &config_path,
        &listen_addr,
        &admin_addr,
        "initial-secret",
        &ResponderConfigOverrides {
            admin_body_limit_bytes: Some(64),
            ..ResponderConfigOverrides::default()
        },
    );

    let mut responder = ResponderProcess::spawn(&config_path);
    let challenge_base_url = format!("http://{listen_addr}");
    let admin_base_url = format!("http://{admin_addr}");
    wait_for_ready(&mut responder, &challenge_base_url, &admin_base_url).await;

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
    let listen_addr = reserve_socket_addr();
    let admin_addr = reserve_socket_addr();
    let config_path = temp_dir.path().join("responder.toml");
    write_responder_config(&config_path, &listen_addr, &admin_addr, "old-secret");

    let mut responder = ResponderProcess::spawn(&config_path);
    let challenge_base_url = format!("http://{listen_addr}");
    let admin_base_url = format!("http://{admin_addr}");
    wait_for_ready(&mut responder, &challenge_base_url, &admin_base_url).await;

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

async fn wait_for_ready(
    responder: &mut ResponderProcess,
    challenge_base_url: &str,
    admin_base_url: &str,
) {
    let challenge_url = format!("{challenge_base_url}{CHALLENGE_PATH_PREFIX}/health-check");
    let admin_url = format!("{admin_base_url}{ADMIN_PATH}");

    for _ in 0..STARTUP_RETRIES {
        if let Some(status) = responder.try_wait() {
            let stderr = responder.take_stderr();
            panic!("responder exited early with {status}: {stderr}");
        }

        let challenge_ready = match reqwest::get(&challenge_url).await {
            Ok(response) => {
                matches!(response.status(), StatusCode::NOT_FOUND | StatusCode::OK)
            }
            Err(_) => false,
        };

        if challenge_ready && reqwest::Client::new().get(&admin_url).send().await.is_ok() {
            return;
        }

        sleep(STARTUP_DELAY).await;
    }

    panic!("responder did not become ready");
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

async fn wait_for_tls_ready(
    responder: &mut ResponderProcess,
    admin_url: &str,
    client: &reqwest::Client,
) {
    for _ in 0..STARTUP_RETRIES {
        if let Some(status) = responder.try_wait() {
            let stderr = responder.take_stderr();
            panic!("responder exited early with {status}: {stderr}");
        }

        match client.get(format!("{admin_url}{ADMIN_PATH}")).send().await {
            Ok(_) => return,
            Err(_) => sleep(STARTUP_DELAY).await,
        }
    }
    panic!("TLS responder did not become ready");
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
    let listen_addr = reserve_socket_addr();
    let admin_addr = reserve_socket_addr();

    let pair = generate_ca_signed_cert_pair("localhost");
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&cert_path, &pair.cert).expect("write cert");
    fs::write(&key_path, &pair.key).expect("write key");

    let config_path = temp_dir.path().join("responder.toml");
    write_responder_config_with_overrides(
        &config_path,
        &listen_addr,
        &admin_addr,
        "tls-secret",
        &ResponderConfigOverrides {
            tls_cert_path: Some(cert_path.to_string_lossy().into_owned()),
            tls_key_path: Some(key_path.to_string_lossy().into_owned()),
            ..ResponderConfigOverrides::default()
        },
    );

    let mut responder = ResponderProcess::spawn(&config_path);
    let admin_base_url = format!(
        "https://localhost:{}",
        admin_addr.split(':').next_back().unwrap()
    );
    let client = build_tls_client(&pair.root);

    wait_for_tls_ready(&mut responder, &admin_base_url, &client).await;

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
    let listen_addr = reserve_socket_addr();
    let admin_addr = reserve_socket_addr();

    let pair1 = generate_ca_signed_cert_pair("localhost");
    let cert_path = temp_dir.path().join("cert.pem");
    let key_path = temp_dir.path().join("key.pem");
    fs::write(&cert_path, &pair1.cert).expect("write cert");
    fs::write(&key_path, &pair1.key).expect("write key");

    let config_path = temp_dir.path().join("responder.toml");
    write_responder_config_with_overrides(
        &config_path,
        &listen_addr,
        &admin_addr,
        "reload-secret",
        &ResponderConfigOverrides {
            tls_cert_path: Some(cert_path.to_string_lossy().into_owned()),
            tls_key_path: Some(key_path.to_string_lossy().into_owned()),
            ..ResponderConfigOverrides::default()
        },
    );

    let mut responder = ResponderProcess::spawn(&config_path);
    let admin_port = admin_addr.split(':').next_back().unwrap();
    let admin_base_url = format!("https://localhost:{admin_port}");
    let client1 = build_tls_client(&pair1.root);

    wait_for_tls_ready(&mut responder, &admin_base_url, &client1).await;

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
