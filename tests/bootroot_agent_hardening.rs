#![cfg(unix)]

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bootroot::config;
use rcgen::generate_simple_self_signed;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct AcmeTlsFixture {
    addr: SocketAddr,
    handle: JoinHandle<()>,
}

impl AcmeTlsFixture {
    fn directory_url(&self) -> String {
        format!("https://127.0.0.1:{}/directory", self.addr.port())
    }
}

fn acme_fixture_response(
    method: &str,
    path: &str,
    base: &str,
    cert_response: String,
) -> (String, String, String, String) {
    match (method, path) {
        ("GET", "/directory") => (
            "200 OK".to_string(),
            "application/json".to_string(),
            format!(
                r#"{{"newNonce":"{base}/nonce","newAccount":"{base}/account","newOrder":"{base}/order"}}"#
            ),
            String::new(),
        ),
        ("HEAD", "/nonce") => (
            "200 OK".to_string(),
            "application/json".to_string(),
            String::new(),
            String::new(),
        ),
        ("POST", "/account") => (
            "201 Created".to_string(),
            "application/json".to_string(),
            "{}".to_string(),
            format!("Location: {base}/account/1\r\n"),
        ),
        ("POST", "/order") => (
            "201 Created".to_string(),
            "application/json".to_string(),
            format!(
                r#"{{"status":"ready","finalize":"{base}/finalize/1","authorizations":["{base}/authz/1"],"certificate":null}}"#
            ),
            format!("Location: {base}/order/1\r\n"),
        ),
        ("POST", "/authz/1") => (
            "200 OK".to_string(),
            "application/json".to_string(),
            format!(
                r#"{{"status":"valid","identifier":{{"type":"dns","value":"fixture.example"}},"challenges":[{{"type":"http-01","url":"{base}/challenge/1","token":"fixture-token","status":"valid","error":null}}]}}"#
            ),
            String::new(),
        ),
        ("POST", "/challenge/1") => (
            "200 OK".to_string(),
            "application/json".to_string(),
            "{}".to_string(),
            String::new(),
        ),
        ("POST", "/finalize/1") => (
            "200 OK".to_string(),
            "application/json".to_string(),
            format!(
                r#"{{"status":"valid","finalize":"{base}/finalize/1","authorizations":["{base}/authz/1"],"certificate":"{base}/cert/1"}}"#
            ),
            String::new(),
        ),
        ("POST", "/cert/1") => (
            "200 OK".to_string(),
            "application/pem-certificate-chain".to_string(),
            cert_response,
            String::new(),
        ),
        _ => (
            "404 Not Found".to_string(),
            "text/plain".to_string(),
            "not found".to_string(),
            String::new(),
        ),
    }
}

async fn assert_fixture_reachable(directory_url: &str) {
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(2))
        .build()
        .expect("build fixture probe client");
    let response = client
        .get(directory_url)
        .send()
        .await
        .expect("fixture directory request");
    assert!(response.status().is_success());
}

async fn start_acme_tls_fixture() -> Result<AcmeTlsFixture> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()])
            .context("generate ACME fixture cert")?;
    let cert_der = cert.der().to_vec();
    let cert_pem = cert.pem();
    let key_der = signing_key.serialize_der();

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::pki_types::CertificateDer::from(cert_der)],
            rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_der,
            )),
        )
        .context("build tls config")?;

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .context("bind fixture listener")?;
    let addr = listener.local_addr().context("fixture local addr")?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let base = format!("https://127.0.0.1:{}", addr.port());
    let nonce_value = "fixture-nonce";
    let cert_response = format!("{cert_pem}\n");

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let base = base.clone();
            let cert_response = cert_response.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buffer = vec![0_u8; 16 * 1024];
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                let request = String::from_utf8_lossy(&buffer[..read]);
                let mut parts = request
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .split_whitespace();
                let method = parts.next().unwrap_or_default();
                let path = parts.next().unwrap_or("/");
                let (status, content_type, body, extra_headers) =
                    acme_fixture_response(method, path, &base, cert_response);

                let body_bytes = body.as_bytes();
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nReplay-Nonce: {nonce_value}\r\nConnection: close\r\n{extra_headers}Content-Length: {}\r\n\r\n{}",
                    body_bytes.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    Ok(AcmeTlsFixture { addr, handle })
}

async fn mount_responder_admin_mock(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/admin/http01"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

fn write_agent_config(
    path: &Path,
    acme_directory_url: &str,
    responder_url: &str,
) -> Result<(PathBuf, PathBuf)> {
    let cert_path = path.join("certs").join("edge.crt");
    let key_path = path.join("certs").join("edge.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).context("create cert dir")?;
    let config_path = path.join("agent.toml");
    let config = format!(
        r#"
email = "admin@example.com"
server = "{acme_directory_url}"
domain = "trusted.domain"

[acme]
http_responder_url = "{responder_url}"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300
directory_fetch_attempts = 1
directory_fetch_base_delay_secs = 1
directory_fetch_max_delay_secs = 1
poll_attempts = 1
poll_interval_secs = 1

[retry]
backoff_secs = [1]

[[profiles]]
service_name = "edge"
instance_id = "001"
hostname = "node-01"

[profiles.paths]
cert = "{cert_path}"
key = "{key_path}"

[trust]
verify_certificates = false
"#,
        acme_directory_url = acme_directory_url,
        responder_url = responder_url,
        cert_path = cert_path.display(),
        key_path = key_path.display(),
    );
    fs::write(&config_path, config).context("write agent config")?;
    let loaded =
        config::Settings::new(Some(config_path.clone())).context("parse written config")?;
    assert_eq!(loaded.profiles.len(), 1);
    Ok((config_path, cert_path))
}

async fn run_agent_oneshot(config_path: &Path, ca_url: &str, insecure: bool) -> Output {
    let config_path = config_path.to_path_buf();
    let ca_url = ca_url.to_string();
    tokio::task::spawn_blocking(move || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bootroot-agent"));
        cmd.args([
            "--config",
            config_path.to_string_lossy().as_ref(),
            "--oneshot",
        ]);
        if !ca_url.is_empty() {
            cmd.args(["--ca-url", ca_url.as_str()]);
        }
        if insecure {
            cmd.arg("--insecure");
        }
        let mut child = cmd
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn bootroot-agent");

        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match child.try_wait().expect("try_wait bootroot-agent") {
                Some(_) => {
                    return child
                        .wait_with_output()
                        .expect("collect bootroot-agent output");
                }
                None if Instant::now() < deadline => thread::sleep(Duration::from_millis(100)),
                None => {
                    let _ = child.kill();
                    let output = child
                        .wait_with_output()
                        .expect("collect timed out bootroot-agent output");
                    panic!(
                        "bootroot-agent timed out\nstdout:\n{}\nstderr:\n{}",
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
            }
        }
    })
    .await
    .expect("join run_agent_oneshot")
}

#[tokio::test]
async fn oneshot_normal_run_auto_hardens_verify_flag() -> Result<()> {
    let fixture = start_acme_tls_fixture().await?;
    assert_fixture_reachable(&fixture.directory_url()).await;
    let tmp = tempdir().context("create tempdir")?;
    let responder = MockServer::start().await;
    mount_responder_admin_mock(&responder).await;
    let (config_path, cert_path) =
        write_agent_config(tmp.path(), &fixture.directory_url(), &responder.uri())?;

    let output = run_agent_oneshot(&config_path, "", false).await;
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let updated = fs::read_to_string(&config_path).context("read updated agent config")?;
    assert!(updated.contains("verify_certificates = true"));
    assert!(cert_path.exists());

    fixture.handle.abort();
    Ok(())
}

#[tokio::test]
async fn oneshot_insecure_then_normal_enforces_hardening() -> Result<()> {
    let fixture = start_acme_tls_fixture().await?;
    assert_fixture_reachable(&fixture.directory_url()).await;
    let tmp = tempdir().context("create tempdir")?;
    let responder = MockServer::start().await;
    mount_responder_admin_mock(&responder).await;
    let (config_path, _cert_path) =
        write_agent_config(tmp.path(), &fixture.directory_url(), &responder.uri())?;

    let insecure_output = run_agent_oneshot(&config_path, "", true).await;
    assert!(
        insecure_output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&insecure_output.stdout),
        String::from_utf8_lossy(&insecure_output.stderr)
    );
    let after_insecure = fs::read_to_string(&config_path).context("read config after insecure")?;
    assert!(after_insecure.contains("verify_certificates = false"));

    let normal_output = run_agent_oneshot(&config_path, "", false).await;
    assert!(
        normal_output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&normal_output.stdout),
        String::from_utf8_lossy(&normal_output.stderr)
    );
    let after_normal = fs::read_to_string(&config_path).context("read config after normal")?;
    assert!(after_normal.contains("verify_certificates = true"));

    fixture.handle.abort();
    Ok(())
}

#[tokio::test]
async fn oneshot_hardening_write_failure_exits_non_zero() -> Result<()> {
    let fixture = start_acme_tls_fixture().await?;
    assert_fixture_reachable(&fixture.directory_url()).await;
    let tmp = tempdir().context("create tempdir")?;
    let responder = MockServer::start().await;
    mount_responder_admin_mock(&responder).await;
    let (config_path, _cert_path) =
        write_agent_config(tmp.path(), &fixture.directory_url(), &responder.uri())?;

    let mut perms = fs::metadata(&config_path)?.permissions();
    perms.set_mode(0o400);
    fs::set_permissions(&config_path, perms).context("make config read-only")?;

    let output = run_agent_oneshot(&config_path, "", false).await;
    assert!(
        !output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let merged = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(merged.contains("TLS hardening") || merged.contains("Failed to issue certificate"));

    fixture.handle.abort();
    Ok(())
}
