#![cfg(unix)]

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bootroot::config;
use rcgen::generate_simple_self_signed;
use reqwest::Certificate;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

struct AcmeTlsFixture {
    addr: SocketAddr,
    ca_pem: String,
    ca_sha256: String,
    handle: JoinHandle<()>,
}

impl AcmeTlsFixture {
    fn directory_url(&self) -> String {
        format!("https://localhost:{}/directory", self.addr.port())
    }

    fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    fn ca_sha256(&self) -> &str {
        &self.ca_sha256
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut output = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("hex write");
    }
    output
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

async fn assert_fixture_reachable(directory_url: &str, ca_pem: &str) {
    let ca_cert = Certificate::from_pem(ca_pem.as_bytes()).expect("parse fixture CA certificate");
    let client = reqwest::Client::builder()
        .add_root_certificate(ca_cert)
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

#[test]
fn bootroot_agent_rejects_removed_verify_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot-agent"))
        .arg("--verify-certificates")
        .output()
        .expect("run bootroot-agent");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(
        stderr.contains("--verify-certificates"),
        "stderr:\n{stderr}"
    );
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
            vec![rustls::pki_types::CertificateDer::from(cert_der.clone())],
            rustls::pki_types::PrivateKeyDer::from(rustls::pki_types::PrivatePkcs8KeyDer::from(
                key_der,
            )),
        )
        .context("build tls config")?;

    let listener = TcpListener::bind("localhost:0")
        .await
        .context("bind fixture listener")?;
    let addr = listener.local_addr().context("fixture local addr")?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let base = format!("https://localhost:{}", addr.port());
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

    Ok(AcmeTlsFixture {
        addr,
        ca_pem: cert_pem,
        ca_sha256: sha256_hex(&cert_der),
        handle,
    })
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
    trust: Option<(&str, &str)>,
) -> Result<(PathBuf, PathBuf, PathBuf)> {
    let cert_dir = path.join("certs");
    let cert_path = cert_dir.join("edge.crt");
    let key_path = cert_dir.join("edge.key");
    let bundle_path = cert_dir.join("ca-bundle.pem");
    fs::create_dir_all(&cert_dir).context("create cert dir")?;
    let trust_block = if let Some((bundle_pem, fingerprint)) = trust {
        fs::write(&bundle_path, bundle_pem).context("write ca bundle")?;
        format!(
            "\n[trust]\nca_bundle_path = \"{}\"\ntrusted_ca_sha256 = [\"{fingerprint}\"]\n",
            bundle_path.display()
        )
    } else {
        String::new()
    };
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
key = "{key_path}"{trust_block}
"#,
        cert_path = cert_path.display(),
        key_path = key_path.display(),
    );
    fs::write(&config_path, &config).context("write agent config")?;
    let loaded =
        config::Settings::new(Some(config_path.clone())).context("parse written config")?;
    assert_eq!(loaded.profiles.len(), 1);
    Ok((config_path, cert_path, bundle_path))
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
async fn oneshot_normal_run_uses_prestaged_trust_without_rewriting_config() -> Result<()> {
    let fixture = start_acme_tls_fixture().await?;
    assert_fixture_reachable(&fixture.directory_url(), fixture.ca_pem()).await;
    let tmp = tempdir().context("create tempdir")?;
    let responder = MockServer::start().await;
    mount_responder_admin_mock(&responder).await;
    let (config_path, cert_path, bundle_path) = write_agent_config(
        tmp.path(),
        &fixture.directory_url(),
        &responder.uri(),
        Some((fixture.ca_pem(), fixture.ca_sha256())),
    )?;
    let before = fs::read_to_string(&config_path).context("read config before run")?;

    let output = run_agent_oneshot(&config_path, "", false).await;
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let after = fs::read_to_string(&config_path).context("read config after run")?;
    assert_eq!(before, after);
    assert!(cert_path.exists());
    assert!(bundle_path.exists());

    fixture.handle.abort();
    Ok(())
}

#[tokio::test]
async fn oneshot_insecure_override_allows_untrusted_server() -> Result<()> {
    let fixture = start_acme_tls_fixture().await?;
    assert_fixture_reachable(&fixture.directory_url(), fixture.ca_pem()).await;
    let tmp = tempdir().context("create tempdir")?;
    let responder = MockServer::start().await;
    mount_responder_admin_mock(&responder).await;
    let (config_path, cert_path, bundle_path) =
        write_agent_config(tmp.path(), &fixture.directory_url(), &responder.uri(), None)?;
    let before = fs::read_to_string(&config_path).context("read config before run")?;

    let output = run_agent_oneshot(&config_path, "", true).await;
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let after = fs::read_to_string(&config_path).context("read config after run")?;
    assert_eq!(before, after);
    assert!(cert_path.exists());
    assert!(!bundle_path.exists());

    fixture.handle.abort();
    Ok(())
}

#[tokio::test]
async fn oneshot_normal_run_without_trust_fails() -> Result<()> {
    let fixture = start_acme_tls_fixture().await?;
    assert_fixture_reachable(&fixture.directory_url(), fixture.ca_pem()).await;
    let tmp = tempdir().context("create tempdir")?;
    let responder = MockServer::start().await;
    mount_responder_admin_mock(&responder).await;
    let (config_path, _cert_path, _bundle_path) =
        write_agent_config(tmp.path(), &fixture.directory_url(), &responder.uri(), None)?;

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
    assert!(
        merged.contains("certificate") || merged.contains("Failed to issue certificate"),
        "{merged}"
    );

    fixture.handle.abort();
    Ok(())
}
