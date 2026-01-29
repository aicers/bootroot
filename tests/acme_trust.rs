use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use bootroot::acme::client::AcmeClient;
use bootroot::config::{AcmeSettings, TrustSettings};
use rcgen::generate_simple_self_signed;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

struct TlsTestServer {
    addr: SocketAddr,
    cert_der: Vec<u8>,
    cert_pem: String,
    handle: JoinHandle<()>,
}

impl TlsTestServer {
    fn url(&self) -> String {
        format!("https://localhost:{}", self.addr.port())
    }
}

async fn start_tls_server() -> Result<TlsTestServer> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()])
            .context("generate self-signed cert")?;
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

    let listener = TcpListener::bind("127.0.0.1:0").await.context("bind tcp")?;
    let addr = listener.local_addr().context("local addr")?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buffer = [0u8; 4096];
                let read = match stream.read(&mut buffer).await {
                    Ok(0) | Err(_) => return,
                    Ok(value) => value,
                };
                let request = String::from_utf8_lossy(&buffer[..read]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                let body = if path == "/directory" {
                    let base = format!("https://localhost:{}", addr.port());
                    format!(
                        r#"{{"newNonce":"{base}/nonce","newAccount":"{base}/account","newOrder":"{base}/order"}}"#
                    )
                } else {
                    String::new()
                };
                let status = if path == "/directory" {
                    "200 OK"
                } else {
                    "404 Not Found"
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });

    Ok(TlsTestServer {
        addr,
        cert_der,
        cert_pem,
        handle,
    })
}

fn test_settings() -> AcmeSettings {
    AcmeSettings {
        directory_fetch_attempts: 1,
        directory_fetch_base_delay_secs: 0,
        directory_fetch_max_delay_secs: 0,
        poll_attempts: 1,
        poll_interval_secs: 1,
        http_responder_url: "http://localhost:8080".to_string(),
        http_responder_hmac: "dev-hmac".to_string(),
        http_responder_timeout_secs: 5,
        http_responder_token_ttl_secs: 300,
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

fn write_ca_bundle(cert_pem: &str, dir: &tempfile::TempDir) -> Result<PathBuf> {
    let path = dir.path().join("ca-bundle.pem");
    std::fs::write(&path, cert_pem).context("write bundle")?;
    Ok(path)
}

#[tokio::test]
async fn acme_trust_allows_insecure_when_disabled() -> Result<()> {
    let server = start_tls_server().await?;
    let trust = TrustSettings {
        verify_certificates: false,
        ..TrustSettings::default()
    };
    let mut client = AcmeClient::new(
        format!("{}/directory", server.url()),
        &test_settings(),
        &trust,
    )?;
    client.fetch_directory().await?;
    server.handle.abort();
    Ok(())
}

#[tokio::test]
async fn acme_trust_rejects_self_signed_without_trust() -> Result<()> {
    let server = start_tls_server().await?;
    let trust = TrustSettings {
        verify_certificates: true,
        ..TrustSettings::default()
    };
    let mut client = AcmeClient::new(
        format!("{}/directory", server.url()),
        &test_settings(),
        &trust,
    )?;
    assert!(client.fetch_directory().await.is_err());
    server.handle.abort();
    Ok(())
}

#[tokio::test]
async fn acme_trust_accepts_bundle_and_pin() -> Result<()> {
    let server = start_tls_server().await?;
    let dir = tempfile::tempdir().context("tempdir")?;
    let bundle_path = write_ca_bundle(&server.cert_pem, &dir)?;
    let trust = TrustSettings {
        verify_certificates: true,
        ca_bundle_path: Some(bundle_path),
        trusted_ca_sha256: vec![sha256_hex(&server.cert_der)],
    };

    let mut client = AcmeClient::new(
        format!("{}/directory", server.url()),
        &test_settings(),
        &trust,
    )?;
    client.fetch_directory().await?;
    server.handle.abort();
    Ok(())
}

#[tokio::test]
async fn acme_trust_rejects_pin_mismatch() -> Result<()> {
    let server = start_tls_server().await?;
    let dir = tempfile::tempdir().context("tempdir")?;
    let bundle_path = write_ca_bundle(&server.cert_pem, &dir)?;
    let trust = TrustSettings {
        verify_certificates: true,
        ca_bundle_path: Some(bundle_path),
        trusted_ca_sha256: vec!["00".repeat(32)],
    };

    let mut client = AcmeClient::new(
        format!("{}/directory", server.url()),
        &test_settings(),
        &trust,
    )?;
    assert!(client.fetch_directory().await.is_err());
    server.handle.abort();
    Ok(())
}
