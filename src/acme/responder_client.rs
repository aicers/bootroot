use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use reqwest::Client;

use super::http01_protocol::{HEADER_SIGNATURE, HEADER_TIMESTAMP, Http01HmacSigner};
use crate::config::Settings;

const DEFAULT_ADMIN_PATH: &str = "/admin/http01";

/// Trust parameters for TLS-pinned responder connections.
///
/// When the responder URL is `https://`, the client uses `ca_pem` as the
/// trust anchor and enforces any SHA-256 certificate pins in `ca_pins`.
pub struct ResponderTrust<'a> {
    /// PEM-encoded CA bundle.
    pub ca_pem: &'a str,
    /// SHA-256 certificate fingerprints to enforce (may be empty).
    pub ca_pins: &'a [String],
}

#[derive(serde::Serialize)]
struct RegisterRequest<'a> {
    token: &'a str,
    key_authorization: &'a str,
    ttl_secs: u64,
}

/// Registers an HTTP-01 token with the responder.
///
/// Reads trust configuration from [`Settings::trust`] only when the responder
/// URL uses `https://`. For plain `http://` URLs the trust settings are ignored
/// and a default client is used.
///
/// # Errors
///
/// Returns an error if the request cannot be sent, if the responder returns a
/// non-success status, or if time encoding fails.
pub async fn register_http01_token(
    settings: &Settings,
    token: &str,
    key_authorization: &str,
) -> Result<()> {
    let url = settings.acme.http_responder_url.trim_end_matches('/');
    let ttl_secs = settings.acme.http_responder_token_ttl_secs;
    let ca_pem = if url.starts_with("https://") {
        read_ca_pem_from_trust(&settings.trust)?
    } else {
        None
    };
    let trust = ca_pem.as_deref().map(|pem| ResponderTrust {
        ca_pem: pem,
        ca_pins: &settings.trust.trusted_ca_sha256,
    });
    register_http01_token_with(
        url,
        &settings.acme.http_responder_hmac,
        settings.acme.http_responder_timeout_secs,
        token,
        key_authorization,
        ttl_secs,
        trust.as_ref(),
    )
    .await
}

/// Reads the CA bundle PEM from disk when [`TrustSettings::ca_bundle_path`] is set.
fn read_ca_pem_from_trust(trust: &crate::config::TrustSettings) -> Result<Option<String>> {
    let Some(path) = trust.ca_bundle_path.as_ref() else {
        return Ok(None);
    };
    let pem = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Failed to read CA bundle at {}: {e}", path.display()))?;
    Ok(Some(pem))
}

/// Registers an HTTP-01 token with explicit connection details.
///
/// When `trust` is `Some`, the client anchors TLS to the embedded CA bundle
/// and enforces any SHA-256 certificate pins. When the URL uses `https://`
/// and `trust` is `None`, the call fails with a clear error rather than
/// falling back to the system trust store.
///
/// # Errors
/// Returns an error if the request cannot be sent or the responder rejects it.
pub async fn register_http01_token_with(
    base_url: &str,
    hmac_secret: &str,
    timeout_secs: u64,
    token: &str,
    key_authorization: &str,
    ttl_secs: u64,
    trust: Option<&ResponderTrust<'_>>,
) -> Result<()> {
    let url = base_url.trim_end_matches('/');
    let endpoint = format!("{url}{DEFAULT_ADMIN_PATH}");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("Failed to read system time: {e}"))?
        .as_secs();
    let timestamp = i64::try_from(timestamp)
        .map_err(|_| anyhow::anyhow!("System time is too large for timestamp"))?;

    let signer = Http01HmacSigner::new(hmac_secret);
    let signature = signer.sign_request(timestamp, token, key_authorization, ttl_secs);

    let client = build_responder_client(base_url, timeout_secs, trust)?;

    let body = RegisterRequest {
        token,
        key_authorization,
        ttl_secs,
    };

    let response = client
        .post(endpoint)
        .header(HEADER_TIMESTAMP, timestamp.to_string())
        .header(HEADER_SIGNATURE, signature)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to register HTTP-01 token: {e}"))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("Responder returned {status}: {body}");
    }

    Ok(())
}

/// Builds a [`Client`] for the responder admin API.
///
/// For `https://` URLs the client is pinned to the given CA PEM bundle with
/// optional SHA-256 certificate pins; a missing trust source is a
/// misconfiguration error. For `http://` URLs a plain client is returned and
/// trust parameters are ignored.
fn build_responder_client(
    base_url: &str,
    timeout_secs: u64,
    trust: Option<&ResponderTrust<'_>>,
) -> Result<Client> {
    if base_url.starts_with("https://") {
        let trust = trust.ok_or_else(|| {
            anyhow::anyhow!(
                "HTTPS responder URL requires a CA trust anchor; \
                 configure trust.ca_bundle_path or supply a CA PEM via the bootstrap artifact"
            )
        })?;
        let tls_config = crate::tls::build_client_config_from_pem(trust.ca_pem, trust.ca_pins)?;
        Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .use_preconfigured_tls(tls_config)
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build TLS responder client: {e}"))
    } else {
        Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|e| anyhow::anyhow!("Failed to build responder client: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;
    use crate::acme::http01_protocol::{Http01HmacSigner, signature_payload};

    #[derive(serde::Deserialize)]
    struct ReceivedRequest {
        token: String,
        key_authorization: String,
        ttl_secs: u64,
    }

    struct SignatureResponder {
        secret: String,
    }

    impl Respond for SignatureResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let Some(timestamp) = request.headers.get(HEADER_TIMESTAMP) else {
                return ResponseTemplate::new(400).set_body_string("Missing timestamp");
            };
            let Some(signature) = request.headers.get(HEADER_SIGNATURE) else {
                return ResponseTemplate::new(400).set_body_string("Missing signature");
            };

            let Some(timestamp) = timestamp
                .to_str()
                .ok()
                .and_then(|value| value.parse::<i64>().ok())
            else {
                return ResponseTemplate::new(400).set_body_string("Invalid timestamp");
            };

            let Ok(body) = serde_json::from_slice::<ReceivedRequest>(&request.body) else {
                return ResponseTemplate::new(400).set_body_string("Invalid JSON");
            };

            let payload = signature_payload(
                timestamp,
                &body.token,
                &body.key_authorization,
                body.ttl_secs,
            );
            let expected = Http01HmacSigner::new(&self.secret).sign_payload(&payload);

            let Ok(signature) = signature.to_str() else {
                return ResponseTemplate::new(400).set_body_string("Invalid signature");
            };
            if expected != signature {
                return ResponseTemplate::new(401).set_body_string("Invalid signature");
            }

            ResponseTemplate::new(200).set_body_string("ok")
        }
    }

    fn test_settings(base_url: &str, secret: &str) -> Settings {
        let mut settings = Settings::new(None).expect("settings must load");
        settings.acme.http_responder_url = base_url.to_string();
        settings.acme.http_responder_hmac = secret.to_string();
        settings.acme.http_responder_timeout_secs = 5;
        settings.acme.http_responder_token_ttl_secs = 60;
        settings
    }

    #[tokio::test]
    async fn test_register_http01_token_sends_signature() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(DEFAULT_ADMIN_PATH))
            .respond_with(SignatureResponder {
                secret: "test-secret".to_string(),
            })
            .mount(&server)
            .await;

        let settings = test_settings(&server.uri(), "test-secret");
        register_http01_token(&settings, "token-1", "token-1.key")
            .await
            .expect("register should succeed");
    }

    #[tokio::test]
    async fn test_register_http01_token_reports_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(DEFAULT_ADMIN_PATH))
            .respond_with(ResponseTemplate::new(500).set_body_string("boom"))
            .mount(&server)
            .await;

        let settings = test_settings(&server.uri(), "test-secret");
        let err = register_http01_token(&settings, "token-2", "token-2.key")
            .await
            .expect_err("register should fail");
        assert!(err.to_string().contains("Responder returned"));
    }

    #[tokio::test]
    async fn test_register_http01_token_with_rejects_https_without_trust() {
        let err = register_http01_token_with(
            "https://responder.internal:8080",
            "hmac-secret",
            5,
            "tok",
            "tok.key",
            60,
            None,
        )
        .await
        .expect_err("HTTPS without trust should fail");
        assert!(
            err.to_string().contains("HTTPS responder URL requires"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn test_register_http01_token_http_ignores_broken_trust_path() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(DEFAULT_ADMIN_PATH))
            .respond_with(SignatureResponder {
                secret: "test-secret".to_string(),
            })
            .mount(&server)
            .await;

        let mut settings = test_settings(&server.uri(), "test-secret");
        settings.trust.ca_bundle_path = Some("/nonexistent/ca-bundle.pem".into());

        register_http01_token(&settings, "token-1", "token-1.key")
            .await
            .expect("http:// must succeed even with broken trust path");
    }

    /// Generates a self-signed CA and a `localhost` server certificate signed
    /// by that CA.  Returns `(ca_pem, ca_fingerprint, server_cert_der,
    /// server_key_der, ca_cert_der)`.
    fn generate_tls_responder_ca() -> (String, String, Vec<u8>, Vec<u8>, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        let ca_key = KeyPair::generate().expect("generate CA key");
        let mut ca_params = CertificateParams::new(Vec::new()).expect("cert params");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test Responder CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
        let ca_pem = ca_cert.pem();
        let ca_der = ca_cert.der().to_vec();

        let fingerprint = {
            let digest = ring::digest::digest(&ring::digest::SHA256, &ca_der);
            let mut hex = String::with_capacity(64);
            for byte in digest.as_ref() {
                use std::fmt::Write;
                write!(hex, "{byte:02x}").expect("hex write");
            }
            hex
        };

        let issuer = Issuer::new(ca_params, ca_key);
        let server_key = KeyPair::generate().expect("generate server key");
        let mut server_params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        server_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        server_params.is_ca = IsCa::NoCa;
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("signed server cert");

        (
            ca_pem,
            fingerprint,
            server_cert.der().to_vec(),
            server_key.serialize_der(),
            ca_der,
        )
    }

    /// Starts a minimal HTTPS responder that returns `200 OK` for any request.
    async fn start_tls_responder(
        server_cert_der: Vec<u8>,
        server_key_der: Vec<u8>,
        ca_cert_der: Vec<u8>,
    ) -> u16 {
        use std::sync::Arc;

        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let server_cert = CertificateDer::from(server_cert_der);
        let ca_cert = CertificateDer::from(ca_cert_der);
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der));

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![server_cert, ca_cert], key)
            .expect("server TLS config");

        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("local addr").port();

        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = vec![0u8; 8192];
                    let _ = tls.read(&mut buf).await;
                    let response =
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
                    let _ = tls.write_all(response.as_bytes()).await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        port
    }

    #[tokio::test]
    async fn test_responder_tls_correct_pin_succeeds() {
        let (ca_pem, ca_fingerprint, server_cert_der, server_key_der, ca_der) =
            generate_tls_responder_ca();
        let port = start_tls_responder(server_cert_der, server_key_der, ca_der).await;

        let pins = vec![ca_fingerprint];
        let trust = ResponderTrust {
            ca_pem: &ca_pem,
            ca_pins: &pins,
        };
        register_http01_token_with(
            &format!("https://localhost:{port}"),
            "hmac-secret",
            5,
            "tok",
            "tok.key",
            60,
            Some(&trust),
        )
        .await
        .expect("correct pin should allow TLS handshake");
    }

    #[tokio::test]
    async fn test_responder_tls_wrong_pin_rejected() {
        let (ca_pem, _ca_fingerprint, server_cert_der, server_key_der, ca_der) =
            generate_tls_responder_ca();
        let port = start_tls_responder(server_cert_der, server_key_der, ca_der).await;

        let pins = vec!["00".repeat(32)];
        let trust = ResponderTrust {
            ca_pem: &ca_pem,
            ca_pins: &pins,
        };
        let err = register_http01_token_with(
            &format!("https://localhost:{port}"),
            "hmac-secret",
            5,
            "tok",
            "tok.key",
            60,
            Some(&trust),
        )
        .await
        .expect_err("wrong pin should reject TLS handshake");
        assert!(
            err.to_string().contains("Failed to register HTTP-01 token"),
            "unexpected error: {err}"
        );
    }
}
