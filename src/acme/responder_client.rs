use std::error::Error as StdError;
use std::future::Future;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use reqwest::{Client, StatusCode};
use tokio::time::{Instant, sleep};

use super::http01_protocol::{HEADER_SIGNATURE, HEADER_TIMESTAMP, Http01HmacSigner};
use crate::config::Settings;

const DEFAULT_ADMIN_PATH: &str = "/admin/http01";
/// Delay between readiness attempts while the responder refuses connections.
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(500);

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

/// Everything one registration request needs, so the readiness wait can
/// replay the very same call without a long argument list.
pub struct ResponderRegistration<'a> {
    /// Responder admin base URL, with or without a trailing slash.
    pub base_url: &'a str,
    /// Shared HMAC secret used to sign the request.
    pub hmac_secret: &'a str,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
    /// HTTP-01 challenge token to register.
    pub token: &'a str,
    /// Key authorization served for `token`.
    pub key_authorization: &'a str,
    /// Lifetime of the registration in seconds.
    pub ttl_secs: u64,
    /// TLS trust anchors, required for `https://` responders.
    pub trust: Option<&'a ResponderTrust<'a>>,
}

/// Outcome of a single registration attempt against the responder.
///
/// The variants exist so callers can distinguish "the responder could not be
/// reached" — which may simply mean it has not finished binding its admin
/// port — from "the responder answered and refused", which is a
/// configuration error that no amount of waiting fixes.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    /// The request could not even be built (bad system time, missing TLS
    /// trust anchor, unusable CA bundle).  Never retryable.
    #[error("{0}")]
    Setup(String),
    /// The request never reached the responder.  The payload is the full
    /// error chain, because the root cause (connection refused versus a TLS
    /// trust or pin failure) is what tells a slow start apart from a
    /// misconfiguration.
    #[error("Failed to register HTTP-01 token: {0}")]
    Transport(String),
    /// The responder answered with a non-success status.
    #[error("Responder returned {status}: {body}")]
    Status {
        /// Status line returned by the responder.
        status: StatusCode,
        /// Response body, truncated by the responder itself if at all.
        body: String,
    },
}

/// Terminal outcome of a bounded readiness wait for the responder.
#[derive(Debug, thiserror::Error)]
pub enum ResponderReadyError {
    /// The readiness budget was zero, so no attempt could ever be made.
    #[error("Responder readiness timeout must be greater than 0 seconds")]
    ZeroBudget,
    /// The readiness budget ran out with every attempt failing in transport.
    #[error(
        "HTTP-01 responder at {endpoint} was still unreachable after {elapsed_secs}s: {last_error}"
    )]
    Unreachable {
        /// Admin endpoint that was polled.
        endpoint: String,
        /// Seconds actually spent waiting.
        elapsed_secs: u64,
        /// Error chain of the last failed attempt.
        last_error: String,
    },
    /// The responder answered with a non-success status.
    #[error("HTTP-01 responder at {endpoint} returned {status}: {body}")]
    Rejected {
        /// Admin endpoint that answered.
        endpoint: String,
        /// Status returned by the responder.
        status: StatusCode,
        /// Response body.
        body: String,
    },
    /// The request could not be built at all.
    #[error("{0}")]
    Setup(String),
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
    .await?;
    Ok(())
}

/// Reads the CA bundle PEM from disk when `TrustSettings::ca_bundle_path` is set.
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
/// Sends exactly one request; callers that need to tolerate a responder that
/// has not finished starting use [`register_http01_token_until_ready`].
///
/// # Errors
/// Returns [`RegisterError::Transport`] if the request cannot be sent,
/// [`RegisterError::Status`] if the responder answers with a non-success
/// status, and [`RegisterError::Setup`] if the request cannot be built.
pub async fn register_http01_token_with(
    base_url: &str,
    hmac_secret: &str,
    timeout_secs: u64,
    token: &str,
    key_authorization: &str,
    ttl_secs: u64,
    trust: Option<&ResponderTrust<'_>>,
) -> Result<(), RegisterError> {
    register_once(&ResponderRegistration {
        base_url,
        hmac_secret,
        timeout_secs,
        token,
        key_authorization,
        ttl_secs,
        trust,
    })
    .await
}

/// Registers an HTTP-01 token, retrying while the responder is unreachable.
///
/// Retries only the transport failure — a responder that has not yet bound
/// its admin port — at [`READINESS_POLL_INTERVAL`] until `ready_timeout` is
/// spent.  A non-success status means the URL or the HMAC is wrong, so it
/// fails immediately without consuming the budget.
///
/// Every attempt goes through [`register_http01_token_with`], which computes
/// its own timestamp and signature, so a wait longer than the responder's
/// `max_skew_secs` never turns into a skew rejection.
///
/// # Errors
/// Returns [`ResponderReadyError::ZeroBudget`] for an empty budget,
/// [`ResponderReadyError::Unreachable`] when the budget is exhausted,
/// [`ResponderReadyError::Rejected`] on a non-success status, and
/// [`ResponderReadyError::Setup`] when the request cannot be built.
pub async fn register_http01_token_until_ready(
    registration: &ResponderRegistration<'_>,
    ready_timeout: Duration,
) -> Result<(), ResponderReadyError> {
    let endpoint = admin_endpoint(registration.base_url);
    // Build the client up front: it is the only part of an attempt that
    // cannot fail because of a slow responder, so a bad TLS trust anchor
    // must not be re-tried once per poll interval.
    let client = build_responder_client(
        registration.base_url,
        registration.timeout_secs,
        registration.trust,
    )
    .map_err(|e| ResponderReadyError::Setup(format!("{e:#}")))?;
    wait_for_registration(&endpoint, ready_timeout, || {
        send_registration(registration, &client)
    })
    .await
}

/// Drives `attempt` until it succeeds, fails terminally, or the readiness
/// budget runs out.
async fn wait_for_registration<F, Fut>(
    endpoint: &str,
    ready_timeout: Duration,
    mut attempt: F,
) -> Result<(), ResponderReadyError>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<(), RegisterError>>,
{
    if ready_timeout.is_zero() {
        return Err(ResponderReadyError::ZeroBudget);
    }

    let start = Instant::now();
    loop {
        let last_error = match attempt().await {
            Ok(()) => return Ok(()),
            Err(RegisterError::Transport(error)) => error,
            Err(RegisterError::Status { status, body }) => {
                return Err(ResponderReadyError::Rejected {
                    endpoint: endpoint.to_string(),
                    status,
                    body,
                });
            }
            Err(RegisterError::Setup(message)) => {
                return Err(ResponderReadyError::Setup(message));
            }
        };

        let elapsed = start.elapsed();
        if elapsed >= ready_timeout {
            return Err(ResponderReadyError::Unreachable {
                endpoint: endpoint.to_string(),
                elapsed_secs: elapsed.as_secs(),
                last_error,
            });
        }
        sleep(READINESS_POLL_INTERVAL.min(ready_timeout.saturating_sub(elapsed))).await;
    }
}

/// Builds the admin endpoint URL for a responder base URL.
fn admin_endpoint(base_url: &str) -> String {
    let url = base_url.trim_end_matches('/');
    format!("{url}{DEFAULT_ADMIN_PATH}")
}

/// Builds a client and sends exactly one registration request with it.
async fn register_once(registration: &ResponderRegistration<'_>) -> Result<(), RegisterError> {
    let client = build_responder_client(
        registration.base_url,
        registration.timeout_secs,
        registration.trust,
    )
    .map_err(|e| RegisterError::Setup(format!("{e:#}")))?;
    send_registration(registration, &client).await
}

/// Sends exactly one registration request over `client`.
///
/// The timestamp and the signature are computed here rather than by the
/// caller, so every retry of the readiness wait carries fresh credentials.
async fn send_registration(
    registration: &ResponderRegistration<'_>,
    client: &Client,
) -> Result<(), RegisterError> {
    let endpoint = admin_endpoint(registration.base_url);

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| RegisterError::Setup(format!("Failed to read system time: {e}")))?
        .as_secs();
    let timestamp = i64::try_from(timestamp)
        .map_err(|_| RegisterError::Setup("System time is too large for timestamp".to_string()))?;

    let signer = Http01HmacSigner::new(registration.hmac_secret);
    let signature = signer.sign_request(
        timestamp,
        registration.token,
        registration.key_authorization,
        registration.ttl_secs,
    );

    let body = RegisterRequest {
        token: registration.token,
        key_authorization: registration.key_authorization,
        ttl_secs: registration.ttl_secs,
    };

    let response = client
        .post(endpoint)
        .header(HEADER_TIMESTAMP, timestamp.to_string())
        .header(HEADER_SIGNATURE, signature)
        .json(&body)
        .send()
        .await
        .map_err(|e| RegisterError::Transport(error_chain(&e)))?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(RegisterError::Status { status, body });
    }

    Ok(())
}

/// Renders an error and its sources as a single `a: b: c` line.
///
/// `reqwest` reports every send failure as the same "error sending request"
/// message and hides the real cause — connection refused, TLS trust failure,
/// pin mismatch — one level down, so the chain is what an operator needs.
fn error_chain(error: &dyn StdError) -> String {
    let mut rendered = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        use std::fmt::Write;

        let _ = write!(rendered, ": {cause}");
        source = cause.source();
    }
    rendered
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;
    use crate::acme::http01_protocol::{Http01HmacSigner, signature_payload};

    const TEST_ENDPOINT: &str = "http://responder.test:8080/admin/http01";
    const TEST_HMAC: &str = "test-secret";
    /// Freshness window enforced by [`FreshnessResponder`]; must stay well
    /// below the delay before the late listener binds.
    const TEST_MAX_SKEW_SECS: i64 = 1;

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
            verify_signed_request(&self.secret, request, None)
        }
    }

    /// Signature responder that also mirrors the production responder's
    /// `within_skew` rule, so a request signed once and replayed later is
    /// rejected exactly as the real responder rejects it.
    struct FreshnessResponder {
        secret: String,
        max_skew_secs: i64,
    }

    impl Respond for FreshnessResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            verify_signed_request(&self.secret, request, Some(self.max_skew_secs))
        }
    }

    fn verify_signed_request(
        secret: &str,
        request: &Request,
        max_skew_secs: Option<i64>,
    ) -> ResponseTemplate {
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
        let expected = Http01HmacSigner::new(secret).sign_payload(&payload);

        let Ok(signature) = signature.to_str() else {
            return ResponseTemplate::new(400).set_body_string("Invalid signature");
        };
        if expected != signature {
            return ResponseTemplate::new(401).set_body_string("Invalid signature");
        }

        if let Some(max_skew_secs) = max_skew_secs {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time is after the unix epoch")
                .as_secs();
            let now = i64::try_from(now).expect("system time fits in i64");
            if (now - timestamp).abs() > max_skew_secs {
                return ResponseTemplate::new(401).set_body_string("Stale timestamp");
            }
        }

        ResponseTemplate::new(200).set_body_string("ok")
    }

    /// Reserves a loopback address, frees it so early connections are
    /// refused, and re-binds a mock responder on that same address after
    /// `delay`.  Returns the responder base URL.
    fn spawn_late_responder<R: Respond + 'static>(delay: Duration, responder: R) -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve address");
        let addr = listener.local_addr().expect("local addr");
        drop(listener);

        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let listener = std::net::TcpListener::bind(addr).expect("re-bind reserved address");
            let server = MockServer::builder().listener(listener).start().await;
            Mock::given(method("POST"))
                .and(path(DEFAULT_ADMIN_PATH))
                .respond_with(responder)
                .mount(&server)
                .await;
            // Hold the server so the listener stays up until the test ends;
            // dropping it here would close the port again.
            std::future::pending::<()>().await;
            drop(server);
        });

        format!("http://{addr}")
    }

    fn test_registration<'a>(base_url: &'a str, token: &'a str) -> ResponderRegistration<'a> {
        ResponderRegistration {
            base_url,
            hmac_secret: TEST_HMAC,
            timeout_secs: 5,
            token,
            key_authorization: "readiness.key",
            ttl_secs: 60,
            trust: None,
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

    /// Starts a minimal HTTPS responder that returns `200 OK` for any request,
    /// presenting the leaf plus the CA certificate (a full-chain fixture).
    async fn start_tls_responder(
        server_cert_der: Vec<u8>,
        server_key_der: Vec<u8>,
        ca_cert_der: Vec<u8>,
    ) -> u16 {
        start_tls_responder_chain(vec![server_cert_der, ca_cert_der], server_key_der).await
    }

    /// Starts a minimal HTTPS responder presenting exactly the given
    /// certificate chain on the wire.  A single-element chain models the
    /// production leaf-only `server.crt` that `step certificate create` writes
    /// without `--bundle`.
    async fn start_tls_responder_chain(cert_chain: Vec<Vec<u8>>, server_key_der: Vec<u8>) -> u16 {
        use std::sync::Arc;

        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio_rustls::TlsAcceptor;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let chain = cert_chain.into_iter().map(CertificateDer::from).collect();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_key_der));

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
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

    /// Generates a self-signed CA and a `localhost` leaf certificate signed by
    /// it.  Returns `(ca_pem, ca_fingerprint, leaf_cert_der, leaf_key_der)`.
    fn generate_ca_with_leaf(ca_common_name: &str) -> (String, String, Vec<u8>, Vec<u8>) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        let ca_key = KeyPair::generate().expect("generate CA key");
        let mut ca_params = CertificateParams::new(Vec::new()).expect("cert params");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, ca_common_name);
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
        let leaf_key = KeyPair::generate().expect("generate leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        leaf_params.is_ca = IsCa::NoCa;
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("signed leaf cert");

        (
            ca_pem,
            fingerprint,
            leaf_cert.der().to_vec(),
            leaf_key.serialize_der(),
        )
    }

    /// Regression for #675: the production responder presents a **leaf-only**
    /// certificate (no bundled issuer), yet the pinned agent client must accept
    /// it because its issuer is pinned.  Before the verifier fix the presented
    /// chain held only the leaf, which matched no CA pin, so the handshake was
    /// wrongly rejected.
    #[tokio::test]
    async fn test_responder_tls_leaf_only_cert_accepted() {
        let (ca_pem, ca_fingerprint, leaf_cert_der, leaf_key_der) =
            generate_ca_with_leaf("Test Responder CA");
        let port = start_tls_responder_chain(vec![leaf_cert_der], leaf_key_der).await;

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
        .expect("leaf-only responder with a pinned issuer should be accepted");
    }

    /// Regression for #675: pinning must narrow trust to the pinned subset of a
    /// larger bundle.  A leaf chaining to a bundle CA that is **not** pinned is
    /// chain-valid against the full bundle yet must still be rejected.
    #[tokio::test]
    async fn test_responder_tls_non_pinned_bundle_ca_rejected() {
        let (pinned_ca_pem, pinned_ca_fingerprint, _pinned_leaf, _pinned_key) =
            generate_ca_with_leaf("Pinned CA");
        let (unpinned_ca_pem, _unpinned_fingerprint, unpinned_leaf_der, unpinned_key_der) =
            generate_ca_with_leaf("Unpinned CA");

        // The bundle trusts both CAs, but only the first CA is pinned.
        let bundle = format!("{pinned_ca_pem}{unpinned_ca_pem}");
        let pins = vec![pinned_ca_fingerprint];
        // The responder serves a leaf chaining to the non-pinned CA.
        let port = start_tls_responder_chain(vec![unpinned_leaf_der], unpinned_key_der).await;

        let trust = ResponderTrust {
            ca_pem: &bundle,
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
        .expect_err("leaf chaining to a non-pinned bundle CA must be rejected");
        assert!(
            err.to_string().contains("Failed to register HTTP-01 token"),
            "unexpected error: {err}"
        );
    }

    /// A responder that only starts answering after a few attempts must be
    /// waited out rather than treated as a terminal failure.
    #[tokio::test(start_paused = true)]
    async fn test_wait_for_registration_retries_transport_failures() {
        const FAILURES: usize = 3;

        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::clone(&calls);
        wait_for_registration(TEST_ENDPOINT, Duration::from_secs(30), move || {
            let attempts = Arc::clone(&attempts);
            async move {
                if attempts.fetch_add(1, Ordering::SeqCst) < FAILURES {
                    Err(RegisterError::Transport("connection refused".to_string()))
                } else {
                    Ok(())
                }
            }
        })
        .await
        .expect("a responder that becomes ready within the budget must succeed");

        assert_eq!(calls.load(Ordering::SeqCst), FAILURES + 1);
    }

    /// A non-success status is a wrong URL or a wrong HMAC: it must fail on
    /// the first answer instead of burning the readiness budget.
    #[tokio::test(start_paused = true)]
    async fn test_wait_for_registration_aborts_on_non_success_status() {
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::clone(&calls);
        let start = Instant::now();
        let err = wait_for_registration(TEST_ENDPOINT, Duration::from_secs(30), move || {
            let attempts = Arc::clone(&attempts);
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Err(RegisterError::Status {
                    status: StatusCode::UNAUTHORIZED,
                    body: "Invalid signature".to_string(),
                })
            }
        })
        .await
        .expect_err("a non-success status must fail immediately");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
        let ResponderReadyError::Rejected { status, body, .. } = &err else {
            panic!("expected a rejection, got: {err:?}");
        };
        assert_eq!(*status, StatusCode::UNAUTHORIZED);
        assert_eq!(body, "Invalid signature");
    }

    #[tokio::test(start_paused = true)]
    async fn test_wait_for_registration_gives_up_after_budget() {
        const BUDGET: Duration = Duration::from_secs(5);

        let start = Instant::now();
        let err = wait_for_registration(TEST_ENDPOINT, BUDGET, || async {
            Err(RegisterError::Transport(
                "error sending request: connection refused".to_string(),
            ))
        })
        .await
        .expect_err("an unreachable responder must exhaust the budget");
        let elapsed = start.elapsed();

        assert!(
            elapsed >= BUDGET && elapsed < BUDGET + READINESS_POLL_INTERVAL,
            "waited {elapsed:?}, expected roughly {BUDGET:?}"
        );
        let ResponderReadyError::Unreachable {
            endpoint,
            elapsed_secs,
            last_error,
        } = &err
        else {
            panic!("expected an unreachable responder, got: {err:?}");
        };
        assert_eq!(endpoint, TEST_ENDPOINT);
        assert_eq!(*elapsed_secs, BUDGET.as_secs());
        assert!(last_error.contains("connection refused"));

        let message = err.to_string();
        assert!(message.contains(TEST_ENDPOINT), "no endpoint in: {message}");
        assert!(message.contains("5s"), "no elapsed wait in: {message}");
        assert!(
            message.contains("connection refused"),
            "no transport cause in: {message}"
        );
    }

    /// The two terminal outcomes must be told apart by matching on the type,
    /// never by inspecting the rendered message.
    #[tokio::test(start_paused = true)]
    async fn test_terminal_readiness_errors_are_distinct_variants() {
        let unreachable = wait_for_registration(TEST_ENDPOINT, Duration::from_secs(1), || async {
            Err(RegisterError::Transport("connection refused".to_string()))
        })
        .await
        .expect_err("unreachable responder");
        let rejected = wait_for_registration(TEST_ENDPOINT, Duration::from_secs(1), || async {
            Err(RegisterError::Status {
                status: StatusCode::NOT_FOUND,
                body: String::new(),
            })
        })
        .await
        .expect_err("rejecting responder");

        assert!(matches!(
            unreachable,
            ResponderReadyError::Unreachable { .. }
        ));
        assert!(matches!(rejected, ResponderReadyError::Rejected { .. }));
        assert_ne!(
            std::mem::discriminant(&unreachable),
            std::mem::discriminant(&rejected)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn test_wait_for_registration_rejects_zero_budget() {
        let calls = Arc::new(AtomicUsize::new(0));
        let attempts = Arc::clone(&calls);
        let err = wait_for_registration(TEST_ENDPOINT, Duration::ZERO, move || {
            let attempts = Arc::clone(&attempts);
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        })
        .await
        .expect_err("a zero readiness budget must be rejected");

        assert!(matches!(err, ResponderReadyError::ZeroBudget));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert!(
            err.to_string().contains("greater than 0"),
            "unexpected error: {err}"
        );
    }

    /// End-to-end over a real socket: the responder is not listening when the
    /// wait starts, so early attempts are refused, and starts serving partway
    /// through the budget.
    #[tokio::test]
    async fn test_register_until_ready_waits_for_late_listener() {
        const BIND_DELAY: Duration = Duration::from_millis(700);

        let base_url = spawn_late_responder(
            BIND_DELAY,
            SignatureResponder {
                secret: TEST_HMAC.to_string(),
            },
        );

        // The single-shot entry point sees the same socket as unreachable,
        // and classifies it as the retryable transport failure.
        let err = register_http01_token_with(
            &base_url,
            TEST_HMAC,
            5,
            "readiness",
            "readiness.key",
            60,
            None,
        )
        .await
        .expect_err("nothing is listening yet");
        assert!(
            matches!(err, RegisterError::Transport(_)),
            "connection refused must be a transport failure, got: {err:?}"
        );

        register_http01_token_until_ready(
            &test_registration(&base_url, "readiness"),
            Duration::from_secs(30),
        )
        .await
        .expect("a responder that binds within the budget must be waited out");
    }

    /// A request that cannot even be built is not a slow start, so the
    /// readiness budget must not absorb it.
    #[tokio::test(start_paused = true)]
    async fn test_register_until_ready_fails_fast_without_trust() {
        let registration = ResponderRegistration {
            base_url: "https://responder.internal:8080",
            hmac_secret: TEST_HMAC,
            timeout_secs: 5,
            token: "tok",
            key_authorization: "tok.key",
            ttl_secs: 60,
            trust: None,
        };

        let start = Instant::now();
        let err = register_http01_token_until_ready(&registration, Duration::from_mins(1))
            .await
            .expect_err("HTTPS without trust should fail");

        assert_eq!(start.elapsed(), Duration::ZERO);
        assert!(matches!(err, ResponderReadyError::Setup(_)));
        assert!(
            err.to_string().contains("HTTPS responder URL requires"),
            "unexpected error: {err}"
        );
    }

    /// Every attempt must carry its own timestamp and signature: the mock
    /// enforces freshness the way the responder's `within_skew` does, so a
    /// request signed once before the loop would be rejected as stale by the
    /// time the responder starts answering.
    #[tokio::test]
    async fn test_register_until_ready_signs_every_attempt() {
        const BIND_DELAY: Duration = Duration::from_millis(2_500);

        let base_url = spawn_late_responder(
            BIND_DELAY,
            FreshnessResponder {
                secret: TEST_HMAC.to_string(),
                max_skew_secs: TEST_MAX_SKEW_SECS,
            },
        );

        register_http01_token_until_ready(
            &test_registration(&base_url, "resigned"),
            Duration::from_secs(30),
        )
        .await
        .expect("each attempt must carry a freshly computed timestamp and signature");

        // Guard against the assertion above passing vacuously: a request
        // signed as long ago as the wait lasted really is refused.
        let stale_offset =
            -i64::try_from(BIND_DELAY.as_secs()).expect("bind delay fits in i64") - 1;
        let status = post_with_timestamp_offset(&base_url, stale_offset)
            .await
            .expect("the responder is serving by now");
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "the mock must enforce freshness for the previous assertion to mean anything"
        );
    }

    /// Sends one correctly signed registration whose timestamp is shifted by
    /// `offset_secs`, and returns the status the responder answered with.
    async fn post_with_timestamp_offset(
        base_url: &str,
        offset_secs: i64,
    ) -> Result<StatusCode, reqwest::Error> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is after the unix epoch")
            .as_secs();
        let timestamp = i64::try_from(now).expect("system time fits in i64") + offset_secs;
        let signature = Http01HmacSigner::new(TEST_HMAC).sign_request(
            timestamp,
            "resigned",
            "resigned.key",
            60,
        );
        let body = RegisterRequest {
            token: "resigned",
            key_authorization: "resigned.key",
            ttl_secs: 60,
        };

        let response = Client::new()
            .post(admin_endpoint(base_url))
            .header(HEADER_TIMESTAMP, timestamp.to_string())
            .header(HEADER_SIGNATURE, signature)
            .json(&body)
            .send()
            .await?;
        Ok(response.status())
    }
}
