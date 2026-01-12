use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use reqwest::Client;
use ring::hmac;

use crate::config::Settings;

const HEADER_TIMESTAMP: &str = "x-bootroot-timestamp";
const HEADER_SIGNATURE: &str = "x-bootroot-signature";
const DEFAULT_ADMIN_PATH: &str = "/admin/http01";

#[derive(serde::Serialize)]
struct RegisterRequest<'a> {
    token: &'a str,
    key_authorization: &'a str,
    ttl_secs: u64,
}

fn signature_payload(
    timestamp: i64,
    token: &str,
    key_authorization: &str,
    ttl_secs: u64,
) -> String {
    format!("{timestamp}.{token}.{key_authorization}.{ttl_secs}")
}

fn sign_request(secret: &str, payload: &str) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, payload.as_bytes());
    STANDARD.encode(tag.as_ref())
}

/// Registers an HTTP-01 token with the responder.
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
    register_http01_token_with(
        url,
        &settings.acme.http_responder_hmac,
        settings.acme.http_responder_timeout_secs,
        token,
        key_authorization,
        ttl_secs,
    )
    .await
}

/// Registers an HTTP-01 token with explicit connection details.
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
) -> Result<()> {
    let url = base_url.trim_end_matches('/');
    let endpoint = format!("{url}{DEFAULT_ADMIN_PATH}");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| anyhow::anyhow!("Failed to read system time: {e}"))?
        .as_secs();
    let timestamp = i64::try_from(timestamp)
        .map_err(|_| anyhow::anyhow!("System time is too large for timestamp"))?;

    let payload = signature_payload(timestamp, token, key_authorization, ttl_secs);
    let signature = sign_request(hmac_secret, &payload);

    let client = Client::builder()
        .timeout(Duration::from_secs(timeout_secs))
        .build()
        .map_err(|e| anyhow::anyhow!("Failed to build responder client: {e}"))?;

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

#[cfg(test)]
mod tests {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;

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
            let expected = sign_request(&self.secret, &payload);

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
}
