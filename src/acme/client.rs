use anyhow::{Context, Result};
use base64::Engine;
use reqwest::{Client, Url};
use ring::digest::{Context as DigestContext, SHA256};
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::acme::types::{Authorization, Order};
use crate::config::{AcmeSettings, TrustSettings};
use crate::eab::EabCredentials;
use crate::tls::build_http_client;

const ALG_ES256: &str = "ES256";
const ALG_HS256: &str = "HS256";
const CRV_P256: &str = "P-256";
const KTY_EC: &str = "EC";
const CONTENT_TYPE_JOSE_JSON: &str = "application/jose+json";
const HEADER_REPLAY_NONCE: &str = "replay-nonce";
const SCHEME_HTTP: &str = "http";
const SCHEME_HTTPS: &str = "https";

/// Length of an uncompressed P-256 public key: 1-byte prefix + two
/// 32-byte coordinates.
const EC_P256_UNCOMPRESSED_LEN: usize = 65;
/// Prefix byte indicating an uncompressed EC point (SEC 1, §2.3.3).
const EC_UNCOMPRESSED_PREFIX: u8 = 0x04;
/// Length of a single P-256 coordinate (32 bytes for a 256-bit curve).
const EC_P256_COORD_LEN: usize = 32;
#[derive(Debug, Deserialize, Clone)]
struct Directory {
    #[serde(rename = "newNonce")]
    nonce: String,
    #[serde(rename = "newAccount")]
    account: String,
    #[serde(rename = "newOrder")]
    order: String,
}

pub(crate) struct AcmeClient {
    client: Client,
    directory_url: String,
    directory: Option<Directory>,
    key_pair: EcdsaKeyPair,
    key_id: Option<String>,
    nonce: Option<String>,
    directory_fetch_attempts: u64,
    directory_fetch_base_delay_secs: u64,
    directory_fetch_max_delay_secs: u64,
}

impl AcmeClient {
    /// Creates a new `AcmeClient` instance.
    ///
    /// # Errors
    /// Returns error if account key generation fails or HTTP client build fails.
    pub(crate) fn new(
        directory_url: String,
        settings: &AcmeSettings,
        trust: &TrustSettings,
        insecure_mode: bool,
    ) -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("Failed to generate account key"))?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .map_err(|_| anyhow::anyhow!("Failed to parse generated key pair"))?;
        let client = build_http_client(trust, insecure_mode)?;

        Ok(Self {
            client,
            directory_url,
            directory: None,
            key_pair,
            key_id: None,
            nonce: None,
            directory_fetch_attempts: settings.directory_fetch_attempts,
            directory_fetch_base_delay_secs: settings.directory_fetch_base_delay_secs,
            directory_fetch_max_delay_secs: settings.directory_fetch_max_delay_secs,
        })
    }

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    /// Fetches the ACME directory and caches it.
    ///
    /// # Errors
    /// Returns error if the directory fetch or JSON parsing fails.
    pub(crate) async fn fetch_directory(&mut self) -> Result<()> {
        if self.directory.is_some() {
            return Ok(());
        }
        let directory_url = Self::enforce_https(&self.directory_url)?;
        info!("Fetching ACME directory from {}", directory_url);
        let mut last_err = None;
        let mut delay_secs = self.directory_fetch_base_delay_secs;
        for attempt in 1..=self.directory_fetch_attempts {
            let resp = self.client.get(directory_url.clone()).send().await;
            match resp {
                Ok(resp) => match resp.json::<Directory>().await {
                    Ok(dir) => {
                        self.directory = Some(dir);
                        return Ok(());
                    }
                    Err(err) => {
                        last_err = Some(err.into());
                    }
                },
                Err(err) => {
                    last_err = Some(err.into());
                }
            }

            if attempt < self.directory_fetch_attempts {
                warn!(
                    "ACME directory fetch failed (attempt {}/{}), retrying in {}s...",
                    attempt, self.directory_fetch_attempts, delay_secs
                );
                tokio::time::sleep(std::time::Duration::from_secs(delay_secs)).await;
                delay_secs = delay_secs
                    .saturating_mul(2)
                    .min(self.directory_fetch_max_delay_secs);
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Directory fetch failed")))
    }

    /// Fetches a nonce for JWS requests.
    ///
    /// # Errors
    /// Returns error if the nonce request fails or the response is missing a nonce.
    pub(crate) async fn get_nonce(&mut self) -> Result<String> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }

        self.fetch_directory().await?;
        let dir = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Directory not loaded"))?;

        let nonce_url = Self::enforce_https(&dir.nonce)?;
        let resp = self.client.head(nonce_url).send().await?;
        let nonce = resp
            .headers()
            .get(HEADER_REPLAY_NONCE)
            .context("Missing Replay-Nonce header")?
            .to_str()?
            .to_string();
        Ok(nonce)
    }

    /// Registers a new account with the ACME server.
    ///
    /// # Errors
    /// Returns error if ACME API fails or EAB data is invalid.
    pub(crate) async fn register_account(
        &mut self,
        contact: &[String],
        eab_creds: Option<&EabCredentials>,
    ) -> Result<()> {
        self.fetch_directory().await?;
        let url = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Directory not loaded"))?
            .account
            .clone();

        let mut payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": contact
        });

        if let Some(creds) = eab_creds {
            let binding = self.external_account_binding(&url, creds)?;
            payload["externalAccountBinding"] = binding;
        }

        info!("Registering account...");
        let resp = self.signed_post(&url, Some(&payload)).await?;
        let resp = check_response(resp, "Account registration").await?;

        let kid = resp
            .headers()
            .get("Location")
            .ok_or_else(|| anyhow::anyhow!("Missing Location header in account registration"))?
            .to_str()?
            .to_string();

        info!("Account registered: {}", kid);
        self.key_id = Some(kid);

        Ok(())
    }

    /// Creates a new order for the given domains.
    ///
    /// # Errors
    /// Returns error if ACME API fails.
    pub(crate) async fn create_order(&mut self, domains: &[String]) -> Result<Order> {
        self.fetch_directory().await?;
        let url = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Directory not loaded"))?
            .order
            .clone();

        let identifiers: Vec<serde_json::Value> = domains
            .iter()
            .map(|d| {
                let r#type = if d.parse::<std::net::IpAddr>().is_ok() {
                    "ip"
                } else {
                    "dns"
                };
                serde_json::json!({ "type": r#type, "value": d })
            })
            .collect();

        let payload = serde_json::json!({
            "identifiers": identifiers
        });

        info!("Creating new order for domains: {:?}", domains);
        let resp = self.signed_post(&url, Some(&payload)).await?;
        let resp = check_response(resp, "Order creation").await?;

        let order_url = resp
            .headers()
            .get("location")
            .and_then(|h| h.to_str().ok())
            .map(ToString::to_string);

        let mut order: Order = resp.json().await?;
        order.url = order_url;
        Ok(order)
    }

    /// Fetches the authorization object from the URL.
    ///
    /// # Errors
    /// Returns error if network fails or status is not success.
    pub(crate) async fn fetch_authorization(&mut self, url: &str) -> Result<Authorization> {
        let resp = self.signed_post::<()>(url, None).await?;
        let resp = check_response(resp, "Fetch authorization").await?;
        let authz: Authorization = resp.json().await?;
        Ok(authz)
    }

    /// Computes the Key Authorization for a token.
    ///
    /// # Errors
    /// Returns error if JWK construction or serialization fails.
    pub(crate) fn compute_key_authorization(&self, token: &str) -> Result<String> {
        let jwk = self.jwk()?;

        let mut map = std::collections::BTreeMap::new();
        map.insert("crv", jwk.crv);
        map.insert("kty", jwk.kty);
        map.insert("x", jwk.x);
        map.insert("y", jwk.y);

        let json = serde_json::to_string(&map)?;
        debug!("Thumbprint Canonical JSON: {}", json);

        let mut context = DigestContext::new(&SHA256);
        context.update(json.as_bytes());
        let digest = context.finish();

        let thumbprint = Self::b64(digest.as_ref());
        Ok(format!("{token}.{thumbprint}"))
    }

    /// Triggers the challenge validation on the server.
    ///
    /// # Errors
    /// Returns error if network fails.
    pub(crate) async fn trigger_challenge(&mut self, url: &str) -> Result<()> {
        info!("Triggering challenge at {}", url);
        let payload = serde_json::json!({});
        let resp = self.signed_post(url, Some(&payload)).await?;
        check_response(resp, "Trigger challenge").await?;
        Ok(())
    }

    /// Finalizes the order with a CSR.
    ///
    /// # Errors
    /// Returns error if finalize call fails.
    pub(crate) async fn finalize_order(&mut self, url: &str, csr_der: &[u8]) -> Result<Order> {
        let csr_b64 = Self::b64(csr_der);
        let payload = serde_json::json!({
            "csr": csr_b64
        });

        info!("Finalizing order...");
        let resp = self.signed_post(url, Some(&payload)).await?;
        let resp = check_response(resp, "Finalize order").await?;
        let order: Order = resp.json().await?;
        Ok(order)
    }

    /// Downloads the issued certificate.
    ///
    /// # Errors
    /// Returns error if download fails.
    pub(crate) async fn download_certificate(&mut self, url: &str) -> Result<String> {
        let resp = self.signed_post::<()>(url, None).await?;
        let resp = check_response(resp, "Download certificate").await?;
        let cert_pem = resp.text().await?;
        Ok(cert_pem)
    }

    /// Polls the order status.
    ///
    /// # Errors
    /// Returns error if poll request fails.
    pub(crate) async fn poll_order(&mut self, url: &str) -> Result<Order> {
        let resp = self.signed_post::<()>(url, None).await?;
        let resp = check_response(resp, "Poll order").await?;
        let order: Order = resp.json().await?;
        Ok(order)
    }

    fn jwk(&self) -> Result<Jwk> {
        let pk = self.key_pair.public_key();
        let pk_bytes = pk.as_ref();

        if pk_bytes.len() != EC_P256_UNCOMPRESSED_LEN || pk_bytes[0] != EC_UNCOMPRESSED_PREFIX {
            return Err(anyhow::anyhow!("Unexpected public key format"));
        }

        let x = &pk_bytes[1..=EC_P256_COORD_LEN];
        let y = &pk_bytes[1 + EC_P256_COORD_LEN..EC_P256_UNCOMPRESSED_LEN];

        Ok(Jwk {
            kty: KTY_EC.to_string(),
            crv: CRV_P256.to_string(),
            x: Self::b64(x),
            y: Self::b64(y),
        })
    }

    fn external_account_binding(
        &self,
        url: &str,
        creds: &EabCredentials,
    ) -> Result<serde_json::Value> {
        let jwk = self.jwk()?;
        let protected = serde_json::json!({
            "alg": ALG_HS256,
            "kid": creds.kid,
            "url": url,
        });

        let protected_json = serde_json::to_string(&protected)?;
        let payload_json = serde_json::to_string(&jwk)?;
        let protected_b64 = Self::b64(protected_json.as_bytes());
        let payload_b64 = Self::b64(payload_json.as_bytes());

        let key_bytes = decode_eab_key(&creds.hmac)?;
        let signing_input = format!("{protected_b64}.{payload_b64}");
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
        let signature = hmac::sign(&key, signing_input.as_bytes());
        let signature_b64 = Self::b64(signature.as_ref());

        Ok(serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64,
        }))
    }

    async fn sign_request<T: Serialize + ?Sized>(
        &mut self,
        url: &Url,
        payload: Option<&T>,
    ) -> Result<serde_json::Value> {
        let nonce = self.get_nonce().await?;
        let url_value = url.as_str().to_string();

        let header = if let Some(kid) = &self.key_id {
            JwsHeader {
                alg: ALG_ES256.to_string(),
                nonce,
                url: url_value.clone(),
                jwk: None,
                kid: Some(kid.clone()),
            }
        } else {
            JwsHeader {
                alg: ALG_ES256.to_string(),
                nonce,
                url: url_value,
                jwk: Some(self.jwk()?),
                kid: None,
            }
        };

        let protected_json = serde_json::to_string(&header)?;
        let protected_b64 = Self::b64(protected_json.as_bytes());

        let payload_json = if let Some(p) = payload {
            serde_json::to_string(p)?
        } else {
            String::new()
        };
        let payload_b64 = if payload.is_some() {
            Self::b64(payload_json.as_bytes())
        } else {
            String::new()
        };

        let signing_input = format!("{protected_b64}.{payload_b64}");

        let rng = SystemRandom::new();
        let signature = self
            .key_pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|_| anyhow::anyhow!("Failed to sign request"))?;

        let signature_b64 = Self::b64(signature.as_ref());

        let jws_body = serde_json::json!({
            "protected": protected_b64,
            "payload": payload_b64,
            "signature": signature_b64
        });

        Ok(jws_body)
    }

    async fn signed_post<T: Serialize + ?Sized>(
        &mut self,
        url: &str,
        payload: Option<&T>,
    ) -> Result<reqwest::Response> {
        let url = Self::enforce_https(url)?;
        let body = self.sign_request(&url, payload).await?;
        let label = if payload.is_some() {
            "POST"
        } else {
            "POST-as-GET"
        };
        debug!("{label} {url} body: {body}");
        let resp = self
            .client
            .post(url)
            .header("Content-Type", CONTENT_TYPE_JOSE_JSON)
            .json(&body)
            .send()
            .await?;
        Ok(resp)
    }

    fn enforce_https(url: &str) -> Result<Url> {
        let parsed = Url::parse(url).context("Invalid ACME URL")?;
        if parsed.scheme() == SCHEME_HTTPS {
            return Ok(parsed);
        }
        if parsed.scheme() == SCHEME_HTTP && cfg!(test) {
            warn!("Allowing non-HTTPS ACME URL in tests: {}", parsed);
            return Ok(parsed);
        }
        Err(anyhow::anyhow!(
            "Refusing to send ACME request over non-HTTPS URL: {parsed}"
        ))
    }
}

/// Checks an HTTP response status and returns the response on success.
///
/// # Errors
/// Returns error with context message if the response status is not
/// successful.
async fn check_response(resp: reqwest::Response, context: &str) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let text = resp.text().await?;
    Err(anyhow::anyhow!("{context} failed: {status} - {text}"))
}

fn decode_eab_key(encoded: &str) -> Result<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .or_else(|_| base64::engine::general_purpose::STANDARD.decode(encoded))
        .map_err(|e| anyhow::anyhow!("Failed to decode EAB key: {e}"))
}

#[derive(Debug, Serialize, Clone)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

#[derive(Debug, Serialize)]
struct JwsHeader {
    alg: String,
    nonce: String,
    url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    jwk: Option<Jwk>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

    use wiremock::matchers::{body_string_contains, header, method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

    use super::*;

    fn test_settings() -> AcmeSettings {
        AcmeSettings {
            directory_fetch_attempts: 3,
            directory_fetch_base_delay_secs: 0,
            directory_fetch_max_delay_secs: 0,
            poll_attempts: 15,
            poll_interval_secs: 2,
            http_responder_url: "http://localhost:8080".to_string(),
            http_responder_hmac: "dev-hmac".to_string(),
            http_responder_timeout_secs: 5,
            http_responder_token_ttl_secs: 300,
        }
    }

    fn test_trust() -> TrustSettings {
        TrustSettings::default()
    }

    #[test]
    fn test_client_initialization() {
        let client = AcmeClient::new(
            "http://example.com".to_string(),
            &test_settings(),
            &test_trust(),
            false,
        );
        assert!(client.is_ok());
    }

    #[test]
    fn test_compute_key_authorization() {
        let client = AcmeClient::new(
            "http://example.com".to_string(),
            &test_settings(),
            &test_trust(),
            false,
        )
        .unwrap();
        let token = "test_token_123_xyz";
        let ka = client.compute_key_authorization(token).unwrap();
        assert!(ka.starts_with(token));
        let parts: Vec<&str> = ka.split('.').collect();
        assert_eq!(
            parts.len(),
            2,
            "Key Authorization should have 2 parts separated by ."
        );
        let thumbprint = parts[1];
        assert!(!thumbprint.is_empty());
        assert!(!thumbprint.contains('='));
        assert!(!thumbprint.contains('+'));
        assert!(!thumbprint.contains('/'));
    }

    #[test]
    fn test_external_account_binding_structure() {
        let client = AcmeClient::new(
            "http://example.com".to_string(),
            &test_settings(),
            &test_trust(),
            false,
        )
        .unwrap();
        let key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"test-secret");
        let creds = EabCredentials {
            kid: "kid-123".to_string(),
            hmac: key,
        };

        let binding = client
            .external_account_binding("http://example.com/newAccount", &creds)
            .unwrap();

        let protected_b64 = binding["protected"].as_str().unwrap();
        let payload_b64 = binding["payload"].as_str().unwrap();
        let protected_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(protected_b64)
            .unwrap();
        let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();

        let protected: serde_json::Value = serde_json::from_slice(&protected_json).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_json).unwrap();
        let jwk = client.jwk().unwrap();
        let jwk_value = serde_json::to_value(jwk).unwrap();

        assert_eq!(protected["alg"], ALG_HS256);
        assert_eq!(protected["kid"], "kid-123");
        assert_eq!(protected["url"], "http://example.com/newAccount");
        assert_eq!(payload, jwk_value);
        assert!(binding["signature"].as_str().unwrap().len() > 10);
    }

    #[tokio::test]
    async fn test_create_order_payload_uses_dns_or_ip_only() {
        let server = MockServer::start().await;
        let directory_body = serde_json::json!({
            "newNonce": format!("{}/nonce", server.uri()),
            "newAccount": format!("{}/account", server.uri()),
            "newOrder": format!("{}/order", server.uri()),
        });

        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&directory_body))
            .mount(&server)
            .await;

        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(200).insert_header("replay-nonce", "nonce-123"))
            .mount(&server)
            .await;

        let order_body = serde_json::json!({
            "status": "pending",
            "finalize": format!("{}/finalize", server.uri()),
            "authorizations": [],
            "certificate": null
        });

        Mock::given(method("POST"))
            .and(path("/order"))
            .respond_with(
                ResponseTemplate::new(201)
                    .set_body_json(&order_body)
                    .insert_header("Location", format!("{}/order/1", server.uri())),
            )
            .mount(&server)
            .await;

        let mut client = AcmeClient::new(
            format!("{}/directory", server.uri()),
            &test_settings(),
            &test_trust(),
            false,
        )
        .unwrap();
        client
            .create_order(&["example.internal".to_string(), "192.0.2.10".to_string()])
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        let order_request = requests
            .iter()
            .find(|request| request.url.path() == "/order")
            .expect("Expected order request");
        let body: serde_json::Value = serde_json::from_slice(&order_request.body).unwrap();
        let payload_b64 = body["payload"].as_str().unwrap();
        let payload_json = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_json).unwrap();
        let identifiers = payload["identifiers"].as_array().unwrap();

        assert_eq!(identifiers.len(), 2);

        let mut found_dns = false;
        let mut found_ip = false;
        for identifier in identifiers {
            let id_type = identifier["type"].as_str().unwrap();
            let value = identifier["value"].as_str().unwrap();
            match id_type {
                "dns" => {
                    assert_eq!(value, "example.internal");
                    found_dns = true;
                }
                "ip" => {
                    assert_eq!(value, "192.0.2.10");
                    found_ip = true;
                }
                unexpected => panic!("Unexpected identifier type: {unexpected}"),
            }
        }

        assert!(found_dns);
        assert!(found_ip);
    }

    struct DirectoryResponder {
        calls: Arc<AtomicUsize>,
        directory_body: serde_json::Value,
    }

    impl Respond for DirectoryResponder {
        fn respond(&self, _request: &Request) -> ResponseTemplate {
            let attempt = self.calls.fetch_add(1, Ordering::SeqCst);
            if attempt < 2 {
                ResponseTemplate::new(500)
            } else {
                ResponseTemplate::new(200).set_body_json(&self.directory_body)
            }
        }
    }

    #[tokio::test]
    async fn test_fetch_directory_retries_then_succeeds() {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let directory_body = serde_json::json!({
            "newNonce": format!("{}/nonce", server.uri()),
            "newAccount": format!("{}/account", server.uri()),
            "newOrder": format!("{}/order", server.uri()),
        });

        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(DirectoryResponder {
                calls: Arc::clone(&calls),
                directory_body,
            })
            .mount(&server)
            .await;

        let mut client = AcmeClient::new(
            format!("{}/directory", server.uri()),
            &test_settings(),
            &test_trust(),
            false,
        )
        .unwrap();
        client.fetch_directory().await.unwrap();

        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_get_nonce_reads_replay_nonce_header() {
        let server = MockServer::start().await;
        let directory_body = serde_json::json!({
            "newNonce": format!("{}/nonce", server.uri()),
            "newAccount": format!("{}/account", server.uri()),
            "newOrder": format!("{}/order", server.uri()),
        });

        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&directory_body))
            .mount(&server)
            .await;

        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(200).insert_header("replay-nonce", "nonce-123"))
            .mount(&server)
            .await;

        let mut client = AcmeClient::new(
            format!("{}/directory", server.uri()),
            &test_settings(),
            &test_trust(),
            false,
        )
        .unwrap();
        let nonce = client.get_nonce().await.unwrap();

        assert_eq!(nonce, "nonce-123");
    }

    #[tokio::test]
    async fn test_post_as_get_sends_empty_payload() {
        let server = MockServer::start().await;
        let directory_body = serde_json::json!({
            "newNonce": format!("{}/nonce", server.uri()),
            "newAccount": format!("{}/account", server.uri()),
            "newOrder": format!("{}/order", server.uri()),
        });

        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&directory_body))
            .mount(&server)
            .await;

        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(200).insert_header("replay-nonce", "nonce-abc"))
            .mount(&server)
            .await;

        let order_body = serde_json::json!({
            "status": "pending",
            "finalize": format!("{}/finalize", server.uri()),
            "authorizations": [],
            "certificate": null
        });

        Mock::given(method("POST"))
            .and(path("/order/1"))
            .and(header("content-type", CONTENT_TYPE_JOSE_JSON))
            .and(body_string_contains("\"payload\":\"\""))
            .and(body_string_contains("\"signature\""))
            .respond_with(ResponseTemplate::new(200).set_body_json(&order_body))
            .mount(&server)
            .await;

        let mut client = AcmeClient::new(
            format!("{}/directory", server.uri()),
            &test_settings(),
            &test_trust(),
            false,
        )
        .unwrap();
        let order = client
            .poll_order(&format!("{}/order/1", server.uri()))
            .await
            .unwrap();

        assert_eq!(order.status, crate::acme::types::OrderStatus::Pending);
    }

    #[tokio::test]
    async fn test_fetch_directory_fails_after_retries() {
        let server = MockServer::start().await;
        let calls = Arc::new(AtomicUsize::new(0));

        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(DirectoryResponder {
                calls: Arc::clone(&calls),
                directory_body: serde_json::json!({"not": "used"}),
            })
            .mount(&server)
            .await;

        let mut client = AcmeClient::new(
            format!("{}/directory", server.uri()),
            &test_settings(),
            &test_trust(),
            false,
        )
        .unwrap();
        let err = client.fetch_directory().await.unwrap_err();

        assert_eq!(calls.load(Ordering::SeqCst), 3);
        assert!(!err.to_string().is_empty());
    }

    #[tokio::test]
    async fn test_get_nonce_missing_header() {
        let server = MockServer::start().await;
        let directory_body = serde_json::json!({
            "newNonce": format!("{}/nonce", server.uri()),
            "newAccount": format!("{}/account", server.uri()),
            "newOrder": format!("{}/order", server.uri()),
        });

        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&directory_body))
            .mount(&server)
            .await;

        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let mut client = AcmeClient::new(
            format!("{}/directory", server.uri()),
            &test_settings(),
            &test_trust(),
            false,
        )
        .unwrap();
        let err = client.get_nonce().await.unwrap_err();

        assert!(err.to_string().contains("Missing Replay-Nonce header"));
    }

    #[tokio::test]
    async fn test_post_as_get_non_success_status() {
        let server = MockServer::start().await;
        let directory_body = serde_json::json!({
            "newNonce": format!("{}/nonce", server.uri()),
            "newAccount": format!("{}/account", server.uri()),
            "newOrder": format!("{}/order", server.uri()),
        });

        Mock::given(method("GET"))
            .and(path("/directory"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&directory_body))
            .mount(&server)
            .await;

        Mock::given(method("HEAD"))
            .and(path("/nonce"))
            .respond_with(ResponseTemplate::new(200).insert_header("replay-nonce", "nonce-xyz"))
            .mount(&server)
            .await;

        Mock::given(method("POST"))
            .and(path("/order/2"))
            .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
            .mount(&server)
            .await;

        let mut client = AcmeClient::new(
            format!("{}/directory", server.uri()),
            &test_settings(),
            &test_trust(),
            false,
        )
        .unwrap();
        let err = client
            .poll_order(&format!("{}/order/2", server.uri()))
            .await
            .unwrap_err();

        assert!(err.to_string().contains("Poll order failed"));
    }

    #[tokio::test]
    async fn test_check_response_returns_response_on_success() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/ok"))
            .respond_with(ResponseTemplate::new(200).set_body_string("all good"))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/ok", server.uri()))
            .send()
            .await
            .unwrap();
        let resp = check_response(resp, "test ok").await.unwrap();
        assert_eq!(resp.text().await.unwrap(), "all good");
    }

    #[tokio::test]
    async fn test_check_response_returns_error_on_failure() {
        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/fail"))
            .respond_with(ResponseTemplate::new(403).set_body_string("forbidden"))
            .mount(&server)
            .await;

        let client = reqwest::Client::new();
        let resp = client
            .get(format!("{}/fail", server.uri()))
            .send()
            .await
            .unwrap();
        let err = check_response(resp, "test fail").await.unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("test fail failed"));
        assert!(msg.contains("403"));
        assert!(msg.contains("forbidden"));
    }

    mod trust {
        use std::net::SocketAddr;
        use std::path::PathBuf;
        use std::sync::Arc;

        use anyhow::{Context, Result};
        use rcgen::generate_simple_self_signed;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use tokio::task::JoinHandle;
        use tokio_rustls::TlsAcceptor;

        use super::*;

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
                    rustls::pki_types::PrivateKeyDer::from(
                        rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
                    ),
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

        fn trust_test_settings() -> AcmeSettings {
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
        async fn allows_insecure_when_disabled() -> Result<()> {
            let server = start_tls_server().await?;
            let trust = TrustSettings::default();
            let mut client = AcmeClient::new(
                format!("{}/directory", server.url()),
                &trust_test_settings(),
                &trust,
                true,
            )?;
            client.fetch_directory().await?;
            server.handle.abort();
            Ok(())
        }

        #[tokio::test]
        async fn rejects_self_signed_without_trust() -> Result<()> {
            let server = start_tls_server().await?;
            let trust = TrustSettings::default();
            let mut client = AcmeClient::new(
                format!("{}/directory", server.url()),
                &trust_test_settings(),
                &trust,
                false,
            )?;
            assert!(client.fetch_directory().await.is_err());
            server.handle.abort();
            Ok(())
        }

        #[tokio::test]
        async fn accepts_bundle_and_pin() -> Result<()> {
            let server = start_tls_server().await?;
            let dir = tempfile::tempdir().context("tempdir")?;
            let bundle_path = write_ca_bundle(&server.cert_pem, &dir)?;
            let trust = TrustSettings {
                ca_bundle_path: Some(bundle_path),
                trusted_ca_sha256: vec![sha256_hex(&server.cert_der)],
            };

            let mut client = AcmeClient::new(
                format!("{}/directory", server.url()),
                &trust_test_settings(),
                &trust,
                false,
            )?;
            client.fetch_directory().await?;
            server.handle.abort();
            Ok(())
        }

        #[tokio::test]
        async fn rejects_pin_mismatch() -> Result<()> {
            let server = start_tls_server().await?;
            let dir = tempfile::tempdir().context("tempdir")?;
            let bundle_path = write_ca_bundle(&server.cert_pem, &dir)?;
            let trust = TrustSettings {
                ca_bundle_path: Some(bundle_path),
                trusted_ca_sha256: vec!["00".repeat(32)],
            };

            let mut client = AcmeClient::new(
                format!("{}/directory", server.url()),
                &trust_test_settings(),
                &trust,
                false,
            )?;
            assert!(client.fetch_directory().await.is_err());
            server.handle.abort();
            Ok(())
        }
    }
}
