use anyhow::{Context, Result};
use base64::Engine;
use reqwest::Client;
use ring::digest::{Context as DigestContext, SHA256};
use ring::hmac;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::acme::types::{Authorization, Order};
use crate::config::AcmeSettings;
use crate::eab::EabCredentials;

const ALG_ES256: &str = "ES256";
const ALG_HS256: &str = "HS256";
const CRV_P256: &str = "P-256";
const KTY_EC: &str = "EC";
const CONTENT_TYPE_JOSE_JSON: &str = "application/jose+json";
const HEADER_REPLAY_NONCE: &str = "replay-nonce";
#[derive(Debug, Deserialize, Clone)]
struct Directory {
    #[serde(rename = "newNonce")]
    nonce: String,
    #[serde(rename = "newAccount")]
    account: String,
    #[serde(rename = "newOrder")]
    order: String,
}

pub struct AcmeClient {
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
    pub fn new(directory_url: String, settings: &AcmeSettings) -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("Failed to generate account key"))?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .map_err(|_| anyhow::anyhow!("Failed to parse generated key pair"))?;

        Ok(Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()?,
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
    pub async fn fetch_directory(&mut self) -> Result<()> {
        if self.directory.is_some() {
            return Ok(());
        }
        info!("Fetching ACME directory from {}", self.directory_url);
        let mut last_err = None;
        let mut delay_secs = self.directory_fetch_base_delay_secs;
        for attempt in 1..=self.directory_fetch_attempts {
            let resp = self.client.get(&self.directory_url).send().await;
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
    pub async fn get_nonce(&mut self) -> Result<String> {
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }

        self.fetch_directory().await?;
        let dir = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Directory not loaded"))?;

        let resp = self.client.head(&dir.nonce).send().await?;
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
    pub async fn register_account(
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
        let resp = self.post(&url, &payload).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            return Err(anyhow::anyhow!(
                "Account registration failed: {status} - {text}"
            ));
        }

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
    pub async fn create_order(&mut self, domains: &[String]) -> Result<Order> {
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
        let resp = self.post(&url, &payload).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            return Err(anyhow::anyhow!("Order creation failed: {status} - {text}"));
        }

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
    pub async fn fetch_authorization(&mut self, url: &str) -> Result<Authorization> {
        let resp = self.post_as_get(url).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            return Err(anyhow::anyhow!("Fetch Authz failed: {status} - {text}"));
        }

        let authz: Authorization = resp.json().await?;
        Ok(authz)
    }

    /// Computes the Key Authorization for a token.
    ///
    /// # Errors
    /// Returns error if JWK construction or serialization fails.
    pub fn compute_key_authorization(&self, token: &str) -> Result<String> {
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
    pub async fn trigger_challenge(&mut self, url: &str) -> Result<()> {
        info!("Triggering challenge at {}", url);
        let payload = serde_json::json!({});
        let resp = self.post(url, &payload).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            return Err(anyhow::anyhow!(
                "Trigger challenge failed: {status} - {text}"
            ));
        }

        Ok(())
    }

    /// Finalizes the order with a CSR.
    ///
    /// # Errors
    /// Returns error if finalize call fails.
    pub async fn finalize_order(&mut self, url: &str, csr_der: &[u8]) -> Result<Order> {
        let csr_b64 = Self::b64(csr_der);
        let payload = serde_json::json!({
            "csr": csr_b64
        });

        info!("Finalizing order...");
        let resp = self.post(url, &payload).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            return Err(anyhow::anyhow!("Finalize failed: {status} - {text}"));
        }

        let order: Order = resp.json().await?;
        Ok(order)
    }

    /// Downloads the issued certificate.
    ///
    /// # Errors
    /// Returns error if download fails.
    pub async fn download_certificate(&mut self, url: &str) -> Result<String> {
        let resp = self.post_as_get(url).await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            return Err(anyhow::anyhow!("Download cert failed: {status} - {text}"));
        }
        let cert_pem = resp.text().await?;
        Ok(cert_pem)
    }

    /// Polls the order status.
    ///
    /// # Errors
    /// Returns error if poll request fails.
    pub async fn poll_order(&mut self, url: &str) -> Result<Order> {
        let resp = self.post_as_get(url).await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            return Err(anyhow::anyhow!("Poll order failed: {status} - {text}"));
        }
        let order: Order = resp.json().await?;
        Ok(order)
    }

    fn jwk(&self) -> Result<Jwk> {
        let pk = self.key_pair.public_key();
        let pk_bytes = pk.as_ref();

        if pk_bytes.len() != 65 || pk_bytes[0] != 0x04 {
            return Err(anyhow::anyhow!("Unexpected public key format"));
        }

        let x = &pk_bytes[1..33];
        let y = &pk_bytes[33..65];

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
        url: &str,
        payload: Option<&T>,
    ) -> Result<serde_json::Value> {
        let nonce = self.get_nonce().await?;

        let header = if let Some(kid) = &self.key_id {
            JwsHeader {
                alg: ALG_ES256.to_string(),
                nonce,
                url: url.to_string(),
                jwk: None,
                kid: Some(kid.clone()),
            }
        } else {
            JwsHeader {
                alg: ALG_ES256.to_string(),
                nonce,
                url: url.to_string(),
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

    async fn post<T: Serialize + ?Sized>(
        &mut self,
        url: &str,
        payload: &T,
    ) -> Result<reqwest::Response> {
        let body = self.sign_request(url, Some(payload)).await?;
        debug!("POST {} body: {}", url, body);
        let resp = self
            .client
            .post(url)
            .header("Content-Type", CONTENT_TYPE_JOSE_JSON)
            .json(&body)
            .send()
            .await?;
        Ok(resp)
    }

    async fn post_as_get(&mut self, url: &str) -> Result<reqwest::Response> {
        let body = self.sign_request::<()>(url, None).await?;
        debug!("POST-as-GET {} body: {}", url, body);
        let resp = self
            .client
            .post(url)
            .header("Content-Type", CONTENT_TYPE_JOSE_JSON)
            .json(&body)
            .send()
            .await?;
        Ok(resp)
    }
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
            http_challenge_port: 80,
            directory_fetch_attempts: 3,
            directory_fetch_base_delay_secs: 0,
            directory_fetch_max_delay_secs: 0,
            poll_attempts: 15,
            poll_interval_secs: 2,
        }
    }

    #[test]
    fn test_client_initialization() {
        let client = AcmeClient::new("http://example.com".to_string(), &test_settings());
        assert!(client.is_ok());
    }

    #[test]
    fn test_compute_key_authorization() {
        let client = AcmeClient::new("http://example.com".to_string(), &test_settings()).unwrap();
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
        let client = AcmeClient::new("http://example.com".to_string(), &test_settings()).unwrap();
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

        let mut client =
            AcmeClient::new(format!("{}/directory", server.uri()), &test_settings()).unwrap();
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

        let mut client =
            AcmeClient::new(format!("{}/directory", server.uri()), &test_settings()).unwrap();
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

        let mut client =
            AcmeClient::new(format!("{}/directory", server.uri()), &test_settings()).unwrap();
        let order = client
            .poll_order(&format!("{}/order/1", server.uri()))
            .await
            .unwrap();

        assert_eq!(order.status, crate::acme::types::OrderStatus::Pending);
    }
}
