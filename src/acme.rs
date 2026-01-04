use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use base64::Engine;
use poem::http::StatusCode;
use poem::listener::TcpListener;
use poem::web::{Data, Path};
use poem::{EndpointExt, Route, Server, handler};
use reqwest::Client;
use ring::digest::{Context as DigestContext, SHA256};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info};

const ALG_ES256: &str = "ES256";
const CRV_P256: &str = "P-256";
const KTY_EC: &str = "EC";
const CONTENT_TYPE_JOSE_JSON: &str = "application/jose+json";
const HEADER_REPLAY_NONCE: &str = "replay-nonce";
const DEFAULT_CONTACT: &str = "mailto:admin@example.com";
const HTTP_CHALLENGE_PORT: u16 = 80;
const POLL_ATTEMPTS: usize = 15;
const POLL_INTERVAL_SECS: u64 = 2;

#[derive(Debug, Deserialize, Clone)]
struct Directory {
    #[serde(rename = "newNonce")]
    nonce: String,
    #[serde(rename = "newAccount")]
    account: String,
    #[serde(rename = "newOrder")]
    order: String,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OrderStatus {
    Pending,
    Ready,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthorizationStatus {
    Pending,
    Valid,
    Invalid,
    Deactivated,
    Expired,
    Revoked,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeStatus {
    Pending,
    Processing,
    Valid,
    Invalid,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum ChallengeType {
    #[serde(rename = "http-01")]
    Http01,
    #[serde(rename = "dns-01")]
    Dns01,
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Order {
    pub status: OrderStatus,
    pub finalize: String,
    pub authorizations: Vec<String>,
    pub certificate: Option<String>,
    #[serde(skip)]
    pub url: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Authorization {
    pub status: AuthorizationStatus,
    #[serde(rename = "identifier")]
    _identifier: serde_json::Value,
    pub challenges: Vec<Challenge>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Challenge {
    #[serde(rename = "type")]
    pub r#type: ChallengeType,
    pub url: String,
    pub token: String,
    pub status: ChallengeStatus,
    pub error: Option<serde_json::Value>,
}

pub struct AcmeClient {
    client: Client,
    directory_url: String,
    directory: Option<Directory>,
    key_pair: EcdsaKeyPair,
    key_id: Option<String>, // Key ID (Account URL) after registration
    nonce: Option<String>,
}

impl AcmeClient {
    /// Creates a new `AcmeClient` instance.
    ///
    /// # Errors
    /// Returns error if account key generation fails or HTTP client build fails.
    pub fn new(directory_url: String) -> Result<Self> {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("Failed to generate account key"))?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .map_err(|_| anyhow::anyhow!("Failed to parse generated key pair"))?;

        Ok(Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()?, // TODO: PRODUCTION SAFETY - Remove this in production. Use proper Root CA verification.
            directory_url,
            directory: None,
            key_pair,
            key_id: None,
            nonce: None,
        })
    }

    fn b64(data: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
    }

    async fn fetch_directory(&mut self) -> Result<()> {
        if self.directory.is_some() {
            return Ok(());
        }
        info!("Fetching ACME directory from {}", self.directory_url);
        let resp = self.client.get(&self.directory_url).send().await?;
        let dir: Directory = resp.json().await?;
        self.directory = Some(dir);
        Ok(())
    }

    async fn get_nonce(&mut self) -> Result<String> {
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
    /// Returns error if ACME API fails.
    pub async fn register_account(&mut self, contact: &[String]) -> Result<()> {
        self.fetch_directory().await?;
        let url = self
            .directory
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Directory not loaded"))?
            .account
            .clone();

        let payload = serde_json::json!({
            "termsOfServiceAgreed": true,
            "contact": contact
        });

        info!("Registering account...");
        let resp = self.post(&url, &payload).await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            return Err(anyhow::anyhow!(
                "Account registration failed: {status} - {text}"
            ));
        }

        // Extract Key ID (Account URL) from Location header
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
                serde_json::json!( { "type": r#type, "value": d })
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

        // Canonical JSON: keys sorted lexicographically.
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

        // P-256 public key is 65 bytes (0x04 uncompressed prefix + 32 bytes X + 32 bytes Y)
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

    async fn sign_request<T: Serialize + ?Sized>(
        &mut self,
        url: &str,
        payload: Option<&T>,
    ) -> Result<serde_json::Value> {
        let nonce = self.get_nonce().await?;

        // Determine header (jwk for newAccount, kid for others)
        let header = if let Some(kid) = &self.key_id {
            JwsHeader {
                alg: ALG_ES256.to_string(),
                nonce,
                url: url.to_string(),
                jwk: None,
                kid: Some(kid.clone()),
            }
        } else {
            // If no Key ID, we must be registering (newAccount) or revoking with key (not typical here)
            // For newAccount, we pass JWK
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

        // Signature input: "protected.payload"
        let signing_input = format!("{protected_b64}.{payload_b64}");

        let rng = SystemRandom::new();
        let signature = self
            .key_pair
            .sign(&rng, signing_input.as_bytes())
            .map_err(|_| anyhow::anyhow!("Failed to sign request"))?;

        let signature_b64 = Self::b64(signature.as_ref());

        // Construct complete JWS
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
            .header("Content-Type", "application/jose+json")
            .json(&body)
            .send()
            .await?;
        Ok(resp)
    }
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

/// Issues a certificate via ACME protocol.
///
/// # Errors
/// Returns error if ACME protocol fails.
///
/// # Panics
/// Panics if the challenge state mutex is poisoned or TCP listener binding fails (critical errors).
#[allow(clippy::too_many_lines)]
pub async fn issue_certificate(
    settings: &crate::config::Settings,
    eab_creds: Option<crate::eab::EabCredentials>,
) -> Result<()> {
    let mut client = AcmeClient::new(settings.server.clone())?;

    // 1. Get Directory
    client.fetch_directory().await?;
    info!("Directory loaded.");

    // 2. Get Nonce (Test)
    let nonce = client.get_nonce().await?;
    debug!("Got initial nonce: {}", nonce);

    // 3. Register Account (or get existing)
    if let Some(creds) = eab_creds {
        info!("Using existing EAB credentials for Key ID: {}", creds.kid);
        tracing::warn!("EAB support is not fully implemented. Proceeding with open enrollment.");
        client
            .register_account(&[DEFAULT_CONTACT.to_string()])
            .await?;
    } else {
        // Open enrollment
        client
            .register_account(&[DEFAULT_CONTACT.to_string()])
            .await?;
    }

    // 4. Create Order
    let order = client.create_order(&settings.domains).await?;
    info!("Order created: {:?}", order);

    // 5. Handle Authorizations (Challenges)
    // Shared state for challenges: Token -> KeyAuth
    let challenges: Arc<Mutex<std::collections::HashMap<String, String>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));

    // Start HTTP Server for HTTP-01
    let server_challenges = challenges.clone();
    #[handler]
    fn http01_challenge(
        Path(token): Path<String>,
        Data(state): Data<&Arc<Mutex<std::collections::HashMap<String, String>>>>,
    ) -> (StatusCode, String) {
        let guard = state.lock().expect("challenges mutex poisoned");
        if let Some(key_auth) = guard.get(&token) {
            return (StatusCode::OK, key_auth.clone());
        }
        (StatusCode::NOT_FOUND, "Not Found".to_string())
    }

    tokio::spawn(async move {
        let app = Route::new()
            .at(
                "/.well-known/acme-challenge/:token",
                poem::get(http01_challenge),
            )
            .data(server_challenges);

        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], HTTP_CHALLENGE_PORT));
        info!("Starting HTTP-01 Challenge Server on {}", addr);
        if let Err(err) = Server::new(TcpListener::bind(addr)).run(app).await {
            error!("HTTP server failed: {}", err);
        }
    });

    for authz_url in &order.authorizations {
        info!("Fetching authorization: {}", authz_url);
        // Initial fetch
        let mut authz = client.fetch_authorization(authz_url).await?;

        if authz.status == AuthorizationStatus::Valid {
            info!("Authorization already valid.");
            continue;
        }

        // Find HTTP-01 challenge
        if let Some(challenge_ref) = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
        {
            // Clone needed data to avoid borrowing authz across the loop
            let challenge_token = challenge_ref.token.clone();
            let challenge_url = challenge_ref.url.clone();
            info!("Found HTTP-01 challenge: token={challenge_token}");

            let key_auth = client.compute_key_authorization(&challenge_token)?;
            info!("Key Authorization computed: {key_auth}");

            // Register challenge response
            {
                let mut guard = challenges.lock().expect("challenges mutex poisoned");
                guard.insert(challenge_token.clone(), key_auth);
            }

            info!("Triggering challenge validation...");
            client.trigger_challenge(&challenge_url).await?;

            // Poll for valid status
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                authz = client.fetch_authorization(authz_url).await?;
                info!("Authz status: {:?}", authz.status);
                debug!("Full Authz: {:?}", authz);

                if authz.status == AuthorizationStatus::Valid {
                    info!("Authorization validated!");
                    break;
                }
                if authz.status == AuthorizationStatus::Invalid {
                    anyhow::bail!("Authorization failed (invalid)");
                }

                // Check if our HTTP-01 challenge failed specifically
                if let Some(c) = authz.challenges.iter().find(|c| {
                    c.token == challenge_token
                        && c.r#type == ChallengeType::Http01
                        && c.status == ChallengeStatus::Invalid
                }) {
                    let error_msg = c
                        .error
                        .as_ref()
                        .map_or_else(|| "Unknown error".to_string(), |e| format!("{e:?}"));
                    anyhow::bail!("Challenge failed: {error_msg}");
                }
                // pending, processing... continue
            }
        } else {
            anyhow::bail!("No HTTP-01 challenge found in authorization");
        }
    }

    // 6. Generate CSR
    let primary_domain = settings
        .domains
        .first()
        .ok_or_else(|| anyhow::anyhow!("No domains configured"))?;
    info!("Generating CSR for domain: {}", primary_domain);
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, primary_domain.clone());

    let mut sans = Vec::new();
    for d in &settings.domains {
        // Rcgen expects Ia5String or String that can be converted
        let dns_name = d.clone().try_into()?;
        sans.push(rcgen::SanType::DnsName(dns_name));
    }
    params.subject_alt_names = sans;
    // We need a key for the certificate, separate from account key
    let cert_key = rcgen::KeyPair::generate()?;
    let csr_der = params.serialize_request(&cert_key)?;

    // 7. Finalize Order
    // Note: This will likely fail if challenges are not valid yet.
    info!("Finalizing order at: {}", order.finalize);
    let finalized_order = client
        .finalize_order(&order.finalize, csr_der.der())
        .await?;
    info!("Order status after finalize: {:?}", finalized_order.status);

    // 8. Poll for "valid" status if "processing"
    let mut finalized_order = finalized_order;
    if finalized_order.status == OrderStatus::Processing {
        if let Some(url) = &order.url {
            // Poll
            for i in 0..POLL_ATTEMPTS {
                info!("Order processing (attempt {})...", i + 1);
                tokio::time::sleep(std::time::Duration::from_secs(POLL_INTERVAL_SECS)).await;
                finalized_order = client.poll_order(url).await?;
                if finalized_order.status != OrderStatus::Processing {
                    break;
                }
            }
        } else {
            tracing::warn!(
                "Order processing but no Order URL known to poll. Waiting 5s and hoping..."
            );
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    }

    // 9. Download Certificate
    if let Some(cert_url) = finalized_order.certificate {
        info!("Downloading certificate from: {}", cert_url);
        let cert_pem = client.download_certificate(&cert_url).await?;
        info!("Certificate received. Saving to files...");

        // Save Certificate
        std::fs::write(&settings.paths.cert, &cert_pem)
            .map_err(|e| anyhow::anyhow!("Failed to write cert file: {e}"))?;
        info!("Certificate saved to: {:?}", settings.paths.cert);

        // Save Private Key
        // key is `cert_key` (rcgen::KeyPair)
        let key_pem = cert_key.serialize_pem();
        std::fs::write(&settings.paths.key, &key_pem)
            .map_err(|e| anyhow::anyhow!("Failed to write key file: {e}"))?;
        info!("Private key saved to: {:?}", settings.paths.key);
    } else {
        info!(
            "Order finalized, but certificate not yet ready (or failed). Status: {:?}",
            finalized_order.status
        );
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_order_status_deserialization() {
        let cases = vec![
            ("\"pending\"", OrderStatus::Pending),
            ("\"ready\"", OrderStatus::Ready),
            ("\"processing\"", OrderStatus::Processing),
            ("\"valid\"", OrderStatus::Valid),
            ("\"invalid\"", OrderStatus::Invalid),
        ];
        for (json, expected) in cases {
            let status: OrderStatus = serde_json::from_str(json).unwrap();
            assert_eq!(status, expected);
        }
    }
    #[test]
    fn test_challenge_type_deserialization() {
        let json = r#""http-01""#;
        let c_type: ChallengeType = serde_json::from_str(json).unwrap();
        assert_eq!(c_type, ChallengeType::Http01);
        let json = r#""dns-01""#;
        let c_type: ChallengeType = serde_json::from_str(json).unwrap();
        assert_eq!(c_type, ChallengeType::Dns01);
    }
    #[test]
    fn test_client_initialization() {
        let client = AcmeClient::new("http://example.com".to_string());
        assert!(client.is_ok());
    }
    #[test]
    fn test_compute_key_authorization() {
        let client = AcmeClient::new("http://example.com".to_string()).unwrap();
        let token = "test_token_123_xyz";
        let ka = client.compute_key_authorization(token).unwrap();
        // KA format: "token.thumbprint"
        assert!(ka.starts_with(token));
        let parts: Vec<&str> = ka.split('.').collect();
        assert_eq!(
            parts.len(),
            2,
            "Key Authorization should have 2 parts separated by ."
        );
        // Check thumbprint is valid web-safe base64 (roughly)
        let thumbprint = parts[1];
        assert!(!thumbprint.is_empty());
        // Simple check: no padding characters usually in raw b64url
        assert!(!thumbprint.contains('='));
        assert!(!thumbprint.contains('+'));
        assert!(!thumbprint.contains('/'));
    }
}
