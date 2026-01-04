#![allow(dead_code)]
#![allow(clippy::struct_field_names)]
#![allow(clippy::missing_errors_doc)]

use anyhow::{Context, Result};
use base64::Engine;
use reqwest::Client;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair};
use serde::Deserialize;
use tracing::{debug, info};

// --- ACME Data Structures ---

#[derive(Debug, Deserialize, Clone)]
struct Directory {
    #[serde(rename = "newNonce")]
    new_nonce: String,
    #[serde(rename = "newAccount")]
    new_account: String,
    #[serde(rename = "newOrder")]
    new_order: String,
}

#[derive(Debug, Deserialize)]
struct Account {
    status: String,
    // orders: String,
}

#[derive(Debug, Deserialize)]
struct Order {
    status: String,
    finalize: String,
    authorizations: Vec<String>,
    certificate: Option<String>,
}

// --- Client ---

pub struct AcmeClient {
    client: Client,
    directory_url: String,
    directory: Option<Directory>,
    key_pair: EcdsaKeyPair,
    key_id: Option<String>, // Key ID (Account URL) after registration
    nonce: Option<String>,
}

#[allow(dead_code)] // Temporary while implementing
impl AcmeClient {
    pub fn new(directory_url: String) -> Result<Self> {
        // Generate a new ephemeral account key (P-256)
        let rng = ring::rand::SystemRandom::new();
        // Fix: Correct argument order (alg, rng)
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng)
            .map_err(|_| anyhow::anyhow!("Failed to generate account key"))?;
        let key_pair =
            EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng)
                .map_err(|_| anyhow::anyhow!("Failed to parse generated key pair"))?;

        Ok(Self {
            client: Client::builder()
                .danger_accept_invalid_certs(true)
                .build()?, // TODO: Handle CA properly
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
        // If we have a cached nonce from previous response, use it (Nonce-replaying not implemented typically, usually one-time)
        // Actually, Replay-Nonce header is key.
        // For the first request, get a fresh nonce from newNonce endpoint.
        if let Some(nonce) = self.nonce.take() {
            return Ok(nonce);
        }

        self.fetch_directory().await?;
        let dir = self.directory.as_ref().unwrap();

        let resp = self.client.head(&dir.new_nonce).send().await?;
        let nonce = resp
            .headers()
            .get("replay-nonce")
            .context("Missing Replay-Nonce header")?
            .to_str()?
            .to_string();
        Ok(nonce)
    }

    // JWS Signing Implementation will go here...
    // async fn post_jose(...)
}

// --- Entry Point ---

#[allow(clippy::missing_errors_doc)]
pub async fn issue_certificate(
    args: &crate::Args,
    _eab: Option<crate::eab::EabCredentials>,
) -> Result<()> {
    let mut client = AcmeClient::new(args.ca_url.clone())?;

    // 1. Get Directory
    client.fetch_directory().await?;
    info!("Directory loaded.");

    // 2. Get Nonce (Test)
    let nonce = client.get_nonce().await?;
    debug!("Got initial nonce: {}", nonce);

    // TODO: Registration, Ordering, Challenge... implementation needed.
    // For now, let's confirm the plumbing (reqwest + ring) compiles and works.

    // Placeholder CSR Gen logic (keeping it to verify rcgen still works)
    info!("Generating CSR locally (Test)...");
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = vec![rcgen::SanType::DnsName(args.domain.clone().try_into()?)];
    let key_pair = rcgen::KeyPair::generate()?;
    let _csr = params.serialize_request(&key_pair)?;

    info!("Core plumbing ready. Next: JWS implementation.");
    Ok(())
}
