use std::collections::HashSet;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tracing::{info, warn};
use x509_parser::pem::Pem;

use crate::acme::client::AcmeClient;
use crate::acme::responder_client;
use crate::acme::types::{AuthorizationStatus, ChallengeStatus, ChallengeType, OrderStatus};
use crate::fs_util;

fn contact_from_email(email: &str) -> String {
    if email.starts_with("mailto:") {
        email.to_string()
    } else {
        format!("mailto:{email}")
    }
}

fn build_csr_params(
    settings: &crate::config::Settings,
    profile: &crate::config::DaemonProfileSettings,
) -> Result<rcgen::CertificateParams> {
    let primary_domain = crate::config::profile_domain(settings, profile);
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, primary_domain.clone());

    let dns_name = primary_domain.try_into()?;
    params.subject_alt_names = vec![rcgen::SanType::DnsName(dns_name)];
    Ok(params)
}

fn split_leaf_and_chain(cert_pem: &str) -> Result<(String, Vec<Vec<u8>>)> {
    let mut certs = Vec::new();
    for pem in Pem::iter_from_buffer(cert_pem.as_bytes()) {
        let pem = pem.map_err(|e| anyhow::anyhow!("Failed to parse PEM block: {e:?}"))?;
        if pem.label == "CERTIFICATE" {
            certs.push(pem);
        }
    }
    if certs.is_empty() {
        anyhow::bail!("No certificate PEM blocks found in ACME response");
    }
    let leaf = certs.remove(0);
    let leaf_pem = encode_cert_pem(&leaf.contents);
    let chain = certs.into_iter().map(|pem| pem.contents).collect();
    Ok((leaf_pem, chain))
}

fn encode_cert_pem(der: &[u8]) -> String {
    const LINE_WRAP: usize = 64;
    let b64 = STANDARD.encode(der);
    let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
    let mut index = 0;
    while index < b64.len() {
        let end = (index + LINE_WRAP).min(b64.len());
        out.push_str(&b64[index..end]);
        out.push('\n');
        index = end;
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut output = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("writing to string should not fail");
    }
    output
}

fn verify_chain_fingerprints(chain: &[Vec<u8>], trusted: &[String]) -> Result<()> {
    let allowed: HashSet<String> = trusted
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect();
    for cert in chain {
        let fingerprint = sha256_hex(cert);
        if !allowed.contains(&fingerprint) {
            anyhow::bail!("Untrusted CA fingerprint: {fingerprint}");
        }
    }
    Ok(())
}

fn build_ca_bundle(chain: &[Vec<u8>]) -> String {
    let mut bundle = String::new();
    for cert in chain {
        bundle.push_str(&encode_cert_pem(cert));
    }
    bundle
}

async fn register_acme_account(
    client: &mut AcmeClient,
    email: &str,
    eab_creds: Option<crate::eab::EabCredentials>,
) -> Result<()> {
    if let Some(creds) = eab_creds {
        info!("Using existing EAB credentials for Key ID: {}", creds.kid);
        client
            .register_account(&[contact_from_email(email)], Some(&creds))
            .await?;
    } else {
        client
            .register_account(&[contact_from_email(email)], None)
            .await?;
    }
    Ok(())
}

async fn validate_http01_authorizations(
    settings: &crate::config::Settings,
    client: &mut AcmeClient,
    order: &crate::acme::types::Order,
) -> Result<()> {
    for authz_url in &order.authorizations {
        validate_authorization_http01(settings, client, authz_url).await?;
    }
    Ok(())
}

async fn validate_authorization_http01(
    settings: &crate::config::Settings,
    client: &mut AcmeClient,
    authz_url: &str,
) -> Result<()> {
    tracing::debug!("Fetching authorization: {}", authz_url);
    let authz = client.fetch_authorization(authz_url).await?;

    if authz.status == AuthorizationStatus::Valid {
        tracing::debug!("Authorization already valid.");
        return Ok(());
    }

    let challenge_ref = authz
        .challenges
        .iter()
        .find(|c| c.r#type == ChallengeType::Http01)
        .ok_or_else(|| anyhow::anyhow!("No HTTP-01 challenge found in authorization"))?;

    let challenge_token = challenge_ref.token.clone();
    let challenge_url = challenge_ref.url.clone();
    tracing::debug!("Found HTTP-01 challenge: token={challenge_token}");

    let key_auth = client.compute_key_authorization(&challenge_token)?;
    tracing::debug!("Key Authorization computed: {key_auth}");

    responder_client::register_http01_token(settings, &challenge_token, &key_auth).await?;

    tracing::debug!("Triggering challenge validation...");
    client.trigger_challenge(&challenge_url).await?;

    wait_for_http01_validation(settings, client, authz_url, &challenge_token).await?;

    Ok(())
}

async fn wait_for_http01_validation(
    settings: &crate::config::Settings,
    client: &mut AcmeClient,
    authz_url: &str,
    challenge_token: &str,
) -> Result<()> {
    let mut last_error: Option<String> = None;

    for attempt in 0..settings.acme.poll_attempts {
        tokio::time::sleep(std::time::Duration::from_secs(
            settings.acme.poll_interval_secs,
        ))
        .await;
        let authz = client.fetch_authorization(authz_url).await?;
        tracing::debug!("Authz status: {:?}", authz.status);
        tracing::debug!("Full Authz: {:?}", authz);

        if authz.status == AuthorizationStatus::Valid {
            info!("Authorization validated!");
            return Ok(());
        }
        if authz.status == AuthorizationStatus::Invalid {
            anyhow::bail!("Authorization failed (invalid)");
        }

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
        if let Some(c) = authz.challenges.iter().find(|c| {
            c.token == challenge_token && c.r#type == ChallengeType::Http01 && c.error.is_some()
        }) {
            last_error = c.error.as_ref().map(|e| format!("{e:?}"));
        }

        tracing::debug!(
            "HTTP-01 authorization pending (attempt {}/{}).",
            attempt + 1,
            settings.acme.poll_attempts
        );
    }

    let error_msg = last_error.unwrap_or_else(|| "Unknown error".to_string());
    anyhow::bail!(
        "Authorization did not validate after {} attempts. Last HTTP-01 error: {error_msg}",
        settings.acme.poll_attempts
    );
}

async fn wait_for_order_completion(
    settings: &crate::config::Settings,
    client: &mut AcmeClient,
    order: &crate::acme::types::Order,
    mut finalized_order: crate::acme::types::Order,
) -> Result<crate::acme::types::Order> {
    if finalized_order.status == OrderStatus::Processing {
        if let Some(url) = &order.url {
            for i in 0..settings.acme.poll_attempts {
                tracing::debug!("Order processing (attempt {})...", i + 1);
                tokio::time::sleep(std::time::Duration::from_secs(
                    settings.acme.poll_interval_secs,
                ))
                .await;
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
    Ok(finalized_order)
}

/// Issues a certificate via ACME protocol.
///
/// # Errors
/// Returns error if ACME protocol fails.
///
pub async fn issue_certificate(
    settings: &crate::config::Settings,
    profile: &crate::config::DaemonProfileSettings,
    eab_creds: Option<crate::eab::EabCredentials>,
) -> Result<()> {
    let mut client = AcmeClient::new(settings.server.clone(), &settings.acme, &settings.trust)?;

    client.fetch_directory().await?;
    tracing::debug!("Directory loaded.");

    let nonce = client.get_nonce().await?;
    tracing::debug!("Got initial nonce: {}", nonce);

    register_acme_account(&mut client, &settings.email, eab_creds).await?;

    let primary_domain = crate::config::profile_domain(settings, profile);
    let order = client
        .create_order(std::slice::from_ref(&primary_domain))
        .await?;
    info!("Order created: {:?}", order);

    validate_http01_authorizations(settings, &mut client, &order).await?;

    info!("Generating CSR for domain: {}", primary_domain);
    let params = build_csr_params(settings, profile)?;
    let cert_key = rcgen::KeyPair::generate()?;
    let csr_der = params.serialize_request(&cert_key)?;

    info!("Finalizing order at: {}", order.finalize);
    let finalized_order = client
        .finalize_order(&order.finalize, csr_der.der())
        .await?;
    info!("Order status after finalize: {:?}", finalized_order.status);

    let finalized_order =
        wait_for_order_completion(settings, &mut client, &order, finalized_order).await?;

    if let Some(cert_url) = finalized_order.certificate {
        info!("Downloading certificate from: {}", cert_url);
        let cert_pem = client.download_certificate(&cert_url).await?;
        info!("Certificate received. Saving to files...");

        let (leaf_pem, chain) = if settings.trust.ca_bundle_path.is_some() {
            split_leaf_and_chain(&cert_pem)?
        } else {
            (cert_pem.clone(), Vec::new())
        };
        let key_pem = cert_key.serialize_pem();
        fs_util::write_cert_and_key(&profile.paths.cert, &profile.paths.key, &leaf_pem, &key_pem)
            .await?;
        info!("Certificate saved to: {:?}", profile.paths.cert);
        info!("Private key saved to: {:?}", profile.paths.key);

        if let Some(bundle_path) = &settings.trust.ca_bundle_path {
            if chain.is_empty() {
                warn!("Certificate chain not present; CA bundle not updated.");
            } else {
                verify_chain_fingerprints(&chain, &settings.trust.trusted_ca_sha256)?;
                let bundle = build_ca_bundle(&chain);
                fs_util::write_ca_bundle(bundle_path, &bundle).await?;
                info!("CA bundle saved to: {:?}", bundle_path);
            }
        }
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
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;

    const TEST_DOMAIN: &str = "trusted.domain";

    #[test]
    fn test_contact_from_email_adds_mailto_prefix() {
        let contact = contact_from_email("admin@example.com");
        assert_eq!(contact, "mailto:admin@example.com");
    }

    #[test]
    fn test_contact_from_email_keeps_existing_prefix() {
        let contact = contact_from_email("mailto:admin@example.com");
        assert_eq!(contact, "mailto:admin@example.com");
    }

    fn test_settings() -> crate::config::Settings {
        crate::config::Settings {
            email: "test@example.com".to_string(),
            server: "https://example.com/acme/directory".to_string(),
            domain: TEST_DOMAIN.to_string(),
            eab: None,
            acme: crate::config::AcmeSettings {
                directory_fetch_attempts: 10,
                directory_fetch_base_delay_secs: 1,
                directory_fetch_max_delay_secs: 10,
                poll_attempts: 15,
                poll_interval_secs: 2,
                http_responder_url: "http://localhost:8080".to_string(),
                http_responder_hmac: "dev-hmac".to_string(),
                http_responder_timeout_secs: 5,
                http_responder_token_ttl_secs: 300,
            },
            retry: crate::config::RetrySettings {
                backoff_secs: vec![5, 10, 30],
            },
            trust: crate::config::TrustSettings::default(),
            scheduler: crate::config::SchedulerSettings {
                max_concurrent_issuances: 3,
            },
            profiles: Vec::new(),
        }
    }

    fn test_profile() -> crate::config::DaemonProfileSettings {
        crate::config::DaemonProfileSettings {
            service_name: "edge-proxy".to_string(),
            instance_id: "001".to_string(),
            hostname: "edge-node-01".to_string(),
            paths: crate::config::Paths {
                cert: PathBuf::from("certs/edge-proxy-a.pem"),
                key: PathBuf::from("certs/edge-proxy-a.key"),
            },
            daemon: crate::config::DaemonRuntimeSettings::default(),
            retry: None,
            hooks: crate::config::HookSettings::default(),
            eab: None,
        }
    }

    fn expected_domain() -> String {
        "001.edge-proxy.edge-node-01.trusted.domain".to_string()
    }

    fn parse_pem_der(pem: &str) -> Vec<u8> {
        let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).unwrap();
        parsed.contents
    }

    fn test_cert_pem(common_name: &str) -> String {
        let mut params = rcgen::CertificateParams::new(vec![common_name.to_string()]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        cert.pem()
    }

    async fn write_outputs_for_test(
        settings: &crate::config::Settings,
        profile: &crate::config::DaemonProfileSettings,
        cert_pem: &str,
    ) -> Result<()> {
        let (leaf_pem, chain) = split_leaf_and_chain(cert_pem)?;
        let key_pem = rcgen::KeyPair::generate()?.serialize_pem();
        fs_util::write_cert_and_key(&profile.paths.cert, &profile.paths.key, &leaf_pem, &key_pem)
            .await?;
        if let Some(bundle_path) = &settings.trust.ca_bundle_path
            && !chain.is_empty()
        {
            verify_chain_fingerprints(&chain, &settings.trust.trusted_ca_sha256)?;
            let bundle = build_ca_bundle(&chain);
            fs_util::write_ca_bundle(bundle_path, &bundle).await?;
        }
        Ok(())
    }

    #[test]
    fn test_build_csr_params_includes_dns_san() {
        let settings = test_settings();
        let profile = test_profile();
        let params = build_csr_params(&settings, &profile).unwrap();
        let mut has_dns = false;
        for san in params.subject_alt_names {
            if let rcgen::SanType::DnsName(dns) = san
                && dns.as_str() == expected_domain()
            {
                has_dns = true;
            }
        }

        assert!(has_dns);
    }

    #[test]
    fn test_build_csr_params_sets_common_name_to_primary_domain() {
        let settings = test_settings();
        let profile = test_profile();
        let params = build_csr_params(&settings, &profile).unwrap();
        let common_name = params.distinguished_name.get(&rcgen::DnType::CommonName);
        let common_name = match common_name {
            Some(rcgen::DnValue::Utf8String(value)) => value.as_str(),
            Some(other) => panic!("Unexpected common name value: {other:?}"),
            None => panic!("Common name missing"),
        };
        assert_eq!(common_name, expected_domain());
    }

    #[test]
    fn test_split_leaf_and_chain_separates_pem_blocks() {
        let leaf_pem = test_cert_pem("leaf.example");
        let chain_pem = test_cert_pem("intermediate.example");
        let combined = format!("{leaf_pem}{chain_pem}");

        let (leaf_only, chain) = split_leaf_and_chain(&combined).unwrap();

        assert_eq!(parse_pem_der(&leaf_pem), parse_pem_der(&leaf_only));
        assert_eq!(chain, vec![parse_pem_der(&chain_pem)]);
    }

    #[test]
    fn test_verify_chain_fingerprints_matches_trusted() {
        let chain_pem = test_cert_pem("intermediate.example");
        let der = parse_pem_der(&chain_pem);
        let fingerprint = sha256_hex(&der);

        verify_chain_fingerprints(std::slice::from_ref(&der), &[fingerprint]).unwrap();

        let err =
            verify_chain_fingerprints(std::slice::from_ref(&der), &["00".repeat(32)]).unwrap_err();
        assert!(err.to_string().contains("Untrusted CA fingerprint"));
    }

    #[tokio::test]
    async fn test_multi_pem_writes_ca_bundle() {
        let temp = tempdir().expect("temp dir");
        let cert_dir = temp.path().join("certs");
        let bundle_path = temp.path().join("ca-bundle.pem");
        tokio::fs::create_dir_all(&cert_dir)
            .await
            .expect("create cert dir");

        let mut settings = test_settings();
        settings.trust.ca_bundle_path = Some(bundle_path.clone());

        let mut profile = test_profile();
        profile.paths.cert = cert_dir.join("leaf.pem");
        profile.paths.key = cert_dir.join("leaf.key");

        let leaf_pem = test_cert_pem("leaf.example");
        let intermediate_pem = test_cert_pem("intermediate.example");
        let root_pem = test_cert_pem("root.example");
        let combined = format!("{leaf_pem}{intermediate_pem}{root_pem}");

        let chain = [parse_pem_der(&intermediate_pem), parse_pem_der(&root_pem)];
        settings.trust.trusted_ca_sha256 = chain.iter().map(|der| sha256_hex(der)).collect();

        write_outputs_for_test(&settings, &profile, &combined)
            .await
            .expect("write outputs");

        let bundle = tokio::fs::read_to_string(&bundle_path)
            .await
            .expect("read bundle");
        let count = bundle.matches("BEGIN CERTIFICATE").count();
        assert_eq!(count, 2);
    }

    #[tokio::test]
    async fn test_multi_pem_fails_on_untrusted_chain() {
        let temp = tempdir().expect("temp dir");
        let cert_dir = temp.path().join("certs");
        let bundle_path = temp.path().join("ca-bundle.pem");
        tokio::fs::create_dir_all(&cert_dir)
            .await
            .expect("create cert dir");

        let mut settings = test_settings();
        settings.trust.ca_bundle_path = Some(bundle_path.clone());
        settings.trust.trusted_ca_sha256 = vec!["00".repeat(32)];

        let mut profile = test_profile();
        profile.paths.cert = cert_dir.join("leaf.pem");
        profile.paths.key = cert_dir.join("leaf.key");

        let leaf_pem = test_cert_pem("leaf.example");
        let intermediate_pem = test_cert_pem("intermediate.example");
        let combined = format!("{leaf_pem}{intermediate_pem}");

        let err = write_outputs_for_test(&settings, &profile, &combined)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("Untrusted CA fingerprint"));
        assert!(!bundle_path.exists());
    }
}
