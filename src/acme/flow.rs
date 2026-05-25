use std::collections::HashSet;
use std::path::Path;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use tracing::{info, warn};
use x509_parser::pem::Pem;

use crate::acme::client::AcmeClient;
use crate::acme::responder_client;
use crate::acme::types::{AuthorizationStatus, ChallengeStatus, ChallengeType, OrderStatus};
use crate::cert_group::CertGroupPolicy;
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
    // codeql[rust/cleartext-logging]: PEM contents are returned for file writes, not logged.
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

/// Merges any trusted certs already on disk at `existing_bundle` with
/// the newly issued `new_chain`, deduping by DER SHA-256.
///
/// The bundle's contract is "everything a consumer needs to validate
/// certs from this CA hierarchy". For a self-signed root + intermediate
/// hierarchy the ACME response chain typically contains only the
/// intermediate, so overwriting the bundle with the chain alone strips
/// the root and breaks default-config TLS clients (#622). Reading the
/// existing bundle and keeping every block whose fingerprint is in
/// `trusted` preserves the root across issuances while still filtering
/// out any junk left behind by an earlier misconfiguration.
fn merge_ca_bundle(
    existing_bundle: Option<&[u8]>,
    new_chain: &[Vec<u8>],
    trusted: &[String],
) -> String {
    let allowed: HashSet<String> = trusted
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect();
    let mut order: Vec<Vec<u8>> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    if let Some(existing) = existing_bundle {
        for pem in Pem::iter_from_buffer(existing) {
            let Ok(pem) = pem else { continue };
            if pem.label != "CERTIFICATE" {
                continue;
            }
            let fingerprint = sha256_hex(&pem.contents);
            if !allowed.contains(&fingerprint) {
                continue;
            }
            if seen.insert(fingerprint) {
                order.push(pem.contents);
            }
        }
    }
    for cert in new_chain {
        let fingerprint = sha256_hex(cert);
        if seen.insert(fingerprint) {
            order.push(cert.clone());
        }
    }
    let mut bundle = String::new();
    for cert in &order {
        bundle.push_str(&encode_cert_pem(cert));
    }
    bundle
}

/// Writes the merged CA bundle to `bundle_path`. Production code and
/// the test helper share this path so the chain-only write cannot be
/// silently reintroduced in only one of them (#622 AC #2).
///
/// `NotFound` on the existing bundle is the legitimate first-issuance
/// case and merges against an empty seed. Every other read error is
/// propagated: a bundle the agent cannot inspect must not be
/// overwritten with only the ACME response chain, or the
/// intermediate-only state this PR hardens against would silently
/// reappear whenever mode/ACL/ownership drift makes the file
/// unreadable but still writeable.
async fn write_merged_ca_bundle(
    bundle_path: &Path,
    chain: &[Vec<u8>],
    trusted: &[String],
    policy: CertGroupPolicy,
) -> Result<()> {
    let existing = match tokio::fs::read(bundle_path).await {
        Ok(bytes) => Some(bytes),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!(
                "refusing to overwrite unreadable CA bundle at {}",
                bundle_path.display()
            )));
        }
    };
    let bundle = merge_ca_bundle(existing.as_deref(), chain, trusted);
    fs_util::write_ca_bundle(bundle_path, &bundle, policy).await
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
    insecure_mode: bool,
) -> Result<()> {
    let mut client = AcmeClient::new(
        settings.server.clone(),
        &settings.acme,
        &settings.trust,
        insecure_mode,
    )?;

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
        let policy = crate::cert_group::CertGroupPolicy {
            gid: profile.cert_group_gid,
        };
        fs_util::write_cert_and_key(
            &profile.paths.cert,
            &profile.paths.key,
            &leaf_pem,
            &key_pem,
            policy,
        )
        .await?;
        info!("Certificate saved to: {:?}", profile.paths.cert);
        info!("Private key saved to: {:?}", profile.paths.key);

        if let Some(bundle_path) = &settings.trust.ca_bundle_path {
            if chain.is_empty() {
                warn!("Certificate chain not present; CA bundle not updated.");
            } else {
                verify_chain_fingerprints(&chain, &settings.trust.trusted_ca_sha256)?;
                write_merged_ca_bundle(
                    bundle_path,
                    &chain,
                    &settings.trust.trusted_ca_sha256,
                    policy,
                )
                .await?;
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
            openbao: None,
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
            cert_group_gid: None,
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
        let policy = crate::cert_group::CertGroupPolicy {
            gid: profile.cert_group_gid,
        };
        fs_util::write_cert_and_key(
            &profile.paths.cert,
            &profile.paths.key,
            &leaf_pem,
            &key_pem,
            policy,
        )
        .await?;
        if let Some(bundle_path) = &settings.trust.ca_bundle_path
            && !chain.is_empty()
        {
            verify_chain_fingerprints(&chain, &settings.trust.trusted_ca_sha256)?;
            write_merged_ca_bundle(
                bundle_path,
                &chain,
                &settings.trust.trusted_ca_sha256,
                policy,
            )
            .await?;
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

    /// Regression for #622: when the operator's `service add` writes a
    /// root+intermediate bundle to disk and the subsequent ACME
    /// response contains only the intermediate, the agent must keep
    /// the root in `ca_bundle_path`. Otherwise default-Node/default-
    /// openssl TLS clients fail with `unable to get issuer certificate`
    /// because the chain no longer terminates at a trust anchor that
    /// lives on disk.
    #[tokio::test]
    async fn test_multi_pem_preserves_existing_root_in_bundle() {
        let temp = tempdir().expect("temp dir");
        let cert_dir = temp.path().join("certs");
        let bundle_path = temp.path().join("ca-bundle.pem");
        tokio::fs::create_dir_all(&cert_dir)
            .await
            .expect("create cert dir");

        let intermediate_pem = test_cert_pem("intermediate.example");
        let root_pem = test_cert_pem("root.example");
        let intermediate_der = parse_pem_der(&intermediate_pem);
        let root_der = parse_pem_der(&root_pem);

        // Seed the on-disk bundle the way `bootroot service add` does:
        // root followed by intermediate.
        tokio::fs::write(&bundle_path, format!("{root_pem}{intermediate_pem}"))
            .await
            .expect("seed bundle");

        let mut settings = test_settings();
        settings.trust.ca_bundle_path = Some(bundle_path.clone());
        settings.trust.trusted_ca_sha256 =
            vec![sha256_hex(&root_der), sha256_hex(&intermediate_der)];

        let mut profile = test_profile();
        profile.paths.cert = cert_dir.join("leaf.pem");
        profile.paths.key = cert_dir.join("leaf.key");

        // ACME response carries leaf + intermediate only (the typical
        // step-ca case that triggered the silent failure).
        let leaf_pem = test_cert_pem("leaf.example");
        let acme_response = format!("{leaf_pem}{intermediate_pem}");

        write_outputs_for_test(&settings, &profile, &acme_response)
            .await
            .expect("write outputs");

        let bundle = tokio::fs::read(&bundle_path).await.expect("read bundle");
        let fingerprints: HashSet<String> = Pem::iter_from_buffer(&bundle)
            .filter_map(Result::ok)
            .filter(|pem| pem.label == "CERTIFICATE")
            .map(|pem| sha256_hex(&pem.contents))
            .collect();
        assert!(
            fingerprints.contains(&sha256_hex(&root_der)),
            "root fingerprint must survive issuance: {fingerprints:?}"
        );
        assert!(
            fingerprints.contains(&sha256_hex(&intermediate_der)),
            "intermediate fingerprint must remain in bundle: {fingerprints:?}"
        );
        assert!(
            !fingerprints.contains(&sha256_hex(&parse_pem_der(&leaf_pem))),
            "leaf must never appear in ca bundle: {fingerprints:?}"
        );
    }

    /// Untrusted blocks already on disk must not survive the merge.
    /// Anything not in `trusted_ca_sha256` is filtered out before the
    /// new chain is appended, so a stale or hostile cert that crept
    /// into `ca-bundle.pem` cannot get re-anointed by the next
    /// issuance write.
    #[tokio::test]
    async fn test_merge_drops_untrusted_existing_blocks() {
        let intermediate_pem = test_cert_pem("intermediate.example");
        let intermediate_der = parse_pem_der(&intermediate_pem);
        let stale_pem = test_cert_pem("stale.example");
        let combined = format!("{intermediate_pem}{stale_pem}");

        let merged = merge_ca_bundle(
            Some(combined.as_bytes()),
            std::slice::from_ref(&intermediate_der),
            &[sha256_hex(&intermediate_der)],
        );

        let fingerprints: HashSet<String> = Pem::iter_from_buffer(merged.as_bytes())
            .filter_map(Result::ok)
            .map(|pem| sha256_hex(&pem.contents))
            .collect();
        assert!(fingerprints.contains(&sha256_hex(&intermediate_der)));
        assert!(!fingerprints.contains(&sha256_hex(&parse_pem_der(&stale_pem))));
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

    /// `write_merged_ca_bundle` must fail closed when the existing
    /// bundle cannot be read for reasons other than `NotFound`. The
    /// previous `.await.ok()` collapsed every read error into an empty
    /// seed, which would silently overwrite a still-present but
    /// unreadable bundle with only the ACME chain — the exact
    /// intermediate-only state #622 hardens against.
    #[tokio::test]
    async fn test_write_merged_ca_bundle_fails_when_existing_unreadable() {
        let temp = tempdir().expect("temp dir");
        // A directory at `bundle_path` reproduces a non-`NotFound`
        // read error portably across platforms without depending on
        // chmod semantics (which root in CI can bypass).
        let bundle_path = temp.path().join("ca-bundle.pem");
        tokio::fs::create_dir_all(&bundle_path)
            .await
            .expect("create directory at bundle path");

        let intermediate_pem = test_cert_pem("intermediate.example");
        let intermediate_der = parse_pem_der(&intermediate_pem);
        let trusted = vec![sha256_hex(&intermediate_der)];

        let err = write_merged_ca_bundle(
            &bundle_path,
            std::slice::from_ref(&intermediate_der),
            &trusted,
            CertGroupPolicy { gid: None },
        )
        .await
        .expect_err("must refuse to overwrite an unreadable bundle");
        let message = format!("{err:#}");
        assert!(
            message.contains("refusing to overwrite unreadable CA bundle"),
            "expected fail-closed context, got: {message}"
        );
    }
}
