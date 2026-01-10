use anyhow::Result;
use tracing::info;

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
    profile: &crate::config::ProfileSettings,
    uri_san: Option<&str>,
) -> Result<rcgen::CertificateParams> {
    let primary_domain = profile
        .domains
        .first()
        .ok_or_else(|| anyhow::anyhow!("No domains configured"))?;
    let mut params = rcgen::CertificateParams::default();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, primary_domain.clone());

    let mut sans = Vec::new();
    for d in &profile.domains {
        let dns_name = d.clone().try_into()?;
        sans.push(rcgen::SanType::DnsName(dns_name));
    }
    if let Some(uri_san) = uri_san {
        let uri = uri_san.try_into()?;
        sans.push(rcgen::SanType::URI(uri));
    }
    params.subject_alt_names = sans;
    Ok(params)
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

    wait_for_http01_validation(client, authz_url, &challenge_token).await?;

    Ok(())
}

async fn wait_for_http01_validation(
    client: &mut AcmeClient,
    authz_url: &str,
    challenge_token: &str,
) -> Result<()> {
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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
    }
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
    profile: &crate::config::ProfileSettings,
    eab_creds: Option<crate::eab::EabCredentials>,
    uri_san: Option<&str>,
) -> Result<()> {
    let mut client = AcmeClient::new(settings.server.clone(), &settings.acme)?;

    client.fetch_directory().await?;
    tracing::debug!("Directory loaded.");

    let nonce = client.get_nonce().await?;
    tracing::debug!("Got initial nonce: {}", nonce);

    register_acme_account(&mut client, &settings.email, eab_creds).await?;

    let order = client.create_order(&profile.domains).await?;
    info!("Order created: {:?}", order);

    validate_http01_authorizations(settings, &mut client, &order).await?;

    let primary_domain = profile
        .domains
        .first()
        .ok_or_else(|| anyhow::anyhow!("No domains configured"))?;
    info!("Generating CSR for domain: {}", primary_domain);
    let params = build_csr_params(profile, uri_san)?;
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

        let key_pem = cert_key.serialize_pem();
        fs_util::write_cert_and_key(&profile.paths.cert, &profile.paths.key, &cert_pem, &key_pem)
            .await?;
        info!("Certificate saved to: {:?}", profile.paths.cert);
        info!("Private key saved to: {:?}", profile.paths.key);
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

    use super::*;

    const TEST_DOMAIN: &str = "example.com";
    const TEST_URI_SAN: &str = "spiffe://trusted.domain/edge-node-01/edge-proxy/001";

    #[test]
    fn test_build_csr_params_includes_uri_san() {
        let profile = crate::config::ProfileSettings {
            name: "edge-proxy-a".to_string(),
            daemon_name: "edge-proxy".to_string(),
            instance_id: "001".to_string(),
            hostname: "edge-node-01".to_string(),
            uri_san_enabled: true,
            domains: vec![TEST_DOMAIN.to_string()],
            paths: crate::config::Paths {
                cert: PathBuf::from("certs/edge-proxy-a.pem"),
                key: PathBuf::from("certs/edge-proxy-a.key"),
            },
            daemon: crate::config::DaemonSettings::default(),
            retry: None,
            hooks: crate::config::HookSettings::default(),
            eab: None,
        };

        let params = build_csr_params(&profile, Some(TEST_URI_SAN)).unwrap();
        let mut has_uri = false;
        let mut has_dns = false;
        for san in params.subject_alt_names {
            match san {
                rcgen::SanType::URI(uri) => {
                    if uri.as_str() == TEST_URI_SAN {
                        has_uri = true;
                    }
                }
                rcgen::SanType::DnsName(dns) => {
                    if dns.as_str() == TEST_DOMAIN {
                        has_dns = true;
                    }
                }
                _ => {}
            }
        }

        assert!(has_uri);
        assert!(has_dns);
    }
}
