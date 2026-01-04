use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Result;
use tokio::fs;
use tracing::info;

use crate::acme::client::AcmeClient;
use crate::acme::http01::ChallengeStore;
use crate::acme::types::{AuthorizationStatus, ChallengeStatus, ChallengeType, OrderStatus};

const KEY_FILE_MODE: u32 = 0o600;
const SECRETS_DIR_MODE: u32 = 0o700;

fn contact_from_email(email: &str) -> String {
    if email.starts_with("mailto:") {
        email.to_string()
    } else {
        format!("mailto:{email}")
    }
}

async fn ensure_secrets_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create secrets dir {}: {e}", path.display()))?;
    fs::set_permissions(path, std::fs::Permissions::from_mode(SECRETS_DIR_MODE))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set secrets dir permissions: {e}"))?;
    Ok(())
}

async fn set_key_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, std::fs::Permissions::from_mode(KEY_FILE_MODE))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set key file permissions: {e}"))?;
    Ok(())
}

/// Issues a certificate via ACME protocol.
///
/// # Errors
/// Returns error if ACME protocol fails.
///
#[allow(clippy::too_many_lines)]
pub async fn issue_certificate(
    settings: &crate::config::Settings,
    eab_creds: Option<crate::eab::EabCredentials>,
    challenges: ChallengeStore,
) -> Result<()> {
    let mut client = AcmeClient::new(settings.server.clone(), &settings.acme)?;

    {
        let mut guard = challenges.lock().await;
        guard.clear();
    }

    client.fetch_directory().await?;
    info!("Directory loaded.");

    let nonce = client.get_nonce().await?;
    tracing::debug!("Got initial nonce: {}", nonce);

    if let Some(creds) = eab_creds {
        info!("Using existing EAB credentials for Key ID: {}", creds.kid);
        client
            .register_account(&[contact_from_email(&settings.email)], Some(&creds))
            .await?;
    } else {
        client
            .register_account(&[contact_from_email(&settings.email)], None)
            .await?;
    }

    let order = client.create_order(&settings.domains).await?;
    info!("Order created: {:?}", order);

    for authz_url in &order.authorizations {
        info!("Fetching authorization: {}", authz_url);
        let mut authz = client.fetch_authorization(authz_url).await?;

        if authz.status == AuthorizationStatus::Valid {
            info!("Authorization already valid.");
            continue;
        }

        if let Some(challenge_ref) = authz
            .challenges
            .iter()
            .find(|c| c.r#type == ChallengeType::Http01)
        {
            let challenge_token = challenge_ref.token.clone();
            let challenge_url = challenge_ref.url.clone();
            info!("Found HTTP-01 challenge: token={challenge_token}");

            let key_auth = client.compute_key_authorization(&challenge_token)?;
            info!("Key Authorization computed: {key_auth}");

            {
                let mut guard = challenges.lock().await;
                guard.insert(challenge_token.clone(), key_auth);
            }

            info!("Triggering challenge validation...");
            client.trigger_challenge(&challenge_url).await?;

            loop {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                authz = client.fetch_authorization(authz_url).await?;
                info!("Authz status: {:?}", authz.status);
                tracing::debug!("Full Authz: {:?}", authz);

                if authz.status == AuthorizationStatus::Valid {
                    info!("Authorization validated!");
                    break;
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
        } else {
            anyhow::bail!("No HTTP-01 challenge found in authorization");
        }
    }

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
        let dns_name = d.clone().try_into()?;
        sans.push(rcgen::SanType::DnsName(dns_name));
    }
    params.subject_alt_names = sans;
    let cert_key = rcgen::KeyPair::generate()?;
    let csr_der = params.serialize_request(&cert_key)?;

    info!("Finalizing order at: {}", order.finalize);
    let finalized_order = client
        .finalize_order(&order.finalize, csr_der.der())
        .await?;
    info!("Order status after finalize: {:?}", finalized_order.status);

    let mut finalized_order = finalized_order;
    if finalized_order.status == OrderStatus::Processing {
        if let Some(url) = &order.url {
            for i in 0..settings.acme.poll_attempts {
                info!("Order processing (attempt {})...", i + 1);
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

    if let Some(cert_url) = finalized_order.certificate {
        info!("Downloading certificate from: {}", cert_url);
        let cert_pem = client.download_certificate(&cert_url).await?;
        info!("Certificate received. Saving to files...");

        let secrets_dir = settings
            .paths
            .key
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Key path has no parent directory"))?;
        ensure_secrets_dir(secrets_dir).await?;

        fs::write(&settings.paths.cert, &cert_pem)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to write cert file: {e}"))?;
        info!("Certificate saved to: {:?}", settings.paths.cert);

        let key_pem = cert_key.serialize_pem();
        fs::write(&settings.paths.key, &key_pem)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to write key file: {e}"))?;
        set_key_permissions(&settings.paths.key).await?;
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
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn test_ensure_secrets_dir_permissions() {
        let dir = tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");

        ensure_secrets_dir(&secrets_dir).await.unwrap();

        let mode = std::fs::metadata(&secrets_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, SECRETS_DIR_MODE);
    }

    #[tokio::test]
    async fn test_set_key_permissions() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        fs::write(&key_path, "key-data").await.unwrap();

        set_key_permissions(&key_path).await.unwrap();

        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_FILE_MODE);
    }
}
