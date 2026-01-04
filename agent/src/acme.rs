use anyhow::{Context, Result};
use rcgen::KeyPair;
use tracing::{info, warn};

use crate::eab::EabCredentials;

// Placeholder for future ACME integration
// use instant_acme::{Account, ExternalAccountBinding, NewAccount, Identifier};

/// Issues a certificate (CSR generation only for now).
///
/// # Errors
///
/// Returns an error if:
/// - Key generation fails.
/// - CSR serialization fails.
/// - File I/O operations fail.
/// - Domain name is invalid for CSR.
pub async fn issue_certificate(args: &crate::Args, _eab: Option<EabCredentials>) -> Result<()> {
    // 1. ACME Account Directory (Placeholder)
    let directory_url = &args.ca_url;
    info!("Target ACME Directory: {}", directory_url);

    // TODO: Implement instant-acme logic here.
    // Current compilation fails due to unknown API signature of instant-acme 0.4/0.8.
    // We need to verify the docs for Account::create and ExternalAccountBinding.
    warn!(
        "ACME communication is currently disabled due to API mismatch. Skipping to CSR generation."
    );

    // 2. Generate Key Pair & CSR (Verified logic)
    info!("Generating Private Key (P-256) and CSR...");

    // rcgen 0.13+ uses default() and field assignment
    let mut params = rcgen::CertificateParams::default();
    params.subject_alt_names = vec![rcgen::SanType::DnsName(args.domain.clone().try_into()?)];

    let key_pair = KeyPair::generate()?;
    let csr = params.serialize_request(&key_pair)?;

    info!(
        "CSR generated successfully. DER size: {} bytes",
        csr.der().len()
    );

    // 3. Save Files
    // Since we don't have a real cert from ACME, we'll skip saving the cert for now.
    // But we CAN save the private key to test file I/O.

    info!("Saving private key to {:?}", args.key_path);
    if let Some(parent) = args.key_path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context("Failed to create cert dir")?;
    }

    // key_pair.serialize_pem() returns String
    tokio::fs::write(&args.key_path, key_pair.serialize_pem())
        .await
        .context("Failed to save private key")?;

    info!("Private key saved.");
    warn!("Certificate was NOT issued (ACME flow skipped).");

    Ok(())
}
