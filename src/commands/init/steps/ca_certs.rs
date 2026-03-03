use std::path::Path;

use anyhow::{Context, Result};
use ring::digest;
use x509_parser::pem::parse_x509_pem;

use super::super::constants::{CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME};
use crate::commands::constants::CA_TRUST_KEY;
use crate::i18n::Messages;

pub(crate) async fn compute_ca_fingerprints(
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<Vec<String>> {
    let certs_dir = secrets_dir.join(CA_CERTS_DIR);
    let root_path = certs_dir.join(CA_ROOT_CERT_FILENAME);
    let intermediate_path = certs_dir.join(CA_INTERMEDIATE_CERT_FILENAME);
    let root = read_ca_cert_fingerprint(&root_path, messages).await?;
    let intermediate = read_ca_cert_fingerprint(&intermediate_path, messages).await?;
    Ok(vec![root, intermediate])
}

pub(crate) async fn compute_ca_bundle_pem(
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<String> {
    let certs_dir = secrets_dir.join(CA_CERTS_DIR);
    let root_path = certs_dir.join(CA_ROOT_CERT_FILENAME);
    let intermediate_path = certs_dir.join(CA_INTERMEDIATE_CERT_FILENAME);
    let root = tokio::fs::read_to_string(&root_path)
        .await
        .with_context(|| messages.error_read_file_failed(&root_path.display().to_string()))?;
    let intermediate = tokio::fs::read_to_string(&intermediate_path)
        .await
        .with_context(|| {
            messages.error_read_file_failed(&intermediate_path.display().to_string())
        })?;
    Ok(format!("{root}{intermediate}"))
}

pub(super) fn trust_payload_changed(
    current: Option<&serde_json::Value>,
    fingerprints: &[String],
    ca_bundle_pem: &str,
) -> bool {
    let Some(current) = current else {
        return true;
    };
    let current_fingerprints = current
        .get(CA_TRUST_KEY)
        .and_then(serde_json::Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        });
    let current_bundle = current
        .get("ca_bundle_pem")
        .and_then(serde_json::Value::as_str);
    current_fingerprints.as_deref() != Some(fingerprints) || current_bundle != Some(ca_bundle_pem)
}

pub(crate) async fn read_ca_cert_fingerprint(path: &Path, messages: &Messages) -> Result<String> {
    if !path.exists() {
        anyhow::bail!(messages.error_ca_cert_missing(&path.display().to_string()));
    }
    let contents = tokio::fs::read(path)
        .await
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let (_, pem) = parse_x509_pem(&contents).map_err(|_| {
        anyhow::anyhow!(messages.error_ca_cert_parse_failed(&path.display().to_string()))
    })?;
    if pem.label != "CERTIFICATE" {
        anyhow::bail!(messages.error_ca_cert_parse_failed(&path.display().to_string()));
    }
    Ok(sha256_hex(&pem.contents))
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = digest::digest(&digest::SHA256, bytes);
    let mut output = String::with_capacity(64);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::super::super::constants::{
        CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME,
    };
    use super::super::test_support::{test_cert_pem, test_messages};
    use super::*;
    use crate::commands::constants::CA_TRUST_KEY;

    #[test]
    fn test_compute_ca_fingerprints_reads_cert_files() {
        let dir = tempdir().expect("temp dir");
        let secrets_dir = dir.path().join("secrets");
        let certs_dir = secrets_dir.join(CA_CERTS_DIR);
        fs::create_dir_all(&certs_dir).expect("create certs");

        let root = test_cert_pem("root.example");
        let intermediate = test_cert_pem("intermediate.example");
        fs::write(certs_dir.join(CA_ROOT_CERT_FILENAME), root).expect("write root cert");
        fs::write(certs_dir.join(CA_INTERMEDIATE_CERT_FILENAME), intermediate)
            .expect("write intermediate cert");

        let messages = test_messages();
        let fingerprints = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(compute_ca_fingerprints(&secrets_dir, &messages))
            .expect("compute fingerprints");
        assert_eq!(fingerprints.len(), 2);
        for fingerprint in fingerprints {
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.chars().all(|ch| ch.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn test_trust_payload_changed_detects_changes() {
        let fingerprints = vec!["a".repeat(64), "b".repeat(64)];
        let bundle = "bundle-pem";
        assert!(trust_payload_changed(None, &fingerprints, bundle));

        let current = serde_json::json!({
            CA_TRUST_KEY: fingerprints,
            "ca_bundle_pem": bundle,
        });
        assert!(!trust_payload_changed(
            Some(&current),
            &["a".repeat(64), "b".repeat(64)],
            "bundle-pem"
        ));
        assert!(trust_payload_changed(
            Some(&current),
            &["c".repeat(64), "d".repeat(64)],
            "bundle-pem"
        ));
        assert!(trust_payload_changed(
            Some(&current),
            &["a".repeat(64), "b".repeat(64)],
            "bundle-pem-updated"
        ));
    }
}
