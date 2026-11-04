use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use aws_lc_rs::digest;
use bootroot::fs_util::SecretsTree;
use x509_parser::pem::parse_x509_pem;

use super::super::constants::{CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME};
use crate::commands::constants::CA_TRUST_KEY;
use crate::i18n::Messages;

/// Returns the SHA-256 fingerprints of the root and intermediate CA
/// certificates under `tree`'s anchor, root first.
///
/// A rooted handle reads both through its descriptors, refusing a link
/// at `certs/` or at either file, on a blocking thread; a path-based one
/// reads them by path, as it always did.
///
/// # Errors
///
/// Returns an error when either certificate is missing, unreadable,
/// refused, or not a PEM certificate.
pub(crate) async fn compute_ca_fingerprints(
    tree: &Arc<SecretsTree>,
    messages: &Messages,
) -> Result<Vec<String>> {
    let certs_dir = tree.anchor().join(CA_CERTS_DIR);
    let root_path = certs_dir.join(CA_ROOT_CERT_FILENAME);
    let intermediate_path = certs_dir.join(CA_INTERMEDIATE_CERT_FILENAME);
    if tree.is_rooted() {
        let messages = messages.clone();
        return tree
            .run(move |tree| {
                Ok(vec![
                    read_ca_cert_fingerprint_in(tree, &root_path, &messages)?,
                    read_ca_cert_fingerprint_in(tree, &intermediate_path, &messages)?,
                ])
            })
            .await;
    }
    let root = read_ca_cert_fingerprint(&root_path, messages).await?;
    let intermediate = read_ca_cert_fingerprint(&intermediate_path, messages).await?;
    Ok(vec![root, intermediate])
}

/// Returns the root and intermediate CA certificates under `tree`'s
/// anchor, concatenated in that order.
///
/// A rooted handle reads both through its descriptors, refusing a link
/// at `certs/` or at either file, on a blocking thread; a path-based one
/// reads them by path, as it always did. The output is the two files'
/// bytes either way.
///
/// # Errors
///
/// Returns an error when either file is missing, unreadable, refused or
/// not UTF-8.
pub(crate) async fn compute_ca_bundle_pem(
    tree: &Arc<SecretsTree>,
    messages: &Messages,
) -> Result<String> {
    let certs_dir = tree.anchor().join(CA_CERTS_DIR);
    let root_path = certs_dir.join(CA_ROOT_CERT_FILENAME);
    let intermediate_path = certs_dir.join(CA_INTERMEDIATE_CERT_FILENAME);
    if tree.is_rooted() {
        let messages = messages.clone();
        return tree
            .run(move |tree| {
                let root = read_text_in(tree, &root_path, &messages)?;
                let intermediate = read_text_in(tree, &intermediate_path, &messages)?;
                Ok(format!("{root}{intermediate}"))
            })
            .await;
    }
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
    fingerprint_ca_cert(&contents, path, messages)
}

/// [`read_ca_cert_fingerprint`] through a rooted `tree`: the certificate
/// at `path`, below the anchor, is read through the handle's descriptors
/// and a link at any level is refused. Blocking.
///
/// # Errors
///
/// Returns an error when the certificate is missing, refused,
/// unreadable, or not a PEM certificate.
pub(crate) fn read_ca_cert_fingerprint_in(
    tree: &SecretsTree,
    path: &Path,
    messages: &Messages,
) -> Result<String> {
    let contents = match tree.read(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            anyhow::bail!(messages.error_ca_cert_missing(&path.display().to_string()));
        }
        Err(err) => {
            return Err(anyhow::Error::new(err)
                .context(messages.error_read_file_failed(&path.display().to_string())));
        }
    };
    fingerprint_ca_cert(&contents, path, messages)
}

/// Reads the text file at `path` through a rooted `tree`. Blocking.
fn read_text_in(tree: &SecretsTree, path: &Path, messages: &Messages) -> Result<String> {
    let bytes = tree
        .read(path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    String::from_utf8(bytes)
        .map_err(|err| anyhow::anyhow!(err))
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))
}

/// The SHA-256 fingerprint of the PEM certificate in `contents`, read
/// from `path`.
pub(crate) fn fingerprint_ca_cert(
    contents: &[u8],
    path: &Path,
    messages: &Messages,
) -> Result<String> {
    let (_, pem) = parse_x509_pem(contents).map_err(|_| {
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
            .block_on(compute_ca_fingerprints(
                &Arc::new(SecretsTree::open(&secrets_dir).expect("open")),
                &messages,
            ))
            .expect("compute fingerprints");
        assert_eq!(fingerprints.len(), 2);
        for fingerprint in fingerprints {
            assert_eq!(fingerprint.len(), 64);
            assert!(fingerprint.chars().all(|ch| ch.is_ascii_hexdigit()));
        }
    }

    /// Writes a root and an intermediate under `secrets/certs`.
    fn seed_certs(root: &crate::test_support::SwapRoot) {
        root.write(
            &format!("{CA_CERTS_DIR}/{CA_ROOT_CERT_FILENAME}"),
            &test_cert_pem("root.example"),
        );
        root.write(
            &format!("{CA_CERTS_DIR}/{CA_INTERMEDIATE_CERT_FILENAME}"),
            &test_cert_pem("intermediate.example"),
        );
    }

    #[tokio::test]
    async fn rooted_ca_reads_match_the_path_based_reads() {
        let root = crate::test_support::SwapRoot::new();
        seed_certs(&root);
        let messages = test_messages();
        let rooted = Arc::new(root.rooted());
        let path_based = Arc::new(SecretsTree::open(&root.secrets).expect("open"));
        assert_eq!(
            compute_ca_bundle_pem(&rooted, &messages)
                .await
                .expect("rooted"),
            compute_ca_bundle_pem(&path_based, &messages)
                .await
                .expect("path-based")
        );
        assert_eq!(
            compute_ca_fingerprints(&rooted, &messages)
                .await
                .expect("rooted"),
            compute_ca_fingerprints(&path_based, &messages)
                .await
                .expect("path-based")
        );
    }

    #[tokio::test]
    async fn rooted_ca_reads_refuse_a_linked_root_and_a_swapped_certs_dir() {
        let messages = test_messages();
        let root = crate::test_support::SwapRoot::new();
        seed_certs(&root);
        fs::write(
            root.outside.join("secret"),
            test_cert_pem("outside.example"),
        )
        .expect("seed");
        let tree = Arc::new(root.rooted());
        let leaf = root.swap(
            &format!("{CA_CERTS_DIR}/{CA_ROOT_CERT_FILENAME}"),
            &root.outside.join("secret"),
        );
        let err = compute_ca_bundle_pem(&tree, &messages)
            .await
            .expect_err("linked root");
        crate::test_support::assert_error_names(&err, &leaf);
        assert!(!format!("{err:#}").contains("outside.example"));
        let err = compute_ca_fingerprints(&tree, &messages)
            .await
            .expect_err("linked root");
        crate::test_support::assert_error_names(&err, &leaf);

        let root = crate::test_support::SwapRoot::new();
        seed_certs(&root);
        fs::write(
            root.outside.join(CA_ROOT_CERT_FILENAME),
            test_cert_pem("outside"),
        )
        .unwrap();
        fs::write(
            root.outside.join(CA_INTERMEDIATE_CERT_FILENAME),
            test_cert_pem("outside"),
        )
        .unwrap();
        let tree = Arc::new(root.rooted());
        let before = root.outside_snapshot();
        let link = root.swap(CA_CERTS_DIR, &root.outside);
        let err = compute_ca_bundle_pem(&tree, &messages)
            .await
            .expect_err("swapped certs");
        crate::test_support::assert_error_names(&err, &link);
        let err = compute_ca_fingerprints(&tree, &messages)
            .await
            .expect_err("swapped certs");
        crate::test_support::assert_error_names(&err, &link);
        assert_eq!(root.outside_snapshot(), before);

        // Path-based, the same link is followed, as it always was.
        let path_based = Arc::new(SecretsTree::open(&root.secrets).expect("open"));
        assert!(compute_ca_bundle_pem(&path_based, &messages).await.is_ok());
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
