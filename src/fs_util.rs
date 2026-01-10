use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Result;
use tokio::fs;

const KEY_FILE_MODE: u32 = 0o600;
const SECRETS_DIR_MODE: u32 = 0o700;

/// Ensures the secrets directory exists and has secure permissions.
///
/// # Errors
/// Returns an error if the directory cannot be created or permissions cannot be set.
pub async fn ensure_secrets_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create secrets dir {}: {e}", path.display()))?;
    fs::set_permissions(path, std::fs::Permissions::from_mode(SECRETS_DIR_MODE))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set secrets dir permissions: {e}"))?;
    Ok(())
}

/// Applies restrictive permissions to a private key file.
///
/// # Errors
/// Returns an error if permissions cannot be set.
pub async fn set_key_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, std::fs::Permissions::from_mode(KEY_FILE_MODE))
        .await
        .map_err(|e| anyhow::anyhow!("Failed to set key file permissions: {e}"))?;
    Ok(())
}

/// Writes the certificate and key to disk with secure permissions.
///
/// # Errors
/// Returns an error if directories cannot be created, files cannot be written,
/// or key permissions cannot be applied.
pub async fn write_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &str,
    key_pem: &str,
) -> Result<()> {
    let cert_dir = cert_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cert path has no parent directory"))?;
    fs::create_dir_all(cert_dir)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create cert dir {}: {e}", cert_dir.display()))?;

    let secrets_dir = key_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Key path has no parent directory"))?;
    ensure_secrets_dir(secrets_dir).await?;

    fs::write(cert_path, cert_pem)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to write cert file: {e}"))?;

    fs::write(key_path, key_pem)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to write key file: {e}"))?;
    set_key_permissions(key_path).await?;

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

    #[tokio::test]
    async fn test_write_cert_and_key_creates_files_with_permissions() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("certs").join("cert.pem");
        let key_path = dir.path().join("secrets").join("key.pem");

        write_cert_and_key(&cert_path, &key_path, "cert-data", "key-data")
            .await
            .unwrap();

        let cert_contents = fs::read_to_string(&cert_path).await.unwrap();
        let key_contents = fs::read_to_string(&key_path).await.unwrap();
        assert_eq!(cert_contents, "cert-data");
        assert_eq!(key_contents, "key-data");

        let secrets_mode = std::fs::metadata(key_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(secrets_mode, SECRETS_DIR_MODE);
        assert_eq!(key_mode, KEY_FILE_MODE);
    }
}
