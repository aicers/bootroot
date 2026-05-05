use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs;

use crate::cert_group::{self, CertGroupPolicy};

const KEY_FILE_MODE: u32 = 0o600;
const SECRETS_DIR_MODE: u32 = 0o700;

/// Ensures the secrets directory exists and has secure permissions.
///
/// This helper is for bootroot-internal config artifacts (sidecar
/// configs, `OpenBao` agent template files, etc.) that must remain
/// operator-only. Cert/key parent directories on the agent's
/// issuance/rotation path go through
/// [`crate::cert_group::ensure_key_parent_dir`] /
/// [`crate::cert_group::ensure_cert_parent_dir`] instead, so the
/// `--cert-group` policy can widen the mode/owner.
///
/// # Errors
/// Returns an error if the directory cannot be created or permissions cannot be set.
pub async fn ensure_secrets_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .await
        .with_context(|| format!("Failed to create secrets dir {}", path.display()))?;
    fs::set_permissions(path, std::fs::Permissions::from_mode(SECRETS_DIR_MODE))
        .await
        .context("Failed to set secrets dir permissions")?;
    Ok(())
}

/// Applies restrictive permissions (`0600`) to a file.
///
/// Used by callers that store operator-only secrets adjacent to the
/// service cert/key — `agent.toml`, `agent.hcl`, the `OpenBao` agent
/// `.ctmpl` files, etc. The issued cert/key files themselves go
/// through [`write_cert_and_key`] and pick up
/// [`crate::cert_group::CertGroupPolicy`] ownership instead.
///
/// # Errors
/// Returns an error if permissions cannot be set.
pub async fn set_key_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, std::fs::Permissions::from_mode(KEY_FILE_MODE))
        .await
        .context("Failed to set key file permissions")?;
    Ok(())
}

/// Writes the certificate and key to disk under the given policy.
///
/// With [`CertGroupPolicy::none`] this preserves the historical
/// host-local default: `0700` parent directories, `0600` key file,
/// `0644` cert file, owned by the agent's uid/gid.
///
/// With an active policy, the parent directories become group-
/// traversable (`0750` for the key parent; `0755` for a distinct
/// cert parent, `0750` when the cert and key share a parent), the
/// key file becomes group-readable (`0640`), and group ownership of
/// all four is set to the configured gid. Mode/ownership is re-
/// applied on every call, so a rotation immediately re-asserts the
/// policy after operator-side `chmod`/`chown` interventions.
///
/// # Errors
/// Returns an error if directories cannot be created, files cannot be written,
/// or key permissions cannot be applied.
pub async fn write_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &str,
    key_pem: &str,
    policy: CertGroupPolicy,
) -> Result<()> {
    let cert_dir = cert_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cert path has no parent directory"))?;
    let key_dir = key_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Key path has no parent directory"))?;

    cert_group::ensure_key_parent_dir(key_dir, policy).await?;
    cert_group::ensure_cert_parent_dir(cert_dir, key_dir, policy).await?;

    cert_group::write_cert_file(cert_path, cert_pem, policy).await?;
    cert_group::write_key_file(key_path, key_pem, policy).await?;

    Ok(())
}

/// Writes a CA bundle to disk, creating parent directories as needed.
///
/// # Errors
/// Returns an error if the directory cannot be created or the bundle cannot be written.
pub async fn write_ca_bundle(bundle_path: &Path, bundle_pem: &str) -> Result<()> {
    let bundle_dir = bundle_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("CA bundle path has no parent directory"))?;
    fs::create_dir_all(bundle_dir)
        .await
        .with_context(|| format!("Failed to create CA bundle dir {}", bundle_dir.display()))?;
    fs::write(bundle_path, bundle_pem)
        .await
        .context("Failed to write CA bundle file")?;
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
    async fn test_write_cert_and_key_default_policy_preserves_modes() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("certs").join("cert.pem");
        let key_path = dir.path().join("secrets").join("key.pem");

        write_cert_and_key(
            &cert_path,
            &key_path,
            "cert-data",
            "key-data",
            CertGroupPolicy::none(),
        )
        .await
        .unwrap();

        let cert_contents = fs::read_to_string(&cert_path).await.unwrap();
        let key_contents = fs::read_to_string(&key_path).await.unwrap();
        assert_eq!(cert_contents, "cert-data");
        assert_eq!(key_contents, "key-data");

        let key_dir_mode = std::fs::metadata(key_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let cert_dir_mode = std::fs::metadata(cert_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        let cert_mode = std::fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_dir_mode, SECRETS_DIR_MODE);
        assert_eq!(cert_dir_mode, SECRETS_DIR_MODE);
        assert_eq!(key_mode, KEY_FILE_MODE);
        assert_eq!(cert_mode, 0o644);
    }

    #[tokio::test]
    async fn test_write_cert_and_key_group_policy_applies_relaxed_modes() {
        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            // Test fixtures without a supplementary gid (single-gid CI
            // runners) cannot exercise the chown path. The
            // e2e-extended job provisions a dedicated supplementary
            // group and still gets coverage.
            return;
        };
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("certs").join("cert.pem");
        let key_path = dir.path().join("secrets").join("key.pem");

        write_cert_and_key(
            &cert_path,
            &key_path,
            "cert-data",
            "key-data",
            CertGroupPolicy::with_gid(gid),
        )
        .await
        .unwrap();

        let key_dir_mode = std::fs::metadata(key_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let cert_dir_mode = std::fs::metadata(cert_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        let cert_mode = std::fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_dir_mode, crate::cert_group::KEY_DIR_MODE_GROUP);
        assert_eq!(cert_dir_mode, crate::cert_group::CERT_DIR_MODE_GROUP);
        assert_eq!(key_mode, crate::cert_group::KEY_FILE_MODE_GROUP);
        assert_eq!(cert_mode, 0o644);
    }

    /// Re-running `write_cert_and_key` (the rotation case) must
    /// re-assert the policy. This guards the issue #593 root cause:
    /// rotation reverting any operator-side `chmod`/`chown`.
    #[tokio::test]
    async fn test_write_cert_and_key_reapplies_policy_on_second_call() {
        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().unwrap();
        let shared = dir.path().join("certs");
        let cert_path = shared.join("svc.pem");
        let key_path = shared.join("svc.key");

        write_cert_and_key(
            &cert_path,
            &key_path,
            "c1",
            "k1",
            CertGroupPolicy::with_gid(gid),
        )
        .await
        .unwrap();

        // Operator-side regression: hand-tighten back to the default.
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Rotation re-runs write_cert_and_key with the same policy:
        write_cert_and_key(
            &cert_path,
            &key_path,
            "c2",
            "k2",
            CertGroupPolicy::with_gid(gid),
        )
        .await
        .unwrap();

        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, crate::cert_group::KEY_FILE_MODE_GROUP);
        assert_eq!(dir_mode, crate::cert_group::KEY_DIR_MODE_GROUP);
    }
}
