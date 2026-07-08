use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs;

use crate::cert_group::{self, CA_BUNDLE_FILE_MODE, CertGroupPolicy};

pub const KEY_FILE_MODE: u32 = 0o600;
const SECRETS_DIR_MODE: u32 = 0o700;

/// Writes `contents` to `path` atomically by staging it in a sibling
/// temp file and `rename(2)`ing into place.
///
/// `bootroot-agent`'s daemon loop re-reads `agent.toml` on every ACME
/// retry. A non-atomic `fs::write` opens the destination with
/// `O_TRUNC` and then issues `write_all`, so a concurrent reader can
/// observe a zero-byte or partially populated file in the gap. That
/// surfaced in the field (#613) as renewal retries failing with
/// "profile not found in reloaded config" and exhausting the retry
/// budget against a transient race. Routing the write through a
/// same-directory temp file + atomic rename closes the window: a
/// reader sees either the previous file or the fully written new one.
///
/// The supplied `mode` is applied to the staged file before the
/// rename so the on-disk mode never changes after the file appears at
/// `path`. When `path` already exists, the existing uid/gid is also
/// re-applied to the staged file before the rename so the caller does
/// not silently re-own the destination to the writer's effective
/// uid/gid (e.g. a `service add` run by root replacing an
/// agent-readable file with a root-owned `0600` file the long-running
/// agent process can no longer read).
///
/// # Errors
/// Returns an error if the temp file cannot be created, written,
/// permissioned, chowned (when ownership preservation is needed), or
/// renamed.
pub async fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| std::path::PathBuf::from("."), Path::to_path_buf);
    let dest = path.to_path_buf();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || -> Result<()> {
        // Capture the existing destination's uid/gid (if any) so the
        // rename does not strip operator-meaningful ownership. Missing
        // file -> None; do not chown the staged file in that case so a
        // fresh create keeps process default ownership.
        let existing_owner = std::fs::metadata(&dest).ok().map(|m| (m.uid(), m.gid()));

        let mut tmp = tempfile::NamedTempFile::new_in(&parent)
            .with_context(|| format!("Failed to create temp file in {}", parent.display()))?;
        tmp.as_file_mut()
            .write_all(&payload)
            .with_context(|| format!("Failed to write temp file for {}", dest.display()))?;
        tmp.as_file_mut()
            .sync_all()
            .with_context(|| format!("Failed to fsync temp file for {}", dest.display()))?;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode)).with_context(
            || {
                format!(
                    "Failed to set mode {mode:o} on temp file for {}",
                    dest.display()
                )
            },
        )?;
        if let Some((dest_uid, dest_gid)) = existing_owner {
            let tmp_meta = std::fs::metadata(tmp.path())
                .with_context(|| format!("Failed to stat temp file for {}", dest.display()))?;
            if tmp_meta.uid() != dest_uid || tmp_meta.gid() != dest_gid {
                std::os::unix::fs::chown(tmp.path(), Some(dest_uid), Some(dest_gid)).with_context(
                    || {
                        format!(
                            "Failed to preserve existing uid={dest_uid} gid={dest_gid} on {}",
                            dest.display()
                        )
                    },
                )?;
            }
        }
        tmp.persist(&dest).map_err(|e| {
            anyhow::anyhow!(
                "Failed to rename temp file to {}: {}",
                dest.display(),
                e.error
            )
        })?;
        Ok(())
    })
    .await
    .context("Atomic write task panicked")?
}

/// Ensures the secrets directory exists and has secure permissions.
///
/// This helper is for bootroot-internal config artifacts (infra
/// `OpenBao` Agent configs, template files, etc.) that must remain
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
/// Always sets the mode to [`CA_BUNDLE_FILE_MODE`] (`0o644`),
/// regardless of `policy`. CA bundles are public trust material, and
/// re-asserting the mode on every write means a rotation overrides
/// any stricter mode left behind by an earlier writer (notably
/// `bootroot-remote`'s bootstrap path, which creates the file via
/// `write_secret_file` at `0o600`). When `policy` is active, also
/// `chown`s the file to the policy's gid so cert-group members can
/// read the bundle alongside the cert and key.
///
/// # Errors
/// Returns an error if the directory cannot be created, the bundle
/// cannot be written, or the mode/owner cannot be applied.
pub async fn write_ca_bundle(
    bundle_path: &Path,
    bundle_pem: &str,
    policy: CertGroupPolicy,
) -> Result<()> {
    let bundle_dir = bundle_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("CA bundle path has no parent directory"))?;
    fs::create_dir_all(bundle_dir)
        .await
        .with_context(|| format!("Failed to create CA bundle dir {}", bundle_dir.display()))?;
    fs::write(bundle_path, bundle_pem)
        .await
        .context("Failed to write CA bundle file")?;
    fs::set_permissions(
        bundle_path,
        std::fs::Permissions::from_mode(CA_BUNDLE_FILE_MODE),
    )
    .await
    .with_context(|| {
        format!(
            "Failed to set mode {CA_BUNDLE_FILE_MODE:o} on CA bundle {}",
            bundle_path.display()
        )
    })?;
    if let Some(gid) = policy.gid {
        let owned = bundle_path.to_path_buf();
        tokio::task::spawn_blocking(move || -> Result<()> {
            std::os::unix::fs::chown(&owned, None, Some(gid)).with_context(|| {
                format!("Failed to chown CA bundle {} to gid {gid}", owned.display())
            })
        })
        .await
        .context("CA bundle chown task panicked")??;
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

    /// CA bundles are public trust material, so the mode must be
    /// `0o644` whether or not a `--cert-group` policy is in effect.
    #[tokio::test]
    async fn write_ca_bundle_no_policy_sets_world_readable_mode() {
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");

        write_ca_bundle(&bundle_path, "BUNDLE", CertGroupPolicy::none())
            .await
            .unwrap();

        let mode = std::fs::metadata(&bundle_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, CA_BUNDLE_FILE_MODE);
        let contents = fs::read_to_string(&bundle_path).await.unwrap();
        assert_eq!(contents, "BUNDLE");
    }

    /// Rotation must re-assert the mode. The issue #608 root cause:
    /// `bootroot-remote` creates the bundle at `0o600`, then the
    /// agent's rotation only rewrote the bytes without restoring the
    /// mode, leaving the container EACCES on the bundle. Seeding the
    /// file at `0o600` first locks in that the rotation widens it.
    #[tokio::test]
    async fn write_ca_bundle_re_asserts_mode_on_rotation_over_0600_seed() {
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        // Seed as a 0o600 file (the bootstrap-time `write_secret_file`
        // state described in the issue).
        fs::write(&bundle_path, "stale").await.unwrap();
        fs::set_permissions(&bundle_path, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();

        write_ca_bundle(&bundle_path, "FRESH", CertGroupPolicy::none())
            .await
            .unwrap();

        let mode = std::fs::metadata(&bundle_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, CA_BUNDLE_FILE_MODE);
        let contents = fs::read_to_string(&bundle_path).await.unwrap();
        assert_eq!(contents, "FRESH");
    }

    /// `atomic_write` must leave the destination at the supplied mode
    /// and the requested contents, both for the create case and for
    /// the overwrite case (rotation).
    #[tokio::test]
    async fn atomic_write_creates_and_overwrites_with_mode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("agent.toml");

        super::atomic_write(&path, b"first", KEY_FILE_MODE)
            .await
            .unwrap();
        let contents = fs::read_to_string(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(contents, "first");
        assert_eq!(mode, KEY_FILE_MODE);

        super::atomic_write(&path, b"second", KEY_FILE_MODE)
            .await
            .unwrap();
        let contents = fs::read_to_string(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(contents, "second");
        assert_eq!(mode, KEY_FILE_MODE);
    }

    /// Overwriting an existing file via `atomic_write` must preserve
    /// the destination's gid. The rename otherwise replaces the inode
    /// with one owned by the writer's effective uid/gid — locking out
    /// readers in deployments that rely on group ownership (e.g.
    /// `bootroot-agent` reading an `agent.toml` originally written
    /// under a cert-group gid, then re-run by root). Requires a
    /// supplementary gid (see `one_supplementary_test_gid`).
    #[tokio::test]
    async fn atomic_write_preserves_existing_gid_on_overwrite() {
        use std::os::unix::fs::MetadataExt;

        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("agent.toml");

        super::atomic_write(&path, b"first", KEY_FILE_MODE)
            .await
            .unwrap();
        std::os::unix::fs::chown(&path, None, Some(gid))
            .expect("test process must be able to chgrp to a supplementary gid");
        let pre_meta = std::fs::metadata(&path).unwrap();
        assert_eq!(pre_meta.gid(), gid, "seed gid must take effect");
        let pre_uid = pre_meta.uid();

        super::atomic_write(&path, b"second", KEY_FILE_MODE)
            .await
            .unwrap();

        let post_meta = std::fs::metadata(&path).unwrap();
        assert_eq!(
            post_meta.gid(),
            gid,
            "atomic_write overwrite must preserve existing gid"
        );
        assert_eq!(
            post_meta.uid(),
            pre_uid,
            "atomic_write overwrite must preserve existing uid"
        );
        assert_eq!(
            post_meta.permissions().mode() & 0o777,
            KEY_FILE_MODE,
            "atomic_write overwrite must still apply the requested mode"
        );
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "second");
    }

    /// `atomic_write` must not leave the destination at an
    /// intermediate state if the rename happens to fail — but in the
    /// common success case, the temp sibling must be cleaned up
    /// (i.e. the destination's parent directory contains exactly the
    /// one file after the call).
    #[tokio::test]
    async fn atomic_write_cleans_up_temp_sibling_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("agent.toml");

        super::atomic_write(&path, b"payload", KEY_FILE_MODE)
            .await
            .unwrap();

        let mut entries = Vec::new();
        let mut rd = fs::read_dir(dir.path()).await.unwrap();
        while let Some(entry) = rd.next_entry().await.unwrap() {
            entries.push(entry.file_name());
        }
        assert_eq!(
            entries.len(),
            1,
            "expected only the final file, got {entries:?}"
        );
        assert_eq!(entries[0], "agent.toml");
    }

    /// Under an active `--cert-group` policy, the bundle file must be
    /// chgrped to the policy's gid and remain at `0o644` (cert-group
    /// members get read access via group membership, everyone else
    /// retains read access because the bundle is public material).
    #[tokio::test]
    async fn write_ca_bundle_with_policy_chowns_to_gid_and_keeps_0644() {
        use std::os::unix::fs::MetadataExt;

        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");

        write_ca_bundle(&bundle_path, "BUNDLE", CertGroupPolicy::with_gid(gid))
            .await
            .unwrap();

        let meta = std::fs::metadata(&bundle_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, CA_BUNDLE_FILE_MODE);
        assert_eq!(meta.gid(), gid, "CA bundle gid must match policy");
    }
}
