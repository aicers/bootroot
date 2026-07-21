use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::sync::watch;
use tracing::warn;

use crate::fs_util;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EabCredentials {
    pub kid: String,
    // `key` is step-ca's native EAB field name; accept it for interop with
    // step-ca-produced files, not as an older bootroot spelling of `hmac`.
    #[serde(alias = "key")]
    pub hmac: String,
}

/// Live, shared view of the daemon's `default_eab`.
///
/// `default_eab` is read at issuance time by both the periodic check loop and
/// the fast-poll force-reissue path. Backing it with a `watch` channel lets
/// the remote fast-poll loop update the value in place when it observes a
/// newer `eab` KV version, so a running renewal reflects the change without a
/// restart. Cloning shares the same underlying channel.
#[derive(Clone)]
pub struct SharedEab {
    rx: watch::Receiver<Option<EabCredentials>>,
}

impl SharedEab {
    /// Wraps a `watch` receiver as a shared, live-readable EAB view.
    #[must_use]
    pub fn from_receiver(rx: watch::Receiver<Option<EabCredentials>>) -> Self {
        Self { rx }
    }

    /// Returns the current `default_eab` value, cloned for the caller.
    #[must_use]
    pub fn current(&self) -> Option<EabCredentials> {
        self.rx.borrow().clone()
    }
}

/// Writes EAB credentials to `path` as pretty `{ "kid", "hmac" }` JSON at
/// key-file permissions (`0o600`), creating the parent secrets directory when
/// needed. Returns `true` when the on-disk bytes changed and `false` when the
/// file already held identical content.
///
/// Shared by `bootroot-remote bootstrap` and the remote fast-poll loop so the
/// producer and the `--eab-file` consumer cannot drift on the on-disk shape.
///
/// # Errors
///
/// Returns an error when the parent directory, the existing file, or the write
/// cannot be created, read, or written.
pub async fn write_eab_file(path: &Path, kid: &str, hmac: &str) -> anyhow::Result<bool> {
    write_key_file(path, &serialize_eab_payload(kid, hmac)?).await
}

/// Serializes EAB credentials into the exact newline-terminated pretty
/// `{ "kid", "hmac" }` JSON that [`write_eab_file`] persists.
///
/// Exposed so a local-file `service add` that relocates `eab.json`
/// outside the secrets tree can write byte-identical content through an
/// ownership-preserving, symlink-safe writer without re-implementing —
/// and drifting from — the on-disk shape.
///
/// # Errors
/// Returns an error if the credentials cannot be serialized to JSON.
pub fn serialize_eab_payload(kid: &str, hmac: &str) -> anyhow::Result<String> {
    let payload = serde_json::to_string_pretty(&serde_json::json!({
        "kid": kid,
        "hmac": hmac,
    }))
    .context("Failed to serialize EAB credentials")?;
    Ok(if payload.ends_with('\n') {
        payload
    } else {
        format!("{payload}\n")
    })
}

/// Writes `contents` (newline-terminated) to a `0o600` key file idempotently,
/// mirroring the bootstrap `write_secret_file` behaviour so a first-sighting
/// re-write from the fast-poll loop is byte-identical to the bootstrap writer.
async fn write_key_file(path: &Path, contents: &str) -> anyhow::Result<bool> {
    if let Some(parent) = path.parent() {
        fs_util::ensure_secrets_dir(parent).await?;
    }
    let next = if contents.ends_with('\n') {
        contents.to_string()
    } else {
        format!("{contents}\n")
    };
    let current = match fs::read_to_string(path).await {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("Failed to read existing EAB file: {}", path.display()));
        }
    };
    if current == next {
        fs_util::set_key_permissions(path).await?;
        return Ok(false);
    }
    fs::write(path, next)
        .await
        .with_context(|| format!("Failed to write EAB file: {}", path.display()))?;
    fs_util::set_key_permissions(path).await?;
    Ok(true)
}

/// Removes a stale `eab.json` written by a previous bootstrap or fast-poll
/// apply so that `bootroot-agent --eab-file` cannot pick up credentials the
/// operator has since cleared from `OpenBao`. Returns `true` when a file
/// existed and was removed and `false` when it was already absent.
///
/// # Errors
///
/// Returns an error when the file exists but cannot be removed.
pub async fn remove_eab_file(path: &Path) -> anyhow::Result<bool> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => {
            Err(err).with_context(|| format!("Failed to remove stale EAB file: {}", path.display()))
        }
    }
}

/// Loads EAB credentials from CLI arguments or a JSON file.
///
/// A configured `--eab-file` that does not exist resolves to `None` (open
/// enrollment): an absent file is the durable cleared representation written by
/// `bootroot-remote bootstrap` and the fast-poll `eab-clear` apply.
///
/// # Errors
///
/// Returns an error if:
/// - The file path is provided and exists but cannot be read (e.g.
///   permissions).
/// - The file content is not valid JSON.
pub async fn load_credentials(
    cli_kid: Option<String>,
    cli_hmac: Option<String>,
    file_path: Option<PathBuf>,
) -> anyhow::Result<Option<EabCredentials>> {
    // 1. CLI args take precedence
    if let (Some(kid), Some(hmac)) = (cli_kid, cli_hmac) {
        return Ok(Some(EabCredentials { kid, hmac }));
    }

    // 2. Try loading from file
    if let Some(path) = file_path {
        // An absent `--eab-file` is the durable "no EAB" representation on
        // remote hosts: `bootroot-remote bootstrap` removes `eab.json` when KV
        // holds no EAB, and the fast-poll loop removes it on an `eab-clear`. So
        // a configured-but-missing file means open enrollment, not a hard
        // error -- otherwise a restart or SIGHUP after a clear would fail to
        // load even though the running process was already using no EAB, which
        // would break the "durable across restart" contract. Other read
        // failures (permissions, etc.) still surface as errors.
        let content = match fs::read_to_string(&path).await {
            Ok(content) => content,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).context("Failed to read EAB file"),
        };

        if content.trim().is_empty() {
            return Ok(None);
        }

        let creds: EabCredentials =
            serde_json::from_str(&content).context("Failed to parse EAB JSON")?;

        if creds.kid.is_empty() || creds.hmac.is_empty() {
            warn!("EAB file has empty kid or hmac field; treating as no credentials");
            return Ok(None);
        }

        return Ok(Some(creds));
    }

    Ok(None)
}
#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;
    #[tokio::test]
    async fn test_load_credentials_cli_precedence() {
        let cli_kid = Some("cli-kid".to_string());
        let cli_hmac = Some("cli-hmac".to_string());
        // Create a dummy file that has DIFFERENT credentials
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"kid": "file-kid", "key": "file-hmac"}}"#).unwrap();
        let file_path = Some(file.path().to_path_buf());
        // Action
        let result = load_credentials(cli_kid, cli_hmac, file_path).await;
        // Assert
        let creds = result.unwrap().unwrap();
        assert_eq!(creds.kid, "cli-kid");
        assert_eq!(creds.hmac, "cli-hmac");
    }
    #[tokio::test]
    async fn test_load_credentials_from_file_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"kid": "test-kid", "key": "test-hmac"}}"#).unwrap();
        let path = file.path().to_path_buf();
        let result = load_credentials(None, None, Some(path)).await;
        let creds = result.unwrap().unwrap();
        assert_eq!(creds.kid, "test-kid");
        assert_eq!(creds.hmac, "test-hmac");
    }
    #[tokio::test]
    async fn test_load_credentials_file_malformed() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "not json content").unwrap();
        let path = file.path().to_path_buf();
        let result = load_credentials(None, None, Some(path)).await;
        // Should be an error
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse EAB JSON")
        );
    }
    #[tokio::test]
    async fn test_load_credentials_file_not_found() {
        // A configured-but-missing `--eab-file` is the durable cleared
        // representation, so the loader reports no credentials (open
        // enrollment) rather than erroring.
        let path = PathBuf::from("/non/existent/path/for/bootroot/test.json");
        let result = load_credentials(None, None, Some(path)).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn load_credentials_after_clear_returns_none() {
        // Regression for the restart/SIGHUP path after `rotate eab-clear`:
        // once the fast-poll loop (or bootstrap) removes `eab.json`, the same
        // startup load path must resolve to `None` so a restart is consistent
        // with the running process's cleared `default_eab`.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets").join("eab.json");

        write_eab_file(&path, "kid-1", "hmac-1").await.unwrap();
        let loaded = load_credentials(None, None, Some(path.clone()))
            .await
            .unwrap()
            .expect("credentials present before clear");
        assert_eq!(loaded.kid, "kid-1");

        assert!(remove_eab_file(&path).await.unwrap());
        let after_clear = load_credentials(None, None, Some(path)).await.unwrap();
        assert!(after_clear.is_none());
    }
    #[tokio::test]
    async fn test_load_credentials_none() {
        let result = load_credentials(None, None, None).await;
        let creds = result.unwrap();
        assert!(creds.is_none());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_eab_file_roundtrips_through_load_credentials() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("secrets").join("eab.json");

        let changed = write_eab_file(&path, "kid-1", "hmac-1").await.unwrap();
        assert!(changed);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let creds = load_credentials(None, None, Some(path.clone()))
            .await
            .unwrap()
            .expect("credentials present");
        assert_eq!(creds.kid, "kid-1");
        assert_eq!(creds.hmac, "hmac-1");

        // A re-write of the identical content reports no change.
        let changed_again = write_eab_file(&path, "kid-1", "hmac-1").await.unwrap();
        assert!(!changed_again);
    }

    #[tokio::test]
    async fn remove_eab_file_reports_removed_then_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eab.json");
        write_eab_file(&path, "kid-1", "hmac-1").await.unwrap();

        assert!(remove_eab_file(&path).await.unwrap());
        assert!(!remove_eab_file(&path).await.unwrap());
        assert!(!path.exists());
    }

    #[test]
    fn shared_eab_reflects_sender_updates() {
        let (tx, rx) = watch::channel(None);
        let shared = SharedEab::from_receiver(rx);
        assert!(shared.current().is_none());

        tx.send_replace(Some(EabCredentials {
            kid: "kid-1".to_string(),
            hmac: "hmac-1".to_string(),
        }));
        let current = shared.current().expect("value present after update");
        assert_eq!(current.kid, "kid-1");

        tx.send_replace(None);
        assert!(shared.current().is_none());
    }
}
