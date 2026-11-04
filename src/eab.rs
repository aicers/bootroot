use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tokio::fs;
use tokio::sync::watch;
use tracing::warn;

use crate::fs_util::{self, EntryKind, KEY_FILE_MODE, RootedOwner, SecretsTree, StagedMode};
use crate::secret::HmacSecret;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EabCredentials {
    pub kid: String,
    // `key` is step-ca's native EAB field name; accept it for interop with
    // step-ca-produced files, not as an older bootroot spelling of `hmac`.
    #[serde(alias = "key")]
    pub hmac: HmacSecret,
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
/// needed. Returns `true` when it publishes a replacement at `path` and
/// `false` when an existing regular file already holds identical content.
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

/// [`write_eab_file`] for a `path` below the secrets directory `tree` is
/// opened on.
///
/// On a path-based handle this is exactly [`write_eab_file`]. On a
/// rooted one every step goes through the handle and follows no name:
/// the parent is created writer-owned at `0700`, the leaf is read
/// without following it, a regular file already holding the payload has
/// its mode repaired through its own descriptor, a symbolic link is
/// replaced, and anything else is published as [`write_eab_file`]
/// publishes it.
///
/// # Errors
///
/// Returns an error under the same conditions as [`write_eab_file`], and
/// on a rooted handle also when a directory level is a symbolic link.
pub async fn write_eab_file_in(
    tree: &Arc<SecretsTree>,
    path: &Path,
    kid: &str,
    hmac: &str,
) -> anyhow::Result<bool> {
    let payload = serialize_eab_payload(kid, hmac)?;
    if !tree.is_rooted() {
        return write_key_file(path, &payload).await;
    }
    let path = path.to_path_buf();
    tree.run(move |tree| write_key_file_rooted(tree, &path, &payload))
        .await
}

/// [`write_key_file`] through a rooted `tree`. Blocking.
fn write_key_file_rooted(tree: &SecretsTree, path: &Path, contents: &str) -> anyhow::Result<bool> {
    if let Some(parent) = path.parent() {
        tree.ensure_dir_as_writer(parent)?;
    }
    let next = if contents.ends_with('\n') {
        contents.to_string()
    } else {
        format!("{contents}\n")
    };
    // A link is republished, which replaces it, whatever its target
    // holds; an absent leaf is written.
    if tree.entry_kind(path)? == Some(EntryKind::File) {
        let current = tree
            .read(path)
            .with_context(|| format!("Failed to read existing EAB file: {}", path.display()))?;
        if current == next.as_bytes() {
            // Repair a mode on an existing file this writer did not
            // create, through the descriptor of the file it opened.
            tree.set_file_mode(path, KEY_FILE_MODE)?;
            return Ok(false);
        }
    }
    tree.publish(
        fs_util::Destination::bootroot_owned(path),
        next.as_bytes(),
        StagedMode::Policy(KEY_FILE_MODE),
        RootedOwner::Destination,
        fs_util::StagedDurability::FlushDirectory,
    )
    .with_context(|| format!("Failed to write EAB file: {}", path.display()))?;
    Ok(true)
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

/// Writes `contents` (newline-terminated) to a `0o600` key file idempotently.
///
/// A first-sighting fast-poll rewrite has the same payload as bootstrap
/// `write_secret_file`. For identical bytes at a final symlink, the writers
/// intentionally diverge: `write_secret_file` repairs the target's mode while
/// this writer republishes to replace the link.
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
        let destination_is_symlink = fs::symlink_metadata(path)
            .await
            .is_ok_and(|metadata| metadata.file_type().is_symlink());
        if !destination_is_symlink {
            // Repair a mode on an existing file this writer did not create.
            fs_util::set_key_permissions(path).await?;
            return Ok(false);
        }
        // Republishing replaces the link instead of repairing its target's
        // mode, even when the target already holds identical bytes.
    }
    fs_util::atomic_write(
        fs_util::Destination::bootroot_owned(path),
        next.as_bytes(),
        StagedMode::Policy(KEY_FILE_MODE),
    )
    .await
    .with_context(|| format!("Failed to write EAB file: {}", path.display()))?;
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

/// [`remove_eab_file`] for a `path` below the secrets directory `tree` is
/// opened on: through the handle on a rooted one, so a link at a
/// directory level is refused and a link at the file itself is removed
/// rather than followed.
///
/// # Errors
///
/// Returns an error under the same conditions as [`remove_eab_file`],
/// and on a rooted handle also when a directory level is a symbolic
/// link.
pub async fn remove_eab_file_in(tree: &Arc<SecretsTree>, path: &Path) -> anyhow::Result<bool> {
    if !tree.is_rooted() {
        return remove_eab_file(path).await;
    }
    let target = path.to_path_buf();
    tree.run(move |tree| match tree.remove_file(&target) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err)
            .with_context(|| format!("Failed to remove stale EAB file: {}", target.display())),
    })
    .await
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
    cli_hmac: Option<HmacSecret>,
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

        return parse_credentials(&content);
    }

    Ok(None)
}

/// [`load_credentials`] for an agent holding a handle on the secrets
/// directory.
///
/// With `tree` rooted and `file_path` below its anchor — a root agent
/// over a `secrets/` another account owns, reading a local-file
/// service's `eab.json` — the file is read through the handle and
/// follows no name: a symbolic link at any level, or anything but a
/// regular file at the leaf, fails the load naming the path. It is then
/// parsed exactly as [`load_credentials`] parses it, an absent file,
/// empty contents and an empty `kid` or `hmac` all giving no EAB. CLI
/// values take precedence as they do there. Any other case is
/// [`load_credentials`] unchanged.
///
/// # Errors
///
/// Returns an error under the same conditions as [`load_credentials`],
/// and when the handle refuses the file.
pub async fn load_credentials_in(
    tree: &Arc<SecretsTree>,
    cli_kid: Option<String>,
    cli_hmac: Option<HmacSecret>,
    file_path: Option<PathBuf>,
) -> anyhow::Result<Option<EabCredentials>> {
    let rooted_file = file_path
        .as_deref()
        .is_some_and(|path| fs_util::takes_rooted_branch(tree, path));
    if !rooted_file || (cli_kid.is_some() && cli_hmac.is_some()) {
        return load_credentials(cli_kid, cli_hmac, file_path).await;
    }
    let Some(path) = file_path else {
        return Ok(None);
    };
    let read = tree
        .run(move |tree| match tree.read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(anyhow::Error::new(err).context("Failed to read EAB file")),
        })
        .await?;
    let Some(bytes) = read else {
        return Ok(None);
    };
    let content = String::from_utf8(bytes).context("Failed to read EAB file")?;
    parse_credentials(&content)
}

/// Parses the contents of an `--eab-file`: empty contents, and an empty
/// `kid` or `hmac`, are no credentials.
fn parse_credentials(content: &str) -> anyhow::Result<Option<EabCredentials>> {
    if content.trim().is_empty() {
        return Ok(None);
    }

    let creds: EabCredentials =
        serde_json::from_str(content).context("Failed to parse EAB JSON")?;

    if creds.kid.is_empty() || creds.hmac.is_empty() {
        warn!("EAB file has empty kid or hmac field; treating as no credentials");
        return Ok(None);
    }

    Ok(Some(creds))
}
#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;
    #[tokio::test]
    async fn test_load_credentials_cli_precedence() {
        let cli_kid = Some("cli-kid".to_string());
        let cli_hmac = Some(HmacSecret::from("cli-hmac"));
        // Create a dummy file that has DIFFERENT credentials
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"kid": "file-kid", "key": "file-hmac"}}"#).unwrap();
        let file_path = Some(file.path().to_path_buf());
        // Action
        let result = load_credentials(cli_kid, cli_hmac, file_path).await;
        // Assert
        let creds = result.unwrap().unwrap();
        assert_eq!(creds.kid, "cli-kid");
        assert_eq!(creds.hmac.expose(), "cli-hmac");
    }
    #[tokio::test]
    async fn test_load_credentials_from_file_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"kid": "test-kid", "key": "test-hmac"}}"#).unwrap();
        let path = file.path().to_path_buf();
        let result = load_credentials(None, None, Some(path)).await;
        let creds = result.unwrap().unwrap();
        assert_eq!(creds.kid, "test-kid");
        assert_eq!(creds.hmac.expose(), "test-hmac");
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

        let creds = load_credentials(None, None, Some(path.clone()))
            .await
            .unwrap()
            .expect("credentials present");
        assert_eq!(creds.kid, "kid-1");
        assert_eq!(creds.hmac.expose(), "hmac-1");

        // An identical payload does not rewrite the bytes, but still repairs
        // the mode of a file this writer did not create.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let changed_again = write_eab_file(&path, "kid-1", "hmac-1").await.unwrap();
        assert!(!changed_again);
        let repaired_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(repaired_mode, 0o600);
    }

    /// A freshly created EAB file holds its policy mode even under a permissive
    /// umask. This guards the staged create-mode policy, not the former
    /// create-then-chmod window, which is not observable after the write.
    #[cfg(unix)]
    #[test]
    fn write_eab_file_creates_with_restricted_mode_under_umask_022() {
        use std::os::unix::fs::PermissionsExt;

        if fs_util::umask_test_ran_in_child(
            "eab::tests::write_eab_file_creates_with_restricted_mode_under_umask_022",
        ) {
            return;
        }

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets").join("eab.json");
        // SAFETY: this test runs in the child spawned above, with no other
        // tests sharing the process, and restores the prior umask immediately.
        let previous = unsafe { libc::umask(0o022) };
        let result = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(write_eab_file(&path, "kid-1", "hmac-1"));
        unsafe { libc::umask(previous) };
        assert!(result.expect("write EAB file"));

        let mode = std::fs::metadata(path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, KEY_FILE_MODE);
    }

    /// A secrets-tree link is replaced so EAB credentials are published at
    /// their bootroot-managed path rather than a link target.
    #[cfg(unix)]
    #[tokio::test]
    async fn write_eab_file_replaces_a_symlinked_destination() {
        let dir = tempfile::tempdir().expect("tempdir");
        let secrets = dir.path().join("secrets");
        std::fs::create_dir(&secrets).expect("mkdir");
        let target = dir.path().join("former-target.json");
        let former_payload = serialize_eab_payload("old-kid", "old-hmac").expect("serialize");
        std::fs::write(&target, &former_payload).expect("seed target");
        let path = secrets.join("eab.json");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");

        assert!(
            write_eab_file(&path, "kid-1", "hmac-1")
                .await
                .expect("write EAB file")
        );

        assert!(
            !std::fs::symlink_metadata(&path)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the secrets-tree symlink must be replaced"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            serialize_eab_payload("kid-1", "hmac-1").expect("serialize")
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("read former target"),
            former_payload
        );
    }

    /// An identical payload at a link target still replaces the link, without
    /// repairing permissions on a file outside the bootroot-managed path.
    #[cfg(unix)]
    #[tokio::test]
    async fn write_eab_file_replaces_an_identical_symlinked_destination() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("tempdir");
        let secrets = dir.path().join("secrets");
        std::fs::create_dir(&secrets).expect("mkdir");
        let payload = serialize_eab_payload("kid-1", "hmac-1").expect("serialize");
        let target = dir.path().join("former-target.json");
        std::fs::write(&target, &payload).expect("seed target");
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644))
            .expect("widen former target");
        let path = secrets.join("eab.json");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");

        assert!(
            write_eab_file(&path, "kid-1", "hmac-1")
                .await
                .expect("write EAB file")
        );

        assert!(
            !std::fs::symlink_metadata(&path)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the secrets-tree symlink must be replaced"
        );
        assert_eq!(std::fs::read_to_string(&path).expect("read"), payload);
        assert_eq!(
            std::fs::read_to_string(&target).expect("read former target"),
            payload
        );
        let target_mode = std::fs::metadata(target)
            .expect("stat former target")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(target_mode, 0o644);
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

    /// A `secrets/` holding `services/` and a sibling `outside/` with a
    /// recorded file, the layout the rooted tests below swap links into.
    fn rooted_layout() -> (tempfile::TempDir, PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(secrets.join("services").join("svc")).unwrap();
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        (dir, secrets, outside)
    }

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;

        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    fn rooted_tree(secrets: &Path) -> Arc<SecretsTree> {
        Arc::new(SecretsTree::open_rooted_for_tests(secrets).unwrap())
    }

    #[tokio::test]
    async fn rooted_write_eab_file_matches_the_path_based_write() {
        let mut results = Vec::new();
        for rooted in [false, true] {
            let (_dir, secrets, _outside) = rooted_layout();
            let tree = if rooted {
                rooted_tree(&secrets)
            } else {
                Arc::new(SecretsTree::open(&secrets).unwrap())
            };
            // `services/new/` is missing: the write creates it.
            let path = secrets.join("services").join("new").join("eab.json");
            assert!(
                write_eab_file_in(&tree, &path, "kid-1", "hmac-1")
                    .await
                    .unwrap()
            );
            assert!(
                !write_eab_file_in(&tree, &path, "kid-1", "hmac-1")
                    .await
                    .unwrap()
            );
            results.push((
                std::fs::read(&path).unwrap(),
                mode_of(&path),
                mode_of(path.parent().unwrap()),
            ));
            assert!(remove_eab_file_in(&tree, &path).await.unwrap());
            assert!(!remove_eab_file_in(&tree, &path).await.unwrap());
        }
        assert_eq!(results[0], results[1]);
        assert_eq!(results[1].1, KEY_FILE_MODE);
        assert_eq!(results[1].2, 0o700);
    }

    #[tokio::test]
    async fn rooted_write_eab_file_refuses_a_swapped_level_and_writes_nothing_outside() {
        let (_dir, secrets, outside) = rooted_layout();
        let tree = rooted_tree(&secrets);
        let services = secrets.join("services");
        std::fs::rename(&services, outside.parent().unwrap().join("aside")).unwrap();
        std::os::unix::fs::symlink(&outside, &services).unwrap();

        let path = services.join("svc").join("eab.json");
        let err = write_eab_file_in(&tree, &path, "kid-1", "hmac-1")
            .await
            .expect_err("a link at services/ is refused");
        assert!(format!("{err:#}").contains(&services.display().to_string()));
        let err = remove_eab_file_in(&tree, &path)
            .await
            .expect_err("a link at services/ is refused");
        assert!(format!("{err:#}").contains(&services.display().to_string()));
        assert!(
            std::fs::read_dir(&outside).unwrap().next().is_none(),
            "nothing was created outside secrets/"
        );
    }

    #[tokio::test]
    async fn rooted_write_eab_file_replaces_an_identical_leaf_link_without_touching_its_target() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, secrets, outside) = rooted_layout();
        let tree = rooted_tree(&secrets);
        let payload = serialize_eab_payload("kid-1", "hmac-1").unwrap();
        let target = outside.join("eab.json");
        std::fs::write(&target, &payload).unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        let path = secrets.join("services").join("svc").join("eab.json");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert!(
            write_eab_file_in(&tree, &path, "kid-1", "hmac-1")
                .await
                .unwrap()
        );
        let meta = std::fs::symlink_metadata(&path).unwrap();
        assert!(meta.file_type().is_file(), "the link was replaced");
        assert_eq!(mode_of(&path), KEY_FILE_MODE);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), payload);
        assert_eq!(std::fs::read_to_string(&target).unwrap(), payload);
        assert_eq!(mode_of(&target), 0o644, "the former target kept its mode");
    }

    #[tokio::test]
    async fn rooted_write_eab_file_repairs_the_mode_of_an_identical_regular_file() {
        use std::os::unix::fs::PermissionsExt;

        let (_dir, secrets, _outside) = rooted_layout();
        let tree = rooted_tree(&secrets);
        let payload = serialize_eab_payload("kid-1", "hmac-1").unwrap();
        let path = secrets.join("services").join("svc").join("eab.json");
        std::fs::write(&path, &payload).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        assert!(
            !write_eab_file_in(&tree, &path, "kid-1", "hmac-1")
                .await
                .unwrap()
        );
        assert_eq!(mode_of(&path), KEY_FILE_MODE);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), payload);
    }

    #[tokio::test]
    async fn rooted_remove_eab_file_removes_a_leaf_link_and_keeps_its_target() {
        let (_dir, secrets, outside) = rooted_layout();
        let tree = rooted_tree(&secrets);
        let target = outside.join("eab.json");
        std::fs::write(&target, "OUTSIDE\n").unwrap();
        let path = secrets.join("services").join("svc").join("eab.json");
        std::os::unix::fs::symlink(&target, &path).unwrap();

        assert!(remove_eab_file_in(&tree, &path).await.unwrap());
        assert!(std::fs::symlink_metadata(&path).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "OUTSIDE\n");
    }

    /// A root agent reading a local-file service's `eab.json` through
    /// its rooted handle refuses a link at `services/<id>` or at the file
    /// itself, naming it, and reads nothing outside `secrets/`.
    #[tokio::test]
    async fn rooted_load_credentials_refuses_a_swapped_level_or_leaf() {
        use crate::test_swap::{SwapRoot, assert_error_names};

        for level in ["services/svc", "services/svc/eab.json"] {
            let root = SwapRoot::new();
            root.write(
                "services/svc/eab.json",
                r#"{"kid":"kid-in","hmac":"hmac-in"}"#,
            );
            let outside_eab = root.outside.join("eab.json");
            std::fs::write(&outside_eab, r#"{"kid":"kid-out","hmac":"hmac-out"}"#).unwrap();
            let tree = root.rooted();
            let before = root.outside_snapshot();
            let target = if level == "services/svc/eab.json" {
                outside_eab.clone()
            } else {
                root.outside.clone()
            };
            let link = root.swap(level, &target);

            let err = load_credentials_in(
                &tree,
                None,
                None,
                Some(root.secrets.join("services/svc/eab.json")),
            )
            .await
            .expect_err("a link below secrets/ is refused");
            assert_error_names(&err, &link);
            assert_eq!(root.outside_snapshot(), before, "{level}");
        }
    }

    /// Through the handle, `eab.json` is parsed exactly as the
    /// path-based load parses it: credentials, an absent file, empty
    /// contents and an empty field alike; CLI values still win.
    #[tokio::test]
    async fn rooted_load_credentials_matches_the_path_based_load() {
        let root = crate::test_swap::SwapRoot::new();
        let path = root.secrets.join("services/svc/eab.json");
        for contents in [
            Some(r#"{"kid":"kid-1","key":"hmac-1"}"#),
            None,
            Some("  \n"),
            Some(r#"{"kid":"","hmac":"hmac-1"}"#),
        ] {
            match contents {
                Some(contents) => {
                    root.write("services/svc/eab.json", contents);
                }
                None => {
                    let _ = std::fs::remove_file(&path);
                }
            }
            let rooted = load_credentials_in(&root.rooted(), None, None, Some(path.clone()))
                .await
                .unwrap()
                .map(|creds| (creds.kid, creds.hmac.expose().to_string()));
            let by_path = load_credentials(None, None, Some(path.clone()))
                .await
                .unwrap()
                .map(|creds| (creds.kid, creds.hmac.expose().to_string()));
            assert_eq!(rooted, by_path, "{contents:?}");
        }
        let pinned = load_credentials_in(
            &root.rooted(),
            Some("cli-kid".to_string()),
            Some(HmacSecret::from("cli-hmac")),
            Some(path),
        )
        .await
        .unwrap()
        .expect("CLI values");
        assert_eq!(pinned.kid, "cli-kid");
    }

    /// An `--eab-file` the operator named outside the anchor is read as
    /// it always was, a link it is included.
    #[tokio::test]
    async fn rooted_load_credentials_leaves_a_file_outside_the_anchor_path_based() {
        let root = crate::test_swap::SwapRoot::new();
        let target = root.outside.join("eab.json");
        std::fs::write(&target, r#"{"kid":"kid-out","hmac":"hmac-out"}"#).unwrap();
        let link = root.root().join("eab-link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let creds = load_credentials_in(&root.rooted(), None, None, Some(link))
            .await
            .unwrap()
            .expect("credentials");
        assert_eq!(creds.kid, "kid-out");
    }

    #[test]
    fn shared_eab_reflects_sender_updates() {
        let (tx, rx) = watch::channel(None);
        let shared = SharedEab::from_receiver(rx);
        assert!(shared.current().is_none());

        tx.send_replace(Some(EabCredentials {
            kid: "kid-1".to_string(),
            hmac: "hmac-1".into(),
        }));
        let current = shared.current().expect("value present after update");
        assert_eq!(current.kid, "kid-1");

        tx.send_replace(None);
        assert!(shared.current().is_none());
    }
}
