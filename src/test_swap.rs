//! The library's swap-test fixture: a `secrets/` and a sibling
//! `outside/` whose recorded contents a test compares before and after
//! the site it drives, with a level below `secrets/` replaced by a
//! symbolic link out of it.
//!
//! The binary crate keeps its own copy in `src/test_support.rs`; the
//! library's tests cannot reach it.

use std::collections::BTreeMap;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::fs_util::SecretsTree;

/// One recorded entry: its kind, mode, uid, gid, and the contents of a
/// file or the target of a link.
pub(crate) type Entry = (String, u32, u32, u32, Vec<u8>);

/// A `tempdir` holding `secrets/` and a sibling `outside/`.
pub(crate) struct SwapRoot {
    dir: tempfile::TempDir,
    /// The `secrets/` directory the site's handle is opened on.
    pub(crate) secrets: PathBuf,
    /// A directory outside `secrets/` a planted link points at.
    pub(crate) outside: PathBuf,
}

impl SwapRoot {
    /// Creates `secrets/` and `outside/`, the latter holding a file
    /// `secret` and a directory `inner/` with a file of its own.
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let secrets = dir.path().join("secrets");
        std::fs::create_dir(&secrets).expect("mkdir secrets");
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))
            .expect("chmod secrets");
        let outside = dir.path().join("outside");
        std::fs::create_dir_all(outside.join("inner")).expect("mkdir outside");
        std::fs::write(outside.join("secret"), "OUTSIDE-SECRET\n").expect("seed outside");
        std::fs::write(outside.join("inner").join("file"), "OUTSIDE-INNER\n")
            .expect("seed outside");
        Self {
            dir,
            secrets,
            outside,
        }
    }

    /// The `tempdir` holding both.
    pub(crate) fn root(&self) -> &Path {
        self.dir.path()
    }

    /// A rooted handle on `secrets/`, as a root process over a
    /// foreign-owned tree would open it.
    pub(crate) fn rooted(&self) -> Arc<SecretsTree> {
        Arc::new(SecretsTree::open_rooted_for_tests(&self.secrets).expect("open rooted handle"))
    }

    /// A path-based handle on `secrets/`, as a non-root process opens it.
    pub(crate) fn path_based(&self) -> Arc<SecretsTree> {
        Arc::new(SecretsTree::open(&self.secrets).expect("open path-based handle"))
    }

    /// Creates `rel` below `secrets/` as a file holding `contents`, its
    /// directories included.
    pub(crate) fn write(&self, rel: &str, contents: &str) -> PathBuf {
        let path = self.secrets.join(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir parent");
        }
        std::fs::write(&path, contents).expect("write");
        path
    }

    /// Moves the entry at `rel` below `secrets/` aside, out of the tree,
    /// and plants a link to `target` at its name. Returns the link's
    /// path.
    pub(crate) fn swap(&self, rel: &str, target: &Path) -> PathBuf {
        let path = self.secrets.join(rel);
        if std::fs::symlink_metadata(&path).is_ok() {
            let aside = self.root().join(format!("aside-{}", rel.replace('/', "-")));
            std::fs::rename(&path, aside).expect("move aside");
        }
        symlink(target, &path).expect("plant link");
        path
    }

    /// `outside/` itself and every entry below it, by relative path.
    pub(crate) fn outside_snapshot(&self) -> BTreeMap<PathBuf, Entry> {
        snapshot_tree(&self.outside)
    }
}

/// `root` itself, under the empty relative path, and every entry below
/// it, by relative path, read without following a link.
pub(crate) fn snapshot_tree(root: &Path) -> BTreeMap<PathBuf, Entry> {
    fn record(root: &Path, path: &Path, out: &mut BTreeMap<PathBuf, Entry>) {
        let meta = std::fs::symlink_metadata(path).expect("stat");
        let rel = path.strip_prefix(root).expect("below root").to_path_buf();
        let mode = meta.permissions().mode() & 0o7777;
        let (uid, gid) = (meta.uid(), meta.gid());
        if meta.file_type().is_symlink() {
            let target = std::fs::read_link(path).expect("readlink");
            out.insert(
                rel,
                (
                    "link".into(),
                    0,
                    uid,
                    gid,
                    target.as_os_str().as_encoded_bytes().to_vec(),
                ),
            );
        } else if meta.is_dir() {
            out.insert(rel, ("dir".into(), mode, uid, gid, Vec::new()));
            for entry in std::fs::read_dir(path).expect("read_dir") {
                record(root, &entry.expect("entry").path(), out);
            }
        } else {
            let contents = std::fs::read(path).expect("read");
            out.insert(rel, ("file".into(), mode, uid, gid, contents));
        }
    }
    let mut out = BTreeMap::new();
    record(root, root, &mut out);
    out
}

/// Asserts the rendered error chain of `err` names `path`.
///
/// The failure message carries neither the path nor the chain: both are
/// built from a `secrets/` path, and a panic message is a log sink to a
/// name-based scanner. A failing case is rerun with the site's error
/// printed by hand.
pub(crate) fn assert_error_names(err: &anyhow::Error, path: &Path) {
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains(&path.display().to_string()),
        "the error chain must name the path below secrets/ the site was given"
    );
}

/// The uid and gid a root-only test gives `secrets/`: an account other
/// than root, as an installer that runs the containers as dedicated
/// host accounts sets the tree up.
pub(crate) const FOREIGN_OWNER: u32 = 65_534;

/// Whether a root-only test should run: it runs as root, and fails
/// rather than skips when `BOOTROOT_E2E_REQUIRE_CERT_OWNER=1` asks for
/// it and the process is not root, so a CI step that meant to run it as
/// root cannot pass by skipping it.
pub(crate) fn running_as_root_or_required() -> bool {
    if crate::fs_util::current_process_euid() == 0 {
        return true;
    }
    assert!(
        std::env::var_os("BOOTROOT_E2E_REQUIRE_CERT_OWNER").is_none_or(|value| value != "1"),
        "BOOTROOT_E2E_REQUIRE_CERT_OWNER=1 requires this test to run as root"
    );
    false
}

/// Creates `secrets/` in `root` at `0700`, owned by [`FOREIGN_OWNER`]
/// for both uid and gid, and returns its path. Root only.
pub(crate) fn foreign_owned_secrets(root: &Path) -> PathBuf {
    let secrets = root.join("secrets");
    std::fs::create_dir(&secrets).expect("mkdir secrets");
    std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700))
        .expect("chmod secrets");
    std::os::unix::fs::chown(&secrets, Some(FOREIGN_OWNER), Some(FOREIGN_OWNER))
        .expect("chown secrets");
    secrets
}

/// Asserts the uid, gid and mode of `path`, not following a link.
///
/// The failure message names the entry by `label`, the test's own
/// description of it, rather than by its path below `secrets/`.
#[track_caller]
pub(crate) fn assert_owner_and_mode(path: &Path, owner: (u32, u32), mode: u32, label: &str) {
    let meta = std::fs::symlink_metadata(path).expect("stat");
    assert_eq!(
        (meta.uid(), meta.gid(), meta.permissions().mode() & 0o7777),
        (owner.0, owner.1, mode),
        "uid, gid and mode of {label}"
    );
}

/// The mode and owner of `path`, not following a link.
pub(crate) fn mode_and_owner(path: &Path) -> (u32, u32, u32) {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::symlink_metadata(path).expect("stat");
    (meta.mode() & 0o7777, meta.uid(), meta.gid())
}

/// The registrar endpoint daemon's config as `init` renders it below
/// `secrets`, for the host label `hostname`.
pub(crate) fn render_internal_config(secrets: &Path, hostname: &str) -> String {
    use crate::registrar::internal::{
        InternalAgentConfigParams, InternalPaths, render_internal_agent_config,
    };

    render_internal_agent_config(
        &InternalPaths::new(secrets),
        &InternalAgentConfigParams {
            email: "ops@example.internal",
            server: "https://127.0.0.1:1/acme/acme/directory",
            domain: "example.internal",
            hostname,
            responder_url: "http://127.0.0.1:1",
            responder_hmac: &"hmac".into(),
            eab_kid: None,
            eab_hmac: None,
            trusted_ca_sha256: &["a".repeat(64)],
            endpoint_tables: None,
        },
    )
}
