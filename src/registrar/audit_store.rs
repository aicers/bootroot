//! The shared audit store's on-disk layout, and the checks that decide
//! whether a directory presenting itself as one may be used.
//!
//! Two writers land in one directory: the daemon's verb records under
//! [`RECORDS_SUBDIR`], and `OpenBao`'s file audit device under
//! [`OPENBAO_SUBDIR`]. Creating that layout is install-side work — it
//! needs uid 0 — so `bootroot init` drives the functions below while
//! running as root, and `bootroot infra up` re-checks the store
//! directory alone, which is all an unprivileged process can reach.
//!
//! The layout lives here, beside the record store whose trust checks
//! ([`super::audit`]) the result has to satisfy, so the two modes and
//! the ownership rule are stated once. Nothing here writes a record,
//! opens a store, or enforces the configured reserve.
//!
//! Which of the two creation shapes the install side drives is decided
//! by `[registrar] audit_store_enforcement`. [`create_layout`] makes
//! all three directories in one pass, which is what a `directory`
//! deployment gets. [`create_mount_point`] makes only the store
//! directory, which is what a `filesystem` deployment gets: there the
//! two subdirectories have to come into being on the filesystem
//! mounted over that directory, so creating them here would put them
//! underneath it. Neither function knows about the reserve itself.
//!
//! # The store directory contract
//!
//! The store directory and its record subdirectory are each a
//! directory and not a symbolic link, owned by an expected uid — 0 in
//! production — at mode exactly [`STORE_DIR_MODE`], reached through
//! ancestors that are all non-symlink directories carrying `o+x`.
//!
//! Exactly `0700`, rather than the record store's looser "not group- or
//! world-writable", is what lets an unprivileged `bootroot infra up`
//! check the store directory and nothing beneath it: a `0755` store
//! would still pass every record-store check while letting any process
//! on the host walk the trail. The ancestors' `o+x` is the other half —
//! it keeps the store directory `lstat`able without privilege, and
//! grants no listing without `o+r`.
//!
//! [`OPENBAO_SUBDIR`] is deliberately outside that contract. It is a
//! bind-mount source whose owner the `OpenBao` entrypoint sets on the
//! first container start, so nothing here asserts, compares or repairs
//! its owner or its mode; the only thing checked about it is that it is
//! a directory and not a symbolic link.
//!
//! Every check is over what is at the path when it runs, never over how
//! it got there.

use std::fs::{DirBuilder, Permissions};
use std::io;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Subdirectory of the store holding the daemon's verb records.
///
/// `[registrar] audit_record_dir` resolves here when it is omitted.
pub const RECORDS_SUBDIR: &str = "records";

/// Subdirectory of the store `OpenBao`'s file audit device is bound
/// into.
pub const OPENBAO_SUBDIR: &str = "openbao";

/// The container path `openbao/openbao.hcl`'s audit stanza writes its
/// file audit device to, and the destination the rendered Compose
/// override binds [`OPENBAO_SUBDIR`] at.
///
/// One spelling, because two places need it for different reasons: the
/// install side renders the bind mount, and the daemon's rotation
/// identifies its own container by looking for exactly that
/// destination in a running container's mount table.
pub const OPENBAO_CONTAINER_AUDIT_DIR: &str = "/openbao/audit";

/// Mode of the store directory and of [`RECORDS_SUBDIR`].
pub const STORE_DIR_MODE: u32 = 0o700;

/// Mode a missing component above the store is created at, matching the
/// record store's own `ANCESTOR_DIR_MODE`.
pub const ANCESTOR_DIR_MODE: u32 = 0o755;

/// Returns the systemd mount-unit name forced by `store_dir`.
///
/// A `.mount` unit must use systemd's escaped spelling of its mount point.
/// The installer renders that unit while the daemon names it in a refusal, so
/// the derivation lives beside the shared store layout rather than in either
/// caller.
#[must_use]
pub fn mount_unit_name(store_dir: &Path) -> String {
    format!("{}.mount", systemd_escape_path(store_dir))
}

fn systemd_escape_path(store_dir: &Path) -> String {
    let components: Vec<&[u8]> = store_dir
        .as_os_str()
        .as_bytes()
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty() && *component != b".")
        .collect();
    if components.is_empty() {
        return "-".to_string();
    }

    let mut escaped = String::new();
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            escaped.push('-');
        }
        for byte in *component {
            if byte.is_ascii_alphanumeric() || matches!(*byte, b':' | b'_' | b'.') {
                escaped.push(char::from(*byte));
            } else {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\x{byte:02x}");
            }
        }
    }
    if let Some(rest) = escaped.strip_prefix('.') {
        format!("\\x2e{rest}")
    } else {
        escaped
    }
}

/// The uid production requires the store directory and its record
/// subdirectory to be owned by.
pub const PRODUCTION_UID: u32 = 0;

/// The permission bits a mode comparison looks at. Wider than `0o777`
/// so a set-user-ID or sticky bit is a departure from `0700` rather
/// than something the mask hides.
const MODE_MASK: u32 = 0o7777;

/// The world-execute bit every component above the store must carry.
const WORLD_EXECUTE: u32 = 0o001;

/// What a path was found to be, where the contract required something
/// else.
///
/// Carries the observed values so the caller can name them; rendering
/// them for an operator is the caller's, because the install side puts
/// its text through a translated catalog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFault {
    /// A symbolic link, which `lstat` sees rather than follows.
    Symlink,
    /// Present, and not a directory.
    NotDirectory,
    /// A directory above the store without the world-execute bit, so
    /// the store below it cannot be reached without privilege.
    NotTraversable {
        /// The mode found, masked to its permission bits.
        mode: u32,
    },
    /// Owned by somebody other than the expected uid.
    Owner {
        /// The uid found.
        found: u32,
        /// The uid the contract requires.
        expected: u32,
    },
    /// At a mode other than exactly the required one.
    Mode {
        /// The mode found, masked to its permission bits.
        found: u32,
        /// The mode the contract requires.
        expected: u32,
    },
}

/// A refusal or a failure from the layout functions in this module.
///
/// Each variant is individually matchable on purpose: the install side
/// renders its own text for an operator through a translated catalog,
/// and which command is reporting decides the remedy it states.
#[derive(Debug, thiserror::Error)]
pub enum AuditStoreLayoutError {
    /// A path could not be inspected.
    #[error("inspecting {path}: {source}")]
    Inspect {
        /// The path that was being inspected.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// A directory could not be created.
    #[error("creating {path}: {source}")]
    CreateDirectory {
        /// The path that was being created.
        path: PathBuf,
        /// The underlying failure.
        #[source]
        source: io::Error,
    },
    /// A component above the store does not satisfy the ancestor rule.
    #[error("{path} is above the audit store and is {fault}")]
    Ancestor {
        /// The offending component.
        path: PathBuf,
        /// What was found there.
        fault: PathFault,
    },
    /// The store directory, or its record subdirectory, departs from
    /// the store directory contract.
    #[error("the audit store directory {path} is {fault}")]
    StoreDirectory {
        /// The offending directory.
        path: PathBuf,
        /// What was found there.
        fault: PathFault,
    },
    /// The `OpenBao` subdirectory is present and is not a plain
    /// directory, so it cannot become a bind-mount source.
    #[error("the OpenBao audit bind source {path} is {fault}")]
    OpenBaoDirectory {
        /// The offending path.
        path: PathBuf,
        /// What was found there.
        fault: PathFault,
    },
}

impl AuditStoreLayoutError {
    /// Returns the path the refusal or failure is about.
    #[must_use]
    pub fn path(&self) -> &Path {
        match self {
            Self::Inspect { path, .. }
            | Self::CreateDirectory { path, .. }
            | Self::Ancestor { path, .. }
            | Self::StoreDirectory { path, .. }
            | Self::OpenBaoDirectory { path, .. } => path,
        }
    }
}

impl std::fmt::Display for PathFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Symlink => write!(f, "a symbolic link"),
            Self::NotDirectory => write!(f, "not a directory"),
            Self::NotTraversable { mode } => {
                write!(f, "a directory at mode {mode:04o}, without o+x")
            }
            Self::Owner { found, expected } => {
                write!(f, "owned by uid {found}, not uid {expected}")
            }
            Self::Mode { found, expected } => {
                write!(f, "at mode {found:04o}, not mode {expected:04o}")
            }
        }
    }
}

/// The three paths the store's layout is made of.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditStoreLayout {
    /// `audit_store_dir` itself.
    pub store_dir: PathBuf,
    /// `<audit_store_dir>/records`, which the daemon's record store
    /// opens.
    pub records_dir: PathBuf,
    /// `<audit_store_dir>/openbao`, the bind-mount source for
    /// `OpenBao`'s file audit device.
    pub openbao_dir: PathBuf,
}

/// Returns the record subdirectory of `store_dir`.
#[must_use]
pub fn records_dir(store_dir: &Path) -> PathBuf {
    store_dir.join(RECORDS_SUBDIR)
}

/// Returns the `OpenBao` subdirectory of `store_dir`.
#[must_use]
pub fn openbao_dir(store_dir: &Path) -> PathBuf {
    store_dir.join(OPENBAO_SUBDIR)
}

/// Returns the layout `store_dir` describes, creating nothing.
#[must_use]
pub fn layout_of(store_dir: &Path) -> AuditStoreLayout {
    AuditStoreLayout {
        store_dir: store_dir.to_path_buf(),
        records_dir: records_dir(store_dir),
        openbao_dir: openbao_dir(store_dir),
    }
}

/// Verifies every **existing** component above `store_dir`, creating
/// nothing.
///
/// Walking stops at the first component that is not there: a missing
/// directory has no children to inspect, and creating what is missing
/// is [`create_layout`]'s second step rather than this check's.
///
/// # Errors
///
/// Returns [`AuditStoreLayoutError::Ancestor`] naming the first
/// component that is a symbolic link, is not a directory, or lacks the
/// world-execute bit, and [`AuditStoreLayoutError::Inspect`] when a
/// component cannot be inspected at all.
pub fn check_ancestors(store_dir: &Path) -> Result<(), AuditStoreLayoutError> {
    for ancestor in ancestors_top_down(store_dir) {
        let meta = match std::fs::symlink_metadata(&ancestor) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => break,
            Err(source) => {
                return Err(AuditStoreLayoutError::Inspect {
                    path: ancestor,
                    source,
                });
            }
        };
        if meta.file_type().is_symlink() {
            return Err(AuditStoreLayoutError::Ancestor {
                path: ancestor,
                fault: PathFault::Symlink,
            });
        }
        if !meta.is_dir() {
            return Err(AuditStoreLayoutError::Ancestor {
                path: ancestor,
                fault: PathFault::NotDirectory,
            });
        }
        let mode = meta.mode() & MODE_MASK;
        if mode & WORLD_EXECUTE == 0 {
            return Err(AuditStoreLayoutError::Ancestor {
                path: ancestor,
                fault: PathFault::NotTraversable { mode },
            });
        }
    }
    Ok(())
}

/// Audits `path` against the store directory contract.
///
/// Checks, never repairs: a departure is reported with what was found,
/// because widening a store directory silently is how a store stops
/// being one and narrowing a deliberate change is no better.
///
/// # Errors
///
/// Returns [`AuditStoreLayoutError::StoreDirectory`] when `path` is a
/// symbolic link, is not a directory, is owned by another uid, or is at
/// any mode other than exactly [`STORE_DIR_MODE`], and
/// [`AuditStoreLayoutError::Inspect`] when it cannot be inspected —
/// which includes its being absent.
pub fn check_store_directory(path: &Path, expected_uid: u32) -> Result<(), AuditStoreLayoutError> {
    // `symlink_metadata` does not follow the final component, so a
    // planted link is seen as a link rather than as whatever it points
    // at.
    let meta =
        std::fs::symlink_metadata(path).map_err(|source| AuditStoreLayoutError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
    let fault = directory_fault(&meta, expected_uid);
    match fault {
        Some(fault) => Err(AuditStoreLayoutError::StoreDirectory {
            path: path.to_path_buf(),
            fault,
        }),
        None => Ok(()),
    }
}

/// Creates the store layout under `store_dir`, owned by the running
/// process and at the contract's modes, and audits whatever is already
/// there.
///
/// The order is normative. Every existing component above the store is
/// verified first, so a rejected path leaves no half-provisioned host
/// behind; missing components are then created at
/// [`ANCESTOR_DIR_MODE`]; and only afterwards is anything created
/// inside the store.
///
/// Creating precedes checking, so the caller has to be running as
/// `expected_uid` already: a process whose uid differs would create the
/// layout under its own uid and only then fail its own owner check.
/// `bootroot init` refuses such a run before it reaches here rather
/// than leaving that directory behind.
///
/// The store directory and [`RECORDS_SUBDIR`] are created at
/// [`STORE_DIR_MODE`] when missing and held to the store directory
/// contract when found. [`OPENBAO_SUBDIR`] is created at the same mode
/// only when it is missing, and an existing one is required to be a
/// directory and not a symbolic link and is otherwise left exactly as
/// it is — after the first container start its owner is the
/// container's, and re-asserting uid 0 there would fail every re-run.
///
/// # Errors
///
/// Returns an error when an ancestor fails [`check_ancestors`], when a
/// directory cannot be created, when the store directory or its record
/// subdirectory departs from the contract, or when [`OPENBAO_SUBDIR`]
/// is present and is not a plain directory.
pub fn create_layout(
    store_dir: &Path,
    expected_uid: u32,
) -> Result<AuditStoreLayout, AuditStoreLayoutError> {
    check_ancestors(store_dir)?;
    create_missing_ancestors(store_dir)?;

    let layout = layout_of(store_dir);
    for dir in [&layout.store_dir, &layout.records_dir] {
        create_dir_with_mode(dir, STORE_DIR_MODE)?;
        check_store_directory(dir, expected_uid)?;
    }

    create_dir_with_mode(&layout.openbao_dir, STORE_DIR_MODE)?;
    check_plain_directory(&layout.openbao_dir)?;

    Ok(layout)
}

/// Creates the store's **mount point** and nothing beneath it, owned
/// by the running process and at the contract's mode.
///
/// [`create_layout`] minus its two subdirectories, for the
/// `filesystem` enforcement mode. There the store's subdirectories
/// have to come into being on the mounted filesystem: creating them
/// first and mounting over them produces an empty store and an
/// `OpenBao` container that cannot write its mandatory audit device,
/// with the originals hidden underneath. So the install path creates
/// only `store_dir` itself — a mount needs somewhere to go — and the
/// two subdirectories are the operator's to create once the mount is
/// active.
///
/// `check_mount_point` decides whether the store directory contract is
/// asserted. It is skipped while a filesystem is mounted here: what
/// `lstat` then sees is that filesystem's root directory, whose mode
/// `mkfs` chose and which no step of this surface may change.
///
/// # Errors
///
/// Returns an error when an ancestor fails [`check_ancestors`], when a
/// directory cannot be created, or when `check_mount_point` is set and
/// the store directory departs from the contract.
pub fn create_mount_point(
    store_dir: &Path,
    expected_uid: u32,
    check_mount_point: bool,
) -> Result<AuditStoreLayout, AuditStoreLayoutError> {
    check_ancestors(store_dir)?;
    create_missing_ancestors(store_dir)?;
    create_dir_with_mode(store_dir, STORE_DIR_MODE)?;
    if check_mount_point {
        check_store_directory(store_dir, expected_uid)?;
    }
    Ok(layout_of(store_dir))
}

/// Requires `path` to be a directory and not a symbolic link, and
/// asserts nothing at all about its owner or its mode.
fn check_plain_directory(path: &Path) -> Result<(), AuditStoreLayoutError> {
    let meta =
        std::fs::symlink_metadata(path).map_err(|source| AuditStoreLayoutError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
    let fault = if meta.file_type().is_symlink() {
        Some(PathFault::Symlink)
    } else if meta.is_dir() {
        None
    } else {
        Some(PathFault::NotDirectory)
    };
    match fault {
        Some(fault) => Err(AuditStoreLayoutError::OpenBaoDirectory {
            path: path.to_path_buf(),
            fault,
        }),
        None => Ok(()),
    }
}

/// The whole store-directory rejection decision, over metadata rather
/// than over a path, so every branch is reachable in a test that is not
/// root.
fn directory_fault(meta: &std::fs::Metadata, expected_uid: u32) -> Option<PathFault> {
    if meta.file_type().is_symlink() {
        return Some(PathFault::Symlink);
    }
    if !meta.is_dir() {
        return Some(PathFault::NotDirectory);
    }
    if meta.uid() != expected_uid {
        return Some(PathFault::Owner {
            found: meta.uid(),
            expected: expected_uid,
        });
    }
    let mode = meta.mode() & MODE_MASK;
    if mode != STORE_DIR_MODE {
        return Some(PathFault::Mode {
            found: mode,
            expected: STORE_DIR_MODE,
        });
    }
    None
}

/// Every component above `store_dir`, from the filesystem root down.
fn ancestors_top_down(store_dir: &Path) -> Vec<PathBuf> {
    let mut ancestors: Vec<PathBuf> = store_dir
        .ancestors()
        .skip(1)
        .map(Path::to_path_buf)
        .collect();
    ancestors.reverse();
    ancestors
}

/// Creates whatever component above `store_dir` is missing, at
/// [`ANCESTOR_DIR_MODE`].
fn create_missing_ancestors(store_dir: &Path) -> Result<(), AuditStoreLayoutError> {
    for ancestor in ancestors_top_down(store_dir) {
        if ancestor.parent().is_none() {
            // The filesystem root is nobody's to create.
            continue;
        }
        create_dir_with_mode(&ancestor, ANCESTOR_DIR_MODE)?;
    }
    Ok(())
}

/// Creates `path` at `mode`, and does nothing at all when it already
/// exists.
fn create_dir_with_mode(path: &Path, mode: u32) -> Result<(), AuditStoreLayoutError> {
    match DirBuilder::new().mode(mode).create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
        Err(source) => {
            return Err(AuditStoreLayoutError::CreateDirectory {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    // `mkdir` masks its mode with the process umask, so the directory
    // just created may be tighter than the contract states. Restating
    // it applies only to a directory that did not exist a line ago, so
    // no pre-existing entry is touched — which is what keeps this from
    // repairing a mode the caller is required to refuse instead.
    std::fs::set_permissions(path, Permissions::from_mode(mode)).map_err(|source| {
        AuditStoreLayoutError::CreateDirectory {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::*;
    use crate::registrar::audit::{
        AuditRecordStore, AuditStoreSettings, DEFAULT_AUDIT_MAX_FILE_BYTES,
        DEFAULT_AUDIT_MAX_RETAINED_FILES,
    };

    /// A temporary directory every ancestor of which is world
    /// traversable.
    ///
    /// The platform default will not do. `std::env::temp_dir()` is a
    /// `0700` per-user directory on macOS, and the logical `/tmp` there
    /// is a symbolic link — both of which the ancestor rule refuses,
    /// for the reasons it exists. Resolving `/tmp` physically and
    /// creating the directory inside it gives a base whose own
    /// ancestors are the conventional world-traversable ones on every
    /// platform these crates target.
    fn traversable_tempdir() -> TempDir {
        let base = Path::new("/tmp")
            .canonicalize()
            .expect("the physical /tmp resolves");
        let dir = tempfile::Builder::new()
            .prefix("bootroot-audit-store")
            .tempdir_in(base)
            .expect("temporary directory");
        std::fs::set_permissions(dir.path(), Permissions::from_mode(0o755))
            .expect("world-traversable base");
        dir
    }

    fn current_uid() -> u32 {
        crate::fs_util::current_process_euid()
    }

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path).expect("metadata").mode() & MODE_MASK
    }

    #[test]
    fn a_created_layout_carries_the_contract_modes() {
        let base = traversable_tempdir();
        let store = base.path().join("audit-store");
        let layout = create_layout(&store, current_uid()).expect("layout");

        assert_eq!(layout.store_dir, store);
        assert_eq!(layout.records_dir, store.join(RECORDS_SUBDIR));
        assert_eq!(layout.openbao_dir, store.join(OPENBAO_SUBDIR));
        assert_eq!(mode_of(&layout.store_dir), STORE_DIR_MODE);
        assert_eq!(mode_of(&layout.records_dir), STORE_DIR_MODE);
        assert!(layout.openbao_dir.is_dir());
    }

    #[test]
    fn a_mount_point_is_created_without_either_subdirectory() {
        let base = traversable_tempdir();
        let store = base.path().join("var").join("lib").join("audit-store");
        let layout = create_mount_point(&store, current_uid(), true).expect("mount point");

        assert_eq!(layout.store_dir, store);
        assert_eq!(mode_of(&store), STORE_DIR_MODE);
        assert_eq!(mode_of(&base.path().join("var")), ANCESTOR_DIR_MODE);
        // Creating these here would put them underneath the filesystem
        // about to be mounted over the store, which is an empty store
        // and a container that cannot write its audit device.
        assert!(!layout.records_dir.exists());
        assert!(!layout.openbao_dir.exists());

        // Idempotent: a second call over the same directory neither
        // creates nor repairs anything.
        create_mount_point(&store, current_uid(), true).expect("mount point again");
        assert!(!layout.records_dir.exists());
        assert!(!layout.openbao_dir.exists());
    }

    #[test]
    fn a_mount_point_check_can_be_skipped_for_a_directory_a_filesystem_is_mounted_over() {
        let base = traversable_tempdir();
        let store = base.path().join("audit-store");
        create_mount_point(&store, current_uid(), true).expect("mount point");
        // `mkfs.ext4` gives a filesystem's root directory `0755`, and
        // that root is what an `lstat` of the store sees once the mount
        // is up — a mode no step of the install path may change, and
        // one the contract would otherwise refuse.
        std::fs::set_permissions(&store, Permissions::from_mode(0o755)).expect("mode");

        assert!(create_mount_point(&store, current_uid(), true).is_err());
        create_mount_point(&store, current_uid(), false).expect("the check is skipped");
        assert_eq!(mode_of(&store), 0o755, "and nothing repaired it");
    }

    #[test]
    fn a_missing_ancestor_is_created_world_traversable() {
        let base = traversable_tempdir();
        let store = base.path().join("var").join("lib").join("audit-store");
        create_layout(&store, current_uid()).expect("layout");

        assert_eq!(mode_of(&base.path().join("var")), ANCESTOR_DIR_MODE);
        assert_eq!(
            mode_of(&base.path().join("var").join("lib")),
            ANCESTOR_DIR_MODE
        );
    }

    #[test]
    fn an_ancestor_without_world_execute_is_refused_before_anything_is_created() {
        let base = traversable_tempdir();
        let tight = base.path().join("tight");
        std::fs::create_dir(&tight).expect("ancestor");
        std::fs::set_permissions(&tight, Permissions::from_mode(0o700)).expect("chmod");
        let store = tight.join("audit-store");

        let err = create_layout(&store, current_uid()).expect_err("refused");
        assert!(
            matches!(
                err,
                AuditStoreLayoutError::Ancestor {
                    fault: PathFault::NotTraversable { .. },
                    ..
                }
            ),
            "unexpected error: {err}"
        );
        assert_eq!(err.path(), tight);
        assert!(!store.exists(), "nothing was created under a refused path");
    }

    #[test]
    fn a_symlinked_ancestor_is_refused() {
        let base = traversable_tempdir();
        let real = base.path().join("real");
        std::fs::create_dir(&real).expect("real");
        std::fs::set_permissions(&real, Permissions::from_mode(0o755)).expect("chmod");
        let link = base.path().join("link");
        symlink(&real, &link).expect("symlink");

        let store = link.join("audit-store");
        let err = create_layout(&store, current_uid()).expect_err("refused");
        assert!(
            matches!(
                err,
                AuditStoreLayoutError::Ancestor {
                    fault: PathFault::Symlink,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
        assert_eq!(err.path(), link);
        assert!(!real.join("audit-store").exists());
    }

    #[test]
    fn world_traversable_ancestors_are_accepted() {
        let base = traversable_tempdir();
        let middle = base.path().join("middle");
        std::fs::create_dir(&middle).expect("middle");
        std::fs::set_permissions(&middle, Permissions::from_mode(0o755)).expect("chmod");

        let store = middle.join("audit-store");
        create_layout(&store, current_uid()).expect("layout");
        check_store_directory(&store, current_uid()).expect("the infra up check passes too");
    }

    #[test]
    fn a_second_run_over_an_existing_layout_changes_nothing() {
        let base = traversable_tempdir();
        let store = base.path().join("audit-store");
        let layout = create_layout(&store, current_uid()).expect("first run");
        std::fs::write(layout.records_dir.join("keepme"), b"x").expect("write");

        let again = create_layout(&store, current_uid()).expect("second run");
        assert_eq!(again, layout);
        assert_eq!(mode_of(&layout.store_dir), STORE_DIR_MODE);
        assert_eq!(mode_of(&layout.records_dir), STORE_DIR_MODE);
        assert!(layout.records_dir.join("keepme").exists());
    }

    #[test]
    fn an_existing_openbao_directory_is_neither_asserted_nor_repaired() {
        let base = traversable_tempdir();
        let store = base.path().join("audit-store");
        let layout = create_layout(&store, current_uid()).expect("first run");
        // Stand in for what the container's entrypoint does on the
        // first start: it chowns and chmods the bind-mount source, and
        // the mode is the half a test can reproduce without privilege.
        std::fs::set_permissions(&layout.openbao_dir, Permissions::from_mode(0o755))
            .expect("chmod");
        std::fs::write(layout.openbao_dir.join("audit.log"), b"entry").expect("write");

        create_layout(&store, current_uid()).expect("a re-run over a started deployment succeeds");
        assert_eq!(
            mode_of(&layout.openbao_dir),
            0o755,
            "left exactly as it was"
        );
        assert!(layout.openbao_dir.join("audit.log").exists());
    }

    #[test]
    fn a_symlink_or_a_file_at_the_openbao_path_is_refused() {
        for plant in ["symlink", "file"] {
            let base = traversable_tempdir();
            let store = base.path().join("audit-store");
            create_dir_with_mode(&store, STORE_DIR_MODE).expect("store");
            let openbao = openbao_dir(&store);
            if plant == "symlink" {
                let target = base.path().join("elsewhere");
                std::fs::create_dir(&target).expect("target");
                symlink(&target, &openbao).expect("symlink");
            } else {
                std::fs::write(&openbao, b"not a directory").expect("file");
            }

            let err = create_layout(&store, current_uid()).expect_err("refused");
            assert!(
                matches!(err, AuditStoreLayoutError::OpenBaoDirectory { .. }),
                "unexpected error for {plant}: {err}"
            );
            assert_eq!(err.path(), openbao);
        }
    }

    #[test]
    fn a_store_directory_at_any_other_mode_is_refused_and_not_repaired() {
        for mode in [0o750, 0o755, 0o770, 0o600] {
            let base = traversable_tempdir();
            let store = base.path().join("audit-store");
            std::fs::create_dir(&store).expect("store");
            std::fs::set_permissions(&store, Permissions::from_mode(mode)).expect("chmod");

            let err = create_layout(&store, current_uid()).expect_err("refused");
            assert!(
                matches!(
                    err,
                    AuditStoreLayoutError::StoreDirectory {
                        fault: PathFault::Mode { .. },
                        ..
                    }
                ),
                "unexpected error at {mode:04o}: {err}"
            );
            assert_eq!(err.path(), store);
            assert_eq!(mode_of(&store), mode, "the mode was not repaired");
        }
    }

    #[test]
    fn a_records_directory_at_another_mode_is_refused() {
        let base = traversable_tempdir();
        let store = base.path().join("audit-store");
        let layout = create_layout(&store, current_uid()).expect("layout");
        std::fs::set_permissions(&layout.records_dir, Permissions::from_mode(0o750))
            .expect("chmod");

        let err = create_layout(&store, current_uid()).expect_err("refused");
        assert_eq!(err.path(), layout.records_dir);
        assert_eq!(mode_of(&layout.records_dir), 0o750);
    }

    #[test]
    fn a_store_directory_owned_by_another_uid_is_refused() {
        let base = traversable_tempdir();
        let store = base.path().join("audit-store");
        create_layout(&store, current_uid()).expect("layout");

        // A test cannot chown, so the foreign owner is expressed the
        // other way round: the same directory held to an expectation it
        // does not meet, which is the branch production reaches when a
        // store is not root-owned.
        let err = check_store_directory(&store, current_uid() + 1).expect_err("refused");
        assert!(
            matches!(
                err,
                AuditStoreLayoutError::StoreDirectory {
                    fault: PathFault::Owner { .. },
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_symlinked_store_directory_is_refused() {
        let base = traversable_tempdir();
        let elsewhere = base.path().join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("elsewhere");
        std::fs::set_permissions(&elsewhere, Permissions::from_mode(STORE_DIR_MODE))
            .expect("chmod");
        let store = base.path().join("audit-store");
        symlink(&elsewhere, &store).expect("symlink");

        let err = check_store_directory(&store, current_uid()).expect_err("refused");
        assert!(
            matches!(
                err,
                AuditStoreLayoutError::StoreDirectory {
                    fault: PathFault::Symlink,
                    ..
                }
            ),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn a_record_store_opens_over_the_created_layout() {
        let base = traversable_tempdir();
        let store = base.path().join("audit-store");
        let layout = create_layout(&store, current_uid()).expect("layout");

        // The record store audits the store directory's immediate
        // parent as well as the directory itself, so this exercises the
        // same trust checks production runs — over the layout the
        // install side produces and nothing else.
        let opened = AuditRecordStore::open_for_tests(AuditStoreSettings {
            dir: layout.records_dir.clone(),
            max_file_bytes: DEFAULT_AUDIT_MAX_FILE_BYTES,
            max_retained_files: DEFAULT_AUDIT_MAX_RETAINED_FILES,
        })
        .await;
        assert!(opened.is_ok(), "record store refused the layout");
    }

    #[test]
    fn the_record_subdirectory_is_where_the_configuration_resolves_it() {
        // `audit_record_dir` defaults to `<audit_store_dir>/records`,
        // so the directory created here has to be the one the daemon
        // will open. The two names are declared apart; this is what
        // keeps them the same name.
        let settings = crate::config::RegistrarSettings::default();
        assert_eq!(
            settings.audit_record_dir,
            records_dir(&settings.audit_store_dir)
        );
    }

    #[test]
    fn the_mount_unit_name_matches_systemd_path_escaping() {
        assert_eq!(
            mount_unit_name(Path::new("/var/lib/bootroot/audit-store")),
            "var-lib-bootroot-audit\\x2dstore.mount"
        );
    }

    #[test]
    fn a_fault_names_what_was_found() {
        assert_eq!(PathFault::Symlink.to_string(), "a symbolic link");
        assert_eq!(
            PathFault::Mode {
                found: 0o755,
                expected: STORE_DIR_MODE
            }
            .to_string(),
            "at mode 0755, not mode 0700"
        );
    }
}
