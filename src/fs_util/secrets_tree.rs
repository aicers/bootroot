//! Writes under `secrets/` that a root process makes without following
//! a name the owner of `secrets/` could have replaced.
//!
//! `secrets/` is meant to be owned by a non-root account: step-ca, both
//! `OpenBao` Agent sidecars and every `step` helper run as that owner,
//! and an installer may give the tree to a dedicated account before it
//! runs `bootroot infra install` and `init` as root. That owner can
//! rename or replace any entry in a directory it owns, so a root write
//! that resolves a directory under `secrets/` by name can be steered out
//! of the tree by a symbolic link swapped in at the right moment.
//!
//! [`SecretsTree`] is the handle the sites that write there take. It
//! decides once, from the opened anchor, whether the writer is root over
//! a tree another uid owns ([`rooted_mode`]). In that case every method
//! walks from the anchor's descriptor, one level at a time, refusing a
//! symbolic link at every level and at the leaf, and applies owner and
//! mode through the descriptor of what it opened. In every other case it
//! calls exactly the path-based helper the site called before, so a
//! non-root run, and a root run over a root-owned tree, keep the
//! documented relocation of a generated file through a symlink.
//!
//! Hard links are not seen by `O_NOFOLLOW`, so a mode fix here applies
//! to a regular file the owner of `secrets/` hard-linked into the tree.
//! While `fs.protected_hardlinks` is `1`, the default on current Linux
//! distributions, that owner cannot link a file it neither owns nor can
//! read and write.

use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write as _;
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{Context, Result};
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use super::{
    Destination, FixedOwner, KEY_FILE_MODE, SECRETS_DIR_MODE, StagedDurability, StagedMode,
    StagedOwner, SymlinkPolicy, chown_containing_dir_context, chown_fixed_context,
    chown_preserve_context, current_process_euid, ensure_secrets_dir_blocking,
    ensure_shared_secrets_dir_blocking, publish_staged_blocking,
};
use crate::registrar::internal::INTERNAL_DIR;

/// The levels directly below the anchor that are root-owned by policy,
/// whatever account owns `secrets/` itself.
///
/// `registrar-internal` holds the bootroot-internal credential; the
/// other two hold the retired registrar client pair a full CA rotation
/// preserves on a registrar endpoint host, and its staging directory.
/// The ownership sweep holds the same three back. The owner of
/// `secrets/` cannot enter them, but it can rename one away and put a
/// directory of its own at the name, which a descriptor walk would open
/// because it is not a link. A rooted walk therefore requires each of
/// them, when it opens one, to be owned by the writing process.
pub const ROOT_BY_POLICY_DIRS: [&str; 3] = [
    INTERNAL_DIR,
    "registrar-client-retired",
    "registrar-client-retired.staging",
];

/// What a directory entry is, read without following it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    /// A directory.
    Dir,
    /// A regular file.
    File,
    /// A symbolic link, whatever it points at.
    Symlink,
    /// Anything else: a FIFO, a socket or a device.
    Other,
}

/// The mode and owner of a file [`SecretsTree::read_with_meta`] read,
/// from the `fstat` of the descriptor it read through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMeta {
    /// The permission bits, masked with `0o7777`.
    pub mode: u32,
    /// The owning uid.
    pub uid: u32,
    /// The owning gid.
    pub gid: u32,
}

/// Names tried for a staged temporary before a rooted publish gives up.
///
/// The owner of `secrets/` can pre-create names in a directory it owns,
/// so an unbounded retry would let it stall the run.
const MAX_STAGED_NAME_ATTEMPTS: u32 = 64;

/// The prefix of a rooted publish's staged temporary.
const STAGED_NAME_PREFIX: &str = ".tmp-bootroot";

/// Distinguishes the staged temporaries one process creates.
static STAGED_NAME_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Returns whether a writer running as `writer_euid` over a `secrets/`
/// owned by `anchor_uid` takes the descriptor-relative writes of
/// [`SecretsTree`].
///
/// True exactly when the writer is root and the tree is not root's: the
/// one case in which the tree's owner can steer a write the writer could
/// not otherwise make. A non-root writer can follow a link only where it
/// could have written anyway, and a root-owned tree has no other owner
/// to swap a name in it.
#[must_use]
pub fn rooted_mode(writer_euid: u32, anchor_uid: u32) -> bool {
    writer_euid == 0 && anchor_uid != 0
}

/// Who owns the file a [`SecretsTree::publish`] renames into place.
///
/// The arms of [`StagedOwner`] the call sites under `secrets/` use, and
/// the ones a rooted publish knows how to reproduce through the staged
/// file's descriptor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootedOwner {
    /// The owner of the directory the file lands in:
    /// [`StagedOwner::ContainingDir`].
    ContainingDir,
    /// The owner of the file being replaced, and the writing process's
    /// for a fresh one: [`StagedOwner::Destination`].
    Destination,
    /// Exactly this uid and gid, established unconditionally through the
    /// staged file's descriptor before the rename: [`StagedOwner::Fixed`].
    Fixed(FixedOwner),
}

impl From<RootedOwner> for StagedOwner {
    fn from(owner: RootedOwner) -> Self {
        match owner {
            RootedOwner::ContainingDir => StagedOwner::ContainingDir,
            RootedOwner::Destination => StagedOwner::Destination,
            RootedOwner::Fixed(fixed) => StagedOwner::Fixed(fixed),
        }
    }
}

/// A handle on a `secrets/` directory through which a site makes every
/// write it makes there.
///
/// Opened once per site, from the anchor the site already holds. The
/// rooted or path-based decision is taken at [`SecretsTree::open`] from
/// `fstat` of the opened anchor, never from a path `stat`, and never
/// changes afterwards: nothing falls back to path-based once a handle is
/// rooted.
///
/// Every method takes the full path the site builds and strips the
/// anchor lexically. A path that is not below the anchor, or whose
/// remainder holds anything but plain names — a `..`, a root, or a
/// literal `.` as spelled, `secrets/.` included — is refused in both
/// modes, before anything is opened.
/// Every method is blocking; an async site runs them inside
/// `spawn_blocking`, through [`SecretsTree::run`] or the `_async`
/// wrappers.
#[derive(Debug)]
pub struct SecretsTree {
    anchor: PathBuf,
    fd: Option<OwnedFd>,
    rooted: bool,
    /// The writing process's effective uid, recorded at open: the owner
    /// a rooted walk requires of a level in [`ROOT_BY_POLICY_DIRS`].
    writer_euid: u32,
}

/// What a rooted publish found at the destination's name, read once
/// without following it.
enum Leaf {
    Absent,
    Symlink,
    Regular { mode: u32, uid: u32, gid: u32 },
    Other,
}

impl SecretsTree {
    /// Opens a handle on `anchor`, deciding from the opened directory
    /// whether its writes are descriptor-relative.
    ///
    /// The anchor is opened following its name as given: the anchor path
    /// and everything above it are outside what the owner of `secrets/`
    /// can rename. An anchor that does not exist yet gives a path-based
    /// handle, because the writer creates it and owns it.
    ///
    /// # Errors
    /// Returns an error if the anchor exists but cannot be opened as a
    /// directory, or cannot be stat'd.
    pub fn open(anchor: &Path) -> Result<Self> {
        Self::open_with(anchor, false)
    }

    /// Opens a handle on `anchor` as [`SecretsTree::open`] does, and
    /// forces rooted mode whatever the process uid.
    ///
    /// Exists for tests: the rooted walk, publish and mode fixes can then
    /// be driven by an unprivileged test process. It lives outside
    /// `cfg(test)` because the sites that take a handle are in the
    /// `bootroot` binary, whose tests link this library built without
    /// it. Forcing rooted mode can only make a write follow fewer names.
    ///
    /// # Errors
    /// Returns an error under the same conditions as
    /// [`SecretsTree::open`], and also when the anchor does not exist.
    #[doc(hidden)]
    pub fn open_rooted_for_tests(anchor: &Path) -> Result<Self> {
        Self::open_with(anchor, true)
    }

    /// [`SecretsTree::open`], run on a blocking thread, for an async site
    /// that shares the handle between the blocking tasks it spawns.
    ///
    /// # Errors
    /// Returns an error under the same conditions as
    /// [`SecretsTree::open`].
    pub async fn open_shared(anchor: &Path) -> Result<Arc<Self>> {
        let anchor = anchor.to_path_buf();
        tokio::task::spawn_blocking(move || Self::open(&anchor).map(Arc::new))
            .await
            .context("Secrets tree open task panicked")?
    }

    fn open_with(anchor: &Path, force_rooted: bool) -> Result<Self> {
        let opened = rustix::fs::openat(
            rustix::fs::CWD,
            anchor,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        );
        let writer_euid = current_process_euid();
        match opened {
            Ok(fd) => {
                let anchor_uid = rustix::fs::fstat(&fd)
                    .with_context(|| format!("Failed to stat {}", anchor.display()))?
                    .st_uid;
                Ok(Self {
                    anchor: anchor.to_path_buf(),
                    fd: Some(fd),
                    rooted: force_rooted || rooted_mode(writer_euid, anchor_uid),
                    writer_euid,
                })
            }
            Err(Errno::NOENT) if !force_rooted => Ok(Self {
                anchor: anchor.to_path_buf(),
                fd: None,
                rooted: false,
                writer_euid,
            }),
            Err(err) => {
                Err(err).with_context(|| format!("Failed to open secrets dir {}", anchor.display()))
            }
        }
    }

    /// Returns the anchor's path, as the handle was opened with it.
    #[must_use]
    pub fn anchor(&self) -> &Path {
        &self.anchor
    }

    /// Returns whether this handle's writes walk from the anchor's
    /// descriptor and follow no name.
    #[must_use]
    pub fn is_rooted(&self) -> bool {
        self.rooted
    }

    /// The anchor's descriptor when the handle is rooted; `None` sends a
    /// method down its path-based branch.
    fn rooted_fd(&self) -> Option<&OwnedFd> {
        self.fd.as_ref().filter(|_| self.rooted)
    }

    /// Records `uid` as the writing process's effective uid, so a test
    /// can make a directory it owns stand in for one another account
    /// owns.
    #[cfg(test)]
    pub(crate) fn set_writer_euid_for_tests(&mut self, uid: u32) {
        self.writer_euid = uid;
    }

    /// The anchor's descriptor for one of the methods that exist only in
    /// rooted mode; on a path-based handle, an `Unsupported` error naming
    /// `path`.
    fn require_rooted(&self, path: &Path) -> std::io::Result<&OwnedFd> {
        self.rooted_fd().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                format!(
                    "{} cannot be reached through a path-based handle on the secrets directory \
                     {}: this operation exists only for a root process over a secrets \
                     directory another account owns",
                    path.display(),
                    self.anchor.display()
                ),
            )
        })
    }

    /// [`SecretsTree::relative`] as an `InvalidInput` I/O error.
    fn relative_io<'p>(&self, path: &'p Path) -> std::io::Result<Vec<&'p OsStr>> {
        self.relative(path).map_err(|err| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("{err:#}"))
        })
    }

    /// Refuses a level directly below the anchor whose name is in
    /// [`ROOT_BY_POLICY_DIRS`] unless the opened directory is owned by
    /// the writing process. `depth` is the level's index below the
    /// anchor, `0` for an entry of the anchor itself.
    fn check_root_by_policy(
        &self,
        depth: usize,
        name: &OsStr,
        dir: &File,
        path: &Path,
    ) -> std::io::Result<()> {
        if depth != 0
            || !ROOT_BY_POLICY_DIRS
                .iter()
                .any(|held| name == OsStr::new(held))
        {
            return Ok(());
        }
        let uid = dir
            .metadata()
            .map_err(|err| io_context(&err, &format!("Failed to stat {}", path.display())))?
            .uid();
        if uid == self.writer_euid {
            return Ok(());
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Refusing to use {}: it must be owned by uid {} by policy, and is owned by uid \
                 {uid}, so it is not the directory bootroot created there",
                path.display(),
                self.writer_euid
            ),
        ))
    }

    /// Opens each of `names` below the anchor in turn, without following
    /// a link at any of them and subject to the root-by-policy check,
    /// and returns the last; the anchor itself when `names` is empty.
    /// Creates nothing. A missing level is `NotFound`.
    fn walk_io(&self, anchor_fd: &OwnedFd, names: &[&OsStr]) -> std::io::Result<File> {
        let mut current = anchor_fd.try_clone().map(File::from).map_err(|err| {
            io_context(
                &err,
                &format!(
                    "Failed to duplicate the descriptor of {}",
                    self.anchor.display()
                ),
            )
        })?;
        let mut level = self.anchor.clone();
        for (depth, name) in names.iter().enumerate() {
            level.push(name);
            current =
                open_dir_nofollow(&current, name).map_err(|err| refused_level_io(err, &level))?;
            self.check_root_by_policy(depth, name, &current, &level)?;
        }
        Ok(current)
    }

    /// The leaf name of `path` and the descriptor of its directory,
    /// reached by [`SecretsTree::walk_io`].
    fn parent_of<'p>(
        &self,
        anchor_fd: &OwnedFd,
        path: &'p Path,
        names: &[&'p OsStr],
    ) -> std::io::Result<(&'p OsStr, usize, File)> {
        let (leaf, dirs) = names.split_last().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} names the secrets directory itself, not an entry in it",
                    path.display()
                ),
            )
        })?;
        Ok((*leaf, dirs.len(), self.walk_io(anchor_fd, dirs)?))
    }

    /// Reads the regular file at `path`.
    ///
    /// Rooted only. The directories are walked as
    /// [`SecretsTree::ensure_dir`] walks them, creating nothing; the leaf
    /// is opened with `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, confirmed a
    /// regular file by `fstat`, and read from that descriptor. A link, a
    /// FIFO, a device or a directory at the leaf is refused, and a FIFO
    /// never blocks the read.
    ///
    /// # Errors
    /// Returns `NotFound` if the leaf or any directory level is missing;
    /// an `Unsupported` error on a path-based handle; and an error naming
    /// the path if `path` is not below the anchor, a level is a link or
    /// fails the root-by-policy check, or the leaf is not a regular file
    /// or cannot be read.
    pub fn read(&self, path: &Path) -> std::io::Result<Vec<u8>> {
        self.read_with_meta(path).map(|(contents, _)| contents)
    }

    /// Removes the directory entry at `path` that is not a directory.
    ///
    /// Rooted only: `unlinkat` on the descriptor of the walked parent. A
    /// symbolic link at the leaf is removed itself, which follows
    /// nothing.
    ///
    /// # Errors
    /// Returns `NotFound` if the leaf or any directory level is missing;
    /// an `Unsupported` error on a path-based handle; and an error naming
    /// the path if a level is a link or fails the root-by-policy check,
    /// or the unlink fails.
    pub fn remove_file(&self, path: &Path) -> std::io::Result<()> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let (leaf, _, dir) = self.parent_of(anchor_fd, path, &names)?;
        rustix::fs::unlinkat(&dir, leaf, AtFlags::empty())
            .map_err(|err| errno_context(err, &format!("Failed to remove {}", path.display())))
    }

    /// Removes the directory at `path` and everything below it.
    ///
    /// Rooted only. The target is opened with
    /// `O_RDONLY | O_DIRECTORY | O_NOFOLLOW` and listed through its
    /// descriptor; each entry that opens the same way is recursed into,
    /// every other entry is unlinked, and the directory itself is
    /// finally unlinked with `AT_REMOVEDIR`. A symbolic link anywhere
    /// inside is unlinked and never descended, and a symbolic link at
    /// the target itself is unlinked, as `std::fs::remove_dir_all` does.
    ///
    /// # Errors
    /// Returns `NotFound` if the target or any directory level above it
    /// is missing; an `Unsupported` error on a path-based handle; and an
    /// error naming the path if a level above the target is a link or
    /// fails the root-by-policy check, the target is neither a directory
    /// nor a link, or an entry cannot be listed or removed.
    pub fn remove_dir_all(&self, path: &Path) -> std::io::Result<()> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let (leaf, depth, parent) = self.parent_of(anchor_fd, path, &names)?;
        let stat = rustix::fs::statat(&parent, leaf, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|err| errno_context(err, &format!("Failed to stat {}", path.display())))?;
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Symlink => rustix::fs::unlinkat(&parent, leaf, AtFlags::empty())
                .map_err(|err| errno_context(err, &format!("Failed to remove {}", path.display()))),
            FileType::Directory => {
                let dir =
                    open_dir_nofollow(&parent, leaf).map_err(|err| refused_level_io(err, path))?;
                self.check_root_by_policy(depth, leaf, &dir, path)?;
                clear_dir_rooted(&dir, path)?;
                drop(dir);
                rustix::fs::unlinkat(&parent, leaf, AtFlags::REMOVEDIR).map_err(|err| {
                    errno_context(err, &format!("Failed to remove {}", path.display()))
                })
            }
            _ => Err(errno_context(
                Errno::NOTDIR,
                &format!("Refusing to remove {} as a directory", path.display()),
            )),
        }
    }

    /// Lists the directory at `path`, skipping `.` and `..`, with each
    /// entry's kind read without following it.
    ///
    /// Rooted only: the directory is reached by the walk and listed
    /// through its own descriptor; each kind comes from
    /// `statat(dir, name, AT_SYMLINK_NOFOLLOW)`. An entry that vanished
    /// between the listing and its `statat` is left out.
    ///
    /// # Errors
    /// Returns `NotFound` if the directory or any level above it is
    /// missing; an `Unsupported` error on a path-based handle; and an
    /// error naming the path if a level is a link or fails the
    /// root-by-policy check, or the directory cannot be listed.
    pub fn read_dir(&self, path: &Path) -> std::io::Result<Vec<(OsString, EntryKind)>> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let dir = self.walk_io(anchor_fd, &names)?;
        let mut listed = Vec::new();
        for name in list_dir(&dir, path)? {
            match rustix::fs::statat(&dir, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => listed.push((name, entry_kind_of(&stat))),
                Err(Errno::NOENT) => {}
                Err(err) => {
                    return Err(errno_context(
                        err,
                        &format!("Failed to stat {}", path.join(&name).display()),
                    ));
                }
            }
        }
        Ok(listed)
    }

    /// Returns what is at `path`, read without following it, or `None`
    /// when nothing is, a missing directory level included.
    ///
    /// Rooted only: `statat(parent, leaf, AT_SYMLINK_NOFOLLOW)` through
    /// the walked parent. It replaces an `exists()`, `is_dir()` or
    /// `std::fs::metadata` probe in a rooted branch.
    ///
    /// # Errors
    /// Returns an `Unsupported` error on a path-based handle, and an
    /// error naming the path if a level above the leaf is a link or fails
    /// the root-by-policy check, or the leaf cannot be stat'd.
    pub fn entry_kind(&self, path: &Path) -> std::io::Result<Option<EntryKind>> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let (leaf, _, dir) = match self.parent_of(anchor_fd, path, &names) {
            Ok(found) => found,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        match rustix::fs::statat(&dir, leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => Ok(Some(entry_kind_of(&stat))),
            Err(Errno::NOENT) => Ok(None),
            Err(err) => Err(errno_context(
                err,
                &format!("Failed to stat {}", path.display()),
            )),
        }
    }

    /// Creates `path` as a directory, every missing level on the way
    /// included, each created level at `0700` and owned by `owner`.
    ///
    /// Rooted only. Each level is opened from its parent's descriptor
    /// with `O_NOFOLLOW`, created with `mkdirat` when missing, and given
    /// its mode and owner through its own descriptor. A level that
    /// already existed keeps its owner, and keeps its mode unless it is
    /// `path` itself, which ends `0700` — as [`SecretsTree::ensure_dir`]
    /// leaves the last level.
    ///
    /// # Errors
    /// Returns an `Unsupported` error on a path-based handle, and an
    /// error naming the path if `path` is not below the anchor, a level
    /// is a link or fails the root-by-policy check, or a level cannot be
    /// created or given its mode or owner.
    pub fn ensure_dir_fixed(&self, path: &Path, owner: FixedOwner) -> std::io::Result<()> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        if names.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "{} names the secrets directory itself, which keeps its own owner",
                    path.display()
                ),
            ));
        }
        let mut current = self.walk_io(anchor_fd, &[])?;
        let mut level = self.anchor.clone();
        let last = names.len() - 1;
        for (depth, name) in names.iter().enumerate() {
            level.push(name);
            let (dir, created) = match open_dir_nofollow(&current, name) {
                Ok(dir) => (dir, false),
                Err(Errno::NOENT) => {
                    let created = match rustix::fs::mkdirat(&current, *name, Mode::RWXU) {
                        Ok(()) => true,
                        Err(Errno::EXIST) => false,
                        Err(err) => {
                            return Err(errno_context(
                                err,
                                &format!("Failed to create secrets dir {}", level.display()),
                            ));
                        }
                    };
                    let dir = open_dir_nofollow(&current, name)
                        .map_err(|err| refused_level_io(err, &level))?;
                    (dir, created)
                }
                Err(err) => return Err(refused_level_io(err, &level)),
            };
            self.check_root_by_policy(depth, name, &dir, &level)?;
            if created || depth == last {
                dir.set_permissions(std::fs::Permissions::from_mode(SECRETS_DIR_MODE))
                    .map_err(|err| {
                        io_context(
                            &err,
                            &format!(
                                "Failed to set mode {SECRETS_DIR_MODE:o} on {}",
                                level.display()
                            ),
                        )
                    })?;
            }
            if created {
                let current_owner = dir
                    .metadata()
                    .map(|meta| (meta.uid(), meta.gid()))
                    .map_err(|err| {
                        io_context(&err, &format!("Failed to stat {}", level.display()))
                    })?;
                if current_owner != (owner.uid, owner.gid) {
                    std::os::unix::fs::fchown(&dir, Some(owner.uid), Some(owner.gid))
                        .map_err(|err| io_context(&err, &chown_fixed_context(owner, &level)))?;
                }
            }
            current = dir;
        }
        Ok(())
    }

    /// Gives the existing directory at `path` the anchor's owner.
    ///
    /// Rooted only: the directory is opened with
    /// `O_RDONLY | O_DIRECTORY | O_NOFOLLOW` from its walked parent and
    /// `fchown`ed to the anchor's `fstat` uid and gid when they differ.
    /// Its mode and its contents are left alone.
    ///
    /// # Errors
    /// Returns `NotFound` if the directory or a level above it is
    /// missing; an `Unsupported` error on a path-based handle; and an
    /// error naming the path if a level is a link or fails the
    /// root-by-policy check, or the directory cannot be stat'd or
    /// chowned.
    pub fn adopt_dir(&self, path: &Path) -> std::io::Result<()> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let anchor_owner = rustix::fs::fstat(anchor_fd)
            .map(|stat| (stat.st_uid, stat.st_gid))
            .map_err(|err| {
                errno_context(err, &format!("Failed to stat {}", self.anchor.display()))
            })?;
        let dir = self.walk_io(anchor_fd, &names)?;
        let current = dir
            .metadata()
            .map(|meta| (meta.uid(), meta.gid()))
            .map_err(|err| io_context(&err, &format!("Failed to stat {}", path.display())))?;
        if current == anchor_owner {
            return Ok(());
        }
        std::os::unix::fs::fchown(&dir, Some(anchor_owner.0), Some(anchor_owner.1))
            .map_err(|err| io_context(&err, &created_level_owner_context(path, anchor_owner)))
    }

    /// Creates `path` as a directory, every missing level on the way
    /// included, each created level at `0700` and owned by the writing
    /// process.
    ///
    /// Rooted only: the counterpart of [`super::ensure_secrets_dir`],
    /// which leaves what it creates to the writer as well. Each missing
    /// level is created with `mkdirat(parent, name, 0700)`, opened with
    /// `O_DIRECTORY | O_NOFOLLOW` and `fchmod`ed `0700` through its own
    /// descriptor, and no owner is changed. A level that already existed
    /// keeps its owner, and keeps its mode unless it is `path` itself,
    /// which ends `0700`. For the anchor itself the anchor's descriptor
    /// is `fchmod`ed `0700`, as [`SecretsTree::ensure_dir`] does.
    ///
    /// # Errors
    /// Returns an `Unsupported` error on a path-based handle, and an
    /// error naming the path if `path` is not below the anchor, a level
    /// is a link or fails the root-by-policy check, or a level cannot be
    /// created or given its mode.
    pub fn ensure_dir_as_writer(&self, path: &Path) -> std::io::Result<()> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let mut current = self.walk_io(anchor_fd, &[])?;
        if names.is_empty() {
            return set_mode_io(&current, SECRETS_DIR_MODE, &self.anchor);
        }
        let mut level = self.anchor.clone();
        let last = names.len() - 1;
        for (depth, name) in names.iter().enumerate() {
            level.push(name);
            let (dir, created) = match open_dir_nofollow(&current, name) {
                Ok(dir) => (dir, false),
                Err(Errno::NOENT) => {
                    let created = match rustix::fs::mkdirat(&current, *name, Mode::RWXU) {
                        Ok(()) => true,
                        // A racing create: the level is now an existing
                        // one, and is opened as such.
                        Err(Errno::EXIST) => false,
                        Err(err) => {
                            return Err(errno_context(
                                err,
                                &format!("Failed to create secrets dir {}", level.display()),
                            ));
                        }
                    };
                    let dir = open_dir_nofollow(&current, name)
                        .map_err(|err| refused_level_io(err, &level))?;
                    (dir, created)
                }
                Err(err) => return Err(refused_level_io(err, &level)),
            };
            self.check_root_by_policy(depth, name, &dir, &level)?;
            if created || depth == last {
                set_mode_io(&dir, SECRETS_DIR_MODE, &level)?;
            }
            current = dir;
        }
        Ok(())
    }

    /// Creates the regular file at `path`, which must not exist, holding
    /// `contents` at exactly `mode`.
    ///
    /// Rooted only. The file is created with
    /// `openat(dir, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW)` in
    /// its walked directory, written, `fchmod`ed to `mode` through its
    /// descriptor so the umask does not narrow it, `fchown`ed to `owner`
    /// when one is given and differs from what it has, and `fsync`ed. It
    /// is not renamed: the name it is created at is the final one. A
    /// failure once the file exists removes it again.
    ///
    /// # Errors
    /// Returns `AlreadyExists` if anything, a symbolic link included, is
    /// at the name; an `Unsupported` error on a path-based handle; and an
    /// error naming the path if `path` is not below the anchor, a
    /// directory level is missing, is a link or fails the root-by-policy
    /// check, or the file cannot be written, given its mode or owner, or
    /// flushed.
    pub fn create_new(
        &self,
        path: &Path,
        contents: &[u8],
        mode: u32,
        owner: Option<(u32, u32)>,
    ) -> std::io::Result<()> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let (leaf, _, dir) = self.parent_of(anchor_fd, path, &names)?;
        let fd = rustix::fs::openat(
            &dir,
            leaf,
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|err| errno_context(err, &format!("Failed to create {}", path.display())))?;
        let mut file = File::from(fd);
        let written = (|| {
            file.write_all(contents)
                .map_err(|err| io_context(&err, &format!("Failed to write {}", path.display())))?;
            set_mode_io(&file, mode, path)?;
            if let Some((uid, gid)) = owner {
                let current = file
                    .metadata()
                    .map(|meta| (meta.uid(), meta.gid()))
                    .map_err(|err| {
                        io_context(&err, &format!("Failed to stat {}", path.display()))
                    })?;
                if current != (uid, gid) {
                    std::os::unix::fs::fchown(&file, Some(uid), Some(gid))
                        .map_err(|err| io_context(&err, &chown_preserve_context(uid, gid, path)))?;
                }
            }
            file.sync_all()
                .map_err(|err| io_context(&err, &format!("Failed to fsync {}", path.display())))
        })();
        if written.is_err() {
            // Best effort: the create is already failing, and its own
            // error is the one to report.
            let _ = rustix::fs::unlinkat(&dir, leaf, AtFlags::empty());
        }
        written
    }

    /// Creates the directory at `path`, which must not exist, at `mode`
    /// and owned by `owner`.
    ///
    /// Rooted only. The directory is created with `mkdirat` in its walked
    /// parent and then opened with `O_DIRECTORY | O_NOFOLLOW`. Before
    /// any mode or owner change, the opened directory must be owned by
    /// the writing process and empty, as the one `mkdirat` just created
    /// is, and must pass the root-by-policy check: a directory somebody
    /// else put at the name between the create and the open is refused
    /// and receives nothing. Only then is it `fchmod`ed to `mode` and
    /// `fchown`ed to `owner` through its descriptor.
    ///
    /// # Errors
    /// Returns `AlreadyExists` naming the path if anything is at the
    /// name; an `Unsupported` error on a path-based handle; and an error
    /// naming the path if `path` is not below the anchor, a level above it
    /// is missing, is a link or fails the root-by-policy check, the
    /// opened directory is not the one just created, or it cannot be
    /// given its mode or owner.
    pub fn create_dir_exclusive(
        &self,
        path: &Path,
        mode: u32,
        owner: (u32, u32),
    ) -> std::io::Result<()> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let (leaf, depth, parent) = self.parent_of(anchor_fd, path, &names)?;
        rustix::fs::mkdirat(&parent, leaf, Mode::RWXU)
            .map_err(|err| errno_context(err, &format!("Failed to create {}", path.display())))?;
        let dir = open_dir_nofollow(&parent, leaf).map_err(|err| refused_level_io(err, path))?;
        let found = dir
            .metadata()
            .map_err(|err| io_context(&err, &format!("Failed to stat {}", path.display())))?
            .uid();
        if found != self.writer_euid || !list_dir(&dir, path)?.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Refusing to use {}: it is not the empty directory this process just \
                     created there (owned by uid {found}, expected uid {})",
                    path.display(),
                    self.writer_euid
                ),
            ));
        }
        self.check_root_by_policy(depth, leaf, &dir, path)?;
        set_mode_io(&dir, mode, path)?;
        if (found, dir_gid(&dir, path)?) != owner {
            std::os::unix::fs::fchown(&dir, Some(owner.0), Some(owner.1))
                .map_err(|err| io_context(&err, &chown_preserve_context(owner.0, owner.1, path)))?;
        }
        Ok(())
    }

    /// Renames the entry at `from` to `to`, both below the anchor.
    ///
    /// Rooted only: `renameat` between the two walked parents' descriptors.
    /// Neither name is followed: a symbolic link at `from` is renamed
    /// itself, and one at `to` is replaced.
    ///
    /// # Errors
    /// Returns `NotFound` if `from` or a level above either name is
    /// missing; an `Unsupported` error on a path-based handle; and an
    /// error naming the paths if either is not below the anchor, a level
    /// above either is a link or fails the root-by-policy check, or the
    /// rename fails.
    pub fn rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
        let anchor_fd = self.require_rooted(from)?;
        let from_names = self.relative_io(from)?;
        let to_names = self.relative_io(to)?;
        let (from_leaf, _, from_dir) = self.parent_of(anchor_fd, from, &from_names)?;
        let (to_leaf, _, to_dir) = self.parent_of(anchor_fd, to, &to_names)?;
        rustix::fs::renameat(&from_dir, from_leaf, &to_dir, to_leaf).map_err(|err| {
            errno_context(
                err,
                &format!("Failed to rename {} to {}", from.display(), to.display()),
            )
        })
    }

    /// Flushes the directory at `path`, the anchor itself included.
    ///
    /// Rooted only: `fsync` of the directory's own descriptor, reached by
    /// the walk.
    ///
    /// # Errors
    /// Returns `NotFound` if the directory or a level above it is
    /// missing; an `Unsupported` error on a path-based handle; and an
    /// error naming the path if a level is a link or fails the
    /// root-by-policy check, or the flush fails.
    pub fn sync_dir(&self, path: &Path) -> std::io::Result<()> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let dir = self.walk_io(anchor_fd, &names)?;
        dir.sync_all().map_err(|err| {
            io_context(
                &err,
                &format!("Failed to fsync directory {}", path.display()),
            )
        })
    }

    /// Opens, creating it at `mode` when missing, the lock file at
    /// `path`, and returns it for the caller to lock.
    ///
    /// Rooted only:
    /// `openat(dir, leaf, O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK)` in
    /// the walked directory, then `fstat` of the opened descriptor, which
    /// must be a regular file. A FIFO at the name never blocks the open.
    ///
    /// # Errors
    /// Returns `NotFound` if a directory level is missing; an
    /// `Unsupported` error on a path-based handle; and an error naming
    /// the path if `path` is not below the anchor, a level is a link or
    /// fails the root-by-policy check, the leaf is a symbolic link or
    /// anything but a regular file, or it cannot be opened.
    pub fn open_lock(&self, path: &Path, mode: u32) -> std::io::Result<File> {
        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let (leaf, _, dir) = self.parent_of(anchor_fd, path, &names)?;
        let fd = rustix::fs::openat(
            &dir,
            leaf,
            OFlags::RDWR | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::from_raw_mode(mode_t_of(mode)),
        )
        .map_err(|err| refused_file_io(err, path))?;
        let file = File::from(fd);
        let meta = file
            .metadata()
            .map_err(|err| io_context(&err, &format!("Failed to stat {}", path.display())))?;
        if !meta.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Refusing to lock {}: it is not a regular file",
                    path.display()
                ),
            ));
        }
        Ok(file)
    }

    /// Reads the regular file at `path`, as [`SecretsTree::read`] does,
    /// and returns its mode and owner from the `fstat` of the same
    /// descriptor.
    ///
    /// # Errors
    /// Returns an error under the same conditions as
    /// [`SecretsTree::read`].
    pub fn read_with_meta(&self, path: &Path) -> std::io::Result<(Vec<u8>, FileMeta)> {
        use std::io::Read as _;

        let anchor_fd = self.require_rooted(path)?;
        let names = self.relative_io(path)?;
        let (leaf, _, dir) = self.parent_of(anchor_fd, path, &names)?;
        let mut file = open_file_nofollow(&dir, leaf).map_err(|err| refused_file_io(err, path))?;
        let meta = file
            .metadata()
            .map_err(|err| io_context(&err, &format!("Failed to stat {}", path.display())))?;
        if !meta.is_file() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Refusing to read {}: it is not a regular file",
                    path.display()
                ),
            ));
        }
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)
            .map_err(|err| io_context(&err, &format!("Failed to read {}", path.display())))?;
        Ok((
            contents,
            FileMeta {
                mode: meta.mode() & 0o7777,
                uid: meta.uid(),
                gid: meta.gid(),
            },
        ))
    }

    /// Runs `op` against this handle on a blocking thread.
    ///
    /// # Errors
    /// Returns whatever `op` returns, or an error if the task panicked.
    pub async fn run<T, F>(self: &Arc<Self>, op: F) -> Result<T>
    where
        F: FnOnce(&SecretsTree) -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let tree = Arc::clone(self);
        tokio::task::spawn_blocking(move || op(&tree))
            .await
            .context("Secrets tree task panicked")?
    }

    /// [`SecretsTree::ensure_dir`] on a blocking thread.
    ///
    /// # Errors
    /// Returns an error under the same conditions as
    /// [`SecretsTree::ensure_dir`].
    pub async fn ensure_dir_async(self: &Arc<Self>, path: &Path) -> Result<()> {
        let path = path.to_path_buf();
        self.run(move |tree| tree.ensure_dir(&path)).await
    }

    /// [`SecretsTree::publish`] on a blocking thread.
    ///
    /// # Errors
    /// Returns an error under the same conditions as
    /// [`SecretsTree::publish`].
    pub async fn publish_async(
        self: &Arc<Self>,
        dest: Destination<'_>,
        contents: &[u8],
        mode: StagedMode,
        owner: RootedOwner,
        durability: StagedDurability,
    ) -> Result<()> {
        let (path, symlink) = dest.to_owned_parts();
        let payload = contents.to_vec();
        self.run(move |tree| {
            tree.publish(
                Destination {
                    path: &path,
                    symlink,
                },
                &payload,
                mode,
                owner,
                durability,
            )
        })
        .await
    }

    /// The names `path` holds below the anchor, outermost first; empty
    /// for the anchor itself.
    ///
    /// `Path::components` drops every `.` after the first component, so
    /// the remainder's own spelling is checked as well: a literal `.`
    /// anywhere below the anchor is refused, `secrets/.` included, even
    /// though it names the same directory. Empty segments from repeated
    /// or trailing separators are not components and stay accepted.
    fn relative<'p>(&self, path: &'p Path) -> Result<Vec<&'p OsStr>> {
        let rest = path.strip_prefix(&self.anchor).map_err(|_| {
            anyhow::anyhow!(
                "{} is not below the secrets directory {}",
                path.display(),
                self.anchor.display()
            )
        })?;
        let not_plain = || {
            anyhow::anyhow!(
                "{} must name an entry below the secrets directory {} by plain names alone",
                path.display(),
                self.anchor.display()
            )
        };
        let names = rest
            .components()
            .map(|component| match component {
                Component::Normal(name) => Ok(name),
                _ => Err(not_plain()),
            })
            .collect::<Result<Vec<_>>>()?;
        let spelled = spelled_remainder(
            self.anchor.as_os_str().as_bytes(),
            path.as_os_str().as_bytes(),
            self.anchor.components().count(),
        )
        .ok_or_else(not_plain)?;
        if spelled
            .split(|&byte| byte == b'/')
            .any(|segment| segment == b".")
        {
            return Err(not_plain());
        }
        Ok(names)
    }

    /// Creates `path` as a directory at mode `0700`, every missing level
    /// on the way included, under the owner of the nearest level that
    /// already existed.
    ///
    /// A level that already existed keeps its owner, and keeps its mode
    /// unless it is `path` itself, which ends `0700`. For the anchor
    /// itself the mode is set and no owner is changed.
    ///
    /// Path-based: [`super::ensure_shared_secrets_dir_blocking`], or for
    /// the anchor [`super::ensure_secrets_dir`]'s blocking half. Rooted:
    /// each level is opened from its parent's descriptor with
    /// `O_NOFOLLOW`, created with `mkdirat` when it is missing, and given
    /// its mode and owner through its own descriptor. A symbolic link at
    /// any level fails the call, and nothing is created, chowned or
    /// chmodded through it.
    ///
    /// # Errors
    /// Returns an error if `path` is not below the anchor or names a level
    /// by anything but plain names, a level cannot be opened as a
    /// directory without following a link, cannot be created, or cannot
    /// be given its mode or owner.
    pub fn ensure_dir(&self, path: &Path) -> Result<()> {
        let names = self.relative(path)?;
        let Some(anchor_fd) = self.rooted_fd() else {
            return if names.is_empty() {
                ensure_secrets_dir_blocking(path)
            } else {
                ensure_shared_secrets_dir_blocking(path)
            };
        };
        let mut current = dup_dir(anchor_fd, &self.anchor)?;
        if names.is_empty() {
            return set_mode(&current, SECRETS_DIR_MODE, &self.anchor);
        }
        let mut owner = owner_of(&current, &self.anchor)?;
        let mut level = self.anchor.clone();
        let last = names.len() - 1;
        for (index, name) in names.iter().enumerate() {
            level.push(name);
            let (dir, created) = match open_dir_nofollow(&current, name) {
                Ok(dir) => (dir, false),
                Err(Errno::NOENT) => {
                    let created = match rustix::fs::mkdirat(&current, *name, Mode::RWXU) {
                        Ok(()) => true,
                        // A racing create: the level is now an existing
                        // one, and is opened as such.
                        Err(Errno::EXIST) => false,
                        Err(err) => {
                            return Err(err).with_context(|| {
                                format!("Failed to create secrets dir {}", level.display())
                            });
                        }
                    };
                    let dir = open_dir_nofollow(&current, name)
                        .map_err(|err| refused_level(err, &level))?;
                    (dir, created)
                }
                Err(err) => return Err(refused_level(err, &level)),
            };
            self.check_root_by_policy(index, name, &dir, &level)?;
            if created {
                set_mode(&dir, SECRETS_DIR_MODE, &level)?;
                let staged = owner_of(&dir, &level)?;
                if staged != owner {
                    std::os::unix::fs::fchown(&dir, Some(owner.0), Some(owner.1))
                        .with_context(|| created_level_owner_context(&level, owner))?;
                }
            } else {
                owner = owner_of(&dir, &level)?;
                if index == last {
                    set_mode(&dir, SECRETS_DIR_MODE, &level)?;
                }
            }
            current = dir;
        }
        Ok(())
    }

    /// Publishes `contents` at `dest` by staging a temporary in the same
    /// directory and renaming it over the destination.
    ///
    /// Path-based: exactly [`publish_staged_blocking`], with `dest`'s
    /// symlink decision answered first as the `atomic_*` wrappers answer
    /// it. Rooted: the destination's directory is reached by the walk
    /// [`SecretsTree::ensure_dir`] uses, creating nothing; the leaf is
    /// read once without following it; the temporary is created in the
    /// directory's descriptor with `O_EXCL | O_NOFOLLOW`, written,
    /// chowned, chmodded and flushed through its own descriptor, and
    /// renamed with `renameat` between that same directory descriptor.
    /// A symbolic link at the leaf is refused under
    /// [`Destination::operator_named`], since following it is what that
    /// constructor asks for and root must not, and replaced under
    /// [`Destination::bootroot_owned`], where it counts as no destination
    /// at all for mode and owner. A failure once the temporary exists
    /// removes it.
    ///
    /// # Errors
    /// Returns an error if `dest` is not below the anchor or names a level
    /// by anything but plain names, a directory level cannot be opened
    /// without following a link, the leaf is a link an operator-named
    /// destination would follow, or the temporary cannot be created,
    /// written, chowned, chmodded, flushed or renamed.
    pub fn publish(
        &self,
        dest: Destination<'_>,
        contents: &[u8],
        mode: StagedMode,
        owner: RootedOwner,
        durability: StagedDurability,
    ) -> Result<()> {
        let names = self.relative(dest.path)?;
        let Some(anchor_fd) = self.rooted_fd() else {
            return publish_staged_blocking(
                &dest.publish_path()?,
                contents,
                mode,
                owner.into(),
                durability,
            );
        };
        let path = dest.path;
        let (leaf, dirs) = names.split_last().ok_or_else(|| {
            anyhow::anyhow!(
                "{} names the secrets directory itself, not a file in it",
                path.display()
            )
        })?;
        let dir_path = self.level_path(dirs);
        let dir = self.walk(anchor_fd, dirs)?;
        let found = match rustix::fs::statat(&dir, *leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => classify_leaf(&stat),
            // Unreadable is absent, as the path-based publish treats a
            // destination it cannot stat: the publish reports the real
            // failure, and a guess here would only replace it.
            Err(_) => Leaf::Absent,
        };
        if matches!(found, Leaf::Symlink) && matches!(dest.symlink, SymlinkPolicy::Resolve) {
            anyhow::bail!(
                "Refusing to publish {}: it is a symbolic link, and a root process does not \
                 follow one under a secrets directory another account owns",
                path.display()
            );
        }
        let existing_mode = match found {
            Leaf::Regular { mode, .. } => Some(mode),
            Leaf::Absent | Leaf::Symlink | Leaf::Other => None,
        };
        let final_mode = mode.resolve_existing(existing_mode);
        // `STAGED_OPEN_MODE` when the umask decides, `STAGED_CREATE_MODE`
        // otherwise — the choice `publish_staged_blocking` makes.
        let create_mode = if final_mode.is_some() {
            Mode::RUSR | Mode::WUSR
        } else {
            Mode::RUSR | Mode::WUSR | Mode::RGRP | Mode::WGRP | Mode::ROTH | Mode::WOTH
        };
        let mut staged = StagedTemp::create(&dir, &dir_path, create_mode)?;
        staged
            .file
            .write_all(contents)
            .with_context(|| format!("Failed to write temp file for {}", path.display()))?;
        chown_staged(&staged.file, &dir, &dir_path, path, owner, &found)?;
        if let Some(final_mode) = final_mode {
            staged
                .file
                .set_permissions(std::fs::Permissions::from_mode(final_mode))
                .with_context(|| {
                    format!(
                        "Failed to set mode {final_mode:o} on temp file for {}",
                        path.display()
                    )
                })?;
        }
        staged
            .file
            .sync_all()
            .with_context(|| format!("Failed to fsync temp file for {}", path.display()))?;
        let replaced_link = if matches!(found, Leaf::Symlink) {
            rustix::fs::readlinkat(&dir, *leaf, Vec::new())
                .ok()
                .map(|target| PathBuf::from(OsStr::from_bytes(target.as_bytes())))
        } else {
            None
        };
        rustix::fs::renameat(&dir, staged.name.as_os_str(), &dir, *leaf).map_err(|err| {
            anyhow::anyhow!("Failed to rename temp file to {}: {err}", path.display())
        })?;
        staged.published();
        if let Some(link_target) = replaced_link {
            tracing::warn!(
                "Replaced the symlink at {} with the published file; it pointed at {}",
                path.display(),
                link_target.display()
            );
        }
        match durability {
            StagedDurability::FlushDirectory => rustix::fs::fsync(&dir)
                .with_context(|| format!("Failed to fsync directory {}", dir_path.display()))?,
            StagedDurability::RenameOnly => {}
        }
        Ok(())
    }

    /// Sets the mode of the regular file at `path`.
    ///
    /// Path-based: `std::fs::set_permissions`, which follows a link.
    /// Rooted: the file's directory is reached by the walk, the file is
    /// opened with `O_NOFOLLOW`, confirmed regular by `fstat` and
    /// chmodded through its descriptor; a link or anything else at the
    /// leaf is an error.
    ///
    /// # Errors
    /// Returns an error if `path` is not below the anchor or names a level
    /// by anything but plain names, a directory level or the leaf cannot
    /// be opened without following a link, the leaf is not a regular
    /// file, or the mode cannot be set.
    pub fn set_file_mode(&self, path: &Path, mode: u32) -> Result<()> {
        let names = self.relative(path)?;
        let Some(anchor_fd) = self.rooted_fd() else {
            return std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
                .with_context(|| format!("Failed to set permissions on {}", path.display()));
        };
        let (leaf, dirs) = names.split_last().ok_or_else(|| {
            anyhow::anyhow!(
                "{} names the secrets directory itself, not a file in it",
                path.display()
            )
        })?;
        let dir = self.walk(anchor_fd, dirs)?;
        let file = open_file_nofollow(&dir, leaf).map_err(|err| refused_file(err, path))?;
        let meta = file
            .metadata()
            .with_context(|| format!("Failed to stat {}", path.display()))?;
        if !meta.is_file() {
            anyhow::bail!(
                "Refusing to set the mode of {}: it is not a regular file",
                path.display()
            );
        }
        set_mode(&file, mode, path)
    }

    /// Sets every directory below the anchor to `0700` and every regular
    /// file to `0600`, leaving owners and the anchor's own mode alone.
    ///
    /// Path-based: the walk `init` has always run, by path, following a
    /// link to a directory or a file. Rooted: each directory is listed
    /// from its own descriptor, each entry is read without following it,
    /// links and anything that is neither a directory nor a regular file
    /// are skipped, and each directory or file is opened with
    /// `O_NOFOLLOW` and chmodded through its descriptor. An entry that
    /// vanished before its open is skipped; a link swapped in after the
    /// read is an error.
    ///
    /// # Errors
    /// Returns an error if a directory cannot be listed, an entry cannot
    /// be read or opened without following a link, or a mode cannot be
    /// set.
    pub fn normalize_modes(&self) -> Result<()> {
        let Some(anchor_fd) = self.rooted_fd() else {
            return normalize_modes_by_path(&self.anchor);
        };
        let anchor = dup_dir(anchor_fd, &self.anchor)?;
        normalize_modes_rooted(&anchor, &self.anchor, Some(self))
    }

    /// The path of the directory `names` reaches below the anchor.
    fn level_path(&self, names: &[&OsStr]) -> PathBuf {
        let mut path = self.anchor.clone();
        path.extend(names);
        path
    }

    /// Opens each of `names` below the anchor in turn, without following
    /// a link at any of them, and returns the last; the anchor itself
    /// when `names` is empty. Creates nothing.
    fn walk(&self, anchor_fd: &OwnedFd, names: &[&OsStr]) -> Result<File> {
        Ok(self.walk_io(anchor_fd, names)?)
    }
}

/// A staged temporary a rooted publish created in a directory it holds
/// open, removed again unless it was renamed into place.
struct StagedTemp<'d> {
    dir: &'d File,
    name: OsString,
    file: File,
    published: bool,
}

impl<'d> StagedTemp<'d> {
    fn create(dir: &'d File, dir_path: &Path, create_mode: Mode) -> Result<Self> {
        let pid = std::process::id();
        for _ in 0..MAX_STAGED_NAME_ATTEMPTS {
            let serial = STAGED_NAME_COUNTER.fetch_add(1, Ordering::Relaxed);
            let name = OsString::from(format!("{STAGED_NAME_PREFIX}-{pid}-{serial}"));
            match rustix::fs::openat(
                dir,
                name.as_os_str(),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                create_mode,
            ) {
                Ok(fd) => {
                    return Ok(Self {
                        dir,
                        name,
                        file: File::from(fd),
                        published: false,
                    });
                }
                Err(Errno::EXIST) => {}
                Err(err) => {
                    return Err(err).with_context(|| {
                        format!("Failed to create temp file in {}", dir_path.display())
                    });
                }
            }
        }
        anyhow::bail!(
            "Failed to create temp file in {}: all {MAX_STAGED_NAME_ATTEMPTS} names tried \
             already existed",
            dir_path.display()
        )
    }

    /// Records that the temporary now holds the destination's name, so
    /// dropping it removes nothing.
    fn published(&mut self) {
        self.published = true;
    }
}

impl Drop for StagedTemp<'_> {
    fn drop(&mut self) {
        if !self.published {
            // Best effort: the publish is already failing, and its own
            // error is the one to report.
            let _ = rustix::fs::unlinkat(self.dir, self.name.as_os_str(), AtFlags::empty());
        }
    }
}

/// Gives a rooted publish's staged file the owner `owner` asks for,
/// through its descriptor, skipping a chown that would change nothing.
fn chown_staged(
    staged: &File,
    dir: &File,
    dir_path: &Path,
    path: &Path,
    owner: RootedOwner,
    found: &Leaf,
) -> Result<()> {
    let wanted = match owner {
        RootedOwner::ContainingDir => Some(owner_of(dir, dir_path)?),
        RootedOwner::Destination => match *found {
            Leaf::Regular { uid, gid, .. } => Some((uid, gid)),
            Leaf::Absent | Leaf::Symlink | Leaf::Other => None,
        },
        RootedOwner::Fixed(fixed) => {
            // Unconditional, as the path-based `Fixed` arm: the call is
            // the authority check, and a process that cannot establish
            // this owner publishes nothing.
            return std::os::unix::fs::fchown(staged, Some(fixed.uid), Some(fixed.gid))
                .with_context(|| chown_fixed_context(fixed, path));
        }
    };
    let Some((uid, gid)) = wanted else {
        return Ok(());
    };
    let current = staged
        .metadata()
        .map(|meta| (meta.uid(), meta.gid()))
        .with_context(|| format!("Failed to stat temp file for {}", path.display()))?;
    if current == (uid, gid) {
        return Ok(());
    }
    std::os::unix::fs::fchown(staged, Some(uid), Some(gid)).with_context(|| match owner {
        RootedOwner::ContainingDir => chown_containing_dir_context(uid, gid, dir_path, path),
        RootedOwner::Destination | RootedOwner::Fixed(_) => chown_preserve_context(uid, gid, path),
    })
}

/// Lists and fixes one directory of a rooted [`SecretsTree::normalize_modes`].
///
/// `anchor_of` is the handle when `dir` is the anchor itself, so the
/// root-by-policy check runs on the levels directly below it.
fn normalize_modes_rooted(
    dir: &File,
    dir_path: &Path,
    anchor_of: Option<&SecretsTree>,
) -> Result<()> {
    let entries = rustix::fs::Dir::read_from(dir)
        .with_context(|| format!("Failed to read secrets dir {}", dir_path.display()))?;
    for entry in entries {
        let entry =
            entry.with_context(|| format!("Failed to read secrets dir {}", dir_path.display()))?;
        let raw = entry.file_name().to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        let name = OsStr::from_bytes(raw);
        let path = dir_path.join(name);
        let stat = match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("Failed to stat {}", path.display()));
            }
        };
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => {
                let child = match open_dir_nofollow(dir, name) {
                    Ok(child) => child,
                    Err(Errno::NOENT) => continue,
                    Err(err) => return Err(refused_level(err, &path)),
                };
                if let Some(tree) = anchor_of {
                    tree.check_root_by_policy(0, name, &child, &path)?;
                }
                set_mode(&child, SECRETS_DIR_MODE, &path)?;
                normalize_modes_rooted(&child, &path, None)?;
            }
            FileType::RegularFile => {
                let file = match open_file_nofollow(dir, name) {
                    Ok(file) => file,
                    Err(Errno::NOENT) => continue,
                    Err(err) => return Err(refused_file(err, &path)),
                };
                let meta = file
                    .metadata()
                    .with_context(|| format!("Failed to stat {}", path.display()))?;
                if !meta.is_file() {
                    anyhow::bail!(
                        "Refusing to set the mode of {}: it is no longer a regular file",
                        path.display()
                    );
                }
                set_mode(&file, KEY_FILE_MODE, &path)?;
            }
            // Links are never followed, and nothing else has a mode
            // policy here.
            _ => {}
        }
    }
    Ok(())
}

/// The path-based [`SecretsTree::normalize_modes`]: the walk `init` ran
/// before the handle existed, moved here from the `bootroot` binary.
fn normalize_modes_by_path(dir: &Path) -> Result<()> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read secrets dir {}", dir.display()))?;
    for entry in entries {
        let path = entry
            .with_context(|| format!("Failed to read secrets dir {}", dir.display()))?
            .path();
        if path.is_dir() {
            ensure_secrets_dir_blocking(&path)?;
            normalize_modes_by_path(&path)?;
        } else if path.is_file() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(KEY_FILE_MODE))
                .context("Failed to set key file permissions")?;
        }
    }
    Ok(())
}

/// The bytes of `path` below the anchor, as `path` spells them, for a
/// `path` already known to start with the anchor's
/// `anchor_components` components.
///
/// A `path` that repeats the anchor's own bytes at a component boundary
/// is cut there, so an anchor spelled with a `.` of its own (`secrets/.`)
/// keeps accepting the paths built by joining names onto it. Any other
/// spelling is cut after the same number of components as the anchor
/// has, so a prefix that differs from the anchor only in separators or
/// `.`s still matches as `Path::strip_prefix` matches it. `None` only if
/// `path` has fewer components than that, which the caller has ruled
/// out.
fn spelled_remainder<'p>(
    anchor: &[u8],
    path: &'p [u8],
    anchor_components: usize,
) -> Option<&'p [u8]> {
    if let Some(rest) = path.strip_prefix(anchor)
        && (anchor.is_empty()
            || anchor.ends_with(b"/")
            || rest.is_empty()
            || rest.starts_with(b"/"))
    {
        return Some(rest);
    }
    path.get(offset_after_components(path, anchor_components)?..)
}

/// The byte offset in `path` just past its first `count` components,
/// counted as `Path::components` counts them on Unix: a leading `/` is
/// the root, a leading `.` segment with no root before it is the one
/// `.` it keeps, and every later empty or `.` segment is skipped.
/// `None` when `path` has fewer than `count` components.
fn offset_after_components(path: &[u8], count: usize) -> Option<usize> {
    let mut seen = 0;
    let mut pos = 0;
    if count > 0 && (path.first() == Some(&b'/') || path == b"." || path.starts_with(b"./")) {
        seen = 1;
        pos = 1;
    }
    while seen < count {
        let rest = path.get(pos..)?;
        let start = pos + rest.iter().take_while(|&&byte| byte == b'/').count();
        let segment = path.get(start..)?;
        if segment.is_empty() {
            return None;
        }
        let len = segment
            .iter()
            .position(|&byte| byte == b'/')
            .unwrap_or(segment.len());
        if segment.get(..len)? != b"." {
            seen += 1;
        }
        pos = start + len;
    }
    Some(pos)
}

/// A second descriptor on the anchor, so a walk can hold its levels as
/// owned files whatever depth it stops at.
fn dup_dir(fd: &OwnedFd, path: &Path) -> Result<File> {
    fd.try_clone()
        .map(File::from)
        .with_context(|| format!("Failed to duplicate the descriptor of {}", path.display()))
}

/// Opens `name` in `dir` as a directory, without following a link.
///
/// A link at `name` fails the open — `ENOTDIR` on Linux, `ELOOP` on some
/// other systems — and no single errno is matched for it.
fn open_dir_nofollow(dir: &File, name: &OsStr) -> rustix::io::Result<File> {
    rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
}

/// Opens `name` in `dir` for its mode, without following a link and
/// without blocking on a FIFO swapped in for it.
fn open_file_nofollow(dir: &File, name: &OsStr) -> rustix::io::Result<File> {
    rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
}

fn owner_of(file: &File, path: &Path) -> Result<(u32, u32)> {
    file.metadata()
        .map(|meta| (meta.uid(), meta.gid()))
        .with_context(|| format!("Failed to stat {}", path.display()))
}

fn set_mode(file: &File, mode: u32, path: &Path) -> Result<()> {
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .with_context(|| format!("Failed to set mode {mode:o} on {}", path.display()))
}

fn classify_leaf(stat: &Stat) -> Leaf {
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Symlink => Leaf::Symlink,
        FileType::RegularFile => Leaf::Regular {
            mode: permission_bits(stat),
            uid: stat.st_uid,
            gid: stat.st_gid,
        },
        _ => Leaf::Other,
    }
}

/// The permission bits of `stat`, as [`StagedMode`] preserves them.
// `st_mode` is a `u32` on Linux and a `u16` on macOS, so the widening
// is a real conversion on one platform and an identity on the other.
#[cfg_attr(target_os = "linux", allow(clippy::useless_conversion))]
fn permission_bits(stat: &Stat) -> u32 {
    u32::from(stat.st_mode) & 0o7777
}

/// The error a rooted walk reports for a directory level it could not
/// open: a link there, swapped in or not, is the case it exists for.
fn refused_level(err: Errno, path: &Path) -> anyhow::Error {
    anyhow::Error::new(err).context(format!(
        "Failed to open secrets dir {} as a directory without following a symbolic link",
        path.display()
    ))
}

fn refused_file(err: Errno, path: &Path) -> anyhow::Error {
    anyhow::Error::new(err).context(format!(
        "Failed to open {} as a regular file without following a symbolic link",
        path.display()
    ))
}

/// Removes every entry of the open directory `dir`, descending into each
/// subdirectory through its own descriptor and unlinking everything
/// else, links included, without following any of them.
fn clear_dir_rooted(dir: &File, dir_path: &Path) -> std::io::Result<()> {
    for name in list_dir(dir, dir_path)? {
        let path = dir_path.join(&name);
        let stat = match rustix::fs::statat(dir, name.as_os_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => continue,
            Err(err) => {
                return Err(errno_context(
                    err,
                    &format!("Failed to stat {}", path.display()),
                ));
            }
        };
        if FileType::from_raw_mode(stat.st_mode) == FileType::Directory {
            match open_dir_nofollow(dir, name.as_os_str()) {
                Ok(child) => {
                    clear_dir_rooted(&child, &path)?;
                    drop(child);
                    match rustix::fs::unlinkat(dir, name.as_os_str(), AtFlags::REMOVEDIR) {
                        Ok(()) | Err(Errno::NOENT) => {}
                        Err(err) => {
                            return Err(errno_context(
                                err,
                                &format!("Failed to remove {}", path.display()),
                            ));
                        }
                    }
                    continue;
                }
                Err(Errno::NOENT) => continue,
                // Swapped for something that is not a directory since
                // the `statat`: unlinked below like any other entry.
                Err(_) => {}
            }
        }
        match rustix::fs::unlinkat(dir, name.as_os_str(), AtFlags::empty()) {
            Ok(()) | Err(Errno::NOENT) => {}
            Err(err) => {
                return Err(errno_context(
                    err,
                    &format!("Failed to remove {}", path.display()),
                ));
            }
        }
    }
    Ok(())
}

/// The names in the open directory `dir`, `.` and `..` left out.
fn list_dir(dir: &File, dir_path: &Path) -> std::io::Result<Vec<OsString>> {
    let entries = rustix::fs::Dir::read_from(dir).map_err(|err| {
        errno_context(
            err,
            &format!("Failed to read secrets dir {}", dir_path.display()),
        )
    })?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|err| {
            errno_context(
                err,
                &format!("Failed to read secrets dir {}", dir_path.display()),
            )
        })?;
        let raw = entry.file_name().to_bytes();
        if raw == b"." || raw == b".." {
            continue;
        }
        names.push(OsStr::from_bytes(raw).to_os_string());
    }
    Ok(names)
}

fn entry_kind_of(stat: &Stat) -> EntryKind {
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::Directory => EntryKind::Dir,
        FileType::RegularFile => EntryKind::File,
        FileType::Symlink => EntryKind::Symlink,
        _ => EntryKind::Other,
    }
}

/// `err` with `context` prepended to its message, keeping its kind so a
/// caller can still match `NotFound`.
fn io_context(err: &std::io::Error, context: &str) -> std::io::Error {
    std::io::Error::new(err.kind(), format!("{context}: {err}"))
}

fn errno_context(err: Errno, context: &str) -> std::io::Error {
    io_context(&std::io::Error::from(err), context)
}

/// [`refused_level`] as an I/O error that keeps the errno's kind.
fn refused_level_io(err: Errno, path: &Path) -> std::io::Error {
    errno_context(
        err,
        &format!(
            "Failed to open secrets dir {} as a directory without following a symbolic link",
            path.display()
        ),
    )
}

fn refused_file_io(err: Errno, path: &Path) -> std::io::Error {
    errno_context(
        err,
        &format!(
            "Failed to open {} as a regular file without following a symbolic link",
            path.display()
        ),
    )
}

fn set_mode_io(file: &File, mode: u32, path: &Path) -> std::io::Result<()> {
    file.set_permissions(std::fs::Permissions::from_mode(mode))
        .map_err(|err| {
            io_context(
                &err,
                &format!("Failed to set mode {mode:o} on {}", path.display()),
            )
        })
}

fn dir_gid(dir: &File, path: &Path) -> std::io::Result<u32> {
    dir.metadata()
        .map(|meta| meta.gid())
        .map_err(|err| io_context(&err, &format!("Failed to stat {}", path.display())))
}

/// `mode` as the platform's `mode_t`, which is a `u16` on macOS.
///
/// Only the permission bits are kept, so the conversion cannot fail.
fn mode_t_of(mode: u32) -> rustix::fs::RawMode {
    rustix::fs::RawMode::try_from(mode & 0o7777)
        .expect("permission bits masked with 0o7777 fit every platform's mode_t")
}

fn created_level_owner_context(path: &Path, owner: (u32, u32)) -> String {
    format!(
        "{} must be owned by the secrets tree (uid {}, gid {}) \u{2014} the uid the step-ca \
         container and the OpenBao Agent sidecars are launched as, and a directory they \
         cannot traverse hides every file inside it",
        path.display(),
        owner.0,
        owner.1
    )
}

#[cfg(test)]
mod tests;
