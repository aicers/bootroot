//! The audit store's loopback-backed reserve: what `bootroot init`
//! derives from the configuration, what it reads off the host, what it
//! renders for the operator, and what it verifies afterwards.
//!
//! The reserve turns `[registrar] audit_store_reserve_bytes` from a
//! recorded number into a ceiling the kernel enforces. A fully
//! allocated image sits beside the store, carries an `ext4` filesystem,
//! and is mounted at `audit_store_dir` through a generated `.mount`
//! unit; both writers then hit `ENOSPC` on the reserve instead of
//! filling the host's root filesystem.
//!
//! # The three phases
//!
//! **Phase 1** derives, evaluates, preflights and renders. It is
//! bootroot's, and it performs no host surgery: no `mkfs`, no mount, no
//! `systemctl`, no write under `/etc/systemd/system`, no `chown` or
//! `chmod` on the image or a subdirectory. The one filesystem object
//! the install path creates is `audit_store_dir` itself, which a mount
//! needs somewhere to go — and which `create_layout` already created on
//! this path before this module existed.
//!
//! **Phase 2** is every step that changes the host, and the operator
//! performs all of it. This module renders those steps as exact
//! commands and runs none of them. [`Phase2Step`] keeps them separately
//! addressable rather than pre-joined, so a later caller can withhold
//! one and emit the rest unchanged.
//!
//! **Phase 3** verifies and reports, reading only metadata.
//!
//! # Why everything reads through [`ReserveProbe`]
//!
//! Every `stat`, `statvfs`, directory listing and `/proc` or `/sys`
//! read this surface makes goes through the trait rather than through
//! `std::fs` directly. The decisions above it — which image state was
//! found, which mount entry is the active one, whether a product
//! overflowed — are then reachable from a test that is not root and
//! owns no loop device, which is the only way the failure modes worth
//! catching get asserted at all.

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::migration::{self, MigrationPresence};
use crate::i18n::Messages;

/// The unit `st_blocks` counts in. Fixed at 512 bytes by POSIX
/// whatever the filesystem's own block size is, so it is a constant of
/// the interface rather than of any one filesystem.
const ST_BLOCKS_UNIT_BYTES: u64 = 512;

/// The fixed floor on `audit_store_reserve_bytes` in `filesystem`
/// mode.
///
/// Keeps the rendered `mkfs.ext4` clear of the sizes at which `mke2fs`
/// refuses outright or quietly omits the journal. It is not an
/// adequacy figure: an image this size holds a working filesystem and
/// says nothing about whether the deployment's records fit in it.
const MIN_RESERVE_FLOOR_BYTES: u64 = 16 * 1024 * 1024;

/// The ceiling `validate_registrar_settings` already puts on
/// `audit_store_reserve_bytes`, which is what decides whether a
/// computed minimum is reachable at all.
const RESERVE_CAP_BYTES: u64 = i64::MAX.unsigned_abs();

/// Suffix appended to `audit_store_dir` to derive the image path.
const IMAGE_SUFFIX: &str = ".img";

/// Mode the loopback image is created at, and held to afterwards. A
/// principal that can rewrite the image can rewrite the audit
/// filesystem underneath both writers.
const IMAGE_FILE_MODE: u32 = 0o600;

/// Mode the store's two subdirectories are held to on the mounted
/// filesystem, matching the store directory contract.
const SUBDIR_MODE: u32 = 0o700;

/// Mode the rendered artifacts are staged and installed at.
const ARTIFACT_FILE_MODE: u32 = 0o644;

/// The permission bits a mode comparison looks at. Wider than `0o777`
/// so a set-user-ID or sticky bit is a departure rather than something
/// the mask hides.
const MODE_MASK: u32 = 0o7777;

/// Suffix systemd forces on a mount unit's name.
const MOUNT_UNIT_SUFFIX: &str = ".mount";

/// Where the three artifacts are installed.
const SYSTEMD_UNIT_DIR: &str = "/etc/systemd/system";

/// The drop-in file name, shared by both ordering targets.
const DROP_IN_FILE_NAME: &str = "10-bootroot-audit-store.conf";

/// The drop-in directory for the `OpenBao` container's ordering
/// target. The container is not started by a bootroot unit — the
/// Compose services carry `restart: always`, so on boot the Docker
/// daemon brings it back.
const DOCKER_DROP_IN_DIR: &str = "docker.service.d";

/// The shipped unit supervising the daemon that writes the verb
/// records, named by the rendered stop command and by the drop-in
/// directory below.
const REGISTRAR_UNIT_NAME: &str = "bootroot-registrar.service";

/// The drop-in directory for the daemon that writes the verb records.
/// The endpoint is a config-gated feature inside `bootroot-agent`, so
/// the ordering reaches it through the shipped unit rather than
/// through one of its own.
const REGISTRAR_DROP_IN_DIR: &str = "bootroot-registrar.service.d";

/// Subdirectory of the compose directory the artifacts are staged in.
/// Beside the rendered Compose override, and never inside
/// `audit_store_dir`, which the mount would hide.
const ARTIFACT_STAGING_SUBDIR: &str = "audit-store";

/// The filesystem type the reserve is made with and verified as.
const RESERVE_FS_TYPE: &str = "ext4";

/// `mkfs.ext4 -E` options, and every one of them keeps the image's
/// blocks where the preallocation put them.
///
/// `nodiscard` stops `mke2fs` from discarding the device's blocks
/// while it creates the filesystem; on a loop device that discard is
/// a hole punch through to the backing file, and the image would be
/// sparse before it was ever mounted.
///
/// `lazy_itable_init=0` closes the same hole one step later. Left at
/// its default, `mke2fs` leaves the inode tables uninitialised and the
/// kernel's `ext4lazyinit` thread zeroes them in the background a few
/// seconds *after* the mount comes up — through `sb_issue_zeroout`,
/// which the loop driver serves by punching the backing file rather
/// than by writing zeros to it. The reserve then quietly gives its
/// inode tables back to the filesystem underneath it: a little over a
/// mebibyte on the 16 MiB floor, and tens of mebibytes on the shipped
/// 2 GiB default, none of which the kernel is holding either writer to
/// any more. Writing the tables at `mkfs` time costs one pass over
/// them once and makes the allocation final.
const MKFS_EXTENDED_OPTIONS: &str = "nodiscard,lazy_itable_init=0";

/// The prefix every loop device node carries.
const LOOP_DEVICE_PREFIX: &str = "/dev/loop";

/// The block size the portable `dd` allocation fallback writes at.
///
/// One mebibyte keeps the fallback practical without relying on a
/// non-portable `dd` suffix such as `1M`.
const DD_ALLOCATION_BLOCK_BYTES: u64 = 1024 * 1024;

/// What the kernel appends to a loop device's backing file when the
/// file has been unlinked.
const DELETED_SUFFIX: &str = " (deleted)";

/// The mount table this surface reads. `/proc/self/mounts` rather than
/// `/etc/mtab`: the first is what the kernel says is mounted now.
const PROC_SELF_MOUNTS: &str = "/proc/self/mounts";

/// The other mount table, read by [`super::migration`] through the same
/// probe. Named here because [`HostProbe`] is what opens it.
const PROC_SELF_MOUNTINFO: &str = "/proc/self/mountinfo";

/// Subdirectory of the store holding the daemon's verb records.
const RECORDS_SUBDIR: &str = bootroot::registrar::audit_store::RECORDS_SUBDIR;

/// Subdirectory of the store `OpenBao`'s file audit device is bound
/// into.
const OPENBAO_SUBDIR: &str = bootroot::registrar::audit_store::OPENBAO_SUBDIR;

/// A `stat`'s file type, as far as this surface distinguishes them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FileKind {
    /// A regular file.
    Regular,
    /// A directory.
    Directory,
    /// A symbolic link, which `lstat` sees rather than follows.
    Symlink,
    /// Anything else — a device node, a FIFO, a socket.
    Other,
}

/// The `lstat` fields this surface reads, as one value a test can
/// build by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FileFacts {
    /// What kind of object the path is.
    pub(crate) kind: FileKind,
    /// `st_size`.
    pub(crate) size: u64,
    /// `st_blocks`, in [`ST_BLOCKS_UNIT_BYTES`] units.
    pub(crate) blocks: u64,
    /// `st_uid`.
    pub(crate) uid: u32,
    /// `st_mode`, permission bits included.
    pub(crate) mode: u32,
    /// `st_dev` — the device the object lives on.
    pub(crate) dev: u64,
    /// `st_ino`.
    pub(crate) ino: u64,
    /// `st_rdev` — the device a device node names.
    pub(crate) rdev: u64,
}

/// The `statvfs` fields the free-space preflight reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FsSpace {
    /// `f_bavail` — free blocks available to an unprivileged process,
    /// which is a **block count** and not a byte count.
    pub(crate) blocks_available: u64,
    /// `f_frsize` — the fragment size those blocks are counted in.
    pub(crate) fragment_size: u64,
}

/// Every host read this surface makes, behind one trait.
pub(crate) trait ReserveProbe {
    /// `lstat`s `path`. `Ok(None)` is **absent**; an `Err` is
    /// **unreadable**, and the two are never collapsed.
    ///
    /// # Errors
    ///
    /// Returns the underlying error for anything but `ENOENT`.
    fn lstat(&self, path: &Path) -> io::Result<Option<FileFacts>>;

    /// Lists `path`'s entries, one level deep. `Ok(None)` is absent.
    ///
    /// # Errors
    ///
    /// Returns the underlying error for anything but `ENOENT`.
    fn list_dir(&self, path: &Path) -> io::Result<Option<Vec<PathBuf>>>;

    /// Reads the filesystem `path` sits on.
    ///
    /// # Errors
    ///
    /// Returns the underlying error.
    fn space(&self, path: &Path) -> io::Result<FsSpace>;

    /// Reads `path`'s bytes. `Ok(None)` is absent.
    ///
    /// # Errors
    ///
    /// Returns the underlying error for anything but `ENOENT`.
    fn read_bytes(&self, path: &Path) -> io::Result<Option<Vec<u8>>>;

    /// Reads the kernel's mount table. An absent table reads as no
    /// entries at all.
    ///
    /// # Errors
    ///
    /// Returns the underlying error for anything but `ENOENT`.
    fn mounts(&self) -> io::Result<String>;

    /// Reads `/proc/self/mountinfo`. An absent table reads as no
    /// entries at all.
    ///
    /// A second mount table beside [`Self::mounts`] rather than a
    /// replacement for it: the two answer different questions. The
    /// reserve's own identity proof needs the source and filesystem
    /// type `/proc/self/mounts` carries in fixed positions, while the
    /// migration's "is anything mounted at or under this tree" needs
    /// every mount regardless of device, which only `mountinfo`'s
    /// per-mount records answer.
    ///
    /// # Errors
    ///
    /// Returns the underlying error for anything but `ENOENT`.
    fn mountinfo(&self) -> io::Result<String>;

    /// Reads `/sys/dev/block/<major>:<minor>/loop/backing_file`, keyed
    /// on the device numbers rather than on the source string.
    /// `Ok(None)` is absent, which is what a device that is not a loop
    /// device gives.
    ///
    /// # Errors
    ///
    /// Returns the underlying error for anything but `ENOENT`.
    fn loop_backing_file(&self, major: u64, minor: u64) -> io::Result<Option<String>>;
}

/// Widens one platform-sized C field to `u64`, falling back to
/// `fallback` where it does not fit.
///
/// These field types differ by platform — `f_bavail` is 32 bits on
/// some targets and 64 on others, and `major`/`minor` likewise — so a
/// bare `From` is redundant on one target and required on the next,
/// while `as` would be a silent truncation waiting for the platform
/// where the value does not fit. Generic over the field type so one
/// spelling is correct on both, and so neither target's build has a
/// conversion the other's compiler calls redundant.
fn widen_platform_field<T>(value: T, fallback: u64) -> u64
where
    u64: TryFrom<T>,
{
    u64::try_from(value).unwrap_or(fallback)
}

/// Narrows `value` to a platform-sized C type, or `None` where it does
/// not fit. Generic for the same reason as [`widen_platform_field`].
fn narrow_platform_field<T>(value: u64) -> Option<T>
where
    T: TryFrom<u64>,
{
    T::try_from(value).ok()
}

/// The real host.
pub(crate) struct HostProbe;

impl ReserveProbe for HostProbe {
    fn lstat(&self, path: &Path) -> io::Result<Option<FileFacts>> {
        use std::os::unix::fs::MetadataExt;

        let meta = match std::fs::symlink_metadata(path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let file_type = meta.file_type();
        let kind = if file_type.is_symlink() {
            FileKind::Symlink
        } else if file_type.is_dir() {
            FileKind::Directory
        } else if file_type.is_file() {
            FileKind::Regular
        } else {
            FileKind::Other
        };
        Ok(Some(FileFacts {
            kind,
            size: meta.size(),
            blocks: meta.blocks(),
            uid: meta.uid(),
            mode: meta.mode(),
            dev: meta.dev(),
            ino: meta.ino(),
            rdev: meta.rdev(),
        }))
    }

    fn list_dir(&self, path: &Path) -> io::Result<Option<Vec<PathBuf>>> {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        let mut collected = Vec::new();
        for entry in entries {
            collected.push(entry?.path());
        }
        Ok(Some(collected))
    }

    fn space(&self, path: &Path) -> io::Result<FsSpace> {
        let raw = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path holds a NUL byte"))?;
        let mut buffer = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `raw` is a NUL-terminated C string that outlives the
        // call, and `buffer` is a correctly sized, correctly aligned
        // allocation `statvfs` fills in full. Its contents are read
        // only after a zero return, which is when the kernel documents
        // them as initialised.
        let rc = unsafe { libc::statvfs(raw.as_ptr(), buffer.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call above returned zero, so the buffer is
        // initialised.
        let stat = unsafe { buffer.assume_init() };
        Ok(FsSpace {
            // Zero on a value that does not fit fails the preflight
            // closed rather than reporting room the host does not have.
            blocks_available: widen_platform_field(stat.f_bavail, 0),
            fragment_size: widen_platform_field(stat.f_frsize, 0),
        })
    }

    fn read_bytes(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn mounts(&self) -> io::Result<String> {
        match std::fs::read_to_string(PROC_SELF_MOUNTS) {
            Ok(text) => Ok(text),
            // A host with no `/proc` mounted has no mount table for any
            // read here to consult, and nothing this surface could
            // name as mounted at the store. An `EACCES` is a different
            // thing entirely and still reaches the caller, which
            // reports it as unreadable.
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(err) => Err(err),
        }
    }

    fn mountinfo(&self) -> io::Result<String> {
        match std::fs::read_to_string(PROC_SELF_MOUNTINFO) {
            Ok(text) => Ok(text),
            // Same reading as `mounts`: a host with no `/proc` mounted
            // has no mount table for any read here to consult. An
            // `EACCES` still reaches the caller.
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(String::new()),
            Err(err) => Err(err),
        }
    }

    fn loop_backing_file(&self, major: u64, minor: u64) -> io::Result<Option<String>> {
        let path = PathBuf::from(format!("/sys/dev/block/{major}:{minor}/loop/backing_file"));
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Some(text)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }
}

/// Everything phase 1 derives the reserve from.
pub(crate) struct ReserveInputs<'a> {
    /// `[registrar] audit_store_dir`.
    pub(crate) store_dir: &'a Path,
    /// The directory the compose file sits in, under which the three
    /// artifacts are staged.
    pub(crate) compose_dir: &'a Path,
    /// `[registrar] audit_store_reserve_bytes`.
    pub(crate) reserve_bytes: u64,
    /// `[registrar] audit_max_file_bytes`.
    pub(crate) max_file_bytes: u64,
    /// `[registrar] audit_max_retained_files`.
    pub(crate) max_retained_files: u32,
    /// The uid the image and `records/` must be owned by. Production
    /// passes 0; a test passes its own uid.
    pub(crate) expected_uid: u32,
    /// The command the run continues under, named by the re-run step.
    pub(crate) rerun_command: &'a str,
}

/// What phase 1 found the derived image path in.
///
/// The two hard errors — a path that is not a regular file, and a
/// regular file of the wrong size — are refusals rather than variants:
/// neither has a remedy this surface may render.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImageEvaluation {
    /// Nothing at the derived path.
    Absent,
    /// The whole image contract holds.
    Correct,
    /// A regular file of exactly the reserve, departing from the
    /// contract in one or more ways that have non-destructive
    /// remedies.
    Deviating {
        /// Bytes of the image's own length that are not allocated. Zero
        /// where the image is fully allocated.
        unallocated_bytes: u64,
        /// The uid found, where it is not the expected one.
        wrong_owner: Option<u32>,
        /// The permission bits found, where they are not
        /// [`IMAGE_FILE_MODE`].
        wrong_mode: Option<u32>,
    },
}

/// What `audit_store_dir` was found mounted from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MountEvaluation {
    /// No mount table entry names `audit_store_dir` at all.
    Absent,
    /// Something is mounted there, and it is not the reserve.
    Foreign {
        /// What is actually mounted, for the outcome to name.
        description: String,
        /// Whether more than one entry names the store.
        stacked: bool,
    },
    /// The derived image, on a loop device, proved rather than
    /// trusted.
    Reserve {
        /// Whether more than one entry names the store.
        stacked: bool,
    },
}

impl MountEvaluation {
    /// Whether any entry names the store, which is what decides
    /// whether the directory underneath can be read at all.
    fn any_entry(&self) -> bool {
        !matches!(self, Self::Absent)
    }
}

impl Phase1Facts {
    /// Whether anything at all is mounted at `audit_store_dir`.
    ///
    /// The store directory contract is asserted against the directory
    /// underneath the mount point; with a filesystem mounted there,
    /// what an `lstat` sees is that filesystem's root, whose mode
    /// `mkfs` chose.
    pub(crate) fn mount_present(&self) -> bool {
        self.mount.any_entry()
    }

    /// Whether the filesystem underneath an absent mount holds
    /// content the mount would hide.
    pub(crate) fn underlying_not_empty(&self) -> bool {
        self.underlying == UnderlyingState::NotEmpty
    }

    /// Whether a migration is in progress, which overrides every other
    /// verdict this surface can reach.
    pub(crate) fn migration_open(&self) -> bool {
        self.migration.holding
    }
}

/// What phase 1 found on the filesystem underneath an absent mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnderlyingState {
    /// A mount is present, so the directory beneath it cannot be named
    /// by any read available here.
    NotVisible,
    /// `audit_store_dir` is empty on the underlying filesystem, or is
    /// not there at all.
    Empty,
    /// `audit_store_dir` holds content the mount would hide.
    NotEmpty,
}

/// Everything phase 1 established, carried into the render and the
/// verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Phase1Facts {
    /// `audit_store_dir` as the artifacts, the rendered commands and
    /// the kernel's own mount table spell it — simplified by
    /// [`simplify_store_path`]. Everything downstream of phase 1 reads
    /// the store path from here rather than from the configured
    /// spelling.
    pub(crate) store_dir: PathBuf,
    /// [`Self::store_dir`] with `.img` appended.
    pub(crate) image_path: PathBuf,
    /// The escaped `.mount` unit name systemd forces.
    pub(crate) unit_name: String,
    /// What the derived image path holds.
    pub(crate) image: ImageEvaluation,
    /// What `audit_store_dir` is mounted from.
    pub(crate) mount: MountEvaluation,
    /// What is underneath an absent mount.
    pub(crate) underlying: UnderlyingState,
    /// What the two derived migration paths hold. Read **first**, so
    /// no other verdict is reached before it, and carried here so
    /// every later decision sees the same reading.
    pub(crate) migration: MigrationPresence,
}

/// One artifact phase 1 renders, staged beside the Compose override
/// and installed under `/etc/systemd/system` by the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RenderedArtifact {
    /// Where phase 1 writes it.
    pub(crate) staged_path: PathBuf,
    /// Where phase 3 requires it, byte-identical.
    pub(crate) installed_path: PathBuf,
    /// The rendered bytes.
    pub(crate) contents: Vec<u8>,
}

/// Which numbered phase-2 step a rendered unit is.
///
/// The kind is what makes the list composable: a later caller filters
/// on it to withhold exactly one step and re-emits the rest unchanged,
/// rather than performing string surgery on rendered text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase2StepKind {
    /// Stop both writers.
    StopWriters,
    /// The image commands for the state phase 1 found it in.
    Image,
    /// Install the three artifacts, reload, and enable the mount.
    InstallUnits,
    /// Create the store's subdirectories on the mounted filesystem.
    Subdirectories,
    /// Run the command the run continues under again.
    ReRun,
    /// Rename the store aside into the holding directory and recreate
    /// an empty mount point, which is what opens a migration.
    AsideRename,
    /// The type guard over the holding directory, run immediately
    /// before the copy.
    TypeGuard,
    /// The one whole-subtree copy onto the mounted reserve.
    Copy,
    /// The type guard over both trees and the three comparisons.
    Verify,
    /// The rename that closes the migration.
    ClosingRename,
    /// The way back out, while the migration is still open.
    Rollback,
}

/// One numbered phase-2 step, separately addressable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Phase2Step {
    /// Which step this is.
    pub(crate) kind: Phase2StepKind,
    /// The operator-facing sentence introducing it.
    pub(crate) title: String,
    /// The commands, each pasted verbatim into a POSIX `sh`.
    pub(crate) commands: Vec<String>,
}

/// The outcome a `filesystem`- or `directory`-mode run reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReserveReport {
    /// `migration incomplete` — a holding directory exists, so the
    /// store's contents are part-way onto the reserve. The run
    /// **fails** under this, and it sits ahead of every other outcome:
    /// however complete the image, the artifacts and the mount are,
    /// the reserve is never reported as enforced while it holds.
    MigrationIncomplete {
        /// What is outstanding, the holding path named first.
        findings: Vec<String>,
        /// The remaining commands, in order.
        steps: Vec<Phase2Step>,
    },
    /// `enforced` — all four phase-3 requirements hold.
    Enforced {
        /// Facts worth stating that are not failures, such as a
        /// stacked mount whose active entry is the reserve.
        notes: Vec<String>,
    },
    /// `provisioned, not activated` — the run fails under this.
    NotActivated {
        /// What is outstanding.
        findings: Vec<String>,
        /// Facts worth stating that are not failures, such as a
        /// `.migrated` directory whose space is reclaimable.
        notes: Vec<String>,
        /// The remaining commands, in order.
        steps: Vec<Phase2Step>,
        /// Whether an otherwise renderable list was **withheld**
        /// because the store already holds records.
        ///
        /// It is what tells the two empty lists apart, and they are
        /// not the same sentence: one is a sequence deliberately not
        /// given, because the step it ends at mounts a filesystem over
        /// those records; the other is a fault with no command
        /// bootroot may render for it at all. Giving the first
        /// sentence for the second tells the operator something untrue
        /// about their own host, and leaves them no way forward.
        steps_withheld: bool,
    },
}

/// Why a configured store path cannot be carried by the artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PathRenderFault {
    /// A newline or carriage return, which a line-based unit file
    /// cannot hold.
    LineBreak,
    /// Leading or trailing whitespace, which systemd strips off the
    /// value, leaving `Where=` naming a path the unit name no longer
    /// matches.
    EdgeWhitespace,
    /// A final backslash, which the unit-file reader takes as a line
    /// continuation.
    FinalBackslash,
}

/// Spells `store_dir` the way systemd's own `path_simplify` does:
/// repeated and trailing `/` removed, and every `.` component dropped.
/// A `..` is left alone, being a component only the filesystem can
/// resolve.
///
/// Everything derived from the store path is derived from **this**
/// form, and for one reason each. The image path is `store_dir` with
/// `.img` appended, so a configured `…/audit-store/` would put the
/// image at `…/audit-store/.img` — inside the very filesystem it
/// backs, and hidden the moment the mount comes up. The mount table
/// names the kernel's own simplified path, so a comparison against the
/// configured bytes would never match one and the host could never
/// reach **enforced**. And `Where=`, which systemd simplifies before
/// matching it against the unit name, has to be the same path the unit
/// name escapes — which the unit-name escaper already simplifies.
fn simplify_store_path(store_dir: &Path) -> PathBuf {
    let bytes = store_dir.as_os_str().as_bytes();
    // Absoluteness is preserved rather than imposed: a relative path
    // is refused by `validate_registrar_settings` long before this,
    // and turning one absolute here would hide the fault behind a
    // path nobody configured.
    let absolute = bytes.first() == Some(&b'/');
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    for component in bytes
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty() && *component != b".")
    {
        if absolute || !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(component);
    }
    if out.is_empty() {
        out.push(if absolute { b'/' } else { b'.' });
    }
    PathBuf::from(OsStr::from_bytes(&out).to_os_string())
}

/// Refuses a store path the three artifacts cannot carry.
///
/// The faults are read off the **simplified** path, which is what the
/// artifacts actually spell, and reported against the configured one,
/// which is what the operator has to edit. The two differ where
/// simplifying exposes a fault the configured spelling hid: a
/// `/srv/store /` ends in a `/` and so carries no trailing whitespace
/// of its own, while the path it simplifies to does, and systemd would
/// strip that space back off `Where=`.
///
/// Every other byte a Unix path may hold is rendered by the escaping
/// rules below rather than refused. This is a mode-gated phase-1
/// refusal and not a new rule in `validate_registrar_settings`, which
/// runs unconditionally and would therefore reject `directory`-mode
/// and endpoint-disabled deployments for which a unit file means
/// nothing.
fn check_store_path_renderable(
    configured: &Path,
    simplified: &Path,
    messages: &Messages,
) -> Result<()> {
    let bytes = simplified.as_os_str().as_bytes();
    let edge_whitespace = bytes.first().is_some_and(u8::is_ascii_whitespace)
        || bytes.last().is_some_and(u8::is_ascii_whitespace);
    let fault = if bytes.iter().any(|byte| *byte == b'\n' || *byte == b'\r') {
        Some(PathRenderFault::LineBreak)
    } else if edge_whitespace {
        Some(PathRenderFault::EdgeWhitespace)
    } else if bytes.last() == Some(&b'\\') {
        Some(PathRenderFault::FinalBackslash)
    } else {
        None
    };
    let Some(fault) = fault else {
        return Ok(());
    };
    let rendered = match fault {
        PathRenderFault::LineBreak => messages.audit_reserve_path_fault_line_break(),
        PathRenderFault::EdgeWhitespace => messages.audit_reserve_path_fault_edge_whitespace(),
        PathRenderFault::FinalBackslash => messages.audit_reserve_path_fault_final_backslash(),
    };
    anyhow::bail!(
        messages.error_audit_reserve_store_path_unrenderable(&display_path(configured), rendered)
    )
}

/// Refuses a layout in which the three artifacts would be staged
/// inside the store the mount covers.
///
/// The artifacts are written beside the Compose override and **never**
/// inside `audit_store_dir`. Nothing but the two paths' shapes keeps
/// them apart, and a deployment whose Compose file sits inside the
/// store puts them there: the mount then hides the very files the
/// operator has to install, and the next run finds a store that is no
/// longer empty — refused rather than mounted over, with the operator
/// pointed at a relocation for content that is bootroot's own. Refused
/// here, before either fault can happen.
///
/// The comparison is over path components rather than over a string
/// prefix, so a `/srv/audit-store-2` beside a `/srv/audit-store` is not
/// mistaken for something inside it. Both paths are simplified first,
/// for the same reason everything else derived from the store path is.
fn check_staging_outside_store(
    store_dir: &Path,
    compose_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let staging = simplify_store_path(&staging_dir(compose_dir));
    let inside = staging.starts_with(store_dir);
    if !inside {
        return Ok(());
    }
    anyhow::bail!(messages.error_audit_reserve_staging_inside_store(
        &display_path(&staging),
        &display_path(store_dir),
    ))
}

/// Returns the image path `store_dir` derives.
///
/// A sibling of the store, never inside the filesystem it backs, and
/// derived rather than configured — a fifth `audit_store_*` key would
/// be a second definition of the same thing.
fn derive_image_path(store_dir: &Path, messages: &Messages) -> Result<PathBuf> {
    if store_dir.parent().is_none() {
        anyhow::bail!(messages.error_audit_reserve_image_parentless(&display_path(store_dir)));
    }
    let mut bytes = store_dir.as_os_str().as_bytes().to_vec();
    bytes.extend_from_slice(IMAGE_SUFFIX.as_bytes());
    Ok(PathBuf::from(OsStr::from_bytes(&bytes).to_os_string()))
}

/// Spells `store_dir` the way `systemd-escape --path` does.
///
/// The mount unit's name is not chosen: a `.mount` unit's name must be
/// the escaped form of its mount point, or systemd refuses to load it.
fn systemd_escape_path(store_dir: &Path) -> String {
    let bytes = store_dir.as_os_str().as_bytes();
    let components: Vec<&[u8]> = bytes
        .split(|byte| *byte == b'/')
        .filter(|component| !component.is_empty() && *component != b".")
        .collect();
    if components.is_empty() {
        // The filesystem root escapes to a single `-`.
        return "-".to_string();
    }
    let mut escaped = String::new();
    for (index, component) in components.iter().enumerate() {
        if index > 0 {
            escaped.push('-');
        }
        for byte in *component {
            escaped.push_str(&escape_unit_name_byte(*byte));
        }
    }
    // A leading `.` would make the unit name a hidden file, so systemd
    // escapes that one position and no other.
    if let Some(rest) = escaped.strip_prefix('.') {
        return format!("\\x2e{rest}");
    }
    escaped
}

/// One byte of a unit name, escaped by systemd's own rule: everything
/// outside `[0-9A-Za-z:_.]` becomes `\xNN` in lower-case hex.
fn escape_unit_name_byte(byte: u8) -> String {
    if byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'.') {
        String::from_utf8(vec![byte]).unwrap_or_else(|_| format!("\\x{byte:02x}"))
    } else {
        format!("\\x{byte:02x}")
    }
}

/// Returns the `.mount` unit's name for `store_dir`.
fn mount_unit_name(store_dir: &Path) -> String {
    format!("{}{MOUNT_UNIT_SUFFIX}", systemd_escape_path(store_dir))
}

/// Renders `path` as a whole unit value — `What=` and `Where=`, which
/// systemd parses as a single path and would keep a quote as part of.
///
/// Every `%` is doubled: a lone one expands to a specifier and leaves
/// `Where=` naming a path the unit name no longer matches.
///
/// A `\` is deliberately **not** escaped here, and that is the whole
/// difference from [`unit_list_value`]. C-style escapes are undone
/// only where systemd splits a value into words, which these two
/// settings are not; systemd's own `fstab-generator` writes them
/// through `specifier_escape()` alone, doubling `%` and passing every
/// other byte through. Doubling a `\` would put a path in `Where=`
/// that is not the configured one, and `mount_verify` — which
/// re-escapes `Where=` and compares it against the unit name — would
/// then refuse the unit. `the_mount_units_where_unescapes_back_to_the_unit_name`
/// models that comparison and fails if this ever starts escaping.
fn unit_path_value(path: &Path) -> Vec<u8> {
    let mut out = Vec::new();
    for byte in path.as_os_str().as_bytes() {
        out.push(*byte);
        if *byte == b'%' {
            out.push(b'%');
        }
    }
    out
}

/// Renders `path` as one element of a whitespace-separated unit value
/// — `RequiresMountsFor=`.
///
/// Double-quoted with `\` and `"` backslash-escaped whenever the path
/// holds whitespace, a quote or a backslash; the `%` doubling of
/// [`unit_path_value`] applies here too.
fn unit_list_value(path: &Path) -> Vec<u8> {
    let bytes = path.as_os_str().as_bytes();
    let needs_quoting = bytes
        .iter()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'"' | b'\\' | b'\''));
    let mut out = Vec::new();
    if needs_quoting {
        out.push(b'"');
    }
    for byte in bytes {
        if needs_quoting && matches!(byte, b'"' | b'\\') {
            out.push(b'\\');
        }
        out.push(*byte);
        if *byte == b'%' {
            out.push(b'%');
        }
    }
    if needs_quoting {
        out.push(b'"');
    }
    out
}

/// Spells `value` as one POSIX `sh` word an operator pastes unchanged.
///
/// The unit name above all: unquoted, `sh` eats the backslash in
/// `\x2d`.
fn sh_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Spells `path` as one POSIX `sh` word.
pub(super) fn sh_quote_path(path: &Path) -> String {
    sh_quote(&display_path(path))
}

/// Renders `path` for a message. Lossy only for a path that is not
/// valid UTF-8, which the unit *name* still carries byte-exactly
/// because its escaper works on bytes.
pub(super) fn display_path(path: &Path) -> String {
    String::from_utf8_lossy(path.as_os_str().as_bytes()).into_owned()
}

/// The worst case the daemon's own rotation can reach:
/// `audit_max_file_bytes` × (`audit_max_retained_files` + 1).
///
/// `None` where that product cannot be represented, which is a
/// configuration no reserve can clear rather than an arithmetic
/// accident to be papered over.
fn record_worst_case_bytes(max_file_bytes: u64, max_retained_files: u32) -> Option<u64> {
    let generations = u64::from(max_retained_files).checked_add(1)?;
    max_file_bytes.checked_mul(generations)
}

/// Refuses a reserve too small to carry a working filesystem.
///
/// The minimum is the larger of [`MIN_RESERVE_FLOOR_BYTES`] and the
/// record worst case, and the comparison against the record figure is
/// **strict**: usable space inside an image never exceeds the image
/// itself, so a reserve at or below that figure is one the daemon's
/// rotation alone can fill.
///
/// That strictness is why the refusal says the reserve does not
/// *clear* the minimum rather than that it is *below* it. Where the
/// record figure is the larger of the two, a reserve exactly equal to
/// the reported minimum is refused, and "below" would then be a
/// sentence the operator can see is false about their own two numbers.
///
/// Clearing the minimum is not an adequacy claim and no message here
/// suggests it is: an ext4 filesystem offers less than the image it
/// sits in, and sizing the reserve so both writers fit stays the
/// operator's arithmetic.
fn check_reserve_minimum(inputs: &ReserveInputs<'_>, messages: &Messages) -> Result<()> {
    let records = record_worst_case_bytes(inputs.max_file_bytes, inputs.max_retained_files);
    // A minimum is reachable exactly when the record figure is
    // strictly below the reserve's own `i64::MAX` cap — a product that
    // overflowed `u64` is not.
    let Some(records) = records.filter(|figure| *figure < RESERVE_CAP_BYTES) else {
        anyhow::bail!(messages.error_audit_reserve_minimum_unreachable(
            &display_path(inputs.store_dir),
            inputs.max_file_bytes,
            inputs.max_retained_files,
        ));
    };
    if inputs.reserve_bytes >= MIN_RESERVE_FLOOR_BYTES && inputs.reserve_bytes > records {
        return Ok(());
    }
    anyhow::bail!(messages.error_audit_reserve_below_minimum(
        &display_path(inputs.store_dir),
        inputs.reserve_bytes,
        MIN_RESERVE_FLOOR_BYTES.max(records),
        MIN_RESERVE_FLOOR_BYTES,
        records,
    ))
}

/// `lstat`s `path`, naming it and the errno when the read itself
/// fails. "Cannot see it" is never collapsed into "it is not there",
/// which reads as an unprovisioned host.
pub(super) fn lstat_named(
    probe: &dyn ReserveProbe,
    path: &Path,
    messages: &Messages,
) -> Result<Option<FileFacts>> {
    probe.lstat(path).map_err(|err| {
        anyhow::anyhow!(
            messages.error_audit_reserve_unreadable(&display_path(path), &err.to_string())
        )
    })
}

/// Multiplies two byte figures, failing the run rather than wrapping.
///
/// `*` wraps silently in a release build, so an unchecked product is a
/// preflight that can pass a host with no room.
fn checked_bytes_mul(left: u64, right: u64, figure: &str, messages: &Messages) -> Result<u64> {
    left.checked_mul(right)
        .ok_or_else(|| anyhow::anyhow!(messages.error_audit_reserve_arithmetic(figure)))
}

/// Evaluates the derived image path against the whole image contract.
///
/// "Already provisioned" is never the size alone: an exact-size sparse
/// image reports a reserve while the root filesystem is still what
/// fills, and an exact-size world-readable or foreign-owned image is a
/// ceiling anyone can move.
///
/// # Errors
///
/// The two states with no remedy this surface may render are refusals:
/// a path that exists and is not a regular file, and a regular file
/// whose size is not exactly the reserve. Reformatting destroys the
/// records this surface exists to keep, and a silent grow leaves the
/// unit, the image and the configuration describing three different
/// ceilings.
fn evaluate_image(
    image_path: &Path,
    inputs: &ReserveInputs<'_>,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<ImageEvaluation> {
    let Some(facts) = lstat_named(probe, image_path, messages)? else {
        return Ok(ImageEvaluation::Absent);
    };
    if facts.kind != FileKind::Regular {
        anyhow::bail!(messages.error_audit_reserve_image_not_regular(
            &display_path(image_path),
            kind_text(facts.kind, messages),
        ));
    }
    if facts.size != inputs.reserve_bytes {
        anyhow::bail!(messages.error_audit_reserve_image_size_mismatch(
            &display_path(image_path),
            facts.size,
            inputs.reserve_bytes,
        ));
    }
    let allocated = checked_bytes_mul(
        facts.blocks,
        ST_BLOCKS_UNIT_BYTES,
        &messages.audit_reserve_figure_allocated(&display_path(image_path)),
        messages,
    )?;
    let unallocated_bytes = facts.size.saturating_sub(allocated);
    let wrong_owner = (facts.uid != inputs.expected_uid).then_some(facts.uid);
    let found_mode = facts.mode & MODE_MASK;
    let wrong_mode = (found_mode != IMAGE_FILE_MODE).then_some(found_mode);
    if unallocated_bytes == 0 && wrong_owner.is_none() && wrong_mode.is_none() {
        return Ok(ImageEvaluation::Correct);
    }
    Ok(ImageEvaluation::Deviating {
        unallocated_bytes,
        wrong_owner,
        wrong_mode,
    })
}

/// Names one [`FileKind`] for a message.
pub(super) fn kind_text(kind: FileKind, messages: &Messages) -> &'static str {
    match kind {
        FileKind::Regular => messages.audit_reserve_kind_regular(),
        FileKind::Directory => messages.audit_reserve_kind_directory(),
        FileKind::Symlink => messages.audit_reserve_kind_symlink(),
        FileKind::Other => messages.audit_reserve_kind_other(),
    }
}

/// One entry of the kernel's mount table, with the octal escapes it
/// writes for space, tab, newline and backslash already decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MountEntry {
    source: Vec<u8>,
    mount_point: Vec<u8>,
    fs_type: Vec<u8>,
}

/// Parses `/proc/self/mounts`.
///
/// A mount point holding a newline is written `\012` by the kernel, so
/// it never splits a line and does not derail the scan.
fn parse_mount_table(text: &str) -> Vec<MountEntry> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_ascii_whitespace();
            let source = fields.next()?;
            let mount_point = fields.next()?;
            let fs_type = fields.next()?;
            Some(MountEntry {
                source: decode_mount_field(source),
                mount_point: decode_mount_field(mount_point),
                fs_type: decode_mount_field(fs_type),
            })
        })
        .collect()
}

/// Decodes the `\NNN` octal escapes the kernel writes for space, tab,
/// newline and backslash.
pub(super) fn decode_mount_field(field: &str) -> Vec<u8> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0usize;
    while let Some(byte) = bytes.get(index) {
        if *byte == b'\\'
            && let Some(digits) = bytes.get(index + 1..index + 4)
            && let Some(value) = octal_triplet(digits)
        {
            out.push(value);
            index += 4;
            continue;
        }
        out.push(*byte);
        index += 1;
    }
    out
}

/// Reads three octal digits as one byte, or `None` where they are not
/// three octal digits or would not fit in one.
fn octal_triplet(digits: &[u8]) -> Option<u8> {
    let mut value: u16 = 0;
    for digit in digits {
        let parsed = digit.checked_sub(b'0').filter(|parsed| *parsed < 8)?;
        value = value.checked_mul(8)?.checked_add(u16::from(parsed))?;
    }
    u8::try_from(value).ok()
}

/// Splits a `st_dev`/`st_rdev` value into the numbers the sysfs path
/// is keyed on.
///
/// A value that does not fit the platform's `dev_t` names no device at
/// all, so it yields a pair no `/sys/dev/block` entry matches rather
/// than a wrapped one that might match the wrong device.
fn device_numbers(device: u64) -> (u64, u64) {
    let Some(raw) = narrow_platform_field::<libc::dev_t>(device) else {
        return (u64::MAX, u64::MAX);
    };
    (
        widen_platform_field(libc::major(raw), u64::MAX),
        widen_platform_field(libc::minor(raw), u64::MAX),
    )
}

/// Decides what `audit_store_dir` is mounted from, proving the choice
/// rather than trusting it.
///
/// A mount point can carry several entries, a later mount stacking
/// over an earlier one with both left listed, so the active entry is
/// the **last** one naming the store and a stack is reported as one.
/// That entry must be `ext4` on a loop device; the device node's
/// `st_rdev` is then compared against the store's own `st_dev`, which
/// for a block-backed filesystem is exactly the device it was mounted
/// from, and the loop device's backing file — read out of sysfs, keyed
/// on those device numbers rather than on the source string — must be
/// the derived image.
fn evaluate_mount(
    store_dir: &Path,
    image_path: &Path,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<MountEvaluation> {
    let text = probe.mounts().map_err(|err| {
        anyhow::anyhow!(messages.error_audit_reserve_unreadable(PROC_SELF_MOUNTS, &err.to_string()))
    })?;
    let target = store_dir.as_os_str().as_bytes();
    let entries = parse_mount_table(&text);
    let matching: Vec<&MountEntry> = entries
        .iter()
        .filter(|entry| entry.mount_point == target)
        .collect();
    let Some(active) = matching.last() else {
        return Ok(MountEvaluation::Absent);
    };
    let stacked = matching.len() > 1;
    let foreign = |active: &MountEntry| MountEvaluation::Foreign {
        description: messages.audit_reserve_mount_description(
            &String::from_utf8_lossy(&active.fs_type),
            &String::from_utf8_lossy(&active.source),
        ),
        stacked,
    };

    if active.fs_type != RESERVE_FS_TYPE.as_bytes()
        || !active.source.starts_with(LOOP_DEVICE_PREFIX.as_bytes())
    {
        return Ok(foreign(active));
    }
    let source_path = PathBuf::from(OsStr::from_bytes(&active.source).to_os_string());
    let Some(device) = lstat_named(probe, &source_path, messages)? else {
        return Ok(foreign(active));
    };
    let Some(store) = lstat_named(probe, store_dir, messages)? else {
        return Ok(foreign(active));
    };
    // The entry named a loop device; this is what proves the mount
    // actually came from *that* device rather than from another one
    // whose entry happens to sit last.
    if device.rdev != store.dev {
        return Ok(foreign(active));
    }
    let (major, minor) = device_numbers(store.dev);
    let backing = probe.loop_backing_file(major, minor).map_err(|err| {
        anyhow::anyhow!(messages.error_audit_reserve_unreadable(
            &format!("/sys/dev/block/{major}:{minor}/loop/backing_file"),
            &err.to_string(),
        ))
    })?;
    let Some(backing) = backing else {
        return Ok(foreign(active));
    };
    let trimmed = backing.trim_end_matches(['\n', '\r']);
    let trimmed = trimmed.strip_suffix(DELETED_SUFFIX).unwrap_or(trimmed);
    if Path::new(trimmed) != image_path {
        return Ok(foreign(active));
    }
    Ok(MountEvaluation::Reserve { stacked })
}

/// Why an allocated-size walk could not produce a figure.
///
/// The two are kept apart because their callers answer them
/// differently: a read that failed is a **failed** run wherever it
/// happens, while a figure that cannot be represented is a refusal the
/// migration reports under its own outcome, naming the figure and
/// rendering no copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MeasureError {
    /// A product or a sum that does not fit in a `u64`, named.
    Arithmetic(String),
    /// A metadata or listing read that failed, already rendered.
    Unreadable(String),
}

impl MeasureError {
    /// Renders this as the run-failing error a caller with no refusal
    /// of its own raises.
    pub(super) fn into_error(self, messages: &Messages) -> anyhow::Error {
        match self {
            Self::Arithmetic(figure) => {
                anyhow::anyhow!(messages.error_audit_reserve_arithmetic(&figure))
            }
            Self::Unreadable(rendered) => anyhow::anyhow!(rendered),
        }
    }
}

/// Sums the allocated bytes of everything beneath `root`.
///
/// Each `(st_dev, st_ino)` counts once, so a hard-linked pair is not
/// double-counted, and the walk does not cross a filesystem boundary:
/// what has to fit inside the reserve is what lives on the underlying
/// store, not what some other filesystem mounted below it holds.
///
/// `root` is a parameter rather than the store: the migration's
/// capacity check calls this against the holding directory, and two
/// walks that disagree about a hard link would be two different answers
/// to "does it fit".
///
/// # Errors
///
/// Returns [`MeasureError::Unreadable`] for a read that failed and
/// [`MeasureError::Arithmetic`] for a byte figure that cannot be
/// represented.
pub(super) fn measure_underlying(
    root: &Path,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> std::result::Result<u64, MeasureError> {
    let unreadable = |path: &Path, err: &io::Error| {
        MeasureError::Unreadable(
            messages.error_audit_reserve_unreadable(&display_path(path), &err.to_string()),
        )
    };
    let Some(root_facts) = probe.lstat(root).map_err(|err| unreadable(root, &err))? else {
        return Ok(0);
    };
    let figure = messages.audit_reserve_figure_underlying(&display_path(root));
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    let mut total = 0u64;
    while let Some(dir) = pending.pop() {
        let entries = probe
            .list_dir(&dir)
            .map_err(|err| unreadable(&dir, &err))?
            .unwrap_or_default();
        for entry in entries {
            let Some(facts) = probe
                .lstat(&entry)
                .map_err(|err| unreadable(&entry, &err))?
            else {
                continue;
            };
            if facts.dev != root_facts.dev {
                continue;
            }
            if !seen.insert((facts.dev, facts.ino)) {
                continue;
            }
            let allocated = facts
                .blocks
                .checked_mul(ST_BLOCKS_UNIT_BYTES)
                .ok_or_else(|| MeasureError::Arithmetic(figure.clone()))?;
            total = total
                .checked_add(allocated)
                .ok_or_else(|| MeasureError::Arithmetic(figure.clone()))?;
            if facts.kind == FileKind::Directory {
                pending.push(entry);
            }
        }
    }
    Ok(total)
}

/// Decides what is on the filesystem underneath the mount point, in
/// the one window in which that is checkable.
///
/// Mounting over content hides it from every reader, this surface's
/// own verification included, and what is hidden may be the only copy
/// of records written before the reserve existed. A shadowed
/// `records/` is the same failure as a shadowed `openbao/`, with the
/// other writer, so the check is the whole directory rather than
/// either subdirectory.
fn evaluate_underlying(
    store_dir: &Path,
    inputs: &ReserveInputs<'_>,
    mount: &MountEvaluation,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<UnderlyingState> {
    if mount.any_entry() {
        return Ok(UnderlyingState::NotVisible);
    }
    let entries = probe.list_dir(store_dir).map_err(|err| {
        anyhow::anyhow!(
            messages.error_audit_reserve_unreadable(&display_path(store_dir), &err.to_string())
        )
    })?;
    let Some(entries) = entries else {
        return Ok(UnderlyingState::Empty);
    };
    if entries.is_empty() {
        return Ok(UnderlyingState::Empty);
    }
    // No image, no mount and no relocation can make a store that is
    // already larger than the reserve fit inside it, so that is a
    // failure rather than something phase 2 could resolve.
    let used =
        measure_underlying(store_dir, probe, messages).map_err(|err| err.into_error(messages))?;
    if used > inputs.reserve_bytes {
        anyhow::bail!(messages.error_audit_reserve_underlying_too_large(
            &display_path(store_dir),
            used,
            inputs.reserve_bytes,
        ));
    }
    Ok(UnderlyingState::NotEmpty)
}

/// The bytes still to be allocated, which is what the free-space
/// preflight is against.
///
/// A fully provisioned host has already spent the reserve on the
/// image, so free space below the reserve is the **normal** steady
/// state; a preflight against the configured reserve would fail every
/// correctly provisioned host on its second run.
fn outstanding_allocation(image: ImageEvaluation, reserve_bytes: u64) -> u64 {
    match image {
        ImageEvaluation::Absent => reserve_bytes,
        ImageEvaluation::Correct => 0,
        ImageEvaluation::Deviating {
            unallocated_bytes, ..
        } => unallocated_bytes,
    }
}

/// Refuses a host with less room than the outstanding allocation
/// needs.
///
/// `f_bavail` rather than `f_bfree` deliberately: spending the host's
/// root-reserved emergency blocks on an audit image is not a trade
/// this surface should make.
fn preflight_free_space(
    inputs: &ReserveInputs<'_>,
    image_path: &Path,
    image: ImageEvaluation,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<()> {
    let outstanding = outstanding_allocation(image, inputs.reserve_bytes);
    if outstanding == 0 {
        return Ok(());
    }
    // The image's parent may not exist yet on a fresh host, so measure
    // the nearest component that does — the filesystem it will be
    // created on is the same one.
    let mut probe_path = image_path.parent().unwrap_or(Path::new("/"));
    while lstat_named(probe, probe_path, messages)?.is_none() {
        match probe_path.parent() {
            Some(parent) => probe_path = parent,
            None => break,
        }
    }
    let space = probe.space(probe_path).map_err(|err| {
        anyhow::anyhow!(
            messages.error_audit_reserve_unreadable(&display_path(probe_path), &err.to_string())
        )
    })?;
    let available = checked_bytes_mul(
        space.blocks_available,
        space.fragment_size,
        &messages.audit_reserve_figure_available(&display_path(probe_path)),
        messages,
    )?;
    if outstanding > available {
        anyhow::bail!(messages.error_audit_reserve_free_space(
            &display_path(image_path),
            outstanding,
            available,
            inputs.reserve_bytes,
        ));
    }
    Ok(())
}

/// Phase 1: derive, evaluate and preflight, creating and rendering
/// nothing.
///
/// The order is normative, since every verdict after the first
/// concerns a filesystem that cannot be made: the reserve minimum; the
/// image path and unit name, refusing a store path the artifacts
/// cannot carry and one that would hide them; the existing image's
/// contract, which makes the
/// outstanding allocation knowable; the free-space preflight against
/// that outstanding figure; and the underlying store's emptiness and
/// size, checkable only while the mount is absent.
///
/// `bootroot reinit` raises exactly these refusals before it wipes:
/// every one of them is a pure read, so running it twice costs nothing
/// and decides nothing.
///
/// # Errors
///
/// Returns a **failed** run's error naming the step: a sub-minimum or
/// unreachable reserve, a store path the artifacts cannot carry, a
/// store that would contain the staged artifacts, a derived image path
/// with no parent, an image that is not a regular
/// file or is the wrong size, a filesystem with less room than the
/// outstanding allocation, an underlying store larger than the
/// reserve, a read that failed for want of permission, or a byte
/// figure that cannot be represented.
pub(crate) fn evaluate(
    inputs: &ReserveInputs<'_>,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<Phase1Facts> {
    let store_dir = simplify_store_path(inputs.store_dir);
    // First, ahead of every refusal and every other reading. An
    // operator who completes the aside rename and stops there leaves a
    // valid image, a valid mount and an empty store; without this
    // ordering the next run reports the reserve as enforced over an
    // audit trail stranded in a sibling directory.
    let migration = migration::detect(&store_dir, probe, messages)?;
    check_reserve_minimum(inputs, messages)?;
    check_store_path_renderable(inputs.store_dir, &store_dir, messages)?;
    check_staging_outside_store(&store_dir, inputs.compose_dir, messages)?;
    let image_path = derive_image_path(&store_dir, messages)?;
    let unit_name = mount_unit_name(&store_dir);
    let image = evaluate_image(&image_path, inputs, probe, messages)?;
    preflight_free_space(inputs, &image_path, image, probe, messages)?;
    let mount = evaluate_mount(&store_dir, &image_path, probe, messages)?;
    let underlying = evaluate_underlying(&store_dir, inputs, &mount, probe, messages)?;
    Ok(Phase1Facts {
        store_dir,
        image_path,
        unit_name,
        image,
        mount,
        underlying,
        migration,
    })
}

/// Returns where the three artifacts are staged.
fn staging_dir(compose_dir: &Path) -> PathBuf {
    compose_dir.join(ARTIFACT_STAGING_SUBDIR)
}

/// Renders the `.mount` unit's bytes.
///
/// Six directives and no more. `RequiresMountsFor=` names the image's
/// parent so the unit orders itself after whatever carries the image;
/// the `[Install]` section is what makes the mount survive a reboot.
fn render_mount_unit(store_dir: &Path, image_path: &Path) -> Vec<u8> {
    let parent = image_path.parent().unwrap_or(Path::new("/"));
    let mut out = Vec::new();
    out.extend_from_slice(b"[Unit]\nRequiresMountsFor=");
    out.extend_from_slice(&unit_list_value(parent));
    out.extend_from_slice(b"\n\n[Mount]\nWhat=");
    out.extend_from_slice(&unit_path_value(image_path));
    out.extend_from_slice(b"\nWhere=");
    out.extend_from_slice(&unit_path_value(store_dir));
    out.extend_from_slice(b"\nType=");
    out.extend_from_slice(RESERVE_FS_TYPE.as_bytes());
    out.extend_from_slice(b"\nOptions=loop\n\n[Install]\nWantedBy=multi-user.target\n");
    out
}

/// Renders the `[Unit]` fragment both ordering drop-ins carry.
///
/// One renderer produces one fragment written to two drop-in paths:
/// `systemd/bootroot-registrar.service` is not edited, and
/// `docker.service` is not bootroot's to edit at all.
///
/// **Ordering only.** A `Requires=` on `docker.service` would fail the
/// whole Compose stack when the mount failed, taking step-ca and
/// postgres down over a fault local to one directory; on
/// `bootroot-registrar.service` it would replace a bootroot error
/// naming the store, the unit and the remedy with systemd's bare
/// refusal, and a `BindsTo=` would tear down a *running* daemon the
/// moment the mount went away.
fn render_drop_in(unit_name: &str) -> Vec<u8> {
    format!("[Unit]\nWants={unit_name}\nAfter={unit_name}\n").into_bytes()
}

/// Renders the three artifacts phase 1 writes.
pub(crate) fn render_artifacts(
    inputs: &ReserveInputs<'_>,
    facts: &Phase1Facts,
) -> Vec<RenderedArtifact> {
    let staging = staging_dir(inputs.compose_dir);
    let systemd = Path::new(SYSTEMD_UNIT_DIR);
    let drop_in = render_drop_in(&facts.unit_name);
    vec![
        RenderedArtifact {
            staged_path: staging.join(&facts.unit_name),
            installed_path: systemd.join(&facts.unit_name),
            contents: render_mount_unit(&facts.store_dir, &facts.image_path),
        },
        RenderedArtifact {
            staged_path: staging.join(DOCKER_DROP_IN_DIR).join(DROP_IN_FILE_NAME),
            installed_path: systemd.join(DOCKER_DROP_IN_DIR).join(DROP_IN_FILE_NAME),
            contents: drop_in.clone(),
        },
        RenderedArtifact {
            staged_path: staging.join(REGISTRAR_DROP_IN_DIR).join(DROP_IN_FILE_NAME),
            installed_path: systemd.join(REGISTRAR_DROP_IN_DIR).join(DROP_IN_FILE_NAME),
            contents: drop_in,
        },
    ]
}

/// Writes the rendered artifacts beside the Compose override.
///
/// They are inert files: nothing here installs, loads or enables one,
/// and a run that renders no phase-2 command at all still writes them,
/// because the operator will need them.
///
/// # Errors
///
/// Returns an error naming the path that could not be written.
pub(crate) fn write_artifacts(artifacts: &[RenderedArtifact], messages: &Messages) -> Result<()> {
    for artifact in artifacts {
        let parent = artifact
            .staged_path
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf();
        std::fs::create_dir_all(&parent)
            .with_context(|| messages.error_write_file_failed(&display_path(&parent)))?;
        bootroot::fs_util::atomic_replace_dir_owner_blocking(
            bootroot::fs_util::Destination::operator_named(&artifact.staged_path),
            &artifact.contents,
            bootroot::fs_util::StagedMode::PreserveOrCreate(ARTIFACT_FILE_MODE),
        )
        .with_context(|| messages.error_write_file_failed(&display_path(&artifact.staged_path)))?;
    }
    Ok(())
}

/// What phase 3 found at one artifact's installed path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactState {
    /// Installed and byte-identical to what phase 1 rendered.
    Identical,
    /// Not installed.
    Absent,
    /// Installed and different. An edited unit can name another image
    /// or mount point, and an edited drop-in can have lost its
    /// `After=`, with all three paths still present.
    Differs,
}

/// What phase 3 found at one of the store's subdirectories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SubdirState {
    /// At its contract.
    Ok,
    /// Not there.
    Absent,
    /// Present and departing from its contract.
    Faulty(bootroot::registrar::audit_store::PathFault),
}

/// Audits `records/`, which carries the whole store directory
/// contract.
fn evaluate_records_dir(facts: Option<FileFacts>, expected_uid: u32) -> SubdirState {
    use bootroot::registrar::audit_store::PathFault;

    let Some(facts) = facts else {
        return SubdirState::Absent;
    };
    if facts.kind == FileKind::Symlink {
        return SubdirState::Faulty(PathFault::Symlink);
    }
    if facts.kind != FileKind::Directory {
        return SubdirState::Faulty(PathFault::NotDirectory);
    }
    if facts.uid != expected_uid {
        return SubdirState::Faulty(PathFault::Owner {
            found: facts.uid,
            expected: expected_uid,
        });
    }
    let mode = facts.mode & MODE_MASK;
    if mode != SUBDIR_MODE {
        return SubdirState::Faulty(PathFault::Mode {
            found: mode,
            expected: SUBDIR_MODE,
        });
    }
    SubdirState::Ok
}

/// Audits `openbao/`, whose **owner is deliberately not compared**.
///
/// Nothing supplies the `OpenBao` container's uid to a phase running
/// before any Docker call, and inferring it from the store would
/// compare a value with itself. The gap is stated in every
/// `filesystem`-mode outcome instead.
fn evaluate_openbao_dir(facts: Option<FileFacts>) -> SubdirState {
    use bootroot::registrar::audit_store::PathFault;

    let Some(facts) = facts else {
        return SubdirState::Absent;
    };
    if facts.kind == FileKind::Symlink {
        return SubdirState::Faulty(PathFault::Symlink);
    }
    if facts.kind != FileKind::Directory {
        return SubdirState::Faulty(PathFault::NotDirectory);
    }
    let mode = facts.mode & MODE_MASK;
    if mode != SUBDIR_MODE {
        return SubdirState::Faulty(PathFault::Mode {
            found: mode,
            expected: SUBDIR_MODE,
        });
    }
    SubdirState::Ok
}

/// The image commands for the state phase 1 found the image in.
///
/// No state but **absent** ever renders `install`, a truncation, an
/// allocation to the full length or `mkfs.ext4` — each of those
/// destroys or reformats an image that may hold the deployment's
/// records. The sparse remedy allocates the missing bytes in place.
/// `fallocate -l <reserve>` does that when it succeeds; otherwise `dd`
/// reads and writes the existing image without truncating it. Reads
/// from a hole yield zeroes, and writing those same bytes allocates the
/// hole while preserving the filesystem and records already present.
/// When the proved reserve is mounted, the `dd` route first unmounts it:
/// the backing file must be offline while it is rewritten.
fn image_commands(inputs: &ReserveInputs<'_>, facts: &Phase1Facts) -> Vec<String> {
    let image = sh_quote_path(&facts.image_path);
    match facts.image {
        ImageEvaluation::Absent => vec![
            format!("install -m {IMAGE_FILE_MODE:04o} /dev/null {image}"),
            allocation_command(
                inputs.reserve_bytes,
                &image,
                &zero_fill_allocation_command(inputs.reserve_bytes, &image),
            ),
            format!("mkfs.ext4 -m 0 -E {MKFS_EXTENDED_OPTIONS} {image}"),
        ],
        ImageEvaluation::Correct => Vec::new(),
        ImageEvaluation::Deviating {
            unallocated_bytes,
            wrong_owner,
            wrong_mode,
        } => {
            let mut commands = Vec::new();
            if unallocated_bytes > 0 {
                let fallback = preserve_existing_allocation_command(&image);
                let fallback = if matches!(facts.mount, MountEvaluation::Reserve { .. }) {
                    format!("umount {} && {fallback}", sh_quote_path(&facts.store_dir))
                } else {
                    fallback
                };
                commands.push(allocation_command(inputs.reserve_bytes, &image, &fallback));
            }
            if wrong_owner.is_some() {
                commands.push(format!("chown 0:0 {image}"));
            }
            if wrong_mode.is_some() {
                commands.push(format!("chmod {IMAGE_FILE_MODE:04o} {image}"));
            }
            commands
        }
    }
}

/// Renders the allocation command with its `fallocate` and portable
/// zero-fill routes.
///
/// `fallocate` remains the usual route, but a failed availability check
/// or allocation falls through to `dd`. The caller supplies a fallback
/// appropriate for either a new image or an existing one, because only
/// a new image may be truncated.
fn allocation_command(reserve_bytes: u64, image: &str, fallback: &str) -> String {
    format!(
        "if command -v fallocate >/dev/null 2>&1 && fallocate -l {reserve_bytes} {image}; then :; else {fallback}; fi"
    )
}

/// Renders a zero-fill allocation of a newly created image.
///
/// The final byte-sized write carries a non-mebibyte remainder without
/// rounding the image's length up. Its `notrunc` conversion is needed
/// because the preceding full-block write may have created the image.
fn zero_fill_allocation_command(reserve_bytes: u64, image: &str) -> String {
    let whole_blocks = reserve_bytes / DD_ALLOCATION_BLOCK_BYTES;
    let remainder = reserve_bytes % DD_ALLOCATION_BLOCK_BYTES;
    let mut commands = Vec::new();
    if whole_blocks > 0 {
        commands.push(format!(
            "dd if=/dev/zero of={image} bs={DD_ALLOCATION_BLOCK_BYTES} count={whole_blocks}"
        ));
    }
    if remainder > 0 {
        let offset = whole_blocks * DD_ALLOCATION_BLOCK_BYTES;
        commands.push(format!(
            "dd if=/dev/zero of={image} bs=1 count={remainder} seek={offset} conv=notrunc"
        ));
    }
    commands.join(" && ")
}

/// Renders an in-place allocation of an existing exact-size image.
///
/// `conv=notrunc` is the non-destructive part of this route: `dd`
/// reads every existing byte before writing it back at the same offset.
/// Existing data is unchanged, while reads from sparse regions supply
/// zeroes that cause the missing blocks to be allocated.
fn preserve_existing_allocation_command(image: &str) -> String {
    format!("dd if={image} of={image} bs={DD_ALLOCATION_BLOCK_BYTES} conv=notrunc")
}

/// The per-directory remediation for one subdirectory.
///
/// bootroot renders no delete: a `records/` that is a symbolic link or
/// a plain file is named and left alone, because what is at that path
/// may be the only copy of something.
fn subdir_commands(path: &Path, state: SubdirState, with_chown: bool) -> Vec<String> {
    use bootroot::registrar::audit_store::PathFault;

    let quoted = sh_quote_path(path);
    match state {
        SubdirState::Absent => {
            let mut commands = vec![format!("mkdir {quoted}")];
            if with_chown {
                commands.push(format!("chown 0:0 {quoted}"));
            }
            commands.push(format!("chmod {SUBDIR_MODE:04o} {quoted}"));
            commands
        }
        SubdirState::Faulty(PathFault::Owner { .. }) if with_chown => {
            vec![format!("chown 0:0 {quoted}")]
        }
        SubdirState::Faulty(PathFault::Mode { .. }) => {
            vec![format!("chmod {SUBDIR_MODE:04o} {quoted}")]
        }
        // A `records/` that is a symbolic link or a plain file is
        // named and left alone: what is at that path may be the only
        // copy of something, and no rendered command removes it.
        SubdirState::Ok | SubdirState::Faulty(_) => Vec::new(),
    }
}

/// Reads one artifact's installed path and compares it byte for byte
/// with what phase 1 rendered.
fn evaluate_artifact(
    artifact: &RenderedArtifact,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<ArtifactState> {
    let found = probe.read_bytes(&artifact.installed_path).map_err(|err| {
        anyhow::anyhow!(messages.error_audit_reserve_unreadable(
            &display_path(&artifact.installed_path),
            &err.to_string()
        ))
    })?;
    Ok(match found {
        None => ArtifactState::Absent,
        Some(bytes) if bytes == artifact.contents => ArtifactState::Identical,
        Some(_) => ArtifactState::Differs,
    })
}

/// Assembles the numbered phase-2 steps, rendering only what is
/// outstanding.
///
/// Each step is its own unit rather than a line of one block: the
/// relocation issue that lands later reports this same list with
/// exactly one step withheld, and a pre-joined renderer would force it
/// to write a second copy.
fn phase2_steps(
    inputs: &ReserveInputs<'_>,
    facts: &Phase1Facts,
    artifacts: &[RenderedArtifact],
    artifact_states: &[ArtifactState],
    subdirs: &[(PathBuf, SubdirState, bool)],
    messages: &Messages,
) -> Vec<Phase2Step> {
    let mount_outstanding = !matches!(facts.mount, MountEvaluation::Reserve { .. });
    let remount_after_sparse_fallback = matches!(
        facts,
        Phase1Facts {
            image: ImageEvaluation::Deviating {
                unallocated_bytes: 1..,
                ..
            },
            mount: MountEvaluation::Reserve { .. },
            ..
        }
    );
    let image = image_commands(inputs, facts);

    let mut artifact_commands: Vec<String> = artifacts
        .iter()
        .zip(artifact_states)
        .filter(|(_, state)| **state != ArtifactState::Identical)
        .map(|(artifact, _)| {
            format!(
                "install -D -m {ARTIFACT_FILE_MODE:04o} {} {}",
                sh_quote_path(&artifact.staged_path),
                sh_quote_path(&artifact.installed_path)
            )
        })
        .collect();
    if !artifact_commands.is_empty() {
        artifact_commands.push("systemctl daemon-reload".to_string());
    }
    if mount_outstanding || remount_after_sparse_fallback {
        artifact_commands.push(format!(
            "systemctl enable --now {}",
            sh_quote(&facts.unit_name)
        ));
    }

    let mut subdirectory_commands: Vec<String> = Vec::new();
    if mount_outstanding {
        // `mkfs.ext4` gives the new filesystem's root directory mode
        // `0755`, and that root *is* `audit_store_dir` once the mount
        // is up. The store directory contract is exactly `0700` —
        // which is what keeps an unprivileged process off the trail,
        // and what an unprivileged `bootroot infra up` checks — so the
        // mount point is restated at that mode by the same hand that
        // creates the two subdirectories. Rendered like every other
        // phase-2 step, and performed by nobody but the operator.
        subdirectory_commands.push(format!(
            "chmod {SUBDIR_MODE:04o} {}",
            sh_quote_path(&facts.store_dir)
        ));
    }
    subdirectory_commands.extend(
        subdirs
            .iter()
            .flat_map(|(path, state, with_chown)| subdir_commands(path, *state, *with_chown)),
    );

    let mut steps = Vec::new();
    if !image.is_empty() || mount_outstanding {
        steps.push(stop_writers_step(messages));
    }
    if !image.is_empty() {
        steps.push(Phase2Step {
            kind: Phase2StepKind::Image,
            title: messages.audit_reserve_step_image().to_string(),
            commands: image,
        });
    }
    if !artifact_commands.is_empty() {
        steps.push(Phase2Step {
            kind: Phase2StepKind::InstallUnits,
            title: messages.audit_reserve_step_install().to_string(),
            commands: artifact_commands,
        });
    }
    if !subdirectory_commands.is_empty() {
        steps.push(Phase2Step {
            kind: Phase2StepKind::Subdirectories,
            title: messages.audit_reserve_step_subdirectories().to_string(),
            commands: subdirectory_commands,
        });
    }
    if !steps.is_empty() {
        steps.push(rerun_step(inputs, messages));
    }
    steps
}

/// The step that stops both writers, shared by the activation sequence
/// and the migration.
///
/// Only the daemon's half is a command this surface can spell: stopping
/// the Compose stack takes the operator's own `-f`/`-p` invocation,
/// which nothing here is given, and a guessed one would stop the wrong
/// deployment.
fn stop_writers_step(messages: &Messages) -> Phase2Step {
    Phase2Step {
        kind: Phase2StepKind::StopWriters,
        title: messages.audit_reserve_step_stop_writers().to_string(),
        commands: vec![format!("systemctl stop {REGISTRAR_UNIT_NAME}")],
    }
}

/// The closing step, naming the command the run was actually invoked
/// under.
fn rerun_step(inputs: &ReserveInputs<'_>, messages: &Messages) -> Phase2Step {
    Phase2Step {
        kind: Phase2StepKind::ReRun,
        title: messages.audit_reserve_step_rerun(inputs.rerun_command),
        commands: vec![inputs.rerun_command.to_string()],
    }
}

/// The findings the image's own contract raises, one per deviation.
fn image_findings(
    inputs: &ReserveInputs<'_>,
    image: ImageEvaluation,
    display: &str,
    messages: &Messages,
) -> Vec<String> {
    let mut findings = Vec::new();
    match image {
        ImageEvaluation::Correct => {}
        ImageEvaluation::Absent => {
            findings.push(messages.audit_reserve_finding_image_absent(display));
        }
        ImageEvaluation::Deviating {
            unallocated_bytes,
            wrong_owner,
            wrong_mode,
        } => {
            if unallocated_bytes > 0 {
                findings.push(messages.audit_reserve_finding_image_sparse(
                    display,
                    unallocated_bytes,
                    inputs.reserve_bytes,
                ));
            }
            if let Some(found) = wrong_owner {
                findings.push(messages.audit_reserve_finding_image_owner(
                    display,
                    found,
                    inputs.expected_uid,
                ));
            }
            if let Some(found) = wrong_mode {
                findings.push(messages.audit_reserve_finding_image_mode(
                    display,
                    found,
                    IMAGE_FILE_MODE,
                ));
            }
        }
    }
    findings
}

/// Audits the store's two subdirectories on the mounted filesystem,
/// pushing a finding for each departure.
///
/// The subdirectory contract is a statement about the **mounted**
/// filesystem. With another filesystem there, or none, these reads
/// would audit the directory underneath the mount point, which is not
/// what **enforced** asserts — so the mount finding stands alone and
/// step 4 renders the creation in full.
fn evaluate_subdirectories(
    inputs: &ReserveInputs<'_>,
    facts: &Phase1Facts,
    records_path: &Path,
    openbao_path: &Path,
    probe: &dyn ReserveProbe,
    messages: &Messages,
    findings: &mut Vec<String>,
) -> Result<(SubdirState, SubdirState)> {
    if !matches!(facts.mount, MountEvaluation::Reserve { .. }) {
        return Ok((SubdirState::Absent, SubdirState::Absent));
    }
    let records = evaluate_records_dir(
        lstat_named(probe, records_path, messages)?,
        inputs.expected_uid,
    );
    let openbao = evaluate_openbao_dir(lstat_named(probe, openbao_path, messages)?);
    for (path, state) in [(records_path, records), (openbao_path, openbao)] {
        let display = display_path(path);
        match state {
            SubdirState::Ok => {}
            SubdirState::Absent => {
                findings.push(messages.audit_reserve_finding_subdir_absent(&display));
            }
            SubdirState::Faulty(fault) => {
                findings.push(messages.audit_reserve_finding_subdir_invalid(
                    &display,
                    &messages.audit_store_fault(fault),
                ));
            }
        }
    }
    Ok((records, openbao))
}

/// Phase 3: verify and report, reading only metadata.
///
/// **enforced** requires all four requirements to hold together: the
/// image's whole contract; all three artifacts installed and
/// byte-identical to what phase 1 rendered; `audit_store_dir` mounted
/// from the derived image; and both subdirectories at their contracts
/// on the mounted filesystem. Any one unsatisfied is **provisioned,
/// not activated** — never a partial success, and never a fallback to
/// `directory`.
///
/// Phase 3 does not re-check the directory underneath the mount: once
/// the filesystem is mounted, what is beneath it cannot be named by
/// any read available here.
///
/// # Errors
///
/// Returns a **failed** run's error when a verification read fails for
/// want of permission, naming the path and the errno.
pub(crate) fn verify(
    inputs: &ReserveInputs<'_>,
    facts: &Phase1Facts,
    artifacts: &[RenderedArtifact],
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<ReserveReport> {
    let store = display_path(&facts.store_dir);
    let holding = display_path(&facts.migration.paths.holding);
    let migrated = display_path(&facts.migration.paths.migrated);

    // Ahead of the image contract, the artifacts and the mount, and
    // overriding all three: however complete those are, a run with a
    // holding directory fails under this outcome and never reports the
    // reserve as enforced.
    if facts.migration.holding {
        return migration_report(inputs, facts, artifacts, probe, messages);
    }

    if facts.underlying == UnderlyingState::NotEmpty {
        return Ok(migration_entry_report(
            inputs, facts, &store, &holding, &migrated, messages,
        ));
    }

    let mut findings = Vec::new();
    let mut notes = migrated_notes(facts, probe, messages)?;
    let image_display = display_path(&facts.image_path);

    findings.extend(image_findings(
        inputs,
        facts.image,
        &image_display,
        messages,
    ));

    let mut artifact_states = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        let state = evaluate_artifact(artifact, probe, messages)?;
        let installed = display_path(&artifact.installed_path);
        match state {
            ArtifactState::Identical => {}
            ArtifactState::Absent => {
                findings.push(messages.audit_reserve_finding_artifact_absent(&installed));
            }
            ArtifactState::Differs => {
                findings.push(messages.audit_reserve_finding_artifact_differs(&installed));
            }
        }
        artifact_states.push(state);
    }

    match &facts.mount {
        MountEvaluation::Reserve { stacked } => {
            if *stacked {
                notes.push(messages.audit_reserve_note_stacked(&store));
            }
        }
        MountEvaluation::Absent => {
            findings.push(messages.audit_reserve_finding_mount_absent(&store));
        }
        MountEvaluation::Foreign {
            description,
            stacked,
        } => {
            findings.push(messages.audit_reserve_finding_mount_foreign(&store, description));
            if *stacked {
                notes.push(messages.audit_reserve_note_stacked(&store));
            }
        }
    }

    let records_path = facts.store_dir.join(RECORDS_SUBDIR);
    let openbao_path = facts.store_dir.join(OPENBAO_SUBDIR);
    let (records_state, openbao_state) = evaluate_subdirectories(
        inputs,
        facts,
        &records_path,
        &openbao_path,
        probe,
        messages,
        &mut findings,
    )?;

    if findings.is_empty() {
        return Ok(ReserveReport::Enforced { notes });
    }
    let subdirs = vec![
        (records_path.clone(), records_state, true),
        (openbao_path.clone(), openbao_state, false),
    ];
    let steps = phase2_steps(
        inputs,
        facts,
        artifacts,
        &artifact_states,
        &subdirs,
        messages,
    );
    Ok(ReserveReport::NotActivated {
        findings,
        notes,
        steps,
        steps_withheld: false,
    })
}

/// What a store that already holds records is answered with.
///
/// It is not mounted over. What is rendered for it is the entry into
/// the migration and nothing else: both writers stopped, the store
/// renamed aside, and an empty mount point in its place. The activation
/// itself comes from the next pass, once the aside rename has made the
/// underlying directory empty.
fn migration_entry_report(
    inputs: &ReserveInputs<'_>,
    facts: &Phase1Facts,
    store: &str,
    holding: &str,
    migrated: &str,
    messages: &Messages,
) -> ReserveReport {
    let mut findings = vec![messages.audit_reserve_finding_store_not_empty(store, holding)];
    // Neither rename may target a path that already exists. `mv dir
    // dir.pre-mount` where the destination is an existing directory
    // does not replace it — it moves the source *inside* it — and a
    // `.migrated` left from an earlier migration would block the
    // closing rename at the far end of the sequence.
    if facts.migration.migrated {
        findings.push(messages.audit_reserve_finding_migration_path_exists(migrated));
        return ReserveReport::NotActivated {
            findings,
            notes: Vec::new(),
            steps: Vec::new(),
            steps_withheld: true,
        };
    }
    ReserveReport::NotActivated {
        findings,
        notes: Vec::new(),
        steps: vec![
            stop_writers_step(messages),
            migration::aside_rename_step(
                &facts.store_dir,
                &facts.migration.paths.holding,
                SUBDIR_MODE,
                messages,
            ),
            rerun_step(inputs, messages),
        ],
        steps_withheld: false,
    }
}

/// The note a retained `<audit_store_dir>.migrated` earns under the
/// normal outcomes.
///
/// It holds a redundant second copy outside the reserve, so its path
/// and size are reported as reclaimable — never as **migration
/// incomplete**, which it does not raise. Removing it is later operator
/// housekeeping, and bootroot renders no delete for it.
fn migrated_notes(
    facts: &Phase1Facts,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<Vec<String>> {
    if !facts.migration.migrated {
        return Ok(Vec::new());
    }
    let path = display_path(&facts.migration.paths.migrated);
    let size = migration::migrated_size(&facts.migration.paths.migrated, probe, messages)?;
    Ok(vec![match size {
        Some(bytes) => messages.audit_reserve_note_migrated_reclaimable(&path, bytes),
        None => messages.audit_reserve_note_migrated_reclaimable_unsized(&path),
    }])
}

/// The **migration incomplete** outcome.
///
/// It names the holding path, states which step is outstanding, and
/// renders what to run next: where the mount is not yet up, the
/// outstanding **activation** — taken from the phase-2 renderer with
/// the subdirectory step withheld, because the copy is what satisfies
/// it — and where it is, the capacity verdict and either the copy or
/// the two routes out. The rollback is offered in every case.
fn migration_report(
    inputs: &ReserveInputs<'_>,
    facts: &Phase1Facts,
    artifacts: &[RenderedArtifact],
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<ReserveReport> {
    let store = display_path(&facts.store_dir);
    let holding = display_path(&facts.migration.paths.holding);
    let migrated = display_path(&facts.migration.paths.migrated);
    let mount_up = matches!(facts.mount, MountEvaluation::Reserve { .. });

    let mut findings = vec![messages.audit_reserve_finding_migration_holding(&holding, &store)];
    if facts.underlying == UnderlyingState::NotEmpty {
        findings.push(messages.audit_reserve_finding_migration_store_not_empty(&store, &holding));
    }
    let verdict = migration::assess_copy(
        &facts.store_dir,
        &facts.migration.paths.holding,
        mount_up,
        probe,
        messages,
    )?;
    findings.extend(migration::verdict_findings(&verdict, messages));
    // The closing rename cannot be rendered onto a path that already
    // exists, so the whole copy is refused rather than started against
    // one and stopped at the far end.
    let closing_blocked = facts.migration.migrated;
    if closing_blocked {
        findings.push(messages.audit_reserve_finding_migration_path_exists(&migrated));
    }

    // The activation comes from the existing phase-2 renderer rather
    // than from a second copy written here, with exactly one step
    // withheld and nothing added. That step is the subdirectory one,
    // and the copy is what satisfies it: `cp -a <source>/. <dest>/`
    // recreates `records/` and `openbao/` with the source's own
    // ownership and modes, and applies the source directory's own mode
    // and owner to the destination root as well — so the `chmod` that
    // step would render for the mount point is not lost with it. A
    // directory made by hand ahead of the copy is a set of attributes
    // the verification then compares against the source's anyway.
    let mut artifact_states = Vec::with_capacity(artifacts.len());
    for artifact in artifacts {
        artifact_states.push(evaluate_artifact(artifact, probe, messages)?);
    }
    let mut steps = phase2_steps(inputs, facts, artifacts, &artifact_states, &[], messages);
    steps.retain(|step| {
        !matches!(
            step.kind,
            Phase2StepKind::ReRun | Phase2StepKind::Subdirectories
        )
    });
    if !steps
        .iter()
        .any(|step| step.kind == Phase2StepKind::StopWriters)
    {
        // Both writers stay down for the whole window, and bootroot
        // cannot see that they already are.
        steps.insert(0, stop_writers_step(messages));
    }
    if verdict.renders_copy() {
        steps.push(migration::type_guard_step(
            &facts.migration.paths.holding,
            messages,
        ));
        steps.push(migration::copy_step(
            &facts.store_dir,
            &facts.migration.paths.holding,
            messages,
        ));
        steps.push(migration::verification_step(
            &facts.store_dir,
            &facts.migration.paths.holding,
            messages,
        ));
        if !closing_blocked {
            steps.push(migration::closing_rename_step(
                &facts.migration.paths.holding,
                &facts.migration.paths.migrated,
                messages,
            ));
        }
    }
    steps.push(rerun_step(inputs, messages));
    steps.push(migration::rollback_step(
        &facts.store_dir,
        &facts.migration.paths.holding,
        messages,
    ));
    Ok(ReserveReport::MigrationIncomplete { findings, steps })
}

/// The `unenforced (directory)` outcome's text.
///
/// A success: the run continues and exits 0 provided the rest of the
/// initialisation succeeds. It is reached only from an explicit
/// `audit_store_enforcement = "directory"` — never as a fallback,
/// never inferred from a missing mount.
#[must_use]
pub(crate) fn render_directory_outcome(
    store_dir: &Path,
    reserve_bytes: u64,
    migration: &MigrationPresence,
    messages: &Messages,
) -> String {
    let mut out = messages.audit_reserve_outcome_directory(&display_path(store_dir), reserve_bytes);
    // None of the enforcement machinery applies here, so a holding
    // directory raises no outcome of its own — but it is still an
    // unfinished migration whose contents are the only copy of those
    // records, and naming it is the difference between that and debris
    // somebody eventually deletes.
    if migration.holding {
        out.push('\n');
        out.push_str(&messages.audit_reserve_directory_migration_open(
            &display_path(&migration.paths.holding),
            &display_path(store_dir),
        ));
    }
    out
}

/// Reads the two derived migration paths for a `directory`-mode run.
///
/// The same check the `filesystem` path makes first, made here too: the
/// holding directory is detected in **both** enforcement modes.
///
/// # Errors
///
/// Returns the reserve's unreadable-path error when either `lstat`
/// fails for anything but `ENOENT`.
pub(crate) fn detect_migration(
    store_dir: &Path,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<MigrationPresence> {
    migration::detect(store_dir, probe, messages)
}

/// A `filesystem`-mode outcome's text.
///
/// Every one of them, **enforced** included, states that `openbao/`'s
/// ownership was not verified.
#[must_use]
pub(crate) fn render_filesystem_outcome(
    inputs: &ReserveInputs<'_>,
    facts: &Phase1Facts,
    artifacts: &[RenderedArtifact],
    report: &ReserveReport,
    messages: &Messages,
) -> String {
    let store = display_path(&facts.store_dir);
    let mut out = String::new();
    match report {
        ReserveReport::Enforced { notes } => {
            out.push_str(&messages.audit_reserve_outcome_enforced(
                &display_path(&facts.image_path),
                inputs.reserve_bytes,
                &facts.unit_name,
                &store,
            ));
            for note in notes {
                out.push('\n');
                out.push_str(note);
            }
        }
        ReserveReport::MigrationIncomplete { findings, steps } => {
            out.push_str(&messages.audit_reserve_outcome_migration_incomplete(&store));
            out.push('\n');
            out.push_str(messages.audit_reserve_outstanding_header());
            for finding in findings {
                out.push_str("\n  - ");
                out.push_str(finding);
            }
            out.push('\n');
            out.push_str(messages.audit_reserve_artifacts_header());
            for artifact in artifacts {
                out.push_str("\n  - ");
                out.push_str(&display_path(&artifact.staged_path));
            }
            out.push('\n');
            out.push_str(messages.audit_reserve_steps_header());
            for (index, step) in steps.iter().enumerate() {
                let _ = write!(out, "\n  {}. {}", index + 1, step.title);
                for command in &step.commands {
                    out.push_str("\n       ");
                    out.push_str(command);
                }
            }
            if steps.iter().any(|step| step.kind == Phase2StepKind::Verify) {
                out.push('\n');
                out.push_str(messages.audit_reserve_migration_prerequisites());
            }
            out.push('\n');
            out.push_str(messages.audit_reserve_migration_window());
        }
        ReserveReport::NotActivated {
            findings,
            notes,
            steps,
            steps_withheld,
        } => {
            out.push_str(&messages.audit_reserve_outcome_not_activated(&store));
            out.push('\n');
            out.push_str(messages.audit_reserve_outstanding_header());
            for finding in findings {
                out.push_str("\n  - ");
                out.push_str(finding);
            }
            for note in notes {
                out.push('\n');
                out.push_str(note);
            }
            out.push('\n');
            out.push_str(messages.audit_reserve_artifacts_header());
            for artifact in artifacts {
                out.push_str("\n  - ");
                out.push_str(&display_path(&artifact.staged_path));
            }
            if steps.is_empty() {
                out.push('\n');
                if *steps_withheld {
                    out.push_str(messages.audit_reserve_no_steps());
                } else {
                    // Nothing was withheld here: what is outstanding
                    // is at a path bootroot neither removes nor
                    // replaces, so there is no command to render for
                    // it and the withheld-list sentence would be an
                    // untrue reason and no way forward.
                    out.push_str(
                        &messages.audit_reserve_no_steps_unremediable(inputs.rerun_command),
                    );
                }
            } else {
                out.push('\n');
                out.push_str(messages.audit_reserve_steps_header());
                for (index, step) in steps.iter().enumerate() {
                    let _ = write!(out, "\n  {}. {}", index + 1, step.title);
                    for command in &step.commands {
                        out.push_str("\n       ");
                        out.push_str(command);
                    }
                }
            }
        }
    }
    out.push('\n');
    out.push_str(messages.audit_reserve_openbao_owner_caveat());
    out
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs::{self, File};
    use std::os::unix::fs::{FileExt, MetadataExt, symlink};
    use std::process::Command;

    use tempfile::tempdir;

    use super::*;
    use crate::i18n::{Messages, test_messages};

    const DEFAULT_RESERVE: u64 = 2 * 1024 * 1024 * 1024;
    const DEFAULT_MAX_FILE_BYTES: u64 = 8 * 1024 * 1024;
    const DEFAULT_MAX_RETAINED: u32 = 16;
    const TEST_UID: u32 = 0;
    const STORE: &str = "/var/lib/bootroot/audit-store";
    const IMAGE: &str = "/var/lib/bootroot/audit-store.img";
    const UNIT: &str = "var-lib-bootroot-audit\\x2dstore.mount";
    const RERUN: &str = "bootroot init";

    /// A host built entirely out of fixture values, so every decision
    /// this module makes is reachable from a test that is not root and
    /// owns no loop device.
    #[derive(Default)]
    struct FakeProbe {
        files: HashMap<PathBuf, FileFacts>,
        dirs: HashMap<PathBuf, Vec<PathBuf>>,
        bytes: HashMap<PathBuf, Vec<u8>>,
        space: HashMap<PathBuf, FsSpace>,
        default_space: Option<FsSpace>,
        mounts: String,
        mountinfo: String,
        backing: HashMap<(u64, u64), String>,
        denied: Vec<PathBuf>,
        mounts_denied: bool,
        backing_denied: bool,
    }

    impl FakeProbe {
        fn with_default_space() -> Self {
            Self {
                default_space: Some(FsSpace {
                    blocks_available: 1 << 40,
                    fragment_size: 4096,
                }),
                ..Self::default()
            }
        }

        fn dir(mut self, path: &str) -> Self {
            self.files
                .insert(PathBuf::from(path), dir_facts(TEST_UID, 0o700));
            self.dirs.entry(PathBuf::from(path)).or_default();
            self
        }

        fn file(mut self, path: &str, facts: FileFacts) -> Self {
            self.files.insert(PathBuf::from(path), facts);
            self
        }

        fn entries(mut self, path: &str, entries: &[&str]) -> Self {
            self.dirs.insert(
                PathBuf::from(path),
                entries.iter().map(PathBuf::from).collect(),
            );
            self
        }

        fn installed(mut self, path: &Path, contents: &[u8]) -> Self {
            self.bytes.insert(path.to_path_buf(), contents.to_vec());
            self
        }

        fn mounts(mut self, text: &str) -> Self {
            self.mounts = text.to_string();
            self
        }

        fn mountinfo(mut self, text: &str) -> Self {
            self.mountinfo = text.to_string();
            self
        }

        fn backing(mut self, major: u64, minor: u64, text: &str) -> Self {
            self.backing.insert((major, minor), text.to_string());
            self
        }

        fn deny(mut self, path: &str) -> Self {
            self.denied.push(PathBuf::from(path));
            self
        }
    }

    impl ReserveProbe for FakeProbe {
        fn lstat(&self, path: &Path) -> io::Result<Option<FileFacts>> {
            if self.denied.iter().any(|denied| denied == path) {
                return Err(denied_error());
            }
            Ok(self.files.get(path).copied())
        }

        fn list_dir(&self, path: &Path) -> io::Result<Option<Vec<PathBuf>>> {
            if self.denied.iter().any(|denied| denied == path) {
                return Err(denied_error());
            }
            Ok(self.dirs.get(path).cloned())
        }

        fn space(&self, path: &Path) -> io::Result<FsSpace> {
            if let Some(space) = self.space.get(path) {
                return Ok(*space);
            }
            self.default_space
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }

        fn read_bytes(&self, path: &Path) -> io::Result<Option<Vec<u8>>> {
            if self.denied.iter().any(|denied| denied == path) {
                return Err(denied_error());
            }
            Ok(self.bytes.get(path).cloned())
        }

        fn mounts(&self) -> io::Result<String> {
            if self.mounts_denied {
                return Err(denied_error());
            }
            Ok(self.mounts.clone())
        }

        fn mountinfo(&self) -> io::Result<String> {
            if self.mounts_denied {
                return Err(denied_error());
            }
            Ok(self.mountinfo.clone())
        }

        fn loop_backing_file(&self, major: u64, minor: u64) -> io::Result<Option<String>> {
            if self.backing_denied {
                return Err(denied_error());
            }
            Ok(self.backing.get(&(major, minor)).cloned())
        }
    }

    fn denied_error() -> io::Error {
        io::Error::from(io::ErrorKind::PermissionDenied)
    }

    fn dir_facts(uid: u32, mode: u32) -> FileFacts {
        FileFacts {
            kind: FileKind::Directory,
            size: 4096,
            blocks: 8,
            uid,
            mode,
            dev: 64,
            ino: 1,
            rdev: 0,
        }
    }

    fn image_facts(size: u64, allocated: u64, uid: u32, mode: u32) -> FileFacts {
        FileFacts {
            kind: FileKind::Regular,
            size,
            blocks: allocated / ST_BLOCKS_UNIT_BYTES,
            uid,
            mode,
            dev: 64,
            ino: 2,
            rdev: 0,
        }
    }

    struct Fixture {
        store: PathBuf,
        compose: PathBuf,
        reserve_bytes: u64,
        max_file_bytes: u64,
        max_retained_files: u32,
    }

    impl Default for Fixture {
        fn default() -> Self {
            Self {
                store: PathBuf::from(STORE),
                compose: PathBuf::from("/opt/bootroot"),
                reserve_bytes: DEFAULT_RESERVE,
                max_file_bytes: DEFAULT_MAX_FILE_BYTES,
                max_retained_files: DEFAULT_MAX_RETAINED,
            }
        }
    }

    impl Fixture {
        fn inputs(&self) -> ReserveInputs<'_> {
            ReserveInputs {
                store_dir: &self.store,
                compose_dir: &self.compose,
                reserve_bytes: self.reserve_bytes,
                max_file_bytes: self.max_file_bytes,
                max_retained_files: self.max_retained_files,
                expected_uid: TEST_UID,
                rerun_command: RERUN,
            }
        }
    }

    /// A probe on which the store exists, is empty, and nothing is
    /// mounted over it.
    fn bare_host() -> FakeProbe {
        FakeProbe::with_default_space()
            .dir("/")
            .dir("/var")
            .dir("/var/lib")
            .dir("/var/lib/bootroot")
            .dir(STORE)
    }

    #[test]
    fn the_unit_name_is_systemds_own_path_escaping() {
        // Pinned byte for byte against `systemd-escape --path`.
        for (path, expected) in [
            (
                "/var/lib/bootroot/audit-store",
                "var-lib-bootroot-audit\\x2dstore",
            ),
            ("/", "-"),
            ("//var//lib//", "var-lib"),
            ("/srv/a b", "srv-a\\x20b"),
            ("/srv/a\tb", "srv-a\\x09b"),
            ("/srv/a\\b", "srv-a\\x5cb"),
            ("/srv/a%b", "srv-a\\x25b"),
            ("/srv/a'b", "srv-a\\x27b"),
            ("/.hidden", "\\x2ehidden"),
            ("/srv/naïve", "srv-na\\xc3\\xafve"),
            ("/srv/a:b_c.d", "srv-a:b_c.d"),
        ] {
            assert_eq!(systemd_escape_path(Path::new(path)), expected, "{path}");
        }
    }

    #[test]
    fn the_mount_units_where_unescapes_back_to_the_unit_name() {
        for path in [
            "/var/lib/bootroot/audit-store",
            "/srv/a b",
            "/srv/a\\b",
            "/srv/a%b",
        ] {
            let store = PathBuf::from(path);
            let image = derive_image_path(&store, &test_messages()).expect("a parent");
            let unit = render_mount_unit(&store, &image);
            let text = String::from_utf8(unit).expect("utf-8");
            let where_value = text
                .lines()
                .find_map(|line| line.strip_prefix("Where="))
                .expect("a Where= directive");
            // Undo the specifier doubling, then re-escape: one shared
            // escaper is what keeps `Where=` and the unit name from
            // ever describing different directories.
            let restored = where_value.replace("%%", "%");
            assert_eq!(
                mount_unit_name(Path::new(&restored)),
                mount_unit_name(&store),
                "{path}"
            );
        }

        // Stated once as bytes as well, because the round trip above
        // holds only while `Where=` carries the configured path
        // verbatim. Systemd undoes C-style escapes where it splits a
        // value into words, which `Where=` is not — its own
        // `fstab-generator` doubles `%` and nothing else — so a `\`
        // that were escaped here would name a directory nobody
        // configured.
        let store = PathBuf::from("/srv/a\\b");
        let image = derive_image_path(&store, &test_messages()).expect("a parent");
        let text = String::from_utf8(render_mount_unit(&store, &image)).expect("utf-8");
        assert!(text.contains("Where=/srv/a\\b\n"), "{text}");
        assert!(text.contains("What=/srv/a\\b.img\n"), "{text}");

        // The word-split setting is the one that quotes and escapes,
        // over the very same byte.
        let nested = PathBuf::from("/srv/a\\b/store");
        let image = derive_image_path(&nested, &test_messages()).expect("a parent");
        let text = String::from_utf8(render_mount_unit(&nested, &image)).expect("utf-8");
        assert!(
            text.contains("RequiresMountsFor=\"/srv/a\\\\b\"\n"),
            "{text}"
        );
        assert!(text.contains("Where=/srv/a\\b/store\n"), "{text}");
    }

    #[test]
    fn a_percent_is_doubled_in_every_unit_value_and_single_in_every_command() {
        let fixture = Fixture {
            store: PathBuf::from("/srv/a%b"),
            ..Fixture::default()
        };
        let inputs = fixture.inputs();
        let facts = Phase1Facts {
            store_dir: fixture.store.clone(),
            image_path: PathBuf::from("/srv/a%b.img"),
            unit_name: mount_unit_name(&fixture.store),
            image: ImageEvaluation::Absent,
            mount: MountEvaluation::Absent,
            underlying: UnderlyingState::Empty,
            migration: MigrationPresence::none(&fixture.store),
        };
        let artifacts = render_artifacts(&inputs, &facts);
        let unit = String::from_utf8(artifacts.first().expect("the unit").contents.clone())
            .expect("utf-8");
        assert!(unit.contains("What=/srv/a%%b.img"), "{unit}");
        assert!(unit.contains("Where=/srv/a%%b"), "{unit}");
        assert!(unit.contains("RequiresMountsFor=/srv"), "{unit}");
        // The drop-ins need no doubling at all: the unit name has
        // already turned every `%` into `\x25`.
        let drop_in = String::from_utf8(artifacts.get(1).expect("a drop-in").contents.clone())
            .expect("utf-8");
        assert!(!drop_in.contains("%%"), "{drop_in}");

        let commands = image_commands(&inputs, &facts);
        assert!(
            commands.iter().all(|command| !command.contains("%%")),
            "{commands:?}"
        );
        assert!(
            commands
                .iter()
                .all(|command| command.contains("'/srv/a%b.img'")),
            "{commands:?}"
        );
    }

    #[test]
    fn requires_mounts_for_quotes_a_parent_that_holds_whitespace() {
        let store = PathBuf::from("/srv/a b/store");
        let image = derive_image_path(&store, &test_messages()).expect("a parent");
        let text = String::from_utf8(render_mount_unit(&store, &image)).expect("utf-8");
        assert!(text.contains("RequiresMountsFor=\"/srv/a b\""), "{text}");
    }

    #[test]
    fn the_mount_unit_carries_exactly_its_six_directives() {
        let fixture = Fixture::default();
        let text =
            String::from_utf8(render_mount_unit(&fixture.store, Path::new(IMAGE))).expect("utf-8");
        let directives: Vec<&str> = text
            .lines()
            .filter(|line| line.contains('=') && !line.starts_with('['))
            .collect();
        assert_eq!(
            directives,
            vec![
                "RequiresMountsFor=/var/lib/bootroot",
                "What=/var/lib/bootroot/audit-store.img",
                "Where=/var/lib/bootroot/audit-store",
                "Type=ext4",
                "Options=loop",
                "WantedBy=multi-user.target",
            ]
        );
    }

    #[test]
    fn both_drop_ins_order_only_and_name_the_derived_unit() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let facts = Phase1Facts {
            store_dir: PathBuf::from(STORE),
            image_path: PathBuf::from(IMAGE),
            unit_name: UNIT.to_string(),
            image: ImageEvaluation::Absent,
            mount: MountEvaluation::Absent,
            underlying: UnderlyingState::Empty,
            migration: MigrationPresence::none(&fixture.store),
        };
        let artifacts = render_artifacts(&inputs, &facts);
        assert_eq!(artifacts.len(), 3);
        for index in [1usize, 2] {
            let artifact = artifacts.get(index).expect("a drop-in");
            let text = String::from_utf8(artifact.contents.clone()).expect("utf-8");
            assert_eq!(text, format!("[Unit]\nWants={UNIT}\nAfter={UNIT}\n"));
            for forbidden in ["Requires=", "BindsTo=", "RequiresMountsFor="] {
                assert!(!text.contains(forbidden), "{text}");
            }
        }
        assert_eq!(
            artifacts.get(1).expect("a drop-in").installed_path,
            Path::new("/etc/systemd/system/docker.service.d/10-bootroot-audit-store.conf")
        );
        assert_eq!(
            artifacts.get(2).expect("a drop-in").installed_path,
            Path::new(
                "/etc/systemd/system/bootroot-registrar.service.d/10-bootroot-audit-store.conf"
            )
        );
    }

    #[test]
    fn an_unrenderable_store_path_is_refused_before_anything_is_rendered() {
        for path in [
            "/srv/a\nb",
            "/srv/a\rb",
            " /srv/store",
            "/srv/store ",
            "/srv/store\\",
        ] {
            let fixture = Fixture {
                store: PathBuf::from(path),
                ..Fixture::default()
            };
            let error =
                evaluate(&fixture.inputs(), &bare_host(), &test_messages()).expect_err("refused");
            assert!(
                error.to_string().contains("systemd artifacts"),
                "{path}: {error}"
            );
        }
    }

    /// A fault the configured spelling hides and simplifying exposes
    /// is still a refusal: `/srv/store /` does not itself end in
    /// whitespace, while the path the artifacts spell does, and
    /// systemd would strip that space back off `Where=` and leave it
    /// naming a directory the unit name no longer matches.
    #[test]
    fn a_fault_only_the_simplified_path_carries_is_refused_too() {
        for path in ["/srv/store /", "/srv/store\\/"] {
            let fixture = Fixture {
                store: PathBuf::from(path),
                ..Fixture::default()
            };
            let error =
                evaluate(&fixture.inputs(), &bare_host(), &test_messages()).expect_err("refused");
            assert!(
                error.to_string().contains("systemd artifacts"),
                "{path}: {error}"
            );
            // The refusal names what the operator configured, not the
            // simplified form they would not recognise.
            assert!(error.to_string().contains(path), "{path}: {error}");
        }
    }

    /// Everything derived from the store path is derived from the
    /// simplified one.
    ///
    /// The regression a raw-bytes implementation fails is a
    /// `…/audit-store/` in the configuration: `.img` appended to it
    /// lands the image at `…/audit-store/.img`, **inside** the
    /// filesystem it backs and hidden the moment the mount comes up,
    /// while the mount table's own simplified path never compares
    /// equal to the configured one, so the host can never reach
    /// **enforced**.
    #[test]
    fn a_store_path_that_is_not_simplified_derives_the_same_artifacts() {
        let messages = test_messages();
        for path in [
            "/var/lib/bootroot/audit-store/",
            "/var/lib//bootroot/audit-store",
            "/var/lib/bootroot/./audit-store",
        ] {
            let fixture = Fixture {
                store: PathBuf::from(path),
                ..Fixture::default()
            };
            let facts = evaluate(&fixture.inputs(), &bare_host(), &messages)
                .unwrap_or_else(|err| panic!("{path}: {err}"));
            assert_eq!(facts.store_dir, Path::new(STORE), "{path}");
            assert_eq!(facts.image_path, Path::new(IMAGE), "{path}");
            assert_eq!(facts.unit_name, UNIT, "{path}");

            let artifacts = render_artifacts(&fixture.inputs(), &facts);
            let unit = String::from_utf8(artifacts.first().expect("the unit").contents.clone())
                .expect("utf-8");
            assert!(unit.contains(&format!("Where={STORE}\n")), "{path}: {unit}");
            assert!(unit.contains(&format!("What={IMAGE}\n")), "{path}: {unit}");

            // And the mount the kernel reports at the simplified path
            // is recognised as the reserve.
            let host = mounted_host("/dev/loop0", "ext4", Some(IMAGE));
            assert_eq!(
                evaluate_mount(&facts.store_dir, Path::new(IMAGE), &host, &messages)
                    .expect("evaluated"),
                MountEvaluation::Reserve { stacked: false },
                "{path}"
            );
        }
    }

    /// The three artifacts are staged beside the Compose override and
    /// never inside the store, and nothing but the two paths' shapes
    /// keeps them apart — so a layout that would put them there is a
    /// phase-1 refusal rather than a run that hides its own artifacts
    /// under the mount and then refuses the store it filled.
    #[test]
    fn a_store_that_would_contain_the_staged_artifacts_is_refused() {
        let messages = test_messages();

        // The compose directory *is* the store, and the staging
        // subdirectory the store's own child.
        for (store, compose) in [
            ("/srv/deploy", "/srv/deploy"),
            ("/srv/deploy", "/srv/deploy/inner"),
            // The store is the staging directory itself.
            ("/srv/deploy/audit-store", "/srv/deploy"),
        ] {
            let fixture = Fixture {
                store: PathBuf::from(store),
                compose: PathBuf::from(compose),
                ..Fixture::default()
            };
            let error = evaluate(&fixture.inputs(), &bare_host(), &messages)
                .expect_err("refused before anything is rendered");
            let text = error.to_string();
            assert!(text.contains("audit-store"), "{store}: {text}");
            assert!(text.contains(store), "{store}: {text}");
        }

        // A sibling whose path is a string prefix of the store's is
        // not inside it: the comparison is over components.
        for (store, compose) in [
            ("/srv/deploy", "/srv/deploy-2"),
            ("/srv/deploy/audit-store", "/srv/deploy2"),
            (STORE, "/opt/bootroot"),
        ] {
            let fixture = Fixture {
                store: PathBuf::from(store),
                compose: PathBuf::from(compose),
                ..Fixture::default()
            };
            check_staging_outside_store(
                &simplify_store_path(&fixture.store),
                &fixture.compose,
                &messages,
            )
            .unwrap_or_else(|err| panic!("{store} with {compose}: {err}"));
        }
    }

    #[test]
    fn a_store_path_holding_awkward_bytes_is_rendered_rather_than_refused() {
        for path in [
            "/srv/a b",
            "/srv/a\tb",
            "/srv/a\\b",
            "/srv/a%b",
            "/srv/a'b",
            "/srv/a-b",
        ] {
            let fixture = Fixture {
                store: PathBuf::from(path),
                ..Fixture::default()
            };
            let simplified = simplify_store_path(&fixture.store);
            check_store_path_renderable(&fixture.store, &simplified, &test_messages())
                .unwrap_or_else(|err| panic!("{path}: {err}"));
        }
    }

    #[test]
    fn the_image_state_machine_renders_exactly_its_rows_commands() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();
        let install = format!("install -m 0600 /dev/null '{IMAGE}'");
        let fallocate = format!("fallocate -l {DEFAULT_RESERVE} '{IMAGE}'");
        let absent_fallback = format!("dd if=/dev/zero of='{IMAGE}' bs=1048576 count=2048");
        let sparse_fallback = format!("dd if='{IMAGE}' of='{IMAGE}' bs=1048576 conv=notrunc");
        let absent_allocate = format!(
            "if command -v fallocate >/dev/null 2>&1 && {fallocate}; then :; else {absent_fallback}; fi"
        );
        let sparse_allocate = format!(
            "if command -v fallocate >/dev/null 2>&1 && {fallocate}; then :; else {sparse_fallback}; fi"
        );
        // Pinned as literal text rather than through
        // `MKFS_EXTENDED_OPTIONS`: what an operator pastes is the only
        // thing that decides whether the image stays allocated, so a
        // silent edit of that constant has to fail here.
        let mkfs = format!("mkfs.ext4 -m 0 -E nodiscard,lazy_itable_init=0 '{IMAGE}'");
        let chown = format!("chown 0:0 '{IMAGE}'");
        let chmod = format!("chmod 0600 '{IMAGE}'");

        // Absent: the only row that creates, allocates to the full
        // length or formats.
        let absent = bare_host();
        let facts = evaluate(&inputs, &absent, &messages).expect("phase 1");
        assert_eq!(facts.image, ImageEvaluation::Absent);
        assert_eq!(
            image_commands(&inputs, &facts),
            vec![install.clone(), absent_allocate, mkfs.clone()]
        );

        // Wrong file type: a hard error with no image command at all.
        for kind in [FileKind::Directory, FileKind::Symlink, FileKind::Other] {
            let host = bare_host().file(
                IMAGE,
                FileFacts {
                    kind,
                    ..image_facts(DEFAULT_RESERVE, DEFAULT_RESERVE, TEST_UID, 0o600)
                },
            );
            let error = evaluate(&inputs, &host, &messages).expect_err("refused");
            assert!(error.to_string().contains("overwrites nothing"), "{error}");
        }

        // Size mismatch in either direction: a hard error naming both
        // sizes and rendering no image command.
        for found in [DEFAULT_RESERVE - 1, DEFAULT_RESERVE + 1] {
            let host = bare_host().file(IMAGE, image_facts(found, found, TEST_UID, 0o600));
            let error = evaluate(&inputs, &host, &messages).expect_err("refused");
            let text = error.to_string();
            assert!(text.contains(&found.to_string()), "{text}");
            assert!(text.contains(&DEFAULT_RESERVE.to_string()), "{text}");
            assert!(text.contains("never resized"), "{text}");
        }

        // Exact size, fully allocated, right owner and mode.
        let correct = bare_host().file(
            IMAGE,
            image_facts(DEFAULT_RESERVE, DEFAULT_RESERVE, TEST_UID, 0o600),
        );
        let facts = evaluate(&inputs, &correct, &messages).expect("phase 1");
        assert_eq!(facts.image, ImageEvaluation::Correct);
        assert!(image_commands(&inputs, &facts).is_empty());

        // Exact size but sparse: an in-place allocation and nothing
        // else — no `install`, no `mkfs`.
        let sparse = bare_host().file(
            IMAGE,
            image_facts(DEFAULT_RESERVE, DEFAULT_RESERVE / 2, TEST_UID, 0o600),
        );
        let facts = evaluate(&inputs, &sparse, &messages).expect("phase 1");
        assert_eq!(
            image_commands(&inputs, &facts),
            vec![sparse_allocate.clone()]
        );

        // Wrong owner alone, wrong mode alone.
        let foreign = bare_host().file(
            IMAGE,
            image_facts(DEFAULT_RESERVE, DEFAULT_RESERVE, TEST_UID + 1, 0o600),
        );
        let facts = evaluate(&inputs, &foreign, &messages).expect("phase 1");
        assert_eq!(image_commands(&inputs, &facts), vec![chown.clone()]);

        let wide = bare_host().file(
            IMAGE,
            image_facts(DEFAULT_RESERVE, DEFAULT_RESERVE, TEST_UID, 0o644),
        );
        let facts = evaluate(&inputs, &wide, &messages).expect("phase 1");
        assert_eq!(image_commands(&inputs, &facts), vec![chmod.clone()]);

        // Sparse *and* wrongly moded: the remedies compose.
        let both = bare_host().file(
            IMAGE,
            image_facts(DEFAULT_RESERVE, DEFAULT_RESERVE / 2, TEST_UID, 0o644),
        );
        let facts = evaluate(&inputs, &both, &messages).expect("phase 1");
        assert_eq!(
            image_commands(&inputs, &facts),
            vec![sparse_allocate, chmod]
        );
    }

    #[test]
    fn the_allocation_fallbacks_preserve_existing_image_data() {
        let reserve = MIN_RESERVE_FLOOR_BYTES + 1;
        let fixture = Fixture {
            reserve_bytes: reserve,
            ..Fixture::default()
        };
        let inputs = fixture.inputs();
        let directory = tempdir().expect("temporary directory");
        let bin_directory = tempdir().expect("temporary PATH directory");
        let dd = Command::new("/bin/sh")
            .args(["-c", "command -v dd"])
            .output()
            .expect("find dd");
        assert!(dd.status.success(), "dd is available for the fallback test");
        let dd = String::from_utf8(dd.stdout).expect("dd path is UTF-8");
        let dd = PathBuf::from(dd.trim());
        symlink(&dd, bin_directory.path().join("dd")).expect("make dd available without fallocate");

        let absent = directory.path().join("absent.img");
        File::create(&absent).expect("create the phase-two absent image");
        let absent_facts = phase1_facts(&fixture, absent.clone(), ImageEvaluation::Absent);
        let absent_commands = image_commands(&inputs, &absent_facts);
        run_allocation_fallback(
            absent_commands
                .get(1)
                .expect("the absent allocation command"),
            bin_directory.path(),
        );
        assert_fully_allocated(&absent, reserve);

        let sparse = directory.path().join("sparse.img");
        let sparse_file = File::create(&sparse).expect("create sparse image");
        sparse_file
            .set_len(reserve)
            .expect("set sparse image length");
        write_all_at(&sparse_file, b"first record", 0);
        write_all_at(&sparse_file, b"middle record", reserve / 2);
        write_all_at(&sparse_file, b"last record", reserve - 11);
        let before = fs::read(&sparse).expect("read sparse image before repair");
        assert!(
            allocated_bytes(&sparse) < reserve,
            "fixture image must begin sparse"
        );

        let sparse_facts = phase1_facts(
            &fixture,
            sparse.clone(),
            ImageEvaluation::Deviating {
                unallocated_bytes: reserve - allocated_bytes(&sparse),
                wrong_owner: None,
                wrong_mode: None,
            },
        );
        let sparse_commands = image_commands(&inputs, &sparse_facts);
        run_allocation_fallback(
            sparse_commands
                .first()
                .expect("the sparse allocation command"),
            bin_directory.path(),
        );
        assert_fully_allocated(&sparse, reserve);
        assert_eq!(
            fs::read(&sparse).expect("read sparse image after repair"),
            before,
            "the sparse repair must preserve every existing byte"
        );
    }

    #[test]
    fn a_mounted_sparse_image_is_offline_for_the_dd_fallback() {
        let fixture = Fixture::default();
        let messages = test_messages();
        let (host, mut facts, artifacts) = activated_host(&fixture);
        facts.image = ImageEvaluation::Deviating {
            unallocated_bytes: DEFAULT_RESERVE / 2,
            wrong_owner: None,
            wrong_mode: None,
        };

        let report =
            verify(&fixture.inputs(), &facts, &artifacts, &host, &messages).expect("phase 3");
        let ReserveReport::NotActivated { steps, .. } = report else {
            panic!("a sparse mounted image is not enforced");
        };
        let image = steps
            .iter()
            .find(|step| step.kind == Phase2StepKind::Image)
            .expect("the image step");
        assert!(
            image.commands.iter().any(|command| {
                command.contains(&format!("umount '{}'", fixture.store.display()))
                    && command.contains("dd if=")
            }),
            "{:?}",
            image.commands
        );

        let install = steps
            .iter()
            .find(|step| step.kind == Phase2StepKind::InstallUnits)
            .expect("the remount step");
        assert!(
            install.commands.iter().any(|command| {
                command == &format!("systemctl enable --now '{}'", facts.unit_name)
            }),
            "{:?}",
            install.commands
        );
    }

    fn phase1_facts(fixture: &Fixture, image_path: PathBuf, image: ImageEvaluation) -> Phase1Facts {
        Phase1Facts {
            store_dir: fixture.store.clone(),
            image_path,
            unit_name: UNIT.to_string(),
            image,
            mount: MountEvaluation::Absent,
            underlying: UnderlyingState::Empty,
            migration: MigrationPresence::none(&fixture.store),
        }
    }

    fn run_allocation_fallback(command: &str, path: &Path) {
        let status = Command::new("/bin/sh")
            .args(["-c", command])
            .env_clear()
            .env("PATH", path)
            .status()
            .expect("run the rendered allocation fallback");
        assert!(status.success(), "{command}");
    }

    fn write_all_at(file: &File, mut bytes: &[u8], mut offset: u64) {
        while !bytes.is_empty() {
            let written = file
                .write_at(bytes, offset)
                .expect("write fixture image data");
            assert_ne!(written, 0, "a non-empty write must make progress");
            bytes = bytes
                .get(written..)
                .expect("a file write cannot exceed its source buffer");
            offset += u64::try_from(written).expect("usize fits in u64");
        }
    }

    fn assert_fully_allocated(path: &Path, expected_length: u64) {
        let metadata = fs::metadata(path).expect("stat allocated image");
        assert_eq!(
            metadata.len(),
            expected_length,
            "the image length must be exact"
        );
        assert!(
            allocated_bytes(path) >= expected_length,
            "the image must have blocks over its full length"
        );
    }

    fn allocated_bytes(path: &Path) -> u64 {
        fs::metadata(path)
            .expect("stat image allocation")
            .blocks()
            .checked_mul(ST_BLOCKS_UNIT_BYTES)
            .expect("test image allocation fits in u64")
    }

    #[test]
    fn the_phase_two_steps_are_separately_addressable() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();
        let facts = evaluate(&inputs, &bare_host(), &messages).expect("phase 1");
        let artifacts = render_artifacts(&inputs, &facts);
        let report = verify(&inputs, &facts, &artifacts, &bare_host(), &messages).expect("phase 3");
        let ReserveReport::NotActivated { steps, .. } = report else {
            panic!("a fresh host is not activated");
        };
        assert_eq!(
            steps.iter().map(|step| step.kind).collect::<Vec<_>>(),
            vec![
                Phase2StepKind::StopWriters,
                Phase2StepKind::Image,
                Phase2StepKind::InstallUnits,
                Phase2StepKind::Subdirectories,
                Phase2StepKind::ReRun,
            ]
        );
        // The relocation issue reports this same list with exactly one
        // step withheld, so filtering has to leave every survivor byte
        // identical. Built by removing the entry from a copy of the
        // full list, rather than by re-rendering, so a renderer that
        // pre-joined its steps could not satisfy it.
        let mut expected = steps.clone();
        let index = expected
            .iter()
            .position(|step| step.kind == Phase2StepKind::Subdirectories)
            .expect("the subdirectory step");
        expected.remove(index);
        let without: Vec<Phase2Step> = steps
            .iter()
            .filter(|step| step.kind != Phase2StepKind::Subdirectories)
            .cloned()
            .collect();
        assert_eq!(without, expected);
        assert_eq!(without.len(), steps.len() - 1);

        let subdir = steps
            .iter()
            .find(|step| step.kind == Phase2StepKind::Subdirectories)
            .expect("the subdirectory step");
        assert_eq!(
            subdir.commands,
            vec![
                // `mkfs.ext4` gives the filesystem's root `0755`, and
                // that root is the store directory once the mount is
                // up.
                format!("chmod 0700 '{STORE}'"),
                format!("mkdir '{STORE}/records'"),
                format!("chown 0:0 '{STORE}/records'"),
                format!("chmod 0700 '{STORE}/records'"),
                format!("mkdir '{STORE}/openbao'"),
                format!("chmod 0700 '{STORE}/openbao'"),
            ]
        );
        assert!(
            !subdir
                .commands
                .iter()
                .any(|command| command.contains("chown") && command.contains("openbao")),
            "openbao/ renders no chown"
        );
    }

    #[test]
    fn the_free_space_preflight_is_against_the_outstanding_allocation() {
        assert_eq!(
            outstanding_allocation(ImageEvaluation::Absent, DEFAULT_RESERVE),
            DEFAULT_RESERVE
        );
        assert_eq!(
            outstanding_allocation(ImageEvaluation::Correct, DEFAULT_RESERVE),
            0
        );
        assert_eq!(
            outstanding_allocation(
                ImageEvaluation::Deviating {
                    unallocated_bytes: 4096,
                    wrong_owner: None,
                    wrong_mode: None,
                },
                DEFAULT_RESERVE
            ),
            4096
        );

        // The regression a reserve-based preflight fails: a fully
        // allocated image on a filesystem with less free space than
        // the reserve still reaches phase 3.
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();
        let mut host = bare_host().file(
            IMAGE,
            image_facts(DEFAULT_RESERVE, DEFAULT_RESERVE, TEST_UID, 0o600),
        );
        host.default_space = Some(FsSpace {
            blocks_available: 1,
            fragment_size: 4096,
        });
        let facts = evaluate(&inputs, &host, &messages).expect("phase 1");
        assert_eq!(facts.image, ImageEvaluation::Correct);

        // An absent image on the same host is refused, and the refusal
        // names all three numbers.
        let mut empty = bare_host();
        empty.default_space = Some(FsSpace {
            blocks_available: 3,
            fragment_size: 8192,
        });
        let error = evaluate(&inputs, &empty, &messages).expect_err("refused");
        let text = error.to_string();
        assert!(text.contains(&DEFAULT_RESERVE.to_string()), "{text}");
        // `f_bavail x f_frsize`, not the bare block count: a fixture
        // whose fragment size is not 4096 catches that.
        assert!(text.contains("24576"), "{text}");
    }

    #[test]
    fn every_filesystem_derived_byte_figure_is_checked_and_fails_closed() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();

        // `f_bavail x f_frsize` past `u64::MAX`.
        let mut host = bare_host();
        host.default_space = Some(FsSpace {
            blocks_available: u64::MAX,
            fragment_size: 4096,
        });
        let error = evaluate(&inputs, &host, &messages).expect_err("refused");
        assert!(error.to_string().contains("space available"), "{error}");

        // `st_blocks` x 512 past `u64::MAX`.
        let host = bare_host().file(
            IMAGE,
            FileFacts {
                blocks: u64::MAX,
                ..image_facts(DEFAULT_RESERVE, DEFAULT_RESERVE, TEST_UID, 0o600)
            },
        );
        let error = evaluate(&inputs, &host, &messages).expect_err("refused");
        assert!(error.to_string().contains("allocated size"), "{error}");

        // The underlying-store sum overflowing on its last entry.
        let huge = FileFacts {
            blocks: u64::MAX / ST_BLOCKS_UNIT_BYTES,
            ino: 7,
            ..image_facts(4096, 4096, TEST_UID, 0o600)
        };
        let host = bare_host()
            .entries(STORE, &[&format!("{STORE}/a"), &format!("{STORE}/b")])
            .file(&format!("{STORE}/a"), huge)
            .file(&format!("{STORE}/b"), FileFacts { ino: 8, ..huge });
        let error = evaluate(&inputs, &host, &messages).expect_err("refused");
        assert!(error.to_string().contains("the size of what"), "{error}");
    }

    #[test]
    fn the_reserve_minimum_is_the_larger_figure_compared_strictly() {
        let messages = test_messages();
        let records = DEFAULT_MAX_FILE_BYTES * u64::from(DEFAULT_MAX_RETAINED + 1);

        // Equal to the record figure fails; one byte above clears it.
        for (reserve, ok) in [(records, false), (records + 1, true)] {
            let fixture = Fixture {
                reserve_bytes: reserve,
                ..Fixture::default()
            };
            assert_eq!(
                check_reserve_minimum(&fixture.inputs(), &messages).is_ok(),
                ok,
                "reserve {reserve}"
            );
        }

        // The refusal at exactly the record figure reports a minimum
        // equal to the configured reserve, because the comparison
        // against that figure is strict. Its sentence has to stay true
        // of those two identical numbers: a message calling the
        // reserve "below" the minimum it is equal to is one the
        // operator can see is false.
        let equal = Fixture {
            reserve_bytes: records,
            ..Fixture::default()
        };
        let text = check_reserve_minimum(&equal.inputs(), &messages)
            .expect_err("refused on the strict comparison")
            .to_string();
        assert!(text.contains("does not clear the"), "{text}");
        assert!(!text.contains("below the"), "{text}");
        // Both figures are named, and they are the same number.
        assert_eq!(text.matches(&records.to_string()).count(), 3, "{text}");

        // Below the fixed floor fails even where the records are tiny.
        let fixture = Fixture {
            reserve_bytes: MIN_RESERVE_FLOOR_BYTES - 1,
            max_file_bytes: 65536,
            max_retained_files: 1,
            ..Fixture::default()
        };
        let error = check_reserve_minimum(&fixture.inputs(), &messages).expect_err("refused");
        let text = error.to_string();
        assert!(
            text.contains(&MIN_RESERVE_FLOOR_BYTES.to_string()),
            "{text}"
        );
        assert!(text.contains("Raise `audit_store_reserve_bytes`"), "{text}");
        assert!(text.contains("directory"), "{text}");
        assert!(text.contains("NOT a claim"), "{text}");

        // Raising the retention turns an accepted reserve into a
        // refusal, with nothing else changed.
        let accepted = Fixture {
            reserve_bytes: records + 1,
            ..Fixture::default()
        };
        assert!(check_reserve_minimum(&accepted.inputs(), &messages).is_ok());
        let raised = Fixture {
            reserve_bytes: records + 1,
            max_retained_files: DEFAULT_MAX_RETAINED + 1,
            ..Fixture::default()
        };
        assert!(check_reserve_minimum(&raised.inputs(), &messages).is_err());
    }

    #[test]
    fn the_reserve_minimums_four_boundary_cases_pin_the_arithmetic() {
        let messages = test_messages();

        // `audit_max_retained_files = u32::MAX` at the 64 KiB file
        // floor is exactly 2^48. An unchecked `+ 1` on the `u32` wraps
        // the count to zero and lets a one-byte reserve through.
        assert_eq!(record_worst_case_bytes(65536, u32::MAX), Some(1 << 48));
        for (reserve, ok) in [(1u64 << 48, false), ((1u64 << 48) + 1, true)] {
            let fixture = Fixture {
                reserve_bytes: reserve,
                max_file_bytes: 65536,
                max_retained_files: u32::MAX,
                ..Fixture::default()
            };
            let outcome = check_reserve_minimum(&fixture.inputs(), &messages);
            assert_eq!(outcome.is_ok(), ok, "reserve {reserve}");
            if let Err(error) = outcome {
                assert!(
                    error
                        .to_string()
                        .contains("Raise `audit_store_reserve_bytes`"),
                    "the ordinary refusal: {error}"
                );
            }
        }

        // A product that overflows `u64` takes the unreachable
        // refusal, which names both record keys.
        assert_eq!(record_worst_case_bytes(u64::MAX, 1), None);
        let fixture = Fixture {
            reserve_bytes: RESERVE_CAP_BYTES,
            max_file_bytes: u64::MAX,
            max_retained_files: 1,
            ..Fixture::default()
        };
        let error = check_reserve_minimum(&fixture.inputs(), &messages).expect_err("refused");
        let text = error.to_string();
        assert!(text.contains("audit_max_file_bytes"), "{text}");
        assert!(text.contains("audit_max_retained_files"), "{text}");
        assert!(
            !text.contains("Raise `audit_store_reserve_bytes`"),
            "{text}"
        );

        // A product landing exactly on `u64::MAX` is unreachable
        // without tripping the overflow guard.
        assert_eq!(record_worst_case_bytes(u64::MAX, 0), Some(u64::MAX));
        let fixture = Fixture {
            reserve_bytes: RESERVE_CAP_BYTES,
            max_file_bytes: u64::MAX,
            max_retained_files: 0,
            ..Fixture::default()
        };
        let error = check_reserve_minimum(&fixture.inputs(), &messages).expect_err("refused");
        assert!(
            error.to_string().contains("Lower `audit_max_file_bytes`"),
            "{error}"
        );

        // A record figure of `i64::MAX - 1` is reachable with a
        // reserve of `i64::MAX`; exactly `i64::MAX` is not.
        let fixture = Fixture {
            reserve_bytes: RESERVE_CAP_BYTES,
            max_file_bytes: RESERVE_CAP_BYTES - 1,
            max_retained_files: 0,
            ..Fixture::default()
        };
        assert!(check_reserve_minimum(&fixture.inputs(), &messages).is_ok());
        let fixture = Fixture {
            reserve_bytes: RESERVE_CAP_BYTES,
            max_file_bytes: RESERVE_CAP_BYTES,
            max_retained_files: 0,
            ..Fixture::default()
        };
        let error = check_reserve_minimum(&fixture.inputs(), &messages).expect_err("refused");
        assert!(
            error.to_string().contains("Lower `audit_max_file_bytes`"),
            "{error}"
        );
    }

    /// A `/proc/self/mounts` line for the store, with the octal
    /// escapes the kernel writes.
    fn mount_line(source: &str, mount_point: &str, fs_type: &str) -> String {
        let escaped: String = mount_point
            .chars()
            .map(|ch| match ch {
                ' ' => "\\040".to_string(),
                '\t' => "\\011".to_string(),
                '\n' => "\\012".to_string(),
                '\\' => "\\134".to_string(),
                other => other.to_string(),
            })
            .collect();
        format!("{source} {escaped} {fs_type} rw,relatime 0 0\n")
    }

    /// A host whose store is mounted from `source`, with `st_rdev` and
    /// the sysfs backing file lined up behind it.
    fn mounted_host(source: &str, fs_type: &str, backing: Option<&str>) -> FakeProbe {
        let rdev = 1792 + 3; // major 7, minor 3 on Linux's encoding.
        let (major, minor) = device_numbers(rdev);
        let mut host = bare_host()
            .file(
                STORE,
                FileFacts {
                    dev: rdev,
                    ..dir_facts(TEST_UID, 0o755)
                },
            )
            .file(
                source,
                FileFacts {
                    kind: FileKind::Other,
                    rdev,
                    ..dir_facts(TEST_UID, 0o660)
                },
            )
            .mounts(&mount_line(source, STORE, fs_type));
        if let Some(backing) = backing {
            host = host.backing(major, minor, &format!("{backing}\n"));
        }
        host
    }

    #[test]
    fn the_mount_is_proved_rather_than_trusted() {
        let fixture = Fixture::default();
        let messages = test_messages();
        let image = Path::new(IMAGE);

        // The derived image on a loop device passes.
        let host = mounted_host("/dev/loop0", "ext4", Some(IMAGE));
        assert_eq!(
            evaluate_mount(&fixture.store, image, &host, &messages).expect("evaluated"),
            MountEvaluation::Reserve { stacked: false }
        );

        // A trailing ` (deleted)` still compares equal.
        let host = mounted_host("/dev/loop0", "ext4", Some(&format!("{IMAGE} (deleted)")));
        assert_eq!(
            evaluate_mount(&fixture.store, image, &host, &messages).expect("evaluated"),
            MountEvaluation::Reserve { stacked: false }
        );

        // A tmpfs, a bind mount and a loop device backed by another
        // file are each not the reserve.
        for (source, fs_type, backing) in [
            ("tmpfs", "tmpfs", None),
            ("/dev/sda1", "ext4", None),
            ("/dev/loop0", "ext4", Some("/var/lib/other.img")),
        ] {
            let host = mounted_host(source, fs_type, backing);
            let evaluated =
                evaluate_mount(&fixture.store, image, &host, &messages).expect("evaluated");
            let MountEvaluation::Foreign { description, .. } = evaluated else {
                panic!("{source} is not the reserve");
            };
            assert!(description.contains(source), "{description}");
        }

        // A last entry naming the derived image while the store's
        // `st_dev` is another device is not the reserve either.
        let mut host = mounted_host("/dev/loop0", "ext4", Some(IMAGE));
        host = host.file(
            STORE,
            FileFacts {
                dev: 999,
                ..dir_facts(TEST_UID, 0o755)
            },
        );
        assert!(matches!(
            evaluate_mount(&fixture.store, image, &host, &messages).expect("evaluated"),
            MountEvaluation::Foreign { .. }
        ));
    }

    #[test]
    fn the_active_mount_entry_is_the_last_one_and_a_stack_is_reported() {
        let fixture = Fixture::default();
        let messages = test_messages();
        let image = Path::new(IMAGE);

        // Image then tmpfs: stacked, and *not* the reserve — the case
        // a first-match implementation fails.
        let host = mounted_host("/dev/loop0", "ext4", Some(IMAGE)).mounts(&format!(
            "{}{}",
            mount_line("/dev/loop0", STORE, "ext4"),
            mount_line("tmpfs", STORE, "tmpfs")
        ));
        assert!(matches!(
            evaluate_mount(&fixture.store, image, &host, &messages).expect("evaluated"),
            MountEvaluation::Foreign { stacked: true, .. }
        ));

        // The reverse is the reserve, and is still reported as
        // stacked.
        let host = mounted_host("/dev/loop0", "ext4", Some(IMAGE)).mounts(&format!(
            "{}{}",
            mount_line("tmpfs", STORE, "tmpfs"),
            mount_line("/dev/loop0", STORE, "ext4")
        ));
        assert_eq!(
            evaluate_mount(&fixture.store, image, &host, &messages).expect("evaluated"),
            MountEvaluation::Reserve { stacked: true }
        );
    }

    #[test]
    fn a_store_path_with_octal_escaped_bytes_matches_through_them() {
        let messages = test_messages();
        for path in ["/srv/a b", "/srv/a\tb", "/srv/a\\b"] {
            let fixture = Fixture {
                store: PathBuf::from(path),
                ..Fixture::default()
            };
            let image = derive_image_path(&fixture.store, &messages).expect("a parent");
            let rdev = 1792 + 4;
            let (major, minor) = device_numbers(rdev);
            let host = FakeProbe::with_default_space()
                .file(
                    path,
                    FileFacts {
                        dev: rdev,
                        ..dir_facts(TEST_UID, 0o755)
                    },
                )
                .file(
                    "/dev/loop1",
                    FileFacts {
                        kind: FileKind::Other,
                        rdev,
                        ..dir_facts(TEST_UID, 0o660)
                    },
                )
                .backing(major, minor, &format!("{}\n", image.display()))
                // An entry whose mount point holds a newline does not
                // derail the scan: the kernel writes it as `\012`.
                .mounts(&format!(
                    "{}{}",
                    mount_line("tmpfs", "/srv/other\nplace", "tmpfs"),
                    mount_line("/dev/loop1", path, "ext4")
                ));
            assert_eq!(
                evaluate_mount(&fixture.store, &image, &host, &messages).expect("evaluated"),
                MountEvaluation::Reserve { stacked: false },
                "{path}"
            );
        }
    }

    /// A host whose store is the reserve, its image correct and its
    /// three artifacts installed byte-identically.
    fn activated_host(fixture: &Fixture) -> (FakeProbe, Phase1Facts, Vec<RenderedArtifact>) {
        let inputs = fixture.inputs();
        let facts = Phase1Facts {
            store_dir: PathBuf::from(STORE),
            image_path: PathBuf::from(IMAGE),
            unit_name: UNIT.to_string(),
            image: ImageEvaluation::Correct,
            mount: MountEvaluation::Reserve { stacked: false },
            underlying: UnderlyingState::NotVisible,
            migration: MigrationPresence::none(Path::new(STORE)),
        };
        let artifacts = render_artifacts(&inputs, &facts);
        let mut host = mounted_host("/dev/loop0", "ext4", Some(IMAGE))
            .file(&format!("{STORE}/records"), dir_facts(TEST_UID, 0o700))
            .file(&format!("{STORE}/openbao"), dir_facts(TEST_UID, 0o700));
        for artifact in &artifacts {
            host = host.installed(&artifact.installed_path, &artifact.contents);
        }
        (host, facts, artifacts)
    }

    #[test]
    fn an_activated_host_reaches_enforced() {
        let fixture = Fixture::default();
        let (host, facts, artifacts) = activated_host(&fixture);
        let messages = test_messages();
        let report =
            verify(&fixture.inputs(), &facts, &artifacts, &host, &messages).expect("phase 3");
        assert_eq!(report, ReserveReport::Enforced { notes: Vec::new() });
        let text =
            render_filesystem_outcome(&fixture.inputs(), &facts, &artifacts, &report, &messages);
        assert!(text.contains("enforced (filesystem)"), "{text}");
        assert!(text.contains(IMAGE), "{text}");
        assert!(text.contains(UNIT), "{text}");
        assert!(text.contains(STORE), "{text}");
        assert!(text.contains(&DEFAULT_RESERVE.to_string()), "{text}");
        assert!(text.contains("ownership is not verified"), "{text}");
    }

    #[test]
    fn each_missing_or_edited_artifact_prevents_enforced_and_renders_its_install() {
        let fixture = Fixture::default();
        let messages = test_messages();
        for index in 0..3usize {
            // Missing: the case a drop-ins-only check fails.
            let (base, facts, artifacts) = activated_host(&fixture);
            let mut host = base;
            let target = artifacts.get(index).expect("an artifact").clone();
            host.bytes.remove(&target.installed_path);
            let report =
                verify(&fixture.inputs(), &facts, &artifacts, &host, &messages).expect("phase 3");
            let ReserveReport::NotActivated {
                findings, steps, ..
            } = report
            else {
                panic!("a missing artifact is not enforced");
            };
            assert!(
                findings.iter().any(|finding| {
                    finding.contains(&target.installed_path.display().to_string())
                }),
                "{findings:?}"
            );
            let install = steps
                .iter()
                .find(|step| step.kind == Phase2StepKind::InstallUnits)
                .expect("the install step");
            assert!(
                install.commands.iter().any(|command| {
                    command.contains(&target.installed_path.display().to_string())
                }),
                "{:?}",
                install.commands
            );
            assert!(
                install
                    .commands
                    .iter()
                    .any(|command| command == "systemctl daemon-reload"),
                "{:?}",
                install.commands
            );
            // The running mount is not restarted over a text
            // difference, so no `systemctl restart` is rendered.
            assert!(
                !install
                    .commands
                    .iter()
                    .any(|command| command.contains("restart")),
                "{:?}",
                install.commands
            );

            // Edited: same outcome, naming the file that differs.
            let (base, facts, artifacts) = activated_host(&fixture);
            let host = base.installed(&target.installed_path, b"[Unit]\n");
            let report =
                verify(&fixture.inputs(), &facts, &artifacts, &host, &messages).expect("phase 3");
            assert!(matches!(report, ReserveReport::NotActivated { .. }));
        }
    }

    #[test]
    fn the_subdirectory_contract_is_checked_per_directory_and_never_repaired() {
        let fixture = Fixture::default();
        let messages = test_messages();
        let records = format!("{STORE}/records");
        let openbao = format!("{STORE}/openbao");

        // `openbao/` at `0700` under a non-root uid reaches enforced:
        // its owner is deliberately not compared.
        let (base, facts, artifacts) = activated_host(&fixture);
        let host = base.file(&openbao, dir_facts(TEST_UID + 5, 0o700));
        assert_eq!(
            verify(&fixture.inputs(), &facts, &artifacts, &host, &messages).expect("phase 3"),
            ReserveReport::Enforced { notes: Vec::new() }
        );

        // `records/` foreign-owned renders only its `chown`.
        let (base, facts, artifacts) = activated_host(&fixture);
        let host = base.file(&records, dir_facts(TEST_UID + 5, 0o700));
        let ReserveReport::NotActivated { steps, .. } =
            verify(&fixture.inputs(), &facts, &artifacts, &host, &messages).expect("phase 3")
        else {
            panic!("a foreign-owned records/ is not enforced");
        };
        let subdir = steps
            .iter()
            .find(|step| step.kind == Phase2StepKind::Subdirectories)
            .expect("the subdirectory step");
        assert_eq!(subdir.commands, vec![format!("chown 0:0 '{records}'")]);

        // `openbao/` at another mode renders only its `chmod`, and no
        // `chown` appears among them.
        let (base, facts, artifacts) = activated_host(&fixture);
        let host = base.file(&openbao, dir_facts(TEST_UID, 0o755));
        let ReserveReport::NotActivated { steps, .. } =
            verify(&fixture.inputs(), &facts, &artifacts, &host, &messages).expect("phase 3")
        else {
            panic!("a wrongly moded openbao/ is not enforced");
        };
        let subdir = steps
            .iter()
            .find(|step| step.kind == Phase2StepKind::Subdirectories)
            .expect("the subdirectory step");
        assert_eq!(subdir.commands, vec![format!("chmod 0700 '{openbao}'")]);

        // Absent, a non-directory and a symlink are each reported.
        for (path, facts_for) in [
            (records.clone(), None),
            (
                openbao.clone(),
                Some(FileFacts {
                    kind: FileKind::Symlink,
                    ..dir_facts(TEST_UID, 0o700)
                }),
            ),
            (
                records.clone(),
                Some(FileFacts {
                    kind: FileKind::Regular,
                    ..dir_facts(TEST_UID, 0o700)
                }),
            ),
        ] {
            let (base, facts, artifacts) = activated_host(&fixture);
            let mut host = base;
            match facts_for {
                Some(replacement) => {
                    host = host.file(&path, replacement);
                }
                None => {
                    host.files.remove(Path::new(&path));
                }
            }
            let report =
                verify(&fixture.inputs(), &facts, &artifacts, &host, &messages).expect("phase 3");
            let ReserveReport::NotActivated { findings, .. } = report else {
                panic!("{path} must not be enforced");
            };
            assert!(
                findings.iter().any(|finding| finding.contains(&path)),
                "{findings:?}"
            );
        }
    }

    /// An outstanding fault with no command bootroot may render — a
    /// subdirectory that is a symbolic link, which nothing here
    /// removes — reaches the operator with a reason that is about
    /// *that* and a way forward, rather than with the sentence the
    /// withheld list carries.
    #[test]
    fn an_empty_list_that_was_not_withheld_says_so_and_names_the_re_run() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();
        let (base, facts, artifacts) = activated_host(&fixture);
        let host = base.file(
            &format!("{STORE}/openbao"),
            FileFacts {
                kind: FileKind::Symlink,
                ..dir_facts(TEST_UID, 0o700)
            },
        );
        let report = verify(&inputs, &facts, &artifacts, &host, &messages).expect("phase 3");
        let ReserveReport::NotActivated {
            steps,
            steps_withheld,
            ..
        } = &report
        else {
            panic!("a symlinked openbao/ is not enforced");
        };
        assert!(steps.is_empty(), "{steps:?}");
        assert!(!steps_withheld);

        let text = render_filesystem_outcome(&inputs, &facts, &artifacts, &report, &messages);
        // The withheld list's reason is about mounting over records,
        // and nothing is being mounted over anything here.
        assert!(!text.contains("mounts a filesystem over"), "{text}");
        assert!(text.contains("nothing is being withheld"), "{text}");
        assert!(text.contains(RERUN), "{text}");
    }

    #[test]
    fn a_non_empty_underlying_store_renders_only_the_entry_into_the_migration() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();
        for entries in [
            vec![format!("{STORE}/records")],
            vec![format!("{STORE}/openbao")],
            vec![format!("{STORE}/records"), format!("{STORE}/openbao")],
        ] {
            let refs: Vec<&str> = entries.iter().map(String::as_str).collect();
            let mut host = bare_host().entries(STORE, &refs);
            for (index, entry) in entries.iter().enumerate() {
                host = host.file(
                    entry,
                    FileFacts {
                        ino: 40 + u64::try_from(index).unwrap_or_default(),
                        ..dir_facts(TEST_UID, 0o700)
                    },
                );
            }
            let facts = evaluate(&inputs, &host, &messages).expect("phase 1");
            assert_eq!(facts.underlying, UnderlyingState::NotEmpty);
            let artifacts = render_artifacts(&inputs, &facts);
            let report = verify(&inputs, &facts, &artifacts, &host, &messages).expect("phase 3");
            let ReserveReport::NotActivated {
                findings,
                steps,
                steps_withheld,
                ..
            } = &report
            else {
                panic!("a non-empty store is not activated");
            };
            assert!(!steps_withheld);
            // Exactly the entry into the migration, and nothing that
            // would mount a filesystem over what is already there: the
            // activation comes from the *next* pass, once the aside
            // rename has made the underlying directory empty.
            assert_eq!(
                steps
                    .iter()
                    .map(|step| step.kind)
                    .collect::<Vec<Phase2StepKind>>(),
                vec![
                    Phase2StepKind::StopWriters,
                    Phase2StepKind::AsideRename,
                    Phase2StepKind::ReRun,
                ],
                "{steps:?}"
            );
            let aside = steps.get(1).expect("the aside rename");
            assert_eq!(
                aside.commands,
                vec![
                    format!("mv '{STORE}' '{STORE}.pre-mount'"),
                    format!("install -d -m 0700 -o root -g root '{STORE}'"),
                ]
            );
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.contains("two supported ways forward")),
                "{findings:?}"
            );
            let text = render_filesystem_outcome(&inputs, &facts, &artifacts, &report, &messages);
            assert!(text.contains("provisioned, not activated"), "{text}");
            for artifact in &artifacts {
                assert!(
                    text.contains(&artifact.staged_path.display().to_string()),
                    "{text}"
                );
            }
            // Still nothing that creates, formats or mounts anything
            // on or over the store.
            for forbidden in ["mkfs", "fallocate", "mkdir", "systemctl enable", "rm "] {
                assert!(!text.contains(forbidden), "{forbidden} in {text}");
            }
        }
    }

    #[test]
    fn a_non_empty_underlying_store_names_the_retained_bind_exposure_in_both_locales() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let host = bare_host()
            .entries(
                STORE,
                &[&format!("{STORE}/records"), &format!("{STORE}/openbao")],
            )
            .file(&format!("{STORE}/records"), dir_facts(TEST_UID, 0o700))
            .file(&format!("{STORE}/openbao"), dir_facts(TEST_UID, 0o700));

        let locales: [(&str, &[&str]); 2] = [
            (
                "en",
                &[
                    "bring-up is refused before the stack starts, so no container starts",
                    "`create_host_path: false` governs creation only",
                    "/var/lib/bootroot/audit-store/openbao already exists",
                    "audit device writes on the root filesystem",
                    "until the records are relocated onto the reserve",
                    "Nothing was deleted, moved or mounted over",
                    "which is what the steps below open",
                    "`audit_store_enforcement = \"directory\"`",
                ],
            ),
            (
                "ko",
                &[
                    "스택을 시작하기 전에 기동이 거부되어 어떤 컨테이너도 시작되지 않습니다",
                    "`create_host_path: false`는 생성만 통제합니다",
                    "/var/lib/bootroot/audit-store/openbao가 이미 있고",
                    "audit device는 루트 파일 시스템에 기록합니다",
                    "레코드를 예약량으로 옮길 때까지 남으며",
                    "아무것도 삭제·이동되지 않았고 그 위로 마운트되지도 않았습니다",
                    "아래 단계가 그 절차를 엽니다",
                    "`audit_store_enforcement = \"directory\"`",
                ],
            ),
        ];

        for (locale, required_passages) in locales {
            let messages = Messages::new(locale).expect("supported test locale");
            let facts = evaluate(&inputs, &host, &messages).expect("phase 1");
            let artifacts = render_artifacts(&inputs, &facts);
            let report = verify(&inputs, &facts, &artifacts, &host, &messages).expect("phase 3");
            let text = render_filesystem_outcome(&inputs, &facts, &artifacts, &report, &messages);

            for passage in required_passages {
                assert!(text.contains(passage), "{locale}: {text}");
            }
        }
    }

    #[test]
    fn manual_existing_records_passages_point_at_the_relocation_without_respelling_it() {
        let manuals: [(&str, &str, &[&str]); 2] = [
            (
                "docs/en/operations.md",
                "#### A store that already holds records",
                &[
                    "The same store is refused by `bootroot infra up`",
                    "before the stack starts, so no container starts.",
                    "`create_host_path: false` governs creation only",
                    "until the records are relocated onto the reserve.",
                    "Nothing is deleted, moved or mounted over",
                    "relocate those records by the documented procedure below",
                ],
            ),
            (
                "docs/ko/operations.md",
                "#### 이미 레코드를 담고 있는 저장소",
                &[
                    "저장소는 실제 배포에서 `bootroot infra up`으로도 스택을 시작하기 전에 거부되므로",
                    "거부되므로 어떤 컨테이너도 시작되지 않습니다.",
                    "`create_host_path: false`는 생성만 통제하므로",
                    "레코드를 예약량으로 옮길 때까지 이 노출은 남습니다.",
                    "아무것도 삭제·이동되지 않고 그 위로 마운트되지도 않습니다.",
                    "아래 문서화된 절차로 그 레코드를 옮기거나",
                ],
            ),
        ];

        for (manual, heading, required_passages) in manuals {
            let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(manual);
            let source = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()));
            let (_, after_heading) = source
                .split_once(heading)
                .unwrap_or_else(|| panic!("{manual}: existing-records heading is absent"));
            let passage = after_heading
                .split("\n#### ")
                .next()
                .expect("heading always has a following passage");
            let normalized = passage.split_whitespace().collect::<Vec<_>>().join(" ");

            for required in required_passages {
                assert!(
                    normalized.contains(required),
                    "{manual}: missing {required:?}"
                );
            }
            // The procedure has one home, in the passage that follows.
            // Re-spelling any of it here is how two copy procedures over
            // the same irreplaceable data come to disagree.
            assert!(
                !passage.contains("\n```"),
                "{manual}: the existing-records passage must not restate the relocation procedure"
            );
            for command in [
                "`mv ", "`cp ", "`rsync ", "`rm ", "`mount ", "`umount ", "`find ", "`cmp ",
                "`diff ",
            ] {
                assert!(
                    !passage.contains(command),
                    "{manual}: the existing-records passage must not add a relocation command: {command}"
                );
            }
            assert!(
                after_heading.contains("#relocating-a-store-that-already-holds-records")
                    || passage.contains("below"),
                "{manual}: the existing-records passage must point at the relocation procedure"
            );
        }
    }

    #[test]
    fn the_underlying_measurement_counts_hard_links_once_and_stops_at_a_boundary() {
        let messages = test_messages();
        let linked = FileFacts {
            ino: 11,
            blocks: 16,
            ..image_facts(8192, 8192, TEST_UID, 0o600)
        };
        let host = bare_host()
            .entries(
                STORE,
                &[
                    &format!("{STORE}/a"),
                    &format!("{STORE}/b"),
                    &format!("{STORE}/elsewhere"),
                ],
            )
            .file(&format!("{STORE}/a"), linked)
            .file(&format!("{STORE}/b"), linked)
            .file(
                &format!("{STORE}/elsewhere"),
                FileFacts {
                    dev: 999,
                    ino: 12,
                    blocks: 1 << 20,
                    ..image_facts(8192, 8192, TEST_UID, 0o600)
                },
            );
        assert_eq!(
            measure_underlying(Path::new(STORE), &host, &messages).expect("measured"),
            16 * ST_BLOCKS_UNIT_BYTES
        );
    }

    #[test]
    fn an_underlying_store_larger_than_the_reserve_fails_before_anything_is_rendered() {
        let fixture = Fixture {
            reserve_bytes: MIN_RESERVE_FLOOR_BYTES + 1,
            max_file_bytes: 65536,
            max_retained_files: 1,
            ..Fixture::default()
        };
        let messages = test_messages();
        let host = bare_host().entries(STORE, &[&format!("{STORE}/big")]).file(
            &format!("{STORE}/big"),
            FileFacts {
                ino: 21,
                blocks: (MIN_RESERVE_FLOOR_BYTES * 4) / ST_BLOCKS_UNIT_BYTES,
                ..image_facts(4096, 4096, TEST_UID, 0o600)
            },
        );
        let error = evaluate(&fixture.inputs(), &host, &messages).expect_err("refused");
        let text = error.to_string();
        assert!(
            text.contains(&(MIN_RESERVE_FLOOR_BYTES * 4).to_string()),
            "{text}"
        );
        assert!(text.contains(&fixture.reserve_bytes.to_string()), "{text}");
    }

    #[test]
    fn an_unreadable_path_is_never_reported_as_an_absent_one() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();

        // The image.
        let host = bare_host().deny(IMAGE);
        let error = evaluate(&inputs, &host, &messages).expect_err("refused");
        assert!(
            error.to_string().contains("reported as unreadable"),
            "{error}"
        );
        assert!(error.to_string().contains(IMAGE), "{error}");

        // The underlying store.
        let host = bare_host().deny(STORE);
        let error = evaluate(&inputs, &host, &messages).expect_err("refused");
        assert!(error.to_string().contains(STORE), "{error}");

        // `/proc/self/mounts`.
        let mut host = bare_host();
        host.mounts_denied = true;
        let error = evaluate(&inputs, &host, &messages).expect_err("refused");
        assert!(error.to_string().contains(PROC_SELF_MOUNTS), "{error}");

        // The sysfs backing file.
        let mut host = mounted_host("/dev/loop0", "ext4", Some(IMAGE));
        host.backing_denied = true;
        let error = evaluate_mount(&fixture.store, Path::new(IMAGE), &host, &messages)
            .expect_err("refused");
        assert!(error.to_string().contains("backing_file"), "{error}");

        // An installed artifact, and a subdirectory.
        for denied_path in [
            "/etc/systemd/system/docker.service.d/10-bootroot-audit-store.conf",
            "/var/lib/bootroot/audit-store/records",
        ] {
            let (base, facts, artifacts) = activated_host(&fixture);
            let host = base.deny(denied_path);
            let error = verify(&inputs, &facts, &artifacts, &host, &messages).expect_err("refused");
            assert!(error.to_string().contains(denied_path), "{error}");
        }
    }

    #[test]
    fn the_directory_outcome_names_the_store_the_reserve_and_the_quota_route() {
        let store = Path::new(STORE);
        let text = render_directory_outcome(
            store,
            DEFAULT_RESERVE,
            &MigrationPresence::none(store),
            &test_messages(),
        );
        assert!(text.contains("unenforced (directory)"), "{text}");
        assert!(text.contains(STORE), "{text}");
        assert!(text.contains(&DEFAULT_RESERVE.to_string()), "{text}");
        assert!(text.contains("project quota"), "{text}");
        assert!(!text.contains(".img"), "{text}");
        assert!(!text.contains(".pre-mount"), "{text}");
    }

    #[test]
    fn a_directory_mode_run_still_names_an_unfinished_migration() {
        let store = Path::new(STORE);
        let messages = test_messages();
        let migration = MigrationPresence {
            paths: migration::derive_paths(store),
            holding: true,
            migrated: false,
        };
        let text = render_directory_outcome(store, DEFAULT_RESERVE, &migration, &messages);
        // A success still: `directory` mode reports no outcome of its
        // own for this, and the holding directory is named rather than
        // left to be mistaken for debris.
        assert!(text.contains("unenforced (directory)"), "{text}");
        assert!(text.contains(&format!("{STORE}.pre-mount")), "{text}");
        assert!(text.contains("only copy"), "{text}");
    }

    #[test]
    fn a_word_pasted_into_a_shell_survives_a_quote_in_the_path() {
        assert_eq!(sh_quote("plain"), "'plain'");
        assert_eq!(sh_quote("a'b"), "'a'\\''b'");
        assert_eq!(
            sh_quote_path(Path::new("/srv/a b/store")),
            "'/srv/a b/store'"
        );
        // Unquoted, `sh` eats the backslash in `\x2d`.
        assert_eq!(sh_quote(UNIT), format!("'{UNIT}'"));
    }

    #[test]
    fn the_mount_table_parser_decodes_the_kernels_octal_escapes() {
        assert_eq!(decode_mount_field("a\\040b"), b"a b".to_vec());
        assert_eq!(decode_mount_field("a\\011b"), b"a\tb".to_vec());
        assert_eq!(decode_mount_field("a\\012b"), b"a\nb".to_vec());
        assert_eq!(decode_mount_field("a\\134b"), b"a\\b".to_vec());
        // Not three octal digits: left exactly as it was.
        assert_eq!(decode_mount_field("a\\09b"), b"a\\09b".to_vec());
        assert_eq!(decode_mount_field("a\\40"), b"a\\40".to_vec());
    }

    const HOLDING: &str = "/var/lib/bootroot/audit-store.pre-mount";
    const MIGRATED: &str = "/var/lib/bootroot/audit-store.migrated";

    /// Adds a holding directory holding one file under `records/`, on
    /// the device the store's *parent* filesystem uses.
    fn with_holding(host: FakeProbe, blocks: u64) -> FakeProbe {
        host.file(
            HOLDING,
            FileFacts {
                ino: 90,
                ..dir_facts(TEST_UID, 0o700)
            },
        )
        .entries(HOLDING, &[&format!("{HOLDING}/records")])
        .file(
            &format!("{HOLDING}/records"),
            FileFacts {
                ino: 91,
                ..dir_facts(TEST_UID, 0o700)
            },
        )
        .entries(
            &format!("{HOLDING}/records"),
            &[&format!("{HOLDING}/records/audit.log")],
        )
        .file(
            &format!("{HOLDING}/records/audit.log"),
            FileFacts {
                kind: FileKind::Regular,
                size: blocks.saturating_mul(ST_BLOCKS_UNIT_BYTES),
                blocks,
                uid: TEST_UID,
                mode: 0o600,
                dev: 64,
                ino: 92,
                rdev: 0,
            },
        )
    }

    /// An activated host on which the operator has renamed the store
    /// aside: image correct, artifacts installed, mount up, and a
    /// holding directory beside it.
    fn migrating_host(
        fixture: &Fixture,
        blocks: u64,
    ) -> (FakeProbe, Phase1Facts, Vec<RenderedArtifact>) {
        let (host, mut facts, artifacts) = activated_host(fixture);
        facts.migration = MigrationPresence {
            paths: migration::derive_paths(Path::new(STORE)),
            holding: true,
            migrated: false,
        };
        (with_holding(host, blocks), facts, artifacts)
    }

    fn migration_report_of(
        fixture: &Fixture,
        facts: &Phase1Facts,
        artifacts: &[RenderedArtifact],
        host: &FakeProbe,
    ) -> (Vec<String>, Vec<Phase2Step>) {
        let inputs = fixture.inputs();
        let messages = test_messages();
        let report = verify(&inputs, facts, artifacts, host, &messages).expect("phase 3");
        match report {
            ReserveReport::MigrationIncomplete { findings, steps } => (findings, steps),
            other => panic!("expected migration incomplete, got {other:?}"),
        }
    }

    fn step_of(steps: &[Phase2Step], kind: Phase2StepKind) -> &Phase2Step {
        steps
            .iter()
            .find(|step| step.kind == kind)
            .unwrap_or_else(|| panic!("no {kind:?} step in {steps:?}"))
    }

    #[test]
    fn a_holding_directory_overrides_an_otherwise_complete_reserve() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();

        // The same host, twice: with the holding directory it is
        // migration incomplete, without it the reserve is enforced.
        let (host, facts, artifacts) = activated_host(&fixture);
        assert!(matches!(
            verify(&inputs, &facts, &artifacts, &host, &messages).expect("phase 3"),
            ReserveReport::Enforced { .. }
        ));

        let (host, facts, artifacts) = migrating_host(&fixture, 8);
        let report = verify(&inputs, &facts, &artifacts, &host, &messages).expect("phase 3");
        let ReserveReport::MigrationIncomplete { findings, .. } = &report else {
            panic!("a holding directory overrides every other verdict: {report:?}");
        };
        assert!(findings.iter().any(|finding| finding.contains(HOLDING)));
        let text = render_filesystem_outcome(&inputs, &facts, &artifacts, &report, &messages);
        assert!(text.contains("migration incomplete"), "{text}");
        assert!(!text.contains("enforced (filesystem)"), "{text}");
    }

    #[test]
    fn phase_one_reads_the_holding_directory_before_any_other_verdict() {
        // A reserve below the minimum is a phase-1 refusal; the
        // holding-directory read still happens first, so it can never
        // be a verdict reached after another one.
        let fixture = Fixture {
            reserve_bytes: 1,
            ..Fixture::default()
        };
        let inputs = fixture.inputs();
        let host = with_holding(bare_host(), 8).deny(HOLDING);
        let error = evaluate(&inputs, &host, &test_messages()).expect_err("refused");
        assert!(error.to_string().contains(HOLDING), "{error}");
    }

    #[test]
    fn the_activation_is_rendered_under_migration_incomplete_without_the_subdirectory_step() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();
        // The store renamed aside, the mount not yet up: what is
        // outstanding is the activation itself.
        let host = with_holding(bare_host(), 8);
        let facts = evaluate(&inputs, &host, &messages).expect("phase 1");
        assert!(facts.migration_open());
        assert_eq!(facts.underlying, UnderlyingState::Empty);
        let artifacts = render_artifacts(&inputs, &facts);
        let (findings, steps) = migration_report_of(&fixture, &facts, &artifacts, &host);
        // Exactly the activation, with the subdirectory step withheld
        // and nothing else changed.
        assert_eq!(
            steps.iter().map(|step| step.kind).collect::<Vec<_>>(),
            vec![
                Phase2StepKind::StopWriters,
                Phase2StepKind::Image,
                Phase2StepKind::InstallUnits,
                Phase2StepKind::ReRun,
                Phase2StepKind::Rollback,
            ],
            "{steps:?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.contains("The reserve is not mounted yet")),
            "{findings:?}"
        );
        let install = step_of(&steps, Phase2StepKind::InstallUnits);
        assert!(
            install
                .commands
                .iter()
                .any(|command| command == "systemctl daemon-reload")
        );
        assert!(
            install
                .commands
                .iter()
                .any(|command| command.starts_with("systemctl enable --now "))
        );
        assert!(
            step_of(&steps, Phase2StepKind::Image)
                .commands
                .iter()
                .any(|command| command.contains("mkfs.ext4"))
        );
        // Nothing creates, chmods or chowns `records/` or `openbao/`,
        // and no `chmod` of the mount point is rendered either: the copy
        // applies the source directory's own mode and owner to the
        // destination root.
        let rendered: Vec<&String> = steps.iter().flat_map(|step| &step.commands).collect();
        for forbidden in [
            format!("{STORE}/records"),
            format!("{STORE}/openbao"),
            format!("chmod 0700 '{STORE}'"),
        ] {
            assert!(
                rendered.iter().all(|command| !command.contains(&forbidden)),
                "{forbidden} in {rendered:?}"
            );
        }
        // The same host without a holding directory renders the
        // subdirectory step as usual.
        let plain = bare_host();
        let plain_facts = evaluate(&inputs, &plain, &messages).expect("phase 1");
        let plain_artifacts = render_artifacts(&inputs, &plain_facts);
        let report =
            verify(&inputs, &plain_facts, &plain_artifacts, &plain, &messages).expect("phase 3");
        let ReserveReport::NotActivated { steps, .. } = report else {
            panic!("a fresh host is not activated");
        };
        assert!(
            step_of(&steps, Phase2StepKind::Subdirectories)
                .commands
                .iter()
                .any(|command| command == &format!("mkdir '{STORE}/records'")),
            "{steps:?}"
        );
    }

    #[test]
    fn the_mounted_pass_renders_the_copy_the_verification_and_the_closing_rename() {
        let fixture = Fixture::default();
        let (host, facts, artifacts) = migrating_host(&fixture, 8);
        let (findings, steps) = migration_report_of(&fixture, &facts, &artifacts, &host);
        assert_eq!(
            steps.iter().map(|step| step.kind).collect::<Vec<_>>(),
            vec![
                Phase2StepKind::StopWriters,
                Phase2StepKind::TypeGuard,
                Phase2StepKind::Copy,
                Phase2StepKind::Verify,
                Phase2StepKind::ClosingRename,
                Phase2StepKind::ReRun,
                Phase2StepKind::Rollback,
            ],
            "{steps:?}"
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.contains("The contents fit")),
            "{findings:?}"
        );
        // The closing rename is its own step, never chained onto the
        // copy or the verification.
        assert_eq!(
            step_of(&steps, Phase2StepKind::ClosingRename).commands,
            vec![format!("mv '{HOLDING}' '{MIGRATED}'")]
        );
        assert_eq!(
            step_of(&steps, Phase2StepKind::Rollback).commands,
            vec![
                format!("umount '{STORE}'"),
                format!("rmdir '{STORE}'"),
                format!("mv '{HOLDING}' '{STORE}'"),
            ]
        );
    }

    #[test]
    fn the_rendered_migration_commands_are_pinned_exactly() {
        let fixture = Fixture::default();
        let (host, facts, artifacts) = migrating_host(&fixture, 8);
        let (_, steps) = migration_report_of(&fixture, &facts, &artifacts, &host);
        let guard =
            format!("find '{HOLDING}' -xdev -mindepth 1 ! -type d ! -type f -exec false {{}} +");
        assert_eq!(
            step_of(&steps, Phase2StepKind::TypeGuard).commands,
            vec![guard.clone()]
        );
        assert_eq!(
            step_of(&steps, Phase2StepKind::Copy).commands,
            vec![format!("cp -a --one-file-system '{HOLDING}/.' '{STORE}/'")]
        );
        assert_eq!(
            step_of(&steps, Phase2StepKind::Verify).commands,
            vec![
                "SCRATCH=\"$(mktemp -d)\"".to_string(),
                guard,
                format!(
                    "find '{STORE}' -xdev -mindepth 1 ! -type d ! -type f -exec false {{}} +"
                ),
                format!("cd '{HOLDING}'"),
                "find . -xdev -mindepth 1 -printf '%y %m %U %G %n %P\\0' > \"$SCRATCH\"/meta.source.raw".to_string(),
                "sort -z -o \"$SCRATCH\"/meta.source \"$SCRATCH\"/meta.source.raw".to_string(),
                "find . -xdev -mindepth 1 -type f -printf '%s %P\\0' > \"$SCRATCH\"/size.source.raw".to_string(),
                "sort -z -o \"$SCRATCH\"/size.source \"$SCRATCH\"/size.source.raw".to_string(),
                "find . -xdev -mindepth 1 -type f -print0 > \"$SCRATCH\"/files.source.raw".to_string(),
                "sort -z -o \"$SCRATCH\"/files.source \"$SCRATCH\"/files.source.raw".to_string(),
                "xargs -0 -r sha256sum --binary --zero < \"$SCRATCH\"/files.source > \"$SCRATCH\"/content.source".to_string(),
                format!("cd '{STORE}'"),
                "find . -xdev -mindepth 1 -printf '%y %m %U %G %n %P\\0' > \"$SCRATCH\"/meta.destination.raw".to_string(),
                "sort -z -o \"$SCRATCH\"/meta.destination \"$SCRATCH\"/meta.destination.raw".to_string(),
                "find . -xdev -mindepth 1 -type f -printf '%s %P\\0' > \"$SCRATCH\"/size.destination.raw".to_string(),
                "sort -z -o \"$SCRATCH\"/size.destination \"$SCRATCH\"/size.destination.raw".to_string(),
                "find . -xdev -mindepth 1 -type f -print0 > \"$SCRATCH\"/files.destination.raw".to_string(),
                "sort -z -o \"$SCRATCH\"/files.destination \"$SCRATCH\"/files.destination.raw".to_string(),
                "xargs -0 -r sha256sum --binary --zero < \"$SCRATCH\"/files.destination > \"$SCRATCH\"/content.destination".to_string(),
                "cmp \"$SCRATCH\"/meta.source \"$SCRATCH\"/meta.destination".to_string(),
                "cmp \"$SCRATCH\"/size.source \"$SCRATCH\"/size.destination".to_string(),
                "cmp \"$SCRATCH\"/content.source \"$SCRATCH\"/content.destination".to_string(),
            ]
        );
        // No pipe anywhere, no `diff -r`, no recursive delete, and no
        // field after `%P`.
        for command in steps.iter().flat_map(|step| &step.commands) {
            assert!(!command.contains('|'), "{command}");
            assert!(!command.contains("diff -r"), "{command}");
            assert!(!command.contains("rm -r"), "{command}");
            assert!(!command.contains("rm -f"), "{command}");
            assert!(!command.contains("%P "), "{command}");
        }
    }

    #[test]
    fn the_capacity_verdict_is_against_the_mounted_filesystem_and_not_the_reserve() {
        let fixture = Fixture::default();
        let margin = super::migration::COPY_MARGIN_BYTES;
        // `records/` and the file beneath it; the holding directory's
        // own root is not part of what has to fit on the destination.
        let source = 2 * 8 * ST_BLOCKS_UNIT_BYTES;

        // (available bytes, whether the copy is rendered)
        let cases: [(u64, bool); 4] = [
            (source + margin, true),
            (source + margin - 1, false),
            // Under `audit_store_reserve_bytes` but over what the
            // mounted filesystem actually has: the case a check
            // against the reserve would wrongly pass.
            (1024, false),
            (source, false),
        ];
        for (available, renders_copy) in cases {
            let (base, facts, artifacts) = migrating_host(&fixture, 8);
            let mut host = base;
            host.space.insert(
                PathBuf::from(STORE),
                FsSpace {
                    blocks_available: available,
                    fragment_size: 1,
                },
            );
            let (findings, steps) = migration_report_of(&fixture, &facts, &artifacts, &host);
            assert_eq!(
                steps.iter().any(|step| step.kind == Phase2StepKind::Copy),
                renders_copy,
                "available {available}: {steps:?}"
            );
            let joined = findings.join("\n");
            for figure in [available, source, margin] {
                assert!(joined.contains(&figure.to_string()), "{joined}");
            }
            assert!(fixture.reserve_bytes > available || renders_copy);
            if !renders_copy {
                assert!(joined.contains("do not fit"), "{joined}");
                assert!(joined.contains("audit_store_reserve_bytes"), "{joined}");
            }
        }
    }

    #[test]
    fn a_forbidden_entry_refuses_the_copy_on_every_pass() {
        let fixture = Fixture::default();
        for (kind, needle) in [
            (FileKind::Symlink, "a symbolic link"),
            (FileKind::Other, "neither a regular file nor a directory"),
        ] {
            let (base, facts, artifacts) = migrating_host(&fixture, 8);
            let planted = format!("{HOLDING}/records/planted");
            let host = base
                .entries(
                    &format!("{HOLDING}/records"),
                    &[&format!("{HOLDING}/records/audit.log"), &planted],
                )
                .file(
                    &planted,
                    FileFacts {
                        kind,
                        ino: 93,
                        ..dir_facts(TEST_UID, 0o777)
                    },
                );
            // Twice over, from the same probe: the entry walk is re-run
            // rather than answered from a cached verdict.
            for _ in 0..2 {
                let (findings, steps) = migration_report_of(&fixture, &facts, &artifacts, &host);
                assert!(!steps.iter().any(|step| step.kind == Phase2StepKind::Copy));
                let joined = findings.join("\n");
                assert!(joined.contains(&planted), "{joined}");
                assert!(joined.contains(needle), "{joined}");
            }
        }
    }

    #[test]
    fn a_same_device_bind_mount_under_the_holding_directory_refuses_the_copy() {
        let fixture = Fixture::default();
        let bind = format!("{HOLDING}/records/bound");
        let sibling = format!("{HOLDING}-other");
        for (mountinfo, refused) in [
            (
                format!(
                    "36 35 0:64 / {bind} rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                     37 35 0:64 / {sibling} rw,relatime shared:2 - ext4 /dev/sda1 rw\n"
                ),
                true,
            ),
            (
                format!("37 35 0:64 / {sibling} rw,relatime shared:2 - ext4 /dev/sda1 rw\n"),
                false,
            ),
        ] {
            let (base, facts, artifacts) = migrating_host(&fixture, 8);
            // Same device as the holding directory throughout, which is
            // exactly what an `st_dev` predicate would pass.
            let host = base.mountinfo(&mountinfo);
            let (findings, steps) = migration_report_of(&fixture, &facts, &artifacts, &host);
            let joined = findings.join("\n");
            if refused {
                assert!(!steps.iter().any(|step| step.kind == Phase2StepKind::Copy));
                assert!(joined.contains(&bind), "{joined}");
            } else {
                assert!(steps.iter().any(|step| step.kind == Phase2StepKind::Copy));
                assert!(!joined.contains(&sibling), "{joined}");
            }
        }
    }

    #[test]
    fn every_byte_figure_the_capacity_verdict_rests_on_is_checked() {
        let fixture = Fixture::default();
        let cases: [(FsSpace, u64, &str); 3] = [
            // `f_bavail` × `f_frsize` past `u64::MAX`.
            (
                FsSpace {
                    blocks_available: u64::MAX,
                    fragment_size: 2,
                },
                8,
                "the space available on the filesystem",
            ),
            // `st_blocks` × 512 past `u64::MAX`.
            (
                FsSpace {
                    blocks_available: 1 << 40,
                    fragment_size: 4096,
                },
                u64::MAX,
                "the size of what",
            ),
            // The sum over unique entries overflowing.
            (
                FsSpace {
                    blocks_available: 1 << 40,
                    fragment_size: 4096,
                },
                u64::MAX / ST_BLOCKS_UNIT_BYTES,
                "the size of what",
            ),
        ];
        for (space, blocks, needle) in cases {
            let (base, facts, artifacts) = migrating_host(&fixture, blocks);
            let mut host = base;
            host.space.insert(PathBuf::from(STORE), space);
            let (findings, steps) = migration_report_of(&fixture, &facts, &artifacts, &host);
            assert!(!steps.iter().any(|step| step.kind == Phase2StepKind::Copy));
            let joined = findings.join("\n");
            assert!(joined.contains(needle), "{joined}");
            assert!(
                joined.contains("cannot be represented as a 64-bit byte count"),
                "{joined}"
            );
        }
    }

    #[test]
    fn a_source_figure_one_below_the_ceiling_refuses_the_copy_on_the_margin() {
        let fixture = Fixture::default();
        let (base, mut facts, artifacts) = activated_host(&fixture);
        facts.migration = MigrationPresence {
            paths: migration::derive_paths(Path::new(STORE)),
            holding: true,
            migrated: false,
        };
        // One entry whose allocated size is `u64::MAX - 1`, so the
        // source figure is representable and source + margin is not.
        let host = base
            .file(
                HOLDING,
                FileFacts {
                    ino: 90,
                    ..dir_facts(TEST_UID, 0o700)
                },
            )
            .entries(HOLDING, &[&format!("{HOLDING}/huge")])
            .file(
                &format!("{HOLDING}/huge"),
                FileFacts {
                    kind: FileKind::Regular,
                    size: u64::MAX,
                    blocks: (u64::MAX - 1) / ST_BLOCKS_UNIT_BYTES,
                    uid: TEST_UID,
                    mode: 0o600,
                    dev: 64,
                    ino: 92,
                    rdev: 0,
                },
            );
        let mut host = host;
        host.space.insert(
            PathBuf::from(STORE),
            FsSpace {
                blocks_available: u64::MAX,
                fragment_size: 1,
            },
        );
        let (findings, steps) = migration_report_of(&fixture, &facts, &artifacts, &host);
        assert!(!steps.iter().any(|step| step.kind == Phase2StepKind::Copy));
        assert!(
            findings.join("\n").contains("plus the copy margin"),
            "{findings:?}"
        );
    }

    #[test]
    fn a_pre_existing_migrated_path_withholds_every_rename() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();

        // Opening the migration: the entry is refused rather than
        // started against a closing rename that could never run.
        let host = bare_host()
            .entries(STORE, &[&format!("{STORE}/records")])
            .file(
                &format!("{STORE}/records"),
                FileFacts {
                    ino: 40,
                    ..dir_facts(TEST_UID, 0o700)
                },
            )
            .file(
                MIGRATED,
                FileFacts {
                    ino: 95,
                    ..dir_facts(TEST_UID, 0o700)
                },
            );
        let facts = evaluate(&inputs, &host, &messages).expect("phase 1");
        let artifacts = render_artifacts(&inputs, &facts);
        let report = verify(&inputs, &facts, &artifacts, &host, &messages).expect("phase 3");
        let ReserveReport::NotActivated {
            findings,
            steps,
            steps_withheld,
            ..
        } = &report
        else {
            panic!("a non-empty store is not activated");
        };
        assert!(steps.is_empty(), "{steps:?}");
        assert!(steps_withheld);
        assert!(findings.iter().any(|finding| finding.contains(MIGRATED)));

        // And mid-migration: the copy is still rendered, but nothing
        // renames onto the path that already exists.
        let (base, facts, artifacts) = migrating_host(&fixture, 8);
        let mut facts = facts;
        facts.migration.migrated = true;
        let host = base.file(
            MIGRATED,
            FileFacts {
                ino: 95,
                ..dir_facts(TEST_UID, 0o700)
            },
        );
        let (findings, steps) = migration_report_of(&fixture, &facts, &artifacts, &host);
        assert!(steps.iter().any(|step| step.kind == Phase2StepKind::Copy));
        assert!(
            !steps
                .iter()
                .any(|step| step.kind == Phase2StepKind::ClosingRename),
            "{steps:?}"
        );
        assert!(findings.iter().any(|finding| finding.contains(MIGRATED)));
    }

    #[test]
    fn a_migrated_directory_clears_the_outcome_and_is_reported_as_reclaimable() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();
        let (base, mut facts, artifacts) = activated_host(&fixture);
        facts.migration.migrated = true;
        let host = base
            .file(
                MIGRATED,
                FileFacts {
                    ino: 95,
                    ..dir_facts(TEST_UID, 0o700)
                },
            )
            .entries(MIGRATED, &[&format!("{MIGRATED}/records")])
            .file(
                &format!("{MIGRATED}/records"),
                FileFacts {
                    ino: 96,
                    blocks: 16,
                    ..dir_facts(TEST_UID, 0o700)
                },
            );
        let report = verify(&inputs, &facts, &artifacts, &host, &messages).expect("phase 3");
        let ReserveReport::Enforced { notes } = &report else {
            panic!("a closed migration does not hold the outcome: {report:?}");
        };
        let joined = notes.join("\n");
        assert!(joined.contains(MIGRATED), "{joined}");
        assert!(
            joined.contains(&(16 * ST_BLOCKS_UNIT_BYTES).to_string()),
            "{joined}"
        );
        let text = render_filesystem_outcome(&inputs, &facts, &artifacts, &report, &messages);
        assert!(text.contains("Reclaimable"), "{text}");
        assert!(!text.contains("migration incomplete"), "{text}");
    }

    #[test]
    fn a_partial_copy_re_renders_the_copy_and_the_verification_unchanged() {
        // Resume is not a separate rendering: the copy and the
        // verification are idempotent, so a pass over a partially
        // populated destination renders exactly what the first pass
        // did, and the holding directory is untouched either way.
        let fixture = Fixture::default();
        let (base, facts, artifacts) = migrating_host(&fixture, 8);
        let (_, fresh) = migration_report_of(&fixture, &facts, &artifacts, &base);
        let partial = base
            .file(
                &format!("{STORE}/records"),
                FileFacts {
                    ino: 70,
                    ..dir_facts(TEST_UID, 0o700)
                },
            )
            .entries(
                &format!("{STORE}/records"),
                &[&format!("{STORE}/records/audit.log")],
            );
        let (_, resumed) = migration_report_of(&fixture, &facts, &artifacts, &partial);
        assert_eq!(fresh, resumed);
        assert!(resumed.iter().any(|step| step.kind == Phase2StepKind::Copy));
        assert!(
            resumed
                .iter()
                .any(|step| step.kind == Phase2StepKind::Rollback)
        );
    }

    #[test]
    fn rollback_is_offered_only_while_the_holding_directory_is_open() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();
        // Once the closing rename has run there is nothing to roll back
        // to: the store is authoritative.
        let (base, mut facts, artifacts) = activated_host(&fixture);
        facts.migration.migrated = true;
        let host = base.file(
            MIGRATED,
            FileFacts {
                ino: 95,
                ..dir_facts(TEST_UID, 0o700)
            },
        );
        let report = verify(&inputs, &facts, &artifacts, &host, &messages).expect("phase 3");
        let text = render_filesystem_outcome(&inputs, &facts, &artifacts, &report, &messages);
        assert!(!text.contains("umount"), "{text}");
        assert!(!text.contains("rmdir"), "{text}");
    }

    #[test]
    fn the_migration_outcome_states_its_window_and_its_prerequisites() {
        let fixture = Fixture::default();
        let inputs = fixture.inputs();
        let messages = test_messages();
        let (host, facts, artifacts) = migrating_host(&fixture, 8);
        let report = verify(&inputs, &facts, &artifacts, &host, &messages).expect("phase 3");
        let text = render_filesystem_outcome(&inputs, &facts, &artifacts, &report, &messages);
        assert!(text.contains("diffutils"), "{text}");
        assert!(text.contains("coreutils 8.25"), "{text}");
        assert!(text.contains("not unconditionally"), "{text}");
        assert!(text.contains("no privileged mount change"), "{text}");
    }
}
