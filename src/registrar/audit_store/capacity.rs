//! The reserved audit store's capacity probe and its low-water alarm.
//!
//! The store's reserve is a ceiling, and a ceiling tells nobody it is
//! about to be reached. This module measures how much of it is left and
//! decides when to say so, on the daemon's existing maintenance tick;
//! `src/daemon.rs` writes the result onto the health snapshot the
//! registrar endpoint already relays.
//!
//! # Two numbers, one descriptor
//!
//! A reading is a [`CapacityMeasurement`]: the store's usage, and the
//! bytes the backing filesystem still has for an unprivileged writer.
//! Both come from one open descriptor for `audit_store_dir`, opened
//! once per tick with `O_NOFOLLOW`, because the two halves of
//! [`headroom_bytes`] only describe one object if they were derived
//! from one resolution of the configured path. A symbolic link at the
//! store root is therefore an `ELOOP` from that open and a failed probe
//! in both enforcement modes, which is what the store contract already
//! says about a link planted there.
//!
//! Usage is measured per enforcement mode, because `statvfs` describes
//! a filesystem and not a subtree:
//!
//! - Under [`AuditStoreEnforcement::Filesystem`] the store is its own
//!   filesystem, so `(f_blocks - f_bfree) * f_frsize` from the same
//!   `fstatvfs` call answers it exactly. Nothing is enumerated.
//! - Under [`AuditStoreEnforcement::Directory`] the store shares the
//!   host's root filesystem, where those fields measure the host. Usage
//!   is walked instead, summing allocated blocks — `st_blocks *
//!   `[`ST_BLOCKS_UNIT_BYTES`] — so a sparse or block-rounded file is
//!   not under-counted against a ceiling the kernel enforces in blocks.
//!
//! # Why the walk descends by descriptor
//!
//! `openbao/` is owned by the `OpenBao` container's uid by design, so
//! every entry the container writes there is inside the subtree this
//! walk sums, and a compromised container writes there too. Each
//! directory is opened with `openat` from its parent's descriptor and
//! enumerated with `fdopendir`/`readdir` on that same descriptor, so
//! the object classified is the object traversed: a path-based `lstat`
//! followed by a path-based listing can be raced, and in `directory`
//! mode a followed link to `/` would sum the whole root filesystem into
//! `used_bytes`, report `exhausted` and refuse every registrar verb.
//!
//! This is deliberately a second implementation of "sum a subtree's
//! allocated blocks". `measure_underlying` in
//! `src/commands/audit_store/reserve.rs` is `pub(super)` in the binary
//! crate and answers a different question under different rules: it is
//! path-based, runs once under an operator's `bootroot init` on a store
//! nothing is writing to, and fails on an arithmetic overflow, while
//! this one runs unattended every minute against a live, partly
//! attacker-writable subtree and saturates instead.
//!
//! # The alarm
//!
//! [`headroom_bytes`] is the smaller of the configured budget's
//! remainder and the device's available bytes, and [`next_state`]
//! turns it into one of the four [`AuditCapacityState`] values under
//! three ordered rules, with hysteresis on the way back up so a store
//! hovering at the threshold does not flap an operator's console. A
//! failed probe leaves the previous state in place: an alarm must not
//! be hidden behind the failure of the thing that raises it.

use std::collections::HashSet;
use std::ffi::{CStr, CString, OsStr, OsString};
use std::io;
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::AuditStoreEnforcement;

/// The fixed unit `st_blocks` is counted in, by POSIX.
///
/// Independent of the filesystem's own `f_frsize`, which is why it is a
/// constant here rather than a value read from `statvfs`.
pub(crate) const ST_BLOCKS_UNIT_BYTES: u64 = 512;

/// The floor under the hysteresis margin, in bytes.
///
/// `audit_store_low_water_bytes / 10` truncates to zero for any
/// configured threshold below ten bytes, which would silently delete
/// the anti-flap rule the margin exists to provide. 1 MiB is chosen
/// because it is far larger than any single record this store can
/// append, so no single write can carry the store across the clear
/// threshold and back.
pub(crate) const AUDIT_STORE_MIN_HYSTERESIS_MARGIN_BYTES: u64 = 1_048_576;

/// The current directory entry `readdir` returns, skipped by name.
const CURRENT_DIR_ENTRY: &[u8] = b".";
/// The parent directory entry `readdir` returns, skipped by name.
const PARENT_DIR_ENTRY: &[u8] = b"..";

/// The capacity alarm's state for one store.
///
/// The four values are decided by [`next_state`], never by a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AuditCapacityState {
    /// No capacity probe has succeeded yet.
    ///
    /// The only state in which the measured members are absent, so that
    /// "we have not measured" is never encoded as [`Self::Ok`].
    #[default]
    Unknown,
    /// Headroom is above the threshold, or above the clear threshold
    /// when an alarm is being cleared.
    Ok,
    /// The alarm is on, and the reserve is not yet consumed.
    LowWater,
    /// The store is at or past its reserve.
    Exhausted,
}

/// One capacity probe's two numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapacityMeasurement {
    /// The store's measured usage, in bytes.
    pub(crate) used_bytes: u64,
    /// The bytes the backing filesystem has for an unprivileged writer.
    pub(crate) available_bytes: u64,
}

/// What one successful probe decides about the store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CapacityReading {
    /// The alarm state the probe leaves the store in.
    pub(crate) state: AuditCapacityState,
    /// The store's measured usage, in bytes.
    pub(crate) used_bytes: u64,
    /// The headroom [`headroom_bytes`] computed, which is signed
    /// because a store past its reserve has less than none.
    pub(crate) headroom_bytes: i64,
}

/// A source of the two capacity numbers for a store directory.
///
/// The alarm and its hysteresis are driven against this trait rather
/// than against a filesystem, so "the alarm fires before the reserve is
/// consumed" is an ordinary test needing no special filesystem, no root
/// and no container.
pub(crate) trait CapacityProbe {
    /// Measures `store_dir` under `enforcement`.
    ///
    /// # Errors
    ///
    /// Returns the underlying error for a store root that cannot be
    /// opened, stat-ed or read, and for any walk step that failed for a
    /// reason other than an entry vanishing under it.
    fn measure(
        &self,
        store_dir: &Path,
        enforcement: AuditStoreEnforcement,
    ) -> io::Result<CapacityMeasurement>;
}

// ---------------------------------------------------------------------
// Arithmetic
// ---------------------------------------------------------------------

/// Widens one platform-sized C field to `u64`, falling back to
/// `fallback` where it does not fit.
///
/// These field types differ by platform — `f_bavail` is 32 bits on some
/// targets and 64 on others, and `st_dev` is signed on one of them — so
/// a bare `From` is redundant on one target and required on the next,
/// while `as` would be a silent truncation waiting for the platform
/// where the value does not fit.
fn widen_platform_field<T>(value: T, fallback: u64) -> u64
where
    u64: TryFrom<T>,
{
    u64::try_from(value).unwrap_or(fallback)
}

/// Multiplies a block count by a block size, saturating at [`u64::MAX`].
///
/// A filesystem reporting a product that overflows 64 bits is reporting
/// something no device holds, so saturating makes that term stop binding
/// in [`headroom_bytes`]'s `min` and lets the reserve term decide.
/// Failing the probe instead would turn an implausible-but-harmless
/// report into [`AuditCapacityState::Unknown`] and drop the alarm.
fn saturating_block_bytes(blocks: u64, block_size: u64) -> u64 {
    blocks.saturating_mul(block_size)
}

/// Returns an entry's allocated bytes from its `st_blocks`.
fn allocated_bytes(blocks: u64) -> u64 {
    saturating_block_bytes(blocks, ST_BLOCKS_UNIT_BYTES)
}

/// Clamps a `u64` byte count into the signed domain the headroom
/// arithmetic works in.
fn clamp_to_signed(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Returns the headroom left in the store, in bytes.
///
/// `min(reserve - used, available)`. The `min` is the point: a reserve
/// larger than the device's free space is not a reserve, and the alarm
/// has to fire on whichever bound binds first. Configuration validation
/// bounds `reserve_bytes` at `i64::MAX`, so it converts exactly; the two
/// filesystem-derived figures are clamped and the subtraction saturates,
/// so a value no device holds cannot wrap into a spurious alarm.
#[must_use]
pub(crate) fn headroom_bytes(reserve_bytes: u64, used_bytes: u64, available_bytes: u64) -> i64 {
    let budget = clamp_to_signed(reserve_bytes).saturating_sub(clamp_to_signed(used_bytes));
    budget.min(clamp_to_signed(available_bytes))
}

/// Returns the hysteresis margin for a configured low-water threshold.
///
/// `max(low_water_bytes / 10, `[`AUDIT_STORE_MIN_HYSTERESIS_MARGIN_BYTES`]`)`,
/// with the division truncating toward zero.
#[must_use]
pub(crate) fn hysteresis_margin_bytes(low_water_bytes: u64) -> u64 {
    (low_water_bytes / 10).max(AUDIT_STORE_MIN_HYSTERESIS_MARGIN_BYTES)
}

/// Returns the state one probe leaves the store in.
///
/// The three rules are evaluated in order:
///
/// 1. Non-positive headroom is [`AuditCapacityState::Exhausted`]. Zero
///    counts as exhausted, not as low water: at zero headroom the next
///    write is already past the reserve.
/// 2. From [`AuditCapacityState::LowWater`] or
///    [`AuditCapacityState::Exhausted`], the state clears to
///    [`AuditCapacityState::Ok`] only at `threshold + margin`. This is
///    the anti-flap rule, and it gates a return *from* an alarm rather
///    than the general route to `ok`, so an exhausted store whose
///    headroom reaches the clear threshold in one probe goes straight
///    to `ok`.
/// 3. From [`AuditCapacityState::Unknown`] or
///    [`AuditCapacityState::Ok`], the state is `ok` above the threshold
///    and [`AuditCapacityState::LowWater`] at or below it. The alarm is
///    therefore on at exactly the configured number, and a cold start
///    has no alarm to clear so the margin is not applied to it.
#[must_use]
pub(crate) fn next_state(
    previous: AuditCapacityState,
    headroom_bytes: i64,
    low_water_bytes: u64,
) -> AuditCapacityState {
    if headroom_bytes <= 0 {
        return AuditCapacityState::Exhausted;
    }
    let threshold = clamp_to_signed(low_water_bytes);
    match previous {
        AuditCapacityState::LowWater | AuditCapacityState::Exhausted => {
            let margin = clamp_to_signed(hysteresis_margin_bytes(low_water_bytes));
            if headroom_bytes >= threshold.saturating_add(margin) {
                AuditCapacityState::Ok
            } else {
                AuditCapacityState::LowWater
            }
        }
        AuditCapacityState::Unknown | AuditCapacityState::Ok => {
            if headroom_bytes > threshold {
                AuditCapacityState::Ok
            } else {
                AuditCapacityState::LowWater
            }
        }
    }
}

/// Turns one measurement into the reading the health snapshot carries.
#[must_use]
pub(crate) fn evaluate(
    previous: AuditCapacityState,
    measurement: CapacityMeasurement,
    reserve_bytes: u64,
    low_water_bytes: u64,
) -> CapacityReading {
    let headroom = headroom_bytes(
        reserve_bytes,
        measurement.used_bytes,
        measurement.available_bytes,
    );
    CapacityReading {
        state: next_state(previous, headroom, low_water_bytes),
        used_bytes: measurement.used_bytes,
        headroom_bytes: headroom,
    }
}

// ---------------------------------------------------------------------
// The syscall seam
// ---------------------------------------------------------------------

/// The `fstat`/`fstatat` fields the walk reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EntryFacts {
    /// `st_dev` — the device the object lives on.
    pub(crate) dev: u64,
    /// `st_ino`.
    pub(crate) ino: u64,
    /// `st_blocks`, in [`ST_BLOCKS_UNIT_BYTES`] units.
    pub(crate) blocks: u64,
    /// Whether the object is a directory, from `st_mode`.
    pub(crate) is_dir: bool,
}

/// The `statvfs` fields the probe reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct FsSpaceFacts {
    /// `f_blocks` — total blocks on the filesystem.
    pub(crate) blocks: u64,
    /// `f_bfree` — free blocks, root's reservation included.
    pub(crate) blocks_free: u64,
    /// `f_bavail` — free blocks available to an unprivileged writer.
    pub(crate) blocks_available: u64,
    /// `f_frsize` — the fragment size those counts are in.
    pub(crate) fragment_size: u64,
}

/// Returns the bytes an unprivileged writer can still use.
///
/// `f_bavail` rather than `f_bfree`: the latter counts the blocks
/// reserved for root, which neither writer of this store can reach.
fn available_bytes(space: &FsSpaceFacts) -> u64 {
    saturating_block_bytes(space.blocks_available, space.fragment_size)
}

/// Returns a whole filesystem's used bytes, which is the store's usage
/// under [`AuditStoreEnforcement::Filesystem`] because the store is that
/// filesystem.
fn filesystem_used_bytes(space: &FsSpaceFacts) -> u64 {
    saturating_block_bytes(
        space.blocks.saturating_sub(space.blocks_free),
        space.fragment_size,
    )
}

/// The walk's own operation set, behind a trait so five behaviours that
/// cannot be staged on disk are testable.
///
/// Those five are a race, a privilege assumption or a process-global
/// observation: `EACCES` on a subdirectory, an entry vanishing between
/// `readdir` and the call that follows it, a directory replaced by a
/// symbolic link mid-walk, `EIO` from `readdir`, and descriptor
/// hygiene. Everything a plain temporary directory already makes
/// deterministic is tested against the real filesystem instead.
///
/// [`SyscallWalkOps`] is the only implementation production reaches, and
/// it has no branch, flag or environment read that would let a deployed
/// daemon take a different path through it.
pub(crate) trait WalkOps {
    /// An open directory, ready to enumerate.
    ///
    /// It exposes its descriptor because the probe's `fstatvfs` is
    /// bound to the store root's own open, never to a second pathname
    /// resolution.
    type Dir: AsFd;

    /// Opens `name` relative to `parent`, or by path when `parent` is
    /// `None`, and returns it ready to enumerate.
    ///
    /// This deliberately spans both `openat` and `fdopendir`, so the
    /// ownership transfer between them has one implementation rather
    /// than one per call site.
    ///
    /// # Errors
    ///
    /// Returns the underlying error, including `ELOOP` for a symbolic
    /// link and `ENOTDIR` for anything that is not a directory.
    fn open_dir(&self, parent: Option<&Self::Dir>, name: &OsStr) -> io::Result<Self::Dir>;

    /// Reads the next entry's name, or `Ok(None)` at end of directory.
    ///
    /// `.` and `..` are returned like any other name; discarding them
    /// is the walk's rule and is stated where a reader can check it.
    ///
    /// # Errors
    ///
    /// Returns the underlying error for a stream that failed mid-read,
    /// which is not the same thing as a short directory.
    fn next_entry(&self, dir: &mut Self::Dir) -> io::Result<Option<OsString>>;

    /// Stats an open directory.
    ///
    /// This is what classifies every directory the walk reaches, the
    /// store root included: the identity and the blocks come from the
    /// descriptor the walk holds, so the object counted is the object
    /// traversed.
    ///
    /// # Errors
    ///
    /// Returns the underlying error.
    fn stat_dir(&self, dir: &Self::Dir) -> io::Result<EntryFacts>;

    /// Stats `name` relative to `parent` without following a symbolic
    /// link.
    ///
    /// # Errors
    ///
    /// Returns the underlying error, `ENOENT` included for an entry
    /// that vanished after `readdir` listed it.
    fn stat_entry(&self, parent: &Self::Dir, name: &OsStr) -> io::Result<EntryFacts>;

    /// Closes an open directory.
    fn close_dir(&self, dir: Self::Dir);
}

/// Returns the thread's `errno` slot.
///
/// `readdir` reports both end-of-directory and failure as a null
/// return, so the slot is zeroed before the call and read back after
/// it. There is no portable spelling of that address, only a
/// per-platform one.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn errno_slot() -> *mut libc::c_int {
    // SAFETY: the call takes no argument and returns the address of this
    // thread's own `errno`, which is valid for the thread's lifetime.
    unsafe { libc::__errno_location() }
}

/// Returns the thread's `errno` slot.
///
/// See the Linux spelling above; Apple's libc names the same accessor
/// differently.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn errno_slot() -> *mut libc::c_int {
    // SAFETY: the call takes no argument and returns the address of this
    // thread's own `errno`, which is valid for the thread's lifetime.
    unsafe { libc::__error() }
}

/// An open directory stream and the descriptor `closedir` releases.
///
/// The descriptor has exactly one owner at every point: `openat`
/// produces it, [`open_stream`] hands it to `fdopendir` by value, and
/// from there `closedir` is the only close.
pub(crate) struct DirStream {
    handle: *mut libc::DIR,
}

impl AsFd for DirStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        // SAFETY: `dirfd` returns the descriptor the stream owns, which
        // stays open for as long as `self` is alive. The borrow does not
        // close it, and its lifetime is tied to `self`.
        unsafe { BorrowedFd::borrow_raw(libc::dirfd(self.handle)) }
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: `self.handle` is a live stream this value owns, and
        // `Drop` runs once, so `closedir` is called exactly once on it.
        unsafe {
            libc::closedir(self.handle);
        }
    }
}

/// Hands `fd` to `fdopendir`, or closes it and reports the failure.
///
/// `fdopendir` takes ownership of the descriptor it is given, so it is
/// handed over with `into_raw_fd`. A null return transfers nothing, and
/// the caller still owns the raw descriptor: reconstructing the
/// [`OwnedFd`] closes it once, structurally, rather than leaking one
/// descriptor per failure on a tick that fires every minute.
fn open_stream(fd: OwnedFd) -> io::Result<DirStream> {
    let raw = fd.into_raw_fd();
    // SAFETY: `raw` is an open directory descriptor that `into_raw_fd`
    // has just released from its `OwnedFd`, so nothing else owns it when
    // `fdopendir` takes ownership of it.
    let handle = unsafe { libc::fdopendir(raw) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: the null return took no ownership, so `raw` is still
        // the open descriptor nothing else owns; the reconstructed
        // `OwnedFd` closes it exactly once as it drops.
        drop(unsafe { OwnedFd::from_raw_fd(raw) });
        return Err(error);
    }
    Ok(DirStream { handle })
}

/// Builds [`EntryFacts`] from a filled `stat` buffer.
fn facts_from_stat(stat: &libc::stat) -> EntryFacts {
    EntryFacts {
        dev: widen_platform_field(stat.st_dev, 0),
        ino: widen_platform_field(stat.st_ino, 0),
        // A negative block count is not a figure any filesystem reports;
        // counting it as zero keeps one implausible entry from deciding
        // the alarm.
        blocks: widen_platform_field(stat.st_blocks, 0),
        is_dir: (stat.st_mode & libc::S_IFMT) == libc::S_IFDIR,
    }
}

/// The real syscalls, and the only implementation production reaches.
pub(crate) struct SyscallWalkOps;

impl WalkOps for SyscallWalkOps {
    type Dir = DirStream;

    fn open_dir(&self, parent: Option<&Self::Dir>, name: &OsStr) -> io::Result<Self::Dir> {
        let raw_name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path holds a NUL byte"))?;
        let parent_fd = parent.map_or(libc::AT_FDCWD, |dir| dir.as_fd().as_raw_fd());
        let flags = libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC;
        // SAFETY: `raw_name` is a NUL-terminated C string that outlives
        // the call, and `parent_fd` is either `AT_FDCWD` or a descriptor
        // the borrowed parent keeps open across it. The call creates one
        // new descriptor and touches nothing this process owns.
        let fd = unsafe { libc::openat(parent_fd, raw_name.as_ptr(), flags) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `openat` returned a fresh descriptor that nothing else
        // owns, so the `OwnedFd` is its sole owner from here.
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        open_stream(owned)
    }

    fn next_entry(&self, dir: &mut Self::Dir) -> io::Result<Option<OsString>> {
        // SAFETY: `errno_slot` returns this thread's own `errno`
        // address, which is valid and writable for the thread's
        // lifetime.
        unsafe {
            *errno_slot() = 0;
        }
        // SAFETY: `dir.handle` is a live directory stream, and the
        // `&mut` borrow makes this call the only one advancing it.
        let entry = unsafe { libc::readdir(dir.handle) };
        if entry.is_null() {
            let error = io::Error::last_os_error();
            // A null with `errno` still zero is the end of the stream; a
            // null with a nonzero one is a failed read, and reading it as
            // the end would return a smaller total for a store the walk
            // could not finish.
            return if error.raw_os_error() == Some(0) {
                Ok(None)
            } else {
                Err(error)
            };
        }
        // SAFETY: `readdir` returned a valid pointer to an entry the
        // stream owns, which stays valid until the next call on it, and
        // `d_name` is the NUL-terminated name inside it.
        let name = unsafe { CStr::from_ptr(std::ptr::addr_of!((*entry).d_name).cast()) };
        Ok(Some(OsString::from_vec(name.to_bytes().to_vec())))
    }

    fn stat_dir(&self, dir: &Self::Dir) -> io::Result<EntryFacts> {
        let mut buffer = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `dir` keeps its descriptor open across the call, and
        // `buffer` is a correctly sized, correctly aligned allocation
        // `fstat` fills in full.
        let rc = unsafe { libc::fstat(dir.as_fd().as_raw_fd(), buffer.as_mut_ptr()) };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call above returned zero, which is when the kernel
        // documents the buffer as initialised.
        let stat = unsafe { buffer.assume_init() };
        Ok(facts_from_stat(&stat))
    }

    fn stat_entry(&self, parent: &Self::Dir, name: &OsStr) -> io::Result<EntryFacts> {
        let raw_name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path holds a NUL byte"))?;
        let mut buffer = MaybeUninit::<libc::stat>::uninit();
        // SAFETY: `parent` keeps its descriptor open across the call,
        // `raw_name` is a NUL-terminated C string that outlives it, and
        // `buffer` is a correctly sized, correctly aligned allocation
        // `fstatat` fills in full. `AT_SYMLINK_NOFOLLOW` keeps it from
        // resolving a link.
        let rc = unsafe {
            libc::fstatat(
                parent.as_fd().as_raw_fd(),
                raw_name.as_ptr(),
                buffer.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: the call above returned zero, which is when the kernel
        // documents the buffer as initialised.
        let stat = unsafe { buffer.assume_init() };
        Ok(facts_from_stat(&stat))
    }

    fn close_dir(&self, dir: Self::Dir) {
        drop(dir);
    }
}

/// Reads the filesystem behind an already open descriptor.
///
/// Deliberately not a [`WalkOps`] operation: the store root's
/// descriptor is the probe's one resolution of the configured path, and
/// this call is what the real-filesystem tests exercise directly.
fn filesystem_space(fd: BorrowedFd<'_>) -> io::Result<FsSpaceFacts> {
    let mut buffer = MaybeUninit::<libc::statvfs>::uninit();
    // SAFETY: `fd` is open across the call, and `buffer` is a correctly
    // sized, correctly aligned allocation `fstatvfs` fills in full.
    let rc = unsafe { libc::fstatvfs(fd.as_raw_fd(), buffer.as_mut_ptr()) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call above returned zero, which is when the kernel
    // documents the buffer as initialised.
    let stat = unsafe { buffer.assume_init() };
    Ok(FsSpaceFacts {
        // Zero on a value that does not fit reports no space rather than
        // room the host does not have.
        blocks: widen_platform_field(stat.f_blocks, 0),
        blocks_free: widen_platform_field(stat.f_bfree, 0),
        blocks_available: widen_platform_field(stat.f_bavail, 0),
        fragment_size: widen_platform_field(stat.f_frsize, 0),
    })
}

// ---------------------------------------------------------------------
// The walk
// ---------------------------------------------------------------------

/// The walk's live state, threaded through one directory at a time.
struct WalkState {
    /// Every `(st_dev, st_ino)` already counted. Two paths hard-linked
    /// to one file consume one file's blocks, which is what the kernel
    /// accounts for and what `filesystem` mode reports for the same
    /// bytes.
    seen: HashSet<(u64, u64)>,
    /// The device `audit_store_dir` itself is on. Usage summed across a
    /// nested mount would be weighed against available bytes for a
    /// different filesystem.
    root_dev: u64,
    /// The allocated bytes counted so far.
    total: u64,
}

/// Reads one directory until it finds a subdirectory to descend into.
///
/// Returns the opened subdirectory, or `None` once the directory is
/// exhausted. Every entry it passes over on the way is accounted for.
fn step_directory<O: WalkOps>(
    ops: &O,
    dir: &mut O::Dir,
    state: &mut WalkState,
) -> io::Result<Option<O::Dir>> {
    loop {
        let Some(name) = ops.next_entry(dir)? else {
            return Ok(None);
        };
        // Before any `fstatat`, any `openat` and any accounting: `..` is
        // an ordinary directory on the same device, so neither
        // `O_NOFOLLOW` nor the same-device rule refuses it, and
        // descending into it would climb out of the store and sum the
        // filesystem above it.
        let raw_name = name.as_bytes();
        if raw_name == CURRENT_DIR_ENTRY || raw_name == PARENT_DIR_ENTRY {
            continue;
        }
        let facts = match ops.stat_entry(dir, &name) {
            Ok(facts) => facts,
            // The one carve-out: the record store and the OpenBao device
            // both rotate generations away while a tick runs, and
            // treating that race as a failure would strand the alarm on
            // a stale reading every time a rotation lands on a tick.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !facts.is_dir {
            // Nothing else is opened or read: a FIFO cannot block the
            // walk, and a symbolic link contributes its own entry's
            // blocks with its target left unresolved, so what its own
            // `fstatat` reported is the whole of its accounting.
            account_for(state, &facts);
            continue;
        }
        // Directories are opened because opening them is the only
        // race-free way to enumerate them — and the descriptor's own
        // `fstat` is then what classifies the entry, so the object
        // counted and dedup-ed is the object traversed. Taking the
        // identity from the `fstatat` above would let a directory
        // substituted between the two calls be counted as one object and
        // walked as another.
        let child = match ops.open_dir(Some(dir), &name) {
            Ok(child) => child,
            // The same vanished-entry carve-out: a generation rotated
            // away between its `fstatat` and its `openat`.
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let child_facts = match ops.stat_dir(&child) {
            Ok(child_facts) => child_facts,
            // An `fstat` on a descriptor this walk holds open cannot
            // report a vanished entry, so any failure here is a failed
            // probe.
            Err(error) => {
                ops.close_dir(child);
                return Err(error);
            }
        };
        if !account_for(state, &child_facts) {
            ops.close_dir(child);
            continue;
        }
        return Ok(Some(child));
    }
}

/// Counts one entry's allocated blocks, unless it is off the store's
/// device or has already been counted under another name.
///
/// Returns whether the entry was counted, which for a directory is also
/// whether it is to be descended into: usage summed across a nested
/// mount would be weighed against available bytes for a different
/// filesystem, and two paths hard-linked to one file consume one file's
/// blocks.
fn account_for(state: &mut WalkState, facts: &EntryFacts) -> bool {
    if facts.dev != state.root_dev || !state.seen.insert((facts.dev, facts.ino)) {
        return false;
    }
    state.total = state.total.saturating_add(allocated_bytes(facts.blocks));
    true
}

/// Sums the allocated blocks of everything below an open store root.
///
/// Consumes `root`, and closes every directory it opened, on the
/// failure path as well as the success one. A failure is a failed
/// probe: an unreadable subdirectory summed silently as zero would
/// report a filling store as empty, which is the one outcome the alarm
/// exists to prevent.
fn walk_used_bytes<O: WalkOps>(ops: &O, root: O::Dir, root_facts: &EntryFacts) -> io::Result<u64> {
    let mut state = WalkState {
        seen: HashSet::from([(root_facts.dev, root_facts.ino)]),
        root_dev: root_facts.dev,
        // The store root counts its own blocks: a directory that once
        // held a great many entries keeps that allocation, the kernel
        // charges it against the reserve, and `filesystem` mode's
        // `statvfs` usage counts it.
        total: allocated_bytes(root_facts.blocks),
    };
    let mut open: Vec<O::Dir> = vec![root];
    let outcome = walk_frames(ops, &mut open, &mut state);
    while let Some(dir) = open.pop() {
        ops.close_dir(dir);
    }
    outcome.map(|()| state.total)
}

/// Drives the suspended-parent stack until every directory is exhausted.
///
/// A parent is pushed back before its child so its stream position
/// survives the descent, and it is left on the stack on the failure path
/// so the caller closes it.
fn walk_frames<O: WalkOps>(
    ops: &O,
    open: &mut Vec<O::Dir>,
    state: &mut WalkState,
) -> io::Result<()> {
    while let Some(mut dir) = open.pop() {
        match step_directory(ops, &mut dir, state) {
            Ok(Some(child)) => {
                open.push(dir);
                open.push(child);
            }
            Ok(None) => ops.close_dir(dir),
            Err(error) => {
                open.push(dir);
                return Err(error);
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------
// The host probe
// ---------------------------------------------------------------------

/// The real capacity probe.
///
/// Generic over [`WalkOps`] so the five behaviours that cannot be staged
/// on disk are reachable from a test; production instantiates it with
/// [`SyscallWalkOps`] and takes exactly one path through it.
pub(crate) struct HostCapacityProbe<O = SyscallWalkOps> {
    ops: O,
    // Synthetic `fstatvfs` facts exist only in test builds, where no
    // filesystem can represent the overflow inputs the arithmetic must
    // tolerate. Production always calls `fstatvfs` on the root descriptor.
    #[cfg(test)]
    test_space: Option<FsSpaceFacts>,
}

impl HostCapacityProbe<SyscallWalkOps> {
    /// Returns the probe production uses.
    #[must_use]
    pub(crate) const fn new() -> Self {
        Self {
            ops: SyscallWalkOps,
            #[cfg(test)]
            test_space: None,
        }
    }
}

impl Default for HostCapacityProbe<SyscallWalkOps> {
    fn default() -> Self {
        Self::new()
    }
}

impl<O: WalkOps> HostCapacityProbe<O> {
    /// Returns a probe over a substituted operation set.
    #[cfg(test)]
    const fn with_ops(ops: O) -> Self {
        Self {
            ops,
            test_space: None,
        }
    }

    /// Returns a test-only probe with synthetic filesystem space facts.
    ///
    /// A real filesystem cannot report block counts whose byte product
    /// overflows `u64`, so probe-level overflow coverage supplies those
    /// facts while preserving the real root-open and walk paths.
    #[cfg(test)]
    const fn with_ops_and_space(ops: O, space: FsSpaceFacts) -> Self {
        Self {
            ops,
            test_space: Some(space),
        }
    }
}

impl<O: WalkOps> CapacityProbe for HostCapacityProbe<O> {
    fn measure(
        &self,
        store_dir: &Path,
        enforcement: AuditStoreEnforcement,
    ) -> io::Result<CapacityMeasurement> {
        // One open, carrying `O_NOFOLLOW`, in both modes: it is the
        // probe's only resolution of the configured path, and it is what
        // refuses a symbolic link planted at the store root before
        // `fstatvfs` can report the target's filesystem instead.
        let root = self.ops.open_dir(None, store_dir.as_os_str())?;
        let facts = match self.ops.stat_dir(&root) {
            Ok(facts) => facts,
            Err(error) => {
                self.ops.close_dir(root);
                return Err(error);
            }
        };
        #[cfg(not(test))]
        let space = filesystem_space(root.as_fd());
        #[cfg(test)]
        let space = self
            .test_space
            .map_or_else(|| filesystem_space(root.as_fd()), Ok);
        let space = match space {
            Ok(space) => space,
            Err(error) => {
                self.ops.close_dir(root);
                return Err(error);
            }
        };
        let available = available_bytes(&space);
        let used = match enforcement {
            AuditStoreEnforcement::Filesystem => {
                // The store is its own filesystem here, so the call that
                // gave the available bytes already answered usage
                // exactly. Nothing is enumerated.
                self.ops.close_dir(root);
                filesystem_used_bytes(&space)
            }
            AuditStoreEnforcement::Directory => walk_used_bytes(&self.ops, root, &facts)?,
        };
        Ok(CapacityMeasurement {
            used_bytes: used,
            available_bytes: available,
        })
    }
}

/// Runs the host capacity probe outside a Tokio runtime worker.
///
/// The walk and the `statvfs` are blocking filesystem work, so they run
/// under `spawn_blocking`; the caller awaits this inside its tick, so
/// nothing is spawned and dropped and a join failure is a failed probe
/// rather than a silent gap.
///
/// # Errors
///
/// Returns the probe's error, or reports that the blocking task did not
/// join.
pub(crate) async fn probe_capacity_off_runtime(
    store_dir: PathBuf,
    enforcement: AuditStoreEnforcement,
) -> io::Result<CapacityMeasurement> {
    tokio::task::spawn_blocking(move || HostCapacityProbe::new().measure(&store_dir, enforcement))
        .await
        .map_err(|error| {
            io::Error::other(format!("the capacity probe task did not join: {error}"))
        })?
}

#[cfg(test)]
mod tests;
