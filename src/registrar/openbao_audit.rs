//! In-place rotation of `OpenBao`'s file audit device, and the bounds
//! the daemon holds the generations it creates to.
//!
//! `OpenBao`'s file audit device never rotates itself, and `OpenBao`
//! fails a request it cannot audit — so an audit log that only grows
//! ends as an `OpenBao` that stops serving. bootroot is not the process
//! appending to that file and cannot become one, so what this module
//! delivers is deliberately narrower than "the device is bounded":
//!
//! - **A hard ceiling on the retained set.** The generations this
//!   module creates and owns total at or under `openbao_audit_max_file_bytes
//!   × openbao_audit_max_retained_files`. Nothing overrides that budget
//!   — not the retention target, not how large the active log had grown,
//!   not how long a pass took — and every bound evaluation that
//!   completes re-establishes it.
//! - **An emptied active log on every successful pass.**
//! - **A loud signal when neither is happening**, in the shape of a
//!   consecutive-failure counter that escalates from `warn` to `error`.
//!
//! What it does **not** deliver is an absolute ceiling on the device's
//! footprint. `OpenBao`'s write rate is an assumption about `OpenBao`,
//! not a limit bootroot imposes, and a run of failed passes leaves the
//! active log growing for as many intervals as the run lasts. The
//! device's total is `retained + active + staging`, and only the first
//! term is bootroot's.
//!
//! # The mechanism
//!
//! Copy the stable prefix aside, then truncate the original to zero.
//! `OpenBao` holds the device open for appending, so after the truncate
//! its writes land at the new end of file and no descriptor is
//! invalidated: nothing is restarted, resealed or signalled, and the
//! active path is never unlinked, renamed or replaced.
//!
//! That rests on the daemon and the container seeing **one** filesystem,
//! which they do: `<audit_store_dir>/openbao` is bind-mounted into the
//! container from the same Linux host the daemon runs on, so a truncate
//! here is the file's length there before the container's next write
//! chooses an offset. (A macOS developer machine is not that: Docker
//! Desktop reaches a host bind mount through a VM, which does not
//! propagate a host-side truncate to the guest's cached length. The
//! `docker-compose` deployment target does not have that layer.) The price is a
//! small, bounded loss window at each rotation — the partial trailing
//! record, plus whatever `OpenBao` appended while the copy ran, is
//! destroyed whole by the truncate — so a record is either complete in
//! the generation or entirely inside that window, never split and never
//! torn.
//!
//! The ordering below is what makes that safe, and it is the discipline
//! [`crate::registrar::audit`] already follows for its own store:
//!
//! 1. capture the active log's length once;
//! 2. copy exactly those bytes into a staging file in the device's own
//!    directory, created mode `0600`;
//! 3. truncate the staging copy to just past its last `\n`;
//! 4. chown it to the device directory's owner, then `fsync` it;
//! 5. `link` it into place under its published
//!    `audit-<stamp>-<NNNNNN>.log` name, confirm that name reached the
//!    inode just staged, and unlink the staging name;
//! 6. `fsync` the containing directory — a flush of the file puts its
//!    bytes on disk, not the entry naming them, and step 7 is about to
//!    destroy the only other copy;
//! 7. truncate the active log to zero; **this is the commit point**;
//! 8. `fsync` the active log, so the emptied length is durable rather
//!    than merely visible.
//!
//! Before step 7 the generation is provisional — the active log still
//! holds every byte it duplicates — so any failure up to and including
//! the truncate unlinks the copy and flushes the directory. Once step 7
//! succeeds the generation is the *only* copy of those records, so no
//! later failure unlinks it to roll the rotation back. Retention is a
//! separate obligation and still deletes whatever the ceiling requires,
//! including that same generation.
//!
//! Step 5 is a `link` and a check rather than a `rename` because the
//! device directory is writable by the container's audit user, so no
//! name in it stays settled: between step 4 and step 5 that user can
//! unlink the staging name and leave an empty file of their own there.
//! A `rename` would publish it, step 6 would make it durable, and step
//! 7 would then destroy the records the pass believed it had copied —
//! the one loss this ordering exists to prevent. `link` also refuses an
//! existing target instead of replacing it, so a name collision can
//! never destroy an already published generation. What the pass acts on
//! after the check is the inode it staged, established by comparing
//! device and inode numbers against the descriptor it still holds open
//! — a name it read them through would only be the same question again.
//!
//! # The residual
//!
//! A crash between step 7 and its flush landing can resurrect the active
//! log at its pre-truncate length while the generation survives, so the
//! next pass rotates an overlapping prefix and two generations share
//! records. Reading the retained set back with `cat` then stays
//! *complete* — every retained record appears at least once — but stops
//! being exact and stops being in write order. Step 8 narrows that
//! window to one flush rather than closing it. Nothing here
//! de-duplicates: two byte-identical lines can be two genuine events,
//! and dropping one would destroy evidence.
//!
//! A crash inside step 5, after the link and before the staging name is
//! unlinked, leaves that name beside the generation as a second link to
//! the same inode. It costs no space, it is outside the `audit-*.log`
//! namespace so no listing, bound or trim ever counts it, and the next
//! pass removes it before staging its own copy.

use std::fs::{File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::time::Duration;

use time::{OffsetDateTime, UtcOffset};
use tokio::sync::watch;
use tracing::{debug, error, warn};

use crate::fs_util::sync_parent_dir;

#[cfg(test)]
mod tests;

/// The name `openbao/openbao.hcl`'s `file_path` gives the device's
/// active log. Fixed: this module does not edit that stanza.
pub const ACTIVE_FILE_NAME: &str = "audit.log";

/// The prefix every rotated generation's name starts with.
///
/// [`ACTIVE_FILE_NAME`] does not match it, so listing, sorting and
/// trimming can never reach the active file.
const ROTATED_PREFIX: &str = "audit-";

/// The suffix every file in the family ends with.
const FILE_SUFFIX: &str = ".log";

/// The staging copy's name while it is still provisional.
///
/// Deliberately outside the `audit-*.log` namespace: a staging file is
/// not a generation, must never be counted towards the retained bound,
/// and must never be published by a trim that mistook it for one.
const STAGING_FILE_NAME: &str = ".audit-rotate.staging";

/// Digits in a rotated generation's collision sequence.
///
/// Fixed width and always present, so the names sort lexicographically
/// in the order they were produced. A suffix added only on collision
/// could not: `audit-<ts>-1.log` sorts *before* the earlier
/// `audit-<ts>.log` because `-` precedes `.`, and unpadded `-10` sorts
/// before `-2`.
const SEQUENCE_DIGITS: usize = 6;

/// The largest collision sequence [`SEQUENCE_DIGITS`] can spell.
const MAX_SEQUENCE: u32 = 999_999;

/// Bytes in the `YYYYMMDDTHHMMSSZ` timestamp half of a rotated
/// generation's name.
const ROTATION_STAMP_LEN: usize = "YYYYMMDDTHHMMSSZ".len();

/// Mode a staging copy and a published generation are created with.
///
/// Applied at creation rather than by a later `set_permissions`, so the
/// file never exists at a wider mode for any instant. It is what the
/// active log already carries, so the whole family reads uniformly on
/// the host and through `docker exec`.
const GENERATION_FILE_MODE: u32 = 0o600;

/// Bytes copied per read while staging the stable prefix.
const COPY_CHUNK_BYTES: u64 = 64 * 1024;

/// Default size bound on the **active** log, in bytes (64 MiB).
///
/// Derived from the shared store's 2 GiB reserve: with
/// [`DEFAULT_OPENBAO_AUDIT_MAX_RETAINED_FILES`] the retained ceiling is
/// 448 MiB and the device's expected in-pass peak is 576 MiB, which
/// leaves the verb-record store's 136 MiB and about 1.3 GiB of
/// headroom.
pub const DEFAULT_OPENBAO_AUDIT_MAX_FILE_BYTES: u64 = 67_108_864;

/// Default number of rotated generations retained beside the active
/// log.
pub const DEFAULT_OPENBAO_AUDIT_MAX_RETAINED_FILES: u32 = 7;

/// Default retention target in days.
///
/// A declared and documented target that nothing here reads: the size
/// ceiling always wins, so the trim never consults it.
pub const DEFAULT_OPENBAO_AUDIT_MIN_RETAIN_DAYS: u32 = 90;

/// The smallest `openbao_audit_max_file_bytes` a configuration may
/// declare (1 MiB).
///
/// Unlike the verb-record store's floor, this one is not *derived* from
/// a maximum record size: bootroot does not control the size of an
/// `OpenBao` audit entry, so there is no such constant to multiply
/// against. The floor exists so a rotation stays rare rather than
/// something the periodic check does on every tick.
pub const MIN_OPENBAO_AUDIT_MAX_FILE_BYTES: u64 = 1_048_576;

/// How often a pass runs.
///
/// A fixed constant rather than a configuration key, and deliberately
/// not the per-profile `check_interval`: that interval is per-profile,
/// jittered and operator-configurable up to hours, while the device is a
/// single global object. A deployment with no profiles would never
/// rotate and one with several would rotate several times over.
pub(crate) const ROTATION_INTERVAL: Duration = Duration::from_mins(1);

/// Consecutive failed passes at which the `warn` per increment becomes
/// an `error`.
///
/// Five, which is five minutes at [`ROTATION_INTERVAL`]. A constant
/// rather than a key for the same reason the interval is.
const FAILURE_ESCALATION_THRESHOLD: u32 = 5;

/// Returns the retained set's hard byte budget, `S × N`.
///
/// Total by construction. Configuration validation has already refused
/// every input that could overflow it — it rejects a configuration whose
/// `S × (N + 1)` does not fit in `u64`, and `S × N` fits a fortiori — so
/// there is no error path here to design or to test. The saturating form
/// is what keeps a future regression, a key that stops being validated
/// or a caller that skips validation, degrading to a looser bound rather
/// than panicking inside the task the daemon holds a handle for.
#[must_use]
pub fn retained_budget_bytes(max_file_bytes: u64, max_retained_files: u32) -> u64 {
    max_file_bytes.saturating_mul(u64::from(max_retained_files))
}

/// Returns `S × (N + 1)`, or `None` where either step overflows `u64`.
///
/// This is the expression configuration validation refuses an overflow
/// of, so that [`retained_budget_bytes`] can be total. Saturating here
/// instead is not an option: a budget saturated to `u64::MAX` is no
/// bound at all.
#[must_use]
pub fn checked_family_bytes(max_file_bytes: u64, max_retained_files: u32) -> Option<u64> {
    let generations = u64::from(max_retained_files).checked_add(1)?;
    max_file_bytes.checked_mul(generations)
}

/// Opens the device's active log through `options`, and hands back the
/// descriptor only once that descriptor is the regular file `OpenBao`
/// writes.
///
/// A pass establishes what is at `audit.log` with `symlink_metadata`
/// before it decides to rotate, but the device directory is writable by
/// the container's audit user, so what that call measured and what an
/// `open` a moment later reaches need not be the same file. The window
/// is small and it is not closeable — there is no atomic "open the file
/// I just stat'd" — so the descriptor is checked rather than the name,
/// and it is opened in a way that cannot come to harm before the check
/// runs:
///
/// - `O_NOFOLLOW` refuses a symbolic link planted at the final
///   component, which is the case [`crate::registrar::audit`] holds its
///   own active file to. Root would otherwise copy whatever the link
///   named into a generation it hands to that user, and truncate it.
/// - `O_NONBLOCK` refuses to *wait* on anything else that can be
///   planted there. `O_NOFOLLOW` says nothing about a FIFO, and opening
///   one blocks until the other end is opened — for reading, until a
///   writer arrives; that open is inside `spawn_blocking`, and a thread
///   parked in it never returns, so the rotation task stops ticking
///   altogether: no retry, no failure counter, no escalation, and no
///   response to shutdown. Non-blocking, the same open either fails
///   outright (`ENXIO`, for the write side with no reader) or returns a
///   descriptor the check below rejects. On a regular file the flag
///   means nothing at all, so it costs the healthy path nothing.
/// - `fstat` on the result is what actually decides. It cannot be raced:
///   the descriptor is already open, and nothing done at the path
///   afterwards changes which inode it refers to.
///
/// # Errors
///
/// Returns the `open` or `fstat` error, or [`io::ErrorKind::InvalidInput`]
/// where the descriptor is not a regular file. Every one of those is a
/// failed pass, which the next tick retries.
fn open_active(options: &mut OpenOptions, path: &Path) -> io::Result<File> {
    let file = options
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not a regular file (found {:?}); refusing to rotate through it",
                path.display(),
                meta.file_type()
            ),
        ));
    }
    Ok(file)
}

/// Returns the `(device, inode)` pair that names a *file*, as opposed
/// to a path that currently happens to lead to one.
///
/// Every path in the device's directory is one the container's audit
/// user can re-point, so wherever this module has to be sure two
/// observations are of the same file it compares this rather than the
/// name it read them through.
fn file_identity(meta: &std::fs::Metadata) -> (u64, u64) {
    (meta.dev(), meta.ino())
}

/// Formats `now` as the `YYYYMMDDTHHMMSSZ` UTC stamp a generation's name
/// carries.
fn rotation_stamp(now: OffsetDateTime) -> String {
    let utc = now.to_offset(UtcOffset::UTC);
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        utc.year(),
        u8::from(utc.month()),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second()
    )
}

/// Composes a rotated generation's name from its timestamp and its
/// collision sequence.
fn rotated_file_name(stamp: &str, sequence: u32) -> String {
    format!("{ROTATED_PREFIX}{stamp}-{sequence:0SEQUENCE_DIGITS$}{FILE_SUFFIX}")
}

/// Splits a rotated generation's name back into its timestamp and its
/// collision sequence, or returns `None` for anything that is not one.
///
/// Held to the exact documented shape. A name this accepts is counted
/// towards the retained bound and, once it is the lexically oldest,
/// deleted by a trim — so a neighbouring file that merely starts
/// `audit-` and ends `.log` must not be mistaken for one.
fn parse_rotated_name(name: &str) -> Option<(&str, u32)> {
    let body = name
        .strip_prefix(ROTATED_PREFIX)?
        .strip_suffix(FILE_SUFFIX)?;
    let (stamp, sequence) = body.rsplit_once('-')?;
    if sequence.len() != SEQUENCE_DIGITS || !sequence.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if !is_rotation_stamp(stamp) {
        return None;
    }
    Some((stamp, sequence.parse().ok()?))
}

/// Reports whether `stamp` is the exact `YYYYMMDDTHHMMSSZ` form
/// [`rotation_stamp`] writes.
///
/// The shape carries the lexical ordering the trim depends on:
/// fixed-width fields in most-significant-first order. The field ranges
/// are checked too, so a name that sorts where no such instant ever fell
/// is not admitted to the set.
fn is_rotation_stamp(stamp: &str) -> bool {
    if stamp.len() != ROTATION_STAMP_LEN
        || stamp.get(8..9) != Some("T")
        || stamp.get(15..16) != Some("Z")
    {
        return false;
    }
    let field = |range: std::ops::Range<usize>| -> Option<u32> {
        let text = stamp.get(range)?;
        if !text.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        text.parse().ok()
    };
    let (Some(_year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        field(0..4),
        field(4..6),
        field(6..8),
        field(9..11),
        field(11..13),
        field(13..15),
    ) else {
        return false;
    };
    (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour <= 23
        && minute <= 59
        // A leap second is a legitimate reading of a clock.
        && second <= 60
}

/// A staged copy and the active log it was read through, held open
/// together for the rest of the pass.
struct StagedCopy {
    /// The staging copy: written, trimmed to its last record, owned,
    /// moded and flushed, and not yet published.
    staged: File,
    /// The active log's descriptor the copy was read through.
    ///
    /// Held open past the truncate rather than dropped with the copy.
    /// The truncate opens the pathname a second time, and the device
    /// directory is writable by the container's audit user, so what it
    /// opens need not be what was copied; this descriptor is what that
    /// one is compared against. Keeping it open is what makes the
    /// comparison mean anything, since an inode number freed in the
    /// meantime could be re-allocated onto the replacement.
    source: File,
}

/// One rotated generation, as a pass sees it.
#[derive(Debug, Clone)]
struct Generation {
    path: PathBuf,
    name: String,
    len: u64,
}

/// What is at `<audit_store_dir>/openbao` when a pass looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeviceDirectory {
    /// Nothing at the path at all: the endpoint enabled on a host
    /// `bootroot init` has not since provisioned the store on. The one
    /// state a pass is silent about.
    Absent,
    /// A real directory, which is the only thing a pass acts through.
    Usable,
    /// Present but not a directory, or unreadable. A fault.
    Unusable,
}

/// Which of a pass's two obligations it left unmet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnmetObligation {
    Rotation,
    RetainedBound,
    Both,
}

impl UnmetObligation {
    fn of(rotation: bool, retained: bool) -> Option<Self> {
        match (rotation, retained) {
            (true, true) => Some(Self::Both),
            (true, false) => Some(Self::Rotation),
            (false, true) => Some(Self::RetainedBound),
            (false, false) => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Rotation => "rotation",
            Self::RetainedBound => "retained-set bound",
            Self::Both => "rotation and retained-set bound",
        }
    }
}

/// What one rotation attempt did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotationOutcome {
    /// No active log at the configured path, or one below `S`. Not an
    /// obligation at all, so it never increments the counter.
    NotRequired,
    /// A generation is in place and the active log is empty.
    Completed,
    /// Nothing was published and nothing was destroyed — the captured
    /// prefix held no complete record, or the second's sequence
    /// namespace was exhausted. Owed and not done, so it increments.
    Skipped,
    /// The attempt errored at some step. Owed and not done.
    Failed,
}

impl RotationOutcome {
    pub(crate) fn is_unmet(self) -> bool {
        !matches!(self, Self::NotRequired | Self::Completed)
    }

    fn label(self) -> &'static str {
        match self {
            Self::NotRequired => "not-required",
            Self::Completed => "completed",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
        }
    }
}

/// What one pass observed and did, for a caller that wants to assert on
/// it rather than read the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PassOutcome {
    /// Whether the device directory was there to evaluate at all.
    pub(crate) evaluated: bool,
    /// What the rotation half of the pass did.
    pub(crate) rotation: RotationOutcome,
    /// Whether the retained set was outside a bound when the pass
    /// returned.
    pub(crate) retained_unmet: bool,
    /// Consecutive passes, this one included, that left something owed
    /// undone.
    pub(crate) consecutive_failures: u32,
    /// Whether a trim's deletions may still be waiting on a directory
    /// flush that has not succeeded. Carried until one does, since
    /// until then the smaller set a listing reports is only in the
    /// page cache — and carried from the first pass of a new task,
    /// which cannot know what the previous one left unflushed.
    pub(crate) trim_flush_pending: bool,
    /// The active log's size when the pass returned.
    pub(crate) active_bytes: u64,
    /// The retained set's total size when the pass returned.
    pub(crate) retained_bytes: u64,
    /// How many generations the retained set held when the pass
    /// returned.
    pub(crate) retained_files: usize,
}

impl PassOutcome {
    /// Whether a generation was published and the active log emptied.
    pub(crate) fn rotated(self) -> bool {
        self.rotation == RotationOutcome::Completed
    }
}

/// The periodic rotation of one `OpenBao` file audit device, and the
/// state a run of passes accumulates.
///
/// Not `Clone` and not shared: exactly one task owns it, so the listing,
/// the publish and the trim never race another pass over the same
/// directory.
pub(crate) struct OpenBaoAuditRotation {
    /// `<audit_store_dir>/openbao`, the bind-mount source backing the
    /// container's `/openbao/audit`.
    dir: PathBuf,
    active_path: PathBuf,
    staging_path: PathBuf,
    /// `S` — the size bound on the active log.
    max_file_bytes: u64,
    /// `N` — the retained generation count.
    max_retained_files: u32,
    consecutive_failures: u32,
    /// Set while a trim's deletions may still be waiting on a
    /// directory flush that has not succeeded, and cleared only when
    /// one does. A failed flush leaves the deletions visible to the
    /// next listing while a crash could still restore the over-budget
    /// set, so the debt is carried rather than discarded: every pass
    /// re-attempts the flush and reports the bound as unmet until it
    /// lands.
    ///
    /// A fresh instance starts owing one, because the debt lives in
    /// memory and a daemon that reloads, restarts or is killed takes
    /// it with it. A task that assumed a clean slate would list the
    /// generations the previous one deleted as absent, call the bound
    /// met and never flush — leaving on disk exactly the over-budget
    /// set a crash restores. Assuming the debt instead costs one
    /// directory `fsync` on the first pass of a process and needs
    /// nothing persisted to remember it by.
    trim_flush_pending: bool,
    reported_absent_dir: bool,
    reported_absent_log: bool,
    #[cfg(test)]
    faults: tests::FaultInjection,
    #[cfg(test)]
    passes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl OpenBaoAuditRotation {
    /// Creates the rotation for the device directory `dir`, under the
    /// bounds `S` and `N`.
    pub(crate) fn new(dir: PathBuf, max_file_bytes: u64, max_retained_files: u32) -> Self {
        let active_path = dir.join(ACTIVE_FILE_NAME);
        let staging_path = dir.join(STAGING_FILE_NAME);
        Self {
            dir,
            active_path,
            staging_path,
            max_file_bytes,
            max_retained_files,
            consecutive_failures: 0,
            // Assumed, not observed: this process cannot know whether
            // the previous one's last trim was ever flushed, and one
            // `fsync` on the first pass is cheaper than either wrong
            // answer.
            trim_flush_pending: true,
            reported_absent_dir: false,
            reported_absent_log: false,
            #[cfg(test)]
            faults: tests::FaultInjection::default(),
            #[cfg(test)]
            passes: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }

    /// Runs one pass: rotate if the active log is at or over `S`, then
    /// hold the retained set inside its bounds — the second owed on
    /// every tick, whether or not the first was.
    ///
    /// `now` is the clock reading a generation's name is derived from,
    /// floored at the newest existing generation's stamp, so a clock
    /// that goes backwards cannot reorder the set.
    pub(crate) fn run_pass(&mut self, now: OffsetDateTime) -> PassOutcome {
        #[cfg(test)]
        self.passes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        match self.inspect_dir() {
            // Nothing on this host backs the device, so there is
            // neither a rotation to owe nor a set to evaluate. Said
            // once rather than once a minute: a message every interval
            // over a non-fault is how a real one gets missed.
            DeviceDirectory::Absent => {
                if !self.reported_absent_dir {
                    self.reported_absent_dir = true;
                    debug!(
                        directory = %self.dir.display(),
                        "the OpenBao audit device directory is absent; nothing to rotate on \
                         this host"
                    );
                }
                self.consecutive_failures = 0;
                return PassOutcome {
                    evaluated: false,
                    rotation: RotationOutcome::NotRequired,
                    retained_unmet: false,
                    consecutive_failures: 0,
                    trim_flush_pending: false,
                    active_bytes: 0,
                    retained_bytes: 0,
                    retained_files: 0,
                };
            }
            // A fault, and the pass stops here rather than acting
            // through it. Falling through would reach every later step
            // by a path whose first component is the suspect one: an
            // `O_NOFOLLOW` open refuses a link at `audit.log`, not one
            // at the directory above it, so a link pointed at another
            // directory would have this pass copy, publish, truncate
            // and delete inside a location nothing here provisioned.
            //
            // Both obligations count as unmet, for the same reason the
            // failed listing below does: with the directory unusable
            // neither the active log's size nor the retained set's
            // total can be read, and reporting either bound as met
            // would report it holding on no evidence.
            DeviceDirectory::Unusable => {
                self.record(true, true, 0, 0);
                return PassOutcome {
                    evaluated: true,
                    rotation: RotationOutcome::Failed,
                    retained_unmet: true,
                    consecutive_failures: self.consecutive_failures,
                    trim_flush_pending: self.trim_flush_pending,
                    active_bytes: 0,
                    retained_bytes: 0,
                    retained_files: 0,
                };
            }
            DeviceDirectory::Usable => {}
        }

        let rotation = self.rotate_if_required(now);
        self.trim();

        let (retained_files, retained_bytes, listing_failed) = match self.rotated_generations() {
            Ok(generations) => (
                generations.len(),
                generations.iter().fold(0_u64, |total, generation| {
                    total.saturating_add(generation.len)
                }),
                false,
            ),
            Err(err) => {
                warn!(
                    directory = %self.dir.display(),
                    error = %err,
                    "could not list the retained OpenBao audit generations to check their bound"
                );
                (0, 0, true)
            }
        };
        let budget = retained_budget_bytes(self.max_file_bytes, self.max_retained_files);
        let retained_cap = usize::try_from(self.max_retained_files).unwrap_or(usize::MAX);
        // A listing that failed is an unmet obligation in its own
        // right: the bound cannot be asserted, and reporting it as met
        // would be reporting the ceiling holding on no evidence. So is
        // a trim whose deletions have not been flushed: the listing
        // above no longer sees the deleted generations, but a crash
        // before that flush lands can restore the whole over-budget
        // set, so the ceiling is not yet established on disk. A task
        // on its first pass owes that flush too — the debt does not
        // survive the process that incurred it, and the deletions it
        // covers do.
        let retained_unmet = listing_failed
            || self.trim_flush_pending
            || retained_files > retained_cap
            || retained_bytes > budget;
        let active_bytes = self.active_len().unwrap_or(0);

        self.record(
            rotation.is_unmet(),
            retained_unmet,
            active_bytes,
            retained_bytes,
        );

        PassOutcome {
            evaluated: true,
            rotation,
            retained_unmet,
            consecutive_failures: self.consecutive_failures,
            trim_flush_pending: self.trim_flush_pending,
            active_bytes,
            retained_bytes,
            retained_files,
        }
    }

    /// Updates the consecutive-failure counter and says what happened.
    ///
    /// Escalation is on the count and nothing else: this reports the
    /// task's own health, never the filesystem's, so it stats no free
    /// space and compares nothing to the store's reserve.
    fn record(
        &mut self,
        rotation_unmet: bool,
        retained_unmet: bool,
        active_bytes: u64,
        retained_bytes: u64,
    ) {
        let Some(unmet) = UnmetObligation::of(rotation_unmet, retained_unmet) else {
            self.consecutive_failures = 0;
            return;
        };
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        warn!(
            directory = %self.dir.display(),
            unmet = unmet.label(),
            consecutive_failures = self.consecutive_failures,
            "an OpenBao audit device rotation pass left an obligation unmet; retrying next pass"
        );
        if self
            .consecutive_failures
            .is_multiple_of(FAILURE_ESCALATION_THRESHOLD)
        {
            // Both sizes go in the message because they name different
            // broken guarantees: a growing active log is the operating
            // envelope drifting, an over-budget retained set is the
            // hard ceiling being violated.
            error!(
                directory = %self.dir.display(),
                unmet = unmet.label(),
                consecutive_failures = self.consecutive_failures,
                active_log_bytes = active_bytes,
                retained_set_bytes = retained_bytes,
                retained_budget_bytes =
                    retained_budget_bytes(self.max_file_bytes, self.max_retained_files),
                "OpenBao audit device rotation has left an obligation unmet on every one of the \
                 last {} passes; the device's footprint is no longer inside its expected envelope",
                self.consecutive_failures
            );
        }
    }

    /// Reports what is at the device directory's path, following
    /// nothing to find out.
    ///
    /// `symlink_metadata`, never `metadata` and never `Path::is_dir`.
    /// A resolving read is wrong in both directions at once here: a
    /// symbolic link planted at `<audit_store_dir>/openbao` and
    /// pointed at another directory is followed, and a pass then acts
    /// on a location nothing here provisioned, while a dangling one
    /// reports `NotFound` and takes the unprovisioned host's silent
    /// no-op — which is rotation and its escalation disabled together
    /// by a link any writer of the parent directory can plant.
    /// `Path::is_dir` adds a third: it reports every metadata error as
    /// `false`, so an unreadable directory reads as one that is not
    /// there.
    ///
    /// Only a real directory is acted through, and only an absent path
    /// is silent. Everything else is a fault the pass counts.
    fn inspect_dir(&self) -> DeviceDirectory {
        match std::fs::symlink_metadata(&self.dir) {
            Ok(meta) if meta.is_dir() => DeviceDirectory::Usable,
            Ok(meta) => {
                warn!(
                    directory = %self.dir.display(),
                    file_type = ?meta.file_type(),
                    "the OpenBao audit device directory is not a directory; refusing to rotate \
                     through it"
                );
                DeviceDirectory::Unusable
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => DeviceDirectory::Absent,
            Err(err) => {
                warn!(
                    directory = %self.dir.display(),
                    error = %err,
                    "could not establish what is at the OpenBao audit device directory; refusing \
                     to rotate through it"
                );
                DeviceDirectory::Unusable
            }
        }
    }

    /// Returns the active log's length, or `None` where it is absent or
    /// is not the regular file `OpenBao` writes.
    ///
    /// Link-resolving `metadata` would report a planted link's target
    /// as the device's footprint, which is a figure about some other
    /// file entirely — and this one goes in the escalation message.
    fn active_len(&self) -> Option<u64> {
        std::fs::symlink_metadata(&self.active_path)
            .ok()
            .filter(std::fs::Metadata::is_file)
            .map(|meta| meta.len())
    }

    /// Rotates when the active log is at or over `S`.
    ///
    /// What is at the path is established before its size is read.
    /// `symlink_metadata`, never `metadata`: the latter resolves a
    /// link, so a link planted at `audit.log` and pointed at a small
    /// file would measure below `S`, return `NotRequired` here, and
    /// never reach the opens that refuse the tampering — and a broken
    /// link would measure as an absent log. The size only means
    /// anything once the file it belongs to is the regular file
    /// `OpenBao` writes.
    ///
    /// This check is about the *decision*, not about the safety of the
    /// steps it leads to. It reads a name in a directory the container's
    /// audit user can write, so what it measured can be replaced before
    /// the copy or the truncate reaches it; each of those opens through
    /// [`open_active`], which re-establishes the same fact about the
    /// descriptor it actually holds.
    fn rotate_if_required(&mut self, now: OffsetDateTime) -> RotationOutcome {
        let meta = match std::fs::symlink_metadata(&self.active_path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // A configuration can enable the endpoint on a host
                // where `bootroot init` has not since provisioned the
                // store. That is a no-op, not a failure.
                if !self.reported_absent_log {
                    self.reported_absent_log = true;
                    debug!(
                        path = %self.active_path.display(),
                        "the OpenBao audit device has no active log; nothing to rotate"
                    );
                }
                return RotationOutcome::NotRequired;
            }
            Err(err) => {
                warn!(
                    path = %self.active_path.display(),
                    error = %err,
                    "could not measure the OpenBao audit device's active log"
                );
                return RotationOutcome::Failed;
            }
        };
        if !meta.is_file() {
            warn!(
                path = %self.active_path.display(),
                file_type = ?meta.file_type(),
                "the OpenBao audit device's active log is not a regular file; refusing to rotate \
                 it"
            );
            return RotationOutcome::Failed;
        }
        let len = meta.len();
        if len < self.max_file_bytes {
            return RotationOutcome::NotRequired;
        }
        self.rotate(len, now)
    }

    /// Performs one rotation of a `len`-byte active log.
    // One ordered sequence whose steps are only meaningful in order,
    // and each of whose failures says something different about where
    // the pass stopped. Splitting it would hide that ordering behind
    // call sites.
    #[allow(clippy::too_many_lines)]
    fn rotate(&self, len: u64, now: OffsetDateTime) -> RotationOutcome {
        let target = match self.published_path(now) {
            Ok(Some(target)) => target,
            Ok(None) => {
                warn!(
                    directory = %self.dir.display(),
                    "every collision sequence under the OpenBao audit generation stamp is taken; \
                     skipping this rotation rather than emitting an out-of-order name"
                );
                return RotationOutcome::Skipped;
            }
            Err(err) => {
                warn!(
                    directory = %self.dir.display(),
                    error = %err,
                    "could not derive the next OpenBao audit generation name"
                );
                return RotationOutcome::Failed;
            }
        };

        #[cfg(test)]
        self.before_stage_hook();

        let copy = match self.stage_prefix(len) {
            Ok(Some(copy)) => {
                // The staging copy already carries its final mode and
                // owner, and has not been published yet. A test looks
                // at it here rather than inferring the ordering.
                #[cfg(test)]
                if let Some(hook) = self.faults.after_stage() {
                    hook(&self.staging_path);
                }
                copy
            }
            Ok(None) => {
                warn!(
                    path = %self.active_path.display(),
                    captured_bytes = len,
                    "the captured OpenBao audit prefix holds no complete record; skipping this \
                     rotation and retrying on the next pass"
                );
                Self::recover(&self.staging_path);
                return RotationOutcome::Skipped;
            }
            Err(err) => {
                warn!(
                    path = %self.active_path.display(),
                    error = %err,
                    "could not stage the OpenBao audit device's stable prefix"
                );
                Self::recover(&self.staging_path);
                return RotationOutcome::Failed;
            }
        };

        if let Err(err) = self.publish(&copy.staged, &target) {
            warn!(
                target = %target.display(),
                error = %err,
                "could not publish the staged OpenBao audit generation"
            );
            // Only the staging name: whether the target is this pass's
            // to remove is known inside `publish`, and it has already
            // acted on that.
            Self::recover(&self.staging_path);
            return RotationOutcome::Failed;
        }

        // Not optional, and the file flush above does not cover it: a
        // crash between the publish and this flush can leave the
        // generation's bytes on disk with nothing pointing at them, and
        // the truncate below is about to destroy the only other copy.
        if let Err(err) = self.sync_dir() {
            warn!(
                target = %target.display(),
                error = %err,
                "could not flush the directory the OpenBao audit generation was published into; \
                 the active log is left intact"
            );
            Self::recover(&target);
            return RotationOutcome::Failed;
        }

        // The one instant where the retained set, the active log at its
        // full captured length and the newly published generation all
        // coexist — the in-pass peak the operating envelope is stated
        // against. A test suspends the pass here to measure it.
        #[cfg(test)]
        if let Some(hook) = self.faults.before_truncate() {
            hook(&target);
        }

        // The publish settled this when it linked the name, and the
        // directory flush above ran after that — on a directory the
        // container's audit user can write throughout. Re-established
        // here, as the last thing before the commit point.
        if let Err(err) = Self::confirm_published(&copy.staged, &target) {
            warn!(
                target = %target.display(),
                error = %err,
                "the published OpenBao audit generation no longer names the staged copy; the \
                 active log is left intact"
            );
            return RotationOutcome::Failed;
        }

        let active = match self.truncate_active(&copy.source) {
            Ok(active) => active,
            Err(err) => {
                warn!(
                    path = %self.active_path.display(),
                    error = %err,
                    "could not empty the OpenBao audit device's active log"
                );
                Self::recover(&target);
                return RotationOutcome::Failed;
            }
        };

        // Past the commit point. The generation now holds records the
        // active log no longer does, so nothing below unlinks it.
        if let Err(err) = self.sync_active(&active) {
            warn!(
                path = %self.active_path.display(),
                generation = %target.display(),
                error = %err,
                "could not flush the emptied OpenBao audit log; the generation is kept, since it \
                 is now the only copy of those records"
            );
            return RotationOutcome::Failed;
        }

        debug!(
            generation = %target.display(),
            captured_bytes = len,
            "rotated the OpenBao audit device"
        );
        RotationOutcome::Completed
    }

    /// Returns the path the next generation is published under, or
    /// `None` where the chosen stamp's sequence namespace is exhausted.
    ///
    /// The stamp is the **greater** of the stamp for `now` and the
    /// newest existing generation's, and the sequence is one past the
    /// greatest already present under whichever won — never the lowest
    /// unused one. Both rules exist for the trim: it drops oldest-first
    /// by name, so a name that sorted before an existing generation
    /// would have it delete the file it has just written.
    fn published_path(&self, now: OffsetDateTime) -> io::Result<Option<PathBuf>> {
        let generations = self.rotated_generations()?;
        let mut stamp = rotation_stamp(now);
        if let Some(newest) = generations.last()
            && let Some((found, _)) = parse_rotated_name(&newest.name)
            && found > stamp.as_str()
        {
            stamp = found.to_string();
        }
        let mut next = 0_u32;
        for generation in &generations {
            if let Some((found, sequence)) = parse_rotated_name(&generation.name)
                && found == stamp
                && sequence >= next
            {
                next = sequence.saturating_add(1);
            }
        }
        if next > MAX_SEQUENCE {
            return Ok(None);
        }
        Ok(Some(self.dir.join(rotated_file_name(&stamp, next))))
    }

    /// Runs the hook a test installs in the window the size decision
    /// has already passed through and the copy has not yet opened, so
    /// the replacement it plants is racing the open rather than the
    /// stat.
    #[cfg(test)]
    fn before_stage_hook(&self) {
        if let Some(hook) = self.faults.before_stage() {
            hook(&self.active_path);
        }
    }

    /// Copies the active log's first `len` bytes into the staging file,
    /// trims the copy to its last record boundary, gives it the device
    /// directory's owner and flushes it.
    ///
    /// Returns the descriptors the copy was written through and read
    /// from, or `None` where the captured prefix held no `\n` at all
    /// and there is therefore no complete record to rotate.
    ///
    /// Descriptors rather than the staged length or a path, because
    /// every step after this one has to know *which file*, not which
    /// name: both names live in a directory the container's audit user
    /// can write, so either can stop leading here at any moment.
    /// [`Self::publish`] compares the published name against the
    /// staging descriptor's inode and [`Self::truncate_active`]
    /// compares what it opens against the source's. Holding both open
    /// for the rest of the pass is what makes those comparisons mean
    /// anything: an inode freed in the meantime could have its number
    /// recycled onto the replacement.
    fn stage_prefix(&self, len: u64) -> io::Result<Option<StagedCopy>> {
        // Reading through a planted link would copy an arbitrary
        // root-readable file into a generation this pass then chowns to
        // the container's audit user, and reading through a planted
        // FIFO would never return at all. [`open_active`] refuses both.
        let mut source = open_active(OpenOptions::new().read(true), &self.active_path)?;
        // A staging file left behind by a crashed pass would keep the
        // mode it was created with, and this one's mode has to come
        // from its own creation.
        match std::fs::remove_file(&self.staging_path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }
        let staging = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(GENERATION_FILE_MODE)
            .open(&self.staging_path)?;

        let mut writer = io::BufWriter::new(&staging);
        let chunk = usize::try_from(COPY_CHUNK_BYTES).unwrap_or(usize::MAX);
        let mut buffer = vec![0_u8; chunk];
        let mut remaining = len;
        let mut copied = 0_u64;
        let mut last_record_end: Option<u64> = None;
        while remaining > 0 {
            let want = usize::try_from(remaining.min(COPY_CHUNK_BYTES)).unwrap_or(chunk);
            let Some(slice) = buffer.get_mut(..want) else {
                break;
            };
            let read = source.read(slice)?;
            if read == 0 {
                // The file is shorter than the captured length, which
                // an appender cannot produce. Rotate what is there.
                break;
            }
            let Some(bytes) = buffer.get(..read) else {
                break;
            };
            if let Some(position) = bytes.iter().rposition(|byte| *byte == b'\n') {
                let offset = u64::try_from(position).map_err(io::Error::other)?;
                last_record_end = Some(copied.saturating_add(offset).saturating_add(1));
            }
            writer.write_all(bytes)?;
            let advanced = u64::try_from(read).map_err(io::Error::other)?;
            copied = copied.saturating_add(advanced);
            remaining = remaining.saturating_sub(advanced);
        }
        writer.flush()?;
        drop(writer);

        let Some(end) = last_record_end else {
            return Ok(None);
        };
        // Trimming the *staging* copy, before it is a generation.
        // "Written once, never rewritten" is about published
        // generations and is untouched by this.
        staging.set_len(end)?;

        // Ownership from the device directory rather than hard-coded:
        // the Compose entrypoint chowns it to the image's own
        // `openbao:openbao` and the numeric ids come from the image.
        //
        // Applied to the descriptor this pass created rather than to the
        // path it created it at. The device directory is writable by the
        // container's audit user, so a path-based `chown` run by a root
        // daemon would follow whatever that name resolves to at the
        // instant of the call; `fchown` can only ever reach the staging
        // copy itself.
        let owner = std::fs::metadata(&self.dir)?;
        std::os::unix::fs::fchown(&staging, Some(owner.uid()), Some(owner.gid()))?;
        // Flushed after the mode and the ownership, never before: an
        // `fsync` persists the inode as it stands.
        self.sync_staging(&staging)?;
        Ok(Some(StagedCopy {
            staged: staging,
            source,
        }))
    }

    /// Publishes the staged inode under `target`, and returns only once
    /// the name that now exists is that inode.
    ///
    /// `rename` cannot do this. It resolves the source name at the
    /// instant of the call, and the device directory is writable by the
    /// container's audit user, so between the staging copy's flush and
    /// the publish that user can unlink `.audit-rotate.staging` and put
    /// an empty file of their own there. A `rename` would publish the
    /// replacement, the directory flush would succeed, and the truncate
    /// below it would then destroy the records the pass believed it had
    /// just copied. That is the one failure this module must not have:
    /// every other one leaves the active log intact.
    ///
    /// So the publish is `link` plus a check, and each half earns its
    /// place:
    ///
    /// - `link` refuses an existing `target` with `EEXIST`, where
    ///   `rename` would replace it silently. A name collision means the
    ///   directory changed under the sequence this pass derived, and
    ///   overwriting is how an *already published* generation's records
    ///   would be destroyed.
    /// - Comparing the published name's `(device, inode)` against the
    ///   staged descriptor's is what catches the replacement, after the
    ///   fact but still before the commit point. The descriptor is
    ///   held open by the caller, so its inode cannot have been freed
    ///   and re-allocated onto the impostor. It also settles the one
    ///   thing [`std::fs::hard_link`] leaves to the platform — whether
    ///   a symbolic link at the source is followed — since either
    ///   answer produces an inode that is not the staged one.
    ///
    /// The staging name is then unlinked, which is what `rename` would
    /// have done in the same step. Nothing is durable until the caller
    /// flushes the directory, and one flush covers both entries.
    ///
    /// The target link is this method's to undo rather than the
    /// caller's, because only here is it known whether one was made:
    /// a `link` that failed created nothing, and the `EEXIST` case is
    /// precisely a target this pass does not own. A caller unlinking
    /// `target` on any error would delete the very generation the
    /// refusal protected.
    ///
    /// # Errors
    ///
    /// Returns the `link`, `stat` or `unlink` error, or
    /// [`io::ErrorKind::InvalidInput`] where the published name did not
    /// reach the staged inode. Every one of those is a failed pass,
    /// before the commit point, so nothing this pass published survives
    /// and the active log is left whole.
    fn publish(&self, staged: &File, target: &Path) -> io::Result<()> {
        let staged_id = file_identity(&staged.metadata()?);
        std::fs::hard_link(&self.staging_path, target)?;
        let published = match std::fs::symlink_metadata(target) {
            Ok(published) => published,
            Err(err) => {
                Self::recover(target);
                return Err(err);
            }
        };
        if file_identity(&published) != staged_id {
            Self::recover(target);
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} did not name the staged copy when it was published; the staging path was \
                     replaced before the link",
                    self.staging_path.display()
                ),
            ));
        }
        if let Err(err) = std::fs::remove_file(&self.staging_path) {
            Self::recover(target);
            return Err(err);
        }
        Ok(())
    }

    /// Re-establishes that `target` still names the staged copy,
    /// immediately before the commit point.
    ///
    /// [`Self::publish`] settled that when it linked the name, but the
    /// directory flush runs after it and the device directory is
    /// writable by the container's audit user for the whole of that
    /// window. Unlinking the generation and leaving an empty file of
    /// their own at the name would otherwise have the truncate below
    /// destroy the only other copy of those records — and the pass
    /// report a rotation that captured nothing. The staged descriptor
    /// is still open, so its inode cannot have been freed and
    /// re-allocated onto the replacement.
    ///
    /// This narrows the window rather than closing it: a check and the
    /// truncate it guards cannot be one operation, which is why it is
    /// the last thing a pass does before that truncate. What it does
    /// close is the interval spanning the directory flush, which is a
    /// disk round trip rather than a few instructions.
    ///
    /// A name the check does not recognise is left exactly where it is.
    /// This pass no longer holds a link to it, and unlinking a name
    /// that leads somewhere else would delete a file that is not this
    /// pass's — the same reason [`Self::publish`] leaves a collision
    /// alone.
    ///
    /// # Errors
    ///
    /// Returns the `stat` error, or [`io::ErrorKind::InvalidInput`]
    /// where the name no longer leads to the staged copy. Both are
    /// failed passes before the commit point, so the active log keeps
    /// every record and the next tick retries.
    fn confirm_published(staged: &File, target: &Path) -> io::Result<()> {
        let staged_id = file_identity(&staged.metadata()?);
        let published = std::fs::symlink_metadata(target)?;
        if file_identity(&published) != staged_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} no longer names the copy this pass staged; it was replaced after it was \
                     published",
                    target.display()
                ),
            ));
        }
        Ok(())
    }

    /// Empties the active log in place, returning the descriptor the
    /// truncate went through so its flush is of the same file.
    ///
    /// Opened `write` without `create` or `truncate`, so a log that
    /// vanished between the capture and here is an error rather than a
    /// new empty file this pass created. Truncating in place is also
    /// what preserves the log's owner and mode: nothing root-owned ever
    /// replaces it.
    ///
    /// And opened through [`open_active`], which refuses anything that
    /// is not the regular file `OpenBao` writes — the same rule
    /// [`crate::registrar::audit`] holds its own active file to. The
    /// device directory is writable by the container's audit user and
    /// this pass runs as root, so whatever is planted at `audit.log`
    /// would otherwise be what root truncates.
    ///
    /// That the descriptor is a regular file is not enough on its own.
    /// A *second* regular file put at `audit.log` in the window between
    /// the copy and here would pass every check [`open_active`] makes,
    /// and emptying it would rotate a file this pass never read while
    /// `OpenBao` went on appending to the original through the descriptor
    /// it still holds — the log unbounded, the pass reporting success,
    /// and the failure counter never moving. So the descriptor is
    /// compared against `source`, the one the copy was read through,
    /// and a truncate only ever lands on the file whose records the
    /// generation now holds. `source` is open for the comparison, so
    /// the identity it is made against cannot have been recycled onto
    /// the replacement.
    ///
    /// # Errors
    ///
    /// Returns the `open`, `fstat` or `ftruncate` error, or
    /// [`io::ErrorKind::InvalidInput`] where the pathname no longer
    /// leads to the file the copy was read through. Every one of those
    /// is a failed pass before the commit point.
    fn truncate_active(&self, source: &File) -> io::Result<File> {
        #[cfg(test)]
        if self.faults.truncate_fails() {
            return Err(io::Error::other("injected truncate failure"));
        }
        let source_id = file_identity(&source.metadata()?);
        let file = open_active(OpenOptions::new().write(true), &self.active_path)?;
        if file_identity(&file.metadata()?) != source_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is no longer the file this pass copied; refusing to empty the replacement",
                    self.active_path.display()
                ),
            ));
        }
        file.set_len(0)?;
        Ok(file)
    }

    fn sync_staging(&self, staging: &File) -> io::Result<()> {
        #[cfg(test)]
        if self.faults.staging_sync_fails() {
            return Err(io::Error::other("injected staging flush failure"));
        }
        staging.sync_all().map_err(|err| {
            io::Error::other(format!("flushing {}: {err}", self.staging_path.display()))
        })
    }

    fn sync_active(&self, active: &File) -> io::Result<()> {
        #[cfg(test)]
        if self.faults.active_sync_fails() {
            return Err(io::Error::other("injected active-log flush failure"));
        }
        active.sync_all().map_err(|err| {
            io::Error::other(format!("flushing {}: {err}", self.active_path.display()))
        })
    }

    /// Flushes the device's own directory, so a name published in it
    /// survives a power failure.
    ///
    /// One directory holds the active log, the staging copy and every
    /// generation, so there is only ever this one entry list to flush
    /// and it is reached through a path this rotation already owns.
    fn sync_dir(&self) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.faults.directory_sync_fails() {
            anyhow::bail!("injected directory flush failure");
        }
        sync_parent_dir(&self.active_path)
    }

    /// Flushes the device's directory after a trim, so the deletions
    /// survive a power failure.
    fn sync_trimmed_dir(&self) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.faults.trim_sync_fails() {
            anyhow::bail!("injected trim flush failure");
        }
        sync_parent_dir(&self.active_path)
    }

    /// Unlinks a copy the pass is abandoning and flushes the directory
    /// so a crash cannot resurrect it.
    ///
    /// Only ever called **before** the truncate has succeeded, where the
    /// active log still holds every byte the copy duplicates and
    /// unlinking loses nothing. A recovery that itself fails says which
    /// path it left behind, so an operator gets one message naming the
    /// file to remove by hand.
    fn recover(path: &Path) {
        match std::fs::remove_file(path) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(err) => {
                error!(
                    path = %path.display(),
                    error = %err,
                    "could not remove the abandoned OpenBao audit copy; remove it by hand"
                );
                return;
            }
        }
        if let Err(err) = sync_parent_dir(path) {
            error!(
                path = %path.display(),
                error = %format!("{err:#}"),
                "could not flush the directory after removing the abandoned OpenBao audit copy"
            );
        }
    }

    /// Returns every rotated generation, sorted lexicographically —
    /// which, given the fixed-width stamp and sequence, is oldest first.
    ///
    /// Deliberately not bounded by `N + 1`: the set can legitimately be
    /// larger than the bound, which is the lowered-bound case the trim
    /// exists to repair.
    fn rotated_generations(&self) -> io::Result<Vec<Generation>> {
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err),
        };
        let mut generations = Vec::new();
        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if parse_rotated_name(name).is_none() {
                continue;
            }
            let len = match entry.metadata() {
                Ok(meta) => meta.len(),
                // Gone between the listing and the stat, so there is no
                // generation left to count against the budget.
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                // Present but unmeasurable, which is a different thing:
                // the listing fails rather than silently omitting a
                // generation, because a set understated against its own
                // budget would report the ceiling holding on no
                // evidence.
                Err(err) => return Err(err),
            };
            generations.push(Generation {
                path: entry.path(),
                name: name.to_string(),
                len,
            });
        }
        generations.sort_unstable_by(|left, right| left.name.cmp(&right.name));
        Ok(generations)
    }

    /// Drops generations oldest-first until at most `N` remain **and**
    /// their total is at or under `S × N`.
    ///
    /// Count alone would not hold the byte ceiling: a generation is as
    /// large as the active log's stable prefix was when it rotated,
    /// which a periodic check can legitimately make `S` plus one
    /// interval's writes.
    ///
    /// Never rolled back. Deletions are oldest-first, so a deletion
    /// that errors part-way leaves the earlier ones standing and that
    /// set is strictly closer to the bound; the next pass resumes from
    /// wherever this one reached.
    ///
    /// The deletions are durable only once the directory holding them
    /// is flushed, and that flush is retried on every later pass until
    /// it succeeds — including on a pass that deleted nothing, since a
    /// host quiet enough never to trim again would otherwise carry the
    /// debt forever without ever re-attempting it, and including the
    /// first pass a new task runs, which starts owing one because it
    /// cannot know what the task before it left unflushed.
    fn trim(&mut self) {
        let generations = match self.rotated_generations() {
            Ok(generations) => generations,
            Err(err) => {
                warn!(
                    directory = %self.dir.display(),
                    error = %err,
                    "could not list the retained OpenBao audit generations to trim them"
                );
                return;
            }
        };
        let budget = retained_budget_bytes(self.max_file_bytes, self.max_retained_files);
        let retained_cap = usize::try_from(self.max_retained_files).unwrap_or(usize::MAX);
        let mut total = generations
            .iter()
            .fold(0_u64, |sum, generation| sum.saturating_add(generation.len));
        let mut removed = false;
        for (index, generation) in generations.iter().enumerate() {
            let remaining = generations.len() - index;
            if remaining <= retained_cap && total <= budget {
                break;
            }
            if remaining == 1 {
                // One interval produced more audit output than the
                // whole retained budget. Dropping it whole is the
                // ceiling being enforced; truncating or rewriting it
                // would leave a corrupted JSON Lines file behind.
                warn!(
                    generation = %generation.name,
                    generation_bytes = generation.len,
                    retained_budget_bytes = budget,
                    interval_secs = ROTATION_INTERVAL.as_secs(),
                    "dropping the single newest OpenBao audit generation whole: by itself it \
                     exceeds the entire retained budget"
                );
            }
            #[cfg(test)]
            let removal = if index >= self.faults.trim_fails_from() {
                Err(io::Error::other("injected generation removal failure"))
            } else {
                std::fs::remove_file(&generation.path)
            };
            #[cfg(not(test))]
            let removal = std::fs::remove_file(&generation.path);
            if let Err(err) = removal {
                warn!(
                    path = %generation.path.display(),
                    error = %err,
                    "could not drop an OpenBao audit generation; the next pass resumes from here"
                );
                break;
            }
            total = total.saturating_sub(generation.len);
            removed = true;
        }
        if removed || self.trim_flush_pending {
            match self.sync_trimmed_dir() {
                Ok(()) => self.trim_flush_pending = false,
                Err(err) => {
                    // Not a warning that is then dropped: the listing
                    // the pass is about to take no longer sees the
                    // deleted generations, so an unflushed trim would
                    // otherwise read as the bound met and reset the
                    // failure counter, while a crash could restore the
                    // whole over-budget set. The debt is carried into
                    // the pass's outcome instead, and re-attempted.
                    self.trim_flush_pending = true;
                    warn!(
                        directory = %self.dir.display(),
                        error = %format!("{err:#}"),
                        "could not flush the directory after trimming OpenBao audit \
                         generations; the deletions are not durable and the retained-set bound \
                         stays unmet until a flush succeeds"
                    );
                }
            }
        }
    }
}

/// Runs one device's rotation until the daemon is asked to stop.
///
/// The interval is a parameter so a test does not wait a minute for a
/// tick; production passes [`ROTATION_INTERVAL`].
///
/// Rotation is an operational duty and not a fail-closed control, so
/// this returns `Ok` on every filesystem failure it meets: a failed pass
/// must never fail an `OpenBao` request, stop the daemon or take the
/// registrar endpoint down.
pub(crate) async fn run_rotation_loop(
    mut rotation: OpenBaoAuditRotation,
    interval: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            _ = shutdown.changed() => break,
            () = tokio::time::sleep(interval) => {
                // The pass is blocking filesystem work — a whole-file
                // copy among it — so it runs off the reactor.
                let joined = tokio::task::spawn_blocking(move || {
                    let outcome = rotation.run_pass(OffsetDateTime::now_utc());
                    (rotation, outcome)
                })
                .await;
                match joined {
                    Ok((returned, outcome)) => {
                        rotation = returned;
                        report_pass(&outcome);
                    }
                    Err(err) => {
                        error!(
                            error = %err,
                            "the OpenBao audit device rotation pass did not return; \
                             this device is no longer being rotated"
                        );
                        return Ok(());
                    }
                }
            }
        }
    }
    Ok(())
}

/// Summarises a pass that did something, at `debug`.
///
/// Deliberately silent on a pass with nothing to report — a quiet host,
/// or one where the gate is on but the store was never provisioned,
/// says nothing at all rather than a line a minute. The `warn` and the
/// `error` an unmet obligation earns are emitted by the pass itself and
/// do not depend on this.
fn report_pass(outcome: &PassOutcome) {
    let nothing_happened =
        !outcome.rotated() && !outcome.rotation.is_unmet() && !outcome.retained_unmet;
    if !outcome.evaluated || nothing_happened {
        return;
    }
    debug!(
        rotation = outcome.rotation.label(),
        retained_unmet = outcome.retained_unmet,
        trim_flush_pending = outcome.trim_flush_pending,
        consecutive_failures = outcome.consecutive_failures,
        active_log_bytes = outcome.active_bytes,
        retained_set_bytes = outcome.retained_bytes,
        retained_files = outcome.retained_files,
        "completed an OpenBao audit device rotation pass"
    );
}
