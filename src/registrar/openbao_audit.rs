//! Rotation of `OpenBao`'s file audit device, and the bounds the daemon
//! holds the generations it creates to.
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
//! - **An active log cleared of the records a successful pass rotated**,
//!   either by moving the whole file into the retained set or by
//!   truncating it to zero.
//! - **A loud signal when neither is happening**, in the shape of a
//!   consecutive-failure counter that escalates from `warn` to `error`.
//!
//! What it does **not** deliver is an absolute ceiling on the device's
//! footprint. `OpenBao`'s write rate is an assumption about `OpenBao`,
//! not a limit bootroot imposes, and a run of failed passes leaves the
//! active log growing for as many intervals as the run lasts.
//!
//! # The two forms
//!
//! A pass attempts **rename-and-reopen** first and falls back to
//! **copy-and-truncate** on the same tick when the reopen cannot be
//! confirmed.
//!
//! **Rename-and-reopen** renames `audit.log` to its generation name,
//! flushes the directory, sends `SIGHUP` to the container's main
//! process and waits for `OpenBao` to create a fresh `audit.log`.
//! Nothing is copied and nothing is truncated, so **not one byte is
//! lost**: `OpenBao`'s descriptor still refers to the renamed inode and
//! keeps every record it wrote, and the new file starts empty. It also
//! stages no copy, so the device's expected in-pass peak is one active
//! log smaller than the fallback's.
//!
//! **Copy-and-truncate** copies the active log's stable prefix into a
//! staging file, publishes it as a generation and truncates the
//! original to zero through the descriptor it copied from. It needs no
//! cooperation from `OpenBao` at all, which is why it is what a
//! deployment whose image does not honour the signal keeps getting —
//! at the cost of a loss window, since every record appended after the
//! length was captured, and the partial trailing record, are destroyed
//! by the truncate. Nothing is torn: a record is either complete in the
//! generation or gone entirely.
//!
//! Both forms rest on the daemon and the container seeing **one**
//! filesystem, which they do: `<audit_store_dir>/openbao` is
//! bind-mounted into the container from the same Linux host the daemon
//! runs on. (A macOS developer machine is not that: Docker Desktop
//! reaches a host bind mount through a VM, which does not propagate a
//! host-side truncate to the guest's cached length. The `docker-compose`
//! deployment target does not have that layer.)
//!
//! # The availability invariant
//!
//! Rename-first necessarily leaves the configured path **absent** from
//! the rename until `OpenBao` recreates it or the recovery renames the
//! generation back. The invariant is therefore about the descriptor,
//! not the name:
//!
//! - `OpenBao`'s already-open descriptor stays writable throughout, since
//!   it refers to the inode rather than to the name;
//! - a pass that succeeds does not return until the path is present
//!   again;
//! - no root-owned active file is ever created at that path — the
//!   daemon never pre-creates `audit.log`, because a root-owned `0600`
//!   file in a directory the container cannot chown is a device that
//!   cannot write.
//!
//! # The rotation-intent marker
//!
//! Immediately **before** the rename, a pass writes
//! `rotation-intent.json` into the device directory holding the active
//! log's `(st_dev, st_ino)` and the generation name it is about to
//! rename to. Rename preserves the inode, so that identity names the
//! same file before and after — the identity every recovery branch
//! decides by. The ordering is the whole point: a marker written after
//! the rename leaves exactly the rename-succeeded, marker-absent state
//! it exists to prevent.
//!
//! Its removal is as load-bearing as its writing. A pass removes it
//! whenever it ends with no rotation in flight, and a removal that fails
//! is not a successful pass: it is logged at `error`, counts toward the
//! escalation, and is retried before anything else on every later tick.
//! Two states deliberately keep it — a pending restore, and a
//! rename-back whose directory flush failed.
//!
//! Any marker found at the start of a pass whose active path is present
//! is stale **by construction** — rotations are serialized and a pass
//! writes its own intent only after that point — so it is removed
//! before that pass does anything else, whatever identity it records. A
//! completed fallback and a successful rename-back both leave
//! `audit.log` on exactly the inode the marker recorded, so an identity
//! test would read those markers as live and keep them for ever.
//!
//! # The residual
//!
//! A crash between the fallback's truncate and its flush landing can
//! resurrect the active log at its pre-truncate length while the
//! generation survives, so the next pass rotates an overlapping prefix
//! and two generations share records. Reading the retained set back with
//! `cat` then stays *complete* — every retained record appears at least
//! once — but stops being exact and stops being in write order. Nothing
//! here de-duplicates: two byte-identical lines can be two genuine
//! events, and dropping one would destroy evidence.
//!
//! One residual of the marker-authorised restore is a **loss
//! condition** rather than a cosmetic one, and it is stated rather than
//! hidden. It is documented on the branch that reaches it, the one a
//! pass takes when it starts with the active path absent and nothing
//! pending.

use std::ffi::CString;
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read as _, Seek as _, Write as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

use crate::fs_util::{self, Destination, StagedMode, sync_parent_dir};
use crate::registrar::audit_store::OPENBAO_CONTAINER_AUDIT_DIR;

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

/// The rotation-intent marker's fixed name in the device directory.
///
/// Outside the `audit-*.log` glob, so no listing, bound or trim ever
/// sees it, and inside the directory the store layout already
/// provisions, so it needs no directory of its own.
const MARKER_FILE_NAME: &str = "rotation-intent.json";

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

/// Mode a staging copy, a published generation and the marker are
/// created with.
///
/// Applied at creation rather than by a later `set_permissions`, so the
/// file never exists at a wider mode for any instant. It is what the
/// active log already carries, so the whole family reads uniformly on
/// the host and through `docker exec`.
const GENERATION_FILE_MODE: u32 = 0o600;

/// Bytes copied per read while staging the stable prefix.
const COPY_CHUNK_BYTES: u64 = 64 * 1024;

/// How long a pass waits for `OpenBao` to recreate the active log after
/// the signal.
///
/// A constant rather than a configuration key, and short beside
/// [`ROTATION_INTERVAL`] so a pass that has to fall back still completes
/// on its own tick.
const REOPEN_DEADLINE: Duration = Duration::from_secs(5);

/// How often that wait looks at the active path.
///
/// A reopen is not synchronous with the signal, so a single check made
/// immediately after `SIGHUP` reads a working reopen as a failure and
/// drives the lossy fallback for nothing.
const REOPEN_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// How long any one `docker` child process may run before it is killed.
///
/// An unresponsive Docker daemon must not block the rotation task: the
/// child is killed when this expires and the pass treats the expiry as
/// an unconfirmed reopen like any other addressing failure.
const DOCKER_DEADLINE: Duration = Duration::from_secs(5);

/// How often a `docker` child is checked for having exited.
const DOCKER_POLL_INTERVAL: Duration = Duration::from_millis(20);

/// Default size bound on the **active** log, in bytes (64 MiB).
///
/// Derived from the shared store's 2 GiB reserve: with
/// [`DEFAULT_OPENBAO_AUDIT_MAX_RETAINED_FILES`] the retained ceiling is
/// 448 MiB and the device's expected in-pass peak is 576 MiB where a
/// pass falls back, which leaves the verb-record store's 136 MiB and
/// about 1.3 GiB of headroom.
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

// ---------------------------------------------------------------------
// Addressing and signalling the container
// ---------------------------------------------------------------------

/// Every `docker` invocation a rotation pass makes, behind one seam.
///
/// A seam rather than direct calls because each of the failures the
/// rotation has to answer for — Docker unreachable, no container
/// matching the device's bind mount, several matching it, a non-zero
/// exit, a call that outlives its deadline — has to be drivable in a
/// test without a Docker daemon, and none of them can be provoked from
/// outside the process otherwise.
pub(crate) trait DockerControl: Send + Sync {
    /// Returns the ids of the containers Docker reports running.
    ///
    /// # Errors
    ///
    /// Returns an error where the `docker` invocation could not be run,
    /// exited non-zero, or outlived its deadline.
    fn running_containers(&self) -> anyhow::Result<Vec<String>>;

    /// Returns `container`'s mount table, as the JSON array
    /// `docker inspect --format '{{json .Mounts}}'` prints.
    ///
    /// # Errors
    ///
    /// As [`DockerControl::running_containers`].
    fn container_mounts(&self, container: &str) -> anyhow::Result<String>;

    /// Sends `SIGHUP` to `container`'s main process, without restarting
    /// it.
    ///
    /// # Errors
    ///
    /// As [`DockerControl::running_containers`]. A failure here is
    /// **not** proof that the signal never arrived: the pass decides
    /// from the filesystem either way.
    fn signal_hup(&self, container: &str) -> anyhow::Result<()>;
}

/// The shipped [`DockerControl`], which runs the `docker` CLI.
pub(crate) struct DockerCli;

impl DockerControl for DockerCli {
    fn running_containers(&self) -> anyhow::Result<Vec<String>> {
        let output = run_docker(&["ps", "--quiet", "--no-trunc"])?;
        Ok(output
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect())
    }

    fn container_mounts(&self, container: &str) -> anyhow::Result<String> {
        run_docker(&["inspect", "--format", "{{json .Mounts}}", container])
    }

    fn signal_hup(&self, container: &str) -> anyhow::Result<()> {
        run_docker(&["kill", "--signal=HUP", container]).map(|_| ())
    }
}

/// Runs `docker` with `args`, bounded by [`DOCKER_DEADLINE`], and
/// returns what it printed to `stdout`.
///
/// The child's `stdout` goes to an unnamed temporary file rather than a
/// pipe. A pipe would have to be drained while the child runs or the
/// child blocks once the pipe buffer fills, and this caller cannot
/// drain one: it is polling for the deadline, which is the whole point.
///
/// The deadline is enforced by polling [`std::process::Child::try_wait`]
/// rather than by blocking in `wait`, so a Docker daemon that never
/// answers costs one killed child rather than a rotation task that stops
/// ticking. This runs inside the pass's blocking phase, so the poll's
/// sleep parks a blocking thread rather than the reactor.
///
/// # Errors
///
/// Returns an error where the child could not be spawned, exited
/// non-zero, or was still running at the deadline.
fn run_docker(args: &[&str]) -> anyhow::Result<String> {
    use anyhow::Context as _;

    let mut stdout = tempfile::tempfile()
        .context("creating the temporary file `docker` writes its output to")?;
    let sink = stdout
        .try_clone()
        .context("duplicating the temporary file `docker` writes its output to")?;
    let mut child = Command::new("docker")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(sink))
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("running `docker {}`", args.join(" ")))?;

    let started = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(err) => {
                return Err(anyhow::Error::new(err)
                    .context(format!("waiting for `docker {}`", args.join(" "))));
            }
        }
        if started.elapsed() >= DOCKER_DEADLINE {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "`docker {}` did not finish within {} seconds and was killed",
                args.join(" "),
                DOCKER_DEADLINE.as_secs()
            );
        }
        std::thread::sleep(DOCKER_POLL_INTERVAL);
    };
    if !status.success() {
        anyhow::bail!("`docker {}` exited with {status}", args.join(" "));
    }
    stdout
        .rewind()
        .context("rewinding the temporary file `docker` wrote its output to")?;
    let mut body = String::new();
    stdout
        .read_to_string(&mut body)
        .context("reading what `docker` printed")?;
    Ok(body)
}

/// Why a pass could not address this install's `OpenBao` container.
///
/// Every variant is an unconfirmed reopen rather than an error that
/// stops the rotation task, and every one of them happens **before**
/// anything moves, so the pass falls back on the same tick with no
/// recovery to run.
#[derive(Debug, Clone, PartialEq, Eq)]
enum AddressingFailure {
    /// `docker` could not be run, exited non-zero, or outlived its
    /// deadline.
    Docker(String),
    /// The device directory itself could not be resolved to the path a
    /// container's mount table would carry.
    Device(String),
    /// No running container binds this install's device directory at
    /// the container audit path.
    NoMatch,
    /// Several do, which is unaddressable exactly as none is: picking
    /// one would signal an install that is not this one.
    Ambiguous(usize),
}

impl AddressingFailure {
    fn label(&self) -> String {
        match self {
            Self::Docker(err) => format!("docker: {err}"),
            Self::Device(err) => format!("device directory: {err}"),
            Self::NoMatch => "no running container binds this device directory".to_string(),
            Self::Ambiguous(count) => {
                format!("{count} running containers bind this device directory")
            }
        }
    }
}

// ---------------------------------------------------------------------
// The rotation-intent marker
// ---------------------------------------------------------------------

/// What a pass records on disk immediately before it renames the active
/// log aside.
///
/// One path and two integers, and no secret: it names a file inside the
/// device directory and the `(st_dev, st_ino)` that file carried when
/// the pass looked. `rename` preserves the inode, so that identity
/// names the same file before and after the rename — which is what lets
/// a restarted daemon tell its own interrupted rotation from an
/// unrelated generation that merely happens to be the newest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RotationIntent {
    /// `st_dev` of the active log, as observed immediately before the
    /// rename.
    active_dev: u64,
    /// `st_ino` of the same observation.
    active_ino: u64,
    /// The generation name the pass was about to rename to.
    generation: String,
}

impl RotationIntent {
    fn identity(&self) -> (u64, u64) {
        (self.active_dev, self.active_ino)
    }
}

// ---------------------------------------------------------------------
// Renaming without replacing
// ---------------------------------------------------------------------

/// Renames `from` to `to`, failing with `EEXIST` rather than replacing
/// anything already at `to`.
///
/// The recovery's rename-back needs exactly this and `std` has no
/// wrapper for it. A check-then-rename would race `OpenBao` creating
/// the new active log in the window between the two calls, and losing
/// that race means renaming the generation over the file `OpenBao` has
/// just started appending to.
///
/// # Errors
///
/// Returns the `renameat2` error, [`io::ErrorKind::AlreadyExists`]
/// among them, or [`io::ErrorKind::InvalidInput`] where either path
/// holds an interior NUL byte.
#[cfg(target_os = "linux")]
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let from_c = CString::new(from.as_os_str().as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let to_c = CString::new(to.as_os_str().as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    // SAFETY: both arguments are NUL-terminated C strings owned by the
    // locals above, which outlive the call; `renameat2` reads them and
    // retains nothing. `AT_FDCWD` with a path resolved exactly as
    // `rename(2)` resolves it is what the call documents, and
    // `RENAME_NOREPLACE` is the one flag passed.
    let result = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            from_c.as_ptr(),
            libc::AT_FDCWD,
            to_c.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// The macOS spelling of [`rename_noreplace`].
///
/// The deployment target is Linux, and this exists so the crate builds
/// and its tests run on a developer machine rather than because a
/// device is ever rotated there. `renamex_np` with `RENAME_EXCL` is the
/// same refusal `RENAME_NOREPLACE` gives, under the platform's own
/// name.
///
/// # Errors
///
/// As the Linux form.
#[cfg(target_os = "macos")]
fn rename_noreplace(from: &Path, to: &Path) -> io::Result<()> {
    let from_c = CString::new(from.as_os_str().as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let to_c = CString::new(to.as_os_str().as_bytes())
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    // SAFETY: both arguments are NUL-terminated C strings owned by the
    // locals above, which outlive the call; `renamex_np` reads them and
    // retains nothing. `RENAME_EXCL` is the one flag passed.
    let result = unsafe { libc::renamex_np(from_c.as_ptr(), to_c.as_ptr(), libc::RENAME_EXCL) };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// ---------------------------------------------------------------------
// Files, names and identities
// ---------------------------------------------------------------------

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
///   writer arrives; that open is inside a blocking phase, and a thread
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
fn file_identity(meta: &Metadata) -> (u64, u64) {
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

/// What is at the active path, decided against a rotated generation's
/// identity.
///
/// **The one predicate that decides success everywhere.** "Reopened"
/// means the configured path exists *and* its `(st_dev, st_ino)`
/// differs from the rotated generation's — presence alone is not the
/// test, since the generation *is* the inode the path used to name. The
/// confirmation after the signal, the recovery's first look and the
/// re-stat after an `EEXIST` all decide by this and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveLook {
    /// Nothing at the path.
    Absent,
    /// A regular file on an inode that is not the generation's: the
    /// reopen happened.
    Reopened,
    /// A file carrying the generation's own identity. Nothing in this
    /// mechanism produces that state.
    Generation,
    /// Something at the path that is not the regular file `OpenBao`
    /// writes.
    Foreign,
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
    /// No active log at the configured path, or one below `S`, or a
    /// tick a cleared restore consumed. Not an obligation at all, so it
    /// never increments the counter.
    NotRequired,
    /// A generation is in place and the active log holds none of its
    /// records.
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

/// Which mechanism a pass's rotation went through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotationForm {
    /// The pass rotated nothing, or stopped before either form
    /// committed.
    None,
    /// Rename-and-reopen: the active file became the generation and
    /// `OpenBao` created a new one. Nothing copied, nothing truncated,
    /// no record lost.
    Signal,
    /// Copy-and-truncate, taken because the reopen could not be
    /// confirmed.
    Fallback,
}

/// What one pass observed and did, for a caller that wants to assert on
/// it rather than read the log.
///
/// Each flag names a distinct obligation or outstanding debt, and they
/// are independent: a pass can owe a trim flush, hold a restore and owe
/// a marker removal at once. Folding them into two-variant enums would
/// rename the same six answers without joining any of them.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PassOutcome {
    /// Whether the device directory was there to evaluate at all.
    pub(crate) evaluated: bool,
    /// What the rotation half of the pass did.
    pub(crate) rotation: RotationOutcome,
    /// Which form it went through.
    pub(crate) form: RotationForm,
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
    /// Whether the live audit inode is still sitting under a generation
    /// name because a rename-back has not succeeded.
    pub(crate) restore_pending: bool,
    /// Whether a rotation-intent marker's removal is still owed.
    pub(crate) marker_cleanup_pending: bool,
    /// The active log's size when the pass returned.
    pub(crate) active_bytes: u64,
    /// The retained set's total size when the pass returned.
    pub(crate) retained_bytes: u64,
    /// How many generations the retained set held when the pass
    /// returned.
    pub(crate) retained_files: usize,
}

impl PassOutcome {
    /// Whether a generation was published and the active log cleared of
    /// the records it holds.
    pub(crate) fn rotated(self) -> bool {
        self.rotation == RotationOutcome::Completed
    }
}

/// The live audit inode sitting under a rotated generation's name,
/// because a rename-back did not succeed.
///
/// Not a rotated generation: it is the active log under the wrong name,
/// it grows, and nothing may trim, truncate or rotate on top of it —
/// unlinking it unlinks the device's only writable target. Held in the
/// rotation task's own memory and given **no** on-disk representation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingRestore {
    /// The generation name the live inode is currently under.
    name: String,
    /// That name's full path.
    path: PathBuf,
    /// The identity the retry decides by.
    identity: (u64, u64),
}

// ---------------------------------------------------------------------
// The rotation
// ---------------------------------------------------------------------

/// Everything about one device that does not change between passes.
///
/// Split from the state a run accumulates so a pass's blocking phases
/// can be handed an owned copy and run off the reactor, while the
/// mutable half travels with them and comes back.
#[derive(Clone)]
pub(crate) struct DeviceLayout {
    /// `<audit_store_dir>/openbao`, the bind-mount source backing the
    /// container's `/openbao/audit`.
    dir: PathBuf,
    active_path: PathBuf,
    staging_path: PathBuf,
    marker_path: PathBuf,
    /// `S` — the size bound on the active log.
    max_file_bytes: u64,
    /// `N` — the retained generation count.
    max_retained_files: u32,
    /// How the pass addresses and signals this install's container.
    docker: Arc<dyn DockerControl>,
    #[cfg(test)]
    faults: Arc<tests::FaultInjection>,
}

/// What a run of passes accumulates, and nothing else.
///
/// Independent flags rather than a state machine, for the reason
/// [`PassOutcome`] gives: they are separate debts that coexist.
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone)]
struct PassState {
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
    /// Whether this process has already said it took the fallback. A
    /// rotation every 60 seconds must not turn a degraded mechanism
    /// into a log flood, so the `info` fires once and never again.
    reported_fallback: bool,
    /// The live audit inode under a generation name, if a rename-back
    /// has not succeeded. Authoritative while the daemon runs, and
    /// never reconstructed from the marker.
    pending_restore: Option<PendingRestore>,
    /// Whether a marker's removal, or that removal's directory flush,
    /// failed and is still owed. No rotation is attempted while one is
    /// outstanding.
    marker_cleanup_pending: bool,
}

/// The periodic rotation of one `OpenBao` file audit device, and the
/// state a run of passes accumulates.
///
/// Not `Clone` and not shared: exactly one task owns it, so the listing,
/// the publish and the trim never race another pass over the same
/// directory.
pub(crate) struct OpenBaoAuditRotation {
    layout: DeviceLayout,
    state: PassState,
    #[cfg(test)]
    passes: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

/// Where a pass's first blocking phase left off.
enum PassPhase {
    /// The pass finished without ever signalling.
    Done(Box<PassOutcome>),
    /// The rename and the signal are behind it; the bounded wait for
    /// the reopen comes next.
    AwaitReopen(Box<SignalContext>),
}

/// What the first blocking phase hands the wait and the second phase.
#[derive(Debug, Clone)]
struct SignalContext {
    /// The generation the active log was renamed to.
    generation: PathBuf,
    /// That generation's name.
    generation_name: String,
    /// The identity the active log carried before the rename, which the
    /// rename carried into the generation. The predicate's other half.
    identity: (u64, u64),
    /// What `docker kill` said, if it failed. Recorded rather than
    /// acted on: a non-zero exit is not proof the signal never arrived.
    signal_error: Option<String>,
}

/// What the bounded wait after the signal saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReopenWait {
    /// The active path is back on a new inode.
    Reopened,
    /// The active path carries the generation's own identity.
    Generation,
    /// The deadline expired with no reopen.
    Expired,
}

/// How the recovery left the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Recovery {
    /// The active path is present on an inode that is not the
    /// generation's, whatever the confirmation reported. The pass in
    /// fact succeeded.
    Reopened,
    /// The generation was renamed back and the directory flushed: the
    /// exact pre-rotation state.
    Restored,
    /// The active path carries the generation's own identity.
    Anomaly,
    /// The rename-back landed but its directory flush did not.
    RestoreFlushFailed(String),
    /// The rename-back did not land. The live audit inode is under a
    /// generation name.
    Failed(String),
}

impl OpenBaoAuditRotation {
    /// Creates the rotation for the device directory `dir`, under the
    /// bounds `S` and `N`, addressing and signalling through the
    /// `docker` CLI.
    pub(crate) fn new(dir: PathBuf, max_file_bytes: u64, max_retained_files: u32) -> Self {
        Self::with_control(dir, max_file_bytes, max_retained_files, Arc::new(DockerCli))
    }

    /// Creates the rotation against a stated [`DockerControl`].
    pub(crate) fn with_control(
        dir: PathBuf,
        max_file_bytes: u64,
        max_retained_files: u32,
        docker: Arc<dyn DockerControl>,
    ) -> Self {
        let active_path = dir.join(ACTIVE_FILE_NAME);
        let staging_path = dir.join(STAGING_FILE_NAME);
        let marker_path = dir.join(MARKER_FILE_NAME);
        Self {
            layout: DeviceLayout {
                dir,
                active_path,
                staging_path,
                marker_path,
                max_file_bytes,
                max_retained_files,
                docker,
                #[cfg(test)]
                faults: Arc::new(tests::FaultInjection::default()),
            },
            state: PassState {
                consecutive_failures: 0,
                // Assumed, not observed: this process cannot know
                // whether the previous one's last trim was ever
                // flushed, and one `fsync` on the first pass is cheaper
                // than either wrong answer.
                trim_flush_pending: true,
                reported_absent_dir: false,
                reported_absent_log: false,
                reported_fallback: false,
                pending_restore: None,
                marker_cleanup_pending: false,
            },
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
    ///
    /// Asynchronous for exactly one reason: the wait for `OpenBao` to
    /// recreate the active log after the signal. A reopen is not
    /// synchronous with the signal, so a check made immediately after
    /// it reads a working reopen as a failure — and a wait that blocked
    /// would park a runtime thread for up to five seconds a minute. The
    /// filesystem work either side of that wait is blocking and runs
    /// off the reactor, which is why it travels as an owned
    /// [`DeviceLayout`] and [`PassState`] rather than borrowing `self`.
    pub(crate) async fn run_pass(&mut self, now: OffsetDateTime) -> PassOutcome {
        #[cfg(test)]
        self.passes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let layout = self.layout.clone();
        let state = self.state.clone();
        let began = blocking(move || {
            let mut state = state;
            let phase = layout.begin(&mut state, now);
            (state, phase)
        })
        .await;
        let (state, phase) = match began {
            Ok(began) => began,
            Err(err) => return self.abandoned(&err),
        };
        self.state = state;

        let context = match phase {
            PassPhase::Done(outcome) => return *outcome,
            PassPhase::AwaitReopen(context) => *context,
        };

        let wait = await_reopen(&self.layout.active_path, context.identity).await;

        let layout = self.layout.clone();
        let state = self.state.clone();
        let finished = blocking(move || {
            let mut state = state;
            let outcome = layout.finish(&mut state, &context, wait, now);
            (state, outcome)
        })
        .await;
        match finished {
            Ok((state, outcome)) => {
                self.state = state;
                outcome
            }
            Err(err) => self.abandoned(&err),
        }
    }

    /// Reports a blocking phase that did not return, and answers with a
    /// failed pass rather than leaving the caller without one.
    ///
    /// The state is left exactly as the previous pass left it, so the
    /// next tick starts from something the filesystem can still be
    /// reconciled against.
    fn abandoned(&mut self, err: &tokio::task::JoinError) -> PassOutcome {
        error!(
            directory = %self.layout.dir.display(),
            error = %err,
            "an OpenBao audit device rotation phase did not return"
        );
        self.state.consecutive_failures = self.state.consecutive_failures.saturating_add(1);
        PassOutcome {
            evaluated: true,
            rotation: RotationOutcome::Failed,
            form: RotationForm::None,
            retained_unmet: true,
            consecutive_failures: self.state.consecutive_failures,
            trim_flush_pending: self.state.trim_flush_pending,
            restore_pending: self.state.pending_restore.is_some(),
            marker_cleanup_pending: self.state.marker_cleanup_pending,
            active_bytes: 0,
            retained_bytes: 0,
            retained_files: 0,
        }
    }
}

/// Runs `body` on a blocking thread with the caller's tracing
/// subscriber still in force.
///
/// A `spawn_blocking` thread does not inherit a thread-local
/// subscriber, and every event a pass emits — every `warn`, and the
/// escalation `error` — is emitted from inside one of these. In
/// production the subscriber is the process-wide one and the
/// propagation costs a `Dispatch` clone; in the tests it is not, and
/// the propagation is what lets a test read what a pass logged.
async fn blocking<T: Send + 'static>(
    body: impl FnOnce() -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    let dispatch = tracing::dispatcher::get_default(tracing::Dispatch::clone);
    tokio::task::spawn_blocking(move || tracing::dispatcher::with_default(&dispatch, body)).await
}

/// Waits for `OpenBao` to recreate the active log, bounded by
/// [`REOPEN_DEADLINE`].
///
/// The first look happens one [`REOPEN_POLL_INTERVAL`] *after* the
/// signal rather than immediately: a reopen is not synchronous with the
/// signal, and a check made at once reads a working reopen as a failure
/// and drives the lossy fallback for nothing. The deadline is short
/// beside [`ROTATION_INTERVAL`], so a pass that has to fall back still
/// completes on its own tick.
///
/// `tokio::time`-based throughout, so it neither blocks the runtime nor
/// costs a test five wall-clock seconds.
async fn await_reopen(active_path: &Path, generation: (u64, u64)) -> ReopenWait {
    let started = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(REOPEN_POLL_INTERVAL).await;
        match look_at_active_async(active_path, generation).await {
            ActiveLook::Reopened => return ReopenWait::Reopened,
            ActiveLook::Generation => return ReopenWait::Generation,
            ActiveLook::Absent | ActiveLook::Foreign => {}
        }
        if started.elapsed() >= REOPEN_DEADLINE {
            return ReopenWait::Expired;
        }
    }
}

/// The predicate, taken through `tokio::fs` so the wait stays off the
/// reactor's critical path.
async fn look_at_active_async(active_path: &Path, generation: (u64, u64)) -> ActiveLook {
    match tokio::fs::symlink_metadata(active_path).await {
        Ok(meta) if !meta.is_file() => ActiveLook::Foreign,
        Ok(meta) if file_identity(&meta) == generation => ActiveLook::Generation,
        Ok(_) => ActiveLook::Reopened,
        Err(err) if err.kind() == io::ErrorKind::NotFound => ActiveLook::Absent,
        Err(_) => ActiveLook::Foreign,
    }
}

/// Where [`DeviceLayout::marker_branch`] left a pass that started with
/// the active path absent.
enum MarkerBranch {
    /// The path is there after all and the stale marker is gone: carry
    /// on with an ordinary pass.
    Resolved,
    /// The pass is finished.
    Done(Box<PassOutcome>),
}

impl PassState {
    /// Updates the consecutive-failure counter and says what happened.
    ///
    /// Escalation is on the count and nothing else: this reports the
    /// task's own health, never the filesystem's, so it stats no free
    /// space and compares nothing to the store's reserve.
    fn record(
        &mut self,
        directory: &Path,
        budget: u64,
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
            directory = %directory.display(),
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
                directory = %directory.display(),
                unmet = unmet.label(),
                consecutive_failures = self.consecutive_failures,
                active_log_bytes = active_bytes,
                retained_set_bytes = retained_bytes,
                retained_budget_bytes = budget,
                "OpenBao audit device rotation has left an obligation unmet on every one of the \
                 last {} passes; the device's footprint is no longer inside its expected envelope",
                self.consecutive_failures
            );
        }
    }
}

impl DeviceLayout {
    // -----------------------------------------------------------------
    // The two blocking phases
    // -----------------------------------------------------------------

    /// Everything a pass does before it waits for the reopen.
    ///
    /// The order is fixed and each step earns its place: an outstanding
    /// marker cleanup first, because a marker outliving its rotation can
    /// authorise the wrong restore; then a pending restore, because
    /// there is no safe active path to rotate or truncate while one is
    /// outstanding; then the stale-marker cleanup or the
    /// marker-authorised branch, depending on whether the active path is
    /// there; and only then the rotation itself.
    fn begin(&self, state: &mut PassState, now: OffsetDateTime) -> PassPhase {
        match self.inspect_dir(state) {
            // Nothing on this host backs the device, so there is
            // neither a rotation to owe nor a set to evaluate. Said
            // once rather than once a minute: a message every interval
            // over a non-fault is how a real one gets missed.
            DeviceDirectory::Absent => {
                state.consecutive_failures = 0;
                return PassPhase::Done(Box::new(PassOutcome {
                    evaluated: false,
                    rotation: RotationOutcome::NotRequired,
                    form: RotationForm::None,
                    retained_unmet: false,
                    consecutive_failures: 0,
                    trim_flush_pending: false,
                    restore_pending: state.pending_restore.is_some(),
                    marker_cleanup_pending: state.marker_cleanup_pending,
                    active_bytes: 0,
                    retained_bytes: 0,
                    retained_files: 0,
                }));
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
            // failed listing does: with the directory unusable neither
            // the active log's size nor the retained set's total can be
            // read, and reporting either bound as met would report it
            // holding on no evidence.
            DeviceDirectory::Unusable => {
                state.record(&self.dir, self.budget(), true, true, 0, 0);
                return PassPhase::Done(Box::new(PassOutcome {
                    evaluated: true,
                    rotation: RotationOutcome::Failed,
                    form: RotationForm::None,
                    retained_unmet: true,
                    consecutive_failures: state.consecutive_failures,
                    trim_flush_pending: state.trim_flush_pending,
                    restore_pending: state.pending_restore.is_some(),
                    marker_cleanup_pending: state.marker_cleanup_pending,
                    active_bytes: 0,
                    retained_bytes: 0,
                    retained_files: 0,
                }));
            }
            DeviceDirectory::Usable => {}
        }

        // A removal owed from an earlier pass is retried before
        // anything else, and nothing rotates while one is outstanding:
        // a marker that outlives its rotation can authorise a restore
        // of a file that is no longer the live audit inode.
        if state.marker_cleanup_pending && !self.clear_marker(state) {
            return PassPhase::Done(Box::new(self.conclude(
                state,
                RotationOutcome::Failed,
                RotationForm::None,
                true,
            )));
        }

        // A tick taken while a restore is pending does exactly two
        // things: it retries the rename-back, and it evaluates the
        // bound with the pending file excluded.
        if let Some(pending) = state.pending_restore.clone() {
            return PassPhase::Done(Box::new(self.retry_restore(state, &pending)));
        }

        if self.active_present() {
            // Any marker still here belongs to an earlier pass, whatever
            // identity it records: rotations are serialized and a pass
            // writes its own only after this point. A completed fallback
            // and a successful rename-back both leave `audit.log` on
            // exactly the inode the marker recorded, so an identity test
            // would read those markers as live and keep them for ever.
            if !self.clear_marker(state) {
                return PassPhase::Done(Box::new(self.conclude(
                    state,
                    RotationOutcome::Failed,
                    RotationForm::None,
                    true,
                )));
            }
        } else {
            match self.marker_branch(state) {
                MarkerBranch::Resolved => {}
                MarkerBranch::Done(outcome) => return PassPhase::Done(outcome),
            }
        }

        self.rotate_if_required(state, now)
    }

    /// Everything a pass does once the wait has answered.
    fn finish(
        &self,
        state: &mut PassState,
        context: &SignalContext,
        wait: ReopenWait,
        now: OffsetDateTime,
    ) -> PassOutcome {
        match wait {
            ReopenWait::Reopened => {
                debug!(
                    generation = %context.generation.display(),
                    "rotated the OpenBao audit device by reopen-on-signal; no record was copied \
                     or truncated"
                );
                let cleared = self.clear_marker(state);
                let rotation = if cleared {
                    RotationOutcome::Completed
                } else {
                    RotationOutcome::Failed
                };
                self.conclude(state, rotation, RotationForm::Signal, true)
            }
            ReopenWait::Generation => self.anomaly(state, context),
            ReopenWait::Expired => {
                debug!(
                    generation = %context.generation.display(),
                    path = %self.active_path.display(),
                    signal_error = context.signal_error.as_deref().unwrap_or("none"),
                    deadline_secs = REOPEN_DEADLINE.as_secs(),
                    "the OpenBao audit device did not reopen inside the deadline; recovering the \
                     active path before deciding what this pass does next"
                );
                self.recover_then(
                    state,
                    context,
                    now,
                    "the OpenBao audit device did not reopen inside the deadline",
                )
            }
        }
    }

    // -----------------------------------------------------------------
    // The signal form
    // -----------------------------------------------------------------

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
    fn rotate_if_required(&self, state: &mut PassState, now: OffsetDateTime) -> PassPhase {
        let meta = match std::fs::symlink_metadata(&self.active_path) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // A configuration can enable the endpoint on a host
                // where `bootroot init` has not since provisioned the
                // store. That is a no-op, not a failure.
                if !state.reported_absent_log {
                    state.reported_absent_log = true;
                    debug!(
                        path = %self.active_path.display(),
                        "the OpenBao audit device has no active log; nothing to rotate"
                    );
                }
                return PassPhase::Done(Box::new(self.conclude(
                    state,
                    RotationOutcome::NotRequired,
                    RotationForm::None,
                    true,
                )));
            }
            Err(err) => {
                warn!(
                    path = %self.active_path.display(),
                    error = %err,
                    "could not measure the OpenBao audit device's active log"
                );
                return PassPhase::Done(Box::new(self.conclude(
                    state,
                    RotationOutcome::Failed,
                    RotationForm::None,
                    true,
                )));
            }
        };
        if !meta.is_file() {
            warn!(
                path = %self.active_path.display(),
                file_type = ?meta.file_type(),
                "the OpenBao audit device's active log is not a regular file; refusing to rotate \
                 it"
            );
            return PassPhase::Done(Box::new(self.conclude(
                state,
                RotationOutcome::Failed,
                RotationForm::None,
                true,
            )));
        }
        if meta.len() < self.max_file_bytes {
            return PassPhase::Done(Box::new(self.conclude(
                state,
                RotationOutcome::NotRequired,
                RotationForm::None,
                true,
            )));
        }
        self.attempt_signal_form(state, now)
    }

    /// Clears the way, records the intent, renames and signals.
    ///
    /// The container is resolved **before** anything moves, because a
    /// failure to address it then costs nothing: nothing has been
    /// renamed, so there is nothing to rename back and the pass goes
    /// straight to copy-and-truncate on the same tick. The
    /// rotation-intent marker is written next and the rename only after
    /// it, so no crash can leave the rename-succeeded, marker-absent
    /// state the recovery cannot recognise.
    // One ordered sequence — name, container, identity, marker,
    // rename, flush, signal — whose steps are only meaningful in that
    // order and each of whose failures answers differently. Splitting
    // it would hide the ordering behind call sites.
    #[allow(clippy::too_many_lines)]
    fn attempt_signal_form(&self, state: &mut PassState, now: OffsetDateTime) -> PassPhase {
        let (generation, generation_name) = match self.published_path(now, None) {
            Ok(Some(target)) => target,
            Ok(None) => {
                warn!(
                    directory = %self.dir.display(),
                    "every collision sequence under the OpenBao audit generation stamp is taken; \
                     skipping this rotation rather than emitting an out-of-order name"
                );
                return PassPhase::Done(Box::new(self.conclude(
                    state,
                    RotationOutcome::Skipped,
                    RotationForm::None,
                    true,
                )));
            }
            Err(err) => {
                warn!(
                    directory = %self.dir.display(),
                    error = %err,
                    "could not derive the next OpenBao audit generation name"
                );
                return PassPhase::Done(Box::new(self.conclude(
                    state,
                    RotationOutcome::Failed,
                    RotationForm::None,
                    true,
                )));
            }
        };

        let container = match self.resolve_container() {
            Ok(container) => container,
            Err(failure) => {
                // `debug`, not `warn`: the fallback below announces the
                // degradation once per process, and a pass every 60
                // seconds must not turn a deployment whose container
                // this daemon cannot address into a log flood.
                debug!(
                    directory = %self.dir.display(),
                    reason = %failure.label(),
                    "could not address this install's OpenBao container; nothing has moved, so \
                     this pass rotates by copy-and-truncate instead"
                );
                return PassPhase::Done(Box::new(self.fall_back(state, now, &failure.label())));
            }
        };

        let identity = match self.active_identity() {
            Ok(identity) => identity,
            Err(err) => {
                warn!(
                    path = %self.active_path.display(),
                    error = %err,
                    "could not establish the OpenBao audit log's identity before rotating it"
                );
                return PassPhase::Done(Box::new(self.conclude(
                    state,
                    RotationOutcome::Failed,
                    RotationForm::None,
                    true,
                )));
            }
        };

        if let Err(err) = self.write_marker(identity, &generation_name) {
            warn!(
                marker = %self.marker_path.display(),
                error = %format!("{err:#}"),
                "could not record the OpenBao audit rotation's intent; renaming nothing and \
                 rotating by copy-and-truncate instead"
            );
            return PassPhase::Done(Box::new(self.fall_back(
                state,
                now,
                "the rotation-intent marker could not be written",
            )));
        }

        if let Err(err) = self.rename_aside(&generation) {
            warn!(
                path = %self.active_path.display(),
                generation = %generation.display(),
                error = %err,
                "could not rename the OpenBao audit log aside"
            );
            // Nothing moved, so this pass's marker is this pass's to
            // remove before it does anything else.
            if !self.clear_marker(state) {
                return PassPhase::Done(Box::new(self.conclude(
                    state,
                    RotationOutcome::Failed,
                    RotationForm::None,
                    true,
                )));
            }
            return PassPhase::Done(Box::new(self.fall_back(
                state,
                now,
                "the active log could not be renamed aside",
            )));
        }

        let context = SignalContext {
            generation,
            generation_name,
            identity,
            signal_error: None,
        };

        // A crash that loses the rename alone is benign; the hazard is
        // the pair. Once OpenBao has created a *new* `audit.log`, an
        // unflushed rename is a directory that may come back holding
        // the new empty file under the name and the old inode with
        // every rotated record and no entry pointing at it.
        if let Err(err) = self.sync_rename_dir() {
            warn!(
                generation = %context.generation.display(),
                error = %format!("{err:#}"),
                "could not flush the directory after renaming the OpenBao audit log aside; \
                 refusing to signal against an unflushed rename"
            );
            return PassPhase::Done(Box::new(self.recover_then(
                state,
                &context,
                now,
                "the rename could not be made durable, so the container was never signalled",
            )));
        }

        let signal_error = match self.docker.signal_hup(&container) {
            Ok(()) => None,
            Err(err) => {
                let message = format!("{err:#}");
                // Recorded, not acted on: a non-zero exit says the
                // command failed, not that the signal never arrived,
                // and a delivered signal can still be acted on after
                // the deadline. The filesystem decides, and where it
                // decides against the reopen the fallback's own
                // once-per-process `info` carries this reason.
                debug!(
                    container = container,
                    error = message,
                    "could not confirm that SIGHUP reached the OpenBao container; deciding from \
                     the filesystem instead"
                );
                Some(message)
            }
        };

        PassPhase::AwaitReopen(Box::new(SignalContext {
            signal_error,
            ..context
        }))
    }

    // -----------------------------------------------------------------
    // Recovery
    // -----------------------------------------------------------------

    /// Restores the active path, then decides what the rest of the tick
    /// does.
    ///
    /// Four of the five outcomes do **not** fall back, and each of them
    /// means the filesystem is not in the state copy-and-truncate
    /// assumes: a truncate issued into it can destroy records rather
    /// than rotate them.
    fn recover_then(
        &self,
        state: &mut PassState,
        context: &SignalContext,
        now: OffsetDateTime,
        reason: &str,
    ) -> PassOutcome {
        match self.recover(context) {
            Recovery::Reopened => {
                debug!(
                    generation = %context.generation.display(),
                    "the OpenBao audit device had reopened after all; the rotation succeeded and \
                     nothing was copied or truncated"
                );
                let cleared = self.clear_marker(state);
                let rotation = if cleared {
                    RotationOutcome::Completed
                } else {
                    RotationOutcome::Failed
                };
                self.conclude(state, rotation, RotationForm::Signal, true)
            }
            Recovery::Restored => self.fall_back(state, now, reason),
            Recovery::Anomaly => self.anomaly(state, context),
            Recovery::RestoreFlushFailed(err) => {
                // The live filesystem is back at the pre-rotation state,
                // so nothing is lost; the entry is merely not durable
                // yet. Falling back on top of that would truncate
                // against a directory a crash can still un-rename.
                error!(
                    path = %self.active_path.display(),
                    generation = %context.generation.display(),
                    error = err,
                    "could not flush the directory after restoring the OpenBao audit log; the \
                     active log is back at its path but the entry is not durable, and this pass \
                     runs no fallback"
                );
                self.conclude(state, RotationOutcome::Failed, RotationForm::None, true)
            }
            Recovery::Failed(err) => {
                error!(
                    live_audit_log = %context.generation.display(),
                    absent_active_path = %self.active_path.display(),
                    error = err,
                    "the OpenBao audit log could not be renamed back: OpenBao is still appending \
                     through its open descriptor to the file now called {}, while {} does not \
                     exist. That file is the live audit log under a rotated name — do not delete, \
                     compress or move it anywhere but back. The daemon retries the rename on \
                     every later pass and rotates nothing until it succeeds",
                    context.generation_name,
                    self.active_path.display()
                );
                state.pending_restore = Some(PendingRestore {
                    name: context.generation_name.clone(),
                    path: context.generation.clone(),
                    identity: context.identity,
                });
                self.conclude(state, RotationOutcome::Failed, RotationForm::None, true)
            }
        }
    }

    /// Looks at the active path, then renames the generation back.
    ///
    /// The rename-back must not overwrite an `audit.log` `OpenBao` has
    /// already recreated, and a check followed by a rename would race
    /// exactly that. `RENAME_NOREPLACE` refuses atomically instead —
    /// and its `EEXIST` is not by itself the answer, since it says a
    /// name appeared rather than what it resolves to, so the path is
    /// re-statted and decided by the same identity rule as everything
    /// else.
    fn recover(&self, context: &SignalContext) -> Recovery {
        #[cfg(test)]
        if let Some(hook) = self.faults.before_recovery() {
            hook(&self.active_path);
        }
        match self.look_at_active(context.identity) {
            ActiveLook::Reopened => return Recovery::Reopened,
            ActiveLook::Generation => return Recovery::Anomaly,
            ActiveLook::Absent | ActiveLook::Foreign => {}
        }
        #[cfg(test)]
        if let Some(hook) = self.faults.before_restore_rename() {
            hook(&self.active_path);
        }
        match self.restore_rename(&context.generation) {
            Ok(()) => match self.sync_restore_dir() {
                Ok(()) => Recovery::Restored,
                Err(err) => Recovery::RestoreFlushFailed(format!("{err:#}")),
            },
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                match self.look_at_active(context.identity) {
                    ActiveLook::Reopened => Recovery::Reopened,
                    ActiveLook::Generation => Recovery::Anomaly,
                    ActiveLook::Absent | ActiveLook::Foreign => Recovery::Failed(format!(
                        "the rename-back was refused because {} already existed, and a re-stat no \
                         longer finds a file this pass can recognise there",
                        self.active_path.display()
                    )),
                }
            }
            Err(err) => Recovery::Failed(err.to_string()),
        }
    }

    /// The state nothing in this mechanism produces: the active path and
    /// the generation are one inode.
    ///
    /// Above all, **do not fall back**: copy-and-truncate would truncate
    /// the very inode the generation names, emptying the generation it
    /// had just copied. Nothing is trimmed either, since the same file
    /// is both a generation and the device's live target.
    fn anomaly(&self, state: &mut PassState, context: &SignalContext) -> PassOutcome {
        error!(
            path = %self.active_path.display(),
            generation = %context.generation.display(),
            "the OpenBao audit device's active path carries the rotated generation's own \
             identity; nothing in this mechanism produces that state, so this pass renames \
             nothing back, truncates nothing, trims nothing and leaves the next pass to \
             re-evaluate"
        );
        self.conclude(state, RotationOutcome::Failed, RotationForm::None, false)
    }

    /// The tick a pending restore consumes: retry the rename-back,
    /// evaluate the bound with the pending file excluded, and do
    /// nothing else.
    ///
    /// Two outcomes clear it and both resume ordinary work on the same
    /// tick — the rename-back succeeding, and an `EEXIST` whose re-stat
    /// shows an inode that is not the pending file's, which is the
    /// reopened predicate applied later.
    fn retry_restore(&self, state: &mut PassState, pending: &PendingRestore) -> PassOutcome {
        state.pending_restore = Some(pending.clone());
        #[cfg(test)]
        if let Some(hook) = self.faults.before_restore_rename() {
            hook(&self.active_path);
        }
        match self.restore_rename(&pending.path) {
            Ok(()) => match self.sync_restore_dir() {
                Ok(()) => {
                    state.pending_restore = None;
                    info!(
                        path = %self.active_path.display(),
                        generation = %pending.name,
                        "renamed the live OpenBao audit log back to its configured path; ordinary \
                         rotation resumes on the next pass"
                    );
                    let cleared = self.clear_marker(state);
                    let rotation = if cleared {
                        RotationOutcome::NotRequired
                    } else {
                        RotationOutcome::Failed
                    };
                    self.conclude(state, rotation, RotationForm::None, true)
                }
                Err(err) => {
                    // The rename landed, so the live filesystem is back
                    // at the pre-rotation state and nothing is pending
                    // any more; only the entry's durability is owed,
                    // and the next pass's stale-marker cleanup flushes
                    // the directory again.
                    state.pending_restore = None;
                    error!(
                        path = %self.active_path.display(),
                        generation = %pending.name,
                        error = %format!("{err:#}"),
                        "could not flush the directory after renaming the live OpenBao audit log \
                         back; the file is at its path but the entry is not durable"
                    );
                    self.conclude(state, RotationOutcome::Failed, RotationForm::None, true)
                }
            },
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                match self.look_at_active(pending.identity) {
                    ActiveLook::Reopened => {
                        state.pending_restore = None;
                        info!(
                            path = %self.active_path.display(),
                            generation = %pending.name,
                            "a new OpenBao audit log appeared while the restore was outstanding; \
                             the file held back is a genuine rotated generation now and rejoins \
                             the retained set"
                        );
                        let cleared = self.clear_marker(state);
                        let rotation = if cleared {
                            RotationOutcome::NotRequired
                        } else {
                            RotationOutcome::Failed
                        };
                        self.conclude(state, rotation, RotationForm::None, true)
                    }
                    ActiveLook::Generation => {
                        error!(
                            path = %self.active_path.display(),
                            generation = %pending.name,
                            "the OpenBao audit device's active path carries the held-back file's \
                             own identity; the restore stays outstanding and this pass trims \
                             nothing"
                        );
                        self.conclude(state, RotationOutcome::Failed, RotationForm::None, false)
                    }
                    ActiveLook::Absent | ActiveLook::Foreign => {
                        error!(
                            path = %self.active_path.display(),
                            generation = %pending.name,
                            "the rename-back was refused because the active path existed, and a \
                             re-stat no longer finds a file the daemon can recognise there; the \
                             restore stays outstanding"
                        );
                        self.conclude(state, RotationOutcome::Failed, RotationForm::None, true)
                    }
                }
            }
            Err(err) => {
                error!(
                    live_audit_log = %pending.path.display(),
                    absent_active_path = %self.active_path.display(),
                    error = %err,
                    "could not rename the live OpenBao audit log back to its configured path; it \
                     is still the live audit log under a rotated name and nothing may touch it"
                );
                self.conclude(state, RotationOutcome::Failed, RotationForm::None, true)
            }
        }
    }

    /// The branch a pass takes when it starts with the active path
    /// absent and nothing pending in memory.
    ///
    /// It consults the rotation-intent marker and **nothing else** — not
    /// generation order, not mtime. A daemon restart during an
    /// outstanding restore is what usually leaves this state, but it is
    /// not the only cause and the directory alone cannot tell them
    /// apart: an operator or a filesystem fault can unlink the active
    /// pathname while `OpenBao` keeps writing to the now-unlinked inode,
    /// in which case the newest visible generation is an older,
    /// unrelated file and renaming it into place restores a name while
    /// the live stream stays unreachable.
    ///
    /// # The residual, stated rather than hidden
    ///
    /// If a terminal marker removal failed **and** something unlinked
    /// the new `audit.log` before the next tick cleared the marker, the
    /// recognised branch renames a *completed* generation back into
    /// place while `OpenBao` goes on appending to the unlinked newer
    /// inode. That generation's own records survive; the records
    /// written to the unlinked inode do not — no path reaches them, and
    /// when its descriptor is closed, by a later signal rotation or by
    /// the container restarting, the inode is freed and everything
    /// written since the unlink is gone. The restore *masks* the
    /// breakage besides, putting a plausible `audit.log` at the
    /// configured path. So the branch reports at `error` and tells the
    /// operator what to check. It remains the right default — in the
    /// ordinary case it is this daemon's own interrupted rotation,
    /// where restoring reunites path and descriptor and loses nothing.
    fn marker_branch(&self, state: &mut PassState) -> MarkerBranch {
        // It may have appeared between the first look and here, or an
        // operator may have restored it.
        if self.active_present() {
            return if self.clear_marker(state) {
                MarkerBranch::Resolved
            } else {
                MarkerBranch::Done(Box::new(self.conclude(
                    state,
                    RotationOutcome::Failed,
                    RotationForm::None,
                    true,
                )))
            };
        }
        let intent = match self.read_marker() {
            Ok(Some(intent)) => intent,
            Ok(None) if self.nothing_was_ever_rotated() => {
                // No marker and no generation. A marker is written
                // before the rename and removed only once the rotation
                // is over, so its absence says no rotation of this
                // daemon's is in flight; with nothing beside it either,
                // the directory holds no file that could be the live
                // inode and nothing to trim. That is the endpoint
                // enabled on a host `bootroot init` has not since
                // provisioned, or one whose container has not yet
                // created the device — a no-op rather than a failure,
                // said once rather than once a minute.
                if !state.reported_absent_log {
                    state.reported_absent_log = true;
                    debug!(
                        path = %self.active_path.display(),
                        "the OpenBao audit device has no active log; nothing to rotate"
                    );
                }
                return MarkerBranch::Done(Box::new(self.conclude(
                    state,
                    RotationOutcome::NotRequired,
                    RotationForm::None,
                    true,
                )));
            }
            Ok(None) => {
                return MarkerBranch::Done(Box::new(
                    self.unrecognised(state, "there is no rotation-intent marker"),
                ));
            }
            Err(err) => {
                return MarkerBranch::Done(Box::new(self.unrecognised(
                    state,
                    &format!("the rotation-intent marker could not be read: {err}"),
                )));
            }
        };
        // The name is held to the exact generation shape before it is
        // joined, not merely on the way in. A pass writes only names
        // `rotated_file_name` produced, but the marker sits in a
        // directory the container's audit user can write — the same
        // adversary every open in this module is `O_NOFOLLOW`ed
        // against — and `Path::join` reads `..` as a step out of the
        // directory and an absolute name as a replacement for the whole
        // path. Unchecked, a marker that user planted would have root
        // rename a file anywhere on the host to the active path.
        if parse_rotated_name(&intent.generation).is_none() {
            return MarkerBranch::Done(Box::new(self.unrecognised(
                state,
                &format!(
                    "the rotation-intent marker names {:?}, which is not a generation name this \
                     daemon could have written",
                    intent.generation
                ),
            )));
        }
        let generation = self.dir.join(&intent.generation);
        let recognised = match std::fs::symlink_metadata(&generation) {
            Ok(meta) => meta.is_file() && file_identity(&meta) == intent.identity(),
            Err(_) => false,
        };
        if !recognised {
            return MarkerBranch::Done(Box::new(self.unrecognised(
                state,
                &format!(
                    "the rotation-intent marker names {}, which is gone or no longer carries the \
                     identity it recorded",
                    intent.generation
                ),
            )));
        }
        error!(
            generation = %generation.display(),
            path = %self.active_path.display(),
            "a rotation-intent marker authorises renaming {} back to {}. In the ordinary case \
             this is an interrupted rotation of this daemon's own and the restore loses nothing. \
             It is also reachable after a failed marker removal followed by something unlinking \
             the new active log, and there the restore masks the breakage while OpenBao keeps \
             appending to an inode no path reaches — those records are lost the moment its \
             descriptor closes. Check whether new entries are appearing in the restored {}: if \
             they are not, OpenBao is writing where nothing can read",
            intent.generation,
            self.active_path.display(),
            self.active_path.display()
        );
        MarkerBranch::Done(Box::new(self.retry_restore(
            state,
            &PendingRestore {
                name: intent.generation.clone(),
                path: generation,
                identity: intent.identity(),
            },
        )))
    }

    /// Whether the device directory holds nothing a rotation could
    /// have produced.
    ///
    /// A listing that fails answers `false`: the refusal is the safe
    /// answer where nothing can be established.
    fn nothing_was_ever_rotated(&self) -> bool {
        self.rotated_generations(None)
            .is_ok_and(|generations| generations.is_empty())
    }

    /// The state the daemon does not recognise as its own, where
    /// refusing to act is the answer.
    fn unrecognised(&self, state: &mut PassState, reason: &str) -> PassOutcome {
        error!(
            path = %self.active_path.display(),
            reason = reason,
            "the OpenBao audit device's active log is absent and the daemon cannot establish \
             which file the device is writing to; rotating nothing, trimming nothing and moving \
             no generation into place. An operator must reconcile the device directory by hand"
        );
        self.conclude(state, RotationOutcome::Failed, RotationForm::None, false)
    }

    // -----------------------------------------------------------------
    // The fallback
    // -----------------------------------------------------------------

    /// Completes the rotation by copy-and-truncate, on the same tick.
    ///
    /// Announced once per process and not again: a rotation every 60
    /// seconds must not turn a degraded mechanism into a log flood. The
    /// marker's lifetime ends here whether the fallback completed or was
    /// abandoned — both leave no rotation in flight.
    fn fall_back(&self, state: &mut PassState, now: OffsetDateTime, reason: &str) -> PassOutcome {
        if state.reported_fallback {
            debug!(
                reason = reason,
                "rotating the OpenBao audit device by copy-and-truncate again"
            );
        } else {
            state.reported_fallback = true;
            info!(
                reason = reason,
                "the OpenBao audit device's reopen-on-signal rotation could not be confirmed; \
                 this process rotates it by copy-and-truncate instead, which loses the records \
                 written while the copy runs and stages a full copy of the active log beside it"
            );
        }
        let rotation = self.copy_and_truncate(now);
        let form = if rotation == RotationOutcome::Completed {
            RotationForm::Fallback
        } else {
            RotationForm::None
        };
        let rotation = if self.clear_marker(state) {
            rotation
        } else {
            RotationOutcome::Failed
        };
        self.conclude(state, rotation, form, true)
    }

    /// Copies the active log's stable prefix aside and truncates the
    /// original to zero.
    ///
    /// The active path is opened **exactly once**, and every step works
    /// through that one descriptor: the `fstat` that captures the length
    /// and the identity, the read that copies the prefix, and the
    /// `ftruncate` that empties it. Copying one inode and truncating
    /// another is impossible by construction, rather than caught by a
    /// comparison afterwards.
    ///
    /// The ordering is what makes the rest safe:
    ///
    /// 1. capture the length once;
    /// 2. copy exactly those bytes into a staging file in the device's
    ///    own directory, created mode `0600`;
    /// 3. truncate the staging copy to just past its last `\n`;
    /// 4. chown it to the device directory's owner, then `fsync` it;
    /// 5. `link` it into place under its published name, confirm that
    ///    name reached the inode just staged, and unlink the staging
    ///    name;
    /// 6. `fsync` the containing directory;
    /// 7. re-verify the held descriptor against the path and the copied
    ///    length, then truncate; **this is the commit point**;
    /// 8. `fsync` the active log.
    ///
    /// Before step 7 the generation is provisional — the active log
    /// still holds every byte it duplicates — so any failure up to and
    /// including the truncate unlinks the copy and flushes the
    /// directory. Once step 7 succeeds the generation is the *only*
    /// copy of those records, so no later failure unlinks it.
    // One ordered sequence whose steps are only meaningful in order,
    // and each of whose failures says something different about where
    // the pass stopped. Splitting it would hide that ordering behind
    // call sites.
    #[allow(clippy::too_many_lines)]
    fn copy_and_truncate(&self, now: OffsetDateTime) -> RotationOutcome {
        let (target, _name) = match self.published_path(now, None) {
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
        if let Some(hook) = self.faults.before_stage() {
            hook(&self.active_path);
        }

        // Reading through a planted link would copy an arbitrary
        // root-readable file into a generation this pass then chowns to
        // the container's audit user, and reading through a planted
        // FIFO would never return at all. `open_active` refuses both.
        let active = match open_active(OpenOptions::new().read(true).write(true), &self.active_path)
        {
            Ok(active) => active,
            Err(err) => {
                warn!(
                    path = %self.active_path.display(),
                    error = %err,
                    "could not open the OpenBao audit device's active log to rotate it"
                );
                return RotationOutcome::Failed;
            }
        };
        let (identity, len) = match active.metadata() {
            Ok(meta) => (file_identity(&meta), meta.len()),
            Err(err) => {
                warn!(
                    path = %self.active_path.display(),
                    error = %err,
                    "could not measure the OpenBao audit device's active log"
                );
                return RotationOutcome::Failed;
            }
        };

        let staged = match self.stage_prefix(&active, len) {
            Ok(Some(staged)) => {
                // The staging copy already carries its final mode and
                // owner, and has not been published yet. A test looks
                // at it here rather than inferring the ordering.
                #[cfg(test)]
                if let Some(hook) = self.faults.after_stage() {
                    hook(&self.staging_path);
                }
                staged
            }
            Ok(None) => {
                warn!(
                    path = %self.active_path.display(),
                    captured_bytes = len,
                    "the captured OpenBao audit prefix holds no complete record; skipping this \
                     rotation and retrying on the next pass"
                );
                Self::discard_provisional(&self.staging_path);
                return RotationOutcome::Skipped;
            }
            Err(err) => {
                warn!(
                    path = %self.active_path.display(),
                    error = %err,
                    "could not stage the OpenBao audit device's stable prefix"
                );
                Self::discard_provisional(&self.staging_path);
                return RotationOutcome::Failed;
            }
        };

        if let Err(err) = self.publish(&staged, &target) {
            warn!(
                target = %target.display(),
                error = %err,
                "could not publish the staged OpenBao audit generation"
            );
            // Only the staging name: whether the target is this pass's
            // to remove is known inside `publish`, and it has already
            // acted on that.
            Self::discard_provisional(&self.staging_path);
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
            Self::discard_provisional(&target);
            return RotationOutcome::Failed;
        }

        // The one instant where the retained set, the active log at its
        // full captured length and the newly published generation all
        // coexist — the in-pass peak the fallback's operating envelope
        // is stated against. A test suspends the pass here to measure
        // it.
        #[cfg(test)]
        if let Some(hook) = self.faults.before_truncate() {
            hook(&target);
        }

        // The publish settled this when it linked the name, and the
        // directory flush above ran after that — on a directory the
        // container's audit user can write throughout. Re-established
        // here, as the last thing before the commit point.
        if let Err(err) = Self::confirm_published(&staged, &target) {
            warn!(
                target = %target.display(),
                error = %err,
                "the published OpenBao audit generation no longer names the staged copy; the \
                 active log is left intact"
            );
            return RotationOutcome::Failed;
        }

        // A delayed reopen can land while this pass runs. The probe
        // establishes that the image reopens an *absent* path; it says
        // nothing about a path that is present, so a reopen that
        // replaced or shortened the file under this pass is not assumed
        // away. Truncating on a mismatch would destroy records the pass
        // never copied.
        if let Err(err) = self.reverify_before_truncate(&active, identity, len) {
            warn!(
                path = %self.active_path.display(),
                target = %target.display(),
                error = %err,
                "the OpenBao audit device's active log no longer matches what this pass copied; \
                 abandoning the rotation without truncating"
            );
            Self::discard_provisional(&target);
            return RotationOutcome::Failed;
        }

        if let Err(err) = self.truncate_active(&active) {
            warn!(
                path = %self.active_path.display(),
                error = %err,
                "could not empty the OpenBao audit device's active log"
            );
            Self::discard_provisional(&target);
            return RotationOutcome::Failed;
        }

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
            "rotated the OpenBao audit device by copy-and-truncate"
        );
        RotationOutcome::Completed
    }

    /// Re-establishes, immediately before the commit point, that the
    /// held descriptor is still what the configured path names and that
    /// it still holds at least the bytes this pass copied.
    ///
    /// # Errors
    ///
    /// Returns the `stat` error, or [`io::ErrorKind::InvalidInput`]
    /// where the path was re-pointed or the file shortened.
    fn reverify_before_truncate(
        &self,
        active: &File,
        identity: (u64, u64),
        copied: u64,
    ) -> io::Result<()> {
        let named = std::fs::symlink_metadata(&self.active_path)?;
        if file_identity(&named) != identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} no longer names the file this pass copied",
                    self.active_path.display()
                ),
            ));
        }
        let held = active.metadata()?;
        if held.len() < copied {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "{} is {} bytes, shorter than the {copied} this pass copied from it",
                    self.active_path.display(),
                    held.len()
                ),
            ));
        }
        Ok(())
    }

    /// Copies the active log's first `len` bytes into the staging file,
    /// trims the copy to its last record boundary, gives it the device
    /// directory's owner and flushes it.
    ///
    /// Returns the staging descriptor, or `None` where the captured
    /// prefix held no `\n` at all and there is therefore no complete
    /// record to rotate.
    ///
    /// A descriptor rather than a path, because every step after this
    /// one has to know *which file*, not which name: the staging name
    /// lives in a directory the container's audit user can write, so it
    /// can stop leading here at any moment. [`Self::publish`] compares
    /// the published name against this descriptor's inode, and holding
    /// it open for the rest of the pass is what makes the comparison
    /// mean anything — an inode freed in the meantime could have its
    /// number recycled onto the replacement.
    fn stage_prefix(&self, source: &File, len: u64) -> io::Result<Option<File>> {
        let mut source = source;
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
        Ok(Some(staging))
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
    /// just copied.
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
    ///   fact but still before the commit point.
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
                Self::discard_provisional(target);
                return Err(err);
            }
        };
        if file_identity(&published) != staged_id {
            Self::discard_provisional(target);
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
            Self::discard_provisional(target);
            return Err(err);
        }
        Ok(())
    }

    /// Re-establishes that `target` still names the staged copy,
    /// immediately before the commit point.
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

    /// Empties the active log through the descriptor the copy was read
    /// from.
    ///
    /// `ftruncate` on the held descriptor, never a freshly resolved
    /// path: the file this empties is the file whose records the
    /// generation now holds, by construction. Truncating in place is
    /// also what preserves the log's owner and mode — nothing
    /// root-owned ever replaces it.
    ///
    /// # Errors
    ///
    /// Returns the `ftruncate` error, which is a failed pass at the
    /// commit point.
    fn truncate_active(&self, active: &File) -> io::Result<()> {
        #[cfg(test)]
        if self.faults.truncate_fails() {
            return Err(io::Error::other("injected truncate failure"));
        }
        active.set_len(0).map_err(|err| {
            io::Error::other(format!("truncating {}: {err}", self.active_path.display()))
        })
    }

    // -----------------------------------------------------------------
    // Looking at the device
    // -----------------------------------------------------------------

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
    fn inspect_dir(&self, state: &mut PassState) -> DeviceDirectory {
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
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                if !state.reported_absent_dir {
                    state.reported_absent_dir = true;
                    debug!(
                        directory = %self.dir.display(),
                        "the OpenBao audit device directory is absent; nothing to rotate on this \
                         host"
                    );
                }
                DeviceDirectory::Absent
            }
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

    /// Whether anything at all is at the active path.
    ///
    /// Deliberately not "is a regular file": a pass that starts with
    /// *something* there takes the ordinary route, where every open
    /// re-establishes what the descriptor is, while the
    /// marker-authorised branch is only ever for a path that is not
    /// there at all.
    fn active_present(&self) -> bool {
        std::fs::symlink_metadata(&self.active_path).is_ok()
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
            .filter(Metadata::is_file)
            .map(|meta| meta.len())
    }

    /// Returns the active log's identity, established on a descriptor
    /// rather than on the name it was reached through.
    ///
    /// # Errors
    ///
    /// Returns the `open` or `fstat` error, or
    /// [`io::ErrorKind::InvalidInput`] where the path does not lead to
    /// the regular file `OpenBao` writes.
    fn active_identity(&self) -> io::Result<(u64, u64)> {
        let file = open_active(OpenOptions::new().read(true), &self.active_path)?;
        Ok(file_identity(&file.metadata()?))
    }

    /// The predicate, against a generation's identity.
    fn look_at_active(&self, generation: (u64, u64)) -> ActiveLook {
        match std::fs::symlink_metadata(&self.active_path) {
            Ok(meta) if !meta.is_file() => ActiveLook::Foreign,
            Ok(meta) if file_identity(&meta) == generation => ActiveLook::Generation,
            Ok(_) => ActiveLook::Reopened,
            Err(err) if err.kind() == io::ErrorKind::NotFound => ActiveLook::Absent,
            Err(_) => ActiveLook::Foreign,
        }
    }

    // -----------------------------------------------------------------
    // Addressing the container
    // -----------------------------------------------------------------

    /// Selects the running container whose mounts carry a `bind` with
    /// destination `/openbao/audit` and source equal to this daemon's
    /// own `<audit_store_dir>/openbao`.
    ///
    /// The device's bind mount is what identifies the container,
    /// because it is what the daemon actually holds. Its configuration
    /// carries `[registrar]`, `[registrar_endpoint]` and an optional
    /// `[openbao]` and nothing else — no compose file, no instance
    /// name, no Docker knowledge — while `audit_store_dir` is
    /// install-discriminating by construction, since two installs
    /// sharing a host have different values for it. Both sides are
    /// canonicalized so a symlinked store still matches.
    ///
    /// Several matches is unaddressable exactly as none is: picking one
    /// would signal an install that is not this one.
    fn resolve_container(&self) -> Result<String, AddressingFailure> {
        let want = std::fs::canonicalize(&self.dir).map_err(|err| {
            AddressingFailure::Device(format!("canonicalizing {}: {err}", self.dir.display()))
        })?;
        let ids = self
            .docker
            .running_containers()
            .map_err(|err| AddressingFailure::Docker(format!("{err:#}")))?;
        let mut matched = Vec::new();
        for id in ids {
            let mounts = self
                .docker
                .container_mounts(&id)
                .map_err(|err| AddressingFailure::Docker(format!("{err:#}")))?;
            if mounts_bind_device(&mounts, &want) {
                matched.push(id);
            }
        }
        match matched.len() {
            0 => Err(AddressingFailure::NoMatch),
            1 => matched.into_iter().next().ok_or(AddressingFailure::NoMatch),
            several => Err(AddressingFailure::Ambiguous(several)),
        }
    }

    // -----------------------------------------------------------------
    // The rotation-intent marker
    // -----------------------------------------------------------------

    /// Records the intent, with the discipline this repository requires
    /// of state another process may read: staged in the destination's
    /// directory, `sync_all`ed, renamed, containing directory flushed.
    ///
    /// # Errors
    ///
    /// Returns the serialisation or publish error. A marker that could
    /// not be written renames nothing, so the pass falls back on the
    /// same tick with nothing to undo.
    fn write_marker(&self, identity: (u64, u64), generation: &str) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.faults.marker_write_fails() {
            anyhow::bail!("injected marker write failure");
        }
        let intent = RotationIntent {
            active_dev: identity.0,
            active_ino: identity.1,
            generation: generation.to_string(),
        };
        let body = serde_json::to_vec(&intent)?;
        fs_util::atomic_write_blocking(
            Destination::bootroot_owned(&self.marker_path),
            &body,
            StagedMode::Policy(GENERATION_FILE_MODE),
        )
    }

    /// Reads the marker, or `None` where there is none.
    ///
    /// # Errors
    ///
    /// Returns the read error, or an [`io::ErrorKind::InvalidData`]
    /// where the marker does not parse. Both take the unrecognised
    /// branch, which refuses to act.
    fn read_marker(&self) -> io::Result<Option<RotationIntent>> {
        match std::fs::read(&self.marker_path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    /// Removes the marker and makes the removal durable, answering
    /// whether the pass may still be called successful.
    ///
    /// A marker outliving its rotation can authorise the wrong restore,
    /// so a failed unlink or a failed post-unlink flush is an `error`,
    /// fails the pass into the consecutive-failure escalation, and is
    /// held as a pending cleanup retried before anything else on every
    /// later tick.
    fn clear_marker(&self, state: &mut PassState) -> bool {
        let existed = match self.unlink_marker() {
            Ok(existed) => existed,
            Err(err) => {
                error!(
                    marker = %self.marker_path.display(),
                    error = %err,
                    "could not remove the OpenBao audit rotation-intent marker; no rotation is \
                     attempted until it is gone, because a marker outliving its rotation can \
                     authorise the wrong restore"
                );
                state.marker_cleanup_pending = true;
                return false;
            }
        };
        if !existed && !state.marker_cleanup_pending {
            return true;
        }
        match self.sync_marker_dir() {
            Ok(()) => {
                state.marker_cleanup_pending = false;
                true
            }
            Err(err) => {
                error!(
                    marker = %self.marker_path.display(),
                    error = %format!("{err:#}"),
                    "could not flush the directory after removing the OpenBao audit \
                     rotation-intent marker; the removal is not durable and no rotation is \
                     attempted until it is"
                );
                state.marker_cleanup_pending = true;
                false
            }
        }
    }

    /// Unlinks the marker, answering whether there was one.
    fn unlink_marker(&self) -> io::Result<bool> {
        // Guarded on the marker being there, so the injection models an
        // unlink of a marker that failed rather than a call that always
        // errors: a pass with no marker to remove must be able to reach
        // the one it is about to write.
        #[cfg(test)]
        if self.faults.marker_unlink_fails() && self.marker_path.exists() {
            return Err(io::Error::other("injected marker unlink failure"));
        }
        match std::fs::remove_file(&self.marker_path) {
            Ok(()) => Ok(true),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(err) => Err(err),
        }
    }

    // -----------------------------------------------------------------
    // Renames and flushes
    // -----------------------------------------------------------------

    /// Renames the active log to its generation name, refusing to
    /// replace anything already there.
    fn rename_aside(&self, target: &Path) -> io::Result<()> {
        #[cfg(test)]
        if self.faults.rename_fails() {
            return Err(io::Error::other("injected rename failure"));
        }
        rename_noreplace(&self.active_path, target)
    }

    /// Renames a generation back to the active path, refusing to
    /// replace an `audit.log` `OpenBao` has already recreated.
    fn restore_rename(&self, from: &Path) -> io::Result<()> {
        #[cfg(test)]
        if let Some(kind) = self.faults.restore_rename_fails() {
            return Err(io::Error::new(kind, "injected rename-back failure"));
        }
        rename_noreplace(from, &self.active_path)
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
    fn sync_dir(&self) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.faults.directory_sync_fails() {
            anyhow::bail!("injected directory flush failure");
        }
        sync_parent_dir(&self.active_path)
    }

    /// Flushes the directory after the rename aside and **before** the
    /// signal.
    fn sync_rename_dir(&self) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.faults.rename_sync_fails() {
            anyhow::bail!("injected rename flush failure");
        }
        sync_parent_dir(&self.active_path)
    }

    /// Flushes the directory after a rename-back, for the mirror of the
    /// reason the rename needed one: until the entry is on disk, a
    /// crash can come back with the generation name still pointing at
    /// the inode the daemon has already decided is the active log
    /// again.
    fn sync_restore_dir(&self) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.faults.restore_sync_fails() {
            anyhow::bail!("injected rename-back flush failure");
        }
        sync_parent_dir(&self.active_path)
    }

    /// Flushes the directory after the marker's removal.
    fn sync_marker_dir(&self) -> anyhow::Result<()> {
        #[cfg(test)]
        if self.faults.marker_flush_fails() {
            anyhow::bail!("injected marker flush failure");
        }
        sync_parent_dir(&self.marker_path)
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
    /// unlinking loses nothing. A removal that itself fails says which
    /// path it left behind, so an operator gets one message naming the
    /// file to remove by hand.
    fn discard_provisional(path: &Path) {
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

    // -----------------------------------------------------------------
    // The retained set
    // -----------------------------------------------------------------

    fn budget(&self) -> u64 {
        retained_budget_bytes(self.max_file_bytes, self.max_retained_files)
    }

    /// Returns the path and the name the next generation is published
    /// under, or `None` where the chosen stamp's sequence namespace is
    /// exhausted.
    ///
    /// The stamp is the **greater** of the stamp for `now` and the
    /// newest existing generation's, and the sequence is one past the
    /// greatest already present under whichever won — never the lowest
    /// unused one. Both rules exist for the trim: it drops oldest-first
    /// by name, so a name that sorted before an existing generation
    /// would have it delete the file it has just written.
    fn published_path(
        &self,
        now: OffsetDateTime,
        exclude: Option<&str>,
    ) -> io::Result<Option<(PathBuf, String)>> {
        let generations = self.rotated_generations(exclude)?;
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
        let name = rotated_file_name(&stamp, next);
        Ok(Some((self.dir.join(&name), name)))
    }

    /// Returns every rotated generation, sorted lexicographically —
    /// which, given the fixed-width stamp and sequence, is oldest first.
    ///
    /// `exclude` names the one file a pending restore holds back: the
    /// live audit inode under a generation name. It is not a rotated
    /// generation, so it is counted neither towards the retained set's
    /// total nor among the trim's candidates.
    ///
    /// Deliberately not bounded by `N + 1`: the set can legitimately be
    /// larger than the bound, which is the lowered-bound case the trim
    /// exists to repair.
    fn rotated_generations(&self, exclude: Option<&str>) -> io::Result<Vec<Generation>> {
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
            if exclude == Some(name) {
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
    /// first pass a new task runs, which cannot know what the task
    /// before it left unflushed.
    fn trim(&self, state: &mut PassState, exclude: Option<&str>) {
        let generations = match self.rotated_generations(exclude) {
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
        let budget = self.budget();
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
        if removed || state.trim_flush_pending {
            match self.sync_trimmed_dir() {
                Ok(()) => state.trim_flush_pending = false,
                Err(err) => {
                    // Not a warning that is then dropped: the listing
                    // the pass is about to take no longer sees the
                    // deleted generations, so an unflushed trim would
                    // otherwise read as the bound met and reset the
                    // failure counter, while a crash could restore the
                    // whole over-budget set. The debt is carried into
                    // the pass's outcome instead, and re-attempted.
                    state.trim_flush_pending = true;
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

    /// Evaluates the retained-set bound, updates the counter and builds
    /// the pass's answer.
    ///
    /// The bound is evaluated on every tick, whether or not a rotation
    /// happened, with exactly two exceptions — both passed as
    /// `evaluate_bound: false`: the same-inode anomaly, and the state a
    /// pass refuses to act in because it cannot establish which file
    /// the device is writing to. In both, a generation name and the
    /// file `OpenBao` is writing to may be one inode.
    fn conclude(
        &self,
        state: &mut PassState,
        rotation: RotationOutcome,
        form: RotationForm,
        evaluate_bound: bool,
    ) -> PassOutcome {
        let excluded = state
            .pending_restore
            .as_ref()
            .map(|pending| pending.name.clone());
        if let Some(name) = excluded.as_deref() {
            info!(
                held_back = name,
                "the OpenBao audit device's retained-set bound is evaluated without the file a \
                 pending restore holds back; it cannot be fully re-established until the restore \
                 succeeds"
            );
        }
        if evaluate_bound {
            self.trim(state, excluded.as_deref());
        }

        let (retained_files, retained_bytes, listing_failed) =
            match self.rotated_generations(excluded.as_deref()) {
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
                        "could not list the retained OpenBao audit generations to check their \
                         bound"
                    );
                    (0, 0, true)
                }
            };
        let budget = self.budget();
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
        // covers do. And a pass that was refused the evaluation
        // altogether has established nothing at all.
        let retained_unmet = !evaluate_bound
            || listing_failed
            || state.trim_flush_pending
            || retained_files > retained_cap
            || retained_bytes > budget;
        let active_bytes = self.active_len().unwrap_or(0);

        state.record(
            &self.dir,
            budget,
            rotation.is_unmet(),
            retained_unmet,
            active_bytes,
            retained_bytes,
        );

        PassOutcome {
            evaluated: true,
            rotation,
            form,
            retained_unmet,
            consecutive_failures: state.consecutive_failures,
            trim_flush_pending: state.trim_flush_pending,
            restore_pending: state.pending_restore.is_some(),
            marker_cleanup_pending: state.marker_cleanup_pending,
            active_bytes,
            retained_bytes,
            retained_files,
        }
    }
}

/// Whether `mounts` — the JSON array `docker inspect` prints for
/// `.Mounts` — carries a `bind` of `want` at the container's audit
/// path.
///
/// Both sides are canonicalized, so a store reached through a symbolic
/// link still matches the container that was given the resolved path,
/// and neither side is compared as text.
fn mounts_bind_device(mounts: &str, want: &Path) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(mounts.trim()) else {
        return false;
    };
    let Some(items) = value.as_array() else {
        return false;
    };
    items.iter().any(|mount| {
        let field = |key: &str| mount.get(key).and_then(serde_json::Value::as_str);
        field("Type") == Some("bind")
            && field("Destination") == Some(OPENBAO_CONTAINER_AUDIT_DIR)
            && field("Source").is_some_and(|source| {
                std::fs::canonicalize(source).is_ok_and(|resolved| resolved == want)
            })
    })
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
                // The branch body runs after its future resolved, so
                // the pass is never cancelled part-way by the shutdown
                // arm: a rotation stops between ticks, never inside
                // one.
                let outcome = rotation.run_pass(OffsetDateTime::now_utc()).await;
                report_pass(&outcome);
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
        restore_pending = outcome.restore_pending,
        marker_cleanup_pending = outcome.marker_cleanup_pending,
        consecutive_failures = outcome.consecutive_failures,
        active_log_bytes = outcome.active_bytes,
        retained_set_bytes = outcome.retained_bytes,
        retained_files = outcome.retained_files,
        "completed an OpenBao audit device rotation pass"
    );
}
