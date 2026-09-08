//! The lock one publication of the registrar's material holds while it
//! replaces the caller's paths.
//!
//! Snapshot, publish and roll back are one transaction over three
//! files, and the rollback can only undo a failure of the run that
//! owns it. It cannot undo a *successful* interleaving: two
//! `bootroot registrar issue` runs against the same paths can publish
//! certificate A, then certificate B and key B, then key A, and both
//! report success while the pair left on disk is certificate B beside
//! key A. Nothing on disk records that, and neither run failed, so
//! neither has anything to put back.
//!
//! The two runs are separate processes — a provisioning tool driving
//! one while an operator drives another — so `crate::ca_bundle_lock`'s
//! process-wide answer does not reach them. This one is `flock(2)` on a
//! lock file in each directory the publication writes into, which is
//! held from before the first snapshot until after the last write or
//! restore. Two runs sharing a destination share that destination's
//! directory, so they share the lock and one waits for the other; the
//! second then snapshots what the first published and publishes over it
//! whole.
//!
//! A publication writes into at most two directories — the certificate
//! and its sibling bundle in one, the key in the other — and takes
//! their locks in sorted order, so two runs that name the same pair of
//! directories in opposite roles cannot each hold the one the other is
//! waiting for.
//!
//! The lock file is a name to lock, never a record: it is empty, it is
//! created `0600`, and it is not removed afterwards, because unlinking
//! it would hand the next two runs a different inode each and serialise
//! neither. `flock` is released by the kernel when the descriptor
//! closes, so a run that is killed mid-publication strands nothing.
//!
//! # What it does not cover
//!
//! The issuance ahead of the publication runs unlocked. It writes only
//! into this run's own staging directory, and holding a lock across an
//! ACME round trip would stall the other run for the length of a
//! network exchange rather than the length of three writes.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The lock file each directory a publication writes into carries.
pub(super) const LOCK_FILE_NAME: &str = ".bootroot-registrar-publish.lock";

/// The mode the lock file is created at.
///
/// It holds nothing, so nothing needs to read it: the descriptor is the
/// lock and the bytes are never written.
const LOCK_FILE_MODE: u32 = 0o600;

/// Exclusive access to every directory one publication writes into,
/// released when it is dropped.
pub(super) struct PublicationLock {
    /// The open lock files. `flock(2)` is released as the descriptor
    /// closes, so holding these open is holding the lock and dropping
    /// them is releasing it; nothing ever reads or writes them.
    _files: Vec<File>,
}

/// Takes the publication lock covering `destinations`, waiting for
/// whichever run holds it.
///
/// The wait is unbounded on purpose. The lock is held across three
/// writes and released by the kernel if the holder dies, so there is no
/// stale lock to time out of — only another run's publication to let
/// finish.
///
/// # Errors
///
/// Returns an error when a destination's directory cannot be created or
/// resolved, when the lock file cannot be opened, or when `flock` fails.
pub(super) async fn hold(destinations: &[&Path]) -> Result<PublicationLock> {
    let dirs: Vec<PathBuf> = destinations.iter().map(|path| parent_of(path)).collect();
    tokio::task::spawn_blocking(move || hold_blocking(&dirs))
        .await
        .context("the publication lock task panicked")?
}

/// The directory a destination is published into.
fn parent_of(path: &Path) -> PathBuf {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    }
}

/// The blocking half of [`hold`]: `flock` waits, so it waits on a
/// blocking thread.
fn hold_blocking(dirs: &[PathBuf]) -> Result<PublicationLock> {
    let mut ordered: Vec<PathBuf> = Vec::with_capacity(dirs.len());
    for dir in dirs {
        // The publication creates these directories itself a moment
        // later; creating them here is what gives the lock a place to
        // live on a first provisioning, and resolving them afterwards
        // is what makes two spellings of one directory one lock.
        std::fs::create_dir_all(dir).with_context(|| {
            format!(
                "creating {} to take the registrar publication lock in",
                dir.display()
            )
        })?;
        ordered.push(std::fs::canonicalize(dir).with_context(|| {
            format!(
                "resolving {} to take the registrar publication lock in",
                dir.display()
            )
        })?);
    }
    // Sorted, so two runs naming one pair of directories in opposite
    // orders still take them in the same order and neither can hold
    // what the other waits for. Deduplicated, because `flock` on two
    // descriptors of one file blocks against itself.
    ordered.sort_unstable();
    ordered.dedup();

    let mut files = Vec::with_capacity(ordered.len());
    for dir in &ordered {
        files.push(lock(&dir.join(LOCK_FILE_NAME))?);
    }
    Ok(PublicationLock { _files: files })
}

/// Opens one lock file and takes its exclusive `flock`.
fn lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(LOCK_FILE_MODE)
        .open(path)
        .with_context(|| format!("opening the registrar publication lock {}", path.display()))?;
    // SAFETY: `file` owns an open descriptor that outlives the call, and
    // `flock` dereferences nothing — it takes that descriptor and an
    // operation constant and reports a status.
    let outcome = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if outcome != 0 {
        return Err(
            anyhow::Error::new(std::io::Error::last_os_error()).context(format!(
                "waiting for the registrar publication lock {}",
                path.display()
            )),
        );
    }
    Ok(file)
}
