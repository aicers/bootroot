//! The lock every writer of the registrar surface's material holds
//! while it replaces a set of destinations.
//!
//! Snapshot, publish and roll back are one transaction over three
//! files, and a rollback can only undo a failure of the run that owns
//! it. It cannot undo a *successful* interleaving: two writers against
//! the same paths can publish certificate A, then certificate B and key
//! B, then key A, and both report success while the pair left on disk
//! is certificate B beside key A. Nothing on disk records that, and
//! neither run failed, so neither has anything to put back.
//!
//! # Who takes it
//!
//! Three writers publish this material, and they are not all in one
//! process:
//!
//! - `bootroot registrar issue`, the provisioning CLI, at the caller's
//!   paths;
//! - the daemon's start-time issuance of the surface pairs
//!   (`crate::registrar_certs`), at the configured paths;
//! - the daemon's renewal of those same pairs
//!   (`crate::registrar_renewal`).
//!
//! The CLI and the daemon are separate processes — a provisioning tool
//! driving one while the other is running — so
//! `crate::ca_bundle_lock`'s process-wide answer does not reach
//! across them, and a lock held by only two of the three leaves the
//! third free to interleave with either. This one is `flock(2)` on a
//! lock file in each directory a publication writes into, held from
//! before the first snapshot until after the last write or restore.
//! Two writers sharing a destination share that destination's
//! directory, so they share the lock and one waits for the other; the
//! second then publishes over the first whole.
//!
//! A publication writes into three destinations and so into at most
//! three directories — the CLI's bundle is the certificate's sibling
//! and leaves it two, the daemon's `[trust] ca_bundle_path` need not
//! sit beside either — and takes their locks in sorted order, so two
//! writers naming the same directories in different roles cannot each
//! hold the one the other is waiting for.
//!
//! The lock file is a name to lock, never a record: it is empty, it is
//! created `0600`, and it is not removed afterwards, because unlinking
//! it would hand the next two runs a different inode each and serialise
//! neither. `flock` is released by the kernel when the descriptor
//! closes, so a run that is killed mid-publication strands nothing.
//!
//! # What it does not cover
//!
//! The issuance ahead of a publication runs unlocked. It writes only
//! into the run's own staging directory or into nothing at all, and
//! holding a lock across an ACME round trip would stall the other
//! writers for the length of a network exchange rather than the length
//! of three writes. Every caller therefore takes the lock *after* it
//! has the material in hand and immediately before the first
//! destination is read back.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The lock file each directory a publication writes into carries.
pub const LOCK_FILE_NAME: &str = ".bootroot-registrar-publish.lock";

/// The mode the lock file is created at.
///
/// It holds nothing, so nothing needs to read it: the descriptor is the
/// lock and the bytes are never written.
const LOCK_FILE_MODE: u32 = 0o600;

/// Exclusive access to every directory one publication writes into,
/// released when it is dropped.
pub struct PublicationLock {
    /// The open lock files. `flock(2)` is released as the descriptor
    /// closes, so holding these open is holding the lock and dropping
    /// them is releasing it; nothing ever reads or writes them.
    _files: Vec<File>,
}

/// Takes the publication lock covering `destinations`, waiting for
/// whichever writer holds it.
///
/// The wait is unbounded on purpose. The lock is held across three
/// writes and released by the kernel if the holder dies, so there is no
/// stale lock to time out of — only another publication to let finish.
///
/// # Errors
///
/// Returns an error when a destination's directory cannot be created or
/// resolved, when the lock file cannot be opened, or when `flock` fails.
pub async fn hold(destinations: &[&Path]) -> Result<PublicationLock> {
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
    // Sorted, so two writers naming one set of directories in opposite
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

/// Attempts the publication lock in `dir` without waiting, and answers
/// whether it was granted.
///
/// Test-only, and the shape every assertion about this lock is made in:
/// `flock(2)` associates a lock with the open file description rather
/// than with the process, so a lock held on another descriptor refuses
/// this one exactly as it refuses another process's. That is what lets
/// a single-process test assert a property about two processes, with no
/// timing in it at all. It is never a gate for production code — the
/// answer is stale the instant it is returned.
#[cfg(test)]
pub(crate) fn is_free(dir: &Path) -> bool {
    let path = dir.join(LOCK_FILE_NAME);
    let Ok(file) = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
    else {
        return false;
    };
    // SAFETY: `file` owns an open descriptor that outlives the call and
    // `flock` dereferences nothing. The lock, if taken, is released as
    // `file` is dropped at the end of this function.
    let outcome = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    outcome == 0
}

/// The directories a set of destinations is published into that no
/// publication is currently holding.
///
/// Test-only, and empty is the assertion: a destination whose directory
/// answers free is one another process could be publishing into right
/// now.
#[cfg(test)]
pub(crate) fn unlocked_directories(destinations: &[&Path]) -> Vec<PathBuf> {
    destinations
        .iter()
        .map(|path| parent_of(path))
        .filter(|dir| is_free(dir))
        .collect()
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    /// The daemon's configured paths and the CLI's caller-supplied ones
    /// are one lock wherever they land in one directory.
    ///
    /// The two are separate processes writing the same registrar client
    /// leaf: the daemon at `[registrar_endpoint] client_cert_path`, the
    /// CLI at whatever a provisioning tool passed. A deployment points
    /// them at the same file, and this is what stops the two
    /// publications from interleaving into a mismatched pair.
    #[tokio::test]
    async fn a_daemon_publication_and_a_cli_publication_share_one_lock() {
        let root = TempDir::new().expect("tempdir");
        let live = root.path().join("live");
        let keys = root.path().join("keys");

        // The daemon's set: the merged bundle and the certificate in one
        // directory, the key in another.
        let daemon = hold(&[
            &live.join("ca-bundle.pem"),
            &live.join("registrar-client.pem"),
            &keys.join("registrar-client-key.pem"),
        ])
        .await
        .expect("the daemon's acquisition");

        assert!(
            !is_free(&live),
            "a CLI issuance must not publish into a directory the daemon is publishing into"
        );
        assert!(
            !is_free(&keys),
            "the key's directory is held for the same span as the certificate's"
        );

        drop(daemon);

        assert!(
            is_free(&live) && is_free(&keys),
            "both directories are released with the publication"
        );
    }

    /// A writer that shares no directory with another waits for
    /// nothing.
    #[tokio::test]
    async fn publications_into_disjoint_directories_do_not_wait_on_each_other() {
        let root = TempDir::new().expect("tempdir");
        let mine = root.path().join("mine");
        let theirs = root.path().join("theirs");

        let _held = hold(&[&mine.join("registrar.pem")])
            .await
            .expect("the acquisition");

        // Granted rather than queued: a second acquisition that had to
        // wait would never return here.
        hold(&[&theirs.join("registrar.pem")])
            .await
            .expect("a disjoint set is a lock of its own");
    }
}
