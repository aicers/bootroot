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
//! neither. The guard unlocks every lock file on drop, so that a copy
//! of a descriptor in a child another thread has forked and not yet
//! `exec`ed cannot keep a lock held, and the kernel still releases the
//! locks of a holder that dies without running `drop`, so a run that is
//! killed mid-publication strands nothing.
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
/// released when it is dropped: the guard unlocks each lock file before
/// closing it.
pub struct PublicationLock {
    /// The open lock files, each holding its `flock(2)`; unlocked on
    /// drop, and released by the kernel if the holder dies first.
    /// Nothing ever reads or writes them.
    files: Vec<File>,
}

impl Drop for PublicationLock {
    fn drop(&mut self) {
        // `flock` belongs to the open file description, which a child
        // forked by another thread shares until its `exec`; closing our
        // descriptors alone would leave the locks held through that
        // copy. Errors are discarded: the descriptors close next, and
        // the kernel releases each lock once no copy remains.
        for file in &self.files {
            let _ = file.unlock();
        }
    }
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

/// Takes the publication lock covering `destinations` as [`hold`] does,
/// but refuses a lock file that is a symlink or anything but a regular
/// file rather than opening it.
///
/// What the generation tree takes. Its root is a directory bootroot
/// creates and owns, and `current` is the only link in it a reader or
/// writer ever follows; a lock file followed out of the tree would let
/// whoever placed the link serialise publications on an inode they
/// control, and a dangling one would have the open create a file
/// wherever it points. The registrar surface keeps [`hold`] unchanged.
///
/// # Errors
///
/// Returns an error as [`hold`] does, and when a lock file is a symlink
/// or is not a regular file.
pub(crate) async fn hold_refusing_links(destinations: &[&Path]) -> Result<PublicationLock> {
    let dirs: Vec<PathBuf> = destinations.iter().map(|path| parent_of(path)).collect();
    tokio::task::spawn_blocking(move || hold_blocking_with(&dirs, LockEntry::RefuseLinks))
        .await
        .context("the publication lock task panicked")?
}

/// How a lock file already in place is treated when it is opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LockEntry {
    /// Opened wherever it resolves to, as the registrar surface always
    /// has.
    Follow,
    /// Refused unless it is a regular file at that very name.
    RefuseLinks,
}

/// The blocking half of [`hold`]: `flock` waits, so it waits on a
/// blocking thread.
fn hold_blocking(dirs: &[PathBuf]) -> Result<PublicationLock> {
    hold_blocking_with(dirs, LockEntry::Follow)
}

/// The blocking half of [`hold`] and [`hold_refusing_links`].
fn hold_blocking_with(dirs: &[PathBuf], entry: LockEntry) -> Result<PublicationLock> {
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
        files.push(lock(&dir.join(LOCK_FILE_NAME), entry)?);
    }
    Ok(PublicationLock { files })
}

/// Opens one lock file and takes its exclusive `flock`.
///
/// Under [`LockEntry::RefuseLinks`] the open carries `O_NOFOLLOW`, so a
/// symlink at the lock's name — dangling or not — fails it rather than
/// being opened or created through, and `O_NONBLOCK`, so a FIFO planted
/// there cannot stall it before the descriptor's own type is checked.
/// Neither flag changes how `flock` waits.
fn lock(path: &Path, entry: LockEntry) -> Result<File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(LOCK_FILE_MODE);
    if entry == LockEntry::RefuseLinks {
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(err) if entry == LockEntry::RefuseLinks && err.raw_os_error() == Some(libc::ELOOP) => {
            return Err(link_refusal(path));
        }
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!(
                "opening the registrar publication lock {}",
                path.display()
            )));
        }
    };
    if entry == LockEntry::RefuseLinks {
        let meta = file.metadata().with_context(|| {
            format!(
                "inspecting the registrar publication lock {}",
                path.display()
            )
        })?;
        if !meta.file_type().is_file() {
            return Err(link_refusal(path));
        }
    }
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

/// The error for a lock file [`LockEntry::RefuseLinks`] will not open.
fn link_refusal(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "the publication lock {} must be a regular file, but a symlink or another kind of file \
         is in its place; it was not followed and nothing was published. Remove it, and the \
         next publication recreates it",
        path.display()
    )
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
    // `flock` dereferences nothing. The lock, if taken, is given back
    // with `unlock` before this function returns.
    let outcome = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    let free = outcome == 0;
    if free {
        // Not left to the descriptor closing: a child another test
        // thread forks in between would carry the probe's lock into the
        // next step of the test.
        let _ = file.unlock();
    }
    free
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

    /// A copy of each of the guard's descriptors — what a child forked
    /// by another thread holds until its `exec` — does not keep a lock
    /// held once the guard is dropped.
    #[tokio::test]
    async fn a_descriptor_copy_does_not_keep_a_dropped_lock_held() {
        let root = TempDir::new().expect("tempdir");
        let certs = root.path().join("certs");
        let keys = root.path().join("keys");
        let held = hold(&[
            &certs.join("registrar.pem"),
            &keys.join("registrar-key.pem"),
        ])
        .await
        .expect("the acquisition");
        assert_eq!(held.files.len(), 2, "one lock file per directory");
        let copies: Vec<File> = held
            .files
            .iter()
            .map(|file| file.try_clone().expect("duplicate the descriptor"))
            .collect();

        drop(held);

        assert!(
            is_free(&certs) && is_free(&keys),
            "dropping the guard releases both locks despite the copies"
        );
        drop(copies);
    }

    /// The generation tree's lock refuses a symlink at the lock's name,
    /// whether it points at an existing file or at nothing, and neither
    /// opens, locks nor creates what it points at.
    #[tokio::test]
    async fn a_symlinked_lock_file_is_refused_and_not_followed() {
        let root = TempDir::new().expect("tempdir");
        let tree = root.path().join("tree");
        std::fs::create_dir(&tree).expect("the tree");
        let outside = root.path().join("outside");
        std::fs::create_dir(&outside).expect("the link's directory");
        let existing = outside.join("existing");
        std::fs::write(&existing, b"someone else's file").expect("the link's target");
        let dangling = outside.join("dangling");
        let lock_path = tree.join(LOCK_FILE_NAME);

        for target in [&existing, &dangling] {
            std::os::unix::fs::symlink(target, &lock_path).expect("plant the link");

            let Err(err) = hold_refusing_links(&[&tree.join("current")]).await else {
                panic!("a symlinked lock file must be refused");
            };

            let message = format!("{err:#}");
            assert!(
                message.contains(&lock_path.display().to_string()),
                "{message}"
            );
            assert!(message.contains("Remove it"), "{message}");
            assert!(
                std::fs::symlink_metadata(&lock_path)
                    .expect("the link is still there")
                    .file_type()
                    .is_symlink()
            );
            std::fs::remove_file(&lock_path).expect("remove the link");
        }

        assert_eq!(
            std::fs::read(&existing).expect("the target is untouched"),
            b"someone else's file"
        );
        assert!(
            std::fs::symlink_metadata(&dangling).is_err(),
            "nothing was created where the dangling link pointed"
        );
    }

    /// Anything but a regular file at the lock's name is refused too.
    #[tokio::test]
    async fn a_directory_in_place_of_the_lock_file_is_refused() {
        let root = TempDir::new().expect("tempdir");
        std::fs::create_dir(root.path().join(LOCK_FILE_NAME)).expect("plant the directory");

        assert!(
            hold_refusing_links(&[&root.path().join("current")])
                .await
                .is_err(),
            "a directory is not a lock file"
        );
    }

    /// A regular lock file, or none yet, is taken as [`hold`] takes it.
    #[tokio::test]
    async fn a_regular_lock_file_is_taken_without_following() {
        let root = TempDir::new().expect("tempdir");
        let current = root.path().join("current");

        let held = hold_refusing_links(&[&current])
            .await
            .expect("the first acquisition creates the lock file");
        assert!(!is_free(root.path()), "the lock is held");
        drop(held);

        let held = hold_refusing_links(&[&current])
            .await
            .expect("the lock file left behind is taken again");
        assert!(!is_free(root.path()), "the lock is held again");
        drop(held);
        assert!(is_free(root.path()));
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
