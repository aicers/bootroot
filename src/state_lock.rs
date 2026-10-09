//! The lock every command that writes `state.json` holds from before
//! it loads the file until after it last saves it.
//!
//! Every such command loads the whole file into a
//! [`StateFile`](crate::state::StateFile), works, and writes the whole
//! struct back. The write is an atomic rename, so the file is never
//! torn, but a rename serializes nothing: a `service add` that commits
//! while a rotation is restarting a container is overwritten when the
//! rotation saves the registry it loaded before the add, and neither
//! command reports an error. Holding this lock across the whole
//! load-to-save interval is what makes the second command start from
//! what the first one wrote.
//!
//! # The shape of the lock
//!
//! An exclusive `flock(2)` on `<resolved state file>.lock`, the design
//! of [`bootroot::publication_lock`]: the file is a name to lock and
//! never a record, it is created `0600`, nothing is written to it, and
//! it is never removed. The guard unlocks on drop — on every error path
//! too — so that a copy of the descriptor in a child another thread has
//! forked and not yet `exec`ed cannot keep the lock held, and the kernel
//! still releases it when the holder is killed without running `drop`.
//! A lock file left behind by a dead process therefore blocks nobody.
//!
//! # Who takes it
//!
//! The entry point `main` dispatches to, once per process, for the
//! commands that save `state.json`: `rotate approle-secret-id`,
//! `rotate infra-cert`, `service add`, `service update`,
//! `service remove`, `infra install`, `init` and `reinit`. Never a
//! helper: `flock` on a second descriptor of the same file blocks
//! against the first, so a nested acquisition would hang the command.
//! The functions underneath take a `&StateLock` instead, which is how a
//! signature says its caller holds the lock.
//!
//! It is the outermost lock: a command takes it before the publication
//! lock, the `agent.toml.lock` and the CA bundle lock. No daemon and no
//! agent ever takes it, so that order cannot cycle.
//!
//! Read-only commands take nothing. The rename already hands them one
//! whole version of the file or the other.

use std::ffi::OsString;
use std::fs::{File, OpenOptions, TryLockError};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;

use crate::i18n::Messages;

/// What is appended to the state file's name to name its lock file.
const LOCK_FILE_SUFFIX: &str = ".lock";

/// The mode the lock file is created at.
///
/// It holds nothing, so nothing needs to read it. Owner-only keeps an
/// unprivileged local user from opening it, holding the lock and
/// stalling rotation until the `secret_id`s expire.
const LOCK_FILE_MODE: u32 = 0o600;

/// Exclusive access to one state file's load-to-save interval, released
/// when it is dropped: the guard unlocks the file before closing it.
#[derive(Debug)]
pub(crate) struct StateLock {
    /// The open lock file, holding the `flock(2)`; nothing ever reads or
    /// writes it. Unlocked on drop, and released by the kernel if the
    /// holder dies first. The descriptor is close-on-exec, the standard
    /// library's default, so a child such as `docker` never inherits the
    /// lock.
    file: File,
}

impl Drop for StateLock {
    fn drop(&mut self) {
        // `flock` belongs to the open file description, which a child
        // forked by another thread shares until its `exec`; closing our
        // descriptor alone would leave the lock held through that copy.
        // An error is discarded: the descriptor closes next, and the
        // kernel releases the lock once no copy remains.
        let _ = self.file.unlock();
    }
}

impl StateLock {
    /// Takes the state lock for `state_path`, waiting for whichever
    /// command holds it.
    ///
    /// The wait is unbounded on purpose: the longest holder is a
    /// rotation or `init`, a second writer finishing late is correct,
    /// and the kernel releases the lock of a holder that dies. A caller
    /// that has to wait says so once on stderr first, so that a
    /// timer-fired unit blocked behind an interactive command shows why
    /// in its journal.
    ///
    /// For the commands that run outside any runtime; async callers use
    /// [`StateLock::acquire`].
    ///
    /// # Errors
    ///
    /// Returns an error naming the lock path when the lock file cannot
    /// be opened or created — it belongs to another user, the directory
    /// is not writable, or a symbolic link sits at its name — and when
    /// the filesystem refuses `flock`. Nothing falls back to running
    /// unlocked.
    pub(crate) fn acquire_blocking(state_path: &Path, messages: &Messages) -> Result<Self> {
        acquire_with(state_path, announce_wait(messages))
    }

    /// Takes the state lock for `state_path` without blocking a runtime
    /// worker while it waits.
    ///
    /// [`StateLock::acquire_blocking`] on a blocking thread. The guard
    /// is a file descriptor, not a `std::sync` guard, so holding it
    /// across an `.await` is what it is for.
    ///
    /// # Errors
    ///
    /// As [`StateLock::acquire_blocking`], and when the blocking task
    /// panics.
    pub(crate) async fn acquire(state_path: &Path, messages: &Messages) -> Result<Self> {
        acquire_async_with(state_path, announce_wait(messages)).await
    }
}

/// The waiting line: one line on stderr naming the lock file.
fn announce_wait(messages: &Messages) -> impl FnOnce(&Path) + Send + 'static {
    let messages = messages.clone();
    move |lock_path| {
        eprintln!(
            "{}",
            messages.info_state_lock_waiting(&lock_path.display().to_string())
        );
    }
}

/// [`acquire_with`] on a blocking thread: `flock` waits, so it waits
/// there and not on a runtime worker.
async fn acquire_async_with(
    state_path: &Path,
    on_wait: impl FnOnce(&Path) + Send + 'static,
) -> Result<StateLock> {
    let state_path = state_path.to_path_buf();
    tokio::task::spawn_blocking(move || acquire_with(&state_path, on_wait))
        .await
        .context("the state lock task panicked")?
}

/// Returns the lock file for the state file a command was given.
///
/// The state file is resolved exactly as `StateFile::save` resolves its
/// destination, so a command that reaches it through a symbolic link
/// and one that names the target directly take the same lock. Derived
/// from that path alone, so two installs with different state files
/// never contend.
fn lock_path_for(state_path: &Path) -> Result<PathBuf> {
    let resolved = fs_util::resolve_symlink_destination(state_path).with_context(|| {
        format!(
            "resolving the state file {} to find its state lock",
            state_path.display()
        )
    })?;
    let Some(file_name) = resolved.file_name() else {
        anyhow::bail!(
            "the state file path {} names no file to take a state lock beside",
            resolved.display()
        );
    };
    let mut lock_name = OsString::from(file_name);
    lock_name.push(LOCK_FILE_SUFFIX);
    Ok(resolved.with_file_name(lock_name))
}

/// Opens the lock file, creating it if it is not there.
///
/// Never truncated and never written. `O_NOFOLLOW` refuses a symbolic
/// link planted at the lock file's own name rather than creating or
/// opening whatever it points at. No directory is created: the state
/// file's directory exists wherever a writer can succeed.
fn open_lock_file(lock_path: &Path) -> Result<File> {
    OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .mode(LOCK_FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(lock_path)
        .with_context(|| format!("opening the state lock {}", lock_path.display()))
}

/// Takes the lock, calling `on_wait` with the lock path once if — and
/// only if — another descriptor holds it.
///
/// The seam the waiting line goes through: production prints it, and a
/// test observes that the second writer reached the wait without
/// reading a stream or sleeping.
fn acquire_with(state_path: &Path, on_wait: impl FnOnce(&Path)) -> Result<StateLock> {
    let lock_path = lock_path_for(state_path)?;
    let file = open_lock_file(&lock_path)?;
    match file.try_lock() {
        Ok(()) => return Ok(StateLock { file }),
        Err(TryLockError::WouldBlock) => {}
        Err(TryLockError::Error(err)) => {
            return Err(anyhow::Error::new(err)
                .context(format!("taking the state lock {}", lock_path.display())));
        }
    }
    on_wait(&lock_path);
    file.lock()
        .with_context(|| format!("waiting for the state lock {}", lock_path.display()))?;
    Ok(StateLock { file })
}

/// Answers whether another descriptor holds the state lock for
/// `state_path` right now.
///
/// Test-only, and the shape every assertion about this lock is made in:
/// `flock(2)` belongs to the open file description rather than to the
/// process, so a lock held on another descriptor refuses this probe
/// exactly as it would refuse another process's. Never a gate for
/// production code — the answer is stale the instant it is returned.
#[cfg(test)]
pub(crate) fn is_held(state_path: &Path) -> bool {
    let lock_path = lock_path_for(state_path).expect("the lock path resolves");
    let Ok(file) = OpenOptions::new().read(true).open(&lock_path) else {
        return false;
    };
    probe_is_held(&file)
}

/// Answers whether another descriptor holds a `flock` on `file`, giving
/// back with `unlock` a lock the probe itself took.
///
/// Unlocked rather than left to the descriptor closing, so that a child
/// another test thread forks in between cannot carry the probe's lock
/// into the next step of the test.
#[cfg(test)]
fn probe_is_held(file: &File) -> bool {
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            false
        }
        Err(TryLockError::WouldBlock) => true,
        Err(TryLockError::Error(_)) => false,
    }
}

/// Takes the state lock for `state_path` in a test.
///
/// For the tests that call a function underneath an entry point and so
/// have to supply the guard its caller would be holding.
#[cfg(test)]
pub(crate) fn hold_for_test(state_path: &Path) -> StateLock {
    acquire_with(state_path, |_| {}).expect("the test takes the state lock")
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::mpsc;

    use tempfile::tempdir;

    use super::*;
    use crate::i18n::test_messages;

    const STATE_FILE: &str = "state.json";
    const LOCK_FILE: &str = "state.json.lock";

    #[test]
    fn the_lock_file_sits_beside_the_state_file_with_lock_appended() {
        assert_eq!(
            lock_path_for(Path::new("/srv/bootroot/state.json")).unwrap(),
            Path::new("/srv/bootroot/state.json.lock")
        );
        assert_eq!(
            lock_path_for(Path::new("state.json")).unwrap(),
            Path::new("state.json.lock")
        );
    }

    /// A state file that does not exist yet — `init`, or `infra install`
    /// on a fresh directory — still has a place for its lock.
    #[test]
    fn the_lock_is_taken_beside_a_state_file_that_does_not_exist_yet() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join(STATE_FILE);

        let _held = StateLock::acquire_blocking(&state_path, &test_messages()).unwrap();

        assert!(dir.path().join(LOCK_FILE).exists());
        assert!(!state_path.exists(), "taking the lock writes no state");
    }

    #[test]
    fn the_lock_file_is_created_owner_only_and_empty() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join(STATE_FILE);

        drop(StateLock::acquire_blocking(&state_path, &test_messages()).unwrap());

        let metadata = std::fs::metadata(dir.path().join(LOCK_FILE)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        assert_eq!(metadata.len(), 0, "nothing is ever written to it");
    }

    /// The lock is the `flock`, not the file: releasing leaves the file
    /// where it is, and a file left by a killed process blocks nobody.
    #[test]
    fn a_released_or_stale_lock_file_stays_and_blocks_nobody() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join(STATE_FILE);
        let lock_path = dir.path().join(LOCK_FILE);
        // What a process that died holding the lock leaves behind.
        std::fs::write(&lock_path, "").unwrap();

        let (waited_tx, waited_rx) = mpsc::channel();
        let held = acquire_with(&state_path, |path| {
            waited_tx.send(path.to_path_buf()).unwrap();
        })
        .unwrap();
        assert!(
            waited_rx.try_recv().is_err(),
            "a free lock is taken without the waiting line"
        );
        assert!(is_held(&state_path));

        drop(held);

        assert!(!is_held(&state_path), "dropping the guard releases it");
        assert!(lock_path.exists(), "the lock file is never removed");
    }

    /// The second writer neither fails nor proceeds while the first
    /// holds the lock, says so exactly once, and proceeds on release.
    #[test]
    fn a_second_writer_waits_says_so_once_and_proceeds_on_release() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join(STATE_FILE);
        let first = hold_for_test(&state_path);

        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let second = std::thread::spawn({
            let state_path = state_path.clone();
            move || {
                let lock = acquire_with(&state_path, |path| {
                    waiting_tx.send(path.to_path_buf()).unwrap();
                });
                acquired_tx.send(()).unwrap();
                lock.map(drop)
            }
        });

        // Blocks until the second writer has found the lock held: no
        // sleep, the callback is the signal.
        let announced = waiting_rx.recv().unwrap();
        assert_eq!(announced, dir.path().join(LOCK_FILE));
        assert!(
            acquired_rx.try_recv().is_err(),
            "the second writer must not get the lock while the first holds it"
        );

        drop(first);

        acquired_rx.recv().unwrap();
        second.join().unwrap().expect("the second writer proceeds");
        assert!(
            waiting_rx.try_recv().is_err(),
            "the waiting line is printed once"
        );
    }

    /// The async acquire waits on a blocking thread: on a runtime with
    /// a single thread, the test task still runs while the second
    /// acquisition is blocked, which is what lets it release the first.
    #[tokio::test(flavor = "current_thread")]
    async fn the_async_acquire_does_not_block_the_runtime_while_waiting() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join(STATE_FILE);
        let first = StateLock::acquire(&state_path, &test_messages())
            .await
            .unwrap();

        let (waiting_tx, waiting_rx) = tokio::sync::oneshot::channel();
        let second = tokio::spawn({
            let state_path = state_path.clone();
            async move {
                acquire_async_with(&state_path, move |_| {
                    waiting_tx.send(()).expect("the test is listening");
                })
                .await
            }
        });

        waiting_rx
            .await
            .expect("the second acquisition reaches the wait");
        assert!(!second.is_finished());
        drop(first);

        let _second = second
            .await
            .unwrap()
            .expect("the second acquisition proceeds");
        assert!(is_held(&state_path));
    }

    /// A writer that fails between load and save has released the lock
    /// by the time its error is returned.
    #[test]
    fn a_writer_that_fails_releases_the_lock() {
        fn failing_writer(state_path: &Path) -> Result<()> {
            let _lock = StateLock::acquire_blocking(state_path, &test_messages())?;
            anyhow::bail!("failed between load and save")
        }

        let dir = tempdir().unwrap();
        let state_path = dir.path().join(STATE_FILE);

        failing_writer(&state_path).unwrap_err();

        assert!(!is_held(&state_path));
        let (waited_tx, waited_rx) = mpsc::channel();
        acquire_with(&state_path, |_| waited_tx.send(()).unwrap())
            .expect("the next writer runs to completion");
        assert!(waited_rx.try_recv().is_err());
    }

    #[test]
    fn a_symlink_at_the_lock_name_is_refused_and_its_target_left_alone() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join(STATE_FILE);
        let lock_path = dir.path().join(LOCK_FILE);

        // Dangling: following it would create the target.
        let missing_target = dir.path().join("planted-missing");
        symlink(&missing_target, &lock_path).unwrap();
        let err = StateLock::acquire_blocking(&state_path, &test_messages()).unwrap_err();
        assert!(
            format!("{err:#}").contains(&lock_path.display().to_string()),
            "the error names the lock path: {err:#}"
        );
        assert!(!missing_target.exists(), "the target is not created");

        // Existing: following the link would have opened the target
        // and taken the lock on it.
        std::fs::remove_file(&lock_path).unwrap();
        let existing_target = dir.path().join("planted-existing");
        std::fs::write(&existing_target, "untouched").unwrap();
        symlink(&existing_target, &lock_path).unwrap();
        let err = StateLock::acquire_blocking(&state_path, &test_messages()).unwrap_err();
        assert!(format!("{err:#}").contains(&lock_path.display().to_string()));
        assert_eq!(
            std::fs::read_to_string(&existing_target).unwrap(),
            "untouched"
        );
        assert!(
            !is_held_at(&existing_target),
            "the link's target is not the thing locked"
        );
    }

    #[test]
    fn a_state_file_reached_through_a_symlink_shares_the_targets_lock() {
        let dir = tempdir().unwrap();
        // Canonical, so the resolved link and the direct name spell the
        // directory the same way (a macOS tempdir sits behind a link).
        let root = dir.path().canonicalize().unwrap();
        let real_dir = root.join("real");
        let link_dir = root.join("links");
        std::fs::create_dir_all(&real_dir).unwrap();
        std::fs::create_dir_all(&link_dir).unwrap();
        let target = real_dir.join(STATE_FILE);
        std::fs::write(&target, "{}").unwrap();
        let link = link_dir.join("via-link.json");
        symlink(&target, &link).unwrap();

        assert_eq!(
            lock_path_for(&link).unwrap(),
            lock_path_for(&target).unwrap()
        );
        assert_eq!(lock_path_for(&link).unwrap(), real_dir.join(LOCK_FILE));

        let _held = hold_for_test(&link);
        assert!(is_held(&target), "the two names contend on one lock");
        assert!(!link_dir.join("via-link.json.lock").exists());
    }

    /// A dangling link is resolved from its own text, so the lock lands
    /// beside where the state file will be written.
    #[test]
    fn a_dangling_state_symlink_locks_beside_its_target() {
        let dir = tempdir().unwrap();
        let real_dir = dir.path().join("real");
        std::fs::create_dir_all(&real_dir).unwrap();
        let link = dir.path().join(STATE_FILE);
        symlink(real_dir.join(STATE_FILE), &link).unwrap();

        let _held = hold_for_test(&link);

        assert!(real_dir.join(LOCK_FILE).exists());
        assert!(!dir.path().join(LOCK_FILE).exists());
    }

    #[test]
    fn an_unopenable_lock_file_fails_the_command_with_its_path() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join("missing-dir").join(STATE_FILE);

        let err = StateLock::acquire_blocking(&state_path, &test_messages()).unwrap_err();

        let rendered = format!("{err:#}");
        assert!(rendered.contains("opening the state lock"), "{rendered}");
        assert!(rendered.contains("state.json.lock"), "{rendered}");
        assert!(
            !dir.path().join("missing-dir").exists(),
            "no directory is created for the lock file"
        );
    }

    #[test]
    fn two_state_files_do_not_contend() {
        let dir = tempdir().unwrap();
        let mine = dir.path().join("mine.json");
        let theirs = dir.path().join("theirs.json");

        let _held = hold_for_test(&mine);

        assert!(!is_held(&theirs));
        // Granted rather than queued: a second acquisition that had to
        // wait would never return here.
        hold_for_test(&theirs);
    }

    /// A copy of the guard's descriptor — what a child forked by another
    /// thread holds until its `exec` — does not keep the lock held once
    /// the guard is dropped.
    #[test]
    fn a_descriptor_copy_does_not_keep_a_dropped_lock_held() {
        let dir = tempdir().unwrap();
        let state_path = dir.path().join(STATE_FILE);
        let held = hold_for_test(&state_path);
        let copy = held.file.try_clone().unwrap();

        drop(held);

        assert!(
            !is_held(&state_path),
            "dropping the guard releases the lock despite the copy"
        );
        drop(copy);
    }

    /// Whether some descriptor holds a `flock` on exactly `path`.
    fn is_held_at(path: &Path) -> bool {
        let file = OpenOptions::new().read(true).open(path).unwrap();
        probe_is_held(&file)
    }
}
