//! The one lock every in-process writer of `[trust] ca_bundle_path`
//! takes.
//!
//! The merged CA bundle is not a per-profile file. The per-profile
//! renewal loop merges its issued chain into it
//! (`acme::flow::write_merged_ca_bundle`), the fast-poll loop
//! replaces it wholesale when a trust update lands, and the registrar
//! surface's renewal reads it, stages a merge, snapshots it, publishes
//! it and — when the publication fails afterwards — restores it. All
//! three run as independent tasks of one daemon, and the daemon's
//! `ProfileLocks` serialises none of them against each other: its keys
//! are profile labels, and this file has no profile.
//!
//! Unserialised, the read-merge-write pairs interleave and lose writes.
//! A profile merge landing after the registrar's snapshot but before its
//! rollback is discarded by that rollback, which puts back bytes that
//! were already stale; a profile merge landing after the registrar's
//! staged read but before its publication is overwritten by it. Either
//! way the daemon ends up serving a bundle missing an anchor it was told
//! to trust, with nothing recording that it went missing.
//!
//! So each of those transactions holds this lock for its whole span —
//! from the read the merge is computed against through the last write or
//! restore that span can perform — and the file changes under none of
//! them.
//!
//! # What it is not
//!
//! It is process-wide, and only process-wide. A second `bootroot`
//! invocation writing the same bundle is outside its reach entirely;
//! that is what the atomic rename in [`crate::fs_util::write_ca_bundle`]
//! is for, and the two answer different questions.
//!
//! The lock is deliberately *not* taken inside
//! [`crate::fs_util::write_ca_bundle`]. A transaction that has already
//! taken it goes on to call that writer, and a second acquisition there
//! would deadlock it against itself. Ownership belongs to the
//! transaction, which is the only layer that knows where its critical
//! section begins.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex as StdMutex, PoisonError};

use tokio::sync::{Mutex as TokioMutex, OwnedMutexGuard};

/// The one bundle-path lock map the whole process shares.
///
/// A `static` rather than something a caller is handed, because the
/// writers have no common owner to be handed it by: the per-profile
/// publication is reached from the daemon loop and from the CLI's
/// issuance alike, several call frames below anything that knows a
/// daemon exists. Threading a registry down all of them would put the
/// correctness of the lock in the hands of every future call site,
/// where forgetting the argument compiles.
static BUNDLE_LOCKS: LazyLock<BundleLocks> = LazyLock::new(BundleLocks::default);

/// Exclusive access to one bundle path, released when dropped.
pub(crate) type BundleGuard = OwnedMutexGuard<()>;

/// Takes `bundle_path`'s lock, waiting for whichever transaction holds
/// it to finish.
///
/// Hold the guard across the whole transaction — the read the merge is
/// computed from, every live write, and any rollback — and not merely
/// across the write itself. A guard scoped to the write alone still
/// lets another writer land between this one's read and its write.
pub(crate) async fn hold(bundle_path: &Path) -> BundleGuard {
    BUNDLE_LOCKS.for_path(bundle_path).lock_owned().await
}

/// The path-keyed registry behind [`hold`].
#[derive(Default)]
struct BundleLocks {
    entries: StdMutex<BTreeMap<PathBuf, Arc<TokioMutex<()>>>>,
}

impl BundleLocks {
    /// Returns `bundle_path`'s mutex, creating it on first access.
    ///
    /// Keyed on the configured path as written, exactly as the daemon's
    /// `ProfileLocks` keys on the configured profile label: every writer
    /// reads it from the same
    /// `[trust] ca_bundle_path` of the same `Settings`, so the keys
    /// coincide by construction. Entries are never removed — a daemon
    /// has one bundle path and a reload can only ever introduce another
    /// one — so a lock is never dropped while a waiter is queued on it.
    fn for_path(&self, bundle_path: &Path) -> Arc<TokioMutex<()>> {
        let mut entries = self
            .entries
            .lock()
            // A lookup and an insert cannot leave the map torn, so an
            // unrelated panic must not make the bundle permanently
            // unwritable.
            .unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            entries
                .entry(bundle_path.to_path_buf())
                .or_insert_with(|| Arc::new(TokioMutex::new(()))),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::hold;

    /// One path hands out one lock, so a second acquisition of it waits
    /// while a different path does not.
    #[tokio::test]
    async fn one_path_is_one_lock_and_two_paths_are_two() {
        let first = PathBuf::from("/tmp/bootroot-ca-bundle-lock-test/first.pem");
        let second = PathBuf::from("/tmp/bootroot-ca-bundle-lock-test/second.pem");
        let held = hold(&first).await;

        let other = tokio::spawn({
            let second = second.clone();
            async move { hold(&second).await }
        });
        other
            .await
            .expect("a different path is a different lock and does not wait");

        let same = tokio::spawn({
            let first = first.clone();
            async move { hold(&first).await }
        });
        tokio::task::yield_now().await;
        assert!(
            !same.is_finished(),
            "a second acquisition of one path waits for the guard to drop"
        );
        drop(held);
        same.await.expect("the queued acquisition proceeds");
    }
}
