//! Tests for the `OpenBao` audit device's rotation.
//!
//! Everything here runs against a real directory under
//! `tempfile::tempdir()`, because every guarantee this module makes is a
//! filesystem guarantee: which name was published, what mode it carries,
//! which bytes survived a failure and which were destroyed. The clock is
//! a parameter of a pass rather than a reading it takes, so the
//! clock-rollback case is driven rather than waited for, and so is the
//! sequence namespace.
//!
//! Docker is behind a seam ([`StubDocker`]), so both forms are reachable
//! without a daemon: a stub that matches no container drives the
//! fallback, and one that creates a fresh active log when it is
//! signalled drives the signal form. Neither ever runs `docker`.
//!
//! The bounds used below are far under
//! [`MIN_OPENBAO_AUDIT_MAX_FILE_BYTES`] on purpose. That floor is a
//! configuration rule, enforced where a configuration is loaded; the
//! rotation itself takes the numbers it is given, and holding the tests
//! to megabyte files would buy nothing but minutes.

use std::ffi::CString;
use std::future::Future;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use tracing::instrument::WithSubscriber as _;

use super::*;

// ---------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------

/// A hook a test installs to observe or measure a pass mid-flight.
type PassHook = Arc<dyn Fn(&Path) + Send + Sync>;

/// The active log's contents, its identity and the retained set's
/// names, as one moment of a pass found them.
type Restored = Option<(Vec<u8>, (u64, u64), Vec<String>)>;

/// Switches a test flips to make one step of a pass fail, and the hooks
/// that let it look at, or interfere with, state a pass holds for one
/// instant.
///
/// A failed `fsync`, a failed rename, a failed truncate and a failed
/// unlink cannot be provoked from outside the process, and "the step
/// returned an error" is exactly the case this module is mostly about.
/// Every check that reads one is `#[cfg(test)]`, so a shipped build
/// contains neither the field nor the branch.
pub(crate) struct FaultInjection {
    /// Fail the flush of the staging copy.
    staging_sync: AtomicBool,
    /// Fail the flush of the directory the generation was published
    /// into.
    directory_sync: AtomicBool,
    /// Fail the truncate that empties the active log.
    truncate: AtomicBool,
    /// Fail the flush that makes that truncate durable.
    active_sync: AtomicBool,
    /// Index into the oldest-first trim at which every further removal
    /// fails. `usize::MAX` disarms it.
    trim_fails_from: AtomicUsize,
    /// Fail the flush that makes a trim's deletions durable.
    trim_sync: AtomicBool,
    /// Fail the rotation-intent marker's write.
    marker_write: AtomicBool,
    /// Fail the marker's unlink.
    marker_unlink: AtomicBool,
    /// Fail the flush that makes that unlink durable.
    marker_flush: AtomicBool,
    /// Fail the rename that moves the active log aside.
    rename: AtomicBool,
    /// Fail the flush that has to land before the signal.
    rename_sync: AtomicBool,
    /// Fail the rename-back. `0` is off, `1` an ordinary error and `2`
    /// the `EEXIST` a name that appeared under it produces — which is
    /// not a failure by itself, so the branch it opens has to be
    /// drivable on its own.
    restore_rename: AtomicUsize,
    /// Fail the flush that makes the rename-back durable.
    restore_sync: AtomicBool,
    /// Runs with the active log's path, after the rotation-intent
    /// marker is on disk and before the rename moves the log aside —
    /// the window in which a replacement at that path costs the pass
    /// the identity it just recorded.
    before_rename_aside: Mutex<Option<PassHook>>,
    /// Runs with the active log's path, after the size decision has
    /// been taken on it and before the fallback's copy opens it.
    before_stage: Mutex<Option<PassHook>>,
    /// Runs with the staging copy's path, after it is staged and before
    /// it is published.
    after_stage: Mutex<Option<PassHook>>,
    /// Runs with the published generation's path, after the directory
    /// flush and before the truncate.
    before_truncate: Mutex<Option<PassHook>>,
    /// Runs with the active log's path, immediately before the
    /// recovery's first look — the window a reopen landing after the
    /// deadline arrives in.
    before_recovery: Mutex<Option<PassHook>>,
    /// Runs with the active log's path, after that look and before the
    /// rename-back — the window an `EEXIST` is produced in.
    before_restore_rename: Mutex<Option<PassHook>>,
    /// Runs with the *generation's* path, after the rename's directory
    /// flush and before the pre-signal re-check — the window in which a
    /// replacement of the generation must still stop the signal.
    before_signal: Mutex<Option<PassHook>>,
    /// Expect a marker owned by somebody other than this process, which
    /// is how a marker the container's audit user wrote looks to the
    /// daemon. A test process cannot chown a file to another uid, so
    /// the expectation moves rather than the file.
    marker_owner_foreign: AtomicBool,
}

impl Default for FaultInjection {
    fn default() -> Self {
        Self {
            staging_sync: AtomicBool::new(false),
            directory_sync: AtomicBool::new(false),
            truncate: AtomicBool::new(false),
            active_sync: AtomicBool::new(false),
            trim_fails_from: AtomicUsize::new(usize::MAX),
            trim_sync: AtomicBool::new(false),
            marker_write: AtomicBool::new(false),
            marker_unlink: AtomicBool::new(false),
            marker_flush: AtomicBool::new(false),
            rename: AtomicBool::new(false),
            rename_sync: AtomicBool::new(false),
            restore_rename: AtomicUsize::new(0),
            restore_sync: AtomicBool::new(false),
            before_rename_aside: Mutex::new(None),
            before_stage: Mutex::new(None),
            after_stage: Mutex::new(None),
            before_truncate: Mutex::new(None),
            before_recovery: Mutex::new(None),
            before_restore_rename: Mutex::new(None),
            before_signal: Mutex::new(None),
            marker_owner_foreign: AtomicBool::new(false),
        }
    }
}

/// Reads one hook out from behind its lock.
fn hook_of(slot: &Mutex<Option<PassHook>>) -> Option<PassHook> {
    slot.lock().expect("the hook lock is live").clone()
}

impl FaultInjection {
    pub(crate) fn staging_sync_fails(&self) -> bool {
        self.staging_sync.load(Ordering::SeqCst)
    }

    pub(crate) fn directory_sync_fails(&self) -> bool {
        self.directory_sync.load(Ordering::SeqCst)
    }

    pub(crate) fn truncate_fails(&self) -> bool {
        self.truncate.load(Ordering::SeqCst)
    }

    pub(crate) fn active_sync_fails(&self) -> bool {
        self.active_sync.load(Ordering::SeqCst)
    }

    pub(crate) fn trim_fails_from(&self) -> usize {
        self.trim_fails_from.load(Ordering::SeqCst)
    }

    pub(crate) fn trim_sync_fails(&self) -> bool {
        self.trim_sync.load(Ordering::SeqCst)
    }

    pub(crate) fn marker_write_fails(&self) -> bool {
        self.marker_write.load(Ordering::SeqCst)
    }

    pub(crate) fn marker_unlink_fails(&self) -> bool {
        self.marker_unlink.load(Ordering::SeqCst)
    }

    pub(crate) fn marker_flush_fails(&self) -> bool {
        self.marker_flush.load(Ordering::SeqCst)
    }

    pub(crate) fn rename_fails(&self) -> bool {
        self.rename.load(Ordering::SeqCst)
    }

    pub(crate) fn rename_sync_fails(&self) -> bool {
        self.rename_sync.load(Ordering::SeqCst)
    }

    pub(crate) fn restore_rename_fails(&self) -> Option<std::io::ErrorKind> {
        match self.restore_rename.load(Ordering::SeqCst) {
            1 => Some(std::io::ErrorKind::Other),
            2 => Some(std::io::ErrorKind::AlreadyExists),
            _ => None,
        }
    }

    pub(crate) fn restore_sync_fails(&self) -> bool {
        self.restore_sync.load(Ordering::SeqCst)
    }

    pub(crate) fn before_rename_aside(&self) -> Option<PassHook> {
        hook_of(&self.before_rename_aside)
    }

    pub(crate) fn before_stage(&self) -> Option<PassHook> {
        hook_of(&self.before_stage)
    }

    pub(crate) fn after_stage(&self) -> Option<PassHook> {
        hook_of(&self.after_stage)
    }

    pub(crate) fn before_truncate(&self) -> Option<PassHook> {
        hook_of(&self.before_truncate)
    }

    pub(crate) fn before_recovery(&self) -> Option<PassHook> {
        hook_of(&self.before_recovery)
    }

    pub(crate) fn before_restore_rename(&self) -> Option<PassHook> {
        hook_of(&self.before_restore_rename)
    }

    pub(crate) fn before_signal(&self) -> Option<PassHook> {
        hook_of(&self.before_signal)
    }

    pub(crate) fn marker_owner_is_foreign(&self) -> bool {
        self.marker_owner_foreign.load(Ordering::SeqCst)
    }
}

impl OpenBaoAuditRotation {
    fn faults(&self) -> &FaultInjection {
        &self.layout.faults
    }

    fn fail_trim_from(&self, index: usize) {
        self.faults().trim_fails_from.store(index, Ordering::SeqCst);
    }

    fn allow_trim(&self) {
        self.faults()
            .trim_fails_from
            .store(usize::MAX, Ordering::SeqCst);
    }

    fn fail_trim_sync(&self) {
        self.faults().trim_sync.store(true, Ordering::SeqCst);
    }

    fn allow_trim_sync(&self) {
        self.faults().trim_sync.store(false, Ordering::SeqCst);
    }

    fn fail_staging_sync(&self) {
        self.faults().staging_sync.store(true, Ordering::SeqCst);
    }

    fn fail_directory_sync(&self) {
        self.faults().directory_sync.store(true, Ordering::SeqCst);
    }

    fn fail_truncate(&self) {
        self.faults().truncate.store(true, Ordering::SeqCst);
    }

    fn allow_truncate(&self) {
        self.faults().truncate.store(false, Ordering::SeqCst);
    }

    fn fail_active_sync(&self) {
        self.faults().active_sync.store(true, Ordering::SeqCst);
    }

    fn allow_active_sync(&self) {
        self.faults().active_sync.store(false, Ordering::SeqCst);
    }

    fn fail_marker_write(&self) {
        self.faults().marker_write.store(true, Ordering::SeqCst);
    }

    fn fail_marker_unlink(&self) {
        self.faults().marker_unlink.store(true, Ordering::SeqCst);
    }

    fn allow_marker_unlink(&self) {
        self.faults().marker_unlink.store(false, Ordering::SeqCst);
    }

    fn fail_marker_flush(&self) {
        self.faults().marker_flush.store(true, Ordering::SeqCst);
    }

    fn allow_marker_flush(&self) {
        self.faults().marker_flush.store(false, Ordering::SeqCst);
    }

    fn fail_rename(&self) {
        self.faults().rename.store(true, Ordering::SeqCst);
    }

    fn fail_rename_sync(&self) {
        self.faults().rename_sync.store(true, Ordering::SeqCst);
    }

    fn fail_restore_rename(&self) {
        self.faults().restore_rename.store(1, Ordering::SeqCst);
    }

    /// Refuses the rename-back exactly as a name that appeared under it
    /// would, so the post-`EEXIST` re-stat decides on its own.
    fn refuse_restore_rename(&self) {
        self.faults().restore_rename.store(2, Ordering::SeqCst);
    }

    fn allow_restore_rename(&self) {
        self.faults().restore_rename.store(0, Ordering::SeqCst);
    }

    fn fail_restore_sync(&self) {
        self.faults().restore_sync.store(true, Ordering::SeqCst);
    }

    fn allow_restore_sync(&self) {
        self.faults().restore_sync.store(false, Ordering::SeqCst);
    }

    fn install(slot: &Mutex<Option<PassHook>>, hook: impl Fn(&Path) + Send + Sync + 'static) {
        *slot.lock().expect("the hook lock is live") = Some(Arc::new(hook));
    }

    fn on_rename_aside(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        Self::install(&self.faults().before_rename_aside, hook);
    }

    fn before_stage(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        Self::install(&self.faults().before_stage, hook);
    }

    fn on_stage(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        Self::install(&self.faults().after_stage, hook);
    }

    fn on_publish(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        Self::install(&self.faults().before_truncate, hook);
    }

    fn on_recovery(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        Self::install(&self.faults().before_recovery, hook);
    }

    fn on_restore_rename(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        Self::install(&self.faults().before_restore_rename, hook);
    }

    fn before_signal(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        Self::install(&self.faults().before_signal, hook);
    }

    /// Makes every marker on disk look like one the container's audit
    /// user wrote.
    fn foreign_marker_owner(&self) {
        self.faults()
            .marker_owner_foreign
            .store(true, Ordering::SeqCst);
    }

    fn marker_path(&self) -> &Path {
        &self.layout.marker_path
    }

    fn restore_is_pending(&self) -> bool {
        self.state.pending_restore.is_some()
    }

    /// The descriptor a pass was left holding on a displaced
    /// generation, if one was.
    fn displaced_incident(&self) -> Option<&DisplacedIncident> {
        self.state.displaced.as_ref()
    }

    fn passes(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.passes)
    }
}

// ---------------------------------------------------------------------
// The Docker seam
// ---------------------------------------------------------------------

/// What a stubbed container "does" when it is signalled.
type SignalHook = Arc<dyn Fn() + Send + Sync>;

/// One addressing failure: a label and the stub that produces it.
type AddressingCase = (&'static str, Box<dyn Fn(&Path) -> Arc<StubDocker>>);

/// A [`DockerControl`] a test drives.
///
/// Every addressing and signalling failure the rotation has to answer
/// for is reachable here — Docker unreachable, no match, several
/// matches, a signal that fails — and so is the one success: a stub
/// that creates a fresh active log when it is signalled is what an
/// image honouring `SIGHUP` looks like from the daemon's side.
pub(crate) struct StubDocker {
    /// Container id paired with the JSON `docker inspect` would print
    /// for its `.Mounts`.
    containers: Vec<(String, String)>,
    ps_fails: AtomicBool,
    inspect_fails: AtomicBool,
    signal_fails: AtomicBool,
    signalled: Mutex<Vec<String>>,
    on_signal: Mutex<Option<SignalHook>>,
}

/// The mount table a container bound at `dir` would report.
fn bind_mounts_json(dir: &Path) -> String {
    format!(
        "[{{\"Type\":\"bind\",\"Source\":\"{}\",\"Destination\":\"{}\"}}]",
        dir.display(),
        OPENBAO_CONTAINER_AUDIT_DIR
    )
}

impl StubDocker {
    /// A Docker with no containers at all: the addressing failure that
    /// drives every fallback test.
    fn without_containers() -> Arc<Self> {
        Arc::new(Self {
            containers: Vec::new(),
            ps_fails: AtomicBool::new(false),
            inspect_fails: AtomicBool::new(false),
            signal_fails: AtomicBool::new(false),
            signalled: Mutex::new(Vec::new()),
            on_signal: Mutex::new(None),
        })
    }

    /// A Docker whose named containers report the given mount tables.
    fn with_containers(containers: Vec<(String, String)>) -> Arc<Self> {
        Arc::new(Self {
            containers,
            ps_fails: AtomicBool::new(false),
            inspect_fails: AtomicBool::new(false),
            signal_fails: AtomicBool::new(false),
            signalled: Mutex::new(Vec::new()),
            on_signal: Mutex::new(None),
        })
    }

    /// The one container this install's device directory is bound into.
    fn bound_to(dir: &Path) -> Arc<Self> {
        Self::with_containers(vec![("bao".to_string(), bind_mounts_json(dir))])
    }

    fn fail_ps(&self) {
        self.ps_fails.store(true, Ordering::SeqCst);
    }

    fn fail_inspect(&self) {
        self.inspect_fails.store(true, Ordering::SeqCst);
    }

    fn fail_signal(&self) {
        self.signal_fails.store(true, Ordering::SeqCst);
    }

    /// Makes the stub behave like an image that honours the signal: the
    /// container creates a fresh active log at `active`, on a new inode,
    /// mode `0600`.
    fn reopens(&self, active: PathBuf) {
        self.on_signal(move || create_active_log(&active));
    }

    /// Makes the stub behave like an image that does not.
    fn stops_reopening(&self) {
        *self.on_signal.lock().expect("the hook lock is live") = None;
    }

    /// Installs what the container does when it is signalled, which is
    /// the window in which the configured path is absent.
    fn on_signal(&self, hook: impl Fn() + Send + Sync + 'static) {
        *self.on_signal.lock().expect("the hook lock is live") = Some(Arc::new(hook));
    }

    fn signalled(&self) -> Vec<String> {
        self.signalled
            .lock()
            .expect("the record lock is live")
            .clone()
    }
}

/// Creates an empty active log the way `OpenBao` would: a fresh inode
/// at the configured name, mode `0600`, never replacing one already
/// there.
fn create_active_log(path: &Path) {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("the reopened active log is created");
}

impl DockerControl for StubDocker {
    fn running_containers(&self) -> anyhow::Result<Vec<String>> {
        if self.ps_fails.load(Ordering::SeqCst) {
            anyhow::bail!("injected `docker ps` failure");
        }
        Ok(self.containers.iter().map(|(id, _)| id.clone()).collect())
    }

    fn container_mounts(&self, container: &str) -> anyhow::Result<String> {
        if self.inspect_fails.load(Ordering::SeqCst) {
            anyhow::bail!("injected `docker inspect` failure");
        }
        self.containers
            .iter()
            .find(|(id, _)| id == container)
            .map(|(_, mounts)| mounts.clone())
            .ok_or_else(|| anyhow::anyhow!("no such container: {container}"))
    }

    fn signal_hup(&self, container: &str) -> anyhow::Result<()> {
        self.signalled
            .lock()
            .expect("the record lock is live")
            .push(container.to_string());
        if let Some(hook) = self
            .on_signal
            .lock()
            .expect("the hook lock is live")
            .clone()
        {
            hook();
        }
        if self.signal_fails.load(Ordering::SeqCst) {
            anyhow::bail!("injected `docker kill` failure");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------

/// The instant every test's clock starts at.
const BASE_TS: &str = "2026-03-01T12:00:00Z";

/// The bounds most tests run under: small enough to be quick, large
/// enough that one record is not a whole generation.
const S: u64 = 4096;
const N: u32 = 3;

fn base() -> OffsetDateTime {
    OffsetDateTime::parse(BASE_TS, &Rfc3339).expect("the pinned instant parses")
}

fn at(offset_secs: i64) -> OffsetDateTime {
    base() + time::Duration::seconds(offset_secs)
}

/// A rotation over `dir` whose Docker matches no container, so every
/// pass falls back to copy-and-truncate.
///
/// The default deliberately: the mechanics the fallback owns — the
/// staging copy, the publish, the trim, the bound — are what most of
/// these tests are about, and they are reached identically either way.
fn rotation_at(dir: PathBuf, max_file_bytes: u64, max_retained_files: u32) -> OpenBaoAuditRotation {
    OpenBaoAuditRotation::with_control(
        dir,
        max_file_bytes,
        max_retained_files,
        StubDocker::without_containers(),
    )
}

fn fixture(max_file_bytes: u64, max_retained_files: u32) -> (TempDir, OpenBaoAuditRotation) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let rotation = rotation_at(dir.path().to_path_buf(), max_file_bytes, max_retained_files);
    (dir, rotation)
}

/// A rotation whose Docker matches this install's container and whose
/// container recreates the active log when it is signalled: the signal
/// form, end to end, with no Docker daemon anywhere.
fn signal_fixture(
    max_file_bytes: u64,
    max_retained_files: u32,
) -> (TempDir, OpenBaoAuditRotation, Arc<StubDocker>) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let docker = StubDocker::bound_to(dir.path());
    docker.reopens(dir.path().join(ACTIVE_FILE_NAME));
    let rotation = OpenBaoAuditRotation::with_control(
        dir.path().to_path_buf(),
        max_file_bytes,
        max_retained_files,
        Arc::clone(&docker) as Arc<dyn DockerControl>,
    );
    (dir, rotation, docker)
}

/// One synthetic audit record, fixed width so a test can count bytes.
fn record(index: usize) -> String {
    format!(
        "{{\"index\":\"{:06}\",\"pad\":\"{}\"}}\n",
        index % 1_000_000,
        "a".repeat(64)
    )
}

/// Appends whole records to `path` until it holds at least `bytes`.
fn append_records(path: &Path, bytes: u64) -> u64 {
    use std::io::Write as _;

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)
        .expect("the active log opens");
    let start = std::fs::metadata(path).map_or(0, |meta| meta.len());
    let mut written = 0_u64;
    let mut index = 0_usize;
    while written < bytes {
        let line = record(index);
        file.write_all(line.as_bytes())
            .expect("a record is written");
        written += u64::try_from(line.len()).expect("a record's length fits");
        index += 1;
    }
    file.flush().expect("the active log flushes");
    start + written
}

/// Writes a generation directly, for the cases that need a set the
/// rotation did not produce.
fn seed_generation(dir: &Path, stamp: &str, sequence: u32, bytes: u64) -> PathBuf {
    let path = dir.join(rotated_file_name(stamp, sequence));
    append_records(&path, bytes);
    path
}

fn generation_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("the device directory lists")
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| entry.file_name().to_str().map(str::to_string))
        .filter(|name| parse_rotated_name(name).is_some())
        .collect();
    names.sort_unstable();
    names
}

fn retained_bytes(dir: &Path) -> u64 {
    generation_names(dir)
        .iter()
        .map(|name| std::fs::metadata(dir.join(name)).map_or(0, |meta| meta.len()))
        .sum()
}

fn len_of(path: &Path) -> u64 {
    std::fs::metadata(path).map_or(0, |meta| meta.len())
}

fn identity_of(path: &Path) -> (u64, u64) {
    let meta = std::fs::symlink_metadata(path).expect("the path stats");
    file_identity(&meta)
}

/// Every byte held by a file of the audit-log family — the active log
/// and the retained generations — and nothing else.
///
/// Deliberately not [`device_bytes`]: the marker and the file it is
/// staged through are neither, and a "nothing was copied" assertion
/// they could satisfy would assert nothing.
fn log_family_bytes(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .expect("the device directory lists")
        .filter_map(std::result::Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name == ACTIVE_FILE_NAME || parse_rotated_name(name).is_some())
        })
        .filter_map(|entry| entry.metadata().ok())
        .filter(std::fs::Metadata::is_file)
        .map(|meta| meta.len())
        .sum()
}

/// Every byte in the device's directory: the retained set, the active
/// log and anything staged. What "the device's footprint" means.
fn device_bytes(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .expect("the device directory lists")
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .filter(std::fs::Metadata::is_file)
        .map(|meta| meta.len())
        .sum()
}

/// Runs `body` with a subscriber of its own and answers what it logged.
///
/// The subscriber is bound to the future rather than to a thread, and
/// the pass propagates it into the blocking phases it runs its
/// filesystem work on, so nothing leaks between tests running in
/// parallel and nothing a pass logs is lost.
async fn logs_from<F: Future<Output = ()>>(body: F) -> String {
    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("the capture lock is live")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Captured(Arc::clone(&buffer));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .with_writer(move || writer.clone())
        .finish();
    body.with_subscriber(subscriber).await;
    let captured = buffer.lock().expect("the capture lock is live").clone();
    String::from_utf8(captured).expect("the captured log is UTF-8")
}

fn count_lines_at(logs: &str, level: &str) -> usize {
    logs.lines().filter(|line| line.contains(level)).count()
}

fn assert_complete_json_lines(path: &Path) {
    let body = std::fs::read_to_string(path).expect("the generation reads");
    assert!(
        body.ends_with('\n'),
        "a generation ends on a record boundary"
    );
    for line in body.lines() {
        serde_json::from_str::<serde_json::Value>(line)
            .unwrap_or_else(|err| panic!("every line of a generation parses: {line} ({err})"));
    }
}

#[tokio::test]
async fn hard_ceiling_holds_after_every_completed_evaluation() {
    let (dir, mut rotation) = fixture(S, N);
    let budget = retained_budget_bytes(S, N);
    for round in 0..24_i64 {
        // Three times the bound, so a generation is oversized and the
        // byte trim rather than the count is what enforces the ceiling.
        append_records(&dir.path().join(ACTIVE_FILE_NAME), S * 3);
        let outcome = rotation.run_pass(at(round * 60)).await;
        assert!(outcome.evaluated);
        assert!(
            !outcome.retained_unmet,
            "round {round} left the retained set outside its bound"
        );
        assert!(
            outcome.retained_bytes <= budget,
            "round {round}: {} bytes retained against a {budget}-byte budget",
            outcome.retained_bytes
        );
        assert!(retained_bytes(dir.path()) <= budget);
        assert!(generation_names(dir.path()).len() <= N as usize);
    }
}

/// The operating envelope, under a model this test states rather than
/// assumes: the preceding pass succeeded, the writer appends exactly
/// `W` bytes per interval and appends nothing while the copy runs, so
/// `L = S + W` and `D = 0`.
///
/// Neither figure here is a bound. `S × (N + 1) + W` is what the device
/// is expected to sit at between passes under that model, and
/// `S × N + 2L + D` is what it is expected to peak at inside one — the
/// instant where the retained set, the active log at its captured
/// length and the newly published generation coexist. A model the
/// deployment leaves is a figure this test says nothing about.
#[tokio::test]
async fn conditional_envelope_under_the_stated_model() {
    const W: u64 = 512;
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let peak = Arc::new(AtomicUsize::new(0));

    let observed = Arc::clone(&peak);
    let watched = dir.path().to_path_buf();
    rotation.on_publish(move |_| {
        let total = usize::try_from(device_bytes(&watched)).unwrap_or(usize::MAX);
        observed.fetch_max(total, Ordering::SeqCst);
    });

    let mut captured_len = 0_u64;
    for round in 0..8_i64 {
        captured_len = append_records(&active, S + W);
        let outcome = rotation.run_pass(at(round * 60)).await;
        assert!(outcome.rotated(), "the model's preceding pass succeeded");

        // Between passes, under the model.
        let between = device_bytes(dir.path());
        let expected_between = S.saturating_mul(u64::from(N) + 1) + W;
        assert!(
            between <= expected_between,
            "round {round}: {between} bytes between passes against an expected {expected_between}"
        );
    }

    let observed_peak = u64::try_from(peak.load(Ordering::SeqCst)).expect("the peak fits");
    let expected_peak = retained_budget_bytes(S, N) + 2 * captured_len;
    assert!(
        observed_peak > 0,
        "the in-pass window was measured at least once"
    );
    assert!(
        observed_peak <= expected_peak,
        "{observed_peak} bytes at the in-pass window against an expected {expected_peak}"
    );
}

/// A long run of failed passes grows the device's total past the
/// envelope — specified behaviour, not a defect — while the retained
/// set stays inside `S × N` throughout.
#[tokio::test]
async fn a_long_run_of_failed_passes_leaves_the_total_unbounded() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let budget = retained_budget_bytes(S, N);

    // A healthy set first, so what follows is measured against a
    // populated retained set rather than an empty one.
    for round in 0..4_i64 {
        append_records(&active, S + 256);
        assert!(rotation.run_pass(at(round * 60)).await.rotated());
    }

    rotation.fail_truncate();
    for round in 4..40_i64 {
        append_records(&active, S);
        let outcome = rotation.run_pass(at(round * 60)).await;
        assert!(
            outcome.rotation.is_unmet(),
            "round {round} should have failed"
        );
        assert!(
            outcome.retained_bytes <= budget,
            "round {round}: the retained set left its ceiling"
        );
    }

    let total = device_bytes(dir.path());
    assert!(
        total > S.saturating_mul(u64::from(N) + 1),
        "a run of failed passes is expected to leave the total past its envelope; got {total}"
    );
    assert!(retained_bytes(dir.path()) <= budget);
}

/// A rotation that publishes and empties, followed by a forced trim
/// failure, counts as unmet rather than completed — and the very next
/// pass repairs the set although no rotation is required by then.
#[tokio::test]
async fn a_rotation_that_could_not_trim_counts_as_unmet() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let budget = retained_budget_bytes(S, N);

    for sequence in 0..5 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    rotation.fail_trim_from(0);
    append_records(&active, S);

    let failed = rotation.run_pass(at(0)).await;
    assert!(failed.rotated(), "the rotation itself completed");
    assert_eq!(len_of(&active), 0, "the active log was emptied");
    assert!(failed.retained_unmet, "the ceiling was left unenforced");
    assert!(!failed.rotation.is_unmet());
    assert_eq!(failed.consecutive_failures, 1);

    rotation.allow_trim();
    assert!(
        len_of(&active) < S,
        "the next pass has no rotation to perform"
    );
    let repaired = rotation.run_pass(at(60)).await;
    assert!(!repaired.rotated(), "no rotation was required");
    assert!(!repaired.retained_unmet);
    assert_eq!(repaired.consecutive_failures, 0);
    assert!(retained_bytes(dir.path()) <= budget);
}

/// A set left over budget by a lowered `N` is trimmed on the next pass,
/// without waiting for a rotation.
#[tokio::test]
async fn a_lowered_bound_is_repaired_without_a_rotation() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    // Under the size trigger, so no rotation is required — but present,
    // because a device directory with generations and no active log at
    // all is a state the daemon refuses to act in.
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S / 4);
    for sequence in 0..6 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S / 2);
    }
    assert_eq!(generation_names(dir.path()).len(), 6);

    let mut lowered = rotation_at(dir.path().to_path_buf(), S, 2);
    let outcome = lowered.run_pass(at(0)).await;
    assert!(!outcome.rotated(), "no active log, so no rotation");
    assert!(!outcome.retained_unmet);
    assert_eq!(outcome.consecutive_failures, 0);
    assert_eq!(generation_names(dir.path()).len(), 2);
    assert!(retained_bytes(dir.path()) <= retained_budget_bytes(S, 2));
}

/// The plain case: an active log driven past `S` becomes a generation
/// and the active log is emptied. No device-level total is asserted.
#[tokio::test]
async fn an_active_log_past_the_bound_is_rotated() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);

    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotated());
    assert_eq!(outcome.consecutive_failures, 0);
    assert_eq!(len_of(&active), 0);

    let names = generation_names(dir.path());
    assert_eq!(names.len(), 1);
    let published = dir.path().join(names.first().expect("one generation"));
    assert_eq!(len_of(&published), captured);
    assert_complete_json_lines(&published);
}

// ---------------------------------------------------------------------
// Rotation mechanics
// ---------------------------------------------------------------------

/// The trailing partial record is destroyed whole rather than carried
/// into the generation, so no record is split across the two files.
#[tokio::test]
async fn a_trailing_partial_record_is_destroyed_rather_than_carried_in() {
    use std::io::Write as _;

    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let complete = append_records(&active, S);
    let fragment = "{\"index\":\"999999\",\"pad\":\"aaa";
    let mut file = OpenOptions::new()
        .append(true)
        .open(&active)
        .expect("the active log opens");
    file.write_all(fragment.as_bytes())
        .expect("the fragment is written");
    file.flush().expect("the fragment flushes");

    assert!(rotation.run_pass(at(0)).await.rotated());
    let names = generation_names(dir.path());
    let published = dir.path().join(names.first().expect("one generation"));
    assert_eq!(
        len_of(&published),
        complete,
        "the generation stops at the last complete record"
    );
    assert_complete_json_lines(&published);
    assert_eq!(len_of(&active), 0, "the fragment went with the truncate");
}

/// The publish order, asserted through what each forced failure leaves
/// behind.
///
/// A staging flush, a publish-directory flush and a truncate that fail
/// each leave the active log byte-for-byte intact and unlink the copy,
/// so no generation ever duplicates records still in the active log. A
/// failure of the active log's *own* flush leaves the generation
/// published and the log empty — which is only reachable if the
/// truncate ran after the directory flush and the flush ran after the
/// truncate.
#[tokio::test]
async fn the_publish_is_ordered_and_each_pre_commit_failure_unlinks_the_copy() {
    for fault in ["staging_sync", "directory_sync", "truncate"] {
        let (dir, mut rotation) = fixture(S, N);
        let active = dir.path().join(ACTIVE_FILE_NAME);
        append_records(&active, S);
        let before = std::fs::read(&active).expect("the active log reads");

        match fault {
            "staging_sync" => rotation.fail_staging_sync(),
            "directory_sync" => rotation.fail_directory_sync(),
            _ => rotation.fail_truncate(),
        }

        let outcome = rotation.run_pass(at(0)).await;
        assert!(
            outcome.rotation.is_unmet(),
            "{fault}: the pass should have failed"
        );
        assert!(!outcome.rotated());
        assert_eq!(
            std::fs::read(&active).expect("the active log reads"),
            before,
            "{fault}: the active log must be untouched"
        );
        assert!(
            generation_names(dir.path()).is_empty(),
            "{fault}: no generation may survive a pre-commit failure"
        );
        assert!(
            !dir.path().join(STAGING_FILE_NAME).exists(),
            "{fault}: the staging copy must be unlinked"
        );
    }

    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    rotation.fail_active_sync();
    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotation.is_unmet());
    assert_eq!(
        generation_names(dir.path()).len(),
        1,
        "the truncate ran after the directory flush"
    );
    assert_eq!(
        len_of(&active),
        0,
        "the active log's flush is attempted after the truncate"
    );
}

/// A staging path replaced between the copy's flush and the publish is
/// refused, and the active log keeps every record.
///
/// The device directory is writable by the container's audit user, so
/// that user can unlink `.audit-rotate.staging` and leave a file of
/// their own at the name. Publishing by that name would hand the
/// replacement to the retained set and then truncate the active log —
/// destroying the records the pass believed it had just copied. The
/// publish therefore checks that the name it created reached the inode
/// it staged.
#[tokio::test]
async fn a_staging_path_replaced_before_the_publish_is_refused() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let before = std::fs::read(&active).expect("the active log reads");

    // Exactly the window the publish has to survive: the copy is
    // staged, flushed and owned, and the name it is about to be
    // published by no longer leads to it.
    rotation.on_stage(move |path| {
        std::fs::remove_file(path).expect("the staging copy is unlinked");
        std::fs::write(path, b"").expect("the impostor is created");
    });

    let outcome = rotation.run_pass(at(0)).await;
    assert!(
        outcome.rotation.is_unmet(),
        "a replaced staging path is a failed pass"
    );
    assert!(!outcome.rotated());
    assert_eq!(
        std::fs::read(&active).expect("the active log reads"),
        before,
        "the active log must keep every record the impostor does not hold"
    );
    assert!(
        generation_names(dir.path()).is_empty(),
        "the impostor must not be published as a generation"
    );
    assert!(
        !dir.path().join(STAGING_FILE_NAME).exists(),
        "the staging name is cleared for the next pass"
    );
}

/// A publish never replaces a name already present, and never removes
/// the generation it collided with.
///
/// `rename` would have overwritten it silently, destroying records the
/// retained set held; `link` refuses. The refusal is a failed pass, and
/// its recovery must leave the colliding file alone — it is not this
/// pass's to unlink.
#[tokio::test]
async fn a_publish_never_overwrites_an_existing_generation() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let before = std::fs::read(&active).expect("the active log reads");

    // The name this pass has already chosen, occupied after it chose
    // it and before it publishes.
    let target = dir
        .path()
        .join(rotated_file_name(&rotation_stamp(at(0)), 0));
    let occupied = target.clone();
    rotation.on_stage(move |_| {
        std::fs::write(&occupied, b"an earlier generation\n").expect("the collision is created");
    });

    let outcome = rotation.run_pass(at(0)).await;
    assert!(
        outcome.rotation.is_unmet(),
        "a name collision is a failed pass, not a silent replacement"
    );
    assert_eq!(
        std::fs::read(&target).expect("the colliding generation reads"),
        b"an earlier generation\n",
        "the generation already at the name must survive untouched"
    );
    assert_eq!(
        std::fs::read(&active).expect("the active log reads"),
        before,
        "the active log must be untouched"
    );
    assert!(
        !dir.path().join(STAGING_FILE_NAME).exists(),
        "the staging copy must be unlinked"
    );
}

/// A generation replaced *after* the publish verified it is refused
/// before the commit point.
///
/// The publish's own check is of an instant, and the directory flush
/// after it is a disk round trip in a directory the container's audit
/// user can write. Unlinking the verified generation and leaving an
/// empty file at the name would otherwise have the truncate destroy
/// records held nowhere else: the staging name is already gone by then,
/// so the copy is reachable only through the descriptor the pass is
/// about to drop.
#[tokio::test]
async fn a_generation_replaced_after_the_publish_is_refused_before_the_truncate() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let before = std::fs::read(&active).expect("the active log reads");

    // The window this closes: past the publish, past the directory
    // flush, and before the truncate.
    rotation.on_publish(move |target| {
        std::fs::remove_file(target).expect("the published generation is unlinked");
        std::fs::write(target, b"").expect("the impostor is created");
    });

    let outcome = rotation.run_pass(at(0)).await;
    assert!(
        outcome.rotation.is_unmet(),
        "a replaced generation is a failed pass"
    );
    assert!(!outcome.rotated());
    assert_eq!(outcome.consecutive_failures, 1, "and it escalates like any");
    assert_eq!(
        std::fs::read(&active).expect("the active log reads"),
        before,
        "the active log must keep every record the impostor does not hold"
    );
    let names = generation_names(dir.path());
    let impostor = names.first().expect("the impostor is left at the name");
    assert_eq!(names.len(), 1, "nothing else was published");
    assert_eq!(
        len_of(&dir.path().join(impostor)),
        0,
        "the impostor is left exactly as it was found: this pass no longer holds a link to that \
         name, and unlinking it would delete a file that is not this pass's"
    );
    assert!(
        !dir.path().join(STAGING_FILE_NAME).exists(),
        "the staging name is cleared for the next pass"
    );
}

/// An active log swapped for *another regular file* between the copy
/// and the truncate is refused, rather than emptied and reported as a
/// rotation.
///
/// `open_active` asks what the descriptor is, and a second regular file
/// answers exactly as the first does. Only the file's identity
/// separates them — so the pass carries the descriptor it copied
/// through to the truncate and compares against it. The test holds the
/// original open for the whole pass, which is what `OpenBao` does: its
/// writes keep landing on the inode the name stopped leading to, so a
/// truncate of the replacement would bound nothing at all.
#[tokio::test]
async fn an_active_log_swapped_for_another_regular_file_is_refused_at_the_truncate() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let writer = OpenOptions::new()
        .append(true)
        .open(&active)
        .expect("OpenBao's own descriptor opens");

    let planted = active.clone();
    rotation.on_publish(move |_| {
        std::fs::remove_file(&planted).expect("the active log is unlinked");
        std::fs::write(&planted, b"a replacement\n").expect("the replacement is created");
    });

    let outcome = rotation.run_pass(at(0)).await;
    assert!(
        outcome.rotation.is_unmet(),
        "a swapped active log is a failed pass, never a completed rotation"
    );
    assert!(!outcome.rotated());
    assert_eq!(outcome.consecutive_failures, 1, "and it escalates like any");
    assert_eq!(
        std::fs::read(&active).expect("the replacement reads"),
        b"a replacement\n",
        "the replacement is left exactly as it was found, never emptied"
    );
    assert_eq!(
        writer.metadata().expect("the held descriptor stats").len(),
        captured,
        "the file OpenBao is still writing to keeps every byte"
    );
    assert!(
        generation_names(dir.path()).is_empty(),
        "the generation was still provisional, so the failure rolls it back"
    );
    assert!(!dir.path().join(STAGING_FILE_NAME).exists());
}

/// A failure past the commit point never rolls the rotation back, and
/// the trim in that same pass still runs.
#[tokio::test]
async fn a_failure_past_the_commit_point_keeps_the_generation_and_still_trims() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let budget = retained_budget_bytes(S, N);

    // Over budget before the pass, so the trim has work of its own.
    for sequence in 0..6 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    let captured = append_records(&active, S);
    rotation.fail_active_sync();

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(outcome.rotation.is_unmet(), "the flush failure is owed");
        assert_eq!(outcome.consecutive_failures, 1);
        assert!(
            !outcome.retained_unmet,
            "the trim in the same pass reached the bound"
        );
    })
    .await;
    assert!(
        logs.contains(&active.display().to_string()),
        "the failure names the path it left the generation at"
    );

    assert_eq!(len_of(&active), 0, "the active log stays empty");
    let names = generation_names(dir.path());
    let newest = dir.path().join(names.last().expect("a newest generation"));
    assert_eq!(
        len_of(&newest),
        captured,
        "the published generation survives with its records intact"
    );
    assert_complete_json_lines(&newest);
    assert!(retained_bytes(dir.path()) <= budget);

    // And the next pass proceeds normally.
    rotation.allow_active_sync();
    append_records(&active, S);
    let next = rotation.run_pass(at(60)).await;
    assert!(next.rotated());
    assert_eq!(next.consecutive_failures, 0);
}

/// A trim is never rolled back: deletions already made stay made, and
/// the next pass resumes from wherever the failed one reached.
#[tokio::test]
async fn a_partial_trim_is_not_rolled_back() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S / 4);
    for sequence in 0..6 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S / 4);
    }
    let mut rotation = rotation_at(dir.path().to_path_buf(), S, 2);
    rotation.fail_trim_from(2);

    let partial = rotation.run_pass(at(0)).await;
    assert!(partial.retained_unmet, "a bound is still unmet");
    assert_eq!(partial.consecutive_failures, 1);
    let after = generation_names(dir.path());
    assert_eq!(after.len(), 4, "the two deletions that succeeded stand");
    assert_eq!(
        after.first().map(String::as_str),
        Some(rotated_file_name("20260301T115900Z", 2).as_str()),
        "the trim resumed from the oldest surviving generation"
    );

    rotation.allow_trim();
    let resumed = rotation.run_pass(at(60)).await;
    assert!(!resumed.retained_unmet);
    assert_eq!(resumed.consecutive_failures, 0);
    assert_eq!(generation_names(dir.path()).len(), 2);
}

/// A captured prefix with no newline at all yields no generation and
/// leaves the active log untouched — while the retained-set bound is
/// still evaluated, so an over-budget set seeded beforehand is trimmed.
#[tokio::test]
async fn a_prefix_with_no_record_boundary_skips_the_rotation_but_still_trims() {
    use std::io::Write as _;

    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    for sequence in 0..6 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(&active)
        .expect("the active log opens");
    let blob = vec![b'x'; usize::try_from(S).expect("the bound fits")];
    file.write_all(&blob).expect("the blob is written");
    file.flush().expect("the blob flushes");
    let before = std::fs::read(&active).expect("the active log reads");

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(
            outcome.rotation.is_unmet(),
            "the rotation was owed and skipped"
        );
        assert!(!outcome.rotated());
        assert!(!outcome.retained_unmet, "the set was still trimmed");
    })
    .await;
    assert!(logs.contains("no complete record"), "the skip is logged");
    assert_eq!(
        std::fs::read(&active).expect("the active log reads"),
        before,
        "the active log is untouched"
    );
    assert!(!dir.path().join(STAGING_FILE_NAME).exists());
    assert!(retained_bytes(dir.path()) <= retained_budget_bytes(S, N));
}

/// Trimming is by bytes as well as by count: a set already within `N`
/// still drops oldest-first until the total is at or under `S × N`.
#[tokio::test]
async fn the_trim_enforces_bytes_and_not_only_the_count() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S / 4);
    // Each half again as large as `S`, which is what a periodic check
    // legitimately produces: two fit the four-generation budget and
    // three do not, although all three fit it by count.
    for sequence in 0..3 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S + S / 2);
    }
    let mut rotation = rotation_at(dir.path().to_path_buf(), S, 4);
    assert_eq!(generation_names(dir.path()).len(), 3, "within N by count");
    assert!(retained_bytes(dir.path()) > retained_budget_bytes(S, 4));

    let outcome = rotation.run_pass(at(0)).await;
    assert!(!outcome.retained_unmet);
    assert!(retained_bytes(dir.path()) <= retained_budget_bytes(S, 4));
    assert!(
        generation_names(dir.path()).len() < 3,
        "the byte bound dropped what the count bound would have kept"
    );
    assert_eq!(
        generation_names(dir.path()).first().map(String::as_str),
        Some(rotated_file_name("20260301T115900Z", 1).as_str()),
        "oldest-first"
    );
}

/// A single generation larger than the whole retained budget is dropped
/// whole and logged with its size and the budget — including when the
/// same pass has just published it.
#[tokio::test]
async fn a_generation_larger_than_the_whole_budget_is_dropped_whole() {
    let budget = retained_budget_bytes(S, 2);

    // Seeded: the oversized generation is already there.
    let dir = tempfile::tempdir().expect("a temporary directory");
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S / 4);
    let seeded = seed_generation(dir.path(), "20260301T115900Z", 0, budget * 3);
    let seeded_len = len_of(&seeded);
    let mut rotation = rotation_at(dir.path().to_path_buf(), S, 2);
    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(!outcome.retained_unmet);
    })
    .await;
    assert!(generation_names(dir.path()).is_empty());
    assert!(logs.contains(&seeded_len.to_string()), "the size is logged");
    assert!(logs.contains(&budget.to_string()), "the budget is logged");

    // Published by this very pass: the usual way the state arises.
    let (fresh, mut rotation) = fixture(S, 2);
    let active = fresh.path().join(ACTIVE_FILE_NAME);
    append_records(&active, budget * 3);
    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(outcome.rotated(), "the rotation itself completed");
        assert!(
            !outcome.retained_unmet,
            "and the ceiling was re-established"
        );
    })
    .await;
    assert!(
        generation_names(fresh.path()).is_empty(),
        "the generation this pass published was dropped whole"
    );
    assert!(logs.contains("exceeds the entire retained budget"));
    assert_eq!(len_of(&active), 0, "and the active log stays emptied");
}

/// Names carry an always-present zero-padded six-digit sequence, are
/// one past the greatest already present rather than the lowest unused
/// one, and sort lexicographically in creation order.
#[tokio::test]
async fn generations_are_named_and_ordered_by_an_always_present_sequence() {
    let (dir, mut rotation) = fixture(S, 16);
    let active = dir.path().join(ACTIVE_FILE_NAME);

    append_records(&active, S);
    assert!(rotation.run_pass(at(0)).await.rotated());
    append_records(&active, S);
    assert!(rotation.run_pass(at(0)).await.rotated());
    assert_eq!(
        generation_names(dir.path()),
        vec![
            rotated_file_name("20260301T120000Z", 0),
            rotated_file_name("20260301T120000Z", 1),
        ],
        "two rotations in one second take -000000 and -000001"
    );

    // A trimmed-away gap is never reused: the next name is one past the
    // greatest present, not the lowest unused.
    std::fs::remove_file(dir.path().join(rotated_file_name("20260301T120000Z", 0)))
        .expect("the oldest generation is removed");
    append_records(&active, S);
    assert!(rotation.run_pass(at(0)).await.rotated());
    assert_eq!(
        generation_names(dir.path()),
        vec![
            rotated_file_name("20260301T120000Z", 1),
            rotated_file_name("20260301T120000Z", 2),
        ]
    );

    // And across a second boundary the sort is still creation order.
    append_records(&active, S);
    assert!(rotation.run_pass(at(1)).await.rotated());
    let names = generation_names(dir.path());
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);
    assert_eq!(
        names.last().map(String::as_str),
        Some(rotated_file_name("20260301T120001Z", 0).as_str())
    );

    assert!(
        active.exists() && parse_rotated_name(ACTIVE_FILE_NAME).is_none(),
        "the active log keeps its name and never matches the generation glob"
    );
}

/// A clock stepped backwards cannot reorder the set: the stamp is
/// floored at the newest existing generation's, so the published name
/// is strictly greater than every name already present.
#[tokio::test]
async fn a_clock_stepped_backwards_cannot_reorder_the_set() {
    let (dir, mut rotation) = fixture(S, 8);
    let active = dir.path().join(ACTIVE_FILE_NAME);

    append_records(&active, S);
    assert!(rotation.run_pass(at(0)).await.rotated());
    let first = generation_names(dir.path());
    let earliest = first.first().cloned().expect("a first generation");

    // An hour backwards, which is what an NTP step or a manual
    // correction produces.
    append_records(&active, S);
    assert!(rotation.run_pass(at(-3600)).await.rotated());
    let names = generation_names(dir.path());
    let newest = names.last().cloned().expect("a newest generation");
    assert!(
        newest > earliest,
        "{newest} must sort after {earliest} whatever the clock did"
    );
    assert_eq!(newest, rotated_file_name("20260301T120000Z", 1));

    // A trim now drops the genuinely oldest rather than the one just
    // written, although the clock says the newest is the older of the
    // two.
    append_records(&active, S);
    assert!(rotation.run_pass(at(-3600)).await.rotated());
    let published = generation_names(dir.path());
    let mut tightened = rotation_at(dir.path().to_path_buf(), S, 2);
    assert!(!tightened.run_pass(at(-3600)).await.retained_unmet);
    let after = generation_names(dir.path());
    assert!(after.len() < published.len(), "the trim dropped something");
    assert!(
        !after.contains(&earliest),
        "the genuinely oldest generation is the one that went"
    );
    assert_eq!(
        after.last(),
        published.last(),
        "and the generation written under the rolled-back clock survived"
    );

    // With the floored stamp's namespace exhausted the rotation is
    // skipped rather than published out of order.
    let exhausted = tempfile::tempdir().expect("a temporary directory");
    seed_generation(exhausted.path(), "20260301T120500Z", MAX_SEQUENCE, 32);
    let mut rotation = rotation_at(exhausted.path().to_path_buf(), S, 4);
    let active = exhausted.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let before = std::fs::read(&active).expect("the active log reads");
    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(-3600)).await;
        assert!(outcome.rotation.is_unmet());
        assert!(!outcome.rotated());
    })
    .await;
    assert!(logs.contains("collision sequence"), "the skip is logged");
    assert_eq!(generation_names(exhausted.path()).len(), 1);
    assert_eq!(
        std::fs::read(&active).expect("the active log reads"),
        before
    );
}

/// The size ceiling wins over the retention age: a generation written
/// this instant is dropped when the budget says so.
///
/// The rotation is not even given `openbao_audit_min_retain_days` — it
/// is a declared target the trim never consults — and this pins that,
/// so nobody later adds an age guard that would break the ceiling.
#[tokio::test]
async fn the_ceiling_wins_over_the_retention_age() {
    let (dir, mut rotation) = fixture(S, 2);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let mut published = Vec::new();
    for round in 0..3_i64 {
        append_records(&active, S);
        assert!(rotation.run_pass(at(round)).await.rotated());
        published = generation_names(dir.path());
    }
    let names = generation_names(dir.path());
    assert!(
        names.len() < 3,
        "generations seconds old were still dropped for the ceiling"
    );
    assert_eq!(
        names.last(),
        published.last(),
        "oldest-first, whatever the retention target would have said"
    );
    assert!(retained_bytes(dir.path()) <= retained_budget_bytes(S, 2));
}

/// Staging copies and generations carry mode `0600` and the device
/// directory's uid and gid, both applied before the publish; the active
/// log's own owner and mode survive a rotation unchanged.
#[tokio::test]
async fn staging_copies_and_generations_carry_the_directory_owner_at_mode_0600() {
    use std::os::unix::fs::MetadataExt as _;

    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let active_before = std::fs::metadata(&active).expect("the active log stats");

    let owner = std::fs::metadata(dir.path()).expect("the directory stats");
    let staged = Arc::new(Mutex::new(None));
    let recorder = Arc::clone(&staged);
    rotation.on_stage(move |path| {
        let meta = std::fs::metadata(path).expect("the staging copy stats");
        *recorder.lock().expect("the record lock is live") =
            Some((meta.permissions().mode() & 0o7777, meta.uid(), meta.gid()));
    });

    assert!(rotation.run_pass(at(0)).await.rotated());

    let observed = staged
        .lock()
        .expect("the record lock is live")
        .take()
        .expect("the staging copy was observed before the publish");
    assert_eq!(
        observed,
        (GENERATION_FILE_MODE, owner.uid(), owner.gid()),
        "the staging copy already carries its final mode and owner"
    );

    let names = generation_names(dir.path());
    let published = dir.path().join(names.first().expect("one generation"));
    let meta = std::fs::metadata(&published).expect("the generation stats");
    assert_eq!(meta.permissions().mode() & 0o7777, GENERATION_FILE_MODE);
    assert_eq!((meta.uid(), meta.gid()), (owner.uid(), owner.gid()));

    let active_after = std::fs::metadata(&active).expect("the active log stats");
    assert_eq!(
        active_after.permissions().mode(),
        active_before.permissions().mode(),
        "truncating in place leaves the active log's mode alone"
    );
    assert_eq!(
        (active_after.uid(), active_after.gid()),
        (active_before.uid(), active_before.gid())
    );
    assert_eq!(
        active_after.ino(),
        active_before.ino(),
        "no replacement of the active log was ever created"
    );
}

/// An active log that is a symbolic link is refused rather than
/// followed.
///
/// The device directory is writable by the container's audit user and a
/// pass runs as root, so a link planted at `audit.log` would otherwise
/// have root copy an arbitrary readable file into a generation it then
/// hands to that user, and truncate the file the link named. `OpenBao`
/// writes a regular file there; a link is tampering, and the pass fails
/// loudly instead of acting on it.
///
/// The link's target is what decides whether the `O_NOFOLLOW` opens are
/// ever reached, so the refusal has to come before the size trigger and
/// not from those opens: a target at or over `S` is only one of three
/// cases, and the other two — a target below `S`, and a link pointing
/// at nothing — would otherwise read as a healthy quiet host and as an
/// unprovisioned one.
#[tokio::test]
async fn an_active_log_replaced_by_a_symlink_is_refused_rather_than_followed() {
    let elsewhere = tempfile::tempdir().expect("a temporary directory");

    // A target at or over `S`, which is the case that would reach the
    // copy and the truncate.
    let (dir, mut rotation) = fixture(S, N);
    let target = elsewhere.path().join("not-the-audit-log");
    let target_len = append_records(&target, S);

    std::os::unix::fs::symlink(&target, dir.path().join(ACTIVE_FILE_NAME))
        .expect("the link is planted");

    let outcome = rotation.run_pass(at(0)).await;
    assert!(
        outcome.rotation.is_unmet(),
        "following the link is a pass this must not complete"
    );
    assert!(!outcome.rotated());
    assert!(
        generation_names(dir.path()).is_empty(),
        "no generation may carry the linked file's bytes"
    );
    assert!(!dir.path().join(STAGING_FILE_NAME).exists());
    assert_eq!(
        len_of(&target),
        target_len,
        "the file the link named is not truncated"
    );

    // A target below `S`. Resolving the link here would measure the
    // target, decide no rotation was required and return, so the pass
    // would report a healthy host and never open the path at all.
    let (dir, mut rotation) = fixture(S, N);
    let small = elsewhere.path().join("small");
    let small_len = append_records(&small, 1);
    assert!(small_len < S, "the target is under the size trigger");
    std::os::unix::fs::symlink(&small, dir.path().join(ACTIVE_FILE_NAME))
        .expect("the link is planted");

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(
            outcome.rotation.is_unmet(),
            "a link under the size trigger is still tampering"
        );
        assert_eq!(
            outcome.consecutive_failures, 1,
            "it escalates like any other"
        );
        assert_eq!(
            outcome.active_bytes, 0,
            "the linked file's size is not the device's footprint"
        );
    })
    .await;
    assert!(logs.contains("not a regular file"), "{logs}");
    assert_eq!(len_of(&small), small_len, "the target is left alone");

    // A link pointing at nothing, which resolving would report as an
    // absent active log — the unprovisioned host's no-op.
    let (dir, mut rotation) = fixture(S, N);
    std::os::unix::fs::symlink(
        elsewhere.path().join("never-created"),
        dir.path().join(ACTIVE_FILE_NAME),
    )
    .expect("the link is planted");

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(
            outcome.rotation.is_unmet(),
            "a broken link is tampering, not an unprovisioned host"
        );
        assert_eq!(outcome.consecutive_failures, 1);
    })
    .await;
    assert!(logs.contains("not a regular file"), "{logs}");
    assert!(
        !logs.contains("no active log"),
        "a planted link must not read as a missing log:\n{logs}"
    );
}

/// An active log replaced *after* the size decision was taken on it is
/// refused at the descriptor, and neither open waits on it.
///
/// The size decision reads a name, and the device directory is writable
/// by the container's audit user, so between that read and each open the
/// name can come to mean something else. A FIFO is the case that makes
/// the window matter rather than merely be untidy: `O_NOFOLLOW` refuses
/// a symbolic link and says nothing whatever about a FIFO, and a
/// blocking open of one waits for the other end — for the copy's read
/// side, until a writer arrives, which is never. That open runs inside
/// `spawn_blocking`, so a thread parked in it takes the whole rotation
/// task with it: no retry on the next tick, no increment, no
/// escalation, and no notice of shutdown — the one failure mode this
/// module's loud-when-unmet contract cannot survive, because it is the
/// absence of any pass at all.
///
/// Each pass therefore runs on a thread of its own here and the test
/// fails if it does not come back, rather than hanging the suite.
#[tokio::test]
async fn an_active_log_replaced_after_the_size_check_is_refused_at_each_open() {
    // Between the size decision and the copy's open. The pass has
    // already decided to rotate, so this is the read side, which is the
    // one that would wait rather than fail.
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let planted = active.clone();
    rotation.before_stage(move |path| {
        assert_eq!(path, planted, "the hook is handed the active log");
        plant_fifo(path);
    });

    let outcome = returns_within("the copy's open", rotation.run_pass(at(0))).await;
    assert!(
        outcome.rotation.is_unmet(),
        "a replaced active log is a failed pass"
    );
    assert_eq!(outcome.consecutive_failures, 1, "and it escalates like any");
    assert!(
        generation_names(dir.path()).is_empty(),
        "nothing may be published from a file that is not the device's log"
    );
    assert!(
        !dir.path().join(STAGING_FILE_NAME).exists(),
        "the abandoned copy is unlinked"
    );

    // Between the publish and the truncate: the write side, which
    // `O_NOFOLLOW` alone would have root open on the FIFO and wait for
    // a reader on. It is still before the commit point, so the pass's
    // ordinary pre-commit recovery applies and takes the provisional
    // generation with it.
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let planted = active.clone();
    rotation.on_publish(move |_| plant_fifo(&planted));

    let outcome = returns_within("the truncate's open", rotation.run_pass(at(0))).await;
    assert!(
        outcome.rotation.is_unmet(),
        "a replaced active log is a failed pass here too"
    );
    assert!(
        generation_names(dir.path()).is_empty(),
        "the generation was still provisional, so the failure rolls it back"
    );
    assert!(!dir.path().join(STAGING_FILE_NAME).exists());
    assert!(
        std::fs::symlink_metadata(&active)
            .expect("the planted FIFO stats")
            .file_type()
            .is_fifo(),
        "the planted FIFO is left exactly as it was found, never opened or emptied"
    );
}

/// Replaces whatever is at `path` with a FIFO owned by this test.
///
/// `libc::mkfifo` because `std` has no `mkfifo`, and a FIFO is the
/// specific thing the case is about: it is creatable by any user with
/// write access to the directory, needs no privilege, and is what an
/// `O_NOFOLLOW` open will happily wait on forever.
fn plant_fifo(path: &Path) {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => panic!("the active log is removed: {err}"),
    }
    let raw = CString::new(path.as_os_str().as_bytes()).expect("a temporary path holds no NUL");
    // SAFETY: `mkfifo` reads the NUL-terminated path it is given and
    // writes nothing back through it. `raw` owns that buffer and
    // outlives the call, and the mode is a plain integer.
    let rc = unsafe { libc::mkfifo(raw.as_ptr(), 0o600) };
    assert_eq!(
        rc,
        0,
        "the FIFO is created: {}",
        std::io::Error::last_os_error()
    );
}

/// How long a pass gets to come back before the test calls it parked.
///
/// Far past what a pass over a few kilobytes takes, and finite, which is
/// the whole point: the failure this guards against is unbounded, so
/// only a deadline can distinguish it from slow.
const HANG_DEADLINE: Duration = Duration::from_secs(30);

/// Awaits `body` and returns what it produced, or fails the test naming
/// `label` when it did not return in time.
///
/// A pass parks on a blocking thread rather than on the reactor, so the
/// deadline still fires while the parked one never comes back — which
/// is exactly the distinction being drawn.
async fn returns_within<R>(label: &str, body: impl Future<Output = R>) -> R {
    tokio::time::timeout(HANG_DEADLINE, body)
        .await
        .unwrap_or_else(|_| {
            panic!(
                "{label} never returned: it is parked on the planted FIFO, and the rotation task \
                 it runs inside would tick, retry and escalate never again"
            )
        })
}

/// Generations sit in the device's own directory beside the active log,
/// and a pass creates no directory at all.
#[tokio::test]
async fn a_pass_creates_no_directory_and_publishes_beside_the_active_log() {
    let (dir, mut rotation) = fixture(S, N);
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S);
    assert!(rotation.run_pass(at(0)).await.rotated());

    let directories: Vec<_> = std::fs::read_dir(dir.path())
        .expect("the device directory lists")
        .filter_map(std::result::Result::ok)
        .filter(|entry| entry.path().is_dir())
        .collect();
    assert!(directories.is_empty(), "a pass creates no directory");
    for name in generation_names(dir.path()) {
        assert!(dir.path().join(name).is_file());
    }
}

// ---------------------------------------------------------------------
// Failure handling
// ---------------------------------------------------------------------

/// A run of consecutive failures warns per increment and escalates at
/// the threshold and each further multiple, never every tick, and is
/// reset by the first completed pass.
#[tokio::test]
async fn consecutive_failures_warn_per_pass_and_escalate_at_each_multiple() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    rotation.fail_truncate();

    // Appended once rather than per round: the run of failures is what
    // this test is about, and a log that grew past the whole retained
    // budget would bring the pathological-generation warning with it.
    append_records(&active, S);
    let logs = logs_from(async {
        for round in 0..12_i64 {
            let outcome = rotation.run_pass(at(round * 60)).await;
            assert!(outcome.rotation.is_unmet());
        }
    })
    .await;
    assert_eq!(
        count_lines_at(&logs, "ERROR"),
        2,
        "an error at the threshold and at twice it, and nowhere else:\n{logs}"
    );
    assert!(
        count_lines_at(&logs, "WARN") >= 12,
        "one warn per increment at least"
    );
    assert!(logs.contains("rotation"), "the unmet obligation is named");
    assert!(
        logs.contains("active_log_bytes"),
        "the active log's size is in the escalation"
    );
    assert!(
        logs.contains("retained_set_bytes"),
        "the retained set's total is in the escalation"
    );

    rotation.allow_truncate();
    let recovered = logs_from(async {
        let outcome = rotation.run_pass(at(12 * 60)).await;
        assert!(outcome.rotated());
        assert_eq!(outcome.consecutive_failures, 0);
    })
    .await;
    assert_eq!(count_lines_at(&recovered, "ERROR"), 0, "{recovered}");
    assert_eq!(count_lines_at(&recovered, "WARN"), 0, "{recovered}");
}

/// A pass with no unmet obligation of either kind neither increments
/// nor escalates, on a quiet host and on one where the gate is on but
/// nothing was ever provisioned — and the same hosts seeded over budget
/// are repaired and reset, or escalate when the trim is forced to fail.
#[tokio::test]
async fn a_pass_with_nothing_owed_never_increments_or_escalates() {
    let ticks = i64::from(FAILURE_ESCALATION_THRESHOLD) * 4;

    // A quiet host: an active log that never reaches S.
    let (quiet, mut rotation) = fixture(S, N);
    append_records(&quiet.path().join(ACTIVE_FILE_NAME), S / 4);
    let logs = logs_from(async {
        for round in 0..ticks {
            let outcome = rotation.run_pass(at(round * 60)).await;
            assert!(outcome.evaluated);
            assert_eq!(outcome.consecutive_failures, 0);
        }
    })
    .await;
    assert_eq!(count_lines_at(&logs, "WARN"), 0, "{logs}");
    assert_eq!(count_lines_at(&logs, "ERROR"), 0, "{logs}");

    // A host where the gate is on and nothing backs it.
    let (bare, mut rotation) = fixture(S, N);
    let logs = logs_from(async {
        for round in 0..ticks {
            let outcome = rotation.run_pass(at(round * 60)).await;
            assert!(outcome.evaluated, "the directory is there");
            assert_eq!(outcome.consecutive_failures, 0);
        }
    })
    .await;
    assert_eq!(count_lines_at(&logs, "WARN"), 0, "{logs}");
    assert_eq!(count_lines_at(&logs, "ERROR"), 0, "{logs}");
    drop(bare);

    // The same quiet host with an over-budget set: trimmed back inside
    // and reset, with no rotation ever required.
    for sequence in 0..8 {
        seed_generation(quiet.path(), "20260301T115900Z", sequence, S);
    }
    let mut rotation = rotation_at(quiet.path().to_path_buf(), S, N);
    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(!outcome.rotated());
        assert!(!outcome.retained_unmet);
        assert_eq!(outcome.consecutive_failures, 0);
    })
    .await;
    assert_eq!(count_lines_at(&logs, "WARN"), 0, "{logs}");

    // And with the trim forced to fail it increments and escalates,
    // although no rotation was ever required.
    for sequence in 8..16 {
        seed_generation(quiet.path(), "20260301T115900Z", sequence, S);
    }
    let mut rotation = rotation_at(quiet.path().to_path_buf(), S, N);
    rotation.fail_trim_from(0);
    let logs = logs_from(async {
        for round in 0..i64::from(FAILURE_ESCALATION_THRESHOLD) {
            let outcome = rotation.run_pass(at(round * 60)).await;
            assert!(!outcome.rotated(), "no rotation was ever required");
            assert!(outcome.retained_unmet);
        }
    })
    .await;
    assert_eq!(count_lines_at(&logs, "ERROR"), 1, "{logs}");
    assert!(logs.contains("retained-set bound"));
}

/// A missing active log is a no-op, said once rather than once a tick,
/// and an absent device directory leaves the pass with nothing
/// evaluated at all.
#[tokio::test]
async fn a_missing_active_log_is_a_no_op_and_an_absent_directory_evaluates_nothing() {
    let (dir, mut rotation) = fixture(S, N);
    let logs = logs_from(async {
        for round in 0..20_i64 {
            let outcome = rotation.run_pass(at(round * 60)).await;
            assert!(outcome.evaluated);
            assert!(!outcome.rotation.is_unmet());
            assert_eq!(outcome.active_bytes, 0);
        }
    })
    .await;
    assert_eq!(
        logs.matches("no active log").count(),
        1,
        "said once per process, never once per tick:\n{logs}"
    );
    assert_eq!(count_lines_at(&logs, "WARN"), 0);

    // Seed an over-budget set beside it and the pass still refuses to
    // act, because with the active path absent any of those files may
    // be the inode OpenBao is writing to. Nothing is trimmed and one
    // `error` names the state.
    for sequence in 0..8 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    let seeded = generation_names(dir.path());
    let refused = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(outcome.rotation.is_unmet());
        assert!(outcome.retained_unmet, "nothing was established");
    })
    .await;
    assert_eq!(count_lines_at(&refused, "ERROR"), 1, "{refused}");
    assert!(refused.contains("no rotation-intent marker"), "{refused}");
    assert_eq!(
        generation_names(dir.path()),
        seeded,
        "a pass that cannot establish which file is live trims nothing"
    );

    // Give it an active log again and the ordinary trim resumes.
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S / 4);
    let outcome = rotation.run_pass(at(60)).await;
    assert!(!outcome.retained_unmet);
    assert!(retained_bytes(dir.path()) <= retained_budget_bytes(S, N));

    // An absent directory evaluates nothing.
    let absent = tempfile::tempdir().expect("a temporary directory");
    let missing = absent.path().join("openbao");
    let mut rotation = rotation_at(missing, S, N);
    let logs = logs_from(async {
        for round in 0..20_i64 {
            let outcome = rotation.run_pass(at(round * 60)).await;
            assert!(!outcome.evaluated);
            assert_eq!(outcome.consecutive_failures, 0);
        }
    })
    .await;
    assert_eq!(logs.matches("directory is absent").count(), 1, "{logs}");
    assert_eq!(count_lines_at(&logs, "WARN"), 0);
    assert_eq!(count_lines_at(&logs, "ERROR"), 0);
}

/// A device directory that is present but is not usable as one is a
/// failed pass, never the unprovisioned host's no-op.
///
/// Only `NotFound` says the host was never provisioned. Everything else
/// — a regular file where the directory should be, a path whose parent
/// is not a directory, an unreadable one — leaves the retained set
/// unassertable, which is an unmet obligation in its own right. Reading
/// those as "absent" would take the no-op path, reset the counter, and
/// disable the rotation and the escalation that reports it together.
///
/// The pass stops at the directory rather than going on to fail one
/// step at a time inside it: nothing is copied, published, truncated or
/// deleted through a path that is not the directory this rotation was
/// given.
#[tokio::test]
async fn a_device_directory_that_is_not_a_directory_is_a_failed_pass() {
    let parent = tempfile::tempdir().expect("a temporary directory");

    // A regular file where the device directory should be.
    let as_file = parent.path().join("openbao");
    append_records(&as_file, 1);
    let mut rotation = rotation_at(as_file, S, N);
    let logs = logs_from(async {
        for round in 0..FAILURE_ESCALATION_THRESHOLD {
            let outcome = rotation.run_pass(at(i64::from(round) * 60)).await;
            assert!(outcome.evaluated, "a fault is not nothing to evaluate");
            assert!(
                outcome.retained_unmet,
                "a set that cannot be listed cannot be asserted to be inside its bound"
            );
            assert_eq!(outcome.consecutive_failures, round + 1);
        }
    })
    .await;
    assert!(
        !logs.contains("directory is absent"),
        "a directory that is present is not absent:\n{logs}"
    );
    assert_eq!(
        count_lines_at(&logs, "ERROR"),
        1,
        "the run escalates like any other:\n{logs}"
    );

    // And a device directory under a path that is not a directory,
    // which errors with something other than `NotFound` at every step.
    let beneath = parent.path().join("openbao").join("audit");
    let mut rotation = rotation_at(beneath, S, N);
    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(outcome.evaluated);
        assert!(outcome.retained_unmet);
        assert_eq!(outcome.consecutive_failures, 1);
    })
    .await;
    assert!(!logs.contains("directory is absent"), "{logs}");
    assert!(count_lines_at(&logs, "WARN") > 0, "{logs}");
}

/// A device directory that is a symbolic link is refused rather than
/// followed, whether or not it resolves.
///
/// The link is the *first* component of every path a pass builds, so
/// the `O_NOFOLLOW` opens below cannot refuse it: they refuse a link at
/// `audit.log`, not one at the directory holding it. A resolving read
/// would therefore have a pass copy, publish, truncate and delete
/// inside whatever directory the link named — and a dangling link would
/// read as `NotFound`, which is the one state that is silent, resets
/// the counter and disables the escalation with it.
#[tokio::test]
async fn a_symlinked_device_directory_is_refused_rather_than_followed() {
    let parent = tempfile::tempdir().expect("a temporary directory");

    // A link resolving to a real directory, populated so that a
    // followed pass would have plenty to do in it: an active log past
    // the size trigger and a set well past both retained bounds.
    let elsewhere = tempfile::tempdir().expect("a temporary directory");
    let active = elsewhere.path().join(ACTIVE_FILE_NAME);
    let active_len = append_records(&active, S);
    for sequence in 0..8 {
        seed_generation(elsewhere.path(), "20260301T115900Z", sequence, S);
    }
    let seeded = generation_names(elsewhere.path());

    let linked = parent.path().join("openbao");
    std::os::unix::fs::symlink(elsewhere.path(), &linked).expect("the link is planted");
    let mut rotation = rotation_at(linked, S, N);

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(
            outcome.evaluated,
            "a planted link is not nothing to evaluate"
        );
        assert!(outcome.rotation.is_unmet());
        assert!(outcome.retained_unmet);
        assert_eq!(outcome.consecutive_failures, 1);
        assert_eq!(
            outcome.active_bytes, 0,
            "nothing behind the link is the device's footprint"
        );
    })
    .await;
    assert!(logs.contains("not a directory"), "{logs}");
    assert_eq!(
        len_of(&active),
        active_len,
        "the log behind the link is not rotated"
    );
    assert_eq!(
        generation_names(elsewhere.path()),
        seeded,
        "nothing behind the link is published or trimmed"
    );
    assert!(!elsewhere.path().join(STAGING_FILE_NAME).exists());

    // A link pointing at nothing, which a resolving read reports as an
    // absent directory: the unprovisioned host's silent no-op.
    let dangling = parent.path().join("dangling");
    std::os::unix::fs::symlink(parent.path().join("never-created"), &dangling)
        .expect("the link is planted");
    let mut rotation = rotation_at(dangling, S, N);

    let logs = logs_from(async {
        for round in 0..FAILURE_ESCALATION_THRESHOLD {
            let outcome = rotation.run_pass(at(i64::from(round) * 60)).await;
            assert!(
                outcome.evaluated,
                "a broken link is tampering, not an unprovisioned host"
            );
            assert!(outcome.retained_unmet);
            assert_eq!(outcome.consecutive_failures, round + 1);
        }
    })
    .await;
    assert!(
        !logs.contains("directory is absent"),
        "a link that resolves to nothing is still a link:\n{logs}"
    );
    assert_eq!(
        count_lines_at(&logs, "ERROR"),
        1,
        "it escalates like any other run of failed passes:\n{logs}"
    );
}

/// A trim whose directory flush failed keeps the pass unmet, retries
/// the flush on every later pass, and only then reports the bound met.
///
/// The deletions are visible to the next listing as soon as they
/// return, so a discarded flush failure would have the very next
/// evaluation find a set inside its bound and reset the counter — while
/// a crash could still restore the whole over-budget set from disk. The
/// retry has to happen on a pass that deleted nothing too, since a host
/// quiet enough never to trim again would otherwise carry the debt for
/// as long as it stays quiet.
#[tokio::test]
async fn a_trim_whose_flush_failed_stays_unmet_until_a_later_flush_succeeds() {
    let (dir, mut rotation) = fixture(S, N);
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S / 4);
    for sequence in 0..8 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    rotation.fail_trim_sync();

    let mut trimmed = Vec::new();
    let logs = logs_from(async {
        for round in 0..FAILURE_ESCALATION_THRESHOLD {
            let outcome = rotation.run_pass(at(i64::from(round) * 60)).await;
            assert!(
                outcome.trim_flush_pending,
                "round {round}: the deletions are still only in the page cache"
            );
            assert!(
                outcome.retained_unmet,
                "round {round}: a bound held only in the page cache is not established"
            );
            assert_eq!(outcome.consecutive_failures, round + 1);
            if round == 0 {
                trimmed = generation_names(dir.path());
            }
        }
    })
    .await;
    assert!(logs.contains("not durable"), "{logs}");
    assert_eq!(
        count_lines_at(&logs, "ERROR"),
        1,
        "an unflushed trim escalates like any other unmet obligation:\n{logs}"
    );
    // The deletions themselves all went through on the first pass, so
    // every later one had nothing to delete and re-attempted the flush
    // anyway — which is the quiet host the debt would otherwise be
    // stranded on.
    assert!(trimmed.len() <= usize::try_from(N).unwrap());
    assert_eq!(generation_names(dir.path()), trimmed);
    assert!(retained_bytes(dir.path()) <= retained_budget_bytes(S, N));

    rotation.allow_trim_sync();
    let repaired = rotation
        .run_pass(at(i64::from(FAILURE_ESCALATION_THRESHOLD) * 60))
        .await;
    assert!(
        !repaired.trim_flush_pending,
        "a flush that succeeded clears the debt"
    );
    assert!(!repaired.retained_unmet);
    assert_eq!(repaired.consecutive_failures, 0);
}

/// The directory-flush debt outlives the task that incurred it.
///
/// The debt is in memory, and a daemon that reloads, restarts or is
/// killed loses it while the deletions it covers stay exactly as
/// unflushed as they were. A task that started clean would list those
/// generations as absent, find the set inside both bounds, reset the
/// counter and never flush — leaving on disk precisely the over-budget
/// set a crash restores, with nothing left anywhere that remembers it.
/// So a fresh instance starts owing a flush rather than assuming one.
#[tokio::test]
async fn the_trim_flush_debt_is_owed_again_by_a_new_rotation_instance() {
    let (dir, mut rotation) = fixture(S, N);
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S / 4);
    for sequence in 0..8 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    rotation.fail_trim_sync();
    let first = rotation.run_pass(at(0)).await;
    assert!(first.trim_flush_pending);
    assert!(first.retained_unmet);
    let trimmed = generation_names(dir.path());
    assert!(trimmed.len() <= usize::try_from(N).unwrap());
    // The daemon goes away with the debt still outstanding.
    drop(rotation);

    // What the new task can see is a set already inside both bounds,
    // which nothing it did put there and no listing can tell apart
    // from one whose deletions reached the disk.
    let mut restarted = rotation_at(dir.path().to_path_buf(), S, N);
    restarted.fail_trim_sync();
    let logs = logs_from(async {
        for round in 0..FAILURE_ESCALATION_THRESHOLD {
            let outcome = restarted.run_pass(at(i64::from(round + 1) * 60)).await;
            assert!(
                outcome.trim_flush_pending,
                "round {round}: a new task owes the flush it cannot prove happened"
            );
            assert!(
                outcome.retained_unmet,
                "round {round}: a bound a crash can undo is not established"
            );
            assert_eq!(
                outcome.consecutive_failures,
                round + 1,
                "round {round}: the counter is not reset by a bound held only in the page cache"
            );
        }
    })
    .await;
    assert!(logs.contains("not durable"), "{logs}");
    assert_eq!(
        count_lines_at(&logs, "ERROR"),
        1,
        "an inherited unflushed trim escalates like any other unmet obligation:\n{logs}"
    );
    assert_eq!(
        generation_names(dir.path()),
        trimmed,
        "the restarted task has nothing left to delete; the flush is all it owes"
    );

    restarted.allow_trim_sync();
    let repaired = restarted
        .run_pass(at(i64::from(FAILURE_ESCALATION_THRESHOLD + 1) * 60))
        .await;
    assert!(
        !repaired.trim_flush_pending,
        "a flush that succeeded discharges the inherited debt"
    );
    assert!(!repaired.retained_unmet);
    assert_eq!(repaired.consecutive_failures, 0);
}

/// The runtime budget helper is total, and the expression validation
/// refuses an overflow of is the one that can overflow.
#[tokio::test]
async fn the_budget_arithmetic_is_total_at_runtime_and_checked_at_validation() {
    // The largest configuration validation admits: `S × (N + 1)` still
    // fits, so `S × N` does a fortiori.
    let n = 7_u32;
    let s = u64::MAX / u64::from(n + 1);
    assert!(checked_family_bytes(s, n).is_some());
    assert_eq!(retained_budget_bytes(s, n), s * u64::from(n));

    // Deliberately overflowing inputs return rather than panicking.
    assert_eq!(retained_budget_bytes(u64::MAX, u32::MAX), u64::MAX);
    assert_eq!(retained_budget_bytes(u64::MAX, 2), u64::MAX);
    assert_eq!(retained_budget_bytes(0, u32::MAX), 0);

    // And validation refuses exactly those.
    assert!(checked_family_bytes(u64::MAX, u32::MAX).is_none());
    assert!(checked_family_bytes(u64::MAX, 1).is_none());
    assert!(checked_family_bytes(u64::MAX, 0).is_some());
}

/// The task retries after an injected failure, through an injected
/// interval so the test does not wait a minute for a tick, and returns
/// cleanly when the daemon asks it to stop.
#[tokio::test]
async fn the_task_retries_a_failed_pass_on_the_next_tick() {
    let (dir, rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S * 8);
    let before = std::fs::read(&active).expect("the active log reads");

    rotation.fail_truncate();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    rotation.on_publish(move |_| {
        let _ = tx.send(());
    });
    let passes = rotation.passes();
    let maintenance_ticks = Arc::new(AtomicUsize::new(0));
    let observed_ticks = Arc::clone(&maintenance_ticks);

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(run_rotation_loop_with_maintenance(
        rotation,
        Duration::from_millis(2),
        shutdown_rx,
        move || {
            observed_ticks.fetch_add(1, Ordering::SeqCst);
            std::future::ready(())
        },
    ));

    // Awaited rather than slept on: each message is one pass reaching
    // the window just before the truncate it is about to fail.
    for _ in 0..3 {
        rx.recv().await.expect("a pass reached the commit window");
    }

    shutdown_tx.send(true).expect("the stop signal is sent");
    handle
        .await
        .expect("the task joins")
        .expect("a failed pass never fails the task");

    assert!(passes.load(Ordering::SeqCst) >= 3, "the pass was retried");
    assert!(
        maintenance_ticks.load(Ordering::SeqCst) >= 3,
        "maintenance runs on every completed rotation tick"
    );
    assert_eq!(
        std::fs::read(&active).expect("the active log reads"),
        before,
        "every failed pass left the active log intact"
    );
    assert!(
        generation_names(dir.path()).is_empty(),
        "every failed pass recovered its copy"
    );
}

// ---------------------------------------------------------------------
// Against a running deployment
// ---------------------------------------------------------------------

/// The device directory this run rotates, on the host.
const E2E_DIR: &str = "BOOTROOT_OPENBAO_AUDIT_E2E_DIR";
/// The deployment's `OpenBao` URL.
const E2E_URL: &str = "BOOTROOT_OPENBAO_AUDIT_E2E_URL";
/// The file holding a token that may read `sys/audit`.
///
/// A path rather than the token itself: this test is run under `sudo`,
/// and an environment assignment on a `sudo` command line is an
/// argument, which `ps` shows to every user on the host for as long as
/// the test runs. The harness writes the file `0600` and root-owned.
const E2E_TOKEN_FILE: &str = "BOOTROOT_OPENBAO_AUDIT_E2E_TOKEN_FILE";
/// The PEM bundle the listener's certificate is anchored to.
///
/// Optional, and absent only where the listener is not TLS-terminated:
/// the harness always sets it, because an endpoint-enabled `init`
/// always moves the listener to `https://`.
const E2E_CA_BUNDLE: &str = "BOOTROOT_OPENBAO_AUDIT_E2E_CA_BUNDLE";

fn required_env(name: &str) -> String {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set; this test is driven by its harness"))
}

/// Reads the token out of the file `name` points at.
///
/// Trimmed, because the harness writes the file with a shell and a
/// trailing newline there would travel into the header.
fn required_secret_file(name: &str) -> String {
    let path = required_env(name);
    let token = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("the token file at {path} reads: {error}"));
    let token = token.trim().to_string();
    assert!(!token.is_empty(), "the token file at {path} is empty");
    token
}

/// Returns the device map `sys/audit` answers with, which is what "the
/// device's registration" means.
///
/// The `data` member alone rather than the whole body: the envelope
/// carries a fresh `request_id` on every call, so comparing the body
/// verbatim would compare the two reads rather than the registration
/// between them.
async fn audit_registration(url: &str, ca_pem: Option<&str>, token: &str) -> String {
    let client = match ca_pem {
        Some(pem) => crate::tls::build_http_client_from_pem(pem, &[]).expect("a pinned client"),
        None => reqwest::Client::new(),
    };
    client
        .get(format!("{}/v1/sys/audit", url.trim_end_matches('/')))
        .header("X-Vault-Token", token)
        .send()
        .await
        .expect("sys/audit answers")
        .json::<serde_json::Value>()
        .await
        .expect("sys/audit returns a JSON body")
        .get("data")
        .expect("sys/audit returns a device map")
        .to_string()
}

/// Rotates a live deployment's file audit device by rename-and-reopen.
///
/// Ignored, and driven by `scripts/impl/run-registrar-internal-init-e2e.sh`
/// against the pinned `OpenBao` image with the device bind-mounted out
/// of the shared audit store. It is the only place the mechanism meets
/// the real writer and the real Docker: the container is addressed
/// through its bind mount and signalled by id, nothing is restarted or
/// resealed, and the harness asserts around this test that `StartedAt`,
/// `RestartCount` and `Pid` did not move and that the seal status did
/// not change.
///
/// The bounds are derived from the live log rather than from the
/// shipped defaults, because a 64 MiB floor would need 64 MiB of audit
/// traffic before anything rotated.
#[tokio::test]
#[ignore = "requires a provisioned OpenBao audit device on the host"]
async fn a_live_openbao_audit_device_rotates_by_reopen_on_signal() {
    use std::os::unix::fs::MetadataExt as _;

    let dir = PathBuf::from(required_env(E2E_DIR));
    let url = required_env(E2E_URL);
    let token = required_secret_file(E2E_TOKEN_FILE);
    let ca_pem = std::env::var(E2E_CA_BUNDLE)
        .ok()
        .map(|path| std::fs::read_to_string(path).expect("the listener's CA bundle reads"));

    let mut client = match ca_pem.as_deref() {
        Some(pem) => crate::openbao::OpenBaoClient::with_pem_trust(&url, pem, &[])
            .expect("a client anchored to the deployment's bundle"),
        None => crate::openbao::OpenBaoClient::new(&url).expect("a client for the deployment"),
    };
    client.set_token(token.clone());
    client
        .verify_audit_file()
        .await
        .expect("the file audit device is registered before the rotation");
    let registration_before = audit_registration(&url, ca_pem.as_deref(), &token).await;

    let active = dir.join(ACTIVE_FILE_NAME);
    let before = std::fs::metadata(&active).expect("the live active log stats");
    assert!(before.len() > 0, "the device has written something");
    let before_bytes = std::fs::read(&active).expect("the live active log reads");

    // The real `DockerControl`: this is where the addressing rule and
    // the signal are exercised against a running container.
    let bound = (before.len() / 2).max(1);
    let mut rotation = OpenBaoAuditRotation::new(dir.clone(), bound, 7);
    let outcome = rotation.run_pass(OffsetDateTime::now_utc()).await;
    assert!(outcome.rotated(), "the live device was rotated");
    assert_eq!(
        outcome.form,
        RotationForm::Signal,
        "the pinned image honours SIGHUP, so no fallback may be taken"
    );
    assert!(!outcome.retained_unmet, "and its retained set is bounded");

    let names = generation_names(&dir);
    let published = dir.join(names.last().expect("a published generation"));
    let generation = std::fs::metadata(&published).expect("the generation stats");
    assert_eq!(
        generation.ino(),
        before.ino(),
        "the generation is the file OpenBao was writing, renamed rather than copied"
    );
    let generation_bytes = std::fs::read(&published).expect("the generation reads");
    assert!(
        generation_bytes.starts_with(&before_bytes),
        "not one byte of the active log was lost by the rotation"
    );

    let after = std::fs::metadata(&active).expect("the new active log stats");
    assert_ne!(
        after.ino(),
        before.ino(),
        "OpenBao created a new active log rather than reusing the renamed one"
    );
    let owner = std::fs::metadata(&dir).expect("the device directory stats");
    assert_eq!(
        (after.uid(), after.gid()),
        (owner.uid(), owner.gid()),
        "the new active log is the container's to write, not root's"
    );
    assert_ne!(after.uid(), 0, "no root-owned audit.log is created");
    assert_eq!(after.permissions().mode() & 0o7777, 0o600);

    assert!(
        !dir.join(STAGING_FILE_NAME).exists(),
        "the signal form stages no copy"
    );
    assert!(
        !dir.join(MARKER_FILE_NAME).exists(),
        "a confirmed reopen removes the rotation-intent marker"
    );

    client
        .verify_audit_file()
        .await
        .expect("the file audit device is still registered after the rotation");
    assert_eq!(
        audit_registration(&url, ca_pem.as_deref(), &token).await,
        registration_before,
        "the device is not disabled, re-registered or re-pathed by a rotation"
    );
}

// ---------------------------------------------------------------------
// The signal form
// ---------------------------------------------------------------------

/// A pass whose reopen is confirmed loses nothing: the active file
/// *becomes* the generation, and the new active log is a different
/// inode that starts empty.
#[tokio::test(start_paused = true)]
async fn a_confirmed_reopen_rotates_without_copying_or_truncating() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let before_bytes = std::fs::read(&active).expect("the active log reads");
    let before_id = identity_of(&active);

    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotated());
    assert_eq!(outcome.form, RotationForm::Signal);
    assert_eq!(outcome.consecutive_failures, 0);
    assert_eq!(
        docker.signalled(),
        vec!["bao".to_string()],
        "the container is signalled by the id the mount matched, exactly once"
    );

    let names = generation_names(dir.path());
    let published = dir.path().join(names.first().expect("one generation"));
    assert_eq!(
        identity_of(&published),
        before_id,
        "the generation is the file OpenBao was writing, renamed rather than copied"
    );
    assert_eq!(
        std::fs::read(&published).expect("the generation reads"),
        before_bytes,
        "not one byte was lost or truncated away"
    );
    assert_eq!(len_of(&published), captured);

    assert!(
        active.exists(),
        "the pass does not return until the path is back"
    );
    assert_ne!(identity_of(&active), before_id, "on a new inode");
    assert_eq!(len_of(&active), 0, "which OpenBao created empty");
    assert!(
        !dir.path().join(STAGING_FILE_NAME).exists(),
        "the signal form stages nothing"
    );
    assert!(
        !rotation.marker_path().exists(),
        "a confirmed reopen removes the rotation-intent marker"
    );
}

/// The signal form stages no copy, asserted against copied *bytes*
/// rather than against a file count the marker could satisfy.
///
/// Measured inside the window, from the seam: at the instant the
/// container is signalled the device directory holds exactly the bytes
/// it held before the pass, under one fewer name.
#[tokio::test(start_paused = true)]
async fn the_signal_form_never_holds_a_second_copy_of_the_active_log() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    for sequence in 0..2 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S / 2);
    }
    append_records(&active, S);
    let before = log_family_bytes(dir.path());

    let observed = Arc::new(AtomicUsize::new(usize::MAX));
    let recorder = Arc::clone(&observed);
    let watched = dir.path().to_path_buf();
    let reopened = active.clone();
    docker.on_signal(move || {
        let total = usize::try_from(log_family_bytes(&watched)).expect("the total fits");
        recorder.store(total, Ordering::SeqCst);
        create_active_log(&reopened);
    });

    assert!(rotation.run_pass(at(0)).await.rotated());
    let inside = u64::try_from(observed.load(Ordering::SeqCst)).expect("the total fits");
    assert_eq!(
        inside, before,
        "the same bytes under one fewer name: nothing was duplicated"
    );

    // And when the pass ends nothing duplicates what the active log
    // still holds, because the active log holds nothing at all.
    assert_eq!(len_of(&active), 0);
    assert_eq!(log_family_bytes(dir.path()), before);
}

/// `OpenBao`'s open descriptor keeps accepting writes across the window
/// in which the configured path is absent, and every one of those
/// writes is in the generation.
///
/// The invariant is the descriptor's, not the path's: this test
/// deliberately asserts the path is *absent* mid-window rather than
/// present at every instant, which rename-first cannot deliver.
#[tokio::test(start_paused = true)]
async fn the_descriptor_stays_writable_while_the_path_is_absent() {
    use std::io::Write as _;

    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);

    // The descriptor OpenBao holds: opened before the rename, never
    // reopened, and appending throughout.
    let writer = Arc::new(Mutex::new(
        OpenOptions::new()
            .append(true)
            .open(&active)
            .expect("OpenBao's own descriptor opens"),
    ));
    let held = Arc::clone(&writer);
    let path = active.clone();
    docker.on_signal(move || {
        assert!(
            !path.exists(),
            "the configured path is absent in this window, and that is the mechanism"
        );
        held.lock()
            .expect("the writer lock is live")
            .write_all(b"{\"written\":\"while the path was absent\"}\n")
            .expect("the descriptor is still writable");
        create_active_log(&path);
    });

    assert!(rotation.run_pass(at(0)).await.rotated());
    let names = generation_names(dir.path());
    let published = dir.path().join(names.first().expect("one generation"));
    let body = std::fs::read_to_string(&published).expect("the generation reads");
    assert!(
        body.contains("while the path was absent"),
        "the write made through the descriptor is in the generation"
    );
    assert!(
        active.exists(),
        "and the path is back before the pass returns"
    );
}

/// A retained set mixing generations from both forms sorts in creation
/// order and trims oldest-first.
#[tokio::test(start_paused = true)]
async fn both_forms_share_one_naming_family_and_one_trim() {
    let (dir, mut rotation, docker) = signal_fixture(S, 16);
    let active = dir.path().join(ACTIVE_FILE_NAME);

    let mut expected = Vec::new();
    for round in 0..4_i64 {
        // Alternate the forms: an image that reopens, then one that
        // does not, then back.
        if round % 2 == 0 {
            docker.reopens(active.clone());
        } else {
            docker.stops_reopening();
        }
        append_records(&active, S);
        let outcome = rotation.run_pass(at(round)).await;
        assert!(outcome.rotated(), "round {round}");
        assert_eq!(
            outcome.form,
            if round % 2 == 0 {
                RotationForm::Signal
            } else {
                RotationForm::Fallback
            },
            "round {round} used the form its image supports"
        );
        expected.push(rotated_file_name(&rotation_stamp(at(round)), 0));
    }

    let names = generation_names(dir.path());
    assert_eq!(names, expected, "one family, in creation order");
    let mut sorted = names.clone();
    sorted.sort_unstable();
    assert_eq!(names, sorted);

    // Tightened, the trim drops oldest-first across both forms.
    let mut tightened = OpenBaoAuditRotation::with_control(
        dir.path().to_path_buf(),
        S,
        2,
        StubDocker::without_containers(),
    );
    assert!(!tightened.run_pass(at(10)).await.retained_unmet);
    let after = generation_names(dir.path());
    assert!(
        !after.is_empty() && after.len() < expected.len(),
        "the tightened bound dropped something and kept something"
    );
    assert_eq!(
        Some(after.as_slice()),
        expected.get(expected.len() - after.len()..),
        "what survived is the newest, whichever form wrote it"
    );
    assert!(retained_bytes(dir.path()) <= retained_budget_bytes(S, 2));
}

/// The pass waits for the reopen instead of checking once, the wait is
/// bounded, and it runs entirely on `tokio::time`.
///
/// Under a paused clock a five-second deadline costs the test nothing,
/// which is the proof that no wall-clock sleep is involved: the elapsed
/// virtual time is asserted, and the test itself returns at once.
#[tokio::test(start_paused = true)]
async fn the_wait_is_bounded_and_runs_on_tokio_time() {
    // A reopen that lands is confirmed, and the pass does not fall back.
    let (dir, mut rotation, _docker) = signal_fixture(S, N);
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S);
    let started = tokio::time::Instant::now();
    let outcome = rotation.run_pass(at(0)).await;
    assert_eq!(outcome.form, RotationForm::Signal);
    assert!(
        started.elapsed() < REOPEN_DEADLINE,
        "a reopen that lands is confirmed well inside the deadline"
    );

    // A reopen that never lands expires the deadline, and only then is
    // the fallback taken.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S);
    let started = tokio::time::Instant::now();
    let outcome = rotation.run_pass(at(0)).await;
    let waited = started.elapsed();
    assert_eq!(outcome.form, RotationForm::Fallback);
    assert!(
        waited >= REOPEN_DEADLINE,
        "the deadline is what triggers the fallback, not a single check: waited {waited:?}"
    );
    assert!(
        waited < REOPEN_DEADLINE + Duration::from_secs(1),
        "and it is bounded: waited {waited:?}"
    );
    assert_eq!(len_of(&dir.path().join(ACTIVE_FILE_NAME)), 0);
}

/// The rotation drives no `OpenBao` request: the only calls it makes are
/// the three Docker ones, and the confirmation is the inode rule.
#[tokio::test(start_paused = true)]
async fn the_runtime_evidence_is_the_inode_rule_and_nothing_is_asked_of_openbao() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);

    // The reopen creates a file at the path whose inode differs, and
    // that alone is the confirmation — no token, no client and no URL
    // exists anywhere in this rotation to ask OpenBao with.
    assert!(rotation.run_pass(at(0)).await.rotated());
    assert_eq!(docker.signalled().len(), 1);

    // Presence alone is not the test. A "reopen" that puts the
    // generation's own inode back at the path is refused, not confirmed.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let dirpath = dir.path().to_path_buf();
    let path = active.clone();
    docker.on_signal(move || {
        let generation = generation_names(&dirpath)
            .pop()
            .expect("the generation is in place before the signal");
        std::fs::hard_link(dirpath.join(generation), &path).expect("the same inode is put back");
    });

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(!outcome.rotated(), "presence is not the predicate");
        assert_eq!(outcome.form, RotationForm::None);
    })
    .await;
    assert!(
        logs.contains("carries the rotated generation's own identity"),
        "{logs}"
    );
}

// ---------------------------------------------------------------------
// Recovery and the fallback
// ---------------------------------------------------------------------

/// A partial failure recovers to the pre-rotation state *before* the
/// tick continues, and the same tick then finishes through
/// copy-and-truncate.
///
/// The two are one tick, not alternatives: what the seam observes at
/// the fallback's first step is the exact pre-pass filesystem — the
/// active log back at its path with its original contents, the signal
/// generation gone, and the retained set at its pre-pass contents with
/// nothing dropped on the strength of the abandoned attempt.
#[tokio::test(start_paused = true)]
async fn a_failed_reopen_restores_the_pre_rotation_state_and_then_falls_back() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    for sequence in 0..2 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S / 2);
    }
    let seeded = generation_names(dir.path());
    append_records(&active, S);
    let before_bytes = std::fs::read(&active).expect("the active log reads");
    let before_id = identity_of(&active);

    let restored: Arc<Mutex<Restored>> = Arc::new(Mutex::new(None));
    let recorder = Arc::clone(&restored);
    let watched = dir.path().to_path_buf();
    rotation.before_stage(move |path| {
        *recorder.lock().expect("the record lock is live") = Some((
            std::fs::read(path).expect("the restored active log reads"),
            identity_of(path),
            generation_names(&watched),
        ));
    });

    let outcome = rotation.run_pass(at(0)).await;
    let (seen_bytes, seen_id, seen_names) = restored
        .lock()
        .expect("the record lock is live")
        .take()
        .expect("the fallback ran after the recovery");
    assert_eq!(seen_bytes, before_bytes, "restored byte for byte");
    assert_eq!(
        seen_id, before_id,
        "and on the very inode it was renamed from"
    );
    assert_eq!(
        seen_names, seeded,
        "the signal generation is gone and nothing was dropped for it"
    );

    assert!(outcome.rotated(), "the same tick completed the rotation");
    assert_eq!(outcome.form, RotationForm::Fallback);
    assert_eq!(outcome.consecutive_failures, 0);
    assert_eq!(len_of(&active), 0, "through copy-and-truncate");
    assert_eq!(identity_of(&active), before_id, "of the same inode");
    let names = generation_names(dir.path());
    assert_eq!(
        names.len(),
        seeded.len() + 1,
        "the fallback's generation joined the set"
    );
    assert!(
        !outcome.retained_unmet,
        "and the ordinary bound evaluation applied"
    );
}

/// The fallback is announced once per process and never again.
#[tokio::test(start_paused = true)]
async fn the_fallback_is_announced_once() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);

    let logs = logs_from(async {
        for round in 0..4_i64 {
            append_records(&active, S);
            let outcome = rotation.run_pass(at(round * 60)).await;
            assert_eq!(outcome.form, RotationForm::Fallback, "round {round}");
        }
    })
    .await;
    assert_eq!(
        logs.matches("this process rotates it by copy-and-truncate instead")
            .count(),
        1,
        "one announcement per process, never one a minute:\n{logs}"
    );
    assert!(logs.contains("INFO"), "and it is an info event:\n{logs}");
    assert!(
        logs.contains("no running container binds this device directory")
            || logs.contains("did not reopen inside the deadline"),
        "naming the reason:\n{logs}"
    );
}

/// The fallback opens the active path exactly once and truncates
/// through that descriptor, and re-verifies before it does.
///
/// With the path re-pointed at another inode, or the held file
/// shortened below the prefix that was copied, nothing is truncated:
/// the copy is unlinked, one `warn` names the failed check, and the
/// pass fails.
#[tokio::test(start_paused = true)]
async fn the_fallback_reverifies_before_truncating_and_truncates_what_it_copied() {
    // Re-pointed to a different inode between the copy and the truncate.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let held = OpenOptions::new()
        .append(true)
        .open(&active)
        .expect("OpenBao's own descriptor opens");
    let planted = active.clone();
    rotation.on_publish(move |_| {
        std::fs::remove_file(&planted).expect("the active log is unlinked");
        std::fs::write(&planted, b"a replacement\n").expect("the replacement is created");
    });

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(!outcome.rotated());
        assert!(outcome.rotation.is_unmet());
    })
    .await;
    assert!(
        logs.contains("no longer names the file this pass copied"),
        "{logs}"
    );
    assert!(
        generation_names(dir.path()).is_empty(),
        "the copy is unlinked rather than published over a truncate that never ran"
    );
    assert_eq!(
        held.metadata().expect("the held descriptor stats").len(),
        captured,
        "the file OpenBao is still writing to keeps every byte"
    );
    assert_eq!(
        std::fs::read(&active).expect("the replacement reads"),
        b"a replacement\n",
        "and the replacement is never emptied"
    );

    // Shortened below the copied prefix, on the very inode that was
    // copied — the delayed reopen that truncates rather than replaces.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let shortened = active.clone();
    rotation.on_publish(move |_| {
        let file = OpenOptions::new()
            .write(true)
            .open(&shortened)
            .expect("the active log opens");
        file.set_len(16).expect("the active log is shortened");
    });

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(!outcome.rotated());
        assert!(outcome.rotation.is_unmet());
    })
    .await;
    assert!(logs.contains("shorter than the"), "{logs}");
    assert!(generation_names(dir.path()).is_empty());
    assert_eq!(
        len_of(&active),
        16,
        "the shortened file is left exactly as it was found"
    );
}

/// A delayed reopen landing after the deadline but before the
/// rename-back is a slow success, not a fallback.
#[tokio::test(start_paused = true)]
async fn a_reopen_landing_before_the_recovery_looks_is_a_success() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let before_id = identity_of(&active);
    rotation.on_recovery(create_active_log);

    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotated(), "a delayed reopen is a slow success");
    assert_eq!(outcome.form, RotationForm::Signal);
    let names = generation_names(dir.path());
    assert_eq!(names.len(), 1, "nothing was copied and nothing truncated");
    assert_eq!(
        identity_of(&dir.path().join(names.first().expect("one generation"))),
        before_id
    );
    assert_ne!(identity_of(&active), before_id);
    assert!(!dir.path().join(STAGING_FILE_NAME).exists());
    assert!(!rotation.marker_path().exists());
}

/// A reopen landing *after* the rename-back resolves a path that
/// exists, so it reopens the very inode `OpenBao` was already appending
/// to. The fallback then works through that same inode from end to end.
#[tokio::test(start_paused = true)]
async fn a_reopen_landing_after_the_rename_back_leaves_the_fallback_intact() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let before_id = identity_of(&active);

    // The reopen resolves the restored name: same file, so nothing about
    // the filesystem changes. Modelled by a hook that opens the path the
    // recovery has just restored.
    let reopened = active.clone();
    rotation.before_stage(move |path| {
        let resolved = OpenOptions::new()
            .append(true)
            .open(&reopened)
            .expect("a reopen of a path that exists finds the same file");
        assert_eq!(
            file_identity(&resolved.metadata().expect("the reopened file stats")),
            identity_of(path),
            "descriptor and path are the same file"
        );
    });

    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotated());
    assert_eq!(outcome.form, RotationForm::Fallback);
    let names = generation_names(dir.path());
    let published = dir.path().join(names.first().expect("one generation"));
    assert_eq!(len_of(&published), captured, "the generation is intact");
    assert_eq!(
        identity_of(&active),
        before_id,
        "against the inode it copied"
    );
    assert_eq!(len_of(&active), 0);
}

/// The rename-back never clobbers a new active log, and `EEXIST` is
/// decided by the common predicate rather than by itself.
#[tokio::test(start_paused = true)]
async fn the_rename_back_refuses_an_active_log_and_decides_by_the_inode() {
    // A new active log appearing between the recovery's look and the
    // rename-back: `EEXIST`, re-statted, a differing inode, a success.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let before_id = identity_of(&active);
    rotation.on_restore_rename(move |path| {
        create_active_log(path);
        std::fs::write(path, b"{\"created\":\"by the delayed reopen\"}\n")
            .expect("the new active log is written");
    });

    let outcome = rotation.run_pass(at(0)).await;
    assert!(
        outcome.rotated(),
        "the delayed reopen is the reopened predicate"
    );
    assert_eq!(outcome.form, RotationForm::Signal);
    assert_eq!(
        std::fs::read(&active).expect("the new active log reads"),
        b"{\"created\":\"by the delayed reopen\"}\n",
        "the file OpenBao created is left untouched"
    );
    let names = generation_names(dir.path());
    assert_eq!(
        names.len(),
        1,
        "the generation is kept: it holds the earlier records"
    );
    assert_eq!(
        identity_of(&dir.path().join(names.first().expect("one generation"))),
        before_id
    );
    assert!(!rotation.marker_path().exists());

    // A re-stat that matches the generation's own identity takes the
    // anomaly path instead.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let watched = dir.path().to_path_buf();
    rotation.on_restore_rename(move |path| {
        let generation = generation_names(&watched)
            .pop()
            .expect("the generation is in place");
        std::fs::hard_link(watched.join(generation), path).expect("the same inode is linked back");
    });

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(!outcome.rotated());
        assert!(outcome.rotation.is_unmet());
        assert_eq!(outcome.form, RotationForm::None);
    })
    .await;
    assert!(
        logs.contains("carries the rotated generation's own identity"),
        "{logs}"
    );
    assert_eq!(
        len_of(&active),
        len_of(
            &dir.path().join(
                generation_names(dir.path())
                    .pop()
                    .expect("the generation stands")
            )
        ),
        "nothing was truncated"
    );
    assert!(
        !dir.path().join(STAGING_FILE_NAME).exists(),
        "and nothing was copied"
    );
}

/// A post-`EEXIST` re-stat that finds the path absent again is a failed
/// restore, and stays in the pending state — neither a silent success
/// nor a fallback.
#[tokio::test(start_paused = true)]
async fn a_post_eexist_restat_finding_the_path_absent_stays_pending() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    // Refused exactly as a name that appeared under the rename-back
    // would refuse it, with nothing at the path by the time the re-stat
    // runs: the name was there for the rename and gone a moment later.
    rotation.refuse_restore_rename();

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(!outcome.rotated());
        assert!(outcome.restore_pending, "the restore is outstanding");
        assert_eq!(outcome.form, RotationForm::None);
    })
    .await;
    assert!(
        logs.contains("live audit log under a rotated name"),
        "{logs}"
    );
    assert!(rotation.restore_is_pending());
    assert!(!active.exists(), "and nothing was invented at the path");
    assert!(
        rotation.marker_path().exists(),
        "a pending restore keeps its marker"
    );
    assert!(
        !dir.path().join(STAGING_FILE_NAME).exists(),
        "no fallback ran"
    );
}

// ---------------------------------------------------------------------
// The pending restore
// ---------------------------------------------------------------------

/// Drives a signal-form pass whose rename-back fails, and returns the
/// device directory, the rotation holding the pending restore, and the
/// name the live audit inode is stranded under.
async fn strand_the_live_inode(
    max_file_bytes: u64,
    max_retained_files: u32,
) -> (TempDir, OpenBaoAuditRotation, String) {
    let (dir, mut rotation, docker) = signal_fixture(max_file_bytes, max_retained_files);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, max_file_bytes);
    rotation.fail_restore_rename();
    let outcome = rotation.run_pass(at(0)).await;
    assert!(
        outcome.restore_pending,
        "the restore did not fail as arranged"
    );
    rotation.allow_restore_rename();
    let stranded = generation_names(dir.path())
        .pop()
        .expect("the live inode is under a generation name");
    (dir, rotation, stranded)
}

/// A failed rename-back never costs the live audit log: it is neither
/// trimmed — with bounds set so an ordinary trim would drop it — nor
/// truncated, one `error` names it and the absent active path, and each
/// pending tick does exactly the restore retry and the bound
/// evaluation.
#[tokio::test(start_paused = true)]
async fn a_failed_rename_back_holds_the_live_inode_and_each_tick_only_retries() {
    // `N` of one, so the retained set is meant to hold a single
    // generation: an ordinary trim would drop everything else, the
    // stranded file included.
    let (dir, mut rotation, docker) = signal_fixture(S, 1);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    for sequence in 0..3 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S / 2);
    }
    append_records(&active, S);
    let live_bytes = std::fs::read(&active).expect("the active log reads");
    rotation.fail_restore_rename();

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(outcome.restore_pending);
        assert!(
            outcome.rotation.is_unmet(),
            "a failed restore is a failed pass"
        );
    })
    .await;
    let stranded = generation_names(dir.path())
        .pop()
        .expect("the live inode is under a generation name");
    assert!(
        logs.contains(&stranded),
        "the error names the file to move back:\n{logs}"
    );
    assert!(
        logs.contains(&active.display().to_string()),
        "and the absent active path:\n{logs}"
    );
    assert!(
        logs.contains("do not delete, compress or move it anywhere but back"),
        "{logs}"
    );

    // Each later tick retries the restore and evaluates the bound with
    // the stranded file excluded — and does nothing else.
    for round in 1..4_i64 {
        let outcome = rotation.run_pass(at(round * 60)).await;
        assert!(outcome.restore_pending, "round {round}");
        assert!(
            outcome.rotation.is_unmet(),
            "round {round} counts toward the escalation"
        );
        assert!(!active.exists(), "round {round}: no rotation, no fallback");
        assert!(
            !dir.path().join(STAGING_FILE_NAME).exists(),
            "round {round}: nothing was copied"
        );
        assert!(
            generation_names(dir.path()).contains(&stranded),
            "round {round}: the live audit log was not trimmed"
        );
        assert_eq!(
            std::fs::read(dir.path().join(&stranded)).expect("the live file reads"),
            live_bytes,
            "round {round}: and it was not truncated"
        );
    }
    assert!(
        generation_names(dir.path()).len() < 4,
        "the remaining generations are still trimmed against bounds computed without it"
    );
}

/// A pending restore clears when the rename-back succeeds, and the next
/// tick rotates as usual.
#[tokio::test(start_paused = true)]
async fn a_pending_restore_clears_when_the_rename_back_succeeds() {
    let (dir, mut rotation, stranded) = strand_the_live_inode(S, N).await;
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let live_bytes = std::fs::read(dir.path().join(&stranded)).expect("the live file reads");

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(60)).await;
        assert!(!outcome.restore_pending, "the restore cleared");
        assert!(!outcome.rotation.is_unmet(), "and the tick owes nothing");
        assert!(
            !outcome.retained_unmet,
            "the bound is evaluated with nothing excluded"
        );
    })
    .await;
    assert!(logs.contains("ordinary rotation resumes"), "{logs}");
    assert_eq!(
        std::fs::read(&active).expect("the restored active log reads"),
        live_bytes,
        "the live inode is back at the configured path"
    );
    assert!(generation_names(dir.path()).is_empty());
    assert!(
        !rotation.marker_path().exists(),
        "a cleared restore removes its marker"
    );

    // And the next tick rotates as usual.
    append_records(&active, S);
    assert!(rotation.run_pass(at(120)).await.rotated());
}

/// A pending restore also clears when a new active log appears while it
/// is outstanding: the `EEXIST` re-stat shows an inode that is not the
/// pending file's, which is the reopened predicate applied later.
#[tokio::test(start_paused = true)]
async fn a_pending_restore_clears_when_a_new_active_log_appears() {
    let (dir, mut rotation, stranded) = strand_the_live_inode(S, N).await;
    let active = dir.path().join(ACTIVE_FILE_NAME);
    // The delayed reopen, or an operator, produced one.
    create_active_log(&active);
    let fresh_id = identity_of(&active);

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(60)).await;
        assert!(!outcome.restore_pending);
        assert!(!outcome.rotation.is_unmet());
        assert!(!outcome.retained_unmet);
    })
    .await;
    assert!(logs.contains("genuine rotated generation now"), "{logs}");
    assert_eq!(identity_of(&active), fresh_id, "the new file is left alone");
    assert!(
        generation_names(dir.path()).contains(&stranded),
        "and the formerly pending file rejoins the retained set"
    );
    assert!(!rotation.marker_path().exists());

    // With nothing excluded any more, a tightened bound may drop it.
    let mut tightened = OpenBaoAuditRotation::with_control(
        dir.path().to_path_buf(),
        S,
        0,
        StubDocker::without_containers(),
    );
    assert!(!tightened.run_pass(at(120)).await.retained_unmet);
    assert!(generation_names(dir.path()).is_empty());
}

/// A retry whose re-stat matches the pending file's own identity is the
/// same-inode anomaly, and the restore stays outstanding.
#[tokio::test(start_paused = true)]
async fn a_retry_restat_matching_the_pending_file_takes_the_anomaly_path() {
    let (dir, mut rotation, stranded) = strand_the_live_inode(S, N).await;
    let active = dir.path().join(ACTIVE_FILE_NAME);
    std::fs::hard_link(dir.path().join(&stranded), &active).expect("the same inode is linked");

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(60)).await;
        assert!(
            outcome.restore_pending,
            "the restore is not resolved by that"
        );
        assert!(outcome.rotation.is_unmet());
        assert!(outcome.retained_unmet, "and no bound was established");
    })
    .await;
    assert!(logs.contains("held-back file's own identity"), "{logs}");
    assert!(
        generation_names(dir.path()).contains(&stranded),
        "nothing was trimmed"
    );
    assert!(
        !dir.path().join(STAGING_FILE_NAME).exists(),
        "nothing was copied"
    );
}

// ---------------------------------------------------------------------
// The same-inode anomaly
// ---------------------------------------------------------------------

/// An active path carrying the generation's own identity fails the pass
/// instead of falling back: nothing truncated, nothing trimmed, no
/// rename-back attempted.
#[tokio::test(start_paused = true)]
async fn the_same_inode_anomaly_truncates_nothing_and_trims_nothing() {
    let (dir, mut rotation, docker) = signal_fixture(S, 1);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    // Over budget, so an ordinary trim would certainly act.
    for sequence in 0..4 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    let seeded = generation_names(dir.path());
    let captured = append_records(&active, S);

    // The generation's own inode put back at the active path, in the
    // window the recovery's first look reads.
    let watched = dir.path().to_path_buf();
    rotation.on_recovery(move |path| {
        let generation = generation_names(&watched)
            .pop()
            .expect("the generation is in place");
        std::fs::hard_link(watched.join(generation), path).expect("the same inode is linked back");
    });

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(!outcome.rotated());
        assert!(outcome.rotation.is_unmet(), "counted toward the escalation");
        assert_eq!(outcome.form, RotationForm::None);
        assert!(outcome.retained_unmet, "no bound was evaluated at all");
    })
    .await;
    assert_eq!(count_lines_at(&logs, "ERROR"), 1, "one error:\n{logs}");
    assert!(
        logs.contains("carries the rotated generation's own identity"),
        "{logs}"
    );
    assert!(
        logs.contains(&active.display().to_string()),
        "naming both paths:\n{logs}"
    );

    let names = generation_names(dir.path());
    assert_eq!(names.len(), seeded.len() + 1, "nothing was trimmed");
    assert_eq!(len_of(&active), captured, "and nothing was truncated");
    assert!(
        !dir.path().join(STAGING_FILE_NAME).exists(),
        "no fallback ran"
    );
}

/// A rename-back whose directory flush failed fails the pass and runs
/// no fallback that tick, although the live filesystem is back at its
/// pre-rotation state.
#[tokio::test(start_paused = true)]
async fn a_failed_rename_back_flush_fails_the_pass_and_runs_no_fallback() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let before_id = identity_of(&active);
    rotation.fail_restore_sync();

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(!outcome.rotated());
        assert!(outcome.rotation.is_unmet());
        assert_eq!(outcome.form, RotationForm::None);
        assert!(!outcome.restore_pending, "the rename itself landed");
    })
    .await;
    assert_eq!(count_lines_at(&logs, "ERROR"), 1, "{logs}");
    assert!(logs.contains("not durable"), "{logs}");
    assert!(
        logs.contains(&active.display().to_string()),
        "naming both paths:\n{logs}"
    );
    assert_eq!(
        identity_of(&active),
        before_id,
        "the log is back at its path"
    );
    assert_eq!(len_of(&active), captured, "with every record");
    assert!(
        generation_names(dir.path()).is_empty(),
        "and no fallback generation was produced on that tick"
    );
    assert!(
        rotation.marker_path().exists(),
        "the marker is kept after a rename-back whose flush failed"
    );

    // The next pass's start-of-pass cleanup removes it and rotates.
    rotation.allow_restore_sync();
    let outcome = rotation.run_pass(at(60)).await;
    assert!(outcome.rotated());
    assert!(!rotation.marker_path().exists());
}

/// The flush after the rename lands before the signal, and a flush that
/// fails signals nothing and runs the recovery.
#[tokio::test(start_paused = true)]
async fn a_failed_rename_flush_signals_nothing_and_recovers() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let before_id = identity_of(&active);
    rotation.fail_rename_sync();

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(
            outcome.rotated(),
            "the same tick still completed the rotation"
        );
        assert_eq!(outcome.form, RotationForm::Fallback);
    })
    .await;
    assert!(
        logs.contains("refusing to signal against an unflushed rename"),
        "{logs}"
    );
    assert!(
        docker.signalled().is_empty(),
        "the container is never signalled against an unflushed rename"
    );
    assert_eq!(
        identity_of(&active),
        before_id,
        "the recovery restored the path"
    );
    assert_eq!(len_of(&active), 0, "and the fallback then emptied it");
    let names = generation_names(dir.path());
    assert_eq!(
        len_of(&dir.path().join(names.first().expect("one generation"))),
        captured
    );
}

// ---------------------------------------------------------------------
// The rotation-intent marker
// ---------------------------------------------------------------------

/// Reads the marker back, for the tests that assert on what a pass
/// wrote.
fn read_intent(path: &Path) -> RotationIntent {
    let body = std::fs::read(path).expect("the marker reads");
    serde_json::from_slice(&body).expect("the marker parses")
}

/// Writes a marker directly, for the restart states no pass produces on
/// its own.
fn write_intent(path: &Path, identity: (u64, u64), generation: &str) {
    let intent = RotationIntent {
        active_dev: identity.0,
        active_ino: identity.1,
        generation: generation.to_string(),
    };
    std::fs::write(
        path,
        serde_json::to_vec(&intent).expect("the marker serialises"),
    )
    .expect("the marker is written");
}

/// The marker is on disk before the rename is issued, holds the active
/// log's pre-rename identity and the generation name, and sits outside
/// the glob every listing and trim uses.
#[tokio::test(start_paused = true)]
async fn the_marker_is_written_before_the_rename_and_holds_the_pre_rename_identity() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let before_id = identity_of(&active);

    // The signal runs after the rename and its flush, so the marker
    // this reads is the one the rename was issued under.
    let observed = Arc::new(Mutex::new(None));
    let recorder = Arc::clone(&observed);
    let marker = rotation.marker_path().to_path_buf();
    let reopened = active.clone();
    docker.on_signal(move || {
        *recorder.lock().expect("the record lock is live") = Some(read_intent(&marker));
        create_active_log(&reopened);
    });

    assert!(rotation.run_pass(at(0)).await.rotated());
    let intent = observed
        .lock()
        .expect("the record lock is live")
        .take()
        .expect("the marker was on disk before the signal");
    assert_eq!(
        intent.identity(),
        before_id,
        "the marker records the identity the rename carries into the generation"
    );
    let published = generation_names(dir.path()).pop().expect("one generation");
    assert_eq!(intent.generation, published);
    assert!(
        parse_rotated_name(MARKER_FILE_NAME).is_none(),
        "the marker's name is outside the glob the trim uses"
    );
}

/// A marker write forced to fail renames nothing and falls back on the
/// same tick.
#[tokio::test(start_paused = true)]
async fn a_marker_write_that_fails_renames_nothing() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let before_id = identity_of(&active);
    rotation.fail_marker_write();

    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotated(), "the tick still rotated");
    assert_eq!(outcome.form, RotationForm::Fallback);
    assert!(
        docker.signalled().is_empty(),
        "nothing was renamed, so nothing was signalled"
    );
    assert_eq!(
        identity_of(&active),
        before_id,
        "the active log never moved"
    );
    assert_eq!(len_of(&active), 0, "the fallback emptied it in place");
    let names = generation_names(dir.path());
    assert_eq!(
        len_of(&dir.path().join(names.first().expect("one generation"))),
        captured
    );
    assert!(!rotation.marker_path().exists());
}

/// A rename that fails removes the marker it wrote and falls back on the
/// same tick.
#[tokio::test(start_paused = true)]
async fn a_rename_that_fails_removes_its_own_marker() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    rotation.fail_rename();

    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotated());
    assert_eq!(outcome.form, RotationForm::Fallback);
    assert!(docker.signalled().is_empty());
    assert!(
        !rotation.marker_path().exists(),
        "a rename that never happened leaves no marker behind"
    );
}

/// A failed marker removal fails the pass, blocks every rotation until
/// it clears, and is retried first on the next tick — while trimming
/// continues.
#[tokio::test(start_paused = true)]
async fn a_failed_marker_removal_fails_the_pass_and_blocks_rotation() {
    for fault in ["unlink", "flush"] {
        let (dir, mut rotation, docker) = signal_fixture(S, N);
        let active = dir.path().join(ACTIVE_FILE_NAME);
        for sequence in 0..8 {
            seed_generation(dir.path(), "20260301T115900Z", sequence, S);
        }
        append_records(&active, S);
        if fault == "unlink" {
            rotation.fail_marker_unlink();
        } else {
            rotation.fail_marker_flush();
        }

        let logs = logs_from(async {
            let outcome = rotation.run_pass(at(0)).await;
            assert!(
                outcome.rotation.is_unmet(),
                "{fault}: a removal that failed is not a successful pass"
            );
            assert!(outcome.marker_cleanup_pending, "{fault}");
            assert!(!outcome.retained_unmet, "{fault}: trimming still runs");
        })
        .await;
        assert_eq!(
            count_lines_at(&logs, "ERROR"),
            1,
            "{fault}: one error:\n{logs}"
        );
        assert!(
            logs.contains(MARKER_FILE_NAME),
            "{fault}: naming the marker:\n{logs}"
        );
        assert!(
            retained_bytes(dir.path()) <= retained_budget_bytes(S, N),
            "{fault}: the trim reached the bound"
        );

        // The next tick retries the removal first and rotates nothing
        // while it is outstanding.
        let signals_before = docker.signalled().len();
        append_records(&active, S);
        let blocked = rotation.run_pass(at(60)).await;
        assert!(blocked.marker_cleanup_pending, "{fault}");
        assert!(blocked.rotation.is_unmet(), "{fault}");
        assert_eq!(
            docker.signalled().len(),
            signals_before,
            "{fault}: no rotation is attempted while a cleanup is outstanding"
        );

        // And once it clears, the tick carries on as usual.
        if fault == "unlink" {
            rotation.allow_marker_unlink();
        } else {
            rotation.allow_marker_flush();
        }
        let cleared = rotation.run_pass(at(120)).await;
        assert!(!cleared.marker_cleanup_pending, "{fault}");
        assert!(!rotation.marker_path().exists(), "{fault}");
        assert!(cleared.rotated(), "{fault}: the same tick rotated");
    }
}

/// A marker found at the start of a pass whose active path is present is
/// removed before that pass does anything else, whatever identity it
/// records — which is what makes the cleanup self-healing across a
/// restart.
#[tokio::test(start_paused = true)]
async fn a_stale_marker_is_removed_at_the_start_of_the_next_pass() {
    // After a completed fallback, whose marker removal was forced to
    // fail, and then a restart.
    for form in ["fallback", "rename-back"] {
        let (dir, mut rotation, docker) = signal_fixture(S, N);
        let active = dir.path().join(ACTIVE_FILE_NAME);
        append_records(&active, S);
        if form == "fallback" {
            docker.stops_reopening();
        } else {
            docker.stops_reopening();
            rotation.fail_truncate();
        }
        rotation.fail_marker_unlink();
        let outcome = rotation.run_pass(at(0)).await;
        assert!(outcome.marker_cleanup_pending, "{form}");
        let marker = rotation.marker_path().to_path_buf();
        assert!(marker.exists(), "{form}: the marker outlived its pass");
        let recorded = read_intent(&marker);
        assert_eq!(
            recorded.identity(),
            identity_of(&active),
            "{form}: after both outcomes the active path is on exactly the inode the marker \
             recorded, so an identity test would read this marker as live"
        );

        // The daemon goes away with the in-memory cleanup debt.
        drop(rotation);
        let mut restarted = OpenBaoAuditRotation::with_control(
            dir.path().to_path_buf(),
            S,
            N,
            StubDocker::without_containers(),
        );
        let after = restarted.run_pass(at(60)).await;
        assert!(!marker.exists(), "{form}: the stale marker is gone");
        assert!(!after.marker_cleanup_pending, "{form}");
    }
}

/// A pass starting with the active path absent decides from the marker
/// alone, and never from generation order or mtime.
#[tokio::test(start_paused = true)]
async fn a_restart_with_the_active_path_absent_decides_from_the_marker_alone() {
    // (a) A marker naming a file that still carries the recorded
    //     identity: renamed back, and the pending-restore path taken.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let live = seed_generation(dir.path(), "20260301T115900Z", 0, S);
    let live_bytes = std::fs::read(&live).expect("the live file reads");
    // A newer, unrelated generation, which name order alone would pick.
    seed_generation(dir.path(), "20260301T120500Z", 0, S / 2);
    let marker = dir.path().join(MARKER_FILE_NAME);
    write_intent(
        &marker,
        identity_of(&live),
        "audit-20260301T115900Z-000000.log",
    );
    let mut rotation = rotation_at(dir.path().to_path_buf(), S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);

    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(0)).await;
        assert!(!outcome.restore_pending, "the rename-back succeeded");
    })
    .await;
    assert!(logs.contains("rotation-intent marker authorises"), "{logs}");
    assert_eq!(
        std::fs::read(&active).expect("the restored active log reads"),
        live_bytes,
        "the file the marker named is what came back, not the newest"
    );
    assert!(
        generation_names(dir.path()).contains(&rotated_file_name("20260301T120500Z", 0)),
        "the newer unrelated generation was never moved into place"
    );
    assert!(!marker.exists(), "and the restore removed the marker");

    // (b) The active path exists after all: the marker is removed and an
    //     ordinary pass carries on.
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let marker = dir.path().join(MARKER_FILE_NAME);
    write_intent(&marker, (1, 2), "audit-20260301T115900Z-000000.log");
    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotated(), "an ordinary pass carried on");
    assert!(!marker.exists());

    // (c) No marker at all, beside a generation: nothing is rotated,
    //     nothing trimmed, nothing moved into place.
    // (d) A marker naming a file that is gone.
    // (e) A marker naming a file whose identity no longer matches.
    for state in ["absent", "vanished", "mismatched"] {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let other = seed_generation(dir.path(), "20260301T115900Z", 0, S);
        let newest = seed_generation(dir.path(), "20260301T120500Z", 0, S);
        let marker = dir.path().join(MARKER_FILE_NAME);
        match state {
            "absent" => {}
            "vanished" => write_intent(&marker, (1, 2), "audit-20260301T110000Z-000000.log"),
            _ => write_intent(
                &marker,
                (identity_of(&other).0, identity_of(&other).1 ^ 0xffff),
                "audit-20260301T115900Z-000000.log",
            ),
        }
        let seeded = generation_names(dir.path());
        let mut rotation = rotation_at(dir.path().to_path_buf(), S, 1);

        let logs = logs_from(async {
            let outcome = rotation.run_pass(at(0)).await;
            assert!(outcome.rotation.is_unmet(), "{state}");
            assert!(outcome.retained_unmet, "{state}: nothing was established");
        })
        .await;
        assert_eq!(
            count_lines_at(&logs, "ERROR"),
            1,
            "{state}: one error:\n{logs}"
        );
        assert!(
            logs.contains("cannot establish which file the device is writing to"),
            "{state}:\n{logs}"
        );
        assert_eq!(
            generation_names(dir.path()),
            seeded,
            "{state}: nothing was trimmed, although the bound says one generation"
        );
        assert!(
            !dir.path().join(ACTIVE_FILE_NAME).exists(),
            "{state}: no generation was moved into place"
        );
        assert!(
            newest.exists(),
            "{state}: and the newest was left where it was"
        );
    }
}

/// A marker naming anything but a generation of this device's own is
/// refused before the name is ever joined to the device directory.
///
/// The marker sits in a directory the container's audit user can write.
/// `Path::join` reads `..` as a step out of that directory and an
/// absolute name as a replacement for the whole path, so a marker that
/// user planted would otherwise have root rename a file anywhere on the
/// host to the active path — and the identity it has to match is one it
/// can read for any file bind-mounted into its own container.
#[tokio::test(start_paused = true)]
async fn a_marker_naming_a_file_outside_the_device_directory_moves_nothing() {
    let root = tempfile::tempdir().expect("a temporary directory");
    let dir = root.path().join("openbao");
    std::fs::create_dir(&dir).expect("the device directory");
    let victim = root.path().join("victim.conf");
    std::fs::write(&victim, b"the file the marker points at\n").expect("the victim writes");
    let victim_bytes = std::fs::read(&victim).expect("the victim reads");

    for name in [
        "../victim.conf".to_string(),
        victim.display().to_string(),
        "audit-20260301T115900Z-00000.log".to_string(),
        "audit.log".to_string(),
    ] {
        write_intent(&dir.join(MARKER_FILE_NAME), identity_of(&victim), &name);
        let mut rotation = rotation_at(dir.clone(), S, N);

        let logs = logs_from(async {
            let outcome = rotation.run_pass(at(0)).await;
            assert!(outcome.rotation.is_unmet(), "{name}");
            assert!(outcome.retained_unmet, "{name}: nothing was established");
        })
        .await;
        assert_eq!(
            count_lines_at(&logs, "ERROR"),
            1,
            "{name}: one error:\n{logs}"
        );
        assert!(
            logs.contains("not a generation name this daemon could have written"),
            "{name}:\n{logs}"
        );
        assert!(
            !dir.join(ACTIVE_FILE_NAME).exists(),
            "{name}: nothing was moved into place"
        );
        assert_eq!(
            std::fs::read(&victim).expect("the victim still reads"),
            victim_bytes,
            "{name}: the file the marker named was left where it was"
        );
    }
}

/// The pending-restore state machine has no on-disk representation, and
/// a running daemon never reconstructs it from the marker.
#[tokio::test(start_paused = true)]
async fn the_pending_restore_state_lives_only_in_memory() {
    let (dir, rotation, stranded) = strand_the_live_inode(S, N).await;
    assert!(rotation.restore_is_pending());

    // Nothing on disk names the state: only the marker, which is the
    // intent rather than the state machine, and it records the identity
    // and the generation name — not that a restore is outstanding.
    let intent = read_intent(rotation.marker_path());
    assert_eq!(intent.generation, stranded);
    let body = std::fs::read_to_string(rotation.marker_path()).expect("the marker reads");
    assert!(
        !body.contains("pending") && !body.contains("restore"),
        "the marker is an intent, not a state machine: {body}"
    );

    // A second rotation over the same directory, standing in for a
    // daemon that never had the state, does not adopt it: it starts
    // with the active path absent and consults the marker, which is the
    // only path by which the marker is ever read.
    let mut restarted = rotation_at(dir.path().to_path_buf(), S, N);
    assert!(
        !restarted.restore_is_pending(),
        "a new task starts with nothing pending"
    );
    let outcome = restarted.run_pass(at(120)).await;
    assert!(
        !outcome.restore_pending,
        "and the marker branch resolved it rather than reconstructing a pending state"
    );
    assert!(dir.path().join(ACTIVE_FILE_NAME).exists());
}

// ---------------------------------------------------------------------
// Addressing the container
// ---------------------------------------------------------------------

/// The daemon addresses only this install's container, from the device's
/// bind mount, and signals it by id.
#[tokio::test(start_paused = true)]
async fn the_container_is_selected_by_this_installs_bind_mount_and_signalled_by_id() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let other = tempfile::tempdir().expect("another install's audit store");
    // Three running containers: one binding another install's store at
    // the same destination, one binding this store somewhere else, and
    // the one that is actually this install's.
    let docker = StubDocker::with_containers(vec![
        ("other-install".to_string(), bind_mounts_json(other.path())),
        (
            "wrong-destination".to_string(),
            format!(
                "[{{\"Type\":\"bind\",\"Source\":\"{}\",\"Destination\":\"/somewhere/else\"}}]",
                dir.path().display()
            ),
        ),
        ("ours".to_string(), bind_mounts_json(dir.path())),
    ]);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    docker.reopens(active.clone());
    let mut rotation = OpenBaoAuditRotation::with_control(
        dir.path().to_path_buf(),
        S,
        N,
        Arc::clone(&docker) as Arc<dyn DockerControl>,
    );
    append_records(&active, S);

    assert!(rotation.run_pass(at(0)).await.rotated());
    assert_eq!(
        docker.signalled(),
        vec!["ours".to_string()],
        "only this install's container is signalled, and by its id"
    );
}

/// Every addressing and signalling failure falls back rather than
/// stopping the rotation task, and none of them renames anything.
#[tokio::test(start_paused = true)]
async fn every_addressing_failure_falls_back_with_nothing_moved() {
    let cases: Vec<AddressingCase> = vec![
        (
            "no match",
            Box::new(|_: &Path| StubDocker::without_containers()),
        ),
        (
            "several matches",
            Box::new(|dir: &Path| {
                StubDocker::with_containers(vec![
                    ("one".to_string(), bind_mounts_json(dir)),
                    ("two".to_string(), bind_mounts_json(dir)),
                ])
            }),
        ),
        (
            "docker unreachable",
            Box::new(|dir: &Path| {
                let docker = StubDocker::bound_to(dir);
                docker.fail_ps();
                docker
            }),
        ),
        (
            "inspect fails",
            Box::new(|dir: &Path| {
                let docker = StubDocker::bound_to(dir);
                docker.fail_inspect();
                docker
            }),
        ),
    ];

    for (label, build) in cases {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let docker = build(dir.path());
        let mut rotation = OpenBaoAuditRotation::with_control(
            dir.path().to_path_buf(),
            S,
            N,
            Arc::clone(&docker) as Arc<dyn DockerControl>,
        );
        let active = dir.path().join(ACTIVE_FILE_NAME);
        let captured = append_records(&active, S);
        let before_id = identity_of(&active);

        let outcome = rotation.run_pass(at(0)).await;
        assert!(outcome.rotated(), "{label}: the rotation still happened");
        assert_eq!(outcome.form, RotationForm::Fallback, "{label}");
        assert_eq!(
            outcome.consecutive_failures, 0,
            "{label}: not a failed pass"
        );
        assert!(
            docker.signalled().is_empty(),
            "{label}: nothing was signalled"
        );
        assert_eq!(
            identity_of(&active),
            before_id,
            "{label}: the active log was never renamed"
        );
        assert_eq!(len_of(&active), 0, "{label}");
        assert!(
            !rotation.marker_path().exists(),
            "{label}: no marker outlives a pass that never renamed"
        );
        let names = generation_names(dir.path());
        assert_eq!(
            len_of(&dir.path().join(names.first().expect("one generation"))),
            captured,
            "{label}"
        );
    }
}

/// A `docker kill` that exits non-zero is never read as proof that the
/// signal was not delivered: the filesystem decides, both ways.
#[tokio::test(start_paused = true)]
async fn a_failed_docker_kill_is_decided_from_the_filesystem() {
    // The signal failed and the path reopened anyway: a success.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.fail_signal();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let before_id = identity_of(&active);

    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotated(), "the exit status decides nothing");
    assert_eq!(outcome.form, RotationForm::Signal);
    assert_ne!(identity_of(&active), before_id);

    // The signal failed and the path stayed absent: the ordinary
    // recovery, then the ordinary fallback.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.fail_signal();
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let before_id = identity_of(&active);

    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotated());
    assert_eq!(outcome.form, RotationForm::Fallback);
    assert_eq!(
        identity_of(&active),
        before_id,
        "restored before the fallback"
    );
    assert_eq!(len_of(&active), 0);
    let names = generation_names(dir.path());
    assert_eq!(
        len_of(&dir.path().join(names.first().expect("one generation"))),
        captured
    );
}

/// The mount predicate itself: destination, type and a canonicalized
/// source all have to agree.
#[test]
fn only_a_bind_of_this_device_directory_at_the_container_audit_path_matches() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let other = tempfile::tempdir().expect("another directory");
    let want = std::fs::canonicalize(dir.path()).expect("the device directory canonicalizes");

    assert!(mounts_bind_device(&bind_mounts_json(dir.path()), &want));
    assert!(!mounts_bind_device(&bind_mounts_json(other.path()), &want));
    assert!(!mounts_bind_device("[]", &want));
    assert!(!mounts_bind_device("not json", &want));
    assert!(!mounts_bind_device(
        &format!(
            "[{{\"Type\":\"volume\",\"Source\":\"{}\",\"Destination\":\"{}\"}}]",
            dir.path().display(),
            OPENBAO_CONTAINER_AUDIT_DIR
        ),
        &want
    ));
    assert!(!mounts_bind_device(
        &format!(
            "[{{\"Type\":\"bind\",\"Source\":\"{}\",\"Destination\":\"/openbao/file\"}}]",
            dir.path().display()
        ),
        &want
    ));

    // A symlinked store still matches, because both sides are resolved.
    let linked = other.path().join("link-to-store");
    std::os::unix::fs::symlink(dir.path(), &linked).expect("the link is planted");
    assert!(mounts_bind_device(&bind_mounts_json(&linked), &want));
}

// ---------------------------------------------------------------------
// The marker-authorised restore's loss condition
// ---------------------------------------------------------------------

/// The marker-authorised restore is reported as a loss condition rather
/// than as a tidy recovery, and the records written to an unlinked
/// active inode are gone once its descriptor closes.
///
/// The sequence: a terminal marker removal forced to fail, the new
/// `audit.log` unlinked while `OpenBao` holds it open, a restart, the
/// marker-authorised restore, and then a reopen closing that
/// descriptor.
#[tokio::test(start_paused = true)]
async fn the_marker_authorised_restore_reports_a_loss_condition() {
    use std::io::Write as _;

    let (dir, mut rotation, _docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);

    // A confirmed reopen whose terminal marker removal fails.
    rotation.fail_marker_unlink();
    let outcome = rotation.run_pass(at(0)).await;
    assert_eq!(outcome.form, RotationForm::Signal);
    assert!(
        outcome.marker_cleanup_pending,
        "the marker outlived its rotation"
    );
    let generation = generation_names(dir.path())
        .pop()
        .expect("the rotation published one");
    let marker = rotation.marker_path().to_path_buf();
    assert!(marker.exists());

    // OpenBao holds the new active log open, and something unlinks it
    // before the next tick can clear the marker.
    let mut writer = OpenOptions::new()
        .append(true)
        .open(&active)
        .expect("OpenBao's descriptor on the new active log");
    std::fs::remove_file(&active).expect("the new active log is unlinked");
    writer
        .write_all(b"{\"written\":\"after the unlink\"}\n")
        .expect("OpenBao keeps appending to the unlinked inode");
    writer.flush().expect("the write lands");

    // The daemon restarts, losing the in-memory cleanup debt.
    drop(rotation);
    let mut restarted = rotation_at(dir.path().to_path_buf(), S, N);
    let logs = logs_from(async {
        let outcome = restarted.run_pass(at(60)).await;
        assert!(!outcome.restore_pending, "the restore itself succeeded");
    })
    .await;

    assert_eq!(
        count_lines_at(&logs, "ERROR"),
        1,
        "reported at error:\n{logs}"
    );
    assert!(
        logs.contains(&generation),
        "naming the restored generation:\n{logs}"
    );
    assert!(
        logs.contains(&active.display().to_string()),
        "and the active path:\n{logs}"
    );
    assert!(
        logs.contains("Check whether new entries are appearing in the restored"),
        "telling the operator what to check:\n{logs}"
    );
    assert!(
        logs.contains("lost the moment its descriptor closes"),
        "and naming the condition:\n{logs}"
    );

    // The restore has put a plausible `audit.log` at the configured
    // path, which is exactly how it masks the breakage.
    assert!(active.exists());
    assert!(
        !std::fs::read_to_string(&active)
            .expect("the restored log reads")
            .contains("after the unlink"),
        "the restored generation does not hold what went to the unlinked inode"
    );

    // And when the descriptor closes, those records are gone: no file
    // anywhere in the device directory holds them.
    drop(writer);
    let anywhere = std::fs::read_dir(dir.path())
        .expect("the device directory lists")
        .filter_map(std::result::Result::ok)
        .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
        .any(|body| body.contains("after the unlink"));
    assert!(
        !anywhere,
        "the records written to the unlinked inode are unreachable and then freed"
    );
}

/// The marker's lifetime is the pass's, outcome by outcome.
///
/// Removed whenever the pass ends with no rotation in flight, and kept
/// by exactly the two states that still have one.
#[tokio::test(start_paused = true)]
async fn the_marker_lives_exactly_as_long_as_its_rotation() {
    // A confirmed reopen.
    let (dir, mut rotation, _docker) = signal_fixture(S, N);
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S);
    assert_eq!(rotation.run_pass(at(0)).await.form, RotationForm::Signal);
    assert!(!rotation.marker_path().exists(), "confirmed reopen");

    // A flushed rename-back followed by a completed fallback: one
    // removal covers the pass, and the pass ends with neither.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S);
    assert_eq!(rotation.run_pass(at(0)).await.form, RotationForm::Fallback);
    assert!(
        !rotation.marker_path().exists(),
        "flushed rename-back and completed fallback"
    );

    // An abandoned fallback: the pre-truncate re-verification refuses,
    // nothing is truncated, and the marker still goes.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let shortened = active.clone();
    rotation.on_publish(move |_| {
        let file = OpenOptions::new()
            .write(true)
            .open(&shortened)
            .expect("the active log opens");
        file.set_len(16).expect("the active log is shortened");
    });
    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotation.is_unmet(), "the fallback was abandoned");
    assert_eq!(len_of(&active), 16, "nothing was truncated by this pass");
    assert!(!rotation.marker_path().exists(), "abandoned fallback");
    assert_ne!(captured, 16);

    // A rename that never happened.
    let (dir, mut rotation, _docker) = signal_fixture(S, N);
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S);
    rotation.fail_rename();
    assert_eq!(rotation.run_pass(at(0)).await.form, RotationForm::Fallback);
    assert!(
        !rotation.marker_path().exists(),
        "rename that never happened"
    );

    // A pending restore keeps it.
    let (_dir, rotation, _stranded) = strand_the_live_inode(S, N).await;
    assert!(rotation.restore_is_pending());
    assert!(rotation.marker_path().exists(), "pending restore");

    // And so does a rename-back whose flush failed.
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    docker.stops_reopening();
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S);
    rotation.fail_restore_sync();
    let outcome = rotation.run_pass(at(0)).await;
    assert!(outcome.rotation.is_unmet());
    assert!(!outcome.restore_pending);
    assert!(
        rotation.marker_path().exists(),
        "rename-back whose flush failed"
    );
}

/// The rotation-intent marker is read the way every other file in this
/// directory is opened, and neither a link, a FIFO, nor a size the
/// container chose gets past it.
///
/// The marker sits in a directory the container's audit user can write,
/// and the branch that reads it runs on a pass's blocking half — so a
/// plain `std::fs::read` there is the same three hazards the active
/// log's opens are held to, on the one path that decides whether a file
/// is renamed into place. It follows a symbolic link, so that user
/// chooses which bytes authorise the restore. It parks for ever on a
/// FIFO, taking the rotation task's ticking, its failure counter and
/// its escalation with it. And it sizes its allocation from a file
/// whose size that user chose. Each case is tampering, so each takes
/// the branch that refuses to act.
#[tokio::test]
async fn a_marker_that_is_not_this_daemon_s_own_file_refuses_to_act() {
    let cap = usize::try_from(MARKER_MAX_BYTES).expect("the cap fits a usize");
    for case in ["fifo", "symlink", "oversize"] {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let live = seed_generation(dir.path(), "20260301T115900Z", 0, S);
        let live_bytes = std::fs::read(&live).expect("the seeded generation reads");
        let name = rotated_file_name("20260301T115900Z", 0);
        let marker = dir.path().join(MARKER_FILE_NAME);
        match case {
            "fifo" => plant_fifo(&marker),
            // A marker that would authorise the restore, reached
            // through a link rather than as itself.
            "symlink" => {
                let elsewhere = dir.path().join("elsewhere.json");
                write_intent(&elsewhere, identity_of(&live), &name);
                std::os::unix::fs::symlink(&elsewhere, &marker).expect("the link is planted");
            }
            // The same marker, valid JSON to the last byte, padded past
            // the cap with the whitespace a parser ignores: uncapped,
            // this parses and moves the generation into place.
            _ => {
                let intent = RotationIntent {
                    active_dev: identity_of(&live).0,
                    active_ino: identity_of(&live).1,
                    generation: name.clone(),
                };
                let mut body = serde_json::to_vec(&intent).expect("the marker serialises");
                body.resize(body.len() + cap, b' ');
                std::fs::write(&marker, body).expect("the oversize marker is written");
            }
        }
        let mut rotation = rotation_at(dir.path().to_path_buf(), S, N);
        let active = dir.path().join(ACTIVE_FILE_NAME);

        let logs = logs_from(async {
            let outcome = returns_within("the marker's read", rotation.run_pass(at(0))).await;
            assert!(outcome.rotation.is_unmet(), "{case}");
            assert_eq!(
                outcome.consecutive_failures, 1,
                "{case}: and it escalates like any other failure"
            );
        })
        .await;
        assert_eq!(
            count_lines_at(&logs, "ERROR"),
            1,
            "{case}: one error:\n{logs}"
        );
        assert!(
            logs.contains("cannot establish which file the device is writing to"),
            "{case}:\n{logs}"
        );
        if case == "oversize" {
            assert!(
                logs.contains("cap on a rotation-intent marker"),
                "the size is what refused it, not the parse:\n{logs}"
            );
        }
        assert!(
            !active.exists(),
            "{case}: no generation was moved into place"
        );
        assert_eq!(
            std::fs::read(&live).expect("the seeded generation still reads"),
            live_bytes,
            "{case}: and the file the marker named was left where it was"
        );
    }
}

/// An active log replaced between the marker and the rename signals
/// nothing and reports no success.
///
/// The identity the marker records is what every later branch decides
/// by, and it is recorded from a file the rename is only *expected* to
/// carry aside. The device directory is writable by the container's
/// audit user, so in that window `audit.log` can be unlinked — `OpenBao`
/// keeps writing through its descriptor to the now-nameless inode — and
/// a fresh file put at the name. Left unchecked, the rename carries the
/// impostor into the generation, the `SIGHUP` closes the descriptor on
/// the real inode and frees every record on it, and the confirmation
/// compares the reopened log against the stale identity, finds it
/// differs and calls the whole thing a lossless rotation.
#[tokio::test(start_paused = true)]
async fn a_replacement_between_the_marker_and_the_rename_is_never_signalled() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let recorded = identity_of(&active);

    let replaced = active.clone();
    let stand_in = dir.path().join("replacement.log");
    let once = Arc::new(AtomicBool::new(false));
    let observed = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&observed);
    rotation.on_rename_aside(move |path| {
        assert_eq!(path, replaced, "the hook is handed the active log");
        if once.swap(true, Ordering::SeqCst) {
            return;
        }
        // Staged under a second name and renamed *over* the live log,
        // rather than unlinking it and recreating the name. While the
        // live inode is still linked its number cannot be handed out
        // again, so the replacement is a different file by
        // construction. Unlinking first would let a filesystem that
        // recycles inode numbers — most of them, ext4 among them —
        // hand back the very identity the marker recorded, and a pass
        // that carried on would be right to.
        create_active_log(&stand_in);
        *slot.lock().expect("the record lock is live") = Some(identity_of(&stand_in));
        std::fs::rename(&stand_in, &replaced).expect("the replacement takes the name");
    });

    let mut result = None;
    let logs = logs_from(async {
        result = Some(rotation.run_pass(at(0)).await);
    })
    .await;
    let outcome = result.expect("the pass returned an outcome");
    assert_ne!(
        observed
            .lock()
            .expect("the record lock is live")
            .take()
            .expect("the replacement was made"),
        recorded,
        "the replacement is a different file, which is the whole of this case"
    );
    assert!(outcome.rotation.is_unmet(), "the pass failed:\n{logs}");
    assert_eq!(outcome.form, RotationForm::None, "and rotated by no form");
    assert_eq!(outcome.consecutive_failures, 1);
    assert!(!outcome.restore_pending, "no restore was attempted");

    assert!(
        docker.signalled().is_empty(),
        "the signal is what would close OpenBao's descriptor on the displaced inode:\n{logs}"
    );
    assert_eq!(count_lines_at(&logs, "ERROR"), 1, "one error:\n{logs}");
    assert!(
        logs.contains("does not carry the identity recorded a moment earlier"),
        "{logs}"
    );
    assert!(
        !active.exists(),
        "the active path is left absent rather than restored under a name that would hide this"
    );
    let generations = generation_names(dir.path());
    let generation = dir
        .path()
        .join(generations.first().expect("the rename did happen"));
    assert_eq!(
        len_of(&generation),
        0,
        "what was renamed aside is the impostor, not the log that held the records"
    );
    assert_ne!(captured, 0);
    assert_ne!(
        identity_of(&generation),
        recorded,
        "which is exactly what the check caught"
    );
    assert!(
        rotation.marker_path().exists(),
        "the marker is kept: removing it would be acting"
    );

    // And the next tick refuses too, from the marker alone: it names a
    // file that no longer carries the identity it recorded.
    let logs = logs_from(async {
        let outcome = rotation.run_pass(at(60)).await;
        assert!(outcome.rotation.is_unmet(), "the next tick refuses too");
    })
    .await;
    assert!(
        logs.contains("no longer carries the identity it recorded"),
        "{logs}"
    );
    assert!(docker.signalled().is_empty());
    assert!(!active.exists());
}

/// A marker the daemon did not write authorises no restore, however
/// well formed it is.
///
/// `/openbao/audit` is owned and writable by the container's audit user
/// (`docker-compose.yml`), and `O_NOFOLLOW` decides which inode a name
/// resolves to rather than who wrote it. That user can therefore unlink
/// `audit.log` — `OpenBao` keeps appending to the now-nameless inode —
/// and drop a perfectly well-formed `rotation-intent.json` naming any
/// generation still on disk. Restoring from it would move an unrelated
/// historical file into place, so the absent-path signal an operator
/// and `assert_openbao_audit_log` would have seen disappears behind a
/// plausible active log while the live stream stays unreachable.
///
/// A test process cannot chown a file to another uid, so the daemon's
/// expectation moves instead of the file: with it, every marker on disk
/// is somebody else's. The same directory and the same marker are then
/// handed to a rotation without it, which restores — so what refused
/// the first pass was the ownership and nothing else about the file.
#[tokio::test(start_paused = true)]
async fn a_marker_the_daemon_did_not_write_is_never_restored_from() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let live = seed_generation(dir.path(), "20260301T115900Z", 0, S);
    let live_bytes = std::fs::read(&live).expect("the seeded generation reads");
    let name = rotated_file_name("20260301T115900Z", 0);
    let marker = dir.path().join(MARKER_FILE_NAME);
    write_intent(&marker, identity_of(&live), &name);
    let active = dir.path().join(ACTIVE_FILE_NAME);

    let mut planted = rotation_at(dir.path().to_path_buf(), S, N);
    planted.foreign_marker_owner();
    let logs = logs_from(async {
        let outcome = planted.run_pass(at(0)).await;
        assert!(outcome.rotation.is_unmet(), "the pass failed");
        assert!(!outcome.restore_pending, "and started no restore");
        assert_eq!(outcome.consecutive_failures, 1);
    })
    .await;
    assert_eq!(count_lines_at(&logs, "ERROR"), 1, "one error:\n{logs}");
    assert!(
        logs.contains("rather than this daemon's own uid"),
        "the owner is what refused it:\n{logs}"
    );
    assert!(
        logs.contains("cannot establish which file the device is writing to"),
        "on the branch that refuses to act:\n{logs}"
    );
    assert!(!active.exists(), "no generation was moved into place");
    assert_eq!(
        std::fs::read(&live).expect("the seeded generation still reads"),
        live_bytes,
        "and the file the marker named was left where it was"
    );
    assert!(marker.exists(), "the marker is kept: removing it is acting");

    // The control: the same directory, the same marker, a daemon that
    // recognises the owner. This one restores.
    drop(planted);
    let mut own = rotation_at(dir.path().to_path_buf(), S, N);
    let logs = logs_from(async {
        let outcome = own.run_pass(at(60)).await;
        assert!(!outcome.restore_pending, "the restore itself succeeded");
    })
    .await;
    assert!(
        logs.contains("authorises renaming"),
        "the marker branch was reached this time:\n{logs}"
    );
    assert!(
        active.exists(),
        "and the generation the marker named is back at the active path"
    );
    assert_eq!(
        std::fs::read(&active).expect("the restored active log reads"),
        live_bytes
    );
}

/// A generation replaced after the rename is never signalled over.
///
/// The identity check made through the pinned descriptor happens
/// immediately after the rename; the directory flush that has to land
/// before the signal is a disk round trip after it, and the device
/// directory is writable by the container's audit user throughout. A
/// replacement landing in that window has to stop the signal, because
/// the signal is what closes `OpenBao`'s descriptor on the inode this
/// pass moved aside — and once it is closed, and no name reaches that
/// inode, every record on it is gone.
#[tokio::test(start_paused = true)]
async fn a_generation_replaced_before_the_signal_stops_the_signal() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let recorded = identity_of(&active);

    let stand_in = dir.path().join("replacement.log");
    let once = Arc::new(AtomicBool::new(false));
    rotation.before_signal(move |generation| {
        if once.swap(true, Ordering::SeqCst) {
            return;
        }
        // Renamed *over* the generation rather than unlinked first, so
        // the live inode stays linked and its number cannot be handed
        // back to the replacement — the reason the sibling race test
        // gives.
        create_active_log(&stand_in);
        std::fs::rename(&stand_in, generation).expect("the replacement takes the name");
    });

    let mut result = None;
    let logs = logs_from(async {
        result = Some(rotation.run_pass(at(0)).await);
    })
    .await;
    let outcome = result.expect("the pass returned an outcome");
    assert!(outcome.rotation.is_unmet(), "the pass failed:\n{logs}");
    assert_eq!(outcome.form, RotationForm::None, "and rotated by no form");
    assert_eq!(outcome.consecutive_failures, 1);
    assert!(!outcome.restore_pending, "no restore was attempted");
    assert!(
        docker.signalled().is_empty(),
        "the signal would have closed OpenBao's descriptor on the displaced inode:\n{logs}"
    );
    assert_eq!(count_lines_at(&logs, "ERROR"), 1, "one error:\n{logs}");
    assert!(
        logs.contains("does not carry the identity recorded a moment earlier"),
        "{logs}"
    );
    assert!(!active.exists(), "and nothing was moved back over it");
    let generation = dir.path().join(
        generation_names(dir.path())
            .first()
            .expect("the rename did happen"),
    );
    assert_ne!(
        identity_of(&generation),
        recorded,
        "the name now leads to the impostor, which is what the check caught"
    );
    assert!(rotation.marker_path().exists(), "the marker is kept");
}

/// A generation replaced while the container is being signalled is
/// never reported as a rotation.
///
/// The interval between the last check and `docker kill` returning is
/// the one no ordering can close, so it is not assumed away: the stub
/// container replaces the generation and then honours the signal, which
/// is a genuine reopen. The active-path predicate alone would call that
/// a lossless rotation — a fresh inode is at the configured path, and
/// it is not the pre-rename identity — while every record the pass
/// moved aside sits on an inode no name reaches. The confirmation
/// re-checks the generation before reporting anything, so what comes
/// back is a failed pass and one `error`.
#[tokio::test(start_paused = true)]
async fn a_generation_replaced_while_the_container_is_signalled_is_never_reported_as_rotated() {
    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);
    let recorded = identity_of(&active);

    let root = dir.path().to_path_buf();
    let reopened = active.clone();
    docker.on_signal(move || {
        let generation = root.join(
            generation_names(&root)
                .first()
                .expect("the rename happened before the signal"),
        );
        let stand_in = root.join("replacement.log");
        create_active_log(&stand_in);
        std::fs::rename(&stand_in, &generation).expect("the replacement takes the name");
        // And the image honours the signal, so the active path comes
        // back on a fresh inode: everything the predicate looks at
        // says this pass succeeded.
        create_active_log(&reopened);
    });

    let mut result = None;
    let logs = logs_from(async {
        result = Some(rotation.run_pass(at(0)).await);
    })
    .await;
    let outcome = result.expect("the pass returned an outcome");
    assert_eq!(
        docker.signalled().len(),
        1,
        "the container was signalled, which is the whole of this case"
    );
    assert!(
        active.exists() && identity_of(&active) != recorded,
        "and the reopen landed, so the active-path predicate alone would report a rotation"
    );
    assert!(outcome.rotation.is_unmet(), "the pass failed:\n{logs}");
    assert_eq!(outcome.form, RotationForm::None, "and rotated by no form");
    assert_eq!(outcome.consecutive_failures, 1);
    assert!(!outcome.restore_pending, "no restore was attempted");
    assert_eq!(count_lines_at(&logs, "ERROR"), 1, "one error:\n{logs}");
    assert!(
        logs.contains("no longer carries the identity recorded before the rename"),
        "{logs}"
    );
    assert!(
        logs.contains("pinned_fd"),
        "naming the descriptor the displaced records are still reachable through:\n{logs}"
    );
    assert_ne!(captured, 0);
    assert!(rotation.marker_path().exists(), "the marker is kept");
}

/// The descriptor on a displaced generation outlives the pass that took
/// it, and every pass after it refuses to touch the device.
///
/// The refusal's whole recovery route is the daemon's `/proc/<pid>/fd`,
/// and an operator reads the line some time after it is written. A
/// descriptor closed when the pass returned would be a route that never
/// existed: `SIGHUP` has already closed `OpenBao`'s own, and the name the
/// records were under leads somewhere else, so the last thing pointing
/// at them would go with it. So the incident is held in the task's
/// state, the records stay readable through it, and the device is
/// rotated no further — the directory's contents are exactly what the
/// first pass could not account for.
#[tokio::test(start_paused = true)]
async fn a_displaced_generation_stays_reachable_after_the_pass_returns() {
    use std::os::unix::fs::{FileExt as _, MetadataExt as _};

    let (dir, mut rotation, docker) = signal_fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let recorded = identity_of(&active);
    let first_record = record(0);

    let root = dir.path().to_path_buf();
    let reopened = active.clone();
    docker.on_signal(move || {
        let generation = root.join(
            generation_names(&root)
                .first()
                .expect("the rename happened before the signal"),
        );
        let stand_in = root.join("replacement.log");
        create_active_log(&stand_in);
        std::fs::rename(&stand_in, &generation).expect("the replacement takes the name");
        create_active_log(&reopened);
    });

    let displaced = rotation.run_pass(at(0)).await;
    assert!(displaced.rotation.is_unmet(), "the pass failed");

    let incident = rotation
        .displaced_incident()
        .expect("the pass kept the descriptor it was holding");
    assert_eq!(
        incident.identity, recorded,
        "and it is the inode the marker recorded"
    );
    let meta = incident.pinned.metadata().expect("the descriptor stats");
    assert_eq!(
        (meta.dev(), meta.ino()),
        recorded,
        "still, after the pass returned: the entry was replaced, the descriptor was not"
    );
    let mut head = vec![0_u8; first_record.len()];
    incident
        .pinned
        .read_at(&mut head, 0)
        .expect("the displaced records are readable through it");
    assert_eq!(
        head,
        first_record.as_bytes(),
        "which is the route the refusal tells an operator to take"
    );
    assert_ne!(
        identity_of(
            &dir.path().join(
                generation_names(dir.path())
                    .first()
                    .expect("the generation name is still there")
            )
        ),
        recorded,
        "while the name itself leads to the impostor"
    );

    // And the next tick acts on nothing: no rename, no signal, no trim.
    append_records(&active, S);
    let before = generation_names(dir.path());
    let mut result = None;
    let logs = logs_from(async {
        result = Some(rotation.run_pass(at(60)).await);
    })
    .await;
    let halted = result.expect("the pass returned an outcome");
    assert!(halted.rotation.is_unmet(), "the pass failed again:\n{logs}");
    assert_eq!(halted.form, RotationForm::None, "by no form");
    assert_eq!(halted.consecutive_failures, 2);
    assert!(halted.retained_unmet, "and established no bound");
    assert_eq!(
        generation_names(dir.path()),
        before,
        "nothing was renamed, published or trimmed:\n{logs}"
    );
    assert_eq!(
        docker.signalled().len(),
        1,
        "and the container was not signalled again:\n{logs}"
    );
    assert!(logs.contains("rotates no further"), "{logs}");
    assert!(
        logs.contains("pinned_fd"),
        "naming the descriptor on every pass, not only the first:\n{logs}"
    );
    assert!(
        rotation.displaced_incident().is_some(),
        "and the incident is kept for the life of the task"
    );
}
