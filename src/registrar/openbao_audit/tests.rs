//! Tests for the `OpenBao` audit device's in-place rotation.
//!
//! Everything here runs against a real directory under
//! `tempfile::tempdir()`, because every guarantee this module makes is a
//! filesystem guarantee: which name was published, what mode it carries,
//! which bytes survived a failure and which were destroyed. The clock is
//! a parameter of a pass rather than a reading it takes, so the
//! clock-rollback case is driven rather than waited for, and so is the
//! sequence namespace.
//!
//! The bounds used below are far under
//! [`MIN_OPENBAO_AUDIT_MAX_FILE_BYTES`] on purpose. That floor is a
//! configuration rule, enforced where a configuration is loaded; the
//! rotation itself takes the numbers it is given, and holding the tests
//! to megabyte files would buy nothing but minutes.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;

use super::*;

// ---------------------------------------------------------------------
// Fault injection
// ---------------------------------------------------------------------

/// A hook a test installs to observe or measure a pass mid-flight.
type PassHook = Arc<dyn Fn(&Path) + Send + Sync>;

/// Switches a test flips to make one step of a pass fail, and the two
/// hooks that let it look at state a pass holds for one instant.
///
/// A failed `fsync`, a failed truncate and a failed unlink cannot be
/// provoked from outside the process, and "the step returned an error"
/// is exactly the case whose handling this module is mostly about.
/// Every check that reads one is `#[cfg(test)]`, so a shipped build
/// contains neither the field nor the branch.
pub(crate) struct FaultInjection {
    /// Fail the flush of the staging copy.
    pub(crate) staging_sync: AtomicBool,
    /// Fail the flush of the directory the generation was published
    /// into.
    pub(crate) directory_sync: AtomicBool,
    /// Fail the truncate that empties the active log.
    pub(crate) truncate: AtomicBool,
    /// Fail the flush that makes that truncate durable.
    pub(crate) active_sync: AtomicBool,
    /// Index into the oldest-first trim at which every further removal
    /// fails. `usize::MAX` disarms it.
    trim_fails_from: AtomicUsize,
    /// Fail the flush that makes a trim's deletions durable.
    trim_sync: AtomicBool,
    /// Runs with the active log's path, after the size decision has
    /// been taken on it and before the copy opens it.
    before_stage: Mutex<Option<PassHook>>,
    /// Runs with the staging copy's path, after it is staged and before
    /// it is published.
    after_stage: Mutex<Option<PassHook>>,
    /// Runs with the published generation's path, after the directory
    /// flush and before the truncate.
    before_truncate: Mutex<Option<PassHook>>,
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
            before_stage: Mutex::new(None),
            after_stage: Mutex::new(None),
            before_truncate: Mutex::new(None),
        }
    }
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

    pub(crate) fn before_stage(&self) -> Option<PassHook> {
        self.before_stage
            .lock()
            .expect("the hook lock is live")
            .clone()
    }

    pub(crate) fn after_stage(&self) -> Option<PassHook> {
        self.after_stage
            .lock()
            .expect("the hook lock is live")
            .clone()
    }

    pub(crate) fn before_truncate(&self) -> Option<PassHook> {
        self.before_truncate
            .lock()
            .expect("the hook lock is live")
            .clone()
    }
}

impl OpenBaoAuditRotation {
    fn fail_trim_from(&self, index: usize) {
        self.faults.trim_fails_from.store(index, Ordering::SeqCst);
    }

    fn allow_trim(&self) {
        self.faults
            .trim_fails_from
            .store(usize::MAX, Ordering::SeqCst);
    }

    fn fail_trim_sync(&self) {
        self.faults.trim_sync.store(true, Ordering::SeqCst);
    }

    fn allow_trim_sync(&self) {
        self.faults.trim_sync.store(false, Ordering::SeqCst);
    }

    fn before_stage(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        *self
            .faults
            .before_stage
            .lock()
            .expect("the hook lock is live") = Some(Arc::new(hook));
    }

    fn on_stage(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        *self
            .faults
            .after_stage
            .lock()
            .expect("the hook lock is live") = Some(Arc::new(hook));
    }

    fn on_publish(&self, hook: impl Fn(&Path) + Send + Sync + 'static) {
        *self
            .faults
            .before_truncate
            .lock()
            .expect("the hook lock is live") = Some(Arc::new(hook));
    }

    fn passes(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.passes)
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

fn fixture(max_file_bytes: u64, max_retained_files: u32) -> (TempDir, OpenBaoAuditRotation) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let rotation =
        OpenBaoAuditRotation::new(dir.path().to_path_buf(), max_file_bytes, max_retained_files);
    (dir, rotation)
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
/// `with_default` binds the subscriber to this thread, which is where a
/// directly driven pass does its work, so nothing leaks between tests
/// running in parallel.
fn logs_from(body: impl FnOnce()) -> String {
    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
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
    tracing::subscriber::with_default(subscriber, body);
    let captured = buffer.lock().unwrap().clone();
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

// ---------------------------------------------------------------------
// Footprint
// ---------------------------------------------------------------------

/// The one hard ceiling: after every bound evaluation that completes,
/// the retained generations alone total at or under `S × N`.
///
/// Driven with an active log far larger than `S` on every round, so the
/// count bound alone could never hold it, and with no assumption about
/// write rate or prior success.
#[test]
fn hard_ceiling_holds_after_every_completed_evaluation() {
    let (dir, mut rotation) = fixture(S, N);
    let budget = retained_budget_bytes(S, N);
    for round in 0..24_i64 {
        // Three times the bound, so a generation is oversized and the
        // byte trim rather than the count is what enforces the ceiling.
        append_records(&dir.path().join(ACTIVE_FILE_NAME), S * 3);
        let outcome = rotation.run_pass(at(round * 60));
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
#[test]
fn conditional_envelope_under_the_stated_model() {
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
        let outcome = rotation.run_pass(at(round * 60));
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
#[test]
fn a_long_run_of_failed_passes_leaves_the_total_unbounded() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let budget = retained_budget_bytes(S, N);

    // A healthy set first, so what follows is measured against a
    // populated retained set rather than an empty one.
    for round in 0..4_i64 {
        append_records(&active, S + 256);
        assert!(rotation.run_pass(at(round * 60)).rotated());
    }

    rotation.faults.truncate.store(true, Ordering::SeqCst);
    for round in 4..40_i64 {
        append_records(&active, S);
        let outcome = rotation.run_pass(at(round * 60));
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
#[test]
fn a_rotation_that_could_not_trim_counts_as_unmet() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let budget = retained_budget_bytes(S, N);

    for sequence in 0..5 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    rotation.fail_trim_from(0);
    append_records(&active, S);

    let failed = rotation.run_pass(at(0));
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
    let repaired = rotation.run_pass(at(60));
    assert!(!repaired.rotated(), "no rotation was required");
    assert!(!repaired.retained_unmet);
    assert_eq!(repaired.consecutive_failures, 0);
    assert!(retained_bytes(dir.path()) <= budget);
}

/// A set left over budget by a lowered `N` is trimmed on the next pass,
/// without waiting for a rotation.
#[test]
fn a_lowered_bound_is_repaired_without_a_rotation() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    for sequence in 0..6 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S / 2);
    }
    assert_eq!(generation_names(dir.path()).len(), 6);

    let mut lowered = OpenBaoAuditRotation::new(dir.path().to_path_buf(), S, 2);
    let outcome = lowered.run_pass(at(0));
    assert!(!outcome.rotated(), "no active log, so no rotation");
    assert!(!outcome.retained_unmet);
    assert_eq!(outcome.consecutive_failures, 0);
    assert_eq!(generation_names(dir.path()).len(), 2);
    assert!(retained_bytes(dir.path()) <= retained_budget_bytes(S, 2));
}

/// The plain case: an active log driven past `S` becomes a generation
/// and the active log is emptied. No device-level total is asserted.
#[test]
fn an_active_log_past_the_bound_is_rotated() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let captured = append_records(&active, S);

    let outcome = rotation.run_pass(at(0));
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
#[test]
fn a_trailing_partial_record_is_destroyed_rather_than_carried_in() {
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

    assert!(rotation.run_pass(at(0)).rotated());
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
#[test]
fn the_publish_is_ordered_and_each_pre_commit_failure_unlinks_the_copy() {
    for fault in ["staging_sync", "directory_sync", "truncate"] {
        let (dir, mut rotation) = fixture(S, N);
        let active = dir.path().join(ACTIVE_FILE_NAME);
        append_records(&active, S);
        let before = std::fs::read(&active).expect("the active log reads");

        match fault {
            "staging_sync" => rotation.faults.staging_sync.store(true, Ordering::SeqCst),
            "directory_sync" => rotation.faults.directory_sync.store(true, Ordering::SeqCst),
            _ => rotation.faults.truncate.store(true, Ordering::SeqCst),
        }

        let outcome = rotation.run_pass(at(0));
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
    rotation.faults.active_sync.store(true, Ordering::SeqCst);
    let outcome = rotation.run_pass(at(0));
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
#[test]
fn a_staging_path_replaced_before_the_publish_is_refused() {
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

    let outcome = rotation.run_pass(at(0));
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
#[test]
fn a_publish_never_overwrites_an_existing_generation() {
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

    let outcome = rotation.run_pass(at(0));
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
#[test]
fn a_generation_replaced_after_the_publish_is_refused_before_the_truncate() {
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

    let outcome = rotation.run_pass(at(0));
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
#[test]
fn an_active_log_swapped_for_another_regular_file_is_refused_at_the_truncate() {
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

    let outcome = rotation.run_pass(at(0));
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
#[test]
fn a_failure_past_the_commit_point_keeps_the_generation_and_still_trims() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let budget = retained_budget_bytes(S, N);

    // Over budget before the pass, so the trim has work of its own.
    for sequence in 0..6 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    let captured = append_records(&active, S);
    rotation.faults.active_sync.store(true, Ordering::SeqCst);

    let logs = logs_from(|| {
        let outcome = rotation.run_pass(at(0));
        assert!(outcome.rotation.is_unmet(), "the flush failure is owed");
        assert_eq!(outcome.consecutive_failures, 1);
        assert!(
            !outcome.retained_unmet,
            "the trim in the same pass reached the bound"
        );
    });
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
    rotation.faults.active_sync.store(false, Ordering::SeqCst);
    append_records(&active, S);
    let next = rotation.run_pass(at(60));
    assert!(next.rotated());
    assert_eq!(next.consecutive_failures, 0);
}

/// A trim is never rolled back: deletions already made stay made, and
/// the next pass resumes from wherever the failed one reached.
#[test]
fn a_partial_trim_is_not_rolled_back() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    for sequence in 0..6 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S / 4);
    }
    let mut rotation = OpenBaoAuditRotation::new(dir.path().to_path_buf(), S, 2);
    rotation.fail_trim_from(2);

    let partial = rotation.run_pass(at(0));
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
    let resumed = rotation.run_pass(at(60));
    assert!(!resumed.retained_unmet);
    assert_eq!(resumed.consecutive_failures, 0);
    assert_eq!(generation_names(dir.path()).len(), 2);
}

/// A captured prefix with no newline at all yields no generation and
/// leaves the active log untouched — while the retained-set bound is
/// still evaluated, so an over-budget set seeded beforehand is trimmed.
#[test]
fn a_prefix_with_no_record_boundary_skips_the_rotation_but_still_trims() {
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

    let logs = logs_from(|| {
        let outcome = rotation.run_pass(at(0));
        assert!(
            outcome.rotation.is_unmet(),
            "the rotation was owed and skipped"
        );
        assert!(!outcome.rotated());
        assert!(!outcome.retained_unmet, "the set was still trimmed");
    });
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
#[test]
fn the_trim_enforces_bytes_and_not_only_the_count() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    // Each half again as large as `S`, which is what a periodic check
    // legitimately produces: two fit the four-generation budget and
    // three do not, although all three fit it by count.
    for sequence in 0..3 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S + S / 2);
    }
    let mut rotation = OpenBaoAuditRotation::new(dir.path().to_path_buf(), S, 4);
    assert_eq!(generation_names(dir.path()).len(), 3, "within N by count");
    assert!(retained_bytes(dir.path()) > retained_budget_bytes(S, 4));

    let outcome = rotation.run_pass(at(0));
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
#[test]
fn a_generation_larger_than_the_whole_budget_is_dropped_whole() {
    let budget = retained_budget_bytes(S, 2);

    // Seeded: the oversized generation is already there.
    let dir = tempfile::tempdir().expect("a temporary directory");
    let seeded = seed_generation(dir.path(), "20260301T115900Z", 0, budget * 3);
    let seeded_len = len_of(&seeded);
    let mut rotation = OpenBaoAuditRotation::new(dir.path().to_path_buf(), S, 2);
    let logs = logs_from(|| {
        let outcome = rotation.run_pass(at(0));
        assert!(!outcome.retained_unmet);
    });
    assert!(generation_names(dir.path()).is_empty());
    assert!(logs.contains(&seeded_len.to_string()), "the size is logged");
    assert!(logs.contains(&budget.to_string()), "the budget is logged");

    // Published by this very pass: the usual way the state arises.
    let (fresh, mut rotation) = fixture(S, 2);
    let active = fresh.path().join(ACTIVE_FILE_NAME);
    append_records(&active, budget * 3);
    let logs = logs_from(|| {
        let outcome = rotation.run_pass(at(0));
        assert!(outcome.rotated(), "the rotation itself completed");
        assert!(
            !outcome.retained_unmet,
            "and the ceiling was re-established"
        );
    });
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
#[test]
fn generations_are_named_and_ordered_by_an_always_present_sequence() {
    let (dir, mut rotation) = fixture(S, 16);
    let active = dir.path().join(ACTIVE_FILE_NAME);

    append_records(&active, S);
    assert!(rotation.run_pass(at(0)).rotated());
    append_records(&active, S);
    assert!(rotation.run_pass(at(0)).rotated());
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
    assert!(rotation.run_pass(at(0)).rotated());
    assert_eq!(
        generation_names(dir.path()),
        vec![
            rotated_file_name("20260301T120000Z", 1),
            rotated_file_name("20260301T120000Z", 2),
        ]
    );

    // And across a second boundary the sort is still creation order.
    append_records(&active, S);
    assert!(rotation.run_pass(at(1)).rotated());
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
#[test]
fn a_clock_stepped_backwards_cannot_reorder_the_set() {
    let (dir, mut rotation) = fixture(S, 8);
    let active = dir.path().join(ACTIVE_FILE_NAME);

    append_records(&active, S);
    assert!(rotation.run_pass(at(0)).rotated());
    let first = generation_names(dir.path());
    let earliest = first.first().cloned().expect("a first generation");

    // An hour backwards, which is what an NTP step or a manual
    // correction produces.
    append_records(&active, S);
    assert!(rotation.run_pass(at(-3600)).rotated());
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
    assert!(rotation.run_pass(at(-3600)).rotated());
    let published = generation_names(dir.path());
    let mut tightened = OpenBaoAuditRotation::new(dir.path().to_path_buf(), S, 2);
    assert!(!tightened.run_pass(at(-3600)).retained_unmet);
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
    let mut rotation = OpenBaoAuditRotation::new(exhausted.path().to_path_buf(), S, 4);
    let active = exhausted.path().join(ACTIVE_FILE_NAME);
    append_records(&active, S);
    let before = std::fs::read(&active).expect("the active log reads");
    let logs = logs_from(|| {
        let outcome = rotation.run_pass(at(-3600));
        assert!(outcome.rotation.is_unmet());
        assert!(!outcome.rotated());
    });
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
#[test]
fn the_ceiling_wins_over_the_retention_age() {
    let (dir, mut rotation) = fixture(S, 2);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    let mut published = Vec::new();
    for round in 0..3_i64 {
        append_records(&active, S);
        assert!(rotation.run_pass(at(round)).rotated());
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
#[test]
fn staging_copies_and_generations_carry_the_directory_owner_at_mode_0600() {
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

    assert!(rotation.run_pass(at(0)).rotated());

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
#[test]
fn an_active_log_replaced_by_a_symlink_is_refused_rather_than_followed() {
    let elsewhere = tempfile::tempdir().expect("a temporary directory");

    // A target at or over `S`, which is the case that would reach the
    // copy and the truncate.
    let (dir, mut rotation) = fixture(S, N);
    let target = elsewhere.path().join("not-the-audit-log");
    let target_len = append_records(&target, S);

    std::os::unix::fs::symlink(&target, dir.path().join(ACTIVE_FILE_NAME))
        .expect("the link is planted");

    let outcome = rotation.run_pass(at(0));
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

    let logs = logs_from(|| {
        let outcome = rotation.run_pass(at(0));
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
    });
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

    let logs = logs_from(|| {
        let outcome = rotation.run_pass(at(0));
        assert!(
            outcome.rotation.is_unmet(),
            "a broken link is tampering, not an unprovisioned host"
        );
        assert_eq!(outcome.consecutive_failures, 1);
    });
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
#[test]
fn an_active_log_replaced_after_the_size_check_is_refused_at_each_open() {
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

    let outcome = returns_within("the copy's open", move || rotation.run_pass(at(0)));
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

    let outcome = returns_within("the truncate's open", move || rotation.run_pass(at(0)));
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

/// Runs `body` on a thread of its own and returns what it produced, or
/// fails the test naming `label` when it did not return in time.
fn returns_within<R: Send + 'static>(label: &str, body: impl FnOnce() -> R + Send + 'static) -> R {
    let (done, waiter) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        let value = body();
        done.send(()).ok();
        value
    });
    match waiter.recv_timeout(HANG_DEADLINE) {
        Ok(()) => handle.join().expect("the pass does not panic"),
        // The sender was dropped without sending, so the body panicked.
        // Joining republishes that panic rather than reporting it as a
        // hang.
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            handle.join().expect("the pass does not panic");
            unreachable!("a body that dropped the sender without sending panicked")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
            "{label} never returned: it is parked on the planted FIFO, and the rotation task it \
             runs inside would tick, retry and escalate never again"
        ),
    }
}

/// Generations sit in the device's own directory beside the active log,
/// and a pass creates no directory at all.
#[test]
fn a_pass_creates_no_directory_and_publishes_beside_the_active_log() {
    let (dir, mut rotation) = fixture(S, N);
    append_records(&dir.path().join(ACTIVE_FILE_NAME), S);
    assert!(rotation.run_pass(at(0)).rotated());

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
#[test]
fn consecutive_failures_warn_per_pass_and_escalate_at_each_multiple() {
    let (dir, mut rotation) = fixture(S, N);
    let active = dir.path().join(ACTIVE_FILE_NAME);
    rotation.faults.truncate.store(true, Ordering::SeqCst);

    // Appended once rather than per round: the run of failures is what
    // this test is about, and a log that grew past the whole retained
    // budget would bring the pathological-generation warning with it.
    append_records(&active, S);
    let logs = logs_from(|| {
        for round in 0..12_i64 {
            let outcome = rotation.run_pass(at(round * 60));
            assert!(outcome.rotation.is_unmet());
        }
    });
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

    rotation.faults.truncate.store(false, Ordering::SeqCst);
    let recovered = logs_from(|| {
        let outcome = rotation.run_pass(at(12 * 60));
        assert!(outcome.rotated());
        assert_eq!(outcome.consecutive_failures, 0);
    });
    assert_eq!(count_lines_at(&recovered, "ERROR"), 0);
    assert_eq!(count_lines_at(&recovered, "WARN"), 0);
}

/// A pass with no unmet obligation of either kind neither increments
/// nor escalates, on a quiet host and on one where the gate is on but
/// nothing was ever provisioned — and the same hosts seeded over budget
/// are repaired and reset, or escalate when the trim is forced to fail.
#[test]
fn a_pass_with_nothing_owed_never_increments_or_escalates() {
    let ticks = i64::from(FAILURE_ESCALATION_THRESHOLD) * 4;

    // A quiet host: an active log that never reaches S.
    let (quiet, mut rotation) = fixture(S, N);
    append_records(&quiet.path().join(ACTIVE_FILE_NAME), S / 4);
    let logs = logs_from(|| {
        for round in 0..ticks {
            let outcome = rotation.run_pass(at(round * 60));
            assert!(outcome.evaluated);
            assert_eq!(outcome.consecutive_failures, 0);
        }
    });
    assert_eq!(count_lines_at(&logs, "WARN"), 0, "{logs}");
    assert_eq!(count_lines_at(&logs, "ERROR"), 0, "{logs}");

    // A host where the gate is on and nothing backs it.
    let (bare, mut rotation) = fixture(S, N);
    let logs = logs_from(|| {
        for round in 0..ticks {
            let outcome = rotation.run_pass(at(round * 60));
            assert!(outcome.evaluated, "the directory is there");
            assert_eq!(outcome.consecutive_failures, 0);
        }
    });
    assert_eq!(count_lines_at(&logs, "WARN"), 0, "{logs}");
    assert_eq!(count_lines_at(&logs, "ERROR"), 0, "{logs}");
    drop(bare);

    // The same quiet host with an over-budget set: trimmed back inside
    // and reset, with no rotation ever required.
    for sequence in 0..8 {
        seed_generation(quiet.path(), "20260301T115900Z", sequence, S);
    }
    let mut rotation = OpenBaoAuditRotation::new(quiet.path().to_path_buf(), S, N);
    let logs = logs_from(|| {
        let outcome = rotation.run_pass(at(0));
        assert!(!outcome.rotated());
        assert!(!outcome.retained_unmet);
        assert_eq!(outcome.consecutive_failures, 0);
    });
    assert_eq!(count_lines_at(&logs, "WARN"), 0, "{logs}");

    // And with the trim forced to fail it increments and escalates,
    // although no rotation was ever required.
    for sequence in 8..16 {
        seed_generation(quiet.path(), "20260301T115900Z", sequence, S);
    }
    let mut rotation = OpenBaoAuditRotation::new(quiet.path().to_path_buf(), S, N);
    rotation.fail_trim_from(0);
    let logs = logs_from(|| {
        for round in 0..i64::from(FAILURE_ESCALATION_THRESHOLD) {
            let outcome = rotation.run_pass(at(round * 60));
            assert!(!outcome.rotated(), "no rotation was ever required");
            assert!(outcome.retained_unmet);
        }
    });
    assert_eq!(count_lines_at(&logs, "ERROR"), 1, "{logs}");
    assert!(logs.contains("retained-set bound"));
}

/// A missing active log is a no-op, said once rather than once a tick,
/// and an absent device directory leaves the pass with nothing
/// evaluated at all.
#[test]
fn a_missing_active_log_is_a_no_op_and_an_absent_directory_evaluates_nothing() {
    let (dir, mut rotation) = fixture(S, N);
    let logs = logs_from(|| {
        for round in 0..20_i64 {
            let outcome = rotation.run_pass(at(round * 60));
            assert!(outcome.evaluated);
            assert!(!outcome.rotation.is_unmet());
            assert_eq!(outcome.active_bytes, 0);
        }
    });
    assert_eq!(
        logs.matches("no active log").count(),
        1,
        "said once per process, never once per tick:\n{logs}"
    );
    assert_eq!(count_lines_at(&logs, "WARN"), 0);

    // Even so, an over-budget set on such a host is trimmed rather than
    // stranded.
    for sequence in 0..8 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    let outcome = rotation.run_pass(at(0));
    assert!(!outcome.retained_unmet);
    assert!(retained_bytes(dir.path()) <= retained_budget_bytes(S, N));

    // An absent directory evaluates nothing.
    let absent = tempfile::tempdir().expect("a temporary directory");
    let missing = absent.path().join("openbao");
    let mut rotation = OpenBaoAuditRotation::new(missing, S, N);
    let logs = logs_from(|| {
        for round in 0..20_i64 {
            let outcome = rotation.run_pass(at(round * 60));
            assert!(!outcome.evaluated);
            assert_eq!(outcome.consecutive_failures, 0);
        }
    });
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
#[test]
fn a_device_directory_that_is_not_a_directory_is_a_failed_pass() {
    let parent = tempfile::tempdir().expect("a temporary directory");

    // A regular file where the device directory should be.
    let as_file = parent.path().join("openbao");
    append_records(&as_file, 1);
    let mut rotation = OpenBaoAuditRotation::new(as_file, S, N);
    let logs = logs_from(|| {
        for round in 0..FAILURE_ESCALATION_THRESHOLD {
            let outcome = rotation.run_pass(at(i64::from(round) * 60));
            assert!(outcome.evaluated, "a fault is not nothing to evaluate");
            assert!(
                outcome.retained_unmet,
                "a set that cannot be listed cannot be asserted to be inside its bound"
            );
            assert_eq!(outcome.consecutive_failures, round + 1);
        }
    });
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
    let mut rotation = OpenBaoAuditRotation::new(beneath, S, N);
    let logs = logs_from(|| {
        let outcome = rotation.run_pass(at(0));
        assert!(outcome.evaluated);
        assert!(outcome.retained_unmet);
        assert_eq!(outcome.consecutive_failures, 1);
    });
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
#[test]
fn a_symlinked_device_directory_is_refused_rather_than_followed() {
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
    let mut rotation = OpenBaoAuditRotation::new(linked, S, N);

    let logs = logs_from(|| {
        let outcome = rotation.run_pass(at(0));
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
    });
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
    let mut rotation = OpenBaoAuditRotation::new(dangling, S, N);

    let logs = logs_from(|| {
        for round in 0..FAILURE_ESCALATION_THRESHOLD {
            let outcome = rotation.run_pass(at(i64::from(round) * 60));
            assert!(
                outcome.evaluated,
                "a broken link is tampering, not an unprovisioned host"
            );
            assert!(outcome.retained_unmet);
            assert_eq!(outcome.consecutive_failures, round + 1);
        }
    });
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
#[test]
fn a_trim_whose_flush_failed_stays_unmet_until_a_later_flush_succeeds() {
    let (dir, mut rotation) = fixture(S, N);
    for sequence in 0..8 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    rotation.fail_trim_sync();

    let mut trimmed = Vec::new();
    let logs = logs_from(|| {
        for round in 0..FAILURE_ESCALATION_THRESHOLD {
            let outcome = rotation.run_pass(at(i64::from(round) * 60));
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
    });
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
    let repaired = rotation.run_pass(at(i64::from(FAILURE_ESCALATION_THRESHOLD) * 60));
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
#[test]
fn the_trim_flush_debt_is_owed_again_by_a_new_rotation_instance() {
    let (dir, mut rotation) = fixture(S, N);
    for sequence in 0..8 {
        seed_generation(dir.path(), "20260301T115900Z", sequence, S);
    }
    rotation.fail_trim_sync();
    let first = rotation.run_pass(at(0));
    assert!(first.trim_flush_pending);
    assert!(first.retained_unmet);
    let trimmed = generation_names(dir.path());
    assert!(trimmed.len() <= usize::try_from(N).unwrap());
    // The daemon goes away with the debt still outstanding.
    drop(rotation);

    // What the new task can see is a set already inside both bounds,
    // which nothing it did put there and no listing can tell apart
    // from one whose deletions reached the disk.
    let mut restarted = OpenBaoAuditRotation::new(dir.path().to_path_buf(), S, N);
    restarted.fail_trim_sync();
    let logs = logs_from(|| {
        for round in 0..FAILURE_ESCALATION_THRESHOLD {
            let outcome = restarted.run_pass(at(i64::from(round + 1) * 60));
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
    });
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
    let repaired = restarted.run_pass(at(i64::from(FAILURE_ESCALATION_THRESHOLD + 1) * 60));
    assert!(
        !repaired.trim_flush_pending,
        "a flush that succeeded discharges the inherited debt"
    );
    assert!(!repaired.retained_unmet);
    assert_eq!(repaired.consecutive_failures, 0);
}

/// The runtime budget helper is total, and the expression validation
/// refuses an overflow of is the one that can overflow.
#[test]
fn the_budget_arithmetic_is_total_at_runtime_and_checked_at_validation() {
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

    rotation.faults.truncate.store(true, Ordering::SeqCst);
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    rotation.on_publish(move |_| {
        let _ = tx.send(());
    });
    let passes = rotation.passes();

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let handle = tokio::spawn(run_rotation_loop(
        rotation,
        Duration::from_millis(2),
        shutdown_rx,
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

/// Rotates a live deployment's file audit device in place.
///
/// Ignored, and driven by `scripts/impl/run-registrar-internal-init-e2e.sh`
/// against the pinned `OpenBao` image with the device bind-mounted out
/// of the shared audit store. It is the only place the mechanism meets
/// the real writer: nothing here restarts, reseals or signals the
/// container, and the harness asserts around this test that `StartedAt`,
/// `RestartCount` and `Pid` did not move and that the seal status did
/// not change.
///
/// The bounds are derived from the live log rather than from the
/// shipped defaults, because a 64 MiB floor would need 64 MiB of audit
/// traffic before anything rotated.
#[tokio::test]
#[ignore = "requires a provisioned OpenBao audit device on the host"]
async fn a_live_openbao_audit_device_rotates_in_place() {
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

    let bound = (before.len() / 2).max(1);
    let mut rotation = OpenBaoAuditRotation::new(dir.clone(), bound, 7);
    let outcome = rotation.run_pass(OffsetDateTime::now_utc());
    assert!(outcome.rotated(), "the live device was rotated");
    assert!(!outcome.retained_unmet, "and its retained set is bounded");

    let names = generation_names(&dir);
    let published = dir.join(names.last().expect("a published generation"));
    assert_complete_json_lines(&published);
    let generation = std::fs::metadata(&published).expect("the generation stats");
    assert_eq!(
        generation.permissions().mode() & 0o7777,
        GENERATION_FILE_MODE
    );
    let owner = std::fs::metadata(&dir).expect("the device directory stats");
    assert_eq!(
        (generation.uid(), generation.gid()),
        (owner.uid(), owner.gid())
    );

    let after = std::fs::metadata(&active).expect("the active log stats");
    assert_eq!(after.len(), 0, "the active log was emptied");
    assert_eq!(after.ino(), before.ino(), "and never replaced");
    assert_eq!(after.permissions().mode(), before.permissions().mode());
    assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));

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
