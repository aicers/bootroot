//! Read-only anomaly scanning for the registrar audit-record store.

use std::collections::{HashMap, HashSet, hash_map::Entry};
use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::{Mutex, MutexGuard, OnceLock};

use thiserror::Error;
use time::{Duration, OffsetDateTime};

use super::{
    ACTIVE_FILE_NAME, AUDIT_RECORD_VERSION, AuditPhase, AuditRecord, MAX_SERIALIZED_RECORD_BYTES,
    PathCondition, parse_rotated_name, parse_rotation_stamp,
};

/// The lookback period used by host-side audit reporting.
pub const AUDIT_SCAN_WINDOW: Duration = Duration::days(30);

/// The time an intent is allowed to wait for its outcome.
const SETTLE_GRACE: Duration = Duration::seconds(60);
const READ_BUFFER_BYTES: usize = 8_192;
/// A serialized record includes its mandatory trailing newline.
const MAX_LINE_CONTENT_BYTES: usize = MAX_SERIALIZED_RECORD_BYTES - 1;

/// The observations made while scanning an audit store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditScan {
    /// Intents older than the settle grace that have no matching outcome.
    pub intent_without_outcome: u64,
    /// Lines in the scan set that cannot be accepted as audit records.
    pub malformed_records: u64,
    /// Whether the retained generations fall short of their time target.
    pub retention_short: bool,
}

/// A failure while inspecting an audit store.
#[derive(Debug, Error)]
pub enum AuditScanError {
    /// The configured store directory is absent.
    #[error("audit store directory does not exist: {path}")]
    StoreAbsent { path: PathBuf },
    /// A path does not meet the audit store trust contract.
    #[error("unsafe audit store path {path}: {condition}")]
    UnsafePath {
        path: PathBuf,
        condition: PathCondition,
    },
    /// A path could not be read.
    #[error("could not read audit store path {path}: {source}")]
    Unreadable {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// A public scanner argument is unusable.
    #[error("invalid audit scan setting {setting}: {message}")]
    InvalidSetting {
        setting: &'static str,
        message: String,
    },
    /// The blocking filesystem task did not complete.
    #[error("the audit scan task did not join: {message}")]
    TaskJoin { message: String },
}

#[derive(Default)]
struct FileData {
    malformed: u64,
    oldest_timestamp: Option<OffsetDateTime>,
}

#[derive(Default)]
struct ScanState {
    intents: HashMap<String, OffsetDateTime>,
    outcomes: HashSet<String>,
    duplicate_lines: u64,
}

/// Scans `dir` without creating or modifying any audit-store path.
///
/// # Errors
///
/// Returns an error when the directory is absent, unsafe, unreadable, or
/// when one of the public scanner arguments is invalid.
pub fn scan_audit_store(
    dir: &Path,
    now: OffsetDateTime,
    window: Duration,
    max_retained_files: u32,
    min_retain_days: u32,
) -> Result<AuditScan, AuditScanError> {
    let (window_start, retention_floor, settle, parent) =
        validate_arguments(dir, now, window, max_retained_files, min_retain_days)?;
    let euid = crate::fs_util::current_process_euid();
    check_directory(dir, true, euid)?;
    check_directory(parent, false, euid)?;

    let mut generations = rotated_generations(dir)?;
    generations.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let retained_count =
        usize::try_from(max_retained_files).map_err(|_| AuditScanError::InvalidSetting {
            setting: "audit_max_retained_files",
            message: "does not fit this platform's usize".to_string(),
        })?;
    let first_retained = generations.len().saturating_sub(retained_count);
    let retained =
        generations
            .get(first_retained..)
            .ok_or_else(|| AuditScanError::InvalidSetting {
                setting: "audit_max_retained_files",
                message: "cannot select retained generations".to_string(),
            })?;

    let mut scan_paths = Vec::new();
    let mut prior = None;
    for (name, stamp) in retained {
        if *stamp < window_start {
            prior = Some(name.clone());
        } else {
            scan_paths.push(name.clone());
        }
    }
    if let Some(path) = prior {
        scan_paths.insert(0, path);
    }
    let active = dir.join(ACTIVE_FILE_NAME);

    let mut files = HashMap::new();
    let mut state = ScanState::default();
    for path in &scan_paths {
        let data = read_file(path, Some(&mut state), euid)?;
        files.insert(path.clone(), data);
    }
    let data = read_file(&active, Some(&mut state), euid)?;
    files.insert(active.clone(), data);

    let mut malformed = state.duplicate_lines;
    for path in &scan_paths {
        if let Some(data) = files.get(path).and_then(Option::as_ref) {
            malformed += data.malformed;
        }
    }
    if let Some(data) = files.get(&active).and_then(Option::as_ref) {
        malformed += data.malformed;
    }

    let retention_short = if retained.len() < retained_count {
        false
    } else {
        let mut oldest = None;
        for (path, _) in retained {
            if !files.contains_key(path) {
                let data = read_file(path, None, euid)?;
                files.insert(path.clone(), data);
            }
            if let Some(timestamp) = files
                .get(path)
                .and_then(Option::as_ref)
                .and_then(|data| data.oldest_timestamp)
            {
                oldest = Some(timestamp);
                break;
            }
        }
        oldest.is_some_and(|timestamp| timestamp > retention_floor)
    };

    Ok(AuditScan {
        intent_without_outcome: count_unpaired(&state, now, window_start, settle),
        malformed_records: malformed,
        retention_short,
    })
}

/// Runs [`scan_audit_store`] outside a Tokio runtime worker.
///
/// # Errors
///
/// Returns the scanner error or reports that the blocking task did not join.
pub async fn scan_audit_store_off_runtime(
    dir: &Path,
    now: OffsetDateTime,
    window: Duration,
    max_retained_files: u32,
    min_retain_days: u32,
) -> Result<AuditScan, AuditScanError> {
    let dir = dir.to_path_buf();
    tokio::task::spawn_blocking(move || {
        scan_audit_store(&dir, now, window, max_retained_files, min_retain_days)
    })
    .await
    .map_err(|error| AuditScanError::TaskJoin {
        message: error.to_string(),
    })?
}

fn validate_arguments(
    dir: &Path,
    now: OffsetDateTime,
    window: Duration,
    max_retained_files: u32,
    min_retain_days: u32,
) -> Result<(OffsetDateTime, OffsetDateTime, OffsetDateTime, &Path), AuditScanError> {
    if !dir.is_absolute() {
        return invalid("audit_record_dir", "must be an absolute path");
    }
    let parent = dir.parent().ok_or_else(|| AuditScanError::InvalidSetting {
        setting: "audit_record_dir",
        message: "must have an immediate parent directory".to_string(),
    })?;
    if !window.is_positive() {
        return invalid("window", "must be strictly positive");
    }
    if max_retained_files == 0 {
        return invalid("audit_max_retained_files", "must be greater than zero");
    }
    if min_retain_days == 0 {
        return invalid("audit_min_retain_days", "must be greater than zero");
    }
    let window_start = now
        .checked_sub(window)
        .ok_or_else(|| AuditScanError::InvalidSetting {
            setting: "window",
            message: "moves now outside OffsetDateTime's range".to_string(),
        })?;
    let retention_duration = Duration::days(i64::from(min_retain_days));
    let retention_floor =
        now.checked_sub(retention_duration)
            .ok_or_else(|| AuditScanError::InvalidSetting {
                setting: "audit_min_retain_days",
                message: "moves now outside OffsetDateTime's range".to_string(),
            })?;
    let settle = now
        .checked_sub(SETTLE_GRACE)
        .ok_or_else(|| AuditScanError::InvalidSetting {
            setting: "now",
            message: "cannot accommodate the settle grace".to_string(),
        })?;
    Ok((window_start, retention_floor, settle, parent))
}

fn invalid<T>(setting: &'static str, message: &'static str) -> Result<T, AuditScanError> {
    Err(AuditScanError::InvalidSetting {
        setting,
        message: message.to_string(),
    })
}

fn check_directory(path: &Path, store_directory: bool, euid: u32) -> Result<(), AuditScanError> {
    #[cfg(test)]
    observe_directory_check(path);

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if store_directory && source.kind() == io::ErrorKind::NotFound => {
            return Err(AuditScanError::StoreAbsent {
                path: path.to_path_buf(),
            });
        }
        Err(source) => return unreadable(path, source),
    };
    if let Some(condition) = path_condition(
        metadata.file_type().is_symlink(),
        metadata.is_dir(),
        metadata.uid(),
        metadata.mode(),
        true,
        euid,
    ) {
        return Err(AuditScanError::UnsafePath {
            path: path.to_path_buf(),
            condition,
        });
    }
    Ok(())
}

fn rotated_generations(dir: &Path) -> Result<Vec<(PathBuf, OffsetDateTime)>, AuditScanError> {
    let entries = std::fs::read_dir(dir).map_err(|source| AuditScanError::Unreadable {
        path: dir.to_path_buf(),
        source,
    })?;
    let mut generations = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| AuditScanError::Unreadable {
            path: dir.to_path_buf(),
            source,
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some((stamp, _)) = parse_rotated_name(name) else {
            continue;
        };
        let timestamp = parse_rotation_stamp(stamp)
            .expect("rotated-name parser accepts only a parsed timestamp");
        generations.push((dir.join(name), timestamp));
    }
    Ok(generations)
}

fn read_file(
    path: &Path,
    scan_state: Option<&mut ScanState>,
    euid: u32,
) -> Result<Option<FileData>, AuditScanError> {
    #[cfg(test)]
    observe_open(path);

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return unreadable(path, source),
    };
    if metadata.file_type().is_symlink() {
        return Err(AuditScanError::UnsafePath {
            path: path.to_path_buf(),
            condition: PathCondition::Symlink,
        });
    }
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) if source.raw_os_error() == Some(libc::ELOOP) => {
            return Err(AuditScanError::UnsafePath {
                path: path.to_path_buf(),
                condition: PathCondition::Symlink,
            });
        }
        Err(source) => return unreadable(path, source),
    };
    let metadata = file
        .metadata()
        .map_err(|source| AuditScanError::Unreadable {
            path: path.to_path_buf(),
            source,
        })?;
    // The descriptor decides the kind, so a path swapped between the
    // check above and the open is judged as what was actually opened.
    // That does not make either symlink refusal above redundant: this
    // one runs on a descriptor `O_NOFOLLOW` already refused to open a
    // symlink through, so it can never report `Symlink` itself, and only
    // the pre-open guard and the `ELOOP` mapping name that condition.
    if let Some(condition) = path_condition(
        metadata.file_type().is_symlink(),
        metadata.is_file(),
        metadata.uid(),
        metadata.mode(),
        false,
        euid,
    ) {
        return Err(AuditScanError::UnsafePath {
            path: path.to_path_buf(),
            condition,
        });
    }
    read_lines(&mut file, path, scan_state).map(Some)
}

/// Classifies one path's metadata against the store's trust contract.
///
/// `directory` selects the arm: the store directory and its immediate
/// parent are judged on kind, owner and mode, while an entry inside the
/// store is judged on kind alone. `euid` is passed as a value so the
/// classification is testable without the invoking process's identity.
fn path_condition(
    is_symlink: bool,
    has_expected_kind: bool,
    uid: u32,
    mode: u32,
    directory: bool,
    euid: u32,
) -> Option<PathCondition> {
    if is_symlink {
        return Some(PathCondition::Symlink);
    }
    if !has_expected_kind {
        return Some(if directory {
            PathCondition::NotADirectory
        } else {
            PathCondition::NotARegularFile
        });
    }
    // Both remaining rules are directory-only. The store's trust
    // contract places them on the store directory and its immediate
    // parent, and deliberately not on the entries inside: a directory
    // owned by root or the invoking user and writable by nobody else
    // already bounds who can create an entry in it, so a per-file owner
    // or mode check would refuse stores the contract accepts without
    // narrowing what can reach them.
    if directory {
        if uid != 0 && uid != euid {
            return Some(PathCondition::Owner {
                expected: euid,
                found: uid,
            });
        }
        if mode & 0o022 != 0 {
            return Some(PathCondition::GroupOrWorldWritable {
                mode: mode & 0o7777,
            });
        }
    }
    None
}

fn read_lines(
    file: &mut File,
    path: &Path,
    mut scan_state: Option<&mut ScanState>,
) -> Result<FileData, AuditScanError> {
    let mut data = FileData::default();
    let mut buffer = [0_u8; READ_BUFFER_BYTES];
    let mut line = Vec::new();
    let mut overlong = false;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|source| AuditScanError::Unreadable {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            if (!line.is_empty() || overlong) && scan_state.is_some() {
                data.malformed += 1;
            }
            break;
        }
        for byte in &buffer[..read] {
            if *byte == b'\n' {
                if overlong {
                    if scan_state.is_some() {
                        data.malformed += 1;
                    }
                } else {
                    classify_line(&line, &mut data, scan_state.as_deref_mut());
                }
                line.clear();
                overlong = false;
            } else if !overlong {
                if line.len() == MAX_LINE_CONTENT_BYTES {
                    overlong = true;
                    line.clear();
                } else {
                    line.push(*byte);
                }
            }
        }
    }
    Ok(data)
}

fn classify_line(line: &[u8], data: &mut FileData, scan_state: Option<&mut ScanState>) {
    let Ok(record) = serde_json::from_slice::<AuditRecord>(line) else {
        if scan_state.is_some() {
            data.malformed += 1;
        }
        return;
    };
    let malformed = record.record_version != AUDIT_RECORD_VERSION
        || matches!(
            (record.phase, record.outcome.is_some()),
            (AuditPhase::Intent | AuditPhase::Limited, true) | (AuditPhase::Outcome, false)
        )
        || (matches!(record.phase, AuditPhase::Intent | AuditPhase::Outcome)
            && (record.limited_bucket.is_some()
                || record.count.is_some()
                || record.window_start.is_some()
                || record.window_end.is_some()))
        || (record.phase == AuditPhase::Limited
            && (!record.request_id.is_empty()
                || !record.requested.service_name.is_empty()
                || !record.requested.host.is_empty()
                || record.requested.instance.is_some()
                || record.registration_id.is_some()
                || record.limited_bucket.is_none()
                || record.count.is_none_or(|count| count == 0)
                || record.window_start.is_none()
                || record.window_end.is_none()
                || record
                    .window_start
                    .zip(record.window_end)
                    .is_some_and(|(start, end)| end < start)
                || record.truncated.as_ref().is_some_and(|truncated| {
                    truncated.requested_service_name.is_some()
                        || truncated.requested_host.is_some()
                        || truncated.outcome_detail.is_some()
                })));
    if malformed {
        if scan_state.is_some() {
            data.malformed += 1;
        }
    } else {
        data.oldest_timestamp = Some(
            data.oldest_timestamp
                .map_or(record.ts, |oldest| oldest.min(record.ts)),
        );
        if let Some(state) = scan_state {
            observe_record(record, state);
        }
    }
}

fn observe_record(record: AuditRecord, state: &mut ScanState) {
    match record.phase {
        AuditPhase::Intent => match state.intents.entry(record.request_id) {
            Entry::Vacant(entry) => {
                entry.insert(record.ts);
            }
            Entry::Occupied(_) => state.duplicate_lines += 1,
        },
        AuditPhase::Outcome => {
            if !state.outcomes.insert(record.request_id) {
                state.duplicate_lines += 1;
            }
        }
        AuditPhase::Limited => {}
    }
}

fn count_unpaired(
    state: &ScanState,
    now: OffsetDateTime,
    window_start: OffsetDateTime,
    settle: OffsetDateTime,
) -> u64 {
    let unpaired = state
        .intents
        .iter()
        .filter(|(request_id, timestamp)| {
            !state.outcomes.contains(*request_id)
                && **timestamp >= window_start
                && **timestamp <= now
                && **timestamp < settle
        })
        .count();
    u64::try_from(unpaired).expect("usize fits u64")
}

fn unreadable<T>(path: &Path, source: io::Error) -> Result<T, AuditScanError> {
    Err(AuditScanError::Unreadable {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(test)]
struct OpenObserver {
    directory: PathBuf,
    counts: HashMap<PathBuf, u32>,
    directory_checks: HashMap<PathBuf, u32>,
    remove_before_open: Option<PathBuf>,
}

#[cfg(test)]
fn open_observer() -> &'static Mutex<Option<OpenObserver>> {
    static OBSERVER: OnceLock<Mutex<Option<OpenObserver>>> = OnceLock::new();
    OBSERVER.get_or_init(|| Mutex::new(None))
}

#[cfg(test)]
fn open_observer_test_lock() -> &'static Mutex<()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK.get_or_init(|| Mutex::new(()))
}

#[cfg(test)]
fn observe_open(path: &Path) {
    let mut observer = open_observer()
        .lock()
        .expect("open observer lock is not poisoned");
    let Some(observer) = observer.as_mut() else {
        return;
    };
    if path.parent() != Some(observer.directory.as_path()) {
        return;
    }
    *observer.counts.entry(path.to_path_buf()).or_default() += 1;
    if observer.remove_before_open.as_deref() == Some(path) {
        std::fs::remove_file(path).expect("test hook removes the observed generation");
        observer.remove_before_open = None;
    }
}

#[cfg(test)]
fn observe_directory_check(path: &Path) {
    let mut observer = open_observer()
        .lock()
        .expect("open observer lock is not poisoned");
    let Some(observer) = observer.as_mut() else {
        return;
    };
    if path != observer.directory {
        return;
    }
    *observer
        .directory_checks
        .entry(path.to_path_buf())
        .or_default() += 1;
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    use std::process::Command;
    use std::sync::atomic::Ordering;
    use std::time::{Duration as StdDuration, Instant};

    use super::*;
    use crate::registrar::audit::{
        AppendGate, AuditOutcome, AuditRecordStore, AuditStoreSettings, AuditVerb,
        DEFAULT_AUDIT_MAX_FILE_BYTES, RefusalReason, RequestedIdentity, canonical_timestamp,
    };

    struct TestAuditStore {
        _parent: tempfile::TempDir,
        path: PathBuf,
    }

    impl TestAuditStore {
        fn path(&self) -> &Path {
            &self.path
        }
    }

    fn audit_store() -> TestAuditStore {
        let parent = tempfile::tempdir().expect("create store parent");
        let path = parent.path().join("registrar-audit");
        fs::create_dir(&path).expect("create store directory");
        TestAuditStore {
            _parent: parent,
            path,
        }
    }

    fn identity() -> RequestedIdentity {
        RequestedIdentity {
            service_name: "api".to_string(),
            host: "host".to_string(),
            instance: None,
        }
    }

    fn append_record(dir: &Path, record: &AuditRecord) {
        let path = dir.join(ACTIVE_FILE_NAME);
        let mut bytes = if path.exists() {
            fs::read(&path).expect("read active file")
        } else {
            Vec::new()
        };
        bytes.extend(record.to_line().expect("serialize record"));
        fs::write(path, bytes).expect("write active file");
    }

    fn append_bytes(dir: &Path, bytes: &[u8]) {
        let path = dir.join(ACTIVE_FILE_NAME);
        let mut existing = fs::read(&path).unwrap_or_default();
        existing.extend(bytes);
        fs::write(path, existing).expect("write active file");
    }

    fn generation_path(dir: &Path, timestamp: OffsetDateTime, sequence: u32) -> PathBuf {
        dir.join(super::super::rotated_file_name(
            &super::super::rotation_stamp(timestamp),
            sequence,
        ))
    }

    fn old_intent(now: OffsetDateTime, request_id: &str) -> AuditRecord {
        AuditRecord::intent(
            now - Duration::minutes(2),
            request_id.to_string(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        )
    }

    fn assert_malformed_line(now: OffsetDateTime, line: &[u8]) {
        let dir = audit_store();
        append_bytes(dir.path(), line);

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan malformed line");
        assert_eq!(scan.intent_without_outcome, 0);
        assert_eq!(scan.malformed_records, 1);
    }

    struct OpenObserverGuard {
        directory: PathBuf,
        _test_lock: MutexGuard<'static, ()>,
    }

    impl OpenObserverGuard {
        fn counts(&self) -> HashMap<PathBuf, u32> {
            let observer_guard = open_observer()
                .lock()
                .expect("open observer lock is not poisoned");
            let observer = observer_guard.as_ref().expect("open observer is installed");
            assert_eq!(observer.directory, self.directory);
            observer.counts.clone()
        }

        fn directory_checks(&self) -> HashMap<PathBuf, u32> {
            let observer_guard = open_observer()
                .lock()
                .expect("open observer lock is not poisoned");
            let observer = observer_guard.as_ref().expect("open observer is installed");
            assert_eq!(observer.directory, self.directory);
            observer.directory_checks.clone()
        }
    }

    impl Drop for OpenObserverGuard {
        fn drop(&mut self) {
            let mut observer = open_observer()
                .lock()
                .expect("open observer lock is not poisoned");
            *observer = None;
        }
    }

    fn observe_opens(directory: &Path, remove_before_open: Option<PathBuf>) -> OpenObserverGuard {
        let test_lock = open_observer_test_lock()
            .lock()
            .expect("open observer test lock is not poisoned");
        let mut observer = open_observer()
            .lock()
            .expect("open observer lock is not poisoned");
        assert!(observer.is_none(), "only one test may observe opens");
        *observer = Some(OpenObserver {
            directory: directory.to_path_buf(),
            counts: HashMap::new(),
            directory_checks: HashMap::new(),
            remove_before_open,
        });
        OpenObserverGuard {
            directory: directory.to_path_buf(),
            _test_lock: test_lock,
        }
    }

    #[test]
    fn reports_an_unpaired_old_intent_and_a_malformed_line() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        append_record(
            dir.path(),
            &AuditRecord::intent(
                now - Duration::minutes(2),
                "one".to_string(),
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
            ),
        );
        let active = dir.path().join(ACTIVE_FILE_NAME);
        let mut bytes = fs::read(&active).expect("read active file");
        bytes.extend(b"not json\n");
        fs::write(&active, bytes).expect("add malformed line");

        let scan =
            scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90).expect("scan audit store");
        assert_eq!(scan.intent_without_outcome, 1);
        assert_eq!(scan.malformed_records, 1);
        assert!(!scan.retention_short);
    }

    #[test]
    fn accepts_limited_records_without_pairing_them() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        append_record(
            dir.path(),
            &AuditRecord::limited(
                now,
                AuditVerb::Mint,
                "limited-caller".to_string(),
                super::super::LimitedBucket::Admission,
                3,
                now - Duration::seconds(60),
                now,
            ),
        );
        append_record(dir.path(), &old_intent(now, "still-unpaired"));

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan limited record");
        assert_eq!(scan.malformed_records, 0);
        assert_eq!(scan.intent_without_outcome, 1);
    }

    #[test]
    fn rejects_limited_only_fields_on_intents_and_outcomes_without_pairing_side_effects() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let request_id = "paired".to_string();
        append_record(
            dir.path(),
            &AuditRecord::intent(
                now - Duration::minutes(2),
                request_id.clone(),
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
            ),
        );
        append_record(
            dir.path(),
            &AuditRecord::outcome(
                now - Duration::minutes(1),
                request_id,
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
                None,
                AuditOutcome::FirstMint,
            ),
        );

        macro_rules! append_records_with_limited_field {
            ($field:ident, $value:expr, $request_id:literal) => {{
                let mut intent = AuditRecord::intent(
                    now - Duration::minutes(2),
                    $request_id.to_string(),
                    AuditVerb::Mint,
                    "caller".to_string(),
                    identity(),
                );
                intent.$field = Some($value);
                append_record(dir.path(), &intent);

                let mut outcome = AuditRecord::outcome(
                    now - Duration::minutes(1),
                    "paired".to_string(),
                    AuditVerb::Mint,
                    "caller".to_string(),
                    identity(),
                    None,
                    AuditOutcome::FirstMint,
                );
                outcome.$field = Some($value);
                append_record(dir.path(), &outcome);
            }};
        }

        append_records_with_limited_field!(
            limited_bucket,
            super::super::LimitedBucket::Admission,
            "limited-bucket-intent"
        );
        append_records_with_limited_field!(count, 1, "count-intent");
        append_records_with_limited_field!(
            window_start,
            now - Duration::seconds(60),
            "window-start-intent"
        );
        append_records_with_limited_field!(window_end, now, "window-end-intent");

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan mixed-phase limited fields");
        assert_eq!(scan.malformed_records, 8);
        assert_eq!(scan.intent_without_outcome, 0);
    }

    #[test]
    fn rejects_invalid_json_as_a_malformed_line() {
        let now = OffsetDateTime::now_utc();
        assert_malformed_line(now, b"not JSON\n");
    }

    #[test]
    fn rejects_an_unknown_field_as_a_malformed_line() {
        let now = OffsetDateTime::now_utc();
        let line = String::from_utf8(
            old_intent(now, "unknown-field")
                .to_line()
                .expect("serialize record"),
        )
        .expect("record is UTF-8");
        assert_malformed_line(
            now,
            line.replacen('{', "{\"unexpected\":true,", 1).as_bytes(),
        );
    }

    #[test]
    fn rejects_a_wrong_record_version_as_a_malformed_line() {
        let now = OffsetDateTime::now_utc();
        let line = String::from_utf8(
            old_intent(now, "wrong-version")
                .to_line()
                .expect("serialize record"),
        )
        .expect("record is UTF-8");
        assert_malformed_line(
            now,
            line.replace("\"record_version\":1", "\"record_version\":2")
                .as_bytes(),
        );
    }

    #[test]
    fn rejects_a_missing_required_field_as_a_malformed_line() {
        let now = OffsetDateTime::now_utc();
        let line = old_intent(now, "missing-field")
            .to_line()
            .expect("serialize record");
        let mut missing_required: serde_json::Value =
            serde_json::from_slice(&line).expect("parse record JSON");
        missing_required
            .as_object_mut()
            .expect("record is an object")
            .remove("caller_identity");
        let missing_required = format!(
            "{}\n",
            serde_json::to_string(&missing_required).expect("serialize missing field")
        );
        assert_malformed_line(now, missing_required.as_bytes());
    }

    #[test]
    fn rejects_an_unterminated_final_line_as_malformed() {
        let now = OffsetDateTime::now_utc();
        let line = old_intent(now, "unterminated")
            .to_line()
            .expect("serialize record");
        let unterminated = line
            .strip_suffix(b"\n")
            .expect("serialized records end with a newline");
        assert_malformed_line(now, unterminated);
    }

    #[test]
    fn rejects_noncanonical_timestamp_spellings_as_malformed() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let line = old_intent(now, "timestamp")
            .to_line()
            .expect("serialize record");
        let mut record: serde_json::Value =
            serde_json::from_slice(&line).expect("parse serialized record");

        for timestamp in [
            "2024-01-01T00:00:00+00:00",
            "2024-01-01T00:00:00.000z",
            "2024-01-01T00:00:00.000001Z",
        ] {
            record["ts"] = serde_json::Value::String(timestamp.to_string());
            let line = format!(
                "{}\n",
                serde_json::to_string(&record).expect("serialize timestamp variant")
            );
            append_bytes(dir.path(), line.as_bytes());
        }

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan malformed timestamps");
        assert_eq!(scan.intent_without_outcome, 0);
        assert_eq!(scan.malformed_records, 3);
    }

    #[test]
    fn ignores_a_missing_active_file_as_an_empty_store() {
        let dir = audit_store();
        let scan = scan_audit_store(
            dir.path(),
            OffsetDateTime::now_utc(),
            AUDIT_SCAN_WINDOW,
            16,
            90,
        )
        .expect("scan empty store");
        assert_eq!(scan.intent_without_outcome, 0);
        assert_eq!(scan.malformed_records, 0);
        assert!(!scan.retention_short);
    }

    #[test]
    fn treats_an_empty_active_file_as_an_empty_store() {
        let dir = audit_store();
        fs::write(dir.path().join(ACTIVE_FILE_NAME), b"").expect("create empty active file");

        let scan = scan_audit_store(
            dir.path(),
            OffsetDateTime::now_utc(),
            AUDIT_SCAN_WINDOW,
            16,
            90,
        )
        .expect("scan empty active file");
        assert_eq!(scan.intent_without_outcome, 0);
        assert_eq!(scan.malformed_records, 0);
        assert!(!scan.retention_short);
    }

    #[test]
    fn reports_a_missing_store_directory_as_absent() {
        let parent = tempfile::tempdir().expect("create missing-store parent");
        let path = parent.path().join("registrar-audit");

        let error = scan_audit_store(&path, OffsetDateTime::now_utc(), AUDIT_SCAN_WINDOW, 16, 90)
            .expect_err("a missing store directory is absent");
        assert!(matches!(
            error,
            AuditScanError::StoreAbsent { path: found } if found == path
        ));
    }

    #[test]
    fn reports_an_unreadable_active_file_as_a_scan_failure() {
        let dir = audit_store();
        let active = dir.path().join(ACTIVE_FILE_NAME);
        fs::write(&active, b"{}\n").expect("create active file");
        fs::set_permissions(&active, fs::Permissions::from_mode(0o000))
            .expect("make active file unreadable");

        let error = scan_audit_store(
            dir.path(),
            OffsetDateTime::now_utc(),
            AUDIT_SCAN_WINDOW,
            16,
            90,
        )
        .expect_err("an unreadable active file is not an empty store");
        assert!(matches!(
            error,
            AuditScanError::Unreadable { path, .. } if path == active
        ));
    }

    #[test]
    fn reports_an_unlistable_store_directory_as_a_scan_failure() {
        let dir = audit_store();
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o000))
            .expect("make store directory unlistable");

        let error = scan_audit_store(
            dir.path(),
            OffsetDateTime::now_utc(),
            AUDIT_SCAN_WINDOW,
            16,
            90,
        )
        .expect_err("an unlistable store directory is not absent");
        assert!(matches!(
            error,
            AuditScanError::Unreadable { path, .. } if path == dir.path()
        ));
    }

    #[test]
    fn rejects_an_overlong_line_without_allocating_the_remainder() {
        let dir = audit_store();
        let mut line = vec![b'x'; MAX_LINE_CONTENT_BYTES + 1];
        line.push(b'\n');
        append_bytes(dir.path(), &line);

        let scan = scan_audit_store(
            dir.path(),
            OffsetDateTime::now_utc(),
            AUDIT_SCAN_WINDOW,
            16,
            90,
        )
        .expect("scan oversized line");
        assert_eq!(scan.malformed_records, 1);
        assert_eq!(scan.intent_without_outcome, 0);
    }

    #[test]
    fn settle_grace_defers_an_in_flight_intent() {
        let dir = audit_store();
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let recent = AuditRecord::intent(
            now - Duration::seconds(1),
            "recent".to_string(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        let aged = AuditRecord::intent(
            now - SETTLE_GRACE - Duration::milliseconds(1),
            "aged".to_string(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        append_record(dir.path(), &recent);
        append_record(dir.path(), &aged);

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan intents around settle grace");
        assert_eq!(scan.intent_without_outcome, 1);
    }

    #[test]
    fn counts_an_intent_that_carries_an_outcome_as_malformed() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let mut record = serde_json::to_value(old_intent(now, "contradictory"))
            .expect("serialize intent as JSON");
        record["outcome"] = serde_json::json!({"class":"first_mint"});
        let line = format!(
            "{}\n",
            serde_json::to_string(&record).expect("serialize record")
        );
        append_bytes(dir.path(), line.as_bytes());

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan contradictory record");
        assert_eq!(scan.malformed_records, 1);
        assert_eq!(scan.intent_without_outcome, 0);
    }

    #[test]
    fn counts_an_outcome_without_an_outcome_value_as_malformed() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let mut record = serde_json::to_value(old_intent(now, "missing-outcome"))
            .expect("serialize intent as JSON");
        record["phase"] = serde_json::json!("outcome");
        let line = format!(
            "{}\n",
            serde_json::to_string(&record).expect("serialize contradictory record")
        );
        append_bytes(dir.path(), line.as_bytes());

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan contradictory record");
        assert_eq!(scan.malformed_records, 1);
        assert_eq!(scan.intent_without_outcome, 0);
    }

    #[test]
    fn accepts_records_with_deliberately_omitted_optional_fields() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let request_id = "omitted-fields".to_string();
        let intent = AuditRecord::intent(
            now - Duration::minutes(2),
            request_id.clone(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        let outcome = AuditRecord::outcome(
            now - Duration::minutes(1),
            request_id,
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
            None,
            AuditOutcome::Refused {
                reason: RefusalReason::ReservedServiceName,
                detail: None,
            },
        );
        let intent_line = intent.to_line().expect("serialize intent");
        let outcome_line = outcome.to_line().expect("serialize outcome");
        let intent_text = std::str::from_utf8(&intent_line).expect("intent line is UTF-8");
        let outcome_text = std::str::from_utf8(&outcome_line).expect("outcome line is UTF-8");
        assert!(!intent_text.contains("registration_id"));
        assert!(!intent_text.contains("instance"));
        assert!(!intent_text.contains("truncated"));
        assert!(!outcome_text.contains("detail"));

        append_bytes(dir.path(), &intent_line);
        append_bytes(dir.path(), &outcome_line);
        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan records with omitted fields");
        assert_eq!(scan.malformed_records, 0);
        assert_eq!(scan.intent_without_outcome, 0);
    }

    #[tokio::test]
    async fn reads_records_written_by_the_audit_store() {
        let parent = tempfile::tempdir().expect("create store parent");
        let directory = parent.path().join("registrar-audit");
        let store = AuditRecordStore::open_for_tests(AuditStoreSettings {
            dir: directory.clone(),
            max_file_bytes: DEFAULT_AUDIT_MAX_FILE_BYTES,
            max_retained_files: 16,
        })
        .await
        .expect("open audit store");
        let now = OffsetDateTime::now_utc();

        let scan = scan_audit_store(&directory, now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan freshly opened store");
        assert_eq!(
            scan,
            AuditScan {
                intent_without_outcome: 0,
                malformed_records: 0,
                retention_short: false,
            }
        );

        store
            .append(old_intent(now, "written-by-store"))
            .await
            .expect("append audit record");
        let scan = scan_audit_store(&directory, now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan written record");
        assert_eq!(scan.intent_without_outcome, 1);
        assert_eq!(scan.malformed_records, 0);
    }

    #[tokio::test]
    async fn counts_a_durable_torn_final_line_as_one_malformed_record() {
        let parent = tempfile::tempdir().expect("create store parent");
        let directory = parent.path().join("registrar-audit");
        let store = AuditRecordStore::open_for_tests(AuditStoreSettings {
            dir: directory.clone(),
            max_file_bytes: DEFAULT_AUDIT_MAX_FILE_BYTES,
            max_retained_files: 16,
        })
        .await
        .expect("open audit store");
        let now = OffsetDateTime::now_utc();
        store
            .append(old_intent(now, "complete"))
            .await
            .expect("append complete record");
        store.faults().partial_append.store(true, Ordering::SeqCst);
        store.faults().truncate.store(true, Ordering::SeqCst);
        store
            .append(old_intent(now, "torn"))
            .await
            .expect_err("the fault-injected append cannot recover its partial line");

        let scan = scan_audit_store(&directory, now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan store with torn final line");
        assert_eq!(scan.malformed_records, 1);
        assert_eq!(scan.intent_without_outcome, 1);
    }

    #[tokio::test]
    async fn scans_a_stable_prefix_while_an_append_is_parked() {
        let parent = tempfile::tempdir().expect("create store parent");
        let directory = parent.path().join("registrar-audit");
        let store = AuditRecordStore::open_for_tests(AuditStoreSettings {
            dir: directory.clone(),
            max_file_bytes: DEFAULT_AUDIT_MAX_FILE_BYTES,
            max_retained_files: 16,
        })
        .await
        .expect("open audit store");
        let now = OffsetDateTime::now_utc();
        store
            .append(old_intent(now, "complete"))
            .await
            .expect("append complete record");

        let (gate, mut entries, releases) = AppendGate::new();
        *store.faults().gate.lock().expect("arm append gate") = Some(gate);
        let pending_store = store.clone();
        let pending =
            tokio::spawn(async move { pending_store.append(old_intent(now, "parked")).await });
        entries
            .recv()
            .await
            .expect("parked append enters its critical section");

        let scan = scan_audit_store(&directory, now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan while append is parked");
        assert_eq!(scan.intent_without_outcome, 1);
        assert_eq!(scan.malformed_records, 0);

        releases.send(()).expect("release parked append");
        pending
            .await
            .expect("parked append task completes")
            .expect("parked append succeeds");
    }

    #[test]
    fn refuses_invalid_arguments_before_opening_the_store() {
        // A relative store path is its own rejected argument, so it
        // cannot name a populated store the way the value table in
        // `rejects_public_arguments_that_cannot_define_a_scan` does.
        let relative = Path::new("relative");
        let observer = observe_opens(relative, None);
        let error = scan_audit_store(
            relative,
            OffsetDateTime::now_utc(),
            AUDIT_SCAN_WINDOW,
            16,
            90,
        )
        .expect_err("relative path is invalid");
        assert!(matches!(
            error,
            AuditScanError::InvalidSetting {
                setting: "audit_record_dir",
                ..
            }
        ));
        assert!(
            observer.counts().is_empty(),
            "a relative store path must fail before any audit file is opened"
        );
        assert!(
            observer.directory_checks().is_empty(),
            "a relative store path must fail before the directory is inspected"
        );
    }

    #[test]
    fn duplicate_intents_are_malformed_without_hiding_an_anomaly() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let record = AuditRecord::intent(
            now - Duration::minutes(2),
            "duplicate".to_string(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        append_record(dir.path(), &record);
        append_record(dir.path(), &record);

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan duplicate records");
        assert_eq!(scan.intent_without_outcome, 1);
        assert_eq!(scan.malformed_records, 1);
    }

    #[test]
    fn duplicate_intents_with_an_outcome_are_malformed_but_paired() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let request_id = "duplicate-intents-with-outcome".to_string();
        let intent = AuditRecord::intent(
            now - Duration::minutes(2),
            request_id.clone(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        append_record(dir.path(), &intent);
        append_record(dir.path(), &intent);
        append_record(
            dir.path(),
            &AuditRecord::outcome(
                now - Duration::minutes(1),
                request_id,
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
                None,
                AuditOutcome::FirstMint,
            ),
        );

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan duplicate intents with outcome");
        assert_eq!(scan.malformed_records, 1);
        assert_eq!(scan.intent_without_outcome, 0);
    }

    #[test]
    fn duplicate_outcomes_are_malformed_without_hiding_a_pair() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let request_id = "duplicate-outcomes".to_string();
        append_record(
            dir.path(),
            &AuditRecord::intent(
                now - Duration::minutes(2),
                request_id.clone(),
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
            ),
        );
        let outcome = AuditRecord::outcome(
            now - Duration::minutes(1),
            request_id,
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
            None,
            AuditOutcome::FirstMint,
        );
        append_record(dir.path(), &outcome);
        append_record(dir.path(), &outcome);

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan duplicate outcomes");
        assert_eq!(scan.malformed_records, 1);
        assert_eq!(scan.intent_without_outcome, 0);
    }

    #[test]
    fn oldest_generation_intent_is_canonical_for_duplicate_request_ids() {
        let dir = audit_store();
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let generation = generation_path(dir.path(), now - Duration::days(1), 0);
        let request_id = "cross-generation-duplicate".to_string();
        let old = AuditRecord::intent(
            now - Duration::minutes(2),
            request_id.clone(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        fs::write(&generation, old.to_line().expect("serialize old intent"))
            .expect("write rotated generation");
        append_record(
            dir.path(),
            &AuditRecord::intent(
                now,
                request_id,
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
            ),
        );

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 1, 90)
            .expect("scan cross-generation duplicate");
        assert_eq!(scan.malformed_records, 1);
        assert_eq!(scan.intent_without_outcome, 1);
    }

    #[test]
    fn orders_rotations_in_one_second_by_sequence() {
        let dir = audit_store();
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let stamp = now - Duration::days(1);
        let request_id = "same-second".to_string();
        let older = AuditRecord::intent(
            now - Duration::minutes(2),
            request_id.clone(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        let newer = AuditRecord::intent(
            now,
            request_id,
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        fs::write(
            generation_path(dir.path(), stamp, 0),
            older.to_line().expect("serialize older intent"),
        )
        .expect("write first same-second generation");
        fs::write(
            generation_path(dir.path(), stamp, 1),
            newer.to_line().expect("serialize newer intent"),
        )
        .expect("write second same-second generation");
        fs::write(dir.path().join("not-an-audit-generation"), b"not JSON\n")
            .expect("write ignored name");

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 2, 90)
            .expect("scan same-second generations");
        assert_eq!(scan.malformed_records, 1);
        assert_eq!(scan.intent_without_outcome, 1);
    }

    #[test]
    fn outcome_outside_the_window_pairs_an_in_window_intent() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let request_id = "across-window".to_string();
        append_record(
            dir.path(),
            &AuditRecord::outcome(
                now - Duration::days(31),
                request_id.clone(),
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
                None,
                AuditOutcome::FirstMint,
            ),
        );
        append_record(
            dir.path(),
            &AuditRecord::intent(
                now - Duration::minutes(2),
                request_id,
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
            ),
        );

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan paired records");
        assert_eq!(scan.intent_without_outcome, 0);
        assert_eq!(scan.malformed_records, 0);
    }

    #[test]
    fn outcome_after_now_pairs_an_in_window_intent() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let request_id = "outcome-after-now".to_string();
        append_record(
            dir.path(),
            &AuditRecord::intent(
                now - Duration::minutes(2),
                request_id.clone(),
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
            ),
        );
        append_record(
            dir.path(),
            &AuditRecord::outcome(
                now + Duration::minutes(5),
                request_id,
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
                None,
                AuditOutcome::FirstMint,
            ),
        );

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan an outcome dated after now");
        assert_eq!(
            scan.intent_without_outcome, 0,
            "an outcome dated after now still pairs its in-window intent"
        );
        assert_eq!(scan.malformed_records, 0);
    }

    #[test]
    fn pairs_an_intent_in_a_retained_generation_with_an_active_outcome() {
        let dir = audit_store();
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let request_id = "across-rotation".to_string();
        let generation = generation_path(dir.path(), now - Duration::days(1), 0);
        let intent = AuditRecord::intent(
            now - Duration::minutes(2),
            request_id.clone(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        fs::write(&generation, intent.to_line().expect("serialize intent"))
            .expect("write rotated generation");
        append_record(
            dir.path(),
            &AuditRecord::outcome(
                now - Duration::minutes(1),
                request_id,
                AuditVerb::Mint,
                "caller".to_string(),
                identity(),
                None,
                AuditOutcome::FirstMint,
            ),
        );

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 1, 90)
            .expect("scan records across a rotation");
        assert_eq!(scan.intent_without_outcome, 0);
        assert_eq!(scan.malformed_records, 0);
    }

    #[test]
    fn retention_shortfall_uses_the_oldest_parseable_record() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        let generation = dir.path().join(super::super::rotated_file_name(
            &super::super::rotation_stamp(now - Duration::days(30)),
            0,
        ));
        let record = AuditRecord::intent(
            now - Duration::days(89),
            "retention".to_string(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        fs::write(
            &generation,
            record.to_line().expect("serialize retention record"),
        )
        .expect("write rotated generation");

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 1, 90)
            .expect("scan short retention");
        assert!(scan.retention_short);

        let record = AuditRecord::intent(
            now - Duration::days(90),
            "retention-floor".to_string(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        fs::write(
            &generation,
            record.to_line().expect("serialize floor record"),
        )
        .expect("write floor generation");
        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 1, 90)
            .expect("scan retention floor");
        assert!(!scan.retention_short);
    }

    #[test]
    fn retention_probe_ignores_structurally_malformed_records() {
        let dir = audit_store();
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let oldest = generation_path(dir.path(), now - Duration::days(50), 0);
        let newer = generation_path(dir.path(), now - Duration::days(40), 0);

        let mut malformed = AuditRecord::intent(
            now - Duration::days(1),
            "wrong-version".to_string(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        malformed.record_version = AUDIT_RECORD_VERSION + 1;
        fs::write(
            &oldest,
            malformed.to_line().expect("serialize malformed record"),
        )
        .expect("write malformed retained generation");

        let record = AuditRecord::intent(
            now - Duration::days(90),
            "retention-floor".to_string(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        fs::write(
            &newer,
            record.to_line().expect("serialize retention record"),
        )
        .expect("write newer retained generation");

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 2, 90)
            .expect("scan retained generations");
        assert!(!scan.retention_short);
        assert_eq!(scan.malformed_records, 0);
    }

    #[test]
    fn retention_probe_ignores_malformed_lines_outside_the_scan_set() {
        let dir = audit_store();
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let oldest = generation_path(dir.path(), now - Duration::days(50), 0);
        let newest = generation_path(dir.path(), now - Duration::days(40), 0);
        fs::write(&oldest, b"not JSON\n").expect("write malformed probe generation");
        let record = AuditRecord::intent(
            now - Duration::days(89),
            "retention-probe".to_string(),
            AuditVerb::Mint,
            "caller".to_string(),
            identity(),
        );
        fs::write(
            &newest,
            record.to_line().expect("serialize retention record"),
        )
        .expect("write retained generation");

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 2, 90)
            .expect("scan retained generations");
        assert!(scan.retention_short);
        assert_eq!(scan.malformed_records, 0);
        assert_eq!(scan.intent_without_outcome, 0);
    }

    #[test]
    fn window_boundaries_only_count_aged_intents_inside_the_window() {
        let dir = audit_store();
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let start = now.checked_sub(AUDIT_SCAN_WINDOW).expect("window fits");
        for (request_id, timestamp) in [
            ("at-start", start),
            (
                "inside",
                start
                    .checked_add(Duration::milliseconds(1))
                    .expect("inside fits"),
            ),
            (
                "outside",
                start
                    .checked_sub(Duration::milliseconds(1))
                    .expect("outside fits"),
            ),
            ("at-now", now),
            (
                "future",
                now.checked_add(Duration::seconds(1)).expect("future fits"),
            ),
        ] {
            append_record(
                dir.path(),
                &AuditRecord::intent(
                    timestamp,
                    request_id.to_string(),
                    AuditVerb::Mint,
                    "caller".to_string(),
                    identity(),
                ),
            );
        }

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan boundary records");
        assert_eq!(scan.intent_without_outcome, 2);
        assert_eq!(scan.malformed_records, 0);
    }

    #[test]
    fn refuses_unsafe_active_entries_without_following_or_blocking() {
        let now = OffsetDateTime::now_utc();
        let outside = tempfile::NamedTempFile::new().expect("create outside file");

        let symlink_dir = audit_store();
        let symlink_path = symlink_dir.path().join(ACTIVE_FILE_NAME);
        symlink(outside.path(), &symlink_path).expect("create active-file symlink");
        let error = scan_audit_store(symlink_dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect_err("symlink must be refused");
        assert!(matches!(
            error,
            AuditScanError::UnsafePath {
                condition: PathCondition::Symlink,
                ..
            }
        ));

        let fifo_dir = audit_store();
        let fifo_path = fifo_dir.path().join(ACTIVE_FILE_NAME);
        let status = Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo must create the FIFO");
        let started = Instant::now();
        let error = scan_audit_store(fifo_dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect_err("FIFO must be refused");
        assert!(
            started.elapsed() < StdDuration::from_secs(1),
            "nonblocking open must not wait for a FIFO writer"
        );
        assert!(matches!(
            error,
            AuditScanError::UnsafePath {
                condition: PathCondition::NotARegularFile,
                ..
            }
        ));

        let directory_dir = audit_store();
        let directory_path = directory_dir.path().join(ACTIVE_FILE_NAME);
        fs::create_dir(&directory_path).expect("create active-file directory entry");
        let error = scan_audit_store(directory_dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect_err("directory must be refused");
        assert!(matches!(
            error,
            AuditScanError::UnsafePath {
                condition: PathCondition::NotARegularFile,
                path,
            } if path == directory_path
        ));
    }

    #[test]
    fn refuses_a_symlinked_store_directory() {
        let parent = tempfile::tempdir().expect("create store parent");
        let target = parent.path().join("store-target");
        fs::create_dir(&target).expect("create store target");
        let link = parent.path().join("registrar-audit");
        symlink(&target, &link).expect("create store-directory symlink");

        let error = scan_audit_store(&link, OffsetDateTime::now_utc(), AUDIT_SCAN_WINDOW, 16, 90)
            .expect_err("symlinked store directory must be refused");
        assert!(matches!(
            error,
            AuditScanError::UnsafePath {
                condition: PathCondition::Symlink,
                ..
            }
        ));
    }

    /// Pins the deliberate limit of the store's trust contract at the
    /// scanner's own surface: the entries inside a safe store are judged
    /// on kind alone, so a permissive mode on one of them is not a
    /// refusal. The classifier's file arm is asserted directly by
    /// [`path_trust_accepts_root_or_the_invoking_user_only`]; this is
    /// the end-to-end half, so re-gating that rule on the entries could
    /// not pass unnoticed.
    #[test]
    fn reads_a_group_or_world_writable_entry_inside_a_safe_store() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        append_record(dir.path(), &old_intent(now, "permissive-mode"));
        let active = dir.path().join(ACTIVE_FILE_NAME);
        fs::set_permissions(&active, fs::Permissions::from_mode(0o666))
            .expect("make the active file group- and world-writable");

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("a permissive mode on an entry is not a refusal");
        assert_eq!(scan.intent_without_outcome, 1);
        assert_eq!(scan.malformed_records, 0);
    }

    #[test]
    fn scanning_never_modifies_a_populated_store() {
        let dir = audit_store();
        let now = OffsetDateTime::now_utc();
        append_record(dir.path(), &old_intent(now, "readonly"));
        let active = dir.path().join(ACTIVE_FILE_NAME);
        let before = fs::metadata(&active).expect("inspect active file before scan");

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 16, 90)
            .expect("scan populated store");
        let after = fs::metadata(&active).expect("inspect active file after scan");
        assert_eq!(scan.intent_without_outcome, 1);
        assert_eq!(before.len(), after.len());
        assert_eq!(
            before.modified().expect("read mtime before scan"),
            after.modified().expect("read mtime after scan")
        );
    }

    #[test]
    fn refuses_unsafe_rotated_entries_without_following_or_blocking() {
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let outside = tempfile::NamedTempFile::new().expect("create outside file");

        let symlink_dir = audit_store();
        let symlink_path = generation_path(symlink_dir.path(), now - Duration::days(1), 0);
        symlink(outside.path(), &symlink_path).expect("create rotated-file symlink");
        let error = scan_audit_store(symlink_dir.path(), now, AUDIT_SCAN_WINDOW, 1, 90)
            .expect_err("symlink must be refused");
        assert!(matches!(
            error,
            AuditScanError::UnsafePath {
                condition: PathCondition::Symlink,
                ..
            }
        ));

        let fifo_dir = audit_store();
        let fifo_path = generation_path(fifo_dir.path(), now - Duration::days(1), 0);
        let status = Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo must create the FIFO");
        let started = Instant::now();
        let error = scan_audit_store(fifo_dir.path(), now, AUDIT_SCAN_WINDOW, 1, 90)
            .expect_err("FIFO must be refused");
        assert!(
            started.elapsed() < StdDuration::from_secs(1),
            "nonblocking open must not wait for a FIFO writer"
        );
        assert!(matches!(
            error,
            AuditScanError::UnsafePath {
                condition: PathCondition::NotARegularFile,
                ..
            }
        ));

        let directory = audit_store();
        let entry = generation_path(directory.path(), now - Duration::days(1), 0);
        fs::create_dir(&entry).expect("create rotated directory entry");
        let error = scan_audit_store(directory.path(), now, AUDIT_SCAN_WINDOW, 1, 90)
            .expect_err("directory must be refused");
        assert!(matches!(
            error,
            AuditScanError::UnsafePath {
                condition: PathCondition::NotARegularFile,
                ..
            }
        ));
    }

    #[test]
    fn ignores_surplus_generations_without_opening_them() {
        let dir = audit_store();
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let surplus = generation_path(dir.path(), now - Duration::days(3), 0);
        let status = Command::new("mkfifo")
            .arg(&surplus)
            .status()
            .expect("run mkfifo");
        assert!(status.success(), "mkfifo must create the surplus FIFO");
        for (days, request_id) in [(2, "retained-first"), (1, "retained-second")] {
            fs::write(
                generation_path(dir.path(), now - Duration::days(days), 0),
                old_intent(now, request_id)
                    .to_line()
                    .expect("serialize retained record"),
            )
            .expect("write retained generation");
        }

        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 2, 90)
            .expect("the scanner must not open a surplus generation");
        assert_eq!(scan.intent_without_outcome, 2);
        assert_eq!(scan.malformed_records, 0);
    }

    #[test]
    fn opens_each_selected_generation_once_and_stays_within_the_bound() {
        let dir = audit_store();
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let oldest = generation_path(dir.path(), now - Duration::days(60), 0);
        let fallback = generation_path(dir.path(), now - Duration::days(50), 0);
        let prior = generation_path(dir.path(), now - Duration::days(40), 0);
        let active = dir.path().join(ACTIVE_FILE_NAME);
        fs::write(&oldest, b"not JSON\n").expect("write malformed probe generation");
        fs::write(
            &fallback,
            old_intent(now, "probe-only")
                .to_line()
                .expect("serialize probe-only record"),
        )
        .expect("write fallback probe generation");
        fs::write(
            &prior,
            old_intent(now, "prior")
                .to_line()
                .expect("serialize prior record"),
        )
        .expect("write prior scan generation");
        append_record(dir.path(), &old_intent(now, "active"));

        let observer = observe_opens(dir.path(), None);
        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 3, 90)
            .expect("scan retained audit files");
        let counts = observer.counts();
        drop(observer);

        assert_eq!(scan.intent_without_outcome, 2);
        assert_eq!(scan.malformed_records, 0);
        assert!(scan.retention_short);
        assert_eq!(counts.len(), 4);
        assert!(
            counts.len() <= 4,
            "the scan opens at most retained plus active"
        );
        for path in [&oldest, &fallback, &prior, &active] {
            assert_eq!(counts.get(path), Some(&1), "{path:?} opens exactly once");
        }
    }

    #[test]
    fn skips_a_generation_that_vanishes_after_enumeration() {
        let dir = audit_store();
        let now = canonical_timestamp(OffsetDateTime::now_utc());
        let malformed_first = generation_path(dir.path(), now - Duration::days(60), 0);
        let malformed_second = generation_path(dir.path(), now - Duration::days(50), 0);
        let prior = generation_path(dir.path(), now - Duration::days(40), 0);
        fs::write(&malformed_first, b"not JSON\n").expect("write first malformed generation");
        fs::write(&malformed_second, b"still not JSON\n")
            .expect("write second malformed generation");
        fs::write(
            &prior,
            old_intent(now, "vanishing-prior")
                .to_line()
                .expect("serialize vanishing prior generation"),
        )
        .expect("write generation that will vanish");
        append_record(dir.path(), &old_intent(now, "active"));

        let observer = observe_opens(dir.path(), Some(prior.clone()));
        let scan = scan_audit_store(dir.path(), now, AUDIT_SCAN_WINDOW, 3, 90)
            .expect("a concurrently trimmed generation is skipped");
        let counts = observer.counts();
        drop(observer);

        assert!(!prior.exists());
        assert_eq!(scan.intent_without_outcome, 1);
        assert_eq!(scan.malformed_records, 0);
        assert!(
            !scan.retention_short,
            "the retention probe falls forward past malformed and vanished generations"
        );
        assert_eq!(counts.len(), 4);
        for path in [&malformed_first, &malformed_second, &prior] {
            assert_eq!(counts.get(path), Some(&1), "{path:?} opens exactly once");
        }
        assert_eq!(
            counts.get(&dir.path().join(ACTIVE_FILE_NAME)),
            Some(&1),
            "the active file opens exactly once"
        );
    }

    #[test]
    fn refuses_a_writable_store_directory() {
        for mode in [0o770, 0o707] {
            let dir = audit_store();
            fs::set_permissions(dir.path(), fs::Permissions::from_mode(mode))
                .expect("make store directory writable");

            let error = scan_audit_store(
                dir.path(),
                OffsetDateTime::now_utc(),
                AUDIT_SCAN_WINDOW,
                16,
                90,
            )
            .expect_err("writable store directory must be refused");
            assert!(matches!(
                error,
                AuditScanError::UnsafePath {
                    condition: PathCondition::GroupOrWorldWritable { mode: found },
                    ..
                } if found == mode
            ));
        }
    }

    #[test]
    fn refuses_a_writable_immediate_parent_directory() {
        for mode in [0o770, 0o707] {
            let parent = tempfile::tempdir().expect("create store parent");
            let store = parent.path().join("registrar-audit");
            fs::create_dir(&store).expect("create store directory");
            fs::set_permissions(parent.path(), fs::Permissions::from_mode(mode))
                .expect("make store parent writable");

            let error =
                scan_audit_store(&store, OffsetDateTime::now_utc(), AUDIT_SCAN_WINDOW, 16, 90)
                    .expect_err("writable parent directory must be refused");
            assert!(matches!(
                error,
                AuditScanError::UnsafePath {
                    condition: PathCondition::GroupOrWorldWritable { mode: found },
                    ..
                } if found == mode
            ));
        }
    }

    /// Drives the classifier as a value table, so every trust condition
    /// the scanner can refuse — the foreign owner included — is asserted
    /// whatever effective UID the run happens to have.
    #[test]
    fn path_trust_accepts_root_or_the_invoking_user_only() {
        let euid = 41;
        assert_eq!(path_condition(false, true, 0, 0o700, true, euid), None);
        assert_eq!(path_condition(false, true, euid, 0o700, true, euid), None);

        let foreign_uid = euid.checked_add(1).expect("test uid is not u32::MAX");
        assert_eq!(
            path_condition(false, true, foreign_uid, 0o700, true, euid),
            Some(PathCondition::Owner {
                expected: euid,
                found: foreign_uid,
            })
        );
        assert_eq!(
            path_condition(true, false, foreign_uid, 0o777, true, euid),
            Some(PathCondition::Symlink)
        );
        assert_eq!(
            path_condition(false, false, foreign_uid, 0o777, true, euid),
            Some(PathCondition::NotADirectory)
        );
        assert_eq!(
            path_condition(false, true, euid, 0o770, true, euid),
            Some(PathCondition::GroupOrWorldWritable { mode: 0o770 })
        );
        assert_eq!(
            path_condition(false, true, foreign_uid, 0o777, true, euid),
            Some(PathCondition::Owner {
                expected: euid,
                found: foreign_uid,
            }),
            "a foreign owner outranks the writable mode it is also refused for"
        );

        // The file arm, which `read_file` reaches for every entry it
        // opens. A symlink and a non-regular kind are refused; nothing
        // else is.
        assert_eq!(
            path_condition(true, true, 0, 0o600, false, euid),
            Some(PathCondition::Symlink)
        );
        assert_eq!(
            path_condition(true, false, foreign_uid, 0o777, false, euid),
            Some(PathCondition::Symlink),
            "a symlink outranks the non-regular kind it is also refused for"
        );
        assert_eq!(
            path_condition(false, false, 0, 0o600, false, euid),
            Some(PathCondition::NotARegularFile)
        );
        assert_eq!(path_condition(false, true, 0, 0o600, false, euid), None);
        assert_eq!(path_condition(false, true, euid, 0o600, false, euid), None);
        // The store's trust contract bounds who may create an entry by
        // the directory's owner and mode, so neither a foreign owner nor
        // a group- or world-writable mode refuses an entry inside it.
        // These are deliberate limits, not missing checks.
        assert_eq!(
            path_condition(false, true, foreign_uid, 0o600, false, euid),
            None,
            "the file arm carries no ownership check"
        );
        for mode in [0o620, 0o602, 0o666, 0o777] {
            assert_eq!(
                path_condition(false, true, euid, mode, false, euid),
                None,
                "the file arm carries no mode check ({mode:o})"
            );
        }
        assert_eq!(
            path_condition(false, false, foreign_uid, 0o777, false, euid),
            Some(PathCondition::NotARegularFile),
            "a non-regular kind outranks the conditions the file arm ignores"
        );
    }

    /// Exercises the foreign-owner refusal end to end, which needs the
    /// privilege to `chown` away from the invoking user. The refusal
    /// itself is asserted unconditionally by
    /// [`path_trust_accepts_root_or_the_invoking_user_only`], so the
    /// coverage does not depend on this test running.
    #[test]
    fn refuses_foreign_owned_directories_when_running_as_root() {
        if crate::fs_util::current_process_euid() != 0 {
            return;
        }

        let parent = tempfile::tempdir().expect("create store parent");
        let store = parent.path().join("registrar-audit");
        fs::create_dir(&store).expect("create store directory");
        for path in [&store, parent.path()] {
            let status = Command::new("chown")
                .arg("1")
                .arg(path)
                .status()
                .expect("run chown");
            assert!(status.success(), "chown must change the test owner");

            let error =
                scan_audit_store(&store, OffsetDateTime::now_utc(), AUDIT_SCAN_WINDOW, 16, 90)
                    .expect_err("a foreign-owned directory must be refused");
            assert!(matches!(
                error,
                AuditScanError::UnsafePath {
                    condition: PathCondition::Owner { .. },
                    ..
                }
            ));

            let status = Command::new("chown")
                .arg("0")
                .arg(path)
                .status()
                .expect("restore test owner");
            assert!(status.success(), "chown must restore the test owner");
        }
    }

    #[test]
    fn rejects_public_arguments_that_cannot_define_a_scan() {
        // The store is real and holds a record, so a rejection that
        // precedes any filesystem work is distinguishable from one that
        // merely coincides with a store the scanner could not have read.
        let populated = audit_store();
        append_record(
            populated.path(),
            &old_intent(OffsetDateTime::now_utc(), "must-not-be-read"),
        );

        let observer = observe_opens(populated.path(), None);
        for now in [OffsetDateTime::UNIX_EPOCH, OffsetDateTime::now_utc()] {
            for (window, retained, days, setting) in [
                (Duration::ZERO, 16, 90, "window"),
                (Duration::seconds(-1), 16, 90, "window"),
                (AUDIT_SCAN_WINDOW, 0, 90, "audit_max_retained_files"),
                (AUDIT_SCAN_WINDOW, 16, 0, "audit_min_retain_days"),
                (Duration::MAX, 16, 90, "window"),
                (AUDIT_SCAN_WINDOW, 16, u32::MAX, "audit_min_retain_days"),
            ] {
                let error = scan_audit_store(populated.path(), now, window, retained, days)
                    .expect_err("invalid scanner arguments must fail");
                assert!(matches!(
                    error,
                    AuditScanError::InvalidSetting {
                        setting: found,
                        ..
                    } if found == setting
                ));
                assert!(
                    observer.counts().is_empty(),
                    "{setting} must be rejected before any audit file is opened"
                );
                assert!(
                    observer.directory_checks().is_empty(),
                    "{setting} must be rejected before the store directory is inspected"
                );
            }
        }
        drop(observer);

        let scan = scan_audit_store(
            populated.path(),
            OffsetDateTime::now_utc(),
            AUDIT_SCAN_WINDOW,
            16,
            90,
        )
        .expect("the same store scans cleanly once its arguments are valid");
        assert_eq!(scan.intent_without_outcome, 1);

        // The parentless root is its own rejected argument, so like the
        // relative path it cannot name the populated store.
        let root = Path::new("/");
        let observer = observe_opens(root, None);
        let error = scan_audit_store(root, OffsetDateTime::now_utc(), AUDIT_SCAN_WINDOW, 16, 90)
            .expect_err("the root has no immediate parent");
        assert!(matches!(
            error,
            AuditScanError::InvalidSetting {
                setting: "audit_record_dir",
                ..
            }
        ));
        assert!(
            observer.counts().is_empty(),
            "invalid root configuration must fail before opening any audit file"
        );
        assert!(
            observer.directory_checks().is_empty(),
            "invalid root configuration must fail before inspecting the filesystem"
        );
    }
}
