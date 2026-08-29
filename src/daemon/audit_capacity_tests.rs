//! Tests for the audit-store capacity and record signals the daemon
//! writes onto the shared health snapshot each maintenance tick.
//!
//! Every case runs under `tempfile::tempdir()`; nothing here writes to a
//! fixed path, mutates the process environment or reaches the network.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use tempfile::TempDir;
use time::{Duration, OffsetDateTime};

use super::{AuditCapacityInputs, refresh_registrar_audit_capacity};
use crate::config::AuditStoreEnforcement;
use crate::registrar::audit::scan::{AUDIT_SCAN_WINDOW, scan_audit_store};
use crate::registrar::audit::{ACTIVE_FILE_NAME, AuditRecord, AuditVerb, RequestedIdentity};
use crate::registrar::audit_store::capacity::AuditCapacityState;
use crate::registrar::endpoint::protocol::{AuditCapacityHealth, RegistrarHealth};

const RESERVE: u64 = 2_147_483_648;
const LOW_WATER: u64 = 536_870_912;
const MAX_RETAINED: u32 = 2;
const MIN_RETAIN_DAYS: u32 = 90;

type Snapshot = Arc<StdMutex<RegistrarHealth>>;

/// A store laid out the way the daemon reads it: the capacity walk sees
/// `audit_store_dir` as a whole, the record scan sees `records/` inside
/// it.
struct StoreFixture {
    _parent: TempDir,
    store_dir: PathBuf,
    record_dir: PathBuf,
}

fn store_fixture() -> StoreFixture {
    let parent = tempfile::tempdir().expect("a temporary directory");
    let store_dir = parent.path().join("audit-store");
    let record_dir = store_dir.join("records");
    std::fs::create_dir_all(&record_dir).expect("the store layout is created");
    std::fs::create_dir(store_dir.join("openbao")).expect("the device directory is created");
    StoreFixture {
        _parent: parent,
        store_dir,
        record_dir,
    }
}

fn inputs_for(fixture: &StoreFixture, enforcement: AuditStoreEnforcement) -> AuditCapacityInputs {
    AuditCapacityInputs {
        store_dir: fixture.store_dir.clone(),
        record_dir: fixture.record_dir.clone(),
        enforcement,
        reserve_bytes: RESERVE,
        low_water_bytes: LOW_WATER,
        max_retained_files: MAX_RETAINED,
        min_retain_days: MIN_RETAIN_DAYS,
    }
}

/// The snapshot the daemon builds before the endpoint can answer
/// anything: configured members present, measured members absent.
fn cold_snapshot(enforcement: AuditStoreEnforcement) -> Snapshot {
    Arc::new(StdMutex::new(RegistrarHealth {
        audit_capacity: AuditCapacityHealth {
            state: AuditCapacityState::Unknown,
            enforcement,
            reserve_bytes: RESERVE,
            low_water_bytes: LOW_WATER,
            ..AuditCapacityHealth::default()
        },
        ..RegistrarHealth::default()
    }))
}

fn capacity_of(health: &Snapshot) -> AuditCapacityHealth {
    health
        .lock()
        .expect("the snapshot lock is not poisoned")
        .audit_capacity
        .clone()
}

fn identity() -> RequestedIdentity {
    RequestedIdentity {
        service_name: "api".to_string(),
        host: "host".to_string(),
        instance: None,
    }
}

fn append_line(path: &Path, bytes: &[u8]) {
    let mut existing = std::fs::read(path).unwrap_or_default();
    existing.extend_from_slice(bytes);
    std::fs::write(path, existing).expect("the audit line is appended");
}

fn append_record(path: &Path, record: &AuditRecord) {
    append_line(path, &record.to_line().expect("the record serializes"));
}

fn paired_record(now: OffsetDateTime, request_id: &str) -> AuditRecord {
    AuditRecord::intent(
        now - Duration::minutes(2),
        request_id.to_string(),
        AuditVerb::Mint,
        "caller".to_string(),
        identity(),
    )
}

/// Composes a rotated generation's name the way the store spells it.
fn rotated_name(stamp: &str, sequence: u32) -> String {
    format!("registrar-audit-{stamp}-{sequence:06}.jsonl")
}

fn rotation_stamp(now: OffsetDateTime) -> String {
    let utc = now.to_offset(time::UtcOffset::UTC);
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

/// Rewrites the configured members the way the daemon does when it
/// builds the snapshot, so a test can move the thresholds between ticks.
fn set_thresholds(health: &Snapshot, inputs: &AuditCapacityInputs) {
    let mut snapshot = health.lock().expect("the snapshot lock is not poisoned");
    snapshot.audit_capacity.reserve_bytes = inputs.reserve_bytes;
    snapshot.audit_capacity.low_water_bytes = inputs.low_water_bytes;
}

/// Runs one maintenance tick's worth of work against the snapshot.
async fn tick(health: &Snapshot, inputs: &AuditCapacityInputs, now: OffsetDateTime) {
    refresh_registrar_audit_capacity(health, inputs, now).await;
}

#[tokio::test]
async fn a_tick_populates_the_capacity_and_record_members_from_the_store() {
    let fixture = store_fixture();
    let now = OffsetDateTime::now_utc();
    append_record(
        &fixture.record_dir.join(ACTIVE_FILE_NAME),
        &paired_record(now, "request-1"),
    );
    let health = cold_snapshot(AuditStoreEnforcement::Directory);
    let inputs = inputs_for(&fixture, AuditStoreEnforcement::Directory);

    assert_eq!(capacity_of(&health).state, AuditCapacityState::Unknown);
    assert!(capacity_of(&health).used_bytes.is_none());

    tick(&health, &inputs, now).await;

    let capacity = capacity_of(&health);
    assert_eq!(capacity.state, AuditCapacityState::Ok);
    assert_eq!(capacity.reserve_bytes, RESERVE);
    assert_eq!(capacity.low_water_bytes, LOW_WATER);
    assert_eq!(capacity.enforcement, AuditStoreEnforcement::Directory);
    assert!(capacity.used_bytes.is_some_and(|used| used > 0));
    assert!(capacity.headroom_bytes.is_some_and(|headroom| headroom > 0));
    assert_eq!(capacity.measured_at, Some(now));

    // Read, not re-derived: the relayed values are the reader's own for
    // the same store and the same window.
    let expected = scan_audit_store(
        &fixture.record_dir,
        now,
        AUDIT_SCAN_WINDOW,
        MAX_RETAINED,
        MIN_RETAIN_DAYS,
    )
    .expect("the reader scans the store");
    assert_eq!(
        capacity.intent_without_outcome,
        Some(expected.intent_without_outcome)
    );
    assert_eq!(capacity.malformed_records, Some(expected.malformed_records));
    assert_eq!(capacity.retention_shortfall, Some(expected.retention_short));
    assert_eq!(capacity.records_measured_at, Some(now));
}

#[tokio::test]
async fn enforcement_is_always_present_and_mirrors_the_configured_mode() {
    for enforcement in [
        AuditStoreEnforcement::Filesystem,
        AuditStoreEnforcement::Directory,
    ] {
        let fixture = store_fixture();
        let health = cold_snapshot(enforcement);
        let inputs = inputs_for(&fixture, enforcement);
        tick(&health, &inputs, OffsetDateTime::now_utc()).await;
        let capacity = capacity_of(&health);
        assert_eq!(
            capacity.enforcement, enforcement,
            "a directory-mode deployment cannot be mistaken for an enforced reserve"
        );
        assert!(capacity.used_bytes.is_some(), "both modes measure usage");
    }
}

/// A symbolic link planted at `audit_store_dir` fails the probe in
/// **both** modes, because the root open carrying `O_NOFOLLOW` is the
/// only step `filesystem` mode has and it refuses the link rather than
/// reporting the target's filesystem.
#[tokio::test]
async fn a_failed_probe_leaves_the_previous_state_and_measured_at_intact() {
    for enforcement in [
        AuditStoreEnforcement::Directory,
        AuditStoreEnforcement::Filesystem,
    ] {
        let fixture = store_fixture();
        let health = cold_snapshot(enforcement);
        let first = OffsetDateTime::now_utc();
        tick(&health, &inputs_for(&fixture, enforcement), first).await;
        let before = capacity_of(&health);
        // Not asserted as `ok`: in `filesystem` mode the tempdir's usage
        // is the whole host filesystem's, which the synthetic reserve
        // here is smaller than. What matters is that a state was reached
        // and stamped, so the failure below has something to preserve.
        assert_ne!(before.state, AuditCapacityState::Unknown);
        assert!(before.measured_at.is_some());

        // A store root that is a symbolic link fails the probe in either
        // mode, which is the store contract's own rule about a link
        // planted there.
        let link_parent = tempfile::tempdir().expect("a temporary directory");
        let link = link_parent.path().join("audit-store");
        std::os::unix::fs::symlink(&fixture.store_dir, &link).expect("the link is planted");
        let mut broken = inputs_for(&fixture, enforcement);
        broken.store_dir = link;

        tick(&health, &broken, first + Duration::minutes(1)).await;
        let after = capacity_of(&health);
        assert_eq!(
            after.state, before.state,
            "an alarm is not hidden by a failure"
        );
        assert_eq!(after.used_bytes, before.used_bytes);
        assert_eq!(after.headroom_bytes, before.headroom_bytes);
        assert_eq!(
            after.measured_at, before.measured_at,
            "no new measurement was stamped"
        );
        assert_eq!(
            after.records_measured_at,
            Some(first + Duration::minutes(1)),
            "the record scan succeeds and fails independently of the probe"
        );
    }
}

#[tokio::test]
async fn a_failed_scan_leaves_the_previous_record_values_and_timestamp_intact() {
    let fixture = store_fixture();
    let now = OffsetDateTime::now_utc();
    append_line(&fixture.record_dir.join(ACTIVE_FILE_NAME), b"not JSON\n");
    let health = cold_snapshot(AuditStoreEnforcement::Directory);
    let inputs = inputs_for(&fixture, AuditStoreEnforcement::Directory);
    tick(&health, &inputs, now).await;
    let before = capacity_of(&health);
    assert_eq!(before.malformed_records, Some(1));

    let mut broken = inputs.clone();
    broken.record_dir = fixture.store_dir.join("records-that-are-not-there");
    let later = now + Duration::minutes(1);
    tick(&health, &broken, later).await;

    let after = capacity_of(&health);
    assert_eq!(
        after.malformed_records, before.malformed_records,
        "a failed scan does not report zero anomalies"
    );
    assert_eq!(after.intent_without_outcome, before.intent_without_outcome);
    assert_eq!(after.retention_shortfall, before.retention_shortfall);
    assert_eq!(after.records_measured_at, before.records_measured_at);
    assert_eq!(
        after.measured_at,
        Some(later),
        "the capacity probe succeeds independently of the scan"
    );
}

#[tokio::test]
async fn the_record_members_stay_absent_while_the_capacity_members_are_present() {
    let fixture = store_fixture();
    let health = cold_snapshot(AuditStoreEnforcement::Directory);
    let mut inputs = inputs_for(&fixture, AuditStoreEnforcement::Directory);
    inputs.record_dir = fixture.store_dir.join("records-that-are-not-there");

    tick(&health, &inputs, OffsetDateTime::now_utc()).await;

    let capacity = capacity_of(&health);
    assert!(capacity.used_bytes.is_some());
    assert!(capacity.headroom_bytes.is_some());
    assert!(capacity.measured_at.is_some());
    assert_eq!(capacity.intent_without_outcome, None);
    assert_eq!(capacity.malformed_records, None);
    assert_eq!(capacity.retention_shortfall, None);
    assert_eq!(capacity.records_measured_at, None);
}

#[tokio::test]
async fn the_relayed_malformed_count_is_exact_and_ignores_a_surplus_generation() {
    let fixture = store_fixture();
    let now = OffsetDateTime::now_utc();
    let active = fixture.record_dir.join(ACTIVE_FILE_NAME);
    for _ in 0..3 {
        append_line(&active, b"not JSON\n");
    }
    // A surplus generation beyond `audit_max_retained_files`, which the
    // reader does not select. Its age comes from `AUDIT_SCAN_WINDOW`
    // rather than a restated number of days.
    let surplus = fixture.record_dir.join(rotated_name(
        &rotation_stamp(now - AUDIT_SCAN_WINDOW - Duration::days(1)),
        0,
    ));
    append_line(&surplus, b"also not JSON\n");
    for (index, offset) in [Duration::days(2), Duration::days(1)]
        .into_iter()
        .enumerate()
    {
        let path = fixture.record_dir.join(rotated_name(
            &rotation_stamp(now - offset),
            u32::try_from(index).expect("the sequence fits"),
        ));
        append_record(&path, &paired_record(now, &format!("rotated-{index}")));
    }

    let health = cold_snapshot(AuditStoreEnforcement::Directory);
    let inputs = inputs_for(&fixture, AuditStoreEnforcement::Directory);
    tick(&health, &inputs, now).await;

    let expected = scan_audit_store(
        &fixture.record_dir,
        now,
        AUDIT_SCAN_WINDOW,
        MAX_RETAINED,
        MIN_RETAIN_DAYS,
    )
    .expect("the reader scans the store");
    assert_eq!(
        expected.malformed_records, 3,
        "the surplus generation is not selected"
    );
    assert_eq!(capacity_of(&health).malformed_records, Some(3));
}

#[tokio::test]
async fn the_retention_shortfall_reaches_the_health_response_both_ways() {
    let now = OffsetDateTime::now_utc();

    // Healthy: nothing rotated, so the retained set is short of its
    // maximum and no shortfall is derived.
    let healthy = store_fixture();
    append_record(
        &healthy.record_dir.join(ACTIVE_FILE_NAME),
        &paired_record(now, "request-1"),
    );
    let health = cold_snapshot(AuditStoreEnforcement::Directory);
    tick(
        &health,
        &inputs_for(&healthy, AuditStoreEnforcement::Directory),
        now,
    )
    .await;
    assert_eq!(capacity_of(&health).retention_shortfall, Some(false));
    assert!(
        !scan_audit_store(
            &healthy.record_dir,
            now,
            AUDIT_SCAN_WINDOW,
            MAX_RETAINED,
            MIN_RETAIN_DAYS
        )
        .expect("the reader scans the store")
        .retention_short,
        "the host-local surface reads the same store the same way"
    );

    // Short: the retained set is at its maximum and its oldest record is
    // newer than the retention floor, so the size ceiling is winning
    // against the retention target.
    let short = store_fixture();
    append_record(
        &short.record_dir.join(ACTIVE_FILE_NAME),
        &paired_record(now, "request-1"),
    );
    for index in 0..MAX_RETAINED {
        let path = short.record_dir.join(rotated_name(
            &rotation_stamp(now - Duration::hours(i64::from(index) + 1)),
            index,
        ));
        append_record(&path, &paired_record(now, &format!("rotated-{index}")));
    }
    let short_health = cold_snapshot(AuditStoreEnforcement::Directory);
    tick(
        &short_health,
        &inputs_for(&short, AuditStoreEnforcement::Directory),
        now,
    )
    .await;
    let expected = scan_audit_store(
        &short.record_dir,
        now,
        AUDIT_SCAN_WINDOW,
        MAX_RETAINED,
        MIN_RETAIN_DAYS,
    )
    .expect("the reader scans the store")
    .retention_short;
    assert!(expected, "the fixture is in the reader's derived shortfall");
    assert_eq!(capacity_of(&short_health).retention_shortfall, Some(true));
}

#[tokio::test]
async fn the_alarm_reaches_the_snapshot_when_the_configured_budget_binds() {
    let fixture = store_fixture();
    let now = OffsetDateTime::now_utc();
    std::fs::write(
        fixture.store_dir.join("openbao").join("audit.log"),
        vec![0; 64 * 1_024],
    )
    .expect("the device file is written");
    let health = cold_snapshot(AuditStoreEnforcement::Directory);
    let mut inputs = inputs_for(&fixture, AuditStoreEnforcement::Directory);

    // The store's own usage decides the synthetic reserve, so the
    // configured budget binds before the device's free space does and
    // the thresholds are exact rather than guessed at.
    tick(&health, &inputs, now).await;
    let used = capacity_of(&health)
        .used_bytes
        .expect("the first tick measured the store");
    assert!(used > 0, "a store holding a file uses blocks");

    inputs.reserve_bytes = used + 1_000;
    inputs.low_water_bytes = 1_000;
    set_thresholds(&health, &inputs);
    tick(&health, &inputs, now).await;
    assert_eq!(
        capacity_of(&health).headroom_bytes,
        Some(1_000),
        "the configured budget binds, not the device"
    );
    assert_eq!(
        capacity_of(&health).state,
        AuditCapacityState::LowWater,
        "the alarm fires before the reserve is consumed"
    );

    inputs.reserve_bytes = used;
    set_thresholds(&health, &inputs);
    tick(&health, &inputs, now).await;
    assert_eq!(capacity_of(&health).headroom_bytes, Some(0));
    assert_eq!(
        capacity_of(&health).state,
        AuditCapacityState::Exhausted,
        "zero headroom counts as exhausted, not as low water"
    );

    inputs.reserve_bytes = used - 512;
    set_thresholds(&health, &inputs);
    tick(&health, &inputs, now).await;
    assert_eq!(
        capacity_of(&health).state,
        AuditCapacityState::Exhausted,
        "a store past its reserve stays exhausted"
    );
    assert_eq!(
        capacity_of(&health).headroom_bytes,
        Some(-512),
        "the overrun is reported as negative headroom rather than clamped to zero"
    );
}

/// The scan window is reused, never restated.
///
/// Two definitions of the look-back period is exactly how the relayed
/// values and the host-local `bootroot status` ones drift apart, so the
/// bar is on a second *code* definition: the `docs/` pages name the
/// 30-day window in prose, and tests that age a fixture across it derive
/// that age from the constant.
#[test]
fn the_tick_declares_no_window_value_of_its_own() {
    let source =
        std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/daemon.rs"))
            .expect("the daemon source reads");
    let body = source
        .split("pub(crate) async fn refresh_registrar_audit_capacity")
        .nth(1)
        .expect("the refresh function is in the daemon source");
    let end = body
        .find("\n}\n")
        .expect("the refresh function has a closing brace at column zero");
    let refresh = body.get(..end).expect("the body slice is in bounds");
    assert!(
        refresh.contains("AUDIT_SCAN_WINDOW"),
        "the reader is called with the constant it already owns"
    );
    for restated in [
        "days(30)",
        "Duration::days",
        "AUDIT_CAPACITY_WINDOW",
        "2_592_000",
    ] {
        assert!(
            !refresh.contains(restated),
            "the tick restates the window as `{restated}`"
        );
    }
}
