use std::collections::BTreeSet;
use std::fs;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use time::{Duration as WallDuration, OffsetDateTime};
use tokio::time::{Duration, Instant};

use super::{CoalescingLimitedInvocationSink, MAX_OPEN_COALESCING_WINDOWS, OpenWindow, WindowKey};
use crate::registrar::audit::{AuditPhase, AuditRecord, AuditRecordStore, AuditVerb};
use crate::registrar::verbs::limiter::{
    ChargeOutcome, CountingLimitedInvocationSink, LimiterBucket, VerbRateLimiter,
    VerbRateLimiterSettings,
};
use crate::registrar::verbs::outcome::CallerIdentity;

const WINDOW_SECONDS: u64 = 60;

fn sink() -> CoalescingLimitedInvocationSink {
    CoalescingLimitedInvocationSink::new(
        Arc::new(CountingLimitedInvocationSink::new()),
        AuditRecordStore::open_temporary().expect("open temporary audit store"),
        WINDOW_SECONDS,
    )
}

fn limiter(sink: Arc<CoalescingLimitedInvocationSink>) -> VerbRateLimiter {
    VerbRateLimiter::new(
        VerbRateLimiterSettings {
            admission_burst: 1,
            admission_refill_interval_ms: 3_600_000,
            predecision_refusal_burst: 1,
            predecision_refusal_refill_interval_ms: 3_600_000,
        },
        sink,
    )
}

fn emit_limited(limiter: &VerbRateLimiter, caller: &str, verb: AuditVerb, bucket: LimiterBucket) {
    let caller = CallerIdentity::new(caller);
    assert!(matches!(
        limiter.charge(&caller, verb, bucket),
        ChargeOutcome::Admitted
    ));
    assert!(matches!(
        limiter.charge(&caller, verb, bucket),
        ChargeOutcome::Limited { .. }
    ));
}

fn records(sink: &CoalescingLimitedInvocationSink) -> Vec<AuditRecord> {
    fs::read_to_string(sink.store.active_path())
        .expect("read audit records")
        .lines()
        .map(|line| serde_json::from_str(line).expect("limited record parses"))
        .collect()
}

fn expire(
    sink: &CoalescingLimitedInvocationSink,
    caller: &str,
    verb: AuditVerb,
    bucket: LimiterBucket,
) {
    let key = WindowKey {
        caller: CallerIdentity::new(caller),
        verb,
        bucket,
    };
    let mut windows = sink.windows.lock().expect("coalescing map lock");
    let window = windows
        .get_mut(&key)
        .expect("limited event opened a window");
    window.deadline = Instant::now();
    // Tokio's monotonic test clock is not advanced here. Make the wall-clock
    // projection agree with the forced deadline, as it would after a real
    // configured window had elapsed.
    window.wall_start = OffsetDateTime::now_utc()
        - WallDuration::seconds(i64::try_from(WINDOW_SECONDS).expect("fits i64"));
}

fn assert_window_span(record: &AuditRecord) {
    let start = record.window_start.expect("limited record has a start");
    let end = record.window_end.expect("limited record has an end");
    assert!(end >= start, "limited record bounds are not inverted");
    assert!(
        end - start <= WallDuration::seconds(i64::try_from(WINDOW_SECONDS).expect("fits i64")),
        "limited record span exceeds its configured window"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn windows_coalesce_by_key_and_forward_every_event_to_the_counter() {
    let sink = Arc::new(sink());
    let limiter = limiter(Arc::clone(&sink));

    emit_limited(
        &limiter,
        "caller-a",
        AuditVerb::Mint,
        LimiterBucket::Admission,
    );
    let caller = CallerIdentity::new("caller-a");
    assert!(matches!(
        limiter.charge(&caller, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Limited { .. }
    ));
    emit_limited(
        &limiter,
        "caller-a",
        AuditVerb::Deregister,
        LimiterBucket::Admission,
    );
    emit_limited(
        &limiter,
        "caller-a",
        AuditVerb::Mint,
        LimiterBucket::PredecisionRefusal,
    );

    assert_eq!(sink.windows.lock().expect("map lock").len(), 3);
    assert_eq!(sink.counts().count(LimiterBucket::Admission), 3);
    assert_eq!(sink.counts().count(LimiterBucket::PredecisionRefusal), 1);

    sink.flush();
    let records = records(&sink);
    assert_eq!(records.len(), 3);
    assert!(
        records
            .iter()
            .all(|record| record.phase == AuditPhase::Limited)
    );
    assert_eq!(
        records
            .iter()
            .find(|record| {
                record.verb == AuditVerb::Mint
                    && record.limited_bucket
                        == Some(crate::registrar::audit::LimitedBucket::Admission)
            })
            .and_then(|record| record.count),
        Some(2)
    );
    for record in &records {
        assert_window_span(record);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_arrival_at_an_expired_deadline_closes_its_predecessor_before_counting_it() {
    let sink = Arc::new(sink());
    let limiter = limiter(Arc::clone(&sink));
    emit_limited(
        &limiter,
        "caller-a",
        AuditVerb::Mint,
        LimiterBucket::Admission,
    );
    expire(&sink, "caller-a", AuditVerb::Mint, LimiterBucket::Admission);

    let caller = CallerIdentity::new("caller-a");
    assert!(matches!(
        limiter.charge(&caller, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Limited { .. }
    ));
    assert_eq!(sink.windows.lock().expect("map lock").len(), 1);

    sink.flush();
    let records = records(&sink);
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].count, Some(1));
    assert_eq!(records[1].count, Some(1));
    assert_eq!(
        records[0].window_end,
        Some(
            records[0].window_start.expect("start")
                + WallDuration::seconds(i64::try_from(WINDOW_SECONDS).expect("fits i64"))
        )
    );
    assert!(
        records[1].window_start.expect("successor start")
            >= records[0].window_end.expect("predecessor end")
    );
    for record in &records {
        assert_window_span(record);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn maintenance_closes_a_silent_window_at_its_deadline() {
    let sink = Arc::new(sink());
    let limiter = limiter(Arc::clone(&sink));
    emit_limited(
        &limiter,
        "silent-caller",
        AuditVerb::Deregister,
        LimiterBucket::PredecisionRefusal,
    );
    expire(
        &sink,
        "silent-caller",
        AuditVerb::Deregister,
        LimiterBucket::PredecisionRefusal,
    );

    sink.maintain();
    assert!(sink.windows.lock().expect("map lock").is_empty());
    let records = records(&sink);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].count, Some(1));
    assert_eq!(
        records[0].window_end,
        Some(
            records[0].window_start.expect("start")
                + WallDuration::seconds(i64::try_from(WINDOW_SECONDS).expect("fits i64"))
        )
    );
    assert_window_span(&records[0]);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_limited_record_write_keeps_the_limiter_decision_nonfatal() {
    let sink = Arc::new(sink());
    sink.store.faults().append.store(true, Ordering::SeqCst);
    let limiter = limiter(Arc::clone(&sink));
    emit_limited(
        &limiter,
        "write-failure-caller",
        AuditVerb::Mint,
        LimiterBucket::Admission,
    );

    sink.flush();
    assert_eq!(sink.counts().count(LimiterBucket::Admission), 1);
    assert!(
        records(&sink).is_empty(),
        "a failed best-effort close writes no limited record"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn capacity_flushes_the_oldest_window_without_losing_the_new_event() {
    let sink = Arc::new(sink());
    let limiter = limiter(Arc::clone(&sink));
    for number in 0..=MAX_OPEN_COALESCING_WINDOWS {
        emit_limited(
            &limiter,
            &format!("caller-{number:03}"),
            AuditVerb::Mint,
            LimiterBucket::Admission,
        );
        assert!(
            sink.windows.lock().expect("map lock").len() <= MAX_OPEN_COALESCING_WINDOWS,
            "coalescing map is bounded after every arrival"
        );
    }

    let early_records = records(&sink);
    assert_eq!(early_records.len(), 1, "one window was flushed early");
    let early = &early_records[0];
    assert!(
        early.window_end.expect("early record has an end")
            < early.window_start.expect("early record has a start")
                + WallDuration::seconds(i64::try_from(WINDOW_SECONDS).expect("fits i64")),
        "a capacity record still before its deadline closes at the flush instant"
    );
    sink.flush();
    let records = records(&sink);
    assert_eq!(records.len(), MAX_OPEN_COALESCING_WINDOWS + 1);
    assert!(records.iter().all(|record| record.count == Some(1)));
    let callers = records
        .iter()
        .map(|record| record.caller_identity.as_str())
        .collect::<BTreeSet<_>>();
    let expected_callers = (0..=MAX_OPEN_COALESCING_WINDOWS)
        .map(|number| format!("caller-{number:03}"))
        .collect::<BTreeSet<_>>();
    assert_eq!(
        callers,
        expected_callers.iter().map(String::as_str).collect(),
        "every flooded key reaches a limited record"
    );
    for record in &records {
        assert_window_span(record);
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn an_overdue_capacity_victim_closes_at_its_deadline() {
    let sink = Arc::new(sink());
    let limiter = limiter(Arc::clone(&sink));
    for number in 0..MAX_OPEN_COALESCING_WINDOWS {
        emit_limited(
            &limiter,
            &format!("caller-{number:03}"),
            AuditVerb::Mint,
            LimiterBucket::Admission,
        );
    }
    expire(
        &sink,
        "caller-000",
        AuditVerb::Mint,
        LimiterBucket::Admission,
    );

    emit_limited(
        &limiter,
        "caller-new",
        AuditVerb::Mint,
        LimiterBucket::Admission,
    );
    let records = records(&sink);
    assert_eq!(records.len(), 1, "capacity closes exactly one victim");
    let record = &records[0];
    assert_eq!(record.caller_identity, "caller-000");
    assert_eq!(
        record.window_end,
        Some(
            record.window_start.expect("overdue record has a start")
                + WallDuration::seconds(i64::try_from(WINDOW_SECONDS).expect("fits i64"))
        ),
        "an overdue capacity victim closes at its deadline, not the later capacity flush"
    );
    assert_window_span(record);
}

#[tokio::test(flavor = "multi_thread")]
async fn shutdown_flush_closes_an_overdue_window_at_its_deadline() {
    let sink = Arc::new(sink());
    let limiter = limiter(Arc::clone(&sink));
    emit_limited(
        &limiter,
        "shutdown-caller",
        AuditVerb::Deregister,
        LimiterBucket::PredecisionRefusal,
    );
    expire(
        &sink,
        "shutdown-caller",
        AuditVerb::Deregister,
        LimiterBucket::PredecisionRefusal,
    );

    sink.flush();
    let records = records(&sink);
    assert_eq!(records.len(), 1);
    let record = &records[0];
    assert_eq!(
        record.window_end,
        Some(
            record.window_start.expect("overdue record has a start")
                + WallDuration::seconds(i64::try_from(WINDOW_SECONDS).expect("fits i64"))
        ),
        "an overdue shutdown window closes at its deadline, not the later flush"
    );
    assert_window_span(record);
}

#[tokio::test(flavor = "multi_thread")]
async fn one_key_keeps_one_open_window_across_three_rollovers() {
    let sink = Arc::new(sink());
    let limiter = limiter(Arc::clone(&sink));
    let caller = CallerIdentity::new("rollover-caller");

    emit_limited(
        &limiter,
        caller.as_str(),
        AuditVerb::Mint,
        LimiterBucket::Admission,
    );
    assert_eq!(sink.windows.lock().expect("map lock").len(), 1);
    expire(
        &sink,
        caller.as_str(),
        AuditVerb::Mint,
        LimiterBucket::Admission,
    );

    for _ in 0..2 {
        assert!(matches!(
            limiter.charge(&caller, AuditVerb::Mint, LimiterBucket::Admission),
            ChargeOutcome::Limited { .. }
        ));
        assert_eq!(
            sink.windows.lock().expect("map lock").len(),
            1,
            "a successor replaces its predecessor instead of creating a second open window"
        );
        expire(
            &sink,
            caller.as_str(),
            AuditVerb::Mint,
            LimiterBucket::Admission,
        );
    }

    sink.flush();
    let records = records(&sink);
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| record.count == Some(1)));
    for record in &records {
        assert_window_span(record);
    }
}

#[test]
fn deterministic_oldest_selection_breaks_a_start_time_tie_by_serialized_key() {
    let now = Instant::now();
    let wall_start = OffsetDateTime::now_utc();
    let mut windows = std::collections::HashMap::new();
    for caller in ["caller-z", "caller-a"] {
        windows.insert(
            WindowKey {
                caller: CallerIdentity::new(caller),
                verb: AuditVerb::Mint,
                bucket: LimiterBucket::Admission,
            },
            OpenWindow {
                started_at: now,
                deadline: now + Duration::from_secs(WINDOW_SECONDS),
                wall_start,
                count: 1,
            },
        );
    }
    while windows.len() < MAX_OPEN_COALESCING_WINDOWS {
        let number = windows.len();
        let caller = format!("filler-{number:03}");
        windows.insert(
            WindowKey {
                caller: CallerIdentity::new(&caller),
                verb: AuditVerb::Mint,
                bucket: LimiterBucket::Admission,
            },
            OpenWindow {
                started_at: now + Duration::from_secs(1),
                deadline: now + Duration::from_secs(WINDOW_SECONDS),
                wall_start,
                count: 1,
            },
        );
    }

    let (key, _) = CoalescingLimitedInvocationSink::close_oldest_for_capacity(&mut windows)
        .expect("a full map selects a victim");
    assert_eq!(key.caller.as_str(), "caller-a");
}
