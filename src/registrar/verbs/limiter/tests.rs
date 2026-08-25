//! Tests for the two token buckets both registrar verbs are charged
//! against.
//!
//! Time is driven with `tokio::time` pause and advance rather than by
//! sleeping, which is also what makes the monotonic-clock assertions
//! possible: the limiter reads [`Instant`], so a paused runtime's clock
//! is the only clock it has, and a wall-clock step is by construction
//! invisible to it.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::time::{Duration, advance, pause};

use super::{
    BucketSizing, ChargeOutcome, CountingLimitedInvocationSink, LimitedInvocation,
    LimitedInvocationSink, LimiterBucket, MAX_LIMITER_ENTRIES, NoopLimitedInvocationSink,
    TokenBucket, VerbRateLimiter, VerbRateLimiterSettings,
};
use crate::registrar::audit::AuditVerb;
use crate::registrar::verbs::outcome::CallerIdentity;

const CALLER: &str = "unix-peer:uid=0";

/// A sizing small enough that a test can drain a bucket in a loop it can
/// read, with an interval large enough that no accrual happens by
/// accident.
fn tiny() -> VerbRateLimiterSettings {
    VerbRateLimiterSettings {
        admission_burst: 3,
        admission_refill_interval_ms: 2_000,
        predecision_refusal_burst: 2,
        predecision_refusal_refill_interval_ms: 4_000,
    }
}

fn caller(value: &str) -> CallerIdentity {
    CallerIdentity::new(value)
}

fn drain(
    limiter: &VerbRateLimiter,
    identity: &CallerIdentity,
    verb: AuditVerb,
    bucket: LimiterBucket,
    burst: u32,
) {
    for spent in 0..burst {
        assert_eq!(
            limiter.charge(identity, verb, bucket),
            ChargeOutcome::Admitted,
            "token {spent} of {burst} must be available"
        );
    }
}

#[test]
fn the_bucket_enum_has_exactly_two_values_with_stable_spellings() {
    assert_eq!(
        LimiterBucket::PredecisionRefusal.as_str(),
        "predecision_refusal"
    );
    assert_eq!(LimiterBucket::Admission.as_str(), "admission");
    assert_eq!(LimiterBucket::Admission.to_string(), "admission");
}

#[tokio::test]
async fn a_fresh_bucket_admits_a_full_burst_and_then_limits() {
    pause();
    let (limiter, counts) = VerbRateLimiter::with_counting_sink(tiny());
    let identity = caller(CALLER);
    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
    let ChargeOutcome::Limited { retry_after } =
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission)
    else {
        panic!("a drained bucket must limit");
    };
    assert!(retry_after >= 1, "the retry payload is floored at 1");
    assert_eq!(counts.count(LimiterBucket::Admission), 1);
    assert_eq!(counts.count(LimiterBucket::PredecisionRefusal), 0);
}

/// A limiter recreated from scratch starts full again, which is the
/// whole of "no persisted state".
#[tokio::test]
async fn a_recreated_limiter_starts_full_again() {
    pause();
    let identity = caller(CALLER);
    let (first, _) = VerbRateLimiter::with_counting_sink(tiny());
    drain(
        &first,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
    assert!(matches!(
        first.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Limited { .. }
    ));

    let (second, _) = VerbRateLimiter::with_counting_sink(tiny());
    drain(
        &second,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
}

/// The retry payload is whole seconds of *remaining* interval, floored
/// at `1` so a `0` can never invite an immediate retry into the bucket
/// that just refused.
#[tokio::test]
async fn the_retry_payload_tracks_the_configured_refill_interval() {
    pause();
    let settings = VerbRateLimiterSettings {
        admission_burst: 1,
        admission_refill_interval_ms: 10_000,
        ..tiny()
    };
    let (limiter, _) = VerbRateLimiter::with_counting_sink(settings);
    let identity = caller(CALLER);
    assert_eq!(
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Admitted
    );
    let ChargeOutcome::Limited { retry_after } =
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission)
    else {
        panic!("a drained bucket must limit");
    };
    assert_eq!(retry_after, 10, "the whole interval is still outstanding");

    advance(Duration::from_millis(7_500)).await;
    let ChargeOutcome::Limited { retry_after } =
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission)
    else {
        panic!("the interval has not elapsed, so the bucket still limits");
    };
    assert_eq!(retry_after, 3, "2.5s remain, rounded up to whole seconds");

    // Under a second remaining still reports 1 rather than 0.
    advance(Duration::from_secs(2)).await;
    let ChargeOutcome::Limited { retry_after } =
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission)
    else {
        panic!("the interval has still not elapsed");
    };
    assert_eq!(retry_after, 1, "0.5s remain, floored at 1");

    advance(Duration::from_millis(500)).await;
    assert_eq!(
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Admitted,
        "the interval has elapsed, so exactly one token accrued"
    );
}

/// A token bucket rather than a fixed window: crossing a boundary does
/// not hand a caller a second full budget.
#[tokio::test]
async fn a_drained_bucket_does_not_refill_to_a_second_full_burst_at_a_boundary() {
    pause();
    let (limiter, _) = VerbRateLimiter::with_counting_sink(tiny());
    let identity = caller(CALLER);
    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );

    // One whole interval accrues exactly one token, not a burst.
    advance(Duration::from_secs(2)).await;
    assert_eq!(
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Admitted
    );
    assert!(
        matches!(
            limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
            ChargeOutcome::Limited { .. }
        ),
        "a fixed window would have handed over a second full burst here"
    );

    // Three intervals accrue three tokens, and no more: the burst caps it.
    advance(Duration::from_secs(20)).await;
    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
    assert!(matches!(
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Limited { .. }
    ));
}

/// A partial interval is banked rather than discarded: two half
/// intervals accrue the token one whole interval would have.
#[tokio::test]
async fn a_partial_interval_is_not_discarded() {
    pause();
    let (limiter, _) = VerbRateLimiter::with_counting_sink(tiny());
    let identity = caller(CALLER);
    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
    advance(Duration::from_millis(1_200)).await;
    assert!(matches!(
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Limited { .. }
    ));
    advance(Duration::from_millis(900)).await;
    assert_eq!(
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Admitted,
        "2.1s of a 2s interval must have accrued a token"
    );
}

/// The bucket reads a monotonic clock, so no wall-clock step can mint a
/// token. Driving the wall clock while the runtime's monotonic clock is
/// paused is exactly that step.
#[tokio::test]
async fn a_wall_clock_jump_adds_no_tokens() {
    pause();
    let (limiter, _) = VerbRateLimiter::with_counting_sink(tiny());
    let identity = caller(CALLER);
    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
    let before = std::time::SystemTime::now();
    // A real elapsed wall-clock interval, with the monotonic clock the
    // limiter reads held still.
    while std::time::SystemTime::now()
        .duration_since(before)
        .unwrap_or_default()
        < std::time::Duration::from_millis(20)
    {
        std::hint::spin_loop();
    }
    assert!(
        matches!(
            limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
            ChargeOutcome::Limited { .. }
        ),
        "only the monotonic clock may accrue tokens"
    );
}

/// Four buckets per identity, and each one is spent independently.
#[tokio::test]
async fn the_four_buckets_of_one_identity_are_independent() {
    pause();
    let (limiter, _) = VerbRateLimiter::with_counting_sink(tiny());
    let identity = caller(CALLER);
    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::PredecisionRefusal,
        2,
    );
    assert!(matches!(
        limiter.charge(
            &identity,
            AuditVerb::Mint,
            LimiterBucket::PredecisionRefusal
        ),
        ChargeOutcome::Limited { .. }
    ));
    for (verb, bucket) in [
        (AuditVerb::Mint, LimiterBucket::Admission),
        (AuditVerb::Deregister, LimiterBucket::PredecisionRefusal),
        (AuditVerb::Deregister, LimiterBucket::Admission),
    ] {
        assert_eq!(
            limiter.charge(&identity, verb, bucket),
            ChargeOutcome::Admitted,
            "{verb:?}/{bucket} must not have been spent"
        );
    }
    assert_eq!(limiter.entry_count(), 4);
}

/// The key is the identity as it arrives, so two sequential connections
/// from one caller spend the same bucket. The limiter cannot be reset by
/// reconnecting.
#[tokio::test]
async fn two_sequential_connections_from_one_caller_spend_the_same_bucket() {
    pause();
    let (limiter, _) = VerbRateLimiter::with_counting_sink(tiny());
    // Two independently constructed identities carrying the same
    // rendering — which is what two connections from one peer produce.
    let first = caller(CALLER);
    let second = caller(CALLER);
    drain(
        &limiter,
        &first,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
    assert!(
        matches!(
            limiter.charge(&second, AuditVerb::Mint, LimiterBucket::Admission),
            ChargeOutcome::Limited { .. }
        ),
        "a second connection must not get a fresh budget"
    );
    assert_eq!(limiter.entry_count(), 1);
}

/// Different identities hold different entries, so one caller's flood
/// does not spend another's budget while the map has room.
#[tokio::test]
async fn distinct_identities_hold_distinct_entries() {
    pause();
    let (limiter, _) = VerbRateLimiter::with_counting_sink(tiny());
    let flooder = caller("unix-peer:uid=1");
    let other = caller("unix-peer:uid=2");
    drain(
        &limiter,
        &flooder,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
    assert!(matches!(
        limiter.charge(&flooder, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Limited { .. }
    ));
    assert_eq!(
        limiter.charge(&other, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Admitted
    );
}

/// Driving far more distinct identities than the cap allows leaves the
/// entry count at or below it.
#[tokio::test]
async fn far_more_identities_than_the_cap_leave_the_entry_count_bounded() {
    pause();
    let (limiter, _) = VerbRateLimiter::with_counting_sink(tiny());
    for index in 0..(MAX_LIMITER_ENTRIES * 8) {
        limiter.charge(
            &caller(&format!("unix-peer:uid={index}")),
            AuditVerb::Mint,
            LimiterBucket::Admission,
        );
        assert!(
            limiter.entry_count() <= MAX_LIMITER_ENTRIES,
            "the map must never exceed {MAX_LIMITER_ENTRIES} entries"
        );
    }
    assert!(limiter.entry_count() <= MAX_LIMITER_ENTRIES);
}

/// A map at the cap holding entries refilled to their full burst
/// reclaims them and admits the new key. Removing a full entry is
/// indistinguishable from recreating it, so nobody is handed a token.
#[tokio::test]
async fn a_full_entry_at_the_cap_is_reclaimed_and_the_new_key_admitted() {
    pause();
    // A burst of one, so a single charge drains an entry and a single
    // elapsed interval refills it.
    let settings = VerbRateLimiterSettings {
        admission_burst: 1,
        admission_refill_interval_ms: 1_000,
        predecision_refusal_burst: 1,
        predecision_refusal_refill_interval_ms: 1_000,
    };
    let (limiter, _) = VerbRateLimiter::with_counting_sink(settings);
    for index in 0..MAX_LIMITER_ENTRIES {
        assert_eq!(
            limiter.charge(
                &caller(&format!("unix-peer:uid={index}")),
                AuditVerb::Mint,
                LimiterBucket::Admission,
            ),
            ChargeOutcome::Admitted
        );
    }
    assert_eq!(limiter.entry_count(), MAX_LIMITER_ENTRIES);

    // Every entry refills to its full burst.
    advance(Duration::from_secs(1)).await;
    assert_eq!(
        limiter.charge(
            &caller("unix-peer:uid=new"),
            AuditVerb::Mint,
            LimiterBucket::Admission
        ),
        ChargeOutcome::Admitted
    );
    assert_eq!(
        limiter.entry_count(),
        1,
        "every full entry is reclaimed, and only the new key remains"
    );
}

/// With the map at the cap and every entry drained, an absent key is
/// charged against the overflow bucket for its `(verb, bucket)` — and is
/// limited on that bucket's tokens rather than admitted unlimited.
#[tokio::test]
async fn a_saturated_drained_map_charges_the_overflow_bucket() {
    pause();
    let settings = VerbRateLimiterSettings {
        admission_burst: 1,
        admission_refill_interval_ms: 60_000,
        predecision_refusal_burst: 1,
        predecision_refusal_refill_interval_ms: 60_000,
    };
    let (limiter, counts) = VerbRateLimiter::with_counting_sink(settings);
    // Fill the map, and drain every entry: each identity's first charge
    // inserts a bucket of one token and spends it.
    for index in 0..MAX_LIMITER_ENTRIES {
        assert_eq!(
            limiter.charge(
                &caller(&format!("unix-peer:uid={index}")),
                AuditVerb::Mint,
                LimiterBucket::Admission,
            ),
            ChargeOutcome::Admitted
        );
    }
    assert_eq!(limiter.entry_count(), MAX_LIMITER_ENTRIES);

    // Every map entry carries (Mint, Admission), so no entry carries the
    // pair below — which is the case that makes "charge some existing
    // entry for the same pair" not total.
    let stranger = caller("unix-peer:uid=stranger");
    assert_eq!(
        limiter.charge(
            &stranger,
            AuditVerb::Deregister,
            LimiterBucket::PredecisionRefusal
        ),
        ChargeOutcome::Admitted,
        "the overflow bucket for the absent pair starts full"
    );
    assert_eq!(
        limiter.entry_count(),
        MAX_LIMITER_ENTRIES,
        "the overflow buckets are not counted against the cap and insert nothing"
    );
    assert!(
        matches!(
            limiter.charge(
                &caller("unix-peer:uid=another"),
                AuditVerb::Deregister,
                LimiterBucket::PredecisionRefusal
            ),
            ChargeOutcome::Limited { .. }
        ),
        "the overflow bucket is shared, so its one token is now spent"
    );
    assert_eq!(counts.count(LimiterBucket::PredecisionRefusal), 1);

    // And the (Mint, Admission) overflow bucket is a different bucket
    // again, with its own token.
    assert_eq!(
        limiter.charge(&stranger, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Admitted
    );
    assert!(matches!(
        limiter.charge(&stranger, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Limited { .. }
    ));
    assert_eq!(limiter.entry_count(), MAX_LIMITER_ENTRIES);
}

/// The reclaim step removes every entry at full burst or none, and never
/// a drained one — which is what keeps waiting from being a bypass.
#[tokio::test]
async fn reclaiming_never_removes_an_entry_below_its_burst() {
    pause();
    let settings = VerbRateLimiterSettings {
        admission_burst: 2,
        admission_refill_interval_ms: 1_000,
        predecision_refusal_burst: 2,
        predecision_refusal_refill_interval_ms: 1_000,
    };
    let (limiter, _) = VerbRateLimiter::with_counting_sink(settings);
    // The first entry spends one of its two tokens and stays drained,
    // because the clock never advances.
    let held = caller("unix-peer:uid=held");
    assert_eq!(
        limiter.charge(&held, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Admitted
    );
    // Fill the rest of the map. Every entry, this one included, is now
    // strictly below its burst, which is the state the reclaim rule has
    // to leave alone.
    for index in 0..(MAX_LIMITER_ENTRIES - 1) {
        limiter.charge(
            &caller(&format!("unix-peer:uid={index}")),
            AuditVerb::Mint,
            LimiterBucket::Admission,
        );
    }
    assert_eq!(limiter.entry_count(), MAX_LIMITER_ENTRIES);

    // Spend the held entry's remaining token, so it is strictly below its
    // burst, then advance by less than one refill interval: no entry is
    // full, so the reclaim frees nothing and the newcomer takes the
    // overflow bucket instead of evicting anybody.
    assert_eq!(
        limiter.charge(&held, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Admitted
    );
    advance(Duration::from_millis(200)).await;
    limiter.charge(
        &caller("unix-peer:uid=newcomer"),
        AuditVerb::Mint,
        LimiterBucket::Admission,
    );
    assert_eq!(
        limiter.entry_count(),
        MAX_LIMITER_ENTRIES,
        "no drained entry may be removed"
    );
    // The held entry kept its drained state rather than being handed a
    // fresh budget.
    assert!(matches!(
        limiter.charge(&held, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Limited { .. }
    ));
}

/// The shipped default sink keeps one `u64` per bucket, and a flood
/// driven at one bucket moves only that bucket's counter.
#[tokio::test]
async fn the_default_sink_counts_each_bucket_separately() {
    pause();
    let (limiter, counts) = VerbRateLimiter::with_counting_sink(tiny());
    let identity = caller(CALLER);
    assert_eq!(counts.count(LimiterBucket::PredecisionRefusal), 0);
    assert_eq!(counts.count(LimiterBucket::Admission), 0);

    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::PredecisionRefusal,
        2,
    );
    for _ in 0..5 {
        limiter.charge(
            &identity,
            AuditVerb::Mint,
            LimiterBucket::PredecisionRefusal,
        );
    }
    assert_eq!(counts.count(LimiterBucket::PredecisionRefusal), 5);
    assert_eq!(
        counts.count(LimiterBucket::Admission),
        0,
        "the admission counter must not move for a refusal flood"
    );

    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
    for _ in 0..2 {
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission);
    }
    assert_eq!(counts.count(LimiterBucket::Admission), 2);
    assert_eq!(counts.count(LimiterBucket::PredecisionRefusal), 5);
}

/// One event per limited invocation, carrying the identity, the verb and
/// the bucket that had no token.
#[derive(Debug, Default)]
struct RecordingSink {
    events: std::sync::Mutex<Vec<LimitedInvocation>>,
}

impl LimitedInvocationSink for RecordingSink {
    fn limited(&self, event: &LimitedInvocation) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
    }
}

#[tokio::test]
async fn a_limited_invocation_publishes_one_event_carrying_its_key() {
    pause();
    let sink = Arc::new(RecordingSink::default());
    let limiter = VerbRateLimiter::new(tiny(), sink.clone());
    let identity = caller(CALLER);
    drain(
        &limiter,
        &identity,
        AuditVerb::Deregister,
        LimiterBucket::PredecisionRefusal,
        2,
    );
    assert!(
        sink.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty(),
        "an admitted charge publishes nothing"
    );
    limiter.charge(
        &identity,
        AuditVerb::Deregister,
        LimiterBucket::PredecisionRefusal,
    );
    let events = sink
        .events
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(events.len(), 1, "exactly one event per limited invocation");
    let event = events.first().expect("one event");
    assert_eq!(event.caller(), &identity);
    assert_eq!(event.verb(), AuditVerb::Deregister);
    assert_eq!(event.bucket(), LimiterBucket::PredecisionRefusal);
}

/// The limiter functions identically with a sink that publishes nothing.
#[tokio::test]
async fn the_limiter_functions_with_a_sink_that_does_nothing() {
    pause();
    let limiter = VerbRateLimiter::new(tiny(), Arc::new(NoopLimitedInvocationSink));
    let identity = caller(CALLER);
    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
    assert!(matches!(
        limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
        ChargeOutcome::Limited { .. }
    ));
}

/// A sink that takes another sink and forwards to it — the composability
/// the sibling record work's coalescing sink depends on. Driving the
/// limiter through it still advances the wrapped sink's two counters.
#[derive(Debug)]
struct ForwardingSink {
    inner: Arc<CountingLimitedInvocationSink>,
    seen: AtomicUsize,
}

impl LimitedInvocationSink for ForwardingSink {
    fn limited(&self, event: &LimitedInvocation) {
        self.seen.fetch_add(1, Ordering::Relaxed);
        self.inner.limited(event);
    }
}

#[tokio::test]
async fn a_forwarding_wrapper_still_advances_the_wrapped_counters() {
    pause();
    let counts = Arc::new(CountingLimitedInvocationSink::new());
    let wrapper = Arc::new(ForwardingSink {
        inner: counts.clone(),
        seen: AtomicUsize::new(0),
    });
    let limiter = VerbRateLimiter::new(tiny(), wrapper.clone());
    let identity = caller(CALLER);
    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::PredecisionRefusal,
        2,
    );
    limiter.charge(
        &identity,
        AuditVerb::Mint,
        LimiterBucket::PredecisionRefusal,
    );
    drain(
        &limiter,
        &identity,
        AuditVerb::Mint,
        LimiterBucket::Admission,
        3,
    );
    limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission);
    assert_eq!(wrapper.seen.load(Ordering::Relaxed), 2);
    assert_eq!(counts.count(LimiterBucket::PredecisionRefusal), 1);
    assert_eq!(counts.count(LimiterBucket::Admission), 1);
}

/// The shipped defaults absorb the reference deployment's whole bring-up
/// wave — 64 hosts × 8 modules — without limiting a single mint.
#[tokio::test]
async fn the_shipped_defaults_absorb_the_reference_bring_up_wave() {
    pause();
    let (limiter, counts) = VerbRateLimiter::with_counting_sink(VerbRateLimiterSettings::default());
    let identity = caller(CALLER);
    for mint in 0..(64 * 8) {
        assert_eq!(
            limiter.charge(&identity, AuditVerb::Mint, LimiterBucket::Admission),
            ChargeOutcome::Admitted,
            "mint {mint} of a legitimate 64 × 8 wave must not be limited"
        );
    }
    assert_eq!(counts.count(LimiterBucket::Admission), 0);
}

/// The four `registrar.rate_limit_*` keys are the whole of how
/// configuration reaches the limiter.
#[test]
fn the_sizing_is_read_from_the_registrar_settings() {
    let settings = crate::config::RegistrarSettings::default();
    assert_eq!(
        VerbRateLimiterSettings::from(&settings),
        VerbRateLimiterSettings::default()
    );
}

/// The sizing clamp keeps a zero — which validation already rejects at
/// load — from becoming a division by zero or a bucket that can never
/// hold a token.
#[tokio::test]
async fn a_zero_sizing_is_clamped_rather_than_dividing_by_zero() {
    pause();
    let sizing = BucketSizing::new(0, 0);
    let mut bucket = TokenBucket::full(sizing, tokio::time::Instant::now());
    let now = tokio::time::Instant::now();
    assert_eq!(bucket.charge(now), ChargeOutcome::Admitted);
    assert!(matches!(
        bucket.charge(now),
        ChargeOutcome::Limited { retry_after: 1 }
    ));
}
