//! The two token buckets both registrar verbs are charged against,
//! before either of them writes anything.
//!
//! Every invocation of either verb writes an `intent` record at entry and
//! an `outcome` record when it finishes, refusals included. That closes a
//! detection gap and opens a resource one: the cheapest refusals are the
//! ones the verbs' *pure* checks settle, before any `OpenBao` work, so a
//! compromised caller can grow the record store for free. A full
//! filesystem stops every mint, and — because the `OpenBao` file audit
//! device is mandatory — can stop `OpenBao` serving at all, on the one
//! host that must not be restarted.
//!
//! # Two words that are not synonyms
//!
//! An invocation is **limited** when the limiter suppressed its audit
//! records, which happens at *either* check point. It is **throttled**
//! when it is limited at the **admission** check point and therefore
//! receives [`VerbError::Throttled`] instead of an attempted verb. Every
//! throttled invocation is limited; the reverse does not hold — an
//! invocation limited on the pre-decision path keeps exactly the refusal
//! its own input earned.
//!
//! [`VerbError::Throttled`]: super::outcome::VerbError::Throttled
//!
//! # The bucket key
//!
//! `(client identity, verb, bucket)`, over the two-value
//! [`LimiterBucket`]. That enum is the **maximal refinement knowable
//! where the charge happens**: a pre-decision refusal *is* knowable
//! there, because the checks that produce it are pure and run before the
//! charge, while the outcome of an admitted invocation is settled by
//! `OpenBao` work that follows the intent write. Keying on the outcome
//! class would require charging after the durable write this limiter
//! exists to prevent.
//!
//! The key never carries the verbs' fine-grained refusal reason: a key
//! that varied with the reason would let a caller multiply its budget by
//! varying its refusal. The client identity is the opaque
//! [`CallerIdentity`] the verbs already carry, used as-is — never
//! parsed, normalised or stripped.
//!
//! # What the two buckets do and do not guarantee
//!
//! A flood on the `predecision_refusal` path cannot consume `admission`
//! budget, so the path an attacker can drive for free — no valid input,
//! no `OpenBao` cost — **cannot starve legitimate mints**. A caller that
//! can produce well-formed, derivable requests can still consume
//! `admission` budget with invocations that end in refusal, because at
//! admission nothing distinguishes them from a real mint. That residual
//! is bounded by **attacker cost** rather than by this limiter: every
//! such attempt spends `OpenBao` work as well as an admission token.
//!
//! # Bounding the map
//!
//! One entry per key, capped at [`MAX_LIMITER_ENTRIES`] entries — not
//! identities, because entries are what consume the memory and a cap
//! counted in identities cannot be honoured by removing a bucket at all.
//! A charge whose key is absent inserts a full bucket below the cap; at
//! the cap it first reclaims **every entry currently refilled to its full
//! burst**, which is indistinguishable from an absent one and so hands
//! nobody a token; and if that frees nothing — every remaining entry is
//! drained — it charges the [`OverflowBuckets`] entry for its `(verb,
//! bucket)` pair. Those four are created with the limiter, are never
//! reclaimed and are not counted against the cap, which is what makes the
//! miss path *total*: no invocation is ever admitted unlimited for want
//! of a slot.
//!
//! While the map is saturated with drained entries, every identity
//! without an entry of its own shares the four overflow buckets, so in
//! that degraded state one caller's flood can throttle another's. That is
//! inherent to any bounded map, and what matters is that it is bounded
//! rather than unlimited.
//!
//! # The bucket itself
//!
//! A token bucket rather than a fixed or sliding window: a fixed window
//! lets a caller spend two full budgets back to back across a boundary,
//! while a token bucket states the legitimate burst and the sustained
//! rate as two independent numbers. Tokens accrue at one per refill
//! interval, are capped at the burst, and are computed from
//! [`tokio::time::Instant`] — a **monotonic** clock, so a wall-clock step
//! cannot mint tokens.
//!
//! A bucket starts full, is held in memory only, and is created lazily,
//! so a freshly started endpoint absorbs the full documented bring-up
//! wave immediately. Nothing is persisted: durable limiter state would
//! have to live on the very store this mechanism protects. Restarting the
//! daemon therefore resets every bucket, which is acceptable because
//! restarting it requires root on the bootroot host, and root compromise
//! of that host is outside what this design defends against.
//!
//! **An entry is removed only while it holds a full burst — never below
//! it, anywhere, for any reason.** Removing a full entry is
//! indistinguishable from recreating it; removing a drained one silently
//! hands that caller a fresh budget, which is a limiter bypass reachable
//! by waiting.

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use tokio::time::{Duration, Instant};

use super::outcome::CallerIdentity;
use crate::registrar::audit::AuditVerb;

/// The cap on the limiter's map, counted in **bucket entries**.
///
/// The reference deployment's `64` identities × the four buckets each
/// identity can create. With one registrar identity it is never reached
/// in normal operation; it exists so that a future identity source
/// varying per connection becomes a bounded degradation rather than
/// memory exhaustion on the bootroot host.
pub(crate) const MAX_LIMITER_ENTRIES: usize = 256;

/// Default `registrar.rate_limit_admission_burst`.
///
/// The reference deployment's bring-up wave: `64` hosts × `8` modules =
/// `512` mints at once. See [`VerbRateLimiterSettings`].
pub(crate) const DEFAULT_RATE_LIMIT_ADMISSION_BURST: u32 = 512;

/// Default `registrar.rate_limit_admission_refill_interval_ms`: two
/// tokens per second sustained.
pub(crate) const DEFAULT_RATE_LIMIT_ADMISSION_REFILL_INTERVAL_MS: u32 = 500;

/// Default `registrar.rate_limit_predecision_refusal_burst`.
///
/// Much smaller than the admission burst because legitimate pre-decision
/// refusals are operator typos arriving one at a time.
pub(crate) const DEFAULT_RATE_LIMIT_PREDECISION_REFUSAL_BURST: u32 = 32;

/// Default `registrar.rate_limit_predecision_refusal_refill_interval_ms`:
/// one token per second sustained.
pub(crate) const DEFAULT_RATE_LIMIT_PREDECISION_REFUSAL_REFILL_INTERVAL_MS: u32 = 1000;

/// Which of an invocation's two buckets a charge lands in.
///
/// Exactly two values, and deliberately so — see this module's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LimiterBucket {
    /// The invocation was refused by the verbs' pure checks:
    /// `pre_derivation`, plus `WrapTtlPolicy::grant` for a mint. Every
    /// such invocation is a refusal by construction, it performs no
    /// `OpenBao` work, and it is the cheapest thing a caller can make
    /// the daemon do.
    ///
    /// This is the enumerated set of checks and nothing else. It is not
    /// "every refusal reached without I/O": `derive_registration_id` is
    /// synchronous and touches nothing outside the process, and its
    /// failures are `admission` refusals all the same, because they are
    /// settled *after* the charge. A check added to the verbs later
    /// joins this set only by being added to that list, deliberately and
    /// with its own reason.
    PredecisionRefusal,
    /// The invocation passed those checks and may therefore reach
    /// `OpenBao`, whatever it turns out to be. The bucket is fixed at
    /// the charge point and is never revised by what the invocation
    /// turns out to be.
    Admission,
}

impl LimiterBucket {
    /// Returns the bucket's stable wire-facing spelling.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::PredecisionRefusal => "predecision_refusal",
            Self::Admission => "admission",
        }
    }
}

impl fmt::Display for LimiterBucket {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One limited invocation, as the sink sees it.
///
/// Both check points publish exactly one of these per limited
/// invocation, carrying the client identity, the verb and the bucket
/// that had no token. Suppressing the record is not suppressing the
/// evidence: skip this and the chain that counts a flood has nothing to
/// count, making a flood least visible exactly while it is worst.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LimitedInvocation {
    caller: CallerIdentity,
    verb: AuditVerb,
    bucket: LimiterBucket,
}

impl LimitedInvocation {
    /// Returns the client identity the charge was keyed on, verbatim.
    pub(crate) fn caller(&self) -> &CallerIdentity {
        &self.caller
    }

    /// Returns the verb whose bucket had no token.
    pub(crate) fn verb(&self) -> AuditVerb {
        self.verb
    }

    /// Returns which of the two buckets was empty.
    pub(crate) fn bucket(&self) -> LimiterBucket {
        self.bucket
    }
}

/// Where limited-invocation events are published.
///
/// The limiter holds exactly **one** sink. An implementation that wants
/// to observe events without displacing an existing one takes that one
/// and forwards to it — which is how the sibling record work installs a
/// coalescing sink around [`CountingLimitedInvocationSink`] while leaving
/// its two counters the single implementation in the tree.
pub(crate) trait LimitedInvocationSink: fmt::Debug + Send + Sync {
    /// Publishes one limited invocation.
    ///
    /// Called with no limiter lock held, so an implementation may do
    /// whatever it needs to without deadlocking the check point.
    fn limited(&self, event: &LimitedInvocation);
}

/// The shipped default sink: one `u64` per bucket, since daemon start.
///
/// Two counters rather than one sum, because the two mean opposite
/// things to an operator. A `predecision_refusal` count rising says
/// someone is flooding malformed input while those callers still got
/// their real answers; an `admission` count rising says legitimate
/// traffic is being held back and a bring-up may be stalling. A single
/// total would have to be split again downstream, and it cannot be.
#[derive(Debug, Default)]
pub(crate) struct CountingLimitedInvocationSink {
    predecision_refusal: AtomicU64,
    admission: AtomicU64,
}

impl CountingLimitedInvocationSink {
    /// Creates a sink with both counters at zero.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Returns how many invocations have been limited on `bucket` since
    /// this sink was created.
    pub(crate) fn count(&self, bucket: LimiterBucket) -> u64 {
        match bucket {
            LimiterBucket::PredecisionRefusal => self.predecision_refusal.load(Ordering::Relaxed),
            LimiterBucket::Admission => self.admission.load(Ordering::Relaxed),
        }
    }
}

impl LimitedInvocationSink for CountingLimitedInvocationSink {
    fn limited(&self, event: &LimitedInvocation) {
        let counter = match event.bucket() {
            LimiterBucket::PredecisionRefusal => &self.predecision_refusal,
            LimiterBucket::Admission => &self.admission,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// A sink that publishes nothing.
///
/// For a deployment — or a test — that wants the limiter's bound without
/// its counters. The limiter functions identically with it.
#[derive(Debug, Default)]
pub(crate) struct NoopLimitedInvocationSink;

impl LimitedInvocationSink for NoopLimitedInvocationSink {
    fn limited(&self, _event: &LimitedInvocation) {}
}

/// One bucket's two independent numbers: the legitimate burst, and the
/// sustained rate expressed as an interval per token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BucketSizing {
    burst: u32,
    refill_interval: Duration,
}

impl BucketSizing {
    /// Builds a sizing from the configured burst and millisecond refill
    /// interval.
    ///
    /// Both are clamped up to `1`. `validate_registrar_settings` already
    /// rejects a zero for either, and the clamp is what keeps that a
    /// configuration error rather than a division by zero or a bucket
    /// that can never hold a token: no arithmetic below has to ask
    /// whether the interval is zero.
    fn new(burst: u32, refill_interval_ms: u32) -> Self {
        Self {
            burst: burst.max(1),
            refill_interval: Duration::from_millis(u64::from(refill_interval_ms.max(1))),
        }
    }
}

/// The four configured numbers the limiter is sized from.
///
/// Every one is an unsigned integer, and the refill rates are expressed
/// as **intervals** rather than rates on purpose: a rate would have to be
/// fractional to express "one token per second or slower", which drags in
/// negative zero, NaN, infinity and precision questions that all have to
/// be validated away.
///
/// # Sizing
///
/// `admission_burst >= wave_hosts × modules_per_host`, where
/// `wave_hosts` is the largest number of hosts an operator brings up at
/// once and `modules_per_host` the largest number of components on one
/// host. The shipped default assumes the reference deployment's `64 × 8
/// = 512` mints in one wave. A wave larger than the burst still
/// completes rather than being refused, taking `(mints − burst) ×
/// admission_refill_interval_ms / 1000` extra seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VerbRateLimiterSettings {
    /// Tokens an idle `admission` bucket holds.
    pub(crate) admission_burst: u32,
    /// Milliseconds per token accrued into an `admission` bucket.
    pub(crate) admission_refill_interval_ms: u32,
    /// Tokens an idle `predecision_refusal` bucket holds.
    pub(crate) predecision_refusal_burst: u32,
    /// Milliseconds per token accrued into a `predecision_refusal`
    /// bucket.
    pub(crate) predecision_refusal_refill_interval_ms: u32,
}

impl Default for VerbRateLimiterSettings {
    fn default() -> Self {
        Self {
            admission_burst: DEFAULT_RATE_LIMIT_ADMISSION_BURST,
            admission_refill_interval_ms: DEFAULT_RATE_LIMIT_ADMISSION_REFILL_INTERVAL_MS,
            predecision_refusal_burst: DEFAULT_RATE_LIMIT_PREDECISION_REFUSAL_BURST,
            predecision_refusal_refill_interval_ms:
                DEFAULT_RATE_LIMIT_PREDECISION_REFUSAL_REFILL_INTERVAL_MS,
        }
    }
}

impl VerbRateLimiterSettings {
    /// Returns the sizing every bucket for `bucket` is created with —
    /// map entries and the overflow bucket alike.
    fn sizing(self, bucket: LimiterBucket) -> BucketSizing {
        match bucket {
            LimiterBucket::PredecisionRefusal => BucketSizing::new(
                self.predecision_refusal_burst,
                self.predecision_refusal_refill_interval_ms,
            ),
            LimiterBucket::Admission => {
                BucketSizing::new(self.admission_burst, self.admission_refill_interval_ms)
            }
        }
    }
}

impl From<&crate::config::RegistrarSettings> for VerbRateLimiterSettings {
    /// Reads the four `registrar.rate_limit_*` keys into the limiter's
    /// sizing, which is the whole of how configuration reaches it.
    fn from(settings: &crate::config::RegistrarSettings) -> Self {
        Self {
            admission_burst: settings.rate_limit_admission_burst,
            admission_refill_interval_ms: settings.rate_limit_admission_refill_interval_ms,
            predecision_refusal_burst: settings.rate_limit_predecision_refusal_burst,
            predecision_refusal_refill_interval_ms: settings
                .rate_limit_predecision_refusal_refill_interval_ms,
        }
    }
}

/// What one charge decided.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChargeOutcome {
    /// A token was available and has been spent.
    Admitted,
    /// The charged bucket was empty. The invocation is **limited**: its
    /// audit records are suppressed and one event has been published.
    Limited {
        /// Whole seconds until the charged bucket holds one token, with
        /// a floor of `1`. A duration, never a deadline, so it does not
        /// depend on the caller's clock agreeing with the daemon's. Only
        /// the admission check point puts it on the wire.
        retry_after: u64,
    },
}

/// A lazily created token bucket.
#[derive(Debug)]
struct TokenBucket {
    burst: u32,
    refill_interval: Duration,
    tokens: u32,
    /// The instant the tokens now held were accrued as of. Advanced by
    /// whole refill intervals so a partial interval is never discarded,
    /// and pinned to `now` once the bucket is full so an idle bucket
    /// cannot bank an unbounded remainder.
    accrued_at: Instant,
}

impl TokenBucket {
    /// Creates a bucket holding a full burst.
    fn full(sizing: BucketSizing, now: Instant) -> Self {
        Self {
            burst: sizing.burst,
            refill_interval: sizing.refill_interval,
            tokens: sizing.burst,
            accrued_at: now,
        }
    }

    /// Accrues whatever whole intervals have elapsed, capped at the
    /// burst.
    fn refill(&mut self, now: Instant) {
        if self.tokens >= self.burst {
            self.accrued_at = now;
            return;
        }
        let elapsed = now.saturating_duration_since(self.accrued_at);
        let gained = elapsed.as_nanos() / self.refill_interval.as_nanos();
        let gained = u32::try_from(gained).unwrap_or(u32::MAX);
        if gained == 0 {
            return;
        }
        self.tokens = self.tokens.saturating_add(gained).min(self.burst);
        self.accrued_at = self
            .refill_interval
            .checked_mul(gained)
            .and_then(|consumed| self.accrued_at.checked_add(consumed))
            .unwrap_or(now);
        if self.tokens >= self.burst {
            self.accrued_at = now;
        }
    }

    /// Reports whether this bucket is refilled to its full burst, which
    /// is the one condition under which its entry may be removed.
    fn is_full(&mut self, now: Instant) -> bool {
        self.refill(now);
        self.tokens >= self.burst
    }

    /// Spends one token, or reports how long until there is one.
    fn charge(&mut self, now: Instant) -> ChargeOutcome {
        self.refill(now);
        if self.tokens > 0 {
            self.tokens -= 1;
            return ChargeOutcome::Admitted;
        }
        ChargeOutcome::Limited {
            retry_after: self.retry_after(now),
        }
    }

    /// Whole seconds until the next token accrues, floored at `1`.
    ///
    /// The floor is what keeps a value of `0` — an invitation to retry
    /// immediately, into the bucket that just refused — off the wire.
    fn retry_after(&self, now: Instant) -> u64 {
        let elapsed = now.saturating_duration_since(self.accrued_at);
        let remaining = self.refill_interval.saturating_sub(elapsed);
        let whole_seconds = remaining.as_secs() + u64::from(remaining.subsec_nanos() > 0);
        whole_seconds.max(1)
    }
}

/// The four buckets a charge falls back to when the map is saturated.
///
/// One per `(verb, bucket)` pair, so the miss path is **total**:
/// whatever the map holds, there is always exactly one bucket to charge.
/// Charging "some existing entry for the same pair" would not be — a
/// saturated map need not contain that pair at all — and it would spend
/// one identity's budget on another's traffic by an unspecified choice of
/// victim.
#[derive(Debug)]
struct OverflowBuckets {
    mint_predecision_refusal: TokenBucket,
    mint_admission: TokenBucket,
    deregister_predecision_refusal: TokenBucket,
    deregister_admission: TokenBucket,
}

impl OverflowBuckets {
    fn new(settings: VerbRateLimiterSettings, now: Instant) -> Self {
        let refusal = settings.sizing(LimiterBucket::PredecisionRefusal);
        let admission = settings.sizing(LimiterBucket::Admission);
        Self {
            mint_predecision_refusal: TokenBucket::full(refusal, now),
            mint_admission: TokenBucket::full(admission, now),
            deregister_predecision_refusal: TokenBucket::full(refusal, now),
            deregister_admission: TokenBucket::full(admission, now),
        }
    }

    /// Returns the one overflow bucket for a pair. Exhaustive by
    /// construction, so there is nothing here to index and nothing to
    /// unwrap.
    fn get_mut(&mut self, verb: AuditVerb, bucket: LimiterBucket) -> &mut TokenBucket {
        match (verb, bucket) {
            (AuditVerb::Mint, LimiterBucket::PredecisionRefusal) => {
                &mut self.mint_predecision_refusal
            }
            (AuditVerb::Mint, LimiterBucket::Admission) => &mut self.mint_admission,
            (AuditVerb::Deregister, LimiterBucket::PredecisionRefusal) => {
                &mut self.deregister_predecision_refusal
            }
            (AuditVerb::Deregister, LimiterBucket::Admission) => &mut self.deregister_admission,
        }
    }
}

/// One entry's key: the opaque client identity, the verb, and which of
/// its two buckets.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BucketKey {
    caller: CallerIdentity,
    verb: AuditVerb,
    bucket: LimiterBucket,
}

/// Everything one limiter guards behind a single lock.
#[derive(Debug)]
struct LimiterState {
    entries: HashMap<BucketKey, TokenBucket>,
    overflow: OverflowBuckets,
}

impl LimiterState {
    /// Drops **every entry currently refilled to its full burst, or
    /// none**. A full entry is indistinguishable from an absent one,
    /// since both yield a full bucket on next use, so this frees slots
    /// without handing anybody a token, and it needs no victim-selection
    /// policy.
    fn reclaim_full_entries(&mut self, now: Instant) {
        self.entries.retain(|_, bucket| !bucket.is_full(now));
    }
}

#[derive(Debug)]
struct LimiterInner {
    settings: VerbRateLimiterSettings,
    sink: Arc<dyn LimitedInvocationSink>,
    state: StdMutex<LimiterState>,
}

/// The limiter both verbs are charged against.
///
/// A construction dependency like every other field on
/// `RegistrarVerbsConfig`: the verbs receive it and can neither choose
/// its sizing nor decline to have one, and nothing in a request reaches
/// it. Cloning shares one map and one sink, exactly as cloning the audit
/// store shares one serialization lock.
#[derive(Debug, Clone)]
pub(crate) struct VerbRateLimiter {
    inner: Arc<LimiterInner>,
}

impl VerbRateLimiter {
    /// Creates a limiter over `settings`, publishing limited invocations
    /// through `sink`.
    pub(crate) fn new(
        settings: VerbRateLimiterSettings,
        sink: Arc<dyn LimitedInvocationSink>,
    ) -> Self {
        let now = Instant::now();
        Self {
            inner: Arc::new(LimiterInner {
                settings,
                sink,
                state: StdMutex::new(LimiterState {
                    entries: HashMap::new(),
                    overflow: OverflowBuckets::new(settings, now),
                }),
            }),
        }
    }

    /// Creates a limiter over `settings` with the shipped counting sink,
    /// and hands back a handle on those counters.
    pub(crate) fn with_counting_sink(
        settings: VerbRateLimiterSettings,
    ) -> (Self, Arc<CountingLimitedInvocationSink>) {
        let sink = Arc::new(CountingLimitedInvocationSink::new());
        (Self::new(settings, sink.clone()), sink)
    }

    /// Charges one invocation's bucket and reports whether it may
    /// proceed.
    ///
    /// **Synchronous, and the lock is taken and released inside.** The
    /// decision is made here; everything after it runs under the locks
    /// the verbs already define, so no bucket lock is ever held across an
    /// `OpenBao` call or a record write.
    ///
    /// A limited charge publishes exactly one event before returning,
    /// with the lock already released.
    pub(crate) fn charge(
        &self,
        caller: &CallerIdentity,
        verb: AuditVerb,
        bucket: LimiterBucket,
    ) -> ChargeOutcome {
        let outcome = self.charge_locked(caller, verb, bucket, Instant::now());
        if matches!(outcome, ChargeOutcome::Limited { .. }) {
            self.inner.sink.limited(&LimitedInvocation {
                caller: caller.clone(),
                verb,
                bucket,
            });
        }
        outcome
    }

    /// The whole of what a charge does to the map, so the miss path is
    /// stated in one place.
    fn charge_locked(
        &self,
        caller: &CallerIdentity,
        verb: AuditVerb,
        bucket: LimiterBucket,
        now: Instant,
    ) -> ChargeOutcome {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let key = BucketKey {
            caller: caller.clone(),
            verb,
            bucket,
        };
        if let Some(entry) = state.entries.get_mut(&key) {
            return entry.charge(now);
        }
        if state.entries.len() >= MAX_LIMITER_ENTRIES {
            state.reclaim_full_entries(now);
        }
        if state.entries.len() < MAX_LIMITER_ENTRIES {
            let mut fresh = TokenBucket::full(self.inner.settings.sizing(bucket), now);
            let outcome = fresh.charge(now);
            state.entries.insert(key, fresh);
            return outcome;
        }
        state.overflow.get_mut(verb, bucket).charge(now)
    }

    /// Returns how many bucket entries the map holds, for the tests that
    /// assert the cap.
    pub(crate) fn entry_count(&self) -> usize {
        self.inner
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entries
            .len()
    }
}
