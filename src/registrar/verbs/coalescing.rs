//! Bounded, tumbling coalescing of limiter-suppressed invocations.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use time::{Duration as WallDuration, OffsetDateTime};
use tokio::time::{Duration, Instant};
use tracing::warn;

use super::limiter::{
    CountingLimitedInvocationSink, LimitedInvocation, LimitedInvocationSink, LimiterBucket,
    MAX_LIMITER_ENTRIES,
};
use super::outcome::CallerIdentity;
use crate::registrar::audit::{AuditRecord, AuditRecordStore, AuditVerb, LimitedBucket};

/// Maximum number of coalescing windows held open at once.
pub(crate) const MAX_OPEN_COALESCING_WINDOWS: usize = MAX_LIMITER_ENTRIES;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WindowKey {
    caller: CallerIdentity,
    verb: AuditVerb,
    bucket: LimiterBucket,
}

impl WindowKey {
    fn from_event(event: &LimitedInvocation) -> Self {
        Self {
            caller: event.caller().clone(),
            verb: event.verb(),
            bucket: event.bucket(),
        }
    }

    fn order_key(&self) -> (&str, &'static str, &'static str) {
        (
            self.caller.as_str(),
            match self.verb {
                AuditVerb::Mint => "mint",
                AuditVerb::Deregister => "deregister",
            },
            self.bucket.as_str(),
        )
    }
}

#[derive(Debug)]
struct OpenWindow {
    started_at: Instant,
    deadline: Instant,
    wall_start: OffsetDateTime,
    count: u64,
}

/// A limiter sink that keeps the delivered process-lifetime counters and
/// turns suppressed traffic into one durable record per bounded window.
#[derive(Debug)]
pub(crate) struct CoalescingLimitedInvocationSink {
    counts: Arc<CountingLimitedInvocationSink>,
    store: AuditRecordStore,
    window: Duration,
    windows: Mutex<HashMap<WindowKey, OpenWindow>>,
}

impl CoalescingLimitedInvocationSink {
    /// Creates the coalescing sink around the delivered counting sink.
    pub(crate) fn new(
        counts: Arc<CountingLimitedInvocationSink>,
        store: AuditRecordStore,
        window_seconds: u64,
    ) -> Self {
        Self {
            counts,
            store,
            window: Duration::from_secs(window_seconds.max(1)),
            windows: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the process-lifetime counters forwarded by this sink.
    pub(crate) fn counts(&self) -> &Arc<CountingLimitedInvocationSink> {
        &self.counts
    }

    /// Closes windows due by `now`; daemon maintenance calls this on its
    /// existing global cadence so silent keys leave evidence too.
    pub(crate) fn maintain(&self) {
        let now = Instant::now();
        let wall_now = OffsetDateTime::now_utc();
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        let keys: Vec<_> = windows
            .iter()
            .filter(|(_, window)| now >= window.deadline)
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            let (key, window) = windows
                .remove_entry(&key)
                .expect("due coalescing window is removable");
            self.write_closed(&key, &window, now, wall_now);
        }
    }

    /// Flushes every open window during orderly shutdown.
    pub(crate) fn flush(&self) {
        let now = Instant::now();
        let wall_now = OffsetDateTime::now_utc();
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        for (key, window) in windows.drain() {
            self.write_closed(&key, &window, now, wall_now);
        }
    }

    fn write_closed(
        &self,
        key: &WindowKey,
        window: &OpenWindow,
        now: Instant,
        wall_now: OffsetDateTime,
    ) {
        let elapsed = if now >= window.deadline {
            self.window
        } else {
            now.saturating_duration_since(window.started_at)
        };
        let end = window.wall_start + WallDuration::try_from(elapsed).unwrap_or(WallDuration::ZERO);
        let bucket = match key.bucket {
            LimiterBucket::PredecisionRefusal => LimitedBucket::PredecisionRefusal,
            LimiterBucket::Admission => LimitedBucket::Admission,
        };
        let record = AuditRecord::limited(
            wall_now,
            key.verb,
            key.caller.as_str().to_string(),
            bucket,
            window.count,
            window.wall_start,
            end,
        );
        // Limiter events are already suppressed traffic: a failure to record
        // their aggregate must never retrospectively change that caller's
        // response. This intentionally logs and continues.
        let result = tokio::runtime::Handle::try_current().map(|handle| {
            tokio::task::block_in_place(|| handle.block_on(self.store.append(record)))
        });
        match result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                warn!("could not append coalesced limited registrar audit record: {error}");
            }
            Err(error) => {
                warn!(
                    "could not append coalesced limited registrar audit record outside Tokio: {error}"
                );
            }
        }
    }

    fn close_oldest_for_capacity(
        windows: &mut HashMap<WindowKey, OpenWindow>,
    ) -> Option<(WindowKey, OpenWindow)> {
        if windows.len() < MAX_OPEN_COALESCING_WINDOWS {
            return None;
        }
        let oldest = windows
            .iter()
            .min_by(|(left_key, left), (right_key, right)| {
                left.started_at
                    .cmp(&right.started_at)
                    .then_with(|| left_key.order_key().cmp(&right_key.order_key()))
            })
            .map(|(key, _)| key.clone());
        oldest.and_then(|key| windows.remove(&key).map(|window| (key, window)))
    }
}

impl LimitedInvocationSink for CoalescingLimitedInvocationSink {
    fn limited(&self, event: &LimitedInvocation) {
        self.counts.limited(event);
        let now = Instant::now();
        let wall_now = OffsetDateTime::now_utc();
        let key = WindowKey::from_event(event);
        let mut windows = self.windows.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(window) = windows.get(&key) {
            if now < window.deadline {
                if let Some(window) = windows.get_mut(&key) {
                    window.count = window.count.saturating_add(1);
                }
                return;
            }
            let predecessor = windows
                .remove(&key)
                .expect("existing coalescing window is removable");
            // Keep this lock through the inline write and successor insertion.
            // Otherwise another arrival for this key can insert its successor
            // while this one is writing, and this insertion would overwrite
            // that count. The limiter deliberately calls sinks with its own
            // lock released, so this only serializes coalescing-map updates.
            self.write_closed(&key, &predecessor, now, wall_now);
        }
        let evicted = Self::close_oldest_for_capacity(&mut windows);
        if let Some((key, window)) = &evicted {
            // Keep the map one slot below its cap until the early record has
            // been closed, so a concurrent arrival cannot transiently exceed
            // the bound or insert ahead of the selected oldest window.
            self.write_closed(key, window, now, wall_now);
        }
        windows.insert(
            key,
            OpenWindow {
                started_at: now,
                deadline: now
                    .checked_add(self.window)
                    .expect("registrar settings validate coalescing deadlines"),
                wall_start: wall_now,
                count: 1,
            },
        );
    }
}

#[cfg(test)]
mod tests;
