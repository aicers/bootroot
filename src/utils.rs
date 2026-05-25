use std::future::Future;
use std::time::Duration;

use anyhow::Result;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::{SecureRandom, SystemRandom};

pub const MIN_JITTER_DELAY_NANOS: i128 = 1_000_000_000;

/// Generates a cryptographically secure random secret encoded as
/// URL-safe base64 (no padding).
///
/// # Errors
///
/// Returns an error if the system random number generator fails.
pub fn generate_secret(len: usize) -> Result<String> {
    let mut buffer = vec![0u8; len];
    let rng = SystemRandom::new();
    rng.fill(&mut buffer)
        .map_err(|_| anyhow::anyhow!("Failed to generate random secret"))?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

/// Retries an operation using the provided backoff delays.
///
/// # Panics
///
/// Panics if the internal delay index is out of bounds, which cannot
/// happen because `attempt` never exceeds `delays.len()`.
///
/// # Errors
///
/// Returns the final error if all attempts fail.
pub async fn retry_with_backoff<F, Fut>(delays: &[u64], mut operation: F) -> anyhow::Result<()>
where
    F: FnMut(usize, usize) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let remaining = delays.len().saturating_sub(attempt - 1);
        match operation(attempt, remaining).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                if attempt > delays.len() {
                    return Err(err);
                }
                let delay = delays
                    .get(attempt - 1)
                    .copied()
                    .expect("attempt is within delays.len() bounds");
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

/// Retries an operation using custom sleep logic between attempts.
///
/// `delays` defines the inter-attempt waits, so the total number of
/// attempts is `delays.len() + 1`: `delays[i]` is slept between
/// attempt `i + 1` and attempt `i + 2`. With `delays = [5, 10, 30, 60]`
/// the operation is invoked at cumulative offsets 0/5/15/45/105s.
///
/// # Errors
/// Returns the final error if all attempts fail.
pub async fn retry_with_backoff_and_sleep<IssueFn, IssueFut, SleepFn, SleepFut, OnError>(
    mut issue_fn: IssueFn,
    mut sleep_fn: SleepFn,
    mut on_error: OnError,
    delays: &[u64],
) -> anyhow::Result<()>
where
    IssueFn: FnMut() -> IssueFut,
    IssueFut: Future<Output = anyhow::Result<()>>,
    SleepFn: FnMut(Duration) -> SleepFut,
    SleepFut: Future<Output = ()>,
    OnError: FnMut(usize, &anyhow::Error),
{
    let total_attempts = delays.len() + 1;
    let mut last_err = None;
    for attempt in 0..total_attempts {
        match issue_fn().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                on_error(attempt + 1, &err);
                last_err = Some(err);
                if let Some(delay) = delays.get(attempt) {
                    sleep_fn(Duration::from_secs(*delay)).await;
                }
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("Operation failed")))
}

/// Calculates a jittered delay based on the current time.
#[must_use]
pub fn jittered_delay(base: Duration, jitter: Duration) -> Duration {
    let now_ns = time::OffsetDateTime::now_utc()
        .unix_timestamp_nanos()
        .max(0);
    jittered_delay_with_seed(base, jitter, now_ns)
}

#[must_use]
pub fn jittered_delay_with_seed(base: Duration, jitter: Duration, now_ns: i128) -> Duration {
    let jitter_ns = i128::try_from(jitter.as_nanos()).unwrap_or(i128::MAX);
    if jitter_ns == 0 {
        return base;
    }

    let base_ns = i128::try_from(base.as_nanos()).unwrap_or(i128::MAX);
    let span = jitter_ns.saturating_mul(2).saturating_add(1);
    let offset = (now_ns % span) - jitter_ns;
    let adjusted = (base_ns + offset).max(MIN_JITTER_DELAY_NANOS);
    let adjusted = adjusted.min(i128::from(u64::MAX));
    let adjusted = u64::try_from(adjusted).unwrap_or(u64::MAX);

    Duration::from_nanos(adjusted)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    const DEFAULT_BACKOFF: [u64; 4] = [5, 10, 30, 60];

    #[tokio::test]
    async fn retry_with_backoff_and_sleep_exhausts_all_delays() {
        // Pins the inter-attempt semantics: `delays.len() + 1` attempts and
        // every delay is slept, so [5, 10, 30, 60] yields attempts at
        // cumulative 0/5/15/45/105s (matching the intent recorded in #303
        // and the fix for #617).
        let attempts = Arc::new(Mutex::new(0usize));
        let sleeps = Arc::new(Mutex::new(Vec::new()));
        let errors = Arc::new(Mutex::new(Vec::new()));

        let attempts_issue = Arc::clone(&attempts);
        let issue_fn = move || {
            let attempts_inner = Arc::clone(&attempts_issue);
            async move {
                *attempts_inner.lock().expect("attempts mutex") += 1;
                anyhow::bail!("persistent failure")
            }
        };

        let sleeps_log = Arc::clone(&sleeps);
        let sleep_fn = move |duration: Duration| {
            let sleeps_inner = Arc::clone(&sleeps_log);
            async move {
                sleeps_inner.lock().expect("sleeps mutex").push(duration);
            }
        };

        let errors_log = Arc::clone(&errors);
        let on_error = move |attempt: usize, _err: &anyhow::Error| {
            errors_log.lock().expect("errors mutex").push(attempt);
        };

        let result =
            retry_with_backoff_and_sleep(issue_fn, sleep_fn, on_error, &DEFAULT_BACKOFF).await;

        assert!(result.is_err());
        assert_eq!(
            *attempts.lock().expect("attempts mutex"),
            DEFAULT_BACKOFF.len() + 1
        );
        assert_eq!(
            *sleeps.lock().expect("sleeps mutex"),
            DEFAULT_BACKOFF
                .iter()
                .copied()
                .map(Duration::from_secs)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            *errors.lock().expect("errors mutex"),
            (1..=DEFAULT_BACKOFF.len() + 1).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn retry_with_backoff_and_sleep_returns_on_success() {
        let attempts = Arc::new(Mutex::new(0usize));
        let sleeps = Arc::new(Mutex::new(Vec::new()));

        let attempts_issue = Arc::clone(&attempts);
        let issue_fn = move || {
            let attempts_inner = Arc::clone(&attempts_issue);
            async move {
                let mut guard = attempts_inner.lock().expect("attempts mutex");
                *guard += 1;
                if *guard < 3 {
                    anyhow::bail!("transient");
                }
                Ok(())
            }
        };

        let sleeps_log = Arc::clone(&sleeps);
        let sleep_fn = move |duration: Duration| {
            let sleeps_inner = Arc::clone(&sleeps_log);
            async move {
                sleeps_inner.lock().expect("sleeps mutex").push(duration);
            }
        };

        let result =
            retry_with_backoff_and_sleep(issue_fn, sleep_fn, |_, _| {}, &DEFAULT_BACKOFF).await;

        assert!(result.is_ok());
        assert_eq!(*attempts.lock().expect("attempts mutex"), 3);
        assert_eq!(
            *sleeps.lock().expect("sleeps mutex"),
            vec![Duration::from_secs(5), Duration::from_secs(10)]
        );
    }

    #[tokio::test]
    async fn retry_with_backoff_and_sleep_runs_once_when_delays_empty() {
        let attempts = Arc::new(Mutex::new(0usize));
        let sleeps = Arc::new(Mutex::new(Vec::new()));

        let attempts_issue = Arc::clone(&attempts);
        let issue_fn = move || {
            let attempts_inner = Arc::clone(&attempts_issue);
            async move {
                *attempts_inner.lock().expect("attempts mutex") += 1;
                anyhow::bail!("boom")
            }
        };

        let sleeps_log = Arc::clone(&sleeps);
        let sleep_fn = move |duration: Duration| {
            let sleeps_inner = Arc::clone(&sleeps_log);
            async move {
                sleeps_inner.lock().expect("sleeps mutex").push(duration);
            }
        };

        let result = retry_with_backoff_and_sleep(issue_fn, sleep_fn, |_, _| {}, &[]).await;

        assert!(result.is_err());
        assert_eq!(*attempts.lock().expect("attempts mutex"), 1);
        assert!(sleeps.lock().expect("sleeps mutex").is_empty());
    }
}
