use std::future::Future;
use std::time::Duration;

pub const MIN_JITTER_DELAY_NANOS: i128 = 1_000_000_000;

/// Retries an operation using the provided backoff delays.
///
/// # Errors
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
                let delay = delays[attempt - 1];
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

/// Retries an operation using custom sleep logic between attempts.
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
    if delays.is_empty() {
        return match issue_fn().await {
            Ok(()) => Ok(()),
            Err(err) => {
                on_error(1, &err);
                Err(err)
            }
        };
    }

    let mut last_err = None;
    for (attempt, delay) in delays.iter().enumerate() {
        match issue_fn().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                on_error(attempt + 1, &err);
                last_err = Some(err);
                if attempt + 1 < delays.len() {
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
