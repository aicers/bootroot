//! Waiting on a condition that a service satisfies only once it is up.

use std::time::{Duration, SystemTime};

use anyhow::Result;
use tokio::time::sleep;

/// Polls `check` until it reports success or `timeout` elapses.
///
/// An `Err` is a retry, not an exit: callers poll a service over HTTP while
/// it may still be binding its port, and a refused or dropped connection
/// arrives as an `Err` rather than an `Ok(false)`. The error is kept across
/// polls and reported when the budget runs out, so a genuine failure still
/// arrives with its cause attached instead of as a bare timeout.
///
/// A later `Ok(false)` does not clear it. An error that the service then
/// recovered from is still the only cause anyone has to work from at a
/// timeout, and dropping it in favour of "not yet" is the diagnostic loss
/// retrying was meant to avoid. The message says the error is the last one
/// *seen*, not necessarily the last poll, so a reader is not told the
/// service was unreachable at the deadline.
///
/// # Errors
///
/// Returns an error once `timeout` has elapsed without `check` reporting
/// success, carrying the last error `check` returned — if it returned one —
/// as its cause.
pub(crate) async fn wait_for<F, Fut>(timeout: Duration, mut check: F) -> Result<()>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<bool>>,
{
    let started = SystemTime::now();
    let mut last_error: Option<anyhow::Error> = None;
    loop {
        match check().await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => last_error = Some(error),
        }
        if started.elapsed().unwrap_or_default() > timeout {
            return Err(match last_error {
                Some(error) => error.context("Timed out waiting for condition; last error seen"),
                None => anyhow::anyhow!("Timed out waiting for condition"),
            });
        }
        sleep(Duration::from_millis(1500)).await;
    }
}
