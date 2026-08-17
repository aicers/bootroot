//! Regression coverage for [`support::polling::wait_for`].
//!
//! Its own target rather than a test alongside the one caller in
//! `tests/monitoring_integration.rs`: that target is run in CI as
//! `cargo test --test monitoring_integration -- --include-ignored`, and #825
//! asks that step to report exactly one test. These tests need no Docker and
//! no host port, so they belong with the rest of the plain `cargo test` run.

#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_polling {
    use std::time::Duration;

    use crate::support::polling::wait_for;

    /// Holds `wait_for` to the diagnostic it exists for: an error seen early
    /// must still be the reported cause at a timeout, even when later polls
    /// reached the service and answered "not yet".
    #[tokio::test]
    async fn wait_for_keeps_an_error_a_later_poll_did_not_repeat() {
        let mut polls = 0_u32;
        // Two poll intervals of budget, so the run reaches the Ok(false)
        // that follows the error rather than timing out on the error
        // itself, which would pass whatever the loop does with it.
        let error = wait_for(Duration::from_secs(2), || {
            polls += 1;
            let poll = polls;
            async move {
                if poll == 1 {
                    Err(anyhow::anyhow!(
                        "connection closed before message completed"
                    ))
                } else {
                    Ok(false)
                }
            }
        })
        .await
        .expect_err("the condition never reports success");

        let report = format!("{error:#}");
        assert!(
            report.contains("Timed out waiting for condition"),
            "{report}"
        );
        assert!(
            report.contains("connection closed before message completed"),
            "{report}"
        );
    }
}
