//! `rotate approle-secret-id --if-due`: lets a scheduler run the
//! rotation often and have each invocation decide whether to act.
//!
//! The decision is read from [`StateFile::approle_rotation`]. A target
//! whose last fully successful rotation is younger than the threshold is
//! skipped before any `OpenBao` request. A due target attempts, unless
//! the runs that may have spent a login of the rotate credential since
//! it was last renewed have used up the target's scheduled budget, or
//! the last of them was too recent; both of those refuse without
//! logging in.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::openbao::{AppRoleLoginError, OpenBaoClient};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::RotateContext;
use crate::cli::args::{InfraRoleTarget, RotateAppRoleSecretIdArgs};
use crate::commands::init::{
    AppRoleLabel, ROTATE_IF_DUE_INFRA_TARGETS, ROTATE_IF_DUE_SCHEDULED_LOGINS, SECRET_ID_TTL,
    parse_ttl_to_secs,
};
use crate::commands::openbao_auth::RuntimeAuthResolved;
use crate::i18n::Messages;
use crate::state::{AppRoleRotationEntry, AppRoleRotationRecord, AppRoleRotationTarget};
use crate::state_lock::StateLock;

/// What a run with `--if-due` does, decided before any `OpenBao`
/// request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Gate {
    /// The target's last success is younger than the threshold.
    NotDue {
        last_success: OffsetDateTime,
        due_at: OffsetDateTime,
    },
    /// Counted logins have reached the target's budget.
    BudgetSpent { logins: u32 },
    /// The last counted login is younger than the spacing.
    BackingOff {
        logins: u32,
        retry_at: OffsetDateTime,
    },
    /// The run attempts; `logins` counted logins stand against the
    /// credential file as it now is.
    Attempt { logins: u32 },
}

/// Decides what a run with `--if-due` does for one target.
///
/// `now` is the run's start instant and `credential_mtime` the
/// modification time of the rotate credential file, both at whole
/// seconds, the latter `None` when it could not be read. An instant in
/// `entry` that does not parse, or that is later than `now`, counts as
/// absent. A credential file modified after the last counted login
/// holds a credential the count does not describe, so the count is void.
pub(super) fn decide(
    entry: &AppRoleRotationEntry,
    credential_mtime: Option<OffsetDateTime>,
    now: OffsetDateTime,
    threshold: Duration,
    budget: u32,
) -> Gate {
    if let Some(last_success) = recorded_instant(entry.last_success.as_deref(), now)
        && age(last_success, now) < threshold
    {
        return Gate::NotDue {
            last_success,
            due_at: add_secs(last_success, ceil_secs(threshold)),
        };
    }

    let mut logins = entry.logins_since_renewal;
    let mut last_login = recorded_instant(entry.last_login.as_deref(), now);
    if let (Some(login), Some(mtime)) = (last_login, credential_mtime)
        && mtime > login
    {
        logins = 0;
        last_login = None;
    }
    if logins >= budget {
        return Gate::BudgetSpent { logins };
    }
    if let Some(login) = last_login {
        let spacing = spacing(threshold, budget);
        if age(login, now) < spacing {
            return Gate::BackingOff {
                logins,
                retry_at: add_secs(login, spacing.as_secs()),
            };
        }
    }
    Gate::Attempt { logins }
}

/// The least interval between two counted logins of one target: the
/// threshold divided by the budget, at whole seconds.
fn spacing(threshold: Duration, budget: u32) -> Duration {
    let divided = threshold.checked_div(budget).unwrap_or(Duration::ZERO);
    Duration::from_secs(divided.as_secs())
}

fn recorded_instant(value: Option<&str>, now: OffsetDateTime) -> Option<OffsetDateTime> {
    let instant = OffsetDateTime::parse(value?, &Rfc3339).ok()?;
    (instant <= now).then_some(instant)
}

/// The age of `instant` at `now`, which is not earlier.
fn age(instant: OffsetDateTime, now: OffsetDateTime) -> Duration {
    Duration::from_secs(u64::try_from((now - instant).whole_seconds()).unwrap_or(0))
}

/// `duration` rounded up to whole seconds, so a run at the instant
/// printed as due is due.
fn ceil_secs(duration: Duration) -> u64 {
    duration.as_secs() + u64::from(duration.subsec_nanos() > 0)
}

fn add_secs(instant: OffsetDateTime, secs: u64) -> OffsetDateTime {
    instant.saturating_add(time::Duration::seconds(
        i64::try_from(secs).unwrap_or(i64::MAX),
    ))
}

/// Returns the scheduled login budget of `target`: the whole budget for
/// the `--all-services` credential, an even share for each `--infra`
/// target of the shared infra-rotate credential.
pub(super) fn budget(target: AppRoleRotationTarget) -> u32 {
    match target {
        AppRoleRotationTarget::AllServices => ROTATE_IF_DUE_SCHEDULED_LOGINS,
        AppRoleRotationTarget::InfraStepca | AppRoleRotationTarget::InfraResponder => {
            ROTATE_IF_DUE_SCHEDULED_LOGINS / ROTATE_IF_DUE_INFRA_TARGETS
        }
    }
}

/// Returns the scheduled target an invocation rotates, or `None` for a
/// `--registration-id` run, which is no scheduled target.
pub(super) fn target_of(args: &RotateAppRoleSecretIdArgs) -> Option<AppRoleRotationTarget> {
    if args.all_services {
        return Some(AppRoleRotationTarget::AllServices);
    }
    args.infra.map(|infra| match infra {
        InfraRoleTarget::Stepca => AppRoleRotationTarget::InfraStepca,
        InfraRoleTarget::Responder => AppRoleRotationTarget::InfraResponder,
    })
}

/// Returns the run's start instant: the current UTC time at whole
/// seconds.
pub(super) fn start_instant() -> OffsetDateTime {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0).unwrap_or(now)
}

fn format_instant(instant: OffsetDateTime) -> Result<String> {
    instant
        .format(&Rfc3339)
        .context("formatting an --if-due record instant")
}

/// Returns whether a login that ended as `status` reports may have
/// spent a use of the `secret_id`: everything but no response at all and
/// a 5xx answer, which `OpenBao` gives before the `AppRole` backend runs
/// (sealed, unavailable).
pub(super) fn login_is_counted(status: Option<u16>) -> bool {
    status.is_some_and(|status| !(500..600).contains(&status))
}

/// A due `--if-due` run that attempts the rotation.
#[derive(Debug, Clone, Copy)]
pub(super) struct IfDuePlan {
    pub(super) target: AppRoleRotationTarget,
    started_at: OffsetDateTime,
    logins: u32,
}

/// Whether a run with `--if-due` goes on.
#[derive(Debug)]
pub(super) enum Admission {
    /// Not due: the `skipped` line is printed and the run is over.
    Skip,
    Attempt(IfDuePlan),
}

/// Applies the refusals and the gate of `--if-due` before any `OpenBao`
/// request, printing the run's `if-due:` line when it ends here.
///
/// # Errors
/// Returns an error when the duration is invalid or out of range, when
/// the run does not authenticate as an `AppRole` from
/// `--approle-secret-id-file`, and when the target is due but its
/// budget is spent or it is backing off.
pub(super) fn admit(
    args: &RotateAppRoleSecretIdArgs,
    value: &str,
    auth: &RuntimeAuthResolved,
    secret_id_file: Option<&Path>,
    ctx: &RotateContext,
    started_at: OffsetDateTime,
    messages: &Messages,
) -> Result<Admission> {
    let target = target_of(args)
        .context("--if-due applies only to --all-services and --infra invocations")?;
    let threshold = parse_threshold(value, ctx.state.rotate_secret_id_ttl.as_deref(), messages)?;
    let file_based_approle = matches!(auth, RuntimeAuthResolved::AppRole { .. });
    let Some(secret_id_file) = secret_id_file.filter(|_| file_based_approle) else {
        anyhow::bail!(messages.error_if_due_requires_file_auth());
    };

    let budget = budget(target);
    let entry = ctx.state.approle_rotation.entry(target);
    match decide(
        entry,
        credential_mtime(secret_id_file),
        started_at,
        threshold,
        budget,
    ) {
        Gate::NotDue {
            last_success,
            due_at,
        } => {
            println!(
                "if-due: skipped target={target} last-success={} due-at={}",
                format_instant(last_success)?,
                format_instant(due_at)?
            );
            Ok(Admission::Skip)
        }
        Gate::BudgetSpent { logins } => {
            println!("if-due: budget_spent target={target} logins={logins}/{budget}");
            anyhow::bail!(messages.error_if_due_budget_spent(target.as_str(), logins, budget))
        }
        Gate::BackingOff { logins, retry_at } => {
            let retry_at = format_instant(retry_at)?;
            println!(
                "if-due: backing_off target={target} logins={logins}/{budget} retry-at={retry_at}"
            );
            anyhow::bail!(messages.error_if_due_backing_off(
                target.as_str(),
                logins,
                budget,
                &retry_at
            ))
        }
        Gate::Attempt { logins } => Ok(Admission::Attempt(IfDuePlan {
            target,
            started_at,
            logins,
        })),
    }
}

/// Parses the `--if-due` value and holds it to the range the spacing
/// assumes: above zero, and no more than half the rotate roles'
/// `secret_id` TTL (`rotate_ttl`, or [`SECRET_ID_TTL`] when absent or
/// unparseable), so at least one threshold is left for retries.
fn parse_threshold(value: &str, rotate_ttl: Option<&str>, messages: &Messages) -> Result<Duration> {
    let threshold = humantime::parse_duration(value)
        .map_err(|_| anyhow::anyhow!(messages.error_if_due_invalid_duration(value)))?;
    let ttl_secs = rotate_ttl
        .and_then(parse_ttl_to_secs)
        .or_else(|| parse_ttl_to_secs(SECRET_ID_TTL))
        .expect("SECRET_ID_TTL is a valid TTL literal");
    let max = Duration::from_secs(ttl_secs) / 2;
    if threshold.is_zero() || threshold > max {
        anyhow::bail!(
            messages.error_if_due_out_of_range(value, &humantime::format_duration(max).to_string())
        );
    }
    Ok(threshold)
}

/// The rotate credential file's modification time at whole seconds, or
/// `None` when it cannot be read.
fn credential_mtime(path: &Path) -> Option<OffsetDateTime> {
    let modified = std::fs::metadata(path)
        .and_then(|meta| meta.modified())
        .ok()?;
    let modified = OffsetDateTime::from(modified);
    Some(modified.replace_nanosecond(0).unwrap_or(modified))
}

/// Logs the client in for a due `--if-due` run with the one request a
/// run without the flag sends, recording a counted login in
/// `state.json` as soon as its response has arrived.
///
/// A failed login fails with the error a run without the flag reports.
///
/// # Errors
/// Returns an error when the login fails, or when saving a counted
/// login fails.
pub(super) async fn log_in(
    ctx: &mut RotateContext,
    state_lock: &StateLock,
    client: &mut OpenBaoClient,
    plan: &IfDuePlan,
    role_id: &str,
    secret_id: &str,
    messages: &Messages,
) -> Result<()> {
    let login = client.login_approle_with_status(role_id, secret_id).await;
    let counted = login
        .as_ref()
        .map_or_else(|failure| login_is_counted(failure.status()), |_| true);
    if counted {
        record_counted_login(ctx, state_lock, plan, messages).await?;
    }
    let token = login
        .map_err(AppRoleLoginError::into_error)
        .with_context(|| messages.error_openbao_approle_login_failed())?;
    client.set_token(token);
    Ok(())
}

async fn record_counted_login(
    ctx: &mut RotateContext,
    _state_lock: &StateLock,
    plan: &IfDuePlan,
    messages: &Messages,
) -> Result<()> {
    let entry = ctx.state.approle_rotation.entry_mut(plan.target);
    entry.logins_since_renewal = plan.logins.saturating_add(1);
    entry.last_login = Some(format_instant(plan.started_at)?);
    ctx.state
        .save_async(&ctx.state_file)
        .await
        .with_context(|| messages.error_serialize_state_failed())
}

/// Returns the line a due `--if-due` run prints last once it rotated.
pub(super) fn rotated_line(target: AppRoleRotationTarget) -> String {
    format!("if-due: rotated target={target}")
}

/// Records in `record` that a run renewed `label`'s rotate credential
/// file by self-mint: every target of that credential has all its
/// logins again, and `own_target`, the scheduled target the run rotated
/// (none for `--registration-id`), was last rotated at `started_at`.
///
/// # Errors
/// Returns an error if `started_at` cannot be formatted.
pub(super) fn record_renewal(
    record: &mut AppRoleRotationRecord,
    label: AppRoleLabel,
    own_target: Option<AppRoleRotationTarget>,
    started_at: OffsetDateTime,
) -> Result<()> {
    let renewed: &[AppRoleRotationTarget] = match label {
        AppRoleLabel::RuntimeRotate => &[AppRoleRotationTarget::AllServices],
        AppRoleLabel::InfraRotate => &AppRoleRotationTarget::INFRA,
        AppRoleLabel::BootrootAgent
        | AppRoleLabel::Responder
        | AppRoleLabel::Stepca
        | AppRoleLabel::RuntimeServiceAdd => &[],
    };
    for &target in renewed {
        let entry = record.entry_mut(target);
        entry.logins_since_renewal = 0;
        entry.last_login = None;
    }
    if let Some(target) = own_target {
        record.entry_mut(target).last_success = Some(format_instant(started_at)?);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::ValueEnum;

    use super::*;
    use crate::commands::init::ROTATE_SELF_MINT_NUM_USES;
    use crate::i18n::test_messages;

    const HOUR: Duration = Duration::from_hours(1);

    fn at(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &Rfc3339).expect("test instant")
    }

    fn entry(
        last_success: Option<&str>,
        logins: u32,
        last_login: Option<&str>,
    ) -> AppRoleRotationEntry {
        AppRoleRotationEntry {
            last_success: last_success.map(str::to_string),
            logins_since_renewal: logins,
            last_login: last_login.map(str::to_string),
        }
    }

    const NOW: &str = "2026-10-10T12:00:00Z";

    #[test]
    fn an_absent_entry_attempts() {
        let gate = decide(&entry(None, 0, None), None, at(NOW), HOUR, 4);
        assert_eq!(gate, Gate::Attempt { logins: 0 });
    }

    #[test]
    fn a_recent_success_is_not_due_until_the_threshold_has_passed() {
        let gate = decide(
            &entry(Some("2026-10-10T11:30:00Z"), 0, None),
            None,
            at(NOW),
            HOUR,
            4,
        );
        assert_eq!(
            gate,
            Gate::NotDue {
                last_success: at("2026-10-10T11:30:00Z"),
                due_at: at("2026-10-10T12:30:00Z"),
            }
        );
    }

    #[test]
    fn a_success_exactly_the_threshold_old_attempts() {
        let gate = decide(
            &entry(Some("2026-10-10T11:00:00Z"), 0, None),
            None,
            at(NOW),
            HOUR,
            4,
        );
        assert_eq!(gate, Gate::Attempt { logins: 0 });
    }

    #[test]
    fn a_success_in_the_future_attempts() {
        let gate = decide(
            &entry(Some("2026-10-10T12:00:01Z"), 0, None),
            None,
            at(NOW),
            HOUR,
            4,
        );
        assert_eq!(gate, Gate::Attempt { logins: 0 });
    }

    #[test]
    fn an_unparseable_instant_counts_as_absent() {
        let gate = decide(
            &entry(Some("yesterday"), 1, Some("not an instant")),
            None,
            at(NOW),
            HOUR,
            4,
        );
        assert_eq!(gate, Gate::Attempt { logins: 1 });
    }

    #[test]
    fn a_count_at_the_budget_is_spent_however_old_the_last_login() {
        let gate = decide(
            &entry(None, 4, Some("2026-10-01T00:00:00Z")),
            None,
            at(NOW),
            HOUR,
            4,
        );
        assert_eq!(gate, Gate::BudgetSpent { logins: 4 });
    }

    #[test]
    fn a_recent_login_below_the_budget_backs_off_until_the_spacing() {
        // 11h30m over 4 logins: 2h52m30s apart.
        let threshold = Duration::from_mins(690);
        let gate = decide(
            &entry(
                Some("2026-10-09T00:00:00Z"),
                1,
                Some("2026-10-10T10:00:00Z"),
            ),
            None,
            at(NOW),
            threshold,
            4,
        );
        assert_eq!(
            gate,
            Gate::BackingOff {
                logins: 1,
                retry_at: at("2026-10-10T12:52:30Z"),
            }
        );
    }

    #[test]
    fn a_login_exactly_the_spacing_old_attempts() {
        let gate = decide(
            &entry(None, 2, Some("2026-10-10T11:45:00Z")),
            None,
            at(NOW),
            HOUR,
            4,
        );
        assert_eq!(gate, Gate::Attempt { logins: 2 });
    }

    #[test]
    fn a_login_in_the_future_attempts() {
        let gate = decide(
            &entry(None, 2, Some("2026-10-10T12:30:00Z")),
            None,
            at(NOW),
            HOUR,
            4,
        );
        assert_eq!(gate, Gate::Attempt { logins: 2 });
    }

    #[test]
    fn not_due_wins_over_a_spent_budget() {
        let gate = decide(
            &entry(
                Some("2026-10-10T11:59:00Z"),
                4,
                Some("2026-10-10T11:59:30Z"),
            ),
            None,
            at(NOW),
            HOUR,
            4,
        );
        assert!(matches!(gate, Gate::NotDue { .. }), "{gate:?}");
    }

    #[test]
    fn a_credential_file_newer_than_the_last_login_voids_the_count() {
        let spent = entry(None, 4, Some("2026-10-10T11:50:00Z"));
        let backing_off = entry(None, 1, Some("2026-10-10T11:50:00Z"));
        let newer = Some(at("2026-10-10T11:50:01Z"));
        for record in [&spent, &backing_off] {
            assert_eq!(
                decide(record, newer, at(NOW), HOUR, 4),
                Gate::Attempt { logins: 0 },
                "{record:?}"
            );
        }
    }

    #[test]
    fn a_credential_file_not_newer_than_the_last_login_resets_nothing() {
        let spent = entry(None, 4, Some("2026-10-10T11:50:00Z"));
        let backing_off = entry(None, 1, Some("2026-10-10T11:50:00Z"));
        for mtime in [
            Some(at("2026-10-10T11:50:00Z")),
            Some(at("2026-10-10T11:00:00Z")),
            None,
        ] {
            assert_eq!(
                decide(&spent, mtime, at(NOW), HOUR, 4),
                Gate::BudgetSpent { logins: 4 }
            );
            assert_eq!(
                decide(&backing_off, mtime, at(NOW), HOUR, 4),
                Gate::BackingOff {
                    logins: 1,
                    retry_at: at("2026-10-10T12:05:00Z"),
                }
            );
        }
    }

    #[test]
    fn the_scheduled_budget_leaves_the_verification_and_an_operator_login() {
        assert_eq!(ROTATE_SELF_MINT_NUM_USES, 6);
        assert_eq!(
            ROTATE_IF_DUE_SCHEDULED_LOGINS,
            ROTATE_SELF_MINT_NUM_USES - 2
        );
        assert_eq!(budget(AppRoleRotationTarget::AllServices), 4);
        assert_eq!(budget(AppRoleRotationTarget::InfraStepca), 2);
        assert_eq!(budget(AppRoleRotationTarget::InfraResponder), 2);
        let infra_total: u32 = AppRoleRotationTarget::INFRA
            .iter()
            .map(|t| budget(*t))
            .sum();
        assert!(infra_total <= ROTATE_IF_DUE_SCHEDULED_LOGINS);
        assert_eq!(
            usize::try_from(ROTATE_IF_DUE_INFRA_TARGETS).expect("small"),
            InfraRoleTarget::value_variants().len(),
            "the infra budget is split over every --infra target"
        );
    }

    #[test]
    fn only_no_response_and_5xx_logins_are_free() {
        for free in [None, Some(500), Some(503), Some(599)] {
            assert!(!login_is_counted(free), "{free:?}");
        }
        for counted in [Some(200), Some(204), Some(400), Some(403), Some(429)] {
            assert!(login_is_counted(counted), "{counted:?}");
        }
    }

    #[test]
    fn the_threshold_must_be_positive_and_at_most_half_the_rotate_ttl() {
        let messages = test_messages();
        assert_eq!(
            parse_threshold("11h30m", None, &messages).expect("valid"),
            Duration::from_mins(690)
        );
        assert_eq!(
            parse_threshold("690m", None, &messages).expect("valid"),
            Duration::from_mins(690)
        );
        assert!(parse_threshold("12h", None, &messages).is_ok());
        assert!(parse_threshold("12h1s", None, &messages).is_err());
        assert!(parse_threshold("0s", None, &messages).is_err());
        assert!(parse_threshold("soon", None, &messages).is_err());
        assert!(parse_threshold("24h", Some("48h"), &messages).is_ok());
        assert!(parse_threshold("13h", Some("48h"), &messages).is_ok());
        // An unparseable recorded TTL falls back to the default.
        assert!(parse_threshold("13h", Some("forever"), &messages).is_err());
    }

    #[test]
    fn a_renewal_resets_every_target_of_the_credential() {
        let started = at(NOW);
        let mut record = AppRoleRotationRecord::default();
        for target in [
            AppRoleRotationTarget::AllServices,
            AppRoleRotationTarget::InfraStepca,
            AppRoleRotationTarget::InfraResponder,
        ] {
            *record.entry_mut(target) = entry(None, 2, Some("2026-10-10T10:00:00Z"));
        }

        record_renewal(
            &mut record,
            AppRoleLabel::InfraRotate,
            Some(AppRoleRotationTarget::InfraStepca),
            started,
        )
        .expect("record");

        assert_eq!(
            record.entry(AppRoleRotationTarget::InfraStepca),
            &entry(Some(NOW), 0, None)
        );
        assert_eq!(
            record.entry(AppRoleRotationTarget::InfraResponder),
            &entry(None, 0, None)
        );
        assert_eq!(
            record.entry(AppRoleRotationTarget::AllServices),
            &entry(None, 2, Some("2026-10-10T10:00:00Z")),
            "the runtime credential was not renewed"
        );

        record_renewal(&mut record, AppRoleLabel::RuntimeRotate, None, started).expect("record");
        assert_eq!(
            record.entry(AppRoleRotationTarget::AllServices),
            &entry(None, 0, None),
            "a --registration-id run resets the count and sets no last_success"
        );
    }
}
