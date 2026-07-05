use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::openbao::{KvMountStatus, OpenBaoClient};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::cli::args::StatusArgs;
use crate::commands::infra::{
    ContainerReadiness, collect_container_failures, collect_readiness, default_infra_services,
};
use crate::commands::init::{
    APPROLE_BOOTROOT_AGENT, APPROLE_BOOTROOT_INFRA_ROTATE, APPROLE_BOOTROOT_RESPONDER,
    APPROLE_BOOTROOT_STEPCA, PATH_AGENT_EAB, PATH_CA_TRUST, PATH_RESPONDER_HMAC, PATH_STEPCA_DB,
    PATH_STEPCA_PASSWORD, SECRET_ID_TTL, parse_ttl_to_secs,
};
use crate::i18n::Messages;
use crate::state::StateFile;

pub(crate) async fn run_status(args: &StatusArgs, messages: &Messages) -> Result<()> {
    let services = default_infra_services();
    let readiness = collect_readiness(&args.compose.compose_file, None, &services, messages)?;
    let infra_failures = collect_container_failures(&readiness);

    let state_path = StateFile::default_path();
    let state = if state_path.exists() {
        Some(StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?)
    } else {
        None
    };
    let mut client = match state.as_ref().map(StateFile::secrets_dir) {
        Some(secrets_dir) => {
            OpenBaoClient::with_local_trust(&args.openbao.openbao_url, secrets_dir)
                .with_context(|| messages.error_openbao_client_create_failed())?
        }
        None => OpenBaoClient::new(&args.openbao.openbao_url)
            .with_context(|| messages.error_openbao_client_create_failed())?,
    };
    let openbao_health = client
        .health_check()
        .await
        .with_context(|| messages.error_openbao_health_check_failed());
    let openbao_ok = openbao_health.is_ok();
    let seal_status = if openbao_ok {
        Some(
            client
                .seal_status()
                .await
                .with_context(|| messages.error_openbao_seal_status_failed())?,
        )
    } else {
        None
    };

    if let Some(token) = &args.root_token.root_token {
        client.set_token(token.clone());
    }

    let kv_mount_status = if openbao_ok && args.root_token.root_token.is_some() {
        Some(
            client
                .kv_mount_status(&args.openbao.kv_mount)
                .await
                .with_context(|| messages.error_openbao_kv_mount_status_failed())?,
        )
    } else {
        None
    };

    let kv_paths = [
        PATH_STEPCA_PASSWORD,
        PATH_STEPCA_DB,
        PATH_RESPONDER_HMAC,
        PATH_CA_TRUST,
        PATH_AGENT_EAB,
    ];
    let kv_statuses = if openbao_ok && args.root_token.root_token.is_some() {
        Some(fetch_kv_statuses(&client, &args.openbao.kv_mount, &kv_paths, messages).await?)
    } else {
        None
    };

    let approles = [
        APPROLE_BOOTROOT_AGENT,
        APPROLE_BOOTROOT_RESPONDER,
        APPROLE_BOOTROOT_STEPCA,
        APPROLE_BOOTROOT_INFRA_ROTATE,
    ];
    let approle_statuses = if openbao_ok && args.root_token.root_token.is_some() {
        Some(fetch_approle_statuses(&client, &approles, messages).await?)
    } else {
        None
    };
    let service_statuses = load_service_statuses(messages)?;

    let last_secret_id_rotation = state
        .as_ref()
        .and_then(|state| state.last_secret_id_rotation.clone());
    let secret_id_rotation_warning = state
        .as_ref()
        .and_then(|state| secret_id_rotation_warning(state, OffsetDateTime::now_utc(), messages));

    let summary = StatusSummary {
        readiness: &readiness,
        openbao_ok,
        sealed: seal_status.map(|status| status.sealed),
        kv_mount: &args.openbao.kv_mount,
        kv_mount_status,
        kv_statuses: kv_statuses.as_deref(),
        approle_statuses: approle_statuses.as_deref(),
        service_statuses: &service_statuses,
        last_secret_id_rotation: last_secret_id_rotation.as_deref(),
        secret_id_rotation_warning,
    };
    print_status_summary(messages, &summary);

    if !infra_failures.is_empty() {
        anyhow::bail!(messages.status_error_infra_unhealthy(&infra_failures.join(", ")));
    }
    if !openbao_ok {
        anyhow::bail!(messages.status_error_openbao_unreachable());
    }

    Ok(())
}

fn load_service_statuses(messages: &Messages) -> Result<Vec<ServiceStatusEntry>> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        return Ok(Vec::new());
    }
    let state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;
    let mut service_statuses = Vec::with_capacity(state.services.len());
    for entry in state.services.values() {
        service_statuses.push(ServiceStatusEntry {
            service_name: entry.service_name.clone(),
            delivery_mode: entry.delivery_mode.to_string(),
        });
    }
    Ok(service_statuses)
}

async fn fetch_kv_statuses(
    client: &OpenBaoClient,
    kv_mount: &str,
    paths: &[&str],
    messages: &Messages,
) -> Result<Vec<(String, bool)>> {
    let mut statuses = Vec::with_capacity(paths.len());
    for path in paths {
        let exists = client
            .kv_exists(kv_mount, path)
            .await
            .with_context(|| messages.error_openbao_kv_exists_failed())?;
        statuses.push((format!("{kv_mount}/{path}"), exists));
    }
    Ok(statuses)
}

async fn fetch_approle_statuses(
    client: &OpenBaoClient,
    roles: &[&str],
    messages: &Messages,
) -> Result<Vec<(String, bool)>> {
    let mut statuses = Vec::with_capacity(roles.len());
    for role in roles {
        let exists = client
            .approle_exists(role)
            .await
            .with_context(|| messages.error_openbao_approle_exists_failed())?;
        statuses.push((role.to_string(), exists));
    }
    Ok(statuses)
}

struct StatusSummary<'a> {
    readiness: &'a [ContainerReadiness],
    openbao_ok: bool,
    sealed: Option<bool>,
    kv_mount: &'a str,
    kv_mount_status: Option<KvMountStatus>,
    kv_statuses: Option<&'a [(String, bool)]>,
    approle_statuses: Option<&'a [(String, bool)]>,
    service_statuses: &'a [ServiceStatusEntry],
    last_secret_id_rotation: Option<&'a str>,
    secret_id_rotation_warning: Option<String>,
}

/// Dead-man check for the scheduled `secret_id` rotation job (#672):
/// returns a warning when the last recorded rotation success is older
/// than half the rotate roles' `secret_id` TTL — a one-missed-run
/// budget under the documented "TTL ≥ 2× rotation interval" cadence
/// rule. No timestamp recorded means no verdict (fresh deployments
/// have not scheduled the job yet); the missing-run failure mode is
/// pure absence, so this timestamp is the only signal available.
fn secret_id_rotation_warning(
    state: &StateFile,
    now: OffsetDateTime,
    messages: &Messages,
) -> Option<String> {
    let last = state.last_secret_id_rotation.as_deref()?;
    let last_ts = OffsetDateTime::parse(last, &Rfc3339).ok()?;
    let ttl = state
        .rotate_secret_id_ttl
        .as_deref()
        .unwrap_or(SECRET_ID_TTL);
    let threshold_secs = parse_ttl_to_secs(ttl)? / 2;
    let age_secs = u64::try_from((now - last_ts).whole_seconds()).ok()?;
    if age_secs <= threshold_secs {
        return None;
    }
    // Round the age to whole minutes so the warning stays readable.
    let rounded_age_secs = age_secs.saturating_sub(age_secs % 60).max(60);
    Some(messages.status_warning_secret_id_rotation_stale(
        &humantime::format_duration(Duration::from_secs(rounded_age_secs)).to_string(),
        &humantime::format_duration(Duration::from_secs(threshold_secs)).to_string(),
    ))
}

struct ServiceStatusEntry {
    service_name: String,
    delivery_mode: String,
}

fn print_status_summary(messages: &Messages, summary: &StatusSummary<'_>) {
    println!("{}", messages.status_summary_title());
    println!("{}", messages.status_section_infra());
    for entry in summary.readiness {
        match entry.health.as_deref() {
            Some(health) => println!(
                "{}",
                messages.status_entry_with_health(&entry.service, &entry.status, health)
            ),
            None => println!(
                "{}",
                messages.status_entry_without_health(&entry.service, &entry.status)
            ),
        }
    }
    print_openbao_section(messages, summary);
    print_kv_paths_section(messages, summary);
    print_approles_section(messages, summary);
    if let Some(value) = summary.last_secret_id_rotation {
        println!("{}", messages.status_last_secret_id_rotation(value));
    }
    print_services_section(messages, summary);
    if let Some(warning) = &summary.secret_id_rotation_warning {
        println!("{warning}");
    }
}

fn print_openbao_section(messages: &Messages, summary: &StatusSummary<'_>) {
    println!("{}", messages.status_section_openbao());
    let health_value = if summary.openbao_ok {
        messages.status_value_ok()
    } else {
        messages.status_value_unreachable()
    };
    println!("{}", messages.status_openbao_health(health_value));
    if let Some(sealed) = summary.sealed {
        println!("{}", messages.status_openbao_sealed(&sealed.to_string()));
    } else {
        println!(
            "{}",
            messages.status_openbao_sealed(messages.status_value_unknown())
        );
    }

    let kv_mount_value = match summary.kv_mount_status {
        Some(KvMountStatus::Ok) => messages.status_value_ok(),
        Some(KvMountStatus::Missing) => messages.status_value_missing(),
        Some(KvMountStatus::NotKv | KvMountStatus::NotV2) => messages.status_value_invalid(),
        None => messages.status_value_unknown(),
    };
    println!(
        "{}",
        messages.status_openbao_kv_mount(summary.kv_mount, kv_mount_value)
    );
}

fn print_kv_paths_section(messages: &Messages, summary: &StatusSummary<'_>) {
    println!("{}", messages.status_section_kv_paths());
    if let Some(statuses) = summary.kv_statuses {
        for (path, present) in statuses {
            let value = if path.ends_with(PATH_AGENT_EAB) {
                if *present {
                    messages.status_value_present()
                } else {
                    messages.status_value_optional_missing()
                }
            } else if *present {
                messages.status_value_present()
            } else {
                messages.status_value_missing()
            };
            println!("{}", messages.status_kv_path_entry(path, value));
        }
    } else {
        for path in [
            format!("{}/{PATH_STEPCA_PASSWORD}", summary.kv_mount),
            format!("{}/{PATH_STEPCA_DB}", summary.kv_mount),
            format!("{}/{PATH_RESPONDER_HMAC}", summary.kv_mount),
            format!("{}/{PATH_CA_TRUST}", summary.kv_mount),
            format!("{}/{PATH_AGENT_EAB}", summary.kv_mount),
        ] {
            println!(
                "{}",
                messages.status_kv_path_entry(&path, messages.status_value_unknown())
            );
        }
    }
}

fn print_approles_section(messages: &Messages, summary: &StatusSummary<'_>) {
    println!("{}", messages.status_section_approles());
    if let Some(statuses) = summary.approle_statuses {
        for (role, present) in statuses {
            let value = if *present {
                messages.status_value_present()
            } else {
                messages.status_value_missing()
            };
            println!("{}", messages.status_approle_entry(role, value));
        }
    } else {
        for role in [
            APPROLE_BOOTROOT_AGENT,
            APPROLE_BOOTROOT_RESPONDER,
            APPROLE_BOOTROOT_STEPCA,
            APPROLE_BOOTROOT_INFRA_ROTATE,
        ] {
            println!(
                "{}",
                messages.status_approle_entry(role, messages.status_value_unknown())
            );
        }
    }
}

fn print_services_section(messages: &Messages, summary: &StatusSummary<'_>) {
    println!("{}", messages.status_section_services());
    if summary.service_statuses.is_empty() {
        println!("{}", messages.status_services_none());
    } else {
        for service in summary.service_statuses {
            println!(
                "{}",
                messages
                    .status_service_delivery_mode(&service.service_name, &service.delivery_mode)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use time::Duration as TimeDuration;

    use super::*;
    use crate::i18n::test_messages;

    fn state_with_rotation(
        last_secret_id_rotation: Option<&str>,
        rotate_secret_id_ttl: Option<&str>,
    ) -> StateFile {
        StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            rotate_secret_id_ttl: rotate_secret_id_ttl.map(str::to_string),
            last_secret_id_rotation: last_secret_id_rotation.map(str::to_string),
            ..Default::default()
        }
    }

    fn rfc3339(ts: OffsetDateTime) -> String {
        ts.format(&Rfc3339).expect("RFC 3339 formatting")
    }

    #[test]
    fn no_recorded_rotation_produces_no_warning() {
        let state = state_with_rotation(None, None);
        let messages = test_messages();
        assert!(secret_id_rotation_warning(&state, OffsetDateTime::now_utc(), &messages).is_none());
    }

    #[test]
    fn fresh_rotation_produces_no_warning() {
        let now = OffsetDateTime::now_utc();
        let last = rfc3339(now - TimeDuration::hours(1));
        let state = state_with_rotation(Some(&last), None);
        let messages = test_messages();
        assert!(secret_id_rotation_warning(&state, now, &messages).is_none());
    }

    // The default threshold is half the default 24h TTL: a
    // one-missed-run budget under the documented ≥2× cadence rule.
    #[test]
    fn stale_rotation_warns_past_half_default_ttl() {
        let now = OffsetDateTime::now_utc();
        let last = rfc3339(now - TimeDuration::hours(13));
        let state = state_with_rotation(Some(&last), None);
        let messages = test_messages();
        let warning = secret_id_rotation_warning(&state, now, &messages)
            .expect("13h staleness must exceed the 12h default threshold");
        assert!(
            warning.contains("13h"),
            "warning must name the age: {warning}"
        );
        assert!(
            warning.contains("12h"),
            "warning must name the threshold: {warning}"
        );
    }

    #[test]
    fn threshold_follows_recorded_rotate_secret_id_ttl() {
        let now = OffsetDateTime::now_utc();
        let last = rfc3339(now - TimeDuration::hours(13));
        // 168h TTL → 84h threshold: 13h staleness stays quiet.
        let state = state_with_rotation(Some(&last), Some("168h"));
        let messages = test_messages();
        assert!(secret_id_rotation_warning(&state, now, &messages).is_none());

        let last = rfc3339(now - TimeDuration::hours(85));
        let state = state_with_rotation(Some(&last), Some("168h"));
        let warning = secret_id_rotation_warning(&state, now, &messages)
            .expect("85h staleness must exceed the 84h threshold");
        assert!(
            warning.contains("3days 13h"),
            "warning must name the age in humanized form: {warning}"
        );
    }

    #[test]
    fn unparseable_timestamp_produces_no_warning() {
        let state = state_with_rotation(Some("not-a-timestamp"), None);
        let messages = test_messages();
        assert!(secret_id_rotation_warning(&state, OffsetDateTime::now_utc(), &messages).is_none());
    }

    #[test]
    fn future_timestamp_produces_no_warning() {
        let now = OffsetDateTime::now_utc();
        let last = rfc3339(now + TimeDuration::hours(2));
        let state = state_with_rotation(Some(&last), None);
        let messages = test_messages();
        assert!(secret_id_rotation_warning(&state, now, &messages).is_none());
    }
}
