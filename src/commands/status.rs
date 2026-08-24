use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::config::{Settings, validate_registrar_settings};
use bootroot::openbao::{KvMountStatus, OpenBaoClient};
use bootroot::registrar::audit::scan::{
    AUDIT_SCAN_WINDOW, AuditScan, AuditScanError, scan_audit_store_off_runtime,
};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::cli::args::StatusArgs;
use crate::commands::compose_file::compose_file_dir;
use crate::commands::compose_project::ComposeIdentity;
use crate::commands::infra::{
    ContainerReadiness, collect_container_failures, collect_readiness, default_infra_services,
};
use crate::commands::init::{
    APPROLE_BOOTROOT_AGENT, APPROLE_BOOTROOT_INFRA_ROTATE, APPROLE_BOOTROOT_RESPONDER,
    APPROLE_BOOTROOT_STEPCA, PATH_AGENT_EAB, PATH_CA_TRUST, PATH_RESPONDER_HMAC, PATH_STEPCA_DB,
    PATH_STEPCA_PASSWORD, SECRET_ID_TTL, parse_ttl_to_secs,
};
use crate::commands::openbao_url::{OPENBAO_HOST_PORT_ENV, effective_openbao_url_with_env};
use crate::i18n::Messages;
use crate::state::StateFile;

pub(crate) async fn run_status(args: &StatusArgs, messages: &Messages) -> Result<()> {
    let audit_status = load_audit_status(args, messages).await?;
    let services = default_infra_services();
    let compose_file = &args.compose.compose_file;
    let identity = ComposeIdentity::resolve(compose_file, None, messages)?;
    let readiness = collect_readiness(compose_file, &identity, None, &services, messages)?;
    let infra_failures = collect_container_failures(&readiness);

    let state_path = StateFile::default_path();
    let state = if state_path.exists() {
        Some(StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?)
    } else {
        None
    };
    let openbao_url = status_openbao_url(args);
    let mut client = match state.as_ref().map(StateFile::secrets_dir) {
        Some(secrets_dir) => OpenBaoClient::with_local_trust(&openbao_url, secrets_dir)
            .with_context(|| messages.error_openbao_client_create_failed())?,
        None => OpenBaoClient::new(&openbao_url)
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
        audit_status: &audit_status,
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

/// Returns the `OpenBao` endpoint `status` reports on.
///
/// Talks to the host port this compose stack publishes rather than the
/// CLI default's literal 8200, which on a shared host would report
/// another bootroot instance's `OpenBao`.  An explicit `--openbao-url`
/// is still honoured verbatim.
fn status_openbao_url(args: &StatusArgs) -> String {
    status_openbao_url_with_env(args, std::env::var(OPENBAO_HOST_PORT_ENV).ok().as_deref())
}

/// [`status_openbao_url`] with the `OPENBAO_HOST_PORT` value supplied by
/// the caller instead of read from the process environment.
fn status_openbao_url_with_env(args: &StatusArgs, host_port_env: Option<&str>) -> String {
    effective_openbao_url_with_env(
        &args.openbao.openbao_url,
        &compose_file_dir(&args.compose.compose_file),
        None,
        host_port_env,
    )
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
            // The registration key, not the SAN label: it is what the
            // operator passes back to `service info --registration-id`,
            // and two registrations of one component would otherwise
            // list under one indistinguishable name.
            registration_id: entry.registration_id.clone(),
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
    audit_status: &'a AuditStatus,
}

enum AuditStatus {
    Absent,
    Scan(AuditScan),
    Failed {
        path: std::path::PathBuf,
        reason: AuditFailureReason,
    },
}

enum AuditFailureReason {
    ExplicitConfigNotRegularFile,
    Diagnostic(String),
}

struct AuditScanSettings {
    directory: PathBuf,
    max_retained_files: u32,
    min_retain_days: u32,
}

enum AuditSettingsLoad {
    Ready(AuditScanSettings),
    Failed {
        path: PathBuf,
        reason: AuditFailureReason,
    },
    MissingExplicitConfig {
        path: PathBuf,
    },
}

async fn load_audit_status(args: &StatusArgs, messages: &Messages) -> Result<AuditStatus> {
    let settings_path = audit_settings_path(args.agent_config.as_ref());
    let settings = match map_audit_settings_join_result(
        settings_path,
        tokio::task::spawn_blocking({
            let agent_config = args.agent_config.clone();
            move || load_audit_settings(agent_config)
        })
        .await,
    ) {
        Ok(settings) => settings,
        Err(status) => return Ok(status),
    };

    let settings = match settings {
        AuditSettingsLoad::Ready(settings) => settings,
        AuditSettingsLoad::Failed { path, reason } => {
            return Ok(AuditStatus::Failed { path, reason });
        }
        AuditSettingsLoad::MissingExplicitConfig { path } => {
            anyhow::bail!(messages.status_error_agent_config_missing(&path.display().to_string()));
        }
    };

    match scan_audit_store_off_runtime(
        &settings.directory,
        OffsetDateTime::now_utc(),
        AUDIT_SCAN_WINDOW,
        settings.max_retained_files,
        settings.min_retain_days,
    )
    .await
    {
        Ok(scan) => Ok(AuditStatus::Scan(scan)),
        Err(AuditScanError::StoreAbsent { .. }) => Ok(AuditStatus::Absent),
        Err(error) => Ok(AuditStatus::Failed {
            path: settings.directory,
            reason: AuditFailureReason::Diagnostic(error.to_string()),
        }),
    }
}

fn audit_settings_path(agent_config: Option<&PathBuf>) -> PathBuf {
    agent_config
        .cloned()
        .unwrap_or_else(|| PathBuf::from("agent.toml"))
}

fn map_audit_settings_join_result(
    settings_path: PathBuf,
    result: std::result::Result<AuditSettingsLoad, tokio::task::JoinError>,
) -> std::result::Result<AuditSettingsLoad, AuditStatus> {
    result.map_err(|error| AuditStatus::Failed {
        path: settings_path,
        reason: AuditFailureReason::Diagnostic(error.to_string()),
    })
}

fn load_audit_settings(agent_config: Option<PathBuf>) -> AuditSettingsLoad {
    if let Some(path) = agent_config.as_ref() {
        match std::fs::metadata(path) {
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                return AuditSettingsLoad::Failed {
                    path: path.clone(),
                    reason: AuditFailureReason::ExplicitConfigNotRegularFile,
                };
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return AuditSettingsLoad::MissingExplicitConfig { path: path.clone() };
            }
            Err(error) => {
                return AuditSettingsLoad::Failed {
                    path: path.clone(),
                    reason: AuditFailureReason::Diagnostic(error.to_string()),
                };
            }
        }
    }
    let settings_path = audit_settings_path(agent_config.as_ref());
    let settings_result = match agent_config {
        Some(path) => Settings::from_required_file(path),
        None => Settings::from_file(None),
    };
    let settings = match settings_result {
        Ok(settings) => settings,
        Err(error) => {
            return AuditSettingsLoad::Failed {
                path: settings_path,
                reason: AuditFailureReason::Diagnostic(error.to_string()),
            };
        }
    };
    if let Err(error) = validate_registrar_settings(&settings.registrar) {
        return AuditSettingsLoad::Failed {
            path: settings_path,
            reason: AuditFailureReason::Diagnostic(error.to_string()),
        };
    }
    AuditSettingsLoad::Ready(AuditScanSettings {
        directory: settings.registrar.audit_record_dir,
        max_retained_files: settings.registrar.audit_max_retained_files,
        min_retain_days: settings.registrar.audit_min_retain_days,
    })
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
    registration_id: String,
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
    print_audit_section(messages, summary.audit_status);
    if let Some(warning) = &summary.secret_id_rotation_warning {
        println!("{warning}");
    }
}

fn print_audit_section(messages: &Messages, audit_status: &AuditStatus) {
    for line in audit_section_lines(messages, audit_status) {
        println!("{line}");
    }
}

fn audit_section_lines(messages: &Messages, audit_status: &AuditStatus) -> Vec<String> {
    let mut lines = vec![messages.status_section_registrar_audit().to_string()];
    match audit_status {
        AuditStatus::Absent => lines.push(messages.status_audit_not_configured().to_string()),
        AuditStatus::Scan(scan) => {
            lines.push(messages.status_audit_unpaired_intents(scan.intent_without_outcome));
            lines.push(messages.status_audit_malformed_records(scan.malformed_records));
            lines.push(messages.status_audit_retention_shortfall(scan.retention_short));
            if scan.intent_without_outcome > 0 {
                lines.push(messages.status_warning_audit_unpaired_intents().to_string());
            }
            if scan.malformed_records > 0 {
                lines.push(
                    messages
                        .status_warning_audit_malformed_records()
                        .to_string(),
                );
            }
            if scan.retention_short {
                lines.push(
                    messages
                        .status_warning_audit_retention_shortfall()
                        .to_string(),
                );
            }
        }
        AuditStatus::Failed { path, reason } => {
            let reason = match reason {
                AuditFailureReason::ExplicitConfigNotRegularFile => {
                    messages.status_warning_audit_config_not_regular_file()
                }
                AuditFailureReason::Diagnostic(error) => error,
            };
            lines.push(
                messages.status_warning_audit_scan_failed(&path.display().to_string(), reason),
            );
        }
    }
    lines
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
                    .status_service_delivery_mode(&service.registration_id, &service.delivery_mode)
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

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

    fn status_args(compose_file: std::path::PathBuf, openbao_url: &str) -> StatusArgs {
        StatusArgs {
            agent_config: None,
            compose: crate::cli::args::ComposeFileArgs { compose_file },
            openbao: crate::cli::args::OpenBaoArgs {
                openbao_url: openbao_url.to_string(),
                kv_mount: "secret".to_string(),
            },
            root_token: crate::cli::args::RootTokenArgs { root_token: None },
        }
    }

    fn status_args_with_agent_config(agent_config: PathBuf) -> StatusArgs {
        // The audit-status loader does not read the compose file.
        let mut args = status_args(
            PathBuf::from("unused-by-audit-status.yml"),
            crate::commands::init::DEFAULT_OPENBAO_URL,
        );
        args.agent_config = Some(agent_config);
        args
    }

    #[tokio::test]
    async fn supplied_agent_config_scans_a_clean_store() {
        let dir = tempfile::tempdir().expect("create test directory");
        let audit_dir = dir.path().join("registrar-audit");
        std::fs::create_dir(&audit_dir).expect("create audit directory");
        let config = dir.path().join("agent.toml");
        std::fs::write(
            &config,
            format!(
                "[registrar]\naudit_store_dir = \"{}\"\naudit_record_dir = \"{}\"\n",
                dir.path().display(),
                audit_dir.display()
            ),
        )
        .expect("write agent config");

        let status = load_audit_status(&status_args_with_agent_config(config), &test_messages())
            .await
            .expect("load audit status");
        let AuditStatus::Scan(scan) = status else {
            panic!("a clean configured store must be scanned");
        };
        assert_eq!(
            scan,
            AuditScan {
                intent_without_outcome: 0,
                malformed_records: 0,
                retention_short: false,
            }
        );
    }

    #[tokio::test]
    async fn supplied_agent_config_maps_a_missing_store_to_absent() {
        let dir = tempfile::tempdir().expect("create test directory");
        let audit_dir = dir.path().join("missing-registrar-audit");
        let config = dir.path().join("agent.toml");
        std::fs::write(
            &config,
            format!(
                "[registrar]\naudit_store_dir = \"{}\"\naudit_record_dir = \"{}\"\n",
                dir.path().display(),
                audit_dir.display()
            ),
        )
        .expect("write agent config");

        let status = load_audit_status(&status_args_with_agent_config(config), &test_messages())
            .await
            .expect("a missing audit store does not abort status");
        assert!(matches!(status, AuditStatus::Absent));
    }

    #[tokio::test]
    async fn no_agent_config_scans_the_default_store_and_maps_absence() {
        assert!(
            !Path::new("agent.toml").exists(),
            "this test requires the workspace to have no default agent configuration"
        );

        let status = load_audit_status(
            &status_args(
                PathBuf::from("unused-by-audit-status.yml"),
                crate::commands::init::DEFAULT_OPENBAO_URL,
            ),
            &test_messages(),
        )
        .await
        .expect("a missing default store does not abort status");
        assert!(matches!(status, AuditStatus::Absent));
    }

    #[tokio::test]
    async fn supplied_missing_agent_config_refuses_status() {
        let dir = tempfile::tempdir().expect("create test directory");
        let config = dir.path().join("missing-agent.toml");
        let Err(error) = load_audit_status(
            &status_args_with_agent_config(config.clone()),
            &test_messages(),
        )
        .await
        else {
            panic!("an explicitly named missing config is an error");
        };
        assert!(error.to_string().contains(&config.display().to_string()));
    }

    #[tokio::test]
    async fn supplied_directory_agent_config_is_a_failed_scan() {
        let dir = tempfile::tempdir().expect("create test directory");
        let config = dir.path().join("agent-config-directory");
        std::fs::create_dir(&config).expect("create config directory");

        let status = load_audit_status(
            &status_args_with_agent_config(config.clone()),
            &test_messages(),
        )
        .await
        .expect("a directory config must not abort status");
        let AuditStatus::Failed { path, reason } = status else {
            panic!("a directory config must report a failed scan");
        };
        assert_eq!(path, config);
        assert!(matches!(
            reason,
            AuditFailureReason::ExplicitConfigNotRegularFile
        ));
    }

    #[tokio::test]
    async fn supplied_unsupported_agent_config_is_a_failed_scan() {
        let dir = tempfile::tempdir().expect("create test directory");
        let config = dir.path().join("agent.unsupported");
        std::fs::write(&config, "[registrar]\n").expect("write unsupported config");

        let status = load_audit_status(
            &status_args_with_agent_config(config.clone()),
            &test_messages(),
        )
        .await
        .expect("an unsupported config must not abort status");
        let AuditStatus::Failed { path, reason } = status else {
            panic!("an unsupported config must report a failed scan");
        };
        assert_eq!(path, config);
        assert!(matches!(reason, AuditFailureReason::Diagnostic(_)));
    }

    #[tokio::test]
    async fn supplied_agent_config_metadata_error_is_a_failed_scan() {
        let dir = tempfile::tempdir().expect("create test directory");
        let blocker = dir.path().join("not-a-directory");
        std::fs::write(&blocker, "blocker").expect("write metadata blocker");
        let config = blocker.join("agent.toml");

        let status = load_audit_status(
            &status_args_with_agent_config(config.clone()),
            &test_messages(),
        )
        .await
        .expect("a metadata error must not abort status");
        let AuditStatus::Failed { path, reason } = status else {
            panic!("a metadata error must report a failed scan");
        };
        assert_eq!(path, config);
        assert!(matches!(reason, AuditFailureReason::Diagnostic(_)));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn unreadable_regular_agent_config_is_a_failed_scan() {
        use std::os::unix::fs::PermissionsExt;

        // SAFETY: geteuid only reads the process identity and has no preconditions.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }

        let dir = tempfile::tempdir().expect("create test directory");
        let config = dir.path().join("agent.toml");
        std::fs::write(&config, "[registrar]\n").expect("write agent config");
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000))
            .expect("remove config read permission");

        let status = load_audit_status(
            &status_args_with_agent_config(config.clone()),
            &test_messages(),
        )
        .await
        .expect("an unreadable config must not abort status");
        let AuditStatus::Failed { path, reason } = status else {
            panic!("an unreadable config must report a failed scan");
        };
        assert_eq!(path, config);
        assert!(matches!(reason, AuditFailureReason::Diagnostic(_)));
    }

    #[tokio::test]
    async fn malformed_agent_config_is_a_failed_scan() {
        let dir = tempfile::tempdir().expect("create test directory");
        let config = dir.path().join("agent.toml");
        std::fs::write(&config, "[registrar\n").expect("write malformed config");

        let status = load_audit_status(
            &status_args_with_agent_config(config.clone()),
            &test_messages(),
        )
        .await
        .expect("a malformed config does not abort status");
        let AuditStatus::Failed { path, reason } = status else {
            panic!("a malformed config must report a failed scan");
        };
        assert_eq!(path, config);
        assert!(matches!(reason, AuditFailureReason::Diagnostic(_)));
    }

    #[tokio::test]
    async fn invalid_registrar_settings_are_a_failed_scan() {
        let dir = tempfile::tempdir().expect("create test directory");
        let config = dir.path().join("agent.toml");
        std::fs::write(&config, "[registrar]\naudit_max_retained_files = 0\n")
            .expect("write invalid agent config");

        let status = load_audit_status(&status_args_with_agent_config(config), &test_messages())
            .await
            .expect("invalid settings must not abort status");
        let AuditStatus::Failed { reason, .. } = status else {
            panic!("invalid registrar settings must report a failed scan");
        };
        let AuditFailureReason::Diagnostic(error) = reason else {
            panic!("invalid registrar settings are diagnostic failures");
        };
        assert!(error.contains("audit_max_retained_files"));
    }

    #[tokio::test]
    async fn invalid_registrar_settings_each_leave_status_in_the_failed_scan_state() {
        let dir = tempfile::tempdir().expect("create test directory");
        for (name, setting) in [
            (
                "relative-directory",
                "audit_record_dir = \"relative-audit\"",
            ),
            ("small-file", "audit_max_file_bytes = 1"),
            ("zero-retained", "audit_max_retained_files = 0"),
            ("zero-days", "audit_min_retain_days = 0"),
        ] {
            let config = dir.path().join(format!("{name}.toml"));
            std::fs::write(&config, format!("[registrar]\n{setting}\n"))
                .expect("write invalid registrar config");

            let status = load_audit_status(
                &status_args_with_agent_config(config.clone()),
                &test_messages(),
            )
            .await
            .expect("invalid registrar settings do not abort status");
            let AuditStatus::Failed { path, reason } = status else {
                panic!("{name} must report a failed scan");
            };
            assert_eq!(path, config);
            let AuditFailureReason::Diagnostic(error) = reason else {
                panic!("{name} must be a diagnostic failure");
            };
            assert!(error.contains("audit_"), "{name}: {error}");
        }
        assert!(
            !dir.path().join("relative-audit").exists(),
            "relative audit paths must not be opened or created"
        );
    }

    #[tokio::test]
    async fn unrelated_invalid_settings_do_not_hide_audit_status() {
        let dir = tempfile::tempdir().expect("create test directory");
        let audit_dir = dir.path().join("registrar-audit");
        std::fs::create_dir(&audit_dir).expect("create audit directory");
        let config = dir.path().join("agent.toml");
        std::fs::write(
            &config,
            format!(
                "domain = \"\"\n[registrar]\naudit_store_dir = \"{}\"\naudit_record_dir = \"{}\"\n",
                dir.path().display(),
                audit_dir.display()
            ),
        )
        .expect("write agent config with unrelated invalid setting");

        let status = load_audit_status(&status_args_with_agent_config(config), &test_messages())
            .await
            .expect("the audit loader does not run whole-settings validation");
        assert!(matches!(status, AuditStatus::Scan(_)));
    }

    #[tokio::test]
    async fn settings_task_join_failure_is_a_failed_audit_status() {
        let join_result = tokio::task::spawn_blocking(|| panic!("deliberate settings panic")).await;
        let join_error = join_result
            .as_ref()
            .err()
            .expect("the blocking task must panic")
            .to_string();
        let path = PathBuf::from("selected-agent.toml");

        let Err(AuditStatus::Failed {
            path: failed_path,
            reason,
        }) = map_audit_settings_join_result(path.clone(), join_result)
        else {
            panic!("the join failure must return failed audit status");
        };
        assert_eq!(failed_path, path);
        let AuditFailureReason::Diagnostic(reason) = reason else {
            panic!("a join error is diagnostic text");
        };
        assert_eq!(reason, join_error);
    }

    #[test]
    fn audit_section_renders_each_state_in_both_locales() {
        let scan = AuditStatus::Scan(AuditScan {
            intent_without_outcome: 2,
            malformed_records: 3,
            retention_short: true,
        });
        let failure = AuditStatus::Failed {
            path: PathBuf::from("/var/lib/bootroot/registrar-audit"),
            reason: AuditFailureReason::Diagnostic("permission denied".to_string()),
        };
        let non_regular_file_failure = AuditStatus::Failed {
            path: PathBuf::from("/etc/bootroot/agent.toml"),
            reason: AuditFailureReason::ExplicitConfigNotRegularFile,
        };

        for locale in ["en", "ko"] {
            let messages = Messages::new(locale).expect("load test locale");
            let absent = audit_section_lines(&messages, &AuditStatus::Absent);
            assert_eq!(absent.len(), 2, "{locale} absent state");
            assert!(
                !absent
                    .iter()
                    .any(|line| line.contains("WARNING") || line.contains("경고"))
            );

            let succeeded = audit_section_lines(&messages, &scan);
            assert_eq!(succeeded.len(), 7, "{locale} successful state");
            assert!(succeeded.iter().any(|line| line.contains('2')));
            assert!(succeeded.iter().any(|line| line.contains('3')));

            let failed = audit_section_lines(&messages, &failure);
            assert_eq!(failed.len(), 2, "{locale} failed state");
            let warning = failed.get(1).expect("failed audit section has a warning");
            assert!(warning.contains("/var/lib/bootroot/registrar-audit"));
            assert!(warning.contains("permission denied"));

            let non_regular_file = audit_section_lines(&messages, &non_regular_file_failure);
            let warning = non_regular_file
                .get(1)
                .expect("non-regular-file failure has a warning");
            assert!(warning.contains("/etc/bootroot/agent.toml"));
            let explanation = match locale {
                "en" => "agent configuration path is not a regular file",
                "ko" => "agent 구성 경로가 일반 파일이 아닙니다",
                _ => unreachable!("the test provides only known locales"),
            };
            assert!(warning.contains(explanation), "{locale}: {warning}");
        }
    }

    /// Closes #731: `status` follows a non-default `OPENBAO_HOST_PORT`
    /// recorded in the compose directory's `.env`.
    #[test]
    fn status_openbao_url_follows_the_configured_host_port() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18200\n").expect("write .env");
        let args = status_args(
            dir.path().join("docker-compose.yml"),
            crate::commands::init::DEFAULT_OPENBAO_URL,
        );
        assert_eq!(
            status_openbao_url_with_env(&args, None),
            "http://localhost:18200"
        );
    }

    /// The first step of the `${OPENBAO_HOST_PORT:-8200}` precedence:
    /// what the invoking environment held outranks the compose `.env`,
    /// so `status` reaches the instance an operator scoped the shell to
    /// rather than the one the directory records.
    #[test]
    fn status_openbao_url_prefers_the_environment_over_the_env_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18200\n").expect("write .env");
        let args = status_args(
            dir.path().join("docker-compose.yml"),
            crate::commands::init::DEFAULT_OPENBAO_URL,
        );
        assert_eq!(
            status_openbao_url_with_env(&args, Some("18201")),
            "http://localhost:18201"
        );
    }

    /// Closes #731: an operator-supplied `--openbao-url` is used
    /// verbatim, whatever the configured host port is.
    #[test]
    fn status_openbao_url_honours_an_explicit_url() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18200\n").expect("write .env");
        let args = status_args(
            dir.path().join("docker-compose.yml"),
            "https://openbao.internal:8200",
        );
        assert_eq!(
            status_openbao_url_with_env(&args, Some("18201")),
            "https://openbao.internal:8200",
            "an explicit --openbao-url outranks every port source"
        );
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
