use anyhow::{Context, Result};
use bootroot::openbao::{KvMountStatus, OpenBaoClient};

use crate::cli::args::StatusArgs;
use crate::commands::infra::{ContainerReadiness, collect_readiness, default_infra_services};
use crate::commands::init::{
    PATH_AGENT_EAB, PATH_CA_TRUST, PATH_RESPONDER_HMAC, PATH_STEPCA_DB, PATH_STEPCA_PASSWORD,
};
use crate::i18n::Messages;
use crate::state::StateFile;

pub(crate) async fn run_status(args: &StatusArgs, messages: &Messages) -> Result<()> {
    let services = default_infra_services();
    let readiness = collect_readiness(&args.compose.compose_file, &services, messages)?;
    let infra_failures = collect_infra_failures(&readiness);

    let mut client = OpenBaoClient::new(&args.openbao.openbao_url)
        .with_context(|| messages.error_openbao_client_create_failed())?;
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

    if let Some(token) = args.root_token.root_token.clone() {
        client.set_token(token);
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
        "bootroot-agent-role",
        "bootroot-responder-role",
        "bootroot-stepca-role",
    ];
    let approle_statuses = if openbao_ok && args.root_token.root_token.is_some() {
        Some(fetch_approle_statuses(&client, &approles, messages).await?)
    } else {
        None
    };
    let service_statuses = load_service_statuses(messages)?;

    let summary = StatusSummary {
        readiness: &readiness,
        openbao_ok,
        sealed: seal_status.map(|status| status.sealed),
        kv_mount: &args.openbao.kv_mount,
        kv_mount_status,
        kv_statuses: kv_statuses.as_deref(),
        approle_statuses: approle_statuses.as_deref(),
        service_statuses: &service_statuses,
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
            delivery_mode: entry.delivery_mode.as_str().to_string(),
        });
    }
    Ok(service_statuses)
}

fn collect_infra_failures(readiness: &[ContainerReadiness]) -> Vec<String> {
    let mut failures = Vec::new();
    for entry in readiness {
        if entry.status != "running" {
            failures.push(format!("{} status={}", entry.service, entry.status));
            continue;
        }
        if let Some(health) = entry.health.as_deref()
            && health != "healthy"
        {
            failures.push(format!("{} health={}", entry.service, health));
        }
    }
    failures
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
                messages.status_infra_entry_with_health(&entry.service, &entry.status, health)
            ),
            None => println!(
                "{}",
                messages.status_infra_entry_without_health(&entry.service, &entry.status)
            ),
        }
    }
    print_openbao_section(messages, summary);
    print_kv_paths_section(messages, summary);
    print_approles_section(messages, summary);
    print_services_section(messages, summary);
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
            "bootroot-agent-role",
            "bootroot-responder-role",
            "bootroot-stepca-role",
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
