use std::path::Path;
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::cli::args::{
    MonitoringDownArgs, MonitoringProfile, MonitoringStatusArgs, MonitoringUpArgs,
};
use crate::commands::infra::{
    ContainerReadiness, collect_container_failures, collect_readiness, docker_compose_output,
    docker_output, run_docker,
};
use crate::i18n::Messages;

pub(crate) fn run_monitoring_up(args: &MonitoringUpArgs, messages: &Messages) -> Result<()> {
    let services = monitoring_services(args.profile);
    if monitoring_already_running(&args.compose_file, args.profile, &services, messages)? {
        println!("{}", messages.monitoring_up_already_running());
        return Ok(());
    }
    let compose_str = args.compose_file.to_string_lossy();
    let profile_str = args.profile.to_string();
    let svc_refs: Vec<&str> = services.iter().map(String::as_str).collect();
    let mut up_args: Vec<&str> = vec![
        "compose",
        "-f",
        &compose_str,
        "--profile",
        &profile_str,
        "up",
        "-d",
    ];
    up_args.extend(&svc_refs);
    run_docker_with_env(
        &up_args,
        "docker compose up",
        messages,
        args.grafana_admin_password.as_deref(),
    )?;

    let readiness = collect_readiness(&args.compose_file, Some(&profile_str), &services, messages)?;
    print_readiness_summary(&readiness, messages);
    ensure_all_healthy(&readiness, messages)?;

    println!("{}", messages.monitoring_up_completed());
    Ok(())
}

pub(crate) fn run_monitoring_status(
    args: &MonitoringStatusArgs,
    messages: &Messages,
) -> Result<()> {
    let profiles = detect_running_profiles(&args.compose_file, messages)?;
    if profiles.is_empty() {
        anyhow::bail!(messages.monitoring_status_no_services());
    }

    println!("{}", messages.monitoring_status_title());

    let mut failures = Vec::new();
    for profile in profiles {
        let services = monitoring_services(profile);
        let profile_str = profile.to_string();
        let readiness =
            collect_readiness(&args.compose_file, Some(&profile_str), &services, messages)?;

        println!(
            "{}",
            messages.monitoring_status_profile(&profile.to_string())
        );
        println!("{}", messages.monitoring_status_section_services());
        for entry in &readiness {
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

        let url = grafana_url(profile);
        println!("{}", messages.monitoring_status_grafana_url(&url));

        let grafana_service = match profile {
            MonitoringProfile::Lan => "grafana",
            MonitoringProfile::Public => "grafana-public",
        };
        let grafana_status = readiness
            .iter()
            .find(|entry| entry.service == grafana_service)
            .and_then(|entry| grafana_admin_password_status(&entry.container_id, messages).ok())
            .unwrap_or(GrafanaAdminPasswordStatus::Unknown);
        // codeql[rust/cleartext-logging]: output is a status label, not the password value.
        println!(
            "{}",
            messages.monitoring_status_grafana_admin_password(grafana_status.as_str(messages))
        );

        failures.extend(collect_container_failures(&readiness));
    }

    if !failures.is_empty() {
        anyhow::bail!(messages.monitoring_unhealthy(&failures.join(", ")))
    }

    Ok(())
}

pub(crate) fn run_monitoring_down(args: &MonitoringDownArgs, messages: &Messages) -> Result<()> {
    let profiles = detect_running_profiles(&args.compose_file, messages)?;
    if profiles.is_empty() {
        anyhow::bail!(messages.monitoring_status_no_services());
    }

    let mut grafana_volumes = Vec::new();
    if args.reset_grafana_admin_password {
        for profile in &profiles {
            let grafana_service = match profile {
                MonitoringProfile::Lan => "grafana",
                MonitoringProfile::Public => "grafana-public",
            };
            let profile_str = profile.to_string();
            let grafana_container_id = docker_compose_output(
                &args.compose_file,
                Some(&profile_str),
                &["ps", "-q", grafana_service],
                messages,
            )?
            .trim()
            .to_string();
            if grafana_container_id.is_empty() {
                continue;
            }
            if let Some(volume) = grafana_data_volume_name(&grafana_container_id, messages)
                .ok()
                .flatten()
            {
                grafana_volumes.push(volume);
            }
        }
    }

    for profile in &profiles {
        let services = monitoring_services(*profile);
        let compose_str = args.compose_file.to_string_lossy();
        let profile_str = profile.to_string();
        let svc_refs: Vec<&str> = services.iter().map(String::as_str).collect();

        let mut stop_args: Vec<&str> = vec![
            "compose",
            "-f",
            &compose_str,
            "--profile",
            &profile_str,
            "stop",
        ];
        stop_args.extend(&svc_refs);
        run_docker(&stop_args, "docker compose stop", messages)?;

        let mut rm_args: Vec<&str> = vec![
            "compose",
            "-f",
            &compose_str,
            "--profile",
            &profile_str,
            "rm",
            "-f",
        ];
        rm_args.extend(&svc_refs);
        run_docker(&rm_args, "docker compose rm", messages)?;
    }

    if args.reset_grafana_admin_password {
        if grafana_volumes.is_empty() {
            println!("{}", messages.monitoring_down_reset_grafana_skipped());
        } else {
            for volume in grafana_volumes {
                let args = ["volume", "rm", &volume];
                run_docker(&args, "docker volume rm", messages)?;
            }
            println!("{}", messages.monitoring_down_reset_grafana());
        }
    }

    println!("{}", messages.monitoring_down_completed());
    Ok(())
}

fn monitoring_services(profile: MonitoringProfile) -> Vec<String> {
    let grafana_service = match profile {
        MonitoringProfile::Lan => "grafana",
        MonitoringProfile::Public => "grafana-public",
    };
    vec!["prometheus".to_string(), grafana_service.to_string()]
}

fn detect_running_profiles(
    compose_file: &Path,
    messages: &Messages,
) -> Result<Vec<MonitoringProfile>> {
    let mut profiles = Vec::new();
    for profile in [MonitoringProfile::Lan, MonitoringProfile::Public] {
        let services = monitoring_services(profile);
        let profile_str = profile.to_string();
        let mut any_running = false;
        for service in &services {
            let container_id = docker_compose_output(
                compose_file,
                Some(&profile_str),
                &["ps", "-q", service],
                messages,
            )?;
            if !container_id.trim().is_empty() {
                any_running = true;
                break;
            }
        }
        if any_running {
            profiles.push(profile);
        }
    }
    Ok(profiles)
}

fn grafana_url(profile: MonitoringProfile) -> String {
    match profile {
        MonitoringProfile::Lan => {
            let host =
                std::env::var("GRAFANA_LAN_BIND_ADDR").unwrap_or_else(|_| "127.0.0.1".to_string());
            format!("http://{host}:3000")
        }
        MonitoringProfile::Public => "http://0.0.0.0:3000".to_string(),
    }
}

fn print_readiness_summary(readiness: &[ContainerReadiness], messages: &Messages) {
    println!("{}", messages.monitoring_readiness_summary());
    for entry in readiness {
        match entry.health.as_deref() {
            Some(health) => println!(
                "{}",
                messages.readiness_entry_with_health(&entry.service, &entry.status, health)
            ),
            None => println!(
                "{}",
                messages.readiness_entry_without_health(&entry.service, &entry.status)
            ),
        }
    }
}

fn ensure_all_healthy(readiness: &[ContainerReadiness], messages: &Messages) -> Result<()> {
    let failures = collect_container_failures(readiness);
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(messages.monitoring_unhealthy(&failures.join(", ")))
    }
}

fn monitoring_already_running(
    compose_file: &Path,
    profile: MonitoringProfile,
    services: &[String],
    messages: &Messages,
) -> Result<bool> {
    let profile_str = profile.to_string();
    for service in services {
        let container_id = docker_compose_output(
            compose_file,
            Some(&profile_str),
            &["ps", "-q", service],
            messages,
        )?;
        let container_id = container_id.trim();
        if container_id.is_empty() {
            return Ok(false);
        }
        let status = docker_output(
            &["inspect", "--format", "{{.State.Status}}", container_id],
            messages,
        )?;
        if status.trim() != "running" {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Copy, Debug)]
enum GrafanaAdminPasswordStatus {
    Set,
    Default,
    Unknown,
}

impl GrafanaAdminPasswordStatus {
    fn as_str(self, messages: &Messages) -> &'static str {
        match self {
            GrafanaAdminPasswordStatus::Set => messages.monitoring_status_value_set(),
            GrafanaAdminPasswordStatus::Default => messages.monitoring_status_value_default(),
            GrafanaAdminPasswordStatus::Unknown => messages.monitoring_status_value_unknown(),
        }
    }
}

fn grafana_admin_password_status(
    container_id: &str,
    messages: &Messages,
) -> Result<GrafanaAdminPasswordStatus> {
    let envs = read_container_env(container_id, messages)?;
    let value = envs
        .iter()
        .find_map(|entry| entry.strip_prefix("GF_SECURITY_ADMIN_PASSWORD="))
        .unwrap_or("admin");
    if value.is_empty() || value == "admin" {
        Ok(GrafanaAdminPasswordStatus::Default)
    } else {
        Ok(GrafanaAdminPasswordStatus::Set)
    }
}

fn read_container_env(container_id: &str, messages: &Messages) -> Result<Vec<String>> {
    let output = docker_output(
        &["inspect", "--format", "{{json .Config.Env}}", container_id],
        messages,
    )?;
    let value: Value = serde_json::from_str(output.trim())
        .with_context(|| messages.error_parse_container_env_failed())?;
    let envs = value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    Ok(envs)
}

fn grafana_data_volume_name(container_id: &str, messages: &Messages) -> Result<Option<String>> {
    let output = docker_output(
        &["inspect", "--format", "{{json .Mounts}}", container_id],
        messages,
    )?;
    let value: Value = serde_json::from_str(output.trim())
        .with_context(|| messages.error_parse_container_mounts_failed())?;
    let mounts = value.as_array().cloned().unwrap_or_default();
    for mount in mounts {
        let destination = mount.get("Destination").and_then(|item| item.as_str());
        if destination != Some("/var/lib/grafana") {
            continue;
        }
        let mount_type = mount.get("Type").and_then(|item| item.as_str());
        if mount_type != Some("volume") {
            continue;
        }
        let name = mount.get("Name").and_then(|item| item.as_str());
        if let Some(name) = name {
            return Ok(Some(name.to_string()));
        }
    }
    Ok(None)
}

fn run_docker_with_env(
    args: &[&str],
    context: &str,
    messages: &Messages,
    grafana_admin_password: Option<&str>,
) -> Result<()> {
    let mut command = ProcessCommand::new("docker");
    command.args(args);
    if let Some(password) = grafana_admin_password {
        command.env("GRAFANA_ADMIN_PASSWORD", password);
    }
    let status = command
        .status()
        .with_context(|| messages.error_command_run_failed(context))?;
    if !status.success() {
        anyhow::bail!(messages.error_command_failed_status(context, &status.to_string()));
    }
    Ok(())
}
