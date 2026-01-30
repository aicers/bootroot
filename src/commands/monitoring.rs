use std::path::Path;
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};
use serde_json::Value;

use crate::cli::args::{
    MonitoringDownArgs, MonitoringProfile, MonitoringStatusArgs, MonitoringUpArgs,
};
use crate::i18n::Messages;

pub(crate) fn run_monitoring_up(args: &MonitoringUpArgs, messages: &Messages) -> Result<()> {
    let services = monitoring_services(args.profile);
    if monitoring_already_running(&args.compose_file, args.profile, &services, messages)? {
        println!("{}", messages.monitoring_up_already_running());
        return Ok(());
    }
    let compose_args = compose_up_args(&args.compose_file, args.profile, &services);
    let compose_args_ref: Vec<&str> = compose_args.iter().map(String::as_str).collect();
    run_docker_with_env(
        &compose_args_ref,
        "docker compose up",
        messages,
        args.grafana_admin_password.as_deref(),
    )?;

    let readiness = collect_readiness(&args.compose_file, args.profile, &services, messages)?;
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
        let readiness = collect_readiness(&args.compose_file, profile, &services, messages)?;

        println!(
            "{}",
            messages.monitoring_status_profile(&profile.to_string())
        );
        println!("{}", messages.monitoring_status_section_services());
        for entry in &readiness {
            match entry.health.as_deref() {
                Some(health) => println!(
                    "{}",
                    messages.monitoring_status_entry_with_health(
                        &entry.service,
                        &entry.status,
                        health
                    )
                ),
                None => println!(
                    "{}",
                    messages.monitoring_status_entry_without_health(&entry.service, &entry.status)
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
        println!(
            "{}",
            messages.monitoring_status_grafana_admin_password(grafana_status.as_str(messages))
        );

        failures.extend(collect_failures(&readiness));
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
            let grafana_container_id = docker_compose_output_with_profile(
                &args.compose_file,
                *profile,
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
        let stop_args = compose_stop_args(&args.compose_file, *profile, &services);
        let stop_args_ref: Vec<&str> = stop_args.iter().map(String::as_str).collect();
        run_docker(&stop_args_ref, "docker compose stop", messages)?;

        let rm_args = compose_rm_args(&args.compose_file, *profile, &services);
        let rm_args_ref: Vec<&str> = rm_args.iter().map(String::as_str).collect();
        run_docker(&rm_args_ref, "docker compose rm", messages)?;
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

#[derive(Debug, Clone)]
struct ContainerReadiness {
    service: String,
    container_id: String,
    status: String,
    health: Option<String>,
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
        let mut any_running = false;
        for service in &services {
            let container_id = docker_compose_output_with_profile(
                compose_file,
                profile,
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

fn collect_readiness(
    compose_file: &Path,
    profile: MonitoringProfile,
    services: &[String],
    messages: &Messages,
) -> Result<Vec<ContainerReadiness>> {
    let mut readiness = Vec::with_capacity(services.len());
    for service in services {
        let container_id = docker_compose_output_with_profile(
            compose_file,
            profile,
            &["ps", "-q", service],
            messages,
        )?;
        let container_id = container_id.trim().to_string();
        if container_id.is_empty() {
            anyhow::bail!(messages.error_service_no_container(service));
        }
        let inspect_output = docker_output(
            &[
                "inspect",
                "--format",
                "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
                &container_id,
            ],
            messages,
        )?;
        let (status, health) = parse_container_state(&inspect_output);
        readiness.push(ContainerReadiness {
            service: service.clone(),
            container_id,
            status,
            health,
        });
    }
    Ok(readiness)
}

fn parse_container_state(raw: &str) -> (String, Option<String>) {
    let trimmed = raw.trim();
    let mut parts = trimmed.splitn(2, '|');
    let status = parts.next().unwrap_or_default().to_string();
    let health = parts.next().and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    });
    (status, health)
}

fn collect_failures(readiness: &[ContainerReadiness]) -> Vec<String> {
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

fn print_readiness_summary(readiness: &[ContainerReadiness], messages: &Messages) {
    println!("{}", messages.monitoring_readiness_summary());
    for entry in readiness {
        match entry.health.as_deref() {
            Some(health) => println!(
                "{}",
                messages.monitoring_entry_with_health(&entry.service, &entry.status, health)
            ),
            None => println!(
                "{}",
                messages.monitoring_entry_without_health(&entry.service, &entry.status)
            ),
        }
    }
}

fn ensure_all_healthy(readiness: &[ContainerReadiness], messages: &Messages) -> Result<()> {
    let failures = collect_failures(readiness);
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(messages.monitoring_unhealthy(&failures.join(", ")))
    }
}

fn compose_up_args(
    compose_file: &Path,
    profile: MonitoringProfile,
    services: &[String],
) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "--profile".to_string(),
        profile.to_string(),
        "up".to_string(),
        "-d".to_string(),
    ];
    args.extend(services.iter().cloned());
    args
}

fn monitoring_already_running(
    compose_file: &Path,
    profile: MonitoringProfile,
    services: &[String],
    messages: &Messages,
) -> Result<bool> {
    for service in services {
        let container_id = docker_compose_output_with_profile(
            compose_file,
            profile,
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

fn docker_compose_output_with_profile(
    compose_file: &Path,
    profile: MonitoringProfile,
    args: &[&str],
    messages: &Messages,
) -> Result<String> {
    let output = ProcessCommand::new("docker")
        .args([
            "compose",
            "-f",
            compose_file.to_string_lossy().as_ref(),
            "--profile",
            &profile.to_string(),
        ])
        .args(args)
        .output()
        .with_context(|| messages.error_command_run_failed("docker compose"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(messages.error_docker_compose_failed(&stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn docker_output(args: &[&str], messages: &Messages) -> Result<String> {
    let output = ProcessCommand::new("docker")
        .args(args)
        .output()
        .with_context(|| messages.error_command_run_failed("docker"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(messages.error_docker_command_failed(&stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
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

fn run_docker(args: &[&str], context: &str, messages: &Messages) -> Result<()> {
    let status = ProcessCommand::new("docker")
        .args(args)
        .status()
        .with_context(|| messages.error_command_run_failed(context))?;
    if !status.success() {
        anyhow::bail!(messages.error_command_failed_status(context, &status.to_string()));
    }
    Ok(())
}

fn compose_stop_args(
    compose_file: &Path,
    profile: MonitoringProfile,
    services: &[String],
) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "--profile".to_string(),
        profile.to_string(),
        "stop".to_string(),
    ];
    args.extend(services.iter().cloned());
    args
}

fn compose_rm_args(
    compose_file: &Path,
    profile: MonitoringProfile,
    services: &[String],
) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "--profile".to_string(),
        profile.to_string(),
        "rm".to_string(),
        "-f".to_string(),
    ];
    args.extend(services.iter().cloned());
    args
}
