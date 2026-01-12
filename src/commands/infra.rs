use std::path::Path;
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};

use crate::InfraUpArgs;
use crate::i18n::Messages;

pub(crate) fn run_infra_up(args: &InfraUpArgs, messages: &Messages) -> Result<()> {
    let loaded_archives = if let Some(dir) = args.image_archive_dir.as_deref() {
        load_local_images(dir)?
    } else {
        0
    };

    if loaded_archives == 0 {
        let pull_args = compose_pull_args(&args.compose_file, &args.services);
        let pull_args_ref: Vec<&str> = pull_args.iter().map(String::as_str).collect();
        run_docker(&pull_args_ref, "docker compose pull")?;
    }

    let compose_args = compose_up_args(&args.compose_file, &args.services);
    let compose_args_ref: Vec<&str> = compose_args.iter().map(String::as_str).collect();
    run_docker(&compose_args_ref, "docker compose up")?;

    let readiness = collect_readiness(&args.compose_file, &args.services, messages)?;

    for entry in &readiness {
        let update_args = docker_update_args(&args.restart_policy, &entry.container_id);
        let update_args_ref: Vec<&str> = update_args.iter().map(String::as_str).collect();
        run_docker(&update_args_ref, "docker update")?;
    }

    print_readiness_summary(&readiness, messages);
    ensure_all_healthy(&readiness, messages)?;

    println!("{}", messages.infra_up_completed());
    Ok(())
}

pub(crate) fn ensure_infra_ready(compose_file: &Path, messages: &Messages) -> Result<()> {
    let services = default_infra_services();
    let readiness = collect_readiness(compose_file, &services, messages)?;
    ensure_all_healthy(&readiness, messages)?;
    Ok(())
}

pub(crate) fn default_infra_services() -> Vec<String> {
    vec![
        "openbao".to_string(),
        "postgres".to_string(),
        "step-ca".to_string(),
        "bootroot-http01".to_string(),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerReadiness {
    pub(crate) service: String,
    pub(crate) container_id: String,
    pub(crate) status: String,
    pub(crate) health: Option<String>,
}

pub(crate) fn collect_readiness(
    compose_file: &Path,
    services: &[String],
    messages: &Messages,
) -> Result<Vec<ContainerReadiness>> {
    let mut readiness = Vec::with_capacity(services.len());
    for service in services {
        let container_id = docker_compose_output(&[
            "-f",
            compose_file.to_string_lossy().as_ref(),
            "ps",
            "-q",
            service,
        ])?;
        let container_id = container_id.trim().to_string();
        if container_id.is_empty() {
            anyhow::bail!(messages.error_service_no_container(service));
        }
        let inspect_output = docker_output(&[
            "inspect",
            "--format",
            "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
            &container_id,
        ])?;
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

fn print_readiness_summary(readiness: &[ContainerReadiness], messages: &Messages) {
    println!("{}", messages.infra_readiness_summary());
    for entry in readiness {
        match entry.health.as_deref() {
            Some(health) => println!(
                "{}",
                messages.infra_entry_with_health(&entry.service, &entry.status, health)
            ),
            None => println!(
                "{}",
                messages.infra_entry_without_health(&entry.service, &entry.status)
            ),
        }
    }
}

fn ensure_all_healthy(readiness: &[ContainerReadiness], messages: &Messages) -> Result<()> {
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
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(messages.infra_unhealthy(&failures.join(", ")))
    }
}

fn load_local_images(dir: &Path) -> Result<usize> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read image archive dir: {}", dir.display()))?;
    let mut loaded = 0;
    for entry in entries {
        let entry = entry.context("Failed to read image archive entry")?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !is_image_archive(&path) {
            continue;
        }
        println!("Loading image archive: {}", path.display());
        let path_str = path.to_string_lossy();
        let args = ["load", "-i", path_str.as_ref()];
        run_docker(&args, "docker load")?;
        loaded += 1;
    }
    Ok(loaded)
}

fn is_image_archive(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let ext = Path::new(name).extension().and_then(|ext| ext.to_str());
    if let Some(ext) = ext
        && (ext.eq_ignore_ascii_case("tar") || ext.eq_ignore_ascii_case("tgz"))
    {
        return true;
    }
    name.to_ascii_lowercase().ends_with(".tar.gz")
}

fn compose_pull_args(compose_file: &Path, services: &[String]) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "pull".to_string(),
        "--ignore-pull-failures".to_string(),
    ];
    args.extend(services.iter().cloned());
    args
}

fn compose_up_args(compose_file: &Path, services: &[String]) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "up".to_string(),
        "-d".to_string(),
    ];
    args.extend(services.iter().cloned());
    args
}

fn docker_update_args(restart_policy: &str, container_id: &str) -> Vec<String> {
    vec![
        "update".to_string(),
        "--restart".to_string(),
        restart_policy.to_string(),
        container_id.to_string(),
    ]
}

pub(crate) fn run_docker(args: &[&str], context: &str) -> Result<()> {
    let status = ProcessCommand::new("docker")
        .args(args)
        .status()
        .with_context(|| format!("Failed to run {context}"))?;
    if !status.success() {
        anyhow::bail!("{context} failed with status: {status}");
    }
    Ok(())
}

fn docker_compose_output(args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new("docker")
        .args(["compose"])
        .args(args)
        .output()
        .context("Failed to run docker compose")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker compose failed: {stderr}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

fn docker_output(args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new("docker")
        .args(args)
        .output()
        .with_context(|| format!("Failed to run docker {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker command failed: {stderr}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn test_is_image_archive_extensions() {
        assert!(is_image_archive(Path::new("image.tar")));
        assert!(is_image_archive(Path::new("image.TAR")));
        assert!(is_image_archive(Path::new("image.tgz")));
        assert!(is_image_archive(Path::new("image.TGZ")));
        assert!(is_image_archive(Path::new("image.tar.gz")));
        assert!(is_image_archive(Path::new("image.TAR.GZ")));
        assert!(!is_image_archive(Path::new("image.zip")));
        assert!(!is_image_archive(Path::new("image")));
    }

    #[test]
    fn test_compose_up_args_includes_services() {
        let compose_file = PathBuf::from("compose.yml");
        let services = vec!["openbao".to_string(), "postgres".to_string()];
        let args = compose_up_args(&compose_file, &services);
        assert_eq!(
            args,
            vec![
                "compose",
                "-f",
                "compose.yml",
                "up",
                "-d",
                "openbao",
                "postgres"
            ]
        );
    }

    #[test]
    fn test_docker_update_args() {
        let args = docker_update_args("unless-stopped", "container123");
        assert_eq!(
            args,
            vec!["update", "--restart", "unless-stopped", "container123"]
        );
    }

    #[test]
    fn test_compose_pull_args_includes_services() {
        let compose_file = PathBuf::from("docker-compose.yml");
        let services = vec!["openbao".to_string(), "postgres".to_string()];
        let args = compose_pull_args(&compose_file, &services);
        assert_eq!(
            args,
            vec![
                "compose",
                "-f",
                "docker-compose.yml",
                "pull",
                "--ignore-pull-failures",
                "openbao",
                "postgres"
            ]
        );
    }

    #[test]
    fn test_parse_container_state_with_health() {
        let (status, health) = parse_container_state("running|healthy\n");
        assert_eq!(status, "running");
        assert_eq!(health.as_deref(), Some("healthy"));
    }

    #[test]
    fn test_parse_container_state_without_health() {
        let (status, health) = parse_container_state("exited|\n");
        assert_eq!(status, "exited");
        assert!(health.is_none());
    }

    #[test]
    fn test_parse_container_state_missing_delimiter() {
        let (status, health) = parse_container_state("running");
        assert_eq!(status, "running");
        assert!(health.is_none());
    }
}
