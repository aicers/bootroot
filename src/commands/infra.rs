use std::path::Path;
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use crate::cli::args::InfraUpArgs;
use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::guardrails::ensure_postgres_localhost_binding;
use crate::commands::openbao_unseal::read_unseal_keys_from_file;
use crate::i18n::Messages;

pub(crate) fn run_infra_up(args: &InfraUpArgs, messages: &Messages) -> Result<()> {
    ensure_postgres_localhost_binding(&args.compose_file.compose_file, messages)?;

    let loaded_archives = if let Some(dir) = args.image_archive_dir.as_deref() {
        load_local_images(dir, messages)?
    } else {
        0
    };

    let compose_str = args.compose_file.compose_file.to_string_lossy();
    let svc_refs: Vec<&str> = args.services.iter().map(String::as_str).collect();

    if loaded_archives == 0 {
        let mut pull_args: Vec<&str> = vec![
            "compose",
            "-f",
            &compose_str,
            "pull",
            "--ignore-pull-failures",
        ];
        pull_args.extend(&svc_refs);
        run_docker(&pull_args, "docker compose pull", messages)?;
    }

    let mut up_args: Vec<&str> = vec!["compose", "-f", &compose_str, "up", "-d"];
    up_args.extend(&svc_refs);
    run_docker(&up_args, "docker compose up", messages)?;

    if let Some(path) = args.openbao_unseal_from_file.as_deref() {
        auto_unseal_openbao(path, &args.openbao_url, messages)?;
    }

    let readiness = collect_readiness(
        &args.compose_file.compose_file,
        None,
        &args.services,
        messages,
    )?;

    for entry in &readiness {
        let update_args = [
            "update",
            "--restart",
            &*args.restart_policy,
            &*entry.container_id,
        ];
        run_docker(&update_args, "docker update", messages)?;
    }

    print_readiness_summary(&readiness, messages);
    ensure_all_healthy(&readiness, messages)?;

    println!("{}", messages.infra_up_completed());
    Ok(())
}

fn auto_unseal_openbao(path: &Path, openbao_url: &str, messages: &Messages) -> Result<()> {
    println!("{}", messages.warning_openbao_unseal_from_file());
    let prompt = messages.prompt_openbao_unseal_from_file_confirm(&path.display().to_string());
    if !prompt_yes_no(&prompt, messages)? {
        anyhow::bail!(messages.error_operation_cancelled());
    }

    let keys = read_unseal_keys_from_file(path, messages)?;
    let runtime = tokio::runtime::Runtime::new()
        .with_context(|| messages.error_runtime_init_failed("infra up"))?;
    runtime.block_on(async {
        let client = OpenBaoClient::new(openbao_url)
            .with_context(|| messages.error_openbao_client_create_failed())?;
        for key in &keys {
            client
                .unseal(key)
                .await
                .with_context(|| messages.error_openbao_unseal_failed())?;
        }
        let status = client
            .seal_status()
            .await
            .with_context(|| messages.error_openbao_seal_status_failed())?;
        if status.sealed {
            anyhow::bail!(messages.error_openbao_sealed());
        }
        Ok(())
    })
}

fn prompt_yes_no(prompt: &str, messages: &Messages) -> Result<bool> {
    use std::io::{self, Write};

    let mut stdout = io::stdout();
    let mut input = String::new();

    write!(stdout, "{prompt}").with_context(|| messages.error_prompt_write_failed())?;
    stdout
        .flush()
        .with_context(|| messages.error_prompt_flush_failed())?;
    io::stdin()
        .read_line(&mut input)
        .with_context(|| messages.error_prompt_read_failed())?;
    let trimmed = input.trim().to_ascii_lowercase();
    Ok(trimmed == "y" || trimmed == "yes")
}

pub(crate) fn ensure_infra_ready(compose_file: &Path, messages: &Messages) -> Result<()> {
    let services = default_infra_services();
    let readiness = collect_readiness(compose_file, None, &services, messages)?;
    ensure_all_healthy(&readiness, messages)?;
    Ok(())
}

pub(crate) fn default_infra_services() -> Vec<String> {
    vec![
        "openbao".to_string(),
        "postgres".to_string(),
        "step-ca".to_string(),
        RESPONDER_SERVICE_NAME.to_string(),
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
    profile: Option<&str>,
    services: &[String],
    messages: &Messages,
) -> Result<Vec<ContainerReadiness>> {
    let mut readiness = Vec::with_capacity(services.len());
    for service in services {
        let container_id =
            docker_compose_output(compose_file, profile, &["ps", "-q", service], messages)?;
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

pub(crate) fn parse_container_state(raw: &str) -> (String, Option<String>) {
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
                messages.readiness_entry_with_health(&entry.service, &entry.status, health)
            ),
            None => println!(
                "{}",
                messages.readiness_entry_without_health(&entry.service, &entry.status)
            ),
        }
    }
}

pub(crate) fn collect_container_failures(readiness: &[ContainerReadiness]) -> Vec<String> {
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

fn ensure_all_healthy(readiness: &[ContainerReadiness], messages: &Messages) -> Result<()> {
    let failures = collect_container_failures(readiness);
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(messages.infra_unhealthy(&failures.join(", ")))
    }
}

fn load_local_images(dir: &Path, messages: &Messages) -> Result<usize> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| messages.error_read_dir_failed(&dir.display().to_string()))?;
    let mut loaded = 0;
    for entry in entries {
        let entry = entry.with_context(|| messages.error_read_dir_entry_failed())?;
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
        run_docker(&args, "docker load", messages)?;
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

pub(crate) fn run_docker(args: &[&str], context: &str, messages: &Messages) -> Result<()> {
    let status = ProcessCommand::new("docker")
        .args(args)
        .status()
        .with_context(|| messages.error_command_run_failed(context))?;
    if !status.success() {
        anyhow::bail!(messages.error_command_failed_status(context, &status.to_string()));
    }
    Ok(())
}

pub(crate) fn docker_compose_output(
    compose_file: &Path,
    profile: Option<&str>,
    args: &[&str],
    messages: &Messages,
) -> Result<String> {
    let compose_str = compose_file.to_string_lossy();
    let mut cmd = ProcessCommand::new("docker");
    cmd.args(["compose", "-f", compose_str.as_ref()]);
    if let Some(profile) = profile {
        cmd.args(["--profile", profile]);
    }
    cmd.args(args);
    let output = cmd
        .output()
        .with_context(|| messages.error_command_run_failed("docker compose"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(messages.error_docker_compose_failed(&stderr));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub(crate) fn docker_output(args: &[&str], messages: &Messages) -> Result<String> {
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

#[cfg(test)]
mod tests {
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
