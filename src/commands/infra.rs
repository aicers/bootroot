use std::io::IsTerminal;
use std::path::Path;
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use crate::cli::args::{InfraInstallArgs, InfraUpArgs};
use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::dotenv::write_dotenv;
use crate::commands::guardrails::ensure_all_services_localhost_binding;
use crate::commands::openbao_unseal::{prompt_unseal_keys_interactive, read_unseal_keys_from_file};
use crate::i18n::Messages;

const DEFAULT_GRAFANA_ADMIN_PASSWORD: &str = "admin";
// Keep in sync with docker-compose.yml POSTGRES_USER / POSTGRES_DB.
const DEFAULT_POSTGRES_USER: &str = "step";
const DEFAULT_POSTGRES_DB: &str = "stepca";
const UNSEAL_KEYS_PATH: &str = "secrets/openbao/unseal-keys.txt";

pub(crate) fn run_infra_up(args: &InfraUpArgs, messages: &Messages) -> Result<()> {
    ensure_all_services_localhost_binding(&args.compose_file.compose_file, messages)?;

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

    // Auto-detect unseal key file if not explicitly specified.
    // Resolve relative to the compose file directory so custom
    // --compose-file layouts work correctly.
    let compose_dir = args
        .compose_file
        .compose_file
        .parent()
        .unwrap_or(Path::new("."));
    let unseal_file = args.openbao_unseal_from_file.clone().or_else(|| {
        let default_path = compose_dir.join(UNSEAL_KEYS_PATH);
        if default_path.exists() {
            Some(default_path)
        } else {
            None
        }
    });
    if let Some(path) = unseal_file.as_deref() {
        auto_unseal_openbao(path, &args.openbao_url, messages)?;
    } else {
        // No key file found — check if OpenBao is sealed and prompt
        // interactively so `infra up` works without --openbao-unseal-from-file.
        maybe_interactive_unseal(&args.openbao_url, messages)?;
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

pub(crate) fn run_infra_install(args: &InfraInstallArgs, messages: &Messages) -> Result<()> {
    ensure_all_services_localhost_binding(&args.compose_file.compose_file, messages)?;

    // Docker Compose resolves relative bind-mount paths (e.g. ./secrets)
    // from the compose file's parent directory, not the process cwd.
    // Create directories there so Docker does not auto-create them as root.
    let compose_dir = args
        .compose_file
        .compose_file
        .parent()
        .unwrap_or(Path::new("."));
    let secrets_dir = compose_dir.join("secrets");
    let certs_dir = compose_dir.join("certs");
    for dir in [&secrets_dir, &certs_dir] {
        if !dir.exists() {
            std::fs::create_dir_all(dir)
                .with_context(|| messages.error_write_file_failed(&dir.display().to_string()))?;
        }
    }
    println!("{}", messages.infra_install_dirs_created());

    // Docker Compose reads .env from the compose file's directory.
    let env_path = compose_dir.join(".env");
    if !env_path.exists() {
        let postgres_password = bootroot::utils::generate_secret(32)
            .with_context(|| messages.error_generate_secret_failed())?;
        write_dotenv(
            &env_path,
            &[
                ("POSTGRES_USER", DEFAULT_POSTGRES_USER),
                ("POSTGRES_PASSWORD", &postgres_password),
                ("POSTGRES_DB", DEFAULT_POSTGRES_DB),
                ("GRAFANA_ADMIN_PASSWORD", DEFAULT_GRAFANA_ADMIN_PASSWORD),
            ],
            messages,
        )?;
        println!("{}", messages.infra_install_env_written());
    }

    // Load local images or pull + build.
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

    // Use --build to build local images (step-ca, bootroot-http01).
    let mut up_args: Vec<&str> = vec!["compose", "-f", &compose_str, "up", "--build", "-d"];
    up_args.extend(&svc_refs);
    run_docker(&up_args, "docker compose up --build", messages)?;

    // Collect readiness but skip step-ca (it has no config yet).
    let prereq_services: Vec<String> = args
        .services
        .iter()
        .filter(|s| s.as_str() != "step-ca")
        .cloned()
        .collect();
    let readiness = collect_readiness(
        &args.compose_file.compose_file,
        None,
        &prereq_services,
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

    // Also set restart policy for step-ca if it's in the service list.
    if args.services.iter().any(|s| s == "step-ca") {
        let stepca_services = vec!["step-ca".to_string()];
        if let Ok(stepca_readiness) = collect_readiness(
            &args.compose_file.compose_file,
            None,
            &stepca_services,
            messages,
        ) {
            for entry in &stepca_readiness {
                let update_args = [
                    "update",
                    "--restart",
                    &*args.restart_policy,
                    &*entry.container_id,
                ];
                let _ = run_docker(&update_args, "docker update", messages);
            }
        }
    }

    print_readiness_summary(&readiness, messages);
    ensure_all_healthy(&readiness, messages)?;
    println!("{}", messages.infra_install_stepca_not_checked());

    println!("{}", messages.infra_install_completed());
    Ok(())
}

/// Checks that `OpenBao` and `PostgreSQL` are running and healthy.
///
/// Unlike `ensure_infra_ready`, this does not check step-ca because
/// it may not be bootstrapped yet during the `init` flow.
pub(crate) fn ensure_init_prereqs_ready(compose_file: &Path, messages: &Messages) -> Result<()> {
    let services = vec!["openbao".to_string(), "postgres".to_string()];
    let readiness = collect_readiness(compose_file, None, &services, messages)?;
    ensure_all_healthy(&readiness, messages)?;
    Ok(())
}

fn auto_unseal_openbao(path: &Path, openbao_url: &str, messages: &Messages) -> Result<()> {
    println!("{}", messages.warning_openbao_unseal_from_file());
    let keys = read_unseal_keys_from_file(path, messages)?;
    let runtime = tokio::runtime::Runtime::new()
        .with_context(|| messages.error_runtime_init_failed("infra up"))?;
    runtime.block_on(async {
        let client = OpenBaoClient::new(openbao_url)
            .with_context(|| messages.error_openbao_client_create_failed())?;

        // An uninitialized instance always reports sealed=true but has
        // no unseal keys yet.  A stale key file from a previous run
        // would cause an unseal error, so skip gracefully.
        if !client
            .is_initialized()
            .await
            .with_context(|| messages.error_openbao_init_status_failed())?
        {
            return Ok(());
        }

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

/// Checks whether `OpenBao` is sealed and, if so, prompts the user
/// for unseal keys interactively.
///
/// Skips the prompt when `OpenBao` has not been initialized yet (fresh
/// `infra install`) or when stdin is not a terminal (CI / scripted
/// usage).
fn maybe_interactive_unseal(openbao_url: &str, messages: &Messages) -> Result<()> {
    let runtime = tokio::runtime::Runtime::new()
        .with_context(|| messages.error_runtime_init_failed("infra up"))?;
    runtime.block_on(async {
        let client = OpenBaoClient::new(openbao_url)
            .with_context(|| messages.error_openbao_client_create_failed())?;

        // An uninitialized instance always reports sealed=true but has
        // no unseal keys, so prompting is nonsensical.
        if !client
            .is_initialized()
            .await
            .with_context(|| messages.error_openbao_init_status_failed())?
        {
            return Ok(());
        }

        let status = client
            .seal_status()
            .await
            .with_context(|| messages.error_openbao_seal_status_failed())?;
        if !status.sealed {
            return Ok(());
        }

        if !std::io::stdin().is_terminal() {
            eprintln!("{}", messages.warning_openbao_sealed_non_interactive());
            return Ok(());
        }

        let keys = prompt_unseal_keys_interactive(status.t, messages)?;
        for key in &keys {
            client
                .unseal(key)
                .await
                .with_context(|| messages.error_openbao_unseal_failed())?;
        }
        let final_status = client
            .seal_status()
            .await
            .with_context(|| messages.error_openbao_seal_status_failed())?;
        if final_status.sealed {
            anyhow::bail!(messages.error_openbao_sealed());
        }
        Ok(())
    })
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
