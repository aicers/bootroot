use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    #[command(subcommand)]
    Infra(InfraCommand),
    Init,
    Status,
    #[command(subcommand)]
    App(AppCommand),
    Verify,
}

#[derive(Subcommand, Debug)]
enum InfraCommand {
    Up(InfraUpArgs),
}

#[derive(Subcommand, Debug)]
enum AppCommand {
    Add,
    Info,
}

#[derive(Args, Debug)]
struct InfraUpArgs {
    /// Path to docker-compose.yml
    #[arg(long, default_value = "docker-compose.yml")]
    compose_file: PathBuf,

    /// Comma-separated list of services to start
    #[arg(
        long,
        default_value = "openbao,postgres,step-ca,bootroot-http01",
        value_delimiter = ','
    )]
    services: Vec<String>,

    /// Directory containing local image archives (optional)
    #[arg(long)]
    image_archive_dir: Option<PathBuf>,

    /// Docker restart policy to apply after containers start
    #[arg(long, default_value = "unless-stopped")]
    restart_policy: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("bootroot error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Infra(InfraCommand::Up(args)) => run_infra_up(&args)?,
        CliCommand::Init => {
            println!("bootroot init: not yet implemented");
        }
        CliCommand::Status => {
            println!("bootroot status: not yet implemented");
        }
        CliCommand::App(AppCommand::Add) => {
            println!("bootroot app add: not yet implemented");
        }
        CliCommand::App(AppCommand::Info) => {
            println!("bootroot app info: not yet implemented");
        }
        CliCommand::Verify => {
            println!("bootroot verify: not yet implemented");
        }
    }
    Ok(())
}

fn run_infra_up(args: &InfraUpArgs) -> Result<()> {
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

    let readiness = collect_readiness(&args.compose_file, &args.services)?;

    for entry in &readiness {
        let update_args = docker_update_args(&args.restart_policy, &entry.container_id);
        let update_args_ref: Vec<&str> = update_args.iter().map(String::as_str).collect();
        run_docker(&update_args_ref, "docker update")?;
    }

    print_readiness_summary(&readiness);
    ensure_all_healthy(&readiness)?;

    println!("bootroot infra up: completed");
    Ok(())
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

fn compose_pull_args(compose_file: &Path, services: &[String]) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "pull".to_string(),
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
        run_docker(
            &["load", "-i", path.to_string_lossy().as_ref()],
            "docker load",
        )?;
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

fn run_docker(args: &[&str], context: &str) -> Result<()> {
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContainerReadiness {
    service: String,
    container_id: String,
    status: String,
    health: Option<String>,
}

fn collect_readiness(compose_file: &Path, services: &[String]) -> Result<Vec<ContainerReadiness>> {
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
            anyhow::bail!("Service has no running container: {service}");
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

fn print_readiness_summary(readiness: &[ContainerReadiness]) {
    println!("bootroot infra up: readiness summary");
    for entry in readiness {
        match entry.health.as_deref() {
            Some(health) => println!("- {}: {} (health: {})", entry.service, entry.status, health),
            None => println!("- {}: {}", entry.service, entry.status),
        }
    }
}

fn ensure_all_healthy(readiness: &[ContainerReadiness]) -> Result<()> {
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
        anyhow::bail!("Infrastructure not healthy: {}", failures.join(", "))
    }
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

    #[test]
    fn test_cli_parses_services_list() {
        let cli = Cli::parse_from(["bootroot", "infra", "up", "--services", "openbao,postgres"]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Up(args)) => {
                assert_eq!(args.services, vec!["openbao", "postgres"]);
            }
            _ => panic!("expected infra up"),
        }
    }
}
