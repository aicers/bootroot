use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};

mod cli;
mod commands;
mod i18n;
mod state;

use crate::commands::init::{
    DEFAULT_COMPOSE_FILE, DEFAULT_KV_MOUNT, DEFAULT_OPENBAO_URL, DEFAULT_SECRETS_DIR,
    DEFAULT_STEPCA_PROVISIONER, DEFAULT_STEPCA_URL,
};
use crate::i18n::Messages;
use crate::state::DeployType;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Language for CLI output (en or ko)
    #[arg(long, env = "BOOTROOT_LANG", default_value = "en", global = true)]
    lang: String,

    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    #[command(subcommand)]
    Infra(InfraCommand),
    Init(Box<InitArgs>),
    Status(Box<StatusArgs>),
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
    Add(AppAddArgs),
    Info(AppInfoArgs),
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

#[derive(Args, Debug)]
struct InitArgs {
    /// `OpenBao` API URL
    #[arg(long, default_value = DEFAULT_OPENBAO_URL)]
    openbao_url: String,

    /// `OpenBao` KV mount path (KV v2)
    #[arg(long, default_value = DEFAULT_KV_MOUNT)]
    kv_mount: String,

    /// Secrets directory to render files into
    #[arg(long, default_value = DEFAULT_SECRETS_DIR)]
    secrets_dir: PathBuf,

    /// Docker compose file for infra health checks
    #[arg(long, default_value = DEFAULT_COMPOSE_FILE)]
    compose_file: PathBuf,

    /// Auto-generate secrets where possible
    #[arg(long)]
    auto_generate: bool,

    /// Show secrets in output summaries
    #[arg(long)]
    show_secrets: bool,

    /// `OpenBao` root token (required if already initialized)
    #[arg(long, env = "OPENBAO_ROOT_TOKEN")]
    root_token: Option<String>,

    /// `OpenBao` unseal key (repeatable)
    #[arg(long, env = "OPENBAO_UNSEAL_KEYS", value_delimiter = ',')]
    unseal_key: Vec<String>,

    /// step-ca password (password.txt)
    #[arg(long, env = "STEPCA_PASSWORD")]
    stepca_password: Option<String>,

    /// `PostgreSQL` DSN for step-ca
    #[arg(long)]
    db_dsn: Option<String>,

    /// HTTP-01 responder HMAC secret
    #[arg(long, env = "HTTP01_HMAC")]
    http_hmac: Option<String>,

    /// HTTP-01 responder admin URL (optional)
    #[arg(long, env = "HTTP01_RESPONDER_URL")]
    responder_url: Option<String>,

    /// HTTP-01 responder request timeout (seconds)
    #[arg(long, default_value_t = 5)]
    responder_timeout_secs: u64,

    /// Auto-issue ACME EAB via step-ca
    #[arg(long)]
    eab_auto: bool,

    /// step-ca URL for EAB issuance
    #[arg(long, default_value = DEFAULT_STEPCA_URL)]
    stepca_url: String,

    /// step-ca ACME provisioner name
    #[arg(long, default_value = DEFAULT_STEPCA_PROVISIONER)]
    stepca_provisioner: String,

    /// ACME EAB key ID (optional)
    #[arg(long, env = "EAB_KID")]
    eab_kid: Option<String>,

    /// ACME EAB HMAC (optional)
    #[arg(long, env = "EAB_HMAC")]
    eab_hmac: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct StatusArgs {
    /// Path to docker-compose.yml
    #[arg(long, default_value = DEFAULT_COMPOSE_FILE)]
    compose_file: PathBuf,

    /// `OpenBao` API URL
    #[arg(long, default_value = DEFAULT_OPENBAO_URL)]
    openbao_url: String,

    /// `OpenBao` KV mount path (KV v2)
    #[arg(long, default_value = DEFAULT_KV_MOUNT)]
    kv_mount: String,

    /// `OpenBao` root token (optional, needed for KV/AppRole checks)
    #[arg(long, env = "OPENBAO_ROOT_TOKEN")]
    root_token: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct AppAddArgs {
    /// App kind identifier
    #[arg(long)]
    app_kind: String,

    /// Deployment type (daemon or docker)
    #[arg(long, value_enum)]
    deploy_type: DeployType,

    /// Hostname used for DNS SAN
    #[arg(long)]
    hostname: String,

    /// `OpenBao` root token
    #[arg(long, env = "OPENBAO_ROOT_TOKEN")]
    root_token: Option<String>,

    /// Freeform notes (optional)
    #[arg(long)]
    notes: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct AppInfoArgs {
    /// App kind identifier
    #[arg(long)]
    app_kind: String,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("bootroot error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    let messages = Messages::new(&cli.lang)?;

    match cli.command {
        CliCommand::Infra(InfraCommand::Up(args)) => {
            commands::infra::run_infra_up(&args, &messages)?;
        }
        CliCommand::Init(args) => {
            let runtime = tokio::runtime::Runtime::new()
                .context("Failed to initialize async runtime for init")?;
            runtime.block_on(commands::init::run_init(&args, &messages))?;
        }
        CliCommand::Status(args) => {
            let runtime = tokio::runtime::Runtime::new()
                .context("Failed to initialize async runtime for status")?;
            runtime.block_on(commands::status::run_status(&args, &messages))?;
        }
        CliCommand::App(AppCommand::Add(args)) => {
            let runtime = tokio::runtime::Runtime::new()
                .context("Failed to initialize async runtime for app add")?;
            runtime.block_on(commands::app::run_app_add(&args, &messages))?;
        }
        CliCommand::App(AppCommand::Info(args)) => {
            commands::app::run_app_info(&args, &messages)?;
        }
        CliCommand::Verify => commands::verify::run_verify(&messages),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
