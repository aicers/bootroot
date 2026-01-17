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
    Verify(VerifyArgs),
    Rotate(RotateArgs),
}

#[derive(Subcommand, Debug)]
enum InfraCommand {
    Up(InfraUpArgs),
}

#[derive(Subcommand, Debug)]
enum AppCommand {
    Add(Box<AppAddArgs>),
    Info(AppInfoArgs),
}

#[derive(Args, Debug)]
struct RotateArgs {
    #[command(subcommand)]
    command: RotateCommand,

    /// Path to state.json
    #[arg(long)]
    state_file: Option<PathBuf>,

    /// Path to docker-compose.yml
    #[arg(long, default_value = DEFAULT_COMPOSE_FILE)]
    compose_file: PathBuf,

    /// `OpenBao` API URL override
    #[arg(long)]
    openbao_url: Option<String>,

    /// `OpenBao` KV mount path override (KV v2)
    #[arg(long)]
    kv_mount: Option<String>,

    /// Secrets directory override
    #[arg(long)]
    secrets_dir: Option<PathBuf>,

    /// `OpenBao` root token
    #[arg(long, env = "OPENBAO_ROOT_TOKEN")]
    root_token: Option<String>,

    /// Skip confirmation prompts
    #[arg(long)]
    yes: bool,
}

#[derive(Subcommand, Debug)]
enum RotateCommand {
    StepcaPassword(RotateStepcaPasswordArgs),
    Eab(RotateEabArgs),
    Db(RotateDbArgs),
    ResponderHmac(RotateResponderHmacArgs),
    #[command(name = "approle-secret-id")]
    AppRoleSecretId(RotateAppRoleSecretIdArgs),
}

#[derive(Args, Debug)]
struct RotateStepcaPasswordArgs {
    /// New step-ca key password
    #[arg(long)]
    new_password: Option<String>,
}

#[derive(Args, Debug)]
struct RotateEabArgs {
    /// step-ca URL for EAB issuance
    #[arg(long, default_value = DEFAULT_STEPCA_URL)]
    stepca_url: String,

    /// step-ca ACME provisioner name
    #[arg(long, default_value = DEFAULT_STEPCA_PROVISIONER)]
    stepca_provisioner: String,
}

#[derive(Args, Debug)]
struct RotateDbArgs {
    /// `PostgreSQL` admin DSN for rotation
    #[arg(long = "db-admin-dsn", env = "BOOTROOT_DB_ADMIN_DSN")]
    admin_dsn: Option<String>,

    /// New database password
    #[arg(long = "db-password", env = "BOOTROOT_DB_PASSWORD")]
    password: Option<String>,

    /// DB connectivity timeout in seconds
    #[arg(long = "db-timeout-secs", default_value_t = 2)]
    timeout_secs: u64,
}

#[derive(Args, Debug)]
struct RotateResponderHmacArgs {
    /// New responder HMAC
    #[arg(long)]
    hmac: Option<String>,
}

#[derive(Args, Debug)]
struct RotateAppRoleSecretIdArgs {
    /// App service name to rotate the `AppRole` `secret_id` for
    #[arg(long)]
    service_name: String,
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

    /// `OpenBao` API URL for auto-unseal (dev/test only)
    #[arg(long, default_value = DEFAULT_OPENBAO_URL)]
    openbao_url: String,

    /// Auto-unseal `OpenBao` from file (dev/test only)
    #[arg(long, env = "OPENBAO_UNSEAL_FILE")]
    openbao_unseal_from_file: Option<PathBuf>,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
// CLI flags intentionally expose independent toggles for init behavior.
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

    /// Auto-unseal `OpenBao` from file (dev/test only)
    #[arg(long, env = "OPENBAO_UNSEAL_FILE")]
    openbao_unseal_from_file: Option<PathBuf>,

    /// step-ca password (password.txt)
    #[arg(long, env = "STEPCA_PASSWORD")]
    stepca_password: Option<String>,

    /// `PostgreSQL` DSN for step-ca
    #[arg(long)]
    db_dsn: Option<String>,

    /// Provision `PostgreSQL` role/database for step-ca
    #[arg(long)]
    db_provision: bool,

    /// `PostgreSQL` admin DSN for provisioning
    #[arg(long, env = "BOOTROOT_DB_ADMIN_DSN")]
    db_admin_dsn: Option<String>,

    /// `PostgreSQL` user for step-ca
    #[arg(long, env = "BOOTROOT_DB_USER")]
    db_user: Option<String>,

    /// `PostgreSQL` password for step-ca
    #[arg(long, env = "BOOTROOT_DB_PASSWORD")]
    db_password: Option<String>,

    /// `PostgreSQL` database name for step-ca
    #[arg(long, env = "BOOTROOT_DB_NAME")]
    db_name: Option<String>,

    /// Validate DB DSN connectivity and auth
    #[arg(long)]
    db_check: bool,

    /// DB connectivity timeout in seconds
    #[arg(long, default_value_t = 2)]
    db_timeout_secs: u64,

    /// HTTP-01 responder HMAC secret
    #[arg(long, env = "HTTP01_HMAC")]
    http_hmac: Option<String>,

    /// HTTP-01 responder admin URL (optional)
    #[arg(long, env = "HTTP01_RESPONDER_URL")]
    responder_url: Option<String>,

    /// Skip HTTP-01 responder check during init
    #[arg(long)]
    skip_responder_check: bool,

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
    /// Service name identifier
    #[arg(long)]
    service_name: Option<String>,

    /// Deployment type (daemon or docker)
    #[arg(long, value_enum)]
    deploy_type: Option<DeployType>,

    /// Hostname used for DNS SAN
    #[arg(long)]
    hostname: Option<String>,

    /// DNS domain for SAN construction
    #[arg(long)]
    domain: Option<String>,

    /// bootroot-agent config path
    #[arg(long)]
    agent_config: Option<PathBuf>,

    /// Certificate output path
    #[arg(long)]
    cert_path: Option<PathBuf>,

    /// Private key output path
    #[arg(long)]
    key_path: Option<PathBuf>,

    /// Instance ID (required for daemon and docker)
    #[arg(long)]
    instance_id: Option<String>,

    /// Container name (required for docker)
    #[arg(long)]
    container_name: Option<String>,

    /// `OpenBao` root token
    #[arg(long, env = "OPENBAO_ROOT_TOKEN")]
    root_token: Option<String>,

    /// Freeform notes (optional)
    #[arg(long)]
    notes: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct AppInfoArgs {
    /// Service name identifier
    #[arg(long, required = true)]
    service_name: String,
}

#[derive(Args, Debug)]
pub(crate) struct VerifyArgs {
    /// Service name identifier
    #[arg(long)]
    service_name: Option<String>,

    /// bootroot-agent config path override
    #[arg(long)]
    agent_config: Option<PathBuf>,

    /// Verify DB connectivity and auth using ca.json DSN
    #[arg(long)]
    db_check: bool,

    /// DB connectivity timeout in seconds
    #[arg(long, default_value_t = 2)]
    db_timeout_secs: u64,
}

fn main() {
    let cli = Cli::parse();
    let messages = match Messages::new(&cli.lang) {
        Ok(messages) => messages,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(1);
        }
    };
    if let Err(err) = run(cli, &messages) {
        let message = err
            .chain()
            .next()
            .map_or_else(|| "bootroot error".to_string(), ToString::to_string);
        eprintln!("{message}");
        if let Some(detail) = err.chain().nth(1) {
            eprintln!("{}", messages.error_details(&detail.to_string()));
        }
        std::process::exit(1);
    }
}

fn run(cli: Cli, messages: &Messages) -> Result<()> {
    match cli.command {
        CliCommand::Infra(InfraCommand::Up(args)) => {
            commands::infra::run_infra_up(&args, messages)
                .with_context(|| messages.error_infra_failed())?;
        }
        CliCommand::Init(args) => {
            let runtime = tokio::runtime::Runtime::new()
                .with_context(|| messages.error_runtime_init_failed("init"))?;
            runtime
                .block_on(commands::init::run_init(&args, messages))
                .with_context(|| messages.error_init_failed())?;
        }
        CliCommand::Status(args) => {
            let runtime = tokio::runtime::Runtime::new()
                .with_context(|| messages.error_runtime_init_failed("status"))?;
            runtime
                .block_on(commands::status::run_status(&args, messages))
                .with_context(|| messages.error_status_failed())?;
        }
        CliCommand::App(AppCommand::Add(args)) => {
            let runtime = tokio::runtime::Runtime::new()
                .with_context(|| messages.error_runtime_init_failed("app add"))?;
            runtime
                .block_on(commands::app::run_app_add(&args, messages))
                .with_context(|| messages.error_app_add_failed())?;
        }
        CliCommand::App(AppCommand::Info(args)) => {
            commands::app::run_app_info(&args, messages)
                .with_context(|| messages.error_app_info_failed())?;
        }
        CliCommand::Verify(args) => commands::verify::run_verify(&args, messages)
            .with_context(|| messages.error_verify_failed())?,
        CliCommand::Rotate(args) => {
            let runtime = tokio::runtime::Runtime::new()
                .with_context(|| messages.error_runtime_init_failed("rotate"))?;
            runtime
                .block_on(commands::rotate::run_rotate(&args, messages))
                .with_context(|| messages.error_rotate_failed())?;
        }
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

    #[test]
    fn test_cli_parses_rotate_stepca() {
        let cli = Cli::parse_from(["bootroot", "rotate", "stepca-password"]);
        assert!(matches!(cli.command, CliCommand::Rotate(_)));
    }

    #[test]
    fn test_cli_parses_rotate_approle_secret_id() {
        let cli = Cli::parse_from([
            "bootroot",
            "rotate",
            "approle-secret-id",
            "--service-name",
            "api",
        ]);
        assert!(matches!(cli.command, CliCommand::Rotate(_)));
    }
}
