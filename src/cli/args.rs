use std::path::PathBuf;

use clap::ValueEnum;
use clap::{Args, Parser, Subcommand};

use crate::commands::init::{
    DEFAULT_COMPOSE_FILE, DEFAULT_KV_MOUNT, DEFAULT_OPENBAO_URL, DEFAULT_SECRETS_DIR,
    DEFAULT_STEPCA_PROVISIONER, DEFAULT_STEPCA_URL,
};
use crate::state::{DeliveryMode, DeployType};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Cli {
    /// Language for CLI output (en or ko)
    #[arg(long, env = "BOOTROOT_LANG", default_value = "en", global = true)]
    pub(crate) lang: String,

    #[command(subcommand)]
    pub(crate) command: CliCommand,
}

#[derive(Subcommand, Debug)]
pub(crate) enum CliCommand {
    #[command(subcommand)]
    Infra(InfraCommand),
    #[command(subcommand)]
    Monitoring(MonitoringCommand),
    Init(Box<InitArgs>),
    Status(Box<StatusArgs>),
    #[command(subcommand)]
    Service(ServiceCommand),
    Verify(VerifyArgs),
    Rotate(RotateArgs),
}

#[derive(Subcommand, Debug)]
pub(crate) enum InfraCommand {
    Up(InfraUpArgs),
}

#[derive(Subcommand, Debug)]
pub(crate) enum MonitoringCommand {
    Up(MonitoringUpArgs),
    Status(MonitoringStatusArgs),
    Down(MonitoringDownArgs),
}

#[derive(Subcommand, Debug)]
pub(crate) enum ServiceCommand {
    Add(Box<ServiceAddArgs>),
    Info(ServiceInfoArgs),
}

#[derive(Args, Debug, Clone)]
pub(crate) struct OpenBaoArgs {
    /// `OpenBao` API URL
    #[arg(long, default_value = DEFAULT_OPENBAO_URL)]
    pub(crate) openbao_url: String,

    /// `OpenBao` KV mount path (KV v2)
    #[arg(long, default_value = DEFAULT_KV_MOUNT)]
    pub(crate) kv_mount: String,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct OpenBaoOverrideArgs {
    /// `OpenBao` API URL override
    #[arg(long)]
    pub(crate) openbao_url: Option<String>,

    /// `OpenBao` KV mount path override (KV v2)
    #[arg(long)]
    pub(crate) kv_mount: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct ComposeFileArgs {
    /// Path to docker-compose.yml
    #[arg(long, default_value = DEFAULT_COMPOSE_FILE)]
    pub(crate) compose_file: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct SecretsDirArgs {
    /// Secrets directory to render files into
    #[arg(long, default_value = DEFAULT_SECRETS_DIR)]
    pub(crate) secrets_dir: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct SecretsDirOverrideArgs {
    /// Secrets directory override
    #[arg(long)]
    pub(crate) secrets_dir: Option<PathBuf>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct RootTokenArgs {
    /// `OpenBao` root token
    #[arg(long, env = "OPENBAO_ROOT_TOKEN")]
    pub(crate) root_token: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct DbAdminDsnArgs {
    /// `PostgreSQL` admin DSN for provisioning
    #[arg(long = "db-admin-dsn", env = "BOOTROOT_DB_ADMIN_DSN")]
    pub(crate) admin_dsn: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub(crate) struct DbTimeoutArgs {
    /// DB connectivity timeout in seconds
    #[arg(long = "db-timeout-secs", default_value_t = 2)]
    pub(crate) timeout_secs: u64,
}

#[derive(Args, Debug)]
pub(crate) struct RotateArgs {
    #[command(subcommand)]
    pub(crate) command: RotateCommand,

    /// Path to state.json
    #[arg(long)]
    pub(crate) state_file: Option<PathBuf>,

    #[command(flatten)]
    pub(crate) compose: ComposeFileArgs,

    #[command(flatten)]
    pub(crate) openbao: OpenBaoOverrideArgs,

    #[command(flatten)]
    pub(crate) secrets_dir: SecretsDirOverrideArgs,

    #[command(flatten)]
    pub(crate) root_token: RootTokenArgs,

    /// Skip confirmation prompts
    #[arg(long)]
    pub(crate) yes: bool,
}

#[derive(Subcommand, Debug)]
pub(crate) enum RotateCommand {
    StepcaPassword(RotateStepcaPasswordArgs),
    Eab(RotateEabArgs),
    Db(RotateDbArgs),
    ResponderHmac(RotateResponderHmacArgs),
    #[command(name = "approle-secret-id")]
    AppRoleSecretId(RotateAppRoleSecretIdArgs),
}

#[derive(Args, Debug)]
pub(crate) struct RotateStepcaPasswordArgs {
    /// New step-ca key password
    #[arg(long)]
    pub(crate) new_password: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct RotateEabArgs {
    /// step-ca URL for EAB issuance
    #[arg(long, default_value = DEFAULT_STEPCA_URL)]
    pub(crate) stepca_url: String,

    /// step-ca ACME provisioner name
    #[arg(long, default_value = DEFAULT_STEPCA_PROVISIONER)]
    pub(crate) stepca_provisioner: String,
}

#[derive(Args, Debug)]
pub(crate) struct RotateDbArgs {
    #[command(flatten)]
    pub(crate) admin_dsn: DbAdminDsnArgs,

    /// New database password
    #[arg(long = "db-password", env = "BOOTROOT_DB_PASSWORD")]
    pub(crate) password: Option<String>,

    #[command(flatten)]
    pub(crate) timeout: DbTimeoutArgs,
}

#[derive(Args, Debug)]
pub(crate) struct RotateResponderHmacArgs {
    /// New responder HMAC
    #[arg(long)]
    pub(crate) hmac: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct RotateAppRoleSecretIdArgs {
    /// App service name to rotate the `AppRole` `secret_id` for
    #[arg(long)]
    pub(crate) service_name: String,
}

#[derive(Args, Debug)]
pub(crate) struct InfraUpArgs {
    /// Path to docker-compose.yml
    #[arg(long, default_value = "docker-compose.yml")]
    pub(crate) compose_file: PathBuf,

    /// Comma-separated list of services to start
    #[arg(
        long,
        default_value = "openbao,postgres,step-ca,bootroot-http01",
        value_delimiter = ','
    )]
    pub(crate) services: Vec<String>,

    /// Directory containing local image archives (optional)
    #[arg(long)]
    pub(crate) image_archive_dir: Option<PathBuf>,

    /// Docker restart policy to apply after containers start
    #[arg(long, default_value = "always")]
    pub(crate) restart_policy: String,

    /// `OpenBao` API URL for auto-unseal (dev/test only)
    #[arg(long, default_value = DEFAULT_OPENBAO_URL)]
    pub(crate) openbao_url: String,

    /// Auto-unseal `OpenBao` from file (dev/test only)
    #[arg(long, env = "OPENBAO_UNSEAL_FILE")]
    pub(crate) openbao_unseal_from_file: Option<PathBuf>,
}

#[derive(ValueEnum, Debug, Clone, Copy)]
pub(crate) enum MonitoringProfile {
    Lan,
    Public,
}

impl std::fmt::Display for MonitoringProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MonitoringProfile::Lan => write!(f, "lan"),
            MonitoringProfile::Public => write!(f, "public"),
        }
    }
}

#[derive(Args, Debug)]
pub(crate) struct MonitoringUpArgs {
    /// Path to docker-compose.yml
    #[arg(long, default_value = "docker-compose.yml")]
    pub(crate) compose_file: PathBuf,

    /// Monitoring profile to start (lan or public)
    #[arg(long, value_enum, default_value_t = MonitoringProfile::Lan)]
    pub(crate) profile: MonitoringProfile,

    /// Grafana admin password override (default: admin)
    #[arg(long, env = "GRAFANA_ADMIN_PASSWORD")]
    pub(crate) grafana_admin_password: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct MonitoringStatusArgs {
    /// Path to docker-compose.yml
    #[arg(long, default_value = "docker-compose.yml")]
    pub(crate) compose_file: PathBuf,
}

#[derive(Args, Debug)]
pub(crate) struct MonitoringDownArgs {
    /// Path to docker-compose.yml
    #[arg(long, default_value = "docker-compose.yml")]
    pub(crate) compose_file: PathBuf,

    /// Reset Grafana admin password on next up
    #[arg(long)]
    pub(crate) reset_grafana_admin_password: bool,
}

#[derive(Args, Debug)]
#[allow(clippy::struct_excessive_bools)]
// CLI flags intentionally expose independent toggles for init behavior.
pub(crate) struct InitArgs {
    #[command(flatten)]
    pub(crate) openbao: OpenBaoArgs,

    #[command(flatten)]
    pub(crate) secrets_dir: SecretsDirArgs,

    #[command(flatten)]
    pub(crate) compose: ComposeFileArgs,

    /// Auto-generate secrets where possible
    #[arg(long)]
    pub(crate) auto_generate: bool,

    /// Show secrets in output summaries
    #[arg(long)]
    pub(crate) show_secrets: bool,

    #[command(flatten)]
    pub(crate) root_token: RootTokenArgs,

    /// `OpenBao` unseal key (repeatable)
    #[arg(long, env = "OPENBAO_UNSEAL_KEYS", value_delimiter = ',')]
    pub(crate) unseal_key: Vec<String>,

    /// Auto-unseal `OpenBao` from file (dev/test only)
    #[arg(long, env = "OPENBAO_UNSEAL_FILE")]
    pub(crate) openbao_unseal_from_file: Option<PathBuf>,

    /// step-ca password (password.txt)
    #[arg(long, env = "STEPCA_PASSWORD")]
    pub(crate) stepca_password: Option<String>,

    /// `PostgreSQL` DSN for step-ca
    #[arg(long)]
    pub(crate) db_dsn: Option<String>,

    /// Provision `PostgreSQL` role/database for step-ca
    #[arg(long)]
    pub(crate) db_provision: bool,

    #[command(flatten)]
    pub(crate) db_admin: DbAdminDsnArgs,

    /// `PostgreSQL` user for step-ca
    #[arg(long, env = "BOOTROOT_DB_USER")]
    pub(crate) db_user: Option<String>,

    /// `PostgreSQL` password for step-ca
    #[arg(long, env = "BOOTROOT_DB_PASSWORD")]
    pub(crate) db_password: Option<String>,

    /// `PostgreSQL` database name for step-ca
    #[arg(long, env = "BOOTROOT_DB_NAME")]
    pub(crate) db_name: Option<String>,

    /// Validate DB DSN connectivity and auth
    #[arg(long)]
    pub(crate) db_check: bool,

    #[command(flatten)]
    pub(crate) db_timeout: DbTimeoutArgs,

    /// HTTP-01 responder HMAC secret
    #[arg(long, env = "HTTP01_HMAC")]
    pub(crate) http_hmac: Option<String>,

    /// HTTP-01 responder admin URL (optional)
    #[arg(long, env = "HTTP01_RESPONDER_URL")]
    pub(crate) responder_url: Option<String>,

    /// Skip HTTP-01 responder check during init
    #[arg(long)]
    pub(crate) skip_responder_check: bool,

    /// HTTP-01 responder request timeout (seconds)
    #[arg(long, default_value_t = 5)]
    pub(crate) responder_timeout_secs: u64,

    /// Auto-issue ACME EAB via step-ca
    #[arg(long)]
    pub(crate) eab_auto: bool,

    /// step-ca URL for EAB issuance
    #[arg(long, default_value = DEFAULT_STEPCA_URL)]
    pub(crate) stepca_url: String,

    /// step-ca ACME provisioner name
    #[arg(long, default_value = DEFAULT_STEPCA_PROVISIONER)]
    pub(crate) stepca_provisioner: String,

    /// ACME EAB key ID (optional)
    #[arg(long, env = "EAB_KID")]
    pub(crate) eab_kid: Option<String>,

    /// ACME EAB HMAC (optional)
    #[arg(long, env = "EAB_HMAC")]
    pub(crate) eab_hmac: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct StatusArgs {
    #[command(flatten)]
    pub(crate) compose: ComposeFileArgs,

    #[command(flatten)]
    pub(crate) openbao: OpenBaoArgs,

    #[command(flatten)]
    pub(crate) root_token: RootTokenArgs,
}

#[derive(Args, Debug)]
pub(crate) struct ServiceAddArgs {
    /// Service name identifier
    #[arg(long)]
    pub(crate) service_name: Option<String>,

    /// Deployment type (daemon or docker)
    #[arg(long, value_enum)]
    pub(crate) deploy_type: Option<DeployType>,

    /// Secret delivery mode (local-file or remote-bootstrap)
    #[arg(long, value_enum)]
    pub(crate) delivery_mode: Option<DeliveryMode>,

    /// Hostname used for DNS SAN
    #[arg(long)]
    pub(crate) hostname: Option<String>,

    /// DNS domain for SAN construction
    #[arg(long)]
    pub(crate) domain: Option<String>,

    /// bootroot-agent config path
    #[arg(long)]
    pub(crate) agent_config: Option<PathBuf>,

    /// Certificate output path
    #[arg(long)]
    pub(crate) cert_path: Option<PathBuf>,

    /// Private key output path
    #[arg(long)]
    pub(crate) key_path: Option<PathBuf>,

    /// Instance ID (required for daemon and docker)
    #[arg(long)]
    pub(crate) instance_id: Option<String>,

    /// Container name (required for docker)
    #[arg(long)]
    pub(crate) container_name: Option<String>,

    #[command(flatten)]
    pub(crate) root_token: RootTokenArgs,

    /// Freeform notes (optional)
    #[arg(long)]
    pub(crate) notes: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct ServiceInfoArgs {
    /// Service name identifier
    #[arg(long, required = true)]
    pub(crate) service_name: String,
}

#[derive(Args, Debug)]
pub(crate) struct VerifyArgs {
    /// Service name identifier
    #[arg(long)]
    pub(crate) service_name: Option<String>,

    /// bootroot-agent config path override
    #[arg(long)]
    pub(crate) agent_config: Option<PathBuf>,

    /// Verify DB connectivity and auth using ca.json DSN
    #[arg(long)]
    pub(crate) db_check: bool,

    #[command(flatten)]
    pub(crate) db_timeout: DbTimeoutArgs,
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

    #[test]
    fn test_cli_parses_monitoring_profile() {
        let cli = Cli::parse_from(["bootroot", "monitoring", "up", "--profile", "public"]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Up(args)) => {
                assert!(matches!(args.profile, MonitoringProfile::Public));
            }
            _ => panic!("expected monitoring up"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_delivery_mode() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--delivery-mode",
            "remote-bootstrap",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(matches!(
                    args.delivery_mode,
                    Some(DeliveryMode::RemoteBootstrap)
                ));
            }
            _ => panic!("expected service add"),
        }
    }
}
