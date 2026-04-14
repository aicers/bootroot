use std::path::PathBuf;

use clap::{ArgGroup, ValueEnum};
use clap::{Args, Parser, Subcommand};

use crate::commands::init::{
    DEFAULT_COMPOSE_FILE, DEFAULT_KV_MOUNT, DEFAULT_OPENBAO_URL, DEFAULT_SECRETS_DIR,
    DEFAULT_STEPCA_PROVISIONER, DEFAULT_STEPCA_URL, SECRET_ID_TTL,
};
use crate::state::{DeliveryMode, DeployType, HookFailurePolicyEntry};

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
    Clean(CleanArgs),
    #[command(subcommand)]
    Openbao(OpenbaoCommand),
}

#[derive(Subcommand, Debug)]
pub(crate) enum InfraCommand {
    Up(InfraUpArgs),
    Install(InfraInstallArgs),
}

#[derive(Subcommand, Debug)]
pub(crate) enum OpenbaoCommand {
    SaveUnsealKeys(OpenbaoSaveUnsealKeysArgs),
    DeleteUnsealKeys(OpenbaoDeleteUnsealKeysArgs),
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
    Update(ServiceUpdateArgs),
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

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthMode {
    Auto,
    Root,
    Approle,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReloadStyle {
    /// Send SIGHUP to a process by name
    Sighup,
    /// Reload a systemd unit
    Systemd,
    /// Restart a Docker container
    DockerRestart,
    /// No post-renew hook
    None,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HookFailurePolicyArg {
    Continue,
    Stop,
}

impl HookFailurePolicyArg {
    pub(crate) fn into_entry(self) -> HookFailurePolicyEntry {
        match self {
            Self::Continue => HookFailurePolicyEntry::Continue,
            Self::Stop => HookFailurePolicyEntry::Stop,
        }
    }
}

#[derive(Args, Debug, Clone)]
pub(crate) struct RuntimeAuthArgs {
    /// Runtime authentication mode (`auto`, `root`, `approle`)
    #[arg(long, value_enum, default_value = "auto")]
    pub(crate) auth_mode: AuthMode,

    /// `OpenBao` root token
    #[arg(long, env = "OPENBAO_ROOT_TOKEN")]
    pub(crate) root_token: Option<String>,

    /// `OpenBao` `AppRole` `role_id`
    #[arg(long, env = "OPENBAO_APPROLE_ROLE_ID")]
    pub(crate) approle_role_id: Option<String>,

    /// `OpenBao` `AppRole` `secret_id`
    #[arg(long, env = "OPENBAO_APPROLE_SECRET_ID")]
    pub(crate) approle_secret_id: Option<String>,

    /// Path to file containing `OpenBao` `AppRole` `role_id`
    #[arg(long, env = "OPENBAO_APPROLE_ROLE_ID_FILE")]
    pub(crate) approle_role_id_file: Option<PathBuf>,

    /// Path to file containing `OpenBao` `AppRole` `secret_id`
    #[arg(long, env = "OPENBAO_APPROLE_SECRET_ID_FILE")]
    pub(crate) approle_secret_id_file: Option<PathBuf>,
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
    pub(crate) runtime_auth: RuntimeAuthArgs,

    /// Skip confirmation prompts
    #[arg(long)]
    pub(crate) yes: bool,

    /// Show secrets in plaintext instead of masking them
    #[arg(long)]
    pub(crate) show_secrets: bool,
}

#[derive(Subcommand, Debug)]
pub(crate) enum RotateCommand {
    StepcaPassword(RotateStepcaPasswordArgs),
    Eab(RotateEabArgs),
    Db(RotateDbArgs),
    ResponderHmac(RotateResponderHmacArgs),
    /// Rotates `OpenBao` recovery credentials manually.
    ///
    /// `--rotate-unseal-keys` requires existing unseal keys. The operator must
    /// provide at least the configured unseal threshold number of key shares
    /// (for example, 3 of 5). If existing unseal keys are lost, unseal key
    /// rotation is impossible and the operator must re-initialize `OpenBao`
    /// (which implies re-running `bootroot init` and re-bootstrapping
    /// services).
    ///
    /// `--rotate-root-token` can run without unseal key input.
    #[command(name = "openbao-recovery")]
    OpenBaoRecovery(RotateOpenBaoRecoveryArgs),
    #[command(name = "approle-secret-id")]
    AppRoleSecretId(RotateAppRoleSecretIdArgs),
    #[command(name = "trust-sync")]
    TrustSync(RotateTrustSyncArgs),
    #[command(name = "force-reissue")]
    ForceReissue(RotateForceReissueArgs),
    #[command(name = "ca-key")]
    CaKey(RotateCaKeyArgs),
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
#[command(
    group(
        ArgGroup::new("recovery_targets")
            .required(true)
            .multiple(true)
            .args(["rotate_unseal_keys", "rotate_root_token"])
    )
)]
pub(crate) struct RotateOpenBaoRecoveryArgs {
    /// Rotates unseal keys via rekey.
    ///
    /// Requires existing unseal keys. Provide at least the configured unseal
    /// threshold number of key shares. If those keys are lost, this rotation
    /// cannot proceed.
    #[arg(long)]
    pub(crate) rotate_unseal_keys: bool,

    /// Rotates `OpenBao` root token.
    ///
    /// Does not require unseal key input.
    #[arg(long)]
    pub(crate) rotate_root_token: bool,

    /// Supplies existing unseal key(s), repeat for multiple keys.
    ///
    /// Used only with `--rotate-unseal-keys`.
    #[arg(long)]
    pub(crate) unseal_key: Vec<String>,

    /// Supplies a file with existing unseal keys (one key per line).
    ///
    /// Used only with `--rotate-unseal-keys`.
    #[arg(long)]
    pub(crate) unseal_key_file: Option<PathBuf>,

    /// Output path for newly generated recovery credentials
    #[arg(long)]
    pub(crate) output: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(crate) struct RotateAppRoleSecretIdArgs {
    /// App service name to rotate the `AppRole` `secret_id` for
    #[arg(long)]
    pub(crate) service_name: String,
}

#[derive(Args, Debug)]
pub(crate) struct RotateTrustSyncArgs {}

#[derive(Args, Debug)]
pub(crate) struct RotateForceReissueArgs {
    /// Service name to force-reissue certificates for
    #[arg(long)]
    pub(crate) service_name: String,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotateSkipPhase {
    /// Skip service certificate re-issuance (Phase 5)
    Reissue,
    /// Skip trust finalization (Phase 6)
    Finalize,
}

#[derive(Args, Debug)]
pub(crate) struct RotateCaKeyArgs {
    /// Rotate both root and intermediate CA keys (full rotation)
    #[arg(long)]
    pub(crate) full: bool,
    /// Skip specific rotation phases
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) skip: Vec<RotateSkipPhase>,
    /// Force finalization even with un-migrated services
    #[arg(long)]
    pub(crate) force: bool,
    /// Delete backup files on completion
    #[arg(long)]
    pub(crate) cleanup: bool,
}

#[derive(Args, Debug)]
pub(crate) struct InfraUpArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

    /// Comma-separated list of services to start
    // Keep "bootroot-http01" in sync with RESPONDER_SERVICE_NAME.
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

#[derive(Args, Debug)]
pub(crate) struct InfraInstallArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

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

    /// `OpenBao` API URL
    #[arg(long, default_value = DEFAULT_OPENBAO_URL)]
    pub(crate) openbao_url: String,
}

#[derive(Args, Debug)]
pub(crate) struct CleanArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

    /// Skip confirmation prompts
    #[arg(long, short)]
    pub(crate) yes: bool,
}

#[derive(Args, Debug)]
pub(crate) struct OpenbaoSaveUnsealKeysArgs {
    /// Secrets directory
    #[arg(long, default_value = DEFAULT_SECRETS_DIR)]
    pub(crate) secrets_dir: PathBuf,
}

#[derive(Args, Debug)]
pub(crate) struct OpenbaoDeleteUnsealKeysArgs {
    /// Secrets directory
    #[arg(long, default_value = DEFAULT_SECRETS_DIR)]
    pub(crate) secrets_dir: PathBuf,
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
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

    /// Monitoring profile to start (lan or public)
    #[arg(long, value_enum, default_value_t = MonitoringProfile::Lan)]
    pub(crate) profile: MonitoringProfile,

    /// Grafana admin password override (default: admin)
    #[arg(long, env = "GRAFANA_ADMIN_PASSWORD")]
    pub(crate) grafana_admin_password: Option<String>,
}

#[derive(Args, Debug)]
pub(crate) struct MonitoringStatusArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,
}

#[derive(Args, Debug)]
pub(crate) struct MonitoringDownArgs {
    #[command(flatten)]
    pub(crate) compose_file: ComposeFileArgs,

    /// Reset Grafana admin password on next up
    #[arg(long)]
    pub(crate) reset_grafana_admin_password: bool,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitFeature {
    /// Auto-generate secrets where possible
    AutoGenerate,
    /// Show secrets in output summaries
    ShowSecrets,
    /// Provision `PostgreSQL` role/database for step-ca
    DbProvision,
    /// Validate DB DSN connectivity and auth
    DbCheck,
    /// Auto-issue ACME EAB via step-ca
    EabAuto,
}

#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InitSkipPhase {
    /// Skip HTTP-01 responder check during init
    ResponderCheck,
}

#[derive(Args, Debug)]
pub(crate) struct InitArgs {
    #[command(flatten)]
    pub(crate) openbao: OpenBaoArgs,

    #[command(flatten)]
    pub(crate) secrets_dir: SecretsDirArgs,

    #[command(flatten)]
    pub(crate) compose: ComposeFileArgs,

    /// Enable optional features
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) enable: Vec<InitFeature>,

    /// Skip optional checks
    #[arg(long, value_enum, value_delimiter = ',')]
    pub(crate) skip: Vec<InitSkipPhase>,

    /// Path to init summary JSON file
    #[arg(long = "summary-json")]
    pub(crate) summary_json: Option<PathBuf>,

    #[command(flatten)]
    pub(crate) root_token: RootTokenArgs,

    /// `OpenBao` unseal key (repeatable)
    #[arg(long, env = "OPENBAO_UNSEAL_KEYS", value_delimiter = ',')]
    pub(crate) unseal_key: Vec<String>,

    /// Auto-unseal `OpenBao` from file (dev/test only)
    #[arg(long, env = "OPENBAO_UNSEAL_FILE")]
    pub(crate) openbao_unseal_from_file: Option<PathBuf>,

    /// Role-level `secret_id` TTL for `AppRole` roles created during init.
    /// Set this to at least 2× your planned rotation interval so that a
    /// missed or delayed run does not expire credentials
    #[arg(long, default_value = SECRET_ID_TTL)]
    pub(crate) secret_id_ttl: String,

    /// step-ca password (password.txt)
    #[arg(long, env = "STEPCA_PASSWORD")]
    pub(crate) stepca_password: Option<String>,

    /// `PostgreSQL` DSN for step-ca
    #[arg(long)]
    pub(crate) db_dsn: Option<String>,

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

    #[command(flatten)]
    pub(crate) db_timeout: DbTimeoutArgs,

    /// HTTP-01 responder HMAC secret
    #[arg(long, env = "HTTP01_HMAC")]
    pub(crate) http_hmac: Option<String>,

    /// HTTP-01 responder admin URL (optional)
    #[arg(long, env = "HTTP01_RESPONDER_URL")]
    pub(crate) responder_url: Option<String>,

    /// HTTP-01 responder request timeout (seconds)
    #[arg(long, default_value_t = 5)]
    pub(crate) responder_timeout_secs: u64,

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

impl InitArgs {
    pub(crate) fn has_feature(&self, feature: InitFeature) -> bool {
        self.enable.contains(&feature)
    }

    pub(crate) fn has_skip(&self, phase: InitSkipPhase) -> bool {
        self.skip.contains(&phase)
    }
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

    /// Preview changes without writing files or state
    #[arg(long)]
    pub(crate) dry_run: bool,

    /// Print manual snippets only without writing files or state
    #[arg(long)]
    pub(crate) print_only: bool,

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
    pub(crate) runtime_auth: RuntimeAuthArgs,

    /// Freeform notes (optional)
    #[arg(long)]
    pub(crate) notes: Option<String>,

    /// Reload style preset for post-renew hook
    #[arg(long, value_enum)]
    pub(crate) reload_style: Option<ReloadStyle>,

    /// Target for reload-style preset (unit name, process name, or container)
    #[arg(long)]
    pub(crate) reload_target: Option<String>,

    /// Post-renew success hook command (low-level)
    #[arg(long)]
    pub(crate) post_renew_command: Option<String>,

    /// Post-renew success hook argument (repeatable, low-level)
    #[arg(long)]
    pub(crate) post_renew_arg: Vec<String>,

    /// Post-renew success hook timeout in seconds (low-level)
    #[arg(long)]
    pub(crate) post_renew_timeout_secs: Option<u64>,

    /// Post-renew success hook failure policy (low-level)
    #[arg(long, value_enum)]
    pub(crate) post_renew_on_failure: Option<HookFailurePolicyArg>,

    /// TTL for the generated `secret_id` (inherits role default when omitted).
    /// Should be at least 2× the rotation interval
    #[arg(long)]
    pub(crate) secret_id_ttl: Option<String>,

    /// Response-wrapping TTL for the `secret_id` [default: 30m]
    #[arg(long)]
    pub(crate) secret_id_wrap_ttl: Option<String>,

    /// Disable response wrapping for the `secret_id`
    #[arg(long, conflicts_with = "secret_id_wrap_ttl")]
    pub(crate) no_wrap: bool,
}

#[derive(Args, Debug)]
pub(crate) struct ServiceInfoArgs {
    /// Service name identifier
    #[arg(long, required = true)]
    pub(crate) service_name: String,
}

#[derive(Args, Debug)]
pub(crate) struct ServiceUpdateArgs {
    /// Service name identifier
    #[arg(long, required = true)]
    pub(crate) service_name: String,

    /// TTL for the generated `secret_id` (use "inherit" to clear override).
    /// Should be at least 2× the rotation interval
    #[arg(long)]
    pub(crate) secret_id_ttl: Option<String>,

    /// Response-wrapping TTL for the `secret_id` (use "inherit" to restore
    /// the default wrapping behavior)
    #[arg(long, conflicts_with = "no_wrap")]
    pub(crate) secret_id_wrap_ttl: Option<String>,

    /// Disable response wrapping for the `secret_id`
    #[arg(long, conflicts_with = "secret_id_wrap_ttl")]
    pub(crate) no_wrap: bool,
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
    fn test_cli_parses_rotate_ca_key_flags() {
        let cli = Cli::parse_from([
            "bootroot",
            "rotate",
            "ca-key",
            "--skip",
            "reissue",
            "--force",
            "--cleanup",
        ]);
        match cli.command {
            CliCommand::Rotate(args) => match args.command {
                RotateCommand::CaKey(ca) => {
                    assert!(!ca.full);
                    assert!(ca.skip.contains(&RotateSkipPhase::Reissue));
                    assert!(!ca.skip.contains(&RotateSkipPhase::Finalize));
                    assert!(ca.force);
                    assert!(ca.cleanup);
                }
                _ => panic!("expected CaKey subcommand"),
            },
            _ => panic!("expected Rotate command"),
        }
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
    fn test_cli_parses_rotate_openbao_recovery() {
        let cli = Cli::parse_from([
            "bootroot",
            "rotate",
            "openbao-recovery",
            "--rotate-unseal-keys",
            "--rotate-root-token",
            "--unseal-key",
            "key-1",
            "--unseal-key",
            "key-2",
            "--output",
            "secrets/openbao-recovery.json",
        ]);
        match cli.command {
            CliCommand::Rotate(args) => match args.command {
                RotateCommand::OpenBaoRecovery(openbao_recovery) => {
                    assert!(openbao_recovery.rotate_unseal_keys);
                    assert!(openbao_recovery.rotate_root_token);
                    assert_eq!(openbao_recovery.unseal_key, vec!["key-1", "key-2"]);
                    assert_eq!(
                        openbao_recovery.output,
                        Some(PathBuf::from("secrets/openbao-recovery.json"))
                    );
                }
                _ => panic!("expected OpenBaoRecovery subcommand"),
            },
            _ => panic!("expected Rotate command"),
        }
    }

    #[test]
    fn test_cli_rejects_rotate_openbao_recovery_without_target() {
        let result = Cli::try_parse_from(["bootroot", "rotate", "openbao-recovery"]);
        assert!(result.is_err(), "expected clap validation error");
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

    #[test]
    fn test_cli_parses_service_add_print_only_flags() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--print-only",
            "--dry-run",
            "--service-name",
            "edge-proxy",
            "--deploy-type",
            "daemon",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            "agent.toml",
            "--cert-path",
            "certs/edge-proxy.crt",
            "--key-path",
            "certs/edge-proxy.key",
            "--instance-id",
            "001",
            "--root-token",
            "root-token",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(args.print_only);
                assert!(args.dry_run);
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_init_summary_json() {
        let cli = Cli::parse_from(["bootroot", "init", "--summary-json", "init-summary.json"]);
        match cli.command {
            CliCommand::Init(args) => {
                assert_eq!(args.summary_json, Some(PathBuf::from("init-summary.json")));
            }
            _ => panic!("expected init"),
        }
    }

    #[test]
    fn test_cli_parses_infra_install() {
        let cli = Cli::parse_from([
            "bootroot",
            "infra",
            "install",
            "--services",
            "openbao,postgres",
        ]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Install(args)) => {
                assert_eq!(args.services, vec!["openbao", "postgres"]);
            }
            _ => panic!("expected infra install"),
        }
    }

    #[test]
    fn test_cli_parses_clean() {
        let cli = Cli::parse_from(["bootroot", "clean", "--yes"]);
        match cli.command {
            CliCommand::Clean(args) => {
                assert!(args.yes);
            }
            _ => panic!("expected clean"),
        }
    }

    #[test]
    fn test_cli_parses_clean_short_yes() {
        let cli = Cli::parse_from(["bootroot", "clean", "-y"]);
        match cli.command {
            CliCommand::Clean(args) => {
                assert!(args.yes);
            }
            _ => panic!("expected clean"),
        }
    }

    #[test]
    fn test_cli_parses_openbao_save_unseal_keys() {
        let cli = Cli::parse_from(["bootroot", "openbao", "save-unseal-keys"]);
        assert!(matches!(
            cli.command,
            CliCommand::Openbao(OpenbaoCommand::SaveUnsealKeys(_))
        ));
    }

    #[test]
    fn test_cli_parses_openbao_delete_unseal_keys() {
        let cli = Cli::parse_from(["bootroot", "openbao", "delete-unseal-keys"]);
        assert!(matches!(
            cli.command,
            CliCommand::Openbao(OpenbaoCommand::DeleteUnsealKeys(_))
        ));
    }

    #[test]
    fn test_infra_up_compose_file_default() {
        let cli = Cli::parse_from(["bootroot", "infra", "up"]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Up(args)) => {
                assert_eq!(
                    args.compose_file.compose_file,
                    PathBuf::from("docker-compose.yml")
                );
            }
            _ => panic!("expected infra up"),
        }
    }

    #[test]
    fn test_infra_up_compose_file_custom() {
        let cli = Cli::parse_from(["bootroot", "infra", "up", "--compose-file", "custom.yml"]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Up(args)) => {
                assert_eq!(args.compose_file.compose_file, PathBuf::from("custom.yml"));
            }
            _ => panic!("expected infra up"),
        }
    }

    #[test]
    fn test_monitoring_up_compose_file_default() {
        let cli = Cli::parse_from(["bootroot", "monitoring", "up"]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Up(args)) => {
                assert_eq!(
                    args.compose_file.compose_file,
                    PathBuf::from("docker-compose.yml")
                );
            }
            _ => panic!("expected monitoring up"),
        }
    }

    #[test]
    fn test_monitoring_up_compose_file_custom() {
        let cli = Cli::parse_from([
            "bootroot",
            "monitoring",
            "up",
            "--compose-file",
            "custom.yml",
        ]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Up(args)) => {
                assert_eq!(args.compose_file.compose_file, PathBuf::from("custom.yml"));
            }
            _ => panic!("expected monitoring up"),
        }
    }

    #[test]
    fn test_monitoring_status_compose_file_default() {
        let cli = Cli::parse_from(["bootroot", "monitoring", "status"]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Status(args)) => {
                assert_eq!(
                    args.compose_file.compose_file,
                    PathBuf::from("docker-compose.yml")
                );
            }
            _ => panic!("expected monitoring status"),
        }
    }

    #[test]
    fn test_monitoring_status_compose_file_custom() {
        let cli = Cli::parse_from([
            "bootroot",
            "monitoring",
            "status",
            "--compose-file",
            "custom.yml",
        ]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Status(args)) => {
                assert_eq!(args.compose_file.compose_file, PathBuf::from("custom.yml"));
            }
            _ => panic!("expected monitoring status"),
        }
    }

    #[test]
    fn test_monitoring_down_compose_file_default() {
        let cli = Cli::parse_from(["bootroot", "monitoring", "down"]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Down(args)) => {
                assert_eq!(
                    args.compose_file.compose_file,
                    PathBuf::from("docker-compose.yml")
                );
            }
            _ => panic!("expected monitoring down"),
        }
    }

    #[test]
    fn test_monitoring_down_compose_file_custom() {
        let cli = Cli::parse_from([
            "bootroot",
            "monitoring",
            "down",
            "--compose-file",
            "custom.yml",
        ]);
        match cli.command {
            CliCommand::Monitoring(MonitoringCommand::Down(args)) => {
                assert_eq!(args.compose_file.compose_file, PathBuf::from("custom.yml"));
            }
            _ => panic!("expected monitoring down"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_reload_style() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--reload-style",
            "systemd",
            "--reload-target",
            "nginx",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(matches!(args.reload_style, Some(ReloadStyle::Systemd)));
                assert_eq!(args.reload_target.as_deref(), Some("nginx"));
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_post_renew_low_level() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--post-renew-command",
            "systemctl",
            "--post-renew-arg",
            "reload",
            "--post-renew-arg",
            "nginx",
            "--post-renew-timeout-secs",
            "60",
            "--post-renew-on-failure",
            "stop",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert_eq!(args.post_renew_command.as_deref(), Some("systemctl"));
                assert_eq!(args.post_renew_arg, vec!["reload", "nginx"]);
                assert_eq!(args.post_renew_timeout_secs, Some(60));
                assert!(matches!(
                    args.post_renew_on_failure,
                    Some(HookFailurePolicyArg::Stop)
                ));
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_reload_style_docker_restart() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--reload-style",
            "docker-restart",
            "--reload-target",
            "my-container",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(matches!(
                    args.reload_style,
                    Some(ReloadStyle::DockerRestart)
                ));
                assert_eq!(args.reload_target.as_deref(), Some("my-container"));
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_reload_style_none() {
        let cli = Cli::parse_from(["bootroot", "service", "add", "--reload-style", "none"]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(matches!(args.reload_style, Some(ReloadStyle::None)));
                assert!(args.reload_target.is_none());
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_secret_id_defaults() {
        let cli = Cli::parse_from(["bootroot", "service", "add"]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(args.secret_id_ttl.is_none());
                assert!(args.secret_id_wrap_ttl.is_none());
                assert!(!args.no_wrap);
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_secret_id_overrides() {
        let cli = Cli::parse_from([
            "bootroot",
            "service",
            "add",
            "--secret-id-ttl",
            "1h",
            "--secret-id-wrap-ttl",
            "10m",
        ]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert_eq!(args.secret_id_ttl.as_deref(), Some("1h"));
                assert_eq!(args.secret_id_wrap_ttl.as_deref(), Some("10m"));
                assert!(!args.no_wrap);
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_parses_service_add_no_wrap() {
        let cli = Cli::parse_from(["bootroot", "service", "add", "--no-wrap"]);
        match cli.command {
            CliCommand::Service(ServiceCommand::Add(args)) => {
                assert!(args.no_wrap);
            }
            _ => panic!("expected service add"),
        }
    }

    #[test]
    fn test_cli_rejects_no_wrap_with_secret_id_wrap_ttl() {
        let result = Cli::try_parse_from([
            "bootroot",
            "service",
            "add",
            "--no-wrap",
            "--secret-id-wrap-ttl",
            "10m",
        ]);
        assert!(result.is_err());
    }
}
