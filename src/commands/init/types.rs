use std::path::PathBuf;

#[derive(Debug, Clone, Copy)]
pub(crate) enum ResponderCheck {
    Skipped,
    Ok,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DbCheckStatus {
    Skipped,
    Ok,
}

#[derive(Debug, Clone)]
pub(crate) struct EabCredentials {
    pub(crate) kid: String,
    pub(crate) hmac: String,
}

pub(crate) struct InitSummary {
    pub(crate) openbao_url: String,
    pub(crate) kv_mount: String,
    pub(crate) secrets_dir: PathBuf,
    pub(crate) show_secrets: bool,
    pub(crate) init_response: bool,
    pub(crate) root_token: String,
    pub(crate) unseal_keys: Vec<String>,
    pub(crate) approles: Vec<AppRoleOutput>,
    pub(crate) stepca_password: String,
    pub(crate) db_dsn: String,
    pub(crate) db_dsn_host_original: String,
    pub(crate) db_dsn_host_effective: String,
    pub(crate) http_hmac: String,
    pub(crate) eab: Option<EabCredentials>,
    pub(crate) step_ca_result: StepCaInitResult,
    pub(crate) responder_check: ResponderCheck,
    pub(crate) responder_url: Option<String>,
    pub(crate) responder_template_path: PathBuf,
    pub(crate) responder_config_path: PathBuf,
    pub(crate) openbao_agent_stepca_config_path: PathBuf,
    pub(crate) openbao_agent_responder_config_path: PathBuf,
    pub(crate) openbao_agent_override_path: Option<PathBuf>,
    pub(crate) db_check: DbCheckStatus,
}

pub(crate) struct InitPlan {
    pub(crate) openbao_url: String,
    pub(crate) kv_mount: String,
    pub(crate) secrets_dir: PathBuf,
    pub(crate) overwrite_password: bool,
    pub(crate) overwrite_ca_json: bool,
    pub(crate) overwrite_state: bool,
}

pub(crate) struct AppRoleOutput {
    pub(crate) label: String,
    pub(crate) role_name: String,
    pub(crate) role_id: String,
    pub(crate) secret_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepCaInitResult {
    Initialized,
    Skipped,
}
