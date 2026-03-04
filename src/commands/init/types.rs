use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

use super::constants::openbao_constants::{
    APPROLE_BOOTROOT_AGENT, APPROLE_BOOTROOT_RESPONDER, APPROLE_BOOTROOT_RUNTIME_ROTATE,
    APPROLE_BOOTROOT_RUNTIME_SERVICE_ADD, APPROLE_BOOTROOT_STEPCA, POLICY_BOOTROOT_AGENT,
    POLICY_BOOTROOT_RESPONDER, POLICY_BOOTROOT_RUNTIME_ROTATE, POLICY_BOOTROOT_RUNTIME_SERVICE_ADD,
    POLICY_BOOTROOT_STEPCA,
};

/// Identifies a built-in `AppRole` created during `init`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AppRoleLabel {
    BootrootAgent,
    Responder,
    Stepca,
    RuntimeServiceAdd,
    RuntimeRotate,
}

impl AppRoleLabel {
    /// Returns all labels in a stable order.
    pub(crate) fn all() -> &'static [Self] {
        &[
            Self::BootrootAgent,
            Self::Responder,
            Self::Stepca,
            Self::RuntimeServiceAdd,
            Self::RuntimeRotate,
        ]
    }

    /// Returns the `OpenBao` policy name for this role.
    pub(crate) fn policy_name(self) -> &'static str {
        match self {
            Self::BootrootAgent => POLICY_BOOTROOT_AGENT,
            Self::Responder => POLICY_BOOTROOT_RESPONDER,
            Self::Stepca => POLICY_BOOTROOT_STEPCA,
            Self::RuntimeServiceAdd => POLICY_BOOTROOT_RUNTIME_SERVICE_ADD,
            Self::RuntimeRotate => POLICY_BOOTROOT_RUNTIME_ROTATE,
        }
    }

    /// Returns the `OpenBao` `AppRole` role name for this role.
    pub(crate) fn role_name(self) -> &'static str {
        match self {
            Self::BootrootAgent => APPROLE_BOOTROOT_AGENT,
            Self::Responder => APPROLE_BOOTROOT_RESPONDER,
            Self::Stepca => APPROLE_BOOTROOT_STEPCA,
            Self::RuntimeServiceAdd => APPROLE_BOOTROOT_RUNTIME_SERVICE_ADD,
            Self::RuntimeRotate => APPROLE_BOOTROOT_RUNTIME_ROTATE,
        }
    }

    /// Builds a label-to-role-name map for state file persistence.
    pub(crate) fn approle_map() -> BTreeMap<String, String> {
        Self::all()
            .iter()
            .map(|l| (l.to_string(), l.role_name().to_string()))
            .collect()
    }

    /// Builds a label-to-policy-name map for state file persistence.
    pub(crate) fn policy_map() -> BTreeMap<String, String> {
        Self::all()
            .iter()
            .map(|l| (l.to_string(), l.policy_name().to_string()))
            .collect()
    }
}

impl fmt::Display for AppRoleLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::BootrootAgent => "bootroot_agent",
            Self::Responder => "responder",
            Self::Stepca => "stepca",
            Self::RuntimeServiceAdd => "runtime_service_add",
            Self::RuntimeRotate => "runtime_rotate",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) enum ResponderCheck {
    Skipped,
    Ok,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub(crate) enum DbCheckStatus {
    Skipped,
    Ok,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EabCredentials {
    pub(crate) kid: String,
    pub(crate) hmac: String,
}

#[derive(Debug, Serialize)]
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

pub(super) struct OpenBaoConfigResult {
    pub(super) role_outputs: Vec<AppRoleOutput>,
    pub(super) approles: BTreeMap<String, String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct AppRoleOutput {
    pub(crate) label: AppRoleLabel,
    pub(crate) role_name: String,
    pub(crate) role_id: String,
    pub(crate) secret_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub(crate) enum StepCaInitResult {
    Initialized,
    Skipped,
}
