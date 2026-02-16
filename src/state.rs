use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

const DEFAULT_SECRETS_DIR: &str = "secrets";
const DEFAULT_STATE_FILE: &str = "state.json";

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct StateFile {
    pub(crate) openbao_url: String,
    pub(crate) kv_mount: String,
    #[serde(default)]
    pub(crate) secrets_dir: Option<PathBuf>,
    #[serde(default)]
    pub(crate) policies: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) approles: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) services: BTreeMap<String, ServiceEntry>,
}

impl StateFile {
    pub(crate) fn default_path() -> PathBuf {
        PathBuf::from(DEFAULT_STATE_FILE)
    }

    pub(crate) fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let state: StateFile =
            serde_json::from_str(&contents).context("Failed to parse state.json")?;
        Ok(state)
    }

    pub(crate) fn save(&self, path: &Path) -> Result<()> {
        let contents =
            serde_json::to_string_pretty(self).context("Failed to serialize state.json")?;
        std::fs::write(path, contents)
            .with_context(|| format!("Failed to write {}", path.display()))
    }

    pub(crate) fn secrets_dir(&self) -> PathBuf {
        self.secrets_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from(DEFAULT_SECRETS_DIR))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ServiceEntry {
    pub(crate) service_name: String,
    pub(crate) deploy_type: DeployType,
    #[serde(default)]
    pub(crate) delivery_mode: DeliveryMode,
    #[serde(default)]
    pub(crate) sync_status: ServiceSyncStatus,
    #[serde(default)]
    pub(crate) sync_metadata: ServiceSyncMetadata,
    pub(crate) hostname: String,
    pub(crate) domain: String,
    pub(crate) agent_config_path: PathBuf,
    pub(crate) cert_path: PathBuf,
    pub(crate) key_path: PathBuf,
    #[serde(default)]
    pub(crate) instance_id: Option<String>,
    #[serde(default)]
    pub(crate) container_name: Option<String>,
    #[serde(default)]
    pub(crate) notes: Option<String>,
    pub(crate) approle: ServiceRoleEntry,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DeliveryMode {
    #[default]
    LocalFile,
    RemoteBootstrap,
}

impl DeliveryMode {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::LocalFile => "local-file",
            Self::RemoteBootstrap => "remote-bootstrap",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum SyncApplyStatus {
    #[default]
    None,
    Pending,
    Applied,
    Failed,
    Expired,
}

impl SyncApplyStatus {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Pending => "pending",
            Self::Applied => "applied",
            Self::Failed => "failed",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub(crate) struct ServiceSyncStatus {
    #[serde(default)]
    pub(crate) secret_id: SyncApplyStatus,
    #[serde(default)]
    pub(crate) eab: SyncApplyStatus,
    #[serde(default)]
    pub(crate) responder_hmac: SyncApplyStatus,
    #[serde(default)]
    pub(crate) trust_sync: SyncApplyStatus,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub(crate) struct ServiceSyncMetadata {
    #[serde(default)]
    pub(crate) secret_id: SyncTiming,
    #[serde(default)]
    pub(crate) eab: SyncTiming,
    #[serde(default)]
    pub(crate) responder_hmac: SyncTiming,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub(crate) struct SyncTiming {
    #[serde(default)]
    pub(crate) started_at_unix: Option<i64>,
    #[serde(default)]
    pub(crate) expires_at_unix: Option<i64>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ServiceRoleEntry {
    pub(crate) role_name: String,
    pub(crate) role_id: String,
    pub(crate) secret_id_path: PathBuf,
    pub(crate) policy_name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DeployType {
    Daemon,
    Docker,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_mode_defaults_to_local_file() {
        let mode = DeliveryMode::default();
        assert_eq!(mode, DeliveryMode::LocalFile);
        assert_eq!(mode.as_str(), "local-file");
    }

    #[test]
    fn sync_status_defaults_to_none() {
        let status = ServiceSyncStatus::default();
        assert_eq!(status.secret_id, SyncApplyStatus::None);
        assert_eq!(status.eab, SyncApplyStatus::None);
        assert_eq!(status.responder_hmac, SyncApplyStatus::None);
        assert_eq!(status.trust_sync, SyncApplyStatus::None);
    }

    #[test]
    fn sync_metadata_defaults_to_empty_timestamps() {
        let metadata = ServiceSyncMetadata::default();
        assert_eq!(metadata.secret_id.started_at_unix, None);
        assert_eq!(metadata.secret_id.expires_at_unix, None);
        assert_eq!(metadata.eab.started_at_unix, None);
        assert_eq!(metadata.eab.expires_at_unix, None);
        assert_eq!(metadata.responder_hmac.started_at_unix, None);
        assert_eq!(metadata.responder_hmac.expires_at_unix, None);
    }
}
