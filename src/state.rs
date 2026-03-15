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

    pub(crate) fn secrets_dir(&self) -> &Path {
        self.secrets_dir
            .as_deref()
            .unwrap_or(Path::new(DEFAULT_SECRETS_DIR))
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ServiceEntry {
    pub(crate) service_name: String,
    pub(crate) deploy_type: DeployType,
    #[serde(default)]
    pub(crate) delivery_mode: DeliveryMode,
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

impl DeployType {
    #[must_use]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Docker => "docker",
        }
    }
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
    fn deploy_type_as_str_matches_serde() {
        for variant in [DeployType::Daemon, DeployType::Docker] {
            let serialized = serde_json::to_value(variant)
                .expect("serialize DeployType")
                .as_str()
                .expect("serde value is a string")
                .to_string();
            assert_eq!(
                variant.as_str(),
                serialized,
                "as_str() and serde disagree for {variant:?}"
            );
        }
    }

    #[test]
    fn delivery_mode_as_str_matches_serde() {
        for variant in [DeliveryMode::LocalFile, DeliveryMode::RemoteBootstrap] {
            let serialized = serde_json::to_value(variant)
                .expect("serialize DeliveryMode")
                .as_str()
                .expect("serde value is a string")
                .to_string();
            assert_eq!(
                variant.as_str(),
                serialized,
                "as_str() and serde disagree for {variant:?}"
            );
        }
    }
}
