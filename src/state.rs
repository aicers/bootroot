use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

const DEFAULT_SECRETS_DIR: &str = "secrets";
pub(crate) const STATE_FILE_NAME: &str = "state.json";
const STEPCA_ROOT_KEY: &str = "secrets/root_ca_key";
const STEPCA_INTERMEDIATE_KEY: &str = "secrets/intermediate_ca_key";
const STEPCA_PASSWORD_FILE: &str = "password.txt";
const RESPONDER_CONFIG_PATH: &str = "responder/responder.toml";
const CA_JSON_PATH: &str = "config/ca.json";

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
    pub(crate) apps: BTreeMap<String, AppEntry>,
}

impl StateFile {
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

    pub(crate) fn default_path() -> PathBuf {
        PathBuf::from(STATE_FILE_NAME)
    }

    pub(crate) fn paths(&self) -> StatePaths {
        StatePaths {
            secrets_dir: self.secrets_dir(),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct StatePaths {
    secrets_dir: PathBuf,
}

impl StatePaths {
    pub(crate) fn stepca_password_path(&self) -> PathBuf {
        self.secrets_dir.join(STEPCA_PASSWORD_FILE)
    }

    pub(crate) fn stepca_root_key_path(&self) -> PathBuf {
        self.secrets_dir.join(STEPCA_ROOT_KEY)
    }

    pub(crate) fn stepca_intermediate_key_path(&self) -> PathBuf {
        self.secrets_dir.join(STEPCA_INTERMEDIATE_KEY)
    }

    pub(crate) fn responder_config_path(&self) -> PathBuf {
        self.secrets_dir.join(RESPONDER_CONFIG_PATH)
    }

    pub(crate) fn ca_json_path(&self) -> PathBuf {
        self.secrets_dir.join(CA_JSON_PATH)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct AppEntry {
    pub(crate) service_name: String,
    pub(crate) deploy_type: DeployType,
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
    pub(crate) approle: AppRoleEntry,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct AppRoleEntry {
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
