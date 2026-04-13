use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

const DEFAULT_SECRETS_DIR: &str = "secrets";
const DEFAULT_STATE_FILE: &str = "state.json";
pub(crate) const DEFAULT_HOOK_TIMEOUT_SECS: u64 = 30;

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
    #[serde(default)]
    pub(crate) post_renew_hooks: Vec<PostRenewHookEntry>,
    pub(crate) approle: ServiceRoleEntry,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DeliveryMode {
    #[default]
    LocalFile,
    RemoteBootstrap,
}

impl fmt::Display for DeliveryMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_serde_string_value(self, formatter)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct ServiceRoleEntry {
    pub(crate) role_name: String,
    pub(crate) role_id: String,
    pub(crate) secret_id_path: PathBuf,
    pub(crate) policy_name: String,
    #[serde(default)]
    pub(crate) secret_id_ttl: Option<String>,
    #[serde(default)]
    pub(crate) secret_id_num_uses: Option<u32>,
    #[serde(default)]
    pub(crate) secret_id_wrap_ttl: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DeployType {
    Daemon,
    Docker,
}

impl fmt::Display for DeployType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_serde_string_value(self, formatter)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HookFailurePolicyEntry {
    #[default]
    Continue,
    Stop,
}

impl fmt::Display for HookFailurePolicyEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_serde_string_value(self, formatter)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub(crate) struct PostRenewHookEntry {
    pub(crate) command: String,
    #[serde(default)]
    pub(crate) args: Vec<String>,
    #[serde(default = "default_hook_timeout_secs")]
    pub(crate) timeout_secs: u64,
    #[serde(default)]
    pub(crate) on_failure: HookFailurePolicyEntry,
}

fn default_hook_timeout_secs() -> u64 {
    DEFAULT_HOOK_TIMEOUT_SECS
}

fn write_serde_string_value<T: Serialize>(
    value: &T,
    formatter: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    match serde_json::to_value(value).map_err(|_| fmt::Error)? {
        serde_json::Value::String(name) => formatter.write_str(&name),
        _ => Err(fmt::Error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delivery_mode_defaults_to_local_file() {
        let mode = DeliveryMode::default();
        assert_eq!(mode, DeliveryMode::LocalFile);
        assert_eq!(mode.to_string(), "local-file");
    }

    #[test]
    fn deploy_type_display_matches_serde() {
        for variant in [DeployType::Daemon, DeployType::Docker] {
            let serialized = serde_json::to_value(variant)
                .expect("serialize DeployType")
                .as_str()
                .expect("serde value is a string")
                .to_string();
            assert_eq!(
                variant.to_string(),
                serialized,
                "Display and serde disagree for {variant:?}"
            );
        }
    }

    #[test]
    fn delivery_mode_display_matches_serde() {
        for variant in [DeliveryMode::LocalFile, DeliveryMode::RemoteBootstrap] {
            let serialized = serde_json::to_value(variant)
                .expect("serialize DeliveryMode")
                .as_str()
                .expect("serde value is a string")
                .to_string();
            assert_eq!(
                variant.to_string(),
                serialized,
                "Display and serde disagree for {variant:?}"
            );
        }
    }

    #[test]
    fn hook_failure_policy_display_matches_serde() {
        for variant in [
            HookFailurePolicyEntry::Continue,
            HookFailurePolicyEntry::Stop,
        ] {
            let serialized = serde_json::to_value(variant)
                .expect("serialize HookFailurePolicyEntry")
                .as_str()
                .expect("serde value is a string")
                .to_string();
            assert_eq!(
                variant.to_string(),
                serialized,
                "Display and serde disagree for {variant:?}"
            );
        }
    }

    #[test]
    fn post_renew_hook_entry_round_trips_json() {
        let hook = PostRenewHookEntry {
            command: "systemctl".to_string(),
            args: vec!["reload".to_string(), "nginx".to_string()],
            timeout_secs: 30,
            on_failure: HookFailurePolicyEntry::Continue,
        };
        let json = serde_json::to_string(&hook).expect("serialize");
        let parsed: PostRenewHookEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(hook, parsed);
    }

    #[test]
    fn service_entry_with_hooks_round_trips_json() {
        let entry = ServiceEntry {
            service_name: "svc".to_string(),
            deploy_type: DeployType::Daemon,
            delivery_mode: DeliveryMode::LocalFile,
            hostname: "h".to_string(),
            domain: "d.com".to_string(),
            agent_config_path: PathBuf::from("agent.toml"),
            cert_path: PathBuf::from("cert.pem"),
            key_path: PathBuf::from("key.pem"),
            instance_id: Some("001".to_string()),
            container_name: None,
            notes: None,
            post_renew_hooks: vec![PostRenewHookEntry {
                command: "pkill".to_string(),
                args: vec!["-HUP".to_string(), "nginx".to_string()],
                timeout_secs: 15,
                on_failure: HookFailurePolicyEntry::Stop,
            }],
            approle: ServiceRoleEntry {
                role_name: "r".to_string(),
                role_id: "id".to_string(),
                secret_id_path: PathBuf::from("s"),
                policy_name: "p".to_string(),
                secret_id_ttl: None,
                secret_id_num_uses: None,
                secret_id_wrap_ttl: None,
            },
        };
        let json = serde_json::to_string_pretty(&entry).expect("serialize");
        let parsed: ServiceEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.post_renew_hooks.len(), 1);
        assert_eq!(parsed.post_renew_hooks[0].command, "pkill");
        assert_eq!(
            parsed.post_renew_hooks[0].on_failure,
            HookFailurePolicyEntry::Stop
        );
    }

    #[test]
    fn service_role_entry_without_policy_fields_deserializes_as_none() {
        let json = r#"{
            "role_name": "r",
            "role_id": "id",
            "secret_id_path": "s",
            "policy_name": "p"
        }"#;
        let parsed: ServiceRoleEntry = serde_json::from_str(json).expect("deserialize");
        assert!(parsed.secret_id_ttl.is_none());
        assert!(parsed.secret_id_num_uses.is_none());
        assert!(parsed.secret_id_wrap_ttl.is_none());
    }

    #[test]
    fn service_role_entry_with_policy_fields_round_trips() {
        let entry = ServiceRoleEntry {
            role_name: "r".to_string(),
            role_id: "id".to_string(),
            secret_id_path: PathBuf::from("s"),
            policy_name: "p".to_string(),
            secret_id_ttl: Some("1h".to_string()),
            secret_id_num_uses: Some(5),
            secret_id_wrap_ttl: Some("0".to_string()),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let parsed: ServiceRoleEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.secret_id_ttl.as_deref(), Some("1h"));
        assert_eq!(parsed.secret_id_num_uses, Some(5));
        assert_eq!(parsed.secret_id_wrap_ttl.as_deref(), Some("0"));
    }

    #[test]
    fn service_entry_without_hooks_deserializes_empty_vec() {
        let json = r#"{
            "service_name": "svc",
            "deploy_type": "daemon",
            "hostname": "h",
            "domain": "d.com",
            "agent_config_path": "agent.toml",
            "cert_path": "cert.pem",
            "key_path": "key.pem",
            "approle": {
                "role_name": "r",
                "role_id": "id",
                "secret_id_path": "s",
                "policy_name": "p"
            }
        }"#;
        let parsed: ServiceEntry = serde_json::from_str(json).expect("deserialize");
        assert!(parsed.post_renew_hooks.is_empty());
    }
}
