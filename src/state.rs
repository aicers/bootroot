use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::ValueEnum;
use serde::{Deserialize, Serialize};

const DEFAULT_SECRETS_DIR: &str = "secrets";
const DEFAULT_STATE_FILE: &str = "state.json";
pub(crate) const DEFAULT_HOOK_TIMEOUT_SECS: u64 = 30;

/// Describes how to reload a service after its infrastructure certificate
/// is renewed.  Keyed by a stable discriminator so the rotation loop can
/// dispatch without hard-coding service names.
///
/// New variants (e.g. `Signal`, `RestartListener`) can be added by
/// follow-up PRs (see #515) without a schema revision — `serde`'s
/// internally-tagged representation handles forward compatibility.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "type")]
pub(crate) enum ReloadStrategy {
    /// Restarts the named Docker container via `docker restart`.
    ContainerRestart { container_name: String },
}

impl fmt::Display for ReloadStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContainerRestart { container_name } => {
                write!(f, "container_restart({container_name})")
            }
        }
    }
}

/// Tracks a bootroot-managed infrastructure certificate (e.g. `OpenBao`
/// server TLS, http01 admin TLS).  Stored in `StateFile::infra_certs`.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub(crate) struct InfraCertEntry {
    pub(crate) cert_path: PathBuf,
    pub(crate) key_path: PathBuf,
    pub(crate) sans: Vec<String>,
    /// Duration before expiry at which renewal should trigger (e.g. "720h").
    pub(crate) renew_before: String,
    pub(crate) reload_strategy: ReloadStrategy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) issued_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) expires_at: Option<String>,
}

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) openbao_bind_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) openbao_advertise_addr: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) http01_admin_bind_addr: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) infra_certs: BTreeMap<String, InfraCertEntry>,
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
    pub(crate) secret_id_wrap_ttl: Option<String>,
    #[serde(default)]
    pub(crate) token_bound_cidrs: Option<Vec<String>>,
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
                secret_id_wrap_ttl: None,
                token_bound_cidrs: None,
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
        assert!(parsed.secret_id_wrap_ttl.is_none());
    }

    #[test]
    fn old_state_with_secret_id_num_uses_still_deserializes() {
        let json = r#"{
            "role_name": "r",
            "role_id": "id",
            "secret_id_path": "s",
            "policy_name": "p",
            "secret_id_ttl": "1h",
            "secret_id_num_uses": 5,
            "secret_id_wrap_ttl": "30m"
        }"#;
        let parsed: ServiceRoleEntry = serde_json::from_str(json).expect("deserialize");
        assert_eq!(parsed.secret_id_ttl.as_deref(), Some("1h"));
        assert_eq!(parsed.secret_id_wrap_ttl.as_deref(), Some("30m"));
    }

    #[test]
    fn service_role_entry_with_policy_fields_round_trips() {
        let entry = ServiceRoleEntry {
            role_name: "r".to_string(),
            role_id: "id".to_string(),
            secret_id_path: PathBuf::from("s"),
            policy_name: "p".to_string(),
            secret_id_ttl: Some("1h".to_string()),
            secret_id_wrap_ttl: Some("0".to_string()),
            token_bound_cidrs: Some(vec!["10.0.0.0/24".to_string()]),
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let parsed: ServiceRoleEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.secret_id_ttl.as_deref(), Some("1h"));
        assert_eq!(parsed.secret_id_wrap_ttl.as_deref(), Some("0"));
        assert_eq!(
            parsed.token_bound_cidrs.as_deref(),
            Some(["10.0.0.0/24".to_string()].as_slice())
        );
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

    #[test]
    fn state_file_without_openbao_bind_addr_deserializes_as_none() {
        let json = r#"{
            "openbao_url": "http://localhost:8200",
            "kv_mount": "secret"
        }"#;
        let parsed: StateFile = serde_json::from_str(json).expect("deserialize");
        assert!(parsed.openbao_bind_addr.is_none());
    }

    #[test]
    fn state_file_with_openbao_bind_addr_round_trips() {
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            infra_certs: BTreeMap::new(),
        };
        let json = serde_json::to_string(&state).expect("serialize");
        let parsed: StateFile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(
            parsed.openbao_bind_addr.as_deref(),
            Some("192.168.1.10:8200")
        );
    }

    #[test]
    fn state_file_without_openbao_bind_addr_skips_field_in_json() {
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            infra_certs: BTreeMap::new(),
        };
        let json = serde_json::to_string(&state).expect("serialize");
        assert!(
            !json.contains("openbao_bind_addr"),
            "None should be skipped"
        );
    }

    #[test]
    fn state_file_without_infra_certs_deserializes_as_empty() {
        let json = r#"{
            "openbao_url": "http://localhost:8200",
            "kv_mount": "secret"
        }"#;
        let parsed: StateFile = serde_json::from_str(json).expect("deserialize");
        assert!(parsed.infra_certs.is_empty());
    }

    #[test]
    fn state_file_empty_infra_certs_skips_field_in_json() {
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            infra_certs: BTreeMap::new(),
        };
        let json = serde_json::to_string(&state).expect("serialize");
        assert!(
            !json.contains("infra_certs"),
            "empty infra_certs should be skipped"
        );
    }

    #[test]
    fn infra_cert_entry_round_trips_json() {
        let entry = InfraCertEntry {
            cert_path: PathBuf::from("openbao/tls/server.crt"),
            key_path: PathBuf::from("openbao/tls/server.key"),
            sans: vec!["openbao.internal".to_string(), "localhost".to_string()],
            renew_before: "720h".to_string(),
            reload_strategy: ReloadStrategy::ContainerRestart {
                container_name: "bootroot-openbao".to_string(),
            },
            issued_at: Some("2026-01-01T00:00:00Z".to_string()),
            expires_at: None,
        };
        let json = serde_json::to_string(&entry).expect("serialize");
        let parsed: InfraCertEntry = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.renew_before, "720h");
        assert_eq!(
            parsed.reload_strategy,
            ReloadStrategy::ContainerRestart {
                container_name: "bootroot-openbao".to_string(),
            }
        );
        assert_eq!(parsed.sans.len(), 2);
    }

    #[test]
    fn state_file_with_infra_certs_round_trips() {
        let mut infra_certs = BTreeMap::new();
        infra_certs.insert(
            "openbao".to_string(),
            InfraCertEntry {
                cert_path: PathBuf::from("openbao/tls/server.crt"),
                key_path: PathBuf::from("openbao/tls/server.key"),
                sans: vec!["openbao.internal".to_string()],
                renew_before: "720h".to_string(),
                reload_strategy: ReloadStrategy::ContainerRestart {
                    container_name: "bootroot-openbao".to_string(),
                },
                issued_at: None,
                expires_at: None,
            },
        );
        let state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            infra_certs,
        };
        let json = serde_json::to_string_pretty(&state).expect("serialize");
        let parsed: StateFile = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed.infra_certs.len(), 1);
        assert!(parsed.infra_certs.contains_key("openbao"));
    }

    #[test]
    fn reload_strategy_display_container_restart() {
        let strategy = ReloadStrategy::ContainerRestart {
            container_name: "bootroot-openbao".to_string(),
        };
        assert_eq!(strategy.to_string(), "container_restart(bootroot-openbao)");
    }
}
