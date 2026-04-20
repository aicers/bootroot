use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

mod defaults;
mod validation;

pub use validation::{parse_cert_duration, validate_cert_duration_vs_default_renew_before};

/// CLI-provided overrides that must survive config reloads in daemon mode.
///
/// Fields mirror the subset of [`crate::Args`] that [`Settings::merge_with_args`]
/// applies. Storing them separately lets the daemon re-apply overrides after
/// every file-based reload without depending on the CLI parser.
#[derive(Clone, Debug, Default)]
pub struct CliOverrides {
    pub email: Option<String>,
    pub ca_url: Option<String>,
    pub http_responder_url: Option<String>,
    pub http_responder_hmac: Option<String>,
}

impl From<&crate::Args> for CliOverrides {
    fn from(args: &crate::Args) -> Self {
        Self {
            email: args.email.clone(),
            ca_url: args.ca_url.clone(),
            http_responder_url: args.http_responder_url.clone(),
            http_responder_hmac: args.http_responder_hmac.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub email: String,
    pub server: String,
    pub domain: String,
    pub eab: Option<Eab>,
    pub acme: AcmeSettings,
    pub retry: RetrySettings,
    #[serde(default)]
    pub trust: TrustSettings,
    #[serde(default)]
    pub scheduler: SchedulerSettings,
    #[serde(default)]
    pub profiles: Vec<DaemonProfileSettings>,
    /// Optional `OpenBao` client configuration. When present, the daemon
    /// spawns a fast-poll task that watches for `rotate force-reissue`
    /// requests on the KV v2 `reissue` path for each registered service.
    #[serde(default)]
    pub openbao: Option<OpenBaoSettings>,
}

/// `OpenBao` connection settings for the remote-agent fast-poll loop.
///
/// The remote `bootroot-agent` authenticates directly via `AppRole` and
/// polls `{kv_mount}/data/bootroot/services/<service>/reissue` on the
/// configured `fast_poll_interval` to pick up force-reissue requests
/// issued by the control plane.
#[derive(Debug, Deserialize, Clone)]
pub struct OpenBaoSettings {
    pub url: String,
    #[serde(default = "defaults::default_kv_mount")]
    pub kv_mount: String,
    pub role_id_path: PathBuf,
    pub secret_id_path: PathBuf,
    #[serde(default)]
    pub ca_bundle_path: Option<PathBuf>,
    #[serde(
        default = "defaults::default_fast_poll_interval",
        with = "duration_serde"
    )]
    pub fast_poll_interval: Duration,
    /// On-disk path where the agent persists its `last_reissue_seen_version`,
    /// `in_flight_renewals`, and `pending_completion_writes` maps across
    /// restarts. Must be absolute — a cwd-relative path is rejected by
    /// validation because the agent process cwd is not contracted to be
    /// stable or writable under systemd-style supervisors.
    /// `bootroot-remote bootstrap` auto-provisions an absolute path
    /// adjacent to `agent.toml`.
    #[serde(default = "defaults::default_fast_poll_state_path")]
    pub state_path: PathBuf,
}

#[must_use]
pub fn profile_domain(settings: &Settings, profile: &DaemonProfileSettings) -> String {
    format!(
        "{}.{}.{}.{}",
        profile.instance_id, profile.service_name, profile.hostname, settings.domain
    )
}

#[derive(Debug, Deserialize, Clone)]
pub struct Paths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Eab {
    pub kid: String,
    pub hmac: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DaemonProfileSettings {
    pub service_name: String,
    pub instance_id: String,
    pub hostname: String,
    pub paths: Paths,
    #[serde(default)]
    pub daemon: DaemonRuntimeSettings,
    #[serde(default)]
    pub retry: Option<RetrySettings>,
    #[serde(default)]
    pub hooks: HookSettings,
    pub eab: Option<Eab>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DaemonRuntimeSettings {
    #[serde(default = "defaults::default_check_interval", with = "duration_serde")]
    pub check_interval: Duration,
    #[serde(default = "defaults::default_renew_before", with = "duration_serde")]
    pub renew_before: Duration,
    #[serde(default = "defaults::default_check_jitter", with = "duration_serde")]
    pub check_jitter: Duration,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AcmeSettings {
    pub http_responder_url: String,
    pub http_responder_hmac: String,
    pub http_responder_timeout_secs: u64,
    pub http_responder_token_ttl_secs: u64,
    pub directory_fetch_attempts: u64,
    pub directory_fetch_base_delay_secs: u64,
    pub directory_fetch_max_delay_secs: u64,
    pub poll_attempts: u64,
    pub poll_interval_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RetrySettings {
    pub backoff_secs: Vec<u64>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct TrustSettings {
    #[serde(default)]
    pub ca_bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub trusted_ca_sha256: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct SchedulerSettings {
    #[serde(default = "defaults::default_max_concurrent_issuances")]
    pub max_concurrent_issuances: u64,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct HookSettings {
    #[serde(default)]
    pub post_renew: PostRenewHooks,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PostRenewHooks {
    #[serde(default)]
    pub success: Vec<HookCommand>,
    #[serde(default)]
    pub failure: Vec<HookCommand>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HookCommand {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<PathBuf>,
    #[serde(default = "defaults::default_hook_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub retry_backoff_secs: Vec<u64>,
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
    #[serde(default)]
    pub on_failure: HookFailurePolicy,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HookFailurePolicy {
    #[default]
    Continue,
    Stop,
}

impl Default for DaemonRuntimeSettings {
    fn default() -> Self {
        Self {
            check_interval: defaults::default_check_interval(),
            renew_before: defaults::default_renew_before(),
            check_jitter: defaults::default_check_jitter(),
        }
    }
}

mod duration_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        humantime::parse_duration(&value).map_err(serde::de::Error::custom)
    }
}

impl Settings {
    /// Creates a new `Settings` instance.
    ///
    /// # Errors
    /// Returns error if configuration parsing fails (e.g. file not found, invalid format).
    pub fn new(config_path: Option<PathBuf>) -> Result<Self, ConfigError> {
        let mut s = Config::builder();

        // 1. Set Defaults
        s = defaults::apply_defaults(s)?;

        // 2. Merge File (optional)
        // If config_path is provided, use it. Otherwise look for "agent.toml"
        let path = config_path.unwrap_or_else(|| PathBuf::from("agent.toml"));

        // Add file source (required = false, so it doesn't panic if missing)
        s = s.add_source(File::from(path).required(false));

        // 3. Environment Variables (double-underscore for nesting)
        // e.g. BOOTROOT_EMAIL, BOOTROOT_PATHS__CERT, BOOTROOT_DAEMON__RENEW_BEFORE
        s = s.add_source(
            Environment::with_prefix("BOOTROOT")
                .separator("__")
                .try_parsing(true)
                .ignore_empty(true)
                .list_separator(",")
                .with_list_parse_key("retry.backoff_secs")
                .with_list_parse_key("trust.trusted_ca_sha256"),
        );

        // 4. Build
        s.build()?.try_deserialize()
    }

    /// Merges CLI arguments into the settings, overriding values if present.
    pub fn merge_with_args(&mut self, args: &crate::Args) {
        self.apply_overrides(&CliOverrides::from(args));
    }

    /// Re-applies CLI-provided overrides on top of these settings.
    pub fn apply_overrides(&mut self, overrides: &CliOverrides) {
        if let Some(email) = &overrides.email {
            email.clone_into(&mut self.email);
        }
        if let Some(ca_url) = &overrides.ca_url {
            ca_url.clone_into(&mut self.server);
        }
        if let Some(responder_url) = &overrides.http_responder_url {
            responder_url.clone_into(&mut self.acme.http_responder_url);
        }
        if let Some(responder_hmac) = &overrides.http_responder_hmac {
            responder_hmac.clone_into(&mut self.acme.http_responder_hmac);
        }
    }

    /// Validates configuration values for correctness.
    ///
    /// # Errors
    /// Returns error if any setting is invalid or out of range.
    pub fn validate(&self) -> Result<()> {
        validation::validate_settings(self)
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::time::Duration;

    use super::*;

    fn write_minimal_profile_config(file: &mut tempfile::NamedTempFile) {
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"
        "#
        )
        .unwrap();
        file.flush().unwrap();
    }

    #[test]
    fn test_load_settings_defaults() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();

        assert_eq!(settings.email, "admin@example.com");
        assert_eq!(
            settings.server,
            "https://localhost:9000/acme/acme/directory"
        );
        assert_eq!(settings.domain, "trusted.domain");
        assert_eq!(settings.acme.http_responder_url, "http://localhost:8080");
        assert_eq!(settings.acme.http_responder_hmac, "dev-hmac");
        assert_eq!(settings.acme.http_responder_timeout_secs, 5);
        assert_eq!(settings.acme.http_responder_token_ttl_secs, 300);
        assert_eq!(settings.acme.directory_fetch_attempts, 10);
        assert_eq!(settings.acme.directory_fetch_base_delay_secs, 1);
        assert_eq!(settings.acme.directory_fetch_max_delay_secs, 10);
        assert_eq!(settings.acme.poll_attempts, 15);
        assert_eq!(settings.acme.poll_interval_secs, 2);
        assert_eq!(settings.retry.backoff_secs, vec![5, 10, 30, 60]);
        assert_eq!(settings.scheduler.max_concurrent_issuances, 3);
        assert!(settings.trust.ca_bundle_path.is_none());
        assert!(settings.trust.trusted_ca_sha256.is_empty());

        let profile = &settings.profiles[0];
        assert_eq!(profile.daemon.check_interval, Duration::from_hours(1));
        assert_eq!(profile.daemon.renew_before, Duration::from_hours(16));
        assert_eq!(profile.daemon.check_jitter, Duration::from_secs(0));
        assert!(profile.hooks.post_renew.success.is_empty());
        assert!(profile.hooks.post_renew.failure.is_empty());
    }

    #[test]
    fn test_load_settings_rejects_invalid_duration() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            email = "file@example.com"
            server = "http://file-server"
            domain = "example.internal"

            [[profiles]]
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "file/cert.pem"
            key = "file/key.pem"

            [profiles.daemon]
            check_interval = "nope"
        "#
        )
        .unwrap();
        file.flush().unwrap();

        let err = Settings::new(Some(file.path().to_path_buf())).unwrap_err();
        assert!(err.to_string().contains("check_interval"));
    }

    #[test]
    fn test_load_settings_rejects_removed_trust_verify_key() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            r"
            [trust]
            verify_certificates = false
        "
        )
        .unwrap();
        file.flush().unwrap();

        let err = Settings::new(Some(file.path().to_path_buf())).unwrap_err();
        assert!(err.to_string().contains("verify_certificates"));
    }

    #[test]
    fn test_load_settings_file_override() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            email = "file@example.com"
            server = "http://file-server"
            domain = "example.internal"

            [[profiles]]
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "file/cert.pem"
            key = "file/key.pem"
        "#
        )
        .unwrap();
        // File::flush is important to ensure content is on disk
        file.flush().unwrap();

        let path = file.path().to_path_buf();
        let settings = Settings::new(Some(path)).unwrap();

        assert_eq!(settings.email, "file@example.com");
        assert_eq!(settings.server, "http://file-server");
        assert_eq!(settings.domain, "example.internal");
    }

    #[test]
    fn test_merge_with_args() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();

        let args = crate::Args {
            config: None,
            email: Some("cli@example.com".to_string()),
            ca_url: None, // Keep default/config
            http_responder_url: None,
            http_responder_hmac: None,
            eab_kid: None,
            eab_hmac: None,
            eab_file: None,
            oneshot: false,
            insecure: false,
        };

        settings.merge_with_args(&args);

        // Should be overridden
        assert_eq!(settings.email, "cli@example.com");
        // Should remain default
        assert_eq!(
            settings.server,
            "https://localhost:9000/acme/acme/directory"
        );
    }

    #[test]
    fn test_apply_overrides_replaces_all_fields() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();

        let overrides = CliOverrides {
            email: Some("override@example.com".to_string()),
            ca_url: Some("https://override-ca".to_string()),
            http_responder_url: Some("http://override-responder".to_string()),
            http_responder_hmac: Some("override-hmac".to_string()),
        };

        settings.apply_overrides(&overrides);

        assert_eq!(settings.email, "override@example.com");
        assert_eq!(settings.server, "https://override-ca");
        assert_eq!(
            settings.acme.http_responder_url,
            "http://override-responder"
        );
        assert_eq!(settings.acme.http_responder_hmac, "override-hmac");
    }

    #[test]
    fn test_apply_overrides_skips_none_fields() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        let original_email = settings.email.clone();
        let original_server = settings.server.clone();

        let overrides = CliOverrides::default();
        settings.apply_overrides(&overrides);

        assert_eq!(settings.email, original_email);
        assert_eq!(settings.server, original_server);
    }

    /// Regression test for #475: reloading the config from disk then applying
    /// CLI overrides must produce the CLI value, not the file/default value.
    #[test]
    fn test_reload_then_apply_overrides_preserves_cli_values() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        // Config deliberately omits http_responder_hmac so it falls back to
        // the compiled default (empty string).
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            email = "file@example.com"

            [acme]
            http_responder_url = "http://localhost:8080"

            [[profiles]]
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"
        "#
        )
        .unwrap();
        file.flush().unwrap();

        let overrides = CliOverrides {
            email: None,
            ca_url: Some("https://cli-ca".to_string()),
            http_responder_url: None,
            http_responder_hmac: Some("cli-hmac-secret".to_string()),
        };

        // Simulate the daemon retry path: reload from disk, then apply overrides.
        let mut fresh = Settings::new(Some(file.path().to_path_buf())).unwrap();
        fresh.apply_overrides(&overrides);

        // CLI-provided values must win.
        assert_eq!(fresh.server, "https://cli-ca");
        assert_eq!(fresh.acme.http_responder_hmac, "cli-hmac-secret");
        // File-provided values stay when CLI has no override.
        assert_eq!(fresh.email, "file@example.com");
        assert_eq!(fresh.acme.http_responder_url, "http://localhost:8080");
    }

    #[test]
    fn test_validate_rejects_invalid_acme_settings() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.acme.directory_fetch_attempts = 0;
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("directory_fetch_attempts"));
    }

    #[test]
    fn test_validate_rejects_empty_domain() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.domain = "  ".to_string();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("domain must not be empty"));
    }

    #[test]
    fn test_validate_rejects_non_ascii_domain() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.domain = "예시.local".to_string();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("domain must be ASCII"));
    }

    #[test]
    fn test_profile_domain_uses_settings_domain() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.domain = "example.internal".to_string();
        let profile = &settings.profiles[0];
        let domain = profile_domain(&settings, profile);
        assert_eq!(domain, "001.edge-proxy.edge-node-01.example.internal");
    }

    #[test]
    fn test_validate_rejects_empty_retry_backoff() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.retry.backoff_secs = Vec::new();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("retry.backoff_secs"));
    }

    #[test]
    fn test_validate_rejects_empty_hook_command() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hooks.post_renew.success = vec![HookCommand {
            command: "   ".to_string(),
            args: Vec::new(),
            working_dir: None,
            timeout_secs: 30,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
            on_failure: HookFailurePolicy::Continue,
        }];

        let err = settings.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("profiles.hooks.post_renew.success")
        );
    }

    #[test]
    fn test_validate_rejects_hook_timeout_zero() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hooks.post_renew.failure = vec![HookCommand {
            command: "true".to_string(),
            args: Vec::new(),
            working_dir: None,
            timeout_secs: 0,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
            on_failure: HookFailurePolicy::Continue,
        }];

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("timeout_secs"));
    }

    #[test]
    fn test_validate_rejects_hook_retry_backoff_zero() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hooks.post_renew.success = vec![HookCommand {
            command: "true".to_string(),
            args: Vec::new(),
            working_dir: None,
            timeout_secs: 30,
            retry_backoff_secs: vec![0],
            max_output_bytes: None,
            on_failure: HookFailurePolicy::Continue,
        }];

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("retry_backoff_secs"));
    }

    #[test]
    fn test_validate_rejects_empty_profiles() {
        let mut settings = Settings::new(None).unwrap();
        settings.acme.http_responder_hmac = "test".to_string();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("profiles must not be empty"));
    }

    #[test]
    fn test_validate_rejects_hook_working_dir_empty() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hooks.post_renew.success = vec![HookCommand {
            command: "true".to_string(),
            args: Vec::new(),
            working_dir: Some(PathBuf::new()),
            timeout_secs: 30,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
            on_failure: HookFailurePolicy::Continue,
        }];

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("working_dir"));
    }

    #[test]
    fn test_validate_rejects_hook_max_output_zero() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hooks.post_renew.success = vec![HookCommand {
            command: "true".to_string(),
            args: Vec::new(),
            working_dir: None,
            timeout_secs: 30,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: Some(0),
            on_failure: HookFailurePolicy::Continue,
        }];

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("max_output_bytes"));
    }

    #[test]
    fn test_validate_rejects_profile_retry_backoff_zero() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].retry = Some(RetrySettings {
            backoff_secs: vec![0],
        });

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("profiles.retry.backoff_secs"));
    }

    /// Regression test: an `[openbao]` section whose `state_path` is
    /// relative (including the in-tree default `bootroot-agent-state.json`)
    /// must fail validation. This is the same restart-persistence hazard
    /// called out in Round 5 — under a systemd-style supervisor the
    /// agent process cwd is not contracted to be stable or writable, so
    /// a cwd-relative state file can be silently lost across restarts.
    #[test]
    fn validate_rejects_relative_openbao_state_path() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"

            [openbao]
            url = "http://openbao:8200"
            role_id_path = "/etc/bootroot/role_id"
            secret_id_path = "/etc/bootroot/secret_id"
            state_path = "bootroot-agent-state.json"
        "#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        let err = settings.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("openbao.state_path"), "{msg}");
        assert!(msg.contains("absolute"), "{msg}");
    }

    /// When `[openbao]` is present but `state_path` is omitted entirely,
    /// the parser fills in the in-tree default (a bare relative
    /// filename). Validation must still reject it — i.e. an omitted
    /// `state_path` surfaces the same error rather than silently
    /// entrenching a cwd-relative path. This mirrors the scenario where
    /// `bootroot-remote bootstrap` ran with a relative `agent_config_path`
    /// and therefore skipped provisioning `state_path`.
    #[test]
    fn validate_rejects_omitted_openbao_state_path_via_default() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"

            [openbao]
            url = "http://openbao:8200"
            role_id_path = "/etc/bootroot/role_id"
            secret_id_path = "/etc/bootroot/secret_id"
        "#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("openbao.state_path"));
    }

    /// Accepts the common case where `[openbao]` carries an absolute
    /// `state_path` — this is what `bootroot-remote bootstrap`
    /// auto-provisions when `agent_config_path` is absolute.
    #[test]
    fn validate_accepts_absolute_openbao_state_path() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"

            [openbao]
            url = "http://openbao:8200"
            role_id_path = "/etc/bootroot/role_id"
            secret_id_path = "/etc/bootroot/secret_id"
            state_path = "/var/lib/bootroot/bootroot-agent-state.json"
        "#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings
            .validate()
            .expect("absolute state_path must validate");
    }
}
