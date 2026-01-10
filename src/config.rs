use std::path::PathBuf;
use std::time::Duration;

use anyhow::Result;
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub email: String,
    pub server: String,
    pub spiffe_trust_domain: String,
    pub eab: Option<Eab>,
    pub acme: AcmeSettings,
    pub retry: RetrySettings,
    #[serde(default)]
    pub scheduler: SchedulerSettings,
    #[serde(default)]
    pub profiles: Vec<ProfileSettings>,
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
pub struct ProfileSettings {
    pub name: String,
    pub daemon_name: String,
    pub instance_id: String,
    pub hostname: String,
    #[serde(default = "default_uri_san_enabled")]
    pub uri_san_enabled: bool,
    pub domains: Vec<String>,
    pub paths: Paths,
    #[serde(default)]
    pub daemon: DaemonSettings,
    #[serde(default)]
    pub retry: Option<RetrySettings>,
    #[serde(default)]
    pub hooks: HookSettings,
    pub eab: Option<Eab>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DaemonSettings {
    #[serde(default = "default_check_interval", with = "duration_serde")]
    pub check_interval: Duration,
    #[serde(default = "default_renew_before", with = "duration_serde")]
    pub renew_before: Duration,
    #[serde(default = "default_check_jitter", with = "duration_serde")]
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
pub struct SchedulerSettings {
    #[serde(default = "default_max_concurrent_issuances")]
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
    #[serde(default = "default_hook_timeout_secs")]
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

const DEFAULT_SERVER: &str = "https://localhost:9000/acme/acme/directory";
const DEFAULT_EMAIL: &str = "admin@example.com";
const DEFAULT_SPIFFE_TRUST_DOMAIN: &str = "trusted.domain";
const DEFAULT_CHECK_INTERVAL_SECS: u64 = 60 * 60;
const DEFAULT_RENEW_BEFORE_SECS: u64 = 720 * 60 * 60;
const DEFAULT_CHECK_JITTER_SECS: u64 = 0;
const DEFAULT_HTTP_RESPONDER_URL: &str = "http://localhost:8080";
const DEFAULT_HTTP_RESPONDER_HMAC: &str = "";
const DEFAULT_HTTP_RESPONDER_TIMEOUT_SECS: u64 = 5;
const DEFAULT_HTTP_RESPONDER_TOKEN_TTL_SECS: u64 = 300;
const DEFAULT_DIRECTORY_FETCH_ATTEMPTS: u64 = 10;
const DEFAULT_DIRECTORY_FETCH_BASE_DELAY_SECS: u64 = 1;
const DEFAULT_DIRECTORY_FETCH_MAX_DELAY_SECS: u64 = 10;
const DEFAULT_POLL_ATTEMPTS: u64 = 15;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;
const DEFAULT_RETRY_BACKOFF_SECS: [u64; 3] = [5, 10, 30];
const DEFAULT_HOOK_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_CONCURRENT_ISSUANCES: u64 = 3;

fn default_hook_timeout_secs() -> u64 {
    DEFAULT_HOOK_TIMEOUT_SECS
}

fn default_check_interval() -> Duration {
    Duration::from_secs(DEFAULT_CHECK_INTERVAL_SECS)
}

fn default_renew_before() -> Duration {
    Duration::from_secs(DEFAULT_RENEW_BEFORE_SECS)
}

fn default_check_jitter() -> Duration {
    Duration::from_secs(DEFAULT_CHECK_JITTER_SECS)
}

fn default_uri_san_enabled() -> bool {
    true
}

impl Default for DaemonSettings {
    fn default() -> Self {
        Self {
            check_interval: default_check_interval(),
            renew_before: default_renew_before(),
            check_jitter: default_check_jitter(),
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

fn default_max_concurrent_issuances() -> u64 {
    DEFAULT_MAX_CONCURRENT_ISSUANCES
}

impl Settings {
    /// Creates a new `Settings` instance.
    ///
    /// # Errors
    /// Returns error if configuration parsing fails (e.g. file not found, invalid format).
    pub fn new(config_path: Option<PathBuf>) -> Result<Self, ConfigError> {
        let mut s = Config::builder();

        // 1. Set Defaults
        s = s
            .set_default("server", DEFAULT_SERVER)?
            .set_default("email", DEFAULT_EMAIL)?
            .set_default("spiffe_trust_domain", DEFAULT_SPIFFE_TRUST_DOMAIN)?
            .set_default("acme.http_responder_url", DEFAULT_HTTP_RESPONDER_URL)?
            .set_default("acme.http_responder_hmac", DEFAULT_HTTP_RESPONDER_HMAC)?
            .set_default(
                "acme.http_responder_timeout_secs",
                DEFAULT_HTTP_RESPONDER_TIMEOUT_SECS,
            )?
            .set_default(
                "acme.http_responder_token_ttl_secs",
                DEFAULT_HTTP_RESPONDER_TOKEN_TTL_SECS,
            )?
            .set_default(
                "acme.directory_fetch_attempts",
                DEFAULT_DIRECTORY_FETCH_ATTEMPTS,
            )?
            .set_default(
                "acme.directory_fetch_base_delay_secs",
                DEFAULT_DIRECTORY_FETCH_BASE_DELAY_SECS,
            )?
            .set_default(
                "acme.directory_fetch_max_delay_secs",
                DEFAULT_DIRECTORY_FETCH_MAX_DELAY_SECS,
            )?
            .set_default("acme.poll_attempts", DEFAULT_POLL_ATTEMPTS)?
            .set_default("acme.poll_interval_secs", DEFAULT_POLL_INTERVAL_SECS)?
            .set_default("retry.backoff_secs", DEFAULT_RETRY_BACKOFF_SECS.to_vec())?
            .set_default(
                "scheduler.max_concurrent_issuances",
                DEFAULT_MAX_CONCURRENT_ISSUANCES,
            )?;

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
                .with_list_parse_key("retry.backoff_secs"),
        );

        // 4. Build
        s.build()?.try_deserialize()
    }

    /// Merges CLI arguments into the settings, overriding values if present.
    pub fn merge_with_args(&mut self, args: &crate::Args) {
        if let Some(email) = &args.email {
            email.clone_into(&mut self.email);
        }
        if let Some(ca_url) = &args.ca_url {
            ca_url.clone_into(&mut self.server);
        }
        if let Some(responder_url) = &args.http_responder_url {
            responder_url.clone_into(&mut self.acme.http_responder_url);
        }
        if let Some(responder_hmac) = &args.http_responder_hmac {
            responder_hmac.clone_into(&mut self.acme.http_responder_hmac);
        }
    }

    /// Validates configuration values for correctness.
    ///
    /// # Errors
    /// Returns error if any setting is invalid or out of range.
    pub fn validate(&self) -> Result<()> {
        if self.spiffe_trust_domain.trim().is_empty() {
            anyhow::bail!("spiffe_trust_domain must not be empty");
        }
        if !self.spiffe_trust_domain.is_ascii() {
            anyhow::bail!("spiffe_trust_domain must be ASCII");
        }
        if self.acme.directory_fetch_attempts == 0 {
            anyhow::bail!("acme.directory_fetch_attempts must be greater than 0");
        }
        if self.acme.http_responder_url.trim().is_empty() {
            anyhow::bail!("acme.http_responder_url must not be empty");
        }
        if self.acme.http_responder_hmac.trim().is_empty() {
            anyhow::bail!("acme.http_responder_hmac must not be empty");
        }
        if self.acme.http_responder_timeout_secs == 0 {
            anyhow::bail!("acme.http_responder_timeout_secs must be greater than 0");
        }
        if self.acme.http_responder_token_ttl_secs == 0 {
            anyhow::bail!("acme.http_responder_token_ttl_secs must be greater than 0");
        }
        if self.acme.poll_attempts == 0 {
            anyhow::bail!("acme.poll_attempts must be greater than 0");
        }
        if self.acme.poll_interval_secs == 0 {
            anyhow::bail!("acme.poll_interval_secs must be greater than 0");
        }
        if self.acme.directory_fetch_base_delay_secs == 0 {
            anyhow::bail!("acme.directory_fetch_base_delay_secs must be greater than 0");
        }
        if self.acme.directory_fetch_max_delay_secs == 0 {
            anyhow::bail!("acme.directory_fetch_max_delay_secs must be greater than 0");
        }
        if self.acme.directory_fetch_base_delay_secs > self.acme.directory_fetch_max_delay_secs {
            anyhow::bail!(
                "acme.directory_fetch_base_delay_secs must be <= acme.directory_fetch_max_delay_secs"
            );
        }
        if self.retry.backoff_secs.is_empty() {
            anyhow::bail!("retry.backoff_secs must not be empty");
        }
        Self::validate_retry_settings(&self.retry.backoff_secs, "retry.backoff_secs")?;
        if self.scheduler.max_concurrent_issuances == 0 {
            anyhow::bail!("scheduler.max_concurrent_issuances must be greater than 0");
        }
        if self.profiles.is_empty() {
            anyhow::bail!("profiles must not be empty");
        }
        for profile in &self.profiles {
            Self::validate_profile(profile)?;
        }
        Ok(())
    }

    fn validate_profile(profile: &ProfileSettings) -> Result<()> {
        if profile.name.trim().is_empty() {
            anyhow::bail!("profiles.name must not be empty");
        }
        if profile.daemon_name.trim().is_empty() {
            anyhow::bail!("profiles.daemon_name must not be empty");
        }
        if profile.hostname.trim().is_empty() {
            anyhow::bail!("profiles.hostname must not be empty");
        }
        if !profile.daemon_name.is_ascii() {
            anyhow::bail!("profiles.daemon_name must be ASCII");
        }
        if !profile.hostname.is_ascii() {
            anyhow::bail!("profiles.hostname must be ASCII");
        }
        if profile.instance_id.trim().is_empty() {
            anyhow::bail!("profiles.instance_id must not be empty");
        }
        if !profile.instance_id.chars().all(|ch| ch.is_ascii_digit()) {
            anyhow::bail!("profiles.instance_id must be numeric");
        }
        if profile.domains.is_empty() {
            anyhow::bail!("profiles.domains must not be empty");
        }
        if profile.paths.cert.as_os_str().is_empty() {
            anyhow::bail!("profiles.paths.cert must not be empty");
        }
        if profile.paths.key.as_os_str().is_empty() {
            anyhow::bail!("profiles.paths.key must not be empty");
        }
        if let Some(retry) = &profile.retry {
            Self::validate_retry_settings(&retry.backoff_secs, "profiles.retry.backoff_secs")?;
        }
        Self::validate_hook_commands(
            &profile.hooks.post_renew.success,
            "profiles.hooks.post_renew.success",
        )?;
        Self::validate_hook_commands(
            &profile.hooks.post_renew.failure,
            "profiles.hooks.post_renew.failure",
        )?;
        Ok(())
    }

    fn validate_hook_commands(hooks: &[HookCommand], label: &str) -> Result<()> {
        for hook in hooks {
            if hook.command.trim().is_empty() {
                anyhow::bail!("{label} hook command must not be empty");
            }
            if let Some(working_dir) = &hook.working_dir
                && working_dir.as_os_str().is_empty()
            {
                anyhow::bail!("{label} hook working_dir must not be empty");
            }
            if hook.timeout_secs == 0 {
                anyhow::bail!("{label} hook timeout_secs must be greater than 0");
            }
            Self::validate_retry_settings(
                &hook.retry_backoff_secs,
                &format!("{label} hook retry_backoff_secs"),
            )?;
            if let Some(max_output_bytes) = hook.max_output_bytes
                && max_output_bytes == 0
            {
                anyhow::bail!("{label} hook max_output_bytes must be greater than 0");
            }
        }
        Ok(())
    }

    fn validate_retry_settings(backoff_secs: &[u64], label: &str) -> Result<()> {
        if backoff_secs.contains(&0) {
            anyhow::bail!("{label} values must be greater than 0");
        }
        Ok(())
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
            spiffe_trust_domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            name = "edge-proxy-a"
            daemon_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"
            domains = ["edge-proxy.internal"]

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
        assert_eq!(settings.spiffe_trust_domain, "trusted.domain");
        assert_eq!(settings.acme.http_responder_url, "http://localhost:8080");
        assert_eq!(settings.acme.http_responder_hmac, "dev-hmac");
        assert_eq!(settings.acme.http_responder_timeout_secs, 5);
        assert_eq!(settings.acme.http_responder_token_ttl_secs, 300);
        assert_eq!(settings.acme.directory_fetch_attempts, 10);
        assert_eq!(settings.acme.directory_fetch_base_delay_secs, 1);
        assert_eq!(settings.acme.directory_fetch_max_delay_secs, 10);
        assert_eq!(settings.acme.poll_attempts, 15);
        assert_eq!(settings.acme.poll_interval_secs, 2);
        assert_eq!(settings.retry.backoff_secs, vec![5, 10, 30]);
        assert_eq!(settings.scheduler.max_concurrent_issuances, 3);

        let profile = &settings.profiles[0];
        assert_eq!(profile.daemon.check_interval, Duration::from_secs(60 * 60));
        assert_eq!(
            profile.daemon.renew_before,
            Duration::from_secs(720 * 60 * 60)
        );
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
            spiffe_trust_domain = "example.internal"

            [[profiles]]
            name = "edge-proxy-a"
            daemon_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"
            domains = ["file-domain"]

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
    fn test_load_settings_file_override() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            email = "file@example.com"
            server = "http://file-server"
            spiffe_trust_domain = "example.internal"

            [[profiles]]
            name = "edge-proxy-a"
            daemon_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"
            domains = ["file-domain"]

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
        assert_eq!(settings.spiffe_trust_domain, "example.internal");
        assert_eq!(settings.profiles[0].domains[0], "file-domain");
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
    fn test_validate_rejects_invalid_acme_settings() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.acme.directory_fetch_attempts = 0;
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("directory_fetch_attempts"));
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
}
