use std::path::PathBuf;

use anyhow::Result;
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub email: String,
    pub domains: Vec<String>,
    pub server: String,
    pub paths: Paths,
    pub eab: Option<Eab>,
    pub daemon: DaemonSettings,
    pub acme: AcmeSettings,
    pub retry: RetrySettings,
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
pub struct DaemonSettings {
    pub check_interval: String,
    pub renew_before: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AcmeSettings {
    pub http_challenge_port: u16,
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

const DEFAULT_SERVER: &str = "https://localhost:9000/acme/acme/directory";
const DEFAULT_EMAIL: &str = "admin@example.com";
const DEFAULT_CERT_PATH: &str = "certs/cert.pem";
const DEFAULT_KEY_PATH: &str = "certs/key.pem";
const DEFAULT_DOMAIN: &str = "bootroot-agent";
const DEFAULT_CHECK_INTERVAL: &str = "1h";
const DEFAULT_RENEW_BEFORE: &str = "720h";
const DEFAULT_HTTP_CHALLENGE_PORT: u16 = 80;
const DEFAULT_DIRECTORY_FETCH_ATTEMPTS: u64 = 10;
const DEFAULT_DIRECTORY_FETCH_BASE_DELAY_SECS: u64 = 1;
const DEFAULT_DIRECTORY_FETCH_MAX_DELAY_SECS: u64 = 10;
const DEFAULT_POLL_ATTEMPTS: u64 = 15;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;
const DEFAULT_RETRY_BACKOFF_SECS: [u64; 3] = [5, 10, 30];

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
            .set_default("paths.cert", DEFAULT_CERT_PATH)?
            .set_default("paths.key", DEFAULT_KEY_PATH)?
            .set_default("domains", vec![DEFAULT_DOMAIN])?
            .set_default("daemon.check_interval", DEFAULT_CHECK_INTERVAL)?
            .set_default("daemon.renew_before", DEFAULT_RENEW_BEFORE)?
            .set_default("acme.http_challenge_port", DEFAULT_HTTP_CHALLENGE_PORT)?
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
            .set_default("retry.backoff_secs", DEFAULT_RETRY_BACKOFF_SECS.to_vec())?;

        // 2. Merge File (optional)
        // If config_path is provided, use it. Otherwise look for "agent.toml"
        let path = config_path.unwrap_or_else(|| PathBuf::from("agent.toml"));

        // Add file source (required = false, so it doesn't panic if missing)
        s = s.add_source(File::from(path).required(false));

        // 3. Environment Variables
        // e.g. BOOTROOT_EMAIL, BOOTROOT_SERVER
        s = s.add_source(Environment::with_prefix("BOOTROOT").separator("_"));

        // 4. Build
        s.build()?.try_deserialize()
    }

    /// Merges CLI arguments into the settings, overriding values if present.
    pub fn merge_with_args(&mut self, args: &crate::Args) {
        if let Some(email) = &args.email {
            email.clone_into(&mut self.email);
        }
        if let Some(domain) = &args.domain {
            self.domains = vec![domain.clone()];
        }
        if let Some(ca_url) = &args.ca_url {
            ca_url.clone_into(&mut self.server);
        }
        if let Some(cert_path) = &args.cert_path {
            cert_path.clone_into(&mut self.paths.cert);
        }
        if let Some(key_path) = &args.key_path {
            key_path.clone_into(&mut self.paths.key);
        }
    }

    /// Validates configuration values for correctness.
    ///
    /// # Errors
    /// Returns error if any setting is invalid or out of range.
    pub fn validate(&self) -> Result<()> {
        if self.acme.directory_fetch_attempts == 0 {
            anyhow::bail!("acme.directory_fetch_attempts must be greater than 0");
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
        if self.retry.backoff_secs.contains(&0) {
            anyhow::bail!("retry.backoff_secs values must be greater than 0");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn test_load_settings_defaults() {
        let settings = Settings::new(None).unwrap();
        assert_eq!(settings.email, "admin@example.com");
        assert_eq!(
            settings.server,
            "https://localhost:9000/acme/acme/directory"
        );
        assert_eq!(settings.daemon.check_interval, "1h");
        assert_eq!(settings.daemon.renew_before, "720h");
        assert_eq!(settings.acme.http_challenge_port, 80);
        assert_eq!(settings.acme.directory_fetch_attempts, 10);
        assert_eq!(settings.acme.directory_fetch_base_delay_secs, 1);
        assert_eq!(settings.acme.directory_fetch_max_delay_secs, 10);
        assert_eq!(settings.acme.poll_attempts, 15);
        assert_eq!(settings.acme.poll_interval_secs, 2);
        assert_eq!(settings.retry.backoff_secs, vec![5, 10, 30]);
    }

    #[test]
    fn test_load_settings_file_override() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            email = "file@example.com"
            domains = ["file-domain"]
            server = "http://file-server"
            [paths]
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
        assert_eq!(settings.domains[0], "file-domain");
        assert_eq!(settings.server, "http://file-server");
    }

    #[test]
    fn test_merge_with_args() {
        let mut settings = Settings::new(None).unwrap();
        // Default check
        assert_eq!(settings.email, "admin@example.com");

        let args = crate::Args {
            config: None,
            email: Some("cli@example.com".to_string()),
            domain: Some("cli-domain".to_string()),
            ca_url: None, // Keep default/config
            eab_kid: None,
            eab_hmac: None,
            eab_file: None,
            cert_path: None,
            key_path: None,
            oneshot: false,
        };

        settings.merge_with_args(&args);

        // Should be overridden
        assert_eq!(settings.email, "cli@example.com");
        assert_eq!(settings.domains[0], "cli-domain");
        // Should remain default
        assert_eq!(
            settings.server,
            "https://localhost:9000/acme/acme/directory"
        );
    }

    #[test]
    fn test_validate_rejects_invalid_acme_settings() {
        let mut settings = Settings::new(None).unwrap();
        settings.acme.directory_fetch_attempts = 0;
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("directory_fetch_attempts"));
    }

    #[test]
    fn test_validate_rejects_empty_retry_backoff() {
        let mut settings = Settings::new(None).unwrap();
        settings.retry.backoff_secs = Vec::new();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("retry.backoff_secs"));
    }
}
