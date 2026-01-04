use std::path::PathBuf;

use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub email: String,
    pub domains: Vec<String>,
    pub server: String,
    pub paths: Paths,
    pub eab: Option<Eab>,
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

const DEFAULT_SERVER: &str = "https://localhost:9000/acme/acme/directory";
const DEFAULT_EMAIL: &str = "admin@example.com";
const DEFAULT_CERT_PATH: &str = "certs/cert.pem";
const DEFAULT_KEY_PATH: &str = "certs/key.pem";
const DEFAULT_DOMAIN: &str = "bootroot-agent";

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
            .set_default("domains", vec![DEFAULT_DOMAIN])?;

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
}
