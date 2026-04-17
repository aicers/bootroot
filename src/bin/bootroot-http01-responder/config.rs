//! Defines the responder configuration loading, validation, and reload flow.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use bootroot::acme::http01_protocol::Http01HmacSigner;
use clap::Parser;
use config::{Config, ConfigError, Environment, File};
use serde::Deserialize;

use super::state::ResponderState;

const DEFAULT_CONFIG_PATH: &str = "responder.toml";
pub(super) const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:80";
pub(super) const DEFAULT_ADMIN_ADDR: &str = "0.0.0.0:8080";
pub(super) const DEFAULT_TOKEN_TTL_SECS: u64 = 300;
pub(super) const DEFAULT_MAX_TOKEN_TTL_SECS: u64 = 900;
pub(super) const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 30;
pub(super) const DEFAULT_MAX_SKEW_SECS: u64 = 60;
pub(super) const DEFAULT_ADMIN_RATE_LIMIT_REQUESTS: u64 = 300;
pub(super) const DEFAULT_ADMIN_RATE_LIMIT_WINDOW_SECS: u64 = 60;
pub(super) const DEFAULT_ADMIN_BODY_LIMIT_BYTES: u64 = 8 * 1024;

#[derive(Parser, Debug)]
#[command(author, version, about = "Bootroot HTTP-01 responder")]
pub(super) struct Args {
    /// Path to responder configuration file (default: responder.toml)
    #[arg(long, short)]
    pub(super) config: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub(super) struct ResponderSettings {
    pub(super) listen_addr: String,
    pub(super) admin_addr: String,
    pub(super) hmac_secret: String,
    pub(super) token_ttl_secs: u64,
    pub(super) max_token_ttl_secs: u64,
    pub(super) cleanup_interval_secs: u64,
    pub(super) max_skew_secs: u64,
    pub(super) admin_rate_limit_requests: u64,
    pub(super) admin_rate_limit_window_secs: u64,
    pub(super) admin_body_limit_bytes: u64,
    #[serde(default)]
    pub(super) tls_cert_path: Option<String>,
    #[serde(default)]
    pub(super) tls_key_path: Option<String>,
}

impl ResponderSettings {
    fn new(config_path: Option<&Path>) -> Result<Self, ConfigError> {
        let path =
            config_path.map_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH), Path::to_path_buf);

        Config::builder()
            .set_default("listen_addr", DEFAULT_LISTEN_ADDR)?
            .set_default("admin_addr", DEFAULT_ADMIN_ADDR)?
            .set_default("token_ttl_secs", DEFAULT_TOKEN_TTL_SECS)?
            .set_default("max_token_ttl_secs", DEFAULT_MAX_TOKEN_TTL_SECS)?
            .set_default("cleanup_interval_secs", DEFAULT_CLEANUP_INTERVAL_SECS)?
            .set_default("max_skew_secs", DEFAULT_MAX_SKEW_SECS)?
            .set_default(
                "admin_rate_limit_requests",
                DEFAULT_ADMIN_RATE_LIMIT_REQUESTS,
            )?
            .set_default(
                "admin_rate_limit_window_secs",
                DEFAULT_ADMIN_RATE_LIMIT_WINDOW_SECS,
            )?
            .set_default("admin_body_limit_bytes", DEFAULT_ADMIN_BODY_LIMIT_BYTES)?
            .add_source(File::from(path).required(false))
            .add_source(
                Environment::with_prefix("BOOTROOT_RESPONDER")
                    .separator("__")
                    .try_parsing(true)
                    .ignore_empty(true),
            )
            .build()?
            .try_deserialize()
    }

    pub(super) fn validate(&self) -> Result<()> {
        if self.hmac_secret.trim().is_empty() {
            anyhow::bail!("hmac_secret must not be empty");
        }
        if self.token_ttl_secs == 0 {
            anyhow::bail!("token_ttl_secs must be greater than 0");
        }
        if self.max_token_ttl_secs == 0 {
            anyhow::bail!("max_token_ttl_secs must be greater than 0");
        }
        if self.max_token_ttl_secs < self.token_ttl_secs {
            anyhow::bail!("max_token_ttl_secs must be greater than or equal to token_ttl_secs");
        }
        if self.cleanup_interval_secs == 0 {
            anyhow::bail!("cleanup_interval_secs must be greater than 0");
        }
        if self.max_skew_secs == 0 {
            anyhow::bail!("max_skew_secs must be greater than 0");
        }
        if self.admin_rate_limit_requests == 0 {
            anyhow::bail!("admin_rate_limit_requests must be greater than 0");
        }
        if usize::try_from(self.admin_rate_limit_requests).is_err() {
            anyhow::bail!("admin_rate_limit_requests must fit into usize");
        }
        if self.admin_rate_limit_window_secs == 0 {
            anyhow::bail!("admin_rate_limit_window_secs must be greater than 0");
        }
        if self.admin_body_limit_bytes == 0 {
            anyhow::bail!("admin_body_limit_bytes must be greater than 0");
        }
        if usize::try_from(self.admin_body_limit_bytes).is_err() {
            anyhow::bail!("admin_body_limit_bytes must fit into usize");
        }
        validate_socket_addr(&self.listen_addr, "listen_addr")?;
        validate_socket_addr(&self.admin_addr, "admin_addr")?;
        match (&self.tls_cert_path, &self.tls_key_path) {
            (Some(cert), Some(key)) => {
                if cert.trim().is_empty() {
                    anyhow::bail!("tls_cert_path must not be empty when set");
                }
                if key.trim().is_empty() {
                    anyhow::bail!("tls_key_path must not be empty when set");
                }
            }
            (Some(_), None) => {
                anyhow::bail!("tls_key_path is required when tls_cert_path is set");
            }
            (None, Some(_)) => {
                anyhow::bail!("tls_cert_path is required when tls_key_path is set");
            }
            (None, None) => {}
        }
        Ok(())
    }

    pub(super) fn tls_enabled(&self) -> bool {
        self.tls_cert_path.is_some() && self.tls_key_path.is_some()
    }

    pub(super) fn build_hmac_signer(&self) -> Http01HmacSigner {
        Http01HmacSigner::new(&self.hmac_secret)
    }
}

pub(super) fn load_settings(config_path: Option<&Path>) -> Result<ResponderSettings> {
    let settings = ResponderSettings::new(config_path)?;
    settings.validate()?;
    Ok(settings)
}

/// Reloads settings from disk and applies them to the running state.
///
/// Rejects transport-mode changes (plain HTTP ↔ TLS) because the
/// listener mode is fixed at startup.  A mode flip requires a process
/// restart; accepting it silently would leave the running listener out
/// of sync with the in-memory settings.
pub(super) async fn reload_settings(
    state: &ResponderState,
    config_path: Option<&Path>,
) -> Result<()> {
    let new_settings = load_settings(config_path)?;
    let current_tls = state.settings().await.tls_enabled();
    let new_tls = new_settings.tls_enabled();
    if current_tls != new_tls {
        anyhow::bail!(
            "transport mode change (TLS {} \u{2192} {}) requires a process restart; \
             keeping current settings",
            if current_tls { "enabled" } else { "disabled" },
            if new_tls { "enabled" } else { "disabled" },
        );
    }
    state.update_settings(new_settings).await;
    Ok(())
}

fn validate_socket_addr(value: &str, field_name: &str) -> Result<()> {
    value
        .parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|err| anyhow::anyhow!("{field_name} invalid: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_settings() -> ResponderSettings {
        ResponderSettings {
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
            admin_addr: DEFAULT_ADMIN_ADDR.to_string(),
            hmac_secret: "test-secret".to_string(),
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
            max_token_ttl_secs: DEFAULT_MAX_TOKEN_TTL_SECS,
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
            max_skew_secs: DEFAULT_MAX_SKEW_SECS,
            admin_rate_limit_requests: DEFAULT_ADMIN_RATE_LIMIT_REQUESTS,
            admin_rate_limit_window_secs: DEFAULT_ADMIN_RATE_LIMIT_WINDOW_SECS,
            admin_body_limit_bytes: DEFAULT_ADMIN_BODY_LIMIT_BYTES,
            tls_cert_path: None,
            tls_key_path: None,
        }
    }

    #[test]
    fn test_validate_rejects_empty_hmac_secret() {
        let mut settings = test_settings();
        settings.hmac_secret = "   ".to_string();

        let err = settings
            .validate()
            .expect_err("empty HMAC secret must be rejected");
        assert!(err.to_string().contains("hmac_secret"));
    }

    #[test]
    fn test_validate_rejects_invalid_admin_addr() {
        let mut settings = test_settings();
        settings.admin_addr = "not-an-address".to_string();

        let err = settings
            .validate()
            .expect_err("invalid admin address must be rejected");
        assert!(err.to_string().contains("admin_addr"));
    }

    #[test]
    fn test_validate_rejects_max_token_ttl_below_default_ttl() {
        let mut settings = test_settings();
        settings.max_token_ttl_secs = settings.token_ttl_secs - 1;

        let err = settings
            .validate()
            .expect_err("max token TTL below default token TTL must be rejected");
        assert!(err.to_string().contains("max_token_ttl_secs"));
    }

    #[test]
    fn test_validate_rejects_cert_without_key() {
        let mut settings = test_settings();
        settings.tls_cert_path = Some("/path/to/cert.pem".to_string());

        let err = settings
            .validate()
            .expect_err("cert without key must be rejected");
        assert!(err.to_string().contains("tls_key_path"));
    }

    #[test]
    fn test_validate_rejects_key_without_cert() {
        let mut settings = test_settings();
        settings.tls_key_path = Some("/path/to/key.pem".to_string());

        let err = settings
            .validate()
            .expect_err("key without cert must be rejected");
        assert!(err.to_string().contains("tls_cert_path"));
    }

    #[test]
    fn test_validate_accepts_both_tls_paths() {
        let mut settings = test_settings();
        settings.tls_cert_path = Some("/path/to/cert.pem".to_string());
        settings.tls_key_path = Some("/path/to/key.pem".to_string());
        settings
            .validate()
            .expect("both TLS paths must be accepted");
    }

    #[test]
    fn test_validate_rejects_empty_tls_cert_path() {
        let mut settings = test_settings();
        settings.tls_cert_path = Some("  ".to_string());
        settings.tls_key_path = Some("/path/to/key.pem".to_string());

        let err = settings
            .validate()
            .expect_err("empty cert path must be rejected");
        assert!(err.to_string().contains("tls_cert_path"));
    }

    #[test]
    fn test_tls_enabled_returns_false_by_default() {
        let settings = test_settings();
        assert!(!settings.tls_enabled());
    }

    #[test]
    fn test_tls_enabled_returns_true_when_configured() {
        let mut settings = test_settings();
        settings.tls_cert_path = Some("/cert.pem".to_string());
        settings.tls_key_path = Some("/key.pem".to_string());
        assert!(settings.tls_enabled());
    }

    #[test]
    fn test_validate_rejects_zero_admin_body_limit() {
        let mut settings = test_settings();
        settings.admin_body_limit_bytes = 0;

        let err = settings
            .validate()
            .expect_err("zero admin body limit must be rejected");
        assert!(err.to_string().contains("admin_body_limit_bytes"));
    }

    #[tokio::test]
    async fn test_reload_rejects_enabling_tls_at_runtime() {
        let state = super::super::state::ResponderState::shared(test_settings());
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("responder.toml");
        std::fs::write(
            &config_path,
            "\
hmac_secret = \"test-secret\"
tls_cert_path = \"/cert.pem\"
tls_key_path = \"/key.pem\"
",
        )
        .unwrap();

        let err = reload_settings(&state, Some(&config_path))
            .await
            .expect_err("enabling TLS at runtime must be rejected");
        assert!(
            err.to_string().contains("transport mode change"),
            "error must mention transport mode change: {err}"
        );
    }

    #[tokio::test]
    async fn test_reload_rejects_disabling_tls_at_runtime() {
        let mut tls_settings = test_settings();
        tls_settings.tls_cert_path = Some("/cert.pem".to_string());
        tls_settings.tls_key_path = Some("/key.pem".to_string());
        let state = super::super::state::ResponderState::shared(tls_settings);
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("responder.toml");
        std::fs::write(&config_path, "hmac_secret = \"test-secret\"\n").unwrap();

        let err = reload_settings(&state, Some(&config_path))
            .await
            .expect_err("disabling TLS at runtime must be rejected");
        assert!(
            err.to_string().contains("transport mode change"),
            "error must mention transport mode change: {err}"
        );
    }
}
