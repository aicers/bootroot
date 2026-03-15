//! Defines the responder configuration loading, validation, and reload flow.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Parser;
use config::{Config, ConfigError, Environment, File};
use ring::hmac;
use serde::Deserialize;

use super::state::ResponderState;

const DEFAULT_CONFIG_PATH: &str = "responder.toml";
pub(super) const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:80";
pub(super) const DEFAULT_ADMIN_ADDR: &str = "0.0.0.0:8080";
pub(super) const DEFAULT_TOKEN_TTL_SECS: u64 = 300;
pub(super) const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 30;
pub(super) const DEFAULT_MAX_SKEW_SECS: u64 = 60;

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
    pub(super) cleanup_interval_secs: u64,
    pub(super) max_skew_secs: u64,
}

impl ResponderSettings {
    fn new(config_path: Option<&Path>) -> Result<Self, ConfigError> {
        let path =
            config_path.map_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH), Path::to_path_buf);

        Config::builder()
            .set_default("listen_addr", DEFAULT_LISTEN_ADDR)?
            .set_default("admin_addr", DEFAULT_ADMIN_ADDR)?
            .set_default("token_ttl_secs", DEFAULT_TOKEN_TTL_SECS)?
            .set_default("cleanup_interval_secs", DEFAULT_CLEANUP_INTERVAL_SECS)?
            .set_default("max_skew_secs", DEFAULT_MAX_SKEW_SECS)?
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
        if self.cleanup_interval_secs == 0 {
            anyhow::bail!("cleanup_interval_secs must be greater than 0");
        }
        if self.max_skew_secs == 0 {
            anyhow::bail!("max_skew_secs must be greater than 0");
        }
        validate_socket_addr(&self.listen_addr, "listen_addr")?;
        validate_socket_addr(&self.admin_addr, "admin_addr")?;
        Ok(())
    }

    pub(super) fn build_hmac_key(&self) -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, self.hmac_secret.as_bytes())
    }
}

pub(super) fn load_settings(config_path: Option<&Path>) -> Result<ResponderSettings> {
    let settings = ResponderSettings::new(config_path)?;
    settings.validate()?;
    Ok(settings)
}

pub(super) async fn reload_settings(
    state: &ResponderState,
    config_path: Option<&Path>,
) -> Result<()> {
    let settings = load_settings(config_path)?;
    state.update_settings(settings).await;
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
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
            max_skew_secs: DEFAULT_MAX_SKEW_SECS,
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
}
