use std::path::PathBuf;
use std::sync::Arc;

pub mod acme;
pub mod agent_args;
pub mod config;
pub mod db;
pub mod eab;
pub mod fs_util;
pub mod hooks;
pub mod locale;
pub mod openbao;
pub mod profile;
pub mod tls;
pub mod toml_util;
pub mod utils;

mod daemon;

pub use agent_args::Args;

/// Runs the agent daemon loop for all profiles.
///
/// # Errors
/// Returns an error if issuance or shutdown handling fails.
pub async fn run_daemon(
    settings: Arc<config::Settings>,
    default_eab: Option<eab::EabCredentials>,
    config_path: Option<PathBuf>,
    insecure_mode: bool,
) -> anyhow::Result<()> {
    daemon::run_daemon(settings, default_eab, config_path, insecure_mode).await
}

/// Runs a single issuance pass for all profiles.
///
/// # Errors
/// Returns an error if any profile issuance fails.
pub async fn run_oneshot(
    settings: Arc<config::Settings>,
    default_eab: Option<eab::EabCredentials>,
    config_path: Option<PathBuf>,
    insecure_mode: bool,
) -> anyhow::Result<()> {
    daemon::run_oneshot(settings, default_eab, config_path, insecure_mode).await
}
