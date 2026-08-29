use std::path::PathBuf;
use std::sync::Arc;

pub mod acme;
pub mod agent_args;
pub mod cert_chain;
pub mod cert_group;
pub mod config;
mod daemon_messages;
pub mod db;
pub mod eab;
pub mod fs_util;
pub mod hooks;
pub mod host_port;
pub mod input_validation;
pub mod kv_payload;
pub mod locale;
pub mod openbao;
pub mod profile;
pub mod registrar;
pub(crate) mod registrar_certs;
// The renewal adapter drives the activated endpoint's TLS swap, and the
// endpoint exists on Linux alone.
#[cfg(target_os = "linux")]
pub(crate) mod registrar_renewal;
pub mod secret;
pub mod service_material;
pub mod tls;
pub mod toml_util;
pub mod trust_bootstrap;
pub mod utils;

mod daemon;
mod fast_poll;

pub use agent_args::Args;
pub use daemon::{DaemonInvocation, DaemonShutdown};
pub use daemon_messages::audit_store_reload_rejection_message;
pub use registrar::RegistrarEndpoint;
pub use registrar_certs::ensure_registrar_surface_certificates;

/// Runs the agent daemon loop for all profiles.
///
/// The invocation's [`DaemonShutdown`] and [`RegistrarEndpoint`] are the
/// caller's, held across `SIGHUP` reloads: the first so a reload is a
/// coordinated stop rather than an abort, the second so the activated
/// socket survives one with its inode unchanged.
///
/// # Errors
/// Returns an error if issuance or shutdown handling fails.
pub async fn run_daemon(invocation: DaemonInvocation) -> anyhow::Result<()> {
    daemon::run_daemon(invocation).await
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
