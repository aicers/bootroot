use anyhow::{Context, Result};

use crate::cli::args::ServiceOpenbaoSidecarRefreshArgs;
use crate::commands::infra::run_docker;
use crate::i18n::Messages;
use crate::state::{DeliveryMode, ServiceEntry, StateFile};

/// Restarts the per-service `OpenBao` Agent sidecar so consul-template
/// re-reads its KV sources. Operators run this after manual KV
/// maintenance (clearing stale EAB, rotating templated secrets, etc.)
/// because consul-template caches a previously-rendered value until
/// the agent process restarts.
pub(crate) fn run_service_openbao_sidecar_refresh(
    args: &ServiceOpenbaoSidecarRefreshArgs,
    messages: &Messages,
) -> Result<()> {
    let state_path = StateFile::default_path();
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;
    let entry = state
        .services
        .get(&args.service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(&args.service_name)))?;
    refresh_service_sidecar(entry, messages)
}

/// Restarts a single service's openbao-sidecar container. Branches on
/// [`DeliveryMode`]: `LocalFile` invokes `docker restart` against the
/// fixed `bootroot-openbao-agent-<svc>` container name; `RemoteBootstrap`
/// emits operator guidance (the sidecar lives on the remote host, where
/// bootroot has no signalling channel).
pub(crate) fn refresh_service_sidecar(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    match entry.delivery_mode {
        DeliveryMode::LocalFile => {
            let container = format!("bootroot-openbao-agent-{}", entry.service_name);
            let docker_args = ["restart", container.as_str()];
            run_docker(
                &docker_args,
                &format!("docker restart {container}"),
                messages,
            )?;
            println!(
                "openbao-sidecar refreshed for service {}",
                entry.service_name
            );
            Ok(())
        }
        DeliveryMode::RemoteBootstrap => {
            println!(
                "service {} uses remote-bootstrap delivery; restart the openbao-sidecar on the remote host (e.g. `docker restart bootroot-openbao-agent-{}`)",
                entry.service_name, entry.service_name
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::state::{DeployType, HookFailurePolicyEntry, PostRenewHookEntry, ServiceRoleEntry};

    fn entry(name: &str, mode: DeliveryMode) -> ServiceEntry {
        ServiceEntry {
            service_name: name.to_string(),
            deploy_type: DeployType::Daemon,
            delivery_mode: mode,
            hostname: "h".to_string(),
            domain: "d.com".to_string(),
            agent_config_path: PathBuf::from("agent.toml"),
            cert_path: PathBuf::from("cert.pem"),
            key_path: PathBuf::from("key.pem"),
            instance_id: None,
            container_name: None,
            notes: None,
            post_renew_hooks: Vec::<PostRenewHookEntry>::new(),
            approle: ServiceRoleEntry {
                role_name: "r".to_string(),
                role_id: "id".to_string(),
                secret_id_path: PathBuf::from("s"),
                policy_name: "p".to_string(),
                secret_id_ttl: None,
                secret_id_wrap_ttl: None,
                token_bound_cidrs: None,
            },
            agent_email: None,
            agent_server: None,
            agent_responder_url: None,
        }
    }

    /// Closes #588 §6 (remote branch): `RemoteBootstrap` services have
    /// no in-tree signalling channel, so refresh emits operator
    /// guidance instead of attempting `docker restart` against a
    /// container that does not exist locally.
    #[test]
    fn refresh_remote_bootstrap_returns_ok_without_docker_call() {
        let _ = HookFailurePolicyEntry::Continue; // ensure import is used
        let messages = crate::i18n::test_messages();
        let entry = entry("edge-proxy", DeliveryMode::RemoteBootstrap);
        // No docker mocking required: the remote branch must not shell
        // out. Test environments typically lack a `docker` binary, so
        // a regression here would fail loudly.
        refresh_service_sidecar(&entry, &messages).expect("remote-bootstrap must succeed");
    }
}
