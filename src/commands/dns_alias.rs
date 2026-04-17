use anyhow::{Context, Result};

use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::infra::{docker_output, run_docker};
use crate::i18n::Messages;
use crate::state::{ServiceEntry, StateFile};

/// Builds the HTTP-01 DNS alias FQDN from a service entry.
///
/// Returns `None` when `instance_id` is absent.
pub(crate) fn dns_alias_for_entry(entry: &ServiceEntry) -> Option<String> {
    let instance_id = entry.instance_id.as_deref()?;
    Some(format!(
        "{}.{}.{}.{}",
        instance_id, entry.service_name, entry.hostname, entry.domain
    ))
}

/// Collects DNS aliases for all registered services.
pub(crate) fn collect_dns_aliases(state: &StateFile) -> Vec<String> {
    state
        .services
        .values()
        .filter_map(dns_alias_for_entry)
        .collect()
}

/// Registers the HTTP-01 DNS alias for a newly added service.
///
/// Collects all aliases (existing + new) and applies them to the
/// `bootroot-http01` container by disconnecting and reconnecting
/// it on its Docker network with the full alias set.
pub(crate) fn register_dns_alias(state: &StateFile, messages: &Messages) -> Result<()> {
    let aliases = collect_dns_aliases(state);
    if aliases.is_empty() {
        return Ok(());
    }
    apply_dns_aliases(&aliases, messages)
}

/// Replays all DNS aliases from `state.json` onto the running
/// `bootroot-http01` container.
///
/// Intended for use after `infra up` to restore aliases that were
/// lost during a container restart.
pub(crate) fn replay_dns_aliases(state: &StateFile, messages: &Messages) -> Result<()> {
    let aliases = collect_dns_aliases(state);
    if aliases.is_empty() {
        return Ok(());
    }
    println!("{}", messages.dns_alias_replaying(aliases.len()));
    apply_dns_aliases(&aliases, messages)
}

/// Applies all DNS aliases to the `bootroot-http01` container at runtime.
///
/// Disconnects the container from its compose network and reconnects
/// it with all provided aliases plus the original service name.  If the
/// reconnect fails, a rollback reconnect (without aliases) is attempted
/// so the responder is never left detached from the network.
///
/// Returns `Ok(())` for all cases where the container remains connected
/// to the network (including when aliases could not be applied).
/// Returns `Err` only when the container is left detached from the
/// network (disconnect succeeded but both reconnect and rollback failed).
fn apply_dns_aliases(aliases: &[String], messages: &Messages) -> Result<()> {
    let Ok(container_id) = find_responder_container(messages) else {
        eprintln!("{}", messages.dns_alias_responder_not_running());
        return Ok(());
    };
    let Ok(network) = find_container_network(&container_id, messages) else {
        eprintln!(
            "{}",
            messages
                .dns_alias_connect_recovered(&messages.dns_alias_network_not_found(&container_id))
        );
        return Ok(());
    };

    if let Err(err) = run_docker(
        &["network", "disconnect", &network, &container_id],
        "docker network disconnect",
        messages,
    ) {
        // Disconnect failed — the container is still connected
        // (possibly was never on this network).  Not critical.
        eprintln!("{}", messages.dns_alias_connect_recovered(&err.to_string()));
        return Ok(());
    }

    let mut args: Vec<&str> = vec!["network", "connect"];
    // Preserve the compose service name so other containers can still
    // reach bootroot-http01 by name after the reconnect.
    args.extend(["--alias", RESPONDER_SERVICE_NAME]);
    for alias in aliases {
        args.extend(["--alias", alias]);
    }
    args.push(&network);
    args.push(&container_id);

    if let Err(err) = run_docker(&args, "docker network connect", messages) {
        // Reconnect failed — attempt rollback to restore network
        // connectivity without aliases so the responder stays reachable.
        eprintln!("{}", messages.dns_alias_connect_rollback());
        if let Err(rollback_err) = run_docker(
            &[
                "network",
                "connect",
                "--alias",
                RESPONDER_SERVICE_NAME,
                &network,
                &container_id,
            ],
            "docker network connect (rollback)",
            messages,
        ) {
            // Rollback also failed — responder is detached from the
            // network.  Propagate as a hard error so the caller does
            // not report success.
            eprintln!(
                "{}",
                messages.dns_alias_rollback_failed(&network, &rollback_err.to_string())
            );
            return Err(err).with_context(|| messages.dns_alias_connect_failed());
        }
        // Rollback succeeded — connectivity is restored but aliases
        // were not applied.  Warn and return Ok so the caller can
        // continue; aliases can be retried with `bootroot infra up`.
        eprintln!("{}", messages.dns_alias_connect_recovered(&err.to_string()));
        return Ok(());
    }

    for alias in aliases {
        println!("{}", messages.dns_alias_registered(alias));
    }
    Ok(())
}

/// Finds the container ID for the `bootroot-http01` service.
fn find_responder_container(messages: &Messages) -> Result<String> {
    let label = format!("com.docker.compose.service={RESPONDER_SERVICE_NAME}");
    let label_filter = format!("label={label}");
    let output = docker_output(&["ps", "-q", "-f", &label_filter], messages)?;
    let id = output.trim().to_string();
    if id.is_empty() {
        anyhow::bail!(messages.dns_alias_responder_not_running());
    }
    // If multiple lines are returned (shouldn't happen in normal usage),
    // take the first one.
    Ok(id.lines().next().unwrap_or_default().trim().to_string())
}

/// Discovers the Docker network the container is attached to.
fn find_container_network(container_id: &str, messages: &Messages) -> Result<String> {
    let output = docker_output(
        &[
            "inspect",
            "--format",
            "{{range $k, $v := .NetworkSettings.Networks}}{{printf \"%s\\n\" $k}}{{end}}",
            container_id,
        ],
        messages,
    )?;
    output
        .lines()
        .find(|line| !line.is_empty())
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!(messages.dns_alias_network_not_found(container_id)))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use super::*;
    use crate::state::{DeliveryMode, DeployType, ServiceEntry, ServiceRoleEntry, StateFile};

    fn sample_entry(name: &str, instance_id: Option<&str>) -> ServiceEntry {
        ServiceEntry {
            service_name: name.to_string(),
            deploy_type: DeployType::Docker,
            delivery_mode: DeliveryMode::LocalFile,
            hostname: "host1".to_string(),
            domain: "test.local".to_string(),
            agent_config_path: PathBuf::from("/etc/agent.toml"),
            cert_path: PathBuf::from("/certs/cert.pem"),
            key_path: PathBuf::from("/certs/key.pem"),
            instance_id: instance_id.map(str::to_string),
            container_name: Some("ctr".to_string()),
            notes: None,
            post_renew_hooks: Vec::new(),
            approle: ServiceRoleEntry {
                role_name: "r".to_string(),
                role_id: "id".to_string(),
                secret_id_path: PathBuf::from("/s"),
                policy_name: "p".to_string(),
                secret_id_ttl: None,
                secret_id_wrap_ttl: None,
                token_bound_cidrs: None,
            },
        }
    }

    #[test]
    fn dns_alias_for_entry_with_instance_id() {
        let entry = sample_entry("review", Some("001"));
        assert_eq!(
            dns_alias_for_entry(&entry).as_deref(),
            Some("001.review.host1.test.local")
        );
    }

    #[test]
    fn dns_alias_for_entry_without_instance_id() {
        let entry = sample_entry("review", None);
        assert!(dns_alias_for_entry(&entry).is_none());
    }

    #[test]
    fn collect_dns_aliases_from_state() {
        let mut state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::default(),
            approles: BTreeMap::default(),
            services: BTreeMap::default(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: BTreeMap::new(),
        };
        state
            .services
            .insert("svc-a".to_string(), sample_entry("svc-a", Some("001")));
        state
            .services
            .insert("svc-b".to_string(), sample_entry("svc-b", Some("002")));
        state
            .services
            .insert("svc-c".to_string(), sample_entry("svc-c", None));

        let mut aliases = collect_dns_aliases(&state);
        aliases.sort_unstable();

        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases[0], "001.svc-a.host1.test.local");
        assert_eq!(aliases[1], "002.svc-b.host1.test.local");
    }
}
