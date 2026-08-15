use anyhow::{Context, Result};

use crate::commands::clean::{COMPOSE_PROJECT_LABEL, COMPOSE_SERVICE_LABEL};
use crate::commands::compose_project::ComposeIdentity;
use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::container_name::BootrootContainer;
use crate::commands::infra::{docker_output, run_docker};
use crate::i18n::Messages;
use crate::state::{ServiceEntry, StateFile};

/// What an alias registration attempt did, so a caller can report it
/// alongside its own result.
///
/// Deliberately not `#[must_use]`: `infra up` and `service remove`
/// discard it on purpose, and under `-D warnings` an ignored
/// `#[must_use]` value on a `expr?;` statement is a build failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DnsAliasOutcome {
    /// Aliases were attached to the responder.
    Registered { count: usize },
    /// The alias set was empty, so nothing was attempted.
    NothingToRegister,
    /// Registration was attempted and attached nothing; a warning was
    /// already printed on stderr.
    Skipped,
}

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
pub(crate) fn register_dns_alias(
    state: &StateFile,
    identity: &ComposeIdentity,
    messages: &Messages,
) -> Result<DnsAliasOutcome> {
    let aliases = collect_dns_aliases(state);
    if aliases.is_empty() {
        return Ok(DnsAliasOutcome::NothingToRegister);
    }
    apply_dns_aliases(&aliases, identity, messages)
}

/// Refreshes the responder's HTTP-01 alias set from `state.json`,
/// reconnecting the `bootroot-http01` container even when the resulting
/// alias set is empty.
///
/// Unlike [`register_dns_alias`], this does **not** short-circuit on an
/// empty alias list. `service remove` calls it after dropping a service
/// so the removed service's stale alias is cleared from the running
/// responder; removing the last (or only) alias-bearing service must
/// still reconnect the container with just the base
/// `bootroot-http01` service alias rather than leaving the orphaned
/// alias in place.
pub(crate) fn reconcile_dns_aliases(
    state: &StateFile,
    identity: &ComposeIdentity,
    messages: &Messages,
) -> Result<DnsAliasOutcome> {
    let aliases = collect_dns_aliases(state);
    apply_dns_aliases(&aliases, identity, messages)
}

/// Replays all DNS aliases from `state.json` onto the running
/// `bootroot-http01` container.
///
/// Intended for use after `infra up` to restore aliases that were
/// lost during a container restart.
pub(crate) fn replay_dns_aliases(
    state: &StateFile,
    identity: &ComposeIdentity,
    messages: &Messages,
) -> Result<DnsAliasOutcome> {
    let aliases = collect_dns_aliases(state);
    if aliases.is_empty() {
        return Ok(DnsAliasOutcome::NothingToRegister);
    }
    let container = identity.container(BootrootContainer::Http01);
    println!(
        "{}",
        messages.dns_alias_replaying(aliases.len(), &container)
    );
    apply_dns_aliases(&aliases, identity, messages)
}

/// Applies all DNS aliases to the `bootroot-http01` container at runtime.
///
/// Disconnects the container from its compose network and reconnects
/// it with all provided aliases plus the original service name.  If the
/// reconnect fails, a rollback reconnect (without aliases) is attempted
/// so the responder is never left detached from the network.
///
/// Returns `Ok` for all cases where the container remains connected to
/// the network: [`DnsAliasOutcome::Registered`] when the aliases were
/// attached, and [`DnsAliasOutcome::Skipped`] when they could not be,
/// which is the outcome every warning path below reports.  The warning
/// on stderr is the detail; the returned outcome is what lets a caller
/// state the result in its own summary.
/// Returns `Err` only when the container is left detached from the
/// network (disconnect succeeded but both reconnect and rollback failed).
fn apply_dns_aliases(
    aliases: &[String],
    identity: &ComposeIdentity,
    messages: &Messages,
) -> Result<DnsAliasOutcome> {
    // The operator-facing half of this function names the container the
    // recovery command has to target, which is this install's responder
    // and not the default instance's.
    let container = identity.container(BootrootContainer::Http01);
    let Some(container_id) = find_responder_container(identity.project(), messages)? else {
        eprintln!("{}", messages.dns_alias_responder_not_running(&container));
        return Ok(DnsAliasOutcome::Skipped);
    };
    let Ok(network) = find_container_network(&container_id, messages) else {
        eprintln!(
            "{}",
            messages
                .dns_alias_connect_recovered(&messages.dns_alias_network_not_found(&container_id))
        );
        return Ok(DnsAliasOutcome::Skipped);
    };

    if let Err(err) = run_docker(
        &["network", "disconnect", &network, &container_id],
        "docker network disconnect",
        messages,
    ) {
        // Disconnect failed — the container is still connected
        // (possibly was never on this network).  Not critical.
        eprintln!("{}", messages.dns_alias_connect_recovered(&err.to_string()));
        return Ok(DnsAliasOutcome::Skipped);
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
        eprintln!("{}", messages.dns_alias_connect_rollback(&container));
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
                messages.dns_alias_rollback_failed(&container, &network, &rollback_err.to_string())
            );
            return Err(err).with_context(|| messages.dns_alias_connect_failed(&container));
        }
        // Rollback succeeded — connectivity is restored but aliases
        // were not applied.  Warn and return Ok so the caller can
        // continue; aliases can be retried with `bootroot infra up`.
        eprintln!("{}", messages.dns_alias_connect_recovered(&err.to_string()));
        return Ok(DnsAliasOutcome::Skipped);
    }

    for alias in aliases {
        println!("{}", messages.dns_alias_registered(alias));
    }
    Ok(DnsAliasOutcome::Registered {
        count: aliases.len(),
    })
}

/// Finds the container ID of `project`'s HTTP-01 responder.
///
/// Filtering on the service label alone matches every co-located
/// instance's responder, and rewiring an arbitrary one would move another
/// instance's DNS aliases.  The project label narrows the match to this
/// install; if more than one container still matches, that is a state no
/// arbitrary choice can make correct, so it is reported rather than
/// guessed at.
///
/// Returns `Ok(None)` when the responder is simply not running — the
/// caller warns and carries on — and `Err` when the filter is ambiguous,
/// which is a hard failure rather than something to skip past.
fn find_responder_container(project: &str, messages: &Messages) -> Result<Option<String>> {
    let args = responder_lookup_args(project);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let Ok(output) = docker_output(&arg_refs, messages) else {
        return Ok(None);
    };
    select_responder_container(&output, project, messages)
}

/// Builds the `docker ps` argument vector that narrows the responder
/// lookup to `project`.
///
/// Split out from the Docker call so a test can assert the project
/// filter is actually passed, rather than re-deriving the string it
/// expects.
fn responder_lookup_args(project: &str) -> Vec<String> {
    vec![
        "ps".to_string(),
        "-q".to_string(),
        "-f".to_string(),
        format!("label={COMPOSE_SERVICE_LABEL}={RESPONDER_SERVICE_NAME}"),
        "-f".to_string(),
        format!("label={COMPOSE_PROJECT_LABEL}={project}"),
    ]
}

/// Picks the single container ID out of `docker ps -q` output.
///
/// Split out from the Docker call so the ambiguity rule is unit-testable
/// without a daemon.
fn select_responder_container(
    output: &str,
    project: &str,
    messages: &Messages,
) -> Result<Option<String>> {
    let ids: Vec<&str> = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    match ids.as_slice() {
        [] => Ok(None),
        [id] => Ok(Some((*id).to_string())),
        _ => anyhow::bail!(messages.dns_alias_responder_ambiguous(ids.len(), project)),
    }
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
    use crate::i18n::Messages;
    use crate::state::{DeliveryMode, ServiceEntry, ServiceRoleEntry, StateFile};

    fn sample_entry(name: &str, instance_id: Option<&str>) -> ServiceEntry {
        ServiceEntry {
            service_name: name.to_string(),
            delivery_mode: DeliveryMode::LocalFile,
            hostname: "host1".to_string(),
            domain: "test.local".to_string(),
            agent_config_path: PathBuf::from("/etc/agent.toml"),
            cert_path: PathBuf::from("/certs/cert.pem"),
            key_path: PathBuf::from("/certs/key.pem"),
            instance_id: instance_id.map(str::to_string),
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
            agent_email: None,
            agent_server: None,
            agent_responder_url: None,
            cert_group_gid: None,
        }
    }

    /// The lookup must filter on the compose project as well as the
    /// service, otherwise a co-located instance's responder matches too
    /// and `dns_alias` would rewire an arbitrary one.
    #[test]
    fn responder_lookup_filters_on_the_project_label() {
        assert_eq!(
            responder_lookup_args("insight"),
            vec![
                "ps",
                "-q",
                "-f",
                "label=com.docker.compose.service=bootroot-http01",
                "-f",
                "label=com.docker.compose.project=insight",
            ]
        );
    }

    #[test]
    fn responder_lookup_returns_the_single_match() {
        let messages = crate::i18n::test_messages();
        let id = select_responder_container("abc123\n", "insight", &messages).unwrap();
        assert_eq!(id.as_deref(), Some("abc123"));
    }

    #[test]
    fn responder_lookup_reports_no_container_as_not_running() {
        let messages = crate::i18n::test_messages();
        assert!(
            select_responder_container("\n  \n", "insight", &messages)
                .unwrap()
                .is_none()
        );
    }

    /// Two matches is a state no arbitrary choice can make correct, so
    /// it must be an error naming the project rather than "take the
    /// first line".
    #[test]
    fn responder_lookup_errors_on_an_ambiguous_match() {
        for locale in ["en", "ko"] {
            let messages = Messages::new(locale).unwrap();
            let err = select_responder_container("abc123\ndef456\n", "insight", &messages)
                .unwrap_err()
                .to_string();
            assert!(err.contains("insight"), "{locale}: {err}");
            assert!(err.contains('2'), "{locale}: {err}");
            assert!(!err.contains('{'), "{locale} left a placeholder: {err}");
        }
    }

    /// The short-circuit runs before Docker is touched, so it must
    /// report `NothingToRegister` rather than borrowing `Skipped`, which
    /// tells the operator to look for a warning that was never printed.
    #[test]
    fn register_dns_alias_reports_an_empty_alias_set_as_nothing_to_register() {
        let messages = crate::i18n::test_messages();
        let identity = ComposeIdentity::for_instance("insight");
        let state = StateFile::default();
        assert_eq!(
            register_dns_alias(&state, &identity, &messages).unwrap(),
            DnsAliasOutcome::NothingToRegister
        );
        assert_eq!(
            replay_dns_aliases(&state, &identity, &messages).unwrap(),
            DnsAliasOutcome::NothingToRegister
        );
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
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
