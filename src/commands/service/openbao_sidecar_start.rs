use std::path::Path;
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};

use super::local_config::{
    DOCKER_RENDERED_CA_BUNDLE, SIDECAR_DAEMON_CERTS_MOUNT, SIDECAR_DAEMON_CONFIG_MOUNT,
};
use super::{OPENBAO_AGENT_DOCKER_CONFIG_FILENAME, OPENBAO_SERVICE_CONFIG_DIR};
use crate::cli::args::ServiceOpenbaoSidecarStartArgs;
use crate::commands::infra::run_docker;
use crate::commands::init::{
    OPENBAO_CONTAINER_NAME, compose_has_openbao, resolve_openbao_agent_addr,
};
use crate::i18n::Messages;
use crate::state::{DeliveryMode, DeployType, ServiceEntry, StateFile};

/// Compose override filename written per service.
const SERVICE_COMPOSE_OVERRIDE: &str = "docker-compose.override.yml";

/// Mount point inside service sidecar containers.
const SIDECAR_CONTAINER_MOUNT: &str = "/openbao/secrets";

/// Docker compose project label inspected on the `OpenBao` container.
const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";

/// Suffix appended to the discovered compose project to derive the
/// default docker network name (`<project>_default`).
const COMPOSE_DEFAULT_NETWORK_SUFFIX: &str = "_default";

/// Outcome of resolving the docker network and (optional) compose
/// project to use for the per-service sidecar.
#[derive(Debug)]
struct SidecarTopology {
    network: String,
    project: Option<String>,
}

/// Runs `bootroot service openbao-sidecar start`.
pub(crate) fn run_service_openbao_sidecar_start(
    args: &ServiceOpenbaoSidecarStartArgs,
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

    if entry.delivery_mode == DeliveryMode::RemoteBootstrap {
        anyhow::bail!(messages.error_service_remote_bootstrap(&args.service_name));
    }

    let secrets_dir = state.secrets_dir();
    let service_openbao_dir = secrets_dir
        .join(OPENBAO_SERVICE_CONFIG_DIR)
        .join(&args.service_name);
    let docker_config = service_openbao_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME);
    if !docker_config.exists() {
        anyhow::bail!(
            messages.error_service_agent_config_missing(&docker_config.display().to_string())
        );
    }

    let compose_file = &args.compose_file.compose_file;
    let override_path = service_openbao_dir.join(SERVICE_COMPOSE_OVERRIDE);

    if let Some(network) = args.openbao_network.as_deref() {
        validate_docker_network_name(network, messages)?;
    }

    let topology = resolve_sidecar_topology(
        compose_file,
        args.openbao_network.as_deref(),
        messages,
        &inspect_label_via_docker,
    )?;

    write_service_agent_compose_override(
        compose_file,
        secrets_dir,
        &service_openbao_dir,
        entry,
        &state.openbao_url,
        &topology.network,
        messages,
    )?;

    let service_name = format!("openbao-agent-{}", args.service_name);
    apply_service_agent_compose_override(
        compose_file,
        &override_path,
        &service_name,
        topology.project.as_deref(),
        messages,
    )?;

    println!(
        "{}",
        messages.service_openbao_sidecar_start_completed(&args.service_name)
    );
    Ok(())
}

/// Resolves the (network, project) pair driving the sidecar override
/// and the `docker compose -p` invocation. Implements the decision
/// matrix from issue #577.
fn resolve_sidecar_topology(
    compose_file: &Path,
    network_override: Option<&str>,
    messages: &Messages,
    inspect_label: &dyn Fn(&str, &str, &Messages) -> Result<LabelLookup>,
) -> Result<SidecarTopology> {
    let has_openbao = compose_has_openbao(compose_file, messages)?;
    match (has_openbao, network_override) {
        (true, Some(net)) => {
            let project = discover_compose_project(messages, inspect_label)?;
            Ok(SidecarTopology {
                network: net.to_string(),
                project: Some(project),
            })
        }
        (true, None) => {
            let project = discover_compose_project(messages, inspect_label)?;
            let network = format!("{project}{COMPOSE_DEFAULT_NETWORK_SUFFIX}");
            validate_docker_network_name(&network, messages)?;
            Ok(SidecarTopology {
                network,
                project: Some(project),
            })
        }
        (false, Some(net)) => Ok(SidecarTopology {
            network: net.to_string(),
            project: None,
        }),
        (false, None) => anyhow::bail!(messages.error_openbao_network_required_external()),
    }
}

/// Outcome of inspecting a docker container label.
enum LabelLookup {
    /// The container exists and the requested label is present.
    Present(String),
    /// The container exists but the requested label is missing or empty.
    MissingLabel,
    /// The container itself does not exist.
    ContainerNotFound,
}

/// Discovers the docker compose project name from the `OpenBao`
/// container's `com.docker.compose.project` label.
fn discover_compose_project(
    messages: &Messages,
    inspect_label: &dyn Fn(&str, &str, &Messages) -> Result<LabelLookup>,
) -> Result<String> {
    match inspect_label(OPENBAO_CONTAINER_NAME, COMPOSE_PROJECT_LABEL, messages)? {
        LabelLookup::Present(value) => {
            validate_docker_network_name(&value, messages)?;
            Ok(value)
        }
        LabelLookup::MissingLabel => {
            anyhow::bail!(messages.error_openbao_container_no_project_label())
        }
        LabelLookup::ContainerNotFound => {
            anyhow::bail!(messages.error_openbao_container_not_found())
        }
    }
}

/// Reads a single label from a docker container via `docker inspect`.
///
/// Distinguishes "container missing" from "label missing/empty" so the
/// caller can surface a precise error.
fn inspect_label_via_docker(
    container: &str,
    label: &str,
    _messages: &Messages,
) -> Result<LabelLookup> {
    let format_arg = format!("{{{{index .Config.Labels \"{label}\"}}}}");
    let output = ProcessCommand::new("docker")
        .args(["inspect", "--format", &format_arg, container])
        .output()
        .with_context(|| "failed to run `docker inspect`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.to_lowercase().contains("no such") {
            return Ok(LabelLookup::ContainerNotFound);
        }
        anyhow::bail!("`docker inspect` failed: {}", stderr.trim());
    }

    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    // `go template` renders missing/empty map values as `<no value>`.
    if value.is_empty() || value == "<no value>" {
        Ok(LabelLookup::MissingLabel)
    } else {
        Ok(LabelLookup::Present(value))
    }
}

/// Validates that `name` is safe to embed in YAML as a docker network
/// name. The whitelist matches docker's own accepted naming rules and
/// rejects characters (newline, colon, quote, ...) that could break
/// the override file.
fn validate_docker_network_name(name: &str, messages: &Messages) -> Result<()> {
    if !is_valid_docker_network_name(name) {
        anyhow::bail!(messages.error_invalid_docker_network_name(name));
    }
    Ok(())
}

fn is_valid_docker_network_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Writes a per-service compose override that defines the sidecar agent
/// container.
fn write_service_agent_compose_override(
    compose_file: &Path,
    secrets_dir: &Path,
    service_openbao_dir: &Path,
    entry: &ServiceEntry,
    openbao_url: &str,
    network_name: &str,
    messages: &Messages,
) -> Result<()> {
    // Defence in depth: never emit an override that would inject
    // arbitrary YAML even if a discovered value slipped past earlier
    // validation.
    validate_docker_network_name(network_name, messages)?;

    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;

    let has_openbao = compose_has_openbao(compose_file, messages)?;
    let depends_on = if has_openbao {
        "    depends_on:\n      - openbao\n"
    } else {
        ""
    };

    let meta = std::fs::metadata(&mount_root)
        .with_context(|| messages.error_resolve_path_failed(&mount_root.display().to_string()))?;
    let user = {
        use std::os::unix::fs::MetadataExt;
        format!("{}:{}", meta.uid(), meta.gid())
    };

    let docker_addr = resolve_openbao_agent_addr(openbao_url, has_openbao);

    let service_name = entry.service_name.as_str();
    let config_rel = service_openbao_dir
        .join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME)
        .strip_prefix(secrets_dir)
        .with_context(|| {
            messages.error_resolve_path_failed(&service_openbao_dir.display().to_string())
        })?
        .to_string_lossy()
        .to_string();
    let container_config_path = format!("{SIDECAR_CONTAINER_MOUNT}/{config_rel}");

    let compose_service = format!("openbao-agent-{service_name}");
    let container_name = format!("bootroot-openbao-agent-{service_name}");

    // When OpenBao uses TLS, also pass the CA bundle path so the
    // container picks up VAULT_CACERT automatically.  For daemon
    // deploy, the CA bundle is rendered at the daemon-certs mount; for
    // docker, it is rendered at the shared secrets mount.
    let ca_env = if docker_addr.starts_with("https://") {
        let ca_path = match entry.deploy_type {
            DeployType::Daemon => {
                format!("{SIDECAR_DAEMON_CERTS_MOUNT}/{DOCKER_RENDERED_CA_BUNDLE}")
            }
            DeployType::Docker => {
                format!(
                    "{SIDECAR_CONTAINER_MOUNT}/services/{service_name}/{DOCKER_RENDERED_CA_BUNDLE}"
                )
            }
        };
        format!("      - VAULT_CACERT={ca_path}\n")
    } else {
        String::new()
    };

    let extra_volumes = match entry.deploy_type {
        DeployType::Docker => String::new(),
        DeployType::Daemon => daemon_sidecar_bind_mounts(entry, messages)?,
    };

    let contents = format!(
        r#"services:
  {compose_service}:
    image: openbao/openbao:latest
    container_name: {container_name}
    user: "{user}"
    restart: always
    command: ["agent", "-config={container_config_path}"]
{depends_on}    environment:
      - VAULT_ADDR={docker_addr}
{ca_env}    volumes:
      - {secrets_path}:{SIDECAR_CONTAINER_MOUNT}
{extra_volumes}    networks:
      - default
networks:
  default:
    name: {network_name}
    external: true
"#,
        secrets_path = mount_root.display(),
    );

    let override_path = service_openbao_dir.join(SERVICE_COMPOSE_OVERRIDE);
    std::fs::write(&override_path, contents)
        .with_context(|| messages.error_write_file_failed(&override_path.display().to_string()))?;

    Ok(())
}

/// Builds the extra `volumes:` entries needed for daemon deploy so the
/// sidecar can render `agent.toml` and `ca-bundle.pem` directly at the
/// host paths `bootroot-agent` reads and `rotate` waits on.
fn daemon_sidecar_bind_mounts(entry: &ServiceEntry, messages: &Messages) -> Result<String> {
    let cfg_parent = entry.agent_config_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            messages.error_parent_not_found(&entry.agent_config_path.display().to_string())
        )
    })?;
    let cert_parent = entry.cert_path.parent().ok_or_else(|| {
        anyhow::anyhow!(messages.error_parent_not_found(&entry.cert_path.display().to_string()))
    })?;
    let cfg_parent_canon = std::fs::canonicalize(cfg_parent)
        .with_context(|| messages.error_resolve_path_failed(&cfg_parent.display().to_string()))?;
    let cert_parent_canon = std::fs::canonicalize(cert_parent)
        .with_context(|| messages.error_resolve_path_failed(&cert_parent.display().to_string()))?;
    Ok(format!(
        "      - {cfg}:{SIDECAR_DAEMON_CONFIG_MOUNT}:rw\n      - {certs}:{SIDECAR_DAEMON_CERTS_MOUNT}:rw\n",
        cfg = cfg_parent_canon.display(),
        certs = cert_parent_canon.display(),
    ))
}

/// Calls `docker compose` to bring up the per-service `OpenBao` Agent sidecar.
fn apply_service_agent_compose_override(
    compose_file: &Path,
    override_path: &Path,
    service_name: &str,
    project: Option<&str>,
    messages: &Messages,
) -> Result<()> {
    let compose_str = compose_file.to_string_lossy();
    let override_str = override_path.to_string_lossy();
    let args = build_compose_up_args(&compose_str, &override_str, service_name, project);
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    run_docker(
        &arg_refs,
        "docker compose service openbao-sidecar start",
        messages,
    )?;
    Ok(())
}

/// Builds the argument list for the `docker compose ... up -d <service>`
/// invocation. Extracted so the `-p` plumbing is unit-testable without
/// shelling out.
fn build_compose_up_args(
    compose_path: &str,
    override_path: &str,
    service_name: &str,
    project: Option<&str>,
) -> Vec<String> {
    let mut args: Vec<String> = vec!["compose".to_string()];
    if let Some(project) = project {
        args.push("-p".to_string());
        args.push(project.to_string());
    }
    args.extend([
        "-f".to_string(),
        compose_path.to_string(),
        "-f".to_string(),
        override_path.to_string(),
        "up".to_string(),
        "-d".to_string(),
        service_name.to_string(),
    ]);
    args
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;
    use crate::state::ServiceRoleEntry;

    fn docker_entry(service_name: &str) -> ServiceEntry {
        ServiceEntry {
            service_name: service_name.to_string(),
            deploy_type: DeployType::Docker,
            delivery_mode: DeliveryMode::LocalFile,
            hostname: "host".to_string(),
            domain: "example.com".to_string(),
            agent_config_path: PathBuf::from("/irrelevant/agent.toml"),
            cert_path: PathBuf::from("/irrelevant/cert.pem"),
            key_path: PathBuf::from("/irrelevant/key.pem"),
            instance_id: None,
            container_name: Some(format!("{service_name}-app")),
            notes: None,
            post_renew_hooks: Vec::new(),
            approle: ServiceRoleEntry {
                role_name: "r".to_string(),
                role_id: "id".to_string(),
                secret_id_path: PathBuf::from("/irrelevant/secret_id"),
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

    fn daemon_entry(
        service_name: &str,
        agent_config_path: PathBuf,
        cert_path: PathBuf,
    ) -> ServiceEntry {
        let key_path = cert_path.with_file_name("server.key");
        ServiceEntry {
            service_name: service_name.to_string(),
            deploy_type: DeployType::Daemon,
            delivery_mode: DeliveryMode::LocalFile,
            hostname: "host".to_string(),
            domain: "example.com".to_string(),
            agent_config_path,
            cert_path,
            key_path,
            instance_id: None,
            container_name: None,
            notes: None,
            post_renew_hooks: Vec::new(),
            approle: ServiceRoleEntry {
                role_name: "r".to_string(),
                role_id: "id".to_string(),
                secret_id_path: PathBuf::from("/irrelevant/secret_id"),
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

    #[test]
    fn compose_override_contains_service_definition() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();

        let compose_file = dir.path().join("docker-compose.yml");
        std::fs::write(
            &compose_file,
            "services:\n  openbao:\n    image: openbao/openbao:latest\n",
        )
        .unwrap();

        let svc_dir = secrets.join("openbao/services/myapp");
        std::fs::create_dir_all(&svc_dir).unwrap();
        std::fs::write(svc_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME), "").unwrap();

        let messages = crate::i18n::test_messages();
        write_service_agent_compose_override(
            &compose_file,
            &secrets,
            &svc_dir,
            &docker_entry("myapp"),
            "http://localhost:8200",
            "bootroot_default",
            &messages,
        )
        .unwrap();

        let override_path = svc_dir.join(SERVICE_COMPOSE_OVERRIDE);
        assert!(override_path.exists());
        let contents = std::fs::read_to_string(&override_path).unwrap();

        assert!(
            contents.contains("openbao-agent-myapp:"),
            "must define compose service"
        );
        assert!(
            contents.contains("container_name: bootroot-openbao-agent-myapp"),
            "must set container name"
        );
        assert!(
            contents.contains("VAULT_ADDR=http://bootroot-openbao:8200"),
            "must set VAULT_ADDR"
        );
        assert!(
            contents.contains("depends_on:"),
            "must depend on openbao when present in compose"
        );
        assert!(
            contents.contains("name: bootroot_default"),
            "must reference the supplied network"
        );
        assert!(
            !contents.contains("VAULT_CACERT"),
            "http must not set VAULT_CACERT"
        );
    }

    #[test]
    fn compose_override_uses_discovered_network_name() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();

        let compose_file = dir.path().join("docker-compose.yml");
        std::fs::write(
            &compose_file,
            "services:\n  openbao:\n    image: openbao/openbao:latest\n",
        )
        .unwrap();

        let svc_dir = secrets.join("openbao/services/myapp");
        std::fs::create_dir_all(&svc_dir).unwrap();
        std::fs::write(svc_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME), "").unwrap();

        let messages = crate::i18n::test_messages();
        write_service_agent_compose_override(
            &compose_file,
            &secrets,
            &svc_dir,
            &docker_entry("myapp"),
            "http://localhost:8200",
            "eloquent-solomon-19b6fe_default",
            &messages,
        )
        .unwrap();

        let contents = std::fs::read_to_string(svc_dir.join(SERVICE_COMPOSE_OVERRIDE)).unwrap();
        assert!(
            contents.contains("name: eloquent-solomon-19b6fe_default"),
            "must use the network name supplied by discovery"
        );
        assert!(
            !contents.contains("name: bootroot_default"),
            "must not fall back to the hardcoded bootroot_default name"
        );
    }

    #[test]
    fn compose_override_rejects_yaml_injection_via_network_name() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();

        let compose_file = dir.path().join("docker-compose.yml");
        std::fs::write(
            &compose_file,
            "services:\n  openbao:\n    image: openbao/openbao:latest\n",
        )
        .unwrap();

        let svc_dir = secrets.join("openbao/services/myapp");
        std::fs::create_dir_all(&svc_dir).unwrap();
        std::fs::write(svc_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME), "").unwrap();

        let messages = crate::i18n::test_messages();
        let err = write_service_agent_compose_override(
            &compose_file,
            &secrets,
            &svc_dir,
            &docker_entry("myapp"),
            "http://localhost:8200",
            "evil\n  rogue: true",
            &messages,
        )
        .expect_err("malicious network name must be rejected");
        assert!(
            err.to_string().contains("invalid docker network name"),
            "unexpected error: {err}"
        );
        assert!(
            !svc_dir.join(SERVICE_COMPOSE_OVERRIDE).exists(),
            "no override file must be written when validation fails"
        );
    }

    #[test]
    fn compose_override_includes_ca_env_for_https() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();

        let compose_file = dir.path().join("docker-compose.yml");
        std::fs::write(
            &compose_file,
            "services:\n  openbao:\n    image: openbao/openbao:latest\n",
        )
        .unwrap();

        let svc_dir = secrets.join("openbao/services/myapp");
        std::fs::create_dir_all(&svc_dir).unwrap();
        std::fs::write(svc_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME), "").unwrap();

        let messages = crate::i18n::test_messages();
        write_service_agent_compose_override(
            &compose_file,
            &secrets,
            &svc_dir,
            &docker_entry("myapp"),
            "https://192.168.1.10:8200",
            "bootroot_default",
            &messages,
        )
        .unwrap();

        let contents = std::fs::read_to_string(svc_dir.join(SERVICE_COMPOSE_OVERRIDE)).unwrap();

        assert!(
            contents.contains("VAULT_ADDR=https://bootroot-openbao:8200"),
            "must use https docker address"
        );
        assert!(
            contents.contains("VAULT_CACERT="),
            "https must set VAULT_CACERT"
        );
        assert!(
            contents.contains("depends_on:"),
            "must depend on openbao when present in compose"
        );
    }

    #[test]
    fn compose_override_keeps_original_addr_without_openbao_in_compose() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();

        let compose_file = dir.path().join("docker-compose.yml");
        std::fs::write(&compose_file, "services:\n  app:\n    image: app:latest\n").unwrap();

        let svc_dir = secrets.join("openbao/services/myapp");
        std::fs::create_dir_all(&svc_dir).unwrap();
        std::fs::write(svc_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME), "").unwrap();

        let messages = crate::i18n::test_messages();
        write_service_agent_compose_override(
            &compose_file,
            &secrets,
            &svc_dir,
            &docker_entry("myapp"),
            "https://192.168.1.10:8200",
            "external_net",
            &messages,
        )
        .unwrap();

        let contents = std::fs::read_to_string(svc_dir.join(SERVICE_COMPOSE_OVERRIDE)).unwrap();

        assert!(
            contents.contains("VAULT_ADDR=https://192.168.1.10:8200"),
            "must keep original address when openbao not in compose"
        );
        assert!(
            !contents.contains("depends_on:"),
            "must not depend on openbao when not in compose"
        );
    }

    #[test]
    fn compose_override_no_version_field() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();

        let compose_file = dir.path().join("docker-compose.yml");
        std::fs::write(&compose_file, "services:\n  app:\n    image: app:latest\n").unwrap();

        let svc_dir = secrets.join("openbao/services/test");
        std::fs::create_dir_all(&svc_dir).unwrap();
        std::fs::write(svc_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME), "").unwrap();

        let messages = crate::i18n::test_messages();
        write_service_agent_compose_override(
            &compose_file,
            &secrets,
            &svc_dir,
            &docker_entry("test"),
            "http://localhost:8200",
            "external_net",
            &messages,
        )
        .unwrap();

        let contents = std::fs::read_to_string(svc_dir.join(SERVICE_COMPOSE_OVERRIDE)).unwrap();

        assert!(
            !contents.contains("version:"),
            "must not include deprecated version field"
        );
    }

    #[test]
    fn compose_override_daemon_includes_config_and_cert_bind_mounts() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();

        let compose_file = dir.path().join("docker-compose.yml");
        std::fs::write(
            &compose_file,
            "services:\n  openbao:\n    image: openbao/openbao:latest\n",
        )
        .unwrap();

        let svc_dir = secrets.join("openbao/services/review");
        std::fs::create_dir_all(&svc_dir).unwrap();
        std::fs::write(svc_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME), "").unwrap();

        let daemon_config_dir = dir.path().join("config");
        std::fs::create_dir_all(&daemon_config_dir).unwrap();
        let daemon_cert_dir = dir.path().join("certs");
        std::fs::create_dir_all(&daemon_cert_dir).unwrap();

        let entry = daemon_entry(
            "review",
            daemon_config_dir.join("review-agent.toml"),
            daemon_cert_dir.join("review.crt"),
        );

        let messages = crate::i18n::test_messages();
        write_service_agent_compose_override(
            &compose_file,
            &secrets,
            &svc_dir,
            &entry,
            "http://localhost:8200",
            "bootroot_default",
            &messages,
        )
        .unwrap();

        let contents = std::fs::read_to_string(svc_dir.join(SERVICE_COMPOSE_OVERRIDE)).unwrap();

        let canon_config_dir = std::fs::canonicalize(&daemon_config_dir).unwrap();
        let canon_cert_dir = std::fs::canonicalize(&daemon_cert_dir).unwrap();
        assert!(
            contents.contains(&format!(
                "- {}:{SIDECAR_DAEMON_CONFIG_MOUNT}:rw",
                canon_config_dir.display()
            )),
            "daemon compose override must bind-mount agent_config parent at {SIDECAR_DAEMON_CONFIG_MOUNT}: {contents}"
        );
        assert!(
            contents.contains(&format!(
                "- {}:{SIDECAR_DAEMON_CERTS_MOUNT}:rw",
                canon_cert_dir.display()
            )),
            "daemon compose override must bind-mount cert parent at {SIDECAR_DAEMON_CERTS_MOUNT}: {contents}"
        );
    }

    #[test]
    fn compose_override_docker_omits_daemon_bind_mounts() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();

        let compose_file = dir.path().join("docker-compose.yml");
        std::fs::write(&compose_file, "services:\n  app:\n    image: app:latest\n").unwrap();

        let svc_dir = secrets.join("openbao/services/myapp");
        std::fs::create_dir_all(&svc_dir).unwrap();
        std::fs::write(svc_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME), "").unwrap();

        let messages = crate::i18n::test_messages();
        write_service_agent_compose_override(
            &compose_file,
            &secrets,
            &svc_dir,
            &docker_entry("myapp"),
            "http://localhost:8200",
            "external_net",
            &messages,
        )
        .unwrap();

        let contents = std::fs::read_to_string(svc_dir.join(SERVICE_COMPOSE_OVERRIDE)).unwrap();
        assert!(
            !contents.contains(SIDECAR_DAEMON_CONFIG_MOUNT),
            "docker deploy must not mount {SIDECAR_DAEMON_CONFIG_MOUNT}: {contents}"
        );
        assert!(
            !contents.contains(SIDECAR_DAEMON_CERTS_MOUNT),
            "docker deploy must not mount {SIDECAR_DAEMON_CERTS_MOUNT}: {contents}"
        );
    }

    #[test]
    fn compose_override_daemon_https_uses_sidecar_mount_for_vault_cacert() {
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();

        let compose_file = dir.path().join("docker-compose.yml");
        std::fs::write(
            &compose_file,
            "services:\n  openbao:\n    image: openbao/openbao:latest\n",
        )
        .unwrap();

        let svc_dir = secrets.join("openbao/services/review");
        std::fs::create_dir_all(&svc_dir).unwrap();
        std::fs::write(svc_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME), "").unwrap();

        let daemon_config_dir = dir.path().join("config");
        std::fs::create_dir_all(&daemon_config_dir).unwrap();
        let daemon_cert_dir = dir.path().join("certs");
        std::fs::create_dir_all(&daemon_cert_dir).unwrap();

        let entry = daemon_entry(
            "review",
            daemon_config_dir.join("review-agent.toml"),
            daemon_cert_dir.join("review.crt"),
        );

        let messages = crate::i18n::test_messages();
        write_service_agent_compose_override(
            &compose_file,
            &secrets,
            &svc_dir,
            &entry,
            "https://localhost:8200",
            "bootroot_default",
            &messages,
        )
        .unwrap();

        let contents = std::fs::read_to_string(svc_dir.join(SERVICE_COMPOSE_OVERRIDE)).unwrap();
        assert!(
            contents.contains(&format!(
                "VAULT_CACERT={SIDECAR_DAEMON_CERTS_MOUNT}/ca-bundle.pem"
            )),
            "daemon VAULT_CACERT must point at the daemon-certs mount: {contents}"
        );
    }

    fn write_compose_with_openbao(dir: &Path) -> std::path::PathBuf {
        let compose_file = dir.join("docker-compose.yml");
        std::fs::write(
            &compose_file,
            "services:\n  openbao:\n    image: openbao/openbao:latest\n",
        )
        .unwrap();
        compose_file
    }

    fn write_compose_without_openbao(dir: &Path) -> std::path::PathBuf {
        let compose_file = dir.join("docker-compose.yml");
        std::fs::write(&compose_file, "services:\n  app:\n    image: app:latest\n").unwrap();
        compose_file
    }

    #[test]
    fn topology_present_unset_uses_discovered_project_and_default_network() {
        let dir = tempdir().unwrap();
        let compose_file = write_compose_with_openbao(dir.path());
        let messages = crate::i18n::test_messages();
        let lookup = |_: &str, _: &str, _: &Messages| Ok(LabelLookup::Present("custom".into()));
        let topo = resolve_sidecar_topology(&compose_file, None, &messages, &lookup).unwrap();
        assert_eq!(topo.network, "custom_default");
        assert_eq!(topo.project.as_deref(), Some("custom"));
    }

    #[test]
    fn topology_present_set_uses_override_network_and_discovered_project() {
        let dir = tempdir().unwrap();
        let compose_file = write_compose_with_openbao(dir.path());
        let messages = crate::i18n::test_messages();
        let lookup = |_: &str, _: &str, _: &Messages| Ok(LabelLookup::Present("custom".into()));
        let topo =
            resolve_sidecar_topology(&compose_file, Some("ops_net"), &messages, &lookup).unwrap();
        assert_eq!(topo.network, "ops_net");
        assert_eq!(topo.project.as_deref(), Some("custom"));
    }

    #[test]
    fn topology_absent_unset_errors_requesting_override() {
        let dir = tempdir().unwrap();
        let compose_file = write_compose_without_openbao(dir.path());
        let messages = crate::i18n::test_messages();
        let lookup = |_: &str, _: &str, _: &Messages| {
            panic!("docker inspect must not be invoked when openbao is absent");
        };
        let err = resolve_sidecar_topology(&compose_file, None, &messages, &lookup)
            .expect_err("missing override must error");
        assert!(
            err.to_string().contains("--openbao-network"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn topology_absent_set_uses_override_network_and_no_project() {
        let dir = tempdir().unwrap();
        let compose_file = write_compose_without_openbao(dir.path());
        let messages = crate::i18n::test_messages();
        let lookup = |_: &str, _: &str, _: &Messages| {
            panic!("docker inspect must not be invoked when openbao is absent");
        };
        let topo =
            resolve_sidecar_topology(&compose_file, Some("ops_net"), &messages, &lookup).unwrap();
        assert_eq!(topo.network, "ops_net");
        assert!(topo.project.is_none());
    }

    #[test]
    fn topology_present_unset_surfaces_container_not_found() {
        let dir = tempdir().unwrap();
        let compose_file = write_compose_with_openbao(dir.path());
        let messages = crate::i18n::test_messages();
        let lookup = |_: &str, _: &str, _: &Messages| Ok(LabelLookup::ContainerNotFound);
        let err = resolve_sidecar_topology(&compose_file, None, &messages, &lookup)
            .expect_err("missing container must error");
        assert!(
            err.to_string().contains("bootroot-openbao"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn topology_present_unset_surfaces_missing_label() {
        let dir = tempdir().unwrap();
        let compose_file = write_compose_with_openbao(dir.path());
        let messages = crate::i18n::test_messages();
        let lookup = |_: &str, _: &str, _: &Messages| Ok(LabelLookup::MissingLabel);
        let err = resolve_sidecar_topology(&compose_file, None, &messages, &lookup)
            .expect_err("missing label must error");
        assert!(
            err.to_string().contains("com.docker.compose.project"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn discover_compose_project_rejects_invalid_label_value() {
        let messages = crate::i18n::test_messages();
        let lookup = |_: &str, _: &str, _: &Messages| Ok(LabelLookup::Present("evil\nname".into()));
        let err = discover_compose_project(&messages, &lookup)
            .expect_err("malicious label must be rejected");
        assert!(
            err.to_string().contains("invalid docker network name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_docker_network_name_accepts_safe_inputs() {
        let messages = crate::i18n::test_messages();
        for name in [
            "bootroot_default",
            "ops-net",
            "abc.def",
            "Project_42",
            "eloquent-solomon-19b6fe_default",
        ] {
            assert!(
                validate_docker_network_name(name, &messages).is_ok(),
                "{name} should be accepted"
            );
        }
    }

    #[test]
    fn build_compose_up_args_includes_project_when_supplied() {
        let args = build_compose_up_args(
            "/path/to/docker-compose.yml",
            "/path/to/override.yml",
            "openbao-agent-myapp",
            Some("myorg-prod"),
        );
        assert_eq!(
            args,
            vec![
                "compose",
                "-p",
                "myorg-prod",
                "-f",
                "/path/to/docker-compose.yml",
                "-f",
                "/path/to/override.yml",
                "up",
                "-d",
                "openbao-agent-myapp",
            ]
        );
    }

    #[test]
    fn build_compose_up_args_omits_project_when_not_supplied() {
        let args = build_compose_up_args(
            "/path/to/docker-compose.yml",
            "/path/to/override.yml",
            "openbao-agent-myapp",
            None,
        );
        assert!(
            !args.iter().any(|a| a == "-p"),
            "must not include -p flag when project is None: {args:?}"
        );
        assert_eq!(args.first().map(String::as_str), Some("compose"));
        assert_eq!(args.last().map(String::as_str), Some("openbao-agent-myapp"));
    }

    #[test]
    fn validate_docker_network_name_rejects_dangerous_inputs() {
        let messages = crate::i18n::test_messages();
        for name in [
            "",
            "_leading-underscore",
            "-leading-dash",
            ".leading-dot",
            "has space",
            "has\nnewline",
            "has:colon",
            "has\"quote",
            "has/slash",
        ] {
            assert!(
                validate_docker_network_name(name, &messages).is_err(),
                "{name} should be rejected"
            );
        }
    }
}
