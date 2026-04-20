use std::path::Path;

use anyhow::{Context, Result};

use super::local_config::{
    DOCKER_RENDERED_CA_BUNDLE, SIDECAR_DAEMON_CERTS_MOUNT, SIDECAR_DAEMON_CONFIG_MOUNT,
};
use super::{OPENBAO_AGENT_DOCKER_CONFIG_FILENAME, OPENBAO_SERVICE_CONFIG_DIR};
use crate::cli::args::ServiceAgentStartArgs;
use crate::commands::infra::run_docker;
use crate::commands::init::{compose_has_openbao, resolve_openbao_agent_addr};
use crate::i18n::Messages;
use crate::state::{DeliveryMode, DeployType, ServiceEntry, StateFile};

/// Compose project name, matching the convention used by `bootroot init`.
const COMPOSE_PROJECT: &str = "bootroot";

/// Docker network created by `docker compose -p bootroot`.
const COMPOSE_NETWORK: &str = "bootroot_default";

/// Compose override filename written per service.
const SERVICE_COMPOSE_OVERRIDE: &str = "docker-compose.override.yml";

/// Mount point inside service sidecar containers.
const SIDECAR_CONTAINER_MOUNT: &str = "/openbao/secrets";

/// Runs `bootroot service agent start`.
pub(crate) fn run_service_agent_start(
    args: &ServiceAgentStartArgs,
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
    write_service_agent_compose_override(
        compose_file,
        secrets_dir,
        &service_openbao_dir,
        entry,
        &state.openbao_url,
        messages,
    )?;

    let service_name = format!("openbao-agent-{}", args.service_name);
    apply_service_agent_compose_override(compose_file, &override_path, &service_name, messages)?;

    println!(
        "{}",
        messages.service_agent_start_completed(&args.service_name)
    );
    Ok(())
}

/// Writes a per-service compose override that defines the sidecar agent
/// container.
fn write_service_agent_compose_override(
    compose_file: &Path,
    secrets_dir: &Path,
    service_openbao_dir: &Path,
    entry: &ServiceEntry,
    openbao_url: &str,
    messages: &Messages,
) -> Result<()> {
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
    name: {COMPOSE_NETWORK}
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

/// Calls `docker compose` to bring up the service agent sidecar.
fn apply_service_agent_compose_override(
    compose_file: &Path,
    override_path: &Path,
    service_name: &str,
    messages: &Messages,
) -> Result<()> {
    let compose_str = compose_file.to_string_lossy();
    let override_str = override_path.to_string_lossy();
    let args = [
        "compose",
        "-p",
        COMPOSE_PROJECT,
        "-f",
        &compose_str,
        "-f",
        &override_str,
        "up",
        "-d",
        service_name,
    ];
    run_docker(&args, "docker compose service agent start", messages)?;
    Ok(())
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
            contents.contains("bootroot_default"),
            "must reference bootroot_default network"
        );
        assert!(
            !contents.contains("VAULT_CACERT"),
            "http must not set VAULT_CACERT"
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
}
