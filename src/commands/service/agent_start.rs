use std::path::Path;

use anyhow::{Context, Result};

use super::{OPENBAO_AGENT_DOCKER_CONFIG_FILENAME, OPENBAO_SERVICE_CONFIG_DIR};
use crate::cli::args::ServiceAgentStartArgs;
use crate::commands::infra::run_docker;
use crate::commands::init::{compose_has_openbao, resolve_openbao_agent_addr};
use crate::i18n::Messages;
use crate::state::{DeliveryMode, DeployType, StateFile};

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

    if entry.deploy_type != DeployType::Docker {
        anyhow::bail!(messages.error_service_not_docker(&args.service_name));
    }

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
        &args.service_name,
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
    service_name: &str,
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
    // container picks up VAULT_CACERT automatically.
    let ca_env = if docker_addr.starts_with("https://") {
        let ca_path = format!("{SIDECAR_CONTAINER_MOUNT}/services/{service_name}/ca-bundle.pem");
        format!("      - VAULT_CACERT={ca_path}\n")
    } else {
        String::new()
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
    networks:
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
    use tempfile::tempdir;

    use super::*;

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
            "myapp",
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
            "myapp",
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
            "myapp",
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
            "test",
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
}
