use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::fs_util;

use super::{OPENBAO_AGENT_CONTAINER_PREFIX, RENDERED_FILE_POLL_INTERVAL, RotateContext};
use crate::cli::prompt::Prompt;
use crate::commands::infra::run_docker;
use crate::i18n::Messages;
use crate::state::{DeliveryMode, ServiceEntry};

pub(super) fn confirm_action(prompt: &str, auto_confirm: bool, messages: &Messages) -> Result<()> {
    if auto_confirm {
        return Ok(());
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout();
    let mut prompt_reader = Prompt::new(&mut input, &mut output, messages);
    let response = prompt_reader.prompt_text(prompt, None)?;
    let normalized = response.trim().to_ascii_lowercase();
    if normalized == "y" || normalized == "yes" {
        Ok(())
    } else {
        anyhow::bail!(messages.error_operation_cancelled());
    }
}

pub(super) fn ensure_non_empty(value: &str, messages: &Messages) -> Result<String> {
    if value.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    Ok(value.trim().to_string())
}

pub(super) fn ensure_file_exists(path: &Path, messages: &Messages) -> Result<()> {
    if path.exists() {
        Ok(())
    } else {
        anyhow::bail!(messages.error_file_missing(&path.display().to_string()));
    }
}

pub(super) async fn write_secret_file(
    path: &Path,
    contents: &str,
    messages: &Messages,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs_util::ensure_secrets_dir(parent).await?;
    }
    tokio::fs::write(path, contents)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    fs_util::set_key_permissions(path).await?;
    Ok(())
}

pub(super) async fn write_secret_id_atomic(
    path: &Path,
    value: &str,
    messages: &Messages,
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(messages.error_parent_not_found(&path.display().to_string()))
    })?;
    if parent.as_os_str().is_empty() {
        anyhow::bail!(messages.error_parent_not_found(&path.display().to_string()));
    }
    fs_util::ensure_secrets_dir(parent).await?;
    let temp_path = temp_secret_path(path);
    tokio::fs::write(&temp_path, value)
        .await
        .with_context(|| messages.error_write_file_failed(&temp_path.display().to_string()))?;
    fs_util::set_key_permissions(&temp_path).await?;
    tokio::fs::rename(&temp_path, path)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

pub(super) fn temp_secret_path(path: &Path) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let file_name = path.file_name().map_or_else(
        || "secret_id".to_string(),
        |name| name.to_string_lossy().to_string(),
    );
    let temp_name = format!("{file_name}.tmp.{pid}.{nanos}");
    path.with_file_name(temp_name)
}

pub(super) fn restart_container(container: &str, messages: &Messages) -> Result<()> {
    let args = ["restart", container];
    run_docker(&args, "docker restart", messages)
}

pub(super) fn restart_compose_service(
    compose_file: &Path,
    service: &str,
    messages: &Messages,
) -> Result<()> {
    let compose_file = compose_file.to_string_lossy();
    let args = ["compose", "-f", compose_file.as_ref(), "restart", service];
    run_docker(&args, "docker compose restart", messages)
}

pub(super) fn reload_compose_service(
    compose_file: &Path,
    service: &str,
    messages: &Messages,
) -> Result<()> {
    let compose_file = compose_file.to_string_lossy();
    let args = [
        "compose",
        "-f",
        compose_file.as_ref(),
        "kill",
        "-s",
        "HUP",
        service,
    ];
    run_docker(&args, "docker compose kill", messages)
}

pub(super) async fn wait_for_rendered_file(
    path: &Path,
    expected: &str,
    timeout: Duration,
    messages: &Messages,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(contents) = tokio::fs::read_to_string(path).await
            && contents.contains(expected)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(messages.error_rendered_file_timeout(&path.display().to_string()));
        }
        tokio::time::sleep(RENDERED_FILE_POLL_INTERVAL).await;
    }
}

pub(super) use crate::commands::init::compose_has_responder;

pub(super) fn openbao_agent_container_name(service_name: &str) -> String {
    format!("{OPENBAO_AGENT_CONTAINER_PREFIX}-{service_name}")
}

pub(super) fn reload_openbao_agent(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    match entry.deploy_type {
        crate::state::DeployType::Docker => {
            let container = openbao_agent_container_name(&entry.service_name);
            run_docker(
                &["restart", &container],
                "docker restart OpenBao Agent",
                messages,
            )
        }
        crate::state::DeployType::Daemon => reload_openbao_agent_daemon(entry, messages),
    }
}

#[cfg(unix)]
fn reload_openbao_agent_daemon(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    let config_path = entry.agent_config_path.display().to_string();
    let status = std::process::Command::new("pkill")
        .args(["-HUP", "-f", &config_path])
        .status()
        .with_context(|| messages.error_command_run_failed("pkill -HUP"))?;
    if !status.success() {
        anyhow::bail!(messages.error_command_failed_status("pkill -HUP", &status.to_string()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reload_openbao_agent_daemon(_entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    anyhow::bail!(messages.error_command_run_failed("pkill -HUP"));
}

pub(super) fn signal_bootroot_agent(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    match entry.deploy_type {
        crate::state::DeployType::Docker => {
            let container = entry
                .container_name
                .as_deref()
                .filter(|name| !name.is_empty())
                .ok_or_else(|| anyhow::anyhow!(messages.error_service_container_name_required()))?;
            run_docker(
                &["restart", container],
                "docker restart bootroot-agent",
                messages,
            )
        }
        crate::state::DeployType::Daemon => signal_bootroot_agent_daemon(entry, messages),
    }
}

#[cfg(unix)]
fn signal_bootroot_agent_daemon(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    let config_path = entry.agent_config_path.display().to_string();
    let status = std::process::Command::new("pkill")
        .args(["-HUP", "-f", &config_path])
        .status()
        .with_context(|| messages.error_command_run_failed("pkill -HUP"))?;
    if !status.success() {
        anyhow::bail!(messages.error_command_failed_status("pkill -HUP", &status.to_string()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn signal_bootroot_agent_daemon(_entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    anyhow::bail!(messages.error_command_run_failed("pkill -HUP"));
}

pub(super) fn try_restart_container(container: &str) -> Result<()> {
    let status = std::process::Command::new("docker")
        .args(["restart", container])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        anyhow::bail!("container {container} not found or restart failed");
    }
    Ok(())
}

pub(super) async fn restart_service_sidecar_agents(
    ctx: &RotateContext,
    expected_hmac: &str,
    messages: &Messages,
) -> Result<()> {
    let mut agent_config_paths = std::collections::BTreeSet::new();
    for entry in ctx.state.services.values() {
        if !matches!(entry.delivery_mode, DeliveryMode::LocalFile) {
            println!(
                "{}",
                messages.rotate_sidecar_skip_remote(
                    &entry.service_name,
                    bootroot::openbao::STATIC_SECRET_RENDER_INTERVAL,
                )
            );
            continue;
        }
        let container = openbao_agent_container_name(&entry.service_name);
        let _ = try_restart_container(&container);
        agent_config_paths.insert(entry.agent_config_path.clone());
    }
    for path in &agent_config_paths {
        wait_for_rendered_file(path, expected_hmac, super::RENDERED_FILE_TIMEOUT, messages).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::Path;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::super::test_support::test_messages;
    use super::*;
    use crate::state::{DeployType, ServiceRoleEntry, StateFile};

    #[test]
    fn openbao_agent_container_name_uses_prefix() {
        let name = openbao_agent_container_name("api");
        assert_eq!(name, "bootroot-openbao-agent-api");
    }

    #[tokio::test]
    async fn write_secret_id_atomic_overwrites_contents() {
        let dir = tempdir().expect("tempdir");
        let secret_path = dir.path().join("app").join("secret_id");
        let messages = test_messages();

        write_secret_id_atomic(&secret_path, "old", &messages)
            .await
            .expect("initial write");
        write_secret_id_atomic(&secret_path, "new", &messages)
            .await
            .expect("overwrite");

        let contents = tokio::fs::read_to_string(&secret_path)
            .await
            .expect("read secret_id");
        assert_eq!(contents, "new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&secret_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn write_secret_id_atomic_requires_parent_dir() {
        let messages = test_messages();
        let err = write_secret_id_atomic(Path::new("secret_id"), "value", &messages)
            .await
            .expect_err("expected parent error");
        let err = err.to_string();
        assert!(err.contains("Parent directory not found"));
    }

    #[test]
    fn temp_secret_path_adds_suffix() {
        let path = Path::new("/tmp/secret_id");
        let temp = temp_secret_path(path);
        let name = temp.file_name().expect("filename").to_string_lossy();
        assert!(name.starts_with("secret_id.tmp."));
    }

    #[tokio::test]
    async fn wait_for_rendered_file_immediate() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("rendered.txt");
        std::fs::write(&path, "expected-value").expect("write file");
        let messages = test_messages();

        wait_for_rendered_file(
            &path,
            "expected-value",
            Duration::from_millis(500),
            &messages,
        )
        .await
        .expect("should return immediately when file already contains expected content");
    }

    #[tokio::test]
    async fn wait_for_rendered_file_timeout() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("never.txt");
        std::fs::write(&path, "wrong-content").expect("write file");
        let messages = test_messages();

        let err = wait_for_rendered_file(
            &path,
            "expected-value",
            Duration::from_millis(100),
            &messages,
        )
        .await
        .expect_err("should timeout when content never matches");
        assert!(err.to_string().contains("Timed out"));
    }

    fn make_service_entry(name: &str, delivery_mode: DeliveryMode) -> ServiceEntry {
        ServiceEntry {
            service_name: name.to_string(),
            deploy_type: DeployType::Docker,
            delivery_mode,
            hostname: "h".to_string(),
            domain: "d.com".to_string(),
            agent_config_path: PathBuf::from("agent.hcl"),
            cert_path: PathBuf::from("cert.pem"),
            key_path: PathBuf::from("key.pem"),
            instance_id: None,
            container_name: None,
            notes: None,
            post_renew_hooks: vec![],
            approle: ServiceRoleEntry {
                role_name: "r".to_string(),
                role_id: "id".to_string(),
                secret_id_path: PathBuf::from("s"),
                policy_name: "p".to_string(),
                secret_id_ttl: None,
                secret_id_wrap_ttl: None,
                token_bound_cidrs: None,
            },
        }
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn restart_service_sidecar_agents_skips_remote() {
        use super::super::test_support::{
            ScopedEnvVar, env_lock, path_with_prepend, write_fake_docker_script,
        };

        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir(&bin_dir).expect("create bin dir");
        let docker_path = bin_dir.join("docker");
        write_fake_docker_script(&docker_path);

        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(super::super::test_support::TEST_DOCKER_ARGS_ENV, &args_log);

        let mut services = BTreeMap::new();
        services.insert(
            "remote-svc".to_string(),
            make_service_entry("remote-svc", DeliveryMode::RemoteBootstrap),
        );

        let ctx = super::super::RotateContext {
            openbao_url: String::new(),
            kv_mount: String::new(),
            compose_file: PathBuf::new(),
            state: StateFile {
                openbao_url: String::new(),
                kv_mount: String::new(),
                secrets_dir: None,
                policies: BTreeMap::new(),
                approles: BTreeMap::new(),
                services,
                openbao_bind_addr: None,
                openbao_advertise_addr: None,
                http01_admin_bind_addr: None,
                http01_admin_advertise_addr: None,
                infra_certs: BTreeMap::new(),
            },
            paths: super::super::StatePaths::new(dir.path().to_path_buf()),
            state_dir: dir.path().to_path_buf(),
            state_file: dir.path().join("state.json"),
        };

        let messages = test_messages();
        restart_service_sidecar_agents(&ctx, "new-hmac", &messages)
            .await
            .expect("should succeed without docker restart");

        assert!(
            !args_log.exists(),
            "docker should not have been invoked for a remote service"
        );
    }

    #[test]
    fn signal_bootroot_agent_docker_uses_entry_container_name() {
        use super::super::test_support::{
            ScopedEnvVar, TEST_DOCKER_ARGS_ENV, env_lock, path_with_prepend,
            write_fake_docker_script,
        };

        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        std::fs::create_dir(&bin_dir).expect("create bin dir");
        let docker_path = bin_dir.join("docker");
        write_fake_docker_script(&docker_path);

        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let mut entry = make_service_entry("nginx-docker", DeliveryMode::LocalFile);
        entry.container_name = Some("my-nginx".to_string());

        signal_bootroot_agent(&entry, &test_messages())
            .expect("should invoke docker restart against entry.container_name");

        let logged = std::fs::read_to_string(&args_log).expect("read logged args");
        let args: Vec<&str> = logged.lines().collect();
        assert_eq!(args, vec!["restart", "my-nginx"]);
    }

    #[test]
    fn signal_bootroot_agent_docker_requires_container_name() {
        let entry = make_service_entry("nginx-docker", DeliveryMode::LocalFile);
        assert!(entry.container_name.is_none());

        let err = signal_bootroot_agent(&entry, &test_messages())
            .expect_err("missing container_name must fail fast");
        assert!(err.to_string().contains("container_name"));
    }
}
