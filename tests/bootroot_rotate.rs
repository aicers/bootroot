#![cfg(unix)]

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;
use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(unix)]
mod support;

const SERVICE_NAME: &str = "edge-proxy";
const SECONDARY_SERVICE_NAME: &str = "edge-alt";
const ROLE_NAME: &str = "bootroot-service-edge-proxy";
const ROLE_ID: &str = "role-edge-proxy";

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_stepca_password_passes_force_flag_to_change_pass() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");
    let secrets_dir = temp_dir.path().join("secrets");
    fs::create_dir_all(secrets_dir.join("secrets")).expect("create secrets key dir");
    fs::write(secrets_dir.join("password.txt"), "old-password").expect("write password");
    fs::write(secrets_dir.join("secrets").join("root_ca_key"), "root-key").expect("write root key");
    fs::write(
        secrets_dir.join("secrets").join("intermediate_ca_key"),
        "intermediate-key",
    )
    .expect("write intermediate key");

    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}\n").expect("write compose file");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    write_fake_docker(&bin_dir, &docker_log).expect("write fake docker");

    stub_openbao_for_stepca_password_rotation(&openbao, "new-pass-123").await;

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--yes",
            "stepca-password",
            "--new-password",
            "new-pass-123",
        ])
        .env("PATH", combined_path)
        .env("DOCKER_OUTPUT", &docker_log)
        .output()
        .expect("run rotate stepca-password");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("bootroot rotate: summary"));

    let docker_args_log = fs::read_to_string(&docker_log).expect("read docker log");
    let lines: Vec<&str> = docker_args_log.lines().collect();

    let change_pass_lines = lines
        .iter()
        .filter(|line| line.contains("crypto change-pass"))
        .copied()
        .collect::<Vec<_>>();
    assert_eq!(change_pass_lines.len(), 2, "docker log:\n{docker_args_log}");
    for line in change_pass_lines {
        assert!(line.contains(" -f"), "docker log line missing -f: {line}");
        assert!(
            line.contains("--password-file") && line.contains("--new-password-file"),
            "docker log line missing password file args: {line}"
        );
    }

    let restart_line = lines
        .iter()
        .find(|line| {
            line.contains("compose") && line.contains("restart") && line.contains("step-ca")
        })
        .copied()
        .unwrap_or_else(|| {
            panic!("restart step-ca command should be invoked\nlog:\n{docker_args_log}")
        });
    assert!(
        restart_line.contains(" -f "),
        "compose command should include -f: {restart_line}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_approle_secret_id_daemon_updates_secret() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
        .expect("prepare state");
    fs::write(&secret_path, "old-secret").expect("seed secret_id");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let pkill_log = temp_dir.path().join("pkill.log");
    write_fake_pkill(&bin_dir, &pkill_log).expect("write fake pkill");

    stub_openbao_for_rotation(&openbao, "secret-new").await;

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "approle-secret-id",
            "--service-name",
            SERVICE_NAME,
        ])
        .env("PATH", combined_path)
        .env("PKILL_OUTPUT", &pkill_log)
        .output()
        .expect("run rotate approle-secret-id");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("bootroot rotate: summary"));
    assert!(stdout.contains("AppRole secret_id rotated"));
    assert!(stdout.contains("AppRole login OK"));

    let updated = fs::read_to_string(&secret_path).expect("read secret_id");
    assert_eq!(updated, "secret-new");
    let mode = fs::metadata(&secret_path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let role_id_path = secret_path.parent().expect("secret parent").join("role_id");
    let role_id_contents = fs::read_to_string(&role_id_path).expect("read role_id");
    assert_eq!(role_id_contents, ROLE_ID);
    let mode = fs::metadata(&role_id_path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let pkill_args = fs::read_to_string(&pkill_log).expect("read pkill log");
    assert!(pkill_args.contains("-HUP"));
    assert!(pkill_args.contains("agent.toml"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_approle_secret_id_docker_restarts_agent() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "docker", "local-file")
        .expect("prepare state");
    fs::write(&secret_path, "old-secret").expect("seed secret_id");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    write_fake_docker(&bin_dir, &docker_log).expect("write fake docker");

    stub_openbao_for_rotation(&openbao, "secret-docker").await;

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "approle-secret-id",
            "--service-name",
            SERVICE_NAME,
        ])
        .env("PATH", combined_path)
        .env("DOCKER_OUTPUT", &docker_log)
        .output()
        .expect("run rotate approle-secret-id");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let docker_args = fs::read_to_string(&docker_log).expect("read docker log");
    assert!(docker_args.contains("restart"));
    assert!(docker_args.contains("bootroot-openbao-agent-edge-proxy"));

    let updated = fs::read_to_string(&secret_path).expect("read secret_id");
    assert_eq!(updated, "secret-docker");
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_approle_secret_id_missing_app_fails() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "approle-secret-id",
            "--service-name",
            "missing-service",
        ])
        .output()
        .expect("run rotate approle-secret-id");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("bootroot rotate failed"));
    assert!(stderr.contains("Service not found"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_approle_secret_id_remote_sets_pending_status() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(
        temp_dir.path(),
        &openbao.uri(),
        "daemon",
        "remote-bootstrap",
    )
    .expect("prepare state");

    stub_openbao_for_rotation(&openbao, "secret-remote").await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "approle-secret-id",
            "--service-name",
            SERVICE_NAME,
        ])
        .output()
        .expect("run rotate approle-secret-id");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_eab_remote_sets_pending_status() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(
        temp_dir.path(),
        &openbao.uri(),
        "daemon",
        "remote-bootstrap",
    )
    .expect("prepare state");

    stub_openbao_for_eab_rotation(&openbao).await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "eab",
            "--stepca-url",
            &openbao.uri(),
            "--stepca-provisioner",
            "acme",
        ])
        .output()
        .expect("run rotate eab");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_remote_sets_pending_status() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(
        temp_dir.path(),
        &openbao.uri(),
        "daemon",
        "remote-bootstrap",
    )
    .expect("prepare state");

    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}\n").expect("write compose");
    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-remote").await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--yes",
            "responder-hmac",
            "--hmac",
            "hmac-remote",
        ])
        .output()
        .expect("run rotate responder-hmac");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_supports_approle_runtime_auth() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(
        temp_dir.path(),
        &openbao.uri(),
        "daemon",
        "remote-bootstrap",
    )
    .expect("prepare state");

    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}\n").expect("write compose");
    stub_openbao_for_runtime_approle_login(
        &openbao,
        "runtime-role-id",
        "runtime-secret-id",
        "runtime-client",
    )
    .await;
    stub_openbao_for_responder_hmac_rotation_with_token(&openbao, "hmac-runtime", "runtime-client")
        .await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--auth-mode",
            "approle",
            "--approle-role-id",
            "runtime-role-id",
            "--approle-secret-id",
            "runtime-secret-id",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--yes",
            "responder-hmac",
            "--hmac",
            "hmac-runtime",
        ])
        .output()
        .expect("run rotate responder-hmac");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("bootroot rotate: summary"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_approle_permission_denied_fails() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(
        temp_dir.path(),
        &openbao.uri(),
        "daemon",
        "remote-bootstrap",
    )
    .expect("prepare state");

    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}\n").expect("write compose");
    stub_openbao_for_runtime_approle_login(
        &openbao,
        "runtime-role-id",
        "runtime-secret-id",
        "runtime-client",
    )
    .await;
    stub_openbao_for_responder_hmac_rotation_forbidden(&openbao, "runtime-client").await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--auth-mode",
            "approle",
            "--approle-role-id",
            "runtime-role-id",
            "--approle-secret-id",
            "runtime-secret-id",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--yes",
            "responder-hmac",
            "--hmac",
            "hmac-runtime",
        ])
        .output()
        .expect("run rotate responder-hmac");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains("bootroot rotate failed"));
    assert!(stderr.contains("OpenBao KV secret write failed"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_eab_marks_remote_pending_and_updates_local_service() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_mixed_service_state(temp_dir.path(), &openbao.uri()).expect("prepare mixed state");
    stub_openbao_for_eab_rotation(&openbao).await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "eab",
            "--stepca-url",
            &openbao.uri(),
            "--stepca-provisioner",
            "acme",
        ])
        .output()
        .expect("run rotate eab");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let local_agent = fs::read_to_string(temp_dir.path().join("agent-local.toml"))
        .expect("read local agent config");
    assert!(local_agent.contains("[eab]"));
    assert!(local_agent.contains("kid = \"new-kid\""));
    assert!(local_agent.contains("hmac = \"new-hmac\""));
    assert!(local_agent.contains("[profiles.eab]"));
}

fn prepare_app_state(
    root: &Path,
    openbao_url: &str,
    deploy_type: &str,
    delivery_mode: &str,
) -> anyhow::Result<PathBuf> {
    write_state_file(root, openbao_url)?;
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).context("read state")?;
    let mut state: serde_json::Value = serde_json::from_str(&contents).context("parse state")?;
    let secret_id_path = PathBuf::from("secrets/services/edge-proxy/secret_id");
    state["services"][SERVICE_NAME] = json!({
        "service_name": SERVICE_NAME,
        "deploy_type": deploy_type,
        "delivery_mode": delivery_mode,
        "hostname": "edge-node-01",
        "domain": "trusted.domain",
        "agent_config_path": "agent.toml",
        "cert_path": "certs/edge-proxy.crt",
        "key_path": "certs/edge-proxy.key",
        "instance_id": "001",
        "container_name": "edge-proxy",
        "approle": {
            "role_name": ROLE_NAME,
            "role_id": ROLE_ID,
            "secret_id_path": secret_id_path,
            "policy_name": ROLE_NAME
        }
    });
    fs::write(&state_path, serde_json::to_string_pretty(&state)?).context("write state")?;

    let secret_dir = root.join("secrets").join("services").join(SERVICE_NAME);
    fs::create_dir_all(&secret_dir).context("create secrets dir")?;
    fs::write(root.join("agent.toml"), "# agent").context("write agent config")?;
    Ok(root.join(secret_id_path))
}

fn prepare_mixed_service_state(root: &Path, openbao_url: &str) -> anyhow::Result<()> {
    write_state_file(root, openbao_url)?;
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).context("read state")?;
    let mut state: serde_json::Value = serde_json::from_str(&contents).context("parse state")?;
    state["services"][SERVICE_NAME] = json!({
        "service_name": SERVICE_NAME,
        "deploy_type": "daemon",
        "delivery_mode": "remote-bootstrap",
        "hostname": "edge-node-01",
        "domain": "trusted.domain",
        "agent_config_path": "agent.toml",
        "cert_path": "certs/edge-proxy.crt",
        "key_path": "certs/edge-proxy.key",
        "instance_id": "001",
        "container_name": "edge-proxy",
        "approle": {
            "role_name": ROLE_NAME,
            "role_id": ROLE_ID,
            "secret_id_path": "secrets/services/edge-proxy/secret_id",
            "policy_name": ROLE_NAME
        }
    });
    state["services"][SECONDARY_SERVICE_NAME] = json!({
        "service_name": SECONDARY_SERVICE_NAME,
        "deploy_type": "daemon",
        "delivery_mode": "local-file",
        "hostname": "edge-node-02",
        "domain": "trusted.domain",
        "agent_config_path": "agent-local.toml",
        "cert_path": "certs/edge-alt.crt",
        "key_path": "certs/edge-alt.key",
        "instance_id": "002",
        "container_name": "edge-alt",
        "approle": {
            "role_name": "bootroot-service-edge-alt",
            "role_id": "role-edge-alt",
            "secret_id_path": "secrets/services/edge-alt/secret_id",
            "policy_name": "bootroot-service-edge-alt"
        }
    });
    fs::write(&state_path, serde_json::to_string_pretty(&state)?).context("write state")?;
    fs::write(root.join("agent.toml"), "# remote agent").context("write remote agent config")?;
    fs::write(
        root.join("agent-local.toml"),
        "[profiles]\nservice_name = \"edge-alt\"\n",
    )
    .context("write local agent config")?;
    Ok(())
}

fn write_state_file(root: &Path, openbao_url: &str) -> anyhow::Result<()> {
    let state = json!({
        "openbao_url": openbao_url,
        "kv_mount": "secret",
        "secrets_dir": "secrets",
        "policies": {},
        "approles": {},
        "services": {}
    });
    fs::write(
        root.join("state.json"),
        serde_json::to_string_pretty(&state)?,
    )
    .context("write state.json")?;
    Ok(())
}

async fn stub_openbao_for_rotation(server: &MockServer, new_secret_id: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/secret-id")))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": new_secret_id }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/role-id")))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": ROLE_ID }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": ROLE_ID,
            "secret_id": new_secret_id
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "client-token" }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/secret_id"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

async fn stub_openbao_for_stepca_password_rotation(server: &MockServer, expected_password: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/stepca/password"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .and(body_json(json!({
            "data": {
                "value": expected_password
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
}

async fn stub_openbao_for_eab_rotation(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/acme/acme/eab"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kid": "new-kid",
            "hmac": "new-hmac"
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .and(body_json(json!({
            "data": {
                "kid": "new-kid",
                "hmac": "new-hmac"
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/eab"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
}

async fn stub_openbao_for_responder_hmac_rotation(server: &MockServer, hmac: &str) {
    stub_openbao_for_responder_hmac_rotation_with_token(server, hmac, support::ROOT_TOKEN).await;
}

async fn stub_openbao_for_responder_hmac_rotation_with_token(
    server: &MockServer,
    hmac: &str,
    token: &str,
) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", token))
        .and(body_json(json!({
            "data": {
                "value": hmac
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/http_responder_hmac"
        )))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
}

async fn stub_openbao_for_responder_hmac_rotation_forbidden(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "errors": ["permission denied"]
        })))
        .mount(server)
        .await;
}

async fn stub_openbao_for_runtime_approle_login(
    server: &MockServer,
    role_id: &str,
    secret_id: &str,
    client_token: &str,
) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": role_id,
            "secret_id": secret_id
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": client_token }
        })))
        .mount(server)
        .await;
}

fn write_fake_pkill(bin_dir: &Path, output_path: &Path) -> anyhow::Result<()> {
    let script = r#"#!/bin/sh
set -eu

if [ -n "${PKILL_OUTPUT:-}" ]; then
  printf "%s" "$*" > "$PKILL_OUTPUT"
fi

exit 0
"#;
    let path = bin_dir.join("pkill");
    fs::write(&path, script).context("write fake pkill")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .context("set fake pkill permissions")?;
    fs::write(output_path, "").context("seed pkill log")?;
    Ok(())
}

fn write_fake_docker(bin_dir: &Path, output_path: &Path) -> anyhow::Result<()> {
    let script = r#"#!/bin/sh
set -eu

if [ -n "${DOCKER_OUTPUT:-}" ]; then
  printf "%s\n" "$*" >> "$DOCKER_OUTPUT"
fi

exit 0
"#;
    let path = bin_dir.join("docker");
    fs::write(&path, script).context("write fake docker")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .context("set fake docker permissions")?;
    fs::write(output_path, "").context("seed docker log")?;
    Ok(())
}
