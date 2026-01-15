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
const ROLE_NAME: &str = "bootroot-app-edge-proxy";
const ROLE_ID: &str = "role-edge-proxy";

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_approle_secret_id_daemon_updates_secret() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path =
        prepare_app_state(temp_dir.path(), &openbao.uri(), "daemon").expect("prepare state");
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

    let pkill_args = fs::read_to_string(&pkill_log).expect("read pkill log");
    assert!(pkill_args.contains("-HUP"));
    assert!(pkill_args.contains("agent.toml"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_approle_secret_id_docker_restarts_agent() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path =
        prepare_app_state(temp_dir.path(), &openbao.uri(), "docker").expect("prepare state");
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
            "missing-app",
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
    assert!(stderr.contains("App not found"));
}

fn prepare_app_state(root: &Path, openbao_url: &str, deploy_type: &str) -> anyhow::Result<PathBuf> {
    write_state_file(root, openbao_url)?;
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).context("read state")?;
    let mut state: serde_json::Value = serde_json::from_str(&contents).context("parse state")?;
    let secret_id_path = PathBuf::from("secrets/apps/edge-proxy/secret_id");
    state["apps"][SERVICE_NAME] = json!({
        "service_name": SERVICE_NAME,
        "deploy_type": deploy_type,
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

    let secret_dir = root.join("secrets").join("apps").join(SERVICE_NAME);
    fs::create_dir_all(&secret_dir).context("create secrets dir")?;
    fs::write(root.join("agent.toml"), "# agent").context("write agent config")?;
    Ok(root.join(secret_id_path))
}

fn write_state_file(root: &Path, openbao_url: &str) -> anyhow::Result<()> {
    let state = json!({
        "openbao_url": openbao_url,
        "kv_mount": "secret",
        "secrets_dir": "secrets",
        "policies": {},
        "approles": {},
        "apps": {}
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
  printf "%s" "$*" > "$DOCKER_OUTPUT"
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
