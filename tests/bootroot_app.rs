#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use anyhow::Context;
use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(unix)]
mod support;

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_writes_state_and_secret() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "app",
            "add",
            "--app-kind",
            "edge-proxy",
            "--deploy-type",
            "daemon",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--notes",
            "primary",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run app add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot app add: summary"));
    assert!(stdout.contains("- app kind: edge-proxy"));
    assert!(stdout.contains("- deploy type: daemon"));

    let state_path = temp_dir.path().join("state.json");
    let contents = fs::read_to_string(&state_path).expect("read state.json");
    let value: serde_json::Value = serde_json::from_str(&contents).expect("parse state.json");
    assert!(value["apps"]["edge-proxy"].is_object());
    assert_eq!(value["apps"]["edge-proxy"]["domain"], "trusted.domain");
    assert_eq!(value["apps"]["edge-proxy"]["instance_id"], "001");

    let secret_path = temp_dir
        .path()
        .join("secrets")
        .join("apps")
        .join("edge-proxy")
        .join("secret_id");
    let secret_contents = fs::read_to_string(&secret_path).expect("read secret_id");
    assert_eq!(secret_contents, "secret-edge-proxy");
    let mode = fs::metadata(&secret_path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_duplicate() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;

    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "app",
            "add",
            "--app-kind",
            "edge-proxy",
            "--deploy-type",
            "daemon",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run app add");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "app",
            "add",
            "--app-kind",
            "edge-proxy",
            "--deploy-type",
            "daemon",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run app add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("App already exists"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_info_prints_summary() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["app", "info", "--app-kind", "edge-proxy"])
        .output()
        .expect("run app info");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot app info: summary"));
    assert!(stdout.contains("- app kind: edge-proxy"));
    assert!(stdout.contains("- domain: trusted.domain"));
    assert!(stdout.contains("- secret_id path: (hidden)"));
}

#[cfg(unix)]
#[test]
fn test_app_info_missing_state_file() {
    let temp_dir = tempdir().expect("create temp dir");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["app", "info", "--app-kind", "edge-proxy"])
        .output()
        .expect("run app info");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("state.json not found"));
}

fn write_state_file(root: &std::path::Path, openbao_url: &str) -> anyhow::Result<()> {
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

fn write_state_with_app(root: &std::path::Path) {
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).expect("read state");
    let mut value: serde_json::Value = serde_json::from_str(&contents).expect("parse state");
    value["apps"]["edge-proxy"] = json!({
        "app_kind": "edge-proxy",
        "deploy_type": "daemon",
        "hostname": "edge-node-01",
        "domain": "trusted.domain",
        "agent_config_path": "agent.toml",
        "cert_path": "certs/edge-proxy.crt",
        "key_path": "certs/edge-proxy.key",
        "instance_id": "001",
        "notes": "primary",
        "approle": {
            "role_name": "bootroot-app-edge-proxy",
            "role_id": "role-edge-proxy",
            "secret_id_path": "secrets/apps/edge-proxy/secret_id",
            "policy_name": "bootroot-app-edge-proxy"
        }
    });
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&value).expect("serialize state"),
    )
    .expect("write state");
}

async fn stub_app_add_openbao(server: &MockServer, app_kind: &str) {
    let role = format!("bootroot-app-{app_kind}");
    Mock::given(method("GET"))
        .and(path("/v1/sys/auth"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "approle/": {}
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/sys/policies/acl/{role}")))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role}")))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{role}/role-id")))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": format!("role-{app_kind}") }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role}/secret-id")))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": format!("secret-{app_kind}") }
        })))
        .mount(server)
        .await;
}
