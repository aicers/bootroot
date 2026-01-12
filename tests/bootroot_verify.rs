#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use anyhow::Context;
use serde_json::json;
use tempfile::tempdir;

#[test]
fn test_verify_success() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    fs::write(&cert_path, "cert").expect("write cert");
    fs::write(&key_path, "key").expect("write key");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");

    let path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .env("PATH", combined_path)
        .args([
            "verify",
            "--app-kind",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot verify: summary"));
    assert!(stdout.contains("- app kind: edge-proxy"));
    assert!(stdout.contains("- result: ok"));
}

#[test]
fn test_verify_missing_cert_fails() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    fs::write(&key_path, "key").expect("write key");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");

    let path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .env("PATH", combined_path)
        .args([
            "verify",
            "--app-kind",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("Certificate not found"));
}

#[test]
fn test_verify_agent_failure_reports_error() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    fs::write(&cert_path, "cert").expect("write cert");
    fs::write(&key_path, "key").expect("write key");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 1).expect("write fake agent");

    let path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .env("PATH", combined_path)
        .args([
            "verify",
            "--app-kind",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot-agent failed"));
}

fn write_state_with_app(
    root: &std::path::Path,
    agent_config: &std::path::Path,
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> anyhow::Result<()> {
    let state = json!({
        "openbao_url": "http://localhost:8200",
        "kv_mount": "secret",
        "secrets_dir": "secrets",
        "policies": {},
        "approles": {},
        "apps": {
            "edge-proxy": {
                "app_kind": "edge-proxy",
                "deploy_type": "daemon",
                "hostname": "edge-node-01",
                "domain": "trusted.domain",
                "agent_config_path": agent_config,
                "cert_path": cert_path,
                "key_path": key_path,
                "instance_id": "001",
                "approle": {
                    "role_name": "bootroot-app-edge-proxy",
                    "role_id": "role-edge-proxy",
                    "secret_id_path": "secrets/apps/edge-proxy/secret_id",
                    "policy_name": "bootroot-app-edge-proxy"
                }
            }
        }
    });

    fs::write(
        root.join("state.json"),
        serde_json::to_string_pretty(&state)?,
    )
    .context("write state.json")?;
    Ok(())
}

fn write_fake_bootroot_agent(dir: &std::path::Path, exit_code: i32) -> anyhow::Result<()> {
    let script = format!(
        r"#!/bin/sh
exit {exit_code}
"
    );
    let path = dir.join("bootroot-agent");
    fs::write(&path, script).context("write fake bootroot-agent")?;
    fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .context("set fake bootroot-agent permissions")?;
    Ok(())
}
