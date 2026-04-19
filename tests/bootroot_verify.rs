#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

use anyhow::Context;
use rcgen::generate_simple_self_signed;
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
    write_cert_with_dns(
        &cert_path,
        &key_path,
        "001.edge-proxy.edge-node-01.trusted.domain",
    )
    .expect("write cert");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--service-name",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stdout.contains("bootroot verify: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(stdout.contains("- result: ok"));
}

#[test]
fn test_verify_docker_success() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("web-app.crt");
    let key_path = temp_dir.path().join("certs").join("web-app.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    write_cert_with_dns(&cert_path, &key_path, "001.web-app.web-01.trusted.domain")
        .expect("write cert");

    write_state_with_docker_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--service-name",
            "web-app",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot verify: summary"));
    assert!(stdout.contains("- service name: web-app"));
    assert!(stdout.contains("- result: ok"));
}

#[test]
fn test_verify_san_mismatch_fails() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    write_cert_with_dns(&cert_path, &key_path, "wrong.trusted.domain").expect("write cert");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--service-name",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stderr.contains("bootroot verify failed"));
}

#[test]
fn test_verify_prompts_for_service_name() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    write_cert_with_dns(
        &cert_path,
        &key_path,
        "001.edge-proxy.edge-node-01.trusted.domain",
    )
    .expect("write cert");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn verify");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"edge-proxy\n")
        .expect("write stdin");

    let output = child.wait_with_output().expect("run verify");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot verify: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(stdout.contains("- result: ok"));
}

#[test]
fn test_verify_reprompts_on_empty_service_name() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    write_cert_with_dns(
        &cert_path,
        &key_path,
        "001.edge-proxy.edge-node-01.trusted.domain",
    )
    .expect("write cert");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn verify");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"\nedge-proxy\n")
        .expect("write stdin");

    let output = child.wait_with_output().expect("run verify");
    assert!(output.status.success());
}

#[test]
fn test_verify_db_check_reports_auth_failure() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    write_cert_with_dns(
        &cert_path,
        &key_path,
        "001.edge-proxy.edge-node-01.trusted.domain",
    )
    .expect("write cert");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    // Representative of what `init` / `rotate db` now persist after the
    // PostgreSQL DSN translation layer: a compose-internal DSN (host
    // `postgres`, port `5432`). `verify --db-check` must translate this
    // back to the host-side pair before connecting; the `.env` file next
    // to the (default) compose file supplies `POSTGRES_HOST_PORT`.
    let stored_dsn = "postgresql://user:pass@postgres:5432/stepca?sslmode=disable";
    write_ca_json_with_dsn(temp_dir.path(), stored_dsn).expect("write ca.json");
    fs::write(
        temp_dir.path().join(".env"),
        format!("POSTGRES_HOST_PORT={port}\n"),
    )
    .expect("write .env");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .env_remove("POSTGRES_HOST_PORT")
        .args([
            "verify",
            "--service-name",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
            "--db-check",
        ])
        .output()
        .expect("run verify");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot verify failed"));
    // Translation must reach the bound listener on 127.0.0.1:<port> rather
    // than failing earlier on `postgres` name resolution. Auth then fails
    // because the listener does not speak the PostgreSQL protocol.
    assert!(
        stderr.contains("DB authentication check failed"),
        "expected auth failure (translation reached host-side listener), got stderr: {stderr}"
    );
}

#[test]
fn test_verify_db_check_translates_compose_dsn_via_process_env() {
    // Regression for issue #542 reviewer feedback: starting from a
    // compose-internal `ca.json` DSN (what `init` / `rotate db` persist
    // post-fix), `verify --db-check` must route through `for_host_runtime`
    // so it never tries to resolve `postgres` from the host. This case
    // exercises the process-env precedence in `resolve_postgres_host_port`
    // — `POSTGRES_HOST_PORT` set on the spawned process must win over any
    // `.env` file lookup.
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    write_cert_with_dns(
        &cert_path,
        &key_path,
        "001.edge-proxy.edge-node-01.trusted.domain",
    )
    .expect("write cert");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind listener");
    let port = listener.local_addr().expect("local addr").port();
    let stored_dsn = "postgresql://user:pass@postgres:5432/stepca?sslmode=disable";
    write_ca_json_with_dsn(temp_dir.path(), stored_dsn).expect("write ca.json");
    // A misleading `.env` would win over default-5432 fallback; assert the
    // process-env override beats it.
    fs::write(temp_dir.path().join(".env"), "POSTGRES_HOST_PORT=1\n").expect("write .env");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .env("POSTGRES_HOST_PORT", port.to_string())
        .args([
            "verify",
            "--service-name",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
            "--db-check",
        ])
        .output()
        .expect("run verify");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    // Auth failure (not name resolution failure) proves translation
    // produced 127.0.0.1:<port> — the bound listener was reached, but it
    // does not speak the PostgreSQL protocol.
    assert!(
        stderr.contains("DB authentication check failed"),
        "expected auth failure (translation reached host-side listener), got stderr: {stderr}"
    );
    // A leak of the raw compose DSN would surface as a name-resolution
    // error referencing `postgres`.
    assert!(
        !stderr.contains("Failed to resolve postgres"),
        "compose hostname leaked into host-side resolution, stderr: {stderr}"
    );
}

#[test]
fn test_verify_missing_cert_fails() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("missing").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(key_path.parent().unwrap()).expect("create cert dir");
    fs::write(&key_path, "key").expect("write key");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--service-name",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot verify failed"));
}

#[test]
fn test_verify_empty_cert_fails() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    fs::File::create(&cert_path).expect("create empty cert");
    fs::write(&key_path, "key").expect("write key");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--service-name",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("Certificate file is empty"));
}

#[test]
fn test_verify_empty_key_fails_docker() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("web-app.crt");
    let key_path = temp_dir.path().join("certs").join("web-app.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    write_cert_with_dns(&cert_path, &key_path, "001.web-app.web-01.trusted.domain")
        .expect("write cert");
    fs::write(&key_path, "").expect("truncate key");

    write_state_with_docker_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--service-name",
            "web-app",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("Key file is empty"));
}

#[test]
fn test_verify_resolves_sibling_agent_without_path_or_flag() {
    // Regression test for the install-layout scenario: operators run a
    // `bootroot` binary that ships next to `bootroot-agent` but neither
    // the directory is on $PATH nor `--agent-binary` is supplied.
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    write_cert_with_dns(
        &cert_path,
        &key_path,
        "001.edge-proxy.edge-node-01.trusted.domain",
    )
    .expect("write cert");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    // Copy the real bootroot binary next to a fake bootroot-agent so that
    // the copy's current_exe() resolves to the install-layout directory.
    let install_dir = temp_dir.path().join("install");
    fs::create_dir_all(&install_dir).expect("create install dir");
    let bootroot_copy = install_dir.join("bootroot");
    fs::copy(env!("CARGO_BIN_EXE_bootroot"), &bootroot_copy).expect("copy bootroot");
    let mut perms = fs::metadata(&bootroot_copy)
        .expect("stat bootroot copy")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&bootroot_copy, perms).expect("chmod bootroot copy");
    write_fake_bootroot_agent(&install_dir, 0).expect("write fake agent");

    // Scrub PATH so only the sibling fallback can succeed.
    let empty_path = temp_dir.path().join("empty-path");
    fs::create_dir_all(&empty_path).expect("create empty PATH dir");

    let output = std::process::Command::new(&bootroot_copy)
        .current_dir(temp_dir.path())
        .env("PATH", &empty_path)
        .args([
            "verify",
            "--service-name",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stdout.contains("bootroot verify: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(stdout.contains("- result: ok"));
}

#[test]
fn test_verify_agent_failure_reports_error() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    write_cert_with_dns(
        &cert_path,
        &key_path,
        "001.edge-proxy.edge-node-01.trusted.domain",
    )
    .expect("write cert");

    write_state_with_app(temp_dir.path(), &agent_config, &cert_path, &key_path)
        .expect("write state");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 1).expect("write fake agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--service-name",
            "edge-proxy",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot verify failed"));
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
        "services": {
            "edge-proxy": {
                "service_name": "edge-proxy",
                "deploy_type": "daemon",
                "hostname": "edge-node-01",
                "domain": "trusted.domain",
                "agent_config_path": agent_config,
                "cert_path": cert_path,
                "key_path": key_path,
                "instance_id": "001",
                "approle": {
                    "role_name": "bootroot-service-edge-proxy",
                    "role_id": "role-edge-proxy",
                    "secret_id_path": "secrets/services/edge-proxy/secret_id",
                    "policy_name": "bootroot-service-edge-proxy"
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

fn write_state_with_docker_app(
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
        "services": {
            "web-app": {
                "service_name": "web-app",
                "deploy_type": "docker",
                "hostname": "web-01",
                "domain": "trusted.domain",
                "instance_id": "001",
                "agent_config_path": agent_config,
                "cert_path": cert_path,
                "key_path": key_path,
                "container_name": "web-app",
                "approle": {
                    "role_name": "bootroot-service-web-app",
                    "role_id": "role-web-app",
                    "secret_id_path": "secrets/services/web-app/secret_id",
                    "policy_name": "bootroot-service-web-app"
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

fn write_ca_json_with_dsn(root: &std::path::Path, dsn: &str) -> anyhow::Result<()> {
    let config_dir = root.join("secrets").join("config");
    fs::create_dir_all(&config_dir).context("create config dir")?;
    let payload = json!({
        "db": {
            "type": "postgresql",
            "dataSource": dsn
        }
    });
    fs::write(
        config_dir.join("ca.json"),
        serde_json::to_string_pretty(&payload)?,
    )
    .context("write ca.json")?;
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

fn write_cert_with_dns(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    dns_name: &str,
) -> anyhow::Result<()> {
    let rcgen::CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec![dns_name.to_string()]).context("generate cert")?;
    fs::write(cert_path, cert.pem()).context("write cert")?;
    fs::write(key_path, signing_key.serialize_pem().as_bytes()).context("write key")?;
    Ok(())
}
