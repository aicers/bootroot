#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

use anyhow::Context;
use rcgen::generate_simple_self_signed;
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
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_trust_missing(&server).await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
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
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot service add: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(stdout.contains("- deploy type: daemon"));
    assert!(stdout.contains("- delivery mode: local-file"));
    assert!(stdout.contains("- sync secret_id: none"));
    assert!(stdout.contains("manual snippets are hidden by default"));
    assert!(stdout.contains("- auto-applied bootroot-agent config:"));
    assert!(stdout.contains("- auto-applied OpenBao Agent config:"));

    assert_state_contains_default_delivery_mode(temp_dir.path());

    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(agent_contents.contains("# BEGIN bootroot managed profile: edge-proxy"));
    assert!(agent_contents.contains("service_name = \"edge-proxy\""));
    assert!(agent_contents.contains("instance_id = \"001\""));
    assert!(agent_contents.contains("hostname = \"edge-node-01\""));
    assert!(agent_contents.contains("[profiles.paths]"));

    let secret_path = temp_dir
        .path()
        .join("secrets")
        .join("services")
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

    let role_id_path = temp_dir
        .path()
        .join("secrets")
        .join("services")
        .join("edge-proxy")
        .join("role_id");
    let role_id_contents = fs::read_to_string(&role_id_path).expect("read role_id");
    assert_eq!(role_id_contents, "role-edge-proxy");
    let mode = fs::metadata(&role_id_path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    assert_openbao_service_agent_files(temp_dir.path(), "edge-proxy");
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_print_only_shows_snippets_without_writes() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--service-name",
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
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot service add: summary"));
    assert!(stdout.contains("daemon profile snippet:"));
    assert!(stdout.contains("preview mode: no files or state were changed"));
    assert!(!stdout.contains("auto-applied"));

    let state_contents =
        fs::read_to_string(temp_dir.path().join("state.json")).expect("read state.json");
    let state: serde_json::Value = serde_json::from_str(&state_contents).expect("parse state");
    assert!(state["services"]["edge-proxy"].is_null());
    assert!(
        !temp_dir
            .path()
            .join("secrets")
            .join("services")
            .join("edge-proxy")
            .join("secret_id")
            .exists()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_prompts_for_missing_inputs() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;

    let input = format!(
        "edge-proxy\n\nedge-node-01\ntrusted.domain\n{}\n{}\n{}\n001\n{}\n",
        agent_config.display(),
        cert_path.display(),
        key_path.display(),
        ROOT_TOKEN
    );

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "add"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");

    let output = child.wait_with_output().expect("run service add");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot service add: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(stdout.contains("- deploy type: daemon"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_reprompts_on_invalid_inputs() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;

    let input = format!(
        "edge-proxy\ninvalid\ndaemon\nedge-node-01\ntrusted.domain\n{}\nmissing/edge-proxy.crt\n{}\n{}\n\n001\n{}\n",
        agent_config.display(),
        cert_path.display(),
        key_path.display(),
        ROOT_TOKEN
    );

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "add"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input.as_bytes())
        .expect("write stdin");

    let output = child.wait_with_output().expect("run service add");
    assert!(output.status.success());
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_prints_docker_snippet() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--service-name",
            "edge-proxy",
            "--deploy-type",
            "docker",
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
            "--container-name",
            "edge-proxy",
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("docker run --rm"));
    assert!(stdout.contains("--name edge-proxy"));
    assert!(stdout.contains("/app/agent.toml"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_persists_remote_bootstrap_delivery_mode() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_remote_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
            "--deploy-type",
            "daemon",
            "--delivery-mode",
            "remote-bootstrap",
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
        .expect("run service add");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(!stdout.contains("auto-applied"));
    assert!(stdout.contains("- remote bootstrap file:"));
    assert!(stdout.contains("- remote run command:"));
    assert!(stdout.contains("- control sync-status command:"));

    let state_contents =
        fs::read_to_string(temp_dir.path().join("state.json")).expect("read state");
    let state: serde_json::Value = serde_json::from_str(&state_contents).expect("parse state");
    assert_eq!(
        state["services"]["edge-proxy"]["delivery_mode"],
        "remote-bootstrap"
    );
    assert_eq!(
        state["services"]["edge-proxy"]["sync_status"]["secret_id"],
        "pending"
    );
    assert_eq!(
        state["services"]["edge-proxy"]["sync_status"]["eab"],
        "pending"
    );
    assert_eq!(
        state["services"]["edge-proxy"]["sync_status"]["responder_hmac"],
        "pending"
    );
    assert_eq!(
        state["services"]["edge-proxy"]["sync_status"]["trust_sync"],
        "pending"
    );

    let openbao_hcl = temp_dir
        .path()
        .join("secrets")
        .join("openbao")
        .join("services")
        .join("edge-proxy")
        .join("agent.hcl");
    assert!(!openbao_hcl.exists());

    let remote_bootstrap = temp_dir
        .path()
        .join("secrets")
        .join("remote-bootstrap")
        .join("services")
        .join("edge-proxy")
        .join("bootstrap.json");
    assert!(remote_bootstrap.exists());
    let bootstrap_contents = fs::read_to_string(&remote_bootstrap).expect("read bootstrap file");
    let bootstrap: serde_json::Value =
        serde_json::from_str(&bootstrap_contents).expect("parse bootstrap json");
    assert_eq!(bootstrap["service_name"], "edge-proxy");
    assert_eq!(bootstrap["kv_mount"], "secret");
    assert!(bootstrap["role_id_path"].is_string());
    assert!(bootstrap["secret_id_path"].is_string());
    assert!(bootstrap["eab_file_path"].is_string());
    assert!(bootstrap["agent_config_path"].is_string());
    assert!(bootstrap["ca_bundle_path"].is_string());
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_remote_bootstrap_rerun_is_idempotent() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_remote_sync_material(&server, "edge-proxy").await;

    let agent_config_value = agent_config.to_string_lossy().to_string();
    let cert_path_value = cert_path.to_string_lossy().to_string();
    let key_path_value = key_path.to_string_lossy().to_string();
    let args = [
        "service",
        "add",
        "--service-name",
        "edge-proxy",
        "--deploy-type",
        "daemon",
        "--delivery-mode",
        "remote-bootstrap",
        "--hostname",
        "edge-node-01",
        "--domain",
        "trusted.domain",
        "--agent-config",
        &agent_config_value,
        "--cert-path",
        &cert_path_value,
        "--key-path",
        &key_path_value,
        "--instance-id",
        "001",
        "--root-token",
        ROOT_TOKEN,
    ];

    let first = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(args)
        .output()
        .expect("run service add first");
    assert!(
        first.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );

    let second = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(args)
        .output()
        .expect("run service add second");
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(second.status.success());
    assert!(stdout.contains("existing remote-bootstrap service matched input"));

    let state_contents =
        fs::read_to_string(temp_dir.path().join("state.json")).expect("read state");
    let state: serde_json::Value = serde_json::from_str(&state_contents).expect("parse state");
    assert!(state["services"]["edge-proxy"].is_object());
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_local_file_sets_verify_prerequisites() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# existing").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;

    let add_output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
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
        .expect("run service add");
    assert!(add_output.status.success());

    write_cert_with_dns(
        &cert_path,
        &key_path,
        "001.edge-proxy.edge-node-01.trusted.domain",
    )
    .expect("write cert");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake bootroot-agent");
    let current_path = std::env::var("PATH").unwrap_or_default();
    let path = format!("{}:{current_path}", bin_dir.display());

    let verify_output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .env("PATH", path)
        .args(["verify", "--service-name", "edge-proxy"])
        .output()
        .expect("run verify");
    let stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(verify_output.status.success());
    assert!(stdout.contains("bootroot verify: summary"));
    assert!(stdout.contains("- result: ok"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_prompts_for_docker_instance_id() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
            "--deploy-type",
            "docker",
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
            "--container-name",
            "edge-proxy",
            "--root-token",
            ROOT_TOKEN,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(b"001\n")
        .expect("write stdin");

    let output = child.wait_with_output().expect("run service add");
    assert!(output.status.success());
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
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;

    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
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
        .expect("run service add");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
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
        .expect("run service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot service add failed"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_includes_trust_snippet_when_present() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_present(&server).await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
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
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(!stdout.contains("[trust]"));
    assert!(!stdout.contains("trusted_ca_sha256"));
    assert!(!stdout.contains("ca_bundle_path"));
    assert!(stdout.contains("manual snippets are hidden by default"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_omits_trust_snippet_when_missing() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
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
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(!stdout.contains("[trust]"));
    assert!(!stdout.contains("trusted_ca_sha256"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_info_prints_summary() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "info", "--service-name", "edge-proxy"])
        .output()
        .expect("run service info");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot service info: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(stdout.contains("- domain: trusted.domain"));
    assert!(stdout.contains("- delivery mode: local-file"));
    assert!(stdout.contains("- sync secret_id: none"));
    assert!(stdout.contains("- secret_id path: secrets/services/edge-proxy/secret_id"));
}

#[cfg(unix)]
#[test]
fn test_service_sync_status_updates_state_from_remote_summary() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());
    let summary_path = temp_dir.path().join("remote-summary.json");
    fs::write(
        &summary_path,
        serde_json::to_string_pretty(&json!({
            "secret_id": {"status": "applied"},
            "eab": {"status": "unchanged"},
            "responder_hmac": {"status": "failed", "error": "simulated"},
            "trust_sync": {"status": "pending"}
        }))
        .expect("serialize summary"),
    )
    .expect("write summary json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "sync-status",
            "--service-name",
            "edge-proxy",
            "--summary-json",
            summary_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run service sync-status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot service sync-status: summary"));
    assert!(stdout.contains("- sync secret_id: applied"));
    assert!(stdout.contains("- sync eab: applied"));
    assert!(stdout.contains("- sync responder_hmac: failed"));
    assert!(stdout.contains("- sync trust_sync: pending"));

    let state_contents =
        fs::read_to_string(temp_dir.path().join("state.json")).expect("read updated state");
    let state: serde_json::Value = serde_json::from_str(&state_contents).expect("parse state");
    assert_eq!(
        state["services"]["edge-proxy"]["sync_status"]["secret_id"],
        "applied"
    );
    assert_eq!(
        state["services"]["edge-proxy"]["sync_status"]["eab"],
        "applied"
    );
    assert_eq!(
        state["services"]["edge-proxy"]["sync_status"]["responder_hmac"],
        "failed"
    );
    assert_eq!(
        state["services"]["edge-proxy"]["sync_status"]["trust_sync"],
        "pending"
    );
}

#[cfg(unix)]
#[test]
fn test_service_sync_status_clears_sync_metadata_after_terminal_update() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());
    let state_path = temp_dir.path().join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
            .expect("parse state");
    state["services"]["edge-proxy"]["sync_metadata"] = json!({
        "secret_id": {"started_at_unix": 1, "expires_at_unix": 2},
        "eab": {"started_at_unix": 3, "expires_at_unix": 4},
        "responder_hmac": {"started_at_unix": 5, "expires_at_unix": 6}
    });
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&state).expect("serialize state"),
    )
    .expect("write state");

    let summary_path = temp_dir.path().join("remote-summary.json");
    fs::write(
        &summary_path,
        serde_json::to_string_pretty(&json!({
            "secret_id": {"status": "applied"},
            "eab": {"status": "failed"},
            "responder_hmac": {"status": "applied"},
            "trust_sync": {"status": "pending"}
        }))
        .expect("serialize summary"),
    )
    .expect("write summary json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "sync-status",
            "--service-name",
            "edge-proxy",
            "--summary-json",
            summary_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run service sync-status");
    assert!(output.status.success());

    let updated: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read updated state"))
            .expect("parse updated state");
    assert!(
        updated["services"]["edge-proxy"]["sync_metadata"]["secret_id"]["started_at_unix"]
            .is_null()
    );
    assert!(
        updated["services"]["edge-proxy"]["sync_metadata"]["secret_id"]["expires_at_unix"]
            .is_null()
    );
    assert!(updated["services"]["edge-proxy"]["sync_metadata"]["eab"]["started_at_unix"].is_null());
    assert!(updated["services"]["edge-proxy"]["sync_metadata"]["eab"]["expires_at_unix"].is_null());
    assert!(
        updated["services"]["edge-proxy"]["sync_metadata"]["responder_hmac"]["started_at_unix"]
            .is_null()
    );
    assert!(
        updated["services"]["edge-proxy"]["sync_metadata"]["responder_hmac"]["expires_at_unix"]
            .is_null()
    );
}

#[cfg(unix)]
#[test]
fn test_service_sync_status_updates_only_target_service() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());
    let state_path = temp_dir.path().join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
            .expect("parse state");
    state["services"]["edge-proxy"]["delivery_mode"] = json!("remote-bootstrap");
    state["services"]["edge-proxy"]["sync_status"] = json!({
        "secret_id": "pending",
        "eab": "pending",
        "responder_hmac": "pending",
        "trust_sync": "pending"
    });
    state["services"]["edge-alt"] = secondary_service_state();
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&state).expect("serialize state"),
    )
    .expect("write state");

    let summary_path = temp_dir.path().join("remote-summary.json");
    fs::write(
        &summary_path,
        serde_json::to_string_pretty(&json!({
            "secret_id": {"status": "applied"},
            "eab": {"status": "unchanged"},
            "responder_hmac": {"status": "failed", "error": "simulated"},
            "trust_sync": {"status": "pending"}
        }))
        .expect("serialize summary"),
    )
    .expect("write summary json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "sync-status",
            "--service-name",
            "edge-proxy",
            "--summary-json",
            summary_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run service sync-status");
    assert!(output.status.success());

    let updated: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read updated state"))
            .expect("parse updated state");

    assert_primary_service_synced(&updated);
    assert_secondary_service_unchanged(&updated);
}

#[cfg(unix)]
#[test]
fn test_service_sync_status_updates_only_target_service_metadata() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());
    let state_path = temp_dir.path().join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
            .expect("parse state");
    state["services"]["edge-proxy"]["delivery_mode"] = json!("remote-bootstrap");
    state["services"]["edge-proxy"]["sync_metadata"] = json!({
        "secret_id": {"started_at_unix": 1, "expires_at_unix": 2},
        "eab": {"started_at_unix": 3, "expires_at_unix": 4},
        "responder_hmac": {"started_at_unix": 5, "expires_at_unix": 6}
    });
    state["services"]["edge-alt"] = secondary_service_state();
    state["services"]["edge-alt"]["sync_metadata"] = json!({
        "secret_id": {"started_at_unix": 101, "expires_at_unix": 102},
        "eab": {"started_at_unix": 103, "expires_at_unix": 104},
        "responder_hmac": {"started_at_unix": 105, "expires_at_unix": 106}
    });
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&state).expect("serialize state"),
    )
    .expect("write state");

    let summary_path = temp_dir.path().join("remote-summary.json");
    fs::write(
        &summary_path,
        serde_json::to_string_pretty(&json!({
            "secret_id": {"status": "applied"},
            "eab": {"status": "failed"},
            "responder_hmac": {"status": "unchanged"},
            "trust_sync": {"status": "pending"}
        }))
        .expect("serialize summary"),
    )
    .expect("write summary json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "sync-status",
            "--service-name",
            "edge-proxy",
            "--summary-json",
            summary_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run service sync-status");
    assert!(output.status.success());

    let updated: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read updated state"))
            .expect("parse updated state");
    assert_terminal_sync_metadata_cleared(
        &updated["services"]["edge-proxy"]["sync_metadata"],
        "secret_id",
    );
    assert_terminal_sync_metadata_cleared(
        &updated["services"]["edge-proxy"]["sync_metadata"],
        "eab",
    );
    assert_terminal_sync_metadata_cleared(
        &updated["services"]["edge-proxy"]["sync_metadata"],
        "responder_hmac",
    );

    assert_eq!(
        updated["services"]["edge-alt"]["sync_metadata"]["secret_id"]["started_at_unix"],
        101
    );
    assert_eq!(
        updated["services"]["edge-alt"]["sync_metadata"]["eab"]["expires_at_unix"],
        104
    );
    assert_eq!(
        updated["services"]["edge-alt"]["sync_metadata"]["responder_hmac"]["started_at_unix"],
        105
    );
}

#[cfg(unix)]
#[test]
fn test_app_info_missing_state_file() {
    let temp_dir = tempdir().expect("create temp dir");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "info", "--service-name", "edge-proxy"])
        .output()
        .expect("run service info");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot service info failed"));
}

fn write_state_file(root: &std::path::Path, openbao_url: &str) -> anyhow::Result<()> {
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

fn assert_state_contains_default_delivery_mode(root: &std::path::Path) {
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).expect("read state.json");
    let value: serde_json::Value = serde_json::from_str(&contents).expect("parse state.json");
    assert!(value["services"]["edge-proxy"].is_object());
    assert_eq!(value["services"]["edge-proxy"]["domain"], "trusted.domain");
    assert_eq!(value["services"]["edge-proxy"]["instance_id"], "001");
    assert_eq!(
        value["services"]["edge-proxy"]["delivery_mode"],
        "local-file"
    );
    assert_eq!(
        value["services"]["edge-proxy"]["sync_status"]["secret_id"],
        "none"
    );
    assert_eq!(
        value["services"]["edge-proxy"]["sync_status"]["eab"],
        "none"
    );
    assert_eq!(
        value["services"]["edge-proxy"]["sync_status"]["responder_hmac"],
        "none"
    );
    assert_eq!(
        value["services"]["edge-proxy"]["sync_status"]["trust_sync"],
        "none"
    );
}

fn assert_openbao_service_agent_files(root: &std::path::Path, service_name: &str) {
    let openbao_service_dir = root
        .join("secrets")
        .join("openbao")
        .join("services")
        .join(service_name);
    let openbao_hcl = openbao_service_dir.join("agent.hcl");
    let openbao_ctmpl = openbao_service_dir.join("agent.toml.ctmpl");
    assert!(openbao_hcl.exists());
    assert!(openbao_ctmpl.exists());
}

fn write_cert_with_dns(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    dns_name: &str,
) -> anyhow::Result<()> {
    let cert = generate_simple_self_signed(vec![dns_name.to_string()])?;
    fs::write(cert_path, cert.cert.pem()).context("write cert pem")?;
    fs::write(key_path, cert.signing_key.serialize_pem()).context("write key pem")?;
    Ok(())
}

fn write_fake_bootroot_agent(dir: &std::path::Path, exit_code: i32) -> anyhow::Result<()> {
    let script_path = dir.join("bootroot-agent");
    let script = format!("#!/bin/sh\nexit {exit_code}\n");
    fs::write(&script_path, script).context("write fake bootroot-agent")?;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
        .context("set fake bootroot-agent perms")?;
    Ok(())
}

fn write_state_with_app(root: &std::path::Path) {
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).expect("read state");
    let mut value: serde_json::Value = serde_json::from_str(&contents).expect("parse state");
    value["services"]["edge-proxy"] = json!({
        "service_name": "edge-proxy",
        "deploy_type": "daemon",
        "hostname": "edge-node-01",
        "domain": "trusted.domain",
        "agent_config_path": "agent.toml",
        "cert_path": "certs/edge-proxy.crt",
        "key_path": "certs/edge-proxy.key",
        "instance_id": "001",
        "notes": "primary",
        "approle": {
            "role_name": "bootroot-service-edge-proxy",
            "role_id": "role-edge-proxy",
            "secret_id_path": "secrets/services/edge-proxy/secret_id",
            "policy_name": "bootroot-service-edge-proxy"
        }
    });
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&value).expect("serialize state"),
    )
    .expect("write state");
}

fn secondary_service_state() -> serde_json::Value {
    json!({
        "service_name": "edge-alt",
        "deploy_type": "daemon",
        "delivery_mode": "local-file",
        "hostname": "edge-node-02",
        "domain": "trusted.domain",
        "agent_config_path": "agent-alt.toml",
        "cert_path": "certs/edge-alt.crt",
        "key_path": "certs/edge-alt.key",
        "instance_id": "002",
        "notes": "secondary",
        "sync_status": {
            "secret_id": "none",
            "eab": "none",
            "responder_hmac": "none",
            "trust_sync": "none"
        },
        "approle": {
            "role_name": "bootroot-service-edge-alt",
            "role_id": "role-edge-alt",
            "secret_id_path": "secrets/services/edge-alt/secret_id",
            "policy_name": "bootroot-service-edge-alt"
        }
    })
}

fn assert_primary_service_synced(updated: &serde_json::Value) {
    assert_eq!(
        updated["services"]["edge-proxy"]["delivery_mode"],
        "remote-bootstrap"
    );
    assert_eq!(
        updated["services"]["edge-proxy"]["sync_status"]["secret_id"],
        "applied"
    );
    assert_eq!(
        updated["services"]["edge-proxy"]["sync_status"]["eab"],
        "applied"
    );
    assert_eq!(
        updated["services"]["edge-proxy"]["sync_status"]["responder_hmac"],
        "failed"
    );
    assert_eq!(
        updated["services"]["edge-proxy"]["sync_status"]["trust_sync"],
        "pending"
    );
}

fn assert_secondary_service_unchanged(updated: &serde_json::Value) {
    assert_eq!(
        updated["services"]["edge-alt"]["delivery_mode"],
        "local-file"
    );
    assert_eq!(
        updated["services"]["edge-alt"]["sync_status"]["secret_id"],
        "none"
    );
    assert_eq!(
        updated["services"]["edge-alt"]["sync_status"]["eab"],
        "none"
    );
    assert_eq!(
        updated["services"]["edge-alt"]["sync_status"]["responder_hmac"],
        "none"
    );
    assert_eq!(
        updated["services"]["edge-alt"]["sync_status"]["trust_sync"],
        "none"
    );
}

fn assert_terminal_sync_metadata_cleared(metadata: &serde_json::Value, key: &str) {
    assert!(metadata[key]["started_at_unix"].is_null());
    assert!(metadata[key]["expires_at_unix"].is_null());
}

async fn stub_app_add_openbao(server: &MockServer, service_name: &str) {
    let role = format!("bootroot-service-{service_name}");
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
            "data": { "role_id": format!("role-{service_name}") }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role}/secret-id")))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": format!("secret-{service_name}") }
        })))
        .mount(server)
        .await;
}

async fn stub_app_add_trust_present(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": {
                    "trusted_ca_sha256": ["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"]
                }
            }
        })))
        .mount(server)
        .await;
}

async fn stub_app_add_trust_missing(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
}

async fn stub_app_add_remote_sync_material(server: &MockServer, service_name: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/agent/eab"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "test-kid", "hmac": "test-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/responder/hmac"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "value": "test-responder-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "trusted_ca_sha256": ["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"],
                "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----"
            } }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/secret_id"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/eab"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/http_responder_hmac"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/trust"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}
