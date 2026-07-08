#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

use anyhow::Context;
use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{body_json, header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(unix)]
mod support;

// End-to-end fixture exercises a full service add → state.json round
// trip; the assertion block grew when the consumer-reload hint
// (issue #614) was added and pushed it past the default 100-line
// threshold. The project CLAUDE.md treats `clippy::too_many_lines`
// loosely, so allow it here rather than fragmenting the test.
#[allow(clippy::too_many_lines)]
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_writes_state_and_secret() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("bootroot service add: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(stdout.contains("- delivery mode: local-file"));
    assert!(stdout.contains("Bootroot-managed:"));
    assert!(stdout.contains("Operator-managed (required):"));
    assert!(stdout.contains("next steps:"));
    assert!(stdout.contains("daemon profile snippet:"));
    // The Bootroot-managed section lists exactly the two host-daemon
    // artifacts: the rendered agent config and the provisioned EAB file.
    // The retired per-service OpenBao Agent artifacts must be gone.
    assert!(stdout.contains("- auto-applied bootroot-agent config:"));
    assert!(stdout.contains(
        "- auto-provisioned EAB file (present only when EAB is configured; \
         pass its path via --eab-file):"
    ));
    assert!(
        !stdout.contains("OpenBao Agent config"),
        "no OpenBao Agent config line may be printed: {stdout}"
    );
    // The next-steps block documents the host-daemon run command,
    // including the --eab-file flag required for EAB rotation to apply.
    assert!(
        stdout.contains(
            "daemon run command (systemd ExecStart or shell; \
             --eab-file is required for EAB rotation to apply):"
        ),
        "next steps must include the daemon run command title: {stdout}"
    );
    assert!(
        stdout.contains("bootroot-agent --config"),
        "next steps must include the bootroot-agent invocation: {stdout}"
    );
    assert!(
        stdout.contains("--eab-file"),
        "run command must pass --eab-file: {stdout}"
    );
    // Issue #614: with no --reload-style, the consumer-reload hint
    // should explicitly call out the missing hook and point at the
    // service-update remediation path.
    assert!(
        stdout.contains("Consumer reload/restart required"),
        "service add should print the consumer-reload hint: {stdout}"
    );
    assert!(
        stdout.contains("NO post-renew hook configured"),
        "service add should flag the missing hook: {stdout}"
    );
    assert!(
        stdout.contains("bootroot service update --service-name"),
        "service add should suggest the service-update remediation: {stdout}"
    );

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

    assert_local_fast_poll_artifacts(temp_dir.path(), &agent_config, "edge-proxy");
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_supports_approle_runtime_auth() {
    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_approle_login(
        &server,
        "runtime-role-id",
        "runtime-secret-id",
        "runtime-client",
    )
    .await;
    stub_app_add_openbao_with_token(&server, "edge-proxy", "runtime-client").await;
    stub_app_add_trust_missing_with_token(&server, "runtime-client").await;
    stub_app_add_service_sync_material_with_token(&server, "edge-proxy", "runtime-client").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--auth-mode",
            "approle",
            "--approle-role-id",
            "runtime-role-id",
            "--approle-secret-id",
            "runtime-secret-id",
            "--service-name",
            "edge-proxy",
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
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("bootroot service add: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(
        temp_dir
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
async fn test_app_add_approle_permission_denied_fails() {
    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_approle_login(
        &server,
        "runtime-role-id",
        "runtime-secret-id",
        "runtime-client",
    )
    .await;
    stub_app_add_trust_missing_with_token(&server, "runtime-client").await;
    stub_app_add_policy_write_forbidden_with_token(&server, "edge-proxy", "runtime-client").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--auth-mode",
            "approle",
            "--approle-role-id",
            "runtime-role-id",
            "--approle-secret-id",
            "runtime-secret-id",
            "--service-name",
            "edge-proxy",
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

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains("bootroot service add failed"));
    assert!(stderr.contains("OpenBao policy write failed"));
}

/// Issue #607: `service add` must `mkdir -p` the parent dirs of the
/// operator-supplied `--agent-config` / `--cert-path` / `--key-path`
/// values instead of bailing out with `Parent directory not found`,
/// which used to force every cold rebuild to keep an out-of-band
/// `mkdir -p` chain in sync with the flag values.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_creates_missing_parent_dirs_for_output_paths() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;

    // Deep nested paths whose parents do NOT exist on disk.  The cert
    // and key parents are intentionally different to exercise both
    // branches of `write_cert_and_key`.
    let agent_config = temp_dir.path().join("config/edge-proxy/agent.toml");
    let cert_path = temp_dir.path().join("mtls/certs/edge-proxy.crt");
    let key_path = temp_dir.path().join("mtls/private/edge-proxy.key");
    assert!(!agent_config.parent().unwrap().exists());
    assert!(!cert_path.parent().unwrap().exists());
    assert!(!key_path.parent().unwrap().exists());

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
    assert!(
        !stderr.contains("Parent directory not found"),
        "service add must no longer reject missing output parents: {stderr}"
    );

    // The agent-config write boundary in `local_config.rs` created the
    // chain and wrote the operator's TOML on top of it.
    assert!(
        agent_config.parent().unwrap().exists(),
        "agent_config parent must be created by service add"
    );
    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(agent_contents.contains("service_name = \"edge-proxy\""));

    // The cert parent is created via the CA-bundle write
    // (`write_local_ca_bundle` → `ensure_secrets_dir`); the key parent
    // is created lazily by `write_cert_and_key` at the first rotation,
    // so we do not assert its existence here.
    assert!(
        cert_path.parent().unwrap().exists(),
        "cert parent must be created by service add (ca-bundle write boundary)"
    );
}

/// Issue #607: pre-existing parent dirs with operator-tightened modes
/// (e.g. `0700`) must NOT be widened by `service add`.  `create_dir_all`
/// is supposed to leave existing components untouched, but this guards
/// against future regressions that mistakenly chmod the dir.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_preserves_existing_parent_dir_mode() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;

    let config_parent = temp_dir.path().join("config");
    fs::create_dir_all(&config_parent).expect("create config dir");
    fs::set_permissions(&config_parent, fs::Permissions::from_mode(0o700))
        .expect("tighten parent mode");
    let agent_config = config_parent.join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let before = fs::metadata(&config_parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(before, 0o700);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let after = fs::metadata(&config_parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        after, 0o700,
        "pre-existing parent dir mode must not be widened by service add"
    );
}

/// Issue #607: when the `--agent-config` parent path collides with an
/// existing regular file, `create_dir_all` must surface a clear error
/// (wrapped with the localized `error_write_file_failed` template)
/// rather than panicking or producing a generic libc message.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_fails_when_agent_config_parent_is_a_file() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;

    // Stage a regular file where service add will try to mkdir its
    // parent.  `create_dir_all("blocker/agent.toml-dir")` must fail.
    let blocker = temp_dir.path().join("blocker");
    fs::write(&blocker, b"not a directory").expect("stage blocker file");
    let agent_config = blocker.join("agent.toml");
    let cert_path = temp_dir.path().join("certs/edge-proxy.crt");
    let key_path = temp_dir.path().join("certs/edge-proxy.key");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
    assert!(
        !output.status.success(),
        "service add must fail when agent-config parent collides with a file; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Failed to write")
            && stderr.contains(agent_config.to_string_lossy().as_ref()),
        "expected localized write-failure for agent-config path, got:\n{stderr}"
    );
}

/// Issue #607: `--dry-run` / `--print-only` must remain side-effect-
/// free even when output-path parents do not exist.  Resolution lives
/// in `resolve.rs` (no filesystem writes), and the actual mkdir lives
/// in `local_config.rs`, so preview-mode never reaches it.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_print_only_does_not_create_missing_parent_dirs() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("config/edge-proxy/agent.toml");
    let cert_path = temp_dir.path().join("mtls/edge-proxy.crt");
    let key_path = temp_dir.path().join("mtls-key/edge-proxy.key");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--service-name",
            "edge-proxy",
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

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !agent_config.parent().unwrap().exists(),
        "--print-only must not create agent_config parent"
    );
    assert!(
        !cert_path.parent().unwrap().exists(),
        "--print-only must not create cert parent"
    );
    assert!(
        !key_path.parent().unwrap().exists(),
        "--print-only must not create key parent"
    );
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
    assert!(stdout.contains("Operator-managed (required):"));
    assert!(stdout.contains("daemon profile snippet:"));
    assert!(stdout.contains("preview mode: no files or state were changed"));
    assert!(stdout.contains("trust preview unavailable"));
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
async fn test_app_add_print_only_with_root_token_shows_trust_snippet() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");
    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_present(&server).await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--service-name",
            "edge-proxy",
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
    assert!(stdout.contains("[trust]"));
    assert!(stdout.contains("trusted_ca_sha256"));
    assert!(stdout.contains("ca_bundle_path"));
    assert!(!stdout.contains("trust preview unavailable"));
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
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let input = format!(
        "edge-proxy\nedge-node-01\ntrusted.domain\n{}\n{}\n{}\n001\n",
        agent_config.display(),
        cert_path.display(),
        key_path.display(),
    );

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "add", "--root-token", ROOT_TOKEN])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(input.as_bytes()).expect("write stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("run service add");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot service add: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
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
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    // Service add only revalidates a path when the parent is missing
    // (`must_exist=true`).  Issue #607 dropped that gate for output paths
    // so `service add` can `create_dir_all` them at the write boundary;
    // the only remaining reprompt-on-invalid path here is the empty
    // instance id.
    let input = format!(
        "edge-proxy\nedge-node-01\ntrusted.domain\n{}\n{}\n{}\n\n001\n",
        agent_config.display(),
        cert_path.display(),
        key_path.display(),
    );

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "add", "--root-token", ROOT_TOKEN])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(input.as_bytes()).expect("write stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("run service add");
    assert!(output.status.success());
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_reprompts_on_invalid_identifier_inputs() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let input = format!(
        "edge.proxy\nedge-proxy\nedge_node\nedge-node-01\ntrusted_domain\ntrusted.domain\n{}\n{}\n{}\ninstance-01\n001\n",
        agent_config.display(),
        cert_path.display(),
        key_path.display(),
    );

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "add", "--print-only"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(input.as_bytes()).expect("write stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("run service add");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout:\n{stdout}");
    assert!(stdout.contains("service_name must be a DNS label"));
    assert!(stdout.contains("hostname must be a DNS label"));
    assert!(stdout.contains("domain must be a DNS name"));
    assert!(stdout.contains("instance_id must be numeric"));
    assert!(stdout.contains("bootroot service add: summary"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_invalid_identifier_args() {
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
            "edge.proxy",
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

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("service_name must be a DNS label"));
}

/// Issue #691: the containerized-consumer story is the consumer-reload
/// hook, not a per-service agent sidecar. `service add` must keep
/// accepting `--reload-style docker-restart --reload-target <container>`
/// so operators can restart a containerized consumer app after renewal.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_accepts_docker_restart_reload_style() {
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
            "--reload-style",
            "docker-restart",
            "--reload-target",
            "edge-proxy-container",
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "service add must accept --reload-style docker-restart; \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("- post-renew hook: docker restart edge-proxy-container"),
        "docker-restart preset must resolve to a docker restart hook: {stdout}"
    );
}

/// Issue #691: the per-service local sidecar run model is retired, so
/// the `--deploy-type`, `--container-name`, and `--no-validate-agent`
/// flags no longer exist on `service add`. Passing any of them must be
/// rejected at the clap boundary, guarding against the flags silently
/// coming back.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_removed_sidecar_flags() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    for (flag, value) in [
        ("--deploy-type", Some("daemon")),
        ("--container-name", Some("web-app")),
        ("--no-validate-agent", None),
    ] {
        let mut args = vec![
            "service",
            "add",
            "--print-only",
            "--service-name",
            "edge-proxy",
            flag,
        ];
        if let Some(value) = value {
            args.push(value);
        }
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(temp_dir.path())
            .args(&args)
            .output()
            .expect("run service add");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "service add must reject the removed {flag} flag, stderr:\n{stderr}"
        );
        assert!(
            stderr.contains("unexpected argument") && stderr.contains(flag),
            "expected clap unexpected-argument error for {flag}, got: {stderr}"
        );
    }
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
    assert!(stdout.contains("Bootroot-managed:"));
    assert!(stdout.contains("Operator-managed (required):"));
    assert!(stdout.contains("Operator-managed (recommended):"));
    assert!(stdout.contains("- remote bootstrap file (machine-readable artifact for automation):"));
    assert!(stdout.contains("- remote run command template:"));
    assert!(stdout.contains("- remote handoff order:"));
    assert!(stdout.contains("1. Copy bootstrap.json and role_id to the service host"));
    assert!(
        stdout.contains("localhost placeholders for `--agent-server` and `--agent-responder-url`")
    );
    assert!(stdout.contains("2. Check status on the step-ca host:"));
    // Remote-bootstrap hosts run the self-auth `bootroot-agent` fast-poll, not
    // a per-service OpenBao Agent. The next-steps block must advertise the
    // self-heal model and must not tell the operator to run an OpenBao Agent.
    assert!(
        stdout.contains("Keep bootroot-agent running on the remote host"),
        "remote-bootstrap add should advertise keeping bootroot-agent running: {stdout}"
    );
    assert!(
        stdout.contains("No OpenBao Agent runs on the remote host"),
        "remote-bootstrap add should state no OpenBao Agent runs: {stdout}"
    );
    assert!(
        !stdout.contains("OpenBao Agent (per-service instance):"),
        "remote-bootstrap add must not print per-service OpenBao Agent steps: {stdout}"
    );
    assert!(
        !stdout.contains("run the service-specific OpenBao Agent"),
        "remote-bootstrap add must not instruct running an OpenBao Agent: {stdout}"
    );

    let state_contents =
        fs::read_to_string(temp_dir.path().join("state.json")).expect("read state");
    let state: serde_json::Value = serde_json::from_str(&state_contents).expect("parse state");
    assert_eq!(
        state["services"]["edge-proxy"]["delivery_mode"],
        "remote-bootstrap"
    );

    // No OpenBao Agent artifacts exist anywhere: the remote host runs the
    // self-auth bootroot-agent fast-poll (schema v4 dropped these paths).
    let openbao_service_dir = temp_dir
        .path()
        .join("secrets")
        .join("openbao")
        .join("services")
        .join("edge-proxy");
    assert!(!openbao_service_dir.exists());

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
    assert_remote_bootstrap_artifact_shape(&bootstrap);
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_remote_bootstrap_no_wrap_handoff_includes_secret_id() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao_no_wrap(&server, "edge-proxy").await;
    stub_app_add_remote_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
            "--no-wrap",
        ])
        .output()
        .expect("run service add");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("1. Copy bootstrap.json, role_id, and secret_id to the service host"),
        "non-wrapped handoff must mention secret_id; got:\n{stdout}"
    );
}

fn assert_remote_bootstrap_artifact_shape(bootstrap: &serde_json::Value) {
    assert_eq!(bootstrap["schema_version"], 4);
    assert_eq!(bootstrap["service_name"], "edge-proxy");
    assert_eq!(bootstrap["kv_mount"], "secret");
    assert!(bootstrap["role_id_path"].is_string());
    assert!(bootstrap["secret_id_path"].is_string());
    assert!(bootstrap["eab_file_path"].is_string());
    assert!(bootstrap["agent_config_path"].is_string());
    assert!(bootstrap["ca_bundle_path"].is_string());
    assert!(bootstrap["ca_bundle_pem"].is_string());
    // schema_version 4 dropped the OpenBao Agent artifact paths: the
    // remote agent self-authenticates and renders trust via fast-poll.
    assert!(
        bootstrap.get("openbao_agent_config_path").is_none(),
        "openbao_agent_config_path must be gone from the schema-4 artifact"
    );
    assert!(bootstrap.get("openbao_agent_template_path").is_none());
    assert!(bootstrap.get("openbao_agent_token_path").is_none());
    assert!(
        bootstrap.get("agent_email").is_none(),
        "agent_email must be omitted when no --agent-email override was supplied"
    );
    assert!(
        bootstrap.get("agent_server").is_none(),
        "agent_server must be omitted when no --agent-server override was supplied"
    );
    assert_eq!(bootstrap["agent_domain"], "trusted.domain");
    assert!(
        bootstrap.get("agent_responder_url").is_none(),
        "agent_responder_url must be omitted when no --agent-responder-url override was supplied"
    );
    assert_eq!(bootstrap["profile_hostname"], "edge-node-01");
    assert_eq!(bootstrap["profile_instance_id"], "001");
    assert!(bootstrap["profile_cert_path"].is_string());
    assert!(bootstrap["profile_key_path"].is_string());
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

    let artifact_path = temp_dir
        .path()
        .join("secrets/remote-bootstrap/services/edge-proxy/bootstrap.json");
    let first_artifact: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&artifact_path).expect("read artifact first"))
            .expect("parse artifact first");
    assert_eq!(
        first_artifact["wrap_token"].as_str(),
        Some("wrap-token-edge-proxy"),
        "first run must produce a wrapped artifact"
    );

    // Tamper with the artifact so the second run must regenerate it via
    // a fresh OpenBao call rather than leaving the old file in place.
    let mut tampered = first_artifact.clone();
    tampered["wrap_token"] = json!("stale-sentinel");
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&tampered).expect("serialize tampered artifact"),
    )
    .expect("write tampered artifact");

    let second = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(args)
        .output()
        .expect("run service add second");
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(second.status.success());
    assert!(stdout.contains("existing remote-bootstrap service matched input"));

    let second_artifact: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&artifact_path).expect("read artifact second"))
            .expect("parse artifact second");
    assert_eq!(
        second_artifact["wrap_token"].as_str(),
        Some("wrap-token-edge-proxy"),
        "idempotent rerun must issue a fresh wrapped secret-id and regenerate the artifact"
    );

    let state_contents =
        fs::read_to_string(temp_dir.path().join("state.json")).expect("read state");
    let state: serde_json::Value = serde_json::from_str(&state_contents).expect("parse state");
    assert!(state["services"]["edge-proxy"].is_object());

    assert_idempotent_rerun_reapplied_policy(&server, "edge-proxy").await;
}

/// Asserts that the idempotent remote re-run re-POSTed the service policy so a
/// pre-existing service picks up the reissue-path write grant (issue #677).
async fn assert_idempotent_rerun_reapplied_policy(server: &MockServer, service_name: &str) {
    let policy_path = format!("/v1/sys/policies/acl/bootroot-service-{service_name}");
    let requests = server
        .received_requests()
        .await
        .expect("mock server records requests");
    let policy_writes: Vec<_> = requests
        .iter()
        .filter(|req| req.method.as_str() == "POST" && req.url.path() == policy_path)
        .collect();
    assert!(
        policy_writes.len() >= 2,
        "expected policy writes from both the initial add and the idempotent re-run, got {}",
        policy_writes.len()
    );
    let last_policy = policy_writes
        .last()
        .expect("at least one policy write recorded");
    let policy_body: serde_json::Value =
        serde_json::from_slice(&last_policy.body).expect("parse policy write body");
    let policy_text = policy_body["policy"]
        .as_str()
        .expect("policy field is a string");
    let expected = format!(
        "path \"secret/data/bootroot/services/{service_name}/reissue\" {{\n  capabilities = [\"read\", \"create\", \"update\"]"
    );
    assert!(
        policy_text.contains(&expected),
        "re-applied policy must grant create/update on the reissue path, got:\n{policy_text}"
    );
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
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let add_output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
    let add_stdout = String::from_utf8_lossy(&add_output.stdout);
    assert!(add_stdout.contains("[trust]"));
    assert!(!add_stdout.contains("verify_certificates"));
    assert!(add_stdout.contains("trusted_ca_sha256"));
    assert!(add_stdout.contains("ca_bundle_path"));
    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(!agent_contents.contains("verify_certificates"));
    assert!(agent_contents.contains("trusted_ca_sha256 = ["));
    assert!(agent_contents.contains("ca_bundle_path = \""));

    write_cert_with_dns(
        &cert_path,
        &key_path,
        "001.edge-proxy.edge-node-01.trusted.domain",
    )
    .expect("write cert");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake bootroot-agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let verify_output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--service-name",
            "edge-proxy",
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");
    let stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(verify_output.status.success());
    assert!(stdout.contains("bootroot verify: summary"));
    assert!(stdout.contains("- result: ok"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_prompts_for_missing_instance_id() {
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
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
            "--root-token",
            ROOT_TOKEN,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(b"001\n").expect("write stdin");
    drop(stdin);

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
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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

/// A second *distinct* local-file service must not reuse another
/// service's `agent.toml`: the top-level `[openbao]` section holds a
/// single `AppRole` identity, so a shared config would let the second
/// add overwrite the first service's `role_id`/`secret_id`/`state_path`
/// and break its KV reads under per-service policies. The rejection
/// happens before any `OpenBao` call, so no stubs exist for the second
/// service name.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_agent_config_shared_across_services() {
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
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let first = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
        .expect("run first service add");
    assert!(first.status.success());

    let second_cert_path = temp_dir.path().join("certs").join("billing-api.crt");
    let second_key_path = temp_dir.path().join("certs").join("billing-api.key");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "billing-api",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            second_cert_path.to_string_lossy().as_ref(),
            "--key-path",
            second_key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run second service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("is already used by service edge-proxy"),
        "expected the agent-config conflict rejection, got: {stderr}"
    );
}

/// The shared-config rejection must survive path re-spelling: the
/// first add registers `agent.toml` and the second spells the same
/// file `./agent.toml`. Without absolute lexical normalization the
/// literal comparison misses the alias and the second service
/// overwrites the first service's single `[openbao]` identity.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_agent_config_shared_via_relative_spelling() {
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
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let first = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            "agent.toml",
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
        .expect("run first service add");
    assert!(first.status.success());

    let second_cert_path = temp_dir.path().join("certs").join("billing-api.crt");
    let second_key_path = temp_dir.path().join("certs").join("billing-api.key");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "billing-api",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            "./agent.toml",
            "--cert-path",
            second_cert_path.to_string_lossy().as_ref(),
            "--key-path",
            second_key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run second service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("is already used by service edge-proxy"),
        "expected the agent-config conflict rejection for the \
         re-spelled path, got: {stderr}"
    );
}

/// A symlinked spelling of a registered config must also be rejected:
/// lexical normalization alone cannot see through symlinks, so the
/// guard canonicalizes existing files when comparing.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_agent_config_shared_via_symlink() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let agent_config_link = temp_dir.path().join("agent-link.toml");
    std::os::unix::fs::symlink(&agent_config, &agent_config_link).expect("symlink agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let first = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
        .expect("run first service add");
    assert!(first.status.success());

    let second_cert_path = temp_dir.path().join("certs").join("billing-api.crt");
    let second_key_path = temp_dir.path().join("certs").join("billing-api.key");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "billing-api",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config_link.to_string_lossy().as_ref(),
            "--cert-path",
            second_cert_path.to_string_lossy().as_ref(),
            "--key-path",
            second_key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run second service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("is already used by service edge-proxy"),
        "expected the agent-config conflict rejection for the \
         symlinked path, got: {stderr}"
    );
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
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
    assert!(stdout.contains("[trust]"));
    assert!(!stdout.contains("verify_certificates"));
    assert!(stdout.contains("trusted_ca_sha256"));
    assert!(stdout.contains("ca_bundle_path"));
    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(agent_contents.contains("[trust]"));
    assert!(!agent_contents.contains("verify_certificates"));
    assert!(agent_contents.contains("trusted_ca_sha256"));
    assert!(agent_contents.contains("ca_bundle_path = \""));
    let bundle_path = temp_dir.path().join("certs").join("ca-bundle.pem");
    let bundle_contents = fs::read_to_string(&bundle_path).expect("read ca bundle");
    assert!(bundle_contents.contains("BEGIN CERTIFICATE"));
    let mode = fs::metadata(&bundle_path)
        .expect("bundle metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o644,
        "operator-facing CA bundle is public trust material and must be 0644"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_uses_synced_trust_when_metadata_missing() {
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
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
    assert!(stdout.contains("[trust]"));
    assert!(!stdout.contains("verify_certificates"));
    assert!(stdout.contains("trusted_ca_sha256"));
    assert!(stdout.contains("ca_bundle_path"));
    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(!agent_contents.contains("verify_certificates"));
    assert!(agent_contents.contains("trusted_ca_sha256"));
    assert!(agent_contents.contains("ca_bundle_path = \""));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_fails_when_synced_trust_bundle_missing() {
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
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material_without_bundle(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--service-name",
            "edge-proxy",
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
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stderr.contains("bootroot service add failed"));
    assert!(stderr.contains("ca_bundle_pem"));
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
    assert!(stdout.contains("- secret_id path: secrets/services/edge-proxy/secret_id"));
    // Local-file next steps document the host-daemon run command; the
    // retired per-service OpenBao Agent step block must be gone.
    assert!(
        stdout.contains(
            "daemon run command (systemd ExecStart or shell; \
             --eab-file is required for EAB rotation to apply):"
        ),
        "service info must print the daemon run command title: {stdout}"
    );
    assert!(
        stdout.contains(
            "bootroot-agent --config agent.toml --eab-file secrets/services/edge-proxy/eab.json"
        ),
        "service info must print the run command with --eab-file: {stdout}"
    );
    assert!(
        !stdout.contains("OpenBao Agent (per-service instance)"),
        "the per-service OpenBao Agent step block is retired: {stdout}"
    );
    assert!(
        !stdout.contains("openbao-sidecar"),
        "the openbao-sidecar start hint is retired: {stdout}"
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
}

/// Asserts the local-file host-daemon artifacts (issue #691): no
/// per-service `OpenBao` Agent directory, an `agent.toml` `[openbao]`
/// section that activates the self-auth fast-poll loop, and an
/// `eab.json` provisioned next to the service `secret_id` (the mock KV
/// serves non-empty `test-kid`/`test-hmac`, so the file must exist).
fn assert_local_fast_poll_artifacts(
    root: &std::path::Path,
    agent_config: &std::path::Path,
    service_name: &str,
) {
    // The per-service OpenBao Agent artifact directory (agent.hcl,
    // *.ctmpl, token) is retired — nothing may create it anymore.
    let openbao_service_dir = root
        .join("secrets")
        .join("openbao")
        .join("services")
        .join(service_name);
    assert!(
        !openbao_service_dir.exists(),
        "no OpenBao Agent artifacts may be created for local-file services"
    );

    // agent.toml carries the [openbao] fast-poll section mirroring what
    // `bootroot-remote bootstrap` provisions on remote hosts.
    let agent_contents = fs::read_to_string(agent_config).expect("read agent config");
    let doc: toml_edit::DocumentMut = agent_contents.parse().expect("agent.toml must parse");
    let openbao = doc
        .get("openbao")
        .and_then(toml_edit::Item::as_table)
        .expect("agent.toml must contain an [openbao] table");
    let get = |key: &str| {
        openbao
            .get(key)
            .and_then(toml_edit::Item::as_str)
            .unwrap_or_else(|| panic!("[openbao].{key} must be a string"))
    };
    assert_eq!(get("kv_mount"), "secret");
    assert!(
        get("url").starts_with("http"),
        "[openbao].url must carry the state openbao_url"
    );
    let cred_dir = root.join("secrets").join("services").join(service_name);
    assert_eq!(
        std::path::Path::new(get("role_id_path")),
        std::path::Path::new("secrets/services")
            .join(service_name)
            .join("role_id")
    );
    assert_eq!(
        std::path::Path::new(get("secret_id_path")),
        std::path::Path::new("secrets/services")
            .join(service_name)
            .join("secret_id")
    );
    assert_eq!(
        std::path::Path::new(get("ca_bundle_path")),
        root.join("certs").join("ca-bundle.pem"),
        "[openbao].ca_bundle_path must sit next to the cert path"
    );
    let state_path = get("state_path");
    assert!(
        std::path::Path::new(state_path).is_absolute(),
        "[openbao].state_path must be absolute, got: {state_path}"
    );
    assert!(
        state_path.ends_with(&format!("bootroot-agent-state-{service_name}.json")),
        "[openbao].state_path must be service-keyed, got: {state_path}"
    );

    // The mock KV serves non-empty EAB material (test-kid/test-hmac), so
    // eab.json must be provisioned next to secret_id at 0600 with both
    // values, ready for the documented `--eab-file` run command.
    let eab_path = cred_dir.join("eab.json");
    let eab_contents = fs::read_to_string(&eab_path).expect("read eab.json");
    let eab: serde_json::Value = serde_json::from_str(&eab_contents).expect("parse eab.json");
    assert_eq!(eab["kid"], "test-kid");
    assert_eq!(eab["hmac"], "test-hmac");
    let eab_mode = fs::metadata(&eab_path)
        .expect("eab metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(eab_mode, 0o600, "eab.json holds credentials; must be 0600");
}

fn write_cert_with_dns(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    dns_name: &str,
) -> anyhow::Result<()> {
    // Sign the leaf with the same CA `support::test_trust_material` puts in
    // the bundle so the chain check added in #627 (`bootroot verify`'s
    // `leaf_chains_to_bundle`) succeeds. A self-signed leaf used to pass
    // through the predecessor's self-signature shortcut, but that path was
    // closed when the predicate was hardened to require a real trust anchor.
    let (cert_pem, key_pem) = support::sign_test_leaf(dns_name);
    fs::write(cert_path, cert_pem).context("write cert pem")?;
    fs::write(key_path, key_pem).context("write key pem")?;
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
    write_state_with_app_policy(root, None, None);
}

fn write_state_with_app_policy(
    root: &std::path::Path,
    secret_id_ttl: Option<&str>,
    secret_id_wrap_ttl: Option<&str>,
) {
    write_state_with_app_full(root, secret_id_ttl, secret_id_wrap_ttl, None);
}

fn write_state_with_app_cidrs(root: &std::path::Path, cidrs: Option<&[&str]>) {
    write_state_with_app_full(root, None, None, cidrs);
}

fn write_state_with_app_full(
    root: &std::path::Path,
    secret_id_ttl: Option<&str>,
    secret_id_wrap_ttl: Option<&str>,
    token_bound_cidrs: Option<&[&str]>,
) {
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).expect("read state");
    let mut value: serde_json::Value = serde_json::from_str(&contents).expect("parse state");
    let mut approle = json!({
        "role_name": "bootroot-service-edge-proxy",
        "role_id": "role-edge-proxy",
        "secret_id_path": "secrets/services/edge-proxy/secret_id",
        "policy_name": "bootroot-service-edge-proxy"
    });
    if let Some(ttl) = secret_id_ttl {
        approle["secret_id_ttl"] = json!(ttl);
    }
    if let Some(wrap_ttl) = secret_id_wrap_ttl {
        approle["secret_id_wrap_ttl"] = json!(wrap_ttl);
    }
    if let Some(cidrs) = token_bound_cidrs {
        approle["token_bound_cidrs"] = json!(cidrs);
    }
    value["services"]["edge-proxy"] = json!({
        "service_name": "edge-proxy",
        "hostname": "edge-node-01",
        "domain": "trusted.domain",
        "agent_config_path": "agent.toml",
        "cert_path": "certs/edge-proxy.crt",
        "key_path": "certs/edge-proxy.key",
        "instance_id": "001",
        "notes": "primary",
        "approle": approle
    });
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&value).expect("serialize state"),
    )
    .expect("write state");
}

async fn stub_app_add_openbao(server: &MockServer, service_name: &str) {
    stub_app_add_openbao_with_token(server, service_name, support::ROOT_TOKEN).await;
}

async fn stub_app_add_openbao_with_token(server: &MockServer, service_name: &str, token: &str) {
    stub_app_add_openbao_common(server, service_name, token).await;

    let role = format!("bootroot-service-{service_name}");
    let wrap_token = format!("wrap-token-{service_name}");
    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role}/secret-id")))
        .and(header("X-Vault-Token", token))
        .and(header_exists("X-Vault-Wrap-TTL"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": &wrap_token,
                "ttl": 1800,
                "creation_time": "2026-04-12T00:00:00Z",
                "creation_path": format!("auth/approle/role/{role}/secret-id")
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(header("X-Vault-Token", &wrap_token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "secret_id": format!("secret-{service_name}"),
                "secret_id_accessor": "acc"
            }
        })))
        .mount(server)
        .await;
}

async fn stub_app_add_openbao_no_wrap(server: &MockServer, service_name: &str) {
    stub_app_add_openbao_common(server, service_name, support::ROOT_TOKEN).await;

    let role = format!("bootroot-service-{service_name}");
    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role}/secret-id")))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "secret_id": format!("secret-{service_name}"),
                "secret_id_accessor": "acc"
            }
        })))
        .mount(server)
        .await;
}

async fn stub_app_add_openbao_common(server: &MockServer, service_name: &str, token: &str) {
    let role = format!("bootroot-service-{service_name}");

    Mock::given(method("POST"))
        .and(path(format!("/v1/sys/policies/acl/{role}")))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role}")))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{role}/role-id")))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": format!("role-{service_name}") }
        })))
        .mount(server)
        .await;
}

async fn stub_app_add_trust_present(server: &MockServer) {
    stub_app_add_trust_present_with_token(server, support::ROOT_TOKEN).await;
}

async fn stub_app_add_trust_present_with_token(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    let (ca_pem, ca_fp) = support::test_trust_material();
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": {
                    "trusted_ca_sha256": [ca_fp],
                    "ca_bundle_pem": ca_pem
                }
            }
        })))
        .mount(server)
        .await;
}

async fn stub_app_add_trust_missing(server: &MockServer) {
    stub_app_add_trust_missing_with_token(server, support::ROOT_TOKEN).await;
}

async fn stub_app_add_trust_missing_with_token(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
}

async fn stub_app_add_policy_write_forbidden_with_token(
    server: &MockServer,
    service_name: &str,
    token: &str,
) {
    let role = format!("bootroot-service-{service_name}");
    Mock::given(method("POST"))
        .and(path(format!("/v1/sys/policies/acl/{role}")))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "errors": ["permission denied"]
        })))
        .mount(server)
        .await;
}

async fn stub_approle_login(
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

async fn stub_app_add_service_sync_material(server: &MockServer, service_name: &str) {
    stub_app_add_service_sync_material_with_token(server, service_name, support::ROOT_TOKEN).await;
}

async fn stub_app_add_service_sync_material_with_token(
    server: &MockServer,
    service_name: &str,
    token: &str,
) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "test-kid", "hmac": "test-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "value": "test-responder-hmac" } }
        })))
        .mount(server)
        .await;

    let (ca_pem, ca_fp) = support::test_trust_material();
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "trusted_ca_sha256": [ca_fp],
                "ca_bundle_pem": ca_pem
            } }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/eab"
        )))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/http_responder_hmac"
        )))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/trust"
        )))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

async fn stub_app_add_service_sync_material_without_bundle(
    server: &MockServer,
    service_name: &str,
) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "test-kid", "hmac": "test-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "value": "test-responder-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "trusted_ca_sha256": ["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"]
            } }
        })))
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

#[cfg(unix)]
#[test]
fn test_service_update_sets_secret_id_ttl() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--secret-id-ttl",
            "2h",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("secret_id_ttl"));
    assert!(stdout.contains("2h"));

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert_eq!(
        state["services"]["edge-proxy"]["approle"]["secret_id_ttl"],
        "2h"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_disables_wrapping() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--no-wrap",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("secret_id_wrap_ttl"));

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert_eq!(
        state["services"]["edge-proxy"]["approle"]["secret_id_wrap_ttl"],
        "0"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_inherit_clears_ttl() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app_policy(temp_dir.path(), Some("1h"), None);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--secret-id-ttl",
            "inherit",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert!(
        state["services"]["edge-proxy"]["approle"]["secret_id_ttl"].is_null(),
        "secret_id_ttl should be cleared (null)"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_reenables_wrapping() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app_policy(temp_dir.path(), None, Some("0"));

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--secret-id-wrap-ttl",
            "15m",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert_eq!(
        state["services"]["edge-proxy"]["approle"]["secret_id_wrap_ttl"],
        "15m"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_wrap_ttl_inherit_restores_default() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app_policy(temp_dir.path(), None, Some("0"));

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--secret-id-wrap-ttl",
            "inherit",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert!(
        state["services"]["edge-proxy"]["approle"]["secret_id_wrap_ttl"].is_null(),
        "secret_id_wrap_ttl should be cleared (null) after inherit"
    );

    // Verify service info shows the default wrap TTL label
    let info_output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "info", "--service-name", "edge-proxy"])
        .output()
        .expect("run service info");

    let info_stdout = String::from_utf8_lossy(&info_output.stdout);
    assert!(
        info_stdout.contains("30m (default)"),
        "service info should report default wrap TTL, got: {info_stdout}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_not_found() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "nonexistent",
            "--secret-id-ttl",
            "1h",
        ])
        .output()
        .expect("run service update");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Service not found"));
}

#[cfg(unix)]
#[test]
fn test_service_update_no_flags_errors() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "update", "--service-name", "edge-proxy"])
        .output()
        .expect("run service update");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No update flags specified"));
}

#[cfg(unix)]
#[test]
fn test_service_update_shows_rotate_hint() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--secret-id-ttl",
            "1h",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("rotate approle-secret-id"),
        "should show rotate hint"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_shows_ttl_rotation_cadence_hint() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--secret-id-ttl",
            "2h",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NOTE: Ensure the secret_id TTL is at least 2"),
        "should show rotation cadence hint on stderr, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_warns_when_ttl_exceeds_recommended() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--secret-id-ttl",
            "72h",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("WARNING: --secret-id-ttl (72h) exceeds the recommended threshold"),
        "should warn about exceeding recommended TTL, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_rejects_ttl_exceeding_max() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--secret-id-ttl",
            "200h",
        ])
        .output()
        .expect("run service update");

    assert!(
        !output.status.success(),
        "should fail when TTL exceeds 168h"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exceeds the maximum allowed value"),
        "should report TTL exceeds max, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_noop_when_value_unchanged() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    // Wrapping already disabled (secret_id_wrap_ttl = "0")
    write_state_with_app_policy(temp_dir.path(), Some("1h"), Some("0"));

    // --no-wrap on already-disabled wrapping should be a no-op
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--no-wrap",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("No fields changed"),
        "should report no changes when value is already set, got: {stdout}"
    );

    // --secret-id-ttl with same value should also be a no-op but still
    // show the rotation-cadence hint
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--secret-id-ttl",
            "1h",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stdout.contains("No fields changed"),
        "should report no changes when TTL is already set, got: {stdout}"
    );
    assert!(
        stderr.contains("NOTE: Ensure the secret_id TTL is at least 2"),
        "should show rotation cadence hint even when value unchanged, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_rn_cidrs_clear_removes_bound_cidrs() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app_cidrs(temp_dir.path(), Some(&["10.0.0.0/24", "192.168.1.0/24"]));

    // Verify CIDRs are set before update
    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert!(
        state["services"]["edge-proxy"]["approle"]["token_bound_cidrs"].is_array(),
        "token_bound_cidrs should be set before clear"
    );

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--rn-cidrs",
            "clear",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("token_bound_cidrs"),
        "should report token_bound_cidrs changed, got: {stdout}"
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert!(
        state["services"]["edge-proxy"]["approle"]["token_bound_cidrs"].is_null(),
        "token_bound_cidrs should be cleared (null) after --rn-cidrs clear"
    );
}

/// Issue #614 — `service update --reload-style sighup --reload-target X`
/// installs a post-renew hook on an already-registered service. Tests
/// the retrofit path that lets operators wire a hook on services that
/// were registered without `--reload-style`, without having to remove
/// and re-add the service.
#[cfg(unix)]
#[test]
fn test_service_update_installs_post_renew_hook_via_reload_style() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    // The retrofit re-renders the managed agent.toml block, so seed a
    // minimal file with the bootroot-managed block markers.
    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--reload-style",
            "sighup",
            "--reload-target",
            "review",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("post_renew_hooks"),
        "should report post_renew_hooks change, got: {stdout}"
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    let hooks = state["services"]["edge-proxy"]["post_renew_hooks"]
        .as_array()
        .expect("post_renew_hooks is an array");
    assert_eq!(hooks.len(), 1, "expected one hook entry");
    assert_eq!(hooks[0]["command"], "pkill");
    assert_eq!(
        hooks[0]["args"],
        serde_json::json!(["-HUP", "review"]),
        "expected sighup args"
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert!(
        agent_contents.contains("[[profiles.hooks.post_renew.success]]"),
        "agent.toml should be re-rendered with the new hook, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("pkill"),
        "agent.toml should embed the hook command, got: {agent_contents}"
    );
}

/// Issue #643 — `service update --reload-style …` must preserve a
/// `[trust]` section that `service add` wrote *inside* the managed-block
/// markers. The whole-span re-render used to drop it, leaving the agent's
/// ACME client unable to verify a private CA (`UnknownIssuer`).
#[cfg(unix)]
#[test]
fn test_service_update_reload_style_preserves_inline_trust() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    // Mirror the `service add` layout: `[trust]` lands inside the
    // BEGIN/END markers as a dangling-comment-preceding table.
    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         \n\
         [trust]\n\
         ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\"\n\
         trusted_ca_sha256 = [\"root-sha\", \"intermediate-sha\"]\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--reload-style",
            "sighup",
            "--reload-target",
            "review",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert!(
        agent_contents.contains("[[profiles.hooks.post_renew.success]]"),
        "agent.toml should be re-rendered with the new hook, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\""),
        "[trust].ca_bundle_path must survive the re-render, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("trusted_ca_sha256 = [\"root-sha\", \"intermediate-sha\"]"),
        "[trust].trusted_ca_sha256 must survive the re-render, got: {agent_contents}"
    );
    assert_eq!(
        agent_contents.matches("[trust]").count(),
        1,
        "exactly one [trust] section expected, got: {agent_contents}"
    );
}

/// Issue #643 — when `[trust]` already lives *outside* the managed-block
/// markers, the carry-over must update it in place and never produce a
/// duplicate section.
#[cfg(unix)]
#[test]
fn test_service_update_reload_style_keeps_outside_trust_unique() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "[trust]\n\
         ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\"\n\
         \n\
         # BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--reload-style",
            "sighup",
            "--reload-target",
            "review",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert_eq!(
        agent_contents.matches("[trust]").count(),
        1,
        "an out-of-block [trust] must not be duplicated, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\""),
        "[trust].ca_bundle_path must survive, got: {agent_contents}"
    );
}

/// Issue #643 — a config with no `[trust]` section must not gain a
/// synthesized empty one during a re-render.
#[cfg(unix)]
#[test]
fn test_service_update_reload_style_no_trust_stays_absent() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--reload-style",
            "sighup",
            "--reload-target",
            "review",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert!(
        !agent_contents.contains("[trust]"),
        "no [trust] section should be synthesized, got: {agent_contents}"
    );
}

/// Issue #645 — `service update --cert-group …` reaches
/// `rerender_local_managed_profile` through the `redeploy_hint` branch
/// (a different trigger than `--reload-style`'s `hooks_changed`), so the
/// `[trust]` carry-over must hold on this path too. A regression here
/// would silently reintroduce the issue #643 `UnknownIssuer` bug for
/// cert-group updates while the `--reload-style` tests stayed green.
#[cfg(unix)]
#[test]
fn test_service_update_cert_group_preserves_inline_trust() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    // Mirror the `service add` layout: `[trust]` lands inside the
    // BEGIN/END markers as a dangling-comment-preceding table.
    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         \n\
         [trust]\n\
         ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\"\n\
         trusted_ca_sha256 = [\"root-sha\", \"intermediate-sha\"]\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    // `--cert-group clear` drives the re-render purely through the
    // `redeploy_hint` branch (no hook change), exercising the trigger the
    // `--reload-style` tests never reach.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--cert-group",
            "clear",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert!(
        agent_contents.contains("ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\""),
        "[trust].ca_bundle_path must survive the cert-group re-render, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("trusted_ca_sha256 = [\"root-sha\", \"intermediate-sha\"]"),
        "[trust].trusted_ca_sha256 must survive the cert-group re-render, got: {agent_contents}"
    );
    assert_eq!(
        agent_contents.matches("[trust]").count(),
        1,
        "exactly one [trust] section expected, got: {agent_contents}"
    );
}

/// Issue #645 — when `[trust]` already lives *outside* the managed-block
/// markers, the `--cert-group` re-render must update it in place and
/// never produce a duplicate section, mirroring the `--reload-style`
/// guarantee.
#[cfg(unix)]
#[test]
fn test_service_update_cert_group_keeps_outside_trust_unique() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "[trust]\n\
         ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\"\n\
         \n\
         # BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--cert-group",
            "clear",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert_eq!(
        agent_contents.matches("[trust]").count(),
        1,
        "an out-of-block [trust] must not be duplicated, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\""),
        "[trust].ca_bundle_path must survive, got: {agent_contents}"
    );
}

/// Issue #614 — `service update --reload-style none` clears a
/// previously configured hook without re-onboarding.
#[cfg(unix)]
#[test]
fn test_service_update_reload_style_none_clears_existing_hook() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    // Seed an existing hook into state and a managed agent.toml block.
    let state_path = temp_dir.path().join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
            .expect("parse state");
    state["services"]["edge-proxy"]["post_renew_hooks"] = serde_json::json!([{
        "command": "pkill",
        "args": ["-HUP", "review"],
        "timeout_secs": 30,
        "on_failure": "continue"
    }]);
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&state).expect("serialize state"),
    )
    .expect("write state");

    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         [[profiles.hooks.post_renew.success]]\n\
         command = \"pkill\"\n\
         args = [\"-HUP\", \"review\"]\n\
         timeout_secs = 30\n\
         on_failure = \"continue\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--service-name",
            "edge-proxy",
            "--reload-style",
            "none",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("post_renew_hooks"),
        "should report hooks change, got: {stdout}"
    );

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
            .expect("parse state");
    let hooks = state["services"]["edge-proxy"]["post_renew_hooks"]
        .as_array()
        .expect("post_renew_hooks is an array");
    assert!(hooks.is_empty(), "hooks should be cleared, got: {hooks:?}");
}

#[cfg(unix)]
#[test]
fn test_service_add_rejects_rn_cidrs_clear() {
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
            "--rn-cidrs",
            "clear",
        ])
        .output()
        .expect("run service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "service add --rn-cidrs clear should fail, stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("clear"),
        "error should mention 'clear', got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_add_print_only_shows_ttl_rotation_cadence_hint() {
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
            "--secret-id-ttl",
            "2h",
        ])
        .output()
        .expect("run service add");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NOTE: Ensure the secret_id TTL is at least 2"),
        "should show rotation cadence hint on stderr, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_add_print_only_warns_when_ttl_exceeds_recommended() {
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
            "--secret-id-ttl",
            "72h",
        ])
        .output()
        .expect("run service add");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("WARNING: --secret-id-ttl (72h) exceeds the recommended threshold"),
        "should warn about exceeding recommended TTL, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_add_print_only_rejects_ttl_exceeding_max() {
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
            "--secret-id-ttl",
            "200h",
        ])
        .output()
        .expect("run service add");

    assert!(
        !output.status.success(),
        "should fail when TTL exceeds 168h"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exceeds the maximum allowed value"),
        "should report TTL exceeds max, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_info_shows_policy_fields() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app_policy(temp_dir.path(), Some("4h"), Some("10m"));

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "info", "--service-name", "edge-proxy"])
        .output()
        .expect("run service info");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("secret_id TTL: 4h"), "stdout: {stdout}");
    assert!(
        stdout.contains("secret_id wrap TTL: 10m"),
        "stdout: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_info_shows_default_policy_fields() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "info", "--service-name", "edge-proxy"])
        .output()
        .expect("run service info");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("secret_id TTL: inherit"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("secret_id wrap TTL: 30m (default)"),
        "stdout: {stdout}"
    );
}

/// Issue #691: the per-service local `OpenBao` Agent run model is retired,
/// so both `service openbao-sidecar` and its deprecated `service agent`
/// alias no longer exist. Invoking either must fail at the clap boundary
/// with an unrecognized-subcommand error, guarding against the commands
/// silently coming back.
#[cfg(unix)]
#[test]
fn test_service_sidecar_subcommands_are_gone() {
    let temp_dir = tempdir().expect("create temp dir");

    for subcommand in ["openbao-sidecar", "agent"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(temp_dir.path())
            .args([
                "service",
                subcommand,
                "start",
                "--service-name",
                "edge-proxy",
            ])
            .output()
            .expect("run removed service subcommand");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "`bootroot service {subcommand}` must no longer parse; stderr:\n{stderr}"
        );
        assert!(
            stderr.contains("unrecognized subcommand") && stderr.contains(subcommand),
            "expected clap unrecognized-subcommand error for `service {subcommand}`, \
             got: {stderr}"
        );
    }
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
    let (ca_pem, ca_fp) = support::test_trust_material();
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "trusted_ca_sha256": [ca_fp],
                "ca_bundle_pem": ca_pem
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
