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
    support::write_password_file(&secrets_dir, "old-password").expect("write password");
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
    // The fake docker will copy RENDER_SOURCE to RENDER_TARGET when it sees
    // `docker restart bootroot-openbao-agent-*`, simulating OBA rendering.
    let render_source = secrets_dir.join("password.txt.new");
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
        .env("RENDER_SOURCE", &render_source)
        .env("RENDER_TARGET", secrets_dir.join("password.txt"))
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

    // Verify restart OBA-stepca comes BEFORE compose restart step-ca
    let oba_restart_idx = lines
        .iter()
        .position(|line| line.contains("restart") && line.contains("bootroot-openbao-agent-stepca"))
        .unwrap_or_else(|| panic!("restart OBA-stepca should be invoked\nlog:\n{docker_args_log}"));
    let compose_restart_idx = lines
        .iter()
        .position(|line| {
            line.contains("compose") && line.contains("restart") && line.contains("step-ca")
        })
        .unwrap_or_else(|| {
            panic!("restart step-ca command should be invoked\nlog:\n{docker_args_log}")
        });
    assert!(
        oba_restart_idx < compose_restart_idx,
        "OBA restart should come before compose restart\nlog:\n{docker_args_log}"
    );

    let restart_line = lines
        .get(compose_restart_idx)
        .expect("compose restart line");
    assert!(
        restart_line.contains(" -f "),
        "compose command should include -f: {restart_line}"
    );

    // Verify password.txt was rendered with new value
    let rendered =
        fs::read_to_string(secrets_dir.join("password.txt")).expect("read rendered password.txt");
    assert_eq!(rendered, "new-pass-123");
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
async fn test_rotate_approle_secret_id_applies_default_wrapping_when_policy_absent() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path =
        prepare_app_state_no_policy(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
            .expect("prepare state");
    fs::write(&secret_path, "old-secret").expect("seed secret_id");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let pkill_log = temp_dir.path().join("pkill.log");
    write_fake_pkill(&bin_dir, &pkill_log).expect("write fake pkill");

    stub_openbao_for_wrapped_rotation(&openbao, "secret-wrapped").await;

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
    assert!(stdout.contains("AppRole secret_id rotated"));
    assert!(stdout.contains("AppRole login OK"));

    let updated = fs::read_to_string(&secret_path).expect("read secret_id");
    assert_eq!(updated, "secret-wrapped");
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
async fn test_rotate_approle_secret_id_skips_login_when_cidr_bound() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path =
        prepare_app_state_with_cidrs(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
            .expect("prepare state");
    fs::write(&secret_path, "old-secret").expect("seed secret_id");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let pkill_log = temp_dir.path().join("pkill.log");
    write_fake_pkill(&bin_dir, &pkill_log).expect("write fake pkill");

    stub_openbao_for_rotation_no_login(&openbao, "secret-cidr").await;

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
        "rotation should succeed without login; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("AppRole secret_id rotated"));
    assert!(
        !stdout.contains("AppRole login OK"),
        "should not attempt login when token_bound_cidrs is set; stdout:\n{stdout}"
    );

    let updated = fs::read_to_string(&secret_path).expect("read secret_id");
    assert_eq!(updated, "secret-cidr");
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
    fs::write(
        &compose_file,
        "services:\n  bootroot-http01:\n    image: test\n",
    )
    .expect("write compose");
    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-remote").await;

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    write_fake_docker(&bin_dir, &docker_log).expect("write fake docker");

    // Prepare render source: write a responder.toml containing the expected hmac
    let responder_dir = temp_dir.path().join("secrets").join("responder");
    fs::create_dir_all(&responder_dir).expect("create responder dir");
    let render_source = temp_dir.path().join("responder-render-src.toml");
    fs::write(&render_source, "hmac_secret = \"hmac-remote\"\n").expect("write render source");

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
            "responder-hmac",
            "--hmac",
            "hmac-remote",
        ])
        .env("PATH", combined_path)
        .env("DOCKER_OUTPUT", &docker_log)
        .env("RENDER_SOURCE", &render_source)
        .env("RENDER_TARGET", responder_dir.join("responder.toml"))
        .output()
        .expect("run rotate responder-hmac");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // Verify OBA-responder restart comes BEFORE compose kill -s HUP bootroot-http01
    let docker_args_log = fs::read_to_string(&docker_log).expect("read docker log");
    let lines: Vec<&str> = docker_args_log.lines().collect();

    let oba_restart_idx = lines
        .iter()
        .position(|line| {
            line.contains("restart") && line.contains("bootroot-openbao-agent-responder")
        })
        .unwrap_or_else(|| {
            panic!("restart OBA-responder should be invoked\nlog:\n{docker_args_log}")
        });
    let hup_idx = lines
        .iter()
        .position(|line| line.contains("kill") && line.contains("HUP"))
        .unwrap_or_else(|| {
            panic!("compose kill -s HUP should be invoked\nlog:\n{docker_args_log}")
        });
    assert!(
        oba_restart_idx < hup_idx,
        "OBA restart should come before HUP reload\nlog:\n{docker_args_log}"
    );

    // Verify responder.toml was rendered with new hmac value
    let rendered = fs::read_to_string(responder_dir.join("responder.toml"))
        .expect("read rendered responder.toml");
    assert!(
        rendered.contains("hmac-remote"),
        "responder.toml should contain new hmac"
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

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    write_fake_docker(&bin_dir, &docker_log).expect("write fake docker");

    let responder_dir = temp_dir.path().join("secrets").join("responder");
    fs::create_dir_all(&responder_dir).expect("create responder dir");
    let render_source = temp_dir.path().join("responder-render-src.toml");
    fs::write(&render_source, "hmac_secret = \"hmac-runtime\"\n").expect("write render source");

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);
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
        .env("PATH", combined_path)
        .env("DOCKER_OUTPUT", &docker_log)
        .env("RENDER_SOURCE", &render_source)
        .env("RENDER_TARGET", responder_dir.join("responder.toml"))
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
    // EAB kid/hmac from mock are "new-kid" and "new-hmac"; both should be masked.
    assert!(
        !stdout.contains("- EAB HMAC: new-hmac"),
        "EAB HMAC should be masked without --show-secrets:\n{stdout}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_openbao_recovery_rotates_root_token_only() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    stub_openbao_for_recovery_root_token_rotation(&openbao).await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "openbao-recovery",
            "--rotate-root-token",
        ])
        .output()
        .expect("run rotate openbao-recovery root-token");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("bootroot rotate: summary"));
    assert!(stdout.contains("OpenBao recovery rotation: root-token"));
    assert!(
        stdout.contains("- root token: ****oken"),
        "expected masked root token in stdout:\n{stdout}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_openbao_recovery_writes_output_file() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    let output_path = temp_dir
        .path()
        .join("secrets")
        .join("openbao-recovery.json");
    stub_openbao_for_recovery_combined_rotation(&openbao).await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "openbao-recovery",
            "--rotate-unseal-keys",
            "--rotate-root-token",
            "--unseal-key",
            "old-unseal-1",
            "--unseal-key",
            "old-unseal-2",
            "--unseal-key",
            "old-unseal-3",
            "--output",
            output_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run rotate openbao-recovery combined");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("recovery credentials written"));
    assert!(!stdout.contains("new-unseal-1"));
    assert!(!stdout.contains("new-root-token"));

    let saved = fs::read_to_string(&output_path).expect("read output file");
    let parsed: serde_json::Value = serde_json::from_str(&saved).expect("parse output json");
    assert_eq!(parsed["root_token"], "new-root-token");
    assert_eq!(
        parsed["unseal_keys"],
        json!([
            "new-unseal-1",
            "new-unseal-2",
            "new-unseal-3",
            "new-unseal-4",
            "new-unseal-5"
        ])
    );

    let mode = fs::metadata(&output_path)
        .expect("output metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_openbao_recovery_keeps_approle_state_unchanged() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
        .expect("prepare state");
    fs::write(&secret_path, "existing-secret-id").expect("write existing secret_id");

    let state_path = temp_dir.path().join("state.json");
    let state_before = fs::read_to_string(&state_path).expect("read initial state");

    let unseal_file = temp_dir.path().join("unseal-keys.txt");
    fs::write(&unseal_file, "old-unseal-1\nold-unseal-2\nold-unseal-3\n")
        .expect("write unseal key file");
    let output_path = temp_dir
        .path()
        .join("secrets")
        .join("openbao-recovery.json");
    stub_openbao_for_recovery_combined_rotation(&openbao).await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "openbao-recovery",
            "--rotate-unseal-keys",
            "--rotate-root-token",
            "--unseal-key-file",
            unseal_file.to_string_lossy().as_ref(),
            "--output",
            output_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run rotate openbao-recovery");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("AppRole + SecretID configuration unchanged"));

    let state_after = fs::read_to_string(&state_path).expect("read final state");
    assert_eq!(state_before, state_after, "state.json should not change");

    let secret_after = fs::read_to_string(&secret_path).expect("read final secret_id");
    assert_eq!(
        secret_after, "existing-secret-id",
        "secret_id file should not be changed"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_openbao_recovery_unseal_keys_fails_when_openbao_sealed() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");
    stub_openbao_for_recovery_sealed(&openbao).await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "openbao-recovery",
            "--rotate-unseal-keys",
            "--unseal-key",
            "old-unseal-1",
            "--unseal-key",
            "old-unseal-2",
            "--unseal-key",
            "old-unseal-3",
        ])
        .output()
        .expect("run rotate openbao-recovery sealed");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains("OpenBao remains sealed"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_openbao_recovery_unseal_keys_fails_when_rotation_not_complete() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");
    stub_openbao_for_recovery_root_rotation_incomplete(&openbao).await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "openbao-recovery",
            "--rotate-unseal-keys",
            "--unseal-key",
            "old-unseal-1",
            "--unseal-key",
            "old-unseal-2",
            "--unseal-key",
            "old-unseal-3",
        ])
        .output()
        .expect("run rotate openbao-recovery root rotation incomplete");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains("root-key rotation did not complete"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_openbao_recovery_unseal_keys_requires_enough_keys_in_yes_mode() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");
    stub_openbao_for_recovery_root_rotation_ready(&openbao).await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "openbao-recovery",
            "--rotate-unseal-keys",
            "--unseal-key",
            "old-unseal-1",
            "--unseal-key",
            "old-unseal-2",
        ])
        .output()
        .expect("run rotate openbao-recovery with insufficient keys");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains("At least 3 existing unseal keys are required for root-key rotation"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_openbao_recovery_show_secrets_reveals_plaintext() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    stub_openbao_for_recovery_root_token_rotation(&openbao).await;

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "--show-secrets",
            "openbao-recovery",
            "--rotate-root-token",
        ])
        .output()
        .expect("run rotate openbao-recovery with --show-secrets");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("- root token: new-root-token"),
        "expected plaintext root token in stdout:\n{stdout}"
    );
}

fn prepare_app_state_no_policy(
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
            "policy_name": ROLE_NAME,
            "secret_id_wrap_ttl": "0"
        }
    });
    fs::write(&state_path, serde_json::to_string_pretty(&state)?).context("write state")?;

    let secret_dir = root.join("secrets").join("services").join(SERVICE_NAME);
    fs::create_dir_all(&secret_dir).context("create secrets dir")?;
    fs::write(root.join("agent.toml"), "# agent").context("write agent config")?;
    Ok(root.join(secret_id_path))
}

fn prepare_app_state_with_cidrs(
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
            "policy_name": ROLE_NAME,
            "secret_id_wrap_ttl": "0",
            "token_bound_cidrs": ["10.0.0.0/24"]
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
            "policy_name": ROLE_NAME,
            "secret_id_wrap_ttl": "0"
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
            "policy_name": "bootroot-service-edge-alt",
            "secret_id_wrap_ttl": "0"
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

/// Stubs `OpenBao` for rotation without a login mock. If login is
/// attempted the request will get no matching mock and return a 404,
/// causing the test to fail — proving the CIDR-bound skip path works.
async fn stub_openbao_for_rotation_no_login(server: &MockServer, new_secret_id: &str) {
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

    // No login mock: any login attempt will get a 404.
}

async fn stub_openbao_for_wrapped_rotation(server: &MockServer, new_secret_id: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/secret-id")))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .and(header("X-Vault-Wrap-TTL", "30m"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": "wrap-rotation-token",
                "ttl": 1800,
                "creation_time": "2026-04-13T00:00:00Z",
                "creation_path": format!("auth/approle/role/{ROLE_NAME}/secret-id")
            }
        })))
        .expect(1)
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(header("X-Vault-Token", "wrap-rotation-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "secret_id": new_secret_id,
                "secret_id_accessor": "acc"
            }
        })))
        .expect(1)
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

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SECONDARY_SERVICE_NAME}/eab"
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

async fn stub_openbao_for_recovery_root_token_rotation(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/seal-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sealed": false,
            "t": 3,
            "n": 5
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/token/create"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .and(body_json(json!({
            "policies": ["root"],
            "renewable": false,
            "no_parent": true
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "new-root-token" }
        })))
        .mount(server)
        .await;
}

async fn stub_openbao_for_recovery_combined_rotation(server: &MockServer) {
    stub_openbao_for_recovery_root_token_rotation(server).await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/rotate/root/init"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .and(body_json(json!({
            "secret_shares": 5,
            "secret_threshold": 3
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "nonce": "nonce-1",
                "progress": 0
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/rotate/root/update"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .and(body_json(json!({
            "nonce": "nonce-1",
            "key": "old-unseal-1"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "complete": false }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/rotate/root/update"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .and(body_json(json!({
            "nonce": "nonce-1",
            "key": "old-unseal-2"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "complete": false }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/rotate/root/update"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .and(body_json(json!({
            "nonce": "nonce-1",
            "key": "old-unseal-3"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "complete": true,
                "keys": [
                    "new-unseal-1",
                    "new-unseal-2",
                    "new-unseal-3",
                    "new-unseal-4",
                    "new-unseal-5"
                ]
            }
        })))
        .mount(server)
        .await;
}

async fn stub_openbao_for_recovery_sealed(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/seal-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sealed": true,
            "t": 3,
            "n": 5
        })))
        .mount(server)
        .await;
}

async fn stub_openbao_for_recovery_root_rotation_ready(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/seal-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sealed": false,
            "t": 3,
            "n": 5
        })))
        .mount(server)
        .await;
}

async fn stub_openbao_for_recovery_root_rotation_incomplete(server: &MockServer) {
    stub_openbao_for_recovery_root_rotation_ready(server).await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/rotate/root/init"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .and(body_json(json!({
            "secret_shares": 5,
            "secret_threshold": 3
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "nonce": "nonce-incomplete",
                "progress": 0
            }
        })))
        .mount(server)
        .await;

    for key in ["old-unseal-1", "old-unseal-2", "old-unseal-3"] {
        Mock::given(method("POST"))
            .and(path("/v1/sys/rotate/root/update"))
            .and(header("X-Vault-Token", support::ROOT_TOKEN))
            .and(body_json(json!({
                "nonce": "nonce-incomplete",
                "key": key
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "complete": false }
            })))
            .mount(server)
            .await;
    }
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

# Simulate OpenBao Agent rendering on restart of OBA containers
if [ "${1:-}" = "restart" ]; then
  case "${2:-}" in
    bootroot-openbao-agent-*)
      if [ -n "${RENDER_SOURCE:-}" ] && [ -n "${RENDER_TARGET:-}" ]; then
        cp "$RENDER_SOURCE" "$RENDER_TARGET"
      fi
      ;;
  esac
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

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_trust_sync_writes_global_and_per_service() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    prepare_app_state(
        temp_dir.path(),
        &openbao.uri(),
        "daemon",
        "remote-bootstrap",
    )
    .expect("prepare state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;
    let global_mock = Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount_as_scoped(&openbao)
        .await;
    let service_mock = Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/trust"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount_as_scoped(&openbao)
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
            "trust-sync",
        ])
        .output()
        .expect("run rotate trust-sync");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("CA trust updated"));
    assert!(
        stdout.contains(SERVICE_NAME),
        "stdout should mention the service name: {stdout}"
    );

    // Verify mock expectations: global and per-service writes each called exactly once.
    drop(global_mock);
    drop(service_mock);
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_force_reissue_deletes_cert_and_key() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
        .expect("prepare state");

    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(temp_dir.path().join("certs")).expect("create certs dir");
    fs::write(&cert_path, "fake-cert").expect("write cert");
    fs::write(&key_path, "fake-key").expect("write key");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let pkill_log = temp_dir.path().join("pkill.log");
    write_fake_pkill(&bin_dir, &pkill_log).expect("write fake pkill");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    let path_env = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path_env);
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "force-reissue",
            "--service-name",
            SERVICE_NAME,
        ])
        .env("PATH", combined_path)
        .env("PKILL_OUTPUT", &pkill_log)
        .output()
        .expect("run rotate force-reissue");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("cert/key deleted"));
    assert!(!cert_path.exists(), "cert should be deleted");
    assert!(!key_path.exists(), "key should be deleted");

    let pkill_args = fs::read_to_string(&pkill_log).expect("read pkill log");
    assert!(pkill_args.contains("-HUP"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_force_reissue_remote_prints_hint() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(
        temp_dir.path(),
        &openbao.uri(),
        "daemon",
        "remote-bootstrap",
    )
    .expect("prepare state");

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
            "force-reissue",
            "--service-name",
            SERVICE_NAME,
        ])
        .output()
        .expect("run rotate force-reissue");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("bootroot-remote bootstrap"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_force_reissue_missing_service_fails() {
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
            "force-reissue",
            "--service-name",
            "missing-service",
        ])
        .output()
        .expect("run rotate force-reissue");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stderr.contains("Service not found"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_db_writes_kv_and_restarts_stepca() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    // Start mock PostgreSQL server.
    let (pg_port, _pg_handle) = start_mock_postgres();

    let admin_dsn =
        format!("postgresql://admin:adminpass@127.0.0.1:{pg_port}/postgres?sslmode=disable");
    let current_dsn =
        format!("postgresql://step:old-pass@127.0.0.1:{pg_port}/stepca?sslmode=disable");

    // Write state.json.
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    // Create secrets/config/ca.json with a current DSN.
    let secrets_dir = temp_dir.path().join("secrets");
    fs::create_dir_all(secrets_dir.join("config")).expect("create config dir");
    fs::write(
        secrets_dir.join("config").join("ca.json"),
        serde_json::to_string(&json!({
            "db": {
                "type": "postgresql",
                "dataSource": current_dsn
            }
        }))
        .expect("serialize ca.json"),
    )
    .expect("write ca.json");

    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}\n").expect("write compose file");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    write_fake_docker(&bin_dir, &docker_log).expect("write fake docker");

    // The new DSN that `rotate_db` will build after provisioning. The rotate
    // path routes the stored step-ca DSN through `for_compose_runtime`, so
    // host/port flip to the compose-internal pair (`postgres:5432`)
    // regardless of the admin/current DSN's host-side host/port.
    let expected_new_dsn =
        "postgresql://step:new-db-pass-123@postgres:5432/stepca?sslmode=disable".to_string();

    stub_openbao_for_db_rotation(&openbao, &expected_new_dsn).await;

    let path_env = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path_env);
    // Fake docker copies RENDER_SOURCE → RENDER_TARGET on OBA restart,
    // simulating OpenBao Agent rendering the ca.json template.
    let render_source = secrets_dir.join("config").join("ca.json.new");
    fs::write(
        &render_source,
        serde_json::to_string(&json!({
            "db": {
                "type": "postgresql",
                "dataSource": expected_new_dsn
            }
        }))
        .expect("serialize new ca.json"),
    )
    .expect("write ca.json.new");

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
            "db",
            "--db-admin-dsn",
            &admin_dsn,
            "--db-password",
            "new-db-pass-123",
        ])
        .env("PATH", combined_path)
        .env("DOCKER_OUTPUT", &docker_log)
        .env("RENDER_SOURCE", &render_source)
        .env("RENDER_TARGET", secrets_dir.join("config").join("ca.json"))
        .output()
        .expect("run rotate db");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("bootroot rotate: summary"));

    // Verify OBA-stepca restart comes BEFORE compose restart step-ca.
    let docker_args_log = fs::read_to_string(&docker_log).expect("read docker log");
    let lines: Vec<&str> = docker_args_log.lines().collect();
    let oba_restart_idx = lines
        .iter()
        .position(|line| line.contains("restart") && line.contains("bootroot-openbao-agent-stepca"))
        .unwrap_or_else(|| panic!("restart OBA-stepca should be invoked\nlog:\n{docker_args_log}"));
    let compose_restart_idx = lines
        .iter()
        .position(|line| {
            line.contains("compose") && line.contains("restart") && line.contains("step-ca")
        })
        .unwrap_or_else(|| {
            panic!("restart step-ca command should be invoked\nlog:\n{docker_args_log}")
        });
    assert!(
        oba_restart_idx < compose_restart_idx,
        "OBA restart should come before compose restart\nlog:\n{docker_args_log}"
    );

    // Verify ca.json was rendered with the new DSN.
    let rendered = fs::read_to_string(secrets_dir.join("config").join("ca.json"))
        .expect("read rendered ca.json");
    assert!(
        rendered.contains("new-db-pass-123"),
        "ca.json should contain the new password:\n{rendered}"
    );
}

#[tokio::test]
async fn test_rotate_db_self_heals_corrupted_compose_port() {
    // Regression for issue #542 Symptom 1: a step-ca DSN previously
    // written to KV / ca.json with a non-canonical (host, port) pair
    // (e.g. `postgres:5433`) must be rewritten back to the canonical
    // compose pair (`postgres:5432`) on the next `rotate db`. The fix is
    // that `rotate db` routes the rebuilt new DSN through
    // `for_compose_runtime` before writing, so the invariant holds
    // regardless of what the previously-stored value was.
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    let (pg_port, _pg_handle) = start_mock_postgres();

    let admin_dsn =
        format!("postgresql://admin:adminpass@127.0.0.1:{pg_port}/postgres?sslmode=disable");
    // Corrupted current DSN: compose-internal host paired with the
    // host-side published port. Represents what Symptom 1 stored.
    let current_dsn = "postgresql://step:old-pass@postgres:5433/stepca?sslmode=disable";

    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    let secrets_dir = temp_dir.path().join("secrets");
    fs::create_dir_all(secrets_dir.join("config")).expect("create config dir");
    fs::write(
        secrets_dir.join("config").join("ca.json"),
        serde_json::to_string(&json!({
            "db": {
                "type": "postgresql",
                "dataSource": current_dsn
            }
        }))
        .expect("serialize ca.json"),
    )
    .expect("write ca.json");

    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}\n").expect("write compose file");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    write_fake_docker(&bin_dir, &docker_log).expect("write fake docker");

    // After rotation, the step-ca DSN must be the canonical compose pair
    // — *not* `postgres:5433` (the corrupted input).
    let expected_new_dsn =
        "postgresql://step:new-db-pass-123@postgres:5432/stepca?sslmode=disable".to_string();

    stub_openbao_for_db_rotation(&openbao, &expected_new_dsn).await;

    let path_env = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path_env);
    let render_source = secrets_dir.join("config").join("ca.json.new");
    fs::write(
        &render_source,
        serde_json::to_string(&json!({
            "db": {
                "type": "postgresql",
                "dataSource": expected_new_dsn
            }
        }))
        .expect("serialize new ca.json"),
    )
    .expect("write ca.json.new");

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
            "db",
            "--db-admin-dsn",
            &admin_dsn,
            "--db-password",
            "new-db-pass-123",
        ])
        .env("PATH", combined_path)
        .env("DOCKER_OUTPUT", &docker_log)
        .env("RENDER_SOURCE", &render_source)
        .env("RENDER_TARGET", secrets_dir.join("config").join("ca.json"))
        .output()
        .expect("run rotate db");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    // The wiremock stub only matches the canonical compose DSN. If the
    // corrupted port had leaked through, the KV POST would 404 and
    // `rotate db` would fail. A successful exit status plus the rendered
    // ca.json containing `postgres:5432` confirms the self-heal.
    let rendered = fs::read_to_string(secrets_dir.join("config").join("ca.json"))
        .expect("read rendered ca.json");
    assert!(
        rendered.contains("postgres:5432"),
        "rendered ca.json should self-heal to postgres:5432:\n{rendered}"
    );
    assert!(
        !rendered.contains("postgres:5433"),
        "rendered ca.json must not preserve the corrupted port:\n{rendered}"
    );
}

async fn stub_openbao_for_db_rotation(server: &MockServer, expected_dsn: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/stepca/db"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .and(body_json(json!({
            "data": {
                "value": expected_dsn
            }
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
}

/// Starts a mock `PostgreSQL` wire-protocol server on a random port.
///
/// Returns the port and a join handle for the background thread.
fn start_mock_postgres() -> (u16, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock pg");
    let port = listener.local_addr().expect("mock pg addr").port();
    let handle = std::thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            mock_pg_session(stream);
        }
    });
    (port, handle)
}

/// Handles a single `PostgreSQL` wire-protocol session for the mock server.
///
/// Supports the startup handshake and the extended query protocol messages
/// used by the `postgres` crate: Parse, Bind, Describe, Execute, Sync, Close.
#[allow(clippy::too_many_lines)]
fn mock_pg_session(mut stream: std::net::TcpStream) {
    use std::io::{Read, Write};

    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
        .expect("set read timeout");

    let mut buf = [0u8; 4096];

    // Read startup message (may be SSL probe first).
    let n = stream.read(&mut buf).expect("read startup");
    if n == 0 {
        return;
    }

    // SSL probe: 8 bytes with code 80877103.
    if n == 8 {
        let code = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if code == 80_877_103 {
            stream.write_all(b"N").expect("write ssl reject");
            stream.flush().expect("flush ssl reject");
            let _n2 = stream.read(&mut buf).expect("read real startup");
        }
    }

    mock_pg_send_startup(&mut stream);

    let mut is_select = false;
    let mut param_count: u16 = 0;
    while let Some(tag) = mock_pg_read_byte(&mut stream) {
        match tag {
            b'P' => {
                let payload = mock_pg_read_payload(&mut stream);
                mock_pg_handle_parse(&payload, &mut is_select, &mut param_count);
                stream
                    .write_all(&[b'1', 0, 0, 0, 4])
                    .expect("write ParseComplete");
            }
            b'D' => {
                let payload = mock_pg_read_payload(&mut stream);
                mock_pg_handle_describe(&mut stream, &payload, is_select, param_count);
            }
            b'B' => {
                let _payload = mock_pg_read_payload(&mut stream);
                stream
                    .write_all(&[b'2', 0, 0, 0, 4])
                    .expect("write BindComplete");
            }
            b'E' => {
                let _payload = mock_pg_read_payload(&mut stream);
                mock_pg_send_command_complete(&mut stream, is_select);
            }
            b'S' => {
                let _payload = mock_pg_read_payload(&mut stream);
                stream
                    .write_all(&[b'Z', 0, 0, 0, 5, b'I'])
                    .expect("write ReadyForQuery");
                stream.flush().expect("flush sync");
            }
            b'C' => {
                let _payload = mock_pg_read_payload(&mut stream);
                stream
                    .write_all(&[b'3', 0, 0, 0, 4])
                    .expect("write CloseComplete");
            }
            b'X' => {
                let _payload = mock_pg_read_payload(&mut stream);
                break;
            }
            _ => {
                let _payload = mock_pg_read_payload(&mut stream);
            }
        }
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn mock_pg_send_startup(stream: &mut std::net::TcpStream) {
    use std::io::Write;

    // AuthenticationOk: 'R' + i32(8) + i32(0)
    stream
        .write_all(&[b'R', 0, 0, 0, 8, 0, 0, 0, 0])
        .expect("write auth ok");

    // Required ParameterStatus messages.
    for (key, val) in [
        ("server_version", "16.0"),
        ("client_encoding", "UTF8"),
        ("server_encoding", "UTF8"),
        ("integer_datetimes", "on"),
    ] {
        let mut msg = vec![b'S'];
        let body_len: i32 = 4 + key.len() as i32 + 1 + val.len() as i32 + 1;
        msg.extend_from_slice(&body_len.to_be_bytes());
        msg.extend_from_slice(key.as_bytes());
        msg.push(0);
        msg.extend_from_slice(val.as_bytes());
        msg.push(0);
        stream.write_all(&msg).expect("write ParameterStatus");
    }

    // BackendKeyData: 'K' + i32(12) + pid(4) + secret(4)
    stream
        .write_all(&[b'K', 0, 0, 0, 12, 0, 0, 0, 1, 0, 0, 0, 1])
        .expect("write BackendKeyData");

    // ReadyForQuery (idle): 'Z' + i32(5) + 'I'
    stream
        .write_all(&[b'Z', 0, 0, 0, 5, b'I'])
        .expect("write ready");
    stream.flush().expect("flush startup");
}

fn mock_pg_handle_parse(payload: &[u8], is_select: &mut bool, param_count: &mut u16) {
    // Parse payload: statement_name\0 + query\0 + i16(param_types) + type_oids...
    if let Some(pos) = payload.iter().position(|&b| b == 0) {
        let after = &payload[pos + 1..];
        if let Some(end) = after.iter().position(|&b| b == 0) {
            let query_str = String::from_utf8_lossy(&after[..end]).to_string();
            *is_select = query_str.to_uppercase().starts_with("SELECT");
            // Count $N placeholders — the client may send 0 param types
            // in Parse (meaning "server decides").
            *param_count = 0;
            for i in 1..=10u16 {
                if query_str.contains(&format!("${i}")) {
                    *param_count = i;
                }
            }
        }
    }
}

fn mock_pg_handle_describe(
    stream: &mut std::net::TcpStream,
    payload: &[u8],
    is_select: bool,
    param_count: u16,
) {
    use std::io::Write;

    let describe_type = payload.first().copied().unwrap_or(b'?');

    if describe_type == b'S' {
        // ParameterDescription: 't' + len + i16(count) + type_oids...
        let pd_body: i32 = 4 + 2 + i32::from(param_count) * 4;
        let mut msg = vec![b't'];
        msg.extend_from_slice(&pd_body.to_be_bytes());
        msg.extend_from_slice(&param_count.to_be_bytes());
        for _ in 0..param_count {
            msg.extend_from_slice(&25i32.to_be_bytes()); // TEXT OID
        }
        stream.write_all(&msg).expect("write ParamDesc");
    }

    if is_select {
        // RowDescription with 1 column (int4).
        // Fixed layout: 'T' + len + i16(1) + "col\0" + table_oid(4) +
        //   col_num(2) + type_oid(4) + type_size(2) + type_mod(4) + fmt(2)
        let col_name = b"col\0";
        let body_len: i32 = 4 + 2 + 4 + 4 + 2 + 4 + 2 + 4 + 2; // col_name is 4 bytes
        let mut msg = vec![b'T'];
        msg.extend_from_slice(&body_len.to_be_bytes());
        msg.extend_from_slice(&1i16.to_be_bytes());
        msg.extend_from_slice(col_name);
        msg.extend_from_slice(&0i32.to_be_bytes()); // table OID
        msg.extend_from_slice(&0i16.to_be_bytes()); // column num
        msg.extend_from_slice(&23i32.to_be_bytes()); // type OID (int4)
        msg.extend_from_slice(&4i16.to_be_bytes()); // type size
        msg.extend_from_slice(&(-1i32).to_be_bytes()); // type modifier
        msg.extend_from_slice(&0i16.to_be_bytes()); // format code
        stream.write_all(&msg).expect("write RowDescription");
    } else {
        // NoData: 'n' + i32(4)
        stream.write_all(&[b'n', 0, 0, 0, 4]).expect("write NoData");
    }
}

#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)]
fn mock_pg_send_command_complete(stream: &mut std::net::TcpStream, is_select: bool) {
    use std::io::Write;

    let tag = if is_select {
        b"SELECT 0\0" as &[u8]
    } else {
        b"COMMAND\0"
    };
    let len: i32 = 4 + tag.len() as i32;
    let mut msg = vec![b'C'];
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(tag);
    stream.write_all(&msg).expect("write CommandComplete");
}

fn mock_pg_read_byte(stream: &mut std::net::TcpStream) -> Option<u8> {
    use std::io::Read;
    let mut b = [0u8; 1];
    match stream.read_exact(&mut b) {
        Ok(()) => Some(b[0]),
        Err(_) => None,
    }
}

#[allow(clippy::cast_sign_loss)]
fn mock_pg_read_payload(stream: &mut std::net::TcpStream) -> Vec<u8> {
    use std::io::Read;
    let mut len_buf = [0u8; 4];
    if stream.read_exact(&mut len_buf).is_err() {
        return Vec::new();
    }
    let len = i32::from_be_bytes(len_buf);
    if len <= 4 {
        return Vec::new();
    }
    let payload_len = (len - 4) as usize;
    let mut payload = vec![0u8; payload_len];
    if stream.read_exact(&mut payload).is_err() {
        return Vec::new();
    }
    payload
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_full_mode_validates_root_key() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    // Delete root_ca_key so pre-flight validation fails
    let root_key = temp_dir
        .path()
        .join("secrets")
        .join("secrets")
        .join("root_ca_key");
    let _ = fs::remove_file(&root_key);

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
            "ca-key",
            "--full",
        ])
        .output()
        .expect("run rotate ca-key --full");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "ca-key --full should fail without root key; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("root_ca_key"),
        "stderr should mention missing root key: {stderr}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_backup_creates_state_file() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Use a fake docker that logs commands but fails on step certificate create
    // so Phase 1 (backup) completes and Phase 2 (generate) fails.
    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    let fake_docker = r#"#!/bin/sh
set -eu
if [ -n "${DOCKER_OUTPUT:-}" ]; then
  printf "%s\n" "$*" >> "$DOCKER_OUTPUT"
fi
# Fail on step certificate create (Phase 2)
case "$*" in
  *"step certificate create"*) exit 1 ;;
esac
exit 0
"#;
    fs::write(bin_dir.join("docker"), fake_docker).expect("write fake docker");
    fs::set_permissions(bin_dir.join("docker"), fs::Permissions::from_mode(0o700))
        .expect("chmod fake docker");
    fs::write(&docker_log, "").expect("seed docker log");

    let path_var = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path_var}", bin_dir.display());

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
        ])
        .env("PATH", &combined_path)
        .env("DOCKER_OUTPUT", &docker_log)
        .output()
        .expect("run rotate ca-key");

    // Phase 2 (docker) should fail, but Phase 1 (backup) should have completed.
    assert!(!output.status.success(), "command should fail at Phase 2");

    // Verify backup files were created (Phase 1)
    let secrets_dir = temp_dir.path().join("secrets");
    assert!(
        secrets_dir
            .join("certs")
            .join("intermediate_ca.crt.bak")
            .exists(),
        "intermediate cert backup should exist"
    );
    assert!(
        secrets_dir
            .join("secrets")
            .join("intermediate_ca_key.bak")
            .exists(),
        "intermediate key backup should exist"
    );

    // Verify rotation-state.json was created
    let state_path = temp_dir.path().join("rotation-state.json");
    assert!(state_path.exists(), "rotation-state.json should exist");
    let state_contents = fs::read_to_string(&state_path).expect("read rotation-state.json");
    let state: serde_json::Value =
        serde_json::from_str(&state_contents).expect("parse rotation-state.json");
    assert_eq!(state["mode"], "intermediate-only");
    assert_eq!(state["phase"], 1);
    assert!(
        !state["old_intermediate_fp"]
            .as_str()
            .unwrap_or("")
            .is_empty()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_resumes_from_phase() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Pre-create rotation-state.json at phase 6 (all trust operations done).
    // Phase 7 (cleanup) should run and delete the file.
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "intermediate-only",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "aaa",
            "new_root_fp": "aaa",
            "old_intermediate_fp": "bbb",
            "new_intermediate_fp": "ccc",
            "phase": 6
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
        ])
        .output()
        .expect("run rotate ca-key resume");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "should succeed resuming from phase 6; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Resuming") || stdout.contains("phase"),
        "stdout should mention resuming: {stdout}"
    );
    // rotation-state.json should be deleted after Phase 7
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be deleted after cleanup"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_finalize_blocks_unmigrated() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
        .expect("prepare state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Pre-create rotation-state.json at phase 5
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "intermediate-only",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "aaa",
            "new_root_fp": "aaa",
            "old_intermediate_fp": "bbb",
            "new_intermediate_fp": "ccc",
            "phase": 5
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    // Service certs don't exist — Phase 6 should see them as un-migrated and block.
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
        ])
        .output()
        .expect("run rotate ca-key finalize");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "should fail when un-migrated services exist; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Cannot finalize") || stderr.contains(SERVICE_NAME),
        "stderr should mention finalization blocked or the service name: {stderr}"
    );
}

#[tokio::test]
async fn test_rotate_trust_sync_blocked_by_rotation_state() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    prepare_app_state(
        temp_dir.path(),
        &openbao.uri(),
        "daemon",
        "remote-bootstrap",
    )
    .expect("prepare state");

    // Simulate an in-progress CA key rotation.
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        r#"{"mode":"intermediate-only","phase":3}"#,
    )
    .expect("write rotation-state.json");

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
            "trust-sync",
        ])
        .output()
        .expect("run rotate trust-sync");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "trust-sync should fail when rotation-state.json exists; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("rotation-state.json") || stderr.contains("trust-sync is blocked"),
        "stderr should mention rotation conflict: {stderr}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_preflight_missing_root_cert() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Remove root_ca.crt to trigger pre-flight failure
    fs::remove_file(
        temp_dir
            .path()
            .join("secrets")
            .join("certs")
            .join("root_ca.crt"),
    )
    .expect("remove root cert");

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
        ])
        .output()
        .expect("run rotate ca-key");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "should fail when root cert missing; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("root_ca.crt"),
        "error should mention missing root cert: {stderr}"
    );
}

/// Writes a fake docker script that replaces the intermediate cert on
/// `step certificate create` and succeeds on `compose restart`.
fn write_full_rotation_fake_docker(
    bin_dir: &Path,
    docker_log: &Path,
    new_cert_source: &Path,
) -> PathBuf {
    let script = format!(
        r#"#!/bin/sh
set -eu
if [ -n "${{DOCKER_OUTPUT:-}}" ]; then
  printf "%s\n" "$*" >> "$DOCKER_OUTPUT"
fi
case "$*" in
  *"step certificate create"*)
    # Simulate cert generation by copying the pre-staged cert
    cp "{new_cert}" "$(echo "$*" | grep -oE '/[^ ]*intermediate_ca\.crt' | head -1 || true)" 2>/dev/null || true
    # Also copy to the secrets dir via mount path extraction
    cp "{new_cert}" "${{ROTATION_NEW_CERT_TARGET:-/dev/null}}" 2>/dev/null || true
    exit 0
    ;;
  *"compose"*"restart"*)
    exit 0
    ;;
esac
exit 0
"#,
        new_cert = new_cert_source.display()
    );
    let docker_path = bin_dir.join("docker");
    fs::write(&docker_path, script).expect("write fake docker");
    fs::set_permissions(&docker_path, fs::Permissions::from_mode(0o700))
        .expect("chmod fake docker");
    fs::write(docker_log, "").expect("seed docker log");
    docker_path
}

/// Writes a fake docker that handles both root and intermediate cert
/// generation for full-mode rotation tests.
fn write_full_mode_rotation_fake_docker(
    bin_dir: &Path,
    docker_log: &Path,
    new_root_cert_source: &Path,
    new_inter_cert_source: &Path,
) -> PathBuf {
    let script = format!(
        r#"#!/bin/sh
set -eu
if [ -n "${{DOCKER_OUTPUT:-}}" ]; then
  printf "%s\n" "$*" >> "$DOCKER_OUTPUT"
fi
case "$*" in
  *"--profile"*"root-ca"*)
    # Root CA generation: copy staged root cert to target
    cp "{new_root}" "${{ROTATION_NEW_ROOT_TARGET:-/dev/null}}" 2>/dev/null || true
    exit 0
    ;;
  *"step certificate create"*)
    # Intermediate CA generation: copy staged intermediate cert
    cp "{new_inter}" "${{ROTATION_NEW_CERT_TARGET:-/dev/null}}" 2>/dev/null || true
    exit 0
    ;;
  *"compose"*"restart"*)
    exit 0
    ;;
esac
exit 0
"#,
        new_root = new_root_cert_source.display(),
        new_inter = new_inter_cert_source.display(),
    );
    let docker_path = bin_dir.join("docker");
    fs::write(&docker_path, script).expect("write fake docker");
    fs::set_permissions(&docker_path, fs::Permissions::from_mode(0o700))
        .expect("chmod fake docker");
    fs::write(docker_log, "").expect("seed docker log");
    docker_path
}

/// Generates a self-signed test certificate PEM for the given common name.
fn generate_test_cert_pem(common_name: &str) -> String {
    use rcgen::{CertificateParams, DnType, KeyPair};

    let key = KeyPair::generate().expect("generate key");
    let mut params = CertificateParams::new(vec![common_name.to_string()]).expect("cert params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).expect("self signed");
    cert.pem()
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_happy_path_phase_0_through_7() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
        .expect("prepare state");

    // Write a docker-compose.yml (needed for Phase 4 restart)
    fs::write(
        temp_dir.path().join("docker-compose.yml"),
        "version: '3'\nservices:\n  step-ca:\n    image: test\n",
    )
    .expect("write compose file");

    // Generate a "new" intermediate cert that will replace the existing one
    let new_inter_pem = generate_test_cert_pem("new-intermediate.example");
    let new_cert_staging = temp_dir.path().join("new_intermediate_staged.crt");
    fs::write(&new_cert_staging, &new_inter_pem).expect("write staged cert");

    let inter_cert_path = temp_dir
        .path()
        .join("secrets")
        .join("certs")
        .join("intermediate_ca.crt");

    // Write a service cert that appears "issued by" the new intermediate.
    // Since new_inter_pem is self-signed (issuer == subject), using it as
    // the service cert makes cert_issued_by_new_intermediate return true.
    let svc_cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    fs::create_dir_all(svc_cert_path.parent().unwrap()).expect("create certs dir");
    fs::write(&svc_cert_path, &new_inter_pem).expect("write service cert");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    write_full_rotation_fake_docker(&bin_dir, &docker_log, &new_cert_staging);

    let pkill_log = temp_dir.path().join("pkill.log");
    write_fake_pkill(&bin_dir, &pkill_log).expect("write fake pkill");

    let path_var = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path_var}", bin_dir.display());

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Phase 3 writes trust to OpenBao (global + per-service)
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/trust"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
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
            "ca-key",
        ])
        .env("PATH", &combined_path)
        .env("DOCKER_OUTPUT", &docker_log)
        .env("PKILL_OUTPUT", &pkill_log)
        .env("ROTATION_NEW_CERT_TARGET", &inter_cert_path)
        .output()
        .expect("run rotate ca-key happy path");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "happy path should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("complete") || stdout.contains("Complete"),
        "stdout should mention completion: {stdout}"
    );
    // rotation-state.json should be cleaned up
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be deleted after completion"
    );
    // Backup files should still exist (no --cleanup)
    assert!(
        temp_dir
            .path()
            .join("secrets")
            .join("certs")
            .join("intermediate_ca.crt.bak")
            .exists(),
        "backup cert should be preserved without --cleanup"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_cleanup_deletes_backups() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    let secrets = temp_dir.path().join("secrets");
    // Create .bak files that Phase 7 should delete
    fs::write(
        secrets.join("certs").join("intermediate_ca.crt.bak"),
        "old-cert",
    )
    .expect("write cert bak");
    fs::write(
        secrets.join("secrets").join("intermediate_ca_key.bak"),
        "old-key",
    )
    .expect("write key bak");

    // Pre-create rotation-state.json at phase 6 so Phases 0-6 are skipped
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "intermediate-only",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "aaa",
            "new_root_fp": "aaa",
            "old_intermediate_fp": "bbb",
            "new_intermediate_fp": "ccc",
            "phase": 6
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
            "--cleanup",
        ])
        .output()
        .expect("run rotate ca-key --cleanup");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !secrets
            .join("certs")
            .join("intermediate_ca.crt.bak")
            .exists(),
        "cert backup should be deleted with --cleanup"
    );
    assert!(
        !secrets
            .join("secrets")
            .join("intermediate_ca_key.bak")
            .exists(),
        "key backup should be deleted with --cleanup"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_skip_reissue_skips_phase_5() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
        .expect("prepare state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/trust"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&openbao)
        .await;

    // Pre-create rotation-state.json at phase 4 to skip Phases 0-4
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "intermediate-only",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "aaa",
            "new_root_fp": "aaa",
            "old_intermediate_fp": "bbb",
            "new_intermediate_fp": "ccc",
            "phase": 4
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    // Write a service cert that does NOT match new intermediate
    // If Phase 5 were NOT skipped, this would trigger reissue logic
    let service_cert = temp_dir
        .path()
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("cert.pem");
    fs::create_dir_all(service_cert.parent().unwrap()).ok();
    fs::write(&service_cert, "dummy-cert-data").ok();

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
            "--skip",
            "reissue,finalize",
        ])
        .output()
        .expect("run rotate ca-key --skip reissue,finalize");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "should succeed with --skip reissue,finalize; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Phase 5 skipped — service cert should remain untouched
    assert!(
        service_cert.exists(),
        "service cert should be untouched when Phase 5 is skipped"
    );
    // rotation-state.json should be cleaned up (Phase 7)
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be deleted"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_force_finalize_with_unmigrated() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
        .expect("prepare state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/trust"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&openbao)
        .await;

    // Pre-create rotation-state.json at phase 5
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "intermediate-only",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "aaa",
            "new_root_fp": "aaa",
            "old_intermediate_fp": "bbb",
            "new_intermediate_fp": "ccc",
            "phase": 5
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    // Service certs don't match new intermediate → normally blocks finalization
    // --force should override
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
            "--force",
        ])
        .output()
        .expect("run rotate ca-key --force");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "should succeed with --force; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be deleted after forced finalization"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_stale_backup_warning() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    let secrets = temp_dir.path().join("secrets");
    // Create .bak files without rotation-state.json → stale backup warning
    fs::write(secrets.join("certs").join("intermediate_ca.crt.bak"), "old")
        .expect("write stale bak");

    // Use a fake docker that fails immediately so the test doesn't proceed too far
    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let fake_docker = "#!/bin/sh\nexit 1\n";
    fs::write(bin_dir.join("docker"), fake_docker).expect("write fake docker");
    fs::set_permissions(bin_dir.join("docker"), fs::Permissions::from_mode(0o700)).expect("chmod");

    let path_var = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path_var}", bin_dir.display());

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
        ])
        .env("PATH", &combined_path)
        .output()
        .expect("run rotate ca-key with stale backups");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("WARNING") || stderr.contains("backup"),
        "should warn about stale backup files: {stderr}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_full_mode_state_records_full() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Use a fake docker that fails on root cert generation so Phase 2 fails
    // but Phase 1 (backup) completes, creating rotation-state.json
    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let fake_docker = "#!/bin/sh\nexit 1\n";
    fs::write(bin_dir.join("docker"), fake_docker).expect("write fake docker");
    fs::set_permissions(bin_dir.join("docker"), fs::Permissions::from_mode(0o700)).expect("chmod");

    let path_var = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path_var}", bin_dir.display());

    let _output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
            "--full",
        ])
        .env("PATH", &combined_path)
        .output()
        .expect("run rotate ca-key --full");

    // Phase 1 should have created rotation-state.json with mode "full"
    let state_path = temp_dir.path().join("rotation-state.json");
    assert!(state_path.exists(), "rotation-state.json should exist");

    let contents = fs::read_to_string(&state_path).expect("read state");
    let state: serde_json::Value = serde_json::from_str(&contents).expect("parse json");
    assert_eq!(
        state["mode"],
        json!("full"),
        "rotation-state.json mode should be 'full'"
    );
    assert_eq!(
        state["phase"],
        json!(1),
        "should have completed phase 1 (backup)"
    );
    // Root backup files should exist in full mode
    let secrets = temp_dir.path().join("secrets");
    assert!(
        secrets.join("certs").join("root_ca.crt.bak").exists(),
        "root cert backup should exist"
    );
    assert!(
        secrets.join("secrets").join("root_ca_key.bak").exists(),
        "root key backup should exist"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_full_mode_4_fingerprints() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Capture what's written to the trust path
    let trust_mock = Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1..)
        .mount_as_scoped(&openbao)
        .await;

    // Pre-create rotation-state.json at phase 2 with mode=full and 4 distinct fingerprints
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "full",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "old-root-aaa",
            "new_root_fp": "new-root-bbb",
            "old_intermediate_fp": "old-inter-ccc",
            "new_intermediate_fp": "new-inter-ddd",
            "phase": 2
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    // Fake docker for compose restart (Phase 4)
    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let fake_docker = "#!/bin/sh\nexit 0\n";
    fs::write(bin_dir.join("docker"), fake_docker).expect("write fake docker");
    fs::set_permissions(bin_dir.join("docker"), fs::Permissions::from_mode(0o700)).expect("chmod");

    let path_var = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path_var}", bin_dir.display());

    // Run only phases 3+ (skip-reissue, skip-finalize to isolate phase 3)
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
            "--full",
            "--skip",
            "reissue,finalize",
            "--cleanup",
        ])
        .env("PATH", &combined_path)
        .output()
        .expect("run rotate ca-key --full from phase 2");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Verify the mock was actually called (trust was written)
    drop(trust_mock);
    assert!(
        stdout.contains("complete") || stdout.contains("Complete"),
        "stdout should mention completion: {stdout}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_mode_mismatch_bails() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Pre-create rotation-state.json with intermediate-only mode
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "intermediate-only",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "aaa",
            "new_root_fp": "aaa",
            "old_intermediate_fp": "bbb",
            "new_intermediate_fp": "ccc",
            "phase": 3
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    // Run with --full — mode mismatch should bail
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
            "--full",
        ])
        .output()
        .expect("run rotate ca-key --full with mismatched state");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "should fail with mode mismatch; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("does not match") || stderr.contains("mode"),
        "stderr should mention mode mismatch: {stderr}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_full_force_finalize_enhanced_warning() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
        .expect("prepare state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/trust"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&openbao)
        .await;

    // Pre-create rotation-state.json at phase 5 with mode=full
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "full",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "old-root",
            "new_root_fp": "new-root",
            "old_intermediate_fp": "old-inter",
            "new_intermediate_fp": "new-inter",
            "phase": 5
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    // Service certs don't match new intermediate → blocks finalization
    // --force should override with enhanced full-mode warning
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
            "--full",
            "--force",
        ])
        .output()
        .expect("run rotate ca-key --full --force");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "should succeed with --force; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Root fingerprint has changed")
            || stderr.contains("루트 지문이 변경되었고"),
        "stderr should have enhanced full-mode warning: {stderr}"
    );
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be deleted after completion"
    );
}

#[cfg(unix)]
#[tokio::test]
#[allow(clippy::too_many_lines)] // Integration test exercising all 8 phases end-to-end
async fn test_rotate_ca_key_full_mode_happy_path_phase_0_through_7() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "daemon", "local-file")
        .expect("prepare state");

    fs::write(
        temp_dir.path().join("docker-compose.yml"),
        "version: '3'\nservices:\n  step-ca:\n    image: test\n",
    )
    .expect("write compose file");

    // Generate distinct certs for root and intermediate
    let new_root_pem = generate_test_cert_pem("new-root.example");
    let new_inter_pem = generate_test_cert_pem("new-intermediate.example");
    let new_root_staging = temp_dir.path().join("new_root_staged.crt");
    let new_inter_staging = temp_dir.path().join("new_inter_staged.crt");
    fs::write(&new_root_staging, &new_root_pem).expect("write staged root cert");
    fs::write(&new_inter_staging, &new_inter_pem).expect("write staged intermediate cert");

    let root_cert_path = temp_dir
        .path()
        .join("secrets")
        .join("certs")
        .join("root_ca.crt");
    let inter_cert_path = temp_dir
        .path()
        .join("secrets")
        .join("certs")
        .join("intermediate_ca.crt");

    // Service cert matches new intermediate (self-signed = issuer == subject)
    let svc_cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    fs::create_dir_all(svc_cert_path.parent().unwrap()).expect("create certs dir");
    fs::write(&svc_cert_path, &new_inter_pem).expect("write service cert");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    write_full_mode_rotation_fake_docker(
        &bin_dir,
        &docker_log,
        &new_root_staging,
        &new_inter_staging,
    );

    let pkill_log = temp_dir.path().join("pkill.log");
    write_fake_pkill(&bin_dir, &pkill_log).expect("write fake pkill");

    let path_var = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path_var}", bin_dir.display());

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/trust"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
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
            "ca-key",
            "--full",
        ])
        .env("PATH", &combined_path)
        .env("DOCKER_OUTPUT", &docker_log)
        .env("PKILL_OUTPUT", &pkill_log)
        .env("ROTATION_NEW_ROOT_TARGET", &root_cert_path)
        .env("ROTATION_NEW_CERT_TARGET", &inter_cert_path)
        .output()
        .expect("run rotate ca-key --full happy path");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "full mode happy path should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Completion summary should mention "full" and show both fingerprints
    assert!(
        stdout.contains("complete") || stdout.contains("Complete"),
        "stdout should mention completion: {stdout}"
    );
    assert!(
        stdout.contains("root") || stdout.contains("루트"),
        "full mode completion should mention root fingerprint: {stdout}"
    );
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be deleted after completion"
    );
    // Root backups should exist (no --cleanup)
    assert!(
        temp_dir
            .path()
            .join("secrets")
            .join("certs")
            .join("root_ca.crt.bak")
            .exists(),
        "root cert backup should be preserved without --cleanup"
    );
    assert!(
        temp_dir
            .path()
            .join("secrets")
            .join("secrets")
            .join("root_ca_key.bak")
            .exists(),
        "root key backup should be preserved without --cleanup"
    );
    // Intermediate backups should also exist
    assert!(
        temp_dir
            .path()
            .join("secrets")
            .join("certs")
            .join("intermediate_ca.crt.bak")
            .exists(),
        "intermediate cert backup should be preserved without --cleanup"
    );

    // Verify docker log shows both root-ca and intermediate-ca generation
    let docker_commands = fs::read_to_string(&docker_log).expect("read docker log");
    assert!(
        docker_commands.contains("root-ca"),
        "docker log should contain root-ca profile: {docker_commands}"
    );
    assert!(
        docker_commands.contains("intermediate-ca"),
        "docker log should contain intermediate-ca profile: {docker_commands}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_full_mode_cleanup_deletes_root_backups() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    let secrets = temp_dir.path().join("secrets");
    // Create all .bak files that Phase 7 should delete in full mode
    fs::write(
        secrets.join("certs").join("root_ca.crt.bak"),
        "old-root-cert",
    )
    .expect("write root cert bak");
    fs::write(
        secrets.join("secrets").join("root_ca_key.bak"),
        "old-root-key",
    )
    .expect("write root key bak");
    fs::write(
        secrets.join("certs").join("intermediate_ca.crt.bak"),
        "old-cert",
    )
    .expect("write cert bak");
    fs::write(
        secrets.join("secrets").join("intermediate_ca_key.bak"),
        "old-key",
    )
    .expect("write key bak");

    // Pre-create rotation-state.json at phase 6 with mode=full
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "full",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "old-root",
            "new_root_fp": "new-root",
            "old_intermediate_fp": "old-inter",
            "new_intermediate_fp": "new-inter",
            "phase": 6
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
            "--full",
            "--cleanup",
        ])
        .output()
        .expect("run rotate ca-key --full --cleanup");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // Root backups should be deleted
    assert!(
        !secrets.join("certs").join("root_ca.crt.bak").exists(),
        "root cert backup should be deleted with --cleanup in full mode"
    );
    assert!(
        !secrets.join("secrets").join("root_ca_key.bak").exists(),
        "root key backup should be deleted with --cleanup in full mode"
    );
    // Intermediate backups should also be deleted
    assert!(
        !secrets
            .join("certs")
            .join("intermediate_ca.crt.bak")
            .exists(),
        "intermediate cert backup should be deleted with --cleanup"
    );
    assert!(
        !secrets
            .join("secrets")
            .join("intermediate_ca_key.bak")
            .exists(),
        "intermediate key backup should be deleted with --cleanup"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_reverse_mode_mismatch_bails() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Pre-create rotation-state.json with full mode
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "full",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "old-root",
            "new_root_fp": "new-root",
            "old_intermediate_fp": "old-inter",
            "new_intermediate_fp": "new-inter",
            "phase": 3
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    // Run WITHOUT --full — mode mismatch should bail
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
        ])
        .output()
        .expect("run rotate ca-key without --full with full state");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "should fail with reverse mode mismatch; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("does not match") || stderr.contains("mode"),
        "stderr should mention mode mismatch: {stderr}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_full_mode_resumes_from_phase() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Pre-create rotation-state.json at phase 6 with mode=full
    fs::write(
        temp_dir.path().join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "full",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "old-root",
            "new_root_fp": "new-root",
            "old_intermediate_fp": "old-inter",
            "new_intermediate_fp": "new-inter",
            "phase": 6
        }))
        .unwrap(),
    )
    .expect("write rotation-state.json");

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "rotate",
            "--openbao-url",
            &openbao.uri(),
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
            "--full",
        ])
        .output()
        .expect("run rotate ca-key --full resume from phase 6");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "should succeed resuming from phase 6; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Resuming") || stdout.contains("재개"),
        "stdout should mention resuming: {stdout}"
    );
    // Completion summary should show all 4 fingerprints for full mode
    assert!(
        stdout.contains("old-root") && stdout.contains("new-root"),
        "full mode summary should show old and new root fingerprints: {stdout}"
    );
    assert!(
        stdout.contains("old-inter") && stdout.contains("new-inter"),
        "full mode summary should show old and new intermediate fingerprints: {stdout}"
    );
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be cleaned up after completion"
    );
}
