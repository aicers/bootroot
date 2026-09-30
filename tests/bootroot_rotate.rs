#![cfg(unix)]

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;
use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{body_json, header, method, path, path_regex};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(unix)]
mod support;

#[path = "../src/runtime_image_declaration.rs"]
mod runtime_image_declaration;

const SERVICE_NAME: &str = "edge-proxy";
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
    // `docker restart` of an infra OBA container, simulating OBA rendering.
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
    for line in &change_pass_lines {
        assert!(line.contains(" -f"), "docker log line missing -f: {line}");
        assert!(
            line.contains("--password-file") && line.contains("--new-password-file"),
            "docker log line missing password file args: {line}"
        );
    }
    // Both helper calls — the root key's and the intermediate key's —
    // run the declared step-ca image.
    assert_eq!(
        change_pass_keys_on_declared_image(&change_pass_lines),
        vec![
            "/home/step/secrets/root_ca_key",
            "/home/step/secrets/intermediate_ca_key"
        ],
        "docker log:\n{docker_args_log}"
    );

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

/// Returns the key path each `step crypto change-pass` line re-encrypts,
/// asserting that the image each one ran, read back from the argv it
/// actually passed to docker, is the declared step-ca image.
fn change_pass_keys_on_declared_image<'a>(lines: &[&'a str]) -> Vec<&'a str> {
    lines
        .iter()
        .map(|line| {
            let args: Vec<&str> = line.split_whitespace().collect();
            let image = args
                .iter()
                .skip_while(|arg| **arg != "-v")
                .nth(2)
                .unwrap_or_else(|| panic!("no image after the `-v <mount>` pair: {line}"));
            runtime_image_declaration::assert_declared_image(
                "step-ca",
                image,
                "rotate stepca-password change-pass",
            );
            args.iter()
                .skip_while(|arg| **arg != "change-pass")
                .nth(1)
                .copied()
                .unwrap_or_else(|| panic!("no key path after change-pass: {line}"))
        })
        .collect()
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_approle_secret_id_local_updates_secret() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path =
        prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");
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
            "--registration-id",
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

    // The agent's fast-poll loop re-reads the secret_id file on every
    // AppRole re-login, so rotation must not signal the agent process.
    let pkill_args = fs::read_to_string(&pkill_log).expect("read pkill log");
    assert!(
        pkill_args.is_empty(),
        "service secret-id rotation should not signal the agent: {pkill_args}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_approle_secret_id_applies_default_wrapping_when_policy_absent() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path = prepare_app_state_no_policy(temp_dir.path(), &openbao.uri(), "local-file")
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
            "--registration-id",
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
async fn test_rotate_approle_secret_id_does_not_restart_containers() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path =
        prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");
    fs::write(&secret_path, "old-secret").expect("seed secret_id");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    write_fake_docker(&bin_dir, &docker_log).expect("write fake docker");

    stub_openbao_for_rotation(&openbao, "secret-rotated").await;

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
            "--registration-id",
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
    // The local bootroot-agent runs only as a host daemon; service
    // secret-id rotation must not touch docker at all.
    let docker_args = fs::read_to_string(&docker_log).expect("read docker log");
    assert!(
        docker_args.is_empty(),
        "service secret-id rotation should not invoke docker: {docker_args}"
    );

    let updated = fs::read_to_string(&secret_path).expect("read secret_id");
    assert_eq!(updated, "secret-rotated");
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_approle_secret_id_skips_login_when_cidr_bound() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path = prepare_app_state_with_cidrs(temp_dir.path(), &openbao.uri(), "local-file")
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
            "--registration-id",
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
            "--registration-id",
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
    let _secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
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
            "--registration-id",
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

/// A remote-bootstrap registration added with a target `--secret-id-path`
/// rotates exactly as one without: the new `secret_id` goes to KV for the
/// target's fast-poll, and nothing is written at the target path on the
/// control node.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_approle_secret_id_remote_ignores_target_secret_id_path() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let control_secret_path =
        prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
            .expect("prepare state");
    let target = temp_dir
        .path()
        .join("target-host")
        .join("edge-proxy")
        .join("secret_id");
    let state_path = temp_dir.path().join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
            .expect("parse state");
    state["services"][SERVICE_NAME]["remote_secret_id_path"] = json!(target.to_string_lossy());
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&state).expect("serialize state"),
    )
    .expect("write state");

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
            "--registration-id",
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

    let kv_path = format!("/v1/secret/data/bootroot/services/{SERVICE_NAME}/secret_id");
    let requests = openbao
        .received_requests()
        .await
        .expect("mock server records requests");
    let kv_write = requests
        .iter()
        .find(|req| req.method.as_str() == "POST" && req.url.path() == kv_path)
        .expect("the rotated secret_id must be pushed to KV");
    let body: serde_json::Value = serde_json::from_slice(&kv_write.body).expect("parse KV body");
    assert_eq!(body["data"]["secret_id"], "secret-remote");

    assert!(
        !temp_dir.path().join("target-host").exists(),
        "rotation must not write at the target path on the control node"
    );
    assert!(
        !control_secret_path.exists(),
        "remote rotation writes no control-side secret_id file, as before"
    );
    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
            .expect("parse state");
    assert_eq!(
        state["services"][SERVICE_NAME]["remote_secret_id_path"],
        target.to_string_lossy().as_ref()
    );
}

/// End-to-end self-mint contract (#672): a file-based `AppRole` run
/// rotates its target, then re-mints its own credential with the
/// documented `num_uses` cap and atomically replaces the
/// `--approle-secret-id-file` file.
#[cfg(unix)]
#[allow(clippy::too_many_lines)] // sequential mock choreography for one CLI run
#[tokio::test]
async fn test_rotate_approle_secret_id_self_mints_with_file_based_auth() {
    const RUNTIME_ROTATE_ROLE: &str = "bootroot-runtime-rotate-role";
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let secret_path =
        prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");
    fs::write(&secret_path, "old-secret").expect("seed secret_id");

    let cred_dir = temp_dir.path().join("rotate-cred");
    fs::create_dir_all(&cred_dir).expect("create cred dir");
    let cred_path = cred_dir.join("secret_id");
    fs::write(&cred_path, "old-rotate-secret\n").expect("seed rotate credential");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let pkill_log = temp_dir.path().join("pkill.log");
    write_fake_pkill(&bin_dir, &pkill_log).expect("write fake pkill");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;
    // Initial authentication with the on-disk (old) credential.
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": "rr-role-id",
            "secret_id": "old-rotate-secret"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "rotate-token" }
        })))
        .expect(1)
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/secret-id")))
        .and(header("X-Vault-Token", "rotate-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": "secret-new" }
        })))
        .expect(1)
        .mount(&openbao)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/role-id")))
        .and(header("X-Vault-Token", "rotate-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": ROLE_ID }
        })))
        .mount(&openbao)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": ROLE_ID,
            "secret_id": "secret-new"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "client-token" }
        })))
        .expect(1)
        .mount(&openbao)
        .await;
    // Mint-own-last: the self-mint must carry the documented
    // num_uses = 6 cap (3 × the enumerated logins per cycle).
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/auth/approle/role/{RUNTIME_ROTATE_ROLE}/secret-id"
        )))
        .and(header("X-Vault-Token", "rotate-token"))
        .and(body_json(json!({ "num_uses": 6 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": "self-minted-secret" }
        })))
        .expect(1)
        .mount(&openbao)
        .await;
    // Post-mint verification login of the new credential.
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": "rr-role-id",
            "secret_id": "self-minted-secret"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "verified-token" }
        })))
        .expect(1)
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
            "--auth-mode",
            "approle",
            "--approle-role-id",
            "rr-role-id",
            "--approle-secret-id-file",
            cred_path.to_string_lossy().as_ref(),
            "--yes",
            "approle-secret-id",
            "--registration-id",
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
    assert!(
        stdout.contains("re-minted own bootroot-runtime-rotate-role secret_id"),
        "summary must report the self-mint; stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("self-mint login verification OK"),
        "summary must report the verification; stdout:\n{stdout}"
    );

    let replaced = fs::read_to_string(&cred_path).expect("read rotate credential");
    assert_eq!(
        replaced, "self-minted-secret",
        "the credential file must be atomically replaced with the self-minted secret_id"
    );
    let mode = fs::metadata(&cred_path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let state = fs::read_to_string(temp_dir.path().join("state.json")).expect("read state");
    assert!(
        state.contains("last_secret_id_rotation"),
        "state.json must record the dead-man timestamp; state:\n{state}"
    );
}

/// Infra two-invocation flow (#672): `--infra stepca` self-mints and
/// replaces the credential file; the follow-up `--infra responder`
/// invocation must authenticate with the fresh credential it reads
/// from that file (the old-credential login mock is capped at one use).
#[cfg(unix)]
#[allow(clippy::too_many_lines)] // sequential mock choreography for two CLI runs
#[tokio::test]
async fn test_rotate_infra_two_invocations_use_fresh_self_minted_credential() {
    const INFRA_ROTATE_ROLE: &str = "bootroot-infra-rotate-role";
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    write_state_file(temp_dir.path(), &openbao.uri()).expect("write state");

    let cred_dir = temp_dir.path().join("rotate-cred");
    fs::create_dir_all(&cred_dir).expect("create cred dir");
    let cred_path = cred_dir.join("secret_id");
    fs::write(&cred_path, "old-infra-rotate-secret").expect("seed rotate credential");

    // Pre-write the infra agent role_id files so the role-id backfill
    // is skipped.
    for (dir, role_id) in [
        ("stepca", "stepca-role-id"),
        ("responder", "responder-role-id"),
    ] {
        let agent_dir = temp_dir.path().join("secrets").join("openbao").join(dir);
        fs::create_dir_all(&agent_dir).expect("create agent dir");
        fs::write(agent_dir.join("role_id"), role_id).expect("write role_id");
    }

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = temp_dir.path().join("docker.log");
    write_fake_docker(&bin_dir, &docker_log).expect("write fake docker");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;
    // The old credential may authenticate exactly once (invocation 1);
    // invocation 2 must use the self-minted replacement from the file.
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": "ir-role-id",
            "secret_id": "old-infra-rotate-secret"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "rotate-token" }
        })))
        .expect(1)
        .mount(&openbao)
        .await;
    for (role, minted) in [
        ("bootroot-stepca-role", "stepca-new"),
        ("bootroot-responder-role", "responder-new"),
    ] {
        Mock::given(method("POST"))
            .and(path(format!("/v1/auth/approle/role/{role}/secret-id")))
            .and(header("X-Vault-Token", "rotate-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "secret_id": minted }
            })))
            .expect(1)
            .mount(&openbao)
            .await;
    }
    for (role_id, minted) in [
        ("stepca-role-id", "stepca-new"),
        ("responder-role-id", "responder-new"),
    ] {
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .and(body_json(json!({
                "role_id": role_id,
                "secret_id": minted
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "client_token": "client-token" }
            })))
            .expect(1)
            .mount(&openbao)
            .await;
    }
    // Both invocations self-mint (per-invocation semantics): mint twice.
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/auth/approle/role/{INFRA_ROTATE_ROLE}/secret-id"
        )))
        .and(header("X-Vault-Token", "rotate-token"))
        .and(body_json(json!({ "num_uses": 6 })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": "self-minted-infra" }
        })))
        .expect(2)
        .mount(&openbao)
        .await;
    // Verification login of the self-minted credential — also consumed
    // by invocation 2's initial authentication (same body).
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": "ir-role-id",
            "secret_id": "self-minted-infra"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "rotate-token" }
        })))
        .expect(3)
        .mount(&openbao)
        .await;

    let path_env = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path_env);
    for target in ["stepca", "responder"] {
        let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(temp_dir.path())
            .args([
                "rotate",
                "--openbao-url",
                &openbao.uri(),
                "--auth-mode",
                "approle",
                "--approle-role-id",
                "ir-role-id",
                "--approle-secret-id-file",
                cred_path.to_string_lossy().as_ref(),
                "--yes",
                "approle-secret-id",
                "--infra",
                target,
            ])
            .env("PATH", &combined_path)
            .env("DOCKER_OUTPUT", &docker_log)
            .output()
            .expect("run rotate approle-secret-id --infra");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "target {target}: stdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert!(
            stdout.contains("re-minted own bootroot-infra-rotate-role secret_id"),
            "target {target}: summary must report the self-mint; stdout:\n{stdout}"
        );
    }

    let replaced = fs::read_to_string(&cred_path).expect("read rotate credential");
    assert_eq!(replaced, "self-minted-infra");
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_remote_sets_pending_status() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
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
    let _secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
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
    let _secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
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
    let secret_path =
        prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");
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
    delivery_mode: &str,
) -> anyhow::Result<PathBuf> {
    write_state_file(root, openbao_url)?;
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).context("read state")?;
    let mut state: serde_json::Value = serde_json::from_str(&contents).context("parse state")?;
    let secret_id_path = PathBuf::from("secrets/services/edge-proxy/secret_id");
    state["services"][SERVICE_NAME] = json!({
        "registration_id": SERVICE_NAME,
        "service_name": SERVICE_NAME,
        "delivery_mode": delivery_mode,
        "hostname": "edge-node-01",
        "domain": "trusted.domain",
        "agent_config_path": "agent.toml",
        "cert_path": "certs/edge-proxy.crt",
        "key_path": "certs/edge-proxy.key",
        "instance_id": "001",
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
    delivery_mode: &str,
) -> anyhow::Result<PathBuf> {
    write_state_file(root, openbao_url)?;
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).context("read state")?;
    let mut state: serde_json::Value = serde_json::from_str(&contents).context("parse state")?;
    let secret_id_path = PathBuf::from("secrets/services/edge-proxy/secret_id");
    state["services"][SERVICE_NAME] = json!({
        "registration_id": SERVICE_NAME,
        "service_name": SERVICE_NAME,
        "delivery_mode": delivery_mode,
        "hostname": "edge-node-01",
        "domain": "trusted.domain",
        "agent_config_path": "agent.toml",
        "cert_path": "certs/edge-proxy.crt",
        "key_path": "certs/edge-proxy.key",
        "instance_id": "001",
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
    delivery_mode: &str,
) -> anyhow::Result<PathBuf> {
    write_state_file(root, openbao_url)?;
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).context("read state")?;
    let mut state: serde_json::Value = serde_json::from_str(&contents).context("parse state")?;
    let secret_id_path = PathBuf::from("secrets/services/edge-proxy/secret_id");
    state["services"][SERVICE_NAME] = json!({
        "registration_id": SERVICE_NAME,
        "service_name": SERVICE_NAME,
        "delivery_mode": delivery_mode,
        "hostname": "edge-node-01",
        "domain": "trusted.domain",
        "agent_config_path": "agent.toml",
        "cert_path": "certs/edge-proxy.crt",
        "key_path": "certs/edge-proxy.key",
        "instance_id": "001",
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

# Simulate OpenBao Agent rendering on restart of the infra OBA
# containers (the only OBA containers left after the local sidecar
# retirement).
if [ "${1:-}" = "restart" ]; then
  case "${2:-}" in
    bootroot-openbao-agent-stepca|bootroot-openbao-agent-responder)
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
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");

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
    let _secret_path =
        prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");

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
            "--registration-id",
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

    // Issue #614: rotate force-reissue must surface the
    // consumer-reload hint so operators with no hook configured see
    // that the consumer process still serves the previous cert via an
    // open file descriptor until restarted.
    assert!(
        stdout.contains("Consumer reload/restart required"),
        "rotate force-reissue should print the consumer-reload hint: {stdout}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_force_reissue_remote_writes_reissue_kv() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // Remote-bootstrap force-reissue publishes the request to OpenBao KV.
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/reissue"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "version": 3 }
        })))
        .mount(&openbao)
        .await;

    // The CLI also reads back to obtain the version for --wait bookkeeping.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/reissue"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": { "requested_at": "2026-04-19T12:34:56Z", "requester": "ci" },
                "metadata": { "version": 3 }
            }
        })))
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
            "--registration-id",
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
    assert!(
        stdout.contains("reissue requested at"),
        "expected reissue-requested summary line in stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("will apply"),
        "expected will-apply hint in stdout:\n{stdout}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_force_reissue_remote_wait_reports_completion() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    // The POST that publishes the request gets version 3 assigned; the
    // CLI must pin on that, NOT on a later GET. We then model the real
    // sequence where the agent's completion write advances the secret
    // metadata version to 4 while the payload carries
    // `completed_version = 3` (the request it applied).
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/reissue"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "version": 3 }
        })))
        .mount(&openbao)
        .await;

    // Stub the GET so metadata.version has already advanced past the
    // request version (agent wrote completion). The CLI must still
    // resolve `--wait` because `completed_version (3) >= request (3)`.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/reissue"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": {
                    "requested_at": "2026-04-19T12:34:56Z",
                    "requester": "ci",
                    "completed_at": "2026-04-19T12:35:10Z",
                    "completed_version": 3
                },
                "metadata": { "version": 4 }
            }
        })))
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
            "--registration-id",
            SERVICE_NAME,
            "--wait",
            "--wait-timeout",
            "10s",
        ])
        .output()
        .expect("run rotate force-reissue --wait");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("reported completion at 2026-04-19T12:35:10Z"),
        "expected completion line in stdout:\n{stdout}"
    );
    // 12:34:56 -> 12:35:10 = 14s; the end-to-end latency must surface
    // on the same line so the operator does not have to subtract
    // timestamps manually (issue #548).
    assert!(
        stdout.contains("end-to-end latency: 14s"),
        "expected end-to-end latency in stdout:\n{stdout}"
    );
}

/// Issue #629: when `--wait` runs out without the agent reporting a
/// completed reissue, the CLI must exit with code 124 (GNU
/// `timeout(1)` convention) so scripted callers can distinguish a
/// finished rotation from one that was merely queued.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_force_reissue_remote_wait_times_out_with_exit_124() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    let _secret_path = prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/reissue"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "version": 3 }
        })))
        .mount(&openbao)
        .await;

    // GET returns the request payload but NEVER advertises a
    // `completed_version`, so the wait polls until `--wait-timeout`
    // elapses without ever observing completion.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/reissue"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": { "requested_at": "2026-04-19T12:34:56Z", "requester": "ci" },
                "metadata": { "version": 3 }
            }
        })))
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
            "--registration-id",
            SERVICE_NAME,
            "--wait",
            "--wait-timeout",
            "1s",
        ])
        .output()
        .expect("run rotate force-reissue --wait");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(124),
        "expected GNU timeout(1) exit code 124 on --wait timeout;\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("--wait timed out"),
        "expected timeout message in stdout:\n{stdout}"
    );
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
            "--registration-id",
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
    // Accept connections in a loop. `provision_db_sync` may open a
    // second connection to the target DB to grant `CREATE, USAGE` on
    // the public schema (see #588 §1), and rotation flows that touch
    // both `postgres` (admin) and the target DB need the listener to
    // outlive the first session.
    let handle = std::thread::spawn(move || {
        while let Ok((stream, _)) = listener.accept() {
            std::thread::spawn(move || mock_pg_session(stream));
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
    prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");

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

/// Common name every `rotate ca-key` gives the intermediate it generates.
const ROTATED_INTERMEDIATE_CN: &str = "Bootroot Intermediate CA";

/// Arranges a second rotation: the service's leaf was signed by a previous
/// generation's intermediate, and the intermediate this rotation generates
/// carries the same subject DN under a fresh key. Writes the service's
/// cert and key and returns the staged new intermediate for the fake
/// docker to install.
fn stage_same_name_intermediate_rotation(root: &Path) -> PathBuf {
    use rcgen::{CertificateParams, DnType, Issuer, KeyPair};

    let ca_params = || {
        let mut params = CertificateParams::new(vec![ROTATED_INTERMEDIATE_CN.to_string()])
            .expect("intermediate params");
        params
            .distinguished_name
            .push(DnType::CommonName, ROTATED_INTERMEDIATE_CN);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
    };
    let old_issuer = Issuer::new(ca_params(), KeyPair::generate().expect("old key"));
    let new_key = KeyPair::generate().expect("new key");
    let new_inter = ca_params()
        .self_signed(&new_key)
        .expect("self-signed new intermediate");

    let leaf_key = KeyPair::generate().expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["edge-proxy.trusted.domain".to_string()]).expect("leaf");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "edge-proxy.trusted.domain");
    let leaf = leaf_params
        .signed_by(&leaf_key, &old_issuer)
        .expect("sign leaf with old intermediate");

    let certs_dir = root.join("certs");
    fs::create_dir_all(&certs_dir).expect("create certs dir");
    fs::write(certs_dir.join("edge-proxy.crt"), leaf.pem()).expect("write service cert");
    fs::write(certs_dir.join("edge-proxy.key"), leaf_key.serialize_pem())
        .expect("write service key");

    let staged = root.join("new_intermediate_staged.crt");
    fs::write(&staged, new_inter.pem()).expect("write staged intermediate");
    staged
}

/// Runs `rotate ca-key` over the arrangement from
/// [`stage_same_name_intermediate_rotation`] with the given extra
/// `ca-key` arguments, returning its output and the fake `pkill` log.
async fn run_same_name_intermediate_rotation(
    root: &Path,
    extra_args: &[&str],
) -> (std::process::Output, PathBuf) {
    let openbao = MockServer::start().await;

    support::create_secrets_dir(root).expect("create secrets dir");
    support::write_password_file(&root.join("secrets"), "test-password").expect("write password");
    prepare_app_state(root, &openbao.uri(), "local-file").expect("prepare state");
    fs::write(
        root.join("docker-compose.yml"),
        "version: '3'\nservices:\n  step-ca:\n    image: test\n",
    )
    .expect("write compose file");

    let staged = stage_same_name_intermediate_rotation(root);
    let inter_cert_path = root
        .join("secrets")
        .join("certs")
        .join("intermediate_ca.crt");

    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = root.join("docker.log");
    write_full_rotation_fake_docker(&bin_dir, &docker_log, &staged);
    let pkill_log = root.join("pkill.log");
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

    let mut args = vec![
        "rotate",
        "--openbao-url",
        &openbao.uri(),
        "--root-token",
        support::ROOT_TOKEN,
        "--yes",
        "ca-key",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<Vec<_>>();
    args.extend(extra_args.iter().map(|arg| (*arg).to_string()));

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args(&args)
        .env("PATH", &combined_path)
        .env("DOCKER_OUTPUT", &docker_log)
        .env("PKILL_OUTPUT", &pkill_log)
        .env("ROTATION_NEW_CERT_TARGET", &inter_cert_path)
        .output()
        .expect("run rotate ca-key");
    (output, pkill_log)
}

/// From a deployment's second rotation on, the new intermediate carries
/// the old one's subject DN. Phase 6 must still see a leaf the old key
/// signed as unmigrated and refuse to narrow trust without `--force`.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_finalize_blocks_same_name_intermediate_leaf() {
    let temp_dir = tempdir().expect("create temp dir");

    let (output, _pkill_log) =
        run_same_name_intermediate_rotation(temp_dir.path(), &["--skip", "reissue"]).await;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "finalization must be blocked; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Cannot finalize") && stderr.contains(SERVICE_NAME),
        "Phase 6 must name the unmigrated service: {stderr}"
    );
    assert!(
        temp_dir
            .path()
            .join("certs")
            .join("edge-proxy.crt")
            .exists(),
        "Phase 5 was skipped, so the old leaf must still be in place"
    );
}

/// Phase 5 over the same arrangement re-issues the service instead of
/// reporting it as already migrated. Finalization is skipped because the
/// fake `pkill` issues no replacement leaf for Phase 6 to find.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_reissues_same_name_intermediate_leaf() {
    let temp_dir = tempdir().expect("create temp dir");

    let (output, pkill_log) =
        run_same_name_intermediate_rotation(temp_dir.path(), &["--skip", "finalize"]).await;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rotation with finalize skipped should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("already issued by new intermediate"),
        "the service must not be reported as already migrated: {stdout}"
    );
    assert!(
        !temp_dir
            .path()
            .join("certs")
            .join("edge-proxy.crt")
            .exists(),
        "Phase 5 must remove the service cert"
    );
    assert!(
        !temp_dir
            .path()
            .join("certs")
            .join("edge-proxy.key")
            .exists(),
        "Phase 5 must remove the service key"
    );
    let pkill = fs::read_to_string(&pkill_log).expect("read pkill log");
    assert!(
        pkill.contains("-HUP") && pkill.contains("agent.toml"),
        "Phase 5 must signal the service's agent: {pkill}"
    );
}

#[tokio::test]
async fn test_rotate_trust_sync_blocked_by_rotation_state() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");

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
    prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");

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
    // Issue #619: phase 5 must only build the consumer-reload hint
    // from services it actually wiped/signaled. Here the only
    // registered service is already issued by the new intermediate
    // (skip-migrated branch), so the hint must NOT appear — listing it
    // would push operators to restart a consumer this rotation did not
    // touch. The skip-migrated line should still appear to confirm
    // phase 5 saw the service.
    assert!(
        stdout.contains("already issued by new intermediate"),
        "phase 5 should report the service as already migrated: {stdout}"
    );
    assert!(
        !stdout.contains("Consumer reload/restart required"),
        "rotate ca-key must not print the consumer-reload hint when no service was reissued: {stdout}"
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
    prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");

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
    prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");

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

    // Use a fake docker that succeeds on the pre-Phase-1 ownership sweep
    // (`chown`) but fails on root cert generation so Phase 2 fails while
    // Phase 1 (backup) completes, creating rotation-state.json.
    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let fake_docker = r#"#!/bin/sh
set -eu
case "$*" in
  *"step certificate create"*) exit 1 ;;
esac
exit 0
"#;
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

    // Any real resumed rotation carries the Phase-1 backups until the
    // Phase-7 cleanup; Phase 3 reads them to build the transitional
    // bundle covering both CA generations.
    let certs_dir = temp_dir.path().join("secrets").join("certs");
    fs::copy(
        certs_dir.join("root_ca.crt"),
        certs_dir.join("root_ca.crt.bak"),
    )
    .expect("back up root cert");
    fs::copy(
        certs_dir.join("intermediate_ca.crt"),
        certs_dir.join("intermediate_ca.crt.bak"),
    )
    .expect("back up intermediate cert");

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
    prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");

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
    prepare_app_state(temp_dir.path(), &openbao.uri(), "local-file").expect("prepare state");

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

/// Requester the remote-reissue tests put in the child's `USER`, which
/// `rotate ca-key` Phase 5 falls back to for the request's `requester`.
const REISSUE_REQUESTER: &str = "rotation-operator";

/// Registers each of `names` in `state.json` as a `remote-bootstrap`
/// service whose leaf lives at `certs/<name>.crt`.
fn prepare_remote_services_state(
    root: &Path,
    openbao_url: &str,
    names: &[&str],
) -> anyhow::Result<()> {
    write_state_file(root, openbao_url)?;
    add_remote_services(root, names)?;
    fs::write(root.join("agent.toml"), "# agent").context("write agent config")?;
    Ok(())
}

/// Appends each of `names` to an existing `state.json` as a
/// `remote-bootstrap` service whose leaf lives at `certs/<name>.crt`.
fn add_remote_services(root: &Path, names: &[&str]) -> anyhow::Result<()> {
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).context("read state")?;
    let mut state: serde_json::Value = serde_json::from_str(&contents).context("parse state")?;
    for name in names {
        state["services"][*name] = json!({
            "registration_id": name,
            "service_name": name,
            "delivery_mode": "remote-bootstrap",
            "hostname": "edge-node-01",
            "domain": "trusted.domain",
            "agent_config_path": "agent.toml",
            "cert_path": format!("certs/{name}.crt"),
            "key_path": format!("certs/{name}.key"),
            "instance_id": "001",
            "approle": {
                "role_name": format!("bootroot-service-{name}"),
                "role_id": format!("role-{name}"),
                "secret_id_path": format!("secrets/services/{name}/secret_id"),
                "policy_name": format!("bootroot-service-{name}"),
                "secret_id_wrap_ttl": "0"
            }
        });
    }
    fs::write(&state_path, serde_json::to_string_pretty(&state)?).context("write state")?;
    Ok(())
}

/// Writes `rotation-state.json` for an intermediate-only rotation that
/// has completed `phase`, so the next `rotate ca-key` resumes after it.
fn write_rotation_state_at_phase(root: &Path, phase: u8) {
    fs::write(
        root.join("rotation-state.json"),
        serde_json::to_string_pretty(&json!({
            "mode": "intermediate-only",
            "started_at": "2026-03-01T10:00:00Z",
            "old_root_fp": "aaa",
            "new_root_fp": "aaa",
            "old_intermediate_fp": "bbb",
            "new_intermediate_fp": "ccc",
            "phase": phase
        }))
        .expect("serialize rotation-state.json"),
    )
    .expect("write rotation-state.json");
}

fn recorded_rotation_phase(root: &Path) -> serde_json::Value {
    let contents =
        fs::read_to_string(root.join("rotation-state.json")).expect("read rotation-state.json");
    let state: serde_json::Value =
        serde_json::from_str(&contents).expect("parse rotation-state.json");
    state["phase"].clone()
}

/// Stages what a `rotate ca-key` run needs outside `OpenBao` — a compose
/// file, a new intermediate for Phase 2 to install, and fake `docker` and
/// `pkill` — and returns the environment the child runs with.
fn stage_ca_key_rotation(root: &Path) -> Vec<(&'static str, std::ffi::OsString)> {
    fs::write(
        root.join("docker-compose.yml"),
        "version: '3'\nservices:\n  step-ca:\n    image: test\n",
    )
    .expect("write compose file");

    let new_cert_staging = root.join("new_intermediate_staged.crt");
    fs::write(
        &new_cert_staging,
        generate_test_cert_pem("new-intermediate.example"),
    )
    .expect("write staged cert");

    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = root.join("docker.log");
    write_full_rotation_fake_docker(&bin_dir, &docker_log, &new_cert_staging);
    let pkill_log = root.join("pkill.log");
    write_fake_pkill(&bin_dir, &pkill_log).expect("write fake pkill");

    let path_var = env::var("PATH").unwrap_or_default();
    vec![
        ("PATH", format!("{}:{path_var}", bin_dir.display()).into()),
        ("DOCKER_OUTPUT", docker_log.into()),
        ("PKILL_OUTPUT", pkill_log.into()),
        (
            "ROTATION_NEW_CERT_TARGET",
            root.join("secrets")
                .join("certs")
                .join("intermediate_ca.crt")
                .into(),
        ),
        ("USER", REISSUE_REQUESTER.into()),
    ]
}

fn run_rotate_ca_key(
    root: &Path,
    openbao_url: &str,
    envs: &[(&'static str, std::ffi::OsString)],
    extra_args: &[&str],
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args([
            "rotate",
            "--openbao-url",
            openbao_url,
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            "ca-key",
        ])
        .args(extra_args)
        .envs(envs.iter().map(|(key, value)| (*key, value)))
        .output()
        .expect("run rotate ca-key")
}

fn reissue_kv_path(registration_id: &str) -> String {
    format!("/v1/secret/data/bootroot/services/{registration_id}/reissue")
}

/// Stubs the health check and the Phase 3 / Phase 6 trust writes, global
/// and per service.
async fn stub_openbao_for_ca_key_rotation(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path_regex(
            r"^/v1/secret/data/bootroot/services/[^/]+/trust$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
}

/// Answers the KV v2 write of `registration_id`'s reissue request with
/// `status`, carrying a version on success.
async fn stub_reissue_write(server: &MockServer, registration_id: &str, status: u16) {
    let response = if status == 200 {
        ResponseTemplate::new(200).set_body_json(json!({ "data": { "version": 7 } }))
    } else {
        ResponseTemplate::new(status).set_body_json(json!({ "errors": ["internal error"] }))
    };
    Mock::given(method("POST"))
        .and(path(reissue_kv_path(registration_id)))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(response)
        .mount(server)
        .await;
}

/// Returns the payloads of every reissue request written for
/// `registration_id`, in the order they arrived.
async fn reissue_requests(server: &MockServer, registration_id: &str) -> Vec<serde_json::Value> {
    let reissue_path = reissue_kv_path(registration_id);
    server
        .received_requests()
        .await
        .expect("mock server records requests")
        .iter()
        .filter(|req| req.method.as_str() == "POST" && req.url.path() == reissue_path)
        .map(|req| {
            let body: serde_json::Value =
                serde_json::from_slice(&req.body).expect("parse reissue write body");
            body["data"].clone()
        })
        .collect()
}

fn assert_reissue_payload(payload: &serde_json::Value) {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    let requested_at = payload["requested_at"]
        .as_str()
        .unwrap_or_else(|| panic!("requested_at missing from {payload}"));
    OffsetDateTime::parse(requested_at, &Rfc3339)
        .unwrap_or_else(|err| panic!("requested_at {requested_at} is not RFC 3339: {err}"));
    assert_eq!(
        payload["requester"], REISSUE_REQUESTER,
        "payload: {payload}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_publishes_reissue_request_for_remote_service() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());

    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_reissue_write(&openbao, SERVICE_NAME, 200).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rotation should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = reissue_requests(&openbao, SERVICE_NAME).await;
    assert_eq!(
        requests.len(),
        1,
        "one reissue request expected: {requests:?}"
    );
    assert_reissue_payload(&requests[0]);
    assert!(
        stdout.contains(&format!("{SERVICE_NAME}: reissue requested at")),
        "phase 5 should report the published request: {stdout}"
    );
    assert!(
        !stdout.contains("bootroot-remote bootstrap"),
        "phase 5 must not tell the operator to re-run bootstrap: {stdout}"
    );
    assert!(
        !stdout.contains("Consumer reload/restart required"),
        "remote services stay out of the consumer-reload hint: {stdout}"
    );
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be deleted after completion"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_skip_reissue_publishes_no_remote_request() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());

    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_reissue_write(&openbao, SERVICE_NAME, 200).await;

    let output = run_rotate_ca_key(
        temp_dir.path(),
        &openbao.uri(),
        &envs,
        &["--skip", "reissue"],
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rotation should succeed with --skip reissue; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = reissue_requests(&openbao, SERVICE_NAME).await;
    assert!(
        requests.is_empty(),
        "--skip reissue must publish no reissue request: {requests:?}"
    );
    assert!(
        !stdout.contains("reissue requested at"),
        "--skip reissue must not report a request: {stdout}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_reissue_publish_failure_resumes_at_phase_5() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());

    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_reissue_write(&openbao, SERVICE_NAME, 500).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a failed reissue publish must fail the rotation; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains(SERVICE_NAME),
        "the error should name the service whose request failed: {stderr}"
    );
    assert_eq!(recorded_rotation_phase(temp_dir.path()), 4);
    assert_eq!(reissue_requests(&openbao, SERVICE_NAME).await.len(), 1);

    openbao.reset().await;
    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_reissue_write(&openbao, SERVICE_NAME, 200).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the re-run should complete; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Resuming CA key rotation from phase 4"),
        "the re-run should resume after phase 4: {stdout}"
    );
    let requests = reissue_requests(&openbao, SERVICE_NAME).await;
    assert_eq!(requests.len(), 1, "the re-run should publish: {requests:?}");
    assert_reissue_payload(&requests[0]);
    assert!(
        stdout.contains(&format!("{SERVICE_NAME}: reissue requested at")),
        "the re-run should report the published request: {stdout}"
    );
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be deleted after completion"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_skips_reissue_request_for_migrated_remote_service() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_remote_services_state(
        temp_dir.path(),
        &openbao.uri(),
        &["svc-migrated", "svc-pending"],
    )
    .expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());
    write_rotation_state_at_phase(temp_dir.path(), 4);

    // The intermediate on disk is self-signed, so a copy of it has the
    // intermediate's subject as its issuer: a leaf "issued by" it.
    let certs_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&certs_dir).expect("create certs dir");
    fs::copy(
        temp_dir
            .path()
            .join("secrets")
            .join("certs")
            .join("intermediate_ca.crt"),
        certs_dir.join("svc-migrated.crt"),
    )
    .expect("write migrated leaf");

    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_reissue_write(&openbao, "svc-migrated", 200).await;
    stub_reissue_write(&openbao, "svc-pending", 200).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rotation should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        reissue_requests(&openbao, "svc-migrated").await.is_empty(),
        "an already-migrated remote service must get no request"
    );
    let pending = reissue_requests(&openbao, "svc-pending").await;
    assert_eq!(pending.len(), 1, "one request for svc-pending: {pending:?}");
    assert_reissue_payload(&pending[0]);
    assert!(
        stdout.contains("svc-migrated: already issued by new intermediate, skipping"),
        "phase 5 should report svc-migrated as migrated: {stdout}"
    );
    assert!(
        stdout.contains("svc-pending: reissue requested at"),
        "phase 5 should report the request for svc-pending: {stdout}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_partial_reissue_failure_republishes_on_resume() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_remote_services_state(temp_dir.path(), &openbao.uri(), &["svc-a", "svc-b"])
        .expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());
    write_rotation_state_at_phase(temp_dir.path(), 4);

    // Services are visited in registration-id order, so svc-a's request
    // lands before svc-b's fails.
    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_reissue_write(&openbao, "svc-a", 200).await;
    stub_reissue_write(&openbao, "svc-b", 500).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a failed reissue publish must fail the rotation; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("svc-b"),
        "the error should name the service whose request failed: {stderr}"
    );
    assert_eq!(recorded_rotation_phase(temp_dir.path()), 4);
    let first_a = reissue_requests(&openbao, "svc-a").await;
    let first_b = reissue_requests(&openbao, "svc-b").await;
    assert_eq!(first_a.len(), 1, "svc-a: {first_a:?}");
    assert_eq!(first_b.len(), 1, "svc-b: {first_b:?}");

    // A reset drops the recorded requests with the 500 stub, so the
    // first run's counts are carried in `first_a` / `first_b`.
    openbao.reset().await;
    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_reissue_write(&openbao, "svc-a", 200).await;
    stub_reissue_write(&openbao, "svc-b", 200).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the re-run should complete; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Resuming CA key rotation from phase 4"),
        "the re-run should resume after phase 4: {stdout}"
    );
    let second_a = reissue_requests(&openbao, "svc-a").await;
    let second_b = reissue_requests(&openbao, "svc-b").await;
    assert_eq!(second_a.len(), 1, "svc-a republished: {second_a:?}");
    assert_eq!(second_b.len(), 1, "svc-b published: {second_b:?}");
    assert_eq!(
        first_a.len() + second_a.len(),
        2,
        "svc-a receives the accepted duplicate across the two runs"
    );
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be deleted after completion"
    );
}

// ---------------------------------------------------------------------------
// Fan-out to registrar-managed identities.
//
// A registrar-minted identity is never in `state.json`; the rotations find
// it by listing `bootroot/services/` for subtrees that carry a
// `registrar_binding`. The stubs below list the `state.json` service, one
// bound registrar identity and one unbound stray subtree, plus a leaf key
// that is not a subtree at all.
// ---------------------------------------------------------------------------

/// A registration id minted through the registrar: bound, not in `state.json`.
const REGISTRAR_ID: &str = "h1-roxyd-001";
/// A subtree under `bootroot/services/` with no binding and no state entry.
const STRAY_ID: &str = "stray";
const SERVICES_LIST_PATH: &str = "/v1/secret/metadata/bootroot/services/";
const SERVICES_METADATA_PREFIX: &str = "/v1/secret/metadata/bootroot/services";
const REGISTRAR_LIST_ERROR: &str =
    "Failed to enumerate registrar-managed identities under secret/metadata/bootroot/services/";

/// Records a `registrar_endpoint` entry in `state.json`, which is what
/// gates the listing.
fn add_registrar_endpoint(root: &Path) -> anyhow::Result<()> {
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).context("read state")?;
    let mut state: serde_json::Value = serde_json::from_str(&contents).context("parse state")?;
    state["registrar_endpoint"] = json!({
        "enabled": true,
        "domain": "trusted.domain",
        "host": "h1"
    });
    fs::write(&state_path, serde_json::to_string_pretty(&state)?).context("write state")?;
    Ok(())
}

fn prepare_app_state_with_registrar(
    root: &Path,
    openbao_url: &str,
    delivery_mode: &str,
) -> anyhow::Result<PathBuf> {
    let secret_path = prepare_app_state(root, openbao_url, delivery_mode)?;
    add_registrar_endpoint(root)?;
    Ok(secret_path)
}

fn binding_kv_path(registration_id: &str) -> String {
    format!("/v1/secret/data/bootroot/services/{registration_id}/registrar_binding")
}

fn service_record_path(registration_id: &str, suffix: &str) -> String {
    format!("/v1/secret/data/bootroot/services/{registration_id}/{suffix}")
}

fn services_listing_response() -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "data": {
            "keys": [
                format!("{SERVICE_NAME}/"),
                format!("{REGISTRAR_ID}/"),
                format!("{STRAY_ID}/"),
                "leaf"
            ]
        }
    }))
}

fn forbidden() -> ResponseTemplate {
    ResponseTemplate::new(403).set_body_json(json!({ "errors": ["permission denied"] }))
}

/// Answers the services listing with `listing`, and the binding reads the
/// way a real deployment would: bound for [`REGISTRAR_ID`], absent for the
/// `state.json` service and the stray subtree.
async fn stub_registrar_bindings(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path(binding_kv_path(REGISTRAR_ID)))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": { "schema_version": 1, "state": "active" },
                "metadata": { "version": 1 }
            }
        })))
        .mount(server)
        .await;
    for unbound in [SERVICE_NAME, STRAY_ID] {
        Mock::given(method("GET"))
            .and(path(binding_kv_path(unbound)))
            .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
            .mount(server)
            .await;
    }
}

async fn stub_services_listing(server: &MockServer, token: &str, listing: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(SERVICES_LIST_PATH))
        .and(wiremock::matchers::query_param("list", "true"))
        .and(header("X-Vault-Token", token))
        .respond_with(listing)
        .mount(server)
        .await;
}

/// Accepts every per-service `trust`, `http_responder_hmac` and `eab`
/// write, so a test asserts on what was sent rather than on a 404.
async fn stub_service_record_writes(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path_regex(
            r"^/v1/secret/data/bootroot/services/[^/]+/(trust|http_responder_hmac|eab)$",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
}

async fn received(server: &MockServer) -> Vec<wiremock::Request> {
    server
        .received_requests()
        .await
        .expect("mock server records requests")
}

/// Returns the `data` payloads written to `request_path`, in arrival order.
fn posted_payloads(requests: &[wiremock::Request], request_path: &str) -> Vec<serde_json::Value> {
    requests
        .iter()
        .filter(|req| req.method.as_str() == "POST" && req.url.path() == request_path)
        .map(|req| {
            let body: serde_json::Value =
                serde_json::from_slice(&req.body).expect("parse write body");
            body["data"].clone()
        })
        .collect()
}

fn position_of(
    requests: &[wiremock::Request],
    http_method: &str,
    request_path: &str,
) -> Option<usize> {
    requests
        .iter()
        .position(|req| req.method.as_str() == http_method && req.url.path() == request_path)
}

fn listing_positions(requests: &[wiremock::Request]) -> Vec<usize> {
    requests
        .iter()
        .enumerate()
        .filter(|(_, req)| req.method.as_str() == "GET" && req.url.path() == SERVICES_LIST_PATH)
        .map(|(idx, _)| idx)
        .collect()
}

fn assert_no_secret_writes(requests: &[wiremock::Request]) {
    let writes: Vec<String> = requests
        .iter()
        .filter(|req| req.method.as_str() == "POST" && req.url.path().starts_with("/v1/secret/"))
        .map(|req| req.url.path().to_string())
        .collect();
    assert!(
        writes.is_empty(),
        "no OpenBao write expected, got {writes:?}"
    );
}

fn assert_no_registrar_enumeration(requests: &[wiremock::Request]) {
    let listed: Vec<String> = requests
        .iter()
        .map(|req| req.url.path().to_string())
        .filter(|p| p.starts_with(SERVICES_METADATA_PREFIX) || p.ends_with("/registrar_binding"))
        .collect();
    assert!(
        listed.is_empty(),
        "without a registrar_endpoint entry nothing may be listed or probed: {listed:?}"
    );
}

/// Stages the compose file, fake `docker` and responder render source a
/// `rotate responder-hmac` run needs, then runs it with `auth_args`.
fn run_responder_hmac(
    root: &Path,
    openbao_url: &str,
    auth_args: &[&str],
    hmac: &str,
) -> std::process::Output {
    run_responder_hmac_with_env(root, openbao_url, auth_args, hmac, &[])
}

/// [`run_responder_hmac`] with extra environment for the fakes staged
/// in `root/bin` — `PKILL_OUTPUT` for [`write_fake_pkill`].
fn run_responder_hmac_with_env(
    root: &Path,
    openbao_url: &str,
    auth_args: &[&str],
    hmac: &str,
    extra_env: &[(&str, &Path)],
) -> std::process::Output {
    let compose_file = root.join("docker-compose.yml");
    fs::write(&compose_file, "services: {}\n").expect("write compose");

    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let docker_log = root.join("docker.log");
    write_fake_docker(&bin_dir, &docker_log).expect("write fake docker");

    let responder_dir = root.join("secrets").join("responder");
    fs::create_dir_all(&responder_dir).expect("create responder dir");
    let render_source = root.join("responder-render-src.toml");
    fs::write(&render_source, format!("hmac_secret = \"{hmac}\"\n")).expect("write render source");

    let path_var = env::var("PATH").unwrap_or_default();
    Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args(["rotate", "--openbao-url", openbao_url])
        .args(auth_args)
        .args([
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--yes",
            "responder-hmac",
            "--hmac",
            hmac,
        ])
        .env("PATH", format!("{}:{path_var}", bin_dir.display()))
        .env("DOCKER_OUTPUT", &docker_log)
        .env("RENDER_SOURCE", &render_source)
        .env("RENDER_TARGET", responder_dir.join("responder.toml"))
        .envs(extra_env.iter().copied())
        .output()
        .expect("run rotate responder-hmac")
}

fn run_rotate_root(root: &Path, openbao_url: &str, subcommand: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args([
            "rotate",
            "--openbao-url",
            openbao_url,
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            subcommand,
        ])
        .output()
        .expect("run rotate")
}

async fn assert_responder_hmac_fans_out(auth_args: &[&str], token: &str) {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    stub_openbao_for_runtime_approle_login(
        &openbao,
        "runtime-role-id",
        "runtime-secret-id",
        "runtime-client",
    )
    .await;
    stub_openbao_for_responder_hmac_rotation_with_token(&openbao, "hmac-fanout", token).await;
    stub_services_listing(&openbao, token, services_listing_response()).await;
    stub_registrar_bindings(&openbao, token).await;
    stub_service_record_writes(&openbao).await;

    let output = run_responder_hmac(temp_dir.path(), &openbao.uri(), auth_args, "hmac-fanout");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let requests = received(&openbao).await;
    let expected = json!({ "hmac": "hmac-fanout" });
    for id in [SERVICE_NAME, REGISTRAR_ID] {
        let payloads = posted_payloads(&requests, &service_record_path(id, "http_responder_hmac"));
        assert_eq!(
            payloads,
            vec![expected.clone()],
            "{id} is written exactly once"
        );
    }
    assert!(
        posted_payloads(
            &requests,
            &service_record_path(STRAY_ID, "http_responder_hmac")
        )
        .is_empty(),
        "an unbound subtree must not be written"
    );
    assert!(
        requests.iter().all(|req| !req.url.path().contains("/leaf")),
        "a leaf key is not a registration subtree"
    );

    let listing = listing_positions(&requests);
    assert_eq!(listing.len(), 1, "one listing per fan-out step");
    let control_write = position_of(&requests, "POST", "/v1/secret/data/bootroot/responder/hmac")
        .expect("control-node HMAC written");
    assert!(
        listing[0] < control_write,
        "the listing must precede the control-node write"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_fans_out_to_registrar_identities() {
    assert_responder_hmac_fans_out(&["--root-token", support::ROOT_TOKEN], support::ROOT_TOKEN)
        .await;
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_fans_out_to_registrar_identities_with_approle() {
    assert_responder_hmac_fans_out(
        &[
            "--auth-mode",
            "approle",
            "--approle-role-id",
            "runtime-role-id",
            "--approle-secret-id",
            "runtime-secret-id",
        ],
        "runtime-client",
    )
    .await;
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_listing_forbidden_writes_nothing() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-denied").await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, forbidden()).await;
    stub_registrar_bindings(&openbao, support::ROOT_TOKEN).await;
    stub_service_record_writes(&openbao).await;

    let output = run_responder_hmac(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-denied",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains(REGISTRAR_LIST_ERROR), "stderr:\n{stderr}");
    assert!(
        stderr.contains("list") && stderr.contains("root token"),
        "the error names the missing grant and the root-token re-run: {stderr}"
    );
    assert_no_secret_writes(&received(&openbao).await);
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_without_registrar_entry_does_not_list() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");

    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-plain").await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;
    stub_registrar_bindings(&openbao, support::ROOT_TOKEN).await;
    stub_service_record_writes(&openbao).await;

    let output = run_responder_hmac(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-plain",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = received(&openbao).await;
    assert_no_registrar_enumeration(&requests);
    assert_eq!(
        posted_payloads(
            &requests,
            &service_record_path(SERVICE_NAME, "http_responder_hmac")
        )
        .len(),
        1
    );
    assert!(
        posted_payloads(
            &requests,
            &service_record_path(REGISTRAR_ID, "http_responder_hmac")
        )
        .is_empty()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_empty_listing_writes_state_services_only() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-empty").await;
    stub_services_listing(
        &openbao,
        support::ROOT_TOKEN,
        ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })),
    )
    .await;
    stub_service_record_writes(&openbao).await;

    let output = run_responder_hmac(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-empty",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = received(&openbao).await;
    let service_writes: Vec<String> = requests
        .iter()
        .filter(|req| {
            req.method.as_str() == "POST"
                && req
                    .url
                    .path()
                    .starts_with("/v1/secret/data/bootroot/services/")
        })
        .map(|req| req.url.path().to_string())
        .collect();
    assert_eq!(
        service_writes,
        vec![service_record_path(SERVICE_NAME, "http_responder_hmac")]
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_writes_bound_state_service_once() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-both").await;
    stub_services_listing(
        &openbao,
        support::ROOT_TOKEN,
        ResponseTemplate::new(200).set_body_json(json!({
            "data": { "keys": [format!("{SERVICE_NAME}/"), format!("{REGISTRAR_ID}/")] }
        })),
    )
    .await;
    // Both ids carry a binding: the `state.json` service is also bound.
    Mock::given(method("GET"))
        .and(path_regex(r"/registrar_binding$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": { "schema_version": 1, "state": "active" },
                "metadata": { "version": 1 }
            }
        })))
        .mount(&openbao)
        .await;
    stub_service_record_writes(&openbao).await;

    let output = run_responder_hmac(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-both",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = received(&openbao).await;
    let service_writes: Vec<String> = requests
        .iter()
        .filter(|req| {
            req.method.as_str() == "POST"
                && req
                    .url
                    .path()
                    .starts_with("/v1/secret/data/bootroot/services/")
        })
        .map(|req| req.url.path().to_string())
        .collect();
    assert_eq!(
        service_writes,
        vec![
            service_record_path(SERVICE_NAME, "http_responder_hmac"),
            service_record_path(REGISTRAR_ID, "http_responder_hmac"),
        ],
        "an id both in state.json and bound is written once, in its state.json position"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_listing_server_error_writes_nothing() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-list-500").await;
    stub_services_listing(
        &openbao,
        support::ROOT_TOKEN,
        ResponseTemplate::new(500).set_body_json(json!({ "errors": ["boom"] })),
    )
    .await;
    stub_service_record_writes(&openbao).await;

    let output = run_responder_hmac(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-list-500",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains(REGISTRAR_LIST_ERROR), "stderr:\n{stderr}");
    assert_no_secret_writes(&received(&openbao).await);
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_binding_read_error_writes_nothing() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-binding-500").await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;
    // Mounted ahead of the ordinary bindings so it wins for the registrar
    // id: a read that fails is not an unbound id.
    Mock::given(method("GET"))
        .and(path(binding_kv_path(REGISTRAR_ID)))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({ "errors": ["boom"] })))
        .mount(&openbao)
        .await;
    stub_registrar_bindings(&openbao, support::ROOT_TOKEN).await;
    stub_service_record_writes(&openbao).await;

    let output = run_responder_hmac(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-binding-500",
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains(REGISTRAR_LIST_ERROR), "stderr:\n{stderr}");
    let requests = received(&openbao).await;
    assert!(
        position_of(&requests, "GET", &binding_kv_path(REGISTRAR_ID)).is_some(),
        "the failing binding read was sent"
    );
    assert_no_secret_writes(&requests);
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_trust_sync_fans_out_to_registrar_identities() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;
    stub_registrar_bindings(&openbao, support::ROOT_TOKEN).await;

    let output = run_rotate_root(temp_dir.path(), &openbao.uri(), "trust-sync");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let requests = received(&openbao).await;
    let global = posted_payloads(&requests, "/v1/secret/data/bootroot/ca");
    assert_eq!(global.len(), 1);
    for id in [SERVICE_NAME, REGISTRAR_ID] {
        let payloads = posted_payloads(&requests, &service_record_path(id, "trust"));
        assert_eq!(
            payloads, global,
            "{id} receives the global trust payload once"
        );
        assert!(
            stdout.contains(&format!("- service trust synced: {id}")),
            "summary names {id}: {stdout}"
        );
    }
    assert!(posted_payloads(&requests, &service_record_path(STRAY_ID, "trust")).is_empty());
    assert!(!stdout.contains(STRAY_ID), "{stdout}");
    let listing = listing_positions(&requests);
    let control_write = position_of(&requests, "POST", "/v1/secret/data/bootroot/ca")
        .expect("global trust written");
    assert!(listing.len() == 1 && listing[0] < control_write);
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_trust_sync_listing_forbidden_writes_nothing() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");

    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, forbidden()).await;

    let output = run_rotate_root(temp_dir.path(), &openbao.uri(), "trust-sync");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains(REGISTRAR_LIST_ERROR), "stderr:\n{stderr}");
    assert_no_secret_writes(&received(&openbao).await);
}

async fn stub_eab_clear(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
    stub_service_record_writes(server).await;
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_eab_clear_clears_global_and_state_services() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    stub_eab_clear(&openbao).await;

    let output = run_rotate_root(temp_dir.path(), &openbao.uri(), "eab-clear");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let requests = received(&openbao).await;
    let cleared = json!({ "kid": "", "hmac": "" });
    assert_eq!(
        posted_payloads(&requests, "/v1/secret/data/bootroot/agent/eab"),
        vec![cleared.clone()]
    );
    assert_eq!(
        posted_payloads(&requests, &service_record_path(SERVICE_NAME, "eab")),
        vec![cleared]
    );
    assert!(stdout.contains("Cleared bootroot/agent/eab"), "{stdout}");
    assert!(
        stdout.contains(&format!("Cleared bootroot/services/{SERVICE_NAME}/eab")),
        "{stdout}"
    );
    assert_no_registrar_enumeration(&requests);
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_eab_clear_fans_out_to_registrar_identities() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    stub_eab_clear(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;
    stub_registrar_bindings(&openbao, support::ROOT_TOKEN).await;

    let output = run_rotate_root(temp_dir.path(), &openbao.uri(), "eab-clear");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let requests = received(&openbao).await;
    let cleared = json!({ "kid": "", "hmac": "" });
    for id in [SERVICE_NAME, REGISTRAR_ID] {
        assert_eq!(
            posted_payloads(&requests, &service_record_path(id, "eab")),
            vec![cleared.clone()],
            "{id} is cleared exactly once"
        );
        assert!(
            stdout.contains(&format!("Cleared bootroot/services/{id}/eab")),
            "{stdout}"
        );
    }
    assert!(posted_payloads(&requests, &service_record_path(STRAY_ID, "eab")).is_empty());
    let listing = listing_positions(&requests);
    let control_write = position_of(&requests, "POST", "/v1/secret/data/bootroot/agent/eab")
        .expect("global EAB cleared");
    assert!(listing.len() == 1 && listing[0] < control_write);
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_eab_clear_listing_forbidden_writes_nothing() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    stub_eab_clear(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, forbidden()).await;

    let output = run_rotate_root(temp_dir.path(), &openbao.uri(), "eab-clear");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains(REGISTRAR_LIST_ERROR), "stderr:\n{stderr}");
    assert_no_secret_writes(&received(&openbao).await);
}

/// The bootroot-internal config below the test state's `secrets` dir.
fn internal_config_path(root: &Path) -> PathBuf {
    root.join("secrets")
        .join("registrar-internal")
        .join("agent.toml")
}

/// Writes `contents` as the bootroot-internal config, the file a
/// registrar endpoint host carries.
fn write_internal_config(root: &Path, contents: &str) -> PathBuf {
    let path = internal_config_path(root);
    fs::create_dir_all(path.parent().expect("internal dir")).expect("create internal dir");
    fs::write(&path, contents).expect("write internal config");
    path
}

/// An internal config the rotations can parse, with or without `[eab]`.
fn valid_internal_config(with_eab: bool) -> String {
    let eab = if with_eab {
        "\n[eab]\nkid = \"kid-1\"\nhmac = \"eab-hmac\"\n"
    } else {
        ""
    };
    format!(
        "email = \"ops@example.internal\"\n\n[acme]\nhttp_responder_hmac = \"old-hmac\"\n\n\
         [trust]\ntrusted_ca_sha256 = [\"aa\"]\n{eab}"
    )
}

/// The internal config's path as the rotation names it: below the
/// `secrets_dir` the test state records, relative to the run's cwd.
const INTERNAL_CONFIG_AS_RECORDED: &str = "secrets/registrar-internal/agent.toml";

/// A config that exists but does not parse as TOML.
const UNPARSEABLE_INTERNAL_CONFIG: &str = "[acme\nhttp_responder_hmac = \"old-hmac\"\n";

/// Stages the fake `pkill` in `root/bin` and returns its log.
fn stage_fake_pkill(root: &Path) -> PathBuf {
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    let log = root.join("pkill.log");
    write_fake_pkill(&bin_dir, &log).expect("write fake pkill");
    log
}

/// Every request the mock received, as `METHOD path`, in order.
fn request_lines(requests: &[wiremock::Request]) -> Vec<String> {
    requests
        .iter()
        .map(|req| format!("{} {}", req.method, req.url.path()))
        .collect()
}

/// Runs `rotate <subcommand>` under the root token with the fake `pkill`
/// staged in `root/bin` on `PATH`.
fn run_rotate_root_with_pkill(
    root: &Path,
    openbao_url: &str,
    subcommand: &str,
    pkill_log: &Path,
) -> std::process::Output {
    let path_var = env::var("PATH").unwrap_or_default();
    Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args([
            "rotate",
            "--openbao-url",
            openbao_url,
            "--root-token",
            support::ROOT_TOKEN,
            "--yes",
            subcommand,
        ])
        .env("PATH", format!("{}:{path_var}", root.join("bin").display()))
        .env("PKILL_OUTPUT", pkill_log)
        .output()
        .expect("run rotate")
}

/// A host whose bootroot-internal config does not parse refuses
/// `rotate responder-hmac` before the first `OpenBao` write, naming the
/// file: proceeding would rotate the responder away from the registrar
/// endpoint daemon.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_unparseable_internal_config_writes_nothing() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-internal").await;
    let config = write_internal_config(temp_dir.path(), UNPARSEABLE_INTERNAL_CONFIG);
    let pkill_log = stage_fake_pkill(temp_dir.path());

    let output = run_responder_hmac_with_env(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-internal",
        &[("PKILL_OUTPUT", &pkill_log)],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains(INTERNAL_CONFIG_AS_RECORDED),
        "the refusal names the file: {stderr}"
    );
    assert!(
        !stdout.contains("hmac-internal") && !stderr.contains("hmac-internal"),
        "the new HMAC is never printed"
    );
    assert_no_secret_writes(&received(&openbao).await);
    assert_eq!(fs::read_to_string(&pkill_log).expect("pkill log"), "");
    assert_eq!(
        fs::read_to_string(&config).expect("config"),
        UNPARSEABLE_INTERNAL_CONFIG
    );
}

/// On a host without the bootroot-internal config `rotate
/// responder-hmac` sends exactly the requests it always has, signals no
/// internal daemon and creates nothing below `secrets/`.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_without_internal_config_is_unchanged() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-plain").await;
    let pkill_log = stage_fake_pkill(temp_dir.path());

    let output = run_responder_hmac_with_env(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-plain",
        &[("PKILL_OUTPUT", &pkill_log)],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        request_lines(&received(&openbao).await),
        vec![
            "GET /v1/sys/health".to_string(),
            "POST /v1/secret/data/bootroot/responder/hmac".to_string(),
            format!("POST /v1/secret/data/bootroot/services/{SERVICE_NAME}/http_responder_hmac"),
        ]
    );
    assert_eq!(fs::read_to_string(&pkill_log).expect("pkill log"), "");
    let docker_log =
        fs::read_to_string(temp_dir.path().join("docker.log")).expect("read docker log");
    assert!(
        docker_log.lines().any(|line| {
            line.contains("restart") && line.contains("bootroot-openbao-agent-responder")
        }),
        "the responder is handed the new HMAC: {docker_log}"
    );
    assert!(
        stdout.contains("responder config updated"),
        "the rotation reports the responder config: {stdout}"
    );
    assert!(
        !temp_dir
            .path()
            .join("secrets")
            .join("registrar-internal")
            .exists(),
        "a host without the registrar gets no internal directory"
    );
    assert!(!stdout.contains("registrar endpoint daemon"), "{stdout}");
}

/// A readable internal config the invoking user cannot republish — the
/// config is root-owned in production — fails the rotation after its
/// `OpenBao` writes, naming the file and both recoveries. The responder
/// is still handed the new HMAC: `OpenBao` and the service agents are
/// already on it, and the `--force` recovery issues against it.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_reports_an_internal_config_it_cannot_publish() {
    assert_ne!(
        bootroot::fs_util::current_process_euid(),
        0,
        "this test asserts what an unprivileged process cannot do, so it must not be root"
    );
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-unpublished").await;
    let before = valid_internal_config(false);
    let config = write_internal_config(temp_dir.path(), &before);
    let pkill_log = stage_fake_pkill(temp_dir.path());

    let output = run_responder_hmac_with_env(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-unpublished",
        &[("PKILL_OUTPUT", &pkill_log)],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains(INTERNAL_CONFIG_AS_RECORDED)
            && stderr.contains("re-run this rotation")
            && stderr.contains("bootroot rotate registrar-internal-credential --force"),
        "{stderr}"
    );
    assert!(
        !stdout.contains("hmac-unpublished") && !stderr.contains("hmac-unpublished"),
        "the new HMAC is never printed"
    );
    let requests = received(&openbao).await;
    assert_eq!(
        posted_payloads(&requests, "/v1/secret/data/bootroot/responder/hmac"),
        vec![json!({ "value": "hmac-unpublished" })],
        "the failure comes after the OpenBao write, which is kept"
    );
    assert_eq!(fs::read_to_string(&config).expect("config"), before);
    assert_eq!(fs::read_to_string(&pkill_log).expect("pkill log"), "");
    let docker_log =
        fs::read_to_string(temp_dir.path().join("docker.log")).expect("read docker log");
    assert!(
        docker_log.lines().any(|line| {
            line.contains("restart") && line.contains("bootroot-openbao-agent-responder")
        }),
        "the responder is handed the new HMAC despite the failure: {docker_log}"
    );
    assert!(
        !stdout.contains("responder config updated"),
        "no summary claims the rotation finished: {stdout}"
    );
}

/// Answers `registration_id`'s per-service `suffix` record write with a
/// server error, ahead of any stub that would accept it.
async fn fail_service_record_write(server: &MockServer, registration_id: &str, suffix: &str) {
    Mock::given(method("POST"))
        .and(path(service_record_path(registration_id, suffix)))
        .respond_with(ResponseTemplate::new(500).set_body_json(json!({
            "errors": ["internal error"]
        })))
        .with_priority(1)
        .mount(server)
        .await;
}

/// On a host with the bootroot-internal config, a fan-out write that
/// fails after the control-node HMAC write does not end `rotate
/// responder-hmac` there. `OpenBao` already carries the
/// new value, so the internal config is still rewritten and the
/// responder still handed the HMAC — both under the lock, which a
/// repair waiting to read that value must not see released before the
/// responder has it — and both failures are reported.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_fanout_failure_still_hands_over_the_hmac() {
    assert_ne!(
        bootroot::fs_util::current_process_euid(),
        0,
        "this test asserts what an unprivileged process cannot do, so it must not be root"
    );
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    fail_service_record_write(&openbao, SERVICE_NAME, "http_responder_hmac").await;
    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-fanout").await;
    let before = valid_internal_config(false);
    let config = write_internal_config(temp_dir.path(), &before);
    let pkill_log = stage_fake_pkill(temp_dir.path());

    let output = run_responder_hmac_with_env(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-fanout",
        &[("PKILL_OUTPUT", &pkill_log)],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("OpenBao KV secret write failed"),
        "the fan-out failure is reported: {stderr}"
    );
    assert!(
        stderr.contains(INTERNAL_CONFIG_AS_RECORDED),
        "the internal config is still rewritten, and its failure reported too: {stderr}"
    );
    assert!(
        !stdout.contains("hmac-fanout") && !stderr.contains("hmac-fanout"),
        "the new HMAC is never printed"
    );
    assert_eq!(
        request_lines(&received(&openbao).await),
        vec![
            "GET /v1/sys/health".to_string(),
            "POST /v1/secret/data/bootroot/responder/hmac".to_string(),
            format!("POST /v1/secret/data/bootroot/services/{SERVICE_NAME}/http_responder_hmac"),
        ]
    );
    assert_eq!(fs::read_to_string(&config).expect("config"), before);
    let docker_log =
        fs::read_to_string(temp_dir.path().join("docker.log")).expect("read docker log");
    assert!(
        docker_log.lines().any(|line| {
            line.contains("restart") && line.contains("bootroot-openbao-agent-responder")
        }),
        "the responder is handed the new HMAC despite the fan-out failure: {docker_log}"
    );
    assert!(
        !stdout.contains("responder config updated"),
        "no summary claims the rotation finished: {stdout}"
    );
}

/// Asserts that a `rotate responder-hmac` run on a host without the
/// bootroot-internal config failed on its fan-out write and stopped
/// there: the failure is reported, the responder's `OpenBao` Agent was
/// not restarted, the responder was not reloaded and no internal daemon
/// was signalled.
fn assert_fanout_failure_ended_the_rotation(
    root: &Path,
    output: &std::process::Output,
    pkill_log: &Path,
    hmac: &str,
) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("OpenBao KV secret write failed"),
        "the fan-out failure is reported: {stderr}"
    );
    assert!(
        !stderr.contains("registrar-internal"),
        "no internal config is involved: {stderr}"
    );
    assert!(
        !stdout.contains(hmac) && !stderr.contains(hmac),
        "the new HMAC is never printed"
    );
    let docker_log = fs::read_to_string(root.join("docker.log")).expect("read docker log");
    assert!(
        !docker_log
            .lines()
            .any(|line| line.contains("restart") || line.contains("HUP")),
        "the responder is neither restarted nor reloaded: {docker_log}"
    );
    assert!(
        !root
            .join("secrets")
            .join("responder")
            .join("responder.toml")
            .exists(),
        "no responder config is rendered for the rotation to wait on"
    );
    assert_eq!(fs::read_to_string(pkill_log).expect("pkill log"), "");
    assert!(
        !root.join("secrets").join("registrar-internal").exists(),
        "a host without the registrar gets no internal directory"
    );
    assert!(
        !stdout.contains("responder config updated"),
        "no summary claims the rotation finished: {stdout}"
    );
}

/// On a host without the bootroot-internal config nothing waits on the
/// internal config lock, so a fan-out write that fails on the first
/// service ends `rotate responder-hmac` there, before the responder is
/// handed the new HMAC.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_without_internal_config_fanout_failure_returns_at_once() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    fail_service_record_write(&openbao, SERVICE_NAME, "http_responder_hmac").await;
    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-fanout-plain").await;
    let pkill_log = stage_fake_pkill(temp_dir.path());

    let output = run_responder_hmac_with_env(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-fanout-plain",
        &[("PKILL_OUTPUT", &pkill_log)],
    );
    assert_fanout_failure_ended_the_rotation(
        temp_dir.path(),
        &output,
        &pkill_log,
        "hmac-fanout-plain",
    );
    assert_eq!(
        request_lines(&received(&openbao).await),
        vec![
            "GET /v1/sys/health".to_string(),
            "POST /v1/secret/data/bootroot/responder/hmac".to_string(),
            format!("POST /v1/secret/data/bootroot/services/{SERVICE_NAME}/http_responder_hmac"),
        ]
    );
}

/// A fan-out write that fails after an earlier one succeeded — here the
/// registrar-managed identity's, which follows the `state.json` service
/// — likewise ends `rotate responder-hmac` on a host without the
/// internal config, keeping the writes already made and handing the
/// responder nothing.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_responder_hmac_without_internal_config_later_fanout_failure_returns_at_once() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    fail_service_record_write(&openbao, REGISTRAR_ID, "http_responder_hmac").await;
    stub_openbao_for_responder_hmac_rotation(&openbao, "hmac-fanout-registrar").await;
    stub_registrar_identities(&openbao, &[(REGISTRAR_ID, binding_record("active"))]).await;
    let pkill_log = stage_fake_pkill(temp_dir.path());

    let output = run_responder_hmac_with_env(
        temp_dir.path(),
        &openbao.uri(),
        &["--root-token", support::ROOT_TOKEN],
        "hmac-fanout-registrar",
        &[("PKILL_OUTPUT", &pkill_log)],
    );
    assert_fanout_failure_ended_the_rotation(
        temp_dir.path(),
        &output,
        &pkill_log,
        "hmac-fanout-registrar",
    );
    let requests = received(&openbao).await;
    assert_eq!(
        request_lines(&requests),
        vec![
            "GET /v1/sys/health".to_string(),
            format!("GET {SERVICES_LIST_PATH}"),
            format!("GET {}", binding_kv_path(SERVICE_NAME)),
            format!("GET {}", binding_kv_path(REGISTRAR_ID)),
            "POST /v1/secret/data/bootroot/responder/hmac".to_string(),
            format!(
                "POST {}",
                service_record_path(SERVICE_NAME, "http_responder_hmac")
            ),
            format!(
                "POST {}",
                service_record_path(REGISTRAR_ID, "http_responder_hmac")
            ),
        ]
    );
    assert_eq!(
        posted_payloads(
            &requests,
            &service_record_path(SERVICE_NAME, "http_responder_hmac")
        ),
        vec![json!({ "hmac": "hmac-fanout-registrar" })],
        "the write made before the failure is kept"
    );
}

/// A per-service write that fails after the global EAB is cleared does
/// not end `rotate eab-clear` there: the internal config is still
/// brought in step with `OpenBao` under the lock, and both failures are
/// reported.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_eab_clear_fanout_failure_still_rewrites_the_internal_config() {
    assert_ne!(
        bootroot::fs_util::current_process_euid(),
        0,
        "this test asserts what an unprivileged process cannot do, so it must not be root"
    );
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    fail_service_record_write(&openbao, SERVICE_NAME, "eab").await;
    stub_eab_clear(&openbao).await;
    let before = valid_internal_config(true);
    let config = write_internal_config(temp_dir.path(), &before);
    let pkill_log = stage_fake_pkill(temp_dir.path());

    let output =
        run_rotate_root_with_pkill(temp_dir.path(), &openbao.uri(), "eab-clear", &pkill_log);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("OpenBao KV secret write failed"),
        "the fan-out failure is reported: {stderr}"
    );
    assert!(
        stderr.contains(INTERNAL_CONFIG_AS_RECORDED)
            && stderr.contains("bootroot rotate registrar-internal-credential --force"),
        "the internal config is still rewritten, and its failure reported too: {stderr}"
    );
    assert_eq!(
        request_lines(&received(&openbao).await),
        vec![
            "GET /v1/sys/health".to_string(),
            "POST /v1/secret/data/bootroot/agent/eab".to_string(),
            format!("POST /v1/secret/data/bootroot/services/{SERVICE_NAME}/eab"),
        ]
    );
    assert_eq!(fs::read_to_string(&config).expect("config"), before);
    assert!(!stdout.contains("EAB clear completed"), "{stdout}");
}

/// `rotate eab-clear` refuses a host whose internal config does not
/// parse before it clears anything.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_eab_clear_unparseable_internal_config_writes_nothing() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    stub_eab_clear(&openbao).await;
    let config = write_internal_config(temp_dir.path(), UNPARSEABLE_INTERNAL_CONFIG);
    let pkill_log = stage_fake_pkill(temp_dir.path());

    let output =
        run_rotate_root_with_pkill(temp_dir.path(), &openbao.uri(), "eab-clear", &pkill_log);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains(INTERNAL_CONFIG_AS_RECORDED),
        "the refusal names the file: {stderr}"
    );
    assert_no_secret_writes(&received(&openbao).await);
    assert_eq!(fs::read_to_string(&pkill_log).expect("pkill log"), "");
    assert_eq!(
        fs::read_to_string(&config).expect("config"),
        UNPARSEABLE_INTERNAL_CONFIG
    );
}

/// On a host without the bootroot-internal config `rotate eab-clear`
/// sends exactly the requests it always has and signals nothing.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_eab_clear_without_internal_config_is_unchanged() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    stub_eab_clear(&openbao).await;
    let pkill_log = stage_fake_pkill(temp_dir.path());

    let output =
        run_rotate_root_with_pkill(temp_dir.path(), &openbao.uri(), "eab-clear", &pkill_log);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(
        request_lines(&received(&openbao).await),
        vec![
            "GET /v1/sys/health".to_string(),
            "POST /v1/secret/data/bootroot/agent/eab".to_string(),
            format!("POST /v1/secret/data/bootroot/services/{SERVICE_NAME}/eab"),
        ]
    );
    assert_eq!(fs::read_to_string(&pkill_log).expect("pkill log"), "");
    assert!(!stdout.contains("Removed [eab]"), "{stdout}");
    assert!(stdout.contains("service bootroot-agents apply"), "{stdout}");
}

/// On a host whose internal config carries no `[eab]`, `rotate
/// eab-clear` leaves the file alone — same bytes, same inode — and
/// signals nothing.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_eab_clear_leaves_an_internal_config_without_eab_alone() {
    use std::os::unix::fs::MetadataExt;

    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    stub_eab_clear(&openbao).await;
    let before = valid_internal_config(false);
    let config = write_internal_config(temp_dir.path(), &before);
    let inode = fs::metadata(&config).expect("meta").ino();
    let pkill_log = stage_fake_pkill(temp_dir.path());

    let output =
        run_rotate_root_with_pkill(temp_dir.path(), &openbao.uri(), "eab-clear", &pkill_log);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(fs::read_to_string(&config).expect("config"), before);
    assert_eq!(fs::metadata(&config).expect("meta").ino(), inode);
    assert_eq!(fs::read_to_string(&pkill_log).expect("pkill log"), "");
    assert!(!stdout.contains("Removed [eab]"), "{stdout}");
}

fn rotation_state_json(root: &Path) -> serde_json::Value {
    let contents =
        fs::read_to_string(root.join("rotation-state.json")).expect("read rotation-state.json");
    serde_json::from_str(&contents).expect("parse rotation-state.json")
}

fn trusted_fingerprints(payload: &serde_json::Value) -> Vec<String> {
    payload["trusted_ca_sha256"]
        .as_array()
        .unwrap_or_else(|| panic!("trusted_ca_sha256 missing from {payload}"))
        .iter()
        .map(|fp| fp.as_str().expect("fingerprint is a string").to_string())
        .collect()
}

/// Mounts everything a registrar-fan-out `rotate ca-key` run needs except
/// the services listing, which each test answers its own way.
async fn stub_ca_key_rotation_with_registrar(server: &MockServer) {
    stub_openbao_for_ca_key_rotation(server).await;
    stub_reissue_write(server, SERVICE_NAME, 200).await;
    stub_registrar_bindings(server, support::ROOT_TOKEN).await;
    stub_reissue_write(server, REGISTRAR_ID, 200).await;
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_fans_out_trust_to_registrar_identities() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());

    stub_ca_key_rotation_with_registrar(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rotation should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let requests = received(&openbao).await;
    let global = posted_payloads(&requests, "/v1/secret/data/bootroot/ca");
    assert_eq!(
        global.len(),
        2,
        "Phase 3 and Phase 6 each write bootroot/ca"
    );
    assert_eq!(
        trusted_fingerprints(&global[0]).len(),
        3,
        "Phase 3 is additive"
    );
    assert_eq!(trusted_fingerprints(&global[1]).len(), 2, "Phase 6 narrows");
    for id in [SERVICE_NAME, REGISTRAR_ID] {
        assert_eq!(
            posted_payloads(&requests, &service_record_path(id, "trust")),
            global,
            "{id} receives both the transitional and the final trust"
        );
    }
    assert!(posted_payloads(&requests, &service_record_path(STRAY_ID, "trust")).is_empty());
    let listing = listing_positions(&requests);
    assert_eq!(listing.len(), 3, "Phases 3, 5 and 6 each enumerate");

    // Phase 5 publishes the same reissue request to the registrar
    // identity as to the `state.json` remote service, after it.
    for id in [SERVICE_NAME, REGISTRAR_ID] {
        let payloads = posted_payloads(&requests, &reissue_kv_path(id));
        assert_eq!(payloads.len(), 1, "{id}: one reissue request");
        assert_reissue_payload(&payloads[0]);
    }
    assert!(posted_payloads(&requests, &reissue_kv_path(STRAY_ID)).is_empty());
    assert!(
        stdout.contains(&format!("{REGISTRAR_ID}: reissue requested at")),
        "phase 5 should report the registrar identity's request: {stdout}"
    );
    let state_publish =
        position_of(&requests, "POST", &reissue_kv_path(SERVICE_NAME)).expect("state publish");
    let registrar_publish =
        position_of(&requests, "POST", &reissue_kv_path(REGISTRAR_ID)).expect("registrar publish");
    assert!(
        state_publish < registrar_publish,
        "state.json services are published before registrar identities"
    );
    assert!(
        listing[1] < state_publish,
        "Phase 5 enumerates before it publishes anything"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_phase_6_listing_failure_resumes_at_phase_6() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());

    stub_ca_key_rotation_with_registrar(&openbao).await;
    // Phase 3's and Phase 5's listings succeed; Phase 6's is refused.
    Mock::given(method("GET"))
        .and(path(SERVICES_LIST_PATH))
        .respond_with(services_listing_response())
        .up_to_n_times(2)
        .mount(&openbao)
        .await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, forbidden()).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains(REGISTRAR_LIST_ERROR), "stderr:\n{stderr}");
    assert_eq!(recorded_rotation_phase(temp_dir.path()), json!(5));

    let requests = received(&openbao).await;
    let listing = listing_positions(&requests);
    assert_eq!(listing.len(), 3, "Phases 3, 5 and 6 each listed");
    let transitional = posted_payloads(&requests, &service_record_path(REGISTRAR_ID, "trust"));
    assert_eq!(transitional.len(), 1, "only Phase 3 reached the identity");
    assert_eq!(trusted_fingerprints(&transitional[0]).len(), 3);
    let after_failure: Vec<String> = requests
        .iter()
        .skip(listing[2])
        .filter(|req| req.method.as_str() == "POST")
        .map(|req| req.url.path().to_string())
        .collect();
    assert!(
        after_failure.is_empty(),
        "Phase 6 wrote nothing after its failed listing: {after_failure:?}"
    );

    // Re-run with the grant fixed: the rotation resumes at Phase 6.
    let rotation_state = rotation_state_json(temp_dir.path());
    let final_fps = vec![
        rotation_state["new_root_fp"]
            .as_str()
            .expect("new root fp")
            .to_string(),
        rotation_state["new_intermediate_fp"]
            .as_str()
            .expect("new intermediate fp")
            .to_string(),
    ];
    openbao.reset().await;
    stub_ca_key_rotation_with_registrar(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the re-run should complete; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Resuming CA key rotation from phase 5"),
        "the re-run should resume after phase 5: {stdout}"
    );
    let requests = received(&openbao).await;
    for id in [SERVICE_NAME, REGISTRAR_ID] {
        let payloads = posted_payloads(&requests, &service_record_path(id, "trust"));
        assert_eq!(payloads.len(), 1, "{id} receives the final trust once");
        assert_eq!(trusted_fingerprints(&payloads[0]), final_fps, "{id}");
    }
    assert!(!temp_dir.path().join("rotation-state.json").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_phase_3_listing_failure_resumes_at_phase_3() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());

    stub_ca_key_rotation_with_registrar(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, forbidden()).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains(REGISTRAR_LIST_ERROR), "stderr:\n{stderr}");
    assert_eq!(recorded_rotation_phase(temp_dir.path()), json!(2));
    assert_no_secret_writes(&received(&openbao).await);

    openbao.reset().await;
    stub_ca_key_rotation_with_registrar(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the re-run should complete; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Resuming CA key rotation from phase 2"),
        "the re-run should resume after phase 2: {stdout}"
    );
    let requests = received(&openbao).await;
    let global = posted_payloads(&requests, "/v1/secret/data/bootroot/ca");
    assert_eq!(global.len(), 2, "the resumed run completes Phases 3 and 6");
    assert_eq!(
        posted_payloads(&requests, &service_record_path(REGISTRAR_ID, "trust")),
        global
    );
    assert!(!temp_dir.path().join("rotation-state.json").exists());
}

// ---------------------------------------------------------------------------
// `approle-secret-id` rotation of registrar-minted identities.
//
// A registrar-minted identity's `secret_id` is renewed by pushing a fresh
// one to `bootroot/services/<id>/secret_id`, issued with the `[registrar]`
// options of `--agent-config`. Only an `active` binding is rotated; a
// `creating` one is skipped and an undecodable one fails.
// ---------------------------------------------------------------------------

/// A second registrar-bound id, used with a `creating` or undecodable binding.
const PIGLET_ID: &str = "h1-piglet-001";
const REGISTRAR_SECRET: &str = "registrar-secret-new";
const STATE_SECRET: &str = "secret-new";
const RUNTIME_ROTATE_ROLE_NAME: &str = "bootroot-runtime-rotate-role";
const AGENT_CONFIG_REQUIRED_ERROR: &str = "`--agent-config <path>` is required";
const NOT_MINTED_ERROR: &str = "has not finished minting";
const SKIPPED_LINE: &str = "AppRole secret_id rotation skipped for";

fn registrar_secret_id_path(registration_id: &str) -> String {
    format!("/v1/auth/approle/role/bootroot-service-{registration_id}/secret-id")
}

fn registrar_role_id_path(registration_id: &str) -> String {
    format!("/v1/auth/approle/role/bootroot-service-{registration_id}/role-id")
}

fn registrar_role_id(registration_id: &str) -> String {
    format!("role-{registration_id}")
}

/// A decodable schema-1 binding record in `state`.
fn binding_record(state: &str) -> serde_json::Value {
    json!({ "schema_version": 1, "host": "h1", "state": state })
}

/// Writes an operator `bootroot-agent` configuration holding `registrar`
/// as its `[registrar]` table, beside tables the rotation must ignore.
fn write_registrar_agent_config(root: &Path, registrar: &str) -> PathBuf {
    let path = root.join("registrar-agent.toml");
    fs::write(
        &path,
        format!(
            "email = \"admin@example.com\"\n\n[registrar]\n{registrar}\n\n[eab]\nkid = \"kid\"\nhmac = \"eab-hmac\"\n"
        ),
    )
    .expect("write registrar agent config");
    path
}

/// A `state.json` with a `registrar_endpoint` entry and no services.
fn prepare_registrar_only_state(root: &Path, openbao_url: &str) {
    write_state_file(root, openbao_url).expect("write state");
    add_registrar_endpoint(root).expect("add registrar endpoint");
}

/// Lists the `state.json` service (unbound) and each given id, and
/// answers each id's binding read with its record.
async fn stub_registrar_identities(server: &MockServer, bindings: &[(&str, serde_json::Value)]) {
    let mut keys = vec![format!("{SERVICE_NAME}/")];
    keys.extend(bindings.iter().map(|(id, _)| format!("{id}/")));
    Mock::given(method("GET"))
        .and(path(SERVICES_LIST_PATH))
        .and(wiremock::matchers::query_param("list", "true"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": { "keys": keys } })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(binding_kv_path(SERVICE_NAME)))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
        .mount(server)
        .await;
    for (id, record) in bindings {
        Mock::given(method("GET"))
            .and(path(binding_kv_path(id)))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "data": record, "metadata": { "version": 1 } }
            })))
            .mount(server)
            .await;
    }
}

/// Stubs the `state.json` service's remote-bootstrap rotation under any
/// token: issuance, verification login and the KV push.
async fn stub_state_service_rotation(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/secret-id")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": STATE_SECRET }
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(
            json!({ "role_id": ROLE_ID, "secret_id": STATE_SECRET }),
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "client-token" }
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(service_record_path(SERVICE_NAME, "secret_id")))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

/// Stubs one registrar identity's issuance (answering `status`),
/// `role_id` read, verification login and KV push.
async fn stub_registrar_rotation(server: &MockServer, registration_id: &str, status: u16) {
    let issued = if status == 200 {
        ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": REGISTRAR_SECRET }
        }))
    } else {
        ResponseTemplate::new(status).set_body_json(json!({ "errors": ["internal error"] }))
    };
    Mock::given(method("POST"))
        .and(path(registrar_secret_id_path(registration_id)))
        .respond_with(issued)
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(registrar_role_id_path(registration_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": registrar_role_id(registration_id) }
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": registrar_role_id(registration_id),
            "secret_id": REGISTRAR_SECRET
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "registrar-client-token" }
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(service_record_path(registration_id, "secret_id")))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

/// Stages a file-based `bootroot-runtime-rotate-role` credential, stubs
/// its login, self-mint and verification, and returns the auth flags.
async fn stage_runtime_rotate_auth(root: &Path, server: &MockServer) -> Vec<String> {
    let cred_path = root.join("rotate-secret-id");
    fs::write(&cred_path, "old-rotate-secret\n").expect("seed rotate credential");
    stub_openbao_for_runtime_approle_login(
        server,
        "rr-role-id",
        "old-rotate-secret",
        "rotate-token",
    )
    .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/auth/approle/role/{RUNTIME_ROTATE_ROLE_NAME}/secret-id"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": "self-minted-secret" }
        })))
        .mount(server)
        .await;
    stub_openbao_for_runtime_approle_login(server, "rr-role-id", "self-minted-secret", "verified")
        .await;
    vec![
        "--auth-mode".to_string(),
        "approle".to_string(),
        "--approle-role-id".to_string(),
        "rr-role-id".to_string(),
        "--approle-secret-id-file".to_string(),
        cred_path.to_string_lossy().into_owned(),
    ]
}

fn root_auth() -> Vec<String> {
    vec!["--root-token".to_string(), support::ROOT_TOKEN.to_string()]
}

fn run_approle_secret_id(
    root: &Path,
    openbao_url: &str,
    auth_args: &[String],
    target_args: &[&str],
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args(["rotate", "--openbao-url", openbao_url])
        .args(auth_args)
        .args(["--yes", "approle-secret-id"])
        .args(target_args)
        .output()
        .expect("run rotate approle-secret-id")
}

fn requests_to<'a>(
    requests: &'a [wiremock::Request],
    http_method: &str,
    request_path: &str,
) -> Vec<&'a wiremock::Request> {
    requests
        .iter()
        .filter(|req| req.method.as_str() == http_method && req.url.path() == request_path)
        .collect()
}

/// The path of every `secret-id` issuance request, in the order received.
fn issuance_paths(requests: &[wiremock::Request]) -> Vec<String> {
    requests
        .iter()
        .filter(|req| req.method.as_str() == "POST" && req.url.path().ends_with("/secret-id"))
        .map(|req| req.url.path().to_string())
        .collect()
}

/// The position of the login that presented `secret_id`, if any.
fn login_position(requests: &[wiremock::Request], secret_id: &str) -> Option<usize> {
    requests.iter().position(|req| {
        req.method.as_str() == "POST"
            && req.url.path() == "/v1/auth/approle/login"
            && serde_json::from_slice::<serde_json::Value>(&req.body)
                .is_ok_and(|body| body["secret_id"] == secret_id)
    })
}

fn self_mint_requested(requests: &[wiremock::Request]) -> bool {
    !requests_to(
        requests,
        "POST",
        &format!("/v1/auth/approle/role/{RUNTIME_ROTATE_ROLE_NAME}/secret-id"),
    )
    .is_empty()
}

/// Asserts the registrar identity's one issuance carried `expected` as
/// its body and no wrap header, and that the minted value was pushed.
fn assert_registrar_issued_and_pushed(
    requests: &[wiremock::Request],
    registration_id: &str,
    expected: &serde_json::Value,
) {
    let issued = requests_to(requests, "POST", &registrar_secret_id_path(registration_id));
    assert_eq!(issued.len(), 1, "one issuance for {registration_id}");
    let body: serde_json::Value =
        serde_json::from_slice(&issued[0].body).expect("parse issuance body");
    assert_eq!(&body, expected, "issuance options for {registration_id}");
    assert!(
        issued[0].headers.get("X-Vault-Wrap-TTL").is_none(),
        "a registrar identity's secret_id is never wrapped"
    );
    assert_eq!(
        posted_payloads(requests, &service_record_path(registration_id, "secret_id")),
        vec![json!({ "secret_id": REGISTRAR_SECRET })],
        "the minted value is pushed to {registration_id}'s KV secret_id"
    );
}

fn assert_registrar_not_login_verified(requests: &[wiremock::Request], registration_id: &str) {
    assert!(
        requests_to(requests, "GET", &registrar_role_id_path(registration_id)).is_empty(),
        "no role_id read for {registration_id}"
    );
    assert!(
        login_position(requests, REGISTRAR_SECRET).is_none(),
        "no login may spend a use of {registration_id}'s pushed secret_id"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_pushes_cidr_bound_registrar_secret_id_unverified() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let agent_config = write_registrar_agent_config(
        temp_dir.path(),
        "secret_id_token_bound_cidrs = [\"10.0.0.0/8\"]",
    );
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(&openbao, &[(REGISTRAR_ID, binding_record("active"))]).await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &[
            "--all-services",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let requests = received(&openbao).await;
    assert_registrar_issued_and_pushed(
        &requests,
        REGISTRAR_ID,
        &json!({ "num_uses": 0, "token_bound_cidrs": ["10.0.0.0/8"] }),
    );
    assert_registrar_not_login_verified(&requests, REGISTRAR_ID);
    assert_eq!(
        posted_payloads(&requests, &service_record_path(SERVICE_NAME, "secret_id")),
        vec![json!({ "secret_id": STATE_SECRET })],
        "the state.json service is rotated as before"
    );
    assert!(
        stdout.contains(&format!("AppRole secret_id rotated for {SERVICE_NAME}")),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains(&format!(
            "AppRole secret_id rotated for {REGISTRAR_ID}: secret/bootroot/services/{REGISTRAR_ID}/secret_id"
        )),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("2 succeeded, 0 failed (total 2)"),
        "stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains(REGISTRAR_SECRET) && !stderr.contains(REGISTRAR_SECRET),
        "the pushed secret_id is never printed"
    );
    assert!(
        !stdout.contains("eab-hmac") && !stderr.contains("eab-hmac"),
        "nothing from --agent-config is printed"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_login_verifies_unbound_unlimited_registrar_secret_id() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let agent_config = write_registrar_agent_config(
        temp_dir.path(),
        "secret_id_num_uses = 0\nsecret_id_ttl = \"12h\"",
    );
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(&openbao, &[(REGISTRAR_ID, binding_record("active"))]).await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &[
            "--all-services",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let requests = received(&openbao).await;
    assert_registrar_issued_and_pushed(
        &requests,
        REGISTRAR_ID,
        &json!({ "num_uses": 0, "ttl": "43200s" }),
    );
    let role_id_read = position_of(&requests, "GET", &registrar_role_id_path(REGISTRAR_ID))
        .expect("the role_id is read for the verification login");
    let login =
        login_position(&requests, REGISTRAR_SECRET).expect("the new secret_id is login-verified");
    let push = position_of(
        &requests,
        "POST",
        &service_record_path(REGISTRAR_ID, "secret_id"),
    )
    .expect("the new secret_id is pushed");
    assert!(
        role_id_read < login && login < push,
        "verification precedes the KV write: role-id {role_id_read}, login {login}, push {push}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_use_limited_registrar_secret_id_is_not_login_verified() {
    for num_uses in [1, 5] {
        let temp_dir = tempdir().expect("create temp dir");
        let openbao = MockServer::start().await;
        prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
            .expect("prepare state");
        let agent_config = write_registrar_agent_config(
            temp_dir.path(),
            &format!("secret_id_num_uses = {num_uses}"),
        );
        stub_state_service_rotation(&openbao).await;
        stub_registrar_identities(&openbao, &[(REGISTRAR_ID, binding_record("active"))]).await;
        stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;

        let output = run_approle_secret_id(
            temp_dir.path(),
            &openbao.uri(),
            &root_auth(),
            &[
                "--all-services",
                "--agent-config",
                agent_config.to_string_lossy().as_ref(),
            ],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "num_uses {num_uses}; stdout:\n{stdout}\nstderr:\n{stderr}"
        );
        let requests = received(&openbao).await;
        assert_registrar_issued_and_pushed(
            &requests,
            REGISTRAR_ID,
            &json!({ "num_uses": num_uses }),
        );
        assert_registrar_not_login_verified(&requests, REGISTRAR_ID);
        assert!(
            !stdout.contains(&format!("AppRole login OK for {REGISTRAR_ID}")),
            "num_uses {num_uses}; stdout:\n{stdout}"
        );
    }
}

/// The single-id path prints a login-ok line only for a verified value,
/// so a use-limited one gets none, and an unlimited one does.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_registration_id_prints_login_ok_only_when_verified() {
    for (registrar, verified) in [("secret_id_num_uses = 1", false), ("", true)] {
        let temp_dir = tempdir().expect("create temp dir");
        let openbao = MockServer::start().await;
        prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
            .expect("prepare state");
        let agent_config = write_registrar_agent_config(temp_dir.path(), registrar);
        stub_state_service_rotation(&openbao).await;
        stub_registrar_identities(&openbao, &[(REGISTRAR_ID, binding_record("active"))]).await;
        stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;

        let output = run_approle_secret_id(
            temp_dir.path(),
            &openbao.uri(),
            &root_auth(),
            &[
                "--registration-id",
                REGISTRAR_ID,
                "--agent-config",
                agent_config.to_string_lossy().as_ref(),
            ],
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{registrar:?}; stdout:\n{stdout}\nstderr:\n{stderr}"
        );
        assert_eq!(
            stdout.contains(&format!("AppRole login OK for {REGISTRAR_ID}")),
            verified,
            "{registrar:?}; stdout:\n{stdout}"
        );
        assert_eq!(
            login_position(&received(&openbao).await, REGISTRAR_SECRET).is_some(),
            verified,
            "{registrar:?}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_requires_agent_config_for_an_active_registrar_id() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(&openbao, &[(REGISTRAR_ID, binding_record("active"))]).await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &["--all-services"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains(AGENT_CONFIG_REQUIRED_ERROR) && stderr.contains(REGISTRAR_ID),
        "stderr:\n{stderr}"
    );
    let issued = issuance_paths(&received(&openbao).await);
    assert!(
        issued.is_empty(),
        "no secret_id may be issued for any target: {issued:?}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_refuses_a_misspelled_registrar_key() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let agent_config = write_registrar_agent_config(temp_dir.path(), "secret_id_num_use = 0");
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(&openbao, &[(REGISTRAR_ID, binding_record("active"))]).await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &[
            "--all-services",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("Refusing to rotate") && stderr.contains("secret_id_num_use"),
        "stderr:\n{stderr}"
    );
    let issued = issuance_paths(&received(&openbao).await);
    assert!(
        issued.is_empty(),
        "no secret_id may be issued for any target: {issued:?}"
    );
}

/// A secret pasted under a key of the wrong type is valid TOML, and the
/// deserializer's own error would quote it in full; the refusal lands in
/// a scheduled job's logs, so it must carry the key and not the value.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_type_error_does_not_print_the_value() {
    const SENTINEL_SECRET: &str = "s3cr3t-hmac-value";
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let agent_config = write_registrar_agent_config(
        temp_dir.path(),
        &format!("secret_id_num_uses = \"{SENTINEL_SECRET}\""),
    );
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(&openbao, &[(REGISTRAR_ID, binding_record("active"))]).await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &[
            "--all-services",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("Refusing to rotate") && stderr.contains("registrar.secret_id_num_uses"),
        "stderr:\n{stderr}"
    );
    assert!(
        !stderr.contains(SENTINEL_SECRET) && !stdout.contains(SENTINEL_SECRET),
        "nothing from --agent-config is printed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let issued = issuance_paths(&received(&openbao).await);
    assert!(
        issued.is_empty(),
        "no secret_id may be issued for any target: {issued:?}"
    );
}

/// Without a `registrar_endpoint` entry nothing is listed or probed and
/// `--agent-config` is neither required nor read.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_without_registrar_endpoint_is_unchanged() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    stub_state_service_rotation(&openbao).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &["--all-services"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = received(&openbao).await;
    assert_no_registrar_enumeration(&requests);
    let paths: Vec<(String, String)> = requests
        .iter()
        .map(|req| (req.method.to_string(), req.url.path().to_string()))
        .filter(|(_, p)| p != "/v1/sys/health")
        .collect();
    assert_eq!(
        paths,
        vec![
            (
                "POST".to_string(),
                format!("/v1/auth/approle/role/{ROLE_NAME}/secret-id")
            ),
            ("POST".to_string(), "/v1/auth/approle/login".to_string()),
            (
                "POST".to_string(),
                service_record_path(SERVICE_NAME, "secret_id")
            ),
        ],
        "exactly the requests a rotation sent before registrar identities existed"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_skips_a_creating_registrar_binding() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let agent_config = write_registrar_agent_config(temp_dir.path(), "");
    let auth = stage_runtime_rotate_auth(temp_dir.path(), &openbao).await;
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(
        &openbao,
        &[
            (REGISTRAR_ID, binding_record("active")),
            (PIGLET_ID, binding_record("creating")),
        ],
    )
    .await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;
    stub_registrar_rotation(&openbao, PIGLET_ID, 200).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &auth,
        &[
            "--all-services",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a creating binding is not a failure; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = received(&openbao).await;
    assert!(
        requests_to(&requests, "POST", &registrar_secret_id_path(PIGLET_ID)).is_empty(),
        "a creating binding gets no secret-id request"
    );
    assert!(
        posted_payloads(&requests, &service_record_path(PIGLET_ID, "secret_id")).is_empty(),
        "nothing is pushed for a creating binding"
    );
    assert_registrar_issued_and_pushed(&requests, REGISTRAR_ID, &json!({ "num_uses": 0 }));
    assert!(
        stdout.contains(&format!("{SKIPPED_LINE} {PIGLET_ID}")) && stdout.contains("creating"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("services skipped: 1"), "stdout:\n{stdout}");
    assert!(
        self_mint_requested(&requests),
        "a skipped target does not withhold the self-mint"
    );
    let state = fs::read_to_string(temp_dir.path().join("state.json")).expect("read state");
    assert!(state.contains("last_secret_id_rotation"), "state:\n{state}");
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_fails_an_undecodable_registrar_binding() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let agent_config = write_registrar_agent_config(temp_dir.path(), "");
    let auth = stage_runtime_rotate_auth(temp_dir.path(), &openbao).await;
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(
        &openbao,
        &[
            (REGISTRAR_ID, binding_record("active")),
            (
                PIGLET_ID,
                json!({ "schema_version": 99, "host": "h1", "state": "active" }),
            ),
        ],
    )
    .await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;
    stub_registrar_rotation(&openbao, PIGLET_ID, 200).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &auth,
        &[
            "--all-services",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(&format!(
            "AppRole secret_id rotation FAILED for {PIGLET_ID}"
        )) && stdout.contains("schema_version 99"),
        "stdout:\n{stdout}"
    );
    assert!(stderr.contains(PIGLET_ID), "stderr:\n{stderr}");
    let requests = received(&openbao).await;
    assert!(requests_to(&requests, "POST", &registrar_secret_id_path(PIGLET_ID)).is_empty());
    assert_registrar_issued_and_pushed(&requests, REGISTRAR_ID, &json!({ "num_uses": 0 }));
    assert_eq!(
        posted_payloads(&requests, &service_record_path(SERVICE_NAME, "secret_id")).len(),
        1,
        "the state.json service is still rotated"
    );
    assert!(
        !self_mint_requested(&requests),
        "a failure withholds the self-mint"
    );
}

/// With nothing `active`, `--agent-config` is not required.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_creating_binding_alone_needs_no_agent_config() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_registrar_only_state(temp_dir.path(), &openbao.uri());
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(&openbao, &[(PIGLET_ID, binding_record("creating"))]).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &["--all-services"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        issuance_paths(&received(&openbao).await).is_empty(),
        "nothing is rotated"
    );
    assert_eq!(
        stdout.matches(SKIPPED_LINE).count(),
        1,
        "one skipped line; stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("No services are registered"),
        "a skipped id is not \"no services\"; stdout:\n{stdout}"
    );
}

/// A binding deregistered between the listing and the re-read is
/// skipped, not failed, and the other targets are still rotated.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_skips_a_binding_gone_before_it_is_reread() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let agent_config = write_registrar_agent_config(temp_dir.path(), "");
    stub_state_service_rotation(&openbao).await;
    // The listing's presence read finds the binding; the re-read that
    // classifies it finds it gone. Mounted first, these win over the
    // standing answer `stub_registrar_identities` mounts for the id.
    Mock::given(method("GET"))
        .and(path(binding_kv_path(PIGLET_ID)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": binding_record("active"), "metadata": { "version": 1 } }
        })))
        .up_to_n_times(1)
        .mount(&openbao)
        .await;
    Mock::given(method("GET"))
        .and(path(binding_kv_path(PIGLET_ID)))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
        .mount(&openbao)
        .await;
    stub_registrar_identities(
        &openbao,
        &[
            (REGISTRAR_ID, binding_record("active")),
            (PIGLET_ID, binding_record("active")),
        ],
    )
    .await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;
    stub_registrar_rotation(&openbao, PIGLET_ID, 200).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &[
            "--all-services",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "a vanished binding is not a failure; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = received(&openbao).await;
    assert!(
        requests_to(&requests, "POST", &registrar_secret_id_path(PIGLET_ID)).is_empty(),
        "a vanished binding gets no secret-id request"
    );
    assert_registrar_issued_and_pushed(&requests, REGISTRAR_ID, &json!({ "num_uses": 0 }));
    assert!(
        stdout.contains(&format!("{SKIPPED_LINE} {PIGLET_ID}"))
            && stdout.contains("no longer exists"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("services skipped: 1"), "stdout:\n{stdout}");
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)] // four sequential CLI runs against one mock
#[tokio::test]
async fn test_rotate_registration_id_targets_registrar_identities() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let agent_config = write_registrar_agent_config(temp_dir.path(), "");
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(
        &openbao,
        &[
            (REGISTRAR_ID, binding_record("active")),
            (PIGLET_ID, binding_record("creating")),
        ],
    )
    .await;
    Mock::given(method("GET"))
        .and(path(binding_kv_path("nope")))
        .respond_with(ResponseTemplate::new(404).set_body_json(json!({ "errors": [] })))
        .mount(&openbao)
        .await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;
    stub_registrar_rotation(&openbao, PIGLET_ID, 200).await;
    let agent_config_arg = agent_config.to_string_lossy().into_owned();

    // An active id alone is rotated, without the enumeration's listing.
    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &[
            "--registration-id",
            REGISTRAR_ID,
            "--agent-config",
            &agent_config_arg,
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = received(&openbao).await;
    assert_eq!(
        issuance_paths(&requests),
        vec![registrar_secret_id_path(REGISTRAR_ID)],
        "only that identity is rotated"
    );
    assert!(
        listing_positions(&requests).is_empty(),
        "rotating one identity needs no list grant"
    );
    assert_registrar_issued_and_pushed(&requests, REGISTRAR_ID, &json!({ "num_uses": 0 }));
    assert!(
        stdout.contains(&format!("AppRole login OK for {REGISTRAR_ID}")),
        "stdout:\n{stdout}"
    );

    // A creating id is refused.
    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &[
            "--registration-id",
            PIGLET_ID,
            "--agent-config",
            &agent_config_arg,
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains(NOT_MINTED_ERROR) && stderr.contains(PIGLET_ID),
        "stderr:\n{stderr}"
    );
    assert!(
        requests_to(
            &received(&openbao).await,
            "POST",
            &registrar_secret_id_path(PIGLET_ID)
        )
        .is_empty()
    );

    // An unknown id keeps today's not-found error.
    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &[
            "--registration-id",
            "nope",
            "--agent-config",
            &agent_config_arg,
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("Service not found: nope"),
        "stderr:\n{stderr}"
    );

    // An id the registrar could never derive is not looked up in KV.
    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &[
            "--registration-id",
            "../escape",
            "--agent-config",
            &agent_config_arg,
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(
        stderr.contains("Service not found: ../escape"),
        "stderr:\n{stderr}"
    );
    let probed: Vec<String> = received(&openbao)
        .await
        .iter()
        .map(|req| req.url.path().to_string())
        .filter(|p| p.contains("escape"))
        .collect();
    assert!(probed.is_empty(), "no KV path is built from it: {probed:?}");
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_continues_past_a_registrar_issuance_failure() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let agent_config = write_registrar_agent_config(temp_dir.path(), "");
    let auth = stage_runtime_rotate_auth(temp_dir.path(), &openbao).await;
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(&openbao, &[(REGISTRAR_ID, binding_record("active"))]).await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 500).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &auth,
        &[
            "--all-services",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains(&format!(
            "AppRole secret_id rotation FAILED for {REGISTRAR_ID}"
        )),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("1 succeeded, 1 failed (total 2)"),
        "stdout:\n{stdout}"
    );
    let requests = received(&openbao).await;
    assert_eq!(
        posted_payloads(&requests, &service_record_path(SERVICE_NAME, "secret_id")).len(),
        1,
        "the state.json service is still rotated"
    );
    assert!(
        posted_payloads(&requests, &service_record_path(REGISTRAR_ID, "secret_id")).is_empty(),
        "nothing is pushed after a failed issuance"
    );
    assert!(
        !self_mint_requested(&requests),
        "a failure withholds the self-mint"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_rotates_a_registrar_id_with_no_state_services() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_registrar_only_state(temp_dir.path(), &openbao.uri());
    let agent_config = write_registrar_agent_config(temp_dir.path(), "");
    stub_state_service_rotation(&openbao).await;
    stub_registrar_identities(&openbao, &[(REGISTRAR_ID, binding_record("active"))]).await;
    stub_registrar_rotation(&openbao, REGISTRAR_ID, 200).await;

    let output = run_approle_secret_id(
        temp_dir.path(),
        &openbao.uri(),
        &root_auth(),
        &[
            "--all-services",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains("No services are registered"),
        "stdout:\n{stdout}"
    );
    assert_registrar_issued_and_pushed(
        &received(&openbao).await,
        REGISTRAR_ID,
        &json!({ "num_uses": 0 }),
    );
}

/// A failed enumeration never aborts the `state.json` rotations: it is
/// one failure, reported with the grant it needs.
#[cfg(unix)]
#[tokio::test]
async fn test_rotate_all_services_listing_failure_still_rotates_state_services() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let auth = stage_runtime_rotate_auth(temp_dir.path(), &openbao).await;
    stub_state_service_rotation(&openbao).await;
    Mock::given(method("GET"))
        .and(path(SERVICES_LIST_PATH))
        .respond_with(forbidden())
        .mount(&openbao)
        .await;

    let output = run_approle_secret_id(temp_dir.path(), &openbao.uri(), &auth, &["--all-services"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains(REGISTRAR_LIST_ERROR), "stdout:\n{stdout}");
    let requests = received(&openbao).await;
    assert_eq!(
        posted_payloads(&requests, &service_record_path(SERVICE_NAME, "secret_id")).len(),
        1,
        "the state.json service is still rotated"
    );
    assert!(
        !self_mint_requested(&requests),
        "a failure withholds the self-mint"
    );
}

/// Returns the path of every reissue request written, in arrival order.
fn reissue_write_paths(requests: &[wiremock::Request]) -> Vec<String> {
    requests
        .iter()
        .filter(|req| req.method.as_str() == "POST" && req.url.path().ends_with("/reissue"))
        .map(|req| req.url.path().to_string())
        .collect()
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_reissue_publishes_once_to_id_in_state_and_bound() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());

    // The `state.json` service also carries a binding, overriding the
    // helper's 404 for it.
    Mock::given(method("GET"))
        .and(path(binding_kv_path(SERVICE_NAME)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": { "schema_version": 1, "state": "active" },
                "metadata": { "version": 1 }
            }
        })))
        .with_priority(1)
        .mount(&openbao)
        .await;
    stub_ca_key_rotation_with_registrar(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rotation should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let requests = received(&openbao).await;
    assert!(
        position_of(&requests, "GET", &binding_kv_path(SERVICE_NAME)).is_some(),
        "the enumeration should have found the state.json service's binding"
    );
    let state_requests = posted_payloads(&requests, &reissue_kv_path(SERVICE_NAME));
    assert_eq!(
        state_requests.len(),
        1,
        "an id in both sets is published once, by the state.json loop: {state_requests:?}"
    );
    assert_reissue_payload(&state_requests[0]);
    assert_eq!(
        posted_payloads(&requests, &reissue_kv_path(REGISTRAR_ID)).len(),
        1
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_phase_5_listing_failure_resumes_at_phase_5() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "local-file")
        .expect("prepare state");
    add_remote_services(temp_dir.path(), &["svc-remote"]).expect("add remote service");
    let envs = stage_ca_key_rotation(temp_dir.path());
    write_rotation_state_at_phase(temp_dir.path(), 4);

    // A local leaf the new intermediate did not sign, which Phase 5 would
    // delete if it got that far.
    let certs_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&certs_dir).expect("create certs dir");
    let local_cert = certs_dir.join("edge-proxy.crt");
    let local_key = certs_dir.join("edge-proxy.key");
    fs::write(&local_cert, generate_test_cert_pem("old-leaf.example")).expect("write local cert");
    fs::write(&local_key, "old key").expect("write local key");

    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_registrar_bindings(&openbao, support::ROOT_TOKEN).await;
    stub_reissue_write(&openbao, "svc-remote", 200).await;
    stub_reissue_write(&openbao, REGISTRAR_ID, 200).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, forbidden()).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains(REGISTRAR_LIST_ERROR), "stderr:\n{stderr}");
    assert_eq!(recorded_rotation_phase(temp_dir.path()), json!(4));
    let requests = received(&openbao).await;
    let reissues = reissue_write_paths(&requests);
    assert!(
        reissues.is_empty(),
        "no reissue request may precede enumeration: {reissues:?}"
    );
    assert!(local_cert.exists(), "the local cert must not be deleted");
    assert!(local_key.exists(), "the local key must not be deleted");

    // Migrate the local leaf, so the re-run's Phase 5 skips it and
    // Phase 6's migration check passes without `--force`.
    fs::copy(
        temp_dir
            .path()
            .join("secrets")
            .join("certs")
            .join("intermediate_ca.crt"),
        &local_cert,
    )
    .expect("write migrated leaf");

    openbao.reset().await;
    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_registrar_bindings(&openbao, support::ROOT_TOKEN).await;
    stub_reissue_write(&openbao, "svc-remote", 200).await;
    stub_reissue_write(&openbao, REGISTRAR_ID, 200).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the re-run should complete; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Resuming CA key rotation from phase 4"),
        "the re-run should resume after phase 4: {stdout}"
    );
    let requests = received(&openbao).await;
    for id in ["svc-remote", REGISTRAR_ID] {
        let payloads = posted_payloads(&requests, &reissue_kv_path(id));
        assert_eq!(payloads.len(), 1, "{id}: one reissue request");
        assert_reissue_payload(&payloads[0]);
    }
    let remote_publish =
        position_of(&requests, "POST", &reissue_kv_path("svc-remote")).expect("remote publish");
    let registrar_publish =
        position_of(&requests, "POST", &reissue_kv_path(REGISTRAR_ID)).expect("registrar publish");
    assert!(
        remote_publish < registrar_publish,
        "state.json services are published before registrar identities"
    );
    assert!(!temp_dir.path().join("rotation-state.json").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_registrar_reissue_publish_failure_resumes_at_phase_5() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());

    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_reissue_write(&openbao, SERVICE_NAME, 200).await;
    stub_registrar_bindings(&openbao, support::ROOT_TOKEN).await;
    stub_reissue_write(&openbao, REGISTRAR_ID, 500).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a failed reissue publish must fail the rotation; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains(REGISTRAR_ID),
        "the error should name the identity whose request failed: {stderr}"
    );
    assert_eq!(recorded_rotation_phase(temp_dir.path()), json!(4));
    let requests = received(&openbao).await;
    assert_eq!(
        posted_payloads(&requests, &reissue_kv_path(SERVICE_NAME)).len(),
        1
    );

    openbao.reset().await;
    stub_ca_key_rotation_with_registrar(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "the re-run should complete; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("Resuming CA key rotation from phase 4"),
        "the re-run should resume after phase 4: {stdout}"
    );
    let requests = received(&openbao).await;
    for id in [SERVICE_NAME, REGISTRAR_ID] {
        let payloads = posted_payloads(&requests, &reissue_kv_path(id));
        assert_eq!(payloads.len(), 1, "{id}: republished on resume");
        assert_reissue_payload(&payloads[0]);
    }
    assert!(!temp_dir.path().join("rotation-state.json").exists());
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_skip_reissue_publishes_no_registrar_request() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;
    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state_with_registrar(temp_dir.path(), &openbao.uri(), "remote-bootstrap")
        .expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());

    stub_ca_key_rotation_with_registrar(&openbao).await;
    stub_services_listing(&openbao, support::ROOT_TOKEN, services_listing_response()).await;

    let output = run_rotate_ca_key(
        temp_dir.path(),
        &openbao.uri(),
        &envs,
        &["--skip", "reissue"],
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rotation should succeed with --skip reissue; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let requests = received(&openbao).await;
    let reissues = reissue_write_paths(&requests);
    assert!(
        reissues.is_empty(),
        "--skip reissue must publish no reissue request: {reissues:?}"
    );
    assert_eq!(
        listing_positions(&requests).len(),
        2,
        "only Phases 3 and 6 enumerate"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_rotate_ca_key_reissue_without_registrar_endpoint_enumerates_nothing() {
    let temp_dir = tempdir().expect("create temp dir");
    let openbao = MockServer::start().await;

    support::create_secrets_dir(temp_dir.path()).expect("create secrets dir");
    support::write_password_file(&temp_dir.path().join("secrets"), "test-password")
        .expect("write password");
    prepare_app_state(temp_dir.path(), &openbao.uri(), "remote-bootstrap").expect("prepare state");
    let envs = stage_ca_key_rotation(temp_dir.path());

    stub_openbao_for_ca_key_rotation(&openbao).await;
    stub_reissue_write(&openbao, SERVICE_NAME, 200).await;

    let output = run_rotate_ca_key(temp_dir.path(), &openbao.uri(), &envs, &[]);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "rotation should succeed; stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    let requests = reissue_requests(&openbao, SERVICE_NAME).await;
    assert_eq!(
        requests.len(),
        1,
        "one reissue request expected: {requests:?}"
    );
    assert_reissue_payload(&requests[0]);
    assert!(
        stdout.contains(&format!("{SERVICE_NAME}: reissue requested at")),
        "phase 5 should report the published request: {stdout}"
    );
    assert_no_registrar_enumeration(&received(&openbao).await);
    assert!(
        !temp_dir.path().join("rotation-state.json").exists(),
        "rotation-state.json should be deleted after completion"
    );
}
