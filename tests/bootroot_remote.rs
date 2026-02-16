#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn test_bootroot_remote_applies_service_secrets() {
    let temp_dir = tempdir().expect("create temp dir");
    let role_id_path = temp_dir.path().join("secrets").join("role_id");
    let secret_id_path = temp_dir.path().join("secrets").join("secret_id");
    let eab_file_path = temp_dir.path().join("secrets").join("eab.json");
    let ca_bundle_path = temp_dir.path().join("certs").join("ca-bundle.pem");
    let agent_config_path = temp_dir.path().join("agent.toml");

    fs::create_dir_all(role_id_path.parent().expect("role_id parent")).expect("create secrets dir");
    fs::write(&role_id_path, "role-edge-proxy\n").expect("write role_id");
    fs::write(&secret_id_path, "old-secret\n").expect("write secret_id");
    fs::write(
        &agent_config_path,
        "[acme]\nhttp_responder_hmac = \"old\"\n[trust]\nca_bundle_path = \"old.pem\"\ntrusted_ca_sha256 = [\"0\" ]\n",
    )
    .expect("write agent config");

    let server = MockServer::start().await;
    stub_openbao_remote_sync(&server).await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .args([
            "--openbao-url",
            &server.uri(),
            "--kv-mount",
            "secret",
            "--service-name",
            "edge-proxy",
            "--role-id-path",
            role_id_path.to_string_lossy().as_ref(),
            "--secret-id-path",
            secret_id_path.to_string_lossy().as_ref(),
            "--eab-file-path",
            eab_file_path.to_string_lossy().as_ref(),
            "--agent-config-path",
            agent_config_path.to_string_lossy().as_ref(),
            "--ca-bundle-path",
            ca_bundle_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run bootroot-remote");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(stdout.contains("bootroot-remote sync summary"));
    assert!(stdout.contains("- secret_id: applied"));
    assert!(stdout.contains("- eab: applied"));
    assert!(stdout.contains("- responder_hmac: applied"));
    assert!(stdout.contains("- trust_sync: applied"));

    let secret_contents = fs::read_to_string(&secret_id_path).expect("read secret_id");
    assert_eq!(secret_contents, "new-secret-id\n");
    let eab_contents = fs::read_to_string(&eab_file_path).expect("read eab file");
    assert!(eab_contents.contains("\"kid\": \"kid-1\""));
    assert!(eab_contents.contains("\"hmac\": \"hmac-1\""));
    let agent_contents = fs::read_to_string(&agent_config_path).expect("read agent config");
    assert!(agent_contents.contains("http_responder_hmac = \"responder-hmac-1\""));
    assert!(agent_contents.contains("ca_bundle_path = \""));
    assert!(agent_contents.contains("trusted_ca_sha256 = ["));
    let bundle_contents = fs::read_to_string(&ca_bundle_path).expect("read ca bundle");
    assert_eq!(
        bundle_contents,
        "-----BEGIN CERTIFICATE-----\nREMOTE\n-----END CERTIFICATE-----\n"
    );

    assert_mode(&secret_id_path, 0o600);
    assert_mode(&eab_file_path, 0o600);
    assert_mode(&agent_config_path, 0o600);
    assert_mode(&ca_bundle_path, 0o600);
    assert_mode(role_id_path.parent().expect("role_id parent"), 0o700);
    assert_mode(ca_bundle_path.parent().expect("ca bundle parent"), 0o700);
}

#[tokio::test]
async fn test_bootroot_remote_is_idempotent_on_second_run() {
    let temp_dir = tempdir().expect("create temp dir");
    let role_id_path = temp_dir.path().join("secrets").join("role_id");
    let secret_id_path = temp_dir.path().join("secrets").join("secret_id");
    let eab_file_path = temp_dir.path().join("secrets").join("eab.json");
    let ca_bundle_path = temp_dir.path().join("certs").join("ca-bundle.pem");
    let agent_config_path = temp_dir.path().join("agent.toml");

    fs::create_dir_all(role_id_path.parent().expect("role_id parent")).expect("create secrets dir");
    fs::write(&role_id_path, "role-edge-proxy\n").expect("write role_id");
    fs::write(&secret_id_path, "old-secret\n").expect("write secret_id");
    fs::write(
        &agent_config_path,
        "[acme]\nhttp_responder_hmac = \"old\"\n",
    )
    .expect("write agent config");

    let server = MockServer::start().await;
    stub_openbao_remote_sync(&server).await;

    let command = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
            .args([
                "--openbao-url",
                &server.uri(),
                "--kv-mount",
                "secret",
                "--service-name",
                "edge-proxy",
                "--role-id-path",
                role_id_path.to_string_lossy().as_ref(),
                "--secret-id-path",
                secret_id_path.to_string_lossy().as_ref(),
                "--eab-file-path",
                eab_file_path.to_string_lossy().as_ref(),
                "--agent-config-path",
                agent_config_path.to_string_lossy().as_ref(),
                "--ca-bundle-path",
                ca_bundle_path.to_string_lossy().as_ref(),
            ])
            .output()
            .expect("run bootroot-remote")
    };

    let first = command();
    assert!(first.status.success());
    let second = command();
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(second.status.success());
    assert!(stdout.contains("- secret_id: unchanged"));
    assert!(stdout.contains("- eab: unchanged"));
    assert!(stdout.contains("- responder_hmac: unchanged"));
    assert!(stdout.contains("- trust_sync: unchanged"));
}

#[tokio::test]
async fn test_bootroot_remote_fails_when_trust_fingerprints_missing() {
    let temp_dir = tempdir().expect("create temp dir");
    let role_id_path = temp_dir.path().join("secrets").join("role_id");
    let secret_id_path = temp_dir.path().join("secrets").join("secret_id");
    let eab_file_path = temp_dir.path().join("secrets").join("eab.json");
    let agent_config_path = temp_dir.path().join("agent.toml");

    fs::create_dir_all(role_id_path.parent().expect("role_id parent")).expect("create secrets dir");
    fs::write(&role_id_path, "role-edge-proxy\n").expect("write role_id");
    fs::write(&secret_id_path, "old-secret\n").expect("write secret_id");
    fs::write(
        &agent_config_path,
        "[acme]\nhttp_responder_hmac = \"old\"\n",
    )
    .expect("write agent config");

    let server = MockServer::start().await;
    stub_openbao_remote_sync_without_trust_list(&server).await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .args([
            "--openbao-url",
            &server.uri(),
            "--service-name",
            "edge-proxy",
            "--role-id-path",
            role_id_path.to_string_lossy().as_ref(),
            "--secret-id-path",
            secret_id_path.to_string_lossy().as_ref(),
            "--eab-file-path",
            eab_file_path.to_string_lossy().as_ref(),
            "--agent-config-path",
            agent_config_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run bootroot-remote");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot-remote failed"));
    assert!(stderr.contains("trusted_ca_sha256"));
}

#[tokio::test]
async fn test_bootroot_remote_reports_partial_failure_with_json_output() {
    let temp_dir = tempdir().expect("create temp dir");
    let role_id_path = temp_dir.path().join("secrets").join("role_id");
    let secret_id_path = temp_dir.path().join("secrets").join("secret_id");
    let eab_file_path = temp_dir.path().join("secrets").join("eab.json");
    let agent_config_path = temp_dir.path().join("agent.toml");

    fs::create_dir_all(role_id_path.parent().expect("role_id parent")).expect("create secrets dir");
    fs::write(&role_id_path, "role-edge-proxy\n").expect("write role_id");
    fs::write(&secret_id_path, "old-secret\n").expect("write secret_id");
    fs::create_dir_all(&agent_config_path)
        .expect("create agent config directory to force read failure");

    let server = MockServer::start().await;
    stub_openbao_remote_sync(&server).await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .args([
            "--openbao-url",
            &server.uri(),
            "--service-name",
            "edge-proxy",
            "--role-id-path",
            role_id_path.to_string_lossy().as_ref(),
            "--secret-id-path",
            secret_id_path.to_string_lossy().as_ref(),
            "--eab-file-path",
            eab_file_path.to_string_lossy().as_ref(),
            "--agent-config-path",
            agent_config_path.to_string_lossy().as_ref(),
            "--output",
            "json",
        ])
        .output()
        .expect("run bootroot-remote");

    assert!(!output.status.success());
    let summary: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse json summary");

    assert_eq!(summary["secret_id"]["status"], "applied");
    assert_eq!(summary["eab"]["status"], "applied");
    assert_eq!(summary["responder_hmac"]["status"], "failed");
    assert_eq!(summary["trust_sync"]["status"], "failed");
    assert!(summary["responder_hmac"]["error"].is_string());
}

async fn stub_openbao_remote_sync(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "remote-token" }
        })))
        .mount(server)
        .await;
    stub_shared_service_payloads(server, json!({
        "trusted_ca_sha256": ["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"],
        "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nREMOTE\n-----END CERTIFICATE-----"
    }))
    .await;
}

async fn stub_openbao_remote_sync_without_trust_list(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "remote-token" }
        })))
        .mount(server)
        .await;
    stub_shared_service_payloads(
        server,
        json!({
            "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nREMOTE\n-----END CERTIFICATE-----"
        }),
    )
    .await;
}

async fn stub_shared_service_payloads(server: &MockServer, trust_payload: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path(
            "/v1/secret/data/bootroot/services/edge-proxy/secret_id",
        ))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "secret_id": "new-secret-id" } }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/eab"))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "kid-1", "hmac": "hmac-1" } }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/v1/secret/data/bootroot/services/edge-proxy/http_responder_hmac",
        ))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "hmac": "responder-hmac-1" } }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/trust"))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": trust_payload }
        })))
        .mount(server)
        .await;
}

fn assert_mode(path: &std::path::Path, expected: u32) {
    let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, expected, "path {}", path.display());
}
