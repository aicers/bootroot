#![cfg(unix)]

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;
use rcgen::generate_simple_self_signed;
use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{body_json, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RUNTIME_SERVICE_ADD_ROLE_ID: &str = "runtime-service-add-role-id";
const RUNTIME_SERVICE_ADD_SECRET_ID: &str = "runtime-service-add-secret-id";
const RUNTIME_ROTATE_ROLE_ID: &str = "runtime-rotate-role-id";
const RUNTIME_ROTATE_SECRET_ID: &str = "runtime-rotate-secret-id";
const RUNTIME_CLIENT_TOKEN: &str = "runtime-client-token";
const SERVICE_NAME: &str = "edge-proxy";
const HOSTNAME: &str = "edge-node-01";
const DOMAIN: &str = "trusted.domain";
const INSTANCE_ID: &str = "001";
const ROLE_NAME: &str = "bootroot-service-edge-proxy";
const ROLE_ID: &str = "role-edge-proxy";

#[tokio::test]
async fn test_same_host_local_file_happy_path() {
    let temp = tempdir().expect("create tempdir");
    let server = MockServer::start().await;
    stub_service_add_openbao(&server).await;

    write_state_file(temp.path(), &server.uri()).expect("write state");
    let files = init_service_files(temp.path()).expect("init service files");

    run_service_add_local(temp.path(), &server.uri(), &files).expect("service add local");

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(temp.path().join("state.json")).expect("state"))
            .expect("parse state");
    assert_eq!(
        state["services"][SERVICE_NAME]["delivery_mode"],
        "local-file"
    );

    let agent_contents = fs::read_to_string(&files.agent_config).expect("read agent.toml");
    assert!(agent_contents.contains("[[profiles]]"));
    assert!(agent_contents.contains("service_name = \"edge-proxy\""));
    assert!(agent_contents.contains("[profiles.paths]"));
    assert!(agent_contents.contains("cert = \""));
    assert!(agent_contents.contains("key = \""));
    assert!(agent_contents.contains("[trust]"));
    assert!(agent_contents.contains("trusted_ca_sha256 = ["));
    assert!(agent_contents.contains("ca_bundle_path = \""));

    let bundle_contents = fs::read_to_string(&files.ca_bundle_path).expect("read ca-bundle");
    assert!(bundle_contents.contains("BEGIN CERTIFICATE"));
    assert!(bundle_contents.contains("LOCAL-TRUST"));
    assert_mode(&files.ca_bundle_path, 0o600);

    assert!(
        temp.path()
            .join("secrets")
            .join("openbao")
            .join("services")
            .join(SERVICE_NAME)
            .join("agent.hcl")
            .exists()
    );
    assert!(
        temp.path()
            .join("secrets")
            .join("openbao")
            .join("services")
            .join(SERVICE_NAME)
            .join("agent.toml.ctmpl")
            .exists()
    );

    write_service_cert(&files.cert_path, &files.key_path).expect("write cert");
    write_fake_bootroot_agent(temp.path(), 0).expect("write fake bootroot-agent");
    run_verify(temp.path(), &files.agent_config).expect("verify succeeds");
}

#[tokio::test]
async fn test_same_host_local_rotation_sequence_keeps_service_operational() {
    let temp = tempdir().expect("create tempdir");
    let server = MockServer::start().await;
    stub_service_add_openbao(&server).await;

    write_state_file(temp.path(), &server.uri()).expect("write state");
    let files = init_service_files(temp.path()).expect("init service files");
    run_service_add_local(temp.path(), &server.uri(), &files).expect("service add local");
    stub_rotate_sequence_openbao(&server, "secret-rotated", "eab-kid-2", "eab-hmac-2").await;
    fs::write(temp.path().join("docker-compose.yml"), "services: {}\n").expect("write compose");
    write_fake_pkill(temp.path(), 0).expect("write fake pkill");
    write_service_cert(&files.cert_path, &files.key_path).expect("write cert");
    write_fake_bootroot_agent(temp.path(), 0).expect("write fake bootroot-agent");

    run_rotate_eab(temp.path(), &server.uri()).expect("rotate eab");
    run_rotate_responder_hmac(temp.path(), &server.uri(), "hmac-updated").expect("rotate hmac");
    let rotate_secret = run_rotate_secret_id_with_output(temp.path(), &server.uri());
    assert!(
        rotate_secret.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rotate_secret.stderr)
    );
    assert!(String::from_utf8_lossy(&rotate_secret.stdout).contains("AppRole login OK"));

    let secret_id = fs::read_to_string(files.secret_id_path).expect("read secret_id");
    assert!(!secret_id.trim().is_empty());
    assert_eq!(
        fs::read_to_string(files.role_id_path).expect("read role_id"),
        ROLE_ID
    );

    let agent_contents = fs::read_to_string(&files.agent_config).expect("read agent.toml");
    assert!(agent_contents.contains("[eab]"));
    assert!(agent_contents.contains("kid = \"eab-kid-2\""));
    assert!(agent_contents.contains("hmac = \"eab-hmac-2\""));
    assert!(agent_contents.contains("http_responder_hmac = \"hmac-updated\""));

    run_verify(temp.path(), &files.agent_config).expect("verify after rotations");
}

#[tokio::test]
async fn test_same_host_trust_change_propagates_to_agent_config() {
    let temp = tempdir().expect("create tempdir");
    let server = MockServer::start().await;
    stub_service_add_openbao(&server).await;
    stub_remote_pull_openbao(&server).await;

    write_state_file(temp.path(), &server.uri()).expect("write state");
    let files = init_service_files(temp.path()).expect("init service files");
    run_service_add_local(temp.path(), &server.uri(), &files).expect("service add local");
    fs::write(&files.role_id_path, format!("{ROLE_ID}\n")).expect("seed role_id");
    fs::write(&files.secret_id_path, "secret-initial\n").expect("seed secret_id");

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .current_dir(temp.path())
        .args([
            "bootstrap",
            "--openbao-url",
            &server.uri(),
            "--kv-mount",
            "secret",
            "--service-name",
            SERVICE_NAME,
            "--role-id-path",
            files.role_id_path.to_string_lossy().as_ref(),
            "--secret-id-path",
            files.secret_id_path.to_string_lossy().as_ref(),
            "--eab-file-path",
            files.eab_path.to_string_lossy().as_ref(),
            "--agent-config-path",
            files.agent_config.to_string_lossy().as_ref(),
            "--ca-bundle-path",
            files.ca_bundle_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run bootroot-remote bootstrap");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&files.agent_config).expect("read agent.toml");
    assert!(agent_contents.contains("trusted_ca_sha256 = ["));
    assert!(agent_contents.contains("ca_bundle_path = \""));
    let bundle_contents = fs::read_to_string(&files.ca_bundle_path).expect("read ca-bundle");
    assert!(bundle_contents.contains("BEGIN CERTIFICATE"));
    assert!(bundle_contents.contains("UPDATED-TRUST"));
}

#[tokio::test]
async fn test_same_host_failure_then_recovery_for_secret_id_rotation() {
    let temp = tempdir().expect("create tempdir");
    let server = MockServer::start().await;
    stub_service_add_openbao(&server).await;

    write_state_file(temp.path(), &server.uri()).expect("write state");
    let files = init_service_files(temp.path()).expect("init service files");
    run_service_add_local(temp.path(), &server.uri(), &files).expect("service add local");
    stub_secret_id_rotation_openbao(&server, "secret-recovered").await;

    write_fake_pkill(temp.path(), 1).expect("write failing pkill");
    let first = run_rotate_secret_id_with_output(temp.path(), &server.uri());
    assert!(
        !first.status.success(),
        "rotation should fail on reload path"
    );
    assert!(String::from_utf8_lossy(&first.stderr).contains("bootroot rotate failed"));

    write_fake_pkill(temp.path(), 0).expect("write successful pkill");
    let second = run_rotate_secret_id_with_output(temp.path(), &server.uri());
    assert!(
        second.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    assert!(
        String::from_utf8_lossy(&second.stdout).contains("AppRole login OK"),
        "stdout: {}",
        String::from_utf8_lossy(&second.stdout)
    );
    let secret = fs::read_to_string(&files.secret_id_path).expect("read secret_id");
    assert!(!secret.trim().is_empty());
    let role_id = fs::read_to_string(&files.role_id_path).expect("read role_id");
    assert_eq!(role_id, ROLE_ID);
}

struct ServicePaths {
    agent_config: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    secret_id_path: PathBuf,
    role_id_path: PathBuf,
    eab_path: PathBuf,
    ca_bundle_path: PathBuf,
}

fn init_service_files(root: &Path) -> anyhow::Result<ServicePaths> {
    let cert_path = root.join("certs").join("edge-proxy.crt");
    let key_path = root.join("certs").join("edge-proxy.key");
    let agent_config = root.join("agent.toml");
    let secret_dir = root.join("secrets").join("services").join(SERVICE_NAME);
    let secret_id_path = secret_dir.join("secret_id");
    let role_id_path = secret_dir.join("role_id");
    let eab_path = secret_dir.join("eab.json");
    let ca_bundle_path = root.join("certs").join("ca-bundle.pem");

    fs::create_dir_all(cert_path.parent().expect("cert parent")).context("create cert dir")?;
    fs::create_dir_all(&secret_dir).context("create secret dir")?;
    fs::write(&agent_config, "# initial\n").context("write agent config")?;
    Ok(ServicePaths {
        agent_config,
        cert_path,
        key_path,
        secret_id_path,
        role_id_path,
        eab_path,
        ca_bundle_path,
    })
}

fn run_service_add_local(
    root: &Path,
    openbao_url: &str,
    files: &ServicePaths,
) -> anyhow::Result<()> {
    let _ = openbao_url;
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args([
            "service",
            "add",
            "--service-name",
            SERVICE_NAME,
            "--deploy-type",
            "daemon",
            "--delivery-mode",
            "local-file",
            "--hostname",
            HOSTNAME,
            "--domain",
            DOMAIN,
            "--agent-config",
            files.agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            files.cert_path.to_string_lossy().as_ref(),
            "--key-path",
            files.key_path.to_string_lossy().as_ref(),
            "--instance-id",
            INSTANCE_ID,
            "--auth-mode",
            "approle",
            "--approle-role-id",
            RUNTIME_SERVICE_ADD_ROLE_ID,
            "--approle-secret-id",
            RUNTIME_SERVICE_ADD_SECRET_ID,
        ])
        .output()
        .context("run service add")?;
    if !output.status.success() {
        anyhow::bail!(
            "service add failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn run_rotate_eab(root: &Path, openbao_url: &str) -> anyhow::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args([
            "rotate",
            "--openbao-url",
            openbao_url,
            "--auth-mode",
            "approle",
            "--approle-role-id",
            RUNTIME_ROTATE_ROLE_ID,
            "--approle-secret-id",
            RUNTIME_ROTATE_SECRET_ID,
            "--yes",
            "eab",
            "--stepca-url",
            openbao_url,
            "--stepca-provisioner",
            "acme",
        ])
        .output()
        .context("run rotate eab")?;
    if !output.status.success() {
        anyhow::bail!(
            "rotate eab failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn run_rotate_responder_hmac(root: &Path, openbao_url: &str, hmac: &str) -> anyhow::Result<()> {
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args([
            "rotate",
            "--openbao-url",
            openbao_url,
            "--auth-mode",
            "approle",
            "--approle-role-id",
            RUNTIME_ROTATE_ROLE_ID,
            "--approle-secret-id",
            RUNTIME_ROTATE_SECRET_ID,
            "--compose-file",
            "docker-compose.yml",
            "--yes",
            "responder-hmac",
            "--hmac",
            hmac,
        ])
        .output()
        .context("run rotate responder-hmac")?;
    if !output.status.success() {
        anyhow::bail!(
            "rotate responder-hmac failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn run_rotate_secret_id_with_output(root: &Path, openbao_url: &str) -> std::process::Output {
    let path_env = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path_env}", root.join("bin").display());
    Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .env("PATH", combined_path)
        .args([
            "rotate",
            "--openbao-url",
            openbao_url,
            "--auth-mode",
            "approle",
            "--approle-role-id",
            RUNTIME_ROTATE_ROLE_ID,
            "--approle-secret-id",
            RUNTIME_ROTATE_SECRET_ID,
            "--yes",
            "approle-secret-id",
            "--service-name",
            SERVICE_NAME,
        ])
        .output()
        .expect("run rotate approle-secret-id")
}

fn run_verify(root: &Path, agent_config: &Path) -> anyhow::Result<()> {
    let path_env = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path_env}", root.join("bin").display());
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .env("PATH", combined_path)
        .args([
            "verify",
            "--service-name",
            SERVICE_NAME,
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
        ])
        .output()
        .context("run verify")?;
    if !output.status.success() {
        anyhow::bail!("verify failed: {}", String::from_utf8_lossy(&output.stderr));
    }
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

fn write_service_cert(cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    let cert = generate_simple_self_signed(vec![format!(
        "{INSTANCE_ID}.{SERVICE_NAME}.{HOSTNAME}.{DOMAIN}"
    )])?;
    fs::write(cert_path, cert.cert.pem()).context("write cert")?;
    fs::write(key_path, cert.signing_key.serialize_pem()).context("write key")?;
    Ok(())
}

fn write_fake_bootroot_agent(root: &Path, exit_code: i32) -> anyhow::Result<()> {
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).context("create bin dir")?;
    let script = format!("#!/bin/sh\nexit {exit_code}\n");
    let script_path = bin_dir.join("bootroot-agent");
    fs::write(&script_path, script).context("write fake bootroot-agent")?;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
        .context("chmod fake bootroot-agent")?;
    Ok(())
}

fn write_fake_pkill(root: &Path, exit_code: i32) -> anyhow::Result<()> {
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).context("create bin dir")?;
    let script = format!("#!/bin/sh\nexit {exit_code}\n");
    let script_path = bin_dir.join("pkill");
    fs::write(&script_path, script).context("write fake pkill")?;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
        .context("chmod fake pkill")?;
    Ok(())
}

async fn stub_service_add_openbao(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": RUNTIME_SERVICE_ADD_ROLE_ID,
            "secret_id": RUNTIME_SERVICE_ADD_SECRET_ID
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": RUNTIME_CLIENT_TOKEN }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/auth"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "approle/": {} }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/sys/policies/acl/{ROLE_NAME}")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/role-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": ROLE_ID }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/secret-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": "secret-initial" }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": {
                    "trusted_ca_sha256": ["11".repeat(32)],
                    "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nLOCAL-TRUST\n-----END CERTIFICATE-----"
                }
            }
        })))
        .mount(server)
        .await;
}

async fn stub_rotate_sequence_openbao(
    server: &MockServer,
    secret_id: &str,
    eab_kid: &str,
    eab_hmac: &str,
) {
    stub_secret_id_rotation_openbao(server, secret_id).await;

    Mock::given(method("POST"))
        .and(path("/acme/acme/eab"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "kid": eab_kid,
            "hmac": eab_hmac
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
}

async fn stub_secret_id_rotation_openbao(server: &MockServer, secret_id: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/secret-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": secret_id }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/role-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": ROLE_ID }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": RUNTIME_CLIENT_TOKEN }
        })))
        .mount(server)
        .await;
}

async fn stub_remote_pull_openbao(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": ROLE_ID,
            "secret_id": "secret-initial"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "remote-token" }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(
            "/v1/secret/data/bootroot/services/edge-proxy/secret_id",
        ))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "secret_id": "secret-updated" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/eab"))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "kid-trust", "hmac": "hmac-trust" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(
            "/v1/secret/data/bootroot/services/edge-proxy/http_responder_hmac",
        ))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "hmac": "responder-trust" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/trust"))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "trusted_ca_sha256": ["22".repeat(32)],
                "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nUPDATED-TRUST\n-----END CERTIFICATE-----"
            } }
        })))
        .mount(server)
        .await;
}

fn assert_mode(path: &Path, expected: u32) {
    let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, expected, "path {}", path.display());
}
