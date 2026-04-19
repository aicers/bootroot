#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Context;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, generate_simple_self_signed,
};
use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{body_json, header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RUNTIME_SERVICE_ADD_ROLE_ID: &str = "runtime-service-add-role-id";
const RUNTIME_SERVICE_ADD_SECRET_ID: &str = "runtime-service-add-secret-id";
const RUNTIME_CLIENT_TOKEN: &str = "runtime-client-token";
const SERVICE_NAME: &str = "edge-proxy";
const HOSTNAME: &str = "edge-node-02";
const DOMAIN: &str = "trusted.domain";
const INSTANCE_ID: &str = "101";

#[tokio::test]
async fn test_two_node_remote_bootstrap_happy_path() {
    let temp = tempdir().expect("create tempdir");
    let control_dir = temp.path().join("node-a-control");
    let service_dir = temp.path().join("node-b-service");
    fs::create_dir_all(&control_dir).expect("create control dir");
    fs::create_dir_all(&service_dir).expect("create service dir");

    let server = MockServer::start().await;
    stub_control_plane_openbao_no_wrap(&server).await;
    stub_remote_service_secrets(&server).await;

    write_control_state(&control_dir, &server.uri()).expect("write control state");
    prepare_service_node_files(&service_dir).expect("prepare service node files");

    run_service_add_remote_no_wrap(&control_dir, &service_dir).expect("service add remote");
    copy_remote_bootstrap_materials(&control_dir, &service_dir).expect("copy role/secret_id");

    run_remote_bootstrap(&service_dir, &server.uri()).expect("remote bootstrap");

    let secret_id_path = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("secret_id");
    let eab_path = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("eab.json");
    let agent_config_path = service_dir.join("agent.toml");
    assert_eq!(
        fs::read_to_string(&secret_id_path).expect("read secret_id"),
        "remote-secret-id\n"
    );
    let eab_contents = fs::read_to_string(&eab_path).expect("read eab");
    assert!(eab_contents.contains("\"kid\": \"remote-kid\""));
    let agent_contents = fs::read_to_string(&agent_config_path).expect("read agent config");
    let ca_bundle_path = service_dir.join("certs").join("ca-bundle.pem");
    let openbao_agent_dir = service_dir
        .join("secrets")
        .join("openbao")
        .join("services")
        .join(SERVICE_NAME);
    let openbao_agent_hcl = openbao_agent_dir.join("agent.hcl");
    let openbao_agent_template = openbao_agent_dir.join("agent.toml.ctmpl");
    let openbao_agent_token = openbao_agent_dir.join("token");
    assert!(openbao_agent_hcl.exists());
    assert!(openbao_agent_template.exists());
    assert!(openbao_agent_token.exists());
    assert!(agent_contents.contains("http_responder_hmac = \"remote-responder-hmac\""));
    assert!(!agent_contents.contains("verify_certificates"));
    assert!(agent_contents.contains("trusted_ca_sha256 = ["));
    assert!(agent_contents.contains("ca_bundle_path = \""));
    assert!(agent_contents.contains("[[profiles]]"));
    assert!(agent_contents.contains("service_name = \"edge-proxy\""));
    let bundle_contents = fs::read_to_string(&ca_bundle_path).expect("read ca-bundle");
    assert!(bundle_contents.contains("BEGIN CERTIFICATE"));
    assert!(bundle_contents.contains("REMOTE"));
    assert_mode(&secret_id_path, 0o600);
    assert_mode(&eab_path, 0o600);
    assert_mode(&agent_config_path, 0o600);
    assert_mode(&ca_bundle_path, 0o600);
    assert_mode(&openbao_agent_hcl, 0o600);
    assert_mode(&openbao_agent_template, 0o600);
    assert_mode(&openbao_agent_token, 0o600);

    write_verify_state(&service_dir).expect("write verify state");
    write_cert_for_service(&service_dir).expect("write cert/key");
    write_fake_bootroot_agent(&service_dir).expect("write fake bootroot-agent");
    run_verify(&service_dir).expect("run verify");
}

fn run_service_add_remote(control_dir: &Path, service_dir: &Path) -> anyhow::Result<()> {
    run_service_add_remote_impl(control_dir, service_dir, false)
}

fn run_service_add_remote_no_wrap(control_dir: &Path, service_dir: &Path) -> anyhow::Result<()> {
    run_service_add_remote_impl(control_dir, service_dir, true)
}

fn run_service_add_remote_impl(
    control_dir: &Path,
    service_dir: &Path,
    no_wrap: bool,
) -> anyhow::Result<()> {
    let mut args = vec![
        "service".to_string(),
        "add".to_string(),
        "--service-name".to_string(),
        SERVICE_NAME.to_string(),
        "--deploy-type".to_string(),
        "daemon".to_string(),
        "--delivery-mode".to_string(),
        "remote-bootstrap".to_string(),
        "--hostname".to_string(),
        HOSTNAME.to_string(),
        "--domain".to_string(),
        DOMAIN.to_string(),
        "--agent-config".to_string(),
        service_dir.join("agent.toml").to_string_lossy().to_string(),
        "--cert-path".to_string(),
        service_dir
            .join("certs")
            .join("edge-proxy.crt")
            .to_string_lossy()
            .to_string(),
        "--key-path".to_string(),
        service_dir
            .join("certs")
            .join("edge-proxy.key")
            .to_string_lossy()
            .to_string(),
        "--instance-id".to_string(),
        INSTANCE_ID.to_string(),
        "--auth-mode".to_string(),
        "approle".to_string(),
        "--approle-role-id".to_string(),
        RUNTIME_SERVICE_ADD_ROLE_ID.to_string(),
        "--approle-secret-id".to_string(),
        RUNTIME_SERVICE_ADD_SECRET_ID.to_string(),
    ];
    if no_wrap {
        args.push("--no-wrap".to_string());
    }
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(control_dir)
        .args(&args)
        .output()
        .context("run bootroot service add")?;
    if !output.status.success() {
        anyhow::bail!(
            "service add failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("bootroot service add: summary"));
    assert!(stdout.contains("- remote bootstrap file (machine-readable artifact for automation):"));
    assert!(stdout.contains("- remote run command template:"));
    Ok(())
}

fn run_remote_bootstrap(service_dir: &Path, openbao_url: &str) -> anyhow::Result<()> {
    let role_id_path = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("role_id");
    let secret_id_path = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("secret_id");
    let eab_file_path = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("eab.json");
    let agent_config_path = service_dir.join("agent.toml");
    let ca_bundle_path = service_dir.join("certs").join("ca-bundle.pem");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .current_dir(service_dir)
        .args([
            "bootstrap",
            "--openbao-url",
            openbao_url,
            "--kv-mount",
            "secret",
            "--service-name",
            SERVICE_NAME,
            "--role-id-path",
            role_id_path.to_string_lossy().as_ref(),
            "--secret-id-path",
            secret_id_path.to_string_lossy().as_ref(),
            "--eab-file-path",
            eab_file_path.to_string_lossy().as_ref(),
            "--agent-config-path",
            agent_config_path.to_string_lossy().as_ref(),
            "--agent-email",
            "admin@example.com",
            "--agent-server",
            "https://localhost:9000/acme/acme/directory",
            "--agent-domain",
            DOMAIN,
            "--agent-responder-url",
            "http://127.0.0.1:8080",
            "--profile-hostname",
            HOSTNAME,
            "--profile-instance-id",
            INSTANCE_ID,
            "--profile-cert-path",
            service_dir
                .join("certs")
                .join("edge-proxy.crt")
                .to_string_lossy()
                .as_ref(),
            "--profile-key-path",
            service_dir
                .join("certs")
                .join("edge-proxy.key")
                .to_string_lossy()
                .as_ref(),
            "--ca-bundle-path",
            ca_bundle_path.to_string_lossy().as_ref(),
        ])
        .output()
        .context("run bootroot-remote bootstrap")?;
    if !output.status.success() {
        anyhow::bail!(
            "remote bootstrap failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn write_control_state(root: &Path, openbao_url: &str) -> anyhow::Result<()> {
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

fn prepare_service_node_files(root: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(root.join("secrets").join("services").join(SERVICE_NAME))
        .context("create service secret dir")?;
    fs::create_dir_all(root.join("certs")).context("create cert dir")?;
    Ok(())
}

fn copy_remote_bootstrap_materials(control_dir: &Path, service_dir: &Path) -> anyhow::Result<()> {
    let control_service_dir = control_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME);
    let service_secret_dir = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME);
    fs::create_dir_all(&service_secret_dir).context("create service secret dir")?;
    fs::copy(
        control_service_dir.join("role_id"),
        service_secret_dir.join("role_id"),
    )
    .context("copy role_id")?;
    fs::copy(
        control_service_dir.join("secret_id"),
        service_secret_dir.join("secret_id"),
    )
    .context("copy secret_id")?;
    Ok(())
}

fn write_verify_state(service_dir: &Path) -> anyhow::Result<()> {
    let state = json!({
        "openbao_url": "http://localhost:8200",
        "kv_mount": "secret",
        "services": {
            SERVICE_NAME: {
                "service_name": SERVICE_NAME,
                "deploy_type": "daemon",
                "delivery_mode": "remote-bootstrap",
                "hostname": HOSTNAME,
                "domain": DOMAIN,
                "agent_config_path": service_dir.join("agent.toml"),
                "cert_path": service_dir.join("certs").join("edge-proxy.crt"),
                "key_path": service_dir.join("certs").join("edge-proxy.key"),
                "instance_id": INSTANCE_ID,
                "notes": null,
                "approle": {
                    "role_name": format!("bootroot-service-{SERVICE_NAME}"),
                    "role_id": "role-edge-proxy",
                    "secret_id_path": service_dir.join("secrets").join("services").join(SERVICE_NAME).join("secret_id"),
                    "policy_name": format!("bootroot-service-{SERVICE_NAME}")
                }
            }
        }
    });
    fs::write(
        service_dir.join("state.json"),
        serde_json::to_string_pretty(&state)?,
    )
    .context("write verify state")?;
    Ok(())
}

fn write_cert_for_service(service_dir: &Path) -> anyhow::Result<()> {
    let cert = generate_simple_self_signed(vec![format!(
        "{INSTANCE_ID}.{SERVICE_NAME}.{HOSTNAME}.{DOMAIN}"
    )])?;
    let cert_path = service_dir.join("certs").join("edge-proxy.crt");
    let key_path = service_dir.join("certs").join("edge-proxy.key");
    fs::write(&cert_path, cert.cert.pem()).context("write cert")?;
    fs::write(&key_path, cert.signing_key.serialize_pem()).context("write key")?;
    Ok(())
}

fn write_fake_bootroot_agent(service_dir: &Path) -> anyhow::Result<()> {
    let bin_dir = service_dir.join("bin");
    fs::create_dir_all(&bin_dir).context("create bin dir")?;
    let script = "#!/bin/sh\nexit 0\n";
    fs::write(bin_dir.join("bootroot-agent"), script).context("write fake bootroot-agent")?;
    fs::set_permissions(
        bin_dir.join("bootroot-agent"),
        fs::Permissions::from_mode(0o700),
    )
    .context("chmod fake bootroot-agent")?;
    Ok(())
}

fn run_verify(service_dir: &Path) -> anyhow::Result<()> {
    let agent_binary = service_dir.join("bin").join("bootroot-agent");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(service_dir)
        .args([
            "verify",
            "--service-name",
            SERVICE_NAME,
            "--agent-config",
            service_dir.join("agent.toml").to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .context("run verify")?;
    if !output.status.success() {
        anyhow::bail!("verify failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("- result: ok"));
    Ok(())
}

fn assert_mode(path: &Path, expected: u32) {
    let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, expected, "path {}", path.display());
}

async fn stub_control_plane_openbao(server: &MockServer) {
    let role_name = format!("bootroot-service-{SERVICE_NAME}");
    stub_control_plane_approle(server, &role_name).await;
    stub_control_plane_global_materials(server).await;
    stub_control_plane_service_material_writes(server).await;
}

async fn stub_control_plane_approle(server: &MockServer, role_name: &str) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": RUNTIME_SERVICE_ADD_ROLE_ID,
            "secret_id": RUNTIME_SERVICE_ADD_SECRET_ID
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": {
                "client_token": RUNTIME_CLIENT_TOKEN
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/auth"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "approle/": {}
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/sys/policies/acl/{role_name}")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role_name}")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{role_name}/role-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": "role-edge-proxy" }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role_name}/secret-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .and(header_exists("X-Vault-Wrap-TTL"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": "wrap-token-edge-proxy",
                "ttl": 1800,
                "creation_time": "2026-04-12T00:00:00Z",
                "creation_path": format!("auth/approle/role/{role_name}/secret-id")
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(header("X-Vault-Token", "wrap-token-edge-proxy"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "secret_id": "secret-edge-proxy",
                "secret_id_accessor": "acc"
            }
        })))
        .mount(server)
        .await;
}

async fn stub_control_plane_openbao_no_wrap(server: &MockServer) {
    let role_name = format!("bootroot-service-{SERVICE_NAME}");
    stub_control_plane_approle_no_wrap(server, &role_name).await;
    stub_control_plane_global_materials(server).await;
    stub_control_plane_service_material_writes(server).await;
}

async fn stub_control_plane_approle_no_wrap(server: &MockServer, role_name: &str) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": RUNTIME_SERVICE_ADD_ROLE_ID,
            "secret_id": RUNTIME_SERVICE_ADD_SECRET_ID
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": {
                "client_token": RUNTIME_CLIENT_TOKEN
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/auth"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "approle/": {}
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/sys/policies/acl/{role_name}")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role_name}")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{role_name}/role-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": "role-edge-proxy" }
        })))
        .mount(server)
        .await;

    // Non-wrapped secret-id creation (no X-Vault-Wrap-TTL header).
    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role_name}/secret-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "secret_id": "secret-edge-proxy",
                "secret_id_accessor": "acc"
            }
        })))
        .mount(server)
        .await;
}

async fn stub_control_plane_global_materials(server: &MockServer) {
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
                    "trusted_ca_sha256": ["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"],
                    "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nCONTROL\n-----END CERTIFICATE-----"
                }
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "control-kid", "hmac": "control-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "value": "control-responder-hmac" } }
        })))
        .mount(server)
        .await;
}

async fn stub_control_plane_service_material_writes(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path(
            "/v1/secret/data/bootroot/services/edge-proxy/secret_id",
        ))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/eab"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/secret/data/bootroot/services/edge-proxy/http_responder_hmac",
        ))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/trust"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

fn copy_bootstrap_artifact_and_role_id(
    control_dir: &Path,
    service_dir: &Path,
) -> anyhow::Result<()> {
    let control_service_dir = control_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME);
    let service_secret_dir = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME);
    fs::create_dir_all(&service_secret_dir).context("create service secret dir")?;
    fs::copy(
        control_service_dir.join("role_id"),
        service_secret_dir.join("role_id"),
    )
    .context("copy role_id")?;

    let artifact_dir = control_dir
        .join("secrets")
        .join("remote-bootstrap")
        .join("services")
        .join(SERVICE_NAME);
    let artifact_path = artifact_dir.join("bootstrap.json");
    let dest_artifact = service_dir.join("bootstrap.json");
    fs::copy(&artifact_path, &dest_artifact).context("copy bootstrap artifact")?;
    Ok(())
}

fn run_remote_bootstrap_with_artifact(
    service_dir: &Path,
    _openbao_url: &str,
) -> anyhow::Result<()> {
    let artifact_path = service_dir.join("bootstrap.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .current_dir(service_dir)
        .args([
            "bootstrap",
            "--artifact",
            artifact_path.to_string_lossy().as_ref(),
        ])
        .output()
        .context("run bootroot-remote bootstrap --artifact")?;
    if !output.status.success() {
        anyhow::bail!(
            "remote bootstrap --artifact failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_remote_bootstrap_artifact_invocation() {
    let temp = tempdir().expect("create tempdir");
    let control_dir = temp.path().join("artifact-control");
    let service_dir = temp.path().join("artifact-service");
    fs::create_dir_all(&control_dir).expect("create control dir");
    fs::create_dir_all(&service_dir).expect("create service dir");

    let server = MockServer::start().await;
    stub_control_plane_openbao(&server).await;
    stub_remote_service_secrets(&server).await;

    write_control_state(&control_dir, &server.uri()).expect("write control state");
    prepare_service_node_files(&service_dir).expect("prepare service node files");

    run_service_add_remote(&control_dir, &service_dir).expect("service add remote");
    copy_bootstrap_artifact_and_role_id(&control_dir, &service_dir)
        .expect("copy artifact + role_id");

    // Verify the artifact contains wrap_token
    let artifact_contents =
        fs::read_to_string(service_dir.join("bootstrap.json")).expect("read artifact");
    assert!(
        artifact_contents.contains("wrap_token"),
        "artifact should contain wrap_token"
    );
    assert!(
        artifact_contents.contains("wrap_expires_at"),
        "artifact should contain wrap_expires_at"
    );

    run_remote_bootstrap_with_artifact(&service_dir, &server.uri())
        .expect("remote bootstrap via artifact");

    let secret_id_path = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("secret_id");
    assert!(
        secret_id_path.exists(),
        "secret_id should be written after unwrap"
    );
    let eab_path = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("eab.json");
    assert!(eab_path.exists(), "eab should be written after bootstrap");
}

#[tokio::test]
async fn test_remote_bootstrap_expired_wrap_token() {
    let temp = tempdir().expect("create tempdir");
    let service_dir = temp.path().join("expired-service");
    fs::create_dir_all(&service_dir).expect("create service dir");

    let server = MockServer::start().await;
    stub_remote_service_secrets(&server).await;

    // Stub an unwrap failure
    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "errors": ["wrapping token is not valid or does not exist"]
        })))
        .mount(&server)
        .await;

    prepare_service_node_files(&service_dir).expect("prepare service node files");
    let role_id_path = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("role_id");
    fs::write(&role_id_path, "role-edge-proxy").expect("write role_id");

    // Create a fake artifact with an EXPIRED wrap token
    let artifact = json!({
        "schema_version": 1,
        "openbao_url": server.uri(),
        "kv_mount": "secret",
        "service_name": SERVICE_NAME,
        "role_id_path": role_id_path.to_string_lossy(),
        "secret_id_path": service_dir.join("secrets").join("services").join(SERVICE_NAME).join("secret_id").to_string_lossy(),
        "eab_file_path": service_dir.join("secrets").join("services").join(SERVICE_NAME).join("eab.json").to_string_lossy(),
        "agent_config_path": service_dir.join("agent.toml").to_string_lossy(),
        "ca_bundle_path": service_dir.join("certs").join("ca-bundle.pem").to_string_lossy(),
        "agent_email": "admin@example.com",
        "agent_server": "https://localhost:9000/acme/acme/directory",
        "agent_domain": "trusted.domain",
        "agent_responder_url": "http://127.0.0.1:8080",
        "profile_hostname": HOSTNAME,
        "profile_instance_id": INSTANCE_ID,
        "profile_cert_path": "",
        "profile_key_path": "",
        "openbao_agent_config_path": "",
        "openbao_agent_template_path": "",
        "openbao_agent_token_path": "",
        "wrap_token": "expired-token",
        "wrap_expires_at": "2020-01-01T00:00:00Z"
    });
    let artifact_path = service_dir.join("bootstrap.json");
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).unwrap(),
    )
    .expect("write artifact");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .current_dir(&service_dir)
        .args([
            "bootstrap",
            "--artifact",
            artifact_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run bootroot-remote");

    assert!(
        !output.status.success(),
        "should fail with expired wrap token"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("expired"),
        "should mention expiration: {stderr}"
    );
    assert!(
        stderr.contains("bootroot service add"),
        "should include recovery command: {stderr}"
    );
}

#[tokio::test]
async fn test_remote_bootstrap_already_unwrapped_token() {
    let temp = tempdir().expect("create tempdir");
    let service_dir = temp.path().join("unwrapped-service");
    fs::create_dir_all(&service_dir).expect("create service dir");

    let server = MockServer::start().await;

    // Stub an unwrap failure (token already used)
    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "errors": ["wrapping token is not valid or does not exist"]
        })))
        .mount(&server)
        .await;

    prepare_service_node_files(&service_dir).expect("prepare service node files");
    let role_id_path = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME)
        .join("role_id");
    fs::write(&role_id_path, "role-edge-proxy").expect("write role_id");

    // Create a fake artifact with a NOT-YET-EXPIRED wrap token (far future)
    let artifact = json!({
        "schema_version": 1,
        "openbao_url": server.uri(),
        "kv_mount": "secret",
        "service_name": SERVICE_NAME,
        "role_id_path": role_id_path.to_string_lossy(),
        "secret_id_path": service_dir.join("secrets").join("services").join(SERVICE_NAME).join("secret_id").to_string_lossy(),
        "eab_file_path": service_dir.join("secrets").join("services").join(SERVICE_NAME).join("eab.json").to_string_lossy(),
        "agent_config_path": service_dir.join("agent.toml").to_string_lossy(),
        "ca_bundle_path": service_dir.join("certs").join("ca-bundle.pem").to_string_lossy(),
        "agent_email": "admin@example.com",
        "agent_server": "https://localhost:9000/acme/acme/directory",
        "agent_domain": "trusted.domain",
        "agent_responder_url": "http://127.0.0.1:8080",
        "profile_hostname": HOSTNAME,
        "profile_instance_id": INSTANCE_ID,
        "profile_cert_path": "",
        "profile_key_path": "",
        "openbao_agent_config_path": "",
        "openbao_agent_template_path": "",
        "openbao_agent_token_path": "",
        "wrap_token": "already-used-token",
        "wrap_expires_at": "2099-12-31T23:59:59Z"
    });
    let artifact_path = service_dir.join("bootstrap.json");
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).unwrap(),
    )
    .expect("write artifact");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .current_dir(&service_dir)
        .args([
            "bootstrap",
            "--artifact",
            artifact_path.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run bootroot-remote");

    assert!(
        !output.status.success(),
        "should fail with already-unwrapped token"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("SECURITY INCIDENT"),
        "should flag security incident: {stderr}"
    );
    assert!(
        stderr.contains("bootroot rotate approle-secret-id"),
        "should include rotate recovery command: {stderr}"
    );
    assert!(
        stderr.contains("bootroot service add"),
        "should include service-add step to mint fresh wrap token: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// TLS test infrastructure — CA generation and minimal HTTPS mock server
// ---------------------------------------------------------------------------

struct TestCa {
    cert: rcgen::Certificate,
    issuer: Issuer<'static, KeyPair>,
}

struct TlsServerCert {
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
}

impl TestCa {
    fn generate() -> Self {
        let key = KeyPair::generate().expect("generate CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("cert params");
        params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-signed CA");
        let issuer = Issuer::new(params, key);
        Self { cert, issuer }
    }

    fn pem(&self) -> String {
        self.cert.pem()
    }

    fn sign_server_cert(&self) -> TlsServerCert {
        let key = KeyPair::generate().expect("generate server key");
        let mut params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("cert params");
        params
            .distinguished_name
            .push(DnType::CommonName, "localhost");
        params.is_ca = IsCa::NoCa;
        let cert = params
            .signed_by(&key, &self.issuer)
            .expect("signed server cert");
        TlsServerCert {
            cert_der: cert.der().to_vec(),
            key_der: key.serialize_der(),
        }
    }
}

/// Routes an HTTP request path to a canned `OpenBao` JSON response.
fn openbao_route(request_path: &str) -> (u16, String) {
    let body = match request_path {
        "/v1/auth/approle/login" => json!({
            "auth": { "client_token": "tls-token" }
        }),
        "/v1/secret/data/bootroot/services/edge-proxy/secret_id" => json!({
            "data": { "data": { "secret_id": "tls-secret-id" } }
        }),
        "/v1/secret/data/bootroot/services/edge-proxy/eab" => json!({
            "data": { "data": { "kid": "tls-kid", "hmac": "tls-hmac" } }
        }),
        "/v1/secret/data/bootroot/services/edge-proxy/http_responder_hmac" => json!({
            "data": { "data": { "hmac": "tls-responder-hmac" } }
        }),
        "/v1/secret/data/bootroot/services/edge-proxy/trust" => json!({
            "data": { "data": {
                "trusted_ca_sha256": ["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"],
                "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nTLS-MOCK\n-----END CERTIFICATE-----"
            } }
        }),
        _ => return (404, r#"{"errors":["not found"]}"#.to_string()),
    };
    (200, body.to_string())
}

/// Starts a minimal HTTPS server that routes requests to canned `OpenBao`
/// responses.  Returns the port on `127.0.0.1`.
async fn start_openbao_tls_mock(server_cert: TlsServerCert) -> u16 {
    use std::sync::Arc;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    let _ = rustls::crypto::ring::default_provider().install_default();
    let cert = CertificateDer::from(server_cert.cert_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(server_cert.key_der));

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server TLS config");

    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("local addr").port();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(stream).await else {
                    return;
                };
                let mut buf = vec![0u8; 8192];
                let n = tls.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]);
                let request_path = request
                    .lines()
                    .next()
                    .and_then(|l| l.split_whitespace().nth(1))
                    .unwrap_or("/");
                let (status, body) = openbao_route(request_path);
                let status_text = if status == 200 { "OK" } else { "Not Found" };
                let response = format!(
                    "HTTP/1.1 {status} {status_text}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n\
                     {body}",
                    body.len()
                );
                let _ = tls.write_all(response.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    port
}

/// Proves that `bootroot-remote bootstrap --artifact` with an HTTPS
/// `openbao_url` succeeds when the artifact-embedded CA matches the
/// server's issuer.  This exercises the full bootstrap code path
/// (`build_openbao_client` → `OpenBaoClient::with_pem_trust` → TLS
/// handshake → `AppRole` login → secret reads) over a real TLS connection.
#[tokio::test]
async fn test_remote_bootstrap_https_with_artifact_ca() {
    let ca = TestCa::generate();
    let server_cert = ca.sign_server_cert();
    let port = start_openbao_tls_mock(server_cert).await;

    let temp = tempdir().expect("create tempdir");
    let service_dir = temp.path().join("tls-service");
    fs::create_dir_all(&service_dir).expect("create service dir");
    prepare_service_node_files(&service_dir).expect("prepare service node files");

    let service_secrets = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME);
    let role_id_path = service_secrets.join("role_id");
    let secret_id_path = service_secrets.join("secret_id");
    fs::write(&role_id_path, "role-edge-proxy").expect("write role_id");
    fs::write(&secret_id_path, "secret-edge-proxy").expect("write secret_id");

    let openbao_agent_dir = service_dir
        .join("secrets")
        .join("openbao")
        .join("services")
        .join(SERVICE_NAME);

    let artifact = json!({
        "schema_version": 2,
        "openbao_url": format!("https://localhost:{port}"),
        "kv_mount": "secret",
        "service_name": SERVICE_NAME,
        "role_id_path": role_id_path.to_string_lossy(),
        "secret_id_path": secret_id_path.to_string_lossy(),
        "eab_file_path": service_secrets.join("eab.json").to_string_lossy(),
        "agent_config_path": service_dir.join("agent.toml").to_string_lossy(),
        "ca_bundle_path": service_dir.join("certs").join("ca-bundle.pem").to_string_lossy(),
        "ca_bundle_pem": ca.pem(),
        "openbao_agent_config_path": openbao_agent_dir.join("agent.hcl").to_string_lossy(),
        "openbao_agent_template_path": openbao_agent_dir.join("agent.toml.ctmpl").to_string_lossy(),
        "openbao_agent_token_path": openbao_agent_dir.join("token").to_string_lossy(),
        "agent_email": "admin@example.com",
        "agent_server": "https://localhost:9000/acme/acme/directory",
        "agent_domain": DOMAIN,
        "agent_responder_url": "http://127.0.0.1:8080",
        "profile_hostname": HOSTNAME,
        "profile_instance_id": INSTANCE_ID,
        "profile_cert_path": service_dir.join("certs").join("edge-proxy.crt").to_string_lossy(),
        "profile_key_path": service_dir.join("certs").join("edge-proxy.key").to_string_lossy(),
    });
    let artifact_path = service_dir.join("bootstrap.json");
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).unwrap(),
    )
    .expect("write artifact");

    // Use tokio::process so the child process does not block the tokio
    // thread — the TLS mock server is a tokio task on the same runtime.
    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .current_dir(&service_dir)
        .arg("bootstrap")
        .arg("--artifact")
        .arg(&artifact_path)
        .output()
        .await
        .expect("run bootroot-remote");

    assert!(
        output.status.success(),
        "HTTPS bootstrap should succeed with artifact CA: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Verify secrets were written through the TLS-protected path.
    let written_secret = fs::read_to_string(&secret_id_path).expect("read secret_id");
    assert_eq!(written_secret.trim(), "tls-secret-id");
}

/// Proves that `bootroot-remote bootstrap --artifact` with an HTTPS
/// `openbao_url` fails when the artifact carries a CA that did not issue
/// the server certificate.  This confirms the bootstrap path does not
/// fall back to the system trust store.
#[tokio::test]
async fn test_remote_bootstrap_https_rejects_wrong_ca() {
    let ca = TestCa::generate();
    let wrong_ca = TestCa::generate();
    let server_cert = ca.sign_server_cert();
    let port = start_openbao_tls_mock(server_cert).await;

    let temp = tempdir().expect("create tempdir");
    let service_dir = temp.path().join("tls-wrong-ca");
    fs::create_dir_all(&service_dir).expect("create service dir");
    prepare_service_node_files(&service_dir).expect("prepare service node files");

    let service_secrets = service_dir
        .join("secrets")
        .join("services")
        .join(SERVICE_NAME);
    let role_id_path = service_secrets.join("role_id");
    let secret_id_path = service_secrets.join("secret_id");
    fs::write(&role_id_path, "role-edge-proxy").expect("write role_id");
    fs::write(&secret_id_path, "secret-edge-proxy").expect("write secret_id");

    let openbao_agent_dir = service_dir
        .join("secrets")
        .join("openbao")
        .join("services")
        .join(SERVICE_NAME);

    // Embed the WRONG CA — the server cert was signed by `ca`, not `wrong_ca`.
    let artifact = json!({
        "schema_version": 2,
        "openbao_url": format!("https://localhost:{port}"),
        "kv_mount": "secret",
        "service_name": SERVICE_NAME,
        "role_id_path": role_id_path.to_string_lossy(),
        "secret_id_path": secret_id_path.to_string_lossy(),
        "eab_file_path": service_secrets.join("eab.json").to_string_lossy(),
        "agent_config_path": service_dir.join("agent.toml").to_string_lossy(),
        "ca_bundle_path": service_dir.join("certs").join("ca-bundle.pem").to_string_lossy(),
        "ca_bundle_pem": wrong_ca.pem(),
        "openbao_agent_config_path": openbao_agent_dir.join("agent.hcl").to_string_lossy(),
        "openbao_agent_template_path": openbao_agent_dir.join("agent.toml.ctmpl").to_string_lossy(),
        "openbao_agent_token_path": openbao_agent_dir.join("token").to_string_lossy(),
        "agent_email": "admin@example.com",
        "agent_server": "https://localhost:9000/acme/acme/directory",
        "agent_domain": DOMAIN,
        "agent_responder_url": "http://127.0.0.1:8080",
        "profile_hostname": HOSTNAME,
        "profile_instance_id": INSTANCE_ID,
        "profile_cert_path": service_dir.join("certs").join("edge-proxy.crt").to_string_lossy(),
        "profile_key_path": service_dir.join("certs").join("edge-proxy.key").to_string_lossy(),
    });
    let artifact_path = service_dir.join("bootstrap.json");
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&artifact).unwrap(),
    )
    .expect("write artifact");

    let output = tokio::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .current_dir(&service_dir)
        .arg("bootstrap")
        .arg("--artifact")
        .arg(&artifact_path)
        .output()
        .await
        .expect("run bootroot-remote");

    assert!(
        !output.status.success(),
        "HTTPS bootstrap should fail with wrong CA"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    // The exact error text depends on the TLS stack; check that bootstrap
    // fails on the login request (which is the first network call).
    assert!(
        stderr.contains("TLS")
            || stderr.contains("certificate")
            || stderr.contains("login failed")
            || stderr.contains("request failed"),
        "error should indicate connection/TLS failure: {stderr}"
    );
}

async fn stub_remote_service_secrets(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
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
            "data": { "data": { "secret_id": "remote-secret-id" } }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/eab"))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "remote-kid", "hmac": "remote-hmac" } }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(
            "/v1/secret/data/bootroot/services/edge-proxy/http_responder_hmac",
        ))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "hmac": "remote-responder-hmac" } }
        })))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/trust"))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "trusted_ca_sha256": ["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"],
                "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\nREMOTE\n-----END CERTIFICATE-----"
            } }
        })))
        .mount(server)
        .await;
}
