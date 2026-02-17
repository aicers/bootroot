#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use rcgen::generate_simple_self_signed;
use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ROOT_TOKEN: &str = "root-token";
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
    stub_control_plane_openbao(&server).await;
    stub_remote_service_secrets(&server).await;

    write_control_state(&control_dir, &server.uri()).expect("write control state");
    prepare_service_node_files(&service_dir).expect("prepare service node files");

    run_service_add_remote(&control_dir, &service_dir).expect("service add remote");
    copy_remote_bootstrap_materials(&control_dir, &service_dir).expect("copy role/secret_id");

    let summary_path = service_dir.join("edge-proxy-summary.json");
    run_remote_sync(&service_dir, &control_dir, &server.uri(), &summary_path).expect("remote sync");

    let control_state = control_dir.join("state.json");
    let control_state_json: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&control_state).expect("read control state"))
            .expect("parse control state");
    assert_eq!(
        control_state_json["services"][SERVICE_NAME]["sync_status"]["secret_id"],
        "applied"
    );
    assert_eq!(
        control_state_json["services"][SERVICE_NAME]["sync_status"]["eab"],
        "applied"
    );
    assert_eq!(
        control_state_json["services"][SERVICE_NAME]["sync_status"]["responder_hmac"],
        "applied"
    );
    assert_eq!(
        control_state_json["services"][SERVICE_NAME]["sync_status"]["trust_sync"],
        "applied"
    );

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
    assert!(agent_contents.contains("trusted_ca_sha256 = ["));
    assert!(agent_contents.contains("[[profiles]]"));
    assert!(agent_contents.contains("service_name = \"edge-proxy\""));
    assert_mode(&secret_id_path, 0o600);
    assert_mode(&eab_path, 0o600);
    assert_mode(&agent_config_path, 0o600);
    assert_mode(&openbao_agent_hcl, 0o600);
    assert_mode(&openbao_agent_template, 0o600);
    assert_mode(&openbao_agent_token, 0o600);

    write_verify_state(&service_dir).expect("write verify state");
    write_cert_for_service(&service_dir).expect("write cert/key");
    write_fake_bootroot_agent(&service_dir).expect("write fake bootroot-agent");
    run_verify(&service_dir).expect("run verify");
}

fn run_service_add_remote(control_dir: &Path, service_dir: &Path) -> anyhow::Result<()> {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(control_dir)
        .args([
            "service",
            "add",
            "--service-name",
            SERVICE_NAME,
            "--deploy-type",
            "daemon",
            "--delivery-mode",
            "remote-bootstrap",
            "--hostname",
            HOSTNAME,
            "--domain",
            DOMAIN,
            "--agent-config",
            service_dir.join("agent.toml").to_string_lossy().as_ref(),
            "--cert-path",
            service_dir
                .join("certs")
                .join("edge-proxy.crt")
                .to_string_lossy()
                .as_ref(),
            "--key-path",
            service_dir
                .join("certs")
                .join("edge-proxy.key")
                .to_string_lossy()
                .as_ref(),
            "--instance-id",
            INSTANCE_ID,
            "--root-token",
            ROOT_TOKEN,
        ])
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
    assert!(stdout.contains("- remote bootstrap file:"));
    assert!(stdout.contains("- remote run command:"));
    Ok(())
}

fn run_remote_sync(
    service_dir: &Path,
    control_dir: &Path,
    openbao_url: &str,
    summary_path: &Path,
) -> anyhow::Result<()> {
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
    let bootroot_proxy = write_bootroot_proxy(service_dir, control_dir)?;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .current_dir(service_dir)
        .args([
            "sync",
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
            "--summary-json",
            summary_path.to_string_lossy().as_ref(),
            "--bootroot-bin",
            bootroot_proxy.to_string_lossy().as_ref(),
            "--retry-attempts",
            "1",
        ])
        .output()
        .context("run bootroot-remote sync")?;
    if !output.status.success() {
        anyhow::bail!(
            "remote sync failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(summary_path.exists());
    Ok(())
}

fn write_bootroot_proxy(service_dir: &Path, control_dir: &Path) -> anyhow::Result<PathBuf> {
    let bin_dir = service_dir.join("bin");
    fs::create_dir_all(&bin_dir).context("create remote bin dir")?;
    let proxy_path = bin_dir.join("bootroot-proxy");
    let script = format!(
        "#!/bin/sh\nset -eu\ncd '{}'\nexec '{}' \"$@\"\n",
        shell_single_quote(control_dir),
        shell_single_quote(Path::new(env!("CARGO_BIN_EXE_bootroot"))),
    );
    fs::write(&proxy_path, script).context("write bootroot proxy")?;
    fs::set_permissions(&proxy_path, fs::Permissions::from_mode(0o700))
        .context("chmod bootroot proxy")?;
    Ok(proxy_path)
}

fn shell_single_quote(path: &Path) -> String {
    path.display().to_string().replace('\'', "'\"'\"'")
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
                "sync_status": {
                    "secret_id": "applied",
                    "eab": "applied",
                    "responder_hmac": "applied",
                    "trust_sync": "applied"
                },
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
    let path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path}", service_dir.join("bin").display());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(service_dir)
        .env("PATH", combined_path)
        .args([
            "verify",
            "--service-name",
            SERVICE_NAME,
            "--agent-config",
            service_dir.join("agent.toml").to_string_lossy().as_ref(),
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
    Mock::given(method("GET"))
        .and(path("/v1/sys/auth"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "approle/": {}
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/sys/policies/acl/{role_name}")))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role_name}")))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{role_name}/role-id")))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": "role-edge-proxy" }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role_name}/secret-id")))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "secret_id": "secret-edge-proxy" }
        })))
        .mount(server)
        .await;
}

async fn stub_control_plane_global_materials(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
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
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "control-kid", "hmac": "control-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
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
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/eab"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(
            "/v1/secret/data/bootroot/services/edge-proxy/http_responder_hmac",
        ))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/trust"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
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
