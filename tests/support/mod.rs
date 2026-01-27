// Helper functions are shared across multiple test crates; not every helper is
// referenced in each test module.
#![allow(dead_code)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use rcgen::{CertificateParams, DnType, KeyPair};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub(crate) const ROOT_TOKEN: &str = "root-token";

pub(crate) fn write_fake_docker(dir: &Path) -> Result<PathBuf> {
    write_fake_docker_with_status(dir, "running", "healthy")
}

pub(crate) fn write_fake_docker_with_status(
    dir: &Path,
    status: &str,
    health: &str,
) -> Result<PathBuf> {
    let script = format!(
        r#"#!/bin/sh
set -eu

if [ "${{1:-}}" = "compose" ] && [ "${{2:-}}" = "-f" ] && [ "${{4:-}}" = "ps" ] && [ "${{5:-}}" = "-q" ]; then
  service="${{6:-}}"
  printf "cid-%s" "$service"
  exit 0
fi

if [ "${{1:-}}" = "inspect" ]; then
  printf "{status}|{health}"
  exit 0
fi

exit 0
"#
    );
    let path = dir.join("docker");
    fs::write(&path, script).context("Failed to write fake docker script")?;
    fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
        .context("Failed to set fake docker permissions")?;
    Ok(path)
}

pub(crate) fn create_secrets_dir(root: &Path) -> Result<PathBuf> {
    let secrets_dir = root.join("secrets");
    fs::create_dir_all(secrets_dir.join("config"))
        .context("Failed to create secrets config dir")?;
    fs::create_dir_all(secrets_dir.join("certs")).context("Failed to create certs dir")?;
    fs::create_dir_all(secrets_dir.join("secrets")).context("Failed to create secrets key dir")?;
    fs::write(
        secrets_dir.join("config").join("ca.json"),
        r#"{"db":{"type":"","dataSource":""}}"#,
    )
    .context("Failed to write ca.json")?;
    fs::write(secrets_dir.join("secrets").join("root_ca_key"), "")
        .context("Failed to write root_ca_key")?;
    fs::write(secrets_dir.join("secrets").join("intermediate_ca_key"), "")
        .context("Failed to write intermediate_ca_key")?;
    fs::write(
        secrets_dir.join("certs").join("root_ca.crt"),
        test_cert_pem("root.example"),
    )
    .context("Failed to write root_ca.crt")?;
    fs::write(
        secrets_dir.join("certs").join("intermediate_ca.crt"),
        test_cert_pem("intermediate.example"),
    )
    .context("Failed to write intermediate_ca.crt")?;
    Ok(secrets_dir)
}

fn test_cert_pem(common_name: &str) -> String {
    let mut params = CertificateParams::new(vec![common_name.to_string()]).expect("params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    let key = KeyPair::generate().expect("key pair");
    let cert = params.self_signed(&key).expect("self signed");
    cert.pem()
}

pub(crate) fn write_password_file(secrets_dir: &Path, contents: &str) -> Result<()> {
    fs::write(secrets_dir.join("password.txt"), contents)
        .context("Failed to write password.txt")?;
    Ok(())
}

pub(crate) async fn stub_openbao(server: &MockServer) {
    stub_health(server).await;
    stub_init_status(server).await;
    stub_seal_status(server).await;
    stub_kv_mount(server).await;
    stub_auth_backends(server).await;
    stub_policies(server).await;
    stub_approles(server).await;
    stub_kv_secrets(server).await;
}

pub(crate) async fn stub_openbao_with_write_failure(server: &MockServer, failing_secret: &str) {
    stub_health(server).await;
    stub_init_status(server).await;
    stub_seal_status(server).await;
    stub_kv_mount(server).await;
    stub_auth_backends(server).await;
    stub_policies(server).await;
    stub_approles(server).await;
    stub_kv_secrets_with_failure(server, failing_secret).await;
}

pub(crate) async fn stub_openbao_unseal_failure(server: &MockServer) {
    stub_health(server).await;
    stub_init_status_uninitialized(server).await;
    stub_seal_status_sealed(server).await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "keys": ["key1"],
            "root_token": ROOT_TOKEN
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/unseal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sealed": true
        })))
        .mount(server)
        .await;
}

pub(crate) async fn stub_openbao_sealed(server: &MockServer) {
    stub_health(server).await;
    stub_init_status(server).await;
    stub_seal_status_sealed(server).await;
    stub_unseal_success(server).await;
    stub_kv_mount(server).await;
    stub_auth_backends(server).await;
    stub_policies(server).await;
    stub_approles(server).await;
    stub_kv_secrets(server).await;
}

pub(crate) async fn expect_rollback_deletes(server: &MockServer, include_ca_trust: bool) {
    for policy in ["bootroot-agent", "bootroot-responder", "bootroot-stepca"] {
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/sys/policies/acl/{policy}")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
    }

    for approle in [
        "bootroot-agent-role",
        "bootroot-responder-role",
        "bootroot-stepca-role",
    ] {
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/auth/approle/role/{approle}")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
    }

    let mut secrets = vec![
        "bootroot/stepca/password",
        "bootroot/stepca/db",
        "bootroot/responder/hmac",
    ];
    if include_ca_trust {
        secrets.push("bootroot/ca");
    }
    for secret in secrets {
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/secret/metadata/{secret}")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
    }
}

async fn stub_health(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

async fn stub_init_status(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "initialized": true
        })))
        .mount(server)
        .await;
}

async fn stub_init_status_uninitialized(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "initialized": false
        })))
        .mount(server)
        .await;
}

async fn stub_seal_status(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/seal-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sealed": false
        })))
        .mount(server)
        .await;
}

async fn stub_seal_status_sealed(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/seal-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sealed": true,
            "t": 1
        })))
        .mount(server)
        .await;
}

async fn stub_unseal_success(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/sys/unseal"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sealed": false
        })))
        .mount(server)
        .await;
}

async fn stub_kv_mount(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/mounts/secret"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/mounts/secret"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

async fn stub_auth_backends(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/auth"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {}
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/auth/approle"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

async fn stub_policies(server: &MockServer) {
    for policy in ["bootroot-agent", "bootroot-responder", "bootroot-stepca"] {
        Mock::given(method("GET"))
            .and(path(format!("/v1/sys/policies/acl/{policy}")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(404))
            .mount(server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/v1/sys/policies/acl/{policy}")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
    }
}

async fn stub_approles(server: &MockServer) {
    for approle in [
        "bootroot-agent-role",
        "bootroot-responder-role",
        "bootroot-stepca-role",
    ] {
        Mock::given(method("GET"))
            .and(path(format!("/v1/auth/approle/role/{approle}")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(404))
            .mount(server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/v1/auth/approle/role/{approle}")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;

        Mock::given(method("GET"))
            .and(path(format!("/v1/auth/approle/role/{approle}/role-id")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "role_id": format!("role-{approle}") }
            })))
            .mount(server)
            .await;

        Mock::given(method("POST"))
            .and(path(format!("/v1/auth/approle/role/{approle}/secret-id")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "secret_id": format!("secret-{approle}") }
            })))
            .mount(server)
            .await;
    }
}

async fn stub_kv_secrets(server: &MockServer) {
    for secret in [
        "bootroot/stepca/password",
        "bootroot/stepca/db",
        "bootroot/responder/hmac",
        "bootroot/agent/eab",
        "bootroot/ca",
    ] {
        Mock::given(method("POST"))
            .and(path(format!("/v1/secret/data/{secret}")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
    }
}

async fn stub_kv_secrets_with_failure(server: &MockServer, failing_secret: &str) {
    for secret in [
        "bootroot/stepca/password",
        "bootroot/stepca/db",
        "bootroot/responder/hmac",
        "bootroot/agent/eab",
        "bootroot/ca",
    ] {
        let response = if secret == failing_secret {
            ResponseTemplate::new(500)
        } else {
            ResponseTemplate::new(200)
        };
        Mock::given(method("POST"))
            .and(path(format!("/v1/secret/data/{secret}")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(response)
            .mount(server)
            .await;
    }
}
