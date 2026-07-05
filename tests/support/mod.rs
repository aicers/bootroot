// Helper functions are shared across multiple test crates; not every helper is
// referenced in each test module.
#![allow(dead_code)]

pub(crate) mod docker_harness;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{Context, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde_json::json;
use wiremock::matchers::{header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

pub(crate) const ROOT_TOKEN: &str = "root-token";
const POLICY_NAMES: &[&str] = &[
    "bootroot-agent",
    "bootroot-responder",
    "bootroot-stepca",
    "bootroot-runtime-service-add",
    "bootroot-runtime-rotate",
    "bootroot-infra-rotate",
];
const APPROLE_NAMES: &[&str] = &[
    "bootroot-agent-role",
    "bootroot-responder-role",
    "bootroot-stepca-role",
    "bootroot-runtime-service-add-role",
    "bootroot-runtime-rotate-role",
    "bootroot-infra-rotate-role",
];

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
        r#"{
            "authority":{"provisioners":[{"type":"ACME","name":"acme"}]},
            "db":{"type":"","dataSource":""}
        }"#,
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

/// Returns a process-wide consistent `(ca_bundle_pem, sha256_fingerprint)`
/// pair so test stubs that hand out trust material on multiple endpoints
/// (e.g. control-plane CA + remote-bootstrap trust) stay self-consistent.
/// `bootroot verify`'s post-issuance bundle-fingerprint check (#622)
/// fails when the agent.toml's `trusted_ca_sha256` does not match every
/// cert in `ca-bundle.pem`, so reusing the same generated cert across
/// stubs keeps the e2e verify path green.
///
/// Since #627 the CA is generated with `BasicConstraints cA=TRUE` and
/// `keyCertSign`, and the keypair is retained inside [`test_ca_state`]
/// so callers can use [`sign_test_leaf`] to issue a leaf that
/// chain-verifies against this bundle.
pub(crate) fn test_trust_material() -> &'static (String, String) {
    static MATERIAL: OnceLock<(String, String)> = OnceLock::new();
    MATERIAL.get_or_init(|| {
        let state = test_ca_state();
        let pem = state.ca_pem.clone();
        let (_, parsed) =
            x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("parse generated ca pem");
        let digest = ring::digest::digest(&ring::digest::SHA256, &parsed.contents);
        let mut hex = String::with_capacity(64);
        for byte in digest.as_ref() {
            use std::fmt::Write as _;
            let _ = write!(&mut hex, "{byte:02x}");
        }
        (pem, hex)
    })
}

/// Holds the persistent test CA's PEM cert plus the serialized signing
/// key so [`sign_test_leaf`] can deserialize it on demand. The keypair
/// is generated once per process; subsequent calls reuse the same
/// material to keep `test_trust_material`'s fingerprint stable across
/// stubs.
pub(crate) struct TestCaState {
    pub ca_pem: String,
    ca_key_pem: String,
}

pub(crate) fn test_ca_state() -> &'static TestCaState {
    static STATE: OnceLock<TestCaState> = OnceLock::new();
    STATE.get_or_init(|| {
        let key = KeyPair::generate().expect("ca key pair");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params
            .distinguished_name
            .push(DnType::CommonName, "bootroot-test-ca");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let cert = params.self_signed(&key).expect("ca self signed");
        TestCaState {
            ca_pem: cert.pem(),
            ca_key_pem: key.serialize_pem(),
        }
    })
}

/// Issues a leaf signed by [`test_ca_state`]'s CA so the on-disk pair
/// chain-verifies against `test_trust_material()`'s bundle. Used by
/// service-add unit tests that exercise the full `bootroot verify`
/// path, which since #627 enforces leaf-to-bundle chaining.
pub(crate) fn sign_test_leaf(dns_name: &str) -> (String, String) {
    let state = test_ca_state();
    let ca_key = KeyPair::from_pem(&state.ca_key_pem).expect("reload ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "bootroot-test-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let mut leaf_params = CertificateParams::new(vec![dns_name.to_string()]).expect("leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, dns_name);
    let leaf_key = KeyPair::generate().expect("leaf key pair");
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca_issuer)
        .expect("sign leaf with test CA");
    (leaf.pem(), leaf_key.serialize_pem())
}

pub(crate) fn write_password_file(secrets_dir: &Path, contents: &str) -> Result<()> {
    fs::write(secrets_dir.join("password.txt"), contents)
        .context("Failed to write password.txt")?;
    Ok(())
}

/// Writes a `.env` file with test DB credentials, matching the format
/// produced by `infra install`.
pub(crate) fn write_dotenv_file(root: &Path) -> Result<()> {
    let content = "POSTGRES_USER=step\nPOSTGRES_PASSWORD=test-bootstrap-pass\nPOSTGRES_DB=stepca\n";
    fs::write(root.join(".env"), content).context("Failed to write .env file")?;
    Ok(())
}

pub(crate) async fn stub_openbao(server: &MockServer) {
    stub_health(server).await;
    stub_init_status(server).await;
    stub_seal_status(server).await;
    stub_kv_mount(server).await;
    stub_auth_backends(server).await;
    stub_audit_backend(server).await;
    stub_policies(server).await;
    stub_approles(server).await;
    stub_kv_secrets(server).await;
}

pub(crate) async fn stub_openbao_expect_audit(server: &MockServer) {
    stub_health(server).await;
    stub_init_status(server).await;
    stub_seal_status(server).await;
    stub_kv_mount(server).await;
    stub_auth_backends(server).await;
    stub_audit_backend_expected(server).await;
    stub_policies(server).await;
    stub_approles(server).await;
    stub_kv_secrets(server).await;
}

pub(crate) async fn stub_openbao_audit_failure(server: &MockServer) {
    stub_health(server).await;
    stub_init_status(server).await;
    stub_seal_status(server).await;
    stub_kv_mount(server).await;
    stub_auth_backends(server).await;
    stub_audit_backend_failure(server).await;
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
    stub_audit_backend(server).await;
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
    stub_audit_backend(server).await;
    stub_policies(server).await;
    stub_approles(server).await;
    stub_kv_secrets(server).await;
}

pub(crate) async fn expect_rollback_deletes(server: &MockServer, include_ca_trust: bool) {
    for policy in POLICY_NAMES {
        Mock::given(method("DELETE"))
            .and(path(format!("/v1/sys/policies/acl/{policy}")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
    }

    for approle in APPROLE_NAMES {
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

async fn stub_audit_backend(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/audit"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "file/": {
                    "type": "file",
                    "options": { "file_path": "/openbao/audit/audit.log" }
                }
            }
        })))
        .mount(server)
        .await;
}

async fn stub_audit_backend_expected(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/audit"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "file/": {
                    "type": "file",
                    "options": { "file_path": "/openbao/audit/audit.log" }
                }
            }
        })))
        .expect(1)
        .mount(server)
        .await;
}

async fn stub_audit_backend_failure(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/audit"))
        .and(header("X-Vault-Token", ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {}
        })))
        .mount(server)
        .await;
}

async fn stub_policies(server: &MockServer) {
    for policy in POLICY_NAMES {
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
    for approle in APPROLE_NAMES {
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

        // Non-wrapped path (used by init flow)
        Mock::given(method("POST"))
            .and(path(format!("/v1/auth/approle/role/{approle}/secret-id")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": { "secret_id": format!("secret-{approle}") }
            })))
            .mount(server)
            .await;

        // Wrapped path (used by service add flow)
        let wrap_token = format!("wrap-token-{approle}");
        Mock::given(method("POST"))
            .and(path(format!("/v1/auth/approle/role/{approle}/secret-id")))
            .and(header("X-Vault-Token", ROOT_TOKEN))
            .and(header_exists("X-Vault-Wrap-TTL"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "wrap_info": {
                    "token": &wrap_token,
                    "ttl": 1800,
                    "creation_time": "2026-04-12T00:00:00Z",
                    "creation_path": format!("auth/approle/role/{approle}/secret-id")
                }
            })))
            .mount(server)
            .await;

        Mock::given(method("POST"))
            .and(path("/v1/sys/wrapping/unwrap"))
            .and(header("X-Vault-Token", &wrap_token))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "data": {
                    "secret_id": format!("secret-{approle}"),
                    "secret_id_accessor": "acc"
                }
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
