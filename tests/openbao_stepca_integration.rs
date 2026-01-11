#[cfg(unix)]
mod unix_integration {
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use anyhow::{Context, Result};
    use serde_json::json;
    use tempfile::tempdir;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const ROOT_TOKEN: &str = "root-token";

    fn write_fake_docker(dir: &Path) -> Result<PathBuf> {
        let script = r#"#!/bin/sh
set -eu

if [ "${1:-}" = "compose" ] && [ "${2:-}" = "-f" ] && [ "${4:-}" = "ps" ] && [ "${5:-}" = "-q" ]; then
  service="${6:-}"
  printf "cid-%s" "$service"
  exit 0
fi

if [ "${1:-}" = "inspect" ]; then
  printf "running|healthy"
  exit 0
fi

exit 0
"#;
        let path = dir.join("docker");
        fs::write(&path, script).context("Failed to write fake docker script")?;
        fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
            .context("Failed to set fake docker permissions")?;
        Ok(path)
    }

    fn create_secrets_dir(root: &Path) -> Result<PathBuf> {
        let secrets_dir = root.join("secrets");
        fs::create_dir_all(secrets_dir.join("config"))
            .context("Failed to create secrets config dir")?;
        fs::create_dir_all(secrets_dir.join("secrets"))
            .context("Failed to create secrets key dir")?;
        fs::write(
            secrets_dir.join("config").join("ca.json"),
            r#"{"db":{"type":"","dataSource":""}}"#,
        )
        .context("Failed to write ca.json")?;
        fs::write(secrets_dir.join("secrets").join("root_ca_key"), "")
            .context("Failed to write root_ca_key")?;
        fs::write(secrets_dir.join("secrets").join("intermediate_ca_key"), "")
            .context("Failed to write intermediate_ca_key")?;
        Ok(secrets_dir)
    }

    async fn stub_openbao(server: &MockServer) {
        stub_health(server).await;
        stub_init_status(server).await;
        stub_seal_status(server).await;
        stub_kv_mount(server).await;
        stub_auth_backends(server).await;
        stub_policies(server).await;
        stub_approles(server).await;
        stub_kv_secrets(server).await;
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

    async fn stub_seal_status(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/v1/sys/seal-status"))
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
        ] {
            Mock::given(method("POST"))
                .and(path(format!("/v1/secret/data/{secret}")))
                .and(header("X-Vault-Token", ROOT_TOKEN))
                .respond_with(ResponseTemplate::new(200))
                .mount(server)
                .await;
        }
    }

    #[tokio::test]
    async fn init_flow_with_openbao_and_stepca_stubs() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let secrets_dir = create_secrets_dir(temp_dir.path())?;
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").context("Failed to write compose file")?;

        let bin_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        write_fake_docker(&bin_dir)?;

        let server = MockServer::start().await;
        stub_openbao(&server).await;

        let path = env::var("PATH").unwrap_or_default();
        let combined_path = format!("{}:{}", bin_dir.display(), path);

        let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(temp_dir.path())
            .args([
                "init",
                "--openbao-url",
                &server.uri(),
                "--root-token",
                ROOT_TOKEN,
                "--db-dsn",
                "postgresql://step:step@localhost:5432/step?sslmode=disable",
                "--auto-generate",
                "--secrets-dir",
                secrets_dir.to_string_lossy().as_ref(),
                "--compose-file",
                compose_file.to_string_lossy().as_ref(),
            ])
            .env("PATH", combined_path)
            .output()
            .context("Failed to run bootroot init")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            anyhow::bail!("bootroot init failed: {stderr}");
        }
        assert!(
            stdout.contains("bootroot init: summary"),
            "stdout was: {stdout}"
        );
        Ok(())
    }
}
