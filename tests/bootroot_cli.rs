use std::process::Command;

#[cfg(unix)]
mod support;

#[cfg(unix)]
mod status_helpers {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(super) async fn stub_openbao_health(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/v1/sys/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
    }

    pub(super) async fn stub_openbao_seal_status(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/v1/sys/seal-status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sealed": false
            })))
            .mount(server)
            .await;
    }

    pub(super) async fn stub_kv_mount_invalid(server: &MockServer, token: &str) {
        Mock::given(method("GET"))
            .and(path("/v1/sys/mounts/secret"))
            .and(header("X-Vault-Token", token))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "type": "transit",
                    "options": {}
                }
            })))
            .mount(server)
            .await;
    }

    pub(super) async fn stub_kv_missing_paths(server: &MockServer, token: &str) {
        for secret in [
            "bootroot/stepca/password",
            "bootroot/stepca/db",
            "bootroot/responder/hmac",
            "bootroot/agent/eab",
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/v1/secret/metadata/{secret}")))
                .and(header("X-Vault-Token", token))
                .respond_with(ResponseTemplate::new(404))
                .mount(server)
                .await;
        }
    }

    pub(super) async fn stub_approles_missing(server: &MockServer, token: &str) {
        for role in [
            "bootroot-agent-role",
            "bootroot-responder-role",
            "bootroot-stepca-role",
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/v1/auth/approle/role/{role}")))
                .and(header("X-Vault-Token", token))
                .respond_with(ResponseTemplate::new(404))
                .mount(server)
                .await;
        }
    }
}

fn run(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .args(args)
        .output()
        .expect("bootroot binary runs in tests");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

fn run_with_env(args: &[&str], key: &str, value: &str) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .args(args)
        .env(key, value)
        .output()
        .expect("bootroot binary runs in tests");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

#[test]
fn test_help_lists_subcommands() {
    let (stdout, _stderr, code) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("infra"));
    assert!(stdout.contains("init"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("app"));
    assert!(stdout.contains("verify"));
}

#[test]
fn test_status_command_message() {
    let (stdout, _stderr, code) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("status"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_status_command_summary() {
    use std::env;
    use std::fs;

    use anyhow::Context;
    use support::{ROOT_TOKEN, stub_openbao, write_fake_docker};
    use tempfile::tempdir;
    use wiremock::MockServer;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    write_fake_docker(&bin_dir).expect("write fake docker");

    let server = MockServer::start().await;
    stub_openbao(&server).await;

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            &server.uri(),
            "--root-token",
            ROOT_TOKEN,
        ])
        .env("PATH", combined_path)
        .output()
        .expect("run status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot status: summary"));
    assert!(stdout.contains("- infra:"));
    assert!(stdout.contains("- OpenBao:"));
    assert!(stdout.contains("- KV paths:"));
    assert!(stdout.contains("- AppRoles:"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_status_command_reports_infra_failure() {
    use std::env;
    use std::fs;

    use anyhow::Context;
    use support::write_fake_docker_with_status;
    use tempfile::tempdir;
    use wiremock::MockServer;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    write_fake_docker_with_status(&bin_dir, "exited", "").expect("write fake docker");

    let server = MockServer::start().await;
    status_helpers::stub_openbao_health(&server).await;
    status_helpers::stub_openbao_seal_status(&server).await;

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            &server.uri(),
        ])
        .env("PATH", combined_path)
        .output()
        .expect("run status");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot status failed"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_status_command_reports_openbao_unreachable() {
    use std::env;
    use std::fs;

    use anyhow::Context;
    use support::write_fake_docker;
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    write_fake_docker(&bin_dir).expect("write fake docker");

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            "http://127.0.0.1:9",
        ])
        .env("PATH", combined_path)
        .output()
        .expect("run status");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot status failed"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_status_command_reports_unknown_without_token() {
    use std::env;
    use std::fs;

    use anyhow::Context;
    use support::write_fake_docker;
    use tempfile::tempdir;
    use wiremock::MockServer;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    write_fake_docker(&bin_dir).expect("write fake docker");

    let server = MockServer::start().await;
    status_helpers::stub_openbao_health(&server).await;
    status_helpers::stub_openbao_seal_status(&server).await;

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            &server.uri(),
        ])
        .env("PATH", combined_path)
        .output()
        .expect("run status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("unknown"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_status_command_reports_invalid_kv_mount() {
    use std::env;
    use std::fs;

    use anyhow::Context;
    use support::{ROOT_TOKEN, write_fake_docker};
    use tempfile::tempdir;
    use wiremock::MockServer;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    write_fake_docker(&bin_dir).expect("write fake docker");

    let server = MockServer::start().await;
    status_helpers::stub_openbao_health(&server).await;
    status_helpers::stub_openbao_seal_status(&server).await;
    status_helpers::stub_kv_mount_invalid(&server, ROOT_TOKEN).await;
    status_helpers::stub_kv_missing_paths(&server, ROOT_TOKEN).await;
    status_helpers::stub_approles_missing(&server, ROOT_TOKEN).await;

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            &server.uri(),
            "--root-token",
            ROOT_TOKEN,
        ])
        .env("PATH", combined_path)
        .output()
        .expect("run status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("invalid"));
}

#[test]
fn test_status_command_message_korean() {
    let (stdout, _stderr, code) = run_with_env(&["--help"], "BOOTROOT_LANG", "ko");
    assert_eq!(code, 0);
    assert!(stdout.contains("status"));
}
