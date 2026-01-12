#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::env;
    use std::fs;
    use std::process::Command;

    use anyhow::{Context, Result};
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::support::{
        ROOT_TOKEN, create_secrets_dir, expect_rollback_deletes, stub_openbao,
        stub_openbao_unseal_failure, stub_openbao_with_write_failure, write_fake_docker,
        write_fake_docker_with_status, write_password_file,
    };

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

    #[tokio::test]
    async fn init_checks_responder_when_configured() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let secrets_dir = create_secrets_dir(temp_dir.path())?;
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").context("Failed to write compose file")?;

        let bin_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        write_fake_docker(&bin_dir)?;

        let server = MockServer::start().await;
        stub_openbao(&server).await;

        let responder = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/admin/http01"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&responder)
            .await;

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
                "--responder-url",
                &responder.uri(),
            ])
            .env("PATH", combined_path)
            .output()
            .context("Failed to run bootroot init")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("bootroot init failed: {stderr}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn init_fails_when_responder_unreachable() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let secrets_dir = create_secrets_dir(temp_dir.path())?;
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").context("Failed to write compose file")?;

        let bin_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        write_fake_docker(&bin_dir)?;

        let server = MockServer::start().await;
        stub_openbao(&server).await;

        let responder = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/admin/http01"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&responder)
            .await;

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
                "--responder-url",
                &responder.uri(),
            ])
            .env("PATH", combined_path)
            .output()
            .context("Failed to run bootroot init")?;

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("HTTP-01 responder check failed"));
        Ok(())
    }

    #[tokio::test]
    async fn init_fails_when_infra_unhealthy() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let secrets_dir = create_secrets_dir(temp_dir.path())?;
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").context("Failed to write compose file")?;

        let bin_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        write_fake_docker_with_status(&bin_dir, "exited", "")?;

        let path = env::var("PATH").unwrap_or_default();
        let combined_path = format!("{}:{}", bin_dir.display(), path);

        let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(temp_dir.path())
            .args([
                "init",
                "--openbao-url",
                "http://127.0.0.1:9999",
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

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Infrastructure not healthy"));
        Ok(())
    }

    #[tokio::test]
    async fn init_fails_when_unseal_stays_sealed() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let secrets_dir = create_secrets_dir(temp_dir.path())?;
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").context("Failed to write compose file")?;

        let bin_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        write_fake_docker(&bin_dir)?;

        let server = MockServer::start().await;
        stub_openbao_unseal_failure(&server).await;

        let path = env::var("PATH").unwrap_or_default();
        let combined_path = format!("{}:{}", bin_dir.display(), path);

        let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(temp_dir.path())
            .args([
                "init",
                "--openbao-url",
                &server.uri(),
                "--unseal-key",
                "key1",
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

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("OpenBao remains sealed"));
        Ok(())
    }

    #[tokio::test]
    async fn init_failure_triggers_rollback() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let secrets_dir = create_secrets_dir(temp_dir.path())?;
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").context("Failed to write compose file")?;

        let bin_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        write_fake_docker(&bin_dir)?;

        let server = MockServer::start().await;
        stub_openbao_with_write_failure(&server, "bootroot/responder/hmac").await;
        expect_rollback_deletes(&server).await;

        let original_password = "old-password";
        write_password_file(&secrets_dir, original_password)?;
        let original_ca_json = fs::read_to_string(secrets_dir.join("config").join("ca.json"))
            .context("Failed to read ca.json")?;

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

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("bootroot init: failed"));
        let password = fs::read_to_string(secrets_dir.join("password.txt"))
            .context("Failed to read password.txt")?;
        assert_eq!(password, original_password);
        let ca_json = fs::read_to_string(secrets_dir.join("config").join("ca.json"))
            .context("Failed to read ca.json after rollback")?;
        assert_eq!(ca_json, original_ca_json);
        Ok(())
    }
}
