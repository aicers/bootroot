#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::env;
    use std::fs;
    use std::io::Write;
    use std::process::{Command, Output, Stdio};

    use anyhow::{Context, Result};
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::support::{
        ROOT_TOKEN, create_secrets_dir, expect_rollback_deletes, stub_openbao, stub_openbao_sealed,
        stub_openbao_unseal_failure, stub_openbao_with_write_failure, write_fake_docker,
        write_fake_docker_with_status, write_password_file,
    };

    fn run_command_with_input(command: &mut Command, input: &str) -> Result<Output> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("Failed to spawn command")?;
        child
            .stdin
            .as_mut()
            .context("Missing stdin")?
            .write_all(input.as_bytes())
            .context("Failed to write stdin")?;
        let output = child
            .wait_with_output()
            .context("Failed to wait for command")?;
        Ok(output)
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

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
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
            .env("PATH", combined_path);
        let output =
            run_command_with_input(&mut command, "y\n").context("Failed to run bootroot init")?;

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

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
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
            .env("PATH", combined_path);
        let output =
            run_command_with_input(&mut command, "y\n").context("Failed to run bootroot init")?;

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

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
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
            .env("PATH", combined_path);
        let output =
            run_command_with_input(&mut command, "y\n").context("Failed to run bootroot init")?;

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("bootroot init failed"));
        Ok(())
    }

    #[tokio::test]
    async fn init_skips_responder_check_when_flag_set() -> Result<()> {
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

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
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
                "--skip-responder-check",
            ])
            .env("PATH", combined_path);
        let output =
            run_command_with_input(&mut command, "y\n").context("Failed to run bootroot init")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("bootroot init failed: {stderr}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn init_auto_eab_registers_credentials() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let secrets_dir = create_secrets_dir(temp_dir.path())?;
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").context("Failed to write compose file")?;

        let bin_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        write_fake_docker(&bin_dir)?;

        let server = MockServer::start().await;
        stub_openbao(&server).await;

        let stepca = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/acme/acme/eab"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keyId": "eab-kid",
                "hmacKey": "eab-hmac"
            })))
            .mount(&stepca)
            .await;

        let path = env::var("PATH").unwrap_or_default();
        let combined_path = format!("{}:{}", bin_dir.display(), path);

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
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
                "--eab-auto",
                "--stepca-url",
                &stepca.uri(),
                "--secrets-dir",
                secrets_dir.to_string_lossy().as_ref(),
                "--compose-file",
                compose_file.to_string_lossy().as_ref(),
            ])
            .env("PATH", combined_path);
        let output =
            run_command_with_input(&mut command, "y\n").context("Failed to run bootroot init")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("bootroot init failed: {stderr}");
        }
        assert!(stdout.contains("eab kid"));
        Ok(())
    }

    #[tokio::test]
    async fn init_auto_eab_failure_triggers_rollback() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let secrets_dir = create_secrets_dir(temp_dir.path())?;
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").context("Failed to write compose file")?;

        let bin_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        write_fake_docker(&bin_dir)?;

        let server = MockServer::start().await;
        stub_openbao(&server).await;
        expect_rollback_deletes(&server).await;

        let stepca = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/acme/acme/eab"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&stepca)
            .await;

        let path = env::var("PATH").unwrap_or_default();
        let combined_path = format!("{}:{}", bin_dir.display(), path);

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
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
                "--eab-auto",
                "--stepca-url",
                &stepca.uri(),
                "--secrets-dir",
                secrets_dir.to_string_lossy().as_ref(),
                "--compose-file",
                compose_file.to_string_lossy().as_ref(),
            ])
            .env("PATH", combined_path);
        let output =
            run_command_with_input(&mut command, "y\n").context("Failed to run bootroot init")?;

        assert!(!output.status.success());
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

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
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
            .env("PATH", combined_path);
        let output =
            run_command_with_input(&mut command, "y\n").context("Failed to run bootroot init")?;

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("bootroot init failed"));
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

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
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
            .env("PATH", combined_path);
        let output =
            run_command_with_input(&mut command, "y\n").context("Failed to run bootroot init")?;

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("bootroot init failed"));
        Ok(())
    }

    #[tokio::test]
    async fn init_reads_unseal_keys_from_file() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let secrets_dir = create_secrets_dir(temp_dir.path())?;
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").context("Failed to write compose file")?;
        let unseal_file = temp_dir.path().join("unseal.txt");
        fs::write(&unseal_file, "key1\n").context("Failed to write unseal file")?;

        let bin_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        write_fake_docker(&bin_dir)?;

        let server = MockServer::start().await;
        stub_openbao_sealed(&server).await;

        let path = env::var("PATH").unwrap_or_default();
        let combined_path = format!("{}:{}", bin_dir.display(), path);

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
            .current_dir(temp_dir.path())
            .args([
                "init",
                "--openbao-url",
                &server.uri(),
                "--root-token",
                ROOT_TOKEN,
                "--openbao-unseal-from-file",
                unseal_file.to_string_lossy().as_ref(),
                "--db-dsn",
                "postgresql://step:step@localhost:5432/step?sslmode=disable",
                "--auto-generate",
                "--secrets-dir",
                secrets_dir.to_string_lossy().as_ref(),
                "--compose-file",
                compose_file.to_string_lossy().as_ref(),
                "--skip-responder-check",
            ])
            .env("PATH", combined_path);
        let output = run_command_with_input(&mut command, "y\ny\n")
            .context("Failed to run bootroot init")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("bootroot init failed: {stderr}");
        }
        assert!(stdout.contains("Auto-unseal"), "stdout was: {stdout}");
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

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
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
            .env("PATH", combined_path);
        let output = run_command_with_input(&mut command, "y\ny\n")
            .context("Failed to run bootroot init")?;

        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("bootroot init failed"));
        let password = fs::read_to_string(secrets_dir.join("password.txt"))
            .context("Failed to read password.txt")?;
        assert_eq!(password, original_password);
        let ca_json = fs::read_to_string(secrets_dir.join("config").join("ca.json"))
            .context("Failed to read ca.json after rollback")?;
        assert_eq!(ca_json, original_ca_json);
        Ok(())
    }

    #[tokio::test]
    async fn init_cancels_on_overwrite_prompt() -> Result<()> {
        let temp_dir = tempdir().context("Failed to create temp dir")?;
        let secrets_dir = create_secrets_dir(temp_dir.path())?;
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").context("Failed to write compose file")?;
        fs::write(temp_dir.path().join("state.json"), "{}")
            .context("Failed to write state.json")?;

        let bin_dir = temp_dir.path().join("bin");
        fs::create_dir_all(&bin_dir).context("Failed to create bin dir")?;
        write_fake_docker(&bin_dir)?;

        let server = MockServer::start().await;
        stub_openbao(&server).await;

        let path = env::var("PATH").unwrap_or_default();
        let combined_path = format!("{}:{}", bin_dir.display(), path);

        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
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
            .env("PATH", combined_path);

        let output =
            run_command_with_input(&mut command, "n\n").context("Failed to run bootroot init")?;
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("bootroot init failed"));
        Ok(())
    }
}
