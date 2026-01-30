#[cfg(unix)]
mod unix_integration {
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result};
    use reqwest::Client;
    use serde_json::Value;
    use tokio::time::sleep;

    const MONITORING_PORTS: [u16; 4] = [8200, 9000, 8080, 3000];

    fn run_command(command: &mut Command) -> Result<Output> {
        let output = command
            .output()
            .with_context(|| "Failed to spawn command")?;
        Ok(output)
    }

    fn bootroot_command(project: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .env("COMPOSE_PROJECT_NAME", project);
        command
    }

    fn docker_compose_command(project: &str, compose_file: &Path) -> Command {
        let mut command = Command::new("docker");
        command
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .args(["compose", "-p", project, "-f"])
            .arg(compose_file);
        command
    }

    struct ComposeGuard {
        project: String,
        compose_file: PathBuf,
    }

    impl Drop for ComposeGuard {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .current_dir(env!("CARGO_MANIFEST_DIR"))
                .args([
                    "compose",
                    "-p",
                    &self.project,
                    "-f",
                    self.compose_file.to_str().unwrap_or("docker-compose.yml"),
                    "down",
                    "-v",
                    "--remove-orphans",
                ])
                .output();
            let _ = std::fs::remove_file(&self.compose_file);
        }
    }

    async fn wait_for<F, Fut>(timeout: Duration, mut check: F) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<bool>>,
    {
        let started = SystemTime::now();
        loop {
            if check().await? {
                return Ok(());
            }
            if started.elapsed().unwrap_or_default() > timeout {
                anyhow::bail!("Timed out waiting for condition");
            }
            sleep(Duration::from_millis(1500)).await;
        }
    }

    fn run_infra_up(project: &str, compose_file: &Path) -> Result<()> {
        let output = run_command(
            bootroot_command(project)
                .args(["infra", "up", "--compose-file"])
                .arg(compose_file)
                .args(["--services", "openbao,postgres,step-ca,bootroot-http01"]),
        )
        .context("Failed to run bootroot infra up")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("bootroot infra up failed: {stderr}");
        }
        Ok(())
    }

    fn run_compose_build(project: &str, compose_file: &Path) -> Result<()> {
        let output = run_command(docker_compose_command(project, compose_file).args([
            "build",
            "bootroot-http01",
            "step-ca",
        ]))
        .context("Failed to run docker compose build")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("docker compose build failed: {stderr}");
        }
        Ok(())
    }

    fn run_monitoring_up(project: &str, compose_file: &Path) -> Result<()> {
        let output = run_command(
            bootroot_command(project)
                .args(["monitoring", "up", "--compose-file"])
                .arg(compose_file)
                .args(["--profile", "lan", "--grafana-admin-password", "admin"]),
        )
        .context("Failed to run bootroot monitoring up")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("bootroot monitoring up failed: {stderr}");
        }
        Ok(())
    }

    async fn wait_for_grafana(client: &Client) -> Result<()> {
        wait_for(Duration::from_secs(90), || {
            let client = client.clone();
            async move {
                let response = client
                    .get("http://127.0.0.1:3000/api/health")
                    .basic_auth("admin", Some("admin"))
                    .send()
                    .await
                    .context("Failed to query Grafana health")?;
                Ok(response.status().is_success())
            }
        })
        .await
        .context("Grafana did not become healthy")
    }

    async fn wait_for_prometheus_targets(project: &str, compose_file: &Path) -> Result<()> {
        wait_for(Duration::from_secs(90), || {
            let mut command = docker_compose_command(project, compose_file);
            async move {
                let output = run_command(command.args([
                    "exec",
                    "-T",
                    "prometheus",
                    "wget",
                    "-qO-",
                    "http://localhost:9090/api/v1/targets",
                ]))?;
                if !output.status.success() {
                    return Ok(false);
                }
                let stdout = String::from_utf8_lossy(&output.stdout);
                let data: Value = serde_json::from_str(&stdout)?;
                let active = data
                    .get("data")
                    .and_then(|item| item.get("activeTargets"))
                    .and_then(|item| item.as_array())
                    .cloned()
                    .unwrap_or_default();
                let mut stepca_up = false;
                let mut openbao_up = false;
                for target in active {
                    let job = target
                        .get("labels")
                        .and_then(|item| item.get("job"))
                        .and_then(|item| item.as_str())
                        .unwrap_or_default();
                    let health = target
                        .get("health")
                        .and_then(|item| item.as_str())
                        .unwrap_or_default();
                    if job == "step-ca" && health == "up" {
                        stepca_up = true;
                    }
                    if job == "openbao" && health == "up" {
                        openbao_up = true;
                    }
                }
                Ok(stepca_up && openbao_up)
            }
        })
        .await
        .context("Prometheus did not report step-ca/openbao as up")
    }

    async fn assert_grafana_dashboard(client: &Client) -> Result<()> {
        let response = client
            .get("http://127.0.0.1:3000/api/search?query=Bootroot")
            .basic_auth("admin", Some("admin"))
            .send()
            .await
            .context("Failed to query Grafana search API")?;
        if !response.status().is_success() {
            anyhow::bail!("Grafana search API returned {}", response.status());
        }
        let search: Value = response
            .json()
            .await
            .context("Failed to parse search JSON")?;
        let items = search.as_array().cloned().unwrap_or_default();
        let found = items.iter().any(|item| {
            item.get("title")
                .and_then(|value| value.as_str())
                .is_some_and(|title| title == "Bootroot Monitoring")
        });
        if !found {
            anyhow::bail!("Grafana dashboard not found via search");
        }
        Ok(())
    }

    fn assert_monitoring_status(project: &str, compose_file: &Path) -> Result<()> {
        let output = run_command(
            bootroot_command(project)
                .args(["monitoring", "status", "--compose-file"])
                .arg(compose_file),
        )
        .context("Failed to run bootroot monitoring status")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("bootroot monitoring status failed: {stderr}");
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("bootroot monitoring status: summary"),
            "stdout was: {stdout}"
        );
        assert!(stdout.contains("profile: lan"), "stdout was: {stdout}");
        Ok(())
    }

    fn write_compose_without_container_names(nonce: u64) -> Result<PathBuf> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let source = root.join("docker-compose.yml");
        let contents = std::fs::read_to_string(&source)
            .with_context(|| format!("Failed to read {}", source.display()))?;
        let mut filtered = String::new();
        for line in contents.lines() {
            if line.trim_start().starts_with("container_name:") {
                continue;
            }
            filtered.push_str(line);
            filtered.push('\n');
        }
        let target = root.join(format!("docker-compose.itest-{nonce}.yml"));
        std::fs::write(&target, filtered)
            .with_context(|| format!("Failed to write {}", target.display()))?;
        Ok(target)
    }

    fn ports_available(ports: &[u16]) -> bool {
        for port in ports {
            if TcpListener::bind(("127.0.0.1", *port)).is_err() {
                return false;
            }
        }
        true
    }

    #[tokio::test]
    #[ignore = "Run explicitly in CI E2E after step-ca init"]
    async fn monitoring_stack_is_ready() -> Result<()> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let project = format!("bootroot-itest-{nonce}");
        if !ports_available(&MONITORING_PORTS) {
            eprintln!("Skipping monitoring integration test: ports are in use.");
            return Ok(());
        }
        let compose_file = write_compose_without_container_names(nonce)?;
        let _guard = ComposeGuard {
            project: project.clone(),
            compose_file: compose_file.clone(),
        };

        run_compose_build(&project, &compose_file)?;
        run_infra_up(&project, &compose_file)?;
        run_monitoring_up(&project, &compose_file)?;

        let client = Client::new();
        wait_for_grafana(&client).await?;
        wait_for_prometheus_targets(&project, &compose_file).await?;
        assert_grafana_dashboard(&client).await?;
        assert_monitoring_status(&project, &compose_file)?;

        Ok(())
    }
}
