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

    /// Host ports the stack this test brings up publishes on `127.0.0.1`:
    /// `OpenBao` (8200), step-ca (9000), the HTTP-01 responder (8080),
    /// Grafana under the `lan` profile (3000) and `PostgreSQL` (5433).
    ///
    /// 9000 belongs here even though `infra up` below does not ask for
    /// step-ca: `prometheus` declares `depends_on: [step-ca, openbao]`, so
    /// `monitoring up` starts the container regardless and it publishes
    /// 9000 the moment it does. Dropping the port from this list would
    /// trade the named failure for a compose port-allocation error.
    const MONITORING_PORTS: [u16; 5] = [8200, 9000, 8080, 3000, 5433];

    /// Grafana admin password given to `monitoring up`, injected into
    /// compose, and used to authenticate against the Grafana API. One
    /// constant so the three cannot drift apart.
    const GRAFANA_ADMIN_PASSWORD: &str = "admin";

    /// Monitoring profile this test brings up, and tears down again.
    const MONITORING_PROFILE: &str = "lan";

    /// `PostgreSQL` password for the stack this test owns. Never read back:
    /// compose only needs *a* value for the variable below.
    const POSTGRES_PASSWORD: &str = "bootroot-itest";

    /// Compose interpolates the whole file on every invocation, and
    /// `docker-compose.yml` declares exactly these two variables in the
    /// fail-if-unset form. They normally arrive through the `.env` that
    /// `infra install` writes, but this test deliberately runs before any
    /// install (it needs the host ports free), so nothing has written one.
    /// Every child process that ends up driving compose — `docker compose`
    /// directly, and `bootroot infra up` / `monitoring up` — therefore
    /// carries them itself.
    const COMPOSE_ENV: [(&str, &str); 2] = [
        ("POSTGRES_PASSWORD", POSTGRES_PASSWORD),
        ("GRAFANA_ADMIN_PASSWORD", GRAFANA_ADMIN_PASSWORD),
    ];

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
            .env("COMPOSE_PROJECT_NAME", project)
            .envs(COMPOSE_ENV);
        command
    }

    fn docker_compose_command(project: &str, compose_file: &Path) -> Command {
        let mut command = Command::new("docker");
        command
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .envs(COMPOSE_ENV)
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
            // Through `docker_compose_command` so the teardown carries the
            // same interpolation variables as the bring-up: compose reads
            // the whole file here too, and without them `down` would die on
            // the fail-if-unset guards and leave the stack running.
            //
            // `--profile` so the teardown models the same set of services
            // the bring-up did: `grafana` and `prometheus` are gated behind
            // it, and naming it here cannot remove less than omitting it
            // would.
            //
            // How much it adds depends on the Compose version. On v5.3.1 a
            // plain `down` already removes profile-gated containers, having
            // matched them by project label rather than from the model; on
            // the version that produced the leftover `…-grafana-1` and
            // `…-prometheus-1` this issue reported, it did not. Passing it
            // costs nothing on the former and is the fix on the latter.
            let outcome = docker_compose_command(&self.project, &self.compose_file)
                .args(["--profile", MONITORING_PROFILE])
                .args(["down", "-v", "--remove-orphans"])
                .output();
            // Say so when it fails. A teardown that removed nothing leaves
            // the stack holding the host ports every later step in
            // `test-core` needs, and this one has failed silently before:
            // until the interpolation variables above reached it, `down`
            // died on a fail-if-unset guard and the discarded output was
            // the only place that said so. Cargo captures this unless the
            // test failed — which is the run whose residue was reported.
            match outcome {
                Ok(output) if !output.status.success() => eprintln!(
                    "compose teardown of {} failed: {}",
                    self.project,
                    String::from_utf8_lossy(&output.stderr).trim()
                ),
                Err(error) => {
                    eprintln!(
                        "could not spawn compose teardown of {}: {error}",
                        self.project
                    );
                }
                Ok(_) => {}
            }
            let _ = std::fs::remove_file(&self.compose_file);
        }
    }

    /// Polls `check` until it reports success or `timeout` elapses.
    ///
    /// An `Err` is a retry, not an exit: every poll in this file talks HTTP
    /// to a service that may still be binding its port, and a refused or
    /// dropped connection is an `Err` rather than an `Ok(false)`. The last
    /// poll's error is kept and reported when the budget runs out, so a
    /// genuine failure still arrives with its cause attached instead of as
    /// a bare timeout. A poll that reached the service and answered "not
    /// yet" clears it: that is the more recent truth about the endpoint.
    async fn wait_for<F, Fut>(timeout: Duration, mut check: F) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<bool>>,
    {
        let started = SystemTime::now();
        loop {
            let last_error = match check().await {
                Ok(true) => return Ok(()),
                Ok(false) => None,
                Err(error) => Some(error),
            };
            if started.elapsed().unwrap_or_default() > timeout {
                return Err(match last_error {
                    Some(error) => error.context("Timed out waiting for condition"),
                    None => anyhow::anyhow!("Timed out waiting for condition"),
                });
            }
            sleep(Duration::from_millis(1500)).await;
        }
    }

    /// Services this test asks `infra up` to bring up and hold to a
    /// readiness check.
    ///
    /// step-ca is deliberately absent. `infra up` ends in
    /// `ensure_all_healthy` over exactly this list, and step-ca cannot be
    /// healthy here: its command is
    /// `step-ca /home/step/config/ca.json --password-file
    /// /home/step/password.txt` over the `./secrets` bind mount, and
    /// `secrets/` is gitignored and written by `bootroot init` — which this
    /// test runs before, by the constraint that it owns the host ports. On
    /// a clean checkout the container therefore crash-loops under
    /// `restart: always` and `infra up` fails with
    /// `step-ca status=restarting`.
    ///
    /// This does not remove step-ca from the stack: `prometheus` depends on
    /// it, so `monitoring up` still starts it. What the list controls is
    /// what gets asserted, and asserting a service that cannot start on the
    /// inputs available at this point in the job is what kept the test from
    /// running at all.
    const INFRA_SERVICES: &str = "openbao,postgres,bootroot-http01";

    fn run_infra_up(project: &str, compose_file: &Path) -> Result<()> {
        let output = run_command(
            bootroot_command(project)
                .args(["infra", "up", "--compose-file"])
                .arg(compose_file)
                .args(["--services", INFRA_SERVICES]),
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
                .args(["--profile", MONITORING_PROFILE])
                .args(["--grafana-admin-password", GRAFANA_ADMIN_PASSWORD]),
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
                    .basic_auth("admin", Some(GRAFANA_ADMIN_PASSWORD))
                    .send()
                    .await
                    .context("Failed to query Grafana health")?;
                Ok(response.status().is_success())
            }
        })
        .await
        .context("Grafana did not become healthy")
    }

    /// Waits until Prometheus reports the `openbao` scrape target healthy.
    ///
    /// The `step-ca` job in `monitoring/prometheus.yml` is not waited on,
    /// because nothing can make it go up. It scrapes `step-ca:9102`, and
    /// step-ca serves metrics only when `metricsAddress` is set in
    /// `ca.json` — a key no code in this repository writes: `ca.json` comes
    /// from `step ca init` inside the image, and the patcher in
    /// `src/commands/init/steps/stepca_setup.rs` touches only `dnsNames`,
    /// `db` and ACME. The pinned image's `step-ca` accepts no flag or
    /// environment variable for it either, so there is no way to set it
    /// from compose. That target has never had anything to scrape, in this
    /// test or in production; waiting on it here would only time out.
    ///
    /// Prometheus scraping is still covered — `openbao` is a real target
    /// over the same config, so a Prometheus upgrade that breaks scraping
    /// or the config format still fails this test.
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
                    .map(Vec::as_slice)
                    .unwrap_or_default();
                let openbao_up = active.iter().any(|target| {
                    let job = target
                        .get("labels")
                        .and_then(|item| item.get("job"))
                        .and_then(|item| item.as_str())
                        .unwrap_or_default();
                    let health = target
                        .get("health")
                        .and_then(|item| item.as_str())
                        .unwrap_or_default();
                    job == "openbao" && health == "up"
                });
                Ok(openbao_up)
            }
        })
        .await
        .context("Prometheus did not report openbao as up")
    }

    async fn assert_grafana_dashboard(client: &Client) -> Result<()> {
        let response = client
            .get("http://127.0.0.1:3000/api/search?query=Bootroot")
            .basic_auth("admin", Some(GRAFANA_ADMIN_PASSWORD))
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

    /// Creates the `secrets/` directory this stack bind-mounts, if it is
    /// not there already.
    ///
    /// step-ca mounts `./secrets` at `/home/step`, and `prometheus`
    /// depends on step-ca, so the container is created whatever this test
    /// asks `infra up` for. When the host directory is missing the Docker
    /// daemon creates it, and the daemon runs as root — leaving a
    /// root-owned `secrets/` in the workspace for the steps that follow in
    /// `test-core`, which run unprivileged and write to that same path.
    /// Creating it here first means the mount finds a directory owned by
    /// whoever runs the test.
    ///
    /// Not removed on teardown: on a developer's machine this path holds
    /// real CA material, and an empty gitignored directory is not the port
    /// or volume residue the teardown exists to clear.
    fn ensure_secrets_dir() -> Result<()> {
        let secrets = Path::new(env!("CARGO_MANIFEST_DIR")).join("secrets");
        std::fs::create_dir_all(&secrets)
            .with_context(|| format!("Failed to create {}", secrets.display()))
    }

    /// Returns the ports of `ports` that something already listens on.
    fn bound_ports(ports: &[u16]) -> Vec<u16> {
        ports
            .iter()
            .copied()
            .filter(|port| TcpListener::bind(("127.0.0.1", *port)).is_err())
            .collect()
    }

    #[tokio::test]
    #[ignore = "Brings the Docker monitoring stack up on fixed host ports; run with --include-ignored and 8200, 9000, 8080, 3000 and 5433 free"]
    async fn monitoring_stack_is_ready() -> Result<()> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let project = format!("bootroot-itest-{nonce}");
        // A conflict is a failure, not a skip: the stack publishes these on
        // 127.0.0.1 from the repo compose file, so there is no port left to
        // fall back to, and reporting success here is how this test spent
        // its life being green without running.
        let bound = bound_ports(&MONITORING_PORTS);
        if !bound.is_empty() {
            let ports = bound
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ");
            anyhow::bail!(
                "Required host ports are already in use: {ports}. \
                 Free them and re-run; this test publishes the monitoring \
                 stack on 127.0.0.1 at fixed ports."
            );
        }
        ensure_secrets_dir()?;
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
