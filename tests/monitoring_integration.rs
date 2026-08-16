#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::OnceLock;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result};
    use reqwest::Client;
    use serde_json::Value;

    use crate::support::polling::wait_for;

    /// Host ports the stack this test brings up publishes on `127.0.0.1`:
    /// `OpenBao` (8200), step-ca (9000), the HTTP-01 responder (8080),
    /// Grafana under the `lan` profile (3000) and `PostgreSQL` (5433).
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

    /// Password protecting the throwaway CA this test initializes. It
    /// encrypts key material that lives for the length of one run inside a
    /// directory the teardown removes, and it is written to the path the
    /// compose file's `--password-file` already names.
    const STEP_CA_PASSWORD: &str = "bootroot-itest";

    /// Where `STEP_CA_PASSWORD` lands inside the step-ca container. Fixed
    /// by `docker-compose.yml`, whose `command` starts step-ca with
    /// `--password-file /home/step/password.txt`.
    const STEP_CA_PASSWORD_FILE: &str = "/home/step/password.txt";

    /// Compose interpolates the whole file on every invocation, and
    /// `docker-compose.yml` declares exactly two variables in the
    /// fail-if-unset form. They normally arrive through the `.env` that
    /// `infra install` writes, but this test deliberately runs before any
    /// install (it needs the host ports free), so nothing has written one.
    /// Every child process that ends up driving compose — `docker compose`
    /// directly, and `bootroot infra up` / `monitoring up` — therefore
    /// carries them itself, along with the step-ca user below.
    fn compose_env() -> [(&'static str, &'static str); 3] {
        [
            ("POSTGRES_PASSWORD", POSTGRES_PASSWORD),
            ("GRAFANA_ADMIN_PASSWORD", GRAFANA_ADMIN_PASSWORD),
            ("BOOTROOT_STEPCA_USER", caller_user()),
        ]
    }

    /// Returns the `uid:gid` this process runs as, for
    /// `BOOTROOT_STEPCA_USER`.
    ///
    /// step-ca writes its CA into a host directory the generated compose
    /// file binds at `/home/step`, and the teardown has to remove it
    /// again. At the compose default of `1000:1000` those files would
    /// belong to a user this process is not — on a GitHub runner, uid 1001
    /// — and the removal would fail, leaving the CA behind in the
    /// workspace. Naming the caller is what the variable exists for:
    /// `docker-compose.yml` describes it as "the owner of ./secrets".
    ///
    /// Falls back to the compose default, so a host without `id` behaves
    /// exactly as it would with the variable unset rather than differently.
    fn caller_user() -> &'static str {
        static USER: OnceLock<String> = OnceLock::new();
        USER.get_or_init(|| match (read_id("-u"), read_id("-g")) {
            (Some(uid), Some(gid)) => format!("{uid}:{gid}"),
            _ => "1000:1000".to_string(),
        })
    }

    fn read_id(flag: &str) -> Option<String> {
        let output = Command::new("id").arg(flag).output().ok()?;
        if !output.status.success() {
            return None;
        }
        let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
        (!value.is_empty()).then_some(value)
    }

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
            .envs(compose_env());
        command
    }

    fn docker_compose_command(project: &str, compose_file: &Path) -> Command {
        let mut command = Command::new("docker");
        command
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .envs(compose_env())
            .args(["compose", "-p", project, "-f"])
            .arg(compose_file);
        command
    }

    struct ComposeGuard {
        project: String,
        compose_file: PathBuf,
        step_ca_dir: PathBuf,
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
            // The throwaway CA goes with it. It is key material, it is of
            // no use after the run that made it, and `caller_user()` is
            // what makes this removal possible at all.
            if let Err(error) = std::fs::remove_dir_all(&self.step_ca_dir)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                eprintln!("could not remove {}: {error}", self.step_ca_dir.display());
            }
        }
    }

    /// Services this test asks `infra up` to bring up and hold to a
    /// readiness check.
    ///
    /// step-ca is one of them, which is only possible because
    /// [`init_step_ca`] has run first. `infra up` ends in
    /// `ensure_all_healthy` over exactly this list, and step-ca's command
    /// is `step-ca /home/step/config/ca.json --password-file
    /// /home/step/password.txt`; on the repository's own `./secrets` mount
    /// that config is a `bootroot init` artifact, and #825 constrains this
    /// test to run *before* any install or init so that it owns the host
    /// ports. Left alone the container crash-loops under `restart: always`
    /// and the command fails with `Infrastructure not healthy: step-ca
    /// status=restarting`.
    const INFRA_SERVICES: &str = "openbao,postgres,step-ca,bootroot-http01";

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

    /// Initializes the throwaway CA the step-ca container starts from.
    ///
    /// The generated compose file binds [`step_ca_dir`] where the
    /// repository's file binds `./secrets`, and that directory is empty
    /// until this runs. `step ca init` fills it with the `config/ca.json`,
    /// `certs/` and `secrets/` layout step-ca expects, and writes the
    /// password at the path the compose `command` already points
    /// `--password-file` at, so the service starts unmodified.
    ///
    /// Run through `docker compose run` rather than `docker run` so the
    /// image pin, the `user:` and the mount all come from the compose file
    /// instead of being restated here, where they could drift from it.
    ///
    /// This is not a stand-in for `bootroot init`, and asserts nothing:
    /// the monitoring stack needs step-ca *running* — Prometheus declares
    /// `depends_on` on it, and `infra up` holds it to a readiness check —
    /// and #825 forbids moving this step behind the `init` that would
    /// otherwise provide it. What the CA contains is never inspected.
    fn init_step_ca(project: &str, compose_file: &Path) -> Result<()> {
        let script = format!(
            "set -e\n\
             printf '%s' '{STEP_CA_PASSWORD}' > {STEP_CA_PASSWORD_FILE}\n\
             step ca init \
             --name 'Bootroot Integration Test CA' \
             --dns step-ca --dns localhost \
             --address :9000 \
             --provisioner admin \
             --password-file {STEP_CA_PASSWORD_FILE} \
             --provisioner-password-file {STEP_CA_PASSWORD_FILE}\n"
        );
        let output = run_command(
            docker_compose_command(project, compose_file)
                .args(["run", "--rm", "-T", "--no-deps"])
                .args(["--entrypoint", "/bin/bash", "step-ca", "-c", &script]),
        )
        .context("Failed to run step ca init")?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("step ca init failed: {stderr}");
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
    /// The `step-ca` job is deliberately not asserted. Nothing in this
    /// repository configures step-ca to serve metrics, so `step-ca:9102`
    /// — the target `monitoring/prometheus.yml` scrapes — has never had a
    /// listener, here or in production: step-ca serves metrics only when
    /// its `ca.json` carries a top-level `metricsAddress`, no code writes
    /// that key, `step ca init` does not emit it, the patcher in
    /// `src/commands/init/steps/stepca_setup.rs` touches only `dnsNames`,
    /// `db` and the ACME provisioner, and the pinned binary accepts the
    /// address through no flag or environment variable, so compose cannot
    /// supply it either.
    ///
    /// That is a defect in the monitoring stack rather than in this test,
    /// and closing it means writing `metricsAddress` from `init` — a
    /// production change #825 does not authorise, and one this test could
    /// not benefit from anyway, since the same issue requires it to run
    /// before any `init`. #825 reserves the call for a human, and the
    /// reduction to `openbao` alone is that call, taken under its
    /// escalation clause: the gap is tracked outside this test. Until it
    /// is closed, step-ca has no runtime monitoring coverage.
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
                let job_is_up = |name: &str| {
                    active.iter().any(|target| {
                        let job = target
                            .get("labels")
                            .and_then(|item| item.get("job"))
                            .and_then(|item| item.as_str())
                            .unwrap_or_default();
                        let health = target
                            .get("health")
                            .and_then(|item| item.as_str())
                            .unwrap_or_default();
                        job == name && health == "up"
                    })
                };
                Ok(job_is_up("openbao"))
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

    /// The step-ca bind mount in `docker-compose.yml`, verbatim.
    const STEP_CA_SECRETS_MOUNT: &str = "- ./secrets:/home/step";

    /// Host directory this run's step-ca uses as its `STEPPATH`, relative
    /// to the compose file's directory, which is the repository root.
    ///
    /// Under `tmp/`, which is gitignored, so a run killed before its
    /// teardown leaves an untracked CA nowhere the working tree or a later
    /// job step can trip over it.
    fn step_ca_dir_relative(nonce: u64) -> String {
        format!("./tmp/stepca-itest-{nonce}")
    }

    fn step_ca_dir(nonce: u64) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("tmp/stepca-itest-{nonce}"))
    }

    /// Creates the repository's `secrets/` directory if it is not there
    /// already.
    ///
    /// Nothing in this test's stack mounts it — [`write_test_compose_file`]
    /// moves step-ca's `STEPPATH` elsewhere — but `bootroot infra up`
    /// resolves it on the host regardless: `sweep_secrets_ownership`
    /// canonicalizes the path before running its ownership sweep, and on a
    /// clean checkout, where `secrets/` is gitignored and written by
    /// `bootroot init`, that fails with `Failed to resolve secrets dir: No
    /// such file or directory` long before any readiness check.
    ///
    /// Created here rather than left to the sweep so it belongs to whoever
    /// runs the test: the steps that follow in `test-core` write to this
    /// same path unprivileged.
    ///
    /// Not removed on teardown: on a developer's machine it holds real CA
    /// material, and an empty gitignored directory is not the port or
    /// volume residue the teardown exists to clear.
    fn ensure_secrets_dir() -> Result<()> {
        let secrets = Path::new(env!("CARGO_MANIFEST_DIR")).join("secrets");
        std::fs::create_dir_all(&secrets)
            .with_context(|| format!("Failed to create {}", secrets.display()))
    }

    /// Writes this run's compose file: the repository's own, with the
    /// container names dropped so a nonce-scoped project does not collide
    /// with a live stack, and step-ca's `STEPPATH` moved off `./secrets`.
    ///
    /// The redirect is what keeps [`init_step_ca`] from writing a CA into
    /// `secrets/` — the path `bootroot init` owns, which holds real key
    /// material on a developer's machine and is written by the steps that
    /// follow this one in `test-core`. It also removes the reason the
    /// Docker daemon used to create that directory root-owned when it was
    /// missing: nothing mounts it any more.
    fn write_test_compose_file(nonce: u64) -> Result<PathBuf> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let source = root.join("docker-compose.yml");
        let contents = std::fs::read_to_string(&source)
            .with_context(|| format!("Failed to read {}", source.display()))?;
        let step_ca_mount = format!("- {}:/home/step", step_ca_dir_relative(nonce));
        let mut filtered = String::new();
        let mut redirected = false;
        for line in contents.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("container_name:") {
                continue;
            }
            if trimmed == STEP_CA_SECRETS_MOUNT {
                let indent = &line[..line.len() - trimmed.len()];
                filtered.push_str(indent);
                filtered.push_str(&step_ca_mount);
                filtered.push('\n');
                redirected = true;
                continue;
            }
            filtered.push_str(line);
            filtered.push('\n');
        }
        // Loudly, rather than by silently running step-ca against the real
        // `secrets/`: a rename or a reindent in `docker-compose.yml` would
        // otherwise turn this test into one that writes a CA there.
        anyhow::ensure!(
            redirected,
            "{} no longer contains `{STEP_CA_SECRETS_MOUNT}`; \
             update STEP_CA_SECRETS_MOUNT to match it",
            source.display()
        );
        let target = root.join(format!("docker-compose.itest-{nonce}.yml"));
        std::fs::write(&target, filtered)
            .with_context(|| format!("Failed to write {}", target.display()))?;
        Ok(target)
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
        let step_ca_dir = step_ca_dir(nonce);
        std::fs::create_dir_all(&step_ca_dir)
            .with_context(|| format!("Failed to create {}", step_ca_dir.display()))?;
        let compose_file = write_test_compose_file(nonce)?;
        let _guard = ComposeGuard {
            project: project.clone(),
            compose_file: compose_file.clone(),
            step_ca_dir,
        };

        run_compose_build(&project, &compose_file)?;
        init_step_ca(&project, &compose_file)?;
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
