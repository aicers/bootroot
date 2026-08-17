#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    /// Closes #733: step-ca's own serving certificate must carry the
    /// address `--stepca-bind` publishes it on, otherwise every off-host
    /// consumer fails hostname verification against the ACME directory.
    ///
    /// Drives both paths the issue names — a fresh install that already
    /// carries the bind intent, and an already-initialized CA repaired
    /// by a second `bootroot init` — and asserts the presented
    /// certificate carries an `IP Address` SAN plus a working
    /// `curl --cacert` fetch of the ACME directory.  The repair path
    /// additionally re-checks the name set after a full `OpenBao` Agent
    /// render interval, because the step-ca sidecar re-renders `ca.json`
    /// from its template and would otherwise silently regress it.
    ///
    /// Also covers #864, which rides on the same co-ownership: `init`
    /// writes the top-level `metricsAddress` step-ca needs before it
    /// will serve `/metrics` at all, and the script asserts both that
    /// the value survives a real sidecar render and that the endpoint
    /// answers from inside the Compose network — where the port is
    /// reachable — rather than from the host, where it is not published.
    /// On the clean install it also brings Prometheus up and waits for
    /// the `step-ca` job the bundled scrape config has always declared
    /// to report `up`.
    #[test]
    #[ignore = "Requires local Docker and a non-loopback bind host for step-ca SAN validation"]
    fn docker_stepca_san_bind_and_repair() -> Result<()> {
        let scenario_id = super::support::docker_harness::unique_scenario_id("stepca-san");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-stepca-san-{scenario_id}"));

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::stepca_san_script_path())
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "COMPOSE_PROJECT_NAME",
                format!("bootroot-e2e-stepca-san-{scenario_id}"),
            )
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .output()
            .with_context(|| "Failed to run docker step-ca SAN script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("step-ca SAN script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        assert!(phase_log.exists());
        let phases =
            std::fs::read_to_string(&phase_log).with_context(|| "Failed to read phase log")?;
        for phase in [
            "scenario-a-install",
            "scenario-a-init",
            "scenario-a-assert",
            "scenario-b-install-loopback",
            "scenario-b-init-loopback",
            "scenario-b-install-bind",
            "scenario-b-init-repair",
            "scenario-b-assert",
            "scenario-b-assert-stable",
        ] {
            assert!(
                phases.contains(&format!("\"phase\":\"{phase}\"")),
                "missing phase {phase} in {phases}"
            );
        }

        // The SAN dumps are the artefact the acceptance criteria name;
        // keep them asserted here so a script that silently stopped
        // short of the certificate checks cannot pass.
        let cert_meta = artifact_dir.join("cert-meta");
        for label in ["scenario-a", "scenario-b"] {
            let san_file = cert_meta.join(format!("{label}-stepca-san.txt"));
            assert!(san_file.exists(), "missing SAN dump for {label}");
            let san = std::fs::read_to_string(&san_file)
                .with_context(|| format!("Failed to read SAN dump for {label}"))?;
            assert!(
                san.contains("IP Address:"),
                "{label} step-ca certificate carries no IP SAN: {san}"
            );
        }

        // The metrics dumps are the #864 artefact, and asserting them
        // here is what stops a script that skipped the scrape from
        // passing: the endpoint is fetched from inside the Compose
        // network, so nothing on the host can produce this file.
        for label in ["scenario-a", "scenario-b"] {
            let metrics = artifact_dir.join(format!("stepca-metrics-{label}.txt"));
            assert!(metrics.exists(), "missing step-ca metrics dump for {label}");
            let body = std::fs::read_to_string(&metrics)
                .with_context(|| format!("Failed to read step-ca metrics for {label}"))?;
            assert!(
                body.lines().any(|line| line.starts_with("# HELP ")),
                "{label} step-ca /metrics returned no Prometheus exposition data: {body}"
            );
        }

        // Prometheus's own view of the same endpoint, on the clean
        // install. The endpoint answering and the declared scrape target
        // resolving to it are two claims, and the operator reads the
        // second one.
        let targets = artifact_dir.join("prometheus-targets-scenario-a.json");
        assert!(targets.exists(), "missing Prometheus targets dump");
        let body = std::fs::read_to_string(&targets)
            .with_context(|| "Failed to read Prometheus targets dump")?;
        let parsed: serde_json::Value =
            serde_json::from_str(&body).with_context(|| "Prometheus targets dump is not JSON")?;
        let step_ca_is_up = parsed["data"]["activeTargets"]
            .as_array()
            .map(Vec::as_slice)
            .unwrap_or_default()
            .iter()
            .any(|target| target["labels"]["job"] == "step-ca" && target["health"] == "up");
        assert!(
            step_ca_is_up,
            "Prometheus did not report the step-ca scrape target as up: {body}"
        );

        for label in ["scenario-a", "scenario-b"] {
            let directory = artifact_dir.join(format!("acme-directory-{label}.json"));
            assert!(
                directory.exists(),
                "missing ACME directory response for {label}"
            );
            let body = std::fs::read_to_string(&directory)
                .with_context(|| format!("Failed to read ACME directory for {label}"))?;
            assert!(
                body.contains("newNonce"),
                "{label} ACME directory response is not a directory: {body}"
            );
        }

        Ok(())
    }
}
