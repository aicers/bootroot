#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use anyhow::{Context, Result};

    /// Phases the harness must log, in the order it runs them.  A
    /// scenario that was skipped or died half-way leaves a gap here, so
    /// the wrapper fails rather than trusting the script's exit status
    /// alone.
    const REQUIRED_PHASES: &[&str] = &[
        "scenario-a-install",
        "scenario-a-init",
        "scenario-a-assert",
        "scenario-b-install-loopback",
        "scenario-b-init-loopback",
        "scenario-b-install-bind",
        "scenario-b-init-repair",
        "scenario-b-assert",
        "scenario-b-assert-stable",
        "scenario-c-strip-metrics",
        "scenario-c-init-upgrade",
        "scenario-c-assert",
        "scenario-c-assert-stable",
    ];

    fn assert_phases_logged(artifact_dir: &Path) -> Result<()> {
        let phase_log = artifact_dir.join("phases.log");
        assert!(phase_log.exists(), "missing phase log");
        let phases =
            std::fs::read_to_string(&phase_log).with_context(|| "Failed to read phase log")?;
        for phase in REQUIRED_PHASES {
            assert!(
                phases.contains(&format!("\"phase\":\"{phase}\"")),
                "missing phase {phase} in {phases}"
            );
        }
        Ok(())
    }

    /// The SAN dumps are the artefact #733's acceptance criteria name;
    /// keeping them asserted here is what stops a script that silently
    /// stopped short of the certificate checks from passing.
    fn assert_ip_sans(artifact_dir: &Path) -> Result<()> {
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
        Ok(())
    }

    /// The metrics dumps are the #864 artefact: the endpoint is fetched
    /// from inside the Compose network, so nothing running on the host
    /// can produce these files.
    ///
    /// Scenario C contributes two of them, and both matter.  Its
    /// baseline is step-ca restarted onto a `ca.json` stripped of
    /// `metricsAddress`; without it, the scenario's own dump would prove
    /// only that a listener from an earlier boot outlived the edit.  The
    /// endpoint going away and then coming back is what attributes it to
    /// `init`.
    fn assert_metrics_dumps(artifact_dir: &Path) -> Result<()> {
        for label in ["scenario-a", "scenario-b", "scenario-c"] {
            let metrics = artifact_dir.join(format!("stepca-metrics-{label}.txt"));
            assert!(metrics.exists(), "missing step-ca metrics dump for {label}");
            let body = std::fs::read_to_string(&metrics)
                .with_context(|| format!("Failed to read step-ca metrics for {label}"))?;
            assert!(
                body.lines().any(|line| line.starts_with("# HELP ")),
                "{label} step-ca /metrics returned no Prometheus exposition data: {body}"
            );
        }

        let baseline = artifact_dir.join("stepca-metrics-scenario-c-baseline.txt");
        assert!(
            baseline.exists(),
            "missing step-ca metrics baseline dump for scenario-c"
        );
        let baseline_body = std::fs::read_to_string(&baseline)
            .with_context(|| "Failed to read step-ca metrics baseline for scenario-c")?;
        assert!(
            !baseline_body
                .lines()
                .any(|line| line.starts_with("# HELP ")),
            "step-ca still served metrics without metricsAddress: {baseline_body}"
        );
        Ok(())
    }

    /// Prometheus's own view of the same endpoint, on the clean install.
    /// The endpoint answering and the declared scrape target resolving
    /// to it are two claims, and the operator reads the second one.
    fn assert_prometheus_reports_stepca_up(artifact_dir: &Path) -> Result<()> {
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
        Ok(())
    }

    fn assert_acme_directories(artifact_dir: &Path) -> Result<()> {
        for label in ["scenario-a", "scenario-b", "scenario-c"] {
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
    ///
    /// A third scenario isolates the upgrade every existing installation
    /// takes: with `dnsNames` already settled, the only thing an `init`
    /// moves is the metrics address, and the listener still has to come
    /// back without the CA material being replaced.  The first two
    /// scenarios both change the name set, so neither can tell that gate
    /// from the one beside it.
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

        assert_phases_logged(&artifact_dir)?;
        assert_ip_sans(&artifact_dir)?;
        assert_metrics_dumps(&artifact_dir)?;
        assert_prometheus_reports_stepca_up(&artifact_dir)?;
        assert_acme_directories(&artifact_dir)?;

        Ok(())
    }
}
