#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    /// Docker-backed E2E coverage for `bootroot reinit` recovery,
    /// per the §"Acceptance criteria" of issue #600.  Drives the
    /// harness through all three #598-derived failure modes and
    /// asserts the recovery contracts (fingerprint preservation,
    /// `password.txt` preservation, non-loopback bind survival,
    /// empty service registry) after each scenario.  Marked
    /// `#[ignore]` so `cargo test` stays fast; CI invokes the
    /// script directly via `scripts/preflight/ci/e2e-matrix.sh`
    /// (and the corresponding workflow job).
    #[test]
    #[ignore = "Requires local Docker for reinit recovery validation"]
    fn docker_reinit_recovery_matrix() -> Result<()> {
        let scenario_id = super::support::docker_harness::unique_scenario_id("reinit-recovery");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-reinit-recovery-{scenario_id}"));

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::reinit_recovery_script_path())
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "COMPOSE_PROJECT_NAME",
                format!("bootroot-e2e-reinit-{scenario_id}"),
            )
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .output()
            .with_context(|| "Failed to run reinit recovery script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("reinit recovery script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        assert!(phase_log.exists(), "phases.log should exist");
        let phases = std::fs::read_to_string(&phase_log)
            .with_context(|| "Failed to read reinit recovery phases log")?;

        for required in [
            "\"phase\":\"bootstrap-install\"",
            "\"phase\":\"bootstrap-init\"",
            "\"phase\":\"scenario-a-clean-openbao-only\"",
            "\"phase\":\"reinit-scenario-a\"",
            "\"phase\":\"scenario-b-no-root-token\"",
            "\"phase\":\"reinit-scenario-b\"",
            "\"phase\":\"scenario-c-rsync-clone\"",
            "\"phase\":\"reinit-scenario-c\"",
            "\"phase\":\"done\"",
        ] {
            assert!(
                phases.contains(required),
                "phases.log missing expected entry: {required}"
            );
        }

        let snapshots = artifact_dir.join("snapshots");
        for label in ["scenario-a", "scenario-b", "scenario-c"] {
            assert!(snapshots.join(label).join("password.txt").exists());
            assert!(snapshots.join(label).join("root_ca.fingerprint").exists());
            assert!(
                snapshots
                    .join(label)
                    .join("intermediate_ca.fingerprint")
                    .exists()
            );
        }

        Ok(())
    }
}
