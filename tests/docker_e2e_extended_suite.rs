#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    #[test]
    #[ignore = "Requires local Docker for extended E2E suite validation"]
    fn docker_extended_suite_scenario_c() -> Result<()> {
        let scenario_id = super::support::docker_harness::unique_scenario_id("extended");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-extended-{scenario_id}"));
        let scenario_file = super::support::docker_harness::baseline_scenario_path(
            "scenario-c-multi-node-uneven.json",
        );

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("scripts")
                    .join("e2e")
                    .join("docker")
                    .join("run-extended-suite.sh"),
            )
            .env("SCENARIO_FILE", scenario_file)
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "PROJECT_PREFIX",
                format!("bootroot-e2e-extended-{scenario_id}"),
            )
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .env("BOOTROOT_REMOTE_BIN", env!("CARGO_BIN_EXE_bootroot-remote"))
            .output()
            .with_context(|| "Failed to run docker extended suite script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("extended suite script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        let summary = artifact_dir.join("extended-summary.json");
        assert!(phase_log.exists());
        assert!(summary.exists());

        let phase_contents = std::fs::read_to_string(&phase_log)
            .with_context(|| "Failed to read extended phases")?;
        assert!(phase_contents.contains("\"phase\":\"scale-contention\""));
        assert!(phase_contents.contains("\"phase\":\"failure-recovery\""));
        assert!(phase_contents.contains("\"phase\":\"runner-timer\""));
        assert!(phase_contents.contains("\"phase\":\"runner-cron\""));

        Ok(())
    }
}
