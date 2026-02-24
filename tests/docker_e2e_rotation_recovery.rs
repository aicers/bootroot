#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    #[test]
    #[ignore = "Requires local Docker for rotation/recovery matrix validation"]
    fn docker_rotation_recovery_matrix_scenario_c() -> Result<()> {
        let scenario_id = super::support::docker_harness::unique_scenario_id("rotation");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-rotation-{scenario_id}"));
        let scenario_file = super::support::docker_harness::baseline_scenario_path(
            "scenario-c-multi-node-uneven.json",
        );

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("scripts")
                    .join("impl")
                    .join("run-rotation-recovery.sh"),
            )
            .env("SCENARIO_FILE", scenario_file)
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "PROJECT_NAME",
                format!("bootroot-e2e-rotation-{scenario_id}"),
            )
            .env("TIMEOUT_SECS", "60")
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .env("BOOTROOT_REMOTE_BIN", env!("CARGO_BIN_EXE_bootroot-remote"))
            .output()
            .with_context(|| "Failed to run docker rotation/recovery script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("rotation/recovery script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        let manifest = artifact_dir.join("rotation-manifest.json");
        let snapshots_dir = artifact_dir.join("snapshots");
        assert!(phase_log.exists());
        assert!(manifest.exists());
        assert!(snapshots_dir.exists());

        let phase_contents = std::fs::read_to_string(phase_log)
            .with_context(|| "Failed to read rotation phase log")?;
        assert!(phase_contents.contains("\"phase\":\"bootstrap\""));
        assert!(phase_contents.contains("\"phase\":\"rotate\""));
        assert!(phase_contents.contains("\"phase\":\"renew\""));
        assert!(phase_contents.contains("\"phase\":\"verify\""));
        assert!(phase_contents.contains("\"rotation_item\":\"secret_id\""));
        assert!(phase_contents.contains("\"rotation_item\":\"trust_sync\""));

        Ok(())
    }
}
