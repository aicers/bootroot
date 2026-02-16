#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use anyhow::{Context, Result};

    fn run_baseline_scenario(file_name: &str) -> Result<PathBuf> {
        let scenario_id = super::support::docker_harness::unique_scenario_id("baseline");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-baseline-{scenario_id}"));
        let scenario_file = super::support::docker_harness::baseline_scenario_path(file_name);

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::baseline_script_path())
            .env("SCENARIO_FILE", &scenario_file)
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "PROJECT_NAME",
                format!("bootroot-e2e-baseline-{scenario_id}"),
            )
            .env("MAX_CYCLES", "2")
            .env("INTERVAL_SECS", "1")
            .env("TIMEOUT_SECS", "45")
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .env("BOOTROOT_REMOTE_BIN", env!("CARGO_BIN_EXE_bootroot-remote"))
            .output()
            .with_context(|| "Failed to run docker baseline matrix script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("baseline script failed: {stderr}");
        }

        assert_common_artifacts(&artifact_dir)?;
        Ok(artifact_dir)
    }

    fn assert_common_artifacts(artifact_dir: &Path) -> Result<()> {
        let phase_log = artifact_dir.join("phases.log");
        let runner_log = artifact_dir.join("runner.log");
        let layout_file = artifact_dir.join("layout-final.json");
        let compose_ps = artifact_dir.join("compose-ps.log");
        assert!(phase_log.exists());
        assert!(runner_log.exists());
        assert!(layout_file.exists());
        assert!(compose_ps.exists());

        let phase_contents = std::fs::read_to_string(&phase_log)
            .with_context(|| "Failed to read baseline phase log")?;
        assert!(phase_contents.contains("\"phase\":\"bootstrap\""));
        assert!(phase_contents.contains("\"phase\":\"runner-start\""));
        assert!(phase_contents.contains("\"phase\":\"sync-loop\""));
        assert!(phase_contents.contains("\"phase\":\"ack\""));
        assert!(phase_contents.contains("\"phase\":\"verify\""));
        assert!(phase_contents.contains("\"phase\":\"cleanup\""));

        let layout_contents = std::fs::read_to_string(layout_file)
            .with_context(|| "Failed to read baseline layout")?;
        assert!(layout_contents.contains("\"services\""));
        assert!(layout_contents.contains("\"nodes\""));

        Ok(())
    }

    #[test]
    #[ignore = "Requires local Docker for baseline matrix validation"]
    fn docker_baseline_matrix_scenarios_a_b_c() -> Result<()> {
        let scenario_files = [
            "scenario-a-single-node-mixed.json",
            "scenario-b-multi-node-distributed.json",
            "scenario-c-multi-node-uneven.json",
        ];
        for scenario in scenario_files {
            let artifact_dir = run_baseline_scenario(scenario)?;
            let layout = std::fs::read_to_string(artifact_dir.join("layout-final.json"))
                .with_context(|| format!("Failed to read layout for {scenario}"))?;
            assert!(layout.contains("\"services\""));
            assert!(layout.contains("\"nodes\""));
        }
        Ok(())
    }
}
