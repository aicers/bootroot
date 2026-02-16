#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;
    use std::time::{SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result};

    fn unique_id() -> String {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        format!("harness-{now}")
    }

    fn smoke_script_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("scripts")
            .join("e2e")
            .join("docker")
            .join("run-harness-smoke.sh")
    }

    #[test]
    #[ignore = "Requires local Docker for E2E harness validation"]
    fn docker_harness_smoke_generates_artifacts() -> Result<()> {
        let scenario_id = unique_id();
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-smoke-{scenario_id}"));

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(smoke_script_path())
            .env("SCENARIO_ID", &scenario_id)
            .env("PROJECT_NAME", format!("bootroot-e2e-{scenario_id}"))
            .env("ARTIFACT_DIR", &artifact_dir)
            .env("MAX_CYCLES", "2")
            .env("INTERVAL_SECS", "1")
            .env("TIMEOUT_SECS", "20")
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .env("BOOTROOT_REMOTE_BIN", env!("CARGO_BIN_EXE_bootroot-remote"))
            .output()
            .with_context(|| "Failed to run docker harness smoke script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("harness smoke script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        let runner_log = artifact_dir.join("runner.log");
        let manifest = artifact_dir.join("manifest.json");
        let state_snapshot = artifact_dir.join("state-final.json");
        assert!(phase_log.exists());
        assert!(runner_log.exists());
        assert!(manifest.exists());
        assert!(state_snapshot.exists());

        let phase_contents =
            std::fs::read_to_string(&phase_log).with_context(|| "Failed to read phase log")?;
        assert!(phase_contents.contains("\"phase\":\"bootstrap\""));
        assert!(phase_contents.contains("\"phase\":\"runner-start\""));
        assert!(phase_contents.contains("\"phase\":\"sync-loop\""));
        assert!(phase_contents.contains("\"phase\":\"ack\""));
        assert!(phase_contents.contains("\"phase\":\"verify\""));
        assert!(phase_contents.contains("\"phase\":\"cleanup\""));

        let state_contents =
            std::fs::read_to_string(state_snapshot).with_context(|| "Failed to read state")?;
        assert!(state_contents.contains("\"secret_id\": \"applied\""));
        assert!(state_contents.contains("\"eab\": \"applied\""));
        assert!(state_contents.contains("\"responder_hmac\": \"applied\""));
        assert!(state_contents.contains("\"trust_sync\": \"applied\""));

        Ok(())
    }
}
