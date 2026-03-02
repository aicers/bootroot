#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    #[test]
    #[ignore = "Requires local Docker for CA key rotation recovery validation"]
    fn docker_ca_key_rotation_recovery() -> Result<()> {
        let scenario_id = super::support::docker_harness::unique_scenario_id("ca-key-recovery");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-ca-key-recovery-{scenario_id}"));

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::ca_key_rotation_recovery_script_path())
            .env("ARTIFACT_DIR", &artifact_dir)
            .env("PROJECT_NAME", format!("bootroot-e2e-cakr-{scenario_id}"))
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .env("BOOTROOT_REMOTE_BIN", env!("CARGO_BIN_EXE_bootroot-remote"))
            .env("BOOTROOT_AGENT_BIN", env!("CARGO_BIN_EXE_bootroot-agent"))
            .output()
            .with_context(|| "Failed to run CA key rotation recovery script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("CA key rotation recovery script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        assert!(phase_log.exists(), "phases.log should exist");

        let phase_contents = std::fs::read_to_string(&phase_log)
            .with_context(|| "Failed to read CA key rotation recovery phase log")?;

        assert!(phase_contents.contains("\"phase\":\"scenario-1-phase3\""));
        assert!(phase_contents.contains("\"phase\":\"scenario-2-phase4\""));
        assert!(phase_contents.contains("\"phase\":\"scenario-3-partial\""));
        assert!(phase_contents.contains("\"phase\":\"scenario-4-blocked\""));
        assert!(phase_contents.contains("\"phase\":\"scenario-5-trustsync\""));

        let cert_meta_dir = artifact_dir.join("cert-meta");
        assert!(cert_meta_dir.join("edge-proxy-s1-after.txt").exists());
        assert!(cert_meta_dir.join("edge-proxy-s2-after.txt").exists());
        assert!(cert_meta_dir.join("edge-proxy-s3-after.txt").exists());
        assert!(cert_meta_dir.join("edge-proxy-s4-after.txt").exists());
        assert!(cert_meta_dir.join("edge-proxy-s5-after.txt").exists());

        Ok(())
    }
}
