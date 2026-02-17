#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    fn run_mode(mode: &str) -> Result<PathBuf> {
        let scenario_id =
            super::support::docker_harness::unique_scenario_id("main-remote-lifecycle");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-main-remote-lifecycle-{mode}-{scenario_id}"));

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::main_remote_lifecycle_script_path())
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "PROJECT_NAME",
                format!("bootroot-e2e-main-remote-lifecycle-{mode}-{scenario_id}"),
            )
            .env("RESOLUTION_MODE", mode)
            .env("TIMEOUT_SECS", "120")
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .env("BOOTROOT_REMOTE_BIN", env!("CARGO_BIN_EXE_bootroot-remote"))
            .env("BOOTROOT_AGENT_BIN", env!("CARGO_BIN_EXE_bootroot-agent"))
            .output()
            .with_context(|| "Failed to run docker main remote lifecycle script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("main remote lifecycle script failed ({mode}): {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        let cert_meta = artifact_dir.join("cert-meta");
        assert!(phase_log.exists());
        assert!(cert_meta.exists());

        let phase_contents =
            std::fs::read_to_string(phase_log).with_context(|| "Failed to read phase log")?;
        assert!(phase_contents.contains("\"phase\":\"infra-up\""));
        assert!(phase_contents.contains("\"phase\":\"init\""));
        assert!(phase_contents.contains("\"phase\":\"service-add\""));
        assert!(phase_contents.contains("\"phase\":\"sync-initial\""));
        assert!(phase_contents.contains("\"phase\":\"verify-initial\""));
        assert!(phase_contents.contains("\"phase\":\"rotate-responder-hmac\""));
        assert!(phase_contents.contains("\"phase\":\"sync-after-rotate\""));
        assert!(phase_contents.contains("\"phase\":\"cleanup\""));

        let initial = cert_meta.join("edge-proxy-initial.txt");
        let after_hmac = cert_meta.join("edge-proxy-after-responder-hmac.txt");
        assert!(initial.exists());
        assert!(after_hmac.exists());

        Ok(artifact_dir)
    }

    #[test]
    #[ignore = "Requires local Docker and root-level hosts updates for hosts-all mode"]
    fn docker_main_remote_lifecycle_hosts_variants() -> Result<()> {
        for mode in ["fqdn-only-hosts", "hosts-all"] {
            let artifact_dir = run_mode(mode)?;
            let phase_log = std::fs::read_to_string(artifact_dir.join("phases.log"))
                .with_context(|| format!("Failed to read phase log for mode={mode}"))?;
            assert!(phase_log.contains(mode));
        }
        Ok(())
    }
}
