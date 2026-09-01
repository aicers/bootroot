#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    /// Runs the extended-tier registrar renewal endurance scenario.
    ///
    /// This is intentionally not a pull-request gate: it waits beyond the
    /// original six-minute leaves to prove renewal and the unchanged endpoint
    /// anchor pin. It does not model a compromised bootroot host, control
    /// plane, or request handler.
    #[test]
    #[ignore = "Requires Docker, passwordless sudo, strace, and certificate expiry"]
    fn docker_registrar_endurance() -> Result<()> {
        let run_id = format!("endurance-{}", std::process::id());
        let project_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let artifact_dir = project_dir
            .join("tmp/e2e")
            .join(format!("docker-registrar-endurance-{run_id}"));
        std::fs::create_dir_all(&artifact_dir)
            .with_context(|| format!("creating {}", artifact_dir.display()))?;
        let output = Command::new("bash")
            .current_dir(&project_dir)
            .arg(project_dir.join("scripts/impl/run-registrar-endurance.sh"))
            .env("BOOTROOT_PROJECT_DIR", &project_dir)
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .env("ARTIFACT_DIR", &artifact_dir)
            .env("RUN_TOKEN", run_id)
            .output()
            .with_context(|| "running registrar-endurance scenario")?;
        if !output.status.success() {
            anyhow::bail!(
                "registrar-endurance scenario failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}
