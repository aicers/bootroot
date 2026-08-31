#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    /// Runs the per-PR registrar credential-boundary scenario.
    ///
    /// The Docker scenario owns live `OpenBao`, process-boundary and
    /// root-owned-socket assertions. Ordinary endpoint round trips remain in
    /// cargo tests and renewal past expiry remains in the endurance suite.
    ///
    /// It always invokes the launcher without positional arguments and passes
    /// the checked-out project root, this checkout's binary, and a unique
    /// writable artifact directory explicitly. The launcher stages only the
    /// manifest-defined registrar leak bundle; it does not inspect daemon
    /// material or the surrounding host filesystem.
    #[test]
    #[ignore = "Requires Docker, root-owned socket activation, and a live OpenBao"]
    fn docker_registrar_redteam() -> Result<()> {
        let run_id = format!("redteam-{}", std::process::id());
        let project_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let artifact_dir = project_dir
            .join("tmp/e2e")
            .join(format!("docker-registrar-redteam-{run_id}"));
        std::fs::create_dir_all(&artifact_dir)
            .with_context(|| format!("creating {}", artifact_dir.display()))?;
        let output = Command::new("bash")
            .current_dir(&project_dir)
            .arg(project_dir.join("scripts/impl/run-registrar-redteam.sh"))
            .env("BOOTROOT_PROJECT_DIR", &project_dir)
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .env("ARTIFACT_DIR", &artifact_dir)
            .env("RUN_TOKEN", run_id)
            .output()
            .with_context(|| "running registrar-redteam scenario")?;
        if !output.status.success() {
            anyhow::bail!(
                "registrar-redteam scenario failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Ok(())
    }
}
