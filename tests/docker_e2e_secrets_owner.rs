#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    /// A root-run `infra install` and `init` over a `secrets/` owned by
    /// a dedicated non-root account must leave every entry under
    /// `secrets/` that account's and every directory there `0700`.
    ///
    /// The harness creates the account, hands it a fresh `secrets/` at
    /// `0700` before bootroot touches anything, runs `infra install` with
    /// the `OpenBao`, step-ca and HTTP-01 admin binds and then `init
    /// --save-unseal-keys` as root, and asserts the owner and mode of
    /// what each left: the override directories straight after `infra
    /// install`, before `init` re-modes the tree, and the whole tree once
    /// the stack is healthy.  Root over a tree another account owns is
    /// the case in which bootroot's writes there walk from the tree's
    /// descriptor and follow no name, so this is what exercises them.
    ///
    /// Marked `#[ignore]` so `cargo test` stays fast; CI invokes the
    /// script directly via `scripts/preflight/ci/e2e-matrix.sh` (and the
    /// `secrets-owner` arm of `test-docker-e2e-matrix`).
    #[test]
    #[ignore = "Requires Linux, local Docker, non-interactive sudo, and a non-loopback bind host (docker0)"]
    fn docker_root_run_keeps_secrets_under_its_owner() -> Result<()> {
        let scenario_id = super::support::docker_harness::unique_scenario_id("secrets-owner");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-secrets-owner-{scenario_id}"));

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::secrets_owner_script_path())
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "COMPOSE_PROJECT_NAME",
                format!("bootroot-e2e-secrets-owner-{scenario_id}"),
            )
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .output()
            .with_context(|| "Failed to run secrets owner script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("secrets owner script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        assert!(phase_log.exists(), "missing phase log at {phase_log:?}");
        let phases =
            std::fs::read_to_string(&phase_log).with_context(|| "Failed to read phase log")?;
        // `assert-install` is the only point at which the mode `infra
        // install` leaves is observable, and `assert-secrets-tree` is the
        // contract itself; a run that skipped either proves nothing.
        for phase in [
            "create-account",
            "prepare-secrets",
            "install",
            "assert-install",
            "init",
            "assert-healthy",
            "assert-secrets-tree",
            "done",
        ] {
            assert!(
                phases.contains(&format!("\"phase\":\"{phase}\"")),
                "missing phase {phase} in {phases}"
            );
        }

        Ok(())
    }
}
