#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    /// `infra install --openbao-user <uid>:<gid>` must run `OpenBao` as
    /// that host account, hand it its TLS key at `<uid>:0 0600`, and keep
    /// doing so for every caller of `docker compose`.
    ///
    /// The harness creates an account, hands it a fresh `secrets/` at
    /// `0700`, runs `infra install --openbao-user` with the `OpenBao`,
    /// step-ca and HTTP-01 admin binds and `init --save-unseal-keys` as
    /// root, and asserts the processes of `OpenBao`, step-ca and both
    /// Agent sidecars, the key's owner and mode, and the `secrets/` tree.
    /// It then recreates `OpenBao` from the base compose file alone,
    /// starts it once over a scratch audit directory to assert what the
    /// entrypoint re-owns there and what it leaves, and finishes with an
    /// `infra up` that must bring `OpenBao` back unsealed as the account.
    ///
    /// Marked `#[ignore]` so `cargo test` stays fast; CI invokes the
    /// script directly via `scripts/preflight/ci/e2e-matrix.sh` (and the
    /// `openbao-user` arm of `test-docker-e2e-matrix`).
    #[test]
    #[ignore = "Requires Linux, local Docker, non-interactive sudo, and a non-loopback bind host (docker0)"]
    fn docker_openbao_runs_as_the_given_user() -> Result<()> {
        let scenario_id = super::support::docker_harness::unique_scenario_id("openbao-user");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-openbao-user-{scenario_id}"));

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::openbao_user_script_path())
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "COMPOSE_PROJECT_NAME",
                format!("bootroot-e2e-openbao-user-{scenario_id}"),
            )
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .output()
            .with_context(|| "Failed to run OpenBao user script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("OpenBao user script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        assert!(phase_log.exists(), "missing phase log at {phase_log:?}");
        let phases =
            std::fs::read_to_string(&phase_log).with_context(|| "Failed to read phase log")?;
        for phase in [
            "create-account",
            "prepare-secrets",
            "install",
            "init",
            "assert-healthy",
            "assert-processes",
            "assert-tls-key",
            "assert-secrets-tree",
            "recreate-base-only",
            "audit-dir",
            "infra-up",
            "assert-unsealed",
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
