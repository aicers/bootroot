#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    /// `infra install --postgres-user <uid>:<gid>` must run step-ca's
    /// `PostgreSQL` as that host account, re-own its data volume to it,
    /// hand it its TLS key at `<uid>:0 0600`, and keep doing so for every
    /// caller of `docker compose` and across a renewal.
    ///
    /// The harness sets up as the `openbao-user` arm does — an account
    /// owning a fresh `secrets/` at `0700`, given to `--openbao-user`,
    /// with bootroot run as root — and creates a second account for
    /// `--postgres-user`. It installs and initialises without the option
    /// and asserts uid 999, writes a marker row, adopts the option with a
    /// second `infra install` and an `infra up`, and asserts the
    /// processes, the data directory, the key, TLS on every session and
    /// the marker. It then recreates `PostgreSQL` from the base compose
    /// file alone, runs `rotate infra-cert`, and finally has both
    /// entrypoints refuse a malformed value written into `.env` by hand.
    ///
    /// Marked `#[ignore]` so `cargo test` stays fast; CI invokes the
    /// script directly via `scripts/preflight/ci/e2e-matrix.sh` (and the
    /// `postgres-user` arm of `test-docker-e2e-matrix`).
    #[test]
    #[ignore = "Requires Linux, local Docker, non-interactive sudo, and a non-loopback bind host (docker0)"]
    fn docker_postgres_runs_as_the_given_user() -> Result<()> {
        let scenario_id = super::support::docker_harness::unique_scenario_id("postgres-user");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-postgres-user-{scenario_id}"));

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::postgres_user_script_path())
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "COMPOSE_PROJECT_NAME",
                format!("bootroot-e2e-postgres-user-{scenario_id}"),
            )
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .output()
            .with_context(|| "Failed to run PostgreSQL user script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("PostgreSQL user script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        assert!(phase_log.exists(), "missing phase log at {phase_log:?}");
        let phases =
            std::fs::read_to_string(&phase_log).with_context(|| "Failed to read phase log")?;
        for phase in [
            "create-accounts",
            "prepare-secrets",
            "install",
            "init",
            "assert-healthy",
            "assert-default-user",
            "write-marker",
            "install-postgres-user",
            "infra-up",
            "assert-postgres-user",
            "recreate-base-only",
            "infra-up-again",
            "rotate-infra-cert",
            "assert-rotated",
            "entrypoint-refusal",
            "assert-untouched",
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
