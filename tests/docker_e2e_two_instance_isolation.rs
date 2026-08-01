#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    /// Closes #747: two bootroot installs on one host must stay
    /// independent.
    ///
    /// Before the instance identity existed, a second install adopted the
    /// first install's containers — Compose reported the first instance's
    /// `OpenBao` Agent sidecars as orphans and recreated its already
    /// initialised `OpenBao` against the wrong storage volume and unseal
    /// keys.  A regression does not surface as a crash but as another
    /// team's CA quietly losing its state, so it needs two live Compose
    /// projects on one real daemon rather than the fake-`docker` argv
    /// assertions in `tests/bootroot_cli.rs`.
    ///
    /// Marked `#[ignore]` so `cargo test` stays fast; CI invokes the
    /// script directly via `scripts/preflight/ci/e2e-matrix.sh` (and the
    /// `two-instance` arm of `test-docker-e2e-matrix`).
    #[test]
    #[ignore = "Requires local Docker and brings up two full bootroot stacks"]
    fn docker_two_co_located_instances_stay_independent() -> Result<()> {
        // The script sanitises the token to `[a-z0-9]` and both derived
        // instance names must stay inside the 39-character limit, so keep
        // the prefix short.
        let scenario_id = super::support::docker_harness::unique_scenario_id("ti");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-two-instance-{scenario_id}"));

        // Deliberately no `COMPOSE_PROJECT_NAME`, unlike every other
        // harness in this directory: this scenario has to resolve each
        // instance's project from that instance's own `.env`, and a
        // caller-supplied project name would collapse both installs into
        // one and quietly reduce the run to a single-instance test.
        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::two_instance_isolation_script_path())
            .env("ARTIFACT_DIR", &artifact_dir)
            .env("RUN_TOKEN", &scenario_id)
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .output()
            .with_context(|| "Failed to run two-instance isolation script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("two-instance isolation script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        assert!(phase_log.exists(), "missing phase log at {phase_log:?}");
        let phases =
            std::fs::read_to_string(&phase_log).with_context(|| "Failed to read phase log")?;
        // `assert-a-survived-b-install` and `assert-a-survived-b-teardown`
        // are the two continuity gates; `dns-alias-containment` is the one
        // cross-instance path that would not announce itself as a Docker
        // name conflict.  A run that skipped any of them would prove
        // nothing about #747 even if every other assertion passed.
        for phase in [
            "prepare",
            "assert-a-installed",
            "snapshot-a",
            "assert-a-survived-b-install",
            "assert-b-installed",
            "assert-disjoint",
            "dns-alias-containment",
            "teardown-b",
            "assert-a-survived-b-teardown",
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
