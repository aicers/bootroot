#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    /// Closes #737: `init` must not record an `https://` `OpenBao` URL
    /// against a listener that is still serving plaintext.
    ///
    /// `openbao.hcl` is bind-mounted, so Compose does not hash its
    /// contents and a plain `docker compose up -d openbao` recreates the
    /// container only when the *compose configuration* changed — which on
    /// the TLS-transition path meant only when `init` itself was the one
    /// adding the `openbao-exposed` override.  The harness reproduces the
    /// precondition that disarms that reload (the override applied by
    /// hand, while `openbao.hcl` is still plaintext) and asserts the
    /// contracts the fix introduces: the container really was recreated,
    /// the bind address answers over TLS against the local step-ca bundle,
    /// plain HTTP no longer serves the API, `state.json` records the
    /// HTTPS URL, the vault is unsealed when `init` returns, and a
    /// following `service add` succeeds with no manual unseal.
    ///
    /// Marked `#[ignore]` so `cargo test` stays fast; CI invokes the
    /// script directly via `scripts/preflight/ci/e2e-matrix.sh` (and the
    /// `openbao-tls-no-delta` arm of `test-docker-e2e-matrix`).
    #[test]
    #[ignore = "Requires local Docker and a non-loopback bind host (docker0) for the OpenBao TLS transition"]
    fn docker_openbao_tls_transition_without_compose_delta() -> Result<()> {
        let scenario_id =
            super::support::docker_harness::unique_scenario_id("openbao-tls-no-delta");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-openbao-tls-no-delta-{scenario_id}"));

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::openbao_tls_no_delta_script_path())
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "COMPOSE_PROJECT_NAME",
                format!("bootroot-e2e-openbao-tls-no-delta-{scenario_id}"),
            )
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .output()
            .with_context(|| "Failed to run OpenBao TLS no-delta script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("OpenBao TLS no-delta script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        assert!(phase_log.exists(), "missing phase log at {phase_log:?}");
        let phases =
            std::fs::read_to_string(&phase_log).with_context(|| "Failed to read phase log")?;
        // `apply-override-by-hand` is the phase that establishes the
        // no-delta precondition; a run that skipped it would prove
        // nothing about #737 even if every later assertion passed.
        for phase in [
            "install",
            "apply-override-by-hand",
            "init",
            "assert",
            "service-add",
            "done",
        ] {
            assert!(
                phases.contains(&format!("\"phase\":\"{phase}\"")),
                "missing phase {phase} in {phases}"
            );
        }

        // The TLS probe response is the artefact the acceptance criteria
        // name: it exists only when `curl --cacert` (no `-k`) verified the
        // listener certificate against the local step-ca bundle, and its
        // `sealed` field is what proves `init` unsealed after the recreate.
        let seal_status = artifact_dir.join("seal-status-https.json");
        assert!(
            seal_status.exists(),
            "missing HTTPS seal-status response; the TLS probe never succeeded"
        );
        let body = std::fs::read_to_string(&seal_status)
            .with_context(|| "Failed to read HTTPS seal-status response")?;
        let parsed: serde_json::Value =
            serde_json::from_str(&body).with_context(|| "HTTPS seal-status is not JSON")?;
        assert_eq!(
            parsed.get("sealed").and_then(serde_json::Value::as_bool),
            Some(false),
            "OpenBao is not unsealed after init returned: {body}"
        );

        Ok(())
    }
}
