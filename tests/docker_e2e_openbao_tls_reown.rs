#[cfg(unix)]
mod support;

#[cfg(unix)]
mod unix_integration {
    use std::path::PathBuf;
    use std::process::Command;

    use anyhow::{Context, Result};

    /// Closes #739: re-issuing the `OpenBao` TLS server certificate must
    /// survive `secrets/` changing owner after `init`.
    ///
    /// `openbao/tls` is a sibling of `secrets/`, so the secrets-ownership
    /// sweep never reaches it: the directory keeps the uid the host
    /// bootroot process created it with and its files keep the uid the
    /// `step` container wrote them as.  Once an operator or an external
    /// installer re-owns the secrets tree — the supported shape that lets
    /// the `OpenBao` Agent sidecars run under a different uid — the next
    /// `rotate infra-cert` runs the `step` container as the new uid
    /// against a directory and files still owned by the old one and dies
    /// with `open /output/server.key: permission denied`.
    ///
    /// The harness reproduces that precondition (a full `init`, then a
    /// `chown -R` of `secrets/` to a foreign uid) and asserts the
    /// contracts the fix introduces: the rotation exits zero,
    /// `openbao/tls` and its files end up owned by the new `secrets/`
    /// owner at mode `0644`, `server.crt` carries a fresh serial, the
    /// listener serves the leaf that is now on disk, and a second
    /// rotation on the unchanged deployment still succeeds.
    ///
    /// Marked `#[ignore]` so `cargo test` stays fast; CI invokes the
    /// script directly via `scripts/preflight/ci/e2e-matrix.sh` (and the
    /// `openbao-tls-reown` arm of `test-docker-e2e-matrix`).
    #[test]
    #[ignore = "Requires local Docker, non-interactive sudo, and a non-loopback bind host (docker0)"]
    fn docker_openbao_tls_reissue_after_secrets_reown() -> Result<()> {
        let scenario_id = super::support::docker_harness::unique_scenario_id("openbao-tls-reown");
        let artifact_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tmp")
            .join("e2e")
            .join(format!("docker-openbao-tls-reown-{scenario_id}"));

        let output = Command::new("bash")
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .arg(super::support::docker_harness::openbao_tls_reown_script_path())
            .env("ARTIFACT_DIR", &artifact_dir)
            .env(
                "COMPOSE_PROJECT_NAME",
                format!("bootroot-e2e-openbao-tls-reown-{scenario_id}"),
            )
            .env("BOOTROOT_BIN", env!("CARGO_BIN_EXE_bootroot"))
            .output()
            .with_context(|| "Failed to run OpenBao TLS re-own script")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("OpenBao TLS re-own script failed: {stderr}");
        }

        let phase_log = artifact_dir.join("phases.log");
        assert!(phase_log.exists(), "missing phase log at {phase_log:?}");
        let phases =
            std::fs::read_to_string(&phase_log).with_context(|| "Failed to read phase log")?;
        // `reown-secrets` is the phase that establishes the ownership
        // skew; a run that skipped it would prove nothing about #739 even
        // if every later assertion passed.  `rotate-second` is what pins
        // the chown being a no-op on an already-correct tree.
        for phase in [
            "install",
            "init",
            "assert-post-init",
            "reown-secrets",
            "rotate-first",
            "assert-first",
            "rotate-second",
            "assert-second",
            "done",
        ] {
            assert!(
                phases.contains(&format!("\"phase\":\"{phase}\"")),
                "missing phase {phase} in {phases}"
            );
        }

        // The post-rotation seal-status response exists only when `curl
        // --cacert` (no `-k`) verified the renewed listener certificate
        // against the local step-ca bundle, and its `sealed` field is what
        // proves the SIGHUP reload did not cost availability.
        let seal_status = artifact_dir.join("seal-status-second.json");
        assert!(
            seal_status.exists(),
            "missing post-rotation seal-status response; the TLS probe never succeeded"
        );
        let body = std::fs::read_to_string(&seal_status)
            .with_context(|| "Failed to read post-rotation seal-status response")?;
        let parsed: serde_json::Value =
            serde_json::from_str(&body).with_context(|| "seal-status is not JSON")?;
        assert_eq!(
            parsed.get("sealed").and_then(serde_json::Value::as_bool),
            Some(false),
            "OpenBao is sealed after the rotation: {body}"
        );

        Ok(())
    }
}
