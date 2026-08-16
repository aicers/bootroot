use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::fs_util;

use super::RENDERED_FILE_POLL_INTERVAL;
use crate::cli::prompt::Prompt;
use crate::commands::compose_project::ComposeIdentity;
use crate::commands::container_name::{BootrootContainer, resolve_container_name};
use crate::commands::infra::{run_compose, run_docker_with_exec};
use crate::i18n::Messages;
use crate::state::ServiceEntry;

pub(super) fn confirm_action(prompt: &str, auto_confirm: bool, messages: &Messages) -> Result<()> {
    if auto_confirm {
        return Ok(());
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout();
    let mut prompt_reader = Prompt::new(&mut input, &mut output, messages);
    let response = prompt_reader.prompt_text(prompt, None)?;
    let normalized = response.trim().to_ascii_lowercase();
    if normalized == "y" || normalized == "yes" {
        Ok(())
    } else {
        anyhow::bail!(messages.error_operation_cancelled());
    }
}

pub(super) fn ensure_non_empty(value: &str, messages: &Messages) -> Result<String> {
    if value.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    Ok(value.trim().to_string())
}

pub(super) fn ensure_file_exists(path: &Path, messages: &Messages) -> Result<()> {
    if path.exists() {
        Ok(())
    } else {
        anyhow::bail!(messages.error_file_missing(&path.display().to_string()));
    }
}

/// Writes an operator-only file inside the secrets tree, publishing it
/// by rename at `0600`.
///
/// Its one caller stages the *new* step-ca CA password here before
/// asking step-ca to re-encrypt its keys with it. The mode is the
/// policy's `0600` rather than the destination's: this is a credential,
/// and a stale wider mode left by an earlier run must not survive the
/// file it was attached to.
///
/// Applying that mode to the staged temporary also closes the window the
/// `write` + `set_key_permissions` pair this replaced left open, in
/// which the password sat world-readable at its final path. A site being
/// re-plumbed for the torn-read fix does not get to keep that window.
///
/// It takes the directory flush. Losing the new password after step-ca
/// has re-encrypted its keys with it leaves an intermediate CA key
/// nobody can decrypt — not a rewrite, an unrecoverable CA.
pub(super) async fn write_secret_file(
    path: &Path,
    contents: &str,
    messages: &Messages,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs_util::ensure_secrets_dir(parent).await?;
    }
    fs_util::atomic_write(
        fs_util::Destination::bootroot_owned(path),
        contents.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

/// Rewrites a `secret_id` file atomically via
/// [`fs_util::atomic_write`]: same-directory temp file, `0600`, the
/// destination's existing uid/gid re-applied, then a rename into
/// place. Ownership preservation is load-bearing for the local-file
/// service path: the local `bootroot-agent` runs as a hardened
/// non-root host daemon and re-reads this file on every `AppRole`
/// re-login, so a root-run `rotate approle-secret-id` must not
/// replace an operator-chowned, daemon-readable file with a
/// root-owned `0600` one the daemon can no longer read — that would
/// kill the fast-poll loop on its next re-login.
pub(super) async fn write_secret_id_atomic(
    path: &Path,
    value: &str,
    messages: &Messages,
) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(messages.error_parent_not_found(&path.display().to_string()))
    })?;
    if parent.as_os_str().is_empty() {
        anyhow::bail!(messages.error_parent_not_found(&path.display().to_string()));
    }
    fs_util::ensure_secrets_dir(parent).await?;
    fs_util::atomic_write(
        fs_util::Destination::bootroot_owned(path),
        value.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

pub(super) fn restart_container(container: &str, docker: &Path, messages: &Messages) -> Result<()> {
    let args = ["restart", container];
    run_docker_with_exec(
        &args,
        &format!("docker restart {container}"),
        docker,
        messages,
    )
}

/// Restarts one of the `OpenBao` Agent sidecars so it re-renders its
/// templates against the value this rotation just wrote.
///
/// The sidecars are addressed by name and therefore bypass Compose's
/// `-p` project scoping, so the name has to come from the identity
/// recorded beside the compose file the command was handed.  A literal
/// would restart a co-located default install's sidecar instead — or
/// fail on a name that does not exist for this install at all.
pub(super) fn restart_openbao_agent(
    compose_file: &Path,
    container: BootrootContainer,
    docker: &Path,
    messages: &Messages,
) -> Result<()> {
    let name = resolve_container_name(compose_file, container, messages)?;
    restart_container(&name, docker, messages)
}

pub(super) fn restart_compose_service(
    compose_file: &Path,
    service: &str,
    messages: &Messages,
) -> Result<()> {
    let identity = ComposeIdentity::resolve(compose_file, None, messages)?;
    let compose_str = compose_file.to_string_lossy();
    let invocation = identity.compose(&[compose_str.as_ref()], None, &["restart", service]);
    run_compose(&invocation, "docker compose restart", messages)
}

pub(super) fn reload_compose_service(
    compose_file: &Path,
    service: &str,
    messages: &Messages,
) -> Result<()> {
    let identity = ComposeIdentity::resolve(compose_file, None, messages)?;
    let compose_str = compose_file.to_string_lossy();
    let invocation = identity.compose(
        &[compose_str.as_ref()],
        None,
        &["kill", "-s", "HUP", service],
    );
    run_compose(&invocation, "docker compose kill", messages)
}

pub(super) async fn wait_for_rendered_file(
    path: &Path,
    expected: &str,
    timeout: Duration,
    messages: &Messages,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(contents) = tokio::fs::read_to_string(path).await
            && contents.contains(expected)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(messages.error_rendered_file_timeout(&path.display().to_string()));
        }
        tokio::time::sleep(RENDERED_FILE_POLL_INTERVAL).await;
    }
}

pub(super) use crate::commands::init::compose_has_responder;

/// Signals the local host-daemon `bootroot-agent` (matched by its
/// `--config` path in the process cmdline) to re-read its config and
/// re-check certificates. The local agent runs only as a host daemon,
/// so `pkill -HUP` is the sole signalling channel.
#[cfg(unix)]
pub(super) fn signal_bootroot_agent(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    let config_path = entry.agent_config_path.display().to_string();
    let status = std::process::Command::new("pkill")
        .args(["-HUP", "-f", &config_path])
        .status()
        .with_context(|| messages.error_command_run_failed("pkill -HUP"))?;
    if !status.success() {
        anyhow::bail!(messages.error_command_failed_status("pkill -HUP", &status.to_string()));
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) fn signal_bootroot_agent(_entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    anyhow::bail!(messages.error_command_run_failed("pkill -HUP"));
}

pub(super) fn try_restart_container(container: &str) -> Result<()> {
    let status = std::process::Command::new("docker")
        .args(["restart", container])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        anyhow::bail!("container {container} not found or restart failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::super::test_support::{
        decode_fake_docker_log, test_messages, write_self_contained_fake_docker,
    };
    use super::*;
    use crate::commands::compose_project::DEFAULT_INSTANCE_NAME;

    /// Runs `restart_openbao_agent` against a fake `docker` handed in
    /// through the executable seam and returns the invocations it saw.
    fn restart_invocations(instance: &str, container: BootrootContainer) -> Vec<Vec<String>> {
        let dir = tempdir().expect("tempdir");
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        std::fs::write(
            dir.path().join(".env"),
            format!("BOOTROOT_INSTANCE={instance}\n"),
        )
        .expect("write .env");
        restart_openbao_agent(
            &dir.path().join("docker-compose.yml"),
            container,
            &fake,
            &test_messages(),
        )
        .expect("restarting the sidecar must succeed");

        decode_fake_docker_log(&args_log)
    }

    /// The sidecars bypass Compose's project scoping, so `rotate db` and
    /// `rotate stepca-password` — which both restart the step-ca agent
    /// so it re-renders `ca.json` / `password.txt` — must name the
    /// container of the install they were pointed at.  A default-named
    /// literal would restart a co-located default install's sidecar.
    #[test]
    fn restarting_the_stepca_agent_names_the_recorded_instance() {
        assert_eq!(
            restart_invocations("insight", BootrootContainer::OpenBaoAgentStepCa),
            [["restart", "insight-openbao-agent-stepca"]]
        );
    }

    /// `rotate responder-hmac` restarts the other sidecar, so the two
    /// kinds must not be interchangeable.
    #[test]
    fn restarting_the_responder_agent_names_the_recorded_instance() {
        assert_eq!(
            restart_invocations("insight", BootrootContainer::OpenBaoAgentResponder),
            [["restart", "insight-openbao-agent-responder"]]
        );
    }

    /// An install that declared no identity keeps the historical names,
    /// which is what leaves the `bootroot-*` literals across `scripts/`,
    /// `tests/` and `docs/` correct.
    #[test]
    fn restarting_a_sidecar_without_a_recorded_identity_keeps_the_default_name() {
        let dir = tempdir().expect("tempdir");
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        restart_openbao_agent(
            &dir.path().join("docker-compose.yml"),
            BootrootContainer::OpenBaoAgentStepCa,
            &fake,
            &test_messages(),
        )
        .expect("restarting the sidecar must succeed");

        // Spelled through the derivation rather than as a literal: a
        // bare default-instance sidecar name in `src/` is what
        // `container_name`'s single-declaration guard forbids.
        let expected = BootrootContainer::OpenBaoAgentStepCa.name(DEFAULT_INSTANCE_NAME);
        assert_eq!(
            decode_fake_docker_log(&args_log),
            [["restart", expected.as_str()]]
        );
    }

    #[tokio::test]
    async fn write_secret_id_atomic_overwrites_contents() {
        let dir = tempdir().expect("tempdir");
        let secret_path = dir.path().join("app").join("secret_id");
        let messages = test_messages();

        write_secret_id_atomic(&secret_path, "old", &messages)
            .await
            .expect("initial write");
        write_secret_id_atomic(&secret_path, "new", &messages)
            .await
            .expect("overwrite");

        let contents = tokio::fs::read_to_string(&secret_path)
            .await
            .expect("read secret_id");
        assert_eq!(contents, "new");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&secret_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn write_secret_id_atomic_requires_parent_dir() {
        let messages = test_messages();
        let err = write_secret_id_atomic(Path::new("secret_id"), "value", &messages)
            .await
            .expect_err("expected parent error");
        let err = err.to_string();
        assert!(err.contains("Parent directory not found"));
    }

    /// A root-run `rotate approle-secret-id` must not strip the
    /// ownership an operator applied so the non-root host daemon can
    /// read the credential — otherwise the agent's next `AppRole`
    /// re-login fails and the fast-poll loop dies. Requires a
    /// supplementary gid (single-gid CI runners skip; the
    /// e2e-extended job provisions one and keeps coverage).
    #[cfg(unix)]
    #[tokio::test]
    async fn write_secret_id_atomic_preserves_existing_owner_on_rewrite() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let Some(gid) = bootroot::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().expect("tempdir");
        let secret_path = dir.path().join("app").join("secret_id");
        let messages = test_messages();

        write_secret_id_atomic(&secret_path, "old", &messages)
            .await
            .expect("initial write");
        std::os::unix::fs::chown(&secret_path, None, Some(gid))
            .expect("test process must be able to chgrp to a supplementary gid");
        let pre_uid = std::fs::metadata(&secret_path).expect("metadata").uid();

        write_secret_id_atomic(&secret_path, "new", &messages)
            .await
            .expect("rewrite");

        let meta = std::fs::metadata(&secret_path).expect("metadata");
        assert_eq!(meta.gid(), gid, "rewrite must preserve the existing gid");
        assert_eq!(
            meta.uid(),
            pre_uid,
            "rewrite must preserve the existing uid"
        );
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
        let contents = tokio::fs::read_to_string(&secret_path)
            .await
            .expect("read secret_id");
        assert_eq!(contents, "new");
    }

    #[tokio::test]
    async fn wait_for_rendered_file_immediate() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("rendered.txt");
        std::fs::write(&path, "expected-value").expect("write file");
        let messages = test_messages();

        wait_for_rendered_file(
            &path,
            "expected-value",
            Duration::from_millis(500),
            &messages,
        )
        .await
        .expect("should return immediately when file already contains expected content");
    }

    #[tokio::test]
    async fn wait_for_rendered_file_timeout() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("never.txt");
        std::fs::write(&path, "wrong-content").expect("write file");
        let messages = test_messages();

        let err = wait_for_rendered_file(
            &path,
            "expected-value",
            Duration::from_millis(100),
            &messages,
        )
        .await
        .expect_err("should timeout when content never matches");
        assert!(err.to_string().contains("Timed out"));
    }
}
