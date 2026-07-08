use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::fs_util;

use super::RENDERED_FILE_POLL_INTERVAL;
use crate::cli::prompt::Prompt;
use crate::commands::infra::run_docker;
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

pub(super) async fn write_secret_file(
    path: &Path,
    contents: &str,
    messages: &Messages,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs_util::ensure_secrets_dir(parent).await?;
    }
    tokio::fs::write(path, contents)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    fs_util::set_key_permissions(path).await?;
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
    fs_util::atomic_write(path, value.as_bytes(), fs_util::KEY_FILE_MODE)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

pub(super) fn restart_container(container: &str, messages: &Messages) -> Result<()> {
    let args = ["restart", container];
    run_docker(&args, &format!("docker restart {container}"), messages)
}

pub(super) fn restart_compose_service(
    compose_file: &Path,
    service: &str,
    messages: &Messages,
) -> Result<()> {
    let compose_file = compose_file.to_string_lossy();
    let args = ["compose", "-f", compose_file.as_ref(), "restart", service];
    run_docker(&args, "docker compose restart", messages)
}

pub(super) fn reload_compose_service(
    compose_file: &Path,
    service: &str,
    messages: &Messages,
) -> Result<()> {
    let compose_file = compose_file.to_string_lossy();
    let args = [
        "compose",
        "-f",
        compose_file.as_ref(),
        "kill",
        "-s",
        "HUP",
        service,
    ];
    run_docker(&args, "docker compose kill", messages)
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

    use super::super::test_support::test_messages;
    use super::*;

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
