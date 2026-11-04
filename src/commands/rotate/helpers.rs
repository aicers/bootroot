use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::fs_util::{RootedOwner, SecretsTree};

use super::RENDERED_FILE_POLL_INTERVAL;
use crate::cli::prompt::Prompt;
use crate::commands::compose_project::ComposeIdentity;
use crate::commands::container_name::{BootrootContainer, resolve_container_name};
use crate::commands::infra::{run_compose, run_docker_with_exec};
use crate::commands::init::{read_ca_cert_fingerprint, read_ca_cert_fingerprint_in};
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
    tree: &Arc<SecretsTree>,
    path: &Path,
    contents: &str,
    messages: &Messages,
) -> Result<()> {
    if tree.is_rooted() {
        return publish_secret_rooted(tree, path, contents, messages).await;
    }
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
///
/// `path` lies below the secrets directory `tree` is opened on. On a
/// rooted handle the parent is created writer-owned through the handle
/// and the file is published through it, following no name; otherwise
/// this is [`write_secret_id_atomic_by_path`].
pub(super) async fn write_secret_id_atomic(
    tree: &Arc<SecretsTree>,
    path: &Path,
    value: &str,
    messages: &Messages,
) -> Result<()> {
    if !tree.is_rooted() {
        return write_secret_id_atomic_by_path(path, value, messages).await;
    }
    secret_id_parent(path, messages)?;
    publish_secret_rooted(tree, path, value, messages).await
}

/// [`write_secret_id_atomic`]'s path-based write, for a handle that is
/// not rooted and for an operator-named file outside the secrets
/// directory.
pub(super) async fn write_secret_id_atomic_by_path(
    path: &Path,
    value: &str,
    messages: &Messages,
) -> Result<()> {
    let parent = secret_id_parent(path, messages)?;
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

/// The directory a `secret_id` file is written into; a bare file name
/// has none bootroot may create.
fn secret_id_parent<'p>(path: &'p Path, messages: &Messages) -> Result<&'p Path> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(messages.error_parent_not_found(&path.display().to_string()))
    })?;
    if parent.as_os_str().is_empty() {
        anyhow::bail!(messages.error_parent_not_found(&path.display().to_string()));
    }
    Ok(parent)
}

/// The rooted half of [`write_secret_file`] and
/// [`write_secret_id_atomic`]: the parent is created writer-owned at
/// `0700` as `ensure_secrets_dir` creates it, and the file is published
/// as `atomic_write` publishes it — `0600`, the destination's owner
/// kept, the directory flushed — through the handle.
async fn publish_secret_rooted(
    tree: &Arc<SecretsTree>,
    path: &Path,
    contents: &str,
    messages: &Messages,
) -> Result<()> {
    let target = path.to_path_buf();
    let payload = contents.as_bytes().to_vec();
    let failed = messages.error_write_file_failed(&path.display().to_string());
    tree.run(move |tree| {
        if let Some(parent) = target.parent() {
            tree.ensure_dir_as_writer(parent)?;
        }
        tree.publish(
            fs_util::Destination::bootroot_owned(&target),
            &payload,
            fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
            RootedOwner::Destination,
            fs_util::StagedDurability::FlushDirectory,
        )
        .context(failed)
    })
    .await
}

/// The SHA-256 fingerprint of the CA certificate at `path` below the
/// secrets directory: read through `tree` on a blocking thread when it
/// is rooted, by path otherwise.
///
/// # Errors
/// Returns an error when the certificate is missing, refused,
/// unreadable, or not a PEM certificate.
pub(super) async fn ca_cert_fingerprint(
    tree: &Arc<SecretsTree>,
    path: &Path,
    messages: &Messages,
) -> Result<String> {
    if !tree.is_rooted() {
        return read_ca_cert_fingerprint(path, messages).await;
    }
    let path = path.to_path_buf();
    let messages = messages.clone();
    tree.run(move |tree| read_ca_cert_fingerprint_in(tree, &path, &messages))
        .await
}

/// Rebases `path`, which `state.json` or the operator spelled, onto the
/// anchor of `tree`, so the handle's lexical strip of the anchor matches
/// it whatever spelling the two use.
///
/// Both are compared after [`fs_util::absolute_lexical`], as
/// [`fs_util::path_is_within`] classifies them; the remainder is joined
/// onto the anchor as the handle was opened with it.
///
/// # Errors
/// Returns an error naming `path` and the anchor when `path` is not
/// below the anchor, and when either cannot be made absolute.
pub(crate) fn rebase_onto_anchor(
    tree: &SecretsTree,
    path: &Path,
    messages: &Messages,
) -> Result<PathBuf> {
    let absolute_path = fs_util::absolute_lexical(path)
        .with_context(|| format!("Failed to resolve {}", path.display()))?;
    let absolute_anchor = fs_util::absolute_lexical(tree.anchor())
        .with_context(|| format!("Failed to resolve {}", tree.anchor().display()))?;
    let rest = absolute_path.strip_prefix(&absolute_anchor).map_err(|_| {
        anyhow::anyhow!(messages.error_path_not_below_secrets_dir(
            &path.display().to_string(),
            &tree.anchor().display().to_string()
        ))
    })?;
    Ok(tree.anchor().join(rest))
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

/// Exit status `pkill` reports when no process matched the pattern.
#[cfg(unix)]
const PKILL_NO_PROCESS_MATCHED: i32 = 1;

/// Reloads the bootroot-internal registrar agent.
///
/// Deliberately **not** [`signal_bootroot_agent`]: the internal profile
/// has no [`ServiceEntry`] and never will — it is not a registered
/// service — so its only address is the fixed
/// `registrar-internal/agent.toml` path below the state-recorded
/// secrets directory, which is what distinguishes its command line from
/// every other `bootroot-agent` on the host.
///
/// `pkill` status 1 means *no process matched*, and that is a success
/// here. The internal agent is the registrar endpoint daemon, which
/// `bootroot-registrar.service` runs and `init` does not start, and a
/// host where it has not been started yet is a host with nothing to
/// reload — not a failed rotation. Any other non-zero status
/// is a real failure and aborts the phase that sent the signal.
///
/// `bootroot init` sends it too, when it replaces a credential the host
/// already carried: the entry is pinned to the new leaf from the moment
/// it is rewritten, and the daemon loads its credential only at start
/// and on `SIGHUP`.
///
/// # Errors
///
/// Returns an error when `pkill` cannot be run, or when it exits with a
/// status other than success or [`PKILL_NO_PROCESS_MATCHED`].
#[cfg(unix)]
pub(crate) fn signal_internal_registrar_agent(
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let pattern = bootroot::registrar::internal::internal_signal_pattern(secrets_dir);
    let status = std::process::Command::new("pkill")
        .args(["-HUP", "-f", &pattern])
        .status()
        .with_context(|| messages.error_command_run_failed("pkill -HUP"))?;
    classify_internal_signal_status(status, messages)
}

/// Turns a `pkill` exit status into the internal reload's outcome.
///
/// Split out from the spawn so the "no process matched is success" rule
/// is testable without a process to signal — which is exactly the state
/// the rule exists for.
///
/// # Errors
///
/// Returns an error for any status that is neither success nor
/// [`PKILL_NO_PROCESS_MATCHED`].
#[cfg(unix)]
fn classify_internal_signal_status(
    status: std::process::ExitStatus,
    messages: &Messages,
) -> Result<()> {
    if status.success() || status.code() == Some(PKILL_NO_PROCESS_MATCHED) {
        return Ok(());
    }
    anyhow::bail!(messages.error_command_failed_status("pkill -HUP", &status.to_string()))
}

#[cfg(not(unix))]
pub(crate) fn signal_internal_registrar_agent(
    _secrets_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    anyhow::bail!(messages.error_command_run_failed("pkill -HUP"));
}

/// Folds a later step's failure into the one a rotation already
/// recorded, so the error it returns names every step that failed
/// rather than only the first. With nothing recorded, the later failure
/// is returned as it is.
pub(super) fn fold_failure(
    earlier: Option<anyhow::Error>,
    step: &str,
    later: anyhow::Error,
) -> anyhow::Error {
    match earlier {
        None => later,
        Some(earlier) => earlier.context(format!("{step} failed as well: {later:#}")),
    }
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
mod internal_signal_tests {
    use std::process::Command;

    use super::classify_internal_signal_status;
    use crate::i18n::test_messages;

    /// Runs `/bin/sh -c "exit <code>"` and returns its status, so the
    /// classifier is exercised against a real `ExitStatus` rather than a
    /// hand-built one.
    fn status_for(code: i32) -> std::process::ExitStatus {
        Command::new("/bin/sh")
            .args(["-c", &format!("exit {code}")])
            .status()
            .expect("the shell must run")
    }

    /// `pkill` status 1 is "no process matched". The internal agent runs
    /// under `bootroot-registrar.service` and `init` never starts it, so a
    /// host where it is not running has nothing to reload — that is a
    /// successful HUP outcome, not a failed rotation phase.
    #[test]
    fn no_process_matched_is_a_successful_reload() {
        let messages = test_messages();
        assert!(classify_internal_signal_status(status_for(0), &messages).is_ok());
        assert!(classify_internal_signal_status(status_for(1), &messages).is_ok());
    }

    /// Any other status is a real failure and aborts the phase that sent
    /// the signal.
    #[test]
    fn any_other_status_aborts_the_phase() {
        let messages = test_messages();
        for code in [2, 3, 127] {
            assert!(
                classify_internal_signal_status(status_for(code), &messages).is_err(),
                "exit {code} must abort"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;
    use std::time::Duration;

    use tempfile::tempdir;

    use super::super::test_support::{
        decode_fake_docker_log, path_tree, test_messages, write_self_contained_fake_docker,
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

        write_secret_id_atomic(&path_tree(dir.path()), &secret_path, "old", &messages)
            .await
            .expect("initial write");
        write_secret_id_atomic(&path_tree(dir.path()), &secret_path, "new", &messages)
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
        let err = write_secret_id_atomic(
            &path_tree(Path::new(".")),
            Path::new("secret_id"),
            "value",
            &messages,
        )
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

        write_secret_id_atomic(&path_tree(dir.path()), &secret_path, "old", &messages)
            .await
            .expect("initial write");
        std::os::unix::fs::chown(&secret_path, None, Some(gid))
            .expect("test process must be able to chgrp to a supplementary gid");
        let pre_uid = std::fs::metadata(&secret_path).expect("metadata").uid();

        write_secret_id_atomic(&path_tree(dir.path()), &secret_path, "new", &messages)
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

    fn rooted_arc(root: &crate::test_support::SwapRoot) -> Arc<SecretsTree> {
        Arc::new(root.rooted())
    }

    /// Both writers refuse a link at the level below the anchor they
    /// walk, name it, and write nothing outside `secrets/`.
    #[tokio::test]
    async fn rooted_secret_writers_refuse_a_swapped_level() {
        let messages = test_messages();
        for level in ["services", "openbao"] {
            let root = crate::test_support::SwapRoot::new();
            root.write(&format!("{level}/svc/secret_id"), "old");
            let tree = rooted_arc(&root);
            let before = root.outside_snapshot();
            let link = root.swap(level, &root.outside);
            let path = root.secrets.join(level).join("svc").join("secret_id");

            let err = write_secret_id_atomic(&tree, &path, "new", &messages)
                .await
                .expect_err("a link above the secret_id is refused");
            crate::test_support::assert_error_names(&err, &link);
            let err = write_secret_file(&tree, &path, "new", &messages)
                .await
                .expect_err("a link above the secret file is refused");
            crate::test_support::assert_error_names(&err, &link);
            assert_eq!(root.outside_snapshot(), before, "{level}");
        }
    }

    /// Over a tree the test's user owns, the rooted write gives the
    /// bytes, mode and owner the path-based one gives, and creates the
    /// missing levels `0700`.
    #[tokio::test]
    async fn rooted_secret_writers_match_the_path_based_writes() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let messages = test_messages();
        let mut results = Vec::new();
        for rooted in [false, true] {
            let root = crate::test_support::SwapRoot::new();
            let tree = if rooted {
                rooted_arc(&root)
            } else {
                path_tree(&root.secrets)
            };
            let secret_id = root
                .secrets
                .join("openbao")
                .join("stepca")
                .join("secret_id");
            write_secret_id_atomic(&tree, &secret_id, "sid", &messages)
                .await
                .expect("write secret_id");
            let password = root.secrets.join("password.txt.new");
            write_secret_file(&tree, &password, "pw", &messages)
                .await
                .expect("write password");
            let mut seen = Vec::new();
            for path in [&secret_id, &password] {
                let meta = std::fs::metadata(path).expect("stat");
                seen.push((
                    std::fs::read(path).expect("read"),
                    meta.permissions().mode() & 0o7777,
                    meta.uid(),
                ));
            }
            let leaf_dir_mode = std::fs::metadata(secret_id.parent().expect("parent"))
                .expect("stat")
                .permissions()
                .mode()
                & 0o7777;
            results.push((seen, leaf_dir_mode));
            if rooted {
                // The intermediate level the rooted write created is
                // `0700`; the path-based one leaves it to the umask.
                let intermediate = std::fs::metadata(root.secrets.join("openbao"))
                    .expect("stat")
                    .permissions()
                    .mode()
                    & 0o7777;
                assert_eq!(intermediate, 0o700);
            }
        }
        assert_eq!(results[0], results[1]);
        assert_eq!(results[1].1, 0o700);
    }

    /// A path `state.json` spelled differently from the anchor is
    /// rebased onto it; one not below the anchor is refused naming both.
    #[test]
    fn rebasing_follows_the_lexical_spelling_and_refuses_a_path_outside() {
        let root = crate::test_support::SwapRoot::new();
        let tree = root.rooted();
        let messages = test_messages();
        let spelled = root
            .root()
            .join("x")
            .join("..")
            .join("secrets")
            .join("services")
            .join("svc")
            .join("secret_id");
        assert_eq!(
            rebase_onto_anchor(&tree, &spelled, &messages).expect("below"),
            root.secrets.join("services").join("svc").join("secret_id")
        );
        let elsewhere = root.root().join("other").join("services").join("secret_id");
        let err = rebase_onto_anchor(&tree, &elsewhere, &messages).expect_err("not below");
        crate::test_support::assert_error_names(&err, &elsewhere);
        crate::test_support::assert_error_names(&err, &root.secrets);
    }
}
