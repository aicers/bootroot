use std::path::Path;
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};

use crate::cli::args::CleanArgs;
use crate::commands::infra::run_docker;
use crate::commands::init::{OPENBAO_CONTAINER_NAME, prompt_yes_no};
use crate::i18n::Messages;
use crate::state::StateFile;

const OPENBAO_AGENT_OVERRIDE: &str = "secrets/openbao/docker-compose.openbao-agent.override.yml";
const OPENBAO_EXPOSED_OVERRIDE: &str = "secrets/openbao/docker-compose.openbao-exposed.yml";

/// Docker compose project label inspected on the `OpenBao` container so
/// volume removal can be scoped to `<project>_openbao-*` and not wipe
/// the project's other named volumes (e.g. `postgres-data`).
pub(crate) const COMPOSE_PROJECT_LABEL: &str = "com.docker.compose.project";

/// Compose label naming the docker-compose service for a container. Used
/// alongside `COMPOSE_PROJECT_LABEL` by `reinit` to verify that the
/// container scheduled for removal is the project's `openbao` service
/// and not an unrelated container that happens to be named
/// `bootroot-openbao`.
pub(crate) const COMPOSE_SERVICE_LABEL: &str = "com.docker.compose.service";

/// Named volumes the `openbao` compose service mounts. Removing only
/// these is the contract `--openbao-only` advertises (#588 §5b);
/// using `docker compose down -v` instead would also wipe
/// `postgres-data`, `prometheus-data`, and `grafana-data`.
pub(crate) const OPENBAO_NAMED_VOLUMES: &[&str] = &["openbao-data", "openbao-audit"];

pub(crate) fn run_clean(args: &CleanArgs, messages: &Messages) -> Result<()> {
    if args.openbao_only {
        return run_clean_openbao_only(args, messages);
    }
    if !args.yes && !prompt_yes_no(messages.clean_confirm(), messages)? {
        anyhow::bail!(messages.error_operation_cancelled());
    }

    // Resolve paths relative to the compose file directory, matching
    // Docker Compose's bind-mount resolution.
    let compose_dir = args
        .compose_file
        .compose_file
        .parent()
        .unwrap_or(Path::new("."));

    let compose_str = args.compose_file.compose_file.to_string_lossy();
    let mut down_args: Vec<&str> = vec!["compose", "-f", &compose_str];

    let agent_override_path = compose_dir.join(OPENBAO_AGENT_OVERRIDE);
    let agent_override_str = agent_override_path.to_string_lossy();
    if agent_override_path.exists() {
        down_args.extend(["-f", &*agent_override_str]);
    }

    let exposed_override_path = compose_dir.join(OPENBAO_EXPOSED_OVERRIDE);
    let exposed_override_str = exposed_override_path.to_string_lossy();
    if exposed_override_path.exists() {
        down_args.extend(["-f", &*exposed_override_str]);
    }

    down_args.extend(["down", "-v", "--remove-orphans"]);
    run_docker(&down_args, "docker compose down", messages)?;

    remove_clean_artifacts(compose_dir, &StateFile::default_path(), messages)?;

    let remove_certs = args.yes || prompt_yes_no(messages.clean_confirm_certs(), messages)?;
    if remove_certs {
        remove_path_if_exists(&compose_dir.join("certs"), messages)?;
    }

    println!("{}", messages.clean_completed());
    Ok(())
}

/// Removes only the `bootroot-openbao` container and its volume.
/// Leaves every other compose service, `secrets/`, `state.json`, and
/// `.env` intact so an operator can recover from a partial-init
/// `OpenBao` state without losing application DB / step-ca state.
/// See issue #588 §5b.
fn run_clean_openbao_only(args: &CleanArgs, messages: &Messages) -> Result<()> {
    if !args.yes && !prompt_yes_no(messages.clean_confirm_openbao_only(), messages)? {
        anyhow::bail!(messages.error_operation_cancelled());
    }
    remove_openbao_container_and_volumes(&args.compose_file.compose_file, messages)?;
    println!("{}", messages.clean_openbao_only_completed());
    Ok(())
}

/// Stops and removes the `bootroot-openbao` container and its named
/// volumes, scoping volume removal to the compose project's prefix so
/// `postgres-data`, `prometheus-data`, and `grafana-data` are not
/// touched.  Shared between `bootroot clean --openbao-only` and
/// `bootroot reinit`; the caller is responsible for any operator
/// confirmation prompt.
pub(crate) fn remove_openbao_container_and_volumes(
    compose_file: &Path,
    messages: &Messages,
) -> Result<()> {
    let compose_str = compose_file.to_string_lossy();
    let compose_dir = compose_file.parent().unwrap_or(Path::new("."));

    // Discover the compose project name BEFORE removing the container,
    // while the label is still readable. Falling back to the compose-dir
    // basename matches docker compose's default project-naming rule and
    // covers the case where the container is already gone.
    let project = resolve_compose_project(compose_dir, &inspect_label_via_docker)?;

    let stop_args = ["compose", "-f", &compose_str, "stop", "openbao"];
    let _ = run_docker(&stop_args, "docker compose stop openbao", messages);
    let rm_args = ["compose", "-f", &compose_str, "rm", "-fsv", "openbao"];
    run_docker(&rm_args, "docker compose rm openbao", messages)?;

    // Remove ONLY the openbao-owned named volumes. `docker compose down
    // -v` removes every named volume in the compose file regardless of
    // any positional service argument and would wipe `postgres-data`,
    // `prometheus-data`, `grafana-data` along with openbao's volumes.
    for vol in OPENBAO_NAMED_VOLUMES {
        let full = format!("{project}_{vol}");
        let vol_args = ["volume", "rm", "-f", full.as_str()];
        run_docker(&vol_args, &format!("docker volume rm {full}"), messages)?;
    }
    Ok(())
}

/// Resolves the docker compose project name. Tries the openbao
/// container's `com.docker.compose.project` label first; if the
/// container is not present, honours `COMPOSE_PROJECT_NAME` so volume
/// removal targets the same project that `docker compose up` will
/// create under (otherwise reinit could wipe `<basename>_openbao-data`
/// while `infra up` recreated `<env>_openbao-data`, leaving the real
/// volume intact); only then falls back to the compose-dir basename
/// normalised the same way docker compose itself derives the default
/// project name (lowercased; characters outside `[a-z0-9_-]` stripped).
pub(crate) fn resolve_compose_project(
    compose_dir: &Path,
    inspect: &dyn Fn(&str, &str) -> Result<Option<String>>,
) -> Result<String> {
    if let Some(value) = inspect(OPENBAO_CONTAINER_NAME, COMPOSE_PROJECT_LABEL)? {
        return Ok(value);
    }
    if let Ok(env_value) = std::env::var("COMPOSE_PROJECT_NAME")
        && !env_value.is_empty()
    {
        return Ok(env_value);
    }
    let canonical =
        std::fs::canonicalize(compose_dir).unwrap_or_else(|_| compose_dir.to_path_buf());
    let basename = canonical
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "could not derive compose project name from {}",
                compose_dir.display()
            )
        })?;
    let normalised = normalise_compose_project_name(basename);
    if normalised.is_empty() {
        anyhow::bail!(
            "could not derive a valid compose project name from {}; restart the openbao container so its `{COMPOSE_PROJECT_LABEL}` label is readable",
            compose_dir.display()
        );
    }
    Ok(normalised)
}

/// Normalises a directory name into a docker compose project name.
/// Mirrors compose's own rule: lowercase ASCII; drop characters that
/// are not `[a-z0-9_-]`. (Compose itself also collapses leading
/// separators; we do not, because the basename is unlikely to start
/// with one and an empty result is rejected by the caller.)
fn normalise_compose_project_name(input: &str) -> String {
    input
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect()
}

/// Reports whether a container exists on the local docker daemon,
/// independent of any label.  Used by `reinit`'s scope check to
/// distinguish "container missing" (the stuck-after-`clean --openbao-only`
/// recovery path) from "container exists but its compose labels are
/// missing", which `inspect_label_via_docker` cannot tell apart.
pub(crate) fn container_exists_via_docker(container: &str) -> Result<bool> {
    let output = ProcessCommand::new("docker")
        .args(["container", "inspect", "--format", "{{.Id}}", container])
        .output()
        .with_context(|| "failed to run `docker container inspect`")?;
    Ok(output.status.success())
}

/// Reads a single label from a docker container. Returns `Ok(None)`
/// when the container is missing OR when the label is unset.
pub(crate) fn inspect_label_via_docker(container: &str, label: &str) -> Result<Option<String>> {
    let format_arg = format!("{{{{index .Config.Labels \"{label}\"}}}}");
    let output = ProcessCommand::new("docker")
        .args(["inspect", "--format", &format_arg, container])
        .output()
        .with_context(|| "failed to run `docker inspect`")?;
    if !output.status.success() {
        // Treat any inspect failure (most commonly "no such object") as
        // "container missing"; we will fall back to the basename.
        return Ok(None);
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() || value == "<no value>" {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

/// Removes artifacts created by `infra install` and `init`.
///
/// `secrets/` and `.env` live in the compose file directory (Docker
/// Compose resolves bind-mount paths relative to the compose file).
/// `state.json` lives at `StateFile::default_path()` (the process
/// working directory), which may differ when `--compose-file` points
/// elsewhere.
fn remove_clean_artifacts(
    compose_dir: &Path,
    state_path: &Path,
    messages: &Messages,
) -> Result<()> {
    remove_path_if_exists(&compose_dir.join("secrets"), messages)?;
    remove_file_if_exists(state_path, messages)?;
    remove_file_if_exists(&compose_dir.join(".env"), messages)?;
    Ok(())
}

fn remove_path_if_exists(path: &Path, messages: &Messages) -> Result<()> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)
            .with_context(|| messages.error_remove_dir_failed(&path.display().to_string()))?;
    } else if path.is_file() {
        std::fs::remove_file(path)
            .with_context(|| messages.error_remove_file_failed(&path.display().to_string()))?;
    }
    Ok(())
}

fn remove_file_if_exists(path: &Path, messages: &Messages) -> Result<()> {
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| messages.error_remove_file_failed(&path.display().to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::{LazyLock, Mutex, MutexGuard};

    use super::*;
    use crate::i18n::Messages;

    /// Serialises tests that mutate `COMPOSE_PROJECT_NAME` so the env
    /// var is in a known state when `resolve_compose_project` is
    /// exercised concurrently with the rest of the test suite.  Mirrors
    /// the `ENV_LOCK` pattern in `commands/reinit.rs::tests`.
    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().expect("test env lock must not be poisoned")
    }

    /// Test helper: clears `COMPOSE_PROJECT_NAME` so basename-fallback
    /// tests exercise the documented fallback regardless of the
    /// developer's ambient shell environment.  Callers must hold
    /// `env_lock()`.
    fn clear_compose_project_name() {
        // SAFETY: `env::remove_var` mutates process-global state.  The
        // caller serialises access via `env_lock()`.
        unsafe {
            std::env::remove_var("COMPOSE_PROJECT_NAME");
        }
    }

    /// Regression test: when the compose file lives in a subdirectory,
    /// `remove_clean_artifacts` must delete `state.json` at the
    /// process-level default path, not inside the compose directory.
    #[test]
    fn clean_removes_state_from_default_path_not_compose_dir() {
        let root = tempfile::tempdir().unwrap();
        let compose_dir = root.path().join("subdir");
        std::fs::create_dir_all(&compose_dir).unwrap();

        // state.json lives in the process working directory (root),
        // NOT in the compose subdirectory.
        let state_path = root.path().join("state.json");
        std::fs::write(&state_path, "{}").unwrap();

        // .env and secrets/ live in the compose directory.
        std::fs::write(compose_dir.join(".env"), "K=V").unwrap();
        std::fs::create_dir(compose_dir.join("secrets")).unwrap();

        let messages = Messages::new("en").unwrap();
        remove_clean_artifacts(&compose_dir, &state_path, &messages).unwrap();

        assert!(!state_path.exists(), "state.json should be deleted");
        assert!(
            !compose_dir.join(".env").exists(),
            ".env should be deleted from compose dir"
        );
        assert!(
            !compose_dir.join("secrets").exists(),
            "secrets/ should be deleted from compose dir"
        );
        // The compose subdirectory had no state.json to begin with;
        // confirm it was never created there by accident.
        assert!(!compose_dir.join("state.json").exists());
    }

    /// Closes #588 §5b regression: `--openbao-only` must scope volume
    /// removal so the openbao container's label drives the project
    /// prefix. Without this, the previous implementation ran
    /// `docker compose down -v` and would have wiped `postgres-data`.
    #[test]
    fn resolve_compose_project_uses_container_label_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let lookup = |container: &str, label: &str| -> Result<Option<String>> {
            assert_eq!(container, OPENBAO_CONTAINER_NAME);
            assert_eq!(label, COMPOSE_PROJECT_LABEL);
            Ok(Some("real-project-name".to_string()))
        };
        let project = resolve_compose_project(dir.path(), &lookup).unwrap();
        assert_eq!(project, "real-project-name");
    }

    #[test]
    fn resolve_compose_project_falls_back_to_compose_dir_basename() {
        let _guard = env_lock();
        let prior = std::env::var_os("COMPOSE_PROJECT_NAME");
        clear_compose_project_name();
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Bootroot.Stack");
        std::fs::create_dir(&dir).unwrap();
        let lookup = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        let project = resolve_compose_project(&dir, &lookup).unwrap();
        if let Some(prior) = prior {
            // SAFETY: still inside the env_lock guard.
            unsafe { std::env::set_var("COMPOSE_PROJECT_NAME", prior) };
        }
        // Lowercased, non-`[a-z0-9_-]` stripped — matches docker
        // compose's default project-name normalisation.
        assert_eq!(project, "bootrootstack");
    }

    /// Closes the Round-8 bug: with the container label unavailable
    /// (e.g. the stuck-after-`clean --openbao-only` recovery path),
    /// volume removal must honour `COMPOSE_PROJECT_NAME` so the
    /// `<env>_openbao-data` volume that `docker compose up` will
    /// recreate is the same one reinit just wiped.  Without this the
    /// basename-fallback would target `<basename>_openbao-data`,
    /// leaving the real env-selected volume intact and recreating the
    /// initialized-without-root-token failure mode.
    #[test]
    fn resolve_compose_project_honours_env_var_when_label_absent() {
        let _guard = env_lock();
        let prior = std::env::var_os("COMPOSE_PROJECT_NAME");
        // SAFETY: env mutation is serialised by `env_lock` above.
        unsafe { std::env::set_var("COMPOSE_PROJECT_NAME", "env-project") };
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("BasenameWouldDiffer");
        std::fs::create_dir(&dir).unwrap();
        let lookup = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        let project = resolve_compose_project(&dir, &lookup).unwrap();
        // Restore the prior env value before assertions so a failure
        // does not leave the shared env mutated.
        if let Some(prior) = prior {
            // SAFETY: still inside the env_lock guard.
            unsafe { std::env::set_var("COMPOSE_PROJECT_NAME", prior) };
        } else {
            // SAFETY: still inside the env_lock guard.
            unsafe { std::env::remove_var("COMPOSE_PROJECT_NAME") };
        }
        assert_eq!(project, "env-project");
    }

    /// The container label is authoritative for what to delete (the
    /// resources were physically created under that project), so it
    /// must win over a divergent `COMPOSE_PROJECT_NAME`.
    #[test]
    fn resolve_compose_project_prefers_container_label_over_env_var() {
        let _guard = env_lock();
        let prior = std::env::var_os("COMPOSE_PROJECT_NAME");
        // SAFETY: env mutation is serialised by `env_lock` above.
        unsafe { std::env::set_var("COMPOSE_PROJECT_NAME", "env-project") };
        let dir = tempfile::tempdir().unwrap();
        let lookup =
            |_: &str, _: &str| -> Result<Option<String>> { Ok(Some("label-project".to_string())) };
        let project = resolve_compose_project(dir.path(), &lookup).unwrap();
        if let Some(prior) = prior {
            // SAFETY: still inside the env_lock guard.
            unsafe { std::env::set_var("COMPOSE_PROJECT_NAME", prior) };
        } else {
            // SAFETY: still inside the env_lock guard.
            unsafe { std::env::remove_var("COMPOSE_PROJECT_NAME") };
        }
        assert_eq!(project, "label-project");
    }

    #[test]
    fn resolve_compose_project_errors_when_basename_normalises_to_empty() {
        let _guard = env_lock();
        let prior = std::env::var_os("COMPOSE_PROJECT_NAME");
        clear_compose_project_name();
        // A directory whose basename strips to empty under the
        // normalisation rule (no ASCII alphanumerics) must not silently
        // produce `_openbao-data` (which would target a nonexistent
        // volume and mask the error).
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("###");
        std::fs::create_dir(&dir).unwrap();
        let lookup = |_: &str, _: &str| -> Result<Option<String>> { Ok(None) };
        let err = resolve_compose_project(&dir, &lookup).unwrap_err();
        if let Some(prior) = prior {
            // SAFETY: still inside the env_lock guard.
            unsafe { std::env::set_var("COMPOSE_PROJECT_NAME", prior) };
        }
        assert!(err.to_string().contains("compose project name"));
    }

    #[test]
    fn normalise_compose_project_name_strips_disallowed_chars() {
        assert_eq!(normalise_compose_project_name("Foo.Bar"), "foobar");
        assert_eq!(normalise_compose_project_name("foo_bar-baz"), "foo_bar-baz");
        assert_eq!(normalise_compose_project_name("a/b\\c d"), "abcd");
    }
}
