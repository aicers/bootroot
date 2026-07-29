use std::path::Path;
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};

use crate::cli::args::CleanArgs;
use crate::commands::compose_file::compose_file_dir;
use crate::commands::compose_project::{compose_args, resolve_compose_project_for_dir};
use crate::commands::infra::run_docker;
use crate::commands::init::prompt_yes_no;
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
    let compose_dir = compose_file_dir(&args.compose_file.compose_file);
    let compose_dir = compose_dir.as_path();

    let compose_str = args.compose_file.compose_file.to_string_lossy();
    let project = resolve_compose_project_for_dir(compose_dir, None, messages)?;
    let mut down_files: Vec<&str> = vec![&compose_str];

    let agent_override_path = compose_dir.join(OPENBAO_AGENT_OVERRIDE);
    let agent_override_str = agent_override_path.to_string_lossy();
    if agent_override_path.exists() {
        down_files.push(&agent_override_str);
    }

    let exposed_override_path = compose_dir.join(OPENBAO_EXPOSED_OVERRIDE);
    let exposed_override_str = exposed_override_path.to_string_lossy();
    if exposed_override_path.exists() {
        down_files.push(&exposed_override_str);
    }

    let down_args = compose_args(
        &project,
        &down_files,
        None,
        &["down", "-v", "--remove-orphans"],
    );
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
    let compose_dir = compose_file_dir(compose_file);
    let compose_dir = compose_dir.as_path();

    // The project the containers and volumes were created under is now
    // known without asking the daemon: every invocation passes an
    // explicit `-p` derived from this same resolver, so the removal and
    // the next `docker compose up` cannot disagree.
    let project = resolve_compose_project_for_dir(compose_dir, None, messages)?;

    let stop_args = compose_args(&project, &[&compose_str], None, &["stop", "openbao"]);
    let _ = run_docker(&stop_args, "docker compose stop openbao", messages);
    let rm_args = compose_args(&project, &[&compose_str], None, &["rm", "-fsv", "openbao"]);
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
    use super::*;
    use crate::commands::compose_project::test_env::{ComposeProjectEnv, env_lock};
    use crate::i18n::Messages;

    // The project-resolution tests below cover what the retired
    // label-first / basename-last derivation covered, restated for the
    // shared resolver in `commands::compose_project`.  Its former
    // "basename normalises to empty" error case is deliberately gone
    // rather than lost: the shared resolver never derives a name from the
    // filesystem, so no input can reach it.

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
    /// removal to the compose project so the previous `docker compose
    /// down -v` cannot wipe `postgres-data`.  The project now comes from
    /// the shared resolver rather than the container label, so the
    /// recorded identity is what drives the `<project>_<volume>` prefix.
    #[test]
    fn resolve_compose_project_uses_the_recorded_instance() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(None);
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "BOOTROOT_INSTANCE=real-project-name\n",
        )
        .unwrap();
        let project =
            resolve_compose_project_for_dir(dir.path(), None, &Messages::new("en").unwrap())
                .unwrap();
        assert_eq!(project, "real-project-name");
    }

    /// The basename derivation is gone: an install in a directory named
    /// anything at all lands in the fixed default project, so `clean`
    /// targets the same project a fresh `infra install` created.
    #[test]
    fn resolve_compose_project_falls_back_to_the_fixed_default() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(None);
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Bootroot.Stack");
        std::fs::create_dir(&dir).unwrap();
        let project =
            resolve_compose_project_for_dir(&dir, None, &Messages::new("en").unwrap()).unwrap();
        assert_eq!(project, "bootroot");
    }

    /// The E2E harness exports `COMPOSE_PROJECT_NAME` for a whole
    /// scenario; volume removal must target the project `docker compose
    /// up` will recreate under, otherwise reinit wipes one volume while
    /// the stack comes back on another.
    #[test]
    fn resolve_compose_project_honours_env_var_over_the_recorded_instance() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(Some("env-project"));
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "BOOTROOT_INSTANCE=recorded\n").unwrap();
        let project =
            resolve_compose_project_for_dir(dir.path(), None, &Messages::new("en").unwrap())
                .unwrap();
        assert_eq!(project, "env-project");
    }

    /// Regression for #611: `--compose-file docker-compose.yml` derives a
    /// `.`-relative compose dir, which the resolver must handle.  The old
    /// derivation `canonicalize`d it; the shared one only reads the
    /// `.env` beside it.
    #[test]
    fn resolve_compose_project_handles_dot_relative_compose_dir() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(None);
        let compose_dir = compose_file_dir(Path::new("docker-compose.yml"));
        assert_eq!(compose_dir, std::path::PathBuf::from("."));
        let project =
            resolve_compose_project_for_dir(&compose_dir, None, &Messages::new("en").unwrap())
                .expect("resolve_compose_project_for_dir must succeed for `.`");
        assert!(!project.is_empty());
    }

    /// Companion to the test above: an exported `COMPOSE_PROJECT_NAME`
    /// must still win when the compose dir is the helper-normalised `.`.
    #[test]
    fn resolve_compose_project_honours_env_var_for_dot_relative_compose_dir() {
        let _guard = env_lock();
        let _env = ComposeProjectEnv::set(Some("explicit-env-project"));
        let compose_dir = compose_file_dir(Path::new("docker-compose.yml"));
        let project =
            resolve_compose_project_for_dir(&compose_dir, None, &Messages::new("en").unwrap())
                .unwrap();
        assert_eq!(project, "explicit-env-project");
    }
}
