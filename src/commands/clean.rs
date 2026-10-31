use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};

use crate::cli::args::CleanArgs;
use crate::commands::compose_file::compose_file_dir;
use crate::commands::compose_project::{ComposeIdentity, DOCKER_BIN};
use crate::commands::container_name::BootrootContainer;
use crate::commands::infra::{run_compose, run_compose_with_exec, run_docker_with_exec};
use crate::commands::init::{
    POSTGRES_COMPOSE_DIR, POSTGRES_TLS_COMPOSE_OVERRIDE_DIR, POSTGRES_TLS_COMPOSE_OVERRIDE_NAME,
    prompt_yes_no,
};
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

/// Named volumes the `openbao` compose service mounts: only its storage.
/// Its audit records have no volume of their own — they go to the
/// container log, or, on a registrar endpoint host, to the audit store
/// the audit override bind-mounts, which no clean removes. Removing only
/// these is the contract `--openbao-only` advertises (#588 §5b); using
/// `docker compose down -v` instead would also wipe `postgres-data`,
/// `prometheus-data`, and `grafana-data`.
pub(crate) const OPENBAO_NAMED_VOLUMES: &[&str] = &["openbao-data"];

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

    let identity = ComposeIdentity::resolve_for_dir(compose_dir, None, messages)?;
    let down_paths = clean_down_files(&args.compose_file.compose_file, compose_dir);
    let down_strs: Vec<String> = down_paths
        .iter()
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    let down_files: Vec<&str> = down_strs.iter().map(String::as_str).collect();

    let down = identity.compose(&down_files, None, &["down", "-v", "--remove-orphans"]);
    run_compose(&down, "docker compose down", messages)?;

    remove_clean_artifacts(compose_dir, &StateFile::default_path(), messages)?;

    let remove_certs = args.yes || prompt_yes_no(messages.clean_confirm_certs(), messages)?;
    if remove_certs {
        remove_path_if_exists(&compose_dir.join("certs"), messages)?;
    }

    println!("{}", messages.clean_completed());
    Ok(())
}

/// Returns the compose files `clean` passes to `docker compose down`:
/// the compose file, then each override `init` or `infra install` wrote
/// that is present.
fn clean_down_files(compose_file: &Path, compose_dir: &Path) -> Vec<PathBuf> {
    let overrides = [
        compose_dir.join(OPENBAO_AGENT_OVERRIDE),
        compose_dir.join(OPENBAO_EXPOSED_OVERRIDE),
        compose_dir
            .join("secrets")
            .join(POSTGRES_TLS_COMPOSE_OVERRIDE_DIR)
            .join(POSTGRES_TLS_COMPOSE_OVERRIDE_NAME),
    ];
    std::iter::once(compose_file.to_path_buf())
        .chain(overrides.into_iter().filter(|path| path.exists()))
        .collect()
}

/// Removes only the `bootroot-openbao` container and its volume.
/// Leaves every other compose service, `secrets/`, `postgres/`,
/// `state.json`, and `.env` intact so an operator can recover from a
/// partial-init `OpenBao` state without losing application DB / step-ca
/// state.
/// See issue #588 §5b.
fn run_clean_openbao_only(args: &CleanArgs, messages: &Messages) -> Result<()> {
    let identity = ComposeIdentity::resolve(&args.compose_file.compose_file, None, messages)?;
    let openbao_container = identity.container(BootrootContainer::OpenBao);
    if !args.yes
        && !prompt_yes_no(
            &messages.clean_confirm_openbao_only(&openbao_container),
            messages,
        )?
    {
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
    remove_openbao_container_and_volumes_with_exec(compose_file, Path::new(DOCKER_BIN), messages)
}

/// [`remove_openbao_container_and_volumes`] with `docker` as the
/// executable, so a test can name a fake.
fn remove_openbao_container_and_volumes_with_exec(
    compose_file: &Path,
    docker: &Path,
    messages: &Messages,
) -> Result<()> {
    let compose_str = compose_file.to_string_lossy();
    let compose_dir = compose_file_dir(compose_file);
    let compose_dir = compose_dir.as_path();

    // The project the containers and volumes were created under is now
    // known without asking the daemon: every invocation passes an
    // explicit `-p` derived from this same resolver, so the removal and
    // the next `docker compose up` cannot disagree.
    let identity = ComposeIdentity::resolve_for_dir(compose_dir, None, messages)?;

    let stop = identity.compose(&[&compose_str], None, &["stop", "openbao"]);
    let _ = run_compose_with_exec(&stop, "docker compose stop openbao", docker, messages);
    let rm = identity.compose(&[&compose_str], None, &["rm", "-fsv", "openbao"]);
    run_compose_with_exec(&rm, "docker compose rm openbao", docker, messages)?;

    // Remove ONLY the openbao-owned named volumes. `docker compose down
    // -v` removes every named volume in the compose file regardless of
    // any positional service argument and would wipe `postgres-data`,
    // `prometheus-data`, `grafana-data` along with openbao's volumes.
    for vol in OPENBAO_NAMED_VOLUMES {
        let full = format!("{}_{vol}", identity.project());
        let vol_args = ["volume", "rm", "-f", full.as_str()];
        run_docker_with_exec(
            &vol_args,
            &format!("docker volume rm {full}"),
            docker,
            messages,
        )?;
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
/// `secrets/`, `postgres/` and `.env` live in the compose file directory
/// (Docker Compose resolves bind-mount paths relative to the compose
/// file).  Removing `postgres/` needs no privilege although its key is
/// owned by uid 999: `postgres/tls` is the secrets-directory owner's.
/// `state.json` lives at `StateFile::default_path()` (the process
/// working directory), which may differ when `--compose-file` points
/// elsewhere.
fn remove_clean_artifacts(
    compose_dir: &Path,
    state_path: &Path,
    messages: &Messages,
) -> Result<()> {
    remove_path_if_exists(&compose_dir.join("secrets"), messages)?;
    remove_path_if_exists(&compose_dir.join(POSTGRES_COMPOSE_DIR), messages)?;
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
    use crate::commands::compose_project::resolve_compose_project_for_dir;
    use crate::i18n::Messages;

    // The project-resolution tests below cover what the retired
    // label-first / basename-last derivation covered, restated for the
    // shared resolver in `commands::compose_project`.  Its former
    // "basename normalises to empty" error case is deliberately gone
    // rather than lost: the shared resolver never derives a name from the
    // filesystem, so no input can reach it.

    /// The removal list is exactly the `openbao-*` named volumes the
    /// shipped compose files declare, so `--openbao-only` and `reinit`
    /// neither leave `OpenBao` state behind nor name a volume that no
    /// longer exists.
    #[test]
    fn openbao_named_volumes_match_the_shipped_compose_files() {
        assert_eq!(OPENBAO_NAMED_VOLUMES, &["openbao-data"]);
        for compose in ["docker-compose.yml", "docker-compose.deploy.yml"] {
            let content =
                std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join(compose))
                    .unwrap();
            let top_level = content
                .split("\nvolumes:\n")
                .nth(1)
                .unwrap_or_else(|| panic!("{compose} declares no top-level volumes"));
            let declared: Vec<&str> = top_level
                .lines()
                .take_while(|line| line.is_empty() || line.starts_with(' '))
                .filter_map(|line| line.trim().strip_suffix(':'))
                .filter(|name| name.starts_with("openbao"))
                .collect();
            assert_eq!(declared, OPENBAO_NAMED_VOLUMES, "{compose}");
            assert!(!content.contains("openbao-audit:"), "{compose}");
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

    /// The `PostgreSQL` TLS override joins `down` when `init` wrote it,
    /// after the compose file and the other overrides.
    #[test]
    fn clean_down_files_carry_the_postgres_tls_override_when_present() {
        let root = tempfile::tempdir().unwrap();
        let compose_file = root.path().join("docker-compose.yml");
        assert_eq!(
            clean_down_files(&compose_file, root.path()),
            vec![compose_file.clone()]
        );

        let exposed = root.path().join(OPENBAO_EXPOSED_OVERRIDE);
        std::fs::create_dir_all(exposed.parent().unwrap()).unwrap();
        std::fs::write(&exposed, "services: {}").unwrap();
        let postgres_tls = root
            .path()
            .join("secrets/postgres/docker-compose.postgres-tls.yml");
        std::fs::create_dir_all(postgres_tls.parent().unwrap()).unwrap();
        std::fs::write(&postgres_tls, "services: {}").unwrap();

        assert_eq!(
            clean_down_files(&compose_file, root.path()),
            vec![compose_file, exposed, postgres_tls]
        );
    }

    /// A full clean leaves no private key behind, nor `pg_hba.conf`.
    #[test]
    fn clean_removes_the_postgres_directory() {
        let root = tempfile::tempdir().unwrap();
        let tls_dir = root.path().join("postgres").join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("server.key"), "key").unwrap();
        std::fs::write(root.path().join("postgres").join("pg_hba.conf"), "hba").unwrap();

        remove_clean_artifacts(
            root.path(),
            &root.path().join("state.json"),
            &Messages::new("en").unwrap(),
        )
        .unwrap();

        assert!(!root.path().join("postgres").exists());
    }

    /// `--openbao-only` touches the `openbao` container and its volume
    /// and nothing on disk, so the `PostgreSQL` certificate survives it.
    #[test]
    fn clean_openbao_only_leaves_the_postgres_directory() {
        let root = tempfile::tempdir().unwrap();
        let tls_dir = root.path().join("postgres").join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("server.key"), "key").unwrap();
        let fake = root.path().join("fake-docker");
        let args_log = root.path().join("docker_args.log");
        write_logging_fake_docker(&fake, &args_log);

        remove_openbao_container_and_volumes_with_exec(
            &root.path().join("docker-compose.yml"),
            &fake,
            &Messages::new("en").unwrap(),
        )
        .unwrap();

        assert!(tls_dir.join("server.key").exists());
        let log = std::fs::read_to_string(&args_log).unwrap();
        assert!(
            log.contains("rm -fsv openbao"),
            "the fake must have stood in for docker, got: {log}"
        );
    }

    /// Writes a fake `docker` that logs each invocation to `args_log`.
    fn write_logging_fake_docker(path: &Path, args_log: &Path) {
        let script = format!(
            "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\n",
            args_log.display()
        );
        crate::test_support::write_executable(path, script.as_bytes());
    }

    /// Closes #588 §5b regression: `--openbao-only` must scope volume
    /// removal to the compose project so the previous `docker compose
    /// down -v` cannot wipe `postgres-data`.  The project now comes from
    /// the shared resolver rather than the container label, so the
    /// recorded identity is what drives the `<project>_<volume>` prefix.
    #[test]
    fn resolve_compose_project_uses_the_recorded_instance() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(".env"),
            "BOOTROOT_INSTANCE=real-project-name\n",
        )
        .unwrap();
        let project =
            resolve_compose_project_for_dir(dir.path(), None, None, &Messages::new("en").unwrap())
                .unwrap();
        assert_eq!(project, "real-project-name");
    }

    /// The basename derivation is gone: an install in a directory named
    /// anything at all lands in the fixed default project, so `clean`
    /// targets the same project a fresh `infra install` created.
    #[test]
    fn resolve_compose_project_falls_back_to_the_fixed_default() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("Bootroot.Stack");
        std::fs::create_dir(&dir).unwrap();
        let project =
            resolve_compose_project_for_dir(&dir, None, None, &Messages::new("en").unwrap())
                .unwrap();
        assert_eq!(project, "bootroot");
    }

    /// The E2E harness exports `COMPOSE_PROJECT_NAME` for a whole
    /// scenario; volume removal must target the project `docker compose
    /// up` will recreate under, otherwise reinit wipes one volume while
    /// the stack comes back on another.
    #[test]
    fn resolve_compose_project_honours_env_var_over_the_recorded_instance() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(".env"), "BOOTROOT_INSTANCE=recorded\n").unwrap();
        let project = resolve_compose_project_for_dir(
            dir.path(),
            None,
            Some("env-project"),
            &Messages::new("en").unwrap(),
        )
        .unwrap();
        assert_eq!(project, "env-project");
    }

    /// Regression for #611: `--compose-file docker-compose.yml` derives a
    /// `.`-relative compose dir, which the resolver must handle.  The old
    /// derivation `canonicalize`d it; the shared one only reads the
    /// `.env` beside it.
    #[test]
    fn resolve_compose_project_handles_dot_relative_compose_dir() {
        let compose_dir = compose_file_dir(Path::new("docker-compose.yml"));
        assert_eq!(compose_dir, std::path::PathBuf::from("."));
        let project = resolve_compose_project_for_dir(
            &compose_dir,
            None,
            None,
            &Messages::new("en").unwrap(),
        )
        .expect("resolve_compose_project_for_dir must succeed for `.`");
        assert_ne!(project, "");
    }

    /// Companion to the test above: an exported `COMPOSE_PROJECT_NAME`
    /// must still win when the compose dir is the helper-normalised `.`.
    #[test]
    fn resolve_compose_project_honours_env_var_for_dot_relative_compose_dir() {
        let compose_dir = compose_file_dir(Path::new("docker-compose.yml"));
        let project = resolve_compose_project_for_dir(
            &compose_dir,
            None,
            Some("explicit-env-project"),
            &Messages::new("en").unwrap(),
        )
        .unwrap();
        assert_eq!(project, "explicit-env-project");
    }
}
