use std::path::Path;

use anyhow::{Context, Result};

use crate::cli::args::CleanArgs;
use crate::commands::infra::run_docker;
use crate::commands::init::prompt_yes_no;
use crate::i18n::Messages;
use crate::state::StateFile;

const OPENBAO_AGENT_OVERRIDE: &str = "secrets/openbao/docker-compose.openbao-agent.override.yml";

pub(crate) fn run_clean(args: &CleanArgs, messages: &Messages) -> Result<()> {
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
    let mut down_args: Vec<&str> = vec![
        "compose",
        "-f",
        &compose_str,
        "down",
        "-v",
        "--remove-orphans",
    ];

    let override_path = compose_dir.join(OPENBAO_AGENT_OVERRIDE);
    let override_str = override_path.to_string_lossy();
    if override_path.exists() {
        down_args.insert(3, "-f");
        down_args.insert(4, &override_str);
    }
    run_docker(&down_args, "docker compose down", messages)?;

    remove_clean_artifacts(compose_dir, &StateFile::default_path(), messages)?;

    let remove_certs = args.yes || prompt_yes_no(messages.clean_confirm_certs(), messages)?;
    if remove_certs {
        remove_path_if_exists(&compose_dir.join("certs"), messages)?;
    }

    println!("{}", messages.clean_completed());
    Ok(())
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
    use crate::i18n::Messages;

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
}
