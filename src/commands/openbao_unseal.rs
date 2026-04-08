use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;

use crate::i18n::Messages;

const UNSEAL_KEYS_DIR: &str = "openbao";
const UNSEAL_KEYS_FILENAME: &str = "unseal-keys.txt";

/// Returns the default path for the unseal keys file within a secrets
/// directory.
pub(crate) fn unseal_keys_path(secrets_dir: &Path) -> std::path::PathBuf {
    secrets_dir.join(UNSEAL_KEYS_DIR).join(UNSEAL_KEYS_FILENAME)
}

/// Saves unseal keys to a file with restricted permissions.
pub(crate) async fn save_unseal_keys(
    secrets_dir: &Path,
    keys: &[String],
    messages: &Messages,
) -> Result<std::path::PathBuf> {
    let dir = secrets_dir.join(UNSEAL_KEYS_DIR);
    fs_util::ensure_secrets_dir(&dir).await?;
    let path = dir.join(UNSEAL_KEYS_FILENAME);
    let contents = keys.join("\n") + "\n";
    tokio::fs::write(&path, contents)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    fs_util::set_key_permissions(&path).await?;
    Ok(path)
}

/// Deletes the unseal keys file if it exists.
pub(crate) fn delete_unseal_keys(secrets_dir: &Path, messages: &Messages) -> Result<()> {
    let path = unseal_keys_path(secrets_dir);
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| messages.error_remove_file_failed(&path.display().to_string()))?;
        println!(
            "{}",
            messages.openbao_unseal_keys_deleted(&path.display().to_string())
        );
    }
    Ok(())
}

/// Prompts the user for unseal keys via stdin (interactive).
pub(crate) fn prompt_unseal_keys_interactive(
    threshold: Option<u32>,
    messages: &Messages,
) -> Result<Vec<String>> {
    use std::io::{self, Write};

    let count = match threshold {
        Some(value) if value > 0 => value,
        _ => {
            print!("Unseal key threshold (t): ");
            io::stdout()
                .flush()
                .with_context(|| messages.error_prompt_flush_failed())?;
            let mut input = String::new();
            io::stdin()
                .read_line(&mut input)
                .with_context(|| messages.error_prompt_read_failed())?;
            input
                .trim()
                .parse::<u32>()
                .context(messages.error_prompt_read_failed())?
        }
    };
    let mut keys = Vec::with_capacity(count as usize);
    for index in 1..=count {
        print!("Unseal key {index}/{count}: ");
        io::stdout()
            .flush()
            .with_context(|| messages.error_prompt_flush_failed())?;
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .with_context(|| messages.error_prompt_read_failed())?;
        keys.push(input.trim().to_string());
    }
    Ok(keys)
}

/// CLI handler for `bootroot openbao save-unseal-keys`.
pub(crate) fn run_save_unseal_keys(
    args: &crate::cli::args::OpenbaoSaveUnsealKeysArgs,
    messages: &Messages,
) -> Result<()> {
    let keys = prompt_unseal_keys_interactive(None, messages)?;
    let runtime = tokio::runtime::Runtime::new()
        .with_context(|| messages.error_openbao_save_unseal_keys_failed())?;
    let path = runtime.block_on(save_unseal_keys(&args.secrets_dir, &keys, messages))?;
    println!(
        "{}",
        messages.openbao_unseal_keys_saved(&path.display().to_string())
    );
    Ok(())
}

pub(crate) fn read_unseal_keys_from_file(path: &Path, messages: &Messages) -> Result<Vec<String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let keys: Vec<String> = contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();
    if keys.is_empty() {
        anyhow::bail!(messages.error_openbao_unseal_file_empty(&path.display().to_string()));
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::i18n::test_messages;

    #[test]
    fn test_read_unseal_keys_from_file_filters_empty_lines() {
        let temp_dir = tempdir().expect("temp dir");
        let file_path = temp_dir.path().join("unseal.txt");
        std::fs::write(&file_path, "\n key-1 \n\nkey-2\n").expect("write");

        let keys = read_unseal_keys_from_file(&file_path, &test_messages()).expect("keys");
        assert_eq!(keys, vec!["key-1".to_string(), "key-2".to_string()]);
    }

    #[test]
    fn test_read_unseal_keys_from_file_errors_on_empty() {
        let temp_dir = tempdir().expect("temp dir");
        let file_path = temp_dir.path().join("unseal.txt");
        std::fs::write(&file_path, "\n\n").expect("write");

        let err = read_unseal_keys_from_file(&file_path, &test_messages()).unwrap_err();
        assert!(err.to_string().contains("Unseal key file is empty"));
    }
}
