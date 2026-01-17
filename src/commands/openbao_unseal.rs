use std::path::Path;

use anyhow::{Context, Result};

use crate::i18n::Messages;

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

    fn test_messages() -> Messages {
        Messages::new("en").expect("messages")
    }

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
