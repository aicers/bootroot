use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::i18n::Messages;

/// Reads a `.env` file and returns key-value pairs.
///
/// Lines starting with `#` are treated as comments.  Blank lines are
/// skipped.  Values may optionally be quoted with single or double
/// quotes; the quotes are stripped.
pub(crate) fn read_dotenv(path: &Path, messages: &Messages) -> Result<BTreeMap<String, String>> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    parse_dotenv(&contents, messages)
}

fn parse_dotenv(contents: &str, messages: &Messages) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            anyhow::bail!(messages.error_env_parse_failed(trimmed));
        };
        let key = key.trim().to_string();
        let value = strip_quotes(value.trim());
        map.insert(key, value);
    }
    Ok(map)
}

fn strip_quotes(value: &str) -> String {
    if ((value.starts_with('"') && value.ends_with('"'))
        || (value.starts_with('\'') && value.ends_with('\'')))
        && value.len() >= 2
    {
        return value[1..value.len() - 1].to_string();
    }
    value.to_string()
}

/// Writes a `.env` file from key-value pairs.
pub(crate) fn write_dotenv(
    path: &Path,
    entries: &[(&str, &str)],
    messages: &Messages,
) -> Result<()> {
    let mut content = String::new();
    for (key, value) in entries {
        content.push_str(key);
        content.push('=');
        content.push_str(value);
        content.push('\n');
    }
    std::fs::write(path, content)
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

/// Loads key-value pairs from a `.env` file into the process environment.
///
/// Only sets variables that are not already present in the process
/// environment, preserving Docker Compose's precedence semantics (process
/// env > `.env` file).
pub(crate) fn load_dotenv_into_env(path: &Path, messages: &Messages) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let map = read_dotenv(path, messages)?;
    for (key, value) in &map {
        if std::env::var(key).is_err() {
            // SAFETY: called once during single-threaded init setup,
            // before any worker threads are spawned.
            unsafe {
                std::env::set_var(key, value);
            }
        }
    }
    Ok(())
}

/// Updates a single key in an existing `.env` file, preserving other entries.
pub(crate) fn update_dotenv_key(
    path: &Path,
    key: &str,
    new_value: &str,
    messages: &Messages,
) -> Result<()> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let mut found = false;
    let mut output = String::new();
    for line in contents.lines() {
        let trimmed = line.trim();
        if !trimmed.is_empty()
            && !trimmed.starts_with('#')
            && trimmed
                .split_once('=')
                .is_some_and(|(k, _)| k.trim() == key)
        {
            output.push_str(key);
            output.push('=');
            output.push_str(new_value);
            output.push('\n');
            found = true;
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if !found {
        output.push_str(key);
        output.push('=');
        output.push_str(new_value);
        output.push('\n');
    }
    std::fs::write(path, output)
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::i18n::test_messages;

    #[test]
    fn test_parse_dotenv_basic() {
        let messages = test_messages();
        let map = parse_dotenv("FOO=bar\nBAZ=qux\n", &messages).unwrap();
        assert_eq!(map.get("FOO").unwrap(), "bar");
        assert_eq!(map.get("BAZ").unwrap(), "qux");
    }

    #[test]
    fn test_parse_dotenv_strips_quotes() {
        let messages = test_messages();
        let map = parse_dotenv("A=\"hello\"\nB='world'\n", &messages).unwrap();
        assert_eq!(map.get("A").unwrap(), "hello");
        assert_eq!(map.get("B").unwrap(), "world");
    }

    #[test]
    fn test_parse_dotenv_skips_comments_and_blank_lines() {
        let messages = test_messages();
        let map = parse_dotenv("# comment\n\nKEY=val\n", &messages).unwrap();
        assert_eq!(map.len(), 1);
        assert_eq!(map.get("KEY").unwrap(), "val");
    }

    #[test]
    fn test_write_and_read_dotenv() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".env");
        let messages = test_messages();
        write_dotenv(&path, &[("A", "1"), ("B", "2")], &messages).unwrap();
        let map = read_dotenv(&path, &messages).unwrap();
        assert_eq!(map.get("A").unwrap(), "1");
        assert_eq!(map.get("B").unwrap(), "2");
    }

    #[test]
    fn test_update_dotenv_key_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".env");
        let messages = test_messages();
        std::fs::write(&path, "A=old\nB=keep\n").unwrap();
        update_dotenv_key(&path, "A", "new", &messages).unwrap();
        let map = read_dotenv(&path, &messages).unwrap();
        assert_eq!(map.get("A").unwrap(), "new");
        assert_eq!(map.get("B").unwrap(), "keep");
    }

    #[test]
    fn test_load_dotenv_into_env_sets_missing_vars() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".env");
        let messages = test_messages();
        // Use a unique key to avoid collision with parallel tests.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let key = format!("DOTENV_TEST_{nonce}");
        std::fs::write(&path, format!("{key}=from_file\n")).unwrap();

        // SAFETY: test-only, unique key avoids interference.
        unsafe {
            std::env::remove_var(&key);
        }
        load_dotenv_into_env(&path, &messages).unwrap();
        assert_eq!(std::env::var(&key).unwrap(), "from_file");

        // Clean up.
        unsafe {
            std::env::remove_var(&key);
        }
    }

    #[test]
    fn test_load_dotenv_into_env_does_not_overwrite_existing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".env");
        let messages = test_messages();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let key = format!("DOTENV_EXIST_{nonce}");
        std::fs::write(&path, format!("{key}=from_file\n")).unwrap();

        // SAFETY: test-only, unique key avoids interference.
        unsafe {
            std::env::set_var(&key, "already_set");
        }
        load_dotenv_into_env(&path, &messages).unwrap();
        assert_eq!(std::env::var(&key).unwrap(), "already_set");

        // Clean up.
        unsafe {
            std::env::remove_var(&key);
        }
    }

    #[test]
    fn test_load_dotenv_into_env_noop_if_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent-env");
        let messages = test_messages();
        // Should succeed without error when file does not exist.
        load_dotenv_into_env(&path, &messages).unwrap();
    }

    #[test]
    fn test_update_dotenv_key_appends_missing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(".env");
        let messages = test_messages();
        std::fs::write(&path, "A=1\n").unwrap();
        update_dotenv_key(&path, "B", "2", &messages).unwrap();
        let map = read_dotenv(&path, &messages).unwrap();
        assert_eq!(map.get("A").unwrap(), "1");
        assert_eq!(map.get("B").unwrap(), "2");
    }
}
