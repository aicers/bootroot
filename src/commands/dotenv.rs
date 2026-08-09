use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};

use crate::commands::compose_project::COMPOSE_PROJECT_NAME_ENV;
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

/// Decides which of `entries` [`load_dotenv_into_env`] would apply,
/// given `is_set`, which answers whether a key already has a value in
/// the target environment.
///
/// The whole decision, split off from the one mutation it feeds so it
/// can be exercised — the exclusion below above all — without a process
/// environment to steer.
fn dotenv_pairs_to_apply<'a>(
    entries: &'a BTreeMap<String, String>,
    is_set: &dyn Fn(&str) -> bool,
) -> Vec<(&'a str, &'a str)> {
    entries
        .iter()
        .filter(|(key, _)| key.as_str() != COMPOSE_PROJECT_NAME_ENV)
        .filter(|(key, _)| !is_set(key))
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect()
}

/// Loads key-value pairs from a `.env` file into the process environment.
///
/// Only sets variables that are not already present in the process
/// environment, preserving Docker Compose's precedence semantics (process
/// env > `.env` file).
///
/// [`COMPOSE_PROJECT_NAME_ENV`] is deliberately excluded.  The compose
/// project resolver reads it from the *invoking* environment, and `init`
/// resolves the project once before calling this and then lets several
/// sub-steps re-resolve it afterwards.  Promoting a `.env`-authored value
/// into the process environment here would make those later resolutions
/// disagree with the first, so `init` would bring the core services up in
/// one project and the agent sidecars, the responder override and the
/// `OpenBao` TLS recreate up in another — a different compose network, so
/// DNS to step-ca would break.  The key is not otherwise needed: every
/// compose invocation passes an explicit `-p`, which outranks the
/// variable, and Compose reads the `.env` beside the compose file for its
/// own interpolation regardless.
pub(crate) fn load_dotenv_into_env(path: &Path, messages: &Messages) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let map = read_dotenv(path, messages)?;
    for (key, value) in dotenv_pairs_to_apply(&map, &|key| std::env::var(key).is_ok()) {
        // SAFETY: called once during single-threaded init setup,
        // before any worker threads are spawned.
        unsafe {
            std::env::set_var(key, value);
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

    /// Builds the parsed `.env` a load would be handed.
    fn entries(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect()
    }

    /// An environment holding exactly `set`.
    fn holding(set: &'static [&'static str]) -> impl Fn(&str) -> bool {
        move |key: &str| set.contains(&key)
    }

    #[test]
    fn load_dotenv_applies_keys_the_environment_does_not_hold() {
        let map = entries(&[("DOTENV_A", "from_file"), ("DOTENV_B", "also_from_file")]);
        assert_eq!(
            dotenv_pairs_to_apply(&map, &holding(&[])),
            vec![("DOTENV_A", "from_file"), ("DOTENV_B", "also_from_file")]
        );
    }

    #[test]
    fn load_dotenv_does_not_overwrite_a_key_the_environment_already_holds() {
        let map = entries(&[("DOTENV_A", "from_file"), ("DOTENV_B", "also_from_file")]);
        assert_eq!(
            dotenv_pairs_to_apply(&map, &holding(&["DOTENV_A"])),
            vec![("DOTENV_B", "also_from_file")],
            "process env > .env file, so an already-set key is left alone"
        );
    }

    /// `init` resolves the compose project once before this load and
    /// then lets the agent-sidecar override, the responder override, the
    /// `OpenBao` TLS recreate, the DB-password rotation and rollback
    /// re-resolve it afterwards.  Promoting a `.env`-authored
    /// `COMPOSE_PROJECT_NAME` into the process environment would make
    /// those later resolutions return a different project than the
    /// first, splitting one `init` run across two compose networks.  The
    /// resolver's second step reads the *invoking* environment, and a
    /// `.env` key is not that.
    #[test]
    fn load_dotenv_into_env_never_promotes_compose_project_name() {
        let map = entries(&[
            (COMPOSE_PROJECT_NAME_ENV, "from-dotenv"),
            ("BOOTROOT_INSTANCE", "insight"),
        ]);
        let applied = dotenv_pairs_to_apply(&map, &holding(&[]));
        assert!(
            !applied
                .iter()
                .any(|(key, _)| *key == COMPOSE_PROJECT_NAME_ENV),
            "a .env-authored {COMPOSE_PROJECT_NAME_ENV} must never be applied: {applied:?}"
        );
    }

    /// The key is skipped because of what it is, not because something
    /// else already holds it: an unset `COMPOSE_PROJECT_NAME` is exactly
    /// the case where a promotion would change the resolved project.
    #[test]
    fn compose_project_name_is_excluded_even_when_the_environment_is_empty() {
        let map = entries(&[(COMPOSE_PROJECT_NAME_ENV, "from-dotenv")]);
        assert!(dotenv_pairs_to_apply(&map, &holding(&[])).is_empty());
    }

    /// The exclusion is scoped to that one key: everything else `.env`
    /// carries still has to reach the process environment, which is the
    /// whole point of the load (`POSTGRES_PASSWORD` for the DSN builders).
    #[test]
    fn load_dotenv_into_env_still_loads_other_keys_alongside_it() {
        let map = entries(&[
            (COMPOSE_PROJECT_NAME_ENV, "from-dotenv"),
            ("POSTGRES_PASSWORD", "from_file"),
        ]);
        assert_eq!(
            dotenv_pairs_to_apply(&map, &holding(&[])),
            vec![("POSTGRES_PASSWORD", "from_file")]
        );
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
