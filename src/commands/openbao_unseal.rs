use std::io::BufRead;
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
    // This bootroot-owned secrets-tree path must replace a final symlink,
    // rather than follow a redirection an attacker could plant there.
    fs_util::atomic_write(
        &path,
        contents.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
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
///
/// # Errors
///
/// Returns an error when stdin reaches EOF before an answer is given,
/// when the threshold does not parse, or when stdout cannot be flushed.
pub(crate) fn prompt_unseal_keys_interactive(
    threshold: Option<u32>,
    messages: &Messages,
) -> Result<Vec<String>> {
    read_unseal_keys(&mut std::io::stdin().lock(), threshold, messages)
}

/// Reads the threshold and that many key shares from `input`.
fn read_unseal_keys(
    input: &mut dyn BufRead,
    threshold: Option<u32>,
    messages: &Messages,
) -> Result<Vec<String>> {
    let count = match threshold {
        Some(value) if value > 0 => value,
        _ => prompt_line(input, messages.prompt_unseal_threshold(), messages)?
            .parse::<u32>()
            .context(messages.error_invalid_unseal_threshold())?,
    };
    let capacity =
        usize::try_from(count).with_context(|| messages.error_invalid_unseal_threshold())?;
    let mut keys = Vec::with_capacity(capacity);
    for index in 1..=count {
        keys.push(prompt_line(
            input,
            &messages.prompt_unseal_key(index, count),
            messages,
        )?);
    }
    Ok(keys)
}

/// Writes `prompt` to stdout and reads one trimmed line from `input`.
///
/// EOF is not an answer. `read_line` reports it as `Ok(0)`, which is
/// indistinguishable from a blank line unless the count is checked, and
/// an unchecked count turns an exhausted stdin into a vector of empty
/// key shares that `save_unseal_keys` then writes over a real one.
fn prompt_line(input: &mut dyn BufRead, prompt: &str, messages: &Messages) -> Result<String> {
    use std::io::Write;
    print!("{prompt}");
    std::io::stdout()
        .flush()
        .with_context(|| messages.error_prompt_flush_failed())?;
    let mut line = String::new();
    let read = input
        .read_line(&mut line)
        .with_context(|| messages.error_prompt_read_failed())?;
    if read == 0 {
        anyhow::bail!(messages.error_prompt_eof());
    }
    Ok(line.trim().to_string())
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
    use std::io::Cursor;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

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

    /// EOF at the threshold prompt is not a blank answer.
    #[test]
    fn test_read_unseal_keys_errors_on_eof_at_threshold() {
        let messages = test_messages();
        let mut input = Cursor::new("");

        let err = read_unseal_keys(&mut input, None, &messages)
            .expect_err("EOF at the threshold prompt must error");
        assert_eq!(err.to_string(), messages.error_prompt_eof());
    }

    /// The reported destruction path: the threshold is answered and the
    /// shares are not, so every remaining read hits EOF.  Before the EOF
    /// check this returned three empty strings, which `save_unseal_keys`
    /// happily wrote over an existing key file.
    #[test]
    fn test_read_unseal_keys_errors_on_eof_after_threshold() {
        let messages = test_messages();
        let mut input = Cursor::new("3\n");

        let err = read_unseal_keys(&mut input, None, &messages)
            .expect_err("EOF at a key-share prompt must error");
        assert_eq!(err.to_string(), messages.error_prompt_eof());
    }

    /// EOF partway through the shares errors rather than padding the
    /// vector with the shares the operator never pasted.
    #[test]
    fn test_read_unseal_keys_errors_on_eof_midway() {
        let messages = test_messages();
        let mut input = Cursor::new("3\nkey-a\nkey-b\n");

        let err = read_unseal_keys(&mut input, None, &messages)
            .expect_err("EOF before the last share must error");
        assert_eq!(err.to_string(), messages.error_prompt_eof());
    }

    #[test]
    fn test_read_unseal_keys_reads_threshold_and_shares() {
        let messages = test_messages();
        let mut input = Cursor::new("2\n key-a \nkey-b\n");

        let keys = read_unseal_keys(&mut input, None, &messages).expect("keys");
        assert_eq!(keys, vec!["key-a".to_string(), "key-b".to_string()]);
    }

    /// A supplied threshold skips the threshold prompt, so the first
    /// line read is a key share rather than a count.
    #[test]
    fn test_read_unseal_keys_skips_threshold_prompt_when_supplied() {
        let messages = test_messages();
        let mut input = Cursor::new("key-a\nkey-b\n");

        let keys = read_unseal_keys(&mut input, Some(2), &messages).expect("keys");
        assert_eq!(keys, vec!["key-a".to_string(), "key-b".to_string()]);
    }

    /// A threshold that does not parse is an invalid threshold, not a
    /// read failure.
    #[test]
    fn test_read_unseal_keys_errors_on_unparsable_threshold() {
        let messages = test_messages();
        let mut input = Cursor::new("abc\n");

        let err = read_unseal_keys(&mut input, None, &messages)
            .expect_err("a non-numeric threshold must error");
        assert_eq!(err.to_string(), messages.error_invalid_unseal_threshold());
    }

    /// A blank line the operator typed is still a blank line: it reaches
    /// the parse and fails there, distinct from the EOF error above.
    #[test]
    fn test_read_unseal_keys_treats_blank_threshold_as_parse_failure() {
        let messages = test_messages();
        let mut input = Cursor::new("\n");

        let err = read_unseal_keys(&mut input, None, &messages)
            .expect_err("a blank threshold must error");
        assert_eq!(err.to_string(), messages.error_invalid_unseal_threshold());
    }

    /// The unseal-key writer states `0600` independently of the process umask.
    ///
    /// Runs in a child process because umask is process-wide; see
    /// [`fs_util::umask_test_ran_in_child`].
    #[cfg(unix)]
    #[test]
    fn save_unseal_keys_creates_with_restricted_mode_under_umask_022() {
        if fs_util::umask_test_ran_in_child(
            "commands::openbao_unseal::tests::save_unseal_keys_creates_with_restricted_mode_under_umask_022",
        ) {
            return;
        }

        let dir = tempdir().expect("tempdir");
        // SAFETY: this test runs in the child spawned above, with no other
        // tests sharing the process, and restores the prior umask immediately.
        let previous = unsafe { libc::umask(0o022) };
        let result = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(save_unseal_keys(
                dir.path(),
                &["key-a".to_string(), "key-b".to_string()],
                &test_messages(),
            ));
        unsafe { libc::umask(previous) };
        let path = result.expect("save unseal keys");

        let mode = std::fs::metadata(path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, fs_util::KEY_FILE_MODE);
    }

    /// A secrets-tree link is replaced so the new key shares cannot be
    /// redirected to an attacker-selected target.
    #[cfg(unix)]
    #[tokio::test]
    async fn save_unseal_keys_replaces_a_symlinked_destination() {
        let dir = tempdir().expect("tempdir");
        let openbao_dir = dir.path().join(UNSEAL_KEYS_DIR);
        std::fs::create_dir(&openbao_dir).expect("mkdir");
        let target = dir.path().join("former-target.txt");
        std::fs::write(&target, "old keys\n").expect("seed target");
        let path = openbao_dir.join(UNSEAL_KEYS_FILENAME);
        std::os::unix::fs::symlink(&target, &path).expect("symlink");

        let saved = save_unseal_keys(
            dir.path(),
            &["key-a".to_string(), "key-b".to_string()],
            &test_messages(),
        )
        .await
        .expect("save unseal keys");

        assert_eq!(saved, path);
        assert!(
            !std::fs::symlink_metadata(&path)
                .expect("stat")
                .file_type()
                .is_symlink(),
            "the secrets-tree symlink must be replaced"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("read"),
            "key-a\nkey-b\n"
        );
        assert_eq!(
            std::fs::read_to_string(&target).expect("read former target"),
            "old keys\n"
        );
    }
}
