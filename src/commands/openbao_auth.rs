use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use crate::cli::args::{AuthMode, RuntimeAuthArgs};
use crate::cli::prompt::Prompt;
use crate::i18n::Messages;

const OPENBAO_ROOT_TOKEN_ENV: &str = "OPENBAO_ROOT_TOKEN";

#[derive(Debug, Clone)]
pub(crate) enum RuntimeAuthResolved {
    RootToken(String),
    AppRole { role_id: String, secret_id: String },
}

pub(crate) fn resolve_runtime_auth(
    args: &RuntimeAuthArgs,
    allow_root_prompt: bool,
    messages: &Messages,
) -> Result<RuntimeAuthResolved> {
    let root_token = resolve_root_token(args)?;
    let approle_role_id = resolve_from_value_or_file(
        args.approle_role_id.as_deref(),
        args.approle_role_id_file.as_deref(),
        "AppRole role_id",
    )?;
    let approle_secret_id = resolve_from_value_or_file(
        args.approle_secret_id.as_deref(),
        args.approle_secret_id_file.as_deref(),
        "AppRole secret_id",
    )?;

    match args.auth_mode {
        AuthMode::Auto => {
            if let Some(root_token) = root_token {
                return Ok(RuntimeAuthResolved::RootToken(root_token));
            }
            if let (Some(role_id), Some(secret_id)) = (approle_role_id, approle_secret_id) {
                return Ok(RuntimeAuthResolved::AppRole { role_id, secret_id });
            }
            if allow_root_prompt {
                return prompt_root_token(messages).map(RuntimeAuthResolved::RootToken);
            }
            anyhow::bail!(
                "OpenBao auth not resolved: provide --root-token, --root-token-file, \
                 OPENBAO_ROOT_TOKEN env, or AppRole credentials \
                 (--approle-role-id/--approle-secret-id or *_FILE)"
            );
        }
        AuthMode::Root => {
            if let Some(root_token) = root_token {
                return Ok(RuntimeAuthResolved::RootToken(root_token));
            }
            if allow_root_prompt {
                return prompt_root_token(messages).map(RuntimeAuthResolved::RootToken);
            }
            anyhow::bail!(messages.error_openbao_root_token_required());
        }
        AuthMode::Approle => {
            let role_id = approle_role_id
                .ok_or_else(|| anyhow::anyhow!("OpenBao AppRole role_id is required"))?;
            let secret_id = approle_secret_id
                .ok_or_else(|| anyhow::anyhow!("OpenBao AppRole secret_id is required"))?;
            Ok(RuntimeAuthResolved::AppRole { role_id, secret_id })
        }
    }
}

pub(crate) fn resolve_runtime_auth_optional(
    args: &RuntimeAuthArgs,
) -> Result<Option<RuntimeAuthResolved>> {
    let root_token = resolve_root_token(args)?;
    let approle_role_id = resolve_from_value_or_file(
        args.approle_role_id.as_deref(),
        args.approle_role_id_file.as_deref(),
        "AppRole role_id",
    )?;
    let approle_secret_id = resolve_from_value_or_file(
        args.approle_secret_id.as_deref(),
        args.approle_secret_id_file.as_deref(),
        "AppRole secret_id",
    )?;

    let auth = match args.auth_mode {
        AuthMode::Auto => {
            if let Some(root_token) = root_token {
                Some(RuntimeAuthResolved::RootToken(root_token))
            } else if let (Some(role_id), Some(secret_id)) = (approle_role_id, approle_secret_id) {
                Some(RuntimeAuthResolved::AppRole { role_id, secret_id })
            } else {
                None
            }
        }
        AuthMode::Root => root_token.map(RuntimeAuthResolved::RootToken),
        AuthMode::Approle => {
            let role_id = approle_role_id
                .ok_or_else(|| anyhow::anyhow!("OpenBao AppRole role_id is required"))?;
            let secret_id = approle_secret_id
                .ok_or_else(|| anyhow::anyhow!("OpenBao AppRole secret_id is required"))?;
            Some(RuntimeAuthResolved::AppRole { role_id, secret_id })
        }
    };
    Ok(auth)
}

/// Resolves the root token from `--root-token-file`, `--root-token`, or the
/// `OPENBAO_ROOT_TOKEN` env var.  Splitting the env var off the CLI flag lets
/// us distinguish an explicit `--root-token` from an env-injected value when
/// detecting conflicts with `--root-token-file`. The clap-level
/// `conflicts_with = "root_token"` already rejects the explicit-flag combo at
/// parse time; we still re-check here for callers that build
/// `RuntimeAuthArgs` directly (e.g. tests).
fn resolve_root_token(args: &RuntimeAuthArgs) -> Result<Option<String>> {
    if let Some(path) = args.root_token_file.as_deref() {
        if args.root_token.is_some() {
            anyhow::bail!("--root-token-file conflicts with --root-token; pass only one of them");
        }
        return read_root_token_file(path).map(Some);
    }
    if let Some(value) = &args.root_token {
        return Ok(Some(value.clone()));
    }
    match std::env::var(OPENBAO_ROOT_TOKEN_ENV) {
        Ok(value) if !value.is_empty() => Ok(Some(value)),
        _ => Ok(None),
    }
}

fn read_root_token_file(path: &Path) -> Result<String> {
    let metadata = fs::metadata(path)
        .with_context(|| format!("Failed to read root token file: {}", path.display()))?;
    if !metadata.is_file() {
        anyhow::bail!("root token file is not a regular file: {}", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o004 != 0 {
            anyhow::bail!(
                "root token file {} is world-readable (mode {:o}); fix with `chmod 0600 {}`",
                path.display(),
                mode,
                path.display(),
            );
        }
    }
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read root token file: {}", path.display()))?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        anyhow::bail!("root token file is empty: {}", path.display());
    }
    Ok(trimmed)
}

pub(crate) async fn authenticate_openbao_client(
    client: &mut OpenBaoClient,
    auth: &RuntimeAuthResolved,
    messages: &Messages,
) -> Result<()> {
    match auth {
        RuntimeAuthResolved::RootToken(token) => {
            client.set_token(token.clone());
        }
        RuntimeAuthResolved::AppRole { role_id, secret_id } => {
            let token = client
                .login_approle(role_id, secret_id)
                .await
                .with_context(|| messages.error_openbao_approle_login_failed())?;
            client.set_token(token);
        }
    }
    Ok(())
}

fn prompt_root_token(messages: &Messages) -> Result<String> {
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout();
    let mut prompt = Prompt::new(&mut input, &mut output, messages);
    let label = messages.prompt_openbao_root_token().trim_end_matches(": ");
    prompt.prompt_with_validation(label, None, |value| {
        if value.trim().is_empty() {
            anyhow::bail!(messages.error_value_required());
        }
        Ok(value.trim().to_string())
    })
}

fn resolve_from_value_or_file(
    value: Option<&str>,
    path: Option<&Path>,
    label: &str,
) -> Result<Option<String>> {
    if let Some(value) = value {
        return Ok(Some(value.to_string()));
    }
    let Some(path) = path else {
        return Ok(None);
    };
    let raw = fs::read_to_string(path)
        .with_context(|| format!("Failed to read {label} file: {}", path.display()))?;
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        anyhow::bail!("{label} file is empty: {}", path.display());
    }
    Ok(Some(trimmed))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    use tempfile::tempdir;

    use super::*;

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK.lock().expect("env lock not poisoned")
    }

    struct ScopedRootTokenEnv {
        previous: Option<String>,
    }

    impl ScopedRootTokenEnv {
        fn set(value: Option<&str>) -> Self {
            let previous = std::env::var(OPENBAO_ROOT_TOKEN_ENV).ok();
            // SAFETY: tests serialise via ENV_LOCK
            unsafe {
                match value {
                    Some(v) => std::env::set_var(OPENBAO_ROOT_TOKEN_ENV, v),
                    None => std::env::remove_var(OPENBAO_ROOT_TOKEN_ENV),
                }
            }
            Self { previous }
        }
    }

    impl Drop for ScopedRootTokenEnv {
        fn drop(&mut self) {
            // SAFETY: tests serialise via ENV_LOCK
            unsafe {
                if let Some(prev) = &self.previous {
                    std::env::set_var(OPENBAO_ROOT_TOKEN_ENV, prev);
                } else {
                    std::env::remove_var(OPENBAO_ROOT_TOKEN_ENV);
                }
            }
        }
    }

    fn args_with(root_token: Option<&str>, root_token_file: Option<&Path>) -> RuntimeAuthArgs {
        RuntimeAuthArgs {
            auth_mode: AuthMode::Auto,
            root_token: root_token.map(str::to_string),
            root_token_file: root_token_file.map(Path::to_path_buf),
            approle_role_id: None,
            approle_secret_id: None,
            approle_role_id_file: None,
            approle_secret_id_file: None,
        }
    }

    fn write_token_file(dir: &Path, name: &str, contents: &str, mode: u32) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).expect("write token file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).expect("set perms");
        }
        path
    }

    #[test]
    fn root_token_file_overrides_env_when_no_cli_flag() {
        let _lock = env_lock();
        let _env = ScopedRootTokenEnv::set(Some("env-token"));
        let dir = tempdir().expect("tempdir");
        let path = write_token_file(dir.path(), "root.token", "file-token\n", 0o600);
        let args = args_with(None, Some(&path));
        let resolved = resolve_root_token(&args).expect("resolve ok");
        assert_eq!(resolved.as_deref(), Some("file-token"));
    }

    #[test]
    fn root_token_file_conflicts_with_explicit_root_token_flag() {
        let _lock = env_lock();
        let _env = ScopedRootTokenEnv::set(None);
        let dir = tempdir().expect("tempdir");
        let path = write_token_file(dir.path(), "root.token", "file-token\n", 0o600);
        let args = args_with(Some("explicit"), Some(&path));
        let err = resolve_root_token(&args).expect_err("should conflict");
        assert!(err.to_string().contains("--root-token-file conflicts"));
    }

    #[test]
    fn explicit_root_token_flag_beats_env() {
        let _lock = env_lock();
        let _env = ScopedRootTokenEnv::set(Some("env-token"));
        let args = args_with(Some("explicit"), None);
        let resolved = resolve_root_token(&args).expect("resolve ok");
        assert_eq!(resolved.as_deref(), Some("explicit"));
    }

    #[test]
    fn env_used_when_no_flag_or_file() {
        let _lock = env_lock();
        let _env = ScopedRootTokenEnv::set(Some("env-token"));
        let args = args_with(None, None);
        let resolved = resolve_root_token(&args).expect("resolve ok");
        assert_eq!(resolved.as_deref(), Some("env-token"));
    }

    #[test]
    fn no_token_when_nothing_provided() {
        let _lock = env_lock();
        let _env = ScopedRootTokenEnv::set(None);
        let args = args_with(None, None);
        let resolved = resolve_root_token(&args).expect("resolve ok");
        assert!(resolved.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn root_token_file_mode_0o600_accepted() {
        let _lock = env_lock();
        let _env = ScopedRootTokenEnv::set(None);
        let dir = tempdir().expect("tempdir");
        let path = write_token_file(dir.path(), "t", "tok\n", 0o600);
        let args = args_with(None, Some(&path));
        let resolved = resolve_root_token(&args).expect("0o600 ok");
        assert_eq!(resolved.as_deref(), Some("tok"));
    }

    #[cfg(unix)]
    #[test]
    fn root_token_file_mode_0o640_accepted_for_group_sharing() {
        let _lock = env_lock();
        let _env = ScopedRootTokenEnv::set(None);
        let dir = tempdir().expect("tempdir");
        let path = write_token_file(dir.path(), "t", "tok\n", 0o640);
        let args = args_with(None, Some(&path));
        let resolved = resolve_root_token(&args).expect("0o640 ok");
        assert_eq!(resolved.as_deref(), Some("tok"));
    }

    #[cfg(unix)]
    #[test]
    fn root_token_file_mode_0o644_rejected() {
        let _lock = env_lock();
        let _env = ScopedRootTokenEnv::set(None);
        let dir = tempdir().expect("tempdir");
        let path = write_token_file(dir.path(), "t", "tok\n", 0o644);
        let args = args_with(None, Some(&path));
        let err = resolve_root_token(&args).expect_err("0o644 must fail");
        let msg = err.to_string();
        assert!(msg.contains("world-readable"), "msg = {msg}");
        assert!(msg.contains("chmod 0600"), "msg = {msg}");
    }

    #[test]
    fn root_token_file_empty_rejected() {
        let _lock = env_lock();
        let _env = ScopedRootTokenEnv::set(None);
        let dir = tempdir().expect("tempdir");
        let path = write_token_file(dir.path(), "t", "   \n", 0o600);
        let args = args_with(None, Some(&path));
        let err = resolve_root_token(&args).expect_err("empty must fail");
        assert!(err.to_string().contains("empty"));
    }
}
