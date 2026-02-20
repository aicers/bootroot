use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use crate::cli::args::{AuthMode, RuntimeAuthArgs};
use crate::cli::prompt::Prompt;
use crate::i18n::Messages;

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
    let approle_role_id = resolve_from_value_or_file(
        args.approle_role_id.clone(),
        args.approle_role_id_file.as_deref(),
        "AppRole role_id",
    )?;
    let approle_secret_id = resolve_from_value_or_file(
        args.approle_secret_id.clone(),
        args.approle_secret_id_file.as_deref(),
        "AppRole secret_id",
    )?;

    match args.auth_mode {
        AuthMode::Auto => {
            if let Some(root_token) = args.root_token.clone() {
                return Ok(RuntimeAuthResolved::RootToken(root_token));
            }
            if let (Some(role_id), Some(secret_id)) = (approle_role_id, approle_secret_id) {
                return Ok(RuntimeAuthResolved::AppRole { role_id, secret_id });
            }
            if allow_root_prompt {
                return prompt_root_token(messages).map(RuntimeAuthResolved::RootToken);
            }
            anyhow::bail!(
                "OpenBao auth not resolved: provide --root-token or AppRole credentials \
                 (--approle-role-id/--approle-secret-id or *_FILE)"
            );
        }
        AuthMode::Root => {
            if let Some(root_token) = args.root_token.clone() {
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
    let approle_role_id = resolve_from_value_or_file(
        args.approle_role_id.clone(),
        args.approle_role_id_file.as_deref(),
        "AppRole role_id",
    )?;
    let approle_secret_id = resolve_from_value_or_file(
        args.approle_secret_id.clone(),
        args.approle_secret_id_file.as_deref(),
        "AppRole secret_id",
    )?;

    let auth = match args.auth_mode {
        AuthMode::Auto => {
            if let Some(root_token) = args.root_token.clone() {
                Some(RuntimeAuthResolved::RootToken(root_token))
            } else if let (Some(role_id), Some(secret_id)) = (approle_role_id, approle_secret_id) {
                Some(RuntimeAuthResolved::AppRole { role_id, secret_id })
            } else {
                None
            }
        }
        AuthMode::Root => args.root_token.clone().map(RuntimeAuthResolved::RootToken),
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
    value: Option<String>,
    path: Option<&Path>,
    label: &str,
) -> Result<Option<String>> {
    if let Some(value) = value {
        return Ok(Some(value));
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
