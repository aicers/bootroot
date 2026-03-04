use std::path::Path;

use anyhow::{Context, Result};

use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;

use super::helpers::{confirm_action, ensure_non_empty};
use super::{
    OPENBAO_RECOVERY_SCOPE_ROOT_TOKEN, OPENBAO_RECOVERY_SCOPE_UNSEAL_KEYS,
    OPENBAO_REKEY_INCOMPLETE_ERROR,
};
use crate::cli::args::RotateOpenBaoRecoveryArgs;
use crate::cli::prompt::Prompt;
use crate::commands::openbao_unseal::read_unseal_keys_from_file;
use crate::i18n::Messages;

#[derive(Debug, serde::Serialize)]
struct OpenBaoRecoveryRotationOutput {
    #[serde(skip_serializing_if = "Option::is_none")]
    root_token: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    unseal_keys: Vec<String>,
}

pub(super) async fn rotate_openbao_recovery(
    client: &OpenBaoClient,
    args: &RotateOpenBaoRecoveryArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    if !args.rotate_unseal_keys && !args.rotate_root_token {
        anyhow::bail!(messages.error_openbao_recovery_target_required());
    }

    let scopes = recovery_scopes(args);
    let scopes_label = scopes.join(", ");

    confirm_action(
        &messages.prompt_rotate_openbao_recovery(&scopes_label),
        auto_confirm,
        messages,
    )?;

    let mut output = OpenBaoRecoveryRotationOutput {
        root_token: None,
        unseal_keys: Vec::new(),
    };

    if args.rotate_unseal_keys {
        output.unseal_keys =
            rotate_openbao_unseal_keys(client, args, auto_confirm, messages).await?;
    }

    if args.rotate_root_token {
        output.root_token = Some(
            client
                .create_root_token()
                .await
                .context("OpenBao root token rotation failed")?,
        );
    }

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_openbao_recovery_targets(&scopes_label)
    );
    println!(
        "{}",
        messages.rotate_summary_openbao_recovery_approle_unchanged()
    );
    println!("{}", messages.rotate_summary_openbao_recovery_next_steps());

    if let Some(output_path) = args.output.as_deref() {
        write_openbao_recovery_output(output_path, &output, messages).await?;
        println!(
            "{}",
            messages.rotate_summary_openbao_recovery_output(&output_path.display().to_string())
        );
        return Ok(());
    }

    print_openbao_recovery_stdout(&output, messages)?;

    Ok(())
}

fn recovery_scopes(args: &RotateOpenBaoRecoveryArgs) -> Vec<&'static str> {
    let mut scopes = Vec::new();
    if args.rotate_unseal_keys {
        scopes.push(OPENBAO_RECOVERY_SCOPE_UNSEAL_KEYS);
    }
    if args.rotate_root_token {
        scopes.push(OPENBAO_RECOVERY_SCOPE_ROOT_TOKEN);
    }
    scopes
}

async fn rotate_openbao_unseal_keys(
    client: &OpenBaoClient,
    args: &RotateOpenBaoRecoveryArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<Vec<String>> {
    let seal_status = client
        .seal_status()
        .await
        .with_context(|| messages.error_openbao_seal_status_failed())?;
    if seal_status.sealed {
        anyhow::bail!(messages.error_openbao_sealed());
    }

    let threshold = seal_status
        .t
        .ok_or_else(|| anyhow::anyhow!(messages.error_invalid_unseal_threshold()))?;
    if threshold == 0 {
        anyhow::bail!(messages.error_invalid_unseal_threshold());
    }
    let shares = seal_status.n.unwrap_or(threshold);
    if shares == 0 {
        anyhow::bail!(messages.error_invalid_unseal_threshold());
    }

    let required = usize::try_from(threshold).context("invalid unseal threshold conversion")?;
    let keys = collect_existing_unseal_keys(args, required, auto_confirm, messages)?;
    if keys.len() < required {
        anyhow::bail!(messages.error_openbao_recovery_unseal_keys_required(&required.to_string()));
    }

    let rekey_init = client
        .start_rekey(shares, threshold)
        .await
        .context("OpenBao rekey init request failed")?;
    for key in keys.iter().take(required) {
        let update = client
            .submit_rekey_share(&rekey_init.nonce, key)
            .await
            .context("OpenBao rekey update request failed")?;
        if update.complete && !update.keys.is_empty() {
            return Ok(update.keys);
        }
    }

    anyhow::bail!(OPENBAO_REKEY_INCOMPLETE_ERROR);
}

fn print_openbao_recovery_stdout(
    output: &OpenBaoRecoveryRotationOutput,
    messages: &Messages,
) -> Result<()> {
    if let Some(root_token) = output.root_token.as_deref() {
        println!("{}", messages.summary_root_token(root_token));
    }

    for (index, unseal_key) in output.unseal_keys.iter().enumerate() {
        let one_based_index = index
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("failed to calculate one-based index for unseal key"))?;
        println!(
            "{}",
            messages.summary_unseal_key(one_based_index, unseal_key)
        );
    }
    Ok(())
}

fn collect_existing_unseal_keys(
    args: &RotateOpenBaoRecoveryArgs,
    required: usize,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<Vec<String>> {
    let mut keys = args.unseal_key.clone();
    if let Some(path) = args.unseal_key_file.as_deref() {
        keys.extend(read_unseal_keys_from_file(path, messages)?);
    }

    if auto_confirm {
        return Ok(keys);
    }

    let required_u32 = u32::try_from(required).context("invalid required unseal key count")?;
    while keys.len() < required {
        let next_index = keys
            .len()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("unseal key index overflow"))?;
        let index_u32 = u32::try_from(next_index).context("invalid unseal key index")?;
        let label = messages.prompt_unseal_key(index_u32, required_u32);

        let mut input = std::io::stdin().lock();
        let mut output = std::io::stdout();
        let mut prompt = Prompt::new(&mut input, &mut output, messages);
        let key = prompt.prompt_with_validation(label.trim_end_matches(": "), None, |value| {
            ensure_non_empty(value, messages)
        })?;
        keys.push(key);
    }

    Ok(keys)
}

async fn write_openbao_recovery_output(
    path: &Path,
    output: &OpenBaoRecoveryRotationOutput,
    messages: &Messages,
) -> Result<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs_util::ensure_secrets_dir(parent).await?;
    }

    let payload = serde_json::to_string_pretty(output)
        .with_context(|| messages.error_serialize_state_failed())?;
    tokio::fs::write(path, payload)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    fs_util::set_key_permissions(path).await?;
    Ok(())
}
