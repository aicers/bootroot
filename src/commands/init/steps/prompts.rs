use anyhow::{Context, Result};

use crate::i18n::Messages;

pub(super) fn prompt_unseal_keys(
    threshold: Option<u32>,
    messages: &Messages,
) -> Result<Vec<String>> {
    let count = match threshold {
        Some(value) if value > 0 => value,
        _ => {
            let input = prompt_text(messages.prompt_unseal_threshold(), messages)?;
            input
                .parse::<u32>()
                .context(messages.error_invalid_unseal_threshold())?
        }
    };
    let mut keys = Vec::with_capacity(count as usize);
    for index in 1..=count {
        let key = prompt_text(&messages.prompt_unseal_key(index, count), messages)?;
        keys.push(key);
    }
    Ok(keys)
}

pub(super) fn prompt_text(prompt: &str, messages: &Messages) -> Result<String> {
    use std::io::{self, Write};
    // codeql[rust/cleartext-logging]: prompt text is non-secret UI output.
    print!("{prompt}");
    io::stdout()
        .flush()
        .with_context(|| messages.error_prompt_flush_failed())?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .with_context(|| messages.error_prompt_read_failed())?;
    Ok(input.trim().to_string())
}

pub(super) fn prompt_text_with_default(
    prompt: &str,
    default: &str,
    messages: &Messages,
) -> Result<String> {
    let input = prompt_text(prompt, messages)?;
    if input.trim().is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

pub(super) fn prompt_yes_no(prompt: &str, messages: &Messages) -> Result<bool> {
    let input = prompt_text(prompt, messages)?;
    let trimmed = input.trim().to_ascii_lowercase();
    Ok(trimmed == "y" || trimmed == "yes")
}

pub(super) fn confirm_overwrite(prompt: &str, messages: &Messages) -> Result<()> {
    if prompt_yes_no(prompt, messages)? {
        return Ok(());
    }
    anyhow::bail!(messages.error_operation_cancelled());
}
