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
    // CodeQL flags this as cleartext-logging, but `prompt` is a UI label
    // (e.g. "PostgreSQL password: "), not a secret value. Dismiss as false positive.
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

pub(crate) fn prompt_yes_no(prompt: &str, messages: &Messages) -> Result<bool> {
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

/// Decides whether one of init's pre-flight confirmations must be shown.
///
/// `condition` is what the prompt guards — file existence for the three
/// overwrite prompts, `has_feature(InitFeature::DbProvision)` for the
/// db-provision confirmation.  `confirmed` is that prompt's own
/// non-interactive flag (`--overwrite-password`, `--overwrite-ca-json`,
/// `--overwrite-state`, `--confirm-db-provision`), which answers `y` on
/// the operator's behalf.  `reinit_mode` suppresses every prompt in the
/// block because `reinit` has already taken the operator's decision.
///
/// Each prompt is gated independently: no flag implies another, and a
/// flag whose `condition` is false is a silent no-op.
pub(super) const fn should_confirm(condition: bool, confirmed: bool, reinit_mode: bool) -> bool {
    condition && !confirmed && !reinit_mode
}

#[cfg(test)]
mod tests {
    use super::should_confirm;

    /// A prompt whose condition does not hold never fires, whatever the
    /// flag says — passing a flag for an absent file is a silent no-op.
    #[test]
    fn test_should_confirm_skips_when_condition_absent() {
        assert!(!should_confirm(false, false, false));
        assert!(!should_confirm(false, true, false));
        assert!(!should_confirm(false, false, true));
        assert!(!should_confirm(false, true, true));
    }

    /// Condition holds and no flag answers it: the interactive default
    /// is preserved and the prompt fires.
    #[test]
    fn test_should_confirm_prompts_when_condition_holds_and_flag_unset() {
        assert!(should_confirm(true, false, false));
    }

    /// The prompt's own flag answers it as if the operator typed `y`.
    #[test]
    fn test_should_confirm_skips_when_flag_set() {
        assert!(!should_confirm(true, true, false));
    }

    /// `reinit_mode` suppresses the prompt on its own, regardless of the
    /// per-prompt flag, so `reinit --yes` stays non-interactive.
    #[test]
    fn test_should_confirm_skips_under_reinit_mode() {
        assert!(!should_confirm(true, false, true));
        assert!(!should_confirm(true, true, true));
    }
}
