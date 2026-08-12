use std::io::{self, BufRead, Write};

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
    read_prompt_text(&mut io::stdin().lock(), prompt, messages)
}

/// Reads one answer from `input`, failing rather than fabricating one
/// when there is nothing left to read.
///
/// # Errors
///
/// Returns `messages.error_prompt_eof()` when `read_line` reports zero
/// bytes, which happens only at EOF: a blank line still carries its
/// newline.  Without the distinction a closed stdin answers every
/// remaining prompt with an empty string, and the one prompt that
/// retries on a rejected answer re-prompts forever.
pub(super) fn read_prompt_text(
    input: &mut dyn BufRead,
    prompt: &str,
    messages: &Messages,
) -> Result<String> {
    // CodeQL flags this as cleartext-logging, but `prompt` is a UI label
    // (e.g. "PostgreSQL password: "), not a secret value. Dismiss as false positive.
    print!("{prompt}");
    io::stdout()
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

pub(super) fn prompt_text_with_default(
    prompt: &str,
    default: &str,
    messages: &Messages,
) -> Result<String> {
    read_prompt_text_with_default(&mut io::stdin().lock(), prompt, default, messages)
}

fn read_prompt_text_with_default(
    input: &mut dyn BufRead,
    prompt: &str,
    default: &str,
    messages: &Messages,
) -> Result<String> {
    let answer = read_prompt_text(input, prompt, messages)?;
    if answer.trim().is_empty() {
        Ok(default.to_string())
    } else {
        Ok(answer)
    }
}

pub(crate) fn prompt_yes_no(prompt: &str, messages: &Messages) -> Result<bool> {
    read_prompt_yes_no(&mut io::stdin().lock(), prompt, messages)
}

fn read_prompt_yes_no(input: &mut dyn BufRead, prompt: &str, messages: &Messages) -> Result<bool> {
    let answer = read_prompt_text(input, prompt, messages)?;
    let trimmed = answer.trim().to_ascii_lowercase();
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
    use std::io::Cursor;

    use super::super::test_support::test_messages;
    use super::{
        read_prompt_text, read_prompt_text_with_default, read_prompt_yes_no, should_confirm,
    };

    /// EOF is not an answer.  Each of the three readers must surface it
    /// as the dedicated error rather than as an empty string, the
    /// supplied default, or a declined confirmation — the three silent
    /// wrong values a closed stdin used to produce.
    #[test]
    fn prompts_error_on_eof() {
        let messages = test_messages();

        let err = read_prompt_text(&mut Cursor::new(""), "Label: ", &messages)
            .expect_err("EOF must error");
        assert_eq!(err.to_string(), messages.error_prompt_eof());

        let err =
            read_prompt_text_with_default(&mut Cursor::new(""), "Label: ", "fallback", &messages)
                .expect_err("EOF must error instead of returning the default");
        assert_eq!(err.to_string(), messages.error_prompt_eof());

        let err = read_prompt_yes_no(&mut Cursor::new(""), "Label: ", &messages)
            .expect_err("EOF must error instead of answering no");
        assert_eq!(err.to_string(), messages.error_prompt_eof());
    }

    /// A blank line remains a deliberate answer everywhere it is one
    /// today, so the EOF check must not swallow a bare Enter.
    #[test]
    fn prompts_treat_blank_line_as_an_answer() {
        let messages = test_messages();

        let value = read_prompt_text(&mut Cursor::new("\n"), "Label: ", &messages)
            .expect("a blank line is an answer");
        assert_eq!(value, "");

        let value =
            read_prompt_text_with_default(&mut Cursor::new("\n"), "Label: ", "fallback", &messages)
                .expect("a blank line is an answer");
        assert_eq!(value, "fallback");

        let answer = read_prompt_yes_no(&mut Cursor::new("\n"), "Label: ", &messages)
            .expect("a blank line is an answer");
        assert!(!answer, "a bare Enter still reads as no");
    }

    #[test]
    fn prompts_read_and_trim_a_typed_answer() {
        let messages = test_messages();

        let value = read_prompt_text(&mut Cursor::new("  value  \n"), "Label: ", &messages)
            .expect("typed answer");
        assert_eq!(value, "value");

        let value = read_prompt_text_with_default(
            &mut Cursor::new("value\n"),
            "Label: ",
            "fallback",
            &messages,
        )
        .expect("typed answer wins over the default");
        assert_eq!(value, "value");

        let answer = read_prompt_yes_no(&mut Cursor::new("y\n"), "Label: ", &messages)
            .expect("typed answer");
        assert!(answer);
    }

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
