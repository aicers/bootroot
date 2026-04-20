use anyhow::Result;
use serde::Serialize;

use super::{Locale, redacted_error_label, summary_header};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ApplyStatus {
    Applied,
    Unchanged,
    Skipped,
    Failed,
}

#[derive(Debug, Serialize)]
pub(super) struct ApplyItemSummary {
    pub(super) status: ApplyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) error: Option<String>,
}

impl ApplyItemSummary {
    pub(super) fn applied(status: ApplyStatus) -> Self {
        Self {
            status,
            error: None,
        }
    }

    pub(super) fn failed(error: String) -> Self {
        Self {
            status: ApplyStatus::Failed,
            error: Some(error),
        }
    }
}

#[derive(Debug, Serialize)]
pub(super) struct ApplySummary {
    pub(super) secret_id: ApplyItemSummary,
    pub(super) eab: ApplyItemSummary,
    pub(super) responder_hmac: ApplyItemSummary,
    pub(super) trust_sync: ApplyItemSummary,
}

impl ApplySummary {
    pub(super) fn has_failures(&self) -> bool {
        [
            self.secret_id.status,
            self.eab.status,
            self.responder_hmac.status,
            self.trust_sync.status,
        ]
        .into_iter()
        .any(|status| matches!(status, ApplyStatus::Failed))
    }
}

pub(super) fn merge_apply_status(
    current: ApplyItemSummary,
    next: ApplyStatus,
    next_error: Option<String>,
) -> ApplyItemSummary {
    if matches!(current.status, ApplyStatus::Failed) {
        return current;
    }
    if matches!(next, ApplyStatus::Failed) {
        return ApplyItemSummary {
            status: next,
            error: next_error,
        };
    }
    if matches!(current.status, ApplyStatus::Applied) || matches!(next, ApplyStatus::Applied) {
        return ApplyItemSummary::applied(ApplyStatus::Applied);
    }
    if matches!(current.status, ApplyStatus::Unchanged) || matches!(next, ApplyStatus::Unchanged) {
        return ApplyItemSummary::applied(ApplyStatus::Unchanged);
    }
    ApplyItemSummary::applied(ApplyStatus::Skipped)
}

pub(super) fn status_to_str(status: ApplyStatus) -> &'static str {
    match status {
        ApplyStatus::Applied => "applied",
        ApplyStatus::Unchanged => "unchanged",
        ApplyStatus::Skipped => "skipped",
        ApplyStatus::Failed => "failed",
    }
}

fn print_text_summary(summary: &ApplySummary, lang: Locale) {
    println!("{}", summary_header(lang));
    println!("- secret_id: {}", status_to_str(summary.secret_id.status));
    print_optional_error("secret_id", summary.secret_id.error.as_deref(), lang);
    println!("- eab: {}", status_to_str(summary.eab.status));
    print_optional_error("eab", summary.eab.error.as_deref(), lang);
    println!(
        "- responder_hmac: {}",
        status_to_str(summary.responder_hmac.status)
    );
    print_optional_error(
        "responder_hmac",
        summary.responder_hmac.error.as_deref(),
        lang,
    );
    println!("- trust_sync: {}", status_to_str(summary.trust_sync.status));
    print_optional_error("trust_sync", summary.trust_sync.error.as_deref(), lang);
}

fn print_optional_error(name: &str, error: Option<&str>, lang: Locale) {
    if let Some(_value) = error {
        println!("  {}({name}): <redacted>", redacted_error_label(lang));
    }
}

pub(super) fn print_summary(
    summary: &ApplySummary,
    output: super::OutputFormat,
    lang: Locale,
) -> Result<()> {
    match output {
        super::OutputFormat::Text => {
            print_text_summary(summary, lang);
            Ok(())
        }
        super::OutputFormat::Json => {
            let payload = serde_json::to_string_pretty(summary)?;
            println!("{payload}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_apply_status_prefers_failed_state() {
        let current = ApplyItemSummary::failed("failed".to_string());
        let merged = merge_apply_status(current, ApplyStatus::Applied, None);
        assert!(matches!(merged.status, ApplyStatus::Failed));
    }

    #[test]
    fn merge_apply_status_returns_skipped_when_both_sides_skipped() {
        let current = ApplyItemSummary::applied(ApplyStatus::Skipped);
        let merged = merge_apply_status(current, ApplyStatus::Skipped, None);
        assert!(matches!(merged.status, ApplyStatus::Skipped));
    }

    #[test]
    fn merge_apply_status_prefers_unchanged_over_skipped() {
        let current = ApplyItemSummary::applied(ApplyStatus::Skipped);
        let merged = merge_apply_status(current, ApplyStatus::Unchanged, None);
        assert!(matches!(merged.status, ApplyStatus::Unchanged));
    }

    #[test]
    fn merge_apply_status_prefers_applied_over_skipped() {
        let current = ApplyItemSummary::applied(ApplyStatus::Skipped);
        let merged = merge_apply_status(current, ApplyStatus::Applied, None);
        assert!(matches!(merged.status, ApplyStatus::Applied));
    }
}
