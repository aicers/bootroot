use anyhow::{Context, Result};

pub(crate) mod en;
pub(crate) mod ko;

pub(crate) struct Strings {
    pub(crate) not_implemented_status: &'static str,
    pub(crate) not_implemented_app_add: &'static str,
    pub(crate) not_implemented_app_info: &'static str,
    pub(crate) not_implemented_verify: &'static str,
    pub(crate) infra_up_completed: &'static str,
    pub(crate) infra_readiness_summary: &'static str,
    pub(crate) infra_entry_with_health: &'static str,
    pub(crate) infra_entry_without_health: &'static str,
    pub(crate) infra_unhealthy: &'static str,
    pub(crate) init_failed_rollback: &'static str,
    pub(crate) prompt_openbao_root_token: &'static str,
    pub(crate) error_openbao_root_token_required: &'static str,
    pub(crate) prompt_unseal_threshold: &'static str,
    pub(crate) prompt_unseal_key: &'static str,
    pub(crate) prompt_stepca_password: &'static str,
    pub(crate) prompt_http_hmac: &'static str,
    pub(crate) prompt_db_dsn: &'static str,
    pub(crate) error_eab_requires_both: &'static str,
    pub(crate) error_openbao_sealed: &'static str,
    pub(crate) summary_title: &'static str,
    pub(crate) summary_openbao_url: &'static str,
    pub(crate) summary_kv_mount: &'static str,
    pub(crate) summary_secrets_dir: &'static str,
    pub(crate) summary_stepca_completed: &'static str,
    pub(crate) summary_stepca_skipped: &'static str,
    pub(crate) summary_openbao_init_completed: &'static str,
    pub(crate) summary_openbao_init_skipped: &'static str,
    pub(crate) summary_root_token: &'static str,
    pub(crate) summary_unseal_key: &'static str,
    pub(crate) summary_stepca_password: &'static str,
    pub(crate) summary_db_dsn: &'static str,
    pub(crate) summary_responder_hmac: &'static str,
    pub(crate) summary_eab_kid: &'static str,
    pub(crate) summary_eab_hmac: &'static str,
    pub(crate) summary_eab_missing: &'static str,
    pub(crate) summary_kv_paths: &'static str,
    pub(crate) summary_approles: &'static str,
    pub(crate) summary_role_id: &'static str,
    pub(crate) summary_secret_id: &'static str,
    pub(crate) summary_next_steps: &'static str,
    pub(crate) next_steps_configure_templates: &'static str,
    pub(crate) next_steps_reload_services: &'static str,
    pub(crate) next_steps_run_status: &'static str,
    pub(crate) next_steps_eab_hint: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Locale {
    En,
    Ko,
}

impl Locale {
    pub(crate) fn parse(input: &str) -> Result<Self> {
        let normalized = input.trim().to_ascii_lowercase();
        let base = normalized
            .split('-')
            .next()
            .context("Missing language code")?;
        match base {
            "en" => Ok(Locale::En),
            "ko" => Ok(Locale::Ko),
            _ => anyhow::bail!("Unsupported language: {input}"),
        }
    }
}

pub(crate) struct Messages {
    locale: Locale,
}

impl Messages {
    pub(crate) fn new(lang: &str) -> Result<Self> {
        let locale = Locale::parse(lang)?;
        Ok(Self { locale })
    }

    pub(crate) fn not_implemented_status(&self) -> &'static str {
        self.strings().not_implemented_status
    }

    pub(crate) fn not_implemented_app_add(&self) -> &'static str {
        self.strings().not_implemented_app_add
    }

    pub(crate) fn not_implemented_app_info(&self) -> &'static str {
        self.strings().not_implemented_app_info
    }

    pub(crate) fn not_implemented_verify(&self) -> &'static str {
        self.strings().not_implemented_verify
    }

    pub(crate) fn infra_up_completed(&self) -> &'static str {
        self.strings().infra_up_completed
    }

    pub(crate) fn infra_readiness_summary(&self) -> &'static str {
        self.strings().infra_readiness_summary
    }

    pub(crate) fn infra_entry_with_health(
        &self,
        service: &str,
        status: &str,
        health: &str,
    ) -> String {
        format_template(
            self.strings().infra_entry_with_health,
            &[("service", service), ("status", status), ("health", health)],
        )
    }

    pub(crate) fn infra_entry_without_health(&self, service: &str, status: &str) -> String {
        format_template(
            self.strings().infra_entry_without_health,
            &[("service", service), ("status", status)],
        )
    }

    pub(crate) fn infra_unhealthy(&self, failures: &str) -> String {
        format_template(self.strings().infra_unhealthy, &[("failures", failures)])
    }

    pub(crate) fn init_failed_rollback(&self) -> &'static str {
        self.strings().init_failed_rollback
    }

    pub(crate) fn prompt_openbao_root_token(&self) -> &'static str {
        self.strings().prompt_openbao_root_token
    }

    pub(crate) fn error_openbao_root_token_required(&self) -> &'static str {
        self.strings().error_openbao_root_token_required
    }

    pub(crate) fn prompt_unseal_threshold(&self) -> &'static str {
        self.strings().prompt_unseal_threshold
    }

    pub(crate) fn prompt_unseal_key(&self, index: u32, count: u32) -> String {
        let index_value = index.to_string();
        let count_value = count.to_string();
        format_template(
            self.strings().prompt_unseal_key,
            &[("index", &index_value), ("count", &count_value)],
        )
    }

    pub(crate) fn prompt_stepca_password(&self) -> &'static str {
        self.strings().prompt_stepca_password
    }

    pub(crate) fn prompt_http_hmac(&self) -> &'static str {
        self.strings().prompt_http_hmac
    }

    pub(crate) fn prompt_db_dsn(&self) -> &'static str {
        self.strings().prompt_db_dsn
    }

    pub(crate) fn error_eab_requires_both(&self) -> &'static str {
        self.strings().error_eab_requires_both
    }

    pub(crate) fn error_openbao_sealed(&self) -> &'static str {
        self.strings().error_openbao_sealed
    }

    pub(crate) fn summary_title(&self) -> &'static str {
        self.strings().summary_title
    }

    pub(crate) fn summary_openbao_url(&self, value: &str) -> String {
        format_template(self.strings().summary_openbao_url, &[("value", value)])
    }

    pub(crate) fn summary_kv_mount(&self, value: &str) -> String {
        format_template(self.strings().summary_kv_mount, &[("value", value)])
    }

    pub(crate) fn summary_secrets_dir(&self, value: &str) -> String {
        format_template(self.strings().summary_secrets_dir, &[("value", value)])
    }

    pub(crate) fn summary_stepca_completed(&self) -> &'static str {
        self.strings().summary_stepca_completed
    }

    pub(crate) fn summary_stepca_skipped(&self) -> &'static str {
        self.strings().summary_stepca_skipped
    }

    pub(crate) fn summary_openbao_init_completed(&self, shares: u8, threshold: u8) -> String {
        let shares_value = shares.to_string();
        let threshold_value = threshold.to_string();
        format_template(
            self.strings().summary_openbao_init_completed,
            &[("shares", &shares_value), ("threshold", &threshold_value)],
        )
    }

    pub(crate) fn summary_openbao_init_skipped(&self) -> &'static str {
        self.strings().summary_openbao_init_skipped
    }

    pub(crate) fn summary_root_token(&self, value: &str) -> String {
        format_template(self.strings().summary_root_token, &[("value", value)])
    }

    pub(crate) fn summary_unseal_key(&self, index: usize, value: &str) -> String {
        let index_value = index.to_string();
        format_template(
            self.strings().summary_unseal_key,
            &[("index", &index_value), ("value", value)],
        )
    }

    pub(crate) fn summary_stepca_password(&self, value: &str) -> String {
        format_template(self.strings().summary_stepca_password, &[("value", value)])
    }

    pub(crate) fn summary_db_dsn(&self, value: &str) -> String {
        format_template(self.strings().summary_db_dsn, &[("value", value)])
    }

    pub(crate) fn summary_responder_hmac(&self, value: &str) -> String {
        format_template(self.strings().summary_responder_hmac, &[("value", value)])
    }

    pub(crate) fn summary_eab_kid(&self, value: &str) -> String {
        format_template(self.strings().summary_eab_kid, &[("value", value)])
    }

    pub(crate) fn summary_eab_hmac(&self, value: &str) -> String {
        format_template(self.strings().summary_eab_hmac, &[("value", value)])
    }

    pub(crate) fn summary_eab_missing(&self) -> &'static str {
        self.strings().summary_eab_missing
    }

    pub(crate) fn summary_kv_paths(&self) -> &'static str {
        self.strings().summary_kv_paths
    }

    pub(crate) fn summary_approles(&self) -> &'static str {
        self.strings().summary_approles
    }

    pub(crate) fn summary_role_id(&self, value: &str) -> String {
        format_template(self.strings().summary_role_id, &[("value", value)])
    }

    pub(crate) fn summary_secret_id(&self, value: &str) -> String {
        format_template(self.strings().summary_secret_id, &[("value", value)])
    }

    pub(crate) fn summary_next_steps(&self) -> &'static str {
        self.strings().summary_next_steps
    }

    pub(crate) fn next_steps_configure_templates(&self) -> &'static str {
        self.strings().next_steps_configure_templates
    }

    pub(crate) fn next_steps_reload_services(&self) -> &'static str {
        self.strings().next_steps_reload_services
    }

    pub(crate) fn next_steps_run_status(&self) -> &'static str {
        self.strings().next_steps_run_status
    }

    pub(crate) fn next_steps_eab_hint(&self, path: &str) -> String {
        format_template(self.strings().next_steps_eab_hint, &[("path", path)])
    }

    fn strings(&self) -> &'static Strings {
        match self.locale {
            Locale::En => &en::STRINGS,
            Locale::Ko => &ko::STRINGS,
        }
    }
}

fn format_template(template: &str, pairs: &[(&str, &str)]) -> String {
    let mut output = template.to_string();
    for (key, value) in pairs {
        output = output.replace(&format!("{{{key}}}"), value);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_locale_parse_en() {
        assert_eq!(Locale::parse("en").unwrap(), Locale::En);
        assert_eq!(Locale::parse("EN").unwrap(), Locale::En);
        assert_eq!(Locale::parse("en-US").unwrap(), Locale::En);
    }

    #[test]
    fn test_locale_parse_ko() {
        assert_eq!(Locale::parse("ko").unwrap(), Locale::Ko);
        assert_eq!(Locale::parse("ko-KR").unwrap(), Locale::Ko);
    }

    #[test]
    fn test_locale_parse_invalid() {
        let err = Locale::parse("fr").unwrap_err();
        assert!(err.to_string().contains("Unsupported language"));
    }
}
