use super::{Messages, format_template};

impl Messages {
    pub(crate) fn verify_summary_title(&self) -> &'static str {
        self.strings().verify_summary_title
    }

    pub(crate) fn verify_plan_title(&self) -> &'static str {
        self.strings().verify_plan_title
    }

    pub(crate) fn verify_service_name(&self, value: &str) -> String {
        format_template(self.strings().verify_service_name, &[("value", value)])
    }

    pub(crate) fn verify_agent_config(&self, value: &str) -> String {
        format_template(self.strings().verify_agent_config, &[("value", value)])
    }

    pub(crate) fn verify_cert_path(&self, value: &str) -> String {
        format_template(self.strings().verify_cert_path, &[("value", value)])
    }

    pub(crate) fn verify_key_path(&self, value: &str) -> String {
        format_template(self.strings().verify_key_path, &[("value", value)])
    }

    pub(crate) fn verify_result_ok(&self) -> &'static str {
        self.strings().verify_result_ok
    }

    pub(crate) fn verify_agent_failed(&self) -> &'static str {
        self.strings().verify_agent_failed
    }

    pub(crate) fn verify_missing_cert(&self, value: &str) -> String {
        format_template(self.strings().verify_missing_cert, &[("value", value)])
    }

    pub(crate) fn verify_missing_key(&self, value: &str) -> String {
        format_template(self.strings().verify_missing_key, &[("value", value)])
    }

    pub(crate) fn verify_empty_cert(&self, value: &str) -> String {
        format_template(self.strings().verify_empty_cert, &[("value", value)])
    }

    pub(crate) fn verify_empty_key(&self, value: &str) -> String {
        format_template(self.strings().verify_empty_key, &[("value", value)])
    }

    pub(crate) fn verify_cert_parse_failed(&self) -> &'static str {
        self.strings().verify_cert_parse_failed
    }

    pub(crate) fn verify_cert_missing_san(&self) -> &'static str {
        self.strings().verify_cert_missing_san
    }

    pub(crate) fn verify_cert_san_mismatch(&self, expected: &str, actual: &str) -> String {
        format_template(
            self.strings().verify_cert_san_mismatch,
            &[("expected", expected), ("actual", actual)],
        )
    }

    pub(crate) fn status_summary_title(&self) -> &'static str {
        self.strings().status_summary_title
    }

    pub(crate) fn status_section_infra(&self) -> &'static str {
        self.strings().status_section_infra
    }

    pub(crate) fn status_section_openbao(&self) -> &'static str {
        self.strings().status_section_openbao
    }

    pub(crate) fn status_section_kv_paths(&self) -> &'static str {
        self.strings().status_section_kv_paths
    }

    pub(crate) fn status_section_approles(&self) -> &'static str {
        self.strings().status_section_approles
    }

    pub(crate) fn status_section_services(&self) -> &'static str {
        self.strings().status_section_services
    }

    pub(crate) fn status_services_none(&self) -> &'static str {
        self.strings().status_services_none
    }

    pub(crate) fn status_openbao_health(&self, value: &str) -> String {
        format_template(self.strings().status_openbao_health, &[("value", value)])
    }

    pub(crate) fn status_openbao_sealed(&self, value: &str) -> String {
        format_template(self.strings().status_openbao_sealed, &[("value", value)])
    }

    pub(crate) fn status_openbao_kv_mount(&self, mount: &str, value: &str) -> String {
        format_template(
            self.strings().status_openbao_kv_mount,
            &[("mount", mount), ("value", value)],
        )
    }

    pub(crate) fn status_kv_path_entry(&self, path: &str, value: &str) -> String {
        format_template(
            self.strings().status_kv_path_entry,
            &[("path", path), ("value", value)],
        )
    }

    pub(crate) fn status_approle_entry(&self, role: &str, value: &str) -> String {
        format_template(
            self.strings().status_approle_entry,
            &[("role", role), ("value", value)],
        )
    }

    pub(crate) fn status_service_delivery_mode(&self, service: &str, value: &str) -> String {
        format_template(
            self.strings().status_service_delivery_mode,
            &[("service", service), ("value", value)],
        )
    }

    pub(crate) fn status_value_ok(&self) -> &'static str {
        self.strings().status_value_ok
    }

    pub(crate) fn status_value_unreachable(&self) -> &'static str {
        self.strings().status_value_unreachable
    }

    pub(crate) fn status_value_present(&self) -> &'static str {
        self.strings().status_value_present
    }

    pub(crate) fn status_value_missing(&self) -> &'static str {
        self.strings().status_value_missing
    }

    pub(crate) fn status_value_optional_missing(&self) -> &'static str {
        self.strings().status_value_optional_missing
    }

    pub(crate) fn status_value_unknown(&self) -> &'static str {
        self.strings().status_value_unknown
    }

    pub(crate) fn status_value_invalid(&self) -> &'static str {
        self.strings().status_value_invalid
    }

    pub(crate) fn status_error_infra_unhealthy(&self, failures: &str) -> String {
        format_template(
            self.strings().status_error_infra_unhealthy,
            &[("failures", failures)],
        )
    }

    pub(crate) fn status_error_openbao_unreachable(&self) -> &'static str {
        self.strings().status_error_openbao_unreachable
    }
}
