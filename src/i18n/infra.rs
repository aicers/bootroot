use super::{Messages, format_template};

impl Messages {
    pub(crate) fn infra_up_completed(&self) -> &'static str {
        self.strings().infra_up_completed
    }

    pub(crate) fn infra_readiness_summary(&self) -> &'static str {
        self.strings().infra_readiness_summary
    }

    pub(crate) fn readiness_entry_with_health(
        &self,
        service: &str,
        status: &str,
        health: &str,
    ) -> String {
        format_template(
            self.strings().readiness_entry_with_health,
            &[("service", service), ("status", status), ("health", health)],
        )
    }

    pub(crate) fn readiness_entry_without_health(&self, service: &str, status: &str) -> String {
        format_template(
            self.strings().readiness_entry_without_health,
            &[("service", service), ("status", status)],
        )
    }

    pub(crate) fn infra_unhealthy(&self, failures: &str) -> String {
        format_template(self.strings().infra_unhealthy, &[("failures", failures)])
    }

    pub(crate) fn monitoring_up_completed(&self) -> &'static str {
        self.strings().monitoring_up_completed
    }

    pub(crate) fn monitoring_readiness_summary(&self) -> &'static str {
        self.strings().monitoring_readiness_summary
    }

    pub(crate) fn monitoring_unhealthy(&self, failures: &str) -> String {
        format_template(
            self.strings().monitoring_unhealthy,
            &[("failures", failures)],
        )
    }

    pub(crate) fn monitoring_status_title(&self) -> &'static str {
        self.strings().monitoring_status_title
    }

    pub(crate) fn monitoring_status_profile(&self, value: &str) -> String {
        format_template(
            self.strings().monitoring_status_profile,
            &[("value", value)],
        )
    }

    pub(crate) fn monitoring_status_section_services(&self) -> &'static str {
        self.strings().monitoring_status_section_services
    }

    pub(crate) fn status_entry_with_health(
        &self,
        service: &str,
        status: &str,
        health: &str,
    ) -> String {
        format_template(
            self.strings().status_entry_with_health,
            &[("service", service), ("status", status), ("health", health)],
        )
    }

    pub(crate) fn status_entry_without_health(&self, service: &str, status: &str) -> String {
        format_template(
            self.strings().status_entry_without_health,
            &[("service", service), ("status", status)],
        )
    }

    pub(crate) fn monitoring_status_grafana_url(&self, value: &str) -> String {
        format_template(
            self.strings().monitoring_status_grafana_url,
            &[("value", value)],
        )
    }

    pub(crate) fn monitoring_status_grafana_admin_password(&self, value: &str) -> String {
        format_template(
            self.strings().monitoring_status_grafana_admin_password,
            &[("value", value)],
        )
    }

    pub(crate) fn monitoring_status_value_set(&self) -> &'static str {
        self.strings().monitoring_status_value_set
    }

    pub(crate) fn monitoring_status_value_default(&self) -> &'static str {
        self.strings().monitoring_status_value_default
    }

    pub(crate) fn monitoring_status_value_unknown(&self) -> &'static str {
        self.strings().monitoring_status_value_unknown
    }

    pub(crate) fn monitoring_status_no_services(&self) -> &'static str {
        self.strings().monitoring_status_no_services
    }

    pub(crate) fn monitoring_down_completed(&self) -> &'static str {
        self.strings().monitoring_down_completed
    }

    pub(crate) fn monitoring_down_reset_grafana(&self) -> &'static str {
        self.strings().monitoring_down_reset_grafana
    }

    pub(crate) fn monitoring_down_reset_grafana_skipped(&self) -> &'static str {
        self.strings().monitoring_down_reset_grafana_skipped
    }

    pub(crate) fn monitoring_up_already_running(&self) -> &'static str {
        self.strings().monitoring_up_already_running
    }
}
