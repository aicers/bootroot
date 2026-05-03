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

    pub(crate) fn infra_install_completed(&self) -> &'static str {
        self.strings().infra_install_completed
    }

    pub(crate) fn infra_install_env_written(&self) -> &'static str {
        self.strings().infra_install_env_written
    }

    pub(crate) fn infra_install_dirs_created(&self) -> &'static str {
        self.strings().infra_install_dirs_created
    }

    pub(crate) fn error_infra_install_failed(&self) -> &'static str {
        self.strings().error_infra_install_failed
    }

    pub(crate) fn clean_completed(&self) -> &'static str {
        self.strings().clean_completed
    }

    pub(crate) fn clean_confirm(&self) -> &'static str {
        self.strings().clean_confirm
    }

    pub(crate) fn clean_confirm_certs(&self) -> &'static str {
        self.strings().clean_confirm_certs
    }

    pub(crate) fn clean_confirm_openbao_only(&self) -> &'static str {
        self.strings().clean_confirm_openbao_only
    }

    pub(crate) fn clean_openbao_only_completed(&self) -> &'static str {
        self.strings().clean_openbao_only_completed
    }

    pub(crate) fn error_init_partial_openbao_state(&self, url: &str) -> String {
        format_template(
            self.strings().error_init_partial_openbao_state,
            &[("url", url)],
        )
    }

    pub(crate) fn error_clean_failed(&self) -> &'static str {
        self.strings().error_clean_failed
    }

    pub(crate) fn error_env_parse_failed(&self, value: &str) -> String {
        format_template(self.strings().error_env_parse_failed, &[("value", value)])
    }

    pub(crate) fn prompt_save_unseal_keys(&self) -> &'static str {
        self.strings().prompt_save_unseal_keys
    }

    pub(crate) fn openbao_unseal_keys_saved(&self, value: &str) -> String {
        format_template(
            self.strings().openbao_unseal_keys_saved,
            &[("value", value)],
        )
    }

    pub(crate) fn openbao_unseal_keys_not_saved_warning(&self) -> &'static str {
        self.strings().openbao_unseal_keys_not_saved_warning
    }

    pub(crate) fn openbao_unseal_keys_deleted(&self, value: &str) -> String {
        format_template(
            self.strings().openbao_unseal_keys_deleted,
            &[("value", value)],
        )
    }

    pub(crate) fn error_openbao_save_unseal_keys_failed(&self) -> &'static str {
        self.strings().error_openbao_save_unseal_keys_failed
    }

    pub(crate) fn error_openbao_delete_unseal_keys_failed(&self) -> &'static str {
        self.strings().error_openbao_delete_unseal_keys_failed
    }

    pub(crate) fn error_remove_dir_failed(&self, value: &str) -> String {
        format_template(self.strings().error_remove_dir_failed, &[("value", value)])
    }

    pub(crate) fn infra_install_stepca_not_checked(&self) -> &'static str {
        self.strings().infra_install_stepca_not_checked
    }

    pub(crate) fn dns_alias_registered(&self, alias: &str) -> String {
        format_template(self.strings().dns_alias_registered, &[("value", alias)])
    }

    pub(crate) fn dns_alias_replaying(&self, count: usize) -> String {
        format_template(
            self.strings().dns_alias_replaying,
            &[("value", &count.to_string())],
        )
    }

    pub(crate) fn dns_alias_responder_not_running(&self) -> &'static str {
        self.strings().dns_alias_responder_not_running
    }

    pub(crate) fn dns_alias_connect_failed(&self) -> &'static str {
        self.strings().dns_alias_connect_failed
    }

    pub(crate) fn dns_alias_connect_rollback(&self) -> &'static str {
        self.strings().dns_alias_connect_rollback
    }

    pub(crate) fn dns_alias_connect_recovered(&self, error: &str) -> String {
        format_template(
            self.strings().dns_alias_connect_recovered,
            &[("error", error)],
        )
    }

    pub(crate) fn dns_alias_rollback_failed(&self, network: &str, error: &str) -> String {
        format_template(
            self.strings().dns_alias_rollback_failed,
            &[("network", network), ("error", error)],
        )
    }

    pub(crate) fn dns_alias_network_not_found(&self, container_id: &str) -> String {
        format_template(
            self.strings().dns_alias_network_not_found,
            &[("value", container_id)],
        )
    }
}
