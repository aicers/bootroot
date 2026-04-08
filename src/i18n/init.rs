use super::{Messages, format_template};

impl Messages {
    pub(crate) fn error_service_no_container(&self, service: &str) -> String {
        format_template(
            self.strings().error_service_no_container,
            &[("service", service)],
        )
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

    pub(crate) fn warning_openbao_unseal_from_file(&self) -> &'static str {
        self.strings().warning_openbao_unseal_from_file
    }

    pub(crate) fn warning_db_password_rotation_skipped(&self) -> &'static str {
        self.strings().warning_db_password_rotation_skipped
    }

    pub(crate) fn prompt_openbao_unseal_from_file_confirm(&self, value: &str) -> String {
        format_template(
            self.strings().prompt_openbao_unseal_from_file_confirm,
            &[("value", value)],
        )
    }

    pub(crate) fn error_openbao_unseal_file_empty(&self, value: &str) -> String {
        format_template(
            self.strings().error_openbao_unseal_file_empty,
            &[("value", value)],
        )
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

    pub(crate) fn prompt_db_admin_dsn(&self) -> &'static str {
        self.strings().prompt_db_admin_dsn
    }

    pub(crate) fn prompt_db_dsn(&self) -> &'static str {
        self.strings().prompt_db_dsn
    }

    pub(crate) fn prompt_db_user(&self) -> &'static str {
        self.strings().prompt_db_user
    }

    pub(crate) fn prompt_db_password(&self) -> &'static str {
        self.strings().prompt_db_password
    }

    pub(crate) fn prompt_db_name(&self) -> &'static str {
        self.strings().prompt_db_name
    }

    pub(crate) fn error_invalid_unseal_threshold(&self) -> &'static str {
        self.strings().error_invalid_unseal_threshold
    }

    pub(crate) fn error_eab_requires_both(&self) -> &'static str {
        self.strings().error_eab_requires_both
    }

    pub(crate) fn error_openbao_sealed(&self) -> &'static str {
        self.strings().error_openbao_sealed
    }

    pub(crate) fn error_invalid_db_dsn(&self) -> &'static str {
        self.strings().error_invalid_db_dsn
    }

    pub(crate) fn error_db_host_not_single_host(&self, host: &str) -> String {
        format_template(
            self.strings().error_db_host_not_single_host,
            &[("host", host)],
        )
    }

    pub(crate) fn error_db_host_compose_runtime(&self, host: &str, expected: &str) -> String {
        format_template(
            self.strings().error_db_host_compose_runtime,
            &[("host", host), ("expected", expected)],
        )
    }

    pub(crate) fn error_postgres_port_binding_unsafe(&self) -> &'static str {
        self.strings().error_postgres_port_binding_unsafe
    }

    pub(crate) fn error_service_port_binding_unsafe(&self, service: &str) -> String {
        format_template(
            self.strings().error_service_port_binding_unsafe,
            &[("service", service)],
        )
    }

    pub(crate) fn error_db_check_failed(&self) -> &'static str {
        self.strings().error_db_check_failed
    }

    pub(crate) fn error_db_auth_failed(&self) -> &'static str {
        self.strings().error_db_auth_failed
    }

    pub(crate) fn error_db_type_unsupported(&self) -> &'static str {
        self.strings().error_db_type_unsupported
    }

    pub(crate) fn error_db_provision_conflict(&self) -> &'static str {
        self.strings().error_db_provision_conflict
    }

    pub(crate) fn error_invalid_db_identifier(&self, value: &str) -> String {
        format_template(
            self.strings().error_invalid_db_identifier,
            &[("value", value)],
        )
    }

    pub(crate) fn prompt_eab_register_now(&self) -> &'static str {
        self.strings().prompt_eab_register_now
    }

    pub(crate) fn eab_prompt_instructions(&self) -> &'static str {
        self.strings().eab_prompt_instructions
    }

    pub(crate) fn prompt_eab_auto_now(&self) -> &'static str {
        self.strings().prompt_eab_auto_now
    }

    pub(crate) fn prompt_eab_kid(&self) -> &'static str {
        self.strings().prompt_eab_kid
    }

    pub(crate) fn prompt_eab_hmac(&self) -> &'static str {
        self.strings().prompt_eab_hmac
    }

    pub(crate) fn prompt_confirm_db_provision(&self) -> &'static str {
        self.strings().prompt_confirm_db_provision
    }

    pub(crate) fn error_responder_check_failed(&self) -> &'static str {
        self.strings().error_responder_check_failed
    }

    pub(crate) fn error_eab_auto_failed(&self) -> &'static str {
        self.strings().error_eab_auto_failed
    }

    pub(crate) fn error_state_missing(&self) -> &'static str {
        self.strings().error_state_missing
    }
}

impl Messages {
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
}

impl Messages {
    pub(crate) fn summary_responder_check_ok(&self) -> &'static str {
        self.strings().summary_responder_check_ok
    }

    pub(crate) fn summary_responder_check_skipped(&self) -> &'static str {
        self.strings().summary_responder_check_skipped
    }

    pub(crate) fn summary_db_check_ok(&self) -> &'static str {
        self.strings().summary_db_check_ok
    }

    pub(crate) fn summary_db_check_skipped(&self) -> &'static str {
        self.strings().summary_db_check_skipped
    }

    pub(crate) fn summary_db_host_resolution(&self, from: &str, to: &str) -> String {
        format_template(
            self.strings().summary_db_host_resolution,
            &[("from", from), ("to", to)],
        )
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

    pub(crate) fn next_steps_responder_template(&self, value: &str) -> String {
        format_template(
            self.strings().next_steps_responder_template,
            &[("value", value)],
        )
    }

    pub(crate) fn next_steps_responder_config(&self, value: &str) -> String {
        format_template(
            self.strings().next_steps_responder_config,
            &[("value", value)],
        )
    }

    pub(crate) fn next_steps_responder_url(&self, value: &str) -> String {
        format_template(self.strings().next_steps_responder_url, &[("value", value)])
    }

    pub(crate) fn next_steps_openbao_agent_stepca_config(&self, value: &str) -> String {
        format_template(
            self.strings().next_steps_openbao_agent_stepca_config,
            &[("value", value)],
        )
    }

    pub(crate) fn next_steps_openbao_agent_responder_config(&self, value: &str) -> String {
        format_template(
            self.strings().next_steps_openbao_agent_responder_config,
            &[("value", value)],
        )
    }

    pub(crate) fn next_steps_openbao_agent_override(&self, value: &str) -> String {
        format_template(
            self.strings().next_steps_openbao_agent_override,
            &[("value", value)],
        )
    }

    pub(crate) fn next_steps_reload_services(&self) -> &'static str {
        self.strings().next_steps_reload_services
    }

    pub(crate) fn next_steps_run_status(&self) -> &'static str {
        self.strings().next_steps_run_status
    }

    pub(crate) fn next_steps_eab_issue(&self) -> &'static str {
        self.strings().next_steps_eab_issue
    }

    pub(crate) fn next_steps_eab_hint(&self, path: &str) -> String {
        format_template(self.strings().next_steps_eab_hint, &[("path", path)])
    }
}
