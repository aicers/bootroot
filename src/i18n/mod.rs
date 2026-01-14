use anyhow::{Context, Result};

pub(crate) mod en;
pub(crate) mod ko;

pub(crate) struct AppNextStepsDaemon<'a> {
    pub(crate) service_name: &'a str,
    pub(crate) instance_id: &'a str,
    pub(crate) hostname: &'a str,
    pub(crate) domain: &'a str,
    pub(crate) cert_path: &'a str,
    pub(crate) key_path: &'a str,
    pub(crate) config_path: &'a str,
}

pub(crate) struct AppNextStepsDocker<'a> {
    pub(crate) service_name: &'a str,
    pub(crate) container_name: &'a str,
    pub(crate) hostname: &'a str,
    pub(crate) domain: &'a str,
    pub(crate) cert_path: &'a str,
    pub(crate) key_path: &'a str,
    pub(crate) config_path: &'a str,
    pub(crate) role_name: &'a str,
    pub(crate) secret_id_path: &'a str,
}

pub(crate) struct AppOpenBaoAgentSteps<'a> {
    pub(crate) service_name: &'a str,
    pub(crate) config_path: &'a str,
    pub(crate) role_id_path: &'a str,
    pub(crate) secret_id_path: &'a str,
    pub(crate) app_dir: &'a str,
}

pub(crate) struct Strings {
    pub(crate) infra_up_completed: &'static str,
    pub(crate) infra_readiness_summary: &'static str,
    pub(crate) infra_entry_with_health: &'static str,
    pub(crate) infra_entry_without_health: &'static str,
    pub(crate) infra_unhealthy: &'static str,
    pub(crate) error_service_no_container: &'static str,
    pub(crate) init_failed_rollback: &'static str,
    pub(crate) prompt_openbao_root_token: &'static str,
    pub(crate) error_openbao_root_token_required: &'static str,
    pub(crate) prompt_unseal_threshold: &'static str,
    pub(crate) prompt_unseal_key: &'static str,
    pub(crate) prompt_stepca_password: &'static str,
    pub(crate) prompt_http_hmac: &'static str,
    pub(crate) prompt_db_admin_dsn: &'static str,
    pub(crate) prompt_db_dsn: &'static str,
    pub(crate) prompt_db_user: &'static str,
    pub(crate) prompt_db_password: &'static str,
    pub(crate) prompt_db_name: &'static str,
    pub(crate) error_invalid_unseal_threshold: &'static str,
    pub(crate) error_eab_requires_both: &'static str,
    pub(crate) error_openbao_sealed: &'static str,
    pub(crate) error_invalid_db_dsn: &'static str,
    pub(crate) error_db_check_failed: &'static str,
    pub(crate) error_db_auth_failed: &'static str,
    pub(crate) error_db_type_unsupported: &'static str,
    pub(crate) error_db_provision_conflict: &'static str,
    pub(crate) error_invalid_db_identifier: &'static str,
    pub(crate) prompt_eab_register_now: &'static str,
    pub(crate) eab_prompt_instructions: &'static str,
    pub(crate) prompt_eab_auto_now: &'static str,
    pub(crate) prompt_eab_kid: &'static str,
    pub(crate) prompt_eab_hmac: &'static str,
    pub(crate) prompt_confirm_db_provision: &'static str,
    pub(crate) error_responder_check_failed: &'static str,
    pub(crate) error_eab_auto_failed: &'static str,
    pub(crate) error_state_missing: &'static str,
    pub(crate) error_app_duplicate: &'static str,
    pub(crate) error_app_not_found: &'static str,
    pub(crate) error_app_instance_id_required: &'static str,
    pub(crate) error_app_container_name_required: &'static str,
    pub(crate) error_value_required: &'static str,
    pub(crate) error_invalid_deploy_type: &'static str,
    pub(crate) error_path_not_found: &'static str,
    pub(crate) error_parent_not_found: &'static str,
    pub(crate) error_operation_cancelled: &'static str,
    pub(crate) error_infra_failed: &'static str,
    pub(crate) error_init_failed: &'static str,
    pub(crate) error_status_failed: &'static str,
    pub(crate) error_app_add_failed: &'static str,
    pub(crate) error_app_info_failed: &'static str,
    pub(crate) error_verify_failed: &'static str,
    pub(crate) error_details: &'static str,
    pub(crate) error_runtime_init_failed: &'static str,
    pub(crate) error_prompt_write_failed: &'static str,
    pub(crate) error_prompt_flush_failed: &'static str,
    pub(crate) error_prompt_read_failed: &'static str,
    pub(crate) error_prompt_error_write_failed: &'static str,
    pub(crate) error_read_file_failed: &'static str,
    pub(crate) error_write_file_failed: &'static str,
    pub(crate) error_read_dir_failed: &'static str,
    pub(crate) error_read_dir_entry_failed: &'static str,
    pub(crate) error_remove_file_failed: &'static str,
    pub(crate) error_restore_file_failed: &'static str,
    pub(crate) error_resolve_path_failed: &'static str,
    pub(crate) error_generate_secret_failed: &'static str,
    pub(crate) error_db_auth_task_failed: &'static str,
    pub(crate) error_db_provision_task_failed: &'static str,
    pub(crate) error_stepca_password_missing: &'static str,
    pub(crate) error_eab_request_failed: &'static str,
    pub(crate) error_eab_response_parse_failed: &'static str,
    pub(crate) error_openbao_client_create_failed: &'static str,
    pub(crate) error_openbao_health_check_failed: &'static str,
    pub(crate) error_openbao_init_status_failed: &'static str,
    pub(crate) error_openbao_init_failed: &'static str,
    pub(crate) error_openbao_seal_status_failed: &'static str,
    pub(crate) error_openbao_unseal_failed: &'static str,
    pub(crate) error_openbao_kv_mount_failed: &'static str,
    pub(crate) error_openbao_kv_mount_status_failed: &'static str,
    pub(crate) error_openbao_approle_auth_failed: &'static str,
    pub(crate) error_openbao_policy_exists_failed: &'static str,
    pub(crate) error_openbao_policy_write_failed: &'static str,
    pub(crate) error_openbao_approle_exists_failed: &'static str,
    pub(crate) error_openbao_approle_create_failed: &'static str,
    pub(crate) error_openbao_role_id_failed: &'static str,
    pub(crate) error_openbao_secret_id_failed: &'static str,
    pub(crate) error_openbao_kv_exists_failed: &'static str,
    pub(crate) error_openbao_kv_write_failed: &'static str,
    pub(crate) error_openbao_kv_delete_failed: &'static str,
    pub(crate) error_openbao_role_output_missing: &'static str,
    pub(crate) error_command_run_failed: &'static str,
    pub(crate) error_command_failed_status: &'static str,
    pub(crate) error_docker_compose_failed: &'static str,
    pub(crate) error_docker_command_failed: &'static str,
    pub(crate) error_bootroot_agent_run_failed: &'static str,
    pub(crate) error_secrets_dir_resolve_failed: &'static str,
    pub(crate) error_parse_ca_json_failed: &'static str,
    pub(crate) error_serialize_ca_json_failed: &'static str,
    pub(crate) error_ca_json_db_missing: &'static str,
    pub(crate) error_parse_state_failed: &'static str,
    pub(crate) error_serialize_state_failed: &'static str,
    pub(crate) prompt_service_name: &'static str,
    pub(crate) prompt_deploy_type: &'static str,
    pub(crate) prompt_hostname: &'static str,
    pub(crate) prompt_domain: &'static str,
    pub(crate) prompt_agent_config: &'static str,
    pub(crate) prompt_cert_path: &'static str,
    pub(crate) prompt_key_path: &'static str,
    pub(crate) prompt_instance_id: &'static str,
    pub(crate) prompt_container_name: &'static str,
    pub(crate) prompt_confirm_overwrite_password: &'static str,
    pub(crate) prompt_confirm_overwrite_ca_json: &'static str,
    pub(crate) prompt_confirm_overwrite_state: &'static str,
    pub(crate) init_plan_title: &'static str,
    pub(crate) init_plan_overwrite_password: &'static str,
    pub(crate) init_plan_overwrite_ca_json: &'static str,
    pub(crate) init_plan_overwrite_state: &'static str,
    pub(crate) app_add_summary: &'static str,
    pub(crate) app_add_plan_title: &'static str,
    pub(crate) app_info_summary: &'static str,
    pub(crate) app_summary_kind: &'static str,
    pub(crate) app_summary_deploy_type: &'static str,
    pub(crate) app_summary_hostname: &'static str,
    pub(crate) app_summary_domain: &'static str,
    pub(crate) app_summary_instance_id: &'static str,
    pub(crate) app_summary_container_name: &'static str,
    pub(crate) app_summary_notes: &'static str,
    pub(crate) app_summary_policy: &'static str,
    pub(crate) app_summary_approle: &'static str,
    pub(crate) app_summary_secret_path: &'static str,
    pub(crate) app_summary_secret_path_hidden: &'static str,
    pub(crate) app_summary_openbao_path: &'static str,
    pub(crate) app_summary_agent_config: &'static str,
    pub(crate) app_summary_cert_path: &'static str,
    pub(crate) app_summary_key_path: &'static str,
    pub(crate) app_summary_next_steps: &'static str,
    pub(crate) app_next_steps_daemon_profile: &'static str,
    pub(crate) app_next_steps_docker_sidecar: &'static str,
    pub(crate) app_next_steps_openbao_agent_title: &'static str,
    pub(crate) app_next_steps_openbao_agent_config: &'static str,
    pub(crate) app_next_steps_openbao_agent_role_id_path: &'static str,
    pub(crate) app_next_steps_openbao_agent_secret_id_path: &'static str,
    pub(crate) app_next_steps_openbao_agent_permissions: &'static str,
    pub(crate) app_next_steps_openbao_agent_daemon_run: &'static str,
    pub(crate) app_next_steps_openbao_agent_docker_run: &'static str,
    pub(crate) app_snippet_daemon_title: &'static str,
    pub(crate) app_snippet_docker_title: &'static str,
    pub(crate) app_snippet_domain_hint: &'static str,
    pub(crate) verify_plan_title: &'static str,
    pub(crate) verify_summary_title: &'static str,
    pub(crate) verify_service_name: &'static str,
    pub(crate) verify_agent_config: &'static str,
    pub(crate) verify_cert_path: &'static str,
    pub(crate) verify_key_path: &'static str,
    pub(crate) verify_result_ok: &'static str,
    pub(crate) verify_agent_failed: &'static str,
    pub(crate) verify_missing_cert: &'static str,
    pub(crate) verify_missing_key: &'static str,
    pub(crate) verify_empty_cert: &'static str,
    pub(crate) verify_empty_key: &'static str,
    pub(crate) verify_cert_parse_failed: &'static str,
    pub(crate) verify_cert_missing_san: &'static str,
    pub(crate) verify_cert_san_mismatch: &'static str,
    pub(crate) status_summary_title: &'static str,
    pub(crate) status_section_infra: &'static str,
    pub(crate) status_section_openbao: &'static str,
    pub(crate) status_section_kv_paths: &'static str,
    pub(crate) status_section_approles: &'static str,
    pub(crate) status_infra_entry_with_health: &'static str,
    pub(crate) status_infra_entry_without_health: &'static str,
    pub(crate) status_openbao_health: &'static str,
    pub(crate) status_openbao_sealed: &'static str,
    pub(crate) status_openbao_kv_mount: &'static str,
    pub(crate) status_kv_path_entry: &'static str,
    pub(crate) status_approle_entry: &'static str,
    pub(crate) status_value_ok: &'static str,
    pub(crate) status_value_unreachable: &'static str,
    pub(crate) status_value_present: &'static str,
    pub(crate) status_value_missing: &'static str,
    pub(crate) status_value_optional_missing: &'static str,
    pub(crate) status_value_unknown: &'static str,
    pub(crate) status_value_invalid: &'static str,
    pub(crate) status_error_infra_unhealthy: &'static str,
    pub(crate) status_error_openbao_unreachable: &'static str,
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
    pub(crate) summary_responder_check_ok: &'static str,
    pub(crate) summary_responder_check_skipped: &'static str,
    pub(crate) summary_db_check_ok: &'static str,
    pub(crate) summary_db_check_skipped: &'static str,
    pub(crate) summary_kv_paths: &'static str,
    pub(crate) summary_approles: &'static str,
    pub(crate) summary_role_id: &'static str,
    pub(crate) summary_secret_id: &'static str,
    pub(crate) summary_next_steps: &'static str,
    pub(crate) next_steps_configure_templates: &'static str,
    pub(crate) next_steps_responder_template: &'static str,
    pub(crate) next_steps_responder_config: &'static str,
    pub(crate) next_steps_responder_url: &'static str,
    pub(crate) next_steps_openbao_agent_stepca_config: &'static str,
    pub(crate) next_steps_openbao_agent_responder_config: &'static str,
    pub(crate) next_steps_openbao_agent_override: &'static str,
    pub(crate) next_steps_reload_services: &'static str,
    pub(crate) next_steps_run_status: &'static str,
    pub(crate) next_steps_eab_issue: &'static str,
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

    pub(crate) fn error_app_duplicate(&self, service_name: &str) -> String {
        format_template(
            self.strings().error_app_duplicate,
            &[("value", service_name)],
        )
    }

    pub(crate) fn error_app_not_found(&self, service_name: &str) -> String {
        format_template(
            self.strings().error_app_not_found,
            &[("value", service_name)],
        )
    }

    pub(crate) fn error_app_instance_id_required(&self) -> &'static str {
        self.strings().error_app_instance_id_required
    }

    pub(crate) fn error_app_container_name_required(&self) -> &'static str {
        self.strings().error_app_container_name_required
    }

    pub(crate) fn error_value_required(&self) -> &'static str {
        self.strings().error_value_required
    }

    pub(crate) fn error_invalid_deploy_type(&self) -> &'static str {
        self.strings().error_invalid_deploy_type
    }

    pub(crate) fn error_path_not_found(&self, value: &str) -> String {
        format_template(self.strings().error_path_not_found, &[("value", value)])
    }

    pub(crate) fn error_parent_not_found(&self, value: &str) -> String {
        format_template(self.strings().error_parent_not_found, &[("value", value)])
    }

    pub(crate) fn error_operation_cancelled(&self) -> &'static str {
        self.strings().error_operation_cancelled
    }

    pub(crate) fn error_infra_failed(&self) -> &'static str {
        self.strings().error_infra_failed
    }

    pub(crate) fn error_init_failed(&self) -> &'static str {
        self.strings().error_init_failed
    }

    pub(crate) fn error_status_failed(&self) -> &'static str {
        self.strings().error_status_failed
    }

    pub(crate) fn error_app_add_failed(&self) -> &'static str {
        self.strings().error_app_add_failed
    }

    pub(crate) fn error_app_info_failed(&self) -> &'static str {
        self.strings().error_app_info_failed
    }

    pub(crate) fn error_verify_failed(&self) -> &'static str {
        self.strings().error_verify_failed
    }

    pub(crate) fn error_details(&self, value: &str) -> String {
        format_template(self.strings().error_details, &[("value", value)])
    }

    pub(crate) fn error_runtime_init_failed(&self, command: &str) -> String {
        format_template(
            self.strings().error_runtime_init_failed,
            &[("command", command)],
        )
    }

    pub(crate) fn error_prompt_write_failed(&self) -> &'static str {
        self.strings().error_prompt_write_failed
    }

    pub(crate) fn error_prompt_flush_failed(&self) -> &'static str {
        self.strings().error_prompt_flush_failed
    }

    pub(crate) fn error_prompt_read_failed(&self) -> &'static str {
        self.strings().error_prompt_read_failed
    }

    pub(crate) fn error_prompt_error_write_failed(&self) -> &'static str {
        self.strings().error_prompt_error_write_failed
    }

    pub(crate) fn error_read_file_failed(&self, value: &str) -> String {
        format_template(self.strings().error_read_file_failed, &[("value", value)])
    }

    pub(crate) fn error_write_file_failed(&self, value: &str) -> String {
        format_template(self.strings().error_write_file_failed, &[("value", value)])
    }

    pub(crate) fn error_read_dir_failed(&self, value: &str) -> String {
        format_template(self.strings().error_read_dir_failed, &[("value", value)])
    }

    pub(crate) fn error_read_dir_entry_failed(&self) -> &'static str {
        self.strings().error_read_dir_entry_failed
    }

    pub(crate) fn error_remove_file_failed(&self, value: &str) -> String {
        format_template(self.strings().error_remove_file_failed, &[("value", value)])
    }

    pub(crate) fn error_restore_file_failed(&self, value: &str) -> String {
        format_template(
            self.strings().error_restore_file_failed,
            &[("value", value)],
        )
    }

    pub(crate) fn error_resolve_path_failed(&self, value: &str) -> String {
        format_template(
            self.strings().error_resolve_path_failed,
            &[("value", value)],
        )
    }

    pub(crate) fn error_generate_secret_failed(&self) -> &'static str {
        self.strings().error_generate_secret_failed
    }

    pub(crate) fn error_db_auth_task_failed(&self) -> &'static str {
        self.strings().error_db_auth_task_failed
    }

    pub(crate) fn error_db_provision_task_failed(&self) -> &'static str {
        self.strings().error_db_provision_task_failed
    }

    pub(crate) fn error_stepca_password_missing(&self, value: &str) -> String {
        format_template(
            self.strings().error_stepca_password_missing,
            &[("value", value)],
        )
    }

    pub(crate) fn error_eab_request_failed(&self) -> &'static str {
        self.strings().error_eab_request_failed
    }

    pub(crate) fn error_eab_response_parse_failed(&self) -> &'static str {
        self.strings().error_eab_response_parse_failed
    }

    pub(crate) fn error_openbao_client_create_failed(&self) -> &'static str {
        self.strings().error_openbao_client_create_failed
    }

    pub(crate) fn error_openbao_health_check_failed(&self) -> &'static str {
        self.strings().error_openbao_health_check_failed
    }

    pub(crate) fn error_openbao_init_status_failed(&self) -> &'static str {
        self.strings().error_openbao_init_status_failed
    }

    pub(crate) fn error_openbao_init_failed(&self) -> &'static str {
        self.strings().error_openbao_init_failed
    }

    pub(crate) fn error_openbao_seal_status_failed(&self) -> &'static str {
        self.strings().error_openbao_seal_status_failed
    }

    pub(crate) fn error_openbao_unseal_failed(&self) -> &'static str {
        self.strings().error_openbao_unseal_failed
    }

    pub(crate) fn error_openbao_kv_mount_failed(&self) -> &'static str {
        self.strings().error_openbao_kv_mount_failed
    }

    pub(crate) fn error_openbao_kv_mount_status_failed(&self) -> &'static str {
        self.strings().error_openbao_kv_mount_status_failed
    }

    pub(crate) fn error_openbao_approle_auth_failed(&self) -> &'static str {
        self.strings().error_openbao_approle_auth_failed
    }

    pub(crate) fn error_openbao_policy_exists_failed(&self) -> &'static str {
        self.strings().error_openbao_policy_exists_failed
    }

    pub(crate) fn error_openbao_policy_write_failed(&self) -> &'static str {
        self.strings().error_openbao_policy_write_failed
    }

    pub(crate) fn error_openbao_approle_exists_failed(&self) -> &'static str {
        self.strings().error_openbao_approle_exists_failed
    }

    pub(crate) fn error_openbao_approle_create_failed(&self) -> &'static str {
        self.strings().error_openbao_approle_create_failed
    }

    pub(crate) fn error_openbao_role_id_failed(&self) -> &'static str {
        self.strings().error_openbao_role_id_failed
    }

    pub(crate) fn error_openbao_secret_id_failed(&self) -> &'static str {
        self.strings().error_openbao_secret_id_failed
    }

    pub(crate) fn error_openbao_kv_exists_failed(&self) -> &'static str {
        self.strings().error_openbao_kv_exists_failed
    }

    pub(crate) fn error_openbao_kv_write_failed(&self) -> &'static str {
        self.strings().error_openbao_kv_write_failed
    }

    pub(crate) fn error_openbao_kv_delete_failed(&self) -> &'static str {
        self.strings().error_openbao_kv_delete_failed
    }

    pub(crate) fn error_openbao_role_output_missing(&self, value: &str) -> String {
        format_template(
            self.strings().error_openbao_role_output_missing,
            &[("value", value)],
        )
    }

    pub(crate) fn error_command_run_failed(&self, command: &str) -> String {
        format_template(
            self.strings().error_command_run_failed,
            &[("value", command)],
        )
    }

    pub(crate) fn error_command_failed_status(&self, command: &str, status: &str) -> String {
        format_template(
            self.strings().error_command_failed_status,
            &[("value", command), ("status", status)],
        )
    }

    pub(crate) fn error_docker_compose_failed(&self, stderr: &str) -> String {
        format_template(
            self.strings().error_docker_compose_failed,
            &[("value", stderr)],
        )
    }

    pub(crate) fn error_docker_command_failed(&self, stderr: &str) -> String {
        format_template(
            self.strings().error_docker_command_failed,
            &[("value", stderr)],
        )
    }

    pub(crate) fn error_bootroot_agent_run_failed(&self) -> &'static str {
        self.strings().error_bootroot_agent_run_failed
    }

    pub(crate) fn error_secrets_dir_resolve_failed(&self) -> &'static str {
        self.strings().error_secrets_dir_resolve_failed
    }

    pub(crate) fn error_parse_ca_json_failed(&self) -> &'static str {
        self.strings().error_parse_ca_json_failed
    }

    pub(crate) fn error_serialize_ca_json_failed(&self) -> &'static str {
        self.strings().error_serialize_ca_json_failed
    }

    pub(crate) fn error_ca_json_db_missing(&self) -> &'static str {
        self.strings().error_ca_json_db_missing
    }

    pub(crate) fn error_parse_state_failed(&self) -> &'static str {
        self.strings().error_parse_state_failed
    }

    pub(crate) fn error_serialize_state_failed(&self) -> &'static str {
        self.strings().error_serialize_state_failed
    }

    pub(crate) fn prompt_service_name(&self) -> &'static str {
        self.strings().prompt_service_name
    }

    pub(crate) fn prompt_deploy_type(&self) -> &'static str {
        self.strings().prompt_deploy_type
    }

    pub(crate) fn prompt_hostname(&self) -> &'static str {
        self.strings().prompt_hostname
    }

    pub(crate) fn prompt_domain(&self) -> &'static str {
        self.strings().prompt_domain
    }

    pub(crate) fn prompt_agent_config(&self) -> &'static str {
        self.strings().prompt_agent_config
    }

    pub(crate) fn prompt_cert_path(&self) -> &'static str {
        self.strings().prompt_cert_path
    }

    pub(crate) fn prompt_key_path(&self) -> &'static str {
        self.strings().prompt_key_path
    }

    pub(crate) fn prompt_instance_id(&self) -> &'static str {
        self.strings().prompt_instance_id
    }

    pub(crate) fn prompt_container_name(&self) -> &'static str {
        self.strings().prompt_container_name
    }

    pub(crate) fn prompt_confirm_overwrite_password(&self) -> &'static str {
        self.strings().prompt_confirm_overwrite_password
    }

    pub(crate) fn prompt_confirm_overwrite_ca_json(&self) -> &'static str {
        self.strings().prompt_confirm_overwrite_ca_json
    }

    pub(crate) fn prompt_confirm_overwrite_state(&self) -> &'static str {
        self.strings().prompt_confirm_overwrite_state
    }

    pub(crate) fn init_plan_title(&self) -> &'static str {
        self.strings().init_plan_title
    }

    pub(crate) fn init_plan_overwrite_password(&self) -> &'static str {
        self.strings().init_plan_overwrite_password
    }

    pub(crate) fn init_plan_overwrite_ca_json(&self) -> &'static str {
        self.strings().init_plan_overwrite_ca_json
    }

    pub(crate) fn init_plan_overwrite_state(&self) -> &'static str {
        self.strings().init_plan_overwrite_state
    }

    pub(crate) fn app_add_summary(&self) -> &'static str {
        self.strings().app_add_summary
    }

    pub(crate) fn app_add_plan_title(&self) -> &'static str {
        self.strings().app_add_plan_title
    }

    pub(crate) fn app_info_summary(&self) -> &'static str {
        self.strings().app_info_summary
    }

    pub(crate) fn app_summary_kind(&self, value: &str) -> String {
        format_template(self.strings().app_summary_kind, &[("value", value)])
    }

    pub(crate) fn app_summary_deploy_type(&self, value: &str) -> String {
        format_template(self.strings().app_summary_deploy_type, &[("value", value)])
    }

    pub(crate) fn app_summary_hostname(&self, value: &str) -> String {
        format_template(self.strings().app_summary_hostname, &[("value", value)])
    }

    pub(crate) fn app_summary_domain(&self, value: &str) -> String {
        format_template(self.strings().app_summary_domain, &[("value", value)])
    }

    pub(crate) fn app_summary_instance_id(&self, value: &str) -> String {
        format_template(self.strings().app_summary_instance_id, &[("value", value)])
    }

    pub(crate) fn app_summary_container_name(&self, value: &str) -> String {
        format_template(
            self.strings().app_summary_container_name,
            &[("value", value)],
        )
    }

    pub(crate) fn app_summary_notes(&self, value: &str) -> String {
        format_template(self.strings().app_summary_notes, &[("value", value)])
    }

    pub(crate) fn app_summary_policy(&self, value: &str) -> String {
        format_template(self.strings().app_summary_policy, &[("value", value)])
    }

    pub(crate) fn app_summary_approle(&self, value: &str) -> String {
        format_template(self.strings().app_summary_approle, &[("value", value)])
    }

    pub(crate) fn app_summary_secret_path(&self, value: &str) -> String {
        format_template(self.strings().app_summary_secret_path, &[("value", value)])
    }

    pub(crate) fn app_summary_secret_path_hidden(&self) -> &'static str {
        self.strings().app_summary_secret_path_hidden
    }

    pub(crate) fn app_summary_openbao_path(&self, value: &str) -> String {
        format_template(self.strings().app_summary_openbao_path, &[("value", value)])
    }

    pub(crate) fn app_summary_agent_config(&self, value: &str) -> String {
        format_template(self.strings().app_summary_agent_config, &[("value", value)])
    }

    pub(crate) fn app_summary_cert_path(&self, value: &str) -> String {
        format_template(self.strings().app_summary_cert_path, &[("value", value)])
    }

    pub(crate) fn app_summary_key_path(&self, value: &str) -> String {
        format_template(self.strings().app_summary_key_path, &[("value", value)])
    }

    pub(crate) fn app_summary_next_steps(&self) -> &'static str {
        self.strings().app_summary_next_steps
    }

    pub(crate) fn app_next_steps_daemon_profile(&self, data: &AppNextStepsDaemon<'_>) -> String {
        format_template(
            self.strings().app_next_steps_daemon_profile,
            &[
                ("service_name", data.service_name),
                ("instance_id", data.instance_id),
                ("hostname", data.hostname),
                ("domain", data.domain),
                ("cert_path", data.cert_path),
                ("key_path", data.key_path),
                ("config_path", data.config_path),
            ],
        )
    }

    pub(crate) fn app_next_steps_docker_sidecar(&self, data: &AppNextStepsDocker<'_>) -> String {
        format_template(
            self.strings().app_next_steps_docker_sidecar,
            &[
                ("service_name", data.service_name),
                ("container_name", data.container_name),
                ("hostname", data.hostname),
                ("domain", data.domain),
                ("cert_path", data.cert_path),
                ("key_path", data.key_path),
                ("config_path", data.config_path),
                ("role_name", data.role_name),
                ("secret_id_path", data.secret_id_path),
            ],
        )
    }

    pub(crate) fn app_next_steps_openbao_agent_title(&self) -> &'static str {
        self.strings().app_next_steps_openbao_agent_title
    }

    pub(crate) fn app_next_steps_openbao_agent_config(
        &self,
        data: &AppOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().app_next_steps_openbao_agent_config,
            &[
                ("service_name", data.service_name),
                ("config_path", data.config_path),
            ],
        )
    }

    pub(crate) fn app_next_steps_openbao_agent_role_id_path(
        &self,
        data: &AppOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().app_next_steps_openbao_agent_role_id_path,
            &[("role_id_path", data.role_id_path)],
        )
    }

    pub(crate) fn app_next_steps_openbao_agent_secret_id_path(
        &self,
        data: &AppOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().app_next_steps_openbao_agent_secret_id_path,
            &[("secret_id_path", data.secret_id_path)],
        )
    }

    pub(crate) fn app_next_steps_openbao_agent_permissions(
        &self,
        data: &AppOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().app_next_steps_openbao_agent_permissions,
            &[("app_dir", data.app_dir)],
        )
    }

    pub(crate) fn app_next_steps_openbao_agent_daemon_run(
        &self,
        data: &AppOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().app_next_steps_openbao_agent_daemon_run,
            &[("config_path", data.config_path)],
        )
    }

    pub(crate) fn app_next_steps_openbao_agent_docker_run(
        &self,
        data: &AppOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().app_next_steps_openbao_agent_docker_run,
            &[("config_path", data.config_path)],
        )
    }

    pub(crate) fn app_snippet_daemon_title(&self) -> &'static str {
        self.strings().app_snippet_daemon_title
    }

    pub(crate) fn app_snippet_docker_title(&self) -> &'static str {
        self.strings().app_snippet_docker_title
    }

    pub(crate) fn app_snippet_domain_hint(&self, value: &str) -> String {
        format_template(self.strings().app_snippet_domain_hint, &[("value", value)])
    }

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

    pub(crate) fn status_infra_entry_with_health(
        &self,
        service: &str,
        status: &str,
        health: &str,
    ) -> String {
        format_template(
            self.strings().status_infra_entry_with_health,
            &[("service", service), ("status", status), ("health", health)],
        )
    }

    pub(crate) fn status_infra_entry_without_health(&self, service: &str, status: &str) -> String {
        format_template(
            self.strings().status_infra_entry_without_health,
            &[("service", service), ("status", status)],
        )
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
