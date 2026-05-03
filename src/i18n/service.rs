use super::{
    Messages, ServiceNextStepsDaemon, ServiceNextStepsDocker, ServiceOpenBaoAgentSteps,
    format_template,
};

impl Messages {
    pub(crate) fn error_service_duplicate(&self, service_name: &str) -> String {
        format_template(
            self.strings().error_service_duplicate,
            &[("value", service_name)],
        )
    }

    pub(crate) fn error_service_policy_mismatch(&self) -> &'static str {
        self.strings().error_service_policy_mismatch
    }

    pub(crate) fn error_service_not_found(&self, service_name: &str) -> String {
        format_template(
            self.strings().error_service_not_found,
            &[("value", service_name)],
        )
    }

    pub(crate) fn error_service_instance_id_required(&self) -> &'static str {
        self.strings().error_service_instance_id_required
    }

    pub(crate) fn error_service_container_name_required(&self) -> &'static str {
        self.strings().error_service_container_name_required
    }

    pub(crate) fn error_value_required(&self) -> &'static str {
        self.strings().error_value_required
    }

    pub(crate) fn error_service_name_invalid(&self) -> &'static str {
        self.strings().error_service_name_invalid
    }

    pub(crate) fn error_hostname_invalid(&self) -> &'static str {
        self.strings().error_hostname_invalid
    }

    pub(crate) fn error_domain_invalid(&self) -> &'static str {
        self.strings().error_domain_invalid
    }

    pub(crate) fn error_instance_id_invalid(&self) -> &'static str {
        self.strings().error_instance_id_invalid
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

    pub(crate) fn error_monitoring_failed(&self) -> &'static str {
        self.strings().error_monitoring_failed
    }

    pub(crate) fn error_init_failed(&self) -> &'static str {
        self.strings().error_init_failed
    }

    pub(crate) fn error_status_failed(&self) -> &'static str {
        self.strings().error_status_failed
    }

    pub(crate) fn error_service_add_failed(&self) -> &'static str {
        self.strings().error_service_add_failed
    }

    pub(crate) fn error_service_info_failed(&self) -> &'static str {
        self.strings().error_service_info_failed
    }

    pub(crate) fn error_verify_failed(&self) -> &'static str {
        self.strings().error_verify_failed
    }

    pub(crate) fn error_rotate_failed(&self) -> &'static str {
        self.strings().error_rotate_failed
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

    pub(crate) fn error_file_missing(&self, value: &str) -> String {
        format_template(self.strings().error_file_missing, &[("value", value)])
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

    pub(crate) fn error_openbao_approle_login_failed(&self) -> &'static str {
        self.strings().error_openbao_approle_login_failed
    }

    pub(crate) fn error_openbao_kv_exists_failed(&self) -> &'static str {
        self.strings().error_openbao_kv_exists_failed
    }

    pub(crate) fn error_openbao_kv_write_failed(&self) -> &'static str {
        self.strings().error_openbao_kv_write_failed
    }

    pub(crate) fn error_openbao_kv_read_failed(&self) -> &'static str {
        self.strings().error_openbao_kv_read_failed
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

    pub(crate) fn error_parse_container_env_failed(&self) -> &'static str {
        self.strings().error_parse_container_env_failed
    }

    pub(crate) fn error_parse_container_mounts_failed(&self) -> &'static str {
        self.strings().error_parse_container_mounts_failed
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

    pub(crate) fn error_bootroot_agent_not_found(&self, candidates: &str) -> String {
        format_template(
            self.strings().error_bootroot_agent_not_found,
            &[("candidates", candidates)],
        )
    }

    pub(crate) fn error_bootroot_agent_container_missing(&self, container: &str) -> String {
        format_template(
            self.strings().error_bootroot_agent_container_missing,
            &[("container", container)],
        )
    }

    pub(crate) fn error_secrets_dir_resolve_failed(&self) -> &'static str {
        self.strings().error_secrets_dir_resolve_failed
    }

    pub(crate) fn error_rendered_file_timeout(&self, value: &str) -> String {
        format_template(
            self.strings().error_rendered_file_timeout,
            &[("value", value)],
        )
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

    pub(crate) fn error_ca_cert_missing(&self, path: &str) -> String {
        format_template(self.strings().error_ca_cert_missing, &[("value", path)])
    }

    pub(crate) fn error_ca_cert_parse_failed(&self, path: &str) -> String {
        format_template(
            self.strings().error_ca_cert_parse_failed,
            &[("value", path)],
        )
    }

    pub(crate) fn error_ca_trust_missing(&self, key: &str) -> String {
        format_template(self.strings().error_ca_trust_missing, &[("value", key)])
    }

    pub(crate) fn error_ca_trust_invalid(&self) -> &'static str {
        self.strings().error_ca_trust_invalid
    }

    pub(crate) fn error_ca_trust_empty(&self) -> &'static str {
        self.strings().error_ca_trust_empty
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

    pub(crate) fn prompt_rotate_stepca_password(&self) -> &'static str {
        self.strings().prompt_rotate_stepca_password
    }

    pub(crate) fn prompt_rotate_db(&self) -> &'static str {
        self.strings().prompt_rotate_db
    }

    pub(crate) fn prompt_rotate_responder_hmac(&self) -> &'static str {
        self.strings().prompt_rotate_responder_hmac
    }

    pub(crate) fn prompt_rotate_approle_secret_id(&self, service_name: &str) -> String {
        format_template(
            self.strings().prompt_rotate_approle_secret_id,
            &[("service_name", service_name)],
        )
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

    pub(crate) fn service_add_summary(&self) -> &'static str {
        self.strings().service_add_summary
    }

    pub(crate) fn service_add_plan_title(&self) -> &'static str {
        self.strings().service_add_plan_title
    }

    pub(crate) fn service_info_summary(&self) -> &'static str {
        self.strings().service_info_summary
    }

    pub(crate) fn service_summary_kind(&self, value: &str) -> String {
        format_template(self.strings().service_summary_kind, &[("value", value)])
    }

    pub(crate) fn service_summary_deploy_type(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_deploy_type,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_hostname(&self, value: &str) -> String {
        format_template(self.strings().service_summary_hostname, &[("value", value)])
    }

    pub(crate) fn service_summary_domain(&self, value: &str) -> String {
        format_template(self.strings().service_summary_domain, &[("value", value)])
    }

    pub(crate) fn service_summary_delivery_mode(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_delivery_mode,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_instance_id(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_instance_id,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_container_name(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_container_name,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_notes(&self, value: &str) -> String {
        format_template(self.strings().service_summary_notes, &[("value", value)])
    }

    pub(crate) fn service_summary_post_renew_hook(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_post_renew_hook,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_policy(&self, value: &str) -> String {
        format_template(self.strings().service_summary_policy, &[("value", value)])
    }

    pub(crate) fn service_summary_approle(&self, value: &str) -> String {
        format_template(self.strings().service_summary_approle, &[("value", value)])
    }

    pub(crate) fn service_summary_secret_path(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_secret_path,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_openbao_path(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_openbao_path,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_auto_applied_agent_config(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_auto_applied_agent_config,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_auto_applied_openbao_config(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_auto_applied_openbao_config,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_auto_applied_openbao_template(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_auto_applied_openbao_template,
            &[("value", value)],
        )
    }

    pub(crate) fn service_scope_bootroot_managed(&self) -> &'static str {
        self.strings().service_scope_bootroot_managed
    }

    pub(crate) fn service_scope_operator_required(&self) -> &'static str {
        self.strings().service_scope_operator_required
    }

    pub(crate) fn service_scope_operator_recommended(&self) -> &'static str {
        self.strings().service_scope_operator_recommended
    }

    pub(crate) fn service_scope_operator_optional(&self) -> &'static str {
        self.strings().service_scope_operator_optional
    }

    pub(crate) fn service_summary_remote_bootstrap_file(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_remote_bootstrap_file,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_remote_run_command(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_remote_run_command,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_remote_handoff_title(&self) -> &'static str {
        self.strings().service_summary_remote_handoff_title
    }

    pub(crate) fn service_summary_remote_handoff_service_host(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_remote_handoff_service_host,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_remote_handoff_service_host_no_wrap(
        &self,
        value: &str,
    ) -> String {
        format_template(
            self.strings()
                .service_summary_remote_handoff_service_host_no_wrap,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_remote_placeholder_warning(&self) -> &'static str {
        self.strings().service_summary_remote_placeholder_warning
    }

    pub(crate) fn service_summary_remote_handoff_status_check(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_remote_handoff_status_check,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_agent_config(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_agent_config,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_cert_path(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_cert_path,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_key_path(&self, value: &str) -> String {
        format_template(self.strings().service_summary_key_path, &[("value", value)])
    }

    pub(crate) fn service_summary_next_steps(&self) -> &'static str {
        self.strings().service_summary_next_steps
    }

    pub(crate) fn service_summary_preview_mode(&self) -> &'static str {
        self.strings().service_summary_preview_mode
    }

    pub(crate) fn service_summary_preview_trust_skipped_no_token(&self) -> &'static str {
        self.strings()
            .service_summary_preview_trust_skipped_no_token
    }

    pub(crate) fn service_summary_preview_trust_not_found(&self) -> &'static str {
        self.strings().service_summary_preview_trust_not_found
    }

    pub(crate) fn service_summary_preview_trust_lookup_failed(&self, value: &str) -> String {
        format_template(
            self.strings().service_summary_preview_trust_lookup_failed,
            &[("value", value)],
        )
    }

    pub(crate) fn service_summary_remote_idempotent_hint(&self) -> &'static str {
        self.strings().service_summary_remote_idempotent_hint
    }

    pub(crate) fn service_next_steps_daemon_profile(
        &self,
        data: &ServiceNextStepsDaemon<'_>,
    ) -> String {
        format_template(
            self.strings().service_next_steps_daemon_profile,
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

    pub(crate) fn service_next_steps_docker_sidecar(
        &self,
        data: &ServiceNextStepsDocker<'_>,
    ) -> String {
        format_template(
            self.strings().service_next_steps_docker_sidecar,
            &[
                ("service_name", data.service_name),
                ("container_name", data.container_name),
                ("instance_id", data.instance_id),
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

    pub(crate) fn service_next_steps_openbao_agent_title(&self) -> &'static str {
        self.strings().service_next_steps_openbao_agent_title
    }

    pub(crate) fn service_next_steps_openbao_agent_config(
        &self,
        data: &ServiceOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().service_next_steps_openbao_agent_config,
            &[
                ("service_name", data.service_name),
                ("config_path", data.config_path),
            ],
        )
    }

    pub(crate) fn service_next_steps_openbao_agent_role_id_path(
        &self,
        data: &ServiceOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().service_next_steps_openbao_agent_role_id_path,
            &[("role_id_path", data.role_id_path)],
        )
    }

    pub(crate) fn service_next_steps_openbao_agent_secret_id_path(
        &self,
        data: &ServiceOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings()
                .service_next_steps_openbao_agent_secret_id_path,
            &[("secret_id_path", data.secret_id_path)],
        )
    }

    pub(crate) fn service_next_steps_openbao_agent_permissions(
        &self,
        data: &ServiceOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().service_next_steps_openbao_agent_permissions,
            &[("service_dir", data.service_dir)],
        )
    }

    pub(crate) fn service_next_steps_openbao_agent_daemon_run(
        &self,
        data: &ServiceOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().service_next_steps_openbao_agent_daemon_run,
            &[("config_path", data.config_path)],
        )
    }

    pub(crate) fn service_next_steps_openbao_agent_docker_run(
        &self,
        data: &ServiceOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().service_next_steps_openbao_agent_docker_run,
            &[("config_path", data.config_path)],
        )
    }

    pub(crate) fn service_next_steps_openbao_sidecar_start(
        &self,
        data: &ServiceOpenBaoAgentSteps<'_>,
    ) -> String {
        format_template(
            self.strings().service_next_steps_openbao_sidecar_start,
            &[
                ("service_name", data.service_name),
                ("config_path", data.config_path),
            ],
        )
    }

    pub(crate) fn service_snippet_daemon_title(&self) -> &'static str {
        self.strings().service_snippet_daemon_title
    }

    pub(crate) fn service_snippet_docker_title(&self) -> &'static str {
        self.strings().service_snippet_docker_title
    }

    pub(crate) fn service_snippet_trust_title(&self) -> &'static str {
        self.strings().service_snippet_trust_title
    }

    pub(crate) fn service_snippet_domain_hint(&self, value: &str) -> String {
        format_template(
            self.strings().service_snippet_domain_hint,
            &[("value", value)],
        )
    }

    pub(crate) fn error_service_update_failed(&self) -> &'static str {
        self.strings().error_service_update_failed
    }

    pub(crate) fn error_service_update_no_flags(&self) -> &'static str {
        self.strings().error_service_update_no_flags
    }

    pub(crate) fn service_update_summary(&self) -> &'static str {
        self.strings().service_update_summary
    }

    pub(crate) fn service_update_field_changed(&self, field: &str, old: &str, new: &str) -> String {
        format_template(
            self.strings().service_update_field_changed,
            &[("field", field), ("old", old), ("new", new)],
        )
    }

    pub(crate) fn service_update_rotate_hint(&self) -> &'static str {
        self.strings().service_update_rotate_hint
    }

    pub(crate) fn hint_secret_id_ttl_rotation_cadence(&self) -> &'static str {
        self.strings().hint_secret_id_ttl_rotation_cadence
    }

    pub(crate) fn service_info_secret_id_ttl(&self, value: &str) -> String {
        format_template(
            self.strings().service_info_secret_id_ttl,
            &[("value", value)],
        )
    }

    pub(crate) fn service_info_secret_id_wrap_ttl(&self, value: &str) -> String {
        format_template(
            self.strings().service_info_secret_id_wrap_ttl,
            &[("value", value)],
        )
    }

    pub(crate) fn service_info_token_bound_cidrs(&self, value: &str) -> String {
        format_template(
            self.strings().service_info_token_bound_cidrs,
            &[("value", value)],
        )
    }

    pub(crate) fn policy_label_inherit(&self) -> &'static str {
        self.strings().policy_label_inherit
    }

    pub(crate) fn policy_label_disabled(&self) -> &'static str {
        self.strings().policy_label_disabled
    }

    pub(crate) fn policy_label_default_wrap_ttl(&self, value: &str) -> String {
        format_template(
            self.strings().policy_label_default_wrap_ttl,
            &[("value", value)],
        )
    }

    pub(crate) fn service_update_no_changes(&self) -> &'static str {
        self.strings().service_update_no_changes
    }

    pub(crate) fn error_service_openbao_sidecar_start_failed(&self) -> &'static str {
        self.strings().error_service_openbao_sidecar_start_failed
    }

    pub(crate) fn error_service_openbao_sidecar_refresh_failed(&self) -> &'static str {
        self.strings().error_service_openbao_sidecar_refresh_failed
    }

    pub(crate) fn warn_service_agent_alias_deprecated(&self) -> &'static str {
        self.strings().warn_service_agent_alias_deprecated
    }

    pub(crate) fn error_service_remote_bootstrap(&self, value: &str) -> String {
        format_template(
            self.strings().error_service_remote_bootstrap,
            &[("value", value)],
        )
    }

    pub(crate) fn error_service_agent_config_missing(&self, value: &str) -> String {
        format_template(
            self.strings().error_service_agent_config_missing,
            &[("value", value)],
        )
    }

    pub(crate) fn service_openbao_sidecar_start_completed(&self, value: &str) -> String {
        format_template(
            self.strings().service_openbao_sidecar_start_completed,
            &[("value", value)],
        )
    }

    pub(crate) fn error_openbao_container_not_found(&self) -> &'static str {
        self.strings().error_openbao_container_not_found
    }

    pub(crate) fn error_openbao_container_no_project_label(&self) -> &'static str {
        self.strings().error_openbao_container_no_project_label
    }

    pub(crate) fn error_openbao_network_required_external(&self) -> &'static str {
        self.strings().error_openbao_network_required_external
    }

    pub(crate) fn error_invalid_docker_network_name(&self, value: &str) -> String {
        format_template(
            self.strings().error_invalid_docker_network_name,
            &[("value", value)],
        )
    }
}
