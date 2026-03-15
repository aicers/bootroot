use super::{Messages, format_template};

impl Messages {
    pub(crate) fn rotate_summary_title(&self) -> &'static str {
        self.strings().rotate_summary_title
    }

    pub(crate) fn rotate_summary_stepca_password(&self, value: &str) -> String {
        format_template(
            self.strings().rotate_summary_stepca_password,
            &[("value", value)],
        )
    }

    pub(crate) fn rotate_summary_restart_stepca(&self) -> &'static str {
        self.strings().rotate_summary_restart_stepca
    }

    pub(crate) fn rotate_summary_db_dsn(&self, value: &str) -> String {
        format_template(self.strings().rotate_summary_db_dsn, &[("value", value)])
    }

    pub(crate) fn rotate_summary_responder_config(&self, value: &str) -> String {
        format_template(
            self.strings().rotate_summary_responder_config,
            &[("value", value)],
        )
    }

    pub(crate) fn rotate_summary_reload_responder(&self) -> &'static str {
        self.strings().rotate_summary_reload_responder
    }

    pub(crate) fn rotate_summary_approle_secret_id(
        &self,
        service_name: &str,
        value: &str,
    ) -> String {
        format_template(
            self.strings().rotate_summary_approle_secret_id,
            &[("service_name", service_name), ("value", value)],
        )
    }

    pub(crate) fn rotate_summary_reload_openbao_agent(&self) -> &'static str {
        self.strings().rotate_summary_reload_openbao_agent
    }

    pub(crate) fn rotate_summary_approle_login_ok(&self, service_name: &str) -> String {
        format_template(
            self.strings().rotate_summary_approle_login_ok,
            &[("service_name", service_name)],
        )
    }

    pub(crate) fn rotate_summary_openbao_recovery_targets(&self, value: &str) -> String {
        format_template(
            self.strings().rotate_summary_openbao_recovery_targets,
            &[("value", value)],
        )
    }

    pub(crate) fn rotate_summary_openbao_recovery_output(&self, value: &str) -> String {
        format_template(
            self.strings().rotate_summary_openbao_recovery_output,
            &[("value", value)],
        )
    }

    pub(crate) fn rotate_summary_openbao_recovery_approle_unchanged(&self) -> &'static str {
        self.strings()
            .rotate_summary_openbao_recovery_approle_unchanged
    }

    pub(crate) fn rotate_summary_openbao_recovery_next_steps(&self) -> &'static str {
        self.strings().rotate_summary_openbao_recovery_next_steps
    }

    pub(crate) fn prompt_rotate_openbao_recovery(&self, value: &str) -> String {
        format_template(
            self.strings().prompt_rotate_openbao_recovery,
            &[("value", value)],
        )
    }

    pub(crate) fn error_openbao_recovery_target_required(&self) -> &'static str {
        self.strings().error_openbao_recovery_target_required
    }

    pub(crate) fn error_openbao_recovery_unseal_keys_required(&self, value: &str) -> String {
        format_template(
            self.strings().error_openbao_recovery_unseal_keys_required,
            &[("value", value)],
        )
    }

    pub(crate) fn prompt_rotate_trust_sync(&self) -> &'static str {
        self.strings().prompt_rotate_trust_sync
    }

    pub(crate) fn prompt_rotate_force_reissue(&self, service_name: &str) -> String {
        format_template(
            self.strings().prompt_rotate_force_reissue,
            &[("service_name", service_name)],
        )
    }

    pub(crate) fn rotate_summary_trust_sync_global(&self, value: &str) -> String {
        format_template(
            self.strings().rotate_summary_trust_sync_global,
            &[("value", value)],
        )
    }

    pub(crate) fn rotate_summary_trust_sync_service(&self, value: &str) -> String {
        format_template(
            self.strings().rotate_summary_trust_sync_service,
            &[("value", value)],
        )
    }

    pub(crate) fn rotate_summary_force_reissue_deleted(
        &self,
        service_name: &str,
        cert_path: &str,
        key_path: &str,
    ) -> String {
        format_template(
            self.strings().rotate_summary_force_reissue_deleted,
            &[
                ("service_name", service_name),
                ("cert_path", cert_path),
                ("key_path", key_path),
            ],
        )
    }

    pub(crate) fn rotate_summary_force_reissue_local_signal(&self, service_name: &str) -> String {
        format_template(
            self.strings().rotate_summary_force_reissue_local_signal,
            &[("service_name", service_name)],
        )
    }

    pub(crate) fn rotate_summary_force_reissue_remote_hint(&self, service_name: &str) -> String {
        format_template(
            self.strings().rotate_summary_force_reissue_remote_hint,
            &[("service_name", service_name)],
        )
    }

    pub(crate) fn warning_rotation_in_progress(&self) -> &'static str {
        self.strings().warning_rotation_in_progress
    }

    pub(crate) fn error_trust_sync_blocked_by_rotation(&self) -> &'static str {
        self.strings().error_trust_sync_blocked_by_rotation
    }

    pub(crate) fn prompt_rotate_ca_key(&self, root_fp: &str, inter_fp: &str) -> String {
        format_template(
            self.strings().prompt_rotate_ca_key,
            &[("root_fp", root_fp), ("inter_fp", inter_fp)],
        )
    }

    pub(crate) fn prompt_rotate_ca_key_full(&self, root_fp: &str, inter_fp: &str) -> String {
        format_template(
            self.strings().prompt_rotate_ca_key_full,
            &[("root_fp", root_fp), ("inter_fp", inter_fp)],
        )
    }

    pub(crate) fn rotate_ca_key_full_checklist(&self) -> &'static str {
        self.strings().rotate_ca_key_full_checklist
    }

    pub(crate) fn error_rotation_mode_mismatch(&self, mode: &str) -> String {
        format_template(
            self.strings().error_rotation_mode_mismatch,
            &[("mode", mode)],
        )
    }

    pub(crate) fn error_rotation_state_corrupt(&self, path: &str) -> String {
        format_template(
            self.strings().error_rotation_state_corrupt,
            &[("path", path)],
        )
    }

    pub(crate) fn error_parse_cert_failed(&self, path: &str, reason: &str) -> String {
        format_template(
            self.strings().error_parse_cert_failed,
            &[("path", path), ("reason", reason)],
        )
    }

    pub(crate) fn warning_stale_backup(&self) -> &'static str {
        self.strings().warning_stale_backup
    }

    pub(crate) fn rotate_ca_key_resuming(&self, phase: &str) -> String {
        format_template(self.strings().rotate_ca_key_resuming, &[("phase", phase)])
    }

    pub(crate) fn rotate_ca_key_phase_backup(&self) -> &'static str {
        self.strings().rotate_ca_key_phase_backup
    }

    pub(crate) fn rotate_ca_key_phase_generate(&self) -> &'static str {
        self.strings().rotate_ca_key_phase_generate
    }

    pub(crate) fn rotate_ca_key_phase_trust_additive(&self) -> &'static str {
        self.strings().rotate_ca_key_phase_trust_additive
    }

    pub(crate) fn rotate_ca_key_phase_restart_stepca(&self) -> &'static str {
        self.strings().rotate_ca_key_phase_restart_stepca
    }

    pub(crate) fn rotate_ca_key_phase_reissue(&self) -> &'static str {
        self.strings().rotate_ca_key_phase_reissue
    }

    pub(crate) fn rotate_ca_key_phase_finalize(&self) -> &'static str {
        self.strings().rotate_ca_key_phase_finalize
    }

    pub(crate) fn rotate_ca_key_phase_cleanup(&self) -> &'static str {
        self.strings().rotate_ca_key_phase_cleanup
    }

    pub(crate) fn rotate_ca_key_skip_migrated(&self, service_name: &str) -> String {
        format_template(
            self.strings().rotate_ca_key_skip_migrated,
            &[("service_name", service_name)],
        )
    }

    pub(crate) fn rotate_ca_key_reissue_remote_hint(&self, service_name: &str) -> String {
        format_template(
            self.strings().rotate_ca_key_reissue_remote_hint,
            &[("service_name", service_name)],
        )
    }

    pub(crate) fn rotate_ca_key_finalize_blocked(&self, services: &str) -> String {
        format_template(
            self.strings().rotate_ca_key_finalize_blocked,
            &[("services", services)],
        )
    }

    pub(crate) fn warning_force_finalize(&self) -> &'static str {
        self.strings().warning_force_finalize
    }

    pub(crate) fn warning_force_finalize_full(&self, services: &str) -> String {
        format_template(
            self.strings().warning_force_finalize_full,
            &[("services", services)],
        )
    }

    pub(crate) fn rotate_ca_key_complete(&self, old_fp: &str, new_fp: &str) -> String {
        format_template(
            self.strings().rotate_ca_key_complete,
            &[("old_fp", old_fp), ("new_fp", new_fp)],
        )
    }

    pub(crate) fn rotate_ca_key_complete_full(
        &self,
        old_root_fp: &str,
        new_root_fp: &str,
        old_inter_fp: &str,
        new_inter_fp: &str,
    ) -> String {
        format_template(
            self.strings().rotate_ca_key_complete_full,
            &[
                ("old_root_fp", old_root_fp),
                ("new_root_fp", new_root_fp),
                ("old_inter_fp", old_inter_fp),
                ("new_inter_fp", new_inter_fp),
            ],
        )
    }

    pub(crate) fn rotate_ca_key_phase_generate_root(&self) -> &'static str {
        self.strings().rotate_ca_key_phase_generate_root
    }

    pub(crate) fn rotate_ca_key_current_fingerprints(
        &self,
        root_fp: &str,
        inter_fp: &str,
    ) -> String {
        format_template(
            self.strings().rotate_ca_key_current_fingerprints,
            &[("root_fp", root_fp), ("inter_fp", inter_fp)],
        )
    }

    pub(crate) fn rotate_ca_key_phase_skipped(&self, phase: &str) -> String {
        format_template(
            self.strings().rotate_ca_key_phase_skipped,
            &[("phase", phase)],
        )
    }
}
