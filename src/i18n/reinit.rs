use super::{Messages, format_template};

impl Messages {
    pub(crate) fn reinit_plan_title(&self) -> &'static str {
        self.strings().reinit_plan_title
    }

    pub(crate) fn reinit_plan_destructive_actions(&self) -> &'static str {
        self.strings().reinit_plan_destructive_actions
    }

    pub(crate) fn reinit_plan_destructive_container(&self) -> &'static str {
        self.strings().reinit_plan_destructive_container
    }

    pub(crate) fn reinit_plan_destructive_volumes(&self) -> &'static str {
        self.strings().reinit_plan_destructive_volumes
    }

    pub(crate) fn reinit_plan_destructive_state_file(&self) -> &'static str {
        self.strings().reinit_plan_destructive_state_file
    }

    pub(crate) fn reinit_plan_destructive_runtime_files(&self, secrets_dir: &str) -> String {
        format_template(
            self.strings().reinit_plan_destructive_runtime_files,
            &[("secrets_dir", secrets_dir)],
        )
    }

    pub(crate) fn reinit_plan_destructive_service_creds(&self, secrets_dir: &str) -> String {
        format_template(
            self.strings().reinit_plan_destructive_service_creds,
            &[("secrets_dir", secrets_dir)],
        )
    }

    pub(crate) fn reinit_plan_preserved_actions(&self) -> &'static str {
        self.strings().reinit_plan_preserved_actions
    }

    pub(crate) fn reinit_plan_preserved_ca(&self, secrets_dir: &str) -> String {
        format_template(
            self.strings().reinit_plan_preserved_ca,
            &[("secrets_dir", secrets_dir)],
        )
    }

    pub(crate) fn reinit_plan_preserved_password(&self, secrets_dir: &str) -> String {
        format_template(
            self.strings().reinit_plan_preserved_password,
            &[("secrets_dir", secrets_dir)],
        )
    }

    pub(crate) fn reinit_plan_preserved_postgres(&self) -> &'static str {
        self.strings().reinit_plan_preserved_postgres
    }

    pub(crate) fn reinit_plan_preserved_compose_overrides(&self, secrets_dir: &str) -> String {
        format_template(
            self.strings().reinit_plan_preserved_compose_overrides,
            &[("secrets_dir", secrets_dir)],
        )
    }

    pub(crate) fn reinit_plan_preserved_intent(&self) -> &'static str {
        self.strings().reinit_plan_preserved_intent
    }

    pub(crate) fn reinit_plan_preserved_intent_section(&self) -> &'static str {
        self.strings().reinit_plan_preserved_intent_section
    }

    pub(crate) fn reinit_plan_preserved_intent_secrets_dir(&self, value: &str) -> String {
        format_template(
            self.strings().reinit_plan_preserved_intent_secrets_dir,
            &[("value", value)],
        )
    }

    pub(crate) fn reinit_plan_preserved_intent_openbao_bind(&self, value: &str) -> String {
        format_template(
            self.strings().reinit_plan_preserved_intent_openbao_bind,
            &[("value", value)],
        )
    }

    pub(crate) fn reinit_plan_preserved_intent_openbao_advertise(&self, value: &str) -> String {
        format_template(
            self.strings()
                .reinit_plan_preserved_intent_openbao_advertise,
            &[("value", value)],
        )
    }

    pub(crate) fn reinit_plan_preserved_intent_http01_bind(&self, value: &str) -> String {
        format_template(
            self.strings().reinit_plan_preserved_intent_http01_bind,
            &[("value", value)],
        )
    }

    pub(crate) fn reinit_plan_preserved_intent_http01_advertise(&self, value: &str) -> String {
        format_template(
            self.strings().reinit_plan_preserved_intent_http01_advertise,
            &[("value", value)],
        )
    }

    pub(crate) fn reinit_plan_preserved_intent_infra_certs(&self, count: usize) -> String {
        format_template(
            self.strings().reinit_plan_preserved_intent_infra_certs,
            &[("count", &count.to_string())],
        )
    }

    pub(crate) fn reinit_plan_preserved_intent_none(&self) -> &'static str {
        self.strings().reinit_plan_preserved_intent_none
    }

    pub(crate) fn reinit_plan_service_registry_warning(&self) -> &'static str {
        self.strings().reinit_plan_service_registry_warning
    }

    pub(crate) fn reinit_confirm(&self) -> &'static str {
        self.strings().reinit_confirm
    }

    pub(crate) fn reinit_completed(&self) -> &'static str {
        self.strings().reinit_completed
    }

    pub(crate) fn reinit_service_registry_post_summary(&self) -> &'static str {
        self.strings().reinit_service_registry_post_summary
    }

    pub(crate) fn error_reinit_failed(&self) -> &'static str {
        self.strings().error_reinit_failed
    }

    pub(crate) fn error_reinit_external_openbao(&self, path: &str) -> String {
        format_template(
            self.strings().error_reinit_external_openbao,
            &[("path", path)],
        )
    }

    pub(crate) fn error_reinit_container_project_mismatch(
        &self,
        actual: &str,
        expected: &str,
    ) -> String {
        format_template(
            self.strings().error_reinit_container_project_mismatch,
            &[("actual", actual), ("expected", expected)],
        )
    }

    pub(crate) fn error_reinit_root_token_output_unsafe(&self, path: &str) -> String {
        format_template(
            self.strings().error_reinit_root_token_output_unsafe,
            &[("path", path)],
        )
    }

    pub(crate) fn error_reinit_root_token_output_not_file(&self, path: &str) -> String {
        format_template(
            self.strings().error_reinit_root_token_output_not_file,
            &[("path", path)],
        )
    }

    pub(crate) fn error_reinit_root_token_output_unwritable(
        &self,
        path: &str,
        reason: &str,
    ) -> String {
        format_template(
            self.strings().error_reinit_root_token_output_unwritable,
            &[("path", path), ("reason", reason)],
        )
    }

    pub(crate) fn error_reinit_root_token_persist_failed(
        &self,
        path: &str,
        reason: &str,
        token: &str,
    ) -> String {
        format_template(
            self.strings().error_reinit_root_token_persist_failed,
            &[("path", path), ("reason", reason), ("token", token)],
        )
    }

    pub(crate) fn error_reinit_summary_json_not_file(&self, path: &str) -> String {
        format_template(
            self.strings().error_reinit_summary_json_not_file,
            &[("path", path)],
        )
    }

    pub(crate) fn error_reinit_summary_json_unwritable(&self, path: &str, reason: &str) -> String {
        format_template(
            self.strings().error_reinit_summary_json_unwritable,
            &[("path", path), ("reason", reason)],
        )
    }

    pub(crate) fn error_reinit_explicit_openbao_url(&self, url: &str) -> String {
        format_template(
            self.strings().error_reinit_explicit_openbao_url,
            &[("url", url)],
        )
    }
}
