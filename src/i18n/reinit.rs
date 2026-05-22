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

    pub(crate) fn reinit_plan_destructive_runtime_files(&self) -> &'static str {
        self.strings().reinit_plan_destructive_runtime_files
    }

    pub(crate) fn reinit_plan_destructive_service_creds(&self) -> &'static str {
        self.strings().reinit_plan_destructive_service_creds
    }

    pub(crate) fn reinit_plan_preserved_actions(&self) -> &'static str {
        self.strings().reinit_plan_preserved_actions
    }

    pub(crate) fn reinit_plan_preserved_ca(&self) -> &'static str {
        self.strings().reinit_plan_preserved_ca
    }

    pub(crate) fn reinit_plan_preserved_password(&self) -> &'static str {
        self.strings().reinit_plan_preserved_password
    }

    pub(crate) fn reinit_plan_preserved_postgres(&self) -> &'static str {
        self.strings().reinit_plan_preserved_postgres
    }

    pub(crate) fn reinit_plan_preserved_compose_overrides(&self) -> &'static str {
        self.strings().reinit_plan_preserved_compose_overrides
    }

    pub(crate) fn reinit_plan_preserved_intent(&self) -> &'static str {
        self.strings().reinit_plan_preserved_intent
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
}
