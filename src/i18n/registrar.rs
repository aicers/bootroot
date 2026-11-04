use super::{Messages, format_template};

impl Messages {
    pub(crate) fn error_registrar_issue_scratch_dir_failed(&self, path: &str) -> String {
        format_template(
            self.strings().error_registrar_issue_scratch_dir_failed,
            &[("path", path)],
        )
    }

    pub(crate) fn registrar_capabilities_summary(
        &self,
        api_version: &str,
        socket_path: &str,
        verbs: &str,
    ) -> String {
        format_template(
            self.strings().registrar_capabilities_summary,
            &[
                ("api_version", api_version),
                ("socket_path", socket_path),
                ("verbs", verbs),
            ],
        )
    }

    pub(crate) fn registrar_issue_complete(
        &self,
        api_version: &str,
        identity: &str,
        not_after: &str,
    ) -> String {
        format_template(
            self.strings().registrar_issue_complete,
            &[
                ("api_version", api_version),
                ("identity", identity),
                ("not_after", not_after),
            ],
        )
    }
}
