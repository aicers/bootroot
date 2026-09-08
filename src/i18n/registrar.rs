use super::{Messages, format_template};

impl Messages {
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

    pub(crate) fn registrar_issue_complete(&self, identity: &str, not_after: &str) -> String {
        format_template(
            self.strings().registrar_issue_complete,
            &[("identity", identity), ("not_after", not_after)],
        )
    }
}
