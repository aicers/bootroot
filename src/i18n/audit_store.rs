use super::{Messages, format_template};

impl Messages {
    pub(crate) fn error_audit_store_agent_config_required(&self) -> &'static str {
        self.strings().error_audit_store_agent_config_required
    }

    pub(crate) fn error_audit_store_agent_config_unreadable(
        &self,
        path: &str,
        reason: &str,
    ) -> String {
        format_template(
            self.strings().error_audit_store_agent_config_unreadable,
            &[("path", path), ("reason", reason)],
        )
    }

    pub(crate) fn error_audit_store_agent_config_malformed(
        &self,
        path: &str,
        reason: &str,
    ) -> String {
        format_template(
            self.strings().error_audit_store_agent_config_malformed,
            &[("path", path), ("reason", reason)],
        )
    }

    pub(crate) fn error_audit_store_agent_config_undeserializable(
        &self,
        path: &str,
        reason: &str,
    ) -> String {
        format_template(
            self.strings()
                .error_audit_store_agent_config_undeserializable,
            &[("path", path), ("reason", reason)],
        )
    }

    pub(crate) fn error_audit_store_agent_config_rejected(
        &self,
        path: &str,
        reason: &str,
    ) -> String {
        format_template(
            self.strings().error_audit_store_agent_config_rejected,
            &[("path", path), ("reason", reason)],
        )
    }

    pub(crate) fn error_audit_store_enablement_mismatch(
        &self,
        state_path: &str,
        state_value: bool,
        config_path: &str,
        config_value: bool,
    ) -> String {
        format_template(
            self.strings().error_audit_store_enablement_mismatch,
            &[
                ("state_path", state_path),
                ("state_value", if state_value { "true" } else { "false" }),
                ("config_path", config_path),
                ("config_value", if config_value { "true" } else { "false" }),
            ],
        )
    }

    pub(crate) fn error_audit_store_not_privileged(
        &self,
        path: &str,
        expected_uid: u32,
        found_uid: u32,
    ) -> String {
        format_template(
            self.strings().error_audit_store_not_privileged,
            &[
                ("path", path),
                ("expected_uid", &expected_uid.to_string()),
                ("found_uid", &found_uid.to_string()),
            ],
        )
    }

    pub(crate) fn error_audit_store_override_stale(
        &self,
        rendered: &str,
        configured: &str,
    ) -> String {
        format_template(
            self.strings().error_audit_store_override_stale,
            &[("rendered", rendered), ("configured", configured)],
        )
    }

    pub(crate) fn error_audit_store_override_unreadable(&self, path: &str) -> String {
        format_template(
            self.strings().error_audit_store_override_unreadable,
            &[("path", path)],
        )
    }

    pub(crate) fn error_audit_store_override_missing(&self) -> &'static str {
        self.strings().error_audit_store_override_missing
    }

    pub(crate) fn error_audit_store_dir_invalid(
        &self,
        path: &str,
        found: &str,
        expected_uid: u32,
        expected_mode: u32,
    ) -> String {
        format_template(
            self.strings().error_audit_store_dir_invalid,
            &[
                ("path", path),
                ("found", found),
                ("expected_uid", &expected_uid.to_string()),
                ("expected_mode", &format!("{expected_mode:04o}")),
            ],
        )
    }

    pub(crate) fn error_audit_store_dir_unusable(
        &self,
        path: &str,
        found: &str,
        expected_uid: u32,
        expected_mode: u32,
    ) -> String {
        format_template(
            self.strings().error_audit_store_dir_unusable,
            &[
                ("path", path),
                ("found", found),
                ("expected_uid", &expected_uid.to_string()),
                ("expected_mode", &format!("{expected_mode:04o}")),
            ],
        )
    }

    pub(crate) fn error_audit_store_ancestor_invalid(&self, path: &str, found: &str) -> String {
        format_template(
            self.strings().error_audit_store_ancestor_invalid,
            &[("path", path), ("found", found)],
        )
    }

    pub(crate) fn error_audit_store_openbao_invalid(&self, path: &str, found: &str) -> String {
        format_template(
            self.strings().error_audit_store_openbao_invalid,
            &[("path", path), ("found", found)],
        )
    }

    pub(crate) fn error_audit_store_layout_failed(&self, path: &str, reason: &str) -> String {
        format_template(
            self.strings().error_audit_store_layout_failed,
            &[("path", path), ("reason", reason)],
        )
    }

    pub(crate) fn error_audit_store_dir_unrenderable(&self, path: &str) -> String {
        format_template(
            self.strings().error_audit_store_dir_unrenderable,
            &[("path", path)],
        )
    }

    /// Renders one [`bootroot::registrar::audit_store::PathFault`] as
    /// the `{found}` fragment the store-directory, ancestor and
    /// `OpenBao` messages interpolate.
    pub(crate) fn audit_store_fault(
        &self,
        fault: bootroot::registrar::audit_store::PathFault,
    ) -> String {
        use bootroot::registrar::audit_store::PathFault;
        match fault {
            PathFault::Symlink => self.strings().audit_store_fault_symlink.to_string(),
            PathFault::NotDirectory => self.strings().audit_store_fault_not_directory.to_string(),
            PathFault::NotTraversable { mode } => format_template(
                self.strings().audit_store_fault_not_traversable,
                &[("mode", &format!("{mode:04o}"))],
            ),
            PathFault::Owner { found, expected } => format_template(
                self.strings().audit_store_fault_owner,
                &[
                    ("found", &found.to_string()),
                    ("expected", &expected.to_string()),
                ],
            ),
            PathFault::Mode { found, expected } => format_template(
                self.strings().audit_store_fault_mode,
                &[
                    ("found", &format!("{found:04o}")),
                    ("expected", &format!("{expected:04o}")),
                ],
            ),
        }
    }
}
