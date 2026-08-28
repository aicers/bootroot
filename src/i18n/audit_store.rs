use super::{Messages, format_template};

impl Messages {
    pub(crate) fn error_audit_store_agent_config_required(&self, command: &str) -> String {
        format_template(
            self.strings().error_audit_store_agent_config_required,
            &[("command", command)],
        )
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

    pub(crate) fn error_audit_reserve_store_path_unrenderable(
        &self,
        path: &str,
        fault: &str,
    ) -> String {
        format_template(
            self.strings().error_audit_reserve_store_path_unrenderable,
            &[("path", path), ("fault", fault)],
        )
    }

    pub(crate) fn audit_reserve_path_fault_line_break(&self) -> &'static str {
        self.strings().audit_reserve_path_fault_line_break
    }

    pub(crate) fn audit_reserve_path_fault_edge_whitespace(&self) -> &'static str {
        self.strings().audit_reserve_path_fault_edge_whitespace
    }

    pub(crate) fn audit_reserve_path_fault_final_backslash(&self) -> &'static str {
        self.strings().audit_reserve_path_fault_final_backslash
    }

    pub(crate) fn error_audit_reserve_image_parentless(&self, path: &str) -> String {
        format_template(
            self.strings().error_audit_reserve_image_parentless,
            &[("path", path)],
        )
    }

    pub(crate) fn error_audit_reserve_staging_inside_store(
        &self,
        staging: &str,
        store: &str,
    ) -> String {
        format_template(
            self.strings().error_audit_reserve_staging_inside_store,
            &[("staging", staging), ("store", store)],
        )
    }

    pub(crate) fn error_audit_reserve_below_minimum(
        &self,
        path: &str,
        configured: u64,
        minimum: u64,
        floor: u64,
        records: u64,
    ) -> String {
        format_template(
            self.strings().error_audit_reserve_below_minimum,
            &[
                ("path", path),
                ("configured", &configured.to_string()),
                ("minimum", &minimum.to_string()),
                ("floor", &floor.to_string()),
                ("records", &records.to_string()),
            ],
        )
    }

    pub(crate) fn error_audit_reserve_minimum_unreachable(
        &self,
        path: &str,
        max_file_bytes: u64,
        max_retained_files: u32,
    ) -> String {
        format_template(
            self.strings().error_audit_reserve_minimum_unreachable,
            &[
                ("path", path),
                ("max_file_bytes", &max_file_bytes.to_string()),
                ("max_retained_files", &max_retained_files.to_string()),
            ],
        )
    }

    pub(crate) fn error_audit_reserve_image_not_regular(&self, path: &str, found: &str) -> String {
        format_template(
            self.strings().error_audit_reserve_image_not_regular,
            &[("path", path), ("found", found)],
        )
    }

    pub(crate) fn error_audit_reserve_image_size_mismatch(
        &self,
        path: &str,
        found: u64,
        expected: u64,
    ) -> String {
        format_template(
            self.strings().error_audit_reserve_image_size_mismatch,
            &[
                ("path", path),
                ("found", &found.to_string()),
                ("expected", &expected.to_string()),
            ],
        )
    }

    pub(crate) fn error_audit_reserve_free_space(
        &self,
        path: &str,
        outstanding: u64,
        available: u64,
        reserve: u64,
    ) -> String {
        format_template(
            self.strings().error_audit_reserve_free_space,
            &[
                ("path", path),
                ("outstanding", &outstanding.to_string()),
                ("available", &available.to_string()),
                ("reserve", &reserve.to_string()),
            ],
        )
    }

    pub(crate) fn error_audit_reserve_underlying_too_large(
        &self,
        path: &str,
        used: u64,
        reserve: u64,
    ) -> String {
        format_template(
            self.strings().error_audit_reserve_underlying_too_large,
            &[
                ("path", path),
                ("used", &used.to_string()),
                ("reserve", &reserve.to_string()),
            ],
        )
    }

    pub(crate) fn error_audit_reserve_arithmetic(&self, figure: &str) -> String {
        format_template(
            self.strings().error_audit_reserve_arithmetic,
            &[("figure", figure)],
        )
    }

    pub(crate) fn error_audit_reserve_unreadable(&self, path: &str, reason: &str) -> String {
        format_template(
            self.strings().error_audit_reserve_unreadable,
            &[("path", path), ("reason", reason)],
        )
    }

    pub(crate) fn audit_reserve_figure_allocated(&self, path: &str) -> String {
        format_template(
            self.strings().audit_reserve_figure_allocated,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_figure_underlying(&self, path: &str) -> String {
        format_template(
            self.strings().audit_reserve_figure_underlying,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_figure_available(&self, path: &str) -> String {
        format_template(
            self.strings().audit_reserve_figure_available,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_kind_regular(&self) -> &'static str {
        self.strings().audit_reserve_kind_regular
    }

    pub(crate) fn audit_reserve_kind_directory(&self) -> &'static str {
        self.strings().audit_reserve_kind_directory
    }

    pub(crate) fn audit_reserve_kind_symlink(&self) -> &'static str {
        self.strings().audit_reserve_kind_symlink
    }

    pub(crate) fn audit_reserve_kind_other(&self) -> &'static str {
        self.strings().audit_reserve_kind_other
    }

    pub(crate) fn audit_reserve_mount_description(&self, fs_type: &str, source: &str) -> String {
        format_template(
            self.strings().audit_reserve_mount_description,
            &[("fs_type", fs_type), ("source", source)],
        )
    }

    pub(crate) fn audit_reserve_outcome_directory(&self, store: &str, reserve: u64) -> String {
        format_template(
            self.strings().audit_reserve_outcome_directory,
            &[("store", store), ("reserve", &reserve.to_string())],
        )
    }

    pub(crate) fn audit_reserve_outcome_enforced(
        &self,
        image: &str,
        size: u64,
        unit: &str,
        store: &str,
    ) -> String {
        format_template(
            self.strings().audit_reserve_outcome_enforced,
            &[
                ("image", image),
                ("size", &size.to_string()),
                ("unit", unit),
                ("store", store),
            ],
        )
    }

    pub(crate) fn audit_reserve_outcome_not_activated(&self, store: &str) -> String {
        format_template(
            self.strings().audit_reserve_outcome_not_activated,
            &[("store", store)],
        )
    }

    pub(crate) fn audit_reserve_openbao_owner_caveat(&self) -> &'static str {
        self.strings().audit_reserve_openbao_owner_caveat
    }

    pub(crate) fn audit_reserve_outstanding_header(&self) -> &'static str {
        self.strings().audit_reserve_outstanding_header
    }

    pub(crate) fn audit_reserve_artifacts_header(&self) -> &'static str {
        self.strings().audit_reserve_artifacts_header
    }

    pub(crate) fn audit_reserve_steps_header(&self) -> &'static str {
        self.strings().audit_reserve_steps_header
    }

    pub(crate) fn audit_reserve_no_steps(&self) -> &'static str {
        self.strings().audit_reserve_no_steps
    }

    pub(crate) fn audit_reserve_no_steps_unremediable(&self, command: &str) -> String {
        format_template(
            self.strings().audit_reserve_no_steps_unremediable,
            &[("command", command)],
        )
    }

    pub(crate) fn audit_reserve_note_stacked(&self, store: &str) -> String {
        format_template(
            self.strings().audit_reserve_note_stacked,
            &[("store", store)],
        )
    }

    pub(crate) fn audit_reserve_finding_store_not_empty(
        &self,
        store: &str,
        holding: &str,
    ) -> String {
        format_template(
            self.strings().audit_reserve_finding_store_not_empty,
            &[("store", store), ("holding", holding)],
        )
    }

    pub(crate) fn audit_reserve_finding_image_absent(&self, path: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_image_absent,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_finding_image_sparse(
        &self,
        path: &str,
        missing: u64,
        size: u64,
    ) -> String {
        format_template(
            self.strings().audit_reserve_finding_image_sparse,
            &[
                ("path", path),
                ("missing", &missing.to_string()),
                ("size", &size.to_string()),
            ],
        )
    }

    pub(crate) fn audit_reserve_finding_image_owner(
        &self,
        path: &str,
        found: u32,
        expected: u32,
    ) -> String {
        format_template(
            self.strings().audit_reserve_finding_image_owner,
            &[
                ("path", path),
                ("found", &found.to_string()),
                ("expected", &expected.to_string()),
            ],
        )
    }

    pub(crate) fn audit_reserve_finding_image_mode(
        &self,
        path: &str,
        found: u32,
        expected: u32,
    ) -> String {
        format_template(
            self.strings().audit_reserve_finding_image_mode,
            &[
                ("path", path),
                ("found", &format!("{found:04o}")),
                ("expected", &format!("{expected:04o}")),
            ],
        )
    }

    pub(crate) fn audit_reserve_finding_artifact_absent(&self, path: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_artifact_absent,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_finding_artifact_differs(&self, path: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_artifact_differs,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_finding_mount_absent(&self, store: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_mount_absent,
            &[("store", store)],
        )
    }

    pub(crate) fn audit_reserve_finding_mount_foreign(&self, store: &str, found: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_mount_foreign,
            &[("store", store), ("found", found)],
        )
    }

    pub(crate) fn audit_reserve_finding_subdir_absent(&self, path: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_subdir_absent,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_finding_subdir_invalid(&self, path: &str, found: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_subdir_invalid,
            &[("path", path), ("found", found)],
        )
    }

    pub(crate) fn audit_reserve_step_stop_writers(&self) -> &'static str {
        self.strings().audit_reserve_step_stop_writers
    }

    pub(crate) fn audit_reserve_step_image(&self) -> &'static str {
        self.strings().audit_reserve_step_image
    }

    pub(crate) fn audit_reserve_step_install(&self) -> &'static str {
        self.strings().audit_reserve_step_install
    }

    pub(crate) fn audit_reserve_step_subdirectories(&self) -> &'static str {
        self.strings().audit_reserve_step_subdirectories
    }

    pub(crate) fn audit_reserve_outcome_migration_incomplete(&self, store: &str) -> String {
        format_template(
            self.strings().audit_reserve_outcome_migration_incomplete,
            &[("store", store)],
        )
    }

    pub(crate) fn audit_reserve_directory_migration_open(
        &self,
        holding: &str,
        store: &str,
    ) -> String {
        format_template(
            self.strings().audit_reserve_directory_migration_open,
            &[("holding", holding), ("store", store)],
        )
    }

    pub(crate) fn audit_reserve_finding_migration_holding(
        &self,
        holding: &str,
        store: &str,
    ) -> String {
        format_template(
            self.strings().audit_reserve_finding_migration_holding,
            &[("holding", holding), ("store", store)],
        )
    }

    pub(crate) fn audit_reserve_finding_migration_store_not_empty(
        &self,
        store: &str,
        holding: &str,
    ) -> String {
        format_template(
            self.strings()
                .audit_reserve_finding_migration_store_not_empty,
            &[("store", store), ("holding", holding)],
        )
    }

    pub(crate) fn audit_reserve_finding_migration_path_exists(&self, path: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_migration_path_exists,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_finding_migration_mount_absent(&self) -> String {
        self.strings()
            .audit_reserve_finding_migration_mount_absent
            .to_string()
    }

    pub(crate) fn audit_reserve_finding_migration_mount_point(&self, path: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_migration_mount_point,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_finding_migration_holding_kind(
        &self,
        path: &str,
        found: &str,
    ) -> String {
        format_template(
            self.strings().audit_reserve_finding_migration_holding_kind,
            &[("path", path), ("found", found)],
        )
    }

    pub(crate) fn audit_reserve_finding_migration_deferred(&self, refusal: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_migration_deferred,
            &[("refusal", refusal)],
        )
    }

    pub(crate) fn audit_reserve_finding_migration_forbidden_entry(
        &self,
        path: &str,
        found: &str,
    ) -> String {
        format_template(
            self.strings()
                .audit_reserve_finding_migration_forbidden_entry,
            &[("path", path), ("found", found)],
        )
    }

    pub(crate) fn audit_reserve_finding_migration_arithmetic(&self, figure: &str) -> String {
        format_template(
            self.strings().audit_reserve_finding_migration_arithmetic,
            &[("figure", figure)],
        )
    }

    pub(crate) fn audit_reserve_finding_migration_capacity_fits(
        &self,
        available: u64,
        source: u64,
        margin: u64,
    ) -> String {
        format_template(
            self.strings().audit_reserve_finding_migration_capacity_fits,
            &[
                ("available", &available.to_string()),
                ("source", &source.to_string()),
                ("margin", &margin.to_string()),
            ],
        )
    }

    pub(crate) fn audit_reserve_finding_migration_capacity_short(
        &self,
        available: u64,
        source: u64,
        margin: u64,
    ) -> String {
        format_template(
            self.strings()
                .audit_reserve_finding_migration_capacity_short,
            &[
                ("available", &available.to_string()),
                ("source", &source.to_string()),
                ("margin", &margin.to_string()),
            ],
        )
    }

    pub(crate) fn audit_reserve_note_migrated_reclaimable(&self, path: &str, size: u64) -> String {
        format_template(
            self.strings().audit_reserve_note_migrated_reclaimable,
            &[("path", path), ("size", &size.to_string())],
        )
    }

    pub(crate) fn audit_reserve_note_migrated_reclaimable_unsized(&self, path: &str) -> String {
        format_template(
            self.strings()
                .audit_reserve_note_migrated_reclaimable_unsized,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_note_retained_image_reclaimable(
        &self,
        path: &str,
        size: u64,
    ) -> String {
        format_template(
            self.strings().audit_reserve_note_retained_image_reclaimable,
            &[("path", path), ("size", &size.to_string())],
        )
    }

    pub(crate) fn audit_reserve_figure_source_plus_margin(&self, path: &str) -> String {
        format_template(
            self.strings().audit_reserve_figure_source_plus_margin,
            &[("path", path)],
        )
    }

    pub(crate) fn audit_reserve_migration_prerequisites(&self) -> &'static str {
        self.strings().audit_reserve_migration_prerequisites
    }

    pub(crate) fn audit_reserve_migration_window(&self) -> &'static str {
        self.strings().audit_reserve_migration_window
    }

    pub(crate) fn audit_reserve_step_aside_rename(&self) -> &'static str {
        self.strings().audit_reserve_step_aside_rename
    }

    pub(crate) fn audit_reserve_step_type_guard(&self) -> &'static str {
        self.strings().audit_reserve_step_type_guard
    }

    pub(crate) fn audit_reserve_step_copy(&self) -> &'static str {
        self.strings().audit_reserve_step_copy
    }

    pub(crate) fn audit_reserve_step_verify(&self) -> &'static str {
        self.strings().audit_reserve_step_verify
    }

    pub(crate) fn audit_reserve_step_closing_rename(&self) -> &'static str {
        self.strings().audit_reserve_step_closing_rename
    }

    pub(crate) fn audit_reserve_step_rollback(&self) -> &'static str {
        self.strings().audit_reserve_step_rollback
    }

    pub(crate) fn audit_reserve_step_rerun(&self, command: &str) -> String {
        format_template(
            self.strings().audit_reserve_step_rerun,
            &[("command", command)],
        )
    }
}
