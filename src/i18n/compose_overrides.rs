use super::{Messages, format_template};

impl Messages {
    pub(crate) fn error_compose_override_symlink(&self, path: &str) -> String {
        format_template(
            self.strings().error_compose_override_symlink,
            &[("path", path)],
        )
    }

    pub(crate) fn error_compose_override_not_directory(&self, path: &str) -> String {
        format_template(
            self.strings().error_compose_override_not_directory,
            &[("path", path)],
        )
    }

    pub(crate) fn error_compose_override_not_regular_file(&self, path: &str) -> String {
        format_template(
            self.strings().error_compose_override_not_regular_file,
            &[("path", path)],
        )
    }

    pub(crate) fn error_compose_override_untrusted_owner(
        &self,
        path: &str,
        uid: u32,
        euid: u32,
        compose_owner: u32,
    ) -> String {
        format_template(
            self.strings().error_compose_override_untrusted_owner,
            &[
                ("path", path),
                ("uid", &uid.to_string()),
                ("euid", &euid.to_string()),
                ("compose_owner", &compose_owner.to_string()),
            ],
        )
    }

    pub(crate) fn error_compose_override_writable(&self, path: &str, mode: &str) -> String {
        format_template(
            self.strings().error_compose_override_writable,
            &[("path", path), ("mode", mode)],
        )
    }

    pub(crate) fn error_compose_override_inside_secrets(
        &self,
        path: &str,
        secrets_dir: &str,
    ) -> String {
        format_template(
            self.strings().error_compose_override_inside_secrets,
            &[("path", path), ("secrets_dir", secrets_dir)],
        )
    }

    pub(crate) fn error_compose_override_legacy_exposure(
        &self,
        path: &str,
        legacy: &str,
    ) -> String {
        format_template(
            self.strings().error_compose_override_legacy_exposure,
            &[("path", path), ("legacy", legacy)],
        )
    }

    pub(crate) fn error_compose_override_legacy_init(&self, path: &str, legacy: &str) -> String {
        format_template(
            self.strings().error_compose_override_legacy_init,
            &[("path", path), ("legacy", legacy)],
        )
    }

    pub(crate) fn warning_clean_compose_override_skipped(
        &self,
        path: &str,
        reason: &str,
    ) -> String {
        format_template(
            self.strings().warning_clean_compose_override_skipped,
            &[("path", path), ("reason", reason)],
        )
    }
}
