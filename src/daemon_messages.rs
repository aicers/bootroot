//! Localized operator messages emitted by `bootroot-agent`.

use std::ffi::OsStr;

use anyhow::Result;

use crate::config::AuditStoreReloadRejection;
use crate::locale::Locale;

/// Renders a refused audit-store reload in the daemon's selected locale.
///
/// The daemon's `SIGHUP` loop lives in the `bootroot-agent` binary, which
/// reaches the locale mechanism through this one entry point rather than by
/// spelling the diagnostic itself.
#[must_use]
pub fn audit_store_reload_rejection_message(rejection: &AuditStoreReloadRejection) -> String {
    DaemonMessages::from_environment().audit_store_reload_rejected(rejection)
}

/// The localized messages used by the unavailable registrar handler.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DaemonMessages {
    locale: Locale,
}

impl DaemonMessages {
    /// Selects messages from `BOOTROOT_LANG`, falling back to English.
    ///
    /// An absent, non-UTF-8, or unsupported value selects English. A locale
    /// used only for diagnostics must not interrupt certificate renewal.
    #[must_use]
    pub(crate) fn from_environment() -> Self {
        Self::from_environment_value(std::env::var_os("BOOTROOT_LANG").as_deref())
    }

    fn from_environment_value(language: Option<&OsStr>) -> Self {
        language
            .and_then(OsStr::to_str)
            .and_then(|language| Self::new(language).ok())
            .unwrap_or_default()
    }

    /// Selects messages for `language`.
    ///
    /// # Errors
    ///
    /// Returns an error when `language` is not a supported locale.
    pub(crate) fn new(language: &str) -> Result<Self> {
        Ok(Self {
            locale: Locale::parse(language)?,
        })
    }

    /// Returns the startup diagnostic for an unmounted audit store.
    ///
    /// The mount gate is compiled only where the registrar endpoint is, so
    /// nothing outside a Linux or test build has anything to say it with.
    #[must_use]
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn audit_store_not_mounted_at_start(self) -> &'static str {
        match self.locale {
            Locale::En => {
                "Registrar endpoint will refuse requests because the audit store is not mounted"
            }
            Locale::Ko => "감사 저장소가 마운트되지 않아 레지스트라 엔드포인트가 요청을 거부합니다",
        }
    }

    /// Returns the per-request diagnostic for an unmounted audit store.
    #[must_use]
    #[cfg(any(target_os = "linux", test))]
    pub(crate) fn audit_store_not_mounted_request_refused(self) -> &'static str {
        match self.locale {
            Locale::En => {
                "Registrar endpoint refused a request because the audit store is not mounted"
            }
            Locale::Ko => {
                "감사 저장소가 마운트되지 않아 레지스트라 엔드포인트가 요청을 거부했습니다"
            }
        }
    }

    /// Returns the diagnostic for a reload the mount verdict cannot absorb.
    ///
    /// Carries the setting the operator has to put back and both of its
    /// values, because the running daemon keeps serving the value it started
    /// with and nothing else says which one that is.
    #[must_use]
    pub(crate) fn audit_store_reload_rejected(
        self,
        rejection: &AuditStoreReloadRejection,
    ) -> String {
        let key = rejection.setting().key();
        let running = rejection.running();
        let reloaded = rejection.reloaded();
        match self.locale {
            Locale::En => format!(
                "Reload rejected: {key} changed from {running} to {reloaded}. The audit store's \
                 filesystem mount verdict is fixed for the process lifetime because the activated \
                 endpoint survives reloads, so the running daemon is left as it is. Restart the \
                 service to apply the change."
            ),
            Locale::Ko => format!(
                "리로드를 거부했습니다: {key} 값이 {running}에서 {reloaded}(으)로 바뀌었습니다. \
                 활성화된 엔드포인트가 리로드 이후에도 유지되므로 감사 저장소의 파일 시스템 \
                 마운트 판정은 프로세스 수명 동안 고정됩니다. 따라서 실행 중인 데몬은 그대로 \
                 두었습니다. 변경을 적용하려면 서비스를 다시 시작하세요."
            ),
        }
    }
}

impl Default for DaemonMessages {
    fn default() -> Self {
        Self { locale: Locale::En }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_store_refusals_are_available_in_both_locales() {
        let english = DaemonMessages::new("en").expect("English is supported");
        let korean = DaemonMessages::new("ko").expect("Korean is supported");

        assert_ne!(
            english.audit_store_not_mounted_at_start(),
            korean.audit_store_not_mounted_at_start()
        );
        assert_ne!(
            english.audit_store_not_mounted_request_refused(),
            korean.audit_store_not_mounted_request_refused()
        );
    }

    #[cfg(unix)]
    #[test]
    fn invalid_environment_language_falls_back_to_english() {
        use std::os::unix::ffi::OsStrExt as _;

        let invalid_utf8 = OsStr::from_bytes(b"\xff");
        let messages = DaemonMessages::from_environment_value(Some(invalid_utf8));

        assert_eq!(
            messages.audit_store_not_mounted_at_start(),
            DaemonMessages::default().audit_store_not_mounted_at_start()
        );
    }

    /// A refused reload is readable in either locale, and each rendering
    /// carries the key and both values the operator needs to put the running
    /// value back or restart the service.
    #[test]
    fn a_refused_reload_is_rendered_with_its_key_and_both_values_in_both_locales() {
        let running = crate::config::RegistrarSettings {
            audit_store_dir: std::path::PathBuf::from("/var/lib/bootroot/audit-store"),
            ..crate::config::RegistrarSettings::default()
        };
        let moved = crate::config::RegistrarSettings {
            audit_store_dir: std::path::PathBuf::from("/srv/bootroot/audit-store"),
            ..running.clone()
        };
        let rejection = crate::config::check_registrar_audit_store_reload(&running, &moved)
            .expect_err("a filesystem store path may not move across a reload");

        let english = DaemonMessages::new("en").expect("English is supported");
        let korean = DaemonMessages::new("ko").expect("Korean is supported");
        let english_message = english.audit_store_reload_rejected(&rejection);
        let korean_message = korean.audit_store_reload_rejected(&rejection);

        assert_ne!(english_message, korean_message);
        for message in [&english_message, &korean_message] {
            assert!(
                message.contains("registrar.audit_store_dir"),
                "the rendering names the setting: {message}"
            );
            assert!(
                message.contains("/var/lib/bootroot/audit-store"),
                "the rendering carries the running value: {message}"
            );
            assert!(
                message.contains("/srv/bootroot/audit-store"),
                "the rendering carries the reloaded value: {message}"
            );
        }
        assert!(!korean_message.is_ascii(), "{korean_message}");

        let enforcement = crate::config::RegistrarSettings {
            audit_store_enforcement: crate::config::AuditStoreEnforcement::Directory,
            ..running.clone()
        };
        let rejection = crate::config::check_registrar_audit_store_reload(&running, &enforcement)
            .expect_err("an enforcement change may not cross a reload");
        for message in [
            english.audit_store_reload_rejected(&rejection),
            korean.audit_store_reload_rejected(&rejection),
        ] {
            assert!(
                message.contains("registrar.audit_store_enforcement")
                    && message.contains("filesystem")
                    && message.contains("directory"),
                "the rendering names the setting and both modes: {message}"
            );
        }
    }

    /// The `bootroot-agent` reload loop reaches the locale mechanism through
    /// the exported entry point, so no English-only literal is left in the
    /// binary for this rejection.
    #[test]
    fn the_exported_entry_point_renders_through_the_daemon_locale() {
        let running = crate::config::RegistrarSettings::default();
        let moved = crate::config::RegistrarSettings {
            audit_store_dir: std::path::PathBuf::from("/srv/bootroot/audit-store"),
            ..running.clone()
        };
        let rejection = crate::config::check_registrar_audit_store_reload(&running, &moved)
            .expect_err("a filesystem store path may not move across a reload");

        let source = include_str!("bin/bootroot-agent.rs");
        assert!(
            source.contains("audit_store_reload_rejection_message(&rejection)"),
            "the reload loop renders the rejection rather than spelling one"
        );
        assert_eq!(
            audit_store_reload_rejection_message(&rejection),
            DaemonMessages::from_environment().audit_store_reload_rejected(&rejection)
        );
    }

    #[test]
    fn unsupported_environment_language_falls_back_to_english() {
        let messages = DaemonMessages::from_environment_value(Some(OsStr::new("fr")));

        assert_eq!(
            messages.audit_store_not_mounted_request_refused(),
            DaemonMessages::default().audit_store_not_mounted_request_refused()
        );
    }
}
