//! Localized operator messages emitted by `bootroot-agent`.

use std::ffi::OsStr;

use anyhow::Result;

use crate::locale::Locale;

/// The localized messages used by one agent invocation.
#[derive(Clone, Copy, Debug)]
pub struct DaemonMessages {
    locale: Locale,
}

impl DaemonMessages {
    /// Selects the messages requested through `BOOTROOT_LANG`.
    ///
    /// An absent, non-UTF-8, or unsupported value selects English. A locale
    /// used only for diagnostics must not interrupt certificate renewal.
    #[must_use]
    pub fn from_environment() -> Self {
        Self::from_environment_value(std::env::var_os("BOOTROOT_LANG").as_deref())
    }

    fn from_environment_value(language: Option<&OsStr>) -> Self {
        language
            .and_then(OsStr::to_str)
            .and_then(|language| Self::new(language).ok())
            .unwrap_or_default()
    }

    /// Selects the messages for `language`.
    ///
    /// # Errors
    ///
    /// Returns an error when `language` is not a supported locale.
    pub fn new(language: &str) -> Result<Self> {
        Ok(Self {
            locale: Locale::parse(language)?,
        })
    }

    /// Returns the startup diagnostic for an unmounted audit store.
    #[must_use]
    pub fn audit_store_not_mounted_at_start(self) -> &'static str {
        match self.locale {
            Locale::En => {
                "Registrar endpoint will refuse requests because the audit store is not mounted"
            }
            Locale::Ko => "감사 저장소가 마운트되지 않아 레지스트라 엔드포인트가 요청을 거부합니다",
        }
    }

    /// Returns the per-request diagnostic for an unmounted audit store.
    #[must_use]
    pub fn audit_store_not_mounted_request_refused(self) -> &'static str {
        match self.locale {
            Locale::En => {
                "Registrar endpoint refused a request because the audit store is not mounted"
            }
            Locale::Ko => {
                "감사 저장소가 마운트되지 않아 레지스트라 엔드포인트가 요청을 거부했습니다"
            }
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

    #[test]
    fn unsupported_environment_language_falls_back_to_english() {
        let messages = DaemonMessages::from_environment_value(Some(OsStr::new("fr")));

        assert_eq!(
            messages.audit_store_not_mounted_request_refused(),
            DaemonMessages::default().audit_store_not_mounted_request_refused()
        );
    }
}
