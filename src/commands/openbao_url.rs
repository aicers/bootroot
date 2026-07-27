//! Derivation of the effective `OpenBao` API URL from the configured
//! host port.
//!
//! `OpenBao`'s host-side published port is configurable (`--openbao-host-port`,
//! `OPENBAO_HOST_PORT` in the process environment or in `<compose_dir>/.env`),
//! but the `--openbao-url` CLI default is the literal
//! [`DEFAULT_OPENBAO_URL`].  Left alone, a command started against a
//! non-default host port would talk to nothing — or, on a host shared with a
//! second bootroot instance, to that instance's `OpenBao`.  Every command
//! that builds a client straight from the CLI value routes it through
//! [`effective_openbao_url`] first.

use std::path::Path;

use bootroot::host_port::resolve_openbao_host_port;

use crate::commands::init::DEFAULT_OPENBAO_URL;

/// Returns the `OpenBao` URL a command should actually talk to.
///
/// An operator-supplied `--openbao-url` is always honoured verbatim: the
/// derivation fires only when `cli_url` is exactly [`DEFAULT_OPENBAO_URL`].
/// In that case the default's port is replaced by the resolved host port —
/// `host_port` when the command has a flag that carries one, else the
/// process environment, else `<compose_dir>/.env`, else 8200 (see
/// [`resolve_openbao_host_port`]).
pub(crate) fn effective_openbao_url(
    cli_url: &str,
    compose_dir: &Path,
    host_port: Option<u16>,
) -> String {
    if cli_url != DEFAULT_OPENBAO_URL {
        return cli_url.to_string();
    }
    let port = host_port.unwrap_or_else(|| resolve_openbao_host_port(compose_dir));
    let Some((prefix, _)) = DEFAULT_OPENBAO_URL.rsplit_once(':') else {
        return cli_url.to_string();
    };
    format!("{prefix}:{port}")
}

/// Shared test guard for the host-port environment variables.
///
/// The variables are process-global, so a test that *sets* one and a
/// test that merely *reads* one (through the resolvers, from a `.env`
/// file) interfere across modules unless both hold the same lock.  Every
/// binary-crate test that touches `OPENBAO_HOST_PORT`,
/// `STEPCA_HOST_PORT` or `HTTP01_ADMIN_HOST_PORT` — in either direction
/// — takes this guard.
#[cfg(test)]
pub(crate) mod test_env {
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

    use bootroot::host_port::{
        HTTP01_ADMIN_HOST_PORT_ENV, OPENBAO_HOST_PORT_ENV, STEPCA_HOST_PORT_ENV,
    };

    const GUARDED_KEYS: [&str; 3] = [
        OPENBAO_HOST_PORT_ENV,
        STEPCA_HOST_PORT_ENV,
        HTTP01_ADMIN_HOST_PORT_ENV,
    ];

    /// Clears the guarded variables for the lifetime of the guard and
    /// restores their pre-test values on drop.
    pub(crate) struct HostPortEnvGuard {
        _lock: MutexGuard<'static, ()>,
        previous: Vec<(&'static str, Option<String>)>,
    }

    impl HostPortEnvGuard {
        pub(crate) fn new() -> Self {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let lock = LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let previous = GUARDED_KEYS
                .iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect();
            for key in GUARDED_KEYS {
                // SAFETY: removal is serialized by the mutex held above.
                unsafe {
                    std::env::remove_var(key);
                }
            }
            Self {
                _lock: lock,
                previous,
            }
        }

        pub(crate) fn set(&self, key: &str, value: &str) {
            assert!(
                self.previous.iter().any(|(tracked, _)| *tracked == key),
                "{key} is not tracked by the guard and would leak into other tests"
            );
            // SAFETY: mutation is serialized by the mutex held by `_lock`.
            unsafe {
                std::env::set_var(key, value);
            }
        }
    }

    impl Drop for HostPortEnvGuard {
        fn drop(&mut self) {
            for (key, previous) in &self.previous {
                // SAFETY: restored inside the shared mutex held by `_lock`.
                unsafe {
                    match previous {
                        Some(value) => std::env::set_var(key, value),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use bootroot::host_port::OPENBAO_HOST_PORT_ENV;

    use super::test_env::HostPortEnvGuard;
    use super::*;

    const NON_DEFAULT_URL: &str = "https://openbao.internal:8200";

    struct EnvGuard(HostPortEnvGuard);

    impl EnvGuard {
        fn new() -> Self {
            Self(HostPortEnvGuard::new())
        }

        fn set(&self, value: &str) {
            self.0.set(OPENBAO_HOST_PORT_ENV, value);
        }
    }

    #[test]
    fn default_url_takes_the_flag_supplied_port() {
        let _guard = EnvGuard::new();
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            effective_openbao_url(DEFAULT_OPENBAO_URL, dir.path(), Some(18200)),
            "http://localhost:18200"
        );
    }

    #[test]
    fn default_url_takes_the_process_env_port() {
        let guard = EnvGuard::new();
        let dir = tempfile::tempdir().expect("tempdir");
        guard.set("18201");
        assert_eq!(
            effective_openbao_url(DEFAULT_OPENBAO_URL, dir.path(), None),
            "http://localhost:18201"
        );
    }

    #[test]
    fn default_url_takes_the_env_file_port() {
        let _guard = EnvGuard::new();
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18202\n").expect("write .env");
        assert_eq!(
            effective_openbao_url(DEFAULT_OPENBAO_URL, dir.path(), None),
            "http://localhost:18202"
        );
    }

    #[test]
    fn flag_wins_over_process_env_and_env_file() {
        let guard = EnvGuard::new();
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18203\n").expect("write .env");
        guard.set("18204");
        assert_eq!(
            effective_openbao_url(DEFAULT_OPENBAO_URL, dir.path(), Some(18205)),
            "http://localhost:18205"
        );
    }

    #[test]
    fn default_url_unchanged_when_nothing_is_configured() {
        let _guard = EnvGuard::new();
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            effective_openbao_url(DEFAULT_OPENBAO_URL, dir.path(), None),
            DEFAULT_OPENBAO_URL
        );
    }

    #[test]
    fn non_default_url_is_never_rewritten() {
        let guard = EnvGuard::new();
        let dir = tempfile::tempdir().expect("tempdir");
        // .env source.
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18206\n").expect("write .env");
        assert_eq!(
            effective_openbao_url(NON_DEFAULT_URL, dir.path(), None),
            NON_DEFAULT_URL
        );
        // Process-environment source.
        guard.set("18207");
        assert_eq!(
            effective_openbao_url(NON_DEFAULT_URL, dir.path(), None),
            NON_DEFAULT_URL
        );
        // Flag source.
        assert_eq!(
            effective_openbao_url(NON_DEFAULT_URL, dir.path(), Some(18208)),
            NON_DEFAULT_URL
        );
    }
}
