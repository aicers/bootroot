//! Resolution of the host-side ports the compose stack publishes.
//!
//! Every core service publishes its host-side port through a
//! `${<NAME>_HOST_PORT:-<default>}` interpolation in `docker-compose.yml`
//! and `docker-compose.deploy.yml`, so two bootroot instances can share a
//! host.  The helpers here reproduce Docker Compose's own precedence for
//! those interpolations — process environment first, then the `.env` file
//! sitting next to the compose file, then the compile-time default — so
//! host-side tooling agrees with what Compose actually published.

use std::path::Path;

/// Environment variable that controls `OpenBao`'s host-side published port.
pub const OPENBAO_HOST_PORT_ENV: &str = "OPENBAO_HOST_PORT";
/// Fallback `OpenBao` host port when `OPENBAO_HOST_PORT` is unset.
///
/// Matches the published default in `docker-compose.yml`.
pub const DEFAULT_OPENBAO_HOST_PORT: u16 = 8200;
/// Environment variable that controls step-ca's host-side published port.
pub const STEPCA_HOST_PORT_ENV: &str = "STEPCA_HOST_PORT";
/// Fallback step-ca host port when `STEPCA_HOST_PORT` is unset.
///
/// Matches the published default in `docker-compose.yml`.
pub const DEFAULT_STEPCA_HOST_PORT: u16 = 9000;
/// Environment variable that controls the HTTP-01 responder admin API's
/// host-side published port.
pub const HTTP01_ADMIN_HOST_PORT_ENV: &str = "HTTP01_ADMIN_HOST_PORT";
/// Fallback HTTP-01 admin host port when `HTTP01_ADMIN_HOST_PORT` is unset.
///
/// Matches the published default in `docker-compose.yml`.
pub const DEFAULT_HTTP01_ADMIN_HOST_PORT: u16 = 8080;

/// Resolves a host-side published port with the same precedence Docker
/// Compose uses for a `${<key>:-<default>}` port mapping:
///
/// 1. process environment `key` (non-empty), else
/// 2. `key` from `compose_dir/.env`, else
/// 3. `default`.
///
/// A present-but-unparseable value falls through to the next source
/// rather than erroring — the caller is deriving an endpoint, not
/// validating the environment.
#[must_use]
pub fn resolve_host_port(compose_dir: &Path, key: &str, default: u16) -> u16 {
    if let Ok(value) = std::env::var(key)
        && !value.is_empty()
        && let Ok(port) = value.parse::<u16>()
    {
        return port;
    }
    if let Some(port) =
        read_env_file_value(compose_dir, key).and_then(|value| value.parse::<u16>().ok())
    {
        return port;
    }
    default
}

/// Resolves the host-side `OpenBao` port.  See [`resolve_host_port`] for
/// the precedence rules.
#[must_use]
pub fn resolve_openbao_host_port(compose_dir: &Path) -> u16 {
    resolve_host_port(
        compose_dir,
        OPENBAO_HOST_PORT_ENV,
        DEFAULT_OPENBAO_HOST_PORT,
    )
}

/// Resolves the host-side step-ca port.  See [`resolve_host_port`] for
/// the precedence rules.
#[must_use]
pub fn resolve_stepca_host_port(compose_dir: &Path) -> u16 {
    resolve_host_port(compose_dir, STEPCA_HOST_PORT_ENV, DEFAULT_STEPCA_HOST_PORT)
}

/// Resolves the host-side HTTP-01 admin API port.  See
/// [`resolve_host_port`] for the precedence rules.
#[must_use]
pub fn resolve_http01_admin_host_port(compose_dir: &Path) -> u16 {
    resolve_host_port(
        compose_dir,
        HTTP01_ADMIN_HOST_PORT_ENV,
        DEFAULT_HTTP01_ADMIN_HOST_PORT,
    )
}

/// Reads a single `key=value` entry out of `compose_dir/.env`.
///
/// Returns `None` when the file is unreadable, the key is absent, or the
/// value is empty — every one of which means "fall through to the next
/// source" for the callers above.  Surrounding single or double quotes
/// are stripped, matching how Compose reads its `.env`.
///
/// A line carrying no `=` is skipped rather than ending the scan, so a
/// stray operator-authored line cannot hide the keys below it and leave
/// the preflight binding a port Compose never publishes.
#[must_use]
fn read_env_file_value(compose_dir: &Path, key: &str) -> Option<String> {
    let contents = std::fs::read_to_string(compose_dir.join(".env")).ok()?;
    for line in contents.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((k, v)) = trimmed.split_once('=') else {
            continue;
        };
        if k.trim() != key {
            continue;
        }
        let value = v.trim();
        let stripped = value
            .strip_prefix('"')
            .and_then(|inner| inner.strip_suffix('"'))
            .or_else(|| {
                value
                    .strip_prefix('\'')
                    .and_then(|inner| inner.strip_suffix('\''))
            })
            .unwrap_or(value);
        if stripped.is_empty() {
            return None;
        }
        return Some(stripped.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};

    use super::*;

    const TEST_KEYS: [&str; 3] = [
        OPENBAO_HOST_PORT_ENV,
        STEPCA_HOST_PORT_ENV,
        HTTP01_ADMIN_HOST_PORT_ENV,
    ];

    /// Serialises every test that touches the host-port environment
    /// variables and restores their pre-test values on drop.
    struct EnvGuard {
        _lock: MutexGuard<'static, ()>,
        previous: Vec<(&'static str, Option<String>)>,
    }

    impl EnvGuard {
        fn new() -> Self {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let lock = LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let previous = TEST_KEYS
                .iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect();
            for key in TEST_KEYS {
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

        fn set(&self, key: &str, value: &str) {
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

    impl Drop for EnvGuard {
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

    /// One new variable, as `(env key, compile-time default, resolver)`.
    type ResolverCase = (&'static str, u16, fn(&Path) -> u16);

    /// Every variable this module adds.
    fn cases() -> Vec<ResolverCase> {
        vec![
            (
                OPENBAO_HOST_PORT_ENV,
                DEFAULT_OPENBAO_HOST_PORT,
                resolve_openbao_host_port as fn(&Path) -> u16,
            ),
            (
                STEPCA_HOST_PORT_ENV,
                DEFAULT_STEPCA_HOST_PORT,
                resolve_stepca_host_port as fn(&Path) -> u16,
            ),
            (
                HTTP01_ADMIN_HOST_PORT_ENV,
                DEFAULT_HTTP01_ADMIN_HOST_PORT,
                resolve_http01_admin_host_port as fn(&Path) -> u16,
            ),
        ]
    }

    #[test]
    fn process_env_wins_over_env_file() {
        let guard = EnvGuard::new();
        for (key, _, resolve) in cases() {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join(".env"), format!("{key}=19999\n")).expect("write .env");
            guard.set(key, "17777");
            assert_eq!(resolve(dir.path()), 17777, "{key} must prefer process env");
        }
    }

    #[test]
    fn env_file_used_when_process_env_unset() {
        let _guard = EnvGuard::new();
        for (key, _, resolve) in cases() {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(
                dir.path().join(".env"),
                format!("# comment\nOTHER=1\n{key}=\"18888\"\n"),
            )
            .expect("write .env");
            assert_eq!(resolve(dir.path()), 18888, "{key} must read .env");
        }
    }

    #[test]
    fn default_used_when_nothing_set() {
        let _guard = EnvGuard::new();
        for (key, default, resolve) in cases() {
            let dir = tempfile::tempdir().expect("tempdir");
            assert_eq!(resolve(dir.path()), default, "{key} must fall back");
        }
    }

    #[test]
    fn unparseable_process_env_falls_through_to_env_file() {
        let guard = EnvGuard::new();
        for (key, _, resolve) in cases() {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join(".env"), format!("{key}=16666\n")).expect("write .env");
            guard.set(key, "not-a-port");
            assert_eq!(
                resolve(dir.path()),
                16666,
                "{key} must fall through to .env"
            );
        }
    }

    #[test]
    fn unparseable_env_file_falls_through_to_default() {
        let _guard = EnvGuard::new();
        for (key, default, resolve) in cases() {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join(".env"), format!("{key}=99999999\n"))
                .expect("write .env");
            assert_eq!(resolve(dir.path()), default, "{key} must fall through");
        }
    }

    #[test]
    fn empty_process_env_falls_through_to_env_file() {
        let guard = EnvGuard::new();
        for (key, _, resolve) in cases() {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join(".env"), format!("{key}=15555\n")).expect("write .env");
            guard.set(key, "");
            assert_eq!(resolve(dir.path()), 15555, "{key} must ignore an empty env");
        }
    }

    #[test]
    fn read_env_file_value_ignores_empty_and_missing_keys() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "EMPTY=\nQUOTED='7'\n").expect("write .env");
        assert_eq!(read_env_file_value(dir.path(), "EMPTY"), None);
        assert_eq!(read_env_file_value(dir.path(), "MISSING"), None);
        assert_eq!(
            read_env_file_value(dir.path(), "QUOTED").as_deref(),
            Some("7")
        );
    }

    /// A line carrying no `=` must not hide the keys after it — that
    /// would silently drop the resolver back to the compile-time
    /// default and preflight a port Compose never publishes.
    #[test]
    fn env_file_line_without_a_separator_does_not_end_the_scan() {
        let _guard = EnvGuard::new();
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(".env"),
            "MALFORMED\nOPENBAO_HOST_PORT=18200\n",
        )
        .expect("write .env");
        assert_eq!(resolve_openbao_host_port(dir.path()), 18200);
    }
}
