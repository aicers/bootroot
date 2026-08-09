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

/// Names the environment variable that controls `OpenBao`'s host-side
/// published port.
pub const OPENBAO_HOST_PORT_ENV: &str = "OPENBAO_HOST_PORT";
/// Defines the `OpenBao` host port used when `OPENBAO_HOST_PORT` is unset.
///
/// Matches the published default in `docker-compose.yml`.
pub const DEFAULT_OPENBAO_HOST_PORT: u16 = 8200;
/// Names the environment variable that controls step-ca's host-side
/// published port.
pub const STEPCA_HOST_PORT_ENV: &str = "STEPCA_HOST_PORT";
/// Defines the step-ca host port used when `STEPCA_HOST_PORT` is unset.
///
/// Matches the published default in `docker-compose.yml`.
pub const DEFAULT_STEPCA_HOST_PORT: u16 = 9000;
/// Names the environment variable that controls the HTTP-01 responder admin
/// API's host-side published port.
pub const HTTP01_ADMIN_HOST_PORT_ENV: &str = "HTTP01_ADMIN_HOST_PORT";
/// Defines the HTTP-01 admin host port used when `HTTP01_ADMIN_HOST_PORT` is
/// unset.
///
/// Matches the published default in `docker-compose.yml`.
pub const DEFAULT_HTTP01_ADMIN_HOST_PORT: u16 = 8080;

/// Resolves a host-side published port with the same precedence Docker
/// Compose uses for a `${<key>:-<default>}` port mapping, given the
/// value the process environment holds for `key`:
///
/// 1. `env_value` (present and non-empty), else
/// 2. `key` from `compose_dir/.env`, else
/// 3. `default`.
///
/// A present-but-unparseable value falls through to the next source
/// rather than erroring — the caller is deriving an endpoint, not
/// validating the environment.
///
/// The environment value is a parameter rather than a read so a caller
/// — a test, or a command that already resolved it — can steer the
/// first step without touching the process-global environment.
///
/// Crate-internal: the exported surface is the per-service resolvers
/// below, which pin the `(key, default)` pair to what the compose files
/// actually interpolate.
#[must_use]
pub(crate) fn resolve_host_port_with_env(
    env_value: Option<&str>,
    compose_dir: &Path,
    key: &str,
    default: u16,
) -> u16 {
    if let Some(value) = env_value
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

/// [`resolve_host_port_with_env`] reading `key` from the process
/// environment.
///
/// The one place in this module that touches the environment; every
/// other resolver here is a `(key, default)` pairing on top of it.
#[must_use]
pub(crate) fn resolve_host_port(compose_dir: &Path, key: &str, default: u16) -> u16 {
    resolve_host_port_with_env(
        std::env::var(key).ok().as_deref(),
        compose_dir,
        key,
        default,
    )
}

/// One service's published host port: the environment variable that
/// overrides it and the compile-time default the compose files
/// interpolate.
///
/// The two travel as one value so a resolver and the test that steers
/// it cannot name different halves of the pair.
#[derive(Debug, Clone, Copy)]
struct HostPortSpec {
    key: &'static str,
    default: u16,
}

const OPENBAO_HOST_PORT: HostPortSpec = HostPortSpec {
    key: OPENBAO_HOST_PORT_ENV,
    default: DEFAULT_OPENBAO_HOST_PORT,
};
const STEPCA_HOST_PORT: HostPortSpec = HostPortSpec {
    key: STEPCA_HOST_PORT_ENV,
    default: DEFAULT_STEPCA_HOST_PORT,
};
const HTTP01_ADMIN_HOST_PORT: HostPortSpec = HostPortSpec {
    key: HTTP01_ADMIN_HOST_PORT_ENV,
    default: DEFAULT_HTTP01_ADMIN_HOST_PORT,
};

impl HostPortSpec {
    /// Resolves this port, reading the override from the process
    /// environment.
    fn resolve(self, compose_dir: &Path) -> u16 {
        resolve_host_port(compose_dir, self.key, self.default)
    }

    /// [`HostPortSpec::resolve`] with the process-environment value
    /// supplied by the caller.
    fn resolve_with_env(self, env_value: Option<&str>, compose_dir: &Path) -> u16 {
        resolve_host_port_with_env(env_value, compose_dir, self.key, self.default)
    }
}

/// Resolves the host-side `OpenBao` port: process environment
/// [`OPENBAO_HOST_PORT_ENV`] (non-empty), else the same key from
/// `compose_dir/.env`, else [`DEFAULT_OPENBAO_HOST_PORT`].  An
/// unparseable value falls through to the next source.
#[must_use]
pub fn resolve_openbao_host_port(compose_dir: &Path) -> u16 {
    OPENBAO_HOST_PORT.resolve(compose_dir)
}

/// [`resolve_openbao_host_port`] with the `OPENBAO_HOST_PORT` value
/// supplied by the caller instead of read from the process
/// environment.
#[must_use]
pub fn resolve_openbao_host_port_with_env(env_value: Option<&str>, compose_dir: &Path) -> u16 {
    OPENBAO_HOST_PORT.resolve_with_env(env_value, compose_dir)
}

/// Resolves the host-side step-ca port: process environment
/// [`STEPCA_HOST_PORT_ENV`] (non-empty), else the same key from
/// `compose_dir/.env`, else [`DEFAULT_STEPCA_HOST_PORT`].  An unparseable
/// value falls through to the next source.
#[must_use]
pub fn resolve_stepca_host_port(compose_dir: &Path) -> u16 {
    STEPCA_HOST_PORT.resolve(compose_dir)
}

/// [`resolve_stepca_host_port`] with the `STEPCA_HOST_PORT` value
/// supplied by the caller instead of read from the process environment.
#[must_use]
pub fn resolve_stepca_host_port_with_env(env_value: Option<&str>, compose_dir: &Path) -> u16 {
    STEPCA_HOST_PORT.resolve_with_env(env_value, compose_dir)
}

/// Resolves the host-side HTTP-01 admin API port: process environment
/// [`HTTP01_ADMIN_HOST_PORT_ENV`] (non-empty), else the same key from
/// `compose_dir/.env`, else [`DEFAULT_HTTP01_ADMIN_HOST_PORT`].  An
/// unparseable value falls through to the next source.
#[must_use]
pub fn resolve_http01_admin_host_port(compose_dir: &Path) -> u16 {
    HTTP01_ADMIN_HOST_PORT.resolve(compose_dir)
}

/// [`resolve_http01_admin_host_port`] with the
/// `HTTP01_ADMIN_HOST_PORT` value supplied by the caller instead of
/// read from the process environment.
#[must_use]
pub fn resolve_http01_admin_host_port_with_env(env_value: Option<&str>, compose_dir: &Path) -> u16 {
    HTTP01_ADMIN_HOST_PORT.resolve_with_env(env_value, compose_dir)
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
    use super::*;

    /// Every host port this module resolves.
    ///
    /// The per-service resolvers are one call each on top of these, so
    /// driving the specs directly covers the precedence rules once for
    /// all three without steering the process environment.
    const SPECS: [HostPortSpec; 3] = [OPENBAO_HOST_PORT, STEPCA_HOST_PORT, HTTP01_ADMIN_HOST_PORT];

    #[test]
    fn process_env_wins_over_env_file() {
        for spec in SPECS {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join(".env"), format!("{}=19999\n", spec.key))
                .expect("write .env");
            assert_eq!(
                spec.resolve_with_env(Some("17777"), dir.path()),
                17777,
                "{} must prefer the process env",
                spec.key
            );
        }
    }

    #[test]
    fn env_file_used_when_process_env_unset() {
        for spec in SPECS {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(
                dir.path().join(".env"),
                format!("# comment\nOTHER=1\n{}=\"18888\"\n", spec.key),
            )
            .expect("write .env");
            assert_eq!(
                spec.resolve_with_env(None, dir.path()),
                18888,
                "{} must read .env",
                spec.key
            );
        }
    }

    #[test]
    fn default_used_when_nothing_set() {
        for spec in SPECS {
            let dir = tempfile::tempdir().expect("tempdir");
            assert_eq!(
                spec.resolve_with_env(None, dir.path()),
                spec.default,
                "{} must fall back",
                spec.key
            );
        }
    }

    #[test]
    fn unparseable_process_env_falls_through_to_env_file() {
        for spec in SPECS {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join(".env"), format!("{}=16666\n", spec.key))
                .expect("write .env");
            assert_eq!(
                spec.resolve_with_env(Some("not-a-port"), dir.path()),
                16666,
                "{} must fall through to .env",
                spec.key
            );
        }
    }

    #[test]
    fn unparseable_env_file_falls_through_to_default() {
        for spec in SPECS {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join(".env"), format!("{}=99999999\n", spec.key))
                .expect("write .env");
            assert_eq!(
                spec.resolve_with_env(None, dir.path()),
                spec.default,
                "{} must fall through",
                spec.key
            );
        }
    }

    #[test]
    fn empty_process_env_falls_through_to_env_file() {
        for spec in SPECS {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join(".env"), format!("{}=15555\n", spec.key))
                .expect("write .env");
            assert_eq!(
                spec.resolve_with_env(Some(""), dir.path()),
                15555,
                "{} must ignore an empty env",
                spec.key
            );
        }
    }

    /// The specs are what pair a key with its default; a resolver that
    /// picked up the wrong one would read the wrong variable and
    /// publish the wrong fallback, and every test above would still
    /// pass.  Pin both halves against the documented values.
    #[test]
    fn each_spec_pairs_its_documented_key_and_default() {
        assert_eq!(
            (OPENBAO_HOST_PORT.key, OPENBAO_HOST_PORT.default),
            (OPENBAO_HOST_PORT_ENV, DEFAULT_OPENBAO_HOST_PORT)
        );
        assert_eq!(
            (STEPCA_HOST_PORT.key, STEPCA_HOST_PORT.default),
            (STEPCA_HOST_PORT_ENV, DEFAULT_STEPCA_HOST_PORT)
        );
        assert_eq!(
            (HTTP01_ADMIN_HOST_PORT.key, HTTP01_ADMIN_HOST_PORT.default),
            (HTTP01_ADMIN_HOST_PORT_ENV, DEFAULT_HTTP01_ADMIN_HOST_PORT)
        );
    }

    /// Each exported resolver's parameterised sibling is what every
    /// caller outside this module steers, so it has to carry the same
    /// spec as the resolver it mirrors.  A sibling wired to the wrong
    /// key would be invisible to every test above.
    #[test]
    fn each_parameterised_sibling_mirrors_its_resolver() {
        type Sibling = fn(Option<&str>, &Path) -> u16;
        let siblings: [(HostPortSpec, Sibling); 3] = [
            (OPENBAO_HOST_PORT, resolve_openbao_host_port_with_env),
            (STEPCA_HOST_PORT, resolve_stepca_host_port_with_env),
            (
                HTTP01_ADMIN_HOST_PORT,
                resolve_http01_admin_host_port_with_env,
            ),
        ];
        for (spec, sibling) in siblings {
            let dir = tempfile::tempdir().expect("tempdir");
            std::fs::write(dir.path().join(".env"), format!("{}=18299\n", spec.key))
                .expect("write .env");
            assert_eq!(
                sibling(None, dir.path()),
                18299,
                "{} must be read from .env",
                spec.key
            );
            assert_eq!(
                sibling(Some("18300"), dir.path()),
                18300,
                "the supplied {} must outrank .env",
                spec.key
            );
            assert_eq!(
                sibling(None, tempfile::tempdir().expect("tempdir").path()),
                spec.default,
                "{} must fall back to its own default",
                spec.key
            );
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
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(".env"),
            "MALFORMED\nOPENBAO_HOST_PORT=18200\n",
        )
        .expect("write .env");
        assert_eq!(resolve_openbao_host_port_with_env(None, dir.path()), 18200);
    }
}
