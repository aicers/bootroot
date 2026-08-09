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

pub(crate) use bootroot::host_port::OPENBAO_HOST_PORT_ENV;
use bootroot::host_port::resolve_openbao_host_port_with_env;

use crate::commands::init::DEFAULT_OPENBAO_URL;

/// Returns the `OpenBao` URL a command should actually talk to.
///
/// An operator-supplied `--openbao-url` is always honoured verbatim: the
/// derivation fires only when `cli_url` is exactly [`DEFAULT_OPENBAO_URL`].
/// In that case the default's port is replaced by the resolved host port —
/// `host_port` when the command has a flag that carries one, else the
/// process environment, else `<compose_dir>/.env`, else 8200 (see
/// [`resolve_openbao_host_port_with_env`]).
pub(crate) fn effective_openbao_url(
    cli_url: &str,
    compose_dir: &Path,
    host_port: Option<u16>,
) -> String {
    effective_openbao_url_with_env(
        cli_url,
        compose_dir,
        host_port,
        std::env::var(OPENBAO_HOST_PORT_ENV).ok().as_deref(),
    )
}

/// [`effective_openbao_url`] with the `OPENBAO_HOST_PORT` value supplied
/// by the caller instead of read from the process environment.
pub(crate) fn effective_openbao_url_with_env(
    cli_url: &str,
    compose_dir: &Path,
    host_port: Option<u16>,
    env_value: Option<&str>,
) -> String {
    if cli_url != DEFAULT_OPENBAO_URL {
        return cli_url.to_string();
    }
    let port =
        host_port.unwrap_or_else(|| resolve_openbao_host_port_with_env(env_value, compose_dir));
    let Some((prefix, _)) = DEFAULT_OPENBAO_URL.rsplit_once(':') else {
        return cli_url.to_string();
    };
    format!("{prefix}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    const NON_DEFAULT_URL: &str = "https://openbao.internal:8200";

    #[test]
    fn default_url_takes_the_flag_supplied_port() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            effective_openbao_url_with_env(DEFAULT_OPENBAO_URL, dir.path(), Some(18200), None),
            "http://localhost:18200"
        );
    }

    #[test]
    fn default_url_takes_the_process_env_port() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            effective_openbao_url_with_env(DEFAULT_OPENBAO_URL, dir.path(), None, Some("18201")),
            "http://localhost:18201"
        );
    }

    #[test]
    fn default_url_takes_the_env_file_port() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18202\n").expect("write .env");
        assert_eq!(
            effective_openbao_url_with_env(DEFAULT_OPENBAO_URL, dir.path(), None, None),
            "http://localhost:18202"
        );
    }

    #[test]
    fn flag_wins_over_process_env_and_env_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18203\n").expect("write .env");
        assert_eq!(
            effective_openbao_url_with_env(
                DEFAULT_OPENBAO_URL,
                dir.path(),
                Some(18205),
                Some("18204")
            ),
            "http://localhost:18205"
        );
    }

    #[test]
    fn default_url_unchanged_when_nothing_is_configured() {
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            effective_openbao_url_with_env(DEFAULT_OPENBAO_URL, dir.path(), None, None),
            DEFAULT_OPENBAO_URL
        );
    }

    #[test]
    fn non_default_url_is_never_rewritten() {
        let dir = tempfile::tempdir().expect("tempdir");
        // .env source.
        std::fs::write(dir.path().join(".env"), "OPENBAO_HOST_PORT=18206\n").expect("write .env");
        assert_eq!(
            effective_openbao_url_with_env(NON_DEFAULT_URL, dir.path(), None, None),
            NON_DEFAULT_URL
        );
        // Process-environment source.
        assert_eq!(
            effective_openbao_url_with_env(NON_DEFAULT_URL, dir.path(), None, Some("18207")),
            NON_DEFAULT_URL
        );
        // Flag source.
        assert_eq!(
            effective_openbao_url_with_env(NON_DEFAULT_URL, dir.path(), Some(18208), None),
            NON_DEFAULT_URL
        );
    }
}
