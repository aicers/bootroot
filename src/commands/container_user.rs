//! The host `uid:gid` a server container runs as when `infra install`
//! gave one: `--openbao-user` for `OpenBao`, `--postgres-user` for
//! step-ca's `PostgreSQL`.
//!
//! Each value is recorded under its own key in the `.env` beside the
//! compose file (`BOOTROOT_OPENBAO_USER`, `BOOTROOT_POSTGRES_USER`), and
//! both base compose files read it by interpolation: the service's
//! entrypoint re-owns its data to it and drops to it. bootroot reads the
//! same record wherever it hands the server its TLS key or checks that
//! key, so every reader here fails closed on a value it cannot parse: a
//! guess would put the key in front of a uid the server does not run as.

use std::fmt;
use std::path::Path;

use anyhow::Result;
use bootroot::host_port::read_env_file_value;

use crate::i18n::Messages;

/// `.env` key, and compose interpolation variable, carrying the
/// `uid:gid` `OpenBao` runs as.
pub(crate) const OPENBAO_USER_ENV_KEY: &str = "BOOTROOT_OPENBAO_USER";

/// `.env` key, and compose interpolation variable, carrying the
/// `uid:gid` step-ca's `PostgreSQL` runs as.
pub(crate) const POSTGRES_USER_ENV_KEY: &str = "BOOTROOT_POSTGRES_USER";

/// The highest uid or gid accepted. `4294967295` is `(uid_t)-1`, which
/// `chown` reads as "leave unchanged".
const MAX_ID: u32 = u32::MAX - 1;

/// A server whose container `infra install` can run as a given host
/// `uid:gid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UserServer {
    /// `OpenBao`, from `--openbao-user`.
    OpenBao,
    /// step-ca's `PostgreSQL`, from `--postgres-user`.
    Postgres,
}

impl UserServer {
    /// The `.env` key, and the compose variable, that carries the value.
    pub(crate) fn env_key(self) -> &'static str {
        match self {
            Self::OpenBao => OPENBAO_USER_ENV_KEY,
            Self::Postgres => POSTGRES_USER_ENV_KEY,
        }
    }

    fn flag_invalid(self, messages: &Messages, value: &str) -> String {
        match self {
            Self::OpenBao => messages.error_openbao_user_invalid(value),
            Self::Postgres => messages.error_postgres_user_invalid(value),
        }
    }

    fn recorded_invalid(self, messages: &Messages, path: &str, value: &str) -> String {
        match self {
            Self::OpenBao => messages.error_openbao_user_recorded_invalid(path, value),
            Self::Postgres => messages.error_postgres_user_recorded_invalid(path, value),
        }
    }

    fn env_mismatch(
        self,
        messages: &Messages,
        exported: &str,
        path: &str,
        recorded: &str,
    ) -> String {
        match self {
            Self::OpenBao => messages.error_openbao_user_env_mismatch(exported, path, recorded),
            Self::Postgres => messages.error_postgres_user_env_mismatch(exported, path, recorded),
        }
    }

    fn env_unrecorded(self, messages: &Messages, exported: &str, path: &str) -> String {
        match self {
            Self::OpenBao => messages.error_openbao_user_env_unrecorded(exported, path),
            Self::Postgres => messages.error_postgres_user_env_unrecorded(exported, path),
        }
    }

    fn env_empty(self, messages: &Messages, path: &str, recorded: &str) -> String {
        match self {
            Self::OpenBao => messages.error_openbao_user_env_empty(path, recorded),
            Self::Postgres => messages.error_postgres_user_env_empty(path, recorded),
        }
    }
}

/// A host uid and gid a server container runs as, neither of them `0`
/// nor `4294967295`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ContainerUser {
    uid: u32,
    gid: u32,
}

impl ContainerUser {
    pub(crate) fn uid(self) -> u32 {
        self.uid
    }

    /// The owner the server's TLS key is handed to: the uid, with group
    /// `0`, which grants nothing at `0600` and keeps the key out of any
    /// host group.
    pub(crate) fn key_owner(self) -> String {
        format!("{}:0", self.uid)
    }
}

impl fmt::Display for ContainerUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.uid, self.gid)
    }
}

/// Parses `<uid>:<gid>`: two decimal numbers of ASCII digits separated by
/// one `:`, each from `1` to `4294967294`, surrounding whitespace
/// trimmed. Returns `None` for anything else.
fn parse(raw: &str) -> Option<ContainerUser> {
    let (uid, gid) = raw.trim().split_once(':')?;
    Some(ContainerUser {
        uid: parse_id(uid)?,
        gid: parse_id(gid)?,
    })
}

fn parse_id(raw: &str) -> Option<u32> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let id: u32 = raw.parse().ok()?;
    (1..=MAX_ID).contains(&id).then_some(id)
}

/// Parses the `--openbao-user` or `--postgres-user` value for `server`.
///
/// # Errors
///
/// Returns the operator-facing refusal naming the option and its rule
/// when `raw` is not a valid `<uid>:<gid>`.
pub(crate) fn parse_user_flag(
    server: UserServer,
    raw: &str,
    messages: &Messages,
) -> Result<ContainerUser> {
    parse(raw).ok_or_else(|| anyhow::anyhow!(server.flag_invalid(messages, raw.trim())))
}

/// Reads the user `compose_dir/.env` records for `server`, refusing a
/// malformed value and an exported variable of the same name that Docker
/// Compose would prefer to it.
///
/// The one place this module reads the process environment; the logic is
/// [`recorded_user_with_env`].
///
/// # Errors
///
/// As [`recorded_user_with_env`].
pub(crate) fn recorded_user(
    server: UserServer,
    compose_dir: &Path,
    messages: &Messages,
) -> Result<Option<ContainerUser>> {
    recorded_user_with_env(
        server,
        compose_dir,
        exported_user(server).as_deref(),
        messages,
    )
}

/// Returns the process environment's value of `server`'s variable,
/// `Some("")` when it is exported empty and `None` only when it is not
/// exported.
///
/// An empty export is kept apart from an absent one because Docker
/// Compose keeps them apart: an exported empty value still wins over
/// `.env`. A value that is not valid UTF-8 is carried lossily, so it can
/// match no record and is refused rather than ignored.
pub(crate) fn exported_user(server: UserServer) -> Option<String> {
    std::env::var_os(server.env_key()).map(|value| value.to_string_lossy().into_owned())
}

/// [`recorded_user`] with the process environment's value of `server`'s
/// variable passed in.
///
/// A missing `.env`, a missing key and an empty value all mean unset, as
/// for the host-port keys.
///
/// # Errors
///
/// Returns an error naming `.env` and the variable when the recorded
/// value is malformed, one naming both values when `process_env` is
/// non-empty and differs from the record, and one when `process_env` is
/// empty while a value is recorded.
pub(crate) fn recorded_user_with_env(
    server: UserServer,
    compose_dir: &Path,
    process_env: Option<&str>,
    messages: &Messages,
) -> Result<Option<ContainerUser>> {
    let env_path = compose_dir.join(".env").display().to_string();
    let recorded =
        match read_env_file_value(compose_dir, server.env_key()) {
            Some(raw) => Some(parse(&raw).ok_or_else(|| {
                anyhow::anyhow!(server.recorded_invalid(messages, &env_path, &raw))
            })?),
            None => None,
        };
    check_process_env(server, process_env, recorded, &env_path, messages)?;
    Ok(recorded)
}

/// Resolves the user one `infra install` acts on for `server`: the flag
/// when given, else the value `.env` records.
///
/// Run before any side effect, so a refused value leaves nothing written.
/// With the flag, a malformed recorded value is not read: the install
/// replaces it.
///
/// # Errors
///
/// Returns the flag's refusal, the recorded value's refusal, or the
/// process-environment refusal of [`recorded_user_with_env`].
pub(crate) fn install_user_with_env(
    server: UserServer,
    compose_dir: &Path,
    flag: Option<&str>,
    process_env: Option<&str>,
    messages: &Messages,
) -> Result<Option<ContainerUser>> {
    let Some(flag) = flag else {
        return recorded_user_with_env(server, compose_dir, process_env, messages);
    };
    let user = parse_user_flag(server, flag, messages)?;
    let env_path = compose_dir.join(".env").display().to_string();
    check_process_env(server, process_env, Some(user), &env_path, messages)?;
    Ok(Some(user))
}

/// Refuses an exported variable that Docker Compose would prefer to
/// `expected`, so that the server would run as a uid bootroot did not
/// hand its files to: a non-empty value that differs from it, and an
/// empty one while a value is recorded, which Compose passes on as empty
/// and the entrypoint reads as "run as the image's own user".
fn check_process_env(
    server: UserServer,
    process_env: Option<&str>,
    expected: Option<ContainerUser>,
    env_path: &str,
    messages: &Messages,
) -> Result<()> {
    let Some(exported) = process_env else {
        return Ok(());
    };
    if exported.is_empty() {
        return match expected {
            Some(expected) => {
                anyhow::bail!(server.env_empty(messages, env_path, &expected.to_string()))
            }
            None => Ok(()),
        };
    }
    match expected {
        Some(expected) if parse(exported) == Some(expected) => Ok(()),
        Some(expected) => {
            anyhow::bail!(server.env_mismatch(messages, exported, env_path, &expected.to_string()))
        }
        None => anyhow::bail!(server.env_unrecorded(messages, exported, env_path)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::i18n::test_messages;

    // The OpenBao tests below predate PostgreSQL's option and are kept as
    // they were, through these shims over the generalised functions.
    type OpenBaoUser = ContainerUser;

    fn parse_openbao_user_flag(raw: &str, messages: &Messages) -> Result<ContainerUser> {
        parse_user_flag(UserServer::OpenBao, raw, messages)
    }

    fn recorded_openbao_user_with_env(
        compose_dir: &Path,
        process_env: Option<&str>,
        messages: &Messages,
    ) -> Result<Option<ContainerUser>> {
        recorded_user_with_env(UserServer::OpenBao, compose_dir, process_env, messages)
    }

    fn install_openbao_user_with_env(
        compose_dir: &Path,
        flag: Option<&str>,
        process_env: Option<&str>,
        messages: &Messages,
    ) -> Result<Option<ContainerUser>> {
        install_user_with_env(
            UserServer::OpenBao,
            compose_dir,
            flag,
            process_env,
            messages,
        )
    }

    #[test]
    fn parse_accepts_canonical_and_padded_values() {
        assert_eq!(parse("1:1"), Some(OpenBaoUser { uid: 1, gid: 1 }));
        assert_eq!(parse(" 1:1 "), Some(OpenBaoUser { uid: 1, gid: 1 }));
        assert_eq!(
            parse("01:02").map(|user| user.to_string()).as_deref(),
            Some("1:2")
        );
        assert_eq!(
            parse("4294967294:4294967294"),
            Some(OpenBaoUser {
                uid: 4_294_967_294,
                gid: 4_294_967_294
            })
        );
    }

    #[test]
    fn parse_refuses_each_invalid_form() {
        for raw in [
            "0:1",
            "1:0",
            "4294967295:1",
            "1:4294967295",
            "4294967296:1",
            "a:1",
            "1",
            "1:2:3",
            "+1:1",
            "-1:1",
            "1 :1",
            "1: 1",
            ":1",
            "1:",
            "",
            "   ",
            "root:root",
        ] {
            assert_eq!(parse(raw), None, "{raw:?} must be refused");
        }
    }

    #[test]
    fn the_flag_refusal_names_the_option_and_the_rule() {
        let messages = test_messages();
        for raw in [
            "0:1",
            "1:0",
            "4294967295:1",
            "a:1",
            "1",
            "1:2:3",
            "+1:1",
            "",
        ] {
            let error = parse_openbao_user_flag(raw, &messages)
                .expect_err("an invalid value must be refused")
                .to_string();
            assert!(error.contains("--openbao-user"), "{error}");
            assert!(error.contains("4294967294"), "{error}");
        }
    }

    #[test]
    fn the_recorded_value_is_read_from_env_and_canonicalised() {
        let dir = tempfile::tempdir().unwrap();
        let messages = test_messages();
        assert_eq!(
            recorded_openbao_user_with_env(dir.path(), None, &messages).unwrap(),
            None,
            "a missing .env is unset"
        );
        fs::write(dir.path().join(".env"), "BOOTROOT_OPENBAO_USER=\n").unwrap();
        assert_eq!(
            recorded_openbao_user_with_env(dir.path(), None, &messages).unwrap(),
            None,
            "an empty value is unset"
        );
        fs::write(dir.path().join(".env"), "BOOTROOT_OPENBAO_USER=\"01:02\"\n").unwrap();
        assert_eq!(
            recorded_openbao_user_with_env(dir.path(), None, &messages)
                .unwrap()
                .map(|user| user.to_string())
                .as_deref(),
            Some("1:2")
        );
    }

    #[test]
    fn a_malformed_recorded_value_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let messages = test_messages();
        fs::write(dir.path().join(".env"), "BOOTROOT_OPENBAO_USER=0:0\n").unwrap();
        let error = recorded_openbao_user_with_env(dir.path(), None, &messages)
            .expect_err("a malformed value must be refused")
            .to_string();
        assert!(error.contains(".env"), "{error}");
        assert!(error.contains(OPENBAO_USER_ENV_KEY), "{error}");
        assert!(error.contains("0:0"), "{error}");
    }

    #[test]
    fn an_exported_value_that_differs_from_env_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let messages = test_messages();
        fs::write(dir.path().join(".env"), "BOOTROOT_OPENBAO_USER=1:2\n").unwrap();

        // Equal, also when spelled differently: accepted.
        for exported in ["1:2", "01:2"] {
            assert!(
                recorded_openbao_user_with_env(dir.path(), Some(exported), &messages).is_ok(),
                "{exported:?} must be accepted"
            );
        }
        // Exported empty: Compose would pass the empty value on and start
        // OpenBao as the image's user, so it is refused too.
        let error = recorded_openbao_user_with_env(dir.path(), Some(""), &messages)
            .expect_err("an exported empty value must be refused while one is recorded")
            .to_string();
        assert!(error.contains("1:2"), "{error}");
        assert!(error.contains(OPENBAO_USER_ENV_KEY), "{error}");
        assert!(error.contains(".env"), "{error}");
        for exported in ["3:4", "garbage"] {
            let error = recorded_openbao_user_with_env(dir.path(), Some(exported), &messages)
                .expect_err("a differing exported value must be refused")
                .to_string();
            assert!(error.contains(exported), "{error}");
            assert!(error.contains("1:2"), "{error}");
            assert!(error.contains(OPENBAO_USER_ENV_KEY), "{error}");
        }

        // Exported with nothing recorded: refused too, unless it is empty,
        // which Compose reads as unset just as the missing record is.
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            recorded_openbao_user_with_env(empty.path(), Some(""), &messages).unwrap(),
            None
        );
        let error = recorded_openbao_user_with_env(empty.path(), Some("3:4"), &messages)
            .expect_err("an exported value with no record must be refused")
            .to_string();
        assert!(error.contains("3:4"), "{error}");
    }

    #[test]
    fn install_prefers_the_flag_and_checks_it_against_the_environment() {
        let dir = tempfile::tempdir().unwrap();
        let messages = test_messages();
        // A malformed record is replaced by the flag, not read.
        fs::write(dir.path().join(".env"), "BOOTROOT_OPENBAO_USER=bad\n").unwrap();
        assert_eq!(
            install_openbao_user_with_env(dir.path(), Some("5:6"), None, &messages)
                .unwrap()
                .map(|user| user.to_string())
                .as_deref(),
            Some("5:6")
        );
        assert!(install_openbao_user_with_env(dir.path(), None, None, &messages).is_err());
        assert!(
            install_openbao_user_with_env(dir.path(), Some("5:6"), Some("5:7"), &messages).is_err()
        );
        assert!(
            install_openbao_user_with_env(dir.path(), Some("5:6"), Some("5:6"), &messages).is_ok()
        );
        assert!(
            install_openbao_user_with_env(dir.path(), Some("5:6"), Some(""), &messages).is_err()
        );
    }

    /// `--postgres-user` takes `--openbao-user`'s rule, and its refusal
    /// names its own option.
    #[test]
    fn the_postgres_flag_refusal_names_its_own_option() {
        let messages = test_messages();
        assert_eq!(
            parse_user_flag(UserServer::Postgres, "01:02", &messages)
                .unwrap()
                .to_string(),
            "1:2"
        );
        for raw in [
            "0:1",
            "1:0",
            "4294967295:1",
            "a:1",
            "1",
            "1:2:3",
            "+1:1",
            "-1:1",
            "",
        ] {
            let error = parse_user_flag(UserServer::Postgres, raw, &messages)
                .expect_err("an invalid value must be refused")
                .to_string();
            assert!(error.contains("--postgres-user"), "{error}");
            assert!(!error.contains("--openbao-user"), "{error}");
            assert!(error.contains("4294967294"), "{error}");
        }
    }

    /// The `PostgreSQL` record lives under its own key and is read apart
    /// from `OpenBao`'s: neither value is taken for the other.
    #[test]
    fn the_postgres_record_is_read_from_its_own_key() {
        let dir = tempfile::tempdir().unwrap();
        let messages = test_messages();
        fs::write(dir.path().join(".env"), "BOOTROOT_OPENBAO_USER=1:2\n").unwrap();
        assert_eq!(
            recorded_user_with_env(UserServer::Postgres, dir.path(), None, &messages).unwrap(),
            None
        );
        fs::write(
            dir.path().join(".env"),
            "BOOTROOT_OPENBAO_USER=1:2\nBOOTROOT_POSTGRES_USER=\"03:4\"\n",
        )
        .unwrap();
        assert_eq!(
            recorded_user_with_env(UserServer::Postgres, dir.path(), None, &messages)
                .unwrap()
                .map(|user| user.to_string())
                .as_deref(),
            Some("3:4")
        );
        assert_eq!(
            recorded_user_with_env(UserServer::OpenBao, dir.path(), None, &messages)
                .unwrap()
                .map(|user| user.to_string())
                .as_deref(),
            Some("1:2")
        );

        fs::write(dir.path().join(".env"), "BOOTROOT_POSTGRES_USER=postgres\n").unwrap();
        let error = recorded_user_with_env(UserServer::Postgres, dir.path(), None, &messages)
            .expect_err("a malformed value must be refused")
            .to_string();
        assert!(error.contains(POSTGRES_USER_ENV_KEY), "{error}");
        assert!(error.contains(".env"), "{error}");
        assert!(error.contains("--postgres-user"), "{error}");
        assert!(
            recorded_user_with_env(UserServer::OpenBao, dir.path(), None, &messages).is_ok(),
            "OpenBao's reader does not read PostgreSQL's key"
        );
    }

    /// Each case of the exported-value check, for `PostgreSQL`'s variable.
    #[test]
    fn an_exported_postgres_user_that_compose_would_prefer_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let messages = test_messages();
        fs::write(dir.path().join(".env"), "BOOTROOT_POSTGRES_USER=1:2\n").unwrap();
        let read = |dir: &Path, exported: Option<&str>| {
            recorded_user_with_env(UserServer::Postgres, dir, exported, &messages)
        };

        for exported in [None, Some("1:2"), Some("01:2")] {
            assert!(read(dir.path(), exported).is_ok(), "{exported:?}");
        }
        let error = read(dir.path(), Some(""))
            .expect_err("an empty export while one is recorded")
            .to_string();
        assert!(
            error.contains(POSTGRES_USER_ENV_KEY) && error.contains("1:2"),
            "{error}"
        );
        assert!(error.contains("PostgreSQL"), "{error}");
        for exported in ["3:4", "garbage"] {
            let error = read(dir.path(), Some(exported))
                .expect_err("a differing export")
                .to_string();
            assert!(
                error.contains(POSTGRES_USER_ENV_KEY)
                    && error.contains(exported)
                    && error.contains("1:2"),
                "{error}"
            );
        }

        let empty = tempfile::tempdir().unwrap();
        assert_eq!(read(empty.path(), Some("")).unwrap(), None);
        let error = read(empty.path(), Some("3:4"))
            .expect_err("an export with nothing recorded")
            .to_string();
        assert!(
            error.contains(POSTGRES_USER_ENV_KEY) && error.contains("3:4"),
            "{error}"
        );

        // An exported OpenBao value says nothing about PostgreSQL's.
        assert!(
            recorded_user_with_env(UserServer::OpenBao, dir.path(), Some("9:9"), &messages)
                .is_err()
        );
        assert!(read(dir.path(), None).is_ok());
    }

    #[test]
    fn install_resolves_the_postgres_flag_against_its_own_record() {
        let dir = tempfile::tempdir().unwrap();
        let messages = test_messages();
        fs::write(dir.path().join(".env"), "BOOTROOT_POSTGRES_USER=bad\n").unwrap();
        let install = |flag: Option<&str>, exported: Option<&str>| {
            install_user_with_env(UserServer::Postgres, dir.path(), flag, exported, &messages)
        };
        assert_eq!(
            install(Some("5:6"), None)
                .unwrap()
                .map(|user| user.to_string())
                .as_deref(),
            Some("5:6")
        );
        assert!(install(None, None).is_err());
        assert!(install(Some("5:6"), Some("5:7")).is_err());
        assert!(install(Some("5:6"), Some("5:6")).is_ok());
        assert!(install(Some("5:6"), Some("")).is_err());
        let error = install(Some("0:0"), None).unwrap_err().to_string();
        assert!(error.contains("--postgres-user"), "{error}");
    }
}
