//! The host `uid:gid` `OpenBao` runs as when `infra install
//! --openbao-user` gave one.
//!
//! The value is recorded as `BOOTROOT_OPENBAO_USER` in the `.env` beside
//! the compose file, and both base compose files read it by
//! interpolation: the `openbao` entrypoint re-owns the raft volume and
//! the audit directory to it and drops to it with `su-exec`. bootroot
//! reads the same record wherever it hands `OpenBao` its TLS key or
//! checks that key, so every reader here fails closed on a value it
//! cannot parse: a guess would put the key in front of a uid the server
//! does not run as.

use std::fmt;
use std::path::Path;

use anyhow::Result;
use bootroot::host_port::read_env_file_value;

use crate::i18n::Messages;

/// `.env` key, and compose interpolation variable, carrying the
/// `uid:gid` `OpenBao` runs as.
pub(crate) const OPENBAO_USER_ENV_KEY: &str = "BOOTROOT_OPENBAO_USER";

/// The highest uid or gid accepted. `4294967295` is `(uid_t)-1`, which
/// `chown` reads as "leave unchanged".
const MAX_ID: u32 = u32::MAX - 1;

/// A host uid and gid `OpenBao` runs as, neither of them `0` nor
/// `4294967295`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OpenBaoUser {
    uid: u32,
    gid: u32,
}

impl OpenBaoUser {
    pub(crate) fn uid(self) -> u32 {
        self.uid
    }

    /// The owner `OpenBao`'s TLS key is handed to: the uid, with group
    /// `0`, which grants nothing at `0600` and keeps the key out of any
    /// host group.
    pub(crate) fn key_owner(self) -> String {
        format!("{}:0", self.uid)
    }
}

impl fmt::Display for OpenBaoUser {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.uid, self.gid)
    }
}

/// Parses `<uid>:<gid>`: two decimal numbers of ASCII digits separated by
/// one `:`, each from `1` to `4294967294`, surrounding whitespace
/// trimmed. Returns `None` for anything else.
fn parse(raw: &str) -> Option<OpenBaoUser> {
    let (uid, gid) = raw.trim().split_once(':')?;
    Some(OpenBaoUser {
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

/// Parses an `--openbao-user` value.
///
/// # Errors
///
/// Returns the operator-facing refusal naming the option and its rule
/// when `raw` is not a valid `<uid>:<gid>`.
pub(crate) fn parse_openbao_user_flag(raw: &str, messages: &Messages) -> Result<OpenBaoUser> {
    parse(raw).ok_or_else(|| anyhow::anyhow!(messages.error_openbao_user_invalid(raw.trim())))
}

/// Reads the `OpenBao` user recorded in `compose_dir/.env`, refusing a
/// malformed value and an exported `BOOTROOT_OPENBAO_USER` that Docker
/// Compose would prefer to it.
///
/// The one place this module reads the process environment; the logic is
/// [`recorded_openbao_user_with_env`].
///
/// # Errors
///
/// As [`recorded_openbao_user_with_env`].
pub(crate) fn recorded_openbao_user(
    compose_dir: &Path,
    messages: &Messages,
) -> Result<Option<OpenBaoUser>> {
    recorded_openbao_user_with_env(compose_dir, exported_openbao_user().as_deref(), messages)
}

/// Returns the process environment's `BOOTROOT_OPENBAO_USER`, `Some("")`
/// when it is exported empty and `None` only when it is not exported.
///
/// An empty export is kept apart from an absent one because Docker
/// Compose keeps them apart: an exported empty value still wins over
/// `.env`. A value that is not valid UTF-8 is carried lossily, so it can
/// match no record and is refused rather than ignored.
pub(crate) fn exported_openbao_user() -> Option<String> {
    std::env::var_os(OPENBAO_USER_ENV_KEY).map(|value| value.to_string_lossy().into_owned())
}

/// [`recorded_openbao_user`] with the process environment's value of
/// `BOOTROOT_OPENBAO_USER` passed in.
///
/// A missing `.env`, a missing key and an empty value all mean unset, as
/// for the host-port keys.
///
/// # Errors
///
/// Returns an error naming `.env` and `BOOTROOT_OPENBAO_USER` when the
/// recorded value is malformed, one naming both values when
/// `process_env` is non-empty and differs from the record, and one when
/// `process_env` is empty while a value is recorded.
pub(crate) fn recorded_openbao_user_with_env(
    compose_dir: &Path,
    process_env: Option<&str>,
    messages: &Messages,
) -> Result<Option<OpenBaoUser>> {
    let env_path = compose_dir.join(".env").display().to_string();
    let recorded = match read_env_file_value(compose_dir, OPENBAO_USER_ENV_KEY) {
        Some(raw) => Some(parse(&raw).ok_or_else(|| {
            anyhow::anyhow!(messages.error_openbao_user_recorded_invalid(&env_path, &raw))
        })?),
        None => None,
    };
    check_process_env(process_env, recorded, &env_path, messages)?;
    Ok(recorded)
}

/// Resolves the `OpenBao` user one `infra install` acts on: the flag when
/// given, else the value `.env` records.
///
/// Run before any side effect, so a refused value leaves nothing written.
/// With the flag, a malformed recorded value is not read: the install
/// replaces it.
///
/// # Errors
///
/// Returns the flag's refusal, the recorded value's refusal, or the
/// process-environment refusal of [`recorded_openbao_user_with_env`].
pub(crate) fn install_openbao_user_with_env(
    compose_dir: &Path,
    flag: Option<&str>,
    process_env: Option<&str>,
    messages: &Messages,
) -> Result<Option<OpenBaoUser>> {
    let Some(flag) = flag else {
        return recorded_openbao_user_with_env(compose_dir, process_env, messages);
    };
    let user = parse_openbao_user_flag(flag, messages)?;
    let env_path = compose_dir.join(".env").display().to_string();
    check_process_env(process_env, Some(user), &env_path, messages)?;
    Ok(Some(user))
}

/// Refuses an exported `BOOTROOT_OPENBAO_USER` that Docker Compose would
/// prefer to `expected`, so that `OpenBao` would run as a uid bootroot did
/// not hand its files to: a non-empty value that differs from it, and an
/// empty one while a value is recorded, which Compose passes on as empty
/// and the entrypoint reads as "run as the image's `openbao` user".
fn check_process_env(
    process_env: Option<&str>,
    expected: Option<OpenBaoUser>,
    env_path: &str,
    messages: &Messages,
) -> Result<()> {
    let Some(exported) = process_env else {
        return Ok(());
    };
    if exported.is_empty() {
        return match expected {
            Some(expected) => anyhow::bail!(
                messages.error_openbao_user_env_empty(env_path, &expected.to_string())
            ),
            None => Ok(()),
        };
    }
    match expected {
        Some(expected) if parse(exported) == Some(expected) => Ok(()),
        Some(expected) => anyhow::bail!(messages.error_openbao_user_env_mismatch(
            exported,
            env_path,
            &expected.to_string()
        )),
        None => anyhow::bail!(messages.error_openbao_user_env_unrecorded(exported, env_path)),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::i18n::test_messages;

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
}
