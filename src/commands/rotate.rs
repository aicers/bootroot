mod approle;
mod ca;
mod db;
mod eab_clear;
mod helpers;
mod infra_cert;
mod openbao_recovery;
mod responder_hmac;
mod stepca_password;

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use crate::cli::args::{RotateArgs, RotateCommand};
use crate::commands::compose_project::DOCKER_BIN;
use crate::commands::init::{CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME};
use crate::commands::openbao_auth::{authenticate_openbao_client, resolve_runtime_auth};
use crate::i18n::Messages;
use crate::state::StateFile;

pub(super) const ROLE_ID_FILENAME: &str = "role_id";
/// Image the `step` helper containers run in the `rotate` flows. The
/// ownership sweep reuses it so it adds no dependency the flow did not
/// already have (unlike the compose step-ca *server* image, which is not
/// present on the air-gapped rotate host).
pub(super) const STEP_CA_HELPER_IMAGE: &str = "smallstep/step-ca:0.30.2";
pub(super) const ROOT_CA_COMMON_NAME: &str = "Bootroot Root CA";
pub(super) const INTERMEDIATE_CA_COMMON_NAME: &str = "Bootroot Intermediate CA";
pub(super) const RENDERED_FILE_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub(super) const RENDERED_FILE_TIMEOUT: Duration = Duration::from_mins(1);
pub(super) const OPENBAO_RECOVERY_SCOPE_UNSEAL_KEYS: &str = "unseal-keys";
pub(super) const OPENBAO_RECOVERY_SCOPE_ROOT_TOKEN: &str = "root-token";
pub(super) const OPENBAO_ROOT_ROTATION_INCOMPLETE_ERROR: &str =
    "OpenBao root-key rotation did not complete; verify unseal keys and retry";

/// Typed outcome of a `bootroot rotate` subcommand so the process
/// exit code can distinguish a completed rotation from a timed-out
/// `--wait` window. Routed up through `run_rotate` to `main`, where
/// `WaitTimedOut` maps to the GNU `timeout(1)` convention of 124.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RotateOutcome {
    Completed,
    WaitTimedOut,
}

#[derive(Debug, Clone)]
pub(super) struct StatePaths {
    secrets_dir: PathBuf,
}

impl StatePaths {
    fn new(secrets_dir: PathBuf) -> Self {
        Self { secrets_dir }
    }

    pub(super) fn secrets_dir(&self) -> &Path {
        &self.secrets_dir
    }

    pub(super) fn stepca_password(&self) -> PathBuf {
        self.secrets_dir.join("password.txt")
    }

    pub(super) fn stepca_password_new(&self) -> PathBuf {
        self.secrets_dir.join("password.txt.new")
    }

    pub(super) fn stepca_root_key(&self) -> PathBuf {
        self.secrets_dir.join("secrets").join("root_ca_key")
    }

    pub(super) fn stepca_intermediate_key(&self) -> PathBuf {
        self.secrets_dir.join("secrets").join("intermediate_ca_key")
    }

    pub(super) fn responder_config(&self) -> PathBuf {
        self.secrets_dir.join("responder").join("responder.toml")
    }

    pub(super) fn ca_json(&self) -> PathBuf {
        self.secrets_dir.join("config").join("ca.json")
    }

    pub(super) fn ca_certs_dir(&self) -> PathBuf {
        self.secrets_dir.join(CA_CERTS_DIR)
    }

    pub(super) fn root_cert(&self) -> PathBuf {
        self.ca_certs_dir().join(CA_ROOT_CERT_FILENAME)
    }

    pub(super) fn intermediate_cert(&self) -> PathBuf {
        self.ca_certs_dir().join(CA_INTERMEDIATE_CERT_FILENAME)
    }

    pub(super) fn root_cert_bak(&self) -> PathBuf {
        self.ca_certs_dir()
            .join(format!("{CA_ROOT_CERT_FILENAME}.bak"))
    }

    pub(super) fn root_key_bak(&self) -> PathBuf {
        self.secrets_dir.join("secrets").join("root_ca_key.bak")
    }

    pub(super) fn intermediate_cert_bak(&self) -> PathBuf {
        self.ca_certs_dir()
            .join(format!("{CA_INTERMEDIATE_CERT_FILENAME}.bak"))
    }

    pub(super) fn intermediate_key_bak(&self) -> PathBuf {
        self.secrets_dir
            .join("secrets")
            .join("intermediate_ca_key.bak")
    }
}

#[derive(Debug)]
pub(super) struct RotateContext {
    pub(super) openbao_url: String,
    pub(super) kv_mount: String,
    pub(super) compose_file: PathBuf,
    pub(super) state: StateFile,
    pub(super) paths: StatePaths,
    pub(super) state_dir: PathBuf,
    pub(super) state_file: PathBuf,
    /// The `docker` executable every spawn in this rotation runs.
    ///
    /// Set once in [`run_rotate_with_exec`] and only read afterwards, so
    /// a test that builds a context — or drives that entry point — can
    /// point the whole tree at a fake without touching `PATH`.
    pub(super) docker: PathBuf,
}

pub(crate) async fn run_rotate(args: &RotateArgs, messages: &Messages) -> Result<RotateOutcome> {
    run_rotate_with_exec(args, Path::new(DOCKER_BIN), messages).await
}

/// [`run_rotate`] with the `docker` executable supplied by the caller.
///
/// Mirrors the `_with_exec` pairs in [`crate::commands::infra`]: the
/// wrapper above is this function with [`DOCKER_BIN`], and a test
/// drives the whole entry point — state-file handling and strategy
/// normalisation included — against a fake it names by path.
#[allow(clippy::too_many_lines)]
async fn run_rotate_with_exec(
    args: &RotateArgs,
    docker: &Path,
    messages: &Messages,
) -> Result<RotateOutcome> {
    let state_path = args
        .state_file
        .clone()
        .unwrap_or_else(StateFile::default_path);
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;

    let openbao_url = args
        .openbao
        .openbao_url
        .clone()
        .unwrap_or_else(|| state.openbao_url.clone());
    let kv_mount = args
        .openbao
        .kv_mount
        .clone()
        .unwrap_or_else(|| state.kv_mount.clone());
    let secrets_dir = args
        .secrets_dir
        .secrets_dir
        .clone()
        .unwrap_or_else(|| state.secrets_dir().to_path_buf());
    let paths = StatePaths::new(secrets_dir.clone());
    let state_dir = state_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let mut ctx = RotateContext {
        openbao_url,
        kv_mount,
        compose_file: args.compose.compose_file.clone(),
        state,
        paths,
        state_dir,
        state_file: state_path,
        docker: docker.to_path_buf(),
    };

    // InfraCert operates on local files and Docker only — it must not
    // require an OpenBao connection so it can fix a broken/expired cert.
    if let RotateCommand::InfraCert(_) = &args.command {
        infra_cert::rotate_infra_certs(&mut ctx, args.yes, messages).await?;
        return Ok(RotateOutcome::Completed);
    }

    let runtime_auth = resolve_runtime_auth(&args.runtime_auth, true, messages)?;
    let mut client = OpenBaoClient::with_local_trust(&ctx.openbao_url, ctx.paths.secrets_dir())
        .with_context(|| messages.error_openbao_client_create_failed())?;
    authenticate_openbao_client(&mut client, &runtime_auth, messages).await?;
    client
        .health_check()
        .await
        .with_context(|| messages.error_openbao_health_check_failed())?;

    match &args.command {
        RotateCommand::StepcaPassword(step_args) => {
            stepca_password::rotate_stepca_password(
                &mut ctx, &client, step_args, args.yes, messages,
            )
            .await?;
        }
        RotateCommand::Db(step_args) => {
            db::rotate_db(&mut ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::ResponderHmac(step_args) => {
            responder_hmac::rotate_responder_hmac(&mut ctx, &client, step_args, args.yes, messages)
                .await?;
        }
        RotateCommand::OpenBaoRecovery(step_args) => {
            openbao_recovery::rotate_openbao_recovery(
                &client,
                step_args,
                args.yes,
                args.show_secrets,
                messages,
            )
            .await?;
        }
        RotateCommand::AppRoleSecretId(step_args) => {
            // The self-mint step replaces the on-disk credential file, so
            // it must know whether the secret_id actually came from a
            // file: inline/env values take precedence over the *_FILE
            // flag in resolve_runtime_auth, in which case there is no
            // file to replace.
            let secret_id_file = if args.runtime_auth.approle_secret_id.is_none() {
                args.runtime_auth.approle_secret_id_file.as_deref()
            } else {
                None
            };
            let auth = approle::RotateAuthContext {
                runtime_auth: &runtime_auth,
                secret_id_file,
            };
            approle::rotate_approle_secret_id(
                &mut ctx,
                &client,
                step_args,
                args.yes,
                &auth,
                args.show_secrets,
                messages,
            )
            .await?;
        }
        RotateCommand::TrustSync(_) => {
            ca::rotate_trust_sync(&mut ctx, &client, args.yes, messages).await?;
        }
        RotateCommand::ForceReissue(step_args) => {
            let outcome =
                ca::rotate_force_reissue(&mut ctx, &client, step_args, args.yes, messages).await?;
            return Ok(outcome);
        }
        RotateCommand::CaKey(step_args) => {
            ca::rotate_ca_key(&mut ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::InfraCert(_) => {
            unreachable!("InfraCert is handled before OpenBao client bootstrap")
        }
        RotateCommand::EabClear(_) => {
            eab_clear::rotate_eab_clear(&mut ctx, &client, args.yes, messages).await?;
        }
    }

    Ok(RotateOutcome::Completed)
}

/// Test harness for the `rotate` commands that shell out to `docker`.
///
/// It is private to this module and its descendants: a test names the
/// fake executable through the `docker` seam production already
/// carries, so nothing outside `rotate` reaches in here any more.
#[cfg(test)]
mod test_support {
    use std::fs;
    use std::path::Path;

    pub(super) use crate::i18n::test_messages;

    /// Writes a fake `docker` at `path` that appends one record per
    /// invocation to `args_log` and reads nothing from its environment.
    ///
    /// The log path is baked into the script text as it is written, so a
    /// test handing this executable to production through the `docker`
    /// seam gets its argv back without setting a single variable on this
    /// process — which is the point, since the test does not construct
    /// the `Command` that runs the fake.
    pub(super) fn write_self_contained_fake_docker(path: &Path, args_log: &Path) {
        write_self_contained_fake_docker_exiting(path, args_log, 0);
    }

    /// [`write_self_contained_fake_docker`] whose fake exits `exit_code`
    /// after logging, so a test can steer the failure path of a docker
    /// call it does not spawn itself.
    ///
    /// Each invocation appends its argument count and then exactly that
    /// many arguments, every field NUL-terminated: `docker restart c`
    /// appends `2\0restart\0c\0` and `docker a '' b` appends
    /// `3\0a\0\0b\0`. The record is framed by its count rather than
    /// delimited by a byte, so an empty argument stays an empty field
    /// and two invocations can never merge into one.
    /// [`decode_fake_docker_log`] reads it back.
    pub(super) fn write_self_contained_fake_docker_exiting(
        path: &Path,
        args_log: &Path,
        exit_code: u8,
    ) {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::PermissionsExt;

        // The script is assembled as bytes, not as a `String`: a Unix
        // path is an arbitrary NUL-free byte sequence, and rendering
        // `args_log` through `Display` would replace any byte that is
        // not valid UTF-8, pointing the fake at a different path that
        // nothing would ever create.
        let mut script = b"#!/bin/sh\nset -eu\nprintf '%s\\0' \"$#\" \"$@\" >> ".to_vec();
        script.extend_from_slice(&shell_single_quote(args_log.as_os_str().as_bytes()));
        script.extend_from_slice(format!("\nexit {exit_code}\n").as_bytes());
        fs::write(path, script).expect("fake docker script should be written");
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .expect("fake docker script should be executable");
    }

    /// Quotes `value` as a single POSIX shell word, byte for byte.
    ///
    /// A tempdir path may legally contain `'`, which ends the quoted
    /// word; the usual `'\''` dance closes, escapes and reopens it.
    /// Every other byte is copied through unchanged, so a path that is
    /// not UTF-8 reaches the script intact.
    fn shell_single_quote(value: &[u8]) -> Vec<u8> {
        let mut quoted = vec![b'\''];
        for byte in value {
            if *byte == b'\'' {
                quoted.extend_from_slice(br"'\''");
            } else {
                quoted.push(*byte);
            }
        }
        quoted.push(b'\'');
        quoted
    }

    /// Decodes a log written by [`write_self_contained_fake_docker`],
    /// returning one argument vector per invocation in call order.
    ///
    /// # Panics
    ///
    /// Panics if the log is unreadable or is not the framing the fake
    /// writes — a missing count, or a record the file ends inside.
    pub(super) fn decode_fake_docker_log(args_log: &Path) -> Vec<Vec<String>> {
        let bytes = fs::read(args_log).expect("fake docker log should be readable");
        if bytes.is_empty() {
            return Vec::new();
        }
        // Every field is NUL-terminated, so dropping the final
        // terminator leaves the fields themselves — including an empty
        // argument, which a terminator-less split would swallow.
        let body = bytes
            .strip_suffix(&[0])
            .expect("the fake terminates every field it writes");
        let mut fields = body.split(|byte| *byte == 0);
        let mut invocations = Vec::new();
        while let Some(count_field) = fields.next() {
            let count: usize = std::str::from_utf8(count_field)
                .expect("argument count must be UTF-8")
                .parse()
                .expect("argument count must be a decimal number");
            let argv: Vec<String> = fields
                .by_ref()
                .take(count)
                .map(|field| String::from_utf8_lossy(field).into_owned())
                .collect();
            assert_eq!(argv.len(), count, "the log ends inside a record");
            invocations.push(argv);
        }
        invocations
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use tempfile::tempdir;

    use super::test_support::{
        decode_fake_docker_log, write_self_contained_fake_docker,
        write_self_contained_fake_docker_exiting,
    };

    /// Runs the fake once with `args`, the way production would.
    fn run_fake(fake: &Path, args: &[&str]) {
        let status = Command::new(fake)
            .args(args)
            .status()
            .expect("the fake docker must be spawnable");
        assert!(status.success(), "the fake docker must exit 0");
    }

    /// A space-joined encoding cannot tell one argument holding a space
    /// from two arguments, which is exactly what the `--user <uid>:<gid>`
    /// assertion in `stepca_password` rests on.
    #[test]
    fn the_fake_docker_log_keeps_argument_boundaries() {
        let dir = tempdir().expect("tempdir");
        let split_log = dir.path().join("split.log");
        let joined_log = dir.path().join("joined.log");
        let split = dir.path().join("split-docker");
        let joined = dir.path().join("joined-docker");
        write_self_contained_fake_docker(&split, &split_log);
        write_self_contained_fake_docker(&joined, &joined_log);

        run_fake(&split, &["--user", "1000:1000"]);
        run_fake(&joined, &["--user 1000:1000"]);

        assert_eq!(
            decode_fake_docker_log(&split_log),
            [["--user", "1000:1000"]]
        );
        assert_eq!(decode_fake_docker_log(&joined_log), [["--user 1000:1000"]]);
        assert_ne!(
            decode_fake_docker_log(&split_log),
            decode_fake_docker_log(&joined_log)
        );
    }

    /// A multi-call flow must decode as its own invocations, in order,
    /// rather than as the last call or one merged record.
    #[test]
    fn the_fake_docker_log_keeps_every_invocation_in_order() {
        let dir = tempdir().expect("tempdir");
        let args_log = dir.path().join("docker_args.log");
        let fake = dir.path().join("fake-docker");
        write_self_contained_fake_docker(&fake, &args_log);

        run_fake(&fake, &["run", "first"]);
        run_fake(&fake, &["kill", "-s", "SIGHUP", "c"]);
        run_fake(&fake, &["restart", "c"]);

        assert_eq!(
            decode_fake_docker_log(&args_log),
            vec![
                vec!["run", "first"],
                vec!["kill", "-s", "SIGHUP", "c"],
                vec!["restart", "c"],
            ]
        );
    }

    /// The pair a doubled-NUL record terminator collapses: `["a", "",
    /// "b"]` once and `["a"]` then `["b"]` encode to the same bytes
    /// under that scheme, and must not under this one.
    #[test]
    fn the_fake_docker_log_frames_empty_arguments() {
        let dir = tempdir().expect("tempdir");
        let single_log = dir.path().join("single.log");
        let pair_log = dir.path().join("pair.log");
        let single = dir.path().join("single-docker");
        let pair = dir.path().join("pair-docker");
        write_self_contained_fake_docker(&single, &single_log);
        write_self_contained_fake_docker(&pair, &pair_log);

        run_fake(&single, &["a", "", "b"]);
        run_fake(&pair, &["a"]);
        run_fake(&pair, &["b"]);

        assert_eq!(decode_fake_docker_log(&single_log), [["a", "", "b"]]);
        assert_eq!(decode_fake_docker_log(&pair_log), [["a"], ["b"]]);
        assert_ne!(
            decode_fake_docker_log(&single_log),
            decode_fake_docker_log(&pair_log)
        );
    }

    /// An argument-less invocation is the degenerate record, `0\0`, and
    /// the count is the only thing that separates it from the next one:
    /// it contributes no fields of its own, so a decoder that scanned
    /// for a boundary instead of counting would swallow the record after
    /// it.
    #[test]
    fn the_fake_docker_log_frames_an_argument_less_invocation() {
        let dir = tempdir().expect("tempdir");
        let args_log = dir.path().join("docker_args.log");
        let fake = dir.path().join("fake-docker");
        write_self_contained_fake_docker(&fake, &args_log);

        run_fake(&fake, &[]);
        run_fake(&fake, &["restart", "c"]);
        run_fake(&fake, &[]);

        assert_eq!(
            decode_fake_docker_log(&args_log),
            vec![vec![], vec!["restart".to_string(), "c".to_string()], vec![]]
        );
    }

    /// `tempfile::tempdir()` can legitimately hand back a path holding
    /// an apostrophe, so the helper quotes rather than rejects one.
    #[test]
    fn the_fake_docker_handles_a_quoted_log_path() {
        let dir = tempdir().expect("tempdir");
        let awkward = dir.path().join("it's a dir");
        fs::create_dir(&awkward).expect("create awkward dir");
        let args_log = awkward.join("docker args.log");
        let fake = dir.path().join("fake-docker");
        write_self_contained_fake_docker(&fake, &args_log);

        run_fake(&fake, &["restart", "c"]);

        assert_eq!(decode_fake_docker_log(&args_log), [["restart", "c"]]);
    }

    /// The redirect the fake is written with must hold the log path's
    /// own bytes. Rendering the path through `Display` instead replaces
    /// every byte that is not valid UTF-8 with `U+FFFD`, which silently
    /// aims the fake at a path nothing creates.
    ///
    /// This asserts on the script text rather than on running it, so it
    /// holds on filesystems that would refuse to create the name.
    #[test]
    fn the_fake_docker_script_embeds_the_log_path_verbatim() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempdir().expect("tempdir");
        let args_log = dir.path().join(OsStr::from_bytes(b"non\xffutf8.log"));
        let fake = dir.path().join("fake-docker");
        write_self_contained_fake_docker(&fake, &args_log);

        let script = fs::read(&fake).expect("the fake docker script should be readable");
        let expected = args_log.as_os_str().as_bytes();
        assert!(
            script
                .windows(expected.len())
                .any(|window| window == expected),
            "the script must redirect to the log path's own bytes"
        );
    }

    /// A Unix path is an arbitrary NUL-free byte sequence, so a tempdir
    /// rooted below one that is not UTF-8 — which `TMPDIR` can be — must
    /// still yield a fake that logs where the test reads.
    ///
    /// The name is only creatable where the filesystem takes it: APFS
    /// and other UTF-8-enforcing filesystems reject it with `EILSEQ`,
    /// and on those the property is unobservable rather than broken.
    #[test]
    fn the_fake_docker_handles_a_non_utf8_log_path() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = tempdir().expect("tempdir");
        let awkward = dir.path().join(OsStr::from_bytes(b"non\xffutf8"));
        if fs::create_dir(&awkward).is_err() {
            return;
        }
        let args_log = awkward.join("docker_args.log");
        let fake = dir.path().join("fake-docker");
        write_self_contained_fake_docker(&fake, &args_log);

        run_fake(&fake, &["restart", "c"]);

        assert_eq!(decode_fake_docker_log(&args_log), [["restart", "c"]]);
    }

    /// The baked-in exit code is what replaces the environment variable
    /// the shared `PATH` fake reads.
    #[test]
    fn the_fake_docker_reports_the_baked_in_exit_code() {
        let dir = tempdir().expect("tempdir");
        let args_log = dir.path().join("docker_args.log");
        let fake = dir.path().join("fake-docker");
        write_self_contained_fake_docker_exiting(&fake, &args_log, 7);

        let status = Command::new(&fake)
            .arg("run")
            .status()
            .expect("the fake docker must be spawnable");

        assert_eq!(status.code(), Some(7));
        assert_eq!(decode_fake_docker_log(&args_log), [["run"]]);
    }
}
