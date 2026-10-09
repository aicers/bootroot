//! The state lock as the `bootroot` CLI takes it: which commands
//! serialize on `state.json.lock`, which leave it alone, and what a
//! command does when the lock is held, stale, or cannot be opened.
//!
//! Every test here probes or holds the lock from this process.
//! `flock(2)` belongs to the open file description, so a descriptor
//! opened here contends with a `bootroot` child exactly as a second
//! `bootroot` would.

#![cfg(unix)]

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::Path;
use std::process::{Command, Output, Stdio};

use serde_json::json;
use tempfile::tempdir;

const SERVICE: &str = "edge-proxy";
const LOCK_FILE: &str = "state.json.lock";
const WAITING_LINE: &str = "Waiting for another bootroot command";

/// Writes a `state.json` holding one registered service.
fn write_state(root: &Path) {
    let state = json!({
        "openbao_url": "http://127.0.0.1:1",
        "kv_mount": "secret",
        "secrets_dir": "secrets",
        "policies": {},
        "approles": {},
        "services": {
            SERVICE: {
                "registration_id": SERVICE,
                "service_name": SERVICE,
                "delivery_mode": "remote-bootstrap",
                "hostname": "edge-node-01",
                "domain": "trusted.domain",
                "agent_config_path": "agent.toml",
                "cert_path": "certs/edge-proxy.crt",
                "key_path": "certs/edge-proxy.key",
                "instance_id": "001",
                "approle": {
                    "role_name": "bootroot-service-edge-proxy",
                    "role_id": "role-edge-proxy",
                    "secret_id_path": "secrets/services/edge-proxy/secret_id",
                    "policy_name": "bootroot-service-edge-proxy",
                    "secret_id_wrap_ttl": "0"
                }
            }
        }
    });
    fs::write(
        root.join("state.json"),
        serde_json::to_string_pretty(&state).expect("serialize state"),
    )
    .expect("write state.json");
}

fn bootroot(root: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
    command.current_dir(root).stdin(Stdio::null());
    command
}

fn service_update(root: &Path, registration_id: &str, ttl: &str) -> Command {
    let mut command = bootroot(root);
    command.args([
        "service",
        "update",
        "--registration-id",
        registration_id,
        "--secret-id-ttl",
        ttl,
    ]);
    command
}

fn recorded_ttl(root: &Path) -> serde_json::Value {
    let contents = fs::read_to_string(root.join("state.json")).expect("read state.json");
    let state: serde_json::Value = serde_json::from_str(&contents).expect("parse state.json");
    state["services"][SERVICE]["approle"]["secret_id_ttl"].clone()
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Whether some other descriptor holds the state lock in `root`.
fn lock_is_held(root: &Path) -> bool {
    let Ok(file) = fs::File::open(root.join(LOCK_FILE)) else {
        return false;
    };
    matches!(file.try_lock(), Err(fs::TryLockError::WouldBlock))
}

#[test]
fn an_uncontended_writer_creates_an_owner_only_lock_file_and_does_not_announce_a_wait() {
    let dir = tempdir().expect("tempdir");
    write_state(dir.path());

    let output = service_update(dir.path(), SERVICE, "12h")
        .output()
        .expect("run service update");

    assert!(output.status.success(), "stderr:\n{}", stderr_of(&output));
    assert!(
        !stderr_of(&output).contains(WAITING_LINE),
        "nothing held the lock, so nothing is waited for: {}",
        stderr_of(&output)
    );
    assert_eq!(recorded_ttl(dir.path()), "12h");
    let meta = fs::metadata(dir.path().join(LOCK_FILE)).expect("the lock file stays behind");
    assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    assert_eq!(meta.len(), 0);
    assert!(!lock_is_held(dir.path()), "the lock went with the process");
}

/// A second writer waits rather than fails while the lock is held, says
/// so once, writes nothing meanwhile, and proceeds on release.
#[test]
fn a_writer_waits_behind_a_held_lock_says_so_and_proceeds_on_release() {
    let dir = tempdir().expect("tempdir");
    write_state(dir.path());
    // A lock file left by an earlier command, held by "another command".
    let holder = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.path().join(LOCK_FILE))
        .expect("create the lock file");
    holder.lock().expect("hold the state lock");

    let mut child = service_update(dir.path(), SERVICE, "12h")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn service update");
    let mut stderr = BufReader::new(child.stderr.take().expect("piped stderr"));
    let mut first_line = String::new();
    // Blocks until the child says something: the waiting line is the
    // signal that it reached the lock, with no sleep on this side.
    stderr.read_line(&mut first_line).expect("read stderr");
    assert!(
        first_line.contains(WAITING_LINE) && first_line.contains(LOCK_FILE),
        "the waiting line names the lock file: {first_line:?}"
    );
    assert!(
        child.try_wait().expect("poll the child").is_none(),
        "the writer waits; it neither fails nor proceeds"
    );
    assert!(recorded_ttl(dir.path()).is_null(), "nothing written yet");

    drop(holder);

    let mut rest = String::new();
    stderr.read_to_string(&mut rest).expect("drain stderr");
    let status = child.wait().expect("wait for the child");
    assert!(status.success(), "stderr:\n{rest}");
    assert!(!rest.contains(WAITING_LINE), "said once: {rest}");
    assert_eq!(recorded_ttl(dir.path()), "12h");
}

/// A lock file nobody holds — what a killed command leaves — is not a
/// lock.
#[test]
fn a_stale_lock_file_blocks_nobody() {
    let dir = tempdir().expect("tempdir");
    write_state(dir.path());
    fs::write(dir.path().join(LOCK_FILE), "").expect("leave a stale lock file");

    let output = service_update(dir.path(), SERVICE, "12h")
        .output()
        .expect("run service update");

    assert!(output.status.success(), "stderr:\n{}", stderr_of(&output));
    assert!(!stderr_of(&output).contains(WAITING_LINE));
    assert!(dir.path().join(LOCK_FILE).exists());
}

/// A writer that fails after its load has released the lock by the time
/// it exits, and the next writer runs to completion.
#[test]
fn a_writer_that_fails_between_load_and_save_releases_the_lock() {
    let dir = tempdir().expect("tempdir");
    write_state(dir.path());

    let failed = service_update(dir.path(), "no-such-service", "12h")
        .output()
        .expect("run the failing service update");
    assert!(!failed.status.success());
    assert!(
        dir.path().join(LOCK_FILE).exists(),
        "the failure came after the lock was taken"
    );
    assert!(!lock_is_held(dir.path()));

    let next = service_update(dir.path(), SERVICE, "12h")
        .output()
        .expect("run the next service update");
    assert!(next.status.success(), "stderr:\n{}", stderr_of(&next));
    assert!(!stderr_of(&next).contains(WAITING_LINE));
    assert_eq!(recorded_ttl(dir.path()), "12h");
}

/// Readers take no lock: `service info` answers while a writer holds
/// it, and creates no lock file where there is none.
#[test]
fn service_info_neither_waits_for_the_lock_nor_creates_it() {
    let dir = tempdir().expect("tempdir");
    write_state(dir.path());
    let info = |root: &Path| {
        bootroot(root)
            .args(["service", "info", "--registration-id", SERVICE])
            .output()
            .expect("run service info")
    };

    let output = info(dir.path());
    assert!(output.status.success(), "stderr:\n{}", stderr_of(&output));
    assert!(!dir.path().join(LOCK_FILE).exists());

    let holder = fs::File::create(dir.path().join(LOCK_FILE)).expect("create the lock file");
    holder.lock().expect("hold the state lock");
    // Returns at all only because it does not wait for the lock.
    let output = info(dir.path());
    assert!(output.status.success(), "stderr:\n{}", stderr_of(&output));
    assert!(!stderr_of(&output).contains(WAITING_LINE));
}

/// A symbolic link at the lock file's own name is refused, not
/// followed.
#[test]
fn a_symlink_at_the_lock_name_fails_the_command_and_spares_its_target() {
    let dir = tempdir().expect("tempdir");
    write_state(dir.path());
    let target = dir.path().join("planted-target");
    symlink(&target, dir.path().join(LOCK_FILE)).expect("plant the link");

    let output = service_update(dir.path(), SERVICE, "12h")
        .output()
        .expect("run service update");

    assert!(!output.status.success());
    let stderr = stderr_of(&output);
    assert!(
        stderr.contains("opening the state lock") && stderr.contains(LOCK_FILE),
        "the error names the lock path: {stderr}"
    );
    assert!(!target.exists(), "the link's target is not created");
    assert!(recorded_ttl(dir.path()).is_null(), "nothing ran unlocked");
}

/// A command run where there is no `state.json` bails before the lock,
/// so the wrong directory is left without a lock file.
#[test]
fn a_missing_state_file_leaves_no_lock_file_behind() {
    let dir = tempdir().expect("tempdir");
    let commands: [&[&str]; 4] = [
        &[
            "service",
            "update",
            "--registration-id",
            SERVICE,
            "--secret-id-ttl",
            "12h",
        ],
        &["service", "remove", "--registration-id", SERVICE, "--yes"],
        &[
            "service",
            "add",
            "--registration-id",
            SERVICE,
            "--service-name",
            SERVICE,
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            "agent.toml",
            "--cert-path",
            "certs/edge-proxy.crt",
            "--key-path",
            "certs/edge-proxy.key",
            "--instance-id",
            "001",
            "--root-token",
            "root-token",
        ],
        &[
            "rotate",
            "--root-token",
            "root-token",
            "--yes",
            "approle-secret-id",
            "--all-services",
        ],
    ];

    for args in commands {
        let output = bootroot(dir.path()).args(args).output().expect("run");
        assert!(!output.status.success(), "{args:?} must fail");
        assert!(
            stderr_of(&output).contains("state.json not found"),
            "{args:?}: {}",
            stderr_of(&output)
        );
        assert!(
            !dir.path().join(LOCK_FILE).exists(),
            "{args:?} must not leave a lock file where there is no state"
        );
    }
}

/// `service add --dry-run` and `--print-only` write nothing and take no
/// lock: they answer while a writer holds it and create no lock file.
#[test]
fn service_add_previews_take_no_lock() {
    for flag in ["--dry-run", "--print-only"] {
        let dir = tempdir().expect("tempdir");
        write_state(dir.path());
        let preview = |root: &Path| {
            bootroot(root)
                .args([
                    "service",
                    "add",
                    flag,
                    "--registration-id",
                    "another",
                    "--service-name",
                    "another",
                    "--hostname",
                    "edge-node-01",
                    "--domain",
                    "trusted.domain",
                    "--agent-config",
                    "another.toml",
                    "--cert-path",
                    "certs/another.crt",
                    "--key-path",
                    "certs/another.key",
                    "--instance-id",
                    "001",
                ])
                .output()
                .expect("run service add")
        };

        let output = preview(dir.path());
        assert!(
            output.status.success(),
            "{flag}: stderr:\n{}",
            stderr_of(&output)
        );
        assert!(
            !dir.path().join(LOCK_FILE).exists(),
            "{flag} must create no lock file"
        );

        let holder = fs::File::create(dir.path().join(LOCK_FILE)).expect("create the lock file");
        holder.lock().expect("hold the state lock");
        let output = preview(dir.path());
        assert!(
            output.status.success(),
            "{flag}: stderr:\n{}",
            stderr_of(&output)
        );
        assert!(!stderr_of(&output).contains(WAITING_LINE));
    }
}

/// The `rotate` subcommands that only read `state.json` take no lock.
///
/// Each is pointed at an `OpenBao` address nothing listens on, so it
/// fails at the health check — which is after the state load, the point
/// the two saving subcommands take the lock at. `approle-secret-id`
/// fails the same way and does leave the lock file, which is what shows
/// the others were given the chance to.
#[test]
fn only_the_saving_rotate_subcommands_take_the_lock() {
    let reading: [&[&str]; 5] = [
        &["stepca-password"],
        &["responder-hmac"],
        &["trust-sync"],
        &["eab-clear"],
        &["force-reissue", "--registration-id", SERVICE],
    ];
    let rotate = |root: &Path, subcommand: &[&str]| {
        bootroot(root)
            .args(["rotate", "--root-token", "root-token", "--yes"])
            .args(subcommand)
            .output()
            .expect("run rotate")
    };

    for subcommand in reading {
        let dir = tempdir().expect("tempdir");
        write_state(dir.path());
        let output = rotate(dir.path(), subcommand);
        assert!(!output.status.success(), "{subcommand:?} has no OpenBao");
        assert!(
            !stderr_of(&output).contains("state.json not found"),
            "{subcommand:?} got past the state check: {}",
            stderr_of(&output)
        );
        assert!(
            !dir.path().join(LOCK_FILE).exists(),
            "{subcommand:?} only reads state.json and must create no lock file"
        );
    }

    let dir = tempdir().expect("tempdir");
    write_state(dir.path());
    let output = rotate(dir.path(), &["approle-secret-id", "--all-services"]);
    assert!(!output.status.success());
    assert!(dir.path().join(LOCK_FILE).exists());
    assert!(!lock_is_held(dir.path()));
}

/// `rotate infra-cert` saves `state.json`, so it takes the lock — and a
/// state file reached through a symbolic link takes the lock beside the
/// link's target, the one a command naming the target directly takes.
#[test]
fn a_state_file_reached_through_a_symlink_locks_beside_its_target() {
    let dir = tempdir().expect("tempdir");
    let real = dir.path().join("real");
    let links = dir.path().join("links");
    fs::create_dir_all(&real).expect("create real dir");
    fs::create_dir_all(&links).expect("create links dir");
    write_state(&real);
    let link = links.join("state.json");
    symlink(real.join("state.json"), &link).expect("link the state file");
    let infra_cert = |state_file: &Path| {
        bootroot(dir.path())
            .args(["rotate", "--state-file"])
            .arg(state_file)
            .args(["--yes", "infra-cert"])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn rotate infra-cert")
    };

    let output = infra_cert(&link).wait_with_output().expect("run");
    assert!(output.status.success(), "stderr:\n{}", stderr_of(&output));
    assert!(real.join(LOCK_FILE).exists(), "locked beside the target");
    assert!(!links.join(LOCK_FILE).exists(), "not beside the link");

    // Held through the target's name, waited for through the link's.
    let holder = fs::File::open(real.join(LOCK_FILE)).expect("open the lock file");
    holder.lock().expect("hold the state lock");
    let mut child = infra_cert(&link);
    let mut stderr = BufReader::new(child.stderr.take().expect("piped stderr"));
    let mut first_line = String::new();
    stderr.read_line(&mut first_line).expect("read stderr");
    assert!(
        first_line.contains(WAITING_LINE),
        "the link and the target are one lock: {first_line:?}"
    );
    drop(holder);
    assert!(child.wait().expect("wait").success());
}

/// A fake `docker` that lets `reinit` through its teardown and its
/// `infra up`: no `OpenBao` container exists beforehand, and every
/// service asked about afterwards is running and healthy.
fn write_reinit_fake_docker(bin_dir: &Path) {
    let script = r#"#!/bin/sh
set -eu

case "${1:-}" in
  container)
    # `container inspect`: no pre-existing OpenBao container.
    exit 1
    ;;
  inspect)
    printf 'running|healthy\n'
    exit 0
    ;;
esac

for arg in "$@"; do
  if [ "$arg" = "ps" ]; then
    printf 'fake-container-id\n'
    exit 0
  fi
done

exit 0
"#;
    let path = bin_dir.join("docker");
    fs::write(&path, script).expect("write fake docker");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).expect("chmod fake docker");
}

/// `reinit` takes the state lock once and hands it to the `init` pass
/// it ends with. Were `init` to take it again, the second `flock` would
/// wait on the first forever and this test would never finish.
///
/// The run is steered through `reinit`'s own state writes and `infra
/// up` and into `init`, where a mock `OpenBao` that reports itself
/// already initialised stops it with `init`'s partial-init diagnostic:
/// an error only the `init` pass produces, after it has read
/// `state.json` under the lock `reinit` holds.
#[tokio::test(flavor = "multi_thread")]
async fn reinit_reaches_its_init_pass_without_taking_the_lock_twice() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let dir = tempdir().expect("tempdir");
    let root = dir.path();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.yml"),
        root.join("docker-compose.yml"),
    )
    .expect("copy the compose file");
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_reinit_fake_docker(&bin_dir);

    let openbao = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/seal-status"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sealed": false,
            "initialized": true,
            "t": 1,
            "n": 1,
            "progress": 0
        })))
        .mount(&openbao)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&openbao)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/sys/init"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "initialized": true })))
        .mount(&openbao)
        .await;
    // `reinit` refuses `--openbao-url`; the host port in `.env` is how
    // an install tells it where its OpenBao listens.
    fs::write(
        root.join(".env"),
        format!("OPENBAO_HOST_PORT={}\n", openbao.address().port()),
    )
    .expect("write .env");

    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = bootroot(root)
        .args(["reinit", "--yes"])
        .env("PATH", path_env)
        .env_remove("COMPOSE_PROJECT_NAME")
        .env_remove("OPENBAO_HOST_PORT")
        .env_remove("OPENBAO_ROOT_TOKEN")
        .output()
        .expect("run reinit");

    let stderr = stderr_of(&output);
    assert!(!output.status.success(), "the mock stops the init pass");
    assert!(
        stderr.contains("bootroot reinit failed") && stderr.contains("--openbao-only"),
        "reinit must fail inside its init pass, on the partial-init diagnostic: {stderr}"
    );
    assert!(
        !stderr.contains(WAITING_LINE),
        "the init pass must not wait for the lock reinit holds: {stderr}"
    );
    assert!(
        root.join("state.json").exists(),
        "reinit wrote its intermediate state under the lock"
    );
    assert!(root.join(LOCK_FILE).exists());
    assert!(!lock_is_held(root));
}
