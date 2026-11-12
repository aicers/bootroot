use std::process::Command;

#[cfg(unix)]
mod support;

#[cfg(unix)]
mod status_helpers {
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    pub(super) async fn stub_openbao_health(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/v1/sys/health"))
            .respond_with(ResponseTemplate::new(200))
            .mount(server)
            .await;
    }

    pub(super) async fn stub_openbao_seal_status(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/v1/sys/seal-status"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sealed": false
            })))
            .mount(server)
            .await;
    }

    pub(super) async fn stub_kv_mount_invalid(server: &MockServer, token: &str) {
        Mock::given(method("GET"))
            .and(path("/v1/sys/mounts/secret"))
            .and(header("X-Vault-Token", token))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": {
                    "type": "transit",
                    "options": {}
                }
            })))
            .mount(server)
            .await;
    }

    pub(super) async fn stub_kv_missing_paths(server: &MockServer, token: &str) {
        for secret in [
            "bootroot/stepca/password",
            "bootroot/stepca/db",
            "bootroot/responder/hmac",
            "bootroot/agent/eab",
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/v1/secret/metadata/{secret}")))
                .and(header("X-Vault-Token", token))
                .respond_with(ResponseTemplate::new(404))
                .mount(server)
                .await;
        }
    }

    pub(super) async fn stub_approles_missing(server: &MockServer, token: &str) {
        for role in [
            "bootroot-agent-role",
            "bootroot-responder-role",
            "bootroot-stepca-role",
        ] {
            Mock::given(method("GET"))
                .and(path(format!("/v1/auth/approle/role/{role}")))
                .and(header("X-Vault-Token", token))
                .respond_with(ResponseTemplate::new(404))
                .mount(server)
                .await;
        }
    }
}

fn run(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .args(args)
        .output()
        .expect("bootroot binary runs in tests");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

fn run_with_env(args: &[&str], key: &str, value: &str) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .args(args)
        .env(key, value)
        .output()
        .expect("bootroot binary runs in tests");
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

#[test]
fn test_help_lists_subcommands() {
    let (stdout, _stderr, code) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("infra"));
    assert!(stdout.contains("init"));
    assert!(stdout.contains("status"));
    assert!(stdout.contains("service"));
    assert!(stdout.contains("verify"));
}

/// Closes #735: every pre-flight confirmation flag is discoverable from
/// `init --help`, so an operator automating the install can find them.
#[test]
fn test_init_help_lists_preflight_confirmation_flags() {
    let (stdout, _stderr, code) = run(&["init", "--help"]);
    assert_eq!(code, 0);
    for flag in [
        "--overwrite-password",
        "--overwrite-ca-json",
        "--overwrite-state",
        "--confirm-db-provision",
    ] {
        assert!(stdout.contains(flag), "init --help must document {flag}");
    }
}

#[test]
fn test_status_command_message() {
    let (stdout, _stderr, code) = run(&["--help"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("status"));
}

/// Closes #745: `status` reaches Docker only through
/// `docker compose ps -q`, so the project recorded in the `.env` beside
/// the compose file is what decides whose containers it reports on. The
/// fake docker records its argv so the `-p <instance>` scoping is
/// asserted directly rather than inferred from the summary text.
#[cfg(unix)]
#[tokio::test]
async fn test_status_scopes_compose_to_the_recorded_instance() {
    use std::env;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use anyhow::Context;
    use support::{ROOT_TOKEN, stub_openbao};
    use tempfile::tempdir;
    use wiremock::MockServer;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();
    // The identity `infra install --instance-name insight` would record.
    fs::write(temp_dir.path().join(".env"), "BOOTROOT_INSTANCE=insight\n")
        .context("write .env")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    let argv_log = temp_dir.path().join("docker-argv.log");
    let fake_docker = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >>"{log}"

if [ "${{1:-}}" = "compose" ]; then
  printf "cid-openbao"
  exit 0
fi

if [ "${{1:-}}" = "inspect" ]; then
  printf "running|healthy"
  exit 0
fi

exit 0
"#,
        log = argv_log.display()
    );
    let docker_path = bin_dir.join("docker");
    fs::write(&docker_path, fake_docker)
        .context("write fake docker")
        .unwrap();
    fs::set_permissions(&docker_path, fs::Permissions::from_mode(0o700))
        .context("chmod fake docker")
        .unwrap();

    let server = MockServer::start().await;
    stub_openbao(&server).await;
    write_state_with_service(temp_dir.path()).expect("write state");

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            &server.uri(),
            "--root-token",
            ROOT_TOKEN,
        ])
        .env("PATH", combined_path)
        // An unset override is what makes the recorded identity decide.
        .env_remove("COMPOSE_PROJECT_NAME")
        .output()
        .expect("run status");

    assert!(output.status.success());
    let argv = fs::read_to_string(&argv_log).expect("fake docker must have been invoked");
    let compose_lines: Vec<&str> = argv
        .lines()
        .filter(|line| line.starts_with("compose "))
        .collect();
    assert!(
        !compose_lines.is_empty(),
        "status must drive `docker compose`, got: {argv}"
    );
    for line in &compose_lines {
        assert!(
            line.contains("-p insight"),
            "every compose invocation must be scoped to the recorded instance: {line}"
        );
    }
}

/// Test-only fixture for driving `infra install` against a fake `docker`.
///
/// The unit tests cover the identity's halves separately — validation,
/// the `.env` upsert, the resolver's precedence, the argument
/// constructor.  What only an end-to-end run pins is that
/// `run_infra_install` wires them together in the right order: the
/// recorded identity is resolved before the `.env` write and ignores
/// `COMPOSE_PROJECT_NAME`, while the project the stack is brought up
/// under is resolved after it and honours the override.
#[cfg(unix)]
struct InstallHarness {
    dir: tempfile::TempDir,
    compose_file: std::path::PathBuf,
    bin_dir: std::path::PathBuf,
    argv_log: std::path::PathBuf,
    instance_env_log: std::path::PathBuf,
    openbao_user_env_log: std::path::PathBuf,
    postgres_user_env_log: std::path::PathBuf,
}

#[cfg(unix)]
impl InstallHarness {
    fn new() -> Self {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create temp dir");
        let compose_file = dir.path().join("docker-compose.yml");
        // No `ports:` at all, so the localhost-binding guardrail passes
        // and only the resolved `--openbao-host-port` is pre-bound.
        fs::write(&compose_file, "services:\n  openbao:\n    image: openbao\n")
            .expect("write compose file");

        let bin_dir = dir.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("create bin dir");
        let argv_log = dir.path().join("docker-argv.log");
        // Compose renders `container_name:` from `BOOTROOT_INSTANCE`, so
        // what the child process sees is as load-bearing as the argv.
        let instance_env_log = dir.path().join("docker-instance-env.log");
        let openbao_user_env_log = dir.path().join("docker-openbao-user-env.log");
        let postgres_user_env_log = dir.path().join("docker-postgres-user-env.log");
        let fake_docker = format!(
            r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >>"{log}"

if [ "${{1:-}}" = "compose" ]; then
  printf '%s\n' "${{BOOTROOT_INSTANCE-<unset>}}" >>"{env_log}"
  printf '%s\n' "${{BOOTROOT_OPENBAO_USER-<unset>}}" >>"{user_log}"
  printf '%s\n' "${{BOOTROOT_POSTGRES_USER-<unset>}}" >>"{postgres_user_log}"
  printf "cid-openbao"
  exit 0
fi

if [ "${{1:-}}" = "inspect" ]; then
  printf "running|healthy"
  exit 0
fi

exit 0
"#,
            log = argv_log.display(),
            env_log = instance_env_log.display(),
            user_log = openbao_user_env_log.display(),
            postgres_user_log = postgres_user_env_log.display()
        );
        let docker_path = bin_dir.join("docker");
        fs::write(&docker_path, fake_docker).expect("write fake docker");
        fs::set_permissions(&docker_path, fs::Permissions::from_mode(0o700))
            .expect("chmod fake docker");

        Self {
            dir,
            compose_file,
            bin_dir,
            argv_log,
            instance_env_log,
            openbao_user_env_log,
            postgres_user_env_log,
        }
    }

    /// Runs `infra install --services openbao` with `extra` appended and
    /// `BOOTROOT_OPENBAO_USER` set to `exported` (removed when `None`) in
    /// bootroot's own environment, returning the raw output.
    fn install_output(&self, extra: &[&str], exported: Option<&str>) -> std::process::Output {
        self.install_output_exporting(extra, "BOOTROOT_OPENBAO_USER", exported)
    }

    /// [`InstallHarness::install_output`] with `BOOTROOT_POSTGRES_USER`
    /// set to `exported` instead.
    fn install_output_postgres(
        &self,
        extra: &[&str],
        exported: Option<&str>,
    ) -> std::process::Output {
        self.install_output_exporting(extra, "BOOTROOT_POSTGRES_USER", exported)
    }

    /// Runs the install with `key` set to `exported` (removed when `None`)
    /// and the other server-user variable removed.
    fn install_output_exporting(
        &self,
        extra: &[&str],
        key: &str,
        exported: Option<&str>,
    ) -> std::process::Output {
        let path = std::env::var("PATH").unwrap_or_default();
        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
            .current_dir(self.dir.path())
            .args([
                "infra",
                "install",
                "--compose-file",
                self.compose_file.to_string_lossy().as_ref(),
                "--services",
                "openbao",
                "--openbao-host-port",
                &Self::free_port().to_string(),
            ])
            .args(extra)
            .env("PATH", format!("{}:{}", self.bin_dir.display(), path))
            .env_remove("COMPOSE_PROJECT_NAME")
            .env_remove("BOOTROOT_INSTANCE")
            .env_remove("BOOTROOT_OPENBAO_USER")
            .env_remove("BOOTROOT_POSTGRES_USER");
        if let Some(value) = exported {
            command.env(key, value);
        }
        command.output().expect("run infra install")
    }

    /// The `BOOTROOT_POSTGRES_USER` each `docker compose` subprocess saw.
    fn compose_postgres_user_env(&self) -> Vec<String> {
        std::fs::read_to_string(&self.postgres_user_env_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The `BOOTROOT_OPENBAO_USER` each `docker compose` subprocess saw.
    fn compose_openbao_user_env(&self) -> Vec<String> {
        std::fs::read_to_string(&self.openbao_user_env_log)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Picks a port that is free right now, so the install's host-port
    /// pre-bind does not collide with whatever the developer happens to
    /// be running.
    fn free_port() -> u16 {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port for probing");
        listener
            .local_addr()
            .expect("probe socket must have an address")
            .port()
    }

    fn install(&self, instance_name: Option<&str>, compose_project_name: Option<&str>) -> String {
        self.install_with_inherited_instance(instance_name, compose_project_name, None)
    }

    /// [`InstallHarness::install`] with an explicit `BOOTROOT_INSTANCE`
    /// exported into bootroot's own environment, so the test can pin
    /// that an inherited value never reaches Compose.
    fn install_with_inherited_instance(
        &self,
        instance_name: Option<&str>,
        compose_project_name: Option<&str>,
        inherited_instance: Option<&str>,
    ) -> String {
        let path = std::env::var("PATH").unwrap_or_default();
        let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
        command
            .current_dir(self.dir.path())
            .args([
                "infra",
                "install",
                "--compose-file",
                self.compose_file.to_string_lossy().as_ref(),
                "--services",
                "openbao",
                "--openbao-host-port",
                &Self::free_port().to_string(),
            ])
            .env("PATH", format!("{}:{}", self.bin_dir.display(), path));
        if let Some(instance_name) = instance_name {
            command.args(["--instance-name", instance_name]);
        }
        match compose_project_name {
            Some(value) => command.env("COMPOSE_PROJECT_NAME", value),
            None => command.env_remove("COMPOSE_PROJECT_NAME"),
        };
        match inherited_instance {
            Some(value) => command.env("BOOTROOT_INSTANCE", value),
            None => command.env_remove("BOOTROOT_INSTANCE"),
        };
        command
            .env_remove("BOOTROOT_OPENBAO_USER")
            .env_remove("BOOTROOT_POSTGRES_USER");

        let output = command.output().expect("run infra install");
        assert!(
            output.status.success(),
            "infra install failed: {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::read_to_string(&self.argv_log).expect("fake docker must have been invoked")
    }

    fn dotenv(&self) -> String {
        std::fs::read_to_string(self.dir.path().join(".env")).expect("install must write .env")
    }

    /// The `BOOTROOT_INSTANCE` each `docker compose` subprocess saw.
    fn compose_instance_env(&self) -> Vec<String> {
        std::fs::read_to_string(&self.instance_env_log)
            .expect("the fake docker must have logged a compose invocation")
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// Asserts every `docker compose` invocation the run made carried
    /// `-p <project>`.  A single hand-built vector would show up here as
    /// a compose line without the flag.
    fn assert_every_compose_scoped_to(argv: &str, project: &str) {
        let compose_lines: Vec<&str> = argv
            .lines()
            .filter(|line| line.starts_with("compose "))
            .collect();
        assert!(
            !compose_lines.is_empty(),
            "infra install must drive `docker compose`, got: {argv}"
        );
        for line in &compose_lines {
            assert!(
                line.contains(&format!("-p {project} ")),
                "every compose invocation must carry `-p {project}`: {line}"
            );
        }
    }
}

/// Closes #745: `infra install --instance-name insight` brings the stack
/// up under project `insight` and records the identity in the `.env`
/// beside the compose file.
#[cfg(unix)]
#[test]
fn test_infra_install_scopes_compose_to_the_declared_instance() {
    let harness = InstallHarness::new();
    let argv = harness.install(Some("insight"), None);
    InstallHarness::assert_every_compose_scoped_to(&argv, "insight");
    assert!(
        harness.dotenv().contains("BOOTROOT_INSTANCE=insight"),
        "the declared identity must be recorded, got: {}",
        harness.dotenv()
    );
    assert!(
        harness
            .compose_instance_env()
            .iter()
            .all(|value| value == "insight"),
        "every compose subprocess must render container names from the \
         declared identity, got: {:?}",
        harness.compose_instance_env()
    );
}

/// Closes #746: an inherited `BOOTROOT_INSTANCE` must never reach
/// Compose.  Compose reads the invoking environment ahead of the project
/// directory's `.env`, so without the pin the stack would come up under
/// another install's container names while `-p` still said `insight`.
#[cfg(unix)]
#[test]
fn test_infra_install_pins_the_recorded_instance_over_an_inherited_one() {
    let harness = InstallHarness::new();
    let argv = harness.install_with_inherited_instance(Some("insight"), None, Some("other"));
    InstallHarness::assert_every_compose_scoped_to(&argv, "insight");
    let seen = harness.compose_instance_env();
    assert!(
        !seen.is_empty() && seen.iter().all(|value| value == "insight"),
        "the inherited value must never reach Compose, got: {seen:?}"
    );
}

/// Closes #746: with an exported harness project the stack is scoped to
/// that project but the containers still follow the recorded identity —
/// the project name is not a valid instance name at all.
#[cfg(unix)]
#[test]
fn test_compose_project_override_does_not_rename_the_containers() {
    const HARNESS_PROJECT: &str = "bootroot-e2e-ci-openbao-tls-no-delta-1234567";
    let harness = InstallHarness::new();
    let argv = harness.install(None, Some(HARNESS_PROJECT));
    InstallHarness::assert_every_compose_scoped_to(&argv, HARNESS_PROJECT);
    let seen = harness.compose_instance_env();
    assert!(
        !seen.is_empty() && seen.iter().all(|value| value == "bootroot"),
        "container names follow the recorded instance, never the project, got: {seen:?}"
    );
}

/// Closes #745: with no flag and no override, the project is the fixed
/// literal `bootroot` — not the compose directory's basename, which
/// here is a random `tempdir` name.
#[cfg(unix)]
#[test]
fn test_infra_install_defaults_to_the_fixed_project() {
    let harness = InstallHarness::new();
    let argv = harness.install(None, None);
    InstallHarness::assert_every_compose_scoped_to(&argv, "bootroot");
    assert!(harness.dotenv().contains("BOOTROOT_INSTANCE=bootroot"));
}

/// Closes #745: an exported `COMPOSE_PROJECT_NAME` selects the project
/// for the invocation — verbatim, and without being validated against
/// the 39-character instance-name rule — but is never recorded, so the
/// `.env` still carries the identity the install would have had without
/// it.
#[cfg(unix)]
#[test]
fn test_infra_install_honours_compose_project_name_without_recording_it() {
    const HARNESS_PROJECT: &str = "bootroot-e2e-ci-openbao-tls-no-delta-1234567";
    assert!(HARNESS_PROJECT.len() > 39, "must exceed the instance limit");

    let harness = InstallHarness::new();
    let argv = harness.install(None, Some(HARNESS_PROJECT));
    InstallHarness::assert_every_compose_scoped_to(&argv, HARNESS_PROJECT);
    assert!(
        harness.dotenv().contains("BOOTROOT_INSTANCE=bootroot"),
        "the override must not become the identity, got: {}",
        harness.dotenv()
    );
}

/// Part of #846: an install may declare an identity and be scoped to a
/// project of another name at the same time.  The exported
/// `COMPOSE_PROJECT_NAME` decides the project — including for the
/// install itself, so the stack lands where every later command in that
/// same environment will look for it — while `--instance-name` decides
/// the recorded identity every container is named after.
///
/// This is what lets the E2E lifecycle harness derive the two
/// separately: a project longer than an instance name may legally be,
/// and an instance cut to the 39 characters `infra install` accepts.
#[cfg(unix)]
#[test]
fn test_infra_install_separates_the_declared_identity_from_the_project() {
    const RUN_PROJECT: &str = "bootroot-e2e-local-ci-local-no-hosts-19283746501-4242";
    assert!(RUN_PROJECT.len() > 39, "must exceed the instance limit");

    let harness = InstallHarness::new();
    let argv = harness.install(Some("insight"), Some(RUN_PROJECT));
    InstallHarness::assert_every_compose_scoped_to(&argv, RUN_PROJECT);
    assert!(
        harness.dotenv().contains("BOOTROOT_INSTANCE=insight"),
        "the declared identity must be recorded whatever the project, got: {}",
        harness.dotenv()
    );
    assert!(
        !harness.dotenv().contains(RUN_PROJECT),
        "the project override must not be recorded, got: {}",
        harness.dotenv()
    );
    assert!(
        harness
            .compose_instance_env()
            .iter()
            .all(|value| value == "insight"),
        "every compose subprocess must render container names from the \
         declared identity, not from the project, got: {:?}",
        harness.compose_instance_env()
    );
}

/// Runs `infra install --services openbao` while a sentinel holds the
/// resolved `OpenBao` host port, against a fake `docker` whose
/// `compose ... port openbao 8200` answers `127.0.0.1:<port>` only when
/// scoped to `-p <answering_project>` and fails otherwise, as Compose
/// does for a project with no running container.  Returns the output
/// and the fake's argv log.
#[cfg(unix)]
fn install_over_a_held_openbao_port(
    answering_project: &str,
    compose_project_name: Option<&str>,
) -> (std::process::Output, String) {
    use std::os::unix::fs::PermissionsExt;

    let harness = InstallHarness::new();
    let sentinel = std::net::TcpListener::bind("127.0.0.1:0").expect("bind sentinel");
    let port = sentinel.local_addr().expect("sentinel address").port();
    let fake_docker = format!(
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >>"{log}"

if [ "${{1:-}}" = "compose" ]; then
  case " $* " in
    *" port openbao 8200 "*)
      case " $* " in
        *" -p {answering_project} "*) printf '127.0.0.1:{port}\n'; exit 0 ;;
        *) echo "no container found for service openbao" >&2; exit 1 ;;
      esac ;;
  esac
  printf "cid-openbao"
  exit 0
fi

if [ "${{1:-}}" = "inspect" ]; then
  printf "running|healthy"
  exit 0
fi

exit 0
"#,
        log = harness.argv_log.display(),
    );
    let docker_path = harness.bin_dir.join("docker");
    std::fs::write(&docker_path, fake_docker).expect("write fake docker");
    std::fs::set_permissions(&docker_path, std::fs::Permissions::from_mode(0o700))
        .expect("chmod fake docker");

    let path = std::env::var("PATH").unwrap_or_default();
    let mut command = Command::new(env!("CARGO_BIN_EXE_bootroot"));
    command
        .current_dir(harness.dir.path())
        .args([
            "infra",
            "install",
            "--compose-file",
            harness.compose_file.to_string_lossy().as_ref(),
            "--services",
            "openbao",
            "--openbao-host-port",
            &port.to_string(),
            "--instance-name",
            "insight",
        ])
        .env("PATH", format!("{}:{}", harness.bin_dir.display(), path))
        .env_remove("BOOTROOT_INSTANCE")
        .env_remove("BOOTROOT_OPENBAO_USER")
        .env_remove("BOOTROOT_POSTGRES_USER");
    match compose_project_name {
        Some(value) => command.env("COMPOSE_PROJECT_NAME", value),
        None => command.env_remove("COMPOSE_PROJECT_NAME"),
    };
    let output = command.output().expect("run infra install");
    drop(sentinel);
    let argv = std::fs::read_to_string(&harness.argv_log).unwrap_or_default();
    (output, argv)
}

/// Part of #1202: a port the instance's own running container already
/// publishes is left to `docker compose up`, and the query that finds it
/// is scoped to the very project `up` acts on — here an exported
/// `COMPOSE_PROJECT_NAME`, not the declared instance.
#[cfg(unix)]
#[test]
fn test_infra_install_leaves_a_port_its_own_container_holds_to_compose() {
    const RUN_PROJECT: &str = "bootroot-e2e-rerun-project";
    let (output, argv) = install_over_a_held_openbao_port(RUN_PROJECT, Some(RUN_PROJECT));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "infra install must pass over its own container's port: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("is already published by this instance's running openbao container"),
        "the skip must be reported: {stdout}"
    );
    InstallHarness::assert_every_compose_scoped_to(&argv, RUN_PROJECT);
    assert!(
        argv.lines()
            .any(|line| line.starts_with("compose ") && line.ends_with(" port openbao 8200")),
        "the preflight must ask Compose about openbao's container port: {argv}"
    );
    assert!(
        argv.lines()
            .any(|line| line.starts_with("compose ") && line.contains(" up ")),
        "docker compose up must still run: {argv}"
    );
}

/// Part of #1202: the same port published by another project's
/// container — another instance's, say — is still refused with today's
/// message, before `docker compose up` runs.
#[cfg(unix)]
#[test]
fn test_infra_install_refuses_a_port_another_project_holds() {
    let (output, argv) = install_over_a_held_openbao_port("other-instance", None);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "infra install must refuse a port another project holds"
    );
    assert!(
        stderr.contains("is already in use") && stderr.contains("--openbao-host-port"),
        "today's message and remediation must be kept: {stderr}"
    );
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("is already published by"),
        "nothing must be reported as skipped"
    );
    InstallHarness::assert_every_compose_scoped_to(&argv, "insight");
    assert!(
        !argv
            .lines()
            .any(|line| line.starts_with("compose ") && line.contains(" up ")),
        "docker compose up must not run: {argv}"
    );
}

/// Closes #745: a re-run without the flag keeps the recorded identity
/// rather than resetting it to the default — while the generated
/// `PostgreSQL` password survives the upsert.
#[cfg(unix)]
#[test]
fn test_infra_install_rerun_preserves_the_recorded_instance() {
    let harness = InstallHarness::new();
    let argv = harness.install(Some("insight"), None);
    InstallHarness::assert_every_compose_scoped_to(&argv, "insight");

    let first_dotenv = harness.dotenv();
    let password = first_dotenv
        .lines()
        .find(|line| line.starts_with("POSTGRES_PASSWORD="))
        .expect("the first install must generate a PostgreSQL password")
        .to_string();

    let argv = harness.install(None, None);
    InstallHarness::assert_every_compose_scoped_to(&argv, "insight");

    let second_dotenv = harness.dotenv();
    assert_eq!(
        second_dotenv
            .lines()
            .filter(|line| line.starts_with("BOOTROOT_INSTANCE="))
            .count(),
        1,
        "the identity must be upserted, not duplicated: {second_dotenv}"
    );
    assert!(second_dotenv.contains("BOOTROOT_INSTANCE=insight"));
    assert!(
        second_dotenv.contains(&password),
        "the generated password must survive the re-run: {second_dotenv}"
    );
}

/// Closes #745: an invalid `--instance-name` is rejected with an error
/// naming the character set and the limit, and nothing is written.
#[cfg(unix)]
#[test]
fn test_infra_install_rejects_invalid_instance_names() {
    let long_name = "a".repeat(40);
    for invalid in ["Insight", "in sight", "-insight", "", long_name.as_str()] {
        let harness = InstallHarness::new();
        let path = std::env::var("PATH").unwrap_or_default();
        let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(harness.dir.path())
            .args([
                "infra",
                "install",
                "--compose-file",
                harness.compose_file.to_string_lossy().as_ref(),
                "--services",
                "openbao",
                "--instance-name",
                invalid,
            ])
            .env("PATH", format!("{}:{}", harness.bin_dir.display(), path))
            .env_remove("COMPOSE_PROJECT_NAME")
            .output()
            .expect("run infra install");

        assert!(!output.status.success(), "{invalid:?} must be rejected");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("39"),
            "{invalid:?} error must name the limit: {stderr}"
        );
        assert!(
            !harness.dir.path().join(".env").exists(),
            "{invalid:?} must not leave an .env behind"
        );
    }
}

/// An invalid `--openbao-user` is refused with the option's own error
/// before anything is written: no `.env`, no `secrets/`, no docker call.
#[cfg(unix)]
#[test]
fn test_infra_install_rejects_invalid_openbao_users() {
    for invalid in [
        "0:1",
        "1:0",
        "4294967295:1",
        "a:1",
        "1",
        "1:2:3",
        "+1:1",
        "",
    ] {
        let harness = InstallHarness::new();
        let output = harness.install_output(&["--openbao-user", invalid], None);
        assert!(!output.status.success(), "{invalid:?} must be rejected");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("--openbao-user") && stderr.contains("4294967294"),
            "{invalid:?} error must name the option and its rule: {stderr}"
        );
        for written in [".env", "secrets", "certs", "docker-argv.log"] {
            assert!(
                !harness.dir.path().join(written).exists(),
                "{invalid:?} must not leave {written} behind"
            );
        }
    }
}

/// `--openbao-user` is recorded in canonical form, handed to the install's
/// own `docker compose` subprocesses, and kept by a later install without
/// it; an install that never gave it records nothing.
#[cfg(unix)]
#[test]
fn test_infra_install_records_and_keeps_the_openbao_user() {
    let without = InstallHarness::new();
    let output = without.install_output(&[], None);
    assert!(output.status.success(), "{output:?}");
    assert!(!without.dotenv().contains("BOOTROOT_OPENBAO_USER"));
    assert!(
        without
            .compose_openbao_user_env()
            .iter()
            .all(|value| value == "<unset>"),
        "{:?}",
        without.compose_openbao_user_env()
    );

    let harness = InstallHarness::new();
    let output = harness.install_output(&["--openbao-user", " 01:02 "], None);
    assert!(output.status.success(), "{output:?}");
    assert!(
        harness.dotenv().contains("BOOTROOT_OPENBAO_USER=1:2\n"),
        "{}",
        harness.dotenv()
    );
    // As for the host-port flags, the `pull` and `up` the install runs
    // carry the flag's value, so it wins over an inherited shell variable.
    let argv = std::fs::read_to_string(&harness.argv_log).unwrap();
    let compose_lines: Vec<&str> = argv
        .lines()
        .filter(|line| line.starts_with("compose "))
        .collect();
    let seen = harness.compose_openbao_user_env();
    assert_eq!(compose_lines.len(), seen.len(), "{argv}\n{seen:?}");
    let up_and_pull: Vec<&String> = compose_lines
        .iter()
        .zip(&seen)
        .filter(|(line, _)| line.contains(" up ") || line.contains(" pull "))
        .map(|(_, value)| value)
        .collect();
    assert!(
        !up_and_pull.is_empty() && up_and_pull.iter().all(|value| *value == "1:2"),
        "compose pull and up must see the flag's value: {argv}\n{seen:?}"
    );

    let output = harness.install_output(&[], None);
    assert!(output.status.success(), "{output:?}");
    let dotenv = harness.dotenv();
    assert_eq!(
        dotenv.matches("BOOTROOT_OPENBAO_USER=").count(),
        1,
        "{dotenv}"
    );
    assert!(dotenv.contains("BOOTROOT_OPENBAO_USER=1:2\n"), "{dotenv}");
}

/// An exported `BOOTROOT_OPENBAO_USER` that differs from the value the
/// install records, or a malformed recorded value, is refused before any
/// docker command; an exported value equal to it is not.
#[cfg(unix)]
#[test]
fn test_infra_install_refuses_a_conflicting_openbao_user() {
    let harness = InstallHarness::new();
    let output = harness.install_output(&["--openbao-user", "1:2"], Some("3:4"));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("3:4") && stderr.contains("1:2"), "{stderr}");
    assert!(!harness.dir.path().join(".env").exists());
    assert!(!harness.dir.path().join("docker-argv.log").exists());

    let output = harness.install_output(&["--openbao-user", "1:2"], Some("1:2"));
    assert!(output.status.success(), "{output:?}");

    std::fs::write(
        harness.dir.path().join(".env"),
        harness
            .dotenv()
            .replace("BOOTROOT_OPENBAO_USER=1:2", "BOOTROOT_OPENBAO_USER=0:0"),
    )
    .unwrap();
    std::fs::remove_file(harness.dir.path().join("docker-argv.log")).unwrap();
    let output = harness.install_output(&[], None);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BOOTROOT_OPENBAO_USER") && stderr.contains(".env"),
        "{stderr}"
    );
    assert!(!harness.dir.path().join("docker-argv.log").exists());
}

/// `infra up` checks the recorded `BOOTROOT_OPENBAO_USER` against the
/// exported one on every stack, not only one with a non-loopback `OpenBao`
/// bind: on this loopback-only install an exported value that differs
/// from the record, or an exported empty one, is refused before any
/// docker command, since Compose would hand either to the entrypoint
/// that re-owns the raft volume.
#[cfg(unix)]
#[test]
fn test_infra_up_refuses_a_conflicting_openbao_user_without_tls() {
    let harness = InstallHarness::new();
    let output = harness.install_output(&["--openbao-user", "2001:2002"], None);
    assert!(output.status.success(), "{output:?}");
    assert!(!harness.dir.path().join("state.json").exists());
    let argv_log = harness.dir.path().join("docker-argv.log");

    for (exported, expected_in_stderr) in [("3001:3002", "3001:3002"), ("", "2001:2002")] {
        if argv_log.exists() {
            std::fs::remove_file(&argv_log).unwrap();
        }
        let path = std::env::var("PATH").unwrap_or_default();
        let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(harness.dir.path())
            .args([
                "infra",
                "up",
                "--compose-file",
                harness.compose_file.to_string_lossy().as_ref(),
                "--services",
                "openbao",
            ])
            .env("PATH", format!("{}:{}", harness.bin_dir.display(), path))
            .env_remove("COMPOSE_PROJECT_NAME")
            .env_remove("BOOTROOT_INSTANCE")
            .env_remove("OPENBAO_UNSEAL_FILE")
            .env("BOOTROOT_OPENBAO_USER", exported)
            .output()
            .expect("run infra up");
        assert!(!output.status.success(), "{exported:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("BOOTROOT_OPENBAO_USER") && stderr.contains(expected_in_stderr),
            "{exported:?}: {stderr}"
        );
        assert!(
            !argv_log.exists(),
            "{exported:?}: infra up must not reach docker: {}",
            std::fs::read_to_string(&argv_log).unwrap_or_default()
        );
    }
}

/// An invalid `--postgres-user` is refused with the option's own error
/// before anything is written: no `.env`, no `secrets/`, no docker call.
#[cfg(unix)]
#[test]
fn test_infra_install_rejects_invalid_postgres_users() {
    for invalid in [
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
        let harness = InstallHarness::new();
        let output = harness.install_output_postgres(&["--postgres-user", invalid], None);
        assert!(!output.status.success(), "{invalid:?} must be rejected");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("--postgres-user") && stderr.contains("4294967294"),
            "{invalid:?} error must name the option and its rule: {stderr}"
        );
        for written in [".env", "secrets", "certs", "docker-argv.log"] {
            assert!(
                !harness.dir.path().join(written).exists(),
                "{invalid:?} must not leave {written} behind"
            );
        }
    }
}

/// `--postgres-user` is recorded in canonical form under its own key,
/// handed to the install's own `docker compose` subprocesses, and kept by
/// a later install without it; an install that never gave it records
/// nothing, and `--openbao-user` is not touched by it.
#[cfg(unix)]
#[test]
fn test_infra_install_records_and_keeps_the_postgres_user() {
    let without = InstallHarness::new();
    let output = without.install_output_postgres(&[], None);
    assert!(output.status.success(), "{output:?}");
    assert!(!without.dotenv().contains("BOOTROOT_POSTGRES_USER"));
    assert!(
        without
            .compose_postgres_user_env()
            .iter()
            .all(|value| value == "<unset>"),
        "{:?}",
        without.compose_postgres_user_env()
    );

    let harness = InstallHarness::new();
    let output = harness.install_output_postgres(&["--postgres-user", " 03:04 "], None);
    assert!(output.status.success(), "{output:?}");
    let dotenv = harness.dotenv();
    assert!(dotenv.contains("BOOTROOT_POSTGRES_USER=3:4\n"), "{dotenv}");
    assert!(!dotenv.contains("BOOTROOT_OPENBAO_USER"), "{dotenv}");
    let argv = std::fs::read_to_string(&harness.argv_log).unwrap();
    let compose_lines: Vec<&str> = argv
        .lines()
        .filter(|line| line.starts_with("compose "))
        .collect();
    let seen = harness.compose_postgres_user_env();
    assert_eq!(compose_lines.len(), seen.len(), "{argv}\n{seen:?}");
    let up_and_pull: Vec<&String> = compose_lines
        .iter()
        .zip(&seen)
        .filter(|(line, _)| line.contains(" up ") || line.contains(" pull "))
        .map(|(_, value)| value)
        .collect();
    assert!(
        !up_and_pull.is_empty() && up_and_pull.iter().all(|value| *value == "3:4"),
        "compose pull and up must see the flag's value: {argv}\n{seen:?}"
    );

    let output = harness.install_output_postgres(&[], None);
    assert!(output.status.success(), "{output:?}");
    let dotenv = harness.dotenv();
    assert_eq!(
        dotenv.matches("BOOTROOT_POSTGRES_USER=").count(),
        1,
        "{dotenv}"
    );
    assert!(dotenv.contains("BOOTROOT_POSTGRES_USER=3:4\n"), "{dotenv}");
}

/// An exported `BOOTROOT_POSTGRES_USER` that differs from the value the
/// install records, an exported empty one while a value is recorded, or a
/// malformed recorded value, is refused before any docker command; an
/// exported value equal to it is not.
#[cfg(unix)]
#[test]
fn test_infra_install_refuses_a_conflicting_postgres_user() {
    let harness = InstallHarness::new();
    let output = harness.install_output_postgres(&["--postgres-user", "1:2"], Some("3:4"));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BOOTROOT_POSTGRES_USER")
            && stderr.contains("3:4")
            && stderr.contains("1:2"),
        "{stderr}"
    );
    assert!(!harness.dir.path().join(".env").exists());
    assert!(!harness.dir.path().join("docker-argv.log").exists());

    let output = harness.install_output_postgres(&["--postgres-user", "1:2"], Some("1:2"));
    assert!(output.status.success(), "{output:?}");

    std::fs::remove_file(harness.dir.path().join("docker-argv.log")).unwrap();
    let output = harness.install_output_postgres(&[], Some(""));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BOOTROOT_POSTGRES_USER") && stderr.contains("1:2"),
        "{stderr}"
    );
    assert!(!harness.dir.path().join("docker-argv.log").exists());

    std::fs::write(
        harness.dir.path().join(".env"),
        harness
            .dotenv()
            .replace("BOOTROOT_POSTGRES_USER=1:2", "BOOTROOT_POSTGRES_USER=0:0"),
    )
    .unwrap();
    let output = harness.install_output_postgres(&[], None);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("BOOTROOT_POSTGRES_USER") && stderr.contains(".env"),
        "{stderr}"
    );
    assert!(!harness.dir.path().join("docker-argv.log").exists());
}

/// `infra up` checks the recorded `BOOTROOT_POSTGRES_USER` against the
/// exported one on every stack, here one whose `--services` names only
/// `openbao`: an exported value that differs from the record, an exported
/// empty one, or one exported with nothing recorded, is refused before
/// any docker command.
#[cfg(unix)]
#[test]
fn test_infra_up_refuses_a_conflicting_postgres_user_without_tls() {
    let recorded = InstallHarness::new();
    let output = recorded.install_output_postgres(&["--postgres-user", "2001:2002"], None);
    assert!(output.status.success(), "{output:?}");
    let unrecorded = InstallHarness::new();
    let output = unrecorded.install_output_postgres(&[], None);
    assert!(output.status.success(), "{output:?}");

    for (harness, exported, expected_in_stderr) in [
        (&recorded, "3001:3002", "3001:3002"),
        (&recorded, "", "2001:2002"),
        (&unrecorded, "3001:3002", "3001:3002"),
    ] {
        assert!(!harness.dir.path().join("state.json").exists());
        let argv_log = harness.dir.path().join("docker-argv.log");
        if argv_log.exists() {
            std::fs::remove_file(&argv_log).unwrap();
        }
        let path = std::env::var("PATH").unwrap_or_default();
        let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(harness.dir.path())
            .args([
                "infra",
                "up",
                "--compose-file",
                harness.compose_file.to_string_lossy().as_ref(),
                "--services",
                "openbao",
            ])
            .env("PATH", format!("{}:{}", harness.bin_dir.display(), path))
            .env_remove("COMPOSE_PROJECT_NAME")
            .env_remove("BOOTROOT_INSTANCE")
            .env_remove("OPENBAO_UNSEAL_FILE")
            .env_remove("BOOTROOT_OPENBAO_USER")
            .env("BOOTROOT_POSTGRES_USER", exported)
            .output()
            .expect("run infra up");
        assert!(!output.status.success(), "{exported:?}: {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("BOOTROOT_POSTGRES_USER") && stderr.contains(expected_in_stderr),
            "{exported:?}: {stderr}"
        );
        assert!(
            !argv_log.exists(),
            "{exported:?}: infra up must not reach docker: {}",
            std::fs::read_to_string(&argv_log).unwrap_or_default()
        );
    }
}

/// A 39-character name is the boundary the limit is derived from, so it
/// must be accepted end to end rather than only by the validator.
#[cfg(unix)]
#[test]
fn test_infra_install_accepts_the_maximum_length_instance_name() {
    let name = "a".repeat(39);
    let harness = InstallHarness::new();
    let argv = harness.install(Some(&name), None);
    InstallHarness::assert_every_compose_scoped_to(&argv, &name);
    assert!(
        harness
            .dotenv()
            .contains(&format!("BOOTROOT_INSTANCE={name}"))
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_status_command_summary() {
    use std::env;
    use std::fs;

    use anyhow::Context;
    use support::{ROOT_TOKEN, stub_openbao, write_fake_docker};
    use tempfile::tempdir;
    use wiremock::MockServer;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    write_fake_docker(&bin_dir).expect("write fake docker");

    let server = MockServer::start().await;
    stub_openbao(&server).await;
    write_state_with_service(temp_dir.path()).expect("write state");

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            &server.uri(),
            "--root-token",
            ROOT_TOKEN,
        ])
        .env("PATH", combined_path)
        .output()
        .expect("run status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot status: summary"));
    assert!(stdout.contains("- infra:"));
    assert!(stdout.contains("- OpenBao:"));
    assert!(stdout.contains("- KV paths:"));
    assert!(stdout.contains("- AppRoles:"));
    assert!(stdout.contains("- services:"));
    assert!(stdout.contains("- edge-proxy delivery mode: local-file"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_status_command_reports_infra_failure() {
    use std::env;
    use std::fs;

    use anyhow::Context;
    use support::write_fake_docker_with_status;
    use tempfile::tempdir;
    use wiremock::MockServer;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    write_fake_docker_with_status(&bin_dir, "exited", "").expect("write fake docker");

    let server = MockServer::start().await;
    status_helpers::stub_openbao_health(&server).await;
    status_helpers::stub_openbao_seal_status(&server).await;

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            &server.uri(),
        ])
        .env("PATH", combined_path)
        .output()
        .expect("run status");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot status failed"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_status_command_reports_openbao_unreachable() {
    use std::env;
    use std::fs;

    use anyhow::Context;
    use support::write_fake_docker;
    use tempfile::tempdir;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    write_fake_docker(&bin_dir).expect("write fake docker");

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            "http://127.0.0.1:9",
        ])
        .env("PATH", combined_path)
        .output()
        .expect("run status");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot status failed"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_status_command_reports_unknown_without_token() {
    use std::env;
    use std::fs;

    use anyhow::Context;
    use support::write_fake_docker;
    use tempfile::tempdir;
    use wiremock::MockServer;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    write_fake_docker(&bin_dir).expect("write fake docker");

    let server = MockServer::start().await;
    status_helpers::stub_openbao_health(&server).await;
    status_helpers::stub_openbao_seal_status(&server).await;

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            &server.uri(),
        ])
        .env("PATH", combined_path)
        .output()
        .expect("run status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("unknown"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_status_command_reports_invalid_kv_mount() {
    use std::env;
    use std::fs;

    use anyhow::Context;
    use support::{ROOT_TOKEN, write_fake_docker};
    use tempfile::tempdir;
    use wiremock::MockServer;

    let temp_dir = tempdir().expect("create temp dir");
    let compose_file = temp_dir.path().join("docker-compose.yml");
    fs::write(&compose_file, "services: {}")
        .context("write compose file")
        .unwrap();

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir)
        .context("create bin dir")
        .unwrap();
    write_fake_docker(&bin_dir).expect("write fake docker");

    let server = MockServer::start().await;
    status_helpers::stub_openbao_health(&server).await;
    status_helpers::stub_openbao_seal_status(&server).await;
    status_helpers::stub_kv_mount_invalid(&server, ROOT_TOKEN).await;
    status_helpers::stub_kv_missing_paths(&server, ROOT_TOKEN).await;
    status_helpers::stub_approles_missing(&server, ROOT_TOKEN).await;

    let path = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{}", bin_dir.display(), path);

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "status",
            "--compose-file",
            compose_file.to_string_lossy().as_ref(),
            "--openbao-url",
            &server.uri(),
            "--root-token",
            ROOT_TOKEN,
        ])
        .env("PATH", combined_path)
        .output()
        .expect("run status");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("invalid"));
}

#[test]
fn test_status_command_message_korean() {
    let (stdout, _stderr, code) = run_with_env(&["--help"], "BOOTROOT_LANG", "ko");
    assert_eq!(code, 0);
    assert!(stdout.contains("status"));
}

#[cfg(unix)]
fn write_state_with_service(root: &std::path::Path) -> anyhow::Result<()> {
    let state = serde_json::json!({
        "openbao_url": "http://localhost:8200",
        "kv_mount": "secret",
        "secrets_dir": "secrets",
        "policies": {},
        "approles": {},
        "services": {
            "edge-proxy": {
                "registration_id": "edge-proxy",
                "service_name": "edge-proxy",
                "delivery_mode": "local-file",
                "hostname": "edge-node-01",
                "domain": "trusted.domain",
                "agent_config_path": "agent.toml",
                "cert_path": "certs/edge-proxy.crt",
                "key_path": "certs/edge-proxy.key",
                "instance_id": "001",
                "notes": null,
                "approle": {
                    "role_name": "bootroot-service-edge-proxy",
                    "role_id": "role-edge-proxy",
                    "secret_id_path": "secrets/services/edge-proxy/secret_id",
                    "policy_name": "bootroot-service-edge-proxy"
                }
            }
        }
    });
    std::fs::write(root.join("state.json"), serde_json::to_vec_pretty(&state)?)?;
    Ok(())
}
