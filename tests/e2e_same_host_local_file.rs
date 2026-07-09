#![cfg(unix)]

mod support;

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context;
use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{body_json, header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const RUNTIME_SERVICE_ADD_ROLE_ID: &str = "runtime-service-add-role-id";
const RUNTIME_SERVICE_ADD_SECRET_ID: &str = "runtime-service-add-secret-id";
const RUNTIME_ROTATE_ROLE_ID: &str = "runtime-rotate-role-id";
const RUNTIME_ROTATE_SECRET_ID: &str = "runtime-rotate-secret-id";
const RUNTIME_CLIENT_TOKEN: &str = "runtime-client-token";
const SERVICE_NAME: &str = "edge-proxy";
const HOSTNAME: &str = "edge-node-01";
const DOMAIN: &str = "trusted.domain";
const INSTANCE_ID: &str = "001";
const ROLE_NAME: &str = "bootroot-service-edge-proxy";
const ROLE_ID: &str = "role-edge-proxy";

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn test_same_host_local_file_happy_path() {
    let temp = tempdir().expect("create tempdir");
    let server = MockServer::start().await;
    stub_service_add_openbao(&server).await;

    write_state_file(temp.path(), &server.uri()).expect("write state");
    let files = init_service_files(temp.path()).expect("init service files");

    let add_stdout =
        run_service_add_local(temp.path(), &server.uri(), &files).expect("service add local");

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(temp.path().join("state.json")).expect("state"))
            .expect("parse state");
    assert_eq!(
        state["services"][SERVICE_NAME]["delivery_mode"],
        "local-file"
    );

    let agent_contents = fs::read_to_string(&files.agent_config).expect("read agent.toml");
    assert!(agent_contents.contains("[[profiles]]"));
    assert!(agent_contents.contains("service_name = \"edge-proxy\""));
    assert!(agent_contents.contains("[profiles.paths]"));
    assert!(agent_contents.contains("cert = \""));
    assert!(agent_contents.contains("key = \""));
    assert!(agent_contents.contains("[trust]"));
    assert!(!agent_contents.contains("verify_certificates"));
    assert!(agent_contents.contains("trusted_ca_sha256 = ["));
    assert!(agent_contents.contains("ca_bundle_path = \""));
    assert!(
        agent_contents.contains("domain = \"trusted.domain\""),
        "agent.toml missing domain: {agent_contents}"
    );
    assert!(
        agent_contents.contains("[acme]"),
        "agent.toml missing [acme] section: {agent_contents}"
    );
    assert!(
        agent_contents.contains("http_responder_hmac = \"test-responder-hmac\""),
        "agent.toml missing http_responder_hmac: {agent_contents}"
    );

    let bundle_contents = fs::read_to_string(&files.ca_bundle_path).expect("read ca-bundle");
    assert!(bundle_contents.contains("BEGIN CERTIFICATE"));
    let (expected_ca_pem, _) = support::test_trust_material();
    assert!(
        bundle_contents.contains(expected_ca_pem.trim()),
        "ca-bundle must carry the synced trust material",
    );
    // Public trust material: the CA bundle must be world-readable so a
    // non-root consumer in a separate container can read the bind-mounted
    // file.
    assert_mode(&files.ca_bundle_path, 0o644);

    // No OpenBao Agent sidecar artifacts are generated anymore: the local
    // bootroot-agent is a host daemon whose fast-poll loop (activated by
    // the [openbao] section) is the single secret-delivery mechanism.
    assert!(
        !temp
            .path()
            .join("secrets")
            .join("openbao")
            .join("services")
            .exists(),
        "no per-service OpenBao Agent artifacts must be generated"
    );
    assert!(
        agent_contents.contains("[openbao]"),
        "agent.toml missing [openbao] fast-poll section: {agent_contents}"
    );
    assert!(
        agent_contents.contains("kv_mount = \"secret\""),
        "agent.toml [openbao] missing kv_mount: {agent_contents}"
    );
    assert!(
        agent_contents.contains("role_id_path = \"") && agent_contents.contains("role_id\""),
        "agent.toml [openbao] missing role_id_path: {agent_contents}"
    );
    assert!(
        agent_contents.contains("secret_id_path = \""),
        "agent.toml [openbao] missing secret_id_path: {agent_contents}"
    );
    assert!(
        agent_contents.contains("bootroot-agent-state-edge-proxy.json"),
        "agent.toml [openbao] missing service-keyed state_path: {agent_contents}"
    );
    let state_path_line = agent_contents
        .lines()
        .find(|line| line.trim_start().starts_with("state_path"))
        .expect("agent.toml must carry a state_path line");
    let state_path_value = state_path_line
        .split('=')
        .nth(1)
        .expect("state_path line has a value")
        .trim()
        .trim_matches('"');
    assert!(
        Path::new(state_path_value).is_absolute(),
        "state_path must be absolute: {state_path_line}"
    );

    // EAB regression guard: KV holds EAB material, so service add must
    // provision eab.json next to secret_id, and the printed run command
    // must pass it via --eab-file — otherwise fast-poll EAB refresh is a
    // silent no-op on this host.
    assert!(files.eab_path.exists(), "eab.json must be provisioned");
    assert_mode(&files.eab_path, 0o600);
    let eab_contents = fs::read_to_string(&files.eab_path).expect("read eab.json");
    assert!(
        eab_contents.contains("\"kid\": \"test-kid\""),
        "eab.json must carry the KV kid: {eab_contents}"
    );
    assert!(
        add_stdout.contains("bootroot-agent --config"),
        "service add must print the daemon run command: {add_stdout}"
    );
    assert!(
        add_stdout.contains("--eab-file") && add_stdout.contains("eab.json"),
        "the documented run command must include --eab-file: {add_stdout}"
    );

    write_service_cert(&files.cert_path, &files.key_path).expect("write cert");
    write_fake_bootroot_agent(temp.path(), 0).expect("write fake bootroot-agent");
    run_verify(temp.path(), &files.agent_config).expect("verify succeeds");
}

#[tokio::test]
async fn test_same_host_local_rotation_sequence_keeps_service_operational() {
    let temp = tempdir().expect("create tempdir");
    let server = MockServer::start().await;
    stub_service_add_openbao(&server).await;

    write_state_file(temp.path(), &server.uri()).expect("write state");
    let files = init_service_files(temp.path()).expect("init service files");
    run_service_add_local(temp.path(), &server.uri(), &files).expect("service add local");
    stub_rotate_sequence_openbao(&server, "secret-rotated").await;
    fs::write(temp.path().join("docker-compose.yml"), "services: {}\n").expect("write compose");
    write_fake_pkill(temp.path(), 0).expect("write fake pkill");
    write_service_cert(&files.cert_path, &files.key_path).expect("write cert");
    write_fake_bootroot_agent(temp.path(), 0).expect("write fake bootroot-agent");

    run_rotate_responder_hmac(temp.path(), &server.uri(), "hmac-updated").expect("rotate hmac");
    let rotate_secret = run_rotate_secret_id_with_output(temp.path(), &server.uri());
    assert!(
        rotate_secret.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&rotate_secret.stderr)
    );
    assert!(String::from_utf8_lossy(&rotate_secret.stdout).contains("AppRole login OK"));

    let secret_id = fs::read_to_string(files.secret_id_path).expect("read secret_id");
    assert!(!secret_id.trim().is_empty());
    assert_eq!(
        fs::read_to_string(files.role_id_path).expect("read role_id"),
        ROLE_ID
    );

    // rotate must not restart any per-service container: HMAC propagation
    // to local agents is the running daemon's fast-poll loop, and the
    // secret_id file write needs no signal at all.
    let docker_log = fs::read_to_string(temp.path().join("docker.log")).unwrap_or_default();
    assert!(
        !docker_log.contains(&format!("bootroot-openbao-agent-{SERVICE_NAME}")),
        "rotate must not touch a per-service container: {docker_log}"
    );

    // Simulate the running bootroot-agent's fast-poll loop applying the
    // rotated responder HMAC from KV to agent.toml. In production the
    // daemon does this itself within fast_poll_interval; here we write
    // the expected output directly.
    simulate_fast_poll_hmac_apply(&files.agent_config, "hmac-updated");
    let agent_contents = fs::read_to_string(&files.agent_config).expect("read agent.toml");
    assert!(agent_contents.contains("http_responder_hmac = \"hmac-updated\""));

    run_verify(temp.path(), &files.agent_config).expect("verify after rotations");
}

#[tokio::test]
async fn test_same_host_trust_change_propagates_to_agent_config() {
    let temp = tempdir().expect("create tempdir");
    let server = MockServer::start().await;
    stub_service_add_openbao(&server).await;
    stub_remote_pull_openbao(&server).await;

    write_state_file(temp.path(), &server.uri()).expect("write state");
    let files = init_service_files(temp.path()).expect("init service files");
    run_service_add_local(temp.path(), &server.uri(), &files).expect("service add local");
    fs::write(&files.role_id_path, format!("{ROLE_ID}\n")).expect("seed role_id");
    fs::write(&files.secret_id_path, "secret-initial\n").expect("seed secret_id");

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot-remote"))
        .current_dir(temp.path())
        .args([
            "bootstrap",
            "--openbao-url",
            &server.uri(),
            "--kv-mount",
            "secret",
            "--service-name",
            SERVICE_NAME,
            "--role-id-path",
            files.role_id_path.to_string_lossy().as_ref(),
            "--secret-id-path",
            files.secret_id_path.to_string_lossy().as_ref(),
            "--eab-file-path",
            files.eab_path.to_string_lossy().as_ref(),
            "--agent-config-path",
            files.agent_config.to_string_lossy().as_ref(),
            "--ca-bundle-path",
            files.ca_bundle_path.to_string_lossy().as_ref(),
            "--profile-instance-id",
            INSTANCE_ID,
        ])
        .output()
        .expect("run bootroot-remote bootstrap");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&files.agent_config).expect("read agent.toml");
    assert!(agent_contents.contains("trusted_ca_sha256 = ["));
    assert!(agent_contents.contains("ca_bundle_path = \""));
    assert!(!agent_contents.contains("verify_certificates"));
    // The local→remote transition must not leave a duplicate profile
    // block: the pre-existing local-file block is stripped and replaced by
    // exactly one remote block for the service (#662).
    assert_eq!(
        agent_contents.matches("[[profiles]]").count(),
        1,
        "exactly one profile block must remain: {agent_contents}"
    );
    assert!(!agent_contents.contains("# BEGIN bootroot managed profile:"));
    assert!(agent_contents.contains("# BEGIN BOOTROOT REMOTE PROFILE"));
    let bundle_contents = fs::read_to_string(&files.ca_bundle_path).expect("read ca-bundle");
    assert!(bundle_contents.contains("BEGIN CERTIFICATE"));
    let (expected_pem, _) = support::test_trust_material();
    assert_eq!(bundle_contents.trim(), expected_pem.trim());
}

/// Guards the fast-poll model's no-signal contract for local
/// `rotate approle-secret-id`: the direct `secret_id` file write is all
/// that happens — the agent re-reads the file on its next `AppRole`
/// re-login, so the rotation must succeed even when `pkill` would fail
/// and no docker daemon exists.
#[tokio::test]
async fn test_same_host_secret_id_rotation_needs_no_process_signal() {
    let temp = tempdir().expect("create tempdir");
    let server = MockServer::start().await;
    stub_service_add_openbao(&server).await;

    write_state_file(temp.path(), &server.uri()).expect("write state");
    let files = init_service_files(temp.path()).expect("init service files");
    run_service_add_local(temp.path(), &server.uri(), &files).expect("service add local");
    stub_secret_id_rotation_openbao(&server, "secret-recovered").await;

    // A failing pkill must be irrelevant: the rotation path performs no
    // process signal and no docker call.
    write_fake_pkill(temp.path(), 1).expect("write failing pkill");
    let output = run_rotate_secret_id_with_output(temp.path(), &server.uri());
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("AppRole login OK"), "stdout: {stdout}");
    assert!(
        !stdout.contains("OpenBao Agent"),
        "no sidecar reload line may be printed: {stdout}"
    );
    let secret = fs::read_to_string(&files.secret_id_path).expect("read secret_id");
    assert!(!secret.trim().is_empty());
    let role_id = fs::read_to_string(&files.role_id_path).expect("read role_id");
    assert_eq!(role_id, ROLE_ID);
}

/// Issue #691 acceptance: containerized consumer apps stay supported
/// with the daemon-only agent. A local `service add` with
/// `--reload-style docker-restart --reload-target <container>` must
/// keep cert delivery on host paths a consumer container can
/// bind-mount, and persist the `docker restart <container>` post-renew
/// hook in the managed profile so the host daemon restarts the
/// consumer after each renewal.
#[tokio::test]
async fn test_same_host_containerized_consumer_docker_restart_hook() {
    let temp = tempdir().expect("create tempdir");
    let server = MockServer::start().await;
    stub_service_add_openbao(&server).await;

    write_state_file(temp.path(), &server.uri()).expect("write state");
    let files = init_service_files(temp.path()).expect("init service files");
    let add_stdout = run_service_add_local_with_extra_args(
        temp.path(),
        &files,
        &[
            "--reload-style",
            "docker-restart",
            "--reload-target",
            "edge-proxy-container",
        ],
    )
    .expect("service add local with docker-restart reload style");

    assert!(
        add_stdout.contains("- post-renew hook: docker restart edge-proxy-container"),
        "docker-restart preset must resolve to a docker restart hook: {add_stdout}"
    );

    // The hook must be persisted in agent.toml so the host-daemon
    // bootroot-agent actually restarts the consumer container after each
    // renewal — not just echoed in the summary.
    let agent_contents = fs::read_to_string(&files.agent_config).expect("read agent.toml");
    assert!(
        agent_contents.contains("[[profiles.hooks.post_renew.success]]"),
        "agent.toml must carry the persisted post-renew hook: {agent_contents}"
    );
    assert!(
        agent_contents.contains("command = \"docker\""),
        "agent.toml hook must run docker: {agent_contents}"
    );
    assert!(
        agent_contents.contains("args = [\"restart\", \"edge-proxy-container\"]"),
        "agent.toml hook must restart the consumer container: {agent_contents}"
    );

    // Cert delivery stays on host paths: the profile's cert/key point at
    // the host directory the consumer container bind-mounts, and the CA
    // bundle is world-readable for a non-root consumer.
    let cert_path = files.cert_path.display().to_string();
    let key_path = files.key_path.display().to_string();
    assert!(
        agent_contents.contains(&format!("cert = \"{cert_path}\"")),
        "profile cert must stay a bind-mountable host path: {agent_contents}"
    );
    assert!(
        agent_contents.contains(&format!("key = \"{key_path}\"")),
        "profile key must stay a bind-mountable host path: {agent_contents}"
    );
    assert_mode(&files.ca_bundle_path, 0o644);
}

struct ServicePaths {
    agent_config: PathBuf,
    cert_path: PathBuf,
    key_path: PathBuf,
    secret_id_path: PathBuf,
    role_id_path: PathBuf,
    eab_path: PathBuf,
    ca_bundle_path: PathBuf,
}

fn init_service_files(root: &Path) -> anyhow::Result<ServicePaths> {
    let cert_path = root.join("certs").join("edge-proxy.crt");
    let key_path = root.join("certs").join("edge-proxy.key");
    let agent_config = root.join("agent.toml");
    let secret_dir = root.join("secrets").join("services").join(SERVICE_NAME);
    let secret_id_path = secret_dir.join("secret_id");
    let role_id_path = secret_dir.join("role_id");
    let eab_path = secret_dir.join("eab.json");
    let ca_bundle_path = root.join("certs").join("ca-bundle.pem");

    fs::create_dir_all(cert_path.parent().expect("cert parent")).context("create cert dir")?;
    fs::create_dir_all(&secret_dir).context("create secret dir")?;
    fs::write(&agent_config, "# initial\n").context("write agent config")?;
    Ok(ServicePaths {
        agent_config,
        cert_path,
        key_path,
        secret_id_path,
        role_id_path,
        eab_path,
        ca_bundle_path,
    })
}

fn run_service_add_local(
    root: &Path,
    openbao_url: &str,
    files: &ServicePaths,
) -> anyhow::Result<String> {
    let _ = openbao_url;
    run_service_add_local_with_extra_args(root, files, &[])
}

fn run_service_add_local_with_extra_args(
    root: &Path,
    files: &ServicePaths,
    extra_args: &[&str],
) -> anyhow::Result<String> {
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args([
            "service",
            "add",
            "--service-name",
            SERVICE_NAME,
            "--delivery-mode",
            "local-file",
            "--hostname",
            HOSTNAME,
            "--domain",
            DOMAIN,
            "--agent-config",
            files.agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            files.cert_path.to_string_lossy().as_ref(),
            "--key-path",
            files.key_path.to_string_lossy().as_ref(),
            "--instance-id",
            INSTANCE_ID,
            "--auth-mode",
            "approle",
            "--approle-role-id",
            RUNTIME_SERVICE_ADD_ROLE_ID,
            "--approle-secret-id",
            RUNTIME_SERVICE_ADD_SECRET_ID,
        ])
        .args(extra_args)
        .output()
        .context("run service add")?;
    if !output.status.success() {
        anyhow::bail!(
            "service add failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn run_rotate_responder_hmac(root: &Path, openbao_url: &str, hmac: &str) -> anyhow::Result<()> {
    write_fake_docker(root)?;

    let responder_dir = root.join("secrets").join("responder");
    fs::create_dir_all(&responder_dir).context("create responder dir")?;
    let render_source = root.join("responder-render-src.toml");
    fs::write(&render_source, format!("hmac_secret = \"{hmac}\"\n"))
        .context("write render source")?;

    let path_env = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path_env}", root.join("bin").display());
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .env("PATH", combined_path)
        .env("DOCKER_OUTPUT", root.join("docker.log"))
        .env("RENDER_SOURCE", &render_source)
        .env("RENDER_TARGET", responder_dir.join("responder.toml"))
        .args([
            "rotate",
            "--openbao-url",
            openbao_url,
            "--auth-mode",
            "approle",
            "--approle-role-id",
            RUNTIME_ROTATE_ROLE_ID,
            "--approle-secret-id",
            RUNTIME_ROTATE_SECRET_ID,
            "--compose-file",
            "docker-compose.yml",
            "--yes",
            "responder-hmac",
            "--hmac",
            hmac,
        ])
        .output()
        .context("run rotate responder-hmac")?;
    if !output.status.success() {
        anyhow::bail!(
            "rotate responder-hmac failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn run_rotate_secret_id_with_output(root: &Path, openbao_url: &str) -> std::process::Output {
    let path_env = env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path_env}", root.join("bin").display());
    Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .env("PATH", combined_path)
        .args([
            "rotate",
            "--openbao-url",
            openbao_url,
            "--auth-mode",
            "approle",
            "--approle-role-id",
            RUNTIME_ROTATE_ROLE_ID,
            "--approle-secret-id",
            RUNTIME_ROTATE_SECRET_ID,
            "--yes",
            "approle-secret-id",
            "--service-name",
            SERVICE_NAME,
        ])
        .output()
        .expect("run rotate approle-secret-id")
}

fn run_verify(root: &Path, agent_config: &Path) -> anyhow::Result<()> {
    let agent_binary = root.join("bin").join("bootroot-agent");
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(root)
        .args([
            "verify",
            "--service-name",
            SERVICE_NAME,
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .context("run verify")?;
    if !output.status.success() {
        anyhow::bail!("verify failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(())
}

fn write_state_file(root: &Path, openbao_url: &str) -> anyhow::Result<()> {
    let state = json!({
        "openbao_url": openbao_url,
        "kv_mount": "secret",
        "secrets_dir": "secrets",
        "policies": {},
        "approles": {},
        "services": {}
    });
    fs::write(
        root.join("state.json"),
        serde_json::to_string_pretty(&state)?,
    )
    .context("write state.json")?;
    Ok(())
}

fn write_service_cert(cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    // Sign the leaf with the same CA `support::test_trust_material`
    // bundles, so the chain check added in #627 (`bootroot verify`'s
    // `leaf_chains_to_bundle`) accepts the pair instead of rejecting
    // it as a self-signed leaf against an unrelated bundle.
    let (cert_pem, key_pem) =
        support::sign_test_leaf(&format!("{INSTANCE_ID}.{SERVICE_NAME}.{HOSTNAME}.{DOMAIN}"));
    fs::write(cert_path, cert_pem).context("write cert")?;
    fs::write(key_path, key_pem).context("write key")?;
    Ok(())
}

fn write_fake_bootroot_agent(root: &Path, exit_code: i32) -> anyhow::Result<()> {
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).context("create bin dir")?;
    let script = format!("#!/bin/sh\nexit {exit_code}\n");
    let script_path = bin_dir.join("bootroot-agent");
    fs::write(&script_path, script).context("write fake bootroot-agent")?;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
        .context("chmod fake bootroot-agent")?;
    Ok(())
}

fn write_fake_docker(root: &Path) -> anyhow::Result<()> {
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).context("create bin dir")?;
    let script = r#"#!/bin/sh
set -eu

if [ -n "${DOCKER_OUTPUT:-}" ]; then
  printf "%s\n" "$*" >> "$DOCKER_OUTPUT"
fi

# Simulate the infra OpenBao Agent (responder) re-rendering its KV
# template on restart via the RENDER_SOURCE / RENDER_TARGET env vars.
if [ "${1:-}" = "restart" ] && [ "${2:-}" = "bootroot-openbao-agent-responder" ]; then
  if [ -n "${RENDER_SOURCE:-}" ] && [ -n "${RENDER_TARGET:-}" ]; then
    cp "$RENDER_SOURCE" "$RENDER_TARGET"
  fi
fi

exit 0
"#;
    let script_path = bin_dir.join("docker");
    fs::write(&script_path, script).context("write fake docker")?;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
        .context("chmod fake docker")?;
    Ok(())
}

fn simulate_fast_poll_hmac_apply(agent_config: &Path, hmac: &str) {
    let rendered = format!(
        "\
[acme]
http_responder_hmac = \"{hmac}\"
"
    );
    fs::write(agent_config, rendered).expect("simulate fast-poll HMAC apply");
}

fn write_fake_pkill(root: &Path, exit_code: i32) -> anyhow::Result<()> {
    let bin_dir = root.join("bin");
    fs::create_dir_all(&bin_dir).context("create bin dir")?;
    let script = format!("#!/bin/sh\nexit {exit_code}\n");
    let script_path = bin_dir.join("pkill");
    fs::write(&script_path, script).context("write fake pkill")?;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
        .context("chmod fake pkill")?;
    Ok(())
}

async fn stub_service_add_openbao(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": RUNTIME_SERVICE_ADD_ROLE_ID,
            "secret_id": RUNTIME_SERVICE_ADD_SECRET_ID
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": RUNTIME_CLIENT_TOKEN }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/sys/auth"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "approle/": {} }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/sys/policies/acl/{ROLE_NAME}")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/role-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": ROLE_ID }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/secret-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .and(header_exists("X-Vault-Wrap-TTL"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": "wrap-token-initial",
                "ttl": 1800,
                "creation_time": "2026-04-12T00:00:00Z",
                "creation_path": format!("auth/approle/role/{ROLE_NAME}/secret-id")
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(header("X-Vault-Token", "wrap-token-initial"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "secret_id": "secret-initial",
                "secret_id_accessor": "acc"
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    let (ca_pem, ca_fp) = support::test_trust_material();
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "data": {
                    "trusted_ca_sha256": [ca_fp],
                    "ca_bundle_pem": ca_pem
                }
            }
        })))
        .mount(server)
        .await;

    stub_service_kv_sync(server).await;
}

async fn stub_service_kv_sync(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "test-kid", "hmac": "test-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "value": "test-responder-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/eab"
        )))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/http_responder_hmac"
        )))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/trust"
        )))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

async fn stub_rotate_sequence_openbao(server: &MockServer, secret_id: &str) {
    stub_secret_id_rotation_openbao(server, secret_id).await;

    Mock::given(method("POST"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{SERVICE_NAME}/http_responder_hmac"
        )))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .mount(server)
        .await;
}

async fn stub_secret_id_rotation_openbao(server: &MockServer, secret_id: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/sys/health"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    let wrap_token = format!("wrap-rot-{secret_id}");
    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/secret-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .and(header_exists("X-Vault-Wrap-TTL"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": &wrap_token,
                "ttl": 1800,
                "creation_time": "2026-04-12T00:00:00Z",
                "creation_path": format!("auth/approle/role/{ROLE_NAME}/secret-id")
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(header("X-Vault-Token", &wrap_token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "secret_id": secret_id,
                "secret_id_accessor": "acc"
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{ROLE_NAME}/role-id")))
        .and(header("X-Vault-Token", RUNTIME_CLIENT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": ROLE_ID }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": RUNTIME_CLIENT_TOKEN }
        })))
        .mount(server)
        .await;
}

async fn stub_remote_pull_openbao(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": ROLE_ID,
            "secret_id": "secret-initial"
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": "remote-token" }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(
            "/v1/secret/data/bootroot/services/edge-proxy/secret_id",
        ))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "secret_id": "secret-updated" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/eab"))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "kid-trust", "hmac": "hmac-trust" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(
            "/v1/secret/data/bootroot/services/edge-proxy/http_responder_hmac",
        ))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "hmac": "responder-trust" } }
        })))
        .mount(server)
        .await;

    // Post-#695 the fast-poll/bootstrap trust parse rejects a bundle whose
    // fingerprints do not match its certificates, so serve a real,
    // internally consistent bundle.
    let (ca_pem, ca_fp) = support::test_trust_material();
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/services/edge-proxy/trust"))
        .and(header("X-Vault-Token", "remote-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "trusted_ca_sha256": [ca_fp],
                "ca_bundle_pem": ca_pem
            } }
        })))
        .mount(server)
        .await;
}

fn assert_mode(path: &Path, expected: u32) {
    let mode = fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, expected, "path {}", path.display());
}
