#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

use anyhow::Context;
use serde_json::json;
use tempfile::tempdir;
use wiremock::matchers::{body_json, header, header_exists, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[cfg(unix)]
mod support;

// End-to-end fixture exercises a full service add → state.json round
// trip; the assertion block grew when the consumer-reload hint
// (issue #614) was added and pushed it past the default 100-line
// threshold. The project CLAUDE.md treats `clippy::too_many_lines`
// loosely, so allow it here rather than fragmenting the test.
#[allow(clippy::too_many_lines)]
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_writes_state_and_secret() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--notes",
            "primary",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("bootroot service add: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(stdout.contains("- delivery mode: local-file"));
    assert!(stdout.contains("Bootroot-managed:"));
    assert!(stdout.contains("Operator-managed (required):"));
    assert!(stdout.contains("next steps:"));
    assert!(stdout.contains("daemon profile snippet:"));
    // The alias registration is best-effort and used to signal failure
    // only by an absence — no per-alias line, a zero exit status, and a
    // summary that never mentioned aliases. The summary states the
    // outcome now, and this fixture runs against whatever Docker this
    // host has, so assert only that the line is there; which outcome it
    // reports is pinned by the two tests below that decide Docker's
    // answers rather than inheriting them.
    assert!(
        stdout
            .lines()
            .any(|line| line.starts_with("- HTTP-01 DNS aliases registered: ")),
        "summary must report the DNS alias outcome: {stdout}"
    );
    // The Bootroot-managed section lists exactly the two host-daemon
    // artifacts: the rendered agent config and the provisioned EAB file.
    // The retired per-service OpenBao Agent artifacts must be gone.
    assert!(stdout.contains("- auto-applied bootroot-agent config:"));
    assert!(stdout.contains(
        "- auto-provisioned EAB file (present only when EAB is configured; \
         pass its path via --eab-file):"
    ));
    assert!(
        !stdout.contains("OpenBao Agent config"),
        "no OpenBao Agent config line may be printed: {stdout}"
    );
    // The next-steps block documents the host-daemon run command,
    // including the --eab-file flag required for EAB rotation to apply.
    assert!(
        stdout.contains(
            "daemon run command (systemd ExecStart or shell; \
             --eab-file is required for EAB rotation to apply):"
        ),
        "next steps must include the daemon run command title: {stdout}"
    );
    assert!(
        stdout.contains("bootroot-agent --config"),
        "next steps must include the bootroot-agent invocation: {stdout}"
    );
    assert!(
        stdout.contains("--eab-file"),
        "run command must pass --eab-file: {stdout}"
    );
    // Issue #614: with no --reload-style, the consumer-reload hint
    // should explicitly call out the missing hook and point at the
    // service-update remediation path.
    assert!(
        stdout.contains("Consumer reload/restart required"),
        "service add should print the consumer-reload hint: {stdout}"
    );
    assert!(
        stdout.contains("NO post-renew hook configured"),
        "service add should flag the missing hook: {stdout}"
    );
    assert!(
        stdout.contains("bootroot service update --registration-id"),
        "service add should suggest the service-update remediation: {stdout}"
    );

    assert_state_contains_default_delivery_mode(temp_dir.path());

    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(agent_contents.contains("# BEGIN bootroot managed profile: edge-proxy"));
    assert!(agent_contents.contains("service_name = \"edge-proxy\""));
    assert!(agent_contents.contains("instance_id = \"001\""));
    assert!(agent_contents.contains("hostname = \"edge-node-01\""));
    assert!(agent_contents.contains("[profiles.paths]"));

    let secret_path = temp_dir
        .path()
        .join("secrets")
        .join("services")
        .join("edge-proxy")
        .join("secret_id");
    let secret_contents = fs::read_to_string(&secret_path).expect("read secret_id");
    assert_eq!(secret_contents, "secret-edge-proxy");
    let mode = fs::metadata(&secret_path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    let role_id_path = temp_dir
        .path()
        .join("secrets")
        .join("services")
        .join("edge-proxy")
        .join("role_id");
    let role_id_contents = fs::read_to_string(&role_id_path).expect("read role_id");
    assert_eq!(role_id_contents, "role-edge-proxy");
    let mode = fs::metadata(&role_id_path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600);

    assert_local_fast_poll_artifacts(temp_dir.path(), &agent_config, "edge-proxy");
}

/// Issue #830 — with a responder to attach to, the summary states how
/// many aliases were registered, the per-alias detail lines are still
/// printed alongside it, and every alias the count claims is in the
/// `docker network connect` the command actually issued.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_summary_reports_registered_dns_aliases() {
    let run = service_add_with_fake_docker(FakeDocker::ResponderUp).await;

    assert!(
        run.output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        run.stdout(),
        run.stderr()
    );
    let stdout = run.stdout();
    assert!(
        stdout.contains("- HTTP-01 DNS aliases registered: 1"),
        "summary must state the registered count: {stdout}"
    );
    // The aggregate does not replace the detail: `apply_dns_aliases` is
    // shared with `infra up` and `service remove`, whose output must not
    // change, so its per-alias lines stay exactly where they were.
    assert!(
        stdout.contains(&format!(
            "bootroot service add: registered HTTP-01 DNS alias {SERVICE_DNS_ALIAS}"
        )),
        "the per-alias line must survive the aggregate: {stdout}"
    );
    assert_alias_line_position(&stdout);
    // The count is only worth grepping if it names aliases that were
    // really attached; the E2E asserts this against `docker inspect`,
    // and here against the command the responder was reconnected with.
    assert!(
        run.docker_log.lines().any(|line| line
            .starts_with("network connect --alias bootroot-http01 --alias ")
            && line.contains(SERVICE_DNS_ALIAS)),
        "every counted alias must reach `docker network connect`: {}",
        run.docker_log
    );
}

/// Issue #830 — with the responder down the registration is skipped,
/// which stays a success: exit 0, the existing warning on stderr, and a
/// summary that now says none were registered instead of leaving the
/// operator to notice an absent line.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_summary_reports_skipped_dns_aliases() {
    let run = service_add_with_fake_docker(FakeDocker::ResponderDown).await;

    assert!(
        run.output.status.success(),
        "a responder that is down must not fail the add: stdout:\n{}\nstderr:\n{}",
        run.stdout(),
        run.stderr()
    );
    let stdout = run.stdout();
    let stderr = run.stderr();
    assert!(
        stderr.contains("container not running — skipping DNS alias registration"),
        "the existing warning must still be printed: {stderr}"
    );
    assert!(
        stdout.contains(
            "- HTTP-01 DNS aliases registered: 0 (registration skipped; see the warning above)"
        ),
        "the summary must state that nothing was registered: {stdout}"
    );
    assert!(
        !stdout.contains("registered HTTP-01 DNS alias"),
        "nothing was attached, so no per-alias line may be printed: {stdout}"
    );
    assert_alias_line_position(&stdout);
    assert!(
        !run.docker_log.contains("network connect"),
        "a missing responder must not be reconnected: {}",
        run.docker_log
    );
}

/// Issue #830 — the second way nothing gets attached: the responder is
/// running, but the reconnect carrying the aliases fails and only the
/// rollback that restores plain connectivity succeeds.  The summary must
/// report it exactly as it reports a responder that was never there —
/// what an operator has to act on is that no alias was attached, and the
/// stderr warning is where the reason lives.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_summary_reports_a_recovered_connect_as_skipped() {
    let run = service_add_with_fake_docker(FakeDocker::AliasedConnectFails).await;

    assert!(
        run.output.status.success(),
        "a recovered reconnect must not fail the add: stdout:\n{}\nstderr:\n{}",
        run.stdout(),
        run.stderr()
    );
    let stdout = run.stdout();
    let stderr = run.stderr();
    assert!(
        stderr.contains("DNS alias registration failed but network connectivity was restored"),
        "the existing recovery warning must still be printed: {stderr}"
    );
    assert!(
        stdout.contains(
            "- HTTP-01 DNS aliases registered: 0 (registration skipped; see the warning above)"
        ),
        "the summary must state that nothing was registered: {stdout}"
    );
    assert!(
        !stdout.contains("registered HTTP-01 DNS alias"),
        "nothing was attached, so no per-alias line may be printed: {stdout}"
    );
    assert_alias_line_position(&stdout);
    // The rollback is what makes this outcome `Skipped` rather than an
    // error: the responder is back on its network, just without aliases.
    assert!(
        run.docker_log.lines().any(|line| line
            == format!(
                "network connect --alias bootroot-http01 {FAKE_RESPONDER_NETWORK} {FAKE_RESPONDER_ID}"
            )),
        "the responder must be reconnected without aliases: {}",
        run.docker_log
    );
}

/// Issue #722 — a local-file `service add --secret-id-path <abs>`
/// relocates `secret_id`, its sibling `role_id`, and `eab.json` into the
/// operator-provisioned directory (outside `<secrets_dir>`), and the
/// state entry, the generated `[openbao]` config, and the summary all
/// report the relocated paths. Nothing is left in the default
/// secrets-tree location.
// The single end-to-end fixture asserts across every relocated seam
// (files, state, config, summary), which pushes it past the default
// 100-line threshold; CLAUDE.md treats `too_many_lines` loosely, so keep
// it whole rather than fragmenting the flow.
#[allow(clippy::too_many_lines)]
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_secret_id_path_override_relocates_credentials() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    // Operator-provisioned, agent-owned credential directory outside the
    // root-owned `<secrets_dir>` tree.
    let agent_dir = temp_dir.path().join("agent").join("edge-proxy");
    fs::create_dir_all(&agent_dir).expect("create agent dir");
    let override_secret_id = agent_dir.join("secret_id");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--secret-id-path",
            override_secret_id.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    // The summary reports the relocated secret_id path, not the default.
    assert!(
        stdout.contains(&override_secret_id.display().to_string()),
        "summary must report the relocated secret_id path: {stdout}"
    );

    // secret_id, sibling role_id, and eab.json land in the override dir,
    // all 0600.
    let assert_0600 = |path: &std::path::Path| {
        let mode = fs::metadata(path)
            .unwrap_or_else(|_| panic!("metadata for {}", path.display()))
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{} must be 0600", path.display());
    };
    assert_eq!(
        fs::read_to_string(&override_secret_id).expect("read relocated secret_id"),
        "secret-edge-proxy"
    );
    assert_0600(&override_secret_id);
    let override_role_id = agent_dir.join("role_id");
    assert_eq!(
        fs::read_to_string(&override_role_id).expect("read relocated role_id"),
        "role-edge-proxy"
    );
    assert_0600(&override_role_id);
    let override_eab = agent_dir.join("eab.json");
    let eab: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&override_eab).expect("read relocated eab.json"))
            .expect("parse eab.json");
    assert_eq!(eab["kid"], "test-kid");
    assert_eq!(eab["hmac"], "test-hmac");
    assert_0600(&override_eab);

    // The default secrets-tree location holds nothing for this service.
    let default_dir = temp_dir
        .path()
        .join("secrets")
        .join("services")
        .join("edge-proxy");
    assert!(
        !default_dir.join("secret_id").exists()
            && !default_dir.join("role_id").exists()
            && !default_dir.join("eab.json").exists(),
        "no credential may be written under the default secrets tree when overridden"
    );

    // State records the relocated secret_id path as the source of truth.
    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state.json"),
    )
    .expect("parse state.json");
    assert_eq!(
        state["services"]["edge-proxy"]["approle"]["secret_id_path"],
        override_secret_id.to_string_lossy().as_ref()
    );

    // The generated [openbao] config points the agent at the relocated
    // role_id/secret_id.
    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    let doc: toml_edit::DocumentMut = agent_contents.parse().expect("agent.toml must parse");
    let openbao = doc
        .get("openbao")
        .and_then(toml_edit::Item::as_table)
        .expect("agent.toml must contain an [openbao] table");
    let get = |key: &str| {
        openbao
            .get(key)
            .and_then(toml_edit::Item::as_str)
            .unwrap_or_else(|| panic!("[openbao].{key} must be a string"))
    };
    assert_eq!(
        std::path::Path::new(get("secret_id_path")),
        override_secret_id
    );
    assert_eq!(std::path::Path::new(get("role_id_path")), override_role_id);
}

/// Issue #722 — `--secret-id-path` is local-file only; passing it with
/// `--delivery-mode remote-bootstrap` is rejected before any `OpenBao`
/// interaction.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_secret_id_path_rejected_with_remote_bootstrap() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    let agent_dir = temp_dir.path().join("agent").join("edge-proxy");
    fs::create_dir_all(&agent_dir).expect("create agent dir");

    write_state_file(temp_dir.path(), "http://127.0.0.1:1").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--delivery-mode",
            "remote-bootstrap",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--secret-id-path",
            agent_dir.join("secret_id").to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    assert!(
        !output.status.success(),
        "remote-bootstrap override must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("only honoured for local-file delivery"),
        "stderr must explain the local-file restriction: {stderr}"
    );
}

/// Issue #722 — a `--secret-id-path` whose final component is `role_id`
/// (which would collide with the derived sibling) is rejected.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_secret_id_path_rejected_role_id_final_component() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    let agent_dir = temp_dir.path().join("agent").join("edge-proxy");
    fs::create_dir_all(&agent_dir).expect("create agent dir");

    write_state_file(temp_dir.path(), "http://127.0.0.1:1").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--secret-id-path",
            agent_dir.join("role_id").to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    assert!(!output.status.success(), "role_id-final override must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must not end in `role_id`"),
        "stderr must explain the role_id collision: {stderr}"
    );
}

/// Issue #722 — a `--secret-id-path` that resolves inside the root-owned
/// `<secrets_dir>` tree (which the non-root agent cannot traverse) is
/// rejected.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_secret_id_path_rejected_inside_secrets_dir() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    // Canonicalize so the absolute `inside` path shares the same prefix
    // the child process derives from its resolved cwd (macOS resolves the
    // `/var` -> `/private/var` symlink in `getcwd()`); the containment
    // check is lexical, so the two spellings must agree.
    let root = temp_dir
        .path()
        .canonicalize()
        .expect("canonicalize temp dir");
    let agent_config = root.join("agent.toml");
    let cert_path = root.join("certs").join("edge-proxy.crt");
    let key_path = root.join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");
    // An absolute path that resolves inside the state's `secrets_dir`
    // (relative "secrets", so under the working dir).
    let inside = root
        .join("secrets")
        .join("services")
        .join("edge-proxy")
        .join("secret_id");
    fs::create_dir_all(inside.parent().unwrap()).expect("create inside dir");

    write_state_file(&root, "http://127.0.0.1:1").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(&root)
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--secret-id-path",
            inside.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    assert!(
        !output.status.success(),
        "inside-secrets-dir override must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must resolve outside the root-owned secrets tree"),
        "stderr must explain the secrets-tree restriction: {stderr}"
    );
}

/// Issue #702 — `service add` may arm a `--reload-style` preset and a
/// `--post-renew-command` custom hook together. Both must be persisted to
/// state and rendered into `agent.toml` in the deterministic "preset
/// first, custom second" order.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_installs_preset_and_custom_hooks_in_order() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
            "--reload-style",
            "docker-restart",
            "--reload-target",
            "aimer-web-next-app-1",
            "--post-renew-command",
            "docker",
            "--post-renew-arg",
            "exec",
            "--post-renew-arg",
            "aimer-web-nginx-prod-1",
            "--post-renew-arg",
            "nginx",
            "--post-renew-arg",
            "-s",
            "--post-renew-arg",
            "reload",
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "preset + custom hook must be accepted; stdout:\n{stdout}\nstderr:\n{stderr}"
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    let hooks = state["services"]["edge-proxy"]["post_renew_hooks"]
        .as_array()
        .expect("post_renew_hooks is an array");
    assert_eq!(hooks.len(), 2, "both hooks must be persisted: {hooks:?}");
    assert_eq!(hooks[0]["command"], "docker");
    assert_eq!(
        hooks[0]["args"],
        serde_json::json!(["restart", "aimer-web-next-app-1"])
    );
    assert_eq!(hooks[1]["command"], "docker");
    assert_eq!(
        hooks[1]["args"],
        serde_json::json!(["exec", "aimer-web-nginx-prod-1", "nginx", "-s", "reload"])
    );

    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert_eq!(
        agent_contents
            .matches("[[profiles.hooks.post_renew.success]]")
            .count(),
        2,
        "agent.toml must render both hook blocks: {agent_contents}"
    );
    let restart_pos = agent_contents
        .find("\"restart\"")
        .expect("restart hook rendered");
    let exec_pos = agent_contents.find("\"exec\"").expect("exec hook rendered");
    assert!(
        restart_pos < exec_pos,
        "preset hook must render before custom hook: {agent_contents}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_supports_approle_runtime_auth() {
    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_approle_login(
        &server,
        "runtime-role-id",
        "runtime-secret-id",
        "runtime-client",
    )
    .await;
    stub_app_add_openbao_with_token(&server, "edge-proxy", "runtime-client").await;
    stub_app_add_trust_missing_with_token(&server, "runtime-client").await;
    stub_app_add_service_sync_material_with_token(&server, "edge-proxy", "runtime-client").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--auth-mode",
            "approle",
            "--approle-role-id",
            "runtime-role-id",
            "--approle-secret-id",
            "runtime-secret-id",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("bootroot service add: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(
        temp_dir
            .path()
            .join("secrets")
            .join("services")
            .join("edge-proxy")
            .join("secret_id")
            .exists()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_approle_permission_denied_fails() {
    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_approle_login(
        &server,
        "runtime-role-id",
        "runtime-secret-id",
        "runtime-client",
    )
    .await;
    stub_app_add_trust_missing_with_token(&server, "runtime-client").await;
    stub_app_add_policy_write_forbidden_with_token(&server, "edge-proxy", "runtime-client").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--auth-mode",
            "approle",
            "--approle-role-id",
            "runtime-role-id",
            "--approle-secret-id",
            "runtime-secret-id",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
        ])
        .output()
        .expect("run service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr:\n{stderr}");
    assert!(stderr.contains("bootroot service add failed"));
    assert!(stderr.contains("OpenBao policy write failed"));
}

/// Issue #607: `service add` must `mkdir -p` the parent dirs of the
/// operator-supplied `--agent-config` / `--cert-path` / `--key-path`
/// values instead of bailing out with `Parent directory not found`,
/// which used to force every cold rebuild to keep an out-of-band
/// `mkdir -p` chain in sync with the flag values.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_creates_missing_parent_dirs_for_output_paths() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;

    // Deep nested paths whose parents do NOT exist on disk.  The cert
    // and key parents are intentionally different to exercise both
    // branches of `write_cert_and_key`.
    let agent_config = temp_dir.path().join("config/edge-proxy/agent.toml");
    let cert_path = temp_dir.path().join("mtls/certs/edge-proxy.crt");
    let key_path = temp_dir.path().join("mtls/private/edge-proxy.key");
    assert!(!agent_config.parent().unwrap().exists());
    assert!(!cert_path.parent().unwrap().exists());
    assert!(!key_path.parent().unwrap().exists());

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains("Parent directory not found"),
        "service add must no longer reject missing output parents: {stderr}"
    );

    // The agent-config write boundary in `local_config.rs` created the
    // chain and wrote the operator's TOML on top of it.
    assert!(
        agent_config.parent().unwrap().exists(),
        "agent_config parent must be created by service add"
    );
    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(agent_contents.contains("service_name = \"edge-proxy\""));

    // The cert parent is created via the CA-bundle write
    // (`write_local_ca_bundle` → `ensure_secrets_dir`); the key parent
    // is created lazily by `write_cert_and_key` at the first rotation,
    // so we do not assert its existence here.
    assert!(
        cert_path.parent().unwrap().exists(),
        "cert parent must be created by service add (ca-bundle write boundary)"
    );
}

/// Issue #607: pre-existing parent dirs with operator-tightened modes
/// (e.g. `0700`) must NOT be widened by `service add`.  `create_dir_all`
/// is supposed to leave existing components untouched, but this guards
/// against future regressions that mistakenly chmod the dir.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_preserves_existing_parent_dir_mode() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;

    let config_parent = temp_dir.path().join("config");
    fs::create_dir_all(&config_parent).expect("create config dir");
    fs::set_permissions(&config_parent, fs::Permissions::from_mode(0o700))
        .expect("tighten parent mode");
    let agent_config = config_parent.join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let before = fs::metadata(&config_parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(before, 0o700);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let after = fs::metadata(&config_parent).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        after, 0o700,
        "pre-existing parent dir mode must not be widened by service add"
    );
}

/// Issue #607: when the `--agent-config` parent path collides with an
/// existing regular file, `create_dir_all` must surface a clear error
/// (wrapped with the localized `error_write_file_failed` template)
/// rather than panicking or producing a generic libc message.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_fails_when_agent_config_parent_is_a_file() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;

    // Stage a regular file where service add will try to mkdir its
    // parent.  `create_dir_all("blocker/agent.toml-dir")` must fail.
    let blocker = temp_dir.path().join("blocker");
    fs::write(&blocker, b"not a directory").expect("stage blocker file");
    let agent_config = blocker.join("agent.toml");
    let cert_path = temp_dir.path().join("certs/edge-proxy.crt");
    let key_path = temp_dir.path().join("certs/edge-proxy.key");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "service add must fail when agent-config parent collides with a file; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("Failed to write")
            && stderr.contains(agent_config.to_string_lossy().as_ref()),
        "expected localized write-failure for agent-config path, got:\n{stderr}"
    );
}

/// Issue #607: `--dry-run` / `--print-only` must remain side-effect-
/// free even when output-path parents do not exist.  Resolution lives
/// in `resolve.rs` (no filesystem writes), and the actual mkdir lives
/// in `local_config.rs`, so preview-mode never reaches it.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_print_only_does_not_create_missing_parent_dirs() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("config/edge-proxy/agent.toml");
    let cert_path = temp_dir.path().join("mtls/edge-proxy.crt");
    let key_path = temp_dir.path().join("mtls-key/edge-proxy.key");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
        ])
        .output()
        .expect("run service add");

    assert!(
        output.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        !agent_config.parent().unwrap().exists(),
        "--print-only must not create agent_config parent"
    );
    assert!(
        !cert_path.parent().unwrap().exists(),
        "--print-only must not create cert parent"
    );
    assert!(
        !key_path.parent().unwrap().exists(),
        "--print-only must not create key parent"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_print_only_shows_snippets_without_writes() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot service add: summary"));
    assert!(stdout.contains("Operator-managed (required):"));
    assert!(stdout.contains("daemon profile snippet:"));
    assert!(stdout.contains("preview mode: no files or state were changed"));
    assert!(stdout.contains("trust preview unavailable"));
    assert!(!stdout.contains("auto-applied"));
    // The preview registers no aliases, so it reports none: reporting
    // zero here would read as a registration that attached nothing, and
    // any count at all would claim work the preview did not do.
    assert!(
        !stdout.contains("HTTP-01 DNS aliases registered"),
        "the preview must not report an alias outcome: {stdout}"
    );

    let state_contents =
        fs::read_to_string(temp_dir.path().join("state.json")).expect("read state.json");
    let state: serde_json::Value = serde_json::from_str(&state_contents).expect("parse state");
    assert!(state["services"]["edge-proxy"].is_null());
    assert!(
        !temp_dir
            .path()
            .join("secrets")
            .join("services")
            .join("edge-proxy")
            .join("secret_id")
            .exists()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_print_only_with_root_token_shows_trust_snippet() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");
    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_present(&server).await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("[trust]"));
    assert!(stdout.contains("trusted_ca_sha256"));
    assert!(stdout.contains("ca_bundle_path"));
    assert!(!stdout.contains("trust preview unavailable"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_prompts_for_missing_inputs() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let input = format!(
        "edge-proxy\nedge-proxy\nedge-node-01\ntrusted.domain\n{}\n{}\n{}\n001\n",
        agent_config.display(),
        cert_path.display(),
        key_path.display(),
    );

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "add", "--root-token", ROOT_TOKEN])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(input.as_bytes()).expect("write stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("run service add");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot service add: summary"));
    // The registration key is prompted for like every other required
    // input, so a bare `service add` still registers under one.
    assert!(stdout.contains("- registration id: edge-proxy"));
    assert!(stdout.contains("- service name: edge-proxy"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_reprompts_on_invalid_inputs() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    // Service add only revalidates a path when the parent is missing
    // (`must_exist=true`).  Issue #607 dropped that gate for output paths
    // so `service add` can `create_dir_all` them at the write boundary;
    // the only remaining reprompt-on-invalid path here is the empty
    // instance id.
    let input = format!(
        "edge-proxy\nedge-proxy\nedge-node-01\ntrusted.domain\n{}\n{}\n{}\n\n001\n",
        agent_config.display(),
        cert_path.display(),
        key_path.display(),
    );

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "add", "--root-token", ROOT_TOKEN])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(input.as_bytes()).expect("write stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("run service add");
    assert!(output.status.success());
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_reprompts_on_invalid_identifier_inputs() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let input = format!(
        "Edge-Proxy\nedge-proxy-001\nedge.proxy\nedge-proxy\nedge_node\nedge-node-01\ntrusted_domain\ntrusted.domain\n{}\n{}\n{}\ninstance-01\n001\n",
        agent_config.display(),
        cert_path.display(),
        key_path.display(),
    );

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "add", "--print-only"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(input.as_bytes()).expect("write stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("run service add");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "stdout:\n{stdout}");
    assert!(stdout.contains("registration_id must be lowercase letters"));
    assert!(stdout.contains("service_name must be a DNS label"));
    assert!(stdout.contains("hostname must be a DNS label"));
    assert!(stdout.contains("domain must be a DNS name"));
    assert!(stdout.contains("instance_id must be numeric"));
    assert!(stdout.contains("bootroot service add: summary"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_invalid_identifier_args() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--registration-id",
            "edge-node-01-edge-proxy-001",
            "--service-name",
            "edge.proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
        ])
        .output()
        .expect("run service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("service_name must be a DNS label"));
}

/// An invalid `--registration-id` supplied as a flag is rejected before
/// anything is registered, and the rejection is localized: an operator
/// running under `ko` gets the Korean message, not an English fallback.
/// The values cover each way the path-safe rule can be broken — charset,
/// shape, and the 131-octet bound — so a validator that checked only one
/// of them would fail here.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_invalid_registration_id_in_both_locales() {
    let over_limit = "a".repeat(132);
    let invalid = [
        "H1-Piglet",         // uppercase
        "h1_piglet",         // underscore
        "-h1-piglet",        // leading hyphen
        "h1/piglet",         // path separator
        "..",                // traversal
        over_limit.as_str(), // one octet past the structural maximum
    ];
    // Substrings of the localized messages, chosen to be stable under
    // rewording of the surrounding sentence.
    let expected = [
        ("en", "registration_id must be lowercase"),
        ("ko", "registration_id는"),
    ];

    for (lang, needle) in expected {
        for value in invalid {
            let temp_dir = tempdir().expect("create temp dir");
            let agent_config = temp_dir.path().join("agent.toml");
            let cert_dir = temp_dir.path().join("certs");
            fs::create_dir_all(&cert_dir).expect("create cert dir");
            let cert_path = cert_dir.join("edge-proxy.crt");
            let key_path = cert_dir.join("edge-proxy.key");

            write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

            // `--flag=value`, not `--flag value`: a leading-hyphen value
            // is otherwise parsed as another flag and never reaches the
            // validator this asserts on.
            let registration_id_arg = format!("--registration-id={value}");

            let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
                .current_dir(temp_dir.path())
                // `--lang` rather than the environment: the process
                // environment stays untouched, so this cannot race a
                // concurrently running test.
                .args([
                    "--lang",
                    lang,
                    "service",
                    "add",
                    "--print-only",
                    registration_id_arg.as_str(),
                    "--service-name",
                    "piglet",
                    "--hostname",
                    "h1",
                    "--domain",
                    "trusted.domain",
                    "--agent-config",
                    agent_config.to_string_lossy().as_ref(),
                    "--cert-path",
                    cert_path.to_string_lossy().as_ref(),
                    "--key-path",
                    key_path.to_string_lossy().as_ref(),
                    "--instance-id",
                    "001",
                ])
                .output()
                .expect("run service add");

            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !output.status.success(),
                "{lang}: {value:?} must be rejected"
            );
            assert!(
                stderr.contains(needle),
                "{lang}: {value:?} must be rejected with the localized \
                 registration_id message, got: {stderr}"
            );
        }
    }
}

/// Issue #691: the containerized-consumer story is the consumer-reload
/// hook, not a per-service agent sidecar. `service add` must keep
/// accepting `--reload-style docker-restart --reload-target <container>`
/// so operators can restart a containerized consumer app after renewal.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_accepts_docker_restart_reload_style() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--reload-style",
            "docker-restart",
            "--reload-target",
            "edge-proxy-container",
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "service add must accept --reload-style docker-restart; \
         stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("- post-renew hook: docker restart edge-proxy-container"),
        "docker-restart preset must resolve to a docker restart hook: {stdout}"
    );
}

/// Issue #691: the per-service local sidecar run model is retired, so
/// the `--deploy-type`, `--container-name`, and `--no-validate-agent`
/// flags no longer exist on `service add`. Passing any of them must be
/// rejected at the clap boundary, guarding against the flags silently
/// coming back.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_removed_sidecar_flags() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    for (flag, value) in [
        ("--deploy-type", Some("daemon")),
        ("--container-name", Some("web-app")),
        ("--no-validate-agent", None),
    ] {
        let mut args = vec![
            "service",
            "add",
            "--print-only",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            flag,
        ];
        if let Some(value) = value {
            args.push(value);
        }
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(temp_dir.path())
            .args(&args)
            .output()
            .expect("run service add");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "service add must reject the removed {flag} flag, stderr:\n{stderr}"
        );
        assert!(
            stderr.contains("unexpected argument") && stderr.contains(flag),
            "expected clap unexpected-argument error for {flag}, got: {stderr}"
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_persists_remote_bootstrap_delivery_mode() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_remote_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--delivery-mode",
            "remote-bootstrap",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(!stdout.contains("auto-applied"));
    assert!(stdout.contains("Bootroot-managed:"));
    assert!(stdout.contains("Operator-managed (required):"));
    assert!(stdout.contains("Operator-managed (recommended):"));
    assert!(stdout.contains("- remote bootstrap file (machine-readable artifact for automation):"));
    assert!(stdout.contains("- remote run command template:"));
    assert!(stdout.contains("- remote handoff order:"));
    assert!(stdout.contains("1. Copy bootstrap.json and role_id to the service host"));
    assert!(
        stdout.contains("localhost placeholders for `--agent-server` and `--agent-responder-url`")
    );
    assert!(stdout.contains("2. Check status on the step-ca host:"));
    // Remote-bootstrap hosts run the self-auth `bootroot-agent` fast-poll, not
    // a per-service OpenBao Agent. The next-steps block must advertise the
    // self-heal model and must not tell the operator to run an OpenBao Agent.
    assert!(
        stdout.contains("Keep bootroot-agent running on the remote host"),
        "remote-bootstrap add should advertise keeping bootroot-agent running: {stdout}"
    );
    assert!(
        stdout.contains("No OpenBao Agent runs on the remote host"),
        "remote-bootstrap add should state no OpenBao Agent runs: {stdout}"
    );
    assert!(
        !stdout.contains("OpenBao Agent (per-service instance):"),
        "remote-bootstrap add must not print per-service OpenBao Agent steps: {stdout}"
    );
    assert!(
        !stdout.contains("run the service-specific OpenBao Agent"),
        "remote-bootstrap add must not instruct running an OpenBao Agent: {stdout}"
    );

    let state_contents =
        fs::read_to_string(temp_dir.path().join("state.json")).expect("read state");
    let state: serde_json::Value = serde_json::from_str(&state_contents).expect("parse state");
    assert_eq!(
        state["services"]["edge-proxy"]["delivery_mode"],
        "remote-bootstrap"
    );

    // No OpenBao Agent artifacts exist anywhere: the remote host runs the
    // self-auth bootroot-agent fast-poll (schema v4 dropped these paths).
    let openbao_service_dir = temp_dir
        .path()
        .join("secrets")
        .join("openbao")
        .join("services")
        .join("edge-proxy");
    assert!(!openbao_service_dir.exists());

    let remote_bootstrap = temp_dir
        .path()
        .join("secrets")
        .join("remote-bootstrap")
        .join("services")
        .join("edge-proxy")
        .join("bootstrap.json");
    assert!(remote_bootstrap.exists());
    let bootstrap_contents = fs::read_to_string(&remote_bootstrap).expect("read bootstrap file");
    let bootstrap: serde_json::Value =
        serde_json::from_str(&bootstrap_contents).expect("parse bootstrap json");
    assert_remote_bootstrap_artifact_shape(&bootstrap);
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_remote_bootstrap_no_wrap_handoff_includes_secret_id() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao_no_wrap(&server, "edge-proxy").await;
    stub_app_add_remote_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--delivery-mode",
            "remote-bootstrap",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
            "--no-wrap",
        ])
        .output()
        .expect("run service add");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        stdout.contains("1. Copy bootstrap.json, role_id, and secret_id to the service host"),
        "non-wrapped handoff must mention secret_id; got:\n{stdout}"
    );
}

fn assert_remote_bootstrap_artifact_shape(bootstrap: &serde_json::Value) {
    assert_eq!(bootstrap["schema_version"], 5);
    assert_eq!(bootstrap["registration_id"], "edge-proxy");
    assert_eq!(bootstrap["service_name"], "edge-proxy");
    assert_eq!(bootstrap["kv_mount"], "secret");
    assert!(bootstrap["role_id_path"].is_string());
    assert!(bootstrap["secret_id_path"].is_string());
    assert!(bootstrap["eab_file_path"].is_string());
    assert!(bootstrap["agent_config_path"].is_string());
    assert!(bootstrap["ca_bundle_path"].is_string());
    assert!(bootstrap["ca_bundle_pem"].is_string());
    // The schema-5 artifact carries no OpenBao Agent artifact paths:
    // they were dropped in schema_version 4, since the remote agent
    // self-authenticates and renders trust via fast-poll.
    assert!(
        bootstrap.get("openbao_agent_config_path").is_none(),
        "openbao_agent_config_path must be absent from the schema-5 artifact"
    );
    assert!(bootstrap.get("openbao_agent_template_path").is_none());
    assert!(bootstrap.get("openbao_agent_token_path").is_none());
    assert!(
        bootstrap.get("agent_email").is_none(),
        "agent_email must be omitted when no --agent-email override was supplied"
    );
    assert!(
        bootstrap.get("agent_server").is_none(),
        "agent_server must be omitted when no --agent-server override was supplied"
    );
    assert_eq!(bootstrap["agent_domain"], "trusted.domain");
    assert!(
        bootstrap.get("agent_responder_url").is_none(),
        "agent_responder_url must be omitted when no --agent-responder-url override was supplied"
    );
    assert_eq!(bootstrap["profile_hostname"], "edge-node-01");
    assert_eq!(bootstrap["profile_instance_id"], "001");
    assert!(bootstrap["profile_cert_path"].is_string());
    assert!(bootstrap["profile_key_path"].is_string());
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_remote_bootstrap_rerun_is_idempotent() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_remote_sync_material(&server, "edge-proxy").await;

    let agent_config_value = agent_config.to_string_lossy().to_string();
    let cert_path_value = cert_path.to_string_lossy().to_string();
    let key_path_value = key_path.to_string_lossy().to_string();
    let args = [
        "service",
        "add",
        "--registration-id",
        "edge-proxy",
        "--service-name",
        "edge-proxy",
        "--delivery-mode",
        "remote-bootstrap",
        "--hostname",
        "edge-node-01",
        "--domain",
        "trusted.domain",
        "--agent-config",
        &agent_config_value,
        "--cert-path",
        &cert_path_value,
        "--key-path",
        &key_path_value,
        "--instance-id",
        "001",
        "--root-token",
        ROOT_TOKEN,
    ];

    let first = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(args)
        .output()
        .expect("run service add first");
    assert!(
        first.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&first.stdout),
        String::from_utf8_lossy(&first.stderr)
    );

    let artifact_path = temp_dir
        .path()
        .join("secrets/remote-bootstrap/services/edge-proxy/bootstrap.json");
    let first_artifact: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&artifact_path).expect("read artifact first"))
            .expect("parse artifact first");
    assert_eq!(
        first_artifact["wrap_token"].as_str(),
        Some("wrap-token-edge-proxy"),
        "first run must produce a wrapped artifact"
    );

    // Tamper with the artifact so the second run must regenerate it via
    // a fresh OpenBao call rather than leaving the old file in place.
    let mut tampered = first_artifact.clone();
    tampered["wrap_token"] = json!("stale-sentinel");
    fs::write(
        &artifact_path,
        serde_json::to_string_pretty(&tampered).expect("serialize tampered artifact"),
    )
    .expect("write tampered artifact");

    let second = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(args)
        .output()
        .expect("run service add second");
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(second.status.success());
    assert!(stdout.contains("existing remote-bootstrap service matched input"));

    let second_artifact: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&artifact_path).expect("read artifact second"))
            .expect("parse artifact second");
    assert_eq!(
        second_artifact["wrap_token"].as_str(),
        Some("wrap-token-edge-proxy"),
        "idempotent rerun must issue a fresh wrapped secret-id and regenerate the artifact"
    );

    let state_contents =
        fs::read_to_string(temp_dir.path().join("state.json")).expect("read state");
    let state: serde_json::Value = serde_json::from_str(&state_contents).expect("parse state");
    assert!(state["services"]["edge-proxy"].is_object());

    assert_idempotent_rerun_reapplied_policy(&server, "edge-proxy").await;
}

/// Asserts that the idempotent remote re-run re-POSTed the service policy so a
/// pre-existing service picks up the reissue-path write grant (issue #677).
async fn assert_idempotent_rerun_reapplied_policy(server: &MockServer, service_name: &str) {
    let policy_path = format!("/v1/sys/policies/acl/bootroot-service-{service_name}");
    let requests = server
        .received_requests()
        .await
        .expect("mock server records requests");
    let policy_writes: Vec<_> = requests
        .iter()
        .filter(|req| req.method.as_str() == "POST" && req.url.path() == policy_path)
        .collect();
    assert!(
        policy_writes.len() >= 2,
        "expected policy writes from both the initial add and the idempotent re-run, got {}",
        policy_writes.len()
    );
    let last_policy = policy_writes
        .last()
        .expect("at least one policy write recorded");
    let policy_body: serde_json::Value =
        serde_json::from_slice(&last_policy.body).expect("parse policy write body");
    let policy_text = policy_body["policy"]
        .as_str()
        .expect("policy field is a string");
    let expected = format!(
        "path \"secret/data/bootroot/services/{service_name}/reissue\" {{\n  capabilities = [\"read\", \"create\", \"update\"]"
    );
    assert!(
        policy_text.contains(&expected),
        "re-applied policy must grant create/update on the reissue path, got:\n{policy_text}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_local_file_sets_verify_prerequisites() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# existing").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let add_output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");
    assert!(add_output.status.success());
    let add_stdout = String::from_utf8_lossy(&add_output.stdout);
    assert!(add_stdout.contains("[trust]"));
    assert!(!add_stdout.contains("verify_certificates"));
    assert!(add_stdout.contains("trusted_ca_sha256"));
    assert!(add_stdout.contains("ca_bundle_path"));
    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(!agent_contents.contains("verify_certificates"));
    assert!(agent_contents.contains("trusted_ca_sha256 = ["));
    assert!(agent_contents.contains("ca_bundle_path = \""));

    write_cert_with_dns(
        &cert_path,
        &key_path,
        "001.edge-proxy.edge-node-01.trusted.domain",
    )
    .expect("write cert");

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    write_fake_bootroot_agent(&bin_dir, 0).expect("write fake bootroot-agent");
    let agent_binary = bin_dir.join("bootroot-agent");

    let verify_output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "verify",
            "--registration-id",
            "edge-proxy",
            "--agent-binary",
            agent_binary.to_string_lossy().as_ref(),
        ])
        .output()
        .expect("run verify");
    let stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(verify_output.status.success());
    assert!(stdout.contains("bootroot verify: summary"));
    assert!(stdout.contains("- result: ok"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_prompts_for_missing_instance_id() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_dir = temp_dir.path().join("certs");
    fs::create_dir_all(&cert_dir).expect("create cert dir");
    let cert_path = cert_dir.join("edge-proxy.crt");
    let key_path = cert_dir.join("edge-proxy.key");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--root-token",
            ROOT_TOKEN,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn service add");

    let mut stdin = child.stdin.take().expect("stdin");
    stdin.write_all(b"001\n").expect("write stdin");
    drop(stdin);

    let output = child.wait_with_output().expect("run service add");
    assert!(output.status.success());
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_duplicate() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let _ = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot service add failed"));
}

/// A second *distinct* local-file service must not reuse another
/// service's `agent.toml`: the top-level `[openbao]` section holds a
/// single `AppRole` identity, so a shared config would let the second
/// add overwrite the first service's `role_id`/`secret_id`/`state_path`
/// and break its KV reads under per-service policies. The rejection
/// happens before any `OpenBao` call, so no stubs exist for the second
/// service name.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_agent_config_shared_across_services() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let first = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run first service add");
    assert!(first.status.success());

    let second_cert_path = temp_dir.path().join("certs").join("billing-api.crt");
    let second_key_path = temp_dir.path().join("certs").join("billing-api.key");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "billing-api",
            "--service-name",
            "billing-api",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            second_cert_path.to_string_lossy().as_ref(),
            "--key-path",
            second_key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run second service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("is already used by service edge-proxy"),
        "expected the agent-config conflict rejection, got: {stderr}"
    );
}

/// The shared-config rejection must survive path re-spelling: the
/// first add registers `agent.toml` and the second spells the same
/// file `./agent.toml`. Without absolute lexical normalization the
/// literal comparison misses the alias and the second service
/// overwrites the first service's single `[openbao]` identity.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_agent_config_shared_via_relative_spelling() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let first = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            "agent.toml",
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run first service add");
    assert!(first.status.success());

    let second_cert_path = temp_dir.path().join("certs").join("billing-api.crt");
    let second_key_path = temp_dir.path().join("certs").join("billing-api.key");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "billing-api",
            "--service-name",
            "billing-api",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            "./agent.toml",
            "--cert-path",
            second_cert_path.to_string_lossy().as_ref(),
            "--key-path",
            second_key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run second service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("is already used by service edge-proxy"),
        "expected the agent-config conflict rejection for the \
         re-spelled path, got: {stderr}"
    );
}

/// A symlinked spelling of a registered config must also be rejected:
/// lexical normalization alone cannot see through symlinks, so the
/// guard canonicalizes existing files when comparing.
#[cfg(unix)]
#[tokio::test]
async fn test_app_add_rejects_agent_config_shared_via_symlink() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let agent_config_link = temp_dir.path().join("agent-link.toml");
    std::os::unix::fs::symlink(&agent_config, &agent_config_link).expect("symlink agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let first = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run first service add");
    assert!(first.status.success());

    let second_cert_path = temp_dir.path().join("certs").join("billing-api.crt");
    let second_key_path = temp_dir.path().join("certs").join("billing-api.key");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "billing-api",
            "--service-name",
            "billing-api",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config_link.to_string_lossy().as_ref(),
            "--cert-path",
            second_cert_path.to_string_lossy().as_ref(),
            "--key-path",
            second_key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run second service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("is already used by service edge-proxy"),
        "expected the agent-config conflict rejection for the \
         symlinked path, got: {stderr}"
    );
}

/// The state-based conflict guard cannot see a service removed without
/// `--strip-config` / `--delete-artifacts`: its `state.json` entry is
/// gone, but its managed profile block survives in `agent.toml` (the
/// documented default preserves the file). A later add of a *different*
/// service reusing that config must still be rejected — the agent
/// fast-polls every profile in the config under the single `[openbao]`
/// `AppRole` identity, so the stale service would run under the new
/// service's credentials.
#[cfg(unix)]
#[tokio::test]
// A linear two-phase scenario (add, remove without --strip-config, re-add)
// whose argument lists grew by one flag with the `registration_id` split.
#[allow(clippy::too_many_lines)]
async fn test_app_add_rejects_agent_config_with_stale_removed_service_profile() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let first = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run first service add");
    assert!(first.status.success());

    // Remove without --strip-config / --delete-artifacts: the entry
    // leaves state.json but the managed profile block stays in the file.
    let remove = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "remove",
            "--registration-id",
            "edge-proxy",
            "--yes",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service remove");
    let remove_stderr = String::from_utf8_lossy(&remove.stderr);
    assert!(
        remove.status.success(),
        "service remove must succeed, got: {remove_stderr}"
    );
    let config_after_remove = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(
        config_after_remove.contains("# BEGIN bootroot managed profile: edge-proxy"),
        "remove without --strip-config must preserve the managed \
         profile block: {config_after_remove}"
    );

    let second_cert_path = temp_dir.path().join("certs").join("billing-api.crt");
    let second_key_path = temp_dir.path().join("certs").join("billing-api.key");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "billing-api",
            "--service-name",
            "billing-api",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            second_cert_path.to_string_lossy().as_ref(),
            "--key-path",
            second_key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run second service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("still contains a bootroot-managed profile for service edge-proxy"),
        "expected the stale-profile rejection, got: {stderr}"
    );
    let config_after_reject = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(
        !config_after_reject.contains("billing-api"),
        "the rejected add must not have written anything: {config_after_reject}"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_includes_trust_snippet_when_present() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_present(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("[trust]"));
    assert!(!stdout.contains("verify_certificates"));
    assert!(stdout.contains("trusted_ca_sha256"));
    assert!(stdout.contains("ca_bundle_path"));
    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(agent_contents.contains("[trust]"));
    assert!(!agent_contents.contains("verify_certificates"));
    assert!(agent_contents.contains("trusted_ca_sha256"));
    assert!(agent_contents.contains("ca_bundle_path = \""));
    let bundle_path = temp_dir.path().join("certs").join("ca-bundle.pem");
    let bundle_contents = fs::read_to_string(&bundle_path).expect("read ca bundle");
    assert!(bundle_contents.contains("BEGIN CERTIFICATE"));
    let mode = fs::metadata(&bundle_path)
        .expect("bundle metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o644,
        "operator-facing CA bundle is public trust material and must be 0644"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_uses_synced_trust_when_metadata_missing() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("[trust]"));
    assert!(!stdout.contains("verify_certificates"));
    assert!(stdout.contains("trusted_ca_sha256"));
    assert!(stdout.contains("ca_bundle_path"));
    let agent_contents = fs::read_to_string(&agent_config).expect("read agent config");
    assert!(!agent_contents.contains("verify_certificates"));
    assert!(agent_contents.contains("trusted_ca_sha256"));
    assert!(agent_contents.contains("ca_bundle_path = \""));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_add_fails_when_synced_trust_bundle_missing() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    fs::write(&agent_config, "# config").expect("write agent config");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material_without_bundle(&server, "edge-proxy").await;

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "stderr: {stderr}");
    assert!(stderr.contains("bootroot service add failed"));
    assert!(stderr.contains("ca_bundle_pem"));
}

#[cfg(unix)]
#[tokio::test]
async fn test_app_info_prints_summary() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "info", "--registration-id", "edge-proxy"])
        .output()
        .expect("run service info");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("bootroot service info: summary"));
    assert!(stdout.contains("- service name: edge-proxy"));
    assert!(stdout.contains("- domain: trusted.domain"));
    assert!(stdout.contains("- delivery mode: local-file"));
    assert!(stdout.contains("- secret_id path: secrets/services/edge-proxy/secret_id"));
    // Local-file next steps document the host-daemon run command; the
    // retired per-service OpenBao Agent step block must be gone.
    assert!(
        stdout.contains(
            "daemon run command (systemd ExecStart or shell; \
             --eab-file is required for EAB rotation to apply):"
        ),
        "service info must print the daemon run command title: {stdout}"
    );
    assert!(
        stdout.contains(
            "bootroot-agent --config agent.toml --eab-file secrets/services/edge-proxy/eab.json"
        ),
        "service info must print the run command with --eab-file: {stdout}"
    );
    assert!(
        !stdout.contains("OpenBao Agent (per-service instance)"),
        "the per-service OpenBao Agent step block is retired: {stdout}"
    );
    assert!(
        !stdout.contains("openbao-sidecar"),
        "the openbao-sidecar start hint is retired: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn test_app_info_missing_state_file() {
    let temp_dir = tempdir().expect("create temp dir");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "info", "--registration-id", "edge-proxy"])
        .output()
        .expect("run service info");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("bootroot service info failed"));
}

/// The container ID the fake `docker` reports for a running responder.
const FAKE_RESPONDER_ID: &str = "fakeresponder01";
/// The network that fake responder is attached to.
const FAKE_RESPONDER_NETWORK: &str = "bootroot_fake_default";
/// The alias `service add` derives for the fixture service below.
const SERVICE_DNS_ALIAS: &str = "001.edge-proxy.edge-node-01.trusted.domain";

/// One `service add` run against a decided Docker.
struct FakeDockerAddRun {
    output: std::process::Output,
    /// Every argument vector the fake `docker` was invoked with, one per
    /// line, so a test can assert what the command actually issued.
    docker_log: String,
}

impl FakeDockerAddRun {
    fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.output.stdout).into_owned()
    }

    fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.output.stderr).into_owned()
    }
}

/// What the fake `docker` decides for one run, so each test names the
/// branch of the registration it is about rather than a container ID.
#[derive(Clone, Copy)]
enum FakeDocker {
    /// No responder container is running.
    ResponderDown,
    /// A responder is running and every reconnect succeeds.
    ResponderUp,
    /// A responder is running, but the reconnect carrying the aliases
    /// fails; the rollback that restores plain connectivity succeeds.
    AliasedConnectFails,
}

impl FakeDocker {
    /// The container ID the fake reports for the responder — empty when
    /// none is running, which is what the `ps` lookup finds nothing on.
    fn responder_id(self) -> &'static str {
        match self {
            Self::ResponderDown => "",
            Self::ResponderUp | Self::AliasedConnectFails => FAKE_RESPONDER_ID,
        }
    }

    /// Non-empty when the fake must refuse the aliased reconnect.
    fn aliased_connect_fails(self) -> &'static str {
        match self {
            Self::ResponderDown | Self::ResponderUp => "",
            Self::AliasedConnectFails => "1",
        }
    }
}

/// Runs `service add` with a `docker` stand-in first on the child's
/// `PATH`, so the alias registration takes a decided branch rather than
/// whatever this host happens to have running.
async fn service_add_with_fake_docker(docker: FakeDocker) -> FakeDockerAddRun {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert path has a parent"))
        .expect("create cert dir");

    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_openbao(&server, "edge-proxy").await;
    stub_app_add_trust_missing(&server).await;
    stub_app_add_service_sync_material(&server, "edge-proxy").await;

    let bin_dir = temp_dir.path().join("bin");
    fs::create_dir_all(&bin_dir).expect("create fake bin dir");
    let docker_log = temp_dir.path().join("docker-args.log");
    write_fake_docker_for_aliases(&bin_dir).expect("write fake docker");
    let path = std::env::var("PATH").unwrap_or_default();
    let combined_path = format!("{}:{path}", bin_dir.display());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .env("PATH", combined_path)
        // The summary is asserted verbatim, so pin the locale rather
        // than inheriting whatever this host sets.
        .env("BOOTROOT_LANG", "en")
        .env("FAKE_DOCKER_LOG", &docker_log)
        .env("FAKE_RESPONDER_ID", docker.responder_id())
        .env("FAKE_RESPONDER_NETWORK", FAKE_RESPONDER_NETWORK)
        .env("FAKE_ALIASED_CONNECT_FAILS", docker.aliased_connect_fails())
        .args([
            "service",
            "add",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--root-token",
            ROOT_TOKEN,
        ])
        .output()
        .expect("run service add");

    FakeDockerAddRun {
        docker_log: fs::read_to_string(&docker_log).unwrap_or_default(),
        output,
    }
}

/// Writes the `docker` stand-in [`service_add_with_fake_docker`] puts on
/// the child's `PATH`.
///
/// It answers only the two lookups the alias registration makes — the
/// responder `docker ps` and the network `docker inspect` — from the
/// environment, and succeeds silently at everything else, which is what
/// a real `docker` with nothing to do would look like here.
fn write_fake_docker_for_aliases(bin_dir: &std::path::Path) -> anyhow::Result<()> {
    let script = r#"#!/bin/sh
set -eu

if [ -n "${FAKE_DOCKER_LOG:-}" ]; then
  printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
fi

case "${1:-}" in
  ps)
    if [ -n "${FAKE_RESPONDER_ID:-}" ]; then
      printf '%s\n' "$FAKE_RESPONDER_ID"
    fi
    ;;
  inspect)
    # Answer the network lookup for the responder only, so an inspect of
    # anything else is not handed this network by accident.
    for arg in "$@"; do
      if [ -n "${FAKE_RESPONDER_ID:-}" ] && [ "$arg" = "$FAKE_RESPONDER_ID" ]; then
        printf '%s\n' "${FAKE_RESPONDER_NETWORK:-}"
      fi
    done
    ;;
  network)
    if [ -n "${FAKE_ALIASED_CONNECT_FAILS:-}" ] && [ "${2:-}" = "connect" ]; then
      aliases=0
      for arg in "$@"; do
        if [ "$arg" = "--alias" ]; then
          aliases=$((aliases + 1))
        fi
      done
      # The rollback reconnect carries the responder's own service alias
      # and nothing else, so it must still succeed; anything beyond that
      # one is the aliased reconnect this run refuses.
      if [ "$aliases" -gt 1 ]; then
        printf 'fake docker: refusing the aliased connect\n' >&2
        exit 1
      fi
    fi
    ;;
esac

exit 0
"#;
    let path = bin_dir.join("docker");
    // Hand the write to a child rather than doing it here: a `fork` on
    // another thread of this test binary duplicates every descriptor
    // this process holds at that instant, and the kernel refuses to
    // execute a file any process still holds open for writing
    // (rust-lang/rust#74214).  A child's descriptor cannot be inherited
    // that way, so the fake is runnable the moment it exists.
    let mut writer = std::process::Command::new("/bin/sh")
        .arg("-c")
        .arg(r#"cat > "$1""#)
        .arg("sh")
        .arg(&path)
        .stdin(Stdio::piped())
        .spawn()
        .context("spawn the fake docker writer")?;
    writer
        .stdin
        .take()
        .context("the fake docker writer's stdin was piped")?
        .write_all(script.as_bytes())
        .context("write fake docker")?;
    let status = writer.wait().context("wait for the fake docker writer")?;
    anyhow::ensure!(status.success(), "fake docker writer failed: {status}");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
        .context("set fake docker permissions")?;
    Ok(())
}

/// Asserts the alias line sits at the fixed position the summary
/// promises: after the `OpenBao path` line and ahead of the optional
/// blocks, so neither an operator nor a script has to find it somewhere
/// that moves with whichever of those blocks a run happens to print.
fn assert_alias_line_position(stdout: &str) {
    let position = |needle: &str| {
        stdout
            .lines()
            .position(|line| line.starts_with(needle))
            .unwrap_or_else(|| panic!("summary must contain a line starting {needle}: {stdout}"))
    };
    let openbao_path = position("- OpenBao path:");
    let alias = position("- HTTP-01 DNS aliases registered:");
    let managed = position("Bootroot-managed:");
    assert!(
        openbao_path < alias && alias < managed,
        "alias line is out of position: {stdout}"
    );
}

fn write_state_file(root: &std::path::Path, openbao_url: &str) -> anyhow::Result<()> {
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

fn assert_state_contains_default_delivery_mode(root: &std::path::Path) {
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).expect("read state.json");
    let value: serde_json::Value = serde_json::from_str(&contents).expect("parse state.json");
    assert!(value["services"]["edge-proxy"].is_object());
    assert_eq!(value["services"]["edge-proxy"]["domain"], "trusted.domain");
    assert_eq!(value["services"]["edge-proxy"]["instance_id"], "001");
    assert_eq!(
        value["services"]["edge-proxy"]["delivery_mode"],
        "local-file"
    );
}

/// Asserts the local-file host-daemon artifacts (issue #691): no
/// per-service `OpenBao` Agent directory, an `agent.toml` `[openbao]`
/// section that activates the self-auth fast-poll loop, and an
/// `eab.json` provisioned next to the service `secret_id` (the mock KV
/// serves non-empty `test-kid`/`test-hmac`, so the file must exist).
fn assert_local_fast_poll_artifacts(
    root: &std::path::Path,
    agent_config: &std::path::Path,
    service_name: &str,
) {
    // The per-service OpenBao Agent artifact directory (agent.hcl,
    // *.ctmpl, token) is retired — nothing may create it anymore.
    let openbao_service_dir = root
        .join("secrets")
        .join("openbao")
        .join("services")
        .join(service_name);
    assert!(
        !openbao_service_dir.exists(),
        "no OpenBao Agent artifacts may be created for local-file services"
    );

    // agent.toml carries the [openbao] fast-poll section mirroring what
    // `bootroot-remote bootstrap` provisions on remote hosts.
    let agent_contents = fs::read_to_string(agent_config).expect("read agent config");
    let doc: toml_edit::DocumentMut = agent_contents.parse().expect("agent.toml must parse");
    let openbao = doc
        .get("openbao")
        .and_then(toml_edit::Item::as_table)
        .expect("agent.toml must contain an [openbao] table");
    let get = |key: &str| {
        openbao
            .get(key)
            .and_then(toml_edit::Item::as_str)
            .unwrap_or_else(|| panic!("[openbao].{key} must be a string"))
    };
    assert_eq!(get("kv_mount"), "secret");
    assert!(
        get("url").starts_with("http"),
        "[openbao].url must carry the state openbao_url"
    );
    let cred_dir = root.join("secrets").join("services").join(service_name);
    assert_eq!(
        std::path::Path::new(get("role_id_path")),
        std::path::Path::new("secrets/services")
            .join(service_name)
            .join("role_id")
    );
    assert_eq!(
        std::path::Path::new(get("secret_id_path")),
        std::path::Path::new("secrets/services")
            .join(service_name)
            .join("secret_id")
    );
    assert_eq!(
        std::path::Path::new(get("ca_bundle_path")),
        root.join("certs").join("ca-bundle.pem"),
        "[openbao].ca_bundle_path must sit next to the cert path"
    );
    let state_path = get("state_path");
    assert!(
        std::path::Path::new(state_path).is_absolute(),
        "[openbao].state_path must be absolute, got: {state_path}"
    );
    assert!(
        state_path.ends_with(&format!("bootroot-agent-state-{service_name}.json")),
        "[openbao].state_path must be service-keyed, got: {state_path}"
    );

    // The mock KV serves non-empty EAB material (test-kid/test-hmac), so
    // eab.json must be provisioned next to secret_id at 0600 with both
    // values, ready for the documented `--eab-file` run command.
    let eab_path = cred_dir.join("eab.json");
    let eab_contents = fs::read_to_string(&eab_path).expect("read eab.json");
    let eab: serde_json::Value = serde_json::from_str(&eab_contents).expect("parse eab.json");
    assert_eq!(eab["kid"], "test-kid");
    assert_eq!(eab["hmac"], "test-hmac");
    let eab_mode = fs::metadata(&eab_path)
        .expect("eab metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(eab_mode, 0o600, "eab.json holds credentials; must be 0600");
}

fn write_cert_with_dns(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    dns_name: &str,
) -> anyhow::Result<()> {
    // Sign the leaf with the same CA `support::test_trust_material` puts in
    // the bundle so the chain check added in #627 (`bootroot verify`'s
    // `leaf_chains_to_bundle`) succeeds. A self-signed leaf used to pass
    // through the predecessor's self-signature shortcut, but that path was
    // closed when the predicate was hardened to require a real trust anchor.
    let (cert_pem, key_pem) = support::sign_test_leaf(dns_name);
    fs::write(cert_path, cert_pem).context("write cert pem")?;
    fs::write(key_path, key_pem).context("write key pem")?;
    Ok(())
}

fn write_fake_bootroot_agent(dir: &std::path::Path, exit_code: i32) -> anyhow::Result<()> {
    let script_path = dir.join("bootroot-agent");
    let script = format!("#!/bin/sh\nexit {exit_code}\n");
    fs::write(&script_path, script).context("write fake bootroot-agent")?;
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o700))
        .context("set fake bootroot-agent perms")?;
    Ok(())
}

fn write_state_with_app(root: &std::path::Path) {
    write_state_with_app_policy(root, None, None);
}

fn write_state_with_app_policy(
    root: &std::path::Path,
    secret_id_ttl: Option<&str>,
    secret_id_wrap_ttl: Option<&str>,
) {
    write_state_with_app_full(root, secret_id_ttl, secret_id_wrap_ttl, None);
}

fn write_state_with_app_cidrs(root: &std::path::Path, cidrs: Option<&[&str]>) {
    write_state_with_app_full(root, None, None, cidrs);
}

fn write_state_with_app_full(
    root: &std::path::Path,
    secret_id_ttl: Option<&str>,
    secret_id_wrap_ttl: Option<&str>,
    token_bound_cidrs: Option<&[&str]>,
) {
    let state_path = root.join("state.json");
    let contents = fs::read_to_string(&state_path).expect("read state");
    let mut value: serde_json::Value = serde_json::from_str(&contents).expect("parse state");
    let mut approle = json!({
        "role_name": "bootroot-service-edge-proxy",
        "role_id": "role-edge-proxy",
        "secret_id_path": "secrets/services/edge-proxy/secret_id",
        "policy_name": "bootroot-service-edge-proxy"
    });
    if let Some(ttl) = secret_id_ttl {
        approle["secret_id_ttl"] = json!(ttl);
    }
    if let Some(wrap_ttl) = secret_id_wrap_ttl {
        approle["secret_id_wrap_ttl"] = json!(wrap_ttl);
    }
    if let Some(cidrs) = token_bound_cidrs {
        approle["token_bound_cidrs"] = json!(cidrs);
    }
    value["services"]["edge-proxy"] = json!({
        "registration_id": "edge-proxy",
        "service_name": "edge-proxy",
        "hostname": "edge-node-01",
        "domain": "trusted.domain",
        "agent_config_path": "agent.toml",
        "cert_path": "certs/edge-proxy.crt",
        "key_path": "certs/edge-proxy.key",
        "instance_id": "001",
        "notes": "primary",
        "approle": approle
    });
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&value).expect("serialize state"),
    )
    .expect("write state");
}

async fn stub_app_add_openbao(server: &MockServer, service_name: &str) {
    stub_app_add_openbao_with_token(server, service_name, support::ROOT_TOKEN).await;
}

async fn stub_app_add_openbao_with_token(server: &MockServer, service_name: &str, token: &str) {
    stub_app_add_openbao_common(server, service_name, token).await;

    let role = format!("bootroot-service-{service_name}");
    let wrap_token = format!("wrap-token-{service_name}");
    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role}/secret-id")))
        .and(header("X-Vault-Token", token))
        .and(header_exists("X-Vault-Wrap-TTL"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": &wrap_token,
                "ttl": 1800,
                "creation_time": "2026-04-12T00:00:00Z",
                "creation_path": format!("auth/approle/role/{role}/secret-id")
            }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path("/v1/sys/wrapping/unwrap"))
        .and(header("X-Vault-Token", &wrap_token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "secret_id": format!("secret-{service_name}"),
                "secret_id_accessor": "acc"
            }
        })))
        .mount(server)
        .await;
}

async fn stub_app_add_openbao_no_wrap(server: &MockServer, service_name: &str) {
    stub_app_add_openbao_common(server, service_name, support::ROOT_TOKEN).await;

    let role = format!("bootroot-service-{service_name}");
    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role}/secret-id")))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {
                "secret_id": format!("secret-{service_name}"),
                "secret_id_accessor": "acc"
            }
        })))
        .mount(server)
        .await;
}

async fn stub_app_add_openbao_common(server: &MockServer, service_name: &str, token: &str) {
    let role = format!("bootroot-service-{service_name}");

    Mock::given(method("POST"))
        .and(path(format!("/v1/sys/policies/acl/{role}")))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role}")))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{role}/role-id")))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "role_id": format!("role-{service_name}") }
        })))
        .mount(server)
        .await;
}

async fn stub_app_add_trust_present(server: &MockServer) {
    stub_app_add_trust_present_with_token(server, support::ROOT_TOKEN).await;
}

async fn stub_app_add_trust_present_with_token(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;

    let (ca_pem, ca_fp) = support::test_trust_material();
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", token))
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
}

async fn stub_app_add_trust_missing(server: &MockServer) {
    stub_app_add_trust_missing_with_token(server, support::ROOT_TOKEN).await;
}

async fn stub_app_add_trust_missing_with_token(server: &MockServer, token: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(404))
        .mount(server)
        .await;
}

async fn stub_app_add_policy_write_forbidden_with_token(
    server: &MockServer,
    service_name: &str,
    token: &str,
) {
    let role = format!("bootroot-service-{service_name}");
    Mock::given(method("POST"))
        .and(path(format!("/v1/sys/policies/acl/{role}")))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "errors": ["permission denied"]
        })))
        .mount(server)
        .await;
}

async fn stub_approle_login(
    server: &MockServer,
    role_id: &str,
    secret_id: &str,
    client_token: &str,
) {
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .and(body_json(json!({
            "role_id": role_id,
            "secret_id": secret_id
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "auth": { "client_token": client_token }
        })))
        .mount(server)
        .await;
}

async fn stub_app_add_service_sync_material(server: &MockServer, service_name: &str) {
    stub_app_add_service_sync_material_with_token(server, service_name, support::ROOT_TOKEN).await;
}

async fn stub_app_add_service_sync_material_with_token(
    server: &MockServer,
    service_name: &str,
    token: &str,
) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "test-kid", "hmac": "test-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "value": "test-responder-hmac" } }
        })))
        .mount(server)
        .await;

    let (ca_pem, ca_fp) = support::test_trust_material();
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "trusted_ca_sha256": [ca_fp],
                "ca_bundle_pem": ca_pem
            } }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/eab"
        )))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/http_responder_hmac"
        )))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/trust"
        )))
        .and(header("X-Vault-Token", token))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

async fn stub_app_add_service_sync_material_without_bundle(
    server: &MockServer,
    service_name: &str,
) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "test-kid", "hmac": "test-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "value": "test-responder-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "trusted_ca_sha256": ["aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"]
            } }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/eab"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/http_responder_hmac"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/trust"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

#[cfg(unix)]
#[test]
fn test_service_update_sets_secret_id_ttl() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--secret-id-ttl",
            "2h",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("secret_id_ttl"));
    assert!(stdout.contains("2h"));

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert_eq!(
        state["services"]["edge-proxy"]["approle"]["secret_id_ttl"],
        "2h"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_disables_wrapping() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--no-wrap",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("secret_id_wrap_ttl"));

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert_eq!(
        state["services"]["edge-proxy"]["approle"]["secret_id_wrap_ttl"],
        "0"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_inherit_clears_ttl() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app_policy(temp_dir.path(), Some("1h"), None);

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--secret-id-ttl",
            "inherit",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert!(
        state["services"]["edge-proxy"]["approle"]["secret_id_ttl"].is_null(),
        "secret_id_ttl should be cleared (null)"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_reenables_wrapping() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app_policy(temp_dir.path(), None, Some("0"));

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--secret-id-wrap-ttl",
            "15m",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert_eq!(
        state["services"]["edge-proxy"]["approle"]["secret_id_wrap_ttl"],
        "15m"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_wrap_ttl_inherit_restores_default() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app_policy(temp_dir.path(), None, Some("0"));

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--secret-id-wrap-ttl",
            "inherit",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert!(
        state["services"]["edge-proxy"]["approle"]["secret_id_wrap_ttl"].is_null(),
        "secret_id_wrap_ttl should be cleared (null) after inherit"
    );

    // Verify service info shows the default wrap TTL label
    let info_output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "info", "--registration-id", "edge-proxy"])
        .output()
        .expect("run service info");

    let info_stdout = String::from_utf8_lossy(&info_output.stdout);
    assert!(
        info_stdout.contains("30m (default)"),
        "service info should report default wrap TTL, got: {info_stdout}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_not_found() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "nonexistent",
            "--secret-id-ttl",
            "1h",
        ])
        .output()
        .expect("run service update");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("Service not found"));
}

#[cfg(unix)]
#[test]
fn test_service_update_no_flags_errors() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "update", "--registration-id", "edge-proxy"])
        .output()
        .expect("run service update");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No update flags specified"));
}

#[cfg(unix)]
#[test]
fn test_service_update_shows_rotate_hint() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--secret-id-ttl",
            "1h",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("rotate approle-secret-id"),
        "should show rotate hint"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_shows_ttl_rotation_cadence_hint() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--secret-id-ttl",
            "2h",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NOTE: Ensure the secret_id TTL is at least 2"),
        "should show rotation cadence hint on stderr, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_warns_when_ttl_exceeds_recommended() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--secret-id-ttl",
            "72h",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("WARNING: --secret-id-ttl (72h) exceeds the recommended threshold"),
        "should warn about exceeding recommended TTL, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_rejects_ttl_exceeding_max() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--secret-id-ttl",
            "200h",
        ])
        .output()
        .expect("run service update");

    assert!(
        !output.status.success(),
        "should fail when TTL exceeds 168h"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exceeds the maximum allowed value"),
        "should report TTL exceeds max, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_noop_when_value_unchanged() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    // Wrapping already disabled (secret_id_wrap_ttl = "0")
    write_state_with_app_policy(temp_dir.path(), Some("1h"), Some("0"));

    // --no-wrap on already-disabled wrapping should be a no-op
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--no-wrap",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("No fields changed"),
        "should report no changes when value is already set, got: {stdout}"
    );

    // --secret-id-ttl with same value should also be a no-op but still
    // show the rotation-cadence hint
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--secret-id-ttl",
            "1h",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "stderr: {stderr}");
    assert!(
        stdout.contains("No fields changed"),
        "should report no changes when TTL is already set, got: {stdout}"
    );
    assert!(
        stderr.contains("NOTE: Ensure the secret_id TTL is at least 2"),
        "should show rotation cadence hint even when value unchanged, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_update_rn_cidrs_clear_removes_bound_cidrs() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app_cidrs(temp_dir.path(), Some(&["10.0.0.0/24", "192.168.1.0/24"]));

    // Verify CIDRs are set before update
    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert!(
        state["services"]["edge-proxy"]["approle"]["token_bound_cidrs"].is_array(),
        "token_bound_cidrs should be set before clear"
    );

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--rn-cidrs",
            "clear",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("token_bound_cidrs"),
        "should report token_bound_cidrs changed, got: {stdout}"
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    assert!(
        state["services"]["edge-proxy"]["approle"]["token_bound_cidrs"].is_null(),
        "token_bound_cidrs should be cleared (null) after --rn-cidrs clear"
    );
}

/// Issue #614 — `service update --reload-style sighup --reload-target X`
/// installs a post-renew hook on an already-registered service. Tests
/// the retrofit path that lets operators wire a hook on services that
/// were registered without `--reload-style`, without having to remove
/// and re-add the service.
#[cfg(unix)]
#[test]
fn test_service_update_installs_post_renew_hook_via_reload_style() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    // The retrofit re-renders the managed agent.toml block, so seed a
    // minimal file with the bootroot-managed block markers.
    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--reload-style",
            "sighup",
            "--reload-target",
            "review",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("post_renew_hooks"),
        "should report post_renew_hooks change, got: {stdout}"
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    let hooks = state["services"]["edge-proxy"]["post_renew_hooks"]
        .as_array()
        .expect("post_renew_hooks is an array");
    assert_eq!(hooks.len(), 1, "expected one hook entry");
    assert_eq!(hooks[0]["command"], "pkill");
    assert_eq!(
        hooks[0]["args"],
        serde_json::json!(["-HUP", "review"]),
        "expected sighup args"
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert!(
        agent_contents.contains("[[profiles.hooks.post_renew.success]]"),
        "agent.toml should be re-rendered with the new hook, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("pkill"),
        "agent.toml should embed the hook command, got: {agent_contents}"
    );
}

/// Issue #702 — `service update` may arm a `--reload-style` preset and a
/// `--post-renew-command` custom hook in one invocation. Both must be
/// persisted to state and rendered into `agent.toml`, in the deterministic
/// order "preset first, custom second", so a leaf consumed by two
/// processes (e.g. a container restart plus an in-container nginx reload)
/// can refresh both from a single renewal.
#[cfg(unix)]
#[test]
fn test_service_update_installs_preset_and_custom_hooks_in_order() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--reload-style",
            "docker-restart",
            "--reload-target",
            "aimer-web-next-app-1",
            "--post-renew-command",
            "docker",
            "--post-renew-arg",
            "exec",
            "--post-renew-arg",
            "aimer-web-nginx-prod-1",
            "--post-renew-arg",
            "nginx",
            "--post-renew-arg",
            "-s",
            "--post-renew-arg",
            "reload",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "preset + custom hook must be accepted; stdout: {stdout}\nstderr: {stderr}"
    );

    let state: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(temp_dir.path().join("state.json")).expect("read state"),
    )
    .expect("parse state");
    let hooks = state["services"]["edge-proxy"]["post_renew_hooks"]
        .as_array()
        .expect("post_renew_hooks is an array");
    assert_eq!(hooks.len(), 2, "both hooks must be persisted: {hooks:?}");

    // Preset entry first.
    assert_eq!(hooks[0]["command"], "docker");
    assert_eq!(
        hooks[0]["args"],
        serde_json::json!(["restart", "aimer-web-next-app-1"])
    );
    // Custom-command entry second.
    assert_eq!(hooks[1]["command"], "docker");
    assert_eq!(
        hooks[1]["args"],
        serde_json::json!(["exec", "aimer-web-nginx-prod-1", "nginx", "-s", "reload"])
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert_eq!(
        agent_contents
            .matches("[[profiles.hooks.post_renew.success]]")
            .count(),
        2,
        "agent.toml must render both hook blocks: {agent_contents}"
    );
    // The preset "restart" block must be emitted before the custom
    // "exec …" block.
    let restart_pos = agent_contents
        .find("\"restart\"")
        .expect("restart hook rendered");
    let exec_pos = agent_contents.find("\"exec\"").expect("exec hook rendered");
    assert!(
        restart_pos < exec_pos,
        "preset hook must render before custom hook: {agent_contents}"
    );
}

/// Issue #643 — `service update --reload-style …` must preserve a
/// `[trust]` section that `service add` wrote *inside* the managed-block
/// markers. The whole-span re-render used to drop it, leaving the agent's
/// ACME client unable to verify a private CA (`UnknownIssuer`).
#[cfg(unix)]
#[test]
fn test_service_update_reload_style_preserves_inline_trust() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    // Mirror the `service add` layout: `[trust]` lands inside the
    // BEGIN/END markers as a dangling-comment-preceding table.
    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         \n\
         [trust]\n\
         ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\"\n\
         trusted_ca_sha256 = [\"root-sha\", \"intermediate-sha\"]\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--reload-style",
            "sighup",
            "--reload-target",
            "review",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert!(
        agent_contents.contains("[[profiles.hooks.post_renew.success]]"),
        "agent.toml should be re-rendered with the new hook, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\""),
        "[trust].ca_bundle_path must survive the re-render, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("trusted_ca_sha256 = [\"root-sha\", \"intermediate-sha\"]"),
        "[trust].trusted_ca_sha256 must survive the re-render, got: {agent_contents}"
    );
    assert_eq!(
        agent_contents.matches("[trust]").count(),
        1,
        "exactly one [trust] section expected, got: {agent_contents}"
    );
}

/// Issue #643 — when `[trust]` already lives *outside* the managed-block
/// markers, the carry-over must update it in place and never produce a
/// duplicate section.
#[cfg(unix)]
#[test]
fn test_service_update_reload_style_keeps_outside_trust_unique() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "[trust]\n\
         ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\"\n\
         \n\
         # BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--reload-style",
            "sighup",
            "--reload-target",
            "review",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert_eq!(
        agent_contents.matches("[trust]").count(),
        1,
        "an out-of-block [trust] must not be duplicated, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\""),
        "[trust].ca_bundle_path must survive, got: {agent_contents}"
    );
}

/// Issue #643 — a config with no `[trust]` section must not gain a
/// synthesized empty one during a re-render.
#[cfg(unix)]
#[test]
fn test_service_update_reload_style_no_trust_stays_absent() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--reload-style",
            "sighup",
            "--reload-target",
            "review",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert!(
        !agent_contents.contains("[trust]"),
        "no [trust] section should be synthesized, got: {agent_contents}"
    );
}

/// Issue #645 — `service update --cert-group …` reaches
/// `rerender_local_managed_profile` through the `redeploy_hint` branch
/// (a different trigger than `--reload-style`'s `hooks_changed`), so the
/// `[trust]` carry-over must hold on this path too. A regression here
/// would silently reintroduce the issue #643 `UnknownIssuer` bug for
/// cert-group updates while the `--reload-style` tests stayed green.
#[cfg(unix)]
#[test]
fn test_service_update_cert_group_preserves_inline_trust() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    // Mirror the `service add` layout: `[trust]` lands inside the
    // BEGIN/END markers as a dangling-comment-preceding table.
    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         \n\
         [trust]\n\
         ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\"\n\
         trusted_ca_sha256 = [\"root-sha\", \"intermediate-sha\"]\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    // `--cert-group clear` drives the re-render purely through the
    // `redeploy_hint` branch (no hook change), exercising the trigger the
    // `--reload-style` tests never reach.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--cert-group",
            "clear",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert!(
        agent_contents.contains("ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\""),
        "[trust].ca_bundle_path must survive the cert-group re-render, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("trusted_ca_sha256 = [\"root-sha\", \"intermediate-sha\"]"),
        "[trust].trusted_ca_sha256 must survive the cert-group re-render, got: {agent_contents}"
    );
    assert_eq!(
        agent_contents.matches("[trust]").count(),
        1,
        "exactly one [trust] section expected, got: {agent_contents}"
    );
}

/// Issue #645 — when `[trust]` already lives *outside* the managed-block
/// markers, the `--cert-group` re-render must update it in place and
/// never produce a duplicate section, mirroring the `--reload-style`
/// guarantee.
#[cfg(unix)]
#[test]
fn test_service_update_cert_group_keeps_outside_trust_unique() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "[trust]\n\
         ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\"\n\
         \n\
         # BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--cert-group",
            "clear",
        ])
        .output()
        .expect("run service update");

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let agent_contents = fs::read_to_string(&agent_toml).expect("read agent.toml");
    assert_eq!(
        agent_contents.matches("[trust]").count(),
        1,
        "an out-of-block [trust] must not be duplicated, got: {agent_contents}"
    );
    assert!(
        agent_contents.contains("ca_bundle_path = \"/opt/demo-mtls/ca-bundle.pem\""),
        "[trust].ca_bundle_path must survive, got: {agent_contents}"
    );
}

/// Issue #614 — `service update --reload-style none` clears a
/// previously configured hook without re-onboarding.
#[cfg(unix)]
#[test]
fn test_service_update_reload_style_none_clears_existing_hook() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    // Seed an existing hook into state and a managed agent.toml block.
    let state_path = temp_dir.path().join("state.json");
    let mut state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
            .expect("parse state");
    state["services"]["edge-proxy"]["post_renew_hooks"] = serde_json::json!([{
        "command": "pkill",
        "args": ["-HUP", "review"],
        "timeout_secs": 30,
        "on_failure": "continue"
    }]);
    fs::write(
        &state_path,
        serde_json::to_string_pretty(&state).expect("serialize state"),
    )
    .expect("write state");

    let agent_toml = temp_dir.path().join("agent.toml");
    fs::write(
        &agent_toml,
        "# BEGIN bootroot managed profile: edge-proxy\n\
         [[profiles]]\n\
         name = \"edge-proxy\"\n\
         [[profiles.hooks.post_renew.success]]\n\
         command = \"pkill\"\n\
         args = [\"-HUP\", \"review\"]\n\
         timeout_secs = 30\n\
         on_failure = \"continue\"\n\
         # END bootroot managed profile: edge-proxy\n",
    )
    .expect("seed agent.toml");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "update",
            "--registration-id",
            "edge-proxy",
            "--reload-style",
            "none",
        ])
        .output()
        .expect("run service update");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    assert!(
        stdout.contains("post_renew_hooks"),
        "should report hooks change, got: {stdout}"
    );

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).expect("read state"))
            .expect("parse state");
    let hooks = state["services"]["edge-proxy"]["post_renew_hooks"]
        .as_array()
        .expect("post_renew_hooks is an array");
    assert!(hooks.is_empty(), "hooks should be cleared, got: {hooks:?}");
}

#[cfg(unix)]
#[test]
fn test_service_add_rejects_rn_cidrs_clear() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--rn-cidrs",
            "clear",
        ])
        .output()
        .expect("run service add");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "service add --rn-cidrs clear should fail, stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("clear"),
        "error should mention 'clear', got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_add_print_only_shows_ttl_rotation_cadence_hint() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--secret-id-ttl",
            "2h",
        ])
        .output()
        .expect("run service add");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("NOTE: Ensure the secret_id TTL is at least 2"),
        "should show rotation cadence hint on stderr, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_add_print_only_warns_when_ttl_exceeds_recommended() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--secret-id-ttl",
            "72h",
        ])
        .output()
        .expect("run service add");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("WARNING: --secret-id-ttl (72h) exceeds the recommended threshold"),
        "should warn about exceeding recommended TTL, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_add_print_only_rejects_ttl_exceeding_max() {
    let temp_dir = tempdir().expect("create temp dir");
    let agent_config = temp_dir.path().join("agent.toml");
    let cert_path = temp_dir.path().join("certs").join("edge-proxy.crt");
    let key_path = temp_dir.path().join("certs").join("edge-proxy.key");
    fs::create_dir_all(cert_path.parent().expect("cert parent")).expect("create cert dir");

    write_state_file(temp_dir.path(), "http://localhost:8200").expect("write state.json");

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args([
            "service",
            "add",
            "--print-only",
            "--registration-id",
            "edge-proxy",
            "--service-name",
            "edge-proxy",
            "--hostname",
            "edge-node-01",
            "--domain",
            "trusted.domain",
            "--agent-config",
            agent_config.to_string_lossy().as_ref(),
            "--cert-path",
            cert_path.to_string_lossy().as_ref(),
            "--key-path",
            key_path.to_string_lossy().as_ref(),
            "--instance-id",
            "001",
            "--secret-id-ttl",
            "200h",
        ])
        .output()
        .expect("run service add");

    assert!(
        !output.status.success(),
        "should fail when TTL exceeds 168h"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exceeds the maximum allowed value"),
        "should report TTL exceeds max, got: {stderr}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_info_shows_policy_fields() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app_policy(temp_dir.path(), Some("4h"), Some("10m"));

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "info", "--registration-id", "edge-proxy"])
        .output()
        .expect("run service info");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(stdout.contains("secret_id TTL: 4h"), "stdout: {stdout}");
    assert!(
        stdout.contains("secret_id wrap TTL: 10m"),
        "stdout: {stdout}"
    );
}

#[cfg(unix)]
#[test]
fn test_service_info_shows_default_policy_fields() {
    let temp_dir = tempdir().expect("create temp dir");
    write_state_file(temp_dir.path(), "http://unused:8200").expect("write state.json");
    write_state_with_app(temp_dir.path());

    let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(temp_dir.path())
        .args(["service", "info", "--registration-id", "edge-proxy"])
        .output()
        .expect("run service info");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("secret_id TTL: inherit"),
        "stdout: {stdout}"
    );
    assert!(
        stdout.contains("secret_id wrap TTL: 30m (default)"),
        "stdout: {stdout}"
    );
}

/// Issue #691: the per-service local `OpenBao` Agent run model is retired,
/// so both `service openbao-sidecar` and its deprecated `service agent`
/// alias no longer exist. Invoking either must fail at the clap boundary
/// with an unrecognized-subcommand error, guarding against the commands
/// silently coming back.
#[cfg(unix)]
#[test]
fn test_service_sidecar_subcommands_are_gone() {
    let temp_dir = tempdir().expect("create temp dir");

    for subcommand in ["openbao-sidecar", "agent"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(temp_dir.path())
            .args([
                "service",
                subcommand,
                "start",
                "--registration-id",
                "edge-proxy",
            ])
            .output()
            .expect("run removed service subcommand");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "`bootroot service {subcommand}` must no longer parse; stderr:\n{stderr}"
        );
        assert!(
            stderr.contains("unrecognized subcommand") && stderr.contains(subcommand),
            "expected clap unrecognized-subcommand error for `service {subcommand}`, \
             got: {stderr}"
        );
    }
}

async fn stub_app_add_remote_sync_material(server: &MockServer, service_name: &str) {
    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/agent/eab"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/agent/eab"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "kid": "test-kid", "hmac": "test-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/responder/hmac"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/responder/hmac"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": { "value": "test-responder-hmac" } }
        })))
        .mount(server)
        .await;

    Mock::given(method("GET"))
        .and(path("/v1/secret/metadata/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    let (ca_pem, ca_fp) = support::test_trust_material();
    Mock::given(method("GET"))
        .and(path("/v1/secret/data/bootroot/ca"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": {
                "trusted_ca_sha256": [ca_fp],
                "ca_bundle_pem": ca_pem
            } }
        })))
        .mount(server)
        .await;

    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/secret_id"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/eab"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/http_responder_hmac"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/secret/data/bootroot/services/{service_name}/trust"
        )))
        .and(header("X-Vault-Token", support::ROOT_TOKEN))
        .respond_with(ResponseTemplate::new(200))
        .mount(server)
        .await;
}

/// Two registrations of one component on one host — `h1-piglet-001` and
/// `h1-piglet-002`, both `service_name = piglet`, both `hostname = h1` —
/// must coexist. Every namespace bootroot owns is derived from the
/// `registration_id`, so the two must differ in registry key, `AppRole`
/// and policy name, KV subtree, credential directory, managed-block
/// marker, fast-poll state filename and cert/key paths, while their SANs
/// differ only in the instance label.
#[allow(clippy::too_many_lines)]
#[cfg(unix)]
#[tokio::test]
async fn test_two_registrations_of_one_component_on_one_host_are_isolated() {
    use support::ROOT_TOKEN;

    let temp_dir = tempdir().expect("create temp dir");
    let server = MockServer::start().await;
    write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
    stub_app_add_trust_missing(&server).await;

    let registrations = ["h1-piglet-001", "h1-piglet-002"];
    for registration_id in registrations {
        stub_app_add_openbao(&server, registration_id).await;
        stub_app_add_service_sync_material(&server, registration_id).await;
    }

    for (registration_id, instance_id) in registrations.iter().zip(["001", "002"]) {
        let agent_config = temp_dir.path().join(format!("{registration_id}.toml"));
        let cert_path = temp_dir
            .path()
            .join("certs")
            .join(format!("{registration_id}.crt"));
        let key_path = temp_dir
            .path()
            .join("certs")
            .join(format!("{registration_id}.key"));
        fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

        let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(temp_dir.path())
            .args([
                "service",
                "add",
                "--registration-id",
                registration_id,
                "--service-name",
                "piglet",
                "--hostname",
                "h1",
                "--domain",
                "trusted.domain",
                "--agent-config",
                agent_config.to_string_lossy().as_ref(),
                "--cert-path",
                cert_path.to_string_lossy().as_ref(),
                "--key-path",
                key_path.to_string_lossy().as_ref(),
                "--instance-id",
                instance_id,
                "--root-token",
                ROOT_TOKEN,
            ])
            .output()
            .expect("run service add");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "add {registration_id} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(temp_dir.path().join("state.json")).unwrap())
            .expect("parse state.json");
    let services = state["services"].as_object().expect("services map");
    assert_eq!(
        services.len(),
        2,
        "both registrations must own their own registry entry: {services:?}"
    );

    let first = &services["h1-piglet-001"];
    let second = &services["h1-piglet-002"];

    // The SAN inputs are shared; only the instance label separates them.
    for entry in [first, second] {
        assert_eq!(entry["service_name"], "piglet");
        assert_eq!(entry["hostname"], "h1");
        assert_eq!(entry["domain"], "trusted.domain");
    }
    let san = |entry: &serde_json::Value| {
        format!(
            "{}.{}.{}.{}",
            entry["instance_id"].as_str().unwrap(),
            entry["service_name"].as_str().unwrap(),
            entry["hostname"].as_str().unwrap(),
            entry["domain"].as_str().unwrap(),
        )
    };
    assert_eq!(san(first), "001.piglet.h1.trusted.domain");
    assert_eq!(san(second), "002.piglet.h1.trusted.domain");

    // No SAN input is the registration key, and no SAN carries it.
    for entry in [first, second] {
        assert!(!san(entry).contains("h1-piglet"), "{}", san(entry));
    }

    // Every derived namespace differs.
    assert_eq!(
        first["approle"]["role_name"],
        "bootroot-service-h1-piglet-001"
    );
    assert_eq!(
        second["approle"]["role_name"],
        "bootroot-service-h1-piglet-002"
    );
    assert_eq!(
        first["approle"]["policy_name"],
        "bootroot-service-h1-piglet-001"
    );
    assert_eq!(
        second["approle"]["policy_name"],
        "bootroot-service-h1-piglet-002"
    );
    assert_ne!(
        first["approle"]["secret_id_path"],
        second["approle"]["secret_id_path"]
    );
    assert_ne!(first["cert_path"], second["cert_path"]);
    assert_ne!(first["key_path"], second["key_path"]);
    assert_ne!(first["agent_config_path"], second["agent_config_path"]);

    for registration_id in registrations {
        assert!(
            temp_dir
                .path()
                .join("secrets")
                .join("services")
                .join(registration_id)
                .join("secret_id")
                .exists(),
            "{registration_id} must own its credential directory"
        );

        let rendered = fs::read_to_string(temp_dir.path().join(format!("{registration_id}.toml")))
            .expect("read agent config");
        assert!(
            rendered.contains(&format!("registration_id = \"{registration_id}\"")),
            "profile must carry its own key: {rendered}"
        );
        assert!(
            rendered.contains("service_name = \"piglet\""),
            "profile must carry the plain SAN label: {rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "# BEGIN bootroot managed profile: {registration_id}"
            )),
            "managed-block marker must name the key: {rendered}"
        );
        assert!(
            rendered.contains(&format!("bootroot-agent-state-{registration_id}.json")),
            "fast-poll state filename must be keyed on the registration: {rendered}"
        );
    }
}

/// The one-key shape has to cover the cases with no instance number too:
/// a one-per-deployment singleton registers as `review`, and a
/// one-per-host component as `h1-roxyd`. For the singleton the derived
/// `OpenBao` paths, `AppRole` name and filenames are byte-identical to
/// what a pre-split `service_name = "review"` produced, because its key
/// is still the bare component name.
#[cfg(unix)]
#[tokio::test]
async fn test_singleton_and_one_per_host_registration_shapes() {
    use support::ROOT_TOKEN;

    for (registration_id, service_name, hostname) in
        [("review", "review", "cn-01"), ("h1-roxyd", "roxyd", "h1")]
    {
        let temp_dir = tempdir().expect("create temp dir");
        let server = MockServer::start().await;
        write_state_file(temp_dir.path(), &server.uri()).expect("write state.json");
        stub_app_add_trust_missing(&server).await;
        stub_app_add_openbao(&server, registration_id).await;
        stub_app_add_service_sync_material(&server, registration_id).await;

        let agent_config = temp_dir.path().join("agent.toml");
        let cert_path = temp_dir.path().join("certs").join("svc.crt");
        let key_path = temp_dir.path().join("certs").join("svc.key");
        fs::create_dir_all(cert_path.parent().unwrap()).expect("create cert dir");

        let output = std::process::Command::new(env!("CARGO_BIN_EXE_bootroot"))
            .current_dir(temp_dir.path())
            .args([
                "service",
                "add",
                "--registration-id",
                registration_id,
                "--service-name",
                service_name,
                "--hostname",
                hostname,
                "--domain",
                "trusted.domain",
                "--agent-config",
                agent_config.to_string_lossy().as_ref(),
                "--cert-path",
                cert_path.to_string_lossy().as_ref(),
                "--key-path",
                key_path.to_string_lossy().as_ref(),
                "--instance-id",
                "001",
                "--root-token",
                ROOT_TOKEN,
            ])
            .output()
            .expect("run service add");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "add {registration_id} failed\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );

        let state: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(temp_dir.path().join("state.json")).unwrap())
                .expect("parse state.json");
        let entry = &state["services"][registration_id];
        assert!(entry.is_object(), "registry key must be {registration_id}");
        assert_eq!(entry["registration_id"], registration_id);
        assert_eq!(entry["service_name"], service_name);
        assert_eq!(
            entry["approle"]["role_name"],
            format!("bootroot-service-{registration_id}")
        );
        assert_eq!(
            entry["approle"]["policy_name"],
            format!("bootroot-service-{registration_id}")
        );
        assert_eq!(
            entry["approle"]["secret_id_path"],
            format!("secrets/services/{registration_id}/secret_id")
        );

        let rendered = fs::read_to_string(&agent_config).expect("read agent config");
        assert!(
            rendered.contains(&format!("bootroot-agent-state-{registration_id}.json")),
            "state filename must be keyed on {registration_id}: {rendered}"
        );
        assert!(
            stdout.contains(&format!(
                "- OpenBao path: bootroot/services/{registration_id}"
            )),
            "summary must report the registration's KV subtree: {stdout}"
        );

        // The singleton is the compatibility anchor: its key is still the
        // bare component name, so every derived string is byte-identical
        // to what the pre-split `service_name` produced. Spelled out
        // literally so a change to any derivation is visible right here.
        if registration_id == "review" {
            assert_eq!(entry["approle"]["role_name"], "bootroot-service-review");
            assert_eq!(entry["approle"]["policy_name"], "bootroot-service-review");
            assert_eq!(
                entry["approle"]["secret_id_path"],
                "secrets/services/review/secret_id"
            );
            assert!(rendered.contains("bootroot-agent-state-review.json"));
            assert!(rendered.contains("# BEGIN bootroot managed profile: review"));
            assert!(stdout.contains("- OpenBao path: bootroot/services/review"));
        }

        // The one-per-host shape keeps the host out of the SAN — it is
        // in the key instead, and the SAN's service label stays plain.
        if registration_id == "h1-roxyd" {
            assert_eq!(entry["approle"]["role_name"], "bootroot-service-h1-roxyd");
            assert_eq!(entry["service_name"], "roxyd");
            assert_eq!(entry["hostname"], "h1");
            assert!(rendered.contains("bootroot-agent-state-h1-roxyd.json"));
            assert!(rendered.contains("service_name = \"roxyd\""));
        }
    }
}
