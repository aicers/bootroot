use std::path::Path;

use anyhow::{Context, Result, bail};

use super::RotateContext;
use super::helpers::{confirm_action, try_restart_container};
use crate::commands::init::{
    HTTP01_ADMIN_INFRA_CERT_KEY, OPENBAO_INFRA_CERT_KEY, reissue_http01_admin_tls_cert,
    reissue_openbao_tls_cert,
};
use crate::i18n::Messages;
use crate::state::{InfraCertEntry, ReloadStrategy};

/// Renews all infrastructure certificates registered in
/// `StateFile::infra_certs`.
///
/// Iterates the map, re-issues each certificate, replaces the files,
/// and invokes the entry's reload strategy.  New certificate types
/// (e.g. #515 http01 admin) register by adding an arm to
/// [`dispatch_reissue`] — the loop body does not need to change.
pub(super) fn rotate_infra_certs(
    ctx: &mut RotateContext,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    if ctx.state.infra_certs.is_empty() {
        println!("{}", messages.rotate_infra_tls_no_entries());
        return Ok(());
    }

    confirm_action(messages.prompt_rotate_infra_tls(), auto_confirm, messages)?;

    let state_file = ctx.state_file.clone();
    let compose_dir = ctx.compose_file.parent().map_or_else(
        || std::path::PathBuf::from("."),
        std::path::Path::to_path_buf,
    );

    let entries: Vec<(String, InfraCertEntry)> = ctx
        .state
        .infra_certs
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    for (name, entry) in &entries {
        dispatch_reissue(name, &compose_dir, ctx.paths.secrets_dir(), entry, messages)
            .with_context(|| messages.error_infra_tls_renew_failed(name))?;

        if let Some(state_entry) = ctx.state.infra_certs.get_mut(name) {
            state_entry.issued_at = Some(
                time::OffsetDateTime::now_utc()
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_default(),
            );
        }

        println!("{}", messages.info_infra_tls_renewed(name));

        let strategy_display = entry.reload_strategy.to_string();
        println!("{}", messages.info_infra_tls_reload(&strategy_display));
        execute_reload_strategy(&entry.reload_strategy)?;
    }

    ctx.state
        .save(&state_file)
        .with_context(|| messages.error_serialize_state_failed())?;

    Ok(())
}

/// Dispatches certificate re-issuance by infra-cert key.
///
/// Each infrastructure certificate type registers an arm here.
/// Unknown keys surface as errors through the standard rotation
/// error path.
fn dispatch_reissue(
    name: &str,
    compose_dir: &Path,
    secrets_dir: &Path,
    entry: &InfraCertEntry,
    messages: &Messages,
) -> Result<()> {
    match name {
        OPENBAO_INFRA_CERT_KEY => {
            reissue_openbao_tls_cert(compose_dir, secrets_dir, entry, messages)
        }
        HTTP01_ADMIN_INFRA_CERT_KEY => reissue_http01_admin_tls_cert(secrets_dir, entry, messages),
        _ => bail!("Unknown infra cert key: {name}"),
    }
}

/// Executes a reload strategy after certificate renewal.
fn execute_reload_strategy(strategy: &ReloadStrategy) -> Result<()> {
    match strategy {
        ReloadStrategy::ContainerRestart { container_name } => {
            try_restart_container(container_name)
                .with_context(|| format!("Failed to restart container {container_name}"))?;
        }
        ReloadStrategy::ContainerSignal {
            container_name,
            signal,
        } => {
            try_signal_container(container_name, signal)
                .with_context(|| format!("Failed to signal container {container_name}"))?;
        }
    }
    Ok(())
}

/// Sends a signal to a Docker container via `docker kill -s`.
fn try_signal_container(container: &str, signal: &str) -> Result<()> {
    let status = std::process::Command::new("docker")
        .args(["kill", "-s", signal, container])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        anyhow::bail!("container {container} not found or signal failed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::super::test_support::{
        ScopedEnvVar, TEST_DOCKER_ARGS_ENV, env_lock, path_with_prepend, test_messages,
        write_fake_docker_script,
    };
    use super::*;
    use crate::cli::args::{
        AuthMode, ComposeFileArgs, OpenBaoOverrideArgs, RotateArgs, RotateCommand,
        RotateInfraCertArgs, RuntimeAuthArgs, SecretsDirOverrideArgs,
    };
    use crate::commands::constants::RESPONDER_SERVICE_NAME;
    use crate::commands::init::{
        HTTP01_ADMIN_INFRA_CERT_KEY, HTTP01_ADMIN_TLS_CERT_REL_PATH,
        HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE, HTTP01_ADMIN_TLS_KEY_REL_PATH,
        OPENBAO_CONTAINER_NAME, OPENBAO_INFRA_CERT_KEY, OPENBAO_TLS_CERT_PATH,
        OPENBAO_TLS_DEFAULT_RENEW_BEFORE, OPENBAO_TLS_KEY_PATH,
    };
    use crate::commands::rotate::run_rotate;
    use crate::state::StateFile;

    fn make_openbao_infra_entry(compose_dir: &std::path::Path) -> InfraCertEntry {
        InfraCertEntry {
            cert_path: compose_dir.join(OPENBAO_TLS_CERT_PATH),
            key_path: compose_dir.join(OPENBAO_TLS_KEY_PATH),
            sans: vec![
                "openbao.internal".to_string(),
                "localhost".to_string(),
                "bootroot-openbao".to_string(),
            ],
            renew_before: OPENBAO_TLS_DEFAULT_RENEW_BEFORE.to_string(),
            reload_strategy: ReloadStrategy::ContainerRestart {
                container_name: OPENBAO_CONTAINER_NAME.to_string(),
            },
            issued_at: None,
            expires_at: None,
        }
    }

    /// Exercises `run_rotate(RotateCommand::InfraCert)` end-to-end with
    /// an unreachable `OpenBao` URL and a registered infra-cert entry.
    ///
    /// On the broken code path (Round 2 bug) `run_rotate` would attempt
    /// `OpenBao` auth/health-check before dispatching `InfraCert` and
    /// fail because the URL is unreachable.  With the fix, `InfraCert`
    /// is dispatched before any `OpenBao` interaction.
    ///
    /// Also verifies state-file path propagation: the state file is
    /// written to a non-default filename (`custom.json`), and the test
    /// asserts the `issued_at` update is persisted to *that* file.
    #[test]
    fn run_rotate_infra_cert_bypasses_openbao_auth() {
        let dir = tempfile::tempdir().expect("tempdir");
        let messages = test_messages();

        // -- Fake docker so both `run_docker` and `try_restart_container`
        //    succeed without a real Docker daemon.
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("bin dir");
        let docker_path = bin_dir.join("docker");
        write_fake_docker_script(&docker_path);

        let compose_dir = dir.path().join("compose");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("secrets dir");

        // Pre-create cert/key files so `set_key_permissions_sync`
        // succeeds after the fake docker "issues" the cert.
        let tls_dir = compose_dir.join("openbao").join("tls");
        fs::create_dir_all(&tls_dir).expect("tls dir");
        fs::write(tls_dir.join("server.crt"), "fake-cert").expect("write cert");
        fs::write(tls_dir.join("server.key"), "fake-key").expect("write key");

        // Build state with one infra-cert entry and an unreachable
        // OpenBao URL (RFC 5737 TEST-NET, port 1).
        let mut infra_certs = BTreeMap::new();
        infra_certs.insert(
            OPENBAO_INFRA_CERT_KEY.to_string(),
            make_openbao_infra_entry(&compose_dir),
        );

        let state = StateFile {
            openbao_url: "https://192.0.2.1:1".to_string(),
            kv_mount: String::new(),
            secrets_dir: Some(secrets_dir.clone()),
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: Some("192.168.1.10:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs,
        };

        // Write state under a non-default filename to verify that the
        // full state-file path propagates through `RotateContext`.
        let state_file = dir.path().join("custom.json");
        state.save(&state_file).expect("write state");

        let args = RotateArgs {
            command: RotateCommand::InfraCert(RotateInfraCertArgs {}),
            state_file: Some(state_file.clone()),
            compose: ComposeFileArgs {
                compose_file: compose_dir.join("docker-compose.yml"),
            },
            openbao: OpenBaoOverrideArgs {
                openbao_url: None,
                kv_mount: None,
            },
            secrets_dir: SecretsDirOverrideArgs {
                secrets_dir: Some(secrets_dir),
            },
            runtime_auth: RuntimeAuthArgs {
                auth_mode: AuthMode::Auto,
                root_token: None,
                root_token_file: None,
                approle_role_id: None,
                approle_secret_id: None,
                approle_role_id_file: None,
                approle_secret_id_file: None,
            },
            yes: true,
            show_secrets: false,
        };

        let args_log = dir.path().join("docker_args.log");

        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _log = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, &args_log);

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(run_rotate(&args, &messages))
            .expect("run_rotate(InfraCert) must succeed without OpenBao");

        // The updated state must have been written back to the
        // custom-named file (not a hardcoded `state.json`).
        let reloaded = StateFile::load(&state_file).expect("custom state file must be readable");
        let entry = reloaded
            .infra_certs
            .get(OPENBAO_INFRA_CERT_KEY)
            .expect("openbao entry must still exist");
        assert!(
            entry.issued_at.is_some(),
            "issued_at must be updated after renewal"
        );

        // No `state.json` sibling should have been created.
        assert!(
            !dir.path().join("state.json").exists(),
            "state must not be written to hardcoded state.json"
        );
    }

    fn make_http01_admin_infra_entry(secrets_dir: &std::path::Path) -> InfraCertEntry {
        InfraCertEntry {
            cert_path: secrets_dir.join(HTTP01_ADMIN_TLS_CERT_REL_PATH),
            key_path: secrets_dir.join(HTTP01_ADMIN_TLS_KEY_REL_PATH),
            sans: vec![
                "responder.internal".to_string(),
                "localhost".to_string(),
                RESPONDER_SERVICE_NAME.to_string(),
            ],
            renew_before: HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE.to_string(),
            reload_strategy: ReloadStrategy::ContainerSignal {
                container_name: RESPONDER_SERVICE_NAME.to_string(),
                signal: "SIGHUP".to_string(),
            },
            issued_at: None,
            expires_at: None,
        }
    }

    /// Exercises `run_rotate(RotateCommand::InfraCert)` with an
    /// HTTP-01 admin entry that uses `ContainerSignal` reload.
    ///
    /// Verifies the `dispatch_reissue` arm for
    /// `HTTP01_ADMIN_INFRA_CERT_KEY` and the `execute_reload_strategy`
    /// path for `ContainerSignal`.
    #[test]
    fn run_rotate_infra_cert_renews_http01_admin_tls() {
        let dir = tempfile::tempdir().expect("tempdir");
        let messages = test_messages();

        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("bin dir");
        let docker_path = bin_dir.join("docker");
        write_fake_docker_script(&docker_path);

        let compose_dir = dir.path().join("compose");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("secrets dir");

        // Pre-create cert/key files so `set_key_permissions_sync`
        // succeeds after the fake docker "issues" the cert.
        let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
        fs::create_dir_all(&tls_dir).expect("tls dir");
        fs::write(tls_dir.join("server.crt"), "fake-cert").expect("write cert");
        fs::write(tls_dir.join("server.key"), "fake-key").expect("write key");

        let mut infra_certs = BTreeMap::new();
        infra_certs.insert(
            HTTP01_ADMIN_INFRA_CERT_KEY.to_string(),
            make_http01_admin_infra_entry(&secrets_dir),
        );

        let state = StateFile {
            openbao_url: "https://192.0.2.1:1".to_string(),
            kv_mount: String::new(),
            secrets_dir: Some(secrets_dir.clone()),
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: Some("192.168.1.10:8080".to_string()),
            http01_admin_advertise_addr: None,
            infra_certs,
        };

        let state_file = dir.path().join("state.json");
        state.save(&state_file).expect("write state");

        let args = RotateArgs {
            command: RotateCommand::InfraCert(RotateInfraCertArgs {}),
            state_file: Some(state_file.clone()),
            compose: ComposeFileArgs {
                compose_file: compose_dir.join("docker-compose.yml"),
            },
            openbao: OpenBaoOverrideArgs {
                openbao_url: None,
                kv_mount: None,
            },
            secrets_dir: SecretsDirOverrideArgs {
                secrets_dir: Some(secrets_dir),
            },
            runtime_auth: RuntimeAuthArgs {
                auth_mode: AuthMode::Auto,
                root_token: None,
                root_token_file: None,
                approle_role_id: None,
                approle_secret_id: None,
                approle_role_id_file: None,
                approle_secret_id_file: None,
            },
            yes: true,
            show_secrets: false,
        };

        let args_log = dir.path().join("docker_args.log");

        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _log = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, &args_log);

        let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
        rt.block_on(run_rotate(&args, &messages))
            .expect("run_rotate(InfraCert) must succeed for http01 admin entry");

        let reloaded = StateFile::load(&state_file).expect("state file must be readable");
        let entry = reloaded
            .infra_certs
            .get(HTTP01_ADMIN_INFRA_CERT_KEY)
            .expect("http01 admin entry must still exist");
        assert!(
            entry.issued_at.is_some(),
            "issued_at must be updated after renewal"
        );

        // Verify the fake docker received a `kill -s SIGHUP` command
        // (the ContainerSignal reload strategy).
        let log = fs::read_to_string(&args_log).unwrap_or_default();
        assert!(
            log.contains("kill") && log.contains("SIGHUP"),
            "docker must have been called with kill -s SIGHUP, got: {log}"
        );
    }
}
