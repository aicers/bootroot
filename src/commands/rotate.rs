mod approle;
mod ca;
mod db;
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
use crate::commands::init::{CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME};
use crate::commands::openbao_auth::{authenticate_openbao_client, resolve_runtime_auth};
use crate::i18n::Messages;
use crate::state::StateFile;

pub(super) const OPENBAO_AGENT_CONTAINER_PREFIX: &str = "bootroot-openbao-agent";
pub(super) const ROLE_ID_FILENAME: &str = "role_id";
pub(super) const OPENBAO_AGENT_STEPCA_CONTAINER: &str = "bootroot-openbao-agent-stepca";
pub(super) const OPENBAO_AGENT_RESPONDER_CONTAINER: &str = "bootroot-openbao-agent-responder";
pub(super) const ROOT_CA_COMMON_NAME: &str = "Bootroot Root CA";
pub(super) const INTERMEDIATE_CA_COMMON_NAME: &str = "Bootroot Intermediate CA";
pub(super) const RENDERED_FILE_POLL_INTERVAL: Duration = Duration::from_secs(1);
pub(super) const RENDERED_FILE_TIMEOUT: Duration = Duration::from_mins(1);
pub(super) const BOOTROOT_AGENT_CONTAINER_PREFIX: &str = "bootroot-agent";
pub(super) const OPENBAO_RECOVERY_SCOPE_UNSEAL_KEYS: &str = "unseal-keys";
pub(super) const OPENBAO_RECOVERY_SCOPE_ROOT_TOKEN: &str = "root-token";
pub(super) const OPENBAO_ROOT_ROTATION_INCOMPLETE_ERROR: &str =
    "OpenBao root-key rotation did not complete; verify unseal keys and retry";

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
}

#[allow(clippy::too_many_lines)]
pub(crate) async fn run_rotate(args: &RotateArgs, messages: &Messages) -> Result<()> {
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
    };

    // InfraCert operates on local files and Docker only — it must not
    // require an OpenBao connection so it can fix a broken/expired cert.
    if let RotateCommand::InfraCert(_) = &args.command {
        return infra_cert::rotate_infra_certs(&mut ctx, args.yes, messages);
    }

    let runtime_auth = resolve_runtime_auth(&args.runtime_auth, true, messages)?;
    let mut client = OpenBaoClient::new(&ctx.openbao_url)
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
            approle::rotate_approle_secret_id(&mut ctx, &client, step_args, args.yes, messages)
                .await?;
        }
        RotateCommand::TrustSync(_) => {
            ca::rotate_trust_sync(&mut ctx, &client, args.yes, messages).await?;
        }
        RotateCommand::ForceReissue(step_args) => {
            ca::rotate_force_reissue(&mut ctx, step_args, args.yes, messages)?;
        }
        RotateCommand::CaKey(step_args) => {
            ca::rotate_ca_key(&mut ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::InfraCert(_) => {
            unreachable!("InfraCert is handled before OpenBao client bootstrap")
        }
    }

    Ok(())
}

#[cfg(test)]
pub(super) mod test_support {
    use std::env;
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::path::Path;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    pub(super) use crate::i18n::test_messages;

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    pub(super) const TEST_DOCKER_ARGS_ENV: &str = "BOOTROOT_TEST_DOCKER_ARGS";
    pub(super) const TEST_DOCKER_EXIT_ENV: &str = "BOOTROOT_TEST_DOCKER_EXIT";

    pub(super) struct ScopedEnvVar {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl ScopedEnvVar {
        pub(super) fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let previous = env::var_os(key);
            // SAFETY: Tests hold ENV_LOCK while mutating process environment.
            unsafe {
                env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            // SAFETY: Tests hold ENV_LOCK while mutating process environment.
            unsafe {
                if let Some(previous) = &self.previous {
                    env::set_var(self.key, previous);
                } else {
                    env::remove_var(self.key);
                }
            }
        }
    }

    pub(super) fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .expect("environment lock must not be poisoned")
    }

    pub(super) fn write_fake_docker_script(path: &Path) {
        let script = r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "${BOOTROOT_TEST_DOCKER_ARGS:?missing log path}"
if [ -n "${BOOTROOT_TEST_DOCKER_EXIT:-}" ]; then
  exit "${BOOTROOT_TEST_DOCKER_EXIT}"
fi
exit 0
"#;
        fs::write(path, script).expect("fake docker script should be written");
        #[cfg(unix)]
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("fake docker script should be executable");
    }

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    pub(super) fn path_with_prepend(bin_dir: &Path) -> OsString {
        let mut paths = vec![bin_dir.to_path_buf()];
        if let Some(existing) = env::var_os("PATH") {
            paths.extend(env::split_paths(&existing));
        }
        env::join_paths(paths).expect("PATH components should be valid")
    }
}
