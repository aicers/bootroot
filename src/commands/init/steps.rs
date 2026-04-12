mod ca_certs;
mod database;
mod openbao_setup;
mod orchestrator;
mod prompts;
mod responder_setup;
mod secrets;
mod stepca_setup;

use std::path::PathBuf;

use anyhow::{Context, Result};
use bootroot::openbao::{InitResponse, OpenBaoClient};
pub(crate) use ca_certs::{
    compute_ca_bundle_pem, compute_ca_fingerprints, read_ca_cert_fingerprint,
};
pub(crate) use orchestrator::run_init;
pub(crate) use prompts::prompt_yes_no;

use super::types::EabCredentials;
use crate::i18n::Messages;

pub(super) struct InitBootstrap {
    pub(super) init_response: Option<InitResponse>,
    pub(super) root_token: String,
    pub(super) unseal_keys: Vec<String>,
}

pub(super) struct InitSecrets {
    pub(super) stepca_password: String,
    pub(super) db_dsn: String,
    pub(super) http_hmac: String,
    pub(super) eab: Option<EabCredentials>,
}

#[derive(Debug, Clone)]
pub(super) struct DbDsnNormalization {
    pub(super) original_host: String,
    pub(super) effective_host: String,
}

#[derive(Debug)]
pub(super) struct RollbackFile {
    pub(super) path: PathBuf,
    pub(super) original: Option<String>,
}

#[derive(Default)]
pub(super) struct InitRollback {
    pub(super) created_policies: Vec<String>,
    pub(super) created_approles: Vec<String>,
    pub(super) written_kv_paths: Vec<String>,
    pub(super) password_backup: Option<RollbackFile>,
    pub(super) ca_json_backup: Option<RollbackFile>,
}

impl InitRollback {
    pub(super) async fn rollback(
        &self,
        client: &OpenBaoClient,
        kv_mount: &str,
        messages: &Messages,
    ) {
        for path in &self.written_kv_paths {
            if let Err(err) = client.delete_kv(kv_mount, path).await {
                eprintln!(
                    "{}: {path}: {err}",
                    messages.error_openbao_kv_delete_failed()
                );
            }
        }
        for role in &self.created_approles {
            if let Err(err) = client.delete_approle(role).await {
                eprintln!("Rollback: failed to delete AppRole {role}: {err}");
            }
        }
        for policy in &self.created_policies {
            if let Err(err) = client.delete_policy(policy).await {
                eprintln!("Rollback: failed to delete policy {policy}: {err}");
            }
        }
        if let Some(file) = &self.password_backup
            && let Err(err) = rollback_file(file, messages)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
        }
        if let Some(file) = &self.ca_json_backup
            && let Err(err) = rollback_file(file, messages)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
        }
    }
}

fn rollback_file(file: &RollbackFile, messages: &Messages) -> Result<()> {
    if let Some(contents) = &file.original {
        std::fs::write(&file.path, contents).with_context(|| {
            messages.error_restore_file_failed(&file.path.display().to_string())
        })?;
    } else if file.path.exists() {
        std::fs::remove_file(&file.path)
            .with_context(|| messages.error_remove_file_failed(&file.path.display().to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) mod test_support {
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use super::super::constants::openbao_constants::SECRET_ID_TTL;
    use super::super::constants::{DEFAULT_STEPCA_PROVISIONER, DEFAULT_STEPCA_URL};
    use crate::cli::args::InitArgs;
    pub(in crate::commands::init::steps) use crate::i18n::test_messages;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    pub(in crate::commands::init::steps) fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    pub(in crate::commands::init::steps) fn default_init_args() -> InitArgs {
        InitArgs {
            openbao: crate::cli::args::OpenBaoArgs {
                openbao_url: "http://localhost:8200".to_string(),
                kv_mount: "secret".to_string(),
            },
            secrets_dir: crate::cli::args::SecretsDirArgs {
                secrets_dir: PathBuf::from("secrets"),
            },
            compose: crate::cli::args::ComposeFileArgs {
                compose_file: PathBuf::from("docker-compose.yml"),
            },
            enable: Vec::new(),
            skip: Vec::new(),
            summary_json: None,
            root_token: crate::cli::args::RootTokenArgs { root_token: None },
            unseal_key: Vec::new(),
            openbao_unseal_from_file: None,
            secret_id_ttl: SECRET_ID_TTL.to_string(),
            stepca_password: None,
            db_dsn: None,
            db_admin: crate::cli::args::DbAdminDsnArgs { admin_dsn: None },
            db_user: None,
            db_password: None,
            db_name: None,
            db_timeout: crate::cli::args::DbTimeoutArgs { timeout_secs: 2 },
            http_hmac: None,
            responder_url: None,
            responder_timeout_secs: 5,
            stepca_url: DEFAULT_STEPCA_URL.to_string(),
            stepca_provisioner: DEFAULT_STEPCA_PROVISIONER.to_string(),
            eab_kid: None,
            eab_hmac: None,
        }
    }

    pub(in crate::commands::init::steps) fn test_cert_pem(common_name: &str) -> String {
        let mut params =
            rcgen::CertificateParams::new(vec![common_name.to_string()]).expect("params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, common_name);
        let key = rcgen::KeyPair::generate().expect("key pair");
        let cert = params.self_signed(&key).expect("self signed");
        cert.pem()
    }
}
