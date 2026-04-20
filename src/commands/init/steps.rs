mod ca_certs;
mod database;
pub(crate) mod http01_admin_tls;
mod openbao_setup;
pub(crate) mod openbao_tls;
mod orchestrator;
mod prompts;
mod responder_setup;
mod secrets;
pub(crate) mod stepca_setup;

use std::path::PathBuf;

use anyhow::{Context, Result};
use bootroot::openbao::{InitResponse, OpenBaoClient};
pub(crate) use ca_certs::{
    compute_ca_bundle_pem, compute_ca_fingerprints, read_ca_cert_fingerprint,
};
pub(crate) use openbao_setup::validate_secret_id_ttl;
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
    pub(super) hcl_backup: Option<RollbackFile>,
    pub(super) tls_artifacts: Vec<PathBuf>,
    pub(super) compose_file: Option<PathBuf>,
    /// Responder config backup for rolling back TLS-enabled config.
    pub(super) responder_config_backup: Option<RollbackFile>,
    /// Responder config compose override for restarting without the
    /// exposed port binding during rollback.
    pub(super) responder_compose_override: Option<PathBuf>,
}

impl InitRollback {
    pub(super) async fn rollback(
        &self,
        client: &OpenBaoClient,
        kv_mount: &str,
        messages: &Messages,
    ) {
        // Restore the HCL and remove TLS artifacts before OpenBao API
        // calls so that a container restart switches OpenBao back to
        // HTTP, letting the original HTTP client reach it for cleanup.
        if let Some(file) = &self.hcl_backup
            && let Err(err) = rollback_file(file, messages)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
        }
        for artifact in &self.tls_artifacts {
            if artifact.exists()
                && let Err(err) = std::fs::remove_file(artifact)
            {
                eprintln!("Rollback: failed to remove {}: {err}", artifact.display());
            }
        }
        if self.hcl_backup.is_some()
            && let Some(compose_file) = &self.compose_file
        {
            // Use `up -d` (not `restart`) so Docker Compose recreates
            // the container from the base compose config alone, removing
            // any non-loopback port mapping the override introduced.
            // `restart` only stops/starts the existing container and
            // preserves port bindings from the applied override, which
            // would leave OpenBao on plaintext HTTP at a non-loopback
            // address.
            let args = rollback_openbao_docker_args(compose_file);
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(err) = crate::commands::infra::run_docker(
                &arg_refs,
                "docker compose up -d openbao (rollback)",
                messages,
            ) {
                eprintln!("Rollback: failed to recreate OpenBao: {err}");
            }
        }

        // Restore the responder config (removing TLS fields) and
        // restart the container with only the config override (no
        // exposed port override) so the admin API returns to
        // loopback-only / plain-HTTP.
        if let Some(file) = &self.responder_config_backup
            && let Err(err) = rollback_file(file, messages)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
        }
        if self.responder_config_backup.is_some()
            && let Some(compose_file) = &self.compose_file
        {
            // Only include the config override when a pre-existing
            // config was restored.  On fresh install (original was
            // None) `rollback_file` removed the file, so the
            // override's `--config=` flag would point at a missing
            // file.  Omitting the override returns the responder to
            // its pre-init state (base compose only).
            let config_override = self
                .responder_config_backup
                .as_ref()
                .filter(|f| f.original.is_some())
                .and(self.responder_compose_override.as_deref());
            let args = rollback_responder_docker_args(compose_file, config_override);
            let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
            if let Err(err) = crate::commands::infra::run_docker(
                &arg_refs,
                "docker compose up -d responder (rollback)",
                messages,
            ) {
                eprintln!("Rollback: failed to recreate responder: {err}");
            }
        }

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

/// Builds the Docker Compose arguments for undoing the TLS override
/// during rollback.
///
/// Returns `["compose", "-f", <compose_file>, "up", "-d", "openbao"]`
/// so that the container is recreated from the base compose config
/// (without the non-loopback override), ensuring the external port
/// mapping is removed.
fn rollback_openbao_docker_args(compose_file: &std::path::Path) -> Vec<String> {
    vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().into_owned(),
        "up".to_string(),
        "-d".to_string(),
        "openbao".to_string(),
    ]
}

/// Builds the Docker Compose arguments for undoing the responder TLS
/// exposure during rollback.
///
/// Includes the config override (if present) so the responder keeps
/// its volume mount, but omits the exposed port override so the
/// container reverts to loopback-only binding.
fn rollback_responder_docker_args(
    compose_file: &std::path::Path,
    config_override: Option<&std::path::Path>,
) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().into_owned(),
    ];
    if let Some(override_path) = config_override {
        args.push("-f".to_string());
        args.push(override_path.to_string_lossy().into_owned());
    }
    args.push("up".to_string());
    args.push("-d".to_string());
    args.push(crate::commands::constants::RESPONDER_SERVICE_NAME.to_string());
    args
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
mod rollback_tests {
    use bootroot::openbao::OpenBaoClient;

    use super::{InitRollback, RollbackFile};

    /// Regression: rollback after a TLS rewrite must restore
    /// `openbao.hcl` to its original plaintext content and remove the
    /// TLS certificate and key artifacts.  Without this, a failure
    /// between `write_openbao_hcl_with_tls()` and `state.save()` would
    /// leave the worktree in a stale TLS-enabled state that the next
    /// `bootroot init` cannot recover from.
    #[tokio::test]
    async fn rollback_restores_hcl_and_removes_tls_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();

        // Simulate the pre-TLS plaintext HCL.
        let openbao_dir = dir.path().join("openbao");
        std::fs::create_dir_all(&openbao_dir).unwrap();
        let hcl_path = openbao_dir.join("openbao.hcl");
        let plaintext_hcl = "tls_disable = 1\n";
        std::fs::write(&hcl_path, plaintext_hcl).unwrap();

        // Simulate TLS artifacts that would be created by
        // `issue_openbao_tls_cert`.
        let tls_dir = openbao_dir.join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        let cert_path = tls_dir.join("server.crt");
        let key_path = tls_dir.join("server.key");
        std::fs::write(&cert_path, "CERT").unwrap();
        std::fs::write(&key_path, "KEY").unwrap();

        // Overwrite HCL with TLS content (simulating the write that
        // would have happened before the failure).
        std::fs::write(&hcl_path, "tls_cert_file = ...\n").unwrap();

        let rollback = InitRollback {
            hcl_backup: Some(RollbackFile {
                path: hcl_path.clone(),
                original: Some(plaintext_hcl.to_string()),
            }),
            tls_artifacts: vec![cert_path.clone(), key_path.clone()],
            // No compose_file — skips the container restart in tests.
            compose_file: None,
            ..Default::default()
        };

        // A dummy client that won't be called (no KV/AppRole entries).
        let client = OpenBaoClient::new("http://127.0.0.1:1").unwrap();
        rollback.rollback(&client, "secret", &messages).await;

        // HCL must be restored to plaintext.
        let restored = std::fs::read_to_string(&hcl_path).unwrap();
        assert_eq!(
            restored, plaintext_hcl,
            "openbao.hcl must be restored to plaintext after rollback"
        );

        // TLS artifacts must be removed.
        assert!(
            !cert_path.exists(),
            "TLS cert must be removed after rollback"
        );
        assert!(!key_path.exists(), "TLS key must be removed after rollback");
    }

    /// Rollback with `hcl_backup` that has `original: None` removes the
    /// HCL file entirely (it did not exist before init created it).
    #[tokio::test]
    async fn rollback_removes_hcl_when_original_was_absent() {
        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();

        let hcl_path = dir.path().join("openbao").join("openbao.hcl");
        std::fs::create_dir_all(hcl_path.parent().unwrap()).unwrap();
        std::fs::write(&hcl_path, "tls_cert_file = ...\n").unwrap();

        let rollback = InitRollback {
            hcl_backup: Some(RollbackFile {
                path: hcl_path.clone(),
                original: None,
            }),
            tls_artifacts: Vec::new(),
            compose_file: None,
            ..Default::default()
        };

        let client = OpenBaoClient::new("http://127.0.0.1:1").unwrap();
        rollback.rollback(&client, "secret", &messages).await;

        assert!(
            !hcl_path.exists(),
            "HCL file must be removed when original was absent"
        );
    }

    /// When no TLS rollback fields are populated (loopback-only init),
    /// rollback must not touch HCL or TLS files.
    #[tokio::test]
    async fn rollback_noop_without_tls_fields() {
        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();

        // Create an unrelated file to ensure rollback doesn't
        // accidentally delete it.
        let unrelated = dir.path().join("other.txt");
        std::fs::write(&unrelated, "keep").unwrap();

        let rollback = InitRollback::default();
        let client = OpenBaoClient::new("http://127.0.0.1:1").unwrap();
        rollback.rollback(&client, "secret", &messages).await;

        assert!(
            unrelated.exists(),
            "unrelated files must survive a no-op TLS rollback"
        );
    }

    /// Regression: rollback must recreate the `OpenBao` container with
    /// `up -d` (not `restart`) so that Docker Compose applies the base
    /// compose config without the non-loopback override.  `restart`
    /// only stops/starts the existing container, preserving the port
    /// bindings from the applied override — which would leave `OpenBao`
    /// reachable on plaintext HTTP at the non-loopback address.
    #[test]
    fn rollback_uses_up_not_restart_to_remove_override() {
        use std::path::PathBuf;

        let compose = PathBuf::from("docker-compose.yml");
        let args = super::rollback_openbao_docker_args(&compose);

        assert!(
            args.contains(&"up".to_string()) && args.contains(&"-d".to_string()),
            "rollback must use `up -d` to recreate the container: {args:?}"
        );
        assert!(
            !args.iter().any(|a| a == "restart"),
            "rollback must not use `restart` — it preserves override port bindings: {args:?}"
        );
        assert_eq!(
            args.last().map(String::as_str),
            Some("openbao"),
            "rollback must target only the openbao service"
        );
    }

    /// Regression: on fresh install (original config absent), rollback
    /// must omit the config override from the docker-compose args so
    /// the responder is restarted from the base compose config only.
    /// Passing the override when the config file was removed would
    /// start the container with `--config=` pointing at a missing file.
    #[test]
    fn rollback_responder_omits_config_override_on_fresh_install() {
        use std::path::PathBuf;

        let compose = PathBuf::from("docker-compose.yml");
        let override_path = PathBuf::from("secrets/responder/override.yml");

        // Simulate fresh install: original is None, override exists.
        let rollback = InitRollback {
            responder_config_backup: Some(RollbackFile {
                path: PathBuf::from("secrets/responder/responder.toml"),
                original: None,
            }),
            compose_file: Some(compose.clone()),
            responder_compose_override: Some(override_path.clone()),
            ..Default::default()
        };

        // The rollback logic should NOT pass the config override when
        // original is None.
        let config_override = rollback
            .responder_config_backup
            .as_ref()
            .filter(|f| f.original.is_some())
            .and(rollback.responder_compose_override.as_deref());
        let args = super::rollback_responder_docker_args(&compose, config_override);

        assert!(
            !args.iter().any(|a| a.ends_with("override.yml")),
            "rollback must omit config override on fresh install (original absent): {args:?}"
        );
    }

    /// When a pre-existing responder config was backed up, rollback
    /// must include the config override so the restored config is
    /// mounted into the container.
    #[test]
    fn rollback_responder_includes_config_override_when_original_exists() {
        use std::path::PathBuf;

        let compose = PathBuf::from("docker-compose.yml");
        let override_path = PathBuf::from("secrets/responder/override.yml");

        let rollback = InitRollback {
            responder_config_backup: Some(RollbackFile {
                path: PathBuf::from("secrets/responder/responder.toml"),
                original: Some("admin_addr = ...".to_string()),
            }),
            compose_file: Some(compose.clone()),
            responder_compose_override: Some(override_path.clone()),
            ..Default::default()
        };

        let config_override = rollback
            .responder_config_backup
            .as_ref()
            .filter(|f| f.original.is_some())
            .and(rollback.responder_compose_override.as_deref());
        let args = super::rollback_responder_docker_args(&compose, config_override);

        assert!(
            args.iter().any(|a| a.ends_with("override.yml")),
            "rollback must include config override when original config existed: {args:?}"
        );
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use std::path::PathBuf;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use super::super::constants::openbao_constants::SECRET_ID_TTL;
    use super::super::constants::{DEFAULT_CERT_DURATION, DEFAULT_STEPCA_PROVISIONER};
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
            stepca_provisioner: DEFAULT_STEPCA_PROVISIONER.to_string(),
            cert_duration: DEFAULT_CERT_DURATION.to_string(),
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
