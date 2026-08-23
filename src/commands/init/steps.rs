mod ca_certs;
mod database;
pub(crate) mod http01_admin_tls;
mod openbao_setup;
pub(crate) mod openbao_tls;
mod openbao_transition;
mod orchestrator;
mod prompts;
pub(crate) mod registrar_internal;
mod responder_setup;
mod secrets;
pub(crate) mod stepca_setup;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::{InitResponse, OpenBaoClient};
pub(crate) use ca_certs::{
    compute_ca_bundle_pem, compute_ca_fingerprints, read_ca_cert_fingerprint,
};
pub(crate) use openbao_setup::{
    infra_rotate_policy, parse_ttl_to_secs, validate_rotate_bound_cidrs, validate_secret_id_ttl,
};
pub(crate) use orchestrator::run_init;
pub(crate) use prompts::prompt_yes_no;

use super::types::EabCredentials;
use crate::commands::compose_project::{
    ComposeIdentity, ComposeInvocation, DEFAULT_INSTANCE_NAME, DOCKER_BIN,
};
use crate::commands::container_name::BootrootContainer;
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
    /// Snapshot of `templates/ca.json.ctmpl` taken before `init`
    /// regenerates it.  `ca.json` is co-owned: the step-ca `OpenBao`
    /// Agent sidecar re-renders it from this template every render
    /// interval, so restoring `ca.json` alone would be undone by the
    /// next render.  Restored together with `ca_json_backup`.
    pub(super) stepca_ca_json_template_backup: Option<RollbackFile>,
    /// Whether `init` restarted the step-ca `OpenBao` Agent sidecar onto
    /// the regenerated template.  When set, rollback restarts it again
    /// so it reloads the restored template instead of holding the new
    /// one in memory.
    pub(super) stepca_agent_restarted: bool,
    pub(super) hcl_backup: Option<RollbackFile>,
    /// Whether this run recreated the `OpenBao` container to load the
    /// TLS listener configuration.  Rollback recreates it from the base
    /// compose file only when this run did, so a failure *before* the
    /// recreate — the unseal-key availability pre-check is the one that
    /// can fire there — leaves the running process untouched.  The
    /// rewritten `openbao.hcl` is a bind-mounted file the process has
    /// not read at that point, and restoring it above is enough to undo
    /// the run.
    pub(super) openbao_recreated: bool,
    pub(super) tls_artifacts: Vec<PathBuf>,
    pub(super) compose_file: Option<PathBuf>,
    /// Responder config backup for rolling back TLS-enabled config.
    pub(super) responder_config_backup: Option<RollbackFile>,
    /// Responder config compose override for restarting without the
    /// exposed port binding during rollback.
    pub(super) responder_compose_override: Option<PathBuf>,
    /// Infra `OpenBao` agent compose override applied in the TLS case
    /// (Phase 2, post-TLS-transition).  On rollback the two agent
    /// containers are stopped and removed so they are not left running
    /// with a TLS `VAULT_ADDR`/`ca_cert` against a rolled-back plaintext
    /// `OpenBao`.
    pub(super) openbao_agent_compose_override: Option<PathBuf>,
    /// State file snapshot taken before the `OpenBao` TLS transition
    /// persists the HTTPS URL and infra cert entries.  On rollback it
    /// restores the pre-TLS `state.json` so it does not keep pointing at
    /// an HTTPS URL / TLS certs after `OpenBao` is recreated on plaintext.
    pub(super) state_backup: Option<RollbackFile>,
    /// The bootroot-internal credential's layout directory, set only
    /// when this run is what created it.  Rollback then removes it whole
    /// — staging included — so a failure anywhere in the provisioning
    /// sequence leaves no half-provisioned credential, no dedicated
    /// config and no private bundle behind.
    ///
    /// Left `None` when the host already carried a credential, so a
    /// failed re-run of `init` does not delete a working one; the
    /// staging directory below is removed either way.
    pub(super) registrar_internal_dir: Option<PathBuf>,
    /// The staging directory the internal leaf is issued into before it
    /// is proved and published.  Removed on rollback whether or not the
    /// layout directory around it is, because it is this run's alone and
    /// holds a private key that was never published.
    pub(super) registrar_internal_staging: Option<PathBuf>,
    /// The `auth/cert` entry this run created, by name.  Deleted on
    /// rollback so a rolled-back host trusts no internal certificate.
    pub(super) registrar_internal_cert_auth_entry: Option<String>,
    /// The `auth/cert` entry this run found already there, captured
    /// verbatim before it was rewritten.  A re-run over an established
    /// credential converges the entry onto the recorded predicate's SAN
    /// and the active root *before* the leaf that matches it is issued,
    /// so a failure after that point would otherwise leave the host
    /// trusting a certificate it does not have.  Written back on
    /// rollback, byte for byte.
    pub(super) registrar_internal_cert_auth_entry_backup: Option<serde_json::Value>,
    /// The `bootroot-registrar-internal` policy this run found already
    /// there, captured before it was rewritten.  Restored on rollback
    /// for the same reason as the entry above: the convergence replaces
    /// it unconditionally, and deleting a policy this run did not create
    /// is not the undo of having replaced it.
    pub(super) registrar_internal_policy_backup: Option<String>,
    /// Whether this run is what mounted `auth/cert`.  Only then does
    /// rollback disable it: a deployment that already had the backend
    /// keeps it, along with every other entry under it.
    pub(super) registrar_internal_cert_auth_mount_created: bool,
    /// The `docker` executable every spawn in the `init` flow runs.
    ///
    /// `None` *is* `docker`: this value comes straight from the derived
    /// `Default`, with no constructor to fill a bare `PathBuf` in, and
    /// an empty path would spawn nothing at all.  [`InitRollback::docker`]
    /// is the one place that resolution happens.
    pub(super) docker: Option<PathBuf>,
}

impl InitRollback {
    /// Returns the executable every `docker` spawn in this run uses.
    ///
    /// The single resolution point for the `init` tree's default: a run
    /// that named no executable gets `docker`.
    pub(super) fn docker(&self) -> &Path {
        self.docker.as_deref().unwrap_or(Path::new(DOCKER_BIN))
    }

    // A linear teardown: each step undoes one forward-path artefact and
    // reports its own failure without aborting the rest, so splitting it
    // would only scatter that sequence across helpers.
    #[allow(clippy::too_many_lines)]
    pub(super) async fn rollback(
        &self,
        client: &OpenBaoClient,
        kv_mount: &str,
        messages: &Messages,
    ) {
        let docker = self.docker();
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
        if self.openbao_recreated
            && let Some(compose_file) = &self.compose_file
        {
            // Use `up -d` (not `restart`) so Docker Compose recreates
            // the container from the base compose config alone, removing
            // any non-loopback port mapping the override introduced.
            // `restart` only stops/starts the existing container and
            // preserves port bindings from the applied override, which
            // would leave OpenBao on plaintext HTTP at a non-loopback
            // address.
            //
            // Gated on this run having recreated the container: the
            // forward path can fail before that (no unseal key source is
            // available), and tearing down a container this run never
            // touched would knock a healthy deployment offline.
            let invocation = rollback_openbao_invocation(
                &rollback_identity(compose_file, messages),
                compose_file,
            );
            if let Err(err) = crate::commands::infra::run_compose_with_exec(
                &invocation,
                "docker compose up -d openbao (rollback)",
                docker,
                messages,
            ) {
                eprintln!("Rollback: failed to recreate OpenBao: {err}");
            }
        }

        // Stop and remove the two infra OpenBao agents.  In the TLS
        // case they were started (Phase 2) with an HTTPS `VAULT_ADDR`
        // and `ca_cert`; OpenBao has just been recreated on plaintext,
        // so leaving them up would keep them failing AppRole login with
        // `400 Client sent an HTTP request to an HTTPS server`.  Removing
        // them returns to the pre-Phase-2 state (agents not started).
        if let Some(override_path) = &self.openbao_agent_compose_override
            && let Some(compose_file) = &self.compose_file
        {
            let invocation = rollback_openbao_agent_invocation(
                &rollback_identity(compose_file, messages),
                compose_file,
                override_path,
            );
            if let Err(err) = crate::commands::infra::run_compose_with_exec(
                &invocation,
                "docker compose rm infra agents (rollback)",
                docker,
                messages,
            ) {
                eprintln!("Rollback: failed to remove infra OpenBao agents: {err}");
            }
        }

        // Restore the pre-TLS `state.json` so it does not keep pointing
        // at the HTTPS URL / TLS infra certs after OpenBao is back on
        // plaintext.  Done after the container work so a failed restore
        // does not skip the Docker teardown above.
        if let Some(file) = &self.state_backup
            && let Err(err) = rollback_file(file, messages)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
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
            let invocation = rollback_responder_invocation(
                &rollback_identity(compose_file, messages),
                compose_file,
                config_override,
            );
            if let Err(err) = crate::commands::infra::run_compose_with_exec(
                &invocation,
                "docker compose up -d responder (rollback)",
                docker,
                messages,
            ) {
                eprintln!("Rollback: failed to recreate responder: {err}");
            }
        }

        // The bootroot-internal artifacts, innermost first: the files,
        // then the entry that trusts them, then the policy that entry
        // names, then the mount — and the mount only when this run is
        // what created it.  Each of the two `OpenBao` artifacts is
        // deleted when this run created it and put back verbatim when
        // this run merely rewrote one it found, so a re-run that fails
        // after convergence leaves the established credential working.
        for dir in [
            &self.registrar_internal_dir,
            &self.registrar_internal_staging,
        ]
        .into_iter()
        .flatten()
        {
            if dir.exists()
                && let Err(err) = std::fs::remove_dir_all(dir)
            {
                eprintln!(
                    "Rollback: failed to remove the bootroot-internal credential at {}: {err}",
                    dir.display()
                );
            }
        }
        // Restored before deleted, and never both: an entry this run
        // created has no prior body and is removed, while one it found
        // and rewrote is put back exactly as it was read.
        if let Some(entry) = &self.registrar_internal_cert_auth_entry_backup {
            if let Err(err) = client
                .write_cert_auth_entry_raw(
                    bootroot::registrar::internal::CERT_AUTH_MOUNT,
                    bootroot::registrar::internal::CERT_AUTH_ROLE,
                    entry,
                )
                .await
            {
                eprintln!(
                    "Rollback: failed to restore the bootroot-registrar-internal cert auth                      entry: {err}; re-run                      `bootroot rotate registrar-internal-credential --force`"
                );
            }
        } else if let Some(name) = &self.registrar_internal_cert_auth_entry
            && let Err(err) = client
                .delete_cert_auth_entry(bootroot::registrar::internal::CERT_AUTH_MOUNT, name)
                .await
        {
            eprintln!("Rollback: failed to delete cert auth entry {name}: {err}");
        }
        if let Some(policy) = &self.registrar_internal_policy_backup
            && let Err(err) = client
                .write_policy(
                    crate::commands::init::constants::openbao_constants::POLICY_BOOTROOT_REGISTRAR_INTERNAL,
                    policy,
                )
                .await
        {
            eprintln!(
                "Rollback: failed to restore the bootroot-registrar-internal policy: {err}"
            );
        }
        if self.registrar_internal_cert_auth_mount_created
            && let Err(err) = client
                .disable_auth(bootroot::registrar::internal::CERT_AUTH_MOUNT)
                .await
        {
            eprintln!("Rollback: failed to disable the cert auth backend: {err}");
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
        self.restore_stepca_ca_json(docker, messages);
    }

    /// Restores `ca.json` together with the Agent template it is
    /// re-rendered from, and puts the sidecar back on that template.
    ///
    /// The three are one unit: the step-ca `OpenBao` Agent sidecar
    /// re-renders `ca.json` from `templates/ca.json.ctmpl` every render
    /// interval, so restoring `ca.json` alone would be undone by the next
    /// render from a template that still carries the new `dnsNames`
    /// (issue #733).  The template goes back first so that a render
    /// triggered by the restart already produces the pre-`init` name set,
    /// and `ca.json` goes back after it so the file left on disk is the
    /// pre-`init` document either way.
    fn restore_stepca_ca_json(&self, docker: &Path, messages: &Messages) {
        if let Some(file) = &self.stepca_ca_json_template_backup
            && let Err(err) = rollback_file(file, messages)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
        }
        if let Some(file) = &self.ca_json_backup
            && let Err(err) = rollback_file(file, messages)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
        }
        // The sidecar loads its templates at start-up, so one that `init`
        // restarted onto the regenerated template keeps rendering the new
        // name set until it is restarted again.  Skipped when `init` never
        // restarted it, and a failure is ignored for the same reason as in
        // the forward path: on a fresh install the container does not
        // exist, and the TLS rollback above may already have removed it.
        if self.stepca_agent_restarted
            && let Some(compose_file) = &self.compose_file
        {
            let identity = rollback_identity(compose_file, messages);
            stepca_setup::restart_stepca_openbao_agent(
                &identity.container(BootrootContainer::OpenBaoAgentStepCa),
                docker,
            );
        }
    }
}

/// Resolves the identity for a rollback invocation.
///
/// Rollback is best-effort and reports through `eprintln!` rather than
/// `Result`, so an unreadable `.env` falls back to the default identity
/// instead of aborting the teardown half-way: leaving the containers up
/// would be worse than acting on the default project, which is the one
/// an install without `--instance-name` created.
fn rollback_identity(compose_file: &std::path::Path, messages: &Messages) -> ComposeIdentity {
    ComposeIdentity::resolve(compose_file, None, messages)
        .unwrap_or_else(|_| ComposeIdentity::for_instance(DEFAULT_INSTANCE_NAME))
}

/// Builds the Docker Compose arguments for undoing the TLS override
/// during rollback.
///
/// Returns a `compose -f <compose_file> -p <project> up -d openbao`
/// vector so that the container is recreated from the base compose config
/// (without the non-loopback override), ensuring the external port
/// mapping is removed.
fn rollback_openbao_invocation(
    identity: &ComposeIdentity,
    compose_file: &std::path::Path,
) -> ComposeInvocation {
    identity.compose(
        &[&compose_file.to_string_lossy()],
        None,
        &["up", "-d", "openbao"],
    )
}

/// Builds the Docker Compose arguments for undoing the responder TLS
/// exposure during rollback.
///
/// Includes the config override (if present) so the responder keeps
/// its volume mount, but omits the exposed port override so the
/// container reverts to loopback-only binding.
fn rollback_responder_invocation(
    identity: &ComposeIdentity,
    compose_file: &std::path::Path,
    config_override: Option<&std::path::Path>,
) -> ComposeInvocation {
    let compose_str = compose_file.to_string_lossy();
    let override_str = config_override.map(|path| path.to_string_lossy().into_owned());
    let mut files: Vec<&str> = vec![&compose_str];
    if let Some(ref override_str) = override_str {
        files.push(override_str);
    }
    identity.compose(
        &files,
        None,
        &[
            "up",
            "-d",
            crate::commands::constants::RESPONDER_SERVICE_NAME,
        ],
    )
}

/// Builds the Docker Compose arguments for tearing down the infra
/// `OpenBao` agents during rollback.
///
/// Returns a `compose -f <compose> -f <override> -p <project> rm -s -f
/// <stepca> <responder>` vector so the two agent containers are
/// stopped and removed.  They were started with a TLS `VAULT_ADDR`/
/// `ca_cert` that a rolled-back plaintext `OpenBao` cannot serve.
fn rollback_openbao_agent_invocation(
    identity: &ComposeIdentity,
    compose_file: &std::path::Path,
    override_path: &std::path::Path,
) -> ComposeInvocation {
    identity.compose(
        &[
            &compose_file.to_string_lossy(),
            &override_path.to_string_lossy(),
        ],
        None,
        &[
            "rm",
            "-s",
            "-f",
            super::constants::OPENBAO_AGENT_STEPCA_SERVICE,
            super::constants::OPENBAO_AGENT_RESPONDER_SERVICE,
        ],
    )
}

/// Restores one snapshotted file, or removes it when `init` created it.
///
/// The restore publishes by rename. This runs on the failure path, where
/// the containers `init` started may still be up and reading the very
/// files being put back — `ca.json`, `password.txt`, the templates — so
/// a truncating restore could hand a half-written document to a service
/// that is already unhappy. It also means an interrupted rollback leaves
/// the pre-`init` file or the `init`-era one, never a shredded third
/// thing that matches neither snapshot.
///
/// The directory is not flushed: the rollback is undoing work, so losing
/// its last entry to a crash leaves the operator exactly where a crash
/// one moment earlier would have, and a re-run of `init` is the recovery
/// either way.
///
/// A `RollbackFile` records a destination that existed before `init`, so
/// the restore normally reads the mode back off it;
/// [`fs_util::StagedMode::PreserveOrUmask`]'s create arm covers only the
/// case where `init` deleted it outright, and hands that create to the
/// umask exactly as the truncating write this replaced did.
fn rollback_file(file: &RollbackFile, messages: &Messages) -> Result<()> {
    if let Some(contents) = &file.original {
        fs_util::atomic_replace_blocking(
            fs_util::Destination::operator_named(&file.path),
            contents.as_bytes(),
            fs_util::StagedMode::PreserveOrUmask,
        )
        .with_context(|| messages.error_restore_file_failed(&file.path.display().to_string()))?;
    } else if file.path.exists() {
        std::fs::remove_file(&file.path)
            .with_context(|| messages.error_remove_file_failed(&file.path.display().to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod rollback_tests {
    use std::path::{Path, PathBuf};

    use bootroot::openbao::OpenBaoClient;

    use super::{
        ComposeIdentity, ComposeInvocation, DEFAULT_INSTANCE_NAME, InitRollback, RollbackFile,
    };

    /// The identity a rollback falls back to when no `.env` is readable.
    fn default_rollback_identity() -> ComposeIdentity {
        ComposeIdentity::for_instance(DEFAULT_INSTANCE_NAME)
    }

    /// Reads a rollback invocation's argument vector back out of the
    /// command it builds.
    fn rollback_args(invocation: &ComposeInvocation) -> Vec<String> {
        invocation
            .command(&[])
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect()
    }

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

    /// A first provisioning either publishes a complete
    /// bootroot-internal credential or leaves nothing behind: rollback
    /// removes the layout directory whole, staging and all.
    #[tokio::test]
    async fn rollback_removes_a_freshly_provisioned_internal_credential() {
        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();
        let paths = bootroot::registrar::internal::InternalPaths::new(dir.path());
        let staging = paths.dir().join(".staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(paths.key(), "KEY").unwrap();
        std::fs::write(paths.chain(), "CHAIN").unwrap();
        std::fs::write(staging.join("key.pem"), "STAGED KEY").unwrap();

        let rollback = InitRollback {
            registrar_internal_dir: Some(paths.dir().to_path_buf()),
            registrar_internal_staging: Some(staging.clone()),
            registrar_internal_cert_auth_entry: Some("bootroot-registrar-internal".to_string()),
            registrar_internal_cert_auth_mount_created: true,
            compose_file: None,
            ..Default::default()
        };
        // Unreachable: the two OpenBao teardown calls report and continue,
        // which is what keeps the file teardown from being skipped.
        let client = OpenBaoClient::new("http://127.0.0.1:1").unwrap();
        rollback.rollback(&client, "secret", &messages).await;

        assert!(
            !paths.dir().exists(),
            "the layout directory must be gone after rollback"
        );
    }

    /// A re-run of `init` over a host that already carried a credential
    /// must not have its rollback delete the working one. Only this
    /// run's staging directory — which holds a private key that was
    /// never published — is swept.
    #[tokio::test]
    async fn rollback_keeps_a_pre_existing_internal_credential() {
        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();
        let paths = bootroot::registrar::internal::InternalPaths::new(dir.path());
        let staging = paths.dir().join(".staging");
        std::fs::create_dir_all(&staging).unwrap();
        std::fs::write(paths.key(), "EXISTING KEY").unwrap();
        std::fs::write(staging.join("key.pem"), "STAGED KEY").unwrap();

        let rollback = InitRollback {
            // Left `None` exactly because the host already had one.
            registrar_internal_dir: None,
            registrar_internal_staging: Some(staging.clone()),
            compose_file: None,
            ..Default::default()
        };
        let client = OpenBaoClient::new("http://127.0.0.1:1").unwrap();
        rollback.rollback(&client, "secret", &messages).await;

        assert!(!staging.exists(), "staging must be swept");
        assert_eq!(
            std::fs::read_to_string(paths.key()).unwrap(),
            "EXISTING KEY",
            "the pre-existing credential must survive"
        );
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

    /// Regression (#733): rollback must restore `ca.json.ctmpl`
    /// alongside `ca.json`.  `init` regenerates the template with the
    /// derived `dnsNames` and restarts the step-ca `OpenBao` Agent
    /// sidecar onto it; restoring only `ca.json` would leave the sidecar
    /// rendering the new name set back over the restored file at its
    /// next interval, so a failed `init` would not actually be undone.
    #[tokio::test]
    async fn rollback_restores_stepca_ca_json_template_with_ca_json() {
        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();

        let config_dir = dir.path().join("config");
        let templates_dir = dir.path().join("templates");
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&templates_dir).unwrap();

        let ca_json_path = config_dir.join("ca.json");
        let template_path = templates_dir.join("ca.json.ctmpl");
        let original_ca_json = r#"{"dnsNames":["localhost"]}"#;
        let original_template = r#"{"dnsNames":["localhost"],"db":{}}"#;
        // Simulate the post-rewrite state: both carry the derived IP.
        std::fs::write(&ca_json_path, r#"{"dnsNames":["localhost","10.0.0.5"]}"#).unwrap();
        std::fs::write(
            &template_path,
            r#"{"dnsNames":["localhost","10.0.0.5"],"db":{}}"#,
        )
        .unwrap();

        let rollback = InitRollback {
            ca_json_backup: Some(RollbackFile {
                path: ca_json_path.clone(),
                original: Some(original_ca_json.to_string()),
            }),
            stepca_ca_json_template_backup: Some(RollbackFile {
                path: template_path.clone(),
                original: Some(original_template.to_string()),
            }),
            // `false` keeps the docker restart out of the unit test; the
            // forward path sets it whenever it restarts the sidecar.
            stepca_agent_restarted: false,
            compose_file: None,
            ..Default::default()
        };

        let client = OpenBaoClient::new("http://127.0.0.1:1").unwrap();
        rollback.rollback(&client, "secret", &messages).await;

        assert_eq!(
            std::fs::read_to_string(&ca_json_path).unwrap(),
            original_ca_json,
            "ca.json must be restored"
        );
        assert_eq!(
            std::fs::read_to_string(&template_path).unwrap(),
            original_template,
            "ca.json.ctmpl must be restored so the sidecar cannot re-render the new dnsNames"
        );
    }

    /// A fresh install has no `ca.json.ctmpl` before `init`; the
    /// snapshot's `original: None` must roll back to "no template"
    /// rather than leaving the generated one behind.
    #[tokio::test]
    async fn rollback_removes_stepca_ca_json_template_when_original_was_absent() {
        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();

        let templates_dir = dir.path().join("templates");
        std::fs::create_dir_all(&templates_dir).unwrap();
        let template_path = templates_dir.join("ca.json.ctmpl");
        std::fs::write(&template_path, "generated").unwrap();

        let rollback = InitRollback {
            stepca_ca_json_template_backup: Some(RollbackFile {
                path: template_path.clone(),
                original: None,
            }),
            compose_file: None,
            ..Default::default()
        };

        let client = OpenBaoClient::new("http://127.0.0.1:1").unwrap();
        rollback.rollback(&client, "secret", &messages).await;

        assert!(
            !template_path.exists(),
            "a template created by init must be removed when none existed before"
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

    /// The derived `Default` is how production builds this value, so a
    /// run that names no executable still has to spawn `docker`.  A bare
    /// `PathBuf` field would default to the empty path and spawn nothing
    /// at all, which no other assertion in this file would catch.
    #[test]
    fn rollback_defaults_to_the_docker_executable() {
        let rollback = InitRollback {
            compose_file: None,
            ..Default::default()
        };

        assert_eq!(rollback.docker(), Path::new("docker"));
    }

    /// The seam: a caller that names an executable is the one the
    /// rollback resolves, and the default is not consulted.
    #[test]
    fn rollback_resolves_the_executable_it_was_given() {
        let rollback = InitRollback {
            docker: Some(PathBuf::from("/tmp/fake-docker")),
            ..Default::default()
        };

        assert_eq!(rollback.docker(), Path::new("/tmp/fake-docker"));
    }

    /// Resolving the field is only half of it: the resolved program has
    /// to reach the child.  A rollback that names an executable runs
    /// *that* one for both spawn shapes it drives — the compose recreate
    /// through `run_compose_with_exec`, and the sidecar restart through
    /// `restart_stepca_openbao_agent`'s own `Command`.
    ///
    /// Nothing process-global moves here: the fake carries its argv-log
    /// path in its own script text, which is the property that lets the
    /// conversion issue delete this file's remaining `PATH` fake.
    #[tokio::test]
    async fn rollback_runs_the_executable_it_was_given() {
        use std::fs;

        use super::test_support::write_self_contained_fake_docker;

        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        let rollback = InitRollback {
            docker: Some(fake),
            compose_file: Some(dir.path().join("docker-compose.yml")),
            openbao_recreated: true,
            stepca_agent_restarted: true,
            ..Default::default()
        };

        let client = OpenBaoClient::new("http://127.0.0.1:1").expect("client");
        rollback
            .rollback(&client, "secret", &crate::i18n::test_messages())
            .await;

        let log = fs::read_to_string(&args_log)
            .expect("the supplied executable must have run, not `docker` from `PATH`");
        let invocations: Vec<&str> = log.lines().collect();
        assert_eq!(
            invocations.len(),
            2,
            "the supplied executable must have run the recreate and the sidecar restart, got: {log}"
        );
        assert!(
            invocations
                .first()
                .is_some_and(|recreate| recreate.contains("up -d openbao")),
            "the first invocation must be the compose recreate, got: {log}"
        );
        assert!(
            invocations
                .get(1)
                .is_some_and(|restart| restart.contains("restart ")),
            "the second invocation must be the sidecar restart, got: {log}"
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
        let args = rollback_args(&super::rollback_openbao_invocation(
            &default_rollback_identity(),
            &compose,
        ));

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
        let args = rollback_args(&super::rollback_responder_invocation(
            &default_rollback_identity(),
            &compose,
            config_override,
        ));

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
        let args = rollback_args(&super::rollback_responder_invocation(
            &default_rollback_identity(),
            &compose,
            config_override,
        ));

        assert!(
            args.iter().any(|a| a.ends_with("override.yml")),
            "rollback must include config override when original config existed: {args:?}"
        );
    }

    /// Regression: the infra-agent rollback teardown must `rm -s -f`
    /// both agent services (stop then remove) using the compose file
    /// plus the agent override, so agents started in the TLS Phase 2
    /// are not left running against a rolled-back plaintext `OpenBao`.
    #[test]
    fn rollback_agent_args_remove_both_services() {
        use std::path::PathBuf;

        let compose = PathBuf::from("docker-compose.yml");
        let override_path = PathBuf::from("secrets/openbao/agent.override.yml");
        let args = rollback_args(&super::rollback_openbao_agent_invocation(
            &default_rollback_identity(),
            &compose,
            &override_path,
        ));

        assert_eq!(
            args.first().map(String::as_str),
            Some(crate::commands::compose_project::DOCKER_COMPOSE_SUBCOMMAND)
        );
        // Every rollback vector must carry the project scoping too,
        // otherwise the teardown would hit Compose's default project.
        assert!(
            args.iter().any(|a| a == "-p") && args.iter().any(|a| a == "bootroot"),
            "rollback must stay scoped to the resolved project: {args:?}"
        );
        assert!(
            args.contains(&"rm".to_string())
                && args.contains(&"-s".to_string())
                && args.contains(&"-f".to_string()),
            "rollback must stop and force-remove the agents: {args:?}"
        );
        assert!(
            args.iter()
                .any(|a| a == crate::commands::init::constants::OPENBAO_AGENT_STEPCA_SERVICE)
                && args
                    .iter()
                    .any(|a| a == crate::commands::init::constants::OPENBAO_AGENT_RESPONDER_SERVICE),
            "rollback must target both infra agent services: {args:?}"
        );
        assert!(
            args.iter().any(|a| a.ends_with("agent.override.yml")),
            "rollback must pass the agent override so its services are defined: {args:?}"
        );
    }

    /// Regression (#737): rollback must not recreate the `OpenBao`
    /// container when this run never did.  The unseal-key availability
    /// pre-check runs after the HCL rewrite but before the recreate, so
    /// a run that fails there has only touched a bind-mounted file the
    /// process has not read — recreating would knock a healthy
    /// deployment into a sealed state for nothing.
    #[test]
    fn rollback_skips_openbao_recreate_when_this_run_did_not_recreate() {
        use std::fs;
        use std::path::PathBuf;

        use super::test_support::write_self_contained_fake_docker;

        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();
        // A fake that *would* log is what makes the absent log evidence:
        // it is named through the seam, so anything the rollback ran
        // would have left a record.
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        let hcl_path = dir.path().join("openbao.hcl");
        fs::write(&hcl_path, "tls_cert_file = ...\n").unwrap();
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");

        let rollback = InitRollback {
            docker: Some(fake),
            hcl_backup: Some(RollbackFile {
                path: hcl_path.clone(),
                original: Some("tls_disable = 1\n".to_string()),
            }),
            compose_file: Some(PathBuf::from("docker-compose.yml")),
            openbao_recreated: false,
            ..Default::default()
        };

        let client = OpenBaoClient::new("http://127.0.0.1:1").unwrap();
        runtime.block_on(rollback.rollback(&client, "secret", &messages));

        assert_eq!(
            fs::read_to_string(&hcl_path).unwrap(),
            "tls_disable = 1\n",
            "the plaintext HCL must still be restored"
        );
        assert!(
            !args_log.exists(),
            "rollback must not run docker against a container this run never recreated"
        );
    }

    /// Regression: rollback must restore the pre-TLS `state.json` so it
    /// does not keep pointing at the HTTPS URL / TLS infra certs after
    /// `OpenBao` is recreated on plaintext.  Guards the failure window
    /// opened by the deferred TLS Phase-2 agent apply.
    #[tokio::test]
    async fn rollback_restores_state_file() {
        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();

        let state_path = dir.path().join("state.json");
        let plaintext_state = "{\"openbao_url\":\"http://127.0.0.1:8200\"}\n";
        std::fs::write(&state_path, plaintext_state).unwrap();
        // Simulate the HTTPS save that happened before the failure.
        std::fs::write(&state_path, "{\"openbao_url\":\"https://host:8200\"}\n").unwrap();

        let rollback = InitRollback {
            state_backup: Some(RollbackFile {
                path: state_path.clone(),
                original: Some(plaintext_state.to_string()),
            }),
            // No compose_file — skips the container teardown in tests.
            compose_file: None,
            ..Default::default()
        };

        let client = OpenBaoClient::new("http://127.0.0.1:1").unwrap();
        rollback.rollback(&client, "secret", &messages).await;

        let restored = std::fs::read_to_string(&state_path).unwrap();
        assert_eq!(
            restored, plaintext_state,
            "state.json must be restored to its pre-TLS content after rollback"
        );
    }
}

#[cfg(test)]
pub(super) mod test_support {
    use std::path::{Path, PathBuf};

    use super::super::constants::openbao_constants::SECRET_ID_TTL;
    use super::super::constants::{DEFAULT_CERT_DURATION, DEFAULT_STEPCA_PROVISIONER};
    use crate::cli::args::InitArgs;
    pub(in crate::commands::init::steps) use crate::i18n::test_messages;
    use crate::test_support::write_executable;

    /// Writes a fake `docker` that appends one line per invocation to
    /// `args_log` and reads nothing from its environment.
    ///
    /// The log path is baked into the script text at the moment it is
    /// written, so a test that hands this executable through the docker
    /// seam gets its argv back without setting a single variable on this
    /// process — which is the property the seam exists to make possible.
    pub(in crate::commands::init::steps) fn write_self_contained_fake_docker(
        path: &Path,
        args_log: &Path,
    ) {
        write_self_contained_fake_docker_exiting(path, args_log, 0);
    }

    /// [`write_self_contained_fake_docker`] whose every invocation exits
    /// `exit_code` after logging, so a test can steer the failure path
    /// of a docker call production spawns on its behalf.
    ///
    /// The log it writes is the same one the zero-exit writer produces —
    /// one appended, space-joined line per invocation — so a test that
    /// swaps one writer for the other keeps its assertions.
    pub(in crate::commands::init::steps) fn write_self_contained_fake_docker_exiting(
        path: &Path,
        args_log: &Path,
        exit_code: u8,
    ) {
        let log = args_log.display().to_string();
        assert!(
            !log.contains('\''),
            "the log path is interpolated into a single-quoted shell word"
        );
        let script = format!(
            "#!/bin/sh\nset -eu\n{{ printf '%s ' \"$@\"; printf '\\n'; }} >> '{log}'\nexit {exit_code}\n"
        );
        write_executable(path, script.as_bytes());
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
            rotate_bound_cidrs: Vec::new(),
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
            responder_ready_timeout_secs: 60,
            stepca_provisioner: DEFAULT_STEPCA_PROVISIONER.to_string(),
            cert_duration: DEFAULT_CERT_DURATION.to_string(),
            eab_kid: None,
            eab_hmac: None,
            no_eab: false,
            save_unseal_keys: false,
            no_save_unseal_keys: false,
            overwrite_password: false,
            overwrite_ca_json: false,
            overwrite_state: false,
            confirm_db_provision: false,
            reinit_mode: false,
            root_token_output: None,
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
