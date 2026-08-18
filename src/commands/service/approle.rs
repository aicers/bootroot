use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::{OpenBaoClient, SecretIdOptions};
use bootroot::service_material::{
    ProvisionedServiceRole, ServiceProvisionError, ServiceProvisionStep, ServiceRoleTtls,
    build_service_policy, provision_service_role, service_policy_name,
};

use super::ServiceAppRoleMaterialized;
use crate::commands::init::{SECRET_ID_TTL, TOKEN_TTL};
use crate::i18n::Messages;
use crate::state::StateFile;

/// Renders the step-specific diagnostic the CLI reported for each of the
/// three provisioning calls before that sequence was shared with the
/// registrar.
fn provision_message(err: &ServiceProvisionError, messages: &Messages) -> &'static str {
    match err.step {
        ServiceProvisionStep::Policy => messages.error_openbao_policy_write_failed(),
        ServiceProvisionStep::AppRole => messages.error_openbao_approle_create_failed(),
        ServiceProvisionStep::RoleId => messages.error_openbao_role_id_failed(),
    }
}

pub(super) async fn ensure_service_approle(
    client: &OpenBaoClient,
    state: &StateFile,
    registration_id: &str,
    secret_id_options: &SecretIdOptions,
    wrap_ttl: Option<&str>,
    messages: &Messages,
) -> Result<ServiceAppRoleMaterialized> {
    // The CLI keeps its own role-level TTLs: the shared helper declares
    // none, so `init`'s constants stay this caller's decision.
    let provisioned = provision_service_role(
        client,
        &state.kv_mount,
        registration_id,
        ServiceRoleTtls {
            token_ttl: TOKEN_TTL,
            secret_id_ttl: SECRET_ID_TTL,
        },
    )
    .await
    .map_err(|err| {
        let message = provision_message(&err, messages);
        anyhow::Error::new(err).context(message)
    })?;
    let ProvisionedServiceRole {
        role_name,
        policy_name,
        role_id,
    } = provisioned;
    // Issuance stays here, not in the shared helper: `service add`
    // delivers the raw `secret_id` to a local file, wrapping only as a
    // transport hop it immediately unwraps.
    let secret_id = match wrap_ttl {
        Some(ttl) => {
            client
                .create_secret_id_wrapped(&role_name, secret_id_options, ttl)
                .await
        }
        None => client.create_secret_id(&role_name, secret_id_options).await,
    }
    .with_context(|| messages.error_openbao_secret_id_failed())?;
    Ok(ServiceAppRoleMaterialized {
        role_name,
        role_id,
        secret_id,
        policy_name,
    })
}

/// Re-applies the service `AppRole` policy for an already-provisioned service.
///
/// `write_policy` is idempotent, so this is safe to run repeatedly. It exists
/// so that services provisioned before the reissue-path write grant was added
/// pick up the updated policy on the idempotent remote `service add` re-run,
/// instead of keeping the old read-only policy indefinitely.
pub(super) async fn reapply_service_policy(
    client: &OpenBaoClient,
    state: &StateFile,
    registration_id: &str,
    messages: &Messages,
) -> Result<()> {
    let policy_name = service_policy_name(registration_id);
    let policy = build_service_policy(&state.kv_mount, registration_id);
    client
        .write_policy(&policy_name, &policy)
        .await
        .with_context(|| messages.error_openbao_policy_write_failed())?;
    Ok(())
}

pub(super) async fn write_secret_id_file(
    secret_id_path: &Path,
    secret_id: &str,
    is_override: bool,
    messages: &Messages,
) -> Result<()> {
    write_service_credential_file(secret_id_path, secret_id, is_override, messages).await
}

pub(super) async fn write_role_id_file(
    role_id_path: &Path,
    role_id: &str,
    is_override: bool,
    messages: &Messages,
) -> Result<()> {
    write_service_credential_file(role_id_path, role_id, is_override, messages).await
}

/// Writes a freshly-minted service credential (`secret_id` or its
/// sibling `role_id`) to `path`.
///
/// For the default secrets-tree location bootroot owns the directory:
/// it is created `0700`, and the file is published by rename at `0600`,
/// replacing any stale file left by a previously removed service. For an
/// operator `--secret-id-path` override the directory is agent-owned and
/// sits outside the secrets tree, so the write goes through the hardened
/// path in [`fs_util::create_owned_credential_noclobber`]: the parent
/// must already exist, the fresh file is chowned to the agent-owning
/// parent, mode `0600`, created no-clobber, and never follows a
/// final-component symlink.
async fn write_service_credential_file(
    path: &Path,
    contents: &str,
    is_override: bool,
    messages: &Messages,
) -> Result<()> {
    if is_override {
        fs_util::create_owned_credential_noclobber(path, contents.as_bytes())
            .await
            .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    } else {
        // Inside the root-owned secrets tree, published by rename at the
        // policy's `0600` — the same mode the `write` +
        // `set_key_permissions` pair this replaced ended at, now applied
        // to the staged temporary so it holds from the moment the
        // credential appears at its path.
        //
        // It takes the directory flush, for the reason
        // `fs_util::create_owned_credential_noclobber` states for the
        // override path beside it: `OpenBao` has already issued this
        // `secret_id` by the time it is written, and losing the
        // directory entry locks the agent out until an operator
        // intervenes rather than costing a rewrite.
        let parent = path.parent().unwrap_or(Path::new("."));
        fs_util::ensure_secrets_dir(parent).await?;
        fs_util::atomic_write(
            fs_util::Destination::bootroot_owned(path),
            contents.as_bytes(),
            fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
        )
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    fn mode_of(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// The default (no-override) write creates the secrets-tree directory
    /// `0700`, writes the file `0600`, and — unlike the override path —
    /// overwrites a stale file left by a previously removed service.
    #[tokio::test]
    async fn write_secret_id_file_default_creates_dir_and_overwrites() {
        let dir = tempdir().unwrap();
        let secret_id_path = dir
            .path()
            .join("secrets")
            .join("services")
            .join("svc")
            .join("secret_id");
        let messages = crate::i18n::test_messages();

        write_secret_id_file(&secret_id_path, "sid-1", false, &messages)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&secret_id_path).unwrap(), "sid-1");
        assert_eq!(mode_of(&secret_id_path), fs_util::KEY_FILE_MODE);
        assert_eq!(mode_of(secret_id_path.parent().unwrap()), 0o700);

        // The default path overwrites a stale file, as before.
        write_secret_id_file(&secret_id_path, "sid-2", false, &messages)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&secret_id_path).unwrap(), "sid-2");
    }

    /// The override write requires an existing parent, produces a `0600`
    /// file, and refuses to clobber a pre-existing regular file.
    #[tokio::test]
    async fn write_role_id_file_override_is_0600_and_noclobber() {
        let dir = tempdir().unwrap();
        let agent_dir = dir.path().join("agent").join("svc");
        std::fs::create_dir_all(&agent_dir).unwrap();
        let role_id_path = agent_dir.join("role_id");
        let messages = crate::i18n::test_messages();

        write_role_id_file(&role_id_path, "rid", true, &messages)
            .await
            .unwrap();
        assert_eq!(std::fs::read_to_string(&role_id_path).unwrap(), "rid");
        assert_eq!(mode_of(&role_id_path), fs_util::KEY_FILE_MODE);

        let err = write_role_id_file(&role_id_path, "rid-2", true, &messages)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("Refusing to overwrite"),
            "override role_id write must be no-clobber, got: {err:#}"
        );
    }
}
