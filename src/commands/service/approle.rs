use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::{OpenBaoClient, SecretIdOptions};
use bootroot::trust_bootstrap::SERVICE_REISSUE_KV_SUFFIX;
use tokio::fs;

use super::{SERVICE_ROLE_PREFIX, ServiceAppRoleMaterialized};
use crate::commands::constants::SERVICE_KV_BASE;
use crate::commands::init::{SECRET_ID_TTL, TOKEN_TTL};
use crate::i18n::Messages;
use crate::state::StateFile;

pub(super) async fn ensure_service_approle(
    client: &OpenBaoClient,
    state: &StateFile,
    service_name: &str,
    secret_id_options: &SecretIdOptions,
    wrap_ttl: Option<&str>,
    messages: &Messages,
) -> Result<ServiceAppRoleMaterialized> {
    let policy_name = service_policy_name(service_name);
    let policy = build_service_policy(&state.kv_mount, service_name);
    client
        .write_policy(&policy_name, &policy)
        .await
        .with_context(|| messages.error_openbao_policy_write_failed())?;

    let role_name = service_role_name(service_name);
    client
        .create_approle(
            &role_name,
            &[policy_name.as_str()],
            TOKEN_TTL,
            SECRET_ID_TTL,
            true,
        )
        .await
        .with_context(|| messages.error_openbao_approle_create_failed())?;
    let role_id = client
        .read_role_id(&role_name)
        .await
        .with_context(|| messages.error_openbao_role_id_failed())?;
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
    service_name: &str,
    messages: &Messages,
) -> Result<()> {
    let policy_name = service_policy_name(service_name);
    let policy = build_service_policy(&state.kv_mount, service_name);
    client
        .write_policy(&policy_name, &policy)
        .await
        .with_context(|| messages.error_openbao_policy_write_failed())?;
    Ok(())
}

fn build_service_policy(kv_mount: &str, service_name: &str) -> String {
    let base = format!("{SERVICE_KV_BASE}/{service_name}");
    // The service subtree is read-only except for its own reissue object: the
    // fast-poll loop must write `completed_at`/`completed_version` back so the
    // control plane's `rotate force-reissue --wait` can observe completion.
    // Narrowly grant create/update on exactly that one path.
    format!(
        r#"path "{kv_mount}/data/{base}/{SERVICE_REISSUE_KV_SUFFIX}" {{
  capabilities = ["read", "create", "update"]
}}
path "{kv_mount}/data/{base}/*" {{
  capabilities = ["read"]
}}
path "{kv_mount}/metadata/{base}/*" {{
  capabilities = ["list"]
}}
"#
    )
}

pub(super) fn service_role_name(service_name: &str) -> String {
    format!("{SERVICE_ROLE_PREFIX}{service_name}")
}

pub(super) fn service_policy_name(service_name: &str) -> String {
    format!("{SERVICE_ROLE_PREFIX}{service_name}")
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
/// it is created `0700`, and the file is plainly (over)written `0600`,
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
        let parent = path.parent().unwrap_or(Path::new("."));
        fs_util::ensure_secrets_dir(parent).await?;
        fs::write(path, contents)
            .await
            .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
        fs_util::set_key_permissions(path).await?;
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

    #[test]
    fn service_policy_grants_write_only_on_reissue_path() {
        let policy = build_service_policy("secret", "edge-proxy");

        assert!(
            policy.contains(
                "path \"secret/data/bootroot/services/edge-proxy/reissue\" {\n  capabilities = [\"read\", \"create\", \"update\"]"
            ),
            "reissue path must carry create/update, got:\n{policy}"
        );
        assert!(
            policy.contains(
                "path \"secret/data/bootroot/services/edge-proxy/*\" {\n  capabilities = [\"read\"]"
            ),
            "rest of data subtree must stay read-only, got:\n{policy}"
        );
        assert!(
            policy.contains(
                "path \"secret/metadata/bootroot/services/edge-proxy/*\" {\n  capabilities = [\"list\"]"
            ),
            "metadata subtree must stay list-only, got:\n{policy}"
        );
    }

    #[test]
    fn service_policy_grants_no_broader_write_scope() {
        let policy = build_service_policy("secret", "edge-proxy");

        // Only the reissue rule may carry create/update; no other rule may.
        for block in policy.split("path ").filter(|b| !b.is_empty()) {
            let has_write = block.contains("create") || block.contains("update");
            let is_reissue =
                block.starts_with("\"secret/data/bootroot/services/edge-proxy/reissue\"");
            assert!(
                !has_write || is_reissue,
                "unexpected write capability outside the reissue path:\n{block}"
            );
        }
    }
}
