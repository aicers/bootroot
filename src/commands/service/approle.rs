use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::{OpenBaoClient, SecretIdOptions};
use bootroot::trust_bootstrap::SERVICE_REISSUE_KV_SUFFIX;
use tokio::fs;

use super::{
    SERVICE_ROLE_ID_FILENAME, SERVICE_ROLE_PREFIX, SERVICE_SECRET_DIR, SERVICE_SECRET_ID_FILENAME,
    ServiceAppRoleMaterialized,
};
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
    secrets_dir: &Path,
    service_name: &str,
    secret_id: &str,
    messages: &Messages,
) -> Result<PathBuf> {
    let service_dir = secrets_dir.join(SERVICE_SECRET_DIR).join(service_name);
    fs_util::ensure_secrets_dir(&service_dir).await?;
    let secret_path = service_dir.join(SERVICE_SECRET_ID_FILENAME);
    fs::write(&secret_path, secret_id)
        .await
        .with_context(|| messages.error_write_file_failed(&secret_path.display().to_string()))?;
    fs_util::set_key_permissions(&secret_path).await?;
    Ok(secret_path)
}

pub(super) async fn write_role_id_file(
    secrets_dir: &Path,
    service_name: &str,
    role_id: &str,
    messages: &Messages,
) -> Result<PathBuf> {
    let service_dir = secrets_dir.join(SERVICE_SECRET_DIR).join(service_name);
    fs_util::ensure_secrets_dir(&service_dir).await?;
    let role_path = service_dir.join(SERVICE_ROLE_ID_FILENAME);
    fs::write(&role_path, role_id)
        .await
        .with_context(|| messages.error_write_file_failed(&role_path.display().to_string()))?;
    fs_util::set_key_permissions(&role_path).await?;
    Ok(role_path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
