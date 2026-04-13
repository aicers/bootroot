use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::{OpenBaoClient, SecretIdOptions};

use super::helpers::{confirm_action, reload_openbao_agent, write_secret_id_atomic};
use super::{ROLE_ID_FILENAME, RotateContext};
use crate::cli::args::RotateAppRoleSecretIdArgs;
use crate::commands::constants::{
    DEFAULT_SECRET_ID_NUM_USES, SERVICE_KV_BASE, SERVICE_SECRET_ID_KEY,
};
use crate::commands::service::resolve::effective_wrap_ttl;
use crate::i18n::Messages;
use crate::state::{DeliveryMode, ServiceEntry};

pub(super) async fn rotate_approle_secret_id(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateAppRoleSecretIdArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(
        &messages.prompt_rotate_approle_secret_id(&args.service_name),
        auto_confirm,
        messages,
    )?;

    let entry = ctx
        .state
        .services
        .get(&args.service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(&args.service_name)))?
        .clone();
    let is_remote = matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap);
    if !is_remote {
        ensure_role_id_file(&entry, client, messages).await?;
    }
    let stored_num_uses = entry
        .approle
        .secret_id_num_uses
        .unwrap_or(DEFAULT_SECRET_ID_NUM_USES);
    // Add 1 for the verify-login below so the caller's requested
    // num_uses still remain after rotation verification.
    let effective_num_uses = if stored_num_uses > 0 {
        stored_num_uses.checked_add(1).ok_or_else(|| {
            anyhow::anyhow!(
                "secret_id_num_uses ({stored_num_uses}) is too large to \
                 add the +1 verification allowance; use a smaller value"
            )
        })?
    } else {
        stored_num_uses
    };
    let secret_id_options = SecretIdOptions {
        ttl: entry.approle.secret_id_ttl.clone(),
        num_uses: Some(effective_num_uses),
        metadata: None,
    };
    let wrap_ttl = effective_wrap_ttl(entry.approle.secret_id_wrap_ttl.as_deref());
    let new_secret_id = match wrap_ttl {
        Some(ttl) => {
            client
                .create_secret_id_wrapped(&entry.approle.role_name, &secret_id_options, ttl)
                .await
        }
        None => {
            client
                .create_secret_id(&entry.approle.role_name, &secret_id_options)
                .await
        }
    }
    .with_context(|| messages.error_openbao_secret_id_failed())?;
    if !is_remote {
        write_secret_id_atomic(&entry.approle.secret_id_path, &new_secret_id, messages).await?;
        reload_openbao_agent(&entry, messages)?;
    }
    client
        .login_approle(&entry.approle.role_id, &new_secret_id)
        .await
        .with_context(|| messages.error_openbao_approle_login_failed())?;
    if is_remote {
        write_remote_service_secret_id(
            client,
            &ctx.kv_mount,
            &args.service_name,
            &new_secret_id,
            messages,
        )
        .await?;
    }

    println!("{}", messages.rotate_summary_title());
    // CodeQL flags this as cleartext-logging, but the second argument is
    // `secret_id_path` (a file path), not the secret_id value. Dismiss as false positive.
    println!(
        "{}",
        messages.rotate_summary_approle_secret_id(
            &args.service_name,
            &entry.approle.secret_id_path.display().to_string()
        )
    );
    if !is_remote {
        println!("{}", messages.rotate_summary_reload_openbao_agent());
    }
    println!(
        "{}",
        messages.rotate_summary_approle_login_ok(&args.service_name)
    );
    Ok(())
}

async fn ensure_role_id_file(
    entry: &ServiceEntry,
    client: &OpenBaoClient,
    messages: &Messages,
) -> Result<()> {
    let service_dir = entry
        .approle
        .secret_id_path
        .parent()
        .unwrap_or(Path::new("."));
    let role_id_path = service_dir.join(ROLE_ID_FILENAME);
    if role_id_path.exists() {
        return Ok(());
    }
    let role_id = client
        .read_role_id(&entry.approle.role_name)
        .await
        .with_context(|| messages.error_openbao_role_id_failed())?;
    fs_util::ensure_secrets_dir(service_dir).await?;
    tokio::fs::write(&role_id_path, role_id)
        .await
        .with_context(|| messages.error_write_file_failed(&role_id_path.display().to_string()))?;
    fs_util::set_key_permissions(&role_id_path).await?;
    Ok(())
}

async fn write_remote_service_secret_id(
    client: &OpenBaoClient,
    kv_mount: &str,
    service_name: &str,
    secret_id: &str,
    messages: &Messages,
) -> Result<()> {
    client
        .write_kv(
            kv_mount,
            &format!("{SERVICE_KV_BASE}/{service_name}/secret_id"),
            serde_json::json!({ SERVICE_SECRET_ID_KEY: secret_id }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())
}
