use anyhow::{Context, Result};
use bootroot::eab::EabCredentials;
use bootroot::openbao::OpenBaoClient;

use super::RotateContext;
use super::helpers::confirm_action;
use crate::cli::args::RotateEabArgs;
use crate::commands::constants::{SERVICE_EAB_HMAC_KEY, SERVICE_EAB_KID_KEY, SERVICE_KV_BASE};
use crate::commands::init::PATH_AGENT_EAB;
use crate::i18n::Messages;

const DEFAULT_EAB_PATH: &str = "eab";

pub(super) async fn rotate_eab(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateEabArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(messages.prompt_rotate_eab(), auto_confirm, messages)?;

    let credentials = issue_eab(args, messages).await?;
    client
        .write_kv(
            &ctx.kv_mount,
            PATH_AGENT_EAB,
            serde_json::json!({ "kid": credentials.kid, "hmac": credentials.hmac }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    sync_service_eab_payloads(ctx, client, &credentials.kid, &credentials.hmac, messages).await?;

    println!("{}", messages.rotate_summary_title());
    println!("{}", messages.summary_eab_kid(&credentials.kid));
    println!("{}", messages.summary_eab_hmac(&credentials.hmac));
    Ok(())
}

async fn issue_eab(args: &RotateEabArgs, messages: &Messages) -> Result<EabCredentials> {
    bootroot::eab::issue_eab_via_stepca(
        &args.stepca_url,
        &args.stepca_provisioner,
        DEFAULT_EAB_PATH,
    )
    .await
    .with_context(|| messages.error_eab_auto_failed())
}

async fn sync_service_eab_payloads(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    kid: &str,
    hmac: &str,
    messages: &Messages,
) -> Result<()> {
    for service_name in ctx
        .state
        .services
        .values()
        .map(|entry| entry.service_name.as_str())
    {
        client
            .write_kv(
                &ctx.kv_mount,
                &format!("{SERVICE_KV_BASE}/{service_name}/eab"),
                serde_json::json!({ SERVICE_EAB_KID_KEY: kid, SERVICE_EAB_HMAC_KEY: hmac }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }
    Ok(())
}
