use anyhow::{Context, Result};

use bootroot::openbao::OpenBaoClient;

use super::helpers::{
    compose_has_responder, confirm_action, reload_compose_service, restart_container,
    restart_service_sidecar_agents, wait_for_rendered_file,
};
use super::{OPENBAO_AGENT_RESPONDER_CONTAINER, RENDERED_FILE_TIMEOUT, RotateContext};
use crate::cli::args::RotateResponderHmacArgs;
use crate::commands::constants::{
    RESPONDER_SERVICE_NAME, SERVICE_KV_BASE, SERVICE_RESPONDER_HMAC_KEY,
};
use crate::commands::init::{PATH_RESPONDER_HMAC, SECRET_BYTES};
use crate::i18n::Messages;

pub(super) async fn rotate_responder_hmac(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateResponderHmacArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(
        messages.prompt_rotate_responder_hmac(),
        auto_confirm,
        messages,
    )?;

    let hmac = match args.hmac.clone() {
        Some(value) => value,
        None => bootroot::utils::generate_secret(SECRET_BYTES)
            .with_context(|| messages.error_generate_secret_failed())?,
    };
    client
        .write_kv(
            &ctx.kv_mount,
            PATH_RESPONDER_HMAC,
            serde_json::json!({ "value": hmac }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    sync_service_responder_hmac_payloads(ctx, client, &hmac, messages).await?;

    let responder_path = ctx.paths.responder_config();
    restart_container(OPENBAO_AGENT_RESPONDER_CONTAINER, messages)?;
    wait_for_rendered_file(&responder_path, &hmac, RENDERED_FILE_TIMEOUT, messages).await?;

    restart_service_sidecar_agents(ctx, &hmac, messages).await?;

    let mut reloaded = false;
    if compose_has_responder(&ctx.compose_file, messages)? {
        reload_compose_service(&ctx.compose_file, RESPONDER_SERVICE_NAME, messages)?;
        reloaded = true;
    }

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_responder_config(&responder_path.display().to_string())
    );
    if reloaded {
        println!("{}", messages.rotate_summary_reload_responder());
    }
    Ok(())
}

async fn sync_service_responder_hmac_payloads(
    ctx: &RotateContext,
    client: &OpenBaoClient,
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
                &format!("{SERVICE_KV_BASE}/{service_name}/http_responder_hmac"),
                serde_json::json!({ SERVICE_RESPONDER_HMAC_KEY: hmac }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }
    Ok(())
}
