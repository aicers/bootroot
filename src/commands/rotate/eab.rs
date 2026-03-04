use anyhow::{Context, Result};

use bootroot::openbao::OpenBaoClient;
use reqwest::StatusCode;

use super::RotateContext;
use super::helpers::confirm_action;
use crate::cli::args::RotateEabArgs;
use crate::commands::constants::{SERVICE_EAB_HMAC_KEY, SERVICE_EAB_KID_KEY, SERVICE_KV_BASE};
use crate::commands::init::PATH_AGENT_EAB;
use crate::i18n::Messages;

#[derive(Debug, serde::Deserialize)]
struct EabAutoResponse {
    kid: String,
    hmac: String,
}

#[derive(Debug)]
struct EabCredentials {
    kid: String,
    hmac: String,
}

pub(super) async fn rotate_eab(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateEabArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(messages.prompt_rotate_eab(), auto_confirm, messages)?;

    let credentials = issue_eab_via_stepca(args, messages).await?;
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

async fn issue_eab_via_stepca(args: &RotateEabArgs, messages: &Messages) -> Result<EabCredentials> {
    let base = args.stepca_url.trim_end_matches('/');
    let provisioner = args.stepca_provisioner.trim();
    let endpoint = format!("{base}/acme/{provisioner}/eab");
    let client = reqwest::Client::new();

    let response = client
        .post(&endpoint)
        .send()
        .await
        .with_context(|| messages.error_eab_request_failed())?;
    let response = if response.status() == StatusCode::METHOD_NOT_ALLOWED {
        client
            .get(&endpoint)
            .send()
            .await
            .with_context(|| messages.error_eab_request_failed())?
    } else {
        response
    };
    let response = response
        .error_for_status()
        .with_context(|| messages.error_eab_request_failed())?;

    let payload: EabAutoResponse = response
        .json()
        .await
        .with_context(|| messages.error_eab_response_parse_failed())?;
    Ok(EabCredentials {
        kid: payload.kid,
        hmac: payload.hmac,
    })
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
