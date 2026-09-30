use std::path::PathBuf;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;
use bootroot::secret::HmacSecret;

use super::helpers::{
    compose_has_responder, confirm_action, reload_compose_service, restart_openbao_agent,
    wait_for_rendered_file,
};
use super::registrar_internal::{
    InternalConfigChange, InternalConfigLock, acquire_internal_config_lock,
    apply_internal_config_change, check_internal_config_change, internal_config_path,
};
use super::registrar_targets::kv_fanout_targets;
use super::{RENDERED_FILE_TIMEOUT, RotateContext};
use crate::cli::args::RotateResponderHmacArgs;
use crate::commands::constants::{
    RESPONDER_SERVICE_NAME, SERVICE_KV_BASE, SERVICE_RESPONDER_HMAC_KEY,
    SERVICE_RESPONDER_HMAC_KV_SUFFIX,
};
use crate::commands::container_name::BootrootContainer;
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

    let hmac = HmacSecret::new(match &args.hmac {
        Some(value) => value.clone(),
        None => bootroot::utils::generate_secret(SECRET_BYTES)
            .with_context(|| messages.error_generate_secret_failed())?,
    });
    let change = InternalConfigChange::SetResponderHmac(&hmac);
    let secrets_dir = ctx.paths.secrets_dir().to_path_buf();
    // Resolved before the control-node write, so a failure to enumerate
    // registrar-managed identities leaves every record on the old value
    // rather than rotating the responder away from the ones it missed.
    let registration_ids = kv_fanout_targets(ctx, client, messages).await?;
    // Likewise before the first write: a host whose registrar endpoint
    // config this run cannot rewrite is refused with nothing written,
    // rather than rotated away from the daemon it would leave behind.
    // On such a host the lock is then held from here — before the value
    // reaches `OpenBao`, where a repair would read it — until the
    // responder has been handed it.
    let internal_lock = if check_internal_config_change(&secrets_dir, change)
        .await?
        .found()
    {
        Some(acquire_internal_config_lock(&secrets_dir).await?)
    } else {
        None
    };
    client
        .write_kv(
            &ctx.kv_mount,
            PATH_RESPONDER_HMAC,
            serde_json::json!({ "value": hmac.expose() }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    sync_service_responder_hmac_payloads(ctx, client, &registration_ids, &hmac, messages).await?;

    // Service agents (local host daemons and remote alike) pick up the
    // rotated HMAC from their per-service KV payload via the fast-poll
    // loop; no per-service restart or reload happens here. The
    // registrar endpoint daemon is the exception: its config polls
    // nothing, so its `http_responder_hmac` is rewritten here and the
    // daemon is sent `SIGHUP`.
    let internal_rewritten = match &internal_lock {
        Some(lock) => apply_internal_config_change(&secrets_dir, change, lock, messages).await?,
        None => false,
    };

    let (responder_path, reloaded) =
        hand_responder_the_hmac(ctx, &hmac, internal_lock.as_ref(), messages).await?;
    drop(internal_lock);

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_responder_config(&responder_path.display().to_string())
    );
    if reloaded {
        println!("{}", messages.rotate_summary_reload_responder());
    }
    if internal_rewritten {
        println!(
            "{}",
            messages.rotate_summary_internal_config(
                &internal_config_path(&secrets_dir).display().to_string()
            )
        );
    }
    Ok(())
}

/// Hands the responder the rotated HMAC: restarts its `OpenBao` Agent,
/// waits for the new value to be rendered into the responder config,
/// and reloads the responder when the compose file runs one.
///
/// Takes the internal config lock by reference so its extent is fixed
/// by the type rather than by convention: the caller cannot release it
/// before these steps have returned. A repair waiting on it reads the
/// new HMAC from `OpenBao` and issues over ACME against the responder,
/// so it must not start until the responder has been handed that HMAC.
/// `None` on a host without an internal config, where nothing waits.
///
/// Returns the responder config path and whether the responder was
/// reloaded.
async fn hand_responder_the_hmac(
    ctx: &RotateContext,
    hmac: &HmacSecret,
    _internal_lock: Option<&InternalConfigLock>,
    messages: &Messages,
) -> Result<(PathBuf, bool)> {
    let responder_path = ctx.paths.responder_config();
    restart_openbao_agent(
        &ctx.compose_file,
        BootrootContainer::OpenBaoAgentResponder,
        &ctx.docker,
        messages,
    )?;
    wait_for_rendered_file(
        &responder_path,
        hmac.expose(),
        RENDERED_FILE_TIMEOUT,
        messages,
    )
    .await?;

    let mut reloaded = false;
    if compose_has_responder(&ctx.compose_file, messages)? {
        reload_compose_service(&ctx.compose_file, RESPONDER_SERVICE_NAME, messages)?;
        reloaded = true;
    }
    Ok((responder_path, reloaded))
}

/// Writes the rotated HMAC to each registration's `http_responder_hmac`
/// record, in the order given: the `state.json` services and the
/// registrar-managed identities alike.
async fn sync_service_responder_hmac_payloads(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    registration_ids: &[String],
    hmac: &HmacSecret,
    messages: &Messages,
) -> Result<()> {
    for registration_id in registration_ids {
        client
            .write_kv(
                &ctx.kv_mount,
                &format!("{SERVICE_KV_BASE}/{registration_id}/{SERVICE_RESPONDER_HMAC_KV_SUFFIX}"),
                serde_json::json!({ SERVICE_RESPONDER_HMAC_KEY: hmac.expose() }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }
    Ok(())
}
