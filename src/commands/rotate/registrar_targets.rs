//! The registration ids a rotation's per-service KV fan-out writes to.
//!
//! `state.json` names the services the CLI added, and a registrar-minted
//! identity is never among them: nothing under the registrar may know the
//! state file's path. Its one durable record is the `registrar_binding`
//! under its own KV subtree, so the rotations that rewrite every
//! service's `trust`, `http_responder_hmac` or `eab` record find those
//! identities by listing `bootroot/services/` for that binding.
//!
//! The listing runs only when `state.json` records a registrar endpoint
//! at all, enabled or not: only an endpoint-enabled `init` provisions the
//! registrar, and an endpoint switched off after minting still leaves
//! live identities behind. Without the entry nothing is listed, and a
//! deployment whose runtime-rotate policy predates the `list` grant sends
//! exactly the requests it always did.
//!
//! A listing failure is never read as "no registrar identities": that
//! would leave them on the old value silently. Callers enumerate
//! immediately before their step's first `OpenBao` write, so a failure
//! aborts the step before it has written anything.

use std::collections::BTreeSet;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;
use bootroot::registrar::{RegistrarBindingState, registrar_binding_state};
use bootroot::service_material::{list_registrar_managed_ids, service_kv_path};
use bootroot::trust_bootstrap::REGISTRAR_BINDING_KV_SUFFIX;

use super::RotateContext;
use crate::commands::constants::SERVICE_KV_BASE;
use crate::i18n::Messages;

/// Returns every registration id a KV fan-out must write: the
/// `state.json` services in their existing map order, then the
/// registrar-managed ids that are not already among them, sorted.
///
/// An id present in both sets appears once, in its `state.json`
/// position. Without a `registrar_endpoint` entry in `state.json` this
/// sends no `OpenBao` request and returns the `state.json` ids alone.
///
/// # Errors
///
/// Returns the localized enumeration error, carrying the `OpenBao`
/// failure as its source, if listing `<kv>/metadata/bootroot/services/`
/// or reading a listed id's binding fails.
pub(super) async fn kv_fanout_targets(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    messages: &Messages,
) -> Result<Vec<String>> {
    let registrar_ids = registrar_only_targets(ctx, client, messages).await?;
    Ok(state_service_ids(ctx)
        .map(str::to_string)
        .chain(registrar_ids)
        .collect())
}

/// Returns the registrar-managed registration ids that `state.json` does
/// not already name, sorted.
///
/// This is the half of [`kv_fanout_targets`] a caller needs when it must
/// treat the two sets differently. Without a `registrar_endpoint` entry
/// in `state.json` it sends no `OpenBao` request and returns nothing.
///
/// # Errors
///
/// Returns the localized enumeration error, carrying the `OpenBao`
/// failure as its source, if listing `<kv>/metadata/bootroot/services/`
/// or reading a listed id's binding fails.
pub(super) async fn registrar_only_targets(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    messages: &Messages,
) -> Result<Vec<String>> {
    if ctx.state.registrar_endpoint.is_none() {
        return Ok(Vec::new());
    }
    let listed = list_registrar_managed_ids(client, &ctx.kv_mount)
        .await
        .with_context(|| {
            messages.error_rotate_registrar_targets_list_failed(&format!(
                "{}/metadata/{SERVICE_KV_BASE}/",
                ctx.kv_mount
            ))
        })?;
    let known: BTreeSet<&str> = state_service_ids(ctx).collect();
    Ok(listed
        .into_iter()
        .filter(|id| !known.contains(id.as_str()))
        .collect())
}

/// Reads one registration id's `registrar_binding` and returns the
/// lifecycle state it decodes to, or `None` when no binding exists.
///
/// Unlike the enumeration above, which reads each binding for presence
/// only, this decodes it: a caller issuing a credential must not act on
/// a binding that is still `creating`, nor on one the registrar itself
/// would refuse to read.
///
/// # Errors
///
/// Returns the localized read error if the KV read fails other than as
/// a clean not-found, and the localized decode error, carrying the
/// [`bootroot::registrar::BindingDecodeError`] as its source, if the
/// stored record is not a readable binding.
pub(super) async fn read_registrar_binding_state(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    registration_id: &str,
    messages: &Messages,
) -> Result<Option<RegistrarBindingState>> {
    let path = service_kv_path(registration_id, REGISTRAR_BINDING_KV_SUFFIX);
    let display = format!("{}/{path}", ctx.kv_mount);
    let Some(value) = client
        .try_read_kv(&ctx.kv_mount, &path)
        .await
        .with_context(|| {
            messages.error_rotate_registrar_binding_read_failed(registration_id, &display)
        })?
    else {
        return Ok(None);
    };
    registrar_binding_state(&value).map(Some).with_context(|| {
        messages.error_rotate_registrar_binding_undecodable(registration_id, &display)
    })
}

/// The `state.json` service ids in the map's order, which is the order
/// every fan-out loop walked before registrar identities existed.
fn state_service_ids(ctx: &RotateContext) -> impl Iterator<Item = &str> {
    ctx.state
        .services
        .values()
        .map(|entry| entry.registration_id.as_str())
}
