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
use bootroot::service_material::list_registrar_managed_ids;

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

/// The `state.json` service ids in the map's order, which is the order
/// every fan-out loop walked before registrar identities existed.
fn state_service_ids(ctx: &RotateContext) -> impl Iterator<Item = &str> {
    ctx.state
        .services
        .values()
        .map(|entry| entry.registration_id.as_str())
}
