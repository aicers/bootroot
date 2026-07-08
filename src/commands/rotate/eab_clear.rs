use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::RotateContext;
use super::helpers::confirm_action;
use crate::commands::init::PATH_AGENT_EAB;
use crate::i18n::Messages;

/// Per-service EAB KV path. The init/service flow writes EAB at
/// `bootroot/services/<svc>/eab` when an operator opts into per-service
/// EAB; clearing it requires writing the same shape, not a `delete`,
/// so consumers observing the path see an explicit empty value instead
/// of a missing secret.
fn service_eab_path(service_name: &str) -> String {
    format!("bootroot/services/{service_name}/eab")
}

/// Companion to the now-removed `rotate eab`. Writes empty
/// `{kid: "", hmac: ""}` to every known EAB KV path. Propagation to the
/// agents is fast-poll's job: each `bootroot-agent` (local host daemon
/// and remote alike) observes the cleared KV value on its next
/// fast-poll cycle and removes its `eab.json`, so no per-service
/// process restart or reload is required. Service enumeration walks the
/// on-disk state file (not KV listings) per issue #588 §3c.
pub(super) async fn rotate_eab_clear(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(
        "Clear EAB credentials from OpenBao KV?",
        auto_confirm,
        messages,
    )?;

    let kv_mount = ctx.kv_mount.clone();
    let empty = serde_json::json!({ "kid": "", "hmac": "" });

    // Per issue #588 §3c: write the empty value unconditionally. KV v2
    // writes are PUTs, so creating the path is safe and idempotent, and
    // stale installs / partial-state services are recovered by the same
    // write.
    client
        .write_kv(&kv_mount, PATH_AGENT_EAB, empty.clone())
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    println!("Cleared {PATH_AGENT_EAB}");

    // Per-service EAB. Enumerate from state, not KV listings: a stale
    // KV entry without a state record would be ambiguous to clear
    // silently.
    let service_names: Vec<String> = ctx.state.services.keys().cloned().collect();
    for service_name in &service_names {
        let path = service_eab_path(service_name);
        client
            .write_kv(&kv_mount, &path, empty.clone())
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
        println!("Cleared {path}");
    }

    println!(
        "EAB clear completed; each bootroot-agent applies the cleared value via its fast-poll loop within fast_poll_interval."
    );
    Ok(())
}
