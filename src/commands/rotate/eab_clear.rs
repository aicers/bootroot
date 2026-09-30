use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::RotateContext;
use super::helpers::confirm_action;
use super::registrar_internal::{
    InternalConfigChange, acquire_internal_config_lock, apply_internal_config_change,
    check_internal_config_change, internal_config_path,
};
use super::registrar_targets::kv_fanout_targets;
use crate::commands::init::PATH_AGENT_EAB;
use crate::i18n::Messages;

/// Per-registration EAB KV path. The init/service flow writes EAB at
/// `bootroot/services/<registration_id>/eab` when an operator opts into
/// per-service EAB; clearing it requires writing the same shape, not a
/// `delete`, so consumers observing the path see an explicit empty value
/// instead of a missing secret.
fn service_eab_path(registration_id: &str) -> String {
    format!("bootroot/services/{registration_id}/eab")
}

/// Companion to the now-removed `rotate eab`. Writes empty
/// `{kid: "", hmac: ""}` to every known EAB KV path. Propagation to the
/// service agents is fast-poll's job: each service `bootroot-agent`
/// (local host daemon and remote alike) observes the cleared KV value on
/// its next fast-poll cycle and removes its `eab.json`, so no
/// per-service process restart or reload is required. Service
/// enumeration walks the on-disk state file plus the ids that carry a
/// registrar binding, not a blind KV listing, per issue #588 §3c: a KV
/// subtree with neither is never cleared.
///
/// The registrar endpoint daemon is the exception. Its config polls
/// nothing, so on a host that carries one the `[eab]` table is removed
/// from it here and the daemon is reloaded, keeping the file in step
/// with `OpenBao` so a later repair changes nothing it did not have to.
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

    // Resolved before the first write, so a failure to enumerate
    // registrar-managed identities clears nothing at all.
    let registration_ids = kv_fanout_targets(ctx, client, messages).await?;
    // Likewise before the first write: a registrar endpoint config this
    // run cannot rewrite refuses the rotation with nothing cleared. On a
    // host that carries one, the lock is held from here until the file
    // is published, so a repair either read the EAB before this clears
    // it or waits to read the cleared value.
    let secrets_dir = ctx.paths.secrets_dir().to_path_buf();
    let change = InternalConfigChange::RemoveEab;
    let internal_lock = if check_internal_config_change(&secrets_dir, change)
        .await?
        .found()
    {
        Some(acquire_internal_config_lock(&secrets_dir).await?)
    } else {
        None
    };

    // Per issue #588 §3c: write the empty value unconditionally. KV v2
    // writes are PUTs, so creating the path is safe and idempotent, and
    // stale installs / partial-state services are recovered by the same
    // write.
    client
        .write_kv(&kv_mount, PATH_AGENT_EAB, empty.clone())
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    println!("Cleared {PATH_AGENT_EAB}");

    // Per-service EAB. Enumerate from state plus registrar bindings, not
    // a blind KV listing: a stale KV entry with neither a state record
    // nor a binding has no recorded owner and would be ambiguous to
    // clear silently.
    for registration_id in &registration_ids {
        let path = service_eab_path(registration_id);
        client
            .write_kv(&kv_mount, &path, empty.clone())
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
        println!("Cleared {path}");
    }

    let internal_rewritten = match &internal_lock {
        Some(lock) => apply_internal_config_change(&secrets_dir, change, lock, messages).await?,
        None => false,
    };
    drop(internal_lock);
    if internal_rewritten {
        println!(
            "Removed [eab] from {}",
            internal_config_path(&secrets_dir).display()
        );
        println!(
            "EAB clear completed; service bootroot-agents apply the cleared value via their fast-poll loop within fast_poll_interval, and the registrar endpoint daemon, which polls nothing, was reloaded on its rewritten config instead."
        );
    } else {
        println!(
            "EAB clear completed; service bootroot-agents apply the cleared value via their fast-poll loop within fast_poll_interval."
        );
    }
    Ok(())
}
