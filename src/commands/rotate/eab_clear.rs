use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::RotateContext;
use super::helpers::confirm_action;
use crate::commands::init::PATH_AGENT_EAB;
use crate::commands::service::openbao_sidecar_refresh::refresh_service_sidecar;
use crate::i18n::Messages;

/// Per-service EAB KV path. The init/service flow writes EAB at
/// `bootroot/services/<svc>/eab` when an operator opts into per-service
/// EAB; clearing it requires writing the same shape, not a `delete`,
/// so the consul-template `{{ if .Data.data.kid }}` branch evaluates
/// to false instead of erroring on a missing path.
fn service_eab_path(service_name: &str) -> String {
    format!("bootroot/services/{service_name}/eab")
}

/// Companion to the now-removed `rotate eab`. Writes empty
/// `{kid: "", hmac: ""}` to every known EAB KV path then refreshes each
/// affected sidecar so the templated agent.toml drops its `[eab]` block
/// on the next cycle. Service enumeration walks the on-disk state file
/// (not KV listings) per issue #588 §3c.
pub(super) async fn rotate_eab_clear(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(
        "Clear EAB credentials from OpenBao KV and refresh affected sidecars?",
        auto_confirm,
        messages,
    )?;

    let kv_mount = ctx.kv_mount.clone();
    let empty = serde_json::json!({ "kid": "", "hmac": "" });

    // Per issue #588 §3c: write the empty value unconditionally. A
    // missing KV path leaves consul-template's `{{ with secret }}` block
    // erroring on a missing secret rather than rendering the empty
    // branch — for stale installs and partial-state services that is
    // exactly the failure mode `eab-clear` exists to recover from. KV
    // v2 writes are PUTs, so creating the path is safe and idempotent.
    client
        .write_kv(&kv_mount, PATH_AGENT_EAB, empty.clone())
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    println!("Cleared {PATH_AGENT_EAB}");

    // Per-service EAB. Enumerate from state, not KV listings: a stale
    // KV entry without a state record would be ambiguous to clear
    // silently.
    let services: Vec<_> = ctx.state.services.values().cloned().collect();
    let mut refresh_failures: Vec<(String, anyhow::Error)> = Vec::new();
    for entry in &services {
        let path = service_eab_path(&entry.service_name);
        client
            .write_kv(&kv_mount, &path, empty.clone())
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
        println!("Cleared {path}");
        // Refresh the sidecar so consul-template re-reads the now-empty
        // path on its next cycle. Collect failures rather than aborting
        // mid-loop so every service still gets its KV cleared and the
        // operator sees the full set of sidecars that need attention.
        // The error is fatal at the end of the loop: a LocalFile sidecar
        // that failed to restart is still rendering the old EAB, which
        // is exactly the §6 stale-render symptom `eab-clear` exists to
        // close. `RemoteBootstrap` returns Ok without shelling out, so
        // it never lands in this list.
        if let Err(err) = refresh_service_sidecar(entry, messages) {
            eprintln!(
                "error: failed to refresh sidecar for service {}: {err}",
                entry.service_name
            );
            refresh_failures.push((entry.service_name.clone(), err));
        }
    }

    if !refresh_failures.is_empty() {
        let names: Vec<&str> = refresh_failures
            .iter()
            .map(|(name, _)| name.as_str())
            .collect();
        anyhow::bail!(
            "EAB cleared in KV, but {} sidecar(s) failed to refresh and are still rendering the old EAB: {}. Restart them manually (`docker restart bootroot-openbao-agent-<svc>`) before re-running issuance.",
            refresh_failures.len(),
            names.join(", ")
        );
    }

    println!("EAB clear completed; templates will render without [eab] on the next cycle.");
    Ok(())
}
