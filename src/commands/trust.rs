use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use crate::commands::init::{CA_TRUST_KEY, PATH_CA_TRUST};
use crate::i18n::Messages;
use crate::state::ServiceEntry;

const CA_BUNDLE_PEM_KEY: &str = "ca_bundle_pem";
const SERVICE_KV_BASE: &str = "bootroot/services";
const SERVICE_TRUST_KV_SUFFIX: &str = "trust";
const ROTATION_STATE_FILENAME: &str = "rotation-state.json";

/// Writes trust payload (fingerprints and CA bundle PEM) to the `OpenBao`
/// global CA path and all per-service trust paths.
pub(crate) async fn write_trust_to_openbao(
    client: &OpenBaoClient,
    kv_mount: &str,
    services: &BTreeMap<String, ServiceEntry>,
    fingerprints: &[String],
    ca_bundle_pem: &str,
    messages: &Messages,
) -> Result<()> {
    client
        .write_kv(
            kv_mount,
            PATH_CA_TRUST,
            serde_json::json!({
                CA_TRUST_KEY: fingerprints,
                CA_BUNDLE_PEM_KEY: ca_bundle_pem,
            }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;

    for entry in services.values() {
        write_service_trust(
            client,
            kv_mount,
            &entry.service_name,
            fingerprints,
            ca_bundle_pem,
            messages,
        )
        .await?;
    }

    Ok(())
}

/// Writes trust payload to a single service's trust path in `OpenBao`.
pub(crate) async fn write_service_trust(
    client: &OpenBaoClient,
    kv_mount: &str,
    service_name: &str,
    fingerprints: &[String],
    ca_bundle_pem: &str,
    messages: &Messages,
) -> Result<()> {
    client
        .write_kv(
            kv_mount,
            &format!("{SERVICE_KV_BASE}/{service_name}/{SERVICE_TRUST_KV_SUFFIX}"),
            serde_json::json!({
                CA_TRUST_KEY: fingerprints,
                CA_BUNDLE_PEM_KEY: ca_bundle_pem,
            }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())
}

/// Returns `true` if `rotation-state.json` exists in the given directory,
/// indicating that a CA key rotation is in progress.
pub(crate) fn rotation_in_progress(state_dir: &Path) -> bool {
    state_dir.join(ROTATION_STATE_FILENAME).exists()
}
