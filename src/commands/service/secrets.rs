use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::resolve::ResolvedServiceAdd;
use super::{CaTrustMaterial, SERVICE_CA_BUNDLE_PEM_KEY, ServiceSyncMaterial};
use crate::commands::constants::{
    CA_TRUST_KEY, SERVICE_EAB_HMAC_KEY, SERVICE_EAB_KID_KEY, SERVICE_KV_BASE,
    SERVICE_RESPONDER_HMAC_KEY, SERVICE_SECRET_ID_KEY,
};
use crate::commands::init::{PATH_AGENT_EAB, PATH_CA_TRUST, PATH_RESPONDER_HMAC};
use crate::i18n::Messages;
use crate::state::{DeliveryMode, StateFile};

pub(super) async fn sync_service_kv_bundle(
    client: &OpenBaoClient,
    state: &StateFile,
    resolved: &ResolvedServiceAdd,
    secret_id: &str,
    messages: &Messages,
) -> Result<()> {
    let material = read_service_sync_material(client, &state.kv_mount, messages).await?;
    write_service_kv_secrets(
        client,
        &state.kv_mount,
        &resolved.service_name,
        &material,
        messages,
    )
    .await?;
    if matches!(resolved.delivery_mode, DeliveryMode::RemoteBootstrap) {
        let base = format!("{SERVICE_KV_BASE}/{}", resolved.service_name);
        client
            .write_kv(
                &state.kv_mount,
                &format!("{base}/secret_id"),
                serde_json::json!({ SERVICE_SECRET_ID_KEY: secret_id }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }
    Ok(())
}

fn read_required_string(
    value: &serde_json::Value,
    key: &str,
    missing_message: &str,
) -> Result<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| anyhow::anyhow!(missing_message.to_string()))
}

async fn read_service_sync_material(
    client: &OpenBaoClient,
    kv_mount: &str,
    messages: &Messages,
) -> Result<ServiceSyncMaterial> {
    let eab = client.read_kv(kv_mount, PATH_AGENT_EAB).await.ok();
    let responder_hmac = client
        .read_kv(kv_mount, PATH_RESPONDER_HMAC)
        .await
        .with_context(|| {
            format!(
                "{} ({PATH_RESPONDER_HMAC})",
                messages.error_openbao_kv_read_failed()
            )
        })?;
    let trust = client
        .read_kv(kv_mount, PATH_CA_TRUST)
        .await
        .with_context(|| {
            format!(
                "{} ({PATH_CA_TRUST})",
                messages.error_openbao_kv_read_failed()
            )
        })?;
    let trusted_ca_sha256 = parse_trusted_ca_list(
        trust
            .get(CA_TRUST_KEY)
            .ok_or_else(|| anyhow::anyhow!(messages.error_ca_trust_missing(CA_TRUST_KEY)))?,
        messages,
    )?;
    if trusted_ca_sha256.is_empty() {
        anyhow::bail!(messages.error_ca_trust_empty());
    }
    let (eab_kid, eab_hmac) = match &eab {
        Some(data) => (
            Some(read_required_string(
                data,
                SERVICE_EAB_KID_KEY,
                "OpenBao EAB data missing key: kid",
            )?),
            Some(read_required_string(
                data,
                SERVICE_EAB_HMAC_KEY,
                "OpenBao EAB data missing key: hmac",
            )?),
        ),
        None => (None, None),
    };
    Ok(ServiceSyncMaterial {
        eab_kid,
        eab_hmac,
        responder_hmac: read_required_string(
            &responder_hmac,
            "value",
            "OpenBao responder HMAC data missing key: value",
        )?,
        trusted_ca_sha256,
        ca_bundle_pem: trust
            .get(SERVICE_CA_BUNDLE_PEM_KEY)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned),
    })
}

async fn write_service_kv_secrets(
    client: &OpenBaoClient,
    kv_mount: &str,
    service_name: &str,
    material: &ServiceSyncMaterial,
    messages: &Messages,
) -> Result<()> {
    let base = format!("{SERVICE_KV_BASE}/{service_name}");
    let eab_kid = material.eab_kid.as_deref().unwrap_or("");
    let eab_hmac = material.eab_hmac.as_deref().unwrap_or("");
    client
        .write_kv(
            kv_mount,
            &format!("{base}/eab"),
            serde_json::json!({
                SERVICE_EAB_KID_KEY: eab_kid,
                SERVICE_EAB_HMAC_KEY: eab_hmac,
            }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    client
        .write_kv(
            kv_mount,
            &format!("{base}/http_responder_hmac"),
            serde_json::json!({ SERVICE_RESPONDER_HMAC_KEY: &material.responder_hmac }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    if let Some(bundle) = material.ca_bundle_pem.as_deref() {
        crate::commands::trust::write_service_trust(
            client,
            kv_mount,
            service_name,
            &material.trusted_ca_sha256,
            bundle,
            messages,
        )
        .await?;
    } else {
        // Legacy fallback for installations before ca_bundle_pem was introduced.
        client
            .write_kv(
                kv_mount,
                &format!("{base}/trust"),
                serde_json::json!({ CA_TRUST_KEY: &material.trusted_ca_sha256 }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }
    Ok(())
}

pub(super) async fn read_ca_trust_material(
    client: &OpenBaoClient,
    kv_mount: &str,
    messages: &Messages,
) -> Result<Option<CaTrustMaterial>> {
    if !client
        .kv_exists(kv_mount, PATH_CA_TRUST)
        .await
        .with_context(|| messages.error_openbao_kv_exists_failed())?
    {
        return Ok(None);
    }
    let data = client
        .read_kv(kv_mount, PATH_CA_TRUST)
        .await
        .with_context(|| messages.error_openbao_kv_read_failed())?;
    let value = data
        .get(CA_TRUST_KEY)
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_trust_missing(CA_TRUST_KEY)))?;
    let fingerprints = parse_trusted_ca_list(value, messages)?;
    if fingerprints.is_empty() {
        anyhow::bail!(messages.error_ca_trust_empty());
    }
    let ca_bundle_pem = data
        .get(SERVICE_CA_BUNDLE_PEM_KEY)
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    Ok(Some(CaTrustMaterial {
        trusted_ca_sha256: fingerprints,
        ca_bundle_pem,
    }))
}

pub(super) fn parse_trusted_ca_list(
    value: &serde_json::Value,
    messages: &Messages,
) -> Result<Vec<String>> {
    let items = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_trust_invalid()))?;
    let mut fingerprints = Vec::with_capacity(items.len());
    for item in items {
        let fingerprint = item
            .as_str()
            .ok_or_else(|| anyhow::anyhow!(messages.error_ca_trust_invalid()))?;
        if !is_valid_sha256_fingerprint(fingerprint) {
            anyhow::bail!(messages.error_ca_trust_invalid());
        }
        fingerprints.push(fingerprint.to_string());
    }
    Ok(fingerprints)
}

fn is_valid_sha256_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::Messages;

    fn test_messages() -> Messages {
        Messages::new("en").expect("valid language")
    }

    #[test]
    fn test_parse_trusted_ca_list_accepts_valid() {
        let messages = test_messages();
        let value = serde_json::json!(["a".repeat(64), "b".repeat(64)]);
        let parsed = parse_trusted_ca_list(&value, &messages).expect("parse list");
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], "a".repeat(64));
        assert_eq!(parsed[1], "b".repeat(64));
    }

    #[test]
    fn test_parse_trusted_ca_list_rejects_non_array() {
        let messages = test_messages();
        let value = serde_json::json!("not-array");
        let err = parse_trusted_ca_list(&value, &messages).unwrap_err();
        assert!(err.to_string().contains("OpenBao CA trust data"));
    }

    #[test]
    fn test_parse_trusted_ca_list_rejects_invalid_fingerprint() {
        let messages = test_messages();
        let value = serde_json::json!(["not-hex"]);
        let err = parse_trusted_ca_list(&value, &messages).unwrap_err();
        assert!(err.to_string().contains("OpenBao CA trust data"));
    }
}
