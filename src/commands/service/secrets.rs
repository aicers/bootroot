use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;
use bootroot::service_material::{
    ServiceTrustError, ServiceTrustMaterial, parse_trusted_ca_list, read_service_trust_material,
    write_service_trust_material,
};

use super::resolve::ResolvedServiceAdd;
use super::{CaTrustMaterial, SERVICE_CA_BUNDLE_PEM_KEY, ServiceSyncMaterial};
use crate::commands::constants::{CA_TRUST_KEY, SERVICE_KV_BASE, SERVICE_SECRET_ID_KEY};
use crate::commands::init::PATH_CA_TRUST;
use crate::i18n::Messages;
use crate::state::{DeliveryMode, StateFile};

pub(super) async fn sync_service_kv_bundle(
    client: &OpenBaoClient,
    state: &StateFile,
    resolved: &ResolvedServiceAdd,
    secret_id: &str,
    messages: &Messages,
) -> Result<ServiceSyncMaterial> {
    let material = read_service_trust_material(client, &state.kv_mount)
        .await
        .map_err(|err| trust_error(err, messages))?;
    write_service_trust_material(
        client,
        &state.kv_mount,
        &resolved.registration_id,
        &material,
    )
    .await
    .map_err(|err| trust_error(err, messages))?;
    if matches!(resolved.delivery_mode, DeliveryMode::RemoteBootstrap) {
        let base = format!("{SERVICE_KV_BASE}/{}", resolved.registration_id);
        client
            .write_kv(
                &state.kv_mount,
                &format!("{base}/secret_id"),
                serde_json::json!({ SERVICE_SECRET_ID_KEY: secret_id }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }
    Ok(ServiceSyncMaterial::from(material))
}

impl From<ServiceTrustMaterial> for ServiceSyncMaterial {
    fn from(material: ServiceTrustMaterial) -> Self {
        let ServiceTrustMaterial {
            eab_kid,
            eab_hmac,
            responder_hmac,
            trusted_ca_sha256,
            ca_bundle_pem,
        } = material;
        Self {
            eab_kid,
            eab_hmac: eab_hmac.map(|hmac| hmac.expose().to_owned()),
            responder_hmac: responder_hmac.expose().to_owned(),
            trusted_ca_sha256,
            ca_bundle_pem,
        }
    }
}

/// Renders a shared trust-material failure as the diagnostic `service
/// add` reported for it before the logic moved into the library.
///
/// Each arm rebuilds the exact error chain the CLI produced then — the
/// localized message over the `OpenBao` failure, or the bare message —
/// rather than wrapping the typed error, so no extra cause line appears
/// under it.
fn trust_error(err: ServiceTrustError, messages: &Messages) -> anyhow::Error {
    match err {
        ServiceTrustError::Read { path, source } => source.context(format!(
            "{} ({path})",
            messages.error_openbao_kv_read_failed()
        )),
        ServiceTrustError::Write { source, .. } => {
            source.context(messages.error_openbao_kv_write_failed())
        }
        ServiceTrustError::CaTrustMissing { key } => {
            anyhow::anyhow!(messages.error_ca_trust_missing(key))
        }
        ServiceTrustError::CaTrustEmpty => anyhow::anyhow!(messages.error_ca_trust_empty()),
        ServiceTrustError::CaTrustInvalid => anyhow::anyhow!(messages.error_ca_trust_invalid()),
        ServiceTrustError::MissingKey(key) => anyhow::anyhow!(key.to_string()),
    }
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

pub(super) async fn read_ca_bundle_pem(
    client: &OpenBaoClient,
    kv_mount: &str,
    messages: &Messages,
) -> Result<String> {
    let trust = client
        .read_kv(kv_mount, PATH_CA_TRUST)
        .await
        .with_context(|| {
            format!(
                "{} ({PATH_CA_TRUST})",
                messages.error_openbao_kv_read_failed()
            )
        })?;
    read_required_string(
        &trust,
        SERVICE_CA_BUNDLE_PEM_KEY,
        &format!("OpenBao CA trust data missing key: {SERVICE_CA_BUNDLE_PEM_KEY}"),
    )
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
    let fingerprints = parse_trusted_ca_list(value).map_err(|err| trust_error(err, messages))?;
    if fingerprints.is_empty() {
        anyhow::bail!(messages.error_ca_trust_empty());
    }
    Ok(Some(CaTrustMaterial {
        trusted_ca_sha256: fingerprints,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::test_messages;

    /// The parser moved into the library; what stays here is that its
    /// typed failures still render as the localized CA-trust diagnostics.
    #[test]
    fn test_invalid_trusted_ca_list_keeps_its_cli_message() {
        let messages = test_messages();
        for value in [
            serde_json::json!("not-array"),
            serde_json::json!(["not-hex"]),
        ] {
            let err = parse_trusted_ca_list(&value)
                .map_err(|err| trust_error(err, &messages))
                .unwrap_err();
            assert_eq!(err.to_string(), messages.error_ca_trust_invalid());
            assert!(err.to_string().contains("OpenBao CA trust data"));
            assert_eq!(err.chain().count(), 1);
        }
    }

    #[test]
    fn test_trust_errors_render_the_pre_refactor_messages() {
        let messages = test_messages();

        let err = trust_error(
            ServiceTrustError::Read {
                path: "bootroot/ca",
                source: anyhow::anyhow!("boom"),
            },
            &messages,
        );
        assert_eq!(
            err.to_string(),
            format!("{} (bootroot/ca)", messages.error_openbao_kv_read_failed())
        );
        let causes: Vec<String> = err.chain().skip(1).map(ToString::to_string).collect();
        assert_eq!(causes, ["boom"]);

        let err = trust_error(
            ServiceTrustError::Write {
                path: "bootroot/services/x/trust".to_string(),
                source: anyhow::anyhow!("boom"),
            },
            &messages,
        );
        assert_eq!(err.to_string(), messages.error_openbao_kv_write_failed());
        assert_eq!(err.chain().count(), 2);

        let err = trust_error(
            ServiceTrustError::CaTrustMissing { key: CA_TRUST_KEY },
            &messages,
        );
        assert_eq!(
            err.to_string(),
            messages.error_ca_trust_missing(CA_TRUST_KEY)
        );

        let err = trust_error(ServiceTrustError::CaTrustEmpty, &messages);
        assert_eq!(err.to_string(), messages.error_ca_trust_empty());

        let err = trust_error(
            ServiceTrustError::MissingKey(
                bootroot::service_material::TrustMaterialKey::ResponderHmac,
            ),
            &messages,
        );
        assert_eq!(
            err.to_string(),
            "OpenBao responder HMAC data missing key: value"
        );
        assert_eq!(err.chain().count(), 1);
    }
}
