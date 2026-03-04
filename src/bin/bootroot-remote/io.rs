use std::path::Path;

use anyhow::Result;
use bootroot::fs_util;
use tokio::fs;

use super::summary::ApplyStatus;
use super::{CA_BUNDLE_PEM_KEY, CliLang, TRUSTED_CA_KEY, localized};

pub(super) async fn read_secret_file(path: &Path, lang: CliLang) -> Result<String> {
    let value = fs::read_to_string(path).await?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                &format!("Secret file is empty: {}", path.display()),
                &format!("시크릿 파일이 비어 있습니다: {}", path.display()),
            )
        );
    }
    Ok(trimmed.to_string())
}

pub(super) fn read_required_string(
    data: &serde_json::Value,
    keys: &[&str],
    lang: CliLang,
) -> Result<String> {
    for key in keys {
        if let Some(value) = data.get(key).and_then(serde_json::Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    anyhow::bail!(
        "{}",
        localized(
            lang,
            &format!("Missing required string key: {}", keys.join("|")),
            &format!("필수 문자열 키가 없습니다: {}", keys.join("|")),
        )
    )
}

pub(super) fn read_required_fingerprints(
    data: &serde_json::Value,
    lang: CliLang,
) -> Result<Vec<String>> {
    let values = data
        .get(TRUSTED_CA_KEY)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                localized(
                    lang,
                    &format!("Missing required array key: {TRUSTED_CA_KEY}"),
                    &format!("필수 배열 키가 없습니다: {TRUSTED_CA_KEY}"),
                )
            )
        })?;
    if values.is_empty() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                &format!("{TRUSTED_CA_KEY} must not be empty"),
                &format!("{TRUSTED_CA_KEY} 값은 비어 있으면 안 됩니다"),
            )
        );
    }
    let mut fingerprints = Vec::with_capacity(values.len());
    for value in values {
        let fingerprint = value.as_str().ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                localized(
                    lang,
                    &format!("{TRUSTED_CA_KEY} must contain strings"),
                    &format!("{TRUSTED_CA_KEY} 배열은 문자열만 포함해야 합니다"),
                )
            )
        })?;
        if fingerprint.len() != 64 || !fingerprint.chars().all(|ch| ch.is_ascii_hexdigit()) {
            anyhow::bail!(
                "{}",
                localized(
                    lang,
                    &format!("{TRUSTED_CA_KEY} must be 64 hex chars"),
                    &format!("{TRUSTED_CA_KEY} 값은 64자리 hex여야 합니다"),
                )
            );
        }
        fingerprints.push(fingerprint.to_string());
    }
    Ok(fingerprints)
}

pub(super) async fn write_secret_file(path: &Path, contents: &str) -> Result<ApplyStatus> {
    if let Some(parent) = path.parent() {
        fs_util::ensure_secrets_dir(parent).await?;
    }
    let next = if contents.ends_with('\n') {
        contents.to_string()
    } else {
        format!("{contents}\n")
    };
    let current = if path.exists() {
        fs::read_to_string(path).await.unwrap_or_default()
    } else {
        String::new()
    };
    if current == next {
        fs_util::set_key_permissions(path).await?;
        return Ok(ApplyStatus::Unchanged);
    }
    fs::write(path, next).await?;
    fs_util::set_key_permissions(path).await?;
    Ok(ApplyStatus::Applied)
}

pub(super) async fn write_eab_file(path: &Path, kid: &str, hmac: &str) -> Result<ApplyStatus> {
    let payload = serde_json::to_string_pretty(&serde_json::json!({
        "kid": kid,
        "hmac": hmac
    }))?;
    write_secret_file(path, &payload).await
}

#[derive(Debug)]
pub(super) struct PulledSecrets {
    pub(super) secret_id: String,
    pub(super) eab_kid: String,
    pub(super) eab_hmac: String,
    pub(super) responder_hmac: String,
    pub(super) trusted_ca_sha256: Vec<String>,
    pub(super) ca_bundle_pem: Option<String>,
}

pub(super) async fn pull_secrets(
    client: &bootroot::openbao::OpenBaoClient,
    mount: &str,
    service: &str,
    lang: CliLang,
) -> Result<PulledSecrets> {
    let base = format!("{}/{service}", super::SERVICE_KV_BASE);
    let secret_id_data = client
        .read_kv(mount, &format!("{base}/secret_id"))
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service secret_id from OpenBao",
                "OpenBao에서 서비스 secret_id를 읽지 못했습니다",
            )
        })?;
    let eab_data = client
        .read_kv(mount, &format!("{base}/eab"))
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service eab from OpenBao",
                "OpenBao에서 서비스 eab를 읽지 못했습니다",
            )
        })?;
    let hmac_data = client
        .read_kv(mount, &format!("{base}/http_responder_hmac"))
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service responder hmac from OpenBao",
                "OpenBao에서 서비스 responder hmac를 읽지 못했습니다",
            )
        })?;
    let trust_data = client
        .read_kv(mount, &format!("{base}/trust"))
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service trust data from OpenBao",
                "OpenBao에서 서비스 trust 데이터를 읽지 못했습니다",
            )
        })?;

    let secret_id = read_required_string(&secret_id_data, &[super::SECRET_ID_KEY, "value"], lang)?;
    let eab_kid = read_required_string(&eab_data, &[super::EAB_KID_KEY], lang)?;
    let eab_hmac = read_required_string(&eab_data, &[super::EAB_HMAC_KEY], lang)?;
    let responder_hmac =
        read_required_string(&hmac_data, &[super::HMAC_KEY, "http_responder_hmac"], lang)?;
    let trusted_ca_sha256 = read_required_fingerprints(&trust_data, lang)?;
    let ca_bundle_pem = trust_data
        .get(CA_BUNDLE_PEM_KEY)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);

    Ok(PulledSecrets {
        secret_id,
        eab_kid,
        eab_hmac,
        responder_hmac,
        trusted_ca_sha256,
        ca_bundle_pem,
    })
}

use anyhow::Context;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_required_fingerprints_accepts_valid_values() {
        let data = serde_json::json!({
            "trusted_ca_sha256": ["a".repeat(64), "b".repeat(64)]
        });
        let parsed =
            read_required_fingerprints(&data, CliLang::En).expect("parse trust fingerprints");
        assert_eq!(parsed.len(), 2);
    }
}
