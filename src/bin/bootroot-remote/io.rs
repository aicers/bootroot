use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;
use tokio::fs;

use super::summary::ApplyStatus;
use super::{CA_BUNDLE_PEM_KEY, Locale, TRUSTED_CA_KEY, localized};

pub(super) async fn read_secret_file(path: &Path, lang: Locale) -> Result<String> {
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
    lang: Locale,
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

/// Reads an optional string from the KV payload. Returns `Ok(None)`
/// when no matching key exists or every candidate value trims to an
/// empty string. Unlike [`read_required_string`], absence is not an
/// error. A present-but-non-string value (e.g., number, array, bool)
/// is treated as malformed operator-provided data and fails loudly so
/// a typo cannot silently demote the field to "absent".
pub(super) fn read_optional_string(
    data: &serde_json::Value,
    keys: &[&str],
    lang: Locale,
) -> Result<Option<String>> {
    for key in keys {
        let Some(value) = data.get(key) else {
            continue;
        };
        let string = value.as_str().ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                localized(
                    lang,
                    &format!("Expected string value for optional key: {key}"),
                    &format!("선택적 키 값이 문자열이 아닙니다: {key}"),
                )
            )
        })?;
        let trimmed = string.trim();
        if !trimmed.is_empty() {
            return Ok(Some(trimmed.to_string()));
        }
    }
    Ok(None)
}

pub(super) fn read_required_fingerprints(
    data: &serde_json::Value,
    lang: Locale,
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
    let current = match fs::read_to_string(path).await {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(err).with_context(|| {
                format!("Failed to read existing secret file: {}", path.display())
            });
        }
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

/// Removes a stale EAB file that was written by a previous bootstrap so
/// that `bootroot-agent --eab-file` cannot pick up credentials the
/// operator has since cleared from `OpenBao`. Returns [`ApplyStatus::Applied`]
/// when the file existed and was removed and [`ApplyStatus::Skipped`] when
/// the file was already absent.
pub(super) async fn remove_eab_file(path: &Path) -> Result<ApplyStatus> {
    match fs::remove_file(path).await {
        Ok(()) => Ok(ApplyStatus::Applied),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(ApplyStatus::Skipped),
        Err(err) => {
            Err(err).with_context(|| format!("Failed to remove stale EAB file: {}", path.display()))
        }
    }
}

#[derive(Debug)]
pub(super) struct PulledSecrets {
    pub(super) secret_id: String,
    pub(super) eab_kid: Option<String>,
    pub(super) eab_hmac: Option<String>,
    pub(super) responder_hmac: String,
    pub(super) trusted_ca_sha256: Vec<String>,
    pub(super) ca_bundle_pem: String,
}

pub(super) async fn pull_secrets(
    client: &bootroot::openbao::OpenBaoClient,
    mount: &str,
    service: &str,
    lang: Locale,
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
    // The EAB KV entry is optional: it is only populated when the
    // operator has provided EAB credentials. A missing entry (404)
    // means the ACME CA does not require EAB for this account, so it
    // must not be fatal. Transport or 5xx errors still propagate —
    // otherwise a transient OpenBao outage would silently demote EAB
    // to "skipped" instead of failing the bootstrap.
    let eab_data = client
        .try_read_kv(mount, &format!("{base}/eab"))
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service EAB from OpenBao",
                "OpenBao에서 서비스 EAB를 읽지 못했습니다",
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
    let (eab_kid, eab_hmac) = match eab_data.as_ref() {
        Some(data) => {
            let kid = read_optional_string(data, &[super::EAB_KID_KEY], lang)?;
            let hmac = read_optional_string(data, &[super::EAB_HMAC_KEY], lang)?;
            // Preserve the "both-or-neither" semantics: a half-populated
            // EAB entry is treated the same as absent so the caller
            // cannot accidentally forward a `kid` without its `hmac`.
            match (kid, hmac) {
                (Some(k), Some(h)) => (Some(k), Some(h)),
                _ => (None, None),
            }
        }
        None => (None, None),
    };
    let responder_hmac =
        read_required_string(&hmac_data, &[super::HMAC_KEY, "http_responder_hmac"], lang)?;
    let trusted_ca_sha256 = read_required_fingerprints(&trust_data, lang)?;
    let ca_bundle_pem = read_required_string(&trust_data, &[CA_BUNDLE_PEM_KEY], lang)?;

    Ok(PulledSecrets {
        secret_id,
        eab_kid,
        eab_hmac,
        responder_hmac,
        trusted_ca_sha256,
        ca_bundle_pem,
    })
}
#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn read_required_fingerprints_accepts_valid_values() {
        let data = serde_json::json!({
            "trusted_ca_sha256": ["a".repeat(64), "b".repeat(64)]
        });
        let parsed =
            read_required_fingerprints(&data, Locale::En).expect("parse trust fingerprints");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn read_optional_string_returns_trimmed_value_when_present() {
        let data = serde_json::json!({ "kid": "  abc  " });
        let parsed = read_optional_string(&data, &["kid"], Locale::En).expect("parse kid");
        assert_eq!(parsed.as_deref(), Some("abc"));
    }

    #[test]
    fn read_optional_string_returns_none_when_key_missing() {
        let data = serde_json::json!({ "other": "value" });
        let parsed =
            read_optional_string(&data, &["kid"], Locale::En).expect("missing key is not an error");
        assert!(parsed.is_none());
    }

    #[test]
    fn read_optional_string_returns_none_when_value_empty_or_whitespace() {
        let empty = serde_json::json!({ "kid": "" });
        let parsed =
            read_optional_string(&empty, &["kid"], Locale::En).expect("empty value is absence");
        assert!(parsed.is_none());

        let whitespace = serde_json::json!({ "kid": "   " });
        let parsed = read_optional_string(&whitespace, &["kid"], Locale::En)
            .expect("whitespace value is absence");
        assert!(parsed.is_none());
    }

    #[test]
    fn read_optional_string_falls_back_to_later_keys() {
        let data = serde_json::json!({ "alt": "value" });
        let parsed = read_optional_string(&data, &["primary", "alt"], Locale::En)
            .expect("fallback to alt key");
        assert_eq!(parsed.as_deref(), Some("value"));
    }

    #[test]
    fn read_optional_string_fails_on_non_string_values() {
        let data = serde_json::json!({ "kid": 42 });
        let err = read_optional_string(&data, &["kid"], Locale::En)
            .expect_err("numeric kid must fail loudly");
        assert!(err.to_string().contains("kid"));
    }

    #[test]
    fn read_optional_string_fails_on_null_values() {
        let data = serde_json::json!({ "kid": serde_json::Value::Null });
        let err = read_optional_string(&data, &["kid"], Locale::En)
            .expect_err("null kid must fail loudly");
        assert!(err.to_string().contains("kid"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn write_secret_file_fails_when_existing_file_is_unreadable() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("secret.txt");
        std::fs::write(&path, "old\n").expect("write secret");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o200))
            .expect("chmod secret");

        let err = write_secret_file(&path, "next")
            .await
            .expect_err("unreadable existing file should fail");
        assert!(
            err.to_string()
                .contains("Failed to read existing secret file")
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("restore secret permissions");
    }
}
