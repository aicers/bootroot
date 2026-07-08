//! Shared parsers and validators for per-service `OpenBao` KV payloads.
//!
//! The `bootroot-remote bootstrap` / `apply-secret-id` paths and the remote
//! `bootroot-agent` fast-poll loop read the same KV paths
//! (`{kv_mount}/data/bootroot/services/<service>/{trust,secret_id}`). This
//! module owns one implementation of the payload validation so both callers
//! agree on shape, required fields, and fingerprint formatting. Callers that
//! need localized error text wrap these errors with their own context.

use anyhow::{Result, bail};

use crate::trust_bootstrap::{
    CA_BUNDLE_PEM_KEY, EAB_HMAC_KEY, EAB_KID_KEY, HMAC_KEY, SECRET_ID_KEY, TRUSTED_CA_KEY,
};

/// Length in hex characters of a SHA-256 fingerprint.
const FINGERPRINT_HEX_LEN: usize = 64;

/// Parsed `trust` KV payload: the trust-anchor pin list and the CA bundle
/// PEM the anchors are drawn from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustPayload {
    pub trusted_ca_sha256: Vec<String>,
    pub ca_bundle_pem: String,
}

/// Parses and validates a service `trust` KV payload.
///
/// # Errors
///
/// Returns an error when `trusted_ca_sha256` is missing, empty, or contains a
/// non-string / non-64-hex value, or when `ca_bundle_pem` is missing or empty.
pub fn parse_trust_payload(data: &serde_json::Value) -> Result<TrustPayload> {
    let trusted_ca_sha256 = parse_fingerprints(data)?;
    let ca_bundle_pem = parse_required_string(data, &[CA_BUNDLE_PEM_KEY])?;
    Ok(TrustPayload {
        trusted_ca_sha256,
        ca_bundle_pem,
    })
}

/// Parses a service `secret_id` KV payload, returning the credential.
///
/// Accepts either the canonical `secret_id` key or a bare `value` key.
///
/// # Errors
///
/// Returns an error when neither key holds a non-empty string.
pub fn parse_secret_id(data: &serde_json::Value) -> Result<String> {
    parse_required_string(data, &[SECRET_ID_KEY, "value"])
}

/// Parsed `eab` KV payload: either populated credentials or an explicit
/// clear.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EabPayload {
    /// Populated EAB — both `kid` and `hmac` are non-empty.
    Populated { kid: String, hmac: String },
    /// Explicit clear — both `kid` and `hmac` are the empty string.
    Clear,
}

/// Parses a service `eab` KV payload.
///
/// Accepts either a populated `{ "kid": non-empty, "hmac": non-empty }` or
/// the explicit clear shape `{ "kid": "", "hmac": "" }`. Rejects partial or
/// ambiguous shapes (an empty `kid` with a non-empty `hmac` or vice versa),
/// a missing key, or a non-string value.
///
/// The clear shape must NOT be routed through [`parse_required_string`]: that
/// helper trims and rejects empty strings, which would misclassify a clear as
/// malformed and prevent it from ever applying. The KV payload keys the secret
/// as `hmac` (distinct from the on-disk `eab.json` `key` alias).
///
/// # Errors
///
/// Returns an error when a key is missing, is not a string, or the two fields
/// disagree on emptiness.
pub fn parse_eab_payload(data: &serde_json::Value) -> Result<EabPayload> {
    let kid = parse_eab_field(data, EAB_KID_KEY)?;
    let hmac = parse_eab_field(data, EAB_HMAC_KEY)?;
    match (kid.is_empty(), hmac.is_empty()) {
        (false, false) => Ok(EabPayload::Populated { kid, hmac }),
        (true, true) => Ok(EabPayload::Clear),
        _ => bail!(
            "EAB payload has partial credentials: {EAB_KID_KEY} and {EAB_HMAC_KEY} must both be \
             set or both be empty"
        ),
    }
}

/// Reads an `eab` string field, trimmed. Unlike [`parse_required_string`], a
/// present-but-empty value is preserved (returned as an empty string) so the
/// caller can distinguish the explicit clear shape from a malformed one.
///
/// # Errors
///
/// Returns an error when the key is absent or its value is not a string.
fn parse_eab_field(data: &serde_json::Value, key: &str) -> Result<String> {
    let value = data
        .get(key)
        .ok_or_else(|| anyhow::anyhow!("Missing required EAB key: {key}"))?;
    let string = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("EAB key {key} must be a string"))?;
    Ok(string.trim().to_string())
}

/// Parses a service `http_responder_hmac` KV payload, returning the HMAC.
///
/// The rotate producer writes the `{ "hmac": <value> }` shape; a bare
/// `value` key is accepted as a fallback, mirroring [`parse_secret_id`].
///
/// # Errors
///
/// Returns an error when neither key holds a non-empty string.
pub fn parse_responder_hmac(data: &serde_json::Value) -> Result<String> {
    parse_required_string(data, &[HMAC_KEY, "value"])
}

/// Reads the first non-empty string value among `keys`, trimmed.
///
/// # Errors
///
/// Returns an error when no candidate key holds a non-empty string.
fn parse_required_string(data: &serde_json::Value, keys: &[&str]) -> Result<String> {
    for key in keys {
        if let Some(value) = data.get(key).and_then(serde_json::Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    bail!("Missing required string key: {}", keys.join("|"))
}

/// Validates the `trusted_ca_sha256` array as a non-empty list of 64-char
/// hex fingerprints.
///
/// # Errors
///
/// Returns an error when the key is absent, not an array, empty, or holds a
/// value that is not a 64-char hex string.
fn parse_fingerprints(data: &serde_json::Value) -> Result<Vec<String>> {
    let values = data
        .get(TRUSTED_CA_KEY)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Missing required array key: {TRUSTED_CA_KEY}"))?;
    if values.is_empty() {
        bail!("{TRUSTED_CA_KEY} must not be empty");
    }
    let mut fingerprints = Vec::with_capacity(values.len());
    for value in values {
        let fingerprint = value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{TRUSTED_CA_KEY} must contain strings"))?;
        if fingerprint.len() != FINGERPRINT_HEX_LEN
            || !fingerprint.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            bail!("{TRUSTED_CA_KEY} must be {FINGERPRINT_HEX_LEN} hex chars");
        }
        fingerprints.push(fingerprint.to_string());
    }
    Ok(fingerprints)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_trust_payload_accepts_valid_values() {
        let data = serde_json::json!({
            "trusted_ca_sha256": ["a".repeat(64), "b".repeat(64)],
            "ca_bundle_pem": "-----BEGIN CERTIFICATE-----\n...\n",
        });
        let parsed = parse_trust_payload(&data).expect("parse trust payload");
        assert_eq!(parsed.trusted_ca_sha256.len(), 2);
        assert!(parsed.ca_bundle_pem.starts_with("-----BEGIN"));
    }

    #[test]
    fn parse_trust_payload_rejects_missing_bundle() {
        let data = serde_json::json!({ "trusted_ca_sha256": ["a".repeat(64)] });
        assert!(parse_trust_payload(&data).is_err());
    }

    #[test]
    fn parse_trust_payload_rejects_empty_fingerprints() {
        let data = serde_json::json!({
            "trusted_ca_sha256": [],
            "ca_bundle_pem": "pem",
        });
        assert!(parse_trust_payload(&data).is_err());
    }

    #[test]
    fn parse_trust_payload_rejects_non_hex_fingerprint() {
        let data = serde_json::json!({
            "trusted_ca_sha256": ["z".repeat(64)],
            "ca_bundle_pem": "pem",
        });
        assert!(parse_trust_payload(&data).is_err());
    }

    #[test]
    fn parse_trust_payload_rejects_short_fingerprint() {
        let data = serde_json::json!({
            "trusted_ca_sha256": ["abc"],
            "ca_bundle_pem": "pem",
        });
        assert!(parse_trust_payload(&data).is_err());
    }

    #[test]
    fn parse_secret_id_reads_canonical_key() {
        let data = serde_json::json!({ "secret_id": "  the-secret  " });
        assert_eq!(parse_secret_id(&data).expect("parse"), "the-secret");
    }

    #[test]
    fn parse_secret_id_falls_back_to_value_key() {
        let data = serde_json::json!({ "value": "fallback-secret" });
        assert_eq!(parse_secret_id(&data).expect("parse"), "fallback-secret");
    }

    #[test]
    fn parse_secret_id_rejects_missing() {
        let data = serde_json::json!({ "other": "x" });
        assert!(parse_secret_id(&data).is_err());
    }

    #[test]
    fn parse_secret_id_rejects_empty() {
        let data = serde_json::json!({ "secret_id": "   " });
        assert!(parse_secret_id(&data).is_err());
    }

    #[test]
    fn parse_responder_hmac_reads_hmac_key() {
        let data = serde_json::json!({ "hmac": "  the-hmac  " });
        assert_eq!(parse_responder_hmac(&data).expect("parse"), "the-hmac");
    }

    #[test]
    fn parse_responder_hmac_falls_back_to_value_key() {
        let data = serde_json::json!({ "value": "fallback-hmac" });
        assert_eq!(parse_responder_hmac(&data).expect("parse"), "fallback-hmac");
    }

    #[test]
    fn parse_responder_hmac_rejects_missing() {
        let data = serde_json::json!({ "other": "x" });
        assert!(parse_responder_hmac(&data).is_err());
    }

    #[test]
    fn parse_responder_hmac_rejects_empty() {
        let data = serde_json::json!({ "hmac": "   " });
        assert!(parse_responder_hmac(&data).is_err());
    }

    #[test]
    fn parse_eab_payload_accepts_populated() {
        let data = serde_json::json!({ "kid": "  the-kid  ", "hmac": "  the-hmac  " });
        assert_eq!(
            parse_eab_payload(&data).expect("parse populated"),
            EabPayload::Populated {
                kid: "the-kid".to_string(),
                hmac: "the-hmac".to_string(),
            }
        );
    }

    #[test]
    fn parse_eab_payload_accepts_explicit_clear() {
        let data = serde_json::json!({ "kid": "", "hmac": "" });
        assert_eq!(
            parse_eab_payload(&data).expect("parse clear"),
            EabPayload::Clear
        );
    }

    #[test]
    fn parse_eab_payload_treats_whitespace_only_as_clear() {
        let data = serde_json::json!({ "kid": "   ", "hmac": "   " });
        assert_eq!(
            parse_eab_payload(&data).expect("parse whitespace clear"),
            EabPayload::Clear
        );
    }

    #[test]
    fn parse_eab_payload_rejects_partial_kid_only() {
        let data = serde_json::json!({ "kid": "the-kid", "hmac": "" });
        assert!(parse_eab_payload(&data).is_err());
    }

    #[test]
    fn parse_eab_payload_rejects_partial_hmac_only() {
        let data = serde_json::json!({ "kid": "", "hmac": "the-hmac" });
        assert!(parse_eab_payload(&data).is_err());
    }

    #[test]
    fn parse_eab_payload_rejects_missing_key() {
        let data = serde_json::json!({ "kid": "the-kid" });
        assert!(parse_eab_payload(&data).is_err());
    }

    #[test]
    fn parse_eab_payload_rejects_non_string_value() {
        let data = serde_json::json!({ "kid": "the-kid", "hmac": 42 });
        assert!(parse_eab_payload(&data).is_err());
    }
}
