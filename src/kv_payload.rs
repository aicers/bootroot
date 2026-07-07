//! Shared parsers and validators for per-service `OpenBao` KV payloads.
//!
//! The `bootroot-remote bootstrap` / `apply-secret-id` paths and the remote
//! `bootroot-agent` fast-poll loop read the same KV paths
//! (`{kv_mount}/data/bootroot/services/<service>/{trust,secret_id}`). This
//! module owns one implementation of the payload validation so both callers
//! agree on shape, required fields, and fingerprint formatting. Callers that
//! need localized error text wrap these errors with their own context.

use anyhow::{Result, bail};

use crate::trust_bootstrap::{CA_BUNDLE_PEM_KEY, SECRET_ID_KEY, TRUSTED_CA_KEY};

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
}
