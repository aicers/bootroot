//! Shared parsers and validators for per-service `OpenBao` KV payloads.
//!
//! The `bootroot-remote bootstrap` / `apply-secret-id` paths and the remote
//! `bootroot-agent` fast-poll loop read the same KV paths
//! (`{kv_mount}/data/bootroot/services/<service>/{trust,secret_id}`). This
//! module owns one implementation of the payload validation so both callers
//! agree on shape, required fields, and fingerprint formatting. Callers that
//! need localized error text wrap these errors with their own context.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};

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
/// Beyond the shape checks, this verifies the payload is internally
/// consistent before any of it can reach disk: the `ca_bundle_pem` must
/// parse into at least one certificate, and every `trusted_ca_sha256`
/// fingerprint must match the SHA-256 of some certificate in that bundle.
/// The fingerprints and the bundle come from the same payload, so this is
/// consistency validation rather than independent authentication — but it
/// rejects non-PEM garbage, empty-certificate bundles, truncated writes,
/// and operator mistakes before the fast-poll trust-apply hook writes the
/// bundle to disk (issue #695).
///
/// # Errors
///
/// Returns an error when `trusted_ca_sha256` is missing, empty, or contains a
/// non-string / non-64-hex value, when `ca_bundle_pem` is missing or empty,
/// when `ca_bundle_pem` does not parse into at least one certificate, or when
/// a fingerprint does not match any certificate in the bundle.
pub fn parse_trust_payload(data: &serde_json::Value) -> Result<TrustPayload> {
    let trusted_ca_sha256 = parse_fingerprints(data)?;
    let ca_bundle_pem = parse_required_string(data, &[CA_BUNDLE_PEM_KEY])?;
    validate_bundle_consistency(&ca_bundle_pem, &trusted_ca_sha256)?;
    Ok(TrustPayload {
        trusted_ca_sha256,
        ca_bundle_pem,
    })
}

/// Verifies the CA bundle parses into certificates and that every pinned
/// fingerprint matches one of them.
///
/// # Errors
///
/// Returns an error when the bundle parses to zero certificates or when a
/// fingerprint is not present among the bundle certificates' SHA-256 hashes.
fn validate_bundle_consistency(ca_bundle_pem: &str, fingerprints: &[String]) -> Result<()> {
    let certs = crate::tls::parse_pem_to_cert_list(ca_bundle_pem.as_bytes())
        .context("trust payload ca_bundle_pem is not a valid certificate bundle")?;
    let present: HashSet<String> = certs
        .iter()
        .map(|cert| crate::tls::sha256_hex(cert.as_ref()))
        .collect();
    for fingerprint in fingerprints {
        if !present.contains(&fingerprint.to_ascii_lowercase()) {
            bail!(
                "trust payload {TRUSTED_CA_KEY} entry {fingerprint} does not match any \
                 certificate in ca_bundle_pem"
            );
        }
    }
    Ok(())
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
/// The clear shape must NOT be routed through `parse_required_string`: that
/// helper trims and rejects empty strings, which would misclassify a clear as
/// malformed and prevent it from ever applying. The KV payload keys the secret
/// as `hmac` (distinct from the `key` alias that `eab.json` also accepts for
/// interop with step-ca's native EAB field name).
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

    /// Generates a self-signed CA certificate, returning its PEM and the
    /// lowercase hex SHA-256 of its DER (the `trusted_ca_sha256` form).
    fn generate_ca_cert() -> (String, String) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        let key = KeyPair::generate().expect("generate CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, "Bootroot Test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-signed cert");
        let fingerprint = crate::tls::sha256_hex(cert.der().as_ref());
        (cert.pem(), fingerprint)
    }

    #[test]
    fn parse_trust_payload_accepts_valid_values() {
        let (pem_a, fp_a) = generate_ca_cert();
        let (pem_b, fp_b) = generate_ca_cert();
        let data = serde_json::json!({
            "trusted_ca_sha256": [fp_a, fp_b],
            "ca_bundle_pem": format!("{pem_a}{pem_b}"),
        });
        let parsed = parse_trust_payload(&data).expect("parse trust payload");
        assert_eq!(parsed.trusted_ca_sha256.len(), 2);
        assert!(parsed.ca_bundle_pem.contains("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn parse_trust_payload_accepts_uppercase_fingerprint() {
        let (pem, fp) = generate_ca_cert();
        let data = serde_json::json!({
            "trusted_ca_sha256": [fp.to_ascii_uppercase()],
            "ca_bundle_pem": pem,
        });
        assert!(parse_trust_payload(&data).is_ok());
    }

    #[test]
    fn parse_trust_payload_rejects_non_pem_bundle() {
        let (_, fp) = generate_ca_cert();
        let data = serde_json::json!({
            "trusted_ca_sha256": [fp],
            "ca_bundle_pem": "this is not a certificate bundle",
        });
        assert!(parse_trust_payload(&data).is_err());
    }

    #[test]
    fn parse_trust_payload_rejects_bundle_with_no_certificates() {
        // A syntactically valid PEM that carries no CERTIFICATE entries
        // parses to zero certs and must be rejected.
        let (_, fp) = generate_ca_cert();
        let data = serde_json::json!({
            "trusted_ca_sha256": [fp],
            "ca_bundle_pem": "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----\n",
        });
        assert!(parse_trust_payload(&data).is_err());
    }

    #[test]
    fn parse_trust_payload_rejects_fingerprint_absent_from_bundle() {
        let (pem, _) = generate_ca_cert();
        let data = serde_json::json!({
            // A well-formed but unrelated fingerprint.
            "trusted_ca_sha256": ["a".repeat(64)],
            "ca_bundle_pem": pem,
        });
        assert!(parse_trust_payload(&data).is_err());
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
