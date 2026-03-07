//! Shared constants and helpers for the HTTP-01 responder HMAC protocol.
//!
//! Both the library client (`acme::responder_client`) and the standalone
//! responder binary (`bootroot-http01-responder`) must agree on header
//! names and payload format.  Keeping them in one place prevents silent
//! protocol divergence.

pub const HEADER_TIMESTAMP: &str = "x-bootroot-timestamp";
pub const HEADER_SIGNATURE: &str = "x-bootroot-signature";

/// Builds the canonical payload that is HMAC-signed for token registration.
///
/// The format is `{timestamp}.{token}.{key_authorization}.{ttl_secs}`.
#[must_use]
pub fn signature_payload(
    timestamp: i64,
    token: &str,
    key_authorization: &str,
    ttl_secs: u64,
) -> String {
    format!("{timestamp}.{token}.{key_authorization}.{ttl_secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_format_is_dot_separated() {
        let payload = signature_payload(1_700_000_000, "tok", "auth", 60);
        assert_eq!(payload, "1700000000.tok.auth.60");
    }

    #[test]
    fn payload_round_trip_sign_verify() {
        use base64::Engine;
        use base64::engine::general_purpose::STANDARD;
        use ring::hmac;

        let key = hmac::Key::new(hmac::HMAC_SHA256, b"test-secret");
        let payload = signature_payload(123, "token", "key-auth", 60);
        let sig = STANDARD.encode(hmac::sign(&key, payload.as_bytes()).as_ref());
        let decoded = STANDARD.decode(sig.as_bytes()).expect("valid base64");
        assert!(hmac::verify(&key, payload.as_bytes(), &decoded).is_ok());
    }
}
