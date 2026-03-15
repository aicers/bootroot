//! Shared constants and helpers for the HTTP-01 responder HMAC protocol.
//!
//! Both the library client (`acme::responder_client`) and the standalone
//! responder binary (`bootroot-http01-responder`) must agree on header
//! names and payload format.  Keeping them in one place prevents silent
//! protocol divergence.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ring::hmac;

pub const HEADER_TIMESTAMP: &str = "x-bootroot-timestamp";
pub const HEADER_SIGNATURE: &str = "x-bootroot-signature";

/// Encapsulates HMAC signing and verification for HTTP-01 registration.
#[derive(Clone)]
pub struct Http01HmacSigner {
    key: hmac::Key,
}

impl Http01HmacSigner {
    /// Creates a signer for the shared HTTP-01 responder HMAC protocol.
    #[must_use]
    pub fn new(secret: &str) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes()),
        }
    }

    /// Signs a canonical HTTP-01 registration payload.
    #[must_use]
    pub fn sign_payload(&self, payload: &str) -> String {
        let tag = hmac::sign(&self.key, payload.as_bytes());
        STANDARD.encode(tag.as_ref())
    }

    /// Signs a full HTTP-01 registration request.
    #[must_use]
    pub fn sign_request(
        &self,
        timestamp: i64,
        token: &str,
        key_authorization: &str,
        ttl_secs: u64,
    ) -> String {
        let payload = signature_payload(timestamp, token, key_authorization, ttl_secs);
        self.sign_payload(&payload)
    }

    /// Verifies a canonical HTTP-01 registration payload.
    #[must_use]
    pub fn verify_payload(&self, signature: &str, payload: &str) -> bool {
        let Ok(decoded) = STANDARD.decode(signature.as_bytes()) else {
            return false;
        };
        hmac::verify(&self.key, payload.as_bytes(), &decoded).is_ok()
    }

    /// Verifies a full HTTP-01 registration request.
    #[must_use]
    pub fn verify_request(
        &self,
        signature: &str,
        timestamp: i64,
        token: &str,
        key_authorization: &str,
        ttl_secs: u64,
    ) -> bool {
        let payload = signature_payload(timestamp, token, key_authorization, ttl_secs);
        self.verify_payload(signature, &payload)
    }
}

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
        let signer = Http01HmacSigner::new("test-secret");
        let payload = signature_payload(123, "token", "key-auth", 60);
        let signature = signer.sign_payload(&payload);
        assert!(signer.verify_payload(&signature, &payload));
        assert!(!signer.verify_payload("invalid", &payload));
    }

    #[test]
    fn request_round_trip_sign_verify() {
        let signer = Http01HmacSigner::new("test-secret");
        let signature = signer.sign_request(123, "token", "key-auth", 60);
        assert!(signer.verify_request(&signature, 123, "token", "key-auth", 60));
        assert!(!signer.verify_request(&signature, 124, "token", "key-auth", 60));
    }
}
