//! Provides header parsing, timestamp checks, and HMAC verification helpers.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use bootroot::acme::http01_protocol::signature_payload;
use poem::Request;
use ring::hmac;

pub(super) fn header_value(req: &Request, key: &str) -> Result<String, String> {
    req.headers()
        .get(key)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .ok_or_else(|| format!("Missing header: {key}"))
}

pub(super) fn within_skew(timestamp: i64, max_skew_secs: u64) -> bool {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => match i64::try_from(value.as_secs()) {
            Ok(secs) => secs,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    (now - timestamp).unsigned_abs() <= max_skew_secs
}

pub(super) fn payload_for_request(
    timestamp: i64,
    token: &str,
    key_authorization: &str,
    ttl_secs: u64,
) -> String {
    signature_payload(timestamp, token, key_authorization, ttl_secs)
}

pub(super) fn verify_signature(key: &hmac::Key, signature: &str, payload: &str) -> bool {
    let Ok(decoded) = STANDARD.decode(signature.as_bytes()) else {
        return false;
    };
    hmac::verify(key, payload.as_bytes(), &decoded).is_ok()
}

#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use super::*;

    #[test]
    fn test_signature_verification_round_trip() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"test-secret");
        let payload = payload_for_request(123, "token", "key-auth", 60);
        let signature = STANDARD.encode(hmac::sign(&key, payload.as_bytes()).as_ref());

        assert!(verify_signature(&key, &signature, &payload));
        assert!(!verify_signature(&key, "invalid", &payload));
    }

    #[test]
    fn test_within_skew_rejects_out_of_range() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time must be after UNIX_EPOCH")
            .as_secs();
        let now = i64::try_from(now).expect("System time must fit in i64");

        assert!(within_skew(now, 60));
        assert!(!within_skew(now - 3600, 60));
    }
}
