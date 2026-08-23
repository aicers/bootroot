//! Redacting wrappers for the secrets that configuration carries.
//!
//! An agent config is not a public artifact: it holds the HTTP-01
//! responder's shared HMAC and, where the deployment registered one, the
//! ACME external-account-binding HMAC. Both are bearer secrets — the
//! first authenticates a token placement at the responder, the second
//! authorises account creation at the CA — and both used to live in the
//! configuration types as bare `String`s under a `#[derive(Debug)]`.
//! That is one `tracing` field, one `{:?}` in an error context, one
//! `anyhow` chain away from printing them verbatim.
//!
//! Wrapping them here fixes that at the type, not at each of the places
//! that might print one: a `#[derive(Debug)]` on anything holding a
//! [`HmacSecret`] renders `<redacted>`, and the raw bytes are reachable
//! only through the deliberate [`HmacSecret::expose`].

use std::convert::Infallible;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A shared HMAC secret: the HTTP-01 responder key or an ACME
/// external-account-binding key.
///
/// `Debug` is hand-written and prints `<redacted>`, following the verb
/// layer's `WrappedSecretIdToken` and the internal credential's
/// `PrivateKeyPem`. It derives no `PartialEq` either, for the same
/// reason those do not: a derived comparison on a secret is a
/// byte-at-a-time timing oracle, and an HMAC is exactly the value a
/// caller would want to guess that way. Nothing in bootroot compares two
/// of these — a responder HMAC is proved by signing with it, and the EAB
/// HMAC by the CA accepting the binding.
///
/// `Serialize` is transparent because the on-disk `eab.json` and the
/// generated `agent.toml` must still carry the real value; redaction is
/// about the *rendered* forms — logs, traces, error chains — not about
/// the file the daemon reads back.
#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct HmacSecret(String);

impl HmacSecret {
    /// Wraps an HMAC at the boundary it enters the program: a parsed
    /// config, a CLI argument, an environment variable, a KV read.
    #[must_use]
    pub fn new(value: String) -> Self {
        Self(value)
    }

    /// Borrows the raw secret, for the signer, the account binder and
    /// the config writers that need the bytes themselves.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    /// Returns whether the secret is empty, so validation need not
    /// expose it to ask.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns whether the secret is empty once surrounding whitespace
    /// is ignored, so validation need not expose it to ask.
    #[must_use]
    pub fn is_blank(&self) -> bool {
        self.0.trim().is_empty()
    }
}

impl fmt::Debug for HmacSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl From<String> for HmacSecret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl From<&str> for HmacSecret {
    fn from(value: &str) -> Self {
        Self(value.to_string())
    }
}

impl FromStr for HmacSecret {
    type Err = Infallible;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(Self(value.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_redacts_the_secret() {
        let secret = HmacSecret::new("super-secret-hmac".to_string());
        assert_eq!(format!("{secret:?}"), "<redacted>");
        assert!(!format!("{secret:?}").contains("super-secret-hmac"));
    }

    #[test]
    fn debug_of_an_enclosing_derive_redacts_too() {
        #[derive(Debug)]
        struct Holder {
            // Read only through the `Debug` this test is about.
            #[allow(dead_code)]
            hmac: HmacSecret,
        }

        let rendered = format!(
            "{:?}",
            Holder {
                hmac: HmacSecret::from("super-secret-hmac"),
            }
        );
        assert!(!rendered.contains("super-secret-hmac"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn expose_returns_the_raw_bytes() {
        assert_eq!(
            HmacSecret::new("raw".to_string()).expose(),
            "raw",
            "the signer needs the value itself"
        );
    }

    #[test]
    fn serde_round_trips_transparently() {
        let json = serde_json::to_string(&HmacSecret::from("wire-value")).unwrap();
        assert_eq!(json, "\"wire-value\"");
        let back: HmacSecret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), "wire-value");
    }

    #[test]
    fn emptiness_is_answerable_without_exposing() {
        assert!(HmacSecret::from("").is_empty());
        assert!(HmacSecret::from("   ").is_blank());
        assert!(!HmacSecret::from("   ").is_empty());
        assert!(!HmacSecret::from("value").is_blank());
    }
}
