//! The bounded wrap-TTL policy the mint verb grants under.
//!
//! The requested `wrap_ttl` is the one lifetime a caller gets to
//! influence, and it is influence rather than choice: the policy is fixed
//! at construction, the request never selects it, and what is granted is
//! `min(requested, maximum)`. Everything else about the credential —
//! the secret-id options, the role-level TTLs — is a construction
//! dependency the request cannot reach at all.
//!
//! Validation happens **before** any `OpenBao` call, so a request that
//! cannot produce a usable duration never reaches the wrapping endpoint
//! and never creates a `secret_id` that would then have to be revoked.

use std::fmt;

use time::Duration;

/// The wrap TTL a request asked for, refused before any `OpenBao` call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum WrapTtlRefusal {
    /// The request asked for zero. A wrapping token that expires on
    /// creation delivers nothing, so it is refused rather than clamped
    /// up to some floor the caller did not ask for.
    #[error("requested wrap_ttl is zero")]
    Zero,
    /// The request asked for a negative duration.
    #[error("requested wrap_ttl is negative")]
    Negative,
    /// The request's duration cannot be written as an `OpenBao` duration
    /// string: `OpenBao` counts whole seconds, so a sub-second remainder
    /// has no representation and truncating it would grant a lifetime
    /// nobody chose.
    #[error("requested wrap_ttl is not a whole number of seconds")]
    NotWholeSeconds,
}

/// A validated, clamped wrap TTL and the `OpenBao` duration string it is
/// spelled with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GrantedWrapTtl {
    duration: Duration,
    openbao: String,
}

impl GrantedWrapTtl {
    /// Returns the granted duration.
    pub(crate) fn duration(&self) -> Duration {
        self.duration
    }

    /// Returns the `OpenBao` duration string for the granted duration.
    pub(crate) fn as_openbao_str(&self) -> &str {
        &self.openbao
    }
}

impl fmt::Display for GrantedWrapTtl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.openbao)
    }
}

/// The registrar's bounded wrap-TTL policy: a maximum plus the rules a
/// requested value is validated under.
///
/// Constructed once, at the verb service's construction, and never
/// selected by a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WrapTtlPolicy {
    maximum: Duration,
    maximum_openbao: String,
}

impl WrapTtlPolicy {
    /// Creates a policy with `maximum` as its ceiling.
    ///
    /// The maximum is held to the same rules a request is: it has to be
    /// a positive whole number of seconds, or nothing it clamps to could
    /// be spelled for `OpenBao`.
    ///
    /// # Errors
    ///
    /// Returns the [`WrapTtlRefusal`] the maximum itself fails.
    pub(crate) fn new(maximum: Duration) -> Result<Self, WrapTtlRefusal> {
        let openbao = openbao_duration(maximum)?;
        Ok(Self {
            maximum,
            maximum_openbao: openbao,
        })
    }

    /// Returns the ceiling this policy grants under.
    pub(crate) fn maximum(&self) -> Duration {
        self.maximum
    }

    /// Validates `requested` and returns the granted wrap TTL,
    /// `min(requested, maximum)`.
    ///
    /// # Errors
    ///
    /// Returns [`WrapTtlRefusal`] for a zero, negative or
    /// non-whole-second request. A request *larger* than the maximum is
    /// not a refusal — it is clamped, which is exactly what the wire
    /// contract's "the registrar MAY clamp it" means and why the granted
    /// deadline is computed rather than echoed.
    pub(crate) fn grant(&self, requested: Duration) -> Result<GrantedWrapTtl, WrapTtlRefusal> {
        let requested_openbao = openbao_duration(requested)?;
        if requested <= self.maximum {
            Ok(GrantedWrapTtl {
                duration: requested,
                openbao: requested_openbao,
            })
        } else {
            Ok(GrantedWrapTtl {
                duration: self.maximum,
                openbao: self.maximum_openbao.clone(),
            })
        }
    }
}

/// Renders a duration as an `OpenBao` duration string, refusing every
/// value that has no such spelling.
fn openbao_duration(value: Duration) -> Result<String, WrapTtlRefusal> {
    if value.is_negative() {
        return Err(WrapTtlRefusal::Negative);
    }
    if value.is_zero() {
        return Err(WrapTtlRefusal::Zero);
    }
    if value.subsec_nanoseconds() != 0 {
        return Err(WrapTtlRefusal::NotWholeSeconds);
    }
    let seconds = value.whole_seconds();
    // `is_negative` and `is_zero` above leave only positive values, and
    // `subsec_nanoseconds` is zero, so the whole-second count is at
    // least one and the conversion cannot fail.
    let seconds = u64::try_from(seconds).map_err(|_| WrapTtlRefusal::NotWholeSeconds)?;
    Ok(format!("{seconds}s"))
}
