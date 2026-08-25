//! The versioned JSON payload protocol for the registrar endpoint.
//!
//! This module owns only the payload boundary.  It deliberately knows
//! nothing about the listener, audit store, limiter, or certificate state:
//! callers decode a request before invoking a verb and hand a health snapshot
//! back when encoding a response.

// The production handler that calls this codec is deliberately a sibling
// issue. Until it lands, these crate-private protocol types are necessarily
// unused outside their focused tests.
#![allow(dead_code)]

use std::fmt;

use base64::Engine as _;
use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;
use time::OffsetDateTime;

use super::frame::Operation;
use crate::kv_payload::{TrustPayload, parse_trust_payload};
use crate::registrar::audit::AuditPhase;
#[cfg(test)]
use crate::registrar::audit::AuditStoreError;
use crate::registrar::error::RegistrarError;
#[cfg(test)]
use crate::registrar::identity::{derive_registration_id, validate_request_labels};
#[cfg(test)]
use crate::registrar::verbs::outcome::{
    CallerIdentity, ProducingArm, RequestId, VerbContext, WrappedSecretIdToken,
};
use crate::registrar::verbs::outcome::{
    DeregisterKind, DeregisterOutcome, MintKind, MintOutcome, VerbError, VerbRefusal,
};
use crate::registrar::verbs::wrap_ttl::WrapTtlRefusal;
#[cfg(test)]
use crate::service_material::TeardownReport;

/// The sole payload version this daemon implements.
pub(crate) const PROTOCOL_VERSION: u32 = 1;

/// A payload protocol version accepted by this build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProtocolVersion;

impl ProtocolVersion {
    /// Returns the version this build speaks.
    pub(crate) const fn current() -> Self {
        Self
    }
}

impl Serialize for ProtocolVersion {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(PROTOCOL_VERSION)
    }
}

impl<'de> Deserialize<'de> for ProtocolVersion {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ProtocolVersionVisitor;

        impl Visitor<'_> for ProtocolVersionVisitor {
            type Value = ProtocolVersion;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "protocol version {PROTOCOL_VERSION}")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == u64::from(PROTOCOL_VERSION) {
                    Ok(ProtocolVersion::current())
                } else {
                    Err(E::invalid_value(de::Unexpected::Unsigned(value), &self))
                }
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(E::invalid_value(de::Unexpected::Signed(value), &self))
            }
        }

        deserializer.deserialize_u64(ProtocolVersionVisitor)
    }
}

/// A request's externally owned delivery mode spelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum WireDeliveryMode {
    /// Material is placed on the host out of band.
    LocalFile,
    /// Material is consumed by `bootroot-remote` bootstrap.
    RemoteBootstrap,
}

/// The externally owned service specification carried without interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct WireServiceSpec {
    pub(crate) component: String,
    pub(crate) service_name: String,
    pub(crate) reload: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "reject_null_option::deserialize"
    )]
    pub(crate) cert_group: Option<String>,
}

/// The register request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RegisterRequest {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) service_name: String,
    pub(crate) delivery_mode: WireDeliveryMode,
    pub(crate) host: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "reject_null_option::deserialize"
    )]
    pub(crate) instance: Option<u32>,
    pub(crate) spec: WireServiceSpec,
    pub(crate) wrap_ttl: u64,
    pub(crate) idempotency_key: String,
}

/// The deregister request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DeregisterRequest {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) service_name: String,
    pub(crate) host: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "reject_null_option::deserialize"
    )]
    pub(crate) instance: Option<u32>,
    pub(crate) idempotency_key: String,
}

/// A request decoded according to the endpoint operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Request {
    /// A mint request.
    Register(RegisterRequest),
    /// A deregister request.
    Deregister(DeregisterRequest),
}

/// A payload codec failure.
#[derive(Debug, Error)]
pub(crate) enum CodecError {
    /// JSON did not match the selected payload shape.
    #[error("registrar protocol JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    /// `ca_anchor` was not standard base64.
    #[error("registrar ca_anchor is not standard base64: {0}")]
    Base64(#[from] base64::DecodeError),
    /// A time value could not use the required RFC 3339 UTC representation.
    #[error("registrar timestamp is not RFC 3339 UTC: {0}")]
    Timestamp(String),
    /// The anchor bytes were not the canonical trust-payload framing.
    #[error("registrar ca_anchor is invalid: {0}")]
    TrustPayload(String),
    /// A verb outcome reached the endpoint without its required derived id.
    #[error("registrar outcome is missing registration_id")]
    MissingRegistrationId,
    /// A refusal's class did not match the contract for its error form.
    #[error("registrar refusal has an invalid class: {0}")]
    InvalidRefusalClass(String),
}

/// Decodes an endpoint request after its operation has been authenticated.
///
/// The frame's operation, not the payload's members, selects the shape: a mint
/// frame decodes only as a [`RegisterRequest`] and a deregistration frame only
/// as a [`DeregisterRequest`].  Every member the selected shape does not name
/// is an unknown member and is ignored, including one the other operation
/// knows, so an additive extension on either shape cannot make the other
/// shape's decoder fail.
pub(crate) fn decode_request(operation: Operation, payload: &[u8]) -> Result<Request, CodecError> {
    match operation {
        Operation::Mint => serde_json::from_slice(payload)
            .map(Request::Register)
            .map_err(Into::into),
        Operation::Deregister => serde_json::from_slice(payload)
            .map(Request::Deregister)
            .map_err(Into::into),
    }
}

/// Encodes a request in the canonical member order.
pub(crate) fn encode_request(request: &Request) -> Result<Vec<u8>, CodecError> {
    match request {
        Request::Register(request) => serde_json::to_vec(request),
        Request::Deregister(request) => serde_json::to_vec(request),
    }
    .map_err(Into::into)
}

/// The endpoint-local class a caller uses when handling a refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RefusalClass {
    /// A caller may retry the request.
    Retryable,
    /// An operator must correct the underlying condition.
    Permanent,
}

/// The closed externally owned `RegistrarUnavailable` reason set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RegistrarUnavailableReason {
    CredentialInvalid,
    NotProvisioned,
    AuditUnwritable,
    EndpointUnreachable,
    PostMintUnrecordable,
    RegistrarUnreachable,
}

/// The closed externally owned typed error identifier set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "id")]
pub(crate) enum EnrollError {
    ServiceSpecConflict,
    ServiceNameCollision,
    ServiceInstanceMismatch,
    ServiceHostMismatch,
    RegistrarUnavailable { reason: RegistrarUnavailableReason },
    RegistrarBusy { retry_after: u64 },
    ServiceLabelInvalid,
}

/// A snapshot of registrar health supplied by the response caller.
///
/// This container is the single place future endpoint signals are added.
/// Three members are reserved and each already has an owner: `certificates`
/// is populated by #769, `limiter` by #787, and `audit_capacity` by #774.
/// Recording the owners fixes neither a member schema nor a value; the
/// container is intentionally empty, and serializes as `{}`, until each owner
/// adds its own member.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RegistrarHealth {
    // Kept private and skipped so `Default` is the only in-crate way to create
    // the empty v1 snapshot, while its wire representation remains `{}`.
    #[serde(skip)]
    _constructor: RegistrarHealthConstructor,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RegistrarHealthConstructor;

/// A response-wrapping token carried only at the serialization boundary.
///
/// This stays distinct from an ordinary string because a wrapping token can be
/// used to obtain a secret once. Its wire representation remains a JSON string
/// while diagnostics redact it.
#[derive(Serialize, Deserialize)]
#[serde(transparent)]
struct WrappedSecretId(String);

impl WrappedSecretId {
    fn new(value: String) -> Self {
        Self(value)
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for WrappedSecretId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted>")
    }
}

/// Bootstrap material encoded for a mint response.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct BootstrapMaterial {
    pub(crate) role_id: String,
    wrapped_secret_id: WrappedSecretId,
    pub(crate) ca_anchor: String,
    #[serde(with = "rfc3339")]
    pub(crate) expires_at: OffsetDateTime,
}

/// A successful mint response.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct MintResponse {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) request_id: String,
    pub(crate) registration_id: String,
    pub(crate) outcome: MintWireOutcome,
    pub(crate) material: BootstrapMaterial,
    pub(crate) registrar_health: RegistrarHealth,
}

/// The wire outcome of a successful mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum MintWireOutcome {
    FirstMint,
    IdempotentRemint,
}

/// A successful deregister response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DeregisterResponse {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) request_id: String,
    pub(crate) registration_id: String,
    pub(crate) outcome: DeregisterWireOutcome,
    pub(crate) registrar_health: RegistrarHealth,
}

/// The wire outcome of a successful deregister.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DeregisterWireOutcome {
    Removed,
    AlreadyAbsent,
}

/// A refused invocation response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RefusalResponse {
    pub(crate) protocol_version: ProtocolVersion,
    pub(crate) request_id: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "reject_null_option::deserialize"
    )]
    pub(crate) registration_id: Option<String>,
    pub(crate) class: RefusalClass,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "reject_null_option::deserialize"
    )]
    pub(crate) error: Option<EnrollError>,
    pub(crate) registrar_health: RegistrarHealth,
}

/// Decodes and validates a mint response from the registrar endpoint.
pub(crate) fn decode_mint_response(payload: &[u8]) -> Result<MintResponse, CodecError> {
    let response = serde_json::from_slice::<MintResponse>(payload)?;
    decode_ca_anchor(response.material.ca_anchor.as_str())?;
    Ok(response)
}

/// Decodes a deregister response from the registrar endpoint.
pub(crate) fn decode_deregister_response(payload: &[u8]) -> Result<DeregisterResponse, CodecError> {
    serde_json::from_slice(payload).map_err(Into::into)
}

/// Decodes a refusal response from the registrar endpoint.
pub(crate) fn decode_refusal_response(payload: &[u8]) -> Result<RefusalResponse, CodecError> {
    let response = serde_json::from_slice::<RefusalResponse>(payload)?;
    validate_refusal_class(response.class, response.error.as_ref())?;
    Ok(response)
}

/// Encodes a mint outcome with the supplied anchor and health snapshot.
pub(crate) fn encode_mint_response(
    outcome: MintOutcome,
    anchor: &TrustPayload,
    health: &RegistrarHealth,
) -> Result<Vec<u8>, CodecError> {
    let expires_at = outcome.expires_at().to_offset(time::UtcOffset::UTC);
    let registration_id = outcome
        .context()
        .registration_id()
        .ok_or(CodecError::MissingRegistrationId)?
        .to_string();
    let response = MintResponse {
        protocol_version: ProtocolVersion::current(),
        request_id: outcome.context().request_id().as_str().to_string(),
        registration_id,
        outcome: match outcome.kind() {
            MintKind::FirstMint => MintWireOutcome::FirstMint,
            MintKind::IdempotentReMint => MintWireOutcome::IdempotentRemint,
        },
        material: BootstrapMaterial {
            role_id: outcome.role_id().to_string(),
            wrapped_secret_id: WrappedSecretId::new(outcome.into_wrapped_secret_id()),
            ca_anchor: encode_ca_anchor(anchor)?,
            expires_at,
        },
        registrar_health: health.clone(),
    };
    serde_json::to_vec(&response).map_err(Into::into)
}

/// Encodes a deregister outcome with the supplied health snapshot.
pub(crate) fn encode_deregister_response(
    outcome: &DeregisterOutcome,
    health: &RegistrarHealth,
) -> Result<Vec<u8>, CodecError> {
    let registration_id = outcome
        .context()
        .registration_id()
        .ok_or(CodecError::MissingRegistrationId)?
        .to_string();
    let response = DeregisterResponse {
        protocol_version: ProtocolVersion::current(),
        request_id: outcome.context().request_id().as_str().to_string(),
        registration_id,
        outcome: match outcome.kind() {
            DeregisterKind::IdentityRemoved => DeregisterWireOutcome::Removed,
            DeregisterKind::AlreadyAbsent => DeregisterWireOutcome::AlreadyAbsent,
        },
        registrar_health: health.clone(),
    };
    serde_json::to_vec(&response).map_err(Into::into)
}

/// Encodes a verb refusal with the supplied health snapshot.
pub(crate) fn encode_refusal_response(
    refusal: &VerbRefusal,
    health: &RegistrarHealth,
) -> Result<Vec<u8>, CodecError> {
    let (class, error) = map_refusal(refusal.error());
    encode_refusal(
        refusal.context().request_id().as_str(),
        refusal.context().registration_id(),
        class,
        error,
        health,
    )
}

fn encode_refusal(
    request_id: &str,
    registration_id: Option<&str>,
    class: RefusalClass,
    error: Option<EnrollError>,
    health: &RegistrarHealth,
) -> Result<Vec<u8>, CodecError> {
    validate_refusal_class(class, error.as_ref())?;
    let response = RefusalResponse {
        protocol_version: ProtocolVersion::current(),
        request_id: request_id.to_string(),
        registration_id: registration_id.map(str::to_string),
        class,
        error,
        registrar_health: health.clone(),
    };
    serde_json::to_vec(&response).map_err(Into::into)
}

fn validate_refusal_class(
    class: RefusalClass,
    error: Option<&EnrollError>,
) -> Result<(), CodecError> {
    let expected = match error {
        Some(EnrollError::RegistrarBusy { .. }) | None => RefusalClass::Retryable,
        Some(
            EnrollError::ServiceSpecConflict
            | EnrollError::ServiceNameCollision
            | EnrollError::ServiceInstanceMismatch
            | EnrollError::ServiceHostMismatch
            | EnrollError::RegistrarUnavailable { .. }
            | EnrollError::ServiceLabelInvalid,
        ) => RefusalClass::Permanent,
    };
    if class == expected {
        Ok(())
    } else {
        Err(CodecError::InvalidRefusalClass(format!(
            "{class:?} does not match {error:?}"
        )))
    }
}

/// Maps every verb-layer refusal onto its caller-visible representation.
// Each internal variant has its own arm so additions cannot silently inherit
// the unclassified wire form, even where two current arms return the same form.
//
// The registrar's own rate-limit refusal is the row the reference records as
// the future assignment: `VerbError::Throttled` maps to retryable
// `RegistrarBusy { retry_after }`, in whole seconds, carrying the value the
// limiter's admission bucket produced. The variant and this arm landed
// together, because neither builds without the other — the mapping is
// exhaustive and wildcard-free, so an arm ahead of the variant would be
// unreachable and a variant ahead of the arm would not compile. It routes to
// an identifier, class and fixture that already existed and introduces none
// of its own.
//
// Both `AuditUnwritable` phases map onto the one transcribed
// `AuditUnwritable` reason. The reference's §6.5 row transcribes the
// source's intent-phase condition; a non-mutating outcome-phase failure
// presents the same caller-visible facts — nothing minted, no teardown
// owed, the audit store unwritable — where `PostMintUnrecordable` would
// falsely owe a teardown and the unclassified form would drop the
// audit-store signal. The locally owned half of the reference records this
// producer set.
#[allow(clippy::match_same_arms)]
#[allow(clippy::too_many_lines)]
fn map_refusal(error: &VerbError) -> (RefusalClass, Option<EnrollError>) {
    match error {
        VerbError::ReservedServiceName { .. } => (RefusalClass::Retryable, None),
        VerbError::Registrar(error) => match error {
            RegistrarError::ConfigUnreadable { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::NotProvisioned,
                }),
            ),
            RegistrarError::FingerprintLineMalformed { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::NotProvisioned,
                }),
            ),
            RegistrarError::FingerprintMismatch { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::NotProvisioned,
                }),
            ),
            RegistrarError::ConfigMalformed { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::NotProvisioned,
                }),
            ),
            RegistrarError::UnsupportedSchemaVersion { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::NotProvisioned,
                }),
            ),
            RegistrarError::UnknownMultiplicity { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::NotProvisioned,
                }),
            ),
            RegistrarError::UnknownReloadKind { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::NotProvisioned,
                }),
            ),
            RegistrarError::InvalidReloadTarget { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::NotProvisioned,
                }),
            ),
            RegistrarError::InvalidDomain { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::NotProvisioned,
                }),
            ),
            RegistrarError::InvalidComponentKey { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::RegistrarUnavailable {
                    reason: RegistrarUnavailableReason::NotProvisioned,
                }),
            ),
            RegistrarError::InvalidServiceName { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::ServiceLabelInvalid),
            ),
            RegistrarError::InvalidHost { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::ServiceLabelInvalid),
            ),
            RegistrarError::ComponentNotConfigured { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::ServiceInstanceMismatch),
            ),
            RegistrarError::ServiceInstanceMismatch { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::ServiceInstanceMismatch),
            ),
            RegistrarError::DerivedKeyInvalid { .. } => (RefusalClass::Retryable, None),
            RegistrarError::SpecIdentityDisagreement { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::ServiceSpecConflict),
            ),
            RegistrarError::ServiceSpecOutsideSafeSet { .. } => (
                RefusalClass::Permanent,
                Some(EnrollError::ServiceSpecConflict),
            ),
        },
        VerbError::RegistrationIdCollision { .. } => (
            RefusalClass::Permanent,
            Some(EnrollError::ServiceNameCollision),
        ),
        VerbError::StoredSpecConflict { .. } => (
            RefusalClass::Permanent,
            Some(EnrollError::ServiceSpecConflict),
        ),
        VerbError::HostMismatch { .. } => (
            RefusalClass::Permanent,
            Some(EnrollError::ServiceHostMismatch),
        ),
        VerbError::InvalidWrapTtl(WrapTtlRefusal::Zero) => (RefusalClass::Retryable, None),
        VerbError::InvalidWrapTtl(WrapTtlRefusal::Negative) => (RefusalClass::Retryable, None),
        VerbError::InvalidWrapTtl(WrapTtlRefusal::NotWholeSeconds) => {
            (RefusalClass::Retryable, None)
        }
        VerbError::InvalidWrapTtl(WrapTtlRefusal::ExceedsOpenBaoRange) => {
            (RefusalClass::Retryable, None)
        }
        VerbError::AuditUnwritable {
            phase: AuditPhase::Intent,
            ..
        } => (
            RefusalClass::Permanent,
            Some(EnrollError::RegistrarUnavailable {
                reason: RegistrarUnavailableReason::AuditUnwritable,
            }),
        ),
        VerbError::AuditUnwritable {
            phase: AuditPhase::Outcome,
            ..
        } => (
            RefusalClass::Permanent,
            Some(EnrollError::RegistrarUnavailable {
                reason: RegistrarUnavailableReason::AuditUnwritable,
            }),
        ),
        VerbError::PostMintUnrecordable { .. } => (
            RefusalClass::Permanent,
            Some(EnrollError::RegistrarUnavailable {
                reason: RegistrarUnavailableReason::PostMintUnrecordable,
            }),
        ),
        VerbError::Throttled { retry_after } => (
            RefusalClass::Retryable,
            Some(EnrollError::RegistrarBusy {
                retry_after: *retry_after,
            }),
        ),
        VerbError::Unavailable { .. } => (RefusalClass::Retryable, None),
    }
}

/// Encodes a trust payload as the `ca_anchor` member.
pub(crate) fn encode_ca_anchor(payload: &TrustPayload) -> Result<String, CodecError> {
    validate_trust_payload(payload)?;
    let framed = WireTrustPayload {
        trusted_ca_sha256: &payload.trusted_ca_sha256,
        ca_bundle_pem: &payload.ca_bundle_pem,
    };
    let bytes = serde_json::to_vec(&framed)?;
    Ok(base64::engine::general_purpose::STANDARD.encode(bytes))
}

/// Decodes and validates a `ca_anchor` member into the shared trust payload.
pub(crate) fn decode_ca_anchor(anchor: &str) -> Result<TrustPayload, CodecError> {
    let bytes = base64::engine::general_purpose::STANDARD.decode(anchor)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let object = value.as_object().ok_or_else(|| {
        CodecError::TrustPayload("decoded ca_anchor must be a JSON object".to_string())
    })?;
    if object.len() != 2
        || !object.contains_key("trusted_ca_sha256")
        || !object.contains_key("ca_bundle_pem")
    {
        return Err(CodecError::TrustPayload(
            "decoded ca_anchor has members other than trusted_ca_sha256 and ca_bundle_pem"
                .to_string(),
        ));
    }
    parse_trust_payload(&value).map_err(|error| CodecError::TrustPayload(error.to_string()))?;
    let wire_payload: DecodedWireTrustPayload = serde_json::from_value(value.clone())?;
    let payload = TrustPayload {
        trusted_ca_sha256: wire_payload.trusted_ca_sha256,
        ca_bundle_pem: wire_payload.ca_bundle_pem,
    };
    validate_trust_payload(&payload)?;
    let canonical = serde_json::to_vec(&WireTrustPayload {
        trusted_ca_sha256: &payload.trusted_ca_sha256,
        ca_bundle_pem: &payload.ca_bundle_pem,
    })?;
    if bytes != canonical {
        return Err(CodecError::TrustPayload(
            "decoded ca_anchor is not canonical compact JSON".to_string(),
        ));
    }
    Ok(payload)
}

#[derive(Serialize)]
struct WireTrustPayload<'a> {
    trusted_ca_sha256: &'a [String],
    ca_bundle_pem: &'a str,
}

#[derive(Deserialize)]
struct DecodedWireTrustPayload {
    trusted_ca_sha256: Vec<String>,
    ca_bundle_pem: String,
}

fn validate_trust_payload(payload: &TrustPayload) -> Result<(), CodecError> {
    if payload.trusted_ca_sha256.is_empty() || payload.ca_bundle_pem.is_empty() {
        return Err(CodecError::TrustPayload(
            "trusted_ca_sha256 and ca_bundle_pem must be non-empty".to_string(),
        ));
    }
    if payload.ca_bundle_pem.contains('\r')
        || !payload.ca_bundle_pem.ends_with('\n')
        || payload.ca_bundle_pem.ends_with("\n\n")
    {
        return Err(CodecError::TrustPayload(
            "ca_bundle_pem must use LF line endings and end with exactly one LF".to_string(),
        ));
    }
    let certificates = crate::tls::parse_pem_to_cert_list(payload.ca_bundle_pem.as_bytes())
        .map_err(|error| CodecError::TrustPayload(error.to_string()))?;
    if certificates.len() != payload.trusted_ca_sha256.len() {
        return Err(CodecError::TrustPayload(
            "trusted_ca_sha256 must contain one fingerprint per certificate".to_string(),
        ));
    }
    for (fingerprint, certificate) in payload.trusted_ca_sha256.iter().zip(certificates.iter()) {
        if fingerprint.len() != 64
            || !fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || fingerprint != &crate::tls::sha256_hex(certificate.as_ref())
        {
            return Err(CodecError::TrustPayload(
                "trusted_ca_sha256 must be lowercase and positionally match ca_bundle_pem"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

mod rfc3339 {
    use serde::{Deserialize as _, Deserializer, Serializer};
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    use super::CodecError;

    pub(super) fn serialize<S>(value: &OffsetDateTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        value
            .format(&Rfc3339)
            .map_err(serde::ser::Error::custom)
            .and_then(|value| serializer.serialize_str(&value))
    }

    pub(super) fn deserialize<'de, D>(deserializer: D) -> Result<OffsetDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let timestamp = OffsetDateTime::parse(&value, &Rfc3339)
            .map_err(|error| serde::de::Error::custom(CodecError::Timestamp(error.to_string())))?;
        if value.ends_with('Z') && timestamp.offset().is_utc() {
            Ok(timestamp)
        } else {
            Err(serde::de::Error::custom(
                "timestamp must use an RFC 3339 UTC Z suffix",
            ))
        }
    }
}

mod reject_null_option {
    use std::fmt;
    use std::marker::PhantomData;

    use serde::de::{self, Deserialize, Deserializer, Visitor};

    pub(super) fn deserialize<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de>,
    {
        struct OptionalValue<T>(PhantomData<T>);

        impl<'de, T> Visitor<'de> for OptionalValue<T>
        where
            T: Deserialize<'de>,
        {
            type Value = Option<T>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an optional member value, not null")
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: Deserializer<'de>,
            {
                T::deserialize(deserializer).map(Some)
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(E::custom("optional members must be omitted, not null"))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Err(E::custom("optional members must be omitted, not null"))
            }
        }

        deserializer.deserialize_option(OptionalValue(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::PathBuf;

    use super::*;
    use crate::input_validation::ValidationError;
    use crate::registrar::config::{Multiplicity, ReloadKind};
    use crate::registrar::error::SpecIdentityField;

    // Names the registrar's own authority vocabulary carries. No request shape
    // declares one, so each stays an ignored unknown member: caller identity
    // reaches a verb from the transport seam, never from the payload.
    const PROTOCOL_ONLY_AUTHORITY_MEMBERS: [&str; 7] = [
        "caller_identity",
        "request_id",
        "composed_name",
        "registration_id",
        "domain",
        "token_policies",
        "policy_body",
    ];

    const WIRE_REFERENCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/docs/reference/registrar-wire-contract.md"
    ));

    fn reference_table_rows(heading: &str) -> Vec<Vec<&str>> {
        WIRE_REFERENCE
            .split_once(heading)
            .expect("reference section exists")
            .1
            .lines()
            .skip_while(|line| !line.starts_with('|'))
            .skip(2)
            .take_while(|line| line.starts_with('|'))
            .map(|line| {
                line.split('|')
                    .skip(1)
                    .map(str::trim)
                    .filter(|column| !column.is_empty())
                    .collect()
            })
            .collect()
    }

    fn reference_count(set: &str) -> usize {
        reference_table_rows("## 11. Counts")
            .into_iter()
            .find_map(|row| {
                (row.first().map(|value| value.replace('`', "")) == Some(set.to_string())).then(
                    || {
                        row.get(1)
                            .expect("count table carries a count")
                            .split(|character: char| !character.is_ascii_digit())
                            .rfind(|value| !value.is_empty())
                            .expect("reference count carries an integer")
                            .parse()
                            .expect("reference count integer parses")
                    },
                )
            })
            .expect("reference set exists")
    }

    fn object_member_names(value: &serde_json::Value) -> Vec<String> {
        let mut members = value
            .as_object()
            .expect("value is a JSON object")
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        members.sort_unstable();
        members
    }

    fn reference_member_names(heading: &str) -> Vec<String> {
        let mut members = reference_table_rows(heading)
            .into_iter()
            .map(|row| {
                row.first()
                    .expect("reference row has a member name")
                    .trim_matches('`')
                    .to_string()
            })
            .collect::<Vec<_>>();
        members.sort_unstable();
        members
    }

    fn assert_external_members_match_reference(
        heading: &str,
        count_set: &str,
        value: &serde_json::Value,
    ) {
        let expected = reference_member_names(heading);
        assert_eq!(expected.len(), reference_count(count_set));
        assert_eq!(object_member_names(value), expected);
    }

    fn replace_serialized_value<T>(
        value: &mut serde_json::Value,
        current: &T,
        replacement: serde_json::Value,
    ) where
        T: Serialize,
    {
        let current = serde_json::to_value(current).expect("current value serializes");
        let members = value.as_object_mut().expect("value is a JSON object");
        let member = members
            .iter()
            .find_map(|(member, value)| (value == &current).then(|| member.clone()))
            .expect("fixture contains the current value");
        members.insert(member, replacement);
    }

    fn remove_serialized_value<T>(value: &mut serde_json::Value, current: &T)
    where
        T: Serialize,
    {
        let current = serde_json::to_value(current).expect("current value serializes");
        let members = value.as_object_mut().expect("value is a JSON object");
        let member = members
            .iter()
            .find_map(|(member, value)| (value == &current).then(|| member.clone()))
            .expect("fixture contains the current value");
        members.remove(&member);
    }

    fn deregister_request(instance: Option<u32>) -> DeregisterRequest {
        DeregisterRequest {
            protocol_version: ProtocolVersion::current(),
            service_name: "api".to_string(),
            host: "node".to_string(),
            instance,
            idempotency_key: "key".to_string(),
        }
    }

    fn register_request(cert_group: Option<&str>) -> RegisterRequest {
        RegisterRequest {
            protocol_version: ProtocolVersion::current(),
            service_name: "api".to_string(),
            delivery_mode: WireDeliveryMode::LocalFile,
            host: "node".to_string(),
            instance: None,
            spec: WireServiceSpec {
                component: "api".to_string(),
                service_name: "api".to_string(),
                reload: "opaque reload".to_string(),
                cert_group: cert_group.map(str::to_string),
            },
            wrap_ttl: 60,
            idempotency_key: "opaque-key".to_string(),
        }
    }

    fn trust_payload() -> TrustPayload {
        let ca_bundle_pem =
            "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n".to_string();
        let certificate = crate::tls::parse_pem_to_cert_list(ca_bundle_pem.as_bytes())
            .expect("fixture PEM parses")
            .into_iter()
            .next()
            .expect("fixture PEM contains one certificate");
        TrustPayload {
            trusted_ca_sha256: vec![crate::tls::sha256_hex(certificate.as_ref())],
            ca_bundle_pem,
        }
    }

    #[test]
    fn protocol_version_rejects_missing_and_unknown_versions() {
        let request = deregister_request(Some(7));
        let mut missing = serde_json::to_value(&request).expect("request serializes");
        remove_serialized_value(&mut missing, &request.protocol_version);
        assert!(
            decode_request(
                Operation::Deregister,
                &serde_json::to_vec(&missing).expect("payload serializes")
            )
            .is_err()
        );

        let mut unknown = serde_json::to_value(&request).expect("request serializes");
        replace_serialized_value(
            &mut unknown,
            &request.protocol_version,
            serde_json::json!(2),
        );
        assert!(
            decode_request(
                Operation::Deregister,
                &serde_json::to_vec(&unknown).expect("payload serializes")
            )
            .is_err()
        );
    }

    #[test]
    fn request_decoding_accepts_unknown_members_but_rejects_invalid_values() {
        let request = deregister_request(None);
        let mut unknown_member = serde_json::to_value(&request).expect("request serializes");
        unknown_member
            .as_object_mut()
            .expect("request serializes as an object")
            .insert("future".to_string(), serde_json::json!("value"));
        assert!(
            decode_request(
                Operation::Deregister,
                &serde_json::to_vec(&unknown_member).expect("payload serializes")
            )
            .is_ok()
        );

        let mut invalid_idempotency_key =
            serde_json::to_value(&request).expect("request serializes");
        replace_serialized_value(
            &mut invalid_idempotency_key,
            &request.idempotency_key,
            serde_json::json!(7),
        );

        let request_with_instance = deregister_request(Some(7));
        let mut out_of_range_instance =
            serde_json::to_value(&request_with_instance).expect("request serializes");
        replace_serialized_value(
            &mut out_of_range_instance,
            &7_u32,
            serde_json::json!(4_294_967_296_u64),
        );

        for payload in [invalid_idempotency_key, out_of_range_instance] {
            assert!(
                decode_request(
                    Operation::Deregister,
                    &serde_json::to_vec(&payload).expect("payload serializes")
                )
                .is_err()
            );
        }

        let register = register_request(None);

        let mut invalid_delivery_mode =
            serde_json::to_value(&register).expect("register serializes");
        replace_serialized_value(
            &mut invalid_delivery_mode,
            &WireDeliveryMode::LocalFile,
            serde_json::Value::String("Other".to_string()),
        );

        let mut negative_ttl = serde_json::to_value(&register).expect("register serializes");
        replace_serialized_value(&mut negative_ttl, &register.wrap_ttl, serde_json::json!(-1));

        let mut fractional_ttl = serde_json::to_value(&register).expect("register serializes");
        replace_serialized_value(
            &mut fractional_ttl,
            &register.wrap_ttl,
            serde_json::json!(1.5),
        );

        for payload in [invalid_delivery_mode, negative_ttl, fractional_ttl] {
            assert!(
                decode_request(
                    Operation::Mint,
                    &serde_json::to_vec(&payload).expect("payload serializes")
                )
                .is_err()
            );
        }
    }

    #[test]
    fn deregister_ignores_members_named_only_by_the_mint_shape() {
        let expected = deregister_request(Some(7));
        let canonical =
            encode_request(&Request::Deregister(expected.clone())).expect("deregister encodes");

        let mint_shape = serde_json::to_value(register_request(Some("opaque group")))
            .expect("register serializes");
        let mint_shape = mint_shape.as_object().expect("register is an object");
        let mut value: serde_json::Value =
            serde_json::from_slice(&canonical).expect("deregister is JSON");
        let members = value.as_object_mut().expect("deregister is an object");
        for member in ["delivery_mode", "spec", "wrap_ttl"] {
            members.insert(
                member.to_string(),
                mint_shape
                    .get(member)
                    .expect("the mint shape names the member")
                    .clone(),
            );
        }
        members.insert(
            "future".to_string(),
            serde_json::json!({"nested": [1, 2, 3]}),
        );

        let payload = serde_json::to_vec(&value).expect("payload serializes");
        let decoded = decode_request(Operation::Deregister, &payload)
            .expect("members of the other operation are unknown members");
        assert_eq!(decoded, Request::Deregister(expected));

        let reencoded = encode_request(&decoded).expect("deregister re-encodes");
        assert_eq!(reencoded, canonical);
        let mut reencoded_value: serde_json::Value =
            serde_json::from_slice(&reencoded).expect("re-encoded deregister is JSON");
        reencoded_value
            .as_object_mut()
            .expect("re-encoded deregister is an object")
            .remove("protocol_version");
        assert_external_members_match_reference(
            "### 4.3 `Deregister` fields",
            "Deregister fields",
            &reencoded_value,
        );
    }

    #[test]
    fn request_decoding_rejects_a_missing_required_member() {
        for (operation, request) in [
            (
                Operation::Mint,
                Request::Register(register_request(Some("opaque group"))),
            ),
            (
                Operation::Deregister,
                Request::Deregister(deregister_request(Some(7))),
            ),
        ] {
            let encoded = encode_request(&request).expect("request encodes");
            let value: serde_json::Value =
                serde_json::from_slice(&encoded).expect("request is JSON");
            let members = value.as_object().expect("request is an object").clone();
            for member in members.keys() {
                if member == "instance" {
                    continue;
                }
                let mut reduced = members.clone();
                reduced.remove(member);
                let payload = serde_json::to_vec(&serde_json::Value::Object(reduced))
                    .expect("payload serializes");
                assert!(
                    decode_request(operation, &payload).is_err(),
                    "{member} is a required member"
                );
            }
        }

        let register = register_request(Some("opaque group"));
        let encoded = encode_request(&Request::Register(register)).expect("register encodes");
        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("register is JSON");
        let spec = value
            .get("spec")
            .and_then(serde_json::Value::as_object)
            .expect("register carries a spec object")
            .clone();
        for member in spec.keys() {
            if member == "cert_group" {
                continue;
            }
            let mut reduced_spec = spec.clone();
            reduced_spec.remove(member);
            let mut reduced = value.clone();
            reduced
                .as_object_mut()
                .expect("register is an object")
                .insert("spec".to_string(), serde_json::Value::Object(reduced_spec));
            let payload = serde_json::to_vec(&reduced).expect("payload serializes");
            assert!(
                decode_request(Operation::Mint, &payload).is_err(),
                "spec.{member} is a required member"
            );
        }
    }

    #[test]
    fn requests_ignore_protocol_only_authority_members() {
        for (operation, expected) in [
            (
                Operation::Mint,
                Request::Register(register_request(Some("opaque group"))),
            ),
            (
                Operation::Deregister,
                Request::Deregister(deregister_request(Some(7))),
            ),
        ] {
            let canonical = encode_request(&expected).expect("request encodes");
            let mut value: serde_json::Value =
                serde_json::from_slice(&canonical).expect("request is JSON");
            let members = value.as_object_mut().expect("request is an object");
            for member in PROTOCOL_ONLY_AUTHORITY_MEMBERS {
                members.insert(
                    member.to_string(),
                    serde_json::json!("unix-peer:uid=1000/asserted"),
                );
            }

            let payload = serde_json::to_vec(&value).expect("payload serializes");
            let decoded =
                decode_request(operation, &payload).expect("authority members are unknown members");
            assert_eq!(decoded, expected);

            let reencoded = encode_request(&decoded).expect("request re-encodes");
            assert_eq!(reencoded, canonical);
            let reencoded = String::from_utf8(reencoded).expect("request is UTF-8 JSON");
            for member in PROTOCOL_ONLY_AUTHORITY_MEMBERS {
                assert!(
                    !reencoded.contains(member),
                    "{member} must not survive into a decoded request"
                );
            }
        }
    }

    #[test]
    fn requests_preserve_opaque_idempotency_keys() {
        const KEYS: [&str; 2] = [" Mixed Case/\u{1f600}\t", "0000-1111"];

        let decoded = KEYS.map(|key| {
            let mut register = register_request(Some("opaque group"));
            register.idempotency_key = key.to_string();
            let mut deregister = deregister_request(Some(7));
            deregister.idempotency_key = key.to_string();

            let register = decode_request(
                Operation::Mint,
                &encode_request(&Request::Register(register)).expect("register encodes"),
            )
            .expect("register decodes");
            let deregister = decode_request(
                Operation::Deregister,
                &encode_request(&Request::Deregister(deregister)).expect("deregister encodes"),
            )
            .expect("deregister decodes");
            let (Request::Register(mut register), Request::Deregister(mut deregister)) =
                (register, deregister)
            else {
                panic!("each operation selects its own request shape")
            };

            assert_eq!(register.idempotency_key, key);
            assert_eq!(deregister.idempotency_key, key);
            register.idempotency_key = String::new();
            deregister.idempotency_key = String::new();
            (register, deregister)
        });
        assert_eq!(decoded.first(), decoded.last());
    }

    #[test]
    fn absent_cert_group_is_omitted_and_decodes_as_none() {
        let absent = Request::Register(register_request(None));
        let encoded = encode_request(&absent).expect("register encodes");
        let text = String::from_utf8(encoded.clone()).expect("register is UTF-8 JSON");
        assert!(!text.contains("cert_group"));
        assert!(!text.contains("null"));
        assert_eq!(
            decode_request(Operation::Mint, &encoded).expect("register decodes"),
            absent
        );

        let present = Request::Register(register_request(Some("opaque group")));
        let encoded = encode_request(&present).expect("register encodes");
        assert_eq!(
            decode_request(Operation::Mint, &encoded).expect("register decodes"),
            present
        );

        let mut null_group =
            serde_json::to_value(register_request(None)).expect("register serializes");
        null_group
            .get_mut("spec")
            .and_then(serde_json::Value::as_object_mut)
            .expect("register carries a spec object")
            .insert("cert_group".to_string(), serde_json::Value::Null);
        assert!(
            decode_request(
                Operation::Mint,
                &serde_json::to_vec(&null_group).expect("payload serializes")
            )
            .is_err()
        );
    }

    #[test]
    fn unclassified_refusals_have_no_error() {
        let (class, error) =
            map_refusal(&VerbError::unavailable("testing", anyhow::anyhow!("down")));
        assert_eq!(class, RefusalClass::Retryable);
        assert_eq!(error, None);
    }

    #[test]
    fn every_unclassified_refusal_omits_its_error_on_the_wire() {
        let errors = [
            VerbError::ReservedServiceName {
                service_name: "bootroot-api".to_string(),
            },
            VerbError::Registrar(RegistrarError::DerivedKeyInvalid {
                key: "invalid".to_string(),
                kind: ValidationError::InvalidRegistrationId,
            }),
            VerbError::InvalidWrapTtl(WrapTtlRefusal::Zero),
            VerbError::InvalidWrapTtl(WrapTtlRefusal::Negative),
            VerbError::InvalidWrapTtl(WrapTtlRefusal::NotWholeSeconds),
            VerbError::InvalidWrapTtl(WrapTtlRefusal::ExceedsOpenBaoRange),
            VerbError::unavailable("fixture", anyhow::anyhow!("unavailable")),
        ];

        for error in errors {
            let refusal =
                VerbRefusal::new(fixture_context(None, ProducingArm::PreDerivation), error);
            let encoded = encode_refusal_response(&refusal, &RegistrarHealth::default())
                .expect("unclassified refusal encodes");
            let decoded = decode_refusal_response(&encoded).expect("unclassified refusal decodes");
            assert_eq!(decoded.class, RefusalClass::Retryable);
            assert_eq!(decoded.error, None);
            assert_eq!(decoded.registration_id, None);
        }
    }

    /// The one refusal this family routes to `RegistrarBusy`. The
    /// variant carries the whole-second duration the limiter's admission
    /// bucket produced, and the arm changes nothing else: the identifier,
    /// its payload spelling, its retryable class and its golden fixture
    /// were all already here.
    #[test]
    fn a_throttled_refusal_encodes_as_a_retryable_registrar_busy() {
        for retry_after in [1_u64, 30, 3_600] {
            let refusal = VerbRefusal::new(
                fixture_context(None, ProducingArm::PreDerivation),
                VerbError::Throttled { retry_after },
            );
            let (class, error) = map_refusal(refusal.error());
            assert_eq!(class, RefusalClass::Retryable);
            assert_eq!(error, Some(EnrollError::RegistrarBusy { retry_after }));

            let encoded = encode_refusal_response(&refusal, &RegistrarHealth::default())
                .expect("a throttle encodes");
            let decoded = decode_refusal_response(&encoded).expect("a throttle decodes");
            assert_eq!(decoded.class, RefusalClass::Retryable);
            assert_eq!(
                decoded.error,
                Some(EnrollError::RegistrarBusy { retry_after })
            );
            assert_eq!(decoded.registration_id, None);
            assert!(
                String::from_utf8(encoded)
                    .expect("response is UTF-8 JSON")
                    .contains("\"retry_after\""),
                "the payload is spelled retry_after"
            );
        }
    }

    #[test]
    fn derived_key_invalid_from_valid_parts_is_an_unclassified_refusal() {
        let service_name = "s".repeat(63);
        let host = "h".repeat(63);
        let instance = u32::MAX;
        validate_request_labels(&service_name, &host).expect("request labels are valid");

        let error = derive_registration_id(
            Multiplicity::ManyPerHost,
            &service_name,
            &host,
            Some(instance),
        )
        .expect_err("the 138-octet derived key is invalid");
        let candidate = match &error {
            RegistrarError::DerivedKeyInvalid { key, .. } => key.clone(),
            _ => panic!("valid parts must fail only when deriving the key"),
        };
        assert_eq!(candidate.len(), 138);

        let refusal = VerbRefusal::new(
            fixture_context(None, ProducingArm::Derivation),
            VerbError::Registrar(error),
        );
        let encoded = encode_refusal_response(&refusal, &RegistrarHealth::default())
            .expect("derivation refusal encodes");
        let decoded = decode_refusal_response(&encoded).expect("derivation refusal decodes");

        assert_eq!(decoded.request_id, "request-0001");
        assert_eq!(decoded.registration_id, None);
        assert_eq!(decoded.class, RefusalClass::Retryable);
        assert_eq!(decoded.error, None);
        assert!(
            !String::from_utf8(encoded)
                .expect("response is UTF-8 JSON")
                .contains(&candidate),
            "the rejected candidate must not reach the response"
        );
    }

    // Every current verb refusal, labelled with the row the reference's own
    // mapping table records it under.  One list feeds both the mapping and the
    // envelope test, so a variant added to `map_refusal` without a row here is
    // a failing assertion rather than an untested arm.
    #[allow(clippy::too_many_lines)]
    fn every_current_verb_error() -> Vec<(&'static str, VerbError)> {
        vec![
            (
                "ReservedServiceName",
                VerbError::ReservedServiceName {
                    service_name: "bootroot-api".to_string(),
                },
            ),
            (
                "Registrar(ConfigUnreadable)",
                VerbError::Registrar(RegistrarError::ConfigUnreadable {
                    path: PathBuf::from("config"),
                    source: std::io::Error::other("unreadable"),
                }),
            ),
            (
                "Registrar(FingerprintLineMalformed)",
                VerbError::Registrar(RegistrarError::FingerprintLineMalformed {
                    path: PathBuf::from("config"),
                }),
            ),
            (
                "Registrar(FingerprintMismatch)",
                VerbError::Registrar(RegistrarError::FingerprintMismatch {
                    path: PathBuf::from("config"),
                    declared: "declared".to_string(),
                    computed: "computed".to_string(),
                }),
            ),
            (
                "Registrar(ConfigMalformed)",
                VerbError::Registrar(RegistrarError::ConfigMalformed {
                    path: PathBuf::from("config"),
                    message: "malformed".to_string(),
                }),
            ),
            (
                "Registrar(UnsupportedSchemaVersion)",
                VerbError::Registrar(RegistrarError::UnsupportedSchemaVersion {
                    path: PathBuf::from("config"),
                    found: 2,
                    supported: 1,
                }),
            ),
            (
                "Registrar(UnknownMultiplicity)",
                VerbError::Registrar(RegistrarError::UnknownMultiplicity {
                    component: "api".to_string(),
                    value: "unknown".to_string(),
                }),
            ),
            (
                "Registrar(UnknownReloadKind)",
                VerbError::Registrar(RegistrarError::UnknownReloadKind {
                    component: "api".to_string(),
                    value: "unknown".to_string(),
                }),
            ),
            (
                "Registrar(InvalidReloadTarget)",
                VerbError::Registrar(RegistrarError::InvalidReloadTarget {
                    component: "api".to_string(),
                    kind: ReloadKind::Systemd,
                }),
            ),
            (
                "Registrar(InvalidDomain)",
                VerbError::Registrar(RegistrarError::InvalidDomain {
                    domain: "invalid".to_string(),
                    kind: ValidationError::InvalidDomainName,
                }),
            ),
            (
                "Registrar(InvalidComponentKey)",
                VerbError::Registrar(RegistrarError::InvalidComponentKey {
                    component: "invalid".to_string(),
                    kind: ValidationError::InvalidDnsLabel,
                }),
            ),
            (
                "Registrar(InvalidServiceName)",
                VerbError::Registrar(RegistrarError::InvalidServiceName {
                    value: "invalid".to_string(),
                    kind: ValidationError::InvalidDnsLabel,
                }),
            ),
            (
                "Registrar(InvalidHost)",
                VerbError::Registrar(RegistrarError::InvalidHost {
                    value: "invalid".to_string(),
                    kind: ValidationError::InvalidDnsLabel,
                }),
            ),
            (
                "Registrar(ComponentNotConfigured)",
                VerbError::Registrar(RegistrarError::ComponentNotConfigured {
                    component: "api".to_string(),
                }),
            ),
            (
                "Registrar(ServiceInstanceMismatch)",
                VerbError::Registrar(RegistrarError::ServiceInstanceMismatch {
                    component: "api".to_string(),
                    multiplicity: Multiplicity::ManyPerHost,
                    instance_supplied: false,
                }),
            ),
            (
                "Registrar(DerivedKeyInvalid)",
                VerbError::Registrar(RegistrarError::DerivedKeyInvalid {
                    key: "invalid".to_string(),
                    kind: ValidationError::InvalidRegistrationId,
                }),
            ),
            (
                "Registrar(SpecIdentityDisagreement)",
                VerbError::Registrar(RegistrarError::SpecIdentityDisagreement {
                    field: SpecIdentityField::Both,
                    expected: "api".to_string(),
                    spec_component: Some("other".to_string()),
                    spec_service_name: Some("other".to_string()),
                }),
            ),
            (
                "Registrar(ServiceSpecOutsideSafeSet)",
                VerbError::Registrar(RegistrarError::ServiceSpecOutsideSafeSet {
                    component: "api".to_string(),
                }),
            ),
            (
                "RegistrationIdCollision",
                VerbError::RegistrationIdCollision {
                    registration_id: "registration-1".to_string(),
                    stored_host: "stored".to_string(),
                    requested_host: "requested".to_string(),
                },
            ),
            (
                "StoredSpecConflict",
                VerbError::StoredSpecConflict {
                    registration_id: "registration-1".to_string(),
                },
            ),
            (
                "HostMismatch",
                VerbError::HostMismatch {
                    registration_id: "registration-1".to_string(),
                    stored_host: "stored".to_string(),
                    requested_host: "requested".to_string(),
                },
            ),
            (
                "InvalidWrapTtl(Zero)",
                VerbError::InvalidWrapTtl(WrapTtlRefusal::Zero),
            ),
            (
                "InvalidWrapTtl(Negative)",
                VerbError::InvalidWrapTtl(WrapTtlRefusal::Negative),
            ),
            (
                "InvalidWrapTtl(NotWholeSeconds)",
                VerbError::InvalidWrapTtl(WrapTtlRefusal::NotWholeSeconds),
            ),
            (
                "InvalidWrapTtl(ExceedsOpenBaoRange)",
                VerbError::InvalidWrapTtl(WrapTtlRefusal::ExceedsOpenBaoRange),
            ),
            (
                "AuditUnwritable { phase: Intent }",
                VerbError::AuditUnwritable {
                    phase: AuditPhase::Intent,
                    source: fixture_audit_store_error(),
                },
            ),
            (
                "AuditUnwritable { phase: Outcome }",
                VerbError::AuditUnwritable {
                    phase: AuditPhase::Outcome,
                    source: fixture_audit_store_error(),
                },
            ),
            (
                "PostMintUnrecordable",
                VerbError::PostMintUnrecordable {
                    source: fixture_audit_store_error(),
                },
            ),
            (
                "Unavailable",
                VerbError::unavailable("fixture", anyhow::anyhow!("unavailable")),
            ),
        ]
    }

    fn fixture_audit_store_error() -> AuditStoreError {
        AuditStoreError::Append {
            path: PathBuf::from("audit"),
            source: std::io::Error::other("append failed"),
        }
    }

    // The reference's mapping table, minus the rows describing refusals no
    // internal variant produces yet.
    fn reference_refusal_mapping() -> BTreeMap<String, (RefusalClass, Option<EnrollError>)> {
        reference_refusal_mapping_rows()
            .into_iter()
            .filter(|(label, _)| !label.starts_with("Future "))
            .collect()
    }

    fn reference_refusal_mapping_rows() -> Vec<(String, (RefusalClass, Option<EnrollError>))> {
        reference_table_rows("The refusal mapping is exhaustive over the current bootroot verb")
            .into_iter()
            .map(|row| {
                let label = row
                    .first()
                    .expect("mapping row names an internal variant")
                    .trim_matches('`')
                    .to_string();
                let class = reference_class(
                    row.get(2)
                        .expect("mapping row carries a class")
                        .trim_matches('`'),
                );
                let identifier = reference_identifier(
                    row.get(1)
                        .expect("mapping row carries a wire identifier")
                        .trim_matches('`'),
                );
                (label, (class, identifier))
            })
            .collect()
    }

    fn reference_class(class: &str) -> RefusalClass {
        serde_json::from_value(serde_json::Value::String(class.to_string()))
            .expect("reference class is a wire class")
    }

    // Reads a mapping-table cell such as `RegistrarUnavailable { reason: X }`
    // back into the identifier it names, so no external spelling is retyped
    // into a test.  A row that records a member without a fixed value — the
    // rate-limit refusal's `retry_after` — supplies a placeholder, because the
    // row assigns the identifier and leaves the value to the refusal.
    fn reference_identifier(identifier: &str) -> Option<EnrollError> {
        if identifier == "none" {
            return None;
        }
        let (identifier, payload) = match identifier.split_once(" { ") {
            None => (identifier, None),
            Some((identifier, payload)) => (identifier, Some(payload.trim_end_matches('}').trim())),
        };
        let mut object = serde_json::Map::new();
        object.insert(
            "id".to_string(),
            serde_json::Value::String(identifier.to_string()),
        );
        if let Some(payload) = payload {
            match payload.split_once(": ") {
                Some((member, value)) => object.insert(
                    member.to_string(),
                    serde_json::Value::String(value.to_string()),
                ),
                None => object.insert(payload.to_string(), serde_json::json!(0)),
            };
        }
        Some(
            serde_json::from_value(serde_json::Value::Object(object))
                .expect("reference identifier is a wire identifier"),
        )
    }

    #[test]
    fn every_verb_refusal_maps_to_its_contract_class_and_identifier() {
        let expected = reference_refusal_mapping();
        let mut covered = BTreeSet::new();
        for (label, error) in every_current_verb_error() {
            let row = expected
                .get(label)
                .unwrap_or_else(|| panic!("the reference records a mapping row for {label}"));
            assert_eq!(
                &map_refusal(&error),
                row,
                "{label} maps to its recorded row"
            );
            covered.insert(label.to_string());
        }
        assert_eq!(
            covered,
            expected.keys().cloned().collect::<BTreeSet<_>>(),
            "every recorded mapping row is exercised"
        );
    }

    #[test]
    fn the_reference_records_the_future_rate_limit_assignment() {
        let future = reference_refusal_mapping_rows()
            .into_iter()
            .filter(|(label, _)| label.starts_with("Future "))
            .map(|(_, row)| row)
            .collect::<Vec<_>>();
        assert_eq!(future.len(), 1);
        for (class, identifier) in &future {
            let identifier = identifier
                .as_ref()
                .expect("a future assignment names an identifier");
            assert!(validate_refusal_class(*class, Some(identifier)).is_ok());
        }
        assert!(
            future
                .iter()
                .any(|(class, identifier)| *class == RefusalClass::Retryable
                    && matches!(identifier, Some(EnrollError::RegistrarBusy { .. })))
        );
    }

    #[test]
    fn every_verb_refusal_round_trips_through_the_refusal_envelope() {
        let health = RegistrarHealth::default();
        for (label, error) in every_current_verb_error() {
            let (class, expected_error) = map_refusal(&error);
            let refusal = VerbRefusal::new(
                fixture_context(Some("registration-1"), ProducingArm::Binding),
                error,
            );
            let encoded = encode_refusal_response(&refusal, &health)
                .unwrap_or_else(|_| panic!("the {label} refusal encodes"));

            let value: serde_json::Value =
                serde_json::from_slice(&encoded).expect("refusal is JSON");
            let members = value.as_object().expect("refusal is an object");
            assert_eq!(
                members.get("class").cloned(),
                Some(serde_json::to_value(class).expect("class serializes")),
                "{label} encodes its recorded class"
            );
            assert_eq!(
                members.get("error").cloned(),
                expected_error
                    .as_ref()
                    .map(|error| serde_json::to_value(error).expect("identifier serializes")),
                "{label} encodes its recorded identifier form"
            );

            let decoded = decode_refusal_response(&encoded)
                .unwrap_or_else(|_| panic!("the {label} refusal decodes"));
            assert_eq!(decoded.class, class);
            assert_eq!(decoded.error, expected_error);
            assert_eq!(decoded.registration_id.as_deref(), Some("registration-1"));
            assert_eq!(decoded.request_id, "request-0001");
        }
    }

    #[test]
    fn every_identifier_and_reason_round_trips_through_the_refusal_envelope() {
        let health = RegistrarHealth::default();
        let classes = reference_identifier_classes();
        let reasons = [
            RegistrarUnavailableReason::CredentialInvalid,
            RegistrarUnavailableReason::NotProvisioned,
            RegistrarUnavailableReason::AuditUnwritable,
            RegistrarUnavailableReason::EndpointUnreachable,
            RegistrarUnavailableReason::PostMintUnrecordable,
            RegistrarUnavailableReason::RegistrarUnreachable,
        ];
        let errors = [
            EnrollError::ServiceSpecConflict,
            EnrollError::ServiceNameCollision,
            EnrollError::ServiceInstanceMismatch,
            EnrollError::ServiceHostMismatch,
            EnrollError::RegistrarBusy { retry_after: 30 },
            EnrollError::ServiceLabelInvalid,
        ]
        .into_iter()
        .chain(
            reasons
                .into_iter()
                .map(|reason| EnrollError::RegistrarUnavailable { reason }),
        );

        let mut covered_identifiers = BTreeSet::new();
        let mut covered_reasons = BTreeSet::new();
        for error in errors {
            let encoded_error = serde_json::to_value(&error).expect("identifier serializes");
            let identifier = encoded_error
                .get("id")
                .and_then(serde_json::Value::as_str)
                .expect("an identifier uses the id tag")
                .to_string();
            let class = *classes
                .get(&identifier)
                .expect("the reference records the identifier");

            let encoded = encode_refusal(
                "request-0001",
                Some("registration-1"),
                class,
                Some(error.clone()),
                &health,
            )
            .expect("the refusal envelope encodes");
            let decoded = decode_refusal_response(&encoded).expect("the refusal envelope decodes");
            assert_eq!(decoded.class, class);
            assert_eq!(decoded.error, Some(error));

            if let Some(reason) = encoded_error
                .get("reason")
                .and_then(serde_json::Value::as_str)
            {
                covered_reasons.insert(reason.to_string());
            }
            covered_identifiers.insert(identifier);
        }

        assert_eq!(
            covered_identifiers.len(),
            reference_count("typed enroll errors")
        );
        assert_eq!(
            covered_identifiers,
            classes.keys().cloned().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            covered_reasons.len(),
            reference_count("RegistrarUnavailable reasons")
        );
    }

    #[test]
    fn collapsed_refusals_encode_one_identical_class_and_error() {
        for (expected_error, errors) in [
            (
                EnrollError::ServiceSpecConflict,
                vec![
                    VerbError::Registrar(RegistrarError::SpecIdentityDisagreement {
                        field: SpecIdentityField::Both,
                        expected: "api".to_string(),
                        spec_component: Some("other".to_string()),
                        spec_service_name: Some("other".to_string()),
                    }),
                    VerbError::Registrar(RegistrarError::ServiceSpecOutsideSafeSet {
                        component: "api".to_string(),
                    }),
                    VerbError::StoredSpecConflict {
                        registration_id: "registration-1".to_string(),
                    },
                ],
            ),
            (
                EnrollError::ServiceInstanceMismatch,
                vec![
                    VerbError::Registrar(RegistrarError::ComponentNotConfigured {
                        component: "api".to_string(),
                    }),
                    VerbError::Registrar(RegistrarError::ServiceInstanceMismatch {
                        component: "api".to_string(),
                        multiplicity: Multiplicity::ManyPerHost,
                        instance_supplied: false,
                    }),
                ],
            ),
        ] {
            let expected_value =
                serde_json::to_value(&expected_error).expect("identifier serializes");
            assert_eq!(
                object_member_names(&expected_value),
                vec!["id".to_string()],
                "a collapsed identifier carries no discriminator beyond its id"
            );
            let expected = (
                serde_json::to_string(&RefusalClass::Permanent).expect("class serializes"),
                serde_json::to_string(&expected_value).expect("identifier serializes"),
            );

            let sources = errors.len();
            let encoded = errors
                .into_iter()
                .map(encoded_class_and_error)
                .collect::<Vec<_>>();
            assert_eq!(encoded.len(), sources);
            for form in &encoded {
                assert_eq!(*form, expected);
            }
        }
    }

    fn encoded_class_and_error(error: VerbError) -> (String, String) {
        let refusal = VerbRefusal::new(
            fixture_context(Some("registration-1"), ProducingArm::Binding),
            error,
        );
        let encoded = encode_refusal_response(&refusal, &RegistrarHealth::default())
            .expect("collapsed refusal encodes");
        let value: serde_json::Value = serde_json::from_slice(&encoded).expect("refusal is JSON");
        let members = value.as_object().expect("refusal is an object");
        (
            serde_json::to_string(members.get("class").expect("refusal carries a class"))
                .expect("class serializes"),
            serde_json::to_string(members.get("error").expect("refusal carries an error"))
                .expect("identifier serializes"),
        )
    }

    #[test]
    fn all_external_error_identifiers_and_reasons_decode() {
        let reasons = [
            RegistrarUnavailableReason::CredentialInvalid,
            RegistrarUnavailableReason::NotProvisioned,
            RegistrarUnavailableReason::AuditUnwritable,
            RegistrarUnavailableReason::EndpointUnreachable,
            RegistrarUnavailableReason::PostMintUnrecordable,
            RegistrarUnavailableReason::RegistrarUnreachable,
        ];
        for reason in reasons {
            let error = EnrollError::RegistrarUnavailable { reason };
            let encoded = serde_json::to_vec(&error).expect("error serializes");
            let decoded: EnrollError = serde_json::from_slice(&encoded).expect("error decodes");
            assert_eq!(decoded, error);
        }

        let errors = [
            EnrollError::ServiceSpecConflict,
            EnrollError::ServiceNameCollision,
            EnrollError::ServiceInstanceMismatch,
            EnrollError::ServiceHostMismatch,
            EnrollError::RegistrarUnavailable {
                reason: RegistrarUnavailableReason::NotProvisioned,
            },
            EnrollError::RegistrarBusy { retry_after: 60 },
            EnrollError::ServiceLabelInvalid,
        ];
        for error in errors {
            let encoded = serde_json::to_vec(&error).expect("error serializes");
            let decoded: EnrollError = serde_json::from_slice(&encoded).expect("error decodes");
            assert_eq!(decoded, error);
        }
    }

    fn reference_identifier_classes() -> BTreeMap<String, RefusalClass> {
        reference_table_rows("### 6.1 The identifier set")
            .into_iter()
            .map(|row| {
                let identifier = row
                    .first()
                    .expect("identifier row has a name")
                    .trim_matches('`')
                    .to_string();
                let class = reference_class(row.get(2).expect("identifier row has a class"));
                (identifier, class)
            })
            .collect()
    }

    #[test]
    fn external_error_names_and_counts_conform_to_the_reference() {
        let expected_identifier_classes = reference_identifier_classes();
        assert_eq!(
            expected_identifier_classes.len(),
            reference_count("typed enroll errors")
        );

        let actual_identifier_classes = [
            EnrollError::ServiceSpecConflict,
            EnrollError::ServiceNameCollision,
            EnrollError::ServiceInstanceMismatch,
            EnrollError::ServiceHostMismatch,
            EnrollError::RegistrarUnavailable {
                reason: RegistrarUnavailableReason::NotProvisioned,
            },
            EnrollError::RegistrarBusy { retry_after: 1 },
            EnrollError::ServiceLabelInvalid,
        ]
        .iter()
        .map(|error| {
            let identifier = serde_json::to_value(error)
                .expect("identifier serializes")
                .get("id")
                .and_then(serde_json::Value::as_str)
                .expect("identifier uses an id member")
                .to_string();
            let class = *expected_identifier_classes
                .get(&identifier)
                .expect("encoded identifier appears in the reference");
            assert!(validate_refusal_class(class, Some(error)).is_ok());
            let other_class = match class {
                RefusalClass::Retryable => RefusalClass::Permanent,
                RefusalClass::Permanent => RefusalClass::Retryable,
            };
            assert!(validate_refusal_class(other_class, Some(error)).is_err());
            (identifier, class)
        })
        .collect::<BTreeMap<_, _>>();
        assert_eq!(actual_identifier_classes, expected_identifier_classes);

        let mut expected_reasons: Vec<_> =
            reference_table_rows("### 6.5 `RegistrarUnavailable` reason set (closed)")
                .into_iter()
                .map(|row| {
                    row.first()
                        .expect("reason row has a name")
                        .trim_matches('`')
                        .to_string()
                })
                .collect();
        expected_reasons.sort_unstable();
        assert_eq!(
            expected_reasons.len(),
            reference_count("RegistrarUnavailable reasons")
        );

        let mut encoded_reasons = [
            RegistrarUnavailableReason::CredentialInvalid,
            RegistrarUnavailableReason::NotProvisioned,
            RegistrarUnavailableReason::AuditUnwritable,
            RegistrarUnavailableReason::EndpointUnreachable,
            RegistrarUnavailableReason::PostMintUnrecordable,
            RegistrarUnavailableReason::RegistrarUnreachable,
        ]
        .iter()
        .map(|reason| {
            serde_json::to_value(reason)
                .expect("reason serializes")
                .as_str()
                .expect("reason serializes as a string")
                .to_string()
        })
        .collect::<Vec<_>>();
        encoded_reasons.sort_unstable();
        assert_eq!(encoded_reasons, expected_reasons);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn all_external_wire_names_conform_to_the_reference() {
        let register = RegisterRequest {
            protocol_version: ProtocolVersion::current(),
            service_name: "api".to_string(),
            delivery_mode: WireDeliveryMode::LocalFile,
            host: "node".to_string(),
            instance: Some(7),
            spec: WireServiceSpec {
                component: "api".to_string(),
                service_name: "api".to_string(),
                reload: "opaque reload".to_string(),
                cert_group: Some("opaque group".to_string()),
            },
            wrap_ttl: 60,
            idempotency_key: "opaque-key".to_string(),
        };
        let mut register_value = serde_json::to_value(register).expect("register serializes");
        register_value
            .as_object_mut()
            .expect("register is an object")
            .remove("protocol_version");
        assert_external_members_match_reference(
            "### 4.2 `Register` fields",
            "Register fields",
            &register_value,
        );

        let deregister = DeregisterRequest {
            protocol_version: ProtocolVersion::current(),
            service_name: "api".to_string(),
            host: "node".to_string(),
            instance: Some(7),
            idempotency_key: "opaque-key".to_string(),
        };
        let mut deregister_value = serde_json::to_value(deregister).expect("deregister serializes");
        deregister_value
            .as_object_mut()
            .expect("deregister is an object")
            .remove("protocol_version");
        assert_external_members_match_reference(
            "### 4.3 `Deregister` fields",
            "Deregister fields",
            &deregister_value,
        );

        let spec = WireServiceSpec {
            component: "api".to_string(),
            service_name: "api".to_string(),
            reload: "opaque reload".to_string(),
            cert_group: Some("opaque group".to_string()),
        };
        assert_external_members_match_reference(
            "### 4.4 `ServiceSpec` fields",
            "ServiceSpec fields",
            &serde_json::to_value(spec).expect("spec serializes"),
        );

        let material = BootstrapMaterial {
            role_id: "role".to_string(),
            wrapped_secret_id: WrappedSecretId::new("wrapped-token".to_string()),
            ca_anchor: "anchor".to_string(),
            expires_at: OffsetDateTime::UNIX_EPOCH,
        };
        assert_external_members_match_reference(
            "### 5.2 `BootstrapMaterial` fields",
            "BootstrapMaterial fields",
            &serde_json::to_value(material).expect("material serializes"),
        );

        let mut expected_delivery_modes = reference_member_names("### 4.5 `DeliveryMode` variants");
        assert_eq!(
            expected_delivery_modes.len(),
            reference_count("DeliveryMode variants")
        );
        let mut encoded_delivery_modes = [
            WireDeliveryMode::LocalFile,
            WireDeliveryMode::RemoteBootstrap,
        ]
        .iter()
        .map(|mode| {
            serde_json::to_value(mode)
                .expect("delivery mode serializes")
                .as_str()
                .expect("delivery mode serializes as a string")
                .to_string()
        })
        .collect::<Vec<_>>();
        expected_delivery_modes.sort_unstable();
        encoded_delivery_modes.sort_unstable();
        assert_eq!(encoded_delivery_modes, expected_delivery_modes);

        let mut expected_error_payload_members = reference_table_rows("### 6.1 The identifier set")
            .into_iter()
            .filter_map(|row| {
                row.get(1).and_then(|payload| {
                    payload
                        .trim_matches('`')
                        .split_once(':')
                        .map(|(name, _)| name.to_string())
                })
            })
            .collect::<Vec<_>>();
        let mut actual_error_payload_members = [
            EnrollError::RegistrarUnavailable {
                reason: RegistrarUnavailableReason::NotProvisioned,
            },
            EnrollError::RegistrarBusy { retry_after: 60 },
        ]
        .iter()
        .flat_map(|error| {
            let mut value = serde_json::to_value(error).expect("error serializes");
            value
                .as_object_mut()
                .expect("error is an object")
                .remove("id");
            object_member_names(&value)
        })
        .collect::<Vec<_>>();
        actual_error_payload_members.sort_unstable();
        expected_error_payload_members.sort_unstable();
        assert_eq!(actual_error_payload_members, expected_error_payload_members);
    }

    #[test]
    fn nullable_optional_members_are_rejected() {
        let request = deregister_request(Some(7));
        let mut payload = serde_json::to_value(&request).expect("request serializes");
        replace_serialized_value(&mut payload, &7_u32, serde_json::Value::Null);
        assert!(
            decode_request(
                Operation::Deregister,
                &serde_json::to_vec(&payload).expect("payload serializes")
            )
            .is_err()
        );
    }

    #[test]
    fn refusal_omits_optional_members_and_decodes_with_unknown_members() {
        let response = RefusalResponse {
            protocol_version: ProtocolVersion::current(),
            request_id: "request".to_string(),
            registration_id: None,
            class: RefusalClass::Retryable,
            error: None,
            registrar_health: RegistrarHealth::default(),
        };
        let encoded = serde_json::to_string(&response).expect("response serializes");
        assert_eq!(
            encoded,
            r#"{"protocol_version":1,"request_id":"request","class":"retryable","registrar_health":{}}"#
        );

        let with_unknown_member = r#"{"protocol_version":1,"request_id":"request","class":"retryable","registrar_health":{},"future":true}"#;
        let decoded = decode_refusal_response(with_unknown_member.as_bytes())
            .expect("unknown response member is tolerated");
        assert_eq!(decoded.class, RefusalClass::Retryable);
        assert_eq!(decoded.error, None);
    }

    #[test]
    fn refusal_decoding_rejects_a_class_that_conflicts_with_its_error_form() {
        let unclassified = RefusalResponse {
            protocol_version: ProtocolVersion::current(),
            request_id: "request".to_string(),
            registration_id: None,
            class: RefusalClass::Permanent,
            error: None,
            registrar_health: RegistrarHealth::default(),
        };
        assert!(
            decode_refusal_response(
                &serde_json::to_vec(&unclassified).expect("unclassified refusal serializes")
            )
            .is_err()
        );

        for (error, class) in [
            (EnrollError::ServiceHostMismatch, RefusalClass::Retryable),
            (
                EnrollError::RegistrarBusy { retry_after: 30 },
                RefusalClass::Permanent,
            ),
        ] {
            let response = RefusalResponse {
                protocol_version: ProtocolVersion::current(),
                request_id: "request".to_string(),
                registration_id: None,
                class,
                error: Some(error),
                registrar_health: RegistrarHealth::default(),
            };
            assert!(
                decode_refusal_response(
                    &serde_json::to_vec(&response).expect("refusal serializes")
                )
                .is_err()
            );
        }
    }

    #[test]
    fn refusal_registration_id_and_health_follow_the_supplied_context() {
        let health = RegistrarHealth::default();
        let refusals = [
            (
                VerbRefusal::new(
                    fixture_context(None, ProducingArm::PreDerivation),
                    VerbError::ReservedServiceName {
                        service_name: "bootroot-api".to_string(),
                    },
                ),
                None,
            ),
            (
                VerbRefusal::new(
                    fixture_context(None, ProducingArm::Derivation),
                    VerbError::Registrar(RegistrarError::DerivedKeyInvalid {
                        key: "invalid".to_string(),
                        kind: ValidationError::InvalidRegistrationId,
                    }),
                ),
                None,
            ),
            (
                VerbRefusal::new(
                    fixture_context(Some("registration-1"), ProducingArm::Binding),
                    VerbError::HostMismatch {
                        registration_id: "registration-1".to_string(),
                        stored_host: "stored".to_string(),
                        requested_host: "requested".to_string(),
                    },
                ),
                Some("registration-1"),
            ),
        ];

        let mut encoded_health = None;
        for (refusal, expected_registration_id) in refusals {
            let encoded =
                encode_refusal_response(&refusal, &health).expect("refusal response encodes");
            let value: serde_json::Value =
                serde_json::from_slice(&encoded).expect("refusal response is JSON");
            let response_health = value
                .get("registrar_health")
                .expect("response carries registrar_health")
                .clone();
            if let Some(expected_health) = &encoded_health {
                assert_eq!(&response_health, expected_health);
            } else {
                encoded_health = Some(response_health);
            }

            let decoded = decode_refusal_response(&encoded).expect("refusal response decodes");
            assert_eq!(decoded.registration_id.as_deref(), expected_registration_id);
        }
    }

    #[test]
    fn mint_response_carries_the_granted_deadline() {
        // Two granted instants, each with the UTC string the response must
        // carry: a deadline derived from the requested lifetime instead would
        // not move with them.
        const GRANTED: [(i64, &str); 2] = [
            (1_700_000_000, "2023-11-14T22:13:20Z"),
            (1_700_003_600, "2023-11-14T23:13:20Z"),
        ];

        let health = RegistrarHealth::default();
        let anchor = trust_payload();
        for (timestamp, expected) in GRANTED {
            let granted = OffsetDateTime::from_unix_timestamp(timestamp)
                .expect("the fixture instant is representable");
            let elsewhere = granted.to_offset(
                time::UtcOffset::from_hms(9, 0, 0).expect("the fixture offset is valid"),
            );
            for expires_at in [granted, elsewhere] {
                let outcome = MintOutcome::new(
                    fixture_context(Some("registration-1"), ProducingArm::Issuance),
                    MintKind::FirstMint,
                    "api.node.example.test".to_string(),
                    "role-id".to_string(),
                    WrappedSecretIdToken::new("wrapped-secret".to_string()),
                    expires_at,
                );
                let encoded =
                    encode_mint_response(outcome, &anchor, &health).expect("mint outcome encodes");
                let value: serde_json::Value =
                    serde_json::from_slice(&encoded).expect("mint response is JSON");
                assert_eq!(
                    value
                        .get("material")
                        .and_then(|material| material.get("expires_at"))
                        .and_then(serde_json::Value::as_str),
                    Some(expected),
                    "the response carries the granted deadline as a UTC instant"
                );
                assert_eq!(
                    decode_mint_response(&encoded)
                        .expect("mint response decodes")
                        .material
                        .expires_at,
                    granted
                );
            }
        }
    }

    #[test]
    fn every_response_shape_carries_one_reproducible_empty_health_snapshot() {
        let health = RegistrarHealth::default();
        let anchor = trust_payload();
        let mint = || {
            MintOutcome::new(
                fixture_context(Some("registration-1"), ProducingArm::Issuance),
                MintKind::FirstMint,
                "api.node.example.test".to_string(),
                "role-id".to_string(),
                WrappedSecretIdToken::new("wrapped-secret".to_string()),
                OffsetDateTime::UNIX_EPOCH,
            )
        };
        let deregister = || {
            DeregisterOutcome::new(
                fixture_context(Some("registration-1"), ProducingArm::Teardown),
                DeregisterKind::IdentityRemoved,
                TeardownReport::default(),
            )
        };
        let permanent = || {
            VerbRefusal::new(
                fixture_context(Some("registration-1"), ProducingArm::Binding),
                VerbError::HostMismatch {
                    registration_id: "registration-1".to_string(),
                    stored_host: "stored".to_string(),
                    requested_host: "node".to_string(),
                },
            )
        };
        let retryable = || {
            VerbRefusal::new(
                fixture_context(None, ProducingArm::PreDerivation),
                VerbError::unavailable("fixture", anyhow::anyhow!("unavailable")),
            )
        };
        let busy = || {
            encode_refusal(
                "request-0001",
                Some("registration-1"),
                RefusalClass::Retryable,
                Some(EnrollError::RegistrarBusy { retry_after: 30 }),
                &health,
            )
        };

        let shapes = [
            (
                "mint success",
                encode_mint_response(mint(), &anchor, &health).expect("mint encodes"),
                encode_mint_response(mint(), &anchor, &health).expect("mint re-encodes"),
            ),
            (
                "deregister success",
                encode_deregister_response(&deregister(), &health).expect("deregister encodes"),
                encode_deregister_response(&deregister(), &health).expect("deregister re-encodes"),
            ),
            (
                "permanent refusal",
                encode_refusal_response(&permanent(), &health).expect("permanent refusal encodes"),
                encode_refusal_response(&permanent(), &health)
                    .expect("permanent refusal re-encodes"),
            ),
            (
                "retryable refusal",
                encode_refusal_response(&retryable(), &health).expect("retryable refusal encodes"),
                encode_refusal_response(&retryable(), &health)
                    .expect("retryable refusal re-encodes"),
            ),
            (
                "retryable refusal with an identifier",
                busy().expect("busy refusal encodes"),
                busy().expect("busy refusal re-encodes"),
            ),
        ];

        for (shape, first, second) in shapes {
            assert_eq!(first, second, "{shape} does not encode reproducibly");

            let text = String::from_utf8(first).expect("response is UTF-8 JSON");
            assert!(
                text.contains(r#""registrar_health":{}"#),
                "{shape} does not carry the empty health snapshot"
            );
            let value: serde_json::Value = serde_json::from_str(&text).expect("response is JSON");
            let snapshot = value
                .get("registrar_health")
                .expect("response carries registrar_health");
            assert_eq!(
                serde_json::from_value::<RegistrarHealth>(snapshot.clone())
                    .expect("the snapshot decodes"),
                RegistrarHealth::default()
            );
        }
    }

    #[test]
    fn mint_response_decoding_enforces_version_and_anchor_framing() {
        let trust_payload = trust_payload();
        let anchor = encode_ca_anchor(&trust_payload).expect("anchor encodes");
        assert_eq!(
            decode_ca_anchor(&anchor).expect("encoded anchor must decode"),
            trust_payload
        );
        let response = MintResponse {
            protocol_version: ProtocolVersion::current(),
            request_id: "request".to_string(),
            registration_id: "registration".to_string(),
            outcome: MintWireOutcome::FirstMint,
            material: BootstrapMaterial {
                role_id: "role".to_string(),
                wrapped_secret_id: WrappedSecretId::new("wrapped-token".to_string()),
                ca_anchor: anchor,
                expires_at: OffsetDateTime::UNIX_EPOCH,
            },
            registrar_health: RegistrarHealth::default(),
        };
        let encoded = serde_json::to_vec(&response).expect("response serializes");
        let decoded = decode_mint_response(&encoded).expect("response decodes");
        assert_eq!(decoded.request_id, "request");
        assert_eq!(decoded.material.wrapped_secret_id.as_str(), "wrapped-token");
        assert!(!format!("{decoded:?}").contains("wrapped-token"));

        let unknown_version = String::from_utf8(encoded)
            .expect("response is UTF-8")
            .replacen("\"protocol_version\":1", "\"protocol_version\":2", 1);
        assert!(decode_mint_response(unknown_version.as_bytes()).is_err());

        let missing_version = unknown_version.replacen("\"protocol_version\":2,", "", 1);
        assert!(decode_mint_response(missing_version.as_bytes()).is_err());

        let malformed_anchor = MintResponse {
            protocol_version: ProtocolVersion::current(),
            request_id: "request".to_string(),
            registration_id: "registration".to_string(),
            outcome: MintWireOutcome::FirstMint,
            material: BootstrapMaterial {
                role_id: "role".to_string(),
                wrapped_secret_id: WrappedSecretId::new("wrapped-token".to_string()),
                ca_anchor: "not-base64".to_string(),
                expires_at: OffsetDateTime::UNIX_EPOCH,
            },
            registrar_health: RegistrarHealth::default(),
        };
        let malformed = serde_json::to_vec(&malformed_anchor).expect("response serializes");
        assert!(decode_mint_response(&malformed).is_err());
    }

    #[test]
    fn response_outcomes_preserve_every_verb_outcome_kind() {
        let health = RegistrarHealth::default();
        for (kind, expected) in [
            (MintKind::FirstMint, MintWireOutcome::FirstMint),
            (
                MintKind::IdempotentReMint,
                MintWireOutcome::IdempotentRemint,
            ),
        ] {
            let outcome = MintOutcome::new(
                fixture_context(Some("registration-1"), ProducingArm::Issuance),
                kind,
                "api.node.example.test".to_string(),
                "role-id".to_string(),
                WrappedSecretIdToken::new("wrapped-secret".to_string()),
                OffsetDateTime::UNIX_EPOCH,
            );
            let encoded = encode_mint_response(outcome, &trust_payload(), &health)
                .expect("mint outcome encodes");
            assert_eq!(
                decode_mint_response(&encoded)
                    .expect("mint response decodes")
                    .outcome,
                expected
            );
        }

        for (kind, expected) in [
            (
                DeregisterKind::IdentityRemoved,
                DeregisterWireOutcome::Removed,
            ),
            (
                DeregisterKind::AlreadyAbsent,
                DeregisterWireOutcome::AlreadyAbsent,
            ),
        ] {
            let outcome = DeregisterOutcome::new(
                fixture_context(Some("registration-1"), ProducingArm::Teardown),
                kind,
                TeardownReport::default(),
            );
            let encoded =
                encode_deregister_response(&outcome, &health).expect("deregister outcome encodes");
            assert_eq!(
                decode_deregister_response(&encoded)
                    .expect("deregister response decodes")
                    .outcome,
                expected
            );
        }
    }

    #[test]
    fn trust_payload_requires_exactly_one_trailing_lf() {
        let mut payload = trust_payload();
        payload.ca_bundle_pem.push('\n');
        assert!(encode_ca_anchor(&payload).is_err());
    }

    #[test]
    fn ca_anchor_rejects_noncanonical_or_inconsistent_framing() {
        let payload = trust_payload();
        let encoded = encode_ca_anchor(&payload).expect("anchor encodes");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .expect("encoded anchor is base64");
        let fingerprint = payload
            .trusted_ca_sha256
            .first()
            .expect("fixture payload has one fingerprint");
        let expected = format!(
            r#"{{"trusted_ca_sha256":["{fingerprint}"],"ca_bundle_pem":"-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n"}}"#
        );
        assert_eq!(decoded, expected.as_bytes());

        let uppercase_fingerprint = base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(&serde_json::json!({
                "trusted_ca_sha256": [fingerprint.to_uppercase()],
                "ca_bundle_pem": &payload.ca_bundle_pem,
            }))
            .expect("JSON serializes"),
        );
        assert!(decode_ca_anchor(&uppercase_fingerprint).is_err());

        let mismatched_lowercase_fingerprint = base64::engine::general_purpose::STANDARD.encode(
            serde_json::to_vec(&serde_json::json!({
                "trusted_ca_sha256": ["a".repeat(64)],
                "ca_bundle_pem": &payload.ca_bundle_pem,
            }))
            .expect("JSON serializes"),
        );
        assert!(decode_ca_anchor(&mismatched_lowercase_fingerprint).is_err());

        let missing_members = base64::engine::general_purpose::STANDARD.encode(br"{}");
        assert!(decode_ca_anchor(&missing_members).is_err());

        let non_json_bytes = base64::engine::general_purpose::STANDARD.encode(b"not JSON");
        assert!(decode_ca_anchor(&non_json_bytes).is_err());
    }

    fn fixture_context(registration_id: Option<&str>, arm: ProducingArm) -> VerbContext {
        VerbContext::new(
            RequestId::for_fixture("request-0001"),
            CallerIdentity::new("registrar-client:001.bootroot-registrar.h1.example.internal"),
            registration_id.map(str::to_string),
            arm,
        )
    }

    fn generated_fixtures() -> Vec<(&'static str, Vec<u8>)> {
        let health = RegistrarHealth::default();
        let register = Request::Register(RegisterRequest {
            protocol_version: ProtocolVersion::current(),
            service_name: "api".to_string(),
            delivery_mode: WireDeliveryMode::RemoteBootstrap,
            host: "node".to_string(),
            instance: Some(7),
            spec: WireServiceSpec {
                component: "api".to_string(),
                service_name: "api".to_string(),
                reload: "opaque reload".to_string(),
                cert_group: Some("opaque group".to_string()),
            },
            wrap_ttl: 60,
            idempotency_key: "opaque-key".to_string(),
        });
        let deregister = Request::Deregister(DeregisterRequest {
            protocol_version: ProtocolVersion::current(),
            service_name: "api".to_string(),
            host: "node".to_string(),
            instance: None,
            idempotency_key: "opaque-key".to_string(),
        });
        let mint = MintOutcome::new(
            fixture_context(Some("registration-1"), ProducingArm::Issuance),
            MintKind::FirstMint,
            "api.node.example.test".to_string(),
            "role-id".to_string(),
            WrappedSecretIdToken::new("wrapped-secret".to_string()),
            OffsetDateTime::UNIX_EPOCH,
        );
        let deregister_outcome = DeregisterOutcome::new(
            fixture_context(Some("registration-1"), ProducingArm::Teardown),
            DeregisterKind::AlreadyAbsent,
            TeardownReport::default(),
        );
        let permanent = VerbRefusal::new(
            fixture_context(Some("registration-1"), ProducingArm::Binding),
            VerbError::HostMismatch {
                registration_id: "registration-1".to_string(),
                stored_host: "stored".to_string(),
                requested_host: "node".to_string(),
            },
        );
        let unclassified = VerbRefusal::new(
            fixture_context(None, ProducingArm::PreDerivation),
            VerbError::unavailable("fixture", anyhow::anyhow!("unavailable")),
        );

        vec![
            (
                "register-request.json",
                encode_request(&register).expect("register fixture encodes"),
            ),
            (
                "deregister-request.json",
                encode_request(&deregister).expect("deregister fixture encodes"),
            ),
            (
                "mint-success.json",
                encode_mint_response(mint, &trust_payload(), &health)
                    .expect("mint fixture encodes"),
            ),
            (
                "deregister-success.json",
                encode_deregister_response(&deregister_outcome, &health)
                    .expect("deregister fixture encodes"),
            ),
            (
                "refusal-permanent.json",
                encode_refusal_response(&permanent, &health).expect("permanent fixture encodes"),
            ),
            (
                "refusal-busy.json",
                encode_refusal(
                    "request-0001",
                    Some("registration-1"),
                    RefusalClass::Retryable,
                    Some(EnrollError::RegistrarBusy { retry_after: 30 }),
                    &health,
                )
                .expect("busy fixture encodes"),
            ),
            (
                "refusal-unclassified.json",
                encode_refusal_response(&unclassified, &health)
                    .expect("unclassified fixture encodes"),
            ),
        ]
    }

    fn committed_fixture(name: &str) -> &'static [u8] {
        match name {
            "register-request.json" => include_bytes!("fixtures/register-request.json"),
            "deregister-request.json" => include_bytes!("fixtures/deregister-request.json"),
            "mint-success.json" => include_bytes!("fixtures/mint-success.json"),
            "deregister-success.json" => include_bytes!("fixtures/deregister-success.json"),
            "refusal-permanent.json" => include_bytes!("fixtures/refusal-permanent.json"),
            "refusal-busy.json" => include_bytes!("fixtures/refusal-busy.json"),
            "refusal-unclassified.json" => include_bytes!("fixtures/refusal-unclassified.json"),
            _ => panic!("unknown fixture name: {name}"),
        }
    }

    fn decode_and_reencode_fixture(name: &str, fixture: &[u8]) -> Vec<u8> {
        match name {
            "register-request.json" | "deregister-request.json" => encode_request(
                &decode_request(
                    if name == "register-request.json" {
                        Operation::Mint
                    } else {
                        Operation::Deregister
                    },
                    fixture,
                )
                .expect("request fixture decodes"),
            )
            .expect("request fixture reencodes"),
            "mint-success.json" => {
                serde_json::to_vec(&decode_mint_response(fixture).expect("mint fixture decodes"))
                    .expect("mint fixture reencodes")
            }
            "deregister-success.json" => serde_json::to_vec(
                &decode_deregister_response(fixture).expect("deregister fixture decodes"),
            )
            .expect("deregister fixture reencodes"),
            _ => serde_json::to_vec(
                &decode_refusal_response(fixture).expect("refusal fixture decodes"),
            )
            .expect("refusal fixture reencodes"),
        }
    }

    fn shuffled_json(value: &serde_json::Value) -> String {
        match value {
            serde_json::Value::Array(values) => format!(
                "[{}]",
                values
                    .iter()
                    .map(shuffled_json)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            serde_json::Value::Object(members) => format!(
                "{{{}}}",
                members
                    .iter()
                    .rev()
                    .map(|(member, value)| {
                        format!(
                            "{}:{}",
                            serde_json::to_string(member).expect("member name serializes"),
                            shuffled_json(value)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            _ => serde_json::to_string(value).expect("JSON value serializes"),
        }
    }

    #[test]
    fn golden_fixtures_match_the_production_codec() {
        for (name, generated) in generated_fixtures() {
            assert_eq!(
                generated,
                committed_fixture(name),
                "fixture {name} is stale"
            );
        }
    }

    #[test]
    fn golden_fixtures_decode_and_reencode_byte_for_byte() {
        for (name, fixture) in generated_fixtures() {
            let reencoded = decode_and_reencode_fixture(name, &fixture);
            assert_eq!(reencoded, fixture, "fixture {name} did not round-trip");

            let fixture_value: serde_json::Value =
                serde_json::from_slice(&fixture).expect("fixture is JSON");
            let shuffled = shuffled_json(&fixture_value);
            assert_ne!(
                shuffled.as_bytes(),
                fixture,
                "fixture {name} did not shuffle"
            );
            assert_eq!(
                decode_and_reencode_fixture(name, shuffled.as_bytes()),
                fixture,
                "shuffled fixture {name} did not decode to the canonical value"
            );
        }
    }

    #[test]
    #[ignore = "prints canonical fixture contents for an intentional fixture update"]
    fn print_golden_fixture_contents() {
        for (name, fixture) in generated_fixtures() {
            println!(
                "{name}: {}",
                String::from_utf8(fixture).expect("fixture is UTF-8")
            );
        }
    }
}
