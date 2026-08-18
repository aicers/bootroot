//! The durable record that binds a derived `registration_id` to the host
//! that claimed it, and to the spec that identity was minted with.
//!
//! This record is the registrar's **only** authority for host collision,
//! host mismatch and the re-mint decision. The derivation is not
//! injective — `web` on `h1-aimer` and `aimer-web` on `h1` both derive
//! `h1-aimer-web-001` — so "is this id already taken, and by whom" cannot
//! be answered from the request's parts, and it has to survive a restart
//! of the registrar to be answered at all.
//!
//! # Why the shape is local
//!
//! The JSON below is a **verb-local** shape, not a serialization of
//! [`crate::registrar::RegistrationSpec`] /
//! [`crate::registrar::ReloadSpec`] /
//! [`crate::registrar::ReloadKind`]. Those three types are the
//! parsed form of a file another repository renders, and putting serde
//! derives on them would make this record's on-disk shape move whenever
//! that file's parsed form did — a stored binding is read back months
//! later by a build that has since re-read a re-rendered config, and the
//! two must not be coupled. The conversion between the two vocabularies
//! is explicit in both directions, and a test pins each local spelling
//! against `ReloadKind::as_str` / `ReloadKind::from_str` so a variant
//! added there cannot silently acquire a different spelling here.
//!
//! # Schema version
//!
//! The version is read on its own before the body is parsed against this
//! build's shape. A record written by a newer registrar is refused
//! **fail-closed and without touching the data**: guessing at its meaning
//! is what would let a second host take over an identity the newer build
//! bound, and deleting it is worse still.

use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::registrar::config::{RegistrationSpec, ReloadKind, ReloadSpec};
use crate::registrar::identity::RequestedSpec;

/// KV path suffix, under `bootroot/services/<registration_id>/`, of the
/// registrar's durable host binding.
///
/// Deliberately **not** in any teardown suffix set: the binding outlives
/// the material it covers, and only the deregister verb deletes it, only
/// after that material is aggregate-gone.
pub(crate) const REGISTRAR_BINDING_KV_SUFFIX: &str = "registrar_binding";

/// The schema version this build writes and reads.
pub(crate) const BINDING_SCHEMA_VERSION: u32 = 1;

/// Where a binding is in its two-step lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum BindingState {
    /// The claim won the compare-and-set, but the role, policy and the
    /// active transition have not all completed yet. A binding left here
    /// by a failed or interrupted convergence is **retained**, never
    /// rolled back: it is what keeps whatever material did get created
    /// covered by a durable claim instead of stranded as an orphan.
    Creating,
    /// Role and policy are converged and the identity is the requesting
    /// host's. Only from here is a credential ever issued.
    Active,
}

/// The post-renew hook style, in this record's own vocabulary.
///
/// The spellings are the same kebab-case words
/// [`ReloadKind`] uses, and a test pins that.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum BindingReloadKind {
    /// `sighup`
    Sighup,
    /// `systemd`
    Systemd,
    /// `docker-restart`
    DockerRestart,
    /// `none`
    None,
}

impl From<ReloadKind> for BindingReloadKind {
    fn from(value: ReloadKind) -> Self {
        match value {
            ReloadKind::Sighup => Self::Sighup,
            ReloadKind::Systemd => Self::Systemd,
            ReloadKind::DockerRestart => Self::DockerRestart,
            ReloadKind::None => Self::None,
        }
    }
}

impl From<BindingReloadKind> for ReloadKind {
    fn from(value: BindingReloadKind) -> Self {
        match value {
            BindingReloadKind::Sighup => Self::Sighup,
            BindingReloadKind::Systemd => Self::Systemd,
            BindingReloadKind::DockerRestart => Self::DockerRestart,
            BindingReloadKind::None => Self::None,
        }
    }
}

impl BindingReloadKind {
    /// Returns the kebab-case word this variant serializes as, which is
    /// the registrar vocabulary's own spelling for it.
    pub(crate) fn as_str(self) -> &'static str {
        ReloadKind::from(self).as_str()
    }

    /// Parses a kebab-case word through the registrar vocabulary, so
    /// there is one parser rather than two.
    pub(crate) fn parse(value: &str) -> Option<Self> {
        ReloadKind::from_str(value).ok().map(Self::from)
    }
}

/// The post-renew hook, in this record's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingReload {
    /// The hook style.
    pub(crate) kind: BindingReloadKind,
    /// The process, unit or container the hook acts on; `null` exactly
    /// when `kind` is `none`.
    pub(crate) target: Option<String>,
}

/// The two per-registration spec fields, in this record's own
/// vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingSpec {
    /// The numeric gid the issued files are owned by, or `null`.
    pub(crate) cert_group: Option<u32>,
    /// The post-renew hook.
    pub(crate) reload: BindingReload,
}

impl BindingSpec {
    /// Converts a requested spec into the record's vocabulary. Only the
    /// two safe-set fields are stored: the spec's identity-restating
    /// `component` / `service_name` are checked against the wire
    /// `service_name` before derivation and are not part of what a
    /// re-mint compares.
    pub(crate) fn from_requested(spec: &RequestedSpec) -> Self {
        Self {
            cert_group: spec.cert_group,
            reload: BindingReload {
                kind: spec.reload.kind.into(),
                target: spec.reload.target.clone(),
            },
        }
    }

    /// Converts back into the registrar vocabulary.
    pub(crate) fn to_registration_spec(&self) -> RegistrationSpec {
        RegistrationSpec {
            cert_group: self.cert_group,
            reload: ReloadSpec {
                kind: self.reload.kind.into(),
                target: self.reload.target.clone(),
            },
        }
    }
}

/// The stored binding record, schema version 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BindingRecord {
    /// The schema version this record was written under.
    pub(crate) schema_version: u32,
    /// The host that claimed this derived id. Every host-collision and
    /// host-mismatch decision compares against this and nothing else.
    pub(crate) host: String,
    /// Where the binding is in its lifecycle.
    pub(crate) state: BindingState,
    /// The spec the claiming request asked for.
    pub(crate) requested_spec: Option<BindingSpec>,
    /// The spec the completed convergence applied — `null` until the
    /// binding goes active, and then the same value `requested_spec`
    /// carries.
    pub(crate) applied_spec: Option<BindingSpec>,
}

/// Just the version, read before the body is parsed against this build's
/// shape.
///
/// Deliberately **not** `deny_unknown_fields`: a record written by a
/// newer build carries fields this one does not know, and it has to be
/// recognisable as "a newer schema" rather than as "an unknown field".
#[derive(Debug, Deserialize)]
struct SchemaProbe {
    schema_version: u32,
}

/// Why a stored binding could not be read as this build's record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum BindingDecodeError {
    /// The stored JSON does not even carry a readable `schema_version`.
    #[error("stored binding does not declare a readable schema_version: {message}")]
    NoSchemaVersion {
        /// What the parser objected to.
        message: String,
    },
    /// The record was written under a schema this build does not
    /// implement.
    #[error(
        "stored binding declares schema_version {found}, but this build implements {supported}"
    )]
    UnsupportedSchemaVersion {
        /// The version the record declares.
        found: u32,
        /// The version this build implements.
        supported: u32,
    },
    /// The version matched but the body is not this build's shape —
    /// including an unknown field, which is refused rather than ignored.
    #[error("stored binding is not a schema-version-{BINDING_SCHEMA_VERSION} record: {message}")]
    Malformed {
        /// What the parser objected to.
        message: String,
    },
}

impl BindingRecord {
    /// Builds the record a compare-and-set claim writes: the host is
    /// bound, the requested spec is recorded so a same-host re-drive has
    /// something to compare against, and nothing is applied yet.
    pub(crate) fn creating(host: &str, spec: &RequestedSpec) -> Self {
        Self {
            schema_version: BINDING_SCHEMA_VERSION,
            host: host.to_string(),
            state: BindingState::Creating,
            requested_spec: Some(BindingSpec::from_requested(spec)),
            applied_spec: None,
        }
    }

    /// Returns this record transitioned to active, with `applied_spec`
    /// set to the same value `requested_spec` carries.
    pub(crate) fn activated(&self, spec: &RequestedSpec) -> Self {
        let stored = BindingSpec::from_requested(spec);
        Self {
            schema_version: BINDING_SCHEMA_VERSION,
            host: self.host.clone(),
            state: BindingState::Active,
            requested_spec: Some(stored.clone()),
            applied_spec: Some(stored),
        }
    }

    /// Decodes a stored record, gating on the schema version first.
    ///
    /// # Errors
    ///
    /// Returns [`BindingDecodeError`] naming which of the three gates the
    /// stored value failed. Every one of them is fail-closed: the caller
    /// changes nothing on any of them.
    pub(crate) fn decode(value: &serde_json::Value) -> Result<Self, BindingDecodeError> {
        let probe: SchemaProbe = serde_json::from_value(value.clone()).map_err(|err| {
            BindingDecodeError::NoSchemaVersion {
                message: err.to_string(),
            }
        })?;
        if probe.schema_version != BINDING_SCHEMA_VERSION {
            return Err(BindingDecodeError::UnsupportedSchemaVersion {
                found: probe.schema_version,
                supported: BINDING_SCHEMA_VERSION,
            });
        }
        serde_json::from_value(value.clone()).map_err(|err| BindingDecodeError::Malformed {
            message: err.to_string(),
        })
    }

    /// Encodes this record for the KV write.
    ///
    /// # Errors
    ///
    /// Returns the serializer's failure, which cannot arise for this
    /// shape but is propagated rather than unwrapped.
    pub(crate) fn encode(&self) -> Result<serde_json::Value, serde_json::Error> {
        serde_json::to_value(self)
    }
}
