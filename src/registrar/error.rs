//! The typed refusals the registrar's config loader and derivation
//! library produce.
//!
//! This enum is *the* definition of these refusals for the whole
//! repository. Downstream verb, endpoint and audit code wraps these
//! variants; none of them redeclares one, so every refusal these checks
//! can produce is declared here rather than left for a caller to invent
//! a parallel name for.
//!
//! Deliberately absent: anything about a *stored* spec. Comparing a
//! request against what a registration was previously minted with is the
//! verb layer's step and produces a different refusal
//! (`ServiceSpecConflict`); this library has no access to registration
//! state and cannot express it.

use std::fmt;
use std::path::PathBuf;

use thiserror::Error;

use crate::input_validation::ValidationError;
use crate::registrar::config::{Multiplicity, ReloadKind};

/// Which identity-restating field of a requested spec disagreed with the
/// wire `service_name`.
///
/// The disagreement is one refusal semantically — the spec names an
/// identity other than the one the wire selected — so it is one error
/// variant, and this is what tells an operator and the audit record
/// which field the caller got wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpecIdentityField {
    /// `spec.component` disagreed; `spec.service_name` did not.
    Component,
    /// `spec.service_name` disagreed; `spec.component` did not.
    ServiceName,
    /// Both fields disagreed.
    Both,
}

impl SpecIdentityField {
    /// Returns the stable lowercase name of the disagreeing field, or
    /// `"component and service_name"` when both did.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Component => "component",
            Self::ServiceName => "service_name",
            Self::Both => "component and service_name",
        }
    }
}

impl fmt::Display for SpecIdentityField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every refusal the registrar config loader and the registration
/// derivation library can produce.
#[derive(Debug, Error)]
pub enum RegistrarError {
    /// The rendered config is missing or could not be read. Never a
    /// default: minting under a guessed domain would issue a
    /// certificate no peer will ever verify.
    #[error("registrar config at {path} is missing or unreadable")]
    ConfigUnreadable {
        /// The path that was read.
        path: PathBuf,
        /// The underlying I/O failure.
        source: std::io::Error,
    },

    /// The first line of the rendered config is not exactly
    /// `fingerprint = "<64 lowercase hex>"` followed by one newline.
    #[error("registrar config at {path} does not open with a fingerprint line")]
    FingerprintLineMalformed {
        /// The path that was read.
        path: PathBuf,
    },

    /// The digest of the body does not match the fingerprint the first
    /// line declares — the file was truncated, edited or partially
    /// rendered. Carries both digests so an operator can tell this from
    /// a file written by a newer provisioning tool.
    #[error(
        "registrar config at {path} declares fingerprint {declared} but its body digests to {computed}"
    )]
    FingerprintMismatch {
        /// The path that was read.
        path: PathBuf,
        /// The digest the first line declared.
        declared: String,
        /// The digest the body actually has.
        computed: String,
    },

    /// The body is not UTF-8, is not TOML, or does not have the shape
    /// this build parses.
    #[error("registrar config at {path} is malformed: {message}")]
    ConfigMalformed {
        /// The path that was read.
        path: PathBuf,
        /// What the parser objected to.
        message: String,
    },

    /// The file declares a `schema_version` this build does not
    /// implement. Carries the found and the supported version so an
    /// operator can tell a newer provisioning tool from a corrupt file.
    #[error(
        "registrar config at {path} declares schema_version {found}, but this build implements {supported}"
    )]
    UnsupportedSchemaVersion {
        /// The path that was read.
        path: PathBuf,
        /// The version the file declares.
        found: u32,
        /// The version this build implements.
        supported: u32,
    },

    /// A component's `multiplicity` is not one of the three classes.
    #[error("component {component} declares unrecognised multiplicity {value:?}")]
    UnknownMultiplicity {
        /// The component whose entry carried the value.
        component: String,
        /// The offending value, verbatim.
        value: String,
    },

    /// A component's `reload.kind` is not one of the four styles.
    #[error("component {component} declares unrecognised reload kind {value:?}")]
    UnknownReloadKind {
        /// The component whose entry carried the value.
        component: String,
        /// The offending value, verbatim.
        value: String,
    },

    /// A component's `reload` omits a `target` its `kind` requires, or
    /// carries one its `kind` forbids.
    #[error("component {component} declares a reload of kind {kind} with an invalid target")]
    InvalidReloadTarget {
        /// The component whose entry carried the reload.
        component: String,
        /// The reload style that was declared.
        kind: ReloadKind,
    },

    /// The file's `domain` is not a dot-separated DNS name.
    #[error("registrar config declares invalid domain {domain:?} ({kind:?})")]
    InvalidDomain {
        /// The offending value, verbatim.
        domain: String,
        /// Why the shared validator refused it.
        kind: ValidationError,
    },

    /// A `[components.<key>]` key no registration could ever use: it is
    /// not a single DNS label, so no wire `service_name` could select
    /// it, or it is not path-safe, so no id derived for it could pass
    /// [`RegistrarError::DerivedKeyInvalid`].
    #[error("registrar config declares invalid component key {component:?} ({kind:?})")]
    InvalidComponentKey {
        /// The offending key, verbatim.
        component: String,
        /// Why the shared validator refused it.
        kind: ValidationError,
    },

    /// The wire `service_name` is not a single DNS label. Refused
    /// before any derivation, so the refusal carries no
    /// `registration_id`.
    #[error("service_name {value:?} is not a single DNS label ({kind:?})")]
    InvalidServiceName {
        /// The offending value, verbatim, for the caller to record.
        value: String,
        /// Why the shared validator refused it.
        kind: ValidationError,
    },

    /// The wire `host` is not a single DNS label. Refused for every
    /// multiplicity class, including the one-per-deployment class whose
    /// derivation arm does not read it.
    #[error("host {value:?} is not a single DNS label ({kind:?})")]
    InvalidHost {
        /// The offending value, verbatim, for the caller to record.
        value: String,
        /// Why the shared validator refused it.
        kind: ValidationError,
    },

    /// The component has no entry in the rendered config, so it has no
    /// multiplicity class and no safe-set. Never defaulted.
    ///
    /// Distinct from [`RegistrarError::ServiceInstanceMismatch`] even
    /// though the endpoint maps both onto that one caller-facing
    /// identifier: the audit record stores the internal variant, and
    /// collapsing them there would erase the difference between a
    /// caller sending the wrong `instance` shape for a known component
    /// and a caller probing component names that do not exist.
    #[error("component {component} has no entry in the registrar config")]
    ComponentNotConfigured {
        /// The component the wire `service_name` named.
        component: String,
    },

    /// The request's `instance` presence contradicts the component's
    /// multiplicity class.
    #[error(
        "component {component} is {multiplicity}, and the request's instance presence \
         (supplied: {instance_supplied}) contradicts that class"
    )]
    ServiceInstanceMismatch {
        /// The component whose class was resolved.
        component: String,
        /// The class the rendered config gives that component.
        multiplicity: Multiplicity,
        /// Whether the request carried an `instance`.
        instance_supplied: bool,
    },

    /// The derived `registration_id` is not a path-safe key — it
    /// exceeds 131 octets or carries a character outside `[a-z0-9-]`.
    /// The bound is enforced on the derived string rather than inferred
    /// from the inputs, which are what a caller controls.
    #[error("derived registration_id {key:?} is not a path-safe key ({kind:?})")]
    DerivedKeyInvalid {
        /// The key that was derived.
        key: String,
        /// Why the shared validator refused it.
        kind: ValidationError,
    },

    /// The requested spec restates an identity other than the one the
    /// wire `service_name` selected.
    #[error("spec restates {field}, which disagrees with the requested service_name {expected:?}")]
    SpecIdentityDisagreement {
        /// Which of the two identity-restating fields disagreed.
        field: SpecIdentityField,
        /// The wire `service_name` the spec had to agree with.
        expected: String,
        /// `spec.component` as supplied, when present.
        spec_component: Option<String>,
        /// `spec.service_name` as supplied, when present.
        spec_service_name: Option<String>,
    },

    /// The requested spec is not the component's single rendered spec.
    /// Comparison is equality on both `cert_group` and `reload`; there
    /// is no template language and no per-instance parameterisation.
    #[error("requested spec is outside the safe-set rendered for component {component}")]
    ServiceSpecOutsideSafeSet {
        /// The component whose rendered spec the request failed.
        component: String,
    },
}
