//! The registrar's provisioning config and the registration identities
//! derived from it.
//!
//! Two repositories must agree on the derivation rule exactly, or every
//! enrollment in the fleet fails — and it fails after deployment, with
//! both repositories' tests green. So the rule lives here as one small,
//! densely tested unit, separate from the verbs that call it:
//!
//! - [`config`] reads the file the provisioning tool renders onto this
//!   host, validates its digest and schema version, and yields the
//!   deployment `domain` plus one entry per component.
//! - [`identity`] derives the `registration_id`, composes the SAN,
//!   checks the identity shape and validates a requested spec against
//!   the component's rendered safe-set — as separately callable steps,
//!   because the verb layer interleaves its own checks between them.
//! - [`error`] declares every refusal the two produce.
//! - [`fixture`] builds a rendered config for tests.
//!
//! Nothing here reads or requires registration state. That is what makes
//! the durable-binding collision check the caller's step rather than a
//! missing one here, and it is why no variant in [`error`] refers to a
//! stored or previously applied spec.

pub mod config;
pub mod error;
pub mod fixture;
pub mod identity;

#[cfg(test)]
mod tests;

pub use config::{
    CONFIG_FILE_NAME, ComponentEntry, DEFAULT_CONFIG_PATH, Multiplicity, RegistrarConfig,
    RegistrationSpec, ReloadKind, ReloadSpec, SUPPORTED_SCHEMA_VERSION,
};
pub use error::{RegistrarError, SpecIdentityField};
pub use identity::{
    DerivedIdentity, RequestedSpec, check_instance_shape, check_spec_identity, compose_san,
    derive_registration_id, validate_request_labels,
};
