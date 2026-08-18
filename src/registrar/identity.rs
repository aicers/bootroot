//! Registration identity derivation: the `registration_id` rule, the SAN
//! composition, the identity-shape check and safe-set validation.
//!
//! # Why these are separate steps
//!
//! The verb layer interleaves its own checks between them, in this fixed
//! order:
//!
//! 1. [`validate_request_labels`] — the wire `service_name` and `host`.
//! 2. [`check_spec_identity`] — the spec must not restate a different
//!    identity.
//! 3. [`RegistrarConfig::multiplicity`](crate::registrar::RegistrarConfig::multiplicity)
//!    — resolve the class, refusing a component with no entry.
//! 4. [`check_instance_shape`] — the `instance`-presence check.
//! 5. [`derive_registration_id`] — the key.
//! 6. *the verb's own* per-identity mutex and durable-binding collision
//!    check, which read state this library has no access to.
//! 7. [`RegistrarConfig::validate_spec`](crate::registrar::RegistrarConfig::validate_spec)
//!    — the safe-set comparison.
//!
//! Two properties break under a fused call. A pre-derivation refusal
//! must carry **no** `registration_id`, so steps 1–4 are reachable
//! without deriving anything. And the collision check runs *between*
//! derivation and safe-set validation: the rendered spec is
//! host-agnostic, so two hosts of one component present the identical
//! spec, and a flow that validated the spec first would match and
//! re-wrap the first host's identity for the second.
//!
//! [`RegistrarConfig::resolve_end_to_end`](crate::registrar::RegistrarConfig::resolve_end_to_end)
//! runs them in order for tests. The verb layer must not use it, because
//! it has nowhere to put step 6.

use crate::input_validation::{validate_dns_label, validate_registration_id};
use crate::registrar::config::{Multiplicity, RegistrarConfig, RegistrationSpec, ReloadSpec};
use crate::registrar::error::{RegistrarError, SpecIdentityField};

/// The `<instance>` segment a SAN takes when the request carries no
/// `instance`, per RFC §5.1.
///
/// This default is **SAN-only**. It must never reach
/// [`derive_registration_id`]: a one-per-host component's id stays
/// `<host>-<component>`, and defaulting before the derivation arm is
/// selected would collapse the two-part/three-part distinction the
/// identity-shape check exists to enforce.
const DEFAULT_SAN_INSTANCE: u32 = 1;

/// A registration spec as it arrives on the wire.
///
/// This mirrors the ecosystem's `ServiceRegistration`: `component`,
/// `service_name`, `reload` and `cert_group`, and four is the whole
/// shape. There is no privilege field and none is being added — bootroot
/// derives every service's authority from the fixed derived policy, so
/// no component differs from another on a privilege dimension.
///
/// The two identity fields are `Option` because a caller may omit them;
/// present, they must agree with the wire `service_name`. Neither is
/// ever a selector, a segment of the derived `registration_id`, or a
/// source of the SAN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedSpec {
    /// The spec's restatement of the component's package id.
    pub component: Option<String>,
    /// The spec's restatement of the component's plain keyword.
    pub service_name: Option<String>,
    /// The requested post-renew hook.
    pub reload: ReloadSpec,
    /// The requested numeric gid, or `None` for no cert-group policy.
    pub cert_group: Option<u32>,
}

impl RequestedSpec {
    /// Creates a requested spec carrying no identity restatement.
    #[must_use]
    pub fn new(reload: ReloadSpec, cert_group: Option<u32>) -> Self {
        Self {
            component: None,
            service_name: None,
            reload,
            cert_group,
        }
    }

    /// Returns this spec with `component` restated as `value`.
    #[must_use]
    pub fn with_component(mut self, value: &str) -> Self {
        self.component = Some(value.to_string());
        self
    }

    /// Returns this spec with `service_name` restated as `value`.
    #[must_use]
    pub fn with_service_name(mut self, value: &str) -> Self {
        self.service_name = Some(value.to_string());
        self
    }
}

/// Everything the derivation produces for one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedIdentity {
    /// The multiplicity class the component's entry declares.
    pub multiplicity: Multiplicity,
    /// The deployment-wide namespace key. Never a certificate field.
    pub registration_id: String,
    /// The certificate SAN, always four segments.
    pub san: String,
}

/// Validates the wire `service_name` and `host` as single DNS labels.
///
/// This runs before anything else and before any derivation, so a
/// refusal here carries no `registration_id` and none is computed as a
/// side effect. `host` is validated for **every** multiplicity class,
/// including the one-per-deployment class whose derivation arm ignores
/// it: the SAN's third segment still needs it, so "not used by the id
/// arm" is not "optional".
///
/// # Errors
///
/// Returns [`RegistrarError::InvalidServiceName`] or
/// [`RegistrarError::InvalidHost`], each carrying the raw offending
/// string for the caller to record.
pub fn validate_request_labels(service_name: &str, host: &str) -> Result<(), RegistrarError> {
    validate_dns_label(service_name).map_err(|kind| RegistrarError::InvalidServiceName {
        value: service_name.to_string(),
        kind,
    })?;
    validate_dns_label(host).map_err(|kind| RegistrarError::InvalidHost {
        value: host.to_string(),
        kind,
    })?;
    Ok(())
}

/// Refuses a spec that restates an identity other than the one the wire
/// `service_name` selected.
///
/// Both `spec.component` and `spec.service_name` are checked, and both
/// produce the **same** variant — they are one refusal semantically —
/// with [`SpecIdentityField`] recording which one disagreed. Run this
/// before the safe-set check and before any derivation, so the refusal
/// is unambiguous.
///
/// The comparison is strict equality against the post-split contract:
/// the spec's identity fields carry the plain keyword, never a composed
/// name. A `spec.service_name` of `roxyd-h1` against a wire
/// `service_name` of `roxyd` is a disagreement like any other; there is
/// no compatibility path that strips a host suffix.
///
/// # Errors
///
/// Returns [`RegistrarError::SpecIdentityDisagreement`].
pub fn check_spec_identity(service_name: &str, spec: &RequestedSpec) -> Result<(), RegistrarError> {
    let component_disagrees = spec
        .component
        .as_deref()
        .is_some_and(|value| value != service_name);
    let service_name_disagrees = spec
        .service_name
        .as_deref()
        .is_some_and(|value| value != service_name);
    let field = match (component_disagrees, service_name_disagrees) {
        (false, false) => return Ok(()),
        (true, false) => SpecIdentityField::Component,
        (false, true) => SpecIdentityField::ServiceName,
        (true, true) => SpecIdentityField::Both,
    };
    Err(RegistrarError::SpecIdentityDisagreement {
        field,
        expected: service_name.to_string(),
        spec_component: spec.component.clone(),
        spec_service_name: spec.service_name.clone(),
    })
}

/// Refuses a registration whose `instance` presence contradicts the
/// component's multiplicity class.
///
/// This is the identity **shape** check. It is reachable without
/// deriving anything, so a refusal here carries no `registration_id`.
///
/// # Errors
///
/// Returns [`RegistrarError::ServiceInstanceMismatch`] when `instance`
/// is present for a one-per-host or one-per-deployment component, or
/// absent for a many-per-host one.
pub fn check_instance_shape(
    component: &str,
    multiplicity: Multiplicity,
    instance: Option<u32>,
) -> Result<(), RegistrarError> {
    if multiplicity.takes_instance() == instance.is_some() {
        return Ok(());
    }
    Err(RegistrarError::ServiceInstanceMismatch {
        component: component.to_string(),
        multiplicity,
        instance_supplied: instance.is_some(),
    })
}

/// Derives the `registration_id` from the identity's parts and the
/// component's multiplicity class, per ecosystem RFC-A §4.
///
/// This is the **only** implementation of that rule in this repository.
/// The three arms are:
///
/// | class | key |
/// | --- | --- |
/// | one-per-deployment | `<component>` |
/// | one-per-host | `<host>-<component>` |
/// | many-per-host | `<host>-<component>-<instance>` |
///
/// `instance` is rendered three digits zero-padded. `host` is required
/// and validated for every class, but the one-per-deployment arm does
/// not read it.
///
/// The derivation is **not injective in general**: component names and
/// host labels both admit hyphens, so `web` on host `h1-aimer` and
/// `aimer-web` on host `h1` derive the same key. A uniqueness check
/// against durable state is therefore required, and it is the caller's —
/// nothing here reads registration state.
///
/// # Errors
///
/// Returns [`RegistrarError::ServiceInstanceMismatch`] when `instance`
/// contradicts `multiplicity`, and [`RegistrarError::DerivedKeyInvalid`]
/// when the derived key is not path-safe — including the ≤131-octet
/// bound, which is enforced on the derived string by the shared
/// [`validate_registration_id`] rather than inferred from the inputs.
pub fn derive_registration_id(
    multiplicity: Multiplicity,
    service_name: &str,
    host: &str,
    instance: Option<u32>,
) -> Result<String, RegistrarError> {
    check_instance_shape(service_name, multiplicity, instance)?;
    let key = match (multiplicity, instance) {
        (Multiplicity::OnePerDeployment, _) => service_name.to_string(),
        (Multiplicity::OnePerHost, _) => format!("{host}-{service_name}"),
        (Multiplicity::ManyPerHost, Some(instance)) => {
            format!("{host}-{service_name}-{instance:03}")
        }
        // Unreachable: `check_instance_shape` above refuses a
        // many-per-host request with no instance.
        (Multiplicity::ManyPerHost, None) => {
            return Err(RegistrarError::ServiceInstanceMismatch {
                component: service_name.to_string(),
                multiplicity,
                instance_supplied: false,
            });
        }
    };
    validate_registration_id(&key).map_err(|kind| RegistrarError::DerivedKeyInvalid {
        key: key.clone(),
        kind,
    })?;
    Ok(key)
}

/// Composes the certificate SAN from the identity's four parts.
///
/// The shape is `<instance>.<service>.<host>.<domain>` and it always has
/// four segments: a component whose class has no instance dimension
/// carries no `instance` on the wire and takes the literal `001` here.
/// `<service>` is the same wire `service_name` that selected the config
/// entry — never the derived `registration_id`, which is a namespace key
/// and not a certificate field. `domain` comes only from the rendered
/// file.
///
/// This is a third site composing this name, by necessity rather than
/// choice: [`crate::config::profile_domain`] formats it from a
/// `Settings` plus a `DaemonProfileSettings`, and
/// `commands::verify::expected_dns_name` from a `ServiceEntry`, and
/// neither takes bare parts. A test pins byte-identical agreement with
/// the first; the second is private to the binary crate and is named in
/// `docs/reference/registrar-provisioning-config.md` §6.1 instead, along
/// with `commands::dns_alias::dns_alias_for_entry`, which composes the
/// HTTP-01 alias from the same four values and must stay in step for the
/// same reason.
#[must_use]
pub fn compose_san(instance: Option<u32>, service_name: &str, host: &str, domain: &str) -> String {
    let instance = instance.unwrap_or(DEFAULT_SAN_INSTANCE);
    format!("{instance:03}.{service_name}.{host}.{domain}")
}

/// Returns whether a requested spec is the component's single rendered
/// spec.
///
/// Both `cert_group` and `reload` must be equal. It is not a per-field
/// allow-list: independent per-field sets would admit cross-products no
/// component ever declares. An omitted `cert_group` in the rendered spec
/// means the component's registrations must carry none, so a request
/// that supplies one is outside the safe-set.
fn spec_matches(rendered: &RegistrationSpec, requested: &RequestedSpec) -> bool {
    rendered.cert_group == requested.cert_group && rendered.reload == requested.reload
}

impl RegistrarConfig {
    /// Resolves the component's class and runs the identity-shape check
    /// against it, without deriving anything.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrarError::ComponentNotConfigured`] when the
    /// component has no entry, and
    /// [`RegistrarError::ServiceInstanceMismatch`] when `instance`
    /// contradicts its class. These are two distinct variants: the
    /// endpoint collapses both onto one caller-facing identifier, but
    /// the audit record stores the internal one, and a single variant
    /// would erase the difference between a caller sending the wrong
    /// `instance` shape and a caller probing component names that do not
    /// exist.
    pub fn check_identity_shape(
        &self,
        service_name: &str,
        instance: Option<u32>,
    ) -> Result<Multiplicity, RegistrarError> {
        let multiplicity = self.multiplicity(service_name)?;
        check_instance_shape(service_name, multiplicity, instance)?;
        Ok(multiplicity)
    }

    /// Composes the SAN for a request, taking the domain from this
    /// loaded file.
    ///
    /// Prefer this over [`compose_san`] wherever a loaded config is in
    /// hand: it is what makes it structurally impossible for a verb to
    /// compose a name under a domain that arrived on the wire, which is
    /// the whole reason the domain is not a request field.
    #[must_use]
    pub fn san_for(&self, instance: Option<u32>, service_name: &str, host: &str) -> String {
        compose_san(instance, service_name, host, self.domain())
    }

    /// Validates a requested spec against the component's single
    /// rendered spec.
    ///
    /// Callable on its own, after the caller has derived the key and
    /// consulted its durable binding — that ordering is a correctness
    /// requirement, not a preference. Comparison is equality on parsed
    /// values and nothing else: a rendered `reload` target that looks
    /// like a placeholder is a literal string and is not expanded.
    ///
    /// # Errors
    ///
    /// Returns [`RegistrarError::ComponentNotConfigured`] when the
    /// component has no entry, and
    /// [`RegistrarError::ServiceSpecOutsideSafeSet`] when the request
    /// differs from the rendered spec in `cert_group` or `reload`.
    ///
    /// Never returns anything about a *stored* spec — this library has
    /// no access to registration state, and a request that disagrees
    /// with what already exists is the verb layer's `ServiceSpecConflict`
    /// rather than a refusal here.
    pub fn validate_spec(
        &self,
        service_name: &str,
        spec: &RequestedSpec,
    ) -> Result<(), RegistrarError> {
        let entry = self.component(service_name)?;
        if spec_matches(entry.spec(), spec) {
            return Ok(());
        }
        Err(RegistrarError::ServiceSpecOutsideSafeSet {
            component: service_name.to_string(),
        })
    }

    /// Runs every step this library owns, in order, for one request.
    ///
    /// **For tests and callers with no durable state to consult.** The
    /// verb layer must not use it: the per-identity mutex and the
    /// durable-binding collision check belong between the derivation and
    /// the safe-set comparison, and there is nowhere to put them here.
    ///
    /// # Errors
    ///
    /// Returns any variant the individual steps produce.
    pub fn resolve_end_to_end(
        &self,
        service_name: &str,
        host: &str,
        instance: Option<u32>,
        spec: Option<&RequestedSpec>,
    ) -> Result<DerivedIdentity, RegistrarError> {
        validate_request_labels(service_name, host)?;
        if let Some(spec) = spec {
            check_spec_identity(service_name, spec)?;
        }
        let multiplicity = self.check_identity_shape(service_name, instance)?;
        let registration_id = derive_registration_id(multiplicity, service_name, host, instance)?;
        if let Some(spec) = spec {
            self.validate_spec(service_name, spec)?;
        }
        Ok(DerivedIdentity {
            multiplicity,
            registration_id,
            san: self.san_for(instance, service_name, host),
        })
    }
}
