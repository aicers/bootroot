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
//! - [`audit`] is the daemon-owned, append-only record store the
//!   registrar's own audit trail is written to, and the versioned JSON
//!   Lines format it writes. It is public because a reader of the
//!   format needs the record types; the store's construction is not.
//! - [`openbao_audit`] rotates `OpenBao`'s own file audit device in
//!   place, so the generations bootroot owns beside it carry a hard
//!   configured ceiling. It is public for the three bounds and the
//!   budget arithmetic the configuration layer validates against; the
//!   rotation itself is the daemon's.
//!
//! The crate-private `verbs` sibling is the layer above: the
//! transport-free mint and deregister control plane that calls those
//! steps in the one order they are correct in, interleaving its own
//! durable-binding checks between them. It is deliberately not part of
//! the library's public surface — the endpoint that drives it lives in
//! this crate — so no consumer can reach a verb without going through
//! the endpoint's authentication.
//!
//! That endpoint is the crate-private, Linux-only `endpoint` sibling:
//! the systemd-socket-activated `AF_UNIX` listener, its envelope, its
//! peer-credential check and the handler seam the registrar protocol
//! plugs into. [`RegistrarEndpoint`] is the one thing of it the daemon
//! sees — an opaque handle held for the process lifetime and cloned into
//! each daemon invocation, so a `SIGHUP` reload resumes on the same
//! socket inode rather than re-consuming an activation contract that has
//! already been consumed.
//!
//! Nothing here reads or requires registration state. That is what makes
//! the durable-binding collision check the caller's step rather than a
//! missing one here, and it is why no variant in [`error`] refers to a
//! stored or previously applied spec.
//!
//! Alongside that library, this module owns the two names the registrar
//! surface itself is known by, and the primitives that recognize them.
//! bootroot issues one certificate shape for ordinary services:
//! `<instance>.<service_name>.<host>.<domain>` as a single DNS SAN
//! ([`crate::config::profile_domain`]). The registrar surface needs two
//! names that an ordinary `service add` cannot mint, so it reuses that
//! composition and distinguishes itself by a reserved second label under
//! the [`RESERVED_SERVICE_NAME_PREFIX`] namespace:
//!
//! - the **registrar client identity**, [`REGISTRAR_CLIENT_LABEL`], is
//!   the leaf the registrar authenticates to the host-local endpoint
//!   with;
//! - the **endpoint server identity**, [`REGISTRAR_ENDPOINT_LABEL`], is
//!   the leaf the daemon's endpoint presents, and the name a client pins
//!   ([`endpoint_pin`]);
//! - the **bootroot-internal identity**, [`REGISTRAR_INTERNAL_LABEL`],
//!   is the leaf bootroot's own daemon authenticates to `OpenBao` with
//!   at `auth/cert` in order to run the verbs ([`internal`]). It is the
//!   one name of the three that never crosses a wire a caller can
//!   reach.
//!
//! Those items are `pub` on purpose. `service add` lives in the binary
//! crate and reaches the reserved-prefix guard through
//! `bootroot::registrar::…`, while the endpoint's verifier is
//! library-side; a `pub(crate)` item would be invisible to one of them
//! and the sibling that cannot reach it would grow a second list of
//! reserved names.

pub mod audit;
pub mod audit_store;
pub mod config;
#[cfg(target_os = "linux")]
pub(crate) mod endpoint;
pub mod endpoint_pin;
pub mod error;
pub mod fixture;
pub mod identity;
pub mod internal;
pub mod openbao_audit;
pub(crate) mod verbs;

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
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::FromDer;

use crate::input_validation::{
    validate_dns_label, validate_domain_name, validate_numeric_instance_id,
};

/// The namespace prefix bootroot reserves for its own certificate
/// identities. A `service_name` whose ASCII-lowercased form starts with
/// it is refused by `service add`, which is what makes
/// [`recognize_registrar_client`] sound: no operator-driven issuance can
/// produce a name under this prefix.
pub const RESERVED_SERVICE_NAME_PREFIX: &str = "bootroot-";

/// The reserved second label of the registrar's own client identity.
pub const REGISTRAR_CLIENT_LABEL: &str = "bootroot-registrar";

/// The reserved second label of the host-local endpoint's server
/// identity.
pub const REGISTRAR_ENDPOINT_LABEL: &str = "bootroot-registrar-endpoint";

/// The one instance label both registrar *surface* identities are ever
/// composed at.
///
/// There is exactly one registrar and exactly one endpoint per bootroot
/// host, so a varying label would name a multiplicity that does not
/// exist — the same argument `REGISTRAR_INTERNAL_INSTANCE` makes for
/// the third name. It is a constant rather than a literal at each call
/// site so the SAN the daemon composes and the SAN a test asserts
/// cannot drift apart.
pub const REGISTRAR_SURFACE_INSTANCE: &str = "001";

/// The reserved second label of the bootroot-internal privileged
/// identity.
///
/// This is the leaf bootroot's own daemon presents to `OpenBao` at
/// `auth/cert`, and the only name the deployment's trusted auth entry
/// accepts. Unlike the two names above it never appears on a
/// caller-facing wire: nothing outside this process reads it, and no
/// request selects it.
pub const REGISTRAR_INTERNAL_LABEL: &str = "bootroot-registrar-internal";

/// The one instance the bootroot-internal identity is ever composed at.
///
/// There is exactly one internal credential per bootroot host, so the
/// instance label is fixed rather than derived. Spelled as a constant so
/// the SAN composed at provisioning time and the SAN the auth entry
/// allows cannot drift.
const REGISTRAR_INTERNAL_INSTANCE: u32 = 1;

/// Number of labels a registrar identity carries in front of the
/// configured domain suffix: instance, reserved service label, host.
/// The domain itself is a suffix of *any* label count
/// ([`validate_domain_name`] accepts one label or five), so a total
/// label count is never hard-coded — it is always this plus the label
/// count of the configured domain.
const IDENTITY_LEADING_LABELS: usize = 3;

/// Reports whether `value` falls inside bootroot's reserved
/// [`RESERVED_SERVICE_NAME_PREFIX`] namespace.
///
/// The comparison is ASCII-case-insensitive because
/// [`validate_dns_label`] admits mixed case and DNS labels compare
/// case-insensitively, so `BOOTROOT-Registrar` is the same name as
/// `bootroot-registrar`.
///
/// This is the single predicate every bootroot-internal identity is
/// protected by. Callers add reserved names *under* the prefix rather
/// than adding a second guard, so there is only ever one list to
/// consult.
#[must_use]
pub fn is_reserved_service_name(value: &str) -> bool {
    value
        .as_bytes()
        .get(..RESERVED_SERVICE_NAME_PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(RESERVED_SERVICE_NAME_PREFIX.as_bytes()))
}

/// Composes the registrar client identity name
/// `<instance>.bootroot-registrar.<host>.<domain>`.
///
/// `domain` is the configured `network.domain` and is a *suffix* of
/// whatever label count it was configured with, not a single label.
#[must_use]
pub fn registrar_client_identity(instance: &str, host: &str, domain: &str) -> String {
    format!("{instance}.{REGISTRAR_CLIENT_LABEL}.{host}.{domain}")
}

/// Composes the endpoint server identity name
/// `<instance>.bootroot-registrar-endpoint.<host>.<domain>`.
///
/// `domain` is the configured `network.domain` and is a *suffix* of
/// whatever label count it was configured with, not a single label.
#[must_use]
pub fn registrar_endpoint_identity(instance: &str, host: &str, domain: &str) -> String {
    format!("{instance}.{REGISTRAR_ENDPOINT_LABEL}.{host}.{domain}")
}

/// Composes the bootroot-internal identity name
/// `001.bootroot-registrar-internal.<host>.<domain>`.
///
/// Built through [`compose_san`], the same composition every ordinary
/// service leaf goes through, so the internal identity is a name of the
/// deployment's own shape rather than a second naming scheme. `domain`
/// is the configured `network.domain` and is a *suffix* of whatever
/// label count it was configured with, not a single label.
#[must_use]
pub fn registrar_internal_identity(host: &str, domain: &str) -> String {
    compose_san(
        Some(REGISTRAR_INTERNAL_INSTANCE),
        REGISTRAR_INTERNAL_LABEL,
        host,
        domain,
    )
}

/// Why a presented certificate does not carry the one DNS SAN both
/// registrar name rules require.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SanShapeError {
    /// The DER did not parse as an X.509 certificate.
    #[error("certificate could not be parsed")]
    Malformed,
    /// The certificate carries no subject alternative name at all.
    #[error("certificate carries no subject alternative name")]
    Missing,
    /// The certificate carries more than one subject alternative name.
    #[error("certificate carries more than one subject alternative name")]
    Multiple,
    /// The certificate's only subject alternative name is not a DNS
    /// name.
    #[error("certificate's only subject alternative name is not a DNS name")]
    NotDns,
}

/// Returns the single DNS subject alternative name of an end-entity
/// certificate, ASCII-lowercased.
///
/// Both registrar name rules require *exactly one* SAN, of type DNS: a
/// certificate carrying a second name could satisfy the rule under one
/// of its names and be used under another, so more than one is a
/// rejection rather than a search.
///
/// The common name is never consulted. Today's leaves mirror the SAN
/// into the CN, but the CN is not a name a verifier may act on.
///
/// # Errors
///
/// Returns [`SanShapeError`] when the DER does not parse, when the
/// certificate carries no SAN, when it carries more than one, or when
/// its only SAN is not a DNS name.
pub fn single_dns_san(end_entity_der: &[u8]) -> Result<String, SanShapeError> {
    let (_, cert) =
        X509Certificate::from_der(end_entity_der).map_err(|_| SanShapeError::Malformed)?;
    single_dns_san_of(&cert)
}

fn single_dns_san_of(cert: &X509Certificate<'_>) -> Result<String, SanShapeError> {
    let mut names = Vec::new();
    for extension in cert.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            names.extend(san.general_names.iter());
        }
    }
    let mut names = names.into_iter();
    let Some(first) = names.next() else {
        return Err(SanShapeError::Missing);
    };
    if names.next().is_some() {
        return Err(SanShapeError::Multiple);
    }
    match first {
        GeneralName::DNSName(dns) => Ok(dns.to_ascii_lowercase()),
        _ => Err(SanShapeError::NotDns),
    }
}

/// The parsed parts of a recognized registrar client identity, each
/// ASCII-lowercased.
///
/// Recognition establishes *which* identity presented itself, never what
/// it may do: scoping an operation by `host` is the endpoint's decision,
/// not this module's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrarClientIdentity {
    /// The leading instance label, e.g. `001`.
    pub instance: String,
    /// The host label the registrar runs on.
    pub host: String,
    /// The configured domain suffix the name was matched against.
    pub domain: String,
}

/// The parsed parts of a recognized endpoint server identity, each
/// ASCII-lowercased.
///
/// The mirror image of [`RegistrarClientIdentity`]: the same three
/// labels under [`REGISTRAR_ENDPOINT_LABEL`] instead of
/// [`REGISTRAR_CLIENT_LABEL`]. It is a distinct type because the two
/// names authenticate opposite ends of the same connection, and a
/// value of one is never a value of the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrarEndpointIdentity {
    /// The leading instance label, e.g. `001`.
    pub instance: String,
    /// The host label the endpoint serves on.
    pub host: String,
    /// The configured domain suffix the name was matched against.
    pub domain: String,
}

/// Why a presented certificate is not a registrar client identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum RegistrarIdentityError {
    /// The locally configured domain is not a valid DNS name, so no
    /// name could be matched against it.
    #[error("the configured domain is not a valid DNS name")]
    InvalidConfiguredDomain,
    /// The certificate does not carry exactly one DNS SAN.
    #[error(transparent)]
    San(#[from] SanShapeError),
    /// The SAN does not end in the configured domain on a label
    /// boundary.
    #[error("subject alternative name does not end in the configured domain")]
    DomainMismatch,
    /// The SAN does not carry exactly three labels in front of the
    /// configured domain suffix.
    #[error("subject alternative name does not carry exactly three labels before the domain")]
    LabelCount,
    /// The SAN's second label is not [`REGISTRAR_CLIENT_LABEL`].
    #[error("subject alternative name's service label is not the registrar client label")]
    NotRegistrarClient,
    /// The SAN's second label is not [`REGISTRAR_ENDPOINT_LABEL`].
    #[error("subject alternative name's service label is not the registrar endpoint label")]
    NotRegistrarEndpoint,
    /// The SAN's first label is not a numeric instance identifier.
    #[error("subject alternative name's instance label is not numeric")]
    InvalidInstanceLabel,
    /// The SAN's third label is not a valid DNS label.
    #[error("subject alternative name's host label is not a valid DNS label")]
    InvalidHostLabel,
}

/// Recognizes the registrar client identity on an already-verified peer
/// certificate.
///
/// This is a *name* rule and nothing more. It builds no chain, checks no
/// validity window and consults no extended key usage — step-ca's
/// template decides the EKU set of every leaf it issues, so an attribute
/// an ordinary service leaf may also carry cannot discriminate.
/// Recognition is by name, and the name is unmintable through
/// `service add` because of [`is_reserved_service_name`].
///
/// Accepts only when the certificate carries exactly one DNS SAN, that
/// name ends in `domain` on a label boundary, exactly three labels
/// precede the suffix, the second of them is [`REGISTRAR_CLIENT_LABEL`],
/// the first is a numeric instance label and the third a valid DNS
/// label. Every comparison is ASCII-case-insensitive.
///
/// # Errors
///
/// Returns the [`RegistrarIdentityError`] naming the first rule the
/// certificate failed.
pub fn recognize_registrar_client(
    end_entity_der: &[u8],
    domain: &str,
) -> Result<RegistrarClientIdentity, RegistrarIdentityError> {
    let dns_name = single_dns_san(end_entity_der)?;
    recognize_registrar_client_name(&dns_name, domain)
}

/// Applies the registrar client name rule to an already-extracted DNS
/// name.
///
/// Split out from [`recognize_registrar_client`] so the rule can be
/// exercised — and reused — without a certificate in hand.
///
/// # Errors
///
/// Returns the [`RegistrarIdentityError`] naming the first rule the name
/// failed.
pub fn recognize_registrar_client_name(
    dns_name: &str,
    domain: &str,
) -> Result<RegistrarClientIdentity, RegistrarIdentityError> {
    let parts = recognize_registrar_name(
        dns_name,
        domain,
        REGISTRAR_CLIENT_LABEL,
        RegistrarIdentityError::NotRegistrarClient,
    )?;
    Ok(RegistrarClientIdentity {
        instance: parts.instance,
        host: parts.host,
        domain: parts.domain,
    })
}

/// Recognizes the endpoint server identity on a presented certificate.
///
/// The mirror image of [`recognize_registrar_client`], over
/// [`REGISTRAR_ENDPOINT_LABEL`]. It is the rule the daemon holds its
/// *own* endpoint leaf to at startup: the daemon knows only the
/// configured domain — no instance and no host label — so it cannot
/// compose the expected name and compare, and checks the shape instead.
///
/// Like the client rule it builds no chain, checks no validity window
/// and makes no authorization decision.
///
/// # Errors
///
/// Returns the [`RegistrarIdentityError`] naming the first rule the
/// certificate failed.
pub fn recognize_registrar_endpoint(
    end_entity_der: &[u8],
    domain: &str,
) -> Result<RegistrarEndpointIdentity, RegistrarIdentityError> {
    let dns_name = single_dns_san(end_entity_der)?;
    recognize_registrar_endpoint_name(&dns_name, domain)
}

/// Applies the endpoint server name rule to an already-extracted DNS
/// name.
///
/// # Errors
///
/// Returns the [`RegistrarIdentityError`] naming the first rule the name
/// failed.
pub fn recognize_registrar_endpoint_name(
    dns_name: &str,
    domain: &str,
) -> Result<RegistrarEndpointIdentity, RegistrarIdentityError> {
    let parts = recognize_registrar_name(
        dns_name,
        domain,
        REGISTRAR_ENDPOINT_LABEL,
        RegistrarIdentityError::NotRegistrarEndpoint,
    )?;
    Ok(RegistrarEndpointIdentity {
        instance: parts.instance,
        host: parts.host,
        domain: parts.domain,
    })
}

/// The three labels a registrar name carries in front of the configured
/// domain suffix, once the shared rule has accepted them.
struct RegistrarNameParts {
    instance: String,
    host: String,
    domain: String,
}

/// The one name rule both registrar identities are recognized by,
/// parameterized by the reserved service label it requires and the
/// refusal a different label produces.
///
/// Factored rather than duplicated: the client leaf and the endpoint
/// leaf authenticate the two ends of the same connection, so a rule that
/// drifted between them would be a rule only one end enforced.
fn recognize_registrar_name(
    dns_name: &str,
    domain: &str,
    expected_label: &str,
    label_mismatch: RegistrarIdentityError,
) -> Result<RegistrarNameParts, RegistrarIdentityError> {
    if validate_domain_name(domain).is_err() {
        return Err(RegistrarIdentityError::InvalidConfiguredDomain);
    }
    if !dns_name.is_ascii() {
        // A non-ASCII name can match neither an ASCII domain suffix nor
        // `validate_dns_label`, and byte offsets into it are not char
        // boundaries, so it is rejected before any slicing happens.
        return Err(RegistrarIdentityError::DomainMismatch);
    }
    let name = dns_name.to_ascii_lowercase();
    let domain = domain.to_ascii_lowercase();

    // A label-boundary suffix match, never a bare string suffix: the
    // domain `example.internal` must not accept a name ending in
    // `evil-example.internal`.
    let boundary = name
        .len()
        .checked_sub(domain.len() + 1)
        .ok_or(RegistrarIdentityError::DomainMismatch)?;
    let (leading, suffix) = name.split_at(boundary);
    if suffix.strip_prefix('.') != Some(domain.as_str()) {
        return Err(RegistrarIdentityError::DomainMismatch);
    }

    let labels: Vec<&str> = leading.split('.').collect();
    if labels.len() != IDENTITY_LEADING_LABELS {
        return Err(RegistrarIdentityError::LabelCount);
    }
    let (Some(instance), Some(service), Some(host)) =
        (labels.first(), labels.get(1), labels.get(2))
    else {
        return Err(RegistrarIdentityError::LabelCount);
    };
    if !service.eq_ignore_ascii_case(expected_label) {
        return Err(label_mismatch);
    }
    if validate_numeric_instance_id(instance).is_err() {
        return Err(RegistrarIdentityError::InvalidInstanceLabel);
    }
    if validate_dns_label(host).is_err() {
        return Err(RegistrarIdentityError::InvalidHostLabel);
    }
    Ok(RegistrarNameParts {
        instance: (*instance).to_string(),
        host: (*host).to_string(),
        domain,
    })
}

/// A handle to the host-local registrar endpoint, held for the process
/// lifetime and cloned into each daemon invocation.
///
/// Opaque, and empty unless the endpoint is enabled *and* this is a
/// Linux build. The listening socket is inherited from `systemd` exactly
/// once, above the `SIGHUP` loop, so this handle — not a reload — is
/// what carries it across a restart of the daemon task, and what keeps
/// the socket inode the same on the other side.
///
/// It exists on every target so the daemon has one signature to call.
/// On anything but Linux it holds nothing at all, and the endpoint's
/// machinery is not compiled: an enabled setting is refused by
/// [`crate::config::Settings::validate`] before activation is ever
/// looked at.
#[derive(Clone, Default)]
pub struct RegistrarEndpoint {
    #[cfg(target_os = "linux")]
    inner: Option<std::sync::Arc<endpoint::ActivatedEndpoint>>,
}

impl RegistrarEndpoint {
    /// Consumes the systemd socket-activation contract once and adopts
    /// the inherited listening socket.
    ///
    /// A disabled endpoint reads no activation variable, touches no
    /// descriptor, loads no certificate material and returns an empty
    /// handle, so a deployment that never asked for the endpoint behaves
    /// exactly as it did before it existed. This process's environment
    /// is never mutated, in either case.
    ///
    /// # Errors
    ///
    /// Returns an error when the endpoint is enabled and cannot be
    /// served: a missing or misaddressed
    /// activation contract, a descriptor that is not a listening
    /// `AF_UNIX` stream socket or whose address is not a pathname, or a
    /// socket pathname whose mode, owner or parent directory fails
    /// policy, or server or client TLS material that is absent,
    /// unusable or not what a pinned caller would accept. On a
    /// non-Linux target an enabled endpoint is an error in itself.
    pub fn activate(settings: &crate::config::Settings) -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                inner: endpoint::activate(settings)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            if settings.registrar_endpoint.enabled {
                anyhow::bail!(
                    "the registrar endpoint is supported on Linux only; \
                     set registrar_endpoint.enabled = false"
                );
            }
            Ok(Self::default())
        }
    }

    /// Reports whether this handle carries a listening socket.
    #[must_use]
    pub fn is_active(&self) -> bool {
        #[cfg(target_os = "linux")]
        {
            self.inner.is_some()
        }
        #[cfg(not(target_os = "linux"))]
        {
            false
        }
    }

    /// Returns the adopted endpoint, for the daemon's accept task.
    #[cfg(target_os = "linux")]
    pub(crate) fn activated(&self) -> Option<std::sync::Arc<endpoint::ActivatedEndpoint>> {
        self.inner.clone()
    }
}

impl std::fmt::Debug for RegistrarEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegistrarEndpoint")
            .field("active", &self.is_active())
            .finish()
    }
}

/// Tests for the reserved-prefix guard and the registrar name rules.
/// The config loader and the derivation library are covered by the
/// sibling [`tests`] module.
#[cfg(test)]
mod recognition_tests {
    use rcgen::{CertificateParams, IsCa, KeyPair, SanType};

    use super::*;

    const TWO_LABEL_DOMAIN: &str = "example.internal";
    const ONE_LABEL_DOMAIN: &str = "internal";
    const THREE_LABEL_DOMAIN: &str = "corp.example.internal";

    /// Self-signs a leaf carrying exactly the given subject alternative
    /// names, and returns its DER.
    fn certificate_with_sans(sans: Vec<SanType>) -> Vec<u8> {
        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params.is_ca = IsCa::NoCa;
        params.subject_alt_names = sans;
        params
            .self_signed(&key)
            .expect("self-signed certificate")
            .der()
            .to_vec()
    }

    fn certificate_with_dns_san(name: &str) -> Vec<u8> {
        certificate_with_sans(vec![SanType::DnsName(
            name.to_string().try_into().expect("valid DNS SAN"),
        )])
    }

    #[test]
    fn reserved_prefix_covers_the_whole_bootroot_namespace() {
        for value in [
            "bootroot-registrar",
            "BOOTROOT-Registrar",
            "bootroot-registrar-endpoint",
            "bootroot-anything",
            "bootroot-",
        ] {
            assert!(is_reserved_service_name(value), "{value}");
        }
    }

    /// Ordinary component keywords are unaffected, including the ones
    /// that merely start with the letters of the prefix but do not carry
    /// the hyphen that makes it a namespace.
    #[test]
    fn reserved_prefix_leaves_ordinary_service_names_alone() {
        for value in ["roxyd", "piglet", "edge-proxy", "bootroot", "bootrootish"] {
            assert!(!is_reserved_service_name(value), "{value}");
        }
    }

    #[test]
    fn identity_names_compose_the_reserved_labels() {
        assert_eq!(
            registrar_client_identity("001", "h1", TWO_LABEL_DOMAIN),
            "001.bootroot-registrar.h1.example.internal"
        );
        assert_eq!(
            registrar_endpoint_identity("001", "h1", TWO_LABEL_DOMAIN),
            "001.bootroot-registrar-endpoint.h1.example.internal"
        );
    }

    /// Both reserved labels must stay usable as single DNS labels, since
    /// they occupy one label of the SAN.
    #[test]
    fn reserved_labels_are_valid_dns_labels() {
        assert_eq!(validate_dns_label(REGISTRAR_CLIENT_LABEL), Ok(()));
        assert_eq!(validate_dns_label(REGISTRAR_ENDPOINT_LABEL), Ok(()));
    }

    /// The expected label count is derived from the configured domain,
    /// never hard-coded: the same name shape is accepted under a
    /// one-, two- and three-label domain.
    #[test]
    fn recognizes_the_registrar_under_domains_of_differing_label_counts() {
        for domain in [ONE_LABEL_DOMAIN, TWO_LABEL_DOMAIN, THREE_LABEL_DOMAIN] {
            let name = registrar_client_identity("001", "h1", domain);
            let der = certificate_with_dns_san(&name);
            let identity = recognize_registrar_client(&der, domain)
                .unwrap_or_else(|err| panic!("{domain} should be recognized: {err}"));
            assert_eq!(
                identity,
                RegistrarClientIdentity {
                    instance: "001".to_string(),
                    host: "h1".to_string(),
                    domain: domain.to_string(),
                }
            );
        }
    }

    #[test]
    fn recognition_returns_the_parsed_parts() {
        let der = certificate_with_dns_san("007.bootroot-registrar.edge-node-01.example.internal");
        let identity = recognize_registrar_client(&der, TWO_LABEL_DOMAIN).expect("recognized");
        assert_eq!(identity.instance, "007");
        assert_eq!(identity.host, "edge-node-01");
        assert_eq!(identity.domain, TWO_LABEL_DOMAIN);
    }

    #[test]
    fn recognition_is_ascii_case_insensitive() {
        let der = certificate_with_dns_san("001.BOOTROOT-Registrar.H1.Example.Internal");
        let identity = recognize_registrar_client(&der, "EXAMPLE.internal").expect("recognized");
        assert_eq!(identity.host, "h1");
        assert_eq!(identity.domain, TWO_LABEL_DOMAIN);
    }

    /// Each rejection is distinguishable, so a caller can tell "not the
    /// registrar" from "malformed certificate".
    #[test]
    fn recognition_rejects_each_near_miss_distinguishably() {
        for (name, expected) in [
            // An ordinary service leaf, including the registrar host's
            // own: same host, same domain, ordinary second label.
            (
                "001.roxyd.h1.example.internal",
                RegistrarIdentityError::NotRegistrarClient,
            ),
            // The right reserved label, the wrong number of labels in
            // front of the domain suffix.
            (
                "bootroot-registrar.h1.example.internal",
                RegistrarIdentityError::LabelCount,
            ),
            (
                "001.extra.bootroot-registrar.h1.example.internal",
                RegistrarIdentityError::LabelCount,
            ),
            // The endpoint's own server identity is not a client
            // identity.
            (
                "001.bootroot-registrar-endpoint.h1.example.internal",
                RegistrarIdentityError::NotRegistrarClient,
            ),
            // A suffix that is not the configured domain, including the
            // non-boundary near-miss.
            (
                "001.bootroot-registrar.h1.evil-example.internal",
                RegistrarIdentityError::DomainMismatch,
            ),
            (
                "001.bootroot-registrar.h1.example.public",
                RegistrarIdentityError::DomainMismatch,
            ),
            (
                "001.bootroot-registrar.h1.internal",
                RegistrarIdentityError::DomainMismatch,
            ),
            // A non-numeric instance label, and a host label that is not
            // a DNS label.
            (
                "abc.bootroot-registrar.h1.example.internal",
                RegistrarIdentityError::InvalidInstanceLabel,
            ),
            (
                "001.bootroot-registrar.-h1.example.internal",
                RegistrarIdentityError::InvalidHostLabel,
            ),
        ] {
            let der = certificate_with_dns_san(name);
            assert_eq!(
                recognize_registrar_client(&der, TWO_LABEL_DOMAIN),
                Err(expected),
                "{name}"
            );
        }
    }

    /// `evil-example.internal` shares a string suffix with the
    /// configured `example.internal` but not a label boundary — and it
    /// carries the *same* total label count as the name that would be
    /// accepted, so nothing but the boundary rule stands between it and
    /// acceptance. A bare `ends_with` would let it through.
    #[test]
    fn recognition_never_matches_a_non_boundary_domain_suffix() {
        let accepted = registrar_client_identity("001", "h1", TWO_LABEL_DOMAIN);
        let near_miss = registrar_client_identity("001", "h1", "evil-example.internal");
        assert_eq!(
            accepted.split('.').count(),
            near_miss.split('.').count(),
            "the near miss must differ from the accepted name only in the suffix"
        );
        assert!(near_miss.ends_with(TWO_LABEL_DOMAIN));

        let der = certificate_with_dns_san(&near_miss);
        assert_eq!(
            recognize_registrar_client(&der, TWO_LABEL_DOMAIN),
            Err(RegistrarIdentityError::DomainMismatch)
        );
        assert!(recognize_registrar_client_name(&accepted, TWO_LABEL_DOMAIN).is_ok());
    }

    #[test]
    fn recognition_rejects_a_certificate_with_more_than_one_san() {
        let der = certificate_with_sans(vec![
            SanType::DnsName(
                registrar_client_identity("001", "h1", TWO_LABEL_DOMAIN)
                    .try_into()
                    .expect("valid DNS SAN"),
            ),
            SanType::DnsName(
                "other.example.internal"
                    .to_string()
                    .try_into()
                    .expect("san"),
            ),
        ]);
        assert_eq!(
            recognize_registrar_client(&der, TWO_LABEL_DOMAIN),
            Err(RegistrarIdentityError::San(SanShapeError::Multiple))
        );
    }

    #[test]
    fn recognition_rejects_a_certificate_whose_only_san_is_not_a_dns_name() {
        let der = certificate_with_sans(vec![SanType::IpAddress(std::net::IpAddr::from([
            10, 0, 0, 1,
        ]))]);
        assert_eq!(
            recognize_registrar_client(&der, TWO_LABEL_DOMAIN),
            Err(RegistrarIdentityError::San(SanShapeError::NotDns))
        );
    }

    #[test]
    fn recognition_rejects_a_certificate_with_no_san() {
        let der = certificate_with_sans(Vec::new());
        assert_eq!(
            recognize_registrar_client(&der, TWO_LABEL_DOMAIN),
            Err(RegistrarIdentityError::San(SanShapeError::Missing))
        );
    }

    #[test]
    fn recognition_rejects_unparseable_der() {
        assert_eq!(
            recognize_registrar_client(b"not a certificate", TWO_LABEL_DOMAIN),
            Err(RegistrarIdentityError::San(SanShapeError::Malformed))
        );
    }

    #[test]
    fn recognition_rejects_an_invalid_configured_domain() {
        assert_eq!(
            recognize_registrar_client_name("001.bootroot-registrar.h1.bad_domain", "bad_domain"),
            Err(RegistrarIdentityError::InvalidConfiguredDomain)
        );
    }

    /// The endpoint rule is the same rule under the other reserved
    /// label, so an endpoint name is accepted and its parts come back
    /// lowercased.
    #[test]
    fn recognizes_the_endpoint_server_identity() {
        let name = registrar_endpoint_identity("007", "H1", TWO_LABEL_DOMAIN);
        assert_eq!(
            recognize_registrar_endpoint_name(&name, TWO_LABEL_DOMAIN),
            Ok(RegistrarEndpointIdentity {
                instance: "007".to_string(),
                host: "h1".to_string(),
                domain: TWO_LABEL_DOMAIN.to_string(),
            })
        );
        let der = certificate_with_dns_san(&name);
        assert_eq!(
            recognize_registrar_endpoint(&der, TWO_LABEL_DOMAIN),
            Ok(RegistrarEndpointIdentity {
                instance: "007".to_string(),
                host: "h1".to_string(),
                domain: TWO_LABEL_DOMAIN.to_string(),
            })
        );
    }

    /// The two rules are mirror images and neither accepts the other's
    /// name — which is what keeps a client leaf from serving as the
    /// endpoint's, and the reverse.
    #[test]
    fn the_two_registrar_rules_do_not_accept_each_others_names() {
        let client = registrar_client_identity("001", "h1", TWO_LABEL_DOMAIN);
        let endpoint = registrar_endpoint_identity("001", "h1", TWO_LABEL_DOMAIN);
        assert_eq!(
            recognize_registrar_endpoint_name(&client, TWO_LABEL_DOMAIN),
            Err(RegistrarIdentityError::NotRegistrarEndpoint)
        );
        assert_eq!(
            recognize_registrar_client_name(&endpoint, TWO_LABEL_DOMAIN),
            Err(RegistrarIdentityError::NotRegistrarClient)
        );
    }

    /// Every rule the shared helper applies still applies under the
    /// endpoint label: the domain is a label-boundary suffix, the label
    /// count is exact, and the instance and host labels are checked.
    #[test]
    fn endpoint_recognition_rejects_each_near_miss_distinguishably() {
        for (name, domain, expected) in [
            (
                "001.bootroot-registrar-endpoint.h1.evil-example.internal",
                TWO_LABEL_DOMAIN,
                RegistrarIdentityError::DomainMismatch,
            ),
            (
                "extra.001.bootroot-registrar-endpoint.h1.example.internal",
                TWO_LABEL_DOMAIN,
                RegistrarIdentityError::LabelCount,
            ),
            (
                "001.bootroot-registrar-endpointer.h1.example.internal",
                TWO_LABEL_DOMAIN,
                RegistrarIdentityError::NotRegistrarEndpoint,
            ),
            (
                "abc.bootroot-registrar-endpoint.h1.example.internal",
                TWO_LABEL_DOMAIN,
                RegistrarIdentityError::InvalidInstanceLabel,
            ),
            (
                "001.bootroot-registrar-endpoint.-h1.example.internal",
                TWO_LABEL_DOMAIN,
                RegistrarIdentityError::InvalidHostLabel,
            ),
            (
                "001.bootroot-registrar-endpoint.h1.bad_domain",
                "bad_domain",
                RegistrarIdentityError::InvalidConfiguredDomain,
            ),
        ] {
            assert_eq!(
                recognize_registrar_endpoint_name(name, domain),
                Err(expected),
                "{name} under {domain}"
            );
        }
    }

    /// The endpoint rule holds the same one-DNS-SAN requirement, so a
    /// certificate carrying a second name is refused rather than
    /// searched.
    #[test]
    fn endpoint_recognition_requires_exactly_one_dns_san() {
        let der = certificate_with_sans(vec![
            SanType::DnsName(
                registrar_endpoint_identity("001", "h1", TWO_LABEL_DOMAIN)
                    .try_into()
                    .expect("valid DNS SAN"),
            ),
            SanType::DnsName("other.example.internal".try_into().expect("valid DNS SAN")),
        ]);
        assert_eq!(
            recognize_registrar_endpoint(&der, TWO_LABEL_DOMAIN),
            Err(RegistrarIdentityError::San(SanShapeError::Multiple))
        );
    }

    /// A one-label and a three-label domain both work here too: the
    /// suffix is matched at whatever label count it was configured
    /// with.
    #[test]
    fn recognizes_the_endpoint_under_domains_of_differing_label_counts() {
        for domain in [ONE_LABEL_DOMAIN, TWO_LABEL_DOMAIN, THREE_LABEL_DOMAIN] {
            let name = registrar_endpoint_identity("001", "h1", domain);
            let identity = recognize_registrar_endpoint_name(&name, domain)
                .unwrap_or_else(|err| panic!("{name} under {domain}: {err}"));
            assert_eq!(identity.domain, domain);
            assert_eq!(identity.host, "h1");
        }
    }
}
