//! What the two verbs return: the envelope every outcome carries, the
//! typed refusals, and the redacting newtype the wrapped credential
//! rides in.
//!
//! These are **in-process** types. The endpoint owns serialization and
//! the caller-facing identifiers; nothing here maps onto a wire name, and
//! several distinctions kept here — safe-set refusal versus stored-spec
//! conflict, component absence versus instance-shape mismatch — are ones
//! the wire contract deliberately groups. Keeping them apart internally
//! is what lets an audit record say which of them happened after the wire
//! has collapsed them.

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

use time::OffsetDateTime;

use crate::registrar::audit::{AuditPhase, AuditStoreError};
use crate::registrar::error::RegistrarError;
use crate::registrar::verbs::wrap_ttl::WrapTtlRefusal;
use crate::service_material::TeardownReport;

/// Bytes of randomness in a generated request id.
const REQUEST_ID_RANDOM_BYTES: usize = 9;

/// Monotonic tail, so two ids minted in one process are distinct even if
/// the system random source is unavailable.
static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A correlation handle for one verb invocation, generated at entry.
///
/// Not a secret and not an idempotency key: it correlates an audit
/// record with a response, and nothing is cached under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestId(String);

impl RequestId {
    /// Generates a fresh request id.
    pub(crate) fn generate() -> Self {
        let sequence = REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        match crate::utils::generate_secret(REQUEST_ID_RANDOM_BYTES) {
            Ok(random) => Self(format!("{random}.{sequence}")),
            // A correlation handle is still useful without the random
            // half, and refusing the whole request because the system
            // random source hiccuped would be a worse outcome than a
            // handle that is unique only within this process.
            Err(_) => Self(format!("seq.{sequence}")),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_fixture(value: &str) -> Self {
        Self(value.to_string())
    }

    /// Returns the handle.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The caller's identity, carried through a verb **unchanged**.
///
/// Opaque on purpose. The verbs never parse it, never authenticate it,
/// never select an `OpenBao` client from it and never derive any part of
/// an identity from it — the derived `registration_id` and the SAN come
/// from the request's parts and the rendered config alone. It exists so
/// an outcome says who asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallerIdentity(String);

impl CallerIdentity {
    /// Wraps a caller identity verbatim.
    pub(crate) fn new(value: &str) -> Self {
        Self(value.to_string())
    }

    /// Returns the identity exactly as it was supplied.
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Which arm of a verb produced an outcome.
///
/// The arms are ordered as the verbs run them, so an outcome records how
/// far a request got before it stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProducingArm {
    /// Label validation, the reserved-name guard, component lookup and
    /// the instance-shape check — everything that runs before any id
    /// exists.
    PreDerivation,
    /// Deriving the `registration_id` and the SAN.
    Derivation,
    /// Reading, claiming or comparing the durable binding.
    Binding,
    /// Comparing the requested spec against the rendered safe-set.
    SafeSet,
    /// Converging the derived role and policy.
    Provisioning,
    /// Issuing the wrap-only credential.
    Issuance,
    /// Deleting the identity's material.
    Teardown,
}

/// The envelope every outcome of either verb carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerbContext {
    request_id: RequestId,
    caller: CallerIdentity,
    registration_id: Option<String>,
    arm: ProducingArm,
}

impl VerbContext {
    pub(crate) fn new(
        request_id: RequestId,
        caller: CallerIdentity,
        registration_id: Option<String>,
        arm: ProducingArm,
    ) -> Self {
        Self {
            request_id,
            caller,
            registration_id,
            arm,
        }
    }

    /// Returns the invocation's correlation handle.
    pub(crate) fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the caller identity, exactly as it arrived.
    pub(crate) fn caller(&self) -> &CallerIdentity {
        &self.caller
    }

    /// Returns the derived `registration_id`, which is `None` for every
    /// outcome produced before derivation.
    pub(crate) fn registration_id(&self) -> Option<&str> {
        self.registration_id.as_deref()
    }

    /// Returns the arm that produced this outcome.
    pub(crate) fn arm(&self) -> ProducingArm {
        self.arm
    }
}

/// A response-wrapping token, held so it cannot be printed by accident.
///
/// The wrapped token is single-use material: whoever holds it can unwrap
/// the `secret_id` once. `Debug` prints `<redacted>` by hand, so a
/// `#[derive(Debug)]` on any enclosing outcome — which is how these
/// values reach a log line — cannot leak it, and there is no `Display`
/// at all.
///
/// It derives nothing else either. `Clone` would let a caller keep a
/// copy alongside the one it sent, which is what the consuming accessor
/// on [`MintOutcome`] exists to prevent, and a derived `PartialEq` on a
/// secret-bearing type is a byte-at-a-time timing oracle. Neither is
/// needed: the token is moved out once, at the endpoint's serialization
/// boundary, and never compared.
pub(crate) struct WrappedSecretIdToken(String);

impl WrappedSecretIdToken {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// Consumes the newtype and yields the raw token.
    fn into_inner(self) -> String {
        self.0
    }
}

impl fmt::Debug for WrappedSecretIdToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// Which successful mint arm produced the material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MintKind {
    /// The identity did not exist: this request claimed the binding,
    /// converged the role and policy, activated the binding and issued.
    FirstMint,
    /// The identity already existed, bound to this host with a matching
    /// spec. The role and policy were reused untouched and only fresh
    /// wrap-only material was issued.
    IdempotentReMint,
}

/// A successful mint.
#[derive(Debug)]
pub(crate) struct MintOutcome {
    context: VerbContext,
    kind: MintKind,
    san: String,
    role_id: String,
    wrapped_secret_id: WrappedSecretIdToken,
    expires_at: OffsetDateTime,
}

impl MintOutcome {
    pub(crate) fn new(
        context: VerbContext,
        kind: MintKind,
        san: String,
        role_id: String,
        wrapped_secret_id: WrappedSecretIdToken,
        expires_at: OffsetDateTime,
    ) -> Self {
        Self {
            context,
            kind,
            san,
            role_id,
            wrapped_secret_id,
            expires_at,
        }
    }

    /// Returns the outcome's envelope.
    pub(crate) fn context(&self) -> &VerbContext {
        &self.context
    }

    /// Returns which mint arm produced this material.
    pub(crate) fn kind(&self) -> MintKind {
        self.kind
    }

    /// Returns the composed certificate SAN for this identity.
    pub(crate) fn san(&self) -> &str {
        &self.san
    }

    /// Returns the service `AppRole`'s `role_id`.
    pub(crate) fn role_id(&self) -> &str {
        &self.role_id
    }

    /// Returns the **granted** absolute deadline: the wrap token's
    /// creation time plus the TTL `OpenBao` actually reported, so an
    /// `OpenBao`-side clamp is reflected here as well as the registrar's
    /// own.
    pub(crate) fn expires_at(&self) -> OffsetDateTime {
        self.expires_at
    }

    /// Consumes the outcome and yields the wrapped token.
    ///
    /// Consuming on purpose, and on the outcome rather than on the
    /// newtype: the token moves to the endpoint at its serialization
    /// boundary and nowhere else, so no caller has to clone it, inspect
    /// it, or hold a copy alongside the one it sent.
    pub(crate) fn into_wrapped_secret_id(self) -> String {
        self.wrapped_secret_id.into_inner()
    }
}

/// Which successful deregister arm produced the outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DeregisterKind {
    /// A binding for this host existed and was removed, after its
    /// material was torn down.
    IdentityRemoved,
    /// No binding existed. The material sweep still ran, and the result
    /// is the idempotent re-drive the verb pair is built around.
    AlreadyAbsent,
}

/// A successful deregister.
#[derive(Debug)]
pub(crate) struct DeregisterOutcome {
    context: VerbContext,
    kind: DeregisterKind,
    teardown: TeardownReport,
}

impl DeregisterOutcome {
    pub(crate) fn new(
        context: VerbContext,
        kind: DeregisterKind,
        teardown: TeardownReport,
    ) -> Self {
        Self {
            context,
            kind,
            teardown,
        }
    }

    /// Returns the outcome's envelope.
    pub(crate) fn context(&self) -> &VerbContext {
        &self.context
    }

    /// Returns which deregister arm produced this outcome.
    pub(crate) fn kind(&self) -> DeregisterKind {
        self.kind
    }

    /// Returns the per-resource teardown report.
    pub(crate) fn teardown(&self) -> &TeardownReport {
        &self.teardown
    }
}

/// Every refusal the two verbs produce.
///
/// The refusals the config loader and the derivation library already
/// declare are **wrapped**, never redeclared: there is one definition of
/// "this component has no entry" in the repository and this is not a
/// second one. What is added here is only what those checks cannot see,
/// because it depends on the reserved namespace, on durable state, or on
/// the registrar's own bounded policy.
#[derive(Debug, thiserror::Error)]
pub(crate) enum VerbError {
    /// The wire `service_name` is inside bootroot's reserved
    /// `bootroot-` namespace. Refused case-insensitively, and refused
    /// **before** the component lookup, so an operator configuration
    /// that happened to declare a reserved key could still never make
    /// ordinary issuance mint a registrar identity.
    #[error("service_name {service_name:?} is inside bootroot's reserved namespace")]
    ReservedServiceName {
        /// The offending value, verbatim.
        service_name: String,
    },

    /// A refusal the config loader or the derivation library produced:
    /// an invalid label, an absent component, an instance-shape
    /// mismatch, a spec-identity disagreement, a derivation failure, or
    /// a safe-set refusal. Individually matchable through this one arm.
    #[error(transparent)]
    Registrar(#[from] RegistrarError),

    /// The derived `registration_id` is already bound to a **different**
    /// host. Raised before any spec comparison, because the rendered
    /// spec is host-agnostic and a spec-first flow would match and
    /// re-wrap the first host's identity for the second.
    #[error(
        "registration_id {registration_id} is bound to host {stored_host}, so host \
         {requested_host} cannot claim it"
    )]
    RegistrationIdCollision {
        /// The derived key both hosts arrived at.
        registration_id: String,
        /// The host the binding records.
        stored_host: String,
        /// The host that asked.
        requested_host: String,
    },

    /// The identity exists, is bound to this host, and was minted with a
    /// different spec. Distinct from a safe-set refusal: the request may
    /// be inside the rendered safe-set and still disagree with what this
    /// identity already carries.
    #[error("registration_id {registration_id} is already bound with a different spec")]
    StoredSpecConflict {
        /// The identity whose stored spec disagreed.
        registration_id: String,
    },

    /// A deregister whose `host` is not the identity's bound host.
    /// Changes nothing at all.
    #[error(
        "registration_id {registration_id} is bound to host {stored_host}, not {requested_host}"
    )]
    HostMismatch {
        /// The identity that was asked about.
        registration_id: String,
        /// The host the binding records.
        stored_host: String,
        /// The host that asked.
        requested_host: String,
    },

    /// The requested `wrap_ttl` cannot produce a usable credential
    /// lifetime.
    ///
    /// Not one of the durable-state refusals above, and deliberately its
    /// own arm rather than folded into [`VerbError::Unavailable`]: it is
    /// a permanent property of the request, not a transient property of
    /// the registrar, and a caller that retried it unchanged would fail
    /// identically forever.
    #[error("requested wrap_ttl is not usable")]
    InvalidWrapTtl(#[from] WrapTtlRefusal),

    /// An audit record could not be written, on an invocation that
    /// changed no `OpenBao` state.
    ///
    /// Two writes produce it: the **intent** write, which precedes every
    /// `OpenBao` call and so refuses with nothing created at all, and an
    /// **outcome** write on an invocation whose mutation disposition is
    /// still clear. Which one is in [`VerbError::AuditUnwritable::phase`]
    /// and is inferable from nothing else on the refusal:
    /// [`ProducingArm`] says how far the *verb* got and has no member
    /// that tells an intent write from an outcome write.
    ///
    /// The name is the one `docs/reference/registrar-wire-contract.md`
    /// §6.5 records for the closed `RegistrarUnavailable` reason set, and
    /// is adopted rather than coined here. That set describes it as
    /// "intent phase only", which is narrower than the condition above;
    /// the divergence is deliberate, because narrowing the condition to
    /// fit the name would leave a non-mutating outcome-write failure
    /// unreported. The endpoint's `map_refusal` maps both phases onto
    /// the transcribed reason; the locally owned half of the wire
    /// reference records that decision and why.
    #[error("the registrar could not write the {phase} audit record")]
    AuditUnwritable {
        /// The write that failed. Reused from the record format rather
        /// than restated, so a third phase breaks this `match` too.
        phase: AuditPhase,
        /// The store's own typed failure.
        #[source]
        source: AuditStoreError,
    },

    /// The outcome record could not be written on an invocation that
    /// did, or may have, changed `OpenBao` state.
    ///
    /// A teardown is owed: the identity may exist, or may have been
    /// removed, and no durable outcome line says which. A successful
    /// mint that lands here does **not** return its material — the
    /// wrapped `secret_id` is dropped and expires unused — so a caller
    /// re-drives the verb once the store recovers and receives fresh
    /// material then.
    ///
    /// It carries no phase, and that is not an oversight: only an
    /// outcome write can produce it, because the disposition cannot be
    /// set before the intent write has already succeeded.
    ///
    /// Like [`VerbError::AuditUnwritable`], the name comes from the wire
    /// contract's §6.5 reason set, which describes it as following "a
    /// successful mint". The condition here is wider — every invocation
    /// whose disposition is set, refusals and completed removals
    /// included — and is deliberately not narrowed to fit the name.
    #[error("the registrar changed OpenBao state but could not record the outcome")]
    PostMintUnrecordable {
        /// The store's own typed failure.
        #[source]
        source: AuditStoreError,
    },

    /// A fail-closed failure: `OpenBao` was unreachable or answered
    /// unexpectedly, a stored binding could not be read, or a
    /// convergence step failed. Nothing was rolled back — a binding this
    /// request claimed is deliberately retained.
    #[error("the registrar could not complete the request while {activity}")]
    Unavailable {
        /// What was being attempted, for the audit record.
        activity: String,
        /// The underlying failure.
        #[source]
        source: anyhow::Error,
    },
}

impl VerbError {
    /// Builds an [`VerbError::Unavailable`] from an underlying failure.
    pub(crate) fn unavailable(activity: &str, source: anyhow::Error) -> Self {
        Self::Unavailable {
            activity: activity.to_string(),
            source,
        }
    }
}

/// A refused invocation: the envelope plus the typed refusal, and — for
/// a deregister that got as far as tearing material down — whatever the
/// teardown managed.
#[derive(Debug)]
pub(crate) struct VerbRefusal {
    context: VerbContext,
    /// Boxed because this is the `Err` half of every verb's `Result`,
    /// and the enum is wide enough that carrying it inline made the
    /// whole `Result` bigger than the success path warrants — the cost
    /// is one allocation on the cold refusal path instead of a fatter
    /// return value on every call.
    error: Box<VerbError>,
    teardown: Option<TeardownReport>,
}

impl VerbRefusal {
    pub(crate) fn new(context: VerbContext, error: VerbError) -> Self {
        Self {
            context,
            error: Box::new(error),
            teardown: None,
        }
    }

    /// Attaches the teardown report a partially-completed deregister
    /// produced, so the caller can see which resources are still there.
    pub(crate) fn with_teardown(mut self, teardown: TeardownReport) -> Self {
        self.teardown = Some(teardown);
        self
    }

    /// Returns the refusal's envelope.
    pub(crate) fn context(&self) -> &VerbContext {
        &self.context
    }

    /// Returns the typed refusal.
    pub(crate) fn error(&self) -> &VerbError {
        &self.error
    }

    /// Returns the teardown report, when the refusal came from a
    /// deregister that had already attempted one.
    pub(crate) fn teardown(&self) -> Option<&TeardownReport> {
        self.teardown.as_ref()
    }
}

/// The mint verb's result.
pub(crate) type MintResult = Result<MintOutcome, VerbRefusal>;

/// The deregister verb's result.
pub(crate) type DeregisterResult = Result<DeregisterOutcome, VerbRefusal>;
