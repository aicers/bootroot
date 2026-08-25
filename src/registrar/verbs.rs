//! The registrar's two restricted verbs: mint an identity, and
//! deregister one.
//!
//! This is a **transport-free** control plane. There is no socket, no
//! codec, no peer authentication and no serialization here — the
//! endpoint owns all of that. What is here is the decision procedure,
//! expressed over in-process types, so it can be tested without a
//! transport and so the transport cannot quietly acquire a decision of
//! its own.
//!
//! # What a caller may and may not influence
//!
//! A request carries an opaque caller identity and the identity's
//! **parts**: `service_name`, `host`, an optional numeric `instance`,
//! and — for a mint — the requested spec and a requested `wrap_ttl`. It
//! carries no composed name, no `registration_id`, no domain, no policy
//! body, no role definition, no policy list and no credential. The
//! privileged `OpenBao` client, the KV mount, the loaded config, the
//! fixed [`SecretIdOptions`], the role-level TTLs and the bounded
//! wrap-TTL policy are **construction** dependencies, so no request can
//! select any of them.
//!
//! The caller identity is carried into every outcome unchanged and is
//! used for nothing else: it is never parsed, never authenticated, never
//! used to pick a client, and no part of the derived identity comes from
//! it.
//!
//! # The fixed order
//!
//! Both verbs run the same three stages, and the order is a correctness
//! requirement rather than a preference:
//!
//! 1. **Pre-derivation**, **stateless and unsynchronized**: validate the
//!    two labels, refuse a reserved `service_name`, resolve the
//!    component's multiplicity from the rendered config, and check the
//!    instance shape. Mint also checks the spec's identity restatement
//!    here. Every refusal on this arm carries **no** `registration_id`,
//!    because none has been computed.
//! 2. **Derivation** of the `registration_id` and the SAN. Fallible even
//!    after the labels validated — the ≤131-octet bound is enforced on
//!    the derived string — and a derivation failure takes no per-id lock
//!    and performs no `OpenBao` or binding operation at all.
//! 3. **Per-id work**, under the `registration_id`'s own
//!    [`tokio::sync::Mutex`], shared by both verbs so a mint and a
//!    deregister for one identity can never interleave.
//!
//! # The limiter in front of those stages
//!
//! Stage 1 runs **before** the intent write, so that the invocation's
//! rate-limit bucket is knowable before anything durable happens. Every
//! check in it is pure — no I/O, no lock, nothing outside the process —
//! so running it early costs nothing and changes no answer it produces,
//! and what it produced is carried forward rather than recomputed. With
//! those checks refusing, the invocation is charged its
//! `predecision_refusal` bucket; with them passing, its `admission`
//! bucket. Only then does the intent write happen. See [`limiter`] for
//! the buckets themselves and for what their isolation does and does not
//! guarantee.
//!
//! An invocation whose bucket was empty is **limited**: neither record is
//! written and one event is published. On the pre-decision path it still
//! receives the refusal its own input earned — limiting suppresses the
//! record, never the answer — while at admission the verb is not
//! attempted at all and the caller receives
//! [`VerbError::Throttled`]. An intent write that *fails* is a different
//! thing entirely: it happens after the charge, on an invocation whose
//! pure checks passed, so it has already spent an `admission` token like
//! any other admitted invocation.
//!
//! # The audit trail around those stages
//!
//! Every invocation that gets past the limiter attempts **two** record
//! writes into the daemon-owned store: an `intent` line at entry, after
//! stage 1 and therefore still before any `OpenBao` call, and an
//! `outcome` line once the verb has run. The two are paired by `request_id` rather
//! than by adjacency — intent lines are ordered only by arrival, which
//! is correct, because nothing holds a lock across a whole invocation.
//! The outcome line for a result produced under the per-id guard is
//! written **before that guard is released**, so the next invocation for
//! the same identity cannot change `OpenBao` and land its outcome line
//! ahead of the line describing the change it superseded.
//!
//! Neither write is best-effort. A failed intent write refuses the
//! invocation with nothing created, which is free at that point. A
//! failed outcome write may arrive after `OpenBao` has already changed,
//! so what it returns is decided by a per-invocation **mutation
//! disposition** — see [`MutationDisposition`] — and by nothing else:
//! not the verb, not the outcome class, not the [`ProducingArm`], and
//! not a re-read of `OpenBao`.
//!
//! The `OpenBao` file audit device stays mandatory and is not replaced.
//! It cannot see a request refused before any `OpenBao` write, and it
//! does not know who asked or for which `(service_name, host,
//! instance)`; this trail does.
//!
//! Stage 3's per-id lock is the **only** in-process serialization
//! boundary either verb has. Its map is owned by this module rather than
//! by a service instance, so two [`RegistrarVerbs`] in one process
//! serialize against each other on one derived id instead of each
//! holding a private lock for it. Stages 1 and 2 read only immutable
//! per-instance configuration and call pure functions, so nothing there
//! needs guarding and independent validations run concurrently. The
//! limiter is the one entry-stage feature that *does* carry shared
//! state, and it synchronizes that state itself rather than reinstating
//! a blanket entry lock over everything before derivation: its lock is
//! taken and released inside one synchronous charge, and is never held
//! across an `OpenBao` call or a record write.
//!
//! Inside stage 3 the binding is consulted **before** the safe-set:
//! a different stored host is a collision, a same-host different spec is
//! a conflict, and only after both does the requested spec get compared
//! against the rendered safe-set. The rendered spec is host-agnostic, so
//! a safe-set-first flow would match for a second host and re-wrap the
//! first host's identity for it.
//!
//! # Why compare-and-set, and why the claim is never rolled back
//!
//! The per-id mutex is a *process* lock. Another process — a second
//! registrar, an operator's CLI — can write the same `OpenBao` namespace,
//! so a new binding is claimed with the absent-only
//! [`OpenBaoClient::create_kv_if_absent`] and the loser is told so rather
//! than overwriting. Once that claim wins, it is **retained** through any
//! subsequent failure: a `creating` binding whose convergence died is
//! what keeps whatever role or policy did get created covered by a
//! durable claim. Rolling it back would manufacture exactly the unbound
//! orphan the binding exists to prevent. The matching host recovers
//! through a mint re-drive or through deregister; every other host stays
//! refused.
//!
//! # The accepted hazard
//!
//! A deregister with **no** binding still sweeps the full service-material
//! set and reports already-absent. That is deliberate — it is how an
//! identity whose binding was lost gets cleaned up — and it means a
//! manually deleted binding, or an identity created through the direct
//! CLI, can leave live material sweepable by a registrar deregister for
//! the same derived id. The alternative is an intent marker or a second
//! state store, and both were rejected: a second store has the same
//! divergence problem one layer up. The hazard is documented rather than
//! masked.

// Two separate things here are unreached from production code, and
// neither is worth a per-item allow. The endpoint that drives these
// verbs is served off a systemd-activated socket and so is Linux-only:
// on any other host nothing constructs a `RegistrarVerbs` at all, which
// makes the whole layer dead and takes the parts of
// `crate::registrar::audit` only these verbs call down with it. And on
// Linux the daemon reaches them through `RegistrarVerbs::internal`
// alone, which leaves the injectable constructor and the accessors only
// tests read behind. The alternatives are worse: publishing the module
// would put a privileged control plane on the library's public surface,
// and per-item allows would have to be undone one at a time as the
// remaining wire grammar lands.
#![allow(dead_code)]

pub(crate) mod binding;
pub(crate) mod limiter;
pub(crate) mod outcome;
pub(crate) mod wrap_ttl;

#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex as StdMutex, PoisonError, Weak};

use anyhow::Context as _;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{Mutex as TokioMutex, OwnedMutexGuard};

use self::binding::{BindingRecord, BindingSpec, BindingState, REGISTRAR_BINDING_KV_SUFFIX};
use self::limiter::{ChargeOutcome, LimiterBucket, VerbRateLimiter};
use self::outcome::{
    CallerIdentity, DeregisterKind, DeregisterOutcome, DeregisterResult, MintKind, MintOutcome,
    MintResult, ProducingArm, RequestId, VerbContext, VerbError, VerbRefusal, WrappedSecretIdToken,
};
use self::wrap_ttl::{GrantedWrapTtl, WrapTtlPolicy};
use crate::openbao::{KvCreateIfAbsent, OpenBaoClient, SecretIdOptions, WrapInfo};
use crate::registrar::audit::{
    AuditOutcome, AuditPhase, AuditRecord, AuditRecordStore, AuditVerb, RequestedIdentity, bridge,
};
use crate::registrar::config::{Multiplicity, RegistrarConfig};
use crate::registrar::identity::{RequestedSpec, check_instance_shape, derive_registration_id};
use crate::registrar::internal::{InternalCredential, InternalCredentialError};
use crate::registrar::{check_spec_identity, is_reserved_service_name, validate_request_labels};
use crate::service_material::{
    ProvisionedServiceRole, ResourceOutcome, ServiceRoleTtls, provision_service_role,
    service_kv_path, service_role_name, teardown_service_material,
};
use crate::trust_bootstrap::{
    SERVICE_EAB_KV_SUFFIX, SERVICE_REISSUE_KV_SUFFIX, SERVICE_RESPONDER_HMAC_KV_SUFFIX,
    SERVICE_SECRET_ID_KV_SUFFIX, SERVICE_TRUST_KV_SUFFIX,
};

/// Every service-material suffix a registrar-managed identity owns.
///
/// The registrar always sweeps all five, `reissue` included. The CLI's
/// `service remove` intentionally keeps its narrower state-derived set
/// and continues not to delete `reissue`, which leaves its reissue
/// inheritance hazard in place for CLI-managed identities; removing it
/// here is what keeps that hazard off registrar-managed ones.
///
/// The registrar binding is **not** in this set. It outlives the material
/// and is deleted separately, only after this sweep reports aggregate
/// success.
pub(crate) const REGISTRAR_TEARDOWN_KV_SUFFIXES: [&str; 5] = [
    SERVICE_EAB_KV_SUFFIX,
    SERVICE_RESPONDER_HMAC_KV_SUFFIX,
    SERVICE_TRUST_KV_SUFFIX,
    SERVICE_SECRET_ID_KV_SUFFIX,
    SERVICE_REISSUE_KV_SUFFIX,
];

/// The one per-`registration_id` lock map the whole process shares.
///
/// Ownership is deliberately the module's rather than a service
/// instance's. Two [`RegistrarVerbs`] built over one `OpenBao` namespace
/// — a re-rendered config, a second endpoint — derive the same
/// `registration_id` from the same parts, and a per-instance map would
/// hand each of them a private lock for it, letting one instance's mint
/// interleave with another's deregister. The absent-only compare-and-set
/// is the *cross-process* ownership primitive and stays exactly that; it
/// cannot serialize a mint against a deregister inside one process, and
/// this map cannot serialize anything outside it.
static ID_LOCKS: LazyLock<IdLocks> = LazyLock::new(IdLocks::default);

/// How many times a mint re-reads the binding after losing the
/// compare-and-set race before giving up as unavailable.
///
/// Losing the race means somebody else wrote the binding, so the re-read
/// finds one and the loop ends. A second lost race can only mean that
/// binding was deleted between the read and the claim, which is a
/// deregister racing this mint from another process; a bound retry keeps
/// a pathological pair of processes from spinning here forever.
const MAX_CLAIM_ATTEMPTS: usize = 3;

/// Whether one invocation has made an `OpenBao` call that can have
/// changed durable state.
///
/// Set from the *result* of each such call and **never cleared**, so it
/// is monotone over the invocation. Reads never set it — a binding read,
/// a `role_id` read, acquiring an authenticated client — and neither
/// does a lost compare-and-set, which wrote nothing at all; that is why
/// exhausting [`MAX_CLAIM_ATTEMPTS`] refuses with it still clear.
///
/// Every *error* does set it, and that asymmetry is the whole point. A
/// call that failed may have failed after its write reached `OpenBao`,
/// and the two ways of being wrong are not symmetrical: reporting a
/// change as an ordinary refusal leaves live, unrecorded state that
/// nobody is told to clean up, while reporting an unchanged invocation
/// as owed costs at most one idempotent re-drive that finds nothing. A
/// `ResourceOutcome::Failed` teardown attempt is indeterminate in
/// exactly the same way and counts the same.
///
/// It is shared behind `&` across `.await` points in a `Send` future, so
/// an [`AtomicBool`] is the shape to use; the value is per-invocation and
/// is read by the same task that set it, so no ordering stronger than
/// the module already uses is needed.
#[derive(Debug, Default)]
struct MutationDisposition(AtomicBool);

impl MutationDisposition {
    /// Records that a call which can have changed `OpenBao` state has
    /// completed, however it completed.
    fn set(&self) {
        self.0.store(true, Ordering::Relaxed);
    }

    /// Records the outcome of a state-changing call and hands its result
    /// straight back, so the call site reads as it did before.
    fn note<T, E>(&self, result: Result<T, E>) -> Result<T, E> {
        self.set();
        result
    }

    /// Reports whether this invocation is owed a teardown.
    fn is_set(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }
}

/// Everything one invocation's two record writes need.
///
/// Built at verb entry, before stage 1. The caller identity and the
/// requested parts are carried into the builders **unchanged and
/// uninterpreted**: whatever [`CallerIdentity`] holds is what the record
/// is handed, and what a durable line ends up saying is the store's
/// business — `AuditRecord::into_bounded` caps the field and records a
/// digest when it had to. Nothing here pre-truncates or works around
/// that.
struct AuditContext {
    request_id: RequestId,
    verb: AuditVerb,
    caller: CallerIdentity,
    requested: RequestedIdentity,
    disposition: MutationDisposition,
}

impl AuditContext {
    /// Opens the context for one invocation, generating its request id.
    fn new(verb: AuditVerb, caller: &CallerIdentity, requested: RequestedIdentity) -> Self {
        Self {
            request_id: RequestId::generate(),
            verb,
            caller: caller.clone(),
            requested,
            disposition: MutationDisposition::default(),
        }
    }

    /// Builds the record shared by both phases: the timestamp, the
    /// correlation handle, the verb, the caller and the requested parts.
    fn intent_record(&self) -> AuditRecord {
        AuditRecord::intent(
            OffsetDateTime::now_utc(),
            self.request_id.as_str().to_string(),
            self.verb,
            self.caller.as_str().to_string(),
            self.requested.clone(),
        )
    }

    /// Builds the `outcome` line for a produced result.
    fn outcome_record(&self, registration_id: Option<&str>, outcome: AuditOutcome) -> AuditRecord {
        AuditRecord::outcome(
            OffsetDateTime::now_utc(),
            self.request_id.as_str().to_string(),
            self.verb,
            self.caller.as_str().to_string(),
            self.requested.clone(),
            registration_id.map(str::to_string),
            outcome,
        )
    }
}

/// The fixed dependencies a [`RegistrarVerbs`] is constructed with.
///
/// Every one of these is chosen once, by whatever provisions the
/// registrar, and none of them is reachable from a request.
pub(crate) struct RegistrarVerbsConfig {
    /// A privileged `OpenBao` client. Its provisioning and renewal are
    /// somebody else's problem; this module only uses it.
    pub(crate) client: OpenBaoClient,
    /// The KV v2 mount every path is written under.
    pub(crate) kv_mount: String,
    /// The loaded, digest-verified registrar config.
    pub(crate) config: RegistrarConfig,
    /// The fixed per-issuance `secret_id` options. No request selects
    /// TTL, use count, metadata or token-bound CIDRs.
    pub(crate) secret_id_options: SecretIdOptions,
    /// Role-level `token_ttl`.
    pub(crate) token_ttl: String,
    /// Role-level `secret_id_ttl`.
    pub(crate) secret_id_ttl: String,
    /// The bounded wrap-TTL policy: the maximum, and the rules a
    /// requested value is validated under.
    pub(crate) wrap_ttl_policy: WrapTtlPolicy,
    /// The daemon-owned audit record store, already opened.
    ///
    /// A fixed dependency like every other field here: the verb layer
    /// receives a handle and can neither choose the path it writes to
    /// nor decline to have one. Whatever provisions the registrar
    /// surface opens the store first, so an unsafe or unusable store
    /// fails that surface closed rather than leaving the verbs running
    /// with no trail.
    ///
    /// Both verbs write through it, twice per invocation, and an
    /// invocation whose record cannot be written is refused rather than
    /// served silently — see this module's header.
    pub(crate) audit_store: AuditRecordStore,
    /// The two-bucket token limiter both verbs are charged against
    /// before either record is written.
    ///
    /// A fixed dependency like the store beside it: the verbs receive it
    /// and can neither choose its sizing nor decline to have one, and
    /// nothing in a request reaches it. Whoever provisions the registrar
    /// surface builds it from the four `registrar.rate_limit_*` keys and
    /// the sink it wants events published through.
    pub(crate) limiter: VerbRateLimiter,
}

/// The fixed, client-free dependencies [`RegistrarVerbs::internal`] is
/// built from.
///
/// Every member is a location or a policy the deployment already fixed.
/// There is deliberately no `client` here and no caller: the privileged
/// client is constructed inside the factory from the credential on
/// disk, which is what makes it unreachable from a request.
pub(crate) struct InternalVerbsSource<'a> {
    /// The state-recorded secrets directory the credential lives below.
    pub(crate) secrets_dir: &'a std::path::Path,
    /// The recorded `OpenBao` URL. Must be `https://`.
    pub(crate) openbao_url: &'a str,
    /// Hex SHA-256 of the deployment's **active** root.
    ///
    /// Compared with the fingerprint stored beside the credential before
    /// anything is built. A mismatch means the `auth/cert` entry no
    /// longer trusts this leaf, so the factory returns repair-required
    /// and the verbs never exist — no ACME request, no login and no
    /// write is made on a credential that cannot work.
    ///
    /// This is the fail-fast, not the guarantee. A verbs object outlives
    /// its construction, and a full rotation replaces the root while one
    /// is in hand, so the credential re-reads the active root from
    /// `secrets_dir` before every acquisition of its login and refuses
    /// there too.
    pub(crate) active_root_fingerprint: &'a str,
    /// The KV v2 mount every path is written under.
    pub(crate) kv_mount: &'a str,
    /// The loaded, digest-verified registrar config.
    pub(crate) config: &'a RegistrarConfig,
    /// The fixed per-issuance `secret_id` options.
    pub(crate) secret_id_options: &'a SecretIdOptions,
    /// Role-level `token_ttl`.
    pub(crate) token_ttl: &'a str,
    /// Role-level `secret_id_ttl`.
    pub(crate) secret_id_ttl: &'a str,
    /// The bounded wrap-TTL policy.
    pub(crate) wrap_ttl_policy: &'a WrapTtlPolicy,
    /// The daemon-owned audit record store, already opened.
    ///
    /// Borrowed and cloned into the service, as every clone shares one
    /// serialization lock: whatever provisions the registrar surface
    /// opens the store and keeps its own handle. Like every other
    /// member here it is a fixed dependency, so the client-free factory
    /// no more chooses where the trail is written than it chooses which
    /// credential it logs in with.
    pub(crate) audit_store: &'a AuditRecordStore,
    /// The two-bucket token limiter, borrowed and cloned into the
    /// service as every clone shares one map and one sink. A fixed
    /// dependency exactly as the store above is.
    pub(crate) limiter: &'a VerbRateLimiter,
}

/// A mint request: an opaque caller plus the identity's parts.
#[derive(Debug, Clone)]
pub(crate) struct MintRequest {
    /// Carried into the outcome unchanged; used for nothing else.
    pub(crate) caller: CallerIdentity,
    /// The component's plain keyword, a single DNS label.
    pub(crate) service_name: String,
    /// The target host's single DNS label.
    pub(crate) host: String,
    /// The instance number, present exactly for a many-per-host
    /// component.
    pub(crate) instance: Option<u32>,
    /// The requested registration spec.
    pub(crate) spec: RequestedSpec,
    /// The *requested* wrapped-material lifetime. The registrar clamps
    /// it to its own maximum and the granted deadline is computed, never
    /// echoed.
    pub(crate) wrap_ttl: time::Duration,
}

/// A deregister request: an opaque caller plus the identity's parts.
#[derive(Debug, Clone)]
pub(crate) struct DeregisterRequest {
    /// Carried into the outcome unchanged; used for nothing else.
    pub(crate) caller: CallerIdentity,
    /// The component's plain keyword, a single DNS label.
    pub(crate) service_name: String,
    /// The host the caller claims the identity is bound to.
    pub(crate) host: String,
    /// The instance number, present exactly for a many-per-host
    /// component.
    pub(crate) instance: Option<u32>,
}

/// Where a verb's privileged `OpenBao` client comes from.
///
/// Two arms, and the asymmetry is the point. Production takes
/// [`VerbClientSource::Internal`], which builds its own
/// certificate-authenticated client from the bootroot-internal
/// credential, re-reads the active root before every acquisition, and
/// re-authenticates before expiry — no caller supplies it, and no
/// request can select it. Tests take
/// [`VerbClientSource::Injected`], which is the pre-existing
/// construction and keeps the transport-free tests transport-free.
pub(crate) enum VerbClientSource {
    /// A client the constructor was handed. Test-only in practice: the
    /// production factory never takes this arm.
    Injected(OpenBaoClient),
    /// The bootroot-internal credential, which mints its own client.
    Internal(InternalCredential),
}

impl VerbClientSource {
    /// Returns a client carrying a live token.
    ///
    /// For the internal arm this is where the active root is compared
    /// again: a verb reached after the deployment root changed refuses
    /// with repair-required, having made no login and no write.
    async fn live(&self) -> Result<OpenBaoClient, VerbError> {
        match self {
            Self::Injected(client) => Ok(client.clone()),
            Self::Internal(credential) => credential.authenticated().await.map_err(|err| {
                VerbError::unavailable(
                    "authenticating with the bootroot-internal credential",
                    anyhow::Error::new(err),
                )
            }),
        }
    }

    /// Reports a failed request so an expired token is dropped from the
    /// cache and the next verb authenticates again.
    async fn note_failure(&self, error: &anyhow::Error) {
        if let Self::Internal(credential) = self {
            credential.note_failure(error).await;
        }
    }
}

/// The registrar's restricted verb service.
pub(crate) struct RegistrarVerbs {
    client: VerbClientSource,
    kv_mount: String,
    config: RegistrarConfig,
    secret_id_options: SecretIdOptions,
    token_ttl: String,
    secret_id_ttl: String,
    wrap_ttl_policy: WrapTtlPolicy,
    audit_store: AuditRecordStore,
    limiter: VerbRateLimiter,
}

impl RegistrarVerbs {
    /// Creates the verb service from its fixed dependencies, over a
    /// client the caller supplies.
    ///
    /// Retained for the tests, which drive the decision procedure
    /// against a mock `OpenBao`. Production uses
    /// [`RegistrarVerbs::internal`], which takes no client at all.
    pub(crate) fn new(config: RegistrarVerbsConfig) -> Self {
        Self {
            client: VerbClientSource::Injected(config.client),
            kv_mount: config.kv_mount,
            config: config.config,
            secret_id_options: config.secret_id_options,
            token_ttl: config.token_ttl,
            secret_id_ttl: config.secret_id_ttl,
            wrap_ttl_policy: config.wrap_ttl_policy,
            audit_store: config.audit_store,
            limiter: config.limiter,
        }
    }

    /// Creates the verb service over the bootroot-internal credential.
    ///
    /// **Takes no client and no caller.** Everything it needs is a
    /// location or a fixed policy: where the secrets tree is, which URL
    /// `OpenBao` answers on, which KV mount the deployment uses, and the
    /// rendered registrar config. The privileged client is built here,
    /// from the credential on disk, and cannot be reached, replaced or
    /// selected from a request.
    ///
    /// # Errors
    ///
    /// Returns [`InternalCredentialError`] when the recorded `OpenBao`
    /// URL is plaintext, when the credential is absent, partial or
    /// invalid, or when the root it was issued under is no longer the
    /// deployment's active one. No network request is made in any of
    /// those cases, and none is made on success either: the certificate
    /// login happens on the first verb, behind a second comparison of
    /// the stored root with the one then on disk.
    pub(crate) fn internal(
        source: &InternalVerbsSource<'_>,
    ) -> Result<Self, InternalCredentialError> {
        let credential = InternalCredential::load(
            source.secrets_dir,
            source.openbao_url,
            source.active_root_fingerprint,
        )?;
        Ok(Self {
            client: VerbClientSource::Internal(credential),
            kv_mount: source.kv_mount.to_string(),
            config: source.config.clone(),
            secret_id_options: source.secret_id_options.clone(),
            token_ttl: source.token_ttl.to_string(),
            secret_id_ttl: source.secret_id_ttl.to_string(),
            wrap_ttl_policy: source.wrap_ttl_policy.clone(),
            audit_store: source.audit_store.clone(),
            limiter: source.limiter.clone(),
        })
    }

    /// Returns a privileged client carrying a live token.
    async fn client(&self) -> Result<OpenBaoClient, VerbError> {
        self.client.live().await
    }

    /// Returns the audit record store this service was constructed
    /// with.
    pub(crate) fn audit_store(&self) -> &AuditRecordStore {
        &self.audit_store
    }

    /// Returns the limiter this service was constructed with.
    pub(crate) fn limiter(&self) -> &VerbRateLimiter {
        &self.limiter
    }

    /// Mints — or idempotently re-mints — one service identity and
    /// returns fresh wrap-only material for it.
    pub(crate) async fn mint(&self, request: &MintRequest) -> MintResult {
        let audit = AuditContext::new(
            AuditVerb::Mint,
            &request.caller,
            requested_identity(&request.service_name, &request.host, request.instance),
        );
        let refuse = |arm: ProducingArm, registration_id: Option<String>, error: VerbError| {
            VerbRefusal::new(
                VerbContext::new(
                    audit.request_id.clone(),
                    audit.caller.clone(),
                    registration_id,
                    arm,
                ),
                error,
            )
        };

        // Stage 1, run first and exactly once. Every check in it is
        // pure — no I/O, no lock, nothing outside the process — so
        // running it ahead of the intent write costs nothing and changes
        // no answer it produces, and it is what makes the invocation's
        // bucket knowable before anything durable happens. What it
        // produced is carried forward below rather than recomputed.
        //
        // The wrap TTL belongs here with it: it is a purely local
        // property of the request, checked under the
        // construction-supplied policy well before any OpenBao call, so
        // an unusable request never creates material that would then
        // have to be revoked — and a flood of out-of-range values is as
        // free to an attacker as a flood of malformed labels.
        let classified = self
            .pre_derivation(
                &request.service_name,
                &request.host,
                request.instance,
                Some(&request.spec),
            )
            .and_then(|multiplicity| {
                let granted = self.wrap_ttl_policy.grant(request.wrap_ttl)?;
                Ok((multiplicity, granted))
            });

        // The charge, before the intent write: a limiter that ran after
        // it could not suppress the record it exists to suppress, and
        // would make that record the amplifier for the exhaustion it is
        // preventing.
        if let Some(retry_after) = self.charge(&audit, bucket_for(classified.is_ok())) {
            let error = match classified {
                // Limited on the pre-decision path. The caller's answer
                // is preserved exactly — same VerbError, same wire
                // identifier or same absence of one, same RefusalClass —
                // and only the records are suppressed.
                Err(err) => err,
                // Throttled at admission, where the daemon has
                // determined nothing, so this adds an answer rather than
                // replacing one. The verb is not attempted at all.
                Ok(_) => VerbError::Throttled { retry_after },
            };
            return Err(refuse(ProducingArm::PreDerivation, None, error));
        }

        // Admitted, so the invocation continues into the flow that
        // existed before the limiter. A store that cannot take this line
        // refuses the invocation here, where refusing is free: nothing
        // has been derived and nothing has been created, which is what
        // the arm and the absent registration_id both say.
        if let Err(err) = self.write_intent(&audit).await {
            return Err(refuse(ProducingArm::PreDerivation, None, err));
        }

        let (multiplicity, granted) = match classified {
            Ok(classified) => classified,
            Err(err) => {
                let refusal = refuse(ProducingArm::PreDerivation, None, err);
                return Err(self.record_refusal(&audit, refusal).await);
            }
        };

        // Stage 2. Derivation is fallible even after the labels
        // validated, and a failure here takes no per-id lock.
        let registration_id = match derive_registration_id(
            multiplicity,
            &request.service_name,
            &request.host,
            request.instance,
        ) {
            Ok(registration_id) => registration_id,
            Err(err) => {
                let refusal = refuse(ProducingArm::Derivation, None, VerbError::Registrar(err));
                return Err(self.record_refusal(&audit, refusal).await);
            }
        };
        let san = self
            .config
            .san_for(request.instance, &request.service_name, &request.host);

        // Stage 3. The outcome record is written while the per-id guard
        // is still held: releasing it first would let the next
        // invocation for this identity claim the binding, change
        // `OpenBao` and land its outcome line ahead of the line
        // describing the change it just superseded.
        let id_guard = self.id_locks().acquire(&registration_id).await;
        let result = self
            .mint_locked(
                request,
                &audit.request_id,
                &registration_id,
                &san,
                &granted,
                &audit.disposition,
            )
            .await;
        let recorded = self.record_mint(&audit, result).await;
        drop(id_guard);
        recorded
    }

    /// Tears one service identity down and removes its durable binding.
    pub(crate) async fn deregister(&self, request: &DeregisterRequest) -> DeregisterResult {
        let audit = AuditContext::new(
            AuditVerb::Deregister,
            &request.caller,
            requested_identity(&request.service_name, &request.host, request.instance),
        );
        let refuse = |arm: ProducingArm, registration_id: Option<String>, error: VerbError| {
            VerbRefusal::new(
                VerbContext::new(
                    audit.request_id.clone(),
                    audit.caller.clone(),
                    registration_id,
                    arm,
                ),
                error,
            )
        };

        // Identical to the mint's, and deliberately so, save that a
        // deregister carries no wrap TTL: stage 1 first and once, then
        // the charge, then the one intent write per invocation.
        let classified =
            self.pre_derivation(&request.service_name, &request.host, request.instance, None);

        if let Some(retry_after) = self.charge(&audit, bucket_for(classified.is_ok())) {
            let error = match classified {
                Err(err) => err,
                Ok(_) => VerbError::Throttled { retry_after },
            };
            return Err(refuse(ProducingArm::PreDerivation, None, error));
        }

        if let Err(err) = self.write_intent(&audit).await {
            return Err(refuse(ProducingArm::PreDerivation, None, err));
        }

        let multiplicity = match classified {
            Ok(multiplicity) => multiplicity,
            Err(err) => {
                let refusal = refuse(ProducingArm::PreDerivation, None, err);
                return Err(self.record_refusal(&audit, refusal).await);
            }
        };

        let registration_id = match derive_registration_id(
            multiplicity,
            &request.service_name,
            &request.host,
            request.instance,
        ) {
            Ok(registration_id) => registration_id,
            Err(err) => {
                let refusal = refuse(ProducingArm::Derivation, None, VerbError::Registrar(err));
                return Err(self.record_refusal(&audit, refusal).await);
            }
        };

        // As in the mint: the outcome line is written under the guard.
        let id_guard = self.id_locks().acquire(&registration_id).await;
        let result = self
            .deregister_locked(
                request,
                &audit.request_id,
                &registration_id,
                &audit.disposition,
            )
            .await;
        let recorded = self.record_deregister(&audit, result).await;
        drop(id_guard);
        recorded
    }

    /// Charges one invocation against its bucket, before either record
    /// is written.
    ///
    /// Returns `None` when a token was available and the invocation may
    /// proceed. Returns `Some(retry_after)` when the charged bucket was
    /// empty, in which case the invocation is **limited**: neither
    /// record is written, and the limiter has already published its one
    /// limited-invocation event. Only the admission check point turns
    /// that value into a caller-facing throttle; on the pre-decision
    /// path it is discarded and the caller keeps its own refusal.
    ///
    /// **A limited invocation writes nothing per invocation anywhere,
    /// the daemon log included.** The sink event is in-process and
    /// counted; a `tracing` line per limited invocation would be one
    /// unbounded write per flooded request, which is the disk pressure
    /// the buckets exist to remove — reintroduced on the very path they
    /// were meant to make cheap. What a flood leaves behind is the
    /// sink's per-bucket count, and coalescing that into a record
    /// belongs to the sibling record issue.
    ///
    /// Synchronous, and the bucket lock is taken and released inside the
    /// limiter, so nothing here holds it across an `OpenBao` call or a
    /// record write.
    fn charge(&self, audit: &AuditContext, bucket: LimiterBucket) -> Option<u64> {
        match self.limiter.charge(&audit.caller, audit.verb, bucket) {
            ChargeOutcome::Admitted => None,
            ChargeOutcome::Limited { retry_after } => Some(retry_after),
        }
    }

    /// Writes the invocation's `intent` line.
    ///
    /// # Errors
    ///
    /// Returns [`VerbError::AuditUnwritable`] carrying
    /// [`AuditPhase::Intent`] for every way the store can fail. There is
    /// no fallback: the write is not buffered, deferred, retried into a
    /// second file or substituted with a log line. The `tracing` event
    /// below carries the store's own error, which may be finer than the
    /// variant a caller eventually sees, and stands in for nothing.
    async fn write_intent(&self, audit: &AuditContext) -> Result<(), VerbError> {
        match self.audit_store.append(audit.intent_record()).await {
            Ok(()) => Ok(()),
            Err(err) => {
                tracing::error!(
                    error = %err,
                    request_id = audit.request_id.as_str(),
                    verb = ?audit.verb,
                    phase = AuditPhase::Intent.as_str(),
                    "the registrar audit record could not be written; refusing the invocation \
                     with nothing created"
                );
                Err(VerbError::AuditUnwritable {
                    phase: AuditPhase::Intent,
                    source: err,
                })
            }
        }
    }

    /// Writes the invocation's `outcome` line.
    ///
    /// # Errors
    ///
    /// Returns [`VerbError::PostMintUnrecordable`] when the mutation
    /// disposition is set and [`VerbError::AuditUnwritable`] carrying
    /// [`AuditPhase::Outcome`] when it is clear. Which store error it
    /// was does not enter into that — every one of them is a write
    /// failure for this phase, `Sync` and `DirectorySync` included.
    async fn write_outcome(
        &self,
        audit: &AuditContext,
        registration_id: Option<&str>,
        outcome: AuditOutcome,
    ) -> Result<(), VerbError> {
        let record = audit.outcome_record(registration_id, outcome);
        match self.audit_store.append(record).await {
            Ok(()) => Ok(()),
            Err(err) => {
                let owed = audit.disposition.is_set();
                tracing::error!(
                    error = %err,
                    request_id = audit.request_id.as_str(),
                    verb = ?audit.verb,
                    phase = AuditPhase::Outcome.as_str(),
                    teardown_owed = owed,
                    "the registrar audit record could not be written"
                );
                Err(if owed {
                    VerbError::PostMintUnrecordable { source: err }
                } else {
                    VerbError::AuditUnwritable {
                        phase: AuditPhase::Outcome,
                        source: err,
                    }
                })
            }
        }
    }

    /// Records a mint's result and returns what the caller gets.
    ///
    /// A successful mint whose outcome write failed does **not** return
    /// its material: the freshly issued wrapped `secret_id` is dropped
    /// and expires unused. The caller is told the identity exists and a
    /// teardown is owed, and re-driving the mint once the store recovers
    /// issues fresh material.
    async fn record_mint(&self, audit: &AuditContext, result: MintResult) -> MintResult {
        match result {
            Ok(outcome) => {
                let written = self
                    .write_outcome(
                        audit,
                        outcome.context().registration_id(),
                        bridge::mint_outcome(outcome.kind()),
                    )
                    .await;
                match written {
                    Ok(()) => Ok(outcome),
                    Err(err) => Err(VerbRefusal::new(outcome.context().clone(), err)),
                }
            }
            Err(refusal) => Err(self.record_refusal(audit, refusal).await),
        }
    }

    /// Records a deregister's result and returns what the caller gets.
    ///
    /// A sweep that ran is still reported: the teardown report rides
    /// out on the refusal a failed outcome write produces, so the caller
    /// sees what was deleted.
    async fn record_deregister(
        &self,
        audit: &AuditContext,
        result: DeregisterResult,
    ) -> DeregisterResult {
        match result {
            Ok(outcome) => {
                let written = self
                    .write_outcome(
                        audit,
                        outcome.context().registration_id(),
                        bridge::deregister_outcome(outcome.kind()),
                    )
                    .await;
                match written {
                    Ok(()) => Ok(outcome),
                    Err(err) => Err(VerbRefusal::new(outcome.context().clone(), err)
                        .with_teardown(outcome.teardown().clone())),
                }
            }
            Err(refusal) => Err(self.record_refusal(audit, refusal).await),
        }
    }

    /// Records a refusal and returns the refusal the caller gets: the
    /// one the verb produced, or the audit failure that replaced it.
    ///
    /// A replacement keeps the produced refusal's own envelope — the arm
    /// says how far the verb got, which is still true — and its teardown
    /// report, which is the only account of what the sweep managed.
    async fn record_refusal(&self, audit: &AuditContext, refusal: VerbRefusal) -> VerbRefusal {
        let Some(outcome) = bridge::refusal_outcome(refusal.error()) else {
            // Neither audit-failure variant is recordable, by
            // construction: the record that would carry one is the
            // record whose write just failed. Nothing is written and the
            // refusal is returned unchanged.
            return refusal;
        };
        match self
            .write_outcome(audit, refusal.context().registration_id(), outcome)
            .await
        {
            Ok(()) => refusal,
            Err(err) => {
                let replaced = VerbRefusal::new(refusal.context().clone(), err);
                match refusal.teardown() {
                    Some(teardown) => replaced.with_teardown(teardown.clone()),
                    None => replaced,
                }
            }
        }
    }

    /// Stage 1, shared by both verbs: stateless, synchronous, and
    /// **unsynchronized**.
    ///
    /// It reads only this instance's immutable construction dependencies
    /// and calls pure validators, so there is no shared mutable state to
    /// guard and independent requests validate concurrently. The only
    /// in-process serialization boundary either verb has is the shared
    /// per-`registration_id` lock taken in stage 3, and fallible
    /// derivation completes before that lock is acquired. Anything added
    /// here that *does* carry shared state brings its own
    /// synchronization for that state; it does not reintroduce a lock
    /// over the whole stage.
    ///
    /// `spec` is `Some` only for a mint: the spec's identity restatement
    /// is a mint-only pre-derivation refusal, because a deregister
    /// carries no spec to restate anything with.
    fn pre_derivation(
        &self,
        service_name: &str,
        host: &str,
        instance: Option<u32>,
        spec: Option<&RequestedSpec>,
    ) -> Result<Multiplicity, VerbError> {
        validate_request_labels(service_name, host)?;
        // Before the component lookup, so no operator configuration can
        // make ordinary issuance mint a registrar identity by declaring
        // a component under the reserved prefix.
        if is_reserved_service_name(service_name) {
            return Err(VerbError::ReservedServiceName {
                service_name: service_name.to_string(),
            });
        }
        if let Some(spec) = spec {
            check_spec_identity(service_name, spec)?;
        }
        let multiplicity = self.config.multiplicity(service_name)?;
        check_instance_shape(service_name, multiplicity, instance)?;
        Ok(multiplicity)
    }

    async fn mint_locked(
        &self,
        request: &MintRequest,
        request_id: &RequestId,
        registration_id: &str,
        san: &str,
        granted: &GrantedWrapTtl,
        disposition: &MutationDisposition,
    ) -> MintResult {
        let refuse = |arm: ProducingArm, error: VerbError| {
            VerbRefusal::new(
                VerbContext::new(
                    request_id.clone(),
                    request.caller.clone(),
                    Some(registration_id.to_string()),
                    arm,
                ),
                error,
            )
        };

        for _ in 0..MAX_CLAIM_ATTEMPTS {
            let existing = self
                .read_binding(registration_id)
                .await
                .map_err(|err| refuse(ProducingArm::Binding, err))?;

            let Some(record) = existing else {
                match self
                    .claim_and_mint(
                        request,
                        request_id,
                        registration_id,
                        san,
                        granted,
                        disposition,
                    )
                    .await?
                {
                    Some(outcome) => return Ok(outcome),
                    // Another writer won the claim. Re-read and repeat
                    // the same host-first order against whatever it
                    // wrote.
                    None => continue,
                }
            };

            return self
                .mint_against_binding(
                    request,
                    request_id,
                    registration_id,
                    san,
                    granted,
                    &record,
                    disposition,
                )
                .await;
        }

        Err(refuse(
            ProducingArm::Binding,
            VerbError::unavailable(
                "claiming the durable binding",
                anyhow::anyhow!(
                    "the binding for {registration_id} was created and removed by another writer \
                     on every attempt"
                ),
            ),
        ))
    }

    /// The no-binding arm: validate the safe-set, claim the binding with
    /// the absent-only compare-and-set, then converge and issue.
    ///
    /// Returns `Ok(None)` when the claim lost the race, which is the
    /// caller's signal to re-read and start the host-first order over.
    async fn claim_and_mint(
        &self,
        request: &MintRequest,
        request_id: &RequestId,
        registration_id: &str,
        san: &str,
        granted: &GrantedWrapTtl,
        disposition: &MutationDisposition,
    ) -> Result<Option<MintOutcome>, VerbRefusal> {
        let refuse = |arm: ProducingArm, error: VerbError| {
            VerbRefusal::new(
                VerbContext::new(
                    request_id.clone(),
                    request.caller.clone(),
                    Some(registration_id.to_string()),
                    arm,
                ),
                error,
            )
        };

        // The safe-set is checked before anything is claimed, so a
        // request outside it writes nothing at all.
        self.config
            .validate_spec(&request.service_name, &request.spec)
            .map_err(|err| refuse(ProducingArm::SafeSet, VerbError::Registrar(err)))?;

        let claim = BindingRecord::creating(&request.host, &request.spec);
        let claimed = self
            .claim_binding(registration_id, &claim, disposition)
            .await
            .map_err(|err| refuse(ProducingArm::Binding, err))?;
        if claimed == KvCreateIfAbsent::AlreadyExists {
            return Ok(None);
        }
        self.converge_and_issue(
            request,
            request_id,
            registration_id,
            san,
            granted,
            &claim,
            MintKind::FirstMint,
            disposition,
        )
        .await
        .map(Some)
    }

    /// The existing-binding arm, in its required order: host, then the
    /// stored spec, then the rendered safe-set.
    // One more than the lint allows, and the extra one is the
    // per-invocation mutation disposition every locked helper now
    // threads. Grouping the rest into a struct would restructure the
    // decision procedure this change is required to leave alone.
    #[allow(clippy::too_many_arguments)]
    async fn mint_against_binding(
        &self,
        request: &MintRequest,
        request_id: &RequestId,
        registration_id: &str,
        san: &str,
        granted: &GrantedWrapTtl,
        record: &BindingRecord,
        disposition: &MutationDisposition,
    ) -> MintResult {
        let refuse = |arm: ProducingArm, error: VerbError| {
            VerbRefusal::new(
                VerbContext::new(
                    request_id.clone(),
                    request.caller.clone(),
                    Some(registration_id.to_string()),
                    arm,
                ),
                error,
            )
        };

        // Host first, always. The rendered spec is host-agnostic, so a
        // spec comparison here would match for the wrong host and re-wrap
        // the bound host's identity for the requesting one.
        if record.host != request.host {
            return Err(refuse(
                ProducingArm::Binding,
                VerbError::RegistrationIdCollision {
                    registration_id: registration_id.to_string(),
                    stored_host: record.host.clone(),
                    requested_host: request.host.clone(),
                },
            ));
        }

        let requested_spec = BindingSpec::from_requested(&request.spec);
        // An active binding is compared against what it applied; a
        // `creating` one against what its claim requested. A `creating`
        // record carrying no requested spec — which this build never
        // writes — has nothing to disagree with, so the re-drive
        // proceeds and the activation records the request's spec.
        let stored = match record.state {
            BindingState::Active => {
                let Some(applied) = record.applied_spec.as_ref() else {
                    return Err(refuse(
                        ProducingArm::Binding,
                        VerbError::unavailable(
                            "reading an active binding",
                            anyhow::anyhow!(
                                "active binding for {registration_id} carries no applied_spec"
                            ),
                        ),
                    ));
                };
                Some(applied)
            }
            BindingState::Creating => record.requested_spec.as_ref(),
        };
        if stored.is_some_and(|stored| *stored != requested_spec) {
            return Err(refuse(
                ProducingArm::Binding,
                VerbError::StoredSpecConflict {
                    registration_id: registration_id.to_string(),
                },
            ));
        }

        // Only after both binding checks.
        self.config
            .validate_spec(&request.service_name, &request.spec)
            .map_err(|err| refuse(ProducingArm::SafeSet, VerbError::Registrar(err)))?;

        match record.state {
            BindingState::Active => {
                // The role and policy are reused untouched; only the
                // credential is fresh.
                let role_name = service_role_name(registration_id);
                let client = self
                    .client()
                    .await
                    .map_err(|err| refuse(ProducingArm::Issuance, err))?;
                let role_id = match client.read_role_id(&role_name).await {
                    Ok(role_id) => role_id,
                    Err(err) => {
                        self.client.note_failure(&err).await;
                        return Err(refuse(
                            ProducingArm::Issuance,
                            VerbError::unavailable(
                                "reusing the derived role",
                                err.context(format!("reading role_id for {role_name}")),
                            ),
                        ));
                    }
                };
                self.issue(
                    request,
                    request_id,
                    registration_id,
                    san,
                    granted,
                    &role_name,
                    role_id,
                    MintKind::IdempotentReMint,
                    disposition,
                )
                .await
            }
            // A claim whose convergence failed or was interrupted. The
            // matching host re-drives exactly the path the claimant
            // would have taken.
            BindingState::Creating => {
                self.converge_and_issue(
                    request,
                    request_id,
                    registration_id,
                    san,
                    granted,
                    record,
                    MintKind::FirstMint,
                    disposition,
                )
                .await
            }
        }
    }

    /// Converges role and policy, flips the binding to active, and only
    /// then issues.
    ///
    /// Every failure in here leaves the `creating` binding exactly where
    /// it is. That is the point: whatever half of the role material got
    /// created stays covered by a durable claim, and the matching host
    /// recovers through a re-drive of this same path or through
    /// deregister's teardown-before-unbind sequence.
    #[allow(clippy::too_many_arguments)]
    async fn converge_and_issue(
        &self,
        request: &MintRequest,
        request_id: &RequestId,
        registration_id: &str,
        san: &str,
        granted: &GrantedWrapTtl,
        claim: &BindingRecord,
        kind: MintKind,
        disposition: &MutationDisposition,
    ) -> MintResult {
        let refuse = |arm: ProducingArm, error: VerbError| {
            VerbRefusal::new(
                VerbContext::new(
                    request_id.clone(),
                    request.caller.clone(),
                    Some(registration_id.to_string()),
                    arm,
                ),
                error,
            )
        };

        let client = self
            .client()
            .await
            .map_err(|err| refuse(ProducingArm::Provisioning, err))?;
        // Convergence writes a policy and a role either way: a failure
        // here may be one that failed after the write reached
        // `OpenBao`, which is exactly what the disposition is monotone
        // for.
        let provisioned = disposition.note(
            provision_service_role(
                &client,
                &self.kv_mount,
                registration_id,
                ServiceRoleTtls {
                    token_ttl: &self.token_ttl,
                    secret_id_ttl: &self.secret_id_ttl,
                },
            )
            .await,
        );
        let ProvisionedServiceRole {
            role_name, role_id, ..
        } = match provisioned {
            Ok(provisioned) => provisioned,
            Err(err) => {
                let err = anyhow::Error::new(err);
                self.client.note_failure(&err).await;
                return Err(refuse(
                    ProducingArm::Provisioning,
                    VerbError::unavailable("converging the derived role and policy", err),
                ));
            }
        };

        let active = claim.activated(&request.spec);
        self.write_binding(registration_id, &active, disposition)
            .await
            .map_err(|err| refuse(ProducingArm::Binding, err))?;

        self.issue(
            request,
            request_id,
            registration_id,
            san,
            granted,
            &role_name,
            role_id,
            kind,
            disposition,
        )
        .await
    }

    /// Issues wrap-only material and computes the granted deadline.
    ///
    /// `create_secret_id_wrap_only`, never `create_secret_id_wrapped`:
    /// the latter unwraps immediately and hands back the raw
    /// `secret_id`, which is exactly the value no registrar path may
    /// hold.
    #[allow(clippy::too_many_arguments)]
    async fn issue(
        &self,
        request: &MintRequest,
        request_id: &RequestId,
        registration_id: &str,
        san: &str,
        granted: &GrantedWrapTtl,
        role_name: &str,
        role_id: String,
        kind: MintKind,
        disposition: &MutationDisposition,
    ) -> MintResult {
        let refuse = |error: VerbError| {
            VerbRefusal::new(
                VerbContext::new(
                    request_id.clone(),
                    request.caller.clone(),
                    Some(registration_id.to_string()),
                    ProducingArm::Issuance,
                ),
                error,
            )
        };

        let client = self.client().await.map_err(refuse)?;
        // An issuance creates a `secret_id` on the role, so it counts as
        // a state change whether it returned one or failed on the way
        // back.
        let issued = disposition.note(
            client
                .create_secret_id_wrap_only(
                    role_name,
                    &self.secret_id_options,
                    granted.as_openbao_str(),
                )
                .await,
        );
        let wrap_info = match issued {
            Ok(wrap_info) => wrap_info,
            Err(err) => {
                self.client.note_failure(&err).await;
                return Err(refuse(VerbError::unavailable(
                    "issuing wrapped material",
                    err.context(format!("issuing wrap-only material for {role_name}")),
                )));
            }
        };

        let expires_at = granted_deadline(&wrap_info).map_err(|err| {
            refuse(VerbError::unavailable(
                "reading the wrap token's expiry",
                err,
            ))
        })?;

        Ok(MintOutcome::new(
            VerbContext::new(
                request_id.clone(),
                request.caller.clone(),
                Some(registration_id.to_string()),
                ProducingArm::Issuance,
            ),
            kind,
            san.to_string(),
            role_id,
            WrappedSecretIdToken::new(wrap_info.token),
            expires_at,
        ))
    }

    async fn deregister_locked(
        &self,
        request: &DeregisterRequest,
        request_id: &RequestId,
        registration_id: &str,
        disposition: &MutationDisposition,
    ) -> DeregisterResult {
        let context = |arm: ProducingArm| {
            VerbContext::new(
                request_id.clone(),
                request.caller.clone(),
                Some(registration_id.to_string()),
                arm,
            )
        };

        let existing = self
            .read_binding(registration_id)
            .await
            .map_err(|err| VerbRefusal::new(context(ProducingArm::Binding), err))?;

        if let Some(record) = &existing
            && record.host != request.host
        {
            // Neither lifecycle state lets a different host act. Nothing
            // is touched.
            return Err(VerbRefusal::new(
                context(ProducingArm::Binding),
                VerbError::HostMismatch {
                    registration_id: registration_id.to_string(),
                    stored_host: record.host.clone(),
                    requested_host: request.host.clone(),
                },
            ));
        }

        // Teardown first, unbind after. A `creating` binding takes the
        // same sequence as an `active` one: it is the durable
        // registration claim, and removing it is what "identity removed"
        // means whether or not the role material was ever completed.
        let client = self
            .client()
            .await
            .map_err(|err| VerbRefusal::new(context(ProducingArm::Teardown), err))?;
        let teardown = teardown_service_material(
            &client,
            &self.kv_mount,
            registration_id,
            &REGISTRAR_TEARDOWN_KV_SUFFIXES,
        )
        .await;
        // A sweep that removed something changed `OpenBao`, and one that
        // failed may have. An all-`AlreadyAbsent` report deleted nothing
        // and leaves the disposition clear — which is what makes an
        // already-absent deregister with nothing to sweep distinguishable
        // from one that swept a planted orphan, though both produce
        // `DeregisterKind::AlreadyAbsent`.
        if teardown.attempts().iter().any(|attempt| {
            matches!(
                attempt.outcome,
                ResourceOutcome::Removed | ResourceOutcome::Failed(_)
            )
        }) {
            disposition.set();
        }

        if !teardown.aggregate_success() {
            return Err(VerbRefusal::new(
                context(ProducingArm::Teardown),
                VerbError::unavailable(
                    "tearing down the identity's material",
                    anyhow::anyhow!("one or more resources could not be deleted"),
                ),
            )
            .with_teardown(teardown));
        }

        if existing.is_none() {
            // The accepted hazard, stated in this module's header: with
            // no binding the sweep still ran, so material left behind by
            // a lost binding or by a direct-CLI registration of the same
            // derived id is removed.
            return Ok(DeregisterOutcome::new(
                context(ProducingArm::Teardown),
                DeregisterKind::AlreadyAbsent,
                teardown,
            ));
        }

        self.delete_binding(registration_id, disposition)
            .await
            .map_err(|err| VerbRefusal::new(context(ProducingArm::Binding), err))?;

        Ok(DeregisterOutcome::new(
            context(ProducingArm::Binding),
            DeregisterKind::IdentityRemoved,
            teardown,
        ))
    }

    /// Returns the process-wide per-`registration_id` lock map both
    /// verbs take their stage 3 lock from.
    ///
    /// Every acquisition goes through here, so no instance can end up
    /// locking against a map of its own.
    // The receiver is not read, and that is the point: routing every
    // instance's lock selection through a method on `&self` is what lets
    // the cross-instance contention test drive this path per service and
    // observe that both land on one map. An associated function would
    // make that assertion untestable, so the lint's suggestion is
    // declined here and nowhere wider.
    #[allow(clippy::unused_self)]
    fn id_locks(&self) -> &'static IdLocks {
        &ID_LOCKS
    }

    /// The lock map this instance would take a per-id lock from.
    ///
    /// Test-only, and deliberately a delegation rather than a second
    /// path to the static: what the contention test has to exercise is
    /// the production lock selection, once per instance.
    #[cfg(test)]
    fn id_locks_for_test(&self) -> &'static IdLocks {
        self.id_locks()
    }

    fn binding_path(registration_id: &str) -> String {
        service_kv_path(registration_id, REGISTRAR_BINDING_KV_SUFFIX)
    }

    async fn read_binding(
        &self,
        registration_id: &str,
    ) -> Result<Option<BindingRecord>, VerbError> {
        let path = Self::binding_path(registration_id);
        let client = self.client().await?;
        let stored = match client.try_read_kv(&self.kv_mount, &path).await {
            Ok(stored) => stored,
            Err(err) => {
                self.client.note_failure(&err).await;
                return Err(VerbError::unavailable(
                    "reading the durable binding",
                    err.context(format!("reading the registrar binding at {path}")),
                ));
            }
        };
        let Some(value) = stored else {
            return Ok(None);
        };
        BindingRecord::decode(&value)
            .map(Some)
            // Fail closed and change nothing: a record this build cannot
            // read may be a newer registrar's, and guessing at it is what
            // would let a second host take an identity over.
            .map_err(|err| {
                VerbError::unavailable("reading the durable binding", anyhow::Error::new(err))
            })
    }

    async fn claim_binding(
        &self,
        registration_id: &str,
        record: &BindingRecord,
        disposition: &MutationDisposition,
    ) -> Result<KvCreateIfAbsent, VerbError> {
        let path = Self::binding_path(registration_id);
        let body = record
            .encode()
            .map_err(|err| VerbError::unavailable("encoding the durable binding", err.into()))?;
        let client = self.client().await?;
        match client
            .create_kv_if_absent(&self.kv_mount, &path, body)
            .await
        {
            // A won claim wrote the binding. A lost one is the single
            // outcome of the six call sites that leaves the disposition
            // clear: the compare-and-set was refused and nothing at all
            // reached `OpenBao`.
            Ok(created @ KvCreateIfAbsent::Created(_)) => {
                disposition.set();
                Ok(created)
            }
            Ok(KvCreateIfAbsent::AlreadyExists) => Ok(KvCreateIfAbsent::AlreadyExists),
            Err(err) => {
                disposition.set();
                self.client.note_failure(&err).await;
                Err(VerbError::unavailable(
                    "claiming the durable binding",
                    err.context(format!("claiming the registrar binding at {path}")),
                ))
            }
        }
    }

    async fn write_binding(
        &self,
        registration_id: &str,
        record: &BindingRecord,
        disposition: &MutationDisposition,
    ) -> Result<(), VerbError> {
        let path = Self::binding_path(registration_id);
        let body = record
            .encode()
            .map_err(|err| VerbError::unavailable("encoding the durable binding", err.into()))?;
        let client = self.client().await?;
        match disposition.note(client.write_kv(&self.kv_mount, &path, body).await) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.client.note_failure(&err).await;
                Err(VerbError::unavailable(
                    "activating the durable binding",
                    err.context(format!("writing the registrar binding at {path}")),
                ))
            }
        }
    }

    async fn delete_binding(
        &self,
        registration_id: &str,
        disposition: &MutationDisposition,
    ) -> Result<(), VerbError> {
        let path = Self::binding_path(registration_id);
        let client = self.client().await?;
        match disposition.note(client.delete_kv(&self.kv_mount, &path).await) {
            Ok(()) => Ok(()),
            Err(err) => {
                self.client.note_failure(&err).await;
                Err(VerbError::unavailable(
                    "removing the durable binding",
                    err.context(format!("deleting the registrar binding at {path}")),
                ))
            }
        }
    }
}

/// Selects the bucket an invocation is charged against from whether the
/// pure checks of stage 1 refused it.
///
/// The whole of the membership rule. `predecision_refusal` is that
/// enumerated set of checks and nothing else — not "every refusal
/// reached without I/O": `derive_registration_id` is synchronous and
/// touches nothing outside the process, and its failures spend an
/// `admission` token all the same, because they are settled *after* the
/// charge. The bucket is fixed here and is never revised by what the
/// invocation turns out to be.
fn bucket_for(passed_pure_checks: bool) -> LimiterBucket {
    if passed_pure_checks {
        LimiterBucket::Admission
    } else {
        LimiterBucket::PredecisionRefusal
    }
}

/// Takes the identity parts a request asked about, exactly as they
/// arrived.
///
/// The three fields of [`RequestedIdentity`] are the whole of what the
/// format records about a request. A mint's `spec`, `delivery_mode` and
/// `wrap_ttl` are deliberately absent: the format defines no field for
/// them, and this module consumes the format rather than extending it.
fn requested_identity(service_name: &str, host: &str, instance: Option<u32>) -> RequestedIdentity {
    RequestedIdentity {
        service_name: service_name.to_string(),
        host: host.to_string(),
        instance,
    }
}

/// Computes the granted absolute deadline from what `OpenBao` reported.
///
/// Both halves come from the response rather than from the request: the
/// creation time is `OpenBao`'s, and the TTL is the one it actually
/// applied, so a server-side clamp shows up here as well as the
/// registrar's own. The conversion to [`time::Duration`] is checked —
/// the reported TTL is a `u64` and the target is signed.
fn granted_deadline(wrap_info: &WrapInfo) -> anyhow::Result<OffsetDateTime> {
    let created = OffsetDateTime::parse(&wrap_info.creation_time, &Rfc3339).with_context(|| {
        format!(
            "parsing the wrap token's creation_time {:?} as RFC 3339",
            wrap_info.creation_time
        )
    })?;
    let seconds = i64::try_from(wrap_info.ttl).with_context(|| {
        format!(
            "the reported wrap ttl {} does not fit a duration",
            wrap_info.ttl
        )
    })?;
    let ttl = time::Duration::seconds(seconds);
    created
        .checked_add(ttl)
        .with_context(|| format!("the wrap token's expiry overflows: {created} + {ttl}"))
}

/// The per-`registration_id` locks, keyed weakly so the map does not grow
/// with every id a caller has ever named.
///
/// The locks themselves are [`tokio::sync::Mutex`] and are what mint and
/// deregister serialize on. The map's own guard is a
/// [`std::sync::Mutex`] deliberately: it is held across no `.await` at
/// all, and reclaiming a dead entry has to happen in `Drop` — which runs
/// when a verb's future is cancelled as well as when it returns, where an
/// explicit async reclaim would not.
///
/// Production has exactly one of these, the module's [`ID_LOCKS`]. The
/// type stays independently constructible so the reclamation tests can
/// assert entry counts on a map of their own, where no other test in the
/// binary can be holding an id.
#[derive(Default)]
struct IdLocks {
    entries: StdMutex<HashMap<String, Weak<TokioMutex<()>>>>,
}

impl IdLocks {
    /// Returns a guard on `registration_id`'s lock, creating the lock if
    /// no live one exists.
    ///
    /// The upgrade-or-insert happens under the map guard, so an
    /// acquisition can never race a reclaim into handing two callers
    /// different locks for one id.
    async fn acquire(&self, registration_id: &str) -> IdGuard<'_> {
        let lock = {
            let mut entries = self.lock_entries();
            if let Some(existing) = entries.get(registration_id).and_then(Weak::upgrade) {
                existing
            } else {
                let fresh = Arc::new(TokioMutex::new(()));
                entries.insert(registration_id.to_string(), Arc::downgrade(&fresh));
                fresh
            }
        };
        let entry = Arc::downgrade(&lock);
        let guard = lock.lock_owned().await;
        IdGuard {
            guard: Some(guard),
            locks: self,
            registration_id: registration_id.to_string(),
            entry,
        }
    }

    /// Removes `registration_id`'s entry, but only when it is the
    /// identical, now-dead `Weak` the releasing guard held.
    ///
    /// Both conditions matter. A live entry means another waiter already
    /// upgraded it, and a different entry means the id was re-acquired
    /// after this one died; removing either would drop a lock somebody
    /// is using.
    fn reclaim(&self, registration_id: &str, entry: &Weak<TokioMutex<()>>) {
        let mut entries = self.lock_entries();
        let is_dead_and_identical = entries
            .get(registration_id)
            .is_some_and(|stored| stored.strong_count() == 0 && Weak::ptr_eq(stored, entry));
        if is_dead_and_identical {
            entries.remove(registration_id);
        }
    }

    /// Takes the map guard, recovering from a poisoned mutex.
    ///
    /// The critical sections here are a map lookup and an insert, so a
    /// panic inside one cannot leave the map torn; treating the poison as
    /// fatal would turn an unrelated panic elsewhere into a permanently
    /// unusable registrar.
    fn lock_entries(&self) -> std::sync::MutexGuard<'_, HashMap<String, Weak<TokioMutex<()>>>> {
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Holds one `registration_id`'s lock, and reclaims its map entry on
/// drop.
struct IdGuard<'a> {
    /// Dropped first, inside `Drop`, so the strong count the reclaim
    /// checks is the one that excludes this guard.
    guard: Option<OwnedMutexGuard<()>>,
    locks: &'a IdLocks,
    registration_id: String,
    entry: Weak<TokioMutex<()>>,
}

impl Drop for IdGuard<'_> {
    fn drop(&mut self) {
        drop(self.guard.take());
        self.locks.reclaim(&self.registration_id, &self.entry);
    }
}
