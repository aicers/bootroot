//! The production [`RegistrarRequestHandler`]: the seam where the codec
//! meets the verb layer.
//!
//! It introduces no wire decision of its own. [`protocol`]
//! owns the payload schema, its encoding and the refusal mapping;
//! [`verbs`](crate::registrar::verbs) owns the decision procedure, the
//! per-identity locks and the outcome classification. What lives here is
//! the three steps between them: decode the payload into the dispatched
//! operation's request type, build the verb's inputs from it, and encode
//! the verb's result.
//!
//! # What it is constructed from
//!
//! Already-built dependencies, never settings. The constructor performs
//! no I/O and reads no configuration, which is what makes the same type
//! reachable from a test over a mock `OpenBao` and from the daemon over
//! the real one: `crate::daemon::build_registrar_handler` is the
//! fallible half that turns a `[registrar]` table into these values, and
//! it is the crate's only call site of
//! [`RegistrarVerbs::internal`](crate::registrar::verbs::RegistrarVerbs::internal).
//! There is no injection slot, no interior mutability and no
//! `#[cfg(test)]` branch on this type — the production wiring a reviewer
//! reads is the one the tests exercise.
//!
//! # What a refusal says, and where
//!
//! [`HandlerRefusal`] is a zero-data marker and the transport treats it
//! as one: it emits the fixed `handler-rejected-payload` line under the
//! connection diagnostic id and writes no bytes. Nothing this module
//! knows can reach that line, so the detail is emitted here instead,
//! before the refusal is returned — at `warn` for a deployment fault and
//! `debug` for a caller-supplied one. The unsettled `spec` grammar is
//! neither, and takes `warn` for the reason given at its own refusal.
//! That event carries no connection id, because
//! [`RegistrarRequestHandler::handle`] receives none; the
//! two lines are correlated by the caller identity both carry and by
//! their ordering within one connection's handling, and that is the
//! whole of the correlation available.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use anyhow::Context as _;
use tracing::{debug, warn};

use super::frame::Operation;
use super::handler::{HandlerRefusal, RegistrarRequestHandler};
use super::protocol::{
    self, DeregisterRequest as WireDeregisterRequest, RegisterRequest as WireRegisterRequest,
    RegistrarHealth, Request, WireServiceSpec,
};
use crate::kv_payload::{TrustPayload, parse_trust_payload};
use crate::registrar::identity::RequestedSpec;
use crate::registrar::internal::InternalCredential;
use crate::registrar::verbs::outcome::CallerIdentity;
use crate::registrar::verbs::{DeregisterRequest, MintRequest, RegistrarVerbs};
use crate::trust_bootstrap::CA_TRUST_KV_PATH;

/// The production handler, over already-built dependencies.
pub(crate) struct ProductionHandler {
    verbs: RegistrarVerbs,
    /// The credential the CA-anchor read borrows a client from.
    ///
    /// [`RegistrarVerbs`] builds its privileged client inside itself and
    /// exposes neither it nor the credential, so the anchor read loads
    /// its own from the same secrets directory, `OpenBao` URL and active
    /// root fingerprint the verbs were built from. The cost is one extra
    /// cached certificate login per process; the benefit is that the
    /// read is held to the same active-root comparison every verb write
    /// is, because `authenticated()` re-checks it before handing back a
    /// client — a rotation that retired the root refuses the read rather
    /// than serving under a superseded one.
    credential: InternalCredential,
    /// The KV v2 mount the anchor is read under. The same value the
    /// verbs were built with, resolved once by the daemon.
    kv_mount: String,
    health: Arc<StdMutex<RegistrarHealth>>,
}

impl ProductionHandler {
    /// Creates the handler over dependencies somebody else built.
    ///
    /// Performs no I/O and reads no configuration.
    #[cfg(test)]
    pub(crate) fn new(
        verbs: RegistrarVerbs,
        credential: InternalCredential,
        kv_mount: String,
    ) -> Self {
        Self::with_health(
            verbs,
            credential,
            kv_mount,
            Arc::new(StdMutex::new(RegistrarHealth::default())),
        )
    }

    /// Creates the handler with the daemon-owned registrar health snapshot.
    pub(crate) fn with_health(
        verbs: RegistrarVerbs,
        credential: InternalCredential,
        kv_mount: String,
        health: Arc<StdMutex<RegistrarHealth>>,
    ) -> Self {
        Self {
            verbs,
            credential,
            kv_mount,
            health,
        }
    }

    /// Serves one mint request.
    async fn mint(
        &self,
        request: &WireRegisterRequest,
        caller: CallerIdentity,
    ) -> Result<Vec<u8>, HandlerRefusal> {
        let request = mint_request(request, caller.clone())?;

        // Before the verb, never after. A read that failed after a
        // successful mint would leave material minted and no response to
        // carry it — the stranded obligation `PostMintUnrecordable`
        // exists to describe. Reading first means a failure refuses
        // before anything is created and the caller simply retries. It
        // is also not cached: a root rotation rewrites the anchor, and
        // an endpoint handing out a stale one would seed a freshly
        // enrolled service with a trust root the deployment retired.
        let anchor = self.read_ca_anchor().await.map_err(|error| {
            warn!(
                caller = caller.as_str(),
                kv_mount = self.kv_mount.as_str(),
                kv_path = CA_TRUST_KV_PATH,
                "Registrar endpoint could not read the deployment CA anchor: {error:#}"
            );
            HandlerRefusal
        })?;

        let health = self
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let encoded = match self.verbs.mint(&request).await {
            Ok(outcome) => protocol::encode_mint_response(outcome, &anchor, &health),
            Err(refusal) => protocol::encode_refusal_response(&refusal, &health),
        };
        encoded.map_err(|error| {
            warn!(
                caller = caller.as_str(),
                "Registrar endpoint could not encode a mint response: {error}"
            );
            HandlerRefusal
        })
    }

    /// Serves one deregistration request.
    ///
    /// Deregister carries no spec and no CA anchor, so neither the spec
    /// conversion nor the KV read on the mint path applies here.
    async fn deregister(
        &self,
        request: &WireDeregisterRequest,
        caller: CallerIdentity,
    ) -> Result<Vec<u8>, HandlerRefusal> {
        // `idempotency_key` is read by nothing here. It is decoded
        // because the reference carries it, and it is carried no
        // further: bootroot's idempotence comes from the durable
        // `registration_id -> host` binding and the stored-spec
        // comparison, and a key-keyed shortcut would let a caller replay
        // or split an identity's history by choosing keys.
        let request = DeregisterRequest {
            caller: caller.clone(),
            service_name: request.service_name.clone(),
            host: request.host.clone(),
            instance: request.instance,
        };

        let health = self
            .health
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let encoded = match self.verbs.deregister(&request).await {
            Ok(outcome) => protocol::encode_deregister_response(&outcome, &health),
            Err(refusal) => protocol::encode_refusal_response(&refusal, &health),
        };
        encoded.map_err(|error| {
            warn!(
                caller = caller.as_str(),
                "Registrar endpoint could not encode a deregistration response: {error}"
            );
            HandlerRefusal
        })
    }

    /// Reads the deployment's CA anchor and returns exactly what the
    /// codec frames.
    ///
    /// # Errors
    ///
    /// Returns an error when the credential cannot authenticate, when
    /// the KV object cannot be read, when it is not the documented trust
    /// shape, or when its stored fingerprints and its bundle disagree.
    async fn read_ca_anchor(&self) -> anyhow::Result<TrustPayload> {
        let client = self
            .credential
            .authenticated()
            .await
            .context("authenticating with the bootroot-internal credential")?;
        let value = client
            .read_kv(&self.kv_mount, CA_TRUST_KV_PATH)
            .await
            .with_context(|| {
                format!(
                    "reading the deployment CA anchor from {}/{CA_TRUST_KV_PATH}",
                    self.kv_mount
                )
            })?;
        let stored = parse_trust_payload(&value).with_context(|| {
            format!(
                "validating the deployment CA anchor at {}/{CA_TRUST_KV_PATH}",
                self.kv_mount
            )
        })?;
        anchor_from_stored(&stored)
    }
}

impl RegistrarRequestHandler for ProductionHandler {
    fn handle<'a>(
        &'a self,
        operation: Operation,
        payload: &'a [u8],
        caller: CallerIdentity,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HandlerRefusal>> + Send + 'a>> {
        Box::pin(async move {
            // The frame's operation alone selects the shape, so the
            // decoded variant and the dispatched operation cannot
            // disagree and no arm here has to reconcile them.
            let request = protocol::decode_request(operation, payload).map_err(|error| {
                debug!(
                    caller = caller.as_str(),
                    operation = operation.as_str(),
                    "Registrar endpoint could not decode the request payload: {error}"
                );
                HandlerRefusal
            })?;
            match request {
                Request::Register(request) => self.mint(&request, caller).await,
                Request::Deregister(request) => self.deregister(&request, caller).await,
            }
        })
    }
}

/// Turns the stored `bootroot/ca` object into the anchor the codec
/// frames.
///
/// Two properties the codec cannot check are established here, because
/// the framing requires each fingerprint to match the certificate at the
/// **same position** while `parse_trust_payload` checks only set
/// membership, and nothing that writes `bootroot/ca` enforces an order
/// at all:
///
/// - the emitted fingerprint array is **derived from the bundle, in
///   bundle order**, rather than copied from the stored array, and the
///   derived set is then compared with the stored one. A `bootroot/ca`
///   whose pins and bundle disagree is precisely the state no freshly
///   enrolled service may be seeded from, and it is a deployment fault
///   rather than a caller's;
/// - the bundle's line endings are normalized to LF with exactly one
///   trailing LF. Fingerprints are computed over DER, so this changes no
///   certificate and no digest; it makes the emitted text match the
///   framing the anchor is contracted to carry however the object was
///   written.
///
/// Split from the read so both rules are testable without an `OpenBao`.
///
/// # Errors
///
/// Returns an error when the normalized bundle does not parse, or when
/// the derived and stored fingerprint sets differ.
fn anchor_from_stored(stored: &TrustPayload) -> anyhow::Result<TrustPayload> {
    let ca_bundle_pem = normalize_bundle(&stored.ca_bundle_pem);
    let certificates = crate::tls::parse_pem_to_cert_list(ca_bundle_pem.as_bytes())
        .context("parsing the deployment CA bundle")?;
    let derived: Vec<String> = certificates
        .iter()
        .map(|certificate| crate::tls::sha256_hex(certificate.as_ref()))
        .collect();
    // Compared case-insensitively, exactly as `parse_trust_payload`
    // matches a stored pin against the bundle. A stored array is only
    // ever written lowercase, but the shared validator accepts either
    // case, and an anchor it accepts must not be refused here on a
    // difference that is not one.
    let stored_set: BTreeSet<String> = stored
        .trusted_ca_sha256
        .iter()
        .map(|pin| pin.to_ascii_lowercase())
        .collect();
    let derived_set: BTreeSet<String> = derived.iter().cloned().collect();
    if stored_set != derived_set {
        anyhow::bail!(
            "the deployment CA anchor's stored fingerprints do not match the certificates in \
             its bundle; a freshly enrolled service must not be seeded from it"
        );
    }
    Ok(TrustPayload {
        trusted_ca_sha256: derived,
        ca_bundle_pem,
    })
}

/// Builds the verb's inputs from a decoded register request.
///
/// Free of the handler on purpose: nothing about this conversion depends
/// on a built dependency, so nothing here can quietly start reading one.
fn mint_request(
    request: &WireRegisterRequest,
    caller: CallerIdentity,
) -> Result<MintRequest, HandlerRefusal> {
    let wrap_ttl = i64::try_from(request.wrap_ttl)
        .map(time::Duration::seconds)
        .map_err(|_| {
            debug!(
                caller = caller.as_str(),
                "Registrar endpoint refused a wrap_ttl no duration can carry"
            );
            HandlerRefusal
        })?;
    // `warn`, not `debug`, and deliberately outside the rule the
    // module doc states. That rule splits a deployment fault from a
    // caller-supplied one, and the unsettled grammar is neither: no
    // payload a caller can send makes this succeed, so every mint on a
    // correctly provisioned deployment stops here. At the daemon's
    // default level the operator would otherwise see only the
    // transport's `handler-rejected-payload` line and nothing saying
    // the endpoint cannot serve mint at all. It returns to `debug` for
    // the caller-supplied faults a settled grammar will have.
    let spec = requested_spec(&request.spec).map_err(|error| {
        warn!(
            caller = caller.as_str(),
            "Registrar endpoint could not convert the wire spec: {error}"
        );
        HandlerRefusal
    })?;
    // `wrap_ttl` is passed through as *requested*. The clamp against
    // the configured maximum is `WrapTtlPolicy`'s, inside the verb,
    // and the granted deadline is the one the outcome carries rather
    // than anything computed here. `idempotency_key` reaches nothing
    // here either; see `deregister`.
    Ok(MintRequest {
        caller,
        service_name: request.service_name.clone(),
        host: request.host.clone(),
        instance: request.instance,
        spec,
        wrap_ttl,
    })
}

/// Rewrites a stored bundle with LF line endings and exactly one
/// trailing LF.
fn normalize_bundle(bundle: &str) -> String {
    let unified = bundle.replace("\r\n", "\n").replace('\r', "\n");
    format!("{}\n", unified.trim_end_matches('\n'))
}

/// Why a wire `spec` could not be converted into a [`RequestedSpec`].
#[derive(Debug, thiserror::Error)]
pub(crate) enum SpecConversionError {
    /// The wire spelling of `reload` and `cert_group` is recorded
    /// nowhere, so there is no grammar to read either string under.
    #[error(
        "the wire spelling of spec.reload and spec.cert_group is not recorded in \
         docs/reference/registrar-wire-contract.md; until the owner of the \
         provisioning-config contract settles it and it is transcribed there, no form of \
         either string can be accepted"
    )]
    GrammarNotSettled,
}

/// Converts the wire `spec` into the verb layer's [`RequestedSpec`].
///
/// # This conversion is deliberately not implemented
///
/// [`RequestedSpec`] needs `reload: ReloadSpec { kind, target }` and
/// `cert_group: Option<u32>`, because that is what the safe-set
/// comparison compares against. The wire carries both as opaque strings,
/// and **no repository records how either is spelled**: the reference's
/// transcribed half types them as opaque `String` newtypes owned by
/// review-protocol and says nothing about their contents, the
/// provisioning tool renders its `ReloadHook` only into `bootroot
/// service add` flags, and the rendered provisioning config has no
/// counterpart at all for its container-`SIGHUP` variant.
///
/// The grammar is not bootroot's to choose, and needing to parse a value
/// does not confer authorship of it. A spelling chosen here would
/// satisfy this repository's tests by construction — the fixtures and
/// the conversion would agree because the same change wrote both — and
/// diverge the first time a real caller sent one, in production, with no
/// test on either side able to catch it. `src/registrar/config.rs` takes
/// exactly that position for the file this spec is compared against, and
/// `docs/reference/registrar-provisioning-config.md` §3.2 rules that a
/// registration the rendered vocabulary cannot express is a coordinated
/// format change in the provisioning repository rather than something
/// this side pattern-matches around.
///
/// So every wire `spec` is refused until the reference's transcribed
/// half records one row for `spec.reload` and one for `spec.cert_group`,
/// with provenance, and its open-items section lists neither. Filling
/// this function in from those rows is then mechanical, and is the whole
/// of what remains: the accepted and rejected forms are enumerated from
/// the reference, never from a decision made here.
///
/// # Errors
///
/// Returns [`SpecConversionError::GrammarNotSettled`] for every input.
fn requested_spec(_spec: &WireServiceSpec) -> Result<RequestedSpec, SpecConversionError> {
    Err(SpecConversionError::GrammarNotSettled)
}

#[cfg(test)]
mod tests;
