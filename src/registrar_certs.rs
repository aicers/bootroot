//! Start-time issuance of the two certificates the registrar surface
//! runs on.
//!
//! An endpoint-enabled host needs two leaves whose names live in the
//! reserved [`crate::registrar::RESERVED_SERVICE_NAME_PREFIX`]
//! namespace, so neither can be minted through `service add`:
//!
//! - the **endpoint server leaf**,
//!   `001.bootroot-registrar-endpoint.<host>.<domain>`, at
//!   `[registrar_endpoint] server_cert_path` / `server_key_path`, which
//!   the endpoint presents and a pinned caller verifies;
//! - the **registrar client leaf**,
//!   `001.bootroot-registrar.<host>.<domain>`, at `client_cert_path` /
//!   `client_key_path`, which the co-located registrar process
//!   authenticates back with.
//!
//! # Who issues them, and as what
//!
//! The daemon does, under the **bootroot-internal privileged
//! credential** ([`crate::registrar::internal::InternalCredential`]) and
//! never through the per-service ACME agent loop. That loop
//! authenticates with a `role_id` + `secret_id`, and routing either leaf
//! through it would put an expiring secret back under the registrar
//! surface — which is exactly what the certificate form was chosen to
//! escape. Nothing on this path reads a `role_id` or a `secret_id`.
//!
//! "Under that credential" has observable content rather than being a
//! statement about which process holds which file: the two ACME inputs
//! [`crate::acme::issue_certificate_with`] needs — the account
//! EAB and the HTTP-01 responder HMAC — are read from `OpenBao` through
//! it, at the mount the deployment state file records, and are used in
//! memory only. There is no fallback to `agent.toml`, to the internal
//! profile's rendered config, or to issuing without EAB.
//!
//! # When
//!
//! Once per process start, before
//! [`crate::registrar::RegistrarEndpoint::activate`] loads the server
//! pair, and only on a host where `registrar_endpoint.enabled` is true.
//! A pair that is already **usable** is left exactly as it is: re-issuing
//! it would churn a file the co-located registrar is reading and hand
//! that process a new key on every restart. The two pairs are evaluated
//! independently.
//!
//! This is not a scheduler. There is no registration point, no lead-time
//! constant and no retry policy, and nothing here changes how the
//! per-service loop or the internal profile's own renewal is scheduled,
//! credentialed or triggered.
//!
//! # Why this is not a module of [`crate::registrar`]
//!
//! Nothing under `src/registrar/` may open, name or know the path of the
//! deployment state file — the registrar authority layer takes the
//! `OpenBao` URL, the KV mount and the secrets directory as parameters,
//! and a test enforces that. This module resolves all three itself,
//! because it runs above `RegistrarEndpoint::activate` and so above the
//! registrar handler that would otherwise have resolved them. It is the
//! daemon's start-up step, a sibling of the daemon module rather than a
//! layer of the registrar, and it lives here so that boundary stays a
//! property of the directory rather than of a comment.
//!
//! # What "usable" means
//!
//! [`evaluate_pair`] applies the eight ordered conditions
//! [`UnusableMaterial`] enumerates, and every one of the eight makes the
//! daemon **attempt** an issuance rather than refuse. That is a
//! guarantee about the attempt: a write that cannot land and a CA bundle
//! that cannot be read are still startup failures, and a replacement
//! that persistent clock skew leaves outside its window is still refused
//! by the endpoint's own TLS loader a few lines later.
//!
//! The evaluation adds no second verification path. Its chain condition
//! is [`crate::cert_chain::leaf_chains_to_bundle`] against
//! `[trust].ca_bundle_path` and nothing else: it consults neither
//! `trust.trusted_ca_sha256` nor the pinned-anchor requirement, and runs
//! neither the endpoint's verifier nor its self-check. Those are the
//! loader's, performed a few lines later, and its acceptance rule is
//! strictly stronger than this one.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tracing::{info, warn};
use x509_parser::prelude::ASN1Time;

use crate::acme::{CsrShape, IssuanceOptions, LeafPublication};
use crate::config::{
    DaemonProfileSettings, HookSettings, Paths, RegistrarEndpointSettings, Settings,
};
use crate::eab::EabCredentials;
use crate::registrar::internal::{
    InternalCredential, InternalPaths, active_root_fingerprint, load_internal_config,
};
use crate::registrar::{
    REGISTRAR_CLIENT_LABEL, REGISTRAR_ENDPOINT_LABEL, REGISTRAR_SURFACE_INSTANCE,
    registrar_client_identity, registrar_endpoint_identity, single_dns_san,
};
use crate::secret::HmacSecret;
use crate::{cert_chain, tls};

/// The KV v2 path the deployment's shared agent EAB is stored at.
///
/// Read here through the internal credential, whose policy already
/// grants it — see the policy body in
/// [`crate::registrar::internal`]. No policy widens for this path.
pub(crate) const PATH_AGENT_EAB: &str = "bootroot/agent/eab";

/// The KV v2 path the deployment's HTTP-01 responder HMAC is stored at.
pub(crate) const PATH_RESPONDER_HMAC: &str = "bootroot/responder/hmac";

/// How both surface leaves are published at their configured
/// certificate path.
///
/// Both are written **with** their issuer chain, unlike an ordinary
/// service leaf, so this is one value rather than a per-leaf choice. A
/// caller pinning this endpoint selects its trust anchors from the
/// certificates the server presents, so a leaf-only `server_cert_path`
/// is refused by the endpoint's own TLS loader and by every correctly
/// pinned caller; the client leaf is written the same way so the two
/// halves of the same connection have the same shape and the registrar
/// can present a complete chain.
const SURFACE_LEAF_PUBLICATION: LeafPublication = LeafPublication::LeafWithChain;

/// Which of the registrar surface's two leaves a pair holds.
///
/// The two are evaluated and issued independently: one being usable is
/// never a reason to leave the other unusable, and one needing issuance
/// is never a reason to re-issue the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SurfaceLeaf {
    /// The leaf the endpoint presents. A server certificate, so it takes
    /// the ordinary CSR shape and requests no extended key usage.
    EndpointServer,
    /// The leaf the co-located registrar authenticates with. Takes
    /// [`CsrShape::RegistrarClient`], which requests `clientAuth`.
    RegistrarClient,
}

impl SurfaceLeaf {
    /// The reserved service label this leaf's name carries.
    #[must_use]
    pub(crate) fn service_label(self) -> &'static str {
        match self {
            Self::EndpointServer => REGISTRAR_ENDPOINT_LABEL,
            Self::RegistrarClient => REGISTRAR_CLIENT_LABEL,
        }
    }

    /// The CSR shape this leaf is requested with.
    #[must_use]
    pub(crate) fn csr_shape(self) -> CsrShape {
        match self {
            Self::EndpointServer => CsrShape::Service,
            Self::RegistrarClient => CsrShape::RegistrarClient,
        }
    }

    /// The issuance options this leaf is minted under.
    #[must_use]
    pub(crate) fn issuance_options(self) -> IssuanceOptions {
        IssuanceOptions {
            csr_shape: self.csr_shape(),
            leaf_publication: SURFACE_LEAF_PUBLICATION,
        }
    }

    /// Composes this leaf's name at the fixed instance label.
    #[must_use]
    pub(crate) fn identity(self, host: &str, domain: &str) -> String {
        match self {
            Self::EndpointServer => {
                registrar_endpoint_identity(REGISTRAR_SURFACE_INSTANCE, host, domain)
            }
            Self::RegistrarClient => {
                registrar_client_identity(REGISTRAR_SURFACE_INSTANCE, host, domain)
            }
        }
    }

    /// How the certificate path is spelled in a diagnostic.
    #[must_use]
    pub(crate) fn cert_setting(self) -> &'static str {
        match self {
            Self::EndpointServer => "[registrar_endpoint] server_cert_path",
            Self::RegistrarClient => "[registrar_endpoint] client_cert_path",
        }
    }

    /// How the key path is spelled in a diagnostic.
    #[must_use]
    pub(crate) fn key_setting(self) -> &'static str {
        match self {
            Self::EndpointServer => "[registrar_endpoint] server_key_path",
            Self::RegistrarClient => "[registrar_endpoint] client_key_path",
        }
    }
}

/// Why the material at a configured pair of paths cannot be used.
///
/// The eight variants are the eight conditions of the usability rule
/// negated one at a time, in the order the rule evaluates them, so the
/// enumeration is exhaustive by construction rather than by assertion.
/// A condition is only meaningful once every condition above it holds —
/// which is why a leaf that does not parse is *malformed* and is never
/// carried into the key, SAN, window or chain arms.
///
/// Every one of the eight is answered by issuing a replacement. None of
/// them is a refusal on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub(crate) enum UnusableMaterial {
    /// One or both files are not there.
    #[error("the certificate or key file does not exist")]
    Absent,
    /// One or both files exist and could not be read.
    #[error("the certificate or key file exists but could not be read")]
    Unreadable,
    /// The certificate file yields no certificate, or the key file
    /// yields no private key.
    #[error("the certificate or key file does not parse")]
    Malformed,
    /// Both parse, but the key is not the leaf's.
    ///
    /// Exactly what a renewal that died between the certificate rename
    /// and the key rename leaves behind.
    #[error("the private key is not the key of the leaf beside it")]
    KeyMismatched,
    /// The leaf does not carry exactly one DNS SAN equal to the reserved
    /// name for this pair.
    #[error("the leaf does not carry the reserved name for this pair as its only DNS SAN")]
    SanMismatched,
    /// The leaf's `not_before` is in the future at this host's clock.
    #[error("the leaf is not yet valid at this host's clock")]
    NotYetValid,
    /// The leaf's `not_after` is in the past at this host's clock.
    #[error("the leaf has expired at this host's clock")]
    Expired,
    /// The leaf no longer chains to `[trust].ca_bundle_path`, or that
    /// bundle is missing, unreadable or unparseable.
    ///
    /// What a destructive trust-anchor rotation leaves: a still-in-date,
    /// correctly named leaf signed by the previous CA generation, which
    /// looks perfect and fails every handshake.
    #[error("the leaf no longer chains to the configured CA bundle")]
    ChainDrifted,
}

/// The verdict [`evaluate_pair`] returns for one configured pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PairUsability {
    /// Every condition holds. The pair is left exactly as it is.
    Usable,
    /// One condition failed, naming which.
    Unusable(UnusableMaterial),
}

/// Applies the eight ordered usability conditions to one configured
/// pair.
///
/// `expected_name` is the reserved name this pair must carry, and
/// `ca_bundle_path` is `[trust].ca_bundle_path`. With that unconfigured
/// the eighth condition does not run at all: the operator opted out of
/// bundle management, and nothing is re-issued for want of an anchor
/// set. That is the opt-out the daemon's own renewal predicate
/// already honours, adopted rather than restated so there is one rule
/// and not two.
///
/// Consults no pin list, builds no verifier and judges no chain other
/// than through [`cert_chain::leaf_chains_to_bundle`].
pub(crate) async fn evaluate_pair(
    cert_path: &Path,
    key_path: &Path,
    expected_name: &str,
    ca_bundle_path: Option<&Path>,
) -> PairUsability {
    tls::install_crypto_provider();

    // 1 and 2: present, then readable. Absence outranks unreadability,
    // so both reads happen before either is classified — otherwise an
    // unreadable certificate beside an absent key would be reported as
    // the second condition when the first is what failed.
    let cert_read = tokio::fs::read(cert_path).await;
    let key_read = tokio::fs::read(key_path).await;
    if is_not_found(&cert_read) || is_not_found(&key_read) {
        return PairUsability::Unusable(UnusableMaterial::Absent);
    }
    let (Ok(cert_bytes), Ok(key_bytes)) = (cert_read, key_read) else {
        return PairUsability::Unusable(UnusableMaterial::Unreadable);
    };

    // 3: both parse. Everything below reads a value off the parsed leaf,
    // so a file that does not parse is classified here and nowhere else.
    let Some(parsed) = parse_pair(&cert_bytes, &key_bytes) else {
        return PairUsability::Unusable(UnusableMaterial::Malformed);
    };

    // 4: the key is the leaf's.
    if !tls::cert_key_matches(&parsed.leaf, parsed.signing_key.as_ref()) {
        return PairUsability::Unusable(UnusableMaterial::KeyMismatched);
    }

    // 5: exactly one DNS SAN, and it is the reserved name for this pair.
    let Ok(san) = single_dns_san(parsed.leaf.as_ref()) else {
        return PairUsability::Unusable(UnusableMaterial::SanMismatched);
    };
    if san != expected_name.to_ascii_lowercase() {
        return PairUsability::Unusable(UnusableMaterial::SanMismatched);
    }

    // 6 and 7: the validity window, split by direction. The two are
    // reachable from opposite host-to-CA skew and do not end the same
    // way, so one condition named "expired" could not express the first.
    // The window was read off the leaf condition 3 parsed, so nothing is
    // parsed twice and no arm here can be reached by a leaf that did
    // not parse.
    let now = ASN1Time::now();
    if now < parsed.not_before {
        return PairUsability::Unusable(UnusableMaterial::NotYetValid);
    }
    if now > parsed.not_after {
        return PairUsability::Unusable(UnusableMaterial::Expired);
    }

    // 8: the chain, and only when an anchor set is configured.
    let Some(bundle_path) = ca_bundle_path else {
        return PairUsability::Usable;
    };
    let Ok(bundle_bytes) = tokio::fs::read(bundle_path).await else {
        return PairUsability::Unusable(UnusableMaterial::ChainDrifted);
    };
    match cert_chain::leaf_chains_to_bundle(&cert_bytes, &bundle_bytes) {
        Ok(true) => PairUsability::Usable,
        Ok(false) | Err(_) => PairUsability::Unusable(UnusableMaterial::ChainDrifted),
    }
}

/// What a pair's two files parse to: the leaf, its signing key, and the
/// validity window read off the leaf while it was parsed.
struct ParsedPair {
    leaf: rustls::pki_types::CertificateDer<'static>,
    signing_key: std::sync::Arc<dyn rustls::sign::SigningKey>,
    not_before: ASN1Time,
    not_after: ASN1Time,
}

/// Parses the certificate and key bytes, or reports that one of them
/// does not parse.
///
/// Quotes none of the bytes it failed on: the key file is key material,
/// and a diagnostic that named it would put it in a log.
fn parse_pair(cert_bytes: &[u8], key_bytes: &[u8]) -> Option<ParsedPair> {
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_bytes))
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
    let leaf = certs.into_iter().next()?;
    let (not_before, not_after) = {
        let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref()).ok()?;
        let validity = parsed.validity();
        (validity.not_before, validity.not_after)
    };
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_bytes)).ok()??;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).ok()?;
    Some(ParsedPair {
        leaf,
        signing_key,
        not_before,
        not_after,
    })
}

fn is_not_found(result: &std::io::Result<Vec<u8>>) -> bool {
    matches!(result, Err(err) if err.kind() == std::io::ErrorKind::NotFound)
}

/// One configured pair, resolved down to everything an issuance needs.
#[derive(Debug, Clone)]
pub(crate) struct SurfacePairPaths {
    /// Which leaf this pair holds.
    pub(crate) leaf: SurfaceLeaf,
    /// The configured certificate path.
    pub(crate) cert_path: PathBuf,
    /// The configured key path.
    pub(crate) key_path: PathBuf,
    /// The reserved name the leaf must carry.
    pub(crate) name: String,
}

/// Resolves both configured pairs from an enabled `[registrar_endpoint]`
/// table and a host label.
///
/// # Errors
///
/// Returns an error naming the first unset path. Configuration
/// validation has already refused an enabled endpoint with any of the
/// four unset, so reaching one of these is a caller that skipped it.
pub(crate) fn surface_pairs(
    endpoint: &RegistrarEndpointSettings,
    host: &str,
    domain: &str,
) -> Result<Vec<SurfacePairPaths>> {
    let mut pairs = Vec::with_capacity(2);
    for (leaf, cert, key) in [
        (
            SurfaceLeaf::EndpointServer,
            endpoint.server_cert_path.as_deref(),
            endpoint.server_key_path.as_deref(),
        ),
        (
            SurfaceLeaf::RegistrarClient,
            endpoint.client_cert_path.as_deref(),
            endpoint.client_key_path.as_deref(),
        ),
    ] {
        let cert_path = cert.ok_or_else(|| unset_path(leaf.cert_setting()))?;
        let key_path = key.ok_or_else(|| unset_path(leaf.key_setting()))?;
        pairs.push(SurfacePairPaths {
            leaf,
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            name: leaf.identity(host, domain),
        });
    }
    Ok(pairs)
}

fn unset_path(setting: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{setting} is unset; there is no default and issuance has nowhere to write the material"
    )
}

/// Ensures both of the registrar surface's leaves are usable, issuing
/// whichever is not.
///
/// The callable unit. `bootroot-agent` drives it once at start, above
/// [`crate::registrar::RegistrarEndpoint::activate`], and the daemon's
/// certificate-renewal mechanism can drive it again without any of this
/// living in start-up-only code.
///
/// Does nothing at all — no path created, no `OpenBao` request, no CA
/// request — unless `registrar_endpoint.enabled` is true. Then, with
/// both pairs usable, it still makes no `OpenBao` and no CA request: the
/// two ACME inputs are read only once a leaf actually needs issuing, so
/// a host whose material is fine starts with `OpenBao` down.
///
/// # Errors
///
/// Returns an error when the deployment state file or the rendered
/// internal config cannot be read or fails its invariants, when the
/// internal credential is absent, invalid or superseded by a trust
/// rotation, when either `OpenBao` read fails, or when an issuance
/// fails — including a CA bundle that cannot be read and a leaf that
/// cannot be written. Every one of them names the material paths it was
/// refused for as well as the failure itself. An issuance names its own
/// pair; the credential load and the two `OpenBao` reads, which are
/// shared by both pairs, name every pair that was pending; and the
/// resolution step, which runs before the host label those names are
/// composed from is known, names the four configured paths.
/// There is no fallback on any of these: no self-signed leaf, no
/// borrowed one, and no second source for either ACME input.
pub async fn ensure_registrar_surface_certificates(
    settings: &Settings,
    insecure_mode: bool,
) -> Result<()> {
    if !settings.registrar_endpoint.enabled {
        return Ok(());
    }
    // Named against the configured paths rather than the pairs: this
    // step is what resolves the host label the pairs' names are composed
    // from, so nothing here can name a leaf, and the four paths are the
    // only material identifiers that exist yet.
    let plan = resolve_surface_plan(settings).with_context(|| {
        format!(
            "resolving the registrar surface issuance for the material at {}",
            describe_configured_paths(&settings.registrar_endpoint)
        )
    })?;
    let pending = pending_pairs(&plan, settings.trust.ca_bundle_path.as_deref()).await;
    if pending.is_empty() {
        return Ok(());
    }
    // Only now: with both pairs usable this is never reached, so a
    // daemon whose material is fine starts with OpenBao down.
    let inputs = read_acme_inputs(&plan.secrets_dir, &plan.openbao_url, &plan.kv_mount)
        .await
        .with_context(|| {
            format!(
                "reading the ACME inputs for the registrar surface material still to be issued: {}",
                describe_pairs(&pending)
            )
        })?;
    for pair in pending {
        issue_surface_pair(settings, &pair, &plan.host, &inputs, insecure_mode).await?;
    }
    Ok(())
}

/// Renders the four configured material paths for a diagnostic, before
/// any of them has been resolved into a pair.
///
/// An unset path is rendered as such rather than skipped: configuration
/// validation has already refused an enabled endpoint with any of the
/// four unset, so a diagnostic that reaches this with one missing is
/// reporting a caller that skipped that validation, and hiding the hole
/// is exactly the wrong answer there.
fn describe_configured_paths(endpoint: &RegistrarEndpointSettings) -> String {
    [
        (
            SurfaceLeaf::EndpointServer.cert_setting(),
            endpoint.server_cert_path.as_deref(),
        ),
        (
            SurfaceLeaf::EndpointServer.key_setting(),
            endpoint.server_key_path.as_deref(),
        ),
        (
            SurfaceLeaf::RegistrarClient.cert_setting(),
            endpoint.client_cert_path.as_deref(),
        ),
        (
            SurfaceLeaf::RegistrarClient.key_setting(),
            endpoint.client_key_path.as_deref(),
        ),
    ]
    .iter()
    .map(|(setting, path)| match path {
        Some(path) => format!("{setting} = {}", path.display()),
        None => format!("{setting} (unset)"),
    })
    .collect::<Vec<_>>()
    .join(", ")
}

/// Renders the pairs' reserved names and configured paths for a
/// diagnostic.
///
/// A failure that is not about one pair in particular — the two
/// `OpenBao` reads are shared by both — still has to name the material
/// it was reached for, so the refusal carries the certificate and key
/// paths of every pair that was pending and of none that was not.
fn describe_pairs(pairs: &[SurfacePairPaths]) -> String {
    pairs
        .iter()
        .map(|pair| {
            format!(
                "{} at {} and {}",
                pair.name,
                pair.cert_path.display(),
                pair.key_path.display()
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Everything an endpoint-enabled host's issuance is resolved from,
/// before any pair has been looked at.
#[derive(Debug, Clone)]
pub(crate) struct SurfacePlan {
    /// The secrets directory the deployment state file resolves to.
    pub(crate) secrets_dir: PathBuf,
    /// The `OpenBao` URL that file records.
    pub(crate) openbao_url: String,
    /// The KV v2 mount that file records. Never taken from `agent.toml`,
    /// which carries no such key for this path.
    pub(crate) kv_mount: String,
    /// The bootroot host's own label, from the rendered internal config.
    pub(crate) host: String,
    /// Both configured pairs, in evaluation order.
    pub(crate) pairs: Vec<SurfacePairPaths>,
}

/// Resolves the state file, the secrets directory, the host label and
/// both configured pairs.
///
/// Resolved here rather than borrowed from the registrar handler: that
/// handler is built inside `run_daemon`, which is reached only after the
/// endpoint has been activated, and issuance has to run before that. The
/// same two helpers are used, so there is one resolution rule and not
/// two, and the handler is not made a prerequisite of anything here.
///
/// # Errors
///
/// Returns an error when `[registrar] state_file` is unset, when that
/// file cannot be read or carries an unusable member, when the rendered
/// internal agent config is absent, unparseable or fails the loader's
/// invariants, or when one of the four material paths is unset. No name
/// is ever composed from a guessed label.
pub(crate) fn resolve_surface_plan(settings: &Settings) -> Result<SurfacePlan> {
    let state_file = settings.registrar.state_file.as_deref().ok_or_else(|| {
        anyhow::anyhow!(
            "registrar.state_file is required when registrar_endpoint.enabled is true, and no \
             value was configured"
        )
    })?;
    let state = crate::daemon::read_registrar_state(state_file)?;
    let secrets_dir = crate::daemon::resolve_secrets_dir(state_file, state.secrets_dir.as_deref());
    let internal_paths = InternalPaths::new(&secrets_dir);

    // The host label is the internal profile's own, held to the loader's
    // invariants rather than trusted blind. Never a new configuration
    // key, never the system hostname, and never parsed back out of the
    // internal leaf's SAN.
    let internal = load_internal_config(&internal_paths).with_context(|| {
        format!(
            "reading the bootroot host label from the rendered internal agent config at {}",
            internal_paths.agent_config().display()
        )
    })?;
    let host = internal
        .profiles
        .first()
        .map(|profile| profile.hostname.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the rendered internal agent config at {} carries no profile to take the host \
                 label from",
                internal_paths.agent_config().display()
            )
        })?;

    let pairs = surface_pairs(&settings.registrar_endpoint, &host, &settings.domain)?;
    Ok(SurfacePlan {
        secrets_dir,
        openbao_url: state.openbao_url,
        kv_mount: state.kv_mount,
        host,
        pairs,
    })
}

/// Evaluates both pairs and returns the ones an issuance has to replace.
///
/// The two are judged independently, so one being usable is never a
/// reason to leave the other unusable.
pub(crate) async fn pending_pairs(
    plan: &SurfacePlan,
    ca_bundle_path: Option<&Path>,
) -> Vec<SurfacePairPaths> {
    let mut pending = Vec::with_capacity(plan.pairs.len());
    for pair in &plan.pairs {
        match evaluate_pair(&pair.cert_path, &pair.key_path, &pair.name, ca_bundle_path).await {
            PairUsability::Usable => {
                info!(
                    "Registrar surface material for {} is usable; leaving it as it is.",
                    pair.name
                );
            }
            PairUsability::Unusable(reason) => {
                warn!(
                    "Registrar surface material for {} at {} is unusable ({reason}); issuing a \
                     replacement.",
                    pair.name,
                    pair.cert_path.display()
                );
                pending.push(pair.clone());
            }
        }
    }
    pending
}

/// The two ACME inputs, read from `OpenBao` under the internal
/// credential and held in memory only.
///
/// Neither is written back to disk. The fast-poll loop's on-disk
/// `[acme] http_responder_hmac` upsert is a different arrangement under
/// a different credential, and is neither used nor imitated here.
#[derive(Debug)]
pub(crate) struct SurfaceAcmeInputs {
    /// The account EAB, absent when the deployment recorded the explicit
    /// clear shape.
    pub(crate) eab: Option<EabCredentials>,
    /// The HTTP-01 responder HMAC the challenge publication is
    /// authenticated with.
    pub(crate) responder_hmac: HmacSecret,
}

/// Reads the account EAB and the responder HMAC under the
/// bootroot-internal credential.
///
/// Both paths are already inside that credential's policy envelope, so
/// no policy widens for this. The credential is loaded here rather than
/// at start because loading it is what refuses a start inside a trust
/// rotation, and that refusal belongs to a start that actually needs to
/// issue.
///
/// # Errors
///
/// Returns an error when the credential is absent, invalid or
/// superseded, when the certificate login fails, when either KV path
/// cannot be read, or when either payload does not parse. Every one of
/// them is a refusal: there is no fallback to `agent.toml`, to the
/// internal profile's rendered config, or to issuing without EAB.
pub(crate) async fn read_acme_inputs(
    secrets_dir: &Path,
    openbao_url: &str,
    kv_mount: &str,
) -> Result<SurfaceAcmeInputs> {
    let active_root = active_root_fingerprint(secrets_dir).with_context(|| {
        format!(
            "reading the deployment's active root fingerprint below {}",
            secrets_dir.display()
        )
    })?;
    // The credential's own active-root refusal stands: a start inside a
    // trust-rotation window refuses with its diagnostic, and finishing
    // the rotation is the remedy. Nothing here retries around it.
    let credential = InternalCredential::load(secrets_dir, openbao_url, &active_root)
        .context("loading the bootroot-internal credential for the registrar surface issuance")?;
    read_acme_inputs_with(&credential, kv_mount).await
}

/// Reads the two inputs through an already-loaded credential.
///
/// Split from [`read_acme_inputs`] so the KV half can be exercised
/// against a client-authenticated transport a test supplies, without a
/// second spelling of either path or either parser.
///
/// # Errors
///
/// Returns an error when the certificate login fails, when either KV
/// path cannot be read, or when either payload does not parse.
pub(crate) async fn read_acme_inputs_with(
    credential: &InternalCredential,
    kv_mount: &str,
) -> Result<SurfaceAcmeInputs> {
    let client = credential.authenticated().await.context(
        "authenticating to OpenBao with the bootroot-internal certificate for the registrar \
         surface issuance",
    )?;

    let eab_value = client
        .read_kv(kv_mount, PATH_AGENT_EAB)
        .await
        .with_context(|| format!("reading the agent EAB at {kv_mount}/data/{PATH_AGENT_EAB}"))?;
    let eab = match crate::kv_payload::parse_eab_payload(&eab_value)
        .with_context(|| format!("parsing the agent EAB at {kv_mount}/data/{PATH_AGENT_EAB}"))?
    {
        crate::kv_payload::EabPayload::Populated { kid, hmac } => Some(EabCredentials {
            kid,
            hmac: hmac.into(),
        }),
        crate::kv_payload::EabPayload::Clear => None,
    };

    let hmac_value = client
        .read_kv(kv_mount, PATH_RESPONDER_HMAC)
        .await
        .with_context(|| {
            format!("reading the responder HMAC at {kv_mount}/data/{PATH_RESPONDER_HMAC}")
        })?;
    let responder_hmac =
        crate::kv_payload::parse_responder_hmac(&hmac_value).with_context(|| {
            format!("parsing the responder HMAC at {kv_mount}/data/{PATH_RESPONDER_HMAC}")
        })?;

    Ok(SurfaceAcmeInputs {
        eab,
        responder_hmac: HmacSecret::new(responder_hmac),
    })
}

/// Issues one pair over the daemon's existing outbound ACME path to the
/// local step-ca and publishes it at its configured paths.
///
/// Never through the registrar endpoint: the endpoint is not a
/// prerequisite for issuing the certificate it presents, which is what
/// lets a first start mint the server pair with nothing listening.
///
/// # Errors
///
/// Returns an error naming both configured paths and the failure.
pub(crate) async fn issue_surface_pair(
    settings: &Settings,
    pair: &SurfacePairPaths,
    host: &str,
    inputs: &SurfaceAcmeInputs,
    insecure_mode: bool,
) -> Result<()> {
    let issuance = issuance_settings(settings, pair, host, &inputs.responder_hmac);
    let profile = issuance
        .profiles
        .first()
        .ok_or_else(|| anyhow::anyhow!("the registrar surface issuance profile was not built"))?;
    crate::acme::issue_certificate_with(
        &issuance,
        profile,
        inputs.eab.clone(),
        insecure_mode,
        pair.leaf.issuance_options(),
    )
    .await
    .with_context(|| {
        format!(
            "issuing {} to {} and {}",
            pair.name,
            pair.cert_path.display(),
            pair.key_path.display()
        )
    })
}

/// Builds the settings one surface issuance runs under.
///
/// The daemon's own settings with two substitutions and nothing else:
/// the single profile is the reserved-name one this pair needs, and
/// `[acme] http_responder_hmac` is the value just read from `OpenBao`.
/// The substitution is in memory; no file is rewritten.
fn issuance_settings(
    settings: &Settings,
    pair: &SurfacePairPaths,
    host: &str,
    responder_hmac: &HmacSecret,
) -> Settings {
    let mut issuance = settings.clone();
    issuance.acme.http_responder_hmac = responder_hmac.clone();
    // `[eab]` is dropped rather than carried: the EAB reaching the ACME
    // account registration is the one read from OpenBao, passed as an
    // argument, and leaving a second source in the settings is how a
    // stale one comes back invisibly.
    issuance.eab = None;
    issuance.profiles = vec![DaemonProfileSettings {
        registration_id: format!("{}-{host}", pair.leaf.service_label()),
        service_name: pair.leaf.service_label().to_string(),
        instance_id: REGISTRAR_SURFACE_INSTANCE.to_string(),
        hostname: host.to_string(),
        paths: Paths {
            cert: pair.cert_path.clone(),
            key: pair.key_path.clone(),
        },
        daemon: crate::config::DaemonRuntimeSettings::default(),
        retry: None,
        hooks: HookSettings::default(),
        eab: None,
        // Root-owned material with no cert group: the key is 0600 and
        // the co-located registrar reads the *client certificate*, which
        // is public, from a path root also owns.
        cert_group_gid: None,
    }];
    issuance
}

#[cfg(test)]
mod tests;
