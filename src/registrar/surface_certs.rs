//! The daemon's self-issuance of the registrar surface's two
//! certificates.
//!
//! An endpoint-enabled bootroot host needs two leaves that no other path
//! in this repository can produce. The host-local endpoint presents
//! `001.bootroot-registrar-endpoint.<host>.<domain>` and the co-located
//! registrar authenticates back with
//! `001.bootroot-registrar.<host>.<domain>`, holding no `OpenBao`
//! credential of its own. Both names fall inside the reserved
//! [`crate::registrar::RESERVED_SERVICE_NAME_PREFIX`] namespace, so
//! [`crate::registrar::is_reserved_service_name`] makes both unmintable
//! through `service add` — by construction, because that is what keeps
//! an operator-authored service identity from ever occupying either
//! name. The only producer they can have is this daemon.
//!
//! # What runs, and when
//!
//! [`ensure_surface_certificates`] runs once per process start —
//! reached from `crate::ensure_registrar_surface_certificates`, the
//! composition boundary that resolves the deployment inventory —
//! **before** [`crate::RegistrarEndpoint::activate`] loads the
//! endpoint's TLS material, so the endpoint never comes up presenting or
//! holding an expired leaf. It is a plain function of the settings
//! rather than start-up-only code, so the daemon's certificate-renewal
//! mechanism can drive the same unit later.
//!
//! This is **not** a registrar-specific scheduler, which
//! [`crate::registrar::internal`] rules out and which this module does
//! not become: there is no registration point, no lead-time constant and
//! no retry policy here, and nothing changes how the internal profile or
//! the per-service loop is scheduled, credentialed or triggered.
//!
//! # Under which credential
//!
//! The producer is the daemon under the bootroot-internal privileged
//! credential ([`crate::registrar::internal::InternalCredential`]),
//! never the per-service ACME agent loop. That loop authenticates with a
//! `role_id` and a `secret_id`, and routing either leaf through it would
//! put an expiring secret back under the registrar surface — exactly
//! what choosing a certificate form for the registrar's identity was
//! meant to escape. Nothing on this path reads a `role_id` or a
//! `secret_id`.
//!
//! Running "under" that credential has observable content rather than
//! being a statement about which process holds which file: the two ACME
//! inputs — the shared agent EAB at
//! [`crate::trust_bootstrap::AGENT_EAB_KV_PATH`] and the HTTP-01
//! responder HMAC at [`crate::trust_bootstrap::RESPONDER_HMAC_KV_PATH`]
//! — are read from `OpenBao` through that credential, under the KV mount
//! the caller resolved, and only when a leaf actually needs issuing.
//!
//! # What this module is not told
//!
//! Nothing here knows where the deployment's inventory lives or how the
//! three values below were arrived at. They arrive as parameters, the
//! same boundary the registrar verb layer is held to, so the whole
//! `registrar` module stays a function of what it is handed.
//!
//! # Issuing is not renewing
//!
//! This module owns only the state the daemon finds at start. Keeping
//! both leaves valid over time — a renewal schedule, the reload contract
//! on either side, a health field carrying remaining lifetime and a
//! surface that reports a lapse — is separate work built on the unit
//! defined here.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use time::OffsetDateTime;
use tracing::{info, warn};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::{ASN1Time, FromDer};

use crate::acme::{CsrShape, issue_certificate_with_shape};
use crate::config::{
    DaemonProfileSettings, HookSettings, Paths, RegistrarEndpointSettings, Settings,
};
use crate::eab::EabCredentials;
use crate::kv_payload::{EabPayload, parse_eab_payload, parse_responder_hmac};
use crate::registrar::internal::{
    InternalCredential, InternalPaths, active_root_fingerprint, load_internal_config,
};
use crate::registrar::{
    REGISTRAR_CLIENT_LABEL, REGISTRAR_ENDPOINT_LABEL, REGISTRAR_SURFACE_INSTANCE,
    registrar_client_identity, registrar_endpoint_identity, single_dns_san,
};
use crate::secret::HmacSecret;
use crate::trust_bootstrap::{AGENT_EAB_KV_PATH, RESPONDER_HMAC_KV_PATH};
use crate::{cert_chain, tls};

/// How the endpoint's server certificate key is spelled in a diagnostic,
/// exactly as an operator would find it in `agent.toml`.
const SERVER_CERT_SETTING: &str = "[registrar_endpoint] server_cert_path";
/// How the endpoint's server private-key key is spelled.
const SERVER_KEY_SETTING: &str = "[registrar_endpoint] server_key_path";
/// How the registrar client certificate key is spelled.
const CLIENT_CERT_SETTING: &str = "[registrar_endpoint] client_cert_path";
/// How the registrar client private-key key is spelled.
const CLIENT_KEY_SETTING: &str = "[registrar_endpoint] client_key_path";

/// Which of the registrar surface's two identities a pair of paths
/// carries.
///
/// The two are evaluated and issued **independently**: one being usable
/// is never a reason to leave the other as it was found, and one needing
/// issuance is never a reason to reissue the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SurfaceLeaf {
    /// The registrar's client identity,
    /// `<instance>.bootroot-registrar.<host>.<domain>`, which requests
    /// `clientAuth`.
    Client,
    /// The endpoint's server identity,
    /// `<instance>.bootroot-registrar-endpoint.<host>.<domain>`, which
    /// needs no added extended key usage.
    Endpoint,
}

impl SurfaceLeaf {
    /// The reserved second label this identity is composed under.
    #[must_use]
    fn service_label(self) -> &'static str {
        match self {
            Self::Client => REGISTRAR_CLIENT_LABEL,
            Self::Endpoint => REGISTRAR_ENDPOINT_LABEL,
        }
    }

    /// The CSR shape this identity is requested with.
    #[must_use]
    fn csr_shape(self) -> CsrShape {
        match self {
            Self::Client => CsrShape::RegistrarClient,
            Self::Endpoint => CsrShape::Service,
        }
    }

    /// Composes this identity's one DNS SAN.
    #[must_use]
    fn identity(self, host: &str, domain: &str) -> String {
        match self {
            Self::Client => registrar_client_identity(REGISTRAR_SURFACE_INSTANCE, host, domain),
            Self::Endpoint => registrar_endpoint_identity(REGISTRAR_SURFACE_INSTANCE, host, domain),
        }
    }

    /// How this identity's two settings are spelled in a diagnostic.
    #[must_use]
    fn settings(self) -> (&'static str, &'static str) {
        match self {
            Self::Client => (CLIENT_CERT_SETTING, CLIENT_KEY_SETTING),
            Self::Endpoint => (SERVER_CERT_SETTING, SERVER_KEY_SETTING),
        }
    }
}

/// Why material at a configured path cannot be used.
///
/// The eight variants are the eight ordered usability conditions negated
/// one at a time, so the enumeration is exhaustive by construction
/// rather than by assertion. **Every one of them is answered by
/// issuing**, never by refusing: each is a state some ordinary mishap
/// leaves behind, and refusing would brick the daemon in precisely the
/// states whose repair requires the daemon to be running.
///
/// "Answered by issuing" is a guarantee about what the daemon
/// *attempts*. A write that cannot land and a CA bundle that cannot be
/// read are both issuance failures, and a replacement still outside its
/// validity window at the host's clock is a successful issuance the
/// endpoint's own loader then refuses.
///
/// An **unset** path is not one of these. It is not a state of material
/// at all, issuance has nowhere to write, and configuration validation
/// refuses it before anything here runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum UnusableMaterial {
    /// Condition 1: one or both files are not there. A first start, or a
    /// host whose material was cleared.
    #[error("the certificate or the key file is absent")]
    Absent,
    /// Condition 2: a file exists and could not be read.
    #[error("the certificate or the key file could not be read")]
    Unreadable,
    /// Condition 3: the certificate file yields no certificate, the
    /// leaf is not a parseable X.509, or the key file yields no usable
    /// private key. What a renewal that lost power mid-write leaves.
    ///
    /// Its own condition rather than folded into the chain arm, because
    /// the chain arm does not run at all when `[trust].ca_bundle_path`
    /// is unconfigured — and a truncated file would then be reported as
    /// key-mismatched or SAN-mismatched, naming the wrong cause on
    /// exactly the material a crashed renewal is most likely to leave.
    #[error("the certificate or the key file does not parse")]
    Malformed,
    /// Condition 4: the key is not the key of the leaf. What a renewal
    /// that died between the certificate rename and the key rename
    /// leaves.
    #[error("the private key is not the key of the leaf certificate")]
    KeyMismatch,
    /// Condition 5: the leaf does not carry exactly one DNS SAN equal to
    /// the reserved name for this pair.
    #[error("the leaf certificate does not carry the expected reserved name as its single DNS SAN")]
    SanMismatch,
    /// Condition 6: the leaf's `not_before` has not passed at the host's
    /// clock. Reachable from clock skew, and split from
    /// [`Self::Expired`] because the endpoint's loader judges the window
    /// at the *host's* clock, so the two are reached from opposite skew.
    #[error("the leaf certificate's validity window has not started at this host's clock")]
    NotYetValid,
    /// Condition 7: the leaf's `not_after` has passed. What a daemon
    /// down through `not_after` comes back to — material that parses
    /// perfectly and cannot be used for anything.
    #[error("the leaf certificate's validity window has ended at this host's clock")]
    Expired,
    /// Condition 8: the leaf no longer chains to `[trust]
    /// ca_bundle_path`. What a destructive trust-anchor rotation leaves:
    /// a still-time-valid, correctly named leaf signed by the *previous*
    /// CA generation, which looks perfect and fails every handshake.
    #[error("the leaf certificate no longer chains to the configured trust anchors")]
    ChainDrifted,
}

/// What the eight ordered conditions decided about one pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Usability {
    /// Every condition holds. The pair is left exactly as it is: it is
    /// not re-issued, which would churn a file the co-located registrar
    /// is reading and hand that process a new key on every restart.
    Usable,
    /// Some condition does not hold, and issuance is attempted.
    Unusable(UnusableMaterial),
}

impl Usability {
    /// Reports whether the pair needs issuing.
    #[must_use]
    pub fn needs_issuance(self) -> bool {
        matches!(self, Self::Unusable(_))
    }
}

/// One identity's configured pair of paths.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PairPaths {
    leaf: SurfaceLeaf,
    cert: PathBuf,
    key: PathBuf,
}

/// Reads the four configured material paths out of `[registrar_endpoint]`.
///
/// Configuration validation has already refused an enabled endpoint with
/// any of them unset, so the diagnostics here are the same refusal
/// restated for a caller that reached this module another way — never a
/// default, and never a repair.
fn material_paths(settings: &RegistrarEndpointSettings) -> anyhow::Result<(PairPaths, PairPaths)> {
    let required = |value: Option<&Path>, setting: &'static str| -> anyhow::Result<PathBuf> {
        value.map(Path::to_path_buf).ok_or_else(|| {
            anyhow::anyhow!("{setting} is required when the registrar endpoint is enabled")
        })
    };
    let client = PairPaths {
        leaf: SurfaceLeaf::Client,
        cert: required(settings.client_cert_path.as_deref(), CLIENT_CERT_SETTING)?,
        key: required(settings.client_key_path.as_deref(), CLIENT_KEY_SETTING)?,
    };
    let endpoint = PairPaths {
        leaf: SurfaceLeaf::Endpoint,
        cert: required(settings.server_cert_path.as_deref(), SERVER_CERT_SETTING)?,
        key: required(settings.server_key_path.as_deref(), SERVER_KEY_SETTING)?,
    };
    Ok((client, endpoint))
}

/// Applies the eight ordered usability conditions to one pair.
///
/// The conditions are ordered so that each is only meaningful once the
/// ones above it hold, and they are evaluated in that order. Nothing
/// here is a second verification path: the chain condition is
/// [`cert_chain::leaf_chains_to_bundle`] against `ca_bundle_path` and
/// nothing more. It consults neither `trust.trusted_ca_sha256` nor the
/// pinned-anchor requirement, and runs neither the endpoint's verifier
/// nor its self-check — those are the loader's, performed a few lines
/// later, and its acceptance rule is strictly stronger than this one.
///
/// With `ca_bundle_path` unconfigured, condition 8 does not run at all
/// and conditions 1 through 7 decide, which is the opt-out
/// `crate::daemon`'s renewal predicate already honours. That is not a
/// supported shape for an endpoint-enabled host — the loader hard-
/// requires a bundle — but keeping one predicate rather than two is
/// worth more than refusing a shape something else already refuses.
#[must_use]
fn evaluate_pair(
    cert_path: &Path,
    key_path: &Path,
    expected_name: &str,
    ca_bundle_path: Option<&Path>,
    now: OffsetDateTime,
) -> Usability {
    let cert_bytes = match std::fs::read(cert_path) {
        Ok(bytes) => bytes,
        Err(err) => return Usability::Unusable(io_condition(&err)),
    };
    let key_bytes = match std::fs::read(key_path) {
        Ok(bytes) => bytes,
        Err(err) => return Usability::Unusable(io_condition(&err)),
    };

    let Some(certs) = parse_certificates(&cert_bytes) else {
        return Usability::Unusable(UnusableMaterial::Malformed);
    };
    let Some(leaf_der) = certs.first() else {
        return Usability::Unusable(UnusableMaterial::Malformed);
    };
    let Ok((_, leaf)) = X509Certificate::from_der(leaf_der.as_ref()) else {
        return Usability::Unusable(UnusableMaterial::Malformed);
    };
    let Some(signing_key) = parse_signing_key(&key_bytes) else {
        return Usability::Unusable(UnusableMaterial::Malformed);
    };

    if !tls::cert_key_matches(leaf_der, signing_key.as_ref()) {
        return Usability::Unusable(UnusableMaterial::KeyMismatch);
    }

    match single_dns_san(leaf_der.as_ref()) {
        Ok(name) if name == expected_name.to_ascii_lowercase() => {}
        _ => return Usability::Unusable(UnusableMaterial::SanMismatch),
    }

    let Ok(now) = ASN1Time::from_timestamp(now.unix_timestamp()) else {
        // A host clock outside what an ASN.1 time can carry cannot judge
        // a validity window at all; treat the window as unsatisfied and
        // let issuance replace the leaf.
        return Usability::Unusable(UnusableMaterial::NotYetValid);
    };
    let validity = leaf.validity();
    if now < validity.not_before {
        return Usability::Unusable(UnusableMaterial::NotYetValid);
    }
    if validity.not_after < now {
        return Usability::Unusable(UnusableMaterial::Expired);
    }

    let Some(bundle_path) = ca_bundle_path else {
        return Usability::Usable;
    };
    match std::fs::read(bundle_path) {
        Ok(bundle_bytes) => match cert_chain::leaf_chains_to_bundle(&cert_bytes, &bundle_bytes) {
            Ok(true) => Usability::Usable,
            _ => Usability::Unusable(UnusableMaterial::ChainDrifted),
        },
        // A bundle that is missing, unreadable or unparseable makes the
        // pair chain-drifted, exactly as the renewal predicate already
        // decides it. What follows *detection* differs by bundle case,
        // and that difference belongs to the write path rather than
        // here: `write_merged_ca_bundle` merges against an empty seed
        // for a missing bundle and refuses to overwrite an unreadable
        // one, before any leaf is published.
        Err(_) => Usability::Unusable(UnusableMaterial::ChainDrifted),
    }
}

/// Separates condition 1 from condition 2.
///
/// "Not there" and "there and unreadable" are distinct states, and an
/// operator sent looking for a permission problem that is really a typo
/// in a path has been told the wrong thing.
fn io_condition(err: &std::io::Error) -> UnusableMaterial {
    if err.kind() == std::io::ErrorKind::NotFound {
        UnusableMaterial::Absent
    } else {
        UnusableMaterial::Unreadable
    }
}

/// Decodes the certificate PEM into DER blocks, or `None` when it holds
/// no certificate at all.
fn parse_certificates(
    cert_bytes: &[u8],
) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_bytes))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!certs.is_empty()).then_some(certs)
}

/// Decodes the key PEM into a signing key this build can sign with.
///
/// The failure carries none of the bytes it failed on: this input is key
/// material, and a parse failure that named it would put it in a log.
fn parse_signing_key(key_bytes: &[u8]) -> Option<std::sync::Arc<dyn rustls::sign::SigningKey>> {
    tls::install_crypto_provider();
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_bytes)).ok()??;
    rustls::crypto::ring::sign::any_supported_type(&key).ok()
}

/// The two ACME inputs one issuance run needs, read from `OpenBao` under
/// the bootroot-internal credential.
///
/// Held in memory and nowhere else. Neither value is written back to
/// disk: the fast-poll loop's `apply_responder_hmac` upserts
/// `[acme] http_responder_hmac` under the per-service `AppRole`, and
/// these issuances neither use that loop nor imitate it.
///
/// The hand-written [`std::fmt::Debug`] is what keeps a derived one on
/// an enclosing type from ever printing either secret.
struct AcmeInputs {
    eab: Option<EabCredentials>,
    responder_hmac: HmacSecret,
}

impl std::fmt::Debug for AcmeInputs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AcmeInputs")
            .field(
                "eab_kid",
                &self.eab.as_ref().map(|creds| creds.kid.as_str()),
            )
            .finish_non_exhaustive()
    }
}

/// What one issuance run needs from the deployment's inventory.
///
/// Three values, all resolved by the caller. This module deliberately
/// does not learn where they came from: the deployment inventory is the
/// daemon's to open, and every path in the `registrar` module stays a
/// function of what it is handed rather than of a file it goes looking
/// for.
#[derive(Debug, Clone, Copy)]
pub struct SurfaceIssuanceInputs<'a> {
    /// The deployment's secrets directory, which the fixed
    /// bootroot-internal layout sits below.
    pub secrets_dir: &'a Path,
    /// The deployment's `OpenBao` URL. Must be `https://`; the internal
    /// credential refuses anything else.
    pub openbao_url: &'a str,
    /// The KV v2 mount the two ACME inputs are read under.
    pub kv_mount: &'a str,
}

/// Issues the registrar surface's two certificates where what is on disk
/// cannot be used, and leaves usable material exactly as it is.
///
/// Does nothing at all — no path created, nothing requested from the CA
/// or from `OpenBao` — when `registrar_endpoint.enabled` is false, which
/// is every deployment but a bootroot host. That is the same setting the
/// endpoint itself is gated on; there is no second enablement key.
///
/// The two pairs are evaluated independently against the eight ordered
/// conditions in [`UnusableMaterial`]. When both are usable the function
/// returns before any `OpenBao` call, so a daemon whose material is fine
/// starts with `OpenBao` down.
///
/// # Errors
///
/// Returns an error, naming the material paths and the failure, when the
/// rendered internal config cannot be read or fails its loader's
/// invariants, when the internal credential is absent, invalid or
/// superseded by a trust rotation, when either `OpenBao` read fails, or
/// when an issuance fails — including a CA bundle that cannot be read
/// and a write that cannot land. There is no fallback to a self-signed
/// or borrowed leaf, and none to a locally configured EAB or responder
/// HMAC.
pub async fn ensure_surface_certificates(
    settings: &Settings,
    inputs: &SurfaceIssuanceInputs<'_>,
    insecure_mode: bool,
) -> anyhow::Result<()> {
    if !settings.registrar_endpoint.enabled {
        return Ok(());
    }
    let (client_paths, endpoint_paths) = material_paths(&settings.registrar_endpoint)?;
    let secrets_dir = inputs.secrets_dir;

    // The host label is the internal profile's own, read through the
    // loader that holds that file to its invariants. Not a new
    // `[registrar_endpoint]` key, which an operator could set to
    // disagree with a name `init` already fixed; not the system
    // hostname, which is not contracted to equal the deployment's host
    // label; and not parsed back out of the internal leaf's SAN, which
    // would be a second derivation of what this loader already returns.
    let internal_paths = InternalPaths::new(secrets_dir);
    let internal = load_internal_config(&internal_paths).with_context(|| {
        format!(
            "loading the rendered bootroot-internal agent config at {} for the registrar \
             surface's host label",
            internal_paths.agent_config().display()
        )
    })?;
    let host = internal
        .profiles
        .first()
        .map(|profile| profile.hostname.clone())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the rendered bootroot-internal agent config at {} carries no profile to take \
                 the registrar surface's host label from",
                internal_paths.agent_config().display()
            )
        })?;

    let pending = pending_issuances(
        [client_paths, endpoint_paths],
        &host,
        &settings.domain,
        settings.trust.ca_bundle_path.as_deref(),
        OffsetDateTime::now_utc(),
    );
    if pending.is_empty() {
        return Ok(());
    }

    let acme_inputs = read_acme_inputs(secrets_dir, inputs.openbao_url, inputs.kv_mount).await?;

    // The substitution is in-memory only, and is the whole point of
    // saying issuance runs "under" the internal credential: the HMAC
    // that reaches `register_http01_token` is the one just read from
    // OpenBao, never the one `agent.toml` or the internal profile's
    // rendered config carries.
    let mut issuance_settings = settings.clone();
    issuance_settings.acme.http_responder_hmac = acme_inputs.responder_hmac;

    for (paths, name, reason) in pending {
        warn!(
            "Registrar surface leaf {name} at {} is unusable ({reason}); issuing a replacement.",
            paths.cert.display()
        );
        issue_pair(
            &issuance_settings,
            &paths,
            &host,
            acme_inputs.eab.clone(),
            insecure_mode,
        )
        .await?;
    }
    Ok(())
}

/// Selects which of the two pairs need issuing, in the order they are
/// issued.
///
/// The two are evaluated **independently**, and returning the selection
/// rather than acting on it is what lets that be asserted with no CA in
/// the loop: one pair being usable never puts the other on this list,
/// and one pair being unusable never keeps the other off it. A usable
/// pair is absent from the result and is therefore never written to —
/// re-issuing it would churn a file the co-located registrar is reading
/// and hand that process a new key on every restart.
#[must_use]
fn pending_issuances(
    pairs: [PairPaths; 2],
    host: &str,
    domain: &str,
    ca_bundle_path: Option<&Path>,
    now: OffsetDateTime,
) -> Vec<(PairPaths, String, UnusableMaterial)> {
    pairs
        .into_iter()
        .filter_map(|paths| {
            let name = paths.leaf.identity(host, domain);
            match evaluate_pair(&paths.cert, &paths.key, &name, ca_bundle_path, now) {
                Usability::Usable => {
                    info!(
                        "Registrar surface leaf {name} at {} is usable; leaving it as it is.",
                        paths.cert.display()
                    );
                    None
                }
                Usability::Unusable(reason) => Some((paths, name, reason)),
            }
        })
        .collect()
}

/// Reads the EAB and the responder HMAC through the bootroot-internal
/// credential.
///
/// Reached only once at least one leaf needs issuing, so a daemon whose
/// material is fine never makes any of these calls.
async fn read_acme_inputs(
    secrets_dir: &Path,
    openbao_url: &str,
    kv_mount: &str,
) -> anyhow::Result<AcmeInputs> {
    let active_root = active_root_fingerprint(secrets_dir).with_context(|| {
        format!(
            "reading the deployment's active root fingerprint below {} for registrar surface \
             certificate issuance",
            secrets_dir.display()
        )
    })?;
    // A superseded credential refuses here with its own repair
    // diagnostic and is not retried around: between the middle and the
    // tail of a full trust rotation the stored fingerprint still names
    // the old root, and a leaf issued into it would be chained to a root
    // the `auth/cert` entry does not yet trust. Finishing the rotation
    // is the remedy.
    let credential = InternalCredential::load(secrets_dir, openbao_url, &active_root).context(
        "loading the bootroot-internal credential for registrar surface certificate issuance",
    )?;
    let client = credential.authenticated().await.context(
        "authenticating to OpenBao with the bootroot-internal credential for registrar surface \
         certificate issuance",
    )?;
    read_acme_inputs_with(&client, kv_mount).await
}

/// Reads the two ACME inputs through an already-authenticated
/// `OpenBao` client.
///
/// Split from the credential acquisition above so the provenance rule —
/// these values come from `OpenBao` and from nowhere else — is a
/// property of a function that can be driven directly, rather than one
/// only a full deployment could demonstrate.
async fn read_acme_inputs_with(
    client: &crate::openbao::OpenBaoClient,
    kv_mount: &str,
) -> anyhow::Result<AcmeInputs> {
    let responder_hmac = client
        .read_kv(kv_mount, RESPONDER_HMAC_KV_PATH)
        .await
        .with_context(|| format!("reading {kv_mount}/{RESPONDER_HMAC_KV_PATH}"))
        .and_then(|value| {
            parse_responder_hmac(&value)
                .with_context(|| format!("parsing {kv_mount}/{RESPONDER_HMAC_KV_PATH}"))
        })
        .map(HmacSecret::new)?;

    // An *absent* EAB record is the answer a deployment that registered
    // no EAB gives — `bootroot init` writes this path only when one was
    // registered, and the internal leaf's own issuance is driven with
    // `None` on such a host. A transport failure or an unparseable
    // payload is a read failure and refuses; neither falls back to
    // `agent.toml`'s `[eab]` or the internal profile's.
    let eab = match client
        .try_read_kv(kv_mount, AGENT_EAB_KV_PATH)
        .await
        .with_context(|| format!("reading {kv_mount}/{AGENT_EAB_KV_PATH}"))?
    {
        None => None,
        Some(value) => {
            match parse_eab_payload(&value)
                .with_context(|| format!("parsing {kv_mount}/{AGENT_EAB_KV_PATH}"))?
            {
                EabPayload::Populated { kid, hmac } => Some(EabCredentials {
                    kid,
                    hmac: HmacSecret::new(hmac),
                }),
                EabPayload::Clear => None,
            }
        }
    };

    Ok(AcmeInputs {
        eab,
        responder_hmac,
    })
}

/// Issues one pair over the daemon's existing outbound ACME path to the
/// local step-ca.
///
/// Never through the registrar endpoint: the endpoint is not a
/// prerequisite for issuing the certificate it presents.
///
/// Each file is staged and `rename(2)`d by `write_cert_and_key`, so each
/// is individually atomic. **The pair is not.** A reader landing between
/// the two renames observes the new leaf with the old key, or the old
/// leaf with the new key; closing that window is the reader's side of
/// the contract and is not this function's work.
///
/// Reusing `issue_certificate_with_shape` also means each issuance
/// merges the returned chain into `[trust] ca_bundle_path`, exactly as
/// every other issuance does — that is how the chain condition stays
/// satisfiable after a rotation. The endpoint pin file is a different
/// file and is never touched here: the pin is over trust *anchors*, not
/// over either leaf, and the provisioning tool writes it once.
async fn issue_pair(
    settings: &Settings,
    paths: &PairPaths,
    host: &str,
    eab: Option<EabCredentials>,
    insecure_mode: bool,
) -> anyhow::Result<()> {
    let profile = surface_profile(paths, host);
    let (cert_setting, key_setting) = paths.leaf.settings();
    issue_certificate_with_shape(
        settings,
        &profile,
        eab,
        insecure_mode,
        paths.leaf.csr_shape(),
    )
    .await
    .with_context(|| {
        format!(
            "issuing the registrar surface leaf {} into {cert_setting} at {} and {key_setting} \
             at {}",
            crate::config::profile_domain(settings, &profile),
            paths.cert.display(),
            paths.key.display()
        )
    })
}

/// Builds the throwaway profile one surface issuance runs under.
///
/// `service_name` is the reserved label, so
/// [`crate::config::profile_domain`] composes exactly the name
/// [`SurfaceLeaf::identity`] does and the order, the CSR and the
/// recognition rule all agree. It is deliberately not the
/// bootroot-internal profile: `internal_profile_paths` matches on that
/// identity and its fixed paths, and neither is what this profile
/// carries, so nothing here changes how the internal profile is renewed.
fn surface_profile(paths: &PairPaths, host: &str) -> DaemonProfileSettings {
    let service_name = paths.leaf.service_label().to_string();
    DaemonProfileSettings {
        registration_id: format!("{REGISTRAR_SURFACE_INSTANCE}.{service_name}.{host}"),
        service_name,
        instance_id: REGISTRAR_SURFACE_INSTANCE.to_string(),
        hostname: host.to_string(),
        paths: Paths {
            cert: paths.cert.clone(),
            key: paths.key.clone(),
        },
        daemon: crate::config::DaemonRuntimeSettings::default(),
        retry: None,
        hooks: HookSettings::default(),
        eab: None,
        // The historical host-local default: `0700` parent directories,
        // a `0600` key and a `0644` certificate, owned by the daemon.
        // The key is never group- or world-readable.
        cert_group_gid: None,
    }
}

#[cfg(test)]
pub(crate) mod fixture;
#[cfg(test)]
mod tests;
