//! The registrar endpoint's pin file and the TLS verification it backs.
//!
//! A TLS handshake to the host-local endpoint has no hostname to match a
//! server certificate against, and the operation the endpoint serves
//! hands back a CA anchor that becomes a newly onboarded host's trust
//! root — so "accept whatever was presented" would let anything that can
//! impersonate the endpoint inject a CA of its choosing. The answer is
//! not a permissive verifier but a pin file plus an exact expected name:
//!
//! - the file pins **trust anchors** by the SHA-256 of their DER, the
//!   one pinning idiom this tree already has
//!   ([`crate::tls::ca_bundle_fingerprints`],
//!   `trust.trusted_ca_sha256`). A leaf-shaped pin is not an option:
//!   every issuance generates a fresh key pair, so a leaf or SPKI digest
//!   goes stale at the next renewal while the file's writer — the
//!   provisioning tool — runs once at install;
//! - pinning the anchor alone would admit any leaf that CA ever issued,
//!   so it is paired with a mandatory check that the presented
//!   end-entity certificate's single DNS SAN is exactly the endpoint
//!   server identity name, which `service add`'s reserved-prefix guard
//!   makes unmintable.
//!
//! Nothing here discovers a path. bootroot has no fixed certificate
//! directory — every cert and key path is per-profile configuration
//! ([`crate::config::Paths`]) — so the pin file's basename is fixed here
//! ([`REGISTRAR_ENDPOINT_ANCHORS_FILE`]) and its directory follows the
//! registrar client certificate's, via
//! [`anchor_pin_path_for_client_certificate`]. The verifier is handed an
//! explicit path and reads no configuration.
//!
//! Nothing here writes the pin file either. The provisioning tool writes
//! it at install, and a full `bootroot rotate ca-key` adds the new CA
//! generation's anchors to it and later removes the old ones; the daemon
//! and its renewal loop only read it.
//!
//! [`probe_endpoint`] is the one dial this module makes: a handshake
//! with a given client pair that sends no request, and reports the chain
//! the endpoint presented and whether it accepted the pair. A rotation
//! uses it to prove the endpoint moved to a new CA generation.

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::{ASN1Time, FromDer};

use crate::registrar::{SanShapeError, single_dns_san};
use crate::tls;

/// Basename of the file a registrar client reads the endpoint's pinned
/// trust anchors from. Only the basename is fixed here; see
/// [`anchor_pin_path_for_client_certificate`] for the directory rule.
pub const REGISTRAR_ENDPOINT_ANCHORS_FILE: &str = "registrar-endpoint-anchors.sha256";

/// Length of a SHA-256 digest written as lowercase hex, the only shape a
/// significant line of the pin file may take. Mirrors the
/// `trusted_ca_sha256` rule in [`crate::kv_payload`].
const FINGERPRINT_HEX_LEN: usize = 64;

/// A line whose first non-whitespace character is this is a comment.
const COMMENT_PREFIX: char = '#';

/// Why the *content* of a pin file is not usable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PinContentError {
    /// A non-ignored line is not 64 ASCII hex characters. The whole file
    /// is rejected: there is no partial acceptance.
    #[error("line {line} is not a {FINGERPRINT_HEX_LEN}-character hex SHA-256 digest")]
    MalformedEntry {
        /// 1-based line number of the offending line.
        line: usize,
    },
    /// The file holds no anchor digest at all.
    #[error("no trust anchor digest present")]
    NoEntries,
}

/// Why a pinned endpoint TLS configuration could not be built.
///
/// Every variant is a refusal. None of them falls back to trusting
/// whatever the peer presents.
#[derive(Debug, thiserror::Error)]
pub enum EndpointPinError {
    /// The pin file does not exist.
    #[error("registrar endpoint pin file {} does not exist", .path.display())]
    Missing {
        /// The path that was handed to the helper.
        path: PathBuf,
    },
    /// The pin file exists but could not be read.
    #[error("registrar endpoint pin file {} could not be read", .path.display())]
    Unreadable {
        /// The path that was handed to the helper.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The pin file was read but its content is not usable.
    #[error("registrar endpoint pin file {}: {source}", .path.display())]
    Content {
        /// The path that was handed to the helper.
        path: PathBuf,
        /// Which content rule the file broke.
        #[source]
        source: PinContentError,
    },
    /// The expected endpoint identity name is not a usable DNS name.
    #[error("expected endpoint identity name {name} is not a valid DNS name")]
    InvalidEndpointName {
        /// The name that was handed to the helper.
        name: String,
    },
}

/// Why a presented server certificate was refused by
/// [`RegistrarEndpointVerifier`].
///
/// Each variant is a distinct refusal, and none of them is a fallback to
/// trusting the certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum EndpointVerifyRejection {
    /// The presented end-entity certificate does not carry exactly one
    /// DNS SAN.
    #[error(transparent)]
    San(#[from] SanShapeError),
    /// The presented end-entity certificate's single DNS SAN is not the
    /// expected endpoint identity name. Applied under both arms: a
    /// directly pinned certificate is refused here too, rather than
    /// accepted because its digest is in the pin set.
    #[error("presented certificate's DNS SAN is not the expected endpoint identity name")]
    SanMismatch,
    /// No presented certificate's DER SHA-256 is in the pin set.
    #[error("no presented certificate matches a pinned trust anchor")]
    AnchorMismatch,
    /// A pinned certificate did not parse as X.509, so it cannot be
    /// checked for CA capability or validity.
    #[error("the pinned certificate could not be parsed")]
    AnchorMalformed,
    /// The pinned certificate the chain would rest on is not CA-capable.
    #[error("the pinned certificate is not a CA certificate")]
    AnchorNotCa,
    /// The pinned anchor's validity window has passed.
    #[error("the pinned trust anchor has expired")]
    AnchorExpired,
    /// The pinned anchor's validity window has not started.
    #[error("the pinned trust anchor is not yet valid")]
    AnchorNotYetValid,
    /// The presented certificate is past its `notAfter`.
    ///
    /// Distinct from [`EndpointVerifyRejection::AnchorExpired`], and the
    /// distinction is the whole reason this variant exists: that one is
    /// a lapse in the *caller's own pinned anchor*, repaired by rotating
    /// the trust anchor, while this one is the endpoint's leaf having
    /// lapsed, repaired by the registrar daemon renewing it. Collapsing
    /// the two would send an operator to renew a certificate that is
    /// fine.
    #[error("the presented endpoint certificate has expired")]
    PresentedCertificateExpired,
    /// A pinned anchor matched, but the presented chain does not build
    /// to it.
    #[error("the presented chain does not build to a pinned trust anchor")]
    ChainVerificationFailed,
}

impl From<EndpointVerifyRejection> for rustls::Error {
    fn from(rejection: EndpointVerifyRejection) -> Self {
        let error = match rejection {
            EndpointVerifyRejection::San(SanShapeError::Malformed)
            | EndpointVerifyRejection::AnchorMalformed => rustls::CertificateError::BadEncoding,
            EndpointVerifyRejection::San(_) | EndpointVerifyRejection::SanMismatch => {
                rustls::CertificateError::NotValidForName
            }
            EndpointVerifyRejection::AnchorMismatch
            | EndpointVerifyRejection::ChainVerificationFailed => {
                rustls::CertificateError::UnknownIssuer
            }
            // `AnchorExpired` joins `AnchorNotCa` rather than taking
            // `Expired`, which is reserved for the refusal below. All a
            // caller recovers from the wrapping `io::Error` is the
            // `CertificateError`, so a pinned anchor that lapsed and an
            // endpoint leaf that lapsed must not spell themselves the
            // same way: they name different material, and renewing the
            // leaf does nothing for a pin file that has gone stale.
            EndpointVerifyRejection::AnchorNotCa | EndpointVerifyRejection::AnchorExpired => {
                rustls::CertificateError::ApplicationVerificationFailure
            }
            EndpointVerifyRejection::PresentedCertificateExpired => {
                rustls::CertificateError::Expired
            }
            EndpointVerifyRejection::AnchorNotYetValid => rustls::CertificateError::NotValidYet,
        };
        Self::InvalidCertificate(error)
    }
}

/// Reports whether `error` is one [`RegistrarEndpointVerifier`] could
/// itself have produced.
///
/// `tokio_rustls` hands a caller one `io::Error` for every way a
/// handshake can fail, and the `rustls::Error` recovered from it is all
/// there is to tell a *trust decision this verifier made* from a later
/// failure that merely shares the `InvalidCertificate` wrapper. The
/// wrapper alone does not separate them: `rustls` reports a bad
/// `CertificateVerify` signature — checked after
/// [`ServerCertVerifier::verify_server_cert`] has already accepted the
/// chain — as `InvalidCertificate(BadSignature)`, which no rule here
/// decided.
///
/// So the question is asked of the exact set
/// `From<EndpointVerifyRejection>` above emits, and it is asked here,
/// beside that impl, because the two have to move together.
#[must_use]
pub fn is_endpoint_verify_rejection(error: &rustls::Error) -> bool {
    let rustls::Error::InvalidCertificate(certificate) = error else {
        return false;
    };
    matches!(
        certificate,
        rustls::CertificateError::BadEncoding
            | rustls::CertificateError::NotValidForName
            | rustls::CertificateError::UnknownIssuer
            | rustls::CertificateError::ApplicationVerificationFailure
            | rustls::CertificateError::Expired
            | rustls::CertificateError::NotValidYet
    )
}

/// Derives the conventional pin-file path from a registrar client
/// certificate path: that path's parent directory joined with
/// [`REGISTRAR_ENDPOINT_ANCHORS_FILE`].
///
/// Pure — it touches no filesystem and reads no configuration. bootroot
/// fixes no certificate directory, so the pin file's absolute directory
/// follows wherever the registrar client certificate was configured to
/// live; only the basename and this beside-the-certificate rule are
/// fixed. A path with no parent yields the bare basename, relative to
/// the caller's working directory.
#[must_use]
pub fn anchor_pin_path_for_client_certificate(client_certificate_path: &Path) -> PathBuf {
    client_certificate_path
        .parent()
        .map_or_else(PathBuf::new, Path::to_path_buf)
        .join(REGISTRAR_ENDPOINT_ANCHORS_FILE)
}

/// Parses pin-file content into the set of pinned anchor digests,
/// lowercased and deduplicated.
///
/// The format is UTF-8 text, LF-separated. Leading and trailing ASCII
/// whitespace is trimmed off each line; blank lines and lines whose
/// first non-whitespace character is `#` are ignored; uppercase hex is
/// accepted and normalized; order is irrelevant and duplicates collapse.
/// Every other line must be exactly 64 ASCII hex characters — the
/// SHA-256 of one trust anchor certificate's DER, the value
/// [`crate::tls::ca_bundle_fingerprints`] produces.
///
/// # Errors
///
/// Returns [`PinContentError::MalformedEntry`] for the first non-ignored
/// line that is not 64 hex characters — the whole file is rejected,
/// never partially accepted — and [`PinContentError::NoEntries`] when no
/// digest is present.
pub fn parse_anchor_pins(contents: &str) -> Result<BTreeSet<String>, PinContentError> {
    let mut pins = BTreeSet::new();
    for (index, raw) in contents.lines().enumerate() {
        let line = raw.trim_matches(|ch: char| ch.is_ascii_whitespace());
        if line.is_empty() || line.starts_with(COMMENT_PREFIX) {
            continue;
        }
        if line.len() != FINGERPRINT_HEX_LEN || !line.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(PinContentError::MalformedEntry { line: index + 1 });
        }
        pins.insert(line.to_ascii_lowercase());
    }
    if pins.is_empty() {
        return Err(PinContentError::NoEntries);
    }
    Ok(pins)
}

/// Reads and parses the pin file at an explicitly supplied path.
///
/// Performs no path discovery and reads no configuration; see
/// [`anchor_pin_path_for_client_certificate`] for the conventional
/// location a caller may derive.
///
/// # Errors
///
/// Returns [`EndpointPinError::Missing`] when the file does not exist,
/// [`EndpointPinError::Unreadable`] when it exists but cannot be read,
/// and [`EndpointPinError::Content`] when its content breaks the format.
pub fn load_anchor_pins(path: &Path) -> Result<BTreeSet<String>, EndpointPinError> {
    let contents = std::fs::read_to_string(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            EndpointPinError::Missing {
                path: path.to_path_buf(),
            }
        } else {
            EndpointPinError::Unreadable {
                path: path.to_path_buf(),
                source,
            }
        }
    })?;
    parse_anchor_pins(&contents).map_err(|source| EndpointPinError::Content {
        path: path.to_path_buf(),
        source,
    })
}

/// Builds the server-certificate verifier a registrar client uses
/// against the host-local endpoint, from an explicitly supplied pin-file
/// path and the exact endpoint identity name it must present.
///
/// # Errors
///
/// Returns [`EndpointPinError`] when the pin file is missing,
/// unreadable, or malformed, or when `expected_endpoint_name` is not a
/// valid DNS name.
pub fn endpoint_server_verifier(
    pin_file: &Path,
    expected_endpoint_name: &str,
) -> Result<Arc<dyn ServerCertVerifier>, EndpointPinError> {
    let pins = load_anchor_pins(pin_file)?;
    Ok(Arc::new(RegistrarEndpointVerifier::new(
        pins.into_iter().collect(),
        expected_endpoint_name,
    )?))
}

/// Builds a [`ClientConfig`] whose only trust decision is the pinned
/// anchor set plus the exact endpoint SAN.
///
/// A convenience over [`endpoint_server_verifier`] for a caller that
/// presents no client certificate. A caller that authenticates with the
/// registrar client identity builds its own config from the same
/// verifier and finishes with
/// [`rustls::ConfigBuilder::with_client_auth_cert`] instead — the
/// verification semantics are identical either way.
///
/// # Errors
///
/// Returns [`EndpointPinError`] when the pin file is missing,
/// unreadable, or malformed, or when `expected_endpoint_name` is not a
/// valid DNS name.
pub fn build_endpoint_client_config(
    pin_file: &Path,
    expected_endpoint_name: &str,
) -> Result<ClientConfig, EndpointPinError> {
    let verifier = endpoint_server_verifier(pin_file, expected_endpoint_name)?;
    Ok(ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth())
}

/// Why a client pair could not be loaded for a handshake probe.
#[derive(Debug, thiserror::Error)]
pub enum ProbeClientPairError {
    /// The certificate or the key file could not be read.
    #[error("could not read {}", .path.display())]
    Unreadable {
        /// The file that could not be read.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The certificate file holds no certificate, or does not parse.
    #[error("{} holds no parseable certificate", .path.display())]
    NoCertificate {
        /// The certificate file.
        path: PathBuf,
    },
    /// The key file holds no private key, or does not parse.
    #[error("{} holds no parseable private key", .path.display())]
    NoPrivateKey {
        /// The key file.
        path: PathBuf,
    },
    /// The key file holds a key `rustls` cannot sign with.
    #[error("{} holds a private key of an unsupported type", .path.display())]
    UnsupportedKey {
        /// The key file.
        path: PathBuf,
    },
    /// The key is not the key of the leaf beside it.
    #[error("the private key at {} is not the key of the leaf at {}", .key_path.display(), .certificate_path.display())]
    KeyMismatch {
        /// The certificate file.
        certificate_path: PathBuf,
        /// The key file.
        key_path: PathBuf,
    },
}

/// A registrar client leaf, its issuer chain and its private key, loaded
/// for a [`probe_endpoint`] dial.
///
/// The key is proven to be the leaf's when the pair is loaded, so a
/// probe never presents a torn pair and blames the endpoint for it.
pub struct ProbeClientPair {
    leaf: CertificateDer<'static>,
    issuers: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl std::fmt::Debug for ProbeClientPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProbeClientPair")
            .field("leaf", &self.leaf)
            .field("issuers", &self.issuers)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl ProbeClientPair {
    /// Loads a pair from a certificate file (leaf first, then its issuer
    /// chain) and a key file.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeClientPairError`] naming the file at fault when
    /// either file cannot be read or parsed, when the key cannot sign,
    /// or when the key is not the leaf's.
    pub fn load(certificate_path: &Path, key_path: &Path) -> Result<Self, ProbeClientPairError> {
        let read = |path: &Path| {
            std::fs::read(path).map_err(|source| ProbeClientPairError::Unreadable {
                path: path.to_path_buf(),
                source,
            })
        };
        let certificate_pem = read(certificate_path)?;
        let key_pem = read(key_path)?;
        Self::from_pem(&certificate_pem, &key_pem, certificate_path, key_path)
    }

    /// Builds a pair from PEM bytes already read, naming `certificate_path`
    /// and `key_path` in any refusal.
    ///
    /// # Errors
    ///
    /// Returns [`ProbeClientPairError`] when either input does not parse,
    /// when the key cannot sign, or when the key is not the leaf's.
    pub fn from_pem(
        certificate_pem: &[u8],
        key_pem: &[u8],
        certificate_path: &Path,
        key_path: &Path,
    ) -> Result<Self, ProbeClientPairError> {
        tls::install_crypto_provider();
        let mut chain = rustls_pemfile::certs(&mut std::io::BufReader::new(certificate_pem))
            .collect::<Result<Vec<CertificateDer<'static>>, _>>()
            .map_err(|_| ProbeClientPairError::NoCertificate {
                path: certificate_path.to_path_buf(),
            })?
            .into_iter();
        let leaf = chain
            .next()
            .ok_or_else(|| ProbeClientPairError::NoCertificate {
                path: certificate_path.to_path_buf(),
            })?;
        // Quotes none of the key's bytes on failure: this is key material.
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem))
            .ok()
            .flatten()
            .ok_or_else(|| ProbeClientPairError::NoPrivateKey {
                path: key_path.to_path_buf(),
            })?;
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|_| {
            ProbeClientPairError::UnsupportedKey {
                path: key_path.to_path_buf(),
            }
        })?;
        if !tls::cert_key_matches(&leaf, signing_key.as_ref()) {
            return Err(ProbeClientPairError::KeyMismatch {
                certificate_path: certificate_path.to_path_buf(),
                key_path: key_path.to_path_buf(),
            });
        }
        Ok(Self {
            leaf,
            issuers: chain.collect(),
            key,
        })
    }

    /// Returns the leaf the pair presents.
    #[must_use]
    pub fn leaf(&self) -> &CertificateDer<'static> {
        &self.leaf
    }

    /// Returns the leaf followed by the issuer chain it was stored with,
    /// which is what a handshake presents.
    fn presented_chain(&self) -> Vec<CertificateDer<'static>> {
        std::iter::once(self.leaf.clone())
            .chain(self.issuers.iter().cloned())
            .collect()
    }
}

/// How long one [`probe_endpoint`] step — the connect, the handshake, or
/// the read that carries the endpoint's verdict — may take.
///
/// Twice the five seconds the endpoint itself allows a handshake, and no
/// probe step waits on anything but a host-local socket.
const PROBE_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// The inert name a probe dials with; the verifier applies the pinned
/// expected name instead, exactly as the endpoint client does.
const PROBE_DIAL_NAME: &str = "registrar-endpoint.invalid";

/// What the endpoint decided about the client pair a probe presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// The endpoint completed the handshake with the pair and closed the
    /// frameless connection cleanly, which is how it answers a caller it
    /// accepted that sent no request.
    Accepted,
    /// The endpoint refused the pair with a TLS alert.
    Refused,
}

/// What one handshake probe of the endpoint observed.
#[derive(Debug, Clone)]
pub struct EndpointProbe {
    /// The chain the endpoint presented on this connection, leaf first,
    /// read from the handshake and never from disk.
    pub presented_chain: Vec<CertificateDer<'static>>,
    /// What the endpoint decided about the probe's client pair.
    pub verdict: ProbeVerdict,
}

/// Why a handshake probe produced no verdict.
#[derive(Debug, thiserror::Error)]
pub enum EndpointProbeError {
    /// The pin file could not back a verifier.
    #[error(transparent)]
    Pin(#[from] EndpointPinError),
    /// `rustls` refused to present the probe's client pair.
    #[error("the probe's client pair could not be configured: {source}")]
    ClientAuth {
        /// What `rustls` refused.
        #[source]
        source: rustls::Error,
    },
    /// Nothing that passed the pinned server verification answered: the
    /// connect failed, the handshake failed, or the server's chain did
    /// not verify under the pin file.
    #[error("no registrar endpoint answered at {}: {source}", .socket_path.display())]
    Unanswered {
        /// The socket that was dialed.
        socket_path: PathBuf,
        /// The failure, carrying the `rustls` error where there was one.
        #[source]
        source: std::io::Error,
    },
    /// The endpoint answered the handshake but ended the connection in a
    /// way that is neither a clean close nor a TLS alert.
    #[error("the registrar endpoint at {} gave no verdict on the probe's client pair: {source}", .socket_path.display())]
    Inconclusive {
        /// The socket that was dialed.
        socket_path: PathBuf,
        /// What the read ended with.
        #[source]
        source: std::io::Error,
    },
}

/// Dials the endpoint with a client pair, completes the pinned handshake,
/// and reports the chain the endpoint presented and whether it accepted
/// the pair.
///
/// Changes nothing on the endpoint: after the handshake the probe sends
/// `close_notify` without writing any request frame, then reads to the
/// end of the stream. The endpoint answers a frameless connection from a
/// caller it accepted with a clean close, and a client certificate it
/// does not accept with a TLS alert.
///
/// Only TLS 1.3 is offered, and finishing the handshake is never taken as
/// acceptance: in TLS 1.3 the client finishes before the server has
/// validated the client certificate, so the verdict is read off the end
/// of the stream instead.
///
/// The probe runs as whatever uid calls it, and the endpoint refuses any
/// peer that is not its own uid before a handshake — which is reported
/// here as [`EndpointProbeError::Unanswered`].
///
/// # Errors
///
/// Returns [`EndpointProbeError::Pin`] when the pin file cannot back a
/// verifier, [`EndpointProbeError::ClientAuth`] when `rustls` refuses the
/// pair, [`EndpointProbeError::Unanswered`] when no endpoint that passes
/// the pinned verification answered, and
/// [`EndpointProbeError::Inconclusive`] when the connection ended in
/// neither a clean close nor an alert.
///
/// # Panics
///
/// Never in practice: the one `expect` is on a literal dial name that is
/// a syntactically valid DNS name.
pub async fn probe_endpoint(
    socket_path: &Path,
    pin_file: &Path,
    expected_endpoint_name: &str,
    client: &ProbeClientPair,
) -> Result<EndpointProbe, EndpointProbeError> {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    tls::install_crypto_provider();
    let verifier = endpoint_server_verifier(pin_file, expected_endpoint_name)?;
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(client.presented_chain(), client.key.clone_key())
        .map_err(|source| EndpointProbeError::ClientAuth { source })?;
    let unanswered = |source: std::io::Error| EndpointProbeError::Unanswered {
        socket_path: socket_path.to_path_buf(),
        source,
    };
    let timed_out = || std::io::Error::new(std::io::ErrorKind::TimedOut, "the probe timed out");

    let stream = tokio::time::timeout(
        PROBE_STEP_TIMEOUT,
        tokio::net::UnixStream::connect(socket_path),
    )
    .await
    .map_err(|_| unanswered(timed_out()))?
    .map_err(unanswered)?;
    let server_name = ServerName::try_from(PROBE_DIAL_NAME)
        .expect("PROBE_DIAL_NAME is a literal that is a syntactically valid DNS name");
    let mut tls = tokio::time::timeout(
        PROBE_STEP_TIMEOUT,
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(server_name, stream),
    )
    .await
    .map_err(|_| unanswered(timed_out()))?
    .map_err(unanswered)?;
    let presented_chain: Vec<CertificateDer<'static>> = tls
        .get_ref()
        .1
        .peer_certificates()
        .map(|chain| chain.iter().map(|cert| cert.clone().into_owned()).collect())
        .unwrap_or_default();

    // No request frame, only `close_notify`. A shutdown that fails has
    // met a peer that already ended the connection, and the read below
    // is what says how it ended.
    let _ = tls.shutdown().await;
    let mut ignored = Vec::new();
    let verdict =
        match tokio::time::timeout(PROBE_STEP_TIMEOUT, tls.read_to_end(&mut ignored)).await {
            Ok(Ok(_)) => ProbeVerdict::Accepted,
            Ok(Err(err)) if is_received_alert(&err) => ProbeVerdict::Refused,
            Ok(Err(source)) => {
                return Err(EndpointProbeError::Inconclusive {
                    socket_path: socket_path.to_path_buf(),
                    source,
                });
            }
            Err(_) => {
                return Err(EndpointProbeError::Inconclusive {
                    socket_path: socket_path.to_path_buf(),
                    source: timed_out(),
                });
            }
        };
    Ok(EndpointProbe {
        presented_chain,
        verdict,
    })
}

/// Reports whether a read ended because the peer sent a TLS alert.
fn is_received_alert(error: &std::io::Error) -> bool {
    matches!(
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>()),
        Some(rustls::Error::AlertReceived(_))
    )
}

/// Anchor-pinning server verifier for the registrar endpoint.
///
/// Wraps [`crate::tls`]'s existing `PinnedCertVerifier` rather than
/// growing a second verification path, and adds the unconditional
/// exact-SAN check on the presented end-entity certificate.
///
/// The trust anchors are taken from the certificates the peer presents,
/// keeping only those whose DER SHA-256 is pinned: a pin file carries
/// digests and no certificate material, so there is nothing else for an
/// anchor to come from. A pin therefore has to name a certificate the
/// endpoint actually sends — in a bootroot deployment, the CA bundle
/// fingerprints the server presents alongside its leaf.
#[derive(Debug)]
pub struct RegistrarEndpointVerifier {
    pins: HashSet<String>,
    expected_name: String,
    /// The expected name again, as the [`ServerName`] handed to the
    /// inner webpki verifier. The name the caller dialed with is
    /// deliberately ignored: over `AF_UNIX` there is no meaningful one,
    /// and the name that matters is the pinned one.
    expected_server_name: ServerName<'static>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl RegistrarEndpointVerifier {
    /// Builds a verifier over an already-parsed pin set.
    ///
    /// `pins` are normalized to lowercase hex, the form `tls::sha256_hex`
    /// produces and the only form a digest is ever compared in.
    /// [`parse_anchor_pins`] already normalizes, but a caller assembling
    /// a pin set some other way would otherwise get a verifier that
    /// refuses every handshake — a fail-closed footgun with no error to
    /// read.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointPinError::InvalidEndpointName`] when
    /// `expected_endpoint_name` is not a valid DNS name.
    pub fn new(
        pins: HashSet<String>,
        expected_endpoint_name: &str,
    ) -> Result<Self, EndpointPinError> {
        tls::install_crypto_provider();
        let pins = pins
            .into_iter()
            .map(|pin| pin.to_ascii_lowercase())
            .collect();
        let expected_name = expected_endpoint_name.to_ascii_lowercase();
        let expected_server_name = ServerName::try_from(expected_name.clone()).map_err(|_| {
            EndpointPinError::InvalidEndpointName {
                name: expected_endpoint_name.to_string(),
            }
        })?;
        Ok(Self {
            pins,
            expected_name,
            expected_server_name,
            supported_algs: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        })
    }

    /// Applies the pinned-anchor and exact-SAN rules, returning the
    /// typed refusal rather than a [`rustls::Error`].
    ///
    /// # Errors
    ///
    /// Returns the [`EndpointVerifyRejection`] naming the first rule the
    /// presented material failed.
    pub fn verify(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<(), EndpointVerifyRejection> {
        // The exact-SAN check runs first and unconditionally, so a SAN
        // mismatch is reported as one instead of being masked by the
        // chain failure it would also cause.
        let presented_name = single_dns_san(end_entity.as_ref())?;
        if presented_name != self.expected_name {
            return Err(EndpointVerifyRejection::SanMismatch);
        }

        let anchors = self.pinned_anchors(end_entity, intermediates, now)?;
        // After the anchor rules and before the chain build, so an
        // untrusted peer is still refused as one and only a leaf under a
        // usable anchor is ever reported as expired.
        validate_presented_leaf_time(end_entity, now)?;
        let verifier = tls::build_pinned_verifier(&anchors, &self.pins)
            .map_err(|_| EndpointVerifyRejection::ChainVerificationFailed)?;
        verifier
            .verify_server_cert(
                end_entity,
                intermediates,
                &self.expected_server_name,
                &[],
                now,
            )
            .map_err(|_| EndpointVerifyRejection::ChainVerificationFailed)?;
        Ok(())
    }

    /// Selects the presented certificates whose DER SHA-256 is pinned
    /// and that are usable as a trust anchor — CA-capable and
    /// time-valid.
    fn pinned_anchors(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<Vec<CertificateDer<'static>>, EndpointVerifyRejection> {
        let mut anchors = Vec::new();
        let mut matched = false;
        let mut rejection = None;
        for candidate in std::iter::once(end_entity).chain(intermediates) {
            if !self.pins.contains(&tls::sha256_hex(candidate.as_ref())) {
                continue;
            }
            matched = true;
            match anchor_usability(candidate, now) {
                Ok(()) => anchors.push(CertificateDer::from(candidate.as_ref().to_vec())),
                Err(err) => {
                    rejection.get_or_insert(err);
                }
            }
        }
        if !matched {
            return Err(EndpointVerifyRejection::AnchorMismatch);
        }
        if anchors.is_empty() {
            return Err(rejection.unwrap_or(EndpointVerifyRejection::AnchorMismatch));
        }
        Ok(anchors)
    }
}

impl ServerCertVerifier for RegistrarEndpointVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verify(end_entity, intermediates, now)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

/// Reports whether a pinned certificate may serve as a trust anchor:
/// CA-capable and inside its validity window. Mirrors what
/// `PinnedCertVerifier`'s direct-pin arm demands, so the two arms agree
/// about what a pinned certificate has to be.
fn anchor_usability(
    certificate: &CertificateDer<'_>,
    now: UnixTime,
) -> Result<(), EndpointVerifyRejection> {
    let (_, cert) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|_| EndpointVerifyRejection::AnchorMalformed)?;
    let is_ca = cert
        .basic_constraints()
        .map_err(|_| EndpointVerifyRejection::AnchorMalformed)?
        .is_some_and(|constraints| constraints.value.ca);
    if !is_ca {
        return Err(EndpointVerifyRejection::AnchorNotCa);
    }
    validate_anchor_time(&cert, now)
}

fn validate_anchor_time(
    cert: &X509Certificate<'_>,
    now: UnixTime,
) -> Result<(), EndpointVerifyRejection> {
    let now = asn1_now(now)?;
    let validity = cert.validity();
    if now < validity.not_before {
        Err(EndpointVerifyRejection::AnchorNotYetValid)
    } else if now > validity.not_after {
        Err(EndpointVerifyRejection::AnchorExpired)
    } else {
        Ok(())
    }
}

/// Refuses a presented end-entity certificate whose `notAfter` has
/// passed.
///
/// Checked here rather than left to the chain build, because the
/// verifier behind this one reports every chain failure identically: an
/// expired endpoint leaf arriving as [`ChainVerificationFailed`] cannot
/// be told from a peer that never chained to the pin, and the two share
/// no repair — one is the registrar daemon's renewal having stopped,
/// the other is the wrong peer at the socket. Lifting it out here is
/// what lets the endpoint client report the lapse as one.
///
/// Only the expiry is lifted out. A leaf that is *not yet valid* still
/// fails the chain build, because a clock short of `notBefore` is not a
/// certificate that lapsed and renewal is not its repair.
///
/// [`ChainVerificationFailed`]: EndpointVerifyRejection::ChainVerificationFailed
fn validate_presented_leaf_time(
    certificate: &CertificateDer<'_>,
    now: UnixTime,
) -> Result<(), EndpointVerifyRejection> {
    // The SAN rule parsed this certificate before the caller reached
    // here, so a parse failure is not a shape this can be entered with;
    // it keeps the chain failure rather than claiming a lifetime it
    // could not read.
    let (_, cert) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|_| EndpointVerifyRejection::ChainVerificationFailed)?;
    if asn1_now(now)? > cert.validity().not_after {
        return Err(EndpointVerifyRejection::PresentedCertificateExpired);
    }
    Ok(())
}

/// `now` as the `ASN1Time` a certificate's validity window is compared
/// against.
fn asn1_now(now: UnixTime) -> Result<ASN1Time, EndpointVerifyRejection> {
    let seconds = i64::try_from(now.as_secs())
        .map_err(|_| EndpointVerifyRejection::ChainVerificationFailed)?;
    ASN1Time::from_timestamp(seconds).map_err(|_| EndpointVerifyRejection::ChainVerificationFailed)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, DnType, KeyPair, KeyUsagePurpose,
        SanType, date_time_ymd,
    };
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use tempfile::tempdir;

    use super::*;
    use crate::registrar::registrar_endpoint_identity;

    const TEST_NOW_SECS: u64 = 1_700_000_000;
    const TEST_DOMAIN: &str = "example.internal";

    fn test_now() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(TEST_NOW_SECS))
    }

    fn endpoint_name() -> String {
        registrar_endpoint_identity("001", "h1", TEST_DOMAIN)
    }

    type TestCa = CertifiedIssuer<'static, KeyPair>;

    /// Generates a self-signed CA whose validity window is
    /// `(not_before, not_after)`.
    fn generate_ca(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> TestCa {
        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, "Bootroot Test CA");
        params.is_ca = rcgen::IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        CertifiedIssuer::self_signed(params, key).expect("self-signed CA")
    }

    fn valid_ca() -> TestCa {
        generate_ca((2020, 1, 1), (2099, 1, 1))
    }

    fn ca_der(ca: &TestCa) -> CertificateDer<'static> {
        CertificateDer::from(ca.der().to_vec())
    }

    /// Issues a leaf carrying `name` as its single DNS SAN, signed by
    /// `ca`.
    fn issue_leaf(ca: &TestCa, name: &str) -> CertificateDer<'static> {
        issue_leaf_with_sans(
            ca,
            vec![SanType::DnsName(
                name.to_string().try_into().expect("valid DNS SAN"),
            )],
        )
    }

    fn issue_leaf_with_sans(ca: &TestCa, sans: Vec<SanType>) -> CertificateDer<'static> {
        issue_leaf_with_sans_and_key(ca, sans).0
    }

    /// The same issuance inside an explicit validity window, for the one
    /// property that needs a closed one: a leaf whose `notAfter` is
    /// already behind [`test_now`].
    fn issue_leaf_within(
        ca: &TestCa,
        name: &str,
        not_before: (i32, u8, u8),
        not_after: (i32, u8, u8),
    ) -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params.is_ca = rcgen::IsCa::NoCa;
        params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
        params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        params.subject_alt_names = vec![SanType::DnsName(
            name.to_string().try_into().expect("valid DNS SAN"),
        )];
        let leaf = params.signed_by(&key, ca).expect("issued leaf");
        CertificateDer::from(leaf.der().to_vec())
    }

    /// The same issuance, keeping the leaf's private key: a server that
    /// has to complete a handshake needs it, and the validity window is
    /// wide open because that handshake is verified against the real
    /// clock rather than [`test_now`].
    fn issue_leaf_with_sans_and_key(
        ca: &TestCa,
        sans: Vec<SanType>,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params.is_ca = rcgen::IsCa::NoCa;
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2099, 1, 1);
        params.subject_alt_names = sans;
        let leaf = params.signed_by(&key, ca).expect("issued leaf");
        (
            CertificateDer::from(leaf.der().to_vec()),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
    }

    fn issue_leaf_and_key(
        ca: &TestCa,
        name: &str,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        issue_leaf_with_sans_and_key(
            ca,
            vec![SanType::DnsName(
                name.to_string().try_into().expect("valid DNS SAN"),
            )],
        )
    }

    /// Runs a TLS handshake between a server presenting `chain` and a
    /// client configured by `client_config`, entirely in memory — no
    /// socket, no port, no timing.
    fn handshake(
        client_config: ClientConfig,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    ) -> Result<(), rustls::Error> {
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .expect("server config");
        let mut server =
            rustls::ServerConnection::new(Arc::new(server_config)).expect("server connection");
        let mut client = rustls::ClientConnection::new(
            Arc::new(client_config),
            // Deliberately not the endpoint identity name: over
            // `AF_UNIX` there is no meaningful name to dial with, and
            // the verifier decides on the pinned one instead.
            ServerName::try_from("localhost").expect("valid server name"),
        )
        .expect("client connection");

        // Bounded rather than `loop`, so a handshake that stops making
        // progress fails the test instead of hanging it.
        for _ in 0..16 {
            let mut to_server = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut to_server).expect("client write");
            }
            let mut pending = to_server.as_slice();
            while !pending.is_empty() {
                server.read_tls(&mut pending).expect("server read");
            }
            server.process_new_packets()?;

            let mut to_client = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut to_client).expect("server write");
            }
            let mut pending = to_client.as_slice();
            while !pending.is_empty() {
                client.read_tls(&mut pending).expect("client read");
            }
            client.process_new_packets()?;

            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        panic!("handshake made no progress");
    }

    /// Writes a pin file holding `pins` and returns the client
    /// configuration the helper builds from it, together with the
    /// temporary directory whose drop removes the file.
    fn client_config_over(pins: &[String], expected: &str) -> (tempfile::TempDir, ClientConfig) {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join(REGISTRAR_ENDPOINT_ANCHORS_FILE);
        let mut contents = String::new();
        for pin in pins {
            contents.push_str(pin);
            contents.push('\n');
        }
        std::fs::write(&path, contents).expect("write pin file");
        let config = build_endpoint_client_config(&path, expected).expect("client config");
        (dir, config)
    }

    /// Self-signs a CA-capable certificate that carries `name` as its
    /// single DNS SAN — the shape the direct-pin arm is exercised with.
    fn self_signed_ca_with_san(name: &str, validity: ((i32, u8, u8), (i32, u8, u8))) -> Vec<u8> {
        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params.is_ca = rcgen::IsCa::Ca(BasicConstraints::Unconstrained);
        params.not_before = date_time_ymd(validity.0.0, validity.0.1, validity.0.2);
        params.not_after = date_time_ymd(validity.1.0, validity.1.1, validity.1.2);
        params.subject_alt_names = vec![SanType::DnsName(
            name.to_string().try_into().expect("valid DNS SAN"),
        )];
        params
            .self_signed(&key)
            .expect("self-signed CA")
            .der()
            .to_vec()
    }

    fn verifier_over(pins: &[String], expected: &str) -> RegistrarEndpointVerifier {
        RegistrarEndpointVerifier::new(pins.iter().cloned().collect(), expected)
            .expect("valid endpoint name")
    }

    #[test]
    fn pin_path_is_derived_beside_the_client_certificate() {
        assert_eq!(
            anchor_pin_path_for_client_certificate(Path::new("/etc/bootroot/registrar/client.crt")),
            PathBuf::from("/etc/bootroot/registrar/registrar-endpoint-anchors.sha256")
        );
        assert_eq!(
            anchor_pin_path_for_client_certificate(Path::new("/var/lib/roxyd/tls/registrar.pem")),
            PathBuf::from("/var/lib/roxyd/tls/registrar-endpoint-anchors.sha256")
        );
    }

    #[test]
    fn pin_path_of_a_bare_filename_is_the_bare_basename() {
        assert_eq!(
            anchor_pin_path_for_client_certificate(Path::new("client.crt")),
            PathBuf::from(REGISTRAR_ENDPOINT_ANCHORS_FILE)
        );
    }

    #[test]
    fn parser_accepts_a_single_anchor() {
        let pins = parse_anchor_pins(&format!("{}\n", "ab".repeat(32))).expect("valid file");
        assert_eq!(pins.len(), 1);
        assert!(pins.contains(&"ab".repeat(32)));
    }

    /// CA rotation keeps the old and the new anchor pinnable at once, so
    /// several entries are required to work — and the documented
    /// niceties (comments, blank lines, surrounding whitespace,
    /// uppercase hex, duplicates) all have to survive in one file.
    #[test]
    fn parser_accepts_the_documented_format() {
        let first = "3b".repeat(32);
        let second = "9d".repeat(32);
        let contents = format!(
            "# bootrootd registrar endpoint — pinned trust anchors\n\
             \n\
             {first}\n\
             \t  {}  \n\
             \n\
             \t# second entry present only during a CA rotation\n\
             {second}\n\
             {first}\n",
            first.to_ascii_uppercase()
        );
        let pins = parse_anchor_pins(&contents).expect("valid file");
        assert_eq!(pins.len(), 2, "duplicates and case must collapse");
        assert!(pins.contains(&first));
        assert!(pins.contains(&second));
    }

    #[test]
    fn parser_rejects_a_malformed_line_and_names_it() {
        let good = "ab".repeat(32);
        for (contents, line) in [
            (format!("{good}\n{}\n", "ab".repeat(31) + "a"), 2),
            (format!("{good}\nnot-a-digest\n"), 2),
            (format!("{}\n{good}\n", "zz".repeat(32)), 1),
        ] {
            assert_eq!(
                parse_anchor_pins(&contents),
                Err(PinContentError::MalformedEntry { line }),
                "{contents}"
            );
        }
    }

    #[test]
    fn parser_rejects_a_file_with_no_entry() {
        for contents in ["", "\n\n", "# only a comment\n", "   \n\t\n"] {
            assert_eq!(
                parse_anchor_pins(contents),
                Err(PinContentError::NoEntries),
                "{contents:?}"
            );
        }
    }

    #[test]
    fn loading_a_missing_pin_file_is_its_own_refusal() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join(REGISTRAR_ENDPOINT_ANCHORS_FILE);
        let err = load_anchor_pins(&path).expect_err("missing file");
        assert!(matches!(err, EndpointPinError::Missing { .. }), "{err:?}");
    }

    /// A directory stands in for an unreadable file: reading it fails
    /// with something other than `NotFound`, which is the distinction
    /// the two refusals rest on. A permission-denied file would need the
    /// test to run as a non-owner.
    #[test]
    fn loading_an_unreadable_pin_file_is_its_own_refusal() {
        let dir = tempdir().expect("temp dir");
        let err = load_anchor_pins(dir.path()).expect_err("unreadable file");
        assert!(
            matches!(err, EndpointPinError::Unreadable { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn loading_a_malformed_pin_file_is_its_own_refusal() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join(REGISTRAR_ENDPOINT_ANCHORS_FILE);
        std::fs::write(&path, "# nothing but a comment\n").expect("write pin file");
        let err = load_anchor_pins(&path).expect_err("no entries");
        assert!(
            matches!(
                err,
                EndpointPinError::Content {
                    source: PinContentError::NoEntries,
                    ..
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn building_a_config_rejects_an_endpoint_name_that_is_not_a_dns_name() {
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join(REGISTRAR_ENDPOINT_ANCHORS_FILE);
        std::fs::write(&path, format!("{}\n", "ab".repeat(32))).expect("write pin file");
        let err = build_endpoint_client_config(&path, "not a dns name")
            .expect_err("invalid endpoint name");
        assert!(
            matches!(err, EndpointPinError::InvalidEndpointName { .. }),
            "{err:?}"
        );
    }

    /// The end-to-end shape a real deployment takes: the endpoint's leaf
    /// is CA-issued, the server presents the issuing anchor alongside
    /// it, and the pin file names that anchor.
    #[test]
    fn accepts_a_chained_leaf_whose_anchor_is_pinned_and_whose_san_matches() {
        let ca = valid_ca();
        let anchor = ca_der(&ca);
        let leaf = issue_leaf(&ca, &endpoint_name());
        let pin = tls::sha256_hex(anchor.as_ref());
        let verifier = verifier_over(&[pin], &endpoint_name());
        assert_eq!(
            verifier.verify(&leaf, std::slice::from_ref(&anchor), test_now()),
            Ok(())
        );
    }

    /// A pin set assembled outside [`parse_anchor_pins`] — uppercase
    /// hex, say — still matches, rather than silently refusing every
    /// handshake.
    #[test]
    fn an_uppercase_pin_still_matches_the_anchor() {
        let ca = valid_ca();
        let anchor = ca_der(&ca);
        let leaf = issue_leaf(&ca, &endpoint_name());
        let pin = tls::sha256_hex(anchor.as_ref()).to_ascii_uppercase();
        let verifier = verifier_over(&[pin], &endpoint_name());
        assert_eq!(
            verifier.verify(&leaf, std::slice::from_ref(&anchor), test_now()),
            Ok(())
        );
    }

    #[test]
    fn refuses_a_chain_whose_anchor_is_not_pinned() {
        let ca = valid_ca();
        let anchor = ca_der(&ca);
        let leaf = issue_leaf(&ca, &endpoint_name());
        let other = valid_ca();
        let verifier = verifier_over(
            &[tls::sha256_hex(ca_der(&other).as_ref())],
            &endpoint_name(),
        );
        assert_eq!(
            verifier.verify(&leaf, std::slice::from_ref(&anchor), test_now()),
            Err(EndpointVerifyRejection::AnchorMismatch)
        );
    }

    /// The refusal that stands between a pinned anchor and an
    /// impersonator: the leaf carries the expected name and the pin file
    /// names a certificate the peer really did present, but that
    /// certificate did not issue the leaf. A pinned anchor arriving on
    /// the wire must not be enough on its own — the chain has to build
    /// to it.
    #[test]
    fn refuses_a_leaf_that_does_not_chain_to_the_pinned_anchor_it_ships_with() {
        let pinned = valid_ca();
        let anchor = ca_der(&pinned);
        let rogue = valid_ca();
        let leaf = issue_leaf(&rogue, &endpoint_name());
        let verifier = verifier_over(&[tls::sha256_hex(anchor.as_ref())], &endpoint_name());
        assert_eq!(
            verifier.verify(&leaf, std::slice::from_ref(&anchor), test_now()),
            Err(EndpointVerifyRejection::ChainVerificationFailed)
        );
    }

    #[test]
    fn refuses_a_leaf_whose_san_is_not_the_endpoint_identity() {
        let ca = valid_ca();
        let anchor = ca_der(&ca);
        let leaf = issue_leaf(&ca, "001.roxyd.h1.example.internal");
        let verifier = verifier_over(&[tls::sha256_hex(anchor.as_ref())], &endpoint_name());
        assert_eq!(
            verifier.verify(&leaf, std::slice::from_ref(&anchor), test_now()),
            Err(EndpointVerifyRejection::SanMismatch)
        );
    }

    #[test]
    fn refuses_a_leaf_carrying_more_than_one_san() {
        let ca = valid_ca();
        let anchor = ca_der(&ca);
        let leaf = issue_leaf_with_sans(
            &ca,
            vec![
                SanType::DnsName(endpoint_name().try_into().expect("valid DNS SAN")),
                SanType::DnsName(
                    "other.example.internal"
                        .to_string()
                        .try_into()
                        .expect("san"),
                ),
            ],
        );
        let verifier = verifier_over(&[tls::sha256_hex(anchor.as_ref())], &endpoint_name());
        assert_eq!(
            verifier.verify(&leaf, std::slice::from_ref(&anchor), test_now()),
            Err(EndpointVerifyRejection::San(SanShapeError::Multiple))
        );
    }

    #[test]
    fn refuses_an_expired_pinned_anchor() {
        let ca = generate_ca((1999, 1, 1), (2000, 1, 1));
        let anchor = ca_der(&ca);
        let leaf = issue_leaf(&ca, &endpoint_name());
        let verifier = verifier_over(&[tls::sha256_hex(anchor.as_ref())], &endpoint_name());
        assert_eq!(
            verifier.verify(&leaf, std::slice::from_ref(&anchor), test_now()),
            Err(EndpointVerifyRejection::AnchorExpired)
        );
    }

    /// An expired *presented leaf* is its own refusal, and not the
    /// chain failure every other webpki verdict collapses into.
    ///
    /// This is the verdict the endpoint client turns into its typed
    /// `endpoint_server` lapse, so it has to survive both this mapping
    /// and the trip through `rustls::Error`: the anchor is live here,
    /// which is what makes the leaf the only thing that can have
    /// expired.
    #[test]
    fn refuses_an_expired_presented_leaf_as_an_expiry() {
        let ca = valid_ca();
        let anchor = ca_der(&ca);
        let leaf = issue_leaf_within(&ca, &endpoint_name(), (2020, 1, 1), (2021, 1, 1));
        let verifier = verifier_over(&[tls::sha256_hex(anchor.as_ref())], &endpoint_name());
        assert_eq!(
            verifier.verify(&leaf, std::slice::from_ref(&anchor), test_now()),
            Err(EndpointVerifyRejection::PresentedCertificateExpired)
        );
        assert_eq!(
            rustls::Error::from(EndpointVerifyRejection::PresentedCertificateExpired),
            rustls::Error::InvalidCertificate(rustls::CertificateError::Expired)
        );
    }

    /// The two lapses are told apart by everything a caller can recover
    /// from the wrapping `io::Error`, which is the `CertificateError`
    /// alone. An anchor that expired is the caller's own pin file going
    /// stale; the endpoint's leaf is fine, and renewing it repairs
    /// nothing.
    #[test]
    fn an_expired_anchor_and_an_expired_leaf_do_not_share_a_spelling() {
        assert_ne!(
            rustls::Error::from(EndpointVerifyRejection::AnchorExpired),
            rustls::Error::from(EndpointVerifyRejection::PresentedCertificateExpired)
        );
        assert!(is_endpoint_verify_rejection(&rustls::Error::from(
            EndpointVerifyRejection::AnchorExpired
        )));
    }

    #[test]
    fn refuses_a_not_yet_valid_pinned_anchor() {
        let ca = generate_ca((2100, 1, 1), (2101, 1, 1));
        let anchor = ca_der(&ca);
        let leaf = issue_leaf(&ca, &endpoint_name());
        let verifier = verifier_over(&[tls::sha256_hex(anchor.as_ref())], &endpoint_name());
        assert_eq!(
            verifier.verify(&leaf, std::slice::from_ref(&anchor), test_now()),
            Err(EndpointVerifyRejection::AnchorNotYetValid)
        );
    }

    /// The direct-pin arm is inherited from `PinnedCertVerifier`, not a
    /// deployment shape: a correctly provisioned endpoint always takes
    /// the chained arm. It is pinned down here so the reuse has a
    /// defined behaviour — a pinned non-CA certificate is refused.
    #[test]
    fn refuses_a_directly_pinned_certificate_that_is_not_a_ca() {
        let ca = valid_ca();
        let leaf = issue_leaf(&ca, &endpoint_name());
        let verifier = verifier_over(&[tls::sha256_hex(leaf.as_ref())], &endpoint_name());
        assert_eq!(
            verifier.verify(&leaf, &[], test_now()),
            Err(EndpointVerifyRejection::AnchorNotCa)
        );
    }

    #[test]
    fn accepts_a_directly_pinned_ca_certificate_carrying_the_endpoint_identity() {
        let der = self_signed_ca_with_san(&endpoint_name(), ((2020, 1, 1), (2099, 1, 1)));
        let certificate = CertificateDer::from(der);
        let verifier = verifier_over(&[tls::sha256_hex(certificate.as_ref())], &endpoint_name());
        assert_eq!(verifier.verify(&certificate, &[], test_now()), Ok(()));
    }

    /// The exact-SAN check is unconditional. A pinned, CA-capable,
    /// time-valid certificate carrying any other name is refused with
    /// the SAN-mismatch refusal rather than accepted because its digest
    /// is in the pin set.
    #[test]
    fn refuses_a_directly_pinned_ca_certificate_carrying_another_name() {
        let der = self_signed_ca_with_san(
            "001.bootroot-registrar-endpoint.h2.example.internal",
            ((2020, 1, 1), (2099, 1, 1)),
        );
        let certificate = CertificateDer::from(der);
        let verifier = verifier_over(&[tls::sha256_hex(certificate.as_ref())], &endpoint_name());
        assert_eq!(
            verifier.verify(&certificate, &[], test_now()),
            Err(EndpointVerifyRejection::SanMismatch)
        );
    }

    #[test]
    fn refuses_an_expired_directly_pinned_ca_certificate() {
        let der = self_signed_ca_with_san(&endpoint_name(), ((1999, 1, 1), (2000, 1, 1)));
        let certificate = CertificateDer::from(der);
        let verifier = verifier_over(&[tls::sha256_hex(certificate.as_ref())], &endpoint_name());
        assert_eq!(
            verifier.verify(&certificate, &[], test_now()),
            Err(EndpointVerifyRejection::AnchorExpired)
        );
    }

    /// Every refusal reaches rustls as a certificate error. None of them
    /// is an acceptance, which is the property that matters more than
    /// which variant each maps to.
    #[test]
    fn every_rejection_reaches_rustls_as_a_certificate_error() {
        for rejection in [
            EndpointVerifyRejection::San(SanShapeError::Malformed),
            EndpointVerifyRejection::San(SanShapeError::Missing),
            EndpointVerifyRejection::SanMismatch,
            EndpointVerifyRejection::AnchorMalformed,
            EndpointVerifyRejection::AnchorMismatch,
            EndpointVerifyRejection::AnchorNotCa,
            EndpointVerifyRejection::AnchorExpired,
            EndpointVerifyRejection::AnchorNotYetValid,
            EndpointVerifyRejection::PresentedCertificateExpired,
            EndpointVerifyRejection::ChainVerificationFailed,
        ] {
            assert!(
                matches!(
                    rustls::Error::from(rejection),
                    rustls::Error::InvalidCertificate(_)
                ),
                "{rejection:?}"
            );
        }
    }

    /// The verifier ignores whatever `ServerName` the caller dialed
    /// with: over `AF_UNIX` there is no meaningful one, and the name
    /// that decides the handshake is the pinned expected name.
    #[test]
    fn the_dialed_server_name_does_not_affect_the_decision() {
        let ca = valid_ca();
        let anchor = ca_der(&ca);
        let leaf = issue_leaf(&ca, &endpoint_name());
        let verifier = verifier_over(&[tls::sha256_hex(anchor.as_ref())], &endpoint_name());
        let result = ServerCertVerifier::verify_server_cert(
            &verifier,
            &leaf,
            std::slice::from_ref(&anchor),
            &ServerName::try_from("localhost").expect("valid server name"),
            &[],
            test_now(),
        );
        assert!(result.is_ok(), "{result:?}");
    }

    /// The helper's deliverable is a `ClientConfig`, and every
    /// assertion above stops at `verify`. A `ServerCertVerifier` also
    /// carries `supported_verify_schemes` and the TLS 1.2/1.3 signature
    /// verification, which no direct call to `verify` touches: get
    /// those wrong and every real handshake fails while the whole suite
    /// above still passes. So one handshake is run end to end, from the
    /// pin file on disk through to a completed session.
    #[test]
    fn a_pinned_client_completes_a_handshake_with_the_endpoint_it_pins() {
        let ca = valid_ca();
        let anchor = ca_der(&ca);
        let (leaf, key) = issue_leaf_and_key(&ca, &endpoint_name());
        let (_dir, config) =
            client_config_over(&[tls::sha256_hex(anchor.as_ref())], &endpoint_name());
        let result = handshake(config, vec![leaf, anchor], key);
        assert!(result.is_ok(), "{result:?}");
    }

    /// And the refusal really refuses: it aborts the handshake rather
    /// than only being returned from a helper the handshake ignores.
    #[test]
    fn a_pinned_client_aborts_the_handshake_when_the_anchor_is_not_pinned() {
        let ca = valid_ca();
        let anchor = ca_der(&ca);
        let (leaf, key) = issue_leaf_and_key(&ca, &endpoint_name());
        let unrelated = valid_ca();
        let (_dir, config) = client_config_over(
            &[tls::sha256_hex(ca_der(&unrelated).as_ref())],
            &endpoint_name(),
        );
        let err = handshake(config, vec![leaf, anchor], key).expect_err("unpinned anchor");
        assert!(
            matches!(err, rustls::Error::InvalidCertificate(_)),
            "{err:?}"
        );
    }

    #[test]
    fn a_pinned_configuration_can_be_built_from_a_file_on_disk() {
        let ca = valid_ca();
        let anchor = ca_der(&ca);
        let dir = tempdir().expect("temp dir");
        let path = dir.path().join(REGISTRAR_ENDPOINT_ANCHORS_FILE);
        std::fs::write(&path, format!("{}\n", tls::sha256_hex(anchor.as_ref())))
            .expect("write pin file");
        assert!(build_endpoint_client_config(&path, &endpoint_name()).is_ok());
    }

    #[test]
    fn every_verifier_rejection_is_recognized_as_one() {
        let rejections = [
            EndpointVerifyRejection::San(SanShapeError::Malformed),
            EndpointVerifyRejection::San(SanShapeError::Missing),
            EndpointVerifyRejection::San(SanShapeError::Multiple),
            EndpointVerifyRejection::San(SanShapeError::NotDns),
            EndpointVerifyRejection::SanMismatch,
            EndpointVerifyRejection::AnchorMismatch,
            EndpointVerifyRejection::AnchorMalformed,
            EndpointVerifyRejection::AnchorNotCa,
            EndpointVerifyRejection::AnchorExpired,
            EndpointVerifyRejection::AnchorNotYetValid,
            EndpointVerifyRejection::PresentedCertificateExpired,
            EndpointVerifyRejection::ChainVerificationFailed,
        ];
        for rejection in rejections {
            // Exhaustive on purpose. A variant added to either enum
            // fails to compile here, which is the reminder that the
            // list above and `is_endpoint_verify_rejection` both have
            // to grow with it — a rejection missing from the predicate
            // would reach a caller as a generic handshake failure.
            match rejection {
                EndpointVerifyRejection::San(shape) => match shape {
                    SanShapeError::Malformed
                    | SanShapeError::Missing
                    | SanShapeError::Multiple
                    | SanShapeError::NotDns => {}
                },
                EndpointVerifyRejection::SanMismatch
                | EndpointVerifyRejection::AnchorMismatch
                | EndpointVerifyRejection::AnchorMalformed
                | EndpointVerifyRejection::AnchorNotCa
                | EndpointVerifyRejection::AnchorExpired
                | EndpointVerifyRejection::AnchorNotYetValid
                | EndpointVerifyRejection::PresentedCertificateExpired
                | EndpointVerifyRejection::ChainVerificationFailed => {}
            }
            assert!(
                is_endpoint_verify_rejection(&rustls::Error::from(rejection)),
                "{rejection:?}"
            );
        }
    }

    #[test]
    fn a_handshake_signature_failure_is_not_a_verifier_rejection() {
        // `rustls` checks the peer's `CertificateVerify` signature
        // after `verify_server_cert` has already accepted the chain,
        // and reports a bad one under the same `InvalidCertificate`
        // wrapper every rejection above uses. No rule in this module
        // produced it.
        assert!(!is_endpoint_verify_rejection(&rustls::Error::from(
            rustls::CertificateError::BadSignature
        )));
        assert!(!is_endpoint_verify_rejection(
            &rustls::Error::NoCertificatesPresented
        ));
        assert!(!is_endpoint_verify_rejection(&rustls::Error::from(
            rustls::CertificateError::Revoked
        )));
    }

    // -----------------------------------------------------------------
    // The handshake probe
    // -----------------------------------------------------------------

    /// Issues a client leaf under `ca`, with the `clientAuth` usage the
    /// endpoint's verifier requires, and returns it as PEM files beside
    /// its key.
    fn write_client_pair(ca: &TestCa, dir: &Path) -> (PathBuf, PathBuf) {
        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params.is_ca = rcgen::IsCa::NoCa;
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(2099, 1, 1);
        params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
        params.subject_alt_names = vec![SanType::DnsName(
            "001.bootroot-registrar.h1.example.internal"
                .to_string()
                .try_into()
                .expect("valid DNS SAN"),
        )];
        let leaf = params.signed_by(&key, ca).expect("issued leaf");
        let cert_path = dir.join("client.crt");
        let key_path = dir.join("client.key");
        std::fs::write(&cert_path, format!("{}{}", leaf.pem(), ca.pem())).expect("write cert");
        std::fs::write(&key_path, key.serialize_pem()).expect("write key");
        (cert_path, key_path)
    }

    /// A stand-in for the endpoint's transport, answering exactly the way
    /// it does for a frameless connection: mTLS against `client_ca`, then
    /// a clean close once the caller closes, or an alert for a client
    /// certificate it does not accept.
    struct ProbeServer {
        _dir: tempfile::TempDir,
        socket_path: PathBuf,
        server_leaf: CertificateDer<'static>,
        task: tokio::task::JoinHandle<()>,
    }

    impl ProbeServer {
        fn start(server_ca: &TestCa, client_ca: &TestCa) -> Self {
            use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

            tls::install_crypto_provider();
            let (leaf, key) = issue_leaf_and_key(server_ca, &endpoint_name());
            let mut roots = rustls::RootCertStore::empty();
            roots.add(ca_der(client_ca)).expect("client anchor");
            let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .expect("client verifier");
            let config = rustls::ServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(vec![leaf.clone(), ca_der(server_ca)], key)
                .expect("server config");
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let dir = tempdir().expect("temp dir");
            let socket_path = dir.path().join("registrar.sock");
            let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind");
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(mut tls) = acceptor.accept(stream).await else {
                            return;
                        };
                        let mut request = Vec::new();
                        let _ = tls.read_to_end(&mut request).await;
                        let _ = tls.shutdown().await;
                    });
                }
            });
            Self {
                _dir: dir,
                socket_path,
                server_leaf: leaf,
                task,
            }
        }
    }

    impl Drop for ProbeServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn pin_file_for(dir: &Path, anchor: &TestCa) -> PathBuf {
        let path = dir.join(REGISTRAR_ENDPOINT_ANCHORS_FILE);
        std::fs::write(
            &path,
            format!("# anchors\n{}\n", tls::sha256_hex(ca_der(anchor).as_ref())),
        )
        .expect("write pin file");
        path
    }

    /// A pair the endpoint trusts is reported accepted, together with
    /// the chain read off the handshake.
    #[tokio::test]
    async fn a_probe_with_a_trusted_pair_is_accepted_and_reports_the_presented_chain() {
        let server_ca = valid_ca();
        let client_ca = valid_ca();
        let server = ProbeServer::start(&server_ca, &client_ca);
        let dir = tempdir().expect("temp dir");
        let pins = pin_file_for(dir.path(), &server_ca);
        let (cert, key) = write_client_pair(&client_ca, dir.path());
        let pair = ProbeClientPair::load(&cert, &key).expect("pair");

        let probe = probe_endpoint(&server.socket_path, &pins, &endpoint_name(), &pair)
            .await
            .expect("the endpoint answers");
        assert_eq!(probe.verdict, ProbeVerdict::Accepted);
        assert_eq!(probe.presented_chain.first(), Some(&server.server_leaf));
    }

    /// A pair under a CA the endpoint does not trust is reported refused
    /// — and the handshake finishing on the client side is not mistaken
    /// for acceptance.
    #[tokio::test]
    async fn a_probe_with_an_untrusted_pair_is_refused() {
        let server_ca = valid_ca();
        let client_ca = valid_ca();
        let foreign = valid_ca();
        let server = ProbeServer::start(&server_ca, &client_ca);
        let dir = tempdir().expect("temp dir");
        let pins = pin_file_for(dir.path(), &server_ca);
        let (cert, key) = write_client_pair(&foreign, dir.path());
        let pair = ProbeClientPair::load(&cert, &key).expect("pair");

        let probe = probe_endpoint(&server.socket_path, &pins, &endpoint_name(), &pair)
            .await
            .expect("the endpoint answers");
        assert_eq!(probe.verdict, ProbeVerdict::Refused);
        assert_eq!(probe.presented_chain.first(), Some(&server.server_leaf));
    }

    /// An endpoint whose chain does not verify under the pin file, and a
    /// socket nothing listens on, are both "no endpoint answered".
    #[tokio::test]
    async fn a_probe_that_cannot_verify_the_server_or_connect_is_unanswered() {
        let server_ca = valid_ca();
        let client_ca = valid_ca();
        let server = ProbeServer::start(&server_ca, &client_ca);
        let dir = tempdir().expect("temp dir");
        let wrong_pins = pin_file_for(dir.path(), &valid_ca());
        let (cert, key) = write_client_pair(&client_ca, dir.path());
        let pair = ProbeClientPair::load(&cert, &key).expect("pair");

        let err = probe_endpoint(&server.socket_path, &wrong_pins, &endpoint_name(), &pair)
            .await
            .expect_err("an unpinned server is not an answer");
        assert!(
            matches!(err, EndpointProbeError::Unanswered { .. }),
            "{err}"
        );

        let absent = dir.path().join("absent.sock");
        let err = probe_endpoint(&absent, &wrong_pins, &endpoint_name(), &pair)
            .await
            .expect_err("nothing listens");
        assert!(
            matches!(err, EndpointProbeError::Unanswered { .. }),
            "{err}"
        );
    }

    /// A pair whose key is not the leaf's is refused at load, naming both
    /// files, before any dial.
    #[test]
    fn a_probe_pair_with_a_mismatched_key_is_refused_at_load() {
        let ca = valid_ca();
        let dir = tempdir().expect("temp dir");
        let (cert, _) = write_client_pair(&ca, dir.path());
        let other = dir.path().join("other.key");
        std::fs::write(
            &other,
            KeyPair::generate().expect("generate key").serialize_pem(),
        )
        .expect("write key");
        let err = ProbeClientPair::load(&cert, &other).expect_err("mismatch");
        assert!(
            matches!(err, ProbeClientPairError::KeyMismatch { .. }),
            "{err}"
        );
        assert!(
            !format!(
                "{:?}",
                ProbeClientPair::load(&cert, &dir.path().join("client.key")).expect("pair")
            )
            .contains("PRIVATE")
        );
    }
}
