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

use std::collections::{BTreeSet, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::ClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
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
            EndpointVerifyRejection::AnchorNotCa => {
                rustls::CertificateError::ApplicationVerificationFailure
            }
            EndpointVerifyRejection::AnchorExpired => rustls::CertificateError::Expired,
            EndpointVerifyRejection::AnchorNotYetValid => rustls::CertificateError::NotValidYet,
        };
        Self::InvalidCertificate(error)
    }
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
    let seconds = i64::try_from(now.as_secs())
        .map_err(|_| EndpointVerifyRejection::ChainVerificationFailed)?;
    let now = ASN1Time::from_timestamp(seconds)
        .map_err(|_| EndpointVerifyRejection::ChainVerificationFailed)?;
    let validity = cert.validity();
    if now < validity.not_before {
        Err(EndpointVerifyRejection::AnchorNotYetValid)
    } else if now > validity.not_after {
        Err(EndpointVerifyRejection::AnchorExpired)
    } else {
        Ok(())
    }
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
}
