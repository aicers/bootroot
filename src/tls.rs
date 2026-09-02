use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Client;
use rustls::ClientConfig;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::ASN1Time;
use x509_parser::prelude::FromDer;

use crate::config::TrustSettings;

/// Connect timeout for `OpenBao` HTTP clients.
///
/// All `OpenBao` payloads are small JSON, so a TCP connect that has not
/// completed within this bound is almost certainly a stalled or
/// black-holed endpoint. Bounding the connect keeps a single hung dial
/// from wedging the shared fast-poll client (see issue #695).
pub(crate) const OPENBAO_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total request timeout for `OpenBao` HTTP clients.
///
/// Bounds the whole request (connect + send + receive) so a peer that
/// accepts the connection and then stalls cannot hang the fast-poll loop
/// indefinitely, which shares one client across every poll.
pub(crate) const OPENBAO_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Builds a [`reqwest::Client`] configured according to the given
/// [`TrustSettings`].
///
/// Two modes:
/// - **System roots** (no `ca_bundle_path`): default webpki verification.
/// - **Custom CA bundle** (with optional SHA-256 pinning): loads the bundle
///   and optionally enforces certificate pins.
///
/// There is no third mode. Certificate verification is never disabled:
/// a peer this client cannot verify against the configured trust fails
/// the handshake, and the fix is the trust anchors, the SANs or the
/// clock rather than an override.
///
/// # Errors
///
/// Returns an error if the CA bundle cannot be read or parsed, if
/// certificate pins are specified without a CA bundle path, or if the
/// HTTP client fails to build.
pub fn build_http_client(trust: &TrustSettings) -> Result<Client> {
    install_crypto_provider();

    let Some(bundle_path) = trust.ca_bundle_path.as_ref() else {
        if !trust.trusted_ca_sha256.is_empty() {
            anyhow::bail!("trust.ca_bundle_path must be set when trust is configured");
        }
        return Client::builder()
            .build()
            .context("Failed to build HTTP client");
    };

    let (certs, pins) = load_ca_bundle(bundle_path, &trust.trusted_ca_sha256)?;
    let root_store = certs_to_root_store(&certs)?;
    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if !pins.is_empty() {
        config
            .dangerous()
            .set_certificate_verifier(build_pinned_verifier(&certs, &pins)?);
    }

    Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .context("Failed to build trusted HTTP client")
}

/// Builds a TLS configuration that establishes trust solely from certificates
/// the peer presents whose fingerprints already occur in `pins`.
///
/// This is intentionally restricted to start-time registrar repair.  The
/// configured CA bundle is derived output in that path, so neither it nor the
/// system roots can establish the connection that recreates it.
///
/// # Errors
///
/// Returns an error when `pins` is empty.
pub(crate) fn build_bootstrap_client_config(pins: &[String]) -> Result<ClientConfig> {
    install_crypto_provider();
    let allowed = pins
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    if allowed.is_empty() {
        anyhow::bail!("trusted_ca_sha256 must not be empty for bootstrap TLS");
    }

    let mut config = ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(BootstrapPinnedCertVerifier::new(allowed)));
    Ok(config)
}

/// Builds a [`reqwest::Client`] whose trust root is the given PEM-encoded
/// CA bundle (in-memory, no file I/O), with optional SHA-256 certificate
/// pinning.
///
/// This is the entry point for RN-side TLS bootstrap: the PEM content
/// travels inside the bootstrap artifact and is used to verify the
/// control-plane TLS certificate without relying on the system trust
/// store.
///
/// When `pins` is non-empty the client enforces SHA-256 certificate
/// pinning via the same `PinnedCertVerifier` path used by
/// [`build_http_client`].
///
/// # Errors
///
/// Returns an error if the PEM content cannot be parsed or if the HTTP
/// client fails to build.
pub fn build_http_client_from_pem(pem_content: &str, pins: &[String]) -> Result<Client> {
    let config = build_client_config_from_pem(pem_content, pins)?;
    Client::builder()
        .use_preconfigured_tls(config)
        .connect_timeout(OPENBAO_CONNECT_TIMEOUT)
        .timeout(OPENBAO_REQUEST_TIMEOUT)
        .build()
        .context("Failed to build HTTP client from PEM bundle")
}

/// Builds a [`ClientConfig`] whose trust root is the given PEM-encoded CA
/// bundle (in-memory), with optional SHA-256 certificate pinning.
///
/// Callers that need to set additional [`reqwest::ClientBuilder`] options
/// (e.g. timeout) can feed the returned config into
/// [`reqwest::ClientBuilder::use_preconfigured_tls`].
///
/// # Errors
///
/// Returns an error if the PEM content cannot be parsed.
pub fn build_client_config_from_pem(pem_content: &str, pins: &[String]) -> Result<ClientConfig> {
    install_crypto_provider();
    let certs = parse_pem_to_cert_list(pem_content.as_bytes())?;
    let root_store = certs_to_root_store(&certs)?;
    let pin_set: HashSet<String> = pins.iter().map(|p| p.to_ascii_lowercase()).collect();
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    if !pin_set.is_empty() {
        cfg.dangerous()
            .set_certificate_verifier(build_pinned_verifier(&certs, &pin_set)?);
    }
    Ok(cfg)
}

/// Builds a [`reqwest::Client`] whose trust store is the union of the
/// Mozilla webpki root certificates (the same set the default `Client`
/// ships with) and the given PEM-encoded CA bundle.
///
/// This is the trust path the CLI uses for state-backed `OpenBao`
/// connections after `init` has written a step-ca bundle to
/// `<secrets_dir>/certs/`: the local step-ca-signed `OpenBao` cert
/// verifies via the appended PEM, while an externally-managed
/// (publicly-trusted) HTTPS endpoint reachable from the same code path
/// keeps verifying via the webpki roots.  Replacing the default trust
/// store with the local PEM alone — as the original `with_pem_trust`
/// path did — would regress any public-CA HTTPS `OpenBao` URL into an
/// `UnknownIssuer` failure once `root_ca.crt` exists on disk.
///
/// # Errors
///
/// Returns an error if the PEM content cannot be parsed or the HTTP
/// client fails to build.
pub fn build_http_client_with_local_and_webpki_roots(pem_content: &str) -> Result<Client> {
    install_crypto_provider();
    let root_store = build_local_plus_webpki_root_store(pem_content)?;
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    Client::builder()
        .use_preconfigured_tls(config)
        .connect_timeout(OPENBAO_CONNECT_TIMEOUT)
        .timeout(OPENBAO_REQUEST_TIMEOUT)
        .build()
        .context("Failed to build HTTP client with local+webpki roots")
}

/// Builds a [`reqwest::Client`] that verifies the server against
/// `ca_pem` **and presents `cert_pem`/`key_pem` as a client
/// certificate**.
///
/// This is the bootroot-internal registrar credential's transport, and
/// the only client-authenticated one in the crate. `OpenBao`'s
/// `auth/cert` backend validates the presented chain against its own
/// trusted entry, so the listener is left requesting client
/// certificates without requiring them — which is what keeps the
/// certificate-less `AppRole` agents and the token-authenticated CLI
/// working against the same listener.
///
/// The trust store is `ca_pem` alone rather than the webpki union: this
/// client only ever talks to the deployment's own `OpenBao`, and a
/// public root has no business verifying it.
///
/// # Errors
///
/// Returns an error if either PEM cannot be parsed, if the key is not a
/// supported private key, or if the HTTP client fails to build.
pub fn build_http_client_with_identity(
    ca_pem: &str,
    cert_pem: &str,
    key_pem: &str,
) -> Result<Client> {
    install_crypto_provider();
    let root_store = certs_to_root_store(&parse_pem_to_cert_list(ca_pem.as_bytes())?)?;
    let chain = parse_pem_to_cert_list(cert_pem.as_bytes())?;
    let key = parse_pem_private_key(key_pem)?;
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(chain, key)
        .context("Failed to configure the client certificate")?;
    Client::builder()
        .use_preconfigured_tls(config)
        .connect_timeout(OPENBAO_CONNECT_TIMEOUT)
        .timeout(OPENBAO_REQUEST_TIMEOUT)
        .build()
        .context("Failed to build client-authenticated HTTP client")
}

/// Parses the first private key in `key_pem`, accepting PKCS#8, PKCS#1
/// and SEC1 encodings.
///
/// The error names none of the bytes it failed on: this input is key
/// material, and a parse failure that quoted it would put it in a log.
fn parse_pem_private_key(key_pem: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(key_pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .context("Failed to parse the client private key")?
        .ok_or_else(|| anyhow::anyhow!("the client private key PEM contained no private key"))
}

pub(crate) fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Builds a [`rustls::RootCertStore`] containing every Mozilla webpki
/// root plus every certificate parsed from `pem_content`.
///
/// Factored out so the union semantics can be asserted in unit tests
/// without driving a real public-CA TLS handshake.
///
/// # Errors
///
/// Returns an error if the PEM content cannot be parsed.
pub(crate) fn build_local_plus_webpki_root_store(
    pem_content: &str,
) -> Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();
    let (loaded, _) = root_store
        .add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
    if loaded == 0 {
        anyhow::bail!("webpki root certificate bundle was empty");
    }
    let local_certs = parse_pem_to_cert_list(pem_content.as_bytes())?;
    for cert in local_certs {
        root_store
            .add(cert)
            .context("Failed to add local CA certificate")?;
    }
    Ok(root_store)
}

/// Parses a PEM-encoded byte buffer into the list of `CERTIFICATE`
/// entries it contains, rejecting a buffer that parses to zero
/// certificates. Widened to `pub(crate)` so `kv_payload` can structurally
/// validate a KV trust bundle before it reaches disk (issue #695).
pub(crate) fn parse_pem_to_cert_list(pem_bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut remaining = pem_bytes;
    let mut certs = Vec::new();
    while !remaining.is_empty() {
        if remaining.iter().all(u8::is_ascii_whitespace) {
            break;
        }
        let (rest, pem) =
            parse_x509_pem(remaining).map_err(|_| anyhow::anyhow!("Failed to parse CA bundle"))?;
        if pem.label == "CERTIFICATE" {
            certs.push(CertificateDer::from(pem.contents));
        }
        remaining = rest;
    }
    if certs.is_empty() {
        anyhow::bail!("CA bundle contained no certificates");
    }
    Ok(certs)
}

#[cfg(test)]
fn parse_pem_to_root_store(pem_bytes: &[u8]) -> Result<rustls::RootCertStore> {
    let certs = parse_pem_to_cert_list(pem_bytes)?;
    let mut root_store = rustls::RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert)
            .context("Failed to add CA certificate")?;
    }
    Ok(root_store)
}

fn load_ca_bundle(
    path: &std::path::Path,
    pins: &[String],
) -> Result<(Vec<CertificateDer<'static>>, HashSet<String>)> {
    let contents = std::fs::read(path)
        .with_context(|| format!("Failed to read CA bundle at {}", path.display()))?;
    let certs = parse_pem_to_cert_list(&contents)?;
    let pins = pins
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    Ok((certs, pins))
}

/// Builds a [`rustls::RootCertStore`] from an already-parsed certificate list.
pub(crate) fn certs_to_root_store(
    certs: &[CertificateDer<'static>],
) -> Result<rustls::RootCertStore> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in certs {
        root_store
            .add(cert.clone())
            .context("Failed to add CA certificate")?;
    }
    Ok(root_store)
}

/// Builds the pinned server-certificate verifier for a CA bundle and pin set.
///
/// The inner webpki verifier trusts only the bundle certificates whose
/// SHA-256 fingerprint is pinned, so a successful webpki verification already
/// proves the presented leaf chains to a pinned trust anchor — no
/// presented-chain scan is required, and a production leaf-only server is
/// accepted as long as its issuer is pinned. When no bundle certificate
/// matches a pin the verifier is direct-pin only: it accepts a handshake
/// solely when the server presents a directly pinned CA certificate.
pub(crate) fn build_pinned_verifier(
    certs: &[CertificateDer<'static>],
    pins: &HashSet<String>,
) -> Result<Arc<dyn ServerCertVerifier>> {
    let inner = build_pinned_root_verifier(certs, pins)?;
    Ok(Arc::new(PinnedCertVerifier::new(inner, pins.clone())))
}

/// Builds a webpki verifier whose trust anchors are the pinned subset of the
/// bundle, or `None` when no bundle certificate matches a pin (an empty root
/// store cannot back a `WebPkiServerVerifier`, so the caller falls back to a
/// direct-pin-only verifier instead of failing to build the client).
fn build_pinned_root_verifier(
    certs: &[CertificateDer<'static>],
    pins: &HashSet<String>,
) -> Result<Option<Arc<dyn ServerCertVerifier>>> {
    let mut root_store = rustls::RootCertStore::empty();
    for cert in certs {
        if pins.contains(&sha256_hex(cert.as_ref())) {
            root_store
                .add(cert.clone())
                .context("Failed to add pinned CA certificate")?;
        }
    }
    if root_store.is_empty() {
        return Ok(None);
    }
    let verifier: Arc<dyn ServerCertVerifier> = WebPkiServerVerifier::builder(Arc::new(root_store))
        .build()
        .context("Failed to build TLS verifier")?;
    Ok(Some(verifier))
}

#[derive(Debug)]
struct PinnedCertVerifier {
    /// Webpki verifier restricted to the pinned trust anchors, or `None` when
    /// no bundle certificate matches a pin (direct-pin-only mode).
    inner: Option<Arc<dyn ServerCertVerifier>>,
    allowed: HashSet<String>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl PinnedCertVerifier {
    fn new(inner: Option<Arc<dyn ServerCertVerifier>>, allowed: HashSet<String>) -> Self {
        Self {
            inner,
            allowed,
            supported_algs: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }

    fn check_direct_pin(
        &self,
        end_entity: &CertificateDer<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        if !self.allowed.contains(&sha256_hex(end_entity.as_ref())) {
            return Err(invalid_certificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        let cert = parse_certificate(end_entity)?;
        validate_direct_pin_certificate(&cert, now)
    }
}

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // When the inner verifier trusts only the pinned CA subset, a
        // successful chain build already proves the leaf chains to a pinned
        // trust anchor, so no presented-chain scan is needed. The direct-pin
        // fallback still covers pins that are not part of the bundle.
        let chained = match &self.inner {
            Some(inner) => inner
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok(),
            None => false,
        };
        if !chained {
            self.check_direct_pin(end_entity, now)?;
        }
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

/// Verifies a peer chain against pins that predate the connection.
///
/// Unlike [`PinnedCertVerifier`], this verifier cannot have roots up front:
/// the only recoverable CA material is the peer's TLS chain.  It filters that
/// chain to configured pins, then lets webpki build a normal path to one of
/// those anchors.  The direct end-entity-pin fallback deliberately remains
/// the same as the ordinary pin verifier's branch.
#[derive(Debug)]
struct BootstrapPinnedCertVerifier {
    allowed: HashSet<String>,
    supported_algs: WebPkiSupportedAlgorithms,
}

impl BootstrapPinnedCertVerifier {
    fn new(allowed: HashSet<String>) -> Self {
        Self {
            allowed,
            supported_algs: rustls::crypto::ring::default_provider()
                .signature_verification_algorithms,
        }
    }

    fn check_direct_pin(
        &self,
        end_entity: &CertificateDer<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        PinnedCertVerifier::new(None, self.allowed.clone()).check_direct_pin(end_entity, now)
    }

    fn verify_to_presented_pin(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Option<bool> {
        let mut roots = rustls::RootCertStore::empty();
        for certificate in std::iter::once(end_entity).chain(intermediates.iter()) {
            if self.allowed.contains(&sha256_hex(certificate.as_ref())) {
                // A directly pinned server leaf is not a trust anchor. Leave
                // it to the unchanged direct-pin branch when it cannot enter
                // the root store; it must not make an actual pinned anchor
                // elsewhere in the chain disappear.
                let _ = roots.add(CertificateDer::from(certificate.as_ref().to_vec()));
            }
        }
        if roots.is_empty() {
            return None;
        }
        let Ok(verifier) = WebPkiServerVerifier::builder(Arc::new(roots)).build() else {
            return Some(false);
        };
        Some(
            verifier
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .is_ok(),
        )
    }
}

impl ServerCertVerifier for BootstrapPinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let chained = self
            .verify_to_presented_pin(end_entity, intermediates, server_name, ocsp_response, now)
            .unwrap_or(false);
        if !chained {
            // Keep the ordinary verifier's direct end-entity-pin fallback:
            // a failed path to a presented pinned anchor must not reject a
            // separately valid direct pin on the server certificate.
            self.check_direct_pin(end_entity, now)?;
        }
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

/// Computes the `trusted_ca_sha256` fingerprints (lowercase hex SHA-256 of
/// each certificate's DER) for every certificate in a PEM bundle.
///
/// Public so the remote bootstrap binary can advertise a bundle's trust
/// anchors in its artifact for TLS pinning (issue #695).
///
/// # Errors
///
/// Returns an error if the PEM parses to zero certificates.
pub fn ca_bundle_fingerprints(pem_content: &str) -> Result<Vec<String>> {
    let certs = parse_pem_to_cert_list(pem_content.as_bytes())?;
    Ok(certs.iter().map(|cert| sha256_hex(cert.as_ref())).collect())
}

/// Computes the lowercase hex SHA-256 of `bytes`. For a certificate DER
/// this yields the fingerprint used for `trusted_ca_sha256` pins and the
/// KV trust-payload consistency check (issue #695).
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut output = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("writing to string should not fail");
    }
    output
}

/// The payload the certificate/key match check signs and verifies.
///
/// Its content is irrelevant — what matters is that the same bytes go
/// through the loaded key and come back out verifiable against the
/// leaf's public key, which is what proves the two are a pair.
const KEY_MATCH_TEST_MESSAGE: &[u8] = b"bootroot-cert-key-match";

/// The signature schemes the certificate/key match check will try, in
/// preference order.
const KEY_MATCH_SCHEMES: [rustls::SignatureScheme; 4] = [
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::ED25519,
];

/// Reports whether `signing_key` is the private key of `leaf`.
///
/// A signature rather than a comparison of encoded key material: the
/// loaded key signs a fixed message and the leaf's public key verifies
/// it, so a key that merely parses alongside an unrelated certificate is
/// refused. The endpoint's TLS loader and the registrar surface's
/// start-time usability evaluation both ask this question, and they ask
/// it here so a leaf one accepts cannot be one the other rejects.
pub(crate) fn cert_key_matches(
    leaf: &CertificateDer<'_>,
    signing_key: &dyn rustls::sign::SigningKey,
) -> bool {
    let Some(signer) = signing_key.choose_scheme(&KEY_MATCH_SCHEMES) else {
        return false;
    };
    let algorithm: &dyn ring::signature::VerificationAlgorithm = match signer.scheme() {
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
        rustls::SignatureScheme::RSA_PSS_SHA256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
        rustls::SignatureScheme::ED25519 => &ring::signature::ED25519,
        _ => return false,
    };
    let Ok(signature) = signer.sign(KEY_MATCH_TEST_MESSAGE) else {
        return false;
    };
    let Ok((_, certificate)) = x509_parser::parse_x509_certificate(leaf.as_ref()) else {
        return false;
    };
    let public_key: &[u8] = certificate.public_key().subject_public_key.as_ref();
    ring::signature::UnparsedPublicKey::new(algorithm, public_key)
        .verify(KEY_MATCH_TEST_MESSAGE, &signature)
        .is_ok()
}

fn invalid_certificate(error: rustls::CertificateError) -> rustls::Error {
    rustls::Error::InvalidCertificate(error)
}

fn parse_certificate<'a>(
    certificate: &'a CertificateDer<'_>,
) -> Result<X509Certificate<'a>, rustls::Error> {
    let (_, cert) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|_| invalid_certificate(rustls::CertificateError::BadEncoding))?;
    Ok(cert)
}

fn validate_direct_pin_certificate(
    cert: &X509Certificate<'_>,
    now: UnixTime,
) -> Result<(), rustls::Error> {
    let is_ca = cert
        .basic_constraints()
        .map_err(|_| invalid_certificate(rustls::CertificateError::BadEncoding))?
        .is_some_and(|constraints| constraints.value.ca);
    if !is_ca {
        return Err(invalid_certificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ));
    }
    validate_certificate_time(cert, now)
}

fn asn1_time_from_unix_time(now: UnixTime) -> Result<ASN1Time, rustls::Error> {
    let now = i64::try_from(now.as_secs()).map_err(|_| {
        invalid_certificate(rustls::CertificateError::ApplicationVerificationFailure)
    })?;
    ASN1Time::from_timestamp(now)
        .map_err(|_| invalid_certificate(rustls::CertificateError::ApplicationVerificationFailure))
}

fn validate_certificate_time(
    cert: &X509Certificate<'_>,
    now: UnixTime,
) -> Result<(), rustls::Error> {
    let now = asn1_time_from_unix_time(now)?;
    let validity = cert.validity();
    if now < validity.not_before {
        Err(invalid_certificate(rustls::CertificateError::NotValidYet))
    } else if now > validity.not_after {
        Err(invalid_certificate(rustls::CertificateError::Expired))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, date_time_ymd};
    use rustls::DigitallySignedStruct;
    use rustls::SignatureScheme;

    use super::*;

    const DIRECT_PIN_TEST_NOW_SECS: u64 = 1_700_000_000;

    #[derive(Debug)]
    struct RejectingVerifier;

    impl ServerCertVerifier for RejectingVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ECDSA_NISTP256_SHA256]
        }
    }

    #[test]
    fn pinned_verifier_accepts_directly_pinned_ca_certificate() {
        let certificate = generate_ca_certificate();
        let fingerprint = sha256_hex(certificate.as_ref());
        let result = verify_direct_certificate(
            &certificate,
            HashSet::from([fingerprint]),
            direct_pin_test_time(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn pinned_verifier_rejects_direct_certificate_without_matching_pin() {
        let certificate = generate_ca_certificate();
        let result = verify_direct_certificate(
            &certificate,
            HashSet::from([String::from("00")]),
            direct_pin_test_time(),
        );

        assert_eq!(
            result.expect_err("pin mismatch should reject direct pin fallback"),
            invalid_certificate(rustls::CertificateError::ApplicationVerificationFailure),
        );
    }

    #[test]
    fn pinned_verifier_rejects_expired_directly_pinned_ca_certificate() {
        let certificate = generate_expired_ca_certificate();
        let fingerprint = sha256_hex(certificate.as_ref());
        let result = verify_direct_certificate(
            &certificate,
            HashSet::from([fingerprint]),
            direct_pin_test_time(),
        );

        assert_eq!(
            result.expect_err("expired pinned CA should be rejected"),
            invalid_certificate(rustls::CertificateError::Expired),
        );
    }

    #[test]
    fn pinned_verifier_rejects_directly_pinned_ca_certificate_that_is_not_valid_yet() {
        let certificate = generate_not_yet_valid_ca_certificate();
        let fingerprint = sha256_hex(certificate.as_ref());
        let result = verify_direct_certificate(
            &certificate,
            HashSet::from([fingerprint]),
            direct_pin_test_time(),
        );

        assert_eq!(
            result.expect_err("future pinned CA should be rejected"),
            invalid_certificate(rustls::CertificateError::NotValidYet),
        );
    }

    #[test]
    fn pinned_verifier_rejects_directly_pinned_non_ca_certificate() {
        let certificate = generate_leaf_certificate();
        let fingerprint = sha256_hex(certificate.as_ref());
        let result = verify_direct_certificate(
            &certificate,
            HashSet::from([fingerprint]),
            direct_pin_test_time(),
        );

        assert_eq!(
            result.expect_err("non-CA pinned certificate should be rejected"),
            invalid_certificate(rustls::CertificateError::ApplicationVerificationFailure),
        );
    }

    #[test]
    fn pinned_verifier_without_inner_accepts_directly_pinned_ca_certificate() {
        let certificate = generate_ca_certificate();
        let fingerprint = sha256_hex(certificate.as_ref());
        let verifier = PinnedCertVerifier::new(None, HashSet::from([fingerprint]));
        let result = verifier.verify_server_cert(
            &certificate,
            &[],
            &ServerName::try_from("localhost").expect("valid server name"),
            &[],
            direct_pin_test_time(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn pinned_verifier_without_inner_rejects_unpinned_certificate() {
        let certificate = generate_ca_certificate();
        let verifier = PinnedCertVerifier::new(None, HashSet::from([String::from("00")]));
        let result = verifier.verify_server_cert(
            &certificate,
            &[],
            &ServerName::try_from("localhost").expect("valid server name"),
            &[],
            direct_pin_test_time(),
        );

        assert!(result.is_err());
    }

    #[test]
    fn bootstrap_verifier_builds_a_path_to_a_presented_pinned_anchor() {
        install_crypto_provider();
        let root_key = KeyPair::generate().expect("root key");
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let root = root_params
            .self_signed(&root_key)
            .expect("root certificate");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("leaf parameters");
        let issuer = rcgen::Issuer::from_params(&root_params, &root_key);
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf certificate");
        let leaf = CertificateDer::from(leaf.der().to_vec());
        let root = CertificateDer::from(root.der().to_vec());
        let verifier = BootstrapPinnedCertVerifier::new(HashSet::from([sha256_hex(root.as_ref())]));

        let result = verifier.verify_server_cert(
            &leaf,
            &[root],
            &ServerName::try_from("localhost").expect("valid server name"),
            &[],
            direct_pin_test_time(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn bootstrap_verifier_rejects_a_pinned_certificate_off_the_chain() {
        install_crypto_provider();
        let pinned_root_key = KeyPair::generate().expect("pinned root key");
        let mut pinned_root_params = CertificateParams::default();
        pinned_root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let pinned_root = pinned_root_params
            .self_signed(&pinned_root_key)
            .expect("pinned root certificate");

        let issuing_root_key = KeyPair::generate().expect("issuing root key");
        let mut issuing_root_params = CertificateParams::default();
        issuing_root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let issuer = rcgen::Issuer::from_params(&issuing_root_params, &issuing_root_key);
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_params =
            CertificateParams::new(vec!["localhost".to_string()]).expect("leaf parameters");
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .expect("leaf certificate");
        let leaf = CertificateDer::from(leaf.der().to_vec());
        let pinned_root = CertificateDer::from(pinned_root.der().to_vec());
        let verifier =
            BootstrapPinnedCertVerifier::new(HashSet::from([sha256_hex(pinned_root.as_ref())]));

        let result = verifier.verify_server_cert(
            &leaf,
            &[pinned_root],
            &ServerName::try_from("localhost").expect("valid server name"),
            &[],
            direct_pin_test_time(),
        );

        assert!(
            result.is_err(),
            "a pinned certificate not on the leaf's validation path must not establish trust"
        );
    }

    #[test]
    fn bootstrap_verifier_keeps_the_direct_pin_fallback() {
        install_crypto_provider();
        let certificate = generate_ca_certificate();
        let verifier =
            BootstrapPinnedCertVerifier::new(HashSet::from([sha256_hex(certificate.as_ref())]));

        let result = verifier.verify_server_cert(
            &certificate,
            &[],
            &ServerName::try_from("localhost").expect("valid server name"),
            &[],
            direct_pin_test_time(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn build_pinned_root_verifier_returns_none_when_no_pin_matches_bundle() {
        install_crypto_provider();
        let pem = generate_ca_pem();
        let certs = parse_pem_to_cert_list(pem.as_bytes()).expect("cert list");
        let pins = HashSet::from([String::from("00")]);
        let verifier = build_pinned_root_verifier(&certs, &pins).expect("build verifier");
        assert!(verifier.is_none());
    }

    #[test]
    fn build_pinned_root_verifier_returns_some_when_pin_matches_bundle() {
        install_crypto_provider();
        let pem = generate_ca_pem();
        let certs = parse_pem_to_cert_list(pem.as_bytes()).expect("cert list");
        let cert = certs.first().expect("at least one certificate");
        let pins = HashSet::from([sha256_hex(cert.as_ref())]);
        let verifier = build_pinned_root_verifier(&certs, &pins).expect("build verifier");
        assert!(verifier.is_some());
    }

    fn direct_pin_test_time() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(DIRECT_PIN_TEST_NOW_SECS))
    }

    fn verify_direct_certificate(
        certificate: &CertificateDer<'_>,
        allowed: HashSet<String>,
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verifier = PinnedCertVerifier::new(Some(Arc::new(RejectingVerifier)), allowed);
        verifier.verify_server_cert(
            certificate,
            &[],
            &ServerName::try_from("localhost").expect("valid server name"),
            &[],
            now,
        )
    }

    fn generate_ca_certificate() -> CertificateDer<'static> {
        generate_certificate(
            "Bootroot Test Intermediate",
            IsCa::Ca(BasicConstraints::Unconstrained),
            None,
            None,
        )
    }

    fn generate_expired_ca_certificate() -> CertificateDer<'static> {
        generate_certificate(
            "Bootroot Expired Intermediate",
            IsCa::Ca(BasicConstraints::Unconstrained),
            Some((1999, 1, 1)),
            Some((2000, 1, 1)),
        )
    }

    fn generate_not_yet_valid_ca_certificate() -> CertificateDer<'static> {
        generate_certificate(
            "Bootroot Future Intermediate",
            IsCa::Ca(BasicConstraints::Unconstrained),
            Some((2100, 1, 1)),
            Some((2101, 1, 1)),
        )
    }

    fn generate_leaf_certificate() -> CertificateDer<'static> {
        generate_certificate("Bootroot Test Leaf", IsCa::NoCa, None, None)
    }

    fn generate_certificate(
        common_name: &str,
        is_ca: IsCa,
        not_before: Option<(i32, u8, u8)>,
        not_after: Option<(i32, u8, u8)>,
    ) -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = is_ca;
        if let Some((year, month, day)) = not_before {
            params.not_before = date_time_ymd(year, month, day);
        }
        if let Some((year, month, day)) = not_after {
            params.not_after = date_time_ymd(year, month, day);
        }
        let cert = params.self_signed(&key).expect("self-signed cert");
        CertificateDer::from(cert.der().to_vec())
    }

    fn generate_ca_pem() -> String {
        use rcgen::CertificateParams;

        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-signed cert");
        cert.pem()
    }

    #[test]
    fn parse_pem_to_root_store_accepts_valid_pem() {
        let pem = generate_ca_pem();
        let store = parse_pem_to_root_store(pem.as_bytes()).expect("valid PEM");
        assert!(!store.is_empty());
    }

    #[test]
    fn parse_pem_to_root_store_rejects_empty_input() {
        let err = parse_pem_to_root_store(b"").expect_err("empty input");
        assert!(
            err.to_string().contains("no certificates"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_pem_to_root_store_rejects_non_pem_content() {
        let err = parse_pem_to_root_store(b"not a PEM").expect_err("non-PEM");
        assert!(
            err.to_string().contains("Failed to parse"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_pem_to_root_store_skips_whitespace_only_trailing() {
        let mut pem = generate_ca_pem();
        pem.push_str("   \n  \n");
        let store = parse_pem_to_root_store(pem.as_bytes()).expect("trailing whitespace");
        assert!(!store.is_empty());
    }

    #[test]
    fn build_http_client_from_pem_succeeds_with_valid_pem() {
        let pem = generate_ca_pem();
        let client = build_http_client_from_pem(&pem, &[]);
        assert!(client.is_ok());
    }

    #[test]
    fn build_http_client_from_pem_fails_with_empty_pem() {
        let err = build_http_client_from_pem("", &[]).expect_err("empty PEM");
        assert!(
            err.to_string().contains("no certificates"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_http_client_from_pem_with_pins_succeeds() {
        let pem = generate_ca_pem();
        let pin = "aa".repeat(32);
        let client = build_http_client_from_pem(&pem, &[pin]);
        assert!(client.is_ok());
    }

    /// Proves the local-plus-webpki root store keeps every Mozilla
    /// webpki trust anchor in place and adds the supplied local PEM on
    /// top.  The regression we are guarding against: the original
    /// `with_local_trust` path called into `with_pem_trust`, which
    /// replaced the trust store with the local PEM alone — so any
    /// externally-managed (publicly-trusted) HTTPS `OpenBao` URL
    /// started failing with `UnknownIssuer` once `root_ca.crt` existed
    /// on disk.
    #[test]
    fn build_local_plus_webpki_root_store_unions_webpki_and_local_pem() {
        let pem = generate_ca_pem();
        let store = build_local_plus_webpki_root_store(&pem).expect("union store");
        let webpki_count = webpki_root_certs::TLS_SERVER_ROOT_CERTS.len();
        assert_eq!(
            store.len(),
            webpki_count + 1,
            "expected webpki ({webpki_count}) + 1 local CA, got {}",
            store.len()
        );
    }

    #[test]
    fn build_local_plus_webpki_root_store_rejects_empty_pem() {
        let err = build_local_plus_webpki_root_store("").expect_err("empty PEM");
        assert!(
            err.to_string().contains("no certificates"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn build_http_client_with_local_and_webpki_roots_succeeds_with_valid_pem() {
        let pem = generate_ca_pem();
        assert!(build_http_client_with_local_and_webpki_roots(&pem).is_ok());
    }
}
