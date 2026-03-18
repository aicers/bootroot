use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{Context, Result};
use reqwest::Client;
use rustls::ClientConfig;
use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::parse_x509_pem;
use x509_parser::prelude::ASN1Time;
use x509_parser::prelude::FromDer;

use crate::config::TrustSettings;

/// Builds a [`reqwest::Client`] configured according to the given
/// [`TrustSettings`].
///
/// Three modes:
/// - **Insecure** (`verify_certificates = false`): accepts any certificate.
/// - **System roots** (no `ca_bundle_path`): default webpki verification.
/// - **Custom CA bundle** (with optional SHA-256 pinning): loads the bundle
///   and optionally enforces certificate pins.
///
/// # Errors
///
/// Returns an error if the CA bundle cannot be read or parsed, if
/// certificate pins are specified without a CA bundle path, or if the
/// HTTP client fails to build.
pub fn build_http_client(trust: &TrustSettings) -> Result<Client> {
    install_crypto_provider();
    if !trust.verify_certificates {
        // CodeQL flags `danger_accept_invalid_certs(true)` as
        // rust/disabled-certificate-check.  This is intentional: during
        // initial bootstrap the TLS CA has not yet been provisioned, so
        // certificate verification cannot succeed.  The caller opts in
        // explicitly via `verify_certificates = false` in TrustSettings;
        // once init completes, the flag is set to `true` and this branch
        // is no longer taken.  Dismiss the alert as a false positive.
        return Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .context("Failed to build insecure HTTP client");
    }

    let Some(bundle_path) = trust.ca_bundle_path.as_ref() else {
        if !trust.trusted_ca_sha256.is_empty() {
            anyhow::bail!("trust.ca_bundle_path must be set when trust is configured");
        }
        return Client::builder()
            .build()
            .context("Failed to build HTTP client");
    };

    let (root_store, pins) = load_ca_bundle(bundle_path, &trust.trusted_ca_sha256)?;
    let verifier = WebPkiServerVerifier::builder(Arc::new(root_store.clone()))
        .build()
        .context("Failed to build TLS verifier")?;
    let verifier: Arc<dyn ServerCertVerifier> = if pins.is_empty() {
        verifier
    } else {
        Arc::new(PinnedCertVerifier::new(verifier, pins))
    };

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if !trust.trusted_ca_sha256.is_empty() {
        config.dangerous().set_certificate_verifier(verifier);
    }

    Client::builder()
        .use_preconfigured_tls(config)
        .build()
        .context("Failed to build trusted HTTP client")
}

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn load_ca_bundle(
    path: &std::path::Path,
    pins: &[String],
) -> Result<(rustls::RootCertStore, HashSet<String>)> {
    let contents = std::fs::read(path)
        .with_context(|| format!("Failed to read CA bundle at {}", path.display()))?;
    let mut remaining = contents.as_slice();
    let mut certs = Vec::new();
    while !remaining.is_empty() {
        if remaining.iter().all(u8::is_ascii_whitespace) {
            break;
        }
        let (rest, pem) =
            parse_x509_pem(remaining).map_err(|_| anyhow::anyhow!("Failed to parse CA bundle"))?;
        if pem.label == "CERTIFICATE" {
            certs.push(pem.contents);
        }
        remaining = rest;
    }
    if certs.is_empty() {
        anyhow::bail!("CA bundle contained no certificates");
    }
    let mut root_store = rustls::RootCertStore::empty();
    for cert in certs {
        root_store
            .add(CertificateDer::from(cert))
            .context("Failed to add CA certificate")?;
    }
    let pins = pins
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<HashSet<_>>();
    Ok((root_store, pins))
}

#[derive(Debug)]
struct PinnedCertVerifier {
    inner: Arc<dyn ServerCertVerifier>,
    allowed: HashSet<String>,
}

impl PinnedCertVerifier {
    fn new(inner: Arc<dyn ServerCertVerifier>, allowed: HashSet<String>) -> Self {
        Self { inner, allowed }
    }

    fn check_pins(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
    ) -> Result<(), rustls::Error> {
        let matches = self.allowed.contains(&sha256_hex(end_entity.as_ref()))
            || intermediates
                .iter()
                .any(|cert| self.allowed.contains(&sha256_hex(cert.as_ref())));
        if matches {
            Ok(())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn check_direct_pin(
        &self,
        end_entity: &CertificateDer<'_>,
        now: UnixTime,
    ) -> Result<(), rustls::Error> {
        if !self.allowed.contains(&sha256_hex(end_entity.as_ref())) {
            return Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        validate_certificate_time(end_entity, now)?;
        Ok(())
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
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => self.check_pins(end_entity, intermediates)?,
            Err(inner_err) => self
                .check_direct_pin(end_entity, now)
                .map_err(|_| inner_err)?,
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut output = String::with_capacity(digest.as_ref().len() * 2);
    for byte in digest.as_ref() {
        use std::fmt::Write;
        write!(output, "{byte:02x}").expect("writing to string should not fail");
    }
    output
}

fn validate_certificate_time(
    certificate: &CertificateDer<'_>,
    now: UnixTime,
) -> Result<(), rustls::Error> {
    let (_, cert) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|_| rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let now = i64::try_from(now.as_secs()).map_err(|_| {
        rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
    })?;
    let now = ASN1Time::from_timestamp(now).map_err(|_| {
        rustls::Error::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
    })?;
    if cert.validity().is_valid_at(now) {
        Ok(())
    } else {
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::Expired,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
    use rustls::DigitallySignedStruct;
    use rustls::SignatureScheme;

    use super::*;

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
        let verifier =
            PinnedCertVerifier::new(Arc::new(RejectingVerifier), HashSet::from([fingerprint]));

        let result = verifier.verify_server_cert(
            &certificate,
            &[],
            &ServerName::try_from("localhost").expect("valid server name"),
            &[],
            UnixTime::now(),
        );

        assert!(result.is_ok());
    }

    #[test]
    fn pinned_verifier_rejects_direct_certificate_without_matching_pin() {
        let certificate = generate_ca_certificate();
        let verifier = PinnedCertVerifier::new(
            Arc::new(RejectingVerifier),
            HashSet::from([String::from("00")]),
        );

        let result = verifier.verify_server_cert(
            &certificate,
            &[],
            &ServerName::try_from("localhost").expect("valid server name"),
            &[],
            UnixTime::since_unix_epoch(Duration::from_secs(1_900_000_000)),
        );

        assert!(result.is_err());
    }

    fn generate_ca_certificate() -> CertificateDer<'static> {
        let key = KeyPair::generate().expect("generate key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, "Bootroot Test Intermediate");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-signed cert");
        CertificateDer::from(cert.der().to_vec())
    }
}
