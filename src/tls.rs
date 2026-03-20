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
/// [`TrustSettings`] and runtime TLS override.
///
/// Three modes:
/// - **Insecure override** (`--insecure`): accepts any certificate.
/// - **System roots** (no `ca_bundle_path`): default webpki verification.
/// - **Custom CA bundle** (with optional SHA-256 pinning): loads the bundle
///   and optionally enforces certificate pins.
///
/// # Errors
///
/// Returns an error if the CA bundle cannot be read or parsed, if
/// certificate pins are specified without a CA bundle path, or if the
/// HTTP client fails to build.
pub fn build_http_client(trust: &TrustSettings, insecure_mode: bool) -> Result<Client> {
    install_crypto_provider();
    if insecure_mode {
        // CodeQL flags `danger_accept_invalid_certs(true)` as
        // rust/disabled-certificate-check.  This is intentional: during
        // break-glass recovery or explicit diagnostics the caller may opt in
        // to an insecure ACME TLS client via `--insecure`. Dismiss the alert
        // as a false positive because the override is explicit and temporary.
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
        match self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        ) {
            Ok(_) => self.check_pins(end_entity, intermediates)?,
            Err(_) => self.check_direct_pin(end_entity, now)?,
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

    fn direct_pin_test_time() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(DIRECT_PIN_TEST_NOW_SECS))
    }

    fn verify_direct_certificate(
        certificate: &CertificateDer<'_>,
        allowed: HashSet<String>,
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let verifier = PinnedCertVerifier::new(Arc::new(RejectingVerifier), allowed);
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
}
