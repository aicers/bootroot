//! The endpoint's TLS material: what it presents, what it accepts, and
//! the seam a renewal swaps through.
//!
//! The socket answers *root on this host*; this layer answers *the
//! registrar*. It terminates mTLS on the accepted connection, so a
//! caller has to present a certificate, that certificate has to verify
//! against the deployment's own pinned CA material, and — one layer up,
//! in [`super::serve`] — its name has to be the registrar client
//! identity.
//!
//! # What is assembled here
//!
//! - **The server material.** The PEM at `[registrar_endpoint]
//!   server_cert_path` is the endpoint's leaf *followed by its issuer
//!   chain*, and the PEM at `server_key_path` is that leaf's key. Both
//!   are required when the endpoint is enabled, there is no fallback,
//!   and nothing here generates, self-signs or issues a certificate.
//! - **The self-check.** A leaf-only file loads cleanly, matches its
//!   key and carries the right name — and is then rejected by *every*
//!   correctly pinned caller, because [`RegistrarEndpointVerifier`]
//!   selects its anchors from the certificates the server actually
//!   presents. That failure would otherwise reach an operator only as a
//!   client-side error with no local symptom, so the loader runs the
//!   caller's own rule against its own material and refuses startup
//!   with the [`EndpointVerifyRejection`] that names the failure. No
//!   verification logic is written here: merged public code is run
//!   against the daemon's material.
//! - **The client verifier.** [`WebPkiClientVerifier`] over the pinned
//!   subset of `trust.ca_bundle_path` — the certificates whose DER
//!   SHA-256 appears in `trust.trusted_ca_sha256`, the same restriction
//!   the outbound path applies. It is never built with
//!   `allow_unauthenticated()`: a caller presenting no certificate
//!   fails the handshake rather than arriving unauthenticated.
//! - **The swap seam.** A complete [`ServerConfig`] is built before
//!   publication and exchanged by [`super::ActivatedEndpoint`] only
//!   after every live file write succeeds. This replaces both the
//!   presented key and the incoming client verifier for the next
//!   handshake without disturbing an established connection.
//!
//! # Where a refusal is decided
//!
//! [`build_server_config`] is a function over its inputs. It opens no
//! socket, touches no descriptor and reads no process environment, so
//! every startup refusal it can produce is reachable from a test under
//! `tempfile::tempdir()` rather than only from a daemon.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, PoisonError, RwLock};

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::{ClientHello, ResolvesServerCert, WebPkiClientVerifier};
use rustls::sign::CertifiedKey;

use crate::registrar::endpoint_pin::{EndpointVerifyRejection, RegistrarEndpointVerifier};
use crate::registrar::{RegistrarIdentityError, recognize_registrar_endpoint_name, single_dns_san};
use crate::tls;

/// How the `[registrar_endpoint]` server-certificate key is spelled in a
/// diagnostic, exactly as an operator would find it in `agent.toml`.
pub(crate) const SERVER_CERT_SETTING: &str = "[registrar_endpoint] server_cert_path";

/// How the `[registrar_endpoint]` private-key key is spelled in a
/// diagnostic.
pub(crate) const SERVER_KEY_SETTING: &str = "[registrar_endpoint] server_key_path";

/// How the `[registrar_endpoint]` client-certificate key is spelled in a
/// diagnostic.
pub(crate) const CLIENT_CERT_SETTING: &str = "[registrar_endpoint] client_cert_path";

/// How the trust bundle setting is spelled in a diagnostic.
pub(crate) const CA_BUNDLE_SETTING: &str = "trust.ca_bundle_path";

/// How the anchor pin list is spelled in a diagnostic.
pub(crate) const TRUSTED_CA_SETTING: &str = "trust.trusted_ca_sha256";

/// Why the endpoint's TLS configuration could not be built.
///
/// Every variant is a startup refusal, and every one of them names the
/// setting at fault. The variants that have a configured value name the
/// path as well; the ones for an absent setting have no path to report
/// and say instead that the setting is required.
///
/// None of them falls back to anything: there is no self-signed
/// certificate, no ordinary service leaf and no issuance path here.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EndpointTlsError {
    /// A setting the enabled endpoint requires has no value.
    #[error("{setting} is required when the registrar endpoint is enabled")]
    MissingSetting {
        /// The setting, spelled as it appears in `agent.toml`.
        setting: &'static str,
    },
    /// The configured path does not exist.
    #[error("{setting} at {} does not exist", .path.display())]
    MissingFile {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
    },
    /// The configured path exists but could not be read.
    #[error("{setting} at {} could not be read", .path.display())]
    Unreadable {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// The file was read but is not the PEM it has to be.
    #[error("{setting} at {} is not a usable PEM file", .path.display())]
    Unparsable {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
    },
    /// The certificate PEM holds no certificate at all.
    #[error("{setting} at {} holds no certificate", .path.display())]
    NoCertificate {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
    },
    /// The key PEM holds no private key at all.
    #[error("{setting} at {} holds no private key", .path.display())]
    NoPrivateKey {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
    },
    /// The private key parsed but is of a type this build cannot sign
    /// with.
    #[error("{setting} at {} is not a supported private key type", .path.display())]
    UnsupportedKey {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
    },
    /// The private key is not the key of the leaf certificate.
    #[error(
        "{setting} at {} is not the private key of the leaf certificate in {}",
        .path.display(),
        .certificate_path.display()
    )]
    KeyMismatch {
        /// The setting at fault — always the key's, because the leaf is
        /// what the key is held against.
        setting: &'static str,
        /// The key path.
        path: PathBuf,
        /// The certificate path the key was held against.
        certificate_path: PathBuf,
    },
    /// The leaf's single DNS SAN is not an endpoint server identity in
    /// the configured domain.
    #[error(
        "{setting} at {}: the leaf certificate is not a registrar endpoint identity in the \
         configured domain: {source}",
        .path.display()
    )]
    NotEndpointIdentity {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
        /// Which rule the name broke.
        #[source]
        source: RegistrarIdentityError,
    },
    /// The leaf's SAN is an endpoint identity but not a name a verifier
    /// can be built over.
    #[error(
        "{setting} at {}: the leaf certificate's subject alternative name {name} is not a \
         usable DNS name",
        .path.display()
    )]
    UnusableEndpointName {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
        /// The name that was read off the leaf.
        name: String,
    },
    /// The loaded material is not material a correctly pinned caller
    /// would accept — the case a bare leaf produces.
    #[error(
        "{setting} at {}: the loaded material is not what a pinned caller accepts, so every \
         correctly configured caller would fail this handshake: {source}. The file must hold \
         the endpoint leaf followed by its issuer chain, up to a certificate pinned in \
         {TRUSTED_CA_SETTING}",
        .path.display()
    )]
    SelfCheck {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
        /// The rejection a caller's own verifier produced.
        #[source]
        source: EndpointVerifyRejection,
    },
    /// The bundle parsed, but no certificate in it is pinned.
    #[error(
        "{setting} at {} holds no certificate whose SHA-256 appears in {TRUSTED_CA_SETTING}, so \
         no client certificate could ever verify",
        .path.display()
    )]
    NoPinnedAnchor {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
    },
    /// The pinned subset could not be turned into a client verifier.
    #[error(
        "the client certificate verifier could not be built from the pinned subset of {setting} \
         at {}: {detail}",
        .path.display()
    )]
    ClientVerifier {
        /// The setting at fault.
        setting: &'static str,
        /// The path it was configured with.
        path: PathBuf,
        /// What the verifier builder reported.
        detail: String,
    },
    /// The registrar client leaf would not authenticate to the endpoint.
    #[error("{setting} at {} is not a valid registrar client certificate: {detail}", .path.display())]
    ClientCertificate {
        /// The setting at fault.
        setting: &'static str,
        /// The staged client certificate path.
        path: PathBuf,
        /// What the verifier reported.
        detail: String,
    },
}

/// The endpoint's server-certificate resolver.
///
/// The `RwLock` is taken and released inside the synchronous `resolve`
/// and `swap`, so no guard is ever held across an `.await`. A poisoned
/// lock recovers the guard instead of panicking: a panic somewhere else
/// in the process must not take the endpoint's handshakes down with it,
/// and the value behind the lock is one `Arc` replaced wholesale, so
/// there is no half-written state to inherit.
pub(crate) struct EndpointCertResolver {
    certified_key: RwLock<Arc<CertifiedKey>>,
}

impl EndpointCertResolver {
    fn new(certified_key: CertifiedKey) -> Self {
        Self {
            certified_key: RwLock::new(Arc::new(certified_key)),
        }
    }

    /// Replaces the certificate and key presented from the next
    /// handshake onwards, with no restart and without disturbing a
    /// connection already established.
    // Kept for endpoint unit tests. Production renewal replaces the
    // complete acceptor so that its client verifier changes too.
    #[allow(dead_code)]
    pub(crate) fn swap(&self, certified_key: CertifiedKey) {
        let mut guard = self
            .certified_key
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *guard = Arc::new(certified_key);
    }
}

impl fmt::Debug for EndpointCertResolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EndpointCertResolver").finish()
    }
}

impl ResolvesServerCert for EndpointCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let guard = self
            .certified_key
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        Some(Arc::clone(&guard))
    }
}

/// Loads the endpoint's server material, checks it against the rule a
/// caller applies, and assembles the mutually-authenticated
/// [`ServerConfig`] the accept loop hands connections to.
///
/// A function over its inputs and nothing else: no descriptor, no
/// socket, no process environment. The typed resolver is returned
/// alongside the configuration because `ServerConfig` keeps only an
/// `Arc<dyn ResolvesServerCert>`, from which there is no way back to
/// the concrete type the swap seam lives on.
///
/// # Errors
///
/// Returns the [`EndpointTlsError`] naming the first setting at fault:
/// an absent `server_cert_path`, `server_key_path`, `ca_bundle_path` or
/// pin list; material that is missing, unreadable, unparseable,
/// key-mismatched or SAN-mismatched; material a correctly pinned caller
/// would reject; or a bundle in which nothing is pinned.
pub(crate) fn build_server_config(
    server_cert_path: Option<&Path>,
    server_key_path: Option<&Path>,
    ca_bundle_path: Option<&Path>,
    pins: &[String],
    domain: &str,
) -> Result<(Arc<ServerConfig>, Arc<EndpointCertResolver>), EndpointTlsError> {
    tls::install_crypto_provider();

    let cert_path = server_cert_path.ok_or(EndpointTlsError::MissingSetting {
        setting: SERVER_CERT_SETTING,
    })?;
    let key_path = server_key_path.ok_or(EndpointTlsError::MissingSetting {
        setting: SERVER_KEY_SETTING,
    })?;

    let certified_key = load_certified_key(cert_path, key_path)?;
    let expected_name = endpoint_san(&certified_key, cert_path, domain)?;

    let bundle_path = ca_bundle_path.ok_or(EndpointTlsError::MissingSetting {
        setting: CA_BUNDLE_SETTING,
    })?;
    if pins.is_empty() {
        return Err(EndpointTlsError::MissingSetting {
            setting: TRUSTED_CA_SETTING,
        });
    }
    let pin_set: HashSet<String> = pins.iter().map(|pin| pin.to_ascii_lowercase()).collect();
    let anchors = pinned_bundle_anchors(bundle_path, &pin_set)?;

    self_check(&certified_key, cert_path, &expected_name, &pin_set)?;

    let roots =
        tls::certs_to_root_store(&anchors).map_err(|err| EndpointTlsError::ClientVerifier {
            setting: CA_BUNDLE_SETTING,
            path: bundle_path.to_path_buf(),
            detail: format!("{err:#}"),
        })?;
    // Never `.allow_unauthenticated()`: a connection presenting no
    // client certificate must fail the handshake, not arrive with no
    // identity for a later check to guess at.
    let client_verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|err| EndpointTlsError::ClientVerifier {
            setting: CA_BUNDLE_SETTING,
            path: bundle_path.to_path_buf(),
            detail: err.to_string(),
        })?;

    let resolver = Arc::new(EndpointCertResolver::new(certified_key));
    let config = ServerConfig::builder()
        .with_client_cert_verifier(client_verifier)
        .with_cert_resolver(Arc::clone(&resolver) as Arc<dyn ResolvesServerCert>);
    Ok((Arc::new(config), resolver))
}

/// Verifies staged registrar client material against the incoming mTLS rule.
///
/// This is the same pinned subset of the staged CA bundle that
/// [`build_server_config`] installs for incoming handshakes. Running it before
/// publication refuses an expired certificate or one without `clientAuth`,
/// rather than leaving the next registrar dial to discover it.
///
/// # Errors
///
/// Returns an error if no configured pin is present in the bundle, the pinned
/// subset cannot construct a verifier, or the client leaf is not currently
/// valid client-authentication material under that verifier.
pub(crate) fn validate_client_certificate(
    certified_key: &CertifiedKey,
    cert_path: &Path,
    bundle_path: &Path,
    pins: &[String],
) -> Result<(), EndpointTlsError> {
    tls::install_crypto_provider();

    if pins.is_empty() {
        return Err(EndpointTlsError::MissingSetting {
            setting: TRUSTED_CA_SETTING,
        });
    }
    let pin_set: HashSet<String> = pins.iter().map(|pin| pin.to_ascii_lowercase()).collect();
    let anchors = pinned_bundle_anchors(bundle_path, &pin_set)?;
    let roots =
        tls::certs_to_root_store(&anchors).map_err(|err| EndpointTlsError::ClientVerifier {
            setting: CA_BUNDLE_SETTING,
            path: bundle_path.to_path_buf(),
            detail: format!("{err:#}"),
        })?;
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|err| EndpointTlsError::ClientVerifier {
            setting: CA_BUNDLE_SETTING,
            path: bundle_path.to_path_buf(),
            detail: err.to_string(),
        })?;
    let leaf = leaf_of(certified_key, cert_path)?;
    verifier
        .verify_client_cert(
            leaf,
            certified_key.cert.get(1..).unwrap_or_default(),
            UnixTime::now(),
        )
        .map_err(|err| EndpointTlsError::ClientCertificate {
            setting: CLIENT_CERT_SETTING,
            path: cert_path.to_path_buf(),
            detail: err.to_string(),
        })?;
    Ok(())
}

/// Reads the loaded leaf's single DNS SAN and holds it to the endpoint
/// server name rule in the configured domain.
///
/// The daemon holds no configured instance or host label — only the
/// domain — so this is the shape rule and not a comparison against a
/// composed name.
fn endpoint_san(
    certified_key: &CertifiedKey,
    cert_path: &Path,
    domain: &str,
) -> Result<String, EndpointTlsError> {
    let leaf = leaf_of(certified_key, cert_path)?;
    let name =
        single_dns_san(leaf.as_ref()).map_err(|source| EndpointTlsError::NotEndpointIdentity {
            setting: SERVER_CERT_SETTING,
            path: cert_path.to_path_buf(),
            source: source.into(),
        })?;
    recognize_registrar_endpoint_name(&name, domain).map_err(|source| {
        EndpointTlsError::NotEndpointIdentity {
            setting: SERVER_CERT_SETTING,
            path: cert_path.to_path_buf(),
            source,
        }
    })?;
    Ok(name)
}

/// Runs the caller's own verifier over the daemon's own material.
///
/// This is the check that turns "every pinned caller rejects this
/// endpoint" into a startup refusal an operator can read. It adds no
/// verification rule: it constructs the merged
/// [`RegistrarEndpointVerifier`] from the deployment's configured pins
/// and the leaf's own name, and calls it on the loaded chain.
fn self_check(
    certified_key: &CertifiedKey,
    cert_path: &Path,
    expected_name: &str,
    pins: &HashSet<String>,
) -> Result<(), EndpointTlsError> {
    let leaf = leaf_of(certified_key, cert_path)?;
    let intermediates = certified_key.cert.get(1..).unwrap_or_default();
    let verifier = RegistrarEndpointVerifier::new(pins.clone(), expected_name).map_err(|_| {
        EndpointTlsError::UnusableEndpointName {
            setting: SERVER_CERT_SETTING,
            path: cert_path.to_path_buf(),
            name: expected_name.to_string(),
        }
    })?;
    verifier
        .verify(leaf, intermediates, UnixTime::now())
        .map_err(|source| EndpointTlsError::SelfCheck {
            setting: SERVER_CERT_SETTING,
            path: cert_path.to_path_buf(),
            source,
        })
}

fn leaf_of<'a>(
    certified_key: &'a CertifiedKey,
    cert_path: &Path,
) -> Result<&'a CertificateDer<'static>, EndpointTlsError> {
    certified_key
        .cert
        .first()
        .ok_or_else(|| EndpointTlsError::NoCertificate {
            setting: SERVER_CERT_SETTING,
            path: cert_path.to_path_buf(),
        })
}

/// Reads the configured CA bundle and keeps only the certificates whose
/// DER SHA-256 is pinned.
///
/// Restricting to the pinned subset rather than trusting the whole file
/// mirrors what the outbound path already does, and stops a bundle that
/// gained a certificate from silently widening who may connect. An empty
/// result is a refusal: an empty root store cannot back a
/// [`WebPkiClientVerifier`], and the outbound path's direct-pin fallback
/// has no meaning for client authentication.
fn pinned_bundle_anchors(
    bundle_path: &Path,
    pins: &HashSet<String>,
) -> Result<Vec<CertificateDer<'static>>, EndpointTlsError> {
    let contents = read_file(bundle_path, CA_BUNDLE_SETTING)?;
    let certs =
        tls::parse_pem_to_cert_list(&contents).map_err(|_| EndpointTlsError::Unparsable {
            setting: CA_BUNDLE_SETTING,
            path: bundle_path.to_path_buf(),
        })?;
    let anchors: Vec<CertificateDer<'static>> = certs
        .into_iter()
        .filter(|cert| pins.contains(&tls::sha256_hex(cert.as_ref())))
        .collect();
    if anchors.is_empty() {
        return Err(EndpointTlsError::NoPinnedAnchor {
            setting: CA_BUNDLE_SETTING,
            path: bundle_path.to_path_buf(),
        });
    }
    Ok(anchors)
}

/// Loads the leaf, its issuer chain and its private key, and proves the
/// two are a pair.
///
/// Mirrors the HTTP-01 responder's loader, which lives in a binary crate
/// and is not importable from the library. The proof is a signature:
/// the loaded key signs a fixed message and the leaf's public key
/// verifies it, so a key that merely parses alongside an unrelated
/// certificate is refused here rather than at the first handshake.
pub(crate) fn load_certified_key(
    cert_path: &Path,
    key_path: &Path,
) -> Result<CertifiedKey, EndpointTlsError> {
    let cert_bytes = read_file(cert_path, SERVER_CERT_SETTING)?;
    let key_bytes = read_file(key_path, SERVER_KEY_SETTING)?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_bytes.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| EndpointTlsError::Unparsable {
                setting: SERVER_CERT_SETTING,
                path: cert_path.to_path_buf(),
            })?;
    if certs.is_empty() {
        return Err(EndpointTlsError::NoCertificate {
            setting: SERVER_CERT_SETTING,
            path: cert_path.to_path_buf(),
        });
    }

    // The error deliberately quotes none of the bytes it failed on:
    // this input is key material, and a parse failure that named it
    // would put it in a log.
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_bytes.as_slice()))
        .map_err(|_| EndpointTlsError::Unparsable {
            setting: SERVER_KEY_SETTING,
            path: key_path.to_path_buf(),
        })?
        .ok_or_else(|| EndpointTlsError::NoPrivateKey {
            setting: SERVER_KEY_SETTING,
            path: key_path.to_path_buf(),
        })?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key).map_err(|_| {
        EndpointTlsError::UnsupportedKey {
            setting: SERVER_KEY_SETTING,
            path: key_path.to_path_buf(),
        }
    })?;

    let leaf = certs
        .first()
        .ok_or_else(|| EndpointTlsError::NoCertificate {
            setting: SERVER_CERT_SETTING,
            path: cert_path.to_path_buf(),
        })?;
    if !tls::cert_key_matches(leaf, signing_key.as_ref()) {
        return Err(EndpointTlsError::KeyMismatch {
            setting: SERVER_KEY_SETTING,
            path: key_path.to_path_buf(),
            certificate_path: cert_path.to_path_buf(),
        });
    }

    Ok(CertifiedKey::new(certs, signing_key))
}

/// Reads a configured file, separating "not there" from "there and
/// unreadable" so an operator is not sent looking for a permission
/// problem that is really a typo in a path.
fn read_file(path: &Path, setting: &'static str) -> Result<Vec<u8>, EndpointTlsError> {
    std::fs::read(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            EndpointTlsError::MissingFile {
                setting,
                path: path.to_path_buf(),
            }
        } else {
            EndpointTlsError::Unreadable {
                setting,
                path: path.to_path_buf(),
                source,
            }
        }
    })
}
