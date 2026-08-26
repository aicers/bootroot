//! Certificate material and log capture shared by every test under
//! `endpoint`.
//!
//! Both halves live here in exactly one copy, and that is the point. A
//! second `rcgen` CA builder would let one module's tests keep passing
//! against material the other module's tests no longer produce, and a
//! second capturing subscriber would do the same for the events an
//! assertion is written against. Nothing here is compiled into a
//! shipped binary: the module is `#[cfg(test)]` and so is every use of
//! it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, KeyPair, KeyUsagePurpose,
    SanType, date_time_ymd,
};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tempfile::TempDir;
use tracing::field::{Field, Visit};
use tracing_subscriber::layer::{Context, SubscriberExt as _};

use super::client;
use super::tls::{EndpointCertResolver, EndpointTlsError, build_server_config};
use crate::registrar::endpoint_pin::{
    REGISTRAR_ENDPOINT_ANCHORS_FILE, build_endpoint_client_config,
};
use crate::registrar::{registrar_client_identity, registrar_endpoint_identity};

// ---------------------------------------------------------------------
// Captured logging, so a refusal's diagnostic fields are assertable
// ---------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(super) struct CapturedEvent {
    pub(super) message: String,
    pub(super) fields: BTreeMap<String, String>,
}

impl CapturedEvent {
    pub(super) fn field(&self, name: &str) -> &str {
        self.fields
            .get(name)
            .map_or("", std::string::String::as_str)
    }
}

#[derive(Clone, Default)]
pub(super) struct CapturedLogs(Arc<StdMutex<Vec<CapturedEvent>>>);

impl CapturedLogs {
    pub(super) fn events(&self) -> Vec<CapturedEvent> {
        self.0
            .lock()
            .expect("the capture mutex is only held to push and read")
            .clone()
    }

    /// Every refusal event captured so far.
    pub(super) fn refusals(&self) -> Vec<CapturedEvent> {
        self.events()
            .into_iter()
            .filter(|event| {
                event
                    .message
                    .starts_with("Registrar endpoint refused a connection")
            })
            .collect()
    }

    /// The one refusal event, which every refusal path emits exactly
    /// once.
    pub(super) fn refusal(&self) -> CapturedEvent {
        let mut matching = self.refusals();
        assert_eq!(
            matching.len(),
            1,
            "expected exactly one refusal event, saw {matching:?}"
        );
        matching.remove(0)
    }
}

struct FieldCollector(BTreeMap<String, String>);

impl Visit for FieldCollector {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_string(), value.to_string());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), format!("{value:?}"));
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CapturedLogs {
    fn on_event(&self, event: &tracing::Event<'_>, _context: Context<'_, S>) {
        let mut collector = FieldCollector(BTreeMap::new());
        event.record(&mut collector);
        let message = collector
            .0
            .remove("message")
            .unwrap_or_default()
            .trim_matches('"')
            .to_string();
        self.0
            .lock()
            .expect("the capture mutex is only held to push and read")
            .push(CapturedEvent {
                message,
                fields: collector.0,
            });
    }
}

/// Installs a capturing subscriber for the current thread.
///
/// Every test that uses it runs on a current-thread runtime, so the
/// whole future stays on the thread the guard was taken on.
///
/// The interest cache is rebuilt afterwards, and that is load-bearing
/// rather than defensive. `tracing` caches each callsite's interest
/// globally, and a callsite first reached on a *parallel* test thread —
/// where the default subscriber is the no-op one — is cached as
/// `Interest::never()` and stays disabled for every thread, including
/// this one. Rebuilding recomputes it over the live subscribers, this
/// one now among them, so a capture cannot come back empty because some
/// other test happened to reach the same log line first.
pub(super) fn capture_logs() -> (CapturedLogs, tracing::subscriber::DefaultGuard) {
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::registry().with(logs.clone());
    let guard = tracing::subscriber::set_default(subscriber);
    tracing::callsite::rebuild_interest_cache();
    (logs, guard)
}
// ---------------------------------------------------------------------
// Certificate material: a whole deployment's PKI under a tempdir
// ---------------------------------------------------------------------

/// The deployment domain every test identity is composed under.
pub(super) const TEST_DOMAIN: &str = "example.internal";
/// The host label the registrar and the endpoint both run on.
pub(super) const TEST_HOST: &str = "h1";
/// The instance label every test identity carries.
pub(super) const TEST_INSTANCE: &str = "001";
/// A domain that is a bare string suffix of [`TEST_DOMAIN`] without
/// being a label-boundary suffix of it.
pub(super) const NEAR_MISS_DOMAIN: &str = "evil-example.internal";
/// Basename stem of the conforming server material.
pub(super) const SERVER_STEM: &str = "endpoint";
/// The name a client dials with. The endpoint verifier deliberately
/// ignores it — over `AF_UNIX` there is no meaningful name — so it is a
/// placeholder and never the pinned identity.
pub(super) const DIAL_NAME: &str = "localhost";

pub(super) type TestCa = CertifiedIssuer<'static, KeyPair>;

/// The endpoint server identity every test endpoint presents.
pub(super) fn endpoint_name() -> String {
    registrar_endpoint_identity(TEST_INSTANCE, TEST_HOST, TEST_DOMAIN)
}

/// The one client identity the endpoint accepts.
pub(super) fn registrar_client_name() -> String {
    registrar_client_identity(TEST_INSTANCE, TEST_HOST, TEST_DOMAIN)
}

pub(super) fn dns_san(name: &str) -> SanType {
    SanType::DnsName(name.to_string().try_into().expect("a valid DNS SAN"))
}

/// Self-signs a CA whose validity window is `(not_before, not_after)`.
pub(super) fn generate_ca(not_before: (i32, u8, u8), not_after: (i32, u8, u8)) -> TestCa {
    let key = KeyPair::generate().expect("generate key");
    let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
    params
        .distinguished_name
        .push(DnType::CommonName, "Bootroot Endpoint Test CA");
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

pub(super) fn valid_ca() -> TestCa {
    generate_ca((2020, 1, 1), (2099, 1, 1))
}

/// Issues a leaf carrying exactly `sans`, signed by `ca`.
///
/// The validity window is wide open because these handshakes run against
/// the real clock.
pub(super) fn issue_leaf(ca: &TestCa, sans: Vec<SanType>) -> (rcgen::Certificate, KeyPair) {
    let key = KeyPair::generate().expect("generate key");
    let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
    params.is_ca = rcgen::IsCa::NoCa;
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2099, 1, 1);
    params.subject_alt_names = sans;
    let certificate = params.signed_by(&key, ca).expect("issued leaf");
    (certificate, key)
}

pub(super) fn key_der(key: &KeyPair) -> PrivateKeyDer<'static> {
    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()))
}

/// Writes a leaf and its key as PEM at the given paths, optionally
/// following the leaf with its issuer, and returns the leaf's DER.
///
/// The one PEM writer for leaf material in this tree's endpoint tests:
/// [`Pki::server_material_from`] and the client's tests both go through
/// it, so material a test writes is material the other side reads back
/// the same way.
pub(super) fn write_leaf_material(
    issuer: &TestCa,
    sans: Vec<SanType>,
    certificate_path: &Path,
    key_path: &Path,
    with_chain: bool,
) -> Vec<u8> {
    let (certificate, key) = issue_leaf(issuer, sans);
    let mut pem = certificate.pem();
    if with_chain {
        pem.push_str(&issuer.pem());
    }
    std::fs::write(certificate_path, pem).expect("write the leaf chain");
    std::fs::write(key_path, key.serialize_pem()).expect("write the leaf key");
    certificate.der().to_vec()
}

/// A deployment's certificate material, written under
/// `tempfile::tempdir()`: one CA, the bundle file, the pin file, and
/// whatever leaves a test asks for.
///
/// Nothing here binds a path: every file is under the temporary
/// directory this value owns, and dropping it removes them.
pub(super) struct Pki {
    pub(super) dir: TempDir,
    pub(super) ca: TestCa,
    /// Every certificate written to the bundle file, as PEM, pinned or
    /// not.
    bundle: Vec<String>,
    /// The subset of the bundle named in `trust.trusted_ca_sha256`.
    pins: Vec<String>,
}

/// Issues a client leaf carrying `sans`, signed by `issuer`, and returns
/// the chain and key a `ClientConfig` authenticates with.
pub(super) fn client_material_from(
    issuer: &TestCa,
    sans: Vec<SanType>,
) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let (certificate, key) = issue_leaf(issuer, sans);
    (
        vec![
            CertificateDer::from(certificate.der().to_vec()),
            CertificateDer::from(issuer.der().to_vec()),
        ],
        key_der(&key),
    )
}

/// A caller pinning whatever `pin_file` names, authenticating with
/// `auth` or with nothing when it is `None`.
///
/// The authenticating arm composes nothing itself: it delegates to
/// [`client::build_client_config`], which is the one place in the tree
/// where the registrar caller's TLS configuration is built. The
/// unauthenticated arm keeps calling
/// [`build_endpoint_client_config`], the helper written for a caller
/// that presents no client certificate.
pub(super) fn client_config_pinning(
    pin_file: &Path,
    auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
) -> ClientConfig {
    match auth {
        Some((chain, key)) => client::build_client_config(pin_file, &endpoint_name(), chain, key)
            .expect("a pinned, authenticating client configuration"),
        None => build_endpoint_client_config(pin_file, &endpoint_name())
            .expect("a pinned client configuration"),
    }
}

impl Pki {
    /// The conforming deployment: one CA, in the bundle and pinned.
    pub(super) fn new() -> Self {
        Self::over(valid_ca())
    }

    pub(super) fn over(ca: TestCa) -> Self {
        let pin = crate::tls::sha256_hex(ca.der().as_ref());
        let pem = ca.pem();
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
            ca,
            bundle: vec![pem],
            pins: vec![pin],
        }
    }

    /// Adds a CA to the bundle file without pinning it, so a leaf it
    /// issued is in the operator's bundle and still not admitted.
    pub(super) fn add_unpinned(&mut self, ca: &TestCa) {
        self.bundle.push(ca.pem());
    }

    pub(super) fn pins(&self) -> Vec<String> {
        self.pins.clone()
    }

    pub(super) fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Writes the bundle file and returns its path.
    pub(super) fn ca_bundle_path(&self) -> PathBuf {
        let path = self.path("ca-bundle.pem");
        let mut pem = String::new();
        for certificate in &self.bundle {
            pem.push_str(certificate);
        }
        std::fs::write(&path, pem).expect("write the CA bundle");
        path
    }

    /// Writes the caller-side pin file and returns its path.
    pub(super) fn pin_file_path(&self) -> PathBuf {
        self.pin_file_over(&self.pins())
    }

    pub(super) fn pin_file_over(&self, pins: &[String]) -> PathBuf {
        let path = self.path(REGISTRAR_ENDPOINT_ANCHORS_FILE);
        let mut contents = String::new();
        for pin in pins {
            contents.push_str(pin);
            contents.push('\n');
        }
        std::fs::write(&path, contents).expect("write the pin file");
        path
    }

    /// Writes server material: the leaf carrying `sans`, optionally
    /// followed by its issuer, plus the leaf's key.
    pub(super) fn server_material_from(
        &self,
        issuer: &TestCa,
        stem: &str,
        sans: Vec<SanType>,
        with_chain: bool,
    ) -> (PathBuf, PathBuf) {
        let cert_path = self.path(&format!("{stem}.crt"));
        let key_path = self.path(&format!("{stem}.key"));
        write_leaf_material(issuer, sans, &cert_path, &key_path, with_chain);
        (cert_path, key_path)
    }

    /// The conforming server material: the endpoint identity, leaf plus
    /// issuer chain, issued by the pinned CA.
    pub(super) fn server_material(&self) -> (PathBuf, PathBuf) {
        self.server_material_from(&self.ca, SERVER_STEM, vec![dns_san(&endpoint_name())], true)
    }

    /// The registrar's own client material, from the pinned CA.
    pub(super) fn registrar_client_material(
        &self,
    ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        client_material_from(&self.ca, vec![dns_san(&registrar_client_name())])
    }

    /// Runs the production configuration builder over this deployment's
    /// material.
    pub(super) fn build(
        &self,
        cert_path: &Path,
        key_path: &Path,
    ) -> Result<(Arc<rustls::ServerConfig>, Arc<EndpointCertResolver>), EndpointTlsError> {
        build_server_config(
            Some(cert_path),
            Some(key_path),
            Some(&self.ca_bundle_path()),
            &self.pins(),
            TEST_DOMAIN,
        )
    }

    /// The configuration and resolver the conforming material produces.
    pub(super) fn conforming(&self) -> (Arc<rustls::ServerConfig>, Arc<EndpointCertResolver>) {
        let (cert_path, key_path) = self.server_material();
        self.build(&cert_path, &key_path)
            .expect("conforming material must build a configuration")
    }

    /// A caller that pins this deployment's anchor and authenticates
    /// with `auth`, or with nothing when it is `None`.
    pub(super) fn client_config(
        &self,
        auth: Option<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)>,
    ) -> ClientConfig {
        client_config_pinning(&self.pin_file_path(), auth)
    }

    /// The caller the endpoint is meant to serve.
    pub(super) fn registrar_client_config(&self) -> ClientConfig {
        self.client_config(Some(self.registrar_client_material()))
    }
}
