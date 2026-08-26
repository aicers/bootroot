//! Tests for the registrar surface's start-time issuance.
//!
//! Everything here runs against `tempfile::tempdir()`, a listener on
//! port 0 and a local mock server. Nothing reaches the network, and no
//! test mutates the process environment.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use tempfile::TempDir;
use wiremock::matchers::{method, path as path_matcher};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::*;
use crate::registrar::internal::{
    InternalAgentConfigParams, active_root_cert_path, render_internal_agent_config,
};
use crate::registrar::{
    RESERVED_SERVICE_NAME_PREFIX, is_reserved_service_name, recognize_registrar_client,
    recognize_registrar_endpoint,
};

const TEST_DOMAIN: &str = "corp.example.internal";
const TEST_HOST: &str = "bootroot-01";
const TEST_KV_MOUNT: &str = "bootroot-kv";
const TEST_EMAIL: &str = "ops@example.internal";

/// The values the *local* configuration carries, so a test can tell them
/// apart from the ones seeded into `OpenBao`.
const LOCAL_HMAC: &str = "local-agent-toml-hmac";
const LOCAL_EAB_KID: &str = "local-eab-kid";

/// The responder HMAC the *rendered internal config* carries. A third
/// distinct value, because that file is the nearest wrong answer: it
/// sits on disk beside the credential this path already loads and
/// carries both ACME keys as `bootroot init` wrote them.
const INTERNAL_CONFIG_HMAC: &str = "internal-config-hmac";

/// The values seeded into `OpenBao`, which are the ones an issuance must
/// actually use.
const OPENBAO_HMAC: &str = "openbao-responder-hmac";
const OPENBAO_EAB_KID: &str = "openbao-eab-kid";
const OPENBAO_EAB_HMAC: &str = "b3BlbmJhby1lYWItaG1hYw";

// ---------------------------------------------------------------------
// Certificate fixtures
// ---------------------------------------------------------------------

type Issuer = CertifiedIssuer<'static, KeyPair>;

/// A one-level test CA: a self-signed root that signs leaves directly.
struct TestCa {
    issuer: Issuer,
    root_pem: String,
    /// The validity window, in days from now, stamped on every leaf
    /// [`TestCa::sign_csr`] signs. `None` leaves rcgen's own window,
    /// which is in date.
    ///
    /// A CA whose leaves come back outside this host's window is what
    /// persistent host-to-CA clock skew looks like from the daemon's
    /// side, and is how the skew cases are reached without touching a
    /// clock.
    signing_window: Mutex<Option<(i64, i64)>>,
}

impl TestCa {
    fn new(common_name: &str) -> Self {
        let key = KeyPair::generate().expect("ca key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ];
        let issuer = CertifiedIssuer::self_signed(params, key).expect("self-signed CA");
        let root_pem = issuer.pem();
        Self {
            issuer,
            root_pem,
            signing_window: Mutex::new(None),
        }
    }

    /// Makes every later issuance come back inside `[not_before_days,
    /// not_after_days]`, measured in days from now.
    fn sign_inside(&self, not_before_days: i64, not_after_days: i64) {
        *self
            .signing_window
            .lock()
            .expect("the signing window is not poisoned") = Some((not_before_days, not_after_days));
    }

    /// Signs `params` and returns the leaf PEM and its key PEM.
    fn issue(&self, params: &CertificateParams) -> (String, String) {
        let key = KeyPair::generate().expect("leaf key");
        let leaf = params
            .clone()
            .signed_by(&key, &self.issuer)
            .expect("issued leaf");
        (leaf.pem(), key.serialize_pem())
    }

    /// Signs a CSR the way `issue_certificate` hands one to a CA.
    fn sign_csr(&self, csr_der: &[u8]) -> String {
        let der = rustls::pki_types::CertificateSigningRequestDer::from(csr_der.to_vec());
        let mut request = rcgen::CertificateSigningRequestParams::from_der(&der)
            .expect("parse CSR the way a CA does");
        if let Some((not_before_days, not_after_days)) = *self
            .signing_window
            .lock()
            .expect("the signing window is not poisoned")
        {
            let now = time::OffsetDateTime::now_utc();
            request.params.not_before = now + time::Duration::days(not_before_days);
            request.params.not_after = now + time::Duration::days(not_after_days);
        }
        request
            .signed_by(&self.issuer)
            .expect("issue certificate")
            .pem()
    }

    fn root_fingerprint(&self) -> String {
        crate::tls::sha256_hex(self.issuer.der())
    }
}

/// Leaf params carrying `name` as the single DNS SAN and CN, valid over
/// `[not_before, not_after]` measured in days from now.
fn leaf_params(name: &str, not_before_days: i64, not_after_days: i64) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    params.is_ca = IsCa::NoCa;
    params.distinguished_name.push(DnType::CommonName, name);
    params.subject_alt_names = vec![SanType::DnsName(
        name.to_string().try_into().expect("a valid DNS SAN"),
    )];
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now + time::Duration::days(not_before_days);
    params.not_after = now + time::Duration::days(not_after_days);
    params
}

/// Writes a usable pair at `cert`/`key` under `ca`, in date.
fn write_usable_pair(ca: &TestCa, name: &str, cert: &Path, key: &Path) {
    let (leaf_pem, key_pem) = ca.issue(&leaf_params(name, -1, 30));
    write_pair(cert, key, &leaf_pem, &key_pem);
}

fn write_pair(cert: &Path, key: &Path, cert_pem: &str, key_pem: &str) {
    if let Some(parent) = cert.parent() {
        std::fs::create_dir_all(parent).expect("create the certificate directory");
    }
    if let Some(parent) = key.parent() {
        std::fs::create_dir_all(parent).expect("create the key directory");
    }
    std::fs::write(cert, cert_pem).expect("write the certificate");
    std::fs::write(key, key_pem).expect("write the key");
}

// ---------------------------------------------------------------------
// Host fixture
// ---------------------------------------------------------------------

/// A provisioned endpoint-enabled host: a state file, a secrets
/// directory carrying the internal layout, and the four material paths.
struct Host {
    dir: TempDir,
    ca: Arc<TestCa>,
    settings: Settings,
}

impl Host {
    fn new() -> Self {
        Self::with_openbao_url("https://127.0.0.1:1")
    }

    fn with_openbao_url(openbao_url: &str) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let ca = Arc::new(TestCa::new("Bootroot Surface Test CA"));
        let secrets_dir = dir.path().join("secrets");
        let internal = InternalPaths::new(&secrets_dir);
        std::fs::create_dir_all(internal.dir()).expect("create the internal directory");

        // The active root the internal credential is compared against.
        let root_path = active_root_cert_path(&secrets_dir);
        std::fs::create_dir_all(root_path.parent().expect("certs directory"))
            .expect("create the certs directory");
        std::fs::write(&root_path, &ca.root_pem).expect("write the active root");

        // The rendered internal agent config, which the host label is
        // read out of.
        let rendered = render_internal_agent_config(
            &internal,
            &InternalAgentConfigParams {
                email: TEST_EMAIL,
                server: "https://127.0.0.1:9000/acme/acme/directory",
                domain: TEST_DOMAIN,
                hostname: TEST_HOST,
                responder_url: "http://127.0.0.1:8080",
                responder_hmac: &INTERNAL_CONFIG_HMAC.into(),
                eab_kid: None,
                eab_hmac: None,
                trusted_ca_sha256: &[ca.root_fingerprint()],
            },
        );
        std::fs::write(internal.agent_config(), rendered).expect("write the internal config");
        std::fs::write(internal.ca_bundle(), &ca.root_pem).expect("write the private bundle");

        let state_file = dir.path().join("state.json");
        std::fs::write(
            &state_file,
            serde_json::json!({
                "openbao_url": openbao_url,
                "kv_mount": TEST_KV_MOUNT,
                "secrets_dir": "secrets",
            })
            .to_string(),
        )
        .expect("write the state file");

        let bundle_path = dir.path().join("certs").join("ca-bundle.pem");
        std::fs::create_dir_all(bundle_path.parent().expect("certs directory"))
            .expect("create the bundle directory");
        std::fs::write(&bundle_path, &ca.root_pem).expect("write the bundle");

        let mut settings = base_settings();
        settings.trust.ca_bundle_path = Some(bundle_path);
        settings.trust.trusted_ca_sha256 = vec![ca.root_fingerprint()];
        settings.registrar.state_file = Some(state_file);
        settings.registrar_endpoint = RegistrarEndpointSettings {
            enabled: true,
            server_cert_path: Some(dir.path().join("certs").join("endpoint.crt")),
            server_key_path: Some(dir.path().join("certs").join("endpoint.key")),
            client_cert_path: Some(dir.path().join("certs").join("client.crt")),
            client_key_path: Some(dir.path().join("certs").join("client.key")),
        };
        Self { dir, ca, settings }
    }

    fn secrets_dir(&self) -> PathBuf {
        self.dir.path().join("secrets")
    }

    fn endpoint(&self) -> &RegistrarEndpointSettings {
        &self.settings.registrar_endpoint
    }

    fn server_pair(&self) -> (PathBuf, PathBuf) {
        (
            self.endpoint()
                .server_cert_path
                .clone()
                .expect("configured"),
            self.endpoint().server_key_path.clone().expect("configured"),
        )
    }

    fn client_pair(&self) -> (PathBuf, PathBuf) {
        (
            self.endpoint()
                .client_cert_path
                .clone()
                .expect("configured"),
            self.endpoint().client_key_path.clone().expect("configured"),
        )
    }

    fn server_name() -> String {
        SurfaceLeaf::EndpointServer.identity(TEST_HOST, TEST_DOMAIN)
    }

    fn client_name() -> String {
        SurfaceLeaf::RegistrarClient.identity(TEST_HOST, TEST_DOMAIN)
    }

    /// Completes the internal credential's six-file set, so
    /// `InternalCredential::load` succeeds and a failure is the
    /// `OpenBao` exchange rather than the material below it.
    ///
    /// The four files are written directly rather than through
    /// `publish_material`: the publication's staging, chown and rename
    /// path is that module's to test, and all this needs is a leaf and
    /// key the client-authenticated transport can be built from.
    fn provision_internal_credential(&self) {
        let internal = InternalPaths::new(&self.secrets_dir());
        let (leaf, key) = self.ca.issue(&leaf_params(
            "internal.bootroot-01.corp.example.internal",
            -1,
            30,
        ));
        std::fs::write(internal.key(), key).expect("write the internal key");
        std::fs::write(internal.chain(), format!("{leaf}{}", self.ca.root_pem))
            .expect("write the internal chain");
        std::fs::write(internal.acme_account(), "{\"account_key_pkcs8\":\"QUJD\"}")
            .expect("write the internal ACME account key");
        std::fs::write(
            internal.root_fingerprint(),
            format!("{}\n", self.ca.root_fingerprint()),
        )
        .expect("write the internal root fingerprint");
    }

    /// Writes usable material at both configured pairs.
    fn provision_both_pairs(&self) {
        let (cert, key) = self.server_pair();
        write_usable_pair(&self.ca, &Self::server_name(), &cert, &key);
        let (cert, key) = self.client_pair();
        write_usable_pair(&self.ca, &Self::client_name(), &cert, &key);
    }
}

fn base_settings() -> Settings {
    Settings {
        email: TEST_EMAIL.to_string(),
        server: "https://127.0.0.1:9000/acme/acme/directory".to_string(),
        domain: TEST_DOMAIN.to_string(),
        eab: Some(crate::config::Eab {
            kid: LOCAL_EAB_KID.to_string(),
            hmac: "bG9jYWwtZWFiLWhtYWM".into(),
        }),
        acme: crate::config::AcmeSettings {
            directory_fetch_attempts: 1,
            directory_fetch_base_delay_secs: 1,
            directory_fetch_max_delay_secs: 1,
            poll_attempts: 3,
            poll_interval_secs: 0,
            account_key_path: None,
            http_responder_url: "http://127.0.0.1:1".to_string(),
            http_responder_hmac: LOCAL_HMAC.into(),
            http_responder_timeout_secs: 5,
            http_responder_token_ttl_secs: 300,
        },
        retry: crate::config::RetrySettings {
            backoff_secs: vec![1],
        },
        trust: crate::config::TrustSettings::default(),
        scheduler: crate::config::SchedulerSettings {
            max_concurrent_issuances: 1,
        },
        profiles: Vec::new(),
        openbao: None,
        registrar_endpoint: RegistrarEndpointSettings::default(),
        registrar: crate::config::RegistrarSettings::default(),
    }
}

fn digest_of(path: &Path) -> String {
    crate::tls::sha256_hex(&std::fs::read(path).expect("read the file to digest"))
}

// ---------------------------------------------------------------------
// Names, shapes and the reserved namespace
// ---------------------------------------------------------------------

/// The instance label is the named constant for both leaves, at every
/// domain label count, and the total label count is derived from the
/// configured domain rather than fixed.
#[test]
fn both_names_are_composed_at_the_fixed_instance_label() {
    assert_eq!(REGISTRAR_SURFACE_INSTANCE, "001");
    for domain in ["internal", "example.internal", "corp.example.internal"] {
        let client = SurfaceLeaf::RegistrarClient.identity(TEST_HOST, domain);
        let server = SurfaceLeaf::EndpointServer.identity(TEST_HOST, domain);
        assert_eq!(
            client,
            registrar_client_identity(REGISTRAR_SURFACE_INSTANCE, TEST_HOST, domain)
        );
        assert_eq!(
            server,
            registrar_endpoint_identity(REGISTRAR_SURFACE_INSTANCE, TEST_HOST, domain)
        );
        for name in [&client, &server] {
            assert!(name.starts_with("001."), "{name}");
            assert_eq!(
                name.split('.').count(),
                3 + domain.split('.').count(),
                "the label count must be derived from the configured domain: {name}"
            );
        }
    }
}

/// The profile an issuance is built with composes exactly the reserved
/// name for its pair, so the SAN the CA is asked for and the SAN the
/// usability rule checks cannot drift apart.
#[test]
fn the_issuance_profile_composes_the_reserved_name_for_its_pair() {
    let host = Host::new();
    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("both pairs resolve");
    assert_eq!(pairs.len(), 2);
    for pair in &pairs {
        let issuance = issuance_settings(&host.settings, pair, TEST_HOST, &"unused".into());
        let profile = issuance.profiles.first().expect("one profile");
        assert_eq!(crate::config::profile_domain(&issuance, profile), pair.name);
        assert_eq!(profile.instance_id, REGISTRAR_SURFACE_INSTANCE);
        assert_eq!(profile.hostname, TEST_HOST);
        assert_eq!(profile.paths.cert, pair.cert_path);
        assert_eq!(profile.paths.key, pair.key_path);
    }
}

/// The client leaf selects the `clientAuth` shape and the server leaf
/// does not: the endpoint's own leaf is a server certificate and needs
/// no added extended key usage.
#[test]
fn only_the_client_leaf_selects_the_client_auth_csr_shape() {
    assert_eq!(
        SurfaceLeaf::RegistrarClient.csr_shape(),
        CsrShape::RegistrarClient
    );
    assert_eq!(SurfaceLeaf::EndpointServer.csr_shape(), CsrShape::Service);
    assert_eq!(CsrShape::default(), CsrShape::Service);
}

/// `clientAuth` is asserted on the CSR **params**, with no CA in the
/// loop. What the issued leaf ends up carrying is the CA template's
/// decision and is never asserted anywhere.
#[test]
fn the_client_shape_requests_client_auth_on_the_params() {
    let params = crate::acme::build_registrar_client_csr_params(
        REGISTRAR_SURFACE_INSTANCE,
        TEST_HOST,
        TEST_DOMAIN,
    )
    .expect("the client CSR params build");
    assert_eq!(
        params.extended_key_usages,
        vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth]
    );
    assert_eq!(params.subject_alt_names.len(), 1);
}

/// Neither name can be produced by `service add`: both fall under the
/// one reserved-prefix guard that command consults.
#[test]
fn neither_reserved_name_can_be_minted_through_service_add() {
    for label in [
        SurfaceLeaf::RegistrarClient.service_label(),
        SurfaceLeaf::EndpointServer.service_label(),
    ] {
        assert!(label.starts_with(RESERVED_SERVICE_NAME_PREFIX), "{label}");
        assert!(is_reserved_service_name(label), "{label}");
        assert!(
            is_reserved_service_name(&label.to_ascii_uppercase()),
            "{label}"
        );
    }
}

/// An issued client leaf is recognized as the registrar client identity
/// and parses back to the triple the daemon composed it from.
#[test]
fn an_issued_client_leaf_is_recognized_as_the_registrar_client() {
    let ca = TestCa::new("Recognition CA");
    let params = crate::acme::build_registrar_client_csr_params(
        REGISTRAR_SURFACE_INSTANCE,
        TEST_HOST,
        TEST_DOMAIN,
    )
    .expect("client CSR params");
    let key = KeyPair::generate().expect("subject key");
    let csr = params.serialize_request(&key).expect("serialize CSR");
    let leaf_pem = ca.sign_csr(csr.der());
    let der = pem_to_der(&leaf_pem);

    let identity =
        recognize_registrar_client(&der, TEST_DOMAIN).expect("the issued leaf is recognized");
    assert_eq!(identity.instance, REGISTRAR_SURFACE_INSTANCE);
    assert_eq!(identity.host, TEST_HOST);
    assert_eq!(identity.domain, TEST_DOMAIN);
}

/// The mirror for the server leaf, issued through the ordinary shape.
#[test]
fn an_issued_server_leaf_is_recognized_as_the_endpoint_identity() {
    let ca = TestCa::new("Recognition CA");
    let name = SurfaceLeaf::EndpointServer.identity(TEST_HOST, TEST_DOMAIN);
    let (leaf_pem, _key) = ca.issue(&leaf_params(&name, -1, 30));
    let der = pem_to_der(&leaf_pem);

    let identity =
        recognize_registrar_endpoint(&der, TEST_DOMAIN).expect("the issued leaf is recognized");
    assert_eq!(identity.instance, REGISTRAR_SURFACE_INSTANCE);
    assert_eq!(identity.host, TEST_HOST);
    assert_eq!(identity.domain, TEST_DOMAIN);
}

/// The endpoint permits the issued client identity at both operations
/// and at no other — read off the checked-in enumeration rather than a
/// list restated here, so a variant added later fails this test.
#[test]
#[cfg(target_os = "linux")]
fn the_issued_client_identity_is_permitted_at_exactly_mint_and_deregister() {
    use crate::registrar::endpoint::frame::Operation;

    let ca = TestCa::new("Authorization CA");
    let params = crate::acme::build_registrar_client_csr_params(
        REGISTRAR_SURFACE_INSTANCE,
        TEST_HOST,
        TEST_DOMAIN,
    )
    .expect("client CSR params");
    let key = KeyPair::generate().expect("subject key");
    let csr = params.serialize_request(&key).expect("serialize CSR");
    let der = pem_to_der(&ca.sign_csr(csr.der()));
    let identity = recognize_registrar_client(&der, TEST_DOMAIN).expect("recognized");

    // The endpoint's authorization *is* recognition: a caller whose leaf
    // is the registrar client identity reaches every operation the
    // checked-in enumeration carries, and no other caller reaches any.
    // So iterating that enumeration is what shows the permitted set is
    // exactly the two — and the exhaustive match below is what a third
    // variant would break.
    let permitted: Vec<Operation> = ["mint", "deregister", "revoke", "rotate", "list"]
        .into_iter()
        .filter_map(Operation::from_name)
        .collect();
    assert_eq!(permitted, vec![Operation::Mint, Operation::Deregister]);
    for operation in permitted {
        match operation {
            Operation::Mint | Operation::Deregister => {}
        }
        assert_eq!(Operation::from_name(operation.as_str()), Some(operation));
    }

    // And it is this identity that reaches them: a leaf under any other
    // service label is not the registrar client and reaches nothing.
    assert_eq!(identity.instance, REGISTRAR_SURFACE_INSTANCE);
    let (impostor, _) = ca.issue(&leaf_params(
        &format!("001.some-other.{TEST_HOST}.{TEST_DOMAIN}"),
        -1,
        30,
    ));
    assert!(recognize_registrar_client(&pem_to_der(&impostor), TEST_DOMAIN).is_err());
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("parse leaf PEM");
    parsed.contents
}

// ---------------------------------------------------------------------
// The eight unusable states, and the usable one
// ---------------------------------------------------------------------

/// Material satisfying every one of the eight conditions is usable, and
/// is what every negation below starts from.
#[tokio::test]
async fn material_satisfying_every_condition_is_usable() {
    let dir = TempDir::new().expect("tempdir");
    let ca = TestCa::new("Usability CA");
    let name = SurfaceLeaf::RegistrarClient.identity(TEST_HOST, TEST_DOMAIN);
    let cert = dir.path().join("leaf.pem");
    let key = dir.path().join("leaf.key");
    write_usable_pair(&ca, &name, &cert, &key);
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(&bundle, &ca.root_pem).expect("write bundle");

    assert_eq!(
        evaluate_pair(&cert, &key, &name, Some(&bundle)).await,
        PairUsability::Usable
    );
}

/// Every one of the eight conditions, negated one at a time, and the
/// state each negation is classified as.
#[tokio::test]
async fn each_of_the_eight_conditions_names_its_own_unusable_state() {
    let mut seen: HashSet<UnusableMaterial> = HashSet::new();
    for (label, prepare, expected) in eight_unusable_cases() {
        let dir = TempDir::new().expect("tempdir");
        let ca = TestCa::new("Usability CA");
        let name = SurfaceLeaf::RegistrarClient.identity(TEST_HOST, TEST_DOMAIN);
        let cert = dir.path().join("material").join("leaf.pem");
        let key = dir.path().join("material").join("leaf.key");
        std::fs::create_dir_all(cert.parent().expect("parent")).expect("create material dir");
        let bundle = dir.path().join("bundle.pem");
        std::fs::write(&bundle, &ca.root_pem).expect("write bundle");

        prepare(&ca, &name, &cert, &key);

        assert_eq!(
            evaluate_pair(&cert, &key, &name, Some(&bundle)).await,
            PairUsability::Unusable(expected),
            "{label} must be classified as {expected}"
        );
        assert!(seen.insert(expected), "{label} duplicated a state");
    }
    assert_eq!(
        seen.len(),
        8,
        "the enumeration is the eight negations and nothing else"
    );
}

/// One row per condition of the usability rule: the setup that negates
/// it, and the state that negation must be classified as.
///
/// Shared by the classification test above and by the test below that
/// every one of the eight actually drives an issuance, so the two cannot
/// come to disagree about what the eight are. A named type alias for the
/// row would move the shape away from the rows it describes, and the
/// eight cases are what has to stay readable.
#[allow(clippy::type_complexity)]
fn eight_unusable_cases() -> Vec<(
    &'static str,
    Box<dyn Fn(&TestCa, &str, &Path, &Path)>,
    UnusableMaterial,
)> {
    vec![
        (
            "absent",
            Box::new(|_ca, _name, _cert, _key| {}),
            UnusableMaterial::Absent,
        ),
        (
            "unreadable",
            // A directory at the certificate path reproduces a
            // non-NotFound read error portably, without depending on
            // chmod semantics that root in CI can bypass.
            Box::new(|ca, name, cert, key| {
                std::fs::create_dir_all(cert).expect("directory at the certificate path");
                let (_, key_pem) = ca.issue(&leaf_params(name, -1, 30));
                std::fs::write(key, key_pem).expect("write the key");
            }),
            UnusableMaterial::Unreadable,
        ),
        (
            "malformed",
            // What a renewal that lost power mid-write leaves.
            Box::new(|ca, name, cert, key| {
                let (leaf_pem, key_pem) = ca.issue(&leaf_params(name, -1, 30));
                let truncated = leaf_pem.get(..leaf_pem.len() / 2).unwrap_or_default();
                write_pair(cert, key, truncated, &key_pem);
            }),
            UnusableMaterial::Malformed,
        ),
        (
            "key-mismatched",
            // What a renewal that died between the two renames leaves.
            Box::new(|ca, name, cert, key| {
                let (leaf_pem, _) = ca.issue(&leaf_params(name, -1, 30));
                let (_, other_key) = ca.issue(&leaf_params(name, -1, 30));
                write_pair(cert, key, &leaf_pem, &other_key);
            }),
            UnusableMaterial::KeyMismatched,
        ),
        (
            "SAN-mismatched",
            Box::new(|ca, _name, cert, key| {
                let (leaf_pem, key_pem) = ca.issue(&leaf_params(
                    "001.some-other.bootroot-01.corp.example.internal",
                    -1,
                    30,
                ));
                write_pair(cert, key, &leaf_pem, &key_pem);
            }),
            UnusableMaterial::SanMismatched,
        ),
        (
            "not-yet-valid",
            // A host clock behind the CA's.
            Box::new(|ca, name, cert, key| {
                let (leaf_pem, key_pem) = ca.issue(&leaf_params(name, 5, 30));
                write_pair(cert, key, &leaf_pem, &key_pem);
            }),
            UnusableMaterial::NotYetValid,
        ),
        (
            "expired",
            // A daemon down through the leaf's not_after.
            Box::new(|ca, name, cert, key| {
                let (leaf_pem, key_pem) = ca.issue(&leaf_params(name, -30, -1));
                write_pair(cert, key, &leaf_pem, &key_pem);
            }),
            UnusableMaterial::Expired,
        ),
        (
            "chain-drifted",
            // A destructive trust-anchor rotation: an in-date, correctly
            // named leaf signed by a CA generation the bundle no longer
            // holds.
            Box::new(|_ca, name, cert, key| {
                let previous = TestCa::new("Previous Generation CA");
                let (leaf_pem, key_pem) = previous.issue(&leaf_params(name, -1, 30));
                write_pair(cert, key, &leaf_pem, &key_pem);
            }),
            UnusableMaterial::ChainDrifted,
        ),
    ]
}

/// Absence outranks unreadability: an unreadable certificate beside an
/// absent key is *absent*, because condition 1 is evaluated first.
#[tokio::test]
async fn an_absent_file_outranks_an_unreadable_one() {
    let dir = TempDir::new().expect("tempdir");
    let cert = dir.path().join("leaf.pem");
    let key = dir.path().join("leaf.key");
    std::fs::create_dir_all(&cert).expect("directory at the certificate path");

    assert_eq!(
        evaluate_pair(&cert, &key, "unused", None).await,
        PairUsability::Unusable(UnusableMaterial::Absent)
    );
}

/// A truncated leaf is *malformed* whether or not a bundle is
/// configured. Folded into the chain arm it would be reported as
/// key-mismatched or SAN-mismatched with `ca_bundle_path` unset — a
/// diagnostic naming the wrong cause, on exactly the material a crashed
/// renewal leaves behind.
#[tokio::test]
async fn a_malformed_leaf_is_malformed_with_and_without_a_configured_bundle() {
    let dir = TempDir::new().expect("tempdir");
    let ca = TestCa::new("Malformed CA");
    let name = SurfaceLeaf::RegistrarClient.identity(TEST_HOST, TEST_DOMAIN);
    let cert = dir.path().join("leaf.pem");
    let key = dir.path().join("leaf.key");
    let (leaf_pem, key_pem) = ca.issue(&leaf_params(&name, -1, 30));
    let truncated = leaf_pem.get(..leaf_pem.len() / 2).unwrap_or_default();
    write_pair(&cert, &key, truncated, &key_pem);
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(&bundle, &ca.root_pem).expect("write bundle");

    for configured in [Some(bundle.as_path()), None] {
        assert_eq!(
            evaluate_pair(&cert, &key, &name, configured).await,
            PairUsability::Unusable(UnusableMaterial::Malformed),
            "configured bundle: {configured:?}"
        );
    }
}

/// With `[trust].ca_bundle_path` unconfigured the chain condition does
/// not run at all, so a leaf signed by a CA no bundle would accept is
/// still usable and is not re-issued for want of an anchor set.
///
/// Exercised at unit level on purpose. A full-daemon start with an
/// enabled endpoint and no bundle configured cannot start, for reasons
/// the endpoint's loader owns and this issue does not.
#[tokio::test]
async fn the_chain_condition_does_not_run_with_no_bundle_configured() {
    let dir = TempDir::new().expect("tempdir");
    let orphan = TestCa::new("Nobody's CA");
    let name = SurfaceLeaf::EndpointServer.identity(TEST_HOST, TEST_DOMAIN);
    let cert = dir.path().join("leaf.pem");
    let key = dir.path().join("leaf.key");
    write_usable_pair(&orphan, &name, &cert, &key);

    assert_eq!(
        evaluate_pair(&cert, &key, &name, None).await,
        PairUsability::Usable
    );

    // The same material against a bundle that does not hold that CA is
    // chain-drifted, which is what shows the opt-out did the work.
    let other = TestCa::new("Deployment CA");
    let bundle = dir.path().join("bundle.pem");
    std::fs::write(&bundle, &other.root_pem).expect("write bundle");
    assert_eq!(
        evaluate_pair(&cert, &key, &name, Some(&bundle)).await,
        PairUsability::Unusable(UnusableMaterial::ChainDrifted)
    );
}

/// A missing or unreadable bundle is *detected* as chain drift, exactly
/// as the daemon's own renewal predicate treats it. What follows
/// detection differs by bundle case and is the issuance path's business,
/// not the evaluation's.
#[tokio::test]
async fn a_missing_or_unreadable_bundle_is_detected_as_chain_drift() {
    let dir = TempDir::new().expect("tempdir");
    let ca = TestCa::new("Bundle CA");
    let name = SurfaceLeaf::RegistrarClient.identity(TEST_HOST, TEST_DOMAIN);
    let cert = dir.path().join("leaf.pem");
    let key = dir.path().join("leaf.key");
    write_usable_pair(&ca, &name, &cert, &key);

    let missing = dir.path().join("not-there.pem");
    assert_eq!(
        evaluate_pair(&cert, &key, &name, Some(&missing)).await,
        PairUsability::Unusable(UnusableMaterial::ChainDrifted)
    );

    let unreadable = dir.path().join("bundle-dir");
    std::fs::create_dir_all(&unreadable).expect("directory at the bundle path");
    assert_eq!(
        evaluate_pair(&cert, &key, &name, Some(&unreadable)).await,
        PairUsability::Unusable(UnusableMaterial::ChainDrifted)
    );

    let unparseable = dir.path().join("garbage.pem");
    std::fs::write(&unparseable, b"not a certificate").expect("write garbage");
    assert_eq!(
        evaluate_pair(&cert, &key, &name, Some(&unparseable)).await,
        PairUsability::Unusable(UnusableMaterial::ChainDrifted)
    );
}

/// Every one of the eight makes the daemon *attempt* an issuance rather
/// than refuse: put the client pair into each state in turn and
/// `pending_pairs` comes back holding it, over a configured pair on a
/// provisioned host rather than over a classification in isolation.
///
/// None of the eight is a refusal on its own, and the usable server pair
/// beside it is never dragged along — which is the same run asserting
/// that one pair needing issuance is not a reason to re-issue the other.
#[tokio::test]
async fn every_unusable_state_drives_an_issuance() {
    for (label, prepare, expected) in eight_unusable_cases() {
        let host = Host::new();
        host.provision_both_pairs();
        let (cert, key) = host.client_pair();
        std::fs::remove_file(&cert).expect("clear the provisioned certificate");
        std::fs::remove_file(&key).expect("clear the provisioned key");
        prepare(&host.ca, &Host::client_name(), &cert, &key);

        let plan = resolve_surface_plan(&host.settings).expect("the plan resolves");
        let pending = pending_pairs(&plan, host.settings.trust.ca_bundle_path.as_deref()).await;
        let leaves: Vec<SurfaceLeaf> = pending.iter().map(|pair| pair.leaf).collect();
        assert_eq!(
            leaves,
            vec![SurfaceLeaf::RegistrarClient],
            "{label} ({expected}) must drive an issuance of the client pair and of nothing else"
        );
    }
}

// ---------------------------------------------------------------------
// The local ACME server and the local HTTP-01 responder
// ---------------------------------------------------------------------

/// What the mock servers observed, so a test can assert on values that
/// actually reached a wire rather than on what was passed in.
#[derive(Default)]
struct Observed {
    /// The decoded `newAccount` payloads, one per registration.
    account_payloads: Mutex<Vec<serde_json::Value>>,
    /// The `(timestamp, signature, token, key_authorization)` of every
    /// HTTP-01 registration the responder received.
    responder_requests: Mutex<Vec<ResponderRequest>>,
    /// Every CSR the CA was asked to sign, in order.
    csrs: Mutex<Vec<Vec<u8>>>,
}

struct ResponderRequest {
    timestamp: i64,
    signature: String,
    token: String,
    key_authorization: String,
    ttl_secs: u64,
}

/// A local ACME directory and the HTTP-01 responder beside it, both
/// bound on port 0.
struct AcmeFixture {
    _acme: MockServer,
    _responder: MockServer,
    directory_url: String,
    responder_url: String,
    observed: Arc<Observed>,
}

/// Answers the authorization: pending on the first fetch, so the
/// HTTP-01 challenge is published and the responder registration is
/// observed, and valid afterwards.
struct AuthzResponder {
    fetches: Mutex<u32>,
    challenge_url: String,
}

impl Respond for AuthzResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let mut fetches = self
            .fetches
            .lock()
            .expect("the fetch counter is not poisoned");
        *fetches += 1;
        let valid = *fetches > 1;
        ResponseTemplate::new(200)
            .insert_header("replay-nonce", "nonce")
            .set_body_json(serde_json::json!({
                "status": if valid { "valid" } else { "pending" },
                "identifier": { "type": "dns", "value": "placeholder" },
                "challenges": [{
                    "type": "http-01",
                    "url": self.challenge_url,
                    "token": "surface-test-token",
                    "status": if valid { "valid" } else { "pending" },
                    "error": serde_json::Value::Null,
                }],
            }))
    }
}

/// Records the CSR the order was finalized with.
struct FinalizeResponder {
    observed: Arc<Observed>,
    certificate_url: String,
}

impl Respond for FinalizeResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let Some(csr) = decode_jws_field(&request.body, "csr") else {
            return ResponseTemplate::new(400);
        };
        self.observed
            .csrs
            .lock()
            .expect("the CSR log is not poisoned")
            .push(csr);
        ResponseTemplate::new(200)
            .insert_header("replay-nonce", "nonce")
            .set_body_json(serde_json::json!({
                "status": "valid",
                "finalize": self.certificate_url,
                "authorizations": Vec::<String>::new(),
                "certificate": self.certificate_url,
            }))
    }
}

/// Signs the CSR the finalize step recorded and answers with the leaf
/// followed by the issuing root, exactly as step-ca does.
struct CertificateResponder {
    ca: Arc<TestCa>,
    observed: Arc<Observed>,
}

impl Respond for CertificateResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let csrs = self.observed.csrs.lock().expect("not poisoned");
        let Some(csr) = csrs.last() else {
            return ResponseTemplate::new(404);
        };
        let leaf = self.ca.sign_csr(csr);
        ResponseTemplate::new(200)
            .insert_header("replay-nonce", "nonce")
            .set_body_string(format!("{leaf}{}", self.ca.root_pem))
    }
}

/// Records one HTTP-01 registration and accepts it.
struct ResponderAdmin {
    observed: Arc<Observed>,
}

impl Respond for ResponderAdmin {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap_or_default();
        self.observed
            .responder_requests
            .lock()
            .expect("not poisoned")
            .push(ResponderRequest {
                timestamp: header(crate::acme::http01_protocol::HEADER_TIMESTAMP)
                    .parse()
                    .unwrap_or_default(),
                signature: header(crate::acme::http01_protocol::HEADER_SIGNATURE),
                token: body
                    .get("token")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                key_authorization: body
                    .get("key_authorization")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                ttl_secs: body
                    .get("ttl_secs")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or_default(),
            });
        ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true }))
    }
}

/// Records the account registration payload and answers with a `kid`.
struct AccountResponder {
    observed: Arc<Observed>,
    account_url: String,
}

impl Respond for AccountResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        if let Some(payload) = jws_payload(&request.body) {
            self.observed
                .account_payloads
                .lock()
                .expect("not poisoned")
                .push(payload);
        }
        ResponseTemplate::new(201)
            .insert_header("replay-nonce", "nonce")
            .insert_header("Location", self.account_url.as_str())
            .set_body_json(serde_json::json!({ "status": "valid" }))
    }
}

/// Starts a local ACME directory that issues from `ca`, plus the
/// HTTP-01 responder the challenge is published through.
async fn start_acme(ca: Arc<TestCa>) -> AcmeFixture {
    let acme = MockServer::start().await;
    let responder = MockServer::start().await;
    let observed = Arc::new(Observed::default());
    let base = acme.uri();

    Mock::given(method("GET"))
        .and(path_matcher("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce": format!("{base}/new-nonce"),
            "newAccount": format!("{base}/new-account"),
            "newOrder": format!("{base}/new-order"),
        })))
        .mount(&acme)
        .await;

    Mock::given(method("HEAD"))
        .and(path_matcher("/new-nonce"))
        .respond_with(ResponseTemplate::new(200).insert_header("replay-nonce", "nonce"))
        .mount(&acme)
        .await;

    Mock::given(method("POST"))
        .and(path_matcher("/new-account"))
        .respond_with(AccountResponder {
            observed: Arc::clone(&observed),
            account_url: format!("{base}/account/1"),
        })
        .mount(&acme)
        .await;

    Mock::given(method("POST"))
        .and(path_matcher("/new-order"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("replay-nonce", "nonce")
                .insert_header("location", format!("{base}/order/1").as_str())
                .set_body_json(serde_json::json!({
                    "status": "pending",
                    "finalize": format!("{base}/finalize/1"),
                    "authorizations": [format!("{base}/authz/1")],
                    "certificate": serde_json::Value::Null,
                })),
        )
        .mount(&acme)
        .await;

    Mock::given(method("POST"))
        .and(path_matcher("/authz/1"))
        .respond_with(AuthzResponder {
            fetches: Mutex::new(0),
            challenge_url: format!("{base}/challenge/1"),
        })
        .mount(&acme)
        .await;

    Mock::given(method("POST"))
        .and(path_matcher("/challenge/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("replay-nonce", "nonce")
                .set_body_json(serde_json::json!({})),
        )
        .mount(&acme)
        .await;

    Mock::given(method("POST"))
        .and(path_matcher("/finalize/1"))
        .respond_with(FinalizeResponder {
            observed: Arc::clone(&observed),
            certificate_url: format!("{base}/cert/1"),
        })
        .mount(&acme)
        .await;

    Mock::given(method("POST"))
        .and(path_matcher("/cert/1"))
        .respond_with(CertificateResponder {
            ca,
            observed: Arc::clone(&observed),
        })
        .mount(&acme)
        .await;

    Mock::given(method("POST"))
        .and(path_matcher("/admin/http01"))
        .respond_with(ResponderAdmin {
            observed: Arc::clone(&observed),
        })
        .mount(&responder)
        .await;

    AcmeFixture {
        directory_url: format!("{base}/directory"),
        responder_url: responder.uri(),
        _acme: acme,
        _responder: responder,
        observed,
    }
}

/// Reads a base64url field out of the JWS payload of an ACME request.
fn decode_jws_field(body: &[u8], field: &str) -> Option<Vec<u8>> {
    let value = jws_payload(body)?;
    let encoded = value.get(field)?.as_str()?;
    base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        encoded.as_bytes(),
    )
    .ok()
}

/// Decodes the JWS payload of an ACME request into JSON.
fn jws_payload(body: &[u8]) -> Option<serde_json::Value> {
    let envelope: serde_json::Value = serde_json::from_slice(body).ok()?;
    let payload = envelope.get("payload")?.as_str()?;
    if payload.is_empty() {
        return Some(serde_json::Value::Null);
    }
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        payload.as_bytes(),
    )
    .ok()?;
    serde_json::from_slice(&decoded).ok()
}

/// The ACME inputs a test hands an issuance, standing in for the two
/// values `read_acme_inputs` would have read from `OpenBao`.
fn openbao_inputs() -> SurfaceAcmeInputs {
    SurfaceAcmeInputs {
        eab: Some(crate::eab::EabCredentials {
            kid: OPENBAO_EAB_KID.to_string(),
            hmac: OPENBAO_EAB_HMAC.into(),
        }),
        responder_hmac: OPENBAO_HMAC.into(),
    }
}

/// Parses the last CSR the mock CA was handed, the way a CA does.
///
/// Takes the guard, copies the bytes and drops it, so nothing holds a
/// `std::sync::Mutex` across the caller's next `.await`.
fn last_csr(acme: &AcmeFixture) -> rcgen::CertificateSigningRequestParams {
    let bytes = {
        let csrs = acme.observed.csrs.lock().expect("not poisoned");
        csrs.last().expect("one CSR reached the CA").clone()
    };
    let der = rustls::pki_types::CertificateSigningRequestDer::from(bytes);
    rcgen::CertificateSigningRequestParams::from_der(&der).expect("the CSR parses as a CA's")
}

/// Points `settings` at a local ACME directory and responder.
fn aim_at(settings: &mut Settings, acme: &AcmeFixture) {
    settings.server = acme.directory_url.clone();
    settings.acme.http_responder_url = acme.responder_url.clone();
}

/// Reads the leaf's single DNS SAN off the file at `path`.
fn san_at(path: &Path) -> String {
    let pem = std::fs::read_to_string(path).expect("read the published leaf");
    single_dns_san(&pem_to_der(&pem)).expect("the published leaf carries one DNS SAN")
}

// ---------------------------------------------------------------------
// Issuance
// ---------------------------------------------------------------------

/// The client leaf, minted end to end over the outbound ACME path:
/// every name invariant, recognition, the key/leaf pairing, the chain to
/// the deployment anchor, and the `clientAuth` request read back off the
/// CSR the CA was actually handed.
///
/// The issued leaf's extended key usages are deliberately **not**
/// asserted. Which EKUs a leaf comes back with is the issuing CA's
/// template's decision, and this repository pins no template.
#[tokio::test]
async fn the_client_pair_is_issued_with_every_name_invariant_and_the_client_auth_request() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);

    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
    let client = pairs
        .iter()
        .find(|pair| pair.leaf == SurfaceLeaf::RegistrarClient)
        .expect("the client pair");
    issue_surface_pair(&host.settings, client, TEST_HOST, &openbao_inputs(), false)
        .await
        .expect("the client pair is issued");

    let (cert_path, key_path) = host.client_pair();
    let name = Host::client_name();
    assert_eq!(san_at(&cert_path), name);

    let der = pem_to_der(&std::fs::read_to_string(&cert_path).expect("read leaf"));
    let identity = recognize_registrar_client(&der, TEST_DOMAIN).expect("recognized");
    assert_eq!(identity.instance, REGISTRAR_SURFACE_INSTANCE);
    assert_eq!(identity.host, TEST_HOST);

    // The CN mirrors the SAN, and there is no SAN of any other type.
    let (_, parsed) = x509_parser::parse_x509_certificate(&der).expect("parse");
    let common_name = parsed
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .expect("a common name");
    assert_eq!(common_name, name);

    // The CSR the CA was handed requested `clientAuth`, asserted on the
    // request rather than on the issued certificate.
    let request = last_csr(&acme);
    assert_eq!(
        request.params.extended_key_usages,
        vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth]
    );

    // The pair is usable by the rule the next start applies.
    assert_eq!(
        evaluate_pair(
            &cert_path,
            &key_path,
            &name,
            host.settings.trust.ca_bundle_path.as_deref(),
        )
        .await,
        PairUsability::Usable
    );
}

/// The server leaf takes the ordinary shape — no extended key usage
/// requested — and is still the endpoint identity the loader's own name
/// rule accepts, with a key that matches it.
#[tokio::test]
async fn the_server_pair_is_issued_in_the_ordinary_shape_and_is_the_endpoint_identity() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);

    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
    let server = pairs
        .iter()
        .find(|pair| pair.leaf == SurfaceLeaf::EndpointServer)
        .expect("the server pair");
    issue_surface_pair(&host.settings, server, TEST_HOST, &openbao_inputs(), false)
        .await
        .expect("the server pair is issued");

    let (cert_path, key_path) = host.server_pair();
    let name = Host::server_name();
    let der = pem_to_der(&std::fs::read_to_string(&cert_path).expect("read leaf"));
    recognize_registrar_endpoint(&der, TEST_DOMAIN).expect("recognized as the endpoint identity");

    let request = last_csr(&acme);
    assert!(
        request.params.extended_key_usages.is_empty(),
        "the server leaf must request no extended key usage: {:?}",
        request.params.extended_key_usages
    );

    // The loader's own key-match check, run over the published pair.
    assert_eq!(
        evaluate_pair(
            &cert_path,
            &key_path,
            &name,
            host.settings.trust.ca_bundle_path.as_deref()
        )
        .await,
        PairUsability::Usable
    );
}

/// Every issuance generates a fresh key pair, so two issuances of the
/// same name produce different keys while every name invariant still
/// holds. Nothing is pinned to a DER, an SPKI, a serial or a
/// fingerprint, because none of those survives a reissue.
#[tokio::test]
async fn two_issuances_of_the_same_name_produce_different_keys() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);
    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
    let client = pairs
        .iter()
        .find(|pair| pair.leaf == SurfaceLeaf::RegistrarClient)
        .expect("the client pair");
    let inputs = openbao_inputs();

    issue_surface_pair(&host.settings, client, TEST_HOST, &inputs, false)
        .await
        .expect("first issuance");
    let (cert_path, key_path) = host.client_pair();
    let first_key = std::fs::read_to_string(&key_path).expect("read key");
    let first_cert = std::fs::read_to_string(&cert_path).expect("read cert");

    issue_surface_pair(&host.settings, client, TEST_HOST, &inputs, false)
        .await
        .expect("second issuance");
    let second_key = std::fs::read_to_string(&key_path).expect("read key");
    let second_cert = std::fs::read_to_string(&cert_path).expect("read cert");

    assert_ne!(first_key, second_key, "each issuance must generate a key");
    assert_ne!(first_cert, second_cert);
    assert_eq!(san_at(&cert_path), Host::client_name());
}

/// The key is written 0600 and the certificate 0644, and both land at
/// their configured paths rather than in a generation directory or a
/// combined PEM.
#[tokio::test]
async fn the_published_key_is_never_group_or_world_readable() {
    use std::os::unix::fs::PermissionsExt as _;

    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);
    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
    let inputs = openbao_inputs();
    for pair in &pairs {
        issue_surface_pair(&host.settings, pair, TEST_HOST, &inputs, false)
            .await
            .expect("issued");
        let key_mode = std::fs::metadata(&pair.key_path)
            .expect("stat the key")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600, "{}", pair.key_path.display());
        assert!(pair.cert_path.is_file(), "{}", pair.cert_path.display());
    }
}

/// Issuance leaves the endpoint anchor pin file untouched. The pin is
/// over trust **anchors**, not over the leaf, and is written once by the
/// provisioning tool.
#[tokio::test]
async fn issuance_never_writes_the_endpoint_pin_file() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);

    let (client_cert, _) = host.client_pair();
    std::fs::create_dir_all(client_cert.parent().expect("parent")).expect("create dir");
    let pin_path =
        crate::registrar::endpoint_pin::anchor_pin_path_for_client_certificate(&client_cert);
    std::fs::write(&pin_path, format!("{}\n", host.ca.root_fingerprint())).expect("seed the pins");
    let before = digest_of(&pin_path);

    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
    let inputs = openbao_inputs();
    for pair in &pairs {
        issue_surface_pair(&host.settings, pair, TEST_HOST, &inputs, false)
            .await
            .expect("issued");
    }

    assert_eq!(before, digest_of(&pin_path), "the pin file must not move");
}

/// The EAB and the responder HMAC that reach the wire are the ones the
/// caller supplied — the values `read_acme_inputs` takes from `OpenBao`
/// — and not the ones the local configuration carries. Neither is
/// written back to disk.
#[tokio::test]
async fn the_supplied_acme_inputs_reach_the_wire_and_the_local_ones_do_not() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);
    // The local configuration deliberately carries different values.
    assert_eq!(host.settings.acme.http_responder_hmac.expose(), LOCAL_HMAC);
    assert_eq!(
        host.settings.eab.as_ref().expect("a local EAB").kid,
        LOCAL_EAB_KID
    );

    // The rendered internal config is the nearest wrong answer, and it
    // is on disk: it carries both ACME keys as `bootroot init` wrote
    // them. Hashed before the issuance so the substitution can be shown
    // to be in memory only.
    let internal_config = InternalPaths::new(&host.secrets_dir()).agent_config();
    let internal_config_before = digest_of(&internal_config);

    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
    let client = pairs
        .iter()
        .find(|pair| pair.leaf == SurfaceLeaf::RegistrarClient)
        .expect("the client pair");
    issue_surface_pair(&host.settings, client, TEST_HOST, &openbao_inputs(), false)
        .await
        .expect("issued");

    // Neither value was written back. The fast-poll loop upserts
    // `[acme] http_responder_hmac` on disk under the AppRole; this path
    // neither uses nor imitates that, so every rendered config it could
    // have reached for is byte-identical afterwards.
    assert_eq!(
        internal_config_before,
        digest_of(&internal_config),
        "the rendered internal config must not be rewritten by an issuance"
    );

    // The responder registration verifies under the OpenBao HMAC and
    // not under the local one.
    let requests = acme
        .observed
        .responder_requests
        .lock()
        .expect("not poisoned");
    let request = requests.first().expect("one responder registration");
    let openbao_signer = crate::acme::http01_protocol::Http01HmacSigner::new(OPENBAO_HMAC);
    assert!(
        openbao_signer.verify_request(
            &request.signature,
            request.timestamp,
            &request.token,
            &request.key_authorization,
            request.ttl_secs,
        ),
        "the registration must be signed with the OpenBao HMAC"
    );
    for (label, hmac) in [
        ("the local agent.toml", LOCAL_HMAC),
        ("the rendered internal config", INTERNAL_CONFIG_HMAC),
    ] {
        let signer = crate::acme::http01_protocol::Http01HmacSigner::new(hmac);
        assert!(
            !signer.verify_request(
                &request.signature,
                request.timestamp,
                &request.token,
                &request.key_authorization,
                request.ttl_secs,
            ),
            "{label} HMAC must not be what signed it"
        );
    }
    drop(requests);

    // The account registered with the OpenBao EAB.
    let payloads = acme.observed.account_payloads.lock().expect("not poisoned");
    let payload = payloads.first().expect("one account registration");
    let binding = payload
        .get("externalAccountBinding")
        .expect("the account registered with an EAB");
    let protected = binding
        .get("protected")
        .and_then(serde_json::Value::as_str)
        .expect("the EAB carries a protected header");
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        protected.as_bytes(),
    )
    .expect("the protected header decodes");
    let header: serde_json::Value = serde_json::from_slice(&decoded).expect("valid JSON");
    assert_eq!(
        header.get("kid").and_then(serde_json::Value::as_str),
        Some(OPENBAO_EAB_KID)
    );
}

/// The chain is verified and the bundle merged **before** the leaf is
/// published, so a CA bundle the merge refuses to overwrite fails the
/// issuance with nothing on disk and the bundle byte-identical.
///
/// Run with `insecure_mode`, which is the daemon's own `--insecure`
/// flag, so the outbound transport does not read the bundle and the
/// merge's own refusal is what is under test. The transport's separate,
/// pre-existing use of the same file is covered by
/// [`a_bundle_the_outbound_transport_cannot_read_fails_before_publication`].
#[tokio::test]
async fn an_unreadable_ca_bundle_fails_before_anything_is_published() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);

    // A directory at the bundle path is a non-NotFound read error on
    // every platform, without depending on chmod semantics that root in
    // CI can bypass.
    let bundle = host.dir.path().join("unreadable-bundle.pem");
    std::fs::create_dir_all(&bundle).expect("directory at the bundle path");
    host.settings.trust.ca_bundle_path = Some(bundle.clone());

    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
    let client = pairs
        .iter()
        .find(|pair| pair.leaf == SurfaceLeaf::RegistrarClient)
        .expect("the client pair");
    let error = issue_surface_pair(&host.settings, client, TEST_HOST, &openbao_inputs(), true)
        .await
        .expect_err("an unreadable bundle must fail the issuance");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("refusing to overwrite unreadable CA bundle"),
        "{rendered}"
    );
    assert!(
        rendered.contains(&bundle.display().to_string()),
        "{rendered}"
    );

    let (cert_path, key_path) = host.client_pair();
    assert!(!cert_path.exists(), "no leaf may be published");
    assert!(!key_path.exists(), "no key may be published");
    assert!(bundle.is_dir(), "the bundle must be left exactly as it was");
}

/// A missing bundle and an unparseable-but-readable one stay on the
/// repair path: the merge seeds against nothing, the pair is published,
/// and the bundle comes back holding the pinned anchor.
#[tokio::test]
async fn a_missing_or_unparseable_bundle_still_publishes() {
    for seed in [None, Some("not a certificate at all\n")] {
        let mut host = Host::new();
        let acme = start_acme(Arc::clone(&host.ca)).await;
        aim_at(&mut host.settings, &acme);
        let bundle = host.dir.path().join("bundle-under-test.pem");
        if let Some(contents) = seed {
            std::fs::write(&bundle, contents).expect("seed the bundle");
        }
        host.settings.trust.ca_bundle_path = Some(bundle.clone());

        let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
        let client = pairs
            .iter()
            .find(|pair| pair.leaf == SurfaceLeaf::RegistrarClient)
            .expect("the client pair");
        issue_surface_pair(&host.settings, client, TEST_HOST, &openbao_inputs(), true)
            .await
            .unwrap_or_else(|err| panic!("seed {seed:?} must still publish: {err:#}"));

        let (cert_path, _) = host.client_pair();
        assert_eq!(san_at(&cert_path), Host::client_name(), "seed {seed:?}");
        let merged = std::fs::read_to_string(&bundle).expect("read the merged bundle");
        assert!(
            merged.contains("BEGIN CERTIFICATE"),
            "seed {seed:?} must leave a populated bundle"
        );
    }
}

/// The outbound ACME transport is anchored to `[trust].ca_bundle_path`
/// too, and that is checked before the flow begins.
///
/// So on a host whose ACME directory is reached over TLS — every real
/// deployment — a bundle that is missing, unreadable or unparseable
/// fails the issuance there rather than at the merge. It is still a
/// failure **before publication**, naming the bundle, and it is
/// pre-existing behaviour of the shared outbound path rather than
/// anything issuance decides. Asserted so the boundary is recorded
/// rather than discovered.
#[tokio::test]
async fn a_bundle_the_outbound_transport_cannot_read_fails_before_publication() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);
    let bundle = host.dir.path().join("absent-bundle.pem");
    host.settings.trust.ca_bundle_path = Some(bundle.clone());

    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
    let client = pairs
        .iter()
        .find(|pair| pair.leaf == SurfaceLeaf::RegistrarClient)
        .expect("the client pair");
    let error = issue_surface_pair(&host.settings, client, TEST_HOST, &openbao_inputs(), false)
        .await
        .expect_err("the transport cannot be anchored to a bundle that is not there");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(&bundle.display().to_string()),
        "{rendered}"
    );

    let (cert_path, key_path) = host.client_pair();
    assert!(!cert_path.exists());
    assert!(!key_path.exists());
}

/// A filesystem condition preventing the replacement from being written
/// is a startup failure naming the path, not a repair.
#[tokio::test]
async fn a_write_that_cannot_land_is_a_failure_naming_the_path() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);

    let (cert_path, _) = host.client_pair();
    std::fs::create_dir_all(&cert_path).expect("a directory where the certificate must go");

    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
    let client = pairs
        .iter()
        .find(|pair| pair.leaf == SurfaceLeaf::RegistrarClient)
        .expect("the client pair");
    let error = issue_surface_pair(&host.settings, client, TEST_HOST, &openbao_inputs(), false)
        .await
        .expect_err("a certificate path that cannot be replaced must fail the start");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(&cert_path.display().to_string()),
        "{rendered}"
    );
    assert!(cert_path.is_dir(), "the obstruction must be left as it was");
}

/// An ACME flow that fails refuses with a diagnostic naming both
/// material paths, and publishes nothing — no self-signed leaf, no
/// borrowed one.
#[tokio::test]
async fn a_failed_acme_flow_refuses_and_names_the_material_paths() {
    let mut host = Host::new();
    // A directory URL nothing is listening on.
    host.settings.server = "http://127.0.0.1:1/directory".to_string();

    let pairs = surface_pairs(host.endpoint(), TEST_HOST, TEST_DOMAIN).expect("pairs resolve");
    let server = pairs
        .iter()
        .find(|pair| pair.leaf == SurfaceLeaf::EndpointServer)
        .expect("the server pair");
    let error = issue_surface_pair(&host.settings, server, TEST_HOST, &openbao_inputs(), false)
        .await
        .expect_err("an unreachable CA must refuse the start");
    let rendered = format!("{error:#}");
    let (cert_path, key_path) = host.server_pair();
    assert!(
        rendered.contains(&cert_path.display().to_string()),
        "{rendered}"
    );
    assert!(
        rendered.contains(&key_path.display().to_string()),
        "{rendered}"
    );
    assert!(rendered.contains(&Host::server_name()), "{rendered}");
    assert!(!cert_path.exists());
    assert!(!key_path.exists());
}

// ---------------------------------------------------------------------
// The orchestration: gating, leaving alone, and what is read when
// ---------------------------------------------------------------------

/// With the endpoint disabled nothing happens at all: no material path
/// is created, and nothing is asked of the CA or of `OpenBao`. The
/// fixture's state file and internal config are removed first, so a
/// path that read either would fail rather than pass quietly.
#[tokio::test]
async fn a_disabled_endpoint_issues_nothing_and_reads_nothing() {
    let host = Host::new();
    let mut settings = host.settings.clone();
    settings.registrar_endpoint.enabled = false;
    std::fs::remove_dir_all(host.secrets_dir()).expect("remove the secrets directory");
    std::fs::remove_file(
        settings
            .registrar
            .state_file
            .as_deref()
            .expect("a state file"),
    )
    .expect("remove the state file");
    // An unreachable CA and an unreachable OpenBao, so any request at
    // all would be a failure rather than a silent success.
    settings.server = "http://127.0.0.1:1/directory".to_string();

    ensure_registrar_surface_certificates(&settings, false)
        .await
        .expect("a disabled endpoint does nothing");

    let (cert_path, key_path) = host.server_pair();
    assert!(!cert_path.exists());
    assert!(!key_path.exists());
    let (cert_path, key_path) = host.client_pair();
    assert!(!cert_path.exists());
    assert!(!key_path.exists());
}

/// With both pairs usable the daemon starts having made no `OpenBao`
/// request at all — the state file points at a URL nothing is listening
/// on — and both pairs survive byte-identically.
#[tokio::test]
async fn both_pairs_usable_starts_with_openbao_unreachable_and_touches_nothing() {
    let host = Host::with_openbao_url("https://127.0.0.1:1");
    host.provision_both_pairs();
    let (server_cert, server_key) = host.server_pair();
    let (client_cert, client_key) = host.client_pair();
    let before = [
        digest_of(&server_cert),
        digest_of(&server_key),
        digest_of(&client_cert),
        digest_of(&client_key),
    ];

    let mut settings = host.settings.clone();
    // Any CA request would fail against this, so a started daemon is
    // proof that none was made.
    settings.server = "http://127.0.0.1:1/directory".to_string();

    ensure_registrar_surface_certificates(&settings, false)
        .await
        .expect("usable material starts with OpenBao down");

    let after = [
        digest_of(&server_cert),
        digest_of(&server_key),
        digest_of(&client_cert),
        digest_of(&client_key),
    ];
    assert_eq!(before, after, "usable material must not be re-issued");
}

/// The two pairs are judged independently: with one usable and the other
/// unusable, the unusable one is issued and the usable one is still
/// byte-identical afterwards.
#[tokio::test]
async fn one_usable_pair_is_left_alone_while_the_other_is_issued() {
    for issue_client in [true, false] {
        let mut host = Host::new();
        let acme = start_acme(Arc::clone(&host.ca)).await;
        aim_at(&mut host.settings, &acme);
        host.provision_both_pairs();

        let (untouched_cert, untouched_key, replaced_cert) = if issue_client {
            let (client_cert, client_key) = host.client_pair();
            // A daemon down through the client leaf's not_after.
            let (leaf, key) = host.ca.issue(&leaf_params(&Host::client_name(), -30, -1));
            write_pair(&client_cert, &client_key, &leaf, &key);
            let (server_cert, server_key) = host.server_pair();
            (server_cert, server_key, client_cert)
        } else {
            let (server_cert, server_key) = host.server_pair();
            let (leaf, key) = host.ca.issue(&leaf_params(&Host::server_name(), -30, -1));
            write_pair(&server_cert, &server_key, &leaf, &key);
            let (client_cert, client_key) = host.client_pair();
            (client_cert, client_key, server_cert)
        };
        let before = (digest_of(&untouched_cert), digest_of(&untouched_key));
        let expired_before = digest_of(&replaced_cert);

        let plan = resolve_surface_plan(&host.settings).expect("the plan resolves");
        let pending = pending_pairs(&plan, host.settings.trust.ca_bundle_path.as_deref()).await;
        assert_eq!(pending.len(), 1, "exactly one pair needs issuing");
        for pair in &pending {
            issue_surface_pair(&host.settings, pair, &plan.host, &openbao_inputs(), false)
                .await
                .expect("the unusable pair is issued");
        }

        assert_eq!(
            before,
            (digest_of(&untouched_cert), digest_of(&untouched_key)),
            "the usable pair must be byte-identical"
        );
        assert_ne!(
            expired_before,
            digest_of(&replaced_cert),
            "the unusable pair must be replaced"
        );
    }
}

/// An expired leaf drives an issuance rather than a refusal, on both
/// pairs, and the replacement is in window at the host's clock.
#[tokio::test]
async fn an_expired_leaf_on_either_pair_is_repaired_rather_than_refused() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);
    for (cert, key, name) in [
        (
            host.server_pair().0,
            host.server_pair().1,
            Host::server_name(),
        ),
        (
            host.client_pair().0,
            host.client_pair().1,
            Host::client_name(),
        ),
    ] {
        let (leaf, key_pem) = host.ca.issue(&leaf_params(&name, -30, -1));
        write_pair(&cert, &key, &leaf, &key_pem);
    }

    let plan = resolve_surface_plan(&host.settings).expect("the plan resolves");
    let pending = pending_pairs(&plan, host.settings.trust.ca_bundle_path.as_deref()).await;
    assert_eq!(pending.len(), 2, "both expired pairs need issuing");
    for pair in &pending {
        issue_surface_pair(&host.settings, pair, &plan.host, &openbao_inputs(), false)
            .await
            .expect("an expired pair is repaired by issuing");
        assert_eq!(
            evaluate_pair(
                &pair.cert_path,
                &pair.key_path,
                &pair.name,
                host.settings.trust.ca_bundle_path.as_deref()
            )
            .await,
            PairUsability::Usable
        );
    }
}

/// Persistent host-to-CA clock skew survives a successful issuance, in
/// **both** directions, and nothing on this path papers over it. The CA
/// answers with a leaf still outside this host's window; issuance
/// publishes it exactly as it came back, asks for it exactly once, and
/// leaves the refusal to the endpoint's own loader.
///
/// The two directions come from opposite skew: a host clock far enough
/// *behind* the CA leaves the replacement not yet valid, and one far
/// enough ahead — by more than a leaf's whole lifetime — leaves it
/// already expired. The second needs much more skew and is rarer, but a
/// dead RTC or a snapshot-restored VM produces it.
#[tokio::test]
async fn a_replacement_still_outside_its_window_is_published_once_and_not_retried() {
    for ((not_before_days, not_after_days), expected) in [
        ((3, 30), UnusableMaterial::NotYetValid),
        ((-30, -1), UnusableMaterial::Expired),
    ] {
        let mut host = Host::new();
        let acme = start_acme(Arc::clone(&host.ca)).await;
        aim_at(&mut host.settings, &acme);
        host.ca.sign_inside(not_before_days, not_after_days);

        let pending = run_issuance(&host).await;
        assert_eq!(pending.len(), 2, "a bare host needs both pairs issued");
        assert_eq!(
            acme.observed.csrs.lock().expect("not poisoned").len(),
            2,
            "one certificate request per pair: issuing once is the whole \
             attempt, with no retry loop around the window"
        );

        for pair in &pending {
            assert!(
                pair.cert_path.is_file() && pair.key_path.is_file(),
                "the replacement is published exactly as the CA minted it"
            );
            assert_eq!(
                evaluate_pair(
                    &pair.cert_path,
                    &pair.key_path,
                    &pair.name,
                    host.settings.trust.ca_bundle_path.as_deref(),
                )
                .await,
                PairUsability::Unusable(expected),
                "the skew reaches past issuance: no clock is corrected for {}",
                pair.name
            );
        }
    }
}

/// Where the skew leaves the **server** leaf outside its window, the
/// endpoint's own TLS loader refuses it and the daemon does not start.
/// The refusal is that loader's pre-existing one — issuance adds no
/// clock correction and no second verifier.
///
/// Linux-only, because the loader is compiled nowhere else.
#[tokio::test]
#[cfg(target_os = "linux")]
async fn the_loader_refuses_a_server_leaf_the_skew_left_outside_its_window() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);
    host.ca.sign_inside(-30, -1);

    assert_eq!(run_issuance(&host).await.len(), 2, "both pairs are issued");

    let endpoint = host.endpoint().clone();
    crate::registrar::endpoint::tls::build_server_config(
        endpoint.server_cert_path.as_deref(),
        endpoint.server_key_path.as_deref(),
        host.settings.trust.ca_bundle_path.as_deref(),
        &host.settings.trust.trusted_ca_sha256,
        &host.settings.domain,
    )
    .expect_err("the loader refuses a server leaf outside its window at this host's clock");
}

/// The same condition on the **client** pair alone does not block the
/// start: the endpoint's loader reads only the server pair, so a client
/// leaf the skew left outside its window is published, is still
/// unusable, and stops nothing.
///
/// Linux-only, for the same reason as above.
#[tokio::test]
#[cfg(target_os = "linux")]
async fn a_client_leaf_the_skew_left_outside_its_window_does_not_block_the_start() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);

    let endpoint = host.endpoint().clone();
    let load = || {
        crate::registrar::endpoint::tls::build_server_config(
            endpoint.server_cert_path.as_deref(),
            endpoint.server_key_path.as_deref(),
            host.settings.trust.ca_bundle_path.as_deref(),
            &host.settings.trust.trusted_ca_sha256,
            &host.settings.domain,
        )
    };

    // Both pairs in window first, so the server leaf under test is one
    // this same issuance published rather than a fixture's.
    assert_eq!(run_issuance(&host).await.len(), 2, "both pairs are issued");
    load().expect("in-window material is material the loader accepts");

    // Only the client pair is re-issued, and only it comes back skewed.
    let (client_cert, client_key) = host.client_pair();
    std::fs::remove_file(&client_cert).expect("remove the client leaf");
    std::fs::remove_file(&client_key).expect("remove the client key");
    host.ca.sign_inside(-30, -1);

    let pending = run_issuance(&host).await;
    assert_eq!(
        pending.iter().map(|pair| pair.leaf).collect::<Vec<_>>(),
        vec![SurfaceLeaf::RegistrarClient],
        "the usable server pair is left alone"
    );
    assert_eq!(
        evaluate_pair(
            &client_cert,
            &client_key,
            &Host::client_name(),
            host.settings.trust.ca_bundle_path.as_deref(),
        )
        .await,
        PairUsability::Unusable(UnusableMaterial::Expired),
        "the client replacement is still outside its window"
    );
    load().expect("a skewed client leaf does not stop the endpoint coming up");
}

/// The host label comes from the rendered internal config, so a config
/// that is absent or fails the loader's invariants refuses the start
/// naming that path — and no name is composed from a guessed label.
#[test]
fn a_rendered_internal_config_that_fails_the_loader_refuses_and_names_the_path() {
    let host = Host::new();
    let internal = InternalPaths::new(&host.secrets_dir());

    std::fs::remove_file(internal.agent_config()).expect("remove the internal config");
    let error = resolve_surface_plan(&host.settings).expect_err("an absent config refuses");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(&internal.agent_config().display().to_string()),
        "{rendered}"
    );
    assert!(
        !rendered.contains(TEST_HOST),
        "no label may be guessed: {rendered}"
    );

    std::fs::write(internal.agent_config(), "this is not TOML = = =").expect("write garbage");
    let error = resolve_surface_plan(&host.settings).expect_err("an unparseable config refuses");
    assert!(
        format!("{error:#}").contains(&internal.agent_config().display().to_string()),
        "{error:#}"
    );
}

/// The host label the plan composes with is the internal profile's own,
/// and the composed names carry it — not the system hostname, and not a
/// value parsed out of any leaf.
#[test]
fn the_plan_takes_the_host_label_from_the_rendered_internal_config() {
    let host = Host::new();
    let plan = resolve_surface_plan(&host.settings).expect("the plan resolves");
    assert_eq!(plan.host, TEST_HOST);
    assert_eq!(plan.kv_mount, TEST_KV_MOUNT);
    let names: Vec<&str> = plan.pairs.iter().map(|pair| pair.name.as_str()).collect();
    assert_eq!(
        names,
        vec![
            format!("001.bootroot-registrar-endpoint.{TEST_HOST}.{TEST_DOMAIN}").as_str(),
            format!("001.bootroot-registrar.{TEST_HOST}.{TEST_DOMAIN}").as_str(),
        ]
    );
}

/// An absent `[registrar] state_file` refuses rather than defaulting to
/// anything.
#[test]
fn an_absent_state_file_setting_refuses() {
    let host = Host::new();
    let mut settings = host.settings.clone();
    settings.registrar.state_file = None;
    let error = resolve_surface_plan(&settings).expect_err("an absent state file refuses");
    assert!(
        format!("{error:#}").contains("registrar.state_file"),
        "{error:#}"
    );
}

// ---------------------------------------------------------------------
// The ACME inputs, read from OpenBao under the internal credential
// ---------------------------------------------------------------------

/// Every path the mock `OpenBao` was asked for, so a test can assert on
/// what was *not* asked for as firmly as on what was.
#[derive(Default)]
struct OpenBaoLog {
    paths: Mutex<Vec<String>>,
}

/// Records the request path and answers with `body`.
struct RecordingResponder {
    log: Arc<OpenBaoLog>,
    status: u16,
    body: serde_json::Value,
}

impl Respond for RecordingResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        self.log
            .paths
            .lock()
            .expect("not poisoned")
            .push(request.url.path().to_string());
        ResponseTemplate::new(self.status).set_body_json(self.body.clone())
    }
}

/// A mock `OpenBao` that answers the certificate login and both KV
/// reads, under `mount`.
async fn start_openbao(mount: &str, log: &Arc<OpenBaoLog>) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_matcher("/v1/auth/cert/login"))
        .respond_with(RecordingResponder {
            log: Arc::clone(log),
            status: 200,
            body: serde_json::json!({
                "auth": { "client_token": "surface-test-token", "lease_duration": 3600 }
            }),
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_matcher(format!("/v1/{mount}/data/{PATH_AGENT_EAB}")))
        .respond_with(RecordingResponder {
            log: Arc::clone(log),
            status: 200,
            body: serde_json::json!({
                "data": { "data": { "kid": OPENBAO_EAB_KID, "hmac": OPENBAO_EAB_HMAC } }
            }),
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_matcher(format!(
            "/v1/{mount}/data/{PATH_RESPONDER_HMAC}"
        )))
        .respond_with(RecordingResponder {
            log: Arc::clone(log),
            status: 200,
            body: serde_json::json!({ "data": { "data": { "hmac": OPENBAO_HMAC } } }),
        })
        .mount(&server)
        .await;
    server
}

/// Both KV paths this module reads are inside the internal
/// credential's own ACL policy, so no policy widens for this issuance
/// and neither read comes back a permission denial on a real
/// deployment.
///
/// The policy names the two paths as literals in its rendered body, and
/// the constants above are a second spelling of them — the binary
/// crate's `PATH_AGENT_EAB` and `PATH_RESPONDER_HMAC` are a third, and
/// are unreachable from the library. So the spellings are pinned to one
/// another here: renaming either KV path without the other would
/// otherwise compile, pass every mock-backed test above — the mock is
/// mounted at whatever the constant says — and only fail against a real
/// `OpenBao`, on an endpoint-enabled host, at start.
#[test]
fn both_kv_paths_are_inside_the_internal_credentials_policy() {
    let policy = crate::registrar::internal::build_registrar_internal_policy(TEST_KV_MOUNT);
    for path in [PATH_AGENT_EAB, PATH_RESPONDER_HMAC] {
        assert!(
            policy.contains(&format!("path \"{TEST_KV_MOUNT}/data/{path}\" {{")),
            "the internal credential's policy must grant {path}: {policy}"
        );
    }
}

/// Both inputs are read at the mount the **deployment state file**
/// records, not at `agent.toml`'s — which carries no such key for this
/// path — and the values that come back are the ones an issuance uses.
#[tokio::test]
async fn the_acme_inputs_are_read_at_the_state_files_mount() {
    const NON_DEFAULT_MOUNT: &str = "a-non-default-mount";
    let host = Host::new();
    let log = Arc::new(OpenBaoLog::default());
    let server = start_openbao(NON_DEFAULT_MOUNT, &log).await;
    let credential = InternalCredential::for_test(
        &server.uri(),
        &host.secrets_dir(),
        &host.ca.root_fingerprint(),
    )
    .expect("a test credential");

    let inputs = read_acme_inputs_with(&credential, NON_DEFAULT_MOUNT)
        .await
        .expect("both inputs are read");

    assert_eq!(inputs.responder_hmac.expose(), OPENBAO_HMAC);
    let eab = inputs.eab.expect("the deployment recorded an EAB");
    assert_eq!(eab.kid, OPENBAO_EAB_KID);

    let paths = log.paths.lock().expect("not poisoned");
    assert!(
        paths.contains(&format!("/v1/{NON_DEFAULT_MOUNT}/data/{PATH_AGENT_EAB}")),
        "{paths:?}"
    );
    assert!(
        paths.contains(&format!(
            "/v1/{NON_DEFAULT_MOUNT}/data/{PATH_RESPONDER_HMAC}"
        )),
        "{paths:?}"
    );
}

/// No `AppRole` anywhere on the path: the credential authenticates at
/// `auth/cert`, and neither the login nor either KV read touches an
/// `AppRole` endpoint. Nothing on the host holds a `role_id` or a
/// `secret_id` for this path to read either.
#[tokio::test]
async fn the_issuance_path_uses_no_approle() {
    let host = Host::new();
    let log = Arc::new(OpenBaoLog::default());
    let server = start_openbao(TEST_KV_MOUNT, &log).await;
    let credential = InternalCredential::for_test(
        &server.uri(),
        &host.secrets_dir(),
        &host.ca.root_fingerprint(),
    )
    .expect("a test credential");

    read_acme_inputs_with(&credential, TEST_KV_MOUNT)
        .await
        .expect("both inputs are read");

    let paths = log.paths.lock().expect("not poisoned");
    assert!(
        paths.iter().any(|path| path == "/v1/auth/cert/login"),
        "the login must be the certificate one: {paths:?}"
    );
    for path in paths.iter() {
        for forbidden in ["approle", "role-id", "role_id", "secret-id", "secret_id"] {
            assert!(
                !path.contains(forbidden),
                "{path} reaches an AppRole surface"
            );
        }
    }

    // And nothing on disk under the secrets directory is one either.
    for entry in walk(&host.secrets_dir()) {
        let name = entry.file_name().unwrap_or_default().to_string_lossy();
        assert!(
            !name.contains("role_id") && !name.contains("secret_id"),
            "{} is an AppRole credential file",
            entry.display()
        );
    }
}

/// Every regular file below `root`.
fn walk(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

/// An unreachable `OpenBao` and a missing KV path are each a startup
/// refusal naming the failing read, never a fallback to a locally
/// configured value.
#[tokio::test]
async fn a_failed_openbao_read_refuses_and_names_the_read() {
    let host = Host::new();

    // Unreachable.
    let credential = InternalCredential::for_test(
        "http://127.0.0.1:1",
        &host.secrets_dir(),
        &host.ca.root_fingerprint(),
    )
    .expect("a test credential");
    let error = read_acme_inputs_with(&credential, TEST_KV_MOUNT)
        .await
        .expect_err("an unreachable OpenBao must refuse");
    assert!(
        format!("{error:#}").contains("OpenBao"),
        "the diagnostic must name the failing read: {error:#}"
    );

    // Reachable, but the EAB path is not there.
    let log = Arc::new(OpenBaoLog::default());
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path_matcher("/v1/auth/cert/login"))
        .respond_with(RecordingResponder {
            log: Arc::clone(&log),
            status: 200,
            body: serde_json::json!({
                "auth": { "client_token": "surface-test-token", "lease_duration": 3600 }
            }),
        })
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path_matcher(format!(
            "/v1/{TEST_KV_MOUNT}/data/{PATH_AGENT_EAB}"
        )))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "errors": Vec::<String>::new()
        })))
        .mount(&server)
        .await;
    let credential = InternalCredential::for_test(
        &server.uri(),
        &host.secrets_dir(),
        &host.ca.root_fingerprint(),
    )
    .expect("a test credential");
    let error = read_acme_inputs_with(&credential, TEST_KV_MOUNT)
        .await
        .expect_err("a missing KV path must refuse");
    let rendered = format!("{error:#}");
    assert!(rendered.contains(PATH_AGENT_EAB), "{rendered}");
    assert!(rendered.contains(TEST_KV_MOUNT), "{rendered}");
}

/// The **public issuance unit**'s own refusal on a failed `OpenBao`
/// exchange names the failing read *and* the material paths of the pairs
/// it was reached for — the requirement the isolated
/// `read_acme_inputs_with` cases above cannot see, because they are
/// called with no pair in hand at all.
///
/// The server pair is left usable, so the pending set is exactly the
/// client pair: the diagnostic must carry that pair's two paths and
/// neither of the untouched pair's.
#[tokio::test]
async fn a_failed_openbao_read_out_of_the_issuance_unit_names_the_pending_material_paths() {
    let host = Host::with_openbao_url("https://127.0.0.1:1");
    host.provision_internal_credential();
    let (server_cert, server_key) = host.server_pair();
    write_usable_pair(&host.ca, &Host::server_name(), &server_cert, &server_key);

    let mut settings = host.settings.clone();
    // Nothing is listening here either, so a CA request would fail on
    // its own — but the OpenBao read is reached first.
    settings.server = "http://127.0.0.1:1/directory".to_string();

    let error = ensure_registrar_surface_certificates(&settings, false)
        .await
        .expect_err("an unreachable OpenBao must refuse the start");
    let rendered = format!("{error:#}");

    assert!(
        rendered.contains("OpenBao"),
        "the failing read must still be named: {rendered}"
    );
    let (client_cert, client_key) = host.client_pair();
    for path in [&client_cert, &client_key] {
        assert!(
            rendered.contains(&path.display().to_string()),
            "the pending pair's {} must be named: {rendered}",
            path.display()
        );
    }
    assert!(
        rendered.contains(&Host::client_name()),
        "the pending pair's reserved name must be named: {rendered}"
    );
    for path in [&server_cert, &server_key] {
        assert!(
            !rendered.contains(&path.display().to_string()),
            "the usable pair's {} must not be reported as pending: {rendered}",
            path.display()
        );
    }

    // And no material was published for the pending pair.
    assert!(!client_cert.exists());
    assert!(!client_key.exists());
}

/// A resolution failure refuses before any pair exists, so it names the
/// four **configured** paths instead — the material identifiers that are
/// available at that point — alongside the failure itself.
#[tokio::test]
async fn a_resolution_failure_names_the_configured_material_paths() {
    let host = Host::new();
    let state_file = host
        .settings
        .registrar
        .state_file
        .clone()
        .expect("a state file");
    std::fs::remove_file(&state_file).expect("remove the state file");

    let error = ensure_registrar_surface_certificates(&host.settings, false)
        .await
        .expect_err("an unreadable state file must refuse the start");
    let rendered = format!("{error:#}");

    let (server_cert, server_key) = host.server_pair();
    let (client_cert, client_key) = host.client_pair();
    for path in [&server_cert, &server_key, &client_cert, &client_key] {
        assert!(
            rendered.contains(&path.display().to_string()),
            "the configured {} must be named: {rendered}",
            path.display()
        );
    }
    assert!(
        rendered.contains(&state_file.display().to_string()),
        "the failure itself must still be named: {rendered}"
    );
}

/// A credential whose stored root fingerprint is not the deployment's
/// active root refuses an endpoint-enabled start that needs issuance,
/// with the credential's own repair diagnostic — neither retried around
/// nor proceeded past.
#[tokio::test]
async fn a_superseded_credential_refuses_with_its_own_repair_diagnostic() {
    let host = Host::new();
    // The rotation has replaced the deployment root; the credential's
    // stored fingerprint still names the old one.
    let rotated = TestCa::new("Rotated Deployment Root");
    std::fs::write(
        active_root_cert_path(&host.secrets_dir()),
        &rotated.root_pem,
    )
    .expect("rewrite the active root");
    let credential = InternalCredential::for_test(
        "http://127.0.0.1:1",
        &host.secrets_dir(),
        &host.ca.root_fingerprint(),
    )
    .expect("a test credential");

    let error = read_acme_inputs_with(&credential, TEST_KV_MOUNT)
        .await
        .expect_err("a superseded credential must refuse");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("bootroot rotate registrar-internal-credential"),
        "the credential's own repair diagnostic must reach the caller: {rendered}"
    );
}

/// Runs the issuance the way `ensure_registrar_surface_certificates`
/// does — resolve, evaluate, issue whatever is pending — with the two
/// ACME inputs supplied directly.
///
/// The composition that reads them from `OpenBao` needs a real
/// client-authenticated transport, which is covered separately over a
/// mock in the `read_acme_inputs_with` tests above.
async fn run_issuance(host: &Host) -> Vec<SurfacePairPaths> {
    let plan = resolve_surface_plan(&host.settings).expect("the plan resolves");
    let pending = pending_pairs(&plan, host.settings.trust.ca_bundle_path.as_deref()).await;
    for pair in &pending {
        issue_surface_pair(&host.settings, pair, &plan.host, &openbao_inputs(), false)
            .await
            .expect("the pending pair is issued");
    }
    pending
}

/// Issuance runs **before** the endpoint's TLS load, and the material it
/// leaves is material that load accepts — including from an expired
/// leaf, which is the case the ordering exists for.
///
/// Linux-only, because the loader is compiled nowhere else.
#[tokio::test]
#[cfg(target_os = "linux")]
async fn issuance_leaves_material_the_endpoints_tls_load_accepts() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);

    // A daemon down through both leaves' not_after.
    for (cert, key, name) in [
        (
            host.server_pair().0,
            host.server_pair().1,
            Host::server_name(),
        ),
        (
            host.client_pair().0,
            host.client_pair().1,
            Host::client_name(),
        ),
    ] {
        let (leaf, key_pem) = host.ca.issue(&leaf_params(&name, -30, -1));
        write_pair(&cert, &key, &leaf, &key_pem);
    }

    let endpoint = host.endpoint().clone();
    let load = || {
        crate::registrar::endpoint::tls::build_server_config(
            endpoint.server_cert_path.as_deref(),
            endpoint.server_key_path.as_deref(),
            host.settings.trust.ca_bundle_path.as_deref(),
            &host.settings.trust.trusted_ca_sha256,
            &host.settings.domain,
        )
    };
    assert!(
        load().is_err(),
        "the expired material must be what the loader would have refused"
    );

    let pending = run_issuance(&host).await;
    assert_eq!(pending.len(), 2, "both expired pairs need issuing");

    load().expect("the loader accepts the material issuance just published");
}

/// The daemon calls issuance **above** `RegistrarEndpoint::activate`, so
/// the endpoint's TLS load sees material issuance has already ensured.
///
/// Asserted over the composition boundary's own source, because the
/// ordering is a property of that one function and there is nothing else
/// to observe it through.
#[test]
fn the_daemon_calls_issuance_above_endpoint_activation() {
    let source = include_str!("../bin/bootroot-agent.rs");
    let issuance = source
        .find("ensure_registrar_surface_certificates(&initial_settings")
        .expect("the daemon calls the issuance unit");
    let activation = source
        .find("RegistrarEndpoint::activate(&initial_settings)")
        .expect("the daemon activates the endpoint");
    assert!(
        issuance < activation,
        "issuance must run before the endpoint's TLS material is loaded"
    );
}

/// Both surface leaves are published **with** their issuer chain. A
/// leaf-only `server_cert_path` loads cleanly and is then refused by the
/// endpoint's loader and by every correctly pinned caller, so the chain
/// is part of what issuance owes that loader.
#[tokio::test]
async fn both_surface_leaves_are_published_with_their_issuer_chain() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);

    let pending = run_issuance(&host).await;
    assert_eq!(pending.len(), 2, "a bare host needs both pairs issued");

    for (cert_path, name) in [
        (host.server_pair().0, Host::server_name()),
        (host.client_pair().0, Host::client_name()),
    ] {
        let pem = std::fs::read_to_string(&cert_path).expect("read the published certificate");
        assert_eq!(
            pem.matches("BEGIN CERTIFICATE").count(),
            2,
            "{} must hold the leaf followed by its issuer",
            cert_path.display()
        );
        assert_eq!(san_at(&cert_path), name);
        // The publication shape is still two configured paths: one
        // certificate file and one key file, with no generation
        // directory and no combined PEM.
        assert!(cert_path.is_file());
    }
}

/// What issuance publishes is what the usability evaluation accepts, so
/// a second start re-issues nothing and both pairs survive it
/// byte-identically.
///
/// The two halves are written and read by this one module and can drift
/// apart without any other test noticing: every "leave alone" test above
/// provisions its material by hand, so a publication shape the
/// evaluation then rejects would still pass all of them while re-minting
/// both leaves on every restart — churning a file the co-located
/// registrar is reading and handing that process a new key each time.
#[tokio::test]
async fn material_this_issuance_published_is_usable_on_the_next_start() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);

    assert_eq!(
        run_issuance(&host).await.len(),
        2,
        "a bare host needs both pairs issued"
    );
    let published: Vec<(PathBuf, String)> = [host.server_pair(), host.client_pair()]
        .into_iter()
        .flat_map(|(cert, key)| [cert, key])
        .map(|path| {
            let digest = digest_of(&path);
            (path, digest)
        })
        .collect();

    let second = run_issuance(&host).await;
    assert!(
        second.is_empty(),
        "the material issuance just published must be usable: {second:?}"
    );
    for (path, digest) in published {
        assert_eq!(
            digest,
            digest_of(&path),
            "{} must survive the restart byte-identically",
            path.display()
        );
    }
}

/// A first start mints the server pair with the endpoint not yet
/// listening: issuance goes over the outbound ACME path to the local
/// step-ca and never through the endpoint it is issuing for.
#[tokio::test]
async fn the_server_pair_is_minted_on_a_first_start_with_nothing_listening() {
    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);
    let (cert_path, key_path) = host.server_pair();
    assert!(!cert_path.exists(), "a first start has no material at all");

    run_issuance(&host).await;

    assert_eq!(san_at(&cert_path), Host::server_name());
    assert!(key_path.is_file());
}

/// The issued **server** leaf chains to an anchor listed in the caller's
/// own pin file, judged by the caller's own verifier over the material
/// the daemon published — the rule a co-located registrar applies, run
/// against what issuance left behind.
///
/// Issuance leaves the pin file itself alone: the pin is over trust
/// **anchors**, not over the leaf, so a fresh leaf changes nothing in
/// it.
#[tokio::test]
async fn the_issued_server_leaf_verifies_under_the_callers_own_pin_file() {
    use rustls::pki_types::{CertificateDer, UnixTime};

    let mut host = Host::new();
    let acme = start_acme(Arc::clone(&host.ca)).await;
    aim_at(&mut host.settings, &acme);

    let (client_cert, _) = host.client_pair();
    std::fs::create_dir_all(client_cert.parent().expect("parent")).expect("create dir");
    let pin_path =
        crate::registrar::endpoint_pin::anchor_pin_path_for_client_certificate(&client_cert);
    std::fs::write(
        &pin_path,
        format!("# deployment anchors\n{}\n", host.ca.root_fingerprint()),
    )
    .expect("seed the pin file");
    let before = digest_of(&pin_path);

    run_issuance(&host).await;

    let pins = crate::registrar::endpoint_pin::load_anchor_pins(&pin_path)
        .expect("the pin file parses")
        .into_iter()
        .collect();
    let verifier =
        crate::registrar::endpoint_pin::RegistrarEndpointVerifier::new(pins, &Host::server_name())
            .expect("the verifier builds over the endpoint name");

    let (cert_path, _) = host.server_pair();
    let pem = std::fs::read(&cert_path).expect("read the published certificate");
    let presented: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(pem.as_slice()))
            .collect::<Result<Vec<_>, _>>()
            .expect("the published certificate parses");
    let (leaf, intermediates) = presented.split_first().expect("a leaf");
    verifier
        .verify(leaf, intermediates, UnixTime::now())
        .expect("a pinned caller accepts the leaf issuance just published");

    assert_eq!(before, digest_of(&pin_path), "the pin file must not move");
}

// ---------------------------------------------------------------------
// The passages this issuance falsifies
// ---------------------------------------------------------------------

/// Every claim start-time issuance makes false, and the file it used to
/// live in.
///
/// Read out of the sources themselves rather than restated in prose, so
/// a passage that comes back — in either language, or in the shipped
/// example an operator copies — fails here rather than being found by
/// an operator acting on it.
const SUPERSEDED_PASSAGES: [(&str, &str); 12] = [
    ("agent.toml.example", "supplied out of band"),
    ("agent.toml.example", "changes any of the three"),
    ("src/config.rs", "None of the three keys"),
    ("src/config.rs", "The two certificate paths are fixed"),
    ("docs/en/configuration.md", "three keys"),
    ("docs/en/configuration.md", "supplied out of band"),
    ("docs/en/configuration.md", "never issues one for itself"),
    (
        "docs/en/configuration.md",
        "**The two certificate paths are fixed",
    ),
    ("docs/ko/configuration.md", "정확히 세 개"),
    ("docs/ko/configuration.md", "대역 외로 공급"),
    ("docs/ko/configuration.md", "스스로 발급하지"),
    ("docs/ko/configuration.md", "**두 인증서 경로도 같은 이유로"),
];

/// What replaced each of them, so the sweep cannot be satisfied by
/// deleting the passage instead of correcting it.
const REPLACEMENT_PASSAGES: [(&str, &str); 10] = [
    ("agent.toml.example", "client_cert_path = "),
    ("agent.toml.example", "client_key_path = "),
    ("src/config.rs", "None of the five keys"),
    ("src/config.rs", "The four certificate paths are fixed"),
    ("docs/en/configuration.md", "five keys"),
    (
        "docs/en/configuration.md",
        "**The four certificate paths are fixed",
    ),
    ("docs/ko/configuration.md", "정확히 다섯 개"),
    ("docs/ko/configuration.md", "**네 인증서 경로도 같은 이유로"),
    ("docs/en/configuration.md", "client_key_path"),
    ("docs/ko/configuration.md", "client_key_path"),
];

/// Reads one repository-relative file for the sweep below.
fn repository_file(relative: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

/// No passage this issuance falsified survives anywhere it used to be
/// stated, and each one's replacement is there instead.
///
/// The two guides are translations of one another, so both are swept:
/// a correction landing in one language only is an incomplete
/// deliverable, and nothing else in the tree would catch it.
#[test]
fn no_superseded_passage_survives_in_the_configuration_surface() {
    for (file, passage) in SUPERSEDED_PASSAGES {
        assert!(
            !repository_file(file).contains(passage),
            "{file} still states the superseded claim {passage:?}"
        );
    }
    for (file, passage) in REPLACEMENT_PASSAGES {
        assert!(
            repository_file(file).contains(passage),
            "{file} no longer carries the corrected claim {passage:?}"
        );
    }
}
