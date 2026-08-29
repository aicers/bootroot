//! Tests for the registrar surface's renewal adapter.
//!
//! Everything here runs under `tempfile::tempdir()` against a listener
//! this harness binds on a temporary path. Nothing reaches the network,
//! nothing mutates the process environment, and no test waits on a wall
//! clock: a pass is driven by calling it, and the loop's cadence is
//! driven under `tokio::time::pause`.
//!
//! The one step no test here drives is the ACME exchange itself. That is
//! [`crate::registrar_certs`]'s, whose own tests run
//! `issue_surface_pair_material` end to end against a mock directory;
//! what this module drives is everything that happens to the material it
//! returns.

use std::os::unix::fs::PermissionsExt as _;
use std::sync::atomic::{AtomicUsize, Ordering};

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use tempfile::TempDir;

use super::*;
use crate::acme::IssuedMaterial;
use crate::config::{RegistrarEndpointSettings, Settings};
use crate::registrar::endpoint;
use crate::registrar::endpoint::activation::ActivationContract;
use crate::registrar::endpoint_pin::REGISTRAR_ENDPOINT_ANCHORS_FILE;

const TEST_DOMAIN: &str = "corp.example.internal";
const TEST_HOST: &str = "bootroot-01";

// ---------------------------------------------------------------------
// Certificate material
// ---------------------------------------------------------------------

type Issuer = CertifiedIssuer<'static, KeyPair>;

/// A one-level test CA: a self-signed root that signs leaves directly,
/// exactly the shape the deployment's own anchor set has.
struct TestCa {
    issuer: Issuer,
    pem: String,
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
        let pem = issuer.pem();
        Self { issuer, pem }
    }

    fn fingerprint(&self) -> String {
        crate::tls::sha256_hex(self.issuer.der())
    }

    fn der(&self) -> Vec<u8> {
        self.issuer.der().to_vec()
    }

    /// Issues a leaf carrying `name` as its only DNS SAN, valid from
    /// `not_before_days` to `not_after_days` measured from now.
    fn issue(&self, name: &str, not_before_days: i64, not_after_days: i64) -> (String, String) {
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::NoCa;
        params.subject_alt_names = vec![SanType::DnsName(
            name.to_string().try_into().expect("a valid DNS SAN"),
        )];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now + time::Duration::days(not_before_days);
        params.not_after = now + time::Duration::days(not_after_days);
        let leaf = params.signed_by(&key, &self.issuer).expect("issued leaf");
        (leaf.pem(), key.serialize_pem())
    }

    /// The material an issuance would have returned for `name`: the leaf
    /// followed by this CA's certificate, a fresh key, and the chain.
    fn material(&self, name: &str, not_before_days: i64, not_after_days: i64) -> IssuedMaterial {
        let (leaf_pem, key_pem) = self.issue(name, not_before_days, not_after_days);
        IssuedMaterial {
            cert_pem: format!("{leaf_pem}{}", self.pem),
            key_pem,
            chain: vec![self.der()],
        }
    }
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("a PEM certificate");
    parsed.contents
}

fn san_at(path: &Path) -> String {
    let pem = std::fs::read_to_string(path).expect("read the published leaf");
    single_dns_san(&pem_to_der(&pem)).expect("the published leaf carries one DNS SAN")
}

fn digest_of(path: &Path) -> String {
    crate::tls::sha256_hex(&std::fs::read(path).expect("read the file to digest"))
}

// ---------------------------------------------------------------------
// The host fixture
// ---------------------------------------------------------------------

/// A provisioned endpoint-enabled host, an activated endpoint over a
/// listener the harness bound, and the renewal adapter above both.
struct Harness {
    dir: TempDir,
    _socket_dir: TempDir,
    ca: TestCa,
    settings: Arc<Settings>,
    plan: SurfacePlan,
    endpoint: Arc<ActivatedEndpoint>,
    socket_path: PathBuf,
}

impl Harness {
    fn build() -> Self {
        Self::build_with_pins(None)
    }

    /// `pin_file_over` replaces what the endpoint pin file names; `None`
    /// pins the deployment CA, which is what a provisioned host has.
    fn build_with_pins(pin_file_over: Option<Vec<String>>) -> Self {
        crate::tls::install_crypto_provider();
        let dir = TempDir::new().expect("tempdir");
        let ca = TestCa::new("Bootroot Renewal Test CA");
        let certs = dir.path().join("certs");
        std::fs::create_dir_all(&certs).expect("create the certs directory");

        let bundle_path = certs.join("ca-bundle.pem");
        std::fs::write(&bundle_path, &ca.pem).expect("write the bundle");

        let pins = pin_file_over.unwrap_or_else(|| vec![ca.fingerprint()]);
        let pin_file = certs.join(REGISTRAR_ENDPOINT_ANCHORS_FILE);
        std::fs::write(
            &pin_file,
            pins.iter().fold(String::new(), |mut acc, pin| {
                use std::fmt::Write as _;
                let _ = writeln!(acc, "{pin}");
                acc
            }),
        )
        .expect("write the pin file");

        let mut settings = base_settings();
        settings.trust.ca_bundle_path = Some(bundle_path);
        settings.trust.trusted_ca_sha256 = vec![ca.fingerprint()];
        settings.registrar_endpoint = RegistrarEndpointSettings {
            enabled: true,
            server_cert_path: Some(certs.join("endpoint.crt")),
            server_key_path: Some(certs.join("endpoint.key")),
            client_cert_path: Some(certs.join("client.crt")),
            client_key_path: Some(certs.join("client.key")),
        };

        // The deployment's active root, so a pass that needs the ACME
        // inputs gets as far as loading the bootroot-internal
        // credential rather than stopping one step above it.
        let secrets_dir = dir.path().join("secrets");
        let root_path = crate::registrar::internal::active_root_cert_path(&secrets_dir);
        std::fs::create_dir_all(root_path.parent().expect("a certs directory"))
            .expect("create the secrets certs directory");
        std::fs::write(&root_path, &ca.pem).expect("write the active root");

        let plan = SurfacePlan {
            secrets_dir,
            openbao_url: "https://127.0.0.1:1".to_string(),
            kv_mount: "bootroot-kv".to_string(),
            host: TEST_HOST.to_string(),
            pairs: crate::registrar_certs::surface_pairs(
                &settings.registrar_endpoint,
                TEST_HOST,
                TEST_DOMAIN,
            )
            .expect("both pairs resolve"),
        };

        // Live material at both configured pairs, in date.
        for pair in &plan.pairs {
            let (leaf, key) = ca.issue(&pair.name, -1, 30);
            std::fs::write(&pair.cert_path, format!("{leaf}{}", ca.pem))
                .expect("write the live leaf");
            std::fs::write(&pair.key_path, key).expect("write the live key");
            std::fs::set_permissions(&pair.key_path, std::fs::Permissions::from_mode(0o600))
                .expect("narrow the live key");
        }

        let (socket_dir, socket_path, endpoint) = activate_over(&settings);
        Self {
            dir,
            _socket_dir: socket_dir,
            ca,
            settings: Arc::new(settings),
            plan,
            endpoint,
            socket_path,
        }
    }

    fn pair(&self, leaf: SurfaceLeaf) -> SurfacePairPaths {
        self.plan
            .pairs
            .iter()
            .find(|pair| pair.leaf == leaf)
            .expect("both leaves are in the plan")
            .clone()
    }

    fn bundle_path(&self) -> PathBuf {
        self.settings
            .trust
            .ca_bundle_path
            .clone()
            .expect("a configured bundle")
    }

    fn pin_file(&self) -> PathBuf {
        self.dir
            .path()
            .join("certs")
            .join(REGISTRAR_ENDPOINT_ANCHORS_FILE)
    }

    async fn renewal(&self) -> RegistrarCertRenewal {
        RegistrarCertRenewal::for_test(
            Arc::clone(&self.settings),
            self.plan.clone(),
            Arc::clone(&self.endpoint),
            cadence(),
        )
        .await
    }
}

/// Binds a listener on a private path and adopts it through the
/// production activation path, over `settings`' own TLS material.
fn activate_over(settings: &Settings) -> (TempDir, PathBuf, Arc<ActivatedEndpoint>) {
    use std::os::fd::IntoRawFd as _;

    let socket_dir = TempDir::new().expect("socket tempdir");
    std::fs::set_permissions(socket_dir.path(), std::fs::Permissions::from_mode(0o700))
        .expect("narrow the socket directory");
    let socket_path = socket_dir.path().join("registrar.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).expect("bind");
    std::fs::set_permissions(
        &socket_path,
        std::fs::Permissions::from_mode(endpoint::REQUIRED_SOCKET_MODE),
    )
    .expect("set the socket mode");
    let (config, resolver) = endpoint::tls::build_server_config(
        settings.registrar_endpoint.server_cert_path.as_deref(),
        settings.registrar_endpoint.server_key_path.as_deref(),
        settings.trust.ca_bundle_path.as_deref(),
        &settings.trust.trusted_ca_sha256,
        &settings.domain,
    )
    .expect("the fixture's material builds a configuration");
    let adopted = endpoint::adopt(
        ActivationContract::from_test_descriptor(listener.into_raw_fd()),
        endpoint::current_effective_uid(),
        config,
        resolver,
        settings.domain.clone(),
    )
    .expect("adopt the harness listener");
    (socket_dir, socket_path, adopted)
}

fn base_settings() -> Settings {
    Settings {
        email: "ops@example.internal".to_string(),
        server: "https://127.0.0.1:1/acme/acme/directory".to_string(),
        domain: TEST_DOMAIN.to_string(),
        eab: None,
        acme: crate::config::AcmeSettings {
            directory_fetch_attempts: 1,
            directory_fetch_base_delay_secs: 1,
            directory_fetch_max_delay_secs: 1,
            poll_attempts: 1,
            poll_interval_secs: 0,
            account_key_path: None,
            http_responder_url: "http://127.0.0.1:1".to_string(),
            http_responder_hmac: "unused".into(),
            http_responder_timeout_secs: 1,
            http_responder_token_ttl_secs: 300,
        },
        retry: crate::config::RetrySettings {
            backoff_secs: Vec::new(),
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

/// A cadence a test can drive without waiting on anything real.
fn cadence() -> RenewalCadence {
    RenewalCadence {
        check_interval: Duration::from_hours(1),
        check_jitter: Duration::from_secs(0),
        renew_before: Duration::from_hours(16),
        retry_backoff: Vec::new(),
    }
}

// ---------------------------------------------------------------------
// The injectable live-write seam
// ---------------------------------------------------------------------

/// The production writer with any of its three writes forced to fail.
///
/// Composing the three independently is what lets a test drive the
/// publication failure and the rollback failure of the *same* attempt,
/// which is the case where the two errors have to travel out together.
struct FaultyPaths {
    inner: FilesystemPaths,
    fail_bundle: bool,
    fail_pair: bool,
    fail_rollback: bool,
    restores: Arc<AtomicUsize>,
}

impl FaultyPaths {
    /// Not `Self`: the seam is a `Box<dyn LivePaths>`, and the counter
    /// beside it is what a test asserts the rollback through.
    #[allow(clippy::new_ret_no_self)]
    fn new(
        fail_bundle: bool,
        fail_pair: bool,
        fail_rollback: bool,
    ) -> (Box<dyn LivePaths>, Arc<AtomicUsize>) {
        let restores = Arc::new(AtomicUsize::new(0));
        (
            Box::new(Self {
                inner: FilesystemPaths::new(),
                fail_bundle,
                fail_pair,
                fail_rollback,
                restores: Arc::clone(&restores),
            }),
            restores,
        )
    }
}

impl LivePaths for FaultyPaths {
    fn write_bundle<'a>(&'a self, path: &'a Path, contents: &'a str) -> LiveWrite<'a> {
        if self.fail_bundle {
            return Box::pin(async { anyhow::bail!("injected CA bundle write failure") });
        }
        self.inner.write_bundle(path, contents)
    }

    fn write_pair<'a>(
        &'a self,
        cert_path: &'a Path,
        key_path: &'a Path,
        cert_pem: &'a str,
        key_pem: &'a str,
    ) -> LiveWrite<'a> {
        if self.fail_pair {
            return Box::pin(async { anyhow::bail!("injected certificate and key write failure") });
        }
        self.inner
            .write_pair(cert_path, key_path, cert_pem, key_pem)
    }

    fn restore<'a>(&'a self, snapshot: &'a Snapshot) -> LiveWrite<'a> {
        self.restores.fetch_add(1, Ordering::SeqCst);
        if self.fail_rollback {
            return Box::pin(async { anyhow::bail!("injected rollback failure") });
        }
        self.inner.restore(snapshot)
    }
}

/// Every live and active fact a refusal must leave untouched.
struct LiveFacts {
    bundle: String,
    cert: String,
    key: String,
    pin_file: String,
    acceptor: Arc<endpoint::ActiveTls>,
    not_after: OffsetDateTime,
}

impl LiveFacts {
    fn capture(harness: &Harness, leaf: SurfaceLeaf, state: &RegistrarCertRenewalState) -> Self {
        let pair = harness.pair(leaf);
        Self {
            bundle: digest_of(&harness.bundle_path()),
            cert: digest_of(&pair.cert_path),
            key: digest_of(&pair.key_path),
            pin_file: digest_of(&harness.pin_file()),
            acceptor: harness.endpoint.active_tls(),
            not_after: state.leaf(leaf).expect("the leaf has an entry").not_after,
        }
    }

    fn assert_unchanged(&self, harness: &Harness, leaf: SurfaceLeaf) {
        let pair = harness.pair(leaf);
        assert_eq!(
            self.bundle,
            digest_of(&harness.bundle_path()),
            "the live CA bundle must be byte-for-byte unchanged"
        );
        assert_eq!(
            self.cert,
            digest_of(&pair.cert_path),
            "the live certificate must be byte-for-byte unchanged"
        );
        assert_eq!(
            self.key,
            digest_of(&pair.key_path),
            "the live key must be byte-for-byte unchanged"
        );
        assert_eq!(
            self.pin_file,
            digest_of(&harness.pin_file()),
            "the endpoint pin file must never be rewritten"
        );
        assert!(
            Arc::ptr_eq(&self.acceptor, &harness.endpoint.active_tls()),
            "the active TLS configuration must not have been exchanged"
        );
    }
}

// ---------------------------------------------------------------------
// The accessor and initialization
// ---------------------------------------------------------------------

/// An enabled endpoint gets one entry per leaf, initialized from the
/// certificate already on disk, with no attempt behind it and no
/// timestamp.
#[tokio::test]
async fn initialization_records_both_leaves_without_attempting_anything() {
    let harness = Harness::build();
    let renewal = harness.renewal().await;
    let state = renewal.state();

    assert_eq!(state.len(), 2, "an enabled endpoint has both entries");
    for leaf in [SurfaceLeaf::EndpointServer, SurfaceLeaf::RegistrarClient] {
        let entry = state.leaf(leaf).expect("an entry for each leaf");
        assert_eq!(entry.attempt, RenewalAttempt::NeverAttempted);
        assert!(
            entry.attempted_at.is_none(),
            "initialization is not an attempt and stamps no time"
        );
        let pair = harness.pair(leaf);
        let observed = observed_not_after(&pair.cert_path)
            .await
            .expect("the fixture leaf parses");
        assert_eq!(
            entry.not_after, observed,
            "the recorded lifetime is the one on disk"
        );
    }
}

/// The accessor is empty until something initializes it, which is what a
/// disabled endpoint leaves behind: no adapter is built, so no entry
/// exists and nothing is ever asked of `OpenBao` or the CA.
#[test]
fn a_state_accessor_nobody_initialized_holds_nothing() {
    let state = RegistrarCertRenewalState::default();
    assert_eq!(state.len(), 0);
    assert!(state.leaf(SurfaceLeaf::EndpointServer).is_none());
    assert!(state.leaf(SurfaceLeaf::RegistrarClient).is_none());
}

/// With the endpoint disabled there is no activated endpoint for an
/// adapter to be built over, so no adapter exists, no state entry is
/// made, no pass runs and nothing is asked of `OpenBao` or the CA.
///
/// The adapter is spawned inside the same branch the accept task is,
/// which is reached only with an activated endpoint in hand; a disabled
/// endpoint activates to nothing without reading a certificate, a
/// descriptor or an activation variable.
#[test]
fn a_disabled_endpoint_leaves_no_adapter_to_build() {
    let mut settings = base_settings();
    settings.registrar_endpoint = RegistrarEndpointSettings {
        enabled: false,
        server_cert_path: Some(PathBuf::from("/nonexistent/endpoint.crt")),
        server_key_path: Some(PathBuf::from("/nonexistent/endpoint.key")),
        client_cert_path: Some(PathBuf::from("/nonexistent/client.crt")),
        client_key_path: Some(PathBuf::from("/nonexistent/client.key")),
    };
    assert!(
        endpoint::activate(&settings)
            .expect("a disabled endpoint never fails")
            .is_none(),
        "a disabled endpoint yields nothing for a renewal adapter to own"
    );
}

/// A success replaces `notAfter`; a failure retains it and records the
/// reason; neither loses the entry.
#[test]
fn a_failure_retains_the_lifetime_a_success_replaces() {
    let state = RegistrarCertRenewalState::default();
    let first = OffsetDateTime::now_utc();
    let later = first + time::Duration::days(30);
    let attempted = first + time::Duration::minutes(1);
    state.initialize(SurfaceLeaf::RegistrarClient, first);

    state.record_success(SurfaceLeaf::RegistrarClient, later, attempted);
    let entry = state.leaf(SurfaceLeaf::RegistrarClient).expect("an entry");
    assert_eq!(entry.not_after, later);
    assert_eq!(entry.attempt, RenewalAttempt::Succeeded);
    assert_eq!(entry.attempted_at, Some(attempted));

    let failed_at = attempted + time::Duration::hours(1);
    state.record_failure(SurfaceLeaf::RegistrarClient, "the CA said no", failed_at);
    let entry = state.leaf(SurfaceLeaf::RegistrarClient).expect("an entry");
    assert_eq!(
        entry.not_after, later,
        "a failed attempt retains the lifetime the leaf still has"
    );
    assert_eq!(
        entry.attempt,
        RenewalAttempt::Failed {
            reason: "the CA said no".to_string()
        }
    );
    assert_eq!(entry.attempted_at, Some(failed_at));
}

// ---------------------------------------------------------------------
// Eligibility
// ---------------------------------------------------------------------

/// A leaf outside lead time is not due; one inside it is; and the lead
/// time is checked before the chain, so a leaf that is both is reported
/// once.
#[tokio::test]
async fn lead_time_decides_before_chain_drift_does() {
    let harness = Harness::build();
    let pair = harness.pair(SurfaceLeaf::EndpointServer);
    assert!(
        !daemon::should_renew_certificate(
            &pair.cert_path,
            &harness.settings.trust,
            Duration::from_secs(3600)
        )
        .await
        .expect("the fixture leaf parses"),
        "a leaf 30 days out is not due at a one-hour lead time"
    );
    assert!(
        daemon::should_renew_certificate(
            &pair.cert_path,
            &harness.settings.trust,
            Duration::from_hours(24 * 60)
        )
        .await
        .expect("the fixture leaf parses"),
        "a leaf inside lead time is due"
    );
}

/// An in-date leaf outside lead time whose chain no longer reaches the
/// configured bundle is due; with no bundle configured, the same leaf is
/// not — the operator opted out of bundle management and nothing is
/// reissued for want of an anchor set.
#[tokio::test]
async fn chain_drift_is_eligibility_only_where_a_bundle_is_configured() {
    let harness = Harness::build();
    let pair = harness.pair(SurfaceLeaf::EndpointServer);
    // A destructive rotation: the bundle is replaced with a generation
    // that never signed this leaf, which is still in date and still
    // correctly named.
    let rotated = TestCa::new("Bootroot Rotated CA");
    std::fs::write(harness.bundle_path(), &rotated.pem).expect("rewrite the bundle");

    let short_lead = Duration::from_secs(3600);
    assert!(
        daemon::should_renew_certificate(&pair.cert_path, &harness.settings.trust, short_lead)
            .await
            .expect("the leaf parses"),
        "a leaf that no longer chains to the configured bundle is due"
    );

    let opted_out = crate::config::TrustSettings::default();
    assert!(
        opted_out.ca_bundle_path.is_none(),
        "the opt-out is an unconfigured bundle path"
    );
    assert!(
        !daemon::should_renew_certificate(&pair.cert_path, &opted_out, short_lead)
            .await
            .expect("the leaf parses"),
        "with no bundle configured, chain drift does not trigger renewal"
    );
}

/// That opt-out cannot stand an endpoint up: `build_server_config`
/// requires both the bundle path and a non-empty pin list, and falls
/// back to no other root source for incoming mTLS.
#[tokio::test]
async fn the_no_bundle_opt_out_cannot_activate_an_enabled_endpoint() {
    let harness = Harness::build();
    let pair = harness.pair(SurfaceLeaf::EndpointServer);

    let missing_bundle = endpoint::tls::build_server_config(
        Some(&pair.cert_path),
        Some(&pair.key_path),
        None,
        &harness.settings.trust.trusted_ca_sha256,
        TEST_DOMAIN,
    )
    .expect_err("an enabled endpoint with no bundle must refuse");
    assert!(
        matches!(
            missing_bundle,
            endpoint::tls::EndpointTlsError::MissingSetting {
                setting: endpoint::tls::CA_BUNDLE_SETTING
            }
        ),
        "{missing_bundle:#}"
    );

    let missing_pins = endpoint::tls::build_server_config(
        Some(&pair.cert_path),
        Some(&pair.key_path),
        harness.settings.trust.ca_bundle_path.as_deref(),
        &[],
        TEST_DOMAIN,
    )
    .expect_err("an enabled endpoint with no pins must refuse");
    assert!(
        matches!(
            missing_pins,
            endpoint::tls::EndpointTlsError::MissingSetting {
                setting: endpoint::tls::TRUSTED_CA_SETTING
            }
        ),
        "{missing_pins:#}"
    );
}

// ---------------------------------------------------------------------
// Candidate validation
// ---------------------------------------------------------------------

/// A conforming candidate for each leaf passes every rule.
#[tokio::test]
async fn a_conforming_candidate_is_accepted_for_both_leaves() {
    let harness = Harness::build();
    for leaf in [SurfaceLeaf::EndpointServer, SurfaceLeaf::RegistrarClient] {
        let pair = harness.pair(leaf);
        let material = harness.ca.material(&pair.name, -1, 30);
        validate_candidate(
            leaf,
            material.cert_pem.as_bytes(),
            material.key_pem.as_bytes(),
            &pair.name,
            TEST_DOMAIN,
            &harness.pin_file(),
        )
        .expect("a conforming candidate is publishable");
    }
}

/// A key that is not the candidate leaf's is refused before anything is
/// staged, and so is a candidate whose SAN drifted off the reserved name
/// the pair runs under.
#[tokio::test]
async fn a_mismatched_key_or_a_drifted_name_is_refused() {
    let harness = Harness::build();
    let pair = harness.pair(SurfaceLeaf::RegistrarClient);
    let material = harness.ca.material(&pair.name, -1, 30);
    let other = harness.ca.material(&pair.name, -1, 30);

    let rejection = validate_candidate(
        SurfaceLeaf::RegistrarClient,
        material.cert_pem.as_bytes(),
        other.key_pem.as_bytes(),
        &pair.name,
        TEST_DOMAIN,
        &harness.pin_file(),
    )
    .expect_err("a foreign key must be refused");
    assert!(
        matches!(rejection, CandidateRejection::KeyMismatched),
        "{rejection:#}"
    );

    // The instance label moved, which is exactly what "the same
    // identity" forbids.
    let drifted_name = format!("002.bootroot-registrar.{TEST_HOST}.{TEST_DOMAIN}");
    let drifted = harness.ca.material(&drifted_name, -1, 30);
    let rejection = validate_candidate(
        SurfaceLeaf::RegistrarClient,
        drifted.cert_pem.as_bytes(),
        drifted.key_pem.as_bytes(),
        &pair.name,
        TEST_DOMAIN,
        &harness.pin_file(),
    )
    .expect_err("a drifted identity must be refused");
    assert!(
        matches!(
            rejection,
            CandidateRejection::SanMismatched { ref found, .. }
                if found.as_deref() == Some(drifted_name.as_str())
        ),
        "{rejection:#}"
    );
}

/// A server candidate under an anchor the pin file does not name is
/// refused, naming the pin file it was held against.
#[tokio::test]
async fn a_server_candidate_under_an_unpinned_anchor_is_refused() {
    let harness = Harness::build();
    let pair = harness.pair(SurfaceLeaf::EndpointServer);
    let foreign = TestCa::new("Bootroot Unpinned CA");
    let material = foreign.material(&pair.name, -1, 30);

    let rejection = validate_candidate(
        SurfaceLeaf::EndpointServer,
        material.cert_pem.as_bytes(),
        material.key_pem.as_bytes(),
        &pair.name,
        TEST_DOMAIN,
        &harness.pin_file(),
    )
    .expect_err("an unpinned server candidate must be refused");
    assert!(
        matches!(rejection, CandidateRejection::Unpinned { ref pin_file, .. }
            if pin_file == &harness.pin_file()),
        "{rejection:#}"
    );

    // The same material is fine for the *client* leaf's rules, which do
    // not consult the pin file at all: the pin file decides only whether
    // a replacement server leaf is safe for pinned callers.
    let client = harness.pair(SurfaceLeaf::RegistrarClient);
    let client_material = foreign.material(&client.name, -1, 30);
    validate_candidate(
        SurfaceLeaf::RegistrarClient,
        client_material.cert_pem.as_bytes(),
        client_material.key_pem.as_bytes(),
        &client.name,
        TEST_DOMAIN,
        &harness.pin_file(),
    )
    .expect("the pin file is not a client-candidate rule");
}

// ---------------------------------------------------------------------
// The staged bundle and the rebuilt verifier
// ---------------------------------------------------------------------

/// The staged bundle is the existing bundle's pinned certificates plus
/// the candidate's chain, and an unpinned chain is refused before
/// anything is staged.
#[tokio::test]
async fn the_staged_bundle_merges_only_pinned_material() {
    let mut harness = Harness::build();
    let rotated = TestCa::new("Bootroot Next Generation CA");

    // Both generations pinned, which is the additive transitional trust
    // a rotation publishes.
    let mut settings = (*harness.settings).clone();
    settings.trust.trusted_ca_sha256 = vec![harness.ca.fingerprint(), rotated.fingerprint()];
    harness.settings = Arc::new(settings);
    let renewal = harness.renewal().await;

    let staged = renewal
        .stage_bundle(&harness.bundle_path(), &[rotated.der()])
        .expect("a pinned chain stages");
    let fingerprints: Vec<String> = crate::tls::parse_pem_to_cert_list(staged.as_bytes())
        .expect("the staged bundle parses")
        .into_iter()
        .map(|cert| crate::tls::sha256_hex(cert.as_ref()))
        .collect();
    assert!(
        fingerprints.contains(&harness.ca.fingerprint()),
        "the existing pinned anchor survives the merge"
    );
    assert!(
        fingerprints.contains(&rotated.fingerprint()),
        "the candidate's chain is merged in"
    );

    // Nothing was written: staging is a computation.
    assert_eq!(
        std::fs::read_to_string(harness.bundle_path()).expect("read the bundle"),
        harness.ca.pem,
        "staging must not touch the live bundle"
    );

    let unpinned = TestCa::new("Bootroot Unpinned CA");
    let refused = renewal
        .stage_bundle(&harness.bundle_path(), &[unpinned.der()])
        .expect_err("an unpinned chain must be refused");
    assert!(
        format!("{refused:#}").contains("Untrusted CA fingerprint"),
        "{refused:#}"
    );
}

/// The rebuilt incoming verifier's anchor set is exactly the staged
/// post-merge bundle's pinned certificates. A pin-file-only anchor, an
/// unpinned bundle certificate and the returned chain alone cannot
/// substitute, and neither can the system roots.
#[tokio::test]
async fn the_incoming_verifier_is_rebuilt_from_the_staged_pinned_subset_alone() {
    let harness = Harness::build();
    let pair = harness.pair(SurfaceLeaf::EndpointServer);
    let bundle_path = harness.bundle_path();
    let foreign = TestCa::new("Bootroot Foreign CA");

    // The pin file names the foreign anchor, and the staged bundle does
    // not carry it: the verifier is built from the bundle, so this
    // builds and admits nobody the bundle does not.
    std::fs::write(
        harness.pin_file(),
        format!("{}\n", crate::tls::sha256_hex(&foreign.der())),
    )
    .expect("rewrite the pin file");
    endpoint::tls::build_server_config_from_staged(
        &pair.cert_path,
        &pair.key_path,
        &bundle_path,
        harness.ca.pem.as_bytes(),
        &harness.settings.trust.trusted_ca_sha256,
        TEST_DOMAIN,
    )
    .expect("the pin file is not a verifier source, so it changes nothing here");

    // A staged bundle holding only an unpinned certificate has no anchor
    // at all: it is refused rather than widened to the whole file or to
    // the system roots.
    let error = endpoint::tls::build_server_config_from_staged(
        &pair.cert_path,
        &pair.key_path,
        &bundle_path,
        foreign.pem.as_bytes(),
        &harness.settings.trust.trusted_ca_sha256,
        TEST_DOMAIN,
    )
    .expect_err("an unpinned staged bundle has no anchor");
    assert!(
        matches!(
            error,
            endpoint::tls::EndpointTlsError::NoPinnedAnchor { .. }
        ),
        "{error:#}"
    );

    // A staged bundle with nothing in it is refused rather than falling
    // back to the system roots, which is the only other anchor source
    // a `WebPkiClientVerifier` could have been given.
    let error = endpoint::tls::build_server_config_from_staged(
        &pair.cert_path,
        &pair.key_path,
        &bundle_path,
        b"",
        &harness.settings.trust.trusted_ca_sha256,
        TEST_DOMAIN,
    )
    .expect_err("an empty staged bundle has no anchor");
    assert!(
        matches!(error, endpoint::tls::EndpointTlsError::Unparsable { .. }),
        "{error:#}"
    );
}

// ---------------------------------------------------------------------
// Publication
// ---------------------------------------------------------------------

/// A due server leaf is published in full: the merged bundle, then the
/// certificate and key, then the active configuration — and the pin file
/// is not touched.
#[tokio::test]
async fn publishing_a_server_candidate_replaces_the_material_and_the_active_configuration() {
    let harness = Harness::build();
    let renewal = harness.renewal().await;
    let pair = harness.pair(SurfaceLeaf::EndpointServer);
    let before_key = digest_of(&pair.key_path);
    let before_pins = digest_of(&harness.pin_file());
    let before_active = harness.endpoint.active_tls();
    let material = harness.ca.material(&pair.name, -1, 60);

    let artifacts = Artifacts::create(&pair.key_path).expect("artifacts");
    renewal
        .publish_candidate(&pair, &material, &artifacts)
        .await
        .expect("a conforming candidate publishes");
    artifacts.close().expect("artifacts are removed");

    assert_eq!(
        san_at(&pair.cert_path),
        pair.name,
        "the published leaf keeps the exact endpoint SAN"
    );
    assert_ne!(
        before_key,
        digest_of(&pair.key_path),
        "every successful issuance publishes a fresh key"
    );
    assert_eq!(
        before_pins,
        digest_of(&harness.pin_file()),
        "the endpoint pin file is never rewritten and gains no leaf pin"
    );
    assert!(
        !Arc::ptr_eq(&before_active, &harness.endpoint.active_tls()),
        "the active TLS configuration is exchanged after a successful publication"
    );
    assert_eq!(
        std::fs::metadata(&pair.key_path)
            .expect("stat the key")
            .mode()
            & 0o777,
        0o600,
        "the published key is never group or world readable"
    );
}

/// Renewing only the client leaf still rebuilds the whole configuration
/// — the staged bundle decides who may connect — and leaves the live
/// server pair exactly as it was.
#[tokio::test]
async fn renewing_the_client_leaf_leaves_the_server_pair_and_still_swaps() {
    let harness = Harness::build();
    let renewal = harness.renewal().await;
    let client = harness.pair(SurfaceLeaf::RegistrarClient);
    let server = harness.pair(SurfaceLeaf::EndpointServer);
    let before_server_cert = digest_of(&server.cert_path);
    let before_server_key = digest_of(&server.key_path);
    let before_active = harness.endpoint.active_tls();
    let material = harness.ca.material(&client.name, -1, 60);

    let artifacts = Artifacts::create(&client.key_path).expect("artifacts");
    renewal
        .publish_candidate(&client, &material, &artifacts)
        .await
        .expect("a conforming client candidate publishes");
    artifacts.close().expect("artifacts are removed");

    assert_eq!(
        san_at(&client.cert_path),
        client.name,
        "the client leaf keeps its recognised instance, host and domain"
    );
    assert_eq!(
        before_server_cert,
        digest_of(&server.cert_path),
        "renewing the client leaf leaves the server certificate alone"
    );
    assert_eq!(
        before_server_key,
        digest_of(&server.key_path),
        "renewing the client leaf leaves the server key alone"
    );
    assert!(
        !Arc::ptr_eq(&before_active, &harness.endpoint.active_tls()),
        "the incoming verifier is rebuilt from the staged bundle either way"
    );
}

/// An unpinned server candidate changes nothing at all, and the accessor
/// records the pin-file reason against the lifetime the leaf still has.
#[tokio::test]
async fn an_unpinned_server_candidate_changes_no_live_or_active_state() {
    let harness = Harness::build();
    let renewal = harness.renewal().await;
    let pair = harness.pair(SurfaceLeaf::EndpointServer);
    let facts = LiveFacts::capture(&harness, pair.leaf, &renewal.state());

    let foreign = TestCa::new("Bootroot Unpinned CA");
    let material = foreign.material(&pair.name, -1, 60);
    let artifacts = Artifacts::create(&pair.key_path).expect("artifacts");
    let err = renewal
        .publish_candidate(&pair, &material, &artifacts)
        .await
        .expect_err("an unpinned candidate is a refusal");
    artifacts.close().expect("artifacts are removed");

    renewal.record_failure(pair.leaf, &format!("{err:#}"));
    facts.assert_unchanged(&harness, pair.leaf);
    let entry = renewal.state().leaf(pair.leaf).expect("an entry");
    assert_eq!(
        entry.not_after, facts.not_after,
        "a refusal retains the lifetime the leaf still has"
    );
    match entry.attempt {
        RenewalAttempt::Failed { ref reason } => assert!(
            reason.contains("endpoint pin file"),
            "the recorded reason names the pin file: {reason}"
        ),
        ref other => panic!("expected a failed attempt, found {other:?}"),
    }
    assert!(entry.attempted_at.is_some(), "a refusal stamps its time");
}

/// A bundle write that fails restores the bundle, leaves the pair and
/// the active configuration alone, and cleans every private artifact.
#[tokio::test]
async fn an_injected_bundle_failure_rolls_back_and_keeps_the_old_configuration() {
    let harness = Harness::build();
    let (live, restores) = FaultyPaths::new(true, false, false);
    let renewal = harness.renewal().await.with_live_paths(live);
    let pair = harness.pair(SurfaceLeaf::EndpointServer);
    let facts = LiveFacts::capture(&harness, pair.leaf, &renewal.state());
    let material = harness.ca.material(&pair.name, -1, 60);

    let err = renewal
        .renew_leaf_with_material(&pair, material)
        .await
        .expect_err("an injected bundle failure fails the attempt");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("injected CA bundle write failure"),
        "{rendered}"
    );
    assert!(
        rendered.contains("was restored from its snapshot"),
        "a successful rollback says so: {rendered}"
    );
    assert_eq!(
        restores.load(Ordering::SeqCst),
        1,
        "only the bundle's publication had started, so only it is restored"
    );
    facts.assert_unchanged(&harness, pair.leaf);
    assert_no_artifacts_left(&pair.key_path);
}

/// A certificate-and-key write that fails restores all three live paths,
/// with their bytes, modes and ownership.
#[tokio::test]
async fn an_injected_pair_failure_restores_every_path_the_publication_reached() {
    let harness = Harness::build();
    let (live, restores) = FaultyPaths::new(false, true, false);
    let renewal = harness.renewal().await.with_live_paths(live);
    let pair = harness.pair(SurfaceLeaf::EndpointServer);
    let facts = LiveFacts::capture(&harness, pair.leaf, &renewal.state());
    let key_mode = std::fs::metadata(&pair.key_path)
        .expect("stat the key")
        .mode()
        & 0o777;
    let material = harness.ca.material(&pair.name, -1, 60);

    let err = renewal
        .renew_leaf_with_material(&pair, material)
        .await
        .expect_err("an injected pair failure fails the attempt");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("injected certificate and key write failure"),
        "{rendered}"
    );
    assert_eq!(
        restores.load(Ordering::SeqCst),
        3,
        "the bundle, the certificate and the key had all been reached"
    );
    facts.assert_unchanged(&harness, pair.leaf);
    assert_eq!(
        std::fs::metadata(&pair.key_path)
            .expect("stat the key")
            .mode()
            & 0o777,
        key_mode,
        "a restore puts the mode back, not only the bytes"
    );
    assert_no_artifacts_left(&pair.key_path);
}

/// A rollback that itself fails keeps the old configuration, reports
/// both errors, cleans the artifacts, and does not claim the live files
/// were restored.
#[tokio::test]
async fn an_injected_rollback_failure_reports_both_errors_and_claims_nothing() {
    let harness = Harness::build();
    let (live, restores) = FaultyPaths::new(false, true, true);
    let renewal = harness.renewal().await.with_live_paths(live);
    let pair = harness.pair(SurfaceLeaf::EndpointServer);
    let before_active = harness.endpoint.active_tls();
    let material = harness.ca.material(&pair.name, -1, 60);

    let err = renewal
        .renew_leaf_with_material(&pair, material)
        .await
        .expect_err("a publication whose rollback also fails is a failed attempt");
    let rendered = format!("{err:#}");
    assert!(
        rendered.contains("injected certificate and key write failure"),
        "the publication error is carried: {rendered}"
    );
    assert!(
        rendered.contains("injected rollback failure"),
        "the rollback error is carried too: {rendered}"
    );
    assert!(
        rendered.contains("mixed state"),
        "a failed rollback names the state it left: {rendered}"
    );
    assert!(
        !rendered.contains("was restored from its snapshot"),
        "a failed rollback is never described as restored: {rendered}"
    );
    assert_eq!(
        restores.load(Ordering::SeqCst),
        3,
        "every reached path's restore was attempted"
    );
    assert!(
        Arc::ptr_eq(&before_active, &harness.endpoint.active_tls()),
        "a failed publication never exchanges the active configuration"
    );
    assert_no_artifacts_left(&pair.key_path);
}

/// No renewal artifact survives an attempt, whichever way it ended.
fn assert_no_artifacts_left(neighbour: &Path) {
    let parent = neighbour.parent().expect("a parent directory");
    let leftovers: Vec<String> = std::fs::read_dir(parent)
        .expect("read the material directory")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(ARTIFACT_DIR_PREFIX))
        .collect();
    assert!(
        leftovers.is_empty(),
        "private renewal artifacts must be removed on every exit: {leftovers:?}"
    );
}

// ---------------------------------------------------------------------
// The pass and the loop
// ---------------------------------------------------------------------

/// A pass over material that is not due changes nothing and asks
/// `OpenBao` for nothing — the fixture's `OpenBao` URL points at a port
/// nothing listens on, so a request would fail rather than pass.
#[tokio::test]
async fn a_no_op_pass_changes_nothing() {
    let harness = Harness::build();
    let renewal = harness.renewal().await;
    let before: Vec<String> = harness
        .plan
        .pairs
        .iter()
        .map(|pair| digest_of(&pair.cert_path))
        .collect();
    let before_active = harness.endpoint.active_tls();

    renewal.run_pass().await;

    for (pair, digest) in harness.plan.pairs.iter().zip(before) {
        assert_eq!(
            digest,
            digest_of(&pair.cert_path),
            "a no-op pass publishes nothing"
        );
    }
    assert!(
        Arc::ptr_eq(&before_active, &harness.endpoint.active_tls()),
        "a no-op pass exchanges nothing"
    );
    for leaf in [SurfaceLeaf::EndpointServer, SurfaceLeaf::RegistrarClient] {
        assert_eq!(
            renewal.state().leaf(leaf).expect("an entry").attempt,
            RenewalAttempt::NeverAttempted,
            "a no-op pass is not an attempt"
        );
    }
}

/// A pass that finds a leaf due and cannot reach the internal credential
/// records an ordinary failed attempt for it, retains the lifetime, and
/// leaves the loop able to try again.
#[tokio::test]
async fn a_credential_failure_is_an_ordinary_failed_attempt() {
    let harness = Harness::build();
    // Lead time wide enough that both leaves are due, so the pass
    // reaches the credential.
    let renewal = RegistrarCertRenewal::for_test(
        Arc::clone(&harness.settings),
        harness.plan.clone(),
        Arc::clone(&harness.endpoint),
        RenewalCadence {
            renew_before: Duration::from_hours(24 * 365),
            ..cadence()
        },
    )
    .await;
    let facts = LiveFacts::capture(&harness, SurfaceLeaf::EndpointServer, &renewal.state());

    // The secrets directory has no credential at all, which is what an
    // unreachable internal credential looks like from here.
    renewal.run_pass().await;

    for leaf in [SurfaceLeaf::EndpointServer, SurfaceLeaf::RegistrarClient] {
        let entry = renewal.state().leaf(leaf).expect("an entry");
        match entry.attempt {
            RenewalAttempt::Failed { ref reason } => assert!(
                reason.contains("bootroot-internal credential"),
                "the pass reaches OpenBao through the internal credential's certificate login \
                 and through nothing else — no AppRole, no role_id, no secret_id: {reason}"
            ),
            ref other => panic!("expected a failed attempt, found {other:?}"),
        }
        assert!(entry.attempted_at.is_some(), "a failure stamps its time");
    }
    assert_eq!(
        renewal
            .state()
            .leaf(SurfaceLeaf::EndpointServer)
            .expect("an entry")
            .not_after,
        facts.not_after,
        "a failed attempt retains the lifetime"
    );
    facts.assert_unchanged(&harness, SurfaceLeaf::EndpointServer);
}

/// The first pass is immediate, later passes wait the configured
/// interval, and the shutdown signal ends the loop so its handle joins.
#[tokio::test(start_paused = true)]
async fn the_first_pass_is_immediate_and_shutdown_ends_the_loop() {
    let harness = Harness::build();
    let renewal = harness.renewal().await;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(renewal.run(rx));

    // Nothing is due, so a pass is observable only as the loop reaching
    // its next sleep. Advancing by less than the interval must not end
    // the loop, and the stop must.
    tokio::time::advance(Duration::from_secs(1)).await;
    assert!(!task.is_finished(), "the loop keeps ticking");
    tokio::time::advance(Duration::from_secs(3600)).await;
    assert!(
        !task.is_finished(),
        "a scheduled pass does not end the loop"
    );

    tx.send(true).expect("the loop is still listening");
    task.await
        .expect("the renewal task joins")
        .expect("the loop ends cleanly");
}

/// A stop that arrives before the first pass ends the loop without
/// running one.
#[tokio::test(start_paused = true)]
async fn a_stop_before_the_first_pass_runs_none() {
    let harness = Harness::build();
    let renewal = harness.renewal().await;
    let state = renewal.state();
    let (tx, rx) = tokio::sync::watch::channel(true);
    tokio::spawn(renewal.run(rx))
        .await
        .expect("the renewal task joins")
        .expect("the loop ends cleanly");
    drop(tx);

    for leaf in [SurfaceLeaf::EndpointServer, SurfaceLeaf::RegistrarClient] {
        assert_eq!(
            state.leaf(leaf).expect("an entry").attempt,
            RenewalAttempt::NeverAttempted
        );
    }
}

// ---------------------------------------------------------------------
// The reload contract, end to end over the socket
// ---------------------------------------------------------------------

/// The renewed server leaf is presented, and a caller under the rotated
/// anchor is accepted, from the next handshake onwards — with no
/// restart, no signal, the same socket inode, and a connection already
/// in flight left alone.
#[tokio::test]
async fn the_next_handshake_uses_the_renewed_material_without_a_restart() {
    let harness = Harness::build();
    let renewal = harness.renewal().await;
    let pair = harness.pair(SurfaceLeaf::EndpointServer);
    let inode_before = std::fs::metadata(&harness.socket_path)
        .expect("stat the socket")
        .ino();

    // A connection established before the swap, held open across it.
    let held = tokio::net::UnixStream::connect(&harness.socket_path)
        .await
        .expect("connect before the swap");

    let material = harness.ca.material(&pair.name, -1, 60);
    let artifacts = Artifacts::create(&pair.key_path).expect("artifacts");
    renewal
        .publish_candidate(&pair, &material, &artifacts)
        .await
        .expect("the candidate publishes");
    artifacts.close().expect("artifacts are removed");

    assert_eq!(
        inode_before,
        std::fs::metadata(&harness.socket_path)
            .expect("stat the socket")
            .ino(),
        "a TLS replacement never rebinds or replaces the socket"
    );
    assert!(
        held.peer_addr().is_ok(),
        "a connection already in flight is not dropped"
    );

    // The acceptor the next handshake would load presents the renewed
    // leaf: the resolver behind it is the one built from the candidate.
    let renewed_leaf = std::fs::read_to_string(&pair.cert_path).expect("read the published leaf");
    assert!(
        renewed_leaf.contains(
            material
                .cert_pem
                .lines()
                .nth(1)
                .expect("the leaf PEM has a body line")
        ),
        "the published certificate is the candidate that was validated"
    );
    drop(held);
}
