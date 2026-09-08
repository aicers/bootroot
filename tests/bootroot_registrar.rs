#![cfg(unix)]
//! The registrar provisioning surface, driven through the real
//! `bootroot` binary.
//!
//! `capabilities` and the two clap exit codes need nothing but the
//! binary. `issue` needs a CA, so this file stands one up: a two-level
//! `rcgen` CA, a mock ACME directory behind a local TLS listener, and
//! the HTTP-01 responder beside it — all on port 0, all in this process.
//! Nothing reaches the network, nothing writes outside a
//! `tempfile::tempdir()`, and no test mutates this process's
//! environment.

use std::io::BufReader;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use bootroot::registrar::internal::{
    InternalAgentConfigParams, InternalPaths, render_internal_agent_config,
};
use bootroot::registrar::{
    REGISTRAR_SURFACE_INSTANCE, recognize_registrar_client, registrar_client_identity,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
    SanType,
};
use tempfile::TempDir;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;
use wiremock::matchers::{method, path as path_matcher};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate, Times};

const TEST_HOST: &str = "bootroot-01";
const TEST_DOMAIN: &str = "corp.example.internal";
const OTHER_DOMAIN: &str = "other.internal";
const TEST_EMAIL: &str = "ops@example.internal";

/// The EAB a deployment provisioned through `bootroot-remote bootstrap`
/// carries in its bootroot-internal registrar configuration.
const TEST_EAB_KID: &str = "registrar-provisioning-eab-kid";
const TEST_EAB_HMAC: &str = "cmVnaXN0cmFyLXByb3Zpc2lvbmluZy1lYWI";

/// clap's exit code for a usage error, the code a caller tells a surface
/// that disagrees from one that has not shipped by.
const USAGE_EXIT: i32 = 2;

/// Where `bootroot init` writes the deployment's CA certificates,
/// relative to the secrets directory.
const CA_CERTS_DIR: &str = "certs";
const CA_ROOT_CERT_FILENAME: &str = "root_ca.crt";
const CA_INTERMEDIATE_CERT_FILENAME: &str = "intermediate_ca.crt";

/// The prefix every per-run staging directory is named under, below the
/// secrets directory.
const STAGING_DIR_PREFIX: &str = "registrar-client-staging";

fn run(args: &[&str]) -> (String, String, i32) {
    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .args(args)
        .output()
        .expect("bootroot binary runs in tests");
    (
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
        output.status.code().unwrap_or(-1),
    )
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .unwrap_or_else(|err| panic!("{} must exist: {err}", path.display()))
        .permissions()
        .mode()
        & 0o777
}

/// Returns every staging directory still sitting below `secrets_dir`.
///
/// Matched on the prefix rather than on one pathname: the directory is
/// named per process, so no run can read back or sweep another's
/// material, and a leftover is found whichever process left it.
fn staging_leftovers(secrets_dir: &Path) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(secrets_dir) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(STAGING_DIR_PREFIX))
        .collect()
}

fn pem_to_der(pem: &str) -> Vec<u8> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("a PEM certificate");
    parsed.contents
}

// ---------------------------------------------------------------------
// capabilities, and the two usage exits
// ---------------------------------------------------------------------

/// The shipped socket unit is what `capabilities` answers on a host that
/// has installed none — and the expected value is read out of that unit
/// rather than spelled here, so the unit and the answer cannot drift.
#[test]
fn capabilities_answers_the_shipped_socket_units_listen_stream() {
    let (stdout, stderr, code) = run(&["registrar", "capabilities", "--json"]);
    assert_eq!(code, 0, "stderr: {stderr}");

    let body: serde_json::Value = serde_json::from_str(stdout.trim()).expect("a JSON body");
    assert_eq!(body["api_version"], "bootroot.registrar.v1");
    assert_eq!(
        body["verbs"],
        serde_json::json!(["registrar.issue", "registrar.mint", "registrar.deregister"])
    );

    let unit = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("systemd")
            .join("bootroot-registrar.socket"),
    )
    .expect("the shipped socket unit is checked in");
    let expected = unit
        .lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("ListenStream="))
        .expect("the shipped unit binds a ListenStream");
    assert_eq!(body["socket_path"], expected);
}

/// The pathname reported is the installed unit's, not a compiled-in
/// literal: a unit binding somewhere else is answered with that.
#[test]
fn capabilities_answers_the_installed_socket_units_listen_stream() {
    let dir = TempDir::new().expect("tempdir");
    let unit = dir.path().join("bootroot-registrar.socket");
    std::fs::write(
        &unit,
        "[Socket]\nListenStream=/run/fixture/registrar.sock\nAccept=no\n",
    )
    .expect("write the fixture unit");

    let (stdout, stderr, code) = run(&[
        "registrar",
        "capabilities",
        "--socket-unit",
        unit.to_str().expect("a UTF-8 path"),
        "--json",
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");

    let body: serde_json::Value = serde_json::from_str(stdout.trim()).expect("a JSON body");
    assert_eq!(body["socket_path"], "/run/fixture/registrar.sock");
}

/// Without `--json` the same answer is a human summary rather than a
/// body, and it still carries every field the machine-readable one does
/// — an operator reading it learns the same three things.
#[test]
fn capabilities_without_json_summarizes_the_same_answer() {
    let dir = TempDir::new().expect("tempdir");
    let unit = dir.path().join("bootroot-registrar.socket");
    std::fs::write(
        &unit,
        "[Socket]\nListenStream=/run/fixture/registrar.sock\nAccept=no\n",
    )
    .expect("write the fixture unit");

    let (stdout, stderr, code) = run(&[
        "registrar",
        "capabilities",
        "--socket-unit",
        unit.to_str().expect("a UTF-8 path"),
    ]);
    assert_eq!(code, 0, "stderr: {stderr}");

    assert!(
        serde_json::from_str::<serde_json::Value>(stdout.trim()).is_err(),
        "without --json the answer is prose, not a body: {stdout}"
    );
    for expected in [
        "bootroot.registrar.v1",
        "/run/fixture/registrar.sock",
        "registrar.issue",
        "registrar.mint",
        "registrar.deregister",
    ] {
        assert!(
            stdout.contains(expected),
            "the summary must name {expected}: {stdout}"
        );
    }
}

/// It answers on a host with no bootroot configuration at all: no
/// `agent.toml`, no state file, no secrets tree, nothing listening. The
/// verb describes the surface, not the runtime.
#[test]
fn capabilities_answers_with_the_endpoint_disabled_and_no_daemon_running() {
    let dir = TempDir::new().expect("tempdir");
    let config = dir.path().join("agent.toml");
    // An explicit, valid, endpoint-disabled configuration sitting in the
    // working directory: `capabilities` reads no configuration at all,
    // so this changes nothing — which is the assertion.
    std::fs::write(
        &config,
        "email = \"ops@example.internal\"\n\
         server = \"https://127.0.0.1:9000/acme/acme/directory\"\n\
         domain = \"corp.example.internal\"\n\
         \n\
         [registrar_endpoint]\n\
         enabled = false\n",
    )
    .expect("write the disabled configuration");

    let output = Command::new(env!("CARGO_BIN_EXE_bootroot"))
        .current_dir(dir.path())
        .args(["registrar", "capabilities", "--json"])
        .output()
        .expect("bootroot binary runs in tests");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body: serde_json::Value =
        serde_json::from_slice(output.stdout.trim_ascii()).expect("a JSON body");
    assert_eq!(body["api_version"], "bootroot.registrar.v1");
    assert!(body["socket_path"].is_string());
}

/// An unknown verb under `registrar` exits with clap's usage code, so a
/// caller can tell a surface that disagrees from one that has not
/// shipped.
#[test]
fn an_unknown_verb_exits_with_claps_usage_code() {
    let (_stdout, stderr, code) = run(&["registrar", "conjure", "--json"]);
    assert_eq!(code, USAGE_EXIT, "stderr: {stderr}");
    assert!(
        stderr
            .to_ascii_lowercase()
            .contains("unrecognized subcommand"),
        "unexpected stderr: {stderr}"
    );
}

/// A missing required flag exits the same way, on both verbs' own
/// required arguments.
#[test]
fn a_missing_required_flag_exits_with_claps_usage_code() {
    let (_stdout, stderr, code) = run(&[
        "registrar",
        "issue",
        "--host",
        TEST_HOST,
        "--domain",
        TEST_DOMAIN,
        "--json",
    ]);
    assert_eq!(code, USAGE_EXIT, "stderr: {stderr}");
    assert!(
        stderr.contains("--cert-path"),
        "the refusal must name the missing flag: {stderr}"
    );
}

/// No flag on this surface takes a composed identity, so the argv a
/// caller pinned against a name-carrying verb is a usage error rather
/// than an issuance under a name bootroot did not compose.
#[test]
fn a_caller_supplied_composed_identity_is_not_a_flag_on_this_surface() {
    let (_stdout, stderr, code) = run(&[
        "registrar",
        "issue",
        "--identity",
        "registrar.bootroot-01.corp.example.internal",
        "--cert-path",
        "/tmp/does-not-matter.pem",
        "--key-path",
        "/tmp/does-not-matter.key",
        "--json",
    ]);
    assert_eq!(code, USAGE_EXIT, "stderr: {stderr}");
    assert!(
        stderr.contains("--identity"),
        "the refusal must name the rejected flag: {stderr}"
    );
}

/// `--host` takes the host's single DNS label, so a composed name passed
/// through it is refused before anything is issued.
#[test]
fn a_composed_name_in_the_host_flag_is_refused() {
    let dir = TempDir::new().expect("tempdir");
    let cert = dir.path().join("registrar-cert.pem");
    let key = dir.path().join("registrar-key.pem");

    let (_stdout, stderr, code) = run(&[
        "registrar",
        "issue",
        "--host",
        "registrar.bootroot-01",
        "--domain",
        TEST_DOMAIN,
        "--cert-path",
        cert.to_str().expect("a UTF-8 path"),
        "--key-path",
        key.to_str().expect("a UTF-8 path"),
        "--json",
    ]);

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("--host"), "unexpected stderr: {stderr}");
    assert!(!cert.exists(), "nothing may be written on a refusal");
    assert!(!key.exists(), "nothing may be written on a refusal");
}

/// Nothing about the daemon's own path handling changes: `capabilities`
/// reads the installed unit, and the configuration table that describes
/// the endpoint still names four material paths and an enable flag and
/// nothing else.
///
/// The destructuring is the assertion. A `socket_path` key added to
/// `[registrar_endpoint]` — a key the daemon could then be pointed at,
/// which this surface exists to avoid introducing — fails to compile
/// here rather than shipping.
#[test]
fn no_configuration_key_names_the_endpoints_socket() {
    let bootroot::config::RegistrarEndpointSettings {
        enabled,
        server_cert_path,
        server_key_path,
        client_cert_path,
        client_key_path,
    } = bootroot::config::RegistrarEndpointSettings::default();

    assert!(!enabled);
    assert!(server_cert_path.is_none());
    assert!(server_key_path.is_none());
    assert!(client_cert_path.is_none());
    assert!(client_key_path.is_none());
}

// ---------------------------------------------------------------------
// A CA, an ACME directory and an HTTP-01 responder
// ---------------------------------------------------------------------

type Issuer = CertifiedIssuer<'static, KeyPair>;

/// A two-level test CA: a self-signed root that certifies an
/// intermediate, which signs every leaf — the shape step-ca presents.
struct TestCa {
    root_pem: String,
    intermediate: Issuer,
    intermediate_pem: String,
}

impl TestCa {
    fn new() -> Self {
        let root_key = KeyPair::generate().expect("root key");
        let root = Issuer::self_signed(ca_params("Bootroot Registrar Test Root"), root_key)
            .expect("self-signed root");
        let intermediate_key = KeyPair::generate().expect("intermediate key");
        let intermediate = Issuer::signed_by(
            ca_params("Bootroot Registrar Test Intermediate"),
            intermediate_key,
            &root,
        )
        .expect("intermediate signed by the root");
        Self {
            root_pem: root.pem(),
            intermediate_pem: intermediate.pem(),
            intermediate,
        }
    }

    /// Signs a CSR the way a CA hands one back over ACME.
    fn sign_csr(&self, csr_der: &[u8]) -> String {
        let der = rustls::pki_types::CertificateSigningRequestDer::from(csr_der.to_vec());
        let request = rcgen::CertificateSigningRequestParams::from_der(&der)
            .expect("parse the CSR the way a CA does");
        request
            .signed_by(&self.intermediate)
            .expect("issue the leaf")
            .pem()
    }

    /// A server leaf for the local TLS listener the ACME directory sits
    /// behind.
    fn server_leaf(&self, name: &str) -> (String, String) {
        let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
        params.is_ca = IsCa::NoCa;
        params.distinguished_name.push(DnType::CommonName, name);
        params.subject_alt_names = vec![SanType::DnsName(
            name.to_string().try_into().expect("a DNS SAN"),
        )];
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::days(1);
        params.not_after = now + time::Duration::days(30);
        let key = KeyPair::generate().expect("leaf key");
        let leaf = params.signed_by(&key, &self.intermediate).expect("leaf");
        (leaf.pem(), key.serialize_pem())
    }

    fn fingerprints(&self) -> Vec<String> {
        [&self.root_pem, &self.intermediate_pem]
            .into_iter()
            .map(|pem| sha256_hex(&pem_to_der(pem)))
            .collect()
    }
}

fn ca_params(common_name: &str) -> CertificateParams {
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
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now - time::Duration::days(1);
    params.not_after = now + time::Duration::days(3650);
    params
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = ring::digest::digest(&ring::digest::SHA256, bytes);
    let mut out = String::with_capacity(64);
    for byte in digest.as_ref() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A local TLS listener forwarding raw HTTP to the mock ACME server.
///
/// `wiremock` offers no TLS listener, and the ACME client refuses a
/// plaintext directory URL, so the flow is exercised over the same TLS
/// client path a real issuance uses.
struct TlsAcmeProxy {
    handle: JoinHandle<()>,
    url: String,
}

impl TlsAcmeProxy {
    async fn start(ca: &TestCa, upstream: &str) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (leaf_pem, key_pem) = ca.server_leaf("localhost");
        let leaf = rustls::pki_types::CertificateDer::from(pem_to_der(&leaf_pem));
        let intermediate =
            rustls::pki_types::CertificateDer::from(pem_to_der(&ca.intermediate_pem));
        let mut reader = BufReader::new(key_pem.as_bytes());
        let key = rustls_pemfile::private_key(&mut reader)
            .expect("the proxy key parses")
            .expect("the proxy key exists");
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![leaf, intermediate], key)
            .expect("the proxy TLS configuration");
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the proxy binds a local port");
        let port = listener.local_addr().expect("the proxy address").port();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let upstream = upstream
            .strip_prefix("http://")
            .expect("wiremock serves HTTP")
            .to_string();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    continue;
                };
                let Ok(mut upstream) = TcpStream::connect(&upstream).await else {
                    return;
                };
                let _ = copy_bidirectional(&mut stream, &mut upstream).await;
            }
        });
        Self {
            handle,
            // `localhost` rather than `127.0.0.1`: the presented leaf
            // names the host it is verified against.
            url: format!("https://localhost:{port}"),
        }
    }
}

impl Drop for TlsAcmeProxy {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Default)]
struct Observed {
    csrs: Mutex<Vec<Vec<u8>>>,
    orders: AtomicUsize,
    /// The decoded payload of every `newAccount` registration, so a test
    /// can assert what the issuance bound its account with.
    accounts: Mutex<Vec<serde_json::Value>>,
}

/// Records the account registration payload and answers as step-ca does.
struct AccountResponder {
    observed: Arc<Observed>,
    location: String,
}

impl Respond for AccountResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        if let Some(payload) = decode_jws_payload(&request.body) {
            self.observed
                .accounts
                .lock()
                .expect("the account log is intact")
                .push(payload);
        }
        ResponseTemplate::new(201)
            .insert_header("replay-nonce", "nonce")
            .insert_header("Location", self.location.as_str())
            .set_body_json(serde_json::json!({ "status": "valid" }))
    }
}

/// Pending on the first fetch, so the HTTP-01 challenge is published,
/// and valid afterwards.
struct AuthzResponder {
    fetches: Mutex<u32>,
    challenge_url: String,
}

impl Respond for AuthzResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let mut fetches = self.fetches.lock().expect("the fetch counter is intact");
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
                    "token": "registrar-provisioning-token",
                    "status": if valid { "valid" } else { "pending" },
                    "error": serde_json::Value::Null,
                }],
            }))
    }
}

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
            .expect("the CSR log is intact")
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

/// Signs the recorded CSR and answers leaf followed by issuer, exactly
/// as step-ca does.
struct CertificateResponder {
    ca: Arc<TestCa>,
    observed: Arc<Observed>,
}

impl Respond for CertificateResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let csrs = self.observed.csrs.lock().expect("the CSR log is intact");
        let Some(csr) = csrs.last() else {
            return ResponseTemplate::new(404);
        };
        let leaf = self.ca.sign_csr(csr);
        ResponseTemplate::new(200)
            .insert_header("replay-nonce", "nonce")
            .set_body_string(format!("{leaf}{}", self.ca.intermediate_pem))
    }
}

struct OrderResponder {
    base: String,
    observed: Arc<Observed>,
}

impl Respond for OrderResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        self.observed.orders.fetch_add(1, Ordering::Relaxed);
        ResponseTemplate::new(201)
            .insert_header("replay-nonce", "nonce")
            .insert_header("location", format!("{}/order/1", self.base).as_str())
            .set_body_json(serde_json::json!({
                "status": "pending",
                "finalize": format!("{}/finalize/1", self.base),
                "authorizations": [format!("{}/authz/1", self.base)],
                "certificate": serde_json::Value::Null,
            }))
    }
}

fn decode_jws_field(body: &[u8], field: &str) -> Option<Vec<u8>> {
    let value = decode_jws_payload(body)?;
    base64_url_decode(value.get(field)?.as_str()?)
}

/// Decodes a JWS envelope's `payload` as JSON.
fn decode_jws_payload(body: &[u8]) -> Option<serde_json::Value> {
    let envelope: serde_json::Value = serde_json::from_slice(body).ok()?;
    let decoded = base64_url_decode(envelope.get("payload")?.as_str()?)?;
    serde_json::from_slice(&decoded).ok()
}

/// Decodes a JWS envelope's `protected` header as JSON.
fn decode_jws_protected(envelope: &serde_json::Value) -> Option<serde_json::Value> {
    let decoded = base64_url_decode(envelope.get("protected")?.as_str()?)?;
    serde_json::from_slice(&decoded).ok()
}

fn base64_url_decode(value: &str) -> Option<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .ok()
}

/// A local ACME directory behind TLS, plus the HTTP-01 responder.
struct AcmeFixture {
    _acme: MockServer,
    _responder: MockServer,
    _proxy: TlsAcmeProxy,
    directory_url: String,
    responder_url: String,
    observed: Arc<Observed>,
}

async fn start_acme(ca: Arc<TestCa>) -> AcmeFixture {
    let acme = MockServer::start().await;
    let responder = MockServer::start().await;
    let proxy = TlsAcmeProxy::start(&ca, &acme.uri()).await;
    let base = proxy.url.clone();
    let observed = Arc::new(Observed::default());

    Mock::given(method("GET"))
        .and(path_matcher("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce": format!("{base}/new-nonce"),
            "newAccount": format!("{base}/new-account"),
            "newOrder": format!("{base}/new-order"),
        })))
        .expect(Times::from(0..))
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
            location: format!("{base}/account/1"),
        })
        .mount(&acme)
        .await;

    Mock::given(method("POST"))
        .and(path_matcher("/new-order"))
        .respond_with(OrderResponder {
            base: base.clone(),
            observed: Arc::clone(&observed),
        })
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
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true })))
        .mount(&responder)
        .await;

    AcmeFixture {
        directory_url: format!("{base}/directory"),
        responder_url: responder.uri(),
        _acme: acme,
        _responder: responder,
        _proxy: proxy,
        observed,
    }
}

// ---------------------------------------------------------------------
// A provisioned bootroot host
// ---------------------------------------------------------------------

/// The state a `bootroot init` leaves behind that `registrar issue`
/// reads: the deployment's CA certificates and the rendered
/// bootroot-internal registrar configuration.
struct Host {
    dir: TempDir,
}

impl Host {
    fn new(ca: &TestCa, acme: &AcmeFixture) -> Self {
        Self::with_eab(ca, acme, None)
    }

    /// The same host, with an `[eab]` in its bootroot-internal registrar
    /// configuration — the state `bootroot-remote bootstrap` leaves on a
    /// deployment whose step-ca requires external account binding.
    fn with_eab(ca: &TestCa, acme: &AcmeFixture, eab: Option<(&str, &str)>) -> Self {
        let dir = TempDir::new().expect("tempdir");
        let secrets = dir.path().join("secrets");

        let certs = secrets.join(CA_CERTS_DIR);
        std::fs::create_dir_all(&certs).expect("the CA certificate directory");
        std::fs::write(certs.join(CA_ROOT_CERT_FILENAME), &ca.root_pem).expect("the root");
        std::fs::write(
            certs.join(CA_INTERMEDIATE_CERT_FILENAME),
            &ca.intermediate_pem,
        )
        .expect("the intermediate");

        let internal = InternalPaths::new(&secrets);
        std::fs::create_dir_all(internal.dir()).expect("the internal directory");
        let eab_hmac = eab.map(|(_, hmac)| bootroot::secret::HmacSecret::from(hmac));
        std::fs::write(
            internal.agent_config(),
            render_internal_agent_config(
                &internal,
                &InternalAgentConfigParams {
                    email: TEST_EMAIL,
                    server: &acme.directory_url,
                    domain: TEST_DOMAIN,
                    hostname: TEST_HOST,
                    responder_url: &acme.responder_url,
                    responder_hmac: &"registrar-provisioning-hmac".into(),
                    eab_kid: eab.map(|(kid, _)| kid),
                    eab_hmac: eab_hmac.as_ref(),
                    trusted_ca_sha256: &ca.fingerprints(),
                },
            ),
        )
        .expect("the internal configuration");
        std::fs::write(
            internal.ca_bundle(),
            format!("{}{}", ca.root_pem, ca.intermediate_pem),
        )
        .expect("the internal private bundle");

        Self { dir }
    }

    fn secrets_dir(&self) -> PathBuf {
        self.dir.path().join("secrets")
    }

    fn material_dir(&self) -> PathBuf {
        self.dir.path().join("registrar")
    }

    fn cert_path(&self) -> PathBuf {
        self.material_dir().join("registrar-cert.pem")
    }

    fn key_path(&self) -> PathBuf {
        self.material_dir().join("registrar-key.pem")
    }

    fn bundle_path(&self) -> PathBuf {
        self.material_dir().join("ca-bundle.pem")
    }

    /// Runs `registrar issue --json` against this host.
    async fn issue(&self, domain: &str) -> (String, String, i32) {
        self.issue_with(domain, true).await
    }

    /// Runs `registrar issue` against this host, with or without
    /// `--json`.
    ///
    /// Awaited on a blocking thread rather than run inline: the local
    /// ACME directory the child dials is a task on *this* runtime, and a
    /// worker parked on `wait(2)` cannot answer it.
    async fn issue_with(&self, domain: &str, json: bool) -> (String, String, i32) {
        let mut args: Vec<String> = vec![
            "registrar".to_string(),
            "issue".to_string(),
            "--host".to_string(),
            TEST_HOST.to_string(),
            "--domain".to_string(),
            domain.to_string(),
            "--cert-path".to_string(),
            self.cert_path().display().to_string(),
            "--key-path".to_string(),
            self.key_path().display().to_string(),
            "--secrets-dir".to_string(),
            self.secrets_dir().display().to_string(),
        ];
        if json {
            args.push("--json".to_string());
        }
        tokio::task::spawn_blocking(move || {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            run(&refs)
        })
        .await
        .expect("the issuance child process is awaited")
    }
}

// ---------------------------------------------------------------------
// issue
// ---------------------------------------------------------------------

/// One issuance writes the certificate, the key and the sibling CA
/// bundle at the modes `service add` establishes; the leaf is the
/// composed identity, is recognized under the deployment's domain and
/// under no other, and its expiry parses as a future RFC 3339 instant.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue_writes_a_recognized_registrar_client_credential() {
    let ca = Arc::new(TestCa::new());
    let acme = start_acme(Arc::clone(&ca)).await;
    let host = Host::new(&ca, &acme);

    let (stdout, stderr, code) = host.issue(TEST_DOMAIN).await;
    assert_eq!(code, 0, "stderr: {stderr}");

    // The response body.
    let body: serde_json::Value = serde_json::from_str(stdout.trim()).expect("a JSON body");
    let expected_identity =
        registrar_client_identity(REGISTRAR_SURFACE_INSTANCE, TEST_HOST, TEST_DOMAIN);
    assert_eq!(body["api_version"], "bootroot.registrar.v1");
    assert_eq!(body["identity"], expected_identity);
    let not_after = body["not_after"].as_str().expect("not_after is a string");
    let not_after =
        time::OffsetDateTime::parse(not_after, &time::format_description::well_known::Rfc3339)
            .expect("not_after parses as RFC 3339");
    assert!(
        not_after > time::OffsetDateTime::now_utc(),
        "the credential's expiry must lie in the future"
    );

    // The three files, at the modes `service add` establishes.
    assert_eq!(mode_of(&host.cert_path()), 0o644);
    assert_eq!(mode_of(&host.key_path()), 0o600);
    assert_eq!(mode_of(&host.bundle_path()), 0o644);

    // The leaf is the composed identity, and the endpoint's own rule
    // accepts it under this deployment's domain and no other.
    let cert_pem = std::fs::read_to_string(host.cert_path()).expect("the certificate");
    let leaf_der = pem_to_der(&cert_pem);
    let identity =
        recognize_registrar_client(&leaf_der, TEST_DOMAIN).expect("the issued leaf is recognized");
    assert_eq!(identity.instance, REGISTRAR_SURFACE_INSTANCE);
    assert_eq!(identity.host, TEST_HOST);
    assert_eq!(identity.domain, TEST_DOMAIN);
    assert!(
        recognize_registrar_client(&leaf_der, OTHER_DOMAIN).is_err(),
        "the leaf must not be recognized under another deployment's domain"
    );

    // The key is a private key and the bundle carries the deployment's
    // anchors, so the trio is usable rather than merely present.
    let key_pem = std::fs::read_to_string(host.key_path()).expect("the key");
    assert!(key_pem.contains("PRIVATE KEY"), "the key file holds a key");
    let bundle = std::fs::read_to_string(host.bundle_path()).expect("the bundle");
    assert!(bundle.contains(&ca.root_pem), "the bundle carries the root");

    // The staging directory is swept: it held a private key that was
    // never published.
    assert!(
        staging_leftovers(&host.secrets_dir()).is_empty(),
        "the staging directory must not survive the run: {:?}",
        staging_leftovers(&host.secrets_dir())
    );

    assert_eq!(acme.observed.orders.load(Ordering::Relaxed), 1);
}

/// Re-invocation re-issues into the same paths and leaves a usable pair:
/// a fresh leaf, a key that is the leaf's, and the bundle beside them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_second_issuance_leaves_a_usable_pair() {
    let ca = Arc::new(TestCa::new());
    let acme = start_acme(Arc::clone(&ca)).await;
    let host = Host::new(&ca, &acme);

    let (_stdout, stderr, code) = host.issue(TEST_DOMAIN).await;
    assert_eq!(code, 0, "stderr: {stderr}");
    let first_cert = std::fs::read_to_string(host.cert_path()).expect("the first certificate");
    let first_key = std::fs::read_to_string(host.key_path()).expect("the first key");

    let (stdout, stderr, code) = host.issue(TEST_DOMAIN).await;
    assert_eq!(code, 0, "stderr: {stderr}");
    let body: serde_json::Value = serde_json::from_str(stdout.trim()).expect("a JSON body");
    assert_eq!(
        body["identity"],
        registrar_client_identity(REGISTRAR_SURFACE_INSTANCE, TEST_HOST, TEST_DOMAIN)
    );

    let second_cert = std::fs::read_to_string(host.cert_path()).expect("the second certificate");
    let second_key = std::fs::read_to_string(host.key_path()).expect("the second key");
    assert_ne!(
        first_key, second_key,
        "every issuance generates a fresh key"
    );
    assert_ne!(first_cert, second_cert, "the leaf is re-issued");

    // Still a pair, still recognized, still at the same modes.
    let leaf_der = pem_to_der(&second_cert);
    recognize_registrar_client(&leaf_der, TEST_DOMAIN).expect("the re-issued leaf is recognized");
    assert!(key_matches_certificate(&second_cert, &second_key));
    assert_eq!(mode_of(&host.cert_path()), 0o644);
    assert_eq!(mode_of(&host.key_path()), 0o600);
    assert_eq!(mode_of(&host.bundle_path()), 0o644);

    assert_eq!(acme.observed.orders.load(Ordering::Relaxed), 2);
}

/// An issuance that cannot complete leaves no half-written pair at the
/// caller's paths: the material is staged and published only once every
/// byte of it is in hand.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failed_issuance_publishes_nothing() {
    let ca = Arc::new(TestCa::new());
    let acme = start_acme(Arc::clone(&ca)).await;
    let host = Host::new(&ca, &acme);

    // The deployment's root is removed, so the trust anchors this
    // issuance runs under cannot be resolved and the ACME path is never
    // reached.
    std::fs::remove_file(
        host.secrets_dir()
            .join(CA_CERTS_DIR)
            .join(CA_ROOT_CERT_FILENAME),
    )
    .expect("remove the root");

    let (_stdout, _stderr, code) = host.issue(TEST_DOMAIN).await;
    assert_eq!(code, 1);
    assert!(!host.cert_path().exists(), "no certificate is published");
    assert!(!host.key_path().exists(), "no key is published");
    assert!(
        staging_leftovers(&host.secrets_dir()).is_empty(),
        "the staging directory must not survive a failure: {:?}",
        staging_leftovers(&host.secrets_dir())
    );
}

/// Without `--json` the issuance reports the identity it composed and
/// the expiry in prose, and publishes the same three files.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn issue_without_json_summarizes_what_it_issued() {
    let ca = Arc::new(TestCa::new());
    let acme = start_acme(Arc::clone(&ca)).await;
    let host = Host::new(&ca, &acme);

    let (stdout, stderr, code) = host.issue_with(TEST_DOMAIN, false).await;
    assert_eq!(code, 0, "stderr: {stderr}");

    assert!(
        serde_json::from_str::<serde_json::Value>(stdout.trim()).is_err(),
        "without --json the answer is prose, not a body: {stdout}"
    );
    let identity = registrar_client_identity(REGISTRAR_SURFACE_INSTANCE, TEST_HOST, TEST_DOMAIN);
    assert!(
        stdout.contains(&identity),
        "the summary must name the composed identity: {stdout}"
    );
    assert!(host.cert_path().exists());
    assert!(host.key_path().exists());
    assert!(host.bundle_path().exists());
}

/// A host that `bootroot init` has not provisioned yet carries no
/// bootroot-internal registrar configuration to take the ACME inputs
/// from. That is a typed refusal naming what is missing, not a
/// half-written pair — the state a provisioning tool finds when it
/// probes too early.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unprovisioned_host_is_refused_before_anything_is_written() {
    let ca = Arc::new(TestCa::new());
    let acme = start_acme(Arc::clone(&ca)).await;
    let host = Host::new(&ca, &acme);

    // The one file `issue` reads its ACME inputs from, removed: the CA
    // certificates beside it are untouched, so this is the internal
    // configuration's absence and nothing else.
    let secrets = host.secrets_dir();
    let internal = InternalPaths::new(&secrets);
    std::fs::remove_file(internal.agent_config()).expect("remove the internal configuration");

    let (_stdout, stderr, code) = host.issue(TEST_DOMAIN).await;

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("bootroot-internal registrar configuration"),
        "the refusal must name what is missing: {stderr}"
    );
    assert!(
        stderr.contains(&internal.agent_config().display().to_string()),
        "the refusal must name the file that is not there: {stderr}"
    );
    // Absence, not malformation. `load_internal_config` cannot tell the
    // two apart — an absent config source deserializes as an empty one —
    // so a host that has never been provisioned would otherwise be
    // reported as a file "expected exactly one profile, found 0", which
    // describes contents no file has.
    assert!(
        !stderr.contains("expected exactly one profile"),
        "an absent configuration must not be reported as a malformed one: {stderr}"
    );
    assert!(!host.cert_path().exists(), "no certificate is published");
    assert!(!host.key_path().exists(), "no key is published");
    assert!(!host.bundle_path().exists(), "no bundle is published");
    assert!(
        staging_leftovers(&host.secrets_dir()).is_empty(),
        "the staging directory must not survive a refusal: {:?}",
        staging_leftovers(&host.secrets_dir())
    );
    assert_eq!(
        acme.observed.orders.load(Ordering::Relaxed),
        0,
        "the ACME path is never reached"
    );
}

/// A configuration that is present but no longer describes the internal
/// identity is a different refusal from an absent one: the file is
/// named, and the reason is what is wrong with its contents.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_malformed_internal_configuration_is_refused_on_its_contents() {
    let ca = Arc::new(TestCa::new());
    let acme = start_acme(Arc::clone(&ca)).await;
    let host = Host::new(&ca, &acme);

    let secrets = host.secrets_dir();
    let internal = InternalPaths::new(&secrets);
    let config = std::fs::read_to_string(internal.agent_config()).expect("the configuration");
    // The one profile removed, leaving a file that parses and describes
    // no identity — the shape an absent file must not be reported as.
    let truncated = config
        .split_once("[[profiles]]")
        .expect("the generated configuration carries a profile")
        .0
        .to_string();
    std::fs::write(internal.agent_config(), truncated).expect("rewrite the configuration");

    let (_stdout, stderr, code) = host.issue(TEST_DOMAIN).await;

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(
        stderr.contains("expected exactly one profile"),
        "a present configuration is refused on its contents: {stderr}"
    );
    assert!(!host.cert_path().exists(), "no certificate is published");
    assert!(!host.key_path().exists(), "no key is published");
    assert_eq!(
        acme.observed.orders.load(Ordering::Relaxed),
        0,
        "the ACME path is never reached"
    );
}

/// A deployment whose step-ca requires external account binding carries
/// an `[eab]` in its bootroot-internal registrar configuration, and that
/// is the one the issuance registers its account with.
///
/// The verb drops `[eab]` from the settings it builds and passes the
/// credentials as an argument instead, so that there is one source for
/// them rather than a second that could go stale invisibly. This asserts
/// the argument arrives: without it, an account registration on a real
/// EAB-requiring step-ca would be rejected, and every assertion in the
/// other issuance tests would still pass.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_configured_eab_binds_the_issuances_account() {
    let ca = Arc::new(TestCa::new());
    let acme = start_acme(Arc::clone(&ca)).await;
    let host = Host::with_eab(&ca, &acme, Some((TEST_EAB_KID, TEST_EAB_HMAC)));

    let (_stdout, stderr, code) = host.issue(TEST_DOMAIN).await;
    assert_eq!(code, 0, "stderr: {stderr}");

    let accounts = acme
        .observed
        .accounts
        .lock()
        .expect("the account log is intact");
    let payload = accounts.first().expect("the account was registered");
    let binding = payload
        .get("externalAccountBinding")
        .expect("the registration carries an externalAccountBinding");
    let protected =
        decode_jws_protected(binding).expect("the binding's protected header decodes as JSON");
    assert_eq!(
        protected["kid"], TEST_EAB_KID,
        "the binding names the configured EAB key: {protected}"
    );
    assert_eq!(
        payload["contact"],
        serde_json::json!([format!("mailto:{TEST_EMAIL}")]),
        "the contact is the deployment's, from the same configuration"
    );
}

/// With no `[eab]` in the configuration the registration carries no
/// binding, so the field is not fabricated on a deployment that
/// registered none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unconfigured_eab_binds_nothing() {
    let ca = Arc::new(TestCa::new());
    let acme = start_acme(Arc::clone(&ca)).await;
    let host = Host::new(&ca, &acme);

    let (_stdout, stderr, code) = host.issue(TEST_DOMAIN).await;
    assert_eq!(code, 0, "stderr: {stderr}");

    let accounts = acme
        .observed
        .accounts
        .lock()
        .expect("the account log is intact");
    let payload = accounts.first().expect("the account was registered");
    assert!(
        payload.get("externalAccountBinding").is_none(),
        "no binding is sent when none is configured: {payload}"
    );
}

/// Returns whether the key is the certificate's, by comparing the
/// leaf's public key with the one the private key derives.
fn key_matches_certificate(cert_pem: &str, key_pem: &str) -> bool {
    let der = pem_to_der(cert_pem);
    let (_, leaf) = x509_parser::parse_x509_certificate(&der).expect("the leaf parses");
    let key = rcgen::KeyPair::from_pem(key_pem).expect("the key parses");
    leaf.public_key().raw == rcgen::PublicKeyData::subject_public_key_info(&key)
}
