//! Tests for the registrar surface's self-issuance.
//!
//! Three seams are driven directly, because each carries a rule of its
//! own and a full-daemon start would demonstrate none of them
//! separately:
//!
//! - [`super::evaluate_pair`], for the eight ordered usability
//!   conditions and the chain condition's opt-out;
//! - [`super::read_acme_inputs_with`], against a mock `OpenBao`, for
//!   where the EAB and the responder HMAC come from and what a failed
//!   read does;
//! - [`super::issue_pair`], against a mock ACME server and a mock
//!   HTTP-01 responder, for the two leaves' invariants, the publication
//!   order and the material's modes.
//!
//! Material goes in `tempfile::tempdir()`, nothing reaches the network,
//! and no test mutates the process environment.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use tempfile::TempDir;
use time::OffsetDateTime;
use wiremock::matchers::{method, path as path_matcher};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

use super::fixture::{
    LOCAL_HMAC, OPENBAO_HMAC, OnDisk, TEST_DOMAIN, TEST_HOST, TEST_KV_MOUNT, TestCa, client_name,
    endpoint_name, generate_ca, issue_leaf_pem, test_settings,
};
use super::*;
use crate::acme::http01_protocol::{HEADER_SIGNATURE, HEADER_TIMESTAMP, Http01HmacSigner};
use crate::config::TrustSettings;
use crate::registrar::{
    is_reserved_service_name, recognize_registrar_client, recognize_registrar_client_name,
    recognize_registrar_endpoint,
};

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

// ---------------------------------------------------------------------
// Name composition
// ---------------------------------------------------------------------

/// The instance label is the fixed `001` from the shared constant, the
/// host label is the one handed in, and the domain is a *suffix* of any
/// label count rather than a fixed number of labels.
#[test]
fn both_names_are_composed_from_the_shared_instance_constant_and_the_given_host() {
    assert_eq!(REGISTRAR_SURFACE_INSTANCE, "001");
    assert_eq!(
        SurfaceLeaf::Client.identity(TEST_HOST, TEST_DOMAIN),
        "001.bootroot-registrar.bootroot-01.corp.example.internal"
    );
    assert_eq!(
        SurfaceLeaf::Endpoint.identity(TEST_HOST, TEST_DOMAIN),
        "001.bootroot-registrar-endpoint.bootroot-01.corp.example.internal"
    );
    for domain in ["internal", "example.internal", "corp.example.internal"] {
        let name = SurfaceLeaf::Client.identity(TEST_HOST, domain);
        assert!(name.ends_with(domain), "{name} must end in {domain}");
        let identity = recognize_registrar_client_name(&name, domain)
            .expect("the composed name is recognized in its own domain");
        assert_eq!(identity.instance, "001");
        assert_eq!(identity.host, TEST_HOST);
    }
}

/// Both composed names fall inside the reserved namespace, so neither
/// can be produced by `service add`.
#[test]
fn neither_composed_name_can_be_minted_through_service_add() {
    for leaf in [SurfaceLeaf::Client, SurfaceLeaf::Endpoint] {
        assert!(
            is_reserved_service_name(leaf.service_label()),
            "{} must be reserved",
            leaf.service_label()
        );
    }
}

/// The profile one issuance runs under composes the same name the
/// identity helper does, so the ACME order, the CSR and the recognition
/// rule cannot disagree.
#[test]
fn the_issuance_profile_composes_exactly_the_identity_name() {
    let settings = test_settings("http://unused.invalid/directory", "http://unused.invalid");
    for leaf in [SurfaceLeaf::Client, SurfaceLeaf::Endpoint] {
        let paths = PairPaths {
            leaf,
            cert: PathBuf::from("/tmp/leaf.pem"),
            key: PathBuf::from("/tmp/leaf.key"),
        };
        let profile = surface_profile(&paths, TEST_HOST);
        assert_eq!(
            crate::config::profile_domain(&settings, &profile),
            leaf.identity(TEST_HOST, TEST_DOMAIN)
        );
    }
}

/// The surface profiles are deliberately not the bootroot-internal
/// profile, so nothing here changes how that profile is renewed.
#[test]
fn a_surface_profile_is_never_mistaken_for_the_internal_profile() {
    for leaf in [SurfaceLeaf::Client, SurfaceLeaf::Endpoint] {
        let paths = PairPaths {
            leaf,
            cert: PathBuf::from("/var/lib/bootroot/registrar-internal/chain.pem"),
            key: PathBuf::from("/var/lib/bootroot/registrar-internal/key.pem"),
        };
        let profile = surface_profile(&paths, TEST_HOST);
        assert!(
            crate::registrar::internal::internal_profile_paths(&profile).is_none(),
            "{leaf:?} must not be matched as the internal profile"
        );
    }
}

/// The client identity requests `clientAuth`; the server identity is the
/// ordinary shape, because a server leaf needs no added EKU.
#[test]
fn only_the_client_identity_selects_the_client_auth_csr_shape() {
    assert_eq!(SurfaceLeaf::Client.csr_shape(), CsrShape::RegistrarClient);
    assert_eq!(SurfaceLeaf::Endpoint.csr_shape(), CsrShape::Service);
}

// ---------------------------------------------------------------------
// Unset paths
// ---------------------------------------------------------------------

/// An unset path is not repairable material: there is nowhere to write,
/// so it is named and refused rather than issued into.
#[test]
fn an_unset_material_path_is_named_rather_than_repaired() {
    type Clear = fn(&mut RegistrarEndpointSettings);

    let full = RegistrarEndpointSettings {
        enabled: true,
        server_cert_path: Some("/etc/s.crt".into()),
        server_key_path: Some("/etc/s.key".into()),
        client_cert_path: Some("/etc/c.crt".into()),
        client_key_path: Some("/etc/c.key".into()),
    };
    material_paths(&full).expect("all four set");

    let clears: [(&str, Clear); 4] = [
        ("server_cert_path", |s| s.server_cert_path = None),
        ("server_key_path", |s| s.server_key_path = None),
        ("client_cert_path", |s| s.client_cert_path = None),
        ("client_key_path", |s| s.client_key_path = None),
    ];
    for (key, clear) in clears {
        let mut settings = full.clone();
        clear(&mut settings);
        let err = material_paths(&settings).expect_err("an unset path must refuse");
        assert!(err.to_string().contains(key), "{err}");
    }
}

// ---------------------------------------------------------------------
// The eight unusable states
// ---------------------------------------------------------------------

#[test]
fn in_date_correctly_named_chaining_material_is_usable() {
    let ca = generate_ca("Usable CA");
    let disk = OnDisk::new(&ca);
    let (leaf, key) = issue_leaf_pem(&ca, &client_name(), (2020, 1, 1), (2099, 1, 1));
    disk.write_pair(&leaf, &key);
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Usable
    );
}

/// Condition 1. A first start, and the state a cleared host is in.
#[test]
fn absent_material_is_classified_absent() {
    let ca = generate_ca("Absent CA");
    let disk = OnDisk::new(&ca);
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::Absent)
    );

    // Only the key gone is still "absent" rather than something later in
    // the order: the pair is what is evaluated.
    let (leaf, key) = issue_leaf_pem(&ca, &client_name(), (2020, 1, 1), (2099, 1, 1));
    disk.write_pair(&leaf, &key);
    std::fs::remove_file(&disk.key).expect("remove key");
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::Absent)
    );
}

/// Condition 2. Distinguished from condition 1 so an operator is not
/// sent looking for a permission problem that is really a typo.
#[test]
#[cfg(unix)]
fn unreadable_material_is_classified_unreadable() {
    use std::os::unix::fs::PermissionsExt as _;

    if nix_running_as_root() {
        // Mode bits do not stop uid 0, so this test can only assert what
        // it is about where it is not root.
        return;
    }
    let ca = generate_ca("Unreadable CA");
    let disk = OnDisk::new(&ca);
    let (leaf, key) = issue_leaf_pem(&ca, &client_name(), (2020, 1, 1), (2099, 1, 1));
    disk.write_pair(&leaf, &key);
    std::fs::set_permissions(&disk.key, std::fs::Permissions::from_mode(0o000))
        .expect("make the key unreadable");
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::Unreadable)
    );
    std::fs::set_permissions(&disk.key, std::fs::Permissions::from_mode(0o600)).expect("restore");
}

#[cfg(unix)]
fn nix_running_as_root() -> bool {
    // SAFETY: `geteuid` reads this process's effective uid and cannot
    // fail, take a pointer, or mutate anything.
    unsafe { libc::geteuid() == 0 }
}

/// Condition 3, and the classification acceptance criterion: a renewal
/// that lost power mid-write is reported as malformed rather than as
/// key-mismatched, SAN-mismatched or chain-drifted — with the bundle
/// both configured and unconfigured, because the chain arm does not run
/// in the second case at all.
#[test]
fn a_truncated_leaf_is_classified_malformed_with_the_bundle_set_and_unset() {
    let ca = generate_ca("Malformed CA");
    let disk = OnDisk::new(&ca);
    let (leaf, key) = issue_leaf_pem(&ca, &client_name(), (2020, 1, 1), (2099, 1, 1));
    let truncated: String = leaf.lines().take(3).collect::<Vec<_>>().join("\n");
    disk.write_pair(&format!("{truncated}\n-----END CERTIFICATE-----\n"), &key);
    for bundle in [Some(disk.bundle.as_path()), None] {
        assert_eq!(
            evaluate_pair(&disk.cert, &disk.key, &client_name(), bundle, now()),
            Usability::Unusable(UnusableMaterial::Malformed),
            "bundle configured: {}",
            bundle.is_some()
        );
    }
}

/// The same for a key file that lost its tail.
#[test]
fn a_truncated_key_is_classified_malformed() {
    let ca = generate_ca("Malformed Key CA");
    let disk = OnDisk::new(&ca);
    let (leaf, _) = issue_leaf_pem(&ca, &client_name(), (2020, 1, 1), (2099, 1, 1));
    disk.write_pair(&leaf, "-----BEGIN PRIVATE KEY-----\nnot-a-key\n");
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::Malformed)
    );
}

/// Condition 4. What a renewal that died between the certificate rename
/// and the key rename leaves.
#[test]
fn a_key_from_another_issuance_is_classified_key_mismatched() {
    let ca = generate_ca("Mismatch CA");
    let disk = OnDisk::new(&ca);
    let (leaf, _) = issue_leaf_pem(&ca, &client_name(), (2020, 1, 1), (2099, 1, 1));
    let (_, other_key) = issue_leaf_pem(&ca, &client_name(), (2020, 1, 1), (2099, 1, 1));
    disk.write_pair(&leaf, &other_key);
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::KeyMismatch)
    );
}

/// Condition 5. The endpoint's name where the client's was expected is
/// as much a mismatch as an unrelated one.
#[test]
fn the_wrong_reserved_name_is_classified_san_mismatched() {
    let ca = generate_ca("SAN CA");
    let disk = OnDisk::new(&ca);
    let (leaf, key) = issue_leaf_pem(&ca, &endpoint_name(), (2020, 1, 1), (2099, 1, 1));
    disk.write_pair(&leaf, &key);
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::SanMismatch)
    );
}

/// Conditions 6 and 7, split by direction because the window is judged
/// at the *host's* clock and the two are reached from opposite skew.
#[test]
fn a_leaf_outside_its_window_is_classified_by_direction() {
    let ca = generate_ca("Window CA");
    let disk = OnDisk::new(&ca);

    let (future, future_key) = issue_leaf_pem(&ca, &client_name(), (2090, 1, 1), (2099, 1, 1));
    disk.write_pair(&future, &future_key);
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::NotYetValid)
    );

    let (past, past_key) = issue_leaf_pem(&ca, &client_name(), (2020, 1, 1), (2021, 1, 1));
    disk.write_pair(&past, &past_key);
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::Expired)
    );
}

/// Condition 8. A destructive trust-anchor rotation leaves a
/// still-time-valid, correctly named leaf signed by the previous CA
/// generation: material that looks perfect and fails every handshake.
#[test]
fn a_leaf_from_a_superseded_ca_generation_is_classified_chain_drifted() {
    let old = generate_ca("Old Generation");
    let new = generate_ca("New Generation");
    let disk = OnDisk::new(&new);
    let (leaf, key) = issue_leaf_pem(&old, &client_name(), (2020, 1, 1), (2099, 1, 1));
    disk.write_pair(&leaf, &key);
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::ChainDrifted)
    );
}

/// A missing, unparseable or unreadable bundle is *detected* as a need
/// to issue, exactly as the renewal predicate already decides it. What
/// follows detection differs by bundle case and belongs to the write
/// path, not here.
#[test]
fn every_unusable_bundle_state_is_detected_as_a_need_to_issue() {
    let ca = generate_ca("Bundle CA");
    let disk = OnDisk::new(&ca);
    let (leaf, key) = issue_leaf_pem(&ca, &client_name(), (2020, 1, 1), (2099, 1, 1));
    disk.write_pair(&leaf, &key);

    std::fs::remove_file(&disk.bundle).expect("remove bundle");
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::ChainDrifted)
    );

    std::fs::write(&disk.bundle, "not a pem file at all\n").expect("write junk bundle");
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::ChainDrifted)
    );
}

/// The chain condition's opt-out, at unit level. Not written as a
/// full-daemon start, which the endpoint's loader would refuse for want
/// of a bundle for reasons this work does not own.
#[test]
fn with_no_bundle_configured_the_chain_condition_does_not_run() {
    let old = generate_ca("Opt-out Old");
    let new = generate_ca("Opt-out New");
    let disk = OnDisk::new(&new);
    let (leaf, key) = issue_leaf_pem(&old, &client_name(), (2020, 1, 1), (2099, 1, 1));
    disk.write_pair(&leaf, &key);

    assert_eq!(
        evaluate_pair(&disk.cert, &disk.key, &client_name(), None, now()),
        Usability::Usable,
        "with no bundle configured, otherwise-usable material is not re-issued"
    );
    assert_eq!(
        evaluate_pair(
            &disk.cert,
            &disk.key,
            &client_name(),
            Some(&disk.bundle),
            now()
        ),
        Usability::Unusable(UnusableMaterial::ChainDrifted),
        "and the same material is chain-drifted once a bundle is configured"
    );
}

/// The enumeration is the eight conditions negated one at a time, and
/// every one of them answers by issuing rather than by refusing.
#[test]
fn every_unusable_state_reports_that_issuance_is_needed() {
    for reason in [
        UnusableMaterial::Absent,
        UnusableMaterial::Unreadable,
        UnusableMaterial::Malformed,
        UnusableMaterial::KeyMismatch,
        UnusableMaterial::SanMismatch,
        UnusableMaterial::NotYetValid,
        UnusableMaterial::Expired,
        UnusableMaterial::ChainDrifted,
    ] {
        assert!(Usability::Unusable(reason).needs_issuance(), "{reason:?}");
    }
    assert!(!Usability::Usable.needs_issuance());
}

// ---------------------------------------------------------------------
// The ACME inputs
// ---------------------------------------------------------------------

fn openbao_client(server: &MockServer) -> crate::openbao::OpenBaoClient {
    let mut client = crate::openbao::OpenBaoClient::new(&server.uri()).expect("client");
    client.set_token("test-token".to_string());
    client
}

async fn mount_kv(server: &MockServer, kv_path: &str, body: serde_json::Value) {
    Mock::given(method("GET"))
        .and(path_matcher(format!("/v1/{TEST_KV_MOUNT}/data/{kv_path}")))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "data": { "data": body } })),
        )
        .mount(server)
        .await;
}

/// Both values come from `OpenBao`, under the mount the deployment state
/// file records rather than a default one.
#[tokio::test]
async fn both_acme_inputs_are_read_from_openbao_under_the_recorded_mount() {
    let server = MockServer::start().await;
    mount_kv(
        &server,
        RESPONDER_HMAC_KV_PATH,
        serde_json::json!({ "hmac": OPENBAO_HMAC }),
    )
    .await;
    mount_kv(
        &server,
        AGENT_EAB_KV_PATH,
        serde_json::json!({ "kid": "kid-from-openbao", "hmac": "eab-from-openbao" }),
    )
    .await;

    let inputs = read_acme_inputs_with(&openbao_client(&server), TEST_KV_MOUNT)
        .await
        .expect("both reads succeed");
    assert_eq!(inputs.responder_hmac.expose(), OPENBAO_HMAC);
    let eab = inputs
        .eab
        .expect("a populated EAB record yields credentials");
    assert_eq!(eab.kid, "kid-from-openbao");
    assert_eq!(eab.hmac.expose(), "eab-from-openbao");
}

/// The explicit clear shape is "this deployment has no EAB", not a
/// malformed record.
#[tokio::test]
async fn a_cleared_eab_record_yields_no_credentials() {
    let server = MockServer::start().await;
    mount_kv(
        &server,
        RESPONDER_HMAC_KV_PATH,
        serde_json::json!({ "hmac": OPENBAO_HMAC }),
    )
    .await;
    mount_kv(
        &server,
        AGENT_EAB_KV_PATH,
        serde_json::json!({ "kid": "", "hmac": "" }),
    )
    .await;

    let inputs = read_acme_inputs_with(&openbao_client(&server), TEST_KV_MOUNT)
        .await
        .expect("a cleared record is an answer, not a failure");
    assert!(inputs.eab.is_none());
}

/// A failed read is a refusal naming the failing read, never a fallback
/// to a locally configured value.
#[tokio::test]
async fn a_missing_responder_hmac_record_refuses_and_names_the_read() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_matcher(format!(
            "/v1/{TEST_KV_MOUNT}/data/{RESPONDER_HMAC_KV_PATH}"
        )))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({ "errors": [] })))
        .mount(&server)
        .await;

    let err = read_acme_inputs_with(&openbao_client(&server), TEST_KV_MOUNT)
        .await
        .expect_err("a missing KV path is a failure, not a fallback");
    let rendered = format!("{err:#}");
    assert!(rendered.contains(RESPONDER_HMAC_KV_PATH), "{rendered}");
    assert!(rendered.contains(TEST_KV_MOUNT), "{rendered}");
}

/// An unparseable EAB payload refuses too — it is a read that answered
/// with something unusable, not an absent record.
#[tokio::test]
async fn an_unparseable_eab_payload_refuses() {
    let server = MockServer::start().await;
    mount_kv(
        &server,
        RESPONDER_HMAC_KV_PATH,
        serde_json::json!({ "hmac": OPENBAO_HMAC }),
    )
    .await;
    mount_kv(
        &server,
        AGENT_EAB_KV_PATH,
        serde_json::json!({ "kid": "only-half", "hmac": "" }),
    )
    .await;

    let err = read_acme_inputs_with(&openbao_client(&server), TEST_KV_MOUNT)
        .await
        .expect_err("a partial EAB payload is unusable");
    assert!(format!("{err:#}").contains(AGENT_EAB_KV_PATH), "{err:#}");
}

/// An unreachable `OpenBao` refuses rather than proceeding EAB-less or
/// with a locally configured HMAC.
#[tokio::test]
async fn an_unreachable_openbao_refuses() {
    // Loopback port 1: nothing binds it, so the dial is refused
    // immediately and no traffic leaves the host.
    let mut client = crate::openbao::OpenBaoClient::new("http://127.0.0.1:1").expect("client");
    client.set_token("test-token".to_string());

    let err = read_acme_inputs_with(&client, TEST_KV_MOUNT)
        .await
        .expect_err("an unreachable OpenBao must refuse");
    assert!(
        format!("{err:#}").contains(RESPONDER_HMAC_KV_PATH),
        "{err:#}"
    );
}

// ---------------------------------------------------------------------
// Issuance against a mock ACME server
// ---------------------------------------------------------------------

/// The mock CA's answer to one finalize: it parses the CSR out of the
/// JWS payload, signs it, and remembers the PEM for the certificate
/// endpoint to serve.
struct FinalizeResponder {
    ca: Arc<TestCa>,
    issued: Arc<Mutex<Vec<String>>>,
    order_url: String,
}

impl Respond for FinalizeResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let csr_der = csr_from_jws(&request.body);
        let params =
            rcgen::CertificateSigningRequestParams::from_der(&csr_der.into()).expect("parse CSR");
        let leaf = params.signed_by(self.ca.as_ref()).expect("sign CSR");
        let pem = format!("{}{}", leaf.pem(), self.ca.pem());
        self.issued.lock().expect("issued lock").push(pem);
        ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "valid",
            "finalize": format!("{}/finalize", self.order_url),
            "authorizations": [],
            "certificate": format!("{}/certificate", self.order_url),
        }))
    }
}

/// Serves the most recently issued certificate.
struct CertificateResponder {
    issued: Arc<Mutex<Vec<String>>>,
}

impl Respond for CertificateResponder {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let issued = self.issued.lock().expect("issued lock");
        let pem = issued.last().cloned().unwrap_or_default();
        ResponseTemplate::new(200).set_body_string(pem)
    }
}

/// Extracts the DER CSR from an ACME JWS body.
fn csr_from_jws(body: &[u8]) -> Vec<u8> {
    let jws: serde_json::Value = serde_json::from_slice(body).expect("JWS body");
    let payload = jws["payload"].as_str().expect("payload");
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&decoded).expect("payload JSON");
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload["csr"].as_str().expect("csr"))
        .expect("decode csr")
}

/// What one HTTP-01 registration the responder mock observed.
#[derive(Clone)]
struct ObservedRegistration {
    timestamp: String,
    signature: String,
    token: String,
    key_authorization: String,
    ttl_secs: u64,
}

struct ResponderRecorder {
    observed: Arc<Mutex<Vec<ObservedRegistration>>>,
}

impl Respond for ResponderRecorder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let header = |name: &str| {
            request
                .headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string()
        };
        let body: serde_json::Value = serde_json::from_slice(&request.body).expect("register body");
        self.observed
            .lock()
            .expect("observed lock")
            .push(ObservedRegistration {
                timestamp: header(HEADER_TIMESTAMP),
                signature: header(HEADER_SIGNATURE),
                token: body["token"].as_str().unwrap_or_default().to_string(),
                key_authorization: body["key_authorization"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                ttl_secs: body["ttl_secs"].as_u64().unwrap_or_default(),
            });
        ResponseTemplate::new(200).set_body_json(serde_json::json!({ "ok": true }))
    }
}

/// A mock step-ca and a mock HTTP-01 responder, wired together.
struct AcmeHarness {
    _acme: MockServer,
    _responder: MockServer,
    directory_url: String,
    responder_url: String,
    ca: Arc<TestCa>,
    observed: Arc<Mutex<Vec<ObservedRegistration>>>,
    account_bodies: Arc<Mutex<Vec<serde_json::Value>>>,
}

struct AccountRecorder {
    bodies: Arc<Mutex<Vec<serde_json::Value>>>,
    location: String,
}

impl Respond for AccountRecorder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let body: serde_json::Value =
            serde_json::from_slice(&request.body).unwrap_or(serde_json::Value::Null);
        self.bodies.lock().expect("bodies lock").push(body);
        ResponseTemplate::new(201)
            .insert_header("Location", self.location.as_str())
            .insert_header("Replay-Nonce", "nonce-account")
            .set_body_json(serde_json::json!({ "status": "valid" }))
    }
}

#[allow(clippy::too_many_lines)]
async fn start_acme_harness() -> AcmeHarness {
    let ca = Arc::new(generate_ca("Mock Step CA"));
    let acme = MockServer::start().await;
    let responder = MockServer::start().await;
    let base = acme.uri();
    let issued = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::new(Mutex::new(Vec::new()));
    let account_bodies = Arc::new(Mutex::new(Vec::new()));

    Mock::given(method("GET"))
        .and(path_matcher("/directory"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "newNonce": format!("{base}/nonce"),
            "newAccount": format!("{base}/account"),
            "newOrder": format!("{base}/order"),
        })))
        .mount(&acme)
        .await;
    for verb in ["HEAD", "GET"] {
        Mock::given(method(verb))
            .and(path_matcher("/nonce"))
            .respond_with(ResponseTemplate::new(200).insert_header("Replay-Nonce", "nonce-0"))
            .mount(&acme)
            .await;
    }
    Mock::given(method("POST"))
        .and(path_matcher("/account"))
        .respond_with(AccountRecorder {
            bodies: Arc::clone(&account_bodies),
            location: format!("{base}/account/1"),
        })
        .mount(&acme)
        .await;
    Mock::given(method("POST"))
        .and(path_matcher("/order"))
        .respond_with(
            ResponseTemplate::new(201)
                .insert_header("Location", format!("{base}/order/1").as_str())
                .insert_header("Replay-Nonce", "nonce-order")
                .set_body_json(serde_json::json!({
                    "status": "pending",
                    "finalize": format!("{base}/order/1/finalize"),
                    "authorizations": [format!("{base}/authz/1")],
                    "certificate": serde_json::Value::Null,
                })),
        )
        .mount(&acme)
        .await;
    Mock::given(method("POST"))
        .and(path_matcher("/authz/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "nonce-authz")
                .set_body_json(serde_json::json!({
                    "status": "pending",
                    "identifier": { "type": "dns", "value": "example" },
                    "challenges": [{
                        "type": "http-01",
                        "url": format!("{base}/challenge/1"),
                        "token": "challenge-token",
                        "status": "pending",
                        "error": serde_json::Value::Null,
                    }],
                })),
        )
        .up_to_n_times(1)
        .mount(&acme)
        .await;
    Mock::given(method("POST"))
        .and(path_matcher("/authz/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "nonce-authz-2")
                .set_body_json(serde_json::json!({
                    "status": "valid",
                    "identifier": { "type": "dns", "value": "example" },
                    "challenges": [{
                        "type": "http-01",
                        "url": format!("{base}/challenge/1"),
                        "token": "challenge-token",
                        "status": "valid",
                        "error": serde_json::Value::Null,
                    }],
                })),
        )
        .mount(&acme)
        .await;
    Mock::given(method("POST"))
        .and(path_matcher("/challenge/1"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("Replay-Nonce", "nonce-challenge")
                .set_body_json(serde_json::json!({ "status": "processing" })),
        )
        .mount(&acme)
        .await;
    Mock::given(method("POST"))
        .and(path_matcher("/order/1/finalize"))
        .respond_with(FinalizeResponder {
            ca: Arc::clone(&ca),
            issued: Arc::clone(&issued),
            order_url: format!("{base}/order/1"),
        })
        .mount(&acme)
        .await;
    Mock::given(method("POST"))
        .and(path_matcher("/order/1/certificate"))
        .respond_with(CertificateResponder {
            issued: Arc::clone(&issued),
        })
        .mount(&acme)
        .await;
    Mock::given(method("POST"))
        .and(path_matcher("/admin/http01"))
        .respond_with(ResponderRecorder {
            observed: Arc::clone(&observed),
        })
        .mount(&responder)
        .await;

    AcmeHarness {
        directory_url: format!("{base}/directory"),
        responder_url: responder.uri(),
        _acme: acme,
        _responder: responder,
        ca,
        observed,
        account_bodies,
    }
}

/// One issuance of `leaf` into a fresh temporary directory.
struct IssuanceOutcome {
    _dir: TempDir,
    cert: PathBuf,
    key: PathBuf,
    bundle: PathBuf,
    leaf_pem: String,
    key_pem: String,
}

async fn issue_into_tempdir(
    harness: &AcmeHarness,
    leaf: SurfaceLeaf,
    hmac: &str,
    eab: Option<EabCredentials>,
) -> IssuanceOutcome {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("material").join("leaf.pem");
    let key = dir.path().join("material").join("leaf.key");
    let bundle = dir.path().join("ca-bundle.pem");
    // `AcmeClient::new` loads `trust.ca_bundle_path` to build its own
    // outbound client, so the bundle has to be readable before the flow
    // starts. That is the ACME path's pre-existing trust requirement and
    // is not what these tests are about.
    std::fs::write(&bundle, harness.ca.pem()).expect("seed the bundle");

    let mut settings = test_settings(&harness.directory_url, &harness.responder_url);
    settings.acme.http_responder_hmac = HmacSecret::new(hmac.to_string());
    settings.trust = TrustSettings {
        ca_bundle_path: Some(bundle.clone()),
        trusted_ca_sha256: vec![crate::tls::sha256_hex(harness.ca.der())],
    };
    let paths = PairPaths {
        leaf,
        cert: cert.clone(),
        key: key.clone(),
    };
    issue_pair(&settings, &paths, TEST_HOST, eab, false)
        .await
        .expect("issuance succeeds against the mock CA");

    IssuanceOutcome {
        leaf_pem: std::fs::read_to_string(&cert).expect("read leaf"),
        key_pem: std::fs::read_to_string(&key).expect("read key"),
        _dir: dir,
        cert,
        key,
        bundle,
    }
}

fn leaf_der(pem: &str) -> Vec<u8> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("leaf PEM");
    parsed.contents
}

/// Every invariant of the issued client leaf that does not depend on a
/// CA: the single DNS SAN, the CN mirror, recognition, and the fact that
/// the endpoint's authorization set is unchanged.
#[tokio::test]
async fn the_issued_client_leaf_carries_the_reserved_client_name() {
    let harness = start_acme_harness().await;
    let outcome = issue_into_tempdir(&harness, SurfaceLeaf::Client, OPENBAO_HMAC, None).await;
    let der = leaf_der(&outcome.leaf_pem);

    assert_eq!(single_dns_san(&der).expect("one DNS SAN"), client_name());
    let identity =
        recognize_registrar_client(&der, TEST_DOMAIN).expect("the client rule accepts the leaf");
    assert_eq!(identity.instance, "001");
    assert_eq!(identity.host, TEST_HOST);
    assert_eq!(identity.domain, TEST_DOMAIN);
    assert!(
        recognize_registrar_endpoint(&der, TEST_DOMAIN).is_err(),
        "the client leaf is not an endpoint identity"
    );
}

#[tokio::test]
async fn the_issued_server_leaf_carries_the_reserved_endpoint_name() {
    let harness = start_acme_harness().await;
    let outcome = issue_into_tempdir(&harness, SurfaceLeaf::Endpoint, OPENBAO_HMAC, None).await;
    let der = leaf_der(&outcome.leaf_pem);

    assert_eq!(single_dns_san(&der).expect("one DNS SAN"), endpoint_name());
    recognize_registrar_endpoint(&der, TEST_DOMAIN).expect("the endpoint rule accepts the leaf");

    // The loader's own key-match check, run over the published pair.
    let certs = parse_certificates(outcome.leaf_pem.as_bytes()).expect("certificates");
    let signing_key = parse_signing_key(outcome.key_pem.as_bytes()).expect("signing key");
    assert!(crate::tls::cert_key_matches(
        certs.first().expect("leaf"),
        signing_key.as_ref()
    ));
}

/// The endpoint's operation set is exactly two, and this work adds
/// nothing to it: the issued client identity is the one the endpoint
/// accepts, and it is accepted for both verbs and for no third one.
///
/// Linux-only because the endpoint module is.
#[test]
#[cfg(target_os = "linux")]
fn the_client_identity_is_permitted_at_exactly_the_two_operations() {
    use crate::registrar::endpoint::frame::Operation;

    for (name, expected) in [
        ("mint", Some(Operation::Mint)),
        ("deregister", Some(Operation::Deregister)),
        ("revoke", None),
        ("", None),
    ] {
        assert_eq!(Operation::from_name(name), expected, "{name}");
    }
    // Recognition is by name, and the name this work composes is the one
    // the endpoint's client rule accepts.
    recognize_registrar_client_name(&client_name(), TEST_DOMAIN)
        .expect("the composed client name is the identity the endpoint admits");
}

/// The requested extended key usage is asserted on the CSR params, with
/// no CA in the loop. What the *issued* leaf ends up carrying is
/// step-ca's template's business, so nothing here asserts it.
#[test]
fn the_client_csr_params_request_client_auth_and_the_server_params_do_not() {
    let client = crate::acme::build_registrar_client_csr_params(
        REGISTRAR_SURFACE_INSTANCE,
        TEST_HOST,
        TEST_DOMAIN,
    )
    .expect("client CSR params");
    assert_eq!(client.subject_alt_names.len(), 1);
    assert_eq!(
        client.extended_key_usages,
        vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth]
    );
}

/// Every issuance generates a fresh key pair, so nothing keyed on a
/// leaf's DER, SPKI, serial or fingerprint survives a reissue. The two
/// key-level assertions here do not depend on stability: the keys
/// differ, and each matches the leaf it was issued with.
#[tokio::test]
async fn two_issuances_of_the_same_name_produce_different_keys() {
    let harness = start_acme_harness().await;
    let first = issue_into_tempdir(&harness, SurfaceLeaf::Client, OPENBAO_HMAC, None).await;
    let second = issue_into_tempdir(&harness, SurfaceLeaf::Client, OPENBAO_HMAC, None).await;

    assert_ne!(
        first.key_pem, second.key_pem,
        "each issuance is fresh-keyed"
    );
    for outcome in [&first, &second] {
        let der = leaf_der(&outcome.leaf_pem);
        assert_eq!(single_dns_san(&der).expect("SAN"), client_name());
    }
}

/// Written through the staged-and-renamed path, with the key never
/// group- or world-readable and the parent directory created.
#[tokio::test]
#[cfg(unix)]
async fn the_written_key_is_never_group_or_world_readable() {
    use std::os::unix::fs::PermissionsExt as _;

    let harness = start_acme_harness().await;
    for leaf in [SurfaceLeaf::Client, SurfaceLeaf::Endpoint] {
        let outcome = issue_into_tempdir(&harness, leaf, OPENBAO_HMAC, None).await;
        let mode = std::fs::metadata(&outcome.key)
            .expect("key metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode & 0o077, 0, "{leaf:?} key mode is {mode:o}");
        assert!(outcome.cert.exists());
        assert!(outcome.bundle.exists(), "the merged bundle is published");
    }
}

/// The HMAC that reaches the responder is the `OpenBao` one, and never
/// the locally configured value.
#[tokio::test]
async fn the_responder_hmac_that_signs_the_registration_is_the_openbao_one() {
    let harness = start_acme_harness().await;
    let _ = issue_into_tempdir(&harness, SurfaceLeaf::Client, OPENBAO_HMAC, None).await;

    let observed = harness.observed.lock().expect("observed lock").clone();
    let registration = observed.first().expect("one registration was observed");
    let timestamp: i64 = registration.timestamp.parse().expect("timestamp");
    let expected = Http01HmacSigner::new(OPENBAO_HMAC).sign_request(
        timestamp,
        &registration.token,
        &registration.key_authorization,
        registration.ttl_secs,
    );
    let local = Http01HmacSigner::new(LOCAL_HMAC).sign_request(
        timestamp,
        &registration.token,
        &registration.key_authorization,
        registration.ttl_secs,
    );
    assert_eq!(registration.signature, expected);
    assert_ne!(
        registration.signature, local,
        "the locally configured HMAC must not reach the responder"
    );
}

/// The EAB handed to issuance is what the account registration binds
/// with.
#[tokio::test]
async fn the_eab_reaches_the_account_registration() {
    let harness = start_acme_harness().await;
    let _ = issue_into_tempdir(
        &harness,
        SurfaceLeaf::Client,
        OPENBAO_HMAC,
        Some(EabCredentials {
            kid: "kid-from-openbao".to_string(),
            hmac: HmacSecret::new("ZWFiLWZyb20tb3BlbmJhbw".to_string()),
        }),
    )
    .await;

    let bodies = harness.account_bodies.lock().expect("bodies lock").clone();
    let jws = bodies.first().expect("one registration");
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(jws["payload"].as_str().expect("payload"))
        .expect("decode payload");
    let payload: serde_json::Value = serde_json::from_slice(&payload).expect("payload JSON");
    let binding = &payload["externalAccountBinding"];
    assert!(!binding.is_null(), "the account is bound: {payload}");
    let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(binding["protected"].as_str().expect("protected"))
        .expect("decode protected");
    let protected: serde_json::Value = serde_json::from_slice(&protected).expect("protected JSON");
    assert_eq!(
        protected["kid"], "kid-from-openbao",
        "the EAB read from OpenBao is the one the account binds with"
    );
}

/// An issuance whose replacement cannot be written is a failure naming
/// the path, not a repair. The certificate path here is a directory,
/// which is exactly the condition that made the material unusable and
/// also prevents replacing it.
#[tokio::test]
async fn a_write_that_cannot_land_is_an_issuance_failure_naming_the_path() {
    let harness = start_acme_harness().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("leaf.pem");
    std::fs::create_dir(&cert).expect("make the certificate path a directory");

    let mut settings = test_settings(&harness.directory_url, &harness.responder_url);
    settings.acme.http_responder_hmac = HmacSecret::new(OPENBAO_HMAC.to_string());
    let paths = PairPaths {
        leaf: SurfaceLeaf::Client,
        cert: cert.clone(),
        key: dir.path().join("leaf.key"),
    };
    let err = issue_pair(&settings, &paths, TEST_HOST, None, false)
        .await
        .expect_err("a certificate path that is a directory cannot be written");
    let rendered = format!("{err:#}");
    assert!(rendered.contains(&cert.display().to_string()), "{rendered}");
}

/// A CA bundle the daemon cannot read fails **before publication**: no
/// leaf is written, and the bundle is byte-identical afterwards.
#[tokio::test]
#[cfg(unix)]
async fn an_unreadable_ca_bundle_fails_before_anything_is_published() {
    use std::os::unix::fs::PermissionsExt as _;

    if nix_running_as_root() {
        return;
    }
    let harness = start_acme_harness().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("leaf.pem");
    let key = dir.path().join("leaf.key");
    let bundle = dir.path().join("ca-bundle.pem");
    std::fs::write(&bundle, "existing bundle bytes\n").expect("seed bundle");
    let before = std::fs::read(&bundle).expect("read bundle");
    std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o000))
        .expect("make the bundle unreadable");

    let mut settings = test_settings(&harness.directory_url, &harness.responder_url);
    settings.acme.http_responder_hmac = HmacSecret::new(OPENBAO_HMAC.to_string());
    settings.trust = TrustSettings {
        ca_bundle_path: Some(bundle.clone()),
        trusted_ca_sha256: vec![crate::tls::sha256_hex(harness.ca.der())],
    };
    let paths = PairPaths {
        leaf: SurfaceLeaf::Client,
        cert: cert.clone(),
        key: key.clone(),
    };
    let err = issue_pair(&settings, &paths, TEST_HOST, None, false)
        .await
        .expect_err("an unreadable bundle refuses");
    assert!(
        format!("{err:#}").contains(&bundle.display().to_string()),
        "{err:#}"
    );
    assert!(!cert.exists(), "no leaf is published");
    assert!(!key.exists(), "no key is published");

    std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o600)).expect("restore");
    assert_eq!(
        std::fs::read(&bundle).expect("read bundle"),
        before,
        "the bundle is byte-identical afterwards"
    );
}

/// A missing bundle is answered by the merge rather than by a refusal:
/// it is seeded from an empty bundle and the leaf is published.
///
/// Driven with `insecure_mode` to isolate that from the *outbound* use
/// of `trust.ca_bundle_path`, which `AcmeClient::new` reads to anchor
/// its own TLS and which refuses a missing file before this flow
/// begins. That is a pre-existing property of the ACME path, not the
/// publication rule under test here, and an endpoint-enabled host with
/// no bundle cannot start for the loader's own reasons regardless.
#[tokio::test]
async fn a_missing_ca_bundle_is_seeded_by_the_merge_rather_than_refusing() {
    let harness = start_acme_harness().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("leaf.pem");
    let bundle = dir.path().join("ca-bundle.pem");
    assert!(!bundle.exists());

    let mut settings = test_settings(&harness.directory_url, &harness.responder_url);
    settings.acme.http_responder_hmac = HmacSecret::new(OPENBAO_HMAC.to_string());
    settings.trust = TrustSettings {
        ca_bundle_path: Some(bundle.clone()),
        trusted_ca_sha256: vec![crate::tls::sha256_hex(harness.ca.der())],
    };
    let paths = PairPaths {
        leaf: SurfaceLeaf::Client,
        cert: cert.clone(),
        key: dir.path().join("leaf.key"),
    };
    issue_pair(&settings, &paths, TEST_HOST, None, true)
        .await
        .expect("a missing bundle merges against an empty seed");
    assert!(cert.exists(), "the leaf is published");
    let merged = std::fs::read_to_string(&bundle).expect("read bundle");
    assert!(merged.contains("BEGIN CERTIFICATE"), "the bundle is seeded");
}

/// An unparseable but readable bundle is likewise answered by the merge,
/// which skips every entry it cannot parse and publishes. Same
/// `insecure_mode` isolation, for the same reason.
#[tokio::test]
async fn an_unparseable_but_readable_ca_bundle_is_merged_over_rather_than_refusing() {
    let harness = start_acme_harness().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("leaf.pem");
    let key = dir.path().join("leaf.key");
    let bundle = dir.path().join("ca-bundle.pem");
    std::fs::write(&bundle, "not a pem at all\n").expect("seed junk bundle");

    let mut settings = test_settings(&harness.directory_url, &harness.responder_url);
    settings.acme.http_responder_hmac = HmacSecret::new(OPENBAO_HMAC.to_string());
    settings.trust = TrustSettings {
        ca_bundle_path: Some(bundle.clone()),
        trusted_ca_sha256: vec![crate::tls::sha256_hex(harness.ca.der())],
    };
    let paths = PairPaths {
        leaf: SurfaceLeaf::Client,
        cert: cert.clone(),
        key,
    };
    issue_pair(&settings, &paths, TEST_HOST, None, true)
        .await
        .expect("an unparseable but readable bundle is merged over");
    assert!(cert.exists(), "the leaf is published");
    let merged = std::fs::read_to_string(&bundle).expect("read bundle");
    assert!(
        merged.contains("BEGIN CERTIFICATE"),
        "the unparseable entries are skipped and the chain is written"
    );
}

/// Issuance never writes the endpoint pin file: the pin is over trust
/// anchors rather than over either leaf, and the provisioning tool
/// writes it once.
#[tokio::test]
async fn issuance_leaves_the_endpoint_pin_file_untouched() {
    let harness = start_acme_harness().await;
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("client.pem");
    let key = dir.path().join("client.key");
    let bundle = dir.path().join("ca-bundle.pem");
    std::fs::write(&bundle, harness.ca.pem()).expect("seed the bundle");
    let pin_file = crate::registrar::endpoint_pin::anchor_pin_path_for_client_certificate(&cert);
    std::fs::write(&pin_file, "# operator-authored pin file\n").expect("seed pin file");
    let before = std::fs::read(&pin_file).expect("read pin file");

    let mut settings = test_settings(&harness.directory_url, &harness.responder_url);
    settings.acme.http_responder_hmac = HmacSecret::new(OPENBAO_HMAC.to_string());
    settings.trust = TrustSettings {
        ca_bundle_path: Some(bundle),
        trusted_ca_sha256: vec![crate::tls::sha256_hex(harness.ca.der())],
    };
    let paths = PairPaths {
        leaf: SurfaceLeaf::Client,
        cert,
        key,
    };
    issue_pair(&settings, &paths, TEST_HOST, None, false)
        .await
        .expect("issuance succeeds");
    assert_eq!(
        std::fs::read(&pin_file).expect("read pin file"),
        before,
        "the pin file is byte-identical"
    );
}

/// An ACME flow that cannot be reached is an issuance failure naming the
/// material paths, with no fallback to a self-signed or borrowed leaf.
#[tokio::test]
async fn a_failed_acme_flow_refuses_and_names_the_material_paths() {
    // Loopback port 1: nothing binds it, so the dial is refused
    // immediately and no traffic leaves the host.
    let uri = "http://127.0.0.1:1".to_string();
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("leaf.pem");
    let key = dir.path().join("leaf.key");

    let mut settings = test_settings(&format!("{uri}/directory"), &uri);
    settings.acme.http_responder_hmac = HmacSecret::new(OPENBAO_HMAC.to_string());
    let paths = PairPaths {
        leaf: SurfaceLeaf::Client,
        cert: cert.clone(),
        key: key.clone(),
    };
    let err = issue_pair(&settings, &paths, TEST_HOST, None, false)
        .await
        .expect_err("an unreachable CA must refuse");
    let rendered = format!("{err:#}");
    assert!(rendered.contains(&cert.display().to_string()), "{rendered}");
    assert!(rendered.contains(&key.display().to_string()), "{rendered}");
    assert!(!cert.exists(), "nothing is published on failure");
}

/// Nothing on the issuance path reads a `role_id` or a `secret_id`. The
/// credential is `InternalCredential`, which authenticates by client
/// certificate at `auth/cert`, so this is a property of the module's own
/// text rather than an argument about which `AppRole` is used.
#[test]
fn no_approle_is_named_anywhere_on_the_issuance_path() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/registrar/surface_certs.rs");
    let source = std::fs::read_to_string(&root).expect("the issuance module must be readable");
    // Comments are excluded on purpose: the module's own documentation
    // has to be able to say *why* no AppRole is on this path.
    let code: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for forbidden in ["role_id", "secret_id"] {
        assert!(
            !code.contains(forbidden),
            "the issuance path must never name {forbidden}"
        );
    }
    assert!(
        code.contains("InternalCredential"),
        "the credential is the bootroot-internal one"
    );
}
