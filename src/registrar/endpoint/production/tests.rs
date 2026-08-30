//! Tests for the production handler's CA-anchor framing and strict wire-spec
//! conversion.

use std::path::Path;
use std::sync::{Arc, Mutex as StdMutex};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use wiremock::matchers::{method, path as request_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{
    ProductionHandler, SpecConversionError, anchor_from_stored, normalize_bundle, requested_spec,
};
use crate::config::AuditStoreEnforcement;
use crate::kv_payload::{TrustPayload, parse_trust_payload};
use crate::openbao::{OpenBaoClient, SecretIdOptions};
use crate::registrar::audit::scan::{AUDIT_SCAN_WINDOW, scan_audit_store};
use crate::registrar::audit::{ACTIVE_FILE_NAME, AuditRecordStore};
use crate::registrar::audit_store::capacity::AuditCapacityState;
use crate::registrar::config::{RegistrarConfig, ReloadKind, ReloadSpec};
use crate::registrar::endpoint::protocol::{
    AuditCapacityHealth, LimiterHealth, RegistrarHealth, WireServiceSpec, decode_ca_anchor,
    decode_mint_response, encode_ca_anchor, encode_mint_response,
};
use crate::registrar::fixture::RegistrarConfigFixture;
use crate::registrar::internal::{InternalCredential, active_root_cert_path};
use crate::registrar::verbs::limiter::{
    NoopLimitedInvocationSink, VerbRateLimiter, VerbRateLimiterSettings,
};
use crate::registrar::verbs::outcome::{
    CallerIdentity, MintKind, MintOutcome, ProducingArm, RequestId, VerbContext,
    WrappedSecretIdToken,
};
use crate::registrar::verbs::wrap_ttl::WrapTtlPolicy;
use crate::registrar::verbs::{RegistrarVerbs, RegistrarVerbsConfig};

/// The KV mount the anchor harness resolves. The daemon resolves it one
/// level up and passes it down; nothing in this layer knows where it was
/// recorded.
const HARNESS_KV_MOUNT: &str = "secret";

/// Generates a self-signed CA certificate, returning its PEM and the
/// lowercase hex SHA-256 of its DER — the `trusted_ca_sha256` form.
fn generate_ca_cert(common_name: &str) -> (String, String) {
    let key = KeyPair::generate().expect("generate CA key");
    let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).expect("self-signed cert");
    let fingerprint = crate::tls::sha256_hex(cert.der().as_ref());
    (cert.pem(), fingerprint)
}

/// The KV object at `bootroot/ca` carries no order guarantee, so a
/// stored array in a different order from the bundle is an ordinary
/// state rather than a corrupt one — and the emitted array must still
/// line up positionally with the bundle.
#[test]
fn the_emitted_fingerprints_follow_the_bundle_not_the_stored_array() {
    let (pem_a, fp_a) = generate_ca_cert("Anchor A");
    let (pem_b, fp_b) = generate_ca_cert("Anchor B");
    let stored = TrustPayload {
        // Deliberately the reverse of the bundle's order.
        trusted_ca_sha256: vec![fp_b.clone(), fp_a.clone()],
        ca_bundle_pem: format!("{pem_a}{pem_b}"),
    };

    let anchor = anchor_from_stored(&stored).expect("a consistent anchor");

    assert_eq!(
        anchor.trusted_ca_sha256,
        vec![fp_a, fp_b],
        "entry n must be the digest of certificate n, whatever order the object stored"
    );
}

/// `parse_trust_payload` compares sets and cannot see the difference the
/// test above asserts, so the positional property is asserted on
/// positions rather than on that validator accepting.
#[test]
fn a_set_comparison_cannot_see_the_ordering_the_framing_requires() {
    let (pem_a, fp_a) = generate_ca_cert("Anchor A");
    let (pem_b, fp_b) = generate_ca_cert("Anchor B");
    let value = serde_json::json!({
        "trusted_ca_sha256": [fp_b, fp_a],
        "ca_bundle_pem": format!("{pem_a}{pem_b}"),
    });
    assert!(
        parse_trust_payload(&value).is_ok(),
        "the shared validator accepts an inverted array, which is why the handler derives its own"
    );
}

/// A `bootroot/ca` whose pins and bundle disagree is precisely the state
/// no freshly enrolled service may be seeded from.
#[test]
fn an_anchor_whose_sets_differ_is_refused() {
    let (pem_a, _fp_a) = generate_ca_cert("Anchor A");
    let (_pem_b, fp_b) = generate_ca_cert("Anchor B");
    let stored = TrustPayload {
        trusted_ca_sha256: vec![fp_b],
        ca_bundle_pem: pem_a,
    };

    let error = anchor_from_stored(&stored).expect_err("the sets differ");
    assert!(
        format!("{error:#}").contains("do not match"),
        "the refusal must say the pins and the bundle disagree: {error:#}"
    );
}

/// A stored bundle written with CRLF endings and no trailing newline is
/// emitted with LF endings and exactly one trailing LF, and every
/// emitted fingerprint still matches a certificate in it — the digests
/// are over DER, so the rewrite changes none of them.
#[test]
fn a_crlf_bundle_is_emitted_as_lf_with_one_trailing_newline() {
    let (pem_a, fp_a) = generate_ca_cert("Anchor A");
    let (pem_b, fp_b) = generate_ca_cert("Anchor B");
    let joined = format!("{pem_a}{pem_b}");
    let crlf = joined.replace('\n', "\r\n");
    let stored = TrustPayload {
        trusted_ca_sha256: vec![fp_a.clone(), fp_b.clone()],
        ca_bundle_pem: crlf.trim_end().to_string(),
    };

    let anchor = anchor_from_stored(&stored).expect("a consistent anchor");

    assert!(
        !anchor.ca_bundle_pem.contains('\r'),
        "the emitted bundle carries LF endings only"
    );
    assert!(
        anchor.ca_bundle_pem.ends_with('\n') && !anchor.ca_bundle_pem.ends_with("\n\n"),
        "the emitted bundle ends with exactly one LF"
    );
    assert_eq!(anchor.trusted_ca_sha256, vec![fp_a, fp_b]);
}

#[test]
fn normalizing_a_bundle_is_idempotent() {
    let once = normalize_bundle("a\r\nb\r\n\r\n");
    assert_eq!(once, "a\nb\n");
    assert_eq!(normalize_bundle(&once), once);
    assert_eq!(normalize_bundle("a\rb"), "a\nb\n");
}

/// The anchor the handler builds is exactly what the codec frames: it
/// round-trips through `encode_ca_anchor`, decodes into a
/// `serde_json::Value` that `parse_trust_payload` accepts, and its
/// decoded **bytes** carry the two members in the fixed order rather
/// than the alphabetical one a `serde_json::Value` would produce.
#[test]
fn the_framed_anchor_carries_the_fixed_member_order() {
    use base64::Engine as _;

    let (pem, fingerprint) = generate_ca_cert("Anchor A");
    let stored = TrustPayload {
        trusted_ca_sha256: vec![fingerprint],
        ca_bundle_pem: pem,
    };
    let anchor = anchor_from_stored(&stored).expect("a consistent anchor");

    let encoded = encode_ca_anchor(&anchor).expect("the codec frames the anchor");
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&encoded)
        .expect("standard base64");
    let text = String::from_utf8(bytes.clone()).expect("compact UTF-8 JSON");
    let pins_at = text.find("trusted_ca_sha256").expect("the pins member");
    let bundle_at = text.find("ca_bundle_pem").expect("the bundle member");
    assert!(
        pins_at < bundle_at,
        "trusted_ca_sha256 must precede ca_bundle_pem: {text}"
    );

    let value: serde_json::Value = serde_json::from_slice(&bytes).expect("a JSON object");
    parse_trust_payload(&value).expect("the shared validator accepts the framed anchor");
    assert_eq!(
        decode_ca_anchor(&encoded).expect("the codec decodes its own framing"),
        anchor
    );
}

/// The immutable bootler row accepts only the canonical rendered reload
/// productions and canonical decimal certificate groups. The restated
/// identity fields are passed to the verb layer unchanged.
#[test]
fn requested_spec_accepts_every_owner_recorded_production() {
    let cases = [
        (r#"{ kind = "none" }"#, None, ReloadSpec::none(), None),
        (
            r#"{ kind = "sighup", target = "review" }"#,
            Some("0"),
            ReloadSpec::new(ReloadKind::Sighup, "review"),
            Some(0),
        ),
        (
            r#"{ kind = "systemd", target = "roxyd.service" }"#,
            Some("4294967295"),
            ReloadSpec::new(ReloadKind::Systemd, "roxyd.service"),
            Some(u32::MAX),
        ),
        (
            r#"{ kind = "docker-restart", target = "a\"b\\c" }"#,
            Some("3000"),
            ReloadSpec::new(ReloadKind::DockerRestart, "a\"b\\c"),
            Some(3000),
        ),
    ];

    for (reload, cert_group, expected_reload, expected_cert_group) in cases {
        let spec = wire_spec(reload, cert_group);
        let requested = requested_spec(&spec).expect("an owner-recorded spelling converts");
        assert_eq!(requested.component.as_deref(), Some("example-component"));
        assert_eq!(requested.service_name.as_deref(), Some("example"));
        assert_eq!(requested.reload, expected_reload);
        assert_eq!(requested.cert_group, expected_cert_group);
    }
}

/// The owner row permits no TOML flexibility: every whitespace, quoting,
/// escape, kind and target form below is outside its canonical output.
#[test]
fn requested_spec_refuses_every_unrecorded_reload_spelling() {
    let cases = [
        (r#"{kind = "none" }"#, "spacing"),
        (r#"{ kind = "none"}"#, "space before closing brace"),
        (r#"{ target = "x", kind = "systemd" }"#, "member order"),
        (
            r#"{ kind = "none", target = "x" }"#,
            "target forbidden for none",
        ),
        (r#"{ kind = "sighup" }"#, "target required for sighup"),
        (r#"{ kind = "systemd", target = "" }"#, "empty target"),
        (
            r#"{ kind = "docker-restart", target = "x\n" }"#,
            "unrecorded escape",
        ),
        (
            r#"{ kind = "sighup", target = unquoted }"#,
            "unquoted target",
        ),
        (
            r#"{ kind = "systemd", target = "a\b" }"#,
            "unescaped backslash",
        ),
        (r#"{ kind = "unknown", target = "x" }"#, "unknown kind"),
        (r#"{ kind = "systemd", target = "a"b" }"#, "unescaped quote"),
        (
            r#"{ kind = "sighup", target = "x" } extra"#,
            "trailing text",
        ),
    ];

    for (reload, what) in cases {
        let error = requested_spec(&wire_spec(reload, None)).expect_err(what);
        assert!(
            matches!(
                error,
                SpecConversionError::ReloadGrammar
                    | SpecConversionError::ReloadTargetRequired { .. }
                    | SpecConversionError::ReloadTargetForbidden
            ),
            "{what} must be a typed reload conversion refusal: {error}"
        );
    }

    assert!(matches!(
        requested_spec(&wire_spec(r#"{ kind = "systemd" }"#, None)),
        Err(SpecConversionError::ReloadTargetRequired {
            kind: ReloadKind::Systemd
        })
    ));
    assert!(matches!(
        requested_spec(&wire_spec(r#"{ kind = "none", target = "x" }"#, None)),
        Err(SpecConversionError::ReloadTargetForbidden)
    ));
}

/// Omitted is the only absence spelling. Present values are decimal `u32`
/// output exactly as the owner renderer emits it.
#[test]
fn requested_spec_refuses_noncanonical_certificate_groups() {
    for value in [
        "", "00", "01", "+1", "-1", " 1", "1 ", "1_000", "١", "null", "x",
    ] {
        assert!(matches!(
            requested_spec(&wire_spec(r#"{ kind = "none" }"#, Some(value))),
            Err(SpecConversionError::CertGroupGrammar)
        ));
    }
    assert!(matches!(
        requested_spec(&wire_spec(r#"{ kind = "none" }"#, Some("4294967296"))),
        Err(SpecConversionError::CertGroupOutOfRange)
    ));
}

fn wire_spec(reload: &str, cert_group: Option<&str>) -> WireServiceSpec {
    WireServiceSpec {
        component: "example-component".to_string(),
        service_name: "example".to_string(),
        reload: reload.to_string(),
        cert_group: cert_group.map(str::to_string),
    }
}

// ---------------------------------------------------------------------
// The anchor read, over a mock OpenBao
// ---------------------------------------------------------------------

/// Writes the deployment root the credential re-reads before every
/// acquisition, and returns its fingerprint.
fn write_harness_root(secrets_dir: &Path) -> String {
    let (pem, fingerprint) = generate_ca_cert("Bootroot Anchor Test Root");
    let path = active_root_cert_path(secrets_dir);
    std::fs::create_dir_all(path.parent().expect("the certs directory")).expect("mkdir certs");
    std::fs::write(&path, pem).expect("write the root certificate");
    fingerprint
}

/// A limiter at the shipped sizing, publishing nothing.
///
/// These tests drive a handful of requests, so the default burst never
/// binds; what is under test here is the anchor read, not the bound.
fn test_limiter() -> VerbRateLimiter {
    VerbRateLimiter::new(
        VerbRateLimiterSettings::default(),
        Arc::new(NoopLimitedInvocationSink),
    )
}

/// Builds the dependencies the handler is constructed from — real
/// verbs over `audit_store` and a real credential, both pointed at
/// `server`.
///
/// Split from the constructors so the two harnesses below differ in
/// nothing but which one they call.
fn harness_dependencies(
    server: &MockServer,
    audit_store: AuditRecordStore,
) -> (tempfile::TempDir, RegistrarVerbs, InternalCredential) {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = RegistrarConfigFixture::new()
        .write_to(dir.path())
        .expect("write the rendered registrar config");
    let config = RegistrarConfig::load(&config_path).expect("the fixture must load");
    let mut client = OpenBaoClient::new(&server.uri()).expect("client");
    client.set_token("test-token".to_string());
    let verbs = RegistrarVerbs::new(RegistrarVerbsConfig {
        client,
        kv_mount: HARNESS_KV_MOUNT.to_string(),
        config,
        secret_id_options: SecretIdOptions::default(),
        token_ttl: "3600s".to_string(),
        secret_id_ttl: "86400s".to_string(),
        wrap_ttl_policy: WrapTtlPolicy::new(time::Duration::minutes(30)).expect("policy maximum"),
        audit_store,
        limiter: test_limiter(),
    });

    let secrets_dir = dir.path().join("secrets");
    let fingerprint = write_harness_root(&secrets_dir);
    let credential = InternalCredential::for_test(&server.uri(), &secrets_dir, &fingerprint)
        .expect("the harness credential");

    (dir, verbs, credential)
}

/// Builds the production handler over real verbs and a real credential,
/// both pointed at `server`.
fn anchor_harness(server: &MockServer) -> (tempfile::TempDir, ProductionHandler) {
    let (dir, verbs, credential) = harness_dependencies(
        server,
        AuditRecordStore::open_temporary().expect("a temporary audit store"),
    );
    (
        dir,
        ProductionHandler::new(verbs, credential, HARNESS_KV_MOUNT.to_string()),
    )
}

/// Builds the production handler the way the daemon does: over the
/// shared health snapshot the maintenance tick writes, and over a
/// caller-held audit store the test can populate.
fn health_harness(
    server: &MockServer,
    audit_store: AuditRecordStore,
    health: Arc<StdMutex<RegistrarHealth>>,
) -> (tempfile::TempDir, ProductionHandler) {
    let (dir, verbs, credential) = harness_dependencies(server, audit_store);
    (
        dir,
        ProductionHandler::with_health(verbs, credential, HARNESS_KV_MOUNT.to_string(), health),
    )
}

async fn mock_cert_login(server: &MockServer) {
    Mock::given(method("POST"))
        .and(request_path("/v1/auth/cert/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": { "client_token": "s.internal-token", "lease_duration": 900 }
        })))
        .mount(server)
        .await;
}

/// Answers the CA-anchor read with `object`, for `expect` reads.
async fn mock_anchor_read(
    server: &MockServer,
    object: serde_json::Value,
    expect: u64,
) -> wiremock::MockGuard {
    Mock::given(method("GET"))
        .and(request_path(format!(
            "/v1/{HARNESS_KV_MOUNT}/data/bootroot/ca"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "data": { "data": object } })),
        )
        .expect(expect)
        .mount_as_scoped(server)
        .await
}

/// The anchor the handler reads is the KV object at `bootroot/ca`,
/// normalized and re-derived, and it is what the codec frames.
#[tokio::test]
async fn the_anchor_read_returns_what_the_codec_frames() {
    let server = MockServer::start().await;
    mock_cert_login(&server).await;
    let (pem, fingerprint) = generate_ca_cert("Deployment CA");
    let _guard = mock_anchor_read(
        &server,
        serde_json::json!({
            "trusted_ca_sha256": [fingerprint.clone()],
            "ca_bundle_pem": pem,
        }),
        1,
    )
    .await;
    let (_dir, handler) = anchor_harness(&server);

    let anchor = handler
        .read_ca_anchor()
        .await
        .expect("the anchor is readable");
    assert_eq!(anchor.trusted_ca_sha256, vec![fingerprint]);
    encode_ca_anchor(&anchor).expect("the codec frames what the read returned");
}

/// The anchor is read per mint, never cached for the daemon's lifetime:
/// a root rotation rewrites `bootroot/ca`, and an endpoint handing out a
/// stale one would seed a freshly enrolled service with a trust root the
/// deployment has retired.
#[tokio::test]
async fn a_rewritten_anchor_is_reflected_on_the_next_read_without_a_restart() {
    let server = MockServer::start().await;
    mock_cert_login(&server).await;
    let (_dir, handler) = anchor_harness(&server);

    let (first_pem, first_fingerprint) = generate_ca_cert("Deployment CA, before rotation");
    {
        let _guard = mock_anchor_read(
            &server,
            serde_json::json!({
                "trusted_ca_sha256": [first_fingerprint.clone()],
                "ca_bundle_pem": first_pem,
            }),
            1,
        )
        .await;
        let anchor = handler.read_ca_anchor().await.expect("the first read");
        assert_eq!(anchor.trusted_ca_sha256, vec![first_fingerprint.clone()]);
    }

    let (second_pem, second_fingerprint) = generate_ca_cert("Deployment CA, after rotation");
    let _guard = mock_anchor_read(
        &server,
        serde_json::json!({
            "trusted_ca_sha256": [second_fingerprint.clone()],
            "ca_bundle_pem": second_pem,
        }),
        1,
    )
    .await;
    let anchor = handler.read_ca_anchor().await.expect("the second read");
    assert_eq!(anchor.trusted_ca_sha256, vec![second_fingerprint]);
    assert_ne!(anchor.trusted_ca_sha256, vec![first_fingerprint]);
}

/// A `bootroot/ca` whose stored pins and bundle disagree is refused by
/// the read itself, so nothing downstream is ever handed it.
#[tokio::test]
async fn an_inconsistent_stored_anchor_is_refused_by_the_read() {
    let server = MockServer::start().await;
    mock_cert_login(&server).await;
    let (pem, _fingerprint) = generate_ca_cert("Deployment CA");
    let (_other_pem, other_fingerprint) = generate_ca_cert("Another CA");
    let _guard = mock_anchor_read(
        &server,
        serde_json::json!({
            "trusted_ca_sha256": [other_fingerprint],
            "ca_bundle_pem": pem,
        }),
        1,
    )
    .await;
    let (_dir, handler) = anchor_harness(&server);

    let error = handler
        .read_ca_anchor()
        .await
        .expect_err("an inconsistent anchor is a deployment fault");
    assert!(
        format!("{error:#}").contains("bootroot/ca"),
        "the failure must name the KV path: {error:#}"
    );
}

/// An unreadable `bootroot/ca` is a failure that names the path, so the
/// handler's own log line has something to say the transport's fixed one
/// cannot.
#[tokio::test]
async fn an_unreadable_anchor_names_its_kv_path() {
    let server = MockServer::start().await;
    mock_cert_login(&server).await;
    let (_dir, handler) = anchor_harness(&server);

    let error = handler
        .read_ca_anchor()
        .await
        .expect_err("nothing is mounted at the anchor path");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("bootroot/ca") && rendered.contains(HARNESS_KV_MOUNT),
        "the failure must name the mount and the path: {rendered}"
    );
}

/// `parse_trust_payload` matches a stored pin against the bundle
/// case-insensitively, so an anchor it accepts must not be refused here
/// on a difference in case. The emitted array is derived, so it is
/// lowercase whatever the object stored.
#[test]
fn an_uppercase_stored_fingerprint_is_the_same_fingerprint() {
    let (pem, fingerprint) = generate_ca_cert("Anchor A");
    let value = serde_json::json!({
        "trusted_ca_sha256": [fingerprint.to_ascii_uppercase()],
        "ca_bundle_pem": pem.clone(),
    });
    parse_trust_payload(&value).expect("the shared validator accepts an uppercase pin");

    let stored = TrustPayload {
        trusted_ca_sha256: vec![fingerprint.to_ascii_uppercase()],
        ca_bundle_pem: pem,
    };
    let anchor = anchor_from_stored(&stored).expect("the same pin, spelled in the other case");
    assert_eq!(anchor.trusted_ca_sha256, vec![fingerprint]);
}

// ---------------------------------------------------------------------
// The health snapshot a response carries
// ---------------------------------------------------------------------

/// The retention settings the reader is driven with here. Any pair the
/// scanner accepts would do: what these tests compare is the reader's
/// output against the relayed snapshot, not the reader's own rules.
const SCAN_MAX_RETAINED: u32 = 14;
const SCAN_MIN_RETAIN_DAYS: u32 = 7;

/// A snapshot no scan of a freshly opened store could produce.
///
/// Every measured member is non-default and the record counts are
/// non-zero, so a response carrying these values took them from the
/// daemon's holder rather than from the store the handler was built
/// over.
fn relay_snapshot() -> RegistrarHealth {
    let measured_at = time::OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_700_000_000);
    RegistrarHealth {
        limiter: LimiterHealth::default(),
        audit_capacity: AuditCapacityHealth {
            state: AuditCapacityState::LowWater,
            enforcement: AuditStoreEnforcement::Directory,
            reserve_bytes: 2_147_483_648,
            low_water_bytes: 536_870_912,
            used_bytes: Some(1_700_000_000),
            headroom_bytes: Some(447_483_648),
            measured_at: Some(measured_at),
            intent_without_outcome: Some(4),
            malformed_records: Some(7),
            retention_shortfall: Some(true),
            records_measured_at: Some(measured_at),
        },
    }
}

/// A verb outcome the mint encoder accepts.
fn mint_outcome() -> MintOutcome {
    MintOutcome::new(
        VerbContext::new(
            RequestId::for_fixture("request-0001"),
            CallerIdentity::new("registrar-client:001.bootroot-registrar.h1.example.internal"),
            Some("registration-1".to_string()),
            ProducingArm::Issuance,
        ),
        MintKind::FirstMint,
        "api.node.example.test".to_string(),
        "role-id".to_string(),
        WrappedSecretIdToken::new("wrapped-secret".to_string()),
        time::OffsetDateTime::UNIX_EPOCH,
    )
}

/// A single-certificate anchor the mint encoder frames.
fn relay_anchor() -> TrustPayload {
    let (pem, fingerprint) = generate_ca_cert("Deployment CA");
    TrustPayload {
        trusted_ca_sha256: vec![fingerprint],
        ca_bundle_pem: pem,
    }
}

/// A mint response relays the daemon's last snapshot and scans no store
/// of its own.
///
/// The reader computes its counts by opening the store's files, so a
/// call from the request path would put a full-store read on every
/// successful mint. Driven over the two halves the mint arm is made of:
/// [`ProductionHandler::health_snapshot`], which is where that arm gets
/// the value, and `encode_mint_response`, which is what it hands the
/// value to. The arm calls exactly those and nothing else — pinned by
/// [`no_request_path_arm_reads_the_audit_store`], which reads this
/// build's `mint` body — and the whole arm cannot be driven end to end
/// here because `requested_spec` refuses every wire `spec` until the
/// grammar is settled, so no payload reaches the encoder through
/// `handle`.
///
/// The proof that no scan ran is not that the numbers look untouched:
/// the reader is run against the handler's own store in the same test
/// and returns something different from what the response carried.
#[tokio::test]
async fn a_mint_response_relays_the_last_snapshot_without_scanning_the_store() {
    let server = MockServer::start().await;
    let audit_store = AuditRecordStore::open_temporary().expect("a temporary audit store");
    let health = Arc::new(StdMutex::new(RegistrarHealth::default()));
    let (_dir, handler) = health_harness(&server, audit_store.clone(), health.clone());

    // One line the reader counts as malformed, so the store the handler
    // holds and the snapshot the daemon holds disagree by construction.
    std::fs::write(
        audit_store.directory().join(ACTIVE_FILE_NAME),
        b"{ not an audit record\n",
    )
    .expect("seed the store the reader would have scanned");

    let snapshot = relay_snapshot();
    *health.lock().expect("the snapshot lock is not poisoned") = snapshot.clone();

    let anchor = relay_anchor();
    let encoded = encode_mint_response(mint_outcome(), &anchor, &handler.health_snapshot())
        .expect("the mint response encodes");
    let decoded = decode_mint_response(&encoded).expect("the mint response decodes");
    assert_eq!(
        decoded.registrar_health, snapshot,
        "a mint response relays the daemon-held snapshot verbatim, limiter included"
    );

    let scanned = scan_audit_store(
        audit_store.directory(),
        time::OffsetDateTime::now_utc(),
        AUDIT_SCAN_WINDOW,
        SCAN_MAX_RETAINED,
        SCAN_MIN_RETAIN_DAYS,
    )
    .expect("the reader scans the handler's own store");
    assert_eq!(
        scanned.malformed_records, 1,
        "the seeded line is one the reader would have counted"
    );
    assert_ne!(
        Some(scanned.malformed_records),
        decoded.registrar_health.audit_capacity.malformed_records,
        "the relayed count is the tick's and not a scan of the store the response was built over"
    );

    // Only a maintenance tick moves it.
    health
        .lock()
        .expect("the snapshot lock is not poisoned")
        .audit_capacity
        .malformed_records = Some(9);
    let refreshed = encode_mint_response(mint_outcome(), &anchor, &handler.health_snapshot())
        .expect("the second mint response encodes");
    assert_eq!(
        decode_mint_response(&refreshed)
            .expect("the second mint response decodes")
            .registrar_health
            .audit_capacity
            .malformed_records,
        Some(9),
        "the next response follows the holder, which only the tick writes"
    );
}

/// No arm of the request path reads the audit store, and every arm takes
/// its health from the one accessor.
///
/// Asserted over this module's source because it is a property of the
/// complete request path rather than of any one response. The source
/// inspection covers both mint and deregister, including any future
/// control flow a response-level test does not exercise.
#[test]
fn no_request_path_arm_reads_the_audit_store() {
    // The test module is a sibling file, so this is the production half
    // whole.
    let source = include_str!("../production.rs");
    for reader in [
        "scan_audit_store",
        "AuditScan",
        "AuditRecordStore",
        "probe_audit_capacity",
        "audit_store_dir",
    ] {
        assert!(
            !source.contains(reader),
            "the request path must not read the audit store ({reader})"
        );
    }

    for arm in ["    async fn mint(", "    async fn deregister("] {
        let body = source
            .split(arm)
            .nth(1)
            .unwrap_or_else(|| panic!("{arm} is declared in this file"))
            .split("\n    }")
            .next()
            .unwrap_or_else(|| panic!("{arm} has a body"));
        assert!(
            body.contains("let health = self.health_snapshot();"),
            "{arm} takes its health from the one accessor: {body}"
        );
        assert!(
            !body.contains(".lock()"),
            "{arm} reaches the holder through the accessor and not around it: {body}"
        );
    }
}
