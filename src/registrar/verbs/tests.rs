//! Tests for the two verbs, split along one deliberate line.
//!
//! **Fast tier.** Everything that is decided before a stateful `OpenBao`
//! interaction: the pre-derivation refusals, the derivation failures, the
//! binding record's JSON, and the wrap-TTL policy. Where a client is
//! needed at all it is a canned-response Wiremock, and the assertion is
//! usually that *no request was made*.
//!
//! **Ignored tier.** Everything whose outcome depends on a prior
//! `OpenBao` write: durable bindings, the compare-and-set, re-mint,
//! wrong-host refusal, the absent-binding sweep, teardown-before-unbind
//! ordering, and both concurrency properties. These are `#[ignore]`d
//! library tests rather than integration tests under `tests/`, because
//! they construct the crate-private verb service and assert crate-private
//! outcomes. `scripts/impl/run-registrar-verbs-e2e.sh` brings up a live
//! `OpenBao` and runs them, and the `test-docker-e2e-matrix` CI job is
//! their gate.
//!
//! There is deliberately **no stateful `OpenBao` fake**. A fake that
//! tracked KV versions would be a second implementation of the
//! compare-and-set semantics the claim depends on, and a bug in the real
//! one would pass against it.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;
use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use wiremock::MockServer;

use super::binding::{
    BINDING_SCHEMA_VERSION, BindingRecord, BindingReloadKind, BindingSpec, BindingState,
    REGISTRAR_BINDING_KV_SUFFIX,
};
use super::outcome::{
    CallerIdentity, DeregisterKind, MintKind, MintOutcome, ProducingArm, RequestId, VerbContext,
    VerbError, VerbRefusal, WrappedSecretIdToken,
};
use super::wrap_ttl::{WrapTtlPolicy, WrapTtlRefusal};
use super::{
    DeregisterRequest, MintRequest, REGISTRAR_TEARDOWN_KV_SUFFIXES, RegistrarVerbs,
    RegistrarVerbsConfig, granted_deadline,
};
use crate::openbao::{OpenBaoClient, SecretIdOptions, WrapInfo};
use crate::registrar::config::{
    Multiplicity, RegistrarConfig, RegistrationSpec, ReloadKind, ReloadSpec,
};
use crate::registrar::error::{RegistrarError, SpecIdentityField};
use crate::registrar::fixture::RegistrarConfigFixture;
use crate::registrar::identity::RequestedSpec;
use crate::service_material::{service_policy_name, service_role_name};

/// Environment variable naming the live `OpenBao` the ignored tier runs
/// against. Read, never written.
const ENV_OPENBAO_URL: &str = "BOOTROOT_REGISTRAR_TEST_OPENBAO_URL";
/// Environment variable carrying that `OpenBao`'s privileged token.
const ENV_OPENBAO_TOKEN: &str = "BOOTROOT_REGISTRAR_TEST_OPENBAO_TOKEN";
/// Environment variable naming the KV v2 mount to write under.
const ENV_KV_MOUNT: &str = "BOOTROOT_REGISTRAR_TEST_KV_MOUNT";

/// A distinctive caller identity, so a test can prove it survives into an
/// outcome and reaches nothing else.
const CALLER: &str = "spiffe://review/manager#7f3a";

const TOKEN_TTL: &str = "1h";
const SECRET_ID_TTL: &str = "24h";

/// Discriminates one test run's identities from another's, so a live
/// `OpenBao` that is reused across runs never has two tests writing one
/// derived id.
fn unique_label(prefix: &str) -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let stamp = OffsetDateTime::now_utc().unix_timestamp().max(0);
    format!("{prefix}{}x{stamp}x{n}", std::process::id())
}

fn sample_spec() -> RegistrationSpec {
    RegistrationSpec {
        cert_group: Some(3001),
        reload: ReloadSpec::new(ReloadKind::DockerRestart, "piglet"),
    }
}

/// The rendered spec of a component the base fixture declares, so a
/// request built for it is inside its safe-set by default. Anything not
/// named here is a component a test added itself with [`sample_spec`].
fn spec_for(component: &str) -> RegistrationSpec {
    match component {
        "roxyd" => RegistrationSpec {
            cert_group: None,
            reload: ReloadSpec::new(ReloadKind::Systemd, "roxyd.service"),
        },
        "review" => RegistrationSpec {
            cert_group: Some(3000),
            reload: ReloadSpec::new(ReloadKind::DockerRestart, "review"),
        },
        _ => sample_spec(),
    }
}

fn requested(spec: &RegistrationSpec) -> RequestedSpec {
    RequestedSpec::new(spec.reload.clone(), spec.cert_group)
}

/// Writes a rendered config into a fresh temporary directory and loads it
/// through the production loader.
fn load_fixture(fixture: &RegistrarConfigFixture) -> (TempDir, RegistrarConfig) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = fixture.write_to(dir.path()).expect("write fixture");
    let config = RegistrarConfig::load(&path).expect("the fixture must load");
    (dir, config)
}

/// The fixture every test starts from: the three documented components,
/// plus one under the reserved prefix so a test can prove the reserved
/// guard runs *before* the component lookup.
fn base_fixture() -> RegistrarConfigFixture {
    RegistrarConfigFixture::new().with_component(
        "bootroot-decoy",
        Multiplicity::OnePerHost,
        &RegistrationSpec {
            cert_group: None,
            reload: ReloadSpec::none(),
        },
    )
}

fn verbs_with(client: OpenBaoClient, kv_mount: &str, config: RegistrarConfig) -> RegistrarVerbs {
    RegistrarVerbs::new(RegistrarVerbsConfig {
        client,
        kv_mount: kv_mount.to_string(),
        config,
        secret_id_options: SecretIdOptions {
            ttl: Some("10m".to_string()),
            num_uses: Some(1),
            ..Default::default()
        },
        token_ttl: TOKEN_TTL.to_string(),
        secret_id_ttl: SECRET_ID_TTL.to_string(),
        wrap_ttl_policy: WrapTtlPolicy::new(Duration::minutes(30)).expect("policy maximum"),
    })
}

fn mint_request(service_name: &str, host: &str, instance: Option<u32>) -> MintRequest {
    MintRequest {
        caller: CallerIdentity::new(CALLER),
        service_name: service_name.to_string(),
        host: host.to_string(),
        instance,
        spec: requested(&spec_for(service_name)),
        wrap_ttl: Duration::minutes(5),
    }
}

fn deregister_request(service_name: &str, host: &str, instance: Option<u32>) -> DeregisterRequest {
    DeregisterRequest {
        caller: CallerIdentity::new(CALLER),
        service_name: service_name.to_string(),
        host: host.to_string(),
        instance,
    }
}

/// Asserts that a refusal names the caller verbatim, carries the expected
/// arm, and — for a pre-derivation or derivation arm — reports no
/// `registration_id`.
fn assert_envelope(refusal: &VerbRefusal, arm: ProducingArm) {
    let context = refusal.context();
    assert_eq!(context.caller().as_str(), CALLER);
    assert!(!context.request_id().as_str().is_empty());
    assert_eq!(context.arm(), arm);
    if matches!(arm, ProducingArm::PreDerivation | ProducingArm::Derivation) {
        assert_eq!(
            context.registration_id(),
            None,
            "a refusal before derivation must carry no registration_id"
        );
    }
}

// ---------------------------------------------------------------------
// Fast tier: pre-derivation control flow
// ---------------------------------------------------------------------

/// A verb service over a Wiremock with **no** mounted responses: any
/// request at all fails the mock, and the count is asserted directly.
async fn refusal_harness(
    fixture: &RegistrarConfigFixture,
) -> (MockServer, TempDir, RegistrarVerbs) {
    let server = MockServer::start().await;
    let mut client = OpenBaoClient::new(&server.uri()).expect("client");
    client.set_token("test-token".to_string());
    let (dir, config) = load_fixture(fixture);
    let verbs = verbs_with(client, "secret", config);
    (server, dir, verbs)
}

async fn assert_untouched(server: &MockServer, verbs: &RegistrarVerbs) {
    let requests = server
        .received_requests()
        .await
        .expect("the mock server records requests");
    assert!(
        requests.is_empty(),
        "a pre-derivation refusal must reach OpenBao not at all, saw {} request(s)",
        requests.len()
    );
    assert_eq!(
        verbs.tracked_lock_count(),
        0,
        "a refusal before the per-id stage must take no per-id lock"
    );
}

/// The reserved namespace is refused case-insensitively, and it is
/// refused *before* the component lookup: the fixture declares
/// `bootroot-decoy` as a perfectly ordinary component, and it is still
/// unmintable.
#[tokio::test]
async fn both_verbs_refuse_a_reserved_service_name_before_the_component_lookup() {
    let (server, _dir, verbs) = refusal_harness(&base_fixture()).await;

    for name in ["bootroot-decoy", "BOOTROOT-Decoy", "bootroot-registrar"] {
        let refusal = verbs
            .mint(&mint_request(name, "h1", None))
            .await
            .expect_err("a reserved service_name must be refused");
        assert_envelope(&refusal, ProducingArm::PreDerivation);
        assert!(
            matches!(refusal.error(), VerbError::ReservedServiceName { service_name } if service_name == name),
            "expected a reserved-name refusal for {name}, got {:?}",
            refusal.error()
        );

        let refusal = verbs
            .deregister(&deregister_request(name, "h1", None))
            .await
            .expect_err("a reserved service_name must be refused");
        assert_envelope(&refusal, ProducingArm::PreDerivation);
        assert!(matches!(
            refusal.error(),
            VerbError::ReservedServiceName { .. }
        ));
    }
    assert_untouched(&server, &verbs).await;
}

#[tokio::test]
async fn both_verbs_refuse_an_invalid_label() {
    let (server, _dir, verbs) = refusal_harness(&base_fixture()).await;

    let refusal = verbs
        .mint(&mint_request("bad_name", "h1", None))
        .await
        .expect_err("an invalid service_name must be refused");
    assert_envelope(&refusal, ProducingArm::PreDerivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::InvalidServiceName { .. })
    ));

    let refusal = verbs
        .deregister(&deregister_request("roxyd", "-h1", None))
        .await
        .expect_err("an invalid host must be refused");
    assert_envelope(&refusal, ProducingArm::PreDerivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::InvalidHost { .. })
    ));

    assert_untouched(&server, &verbs).await;
}

#[tokio::test]
async fn both_verbs_refuse_an_absent_component() {
    let (server, _dir, verbs) = refusal_harness(&base_fixture().without_component("roxyd")).await;

    let refusal = verbs
        .mint(&mint_request("roxyd", "h1", None))
        .await
        .expect_err("an absent component must be refused");
    assert_envelope(&refusal, ProducingArm::PreDerivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::ComponentNotConfigured { .. })
    ));

    let refusal = verbs
        .deregister(&deregister_request("roxyd", "h1", None))
        .await
        .expect_err("an absent component must be refused");
    assert_envelope(&refusal, ProducingArm::PreDerivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::ComponentNotConfigured { .. })
    ));

    assert_untouched(&server, &verbs).await;
}

#[tokio::test]
async fn both_verbs_refuse_an_instance_shape_mismatch() {
    let (server, _dir, verbs) = refusal_harness(&base_fixture()).await;

    // `piglet` is many-per-host: an instance is required.
    let refusal = verbs
        .mint(&mint_request("piglet", "h1", None))
        .await
        .expect_err("a missing instance must be refused");
    assert_envelope(&refusal, ProducingArm::PreDerivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::ServiceInstanceMismatch { .. })
    ));

    // `roxyd` is one-per-host: an instance is forbidden.
    let refusal = verbs
        .deregister(&deregister_request("roxyd", "h1", Some(1)))
        .await
        .expect_err("a supplied instance must be refused");
    assert_envelope(&refusal, ProducingArm::PreDerivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::ServiceInstanceMismatch { .. })
    ));

    assert_untouched(&server, &verbs).await;
}

/// A mint-only refusal: a deregister carries no spec to restate an
/// identity with.
#[tokio::test]
async fn mint_refuses_a_spec_identity_disagreement_before_derivation() {
    let (server, _dir, verbs) = refusal_harness(&base_fixture()).await;

    let mut request = mint_request("roxyd", "h1", None);
    request.spec = requested(&sample_spec()).with_service_name("roxyd-h1");
    let refusal = verbs
        .mint(&request)
        .await
        .expect_err("a restated identity that disagrees must be refused");
    assert_envelope(&refusal, ProducingArm::PreDerivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::SpecIdentityDisagreement {
            field: SpecIdentityField::ServiceName,
            ..
        })
    ));

    assert_untouched(&server, &verbs).await;
}

/// Both named derivation failures: the derived key exceeds the 131-octet
/// bound, and an uppercase host makes it non-path-safe. Neither takes a
/// per-id lock, and neither reaches `OpenBao`.
#[tokio::test]
async fn derivation_failures_take_no_lock_and_no_openbao_work() {
    let long_component = "c".repeat(63);
    let long_host = "h".repeat(63);
    let fixture =
        base_fixture().with_component(&long_component, Multiplicity::ManyPerHost, &sample_spec());
    let (server, _dir, verbs) = refusal_harness(&fixture).await;

    // 63 + 1 + 63 + 1 + 4 = 132 octets, one past the bound.
    let refusal = verbs
        .mint(&mint_request(&long_component, &long_host, Some(1000)))
        .await
        .expect_err("an over-long derived key must be refused");
    assert_envelope(&refusal, ProducingArm::Derivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::DerivedKeyInvalid { .. })
    ));

    // The host label is a valid DNS label but not a path-safe key
    // segment, so the failure is on the derived string.
    let refusal = verbs
        .deregister(&deregister_request("roxyd", "H1", None))
        .await
        .expect_err("an uppercase host must fail derivation");
    assert_envelope(&refusal, ProducingArm::Derivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::DerivedKeyInvalid { .. })
    ));

    assert_untouched(&server, &verbs).await;
}

// ---------------------------------------------------------------------
// Fast tier: the binding record
// ---------------------------------------------------------------------

fn binding_spec_for(kind: ReloadKind) -> BindingSpec {
    let reload = if kind.takes_target() {
        ReloadSpec::new(kind, "target-1")
    } else {
        ReloadSpec::none()
    };
    BindingSpec::from_requested(&RequestedSpec::new(reload, Some(3000)))
}

/// The record's version-1 JSON is pinned field by field, for a `creating`
/// record and for the `active` one it becomes.
#[test]
fn binding_record_round_trips_its_version_one_json() {
    let spec = requested(&sample_spec());
    let creating = BindingRecord::creating("h1", &spec);
    let encoded = creating.encode().expect("encode");
    assert_eq!(
        encoded,
        json!({
            "schema_version": 1,
            "host": "h1",
            "state": "creating",
            "requested_spec": {
                "cert_group": 3001,
                "reload": { "kind": "docker-restart", "target": "piglet" }
            },
            "applied_spec": null
        })
    );
    assert_eq!(BindingRecord::decode(&encoded).expect("decode"), creating);

    let active = creating.activated(&spec);
    let encoded = active.encode().expect("encode");
    assert_eq!(encoded["state"], json!("active"));
    assert_eq!(encoded["applied_spec"], encoded["requested_spec"]);
    assert_eq!(BindingRecord::decode(&encoded).expect("decode"), active);
    assert_eq!(active.state, BindingState::Active);
}

/// Every reload kind round-trips, and each local spelling is the one the
/// registrar vocabulary uses — so a variant added to [`ReloadKind`]
/// cannot silently acquire a different word here.
#[test]
fn binding_reload_kinds_round_trip_and_match_the_registrar_spellings() {
    for kind in [
        ReloadKind::Sighup,
        ReloadKind::Systemd,
        ReloadKind::DockerRestart,
        ReloadKind::None,
    ] {
        let local = BindingReloadKind::from(kind);
        assert_eq!(local.as_str(), kind.as_str());
        assert_eq!(BindingReloadKind::parse(kind.as_str()), Some(local));
        assert_eq!(ReloadKind::from(local), kind);

        let spec = binding_spec_for(kind);
        let record = BindingRecord {
            schema_version: BINDING_SCHEMA_VERSION,
            host: "h1".to_string(),
            state: BindingState::Active,
            requested_spec: Some(spec.clone()),
            applied_spec: Some(spec.clone()),
        };
        let encoded = record.encode().expect("encode");
        assert_eq!(
            encoded["requested_spec"]["reload"]["kind"],
            json!(kind.as_str())
        );
        assert_eq!(BindingRecord::decode(&encoded).expect("decode"), record);
        assert_eq!(spec.to_registration_spec().reload.kind, kind);
    }
    assert_eq!(BindingReloadKind::parse("reboot"), None);
}

#[test]
fn binding_record_rejects_an_unknown_field() {
    let mut encoded = BindingRecord::creating("h1", &requested(&sample_spec()))
        .encode()
        .expect("encode");
    encoded["intent"] = json!("mint");
    let err = BindingRecord::decode(&encoded).expect_err("an unknown field must be refused");
    assert!(
        format!("{err}").contains("intent"),
        "the refusal must name the unknown field, got: {err}"
    );
}

#[test]
fn binding_record_rejects_an_unknown_schema_version() {
    let mut encoded = BindingRecord::creating("h1", &requested(&sample_spec()))
        .encode()
        .expect("encode");
    encoded["schema_version"] = json!(2);
    let err = BindingRecord::decode(&encoded).expect_err("a newer schema must be refused");
    assert!(
        format!("{err}").contains("schema_version 2"),
        "the refusal must name the version it found, got: {err}"
    );

    // A record whose version is unreadable is refused too, and it is a
    // distinguishable failure rather than a shape complaint.
    let err = BindingRecord::decode(&json!({ "host": "h1" }))
        .expect_err("a record with no version must be refused");
    assert!(format!("{err}").contains("schema_version"), "got: {err}");
}

/// A newer record carrying fields this build does not know is refused as
/// a *version* problem, not as an unknown field: the version gate reads
/// its own shape before the body is parsed.
#[test]
fn binding_record_reads_the_version_of_a_newer_record_before_its_body() {
    let err = BindingRecord::decode(&json!({
        "schema_version": 7,
        "host": "h1",
        "lease": { "epoch": 3 }
    }))
    .expect_err("a newer record must be refused");
    assert!(format!("{err}").contains("schema_version 7"), "got: {err}");
}

// ---------------------------------------------------------------------
// Fast tier: the wrap-TTL policy and the granted deadline
// ---------------------------------------------------------------------

#[test]
fn wrap_ttl_policy_refuses_zero_negative_and_unrepresentable_requests() {
    let policy = WrapTtlPolicy::new(Duration::minutes(30)).expect("policy");
    assert_eq!(policy.grant(Duration::ZERO), Err(WrapTtlRefusal::Zero));
    assert_eq!(
        policy.grant(Duration::seconds(-1)),
        Err(WrapTtlRefusal::Negative)
    );
    assert_eq!(
        policy.grant(Duration::milliseconds(-500)),
        Err(WrapTtlRefusal::Negative)
    );
    assert_eq!(
        policy.grant(Duration::milliseconds(1500)),
        Err(WrapTtlRefusal::NotWholeSeconds)
    );
    // Below a whole second, which has no OpenBao spelling either.
    assert_eq!(
        policy.grant(Duration::milliseconds(500)),
        Err(WrapTtlRefusal::NotWholeSeconds)
    );
}

#[test]
fn wrap_ttl_policy_grants_the_minimum_of_request_and_maximum() {
    let policy = WrapTtlPolicy::new(Duration::minutes(30)).expect("policy");
    assert_eq!(policy.maximum(), Duration::minutes(30));

    let granted = policy
        .grant(Duration::minutes(5))
        .expect("within the maximum");
    assert_eq!(granted.duration(), Duration::minutes(5));
    assert_eq!(granted.as_openbao_str(), "300s");

    let granted = policy.grant(Duration::hours(4)).expect("clamped");
    assert_eq!(granted.duration(), Duration::minutes(30));
    assert_eq!(granted.as_openbao_str(), "1800s");

    let granted = policy
        .grant(Duration::minutes(30))
        .expect("exactly at the maximum");
    assert_eq!(granted.duration(), Duration::minutes(30));
}

#[test]
fn wrap_ttl_policy_holds_its_own_maximum_to_the_same_rules() {
    assert_eq!(
        WrapTtlPolicy::new(Duration::ZERO),
        Err(WrapTtlRefusal::Zero)
    );
    assert_eq!(
        WrapTtlPolicy::new(Duration::seconds(-30)),
        Err(WrapTtlRefusal::Negative)
    );
}

/// The granted deadline comes from what `OpenBao` reported, so a
/// server-side clamp — a TTL smaller than the one asked for — is
/// reflected rather than the request being echoed back.
#[test]
fn granted_deadline_reflects_the_reported_creation_time_and_ttl() {
    let wrap_info = WrapInfo {
        token: "wrap-token".to_string(),
        ttl: 60,
        creation_time: "2026-08-18T12:00:00Z".to_string(),
        creation_path: "auth/approle/role/x/secret-id".to_string(),
    };
    let deadline = granted_deadline(&wrap_info).expect("a well-formed WrapInfo");
    assert_eq!(
        deadline,
        OffsetDateTime::parse("2026-08-18T12:01:00Z", &Rfc3339).expect("expected deadline")
    );
}

#[test]
fn granted_deadline_refuses_a_creation_time_that_is_not_rfc3339() {
    let wrap_info = WrapInfo {
        token: "wrap-token".to_string(),
        ttl: 60,
        creation_time: "not a timestamp".to_string(),
        creation_path: "auth/approle/role/x/secret-id".to_string(),
    };
    assert!(granted_deadline(&wrap_info).is_err());
}

/// A mint whose `wrap_ttl` cannot produce a usable lifetime is refused
/// before any `OpenBao` call, so no credential and no binding is created
/// that would then have to be revoked.
#[tokio::test]
async fn mint_refuses_an_unusable_wrap_ttl_before_touching_openbao() {
    let (server, _dir, verbs) = refusal_harness(&base_fixture()).await;

    for (requested, expected) in [
        (Duration::ZERO, WrapTtlRefusal::Zero),
        (Duration::seconds(-5), WrapTtlRefusal::Negative),
        (Duration::milliseconds(250), WrapTtlRefusal::NotWholeSeconds),
    ] {
        let mut request = mint_request("roxyd", "h1", None);
        request.wrap_ttl = requested;
        let refusal = verbs
            .mint(&request)
            .await
            .expect_err("an unusable wrap_ttl must be refused");
        assert_envelope(&refusal, ProducingArm::PreDerivation);
        assert!(
            matches!(refusal.error(), VerbError::InvalidWrapTtl(err) if *err == expected),
            "expected {expected:?}, got {:?}",
            refusal.error()
        );
    }
    assert_untouched(&server, &verbs).await;
}

// ---------------------------------------------------------------------
// Fast tier: the outcome's redaction and the teardown suffix set
// ---------------------------------------------------------------------

/// No `Debug` on a successful mint may print the wrapped token, and the
/// only way to get at it is the consuming accessor on the outcome.
#[test]
fn a_mint_outcome_redacts_its_wrapped_token_in_debug() {
    const TOKEN: &str = "hvs.super-secret-wrap-token";
    let outcome = MintOutcome::new(
        VerbContext::new(
            RequestId::generate(),
            CallerIdentity::new(CALLER),
            Some("h1-roxyd".to_string()),
            ProducingArm::Issuance,
        ),
        MintKind::FirstMint,
        "001.roxyd.h1.trusted.domain".to_string(),
        "role-id".to_string(),
        WrappedSecretIdToken::new(TOKEN.to_string()),
        OffsetDateTime::now_utc(),
    );

    let rendered = format!("{outcome:?}");
    assert!(
        !rendered.contains(TOKEN),
        "the wrapped token must never reach a Debug rendering: {rendered}"
    );
    assert!(
        rendered.contains("<redacted>"),
        "the redaction must be visible rather than the field being dropped: {rendered}"
    );
    assert!(
        rendered.contains("role-id"),
        "the rest of the outcome must still be legible: {rendered}"
    );
    assert_eq!(
        format!("{:?}", WrappedSecretIdToken::new(TOKEN.to_string())),
        "<redacted>"
    );
    assert_eq!(outcome.into_wrapped_secret_id(), TOKEN);
}

/// The registrar sweeps all five service-material suffixes, `reissue`
/// included, and never the binding — which outlives the material and is
/// deleted separately.
#[test]
fn the_registrar_teardown_set_is_the_five_material_suffixes_and_not_the_binding() {
    use crate::trust_bootstrap::{
        SERVICE_EAB_KV_SUFFIX, SERVICE_REISSUE_KV_SUFFIX, SERVICE_RESPONDER_HMAC_KV_SUFFIX,
        SERVICE_SECRET_ID_KV_SUFFIX, SERVICE_TRUST_KV_SUFFIX,
    };

    assert_eq!(
        REGISTRAR_TEARDOWN_KV_SUFFIXES,
        [
            SERVICE_EAB_KV_SUFFIX,
            SERVICE_RESPONDER_HMAC_KV_SUFFIX,
            SERVICE_TRUST_KV_SUFFIX,
            SERVICE_SECRET_ID_KV_SUFFIX,
            SERVICE_REISSUE_KV_SUFFIX,
        ]
    );
    assert!(
        !REGISTRAR_TEARDOWN_KV_SUFFIXES.contains(&REGISTRAR_BINDING_KV_SUFFIX),
        "the binding must never be swept as material"
    );
}

// ---------------------------------------------------------------------
// Ignored tier: everything that depends on a prior OpenBao write
// ---------------------------------------------------------------------

/// The live backend's connection details, read from the scenario-supplied
/// environment. Nothing here writes the environment.
struct LiveBackend {
    url: String,
    token: String,
    kv_mount: String,
}

impl LiveBackend {
    fn from_env() -> Self {
        let read = |name: &str| {
            std::env::var(name).unwrap_or_else(|_| {
                panic!("{name} must be set; run scripts/impl/run-registrar-verbs-e2e.sh")
            })
        };
        Self {
            url: read(ENV_OPENBAO_URL),
            token: read(ENV_OPENBAO_TOKEN),
            kv_mount: read(ENV_KV_MOUNT),
        }
    }

    fn client(&self) -> OpenBaoClient {
        self.client_with_token(&self.token)
    }

    fn client_with_token(&self, token: &str) -> OpenBaoClient {
        let mut client = OpenBaoClient::new(&self.url).expect("client");
        client.set_token(token.to_string());
        client
    }

    fn verbs(&self, config: RegistrarConfig) -> RegistrarVerbs {
        verbs_with(self.client(), &self.kv_mount, config)
    }

    /// Issues a token carrying exactly `policies`, so a test can drive a
    /// verb whose privileges are deliberately incomplete.
    async fn scoped_token(&self, policies: &[&str]) -> String {
        let response = reqwest::Client::new()
            .post(format!("{}/v1/auth/token/create", self.url))
            .header("X-Vault-Token", &self.token)
            .json(&json!({ "policies": policies, "ttl": "30m", "no_default_policy": true }))
            .send()
            .await
            .expect("token create");
        let body: serde_json::Value = response.json().await.expect("token create body");
        body["auth"]["client_token"]
            .as_str()
            .expect("a client token")
            .to_string()
    }

    async fn read_role(&self, role_name: &str) -> Option<serde_json::Value> {
        let response = reqwest::Client::new()
            .get(format!("{}/v1/auth/approle/role/{role_name}", self.url))
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .expect("role read");
        if !response.status().is_success() {
            return None;
        }
        let body: serde_json::Value = response.json().await.expect("role body");
        Some(body["data"].clone())
    }

    async fn lookup_secret_id(&self, role_name: &str, secret_id: &str) -> serde_json::Value {
        let response = reqwest::Client::new()
            .post(format!(
                "{}/v1/auth/approle/role/{role_name}/secret-id/lookup",
                self.url
            ))
            .header("X-Vault-Token", &self.token)
            .json(&json!({ "secret_id": secret_id }))
            .send()
            .await
            .expect("secret-id lookup");
        let body: serde_json::Value = response.json().await.expect("lookup body");
        body["data"].clone()
    }

    async fn binding_of(&self, registration_id: &str) -> Option<serde_json::Value> {
        self.client()
            .try_read_kv(
                &self.kv_mount,
                &format!("bootroot/services/{registration_id}/{REGISTRAR_BINDING_KV_SUFFIX}"),
            )
            .await
            .expect("binding read")
    }

    async fn plant(&self, registration_id: &str, suffix: &str) {
        self.client()
            .write_kv(
                &self.kv_mount,
                &format!("bootroot/services/{registration_id}/{suffix}"),
                json!({ "planted": true }),
            )
            .await
            .expect("plant a record");
    }

    async fn kv_exists(&self, registration_id: &str, suffix: &str) -> bool {
        self.client()
            .kv_exists(
                &self.kv_mount,
                &format!("bootroot/services/{registration_id}/{suffix}"),
            )
            .await
            .expect("kv exists")
    }
}

/// Grants exactly what a verb needs to read and claim a binding, and
/// nothing that would let it write a policy — so a mint's compare-and-set
/// wins and its convergence then fails.
async fn install_binding_only_policy(backend: &LiveBackend, name: &str) {
    let mount = &backend.kv_mount;
    let policy = format!(
        r#"path "{mount}/data/bootroot/services/*" {{
  capabilities = ["create", "read", "update"]
}}
path "{mount}/metadata/bootroot/services/*" {{
  capabilities = ["read", "list", "delete"]
}}
"#
    );
    backend
        .client()
        .write_policy(name, &policy)
        .await
        .expect("write the restricted policy");
}

#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn first_mint_creates_exactly_the_derived_role_and_policy() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let verbs = backend.verbs(config);

    let outcome = verbs
        .mint(&mint_request("piglet", &host, Some(1)))
        .await
        .expect("the first mint must succeed");
    let registration_id = format!("{host}-piglet-001");

    assert_eq!(outcome.kind(), MintKind::FirstMint);
    assert_eq!(outcome.context().caller().as_str(), CALLER);
    assert_eq!(
        outcome.context().registration_id(),
        Some(registration_id.as_str())
    );
    assert_eq!(
        outcome.san(),
        format!("001.piglet.{host}.trusted.domain"),
        "the SAN is composed from the parts and the rendered domain"
    );

    let role_name = service_role_name(&registration_id);
    let role = backend
        .read_role(&role_name)
        .await
        .expect("the derived role must exist");
    assert_eq!(
        role["token_policies"],
        json!([service_policy_name(&registration_id)]),
        "the role must carry exactly the derived policy"
    );
    assert_eq!(role["token_ttl"], json!(3600));
    assert_eq!(role["secret_id_ttl"], json!(86400));

    // The binding is active before any material was returned.
    let binding = backend
        .binding_of(&registration_id)
        .await
        .expect("a binding must exist");
    assert_eq!(binding["state"], json!("active"));
    assert_eq!(binding["host"], json!(host));
    assert_eq!(binding["applied_spec"], binding["requested_spec"]);

    // The material is wrap-only: unwrapping it here is the first and only
    // unwrap, which is what proves the verb did not unwrap it itself.
    let expires_at = outcome.expires_at();
    let now = OffsetDateTime::now_utc();
    assert!(expires_at > now && expires_at <= now + Duration::minutes(6));
    let token = outcome.into_wrapped_secret_id();
    let secret_id = backend
        .client()
        .unwrap_secret_id(&token)
        .await
        .expect("the wrap token must still be unused");
    let lookup = backend.lookup_secret_id(&role_name, &secret_id).await;
    assert_eq!(
        lookup["secret_id_num_uses"],
        json!(1),
        "the construction-fixed secret-id options must be what was applied"
    );

    verbs
        .deregister(&deregister_request("piglet", &host, Some(1)))
        .await
        .expect("cleanup");
}

/// A same-host, same-spec re-mint returns fresh material and leaves the
/// role and policy exactly as they were.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn same_host_rematch_reuses_the_role_and_returns_fresh_material() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let verbs = backend.verbs(config);
    let registration_id = format!("{host}-roxyd");
    let role_name = service_role_name(&registration_id);

    let request = mint_request("roxyd", &host, None);
    let first = verbs.mint(&request).await.expect("first mint");
    assert_eq!(first.kind(), MintKind::FirstMint);
    let first_role_id = first.role_id().to_string();
    let first_token = first.into_wrapped_secret_id();

    // A different caller identity reaches the outcome unchanged and
    // influences neither the derived identity nor the role it addresses.
    let mut other_caller = request.clone();
    other_caller.caller = CallerIdentity::new("spiffe://review/other#0001");
    let second = verbs.mint(&other_caller).await.expect("re-mint");
    assert_eq!(
        second.context().caller().as_str(),
        "spiffe://review/other#0001"
    );
    assert_eq!(
        second.context().registration_id(),
        Some(registration_id.as_str()),
        "the caller identity is no part of the derivation"
    );
    assert_eq!(second.kind(), MintKind::IdempotentReMint);
    assert_eq!(
        second.role_id(),
        first_role_id,
        "a re-mint must not replace the role"
    );
    let second_token = second.into_wrapped_secret_id();
    assert_ne!(first_token, second_token, "the material must be fresh");

    // Both tokens are live and independent: the re-mint issued a new
    // secret_id rather than re-wrapping the first.
    let role = backend.read_role(&role_name).await.expect("role");
    assert_eq!(role["token_policies"], json!([role_name]));
    backend
        .client()
        .unwrap_secret_id(&first_token)
        .await
        .expect("the first token is still unused");
    backend
        .client()
        .unwrap_secret_id(&second_token)
        .await
        .expect("the second token is unused");

    verbs
        .deregister(&deregister_request("roxyd", &host, None))
        .await
        .expect("cleanup");
}

/// A request larger than the registrar's maximum is clamped, and the
/// deadline reported is the granted one — never the requested one.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn a_request_over_the_maximum_is_clamped_in_the_granted_expiry() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let verbs = backend.verbs(config);

    let mut request = mint_request("piglet", &host, Some(2));
    request.wrap_ttl = Duration::hours(12);
    let before = OffsetDateTime::now_utc();
    let outcome = verbs.mint(&request).await.expect("mint");
    let expires_at = outcome.expires_at();

    assert!(
        expires_at <= before + Duration::minutes(31),
        "the granted deadline must reflect the registrar's 30m maximum, got {expires_at}"
    );
    assert!(
        expires_at > before,
        "the granted deadline must be in the future, got {expires_at}"
    );

    verbs
        .deregister(&deregister_request("piglet", &host, Some(2)))
        .await
        .expect("cleanup");
}

/// The non-injective pair: `web` on `h1-aimer` and `aimer-web` on `h1`
/// derive one id, and the second host is refused **before** any spec
/// comparison — including from a second verb service, which is what a
/// second process would be.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn a_second_host_is_refused_before_the_spec_comparison_across_instances() {
    let backend = LiveBackend::from_env();
    let stem = unique_label("n");
    // `web` on `<stem>-aimer` and `aimer-web` on `<stem>` derive one id:
    // both a component name and a host label may carry hyphens, so the
    // derivation is not injective and the durable binding is the only
    // thing that can tell the two installations apart.
    let host_a = format!("{stem}-aimer");
    let host_b = stem.clone();
    let fixture = base_fixture()
        .with_component("web", Multiplicity::ManyPerHost, &sample_spec())
        .with_component("aimer-web", Multiplicity::ManyPerHost, &sample_spec());
    let (_dir_one, config_one) = load_fixture(&fixture);
    let (_dir_two, config_two) = load_fixture(&fixture);
    let first = backend.verbs(config_one);
    let second = backend.verbs(config_two);

    let derived = format!("{host_a}-web-001");
    assert_eq!(
        derived,
        format!("{host_b}-aimer-web-001"),
        "the pair must derive one id"
    );

    first
        .mint(&mint_request("web", &host_a, Some(1)))
        .await
        .expect("the first host claims the id");

    // A different verb service, sharing only OpenBao: the refusal comes
    // from the durable binding, not from process memory, so it is the
    // same refusal a restarted registrar would produce.
    let refusal = second
        .mint(&mint_request("aimer-web", &host_b, Some(1)))
        .await
        .expect_err("the second host must be refused");
    assert!(
        matches!(
            refusal.error(),
            VerbError::RegistrationIdCollision { stored_host, .. } if *stored_host == host_a
        ),
        "expected a collision naming the bound host, got {:?}",
        refusal.error()
    );
    assert_eq!(refusal.context().arm(), ProducingArm::Binding);

    let binding = backend.binding_of(&derived).await.expect("binding");
    assert_eq!(binding["host"], json!(host_a));
    assert_eq!(binding["state"], json!("active"));

    first
        .deregister(&deregister_request("web", &host_a, Some(1)))
        .await
        .expect("cleanup");
}

/// Safe-set refusal and stored-spec conflict are distinct, and neither
/// changes anything.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn safe_set_refusal_and_stored_spec_conflict_are_distinct_no_change_outcomes() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let component = unique_label("c");
    let rendered = sample_spec();
    let fixture = base_fixture().with_component(&component, Multiplicity::ManyPerHost, &rendered);
    let (_dir, config) = load_fixture(&fixture);
    let verbs = backend.verbs(config);
    let registration_id = format!("{host}-{component}-001");

    // No binding yet: a spec outside the rendered safe-set is refused,
    // and nothing is claimed.
    let mut outside = mint_request(&component, &host, Some(1));
    outside.spec = requested(&RegistrationSpec {
        cert_group: Some(9999),
        reload: rendered.reload.clone(),
    });
    let refusal = verbs
        .mint(&outside)
        .await
        .expect_err("a spec outside the safe-set must be refused");
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::ServiceSpecOutsideSafeSet { .. })
    ));
    assert_eq!(refusal.context().arm(), ProducingArm::SafeSet);
    assert!(
        backend.binding_of(&registration_id).await.is_none(),
        "a safe-set refusal must claim nothing"
    );

    verbs
        .mint(&mint_request(&component, &host, Some(1)))
        .await
        .expect("the in-safe-set mint succeeds");

    // Now re-render the config so a different spec is inside the
    // safe-set, and re-mint: the *stored* spec is what disagrees.
    let widened = RegistrationSpec {
        cert_group: Some(4242),
        reload: rendered.reload.clone(),
    };
    let (_dir2, config2) = load_fixture(&base_fixture().with_component(
        &component,
        Multiplicity::ManyPerHost,
        &widened,
    ));
    let rewidened = backend.verbs(config2);
    let mut conflicting = mint_request(&component, &host, Some(1));
    conflicting.spec = requested(&widened);
    let refusal = rewidened
        .mint(&conflicting)
        .await
        .expect_err("a stored-spec disagreement must be refused");
    assert!(
        matches!(refusal.error(), VerbError::StoredSpecConflict { .. }),
        "expected a stored-spec conflict, got {:?}",
        refusal.error()
    );
    let binding = backend.binding_of(&registration_id).await.expect("binding");
    assert_eq!(binding["applied_spec"]["cert_group"], json!(3001));

    verbs
        .deregister(&deregister_request(&component, &host, Some(1)))
        .await
        .expect("cleanup");
}

/// A failed convergence retains its `creating` binding. The matching host
/// recovers by re-driving the mint; a different host stays refused; and
/// nothing manufactures an unbound partial state.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn a_failed_convergence_retains_its_creating_binding_and_recovers() {
    let backend = LiveBackend::from_env();
    let stem = unique_label("r");
    let policy_name = format!("bootroot-test-{stem}");
    install_binding_only_policy(&backend, &policy_name).await;
    let restricted = backend.scoped_token(&[policy_name.as_str()]).await;

    // One-per-deployment, so the derived id is the bare component name
    // and two different hosts address the same identity.
    let component = format!("{stem}c");
    let host = format!("{stem}a");
    let other_host = format!("{stem}b");
    let fixture =
        base_fixture().with_component(&component, Multiplicity::OnePerDeployment, &sample_spec());
    let (_dir, config) = load_fixture(&fixture);
    let crippled = verbs_with(
        backend.client_with_token(&restricted),
        &backend.kv_mount,
        config,
    );
    let registration_id = component.clone();

    let request = mint_request(&component, &host, None);
    let refusal = crippled
        .mint(&request)
        .await
        .expect_err("the convergence must fail without policy privileges");
    assert!(
        matches!(refusal.error(), VerbError::Unavailable { .. }),
        "expected an unavailable refusal, got {:?}",
        refusal.error()
    );
    assert_eq!(refusal.context().arm(), ProducingArm::Provisioning);

    let binding = backend
        .binding_of(&registration_id)
        .await
        .expect("the claim must be retained, not rolled back");
    assert_eq!(binding["state"], json!("creating"));
    assert_eq!(binding["host"], json!(host));
    assert_eq!(binding["applied_spec"], json!(null));
    assert!(
        backend
            .read_role(&service_role_name(&registration_id))
            .await
            .is_none(),
        "no role was created, and the binding is what covers that"
    );

    let (_dir2, config2) = load_fixture(&fixture);
    let privileged = backend.verbs(config2);

    // A different host cannot take a `creating` binding over.
    let refusal = privileged
        .mint(&mint_request(&component, &other_host, None))
        .await
        .expect_err("another host must not take a creating binding over");
    assert!(
        matches!(
            refusal.error(),
            VerbError::RegistrationIdCollision { stored_host, .. } if *stored_host == host
        ),
        "expected a collision, got {:?}",
        refusal.error()
    );
    let binding = backend.binding_of(&registration_id).await.expect("binding");
    assert_eq!(binding["state"], json!("creating"));
    assert_eq!(binding["host"], json!(host));

    // The matching host re-drives exactly the claimant's path.
    let recovered = privileged
        .mint(&request)
        .await
        .expect("the matching host re-drives the same path");
    assert_eq!(recovered.kind(), MintKind::FirstMint);
    let binding = backend.binding_of(&registration_id).await.expect("binding");
    assert_eq!(binding["state"], json!("active"));
    assert_eq!(binding["applied_spec"], binding["requested_spec"]);
    assert!(
        backend
            .read_role(&service_role_name(&registration_id))
            .await
            .is_some(),
        "the re-drive converges the role"
    );

    privileged
        .deregister(&deregister_request(&component, &host, None))
        .await
        .expect("cleanup");
}

/// A deregister from the wrong host changes neither the binding nor the
/// material.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn wrong_host_deregister_changes_nothing() {
    let backend = LiveBackend::from_env();
    let stem = unique_label("w");
    let component = format!("{stem}c");
    let bound_host = format!("{stem}a");
    let other_host = format!("{stem}b");
    // One-per-deployment, so the derived id does not carry the host and
    // both hosts address the same identity.
    let fixture =
        base_fixture().with_component(&component, Multiplicity::OnePerDeployment, &sample_spec());
    let (_dir, config) = load_fixture(&fixture);
    let verbs = backend.verbs(config);

    verbs
        .mint(&mint_request(&component, &bound_host, None))
        .await
        .expect("the bound host mints");

    let refusal = verbs
        .deregister(&deregister_request(&component, &other_host, None))
        .await
        .expect_err("a wrong-host deregister must be refused");
    assert!(
        matches!(
            refusal.error(),
            VerbError::HostMismatch { stored_host, .. } if *stored_host == bound_host
        ),
        "expected a host mismatch, got {:?}",
        refusal.error()
    );
    assert!(refusal.teardown().is_none(), "nothing may be torn down");

    assert!(backend.binding_of(&component).await.is_some());
    assert!(
        backend
            .read_role(&service_role_name(&component))
            .await
            .is_some()
    );

    // And a wrong-host *mint* is a collision, not a re-mint.
    let refusal = verbs
        .mint(&mint_request(&component, &other_host, None))
        .await
        .expect_err("a wrong-host mint must be refused");
    assert!(matches!(
        refusal.error(),
        VerbError::RegistrationIdCollision { .. }
    ));

    verbs
        .deregister(&deregister_request(&component, &bound_host, None))
        .await
        .expect("cleanup");
}

/// Matching-host deregister tears the material down first and only then
/// deletes the binding, and it sweeps all five suffixes.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn matching_host_deregister_tears_down_before_it_unbinds() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let verbs = backend.verbs(config);
    let registration_id = format!("{host}-piglet-003");

    verbs
        .mint(&mint_request("piglet", &host, Some(3)))
        .await
        .expect("mint");
    for suffix in REGISTRAR_TEARDOWN_KV_SUFFIXES {
        backend.plant(&registration_id, suffix).await;
    }

    let outcome = verbs
        .deregister(&deregister_request("piglet", &host, Some(3)))
        .await
        .expect("deregister");
    assert_eq!(outcome.kind(), DeregisterKind::IdentityRemoved);
    assert!(outcome.teardown().aggregate_success());
    assert_eq!(
        outcome.teardown().attempts().len(),
        REGISTRAR_TEARDOWN_KV_SUFFIXES.len() + 2,
        "every KV suffix plus the role and the policy"
    );

    for suffix in REGISTRAR_TEARDOWN_KV_SUFFIXES {
        assert!(
            !backend.kv_exists(&registration_id, suffix).await,
            "{suffix} must be swept"
        );
    }
    assert!(
        backend
            .read_role(&service_role_name(&registration_id))
            .await
            .is_none()
    );
    assert!(backend.binding_of(&registration_id).await.is_none());

    // A re-mint after deregister inherits nothing, `reissue` included.
    verbs
        .mint(&mint_request("piglet", &host, Some(3)))
        .await
        .expect("re-mint after removal");
    assert!(
        !backend
            .kv_exists(
                &registration_id,
                crate::trust_bootstrap::SERVICE_REISSUE_KV_SUFFIX
            )
            .await,
        "a re-mint must not inherit a reissue record"
    );
    verbs
        .deregister(&deregister_request("piglet", &host, Some(3)))
        .await
        .expect("cleanup");
}

/// With no binding at all, deregister still sweeps the full five-suffix
/// set plus the role and policy, and reports already-absent. This is the
/// accepted hazard the module header documents, exercised deliberately.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn absent_binding_deregister_sweeps_planted_orphans() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let verbs = backend.verbs(config);
    let registration_id = format!("{host}-roxyd");

    // Plant a full orphan: role, policy and every service record, with no
    // binding anywhere.
    backend
        .client()
        .write_policy(
            &service_policy_name(&registration_id),
            "path \"sys/health\" { capabilities = [\"read\"] }\n",
        )
        .await
        .expect("plant a policy");
    backend
        .client()
        .create_approle(
            &service_role_name(&registration_id),
            &[service_policy_name(&registration_id).as_str()],
            TOKEN_TTL,
            SECRET_ID_TTL,
            true,
        )
        .await
        .expect("plant a role");
    for suffix in REGISTRAR_TEARDOWN_KV_SUFFIXES {
        backend.plant(&registration_id, suffix).await;
    }
    assert!(backend.binding_of(&registration_id).await.is_none());

    let outcome = verbs
        .deregister(&deregister_request("roxyd", &host, None))
        .await
        .expect("an absent-binding deregister is idempotent");
    assert_eq!(outcome.kind(), DeregisterKind::AlreadyAbsent);
    assert!(outcome.teardown().aggregate_success());

    for suffix in REGISTRAR_TEARDOWN_KV_SUFFIXES {
        assert!(
            !backend.kv_exists(&registration_id, suffix).await,
            "{suffix} must be swept even with no binding"
        );
    }
    assert!(
        backend
            .read_role(&service_role_name(&registration_id))
            .await
            .is_none()
    );
    assert!(backend.binding_of(&registration_id).await.is_none());
}

/// An already-absent role, policy and material is a successful idempotent
/// teardown, and the binding is still removed after it.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn deregister_removes_the_binding_after_an_already_absent_teardown() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let verbs = backend.verbs(config);
    let registration_id = format!("{host}-roxyd");

    verbs
        .mint(&mint_request("roxyd", &host, None))
        .await
        .expect("mint");

    // Delete the role and policy out from under the binding.
    backend
        .client()
        .delete_approle(&service_role_name(&registration_id))
        .await
        .expect("delete role");
    backend
        .client()
        .delete_policy(&service_policy_name(&registration_id))
        .await
        .expect("delete policy");

    let outcome = verbs
        .deregister(&deregister_request("roxyd", &host, None))
        .await
        .expect("an already-absent teardown is still a success");
    assert_eq!(outcome.kind(), DeregisterKind::IdentityRemoved);
    assert!(outcome.teardown().aggregate_success());
    assert!(backend.binding_of(&registration_id).await.is_none());
}

/// A deregister whose component was removed from the rendered config
/// cannot resolve a multiplicity, so it is a pre-derivation refusal that
/// leaves the binding and the material intact.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn deregister_is_refused_when_the_component_left_the_configuration() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let verbs = backend.verbs(config);
    let registration_id = format!("{host}-roxyd");

    verbs
        .mint(&mint_request("roxyd", &host, None))
        .await
        .expect("mint");

    let (_dir2, trimmed) = load_fixture(&base_fixture().without_component("roxyd"));
    let after_rerender = backend.verbs(trimmed);
    let refusal = after_rerender
        .deregister(&deregister_request("roxyd", &host, None))
        .await
        .expect_err("an absent component cannot be deregistered");
    assert_envelope(&refusal, ProducingArm::PreDerivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::ComponentNotConfigured { .. })
    ));

    assert!(backend.binding_of(&registration_id).await.is_some());
    assert!(
        backend
            .read_role(&service_role_name(&registration_id))
            .await
            .is_some()
    );

    // Restoring the entry restores the ability to deregister.
    verbs
        .deregister(&deregister_request("roxyd", &host, None))
        .await
        .expect("cleanup once the entry is back");
}

/// Two verb services sharing one live `OpenBao` — the in-process stand-in
/// for two processes — race the compare-and-set for one derived id from
/// two different hosts. Exactly one gets material; the other is refused
/// through the CAS conflict path.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn two_instances_racing_one_id_produce_exactly_one_claimant() {
    let backend = LiveBackend::from_env();
    let stem = unique_label("x");
    let component = format!("{stem}c");
    let host_a = format!("{stem}a");
    let host_b = format!("{stem}b");
    let fixture =
        base_fixture().with_component(&component, Multiplicity::OnePerDeployment, &sample_spec());
    let (_dir_one, config_one) = load_fixture(&fixture);
    let (_dir_two, config_two) = load_fixture(&fixture);
    let first = backend.verbs(config_one);
    let second = backend.verbs(config_two);

    let request_a = mint_request(&component, &host_a, None);
    let request_b = mint_request(&component, &host_b, None);
    let (a, b) = tokio::join!(first.mint(&request_a), second.mint(&request_b));

    let winners = usize::from(a.is_ok()) + usize::from(b.is_ok());
    assert_eq!(winners, 1, "exactly one host may receive material");

    let ((Ok(_), Err(loser)) | (Err(loser), Ok(_))) = (a, b) else {
        unreachable!("exactly one winner was just asserted")
    };
    assert!(
        matches!(loser.error(), VerbError::RegistrationIdCollision { .. }),
        "the loser must be refused as a collision, got {:?}",
        loser.error()
    );

    let binding = backend.binding_of(&component).await.expect("binding");
    let bound = binding["host"].as_str().expect("a bound host").to_string();
    assert!(bound == host_a || bound == host_b);
    let winner = if bound == host_a { &first } else { &second };
    winner
        .deregister(&deregister_request(&component, &bound, None))
        .await
        .expect("cleanup");
}

/// A mint and a deregister for one identity, issued concurrently against
/// one service, are serialized: the result is one of the two clean
/// orderings, never a half-existing identity.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn a_concurrent_mint_and_deregister_never_interleave() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let verbs = Arc::new(backend.verbs(config));
    let registration_id = format!("{host}-roxyd");

    verbs
        .mint(&mint_request("roxyd", &host, None))
        .await
        .expect("seed the identity");

    let for_mint = Arc::clone(&verbs);
    let for_deregister = Arc::clone(&verbs);
    let mint_host = host.clone();
    let remove_host = host.clone();
    let mint_task = tokio::spawn(async move {
        for_mint
            .mint(&mint_request("roxyd", &mint_host, None))
            .await
            .is_ok()
    });
    let remove_task = tokio::spawn(async move {
        for_deregister
            .deregister(&deregister_request("roxyd", &remove_host, None))
            .await
            .is_ok()
    });
    let minted = mint_task.await.expect("the mint task must not panic");
    let removed = remove_task
        .await
        .expect("the deregister task must not panic");
    assert!(removed, "the deregister must complete either way");

    let binding_present = backend.binding_of(&registration_id).await.is_some();
    let role_present = backend
        .read_role(&service_role_name(&registration_id))
        .await
        .is_some();
    assert_eq!(
        binding_present, role_present,
        "the identity must be wholly present or wholly gone, never half: \
         minted={minted}, binding={binding_present}, role={role_present}"
    );

    if binding_present {
        verbs
            .deregister(&deregister_request("roxyd", &host, None))
            .await
            .expect("cleanup");
    }
}

/// The scenario passes the connection details in and the tests only read
/// them. This asserts the contract rather than assuming it.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn the_scenario_environment_is_read_only_and_complete() {
    let backend = LiveBackend::from_env();
    assert!(!backend.url.is_empty());
    assert!(!backend.token.is_empty());
    assert!(!backend.kv_mount.is_empty());
    backend
        .client()
        .health_check()
        .await
        .expect("the scenario's OpenBao must be reachable");
    // Unchanged after the whole suite has run: nothing here writes them.
    assert_eq!(
        std::env::var(ENV_OPENBAO_URL).ok().as_deref(),
        Some(backend.url.as_str())
    );
}
