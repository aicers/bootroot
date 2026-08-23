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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

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
    DeregisterRequest, IdLocks, MintRequest, REGISTRAR_TEARDOWN_KV_SUFFIXES, RegistrarVerbs,
    RegistrarVerbsConfig, granted_deadline,
};
use crate::openbao::{OpenBaoClient, SecretIdOptions, WrapInfo};
use crate::registrar::config::{
    Multiplicity, RegistrarConfig, RegistrationSpec, ReloadKind, ReloadSpec,
};
use crate::registrar::error::{RegistrarError, SpecIdentityField};
use crate::registrar::fixture::RegistrarConfigFixture;
use crate::registrar::identity::RequestedSpec;
use crate::service_material::{
    ResourceOutcome, ServiceResource, service_policy_name, service_role_name,
};

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

/// A client pointed at a Wiremock with **no** mounted responses, so any
/// request at all is visible in the server's recorded requests.
fn mock_client(server: &MockServer) -> OpenBaoClient {
    let mut client = OpenBaoClient::new(&server.uri()).expect("client");
    client.set_token("test-token".to_string());
    client
}

/// A verb service over a Wiremock with **no** mounted responses: any
/// request at all fails the mock, and the count is asserted directly.
async fn refusal_harness(
    fixture: &RegistrarConfigFixture,
) -> (MockServer, TempDir, RegistrarVerbs) {
    let server = MockServer::start().await;
    let client = mock_client(&server);
    let (dir, config) = load_fixture(fixture);
    let verbs = verbs_with(client, "secret", config);
    (server, dir, verbs)
}

async fn assert_untouched(server: &MockServer) {
    let requests = server
        .received_requests()
        .await
        .expect("the mock server records requests");
    assert!(
        requests.is_empty(),
        "a pre-derivation refusal must reach OpenBao not at all, saw {} request(s)",
        requests.len()
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
    assert_untouched(&server).await;
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

    assert_untouched(&server).await;
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

    assert_untouched(&server).await;
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

    assert_untouched(&server).await;
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

    assert_untouched(&server).await;
}

/// Both named derivation failures: the derived key exceeds the 131-octet
/// bound, and an uppercase host makes it non-path-safe. Neither reaches
/// `OpenBao`, which is what a refusal short of stage 3 is observable by:
/// the per-id map is process-wide, so a count over it would be shared
/// mutable state across this whole test binary rather than a statement
/// about this request.
#[tokio::test]
async fn derivation_failures_reach_no_openbao_work() {
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

    assert_untouched(&server).await;
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
    // One second past the largest value a Go `time.Duration` holds. It
    // is a whole number of seconds and it is larger than the maximum,
    // but it is refused rather than clamped: `OpenBao` cannot parse the
    // string it would take to ask for it, so the request has no
    // representation to grant a lesser share of.
    assert_eq!(
        policy.grant(Duration::seconds(9_223_372_037)),
        Err(WrapTtlRefusal::ExceedsOpenBaoRange)
    );
    // The boundary itself is representable, so it clamps like any other
    // over-long request.
    let granted = policy
        .grant(Duration::seconds(9_223_372_036))
        .expect("the largest representable request is clamped, not refused");
    assert_eq!(granted.duration(), Duration::minutes(30));
    assert_eq!(granted.as_openbao_str(), "1800s");
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
    assert_eq!(
        WrapTtlPolicy::new(Duration::seconds(9_223_372_037)),
        Err(WrapTtlRefusal::ExceedsOpenBaoRange)
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
        (
            Duration::seconds(9_223_372_037),
            WrapTtlRefusal::ExceedsOpenBaoRange,
        ),
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
    assert_untouched(&server).await;
}

// ---------------------------------------------------------------------
// Fast tier: the per-id lock map
// ---------------------------------------------------------------------

/// A released guard reclaims its entry, so the map does not grow with
/// every id a caller has ever named.
///
/// The three reclamation tests below run against locally constructed
/// maps rather than the process-wide static, so what they assert about
/// entry counts is theirs alone and cannot be perturbed by another test
/// holding a lock for the same id.
#[tokio::test]
async fn a_released_id_lock_reclaims_its_map_entry() {
    let locks = IdLocks::default();

    for id in ["h1-roxyd", "h2-roxyd", "h1-piglet-001"] {
        let guard = locks.acquire(id).await;
        assert_eq!(locks.lock_entries().len(), 1, "one live id at a time");
        drop(guard);
        assert_eq!(
            locks.lock_entries().len(),
            0,
            "dropping {id}'s guard must reclaim its entry"
        );
    }
}

/// A waiter keeps the entry alive and gets the *same* lock, so the two
/// holders serialize rather than each taking a private mutex.
///
/// This is what makes a mint and a deregister for one id mutually
/// exclusive, and it is also the case a careless reclaim would break by
/// removing an entry another caller is queued on.
#[tokio::test]
async fn a_contended_id_lock_is_shared_and_survives_the_first_release() {
    let locks = Arc::new(IdLocks::default());
    let first = locks.acquire("h1-roxyd").await;

    let acquired = Arc::new(AtomicBool::new(false));
    let waiter = tokio::spawn({
        let locks = Arc::clone(&locks);
        let acquired = Arc::clone(&acquired);
        async move {
            let guard = locks.acquire("h1-roxyd").await;
            acquired.store(true, Ordering::SeqCst);
            assert_eq!(
                locks.lock_entries().len(),
                1,
                "the waiter must hold the entry it woke on"
            );
            drop(guard);
        }
    });

    // Give the waiter every chance to run. It cannot acquire, because
    // the lock it found in the map is the one `first` is holding — had
    // it been handed a private mutex instead, it would be through by
    // now and the two verbs would not serialize.
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        !acquired.load(Ordering::SeqCst),
        "a second holder of one id must block until the first releases"
    );
    assert_eq!(
        locks.lock_entries().len(),
        1,
        "the waiter must be queued on the entry already in the map"
    );

    drop(first);
    waiter.await.expect("the waiter must acquire and release");
    assert!(acquired.load(Ordering::SeqCst));

    assert_eq!(
        locks.lock_entries().len(),
        0,
        "the last holder out reclaims the entry"
    );
}

/// Re-acquiring a reclaimed id inserts a fresh entry rather than
/// resurrecting a dead `Weak`.
#[tokio::test]
async fn a_reclaimed_id_is_re_acquirable() {
    let locks = IdLocks::default();

    drop(locks.acquire("h1-roxyd").await);
    assert_eq!(locks.lock_entries().len(), 0);

    let guard = locks.acquire("h1-roxyd").await;
    assert_eq!(
        locks.lock_entries().len(),
        1,
        "the id must be lockable again after its entry was reclaimed"
    );
    drop(guard);
    assert_eq!(locks.lock_entries().len(), 0);
}

/// Two separately constructed services must serialize on one derived id.
///
/// This is the defect the shared map exists to close: a mint driven
/// through one service and a deregister driven through another derive
/// the same `registration_id`, and with a map per instance each would
/// take a private lock for it and their binding and `OpenBao` work would
/// interleave. Both acquisitions go through the services' own
/// lock-selection path rather than naming the static, so an
/// implementation that handed each instance its own map would let the
/// waiter through immediately and fail the blocking assertion below.
///
/// The id is unique because the map is process-wide: a fixed label would
/// queue behind any other test in this binary that happened to use it.
#[tokio::test]
async fn two_instances_share_one_per_id_lock() {
    let server = MockServer::start().await;
    let (_dir_one, config_one) = load_fixture(&base_fixture());
    let (_dir_two, config_two) = load_fixture(&base_fixture());
    let first = verbs_with(mock_client(&server), "secret", config_one);
    let second = Arc::new(verbs_with(mock_client(&server), "secret", config_two));

    let registration_id = unique_label("lk");
    let held = first.id_locks_for_test().acquire(&registration_id).await;

    let acquired = Arc::new(AtomicBool::new(false));
    let waiter = tokio::spawn({
        let second = Arc::clone(&second);
        let acquired = Arc::clone(&acquired);
        let registration_id = registration_id.clone();
        async move {
            let guard = second.id_locks_for_test().acquire(&registration_id).await;
            acquired.store(true, Ordering::SeqCst);
            drop(guard);
        }
    });

    // Give the second service every chance to run.
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
    assert!(
        !acquired.load(Ordering::SeqCst),
        "a second service instance must queue on the lock the first is holding for {registration_id}"
    );

    drop(held);
    waiter
        .await
        .expect("the second service must acquire and release");
    assert!(acquired.load(Ordering::SeqCst));
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

/// Grants exactly what a teardown needs to sweep the KV material, and
/// nothing that lets it see or delete the `AppRole` or the policy — so a
/// deregister's sweep runs to the end and still fails in aggregate.
async fn install_material_only_policy(backend: &LiveBackend, name: &str) {
    let mount = &backend.kv_mount;
    let policy = format!(
        r#"path "{mount}/data/bootroot/services/*" {{
  capabilities = ["read"]
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
        .expect("write the material-only policy");
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

/// A deregister whose teardown fails in aggregate keeps the binding.
///
/// This is the other half of the teardown-before-unbind rule: the sweep
/// attempts every resource rather than stopping at the first failure, and
/// the durable claim is what keeps whatever survived it covered until a
/// re-run can finish the job. Deleting the binding here would manufacture
/// exactly the unbound orphan the binding exists to prevent.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn a_failed_teardown_retains_the_binding_and_attempts_every_resource() {
    let backend = LiveBackend::from_env();
    let stem = unique_label("f");
    let policy_name = format!("bootroot-test-{stem}");
    install_material_only_policy(&backend, &policy_name).await;
    let restricted = backend.scoped_token(&[policy_name.as_str()]).await;

    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let verbs = backend.verbs(config);
    let registration_id = format!("{host}-piglet-004");

    verbs
        .mint(&mint_request("piglet", &host, Some(4)))
        .await
        .expect("mint");
    for suffix in REGISTRAR_TEARDOWN_KV_SUFFIXES {
        backend.plant(&registration_id, suffix).await;
    }

    let (_dir2, config2) = load_fixture(&base_fixture());
    let crippled = verbs_with(
        backend.client_with_token(&restricted),
        &backend.kv_mount,
        config2,
    );
    let refusal = crippled
        .deregister(&deregister_request("piglet", &host, Some(4)))
        .await
        .expect_err("a teardown that could not finish must refuse");
    assert_eq!(refusal.context().arm(), ProducingArm::Teardown);
    assert!(
        matches!(refusal.error(), VerbError::Unavailable { .. }),
        "expected an unavailable refusal, got {:?}",
        refusal.error()
    );

    // The report reaches the caller, and it names every resource: the
    // sweep did not stop at the role it could not read.
    let report = refusal.teardown().expect("the partial report is carried");
    assert!(!report.aggregate_success());
    assert_eq!(
        report.attempts().len(),
        REGISTRAR_TEARDOWN_KV_SUFFIXES.len() + 2,
        "every KV suffix plus the role and the policy must be attempted"
    );
    assert!(
        report.attempts().iter().any(|attempt| matches!(
            attempt.resource,
            ServiceResource::AppRole(_)
        ) && matches!(
            attempt.outcome,
            ResourceOutcome::Failed(_)
        )),
        "the AppRole attempt must be the failure, got {:?}",
        report.attempts()
    );
    // What it *could* remove, it did — a retained binding is not a
    // rolled-back sweep.
    for suffix in REGISTRAR_TEARDOWN_KV_SUFFIXES {
        assert!(
            !backend.kv_exists(&registration_id, suffix).await,
            "{suffix} was deletable and must have been swept"
        );
    }

    assert!(
        backend.binding_of(&registration_id).await.is_some(),
        "the binding must outlive a teardown that did not finish"
    );
    assert!(
        backend
            .read_role(&service_role_name(&registration_id))
            .await
            .is_some(),
        "the role the sweep could not touch is still there, and still bound"
    );

    // A privileged re-run finishes the job, binding included.
    let outcome = verbs
        .deregister(&deregister_request("piglet", &host, Some(4)))
        .await
        .expect("the re-run completes the teardown");
    assert_eq!(outcome.kind(), DeregisterKind::IdentityRemoved);
    assert!(backend.binding_of(&registration_id).await.is_none());
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

/// Two verb services sharing one live `OpenBao` race one derived id from
/// two different hosts. Exactly one gets material; the other is refused.
///
/// The two services share the process-wide per-id lock, so the race is
/// resolved in-process: the loser runs after the winner has persisted
/// the binding, reads it, and is refused for the host collision. It does
/// **not** reach the compare-and-set conflict. The verb layer's
/// `KvCreateIfAbsent::AlreadyExists` re-read branch is by construction
/// only reachable from another process writing the same namespace, and
/// nothing in this suite exercises it; `src/openbao.rs` covers the
/// client-level distinction between `OpenBao`'s documented CAS mismatch
/// and other HTTP 400 responses against canned responses. What is
/// asserted here remains worth asserting: concurrent requests for one
/// derived id from two hosts produce exactly one winner and one durable
/// binding, whichever of them gets there first.
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

/// A mint and a deregister for one identity, issued concurrently through
/// two **separately constructed** services, are serialized: the result is
/// one of the two clean orderings, never a half-existing identity.
///
/// The two services are what makes this a test of the shared lock rather
/// than of one instance's private map. Each loads the fixture into its
/// own directory, and both `TempDir` guards stay alive for the whole
/// body so neither rendered config is removed underneath its service.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn a_concurrent_mint_and_deregister_never_interleave() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir_one, config_one) = load_fixture(&base_fixture());
    let (_dir_two, config_two) = load_fixture(&base_fixture());
    let minting = Arc::new(backend.verbs(config_one));
    let deregistering = Arc::new(backend.verbs(config_two));
    let registration_id = format!("{host}-roxyd");

    minting
        .mint(&mint_request("roxyd", &host, None))
        .await
        .expect("seed the identity");

    let for_mint = Arc::clone(&minting);
    let for_deregister = Arc::clone(&deregistering);
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
        deregistering
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

/// The parameterless factory: it takes no client and no caller, builds
/// its own privileged client from the credential on disk, and refuses
/// fail-closed rather than falling back to anything.
mod internal_factory {
    use tempfile::TempDir;
    use time::Duration;

    use super::{RegistrarVerbs, base_fixture, load_fixture, mint_request};
    use crate::openbao::SecretIdOptions;
    use crate::registrar::internal::InternalCredentialError;
    use crate::registrar::verbs::InternalVerbsSource;
    use crate::registrar::verbs::outcome::VerbError;
    use crate::registrar::verbs::wrap_ttl::WrapTtlPolicy;

    const ACTIVE_ROOT_FP: &str = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900";

    fn source<'a>(
        secrets_dir: &'a std::path::Path,
        openbao_url: &'a str,
        config: &'a crate::registrar::config::RegistrarConfig,
        options: &'a SecretIdOptions,
        policy: &'a crate::registrar::verbs::wrap_ttl::WrapTtlPolicy,
    ) -> InternalVerbsSource<'a> {
        InternalVerbsSource {
            secrets_dir,
            openbao_url,
            active_root_fingerprint: ACTIVE_ROOT_FP,
            kv_mount: "secret",
            config,
            secret_id_options: options,
            token_ttl: "1h",
            secret_id_ttl: "24h",
            wrap_ttl_policy: policy,
        }
    }

    /// Certificate login is never attempted over plaintext, and the
    /// refusal happens before the credential is even read.
    #[test]
    fn the_factory_refuses_a_plaintext_openbao_url() {
        let dir = TempDir::new().expect("tempdir");
        let (_config_dir, config) = load_fixture(&base_fixture());
        let options = SecretIdOptions::default();
        let policy = WrapTtlPolicy::new(Duration::minutes(30)).expect("policy maximum");
        let Err(err) = RegistrarVerbs::internal(&source(
            dir.path(),
            "http://localhost:8200",
            &config,
            &options,
            &policy,
        )) else {
            panic!("plaintext must be refused");
        };
        assert!(
            matches!(err, InternalCredentialError::PlaintextOpenBaoUrl { .. }),
            "{err:?}"
        );
    }

    /// A host whose generated config drifted is refused too.
    ///
    /// Every one of the six files is there, so the presence check alone
    /// would call this host provisioned — but the config it would renew
    /// under names another identity's key, so the daemon that keeps this
    /// certificate alive cannot start. The verbs must not be served over
    /// a credential nothing renews.
    #[tokio::test]
    async fn the_factory_refuses_a_host_whose_generated_config_is_invalid() {
        use crate::registrar::internal::{
            AcmeAccountKey, InternalAgentConfigParams, InternalMaterial, InternalPaths,
            PrivateKeyPem, publish_material, render_internal_agent_config,
        };

        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        publish_material(
            &paths,
            &InternalMaterial {
                key: PrivateKeyPem::new(
                    "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n".to_string(),
                ),
                chain: "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n".to_string(),
                acme_account: AcmeAccountKey::new("{\"account_key_pkcs8\":\"QUJD\"}".to_string()),
                root_fingerprint: ACTIVE_ROOT_FP.to_string(),
            },
        )
        .await
        .expect("publish");
        std::fs::write(
            paths.ca_bundle(),
            "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
        )
        .expect("bundle");
        let hijacked = render_internal_agent_config(
            &paths,
            &InternalAgentConfigParams {
                email: "ops@example.internal",
                server: "https://localhost:9000/acme/acme/directory",
                domain: "example.internal",
                hostname: "bootroot-01",
                responder_url: "http://127.0.0.1:8080",
                responder_hmac: &"hmac".into(),
                eab_kid: None,
                eab_hmac: None,
                trusted_ca_sha256: &[ACTIVE_ROOT_FP.to_string()],
            },
        )
        .replace(
            &paths.chain().display().to_string(),
            "/srv/secrets/services/other/chain.pem",
        );
        std::fs::write(paths.agent_config(), hijacked).expect("config");

        let (_config_dir, config) = load_fixture(&base_fixture());
        let options = SecretIdOptions::default();
        let policy = WrapTtlPolicy::new(Duration::minutes(30)).expect("policy maximum");
        let Err(err) = RegistrarVerbs::internal(&source(
            dir.path(),
            "https://localhost:8200",
            &config,
            &options,
            &policy,
        )) else {
            panic!("a drifted config must be refused");
        };
        assert!(
            matches!(&err, InternalCredentialError::Invalid { path, .. }
                if path == &paths.agent_config()),
            "{err:?}"
        );
    }

    /// The root can be replaced *after* the factory has handed out a
    /// verbs object, and the very next verb refuses.
    ///
    /// A rotation does exactly this: Phase 2 replaces the deployment
    /// root and the mandatory tail after Phase 4 replaces this
    /// credential, so anything holding a verbs object across that window
    /// holds one whose leaf the `auth/cert` entry has stopped trusting.
    /// Comparing the roots only in the factory would leave that object
    /// logging in — or serving a still-valid cached token, which is
    /// worse, because that is a *write* under a superseded credential.
    ///
    /// `OpenBao` is pointed at a port nothing listens on, so the
    /// assertion is not merely that the verb failed: a login or a write
    /// that was attempted would fail as a transport error, and what is
    /// asserted is the typed repair-required refusal instead.
    #[tokio::test]
    async fn a_root_replaced_after_construction_refuses_every_verb() {
        let host = ProvisionedHost::new().await;
        let (_config_dir, config) = load_fixture(&base_fixture());
        let options = SecretIdOptions::default();
        let policy = WrapTtlPolicy::new(Duration::minutes(30)).expect("policy maximum");
        let url = dead_https_url();
        let verbs = RegistrarVerbs::internal(&InternalVerbsSource {
            secrets_dir: host.dir.path(),
            openbao_url: &url,
            active_root_fingerprint: &host.root_fingerprint,
            kv_mount: "secret",
            config: &config,
            secret_id_options: &options,
            token_ttl: "1h",
            secret_id_ttl: "24h",
            wrap_ttl_policy: &policy,
        })
        .expect("a provisioned host on its own root must build the verbs");

        host.replace_active_root();

        let refusal = verbs
            .mint(&mint_request("roxyd", "h1", None))
            .await
            .expect_err("a verb under a superseded root must be refused");
        let VerbError::Unavailable { source, .. } = refusal.error() else {
            panic!("{:?}", refusal.error());
        };
        let rendered = format!("{source:#}");
        assert!(
            rendered.contains("bootroot rotate registrar-internal-credential"),
            "expected repair-required, got {rendered}"
        );

        let refusal = verbs
            .deregister(&super::deregister_request("roxyd", "h1", None))
            .await
            .expect_err("the other verb must be refused too");
        assert!(
            matches!(refusal.error(), VerbError::Unavailable { source, .. }
                if format!("{source:#}").contains("bootroot rotate registrar-internal-credential")),
            "{:?}",
            refusal.error()
        );
    }

    /// An `https://` URL whose port nothing listens on.
    ///
    /// Bound and dropped, so the port was free at the moment it was
    /// chosen and nothing in the test hard-codes one.
    fn dead_https_url() -> String {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind an ephemeral port");
        let port = listener.local_addr().expect("the bound address").port();
        drop(listener);
        format!("https://127.0.0.1:{port}")
    }

    /// A secrets directory carrying a complete, valid internal
    /// credential issued under a real root.
    ///
    /// Real key material, because the factory builds a
    /// client-authenticated transport out of it and a placeholder would
    /// fail there rather than reaching the root comparison this test is
    /// about.
    struct ProvisionedHost {
        dir: TempDir,
        root_fingerprint: String,
    }

    impl ProvisionedHost {
        async fn new() -> Self {
            use crate::registrar::internal::{
                AcmeAccountKey, InternalAgentConfigParams, InternalMaterial, InternalPaths,
                PrivateKeyPem, render_internal_agent_config,
            };

            let dir = TempDir::new().expect("tempdir");
            let paths = InternalPaths::new(dir.path());
            let (root_pem, root_key, root_params) = self_signed_root("bootroot-active-root");
            let root_fingerprint = write_active_root(dir.path(), &root_pem);

            let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
            let leaf =
                rcgen::CertificateParams::new(vec![crate::registrar::registrar_internal_identity(
                    "bootroot-01",
                    "example.internal",
                )])
                .expect("leaf params")
                .signed_by(
                    &leaf_key,
                    &rcgen::Issuer::from_params(&root_params, &root_key),
                )
                .expect("leaf");

            let material = InternalMaterial {
                key: PrivateKeyPem::new(leaf_key.serialize_pem()),
                chain: format!("{}{root_pem}", leaf.pem()),
                acme_account: AcmeAccountKey::new("{\"account_key_pkcs8\":\"QUJD\"}".to_string()),
                root_fingerprint: root_fingerprint.clone(),
            };
            crate::registrar::internal::publish_material(&paths, &material)
                .await
                .expect("publish");
            std::fs::write(paths.ca_bundle(), &root_pem).expect("bundle");
            std::fs::write(
                paths.agent_config(),
                render_internal_agent_config(
                    &paths,
                    &InternalAgentConfigParams {
                        email: "ops@example.internal",
                        server: "https://localhost:9000/acme/acme/directory",
                        domain: "example.internal",
                        hostname: "bootroot-01",
                        responder_url: "http://127.0.0.1:8080",
                        responder_hmac: &"hmac".into(),
                        eab_kid: None,
                        eab_hmac: None,
                        trusted_ca_sha256: std::slice::from_ref(&root_fingerprint),
                    },
                ),
            )
            .expect("config");

            Self {
                dir,
                root_fingerprint,
            }
        }

        /// What a full rotation's Phase 2 does to this host: a different
        /// root, in the same file, with nothing told to the credential.
        fn replace_active_root(&self) {
            let (pem, _, _) = self_signed_root("bootroot-new-root");
            write_active_root(self.dir.path(), &pem);
        }
    }

    fn self_signed_root(common_name: &str) -> (String, rcgen::KeyPair, rcgen::CertificateParams) {
        let key = rcgen::KeyPair::generate().expect("ca key");
        let mut params =
            rcgen::CertificateParams::new(vec![common_name.to_string()]).expect("ca params");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let pem = params.self_signed(&key).expect("self-signed ca").pem();
        (pem, key, params)
    }

    fn write_active_root(secrets_dir: &std::path::Path, pem: &str) -> String {
        let path = crate::registrar::internal::active_root_cert_path(secrets_dir);
        std::fs::create_dir_all(path.parent().expect("the certs directory"))
            .expect("create the certs directory");
        std::fs::write(&path, pem).expect("write the active root");
        crate::registrar::internal::active_root_fingerprint(secrets_dir)
            .expect("the written root must hash")
    }

    /// A host with no internal credential gets a typed absence, never a
    /// verb service over some other client.
    #[test]
    fn the_factory_refuses_an_unprovisioned_host() {
        let dir = TempDir::new().expect("tempdir");
        let (_config_dir, config) = load_fixture(&base_fixture());
        let options = SecretIdOptions::default();
        let policy = WrapTtlPolicy::new(Duration::minutes(30)).expect("policy maximum");
        let Err(err) = RegistrarVerbs::internal(&source(
            dir.path(),
            "https://localhost:8200",
            &config,
            &options,
            &policy,
        )) else {
            panic!("an unprovisioned host must be refused");
        };
        assert!(matches!(err, InternalCredentialError::Absent(_)), "{err:?}");
    }
}

/// A credential issued under a superseded root makes no request at all.
#[tokio::test]
async fn the_factory_returns_repair_required_on_a_root_mismatch() {
    use tempfile::TempDir;
    use time::Duration;

    use crate::openbao::SecretIdOptions;
    use crate::registrar::internal::{
        AcmeAccountKey, InternalAgentConfigParams, InternalMaterial, InternalPaths, PrivateKeyPem,
        publish_material, render_internal_agent_config,
    };
    use crate::registrar::verbs::wrap_ttl::WrapTtlPolicy;
    use crate::registrar::verbs::{InternalVerbsSource, RegistrarVerbs};

    const STORED_ROOT: &str = "1111111111111111111111111111111111111111111111111111111111111111";
    const ACTIVE_ROOT: &str = "2222222222222222222222222222222222222222222222222222222222222222";

    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    publish_material(
        &paths,
        &InternalMaterial {
            key: PrivateKeyPem::new(
                "-----BEGIN PRIVATE KEY-----\nQUJD\n-----END PRIVATE KEY-----\n".to_string(),
            ),
            chain: "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n".to_string(),
            acme_account: AcmeAccountKey::new("{\"account_key_pkcs8\":\"QUJD\"}".to_string()),
            root_fingerprint: STORED_ROOT.to_string(),
        },
    )
    .await
    .expect("publish");
    std::fs::write(
        paths.ca_bundle(),
        "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n",
    )
    .expect("bundle");
    std::fs::write(
        paths.agent_config(),
        render_internal_agent_config(
            &paths,
            &InternalAgentConfigParams {
                email: "ops@example.internal",
                server: "https://localhost:9000/acme/acme/directory",
                domain: "example.internal",
                hostname: "bootroot-01",
                responder_url: "http://127.0.0.1:8080",
                responder_hmac: &"hmac".into(),
                eab_kid: None,
                eab_hmac: None,
                trusted_ca_sha256: &[STORED_ROOT.to_string()],
            },
        ),
    )
    .expect("config");

    let (_config_dir, config) = load_fixture(&base_fixture());
    let options = SecretIdOptions::default();
    let policy = WrapTtlPolicy::new(Duration::minutes(30)).expect("policy maximum");
    let Err(err) = RegistrarVerbs::internal(&InternalVerbsSource {
        secrets_dir: dir.path(),
        openbao_url: "https://localhost:8200",
        active_root_fingerprint: ACTIVE_ROOT,
        kv_mount: "secret",
        config: &config,
        secret_id_options: &options,
        token_ttl: "1h",
        secret_id_ttl: "24h",
        wrap_ttl_policy: &policy,
    }) else {
        panic!("a superseded root must be refused");
    };
    match err {
        crate::registrar::internal::InternalCredentialError::RepairRequired { stored, active } => {
            assert_eq!(stored, STORED_ROOT);
            assert_eq!(active, ACTIVE_ROOT);
        }
        other => panic!("{other:?}"),
    }
}
