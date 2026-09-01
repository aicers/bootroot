//! Tests for the two verbs, split along one deliberate line.
//!
//! **Fast tier.** Everything that is decided before a stateful `OpenBao`
//! interaction: the pre-derivation refusals, the derivation failures, the
//! binding record's JSON, and the wrap-TTL policy. Where a client is
//! needed at all it is a canned-response Wiremock, and the assertion is
//! usually that *no request was made*.
//! Every socket this module's fast tier opens is the in-process loopback
//! socket a `wiremock::MockServer` owns and stops with the test process;
//! it binds and dials no externally supplied address.
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
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::binding::{
    BINDING_SCHEMA_VERSION, BindingRecord, BindingReloadKind, BindingSpec, BindingState,
    REGISTRAR_BINDING_KV_SUFFIX,
};
use super::coalescing::CoalescingLimitedInvocationSink;
use super::limiter::{
    CountingLimitedInvocationSink, LimitedInvocation, LimitedInvocationSink, LimiterBucket,
    VerbRateLimiter, VerbRateLimiterSettings,
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
use crate::registrar::audit::{
    AppendGate, AuditPhase, AuditRecordStore, AuditStoreSettings, FaultInjection,
    MIN_AUDIT_MAX_FILE_BYTES,
};
use crate::registrar::config::{
    Multiplicity, RegistrarConfig, RegistrationSpec, ReloadKind, ReloadSpec,
};
use crate::registrar::error::{RegistrarError, SpecIdentityField};
use crate::registrar::fixture::RegistrarConfigFixture;
use crate::registrar::identity::RequestedSpec;
use crate::service_material::{
    ResourceOutcome, ServiceResource, service_kv_path, service_policy_name, service_role_name,
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
    // Every fixture gets its own throwaway store, so what a test reads
    // back out of the trail is only what its own invocations wrote.
    verbs_with_store(
        client,
        kv_mount,
        config,
        AuditRecordStore::open_temporary().expect("a temporary audit store"),
    )
}

fn verbs_with_store(
    client: OpenBaoClient,
    kv_mount: &str,
    config: RegistrarConfig,
    audit_store: AuditRecordStore,
) -> RegistrarVerbs {
    verbs_with_limiter(
        client,
        kv_mount,
        config,
        audit_store,
        VerbRateLimiter::with_counting_sink(VerbRateLimiterSettings::default()).0,
    )
}

fn verbs_with_limiter(
    client: OpenBaoClient,
    kv_mount: &str,
    config: RegistrarConfig,
    audit_store: AuditRecordStore,
    limiter: VerbRateLimiter,
) -> RegistrarVerbs {
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
        audit_store,
        limiter,
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
// Reading the audit trail back
// ---------------------------------------------------------------------

/// Every line the verb service's trail holds, as raw JSON, in file
/// order.
///
/// Raw `Value`s rather than `AuditRecord`s on purpose: several
/// assertions here are about a key being **absent** from the object,
/// which a `serde` round trip through an `Option` field cannot tell
/// from `null`. Every line is still required to parse.
fn trail(verbs: &RegistrarVerbs) -> Vec<serde_json::Value> {
    let path = verbs.audit_store().active_path();
    let contents = match std::fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => panic!("read {}: {err}", path.display()),
    };
    contents
        .lines()
        .map(|line| {
            serde_json::from_str(line)
                .unwrap_or_else(|err| panic!("every trail line must parse: {err}: {line}"))
        })
        .collect()
}

/// The lines one invocation wrote, selected by `request_id`.
fn lines_for(verbs: &RegistrarVerbs, request_id: &str) -> Vec<serde_json::Value> {
    trail(verbs)
        .into_iter()
        .filter(|line| line["request_id"] == json!(request_id))
        .collect()
}

/// What one invocation asked for, as the record spells it.
struct Asked<'a> {
    verb: &'a str,
    caller: &'a str,
    service_name: &'a str,
    host: &'a str,
    instance: Option<u32>,
}

impl<'a> Asked<'a> {
    fn new(verb: &'a str, service_name: &'a str, host: &'a str, instance: Option<u32>) -> Self {
        Self {
            verb,
            caller: CALLER,
            service_name,
            host,
            instance,
        }
    }

    /// Names a caller other than the suite's default one.
    fn by(mut self, caller: &'a str) -> Self {
        self.caller = caller;
        self
    }
}

/// Asserts that `request_id` produced one complete intent/outcome pair
/// and returns the outcome line.
///
/// This is the shape every invocation owes, so it is asserted in one
/// place: the two lines share the request id, the intent line comes
/// first and **omits** the `registration_id` key entirely rather than
/// carrying `null` or `""`, both carry a timestamp, the verb, the caller
/// identity verbatim and the requested parts, and the outcome line
/// carries an outcome while the intent line does not.
fn assert_pair(verbs: &RegistrarVerbs, request_id: &str, asked: &Asked<'_>) -> serde_json::Value {
    let lines = lines_for(verbs, request_id);
    assert_eq!(
        lines.len(),
        2,
        "one invocation owes exactly one intent line and one outcome line, got {lines:#?}"
    );
    let (intent, outcome) = (&lines[0], &lines[1]);

    assert_eq!(intent["phase"], json!("intent"), "{intent}");
    assert_eq!(outcome["phase"], json!("outcome"), "{outcome}");
    assert!(
        !intent
            .as_object()
            .expect("a record is a JSON object")
            .contains_key("registration_id"),
        "an intent line must omit the registration_id key entirely, got {intent}"
    );
    assert!(intent.get("outcome").is_none(), "{intent}");
    assert!(outcome.get("outcome").is_some(), "{outcome}");

    for line in &lines {
        assert_eq!(line["request_id"], json!(request_id));
        assert_eq!(line["verb"], json!(asked.verb), "{line}");
        assert_eq!(line["caller_identity"], json!(asked.caller), "{line}");
        assert_eq!(line["requested"]["service_name"], json!(asked.service_name));
        assert_eq!(line["requested"]["host"], json!(asked.host));
        assert_eq!(
            line["requested"]
                .get("instance")
                .and_then(serde_json::Value::as_u64),
            asked.instance.map(u64::from),
            "{line}"
        );
        assert!(
            line["ts"].as_str().is_some_and(|ts| ts.ends_with('Z')),
            "every line carries a UTC timestamp: {line}"
        );
        assert_eq!(line["record_version"], json!(1), "{line}");
    }
    outcome.clone()
}

/// Asserts the pair a refused invocation owes, and returns its
/// `outcome.reason`.
fn assert_refusal_pair(verbs: &RegistrarVerbs, refusal: &VerbRefusal, asked: &Asked<'_>) -> String {
    let outcome = assert_pair(verbs, refusal.context().request_id().as_str(), asked);
    assert_eq!(outcome["outcome"]["class"], json!("refused"), "{outcome}");
    outcome["outcome"]["reason"]
        .as_str()
        .unwrap_or_else(|| panic!("a refusal outcome names a reason: {outcome}"))
        .to_string()
}

/// Asserts that the limiter-admitted invalid-label refusals each left their
/// own complete audit pair.
fn assert_durable_invalid_service_name_pairs(
    verbs: &RegistrarVerbs,
    refusals: &[VerbRefusal],
    flood: u32,
    expected_count: usize,
) {
    let recorded: Vec<_> = refusals
        .iter()
        .filter(|refusal| !lines_for(verbs, refusal.context().request_id().as_str()).is_empty())
        .collect();
    let recorded_request_ids: std::collections::HashSet<_> = recorded
        .iter()
        .map(|refusal| refusal.context().request_id().as_str())
        .collect();
    assert_eq!(
        recorded.len(),
        expected_count,
        "flood of {flood} admits exactly {expected_count} requests"
    );
    assert_eq!(
        recorded_request_ids.len(),
        expected_count,
        "flood of {flood} gives each durable pair a distinct request id"
    );
    for refusal in recorded {
        assert_eq!(
            assert_refusal_pair(
                verbs,
                refusal,
                &Asked::new("mint", "not a label", "h1", None),
            ),
            "invalid_service_name",
            "each admitted request carries its own invalid-service-name refusal"
        );
    }
}

/// A store over a directory the caller keeps alive, so a test can pick
/// its size limit and reach its fault switches.
///
/// [`AuditRecordStore::open_temporary`] owns its directory and fixes the
/// defaults; this is for the tests that need neither.
async fn open_store(root: &std::path::Path, max_file_bytes: u64) -> AuditRecordStore {
    // The store audits its immediate parent, which is this directory.
    // `tempfile` creates it under the ambient umask — `002` on a
    // Debian-style account — so state the mode rather than inherit a
    // group-writable one the store would rightly refuse.
    std::fs::set_permissions(root, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .expect("chmod");
    AuditRecordStore::open_for_tests(AuditStoreSettings {
        dir: root.join("registrar-audit"),
        max_file_bytes,
        max_retained_files: 4,
    })
    .await
    .expect("a store opens over a temporary directory")
}

/// A verb service whose store's faults a test can arm, over a Wiremock
/// with no mounted responses.
///
/// The `TempDir` is returned so the caller keeps the store's directory
/// alive for the whole test.
async fn audit_harness(
    fixture: &RegistrarConfigFixture,
) -> (MockServer, TempDir, TempDir, RegistrarVerbs) {
    let server = MockServer::start().await;
    let store_root = tempfile::tempdir().expect("tempdir");
    let store = open_store(store_root.path(), MIN_AUDIT_MAX_FILE_BYTES).await;
    let (dir, config) = load_fixture(fixture);
    let verbs = verbs_with_store(mock_client(&server), "secret", config, store);
    (server, dir, store_root, verbs)
}

/// Drives `verb` with the store's `append` fault armed for the
/// **outcome** write only.
///
/// The gate parks each blocking append at its entry and notifies here,
/// so the fault can be armed in the window between the two: the intent
/// append is released before it is set, and the outcome append is
/// already parked when it is. This is the only way to fail one specific
/// append rather than all of them, and it needs no production branch.
async fn with_outcome_append_failure<F, T>(verbs: &RegistrarVerbs, verb: F) -> T
where
    F: std::future::Future<Output = T>,
{
    fail_the_outcome_write(verbs, verb, |faults| {
        faults.append.store(true, Ordering::SeqCst);
    })
    .await
}

/// As [`with_outcome_append_failure`], with the store step the caller
/// names failed instead.
async fn fail_the_outcome_write<F, T>(
    verbs: &RegistrarVerbs,
    verb: F,
    arm: impl FnOnce(&FaultInjection),
) -> T
where
    F: std::future::Future<Output = T>,
{
    let store = verbs.audit_store().clone();
    let (gate, mut entries, releases) = AppendGate::new();
    *store.faults().gate.lock().expect("arm the gate") = Some(gate);

    let mut driven = Box::pin(verb);
    // The intent append, released before anything is armed.
    tokio::select! {
        () = async { (&mut driven).await; } => {
            panic!("a gated invocation cannot have finished its verb")
        }
        entered = entries.recv() => entered.expect("the intent append reaches the gate"),
    }
    releases.send(()).expect("release the intent append");

    // The outcome append, parked at the gate before it has opened the
    // file — which is the window the fault is armed in.
    tokio::select! {
        () = async { (&mut driven).await; } => {
            panic!("the invocation finished without attempting its outcome write")
        }
        entered = entries.recv() => entered.expect("the outcome append reaches the gate"),
    }
    arm(store.faults());
    releases.send(()).expect("release the outcome append");
    driven.await
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
// Fast tier: the audit trail around both verbs
// ---------------------------------------------------------------------

/// The URL path a registrar binding's KV data lives at.
fn binding_data_url(registration_id: &str) -> String {
    format!(
        "/v1/secret/data/{}",
        service_kv_path(registration_id, REGISTRAR_BINDING_KV_SUFFIX)
    )
}

/// The URL path a registrar binding's KV metadata lives at, which is
/// what a delete addresses.
fn binding_metadata_url(registration_id: &str) -> String {
    format!(
        "/v1/secret/metadata/{}",
        service_kv_path(registration_id, REGISTRAR_BINDING_KV_SUFFIX)
    )
}

/// Answers the binding read with `record`.
///
/// Everything this suite leaves unmounted answers 404, which the client
/// reads as absent — so a resource is "not there" by saying nothing
/// about it.
async fn mock_binding_read(server: &MockServer, registration_id: &str, record: &BindingRecord) {
    Mock::given(method("GET"))
        .and(path(binding_data_url(registration_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "data": record.encode().expect("the record encodes") }
        })))
        .mount(server)
        .await;
}

/// Answers both binding writes — the absent-only claim and the
/// activation, which address one path — as accepted.
async fn mock_binding_writes(server: &MockServer, registration_id: &str) {
    Mock::given(method("POST"))
        .and(path(binding_data_url(registration_id)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": { "version": 1 }
        })))
        .mount(server)
        .await;
}

/// Answers the binding delete as done.
async fn mock_binding_delete(server: &MockServer, registration_id: &str) {
    Mock::given(method("DELETE"))
        .and(path(binding_metadata_url(registration_id)))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
}

/// Answers every service-material read as present and every delete as
/// done, which is the planted-orphan sweep.
async fn mock_material_present(server: &MockServer, registration_id: &str) {
    for suffix in REGISTRAR_TEARDOWN_KV_SUFFIXES {
        let url = format!(
            "/v1/secret/metadata/{}",
            service_kv_path(registration_id, suffix)
        );
        Mock::given(method("GET"))
            .and(path(url.clone()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "data": {} })))
            .mount(server)
            .await;
        Mock::given(method("DELETE"))
            .and(path(url))
            .respond_with(ResponseTemplate::new(204))
            .mount(server)
            .await;
    }
}

/// Answers everything a first mint needs, through to wrapped material.
async fn mock_first_mint(server: &MockServer, registration_id: &str) {
    mock_binding_writes(server, registration_id).await;
    let role_name = service_role_name(registration_id);
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/sys/policies/acl/{}",
            service_policy_name(registration_id)
        )))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role_name}")))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(path(format!("/v1/auth/approle/role/{role_name}/role-id")))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "data": { "role_id": "role-id-1" } })),
        )
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(path(format!("/v1/auth/approle/role/{role_name}/secret-id")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "wrap_info": {
                "token": "hvs.wrap-token",
                "ttl": 300,
                "creation_time": "2026-08-23T12:00:00Z",
                "creation_path": format!("auth/approle/role/{role_name}/secret-id"),
            }
        })))
        .mount(server)
        .await;
}

/// Reports whether the mock server was asked to write a `creating`
/// binding and never asked to delete one.
async fn creating_binding_left_behind(server: &MockServer, registration_id: &str) -> bool {
    let requests = server
        .received_requests()
        .await
        .expect("the mock server records requests");
    let claimed = requests.iter().any(|request| {
        request.url.path() == binding_data_url(registration_id)
            && serde_json::from_slice::<serde_json::Value>(&request.body)
                .is_ok_and(|body| body["data"]["state"] == json!("creating"))
    });
    let deleted = requests
        .iter()
        .any(|request| request.url.path() == binding_metadata_url(registration_id));
    claimed && !deleted
}

/// Every refusal decided before the per-id lock owes a complete pair,
/// and neither of its lines carries a `registration_id` — nothing has
/// derived one.
///
/// One case per pre-lock arm, driven through both verbs, each against
/// its own store and its own mock so what is read back is only what
/// these two invocations wrote.
#[tokio::test]
async fn every_pre_lock_refusal_writes_a_pair_with_no_registration_id() {
    let long_component = "c".repeat(63);
    let long_host = "h".repeat(63);
    let cases: Vec<(RegistrarConfigFixture, &str, String, String, Option<u32>)> = vec![
        // A `service_name` that is not a DNS label.
        (
            base_fixture(),
            "invalid_service_name",
            "not a label".to_string(),
            "h1".to_string(),
            None,
        ),
        // A reserved `bootroot-` name, declared as an ordinary
        // component so the reserved guard is what refuses it.
        (
            base_fixture(),
            "reserved_service_name",
            "bootroot-decoy".to_string(),
            "h1".to_string(),
            None,
        ),
        // A component with no multiplicity entry.
        (
            base_fixture().without_component("roxyd"),
            "component_not_configured",
            "roxyd".to_string(),
            "h1".to_string(),
            None,
        ),
        // An instance where the component is one-per-host.
        (
            base_fixture(),
            "service_instance_mismatch",
            "roxyd".to_string(),
            "h1".to_string(),
            Some(4),
        ),
        // A derived key one octet past the 131-octet bound.
        (
            base_fixture().with_component(
                &long_component,
                Multiplicity::ManyPerHost,
                &sample_spec(),
            ),
            "derived_key_invalid",
            long_component.clone(),
            long_host.clone(),
            Some(1000),
        ),
    ];

    for (fixture, expected_reason, service_name, host, instance) in cases {
        let (server, _dir, _store_root, verbs) = audit_harness(&fixture).await;

        for verb in ["mint", "deregister"] {
            let refusal = if verb == "mint" {
                verbs
                    .mint(&mint_request(&service_name, &host, instance))
                    .await
                    .expect_err("every one of these must refuse")
            } else {
                verbs
                    .deregister(&deregister_request(&service_name, &host, instance))
                    .await
                    .expect_err("every one of these must refuse")
            };
            let asked = Asked::new(verb, &service_name, &host, instance);
            let reason = assert_refusal_pair(&verbs, &refusal, &asked);
            assert_eq!(reason, expected_reason, "{service_name}/{host} as a {verb}");
            for line in lines_for(&verbs, refusal.context().request_id().as_str()) {
                assert!(
                    !line
                        .as_object()
                        .expect("a record is a JSON object")
                        .contains_key("registration_id"),
                    "a refusal before the lock carries no registration_id: {line}"
                );
            }
        }
        assert_untouched(&server).await;
    }
}

/// The two mint-only pre-lock refusals: a spec that restates a
/// different identity, and a `wrap_ttl` no credential could be issued
/// under.
#[tokio::test]
async fn the_mint_only_pre_lock_refusals_write_their_pairs() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;

    let mut disagreeing = mint_request("roxyd", "h1", None);
    disagreeing.spec = requested(&sample_spec()).with_service_name("roxyd-h1");
    let refusal = verbs
        .mint(&disagreeing)
        .await
        .expect_err("a restated identity that disagrees must be refused");
    assert_eq!(
        assert_refusal_pair(&verbs, &refusal, &Asked::new("mint", "roxyd", "h1", None)),
        "spec_identity_disagreement"
    );

    let mut unusable = mint_request("roxyd", "h1", None);
    unusable.wrap_ttl = Duration::ZERO;
    let refusal = verbs
        .mint(&unusable)
        .await
        .expect_err("a zero wrap_ttl must be refused");
    assert_eq!(
        assert_refusal_pair(&verbs, &refusal, &Asked::new("mint", "roxyd", "h1", None)),
        "zero"
    );

    assert_untouched(&server).await;
}

/// A `RegistrationIdCollision` is decided by *reading* the binding and
/// writes nothing, so the `OpenBao` audit device cannot see it. This
/// trail can, and the pair proves it.
#[tokio::test]
async fn a_registration_id_collision_writes_a_complete_pair() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let registration_id = "h1-roxyd";
    let bound = BindingRecord::creating("h2", &requested(&spec_for("roxyd")))
        .activated(&requested(&spec_for("roxyd")));
    mock_binding_read(&server, registration_id, &bound).await;

    let refusal = verbs
        .mint(&mint_request("roxyd", "h1", None))
        .await
        .expect_err("a binding bound to another host must be refused");
    assert!(matches!(
        refusal.error(),
        VerbError::RegistrationIdCollision { .. }
    ));

    let outcome = assert_pair(
        &verbs,
        refusal.context().request_id().as_str(),
        &Asked::new("mint", "roxyd", "h1", None),
    );
    assert_eq!(
        outcome["outcome"]["reason"],
        json!("registration_id_collision")
    );
    assert_eq!(outcome["registration_id"], json!(registration_id));

    let requests = server
        .received_requests()
        .await
        .expect("the mock server records requests");
    assert_eq!(requests.len(), 1, "the binding read and nothing else");
    assert_eq!(requests[0].method, wiremock::http::Method::GET);
}

/// A mint the store *can* record returns its material and leaves a
/// complete pair behind, on both mint arms.
///
/// Every other mint test in this section injects a write failure and so
/// stops short of the recorded-and-returned path. This is what holds it:
/// an outcome write that succeeded must hand back the wrapped
/// `secret_id` that a failed one drops, and the two arms must land under
/// their two different classes.
#[tokio::test]
async fn a_recorded_mint_returns_its_material_on_both_arms() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    mock_first_mint(&server, "h1-roxyd").await;

    let first = verbs
        .mint(&mint_request("roxyd", "h1", None))
        .await
        .expect("a mint against a writable store succeeds");
    assert_eq!(first.kind(), MintKind::FirstMint);
    let minted = assert_pair(
        &verbs,
        first.context().request_id().as_str(),
        &Asked::new("mint", "roxyd", "h1", None),
    );
    assert_eq!(minted["outcome"]["class"], json!("first_mint"));
    assert_eq!(minted["registration_id"], json!("h1-roxyd"));
    assert!(
        !first.into_wrapped_secret_id().is_empty(),
        "a recorded mint still hands its material back"
    );

    // The same identity, answered by an active binding: the re-mint arm,
    // through the same outcome write.
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let active = BindingRecord::creating("h1", &requested(&spec_for("roxyd")))
        .activated(&requested(&spec_for("roxyd")));
    mock_binding_read(&server, "h1-roxyd", &active).await;
    mock_first_mint(&server, "h1-roxyd").await;

    let again = verbs
        .mint(&mint_request("roxyd", "h1", None))
        .await
        .expect("a re-mint against a writable store succeeds");
    assert_eq!(again.kind(), MintKind::IdempotentReMint);
    let reminted = assert_pair(
        &verbs,
        again.context().request_id().as_str(),
        &Asked::new("mint", "roxyd", "h1", None),
    );
    assert_eq!(reminted["outcome"]["class"], json!("idempotent_remint"));
    assert_eq!(reminted["registration_id"], json!("h1-roxyd"));
    assert!(
        !again.into_wrapped_secret_id().is_empty(),
        "a recorded re-mint still hands its material back"
    );
}

/// An already-absent deregister the store *can* record leaves a
/// complete pair behind, under the idempotent class that arm owes.
///
/// Every other already-absent test in this section injects a write
/// failure — that is how a sweeping deregister is told from an empty
/// one — and so asserts the returned variant rather than the line. This
/// is what holds the line itself: `idempotent_already_absent` is
/// otherwise the one outcome class whose record is asserted only in the
/// ignored live tier, where CI's `test-core` job never reaches it.
#[tokio::test]
async fn a_recorded_already_absent_deregister_records_its_idempotent_class() {
    // Nothing mounted at all: no binding, and every resource reads
    // absent, so the sweep deletes nothing.
    let (_server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let outcome = verbs
        .deregister(&deregister_request("roxyd", "h1", None))
        .await
        .expect("an absent-binding deregister is idempotent");
    assert_eq!(outcome.kind(), DeregisterKind::AlreadyAbsent);
    let swept_nothing = assert_pair(
        &verbs,
        outcome.context().request_id().as_str(),
        &Asked::new("deregister", "roxyd", "h1", None),
    );
    assert_eq!(
        swept_nothing["outcome"]["class"],
        json!("idempotent_already_absent")
    );
    assert_eq!(swept_nothing["registration_id"], json!("h1-roxyd"));

    // The same class, reached by a sweep that removed a planted orphan.
    // The two are one class in the record — what tells them apart is the
    // mutation disposition, and only when a write fails — so the line is
    // the trail's only trace that the orphan is gone.
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    mock_material_present(&server, "h1-roxyd").await;
    let outcome = verbs
        .deregister(&deregister_request("roxyd", "h1", None))
        .await
        .expect("a sweeping absent-binding deregister is idempotent too");
    assert_eq!(outcome.kind(), DeregisterKind::AlreadyAbsent);
    assert!(outcome.teardown().aggregate_success());
    let swept = assert_pair(
        &verbs,
        outcome.context().request_id().as_str(),
        &Asked::new("deregister", "roxyd", "h1", None),
    );
    assert_eq!(
        swept["outcome"]["class"],
        json!("idempotent_already_absent")
    );
    assert_eq!(swept["registration_id"], json!("h1-roxyd"));
}

/// With the store failing the intent write, the invocation is refused
/// having made **no** `OpenBao` request at all.
///
/// This is the direct test that the intent write precedes every
/// `OpenBao` write: an implementation that wrote one record after the
/// fact and refused on failure would have reached the mock by now.
/// The trail is then empty — a property of *this* fault mode, which
/// fails before any byte reaches the file, not of failed intent writes
/// in general.
#[tokio::test]
async fn an_intent_write_failure_refuses_before_any_openbao_call() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    verbs
        .audit_store()
        .faults()
        .append
        .store(true, Ordering::SeqCst);

    let refusal = verbs
        .mint(&mint_request("roxyd", "h1", None))
        .await
        .expect_err("a mint whose intent record cannot be written must refuse");
    assert!(
        matches!(
            refusal.error(),
            VerbError::AuditUnwritable {
                phase: AuditPhase::Intent,
                ..
            }
        ),
        "expected an intent-phase audit failure, got {:?}",
        refusal.error()
    );
    assert_envelope(&refusal, ProducingArm::PreDerivation);

    let refusal = verbs
        .deregister(&deregister_request("roxyd", "h1", None))
        .await
        .expect_err("a deregister whose intent record cannot be written must refuse");
    assert!(
        matches!(
            refusal.error(),
            VerbError::AuditUnwritable {
                phase: AuditPhase::Intent,
                ..
            }
        ),
        "expected an intent-phase audit failure, got {:?}",
        refusal.error()
    );
    assert_envelope(&refusal, ProducingArm::PreDerivation);

    assert_untouched(&server).await;
    assert!(
        trail(&verbs).is_empty(),
        "this fault fails before any byte reaches the file"
    );
}

/// **The mint discriminating pair**, over one injected outcome-phase
/// failure.
///
/// A `StoredSpecConflict` is decided from a read and must not arm a
/// teardown obligation — a caller told one was owed there would
/// deregister a live identity this invocation did not create. A
/// provisioning failure that followed a successful claim must arm it,
/// and its `creating` binding is still in `OpenBao`. Asserting the two
/// together is what catches an implementation that classifies from
/// success-versus-refusal: both of these are refusals.
#[tokio::test]
async fn a_failed_outcome_write_tells_a_read_refusal_from_one_that_wrote() {
    let conflicting = RegistrationSpec {
        cert_group: Some(4242),
        reload: spec_for("roxyd").reload.clone(),
    };

    // Decided from a read: the binding exists, is bound to this host,
    // and carries a different spec.
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let stored =
        BindingRecord::creating("h1", &requested(&conflicting)).activated(&requested(&conflicting));
    mock_binding_read(&server, "h1-roxyd", &stored).await;
    let refusal =
        with_outcome_append_failure(&verbs, verbs.mint(&mint_request("roxyd", "h1", None)))
            .await
            .expect_err("a stored-spec conflict is a refusal");
    assert!(
        matches!(
            refusal.error(),
            VerbError::AuditUnwritable {
                phase: AuditPhase::Outcome,
                ..
            }
        ),
        "a refusal decided from a read owes no teardown, got {:?}",
        refusal.error()
    );

    // Wrote first: the claim landed, and the convergence then failed.
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    mock_binding_writes(&server, "h1-roxyd").await;
    Mock::given(method("POST"))
        .and(path(format!(
            "/v1/sys/policies/acl/{}",
            service_policy_name("h1-roxyd")
        )))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let refusal =
        with_outcome_append_failure(&verbs, verbs.mint(&mint_request("roxyd", "h1", None)))
            .await
            .expect_err("a failed convergence is a refusal");
    assert!(
        matches!(refusal.error(), VerbError::PostMintUnrecordable { .. }),
        "a refusal that followed a durable write owes a teardown, got {:?}",
        refusal.error()
    );
    assert!(
        creating_binding_left_behind(&server, "h1-roxyd").await,
        "the claim is retained through a failed convergence"
    );
}

/// **The deregister discriminating pair**, over one injected
/// outcome-phase failure.
///
/// Both invocations produce `DeregisterKind::AlreadyAbsent`. One swept
/// a planted orphan and is the only trace that the orphan is gone; the
/// other found nothing at all and changed nothing. An implementation
/// that classified from the outcome class fails one of them.
#[tokio::test]
async fn a_failed_outcome_write_tells_a_sweeping_already_absent_from_an_empty_one() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    mock_material_present(&server, "h1-roxyd").await;
    let refusal = with_outcome_append_failure(
        &verbs,
        verbs.deregister(&deregister_request("roxyd", "h1", None)),
    )
    .await
    .expect_err("a failed outcome write refuses");
    assert!(
        matches!(refusal.error(), VerbError::PostMintUnrecordable { .. }),
        "a sweep that removed material owes a teardown, got {:?}",
        refusal.error()
    );

    // Nothing mounted at all: every resource reads absent, so the sweep
    // deleted nothing.
    let (_server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let refusal = with_outcome_append_failure(
        &verbs,
        verbs.deregister(&deregister_request("roxyd", "h1", None)),
    )
    .await
    .expect_err("a failed outcome write refuses");
    assert!(
        matches!(
            refusal.error(),
            VerbError::AuditUnwritable {
                phase: AuditPhase::Outcome,
                ..
            }
        ),
        "an all-already-absent sweep changed nothing, got {:?}",
        refusal.error()
    );
}

/// A failed outcome write after a successful mint returns
/// `PostMintUnrecordable`, and the mint's `OpenBao` state is exactly
/// where the verb left it.
#[tokio::test]
async fn a_failed_outcome_write_after_a_first_mint_owes_a_teardown() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    mock_first_mint(&server, "h1-roxyd").await;

    let refusal =
        with_outcome_append_failure(&verbs, verbs.mint(&mint_request("roxyd", "h1", None)))
            .await
            .expect_err("a mint whose outcome cannot be recorded does not return its material");
    assert!(
        matches!(refusal.error(), VerbError::PostMintUnrecordable { .. }),
        "expected a teardown obligation, got {:?}",
        refusal.error()
    );

    let requests = server
        .received_requests()
        .await
        .expect("the mock server records requests");
    assert!(
        requests.iter().any(|request| request.url.path()
            == format!("/v1/auth/approle/role/{}", service_role_name("h1-roxyd"))),
        "the role the mint created is where it left it"
    );
    assert!(
        requests
            .iter()
            .all(|request| request.url.path() != binding_metadata_url("h1-roxyd")),
        "nothing rolls the binding back"
    );

    // A property of *this* fault mode, which fails before any byte
    // reaches the file — not a general consequence of a failed outcome
    // write, several of which leave the line complete and readable.
    let lines = trail(&verbs);
    assert_eq!(lines.len(), 1, "the intent line and no outcome line");
    assert_eq!(lines[0]["phase"], json!("intent"));
}

/// A mint that lost the compare-and-set on every attempt wrote nothing,
/// so its failed outcome write owes no teardown.
///
/// `Ok(KvCreateIfAbsent::AlreadyExists)` is the one result of the six
/// call sites that leaves the disposition clear: the claim was refused
/// and nothing at all reached `OpenBao`. Exhausting the bounded retry is
/// what drives it, and it is a refusal like the mutating ones above —
/// which is again why the class cannot be read off success versus
/// refusal.
#[tokio::test]
async fn a_lost_claim_race_leaves_the_disposition_clear() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    // The binding read finds nothing every time, and the claim is
    // refused by the absent-only compare-and-set every time — which is
    // another writer creating and removing it under this mint.
    Mock::given(method("POST"))
        .and(path(binding_data_url("h1-roxyd")))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "errors": ["check-and-set parameter did not match the current version"]
        })))
        .mount(&server)
        .await;

    let refusal =
        with_outcome_append_failure(&verbs, verbs.mint(&mint_request("roxyd", "h1", None)))
            .await
            .expect_err("an exhausted claim retry refuses");
    assert!(
        matches!(
            refusal.error(),
            VerbError::AuditUnwritable {
                phase: AuditPhase::Outcome,
                ..
            }
        ),
        "a lost compare-and-set wrote nothing, got {:?}",
        refusal.error()
    );
}

/// A failed outcome write after an idempotent re-mint owes a teardown
/// too: the re-mint issued fresh material, which is a state change even
/// though the role and the policy were reused untouched.
#[tokio::test]
async fn a_failed_outcome_write_after_a_remint_owes_a_teardown() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let active = BindingRecord::creating("h1", &requested(&spec_for("roxyd")))
        .activated(&requested(&spec_for("roxyd")));
    mock_binding_read(&server, "h1-roxyd", &active).await;
    mock_first_mint(&server, "h1-roxyd").await;

    let refusal =
        with_outcome_append_failure(&verbs, verbs.mint(&mint_request("roxyd", "h1", None)))
            .await
            .expect_err("a re-mint whose outcome cannot be recorded does not return its material");
    assert!(
        matches!(refusal.error(), VerbError::PostMintUnrecordable { .. }),
        "expected a teardown obligation, got {:?}",
        refusal.error()
    );

    let requests = server
        .received_requests()
        .await
        .expect("the mock server records requests");
    assert!(
        requests.iter().any(|request| request.url.path()
            == format!(
                "/v1/auth/approle/role/{}/secret-id",
                service_role_name("h1-roxyd")
            )),
        "the re-mint issued fresh material before the record could be written"
    );
    assert!(
        requests.iter().all(|request| {
            request.url.path() != binding_data_url("h1-roxyd")
                || request.method == wiremock::http::Method::GET
        }),
        "a re-mint against an active binding rewrites nothing"
    );
}

/// A failed outcome write after a deregister that removed a bound
/// identity owes a teardown, still reports what the sweep managed, and
/// re-drives cleanly once the store recovers.
#[tokio::test]
async fn a_failed_outcome_write_after_an_identity_removal_re_drives() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let bound = BindingRecord::creating("h1", &requested(&spec_for("roxyd")))
        .activated(&requested(&spec_for("roxyd")));
    mock_binding_read(&server, "h1-roxyd", &bound).await;
    mock_material_present(&server, "h1-roxyd").await;
    mock_binding_delete(&server, "h1-roxyd").await;

    let refusal = with_outcome_append_failure(
        &verbs,
        verbs.deregister(&deregister_request("roxyd", "h1", None)),
    )
    .await
    .expect_err("a failed outcome write refuses");
    assert!(
        matches!(refusal.error(), VerbError::PostMintUnrecordable { .. }),
        "expected a teardown obligation, got {:?}",
        refusal.error()
    );
    let report = refusal
        .teardown()
        .expect("the sweep's report still reaches the caller");
    assert!(report.aggregate_success());

    let requests = server
        .received_requests()
        .await
        .expect("the mock server records requests");
    assert!(
        requests.iter().any(|request| {
            request.url.path() == binding_metadata_url("h1-roxyd")
                && request.method == wiremock::http::Method::DELETE
        }),
        "the binding was deleted before the record could be written"
    );

    // The store recovers, and the re-drive writes its own pair.
    verbs
        .audit_store()
        .faults()
        .append
        .store(false, Ordering::SeqCst);
    let outcome = verbs
        .deregister(&deregister_request("roxyd", "h1", None))
        .await
        .expect("a re-drive against a working store succeeds");
    assert_eq!(outcome.kind(), DeregisterKind::IdentityRemoved);
    let line = assert_pair(
        &verbs,
        outcome.context().request_id().as_str(),
        &Asked::new("deregister", "roxyd", "h1", None),
    );
    assert_eq!(line["outcome"]["class"], json!("identity_removed"));
    assert_eq!(line["registration_id"], json!("h1-roxyd"));
}

/// A failed outcome write on a refusal decided before anything was
/// touched carries `AuditPhase::Outcome` and never a teardown
/// obligation.
///
/// Paired with the intent-failure test above, this is what pins both
/// phase values: a variant that hard-coded `Intent` would satisfy that
/// one and fail here, and one that hard-coded `Outcome` the reverse.
#[tokio::test]
async fn a_failed_outcome_write_on_a_no_change_refusal_carries_the_outcome_phase() {
    // Decided from a read, before the sweep.
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let bound = BindingRecord::creating("h2", &requested(&spec_for("roxyd")))
        .activated(&requested(&spec_for("roxyd")));
    mock_binding_read(&server, "h1-roxyd", &bound).await;
    let refusal = with_outcome_append_failure(
        &verbs,
        verbs.deregister(&deregister_request("roxyd", "h1", None)),
    )
    .await
    .expect_err("a wrong-host deregister is refused");
    assert!(
        matches!(
            refusal.error(),
            VerbError::AuditUnwritable {
                phase: AuditPhase::Outcome,
                ..
            }
        ),
        "a host mismatch changes nothing, got {:?}",
        refusal.error()
    );
    assert!(
        !matches!(refusal.error(), VerbError::PostMintUnrecordable { .. }),
        "a host mismatch owes no teardown"
    );

    // Decided before derivation, with no `OpenBao` call at all.
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let refusal = with_outcome_append_failure(
        &verbs,
        verbs.mint(&mint_request("bootroot-decoy", "h1", None)),
    )
    .await
    .expect_err("a reserved name is refused");
    assert!(
        matches!(
            refusal.error(),
            VerbError::AuditUnwritable {
                phase: AuditPhase::Outcome,
                ..
            }
        ),
        "a pre-derivation refusal changes nothing, got {:?}",
        refusal.error()
    );
    assert_untouched(&server).await;
}

/// A failed outcome write after a teardown whose report shows a
/// resource `Removed` or `Failed` owes a teardown, even though the
/// invocation was refused.
#[tokio::test]
async fn a_failed_outcome_write_after_a_failed_teardown_owes_a_teardown() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let bound = BindingRecord::creating("h1", &requested(&spec_for("roxyd")))
        .activated(&requested(&spec_for("roxyd")));
    mock_binding_read(&server, "h1-roxyd", &bound).await;
    mock_material_present(&server, "h1-roxyd").await;
    // The role read fails outright, so the sweep records a `Failed`
    // attempt and refuses in aggregate having already removed the KV
    // material.
    Mock::given(method("GET"))
        .and(path(format!(
            "/v1/auth/approle/role/{}",
            service_role_name("h1-roxyd")
        )))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;

    let refusal = with_outcome_append_failure(
        &verbs,
        verbs.deregister(&deregister_request("roxyd", "h1", None)),
    )
    .await
    .expect_err("a teardown that could not finish must refuse");
    assert!(
        matches!(refusal.error(), VerbError::PostMintUnrecordable { .. }),
        "expected a teardown obligation, got {:?}",
        refusal.error()
    );
    let report = refusal.teardown().expect("the partial report is carried");
    assert!(!report.aggregate_success());
    assert!(
        report
            .attempts()
            .iter()
            .any(|attempt| matches!(attempt.outcome, ResourceOutcome::Removed)),
        "the KV material was removed before the role read failed: {:?}",
        report.attempts()
    );
}

/// A `sync_data` failure is a write failure for its phase like any
/// other, and the disposition still decides what it returns.
///
/// It is the one failure mode that leaves a complete, newline-terminated
/// line already in the file, so the trail is asserted only for JSONL
/// integrity: whether the unflushed line is there is the store's
/// business and this issue neither promises nor removes it.
#[tokio::test]
async fn a_sync_failure_is_a_write_failure_for_its_phase() {
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    verbs
        .audit_store()
        .faults()
        .sync
        .store(true, Ordering::SeqCst);
    let refusal = verbs
        .mint(&mint_request("roxyd", "h1", None))
        .await
        .expect_err("an unflushed intent record is not a written one");
    assert!(
        matches!(
            refusal.error(),
            VerbError::AuditUnwritable {
                phase: AuditPhase::Intent,
                ..
            }
        ),
        "expected an intent-phase audit failure, got {:?}",
        refusal.error()
    );
    assert_untouched(&server).await;

    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    mock_first_mint(&server, "h1-roxyd").await;
    let refusal = fail_the_outcome_write(
        &verbs,
        verbs.mint(&mint_request("roxyd", "h1", None)),
        |faults| faults.sync.store(true, Ordering::SeqCst),
    )
    .await
    .expect_err("an unflushed outcome record is not a written one");
    assert!(
        matches!(refusal.error(), VerbError::PostMintUnrecordable { .. }),
        "expected a teardown obligation, got {:?}",
        refusal.error()
    );
    let requests = server
        .received_requests()
        .await
        .expect("the mock server records requests");
    assert!(
        requests.iter().any(|request| request.url.path()
            == format!("/v1/auth/approle/role/{}", service_role_name("h1-roxyd"))),
        "the mint's state is where the verb left it"
    );
    // Every line parses, whether or not the unflushed one is there.
    let lines = trail(&verbs);
    assert!((1..=2).contains(&lines.len()), "got {lines:#?}");
}

/// A rotation the pending record required, and that failed, is a write
/// failure for its phase too.
#[tokio::test]
async fn a_failed_rotation_is_a_write_failure_for_its_phase() {
    /// Fills the active file to one byte short of the limit, so the very
    /// next record genuinely requires a rotation.
    fn fill_to_limit(store: &AuditRecordStore) {
        use std::io::Write as _;

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(store.active_path())
            .expect("open the active file");
        let existing = file.metadata().expect("stat").len();
        let padding = MIN_AUDIT_MAX_FILE_BYTES - existing - 1;
        let line = "{\"filler\":\"x\"}\n";
        let step = u64::try_from(line.len()).expect("the filler line fits a u64");
        let mut written = 0u64;
        while written + step <= padding {
            file.write_all(line.as_bytes()).expect("pad");
            written += step;
        }
    }

    // Intent phase: the very first append has to rotate, and cannot.
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    fill_to_limit(verbs.audit_store());
    verbs
        .audit_store()
        .faults()
        .rotate
        .store(true, Ordering::SeqCst);
    let refusal = verbs
        .mint(&mint_request("roxyd", "h1", None))
        .await
        .expect_err("a record that cannot be rotated into place is not written");
    assert!(
        matches!(
            refusal.error(),
            VerbError::AuditUnwritable {
                phase: AuditPhase::Intent,
                ..
            }
        ),
        "expected an intent-phase audit failure, got {:?}",
        refusal.error()
    );
    assert_untouched(&server).await;

    // Outcome phase, after a mint that changed `OpenBao`. The file is
    // filled while the outcome append is parked at the gate — it has
    // not opened the file yet — so the rotation it then needs is the
    // one that fails.
    let (server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    mock_first_mint(&server, "h1-roxyd").await;
    let store = verbs.audit_store().clone();
    let refusal = fail_the_outcome_write(
        &verbs,
        verbs.mint(&mint_request("roxyd", "h1", None)),
        |faults| {
            fill_to_limit(&store);
            faults.rotate.store(true, Ordering::SeqCst);
        },
    )
    .await
    .expect_err("a record that cannot be rotated into place is not written");
    assert!(
        matches!(refusal.error(), VerbError::PostMintUnrecordable { .. }),
        "expected a teardown obligation, got {:?}",
        refusal.error()
    );
}

/// The record carries the verb layer's own refusal variant, not a
/// coarser wire grouping: three refusals a wire contract would collapse
/// produce three different `outcome.reason` values.
#[tokio::test]
async fn three_close_refusals_produce_three_distinct_reasons() {
    let widened = RegistrationSpec {
        cert_group: Some(4242),
        reload: spec_for("roxyd").reload.clone(),
    };

    // Outside the rendered safe-set, with no binding at all.
    let (_server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let mut outside = mint_request("roxyd", "h1", None);
    outside.spec = requested(&widened);
    let refusal = verbs
        .mint(&outside)
        .await
        .expect_err("a spec outside the safe-set must be refused");
    let outside_reason =
        assert_refusal_pair(&verbs, &refusal, &Asked::new("mint", "roxyd", "h1", None));

    // Inside the safe-set, and disagreeing with what the identity
    // already carries.
    let (server, _dir, _store_root, verbs) =
        audit_harness(&base_fixture().with_component("roxyd", Multiplicity::OnePerHost, &widened))
            .await;
    let stored = BindingRecord::creating("h1", &requested(&spec_for("roxyd")))
        .activated(&requested(&spec_for("roxyd")));
    mock_binding_read(&server, "h1-roxyd", &stored).await;
    let mut conflicting = mint_request("roxyd", "h1", None);
    conflicting.spec = requested(&widened);
    let refusal = verbs
        .mint(&conflicting)
        .await
        .expect_err("a stored-spec disagreement must be refused");
    let conflict_reason =
        assert_refusal_pair(&verbs, &refusal, &Asked::new("mint", "roxyd", "h1", None));

    // A spec that restates a different identity, refused before
    // derivation.
    let (_server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;
    let mut disagreeing = mint_request("roxyd", "h1", None);
    disagreeing.spec = requested(&sample_spec()).with_service_name("roxyd-h1");
    let refusal = verbs
        .mint(&disagreeing)
        .await
        .expect_err("a restated identity that disagrees must be refused");
    let identity_reason =
        assert_refusal_pair(&verbs, &refusal, &Asked::new("mint", "roxyd", "h1", None));

    assert_eq!(outside_reason, "service_spec_outside_safe_set");
    assert_eq!(conflict_reason, "stored_spec_conflict");
    assert_eq!(identity_reason, "spec_identity_disagreement");
    let mut all = vec![outside_reason, conflict_reason, identity_reason];
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), 3, "the trail must tell the three apart");
}

/// The caller identity reaches the record unchanged and uninterpreted.
///
/// A distinctive value **within** the store's field cap, so what is
/// asserted is that the verb layer passes it through — the bounding of
/// an over-long one is the store's own, and is tested there.
#[tokio::test]
async fn the_caller_identity_reaches_the_record_unchanged() {
    const DISTINCTIVE: &str = "spiffe://review/manager#7f3a \"quoted\" \\ and a tab\t";

    let (_server, _dir, _store_root, verbs) = audit_harness(&base_fixture()).await;

    let mut request = mint_request("bootroot-decoy", "h1", None);
    request.caller = CallerIdentity::new(DISTINCTIVE);
    let refusal = verbs
        .mint(&request)
        .await
        .expect_err("a reserved name is refused");

    let lines = lines_for(&verbs, refusal.context().request_id().as_str());
    assert_eq!(lines.len(), 2);
    for line in &lines {
        assert_eq!(line["caller_identity"], json!(DISTINCTIVE), "{line}");
        assert!(
            line.get("truncated").is_none(),
            "a value inside the cap is not shortened: {line}"
        );
    }
    assert_eq!(
        refusal.context().caller().as_str(),
        DISTINCTIVE,
        "and the outcome carries it too"
    );
}

// ---------------------------------------------------------------------
// Fast tier: the two token buckets in front of both verbs
// ---------------------------------------------------------------------

/// A sink that both counts and keeps every event, built as a trivial
/// forwarding wrapper around the shipped counting sink.
///
/// The wrapper is the shape the sibling record work's coalescing sink
/// takes, so driving the verbs through one here is the composability
/// assertion as well as the recording one.
#[derive(Debug)]
struct RecordingSink {
    counts: Arc<CountingLimitedInvocationSink>,
    events: std::sync::Mutex<Vec<LimitedInvocation>>,
}

impl RecordingSink {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            counts: Arc::new(CountingLimitedInvocationSink::new()),
            events: std::sync::Mutex::new(Vec::new()),
        })
    }

    fn events(&self) -> Vec<LimitedInvocation> {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn count(&self, bucket: LimiterBucket) -> u64 {
        self.counts.count(bucket)
    }
}

impl LimitedInvocationSink for RecordingSink {
    fn limited(&self, event: &LimitedInvocation) {
        self.events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.clone());
        self.counts.limited(event);
    }
}

/// A refusal harness whose limiter the test sizes itself, with the sink
/// that recorded its limited invocations.
async fn limited_harness(
    fixture: &RegistrarConfigFixture,
    settings: VerbRateLimiterSettings,
) -> (MockServer, TempDir, RegistrarVerbs, Arc<RecordingSink>) {
    let server = MockServer::start().await;
    let (dir, config) = load_fixture(fixture);
    let sink = RecordingSink::new();
    let verbs = verbs_with_limiter(
        mock_client(&server),
        "secret",
        config,
        AuditRecordStore::open_temporary().expect("a temporary audit store"),
        VerbRateLimiter::new(settings, sink.clone()),
    );
    (server, dir, verbs, sink)
}

/// A refusal budget of `refusal_burst` with the admission budget left
/// wide, and refill intervals long enough that no test accrues a token
/// by accident.
fn refusal_budget(refusal_burst: u32) -> VerbRateLimiterSettings {
    VerbRateLimiterSettings {
        predecision_refusal_burst: refusal_burst,
        predecision_refusal_refill_interval_ms: 600_000,
        ..VerbRateLimiterSettings::default()
    }
}

/// The mirror of [`refusal_budget`]: a narrow admission budget with the
/// refusal budget left wide.
fn admission_budget(admission_burst: u32) -> VerbRateLimiterSettings {
    VerbRateLimiterSettings {
        admission_burst,
        admission_refill_interval_ms: 600_000,
        ..VerbRateLimiterSettings::default()
    }
}

/// Asserts that a limited refusal and its unlimited twin map to the same
/// wire answer — the same `RefusalClass` and the same identifier, or the
/// same absence of one — and that neither is `RegistrarBusy`.
///
/// `map_refusal` lives in the endpoint module, which is compiled only on
/// Linux, so off Linux there is no mapping to read and the pairwise
/// assertion covers the `VerbError` alone. The `check` and `test-core`
/// CI jobs both run on Linux, which is where the wire half is gated.
#[cfg(target_os = "linux")]
fn assert_same_wire_answer(name: &str, limited: &VerbRefusal, unlimited: &VerbRefusal) {
    use crate::registrar::endpoint::protocol::{
        RegistrarHealth, decode_refusal_response, encode_refusal_response,
    };

    let answer = |refusal: &VerbRefusal| {
        let encoded = encode_refusal_response(refusal, &RegistrarHealth::default())
            .expect("a refusal encodes");
        let decoded = decode_refusal_response(&encoded).expect("a refusal decodes");
        (
            format!("{:?}", decoded.class),
            decoded.error.map(|error| format!("{error:?}")),
        )
    };

    let (class, identifier) = answer(limited);
    assert_eq!(
        (class, identifier.clone()),
        answer(unlimited),
        "{name}: limiting must not change the wire identifier or the class"
    );
    assert!(
        !identifier
            .as_deref()
            .is_some_and(|rendered| rendered.contains("RegistrarBusy")),
        "{name}: RegistrarBusy is never substituted on the pre-decision path"
    );
}

#[cfg(not(target_os = "linux"))]
fn assert_same_wire_answer(_name: &str, _limited: &VerbRefusal, _unlimited: &VerbRefusal) {}

/// One pre-decision refusal case: the request, the fixture it needs,
/// and the [`VerbError`] the request exists to provoke.
struct PreDecisionCase {
    name: &'static str,
    fixture: RegistrarConfigFixture,
    request: MintRequest,
    expects: fn(&VerbError) -> bool,
}

fn pre_decision_case(
    name: &'static str,
    fixture: RegistrarConfigFixture,
    request: MintRequest,
    expects: fn(&VerbError) -> bool,
) -> PreDecisionCase {
    PreDecisionCase {
        name,
        fixture,
        request,
        expects,
    }
}

/// Every pre-decision refusal the verbs can produce, as a mint request
/// paired with the fixture it needs and the refusal it is here for.
///
/// The set spans both wire classes deliberately: a permanent
/// identifier-carrying refusal, a reserved name and an out-of-range
/// `wrap_ttl`, the last two of which are retryable with no identifier
/// today. What limiting preserves is the answer, not its permanence.
///
/// The expected error travels with each case so that a case cannot
/// quietly stop covering the refusal it names. A request that began
/// tripping some earlier check would still pair identically under
/// limiting and would still satisfy every assertion below, leaving the
/// refusal uncovered with nothing to say so.
fn pre_decision_cases() -> Vec<PreDecisionCase> {
    let mut cases = identity_pre_decision_cases();
    cases.extend(wrap_ttl_pre_decision_cases());
    cases
}

/// The refusals a request earns from its identity triple or its
/// restated spec, before any wrap-TTL rule is consulted.
fn identity_pre_decision_cases() -> Vec<PreDecisionCase> {
    let unconfigured = base_fixture();
    let mut spec_conflict = mint_request("roxyd", "h1", None);
    spec_conflict.spec = requested(&sample_spec()).with_service_name("roxyd-h1");
    vec![
        pre_decision_case(
            "an invalid service_name label",
            base_fixture(),
            mint_request("bad_name", "h1", None),
            |error| {
                matches!(
                    error,
                    VerbError::Registrar(RegistrarError::InvalidServiceName { .. })
                )
            },
        ),
        pre_decision_case(
            "an invalid host label",
            base_fixture(),
            mint_request("roxyd", "-h1", None),
            |error| {
                matches!(
                    error,
                    VerbError::Registrar(RegistrarError::InvalidHost { .. })
                )
            },
        ),
        pre_decision_case(
            "a reserved service_name",
            base_fixture(),
            mint_request("bootroot-decoy", "h1", None),
            |error| matches!(error, VerbError::ReservedServiceName { .. }),
        ),
        pre_decision_case(
            "an unconfigured component",
            unconfigured,
            mint_request("absent", "h1", None),
            |error| {
                matches!(
                    error,
                    VerbError::Registrar(RegistrarError::ComponentNotConfigured { .. })
                )
            },
        ),
        pre_decision_case(
            "an instance on a one-per-host component",
            base_fixture(),
            mint_request("roxyd", "h1", Some(1)),
            |error| {
                matches!(
                    error,
                    VerbError::Registrar(RegistrarError::ServiceInstanceMismatch { .. })
                )
            },
        ),
        pre_decision_case(
            "a restated spec that disagrees",
            base_fixture(),
            spec_conflict,
            |error| {
                matches!(
                    error,
                    VerbError::Registrar(RegistrarError::SpecIdentityDisagreement { .. })
                )
            },
        ),
    ]
}

/// One case per [`WrapTtlRefusal`] variant, because each is a distinct
/// answer the caller earned and the limiter must hand back unchanged.
///
/// The request each case sends is chosen by matching over the variants
/// rather than written out beside them, so a fifth variant fails to
/// build here until someone writes the request that provokes it.
///
/// The list below is the one part the compiler cannot hold: nothing in
/// Rust enumerates an enum's variants without a derive, so a variant
/// given a match arm and left out of this list would build and cover
/// nothing. The arm is what sends whoever adds it here.
fn wrap_ttl_pre_decision_cases() -> Vec<PreDecisionCase> {
    [
        WrapTtlRefusal::Zero,
        WrapTtlRefusal::Negative,
        WrapTtlRefusal::NotWholeSeconds,
        WrapTtlRefusal::ExceedsOpenBaoRange,
    ]
    .into_iter()
    .map(|refusal| {
        let (name, requested, expects): (_, _, fn(&VerbError) -> bool) = match refusal {
            WrapTtlRefusal::Zero => ("a zero wrap_ttl", Duration::ZERO, |error| {
                matches!(error, VerbError::InvalidWrapTtl(WrapTtlRefusal::Zero))
            }),
            WrapTtlRefusal::Negative => ("a negative wrap_ttl", Duration::seconds(-5), |error| {
                matches!(error, VerbError::InvalidWrapTtl(WrapTtlRefusal::Negative))
            }),
            WrapTtlRefusal::NotWholeSeconds => (
                "a sub-second wrap_ttl",
                Duration::milliseconds(250),
                |error| {
                    matches!(
                        error,
                        VerbError::InvalidWrapTtl(WrapTtlRefusal::NotWholeSeconds)
                    )
                },
            ),
            WrapTtlRefusal::ExceedsOpenBaoRange => (
                "a wrap_ttl past the OpenBao range",
                // One second past the largest whole-second value an
                // `OpenBao` duration string can carry, so it is refused
                // rather than clamped.
                Duration::seconds(9_223_372_037),
                |error| {
                    matches!(
                        error,
                        VerbError::InvalidWrapTtl(WrapTtlRefusal::ExceedsOpenBaoRange)
                    )
                },
            ),
        };
        let mut request = mint_request("roxyd", "h1", None);
        request.wrap_ttl = requested;
        pre_decision_case(name, base_fixture(), request, expects)
    })
    .collect()
}

/// A flood of invocations the pure checks refuse is limited: past the
/// burst, neither record phase is written, one event is emitted per
/// limited invocation, and the caller still receives the refusal its own
/// input earned.
#[tokio::test]
async fn a_pre_decision_flood_is_limited_without_writing_a_record() {
    const BURST: u32 = 2;
    const FLOOD: u32 = 5;
    let (server, _dir, verbs, sink) = limited_harness(&base_fixture(), refusal_budget(BURST)).await;

    let mut refusals = Vec::new();
    for _ in 0..FLOOD {
        refusals.push(
            verbs
                .mint(&mint_request("bootroot-decoy", "h1", None))
                .await
                .expect_err("a reserved service_name must be refused"),
        );
    }

    // Every caller got the same answer, limited or not.
    for refusal in &refusals {
        assert_envelope(refusal, ProducingArm::PreDerivation);
        assert!(
            matches!(refusal.error(), VerbError::ReservedServiceName { .. }),
            "limiting suppresses the record, never the answer: {:?}",
            refusal.error()
        );
    }

    // Only the first two wrote anything, and each wrote a complete pair.
    let recorded: Vec<_> = refusals
        .iter()
        .filter(|refusal| !lines_for(&verbs, refusal.context().request_id().as_str()).is_empty())
        .collect();
    assert_eq!(
        recorded.len(),
        BURST as usize,
        "only the invocations that found a token may write"
    );
    for refusal in recorded {
        let asked = Asked::new("mint", "bootroot-decoy", "h1", None);
        assert_eq!(
            assert_refusal_pair(&verbs, refusal, &asked),
            "reserved_service_name"
        );
    }
    assert_eq!(
        trail(&verbs).len(),
        BURST as usize * 2,
        "a limited invocation appends nothing at all"
    );

    // One event per limited invocation, carrying the key it was charged
    // against, and nothing on the other bucket.
    let events = sink.events();
    assert_eq!(events.len(), (FLOOD - BURST) as usize);
    for event in &events {
        assert_eq!(event.caller().as_str(), CALLER);
        assert_eq!(event.verb(), crate::registrar::audit::AuditVerb::Mint);
        assert_eq!(event.bucket(), LimiterBucket::PredecisionRefusal);
    }
    assert_eq!(
        sink.count(LimiterBucket::PredecisionRefusal),
        u64::from(FLOOD - BURST)
    );
    assert_eq!(sink.count(LimiterBucket::Admission), 0);

    assert_untouched(&server).await;
}

/// The shipped pre-decision limiter bound remains durable when the real
/// verb path feeds its limited events through the coalescing sink.
///
/// The flood remains inside one paused Tokio-time coalescing window, so
/// differing traffic volume changes the aggregate count but not the number
/// of durable records it creates.
#[tokio::test(start_paused = true)]
async fn pre_decision_refusal_floods_coalesce_at_the_shipped_bound() {
    const FLOODS: [u32; 2] = [40, 256];
    const WINDOW_SECONDS: u64 = 60;
    const ADMITTED_REQUESTS: usize = 32;
    const EXPECTED_RECORDS: usize = 2 * ADMITTED_REQUESTS + 1;
    let settings = VerbRateLimiterSettings::default();
    assert_eq!(settings.predecision_refusal_burst, 32);
    assert_eq!(settings.predecision_refusal_refill_interval_ms, 1_000);

    let mut record_totals = Vec::new();
    for flood in FLOODS {
        let server = MockServer::start().await;
        let (_dir, config) = load_fixture(&base_fixture());
        let audit_store = AuditRecordStore::open_temporary().expect("a temporary audit store");
        let counts = Arc::new(CountingLimitedInvocationSink::new());
        let sink = Arc::new(CoalescingLimitedInvocationSink::new(
            Arc::clone(&counts),
            audit_store.clone(),
            WINDOW_SECONDS,
        ));
        let verbs = verbs_with_limiter(
            mock_client(&server),
            "secret",
            config,
            audit_store,
            VerbRateLimiter::new(settings, sink.clone()),
        );

        let mut refusals = Vec::new();
        for _ in 0..flood {
            let refusal = verbs
                .mint(&mint_request("not a label", "h1", None))
                .await
                .expect_err("an invalid service name must be refused");
            assert_envelope(&refusal, ProducingArm::PreDerivation);
            assert!(matches!(
                refusal.error(),
                VerbError::Registrar(RegistrarError::InvalidServiceName { .. })
            ));
            refusals.push(refusal);
        }
        sink.flush();

        let records = trail(&verbs);
        assert_eq!(records.len(), EXPECTED_RECORDS, "flood of {flood}");
        assert_eq!(
            records
                .iter()
                .filter(|record| record["phase"] == json!("intent"))
                .count(),
            32,
            "the admitted requests each write one intent"
        );
        assert_eq!(
            records
                .iter()
                .filter(|record| record["phase"] == json!("outcome"))
                .count(),
            32,
            "the admitted requests each write one refusal outcome"
        );
        assert_durable_invalid_service_name_pairs(&verbs, &refusals, flood, ADMITTED_REQUESTS);
        let limited: Vec<_> = records
            .iter()
            .filter(|record| record["phase"] == json!("limited"))
            .collect();
        assert_eq!(limited.len(), 1, "one coalesced limited record");
        assert_eq!(limited[0]["limited_bucket"], json!("predecision_refusal"));
        assert_eq!(limited[0]["count"], json!(flood - 32));
        assert_eq!(
            counts.count(LimiterBucket::PredecisionRefusal),
            u64::from(flood - 32)
        );
        assert_eq!(counts.count(LimiterBucket::Admission), 0);
        assert_untouched(&server).await;
        record_totals.push(records.len());
    }
    assert_eq!(record_totals, vec![EXPECTED_RECORDS; FLOODS.len()]);
}

/// Driven pairwise across the whole pre-decision refusal set: the
/// `VerbError`, the mapped wire identifier — or its absence — and the
/// `RefusalClass` are equal whether the invocation was limited or not,
/// and `RegistrarBusy` is never substituted for an answer the daemon has
/// already determined.
#[tokio::test]
async fn limiting_preserves_the_callers_answer_across_every_pre_decision_refusal() {
    for PreDecisionCase {
        name,
        fixture,
        request,
        expects,
    } in pre_decision_cases()
    {
        // Unlimited: a wide refusal budget, so the first invocation finds
        // a token.
        let (unlimited_server, _unlimited_dir, unlimited, _) =
            limited_harness(&fixture, refusal_budget(1)).await;
        let unlimited_refusal = unlimited
            .mint(&request)
            .await
            .expect_err("every case here is a pre-decision refusal");

        // Limited: a burst of exactly one, spent by an invocation of the
        // same shape, so the second is limited on the same bucket.
        let (limited_server, _limited_dir, limited, sink) =
            limited_harness(&fixture, refusal_budget(1)).await;
        let _spent = limited
            .mint(&request)
            .await
            .expect_err("the first invocation spends the bucket's one token");
        let limited_refusal = limited
            .mint(&request)
            .await
            .expect_err("the second invocation is limited");
        assert_eq!(
            sink.count(LimiterBucket::PredecisionRefusal),
            1,
            "{name} must have been limited on the pre-decision bucket"
        );

        // The case still refuses for the reason it was written for, so
        // the pairwise assertions below are comparing the answer this
        // case exists to cover.
        assert!(
            expects(unlimited_refusal.error()),
            "{name}: no longer produces the refusal it covers: {:?}",
            unlimited_refusal.error()
        );
        assert_eq!(
            format!("{:?}", limited_refusal.error()),
            format!("{:?}", unlimited_refusal.error()),
            "{name}: limiting must not change the VerbError"
        );
        assert!(
            !matches!(limited_refusal.error(), VerbError::Throttled { .. }),
            "{name}: a pre-decision refusal is never replaced by a throttle"
        );
        assert_same_wire_answer(name, &limited_refusal, &unlimited_refusal);

        // Neither invocation reached OpenBao, and the limited one wrote
        // nothing.
        assert_untouched(&unlimited_server).await;
        assert_untouched(&limited_server).await;
        assert!(
            lines_for(&limited, limited_refusal.context().request_id().as_str()).is_empty(),
            "{name}: a limited invocation appends nothing"
        );
    }
}

/// The isolation the two buckets exist for: a flood on the free path
/// cannot starve legitimate mints. With the `predecision_refusal` bucket
/// drained, an admitted mint is still performed — it reaches `OpenBao`
/// and both its records are written.
#[tokio::test]
async fn a_pre_decision_flood_does_not_starve_an_admitted_mint() {
    let (server, _dir, verbs, sink) = limited_harness(&base_fixture(), refusal_budget(1)).await;

    // Drain the refusal bucket and then flood past it.
    for _ in 0..4 {
        verbs
            .mint(&mint_request("bootroot-decoy", "h1", None))
            .await
            .expect_err("a reserved service_name must be refused");
    }
    assert_eq!(sink.count(LimiterBucket::PredecisionRefusal), 3);
    assert_untouched(&server).await;

    // A well-formed mint is charged the untouched admission bucket, so
    // it is attempted: it reaches OpenBao — which this harness answers
    // with nothing, so the invocation ends unavailable rather than
    // throttled — and its pair is written.
    let refusal = verbs
        .mint(&mint_request("roxyd", "h1", None))
        .await
        .expect_err("an unanswered OpenBao makes this mint unavailable");
    assert!(
        matches!(refusal.error(), VerbError::Unavailable { .. }),
        "an admitted mint is performed, not throttled: {:?}",
        refusal.error()
    );
    let requests = server
        .received_requests()
        .await
        .expect("the mock server records requests");
    assert!(
        !requests.is_empty(),
        "the admitted mint must have reached OpenBao"
    );
    assert_pair(
        &verbs,
        refusal.context().request_id().as_str(),
        &Asked::new("mint", "roxyd", "h1", None),
    );
    assert_eq!(
        sink.count(LimiterBucket::Admission),
        0,
        "the refusal flood must not have spent admission budget"
    );
}

/// A refusal raised **after** the pure checks pass spends an `admission`
/// token, and the bucket charged is never revised by what the invocation
/// turned out to be. Draining it that way makes the next mint throttled
/// — with no `OpenBao` call, no record, and one event on the admission
/// bucket.
#[tokio::test]
async fn a_derivation_refusal_spends_an_admission_token_and_the_next_mint_is_throttled() {
    let long_component = "c".repeat(63);
    let long_host = "h".repeat(63);
    let fixture =
        base_fixture().with_component(&long_component, Multiplicity::ManyPerHost, &sample_spec());
    let (server, _dir, verbs, sink) = limited_harness(&fixture, admission_budget(1)).await;

    // Stage 1 passes, so this is an admission invocation even though it
    // refuses before any OpenBao call and reaches no lock.
    let refusal = verbs
        .mint(&mint_request(&long_component, &long_host, Some(1000)))
        .await
        .expect_err("an over-long derived key must be refused");
    assert_envelope(&refusal, ProducingArm::Derivation);
    assert!(matches!(
        refusal.error(),
        VerbError::Registrar(RegistrarError::DerivedKeyInvalid { .. })
    ));
    assert_pair(
        &verbs,
        refusal.context().request_id().as_str(),
        &Asked::new("mint", &long_component, &long_host, Some(1000)),
    );
    let lines_before = trail(&verbs).len();

    // The admission bucket is now empty, so the next mint is not
    // attempted at all.
    let throttled = verbs
        .mint(&mint_request("roxyd", "h1", None))
        .await
        .expect_err("a drained admission bucket throttles");
    assert_envelope(&throttled, ProducingArm::PreDerivation);
    let VerbError::Throttled { retry_after } = throttled.error() else {
        panic!("expected a throttle, got {:?}", throttled.error());
    };
    assert!(
        *retry_after >= 1,
        "the retry payload is an unsigned whole-second duration of at least 1"
    );
    assert_eq!(
        trail(&verbs).len(),
        lines_before,
        "a throttled invocation writes neither record"
    );
    assert_untouched(&server).await;

    let events = sink.events();
    assert_eq!(events.len(), 1, "one event per limited invocation");
    let event = events.first().expect("one event");
    assert_eq!(event.bucket(), LimiterBucket::Admission);
    assert_eq!(event.caller().as_str(), CALLER);
    assert_eq!(sink.count(LimiterBucket::Admission), 1);
    assert_eq!(sink.count(LimiterBucket::PredecisionRefusal), 0);

    // And the other bucket is untouched: a pre-decision refusal still
    // gets its own answer and its own pair.
    let reserved = verbs
        .mint(&mint_request("bootroot-decoy", "h1", None))
        .await
        .expect_err("a reserved service_name must be refused");
    assert!(matches!(
        reserved.error(),
        VerbError::ReservedServiceName { .. }
    ));
    assert_pair(
        &verbs,
        reserved.context().request_id().as_str(),
        &Asked::new("mint", "bootroot-decoy", "h1", None),
    );
}

/// The throttle is distinguishable in `VerbError` from every permanent
/// unavailability variant, whose reasons all mean *until an operator
/// acts*.
#[tokio::test]
async fn the_throttle_is_its_own_variant_rather_than_an_unavailability() {
    let (_server, _dir, verbs, _sink) = limited_harness(&base_fixture(), admission_budget(1)).await;

    // Spend the deregister verb's admission token, then throttle it.
    let _spent = verbs
        .deregister(&deregister_request("roxyd", "h1", None))
        .await;
    let throttled = verbs
        .deregister(&deregister_request("roxyd", "h1", None))
        .await
        .expect_err("a drained admission bucket throttles");
    assert!(
        matches!(throttled.error(), VerbError::Throttled { .. }),
        "expected a throttle, got {:?}",
        throttled.error()
    );
    assert!(
        !matches!(
            throttled.error(),
            VerbError::Unavailable { .. }
                | VerbError::AuditUnwritable { .. }
                | VerbError::PostMintUnrecordable { .. }
        ),
        "the throttle is its own variant"
    );
}

/// Counts every `tracing` event emitted on the thread it is installed
/// on, and does nothing else.
#[derive(Debug)]
struct EventCounter {
    events: Arc<AtomicU64>,
}

impl EventCounter {
    fn new() -> (Self, Arc<AtomicU64>) {
        let events = Arc::new(AtomicU64::new(0));
        (
            Self {
                events: events.clone(),
            },
            events,
        )
    }
}

impl tracing::Subscriber for EventCounter {
    fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
        tracing::span::Id::from_u64(1)
    }

    fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

    fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

    fn event(&self, _event: &tracing::Event<'_>) {
        self.events.fetch_add(1, Ordering::Relaxed);
    }

    fn enter(&self, _span: &tracing::span::Id) {}

    fn exit(&self, _span: &tracing::span::Id) {}
}

/// A limited invocation writes nothing per invocation anywhere, the
/// daemon log included. One `tracing` line per limited invocation would
/// be one unbounded write per flooded request — the disk pressure the
/// buckets exist to remove, handed back on the cheapest path a caller
/// has. The evidence a flood leaves is the sink's per-bucket count.
#[tokio::test]
async fn a_limited_invocation_emits_no_daemon_log_line() {
    const FLOOD: u32 = 8;
    let settings = VerbRateLimiterSettings {
        admission_burst: 1,
        admission_refill_interval_ms: 600_000,
        predecision_refusal_burst: 1,
        predecision_refusal_refill_interval_ms: 600_000,
    };
    let (_server, _dir, verbs, sink) = limited_harness(&base_fixture(), settings).await;

    // Spend both tokens before the counter is watching: an admitted
    // invocation logs whatever it logs, and that is not what this pins.
    let _refusal = verbs
        .mint(&mint_request("bootroot-decoy", "h1", None))
        .await;
    let _admitted = verbs
        .deregister(&deregister_request("roxyd", "h1", None))
        .await;

    let (counter, events) = EventCounter::new();
    let _guard = tracing::subscriber::set_default(counter);
    for _ in 0..FLOOD {
        verbs
            .mint(&mint_request("bootroot-decoy", "h1", None))
            .await
            .expect_err("a reserved service_name must be refused");
        verbs
            .deregister(&deregister_request("roxyd", "h1", None))
            .await
            .expect_err("a drained admission bucket throttles");
    }

    assert_eq!(
        events.load(Ordering::Relaxed),
        0,
        "a limited invocation must leave the daemon log untouched"
    );
    assert_eq!(
        sink.count(LimiterBucket::PredecisionRefusal) + sink.count(LimiterBucket::Admission),
        u64::from(FLOOD) * 2,
        "the sink counted every limited invocation the log did not"
    );
}

/// Each invocation charges its bucket exactly once. The pure checks run
/// once per invocation and what they produced is carried forward, so an
/// invocation never pays two tokens for one request.
#[tokio::test]
async fn each_invocation_charges_its_bucket_exactly_once() {
    const BURST: u32 = 4;
    let (server, _dir, verbs, sink) = limited_harness(&base_fixture(), refusal_budget(BURST)).await;

    for _ in 0..BURST {
        verbs
            .mint(&mint_request("bootroot-decoy", "h1", None))
            .await
            .expect_err("a reserved service_name must be refused");
    }
    assert_eq!(
        sink.count(LimiterBucket::PredecisionRefusal),
        0,
        "exactly {BURST} tokens cover exactly {BURST} invocations"
    );

    verbs
        .mint(&mint_request("bootroot-decoy", "h1", None))
        .await
        .expect_err("a reserved service_name must be refused");
    assert_eq!(sink.count(LimiterBucket::PredecisionRefusal), 1);
    assert_untouched(&server).await;
}

/// Both verbs hold their own buckets, so draining one verb's refusal
/// budget leaves the other's whole.
#[tokio::test]
async fn the_two_verbs_hold_separate_buckets() {
    let (server, _dir, verbs, sink) = limited_harness(&base_fixture(), refusal_budget(1)).await;

    for _ in 0..3 {
        verbs
            .mint(&mint_request("bootroot-decoy", "h1", None))
            .await
            .expect_err("a reserved service_name must be refused");
    }
    assert_eq!(sink.count(LimiterBucket::PredecisionRefusal), 2);

    let refusal = verbs
        .deregister(&deregister_request("bootroot-decoy", "h1", None))
        .await
        .expect_err("a reserved service_name must be refused");
    assert_eq!(
        sink.count(LimiterBucket::PredecisionRefusal),
        2,
        "the deregister verb's own bucket is still full"
    );
    assert_pair(
        &verbs,
        refusal.context().request_id().as_str(),
        &Asked::new("deregister", "bootroot-decoy", "h1", None),
    );
    assert_untouched(&server).await;
}

/// The limiter is charged before the intent write, so a limited
/// invocation cannot be the amplifier for the exhaustion it prevents:
/// nothing is appended on either bucket.
#[tokio::test]
async fn a_limited_invocation_on_either_bucket_appends_nothing() {
    let settings = VerbRateLimiterSettings {
        admission_burst: 1,
        admission_refill_interval_ms: 600_000,
        predecision_refusal_burst: 1,
        predecision_refusal_refill_interval_ms: 600_000,
    };
    let (server, _dir, verbs, sink) = limited_harness(&base_fixture(), settings).await;

    // Spend both of the deregister verb's buckets: one pre-decision
    // refusal and one admitted invocation that refuses at derivation.
    verbs
        .deregister(&deregister_request("bootroot-decoy", "h1", None))
        .await
        .expect_err("a reserved service_name must be refused");
    verbs
        .deregister(&deregister_request("roxyd", "H1", None))
        .await
        .expect_err("an uppercase host must fail derivation");
    let lines_before = trail(&verbs).len();
    assert_eq!(lines_before, 4, "two admitted invocations, two pairs");

    verbs
        .deregister(&deregister_request("bootroot-decoy", "h1", None))
        .await
        .expect_err("a reserved service_name must be refused");
    verbs
        .deregister(&deregister_request("roxyd", "h1", None))
        .await
        .expect_err("a drained admission bucket throttles");
    assert_eq!(
        trail(&verbs).len(),
        lines_before,
        "neither limited invocation may append"
    );
    assert_eq!(sink.count(LimiterBucket::PredecisionRefusal), 1);
    assert_eq!(sink.count(LimiterBucket::Admission), 1);
    assert_untouched(&server).await;
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

    /// As [`LiveBackend::verbs`], with a limiter the test sizes itself
    /// and the sink that recorded its limited invocations.
    fn verbs_with_sink(
        &self,
        config: RegistrarConfig,
        settings: VerbRateLimiterSettings,
    ) -> (RegistrarVerbs, Arc<RecordingSink>) {
        let sink = RecordingSink::new();
        let verbs = verbs_with_limiter(
            self.client(),
            &self.kv_mount,
            config,
            AuditRecordStore::open_temporary().expect("a temporary audit store"),
            VerbRateLimiter::new(settings, sink.clone()),
        );
        (verbs, sink)
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
    let mint_id = outcome.context().request_id().as_str().to_string();

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

    let removal = verbs
        .deregister(&deregister_request("piglet", &host, Some(1)))
        .await
        .expect("cleanup");

    // The success arms are only reachable with a live backend, so this
    // is where a first mint and an identity removal are held to the
    // pairing rule the refusal arms are held to in the fast tier.
    let minted = assert_pair(
        &verbs,
        &mint_id,
        &Asked::new("mint", "piglet", &host, Some(1)),
    );
    assert_eq!(minted["outcome"]["class"], json!("first_mint"));
    assert_eq!(minted["registration_id"], json!(registration_id));

    let removed = assert_pair(
        &verbs,
        removal.context().request_id().as_str(),
        &Asked::new("deregister", "piglet", &host, Some(1)),
    );
    assert_eq!(removed["outcome"]["class"], json!("identity_removed"));
    assert_eq!(removed["registration_id"], json!(registration_id));
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
    let first_id = first.context().request_id().as_str().to_string();
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
    let second_id = second.context().request_id().as_str().to_string();
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

    let removal = verbs
        .deregister(&deregister_request("roxyd", &host, None))
        .await
        .expect("cleanup");

    // Three invocations, three pairs — and the second one's line names
    // the caller that drove it, not the one before it.
    let minted = assert_pair(&verbs, &first_id, &Asked::new("mint", "roxyd", &host, None));
    assert_eq!(minted["outcome"]["class"], json!("first_mint"));
    let reminted = assert_pair(
        &verbs,
        &second_id,
        &Asked::new("mint", "roxyd", &host, None).by("spiffe://review/other#0001"),
    );
    assert_eq!(reminted["outcome"]["class"], json!("idempotent_remint"));
    assert_eq!(reminted["registration_id"], json!(registration_id));
    let removed = assert_pair(
        &verbs,
        removal.context().request_id().as_str(),
        &Asked::new("deregister", "roxyd", &host, None),
    );
    assert_eq!(removed["outcome"]["class"], json!("identity_removed"));
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

/// The fixture-backed non-injective identity is refused through the binding
/// path without needing the durable `OpenBao` tier: a canned binding response
/// represents the first claim, and the second request must stop at it.
#[tokio::test]
async fn colliding_fixture_identities_refuse_on_the_binding_arm() {
    let fixture = RegistrarConfigFixture::new()
        .with_multiplicity("web", Multiplicity::ManyPerHost)
        .with_multiplicity("aimer-web", Multiplicity::ManyPerHost);
    let (_dir, config) = load_fixture(&fixture);
    let expected_spec = RegistrationSpec {
        cert_group: None,
        reload: ReloadSpec::none(),
    };
    for component in ["web", "aimer-web"] {
        let entry = config
            .component(component)
            .expect("fixture component exists");
        assert_eq!(entry.multiplicity(), Multiplicity::ManyPerHost);
        assert_eq!(entry.spec(), &expected_spec);
    }
    let first_request = MintRequest {
        caller: CallerIdentity::new(CALLER),
        service_name: "web".to_string(),
        host: "h1-aimer".to_string(),
        instance: Some(1),
        spec: requested(&expected_spec),
        wrap_ttl: Duration::minutes(5),
    };
    let second_request = MintRequest {
        caller: CallerIdentity::new(CALLER),
        service_name: "aimer-web".to_string(),
        host: "h1".to_string(),
        instance: Some(1),
        spec: requested(&expected_spec),
        wrap_ttl: Duration::minutes(5),
    };
    let registration_id = "h1-aimer-web-001";
    for request in [&first_request, &second_request] {
        assert_eq!(
            crate::registrar::identity::derive_registration_id(
                Multiplicity::ManyPerHost,
                &request.service_name,
                &request.host,
                request.instance,
            )
            .expect("the fixture identity derives"),
            registration_id
        );
    }

    let server = MockServer::start().await;
    mock_first_mint(&server, registration_id).await;
    let verbs = verbs_with(mock_client(&server), "secret", config);
    let first = verbs
        .mint(&first_request)
        .await
        .expect("first claim succeeds");
    assert_eq!(first.kind(), MintKind::FirstMint);

    let active = BindingRecord::creating("h1-aimer", &requested(&expected_spec))
        .activated(&requested(&expected_spec));
    mock_binding_read(&server, registration_id, &active).await;
    let refusal = verbs
        .mint(&second_request)
        .await
        .expect_err("the second host must be refused by the binding");
    assert!(matches!(
        refusal.error(),
        VerbError::RegistrationIdCollision { stored_host, .. } if stored_host == "h1-aimer"
    ));
    assert_eq!(refusal.context().arm(), ProducingArm::Binding);
    let outcome = assert_pair(
        &verbs,
        refusal.context().request_id().as_str(),
        &Asked::new("mint", "aimer-web", "h1", Some(1)),
    );
    assert_eq!(
        outcome["outcome"]["reason"],
        json!("registration_id_collision")
    );
    assert_eq!(outcome["registration_id"], json!(registration_id));
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

    let outside_id = refusal.context().request_id().as_str().to_string();
    let accepted = verbs
        .mint(&mint_request(&component, &host, Some(1)))
        .await
        .expect("the in-safe-set mint succeeds");
    let accepted_id = accepted.context().request_id().as_str().to_string();

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

    let conflict_id = refusal.context().request_id().as_str().to_string();
    let removal = verbs
        .deregister(&deregister_request(&component, &host, Some(1)))
        .await
        .expect("cleanup");

    // Post-derivation refusals reach further into the verb than any arm
    // the mock-server tier can drive, and each still owes its pair. The
    // stored-spec conflict was driven through a second service, so its
    // line is in that service's own trail.
    let asked = Asked::new("mint", &component, &host, Some(1));
    let outside_line = assert_pair(&verbs, &outside_id, &asked);
    assert_eq!(
        outside_line["outcome"]["reason"],
        json!("service_spec_outside_safe_set")
    );
    assert_eq!(outside_line["registration_id"], json!(registration_id));
    let minted = assert_pair(&verbs, &accepted_id, &asked);
    assert_eq!(minted["outcome"]["class"], json!("first_mint"));
    assert_eq!(minted["registration_id"], json!(registration_id));
    let conflicted = assert_pair(&rewidened, &conflict_id, &asked);
    assert_eq!(
        conflicted["outcome"]["reason"],
        json!("stored_spec_conflict")
    );
    assert_eq!(conflicted["registration_id"], json!(registration_id));
    let removed = assert_pair(
        &verbs,
        removal.context().request_id().as_str(),
        &Asked::new("deregister", &component, &host, Some(1)),
    );
    assert_eq!(removed["outcome"]["class"], json!("identity_removed"));
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

    let swept = assert_pair(
        &verbs,
        outcome.context().request_id().as_str(),
        &Asked::new("deregister", "roxyd", &host, None),
    );
    assert_eq!(
        swept["outcome"]["class"],
        json!("idempotent_already_absent"),
        "an absent-binding sweep is recorded as the idempotent class it is"
    );
    assert_eq!(swept["registration_id"], json!(registration_id));
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

/// Concurrent mints for one identity each produce a correctly paired
/// intent and outcome, and the `first_mint` outcome line precedes every
/// `idempotent_remint` outcome line in the file.
///
/// That ordering is what writing the outcome record **inside** the
/// per-id guard buys: releasing the guard first would let a re-mint
/// change `OpenBao` and land its line ahead of the line describing the
/// claim it superseded. It is a property test rather than a
/// discriminator — an implementation that wrote outside the guard races
/// and may still pass — so the in-guard placement is a code-review
/// criterion as well.
///
/// Intent lines are deliberately **not** ordered here. They are written
/// before stage 1, so concurrent invocations interleave them freely;
/// the trail is paired by `request_id`, not by adjacency.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn concurrent_mints_for_one_identity_write_ordered_outcome_lines() {
    const MINTS: usize = 4;

    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let verbs = Arc::new(backend.verbs(config));

    let mut handles = Vec::new();
    for _ in 0..MINTS {
        let verbs = Arc::clone(&verbs);
        let host = host.clone();
        handles.push(tokio::spawn(async move {
            let outcome = verbs
                .mint(&mint_request("roxyd", &host, None))
                .await
                .expect("every concurrent mint for one identity must succeed");
            (
                outcome.context().request_id().as_str().to_string(),
                outcome.kind(),
            )
        }));
    }
    let mut minted = Vec::new();
    for handle in handles {
        minted.push(handle.await.expect("a mint task must not panic"));
    }

    let firsts = minted
        .iter()
        .filter(|(_, kind)| *kind == MintKind::FirstMint)
        .count();
    assert_eq!(firsts, 1, "exactly one invocation may claim the identity");

    // Every invocation owes a complete pair, whichever arm produced it.
    for (request_id, kind) in &minted {
        let outcome = assert_pair(
            &verbs,
            request_id,
            &Asked::new("mint", "roxyd", &host, None),
        );
        let expected = match kind {
            MintKind::FirstMint => "first_mint",
            MintKind::IdempotentReMint => "idempotent_remint",
        };
        assert_eq!(outcome["outcome"]["class"], json!(expected));
        assert_eq!(outcome["registration_id"], json!(format!("{host}-roxyd")));
    }

    let outcome_classes: Vec<String> = trail(&verbs)
        .into_iter()
        .filter(|line| line["phase"] == json!("outcome"))
        .map(|line| {
            line["outcome"]["class"]
                .as_str()
                .expect("an outcome line names a class")
                .to_string()
        })
        .collect();
    assert_eq!(outcome_classes.len(), MINTS);
    assert_eq!(
        outcome_classes.first().map(String::as_str),
        Some("first_mint"),
        "the claim's outcome line must precede every re-mint's, got {outcome_classes:?}"
    );

    verbs
        .deregister(&deregister_request("roxyd", &host, None))
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

    use super::{
        AuditRecordStore, RegistrarVerbs, VerbRateLimiter, VerbRateLimiterSettings, base_fixture,
        load_fixture, mint_request,
    };
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
        audit_store: &'a AuditRecordStore,
        limiter: &'a VerbRateLimiter,
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
            audit_store,
            limiter,
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
        let store = AuditRecordStore::open_temporary().expect("a temporary audit store");
        let limiter = VerbRateLimiter::with_counting_sink(VerbRateLimiterSettings::default()).0;
        let Err(err) = RegistrarVerbs::internal(&source(
            dir.path(),
            "http://localhost:8200",
            &config,
            &options,
            &policy,
            &store,
            &limiter,
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
        let store = AuditRecordStore::open_temporary().expect("a temporary audit store");
        let limiter = VerbRateLimiter::with_counting_sink(VerbRateLimiterSettings::default()).0;
        let Err(err) = RegistrarVerbs::internal(&source(
            dir.path(),
            "https://localhost:8200",
            &config,
            &options,
            &policy,
            &store,
            &limiter,
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
        let store = AuditRecordStore::open_temporary().expect("a temporary audit store");
        let limiter = VerbRateLimiter::with_counting_sink(VerbRateLimiterSettings::default()).0;
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
            audit_store: &store,
            limiter: &limiter,
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
        let store = AuditRecordStore::open_temporary().expect("a temporary audit store");
        let limiter = VerbRateLimiter::with_counting_sink(VerbRateLimiterSettings::default()).0;
        let Err(err) = RegistrarVerbs::internal(&source(
            dir.path(),
            "https://localhost:8200",
            &config,
            &options,
            &policy,
            &store,
            &limiter,
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
    let store = AuditRecordStore::open_temporary().expect("a temporary audit store");
    let limiter = VerbRateLimiter::with_counting_sink(VerbRateLimiterSettings::default()).0;
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
        audit_store: &store,
        limiter: &limiter,
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

/// The isolation the two buckets exist for, against a live `OpenBao`: a
/// caller that has drained its `predecision_refusal` bucket still gets a
/// real mint performed and recorded on the same connection.
#[tokio::test]
#[ignore = "needs a live OpenBao; run scripts/impl/run-registrar-verbs-e2e.sh"]
async fn a_drained_refusal_bucket_does_not_starve_a_live_mint() {
    let backend = LiveBackend::from_env();
    let host = unique_label("h");
    let (_dir, config) = load_fixture(&base_fixture());
    let (verbs, sink) = backend.verbs_with_sink(config, refusal_budget(1));

    for _ in 0..4 {
        verbs
            .mint(&mint_request("bootroot-decoy", &host, None))
            .await
            .expect_err("a reserved service_name must be refused");
    }
    assert_eq!(sink.count(LimiterBucket::PredecisionRefusal), 3);

    let outcome = verbs
        .mint(&mint_request("roxyd", &host, None))
        .await
        .expect("a flood on the free path must not starve a legitimate mint");
    assert_eq!(outcome.kind(), MintKind::FirstMint);
    assert_eq!(
        sink.count(LimiterBucket::Admission),
        0,
        "the refusal flood must not have spent admission budget"
    );
    let recorded = assert_pair(
        &verbs,
        outcome.context().request_id().as_str(),
        &Asked::new("mint", "roxyd", &host, None),
    );
    assert_eq!(
        recorded["outcome"]["class"],
        json!("first_mint"),
        "{recorded}"
    );
}
