//! End-to-end tests for the artifact a `RemoteBootstrap` mint returns.
//!
//! Every case drives the production handler over real verbs, a real
//! internal credential and a real audit store, with `OpenBao` a local
//! mock. What a case asserts is therefore what a caller of the endpoint
//! would observe: the response bytes, the requests `OpenBao` received and
//! the audit trail written — never a value a unit test could have handed
//! the encoder directly.

use std::path::Path;

use base64::Engine as _;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use tempfile::TempDir;
use wiremock::matchers::{method, path as request_path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{ArtifactDeployment, ProductionHandler, mint_request, remote_bootstrap_parts};
use crate::openbao::{OpenBaoClient, SecretIdOptions};
use crate::registrar::audit::AuditRecordStore;
use crate::registrar::config::{Multiplicity, RegistrarConfig, ReloadKind, ReloadSpec};
use crate::registrar::endpoint::frame::Operation;
use crate::registrar::endpoint::handler::RegistrarRequestHandler;
use crate::registrar::endpoint::protocol::{
    RegisterRequest, WireDeliveryMode, decode_ca_anchor, decode_mint_response,
};
use crate::registrar::endpoint::test_support::capture_logs;
use crate::registrar::fixture::{FIXTURE_DOMAIN, RegistrarConfigFixture};
use crate::registrar::identity::{RequestedSpec, derive_registration_id};
use crate::registrar::internal::{InternalCredential, active_root_cert_path};
use crate::registrar::verbs::binding::{BindingRecord, REGISTRAR_BINDING_KV_SUFFIX};
use crate::registrar::verbs::limiter::{
    NoopLimitedInvocationSink, VerbRateLimiter, VerbRateLimiterSettings,
};
use crate::registrar::verbs::outcome::CallerIdentity;
use crate::registrar::verbs::wrap_ttl::WrapTtlPolicy;
use crate::registrar::verbs::{RegistrarVerbs, RegistrarVerbsConfig};
use crate::remote_bootstrap::{
    DEFAULT_HOOK_TIMEOUT_SECS, HookFailurePolicyEntry, PostRenewHookEntry, fingerprints_from_bundle,
};
use crate::service_material::{service_kv_path, service_policy_name, service_role_name};

const KV_MOUNT: &str = "secret";
const HOST: &str = "h1";
const WRAP_TOKEN: &str = "hvs.remote-bootstrap-wrap-token";
const OPENBAO_URL: &str = "https://openbao.advertised.test:8200";
const AGENT_SERVER: &str = "https://stepca.example.test:9000/acme/acme/directory";
const AGENT_RESPONDER_URL: &str = "http://responder.example.test:8080";
const ROXYD_RELOAD: &str = r#"{ kind = "systemd", target = "roxyd.service" }"#;

/// The seven target-path members, in wire order.
const PATH_MEMBERS: [&str; 7] = [
    "agent_config_path",
    "role_id_path",
    "secret_id_path",
    "eab_file_path",
    "profile_cert_path",
    "profile_key_path",
    "ca_bundle_path",
];

struct Harness {
    _dir: TempDir,
    audit: AuditRecordStore,
    handler: ProductionHandler,
}

fn generate_ca(common_name: &str) -> rcgen::Certificate {
    let key = KeyPair::generate().expect("generate CA key");
    let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.self_signed(&key).expect("self-signed CA")
}

fn write_root(secrets_dir: &Path) -> String {
    let root = generate_ca("Bootroot Remote Bootstrap Test Root");
    let path = active_root_cert_path(secrets_dir);
    std::fs::create_dir_all(path.parent().expect("the certs directory")).expect("mkdir certs");
    std::fs::write(&path, root.pem()).expect("write the root certificate");
    crate::tls::sha256_hex(root.der().as_ref())
}

/// Builds the production handler the way the daemon does, over real
/// verbs and a real credential pointed at `server`.
fn harness(server: &MockServer) -> Harness {
    let dir = tempfile::tempdir().expect("tempdir");
    let config_path = RegistrarConfigFixture::new()
        .write_to(dir.path())
        .expect("write the rendered registrar config");
    let config = RegistrarConfig::load(&config_path).expect("the fixture must load");
    let mut client = OpenBaoClient::new(&server.uri()).expect("client");
    client.set_token("test-token".to_string());
    let audit = AuditRecordStore::open_temporary().expect("a temporary audit store");
    let verbs = RegistrarVerbs::new(RegistrarVerbsConfig {
        client,
        kv_mount: KV_MOUNT.to_string(),
        config,
        secret_id_options: SecretIdOptions::default(),
        token_ttl: "3600s".to_string(),
        secret_id_ttl: "86400s".to_string(),
        wrap_ttl_policy: WrapTtlPolicy::new(time::Duration::minutes(30)).expect("policy maximum"),
        audit_store: audit.clone(),
        limiter: VerbRateLimiter::new(
            VerbRateLimiterSettings::default(),
            std::sync::Arc::new(NoopLimitedInvocationSink),
        ),
    });
    let secrets_dir = dir.path().join("secrets");
    let fingerprint = write_root(&secrets_dir);
    let credential = InternalCredential::for_test(&server.uri(), &secrets_dir, &fingerprint)
        .expect("the harness credential");
    let handler = ProductionHandler::new(
        verbs,
        credential,
        KV_MOUNT.to_string(),
        ArtifactDeployment {
            openbao_url: OPENBAO_URL.to_string(),
            agent_server: AGENT_SERVER.to_string(),
            agent_responder_url: AGENT_RESPONDER_URL.to_string(),
        },
    );
    Harness {
        _dir: dir,
        audit,
        handler,
    }
}

/// Mounts the login, the anchor read and a first mint's issuance for
/// `registration_id`, and returns the anchor's PEM.
async fn mock_first_mint(server: &MockServer, registration_id: &str) -> String {
    Mock::given(method("POST"))
        .and(request_path("/v1/auth/cert/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": { "client_token": "s.internal-token", "lease_duration": 900 }
        })))
        .mount(server)
        .await;
    let anchor = generate_ca("Deployment CA");
    Mock::given(method("GET"))
        .and(request_path(format!("/v1/{KV_MOUNT}/data/bootroot/ca")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "data": {
                "trusted_ca_sha256": [crate::tls::sha256_hex(anchor.der().as_ref())],
                "ca_bundle_pem": anchor.pem(),
            }}
        })))
        .mount(server)
        .await;

    let role_name = service_role_name(registration_id);
    let binding_path = service_kv_path(registration_id, REGISTRAR_BINDING_KV_SUFFIX);
    Mock::given(method("POST"))
        .and(request_path(format!("/v1/{KV_MOUNT}/data/{binding_path}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "version": 1 }
        })))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(request_path(format!(
            "/v1/sys/policies/acl/{}",
            service_policy_name(registration_id)
        )))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(request_path(format!("/v1/auth/approle/role/{role_name}")))
        .respond_with(ResponseTemplate::new(204))
        .mount(server)
        .await;
    Mock::given(method("GET"))
        .and(request_path(format!(
            "/v1/auth/approle/role/{role_name}/role-id"
        )))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "data": { "role_id": "role-id-1" } })),
        )
        .mount(server)
        .await;
    Mock::given(method("POST"))
        .and(request_path(format!(
            "/v1/auth/approle/role/{role_name}/secret-id"
        )))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "wrap_info": {
                "token": WRAP_TOKEN,
                "ttl": 300,
                "creation_time": "2026-08-23T12:00:00Z",
                "creation_path": format!("auth/approle/role/{role_name}/secret-id"),
            }
        })))
        .mount(server)
        .await;
    anchor.pem()
}

/// Answers the binding read with an active binding for `spec`, so the
/// next mint is an idempotent re-mint.
async fn mock_active_binding(server: &MockServer, registration_id: &str, spec: &RequestedSpec) {
    let binding_path = service_kv_path(registration_id, REGISTRAR_BINDING_KV_SUFFIX);
    let active = BindingRecord::creating(HOST, spec).activated(spec);
    Mock::given(method("GET"))
        .and(request_path(format!("/v1/{KV_MOUNT}/data/{binding_path}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": { "data": active.encode().expect("the active binding encodes") }
        })))
        .mount(server)
        .await;
}

/// Seven distinct absolute paths under `root`, keyed by member.
fn target_paths(root: &str) -> serde_json::Map<String, serde_json::Value> {
    PATH_MEMBERS
        .iter()
        .map(|member| {
            (
                (*member).to_string(),
                serde_json::Value::String(format!("{root}/{member}")),
            )
        })
        .collect()
}

/// A register payload for `service_name` on [`HOST`].
fn payload(
    delivery_mode: &str,
    service_name: &str,
    instance: Option<u32>,
    reload: &str,
    cert_group: Option<&str>,
    paths: &serde_json::Map<String, serde_json::Value>,
) -> serde_json::Value {
    let mut spec = serde_json::json!({
        "component": service_name,
        "service_name": service_name,
        "reload": reload,
    });
    if let Some(cert_group) = cert_group {
        spec["cert_group"] = serde_json::json!(cert_group);
    }
    let mut value = serde_json::json!({
        "protocol_version": 1,
        "service_name": service_name,
        "delivery_mode": delivery_mode,
        "host": HOST,
        "spec": spec,
        "wrap_ttl": 300,
        "idempotency_key": "key",
    });
    if let Some(instance) = instance {
        value["instance"] = serde_json::json!(instance);
    }
    let members = value.as_object_mut().expect("the payload is an object");
    for (member, path) in paths {
        members.insert(member.clone(), path.clone());
    }
    value
}

fn roxyd_payload(paths: &serde_json::Map<String, serde_json::Value>) -> serde_json::Value {
    payload("RemoteBootstrap", "roxyd", None, ROXYD_RELOAD, None, paths)
}

async fn mint(harness: &Harness, payload: &serde_json::Value) -> Option<Vec<u8>> {
    harness
        .handler
        .handle(
            Operation::Mint,
            &serde_json::to_vec(payload).expect("the payload encodes"),
            CallerIdentity::new("registrar-client:001.bootroot-registrar.h1.example.internal"),
        )
        .await
        .ok()
}

/// The decoded artifact a response carries, as JSON and as its bytes.
fn artifact_of(response: &[u8]) -> (serde_json::Value, Vec<u8>) {
    let decoded = decode_mint_response(response).expect("the mint response decodes");
    let bytes = decoded
        .material
        .bootstrap_artifact()
        .expect("a RemoteBootstrap mint carries the artifact")
        .to_vec();
    (
        serde_json::from_slice(&bytes).expect("the artifact is JSON"),
        bytes,
    )
}

fn raw(response: &[u8]) -> serde_json::Value {
    serde_json::from_slice(response).expect("the response is JSON")
}

async fn secret_id_issuances(server: &MockServer) -> usize {
    server
        .received_requests()
        .await
        .expect("the mock records requests")
        .iter()
        .filter(|request| {
            request.method.as_str() == "POST" && request.url.path().ends_with("/secret-id")
        })
        .count()
}

/// Everything `OpenBao` received and the audit trail holds, as text.
async fn everything_recorded(server: &MockServer, audit: &AuditRecordStore) -> String {
    let mut recorded = std::fs::read_to_string(audit.active_path()).unwrap_or_default();
    for request in server
        .received_requests()
        .await
        .expect("the mock records requests")
    {
        recorded.push_str(request.url.as_str());
        recorded.push_str(&String::from_utf8_lossy(&request.body));
    }
    recorded
}

/// The acceptance case: every artifact member equals its source, the
/// seven paths byte for byte, and the mint issued one wrapped
/// `secret_id` which both the material and the artifact carry.
#[tokio::test]
async fn a_remote_bootstrap_mint_returns_the_artifact_its_sources_determine() {
    let (logs, _guard) = capture_logs();
    let server = MockServer::start().await;
    let registration_id = "h1-roxyd";
    let anchor_pem = mock_first_mint(&server, registration_id).await;
    let harness = harness(&server);
    // Unusual but absolute spellings, to show nothing normalizes them.
    let mut paths = target_paths("/opt/roxyd");
    paths.insert(
        "agent_config_path".to_string(),
        serde_json::json!("/etc//roxyd/./agent config\u{e9}.toml"),
    );

    let response = mint(&harness, &roxyd_payload(&paths))
        .await
        .expect("the mint answers");
    let (artifact, bytes) = artifact_of(&response);
    let wire = raw(&response);
    let material = &wire["material"];

    assert_eq!(artifact["schema_version"], 5);
    for member in PATH_MEMBERS {
        assert_eq!(artifact[member], paths[member], "{member} is copied");
    }
    assert_eq!(
        artifact["agent_config_path"].as_str().map(str::as_bytes),
        Some("/etc//roxyd/./agent config\u{e9}.toml".as_bytes())
    );
    assert_eq!(artifact["openbao_url"], OPENBAO_URL);
    assert_eq!(artifact["kv_mount"], KV_MOUNT);
    assert_eq!(artifact["registration_id"], wire["registration_id"]);
    assert_eq!(artifact["registration_id"], registration_id);
    assert_eq!(artifact["service_name"], "roxyd");
    let anchor = decode_ca_anchor(material["ca_anchor"].as_str().expect("ca_anchor"))
        .expect("the anchor decodes");
    assert_eq!(artifact["ca_bundle_pem"], anchor.ca_bundle_pem.as_str());
    assert_eq!(anchor.ca_bundle_pem, anchor_pem);
    assert_eq!(
        artifact["trusted_ca_sha256"],
        serde_json::json!(fingerprints_from_bundle(&anchor.ca_bundle_pem))
    );
    assert!(artifact.get("agent_email").is_none());
    assert_eq!(artifact["agent_server"], AGENT_SERVER);
    assert_eq!(artifact["agent_responder_url"], AGENT_RESPONDER_URL);
    assert_eq!(artifact["agent_domain"], FIXTURE_DOMAIN);
    assert_eq!(artifact["profile_hostname"], HOST);
    assert_eq!(
        artifact["profile_instance_id"], "001",
        "a request without instance carries the SAN's default label"
    );
    assert_eq!(
        artifact["post_renew_hooks"],
        serde_json::json!([{
            "command": "systemctl",
            "args": ["reload", "roxyd.service"],
            "timeout_secs": 30,
            "on_failure": "continue",
        }])
    );
    assert_eq!(artifact["wrap_token"], material["wrapped_secret_id"]);
    assert_eq!(artifact["wrap_token"], WRAP_TOKEN);
    assert_eq!(artifact["wrap_expires_at"], material["expires_at"]);
    assert!(artifact.get("cert_group_gid").is_none());
    assert_eq!(
        secret_id_issuances(&server).await,
        1,
        "the artifact reuses the one wrapped secret_id the mint issued"
    );

    // `service add`'s byte form: pretty-printed, members in order.
    let text = String::from_utf8(bytes.clone()).expect("UTF-8");
    assert!(text.starts_with("{\n  \"schema_version\": 5,\n  \"openbao_url\""));

    // Neither the token nor the artifact reaches a diagnostic.
    let decoded = decode_mint_response(&response).expect("decodes");
    let debug = format!("{decoded:?}");
    let encoded_artifact = base64::engine::general_purpose::STANDARD.encode(&bytes);
    assert!(!debug.contains(WRAP_TOKEN), "{debug}");
    assert!(!debug.contains(&encoded_artifact), "{debug}");
    for event in logs.events() {
        let rendered = format!("{} {:?}", event.message, event.fields);
        assert!(!rendered.contains(WRAP_TOKEN), "{rendered}");
        assert!(!rendered.contains(&encoded_artifact), "{rendered}");
        assert!(!rendered.contains("schema_version"), "{rendered}");
    }
}

/// A many-per-host component's instance becomes the three-digit label,
/// and its rendered certificate group the artifact's gid.
#[tokio::test]
async fn a_many_per_host_mint_carries_its_instance_label_and_group() {
    let server = MockServer::start().await;
    let registration_id =
        derive_registration_id(Multiplicity::ManyPerHost, "piglet", HOST, Some(2))
            .expect("the id derives");
    mock_first_mint(&server, &registration_id).await;
    let harness = harness(&server);

    let response = mint(
        &harness,
        &payload(
            "RemoteBootstrap",
            "piglet",
            Some(2),
            r#"{ kind = "docker-restart", target = "piglet" }"#,
            Some("3001"),
            &target_paths("/srv/piglet-2"),
        ),
    )
    .await
    .expect("the mint answers");
    let (artifact, _) = artifact_of(&response);
    assert_eq!(artifact["registration_id"], registration_id.as_str());
    assert_eq!(artifact["profile_instance_id"], "002");
    assert_eq!(artifact["cert_group_gid"], 3001);
    assert_eq!(
        artifact["post_renew_hooks"],
        serde_json::json!([{
            "command": "docker",
            "args": ["restart", "piglet"],
            "timeout_secs": 30,
            "on_failure": "continue",
        }])
    );
}

/// Each reload kind maps onto exactly the hook `service add
/// --reload-style` installs for it — the entries its own tests pin.
#[test]
fn each_reload_kind_maps_to_the_service_add_preset() {
    let preset = |command: &str, verb: &str, target: &str| {
        vec![PostRenewHookEntry {
            command: command.to_string(),
            args: vec![verb.to_string(), target.to_string()],
            timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
            on_failure: HookFailurePolicyEntry::Continue,
        }]
    };
    let cases = [
        (r#"{ kind = "none" }"#, Vec::new()),
        (
            r#"{ kind = "systemd", target = "nginx" }"#,
            preset("systemctl", "reload", "nginx"),
        ),
        (
            r#"{ kind = "sighup", target = "nginx" }"#,
            preset("pkill", "-HUP", "nginx"),
        ),
        (
            r#"{ kind = "docker-restart", target = "nginx" }"#,
            preset("docker", "restart", "nginx"),
        ),
    ];
    for (reload, expected) in cases {
        let wire: RegisterRequest = serde_json::from_value(payload(
            "RemoteBootstrap",
            "roxyd",
            Some(42),
            reload,
            None,
            &target_paths("/t"),
        ))
        .expect("the payload decodes");
        let caller = CallerIdentity::new("test");
        let request =
            mint_request(&wire, caller.clone()).unwrap_or_else(|_| panic!("{reload} converts"));
        let parts = remote_bootstrap_parts(&wire, &request, &caller)
            .unwrap_or_else(|_| panic!("{reload} maps"))
            .expect("a RemoteBootstrap request yields parts");
        assert_eq!(parts.post_renew_hooks, expected, "{reload}");
        assert_eq!(parts.profile_instance_id, "042");
    }
}

/// Every payload fault is refused before the verb: no response bytes,
/// nothing sent to `OpenBao` — not even the login or the anchor read —
/// and no audit record.
#[tokio::test]
async fn unusable_target_paths_and_reloads_are_refused_before_the_verb() {
    let server = MockServer::start().await;
    mock_first_mint(&server, "h1-roxyd").await;
    let harness = harness(&server);
    let complete = target_paths("/opt/roxyd");

    let mut cases: Vec<(String, serde_json::Value)> = Vec::new();
    for member in PATH_MEMBERS {
        let mut missing = complete.clone();
        missing.remove(member);
        cases.push((
            format!("RemoteBootstrap without {member}"),
            roxyd_payload(&missing),
        ));

        let mut one = serde_json::Map::new();
        one.insert(member.to_string(), serde_json::json!("/opt/one"));
        cases.push((
            format!("LocalFile with {member}"),
            payload("LocalFile", "roxyd", None, ROXYD_RELOAD, None, &one),
        ));

        for (what, value) in [
            ("relative", "opt/relative"),
            ("empty", ""),
            ("NUL-carrying", "/opt/nul\0byte"),
        ] {
            let mut bad = complete.clone();
            bad.insert(member.to_string(), serde_json::json!(value));
            cases.push((format!("{what} {member}"), roxyd_payload(&bad)));
        }
    }
    let mut duplicate = complete.clone();
    duplicate.insert(
        "profile_key_path".to_string(),
        complete["profile_cert_path"].clone(),
    );
    cases.push(("two equal paths".to_string(), roxyd_payload(&duplicate)));
    cases.push((
        "a sighup target containing /".to_string(),
        payload(
            "RemoteBootstrap",
            "roxyd",
            None,
            r#"{ kind = "sighup", target = "/usr/sbin/roxyd" }"#,
            None,
            &complete,
        ),
    ));

    for (what, payload) in &cases {
        assert!(
            mint(&harness, payload).await.is_none(),
            "{what} must be refused with no response bytes"
        );
    }
    assert!(
        server
            .received_requests()
            .await
            .expect("the mock records requests")
            .is_empty(),
        "nothing is read, created or recorded for a refused payload"
    );
    assert_eq!(
        std::fs::read_to_string(harness.audit.active_path()).unwrap_or_default(),
        "",
        "a payload fault writes no audit record"
    );
}

/// A `LocalFile` mint carries no paths, returns no artifact, and its
/// `material` is the four-member form.
#[tokio::test]
async fn a_local_file_mint_returns_no_artifact() {
    let server = MockServer::start().await;
    mock_first_mint(&server, "h1-roxyd").await;
    let harness = harness(&server);

    let response = mint(
        &harness,
        &payload(
            "LocalFile",
            "roxyd",
            None,
            ROXYD_RELOAD,
            None,
            &serde_json::Map::new(),
        ),
    )
    .await
    .expect("the mint answers");
    let wire = raw(&response);
    let mut members: Vec<&str> = wire["material"]
        .as_object()
        .expect("material is an object")
        .keys()
        .map(String::as_str)
        .collect();
    members.sort_unstable();
    assert_eq!(
        members,
        ["ca_anchor", "expires_at", "role_id", "wrapped_secret_id"]
    );
    assert!(
        decode_mint_response(&response)
            .expect("decodes")
            .material
            .bootstrap_artifact()
            .is_none()
    );
    assert_eq!(secret_id_issuances(&server).await, 1);
}

/// The paths are the target owner's and not the identity's: nothing
/// sent to `OpenBao` — the binding record included — and nothing in the
/// audit trail carries one, and a re-mint of the active binding with
/// different paths succeeds and returns the new ones.
#[tokio::test]
async fn paths_are_never_recorded_and_a_remint_returns_new_ones() {
    let server = MockServer::start().await;
    let registration_id = "h1-roxyd";
    mock_first_mint(&server, registration_id).await;
    let harness = harness(&server);

    let first = mint(&harness, &roxyd_payload(&target_paths("/first-target")))
        .await
        .expect("the first mint answers");
    assert_eq!(raw(&first)["outcome"], "first_mint");
    let recorded = everything_recorded(&server, &harness.audit).await;
    assert!(
        recorded.contains(registration_id),
        "the records under inspection are the ones this mint wrote"
    );
    assert!(
        !recorded.contains("/first-target"),
        "no path reaches OpenBao or the audit trail: {recorded}"
    );

    let spec = RequestedSpec {
        component: Some("roxyd".to_string()),
        service_name: Some("roxyd".to_string()),
        reload: ReloadSpec::new(ReloadKind::Systemd, "roxyd.service"),
        cert_group: None,
    };
    mock_active_binding(&server, registration_id, &spec).await;
    let second_paths = target_paths("/second-target");
    let second = mint(&harness, &roxyd_payload(&second_paths))
        .await
        .expect("a re-mint with different paths succeeds");
    assert_eq!(raw(&second)["outcome"], "idempotent_remint");
    let (artifact, _) = artifact_of(&second);
    for member in PATH_MEMBERS {
        assert_eq!(artifact[member], second_paths[member], "{member}");
    }
    let recorded = everything_recorded(&server, &harness.audit).await;
    assert!(!recorded.contains("/first-target"), "{recorded}");
    assert!(!recorded.contains("/second-target"), "{recorded}");
}

/// The request shape the tests above build is the one the codec
/// decodes, so a payload fault they exercise is the handler's refusal
/// and not a decode failure.
#[test]
fn the_payloads_above_decode_before_they_are_refused() {
    let mut relative = target_paths("/opt");
    relative.insert("role_id_path".to_string(), serde_json::json!("relative"));
    let wire: RegisterRequest = serde_json::from_value(roxyd_payload(&relative))
        .expect("a relative path is still a string the codec carries");
    assert_eq!(wire.delivery_mode, WireDeliveryMode::RemoteBootstrap);
    assert_eq!(wire.target_paths.role_id_path.as_deref(), Some("relative"));
}
