//! Tests for the daemon-side composition of the registrar request
//! handler: the `state.json` projection, the secrets-directory
//! resolution and the invocation-level failures.
//!
//! Every case runs under `tempfile::tempdir()`; nothing here writes to a
//! fixed path, mutates the process environment or reaches the network.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{
    DaemonInvocation, DaemonShutdown, RegistrarStateProjection, audit_store_is_mount_point,
    audit_store_mount_unit_name, build_registrar_handler, has_distinct_device_ids,
    openbao_duration, read_registrar_state, registrar_secret_id_options,
    resolve_registrar_handler_for_gate, resolve_secrets_dir, run_daemon,
};
use crate::config::{AuditStoreEnforcement, OpenBaoSettings, Settings};
use crate::registrar::endpoint::client::MintReply;
use crate::registrar::endpoint::protocol::{
    EnrollError, ProtocolVersion, RefusalClass, RegisterRequest, RegistrarUnavailableReason,
    WireDeliveryMode, WireServiceSpec,
};
use crate::registrar::fixture::RegistrarConfigFixture;
use crate::registrar::internal::{
    InternalAgentConfigParams, InternalPaths, active_root_cert_path, render_internal_agent_config,
};
use crate::secret::HmacSecret;

/// A `state.json` carrying members the daemon does not know, so the
/// tolerance is exercised rather than assumed.
const EXTRA_MEMBERS: &str = r#""policies": {"a": "b"}, "services": {}, "openbao_bind_addr": "x""#;

fn write_state_file(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("state.json");
    std::fs::write(&path, body).expect("write the state file");
    path
}

fn state_json(openbao_url: &str, kv_mount: &str, secrets_dir: Option<&str>) -> String {
    let recorded = match secrets_dir {
        Some(value) => format!(r#", "secrets_dir": "{value}""#),
        None => String::new(),
    };
    format!(
        r#"{{"openbao_url": "{openbao_url}", "kv_mount": "{kv_mount}"{recorded}, {EXTRA_MEMBERS}}}"#
    )
}

/// Writes the one file `active_root_fingerprint` reads, and returns its
/// digest.
fn write_active_root(secrets_dir: &Path) -> String {
    let key = KeyPair::generate().expect("generate CA key");
    let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
    params
        .distinguished_name
        .push(DnType::CommonName, "Bootroot Test Root");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let cert = params.self_signed(&key).expect("self-signed root");
    let path = active_root_cert_path(secrets_dir);
    std::fs::create_dir_all(path.parent().expect("the certs directory")).expect("mkdir certs");
    std::fs::write(&path, cert.pem()).expect("write the root certificate");
    crate::tls::sha256_hex(cert.der().as_ref())
}

/// Writes a complete internal credential set whose recorded root
/// fingerprint is `root_fingerprint`.
fn write_internal_credential(secrets_dir: &Path, root_fingerprint: &str) {
    let paths = InternalPaths::new(secrets_dir);
    std::fs::create_dir_all(paths.dir()).expect("mkdir the internal directory");

    let key = KeyPair::generate().expect("generate leaf key");
    let mut params = CertificateParams::new(vec!["bootroot-registrar.example.com".to_string()])
        .expect("certificate params");
    params
        .distinguished_name
        .push(DnType::CommonName, "Bootroot Internal Leaf");
    let leaf = params.self_signed(&key).expect("self-signed leaf");

    std::fs::write(paths.key(), key.serialize_pem()).expect("write the leaf key");
    std::fs::write(paths.chain(), leaf.pem()).expect("write the chain");
    std::fs::write(paths.ca_bundle(), leaf.pem()).expect("write the bundle");
    std::fs::write(paths.acme_account(), "{\"key\":\"stub\"}\n").expect("write the account key");
    std::fs::write(paths.root_fingerprint(), format!("{root_fingerprint}\n"))
        .expect("write the root fingerprint");

    let hmac = HmacSecret::from("responder-hmac");
    let rendered = render_internal_agent_config(
        &paths,
        &InternalAgentConfigParams {
            email: "admin@example.com",
            server: "https://ca.example.com/acme/acme/directory",
            domain: "example.com",
            hostname: "bootroot-host",
            responder_url: "http://localhost:8080",
            responder_hmac: &hmac,
            eab_kid: None,
            eab_hmac: None,
            trusted_ca_sha256: &[crate::tls::sha256_hex(leaf.der().as_ref())],
        },
    );
    std::fs::write(paths.agent_config(), rendered).expect("write the internal agent config");
}

/// The whole arrangement one invocation needs, minus whatever the case
/// under test deliberately withholds.
struct Deployment {
    dir: TempDir,
    state_file: PathBuf,
    secrets_dir: PathBuf,
    provisioning: PathBuf,
    audit_dir: PathBuf,
}

impl Deployment {
    /// Lays out a deployment that would build a handler, so a test only
    /// has to break the one thing it is about.
    fn arrange() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let secrets_dir = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets_dir).expect("mkdir secrets");
        let fingerprint = write_active_root(&secrets_dir);
        write_internal_credential(&secrets_dir, &fingerprint);
        let provisioning = RegistrarConfigFixture::new()
            .write_to(dir.path())
            .expect("write the rendered registrar config");
        let audit_dir = dir.path().join("audit-store");
        std::fs::create_dir_all(audit_dir.join("records")).expect("mkdir the audit store");
        let state_file = write_state_file(
            dir.path(),
            &state_json("https://openbao.example:8200", "secret", None),
        );
        Self {
            dir,
            state_file,
            secrets_dir,
            provisioning,
            audit_dir,
        }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    /// Loads a `Settings` whose `[registrar]` table points at this
    /// deployment and whose endpoint is disabled.
    fn settings(&self) -> Settings {
        self.settings_with_endpoint(false)
    }

    /// Loads a `Settings` whose `[registrar]` table points at this
    /// deployment, through the production loader.
    fn settings_with_endpoint(&self, enabled: bool) -> Settings {
        let config = self.path().join("agent.toml");
        std::fs::write(
            &config,
            format!(
                r#"
domain = "example.com"

[acme]
http_responder_url = "http://localhost:8080"
http_responder_hmac = "dev-hmac"

[[profiles]]
registration_id = "edge-proxy"
service_name = "edge-proxy"
instance_id = "001"
hostname = "edge-node-01"

[profiles.paths]
cert = "certs/edge-proxy.pem"
key = "certs/edge-proxy.key"

[registrar]
audit_store_dir = "{store}"
audit_record_dir = "{records}"
provisioning_config_path = "{provisioning}"
state_file = "{state}"

[registrar_endpoint]
enabled = {enabled}
"#,
                store = self.audit_dir.display(),
                records = self.audit_dir.join("records").display(),
                provisioning = self.provisioning.display(),
                state = self.state_file.display(),
            ),
        )
        .expect("write agent.toml");
        Settings::from_required_file(&config).expect("the test configuration loads")
    }
}

fn configure_valid_profile_certificate(settings: &mut Settings, deployment: &Deployment) {
    let certificate = deployment.path().join("current-profile.pem");
    let key = KeyPair::generate().expect("generate profile certificate key");
    let certificate_params = CertificateParams::new(Vec::new()).expect("build profile certificate");
    let certificate_pem = certificate_params
        .self_signed(&key)
        .expect("self-sign profile certificate")
        .pem();
    std::fs::write(&certificate, certificate_pem).expect("write current profile certificate");
    settings.profiles[0].paths.cert = certificate;
}

/// The projection reads exactly three members and tolerates every other
/// one, so the CLI's inventory can grow a field without breaking a
/// daemon that never looks at it.
#[test]
fn the_projection_reads_three_members_and_tolerates_the_rest() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_state_file(
        dir.path(),
        &state_json("https://openbao.example:8200", "kv", Some("/srv/secrets")),
    );

    let state = read_registrar_state(&path).expect("the three members are readable");
    assert_eq!(state.openbao_url, "https://openbao.example:8200");
    assert_eq!(state.kv_mount, "kv");
    assert_eq!(
        state.secrets_dir.as_deref(),
        Some(Path::new("/srv/secrets"))
    );
}

/// The projection derives `Deserialize` and **not** `Serialize`: a
/// serializer here is how a later edit comes to write an operator's
/// state file back out with three fields and lose the rest.
#[test]
fn the_projection_has_no_serialize_impl() {
    let source = include_str!("../daemon.rs");
    let declaration = source
        .split("pub(crate) struct RegistrarStateProjection")
        .next()
        .expect("the projection is declared in this file");
    let derive = declaration
        .rsplit("#[derive(")
        .next()
        .expect("the projection carries a derive");
    assert!(
        !derive.contains("Serialize"),
        "the state-file projection must never gain a Serialize impl: {derive}"
    );
}

/// A successful read leaves the operator's file exactly as it was.
#[test]
fn a_successful_read_leaves_the_state_file_byte_unchanged() {
    let dir = tempfile::tempdir().expect("tempdir");
    let body = state_json("https://openbao.example:8200", "secret", None);
    let path = write_state_file(dir.path(), &body);

    read_registrar_state(&path).expect("the file is readable");
    assert_eq!(
        std::fs::read_to_string(&path).expect("re-read"),
        body,
        "the daemon only reads the deployment's state file"
    );
}

#[test]
fn an_unreadable_state_file_names_its_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("state.json");
    let error = read_registrar_state(&missing).expect_err("an absent state file is a failure");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("registrar.state_file") && rendered.contains("state.json"),
        "the failure must name the key and the path: {rendered}"
    );
}

#[test]
fn a_malformed_state_file_names_its_path() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_state_file(dir.path(), "{ not json");
    let error = read_registrar_state(&path).expect_err("a malformed state file is a failure");
    assert!(
        format!("{error:#}").contains("state.json"),
        "the failure must name the path: {error:#}"
    );
}

#[test]
fn an_absent_or_empty_recorded_member_names_the_member() {
    let dir = tempfile::tempdir().expect("tempdir");
    for (body, member) in [
        (r#"{"kv_mount": "secret"}"#, "openbao_url"),
        (
            r#"{"openbao_url": "   ", "kv_mount": "secret"}"#,
            "openbao_url",
        ),
        (
            r#"{"openbao_url": "https://openbao.example:8200"}"#,
            "kv_mount",
        ),
        (
            r#"{"openbao_url": "https://openbao.example:8200", "kv_mount": ""}"#,
            "kv_mount",
        ),
    ] {
        let path = write_state_file(dir.path(), body);
        let error = read_registrar_state(&path).expect_err("an unusable member is a failure");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains(member),
            "the failure must name {member}: {rendered}"
        );
    }
}

#[test]
fn a_plaintext_recorded_openbao_url_is_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = write_state_file(
        dir.path(),
        &state_json("http://openbao.example:8200", "kv", None),
    );
    let error = read_registrar_state(&path).expect_err("a plaintext URL is a failure");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("openbao_url") && rendered.contains("https://"),
        "the failure must name the member and the scheme it required: {rendered}"
    );
}

/// The three ways a recorded `secrets_dir` can arrive, resolved against
/// the state file's own directory rather than the process working
/// directory — asserted from a test whose working directory is not that
/// directory.
#[test]
fn the_secrets_directory_resolves_against_the_state_files_directory() {
    let dir = tempfile::tempdir().expect("tempdir");
    let state_file = dir.path().join("state.json");
    let cwd = std::env::current_dir().expect("a working directory");
    assert_ne!(
        cwd.as_path(),
        dir.path(),
        "the case is only meaningful when the two differ"
    );

    assert_eq!(
        resolve_secrets_dir(&state_file, None),
        dir.path().join("secrets"),
        "an absent member resolves to `secrets` beside the state file"
    );
    assert_eq!(
        resolve_secrets_dir(&state_file, Some(Path::new("private/keys"))),
        dir.path().join("private/keys"),
        "a relative member resolves against the state file's directory"
    );
    assert_eq!(
        resolve_secrets_dir(&state_file, Some(Path::new("/srv/bootroot/secrets"))),
        PathBuf::from("/srv/bootroot/secrets"),
        "an absolute member is used as recorded"
    );
}

/// The resolved directory is what the fingerprint derivation is handed,
/// so a resolved directory with no root certificate fails at startup
/// with its own path named rather than the recorded one.
#[tokio::test]
async fn a_resolved_secrets_directory_without_a_root_fails_with_its_path_named() {
    let deployment = Deployment::arrange();
    write_state_file(
        deployment.path(),
        &state_json("https://openbao.example:8200", "secret", Some("elsewhere")),
    );
    std::fs::create_dir_all(deployment.path().join("elsewhere")).expect("mkdir elsewhere");

    let settings = deployment.settings();
    let Err(error) = build_registrar_handler(&settings).await else {
        panic!("there is no active root below the resolved directory");
    };
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("elsewhere"),
        "the failure must name the resolved directory: {rendered}"
    );
}

#[tokio::test]
async fn a_resolved_secrets_directory_that_does_not_exist_fails_with_its_path_named() {
    let deployment = Deployment::arrange();
    write_state_file(
        deployment.path(),
        &state_json("https://openbao.example:8200", "secret", Some("absent-dir")),
    );

    let settings = deployment.settings();
    let Err(error) = build_registrar_handler(&settings).await else {
        panic!("a resolved directory that does not exist fails the invocation");
    };
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("absent-dir") && rendered.contains("not a directory"),
        "the failure must name the resolved directory: {rendered}"
    );
}

#[tokio::test]
async fn an_absent_state_file_fails_the_invocation() {
    let deployment = Deployment::arrange();
    std::fs::remove_file(&deployment.state_file).expect("remove the state file");

    let settings = deployment.settings();
    let Err(error) = build_registrar_handler(&settings).await else {
        panic!("an absent state file fails the invocation");
    };
    assert!(
        format!("{error:#}").contains("registrar.state_file"),
        "the failure must name the key: {error:#}"
    );
}

#[tokio::test]
async fn an_absent_provisioning_config_names_the_key_and_the_path() {
    let deployment = Deployment::arrange();
    std::fs::remove_file(&deployment.provisioning).expect("remove the provisioning config");

    let settings = deployment.settings();
    let Err(error) = build_registrar_handler(&settings).await else {
        panic!("an absent provisioning config fails the invocation");
    };
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("registrar.provisioning_config_path")
            && rendered.contains("provisioning.toml"),
        "the failure must name the key and the path: {rendered}"
    );
}

#[tokio::test]
async fn a_digest_mismatched_provisioning_config_names_the_key() {
    let deployment = Deployment::arrange();
    let rendered = RegistrarConfigFixture::new()
        .with_fingerprint(&"0".repeat(64))
        .render();
    std::fs::write(&deployment.provisioning, rendered).expect("rewrite the provisioning config");

    let settings = deployment.settings();
    let Err(error) = build_registrar_handler(&settings).await else {
        panic!("a digest mismatch fails the invocation");
    };
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("registrar.provisioning_config_path"),
        "the failure must name the key: {rendered}"
    );
}

#[tokio::test]
async fn an_absent_internal_credential_names_its_directory() {
    let deployment = Deployment::arrange();
    let internal = InternalPaths::new(&deployment.secrets_dir);
    std::fs::remove_dir_all(internal.dir()).expect("remove the internal credential");

    let settings = deployment.settings();
    let Err(error) = build_registrar_handler(&settings).await else {
        panic!("an absent credential fails the invocation");
    };
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("bootroot-internal credential"),
        "the failure must name the dependency: {rendered}"
    );
}

/// A credential issued under a root the deployment has since retired is
/// refused before any login, any write and any audit file is touched.
#[tokio::test]
async fn a_stale_internal_credential_fails_the_invocation() {
    let deployment = Deployment::arrange();
    write_internal_credential(&deployment.secrets_dir, &"a".repeat(64));

    let settings = deployment.settings();
    let Err(error) = build_registrar_handler(&settings).await else {
        panic!("a superseded root fails the invocation");
    };
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("bootroot-internal credential"),
        "the failure must name the dependency: {rendered}"
    );
}

/// An audit record directory that is not a directory at all is a failure
/// whatever uid the test process runs under, so the case asserts the
/// diagnostic rather than the store's ownership policy.
#[tokio::test]
async fn an_unusable_audit_store_names_the_record_directory() {
    let deployment = Deployment::arrange();
    std::fs::remove_dir_all(deployment.audit_dir.join("records")).expect("remove the records dir");
    std::fs::write(deployment.audit_dir.join("records"), b"not a directory")
        .expect("put a file where the records directory belongs");

    let settings = deployment.settings();
    let Err(error) = build_registrar_handler(&settings).await else {
        panic!("an unusable audit store fails the invocation");
    };
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("audit record store") && rendered.contains("records"),
        "the failure must name the store and its directory: {rendered}"
    );
}

/// Nothing under `src/registrar/` opens, names or knows the path of the
/// deployment state file: the three values arrive as parameters.
#[test]
fn nothing_under_the_registrar_module_names_the_state_file() {
    fn walk(dir: &Path, found: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("the registrar module is readable") {
            let entry = entry.expect("a directory entry");
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                let source = std::fs::read_to_string(&path).expect("a Rust source file");
                if source.contains("state.json") || source.contains("state_file") {
                    found.push(path.display().to_string());
                }
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    walk(&root.join("src/registrar"), &mut found);
    let registrar_module = root.join("src/registrar.rs");
    let source = std::fs::read_to_string(&registrar_module).expect("the registrar module file");
    if source.contains("state.json") || source.contains("state_file") {
        found.push(registrar_module.display().to_string());
    }
    assert!(
        found.is_empty(),
        "the registrar layer must learn nothing about the deployment state file: {found:?}"
    );
}

/// The projection is what reaches the factory, so a member the daemon
/// does not read cannot reach it either.
#[test]
fn the_projection_declares_exactly_three_members() {
    let state: RegistrarStateProjection = serde_json::from_str(&state_json(
        "https://openbao.example:8200",
        "secret",
        Some("secrets"),
    ))
    .expect("the projection deserializes");
    let debug = format!("{state:?}");
    assert!(debug.contains("openbao_url"));
    assert!(debug.contains("kv_mount"));
    assert!(debug.contains("secrets_dir"));
    assert!(
        !debug.contains("policies") && !debug.contains("services"),
        "no other member is carried: {debug}"
    );
}

/// A disabled endpoint loads no provisioning config, opens no audit
/// store, reads no state file and builds no credential.
///
/// Proven twice over: the activation handle is inactive, so the one
/// guard the composition layer has never reaches the build; and a
/// deployment with every dependency missing leaves nothing behind, which
/// a build would not have — as the same settings run through the build
/// show by failing on the first of them.
#[tokio::test]
async fn a_disabled_endpoint_opens_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let audit_dir = dir.path().join("audit-store");
    let state_file = dir.path().join("state.json");
    let provisioning = dir.path().join("provisioning.toml");
    let config = dir.path().join("agent.toml");
    std::fs::write(
        &config,
        format!(
            r#"
domain = "example.com"

[acme]
http_responder_url = "http://localhost:8080"
http_responder_hmac = "dev-hmac"

[[profiles]]
registration_id = "edge-proxy"
service_name = "edge-proxy"
instance_id = "001"
hostname = "edge-node-01"

[profiles.paths]
cert = "certs/edge-proxy.pem"
key = "certs/edge-proxy.key"

[registrar]
audit_store_dir = "{store}"
audit_record_dir = "{records}"
provisioning_config_path = "{provisioning}"
"#,
            store = audit_dir.display(),
            records = audit_dir.join("records").display(),
            provisioning = provisioning.display(),
        ),
    )
    .expect("write agent.toml");

    let settings = Settings::from_required_file(&config).expect("the configuration loads");
    settings
        .validate()
        .expect("a disabled endpoint needs no state_file");
    assert!(!settings.registrar_endpoint.enabled);

    let endpoint = crate::registrar::RegistrarEndpoint::activate(&settings)
        .expect("a disabled endpoint activates to nothing");
    assert!(
        !endpoint.is_active(),
        "the composition layer's one guard never opens for a disabled endpoint"
    );

    // Nothing was created, and a build would have failed on the very
    // first dependency it reached.
    assert!(!audit_dir.exists(), "no audit store directory was created");
    assert!(!state_file.exists(), "no state file was written");
    assert!(
        build_registrar_handler(&settings).await.is_err(),
        "the same settings could not have built a handler, so nothing here did"
    );
    assert!(
        !audit_dir.exists(),
        "even the failed build stops before the audit store"
    );
}

/// The handler is built inside the one guard that opens only for an
/// active endpoint, and nowhere else.
#[test]
fn the_handler_is_built_only_for_an_active_endpoint() {
    let source = include_str!("../daemon.rs");
    let call_sites: Vec<&str> = source
        .match_indices("build_registrar_handler(settings)")
        .map(|(at, _)| &source[at.saturating_sub(160)..at])
        .collect();
    assert_eq!(
        call_sites.len(),
        1,
        "the handler has exactly one call site in the composition layer"
    );
    assert!(
        source
            .split("async fn resolve_registrar_service")
            .nth(1)
            .is_some_and(|resolver| resolver.contains("registrar_endpoint.activated()")),
        "the one call site is inside the active-endpoint guard"
    );
}

/// The daemon-side gate needs only the device-id comparison; its metadata
/// source is deliberately injected at this seam so the test needs no mount.
#[test]
fn the_audit_store_mount_gate_compares_only_device_ids() {
    assert!(has_distinct_device_ids(10, 11));
    assert!(!has_distinct_device_ids(10, 10));
    assert_eq!(
        audit_store_mount_unit_name(Path::new("/var/lib/bootroot/audit-store")),
        "var-lib-bootroot-audit\\x2dstore.mount"
    );
    assert_eq!(
        audit_store_mount_unit_name(Path::new("/store/with space")),
        "store-with\\x20space.mount"
    );

    let source = include_str!("../daemon.rs");
    let resolver = source
        .split("async fn resolve_registrar_service")
        .nth(1)
        .expect("the registrar resolver is present");
    let gate = resolver
        .find("audit_store_mount_gate")
        .expect("the resolver consults the mount gate");
    let handler = resolver
        .find("build_registrar_handler(settings)")
        .expect("the resolver builds the production handler");
    assert!(
        gate < handler,
        "the mount gate precedes every handler dependency"
    );
    assert!(!resolver.contains("/proc/self/mounts"));
    assert!(!resolver.contains("/sys/block"));
}

/// A missing path or a directory on its parent's filesystem is not evidence
/// of the filesystem reserve. The probe is read-only, so neither case creates
/// the configured store before the refusal path takes over.
#[test]
fn the_mount_point_probe_fails_closed_without_creating_the_store() {
    let temp = tempfile::tempdir().expect("temporary store parent");
    let missing_store = temp.path().join("missing-audit-store");
    assert!(!audit_store_is_mount_point(&missing_store));
    assert!(
        !missing_store.exists(),
        "probing a missing store must not create it"
    );

    let plain_store = temp.path().join("plain-audit-store");
    std::fs::create_dir(&plain_store).expect("create a non-mounted store directory");
    assert!(!audit_store_is_mount_point(&plain_store));
}

/// An absent mount selects the refusing handler before any production
/// dependency can open the record store, load a credential or read state.
#[tokio::test]
async fn an_unmounted_store_bypasses_production_handler_construction() {
    let temp = tempfile::tempdir().expect("temporary store parent");
    let store = temp.path().join("audit-store");
    let gate = crate::registrar::AuditStoreMountGate::unmounted_for_test(store.clone());

    let built = resolve_registrar_handler_for_gate(&gate, || async {
        Err(anyhow::anyhow!(
            "the production handler must not be constructed"
        ))
    })
    .await
    .expect("the unmounted store receives a refusing handler instead of an error");

    assert!(
        built.maintenance.is_none(),
        "the refusing handler owns no limiter or audit-store maintenance"
    );
    assert!(
        !store.exists(),
        "selecting the refusal does not create the unmounted store"
    );
}

/// An absent filesystem mount substitutes only the endpoint handler: the
/// accept task still answers callers, while the normal profile and fast-poll
/// daemon duties continue until the invocation is asked to stop.
#[tokio::test(flavor = "current_thread")]
#[allow(clippy::too_many_lines)]
async fn an_unmounted_store_keeps_daemon_duties_running() {
    let (logs, _guard) = crate::registrar::endpoint::test_support::capture_logs();
    let openbao = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/auth/approle/login"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "auth": { "client_token": "test-token" }
        })))
        .mount(&openbao)
        .await;

    let deployment = Deployment::arrange();
    let mut settings = deployment.settings_with_endpoint(true);
    let unmounted_store = deployment.path().join("unmounted-audit-store");
    settings.registrar.audit_store_dir = unmounted_store.clone();
    settings.registrar.audit_record_dir = unmounted_store.join("records");

    configure_valid_profile_certificate(&mut settings, &deployment);

    let role_id = deployment.path().join("role-id");
    let secret_id = deployment.path().join("secret-id");
    std::fs::write(&role_id, "role-id\n").expect("write AppRole role id");
    std::fs::write(&secret_id, "secret-id\n").expect("write AppRole secret id");
    settings.openbao = Some(OpenBaoSettings {
        url: openbao.uri(),
        allow_plaintext_http: false,
        kv_mount: "secret".to_string(),
        role_id_path: role_id,
        secret_id_path: secret_id,
        ca_bundle_path: None,
        fast_poll_interval: Duration::from_secs(60),
        state_path: deployment.path().join("fast-poll-state.json"),
    });

    let endpoint = crate::registrar::endpoint::DaemonTestEndpoint::bind()
        .expect("bind a test endpoint through the production adoption seam");
    let registrar_endpoint = endpoint.registrar_endpoint();
    let shutdown = DaemonShutdown::new();
    let daemon = tokio::spawn(run_daemon(DaemonInvocation {
        settings: Arc::new(settings),
        default_eab: None,
        eab_refresh_path: None,
        config_path: Some(deployment.path().join("agent.toml")),
        insecure_mode: false,
        cli_overrides: crate::config::CliOverrides::default(),
        shutdown: shutdown.clone(),
        registrar_endpoint,
    }));

    let response = endpoint
        .client()
        .mint(RegisterRequest {
            protocol_version: ProtocolVersion::current(),
            service_name: "edge-proxy".to_string(),
            delivery_mode: WireDeliveryMode::LocalFile,
            host: "edge-node-01".to_string(),
            instance: Some(1),
            spec: WireServiceSpec {
                component: "edge-proxy".to_string(),
                service_name: "edge-proxy".to_string(),
                reload: "none".to_string(),
                cert_group: None,
            },
            wrap_ttl: 300,
            idempotency_key: "caller-key".to_string(),
        })
        .await
        .expect("the daemon must answer instead of leaving the activated socket pending");
    let MintReply::Refused(response) = response else {
        panic!("the unmounted store must refuse rather than invoke a verb");
    };
    assert_eq!(response.class, RefusalClass::Permanent);
    assert_eq!(
        response.error,
        Some(EnrollError::RegistrarUnavailable {
            reason: RegistrarUnavailableReason::AuditUnwritable,
        })
    );

    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let profile_checked = logs
                .events()
                .into_iter()
                .any(|event| event.message.contains("certificate still valid"));
            let fast_poll_logged_in = openbao
                .received_requests()
                .await
                .expect("read mock OpenBao requests")
                .iter()
                .any(|request| request.url.path() == "/v1/auth/approle/login");
            if profile_checked && fast_poll_logged_in {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the profile and fast-poll duties must run while the endpoint refuses");

    assert!(
        !daemon.is_finished(),
        "the mount refusal must not return from run_daemon"
    );
    assert!(
        !unmounted_store.exists(),
        "the refusing daemon must not create the unmounted store"
    );
    let startup_diagnostics: Vec<_> = logs
        .events()
        .into_iter()
        .filter(|event| {
            event.message
                == "Registrar endpoint will refuse requests because the audit store is not mounted"
        })
        .collect();
    assert_eq!(
        startup_diagnostics.len(),
        1,
        "the process-lifetime mount verdict emits one startup warning"
    );
    let startup = &startup_diagnostics[0];
    assert_eq!(startup.level, "WARN");
    assert_eq!(
        startup.field("audit_store"),
        unmounted_store.display().to_string()
    );
    assert_eq!(
        startup.field("mount_unit"),
        audit_store_mount_unit_name(&unmounted_store)
    );
    shutdown.stop();
    daemon
        .await
        .expect("the daemon task joins")
        .expect("the mount refusal does not make run_daemon fail");
}

/// Disabling the endpoint leaves the audit-store mount gate entirely out of
/// daemon composition, whether the configured enforcement is filesystem or a
/// plain directory. The profile loop still starts and no missing directory is
/// created while it runs.
#[tokio::test(flavor = "current_thread")]
async fn disabled_endpoint_configurations_do_not_enter_the_mount_refusal_path() {
    for (name, enforcement) in [
        ("filesystem", AuditStoreEnforcement::Filesystem),
        ("directory", AuditStoreEnforcement::Directory),
    ] {
        let (logs, _guard) = crate::registrar::endpoint::test_support::capture_logs();
        let deployment = Deployment::arrange();
        let mut settings = deployment.settings();
        let unused_store = deployment.path().join(format!("unused-{name}-audit-store"));
        settings.registrar.audit_store_enforcement = enforcement;
        settings.registrar.audit_store_dir = unused_store.clone();
        settings.registrar.audit_record_dir = unused_store.join("records");
        configure_valid_profile_certificate(&mut settings, &deployment);

        let shutdown = DaemonShutdown::new();
        let daemon = tokio::spawn(run_daemon(DaemonInvocation {
            settings: Arc::new(settings),
            default_eab: None,
            eab_refresh_path: None,
            config_path: Some(deployment.path().join("agent.toml")),
            insecure_mode: false,
            cli_overrides: crate::config::CliOverrides::default(),
            shutdown: shutdown.clone(),
            registrar_endpoint: crate::registrar::RegistrarEndpoint::default(),
        }));

        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if logs
                    .events()
                    .into_iter()
                    .any(|event| event.message.contains("daemon enabled"))
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the profile daemon remains available while the endpoint is disabled");
        assert!(
            !unused_store.exists(),
            "{name} mode must not probe the audit store"
        );
        assert!(
            logs.events().into_iter().all(|event| {
                event.message
                    != "Registrar endpoint will refuse requests because the audit store is not mounted"
                    && event.message
                        != "Registrar endpoint refused a request because the audit store is not mounted"
            }),
            "{name} mode must not emit an audit-mount diagnostic or refusal"
        );

        shutdown.stop();
        daemon
            .await
            .expect("the disabled daemon task joins")
            .expect("the disabled daemon shuts down cleanly");
    }
}

/// Directory enforcement invokes the ordinary handler builder without probing
/// the audit-store mount or emitting the filesystem-mode startup diagnostic.
///
/// A successful production builder needs root-owned audit directories, which
/// unit tests intentionally cannot create. The production-builder failure
/// test below covers that seam with a real unopenable store; this test holds
/// the mount-gate choice itself to the endpoint-enabled directory contract.
#[tokio::test(flavor = "current_thread")]
async fn an_enabled_directory_endpoint_does_not_select_the_mount_refusal() {
    let (logs, _guard) = crate::registrar::endpoint::test_support::capture_logs();
    let deployment = Deployment::arrange();
    let mut settings = deployment.settings_with_endpoint(true);
    settings.registrar.audit_store_enforcement = AuditStoreEnforcement::Directory;
    let endpoint = crate::registrar::endpoint::DaemonTestEndpoint::bind()
        .expect("bind a test endpoint through the production adoption seam");
    let registrar_endpoint = endpoint.registrar_endpoint();
    let gate = registrar_endpoint
        .audit_store_mount_gate(&settings.registrar, |_| {
            panic!("directory mode must not probe the audit store")
        })
        .expect("the enabled endpoint carries a mount gate");
    let builder_called = Arc::new(AtomicBool::new(false));
    let builder_called_by_future = Arc::clone(&builder_called);
    let Err(error) = resolve_registrar_handler_for_gate(gate, move || async move {
        builder_called_by_future.store(true, Ordering::Relaxed);
        anyhow::bail!("the ordinary production handler builder was reached")
    })
    .await
    else {
        panic!("directory mode must invoke the ordinary production handler builder");
    };
    assert!(builder_called.load(Ordering::Relaxed));
    assert!(format!("{error:#}").contains("ordinary production handler builder was reached"));
    assert!(
        logs.events().into_iter().all(|event| {
            event.message
                != "Registrar endpoint will refuse requests because the audit store is not mounted"
                && event.message
                    != "Registrar endpoint refused a request because the audit store is not mounted"
        }),
        "directory mode must not emit an audit-mount diagnostic or refusal"
    );
}

/// A production audit-store failure remains a daemon failure: directory mode
/// reaches the real builder without consulting the mount predicate, and a
/// regular file cannot become the record directory it needs.
#[tokio::test]
async fn an_unopenable_production_audit_store_stops_the_daemon() {
    let deployment = Deployment::arrange();
    let mut settings = deployment.settings_with_endpoint(true);
    settings.registrar.audit_store_enforcement = AuditStoreEnforcement::Directory;
    std::fs::remove_dir_all(&settings.registrar.audit_record_dir)
        .expect("remove the fixture record directory");
    std::fs::write(&settings.registrar.audit_record_dir, "not a directory")
        .expect("place an unopenable record directory fixture");

    let endpoint = crate::registrar::endpoint::DaemonTestEndpoint::bind()
        .expect("bind a test endpoint through the production adoption seam");
    let error = run_daemon(DaemonInvocation {
        settings: Arc::new(settings),
        default_eab: None,
        eab_refresh_path: None,
        config_path: Some(deployment.path().join("agent.toml")),
        insecure_mode: false,
        cli_overrides: crate::config::CliOverrides::default(),
        shutdown: DaemonShutdown::new(),
        registrar_endpoint: endpoint.registrar_endpoint(),
    })
    .await
    .expect_err("an unopenable production audit store must stop the daemon");
    assert!(
        format!("{error:#}").contains("opening the registrar audit record store at"),
        "the production audit-store failure remains visible: {error:#}"
    );
}

/// The one guard is consulted before `run_daemon` spawns anything, so a
/// dependency it cannot resolve fails the invocation rather than leaving
/// a task, or the adopted socket, behind.
#[test]
fn the_registrar_service_is_resolved_before_anything_is_spawned() {
    let source = include_str!("../daemon.rs");
    let body = source
        .split("pub(crate) async fn run_daemon")
        .nth(1)
        .expect("run_daemon is in this file");
    let resolved_at = body
        .find("resolve_registrar_service(")
        .expect("run_daemon resolves the registrar service");
    let first_spawn = body
        .find("tokio::spawn")
        .expect("run_daemon spawns something");
    let watcher = body
        .find("spawn_shutdown_watcher(")
        .expect("run_daemon spawns the shutdown watcher");
    assert!(
        resolved_at < first_spawn && resolved_at < watcher,
        "the registrar service is resolved before the invocation spawns anything"
    );
}

/// A `SIGHUP` rebuilds the handler from the reloaded settings, because
/// the whole invocation is rebuilt: a `[registrar]` value changed
/// between two loads is the value the second build uses.
#[tokio::test]
async fn a_changed_registrar_value_takes_effect_on_the_next_invocation() {
    let deployment = Deployment::arrange();
    let first = deployment.settings();
    assert_eq!(
        first.registrar.provisioning_config_path,
        deployment.provisioning
    );

    // The reload: the operator repoints the key, and the next
    // invocation's build follows it rather than the value it started
    // with.
    let moved = deployment.path().join("moved-provisioning.toml");
    std::fs::rename(&deployment.provisioning, &moved).expect("move the provisioning config");
    let reloaded = Settings::from_required_file(&deployment.path().join("agent.toml"))
        .expect("the same file still loads");
    let Err(error) = build_registrar_handler(&reloaded).await else {
        panic!("the second invocation follows the reloaded value to a file that is not there");
    };
    assert!(
        format!("{error:#}").contains("provisioning.toml"),
        "the failure names the path the reloaded settings pointed at: {error:#}"
    );

    // `enabled` is the one value a reload may not change, whatever else
    // in the table did.
    let disabled = crate::config::RegistrarEndpointSettings::default();
    let enabled = crate::config::RegistrarEndpointSettings {
        enabled: true,
        ..crate::config::RegistrarEndpointSettings::default()
    };
    crate::config::check_registrar_endpoint_reload(&disabled, &disabled)
        .expect("an unchanged enablement reloads");
    let rejected = crate::config::check_registrar_endpoint_reload(&disabled, &enabled)
        .expect_err("a changed enablement is rejected outright");
    assert!(
        format!("{rejected:#}").contains("registrar_endpoint.enabled"),
        "the rejection names the key: {rejected:#}"
    );
}

/// The state file is read once per invocation rather than cached, so an
/// operator who rewrites `state.json` and sends a `SIGHUP` gets the
/// rewritten values — the same way a changed `[registrar]` key does
/// above.
///
/// Asserted on a failure either way, because `AuditRecordStore::open`
/// requires uid 0 and no production entry point may relax that: the
/// first invocation resolves the secrets directory `arrange` laid down,
/// and only the second one can name a directory that did not exist when
/// it started.
#[tokio::test]
async fn a_rewritten_state_file_takes_effect_on_the_next_invocation() {
    let deployment = Deployment::arrange();
    let settings = deployment.settings();

    let first = match build_registrar_handler(&settings).await {
        Ok(_) => String::new(),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        !first.contains("rewritten-secrets"),
        "the first invocation cannot have seen a value written after it: {first}"
    );

    // The operator repoints the recorded member and reloads. Nothing
    // else changed, so a daemon that cached the file would fail exactly
    // as it just did.
    write_state_file(
        deployment.path(),
        &state_json(
            "https://openbao.example:8200",
            "secret",
            Some("rewritten-secrets"),
        ),
    );

    let Err(error) = build_registrar_handler(&settings).await else {
        panic!("the rewritten secrets directory does not exist, so the build fails");
    };
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("rewritten-secrets"),
        "the second invocation follows the rewritten state file: {rendered}"
    );
}

/// The `secret_id` options the factory is handed come from exactly four
/// keys, and `metadata` is not one of them.
#[test]
fn the_secret_id_options_carry_no_metadata_and_default_to_unlimited_uses() {
    let defaults = crate::config::RegistrarSettings::default();
    let options = registrar_secret_id_options(&defaults);
    assert!(options.metadata.is_none(), "metadata is fixed to None");
    assert_eq!(
        options.num_uses,
        Some(0),
        "an enrolled host logs in again on every renewal, so a single-use credential strands it"
    );
    assert!(
        options.ttl.is_none(),
        "an absent secret_id_ttl leaves the role-level TTL governing"
    );
    assert!(options.token_bound_cidrs.is_none());

    let configured = crate::config::RegistrarSettings {
        secret_id_ttl: Some(std::time::Duration::from_mins(10)),
        secret_id_num_uses: 3,
        secret_id_token_bound_cidrs: Some(vec!["10.0.0.0/8".to_string()]),
        ..crate::config::RegistrarSettings::default()
    };
    let options = registrar_secret_id_options(&configured);
    assert!(options.metadata.is_none(), "no key can set metadata");
    assert_eq!(options.num_uses, Some(3));
    assert_eq!(options.ttl.as_deref(), Some("600s"));
    assert_eq!(
        options.token_bound_cidrs.as_deref(),
        Some(["10.0.0.0/8".to_string()].as_slice())
    );
}

/// The role TTLs are handed over in `OpenBao`'s own `<n>s` spelling,
/// never in the humantime form the operator typed.
#[test]
fn a_configured_duration_is_rendered_in_openbaos_spelling() {
    assert_eq!(
        openbao_duration(std::time::Duration::from_hours(1)),
        "3600s"
    );
    assert_eq!(
        openbao_duration(std::time::Duration::from_hours(24)),
        "86400s"
    );
    assert_eq!(
        openbao_duration(std::time::Duration::from_mins(30)),
        "1800s"
    );
}

/// Every one of the factory's eleven dependencies comes from the one
/// place that owns it.
///
/// Nothing else asserts this. The composition build cannot be driven to
/// success unprivileged — `AuditRecordStore::open` requires uid 0 and no
/// production entry point may relax that — so every case here asserts a
/// failure, and the two role TTLs in particular are both `&str` rendered
/// by the same helper from two adjacent keys. Transposing them would
/// issue every registrar `AppRole` with an hour-long `secret_id_ttl` and
/// a day-long `token_ttl`, and no test above would notice.
#[test]
fn every_factory_dependency_is_wired_to_the_value_that_owns_it() {
    let source = include_str!("../daemon.rs");
    let literal = source
        .split("RegistrarVerbs::internal(&InternalVerbsSource {")
        .nth(1)
        .expect("the composition layer builds the factory's source here")
        .split("})")
        .next()
        .expect("the struct literal ends");
    let fields: Vec<&str> = literal
        .lines()
        .map(str::trim)
        .filter(|line| line.ends_with(','))
        .collect();
    assert_eq!(
        fields,
        vec![
            "secrets_dir: &secrets_dir,",
            "openbao_url: &state.openbao_url,",
            "active_root_fingerprint: &active_root,",
            "kv_mount: &state.kv_mount,",
            "config: &provisioning,",
            "secret_id_options: &secret_id_options,",
            "token_ttl: &openbao_duration(registrar.role_token_ttl),",
            "secret_id_ttl: &openbao_duration(registrar.role_secret_id_ttl),",
            "wrap_ttl_policy: &wrap_ttl_policy,",
            "audit_store: &audit_store,",
            "limiter: &limiter,",
        ],
        "each dependency comes from the state file, the [registrar] key or the built value that \
         owns it — and the two role TTLs are not transposed"
    );
}

/// The daemon composition layer is the crate's only **production** call
/// site of `RegistrarVerbs::internal`. Every other construction goes
/// through `RegistrarVerbs::new`, which is what lets a test drive the
/// real decision procedure against a mock without a test branch in
/// production. The factory's own tests are excluded by name, since a
/// factory nothing tested would be worse.
#[test]
fn the_internal_factory_has_exactly_one_production_call_site() {
    fn is_test_source(path: &Path) -> bool {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "tests.rs" || name.ends_with("_tests.rs"))
    }

    fn walk(dir: &Path, found: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).expect("the source tree is readable") {
            let entry = entry.expect("a directory entry");
            let path = entry.path();
            if path.is_dir() {
                walk(&path, found);
            } else if path.extension().is_some_and(|ext| ext == "rs") && !is_test_source(&path) {
                let source = std::fs::read_to_string(&path).expect("a Rust source file");
                for _ in 0..source.matches("RegistrarVerbs::internal(").count() {
                    found.push(path.display().to_string());
                }
            }
        }
    }

    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut found = Vec::new();
    walk(&root.join("src"), &mut found);
    walk(&root.join("tests"), &mut found);
    assert_eq!(
        found,
        vec![root.join("src/daemon.rs").display().to_string()],
        "the internal factory is called from the composition layer and nowhere else"
    );
}

/// The production handler reads no settings and does no I/O in its
/// constructor: it takes an already-built verb service, an already-built
/// credential and an already-resolved mount, and it carries no
/// `#[cfg(test)]` branch.
#[test]
fn the_production_handler_constructs_from_built_dependencies_only() {
    let source = include_str!("../registrar/endpoint/production.rs");
    let constructor = source
        .split("pub(crate) fn new(")
        .nth(1)
        .expect("the constructor is declared in this file")
        .split("\n    }")
        .next()
        .expect("the constructor body ends");
    assert!(
        constructor.contains("verbs: RegistrarVerbs")
            && constructor.contains("credential: InternalCredential")
            && constructor.contains("kv_mount: String"),
        "the constructor takes built dependencies: {constructor}"
    );
    for forbidden in ["Settings", "load(", "open(", "read(", "await"] {
        assert!(
            !constructor.contains(forbidden),
            "the constructor neither reads settings nor performs I/O ({forbidden}): {constructor}"
        );
    }
    let production_half = source
        .split("#[cfg(test)]")
        .next()
        .expect("the production half precedes the test module");
    assert!(
        !production_half.contains("cfg(test)"),
        "the production type carries no test branch"
    );
}
