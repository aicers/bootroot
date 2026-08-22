//! Tests for the bootroot-internal credential: the fixed layout, the
//! all-or-none material set, redaction, the exact-allowlist policy, the
//! generated config and the fail-closed refusals.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use tempfile::TempDir;

use super::agent_config::{
    INTERNAL_INSTANCE_ID, internal_agent_invocation, internal_registration_id,
    internal_signal_pattern, upsert_internal_trust,
};
use super::material::{
    AcmeAccountKey, InternalMaterial, MaterialStatus, PrivateKeyPem, load_material,
    material_status, publish_material,
};
use super::{
    ACME_ACCOUNT_FILE, AGENT_CONFIG_FILE, CA_BUNDLE_FILE, CERT_AUTH_ROLE, CHAIN_FILE, INTERNAL_DIR,
    InternalAgentConfigParams, InternalCredential, InternalCredentialError, InternalPaths,
    KEY_FILE, ROOT_FINGERPRINT_FILE, build_registrar_internal_policy, render_internal_agent_config,
    require_https,
};
use crate::registrar::{
    REGISTRAR_INTERNAL_LABEL, RESERVED_SERVICE_NAME_PREFIX, is_reserved_service_name,
    registrar_internal_identity,
};

const KV_MOUNT: &str = "secret";
const DOMAIN: &str = "example.internal";
const HOST: &str = "bootroot-01";
const ROOT_FP: &str = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900";
const OTHER_FP: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const SECRET_KEY_BODY: &str = "SUPERSECRETKEYBYTES";

fn key_pem() -> String {
    format!("-----BEGIN PRIVATE KEY-----\n{SECRET_KEY_BODY}\n-----END PRIVATE KEY-----\n")
}

fn chain_pem() -> String {
    "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n".to_string()
}

fn account_json() -> String {
    "{\"account_key_pkcs8\":\"QUJD\"}".to_string()
}

fn material() -> InternalMaterial {
    InternalMaterial {
        key: PrivateKeyPem::new(key_pem()),
        chain: chain_pem(),
        acme_account: AcmeAccountKey::new(account_json()),
        root_fingerprint: ROOT_FP.to_string(),
    }
}

/// Writes the two non-credential members of the all-or-none set so a
/// test that only cares about the four credential files still presents a
/// complete host.
fn write_companions(paths: &InternalPaths) {
    std::fs::create_dir_all(paths.dir()).expect("create the internal directory");
    std::fs::write(paths.agent_config(), "email = \"a@b\"\n").expect("write the config");
    std::fs::write(paths.ca_bundle(), chain_pem()).expect("write the bundle");
}

async fn provisioned_host() -> (TempDir, InternalPaths) {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    publish_material(&paths, &material())
        .await
        .expect("publish the material");
    write_companions(&paths);
    (dir, paths)
}

fn mode_of(path: &Path) -> u32 {
    std::fs::metadata(path)
        .expect("stat the published file")
        .permissions()
        .mode()
        & 0o777
}

/// The layout is fixed, and every name is spelled in exactly one place.
#[test]
fn the_layout_is_the_fixed_one() {
    let paths = InternalPaths::new(Path::new("/srv/secrets"));
    assert_eq!(paths.dir(), Path::new("/srv/secrets").join(INTERNAL_DIR));
    assert_eq!(paths.key().file_name().expect("name"), KEY_FILE);
    assert_eq!(paths.chain().file_name().expect("name"), CHAIN_FILE);
    assert_eq!(
        paths.acme_account().file_name().expect("name"),
        ACME_ACCOUNT_FILE
    );
    assert_eq!(
        paths.root_fingerprint().file_name().expect("name"),
        ROOT_FINGERPRINT_FILE
    );
    assert_eq!(
        paths.agent_config().file_name().expect("name"),
        AGENT_CONFIG_FILE
    );
    assert_eq!(paths.ca_bundle().file_name().expect("name"), CA_BUNDLE_FILE);
    assert_eq!(paths.all().len(), 6);
}

/// The internal identity is composed through the shared SAN
/// composition, is fixed at instance `001`, and is unmintable through
/// `service add`.
#[test]
fn the_internal_identity_is_the_fixed_reserved_name() {
    assert_eq!(
        registrar_internal_identity(HOST, DOMAIN),
        format!("001.{REGISTRAR_INTERNAL_LABEL}.{HOST}.{DOMAIN}")
    );
    assert!(REGISTRAR_INTERNAL_LABEL.starts_with(RESERVED_SERVICE_NAME_PREFIX));
    assert!(is_reserved_service_name(REGISTRAR_INTERNAL_LABEL));
    assert_eq!(CERT_AUTH_ROLE, REGISTRAR_INTERNAL_LABEL);
    assert_eq!(INTERNAL_INSTANCE_ID, "001");
}

/// The `auth/cert` entry allows this one SAN, so the names it must
/// reject are exactly the ones that differ from it — including the two
/// other reserved registrar names on the same host.
#[test]
fn the_internal_san_collides_with_no_other_leaf_the_deployment_issues() {
    use crate::registrar::identity::compose_san;
    use crate::registrar::{registrar_client_identity, registrar_endpoint_identity};

    let internal = registrar_internal_identity(HOST, DOMAIN);
    for other in [
        // The two other reserved registrar identities.
        registrar_client_identity("001", HOST, DOMAIN),
        registrar_endpoint_identity("001", HOST, DOMAIN),
        // Ordinary service leaves on the same host, including one whose
        // component keyword is a prefix of the reserved label.
        compose_san(Some(1), "roxyd", HOST, DOMAIN),
        compose_san(Some(1), "bootroot-registrar-internals", HOST, DOMAIN),
        // The same identity under a neighbouring host or domain.
        registrar_internal_identity("bootroot-02", DOMAIN),
        registrar_internal_identity(HOST, "other.internal"),
        // A second instance of the internal name, which is never issued:
        // the instance label is fixed at 001.
        compose_san(Some(2), REGISTRAR_INTERNAL_LABEL, HOST, DOMAIN),
    ] {
        assert_ne!(internal, other, "{other} must not match the internal SAN");
    }
}

/// Every refusal this module can produce is safe to log: none of them
/// carries key material, a login token or an ACME secret.
#[test]
fn no_refusal_carries_secret_material() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let errors = vec![
        InternalCredentialError::Absent(paths.dir().into()),
        InternalCredentialError::Partial {
            dir: paths.dir().into(),
            missing: vec![KEY_FILE.to_string()],
        },
        InternalCredentialError::Invalid {
            path: paths.key(),
            reason: "no PEM block labelled `PRIVATE KEY` was found".to_string(),
        },
        InternalCredentialError::PlaintextOpenBaoUrl {
            url: "http://localhost:8200".to_string(),
        },
        InternalCredentialError::RepairRequired {
            stored: ROOT_FP.to_string(),
            active: OTHER_FP.to_string(),
        },
        InternalCredentialError::RootAuthorityRequired {
            policies: vec!["default".to_string()],
        },
        InternalCredentialError::Io {
            operation: "reading",
            path: paths.acme_account(),
            source: std::io::Error::other("boom"),
        },
        InternalCredentialError::OpenBao {
            operation: "authenticating to OpenBao with the internal certificate",
            source: anyhow::anyhow!("OpenBao API error (403 Forbidden)"),
        },
    ];
    for error in errors {
        for rendered in [format!("{error}"), format!("{error:?}")] {
            for secret in [SECRET_KEY_BODY, "account_key_pkcs8", "BEGIN PRIVATE KEY"] {
                assert!(!rendered.contains(secret), "{rendered}");
            }
        }
    }
}

/// A host that never provisioned the credential reports `Absent`, not a
/// partial set: that is what makes the endpoint-disabled case
/// distinguishable from a broken one.
#[test]
fn an_unprovisioned_host_reports_absent() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    assert_eq!(material_status(&paths), MaterialStatus::Absent);
    let err = load_material(&paths).expect_err("absent material must not load");
    assert!(matches!(err, InternalCredentialError::Absent(_)), "{err:?}");
}

#[tokio::test]
async fn a_complete_set_round_trips() {
    let (_dir, paths) = provisioned_host().await;
    assert_eq!(material_status(&paths), MaterialStatus::Present);
    let loaded = load_material(&paths).expect("load the material");
    assert_eq!(loaded, material());
}

/// The set is all-or-none in both directions: removing any one of the
/// six turns a complete host into a typed failure that names it.
#[tokio::test]
async fn any_missing_member_makes_the_set_partial() {
    for name in [
        KEY_FILE,
        CHAIN_FILE,
        ACME_ACCOUNT_FILE,
        ROOT_FINGERPRINT_FILE,
        AGENT_CONFIG_FILE,
        CA_BUNDLE_FILE,
    ] {
        let (_dir, paths) = provisioned_host().await;
        std::fs::remove_file(paths.dir().join(name)).expect("remove one member");
        let status = material_status(&paths);
        assert_eq!(
            status,
            MaterialStatus::Partial(vec![name.to_string()]),
            "{name}"
        );
        let err = load_material(&paths).expect_err("a partial set must not load");
        let rendered = err.to_string();
        assert!(rendered.contains(name), "{name}: {rendered}");
    }
}

#[tokio::test]
async fn invalid_members_fail_with_a_typed_error() {
    let (_dir, paths) = provisioned_host().await;
    std::fs::write(paths.key(), chain_pem()).expect("swap the key for a certificate");
    let err = load_material(&paths).expect_err("a certificate is not a key");
    assert!(
        matches!(err, InternalCredentialError::Invalid { .. }),
        "{err:?}"
    );

    let (_dir, paths) = provisioned_host().await;
    std::fs::write(paths.root_fingerprint(), "not-a-fingerprint\n").expect("write");
    let err = load_material(&paths).expect_err("a malformed fingerprint must not load");
    match err {
        InternalCredentialError::Invalid { path, .. } => {
            assert_eq!(path, paths.root_fingerprint());
        }
        other => panic!("{other:?}"),
    }
}

/// The two secret-bearing files land at `0600`, and are never observable
/// wider because the publish renames a temporary that was created narrow.
#[tokio::test]
async fn secret_members_are_published_at_0600() {
    let (_dir, paths) = provisioned_host().await;
    assert_eq!(mode_of(&paths.key()), 0o600);
    assert_eq!(mode_of(&paths.acme_account()), 0o600);
}

/// A `#[derive(Debug)]` on anything holding the material cannot leak the
/// key or the account key.
#[test]
fn secret_members_redact_themselves() {
    let material = material();
    let rendered = format!("{material:?}");
    assert!(!rendered.contains(SECRET_KEY_BODY), "{rendered}");
    assert!(!rendered.contains("account_key_pkcs8"), "{rendered}");
    assert_eq!(format!("{:?}", material.key), "<redacted>");
    assert_eq!(format!("{:?}", material.acme_account), "<redacted>");
    // The chain and the fingerprint are public certificate data and are
    // deliberately printed.
    assert!(rendered.contains(ROOT_FP), "{rendered}");
}

/// The credential is never used over plaintext, and the refusal happens
/// before any transport is built.
#[test]
fn a_plaintext_openbao_url_is_refused() {
    for url in ["http://localhost:8200", "http://10.0.0.1:8200"] {
        let err = require_https(url).expect_err("plaintext must be refused");
        assert!(
            matches!(err, InternalCredentialError::PlaintextOpenBaoUrl { .. }),
            "{err:?}"
        );
        assert!(err.to_string().contains(url));
    }
    assert!(require_https("https://localhost:8200").is_ok());
}

#[tokio::test]
async fn loading_over_plaintext_never_reaches_the_material() {
    let (dir, _paths) = provisioned_host().await;
    let err = InternalCredential::load(dir.path(), "http://localhost:8200", ROOT_FP)
        .expect_err("plaintext must be refused");
    assert!(
        matches!(err, InternalCredentialError::PlaintextOpenBaoUrl { .. }),
        "{err:?}"
    );
}

/// A root mismatch is reported before any ACME, login or write, and
/// names the repair command.
#[test]
fn a_root_mismatch_returns_repair_required() {
    let (bundle, leaf_material) = real_credential();
    let credential =
        InternalCredential::from_parts("https://localhost:8200", &leaf_material, &bundle)
            .expect("a real leaf and bundle must build the transport");
    assert_eq!(credential.root_fingerprint(), ROOT_FP);
    credential
        .check_active_root(ROOT_FP)
        .expect("the matching root is accepted");
    let err = credential
        .check_active_root(OTHER_FP)
        .expect_err("a mismatched root must be refused");
    match err {
        InternalCredentialError::RepairRequired { stored, active } => {
            assert_eq!(stored, ROOT_FP);
            assert_eq!(active, OTHER_FP);
        }
        other => panic!("{other:?}"),
    }
    assert!(
        err_repair_message().contains("bootroot rotate registrar-internal-credential"),
        "{}",
        err_repair_message()
    );
}

fn err_repair_message() -> String {
    InternalCredentialError::RepairRequired {
        stored: ROOT_FP.to_string(),
        active: OTHER_FP.to_string(),
    }
    .to_string()
}

/// The transport is built from real key material, so a credential whose
/// key does not parse cannot pass for one that does.
#[test]
fn an_unparseable_key_fails_the_transport() {
    let (bundle, _) = real_credential();
    let err = InternalCredential::from_parts("https://localhost:8200", &material(), &bundle)
        .expect_err("a synthetic key must not build a transport");
    assert!(
        matches!(err, InternalCredentialError::OpenBao { .. }),
        "{err:?}"
    );
    // The refusal never quotes the key it failed on.
    let rendered = format!("{err:?}");
    assert!(!rendered.contains(SECRET_KEY_BODY), "{rendered}");
}

/// Issues a self-signed CA and a leaf under it, returning the CA bundle
/// PEM and the internal material that chains to it.
fn real_credential() -> (String, InternalMaterial) {
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let mut ca_params =
        rcgen::CertificateParams::new(vec!["bootroot-ca".to_string()]).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("self-signed ca");

    let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
    let leaf_params =
        rcgen::CertificateParams::new(vec![registrar_internal_identity(HOST, DOMAIN)])
            .expect("leaf params");
    let issuer = rcgen::Issuer::from_params(&ca_params, &ca_key);
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf");

    (
        ca.pem(),
        InternalMaterial {
            key: PrivateKeyPem::new(leaf_key.serialize_pem()),
            chain: format!("{}{}", leaf.pem(), ca.pem()),
            acme_account: AcmeAccountKey::new(account_json()),
            root_fingerprint: ROOT_FP.to_string(),
        },
    )
}

/// The policy permits exactly the verb operations and the three reads,
/// and denies every representative path outside them.
#[test]
fn the_policy_is_an_exact_allowlist() {
    let policy = build_registrar_internal_policy(KV_MOUNT);
    for permitted in [
        "path \"sys/policies/acl/bootroot-service-*\"",
        "path \"auth/approle/role/bootroot-service-*\"",
        "path \"secret/data/bootroot/services/*\"",
        "path \"secret/metadata/bootroot/services/*\"",
        "path \"secret/data/bootroot/ca\"",
        "path \"secret/data/bootroot/responder/hmac\"",
        "path \"secret/data/bootroot/agent/eab\"",
    ] {
        assert!(policy.contains(permitted), "missing {permitted}\n{policy}");
    }
    for denied in [
        // No wildcard over policies or roles: a credential that could
        // author a policy under any name, or bind a role to one, is the
        // hole this whole effort closes.
        "path \"sys/policies/acl/*\"",
        "path \"auth/approle/role/*\"",
        "path \"sys/auth/",
        "path \"auth/token/",
        // The CA core secrets a service credential must never reach.
        "bootroot/stepca/password",
        "bootroot/stepca/db",
        "bootroot/stepca/db_admin",
        // No self-propagation: the internal policy cannot rewrite itself.
        "bootroot-registrar-internal\"",
        "path \"*\"",
        "sudo",
    ] {
        assert!(
            !policy.contains(denied),
            "unexpectedly grants {denied}\n{policy}"
        );
    }
}

/// The policy follows the KV mount it is rendered for; nothing in it is
/// hard-coded to `secret`.
#[test]
fn the_policy_follows_the_configured_kv_mount() {
    let policy = build_registrar_internal_policy("kv-two");
    assert!(
        policy.contains("path \"kv-two/data/bootroot/ca\""),
        "{policy}"
    );
    assert!(!policy.contains("secret/data/"), "{policy}");
}

fn config_params(pins: &[String]) -> InternalAgentConfigParams<'_> {
    InternalAgentConfigParams {
        email: "ops@example.internal",
        server: "https://bootroot-ca:9000/acme/acme/directory",
        domain: DOMAIN,
        hostname: HOST,
        responder_url: "http://bootroot-http01:8080",
        responder_hmac: "hmac-value",
        eab_kid: Some("kid-1"),
        eab_hmac: Some("hmac-1"),
        trusted_ca_sha256: pins,
    }
}

#[test]
fn the_generated_config_names_the_fixed_identity_and_private_trust() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let pins = vec![ROOT_FP.to_string(), OTHER_FP.to_string()];
    let rendered = render_internal_agent_config(&paths, &config_params(&pins));

    let settings: crate::config::Settings = toml_settings(&rendered);
    assert_eq!(settings.profiles.len(), 1);
    let profile = settings.profiles.first().expect("one profile");
    assert_eq!(profile.service_name, REGISTRAR_INTERNAL_LABEL);
    assert_eq!(profile.instance_id, INTERNAL_INSTANCE_ID);
    assert_eq!(profile.hostname, HOST);
    assert_eq!(profile.registration_id, internal_registration_id(HOST));
    assert_eq!(profile.paths.cert, paths.chain());
    assert_eq!(profile.paths.key, paths.key());
    assert_eq!(
        crate::config::profile_domain(&settings, profile),
        registrar_internal_identity(HOST, DOMAIN)
    );

    // The private bundle, never the shared one.
    assert_eq!(
        settings.trust.ca_bundle_path.as_deref(),
        Some(paths.ca_bundle().as_path())
    );
    assert_eq!(settings.trust.trusted_ca_sha256, pins);
    assert_eq!(
        settings.acme.account_key_path.as_deref(),
        Some(paths.acme_account().as_path())
    );
    let eab = settings.eab.expect("the config carries EAB credentials");
    assert_eq!(eab.kid, "kid-1");
    assert_eq!(eab.hmac, "hmac-1");
    assert_eq!(
        settings.server,
        "https://bootroot-ca:9000/acme/acme/directory"
    );
    assert_eq!(settings.acme.http_responder_hmac, "hmac-value");
    // No `[openbao]` section: the internal profile polls nothing.
    assert!(settings.openbao.is_none());
    // The documented invocation is in the file the operator reads.
    assert!(
        rendered.contains(&internal_agent_invocation(&paths)),
        "{rendered}"
    );
}

/// A deployment with no EAB renders no `[eab]` table rather than an
/// empty one, which would fail deserialization.
#[test]
fn the_generated_config_omits_absent_eab() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let params = InternalAgentConfigParams {
        eab_kid: None,
        eab_hmac: None,
        ..config_params(&[])
    };
    let rendered = render_internal_agent_config(&paths, &params);
    assert!(!rendered.contains("[eab]"), "{rendered}");
    assert!(toml_settings(&rendered).eab.is_none());
}

/// A rotation rewrites only the `[trust]` table, leaving the identity,
/// the paths and the ACME settings exactly where they were.
#[test]
fn a_trust_upsert_leaves_the_rest_of_the_config_alone() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let before = render_internal_agent_config(&paths, &config_params(&[ROOT_FP.to_string()]));
    let additive = vec![
        ROOT_FP.to_string(),
        OTHER_FP.to_string(),
        "2".repeat(64),
        "3".repeat(64),
    ];
    let after = upsert_internal_trust(&before, &paths, &additive).expect("upsert");
    let settings = toml_settings(&after);
    assert_eq!(settings.trust.trusted_ca_sha256, additive);
    assert_eq!(
        settings.trust.ca_bundle_path.as_deref(),
        Some(paths.ca_bundle().as_path())
    );
    let profile = settings.profiles.first().expect("one profile");
    assert_eq!(profile.paths.cert, paths.chain());
    assert_eq!(
        settings.acme.account_key_path.as_deref(),
        Some(paths.acme_account().as_path())
    );
}

/// The `pkill` pattern is the fixed config path below the state-recorded
/// secrets directory, and nothing else.
#[test]
fn the_signal_pattern_is_the_fixed_config_path() {
    let secrets = Path::new("/srv/bootroot/secrets");
    assert_eq!(
        internal_signal_pattern(secrets),
        secrets
            .join(INTERNAL_DIR)
            .join(AGENT_CONFIG_FILE)
            .display()
            .to_string()
    );
}

/// Parses a rendered config the way `bootroot-agent` does.
fn toml_settings(rendered: &str) -> crate::config::Settings {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("agent.toml");
    std::fs::write(&path, rendered).expect("write the rendered config");
    crate::config::Settings::from_file(Some(path)).expect("the rendered config must deserialize")
}

/// Certificate-login behaviour: one login per lease window, a fresh one
/// once the cache is dropped, and no `role_id`/`secret_id` anywhere.
mod login {
    use serde_json::json;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{OTHER_FP, ROOT_FP};
    use crate::registrar::internal::{CERT_AUTH_ROLE, InternalCredential, is_expired_token_error};

    const TOKEN: &str = "s.internal-token";

    async fn mock_login(server: &MockServer, lease_secs: u64, expect: u64) {
        Mock::given(method("POST"))
            .and(path("/v1/auth/cert/login"))
            // The request body is the entry name and nothing else: no
            // `role_id`, no `secret_id`, no bearer secret at all.
            .and(body_json(json!({ "name": CERT_AUTH_ROLE })))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "auth": { "client_token": TOKEN, "lease_duration": lease_secs }
            })))
            .expect(expect)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn one_login_serves_a_whole_lease_window() {
        let server = MockServer::start().await;
        mock_login(&server, 3600, 1).await;
        let credential = InternalCredential::for_test(&server.uri(), ROOT_FP).expect("credential");

        for _ in 0..3 {
            credential.authenticated().await.expect("authenticated");
        }
        // `expect(1)` above is asserted when the server drops.
    }

    /// After an expired-token response the cached login is dropped and
    /// the next verb authenticates again, so both verbs continue.
    #[tokio::test]
    async fn an_expired_token_response_forces_a_fresh_login() {
        let server = MockServer::start().await;
        mock_login(&server, 3600, 2).await;
        let credential = InternalCredential::for_test(&server.uri(), ROOT_FP).expect("credential");

        credential.authenticated().await.expect("first login");
        credential
            .note_failure(&anyhow::anyhow!(
                "OpenBao API error (403 Forbidden): denied"
            ))
            .await;
        credential.authenticated().await.expect("second login");
    }

    /// A failure that is not an expired token leaves the cached login
    /// alone: re-authenticating on every transport hiccup would turn one
    /// slow network into a login storm.
    #[tokio::test]
    async fn an_unrelated_failure_keeps_the_cached_login() {
        let server = MockServer::start().await;
        mock_login(&server, 3600, 1).await;
        let credential = InternalCredential::for_test(&server.uri(), ROOT_FP).expect("credential");

        credential.authenticated().await.expect("first login");
        credential
            .note_failure(&anyhow::anyhow!(
                "OpenBao API error (503 Service Unavailable)"
            ))
            .await;
        credential.authenticated().await.expect("cached login");
    }

    /// A lease shorter than the refresh lead is already stale, so the
    /// next acquisition logs in rather than handing out a token that is
    /// about to be rejected.
    #[tokio::test]
    async fn a_lease_inside_the_refresh_lead_is_refreshed_every_time() {
        let server = MockServer::start().await;
        mock_login(&server, 5, 2).await;
        let credential = InternalCredential::for_test(&server.uri(), ROOT_FP).expect("credential");

        credential.authenticated().await.expect("first login");
        credential.authenticated().await.expect("refreshed login");
    }

    #[test]
    fn only_a_403_reads_as_an_expired_token() {
        assert!(is_expired_token_error(&anyhow::anyhow!(
            "OpenBao API error (403 Forbidden): permission denied"
        )));
        for other in [
            "OpenBao API error (503 Service Unavailable)",
            "OpenBao request failed: auth/cert/login",
            "connection refused",
        ] {
            assert!(
                !is_expired_token_error(&anyhow::anyhow!("{other}")),
                "{other}"
            );
        }
        // A fingerprint that happens to contain "403" is not a status.
        assert!(!is_expired_token_error(&anyhow::anyhow!("{OTHER_FP}")));
    }
}

/// The root-authority check every repair runs before it mutates.
mod authority {
    use serde_json::json;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use crate::openbao::OpenBaoClient;
    use crate::registrar::internal::{InternalCredentialError, require_root_authority};

    async fn client_with_policies(server: &MockServer, policies: &[&str]) -> OpenBaoClient {
        Mock::given(method("GET"))
            .and(path("/v1/auth/token/lookup-self"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(json!({ "data": { "policies": policies } })),
            )
            .mount(server)
            .await;
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("token".to_string());
        client
    }

    #[tokio::test]
    async fn a_root_token_is_accepted() {
        let server = MockServer::start().await;
        let client = client_with_policies(&server, &["root"]).await;
        require_root_authority(&client)
            .await
            .expect("root is accepted");
    }

    /// An `AppRole` token — including the runtime-rotate one, which can
    /// write plenty else — is refused with a typed error naming what it
    /// actually carries.
    #[tokio::test]
    async fn an_approle_token_is_refused() {
        let server = MockServer::start().await;
        let client = client_with_policies(&server, &["default", "bootroot-runtime-rotate"]).await;
        let err = require_root_authority(&client)
            .await
            .expect_err("a non-root token must be refused");
        match err {
            InternalCredentialError::RootAuthorityRequired { policies } => {
                assert_eq!(policies, ["default", "bootroot-runtime-rotate"]);
            }
            other => panic!("{other:?}"),
        }
    }
}

/// Live tier: the `auth/cert` contract, against a real `OpenBao`.
///
/// The mocked tests above prove the request *shapes* — which fields go
/// out, and that no token rides along with the login. They cannot prove
/// what the backend does with those fields: a misspelt
/// `allowed_dns_sans`, a `token_no_default_policy` the backend ignores,
/// or a policy body whose paths do not mean what they look like would
/// satisfy every one of them and still leave the daemon with a
/// credential that either cannot log in or can do more than it should.
/// That is what this tier is for, and it is why it needs a real backend
/// rather than a second implementation of `OpenBao`'s ACL engine here.
///
/// The connection details arrive on the environment from
/// `scripts/impl/run-registrar-internal-e2e.sh` and are read, never
/// written.
///
/// Server trust and client trust are separate anchors here, exactly as
/// they are in a deployment: the scenario's `OpenBao` serves its own dev
/// TLS certificate, while the leaves these tests present are signed by a
/// CA the test mints and registers in the entry.
mod live {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{DOMAIN, HOST, ROOT_FP, account_json};
    use crate::openbao::OpenBaoClient;
    use crate::registrar::internal::{
        AcmeAccountKey, CERT_AUTH_MOUNT, CERT_AUTH_ROLE, InternalCredential, InternalMaterial,
        PrivateKeyPem, build_registrar_internal_policy,
    };
    use crate::registrar::{registrar_endpoint_identity, registrar_internal_identity};

    /// Environment variable naming the live `OpenBao`'s HTTPS URL.
    const ENV_URL: &str = "BOOTROOT_INTERNAL_TEST_OPENBAO_URL";
    /// Environment variable carrying that `OpenBao`'s privileged token.
    const ENV_TOKEN: &str = "BOOTROOT_INTERNAL_TEST_OPENBAO_TOKEN";
    /// Environment variable naming the PEM that verifies its **server**
    /// certificate. Unrelated to the CA the entry trusts.
    const ENV_SERVER_CA: &str = "BOOTROOT_INTERNAL_TEST_SERVER_CA";
    /// Environment variable naming the KV v2 mount the policy is scoped
    /// to.
    const ENV_KV_MOUNT: &str = "BOOTROOT_INTERNAL_TEST_KV_MOUNT";

    /// A policy body a derived per-registration write can carry. Its
    /// contents are irrelevant: what is under test is whether the ACL
    /// engine lets the write happen at all.
    const TRIVIAL_POLICY: &str = "path \"secret/data/nothing\" {\n  capabilities = [\"read\"]\n}\n";

    /// The scenario's backend, read out of the environment once per test.
    struct LiveBackend {
        url: String,
        token: String,
        server_ca_pem: String,
        kv_mount: String,
    }

    impl LiveBackend {
        fn from_env() -> Self {
            let read = |name: &str| {
                std::env::var(name).unwrap_or_else(|_| {
                    panic!("{name} must be set; run scripts/impl/run-registrar-internal-e2e.sh")
                })
            };
            let ca_path = read(ENV_SERVER_CA);
            Self {
                url: read(ENV_URL),
                token: read(ENV_TOKEN),
                server_ca_pem: std::fs::read_to_string(&ca_path)
                    .unwrap_or_else(|err| panic!("reading the server CA at {ca_path}: {err}")),
                kv_mount: read(ENV_KV_MOUNT),
            }
        }

        /// A root-token client over the ordinary token-authenticated
        /// transport: server trust only, no client certificate.
        fn root_client(&self) -> OpenBaoClient {
            let http = crate::tls::build_http_client_from_pem(&self.server_ca_pem, &[])
                .expect("a server-trusting transport");
            let mut client = OpenBaoClient::with_client(&self.url, http);
            client.set_token(self.token.clone());
            client
        }

        /// A client-authenticated transport presenting `material`.
        fn cert_client(&self, material: &InternalMaterial) -> OpenBaoClient {
            let http = crate::tls::build_http_client_with_identity(
                &self.server_ca_pem,
                &material.chain,
                material.key.expose(),
            )
            .expect("a client-authenticated transport");
            OpenBaoClient::with_client(&self.url, http)
        }

        /// Mounts `auth/cert` if needed and writes one entry trusting
        /// `ca`, bound to the fixed internal SAN, carrying one freshly
        /// written copy of the real policy body.
        ///
        /// Returns the policy's name, for a caller that needs to name
        /// it again.
        async fn provision_entry(&self, ca: &TestCa, entry: &str) -> String {
            let root = self.root_client();
            root.ensure_cert_auth(CERT_AUTH_MOUNT)
                .await
                .expect("the cert backend must mount");
            let policy = unique("bootroot-internal-policy");
            root.write_policy(&policy, &build_registrar_internal_policy(&self.kv_mount))
                .await
                .expect("the policy must be written");
            root.write_cert_auth_entry(
                CERT_AUTH_MOUNT,
                entry,
                &ca.pem,
                &registrar_internal_identity(HOST, DOMAIN),
                &[policy.as_str()],
                "1h",
            )
            .await
            .expect("the entry must be written");
            policy
        }
    }

    /// Discriminates one test's `OpenBao` artifacts from another's, so
    /// the tests can run in parallel against one backend.
    fn unique(prefix: &str) -> String {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{prefix}-{}-{n}", std::process::id())
    }

    /// One CA, and the leaves signed under it.
    struct TestCa {
        pem: String,
        params: rcgen::CertificateParams,
        key: rcgen::KeyPair,
    }

    impl TestCa {
        fn new() -> Self {
            let key = rcgen::KeyPair::generate().expect("ca key");
            let mut params = rcgen::CertificateParams::new(vec!["bootroot-test-ca".to_string()])
                .expect("params");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let cert = params.self_signed(&key).expect("self-signed ca");
            Self {
                pem: cert.pem(),
                params,
                key,
            }
        }

        /// Material carrying a leaf whose only DNS SAN is `san`.
        fn leaf(&self, san: &str) -> InternalMaterial {
            let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
            let leaf_params =
                rcgen::CertificateParams::new(vec![san.to_string()]).expect("leaf params");
            let issuer = rcgen::Issuer::from_params(&self.params, &self.key);
            let leaf = leaf_params.signed_by(&leaf_key, &issuer).expect("leaf");
            InternalMaterial {
                key: PrivateKeyPem::new(leaf_key.serialize_pem()),
                chain: format!("{}{}", leaf.pem(), self.pem),
                acme_account: AcmeAccountKey::new(account_json()),
                root_fingerprint: ROOT_FP.to_string(),
            }
        }
    }

    /// The credential type itself authenticates at the **fixed** entry
    /// name, over TLS, with no `role_id` and no `secret_id` anywhere —
    /// the acceptance criterion, end to end against a real backend.
    ///
    /// The one test that uses [`CERT_AUTH_ROLE`]; the rest name their
    /// own entries so they can run beside it.
    #[tokio::test]
    #[ignore = "needs a live TLS OpenBao; run scripts/impl/run-registrar-internal-e2e.sh"]
    async fn the_credential_logs_in_at_the_fixed_entry() {
        let backend = LiveBackend::from_env();
        let ca = TestCa::new();
        backend.provision_entry(&ca, CERT_AUTH_ROLE).await;

        let material = ca.leaf(&registrar_internal_identity(HOST, DOMAIN));
        let credential =
            InternalCredential::from_parts(&backend.url, &material, &backend.server_ca_pem)
                .expect("the credential must build over the scenario's server trust");
        let client = credential
            .authenticated()
            .await
            .expect("the certificate login must succeed");
        // Live, not merely issued: the token carries out an operation
        // the allowlist grants.
        client
            .write_policy(&unique("bootroot-service-fixed"), TRIVIAL_POLICY)
            .await
            .expect("the minted token must carry the derived-policy grant");

        // The cached login serves the second acquisition too: the lease
        // window has barely opened, so no second login is made.
        credential
            .authenticated()
            .await
            .expect("the cached login must still serve");
    }

    /// The entry accepts the one fixed SAN and nothing else.
    ///
    /// The refused leaves carry the deployment's *other* registrar name
    /// and an ordinary service name, and both are signed by the very CA
    /// the entry trusts — so what is proved is that the SAN allowlist is
    /// doing the work, not the chain check.
    #[tokio::test]
    #[ignore = "needs a live TLS OpenBao; run scripts/impl/run-registrar-internal-e2e.sh"]
    async fn the_entry_accepts_only_the_fixed_internal_san() {
        let backend = LiveBackend::from_env();
        let ca = TestCa::new();
        let entry = unique("internal-san");
        backend.provision_entry(&ca, &entry).await;

        backend
            .cert_client(&ca.leaf(&registrar_internal_identity(HOST, DOMAIN)))
            .login_cert(CERT_AUTH_MOUNT, &entry)
            .await
            .expect("the fixed internal SAN must authenticate");

        for refused in [
            registrar_endpoint_identity("001", HOST, DOMAIN),
            format!("001.piglet.{HOST}.{DOMAIN}"),
        ] {
            let err = backend
                .cert_client(&ca.leaf(&refused))
                .login_cert(CERT_AUTH_MOUNT, &entry)
                .await
                .expect_err("only the fixed internal SAN may authenticate");
            assert!(
                format!("{err:#}").contains("OpenBao API error"),
                "{refused}: {err:#}"
            );
        }
    }

    /// `token_no_default_policy` is not decoration: without it the
    /// minted token would also carry `default`, and the exact allowlist
    /// is only exact if it is the whole grant.
    ///
    /// The proof is `auth/token/lookup-self`. Nothing in the allowlist
    /// grants it and `default` does, so a token that could look itself
    /// up would be a token carrying `default` — and a token that cannot,
    /// while still exercising an allowlisted path, is one carrying the
    /// allowlist and nothing else. Reading the policy list back would be
    /// the weaker check: it needs the very grant whose absence is the
    /// point.
    #[tokio::test]
    #[ignore = "needs a live TLS OpenBao; run scripts/impl/run-registrar-internal-e2e.sh"]
    async fn the_minted_token_carries_the_allowlist_and_nothing_else() {
        let backend = LiveBackend::from_env();
        let ca = TestCa::new();
        let entry = unique("internal-policies");
        backend.provision_entry(&ca, &entry).await;

        let material = ca.leaf(&registrar_internal_identity(HOST, DOMAIN));
        let mut client = backend.cert_client(&material);
        let login = client
            .login_cert(CERT_AUTH_MOUNT, &entry)
            .await
            .expect("the login must succeed");
        client.set_token(login.client_token);

        let err = client
            .token_self_policies()
            .await
            .expect_err("`default` grants lookup-self, and this token must not carry it");
        assert!(format!("{err:#}").contains("403"), "{err:#}");

        // The same token still does what the allowlist grants, so the
        // refusal above is the absence of `default` rather than a token
        // that never worked.
        client
            .write_policy(&unique("bootroot-service-nodefault"), TRIVIAL_POLICY)
            .await
            .expect("the minted token must carry the derived-policy grant");
    }

    /// The policy body means, to the real ACL engine, what it is meant
    /// to mean: the derived per-registration prefix and the deployment
    /// reads, and nothing beyond them.
    #[tokio::test]
    #[ignore = "needs a live TLS OpenBao; run scripts/impl/run-registrar-internal-e2e.sh"]
    async fn the_policy_permits_the_verb_paths_and_denies_the_rest() {
        let backend = LiveBackend::from_env();
        let ca = TestCa::new();
        let entry = unique("internal-acl");
        backend.provision_entry(&ca, &entry).await;

        let material = ca.leaf(&registrar_internal_identity(HOST, DOMAIN));
        let mut client = backend.cert_client(&material);
        let login = client
            .login_cert(CERT_AUTH_MOUNT, &entry)
            .await
            .expect("the login must succeed");
        client.set_token(login.client_token);

        // Permitted: a derived per-registration policy, under the
        // confined prefix the verbs write beneath.
        let derived = unique("bootroot-service-live");
        client
            .write_policy(&derived, TRIVIAL_POLICY)
            .await
            .expect("the derived per-registration policy must be writable");

        // Denied: the same operation just outside that prefix.
        let err = client
            .write_policy(&unique("bootroot-elsewhere"), TRIVIAL_POLICY)
            .await
            .expect_err("a policy outside the derived prefix must be denied");
        assert!(format!("{err:#}").contains("403"), "{err:#}");

        // Permitted: the CA trust record. It is absent on this
        // scenario's backend, so the answer is "not found" rather than
        // "denied" — which is exactly the distinction being asserted.
        client
            .try_read_kv(&backend.kv_mount, "bootroot/ca")
            .await
            .expect("the CA trust record must be readable");

        // Denied: the CA core secrets a verb has no business reading.
        for denied in ["bootroot/stepca/password", "bootroot/stepca/db_admin"] {
            let err = client
                .try_read_kv(&backend.kv_mount, denied)
                .await
                .expect_err("a path outside the allowlist must be denied");
            assert!(format!("{err:#}").contains("403"), "{denied}: {err:#}");
        }
    }
}
