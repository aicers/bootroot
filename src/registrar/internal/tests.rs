//! Tests for the bootroot-internal credential: the fixed layout, the
//! all-or-none material set, redaction, the exact-allowlist policy, the
//! generated config and the fail-closed refusals.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::sync::LazyLock;

use tempfile::TempDir;

use super::agent_config::{
    INTERNAL_INSTANCE_ID, internal_agent_invocation, internal_registration_id,
    internal_signal_pattern, load_internal_config, upsert_internal_trust,
};
use super::material::{
    AcmeAccountKey, InternalMaterial, MaterialStatus, PrivateKeyPem, SET_FILES, is_protected,
    load_material, material_status, publish_material,
};
use super::{
    ACME_ACCOUNT_FILE, AGENT_CONFIG_FILE, CA_BUNDLE_FILE, CERT_AUTH_ROLE, CHAIN_FILE, INTERNAL_DIR,
    InternalAgentConfigParams, InternalCredential, InternalCredentialError, InternalPaths,
    KEY_FILE, ROOT_FINGERPRINT_FILE, active_root_cert_path, active_root_fingerprint,
    build_registrar_internal_policy, render_internal_agent_config, require_https,
};
use crate::fs_util::KEY_FILE_MODE;
use crate::registrar::{
    REGISTRAR_INTERNAL_LABEL, RESERVED_SERVICE_NAME_PREFIX, is_reserved_service_name,
    registrar_internal_identity,
};
use crate::secret::HmacSecret;

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

/// The generated config, exactly as `init` renders it for this layout.
///
/// The loader holds the config to the generator's invariants, so a
/// fixture that stands in for a provisioned host has to be the real
/// thing rather than a placeholder.
fn generated_config(paths: &InternalPaths) -> String {
    render_internal_agent_config(
        paths,
        &InternalAgentConfigParams {
            email: "ops@example.internal",
            server: "https://localhost:9000/acme/acme/directory",
            domain: DOMAIN,
            hostname: HOST,
            responder_url: "http://127.0.0.1:8080",
            responder_hmac: &"responder-hmac".into(),
            eab_kid: None,
            eab_hmac: None,
            trusted_ca_sha256: &[ROOT_FP.to_string()],
        },
    )
}

/// Writes the two non-credential members of the all-or-none set so a
/// test that only cares about the four credential files still presents a
/// complete host.
fn write_companions(paths: &InternalPaths) {
    std::fs::create_dir_all(paths.dir()).expect("create the internal directory");
    std::fs::write(paths.agent_config(), generated_config(paths)).expect("write the config");
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

/// Writes `pem` into the fixed active-root path below `secrets_dir` and
/// returns its fingerprint.
///
/// The credential re-reads that file before every login, so a test that
/// wants a login to happen has to give it a real root to read, and a
/// test that wants one refused changes the file rather than a variable.
fn write_active_root(secrets_dir: &Path, pem: &str) -> String {
    let path = active_root_cert_path(secrets_dir);
    std::fs::create_dir_all(path.parent().expect("the certs directory"))
        .expect("create the certs directory");
    std::fs::write(&path, pem).expect("write the active root");
    active_root_fingerprint(secrets_dir).expect("the written root must hash")
}

/// A self-signed CA, as PEM.
fn self_signed_root(common_name: &str) -> String {
    let key = rcgen::KeyPair::generate().expect("ca key");
    let mut params =
        rcgen::CertificateParams::new(vec![common_name.to_string()]).expect("ca params");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.self_signed(&key).expect("self-signed ca").pem()
}

/// A fresh secrets directory carrying a real active root, with that
/// root's fingerprint.
fn secrets_dir_with_active_root() -> (TempDir, String) {
    let dir = TempDir::new().expect("tempdir");
    let fingerprint = write_active_root(dir.path(), &self_signed_root("bootroot-active-root"));
    (dir, fingerprint)
}

/// The uid and gid a published file ended up with.
fn owner_of(path: &Path) -> (u32, u32) {
    let meta = std::fs::metadata(path).expect("stat the published file");
    (meta.uid(), meta.gid())
}

/// The ids the protected writers establish under `cfg(test)`: this
/// process's own, standing in for the uid 0 / gid 0 production asks for.
fn protected_test_owner() -> (u32, u32) {
    (
        crate::fs_util::current_process_euid(),
        crate::cert_group::current_process_egid(),
    )
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
    // Compared member by member rather than through a derived
    // `PartialEq`: the two secret members deliberately do not carry one,
    // so a comparison has to be spelled out where it is wanted.
    let expected = material();
    assert_eq!(loaded.key.expose(), expected.key.expose());
    assert_eq!(loaded.chain, expected.chain);
    assert_eq!(loaded.acme_account.expose(), expected.acme_account.expose());
    assert_eq!(loaded.root_fingerprint, expected.root_fingerprint);
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

/// The generated config is a member of the all-or-none set, so the
/// shared loader holds it to every invariant the generator gives it.
///
/// A host whose config no longer describes this identity is a host whose
/// renewal daemon cannot start. Reporting it as provisioned would let
/// the privileged verbs run over a certificate nothing renews, so each
/// drift below is a typed refusal naming the config rather than a silent
/// pass.
#[tokio::test]
async fn a_config_that_drifted_from_the_generator_fails_the_shared_loader() {
    // Not TOML at all.
    let (_dir, paths) = provisioned_host().await;
    std::fs::write(paths.agent_config(), "email = \n").expect("write");
    let err = load_material(&paths).expect_err("an unparseable config must not load");
    match err {
        InternalCredentialError::Invalid { path, reason } => {
            assert_eq!(path, paths.agent_config());
            assert!(reason.contains("does not parse"), "{reason}");
        }
        other => panic!("{other:?}"),
    }

    // Parses, but describes no profile at all.
    let (_dir, paths) = provisioned_host().await;
    std::fs::write(paths.agent_config(), "email = \"a@b\"\n").expect("write");
    let err = load_material(&paths).expect_err("a config with no profile must not load");
    assert!(
        matches!(&err, InternalCredentialError::Invalid { path, reason }
            if path == &paths.agent_config() && reason.contains("exactly one profile")),
        "{err:?}"
    );

    // Parses and carries one profile, but points it at another
    // identity's key.
    let (_dir, paths) = provisioned_host().await;
    let hijacked = generated_config(&paths).replace(
        &paths.key().display().to_string(),
        "/srv/secrets/services/other/key.pem",
    );
    std::fs::write(paths.agent_config(), hijacked).expect("write");
    let err = load_material(&paths).expect_err("a redirected key path must not load");
    assert!(
        matches!(&err, InternalCredentialError::Invalid { reason, .. }
            if reason.contains("profiles.paths.key")),
        "{err:?}"
    );

    // Parses, but a rotation left the pins empty, so nothing anchors the
    // private bundle.
    let (_dir, paths) = provisioned_host().await;
    let unpinned = upsert_internal_trust(&generated_config(&paths), &paths, &[]).expect("upsert");
    std::fs::write(paths.agent_config(), unpinned).expect("write");
    let err = load_material(&paths).expect_err("an unpinned config must not load");
    assert!(
        matches!(&err, InternalCredentialError::Invalid { reason, .. }
            if reason.contains("trusted_ca_sha256")),
        "{err:?}"
    );
}

/// The private bundle is a member of the set too: a file that holds no
/// certificate fails every trust check the daemon makes, so it fails the
/// loader rather than the renewal.
#[tokio::test]
async fn a_bundle_holding_no_certificate_fails_the_shared_loader() {
    let (_dir, paths) = provisioned_host().await;
    std::fs::write(paths.ca_bundle(), "# no certificates here\n").expect("write");
    let err = load_material(&paths).expect_err("an empty bundle must not load");
    match err {
        InternalCredentialError::Invalid { path, .. } => assert_eq!(path, paths.ca_bundle()),
        other => panic!("{other:?}"),
    }
}

/// The generated config is what the loader accepts, unchanged, and after
/// a rotation has rewritten its `[trust]` table.
#[tokio::test]
async fn the_generated_config_and_its_rotated_form_both_load() {
    let (_dir, paths) = provisioned_host().await;
    load_internal_config(&paths).expect("the generated config must load");

    let rotated = upsert_internal_trust(
        &generated_config(&paths),
        &paths,
        &[ROOT_FP.to_string(), OTHER_FP.to_string()],
    )
    .expect("upsert");
    std::fs::write(paths.agent_config(), rotated).expect("write");
    let settings = load_internal_config(&paths).expect("a rotated config must still load");
    assert_eq!(
        settings.trust.trusted_ca_sha256,
        vec![ROOT_FP.to_string(), OTHER_FP.to_string()]
    );
}

/// The two secret-bearing files land at `0600`, and are never observable
/// wider because the publish renames a temporary that was created narrow.
#[tokio::test]
async fn secret_members_are_published_at_0600() {
    let (_dir, paths) = provisioned_host().await;
    assert_eq!(mode_of(&paths.key()), 0o600);
    assert_eq!(mode_of(&paths.acme_account()), 0o600);
}

/// Every member of the all-or-none set is classified, and the private
/// CA bundle is the only one that is not protected.
///
/// The ownership split is a second list beside [`SET_FILES`], and a
/// name that reaches the set without reaching that list publishes
/// owner-preserving without anything failing — a credential file left
/// to whoever ran the command, which is the whole defect the protected
/// writer exists to close. Asserted over the set rather than over the
/// five names on their own, so a seventh member cannot be added without
/// deciding which side of the split it falls on.
#[test]
fn every_member_of_the_set_is_protected_or_is_the_private_bundle() {
    for name in SET_FILES {
        assert_eq!(
            is_protected(name),
            name != CA_BUNDLE_FILE,
            "{name} is on the wrong side of the ownership split"
        );
    }
    assert!(
        SET_FILES.contains(&CA_BUNDLE_FILE),
        "the bundle is still the sixth member of the all-or-none set"
    );
}

/// The four credential files carry the protected owner, on a first
/// publication and on the replacement a repair performs.
///
/// Production asks for uid 0 and gid 0; this asks for the test process's
/// own ids through the same writer, the same chown on the same staged
/// inode and the same rename — the ownership an unprivileged process is
/// allowed to establish is the only thing that differs. The
/// already-provisioned case is the one that matters most: a rename
/// installs a fresh inode, so a replacement that did not re-assert the
/// owner would silently hand the credential to whoever ran the command.
#[tokio::test]
async fn the_credential_files_are_published_under_the_protected_owner() {
    let (_dir, paths) = provisioned_host().await;
    let owner = protected_test_owner();
    for path in [
        paths.key(),
        paths.chain(),
        paths.acme_account(),
        paths.root_fingerprint(),
    ] {
        assert_eq!(
            owner_of(&path),
            owner,
            "first publication: {}",
            path.display()
        );
    }

    publish_material(&paths, &material())
        .await
        .expect("republish the material");
    for path in [
        paths.key(),
        paths.chain(),
        paths.acme_account(),
        paths.root_fingerprint(),
    ] {
        assert_eq!(owner_of(&path), owner, "replacement: {}", path.display());
        assert_eq!(mode_of(&path), KEY_FILE_MODE, "{}", path.display());
    }
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
///
/// The comparison is against the root *on disk*, re-read each time, so
/// the mismatch is produced by replacing the deployment's root
/// certificate rather than by passing a different string — which is the
/// only form the rotation actually takes.
#[tokio::test]
async fn a_root_mismatch_returns_repair_required() {
    let dir = TempDir::new().expect("tempdir");
    let (bundle, leaf_material) = real_credential();
    let stored = write_active_root(dir.path(), &bundle);
    let credential = InternalCredential::from_parts(
        dir.path(),
        "https://localhost:8200",
        &InternalMaterial {
            root_fingerprint: stored.clone(),
            ..clone_material(&leaf_material)
        },
        &bundle,
    )
    .expect("a real leaf and bundle must build the transport");
    assert_eq!(credential.root_fingerprint(), stored);
    credential
        .check_active_root()
        .await
        .expect("the matching root is accepted");

    // The rotation replaces the file; nothing tells the long-lived
    // credential about it.
    let active = write_active_root(dir.path(), &self_signed_root("bootroot-new-root"));
    let err = credential
        .check_active_root()
        .await
        .expect_err("a mismatched root must be refused");
    match err {
        InternalCredentialError::RepairRequired {
            stored: reported,
            active: reported_active,
        } => {
            assert_eq!(reported, stored);
            assert_eq!(reported_active, active);
        }
        other => panic!("{other:?}"),
    }
    assert!(
        err_repair_message().contains("bootroot rotate registrar-internal-credential"),
        "{}",
        err_repair_message()
    );
}

/// An active root that cannot be read is a refusal, not an assumption
/// that the stored one still matches.
#[tokio::test]
async fn an_unreadable_active_root_refuses_the_login() {
    let dir = TempDir::new().expect("tempdir");
    let (bundle, leaf_material) = real_credential();
    let stored = write_active_root(dir.path(), &bundle);
    let credential = InternalCredential::from_parts(
        dir.path(),
        "https://localhost:8200",
        &InternalMaterial {
            root_fingerprint: stored,
            ..clone_material(&leaf_material)
        },
        &bundle,
    )
    .expect("the credential must build");
    std::fs::remove_file(active_root_cert_path(dir.path())).expect("remove the active root");
    let err = credential
        .authenticated()
        .await
        .expect_err("an unreadable active root must refuse");
    assert!(matches!(err, InternalCredentialError::Io { .. }), "{err:?}");
}

/// `InternalMaterial` is deliberately not `Clone` — the key inside it
/// is not a value to copy around casually — so the tests that need a
/// second copy under a different root fingerprint say so here.
fn clone_material(material: &InternalMaterial) -> InternalMaterial {
    InternalMaterial {
        key: PrivateKeyPem::new(material.key.expose().to_string()),
        chain: material.chain.clone(),
        acme_account: AcmeAccountKey::new(material.acme_account.expose().to_string()),
        root_fingerprint: material.root_fingerprint.clone(),
    }
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
    let dir = TempDir::new().expect("tempdir");
    let err =
        InternalCredential::from_parts(dir.path(), "https://localhost:8200", &material(), &bundle)
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

/// The two secrets `config_params` lends out. Owned by a `static` rather
/// than built inline, because the params borrow them and a temporary
/// cannot outlive the function that returns the borrow.
static CONFIG_RESPONDER_HMAC: LazyLock<HmacSecret> =
    LazyLock::new(|| HmacSecret::from("hmac-value"));
static CONFIG_EAB_HMAC: LazyLock<HmacSecret> = LazyLock::new(|| HmacSecret::from("hmac-1"));

fn config_params(pins: &[String]) -> InternalAgentConfigParams<'_> {
    InternalAgentConfigParams {
        email: "ops@example.internal",
        server: "https://bootroot-ca:9000/acme/acme/directory",
        domain: DOMAIN,
        hostname: HOST,
        responder_url: "http://bootroot-http01:8080",
        responder_hmac: &CONFIG_RESPONDER_HMAC,
        eab_kid: Some("kid-1"),
        eab_hmac: Some(&CONFIG_EAB_HMAC),
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
    assert_eq!(eab.hmac.expose(), "hmac-1");
    assert_eq!(
        settings.server,
        "https://bootroot-ca:9000/acme/acme/directory"
    );
    assert_eq!(settings.acme.http_responder_hmac.expose(), "hmac-value");
    // No `[openbao]` section: the internal profile polls nothing.
    assert!(settings.openbao.is_none());
    // The documented invocation is in the file the operator reads.
    assert!(
        rendered.contains(&internal_agent_invocation(&paths)),
        "{rendered}"
    );
}

/// The generated config carries two bearer secrets — the HTTP-01
/// responder HMAC and, where the deployment registered one, the EAB HMAC
/// — so the `Settings` it deserializes into must not print them.
///
/// This is the leak the redaction exists for: nothing has to *decide* to
/// log a secret for one to escape. A `tracing` field, a `{:?}` in an
/// error context or an `anyhow` chain over anything holding these
/// settings renders the whole tree, and before [`HmacSecret`] both HMACs
/// were bare `String`s under a `#[derive(Debug)]`. The assertion is on
/// the *loaded* value rather than on the wrapper alone, because the file
/// is the one place the raw bytes legitimately live: the point is that
/// they stop being renderable the moment they are read back.
#[test]
fn the_loaded_internal_config_never_renders_its_secrets() {
    const RESPONDER: &str = "responder-hmac-that-must-not-appear";
    const EAB: &str = "eab-hmac-that-must-not-appear";

    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let responder_hmac = HmacSecret::from(RESPONDER);
    let eab_hmac = HmacSecret::from(EAB);
    let pins = vec![ROOT_FP.to_string()];
    let rendered = render_internal_agent_config(
        &paths,
        &InternalAgentConfigParams {
            responder_hmac: &responder_hmac,
            eab_kid: Some("kid-1"),
            eab_hmac: Some(&eab_hmac),
            ..config_params(&pins)
        },
    );

    // The file itself still carries the real values: the daemon has to
    // authenticate with them.
    assert!(rendered.contains(RESPONDER), "{rendered}");
    assert!(rendered.contains(EAB), "{rendered}");

    // Load through the production loader, not just the deserializer, so
    // the regression covers the path every caller reaches the config by.
    std::fs::create_dir_all(paths.dir()).expect("create the credential directory");
    std::fs::write(paths.agent_config(), &rendered).expect("write the generated config");
    let settings = load_internal_config(&paths).expect("the generated config must load");

    let rendered_debug = format!("{settings:?}");
    assert!(!rendered_debug.contains(RESPONDER), "{rendered_debug}");
    assert!(!rendered_debug.contains(EAB), "{rendered_debug}");
    assert!(rendered_debug.contains("<redacted>"), "{rendered_debug}");

    // The same holds one level down, where a narrower `{:?}` would land.
    assert_eq!(
        format!("{:?}", settings.acme.http_responder_hmac),
        "<redacted>"
    );
    let eab = settings.eab.expect("the config carries EAB credentials");
    assert_eq!(format!("{:?}", eab.hmac), "<redacted>");
    assert!(!format!("{eab:?}").contains(EAB), "{eab:?}");

    // And the values are still the ones the daemon needs.
    assert_eq!(settings.acme.http_responder_hmac.expose(), RESPONDER);
    assert_eq!(eab.hmac.expose(), EAB);
}

/// The same redaction over the values that reach `Settings` from the
/// command line and from `eab.json`, which are the other two doors these
/// secrets come in by.
#[test]
fn cli_and_file_supplied_secrets_are_redacted_too() {
    let overrides = crate::config::CliOverrides {
        http_responder_hmac: Some(HmacSecret::from("cli-hmac-must-not-appear")),
        ..crate::config::CliOverrides::default()
    };
    let rendered = format!("{overrides:?}");
    assert!(!rendered.contains("cli-hmac-must-not-appear"), "{rendered}");
    assert!(rendered.contains("<redacted>"), "{rendered}");

    let creds = crate::eab::EabCredentials {
        kid: "kid-1".to_string(),
        hmac: HmacSecret::from("file-hmac-must-not-appear"),
    };
    let rendered = format!("{creds:?}");
    assert!(
        !rendered.contains("file-hmac-must-not-appear"),
        "{rendered}"
    );
    assert!(rendered.contains("<redacted>"), "{rendered}");
    // The kid is not a secret and stays legible: it is how an operator
    // tells which account a refusal is about.
    assert!(rendered.contains("kid-1"), "{rendered}");
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

/// The prior-set snapshot a publication is held to: what it captures,
/// what it puts back, and what it refuses to touch.
mod snapshot {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::{
        account_json, chain_pem, key_pem, mode_of, owner_of, protected_test_owner, provisioned_host,
    };
    use crate::cert_group::CA_BUNDLE_FILE_MODE;
    use crate::fs_util::KEY_FILE_MODE;
    use crate::registrar::internal::material::{PRIOR_DIR, capture_set};
    use crate::registrar::internal::{InternalPaths, MaterialStatus, material_status};

    /// The failure the snapshot exists for: a publication over an
    /// already-provisioned host that dies part-way through. Every member
    /// goes back to its own bytes — not just the ones the failure
    /// reached — and each goes back at the mode the layout gives it,
    /// which is what a restore that merely copied the backup would lose.
    #[tokio::test]
    async fn a_restore_puts_every_member_back_at_its_own_mode() {
        let (dir, paths) = provisioned_host().await;
        let config_before = std::fs::read_to_string(paths.agent_config()).expect("config");
        let snapshot = capture_set(&paths).await.expect("capture");

        // A publication that replaced the bundle and the key and then
        // failed on the chain.
        std::fs::write(paths.ca_bundle(), "NEW BUNDLE").expect("new bundle");
        std::fs::write(paths.key(), "NEW KEY").expect("new key");
        std::fs::set_permissions(paths.key(), std::fs::Permissions::from_mode(0o644))
            .expect("widen the new key");

        snapshot.restore().await.expect("restore");

        assert_eq!(
            std::fs::read_to_string(paths.key()).expect("key"),
            key_pem()
        );
        assert_eq!(
            std::fs::read_to_string(paths.chain()).expect("chain"),
            chain_pem()
        );
        assert_eq!(
            std::fs::read_to_string(paths.acme_account()).expect("account"),
            account_json()
        );
        assert_eq!(
            std::fs::read_to_string(paths.ca_bundle()).expect("bundle"),
            chain_pem()
        );
        assert_eq!(
            std::fs::read_to_string(paths.agent_config()).expect("config"),
            config_before
        );
        assert_eq!(mode_of(&paths.key()), KEY_FILE_MODE);
        assert_eq!(mode_of(&paths.acme_account()), KEY_FILE_MODE);
        assert_eq!(mode_of(&paths.agent_config()), KEY_FILE_MODE);
        assert_eq!(mode_of(&paths.ca_bundle()), CA_BUNDLE_FILE_MODE);

        snapshot.discard().await.expect("discard");
        assert!(!paths.dir().join(PRIOR_DIR).exists());
        drop(dir);
    }

    /// A first provisioning has nothing to put back, so a restore takes
    /// the host back to bare rather than leaving the half-set the failed
    /// publication wrote. That is the same end state `init`'s rollback
    /// reaches by removing the layout directory it registered.
    #[tokio::test]
    async fn a_restore_removes_members_that_were_not_there_before() {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(paths.dir()).expect("layout dir");
        let snapshot = capture_set(&paths).await.expect("capture");

        std::fs::write(paths.ca_bundle(), "NEW BUNDLE").expect("new bundle");
        std::fs::write(paths.key(), "NEW KEY").expect("new key");

        snapshot.restore().await.expect("restore");
        assert_eq!(material_status(&paths), MaterialStatus::Absent);
    }

    /// A member that is not a regular file cannot be copied, and it is
    /// not the publication's to delete: it belongs to whatever left it
    /// there. The restore repairs the five members around it and reports
    /// success, so the publication failure — not a restore failure — is
    /// what reaches the operator.
    #[tokio::test]
    async fn an_irregular_member_is_left_exactly_as_found() {
        let (_dir, paths) = provisioned_host().await;
        std::fs::remove_file(paths.chain()).expect("remove the chain");
        std::fs::create_dir_all(paths.chain().join("nested")).expect("a directory at the chain");

        let snapshot = capture_set(&paths).await.expect("capture");
        std::fs::write(paths.key(), "NEW KEY").expect("new key");
        snapshot.restore().await.expect("restore");

        assert_eq!(
            std::fs::read_to_string(paths.key()).expect("key"),
            key_pem()
        );
        assert!(
            paths.chain().join("nested").is_dir(),
            "the restore must not delete what it could not capture"
        );
    }

    /// A snapshot that survived a crash is not the prior state any
    /// longer — the set beside it is. Capturing clears it first, so a
    /// restore can never put back bytes from a run that ended long ago.
    #[tokio::test]
    async fn a_stale_snapshot_is_cleared_before_the_next_capture() {
        let (_dir, paths) = provisioned_host().await;
        let prior = paths.dir().join(PRIOR_DIR);
        std::fs::create_dir_all(&prior).expect("stale snapshot");
        std::fs::write(prior.join("key.pem"), "ANCIENT KEY").expect("stale key");

        let snapshot = capture_set(&paths).await.expect("capture");
        assert_eq!(
            std::fs::read_to_string(prior.join("key.pem")).expect("captured key"),
            key_pem()
        );

        std::fs::write(paths.key(), "NEW KEY").expect("new key");
        snapshot.restore().await.expect("restore");
        assert_eq!(
            std::fs::read_to_string(paths.key()).expect("key"),
            key_pem()
        );
    }

    /// A snapshot copy of a protected member is that member: same
    /// bytes, so the same owner and the same mode, and the restore that
    /// puts it back publishes it under them again.
    ///
    /// The private bundle beside them is public trust material and stays
    /// on the ownership policy it has always had — it is the sixth
    /// member of the all-or-none set, not a sixth protected file.
    #[tokio::test]
    async fn the_protected_snapshot_and_restore_carry_the_protected_owner() {
        let (_dir, paths) = provisioned_host().await;
        let owner = protected_test_owner();
        let snapshot = capture_set(&paths).await.expect("capture");
        let prior = paths.dir().join(PRIOR_DIR);

        for name in [
            "key.pem",
            "chain.pem",
            "acme-account.json",
            "root-fingerprint",
            "agent.toml",
        ] {
            let copy = prior.join(name);
            assert_eq!(owner_of(&copy), owner, "the snapshot of {name}");
            assert_eq!(mode_of(&copy), KEY_FILE_MODE, "the snapshot of {name}");
        }
        assert!(
            prior.join("ca-bundle.pem").exists(),
            "the bundle is still captured with the rest of the all-or-none set"
        );

        // A publication that replaced two members and then failed.
        std::fs::write(paths.key(), "NEW KEY").expect("new key");
        std::fs::write(paths.agent_config(), "email = \"new@example.internal\"\n")
            .expect("new config");
        snapshot.restore().await.expect("restore");

        for path in [paths.key(), paths.agent_config()] {
            assert_eq!(owner_of(&path), owner, "the restore of {}", path.display());
            assert_eq!(
                mode_of(&path),
                KEY_FILE_MODE,
                "the restore of {}",
                path.display()
            );
        }
    }

    /// A capture that cannot complete removes what it had copied.
    ///
    /// The publication it would have protected never starts, so a
    /// half-written `.prior` is a second copy of the credential and
    /// nothing else — including, on a host whose capture failed while
    /// establishing ownership, a copy under an owner the publication was
    /// refused for. The published names are untouched either way: a
    /// capture only reads them.
    #[tokio::test]
    async fn a_capture_that_cannot_complete_leaves_no_partial_snapshot() {
        assert_ne!(
            crate::fs_util::current_process_euid(),
            0,
            "an unreadable member is only unreadable to a process that is not root"
        );
        let (_dir, paths) = provisioned_host().await;
        // The key is captured first and the chain second, so this fails
        // the capture with one member already copied.
        std::fs::set_permissions(paths.chain(), std::fs::Permissions::from_mode(0o000))
            .expect("make the chain unreadable");

        let Err(err) = capture_set(&paths).await else {
            panic!("a member that cannot be read must fail the capture");
        };
        assert!(
            format!("{err}").contains("chain.pem"),
            "the failure must name the member it could not capture: {err}"
        );
        assert!(
            !paths.dir().join(PRIOR_DIR).exists(),
            "a partial snapshot must not survive the capture that failed"
        );
        assert_eq!(
            material_status(&paths),
            MaterialStatus::Present,
            "a capture reads the published names and never writes them"
        );
    }

    /// The captured bytes are a copy of the credential, so they are held
    /// at the credential's own mode and inside the directory whose
    /// permissions already protect it.
    #[tokio::test]
    async fn the_capture_holds_the_secrets_at_0600_beside_the_credential() {
        let (_dir, paths) = provisioned_host().await;
        let snapshot = capture_set(&paths).await.expect("capture");
        let prior = paths.dir().join(PRIOR_DIR);
        assert_eq!(snapshot.dir(), prior);
        assert_eq!(mode_of(&prior.join("key.pem")), KEY_FILE_MODE);
        assert_eq!(mode_of(&prior.join("acme-account.json")), KEY_FILE_MODE);
        // The layout status is unchanged by a capture: the snapshot
        // directory is not one of the six names.
        assert_eq!(material_status(&paths), MaterialStatus::Present);
    }
}

/// Certificate-login behaviour: one login per lease window, a fresh one
/// once the cache is dropped, and no `role_id`/`secret_id` anywhere.
mod login {
    use serde_json::json;
    use tempfile::TempDir;
    use wiremock::matchers::{body_json, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{OTHER_FP, secrets_dir_with_active_root, self_signed_root, write_active_root};
    use crate::registrar::internal::{
        CERT_AUTH_ROLE, InternalCredential, InternalCredentialError, is_expired_token_error,
    };

    const TOKEN: &str = "s.internal-token";

    /// A credential over the mock, holding the real root the fixture
    /// wrote — the one the login boundary re-reads on every
    /// acquisition.
    fn credential_over(server: &MockServer) -> (TempDir, InternalCredential) {
        let (dir, fingerprint) = secrets_dir_with_active_root();
        let credential = InternalCredential::for_test(&server.uri(), dir.path(), &fingerprint)
            .expect("credential");
        (dir, credential)
    }

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
        let (_dir, credential) = credential_over(&server);

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
        let (_dir, credential) = credential_over(&server);

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
        let (_dir, credential) = credential_over(&server);

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
        let (_dir, credential) = credential_over(&server);

        credential.authenticated().await.expect("first login");
        credential.authenticated().await.expect("refreshed login");
    }

    /// The root can change under a credential that is already built,
    /// and when it does neither a cached token nor a fresh login is
    /// handed out.
    ///
    /// The mock expects exactly one login: the one made before the
    /// rotation. The token it returned is well inside its lease, so a
    /// credential that compared roots only at construction would go on
    /// serving it — which is the worse half of the failure, because it
    /// is a *write* under a superseded credential rather than a login
    /// that would have been refused anyway.
    #[tokio::test]
    async fn a_root_replaced_after_construction_stops_the_login_and_the_cache() {
        let server = MockServer::start().await;
        mock_login(&server, 3600, 1).await;
        let (dir, credential) = credential_over(&server);
        credential
            .authenticated()
            .await
            .expect("the login before the rotation must succeed");

        write_active_root(dir.path(), &self_signed_root("bootroot-rotated-root"));

        for attempt in 0..2 {
            let err = credential
                .authenticated()
                .await
                .expect_err("a superseded root must refuse");
            assert!(
                matches!(err, InternalCredentialError::RepairRequired { .. }),
                "attempt {attempt}: {err:?}"
            );
        }
        // `expect(1)` is asserted when the server drops: the refusals
        // above made no second login.
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

    use tempfile::TempDir;

    use super::{DOMAIN, HOST, ROOT_FP, account_json, write_active_root};
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

        // The CA the entry trusts is also this scenario's deployment
        // root, written where the credential re-reads it from before
        // every login.
        let dir = TempDir::new().expect("tempdir");
        let mut material = ca.leaf(&registrar_internal_identity(HOST, DOMAIN));
        material.root_fingerprint = write_active_root(dir.path(), &ca.pem);
        let credential = InternalCredential::from_parts(
            dir.path(),
            &backend.url,
            &material,
            &backend.server_ca_pem,
        )
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

/// The fail-closed guard the ordinary renewal loop runs before it
/// issues. The window it exists for is between a full rotation's Phase
/// 3, which publishes the additive trust set and reloads this daemon,
/// and the tail after Phase 4, which is the only place the entry, the
/// leaf and the stored fingerprint move.
mod renewal_guard {
    use tempfile::TempDir;

    use super::{account_json, chain_pem, generated_config, key_pem};
    use crate::config::{DaemonProfileSettings, Settings};
    use crate::registrar::internal::{
        InternalCredentialError, InternalPaths, check_renewal_allowed, internal_profile_paths,
    };

    /// A self-signed root and its hex SHA-256, as the deployment's
    /// `certs/root_ca.crt` and as the fingerprint recorded beside the
    /// credential.
    fn root_ca(label: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("generate a root key");
        let mut params =
            rcgen::CertificateParams::new(Vec::<String>::new()).expect("root parameters");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, label);
        let cert = params.self_signed(&key).expect("self-sign the root");
        let fingerprint = crate::tls::sha256_hex(cert.der().as_ref());
        (cert.pem(), fingerprint)
    }

    /// A provisioned host whose active root is `active_pem` and whose
    /// credential records `stored_fp`.
    fn host(active_pem: &str, stored_fp: &str) -> (TempDir, InternalPaths) {
        let dir = TempDir::new().expect("tempdir");
        let paths = InternalPaths::new(dir.path());
        std::fs::create_dir_all(dir.path().join("certs")).expect("create the CA directory");
        std::fs::write(dir.path().join("certs").join("root_ca.crt"), active_pem)
            .expect("write the active root");
        std::fs::create_dir_all(paths.dir()).expect("create the internal directory");
        std::fs::write(paths.key(), key_pem()).expect("key");
        std::fs::write(paths.chain(), chain_pem()).expect("chain");
        std::fs::write(paths.acme_account(), account_json()).expect("account key");
        std::fs::write(paths.root_fingerprint(), format!("{stored_fp}\n")).expect("fingerprint");
        std::fs::write(paths.ca_bundle(), chain_pem()).expect("bundle");
        std::fs::write(paths.agent_config(), generated_config(&paths)).expect("config");
        (dir, paths)
    }

    /// The one profile the generated config carries, read the way
    /// `bootroot-agent` reads it.
    fn internal_profile(paths: &InternalPaths) -> DaemonProfileSettings {
        let settings =
            Settings::from_file(Some(paths.agent_config())).expect("the generated config parses");
        settings
            .profiles
            .into_iter()
            .next()
            .expect("the generated config carries one profile")
    }

    /// The ordinary case: the stored root is the active one, so the
    /// guard is invisible and the loop renews as it always did.
    #[test]
    fn a_current_root_lets_the_ordinary_loop_renew() {
        let (root_pem, root_fp) = root_ca("current");
        let (_dir, paths) = host(&root_pem, &root_fp);
        check_renewal_allowed(&internal_profile(&paths)).expect("a matching root renews normally");
    }

    /// The window itself: the root moved and the fingerprint has not
    /// caught up, so the refusal is the typed repair-required one and
    /// it names the command that fixes it.
    #[test]
    fn a_stale_stored_root_refuses_with_repair_required() {
        let (_old_pem, old_fp) = root_ca("old");
        let (new_pem, new_fp) = root_ca("new");
        let (_dir, paths) = host(&new_pem, &old_fp);

        let err = check_renewal_allowed(&internal_profile(&paths))
            .expect_err("a superseded root must refuse renewal");
        match &err {
            InternalCredentialError::RepairRequired { stored, active } => {
                assert_eq!(stored, &old_fp);
                assert_eq!(active, &new_fp);
            }
            other => panic!("expected repair-required, got {other:?}"),
        }
        assert!(
            err.to_string()
                .contains("bootroot rotate registrar-internal-credential")
        );
    }

    /// An ordinary service profile is not guarded at all. It is not
    /// bound to an `auth/cert` entry, and renewing it across a rotation
    /// is exactly what the rotation wants — so the guard must not even
    /// look for a credential beside it.
    #[test]
    fn an_ordinary_service_profile_is_not_guarded() {
        let (new_pem, _new_fp) = root_ca("new");
        let (_old_pem, old_fp) = root_ca("old");
        let (_dir, paths) = host(&new_pem, &old_fp);
        let mut profile = internal_profile(&paths);
        profile.service_name = "edge-proxy".to_string();
        check_renewal_allowed(&profile).expect("a service profile is never guarded");
        assert!(internal_profile_paths(&profile).is_none());
    }

    /// The staging profile a provisioning or a repair issues through
    /// carries the internal identity but writes into
    /// `registrar-internal/staging`. It must not be matched: a repair
    /// issues its replacement leaf precisely when the stored root no
    /// longer matches, so a guard that caught it there could never be
    /// satisfied.
    #[test]
    fn the_staging_profile_a_repair_issues_through_is_not_guarded() {
        let (new_pem, _new_fp) = root_ca("new");
        let (_old_pem, old_fp) = root_ca("old");
        let (_dir, paths) = host(&new_pem, &old_fp);
        let mut profile = internal_profile(&paths);
        let staging = paths.dir().join("staging");
        profile.paths.cert = staging.join("leaf.pem");
        profile.paths.key = staging.join("key.pem");
        assert!(internal_profile_paths(&profile).is_none());
        check_renewal_allowed(&profile).expect("the staging issuance is not the guarded one");
    }

    /// Fail closed rather than open: a host whose active root cannot be
    /// read refuses too, because "cannot tell" and "does not match" have
    /// the same consequence for a leaf about to be reissued.
    #[test]
    fn an_unreadable_active_root_refuses_as_well() {
        let (root_pem, root_fp) = root_ca("current");
        let (dir, paths) = host(&root_pem, &root_fp);
        std::fs::remove_file(dir.path().join("certs").join("root_ca.crt"))
            .expect("remove the active root");
        let err = check_renewal_allowed(&internal_profile(&paths))
            .expect_err("an unreadable active root must refuse renewal");
        assert!(matches!(err, InternalCredentialError::Io { .. }), "{err:?}");
    }
}
