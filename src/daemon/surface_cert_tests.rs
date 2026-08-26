//! The composition boundary that resolves the deployment inventory and
//! hands it to the registrar surface's issuance.
//!
//! The issuance rules themselves — the eight usability conditions, the
//! names, the ACME inputs, the write — are tested beside the unit that
//! owns them, in `crate::registrar::surface_certs`. What is tested here
//! is what only this layer decides: the gate, the state-file
//! resolution, and that a whole deployment whose material is fine
//! reaches neither the CA nor `OpenBao`.

use std::path::PathBuf;

use tempfile::TempDir;

use super::ensure_registrar_surface_certificates;
use crate::config::{RegistrarEndpointSettings, Settings, TrustSettings};
use crate::registrar::internal::{InternalAgentConfigParams, InternalPaths};
use crate::registrar::surface_certs::fixture::{
    TEST_DOMAIN, TEST_HOST, TEST_KV_MOUNT, TestCa, client_name, endpoint_name, generate_ca,
    issue_leaf_pem, test_settings,
};
use crate::secret::HmacSecret;

// ---------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------

/// With the endpoint disabled nothing is issued, no material path is
/// created, and nothing is requested from the CA or from `OpenBao` — so
/// a default-configured agent on any service host is untouched. The
/// state file deliberately names a path that does not exist: reaching
/// for it would fail loudly.
#[tokio::test]
async fn a_disabled_endpoint_issues_nothing_and_reads_nothing() {
    let dir = tempfile::tempdir().expect("tempdir");
    let cert = dir.path().join("client.crt");
    let mut settings = test_settings(
        "http://unreachable.invalid/directory",
        "http://unreachable.invalid",
    );
    settings.registrar_endpoint = RegistrarEndpointSettings {
        enabled: false,
        server_cert_path: Some(dir.path().join("server.crt")),
        server_key_path: Some(dir.path().join("server.key")),
        client_cert_path: Some(cert.clone()),
        client_key_path: Some(dir.path().join("client.key")),
    };
    settings.registrar.state_file = Some(dir.path().join("does-not-exist/state.json"));

    ensure_registrar_surface_certificates(&settings, false)
        .await
        .expect("a disabled endpoint does nothing at all");
    assert!(!cert.exists(), "no material path is created");
    assert_eq!(
        std::fs::read_dir(dir.path()).expect("read tempdir").count(),
        0,
        "a disabled endpoint creates nothing"
    );
}

// ---------------------------------------------------------------------
// The whole unit, against a rendered deployment
// ---------------------------------------------------------------------

/// A deployment laid out the way `bootroot init` leaves one: a state
/// file, the fixed internal layout below the secrets directory, and the
/// four configured material paths.
struct Deployment {
    _dir: TempDir,
    settings: Settings,
    client_cert: PathBuf,
    client_key: PathBuf,
    server_cert: PathBuf,
    server_key: PathBuf,
    ca: TestCa,
}

impl Deployment {
    /// Lays out a deployment whose `OpenBao` URL points at loopback port
    /// 1 — nothing binds it, so any read this unit makes fails loudly
    /// rather than silently succeeding.
    fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let secrets_dir = dir.path().join("secrets");
        let material = dir.path().join("certs");
        std::fs::create_dir_all(&material).expect("material dir");
        let internal = InternalPaths::new(&secrets_dir);
        std::fs::create_dir_all(internal.dir()).expect("internal dir");

        let ca = generate_ca("Deployment CA");
        let bundle = material.join("ca-bundle.pem");
        std::fs::write(&bundle, ca.pem()).expect("write bundle");
        let fingerprint = crate::tls::sha256_hex(ca.der());

        let rendered = crate::registrar::internal::render_internal_agent_config(
            &internal,
            &InternalAgentConfigParams {
                email: "ops@example.com",
                server: "https://127.0.0.1:1/acme/acme/directory",
                domain: TEST_DOMAIN,
                hostname: TEST_HOST,
                responder_url: "http://127.0.0.1:1",
                responder_hmac: &HmacSecret::new("rendered-hmac".to_string()),
                eab_kid: None,
                eab_hmac: None,
                trusted_ca_sha256: std::slice::from_ref(&fingerprint),
            },
        );
        std::fs::write(internal.agent_config(), rendered).expect("write internal config");

        let state_file = dir.path().join("state.json");
        std::fs::write(
            &state_file,
            serde_json::to_vec(&serde_json::json!({
                "openbao_url": "https://127.0.0.1:1",
                "kv_mount": TEST_KV_MOUNT,
                "secrets_dir": secrets_dir,
            }))
            .expect("state json"),
        )
        .expect("write state file");

        let client_cert = material.join("registrar-client.crt");
        let client_key = material.join("registrar-client.key");
        let server_cert = material.join("registrar-endpoint.crt");
        let server_key = material.join("registrar-endpoint.key");

        let mut settings = test_settings("https://127.0.0.1:1/directory", "http://127.0.0.1:1");
        settings.trust = TrustSettings {
            ca_bundle_path: Some(bundle),
            trusted_ca_sha256: vec![fingerprint],
        };
        settings.registrar_endpoint = RegistrarEndpointSettings {
            enabled: true,
            server_cert_path: Some(server_cert.clone()),
            server_key_path: Some(server_key.clone()),
            client_cert_path: Some(client_cert.clone()),
            client_key_path: Some(client_key.clone()),
        };
        settings.registrar.state_file = Some(state_file);

        Self {
            _dir: dir,
            settings,
            client_cert,
            client_key,
            server_cert,
            server_key,
            ca,
        }
    }

    /// Publishes usable material for both pairs.
    fn seed_both_pairs(&self) {
        let (leaf, key) = issue_leaf_pem(&self.ca, &client_name(), (2020, 1, 1), (2099, 1, 1));
        std::fs::write(&self.client_cert, leaf).expect("write client leaf");
        std::fs::write(&self.client_key, key).expect("write client key");
        let (leaf, key) = issue_leaf_pem(&self.ca, &endpoint_name(), (2020, 1, 1), (2099, 1, 1));
        std::fs::write(&self.server_cert, leaf).expect("write server leaf");
        std::fs::write(&self.server_key, key).expect("write server key");
    }

    fn snapshot(&self) -> Vec<Vec<u8>> {
        [
            &self.client_cert,
            &self.client_key,
            &self.server_cert,
            &self.server_key,
        ]
        .iter()
        .map(|path| std::fs::read(path).unwrap_or_default())
        .collect()
    }
}

/// With both pairs usable the daemon starts having made no `OpenBao`
/// call and no CA request at all, and the material survives byte-
/// identically. `OpenBao` and the CA both point at a loopback port
/// nothing binds, so any request would fail the call rather than pass
/// it.
#[tokio::test]
async fn both_pairs_usable_starts_with_openbao_down_and_touches_nothing() {
    let deployment = Deployment::new();
    deployment.seed_both_pairs();
    let before = deployment.snapshot();

    ensure_registrar_surface_certificates(&deployment.settings, false)
        .await
        .expect("usable material needs no OpenBao and no CA");

    assert_eq!(
        deployment.snapshot(),
        before,
        "usable material is left byte-identical, certificate and key alike"
    );
}

/// Each of the eight states, driven through the whole unit: an
/// `OpenBao` that cannot be reached proves the daemon decided to issue,
/// and the failure names the read rather than the material's state.
#[tokio::test]
async fn every_unusable_state_drives_the_unit_to_read_openbao() {
    for (label, seed) in unusable_seeds() {
        let deployment = Deployment::new();
        deployment.seed_both_pairs();
        seed(&deployment);
        let before = deployment.snapshot();

        let err = ensure_registrar_surface_certificates(&deployment.settings, false)
            .await
            .expect_err("an unusable pair drives an issuance, which this deployment cannot reach");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains("bootroot-internal") || rendered.contains("root fingerprint"),
            "{label}: the failure is the credentialed read, not a refusal over the material: \
             {rendered}"
        );
        // The two pairs are independent, and the credentialed read
        // happens before anything is written: the pair that was still
        // usable is untouched, and so is the one that was not.
        assert_eq!(
            deployment.snapshot(),
            before,
            "{label}: nothing is written before the ACME inputs are read"
        );
    }
}

/// One seeding function per unusable state, applied to an already-usable
/// deployment.
#[allow(clippy::type_complexity)]
fn unusable_seeds() -> Vec<(&'static str, Box<dyn Fn(&Deployment)>)> {
    vec![
        (
            "absent",
            Box::new(|d: &Deployment| {
                std::fs::remove_file(&d.client_cert).expect("remove");
            }),
        ),
        (
            "malformed",
            Box::new(|d: &Deployment| {
                std::fs::write(&d.client_cert, "-----BEGIN CERTIFICATE-----\nbroken\n")
                    .expect("write");
            }),
        ),
        (
            "key-mismatched",
            Box::new(|d: &Deployment| {
                let (_, key) = issue_leaf_pem(&d.ca, &client_name(), (2020, 1, 1), (2099, 1, 1));
                std::fs::write(&d.client_key, key).expect("write");
            }),
        ),
        (
            "san-mismatched",
            Box::new(|d: &Deployment| {
                let (leaf, key) =
                    issue_leaf_pem(&d.ca, &endpoint_name(), (2020, 1, 1), (2099, 1, 1));
                std::fs::write(&d.client_cert, leaf).expect("write");
                std::fs::write(&d.client_key, key).expect("write");
            }),
        ),
        (
            "not-yet-valid",
            Box::new(|d: &Deployment| {
                let (leaf, key) = issue_leaf_pem(&d.ca, &client_name(), (2090, 1, 1), (2099, 1, 1));
                std::fs::write(&d.client_cert, leaf).expect("write");
                std::fs::write(&d.client_key, key).expect("write");
            }),
        ),
        (
            "expired",
            Box::new(|d: &Deployment| {
                let (leaf, key) = issue_leaf_pem(&d.ca, &client_name(), (2020, 1, 1), (2021, 1, 1));
                std::fs::write(&d.client_cert, leaf).expect("write");
                std::fs::write(&d.client_key, key).expect("write");
            }),
        ),
        (
            "chain-drifted",
            Box::new(|d: &Deployment| {
                let other = generate_ca("Superseded Generation");
                let (leaf, key) =
                    issue_leaf_pem(&other, &client_name(), (2020, 1, 1), (2099, 1, 1));
                std::fs::write(&d.client_cert, leaf).expect("write");
                std::fs::write(&d.client_key, key).expect("write");
            }),
        ),
        (
            "expired-server-leaf",
            Box::new(|d: &Deployment| {
                let (leaf, key) =
                    issue_leaf_pem(&d.ca, &endpoint_name(), (2020, 1, 1), (2021, 1, 1));
                std::fs::write(&d.server_cert, leaf).expect("write");
                std::fs::write(&d.server_key, key).expect("write");
            }),
        ),
    ]
}

/// A rendered internal config that fails the loader's invariants refuses
/// the start naming that path and the reason, with no name composed from
/// a guessed label.
#[tokio::test]
async fn an_unusable_internal_config_refuses_and_names_the_path() {
    let deployment = Deployment::new();
    deployment.seed_both_pairs();
    let state_file = deployment
        .settings
        .registrar
        .state_file
        .as_deref()
        .expect("state file");
    let state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state_file).expect("read state"))
            .expect("state json");
    let secrets_dir = PathBuf::from(state["secrets_dir"].as_str().expect("secrets_dir"));
    let internal = InternalPaths::new(&secrets_dir);

    for body in ["not toml at all {{{", ""] {
        std::fs::write(internal.agent_config(), body).expect("clobber internal config");
        let err = ensure_registrar_surface_certificates(&deployment.settings, false)
            .await
            .expect_err("an unusable internal config refuses the start");
        let rendered = format!("{err:#}");
        assert!(
            rendered.contains(&internal.agent_config().display().to_string()),
            "{rendered}"
        );
    }

    std::fs::remove_file(internal.agent_config()).expect("remove internal config");
    let err = ensure_registrar_surface_certificates(&deployment.settings, false)
        .await
        .expect_err("an absent internal config refuses the start");
    assert!(
        format!("{err:#}").contains(&internal.agent_config().display().to_string()),
        "{err:#}"
    );
}

/// An unreadable state file refuses the start naming the key and the
/// path, before anything is composed or requested.
#[tokio::test]
async fn an_unreadable_state_file_refuses_and_names_it() {
    let mut deployment = Deployment::new();
    deployment.seed_both_pairs();
    let missing = deployment
        .settings
        .registrar
        .state_file
        .as_deref()
        .expect("state file")
        .with_file_name("no-such-state.json");
    deployment.settings.registrar.state_file = Some(missing.clone());

    let err = ensure_registrar_surface_certificates(&deployment.settings, false)
        .await
        .expect_err("an unreadable state file refuses");
    let rendered = format!("{err:#}");
    assert!(rendered.contains("registrar.state_file"), "{rendered}");
    assert!(
        rendered.contains(&missing.display().to_string()),
        "{rendered}"
    );
}
