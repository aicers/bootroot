//! Shared material fixtures for the registrar surface's issuance tests.
//!
//! Lives beside the module rather than inside its test file because two
//! test modules need the same CA and the same two names: this module's
//! own, and the daemon's, which drives the composition boundary that
//! resolves the deployment inventory. Nothing here knows what that
//! inventory is or where it lives.

use std::path::PathBuf;

use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, KeyPair, KeyUsagePurpose,
    SanType, date_time_ymd,
};
use tempfile::TempDir;

use crate::config::{
    AcmeSettings, RegistrarEndpointSettings, RetrySettings, SchedulerSettings, Settings,
    TrustSettings,
};
use crate::registrar::{
    REGISTRAR_SURFACE_INSTANCE, registrar_client_identity, registrar_endpoint_identity,
};
use crate::secret::HmacSecret;

/// A domain of more than one label, so nothing can pass by hard-coding a
/// total label count instead of treating the domain as a suffix.
pub(crate) const TEST_DOMAIN: &str = "corp.example.internal";
/// The host label a rendered internal config would carry.
pub(crate) const TEST_HOST: &str = "bootroot-01";
/// The KV mount a state file naming a non-default one records.
pub(crate) const TEST_KV_MOUNT: &str = "bootroot-kv";
/// The HMAC that only `OpenBao` holds. Deliberately unlike the one the
/// local configuration carries.
pub(crate) const OPENBAO_HMAC: &str = "hmac-from-openbao";
/// The HMAC the daemon's own `agent.toml` carries, which must never
/// reach the responder.
pub(crate) const LOCAL_HMAC: &str = "hmac-from-agent-toml";

pub(crate) type TestCa = CertifiedIssuer<'static, KeyPair>;

// ---------------------------------------------------------------------
// Material fixtures
// ---------------------------------------------------------------------

pub(crate) fn generate_ca(common_name: &str) -> TestCa {
    let key = KeyPair::generate().expect("generate key");
    let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = rcgen::IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2099, 1, 1);
    CertifiedIssuer::self_signed(params, key).expect("self-signed CA")
}

/// Issues a leaf carrying `name` as its single DNS SAN, inside
/// `(not_before, not_after)`, and returns the leaf and key PEMs.
pub(crate) fn issue_leaf_pem(
    ca: &TestCa,
    name: &str,
    not_before: (i32, u8, u8),
    not_after: (i32, u8, u8),
) -> (String, String) {
    let key = KeyPair::generate().expect("generate key");
    let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
    params.is_ca = rcgen::IsCa::NoCa;
    params.not_before = date_time_ymd(not_before.0, not_before.1, not_before.2);
    params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
    params.subject_alt_names = vec![SanType::DnsName(
        name.to_string().try_into().expect("valid DNS SAN"),
    )];
    params
        .distinguished_name
        .push(DnType::CommonName, name.to_string());
    let leaf = params.signed_by(&key, ca).expect("issued leaf");
    (leaf.pem(), key.serialize_pem())
}

/// A pair on disk, in a temporary directory of its own.
pub(crate) struct OnDisk {
    _dir: TempDir,
    pub(crate) cert: PathBuf,
    pub(crate) key: PathBuf,
    pub(crate) bundle: PathBuf,
}

impl OnDisk {
    pub(crate) fn new(ca: &TestCa) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let cert = dir.path().join("leaf.pem");
        let key = dir.path().join("leaf.key");
        let bundle = dir.path().join("ca-bundle.pem");
        std::fs::write(&bundle, ca.pem()).expect("write bundle");
        Self {
            _dir: dir,
            cert,
            key,
            bundle,
        }
    }

    pub(crate) fn write_pair(&self, leaf_pem: &str, key_pem: &str) {
        std::fs::write(&self.cert, leaf_pem).expect("write leaf");
        std::fs::write(&self.key, key_pem).expect("write key");
    }
}

pub(crate) fn client_name() -> String {
    registrar_client_identity(REGISTRAR_SURFACE_INSTANCE, TEST_HOST, TEST_DOMAIN)
}

pub(crate) fn endpoint_name() -> String {
    registrar_endpoint_identity(REGISTRAR_SURFACE_INSTANCE, TEST_HOST, TEST_DOMAIN)
}

pub(crate) fn test_settings(directory_url: &str, responder_url: &str) -> Settings {
    Settings {
        email: "ops@example.com".to_string(),
        server: directory_url.to_string(),
        domain: TEST_DOMAIN.to_string(),
        eab: None,
        acme: AcmeSettings {
            http_responder_url: responder_url.to_string(),
            http_responder_hmac: HmacSecret::new(LOCAL_HMAC.to_string()),
            http_responder_timeout_secs: 5,
            http_responder_token_ttl_secs: 300,
            directory_fetch_attempts: 2,
            directory_fetch_base_delay_secs: 1,
            directory_fetch_max_delay_secs: 1,
            poll_attempts: 5,
            poll_interval_secs: 0,
            account_key_path: None,
        },
        retry: RetrySettings {
            backoff_secs: vec![1],
        },
        trust: TrustSettings::default(),
        scheduler: SchedulerSettings {
            max_concurrent_issuances: 1,
        },
        profiles: Vec::new(),
        openbao: None,
        registrar_endpoint: RegistrarEndpointSettings::default(),
        registrar: crate::config::RegistrarSettings::default(),
    }
}
