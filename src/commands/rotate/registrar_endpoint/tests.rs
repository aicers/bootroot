use std::cell::{Cell, RefCell};
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::os::unix::io::AsRawFd as _;

use bootroot::registrar::internal::{
    InternalAgentConfigParams, InternalPaths, render_internal_agent_config,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, date_time_ymd,
};
use rustls::pki_types::CertificateDer;
use tempfile::{TempDir, tempdir};

use super::*;
use crate::commands::trust::RotationMode;
use crate::i18n::test_messages;

const HOST: &str = "bootroot-01";
const DOMAIN: &str = "corp.example.internal";
const INTERMEDIATE_NAME: &str = "Bootroot Intermediate CA";

// ---------------------------------------------------------------------
// PKI fixtures
// ---------------------------------------------------------------------

type Ca = CertifiedIssuer<'static, KeyPair>;

/// A root and the intermediate it signed. Every generation's
/// intermediate carries the same subject name, exactly as a full
/// rotation generates it.
struct Generation {
    root: Ca,
    intermediate: Ca,
}

fn ca_params(name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::new()).expect("params");
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2099, 1, 1);
    params
}

impl Generation {
    fn new() -> Self {
        let root = CertifiedIssuer::self_signed(
            ca_params("Bootroot Root CA"),
            KeyPair::generate().expect("key"),
        )
        .expect("root");
        let intermediate = CertifiedIssuer::signed_by(
            ca_params(INTERMEDIATE_NAME),
            KeyPair::generate().expect("key"),
            &root,
        )
        .expect("intermediate");
        Self { root, intermediate }
    }

    fn root_fp(&self) -> String {
        der_sha256_hex(self.root.der().as_ref())
    }

    fn intermediate_fp(&self) -> String {
        der_sha256_hex(self.intermediate.der().as_ref())
    }

    /// Writes the root and intermediate PEM into `dir` and loads them
    /// back as the rotation would.
    fn write(&self, dir: &Path, prefix: &str) -> (PathBuf, PathBuf, CaGeneration) {
        let root = dir.join(format!("{prefix}-root.crt"));
        let intermediate = dir.join(format!("{prefix}-intermediate.crt"));
        std::fs::write(&root, self.root.pem()).expect("write root");
        std::fs::write(&intermediate, self.intermediate.pem()).expect("write intermediate");
        let generation =
            CaGeneration::load(&root, &intermediate, &test_messages()).expect("generation");
        (root, intermediate, generation)
    }

    /// Issues a leaf under this generation's intermediate and returns its
    /// chain PEM and key PEM.
    fn leaf(&self, name: &str, not_after: (i32, u8, u8)) -> (String, String) {
        let key = KeyPair::generate().expect("key");
        let mut params = CertificateParams::new(vec![name.to_string()]).expect("params");
        params.is_ca = IsCa::NoCa;
        params.not_before = date_time_ymd(2020, 1, 1);
        params.not_after = date_time_ymd(not_after.0, not_after.1, not_after.2);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let leaf = params.signed_by(&key, &self.intermediate).expect("leaf");
        (
            format!("{}{}", leaf.pem(), self.intermediate.pem()),
            key.serialize_pem(),
        )
    }
}

fn leaf_der(chain_pem: &str) -> Vec<u8> {
    first_certificate(chain_pem.as_bytes()).expect("a certificate")
}

fn write_pair(pair: &SurfacePair, (cert, key): &(String, String)) {
    std::fs::create_dir_all(pair.cert.parent().expect("parent")).expect("dir");
    std::fs::write(&pair.cert, cert).expect("write cert");
    std::fs::write(&pair.key, key).expect("write key");
}

// ---------------------------------------------------------------------
// Host fixtures
// ---------------------------------------------------------------------

/// A registrar endpoint host: a secrets directory carrying the internal
/// config with a `[registrar_endpoint]` table, and the surface paths it
/// names.
struct Host {
    dir: TempDir,
    paths: StatePaths,
    endpoint: EndpointHost,
}

impl Host {
    fn new() -> Self {
        Self::with_endpoint_table(true)
    }

    fn with_endpoint_table(table: bool) -> Self {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path().join("secrets");
        let internal = InternalPaths::new(&secrets);
        std::fs::create_dir_all(internal.dir()).expect("internal dir");
        let mut rendered = render_internal_agent_config(
            &internal,
            &InternalAgentConfigParams {
                email: "admin@example.com",
                server: "https://127.0.0.1:9000/acme/acme/directory",
                domain: DOMAIN,
                hostname: HOST,
                responder_url: "http://127.0.0.1:8080",
                responder_hmac: &"hmac".into(),
                eab_kid: None,
                eab_hmac: None,
                trusted_ca_sha256: &["00".repeat(32)],
                endpoint_tables: None,
            },
        );
        let surface = dir.path().join("surface");
        if table {
            use std::fmt::Write as _;
            write!(
                rendered,
                "\n[registrar_endpoint]\nserver_cert_path = \"{0}/endpoint.crt\"\nserver_key_path = \
                 \"{0}/endpoint.key\"\nclient_cert_path = \"{0}/client.crt\"\nclient_key_path = \
                 \"{0}/client.key\"\n",
                surface.display()
            )
            .expect("writing to a String cannot fail");
        }
        std::fs::write(internal.agent_config(), rendered).expect("write config");
        std::fs::create_dir_all(&surface).expect("surface dir");
        let paths = StatePaths::new(secrets.clone());
        let host = if table {
            EndpointHost::resolve(&secrets, &test_messages()).expect("host")
        } else {
            EndpointHost {
                pin_file: surface.join(endpoint_pin::REGISTRAR_ENDPOINT_ANCHORS_FILE),
                server: SurfacePair {
                    setting: SERVER_CERT_SETTING,
                    cert: surface.join("endpoint.crt"),
                    key: surface.join("endpoint.key"),
                },
                client: SurfacePair {
                    setting: CLIENT_CERT_SETTING,
                    cert: surface.join("client.crt"),
                    key: surface.join("client.key"),
                },
                endpoint_name: String::new(),
            }
        };
        Self {
            dir,
            paths,
            endpoint: host,
        }
    }

    fn secrets_dir(&self) -> PathBuf {
        self.dir.path().join("secrets")
    }

    /// Rewrites the internal config's `trusted_ca_sha256`.
    fn set_internal_pins(&self, pins: &[String]) {
        let internal = InternalPaths::new(&self.secrets_dir());
        let current = std::fs::read_to_string(internal.agent_config()).expect("read config");
        let next = bootroot::registrar::internal::upsert_internal_trust(&current, &internal, pins)
            .expect("upsert");
        std::fs::write(internal.agent_config(), next).expect("write config");
    }
}

fn state(phase: u8, old: &Generation, new: &Generation) -> RotationState {
    RotationState {
        mode: RotationMode::Full,
        started_at: "2026-09-30T00:00:00Z".to_string(),
        old_root_fp: old.root_fp(),
        new_root_fp: new.root_fp(),
        old_intermediate_fp: old.intermediate_fp(),
        new_intermediate_fp: new.intermediate_fp(),
        phase,
    }
}

// ---------------------------------------------------------------------
// A scripted endpoint
// ---------------------------------------------------------------------

/// An endpoint whose answers the test scripts: the chain it presents,
/// the client leaves it accepts, and whether anything answers at all.
#[derive(Default)]
struct FakeEndpoint {
    presented: RefCell<Vec<CertificateDer<'static>>>,
    accepted: RefCell<Vec<Vec<u8>>>,
    silent: Cell<bool>,
    dials: Cell<usize>,
}

impl FakeEndpoint {
    fn present(&self, chain_pem: &str) {
        *self.presented.borrow_mut() = vec![CertificateDer::from(leaf_der(chain_pem))];
    }

    fn accept_only(&self, leaves: &[&str]) {
        *self.accepted.borrow_mut() = leaves.iter().map(|pem| leaf_der(pem)).collect();
    }
}

impl EndpointDialer for FakeEndpoint {
    fn dial(
        &self,
        pair: &ProbeClientPair,
    ) -> impl std::future::Future<Output = Result<EndpointProbe, EndpointProbeError>> {
        self.dials.set(self.dials.get() + 1);
        if self.silent.get() {
            return std::future::ready(Err(EndpointProbeError::Unanswered {
                socket_path: PathBuf::from("/run/bootroot/registrar.sock"),
                source: std::io::Error::from(std::io::ErrorKind::ConnectionRefused),
            }));
        }
        let accepted = self
            .accepted
            .borrow()
            .iter()
            .any(|leaf| leaf.as_slice() == pair.leaf().as_ref());
        std::future::ready(Ok(EndpointProbe {
            presented_chain: self.presented.borrow().clone(),
            verdict: if accepted {
                ProbeVerdict::Accepted
            } else {
                ProbeVerdict::Refused
            },
        }))
    }
}

fn quick() -> WaitBudget {
    WaitBudget {
        timeout: Duration::from_millis(200),
        poll: Duration::from_millis(10),
    }
}

// ---------------------------------------------------------------------
// The pin file edits
// ---------------------------------------------------------------------

fn fp(byte: char) -> String {
    byte.to_string().repeat(64)
}

fn succession() -> [(String, String); 2] {
    [(fp('a'), fp('b')), (fp('c'), fp('d'))]
}

/// A pinned root gains the new root, and only the new root.
#[test]
fn widening_a_root_only_pin_adds_the_new_root() {
    let contents = format!("# deployment root\n{}\n", fp('a'));
    let widened = widened_pin_contents(&contents, &succession()).expect("widened");
    assert_eq!(
        widened,
        format!("# deployment root\n{}\n{}\n", fp('a'), fp('b'))
    );
}

/// A pinned intermediate gains the new intermediate, and only that.
#[test]
fn widening_an_intermediate_only_pin_adds_the_new_intermediate() {
    let contents = format!("{}\n", fp('c'));
    let widened = widened_pin_contents(&contents, &succession()).expect("widened");
    assert_eq!(widened, format!("{}\n{}\n", fp('c'), fp('d')));
}

/// Both pinned gain both, in order, and comments, blank lines and an
/// unrelated entry survive where they were. An uppercase old entry is
/// still recognised, and the new one is appended in lowercase.
#[test]
fn widening_both_pins_keeps_every_existing_line_in_order() {
    let contents = format!(
        "# anchors\n\n{}\n  {}  \n# unrelated\n{}",
        fp('a').to_uppercase(),
        fp('c'),
        fp('e')
    );
    let widened = widened_pin_contents(&contents, &succession()).expect("widened");
    assert_eq!(
        widened,
        format!(
            "# anchors\n\n{}\n  {}  \n# unrelated\n{}\n{}\n{}\n",
            fp('a').to_uppercase(),
            fp('c'),
            fp('e'),
            fp('b'),
            fp('d')
        )
    );
    assert!(endpoint_pin::parse_anchor_pins(&widened).is_ok());
}

/// Widening twice is widening once: an interrupted Phase 3 re-run does
/// not add an entry again.
#[test]
fn widening_is_idempotent() {
    let contents = format!("{}\n{}\n", fp('a'), fp('c'));
    let once = widened_pin_contents(&contents, &succession()).expect("widened");
    assert_eq!(widened_pin_contents(&once, &succession()), None);
}

/// Narrowing removes exactly the old entries whose counterparts are
/// present, keeping comments and unrelated entries.
#[test]
fn narrowing_removes_old_entries_and_keeps_everything_else() {
    let contents = format!(
        "# anchors\n{}\n{}\n# unrelated\n{}\n{}\n{}\n",
        fp('a'),
        fp('c'),
        fp('e'),
        fp('b'),
        fp('d')
    );
    let narrowed = narrowed_pin_contents(&contents, &succession())
        .expect("counterparts present")
        .expect("narrowed");
    assert_eq!(
        narrowed,
        format!(
            "# anchors\n# unrelated\n{}\n{}\n{}\n",
            fp('e'),
            fp('b'),
            fp('d')
        )
    );
    assert_eq!(
        narrowed_pin_contents(&narrowed, &succession()),
        Ok(None),
        "a resumed Phase 6 whose old entries are gone changes nothing"
    );
}

/// Root-only and intermediate-only pins narrow to the new counterpart.
#[test]
fn narrowing_a_single_pinned_anchor_leaves_its_counterpart() {
    let root_only = format!("{}\n{}\n", fp('a'), fp('b'));
    assert_eq!(
        narrowed_pin_contents(&root_only, &succession()),
        Ok(Some(format!("{}\n", fp('b'))))
    );
    let intermediate_only = format!("{}\n{}\n", fp('c'), fp('d'));
    assert_eq!(
        narrowed_pin_contents(&intermediate_only, &succession()),
        Ok(Some(format!("{}\n", fp('d'))))
    );
}

/// An old entry whose new counterpart is absent is never removed, and
/// neither is anything else: the refusal names the missing fingerprint.
#[test]
fn narrowing_refuses_with_nothing_removed_when_a_counterpart_is_missing() {
    let contents = format!("{}\n{}\n{}\n", fp('a'), fp('b'), fp('c'));
    assert_eq!(
        narrowed_pin_contents(&contents, &succession()),
        Err(fp('d'))
    );
}

/// The file on disk keeps its owner, group and mode across a widening,
/// is replaced by a fresh inode rather than rewritten in place, and a
/// resumed widening leaves it byte-identical.
#[tokio::test]
async fn widening_the_file_preserves_owner_group_and_mode() {
    let dir = tempdir().expect("tempdir");
    let pin = dir
        .path()
        .join(endpoint_pin::REGISTRAR_ENDPOINT_ANCHORS_FILE);
    std::fs::write(&pin, format!("# root\n{}\n", fp('a'))).expect("write");
    std::fs::set_permissions(&pin, std::fs::Permissions::from_mode(0o640)).expect("chmod");
    let before = std::fs::metadata(&pin).expect("stat");

    widen_pin_file(&pin, &succession(), &test_messages())
        .await
        .expect("widen");
    let after = std::fs::metadata(&pin).expect("stat");
    assert_eq!(after.mode() & 0o7777, 0o640);
    assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
    assert_ne!(after.ino(), before.ino(), "published by rename");
    let widened = std::fs::read_to_string(&pin).expect("read");
    assert_eq!(widened, format!("# root\n{}\n{}\n", fp('a'), fp('b')));

    widen_pin_file(&pin, &succession(), &test_messages())
        .await
        .expect("widen again");
    assert_eq!(std::fs::read_to_string(&pin).expect("read"), widened);
}

/// A narrowing that is refused leaves the file untouched; one that is
/// allowed keeps the owner, group and mode.
#[tokio::test]
async fn narrowing_the_file_refuses_or_preserves() {
    let dir = tempdir().expect("tempdir");
    let pin = dir
        .path()
        .join(endpoint_pin::REGISTRAR_ENDPOINT_ANCHORS_FILE);
    let only_old = format!("{}\n", fp('a'));
    std::fs::write(&pin, &only_old).expect("write");
    std::fs::set_permissions(&pin, std::fs::Permissions::from_mode(0o604)).expect("chmod");

    let err = narrow_pin_file(&pin, &succession(), &test_messages())
        .await
        .expect_err("the new root is missing");
    assert!(err.to_string().contains(&fp('b')), "{err}");
    assert!(
        err.to_string().contains(&pin.display().to_string()),
        "{err}"
    );
    assert_eq!(std::fs::read_to_string(&pin).expect("read"), only_old);

    std::fs::write(&pin, format!("{}\n{}\n", fp('a'), fp('b'))).expect("write");
    narrow_pin_file(&pin, &succession(), &test_messages())
        .await
        .expect("narrow");
    assert_eq!(
        std::fs::read_to_string(&pin).expect("read"),
        format!("{}\n", fp('b'))
    );
    assert_eq!(
        std::fs::metadata(&pin).expect("stat").mode() & 0o7777,
        0o604
    );
}

/// A rotation never creates the pin file.
#[tokio::test]
async fn an_absent_pin_file_is_never_created() {
    let dir = tempdir().expect("tempdir");
    let pin = dir
        .path()
        .join(endpoint_pin::REGISTRAR_ENDPOINT_ANCHORS_FILE);
    assert!(
        widen_pin_file(&pin, &succession(), &test_messages())
            .await
            .is_err()
    );
    assert!(
        narrow_pin_file(&pin, &succession(), &test_messages())
            .await
            .is_err()
    );
    assert!(!pin.exists());
}

// ---------------------------------------------------------------------
// Phase 0
// ---------------------------------------------------------------------

/// The pin file is found beside the client certificate the internal
/// config names, and the endpoint name is composed from its host label.
#[test]
fn the_endpoint_host_is_read_from_the_internal_config() {
    let host = Host::new();
    assert_eq!(
        host.endpoint.pin_file,
        host.dir
            .path()
            .join("surface")
            .join(endpoint_pin::REGISTRAR_ENDPOINT_ANCHORS_FILE)
    );
    assert_eq!(
        host.endpoint.endpoint_name,
        registrar_endpoint_identity(REGISTRAR_SURFACE_INSTANCE, HOST, DOMAIN)
    );
}

/// An internal config with no `client_cert_path` is refused, naming the
/// key and the file.
#[test]
fn phase0_refuses_an_internal_config_without_client_cert_path() {
    let host = Host::with_endpoint_table(false);
    let err = EndpointHost::resolve(&host.secrets_dir(), &test_messages())
        .expect_err("no [registrar_endpoint] table");
    let text = err.to_string();
    assert!(
        text.contains("[registrar_endpoint] client_cert_path"),
        "{text}"
    );
    assert!(text.contains("agent.toml"), "{text}");
}

/// An absent pin file is refused, naming it.
#[test]
fn phase0_refuses_an_absent_pin_file() {
    let host = Host::new();
    let accepted = [fp('a'), fp('c')];
    let err =
        check_pin_file(&host.endpoint.pin_file, &accepted, &test_messages()).expect_err("absent");
    assert!(
        err.to_string()
            .contains(&host.endpoint.pin_file.display().to_string())
    );
}

/// A pin file that does not parse is refused, naming it.
#[test]
fn phase0_refuses_a_malformed_pin_file() {
    let host = Host::new();
    std::fs::write(&host.endpoint.pin_file, "not a digest\n").expect("write");
    let err = check_pin_file(
        &host.endpoint.pin_file,
        &[fp('a'), fp('c')],
        &test_messages(),
    )
    .expect_err("malformed");
    assert!(
        err.to_string()
            .contains(&host.endpoint.pin_file.display().to_string())
    );
}

/// Which generation the pin file must name follows the recorded phase:
/// the current one on a fresh rotation, the old one before Phase 3 is
/// recorded, and the new one from then on.
#[test]
fn phase0_accepts_the_generation_the_recorded_phase_calls_for() {
    let old = Generation::new();
    let new = Generation::new();
    let messages = test_messages();
    let host = Host::new();
    let pin = &host.endpoint.pin_file;

    // Fresh: the current pair.
    std::fs::write(pin, format!("{}\n", old.root_fp())).expect("write");
    let fresh = phase0_accepted_fingerprints(None, &old.root_fp(), &old.intermediate_fp());
    check_pin_file(pin, &fresh, &messages).expect("the current root is pinned");
    std::fs::write(pin, format!("{}\n", fp('e'))).expect("write");
    let err = check_pin_file(pin, &fresh, &messages).expect_err("nothing usable");
    assert!(err.to_string().contains(&pin.display().to_string()));

    // Resumed before Phase 3 is recorded: the old generation.
    let before_three = state(2, &old, &new);
    let accepted = phase0_accepted_fingerprints(Some(&before_three), "", "");
    std::fs::write(pin, format!("{}\n", old.intermediate_fp())).expect("write");
    check_pin_file(pin, &accepted, &messages).expect("the old intermediate is pinned");
    std::fs::write(pin, format!("{}\n", new.root_fp())).expect("write");
    assert!(check_pin_file(pin, &accepted, &messages).is_err());

    // From Phase 3 on: the new generation. A file naming only the old
    // root — a resumed Phase 6 whose Phase 3 widening never landed — is
    // refused; one naming only the new generation — a Phase 6 that
    // removed the old entries and was interrupted before recording
    // itself — passes.
    let from_three = state(5, &old, &new);
    let accepted = phase0_accepted_fingerprints(Some(&from_three), "", "");
    std::fs::write(pin, format!("{}\n", old.root_fp())).expect("write");
    assert!(check_pin_file(pin, &accepted, &messages).is_err());
    std::fs::write(pin, format!("{}\n", new.root_fp())).expect("write");
    check_pin_file(pin, &accepted, &messages).expect("the new root is pinned");
}

/// A fresh rotation checks the current client pair and preserves it
/// root-owned-style: `0700` directory, `0600` files, byte-identical.
#[tokio::test]
async fn phase0_preserves_the_current_client_pair() {
    let host = Host::new();
    let current = Generation::new();
    let (_, _, generation) = current.write(host.dir.path(), "current");
    let pair = current.leaf("client", (2099, 1, 1));
    write_pair(&host.endpoint.client, &pair);

    preserve_retired_pair(
        &host.endpoint.client,
        &host.paths,
        &generation,
        RetiredOwner::current_process(),
        &test_messages(),
    )
    .await
    .expect("preserved");

    let retired = host.paths.registrar_client_retired();
    assert_eq!(
        std::fs::metadata(&retired).expect("stat").mode() & 0o7777,
        0o700
    );
    for (name, expected) in [(RETIRED_CERT_FILE, &pair.0), (RETIRED_KEY_FILE, &pair.1)] {
        let path = retired.join(name);
        assert_eq!(
            std::fs::metadata(&path).expect("stat").mode() & 0o7777,
            0o600
        );
        assert_eq!(&std::fs::read_to_string(&path).expect("read"), expected);
    }
    assert!(!host.paths.registrar_client_retired_staging().exists());
}

/// A fresh rotation replaces a retired pair a previous rotation left.
#[tokio::test]
async fn phase0_replaces_an_existing_retired_pair_on_a_fresh_rotation() {
    let host = Host::new();
    let current = Generation::new();
    let (_, _, generation) = current.write(host.dir.path(), "current");
    let stale = host.paths.registrar_client_retired();
    std::fs::create_dir_all(&stale).expect("stale dir");
    std::fs::write(stale.join(RETIRED_CERT_FILE), "stale").expect("stale");
    let pair = current.leaf("client", (2099, 1, 1));
    write_pair(&host.endpoint.client, &pair);

    preserve_retired_pair(
        &host.endpoint.client,
        &host.paths,
        &generation,
        RetiredOwner::current_process(),
        &test_messages(),
    )
    .await
    .expect("preserved");
    assert_eq!(
        std::fs::read_to_string(stale.join(RETIRED_CERT_FILE)).expect("read"),
        pair.0
    );
}

/// Each of the three checks refuses the rotation and names itself.
#[tokio::test]
async fn phase0_refuses_a_client_pair_that_fails_a_check() {
    let messages = test_messages();
    let current = Generation::new();
    let foreign = Generation::new();

    let cases: Vec<(&str, (String, String), String)> = vec![
        (
            "key",
            {
                let (cert, _) = current.leaf("client", (2099, 1, 1));
                let (_, other_key) = current.leaf("client", (2099, 1, 1));
                (cert, other_key)
            },
            messages.rotate_endpoint_check_key_match(""),
        ),
        (
            "validity",
            current.leaf("client", (2021, 1, 1)),
            messages.rotate_endpoint_check_validity().to_string(),
        ),
        (
            "chain",
            foreign.leaf("client", (2099, 1, 1)),
            messages.rotate_endpoint_check_chain().to_string(),
        ),
    ];
    for (label, pair, check) in cases {
        let host = Host::new();
        let (_, _, generation) = current.write(host.dir.path(), "current");
        write_pair(&host.endpoint.client, &pair);
        let err = preserve_retired_pair(
            &host.endpoint.client,
            &host.paths,
            &generation,
            RetiredOwner::current_process(),
            &messages,
        )
        .await
        .expect_err(label);
        let prefix = check.split(" (").next().expect("prefix");
        assert!(err.to_string().contains(prefix), "{label}: {err}");
        assert!(
            !host.paths.registrar_client_retired().exists(),
            "{label}: nothing is preserved"
        );
    }
}

/// An interrupted copy leaves only the certificate in the staging
/// directory. The next Phase 0 removes it; a fresh run copies again, and
/// a resumed run finds no complete pair and treats it as absent.
#[tokio::test]
async fn an_interrupted_copy_is_swept_and_never_taken_for_a_pair() {
    let host = Host::new();
    let current = Generation::new();
    let (_, _, generation) = current.write(host.dir.path(), "current");
    let pair = current.leaf("client", (2099, 1, 1));
    write_pair(&host.endpoint.client, &pair);
    let staging = host.paths.registrar_client_retired_staging();
    std::fs::create_dir_all(&staging).expect("staging");
    std::fs::write(staging.join(RETIRED_CERT_FILE), &pair.0).expect("half a copy");

    // Resumed: the staging directory is removed and no pair is found.
    sweep_retired_staging(&host.paths, &test_messages()).expect("sweep");
    assert!(!staging.exists());
    assert!(matches!(
        assess_retired_pair(&host.paths, &generation, &test_messages()),
        RetiredPair::Unusable(_)
    ));

    // Fresh: the copy is made again, whole.
    preserve_retired_pair(
        &host.endpoint.client,
        &host.paths,
        &generation,
        RetiredOwner::current_process(),
        &test_messages(),
    )
    .await
    .expect("preserved");
    assert!(matches!(
        assess_retired_pair(&host.paths, &generation, &test_messages()),
        RetiredPair::Usable(_)
    ));
}

/// The copy is taken under the publication lock: a writer holding it
/// makes the copy wait.
#[tokio::test]
async fn phase0_takes_the_publication_lock_for_the_client_pair() {
    let host = Host::new();
    let current = Generation::new();
    let (_, _, generation) = current.write(host.dir.path(), "current");
    let pair = current.leaf("client", (2099, 1, 1));
    write_pair(&host.endpoint.client, &pair);

    let guard = bootroot::publication_lock::hold(&[&host.endpoint.client.cert])
        .await
        .expect("lock");
    let messages = test_messages();
    let copy = preserve_retired_pair(
        &host.endpoint.client,
        &host.paths,
        &generation,
        RetiredOwner::current_process(),
        &messages,
    );
    tokio::pin!(copy);
    tokio::select! {
        _ = &mut copy => panic!("the copy must wait for the lock"),
        () = tokio::time::sleep(Duration::from_millis(200)) => {}
    }
    assert!(!host.paths.registrar_client_retired().exists());
    drop(guard);
    copy.await.expect("preserved once the lock is free");
    assert!(host.paths.registrar_client_retired().exists());
}

// ---------------------------------------------------------------------
// The surface migration check
// ---------------------------------------------------------------------

/// A leaf signed by the new intermediate passes; a leaf signed by an old
/// intermediate with the same subject name but a different key fails,
/// although its issuer name is the new intermediate's; an absent leaf
/// fails.
#[test]
fn the_surface_check_is_a_signature_check_not_a_name_check() {
    let dir = tempdir().expect("tempdir");
    let old = Generation::new();
    let new = Generation::new();
    let (_, _, new_generation) = new.write(dir.path(), "new");

    let moved = dir.path().join("moved.crt");
    std::fs::write(&moved, new.leaf("endpoint", (2099, 1, 1)).0).expect("write");
    assert!(surface_leaf_moved(&moved, &new_generation));

    let stale = dir.path().join("stale.crt");
    let stale_pem = old.leaf("endpoint", (2099, 1, 1)).0;
    std::fs::write(&stale, &stale_pem).expect("write");
    let stale_der = leaf_der(&stale_pem);
    let (_, stale_leaf) = X509Certificate::from_der(&stale_der).expect("parse");
    let new_intermediate_der = new.intermediate.der().as_ref().to_vec();
    let (_, new_intermediate) = X509Certificate::from_der(&new_intermediate_der).expect("parse");
    assert_eq!(
        stale_leaf.issuer(),
        new_intermediate.subject(),
        "the old leaf's issuer name is the new intermediate's"
    );
    assert!(!surface_leaf_moved(&stale, &new_generation));

    assert!(!surface_leaf_moved(
        &dir.path().join("absent.crt"),
        &new_generation
    ));
}

/// Unmigrated leaves are named by their `[registrar_endpoint]` key.
#[test]
fn unmigrated_surface_leaves_are_named_by_key() {
    let host = Host::new();
    let new = Generation::new();
    let (_, _, generation) = new.write(host.dir.path(), "new");
    assert_eq!(
        unmigrated_surface_leaves(&host.endpoint, &generation),
        vec![
            SERVER_CERT_SETTING.to_string(),
            CLIENT_CERT_SETTING.to_string()
        ]
    );
    write_pair(&host.endpoint.server, &new.leaf("endpoint", (2099, 1, 1)));
    assert_eq!(
        unmigrated_surface_leaves(&host.endpoint, &generation),
        vec![CLIENT_CERT_SETTING.to_string()]
    );
}

// ---------------------------------------------------------------------
// Phase 5
// ---------------------------------------------------------------------

/// Reports whether another process could take the publication lock in
/// `dir` right now, without waiting.
fn lock_is_free(dir: &Path) -> bool {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(bootroot::publication_lock::LOCK_FILE_NAME))
        .expect("open the lock file");
    // SAFETY: `flock` is called on a descriptor this function owns and
    // keeps open for the duration of the call.
    let taken = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0;
    if taken {
        // SAFETY: as above.
        unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    }
    taken
}

/// An unmoved pair is removed under the publication lock — a writer
/// holding it makes the removal wait — the lock is free again by the time
/// the daemon is signalled, and the signal is sent once.
#[tokio::test]
async fn phase5_removes_under_the_lock_and_signals_after_releasing_it() {
    let host = Host::new();
    let old = Generation::new();
    let new = Generation::new();
    let (_, _, new_generation) = new.write(host.dir.path(), "new");
    write_pair(&host.endpoint.server, &old.leaf("endpoint", (2099, 1, 1)));
    write_pair(&host.endpoint.client, &old.leaf("client", (2099, 1, 1)));
    let surface = host
        .endpoint
        .client
        .cert
        .parent()
        .expect("dir")
        .to_path_buf();

    let endpoint = FakeEndpoint::default();
    let reissued_server = new.leaf("endpoint", (2099, 1, 1));
    let reissued_client = new.leaf("client", (2099, 1, 1));
    let signals = Cell::new(0);
    let messages = test_messages();

    let guard = bootroot::publication_lock::hold(&[&host.endpoint.server.cert])
        .await
        .expect("lock");
    let phase5 = move_surface_leaves(
        &host.endpoint,
        &new_generation,
        &endpoint,
        || {
            assert!(lock_is_free(&surface), "the lock is released first");
            signals.set(signals.get() + 1);
            // The daemon's reload: re-issue both and serve the new chain.
            write_pair(&host.endpoint.server, &reissued_server);
            write_pair(&host.endpoint.client, &reissued_client);
            endpoint.present(&reissued_server.0);
            endpoint.accept_only(&[&reissued_client.0]);
            Ok(())
        },
        quick(),
        &messages,
    );
    tokio::pin!(phase5);
    tokio::select! {
        _ = &mut phase5 => panic!("the removal must wait for the lock"),
        () = tokio::time::sleep(Duration::from_millis(200)) => {}
    }
    assert!(
        host.endpoint.server.cert.exists(),
        "nothing removed while locked"
    );
    assert_eq!(signals.get(), 0);
    drop(guard);
    phase5.await.expect("the endpoint moved");
    assert_eq!(signals.get(), 1);
}

/// A pair renewal publishes under the new generation while Phase 5 waits
/// for the publication lock is seen as moved once Phase 5 holds the lock,
/// and kept: the decision is made under the lock, not before it.
#[tokio::test]
async fn phase5_keeps_a_pair_renewal_moved_while_it_waited_for_the_lock() {
    let host = Host::new();
    let old = Generation::new();
    let new = Generation::new();
    let (_, _, new_generation) = new.write(host.dir.path(), "new");
    // The server pair has already moved, so the client pair is the first
    // Phase 5 decides about, and it decides while renewal holds the lock.
    let server = new.leaf("endpoint", (2099, 1, 1));
    write_pair(&host.endpoint.server, &server);
    write_pair(&host.endpoint.client, &old.leaf("client", (2099, 1, 1)));

    let endpoint = FakeEndpoint::default();
    endpoint.present(&server.0);
    let renewed_client = new.leaf("client", (2099, 1, 1));
    let messages = test_messages();

    // Renewal holds the lock for the client pair's destinations.
    let renewal = bootroot::publication_lock::hold(&[&host.endpoint.client.cert])
        .await
        .expect("lock");
    let phase5 = move_surface_leaves(
        &host.endpoint,
        &new_generation,
        &endpoint,
        || {
            assert_eq!(
                std::fs::read_to_string(&host.endpoint.client.cert).expect("client kept"),
                renewed_client.0,
                "the renewed client pair survives Phase 5"
            );
            endpoint.accept_only(&[&renewed_client.0]);
            Ok(())
        },
        quick(),
        &messages,
    );
    tokio::pin!(phase5);
    tokio::select! {
        _ = &mut phase5 => panic!("Phase 5 must wait for the lock"),
        () = tokio::time::sleep(Duration::from_millis(200)) => {}
    }
    // Renewal publishes the new-generation client pair, then releases.
    write_pair(&host.endpoint.client, &renewed_client);
    drop(renewal);
    phase5.await.expect("the endpoint moved");
    assert_eq!(
        std::fs::read_to_string(&host.endpoint.client.cert).expect("read"),
        renewed_client.0
    );
    assert_eq!(
        std::fs::read_to_string(&host.endpoint.client.key).expect("read"),
        renewed_client.1
    );
}

/// A pair already under the new generation is left alone — a resumed
/// Phase 5 does not remove what the previous run moved — and the daemon
/// is still signalled and waited for.
#[tokio::test]
async fn phase5_leaves_a_moved_pair_alone_and_waits_again() {
    let host = Host::new();
    let new = Generation::new();
    let (_, _, new_generation) = new.write(host.dir.path(), "new");
    let server = new.leaf("endpoint", (2099, 1, 1));
    let client = new.leaf("client", (2099, 1, 1));
    write_pair(&host.endpoint.server, &server);
    write_pair(&host.endpoint.client, &client);
    let endpoint = FakeEndpoint::default();
    endpoint.present(&server.0);
    endpoint.accept_only(&[&client.0]);
    let signals = Cell::new(0);

    move_surface_leaves(
        &host.endpoint,
        &new_generation,
        &endpoint,
        || {
            signals.set(signals.get() + 1);
            Ok(())
        },
        quick(),
        &test_messages(),
    )
    .await
    .expect("already moved");
    assert_eq!(signals.get(), 1);
    assert_eq!(
        std::fs::read_to_string(&host.endpoint.server.cert).expect("read"),
        server.0
    );
    assert!(endpoint.dials.get() >= 1, "the live chain is still checked");
}

/// Three ways Phase 5's wait can fail, each named: the daemon never
/// re-issued, the files are new but the live handshake still presents
/// the old chain, and nothing answers.
#[tokio::test]
async fn phase5_wait_names_each_failed_condition() {
    let messages = test_messages();
    let timeout = humantime::format_duration(quick().timeout).to_string();
    let old = Generation::new();
    let new = Generation::new();

    // Nothing re-issued.
    let host = Host::new();
    let (_, _, new_generation) = new.write(host.dir.path(), "new");
    write_pair(&host.endpoint.server, &old.leaf("endpoint", (2099, 1, 1)));
    write_pair(&host.endpoint.client, &old.leaf("client", (2099, 1, 1)));
    let endpoint = FakeEndpoint::default();
    let err = move_surface_leaves(
        &host.endpoint,
        &new_generation,
        &endpoint,
        || Ok(()),
        quick(),
        &messages,
    )
    .await
    .expect_err("not re-issued");
    assert_eq!(
        err.to_string(),
        messages.error_rotate_endpoint_surface_not_reissued(
            &format!("{SERVER_CERT_SETTING}, {CLIENT_CERT_SETTING}"),
            &timeout
        )
    );

    // Re-issued on disk, but the TLS rebuild failed: old chain served.
    let host = Host::new();
    let (_, _, new_generation) = new.write(host.dir.path(), "new");
    let old_server = old.leaf("endpoint", (2099, 1, 1));
    write_pair(&host.endpoint.server, &old_server);
    write_pair(&host.endpoint.client, &old.leaf("client", (2099, 1, 1)));
    let endpoint = FakeEndpoint::default();
    endpoint.present(&old_server.0);
    let err = move_surface_leaves(
        &host.endpoint,
        &new_generation,
        &endpoint,
        || {
            write_pair(&host.endpoint.server, &new.leaf("endpoint", (2099, 1, 1)));
            write_pair(&host.endpoint.client, &new.leaf("client", (2099, 1, 1)));
            Ok(())
        },
        quick(),
        &messages,
    )
    .await
    .expect_err("old chain");
    assert_eq!(
        err.to_string(),
        messages.error_rotate_endpoint_still_old_chain(&timeout)
    );

    // Re-issued, but nothing answers on the socket.
    let host = Host::new();
    let (_, _, new_generation) = new.write(host.dir.path(), "new");
    let endpoint = FakeEndpoint::default();
    endpoint.silent.set(true);
    let err = move_surface_leaves(
        &host.endpoint,
        &new_generation,
        &endpoint,
        || {
            write_pair(&host.endpoint.server, &new.leaf("endpoint", (2099, 1, 1)));
            write_pair(&host.endpoint.client, &new.leaf("client", (2099, 1, 1)));
            Ok(())
        },
        quick(),
        &messages,
    )
    .await
    .expect_err("silent");
    assert!(
        err.to_string().starts_with(
            messages
                .error_rotate_endpoint_unanswered("", "")
                .split(':')
                .next()
                .expect("prefix")
        ),
        "{err}"
    );
}

/// The new chain is presented but the re-issued client pair is refused:
/// Phase 5 fails unrecorded and says so, because recording it would pause
/// a rotation whose client cannot use the endpoint.
#[tokio::test]
async fn phase5_wait_requires_the_reissued_client_pair_accepted() {
    let messages = test_messages();
    let timeout = humantime::format_duration(quick().timeout).to_string();
    let new = Generation::new();

    let host = Host::new();
    let (_, _, new_generation) = new.write(host.dir.path(), "new");
    let new_server = new.leaf("endpoint", (2099, 1, 1));
    let endpoint = FakeEndpoint::default();
    let err = move_surface_leaves(
        &host.endpoint,
        &new_generation,
        &endpoint,
        || {
            write_pair(&host.endpoint.server, &new_server);
            write_pair(&host.endpoint.client, &new.leaf("client", (2099, 1, 1)));
            endpoint.present(&new_server.0);
            Ok(())
        },
        quick(),
        &messages,
    )
    .await
    .expect_err("client refused");
    assert_eq!(
        err.to_string(),
        messages.error_rotate_endpoint_reissued_client_refused(&timeout)
    );
    assert!(
        endpoint.dials.get() >= 1,
        "the refusal came from a live dial"
    );
}

// ---------------------------------------------------------------------
// Phase 6
// ---------------------------------------------------------------------

/// A rotation mid-Phase-6 on a host with a preserved retired pair, a
/// re-issued current pair and a scripted endpoint.
struct Finalizing {
    host: Host,
    old: Generation,
    new: Generation,
    old_generation: CaGeneration,
    retired: (String, String),
    current: (String, String),
}

impl Finalizing {
    async fn new() -> Self {
        let host = Host::new();
        let old = Generation::new();
        let new = Generation::new();
        let (_, _, old_generation) = old.write(host.dir.path(), "old");
        let retired = old.leaf("client", (2099, 1, 1));
        write_pair(&host.endpoint.client, &retired);
        preserve_retired_pair(
            &host.endpoint.client,
            &host.paths,
            &old_generation,
            RetiredOwner::current_process(),
            &test_messages(),
        )
        .await
        .expect("preserved");
        // The daemon renewed the client pair under the new generation
        // before Phase 5: the preserved copy is still the one in use.
        let current = new.leaf("client", (2099, 1, 1));
        write_pair(&host.endpoint.client, &current);
        Self {
            host,
            old,
            new,
            old_generation,
            retired,
            current,
        }
    }

    fn retired(&self) -> RetiredPair {
        assess_retired_pair(&self.host.paths, &self.old_generation, &test_messages())
    }
}

/// A client pair renewed under the new generation after Phase 0 leaves
/// the preserved copy in use.
#[tokio::test]
async fn the_preserved_copy_survives_a_renewal_of_the_client_pair() {
    let finalizing = Finalizing::new().await;
    let RetiredPair::Usable(pair) = finalizing.retired() else {
        panic!("the preserved pair is usable");
    };
    assert_eq!(pair.leaf().as_ref(), leaf_der(&finalizing.retired.0));
}

/// An expired or key-mismatched preserved copy is unusable.
#[tokio::test]
async fn an_expired_or_mismatched_retired_copy_is_unusable() {
    let finalizing = Finalizing::new().await;
    let dir = finalizing.host.paths.registrar_client_retired();
    let (_, other_key) = finalizing.old.leaf("client", (2099, 1, 1));
    std::fs::write(dir.join(RETIRED_KEY_FILE), other_key).expect("write");
    assert!(matches!(finalizing.retired(), RetiredPair::Unusable(_)));

    let (expired_cert, expired_key) = finalizing.old.leaf("client", (2021, 1, 1));
    std::fs::write(dir.join(RETIRED_CERT_FILE), expired_cert).expect("write");
    std::fs::write(dir.join(RETIRED_KEY_FILE), expired_key).expect("write");
    let RetiredPair::Unusable(reason) = finalizing.retired() else {
        panic!("an expired copy is unusable");
    };
    assert_eq!(reason, test_messages().rotate_endpoint_check_validity());
}

/// The retired pair is checked against the old generation read from the
/// Phase-1 backups. A backup that is gone, or that is no longer the
/// certificate the rotation recorded, makes the pair unusable — which
/// `--force` can waive — rather than failing Phase 6 outright.
#[tokio::test]
async fn a_missing_or_replaced_backup_makes_the_retired_pair_unusable() {
    let finalizing = Finalizing::new().await;
    let paths = &finalizing.host.paths;
    let state = state(5, &finalizing.old, &finalizing.new);
    std::fs::create_dir_all(paths.root_cert_bak().parent().expect("parent")).expect("dir");
    std::fs::write(paths.root_cert_bak(), finalizing.old.root.pem()).expect("write");
    std::fs::write(
        paths.intermediate_cert_bak(),
        finalizing.old.intermediate.pem(),
    )
    .expect("write");
    assert!(matches!(
        assess_recorded_retired_pair(paths, &state, &test_messages()),
        RetiredPair::Usable(_)
    ));

    std::fs::write(
        paths.intermediate_cert_bak(),
        finalizing.new.intermediate.pem(),
    )
    .expect("write");
    let RetiredPair::Unusable(reason) =
        assess_recorded_retired_pair(paths, &state, &test_messages())
    else {
        panic!("a replaced backup cannot check the chain");
    };
    assert!(reason.contains(&state.old_intermediate_fp), "{reason}");

    std::fs::remove_file(paths.intermediate_cert_bak()).expect("remove");
    assert!(matches!(
        assess_recorded_retired_pair(paths, &state, &test_messages()),
        RetiredPair::Unusable(_)
    ));
}

/// Before narrowing, the retired pair has to be accepted. A refusal
/// fails Phase 6 with nothing yet narrowed.
#[tokio::test]
async fn phase6_fails_when_the_before_dial_is_refused() {
    let finalizing = Finalizing::new().await;
    let endpoint = FakeEndpoint::default();
    endpoint.accept_only(&[&finalizing.current.0]);
    let err = prepare_refusal_proof(
        &endpoint,
        finalizing.retired(),
        false,
        false,
        &mut std::io::sink(),
        &test_messages(),
    )
    .await
    .expect_err("the retired pair was refused before narrowing");
    assert_eq!(
        err.to_string(),
        test_messages().error_rotate_endpoint_before_dial_refused()
    );
}

/// The whole proof: accepted before, then the current pair accepted and
/// the retired pair refused after narrowing.
#[tokio::test]
async fn phase6_passes_when_the_narrowing_takes_effect() {
    let finalizing = Finalizing::new().await;
    let endpoint = FakeEndpoint::default();
    endpoint.accept_only(&[&finalizing.retired.0, &finalizing.current.0]);
    let proof = prepare_refusal_proof(
        &endpoint,
        finalizing.retired(),
        false,
        false,
        &mut std::io::sink(),
        &test_messages(),
    )
    .await
    .expect("accepted before narrowing");
    assert_eq!(endpoint.dials.get(), 1);

    // The daemon reloaded onto the narrowed trust.
    endpoint.accept_only(&[&finalizing.current.0]);
    wait_for_narrowing(
        &finalizing.host.endpoint,
        &endpoint,
        &proof,
        quick(),
        &test_messages(),
    )
    .await
    .expect("narrowing proven");
}

/// After narrowing, a daemon whose reload kept the old client verifier —
/// the retired pair still accepted — and one that refuses the current
/// pair both fail Phase 6, naming the condition.
#[tokio::test]
async fn phase6_wait_names_each_failed_condition() {
    let messages = test_messages();
    let timeout = humantime::format_duration(quick().timeout).to_string();
    let finalizing = Finalizing::new().await;
    let RetiredPair::Usable(retired) = finalizing.retired() else {
        panic!("usable");
    };
    let proof = RefusalProof::Required(retired);

    let endpoint = FakeEndpoint::default();
    endpoint.accept_only(&[&finalizing.retired.0, &finalizing.current.0]);
    let err = wait_for_narrowing(
        &finalizing.host.endpoint,
        &endpoint,
        &proof,
        quick(),
        &messages,
    )
    .await
    .expect_err("old verifier kept");
    assert_eq!(
        err.to_string(),
        messages.error_rotate_endpoint_retired_still_accepted(&timeout)
    );

    let endpoint = FakeEndpoint::default();
    endpoint.accept_only(&[]);
    let err = wait_for_narrowing(
        &finalizing.host.endpoint,
        &endpoint,
        &proof,
        quick(),
        &messages,
    )
    .await
    .expect_err("current refused");
    assert_eq!(
        err.to_string(),
        messages.error_rotate_endpoint_current_not_accepted(
            messages.rotate_endpoint_pair_refused(),
            &timeout
        )
    );
}

/// A resumed Phase 6 whose trust is already narrowed does not run the
/// before-dial — it relies on the local checks — and waits again.
#[tokio::test]
async fn a_resumed_phase6_with_narrowed_trust_skips_the_before_dial() {
    let finalizing = Finalizing::new().await;
    let state = state(5, &finalizing.old, &finalizing.new);
    finalizing
        .host
        .set_internal_pins(&[state.new_root_fp.clone(), state.new_intermediate_fp.clone()]);
    let narrowed =
        internal_trust_narrowed(&finalizing.host.secrets_dir(), &state, &test_messages())
            .expect("read");
    assert!(narrowed);
    finalizing
        .host
        .set_internal_pins(&[state.old_root_fp.clone(), state.new_root_fp.clone()]);
    assert!(
        !internal_trust_narrowed(&finalizing.host.secrets_dir(), &state, &test_messages())
            .expect("read")
    );

    let endpoint = FakeEndpoint::default();
    endpoint.accept_only(&[&finalizing.current.0]);
    let proof = prepare_refusal_proof(
        &endpoint,
        finalizing.retired(),
        true,
        false,
        &mut std::io::sink(),
        &test_messages(),
    )
    .await
    .expect("local checks passed");
    assert_eq!(endpoint.dials.get(), 0, "no before-dial once narrowed");
    wait_for_narrowing(
        &finalizing.host.endpoint,
        &endpoint,
        &proof,
        quick(),
        &test_messages(),
    )
    .await
    .expect("narrowing proven");
}

/// An absent retired pair on a resume fails Phase 6 without `--force`.
/// With it, only the refusal half is waived, and the operator is warned
/// that the refusal was not proven: the current pair still has to be
/// accepted.
#[tokio::test]
async fn an_absent_retired_pair_needs_force_and_force_still_needs_the_current_pair() {
    let finalizing = Finalizing::new().await;
    remove_retired_pair(&finalizing.host.paths, &test_messages()).expect("remove");
    let endpoint = FakeEndpoint::default();
    endpoint.accept_only(&[&finalizing.current.0]);

    let RetiredPair::Unusable(reason) = finalizing.retired() else {
        panic!("an absent retired pair is unusable");
    };

    let mut warnings = Vec::new();
    let err = prepare_refusal_proof(
        &endpoint,
        finalizing.retired(),
        true,
        false,
        &mut warnings,
        &test_messages(),
    )
    .await
    .expect_err("cannot prove the refusal");
    assert!(err.to_string().contains("--force"), "{err}");
    assert!(warnings.is_empty(), "nothing is waived without --force");

    let proof = prepare_refusal_proof(
        &endpoint,
        finalizing.retired(),
        true,
        true,
        &mut warnings,
        &test_messages(),
    )
    .await
    .expect("waived");
    assert!(matches!(proof, RefusalProof::Waived));
    assert_eq!(
        String::from_utf8(warnings).expect("utf-8"),
        format!(
            "WARNING: --force given; finalizing without proof that the registrar endpoint \
             rejects the old trust ({reason}). A dial with the current client pair is still \
             required\n"
        ),
        "the operator is told the refusal was not proven"
    );
    assert_eq!(endpoint.dials.get(), 0, "an unusable pair is never dialed");
    wait_for_narrowing(
        &finalizing.host.endpoint,
        &endpoint,
        &proof,
        quick(),
        &test_messages(),
    )
    .await
    .expect("the current pair is accepted");

    endpoint.accept_only(&[]);
    assert!(
        wait_for_narrowing(
            &finalizing.host.endpoint,
            &endpoint,
            &proof,
            quick(),
            &test_messages(),
        )
        .await
        .is_err(),
        "--force never waives the current-pair dial"
    );
}

// ---------------------------------------------------------------------
// Skipping finalization
// ---------------------------------------------------------------------

/// Only an endpoint host with Phase 6 still ahead pauses on
/// `--skip finalize`.
#[test]
fn only_an_endpoint_host_pauses_before_finalize() {
    assert!(pauses_before_finalize(true, 0, true));
    assert!(pauses_before_finalize(true, 5, true));
    assert!(
        !pauses_before_finalize(true, 6, true),
        "Phase 6 already done"
    );
    assert!(!pauses_before_finalize(true, 5, false));
    assert!(
        !pauses_before_finalize(false, 5, true),
        "a host without the internal credential keeps today's behaviour"
    );
}

/// A resumed Phase 6 whose wait fails — here, a daemon that kept the old
/// client verifier — leaves the pin file exactly as it was; once the wait
/// passes, the old anchors go.
#[tokio::test]
async fn the_pin_file_is_narrowed_only_after_the_wait_passes() {
    let finalizing = Finalizing::new().await;
    let state = state(5, &finalizing.old, &finalizing.new);
    let succession = anchor_succession(&state);
    let pin = &finalizing.host.endpoint.pin_file;
    let widened = format!("# anchors\n{}\n{}\n", state.old_root_fp, state.new_root_fp);
    std::fs::write(pin, &widened).expect("write");
    let RetiredPair::Usable(retired) = finalizing.retired() else {
        panic!("usable");
    };
    let proof = RefusalProof::Required(retired);

    let endpoint = FakeEndpoint::default();
    endpoint.accept_only(&[&finalizing.retired.0, &finalizing.current.0]);
    assert!(
        finish_narrowing(
            &finalizing.host.endpoint,
            &endpoint,
            &proof,
            &succession,
            quick(),
            &test_messages(),
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read_to_string(pin).expect("read"), widened);

    endpoint.accept_only(&[&finalizing.current.0]);
    finish_narrowing(
        &finalizing.host.endpoint,
        &endpoint,
        &proof,
        &succession,
        quick(),
        &test_messages(),
    )
    .await
    .expect("narrowed");
    assert_eq!(
        std::fs::read_to_string(pin).expect("read"),
        format!("# anchors\n{}\n", state.new_root_fp)
    );
}
