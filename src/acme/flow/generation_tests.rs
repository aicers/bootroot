//! The `Snapshot` publication, driven without an ACME server: the
//! three steps `issue_certificate` runs after the exchange, in their
//! order, over an [`IssuedMaterial`] built here.

use std::collections::BTreeSet;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, mpsc};

use tempfile::TempDir;

use super::*;
use crate::fs_util::generation::{
    CURRENT_LINK_NAME, GENERATIONS_DIR_NAME, PublicationPoint, republish_for_trust,
};

const REGISTRATION_ID: &str = "edge-node-01-roxyd-001";
const CERT_NAME: &str = "roxyd-cert.pem";
const KEY_NAME: &str = "roxyd-key.pem";
const BUNDLE_NAME: &str = "ca-bundle.pem";

/// One profile's configured paths under a temporary directory, with the
/// certificate and the key in separate directories so nothing passes by
/// the two happening to share one.
struct Fixture {
    _dir: TempDir,
    settings: crate::config::Settings,
    cert: PathBuf,
    key: PathBuf,
    bundle: PathBuf,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let cert = dir.path().join("certs").join(CERT_NAME);
        let key = dir.path().join("keys").join(KEY_NAME);
        let bundle = dir.path().join("trust").join(BUNDLE_NAME);
        let root = dir
            .path()
            .join("keys")
            .join(GENERATIONS_DIR_NAME)
            .join(REGISTRATION_ID);
        let mut settings = settings();
        settings.trust.ca_bundle_path = Some(bundle.clone());
        settings
            .profiles
            .push(profile(REGISTRATION_ID, &cert, &key));
        Self {
            _dir: dir,
            settings,
            cert,
            key,
            bundle,
            root,
        }
    }

    fn profile(&self) -> &crate::config::DaemonProfileSettings {
        &self.settings.profiles[0]
    }

    /// Replaces the bundle on disk the way a writer of it would have.
    fn write_bundle(&self, contents: &str) {
        std::fs::create_dir_all(self.bundle.parent().expect("bundle parent")).expect("mkdir");
        std::fs::write(&self.bundle, contents).expect("write the bundle");
    }

    /// The whole `Snapshot` publication, as `issue_certificate` runs it.
    async fn publish(&self, material: &IssuedMaterial, probe: &Probe) -> Result<()> {
        publish_snapshot(&self.settings, self.profile(), material, probe).await
    }

    /// What a reader of the configured paths sees right now.
    fn configured(&self) -> (Option<String>, Option<String>) {
        (read(&self.cert), read(&self.key))
    }

    /// The names in the generation root.
    fn entries(&self) -> BTreeSet<String> {
        entries(&self.root)
    }

    /// What `current` names, exactly as stored.
    fn current(&self) -> Option<PathBuf> {
        std::fs::read_link(self.root.join(CURRENT_LINK_NAME)).ok()
    }
}

/// What a consumer honouring the reader contract sees: `current`
/// resolved **once**, and every file read from that one generation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Snapshot {
    cert: String,
    key: String,
    bundle: Option<String>,
}

fn read_snapshot(root: &Path) -> Option<Snapshot> {
    let generation = root.join(std::fs::read_link(root.join(CURRENT_LINK_NAME)).ok()?);
    Some(Snapshot {
        cert: read(&generation.join(CERT_NAME)).expect("a generation holds its certificate"),
        key: read(&generation.join(KEY_NAME)).expect("a generation holds its key"),
        bundle: read(&generation.join(BUNDLE_NAME)),
    })
}

fn read(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

fn entries(dir: &Path) -> BTreeSet<String> {
    std::fs::read_dir(dir)
        .expect("list the directory")
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect()
}

/// Whether `name` is something a publication staged and never renamed.
fn is_staged(name: &str) -> bool {
    Path::new(name)
        .extension()
        .is_some_and(|extension| extension == "tmp")
}

fn names(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|name| (*name).to_string()).collect()
}

fn mode(path: &Path) -> u32 {
    std::fs::symlink_metadata(path)
        .expect("stat")
        .permissions()
        .mode()
        & 0o7777
}

/// A pair labelled so that a certificate and a key are each other's
/// exactly when their labels agree.
fn material(label: &str) -> IssuedMaterial {
    IssuedMaterial {
        cert_pem: format!("certificate {label}\n"),
        key_pem: PrivateKeyPem::new(format!("key {label}\n")),
        chain: Vec::new(),
    }
}

fn pair(label: &str) -> (Option<String>, Option<String>) {
    (
        Some(format!("certificate {label}\n")),
        Some(format!("key {label}\n")),
    )
}

fn snapshot(label: &str, bundle: Option<&str>) -> Snapshot {
    Snapshot {
        cert: format!("certificate {label}\n"),
        key: format!("key {label}\n"),
        bundle: bundle.map(str::to_string),
    }
}

fn profile(registration_id: &str, cert: &Path, key: &Path) -> crate::config::DaemonProfileSettings {
    crate::config::DaemonProfileSettings {
        registration_id: registration_id.to_string(),
        service_name: "roxyd".to_string(),
        instance_id: "001".to_string(),
        hostname: "edge-node-01".to_string(),
        paths: crate::config::Paths {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
        },
        daemon: crate::config::DaemonRuntimeSettings::default(),
        retry: None,
        hooks: crate::config::HookSettings::default(),
        eab: None,
        cert_group_gid: None,
    }
}

fn settings() -> crate::config::Settings {
    crate::config::Settings {
        email: "test@example.com".to_string(),
        server: "https://example.com/acme/directory".to_string(),
        domain: "trusted.domain".to_string(),
        eab: None,
        acme: crate::config::AcmeSettings {
            directory_fetch_attempts: 10,
            directory_fetch_base_delay_secs: 1,
            directory_fetch_max_delay_secs: 10,
            poll_attempts: 15,
            poll_interval_secs: 2,
            account_key_path: None,
            http_responder_url: "http://localhost:8080".to_string(),
            http_responder_hmac: "dev-hmac".into(),
            http_responder_timeout_secs: 5,
            http_responder_token_ttl_secs: 300,
        },
        retry: crate::config::RetrySettings {
            backoff_secs: vec![5, 10, 30],
        },
        trust: crate::config::TrustSettings::default(),
        scheduler: crate::config::SchedulerSettings {
            max_concurrent_issuances: 3,
        },
        profiles: Vec::new(),
        openbao: None,
        registrar_endpoint: crate::config::RegistrarEndpointSettings::default(),
        registrar: crate::config::RegistrarSettings::default(),
    }
}

/// Runs `publish` on a runtime of its own and returns what it logged.
///
/// The subscriber is the thread's default, and a current-thread runtime
/// polls the future on this thread, so the events of the async half are
/// the ones captured.
fn logs_from<F: Future>(publish: impl FnOnce() -> F) -> (F::Output, String) {
    #[derive(Clone)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let buffer = Arc::new(Mutex::new(Vec::new()));
    let writer = Captured(Arc::clone(&buffer));
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_writer(move || writer.clone())
        .finish();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    let output = tracing::subscriber::with_default(subscriber, || runtime.block_on(publish()));
    let captured = buffer.lock().unwrap().clone();
    (output, String::from_utf8(captured).unwrap())
}

/// A probe that fails the publication when it reaches `point`.
fn failing_at(point: PublicationPoint) -> Probe {
    Probe::new(move |reached| {
        if reached == point {
            anyhow::bail!("injected failure at {reached:?}");
        }
        Ok(())
    })
}

/// The race this tree exists to remove, stopped at each of its three
/// moments.
///
/// A reader that resolves `current` once always holds a pair that is
/// each other's: the previous one until the swap, the new one from the
/// swap on. The configured paths, read at the same moments, show the
/// old pair twice and then a new certificate beside an old key — the
/// state one consumer fell into for four hours.
#[tokio::test]
async fn a_reader_of_current_never_sees_a_torn_pair() {
    let fixture = Fixture::new();
    fixture
        .publish(&material("A"), &Probe::default())
        .await
        .expect("publish A");
    assert_eq!(read_snapshot(&fixture.root), Some(snapshot("A", None)));

    let seen = Arc::new(Mutex::new(Vec::new()));
    let probe = Probe::new({
        let seen = Arc::clone(&seen);
        let (root, cert, key) = (
            fixture.root.clone(),
            fixture.cert.clone(),
            fixture.key.clone(),
        );
        move |point| {
            seen.lock().unwrap().push((
                point,
                read_snapshot(&root).expect("current always resolves"),
                (read(&cert), read(&key)),
            ));
            Ok(())
        }
    });
    fixture
        .publish(&material("B"), &probe)
        .await
        .expect("publish B");

    let seen = seen.lock().unwrap().clone();
    let at = |point| {
        seen.iter()
            .find(|(reached, _, _)| *reached == point)
            .map_or_else(
                || panic!("the publication never reached {point:?}"),
                |(_, snapshot, configured)| (snapshot.clone(), configured.clone()),
            )
    };
    // (a) The new generation is fully staged and not yet named.
    assert_eq!(
        at(PublicationPoint::Staged),
        (snapshot("A", None), pair("A"))
    );
    assert_eq!(
        at(PublicationPoint::LinkStaged),
        (snapshot("A", None), pair("A"))
    );
    // (b) Swapped, with the configured pair still unwritten.
    assert_eq!(
        at(PublicationPoint::Swapped),
        (snapshot("B", None), pair("A"))
    );
    // (c) Between the configured certificate's rename and the key's.
    assert_eq!(
        at(PublicationPoint::CertificateWritten),
        (
            snapshot("B", None),
            (
                Some("certificate B\n".to_string()),
                Some("key A\n".to_string())
            )
        ),
        "the configured paths are torn here, and the generation is not"
    );
    assert_eq!(fixture.configured(), pair("B"));

    // The order the points were reached in is the order the issue
    // fixes: the generation through its swap, then the configured pair.
    let order: Vec<PublicationPoint> = seen.iter().map(|(point, _, _)| *point).collect();
    assert_eq!(
        order,
        vec![
            PublicationPoint::LockRequested,
            PublicationPoint::Staged,
            PublicationPoint::Renamed,
            PublicationPoint::LinkStaged,
            PublicationPoint::Swapped,
            PublicationPoint::CertificateWritten,
        ]
    );
}

/// `current` is a relative link to `gen-1`, whose three files carry the
/// configured basenames, the configured files' bytes and their modes.
#[tokio::test]
async fn a_generation_mirrors_the_configured_files_under_the_default_policy() {
    let fixture = Fixture::new();
    fixture.write_bundle("bundle one\n");
    fixture
        .publish(&material("A"), &Probe::default())
        .await
        .expect("publish");

    assert_eq!(fixture.current(), Some(PathBuf::from("gen-1")));
    let generation = fixture.root.join("gen-1");
    assert_eq!(
        entries(&generation),
        names(&[CERT_NAME, KEY_NAME, BUNDLE_NAME])
    );
    for (name, configured) in [
        (CERT_NAME, &fixture.cert),
        (KEY_NAME, &fixture.key),
        (BUNDLE_NAME, &fixture.bundle),
    ] {
        assert_eq!(
            std::fs::read(generation.join(name)).expect("read the copy"),
            std::fs::read(configured).expect("read the configured file"),
            "{name}"
        );
    }

    let uid = crate::fs_util::current_process_euid();
    for dir in [
        fixture.root.parent().expect("generations dir"),
        &fixture.root,
        &generation,
    ] {
        assert_eq!(mode(dir), 0o700, "{}", dir.display());
        assert_eq!(std::fs::metadata(dir).expect("stat").uid(), uid);
    }
    assert_eq!(mode(&generation.join(CERT_NAME)), 0o644);
    assert_eq!(mode(&generation.join(KEY_NAME)), 0o600);
    assert_eq!(mode(&generation.join(BUNDLE_NAME)), 0o644);
    // The copies carry the modes of the files they mirror.
    assert_eq!(mode(&generation.join(CERT_NAME)), mode(&fixture.cert));
    assert_eq!(mode(&generation.join(KEY_NAME)), mode(&fixture.key));
    for name in [CERT_NAME, KEY_NAME, BUNDLE_NAME] {
        assert_eq!(
            std::fs::metadata(generation.join(name))
                .expect("stat")
                .uid(),
            uid
        );
    }
}

/// Under a `--cert-group` policy every directory of the tree is `0750`
/// and the key `0640`, all owned by the policy's group, as the key
/// directory and the configured key are.
#[tokio::test]
async fn a_generation_takes_the_cert_group_policy() {
    let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
        // No supplementary gid to chown to in this environment; the
        // extended CI fixture provisions one.
        return;
    };
    let mut fixture = Fixture::new();
    fixture.settings.profiles[0].cert_group_gid = Some(gid);
    fixture.write_bundle("bundle one\n");
    fixture
        .publish(&material("A"), &Probe::default())
        .await
        .expect("publish");

    let generation = fixture.root.join("gen-1");
    for dir in [
        fixture.root.parent().expect("generations dir"),
        &fixture.root,
        &generation,
    ] {
        assert_eq!(mode(dir), 0o750, "{}", dir.display());
        assert_eq!(std::fs::metadata(dir).expect("stat").gid(), gid);
    }
    for (name, expected) in [(CERT_NAME, 0o644), (KEY_NAME, 0o640), (BUNDLE_NAME, 0o644)] {
        let path = generation.join(name);
        assert_eq!(mode(&path), expected, "{name}");
        assert_eq!(std::fs::metadata(&path).expect("stat").gid(), gid, "{name}");
    }
    assert_eq!(mode(&generation.join(KEY_NAME)), mode(&fixture.key));
    assert_eq!(
        std::fs::metadata(generation.join(KEY_NAME))
            .expect("stat")
            .gid(),
        std::fs::metadata(&fixture.key).expect("stat").gid()
    );
}

/// With no bundle on disk, or none configured, a generation holds the
/// pair alone.
#[tokio::test]
async fn a_generation_has_no_bundle_file_when_there_is_no_bundle() {
    let absent = Fixture::new();
    absent
        .publish(&material("A"), &Probe::default())
        .await
        .expect("publish with the bundle file absent");
    assert_eq!(
        entries(&absent.root.join("gen-1")),
        names(&[CERT_NAME, KEY_NAME])
    );

    let mut unset = Fixture::new();
    unset.settings.trust.ca_bundle_path = None;
    unset
        .publish(&material("A"), &Probe::default())
        .await
        .expect("publish with no bundle configured");
    assert_eq!(
        entries(&unset.root.join("gen-1")),
        names(&[CERT_NAME, KEY_NAME])
    );
}

/// Three publications number themselves 1, 2, 3 and keep exactly one
/// generation behind the current one.
#[tokio::test]
async fn consecutive_publications_keep_one_previous_generation() {
    let fixture = Fixture::new();
    for (label, expected) in [("A", "gen-1"), ("B", "gen-2"), ("C", "gen-3")] {
        fixture
            .publish(&material(label), &Probe::default())
            .await
            .expect("publish");
        assert_eq!(fixture.current(), Some(PathBuf::from(expected)));
    }

    assert_eq!(
        fixture.entries(),
        names(&[
            "gen-2",
            "gen-3",
            CURRENT_LINK_NAME,
            crate::publication_lock::LOCK_FILE_NAME,
        ])
    );
    assert_eq!(read_snapshot(&fixture.root), Some(snapshot("C", None)));
    // The generation a reader resolved just before the last swap is
    // still whole.
    assert_eq!(
        read(&fixture.root.join("gen-2").join(KEY_NAME)),
        Some("key B\n".to_string())
    );
}

/// Entries the publication does not own survive pruning, and names that
/// only resemble a generation are neither counted nor removed.
#[tokio::test]
async fn pruning_leaves_every_entry_that_is_not_a_generation() {
    let fixture = Fixture::new();
    fixture
        .publish(&material("A"), &Probe::default())
        .await
        .expect("publish A");
    std::fs::create_dir(fixture.root.join("gen-07")).expect("a non-canonical name");
    std::fs::write(fixture.root.join("notes"), b"operator's").expect("a stray file");

    fixture
        .publish(&material("B"), &Probe::default())
        .await
        .expect("publish B");

    assert_eq!(
        fixture.current(),
        Some(PathBuf::from("gen-2")),
        "gen-07 is not a generation and does not push the number to 8"
    );
    assert!(fixture.root.join("gen-07").is_dir());
    assert!(fixture.root.join("notes").is_file());
}

/// A publication that fails while staging, after the generation's
/// rename, or with the new link staged leaves `current` and the
/// configured pair exactly as they were, and the next one clears what it
/// left behind.
#[tokio::test]
async fn a_failed_generation_leaves_current_and_the_configured_pair_alone() {
    for point in [
        PublicationPoint::Staged,
        PublicationPoint::Renamed,
        PublicationPoint::LinkStaged,
    ] {
        let fixture = Fixture::new();
        fixture
            .publish(&material("A"), &Probe::default())
            .await
            .expect("publish A");

        let err = fixture
            .publish(&material("B"), &failing_at(point))
            .await
            .expect_err("the injected failure fails the publication");
        assert!(
            format!("{err:#}").contains("injected failure"),
            "{point:?}: {err:#}"
        );
        assert_eq!(
            fixture.current(),
            Some(PathBuf::from("gen-1")),
            "{point:?}: current keeps naming the last complete generation"
        );
        assert_eq!(read_snapshot(&fixture.root), Some(snapshot("A", None)));
        assert_eq!(
            fixture.configured(),
            pair("A"),
            "{point:?}: the configured pair is not written"
        );

        fixture
            .publish(&material("C"), &Probe::default())
            .await
            .expect("the next publication succeeds");
        let entries = fixture.entries();
        assert!(
            !entries.iter().any(|name| is_staged(name)),
            "{point:?}: {entries:?}"
        );
        assert_eq!(
            entries
                .iter()
                .filter(|name| name.starts_with("gen-"))
                .count(),
            2,
            "{point:?}: the abandoned generation is pruned: {entries:?}"
        );
        assert!(entries.contains("gen-1"), "{point:?}: {entries:?}");
        assert_eq!(read_snapshot(&fixture.root), Some(snapshot("C", None)));
        assert_eq!(fixture.configured(), pair("C"));
    }
}

/// The same three failures on a profile's very first publication leave
/// no `current` at all and no configured pair.
#[tokio::test]
async fn a_failed_first_generation_leaves_no_current() {
    for point in [
        PublicationPoint::Staged,
        PublicationPoint::Renamed,
        PublicationPoint::LinkStaged,
    ] {
        let fixture = Fixture::new();
        fixture
            .publish(&material("A"), &failing_at(point))
            .await
            .expect_err("the injected failure fails the publication");

        assert_eq!(fixture.current(), None, "{point:?}");
        assert_eq!(fixture.configured(), (None, None), "{point:?}");

        fixture
            .publish(&material("B"), &Probe::default())
            .await
            .expect("the next publication succeeds");
        let entries = fixture.entries();
        assert!(
            !entries.iter().any(|name| is_staged(name)),
            "{point:?}: {entries:?}"
        );
        assert_eq!(read_snapshot(&fixture.root), Some(snapshot("B", None)));
    }
}

/// A trust update that waits on the generation lock while a renewal
/// holds it carries forward the pair that renewal published — not the
/// one `current` named when the update started waiting.
///
/// The renewal is stopped with its generation staged and the lock held;
/// the update is let run until it is about to take the lock, which is
/// the last point at which a pair resolved too early would already have
/// been read.
#[tokio::test]
async fn a_trust_update_waiting_on_a_renewal_republishes_the_renewed_pair() {
    let fixture = Arc::new(Fixture::new());
    fixture.write_bundle("bundle one\n");
    fixture
        .publish(&material("A"), &Probe::default())
        .await
        .expect("publish A");

    let (staged_tx, staged_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel::<()>();
    let resume_rx = Mutex::new(resume_rx);
    let renewal_probe = Probe::new(move |point| {
        if point == PublicationPoint::Staged {
            staged_tx.send(()).expect("the test is listening");
            resume_rx
                .lock()
                .unwrap()
                .recv()
                .expect("the test lets the renewal go on");
        }
        Ok(())
    });
    let renewal = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { fixture.publish(&material("B"), &renewal_probe).await }
    });
    tokio::task::spawn_blocking(move || staged_rx.recv())
        .await
        .expect("join")
        .expect("the renewal staged its generation");
    assert!(
        !crate::publication_lock::is_free(&fixture.root),
        "the renewal holds the generation lock while it is stopped"
    );

    // The trust update's own write, then its republication.
    fixture.write_bundle("bundle two\n");
    let (requested_tx, requested_rx) = mpsc::channel();
    let trust_probe = Probe::new(move |point| {
        if point == PublicationPoint::LockRequested {
            requested_tx.send(()).expect("the test is listening");
        }
        Ok(())
    });
    let trust = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { republish_for_trust(&fixture.settings, &trust_probe).await }
    });
    tokio::task::spawn_blocking(move || requested_rx.recv())
        .await
        .expect("join")
        .expect("the trust update reached the lock");
    assert_eq!(
        fixture.current(),
        Some(PathBuf::from("gen-1")),
        "the renewal has not swapped yet"
    );

    resume_tx.send(()).expect("the renewal is waiting");
    renewal.await.expect("join").expect("the renewal publishes");
    trust
        .await
        .expect("join")
        .expect("the trust update publishes");

    assert_eq!(fixture.current(), Some(PathBuf::from("gen-3")));
    assert_eq!(
        read_snapshot(&fixture.root),
        Some(snapshot("B", Some("bundle two\n"))),
        "the renewal's pair, beside the bundle now on disk"
    );
    assert_eq!(fixture.configured(), pair("B"));
}

/// A trust update that lands while a profile's very first issuance holds
/// the generation lock carries that issuance's pair forward beside the
/// new bundle.
///
/// The issuance read the old bundle under the lock and is stopped before
/// `current` exists. Had the update decided there was nothing to
/// republish before taking the lock, the issuance would go on to publish
/// the old bundle and nothing would replace it until the next renewal —
/// the state of every host on its first issuance after an upgrade.
#[tokio::test]
async fn a_trust_update_during_a_first_issuance_republishes_its_pair() {
    let fixture = Arc::new(Fixture::new());
    fixture.write_bundle("bundle one\n");

    let (staged_tx, staged_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel::<()>();
    let resume_rx = Mutex::new(resume_rx);
    let issuance_probe = Probe::new(move |point| {
        if point == PublicationPoint::Staged {
            staged_tx.send(()).expect("the test is listening");
            resume_rx
                .lock()
                .unwrap()
                .recv()
                .expect("the test lets the issuance go on");
        }
        Ok(())
    });
    let issuance = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { fixture.publish(&material("A"), &issuance_probe).await }
    });
    tokio::task::spawn_blocking(move || staged_rx.recv())
        .await
        .expect("join")
        .expect("the issuance staged its generation");
    assert_eq!(
        fixture.current(),
        None,
        "the first issuance has not swapped"
    );

    fixture.write_bundle("bundle two\n");
    let (requested_tx, requested_rx) = mpsc::channel();
    let trust_probe = Probe::new(move |point| {
        if point == PublicationPoint::LockRequested {
            requested_tx.send(()).expect("the test is listening");
        }
        Ok(())
    });
    let trust = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { republish_for_trust(&fixture.settings, &trust_probe).await }
    });
    tokio::task::spawn_blocking(move || requested_rx.recv())
        .await
        .expect("join")
        .expect("the trust update waits on the lock rather than skipping the profile");
    assert_eq!(fixture.current(), None, "still no current while it waits");

    resume_tx.send(()).expect("the issuance is waiting");
    issuance
        .await
        .expect("join")
        .expect("the issuance publishes");
    trust
        .await
        .expect("join")
        .expect("the trust update publishes");

    assert_eq!(fixture.current(), Some(PathBuf::from("gen-2")));
    assert_eq!(
        read_snapshot(&fixture.root),
        Some(snapshot("A", Some("bundle two\n"))),
        "the first issuance's pair, beside the bundle now on disk"
    );
    assert_eq!(
        read(&fixture.root.join("gen-1").join(BUNDLE_NAME)),
        Some("bundle one\n".to_string()),
        "the issuance itself published the bundle it read"
    );
}

/// A trust update that reaches the lock while `current` is unusable,
/// with a renewal holding the lock, judges `current` as that renewal
/// leaves it — not as it was when the update started waiting.
///
/// `current` names a generation whose key is gone. Had the update
/// inspected it before taking the lock it would have failed; once the
/// renewal has swapped in a whole generation, the update carries that
/// one forward.
#[tokio::test]
async fn a_trust_update_waiting_on_a_renewal_judges_the_renewed_current() {
    let fixture = Arc::new(Fixture::new());
    fixture.write_bundle("bundle one\n");
    fixture
        .publish(&material("A"), &Probe::default())
        .await
        .expect("publish A");
    std::fs::remove_file(fixture.root.join("gen-1").join(KEY_NAME)).expect("spoil gen-1");

    let (staged_tx, staged_rx) = mpsc::channel();
    let (resume_tx, resume_rx) = mpsc::channel::<()>();
    let resume_rx = Mutex::new(resume_rx);
    let renewal_probe = Probe::new(move |point| {
        if point == PublicationPoint::Staged {
            staged_tx.send(()).expect("the test is listening");
            resume_rx
                .lock()
                .unwrap()
                .recv()
                .expect("the test lets the renewal go on");
        }
        Ok(())
    });
    let renewal = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { fixture.publish(&material("B"), &renewal_probe).await }
    });
    tokio::task::spawn_blocking(move || staged_rx.recv())
        .await
        .expect("join")
        .expect("the renewal staged its generation");

    fixture.write_bundle("bundle two\n");
    let (requested_tx, requested_rx) = mpsc::channel();
    let trust_probe = Probe::new(move |point| {
        if point == PublicationPoint::LockRequested {
            requested_tx.send(()).expect("the test is listening");
        }
        Ok(())
    });
    let trust = tokio::spawn({
        let fixture = Arc::clone(&fixture);
        async move { republish_for_trust(&fixture.settings, &trust_probe).await }
    });
    tokio::task::spawn_blocking(move || requested_rx.recv())
        .await
        .expect("join")
        .expect("the trust update reached the lock");
    assert_eq!(
        fixture.current(),
        Some(PathBuf::from("gen-1")),
        "current is still the unusable generation while the update waits"
    );

    resume_tx.send(()).expect("the renewal is waiting");
    renewal.await.expect("join").expect("the renewal publishes");
    trust
        .await
        .expect("join")
        .expect("the renewed current is usable");

    assert_eq!(fixture.current(), Some(PathBuf::from("gen-3")));
    assert_eq!(
        read_snapshot(&fixture.root),
        Some(snapshot("B", Some("bundle two\n")))
    );
}

/// A failed profile does not stop a trust update: every eligible
/// profile is attempted, the first failure is the one returned, each is
/// logged, and a usable profile after them still gets the new bundle
/// beside its own pair.
#[test]
fn a_trust_update_attempts_every_profile_and_returns_the_first_failure() {
    let dir = TempDir::new().expect("tempdir");
    let bundle = dir.path().join("trust").join(BUNDLE_NAME);
    let mut settings = settings();
    settings.trust.ca_bundle_path = Some(bundle.clone());
    for (index, id) in ["first", "second", "usable"].into_iter().enumerate() {
        let mut profile = profile(
            id,
            &dir.path().join("certs").join(format!("{id}-{CERT_NAME}")),
            &dir.path().join("keys").join(format!("{id}-{KEY_NAME}")),
        );
        profile.instance_id = format!("00{}", index + 1);
        settings.profiles.push(profile);
    }
    let root = |id: &str| dir.path().join("keys").join(GENERATIONS_DIR_NAME).join(id);

    let (result, logs) = logs_from(|| async {
        std::fs::create_dir_all(bundle.parent().expect("bundle parent")).expect("mkdir");
        std::fs::write(&bundle, "bundle one\n").expect("write the bundle");
        for (profile, label) in settings.profiles.iter().zip(["F", "S", "U"]) {
            publish_snapshot(&settings, profile, &material(label), &Probe::default())
                .await
                .expect("the first issuance");
        }
        // The first profile's generation is gone; the second's has lost
        // its certificate.
        std::fs::remove_dir_all(root("first").join("gen-1")).expect("spoil first");
        std::fs::remove_file(
            root("second")
                .join("gen-1")
                .join(format!("second-{CERT_NAME}")),
        )
        .expect("spoil second");
        std::fs::write(&bundle, "bundle two\n").expect("the trust update's bundle");
        republish_for_trust(&settings, &Probe::default()).await
    });

    let first = crate::config::profile_domain(&settings, &settings.profiles[0]);
    let second = crate::config::profile_domain(&settings, &settings.profiles[1]);
    let message = format!("{:#}", result.expect_err("the failures are returned"));
    assert!(message.contains(&first), "{message}");
    assert!(
        message.contains(&root("first").join("gen-1").display().to_string()),
        "{message}"
    );
    assert!(!message.contains(&second), "{message}");
    assert!(logs.contains(&first), "{logs}");
    assert!(logs.contains(&second), "{logs}");
    assert!(
        logs.contains(
            &root("second")
                .join("gen-1")
                .join(format!("second-{CERT_NAME}"))
                .display()
                .to_string()
        ),
        "{logs}"
    );

    for id in ["first", "second"] {
        assert_eq!(
            std::fs::read_link(root(id).join(CURRENT_LINK_NAME)).ok(),
            Some(PathBuf::from("gen-1")),
            "{id}"
        );
        assert!(!root(id).join("gen-2").exists(), "{id}");
    }
    let usable = root("usable").join("gen-2");
    assert_eq!(
        std::fs::read_link(root("usable").join(CURRENT_LINK_NAME)).ok(),
        Some(PathBuf::from("gen-2"))
    );
    assert_eq!(
        read(&usable.join(format!("usable-{CERT_NAME}"))),
        Some("certificate U\n".to_string())
    );
    assert_eq!(
        read(&usable.join(format!("usable-{KEY_NAME}"))),
        Some("key U\n".to_string())
    );
    assert_eq!(
        read(&usable.join(BUNDLE_NAME)),
        Some("bundle two\n".to_string())
    );
}

/// A failure to flush the swap of `current` comes after the commit
/// point, so the publication goes on: `current` keeps the new
/// generation, and the configured pair is written as on success.
#[tokio::test]
async fn a_failed_flush_after_the_swap_still_publishes() {
    let fixture = Fixture::new();
    fixture
        .publish(&material("A"), &Probe::default())
        .await
        .expect("publish A");

    fixture
        .publish(&material("B"), &failing_at(PublicationPoint::Swapped))
        .await
        .expect("a failure after the swap does not fail the publication");

    assert_eq!(fixture.current(), Some(PathBuf::from("gen-2")));
    assert_eq!(read_snapshot(&fixture.root), Some(snapshot("B", None)));
    assert_eq!(
        fixture.configured(),
        pair("B"),
        "the configured pair is not left behind a live generation"
    );
    assert_eq!(
        fixture.entries(),
        names(&[
            "gen-1",
            "gen-2",
            CURRENT_LINK_NAME,
            crate::publication_lock::LOCK_FILE_NAME,
        ])
    );
}

/// A trust update on a profile with no `current` creates nothing — not
/// a generation, not a lock file, not the tree.
#[tokio::test]
async fn a_trust_update_creates_no_tree_for_a_profile_without_one() {
    let fixture = Fixture::new();
    fixture.write_bundle("bundle one\n");

    republish_for_trust(&fixture.settings, &Probe::default())
        .await
        .expect("nothing to republish is not a failure");

    assert!(!fixture.root.exists());
    assert!(
        !fixture
            .key
            .parent()
            .expect("key dir")
            .join(GENERATIONS_DIR_NAME)
            .exists()
    );
}

/// The ordinary service issuance publishes a generation; nothing else
/// does unless it says so.
#[test]
fn the_default_issuance_publishes_a_generation() {
    assert_eq!(
        IssuanceOptions::default().generation,
        GenerationPublication::Snapshot
    );
    assert_eq!(
        GenerationPublication::default(),
        GenerationPublication::Snapshot
    );
}

/// The registrar surface's publication, `publish_issued_material`,
/// writes the bundle and the pair and no generation tree.
#[tokio::test]
async fn the_registrar_publication_creates_no_generation_tree() {
    let fixture = Fixture::new();
    publish_issued_material(&fixture.settings, fixture.profile(), &material("A"))
        .await
        .expect("publish");

    assert_eq!(fixture.configured(), pair("A"));
    assert_eq!(
        entries(fixture.key.parent().expect("key dir")),
        names(&[KEY_NAME])
    );
}

/// Two configured paths sharing a file name cannot both live in one
/// generation directory, so no generation is published — with a warning
/// naming the profile — and the issuance succeeds as it always has.
#[test]
fn coinciding_basenames_publish_no_generation_and_still_issue() {
    let dir = TempDir::new().expect("tempdir");
    let cert = dir.path().join("certs").join("roxyd.pem");
    let key = dir.path().join("keys").join("roxyd.pem");
    let mut settings = settings();
    settings
        .profiles
        .push(profile(REGISTRATION_ID, &cert, &key));

    let (issued, probe) = (material("A"), Probe::default());
    let (published, logs) =
        logs_from(|| publish_snapshot(&settings, &settings.profiles[0], &issued, &probe));
    published.expect("the issuance succeeds as before");

    assert_eq!((read(&cert), read(&key)), pair("A"));
    assert_eq!(
        entries(key.parent().expect("key dir")),
        names(&["roxyd.pem"])
    );
    assert!(logs.contains("WARN"), "{logs}");
    assert!(
        logs.contains(
            "No generation is published for profile \
             '001.roxyd.edge-node-01.trusted.domain'"
        ),
        "{logs}"
    );
    assert!(logs.contains("share a file name"), "{logs}");
}

/// The bundle's name colliding with the key's is the same refusal.
#[test]
fn a_bundle_named_like_the_key_publishes_no_generation() {
    let dir = TempDir::new().expect("tempdir");
    let mut settings = settings();
    settings.trust.ca_bundle_path = Some(dir.path().join("trust").join("shared.pem"));
    settings.profiles.push(profile(
        REGISTRATION_ID,
        &dir.path().join("certs").join("cert.pem"),
        &dir.path().join("keys").join("shared.pem"),
    ));

    assert!(matches!(
        GenerationTarget::plan(&settings, &settings.profiles[0]),
        GenerationPlan::Skip(_)
    ));
}

/// Two profiles that agree on `registration_id` and key directory would
/// publish into one tree, each `current` holding only the other's
/// files. Neither gets a generation; profiles that differ in either do.
#[test]
fn profiles_sharing_one_tree_publish_no_generation() {
    let dir = TempDir::new().expect("tempdir");
    let keys = dir.path().join("keys");
    let mut settings = settings();
    settings.profiles.push(profile(
        REGISTRATION_ID,
        &keys.join("a-cert.pem"),
        &keys.join("a-key.pem"),
    ));
    settings.profiles.push(profile(
        REGISTRATION_ID,
        &keys.join("b-cert.pem"),
        &keys.join("b-key.pem"),
    ));
    for profile in &settings.profiles {
        assert!(matches!(
            GenerationTarget::plan(&settings, profile),
            GenerationPlan::Skip(_)
        ));
    }

    // Sharing a key directory alone is two trees, keyed by the id.
    settings.profiles[1].registration_id = "edge-node-01-roxyd-002".to_string();
    let roots: Vec<PathBuf> = settings
        .profiles
        .iter()
        .map(|profile| match GenerationTarget::plan(&settings, profile) {
            GenerationPlan::Publish(target) => target.root().to_path_buf(),
            GenerationPlan::Skip(reason) => panic!("unexpected skip: {reason}"),
        })
        .collect();
    assert_eq!(
        roots,
        vec![
            keys.join(GENERATIONS_DIR_NAME).join(REGISTRATION_ID),
            keys.join(GENERATIONS_DIR_NAME)
                .join("edge-node-01-roxyd-002"),
        ]
    );
}

/// A symlink where either directory of the tree belongs is refused, not
/// followed: nothing is written through it and the configured pair is
/// not written either.
#[tokio::test]
async fn a_symlink_in_place_of_the_tree_is_refused_and_not_followed() {
    for place_at_root in [false, true] {
        let fixture = Fixture::new();
        let elsewhere = fixture
            .cert
            .parent()
            .expect("cert dir")
            .parent()
            .expect("tempdir")
            .join("elsewhere");
        std::fs::create_dir(&elsewhere).expect("the link's target");
        let generations = fixture.root.parent().expect("generations dir");
        let link = if place_at_root {
            std::fs::create_dir_all(generations).expect("the shared directory");
            fixture.root.clone()
        } else {
            std::fs::create_dir_all(generations.parent().expect("key dir")).expect("key dir");
            generations.to_path_buf()
        };
        std::os::unix::fs::symlink(&elsewhere, &link).expect("plant the link");

        let err = fixture
            .publish(&material("A"), &Probe::default())
            .await
            .expect_err("a symlink in the tree is refused");

        let message = format!("{err:#}");
        assert!(message.contains(&link.display().to_string()), "{message}");
        assert!(message.contains("Remove it"), "{message}");
        assert!(
            entries(&elsewhere).is_empty(),
            "nothing was written through the link"
        );
        assert!(
            std::fs::symlink_metadata(&link)
                .expect("the link is still there")
                .file_type()
                .is_symlink()
        );
        assert_eq!(fixture.configured(), (None, None));
    }
}

/// A regular file in the tree's place is the same refusal.
#[tokio::test]
async fn a_file_in_place_of_the_tree_is_refused() {
    let fixture = Fixture::new();
    let generations = fixture.root.parent().expect("generations dir");
    std::fs::create_dir_all(generations.parent().expect("key dir")).expect("key dir");
    std::fs::write(generations, b"not a directory").expect("plant the file");

    fixture
        .publish(&material("A"), &Probe::default())
        .await
        .expect_err("a file in the tree's place is refused");

    assert_eq!(fixture.configured(), (None, None));
    assert_eq!(
        std::fs::read(generations).expect("the file is untouched"),
        b"not a directory"
    );
}

/// A symlink planted at the tree's lock file is refused, not followed:
/// a publication neither locks, writes nor creates what it points at,
/// publishes no generation, and leaves the configured pair unwritten.
/// A renewal and a trust update are refused alike.
#[tokio::test]
async fn a_symlinked_lock_file_is_refused_and_not_followed() {
    let fixture = Fixture::new();
    fixture.write_bundle("bundle one\n");
    let outside = fixture
        .cert
        .parent()
        .expect("cert dir")
        .parent()
        .expect("tempdir")
        .join("outside");
    std::fs::create_dir(&outside).expect("the link's directory");
    let existing = outside.join("existing");
    std::fs::write(&existing, b"someone else's file").expect("the link's target");
    let dangling = outside.join("dangling");
    let lock = fixture.root.join(crate::publication_lock::LOCK_FILE_NAME);
    std::fs::create_dir_all(&fixture.root).expect("the tree");

    for target in [&existing, &dangling] {
        std::os::unix::fs::symlink(target, &lock).expect("plant the link");

        let err = fixture
            .publish(&material("A"), &Probe::default())
            .await
            .expect_err("a symlinked lock file is refused");
        let message = format!("{err:#}");
        assert!(message.contains(&lock.display().to_string()), "{message}");
        assert!(message.contains("Remove it"), "{message}");

        republish_for_trust(&fixture.settings, &Probe::default())
            .await
            .expect_err("a trust update refuses it too");

        assert_eq!(fixture.configured(), (None, None));
        assert_eq!(
            fixture.entries(),
            names(&[crate::publication_lock::LOCK_FILE_NAME]),
            "no generation was published"
        );
        assert!(
            std::fs::symlink_metadata(&lock)
                .expect("the link is still there")
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(&lock).expect("remove the link");
    }

    assert_eq!(
        std::fs::read(&existing).expect("the target is untouched"),
        b"someone else's file"
    );
    assert!(
        std::fs::symlink_metadata(&dangling).is_err(),
        "nothing was created where the dangling link pointed"
    );
}

/// An agent upgraded in place has a configured pair and no tree. Its
/// first issuance creates `gen-1` from what it issued; nothing is seeded
/// from the files already there.
#[tokio::test]
async fn an_upgraded_host_starts_at_generation_one() {
    let fixture = Fixture::new();
    crate::fs_util::write_cert_and_key(
        &fixture.cert,
        &fixture.key,
        "certificate old\n",
        "key old\n",
        crate::cert_group::CertGroupPolicy::none(),
    )
    .await
    .expect("the pair an older agent left");
    assert!(!fixture.root.exists());

    fixture
        .publish(&material("A"), &Probe::default())
        .await
        .expect("publish");

    assert_eq!(fixture.current(), Some(PathBuf::from("gen-1")));
    assert_eq!(
        fixture.entries(),
        names(&[
            "gen-1",
            CURRENT_LINK_NAME,
            crate::publication_lock::LOCK_FILE_NAME
        ])
    );
    assert_eq!(read_snapshot(&fixture.root), Some(snapshot("A", None)));
}
