use std::cell::{Cell, RefCell};
use std::fmt::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use bootroot::openbao::OpenBaoClient;
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PublicKeyData};
use tempfile::{TempDir, tempdir};

use super::super::super::test_support::{
    decode_fake_docker_log, path_tree, test_messages, write_self_contained_fake_docker,
};
use super::super::super::{INTERMEDIATE_CA_COMMON_NAME, ROOT_CA_COMMON_NAME};
use super::super::{
    LIVE_CA_TARGETS, concat_unique_ca_certs, concat_unique_ca_certs_for_repair,
    generate_intermediate_docker_args, generate_root_docker_args,
};
use super::*;
use crate::commands::trust::{
    RotationMode, create_rotation_state, load_rotation_state, update_rotation_state,
};
use crate::state::{InfraCertEntry, ReloadStrategy, StateFile};

const RESTART_POLICY: &str = "unless-stopped";

/// One CA generation as PEM: a root, an intermediate it signed, and
/// their keys, unencrypted.
struct Generation {
    root_cert: String,
    root_key: String,
    intermediate_cert: String,
    intermediate_key: String,
}

impl Generation {
    fn new() -> Self {
        let root_key = KeyPair::generate().expect("root key");
        let root_params = ca_params(ROOT_CA_COMMON_NAME);
        let root_cert = root_params
            .clone()
            .self_signed(&root_key)
            .expect("self-signed root")
            .pem();
        let root_key_pem = root_key.serialize_pem();
        let issuer = Issuer::new(root_params, root_key);
        Self::with_intermediate_of(root_cert, root_key_pem, &issuer)
    }

    /// A generation whose intermediate `issuer` signed, whatever root
    /// the generation names.
    fn with_intermediate_of(
        root_cert: String,
        root_key: String,
        issuer: &Issuer<'static, KeyPair>,
    ) -> Self {
        let intermediate_key = KeyPair::generate().expect("intermediate key");
        let intermediate_cert = ca_params(INTERMEDIATE_CA_COMMON_NAME)
            .signed_by(&intermediate_key, issuer)
            .expect("signed intermediate")
            .pem();
        Self {
            root_cert,
            root_key,
            intermediate_cert,
            intermediate_key: intermediate_key.serialize_pem(),
        }
    }

    fn root_issuer(&self) -> Issuer<'static, KeyPair> {
        Issuer::from_ca_cert_pem(
            &self.root_cert,
            KeyPair::from_pem(&self.root_key).expect("root key"),
        )
        .expect("root issuer")
    }

    fn root_fp(&self) -> String {
        fingerprint(&self.root_cert)
    }

    fn intermediate_fp(&self) -> String {
        fingerprint(&self.intermediate_cert)
    }

    /// A `PostgreSQL` server leaf this generation's intermediate signed.
    fn sign_leaf(&self) -> String {
        let issuer = Issuer::from_ca_cert_pem(
            &self.intermediate_cert,
            KeyPair::from_pem(&self.intermediate_key).expect("intermediate key"),
        )
        .expect("intermediate issuer");
        let key = KeyPair::generate().expect("leaf key");
        let mut params = CertificateParams::new(vec!["postgres".to_string()]).expect("leaf");
        params
            .distinguished_name
            .push(DnType::CommonName, "postgres");
        params.signed_by(&key, &issuer).expect("signed leaf").pem()
    }
}

fn ca_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("params");
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
}

fn fingerprint(pem: &str) -> String {
    fingerprint_ca_cert(pem.as_bytes(), Path::new("cert"), &test_messages()).expect("fingerprint")
}

/// SHA-256 of a PEM certificate's DER, computed apart from production.
fn independent_sha256_hex(pem: &str) -> String {
    let (_, block) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).expect("pem");
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &block.contents);
    let mut hex = String::new();
    for byte in digest.as_ref() {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn spki_of_pem_cert(pem: &str) -> Vec<u8> {
    let der = cert_der_from_pem(pem.as_bytes(), Path::new("cert"), &test_messages()).expect("der");
    subject_public_key_der(&der).expect("spki")
}

fn spki_of_pem_key(pem: &str) -> Vec<u8> {
    KeyPair::from_pem(pem)
        .expect("key")
        .subject_public_key_info()
}

/// A secrets directory paused after Phase 3 of a staged rotation: the
/// old generation live and in the Phase-1 backups, the new one at the
/// staging paths, and the state recording Phase 3.
struct Rig {
    dir: TempDir,
    ctx: RotateContext,
    old: Generation,
    new: Generation,
    docker_log: PathBuf,
}

impl Rig {
    fn paused() -> Self {
        let dir = tempdir().expect("tempdir");
        let secrets = dir.path().join("secrets");
        fs::create_dir_all(secrets.join("certs")).expect("certs dir");
        fs::create_dir_all(secrets.join("secrets")).expect("keys dir");
        fs::write(secrets.join("password.txt"), "pw").expect("password");
        fs::write(dir.path().join(".env"), "BOOTROOT_INSTANCE=insight\n").expect(".env");
        fs::write(
            dir.path().join("docker-compose.yml"),
            "services:\n  step-ca:\n    image: test\n",
        )
        .expect("compose file");
        let docker = dir.path().join("fake-docker");
        let docker_log = dir.path().join("docker.log");
        write_self_contained_fake_docker(&docker, &docker_log);
        fs::write(&docker_log, "").expect("seed docker log");
        let ctx = RotateContext {
            openbao_url: String::new(),
            kv_mount: "secret".to_string(),
            compose_file: dir.path().join("docker-compose.yml"),
            state: StateFile::default(),
            paths: StatePaths::new(secrets.clone()),
            state_dir: dir.path().to_path_buf(),
            state_file: dir.path().join("state.json"),
            docker,
            secrets: path_tree(&secrets),
        };
        let old = Generation::new();
        let new = Generation::new();
        let paths = &ctx.paths;
        for (path, contents) in [
            (paths.root_cert(), &old.root_cert),
            (paths.stepca_root_key(), &old.root_key),
            (paths.intermediate_cert(), &old.intermediate_cert),
            (paths.stepca_intermediate_key(), &old.intermediate_key),
            (paths.root_cert_bak(), &old.root_cert),
            (paths.root_key_bak(), &old.root_key),
            (paths.intermediate_cert_bak(), &old.intermediate_cert),
            (paths.intermediate_key_bak(), &old.intermediate_key),
            (paths.root_cert_staged(), &new.root_cert),
            (paths.root_key_staged(), &new.root_key),
            (paths.intermediate_cert_staged(), &new.intermediate_cert),
            (paths.intermediate_key_staged(), &new.intermediate_key),
        ] {
            fs::write(path, contents).expect("write CA file");
        }
        let rig = Self {
            dir,
            ctx,
            old,
            new,
            docker_log,
        };
        create_rotation_state(&rig.ctx.state_dir, &rig.state(3), &test_messages()).expect("state");
        rig
    }

    fn state(&self, phase: u8) -> RotationState {
        RotationState {
            mode: RotationMode::Full,
            started_at: "2026-11-26T00:00:00Z".to_string(),
            old_root_fp: self.old.root_fp(),
            new_root_fp: self.new.root_fp(),
            old_intermediate_fp: self.old.intermediate_fp(),
            new_intermediate_fp: self.new.intermediate_fp(),
            phase,
            staged: true,
            phase4_started: false,
            stepca_restart_policy: None,
        }
    }

    fn recorded(&self) -> RotationState {
        load_rotation_state(&self.ctx.state_dir, &test_messages())
            .expect("load")
            .expect("state present")
    }

    /// Records a `postgres` entry and puts a leaf `generation` signed at
    /// the path Phase 4 reissues.
    fn with_postgres_signed_by(mut self, generation: &Generation) -> Self {
        let cert = self.postgres_cert();
        fs::create_dir_all(cert.parent().expect("tls dir")).expect("tls dir");
        fs::write(&cert, generation.sign_leaf()).expect("postgres cert");
        self.ctx.state.infra_certs.insert(
            POSTGRES_INFRA_CERT_KEY.to_string(),
            InfraCertEntry {
                cert_path: cert.clone(),
                key_path: cert.with_file_name("server.key"),
                sans: vec!["postgres".to_string()],
                renew_before: "720h".to_string(),
                reload_strategy: ReloadStrategy::ContainerSignal {
                    container_name: "insight-postgres".to_string(),
                    signal: "SIGHUP".to_string(),
                },
                issued_at: None,
                expires_at: None,
            },
        );
        self
    }

    fn postgres_cert(&self) -> PathBuf {
        self.dir.path().join(POSTGRES_TLS_CERT_PATH)
    }

    fn staged_present(&self) -> usize {
        staged_moves(&self.ctx.paths, &self.state(3))
            .iter()
            .filter(|staged_move| staged_move.staged.exists())
            .count()
    }

    /// Runs the first `count` of Phase 4's moves, as a run interrupted
    /// right after them leaves the directory.
    fn apply_moves(&self, count: usize) {
        for staged_move in staged_moves(&self.ctx.paths, &self.state(3))
            .into_iter()
            .take(count)
        {
            move_staged_file(&self.ctx.secrets, &staged_move, &test_messages()).expect("move");
        }
    }
}

/// What the recording [`StepCaSwitch`] saw, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Event {
    Policy,
    Remove {
        phase4_started_on_disk: bool,
        staged_present: usize,
    },
    Reissue {
        staged_present: usize,
    },
    PublicKey(PathBuf),
    Start(Option<String>),
}

/// A [`StepCaSwitch`] that records each call against the rig's
/// directory and reads the CA keys as the unencrypted PEM the rig wrote.
struct RecordingSwitch<'a> {
    rig: &'a Rig,
    events: RefCell<Vec<Event>>,
    policy: Option<String>,
    /// The generation whose intermediate a reissue signs `PostgreSQL`'s
    /// leaf with; `None` leaves the leaf as it is.
    reissue_with: Option<&'a Generation>,
    /// Answers the root key with another key's public half.
    wrong_root_key: bool,
    /// Fails the next reissue after it has written the new leaf, as an
    /// issuance whose key handover or reload then fails leaves it.
    fail_after_issuance: Cell<bool>,
}

impl<'a> RecordingSwitch<'a> {
    fn new(rig: &'a Rig) -> Self {
        Self {
            rig,
            events: RefCell::new(Vec::new()),
            policy: Some(RESTART_POLICY.to_string()),
            reissue_with: Some(&rig.new),
            wrong_root_key: false,
            fail_after_issuance: Cell::new(false),
        }
    }

    fn events(&self) -> Vec<Event> {
        self.events.borrow().clone()
    }

    fn started(&self) -> bool {
        self.events()
            .iter()
            .any(|event| matches!(event, Event::Start(_)))
    }
}

impl StepCaSwitch for RecordingSwitch<'_> {
    fn current_restart_policy(&self) -> Result<Option<String>> {
        self.events.borrow_mut().push(Event::Policy);
        Ok(self.policy.clone())
    }

    fn remove_stepca(&self) -> Result<()> {
        let on_disk = load_rotation_state(&self.rig.ctx.state_dir, &test_messages())?
            .is_some_and(|state| state.phase4_started);
        self.events.borrow_mut().push(Event::Remove {
            phase4_started_on_disk: on_disk,
            staged_present: self.rig.staged_present(),
        });
        Ok(())
    }

    fn reissue_postgres(&self) -> Result<()> {
        self.events.borrow_mut().push(Event::Reissue {
            staged_present: self.rig.staged_present(),
        });
        if let Some(generation) = self.reissue_with {
            fs::write(self.rig.postgres_cert(), generation.sign_leaf())?;
        }
        if self.fail_after_issuance.replace(false) {
            anyhow::bail!("postgres reload failed");
        }
        Ok(())
    }

    fn public_key_der(&self, key: &Path) -> Result<Vec<u8>> {
        self.events
            .borrow_mut()
            .push(Event::PublicKey(key.to_path_buf()));
        if self.wrong_root_key && key == self.rig.ctx.paths.stepca_root_key() {
            return Ok(KeyPair::generate()?.subject_public_key_info());
        }
        Ok(spki_of_pem_key(&fs::read_to_string(key)?))
    }

    fn start_stepca(&self, restart_policy: Option<&str>) -> Result<()> {
        self.events
            .borrow_mut()
            .push(Event::Start(restart_policy.map(str::to_string)));
        Ok(())
    }
}

fn read_file(path: &Path) -> String {
    fs::read_to_string(path).expect("read")
}

fn assert_live_is(rig: &Rig, generation: &Generation) {
    let paths = &rig.ctx.paths;
    assert_eq!(read_file(&paths.root_cert()), generation.root_cert);
    assert_eq!(read_file(&paths.stepca_root_key()), generation.root_key);
    assert_eq!(
        read_file(&paths.intermediate_cert()),
        generation.intermediate_cert
    );
    assert_eq!(
        read_file(&paths.stepca_intermediate_key()),
        generation.intermediate_key
    );
}

fn assert_backups_are(rig: &Rig, generation: &Generation) {
    let paths = &rig.ctx.paths;
    assert_eq!(read_file(&paths.root_cert_bak()), generation.root_cert);
    assert_eq!(read_file(&paths.root_key_bak()), generation.root_key);
    assert_eq!(
        read_file(&paths.intermediate_cert_bak()),
        generation.intermediate_cert
    );
    assert_eq!(
        read_file(&paths.intermediate_key_bak()),
        generation.intermediate_key
    );
}

fn state_at(phase: u8, staged: bool, phase4_started: bool) -> RotationState {
    RotationState {
        mode: RotationMode::Full,
        started_at: String::new(),
        old_root_fp: "a".repeat(64),
        new_root_fp: "b".repeat(64),
        old_intermediate_fp: "c".repeat(64),
        new_intermediate_fp: "d".repeat(64),
        phase,
        staged,
        phase4_started,
        stepca_restart_policy: None,
    }
}

// ---------------------------------------------------------------------
// The decision a run takes from the state it found
// ---------------------------------------------------------------------

#[test]
fn no_state_starts_a_rotation_staged_only_with_the_flag() {
    let messages = test_messages();
    assert_eq!(
        decide_staging(None, true, &messages).expect("decide"),
        StagingDecision::Start { staged: true }
    );
    assert_eq!(
        decide_staging(None, false, &messages).expect("decide"),
        StagingDecision::Start { staged: false }
    );
}

#[test]
fn without_the_flag_every_recorded_rotation_resumes() {
    let messages = test_messages();
    for phase in 0..=6 {
        for (staged, started) in [(false, false), (true, false), (true, true)] {
            let state = state_at(phase, staged, started);
            assert_eq!(
                decide_staging(Some(&state), false, &messages).expect("decide"),
                StagingDecision::Resume,
                "phase {phase}, staged {staged}, phase4_started {started}"
            );
        }
    }
}

#[test]
fn with_the_flag_a_staged_rotation_before_phase3_resumes_to_pause() {
    let messages = test_messages();
    for phase in 0..3 {
        assert_eq!(
            decide_staging(Some(&state_at(phase, true, false)), true, &messages).expect("decide"),
            StagingDecision::Resume
        );
    }
}

#[test]
fn with_the_flag_a_paused_rotation_repeats_the_pause() {
    let messages = test_messages();
    assert_eq!(
        decide_staging(Some(&state_at(3, true, false)), true, &messages).expect("decide"),
        StagingDecision::RepeatPause
    );
}

#[test]
fn with_the_flag_a_started_phase4_is_refused() {
    let messages = test_messages();
    let err = decide_staging(Some(&state_at(3, true, true)), true, &messages)
        .expect_err("phase 4 has started");
    assert_eq!(
        err.to_string(),
        messages.error_rotation_pause_phase4_started()
    );
    assert!(err.to_string().contains("without --pause-before-step-ca"));
}

#[test]
fn with_the_flag_a_rotation_past_phase3_is_refused() {
    let messages = test_messages();
    for phase in 4..=6 {
        for staged in [false, true] {
            let err = decide_staging(Some(&state_at(phase, staged, true)), true, &messages)
                .expect_err("step-ca has been switched");
            assert_eq!(
                err.to_string(),
                messages.error_rotation_pause_stepca_switched(&phase.to_string())
            );
        }
    }
}

#[test]
fn with_the_flag_an_unstaged_rotation_is_refused() {
    let messages = test_messages();
    for phase in 0..=3 {
        let err = decide_staging(Some(&state_at(phase, false, false)), true, &messages)
            .expect_err("not staged");
        assert_eq!(
            err.to_string(),
            messages.error_rotation_pause_not_staged(&phase.to_string())
        );
    }
}

// ---------------------------------------------------------------------
// Paused after Phase 3
// ---------------------------------------------------------------------

/// The pause output names the staged root, its SHA-256 DER fingerprint
/// in lowercase hex and the command that continues, and is the same on
/// every run.
#[tokio::test]
async fn pause_notice_names_the_staged_root_its_fingerprint_and_the_continue_command() {
    let rig = Rig::paused();
    let messages = test_messages();
    let state = rig.recorded();

    let first = pause_notice(&rig.ctx, &state, &messages)
        .await
        .expect("notice");
    let second = pause_notice(&rig.ctx, &state, &messages)
        .await
        .expect("notice");

    let fingerprint = independent_sha256_hex(&rig.new.root_cert);
    assert_eq!(fingerprint.len(), 64);
    assert!(
        fingerprint
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    );
    assert!(
        first.contains(&rig.ctx.paths.root_cert_staged().display().to_string()),
        "{first}"
    );
    assert!(first.contains(&fingerprint), "{first}");
    assert!(first.contains("bootroot rotate ca-key --full"), "{first}");
    assert!(first.contains(rig.new.root_cert.trim()), "{first}");
    assert_eq!(first, second);
}

#[tokio::test]
async fn pause_notice_refuses_a_staged_root_other_than_the_recorded_one() {
    let rig = Rig::paused();
    let messages = test_messages();
    fs::write(rig.ctx.paths.root_cert_staged(), &rig.old.root_cert).expect("swap");

    let err = pause_notice(&rig.ctx, &rig.recorded(), &messages)
        .await
        .expect_err("not the recorded root");
    assert!(err.to_string().contains(&rig.new.root_fp()), "{err}");
}

/// step-ca reads the live root certificate and intermediate pair named by
/// its `ca.json`; while paused they, and the live root key, are the old
/// generation, and no staging path is among them.
#[test]
fn while_paused_the_files_stepca_reads_are_the_old_generation() {
    let rig = Rig::paused();
    assert_live_is(&rig, &rig.old);

    let ca_json = format!(
        r#"{{"root":"{}","crt":"{}","key":"{}"}}"#,
        LIVE_CA_TARGETS.root_cert,
        LIVE_CA_TARGETS.intermediate_cert,
        LIVE_CA_TARGETS.intermediate_key
    );
    let secrets = rig.ctx.paths.secrets_dir();
    for staged in [
        rig.ctx.paths.root_cert_staged(),
        rig.ctx.paths.root_key_staged(),
        rig.ctx.paths.intermediate_cert_staged(),
        rig.ctx.paths.intermediate_key_staged(),
    ] {
        let container = to_container_path(secrets, &staged, STEP_HELPER_MOUNT).expect("path");
        assert!(
            !ca_json.contains(&container),
            "ca.json reads a staging path"
        );
    }
    for (live, target) in [
        (rig.ctx.paths.root_cert(), LIVE_CA_TARGETS.root_cert),
        (rig.ctx.paths.stepca_root_key(), LIVE_CA_TARGETS.root_key),
        (
            rig.ctx.paths.intermediate_cert(),
            LIVE_CA_TARGETS.intermediate_cert,
        ),
        (
            rig.ctx.paths.stepca_intermediate_key(),
            LIVE_CA_TARGETS.intermediate_key,
        ),
    ] {
        assert_eq!(
            to_container_path(secrets, &live, STEP_HELPER_MOUNT).expect("path"),
            target
        );
    }
}

#[tokio::test]
async fn phase3_bundle_carries_both_generations() {
    let rig = Rig::paused();
    let bundle = concat_unique_ca_certs(
        &rig.ctx.secrets,
        &phase3_bundle_sources(&rig.ctx.paths),
        &test_messages(),
    )
    .await
    .expect("bundle");

    assert_eq!(bundle.matches("BEGIN CERTIFICATE").count(), 4);
    for generation in [&rig.old, &rig.new] {
        assert!(bundle.contains(generation.root_cert.trim()));
        assert!(bundle.contains(generation.intermediate_cert.trim()));
    }
}

/// A repair run while paused, or after any one of Phase 4's moves,
/// publishes both generations — and while paused the same bytes Phase 3
/// published.
#[tokio::test]
async fn repair_bundle_carries_both_generations_while_paused_and_after_each_move() {
    let messages = test_messages();
    for moved in 0..=4 {
        let rig = Rig::paused();
        let phase3 = concat_unique_ca_certs(
            &rig.ctx.secrets,
            &phase3_bundle_sources(&rig.ctx.paths),
            &messages,
        )
        .await
        .expect("phase 3 bundle");
        rig.apply_moves(moved);

        let bundle = concat_unique_ca_certs_for_repair(&rig.ctx, true, &messages)
            .await
            .expect("repair bundle");

        assert_eq!(
            bundle.matches("BEGIN CERTIFICATE").count(),
            4,
            "after {moved} moves"
        );
        for generation in [&rig.old, &rig.new] {
            assert!(
                bundle.contains(generation.root_cert.trim()),
                "after {moved}"
            );
            assert!(
                bundle.contains(generation.intermediate_cert.trim()),
                "after {moved}"
            );
        }
        if moved == 0 {
            assert_eq!(bundle, phase3);
        }
    }
}

// ---------------------------------------------------------------------
// Phase 2 at the staging paths
// ---------------------------------------------------------------------

/// The staged docker targets are the live names followed by the staging
/// suffix, as [`StatePaths`] spells them on the host.
#[test]
fn staged_targets_are_the_staging_paths() {
    let dir = tempdir().expect("tempdir");
    let secrets = dir.path().join("secrets");
    let paths = StatePaths::new(secrets.clone());
    for (host, target) in [
        (paths.root_cert_staged(), STAGED_CA_TARGETS.root_cert),
        (paths.root_key_staged(), STAGED_CA_TARGETS.root_key),
        (
            paths.intermediate_cert_staged(),
            STAGED_CA_TARGETS.intermediate_cert,
        ),
        (
            paths.intermediate_key_staged(),
            STAGED_CA_TARGETS.intermediate_key,
        ),
    ] {
        assert_eq!(
            to_container_path(&secrets, &host, STEP_HELPER_MOUNT).expect("path"),
            target
        );
    }
    for (staged, live) in [
        (paths.root_cert_staged(), paths.root_cert()),
        (paths.root_key_staged(), paths.stepca_root_key()),
        (paths.intermediate_cert_staged(), paths.intermediate_cert()),
        (
            paths.intermediate_key_staged(),
            paths.stepca_intermediate_key(),
        ),
    ] {
        assert_eq!(staged.parent(), live.parent(), "same directory");
    }
}

/// Phase 2a writes the new root at the staging paths, and Phase 2b
/// writes the new intermediate there signed by that staged root and its
/// key, never by the live root.
#[test]
fn staged_generation_args_write_and_sign_at_the_staging_paths() {
    let mount = "/host/secrets:/home/step";
    let root = generate_root_docker_args(mount, "1000:1000", &STAGED_CA_TARGETS);
    assert!(root.iter().any(|arg| arg == STAGED_CA_TARGETS.root_cert));
    assert!(root.iter().any(|arg| arg == STAGED_CA_TARGETS.root_key));
    assert!(!root.iter().any(|arg| arg == LIVE_CA_TARGETS.root_cert));
    assert!(!root.iter().any(|arg| arg == LIVE_CA_TARGETS.root_key));

    let intermediate = generate_intermediate_docker_args(mount, "1000:1000", &STAGED_CA_TARGETS);
    let value_of = |flag: &str| {
        intermediate
            .iter()
            .position(|arg| arg == flag)
            .and_then(|pos| intermediate.get(pos + 1))
            .map(String::as_str)
    };
    assert_eq!(value_of("--ca"), Some(STAGED_CA_TARGETS.root_cert));
    assert_eq!(value_of("--ca-key"), Some(STAGED_CA_TARGETS.root_key));
    assert!(
        intermediate
            .iter()
            .any(|arg| arg == STAGED_CA_TARGETS.intermediate_cert)
    );
    assert!(
        intermediate
            .iter()
            .any(|arg| arg == STAGED_CA_TARGETS.intermediate_key)
    );
    for live in [
        LIVE_CA_TARGETS.root_cert,
        LIVE_CA_TARGETS.root_key,
        LIVE_CA_TARGETS.intermediate_cert,
        LIVE_CA_TARGETS.intermediate_key,
    ] {
        assert!(
            !intermediate.iter().any(|arg| arg == live),
            "the staged intermediate reads a live path"
        );
    }
}

#[tokio::test]
async fn the_staged_intermediate_chains_to_the_staged_root_only() {
    let rig = Rig::paused();
    let messages = test_messages();
    let staged_intermediate = cert_der_from_pem(
        rig.new.intermediate_cert.as_bytes(),
        Path::new("i"),
        &messages,
    )
    .expect("der");
    let staged_root =
        cert_der_from_pem(rig.new.root_cert.as_bytes(), Path::new("r"), &messages).expect("der");
    let old_root =
        cert_der_from_pem(rig.old.root_cert.as_bytes(), Path::new("o"), &messages).expect("der");
    assert!(cert_signed_by(&staged_intermediate, &staged_root).expect("verify"));
    assert!(!cert_signed_by(&staged_intermediate, &old_root).expect("verify"));
    check_staged_chain(&rig.ctx, &messages)
        .await
        .expect("chain holds");

    // An intermediate the old root signed is refused.
    let misissued = Generation::with_intermediate_of(
        rig.new.root_cert.clone(),
        rig.new.root_key.clone(),
        &rig.old.root_issuer(),
    );
    fs::write(
        rig.ctx.paths.intermediate_cert_staged(),
        &misissued.intermediate_cert,
    )
    .expect("swap");
    let err = check_staged_chain(&rig.ctx, &messages)
        .await
        .expect_err("not the staged root's");
    assert!(
        err.to_string()
            .contains(&rig.ctx.paths.root_cert_staged().display().to_string()),
        "{err}"
    );
}

/// A resumed Phase 2 finds the new generation at the staging paths and
/// takes its fingerprints from there, generating nothing.
#[tokio::test]
async fn resumed_phase2_reads_the_new_generation_from_the_staging_paths() {
    let rig = Rig::paused();
    let messages = test_messages();
    let mut state = rig.state(1);
    state.new_root_fp = state.old_root_fp.clone();
    state.new_intermediate_fp = String::new();

    generate_staged_generation(&rig.ctx, &mut state, true, &messages)
        .await
        .expect("phase 2");

    assert_eq!(decode_fake_docker_log(&rig.docker_log).len(), 0);
    assert_eq!(state.new_root_fp, rig.new.root_fp());
    assert_eq!(state.new_intermediate_fp, rig.new.intermediate_fp());
    assert_live_is(&rig, &rig.old);
}

/// A new rotation generates both at the staging paths even when an
/// abandoned one left files there, and the live files are not touched.
#[tokio::test]
async fn fresh_phase2_generates_at_the_staging_paths() {
    let rig = Rig::paused();
    let messages = test_messages();
    let mut state = rig.state(1);

    generate_staged_generation(&rig.ctx, &mut state, false, &messages)
        .await
        .expect("phase 2");

    let invocations = decode_fake_docker_log(&rig.docker_log);
    assert_eq!(invocations.len(), 2, "{invocations:?}");
    assert!(
        invocations
            .first()
            .is_some_and(|argv| argv.iter().any(|arg| arg == STAGED_CA_TARGETS.root_cert))
    );
    assert!(invocations.get(1).is_some_and(|argv| {
        argv.iter()
            .any(|arg| arg == STAGED_CA_TARGETS.intermediate_cert)
    }));
    // The fake writes nothing, so the fingerprints are those of the files
    // at the staging paths.
    assert_eq!(state.new_root_fp, rig.new.root_fp());
    assert_eq!(state.new_intermediate_fp, rig.new.intermediate_fp());
    assert_live_is(&rig, &rig.old);
}

/// A staged root whose key is missing is generated again, and with it the
/// intermediate it has to sign.
#[tokio::test]
async fn resumed_phase2_regenerates_an_incomplete_staged_root() {
    let rig = Rig::paused();
    let messages = test_messages();
    fs::remove_file(rig.ctx.paths.root_key_staged()).expect("remove key");
    let mut state = rig.state(1);

    generate_staged_generation(&rig.ctx, &mut state, true, &messages)
        .await
        .expect("phase 2");

    assert_eq!(decode_fake_docker_log(&rig.docker_log).len(), 2);
}

// ---------------------------------------------------------------------
// Phase 2: the staged keys' mode and owner
// ---------------------------------------------------------------------

/// The mode an operator may give the live CA keys instead of the
/// default `0600`.
const OPERATOR_KEY_MODE: u32 = 0o640;

/// The permission bits, uid and gid of `path`.
fn mode_and_owner(path: &Path) -> (u32, u32, u32) {
    let meta = fs::metadata(path).expect("stat");
    (meta.mode() & 0o7777, meta.uid(), meta.gid())
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
}

/// The test's own uid and gid, as the files it creates get them.
fn own_owner(rig: &Rig) -> (u32, u32) {
    let meta = fs::metadata(rig.dir.path()).expect("stat tempdir");
    (meta.uid(), meta.gid())
}

/// Gives the rig's live keys `mode`, owned by the test's own uid and
/// gid, and its staged keys `step`'s default `0600`.
fn set_key_modes(rig: &Rig, mode: u32) -> (u32, u32) {
    let (uid, gid) = own_owner(rig);
    let paths = &rig.ctx.paths;
    for live in [paths.stepca_root_key(), paths.stepca_intermediate_key()] {
        std::os::unix::fs::chown(&live, Some(uid), Some(gid)).expect("chown live key");
        set_mode(&live, mode);
    }
    for staged in [paths.root_key_staged(), paths.intermediate_key_staged()] {
        set_mode(&staged, 0o600);
    }
    (uid, gid)
}

/// Uses a handle forced into rooted mode, so the descriptor-relative
/// branch runs as it does for root over a tree another account owns.
fn use_rooted_tree(rig: &mut Rig) {
    rig.ctx.secrets = std::sync::Arc::new(
        SecretsTree::open_rooted_for_tests(rig.ctx.paths.secrets_dir()).expect("rooted tree"),
    );
}

/// With the live keys at `0640` and a given owner, Phase 2 gives the
/// staged keys exactly that mode and owner, through either handle, and
/// the switch puts them in place with it.
#[tokio::test]
async fn phase2_gives_the_staged_keys_the_live_keys_mode_and_owner() {
    for rooted in [false, true] {
        let mut rig = Rig::paused();
        if rooted {
            use_rooted_tree(&mut rig);
        }
        let messages = test_messages();
        let (uid, gid) = set_key_modes(&rig, OPERATOR_KEY_MODE);
        let mut state = rig.state(1);

        // The fake `docker` writes nothing, so the keys at the staging
        // paths stand in for the ones `step` would have written.
        generate_staged_generation(&rig.ctx, &mut state, false, &messages)
            .await
            .expect("phase 2");

        let paths = &rig.ctx.paths;
        for staged in [paths.root_key_staged(), paths.intermediate_key_staged()] {
            assert_eq!(
                mode_and_owner(&staged),
                (OPERATOR_KEY_MODE, uid, gid),
                "{} (rooted: {rooted})",
                staged.display()
            );
        }
        rig.apply_moves(4);
        for live in [paths.stepca_root_key(), paths.stepca_intermediate_key()] {
            assert_eq!(
                mode_and_owner(&live),
                (OPERATOR_KEY_MODE, uid, gid),
                "{} after the switch (rooted: {rooted})",
                live.display()
            );
        }
        assert_live_is(&rig, &rig.new);
    }
}

/// A supplementary group of this process other than the gid the rig's
/// files get, confirmed by giving a probe file that group; `None` when
/// there is none.
fn other_group(rig: &Rig) -> Option<u32> {
    let probe = rig.dir.path().join("group-probe");
    fs::write(&probe, "").expect("write probe");
    let own = mode_and_owner(&probe).2;
    let output = ProcessCommand::new("id")
        .arg("-G")
        .output()
        .expect("run id -G");
    let found = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .filter_map(|gid| gid.parse::<u32>().ok())
        .filter(|gid| *gid != own)
        .find(|gid| std::os::unix::fs::chown(&probe, None, Some(*gid)).is_ok());
    fs::remove_file(&probe).expect("remove probe");
    found
}

/// With the live keys in another of the user's groups, Phase 2 changes
/// the staged keys' group to it, through either handle: the owner change
/// itself, not only a mode change.
#[tokio::test]
async fn phase2_gives_the_staged_keys_the_live_keys_group() {
    for rooted in [false, true] {
        let mut rig = Rig::paused();
        let Some(group) = other_group(&rig) else {
            // No second group to change to: the owner change cannot be shown.
            return;
        };
        if rooted {
            use_rooted_tree(&mut rig);
        }
        let messages = test_messages();
        let (uid, gid) = set_key_modes(&rig, OPERATOR_KEY_MODE);
        let paths = &rig.ctx.paths;
        for live in [paths.stepca_root_key(), paths.stepca_intermediate_key()] {
            std::os::unix::fs::chown(&live, None, Some(group)).expect("chgrp live key");
        }
        let mut state = rig.state(1);

        generate_staged_generation(&rig.ctx, &mut state, false, &messages)
            .await
            .expect("phase 2");

        for staged in [paths.root_key_staged(), paths.intermediate_key_staged()] {
            assert_ne!(gid, group);
            assert_eq!(
                mode_and_owner(&staged),
                (OPERATOR_KEY_MODE, uid, group),
                "{} (rooted: {rooted})",
                staged.display()
            );
        }
    }
}

/// A staged key the secrets owner replaced with a hard link to another
/// file is refused under a rooted handle, with a message naming the
/// staged key and its live counterpart, and the other file is left as
/// it was.
#[tokio::test]
async fn rooted_phase2_refuses_a_hard_linked_staged_key() {
    let mut rig = Rig::paused();
    use_rooted_tree(&mut rig);
    let messages = test_messages();
    set_key_modes(&rig, OPERATOR_KEY_MODE);
    let paths = &rig.ctx.paths;
    let elsewhere = rig.dir.path().join("elsewhere");
    fs::write(&elsewhere, &rig.new.root_key).expect("write elsewhere");
    set_mode(&elsewhere, 0o600);
    let staged = paths.root_key_staged();
    fs::remove_file(&staged).expect("remove staged key");
    fs::hard_link(&elsewhere, &staged).expect("hard-link staged key");
    let mut state = rig.state(1);

    let err = generate_staged_generation(&rig.ctx, &mut state, false, &messages)
        .await
        .expect_err("hard link refused");

    let message = format!("{err:#}");
    assert!(message.contains(&staged.display().to_string()), "{message}");
    assert!(
        message.contains(&paths.stepca_root_key().display().to_string()),
        "{message}"
    );
    assert!(message.contains("links"), "{message}");
    assert_eq!(mode_and_owner(&elsewhere).0, 0o600);
}

/// A kept staged key is given the live key's mode too, as a run that
/// failed after writing it leaves it.
#[tokio::test]
async fn resumed_phase2_gives_a_kept_staged_key_the_live_keys_mode() {
    let rig = Rig::paused();
    let messages = test_messages();
    let (uid, gid) = set_key_modes(&rig, OPERATOR_KEY_MODE);
    let mut state = rig.state(1);

    generate_staged_generation(&rig.ctx, &mut state, true, &messages)
        .await
        .expect("phase 2");

    assert_eq!(decode_fake_docker_log(&rig.docker_log).len(), 0);
    let paths = &rig.ctx.paths;
    for staged in [paths.root_key_staged(), paths.intermediate_key_staged()] {
        assert_eq!(mode_and_owner(&staged), (OPERATOR_KEY_MODE, uid, gid));
    }
}

/// With the live keys at the default mode, Phase 2 changes nothing on
/// the staged keys: not their mode, not their owner, and not their
/// change time.
#[tokio::test]
async fn phase2_leaves_the_staged_keys_alone_at_the_default_mode() {
    for rooted in [false, true] {
        let mut rig = Rig::paused();
        if rooted {
            use_rooted_tree(&mut rig);
        }
        let messages = test_messages();
        let (uid, gid) = set_key_modes(&rig, 0o600);
        let paths = &rig.ctx.paths;
        let staged_keys = [paths.root_key_staged(), paths.intermediate_key_staged()];
        let before: Vec<_> = staged_keys
            .iter()
            .map(|staged| {
                let meta = fs::metadata(staged).expect("stat");
                (meta.ctime(), meta.ctime_nsec())
            })
            .collect();
        let mut state = rig.state(1);

        generate_staged_generation(&rig.ctx, &mut state, false, &messages)
            .await
            .expect("phase 2");

        for (staged, changed) in staged_keys.iter().zip(before) {
            assert_eq!(
                mode_and_owner(staged),
                (0o600, uid, gid),
                "rooted: {rooted}"
            );
            let meta = fs::metadata(staged).expect("stat");
            assert_eq!(
                (meta.ctime(), meta.ctime_nsec()),
                changed,
                "{} was changed (rooted: {rooted})",
                staged.display()
            );
        }
    }
}

/// A live key that is absent leaves the staged key at the mode `step`
/// created it with.
#[tokio::test]
async fn phase2_keeps_the_creation_mode_without_a_live_key() {
    let rig = Rig::paused();
    let messages = test_messages();
    set_key_modes(&rig, OPERATOR_KEY_MODE);
    let paths = &rig.ctx.paths;
    fs::remove_file(paths.stepca_root_key()).expect("remove live root key");
    fs::remove_file(paths.stepca_intermediate_key()).expect("remove live intermediate key");
    let mut state = rig.state(1);

    generate_staged_generation(&rig.ctx, &mut state, false, &messages)
        .await
        .expect("phase 2");

    for staged in [paths.root_key_staged(), paths.intermediate_key_staged()] {
        assert_eq!(mode_and_owner(&staged).0, 0o600);
    }
}

/// An owner the run cannot give the staged key fails with a message
/// naming the staged key and its live counterpart, and leaves the staged
/// key where it is.
#[test]
fn an_owner_that_cannot_be_applied_names_the_staged_key() {
    let rig = Rig::paused();
    if own_owner(&rig).0 == 0 {
        // Root may give any file any owner; nothing here can fail.
        return;
    }
    let messages = test_messages();
    let paths = &rig.ctx.paths;
    let staged = paths.root_key_staged();
    let live = paths.stepca_root_key();
    let root_owned = FileMeta {
        mode: OPERATOR_KEY_MODE,
        uid: 0,
        gid: 0,
    };

    let err = apply_live_key_meta(&rig.ctx.secrets, &staged, &live, root_owned, &messages)
        .expect_err("chown to root without the privilege");

    let message = format!("{err:#}");
    assert!(message.contains(&staged.display().to_string()), "{message}");
    assert!(message.contains(&live.display().to_string()), "{message}");
    assert!(message.contains("uid=0 gid=0"), "{message}");
    assert!(staged.exists(), "the staged key is left in place");
}

// ---------------------------------------------------------------------
// Phase 4: the moves
// ---------------------------------------------------------------------

#[test]
fn moves_run_root_cert_root_key_intermediate_key_intermediate_cert() {
    let rig = Rig::paused();
    let paths = &rig.ctx.paths;
    let moves = staged_moves(paths, &rig.state(3));
    let order: Vec<(PathBuf, PathBuf)> = moves
        .iter()
        .map(|staged_move| (staged_move.staged.clone(), staged_move.live.clone()))
        .collect();
    assert_eq!(
        order,
        vec![
            (paths.root_cert_staged(), paths.root_cert()),
            (paths.root_key_staged(), paths.stepca_root_key()),
            (
                paths.intermediate_key_staged(),
                paths.stepca_intermediate_key()
            ),
            (paths.intermediate_cert_staged(), paths.intermediate_cert()),
        ]
    );
}

/// Between any two moves the live intermediate pair is the old pair or
/// a key that does not match its certificate; the new pair is live only
/// after the last move.
#[test]
fn the_new_intermediate_pair_is_live_only_after_the_last_move() {
    for moved in 0..=4 {
        let rig = Rig::paused();
        rig.apply_moves(moved);
        let cert = read_file(&rig.ctx.paths.intermediate_cert());
        let key = read_file(&rig.ctx.paths.stepca_intermediate_key());
        let old_pair = cert == rig.old.intermediate_cert && key == rig.old.intermediate_key;
        let new_pair = cert == rig.new.intermediate_cert && key == rig.new.intermediate_key;
        let mismatched = spki_of_pem_cert(&cert) != spki_of_pem_key(&key);
        if moved == 4 {
            assert!(new_pair, "after the last move");
        } else {
            assert!(!new_pair, "after {moved} moves");
            assert!(old_pair || mismatched, "after {moved} moves");
        }
        assert_backups_are(&rig, &rig.old);
    }
}

#[test]
fn an_absent_staged_certificate_needs_the_new_one_live() {
    let rig = Rig::paused();
    let messages = test_messages();
    fs::remove_file(rig.ctx.paths.root_cert_staged()).expect("remove");
    let first = staged_moves(&rig.ctx.paths, &rig.state(3))
        .into_iter()
        .next()
        .expect("first move");

    let err = move_staged_file(&rig.ctx.secrets, &first, &messages)
        .expect_err("the live root is still the old one");
    assert_eq!(
        err.to_string(),
        messages.error_staged_cert_not_new(
            &rig.ctx.paths.root_cert().display().to_string(),
            &rig.new.root_fp(),
            &rig.old.root_fp(),
        )
    );
}

// ---------------------------------------------------------------------
// Phase 4: the whole switch
// ---------------------------------------------------------------------

/// `phase4_started` is on disk before step-ca is removed, step-ca is
/// removed before any move, PostgreSQL is reissued after the moves, and
/// step-ca starts only after the keys are checked, with the restart
/// policy the removed container carried.
#[tokio::test]
async fn phase4_records_then_removes_then_moves_then_reissues_then_verifies_then_starts() {
    let rig = Rig::paused();
    let rig = {
        let old = Generation {
            root_cert: rig.old.root_cert.clone(),
            root_key: rig.old.root_key.clone(),
            intermediate_cert: rig.old.intermediate_cert.clone(),
            intermediate_key: rig.old.intermediate_key.clone(),
        };
        rig.with_postgres_signed_by(&old)
    };
    let messages = test_messages();
    let switch = RecordingSwitch::new(&rig);
    let mut state = rig.recorded();

    switch_to_staged_generation(&rig.ctx, &mut state, &switch, &messages)
        .await
        .expect("phase 4");

    let paths = &rig.ctx.paths;
    assert_eq!(
        switch.events(),
        vec![
            Event::Policy,
            Event::Remove {
                phase4_started_on_disk: true,
                staged_present: 4,
            },
            Event::Reissue { staged_present: 0 },
            Event::PublicKey(paths.stepca_root_key()),
            Event::PublicKey(paths.stepca_intermediate_key()),
            Event::Start(Some(RESTART_POLICY.to_string())),
        ]
    );
    assert_live_is(&rig, &rig.new);
    assert_backups_are(&rig, &rig.old);
    assert_eq!(rig.staged_present(), 0);
    let recorded = rig.recorded();
    assert!(recorded.phase4_started);
    assert_eq!(recorded.phase, 3, "Phase 4 is recorded by the caller");
    assert_eq!(
        recorded.stepca_restart_policy.as_deref(),
        Some(RESTART_POLICY)
    );
}

/// A run interrupted after any number of moves completes on the next
/// run, which keeps the restart policy the first one recorded.
#[tokio::test]
async fn phase4_resumes_after_an_interruption_at_each_move() {
    let messages = test_messages();
    for moved in 0..=4 {
        let rig = Rig::paused();
        let mut state = rig.recorded();
        state.phase4_started = true;
        state.stepca_restart_policy = Some("always".to_string());
        crate::commands::trust::update_rotation_state(&rig.ctx.state_dir, &state, &messages)
            .expect("record");
        rig.apply_moves(moved);
        let mut switch = RecordingSwitch::new(&rig);
        switch.policy = Some("no".to_string());

        switch_to_staged_generation(&rig.ctx, &mut state, &switch, &messages)
            .await
            .unwrap_or_else(|err| panic!("after {moved} moves: {err:#}"));

        let events = switch.events();
        assert!(!events.contains(&Event::Policy), "{events:?}");
        assert_eq!(
            events.last(),
            Some(&Event::Start(Some("always".to_string())))
        );
        assert_live_is(&rig, &rig.new);
        assert_backups_are(&rig, &rig.old);
    }
}

#[tokio::test]
async fn phase4_does_not_start_stepca_when_a_key_does_not_match() {
    let rig = Rig::paused();
    let messages = test_messages();
    let mut switch = RecordingSwitch::new(&rig);
    switch.wrong_root_key = true;
    let mut state = rig.recorded();

    let err = switch_to_staged_generation(&rig.ctx, &mut state, &switch, &messages)
        .await
        .expect_err("the root key is not the root's");

    assert!(!switch.started());
    assert_eq!(
        err.to_string(),
        messages.error_stepca_switch_verification_failed()
    );
    assert!(
        format!("{err:#}").contains(&messages.error_staged_key_mismatch(
            &rig.ctx.paths.stepca_root_key().display().to_string(),
            &rig.ctx.paths.root_cert().display().to_string(),
        )),
        "{err:#}"
    );
}

#[tokio::test]
async fn phase4_does_not_start_stepca_when_postgres_is_not_new_generation() {
    let rig = Rig::paused();
    let old_leaf_signer = Generation {
        root_cert: rig.old.root_cert.clone(),
        root_key: rig.old.root_key.clone(),
        intermediate_cert: rig.old.intermediate_cert.clone(),
        intermediate_key: rig.old.intermediate_key.clone(),
    };
    let rig = rig.with_postgres_signed_by(&old_leaf_signer);
    let messages = test_messages();
    let mut switch = RecordingSwitch::new(&rig);
    switch.reissue_with = None;
    let mut state = rig.recorded();

    let err = switch_to_staged_generation(&rig.ctx, &mut state, &switch, &messages)
        .await
        .expect_err("postgres still presents the old generation");

    assert!(!switch.started());
    assert!(
        format!("{err:#}").contains(&messages.error_postgres_cert_not_new_generation(
            &rig.postgres_cert().display().to_string(),
            &rig.ctx.paths.intermediate_cert().display().to_string(),
        )),
        "{err:#}"
    );
}

#[tokio::test]
async fn phase4_does_not_start_stepca_when_a_live_certificate_is_not_new() {
    let rig = Rig::paused();
    let messages = test_messages();
    // The staged intermediate is gone and the live one is still old.
    fs::remove_file(rig.ctx.paths.intermediate_cert_staged()).expect("remove");
    let switch = RecordingSwitch::new(&rig);
    let mut state = rig.recorded();

    switch_to_staged_generation(&rig.ctx, &mut state, &switch, &messages)
        .await
        .expect_err("the live intermediate is old");

    assert!(!switch.started());
}

/// A resumed Phase 4 that finds every file moved reissues PostgreSQL's
/// certificate before step-ca starts, whether the leaf on disk is still
/// old or already new: a new leaf on disk does not show that its key was
/// handed over or that PostgreSQL was reloaded onto it.
#[tokio::test]
async fn resumed_phase4_reissues_postgres_whether_or_not_the_leaf_is_new() {
    let messages = test_messages();
    for already_new in [false, true] {
        let rig = Rig::paused();
        let signer = if already_new { &rig.new } else { &rig.old };
        let signer = Generation {
            root_cert: signer.root_cert.clone(),
            root_key: signer.root_key.clone(),
            intermediate_cert: signer.intermediate_cert.clone(),
            intermediate_key: signer.intermediate_key.clone(),
        };
        let rig = rig.with_postgres_signed_by(&signer);
        rig.apply_moves(4);
        let mut state = rig.recorded();
        state.phase4_started = true;
        let switch = RecordingSwitch::new(&rig);

        switch_to_staged_generation(&rig.ctx, &mut state, &switch, &messages)
            .await
            .expect("phase 4");

        let events = switch.events();
        let reissue = events
            .iter()
            .position(|event| matches!(event, Event::Reissue { .. }));
        let start = events
            .iter()
            .position(|event| matches!(event, Event::Start(_)));
        assert!(
            reissue.is_some() && start.is_some() && reissue < start,
            "already_new={already_new}: {events:?}"
        );
    }
}

/// A reissue that writes the new leaf and then fails — its key handover
/// or `PostgreSQL`'s reload — leaves step-ca absent, and the next run,
/// finding a new-generation leaf on disk, still reissues before it
/// starts step-ca.
#[tokio::test]
async fn phase4_resumed_after_a_failure_past_issuance_reissues_before_starting_stepca() {
    let rig = Rig::paused();
    let old = Generation {
        root_cert: rig.old.root_cert.clone(),
        root_key: rig.old.root_key.clone(),
        intermediate_cert: rig.old.intermediate_cert.clone(),
        intermediate_key: rig.old.intermediate_key.clone(),
    };
    let rig = rig.with_postgres_signed_by(&old);
    let messages = test_messages();
    let switch = RecordingSwitch::new(&rig);
    switch.fail_after_issuance.set(true);
    let mut state = rig.recorded();

    switch_to_staged_generation(&rig.ctx, &mut state, &switch, &messages)
        .await
        .expect_err("the reload after issuance fails");
    assert!(!switch.started());
    assert_eq!(rig.staged_present(), 0);
    let leaf = cert_der_from_pem(
        read_file(&rig.postgres_cert()).as_bytes(),
        &rig.postgres_cert(),
        &messages,
    )
    .expect("leaf");
    let new_intermediate = cert_der_from_pem(
        rig.new.intermediate_cert.as_bytes(),
        Path::new("intermediate"),
        &messages,
    )
    .expect("intermediate");
    assert!(
        cert_signed_by(&leaf, &new_intermediate).expect("verify"),
        "the failed run left a new-generation leaf on disk"
    );

    let switch = RecordingSwitch::new(&rig);
    let mut state = rig.recorded();
    assert!(state.phase4_started);
    switch_to_staged_generation(&rig.ctx, &mut state, &switch, &messages)
        .await
        .expect("resumed phase 4");

    let events = switch.events();
    let reissue = events
        .iter()
        .position(|event| matches!(event, Event::Reissue { .. }));
    let start = events
        .iter()
        .position(|event| matches!(event, Event::Start(_)));
    assert!(
        reissue.is_some() && start.is_some() && reissue < start,
        "{events:?}"
    );
}

#[tokio::test]
async fn phase4_without_a_postgres_entry_reissues_nothing() {
    let rig = Rig::paused();
    let messages = test_messages();
    let switch = RecordingSwitch::new(&rig);
    let mut state = rig.recorded();

    switch_to_staged_generation(&rig.ctx, &mut state, &switch, &messages)
        .await
        .expect("phase 4");

    assert!(
        !switch
            .events()
            .iter()
            .any(|event| matches!(event, Event::Reissue { .. }))
    );
    assert!(switch.started());
}

// ---------------------------------------------------------------------
// Phase 4: what reaches Docker
// ---------------------------------------------------------------------

fn compose_files_of(argv: &[String]) -> Vec<String> {
    argv.windows(2)
        .filter(|pair| pair.first().is_some_and(|flag| flag == "-f"))
        .filter_map(|pair| pair.get(1).cloned())
        .collect()
}

fn tail_after_project(argv: &[String]) -> Vec<String> {
    argv.iter()
        .position(|arg| arg == "-p")
        .map_or_else(Vec::new, |pos| argv.iter().skip(pos + 2).cloned().collect())
}

/// Without a recorded `stepca_bind_addr` the recreate passes the base
/// compose file alone, and the removal goes through the same identity.
#[test]
fn docker_switch_recreates_stepca_on_the_base_compose_file() {
    let rig = Rig::paused();
    let messages = test_messages();
    let switch = DockerStepCaSwitch::prepare(&rig.ctx, &messages).expect("prepare");

    switch.remove_stepca().expect("remove");
    switch.start_stepca(Some(RESTART_POLICY)).expect("start");

    let compose = rig.ctx.compose_file.display().to_string();
    let invocations = decode_fake_docker_log(&rig.docker_log);
    assert_eq!(invocations.len(), 3, "{invocations:?}");
    let remove = invocations.first().expect("rm");
    assert_eq!(compose_files_of(remove), vec![compose.clone()]);
    assert_eq!(tail_after_project(remove), ["rm", "-sf", "step-ca"]);
    let up = invocations.get(1).expect("up");
    assert_eq!(compose_files_of(up), vec![compose]);
    assert_eq!(tail_after_project(up), ["up", "-d", "--no-deps", "step-ca"]);
    let container = ComposeIdentity::resolve(&rig.ctx.compose_file, None, &messages)
        .expect("identity")
        .container(BootrootContainer::StepCa);
    assert_eq!(
        invocations.get(2).expect("update"),
        &vec![
            "update".to_string(),
            "--restart".to_string(),
            RESTART_POLICY.to_string(),
            container,
        ]
    );
}

/// With a recorded `stepca_bind_addr` the recreate adds the step-ca
/// exposed-port override after the base file, as `infra up` does.
#[test]
fn docker_switch_recreates_stepca_with_the_recorded_bind_override() {
    let rig = Rig::paused();
    let messages = test_messages();
    let bind = "192.168.1.10:9000";
    let state = StateFile {
        stepca_bind_addr: Some(bind.to_string()),
        ..StateFile::default()
    };
    state.save(&rig.ctx.state_file).expect("save state");
    let override_path =
        crate::commands::guardrails::write_stepca_exposed_override(rig.dir.path(), bind, &messages)
            .expect("override");
    let switch = DockerStepCaSwitch::prepare(&rig.ctx, &messages).expect("prepare");

    switch.start_stepca(None).expect("start");

    let invocations = decode_fake_docker_log(&rig.docker_log);
    assert_eq!(invocations.len(), 1, "no update without a policy");
    let up = invocations.first().expect("up");
    assert_eq!(
        compose_files_of(up),
        vec![
            rig.ctx.compose_file.display().to_string(),
            override_path.display().to_string(),
        ]
    );
    assert_eq!(tail_after_project(up), ["up", "-d", "--no-deps", "step-ca"]);
}

#[test]
fn docker_switch_refuses_a_recorded_bind_without_its_override_before_anything() {
    let rig = Rig::paused();
    let messages = test_messages();
    let state = StateFile {
        stepca_bind_addr: Some("192.168.1.10:9000".to_string()),
        ..StateFile::default()
    };
    state.save(&rig.ctx.state_file).expect("save state");

    assert!(DockerStepCaSwitch::prepare(&rig.ctx, &messages).is_err());
    assert_eq!(decode_fake_docker_log(&rig.docker_log).len(), 0);
}

/// A fake `docker` beside the rig's log that logs every invocation as
/// the self-contained fake does, and fails `inspect` with `stderr`;
/// every other command succeeds.
fn write_inspect_failing_docker(path: &Path, stderr: &str) {
    assert!(
        !stderr.contains('\''),
        "stderr is a single-quoted shell word"
    );
    crate::test_support::write_executable(
        path,
        format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\0' \"$#\" \"$@\" >> \"$(dirname \"$0\")/docker.log\"\n\
             if [ \"$1\" = inspect ]; then printf '%s\\n' '{stderr}' >&2; exit 1; fi\nexit 0\n"
        )
        .as_bytes(),
    );
}

/// The rig's context with `docker` in place of its fake.
fn ctx_with_docker(rig: &Rig, docker: PathBuf) -> RotateContext {
    RotateContext {
        docker,
        openbao_url: String::new(),
        kv_mount: rig.ctx.kv_mount.clone(),
        compose_file: rig.ctx.compose_file.clone(),
        state: StateFile::default(),
        paths: StatePaths::new(rig.ctx.paths.secrets_dir().to_path_buf()),
        state_dir: rig.ctx.state_dir.clone(),
        state_file: rig.ctx.state_file.clone(),
        secrets: path_tree(rig.ctx.paths.secrets_dir()),
    }
}

const DAEMON_ERROR: &str = "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?";

#[test]
fn docker_switch_reads_the_restart_policy_of_the_running_container() {
    let rig = Rig::paused();
    let messages = test_messages();
    let docker = rig.dir.path().join("inspect-docker");
    crate::test_support::write_executable(
        &docker,
        format!("#!/bin/sh\necho {RESTART_POLICY}\n").as_bytes(),
    );
    let ctx = ctx_with_docker(&rig, docker);
    let switch = DockerStepCaSwitch::prepare(&ctx, &messages).expect("prepare");
    assert_eq!(
        switch.current_restart_policy().expect("inspect").as_deref(),
        Some(RESTART_POLICY)
    );
}

/// Only Docker's own report that the container does not exist reads as
/// "no policy", in each spelling Docker releases have used.
#[test]
fn docker_switch_reads_no_policy_only_when_the_container_is_absent() {
    let rig = Rig::paused();
    let messages = test_messages();
    for stderr in [
        "Error: No such container: insight-bootroot-ca",
        "Error response from daemon: No such container: insight-bootroot-ca",
        "Error: No such object: insight-bootroot-ca",
        "error: no such object: insight-bootroot-ca",
    ] {
        let docker = rig.dir.path().join("absent-docker");
        write_inspect_failing_docker(&docker, stderr);
        let ctx = ctx_with_docker(&rig, docker);
        let switch = DockerStepCaSwitch::prepare(&ctx, &messages).expect("prepare");
        assert_eq!(
            switch.current_restart_policy().expect(stderr),
            None,
            "{stderr}"
        );
    }
}

/// Any other inspect failure is an error naming the container and what
/// Docker said, not an absent container.
#[test]
fn docker_switch_refuses_an_inspect_failure_that_is_not_absence() {
    let rig = Rig::paused();
    let messages = test_messages();
    for stderr in [DAEMON_ERROR, ""] {
        let docker = rig.dir.path().join("failing-docker");
        write_inspect_failing_docker(&docker, stderr);
        let ctx = ctx_with_docker(&rig, docker);
        let switch = DockerStepCaSwitch::prepare(&ctx, &messages).expect("prepare");
        let err = switch
            .current_restart_policy()
            .expect_err("an inspect failure is not absence")
            .to_string();
        assert!(err.contains(&switch.container()), "{err}");
        assert!(err.contains(stderr), "{err}");
    }
}

/// An inspect that fails while the container exists stops Phase 4
/// before anything changes: `phase4_started` stays unrecorded, step-ca
/// is neither removed nor recreated, and every staged file is still in
/// place, so a re-run reads the policy again.
#[tokio::test]
async fn phase4_changes_nothing_when_the_restart_policy_cannot_be_read() {
    let rig = Rig::paused();
    let messages = test_messages();
    let docker = rig.dir.path().join("failing-docker");
    write_inspect_failing_docker(&docker, DAEMON_ERROR);
    let ctx = ctx_with_docker(&rig, docker);
    let switch = DockerStepCaSwitch::prepare(&ctx, &messages).expect("prepare");
    let mut state = rig.recorded();

    let err = switch_to_staged_generation(&ctx, &mut state, &switch, &messages)
        .await
        .expect_err("an unreadable policy stops Phase 4");

    assert!(err.to_string().contains(DAEMON_ERROR), "{err}");
    let invocations = decode_fake_docker_log(&rig.docker_log);
    assert_eq!(
        invocations.len(),
        1,
        "only the inspect ran: {invocations:?}"
    );
    assert_eq!(
        invocations
            .first()
            .and_then(|args| args.first())
            .map(String::as_str),
        Some("inspect")
    );
    let recorded = rig.recorded();
    assert!(!recorded.phase4_started);
    assert_eq!(recorded.stepca_restart_policy, None);
    assert_eq!(rig.staged_present(), 4);
    assert_live_is(&rig, &rig.old);
}

/// The restart policy read back from `docker inspect` is the value
/// `infra up --restart-policy` gave, retry limit included.
#[test]
fn restart_policy_from_inspect_keeps_an_on_failure_retry_limit() {
    for (printed, expected) in [
        ("always 0\n", Some("always")),
        ("unless-stopped 0", Some("unless-stopped")),
        ("no 0", Some("no")),
        ("on-failure 5\n", Some("on-failure:5")),
        ("on-failure 0", Some("on-failure")),
        ("on-failure", Some("on-failure")),
        ("unless-stopped", Some("unless-stopped")),
        (" 0\n", Some("no")),
        (" 0", Some("no")),
        ("", None),
        ("  \n", None),
    ] {
        assert_eq!(
            restart_policy_from_inspect(printed).as_deref(),
            expected,
            "{printed:?}"
        );
    }
}

#[test]
fn key_public_args_read_the_key_with_the_password_as_the_owner() {
    let args = key_public_docker_args(
        "/host/secrets:/home/step",
        "1000:1000",
        LIVE_CA_TARGETS.root_key,
    );
    assert_eq!(
        args,
        [
            "run",
            "--user",
            "1000:1000",
            "--rm",
            "-v",
            "/host/secrets:/home/step",
            STEP_CA_HELPER_IMAGE,
            "step",
            "crypto",
            "key",
            "public",
            LIVE_CA_TARGETS.root_key,
            "--password-file",
            "/home/step/password.txt",
        ]
    );
}

#[test]
fn public_key_pem_decodes_to_the_certificate_spki() {
    let key = KeyPair::generate().expect("key");
    let der = public_key_der_from_pem(key.public_key_pem().as_bytes()).expect("decode");
    assert_eq!(der, key.subject_public_key_info());
    assert!(public_key_der_from_pem(key.serialize_pem().as_bytes()).is_err());
}

// ---------------------------------------------------------------------
// The OpenBao connection a run continuing a staged rotation makes
// ---------------------------------------------------------------------

/// A leaf-only HTTPS server for `localhost` whose certificate
/// `generation`'s intermediate signed, as `OpenBao`'s listener presents
/// the certificate `step certificate create` wrote for it. Answers every
/// request `200 OK`. Returns its port and the accept loop, to abort.
async fn serve_https_signed_by(generation: &Generation) -> (u16, tokio::task::JoinHandle<()>) {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let issuer = Issuer::from_ca_cert_pem(
        &generation.intermediate_cert,
        KeyPair::from_pem(&generation.intermediate_key).expect("intermediate key"),
    )
    .expect("intermediate issuer");
    let key = KeyPair::generate().expect("leaf key");
    let cert = CertificateParams::new(vec!["localhost".to_string()])
        .expect("leaf params")
        .signed_by(&key, &issuer)
        .expect("signed leaf");
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivateKeyDer::Pkcs8(key.serialize_der().into()),
        )
        .expect("server TLS config");
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("local addr").port();
    let server = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            // One connection at a time: a health check makes one request.
            let Ok(mut tls) = acceptor.accept(stream).await else {
                continue;
            };
            let mut buf = vec![0u8; 4096];
            let _ = tls.read(&mut buf).await;
            let _ = tls
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                .await;
            let _ = tls.shutdown().await;
        }
    });
    (port, server)
}

fn ca_key_command() -> crate::cli::args::RotateCommand {
    crate::cli::args::RotateCommand::CaKey(crate::cli::args::RotateCaKeyArgs {
        full: true,
        skip: Vec::new(),
        force: false,
        cleanup: false,
        pause_before_step_ca: false,
        registrar_socket_unit: None,
    })
}

/// After Phase 4's last move the live certificates are the new
/// generation while `OpenBao`'s listener still presents an old-generation
/// leaf: trust from the live files alone refuses it, and the client a
/// `rotate ca-key` run continuing the rotation builds still reaches it.
/// The same holds while paused and after each earlier move.
#[tokio::test]
async fn ca_key_resume_reaches_openbao_serving_an_old_generation_leaf() {
    let messages = test_messages();
    for moves in 0..=4 {
        let mut rig = Rig::paused();
        rig.apply_moves(moves);
        let (port, server) = serve_https_signed_by(&rig.old).await;
        rig.ctx.openbao_url = format!("https://localhost:{port}");

        if moves == 4 {
            let live_only =
                OpenBaoClient::with_local_trust(&rig.ctx.openbao_url, rig.ctx.paths.secrets_dir())
                    .expect("live-trust client");
            live_only
                .health_check()
                .await
                .expect_err("the live files alone are the new generation");
        }

        let client =
            super::super::super::rotate_openbao_client(&ca_key_command(), &rig.ctx, &messages)
                .await
                .expect("client");
        client
            .health_check()
            .await
            .unwrap_or_else(|err| panic!("after {moves} moves: {err:#}"));
        server.abort();
    }
}

/// An interruption in Phase 7 after `--cleanup` removed the backups and
/// before the state was deleted still leaves a client to resume with,
/// trusting the generation now live.
#[tokio::test]
async fn ca_key_resume_trust_skips_backups_cleanup_removed() {
    let messages = test_messages();
    let mut rig = Rig::paused();
    rig.apply_moves(4);
    for backup in [
        rig.ctx.paths.root_cert_bak(),
        rig.ctx.paths.root_key_bak(),
        rig.ctx.paths.intermediate_cert_bak(),
        rig.ctx.paths.intermediate_key_bak(),
    ] {
        fs::remove_file(backup).expect("remove backup");
    }
    let (port, server) = serve_https_signed_by(&rig.new).await;
    rig.ctx.openbao_url = format!("https://localhost:{port}");

    let client = super::super::super::rotate_openbao_client(&ca_key_command(), &rig.ctx, &messages)
        .await
        .expect("client");
    client
        .health_check()
        .await
        .expect("new-generation listener");
    server.abort();
}

/// Only a staged full rotation widens the trust; with no rotation, or an
/// unstaged one, the live certificates alone are it.
#[tokio::test]
async fn openbao_recovery_trust_applies_only_to_a_staged_rotation() {
    let messages = test_messages();
    let rig = Rig::paused();
    assert!(
        super::super::staged_rotation_openbao_trust(&rig.ctx, &messages)
            .await
            .expect("trust")
            .is_some()
    );

    let mut unstaged = rig.state(3);
    unstaged.staged = false;
    update_rotation_state(&rig.ctx.state_dir, &unstaged, &messages).expect("state");
    assert!(
        super::super::staged_rotation_openbao_trust(&rig.ctx, &messages)
            .await
            .expect("trust")
            .is_none()
    );

    crate::commands::trust::delete_rotation_state(&rig.ctx.state_dir, &messages).expect("delete");
    assert!(
        super::super::staged_rotation_openbao_trust(&rig.ctx, &messages)
            .await
            .expect("trust")
            .is_none()
    );
}
