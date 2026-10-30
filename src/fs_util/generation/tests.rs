//! The engine's own rules: what counts as a generation, and what a
//! republication does with a tree it cannot carry forward.
//!
//! The publication as an issuance runs it — order, retention, failure
//! and the interleavings with a trust update — is driven from
//! `crate::acme::flow`'s tests, through the entry points the daemon
//! calls.

use std::ffi::OsStr;

use tempfile::TempDir;

use super::*;

fn target(dir: &Path) -> GenerationTarget {
    let key_dir = dir.join("keys");
    GenerationTarget {
        root: key_dir.join(GENERATIONS_DIR_NAME).join("svc"),
        key_dir,
        policy: CertGroupPolicy::none(),
        cert_name: "cert.pem".into(),
        key_name: "key.pem".into(),
        bundle: None,
    }
}

fn issued(label: &str) -> PairSource {
    PairSource::Issued {
        cert_pem: format!("certificate {label}"),
        key_pem: PrivateKeyPem::new(format!("key {label}")),
    }
}

/// Only `gen-` followed by a decimal number from 1 up, with no leading
/// zero, is a generation; everything else is somebody else's entry.
#[test]
fn only_canonical_names_are_generations() {
    for (name, expected) in [
        ("gen-1", Some(1)),
        ("gen-42", Some(42)),
        ("gen-18446744073709551615", Some(u64::MAX)),
        ("gen-0", None),
        ("gen-01", None),
        ("gen-", None),
        ("gen-1.tmp", None),
        ("gen-+1", None),
        ("gen-1a", None),
        ("gen-18446744073709551616", None),
        ("GEN-1", None),
        ("current", None),
    ] {
        assert_eq!(parse_generation(OsStr::new(name)), expected, "{name}");
    }
    assert!(is_staged_generation(OsStr::new("gen-3.tmp")));
    assert!(!is_staged_generation(OsStr::new("gen-3")));
    assert!(!is_staged_generation(OsStr::new("current.tmp")));
}

/// A republication whose `current` generation does not hold the pair
/// under the configured names — the paths were renamed since — fails,
/// names the member it looked for, publishes nothing and leaves
/// `current` where it was.
#[tokio::test]
async fn a_republication_without_the_configured_names_publishes_nothing() {
    for rename_key in [false, true] {
        let dir = TempDir::new().expect("tempdir");
        let mut target = target(dir.path());
        publish_generation(&target, issued("A"), &Probe::default())
            .await
            .expect("publish");

        let missing = if rename_key {
            target.key_name = "renamed-key.pem".into();
            target.root.join("gen-1").join("renamed-key.pem")
        } else {
            target.cert_name = "renamed-cert.pem".into();
            target.root.join("gen-1").join("renamed-cert.pem")
        };
        let err = publish_generation(&target, PairSource::Current, &Probe::default())
            .await
            .expect_err("a snapshot without the configured names is not skipped");

        let message = format!("{err:#}");
        assert!(
            message.contains(&missing.display().to_string()),
            "{message}"
        );
        assert_eq!(
            std::fs::read_link(target.current()).expect("current"),
            Path::new("gen-1")
        );
        assert_no_new_generation(&target);
    }
}

/// Configured certificate and key files beside the tree, labelled so a
/// generation that copied them would show it.
fn configured(target: &GenerationTarget) -> (PathBuf, PathBuf) {
    std::fs::create_dir_all(&target.key_dir).expect("key dir");
    let cert = target.key_dir.join(&target.cert_name);
    let key = target.key_dir.join(&target.key_name);
    std::fs::write(&cert, "certificate configured").expect("write");
    std::fs::write(&key, "key configured").expect("write");
    (cert, key)
}

/// Every entry under `root`, recursively, with a symlink's target or a
/// file's bytes: what a failed republication must leave unchanged.
fn tree_state(root: &Path) -> Vec<(PathBuf, String)> {
    let mut state = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("list") {
            let path = entry.expect("entry").path();
            let meta = std::fs::symlink_metadata(&path).expect("stat");
            let contents = if meta.file_type().is_symlink() {
                format!(
                    "-> {}",
                    std::fs::read_link(&path).expect("readlink").display()
                )
            } else if meta.is_dir() {
                pending.push(path.clone());
                "dir".to_string()
            } else {
                std::fs::read_to_string(&path).expect("read")
            };
            state.push((path, contents));
        }
    }
    state.sort_unstable();
    state
}

fn assert_no_new_generation(target: &GenerationTarget) {
    let names: Vec<_> = std::fs::read_dir(&target.root)
        .expect("list the root")
        .map(|entry| entry.expect("entry").file_name())
        .collect();
    assert!(
        !names
            .iter()
            .any(|name| name.to_string_lossy().starts_with("gen-2")),
        "{names:?}"
    );
}

/// Every way an existing `current` can be unusable for a trust update
/// fails it with an error naming the offending link, directory or
/// member, and leaves the tree and the configured pair byte for byte as
/// they were: no replacement generation, nothing repaired, and nothing
/// taken from the configured files instead.
#[tokio::test]
async fn an_unusable_current_fails_a_republication_and_changes_nothing() {
    type Spoil = fn(&mut GenerationTarget) -> PathBuf;
    let cases: [(&str, Spoil); 7] = [
        ("the generation is gone", |target| {
            let generation = target.root.join("gen-1");
            std::fs::remove_dir_all(&generation).expect("remove gen-1");
            generation
        }),
        ("the certificate is gone", |target| {
            let member = target.root.join("gen-1").join("cert.pem");
            std::fs::remove_file(&member).expect("remove the certificate");
            member
        }),
        ("the key is gone", |target| {
            let member = target.root.join("gen-1").join("key.pem");
            std::fs::remove_file(&member).expect("remove the key");
            member
        }),
        ("the certificate was renamed", |target| {
            target.cert_name = "renamed-cert.pem".into();
            target.root.join("gen-1").join("renamed-cert.pem")
        }),
        ("the key was renamed", |target| {
            target.key_name = "renamed-key.pem".into();
            target.root.join("gen-1").join("renamed-key.pem")
        }),
        ("current names gen-01", |target| {
            // A complete generation under a noncanonical name: whole,
            // and still not carried forward.
            let other = target.root.join("gen-01");
            std::fs::create_dir(&other).expect("mkdir gen-01");
            std::fs::write(other.join("cert.pem"), "certificate other").expect("write");
            std::fs::write(other.join("key.pem"), "key other").expect("write");
            std::fs::remove_file(target.current()).expect("remove current");
            std::os::unix::fs::symlink("gen-01", target.current()).expect("repoint current");
            PathBuf::from("gen-01")
        }),
        ("current is absolute", |target| {
            let absolute = target.root.join("gen-1");
            std::fs::remove_file(target.current()).expect("remove current");
            std::os::unix::fs::symlink(&absolute, target.current()).expect("repoint current");
            absolute
        }),
    ];
    for (case, spoil) in cases {
        let dir = TempDir::new().expect("tempdir");
        let mut target = target(dir.path());
        publish_generation(&target, issued("A"), &Probe::default())
            .await
            .expect("publish A");
        let offending = spoil(&mut target);
        // After the spoil, so a renamed member is on disk under its new
        // configured name for a fallback to find.
        let (cert, key) = configured(&target);
        let link = std::fs::read_link(target.current()).expect("current");
        let before = tree_state(&target.root);

        let err = publish_generation(&target, PairSource::Current, &Probe::default())
            .await
            .expect_err(case);

        let message = format!("{err:#}");
        assert!(
            message.contains(&offending.display().to_string()),
            "{case}: {message}"
        );
        assert!(
            message.contains(&target.current().display().to_string()),
            "{case}: {message}"
        );
        assert!(!message.contains("key A"), "{case}: {message}");
        assert_eq!(
            std::fs::read_link(target.current()).expect("current"),
            link,
            "{case}"
        );
        assert_eq!(tree_state(&target.root), before, "{case}");
        assert_eq!(
            std::fs::read_to_string(&cert).expect("cert"),
            "certificate configured",
            "{case}"
        );
        assert_eq!(
            std::fs::read_to_string(&key).expect("key"),
            "key configured",
            "{case}"
        );
    }
}

/// A trust update on a profile with no tree, whose configured pair is
/// already on disk, succeeds without creating the tree and without
/// seeding a generation from those files.
#[tokio::test]
async fn a_trust_update_without_a_tree_seeds_nothing() {
    let dir = TempDir::new().expect("tempdir");
    let target = target(dir.path());
    let (cert, key) = configured(&target);

    let outcome = publish_generation(&target, PairSource::Current, &Probe::default())
        .await
        .expect("nothing to carry forward is not a failure");

    assert_eq!(outcome, GenerationOutcome::NoCurrent);
    assert!(!target.key_dir.join(GENERATIONS_DIR_NAME).exists());
    assert_eq!(
        std::fs::read_to_string(&cert).expect("cert"),
        "certificate configured"
    );
    assert_eq!(
        std::fs::read_to_string(&key).expect("key"),
        "key configured"
    );
}

/// A directory or a file where `current` belongs is not renamed over:
/// the publication fails and names it.
#[tokio::test]
async fn a_current_that_is_not_a_symlink_is_refused() {
    let dir = TempDir::new().expect("tempdir");
    let target = target(dir.path());
    std::fs::create_dir_all(target.current()).expect("plant a directory");

    let err = publish_generation(&target, issued("A"), &Probe::default())
        .await
        .expect_err("a directory at current is refused");

    assert!(
        format!("{err:#}").contains(&target.current().display().to_string()),
        "{err:#}"
    );
    assert!(target.current().is_dir());
}

/// A `current` naming something that is not a generation is never
/// trusted: a trust update fails on it and leaves it, and the next
/// issuance replaces it.
#[tokio::test]
async fn a_current_naming_no_generation_is_replaced() {
    let dir = TempDir::new().expect("tempdir");
    let target = target(dir.path());
    publish_generation(&target, issued("A"), &Probe::default())
        .await
        .expect("publish A");
    std::fs::remove_file(target.current()).expect("remove current");
    std::os::unix::fs::symlink("../../elsewhere", target.current()).expect("repoint current");

    let err = publish_generation(&target, PairSource::Current, &Probe::default())
        .await
        .expect_err("a link that names no generation is not skipped");
    assert!(format!("{err:#}").contains("../../elsewhere"), "{err:#}");
    assert_eq!(
        std::fs::read_link(target.current()).expect("current"),
        Path::new("../../elsewhere")
    );

    let outcome = publish_generation(&target, issued("B"), &Probe::default())
        .await
        .expect("publish B");
    assert_eq!(outcome, GenerationOutcome::Published { generation: 2 });
    assert_eq!(
        std::fs::read_link(target.current()).expect("current"),
        Path::new("gen-2")
    );
}

/// Writes a certificate and key labelled `X` outside the tree, for a
/// link inside it to point at.
fn outside(dir: &Path) -> PathBuf {
    let outside = dir.join("outside");
    std::fs::create_dir(&outside).expect("mkdir");
    std::fs::write(outside.join("cert.pem"), "certificate X").expect("write");
    std::fs::write(outside.join("key.pem"), "key X").expect("write");
    outside
}

/// A trust update whose `current` names a generation that is itself a
/// symlink refuses it, names it, and copies nothing from where it
/// points.
#[tokio::test]
async fn a_symlinked_generation_is_refused_and_not_followed() {
    let dir = TempDir::new().expect("tempdir");
    let target = target(dir.path());
    publish_generation(&target, issued("A"), &Probe::default())
        .await
        .expect("publish A");
    let outside = outside(dir.path());
    let generation = target.root.join("gen-1");
    std::fs::remove_dir_all(&generation).expect("remove gen-1");
    std::os::unix::fs::symlink(&outside, &generation).expect("plant a link");

    let err = publish_generation(&target, PairSource::Current, &Probe::default())
        .await
        .expect_err("a symlinked generation is refused");

    assert!(
        format!("{err:#}").contains(&generation.display().to_string()),
        "{err:#}"
    );
    assert_eq!(
        std::fs::read_link(target.current()).expect("current"),
        Path::new("gen-1")
    );
    assert!(!target.root.join("gen-2").exists());
    assert!(!target.root.join("gen-2.tmp").exists());
}

/// A certificate or key inside the generation that is a symlink is
/// refused the same way, rather than read through.
#[tokio::test]
async fn a_symlinked_generation_member_is_refused_and_not_followed() {
    for member in ["cert.pem", "key.pem"] {
        let dir = TempDir::new().expect("tempdir");
        let target = target(dir.path());
        publish_generation(&target, issued("A"), &Probe::default())
            .await
            .expect("publish A");
        let outside = outside(dir.path());
        let path = target.root.join("gen-1").join(member);
        std::fs::remove_file(&path).expect("remove the member");
        std::os::unix::fs::symlink(outside.join(member), &path).expect("plant a link");

        let err = publish_generation(&target, PairSource::Current, &Probe::default())
            .await
            .expect_err("a symlinked member is refused");

        assert!(
            format!("{err:#}").contains(&path.display().to_string()),
            "{member}: {err:#}"
        );
        assert_eq!(
            std::fs::read_link(target.current()).expect("current"),
            Path::new("gen-1"),
            "{member}"
        );
        let names: Vec<_> = std::fs::read_dir(&target.root)
            .expect("list the root")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert!(
            !names
                .iter()
                .any(|name| name.to_string_lossy().starts_with("gen-2")),
            "{member}: {names:?}"
        );
    }
}

/// A trust update on a tree that exists without a `current` — its first
/// issuance failed before the swap — takes the lock, finds nothing to
/// carry forward, and publishes nothing.
#[tokio::test]
async fn a_trust_update_on_a_tree_without_current_publishes_nothing() {
    let dir = TempDir::new().expect("tempdir");
    let target = target(dir.path());
    let failing = Probe::new(|point| {
        if point == PublicationPoint::Staged {
            anyhow::bail!("injected failure at {point:?}");
        }
        Ok(())
    });
    publish_generation(&target, issued("A"), &failing)
        .await
        .expect_err("the first issuance fails before the swap");
    let (cert, key) = configured(&target);

    let outcome = publish_generation(&target, PairSource::Current, &Probe::default())
        .await
        .expect("nothing to carry forward is not a failure");

    assert_eq!(outcome, GenerationOutcome::NoCurrent);
    assert!(!is_symlink(&target.current()));
    assert!(!target.root.join("gen-1").exists());
    assert_eq!(
        std::fs::read_to_string(&cert).expect("cert"),
        "certificate configured",
        "nothing is seeded from the configured pair"
    );
    assert_eq!(
        std::fs::read_to_string(&key).expect("key"),
        "key configured"
    );
}

fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// A uid the test process is not.
fn foreign_uid() -> u32 {
    if super::super::current_process_euid() == 4_000_000_000 {
        4_000_000_001
    } else {
        4_000_000_000
    }
}

/// Whether a root-only test should run: it runs as root, and fails
/// rather than skips when `BOOTROOT_E2E_REQUIRE_CERT_OWNER=1` asks for it
/// and the process is not root, so a CI step that meant to run it as
/// root cannot pass by skipping it.
fn running_as_root_or_required() -> bool {
    if super::super::current_process_euid() == 0 {
        return true;
    }
    assert!(
        std::env::var_os("BOOTROOT_E2E_REQUIRE_CERT_OWNER").is_none_or(|value| value != "1"),
        "BOOTROOT_E2E_REQUIRE_CERT_OWNER=1 requires this test to run as root"
    );
    false
}

/// A non-root process cannot give a generation's key to another uid:
/// the publication fails naming the uid and the root requirement, and
/// `current` still names the generation it named before. Skipped as
/// root, where the chown succeeds.
#[tokio::test]
async fn an_owner_publication_a_non_root_process_cannot_apply_keeps_current() {
    if super::super::current_process_euid() == 0 {
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    let mut target = target(dir.path());
    publish_generation(&target, issued("A"), &Probe::default())
        .await
        .expect("publish");

    let uid = foreign_uid();
    target.policy = CertGroupPolicy::with_owner(uid);
    let err = publish_generation(&target, issued("B"), &Probe::default())
        .await
        .expect_err("a non-root process cannot give the key away");
    let message = format!("{err:#}");
    assert!(
        message.contains(&format!("uid {uid} gid 0"))
            && message.contains("bootroot-agent to run as root"),
        "{message}"
    );
    assert_eq!(
        std::fs::read_link(target.current()).expect("current"),
        Path::new("gen-1")
    );
    assert_eq!(
        std::fs::read_to_string(target.root.join("gen-1").join("key.pem")).expect("key"),
        "key A"
    );
}

/// As root, a generation published under an owner holds the key owned
/// by that uid and group 0 at `0600`, the certificate and the bundle at
/// `0644` owned by the writer, and every directory of the tree at
/// `0755` — and a republication for trust re-asserts all of it. The uid
/// is one the host's user database need not have.
#[tokio::test]
async fn cert_owner_generation_modes_as_root_only() {
    use std::os::unix::fs::MetadataExt as _;

    if !running_as_root_or_required() {
        return;
    }
    let dir = TempDir::new().expect("tempdir");
    let mut target = target(dir.path());
    let uid = 4_000_000_000;
    target.policy = CertGroupPolicy::with_owner(uid);
    std::fs::create_dir_all(&target.key_dir).expect("key dir");
    let bundle_path = target.key_dir.join("ca-bundle.pem");
    std::fs::write(&bundle_path, "bundle").expect("bundle");
    target.bundle = Some((bundle_path, "ca-bundle.pem".into()));

    publish_generation(&target, issued("A"), &Probe::default())
        .await
        .expect("publish as root");
    publish_generation(&target, PairSource::Current, &Probe::default())
        .await
        .expect("republish as root");

    let generation = target.root.join("gen-2");
    assert_eq!(
        std::fs::read_link(target.current()).expect("current"),
        Path::new("gen-2")
    );
    let key = std::fs::metadata(generation.join("key.pem")).expect("key");
    assert_eq!((key.uid(), key.gid()), (uid, 0));
    assert_eq!(key.mode() & 0o7777, 0o600);
    for public in ["cert.pem", "ca-bundle.pem"] {
        let meta = std::fs::metadata(generation.join(public)).expect(public);
        assert_eq!((meta.uid(), meta.gid()), (0, 0), "{public}");
        assert_eq!(meta.mode() & 0o7777, 0o644, "{public}");
    }
    for tree_dir in [
        target.key_dir.clone(),
        target.key_dir.join(GENERATIONS_DIR_NAME),
        target.root.clone(),
        generation,
    ] {
        let meta = std::fs::metadata(&tree_dir).expect("dir");
        assert_eq!(meta.mode() & 0o7777, 0o755, "{}", tree_dir.display());
    }
}
