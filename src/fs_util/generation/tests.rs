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
/// under the configured names — the paths were renamed since — publishes
/// nothing and leaves `current` where it was.
#[tokio::test]
async fn a_republication_without_the_configured_names_publishes_nothing() {
    let dir = TempDir::new().expect("tempdir");
    let mut target = target(dir.path());
    publish_generation(&target, issued("A"), &Probe::default())
        .await
        .expect("publish");

    target.key_name = "renamed-key.pem".into();
    let outcome = publish_generation(&target, PairSource::Current, &Probe::default())
        .await
        .expect("not a failure");

    assert_eq!(outcome, GenerationOutcome::StalePair);
    assert_eq!(
        std::fs::read_link(target.current()).expect("current"),
        Path::new("gen-1")
    );
    assert!(!target.root.join("gen-2").exists());
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

/// A `current` naming something that is not a generation is replaced by
/// the next publication rather than trusted.
#[tokio::test]
async fn a_current_naming_no_generation_is_replaced() {
    let dir = TempDir::new().expect("tempdir");
    let target = target(dir.path());
    publish_generation(&target, issued("A"), &Probe::default())
        .await
        .expect("publish A");
    std::fs::remove_file(target.current()).expect("remove current");
    std::os::unix::fs::symlink("../../elsewhere", target.current()).expect("repoint current");

    let outcome = publish_generation(&target, PairSource::Current, &Probe::default())
        .await
        .expect("nothing to carry forward is not a failure");
    assert_eq!(outcome, GenerationOutcome::NoCurrent);

    let outcome = publish_generation(&target, issued("B"), &Probe::default())
        .await
        .expect("publish B");
    assert_eq!(outcome, GenerationOutcome::Published { generation: 2 });
    assert_eq!(
        std::fs::read_link(target.current()).expect("current"),
        Path::new("gen-2")
    );
}
