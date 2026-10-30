//! Root-only coverage for `--cert-owner`: the issued key is given to a
//! numeric uid with group 0 and mode `0600`, the certificate and the CA
//! bundle stay `0644` under the writer, and both directories become
//! `0755`, on the first write and on every write after it.
//!
//! Giving a file to another uid needs root, so the unit tests can only
//! show that a non-root writer fails cleanly. This file shows what a root
//! writer produces, and that the result does what it is for: the owner
//! uid can read all three files and any other non-root uid can read only
//! the public two. The uids are ones the host's user database does not
//! have, which is the ordinary case for a uid that names a user inside a
//! container.
//!
//! Behavior:
//! - Run as root, every test runs.
//! - When `BOOTROOT_E2E_REQUIRE_CERT_OWNER=1` is set and the process is
//!   not root, every test fails rather than skips, so a CI step meant to
//!   run this file as root cannot go green by skipping it.
//! - Otherwise (a developer's non-root `cargo test`), every test skips.

#![cfg(unix)]

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::Path;

use bootroot::cert_group::{
    CA_BUNDLE_FILE_MODE, CERT_FILE_MODE, CertGroupPolicy, DIR_MODE_OWNER, KEY_FILE_MODE_OWNER,
};
use bootroot::fs_util;

const REQUIRE_ENV: &str = "BOOTROOT_E2E_REQUIRE_CERT_OWNER";

/// Whether the tests can run: they need root, and fail rather than skip
/// without it when [`REQUIRE_ENV`] asks for them.
fn running_as_root() -> bool {
    if fs_util::current_process_euid() == 0 {
        return true;
    }
    assert!(
        std::env::var(REQUIRE_ENV).ok().as_deref() != Some("1"),
        "{REQUIRE_ENV}=1 but the process runs as uid {}; this test must run as root",
        fs_util::current_process_euid()
    );
    eprintln!("skipped: --cert-owner chown coverage needs root");
    false
}

/// Whether `uid` is in the host's user database (`getpwuid_r`).
fn uid_exists_on_host(uid: u32) -> bool {
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    // SAFETY: a zeroed `libc::passwd` is a valid initial value: every
    // field is a pointer or an integer, and the call below fills them.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer names a live buffer exclusively borrowed for
    // the duration of the call, and `buf.len()` is its true length.
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            std::ptr::addr_of_mut!(pwd),
            buf.as_mut_ptr(),
            buf.len(),
            std::ptr::addr_of_mut!(result),
        )
    };
    rc == 0 && !result.is_null()
}

/// Two distinct uids the host does not know: the key's owner, and a
/// second account that must be refused the key.
fn unknown_uids() -> (u32, u32) {
    let mut uids = (4_000_000_000..4_000_001_000).filter(|uid| !uid_exists_on_host(*uid));
    let owner = uids.next().expect("an unused uid");
    let other = uids.next().expect("a second unused uid");
    (owner, other)
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).expect("stat").permissions().mode() & 0o7777
}

fn owner(path: &Path) -> (u32, u32) {
    let meta = std::fs::metadata(path).expect("stat");
    (meta.uid(), meta.gid())
}

/// Asserts the owner policy's result for one key, certificate and
/// bundle, and their directories.
fn assert_owner_layout(uid: u32, key: &Path, cert: &Path, bundle: &Path) {
    assert_eq!(owner(key), (uid, 0), "the key is given to the uid, group 0");
    assert_eq!(mode(key), KEY_FILE_MODE_OWNER);
    assert_eq!(owner(cert), (0, 0), "the certificate keeps the writer");
    assert_eq!(mode(cert), CERT_FILE_MODE);
    assert_eq!(owner(bundle), (0, 0), "the bundle keeps the writer");
    assert_eq!(mode(bundle), CA_BUNDLE_FILE_MODE);
    for dir in [key.parent(), cert.parent()] {
        let dir = dir.expect("parent");
        assert_eq!(mode(dir), DIR_MODE_OWNER, "{}", dir.display());
        assert_eq!(owner(dir), (0, 0), "{} keeps its owner", dir.display());
    }
}

/// A temporary root every uid can traverse: `tempfile` creates it
/// `0700`, which would stop both uids before they reach the key's
/// directory.
fn traversable_tempdir() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
        .expect("chmod tempdir");
    dir
}

/// Whether `uid` can read `path`, judged by `cat` run as that uid.
fn readable_as(uid: u32, path: &Path) -> bool {
    std::process::Command::new("cat")
        .arg(path)
        .uid(uid)
        .gid(uid)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run cat")
        .success()
}

#[tokio::test]
async fn cert_owner_full_round_trip_distinct_parents() {
    if !running_as_root() {
        return;
    }
    let (uid, _) = unknown_uids();
    let dir = traversable_tempdir();
    let cert = dir.path().join("certs").join("svc-cert.pem");
    let key = dir.path().join("secrets").join("svc-key.pem");
    let bundle = dir.path().join("certs").join("ca-bundle.pem");
    let policy = CertGroupPolicy::with_owner(uid);

    fs_util::write_cert_and_key(&cert, &key, "CERT-DATA", "KEY-DATA", policy)
        .await
        .expect("write the pair as root");
    fs_util::write_ca_bundle(&bundle, "BUNDLE-DATA", policy)
        .await
        .expect("write the bundle as root");

    assert_owner_layout(uid, &key, &cert, &bundle);
}

#[tokio::test]
async fn cert_owner_full_round_trip_shared_parent() {
    if !running_as_root() {
        return;
    }
    let (uid, _) = unknown_uids();
    let dir = traversable_tempdir();
    let shared = dir.path().join("tls");
    let cert = shared.join("svc-cert.pem");
    let key = shared.join("svc-key.pem");
    let bundle = shared.join("ca-bundle.pem");
    let policy = CertGroupPolicy::with_owner(uid);

    fs_util::write_ca_bundle(&bundle, "BUNDLE-DATA", policy)
        .await
        .expect("write the bundle as root");
    fs_util::write_cert_and_key(&cert, &key, "CERT-DATA", "KEY-DATA", policy)
        .await
        .expect("write the pair as root");

    assert_owner_layout(uid, &key, &cert, &bundle);
}

/// A renewal re-asserts the owner and the mode a hand edit took away,
/// and gives the consumer a fresh inode rather than rewriting the file.
#[tokio::test]
async fn cert_owner_renewal_reasserts_owner_and_mode() {
    if !running_as_root() {
        return;
    }
    let (uid, _) = unknown_uids();
    let dir = traversable_tempdir();
    let cert = dir.path().join("tls").join("svc-cert.pem");
    let key = dir.path().join("tls").join("svc-key.pem");
    let policy = CertGroupPolicy::with_owner(uid);
    fs_util::write_cert_and_key(&cert, &key, "CERT-1", "KEY-1", policy)
        .await
        .expect("first write");

    std::os::unix::fs::chown(&key, Some(0), Some(0)).expect("chown the key to root");
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).expect("chmod 0644");
    let tampered = std::fs::metadata(&key).expect("stat").ino();

    fs_util::write_cert_and_key(&cert, &key, "CERT-2", "KEY-2", policy)
        .await
        .expect("renewal");

    assert_eq!(std::fs::read_to_string(&key).expect("read"), "KEY-2");
    assert_eq!(owner(&key), (uid, 0));
    assert_eq!(mode(&key), KEY_FILE_MODE_OWNER);
    assert_ne!(
        std::fs::metadata(&key).expect("stat").ino(),
        tampered,
        "the renewal publishes a new inode"
    );
}

/// The point of the policy: the owner uid reads the key, the certificate
/// and the bundle, and another non-root uid reads only the public two.
#[tokio::test]
async fn cert_owner_only_the_owner_reads_the_key() {
    if !running_as_root() {
        return;
    }
    let (uid, other) = unknown_uids();
    let dir = traversable_tempdir();
    let cert = dir.path().join("certs").join("svc-cert.pem");
    let key = dir.path().join("secrets").join("svc-key.pem");
    let bundle = dir.path().join("certs").join("ca-bundle.pem");
    let policy = CertGroupPolicy::with_owner(uid);
    fs_util::write_cert_and_key(&cert, &key, "CERT-DATA", "KEY-DATA", policy)
        .await
        .expect("write the pair as root");
    fs_util::write_ca_bundle(&bundle, "BUNDLE-DATA", policy)
        .await
        .expect("write the bundle as root");

    for path in [&key, &cert, &bundle] {
        assert!(readable_as(uid, path), "the owner reads {}", path.display());
    }
    assert!(
        readable_as(other, &cert),
        "another uid reads the certificate"
    );
    assert!(readable_as(other, &bundle), "another uid reads the bundle");
    assert!(!readable_as(other, &key), "another uid is refused the key");
}
