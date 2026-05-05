//! E2E-extended coverage for issue #593: full issuance/rotation
//! `write_cert_and_key` round-trip with `--cert-group` set to a gid
//! that is *not* the caller's primary gid, asserting both the mode
//! and the resulting group ownership.
//!
//! The unit tests in `src/fs_util.rs` and `src/cert_group.rs` cover
//! mode-by-mode behavior. This file adds the gid-ownership assertion
//! the issue calls out — proving the kernel's `chown` permission
//! check actually accepts the call and that the `gid` field of the
//! resulting file matches the requested policy gid.
//!
//! Behavior:
//! - When `BOOTROOT_E2E_REQUIRE_CERT_GROUP=1` is set (CI fixture
//!   path), the test fails — rather than skips — if
//!   `BOOTROOT_E2E_CERT_GROUP_GID` is missing, zero, equal to the
//!   primary gid, unknown to the host group DB, or one the caller
//!   cannot chown to. This is what locks in the e2e-extended
//!   regression: a CI environment that didn't provision the fixture
//!   shows up as a failure, not a silent green.
//! - Otherwise (local developer runs), the test honors
//!   `BOOTROOT_E2E_CERT_GROUP_GID` when usable, falls back to a
//!   supplementary gid of the current process, and skips when no
//!   suitable gid exists. This keeps `cargo test` runnable on
//!   developer machines without group setup.

#![cfg(unix)]

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

use bootroot::cert_group::{
    self, CERT_DIR_MODE_GROUP, CERT_FILE_MODE, CertGroupPolicy, KEY_DIR_MODE_GROUP,
    KEY_FILE_MODE_GROUP,
};
use bootroot::fs_util;

const REQUIRE_ENV: &str = "BOOTROOT_E2E_REQUIRE_CERT_GROUP";
const GID_ENV: &str = "BOOTROOT_E2E_CERT_GROUP_GID";

fn require_ci_fixture() -> bool {
    matches!(
        std::env::var(REQUIRE_ENV).ok().as_deref(),
        Some("1" | "true" | "yes" | "TRUE")
    )
}

/// Resolves the gid the test should chown to. In CI-fixture mode
/// (`BOOTROOT_E2E_REQUIRE_CERT_GROUP=1`) the env-provided gid is
/// mandatory and any deviation panics with a description of how to
/// fix the fixture. In dev mode a missing/unusable env var falls
/// back to a supplementary gid; if none is available the caller
/// returns `None` and the test is skipped.
fn resolve_test_gid() -> Option<u32> {
    let primary_gid = cert_group::current_process_egid();
    let raw = std::env::var(GID_ENV).ok();

    if require_ci_fixture() {
        let raw = raw.unwrap_or_else(|| {
            panic!(
                "{REQUIRE_ENV}=1 but {GID_ENV} is not set; the CI fixture \
                 must create a dedicated group, add the runner to it, and \
                 export the numeric gid before running cargo test"
            )
        });
        let gid: u32 = raw
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{GID_ENV}={raw:?} is not a valid numeric gid"));
        assert!(gid != 0, "{GID_ENV}=0 is rejected: gid 0 is root");
        assert!(
            gid != primary_gid,
            "{GID_ENV}={gid} equals the runner's primary gid; the fixture \
             must allocate a dedicated group whose gid differs from the \
             runner's primary gid so the chown path is actually exercised"
        );
        assert!(
            cert_group::gid_exists_on_host(gid),
            "{GID_ENV}={gid} is not present in the host group database; \
             the fixture must `groupadd` the gid before exporting it"
        );
        assert!(
            cert_group::caller_can_chown_to(gid),
            "{GID_ENV}={gid} is set but the caller is not a supplementary \
             member of that group; the fixture must `usermod -aG <name> \
             $USER` and re-enter the shell (e.g. `sg <name> -c ...`) so \
             the supplementary membership is visible to the test process"
        );
        return Some(gid);
    }

    if let Some(raw) = raw
        && let Ok(gid) = raw.trim().parse::<u32>()
    {
        if gid != 0 && gid != primary_gid && cert_group::caller_can_chown_to(gid) {
            return Some(gid);
        }
        eprintln!(
            "{GID_ENV}={raw} unusable (zero, equal to primary gid, or caller \
             is not a member); falling back to a supplementary gid"
        );
    }
    cert_group::one_supplementary_test_gid()
}

#[tokio::test]
async fn cert_group_chown_full_round_trip_distinct_parents() {
    let Some(gid) = resolve_test_gid() else {
        eprintln!("skipped: no supplementary gid available for chown test");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("certs").join("svc-cert.pem");
    let key_path = dir.path().join("secrets").join("svc-key.pem");

    fs_util::write_cert_and_key(
        &cert_path,
        &key_path,
        "CERT-DATA",
        "KEY-DATA",
        CertGroupPolicy::with_gid(gid),
    )
    .await
    .unwrap();

    let key_meta = std::fs::metadata(&key_path).unwrap();
    let cert_meta = std::fs::metadata(&cert_path).unwrap();
    let key_dir_meta = std::fs::metadata(key_path.parent().unwrap()).unwrap();
    let cert_dir_meta = std::fs::metadata(cert_path.parent().unwrap()).unwrap();

    assert_eq!(key_meta.permissions().mode() & 0o777, KEY_FILE_MODE_GROUP);
    assert_eq!(cert_meta.permissions().mode() & 0o777, CERT_FILE_MODE);
    assert_eq!(
        key_dir_meta.permissions().mode() & 0o777,
        KEY_DIR_MODE_GROUP
    );
    assert_eq!(
        cert_dir_meta.permissions().mode() & 0o777,
        CERT_DIR_MODE_GROUP
    );
    assert_eq!(key_meta.gid(), gid, "key file gid must match policy");
    assert_eq!(cert_meta.gid(), gid, "cert file gid must match policy");
    assert_eq!(key_dir_meta.gid(), gid, "key parent dir gid must match");
    assert_eq!(cert_dir_meta.gid(), gid, "cert parent dir gid must match");
}

/// Rotation regression: re-running `write_cert_and_key` after a
/// hostile operator-side `chmod`/`chgrp` must restore both mode and
/// gid ownership. This is the exact failure mode that caused #593 in
/// the field — without it, every rotation reverts the operator's
/// container-access fix.
#[tokio::test]
async fn cert_group_chown_rotation_re_asserts_gid_ownership() {
    let Some(gid) = resolve_test_gid() else {
        eprintln!("skipped: no supplementary gid available for chown test");
        return;
    };
    let primary_gid = cert_group::current_process_egid();
    if primary_gid == gid {
        eprintln!("skipped: test gid equals primary gid; rotation regression is uninteresting");
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("certs");
    let cert_path = shared.join("svc-cert.pem");
    let key_path = shared.join("svc-key.pem");

    fs_util::write_cert_and_key(
        &cert_path,
        &key_path,
        "C1",
        "K1",
        CertGroupPolicy::with_gid(gid),
    )
    .await
    .unwrap();
    assert_eq!(std::fs::metadata(&key_path).unwrap().gid(), gid);

    // Hostile regression: operator (or a buggy hook) chgrps back to
    // the primary gid and clamps the mode to 0600. The next rotation
    // must put it back without operator intervention.
    std::os::unix::fs::chown(&key_path, None, Some(primary_gid)).unwrap();
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::os::unix::fs::chown(&shared, None, Some(primary_gid)).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).unwrap();

    fs_util::write_cert_and_key(
        &cert_path,
        &key_path,
        "C2",
        "K2",
        CertGroupPolicy::with_gid(gid),
    )
    .await
    .unwrap();

    let key_meta = std::fs::metadata(&key_path).unwrap();
    let dir_meta = std::fs::metadata(&shared).unwrap();
    assert_eq!(key_meta.permissions().mode() & 0o777, KEY_FILE_MODE_GROUP);
    assert_eq!(key_meta.gid(), gid, "rotation must restore key gid");
    assert_eq!(dir_meta.permissions().mode() & 0o777, KEY_DIR_MODE_GROUP);
    assert_eq!(dir_meta.gid(), gid, "rotation must restore parent gid");
}
