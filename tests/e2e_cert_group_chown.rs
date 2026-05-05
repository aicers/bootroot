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
//! - Honors the `BOOTROOT_E2E_CERT_GROUP_GID` env var when the CI
//!   fixture provisions a dedicated supplementary group for the
//!   runner user. The number must be non-zero and a supplementary
//!   gid of the current process.
//! - Falls back to one of the current process's supplementary gids
//!   (excluding the primary gid). Skips when none exists, so local
//!   developer runs without supplementary groups still pass.

#![cfg(unix)]

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

use bootroot::cert_group::{
    self, CERT_DIR_MODE_GROUP, CERT_FILE_MODE, CertGroupPolicy, KEY_DIR_MODE_GROUP,
    KEY_FILE_MODE_GROUP,
};
use bootroot::fs_util;

fn pick_test_gid() -> Option<u32> {
    if let Ok(raw) = std::env::var("BOOTROOT_E2E_CERT_GROUP_GID")
        && let Ok(gid) = raw.trim().parse::<u32>()
    {
        if gid != 0 && cert_group::caller_can_chown_to(gid) {
            return Some(gid);
        }
        eprintln!(
            "BOOTROOT_E2E_CERT_GROUP_GID={raw} unusable (zero or caller is not a member); \
             falling back to a supplementary gid"
        );
    }
    cert_group::one_supplementary_test_gid()
}

#[tokio::test]
async fn cert_group_chown_full_round_trip_distinct_parents() {
    let Some(gid) = pick_test_gid() else {
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
    let Some(gid) = pick_test_gid() else {
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
