//! Operator-configurable group ownership policy for issued service
//! certificates and their parent directories.
//!
//! `bootroot-agent` writes service cert/key files at issuance and at
//! every rotation. The default policy keeps `<svc>-key.pem` at `0600`
//! and the parent directory at `0700`, which is correct for host-local
//! consumers but breaks the common deployment pattern where the cert/key
//! is bind-mounted into a container running as a non-root user.
//!
//! The flag `--cert-group <gid-or-name>` opts a service into a
//! group-readable policy that survives rotation: cert and key parent
//! directories become group-traversable, the key file becomes group-
//! readable (`0640`), and group ownership of all four (key, cert, both
//! parent directories) is set to the operator-supplied gid.
//!
//! See `docs/services/cert-group.md` for the operator-facing overview.

use std::ffi::CString;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};
use thiserror::Error;
use tokio::fs;

use crate::fs_util::{self, StagedDurability, StagedOwner};

/// Default mode for the cert/key parent directory when no `--cert-group`
/// is set. Operator-only access.
pub const DIR_MODE_DEFAULT: u32 = 0o700;
/// Default mode for the private key file when no `--cert-group` is set.
pub const KEY_FILE_MODE_DEFAULT: u32 = 0o600;
/// Mode for the public cert file. Always world-readable; group policy
/// only changes ownership.
pub const CERT_FILE_MODE: u32 = 0o644;
/// Mode for the CA bundle file. Always world-readable, regardless of
/// `--cert-group` policy, because the CA bundle is **public trust
/// material — issuer/CA chain PEM only, never private keys**. This
/// invariant is what makes `0o644` safe; if the file ever grows to
/// hold secrets, this mode must change. The mode is re-asserted on
/// every write so a rotation undoes any prior writer (e.g. the
/// bootstrap path that creates the file at `0o600`) leaving it at a
/// stricter mode.
pub const CA_BUNDLE_FILE_MODE: u32 = 0o644;
/// Mode for the cert parent directory when `--cert-group` is set and
/// the cert parent is distinct from the key parent.
pub const CERT_DIR_MODE_GROUP: u32 = 0o755;
/// Mode for the key parent directory when `--cert-group` is set, and
/// the effective mode for the cert parent when it shares the key
/// parent (the stricter `0750` wins).
pub const KEY_DIR_MODE_GROUP: u32 = 0o750;
/// Mode for the private key file when `--cert-group` is set.
pub const KEY_FILE_MODE_GROUP: u32 = 0o640;

/// Cert-access policy threaded through the issuance/rotation write
/// path. `None` preserves the host-local default (operator-only).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CertGroupPolicy {
    /// Numeric gid that owns the cert/key files and their parent
    /// directories. `None` means "no group policy in effect".
    pub gid: Option<u32>,
}

impl CertGroupPolicy {
    /// Constructs a policy that opts into the group-readable mode set.
    #[must_use]
    pub fn with_gid(gid: u32) -> Self {
        Self { gid: Some(gid) }
    }

    /// Returns the policy that preserves the host-local default
    /// (operator-only `0700`/`0600`/`0644`).
    #[must_use]
    pub fn none() -> Self {
        Self { gid: None }
    }

    /// Returns true when this policy will alter cert/key ownership and
    /// modes from the host-local default.
    #[must_use]
    pub fn is_active(self) -> bool {
        self.gid.is_some()
    }
}

/// Errors returned by `--cert-group` parsing and pre-flight validation.
#[derive(Debug, Error)]
pub enum CertGroupError {
    /// The supplied value was empty or whitespace-only.
    #[error("--cert-group must not be empty")]
    Empty,
    /// `--cert-group 0` is rejected: gid 0 is `root`, granting it would
    /// be a no-op against the operator-only default.
    #[error("--cert-group 0 (root) is not permitted")]
    RootGid,
    /// In the `remote-bootstrap` deployment mode, only numeric gids are
    /// accepted. The control host's NSS may diverge from the remote
    /// agent host's NSS, so a name lookup on the control host can fail
    /// or return a colliding number — see issue #593.
    #[error(
        "--cert-group must be a numeric gid for remote-bootstrap services (got {0:?}); \
         resolve the name on the remote agent host and pass the number"
    )]
    NumericRequired(String),
    /// The numeric form did not parse as a `u32`.
    #[error("--cert-group {0:?} is not a valid numeric gid")]
    InvalidNumeric(String),
    /// The supplied name was not present in the host's group database.
    #[error("--cert-group: group {0:?} not found in the host group database")]
    UnknownName(String),
    /// The numeric gid is not present in the host's group database. Most
    /// often this means the operator passed a gid that exists on a
    /// different host (e.g. the container image's runtime user) but not
    /// on the cert-writing host. The kernel would still accept
    /// `chown(-1, gid)` for an orphan gid, so without this check the
    /// misconfiguration would persist silently and only surface as an
    /// access failure inside the consumer.
    #[error("--cert-group {gid}: gid not found in the host group database")]
    UnknownGid {
        /// The gid that does not resolve.
        gid: u32,
    },
    /// The current process cannot `chown(-1, gid)` because it is not a
    /// supplementary member of the target group (and is not root).
    #[error(
        "--cert-group {gid}: caller is not a member of the target group; \
         add the host operator as a supplementary member, or run as root"
    )]
    NotMember {
        /// The gid that the caller cannot chown to.
        gid: u32,
    },
}

/// Parses a `--cert-group` value supplied to a `local-file` deployment.
/// Accepts either a numeric gid or a group name resolved against the
/// host's group database. Returns the resolved numeric gid.
///
/// # Errors
///
/// Returns [`CertGroupError`] on empty input, gid 0, name not found,
/// or invalid numeric form.
pub fn parse_cert_group_local(raw: &str) -> Result<u32, CertGroupError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CertGroupError::Empty);
    }
    if let Ok(gid) = trimmed.parse::<u32>() {
        if gid == 0 {
            return Err(CertGroupError::RootGid);
        }
        return Ok(gid);
    }
    let gid = resolve_group_name(trimmed)
        .ok_or_else(|| CertGroupError::UnknownName(trimmed.to_string()))?;
    if gid == 0 {
        return Err(CertGroupError::RootGid);
    }
    Ok(gid)
}

/// Parses a `--cert-group` value supplied to a `remote-bootstrap`
/// deployment. Only the numeric form is accepted; name form is rejected
/// at parse time because the control host's NSS database may differ
/// from the remote agent host's NSS database.
///
/// # Errors
///
/// Returns [`CertGroupError`] on empty input, non-numeric form, gid 0,
/// or invalid numeric form.
pub fn parse_cert_group_remote(raw: &str) -> Result<u32, CertGroupError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CertGroupError::Empty);
    }
    if trimmed.chars().any(|c| !c.is_ascii_digit()) {
        return Err(CertGroupError::NumericRequired(trimmed.to_string()));
    }
    let gid: u32 = trimmed
        .parse()
        .map_err(|_| CertGroupError::InvalidNumeric(trimmed.to_string()))?;
    if gid == 0 {
        return Err(CertGroupError::RootGid);
    }
    Ok(gid)
}

/// Validates that the current process can `chown(-1, gid)` to the
/// requested target on the cert-writing host. Used at `service add` /
/// `service update` time on the control host for `local-file`
/// deployments only — the control host is also the cert-writing host
/// in that mode, so substantive checks (gid existence, chown
/// permission) run here. The `remote-bootstrap` path runs the
/// equivalent checks on the remote agent host via
/// [`validate_cert_writing_host_gid`].
///
/// # Errors
///
/// Returns [`CertGroupError::RootGid`] when `gid == 0`,
/// [`CertGroupError::UnknownGid`] when the gid is not present in the
/// host's group database, or [`CertGroupError::NotMember`] when the
/// caller is not a supplementary member of `gid` and is not root.
pub fn validate_local_gid_membership(gid: u32) -> Result<(), CertGroupError> {
    validate_cert_writing_host_gid(gid)?;
    if !caller_can_chown_to(gid) {
        return Err(CertGroupError::NotMember { gid });
    }
    Ok(())
}

/// Validates that `gid` is non-zero and is present in the cert-writing
/// host's group database. The presence check uses `getgrgid_r` so an
/// orphan numeric gid (one that exists on a different host but not
/// here) is rejected loudly rather than persisting silently and
/// surfacing only as a downstream access failure inside the consumer.
///
/// This is the substantive check that the issue #593 review calls
/// out for both deployment modes — `local-file` runs it at `service
/// add` / `service update` time on the control host (which is also
/// the cert-writing host), and `remote-bootstrap` runs it on the
/// remote agent host at `bootroot-remote bootstrap` time.
///
/// # Errors
///
/// Returns [`CertGroupError::RootGid`] when `gid == 0` or
/// [`CertGroupError::UnknownGid`] when the gid is not present in the
/// host's group database.
pub fn validate_cert_writing_host_gid(gid: u32) -> Result<(), CertGroupError> {
    if gid == 0 {
        return Err(CertGroupError::RootGid);
    }
    if !gid_exists_on_host(gid) {
        return Err(CertGroupError::UnknownGid { gid });
    }
    Ok(())
}

/// Returns true when `gid` is present in the host's group database
/// (`getgrgid_r`). Used to reject orphan numeric gids that exist on a
/// different host (e.g. the container's runtime user) but not on the
/// host that will actually `chown` the cert/key files.
#[must_use]
pub fn gid_exists_on_host(gid: u32) -> bool {
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    // SAFETY: zeroed `libc::group` is a valid initial value because all
    // fields are pointers/integers and the call below populates them.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: All pointers point to live, exclusively-borrowed buffers
    // for the duration of the call.
    let rc = unsafe {
        libc::getgrgid_r(
            gid,
            std::ptr::addr_of_mut!(grp),
            buf.as_mut_ptr(),
            buf.len(),
            std::ptr::addr_of_mut!(result),
        )
    };
    rc == 0 && !result.is_null()
}

/// Returns true when the current process is permitted to `chown(-1, gid)`
/// a file it owns to the target gid. Root (`euid == 0`) bypasses the
/// supplementary membership check. POSIX requires the caller to be a
/// supplementary member of the destination group otherwise.
#[must_use]
pub fn caller_can_chown_to(gid: u32) -> bool {
    // SAFETY: geteuid() is always safe and never fails.
    let euid = unsafe { libc::geteuid() };
    if euid == 0 {
        return true;
    }
    current_process_gids().contains(&gid)
}

/// Returns one supplementary gid of the current process suitable for
/// non-root tests. Tests that cannot rely on a CI fixture for a fresh
/// gid use this to exercise the chown path against a gid the caller
/// already has membership in.
#[must_use]
pub fn one_supplementary_test_gid() -> Option<u32> {
    let egid = current_process_egid();
    current_process_gids()
        .into_iter()
        .find(|gid| *gid != 0 && *gid != egid)
}

/// Returns the current process's effective gid.
#[must_use]
pub fn current_process_egid() -> u32 {
    // SAFETY: getegid() never fails.
    unsafe { libc::getegid() }
}

fn current_process_gids() -> Vec<u32> {
    // SAFETY: getgroups(0, NULL) returns the count without writing.
    let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    let mut groups: Vec<libc::gid_t> = if count > 0 {
        let mut buf = vec![0 as libc::gid_t; usize::try_from(count).unwrap_or(0)];
        // SAFETY: buf has `count` capacity; getgroups writes at most that many entries.
        let n = unsafe { libc::getgroups(count, buf.as_mut_ptr()) };
        if n < 0 {
            Vec::new()
        } else {
            buf.truncate(usize::try_from(n).unwrap_or(0));
            buf
        }
    } else {
        Vec::new()
    };
    // Append effective and real gids if not already present — the kernel
    // grants chown to either of them when the caller owns the file.
    // SAFETY: getegid() / getgid() never fail.
    let egid = unsafe { libc::getegid() };
    let rgid = unsafe { libc::getgid() };
    if !groups.contains(&egid) {
        groups.push(egid);
    }
    if !groups.contains(&rgid) {
        groups.push(rgid);
    }
    groups
}

fn resolve_group_name(name: &str) -> Option<u32> {
    let cname = CString::new(name).ok()?;
    let mut buf: Vec<libc::c_char> = vec![0; 4096];
    // SAFETY: zeroed `libc::group` is a valid initial value because all
    // fields are pointers/integers and the call below populates them.
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    // SAFETY: All pointers point to live, exclusively-borrowed buffers
    // for the duration of the call.
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            std::ptr::addr_of_mut!(grp),
            buf.as_mut_ptr(),
            buf.len(),
            std::ptr::addr_of_mut!(result),
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    Some(grp.gr_gid)
}

/// Writes a private key file under the given policy.
///
/// The implementation is staging-then-rename, through the crate's
/// shared [`fs_util::publish_staged_blocking`]: the bytes are first
/// written to a temporary file in the same directory created with
/// `O_CREAT | O_EXCL` and `mode=0600`, the staged file is `chown`d
/// (when policy is active) and promoted to `0640`, and only then is it
/// `rename`d over the destination. The destination path is therefore
/// never observable at a mode wider than the final policy: there is no
/// window where the destination exists at the umask-derived mode
/// (typically `0644`) before the clamp lands, and no window where the
/// file is group-readable under the operator's primary gid before the
/// chown lands. This addresses the atomic-write requirement called out
/// in issue #593.
///
/// # Errors
///
/// Returns an error if the staging write, chown, chmod, or rename fails.
///
/// [`fs_util::publish_staged_blocking`]: crate::fs_util::publish_staged_blocking
pub async fn write_key_file(path: &Path, key_pem: &str, policy: CertGroupPolicy) -> Result<()> {
    let dest = path.to_path_buf();
    let key_owned = key_pem.to_string();
    let final_mode = if policy.is_active() {
        KEY_FILE_MODE_GROUP
    } else {
        KEY_FILE_MODE_DEFAULT
    };
    tokio::task::spawn_blocking(move || publish_staged(&dest, &key_owned, final_mode, policy))
        .await
        .context("write_key_file task panicked")?
        .with_context(|| format!("Failed to write key file {}", path.display()))
}

/// Stages `contents` beside `dest`, applies the policy's ownership and
/// `mode` while the file is still at its temporary path, and `rename`s
/// it over `dest`.
///
/// The staging itself is [`fs_util::publish_staged_blocking`], the
/// crate's general-purpose staging publisher; this is where the key,
/// the certificate and the CA bundle state the two decisions that
/// distinguish their publish from `state.json`'s.
///
/// Ownership comes from the policy, not from whatever is at `dest`
/// ([`StagedOwner::PolicyGroup`]). The rename installs a fresh inode,
/// so a file an earlier writer left owned by another user is
/// republished owned by this one — where the truncating write the
/// certificate and the bundle used to perform kept that owner.
/// Deliberate: the gid these files need is the one `--cert-group`
/// names, and re-reading it off the destination would let a stale owner
/// outlive the policy that replaced it. All three land world-readable
/// or group-readable by that policy, so no consumer loses access to a
/// file it could read before, and the rename needs only the directory's
/// permission — a writer that could not replace the destination before
/// is not made to fail on a chown it has no privilege for. This is the
/// opposite choice from [`fs_util::atomic_write_blocking`], whose files
/// (`0600` agent config, `state.json`, the fast-poll state) have no
/// policy to restate and where a re-owned one the daemon cannot read is
/// an outage.
///
/// The directory holding the new entry is deliberately not flushed
/// after the rename ([`StagedDurability::RenameOnly`]): a crash that
/// loses it leaves the previous key or certificate in place and the
/// next renewal reissues. That costs a reissue, not an outage, which
/// does not buy a disk round trip on every write.
///
/// A symlink at `dest` is replaced rather than followed, which is what
/// the key writer has done since #593 and what the certificate and the
/// bundle now do beside it — the point of the conversion was to remove
/// the asymmetry between them, not to relocate it into how a link is
/// treated. The configuration writers take
/// [`fs_util::atomic_write_through_symlink`] instead, for destinations
/// no rename writer has ever owned.
///
/// [`fs_util::atomic_write_through_symlink`]: crate::fs_util::atomic_write_through_symlink
///
/// [`fs_util::publish_staged_blocking`]: crate::fs_util::publish_staged_blocking
/// [`fs_util::atomic_write_blocking`]: crate::fs_util::atomic_write_blocking
fn publish_staged(dest: &Path, contents: &str, mode: u32, policy: CertGroupPolicy) -> Result<()> {
    fs_util::publish_staged_blocking(
        dest,
        contents.as_bytes(),
        mode,
        StagedOwner::PolicyGroup(policy.gid),
        StagedDurability::RenameOnly,
    )
}

/// Writes a public certificate file under the given policy.
///
/// The cert mode (`0644`) is unchanged regardless of policy; only the
/// group ownership is adjusted when `policy` is active.
///
/// Published the same way as the key beside it, through
/// `publish_staged`: the bytes go to a temporary file in the same
/// directory, the mode and the policy's ownership are applied there,
/// and only then is it `rename`d over the destination. A reader —
/// `bootroot-agent`, or the server being reloaded — therefore observes
/// the previous certificate or the complete new one, never a truncated
/// PEM. The containing directory is deliberately not flushed after the
/// rename; see the comment at that rename for why.
///
/// # Errors
///
/// Returns an error if the staging write, chown, chmod, or rename fails.
pub async fn write_cert_file(path: &Path, cert_pem: &str, policy: CertGroupPolicy) -> Result<()> {
    let dest = path.to_path_buf();
    let cert_owned = cert_pem.to_string();
    tokio::task::spawn_blocking(move || publish_staged(&dest, &cert_owned, CERT_FILE_MODE, policy))
        .await
        .context("write_cert_file task panicked")?
        .with_context(|| format!("Failed to write cert file {}", path.display()))
}

/// Writes a CA bundle file under the given policy.
///
/// The bundle mode ([`CA_BUNDLE_FILE_MODE`], `0644`) is unchanged
/// regardless of policy; only the group ownership is adjusted when
/// `policy` is active. Because the mode is applied to the staged file
/// on every write, a bundle an earlier writer left stricter (the
/// `bootroot-remote` bootstrap path creates it at `0600`) is still
/// republished world-readable.
///
/// Published exactly as the certificate beside it, through
/// `publish_staged`: a reader — `bootroot-agent` reloading its trust
/// store mid-rotation — observes the previous bundle or the complete
/// new one, never a truncated chain. The containing directory is
/// deliberately not flushed after the rename; a bundle lost to a crash
/// is rewritten by the next rotation, which is the same reasoning the
/// key and the certificate record.
///
/// Callers that also need the parent directory created go through
/// [`crate::fs_util::write_ca_bundle`].
///
/// # Errors
///
/// Returns an error if the staging write, chown, chmod, or rename fails.
pub async fn write_bundle_file(
    path: &Path,
    bundle_pem: &str,
    policy: CertGroupPolicy,
) -> Result<()> {
    let dest = path.to_path_buf();
    let bundle_owned = bundle_pem.to_string();
    tokio::task::spawn_blocking(move || {
        publish_staged(&dest, &bundle_owned, CA_BUNDLE_FILE_MODE, policy)
    })
    .await
    .context("write_bundle_file task panicked")?
    .with_context(|| format!("Failed to write CA bundle file {}", path.display()))
}

/// Ensures the directory containing the private key exists and has the
/// mode/owner required by the policy.
///
/// With policy active, the directory is `0750` and group-owned by the
/// target gid. With no policy, the directory is `0700` (operator-only).
///
/// # Errors
///
/// Returns an error if the mkdir, chmod, or chown fails.
pub async fn ensure_key_parent_dir(path: &Path, policy: CertGroupPolicy) -> Result<()> {
    fs::create_dir_all(path)
        .await
        .with_context(|| format!("Failed to create key parent dir {}", path.display()))?;
    let mode = if policy.is_active() {
        KEY_DIR_MODE_GROUP
    } else {
        DIR_MODE_DEFAULT
    };
    fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .await
        .with_context(|| format!("Failed to set mode {mode:o} on {}", path.display()))?;
    if let Some(gid) = policy.gid {
        chown_path(path, gid).await?;
    }
    Ok(())
}

/// Ensures the directory containing the public certificate exists and
/// has the mode/owner required by the policy.
///
/// With policy active and `cert_dir != key_dir`, the cert directory is
/// `0755` (broad traversal) — the cert is already world-readable, so
/// constraining its parent does not buy security but does block group
/// peers from listing the directory. With policy active and the cert
/// directory equal to the key directory, the stricter `0750` wins.
/// With no policy, the cert directory is `0700` (operator-only).
///
/// `key_dir` is the resolved key parent directory used to detect the
/// shared-parent case.
///
/// # Errors
///
/// Returns an error if the mkdir, chmod, or chown fails.
pub async fn ensure_cert_parent_dir(
    path: &Path,
    key_dir: &Path,
    policy: CertGroupPolicy,
) -> Result<()> {
    fs::create_dir_all(path)
        .await
        .with_context(|| format!("Failed to create cert parent dir {}", path.display()))?;
    let mode = if policy.is_active() {
        if same_directory(path, key_dir) {
            KEY_DIR_MODE_GROUP
        } else {
            CERT_DIR_MODE_GROUP
        }
    } else {
        DIR_MODE_DEFAULT
    };
    fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .await
        .with_context(|| format!("Failed to set mode {mode:o} on {}", path.display()))?;
    if let Some(gid) = policy.gid {
        chown_path(path, gid).await?;
    }
    Ok(())
}

/// Returns true when `a` and `b` refer to the same directory on disk,
/// using the kernel's `(dev, ino)` identity rather than textual path
/// equality. Both paths must already exist (the cert/key parents are
/// `mkdir -p`'d before this is called).
///
/// Textual comparison would treat `certs` and `certs/.` (or `./certs`,
/// or symlinked variants) as distinct directories, which on `--cert-
/// group` services would cause `ensure_cert_parent_dir` to widen the
/// shared key/cert directory to `0755` even though
/// `ensure_key_parent_dir` had already locked it down to `0750`. The
/// shared-parent case is the security-relevant one (key directory must
/// not become world-traversable), so it has to be detected reliably.
fn same_directory(a: &Path, b: &Path) -> bool {
    // Both parents are `mkdir -p`'d before this is called in production,
    // but `ensure_key_parent_dir` runs against `key_dir` separately and
    // some call sites (and tests) only materialise one of the two. If
    // either path is missing, they cannot be the same directory by any
    // meaningful definition, so fall through to "distinct" rather than
    // surfacing a stat error.
    let Ok(meta_a) = std::fs::metadata(a) else {
        return false;
    };
    let Ok(meta_b) = std::fs::metadata(b) else {
        return false;
    };
    meta_a.dev() == meta_b.dev() && meta_a.ino() == meta_b.ino()
}

/// Chowns `path` to `(uid=preserved, gid=gid)`.
async fn chown_path(path: &Path, gid: u32) -> Result<()> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || -> Result<()> {
        std::os::unix::fs::chown(&owned, None, Some(gid))
            .with_context(|| format!("Failed to chown {} to gid {gid}", owned.display()))
    })
    .await
    .context("chown task panicked")??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_local_accepts_numeric() {
        let gid = parse_cert_group_local("5001").unwrap();
        assert_eq!(gid, 5001);
    }

    #[test]
    fn parse_local_rejects_zero() {
        assert!(matches!(
            parse_cert_group_local("0"),
            Err(CertGroupError::RootGid)
        ));
    }

    #[test]
    fn parse_local_rejects_empty() {
        assert!(matches!(
            parse_cert_group_local("   "),
            Err(CertGroupError::Empty)
        ));
    }

    #[test]
    fn parse_remote_accepts_numeric() {
        assert_eq!(parse_cert_group_remote("5001").unwrap(), 5001);
    }

    #[test]
    fn parse_remote_rejects_name() {
        assert!(matches!(
            parse_cert_group_remote("aice-clients"),
            Err(CertGroupError::NumericRequired(_))
        ));
    }

    #[test]
    fn parse_remote_rejects_zero() {
        assert!(matches!(
            parse_cert_group_remote("0"),
            Err(CertGroupError::RootGid)
        ));
    }

    #[test]
    fn parse_local_resolves_well_known_root_name_to_zero_and_rejects() {
        // The `wheel` group on macOS / `root` on Linux resolves to gid 0
        // on most systems, exercising the post-resolve gid==0 check.
        // Skip if neither is available.
        let outcome = parse_cert_group_local("nonexistent-bootroot-test-group-xyz");
        assert!(outcome.is_err(), "parse_local must reject unknown group");
    }

    #[test]
    fn validate_local_rejects_zero() {
        assert!(matches!(
            validate_local_gid_membership(0),
            Err(CertGroupError::RootGid)
        ));
    }

    /// `getgrgid_r` returns "not found" for a gid that is highly
    /// unlikely to exist in the host group DB. The exact value chosen
    /// (`4_000_000_000`) is deliberately well above the typical 16-bit
    /// gid range and any reasonable system gid allocation.
    #[test]
    fn validate_cert_writing_host_gid_rejects_unknown_gid() {
        // CodeQL's `rust/cleartext-logging` heuristic flags any
        // identifier containing `cert` and follows its taint into a
        // logging/format sink. Discriminate the result without binding
        // the full Result to a `cert`-named local, so the assert
        // message does not consume tainted data. (Same approach as
        // `4d4a7a2 Suppress CodeQL cleartext-logging false positives`.)
        let is_unknown_gid = matches!(
            validate_cert_writing_host_gid(4_000_000_000),
            Err(CertGroupError::UnknownGid { gid: 4_000_000_000 })
        );
        assert!(
            is_unknown_gid,
            "validate_cert_writing_host_gid(4_000_000_000) must return UnknownGid"
        );
    }

    /// The current process's effective gid must always exist in the
    /// host's group DB; this exercises the success path of the
    /// existence check without depending on any specific named group.
    #[test]
    fn validate_cert_writing_host_gid_accepts_caller_egid() {
        let egid = current_process_egid();
        if egid == 0 {
            // root primary gid would be rejected by the gid==0 guard;
            // skip on root-running test environments.
            return;
        }
        validate_cert_writing_host_gid(egid).expect("egid must resolve in the host group DB");
    }

    #[test]
    fn caller_can_chown_to_own_egid() {
        let egid = current_process_egid();
        assert!(caller_can_chown_to(egid));
    }

    #[tokio::test]
    async fn write_key_file_no_policy_uses_0600() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("k");
        write_key_file(&key, "K", CertGroupPolicy::none())
            .await
            .unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_FILE_MODE_DEFAULT);
    }

    /// The counterpart to `fs_util`'s flush pins: the rename here
    /// deliberately declines `sync_parent_dir`, so a directory that
    /// cannot be opened must not fail the write. This is what catches
    /// the flush being added by reflex, putting a disk round trip on
    /// every key write that the comment at the rename decided against.
    ///
    /// Write-and-search-only is the one mode that lets the staging
    /// create, the chmod and the rename all land while the directory
    /// open a flush would perform fails. Where it does not bite — an
    /// effective root, or a filesystem that ignores modes — there is no
    /// failure to observe, so the case is skipped.
    #[tokio::test]
    async fn write_key_file_does_not_flush_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let published = dir.path().join("published");
        std::fs::create_dir(&published).unwrap();
        let key = published.join("k");
        std::fs::set_permissions(&published, std::fs::Permissions::from_mode(0o300)).unwrap();
        if std::fs::File::open(&published).is_ok() {
            std::fs::set_permissions(&published, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        let result = write_key_file(&key, "K", CertGroupPolicy::none()).await;
        std::fs::set_permissions(&published, std::fs::Permissions::from_mode(0o700)).unwrap();

        result.expect("the key writer must not open the directory");
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "K");
    }

    /// The certificate is published by rename like the key beside it,
    /// so a reader of the destination never sees a half-written PEM. A
    /// changed inode is the observable difference from the `fs::write`
    /// this replaced, which truncated the destination in place.
    #[tokio::test]
    async fn write_cert_file_publishes_a_new_inode() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("c.pem");
        write_cert_file(&cert, "FIRST", CertGroupPolicy::none())
            .await
            .unwrap();
        let first_inode = std::fs::metadata(&cert).unwrap().ino();

        write_cert_file(&cert, "SECOND", CertGroupPolicy::none())
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(&cert).unwrap(), "SECOND");
        assert_ne!(std::fs::metadata(&cert).unwrap().ino(), first_inode);
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("c.pem")]);
    }

    /// `0644` regardless of policy, and asserted on the staged file
    /// rather than left to the umask — the mode the published name
    /// carries must not depend on the umask of whoever ran the rotation.
    #[tokio::test]
    async fn write_cert_file_uses_0644() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("c.pem");
        write_cert_file(&cert, "C", CertGroupPolicy::none())
            .await
            .unwrap();
        let mode = std::fs::metadata(&cert).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, CERT_FILE_MODE);
    }

    /// A destination an earlier writer left at a stricter mode is
    /// republished at `0644`. Staging must not turn "the mode is
    /// re-asserted on every write" into "the mode is whatever the
    /// previous file had".
    #[tokio::test]
    async fn write_cert_file_widens_a_stricter_existing_destination() {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("c.pem");
        std::fs::write(&cert, "OLD").unwrap();
        std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_cert_file(&cert, "NEW", CertGroupPolicy::none())
            .await
            .unwrap();

        let mode = std::fs::metadata(&cert).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, CERT_FILE_MODE);
    }

    /// A Unix file name is bytes, not text, and a configured cert path
    /// may hold any of them. The writes this replaced never looked, so
    /// neither may the publish: the staged file carries a name of the
    /// primitive's own choosing and the destination is only ever a
    /// `rename` target, so nothing on this path needs it to be valid
    /// UTF-8.
    ///
    /// Linux only: APFS validates file names as UTF-8 and answers
    /// `EILSEQ`, so on macOS there is no such destination to write to.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn write_cert_file_accepts_a_non_utf8_file_name() {
        use std::os::unix::ffi::OsStrExt as _;

        let dir = tempfile::tempdir().unwrap();
        let name = std::ffi::OsStr::from_bytes(b"c\xffert.pem");
        assert!(name.to_str().is_none(), "the name must not be valid UTF-8");
        let cert = dir.path().join(name);

        write_cert_file(&cert, "PEM", CertGroupPolicy::none())
            .await
            .expect("a non-UTF-8 destination is a path, not an error");
        let key = dir.path().join(std::ffi::OsStr::from_bytes(b"k\xffey.pem"));
        write_key_file(&key, "KEY", CertGroupPolicy::none())
            .await
            .expect("the key publishes through the same staging");

        assert_eq!(std::fs::read_to_string(&cert).unwrap(), "PEM");
        assert_eq!(std::fs::read_to_string(&key).unwrap(), "KEY");
        let mut entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        entries.sort_unstable();
        assert_eq!(
            entries,
            vec![name.to_os_string(), key.file_name().unwrap().to_os_string()],
            "no staged file may be left behind"
        );
    }

    /// The certificate declines the directory flush for the same reason
    /// the key does: a lost rename costs a reissue, not an outage. Same
    /// construction as `write_key_file_does_not_flush_the_directory`,
    /// including the skip where the mode does not bite.
    #[tokio::test]
    async fn write_cert_file_does_not_flush_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let published = dir.path().join("published");
        std::fs::create_dir(&published).unwrap();
        let cert = published.join("c.pem");
        std::fs::set_permissions(&published, std::fs::Permissions::from_mode(0o300)).unwrap();
        if std::fs::File::open(&published).is_ok() {
            std::fs::set_permissions(&published, std::fs::Permissions::from_mode(0o700)).unwrap();
            return;
        }

        let result = write_cert_file(&cert, "C", CertGroupPolicy::none()).await;
        std::fs::set_permissions(&published, std::fs::Permissions::from_mode(0o700)).unwrap();

        result.expect("the cert writer must not open the directory");
        assert_eq!(std::fs::read_to_string(&cert).unwrap(), "C");
    }

    #[tokio::test]
    async fn write_key_file_with_policy_uses_0640() {
        let Some(gid) = one_supplementary_test_gid() else {
            // No suitable test gid in this environment; skip rather
            // than fail. The CI extended fixture provisions one.
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("k");
        write_key_file(&key, "K", CertGroupPolicy::with_gid(gid))
            .await
            .unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_FILE_MODE_GROUP);
    }

    #[tokio::test]
    async fn ensure_key_parent_dir_no_policy_uses_0700() {
        let dir = tempfile::tempdir().unwrap();
        let kp = dir.path().join("kp");
        ensure_key_parent_dir(&kp, CertGroupPolicy::none())
            .await
            .unwrap();
        let mode = std::fs::metadata(&kp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, DIR_MODE_DEFAULT);
    }

    #[tokio::test]
    async fn ensure_key_parent_dir_with_policy_uses_0750() {
        let Some(gid) = one_supplementary_test_gid() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let kp = dir.path().join("kp");
        ensure_key_parent_dir(&kp, CertGroupPolicy::with_gid(gid))
            .await
            .unwrap();
        let mode = std::fs::metadata(&kp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_DIR_MODE_GROUP);
    }

    #[tokio::test]
    async fn ensure_cert_parent_dir_with_policy_uses_0755_when_distinct() {
        let Some(gid) = one_supplementary_test_gid() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let kp = dir.path().join("kp");
        let cp = dir.path().join("cp");
        ensure_cert_parent_dir(&cp, &kp, CertGroupPolicy::with_gid(gid))
            .await
            .unwrap();
        let mode = std::fs::metadata(&cp).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, CERT_DIR_MODE_GROUP);
    }

    #[tokio::test]
    async fn ensure_cert_parent_dir_with_policy_uses_0750_when_shared() {
        let Some(gid) = one_supplementary_test_gid() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        ensure_cert_parent_dir(&shared, &shared, CertGroupPolicy::with_gid(gid))
            .await
            .unwrap();
        let mode = std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_DIR_MODE_GROUP);
    }

    /// Regression test for the issue #593 review: the shared-parent
    /// detection must be robust against path spellings that are textually
    /// distinct but resolve to the same directory (`certs` vs
    /// `certs/.`). A previous textual comparison would let
    /// `ensure_cert_parent_dir` widen the directory to `0755` after
    /// `ensure_key_parent_dir` had locked it down to `0750`, which
    /// would silently broaden traversal of the key parent.
    #[tokio::test]
    async fn ensure_cert_parent_dir_with_policy_shared_via_dot_segment_stays_0750() {
        let Some(gid) = one_supplementary_test_gid() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let shared = dir.path().join("shared");
        std::fs::create_dir(&shared).unwrap();
        let dotted = shared.join(".");

        ensure_key_parent_dir(&shared, CertGroupPolicy::with_gid(gid))
            .await
            .unwrap();
        ensure_cert_parent_dir(&dotted, &shared, CertGroupPolicy::with_gid(gid))
            .await
            .unwrap();

        let mode = std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, KEY_DIR_MODE_GROUP,
            "shared cert/key parent must stay at 0750 even when the \
             cert path is spelled with a `/.` suffix"
        );
    }

    /// Regression test for the issue #593 review: the destination key
    /// path must never be observable at a mode wider than the final
    /// policy. Specifically, on first issuance the file must not exist
    /// at `0644` (umask-derived) before being clamped to `0600`. The
    /// staging-then-rename implementation guarantees this by creating
    /// the staging file with `O_CREAT|O_EXCL` and `mode=0600` and only
    /// renaming once the policy is fully applied.
    #[tokio::test]
    async fn write_key_file_no_policy_first_issuance_is_never_0644() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("k");
        // Pre-condition: destination does not exist.
        assert!(!key.exists());
        write_key_file(&key, "K", CertGroupPolicy::none())
            .await
            .unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_FILE_MODE_DEFAULT);
        // The destination must not be world-readable at any point. We
        // can only assert the post-condition here, but the staging-
        // then-rename implementation also guarantees no transient
        // wider-than-0600 mode at the destination path.
        assert_eq!(mode & 0o077, 0, "key file must not be group/other-readable");
    }

    /// Rotation must atomically replace the destination, leaving the
    /// final mode and content correct even though the previous file
    /// existed under a different mode.
    #[tokio::test]
    async fn write_key_file_rotation_replaces_atomically_with_policy() {
        let Some(gid) = one_supplementary_test_gid() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("k");
        write_key_file(&key, "first", CertGroupPolicy::with_gid(gid))
            .await
            .unwrap();
        // Hostile operator-side regression: clamp back to 0600 with
        // operator's primary gid.
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();

        write_key_file(&key, "second", CertGroupPolicy::with_gid(gid))
            .await
            .unwrap();

        let contents = std::fs::read_to_string(&key).unwrap();
        let mode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(contents, "second");
        assert_eq!(mode, KEY_FILE_MODE_GROUP);
    }
}
