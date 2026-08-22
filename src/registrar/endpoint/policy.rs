//! Whether the pathname the inherited descriptor is bound to is one this
//! daemon may serve on.
//!
//! This is a *precondition on the listener*, never client
//! authentication: a mode and an owner say who could have connected, not
//! who did, and the answer to the second question comes from the
//! connected socket's peer credentials alone. What it does rule out is a
//! socket systemd was talked into creating somewhere a second party can
//! reach — a world-accessible mode, an owner that is not this daemon, or
//! a parent directory some other account can rename entries in.
//!
//! The metadata comes from `stat` on the **pathname**, not `fstat` on the
//! descriptor. `fstat` describes the socket inode, which carries neither
//! the directory that holds it nor any guarantee that the name still
//! resolves to it; the pathname is what a caller connects through, so
//! the pathname is what is checked. Collection and decision are separate
//! functions so every owner and permission branch is one struct literal
//! away from a test, without needing a filesystem that can produce it.

use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use super::REQUIRED_SOCKET_MODE;

/// The permission bits a directory holding the socket must not have.
///
/// A bitmask, not an equality: the shipped unit's
/// `RuntimeDirectoryMode=0755` and a hand-made `0700` are both fine, and
/// anything group- or other-writable is not, whatever else it carries.
const FORBIDDEN_DIRECTORY_WRITE_BITS: u32 = 0o022;

/// Everything the policy decides over, collected in one pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SocketMetadata {
    /// The pathname the socket is bound to.
    pub(crate) socket_path: PathBuf,
    /// The socket's permission bits.
    pub(crate) socket_mode: u32,
    /// The socket's owning uid.
    pub(crate) socket_uid: u32,
    /// The directory holding the socket.
    pub(crate) directory_path: PathBuf,
    /// The directory's permission bits.
    pub(crate) directory_mode: u32,
    /// The directory's owning uid.
    pub(crate) directory_uid: u32,
}

/// Why an activated socket's pathname fails policy.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SocketPolicyViolation {
    /// The socket's mode is not exactly the required one.
    #[error(
        "the activated socket {path} has mode {found:04o}, but the registrar endpoint requires \
         exactly {required:04o}; set SocketMode={required:04o} in bootroot-registrar.socket"
    )]
    SocketMode {
        /// The socket's pathname.
        path: PathBuf,
        /// The observed mode.
        found: u32,
        /// The required mode.
        required: u32,
    },
    /// The socket belongs to somebody other than this daemon.
    #[error(
        "the activated socket {path} is owned by uid {found}, but this daemon runs as uid \
         {expected}; set SocketUser and SocketGroup to the account bootroot-agent runs as"
    )]
    SocketOwner {
        /// The socket's pathname.
        path: PathBuf,
        /// The observed owner.
        found: u32,
        /// This daemon's effective uid.
        expected: u32,
    },
    /// The directory holding the socket belongs to somebody else, so
    /// that account can replace the socket with a name of its own.
    #[error(
        "the directory {path} holding the activated socket is owned by uid {found}, but this \
         daemon runs as uid {expected}; its owner can replace the socket with one of their own"
    )]
    DirectoryOwner {
        /// The directory's pathname.
        path: PathBuf,
        /// The observed owner.
        found: u32,
        /// This daemon's effective uid.
        expected: u32,
    },
    /// The directory is group- or other-writable, so an account that is
    /// not this daemon can unlink the socket and bind its own.
    #[error(
        "the directory {path} holding the activated socket has mode {found:04o}, which is group- \
         or other-writable; another account could unlink the socket and bind its own in its place"
    )]
    DirectoryWritable {
        /// The directory's pathname.
        path: PathBuf,
        /// The observed mode.
        found: u32,
    },
}

/// Applies the policy to already-collected metadata.
///
/// Ordered socket-first so the most specific misconfiguration — the
/// socket unit's own `SocketMode` — is the one an operator is told about
/// when several things are wrong at once.
///
/// # Errors
///
/// Returns the first [`SocketPolicyViolation`] the metadata fails.
pub(crate) fn check(
    metadata: &SocketMetadata,
    daemon_uid: u32,
) -> Result<(), SocketPolicyViolation> {
    if metadata.socket_mode != REQUIRED_SOCKET_MODE {
        return Err(SocketPolicyViolation::SocketMode {
            path: metadata.socket_path.clone(),
            found: metadata.socket_mode,
            required: REQUIRED_SOCKET_MODE,
        });
    }
    if metadata.socket_uid != daemon_uid {
        return Err(SocketPolicyViolation::SocketOwner {
            path: metadata.socket_path.clone(),
            found: metadata.socket_uid,
            expected: daemon_uid,
        });
    }
    if metadata.directory_uid != daemon_uid {
        return Err(SocketPolicyViolation::DirectoryOwner {
            path: metadata.directory_path.clone(),
            found: metadata.directory_uid,
            expected: daemon_uid,
        });
    }
    if metadata.directory_mode & FORBIDDEN_DIRECTORY_WRITE_BITS != 0 {
        return Err(SocketPolicyViolation::DirectoryWritable {
            path: metadata.directory_path.clone(),
            found: metadata.directory_mode,
        });
    }
    Ok(())
}

/// Collects the socket's and its parent directory's mode and owner.
///
/// # Errors
///
/// Returns the underlying `stat` failure, or an error when the pathname
/// has no parent directory at all.
pub(crate) fn collect(socket_path: &Path) -> anyhow::Result<SocketMetadata> {
    let directory_path = socket_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "the activated socket {} has no parent directory to check",
                socket_path.display()
            )
        })?
        .to_path_buf();
    let socket = std::fs::metadata(socket_path)?;
    let directory = std::fs::metadata(&directory_path)?;
    Ok(SocketMetadata {
        socket_path: socket_path.to_path_buf(),
        socket_mode: socket.mode() & 0o7777,
        socket_uid: socket.uid(),
        directory_path,
        directory_mode: directory.mode() & 0o7777,
        directory_uid: directory.uid(),
    })
}
