//! The systemd socket-activation contract, split into pure decisions
//! and the two syscall wrappers that feed them.
//!
//! Everything that *decides* — whether the announced pid is this
//! process, whether exactly one descriptor arrived, whether the
//! descriptor is a listening `AF_UNIX` stream, whether the address is a
//! usable pathname — takes its inputs as values. That is what makes the
//! whole contract testable from a plain unit test: no inherited socket,
//! no `systemd`, and above all no mutation of this process's
//! environment, which is unsound the moment a Tokio runtime exists.

use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::io::RawFd;
use std::path::PathBuf;

use super::SD_LISTEN_FDS_START;

/// The name systemd announces the target process id under.
const LISTEN_PID: &str = "LISTEN_PID";

/// The name systemd announces the inherited descriptor count under.
const LISTEN_FDS: &str = "LISTEN_FDS";

/// The exact number of descriptors this endpoint accepts.
const REQUIRED_LISTEN_FDS: u32 = 1;

/// The raw activation variables, read from the environment exactly once.
///
/// Held as [`OsString`] rather than [`String`] so a non-UTF-8 value is a
/// *rejection with a diagnostic* rather than a variable that silently
/// reads as absent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ActivationValues {
    /// `LISTEN_PID`, verbatim.
    pub(crate) listen_pid: Option<OsString>,
    /// `LISTEN_FDS`, verbatim.
    pub(crate) listen_fds: Option<OsString>,
}

impl ActivationValues {
    /// Reads both activation variables from this process's environment.
    ///
    /// Called once, at the composition boundary, and never again. The
    /// variables are deliberately *not* cleared afterwards:
    /// `std::env::remove_var` is unsafe in edition 2024 and unsound with
    /// a Tokio runtime already running, and reading once achieves what
    /// clearing them was for.
    pub(crate) fn from_environment() -> Self {
        Self {
            listen_pid: std::env::var_os(LISTEN_PID),
            listen_fds: std::env::var_os(LISTEN_FDS),
        }
    }

    /// Builds a set of values directly, for tests and for a caller that
    /// has already read the environment.
    #[cfg(test)]
    pub(crate) fn new(listen_pid: Option<&str>, listen_fds: Option<&str>) -> Self {
        Self {
            listen_pid: listen_pid.map(OsString::from),
            listen_fds: listen_fds.map(OsString::from),
        }
    }
}

/// Why an activation contract was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ActivationError {
    /// `LISTEN_PID` is absent, so this process was not socket-activated.
    #[error(
        "{LISTEN_PID} is not set: the registrar endpoint is served only on a systemd-activated \
         socket, so bootroot-agent must be started by bootroot-registrar.socket"
    )]
    MissingListenPid,
    /// `LISTEN_FDS` is absent.
    #[error(
        "{LISTEN_FDS} is not set: the registrar endpoint requires exactly one inherited listening \
         descriptor from bootroot-registrar.socket"
    )]
    MissingListenFds,
    /// `LISTEN_PID` is not a decimal process id.
    #[error("{LISTEN_PID} is not a process id: {value}")]
    UnparsableListenPid {
        /// The value as it arrived, lossily decoded for the message.
        value: String,
    },
    /// `LISTEN_FDS` is not a decimal count.
    #[error("{LISTEN_FDS} is not a descriptor count: {value}")]
    UnparsableListenFds {
        /// The value as it arrived, lossily decoded for the message.
        value: String,
    },
    /// `LISTEN_PID` names a different process, so these descriptors are
    /// somebody else's — most often an inherited environment in a child.
    #[error("{LISTEN_PID} is {announced}, but this process is {actual}")]
    PidMismatch {
        /// The pid systemd addressed the contract to.
        announced: u32,
        /// This process's id.
        actual: u32,
    },
    /// `LISTEN_FDS` announced anything but one descriptor.
    #[error(
        "{LISTEN_FDS} is {count}, but the registrar endpoint requires exactly \
         {REQUIRED_LISTEN_FDS} inherited descriptor"
    )]
    DescriptorCount {
        /// The announced count.
        count: u32,
    },
}

/// One validated inherited descriptor.
///
/// Constructed only by [`ActivationContract::consume`] in production, so
/// the descriptor a caller gets back is always the one the contract
/// named. It is consumed by value when the listener is adopted, which is
/// what makes the single `from_raw_fd` in [`super::adopt`] sound: there
/// is no second owner left to hand the same descriptor out again.
#[derive(Debug)]
pub(crate) struct ActivationContract {
    descriptor: RawFd,
}

impl ActivationContract {
    /// Validates the activation values against this process's id and
    /// yields the single descriptor at [`SD_LISTEN_FDS_START`].
    ///
    /// `LISTEN_FDNAMES` is not consulted. Exactly one descriptor is
    /// required, so there is nothing to select by name, and a contract
    /// that carries a name for a descriptor it did not pass is already
    /// rejected by the count.
    ///
    /// # Errors
    ///
    /// Returns the [`ActivationError`] naming the first rule the
    /// contract failed.
    pub(crate) fn consume(
        values: &ActivationValues,
        effective_pid: u32,
    ) -> Result<Self, ActivationError> {
        let listen_pid = values
            .listen_pid
            .as_deref()
            .ok_or(ActivationError::MissingListenPid)?;
        let listen_fds = values
            .listen_fds
            .as_deref()
            .ok_or(ActivationError::MissingListenFds)?;

        let announced =
            parse_decimal(listen_pid).ok_or_else(|| ActivationError::UnparsableListenPid {
                value: listen_pid.to_string_lossy().into_owned(),
            })?;
        if announced != effective_pid {
            return Err(ActivationError::PidMismatch {
                announced,
                actual: effective_pid,
            });
        }

        let count =
            parse_decimal(listen_fds).ok_or_else(|| ActivationError::UnparsableListenFds {
                value: listen_fds.to_string_lossy().into_owned(),
            })?;
        if count != REQUIRED_LISTEN_FDS {
            return Err(ActivationError::DescriptorCount { count });
        }

        Ok(Self {
            descriptor: SD_LISTEN_FDS_START,
        })
    }

    /// Wraps a descriptor a test harness opened itself, so the harness's
    /// listener travels the same adoption path production does.
    ///
    /// Tests may *bind* a listener; nothing below this constructor may.
    /// Production never reaches it — the contract's descriptor is always
    /// [`SD_LISTEN_FDS_START`] there.
    #[cfg(test)]
    pub(crate) fn from_test_descriptor(descriptor: RawFd) -> Self {
        Self { descriptor }
    }

    /// Consumes the contract and yields the descriptor it names.
    ///
    /// By value on purpose: the descriptor is adopted exactly once, and
    /// a contract that could hand it out twice is a contract that could
    /// produce two owners of one file descriptor.
    pub(crate) fn into_descriptor(self) -> RawFd {
        self.descriptor
    }
}

/// Parses a bare decimal `u32`, rejecting a sign, whitespace or any
/// other decoration systemd would never write.
fn parse_decimal(value: &OsStr) -> Option<u32> {
    let text = value.to_str()?;
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// The socket facts a descriptor has to satisfy before it is served on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DescriptorFacts {
    /// `SO_DOMAIN`.
    pub(crate) domain: i32,
    /// `SO_TYPE`.
    pub(crate) sock_type: i32,
    /// `SO_ACCEPTCONN`.
    pub(crate) accepting: bool,
    /// Whether `FD_CLOEXEC` is set. Read *after* it is set, so this is
    /// an assertion that the flag took, not a question about systemd.
    pub(crate) cloexec: bool,
}

/// Why an inherited descriptor cannot be served on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum DescriptorError {
    /// Not an `AF_UNIX` socket. The endpoint is never TCP, not even on
    /// loopback.
    #[error("the inherited descriptor is not an AF_UNIX socket (SO_DOMAIN = {domain})")]
    Family {
        /// The observed `SO_DOMAIN`.
        domain: i32,
    },
    /// Not a `SOCK_STREAM` socket.
    #[error("the inherited descriptor is not a SOCK_STREAM socket (SO_TYPE = {sock_type})")]
    Kind {
        /// The observed `SO_TYPE`.
        sock_type: i32,
    },
    /// Not listening, so `Accept=yes` or a connected socket was passed.
    #[error(
        "the inherited descriptor is not a listening socket; bootroot-registrar.socket must set \
         Accept=no"
    )]
    NotListening,
    /// `FD_CLOEXEC` did not take, so a hook child could inherit the
    /// listening socket and accept on it.
    #[error("FD_CLOEXEC is not set on the inherited descriptor")]
    NotCloexec,
}

/// Decides whether a descriptor's socket facts admit it.
///
/// Pure, so every branch is reachable without a socket of that shape in
/// hand — an `AF_INET` listener, a datagram socket and a connected
/// stream are all one struct literal each.
pub(crate) fn check_descriptor(facts: DescriptorFacts) -> Result<(), DescriptorError> {
    if facts.domain != libc::AF_UNIX {
        return Err(DescriptorError::Family {
            domain: facts.domain,
        });
    }
    if facts.sock_type != libc::SOCK_STREAM {
        return Err(DescriptorError::Kind {
            sock_type: facts.sock_type,
        });
    }
    if !facts.accepting {
        return Err(DescriptorError::NotListening);
    }
    if !facts.cloexec {
        return Err(DescriptorError::NotCloexec);
    }
    Ok(())
}

/// What kind of Unix address `getsockname()` reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UnixAddressKind {
    /// A filesystem pathname, which is the only kind that can be
    /// protected by a mode and an owner.
    Pathname(PathBuf),
    /// A socket that was never bound.
    Unnamed,
    /// A Linux abstract-namespace socket. It lives outside the
    /// filesystem, so no permission check can be applied to it.
    Abstract,
    /// The kernel reported a longer address than the buffer held, or a
    /// pathname with no terminator, so the name cannot be trusted.
    Truncated,
    /// Not `AF_UNIX` at all.
    WrongFamily {
        /// The reported address family.
        family: i32,
    },
}

/// Why an inherited descriptor's address cannot be served on.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum AddressError {
    /// The address is not a pathname, so nothing about it can be
    /// checked against a mode or an owner.
    #[error(
        "the inherited socket's address is {kind}, but the registrar endpoint requires a \
         filesystem pathname whose mode and owner can be checked"
    )]
    NotAPathname {
        /// A short description of what arrived instead.
        kind: &'static str,
    },
}

impl UnixAddressKind {
    /// A short, stable description used in the refusal message.
    fn describe(&self) -> &'static str {
        match self {
            Self::Pathname(_) => "a pathname",
            Self::Unnamed => "unnamed",
            Self::Abstract => "an abstract-namespace name",
            Self::Truncated => "a truncated name",
            Self::WrongFamily { .. } => "not an AF_UNIX address",
        }
    }

    /// Yields the pathname, or the reason there is not one.
    ///
    /// # Errors
    ///
    /// Returns [`AddressError::NotAPathname`] for every other kind.
    pub(crate) fn into_pathname(self) -> Result<PathBuf, AddressError> {
        let kind = self.describe();
        match self {
            Self::Pathname(path) => Ok(path),
            _ => Err(AddressError::NotAPathname { kind }),
        }
    }
}

/// Classifies a raw `sockaddr_un` as the kernel filled it in.
///
/// Split out from the `getsockname()` call so the four rejections —
/// unnamed, abstract, truncated and wrong-family — are ordinary unit
/// tests over byte arrays rather than sockets that have to be conjured
/// into those states.
///
/// `sun_path` is the address's path field and `address_len` the length
/// the kernel reported for the *whole* `sockaddr_un`, including the
/// two-byte family. A length past the buffer means the kernel had more
/// to say than fitted, and a pathname that fills `sun_path` with no NUL
/// is equally untrustworthy: in both cases the name that would be
/// checked is not the name that is bound.
pub(crate) fn classify_unix_address(
    family: i32,
    sun_path: &[u8],
    address_len: usize,
) -> UnixAddressKind {
    if family != libc::AF_UNIX {
        return UnixAddressKind::WrongFamily { family };
    }
    let header_len = std::mem::size_of::<libc::sa_family_t>();
    if address_len > header_len + sun_path.len() {
        return UnixAddressKind::Truncated;
    }
    let Some(path_len) = address_len.checked_sub(header_len) else {
        return UnixAddressKind::Truncated;
    };
    if path_len == 0 {
        return UnixAddressKind::Unnamed;
    }
    let Some(path) = sun_path.get(..path_len) else {
        return UnixAddressKind::Truncated;
    };
    match path.first() {
        None => UnixAddressKind::Unnamed,
        // A leading NUL is the abstract namespace, which has no
        // filesystem presence and therefore no mode or owner.
        Some(0) => UnixAddressKind::Abstract,
        Some(_) => match path.iter().position(|byte| *byte == 0) {
            Some(end) => UnixAddressKind::Pathname(PathBuf::from(OsStr::from_bytes(&path[..end]))),
            // No terminator inside the reported length: the name filled
            // the field, so it may have been cut short.
            None if path_len == sun_path.len() => UnixAddressKind::Truncated,
            None => UnixAddressKind::Pathname(PathBuf::from(OsStr::from_bytes(path))),
        },
    }
}

/// Sets `FD_CLOEXEC` on a descriptor, preserving whatever else is set.
///
/// Called before the descriptor is converted or retained, and therefore
/// before any code in this process can spawn a child. Post-renew hooks
/// run inside this daemon, and a hook that inherited a listening
/// registrar socket could accept on it.
///
/// # Errors
///
/// Returns the underlying `fcntl` failure. Startup refuses on it rather
/// than serving with an inheritable listening socket.
pub(crate) fn set_cloexec(fd: RawFd) -> std::io::Result<()> {
    // SAFETY: `fcntl` with `F_GETFD` reads only the descriptor's flags
    // and touches no caller memory; `fd` is the descriptor the
    // activation contract named.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `F_SETFD` takes an int by value and touches no caller
    // memory. The existing flags are preserved rather than replaced.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Reports whether `FD_CLOEXEC` is set on a descriptor.
///
/// # Errors
///
/// Returns the underlying `fcntl` failure.
pub(crate) fn is_cloexec(fd: RawFd) -> std::io::Result<bool> {
    // SAFETY: as in `set_cloexec`, `F_GETFD` only reads flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(flags & libc::FD_CLOEXEC != 0)
}

/// Reads the socket facts of a descriptor.
///
/// # Errors
///
/// Returns the first `getsockopt` or `fcntl` failure. A descriptor that
/// is not a socket at all fails here with `ENOTSOCK`.
pub(crate) fn descriptor_facts(fd: RawFd) -> std::io::Result<DescriptorFacts> {
    Ok(DescriptorFacts {
        domain: socket_option(fd, libc::SO_DOMAIN)?,
        sock_type: socket_option(fd, libc::SO_TYPE)?,
        accepting: socket_option(fd, libc::SO_ACCEPTCONN)? != 0,
        cloexec: is_cloexec(fd)?,
    })
}

/// Reads one `SOL_SOCKET` integer option.
fn socket_option(fd: RawFd, option: libc::c_int) -> std::io::Result<i32> {
    let mut value: libc::c_int = 0;
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::c_int>())
        .map_err(|_| std::io::Error::other("socklen_t cannot hold sizeof(int)"))?;
    // SAFETY: `value` is a live `c_int` and `len` is its exact size, so
    // the kernel writes at most those bytes; both pointers outlive the
    // call.
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            std::ptr::from_mut(&mut value).cast::<libc::c_void>(),
            &raw mut len,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(value)
}

/// Resolves a descriptor's bound pathname with `getsockname()`.
///
/// The pathname comes from the kernel, never from configuration. It is
/// what the mode and ownership policy is then applied to.
///
/// # Errors
///
/// Returns the `getsockname` failure, or [`AddressError`] when the
/// address is not a pathname.
pub(crate) fn resolve_pathname(fd: RawFd) -> anyhow::Result<PathBuf> {
    // SAFETY: `sockaddr_un` is a plain C struct of integers and a byte
    // array, with no padding invariant, no niche and no pointer, so an
    // all-zero bit pattern is a valid value of it. Zeroing rather than
    // leaving it uninitialised is also what makes the classification
    // below sound when the kernel writes fewer bytes than the struct
    // holds: everything past `len` is a known 0 rather than whatever the
    // stack happened to carry.
    let mut storage: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let mut len = libc::socklen_t::try_from(std::mem::size_of::<libc::sockaddr_un>())
        .map_err(|_| std::io::Error::other("socklen_t cannot hold sizeof(sockaddr_un)"))?;
    // SAFETY: `storage` is a live, zeroed `sockaddr_un` and `len` its
    // exact size, so the kernel writes no more than the struct holds.
    let result = unsafe {
        libc::getsockname(
            fd,
            std::ptr::from_mut(&mut storage).cast::<libc::sockaddr>(),
            &raw mut len,
        )
    };
    if result < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let path_bytes: Vec<u8> = storage
        .sun_path
        .iter()
        .map(|byte| u8::from_ne_bytes(byte.to_ne_bytes()))
        .collect();
    let kind = classify_unix_address(
        i32::from(storage.sun_family),
        &path_bytes,
        usize::try_from(len).unwrap_or(usize::MAX),
    );
    Ok(kind.into_pathname()?)
}
