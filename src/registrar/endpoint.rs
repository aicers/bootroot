//! The host-local transport that reaches the registrar's two verbs.
//!
//! Linux only, and systemd socket activation only. The daemon never
//! creates the endpoint: `systemd` binds `/run/bootroot/registrar.sock`,
//! owns its pathname and its mode, and hands the already-listening
//! descriptor to `bootroot-agent` as fd 3. Nothing here binds, unlinks,
//! renames or chmods a socket, and no configuration key names one — a
//! daemon that could be pointed at a path of its own is a daemon that
//! could be pointed at an unprotected one, and a daemon that unlinks
//! before binding has a window in which another process owns the name.
//!
//! # The layers, and why they are separate
//!
//! - [`activation`] turns the activation contract into one descriptor:
//!   the `LISTEN_PID`/`LISTEN_FDS` check, `FD_CLOEXEC`, the
//!   `SO_DOMAIN`/`SO_TYPE`/`SO_ACCEPTCONN` facts and the `getsockname()`
//!   address classification. Every decision is a pure function over
//!   injected values, so the whole contract is testable without an
//!   inherited socket and without touching this process's environment.
//! - [`policy`] decides whether the pathname the descriptor resolves to
//!   is one this daemon may serve on: the socket's mode and owner, and
//!   the parent directory's owner and write bits. Collection and
//!   decision are separate so every branch is reachable from a test.
//! - [`frame`] is the bootroot-owned envelope: one request per
//!   connection, four-byte big-endian payload length, one-byte operation
//!   name length, the name, the payload. No version, no magic, no status.
//! - [`refusal`] is the single pre-verb refusal path: a closed taxonomy
//!   of seven reasons, a daemon-generated connection diagnostic id, zero
//!   response bytes and a clean close.
//! - [`handler`] is the seam this issue stops at. The endpoint owns the
//!   transport; the payload schema, its codec and the mapping of verb
//!   outcomes onto caller-visible responses belong to the protocol work
//!   that supplies the production [`handler::RegistrarRequestHandler`].
//! - [`serve`] is the accept loop, the bounded connection fleet and the
//!   drain-then-abort shutdown.
//!
//! # What authenticates a caller
//!
//! The connected socket's peer credentials, and nothing else. The
//! pathname's mode and owner are a *precondition* on the listener, not a
//! statement about who connected: a check on the path cannot tell one
//! connection from another. Only a peer whose uid equals this daemon's
//! effective uid reaches a handler, which under the shipped units means
//! root talking to root. A full root compromise is outside this
//! endpoint's boundary and always was.
//!
//! The peer's pid and gid are logged as connection diagnostics and are
//! deliberately not part of the identity: a pid is reused and races
//! against the credential it was read with, and a gid is not the
//! subject. The identity is [`serve::caller_identity`]'s
//! `unix-peer:uid=<uid>`, rendered at that one site and passed to the
//! handler unchanged.
//!
//! # Production wiring
//!
//! There is no production handler yet, so an enabled endpoint refuses
//! startup ([`production_handler`]). That is deliberate: a listener that
//! accepted requests and had nowhere to send them would be a worse
//! answer than a daemon that will not start.

pub(crate) mod activation;
pub(crate) mod frame;
pub(crate) mod handler;
pub(crate) mod policy;
pub(crate) mod refusal;
pub(crate) mod serve;

#[cfg(test)]
mod tests;

use std::os::unix::io::{FromRawFd as _, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::net::UnixListener;
use tracing::{info, warn};

use self::activation::{ActivationContract, ActivationValues};
use self::handler::RegistrarRequestHandler;

/// Largest declared request payload the endpoint will read.
pub(crate) const MAX_FRAME_PAYLOAD_BYTES: usize = 65_536;

/// Largest handler response the endpoint will write.
pub(crate) const MAX_RESPONSE_PAYLOAD_BYTES: usize = 65_536;

/// Cumulative deadline from acceptance through the five-byte prefix
/// *and* the declared operation-name bytes.
pub(crate) const HEADER_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

/// Cumulative deadline from header completion through payload
/// completion.
pub(crate) const BODY_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Cumulative deadline from the first response write through its
/// completion.
pub(crate) const RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// How many connections may be in flight at once. Capacity is acquired
/// after accept and before anything is spawned, so an over-capacity
/// caller is refused and closed rather than left waiting in the kernel
/// backlog with no idea why — and refusing it costs the daemon neither
/// a task nor a retained stream, which is what makes this a bound on
/// the daemon rather than only on the handlers.
pub(crate) const MAX_CONCURRENT_CONNECTIONS: usize = 16;

/// How long in-flight connections are allowed to finish after the
/// endpoint stops accepting, before the remaining tasks are aborted and
/// joined.
pub(crate) const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// The one descriptor number systemd's activation contract starts at.
pub(crate) const SD_LISTEN_FDS_START: RawFd = 3;

/// The mode the activated socket must carry, exactly.
pub(crate) const REQUIRED_SOCKET_MODE: u32 = 0o700;

/// The listening socket the daemon serves the registrar verbs on,
/// together with everything a connection is decided against.
///
/// Held behind an [`Arc`] above the `SIGHUP` loop and cloned into each
/// daemon invocation, so a reload resumes accepting on the same socket
/// inode rather than re-consuming an activation contract that has
/// already been consumed.
pub(crate) struct ActivatedEndpoint {
    listener: UnixListener,
    socket_path: PathBuf,
    daemon_uid: u32,
    handler: Arc<dyn RegistrarRequestHandler>,
}

impl ActivatedEndpoint {
    /// Returns the listener the accept loop runs on.
    pub(crate) fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// Returns the pathname `getsockname()` resolved the descriptor to.
    pub(crate) fn socket_path(&self) -> &std::path::Path {
        &self.socket_path
    }

    /// Returns the effective uid a peer must match to reach a handler.
    pub(crate) fn daemon_uid(&self) -> u32 {
        self.daemon_uid
    }

    /// Returns the injected request handler.
    pub(crate) fn handler(&self) -> &Arc<dyn RegistrarRequestHandler> {
        &self.handler
    }
}

impl std::fmt::Debug for ActivatedEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivatedEndpoint")
            .field("socket_path", &self.socket_path)
            .field("daemon_uid", &self.daemon_uid)
            .finish_non_exhaustive()
    }
}

/// The production request handler, of which there is none.
///
/// The versioned request and response payloads, their codec and the
/// mapping of verb outcomes onto caller-visible responses are the
/// protocol sibling's, not this listener's. Until that lands, an enabled
/// endpoint refuses to start rather than accepting requests it cannot
/// answer.
fn production_handler() -> Option<Arc<dyn RegistrarRequestHandler>> {
    None
}

/// Reports whether an enabled endpoint must warn that the privileged
/// internal credential is out of reach.
///
/// A pure function of the two inputs that decide it, so the wording and
/// the condition are testable without a daemon, a socket or a uid change.
#[must_use]
pub(crate) fn warns_about_unprivileged_daemon(enabled: bool, effective_uid: u32) -> bool {
    enabled && effective_uid != 0
}

/// The warning an enabled non-root daemon emits, stated as the
/// consequence rather than as the observation.
pub(crate) const UNPRIVILEGED_DAEMON_WARNING: &str = concat!(
    "The registrar endpoint is enabled but this daemon is not running as root, so mint and ",
    "deregister cannot succeed: the privileged internal credential they need is unreachable ",
    "from an unprivileged process. Run bootroot-agent as root under the shipped ",
    "bootroot-registrar.service, or disable registrar_endpoint.",
);

/// Consumes the systemd activation contract and adopts the inherited
/// listening socket, once, at the composition boundary.
///
/// Every step is ordered deliberately:
///
/// 1. A disabled endpoint returns immediately. It reads no activation
///    variable, touches no descriptor and changes nothing.
/// 2. The unprivileged-daemon warning comes before every other endpoint
///    check, so an operator sees *why* the verbs will fail even when the
///    startup then stops for a different reason.
/// 3. The handler is required next. Without one there is nothing to
///    serve, and finding that out before inspecting the environment
///    keeps the diagnostic about the missing handler rather than about a
///    descriptor that was never going to be used.
/// 4. Only then are `LISTEN_PID` and `LISTEN_FDS` read — once — and the
///    descriptor validated and adopted.
///
/// This process's environment is never mutated, not even to clear the
/// activation variables after consuming them. A Tokio runtime exists
/// before `main`'s body runs, and `std::env::set_var` is unsound with
/// any other thread that may read the environment. The values are read
/// once and never reread instead, which is the property clearing them
/// was for. `LISTEN_FDNAMES` is ignored: exactly one descriptor is
/// required, so there is nothing to select by name.
///
/// # Errors
///
/// Returns an error when the endpoint is enabled and no handler is
/// registered, when the activation contract is missing, addressed to
/// another process or announces anything but one descriptor, when
/// `FD_CLOEXEC` cannot be set, when the descriptor is not a listening
/// `AF_UNIX` stream socket, when its address is not a pathname, or when
/// the pathname or its parent directory fails the ownership and
/// permission policy.
pub(crate) fn activate(enabled: bool) -> anyhow::Result<Option<Arc<ActivatedEndpoint>>> {
    if !enabled {
        return Ok(None);
    }
    let effective_uid = current_effective_uid();
    if warns_about_unprivileged_daemon(enabled, effective_uid) {
        warn!("{UNPRIVILEGED_DAEMON_WARNING}");
    }
    let Some(handler) = production_handler() else {
        anyhow::bail!(
            "registrar_endpoint.enabled is true, but no registrar request handler is registered \
             in this build. Enabling the endpoint is unsupported until the registrar protocol \
             work supplies one; set registrar_endpoint.enabled = false"
        );
    };
    let contract =
        ActivationContract::consume(&ActivationValues::from_environment(), current_pid())
            .context("consuming the systemd socket-activation contract")?;
    adopt(contract, effective_uid, handler).map(Some)
}

/// Adopts an already-validated activation contract as a serving
/// endpoint.
///
/// Split from [`activate`] so a test can drive the whole descriptor,
/// address and filesystem-policy path against a listener its own harness
/// bound, through the very code production runs. Nothing below this
/// point binds, unlinks or chmods anything.
///
/// # Errors
///
/// Returns an error for any descriptor, address or filesystem-policy
/// failure; see [`activate`].
pub(crate) fn adopt(
    contract: ActivationContract,
    effective_uid: u32,
    handler: Arc<dyn RegistrarRequestHandler>,
) -> anyhow::Result<Arc<ActivatedEndpoint>> {
    let fd = contract.into_descriptor();

    // FD_CLOEXEC first, and before anything that could spawn a child.
    // Post-renew hooks run inside this process, and a hook that inherits
    // a listening registrar socket can accept on it. systemd does not
    // set the flag on activation descriptors, and `Command` clears it on
    // nothing it did not open itself, so it is set here or not at all.
    activation::set_cloexec(fd).context("setting FD_CLOEXEC on the inherited descriptor")?;

    let facts = activation::descriptor_facts(fd)
        .context("reading the inherited descriptor's socket options")?;
    activation::check_descriptor(facts)?;

    let socket_path = activation::resolve_pathname(fd)?;

    let metadata = policy::collect(&socket_path).with_context(|| {
        format!(
            "reading the activated socket's filesystem metadata at {}",
            socket_path.display()
        )
    })?;
    policy::check(&metadata, effective_uid)?;

    // SAFETY: `fd` came out of the activation contract, was validated
    // above as a listening AF_UNIX stream socket, and is adopted exactly
    // once — `ActivationContract` is consumed by value and hands the
    // descriptor out only here, so no other owner exists to close it.
    let std_listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    std_listener
        .set_nonblocking(true)
        .context("making the inherited listening socket non-blocking")?;
    let listener = UnixListener::from_std(std_listener)
        .context("registering the inherited listening socket with the Tokio runtime")?;

    info!(
        socket = %socket_path.display(),
        daemon_uid = effective_uid,
        "Registrar endpoint activated on the inherited systemd socket."
    );
    Ok(Arc::new(ActivatedEndpoint {
        listener,
        socket_path,
        daemon_uid: effective_uid,
        handler,
    }))
}

/// Returns this process's effective uid.
pub(crate) fn current_effective_uid() -> u32 {
    crate::fs_util::current_process_euid()
}

/// Returns this process's id.
fn current_pid() -> u32 {
    std::process::id()
}

/// Turns a listener back into a raw descriptor without closing it.
///
/// Used only by tests, which bind their own listener in the harness and
/// then hand its descriptor through the production activation seam. The
/// harness must keep the descriptor open across that handoff, so the
/// listener is deconstructed rather than dropped.
#[cfg(test)]
pub(crate) fn into_raw_fd(listener: std::os::unix::net::UnixListener) -> RawFd {
    use std::os::unix::io::IntoRawFd as _;

    listener.into_raw_fd()
}
