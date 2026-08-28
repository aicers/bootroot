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
//! - [`handler`] is the seam this module stops at. The endpoint owns the
//!   transport; [`protocol`] owns the payload schema, its codec and the
//!   mapping of verb outcomes onto caller-visible responses, and
//!   [`production`] is the implementation that joins the two to the verb
//!   layer.
//! - [`tls`] is the mutually-authenticated transport the connection is
//!   wrapped in: the server material the endpoint presents, the
//!   verifier every client certificate is built against, and the
//!   resolver a renewal swaps new material through.
//! - [`serve`] is the accept loop, the bounded connection fleet and the
//!   drain-then-abort shutdown.
//! - [`client`] is the other end of all of it: this repository's
//!   reference caller, which dials the socket, completes the pinned
//!   handshake and drives one request over one connection. It has no
//!   production consumer here — the deployed caller lives in another
//!   repository — and exists so that the caller behaviour this endpoint
//!   expects is written down as running code rather than reinvented
//!   inline by whichever test needs it next.
//!
//! # What authenticates a caller
//!
//! Two checks, in this order, answering two different questions.
//!
//! First the connected socket's peer credentials. The pathname's mode
//! and owner are a *precondition* on the listener, not a statement about
//! who connected: a check on the path cannot tell one connection from
//! another. Only a peer whose uid equals this daemon's effective uid
//! goes any further, which under the shipped units means root talking to
//! root. It stays first and stays a gate of its own — it costs one
//! syscall and no handshake, and a connection failing it is refused even
//! when its client certificate is the registrar's. A full root
//! compromise is outside this endpoint's boundary and always was.
//!
//! Then the client certificate. The connection is wrapped in mTLS
//! ([`tls`]): a caller presenting no certificate, or one whose chain
//! does not verify against the pinned subset of the deployment's own CA
//! bundle, fails the handshake before a request byte is read. What
//! verified is not yet what is *accepted* — the endpoint admits exactly
//! one identity, the registrar client name
//! `<instance>.bootroot-registrar.<host>.<domain>`, and a leaf that
//! verified but carries any other name is refused through the same
//! [`refusal`] path every other pre-verb refusal uses. An ordinary
//! service leaf issued for the registrar's own host is refused there.
//!
//! The identity is [`serve::caller_identity`]'s
//! `registrar-client:<san>`, rendered at that one site from the
//! presented leaf's single DNS SAN and passed to the handler unchanged.
//! The peer's uid, pid and gid are logged as connection diagnostics and
//! are deliberately not part of it: a pid is reused and races against
//! the credential it was read with, a gid is not the subject, and a uid
//! names root on this host rather than the registrar.
//!
//! # Production wiring
//!
//! The handler is **not** part of the activated endpoint. Activation
//! consumes the socket-activation contract once, above the `SIGHUP`
//! loop; the handler is built per invocation from that invocation's
//! settings and handed to [`serve::run`] as an argument. The accept task
//! therefore cannot be spawned without one, which is a signature rather
//! than a runtime invariant — no slot, no lock and no interior
//! mutability. A reload rebuilds the handler from the reloaded settings
//! while the socket inode stays exactly as it was.

pub(crate) mod activation;
pub(crate) mod client;
pub(crate) mod frame;
pub(crate) mod handler;
pub(crate) mod policy;
pub(crate) mod production;
pub(crate) mod protocol;
pub(crate) mod refusal;
pub(crate) mod refusing;
pub(crate) mod serve;
pub(crate) mod tls;

#[cfg(test)]
mod test_support;
#[cfg(test)]
mod tests;

use std::os::unix::io::{FromRawFd as _, RawFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::net::UnixListener;
use tokio::time::Instant;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use self::activation::{ActivationContract, ActivationValues};
use self::tls::EndpointCertResolver;
use crate::config::Settings;

/// Largest declared request payload the endpoint will read.
pub(crate) const MAX_FRAME_PAYLOAD_BYTES: usize = 65_536;

/// Largest handler response the endpoint will write.
pub(crate) const MAX_RESPONSE_PAYLOAD_BYTES: usize = 65_536;

/// Cumulative deadline from acceptance through a completed TLS
/// handshake.
///
/// A peer that opens a connection and never sends a `ClientHello` holds
/// one of [`MAX_CONCURRENT_CONNECTIONS`] slots for as long as it likes
/// without this, and it has not authenticated itself with anything yet.
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// Cumulative deadline from *handshake completion* through the
/// five-byte prefix *and* the declared operation-name bytes.
///
/// Measured from the handshake rather than from acceptance: a slow
/// handshake has its own budget above, and must not also consume the
/// budget for sending a header.
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

/// The instant a TLS handshake completed, which is the origin
/// [`HEADER_IDLE_TIMEOUT`] is measured from.
///
/// A newtype rather than a bare `Instant` because the serving path
/// carries two instants of that one type whose deadlines are not
/// interchangeable, and the older of the two — acceptance, which starts
/// [`HANDSHAKE_TIMEOUT`] — is still in scope at the call that arms the
/// header budget. Nothing turns an `Instant` into one of these, so
/// arming that budget from acceptance is a compile error rather than
/// something a test has to be built to notice.
#[derive(Clone, Copy)]
pub(crate) struct HandshakeCompleted(Instant);

impl HandshakeCompleted {
    /// Stamps the origin at the moment of the call.
    ///
    /// Call it where the handshake has just completed and nowhere else:
    /// what makes the value mean what it says is the call site, and
    /// that is the one thing the type cannot check.
    #[must_use]
    pub(crate) fn now() -> Self {
        Self(Instant::now())
    }

    /// Returns the instant the header deadline expires.
    #[must_use]
    pub(crate) fn header_deadline(self) -> Instant {
        self.0 + HEADER_IDLE_TIMEOUT
    }
}

/// The listening socket the daemon serves the registrar verbs on,
/// together with everything a connection is decided against.
///
/// Held behind an [`Arc`] above the `SIGHUP` loop and cloned into each
/// daemon invocation, so a reload resumes accepting on the same socket
/// inode rather than re-consuming an activation contract that has
/// already been consumed.
///
/// It carries no handler. What answers a request is built per
/// invocation, from that invocation's settings, and reaches the accept
/// loop as an argument to [`serve::run`] — so the three things here are
/// exactly the three that have to outlive a reload.
pub(crate) struct ActivatedEndpoint {
    listener: UnixListener,
    socket_path: PathBuf,
    daemon_uid: u32,
    acceptor: TlsAcceptor,
    // The certificate resolver is retained for exactly one consumer,
    // and that consumer — renewal for the endpoint leaf — is a sibling
    // issue. It has to be retained now because there is no way back to
    // the concrete resolver from a built `ServerConfig`, so a build
    // that dropped it would leave renewal with nothing to swap
    // through. Reachability is asserted through `cert_resolver`.
    resolver: Arc<EndpointCertResolver>,
    domain: String,
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

    /// Returns the acceptor every accepted connection is handed to.
    pub(crate) fn tls_acceptor(&self) -> &TlsAcceptor {
        &self.acceptor
    }

    /// Returns the resolver that decides which certificate the next
    /// handshake presents.
    ///
    /// This is the whole of the renewal seam. [`rustls::ServerConfig`]
    /// keeps only an `Arc<dyn ResolvesServerCert>`, and the trait does
    /// not extend `Any`, so code holding the configuration or the
    /// acceptor cannot reach the concrete resolver at all — it survives
    /// here or nowhere.
    // The renewal work that calls this is a sibling issue, so until it
    // lands nothing outside a test reaches the accessor. It exists now
    // so that work needs nothing from this one.
    #[allow(dead_code)]
    pub(crate) fn cert_resolver(&self) -> &Arc<EndpointCertResolver> {
        &self.resolver
    }

    /// Returns the configured `network.domain` the presented client
    /// identity is recognized against.
    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }
}

impl std::fmt::Debug for ActivatedEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActivatedEndpoint")
            .field("socket_path", &self.socket_path)
            .field("daemon_uid", &self.daemon_uid)
            .field("domain", &self.domain)
            .finish_non_exhaustive()
    }
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
/// 3. The TLS material comes next: the endpoint's own certificate chain
///    and key, and the client verifier built over the pinned subset of
///    the deployment's CA bundle. It goes here so an endpoint fails on
///    unusable certificate material before it touches the inherited
///    descriptor.
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
/// Returns an error when the server certificate material or the client
/// trust material is absent, unusable or not what a pinned caller would
/// accept, when the activation contract is missing, addressed to
/// another process or announces anything but one descriptor, when
/// `FD_CLOEXEC` cannot be set, when the descriptor is not a listening
/// `AF_UNIX` stream socket, when its address is not a pathname, or when
/// the pathname or its parent directory fails the ownership and
/// permission policy.
pub(crate) fn activate(settings: &Settings) -> anyhow::Result<Option<Arc<ActivatedEndpoint>>> {
    let enabled = settings.registrar_endpoint.enabled;
    if !enabled {
        return Ok(None);
    }
    let effective_uid = current_effective_uid();
    if warns_about_unprivileged_daemon(enabled, effective_uid) {
        warn!("{UNPRIVILEGED_DAEMON_WARNING}");
    }
    let (server_config, resolver) = tls::build_server_config(
        settings.registrar_endpoint.server_cert_path.as_deref(),
        settings.registrar_endpoint.server_key_path.as_deref(),
        settings.trust.ca_bundle_path.as_deref(),
        &settings.trust.trusted_ca_sha256,
        &settings.domain,
    )
    .context("loading the registrar endpoint's TLS material")?;
    let contract =
        ActivationContract::consume(&ActivationValues::from_environment(), current_pid())
            .context("consuming the systemd socket-activation contract")?;
    adopt(
        contract,
        effective_uid,
        server_config,
        resolver,
        settings.domain.clone(),
    )
    .map(Some)
}

/// Adopts an already-validated activation contract as a serving
/// endpoint.
///
/// Split from [`activate`] so a test can drive the whole descriptor,
/// address and filesystem-policy path — and the whole TLS serving path —
/// against a listener its own harness bound, through the very code
/// production runs. Nothing below this point binds, unlinks or chmods
/// anything, and nothing below it reads certificate material: the
/// already-built configuration and its resolver arrive as values.
///
/// # Errors
///
/// Returns an error for any descriptor, address or filesystem-policy
/// failure; see [`activate`].
pub(crate) fn adopt(
    contract: ActivationContract,
    effective_uid: u32,
    server_config: Arc<rustls::ServerConfig>,
    resolver: Arc<EndpointCertResolver>,
    domain: String,
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
        acceptor: TlsAcceptor::from(server_config),
        resolver,
        domain,
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
