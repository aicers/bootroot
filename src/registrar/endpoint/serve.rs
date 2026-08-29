//! The accept loop, one connection's whole life, and the coordinated
//! stop.
//!
//! # Task ownership
//!
//! Nothing here is detached. The accept loop is one task the daemon
//! holds a handle to, and every connection it accepts is a task in a
//! [`JoinSet`] the accept loop owns. When the shared shutdown watch goes
//! true — a `SIGHUP` reload or process shutdown, which are the same
//! signal to this layer — the loop stops accepting, gives the in-flight
//! connections [`CONNECTION_DRAIN_TIMEOUT`] to finish, then aborts and
//! joins whatever is left. The set is never simply dropped: dropping it
//! would abort each task at its current `.await` and the loop would go
//! on to report a clean stop it did not perform.
//!
//! The listener itself outlives all of this. It is held above the reload
//! loop, so the next daemon invocation resumes accepting on the same
//! socket inode rather than asking systemd for a contract that has
//! already been consumed.
//!
//! # One connection
//!
//! Accept, stamp the acceptance instant, assign a diagnostic id and take
//! a capacity permit — all three on the accept loop's own task, before
//! anything is spawned — then authenticate the peer, complete the TLS
//! handshake, recognize the certificate identity, read one frame under
//! cumulative deadlines, dispatch it, and write one response. That order
//! is the contract, and the peer check stays first: it costs one syscall
//! and no handshake, and it answers a different question from the
//! certificate's.
//!
//! Every exit before the verb runs goes through [`refusal::refuse`], and
//! every exit at all closes the stream — except a handshake that never
//! completed, which has no application stream to close and is dropped
//! after being logged.
//!
//! Taking the permit before the spawn is what makes
//! [`MAX_CONCURRENT_CONNECTIONS`] a bound on the daemon and not only on
//! the handlers: a connection that cannot have one is refused inline,
//! so an over-capacity peer can neither create a task nor make the
//! daemon retain an accepted stream. What it gets instead is the kernel
//! backlog, which is systemd's bound and not this loop's.

use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, timeout_at};
use tracing::{debug, error, info, warn};

use super::frame::{
    self, Operation, REQUEST_PREFIX_BYTES, RESPONSE_PREFIX_BYTES, check_operation_name,
    check_operation_name_length,
};
use super::handler::RegistrarRequestHandler;
use super::refusal::{
    self, CallerIdentityRefusal, ConnectionId, FrameEnd, PartialStage, Refusal,
    TransportRefusalReason,
};
use super::{
    ActivatedEndpoint, BODY_READ_TIMEOUT, CONNECTION_DRAIN_TIMEOUT, HANDSHAKE_TIMEOUT,
    HandshakeCompleted, MAX_CONCURRENT_CONNECTIONS, MAX_FRAME_PAYLOAD_BYTES,
    MAX_RESPONSE_PAYLOAD_BYTES, RESPONSE_WRITE_TIMEOUT,
};
use crate::registrar::verbs::outcome::CallerIdentity;
use crate::registrar::{recognize_registrar_client_name, single_dns_san};

/// How long the accept loop pauses after a failed `accept`.
///
/// Short enough that a transient failure costs a caller nothing it would
/// notice, and long enough that a persistent one — descriptor exhaustion
/// is the realistic case — cannot turn this loop into a busy wait. It is
/// paid only on the error path, so it delays a stop by at most this much
/// and only when an accept has just failed.
const ACCEPT_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(100);

/// The one site the authenticated caller identity is rendered at.
///
/// `registrar-client:<san>` and nothing else, where `<san>` is the
/// ASCII-lowercased single DNS SAN of the leaf the caller completed the
/// handshake with. The prefix mirrors the `unix-peer:` convention this
/// replaced.
///
/// It is a function of the presented certificate and nothing else, and
/// the certificate reached this point only by verifying against the
/// deployment's pinned CA material, so the value carries no unchecked
/// caller input. This is the caller of record the verb layer receives
/// and the value an audit record carries.
///
/// The peer's uid, pid and gid are deliberately absent. A uid names root
/// on this host rather than the registrar, a pid is reused and races the
/// credential it was read alongside, and a gid is not the subject; all
/// three are logged as connection diagnostics instead.
#[must_use]
pub(crate) fn caller_identity(san: &str) -> CallerIdentity {
    CallerIdentity::new(&format!("registrar-client:{}", san.to_ascii_lowercase()))
}

/// Reports whether a peer may reach a handler.
///
/// The socket policy admits exactly one uid, so this is an equality and
/// not a list: peer identity is a transport fact for the verb and audit
/// boundary, not a discriminator among several permitted callers.
#[must_use]
pub(crate) fn authorize_peer(peer_uid: u32, daemon_uid: u32) -> bool {
    peer_uid == daemon_uid
}

/// Runs the endpoint until the shared shutdown watch goes true.
///
/// `handler` is this invocation's, built by the daemon from this
/// invocation's settings and cloned into each accepted connection. It is
/// a parameter rather than something [`ActivatedEndpoint`] carries,
/// which is what makes "no connection is accepted without a handler
/// behind it" a signature: there is nothing to fill in later, so there
/// is no slot, no lock and no interior mutability. A reload builds a
/// fresh one and starts a fresh accept task over the same listener.
///
/// # Errors
///
/// Reserved for a failure that ends the endpoint itself; there is none
/// today, so this returns `Ok` once the drain completes. A refused or
/// failed *connection* is never an error of the endpoint's, and neither
/// is a failed `accept`: both are logged and the loop goes on.
pub(crate) async fn run(
    endpoint: Arc<ActivatedEndpoint>,
    handler: Arc<dyn RegistrarRequestHandler>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    info!(
        socket = %endpoint.socket_path().display(),
        "Registrar endpoint accepting connections."
    );
    let capacity = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let mut connections: JoinSet<()> = JoinSet::new();

    loop {
        if *shutdown.borrow_and_update() {
            break;
        }
        tokio::select! {
            // `changed()` and `UnixListener::accept()` are both
            // cancel-safe, and `JoinSet::join_next` yields nothing that
            // is lost when another branch wins.
            _ = shutdown.changed() => break,
            joined = connections.join_next(), if !connections.is_empty() => {
                report_finished_connection(joined);
            }
            accepted = endpoint.listener().accept() => {
                match accepted {
                    Ok((stream, _addr)) => {
                        // The TLS handshake deadline is cumulative
                        // *from acceptance*, so the clock starts here
                        // rather than wherever the connection task is
                        // eventually scheduled: under executor
                        // contention those are not the same instant,
                        // and only this one is the one the contract
                        // names. The header deadline is a separate
                        // budget that starts once the handshake has
                        // completed.
                        let accepted_at = Instant::now();
                        admit(
                            &mut connections,
                            &capacity,
                            &endpoint,
                            &handler,
                            stream,
                            accepted_at,
                        )
                        .await;
                    }
                    Err(err) => {
                        // A per-connection accept failure is the peer's
                        // problem, not the listener's; the descriptor is
                        // still valid and the loop keeps serving. What
                        // the pause is for is the *other* kind: a
                        // process-wide descriptor exhaustion (`EMFILE`,
                        // `ENFILE`) leaves the listener permanently
                        // readable, so retrying at once would spin this
                        // task on a core and fill the log with one line
                        // per iteration for as long as the condition
                        // lasts.
                        warn!("Registrar endpoint failed to accept a connection: {err}");
                        tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
                    }
                }
            }
        }
    }

    info!(
        socket = %endpoint.socket_path().display(),
        "Registrar endpoint stopped accepting; draining in-flight connections."
    );
    drain(connections).await;
    Ok(())
}

/// Admits one accepted connection, or refuses it for capacity.
///
/// The permit is taken *after* accept and *before* the spawn. When it is
/// unavailable the connection is refused through the common helper on
/// this loop's own task — a caller that is over capacity finds out by
/// being closed on rather than by waiting in the backlog, and it costs
/// the daemon neither a task nor a retained stream. Refusing writes no
/// bytes and only shuts the socket down, so the accept loop pays a
/// syscall for it and not a wait.
///
/// Finished tasks are reaped first, so every task still in the set holds
/// a permit and the set cannot outgrow [`MAX_CONCURRENT_CONNECTIONS`].
async fn admit(
    connections: &mut JoinSet<()>,
    capacity: &Arc<Semaphore>,
    endpoint: &Arc<ActivatedEndpoint>,
    handler: &Arc<dyn RegistrarRequestHandler>,
    mut stream: UnixStream,
    accepted_at: Instant,
) {
    while let Some(joined) = connections.try_join_next() {
        report_finished_connection(Some(joined));
    }
    let connection = ConnectionId::next();
    let Ok(permit) = Arc::clone(capacity).try_acquire_owned() else {
        refusal::refuse(
            &mut stream,
            &connection,
            &Refusal::transport(TransportRefusalReason::OverCapacity),
        )
        .await;
        return;
    };
    let endpoint = Arc::clone(endpoint);
    let handler = Arc::clone(handler);
    connections.spawn(async move {
        handle_connection(
            &endpoint,
            handler.as_ref(),
            stream,
            &connection,
            accepted_at,
        )
        .await;
        drop(permit);
    });
}

/// Logs a finished connection task's outcome.
///
/// A connection task returns `()` and swallows its own errors, so the
/// only thing left to report here is a panic inside one.
fn report_finished_connection(joined: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(err)) = joined
        && !err.is_cancelled()
    {
        error!("Registrar endpoint connection task failed: {err}");
    }
}

/// Stops the connection fleet: drain for [`CONNECTION_DRAIN_TIMEOUT`],
/// then abort and join whatever is left.
///
/// Returns once the set is empty, which is what makes "all endpoint
/// tasks joined" true rather than merely intended.
pub(crate) async fn drain(mut connections: JoinSet<()>) {
    let deadline = Instant::now() + CONNECTION_DRAIN_TIMEOUT;
    while !connections.is_empty() {
        match timeout_at(deadline, connections.join_next()).await {
            Ok(joined) => report_finished_connection(joined),
            Err(_elapsed) => {
                warn!(
                    remaining = connections.len(),
                    "Registrar endpoint connections did not finish within the drain timeout; \
                     aborting them."
                );
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                return;
            }
        }
    }
}

/// Authenticates the peer, terminates mTLS, recognizes the caller and,
/// if all three hold, serves its one request.
///
/// The order is the contract: peer credentials, then the handshake, then
/// the identity, then the first request byte. The peer check stays first
/// and stays a gate of its own — certificate authentication and
/// socket-level authentication answer different questions, the peer
/// check costs one syscall and no handshake, and a connection failing it
/// is refused even when its client certificate is the registrar's.
///
/// This is the only function in the serving path concrete over
/// [`UnixStream`]; everything below it is generic over the stream, so
/// the wrap is one change at one place and nothing under it knows the
/// difference.
async fn handle_connection(
    endpoint: &ActivatedEndpoint,
    handler: &dyn RegistrarRequestHandler,
    mut stream: UnixStream,
    connection: &ConnectionId,
    accepted_at: Instant,
) {
    let credentials = match stream.peer_cred() {
        Ok(credentials) => credentials,
        Err(err) => {
            // Without credentials there is no authorization decision to
            // make, so the connection is closed rather than guessed at.
            warn!(
                connection = connection.as_str(),
                "Registrar endpoint could not read peer credentials: {err}"
            );
            refusal::close(&mut stream, connection).await;
            return;
        }
    };
    let peer_uid = credentials.uid();
    debug!(
        connection = connection.as_str(),
        peer_uid,
        peer_gid = credentials.gid(),
        peer_pid = credentials.pid().unwrap_or(-1),
        "Registrar endpoint accepted a connection."
    );
    if !authorize_peer(peer_uid, endpoint.daemon_uid()) {
        refusal::refuse(
            &mut stream,
            connection,
            &Refusal::transport(TransportRefusalReason::UnauthorizedPeer {
                peer_uid,
                expected_uid: endpoint.daemon_uid(),
            }),
        )
        .await;
        return;
    }

    let Some(mut tls) = handshake(endpoint, stream, connection, accepted_at).await else {
        return;
    };
    // The header budget restarts here rather than continuing from
    // acceptance: the handshake had a budget of its own, and a slow one
    // must not leave a caller with no time left to send a header.
    let handshaken_at = HandshakeCompleted::now();
    // Logged because this instant is the origin of the header deadline:
    // without it the log shows a connection accepted and then refused
    // for a missing header, with nothing to say which of the two
    // budgets the caller actually spent.
    debug!(
        connection = connection.as_str(),
        "Registrar endpoint completed a TLS handshake."
    );

    // The identity is decided here, after the handshake, rather than
    // inside a `ClientCertVerifier` — see [`CallerIdentityRefusal`].
    // Nothing has been read from the caller yet, so "refused before any
    // request byte" still holds.
    match recognize_caller(&tls, endpoint.domain()) {
        Ok(caller) => {
            serve_request(&mut tls, connection, &caller, handler, handshaken_at).await;
        }
        Err(refusal) => {
            refusal::refuse(&mut tls, connection, &Refusal::caller_identity(refusal)).await;
        }
    }
}

/// Runs the TLS handshake under its cumulative deadline, or logs why it
/// did not complete.
///
/// A failed handshake reaches the caller only as a TLS alert, so the
/// daemon's log is the only diagnosis there is and the typed label is a
/// requirement rather than a nicety. Nothing is written and the stream
/// is dropped: there is no application stream yet to close cleanly.
async fn handshake(
    endpoint: &ActivatedEndpoint,
    stream: UnixStream,
    connection: &ConnectionId,
    accepted_at: Instant,
) -> Option<tokio_rustls::server::TlsStream<UnixStream>> {
    let deadline = accepted_at + HANDSHAKE_TIMEOUT;
    // Loaded here, immediately before the handshake, rather than held
    // for the life of the accept loop: a renewal that exchanged the
    // active configuration is in force from this connection onwards,
    // and one that lands while this handshake runs leaves it on the
    // configuration it started with.
    let acceptor = endpoint.tls_acceptor();
    match timeout_at(deadline, acceptor.accept(stream)).await {
        Ok(Ok(tls)) => Some(tls),
        Ok(Err(err)) => {
            warn!(
                connection = connection.as_str(),
                reason = handshake_failure_label(&err),
                "Registrar endpoint could not complete a TLS handshake: {err}"
            );
            None
        }
        Err(_elapsed) => {
            warn!(
                connection = connection.as_str(),
                reason = HANDSHAKE_TIMED_OUT,
                "Registrar endpoint dropped a connection that did not complete a TLS handshake \
                 within the handshake timeout."
            );
            None
        }
    }
}

/// The label a handshake that never completed is logged under.
const HANDSHAKE_TIMED_OUT: &str = "handshake-timeout";

/// The label a caller that presented no client certificate is logged
/// under.
const NO_CLIENT_CERTIFICATE: &str = "no-client-certificate";

/// The label a caller whose chain did not verify is logged under.
const CLIENT_CHAIN_REJECTED: &str = "client-chain-rejected";

/// The label every other handshake failure is logged under.
const HANDSHAKE_FAILED: &str = "handshake-failed";

/// Recovers the typed reason a handshake failed from the `io::Error`
/// `tokio_rustls` wrapped it in.
///
/// The three that matter are distinguished because they send an operator
/// to three different places: a caller that authenticates with nothing,
/// a caller whose certificate does not build to a pinned anchor, and
/// everything else.
fn handshake_failure_label(err: &std::io::Error) -> &'static str {
    match err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::NoCertificatesPresented) => NO_CLIENT_CERTIFICATE,
        Some(rustls::Error::InvalidCertificate(_)) => CLIENT_CHAIN_REJECTED,
        _ => HANDSHAKE_FAILED,
    }
}

/// Recognizes the identity that completed the handshake.
///
/// Chain verification already happened inside `WebPkiClientVerifier`, so
/// what is decided here is exclusively the *name*: either the caller of
/// record, or the typed refusal to log.
fn recognize_caller(
    tls: &tokio_rustls::server::TlsStream<UnixStream>,
    domain: &str,
) -> Result<CallerIdentity, CallerIdentityRefusal> {
    let (_, session) = tls.get_ref();
    let leaf = session
        .peer_certificates()
        .and_then(<[rustls::pki_types::CertificateDer<'_>]>::first)
        .ok_or(CallerIdentityRefusal::NoPeerCertificate)?;
    let san = single_dns_san(leaf.as_ref()).map_err(|source| {
        CallerIdentityRefusal::NotRegistrarClient {
            source: source.into(),
        }
    })?;
    recognize_registrar_client_name(&san, domain)
        .map_err(|source| CallerIdentityRefusal::NotRegistrarClient { source })?;
    Ok(caller_identity(&san))
}

/// Reads one framed request, dispatches it and writes one response.
///
/// Generic over the stream so a test drives the whole state machine over
/// an in-memory duplex — including every deadline, with `tokio::time`
/// paused — without a socket, a peer or a uid.
///
/// `handshaken_at` starts the header deadline, which is cumulative
/// through both the five-byte prefix and the declared operation-name
/// bytes. It is the instant the TLS handshake completed, not the
/// instant the connection was accepted: the handshake has a budget of
/// its own, and a slow one must not leave a caller with no time left to
/// send a header. That distinction is the parameter's type rather than
/// its name — see [`HandshakeCompleted`] — because acceptance is an
/// `Instant` in scope at the only call site there is.
pub(crate) async fn serve_request<S>(
    stream: &mut S,
    connection: &ConnectionId,
    caller: &CallerIdentity,
    handler: &dyn RegistrarRequestHandler,
    handshaken_at: HandshakeCompleted,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let Some((operation, payload_length)) = read_header(stream, connection, handshaken_at).await
    else {
        return;
    };

    // The body deadline is cumulative from header completion, not from
    // acceptance: a caller that spent its header budget still gets the
    // full body budget, and neither can be extended by dribbling bytes.
    let body_deadline = Instant::now() + BODY_READ_TIMEOUT;
    let mut payload = vec![0u8; payload_length];
    if let Err(stop) = read_exactly(stream, &mut payload, body_deadline, connection).await {
        refusal::refuse(
            stream,
            connection,
            &Refusal::transport(TransportRefusalReason::PartialFrame {
                stage: PartialStage::Payload,
                end: stop.end,
                received: stop.received,
                expected: payload_length,
            })
            .with_operation(operation),
        )
        .await;
        return;
    }

    dispatch(stream, connection, caller, handler, operation, &payload).await;
}

/// Reads and checks everything up to the end of the operation name.
///
/// Returns the recognized operation and the declared payload length, or
/// `None` once it has already refused the connection through the common
/// helper — every exit from here is either a complete, valid header or a
/// closed stream.
async fn read_header<S>(
    stream: &mut S,
    connection: &ConnectionId,
    handshaken_at: HandshakeCompleted,
) -> Option<(Operation, usize)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let header_deadline = handshaken_at.header_deadline();

    let mut prefix = [0u8; REQUEST_PREFIX_BYTES];
    if let Err(stop) = read_exactly(stream, &mut prefix, header_deadline, connection).await {
        let reason = if stop.received == 0 {
            TransportRefusalReason::NoHeader { end: stop.end }
        } else {
            TransportRefusalReason::PartialFrame {
                stage: PartialStage::Prefix,
                end: stop.end,
                received: stop.received,
                expected: REQUEST_PREFIX_BYTES,
            }
        };
        refusal::refuse(stream, connection, &Refusal::transport(reason)).await;
        return None;
    }

    // The declared payload length is checked before a byte of the name
    // or the body is read, and before anything is allocated for either.
    let declared_payload = frame::declared_payload_length(prefix);
    let payload_length = match usize::try_from(declared_payload) {
        Ok(length) if length <= MAX_FRAME_PAYLOAD_BYTES => length,
        _ => {
            refusal::refuse(
                stream,
                connection,
                &Refusal::transport(TransportRefusalReason::OverLongFrame {
                    declared: declared_payload,
                    limit: MAX_FRAME_PAYLOAD_BYTES,
                }),
            )
            .await;
            return None;
        }
    };

    let name_length = match check_operation_name_length(frame::declared_name_length(prefix)) {
        Ok(length) => length,
        Err(cause) => {
            refusal::refuse(
                stream,
                connection,
                &Refusal::transport(TransportRefusalReason::MalformedHeader { cause }),
            )
            .await;
            return None;
        }
    };

    let mut name_bytes = vec![0u8; name_length];
    if let Err(stop) = read_exactly(stream, &mut name_bytes, header_deadline, connection).await {
        let mut refusal = Refusal::transport(TransportRefusalReason::PartialFrame {
            stage: PartialStage::OperationName,
            end: stop.end,
            received: stop.received,
            expected: name_length,
        });
        // The name is incomplete, so there is no identifier to log —
        // but the bytes that did arrive are logged as received bytes,
        // escaped and separately from the identifier. The unread marker
        // is for a stage that produced nothing at all, so a name that
        // stopped after `mi` is logged as `mi` and not as unread.
        if let Some(received) = name_bytes.get(..stop.received)
            && !received.is_empty()
        {
            refusal = refusal.with_received_name(received);
        }
        refusal::refuse(stream, connection, &refusal).await;
        return None;
    }

    let name = match check_operation_name(&name_bytes) {
        Ok(name) => name,
        Err(cause) => {
            refusal::refuse(
                stream,
                connection,
                &Refusal::transport(TransportRefusalReason::MalformedHeader { cause })
                    .with_received_name(&name_bytes),
            )
            .await;
            return None;
        }
    };
    let Some(operation) = Operation::from_name(name) else {
        refusal::refuse(
            stream,
            connection,
            &Refusal::transport(TransportRefusalReason::UnrecognizedOperation)
                .with_received_name(&name_bytes),
        )
        .await;
        return None;
    };

    Some((operation, payload_length))
}

/// Hands one checked request to the handler and writes its answer.
///
/// The match on [`Operation`] is exhaustive, so a third operation cannot
/// be added to the envelope without this dispatcher being made to
/// account for it.
async fn dispatch<S>(
    stream: &mut S,
    connection: &ConnectionId,
    caller: &CallerIdentity,
    handler: &dyn RegistrarRequestHandler,
    operation: Operation,
    payload: &[u8],
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // Exhaustive by design: a third operation cannot reach a handler
    // without this dispatcher being made to account for it.
    let intent = match operation {
        Operation::Mint => "mint an identity",
        Operation::Deregister => "tear an identity down",
    };
    debug!(
        connection = connection.as_str(),
        operation = operation.as_str(),
        payload_bytes = payload.len(),
        "Registrar endpoint dispatching a request to {intent}."
    );
    match handler.handle(operation, payload, caller.clone()).await {
        Ok(response) => write_response(stream, connection, operation, &response).await,
        Err(_refusal) => {
            refusal::refuse(
                stream,
                connection,
                &Refusal::handler_rejected_payload(operation),
            )
            .await;
        }
    }
}

/// Writes one response frame under the cumulative write deadline.
///
/// An over-long response is a *post-verb internal failure*: the verb
/// already ran, so this is not a refusal and does not go through the
/// refusal taxonomy. It is logged at error and the connection is closed
/// with nothing written, because the alternative is emitting a frame
/// this endpoint's own bound says is not writable.
async fn write_response<S>(
    stream: &mut S,
    connection: &ConnectionId,
    operation: Operation,
    response: &[u8],
) where
    S: AsyncWrite + Unpin,
{
    let Ok(length) = u32::try_from(response.len()) else {
        error!(
            connection = connection.as_str(),
            operation = operation.as_str(),
            response_bytes = response.len(),
            "Registrar endpoint handler produced a response too large to frame; closing without \
             a response."
        );
        refusal::close(stream, connection).await;
        return;
    };
    if response.len() > MAX_RESPONSE_PAYLOAD_BYTES {
        error!(
            connection = connection.as_str(),
            operation = operation.as_str(),
            response_bytes = response.len(),
            limit = MAX_RESPONSE_PAYLOAD_BYTES,
            "Registrar endpoint handler produced an over-long response; closing without a \
             response."
        );
        refusal::close(stream, connection).await;
        return;
    }

    let deadline = Instant::now() + RESPONSE_WRITE_TIMEOUT;
    let write = async {
        let prefix: [u8; RESPONSE_PREFIX_BYTES] = length.to_be_bytes();
        stream.write_all(&prefix).await?;
        stream.write_all(response).await?;
        stream.flush().await
    };
    match timeout_at(deadline, write).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => warn!(
            connection = connection.as_str(),
            "Registrar endpoint failed to write the response: {err}"
        ),
        Err(_elapsed) => warn!(
            connection = connection.as_str(),
            "Registrar endpoint did not finish writing the response within the write timeout."
        ),
    }
    refusal::close(stream, connection).await;
}

/// How a read stopped short.
struct ReadStop {
    /// Bytes of this stage that had arrived.
    received: usize,
    /// Whether the peer or the clock ended it.
    end: FrameEnd,
}

/// Fills `buf` completely, or reports how far it got and why it stopped.
///
/// `deadline` is cumulative for the whole stage rather than per-read, so
/// a caller cannot hold a connection open by sending one byte at a time.
/// An I/O failure is classified exactly as an EOF is — the frame ended
/// before it was complete, which is the observation the taxonomy is
/// about — and the underlying error is logged as a diagnostic rather
/// than turned into an eighth reason.
async fn read_exactly<S>(
    stream: &mut S,
    buf: &mut [u8],
    deadline: Instant,
    connection: &ConnectionId,
) -> Result<(), ReadStop>
where
    S: AsyncRead + Unpin,
{
    let mut received = 0usize;
    while received < buf.len() {
        let Some(rest) = buf.get_mut(received..) else {
            break;
        };
        match timeout_at(deadline, stream.read(rest)).await {
            Ok(Ok(0)) => {
                return Err(ReadStop {
                    received,
                    end: FrameEnd::Eof,
                });
            }
            Ok(Ok(read)) => received += read,
            Ok(Err(err)) => {
                debug!(
                    connection = connection.as_str(),
                    "Registrar endpoint read failed after {received} byte(s): {err}"
                );
                return Err(ReadStop {
                    received,
                    end: FrameEnd::Eof,
                });
            }
            Err(_elapsed) => {
                return Err(ReadStop {
                    received,
                    end: FrameEnd::Deadline,
                });
            }
        }
    }
    Ok(())
}
