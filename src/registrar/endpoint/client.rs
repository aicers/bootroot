//! The in-repo client for the registrar endpoint.
//!
//! One dial, one request, one response, then close. The client opens the
//! host-local `AF_UNIX` socket, completes a pinned mTLS handshake
//! presenting the registrar client leaf, writes exactly one
//! [`frame`]-encoded request, reads exactly one response to a clean end
//! of stream, and turns what came back into a typed outcome.
//!
//! # What it decides, and what it deliberately does not
//!
//! Every *verification* decision belongs to
//! [`crate::registrar::endpoint_pin`]: the anchor set comes from the pin
//! file and the presented leaf's single DNS SAN has to equal the
//! expected endpoint name. This module composes that verifier with its
//! own per-dial identity and holds no second copy of either rule. It
//! never parses the peer's certificate — not to extract a SAN, not to
//! enrich an error — and it never reads `notAfter` on either leaf.
//!
//! It implements no retry of any kind. A refusal the endpoint encoded is
//! a *successful exchange* here and is returned in the `Ok` position,
//! carrying [`protocol::EnrollError`] and [`protocol::RefusalClass`]
//! exactly as they arrived; deciding what to do about one belongs to a
//! caller that owns the reasons.
//!
//! # One limitation the wire cannot carry
//!
//! A connection the endpoint refuses *before* the handshake completes —
//! for capacity, or for peer credentials — has no application stream to
//! close, so it reaches this client as a connect- or handshake-level
//! failure and is not distinguishable there from an ordinary one. The
//! endpoint answers a refused caller with a bare close by design, and
//! this client does not guess at a reason the wire does not carry.

// This module has no production consumer in this crate, and that is the
// same fact `protocol.rs` and `verbs.rs` already record about their own
// halves: the deployed caller of this endpoint is roxyd, the co-located
// registrar, which lives in another repository and dials the socket
// itself. What lives here is this repository's reference implementation
// of that caller — the running record of the caller behaviour the
// endpoint expects — and the vehicle the registrar acceptance suite
// drives. Publishing it to escape the lint is not an option: it speaks
// `frame` and `protocol`, both `pub(crate)`, so a `pub` client would
// widen every payload type onto the library's public surface.
#![allow(dead_code)]

#[cfg(test)]
mod tests;

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use super::frame::{self, Operation};
use super::protocol::{self, CodecError};
use crate::registrar::endpoint;
use crate::registrar::endpoint_pin::{self, EndpointPinError};

/// Largest response this client will read off the wire, prefix
/// included — 65,540 bytes as the endpoint's constants stand.
///
/// Defined by referencing those constants rather than by restating a
/// literal, so the caller's bound cannot drift from the server's when
/// either moves.
const MAX_RESPONSE_BYTES: usize =
    frame::RESPONSE_PREFIX_BYTES + endpoint::MAX_RESPONSE_PAYLOAD_BYTES;

/// The declared payload length [`MAX_RESPONSE_BYTES`] leaves room for,
/// which is the only length this client ever allocates a buffer for. A
/// larger declaration fails before a payload byte is read.
const MAX_DECLARED_PAYLOAD_BYTES: usize = MAX_RESPONSE_BYTES - frame::RESPONSE_PREFIX_BYTES;

/// Deadline on the dial alone.
///
/// The dial is a host-local `AF_UNIX` connect, so this matches the scale
/// the endpoint already uses for its own [`endpoint::HANDSHAKE_TIMEOUT`].
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Deadline covering the TLS handshake, the request write and the
/// response read together.
///
/// It has to span the client-side handshake, the endpoint's verb
/// execution — a mint reaches `OpenBao` on the same host and has no
/// server-side execution deadline — and the response read. The server
/// budgets [`endpoint::HANDSHAKE_TIMEOUT`] (5 s) for the handshake and
/// [`endpoint::RESPONSE_WRITE_TIMEOUT`] (10 s) for the write, so this
/// bounds a stalled endpoint with clear headroom over every server-side
/// deadline.
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// The name handed to [`TlsConnector::connect`].
///
/// Inert. [`endpoint_pin::RegistrarEndpointVerifier`] deliberately
/// ignores the dialed name and applies the pinned expected name instead,
/// because a handshake over `AF_UNIX` has no hostname to match against.
/// Only its syntax matters, and only because `ServerName` insists on it.
const DIAL_NAME: &str = "registrar-endpoint.invalid";

/// The one response member success and refusal are told apart by.
const REFUSAL_DISCRIMINATOR: &str = "class";

/// How many times one dial reads the client pair before it gives up on
/// finding a matching one.
///
/// The writer publishes the pair with two separate renames, so a reader
/// that lands between them sees the new certificate beside the old key,
/// or the old certificate beside the new key. That window is the
/// writer's whole publication step and is over in microseconds, so what
/// closes it is a short bounded retry rather than a lock: the reader
/// re-reads both files and keeps whichever read finds a matching pair.
const CLIENT_MATERIAL_READS: usize = 5;

/// The waits between those reads — one after each of the first four
/// mismatches, and none after the fifth, which is the read the typed
/// mismatch is reported from.
///
/// This is a fixed local policy of the reader's, and deliberately not
/// the daemon's issuance-retry backoff: it is measured against one
/// `rename(2)` pair on the same host, not against a CA that is down.
const CLIENT_MATERIAL_BACKOFF: [Duration; CLIENT_MATERIAL_READS - 1] = [
    Duration::from_millis(1),
    Duration::from_millis(2),
    Duration::from_millis(4),
    Duration::from_millis(8),
];

/// Which half of the exchange an I/O failure interrupted.
///
/// The one thing an [`io::Error`] cannot say by itself: whether the
/// request could have reached the endpoint at all. A caller that knows
/// the write never completed knows a retry elsewhere cannot duplicate a
/// mint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExchangePhase {
    /// The request was still being written.
    Request,
    /// The response was being read.
    Response,
}

impl std::fmt::Display for ExchangePhase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Request => f.write_str("writing the request"),
            Self::Response => f.write_str("reading the response"),
        }
    }
}

/// Why the registrar client's own certificate and key are not usable.
///
/// Every variant names a path and nothing else. The bytes these
/// failures were reading are key material, and an error that quoted them
/// would put them in a log.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClientMaterialError {
    /// The certificate file does not exist.
    #[error("registrar client certificate {} does not exist", .path.display())]
    MissingCertificate {
        /// The path that was handed to the client.
        path: PathBuf,
    },
    /// The key file does not exist.
    #[error("registrar client key {} does not exist", .path.display())]
    MissingKey {
        /// The path that was handed to the client.
        path: PathBuf,
    },
    /// The certificate file exists but could not be read.
    #[error("registrar client certificate {} could not be read", .path.display())]
    UnreadableCertificate {
        /// The path that was handed to the client.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// The key file exists but could not be read.
    #[error("registrar client key {} could not be read", .path.display())]
    UnreadableKey {
        /// The path that was handed to the client.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// The certificate file holds no PEM certificate.
    #[error("registrar client certificate {} holds no PEM certificate", .path.display())]
    NoCertificate {
        /// The path that was handed to the client.
        path: PathBuf,
    },
    /// The certificate file holds a PEM block the parser refused.
    ///
    /// Distinct from [`ClientMaterialError::NoCertificate`] because the
    /// file is not empty of certificates — it is wrong — and distinct
    /// from silence because a refused block is never skipped over.
    #[error("registrar client certificate {} holds a malformed PEM block", .path.display())]
    MalformedCertificate {
        /// The path that was handed to the client.
        path: PathBuf,
    },
    /// The key file holds no PEM private key.
    #[error("registrar client key {} holds no PEM private key", .path.display())]
    NoPrivateKey {
        /// The path that was handed to the client.
        path: PathBuf,
    },
    /// Every read of the pair found a key that is not the leaf's.
    ///
    /// A renewal in flight leaves that state for the length of one
    /// `rename(2)`, and the bounded re-read above is what rides it out;
    /// reaching this means the two files disagreed on every read, which
    /// is a misconfiguration rather than a race. Neither path's bytes
    /// are named: one of them is key material.
    #[error(
        "registrar client certificate {} and key {} did not match on any of {reads} reads",
        .certificate_path.display(),
        .key_path.display()
    )]
    KeyMismatch {
        /// The certificate path that was handed to the client.
        certificate_path: PathBuf,
        /// The key path that was handed to the client.
        key_path: PathBuf,
        /// How many reads found a mismatch.
        reads: usize,
    },
    /// The pair parsed but `rustls` will not authenticate with it.
    #[error(
        "registrar client certificate {} and key {} are not usable client authentication \
         material: {source}",
        .certificate_path.display(),
        .key_path.display()
    )]
    Unusable {
        /// The certificate path that was handed to the client.
        certificate_path: PathBuf,
        /// The key path that was handed to the client.
        key_path: PathBuf,
        /// What `rustls` said about the pair.
        #[source]
        source: rustls::Error,
    },
}

/// Why a pinned, authenticating client configuration could not be built.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ClientConfigError {
    /// The pin file or the expected endpoint name was unusable.
    #[error(transparent)]
    Pin(#[from] EndpointPinError),
    /// `rustls` refused the presented pair as authentication material.
    #[error("the registrar client pair was refused as client authentication material: {0}")]
    ClientAuth(#[source] rustls::Error),
}

/// Why one exchange with the registrar endpoint did not produce an
/// answer.
///
/// Covers the exchange itself failing and nothing else. A refusal the
/// endpoint encoded is a *successful* exchange and has no variant here:
/// it arrives in the `Ok` position, in the `Refused` arm of the verb's
/// reply.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExchangeError {
    /// The pin file could not be read or parsed, or the expected
    /// endpoint name is not a usable DNS name. Never a fallback to
    /// trusting whatever the peer presents.
    #[error("the registrar endpoint trust decision could not be made: {source}")]
    Pin {
        /// Which pin rule the deployment broke.
        #[source]
        source: EndpointPinError,
    },
    /// The registrar client certificate or key could not be loaded.
    #[error("{source}")]
    Material {
        /// Which half of the pair, and how.
        #[source]
        source: ClientMaterialError,
    },
    /// The per-dial load never reported back.
    ///
    /// It runs on Tokio's blocking pool, so this is the hand-off itself
    /// failing rather than any file being wrong: the runtime shut down
    /// with the load still queued, or the load panicked. Neither is a
    /// statement about the endpoint, and no connection was opened.
    #[error("the registrar endpoint dial configuration was never loaded: {source}")]
    LoadAbandoned {
        /// Why the blocking task produced no result.
        #[source]
        source: tokio::task::JoinError,
    },
    /// The encoded request is longer than the envelope admits. Refused
    /// locally, before the dial.
    #[error("the registrar endpoint request could not be framed: {source}")]
    RequestTooLarge {
        /// The envelope's own complaint, carrying the length and limit.
        #[source]
        source: frame::OverLongRequestPayload,
    },
    /// The socket could not be connected.
    #[error("the registrar endpoint socket {} could not be connected", .path.display())]
    Connect {
        /// The socket path that was handed to the client.
        path: PathBuf,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// The dial did not finish inside [`CONNECT_TIMEOUT`].
    #[error(
        "connecting the registrar endpoint socket {} did not finish within {timeout:?}",
        .path.display()
    )]
    ConnectTimeout {
        /// The socket path that was handed to the client.
        path: PathBuf,
        /// The budget that elapsed.
        timeout: Duration,
    },
    /// The handshake, write and read together did not finish inside
    /// [`READ_TIMEOUT`].
    #[error("the registrar endpoint exchange did not finish within {timeout:?}")]
    ReadTimeout {
        /// The budget that elapsed.
        timeout: Duration,
    },
    /// The handshake failed for a reason the pin did not cause.
    #[error("the registrar endpoint TLS handshake failed: {source}")]
    Handshake {
        /// What `tokio_rustls` reported.
        #[source]
        source: io::Error,
    },
    /// The server was refused by the pin: it chained to no pinned
    /// anchor, or it carried a SAN other than the expected one.
    ///
    /// The two arrive as different [`rustls::CertificateError`]s and are
    /// deliberately one variant here, because both mean the same thing
    /// to a caller — the peer is not the endpoint this client pinned.
    #[error(
        "the registrar endpoint certificate was refused by the pin for {expected_name}: {source}"
    )]
    PinRefused {
        /// The endpoint name this client was constructed with. Not the
        /// name the server presented: recovering that would mean
        /// parsing the peer's certificate, which is a second copy of
        /// logic `endpoint_pin` owns.
        expected_name: String,
        /// The `rustls::Error` recovered from the wrapping
        /// [`io::Error`], verbatim.
        #[source]
        source: rustls::Error,
    },
    /// The response prefix declared more than [`MAX_RESPONSE_BYTES`]
    /// leaves room for. Refused before the payload is read.
    #[error(
        "the registrar endpoint declared a {declared}-byte response payload, over the \
         {limit}-byte maximum"
    )]
    ResponseTooLarge {
        /// The length the prefix declared.
        declared: u32,
        /// The bound it broke.
        limit: usize,
    },
    /// Fewer bytes arrived than the response frame needed, and then the
    /// stream ended *cleanly*.
    ///
    /// Both counts are over the whole frame, prefix included, so a
    /// prefix that itself arrived short is described the same way as a
    /// payload that did.
    #[error("the registrar endpoint response stopped cleanly after {received} of {expected} bytes")]
    Truncated {
        /// Bytes the frame needed.
        expected: usize,
        /// Bytes that arrived.
        received: usize,
    },
    /// Bytes arrived after the declared response payload.
    ///
    /// Its own variant rather than a decode failure: the frame was
    /// complete and something followed it, so the payload is not decoded
    /// and no outcome is returned.
    #[error("the registrar endpoint wrote {observed} byte(s) after a complete response frame")]
    TrailingBytes {
        /// How many bytes the one-byte probe saw. It neither drains nor
        /// buffers whatever else is pending.
        observed: usize,
    },
    /// The connection ended cleanly with zero application bytes read —
    /// the endpoint's bare-close refusal shape for a caller it will not
    /// serve.
    #[error("the registrar endpoint closed the connection cleanly without answering")]
    EmptyResponse,
    /// The exchange failed on an I/O error after the handshake
    /// completed.
    ///
    /// Includes the `UnexpectedEof` `rustls` reports for a peer that
    /// vanished without `close_notify`, which is an `Err` and not an
    /// orderly end. A response that arrived in full behind an unclean
    /// close is reported here rather than returned.
    #[error("the registrar endpoint exchange failed while {phase}: {source}")]
    Transport {
        /// Whether the request could have reached the endpoint at all.
        phase: ExchangePhase,
        /// The underlying I/O failure.
        #[source]
        source: io::Error,
    },
    /// The payload codec failed.
    ///
    /// In practice only the response direction is reachable: every
    /// request shape this client encodes is plain JSON that
    /// `serde_json` cannot fail on, so what lands here is a response the
    /// selected decoder rejected — or a payload that is not a JSON
    /// object at all, which the discriminator rejects before any
    /// decoder runs.
    #[error("the registrar endpoint payload codec failed: {source}")]
    Codec {
        /// The protocol's own complaint.
        #[source]
        source: CodecError,
    },
}

/// What a mint exchange produced.
///
/// Two arms because [`protocol`] models the success shape and the
/// refusal shape as separate types and the envelope carries no status
/// field to choose between them. The enum adds no field the protocol
/// does not already define.
#[derive(Debug)]
pub(crate) enum MintReply {
    /// The endpoint minted, or idempotently re-minted, the identity.
    Success(protocol::MintResponse),
    /// The endpoint refused the invocation, and said why.
    Refused(protocol::RefusalResponse),
}

/// What a deregister exchange produced.
#[derive(Debug)]
pub(crate) enum DeregisterReply {
    /// The endpoint removed the identity, or found it already absent.
    Success(protocol::DeregisterResponse),
    /// The endpoint refused the invocation, and said why.
    Refused(protocol::RefusalResponse),
}

/// A caller of the host-local registrar endpoint.
///
/// Constructed from four paths and one expected endpoint name and from
/// nothing else: it reads no configuration and introduces no
/// configuration key, which keeps configuration ownership where it
/// already is and makes the client directly constructible from a
/// `tempfile::tempdir()` in a test.
///
/// The expected name is the one
/// [`crate::registrar::registrar_endpoint_identity`] composes,
/// `<instance>.bootroot-registrar-endpoint.<host>.<domain>`, where
/// `<domain>` is a *suffix* of whatever label count it was configured
/// with rather than a single label. The client stores it and asserts
/// nothing about its shape.
#[derive(Debug)]
pub(crate) struct RegistrarEndpointClient {
    socket_path: PathBuf,
    pin_file: PathBuf,
    certificate_path: PathBuf,
    key_path: PathBuf,
    expected_endpoint_name: String,
}

impl RegistrarEndpointClient {
    /// Builds a client over explicit paths and one expected endpoint
    /// name.
    pub(crate) fn new(
        socket_path: impl Into<PathBuf>,
        pin_file: impl Into<PathBuf>,
        certificate_path: impl Into<PathBuf>,
        key_path: impl Into<PathBuf>,
        expected_endpoint_name: impl Into<String>,
    ) -> Self {
        Self {
            socket_path: socket_path.into(),
            pin_file: pin_file.into(),
            certificate_path: certificate_path.into(),
            key_path: key_path.into(),
            expected_endpoint_name: expected_endpoint_name.into(),
        }
    }

    /// Returns the endpoint name every dial pins the presented leaf
    /// against.
    pub(crate) fn expected_endpoint_name(&self) -> &str {
        &self.expected_endpoint_name
    }

    /// Mints, or idempotently re-mints, one service identity.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError`] when the exchange itself failed. An
    /// endpoint refusal is not one: it arrives as
    /// [`MintReply::Refused`].
    pub(crate) async fn mint(
        &self,
        request: protocol::RegisterRequest,
    ) -> Result<MintReply, ExchangeError> {
        let payload = self
            .exchange(Operation::Mint, &protocol::Request::Register(request))
            .await?;
        if is_refusal(&payload).map_err(codec)? {
            protocol::decode_refusal_response(&payload)
                .map(MintReply::Refused)
                .map_err(codec)
        } else {
            protocol::decode_mint_response(&payload)
                .map(MintReply::Success)
                .map_err(codec)
        }
    }

    /// Tears one service identity down.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError`] when the exchange itself failed. An
    /// endpoint refusal is not one: it arrives as
    /// [`DeregisterReply::Refused`].
    pub(crate) async fn deregister(
        &self,
        request: protocol::DeregisterRequest,
    ) -> Result<DeregisterReply, ExchangeError> {
        let payload = self
            .exchange(
                Operation::Deregister,
                &protocol::Request::Deregister(request),
            )
            .await?;
        if is_refusal(&payload).map_err(codec)? {
            protocol::decode_refusal_response(&payload)
                .map(DeregisterReply::Refused)
                .map_err(codec)
        } else {
            protocol::decode_deregister_response(&payload)
                .map(DeregisterReply::Success)
                .map_err(codec)
        }
    }

    /// Runs one whole exchange and returns the response payload.
    ///
    /// Everything that can fail before a byte reaches the socket — the
    /// codec, the envelope bound, the client material and the pin
    /// decision — fails here and in that order, so a misconfigured
    /// caller never opens a connection it cannot use.
    async fn exchange(
        &self,
        operation: Operation,
        request: &protocol::Request,
    ) -> Result<Vec<u8>, ExchangeError> {
        crate::tls::install_crypto_provider();

        let payload = protocol::encode_request(request).map_err(codec)?;
        let request_frame = frame::encode_request_frame(operation, &payload)
            .map_err(|source| ExchangeError::RequestTooLarge { source })?;
        let config = self.dial_config().await?;

        debug!(
            operation = operation.as_str(),
            socket = %self.socket_path.display(),
            request_bytes = request_frame.len(),
            "Dialing the registrar endpoint."
        );

        let stream = connect_within(
            &self.socket_path,
            UnixStream::connect(&self.socket_path),
            CONNECT_TIMEOUT,
        )
        .await?;

        let response =
            match timeout(READ_TIMEOUT, self.converse(stream, config, &request_frame)).await {
                Ok(result) => result?,
                Err(_elapsed) => {
                    return Err(ExchangeError::ReadTimeout {
                        timeout: READ_TIMEOUT,
                    });
                }
            };

        debug!(
            operation = operation.as_str(),
            response_bytes = response.len(),
            "The registrar endpoint answered."
        );
        Ok(response)
    }

    /// Builds this dial's TLS configuration.
    ///
    /// Called on every dial, so the pin file and the client material are
    /// re-read every time. That is intended: a pin file that is missing,
    /// unreadable or malformed is a typed failure of the dial rather
    /// than a panic or a fallback, and a renewed pair is picked up
    /// without a restart.
    ///
    /// Those three reads are the only blocking syscalls on the dial
    /// path, and they are outside both exchange timeouts — the connect
    /// budget starts after this returns — so a filesystem that answers
    /// slowly, or a path that turns out to be a FIFO, would otherwise
    /// hold a runtime worker for as long as it liked. They run on the
    /// blocking pool for that reason, together with the key parsing
    /// `with_client_auth_cert` does, rather than each read being made
    /// async separately: the pin file is read inside
    /// [`endpoint_pin::endpoint_server_verifier`], whose signature this
    /// issue leaves alone.
    async fn dial_config(&self) -> Result<ClientConfig, ExchangeError> {
        let pin_file = self.pin_file.clone();
        let expected_endpoint_name = self.expected_endpoint_name.clone();
        let certificate_path = self.certificate_path.clone();
        let key_path = self.key_path.clone();
        let loaded = finish_dial_load(
            tokio::task::spawn_blocking(move || {
                load_dial_config(
                    &pin_file,
                    &expected_endpoint_name,
                    &certificate_path,
                    &key_path,
                )
            })
            .await,
        );
        if let Err(ExchangeError::Material { source }) = &loaded {
            // Emitted here rather than inside the closure: a
            // `tracing` subscriber installed for one thread — which is
            // what `tracing::subscriber::set_default` gives, and what
            // this module's tests capture with — does not see an event
            // a blocking-pool thread records.
            warn!(
                certificate = %self.certificate_path.display(),
                key = %self.key_path.display(),
                "Registrar client material could not be loaded: {source}"
            );
        }
        loaded
    }

    /// Completes the handshake, writes the one request and reads the one
    /// response.
    async fn converse(
        &self,
        stream: UnixStream,
        config: ClientConfig,
        request_frame: &[u8],
    ) -> Result<Vec<u8>, ExchangeError> {
        let server_name = ServerName::try_from(DIAL_NAME)
            .expect("DIAL_NAME is a literal that is a syntactically valid DNS name");
        let mut tls = TlsConnector::from(Arc::new(config))
            .connect(server_name, stream)
            .await
            .map_err(|err| self.classify_handshake(err))?;

        tls.write_all(request_frame).await.map_err(write_failed)?;
        tls.flush().await.map_err(write_failed)?;

        let response = read_response(&mut tls).await?;

        // The exchange is over and this connection carries nothing
        // else, so it is closed the way the endpoint closes its own:
        // with a `close_notify` rather than a disappearance. The peer
        // has already ended its side, so a write failure here says
        // nothing a caller could act on.
        let _ = tls.shutdown().await;
        Ok(response)
    }

    /// Selects between the pin-refusal variant and the generic handshake
    /// variant.
    ///
    /// `tokio_rustls` wraps the `rustls::Error` the verifier produced in
    /// an [`io::Error`]; recovering it is the same downcast
    /// `serve::handshake_failure_label` performs on the server side, so
    /// one rule decides both directions.
    ///
    /// What the recovered error is then asked is
    /// [`endpoint_pin::is_endpoint_verify_rejection`] rather than the
    /// bare `InvalidCertificate(_)` the server side asks. The two
    /// questions are not the same one: the server's verifier is
    /// `WebPkiClientVerifier`, whose decision is the whole of the
    /// caller's chain check, while this client verifies the peer and
    /// then goes on to check its `CertificateVerify` signature — and
    /// `rustls` reports a bad one as `InvalidCertificate(BadSignature)`,
    /// after the pin has already passed. That is a handshake failure the
    /// pin did not cause, which is exactly what the generic variant is
    /// for, so the predicate that owns the rejection mapping decides it
    /// instead of the wrapper.
    fn classify_handshake(&self, err: io::Error) -> ExchangeError {
        match err
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            Some(source) if endpoint_pin::is_endpoint_verify_rejection(source) => {
                ExchangeError::PinRefused {
                    expected_name: self.expected_endpoint_name.clone(),
                    source: source.clone(),
                }
            }
            _ => ExchangeError::Handshake { source: err },
        }
    }
}

/// Turns the blocking load's join result into this dial's outcome.
///
/// The one place [`ExchangeError::LoadAbandoned`] is built. Everything
/// the load itself decided is already an `ExchangeError` and passes
/// through untouched; the only failure this adds is the hand-off's own —
/// the runtime shutting down with the load still queued, or the load
/// panicking.
///
/// Kept as a function rather than an inline `map_err` so that a test can
/// hand it a real [`tokio::task::JoinError`], taken from a blocking task
/// that really panicked, and assert the variant it selects. No dial can
/// be made to produce one: a test that killed its own runtime to force
/// the hand-off to fail would have nothing left to await the verb with.
fn finish_dial_load(
    joined: Result<Result<ClientConfig, ExchangeError>, tokio::task::JoinError>,
) -> Result<ClientConfig, ExchangeError> {
    match joined {
        Ok(loaded) => loaded,
        Err(source) => Err(ExchangeError::LoadAbandoned { source }),
    }
}

/// The whole per-dial load, in one blocking call.
///
/// [`RegistrarEndpointClient::dial_config`] hands this to the blocking
/// pool. Kept as a free function taking owned paths so that it can be
/// moved into the closure, and so the three reads it performs — the
/// certificate, the key and, inside the verifier, the pin file — stay in
/// one place.
fn load_dial_config(
    pin_file: &Path,
    expected_endpoint_name: &str,
    certificate_path: &Path,
    key_path: &Path,
) -> Result<ClientConfig, ExchangeError> {
    // `std::thread::sleep` because this whole function is already on
    // Tokio's blocking pool, where blocking the thread is what the pool
    // is for. The waits are microseconds against one `rename(2)` pair.
    let (chain, key) =
        load_matching_client_material(certificate_path, key_path, std::thread::sleep)
            .map_err(|source| ExchangeError::Material { source })?;
    build_client_config(pin_file, expected_endpoint_name, chain, key).map_err(|err| match err {
        ClientConfigError::Pin(source) => ExchangeError::Pin { source },
        ClientConfigError::ClientAuth(source) => ExchangeError::Material {
            source: ClientMaterialError::Unusable {
                certificate_path: certificate_path.to_path_buf(),
                key_path: key_path.to_path_buf(),
                source,
            },
        },
    })
}

/// Builds the pinned, authenticating client configuration.
///
/// The one place in this tree where the registrar caller's TLS
/// configuration is composed. It is exactly
/// [`endpoint_pin::endpoint_server_verifier`] finished with
/// [`rustls::ConfigBuilder::with_client_auth_cert`], which is what
/// [`endpoint_pin::build_endpoint_client_config`]'s own rustdoc directs
/// an authenticating caller to do — that helper is a convenience for a
/// caller presenting no client certificate and is deliberately not used
/// here. Every verification decision stays inside the verifier; this
/// function only attaches the caller's identity.
///
/// # Errors
///
/// Returns [`ClientConfigError::Pin`] when the pin file is missing,
/// unreadable or malformed, or when `expected_endpoint_name` is not a
/// usable DNS name, and [`ClientConfigError::ClientAuth`] when `rustls`
/// refuses the presented pair.
pub(crate) fn build_client_config(
    pin_file: &Path,
    expected_endpoint_name: &str,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<ClientConfig, ClientConfigError> {
    let verifier = endpoint_pin::endpoint_server_verifier(pin_file, expected_endpoint_name)?;
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_auth_cert(chain, key)
        .map_err(ClientConfigError::ClientAuth)
}

/// Reads the pair until the key is the leaf's, or reports that it never
/// was.
///
/// This is the reader's half of the publication contract. The writer
/// stages the certificate and the key and `rename(2)`s them one after
/// the other, so the pair is not published atomically even though
/// neither file is ever truncated: a dial landing between the two
/// renames sees a certificate and a key that are not each other's.
/// Presenting that pair would fail the handshake with a signature error
/// that says nothing about what really happened, so it is never
/// presented — the reader re-reads instead, up to
/// [`CLIENT_MATERIAL_READS`] times with the
/// [`CLIENT_MATERIAL_BACKOFF`] waits between them, and returns the
/// typed [`ClientMaterialError::KeyMismatch`] only once every read has
/// disagreed.
///
/// `wait` is a parameter so the policy is drivable without real waits:
/// a test asserts the exact delays it is asked for, and can publish a
/// matching pair from inside one of them.
///
/// A read that fails for any *other* reason — an absent file, an
/// unreadable one, a certificate PEM the parser refuses — is returned
/// at once and is not retried. Those are not races, and re-reading them
/// only delays the diagnostic.
///
/// # Errors
///
/// Returns whatever [`load_client_material`] reported, or
/// [`ClientMaterialError::KeyMismatch`] when every read found a key
/// that is not the leaf's.
fn load_matching_client_material(
    certificate_path: &Path,
    key_path: &Path,
    mut wait: impl FnMut(Duration),
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ClientMaterialError> {
    for read in 0..CLIENT_MATERIAL_READS {
        let (chain, key) = load_client_material(certificate_path, key_path)?;
        if client_pair_matches(&chain, &key) {
            return Ok((chain, key));
        }
        debug!(
            certificate = %certificate_path.display(),
            read = read + 1,
            "The registrar client pair did not match; re-reading it."
        );
        if let Some(delay) = CLIENT_MATERIAL_BACKOFF.get(read) {
            wait(*delay);
        }
    }
    Err(ClientMaterialError::KeyMismatch {
        certificate_path: certificate_path.to_path_buf(),
        key_path: key_path.to_path_buf(),
        reads: CLIENT_MATERIAL_READS,
    })
}

/// Reports whether the loaded key is the loaded leaf's.
///
/// The proof is a signature, through the same helper the endpoint's own
/// loader uses, so there is one matching rule on both sides of the
/// connection rather than two.
///
/// A key `rustls` cannot sign with at all is *not* reported as a
/// mismatch: re-reading it would find the same key five times and then
/// blame a race that never happened, so it is passed through for
/// `with_client_auth_cert` to refuse with
/// [`ClientMaterialError::Unusable`], which names the real fault.
fn client_pair_matches(chain: &[CertificateDer<'static>], key: &PrivateKeyDer<'static>) -> bool {
    let Some(leaf) = chain.first() else {
        return false;
    };
    let Ok(signing_key) = rustls::crypto::ring::sign::any_supported_type(key) else {
        return true;
    };
    crate::tls::cert_key_matches(leaf, signing_key.as_ref())
}

/// Loads the registrar client leaf and its key from disk.
///
/// The plain load, and nothing more: it does not decide whether the key
/// is the leaf's and it does not inspect `notAfter`. The matching rule
/// and the bounded re-read that rides out a renewal's torn pair live in
/// [`load_matching_client_material`], which is what the dial path calls.
///
/// # Errors
///
/// Returns [`ClientMaterialError`] naming the offending path. It names
/// no byte of either file.
fn load_client_material(
    certificate_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ClientMaterialError> {
    let certificate_bytes = std::fs::read(certificate_path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            ClientMaterialError::MissingCertificate {
                path: certificate_path.to_path_buf(),
            }
        } else {
            ClientMaterialError::UnreadableCertificate {
                path: certificate_path.to_path_buf(),
                source,
            }
        }
    })?;
    let key_bytes = std::fs::read(key_path).map_err(|source| {
        if source.kind() == io::ErrorKind::NotFound {
            ClientMaterialError::MissingKey {
                path: key_path.to_path_buf(),
            }
        } else {
            ClientMaterialError::UnreadableKey {
                path: key_path.to_path_buf(),
                source,
            }
        }
    })?;

    // Collected as a `Result` rather than flattened: a block this
    // parser refuses is a fault in the file, and dropping it would
    // authenticate with whatever else the file happened to hold — a
    // valid leaf followed by a corrupt block would dial with the leaf
    // alone and report nothing. The parser's own complaint is not
    // carried: a certificate path can be misconfigured onto a key file,
    // and `rustls_pemfile` quotes the offending line.
    let chain: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut io::BufReader::new(certificate_bytes.as_slice()))
            .collect::<Result<_, io::Error>>()
            .map_err(|_source| ClientMaterialError::MalformedCertificate {
                path: certificate_path.to_path_buf(),
            })?;
    if chain.is_empty() {
        return Err(ClientMaterialError::NoCertificate {
            path: certificate_path.to_path_buf(),
        });
    }

    // The error deliberately quotes none of the bytes it failed on:
    // this input is key material, and a parse failure that named it
    // would put it in a log.
    let key = rustls_pemfile::private_key(&mut io::BufReader::new(key_bytes.as_slice()))
        .ok()
        .flatten()
        .ok_or_else(|| ClientMaterialError::NoPrivateKey {
            path: key_path.to_path_buf(),
        })?;

    Ok((chain, key))
}

/// Wraps a dial in [`CONNECT_TIMEOUT`].
///
/// The future is a parameter so the wrapper itself is drivable under a
/// paused clock: a stalled `AF_UNIX` `connect(2)` is not portably
/// constructible, and an accept-and-stall listener would exercise the
/// handshake instead.
async fn connect_within<F>(
    path: &Path,
    dial: F,
    budget: Duration,
) -> Result<UnixStream, ExchangeError>
where
    F: std::future::Future<Output = io::Result<UnixStream>>,
{
    match timeout(budget, dial).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(source)) => Err(ExchangeError::Connect {
            path: path.to_path_buf(),
            source,
        }),
        Err(_elapsed) => Err(ExchangeError::ConnectTimeout {
            path: path.to_path_buf(),
            timeout: budget,
        }),
    }
}

/// How a bounded read ended.
enum FillOutcome {
    /// The buffer was filled.
    Filled,
    /// The peer ended the stream cleanly, `received` bytes in.
    EndOfStream {
        /// Bytes of this buffer that had arrived.
        received: usize,
    },
}

/// Reads until `buffer` is full or the peer ends the stream cleanly.
///
/// An `Err` — including the `UnexpectedEof` `rustls` reports for a peer
/// that vanished without `close_notify` — is propagated rather than
/// folded into an end of stream. That is what keeps a truncation, a
/// reset and a broken pipe out of the orderly-close variants.
async fn fill<S>(stream: &mut S, buffer: &mut [u8]) -> io::Result<FillOutcome>
where
    S: AsyncRead + Unpin,
{
    let mut received = 0;
    while received < buffer.len() {
        let read = stream.read(&mut buffer[received..]).await?;
        if read == 0 {
            return Ok(FillOutcome::EndOfStream { received });
        }
        received += read;
    }
    Ok(FillOutcome::Filled)
}

/// Reads exactly one response frame and the clean end of stream that has
/// to follow it.
///
/// Three outcomes decide the post-payload read, and only the first
/// completes the exchange: a clean end of stream, any byte at all, or an
/// `Err`. The payload is decoded only after the first of them, so a peer
/// cannot append a second frame — or anything else — behind a
/// well-formed one and still have the first honoured.
async fn read_response<S>(stream: &mut S) -> Result<Vec<u8>, ExchangeError>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; frame::RESPONSE_PREFIX_BYTES];
    match fill(stream, &mut prefix).await.map_err(read_failed)? {
        FillOutcome::Filled => {}
        FillOutcome::EndOfStream { received: 0 } => return Err(ExchangeError::EmptyResponse),
        FillOutcome::EndOfStream { received } => {
            return Err(ExchangeError::Truncated {
                expected: frame::RESPONSE_PREFIX_BYTES,
                received,
            });
        }
    }

    // The declared length is checked before a payload byte is read and
    // before anything is allocated for one, so the buffer never grows
    // past the bound.
    let declared = u32::from_be_bytes(prefix);
    let payload_length = match usize::try_from(declared) {
        Ok(length) if length <= MAX_DECLARED_PAYLOAD_BYTES => length,
        _ => {
            return Err(ExchangeError::ResponseTooLarge {
                declared,
                limit: MAX_DECLARED_PAYLOAD_BYTES,
            });
        }
    };

    let mut payload = vec![0_u8; payload_length];
    match fill(stream, &mut payload).await.map_err(read_failed)? {
        FillOutcome::Filled => {}
        FillOutcome::EndOfStream { received } => {
            return Err(ExchangeError::Truncated {
                expected: frame::RESPONSE_PREFIX_BYTES + payload_length,
                received: frame::RESPONSE_PREFIX_BYTES + received,
            });
        }
    }

    // One byte settles it, so the probe reads into a small fixed buffer
    // and neither drains nor buffers whatever else is pending. It does
    // not read a second frame in order to describe it.
    let mut probe = [0_u8; 1];
    match stream.read(&mut probe).await.map_err(read_failed)? {
        0 => Ok(payload),
        observed => Err(ExchangeError::TrailingBytes { observed }),
    }
}

/// Decides whether a response payload is a refusal.
///
/// The rule is about the *membership* of the top-level `class` member
/// and not about that member's value: `class` is required and
/// non-nullable on [`protocol::RefusalResponse`] and appears in neither
/// success shape, so a payload carrying it is a refusal — a malformed
/// one when its value is not a class, which the refusal decoder is left
/// to say.
///
/// The probe is written structurally rather than derived because both
/// obvious derived probes are wrong. A `#[serde(default)] class:
/// Option<T>` field deserializes an explicit `null` to `None`, making
/// `{"class": null, ...}` indistinguishable from a payload with no
/// `class` at all; a `#[serde(default)] class: IgnoredAny` field keeps no
/// presence bit beside a zero-sized value that accepts anything, so an
/// absent member and a present one produce the identical value. Asking
/// a parsed [`serde_json::Map`] for the key answers exactly the question
/// asked: it rejects a payload that is not a JSON object by itself, and
/// it counts `null` as the present member it is.
///
/// It matters because no response type sets `deny_unknown_fields`, so
/// the success decoders ignore a `class` member entirely — routing a
/// present-`class` payload to a success decoder would let a malformed
/// refusal decode as a success whenever it happened to carry the success
/// members too.
///
/// # Errors
///
/// Returns [`CodecError::Json`] when the payload is not a JSON object —
/// an array, a string, a number, a bare `null`, or bytes that are not
/// JSON. No protocol decoder runs for one.
fn is_refusal(payload: &[u8]) -> Result<bool, CodecError> {
    let members = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(payload)?;
    Ok(members.contains_key(REFUSAL_DISCRIMINATOR))
}

/// Wraps a codec failure, in either direction.
fn codec(source: CodecError) -> ExchangeError {
    ExchangeError::Codec { source }
}

/// Wraps an I/O failure that interrupted the request write.
fn write_failed(source: io::Error) -> ExchangeError {
    ExchangeError::Transport {
        phase: ExchangePhase::Request,
        source,
    }
}

/// Wraps an I/O failure that interrupted the response read.
fn read_failed(source: io::Error) -> ExchangeError {
    ExchangeError::Transport {
        phase: ExchangePhase::Response,
        source,
    }
}
