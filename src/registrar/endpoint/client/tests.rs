//! Tests for the registrar endpoint client.
//!
//! **None of these starts the endpoint's own listener.** Every property
//! this module owns is a property of the *caller*: what it presents at
//! the handshake, how many messages it puts on a connection, how much it
//! is willing to read, how long it is willing to wait, and how it
//! classifies what came back. All of it is observable against a **server
//! double** standing entirely inside this file — a `UnixListener` bound
//! to a socket in a `tempfile::tempdir()`, whose behaviour each case
//! chooses.
//!
//! Most cases run the double TLS-wrapped. Two must run it **raw**, with
//! no `TlsAcceptor` at all, because what they exercise happens below or
//! during the handshake and a completed handshake would make the case
//! untestable: the read-timeout case needs a peer that accepts and then
//! never completes a handshake, and the non-pin handshake case needs a
//! peer that answers the `ClientHello` with bytes that are not a TLS
//! record. Being raw is the point of each rather than a shortcut. The
//! connect-failure case has no listener at all, which is likewise the
//! point.
//!
//! The double is required regardless of convenience: the degenerate and
//! hostile behaviours this client's error taxonomy is defined against —
//! a stall, a clean bare close, an unclean disappearance, an oversized
//! frame, an unpinned or wrong-SAN certificate — are precisely the ones
//! the real listener will not produce.
//!
//! The whole file therefore runs under plain, unprivileged `cargo test`:
//! no root, no Docker, no `OpenBao`, no dispatcher and no real verb
//! execution. "Returns the mint success shape" means the double wrote
//! the encoded mint success response and the client handed it back
//! unchanged; nothing is minted and no privileged credential is reached.

use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::registrar::endpoint::test_support::{
    CapturedEvent, Pki, TestCa, capture_logs, dns_san, endpoint_name, issue_leaf, key_der,
    registrar_client_name, valid_ca, write_leaf_material,
};

/// The canned success and refusal payloads, taken from the golden
/// fixtures the protocol module already round-trips, so a case that
/// hand-writes a payload is only ever hand-writing the deviation it is
/// about.
const MINT_SUCCESS: &[u8] = include_bytes!("../fixtures/mint-success.json");
const DEREGISTER_SUCCESS: &[u8] = include_bytes!("../fixtures/deregister-success.json");
const REFUSAL_PERMANENT: &[u8] = include_bytes!("../fixtures/refusal-permanent.json");

/// Bytes that are not a TLS record, for the raw handshake-failure case.
const NOT_A_TLS_RECORD: &[u8] = b"this is not a TLS record, not even slightly\n";

/// A distinctive string a secret-leak assertion looks for. It appears in
/// no path, so finding it anywhere means it came from the material or
/// the payload it was planted in.
const SECRET_MARKER: &str = "z9Q-marker-that-must-never-be-logged";

// ---------------------------------------------------------------------
// The server double
// ---------------------------------------------------------------------

/// What the double writes once it has read one request frame.
#[derive(Clone)]
struct Reply {
    /// The exact bytes to write, response prefix included. Empty means
    /// the double answers with nothing at all.
    bytes: Vec<u8>,
    /// Whether the double ends the stream cleanly. Several cases below
    /// come in pairs that differ by exactly this flag, which is what
    /// pins the clean-versus-unclean rule to a test rather than to a
    /// comment.
    shutdown: bool,
}

/// A clean answer: these bytes, then `close_notify`.
fn answered(bytes: Vec<u8>) -> Reply {
    Reply {
        bytes,
        shutdown: true,
    }
}

/// These bytes, then a disappearance with no `close_notify`.
fn abandoned(bytes: Vec<u8>) -> Reply {
    Reply {
        bytes,
        shutdown: false,
    }
}

/// What the double does with each connection it accepts.
enum Script {
    /// Complete a TLS handshake, read one request frame, then reply.
    Tls { acceptor: TlsAcceptor, reply: Reply },
    /// No `TlsAcceptor` at all: accept and hold the connection open
    /// forever, completing no handshake and writing no bytes.
    RawStall,
    /// No `TlsAcceptor` at all: answer the `ClientHello` with bytes
    /// that are not a TLS record.
    RawGarbage,
}

/// Everything the double saw, which is what a case asserts the client
/// did.
#[derive(Debug, Clone, Default)]
struct Observed {
    /// Connections accepted, whether or not they handshook.
    connections: usize,
    /// Application bytes read across every connection. Zero is what
    /// "the double observes no request byte" means.
    request_bytes: usize,
    /// Complete request frames read, in order.
    requests: Vec<Vec<u8>>,
    /// DER of each connection's client leaf, in order.
    peer_leaves: Vec<Vec<u8>>,
    /// Application bytes that arrived *after* a connection's one
    /// request frame.
    trailing_request_bytes: usize,
    /// Whether a connection's stream ended after its one request frame.
    ended_after_one_request: bool,
    /// Handshakes the double itself could not complete.
    handshake_failures: usize,
}

/// A listener bound in a `tempfile::tempdir()` and driven by this
/// harness.
struct Double {
    observed: Arc<StdMutex<Observed>>,
    /// Connections the double has finished with. The client returns as
    /// soon as it has read its answer, which is before the double has
    /// seen the `close_notify` that follows, so anything asserted about
    /// how a connection *ended* waits on this rather than racing it.
    completed: watch::Receiver<usize>,
    task: JoinHandle<()>,
}

impl Drop for Double {
    fn drop(&mut self) {
        // The double outlives no test: whichever connection it is
        // parked on, the harness owns the handle and ends the task
        // here rather than leaving it detached.
        self.task.abort();
    }
}

impl Double {
    fn start(socket_path: &Path, script: Script) -> Self {
        let listener = UnixListener::bind(socket_path).expect("bind the double's socket");
        let observed = Arc::new(StdMutex::new(Observed::default()));
        let (progress, completed) = watch::channel(0);
        let task = tokio::spawn(run_double(
            listener,
            script,
            Arc::clone(&observed),
            progress,
        ));
        Self {
            observed,
            completed,
            task,
        }
    }

    fn observed(&self) -> Observed {
        self.observed
            .lock()
            .expect("the observation mutex is only held to record and read")
            .clone()
    }

    /// Waits until the double has finished with `count` connections.
    async fn settled(&self, count: usize) {
        let mut completed = self.completed.clone();
        while *completed.borrow_and_update() < count {
            completed
                .changed()
                .await
                .expect("the double outlives the assertion");
        }
    }
}

async fn run_double(
    listener: UnixListener,
    script: Script,
    observed: Arc<StdMutex<Observed>>,
    progress: watch::Sender<usize>,
) {
    // Held so a stalled peer stays a stalled peer: dropping the stream
    // would close it and turn the case into a disappearance.
    let mut stalled = Vec::new();
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        record(&observed, |seen| seen.connections += 1);
        match &script {
            Script::Tls { acceptor, reply } => {
                serve_tls(acceptor.clone(), stream, reply.clone(), &observed).await;
            }
            Script::RawStall => stalled.push(stream),
            Script::RawGarbage => serve_garbage(stream).await,
        }
        progress.send_modify(|finished| *finished += 1);
    }
}

async fn serve_tls(
    acceptor: TlsAcceptor,
    stream: UnixStream,
    reply: Reply,
    observed: &Arc<StdMutex<Observed>>,
) {
    let Ok(mut tls) = acceptor.accept(stream).await else {
        record(observed, |seen| seen.handshake_failures += 1);
        return;
    };
    let leaf = {
        let (_, session) = tls.get_ref();
        session
            .peer_certificates()
            .and_then(<[CertificateDer<'_>]>::first)
            .map(|leaf| leaf.as_ref().to_vec())
    };
    if let Some(leaf) = leaf {
        record(observed, |seen| seen.peer_leaves.push(leaf));
    }

    let Some(request) = read_request_frame(&mut tls, observed).await else {
        return;
    };
    record(observed, |seen| seen.requests.push(request));

    if !reply.bytes.is_empty() {
        if tls.write_all(&reply.bytes).await.is_err() {
            return;
        }
        if tls.flush().await.is_err() {
            return;
        }
    }
    if !reply.shutdown {
        // Dropping without `shutdown()` is the whole point of the
        // cases that ask for it: the client must see an
        // `UnexpectedEof` and not an orderly end.
        return;
    }
    let _ = tls.shutdown().await;

    // Whatever else the client had to say on this connection. A client
    // that honours one-request-per-connection says nothing.
    let mut extra = Vec::new();
    if tls.read_to_end(&mut extra).await.is_ok() {
        record(observed, |seen| {
            seen.trailing_request_bytes += extra.len();
            seen.ended_after_one_request = true;
        });
    }
}

async fn serve_garbage(mut stream: UnixStream) {
    let mut buffer = [0_u8; 512];
    let _ = stream.read(&mut buffer).await;
    let _ = stream.write_all(NOT_A_TLS_RECORD).await;
    let _ = stream.flush().await;
}

fn record(observed: &Arc<StdMutex<Observed>>, edit: impl FnOnce(&mut Observed)) {
    let mut seen = observed
        .lock()
        .expect("the observation mutex is only held to record and read");
    edit(&mut seen);
}

async fn read_request_frame<S>(
    stream: &mut S,
    observed: &Arc<StdMutex<Observed>>,
) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut prefix = [0_u8; frame::REQUEST_PREFIX_BYTES];
    read_exactly(stream, &mut prefix, observed).await?;
    let payload_length = usize::try_from(frame::declared_payload_length(prefix)).ok()?;
    let name_length = usize::from(frame::declared_name_length(prefix));
    let mut rest = vec![0_u8; name_length + payload_length];
    read_exactly(stream, &mut rest, observed).await?;
    let mut whole = prefix.to_vec();
    whole.extend_from_slice(&rest);
    Some(whole)
}

async fn read_exactly<S>(
    stream: &mut S,
    buffer: &mut [u8],
    observed: &Arc<StdMutex<Observed>>,
) -> Option<()>
where
    S: AsyncRead + Unpin,
{
    let mut received = 0;
    while received < buffer.len() {
        let read = stream.read(&mut buffer[received..]).await.ok()?;
        if read == 0 {
            return None;
        }
        received += read;
        record(observed, |seen| seen.request_bytes += read);
    }
    Some(())
}

// ---------------------------------------------------------------------
// The deployment every case is built from
// ---------------------------------------------------------------------

/// One CA, one pin file, one registrar client pair on disk, and a socket
/// path — all under one `tempfile::tempdir()`.
struct Deployment {
    pki: Pki,
    certificate_path: PathBuf,
    key_path: PathBuf,
}

impl Deployment {
    fn new() -> Self {
        crate::tls::install_crypto_provider();
        let pki = Pki::new();
        let certificate_path = pki.path("registrar-client.crt");
        let key_path = pki.path("registrar-client.key");
        write_leaf_material(
            &pki.ca,
            vec![dns_san(&registrar_client_name())],
            &certificate_path,
            &key_path,
            true,
        );
        Self {
            pki,
            certificate_path,
            key_path,
        }
    }

    fn socket_path(&self) -> PathBuf {
        self.pki.path("registrar.sock")
    }

    /// A client wired to this deployment, constructed from paths under
    /// the temporary directory and from nothing else.
    fn client(&self) -> RegistrarEndpointClient {
        RegistrarEndpointClient::new(
            self.socket_path(),
            self.pki.pin_file_path(),
            &self.certificate_path,
            &self.key_path,
            endpoint_name(),
        )
    }

    /// An acceptor presenting a leaf carrying `san`, issued by `issuer`
    /// and chained to it, and requiring a client certificate this
    /// deployment's CA issued.
    fn acceptor(&self, issuer: &TestCa, san: &str) -> TlsAcceptor {
        let (certificate, key) = issue_leaf(issuer, vec![dns_san(san)]);
        let chain = vec![
            CertificateDer::from(certificate.der().to_vec()),
            CertificateDer::from(issuer.der().to_vec()),
        ];
        let mut roots = RootCertStore::empty();
        roots
            .add(CertificateDer::from(self.pki.ca.der().to_vec()))
            .expect("the deployment CA is a usable anchor");
        let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
            .build()
            .expect("a client verifier over the deployment CA");
        let config = ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key_der(&key))
            .expect("the double's own server material");
        TlsAcceptor::from(Arc::new(config))
    }

    /// The conforming double: the pinned CA, the expected endpoint SAN.
    fn double(&self, reply: Reply) -> Double {
        self.double_presenting(&self.pki.ca, &endpoint_name(), reply)
    }

    fn double_presenting(&self, issuer: &TestCa, san: &str, reply: Reply) -> Double {
        Double::start(
            &self.socket_path(),
            Script::Tls {
                acceptor: self.acceptor(issuer, san),
                reply,
            },
        )
    }

    fn raw_double(&self, script: Script) -> Double {
        Double::start(&self.socket_path(), script)
    }
}

// ---------------------------------------------------------------------
// Payload and frame helpers
// ---------------------------------------------------------------------

fn response_frame(payload: &[u8]) -> Vec<u8> {
    let length = u32::try_from(payload.len()).expect("a test payload shorter than 4 GiB");
    let mut frame = length.to_be_bytes().to_vec();
    frame.extend_from_slice(payload);
    frame
}

/// A response prefix declaring `declared` bytes and nothing behind it.
fn response_prefix(declared: u32) -> Vec<u8> {
    declared.to_be_bytes().to_vec()
}

/// A fixture payload with one edit applied, so a case hand-writes only
/// the deviation it is about.
fn payload_with(
    base: &[u8],
    edit: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> Vec<u8> {
    let mut members = serde_json::from_slice::<serde_json::Map<String, serde_json::Value>>(base)
        .expect("every fixture is a JSON object");
    edit(&mut members);
    serde_json::to_vec(&members).expect("a JSON object re-encodes")
}

fn register_request() -> protocol::RegisterRequest {
    protocol::RegisterRequest {
        protocol_version: protocol::ProtocolVersion::current(),
        service_name: "api".to_string(),
        delivery_mode: protocol::WireDeliveryMode::RemoteBootstrap,
        host: "node".to_string(),
        instance: Some(7),
        spec: protocol::WireServiceSpec {
            component: "api".to_string(),
            service_name: "api".to_string(),
            reload: "opaque reload".to_string(),
            cert_group: None,
        },
        wrap_ttl: 60,
        idempotency_key: "opaque-key".to_string(),
    }
}

fn deregister_request() -> protocol::DeregisterRequest {
    protocol::DeregisterRequest {
        protocol_version: protocol::ProtocolVersion::current(),
        service_name: "api".to_string(),
        host: "node".to_string(),
        instance: Some(7),
        idempotency_key: "opaque-key".to_string(),
    }
}

fn mint_success(reply: MintReply) -> protocol::MintResponse {
    match reply {
        MintReply::Success(response) => response,
        MintReply::Refused(refusal) => panic!("expected the success arm, saw {refusal:?}"),
    }
}

fn mint_refusal(reply: MintReply) -> protocol::RefusalResponse {
    match reply {
        MintReply::Refused(refusal) => refusal,
        MintReply::Success(response) => panic!("expected the refusal arm, saw {response:?}"),
    }
}

/// The `rustls::Error` `tokio_rustls` wrapped in an `io::Error`, which
/// is what selects between the two handshake variants.
fn recovered(err: &io::Error) -> Option<&rustls::Error> {
    err.get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
}

// ---------------------------------------------------------------------
// Round trip
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_mint_returns_the_success_shape_the_double_encoded() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(MINT_SUCCESS)));

    let reply = deployment
        .client()
        .mint(register_request())
        .await
        .expect("the exchange completes");

    let response = mint_success(reply);
    assert_eq!(response.request_id, "request-0001");
    assert_eq!(response.registration_id, "registration-1");
    assert_eq!(response.outcome, protocol::MintWireOutcome::FirstMint);
    assert_eq!(response.material.role_id, "role-id");

    let seen = double.observed();
    assert_eq!(seen.connections, 1);
    assert_eq!(seen.requests.len(), 1);
}

#[tokio::test]
async fn a_deregister_returns_the_success_shape_the_double_encoded() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(DEREGISTER_SUCCESS)));

    let reply = deployment
        .client()
        .deregister(deregister_request())
        .await
        .expect("the exchange completes");

    let response = match reply {
        DeregisterReply::Success(response) => response,
        DeregisterReply::Refused(refusal) => panic!("expected the success arm, saw {refusal:?}"),
    };
    assert_eq!(response.request_id, "request-0001");
    assert_eq!(
        response.outcome,
        protocol::DeregisterWireOutcome::AlreadyAbsent
    );
    assert_eq!(double.observed().requests.len(), 1);
}

#[tokio::test]
async fn exactly_one_request_and_one_response_cross_a_connection() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(MINT_SUCCESS)));

    deployment
        .client()
        .mint(register_request())
        .await
        .expect("the exchange completes");

    double.settled(1).await;
    let seen = double.observed();
    assert_eq!(seen.connections, 1, "the client dialed more than once");
    assert_eq!(seen.requests.len(), 1, "the client wrote a second request");
    assert_eq!(
        seen.trailing_request_bytes, 0,
        "the client wrote something after its one request"
    );
    assert!(
        seen.ended_after_one_request,
        "the client left the connection open after the exchange"
    );

    // The one frame the double read is exactly the one the envelope
    // writer composes for this request.
    let payload = protocol::encode_request(&protocol::Request::Register(register_request()))
        .expect("the request encodes");
    let expected =
        frame::encode_request_frame(Operation::Mint, &payload).expect("the request frames");
    assert_eq!(seen.requests.first(), Some(&expected));
}

// ---------------------------------------------------------------------
// Everything that fails before a byte reaches the socket
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_missing_client_certificate_fails_before_the_dial() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(MINT_SUCCESS)));
    let client = RegistrarEndpointClient::new(
        deployment.socket_path(),
        deployment.pki.pin_file_path(),
        deployment.pki.path("absent.crt"),
        &deployment.key_path,
        endpoint_name(),
    );

    let err = client
        .mint(register_request())
        .await
        .expect_err("a certificate that is not there cannot be presented");

    assert!(
        matches!(
            err,
            ExchangeError::Material {
                source: ClientMaterialError::MissingCertificate { .. }
            }
        ),
        "{err:?}"
    );
    assert_eq!(double.observed().connections, 0);
}

#[tokio::test]
async fn a_missing_client_key_fails_before_the_dial() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(MINT_SUCCESS)));
    let client = RegistrarEndpointClient::new(
        deployment.socket_path(),
        deployment.pki.pin_file_path(),
        &deployment.certificate_path,
        deployment.pki.path("absent.key"),
        endpoint_name(),
    );

    let err = client
        .mint(register_request())
        .await
        .expect_err("a key that is not there cannot sign");

    assert!(
        matches!(
            err,
            ExchangeError::Material {
                source: ClientMaterialError::MissingKey { .. }
            }
        ),
        "{err:?}"
    );
    assert_eq!(double.observed().connections, 0);
}

#[tokio::test]
async fn a_certificate_that_is_not_pem_fails_before_the_dial() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(MINT_SUCCESS)));
    std::fs::write(&deployment.certificate_path, b"these bytes are not PEM\n")
        .expect("write the malformed certificate");

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("bytes that are not PEM carry no certificate");

    assert!(
        matches!(
            err,
            ExchangeError::Material {
                source: ClientMaterialError::NoCertificate { .. }
            }
        ),
        "{err:?}"
    );
    assert_eq!(double.observed().connections, 0);
}

#[tokio::test]
async fn a_key_that_is_not_a_private_key_fails_before_the_dial() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(MINT_SUCCESS)));
    std::fs::write(&deployment.key_path, b"these bytes are not a private key\n")
        .expect("write the malformed key");

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("bytes that are not PEM carry no key");

    assert!(
        matches!(
            err,
            ExchangeError::Material {
                source: ClientMaterialError::NoPrivateKey { .. }
            }
        ),
        "{err:?}"
    );
    assert_eq!(double.observed().connections, 0);
}

#[tokio::test]
async fn a_pem_key_rustls_will_not_load_fails_before_the_dial() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(MINT_SUCCESS)));
    // Well-formed PEM framing around base64 that is not a key: the
    // parse succeeds and `rustls` refuses the result.
    std::fs::write(
        &deployment.key_path,
        "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5IGF0IGFsbA==\n-----END PRIVATE KEY-----\n",
    )
    .expect("write the unusable key");

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("rustls refuses a key it cannot load");

    assert!(
        matches!(
            err,
            ExchangeError::Material {
                source: ClientMaterialError::Unusable { .. }
            }
        ),
        "{err:?}"
    );
    assert_eq!(double.observed().connections, 0);
}

#[tokio::test]
async fn a_request_over_the_frame_bound_is_refused_locally() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(MINT_SUCCESS)));
    let mut request = register_request();
    request.idempotency_key = "k".repeat(endpoint::MAX_FRAME_PAYLOAD_BYTES + 1);

    let err = deployment
        .client()
        .mint(request)
        .await
        .expect_err("the envelope will not carry it");

    let ExchangeError::RequestTooLarge { source } = err else {
        panic!("expected the local frame refusal, saw {err:?}");
    };
    assert_eq!(source.limit, endpoint::MAX_FRAME_PAYLOAD_BYTES);
    assert!(source.length > endpoint::MAX_FRAME_PAYLOAD_BYTES);
    assert_eq!(
        double.observed().connections,
        0,
        "the client dialed for a request it had already refused"
    );
}

#[tokio::test]
async fn a_missing_pin_file_is_a_typed_refusal() {
    let deployment = Deployment::new();
    let client = RegistrarEndpointClient::new(
        deployment.socket_path(),
        deployment.pki.path("absent-pins.sha256"),
        &deployment.certificate_path,
        &deployment.key_path,
        endpoint_name(),
    );

    let err = client
        .mint(register_request())
        .await
        .expect_err("there is no trust decision to make");

    assert!(
        matches!(
            err,
            ExchangeError::Pin {
                source: EndpointPinError::Missing { .. }
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_malformed_pin_file_is_a_typed_refusal() {
    let deployment = Deployment::new();
    let pin_file = deployment.pki.path("malformed-pins.sha256");
    std::fs::write(&pin_file, "not-a-digest\n").expect("write the malformed pin file");
    let client = RegistrarEndpointClient::new(
        deployment.socket_path(),
        pin_file,
        &deployment.certificate_path,
        &deployment.key_path,
        endpoint_name(),
    );

    let err = client
        .mint(register_request())
        .await
        .expect_err("a malformed pin file is not partially accepted");

    assert!(
        matches!(
            err,
            ExchangeError::Pin {
                source: EndpointPinError::Content { .. }
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn an_expected_name_that_is_not_a_dns_name_is_a_typed_refusal() {
    let deployment = Deployment::new();
    let client = RegistrarEndpointClient::new(
        deployment.socket_path(),
        deployment.pki.pin_file_path(),
        &deployment.certificate_path,
        &deployment.key_path,
        "not a dns name",
    );

    let err = client
        .mint(register_request())
        .await
        .expect_err("there is no name to pin against");

    assert!(
        matches!(
            err,
            ExchangeError::Pin {
                source: EndpointPinError::InvalidEndpointName { .. }
            }
        ),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------
// Connect and handshake
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_socket_nothing_listens_on_produces_the_connect_variant() {
    let deployment = Deployment::new();
    let started = tokio::time::Instant::now();

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("nothing is listening");

    assert!(matches!(err, ExchangeError::Connect { .. }), "{err:?}");
    assert!(
        started.elapsed() < CONNECT_TIMEOUT,
        "a refused connect must not wait out the connect timeout"
    );
}

#[tokio::test(start_paused = true)]
async fn the_connect_timeout_wraps_the_dial() {
    // A stalled `AF_UNIX` `connect(2)` is not portably constructible: a
    // missing path fails immediately with `ENOENT`, and a live
    // listener's backlog cannot be filled deterministically across
    // Linux and macOS. The wrapper itself is what this asserts, driven
    // over a future that never resolves.
    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("registrar.sock");
    let started = tokio::time::Instant::now();

    let err = connect_within(
        &socket,
        std::future::pending::<io::Result<UnixStream>>(),
        CONNECT_TIMEOUT,
    )
    .await
    .expect_err("a dial that never resolves must elapse");

    let ExchangeError::ConnectTimeout { timeout, .. } = err else {
        panic!("expected the connect timeout, saw {err:?}");
    };
    assert_eq!(timeout, CONNECT_TIMEOUT);
    assert!(started.elapsed() >= CONNECT_TIMEOUT);
}

#[tokio::test]
async fn a_server_chaining_to_an_unpinned_anchor_is_refused_by_the_pin() {
    let deployment = Deployment::new();
    let stranger = valid_ca();
    let double = deployment.double_presenting(
        &stranger,
        &endpoint_name(),
        answered(response_frame(MINT_SUCCESS)),
    );

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("the anchor is not pinned");

    let ExchangeError::PinRefused {
        expected_name,
        source,
    } = err
    else {
        panic!("expected the pin refusal, saw {err:?}");
    };
    assert_eq!(expected_name, endpoint_name());
    assert!(
        matches!(source, rustls::Error::InvalidCertificate(_)),
        "{source:?}"
    );
    assert_eq!(
        double.observed().request_bytes,
        0,
        "a request byte was written to an unpinned server"
    );
}

#[tokio::test]
async fn a_server_carrying_the_wrong_san_is_refused_by_the_pin() {
    let deployment = Deployment::new();
    let double = deployment.double_presenting(
        &deployment.pki.ca,
        "somewhere.else.example.internal",
        answered(response_frame(MINT_SUCCESS)),
    );

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("the SAN is not the expected one");

    let ExchangeError::PinRefused {
        expected_name,
        source,
    } = err
    else {
        panic!("expected the pin refusal, saw {err:?}");
    };
    assert_eq!(
        expected_name,
        endpoint_name(),
        "the variant names the expected SAN, which the client owns"
    );
    assert!(
        matches!(source, rustls::Error::InvalidCertificate(_)),
        "{source:?}"
    );
    assert_eq!(
        double.observed().request_bytes,
        0,
        "a request byte was written to a server carrying the wrong name"
    );
}

#[tokio::test]
async fn bytes_that_are_not_a_tls_record_produce_the_generic_handshake_variant() {
    let deployment = Deployment::new();
    let _double = deployment.raw_double(Script::RawGarbage);

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("the peer does not speak TLS");

    let ExchangeError::Handshake { source } = err else {
        panic!("expected the generic handshake failure, saw {err:?}");
    };
    // The two handshake variants are selected by the recovery, not by
    // which test wrote them.
    assert!(
        !matches!(
            recovered(&source),
            Some(rustls::Error::InvalidCertificate(_))
        ),
        "{source:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_peer_that_completes_no_handshake_elapses_the_read_timeout() {
    let deployment = Deployment::new();
    let _double = deployment.raw_double(Script::RawStall);
    let started = tokio::time::Instant::now();

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("a stalled peer answers nothing");

    let ExchangeError::ReadTimeout { timeout } = err else {
        panic!("expected the read timeout, saw {err:?}");
    };
    assert_eq!(timeout, READ_TIMEOUT);
    assert!(
        started.elapsed() >= READ_TIMEOUT,
        "the connect timeout fired instead of the read timeout"
    );
}

// ---------------------------------------------------------------------
// Reading the response
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_clean_close_after_zero_bytes_has_its_own_variant() {
    let deployment = Deployment::new();
    let _double = deployment.double(answered(Vec::new()));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("a bare close is not an answer");

    assert!(matches!(err, ExchangeError::EmptyResponse), "{err:?}");
}

#[tokio::test]
async fn a_disappearance_before_the_prefix_is_a_transport_failure() {
    let deployment = Deployment::new();
    // The same double as above, minus one `shutdown()`.
    let _double = deployment.double(abandoned(Vec::new()));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("a peer that vanished answered nothing");

    let ExchangeError::Transport { phase, source } = err else {
        panic!("expected the transport variant, saw {err:?}");
    };
    assert_eq!(phase, ExchangePhase::Response);
    assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn a_short_prefix_before_a_clean_close_is_a_truncation() {
    let deployment = Deployment::new();
    let _double = deployment.double(answered(vec![0x00, 0x00]));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("two bytes are not a response prefix");

    let ExchangeError::Truncated { expected, received } = err else {
        panic!("expected the truncation variant, saw {err:?}");
    };
    assert_eq!(expected, frame::RESPONSE_PREFIX_BYTES);
    assert_eq!(received, 2);
}

#[tokio::test]
async fn a_short_payload_before_a_clean_close_is_a_truncation() {
    let deployment = Deployment::new();
    let mut truncated = response_prefix(64);
    truncated.extend_from_slice(&[b'x'; 10]);
    let _double = deployment.double(answered(truncated));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("ten bytes are not sixty-four");

    let ExchangeError::Truncated { expected, received } = err else {
        panic!("expected the truncation variant, saw {err:?}");
    };
    assert_eq!(expected, frame::RESPONSE_PREFIX_BYTES + 64);
    assert_eq!(received, frame::RESPONSE_PREFIX_BYTES + 10);
}

#[tokio::test]
async fn a_disappearance_mid_payload_is_a_transport_failure() {
    let deployment = Deployment::new();
    let mut truncated = response_prefix(64);
    truncated.extend_from_slice(&[b'x'; 10]);
    // The same double as above, minus one `shutdown()`.
    let _double = deployment.double(abandoned(truncated));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("a peer that vanished mid-payload answered nothing");

    let ExchangeError::Transport { phase, source } = err else {
        panic!("expected the transport variant, saw {err:?}");
    };
    assert_eq!(phase, ExchangePhase::Response);
    assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn a_complete_response_behind_an_unclean_close_is_a_transport_failure() {
    let deployment = Deployment::new();
    // The round-trip double, minus one `shutdown()`. A complete payload
    // does not exempt a connection from the clean-close rule.
    let _double = deployment.double(abandoned(response_frame(MINT_SUCCESS)));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("the connection did not end cleanly");

    let ExchangeError::Transport { phase, source } = err else {
        panic!("expected the transport variant, saw {err:?}");
    };
    assert_eq!(phase, ExchangePhase::Response);
    assert_eq!(source.kind(), io::ErrorKind::UnexpectedEof);
}

#[tokio::test]
async fn a_stray_byte_after_a_complete_response_is_refused() {
    let deployment = Deployment::new();
    let mut answer = response_frame(MINT_SUCCESS);
    answer.push(b'!');
    let _double = deployment.double(answered(answer));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("the first frame is not honoured behind trailing bytes");

    assert!(
        matches!(err, ExchangeError::TrailingBytes { observed: 1 }),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_second_frame_after_a_complete_response_is_refused() {
    let deployment = Deployment::new();
    let mut answer = response_frame(MINT_SUCCESS);
    answer.extend_from_slice(&response_frame(DEREGISTER_SUCCESS));
    let _double = deployment.double(answered(answer));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("a second frame cannot ride behind the first");

    assert!(
        matches!(err, ExchangeError::TrailingBytes { .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn a_response_declaring_more_than_the_bound_is_refused_before_the_payload() {
    let deployment = Deployment::new();
    let over = u32::try_from(MAX_DECLARED_PAYLOAD_BYTES + 1).expect("the bound fits a u32");
    // Nothing but the prefix is ever written, so a client that read the
    // payload before checking the declaration would hang instead.
    let _double = deployment.double(answered(response_prefix(over)));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("the declaration is over the bound");

    let ExchangeError::ResponseTooLarge { declared, limit } = err else {
        panic!("expected the oversize variant, saw {err:?}");
    };
    assert_eq!(declared, over);
    assert_eq!(limit, MAX_DECLARED_PAYLOAD_BYTES);
    assert_eq!(
        MAX_RESPONSE_BYTES,
        frame::RESPONSE_PREFIX_BYTES + endpoint::MAX_RESPONSE_PAYLOAD_BYTES,
        "the client's bound is the endpoint's, not a literal of its own"
    );
}

// ---------------------------------------------------------------------
// Discrimination and decoding
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_refusal_is_a_successful_exchange() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(REFUSAL_PERMANENT)));

    let reply = deployment
        .client()
        .mint(register_request())
        .await
        .expect("a refusal is not an exchange failure");

    let refusal = mint_refusal(reply);
    assert_eq!(refusal.class, protocol::RefusalClass::Permanent);
    assert_eq!(
        refusal.error,
        Some(protocol::EnrollError::ServiceHostMismatch)
    );
    assert_eq!(
        double.observed().connections,
        1,
        "the client retried a refusal"
    );
}

#[tokio::test]
async fn a_deregister_refusal_is_a_successful_exchange() {
    // The discrimination is written once per verb, so the deregister
    // arm gets its own refusal case rather than resting on the mint
    // one having exercised the shared rule.
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(REFUSAL_PERMANENT)));

    let reply = deployment
        .client()
        .deregister(deregister_request())
        .await
        .expect("a refusal is not an exchange failure");

    let refusal = match reply {
        DeregisterReply::Refused(refusal) => refusal,
        DeregisterReply::Success(response) => panic!("expected the refusal arm, saw {response:?}"),
    };
    assert_eq!(refusal.class, protocol::RefusalClass::Permanent);
    assert_eq!(
        refusal.error,
        Some(protocol::EnrollError::ServiceHostMismatch)
    );
    assert_eq!(
        double.observed().connections,
        1,
        "the client retried a refusal"
    );
}

#[tokio::test]
async fn a_success_payload_is_not_misdecoded_as_a_refusal() {
    let deployment = Deployment::new();
    let _double = deployment.double(answered(response_frame(DEREGISTER_SUCCESS)));

    let reply = deployment
        .client()
        .deregister(deregister_request())
        .await
        .expect("the exchange completes");

    assert!(matches!(reply, DeregisterReply::Success(_)), "{reply:?}");
}

#[tokio::test]
async fn a_success_payload_missing_a_required_member_names_the_success_shape() {
    let deployment = Deployment::new();
    let payload = payload_with(MINT_SUCCESS, |members| {
        members.remove("registration_id");
    });
    let _double = deployment.double(answered(response_frame(&payload)));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("the success shape requires registration_id");

    let ExchangeError::Codec { source } = err else {
        panic!("expected the decode variant, saw {err:?}");
    };
    assert!(matches!(source, CodecError::Json(_)), "{source:?}");
    assert!(
        source.to_string().contains("registration_id"),
        "the failure must name the one shape it tried: {source}"
    );
}

#[tokio::test]
async fn a_refusal_whose_class_contradicts_its_error_is_a_decode_failure() {
    let deployment = Deployment::new();
    let payload = payload_with(REFUSAL_PERMANENT, |members| {
        members.insert(
            "class".to_string(),
            serde_json::Value::String("retryable".to_string()),
        );
    });
    let _double = deployment.double(answered(response_frame(&payload)));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("retryable does not match ServiceSpecConflict's family");

    let ExchangeError::Codec { source } = err else {
        panic!("expected the decode variant, saw {err:?}");
    };
    assert!(
        matches!(source, CodecError::InvalidRefusalClass(_)),
        "{source:?}"
    );
}

#[tokio::test]
async fn a_null_class_beside_every_success_member_is_a_malformed_refusal() {
    let deployment = Deployment::new();
    // Every member `MintResponse` requires, plus a `class` that is not
    // a class. A discrimination that looked at the value instead of the
    // key would hand this to the success decoder and return it.
    let payload = payload_with(MINT_SUCCESS, |members| {
        members.insert("class".to_string(), serde_json::Value::Null);
    });
    let _double = deployment.double(answered(response_frame(&payload)));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("a present class member is a refusal, whatever its value");

    let ExchangeError::Codec { source } = err else {
        panic!("expected the decode variant, saw {err:?}");
    };
    assert!(matches!(source, CodecError::Json(_)), "{source:?}");
}

#[tokio::test]
async fn a_numeric_class_is_a_malformed_refusal() {
    let deployment = Deployment::new();
    let payload = payload_with(MINT_SUCCESS, |members| {
        members.insert("class".to_string(), serde_json::Value::from(7));
    });
    let _double = deployment.double(answered(response_frame(&payload)));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("a present class member is a refusal, whatever its value");

    assert!(matches!(err, ExchangeError::Codec { .. }), "{err:?}");
}

#[tokio::test]
async fn a_json_array_payload_runs_no_protocol_decoder() {
    let deployment = Deployment::new();
    let _double = deployment.double(answered(response_frame(b"[1, 2, 3]")));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("an array is not a response shape");

    let ExchangeError::Codec { source } = err else {
        panic!("expected the decode variant, saw {err:?}");
    };
    assert!(matches!(source, CodecError::Json(_)), "{source:?}");
}

#[tokio::test]
async fn a_payload_that_is_not_json_runs_no_protocol_decoder() {
    let deployment = Deployment::new();
    let _double = deployment.double(answered(response_frame(b"not json at all")));

    let err = deployment
        .client()
        .mint(register_request())
        .await
        .expect_err("these bytes are not JSON");

    let ExchangeError::Codec { source } = err else {
        panic!("expected the decode variant, saw {err:?}");
    };
    assert!(matches!(source, CodecError::Json(_)), "{source:?}");
}

#[test]
fn the_discriminator_reads_the_key_and_not_its_value() {
    assert!(!is_refusal(MINT_SUCCESS).expect("the fixture is a JSON object"));
    assert!(!is_refusal(DEREGISTER_SUCCESS).expect("the fixture is a JSON object"));
    assert!(is_refusal(REFUSAL_PERMANENT).expect("the fixture is a JSON object"));
    assert!(is_refusal(br#"{"class": null}"#).expect("an object with a null member"));
    assert!(is_refusal(br#"{"class": 7}"#).expect("an object with a numeric member"));
    assert!(is_refusal(br"{}").is_ok_and(|refusal| !refusal));
    assert!(is_refusal(b"[]").is_err());
    assert!(is_refusal(b"null").is_err());
    assert!(is_refusal(b"\"class\"").is_err());
}

// ---------------------------------------------------------------------
// The per-dial load seam
// ---------------------------------------------------------------------

#[tokio::test]
async fn a_second_dial_re_reads_the_client_material() {
    let deployment = Deployment::new();
    let double = deployment.double(answered(response_frame(MINT_SUCCESS)));
    let client = deployment.client();

    client
        .mint(register_request())
        .await
        .expect("the first exchange completes");

    let replacement = write_leaf_material(
        &deployment.pki.ca,
        vec![dns_san(&registrar_client_name())],
        &deployment.certificate_path,
        &deployment.key_path,
        true,
    );

    client
        .mint(register_request())
        .await
        .expect("the second exchange completes");

    double.settled(2).await;
    let seen = double.observed();
    assert_eq!(seen.connections, 2);
    assert_eq!(seen.peer_leaves.len(), 2);
    assert_ne!(
        seen.peer_leaves.first(),
        seen.peer_leaves.get(1),
        "the second dial presented the first dial's cached leaf"
    );
    assert_eq!(
        seen.peer_leaves.get(1),
        Some(&replacement),
        "the second dial did not present what is on disk"
    );
}

// ---------------------------------------------------------------------
// The one variant with no portable test
// ---------------------------------------------------------------------

#[test]
fn the_two_transport_phases_are_distinguishable() {
    // The write phase has no portable test and does not get a fake one.
    // Forcing a real `EPIPE` on the request write means filling the
    // peer's `AF_UNIX` send buffer, whose size differs between Linux
    // and macOS; a double that drops before reading absorbs a small
    // frame into that buffer and fails the *read* instead, exactly as
    // the two disappearance cases above do. What a caller needs from
    // the phase is that the two are distinguishable, and that is
    // asserted here.
    let writing = ExchangeError::Transport {
        phase: ExchangePhase::Request,
        source: io::Error::from(io::ErrorKind::BrokenPipe),
    };
    let reading = ExchangeError::Transport {
        phase: ExchangePhase::Response,
        source: io::Error::from(io::ErrorKind::UnexpectedEof),
    };
    let (
        ExchangeError::Transport { phase: written, .. },
        ExchangeError::Transport { phase: read, .. },
    ) = (&writing, &reading)
    else {
        panic!("both are transport failures");
    };
    assert_ne!(written, read);
    assert_eq!(written.to_string(), "writing the request");
    assert_eq!(read.to_string(), "reading the response");
    assert_ne!(writing.to_string(), reading.to_string());
}

// ---------------------------------------------------------------------
// Nothing secret is logged or rendered
// ---------------------------------------------------------------------

/// Runs `attempt` under a capturing subscriber until it has emitted at
/// least one event, and hands back the last attempt's outcome together
/// with everything captured.
///
/// The retry is the price of `tracing`'s global callsite cache rather
/// than a way of hiding a flake. A callsite's interest is cached
/// process-wide and computed once, the first time any thread reaches it:
/// a sibling test reaching one of the client's log lines first computes
/// it against *its* thread's no-op subscriber and stores
/// `Interest::never()`, which can land after this subscriber's own
/// registration established otherwise. That first registration happens
/// exactly once, so rebuilding the cache with this subscriber live and
/// running again settles it for good. A capture still empty after every
/// attempt fails the test rather than passing vacuously.
async fn captured<T, Fut>(mut attempt: impl FnMut() -> Fut) -> (T, Vec<CapturedEvent>)
where
    Fut: Future<Output = T>,
{
    const ATTEMPTS: usize = 8;

    let (logs, _guard) = capture_logs();
    let mut outcome = attempt().await;
    for _ in 1..ATTEMPTS {
        if !logs.events().is_empty() {
            break;
        }
        tracing::callsite::rebuild_interest_cache();
        outcome = attempt().await;
    }
    let events = logs.events();
    assert!(
        !events.is_empty(),
        "the client emitted nothing to check in {ATTEMPTS} attempts"
    );
    (outcome, events)
}

fn marker_free(events: &[CapturedEvent]) {
    for event in events {
        assert!(
            !format!("{event:?}").contains(SECRET_MARKER),
            "a captured event carried the marker: {event:?}"
        );
    }
}

#[tokio::test]
async fn a_key_load_failure_logs_and_renders_no_key_byte() {
    let deployment = Deployment::new();
    let _double = deployment.double(answered(response_frame(MINT_SUCCESS)));
    // The raw file bytes are in hand on this path and a `source` error
    // is the easiest thing to interpolate, which is why it is the one
    // the marker is planted on.
    std::fs::write(
        &deployment.key_path,
        format!("-----BEGIN NOTHING-----\n{SECRET_MARKER}\n"),
    )
    .expect("write the marked key");
    let client = deployment.client();

    let (outcome, events) = captured(|| client.mint(register_request())).await;

    let err = outcome.expect_err("the marked bytes are not a private key");
    assert!(matches!(err, ExchangeError::Material { .. }), "{err:?}");
    assert!(
        !err.to_string().contains(SECRET_MARKER),
        "Display leaked the marker: {err}"
    );
    assert!(
        !format!("{err:?}").contains(SECRET_MARKER),
        "Debug leaked the marker: {err:?}"
    );
    marker_free(&events);
}

#[tokio::test]
async fn a_successful_exchange_logs_no_response_payload() {
    let deployment = Deployment::new();
    let payload = payload_with(MINT_SUCCESS, |members| {
        let material = members
            .get_mut("material")
            .and_then(serde_json::Value::as_object_mut)
            .expect("the fixture carries material");
        material.insert(
            "wrapped_secret_id".to_string(),
            serde_json::Value::String(SECRET_MARKER.to_string()),
        );
    });
    let _double = deployment.double(answered(response_frame(&payload)));
    let client = deployment.client();

    let (outcome, events) = captured(|| client.mint(register_request())).await;

    let reply = outcome.expect("the exchange completes");
    assert!(matches!(reply, MintReply::Success(_)));
    assert!(
        !format!("{reply:?}").contains(SECRET_MARKER),
        "the response Debug leaked the wrapped secret id"
    );
    marker_free(&events);
}
