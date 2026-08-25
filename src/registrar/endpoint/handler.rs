//! The seam between the transport and whatever answers a request.
//!
//! The endpoint owns the socket, the envelope, the peer check and the
//! refusal path. It does not own the payload: the versioned request and
//! response schemas, their codec, their field names and the mapping of
//! verb outcomes onto caller-visible responses belong to the registrar
//! protocol module. This trait is the whole of the contract between the
//! endpoint and a production handler that consumes that protocol.
//!
//! What crosses it is deliberately narrow. The handler receives the
//! *checked* operation as an enum, the payload as opaque bytes, and the
//! caller identity the transport authenticated. It cannot influence the
//! transport in return: not the identity, not the connection diagnostic
//! id, not the refusal taxonomy. Its only two answers are opaque
//! response bytes and [`HandlerRefusal`].

use std::future::Future;
use std::pin::Pin;

use super::frame::Operation;
use crate::registrar::verbs::outcome::CallerIdentity;

/// A handler's refusal of the payload bytes it was given.
///
/// A distinct, zero-data marker, and deliberately not an eighth
/// transport reason. The transport taxonomy is closed at seven because
/// each of those reasons is something *the transport* observed about the
/// frame; a payload a production codec cannot decode is something the
/// layer above observed about bytes the transport was right to deliver.
/// Carrying no data is the point: whatever the handler knows about why
/// it refused is the handler's to log, and none of it belongs on a wire
/// this endpoint answers with a clean close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HandlerRefusal;

/// The diagnostic cause a [`HandlerRefusal`] is logged under, fixed so
/// no handler can vary it.
pub(crate) const HANDLER_REJECTED_PAYLOAD: &str = "handler rejected the payload before a verb ran";

/// What the endpoint dispatches a checked request to.
///
/// Injected into the endpoint rather than reached for, so the transport
/// has no dependency on the protocol and a test can substitute a handler
/// that refuses, that panics on a second request, or that drives the
/// real in-process verbs.
pub(crate) trait RegistrarRequestHandler: Send + Sync + 'static {
    /// Handles one request and returns its opaque response bytes.
    ///
    /// `payload` may be empty: a zero-length payload is a valid frame,
    /// and what it means is the payload schema's business, not the
    /// transport's.
    ///
    /// `caller` is the transport-authenticated identity, rendered once
    /// at the endpoint's one identity site. It is never derived from
    /// request bytes, so a handler may use it as the caller of record
    /// without re-checking anything.
    ///
    /// # Errors
    ///
    /// Returns [`HandlerRefusal`] when the payload is rejected before a
    /// registrar verb runs. A verb that runs and refuses is a *success*
    /// here: its refusal is part of the response the protocol defines.
    fn handle<'a>(
        &'a self,
        operation: Operation,
        payload: &'a [u8],
        caller: CallerIdentity,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HandlerRefusal>> + Send + 'a>>;
}
