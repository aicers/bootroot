//! The endpoint handler used while the filesystem audit store is absent.
//!
//! It deliberately decodes only far enough to preserve the endpoint's normal
//! malformed-payload refusal path. A well-formed request gets a typed wire
//! refusal without opening the record store or constructing any verb-layer
//! dependency.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use tracing::debug;

use super::frame::Operation;
use super::handler::{HandlerRefusal, RegistrarRequestHandler};
use super::protocol;
use crate::daemon_messages::DaemonMessages;
use crate::registrar::verbs::outcome::{CallerIdentity, RequestId};

/// A handler that refuses registrar verbs until the audit store is mounted.
pub(crate) struct RefusingHandler {
    audit_store_dir: PathBuf,
    mount_unit: String,
    messages: DaemonMessages,
}

impl RefusingHandler {
    /// Creates a handler that names the unavailable audit-store mount.
    pub(crate) fn new(
        audit_store_dir: PathBuf,
        mount_unit: String,
        messages: DaemonMessages,
    ) -> Self {
        Self {
            audit_store_dir,
            mount_unit,
            messages,
        }
    }
}

impl RegistrarRequestHandler for RefusingHandler {
    fn handle<'a>(
        &'a self,
        operation: Operation,
        payload: &'a [u8],
        caller: CallerIdentity,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HandlerRefusal>> + Send + 'a>> {
        Box::pin(async move {
            // Keep malformed bytes on the handler-refusal path. Treating them
            // as an audit-store fault would conceal a caller bug.
            protocol::decode_request(operation, payload).map_err(|_| HandlerRefusal)?;

            let request_id = RequestId::generate();
            debug!(
                request_id = request_id.as_str(),
                operation = operation.as_str(),
                caller = caller.as_str(),
                audit_store = %self.audit_store_dir.display(),
                mount_unit = self.mount_unit.as_str(),
                "{}", self.messages.audit_store_not_mounted_request_refused()
            );
            protocol::encode_audit_store_unavailable(request_id.as_str())
                .map_err(|_| HandlerRefusal)
        })
    }
}
