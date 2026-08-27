//! The handler used when the filesystem-backed audit store is unavailable.
//!
//! It validates the payload shape so malformed requests retain the endpoint's
//! existing [`HandlerRefusal`] path, but it otherwise reaches neither the verb
//! layer nor any of its dependencies. In particular, it does not open the
//! record store that is unavailable.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use tracing::{debug, info, warn};

use super::frame::Operation;
use super::handler::{HandlerRefusal, RegistrarRequestHandler};
use super::protocol::{self, RegistrarHealth, RegistrarUnavailableReason};
use crate::DaemonMessages;
use crate::registrar::verbs::outcome::{CallerIdentity, RequestId};

/// A handler that permanently refuses verbs because their audit store is absent.
pub(crate) struct UnavailableHandler {
    audit_store_dir: PathBuf,
    mount_unit: String,
    messages: DaemonMessages,
}

impl UnavailableHandler {
    /// Creates a handler that names the missing store and mount unit in logs.
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

impl RegistrarRequestHandler for UnavailableHandler {
    fn handle<'a>(
        &'a self,
        operation: Operation,
        payload: &'a [u8],
        caller: CallerIdentity,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, HandlerRefusal>> + Send + 'a>> {
        Box::pin(async move {
            protocol::decode_request(operation, payload).map_err(|error| {
                debug!(
                    caller = caller.as_str(),
                    operation = operation.as_str(),
                    "Registrar endpoint could not decode the request payload: {error}"
                );
                HandlerRefusal
            })?;

            let request_id = RequestId::generate();
            info!(
                request_id = request_id.as_str(),
                operation = operation.as_str(),
                caller = caller.as_str(),
                audit_store_dir = %self.audit_store_dir.display(),
                expected_mount_unit = self.mount_unit.as_str(),
                "{}", self.messages.audit_store_not_mounted_request_refused()
            );
            protocol::encode_registrar_unavailable(
                request_id.as_str(),
                RegistrarUnavailableReason::AuditUnwritable,
                &RegistrarHealth::default(),
            )
            .map_err(|error| {
                warn!(
                    caller = caller.as_str(),
                    "Registrar endpoint could not encode an audit-store refusal: {error}"
                );
                HandlerRefusal
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registrar::endpoint::protocol::{
        DeregisterRequest, EnrollError, ProtocolVersion, RefusalClass, Request,
        decode_refusal_response, encode_request,
    };
    use crate::registrar::endpoint::test_support::capture_logs;

    fn deregister_payload(idempotency_key: &str) -> Vec<u8> {
        encode_request(&Request::Deregister(DeregisterRequest {
            protocol_version: ProtocolVersion::current(),
            service_name: "api".to_string(),
            host: "host".to_string(),
            instance: Some(1),
            idempotency_key: idempotency_key.to_string(),
        }))
        .expect("a valid request encodes")
    }

    #[tokio::test]
    async fn refuses_well_formed_requests_with_fresh_correlation_ids() {
        let handler = UnavailableHandler::new(
            PathBuf::from("/srv/bootroot/audit-store"),
            "srv-bootroot-audit\\x2dstore.mount".to_string(),
            DaemonMessages::default(),
        );
        let caller = CallerIdentity::new("registrar-client:client.example");
        let first = handler
            .handle(
                Operation::Deregister,
                &deregister_payload("caller-supplied-key"),
                caller.clone(),
            )
            .await
            .expect("a valid request is answered");
        let second = handler
            .handle(
                Operation::Deregister,
                &deregister_payload("caller-supplied-key"),
                caller,
            )
            .await
            .expect("a valid request is answered");

        let first = decode_refusal_response(&first).expect("refusal decodes");
        let second = decode_refusal_response(&second).expect("refusal decodes");
        assert_eq!(first.class, RefusalClass::Permanent);
        assert_eq!(
            first.error,
            Some(EnrollError::RegistrarUnavailable {
                reason: RegistrarUnavailableReason::AuditUnwritable,
            })
        );
        assert!(first.registration_id.is_none());
        assert_eq!(first.registrar_health, RegistrarHealth::default());
        assert!(!first.request_id.is_empty());
        assert_ne!(first.request_id, "caller-supplied-key");
        assert_ne!(first.request_id, second.request_id);
    }

    #[tokio::test]
    async fn malformed_payload_uses_the_existing_handler_refusal() {
        let handler = UnavailableHandler::new(
            PathBuf::from("/srv/bootroot/audit-store"),
            "srv-bootroot-audit\\x2dstore.mount".to_string(),
            DaemonMessages::default(),
        );
        let result = handler
            .handle(
                Operation::Deregister,
                b"not json",
                CallerIdentity::new("registrar-client:client.example"),
            )
            .await;
        assert_eq!(result, Err(HandlerRefusal));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refusal_uses_the_selected_operator_locale() {
        let (logs, _guard) = capture_logs();
        let messages = DaemonMessages::new("ko").expect("Korean is supported");
        let handler = UnavailableHandler::new(
            PathBuf::from("/srv/bootroot/audit-store"),
            "srv-bootroot-audit\\x2dstore.mount".to_string(),
            messages,
        );

        handler
            .handle(
                Operation::Deregister,
                &deregister_payload("caller-supplied-key"),
                CallerIdentity::new("registrar-client:client.example"),
            )
            .await
            .expect("a valid request is answered");

        assert!(
            logs.events().iter().any(|event| {
                event.message == messages.audit_store_not_mounted_request_refused()
            })
        );
    }
}
