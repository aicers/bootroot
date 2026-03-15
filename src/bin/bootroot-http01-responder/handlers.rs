//! Defines the HTTP challenge and admin registration handlers.

use std::sync::Arc;

use bootroot::acme::http01_protocol::{HEADER_SIGNATURE, HEADER_TIMESTAMP};
use poem::http::StatusCode;
use poem::web::{Data, Json, Path};
use poem::{Request, handler};

use super::signature::{header_value, within_skew};
use super::state::{RegisterRequest, ResponderState};

#[handler]
pub(super) async fn http01_challenge(
    Path(token): Path<String>,
    Data(state): Data<&Arc<ResponderState>>,
) -> (StatusCode, String) {
    match state.fetch_key_authorization(&token).await {
        Some(value) => (StatusCode::OK, value),
        None => (StatusCode::NOT_FOUND, "Not Found".to_string()),
    }
}

#[handler]
pub(super) async fn register_token(
    req: &Request,
    Json(request): Json<RegisterRequest>,
    Data(state): Data<&Arc<ResponderState>>,
) -> (StatusCode, String) {
    let timestamp = match header_value(req, HEADER_TIMESTAMP) {
        Ok(value) => value,
        Err(err) => return (StatusCode::UNAUTHORIZED, err),
    };

    let signature = match header_value(req, HEADER_SIGNATURE) {
        Ok(value) => value,
        Err(err) => return (StatusCode::UNAUTHORIZED, err),
    };

    let Ok(timestamp) = timestamp.parse::<i64>() else {
        return (StatusCode::BAD_REQUEST, "Invalid timestamp".to_string());
    };

    let max_skew = state.max_skew_secs().await;
    if !within_skew(timestamp, max_skew) {
        return (
            StatusCode::UNAUTHORIZED,
            "Timestamp out of range".to_string(),
        );
    }

    match state.register_request(timestamp, &signature, request).await {
        Ok(()) => (StatusCode::OK, "ok".to_string()),
        Err(err) => (StatusCode::UNAUTHORIZED, err),
    }
}
