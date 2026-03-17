//! Defines the HTTP challenge and admin registration handlers.

use std::sync::Arc;

use bootroot::acme::http01_protocol::{HEADER_SIGNATURE, HEADER_TIMESTAMP};
use poem::error::{GetDataError, ParseJsonError};
use poem::http::StatusCode;
use poem::web::{Data, Path};
use poem::{FromRequest, Request, RequestBody, Result, handler};

use super::signature::{header_value, within_skew};
use super::state::{RegisterError, RegisterRequest, ResponderState};

struct AdminRegisterPayload(RegisterRequest);

impl<'a> FromRequest<'a> for AdminRegisterPayload {
    async fn from_request(req: &'a Request, body: &mut RequestBody) -> Result<Self> {
        let state = req
            .data::<Arc<ResponderState>>()
            .ok_or_else(|| GetDataError(std::any::type_name::<Arc<ResponderState>>()))?;
        let content_type = req
            .content_type()
            .ok_or(ParseJsonError::ContentTypeRequired)?;
        if !is_json_content_type(content_type) {
            return Err(ParseJsonError::InvalidContentType(content_type.to_string()).into());
        }

        let payload = body
            .take()?
            .into_bytes_limit(state.admin_body_limit_bytes().await)
            .await?;
        let request = serde_json::from_slice(&payload).map_err(ParseJsonError::Parse)?;
        Ok(Self(request))
    }
}

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
    AdminRegisterPayload(request): AdminRegisterPayload,
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
        Err(RegisterError::InvalidSignature) => (
            StatusCode::UNAUTHORIZED,
            RegisterError::InvalidSignature.to_string(),
        ),
        Err(RegisterError::InvalidTtl) => (
            StatusCode::BAD_REQUEST,
            RegisterError::InvalidTtl.to_string(),
        ),
        Err(RegisterError::RateLimited) => (
            StatusCode::TOO_MANY_REQUESTS,
            RegisterError::RateLimited.to_string(),
        ),
    }
}

fn is_json_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split_once(';')
        .map_or(content_type, |(value, _)| value)
        .trim()
        .to_ascii_lowercase();

    media_type == "application/json"
        || (media_type.starts_with("application/") && media_type.ends_with("+json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_json_content_type_accepts_json_suffix_types() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(is_json_content_type("application/problem+json"));
        assert!(!is_json_content_type("text/plain"));
    }
}
