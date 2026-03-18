//! Defines the in-memory HTTP-01 token state and mutation helpers.

use std::collections::{HashMap, VecDeque};
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use bootroot::acme::http01_protocol::Http01HmacSigner;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use super::config::ResponderSettings;

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct RegisterRequest {
    pub(super) token: String,
    pub(super) key_authorization: String,
    pub(super) ttl_secs: Option<u64>,
}

#[derive(Debug, Clone)]
struct TokenEntry {
    key_authorization: String,
    expires_at: tokio::time::Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum RegisterError {
    InvalidSignature,
    InvalidTtl,
    RateLimited,
}

impl Display for RegisterError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidSignature => f.write_str("Invalid signature"),
            Self::InvalidTtl => f.write_str("Invalid ttl_secs"),
            Self::RateLimited => f.write_str("Rate limit exceeded"),
        }
    }
}

#[derive(Debug, Default)]
struct AdminRateLimiter {
    registrations: VecDeque<tokio::time::Instant>,
}

impl AdminRateLimiter {
    fn allow_registration_at(
        &mut self,
        now: tokio::time::Instant,
        max_requests: usize,
        window: Duration,
    ) -> bool {
        while self
            .registrations
            .front()
            .is_some_and(|timestamp| *timestamp + window <= now)
        {
            self.registrations.pop_front();
        }

        if self.registrations.len() >= max_requests {
            return false;
        }

        self.registrations.push_back(now);
        true
    }
}

pub(super) struct ResponderState {
    settings: RwLock<ResponderSettings>,
    hmac_signer: RwLock<Http01HmacSigner>,
    tokens: RwLock<HashMap<String, TokenEntry>>,
    admin_rate_limiter: Mutex<AdminRateLimiter>,
}

impl ResponderState {
    pub(super) fn shared(settings: ResponderSettings) -> Arc<Self> {
        Arc::new(Self::new(settings))
    }

    fn new(settings: ResponderSettings) -> Self {
        let hmac_signer = settings.build_hmac_signer();
        Self {
            settings: RwLock::new(settings),
            hmac_signer: RwLock::new(hmac_signer),
            tokens: RwLock::new(HashMap::new()),
            admin_rate_limiter: Mutex::new(AdminRateLimiter::default()),
        }
    }

    pub(super) async fn fetch_key_authorization(&self, token: &str) -> Option<String> {
        let mut tokens = self.tokens.write().await;
        if let Some(entry) = tokens.get(token) {
            if tokio::time::Instant::now() <= entry.expires_at {
                return Some(entry.key_authorization.clone());
            }
            tokens.remove(token);
        }
        None
    }

    pub(super) async fn register_request(
        &self,
        timestamp: i64,
        signature: &str,
        request: RegisterRequest,
    ) -> Result<(), RegisterError> {
        let (
            default_ttl_secs,
            max_token_ttl_secs,
            admin_rate_limit_requests,
            admin_rate_limit_window_secs,
        ) = {
            let settings = self.settings.read().await;
            (
                settings.token_ttl_secs,
                settings.max_token_ttl_secs,
                usize::try_from(settings.admin_rate_limit_requests)
                    .expect("validated admin_rate_limit_requests must fit into usize"),
                Duration::from_secs(settings.admin_rate_limit_window_secs),
            )
        };
        let requested_ttl_secs = request.ttl_secs.unwrap_or(default_ttl_secs);
        if requested_ttl_secs == 0 {
            return Err(RegisterError::InvalidTtl);
        }
        let signer = { self.hmac_signer.read().await.clone() };
        if !signer.verify_request(
            signature,
            timestamp,
            &request.token,
            &request.key_authorization,
            requested_ttl_secs,
        ) {
            return Err(RegisterError::InvalidSignature);
        }

        let now = tokio::time::Instant::now();
        if !self.admin_rate_limiter.lock().await.allow_registration_at(
            now,
            admin_rate_limit_requests,
            admin_rate_limit_window_secs,
        ) {
            return Err(RegisterError::RateLimited);
        }

        let effective_ttl_secs = requested_ttl_secs.min(max_token_ttl_secs);
        let expires_at = now + Duration::from_secs(effective_ttl_secs);
        let mut tokens = self.tokens.write().await;
        tokens.insert(
            request.token,
            TokenEntry {
                key_authorization: request.key_authorization,
                expires_at,
            },
        );
        Ok(())
    }

    pub(super) async fn max_skew_secs(&self) -> u64 {
        self.settings.read().await.max_skew_secs
    }

    pub(super) async fn admin_body_limit_bytes(&self) -> usize {
        usize::try_from(self.settings.read().await.admin_body_limit_bytes)
            .expect("validated admin_body_limit_bytes must fit into usize")
    }

    pub(super) async fn cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.settings.read().await.cleanup_interval_secs)
    }

    pub(super) async fn update_settings(&self, settings: ResponderSettings) {
        let hmac_signer = settings.build_hmac_signer();
        {
            let mut settings_lock = self.settings.write().await;
            *settings_lock = settings;
        }
        {
            let mut signer_lock = self.hmac_signer.write().await;
            *signer_lock = hmac_signer;
        }
    }

    pub(super) async fn purge_expired_tokens(&self) -> usize {
        let mut tokens = self.tokens.write().await;
        let now = tokio::time::Instant::now();
        let before = tokens.len();
        tokens.retain(|_, entry| entry.expires_at > now);
        before.saturating_sub(tokens.len())
    }
}

#[cfg(test)]
mod tests {
    use bootroot::acme::http01_protocol::Http01HmacSigner;

    use super::*;
    use crate::config::{
        DEFAULT_ADMIN_ADDR, DEFAULT_ADMIN_BODY_LIMIT_BYTES, DEFAULT_ADMIN_RATE_LIMIT_REQUESTS,
        DEFAULT_ADMIN_RATE_LIMIT_WINDOW_SECS, DEFAULT_CLEANUP_INTERVAL_SECS, DEFAULT_LISTEN_ADDR,
        DEFAULT_MAX_SKEW_SECS, DEFAULT_MAX_TOKEN_TTL_SECS, DEFAULT_TOKEN_TTL_SECS,
    };

    fn test_settings() -> ResponderSettings {
        ResponderSettings {
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
            admin_addr: DEFAULT_ADMIN_ADDR.to_string(),
            hmac_secret: "test-secret".to_string(),
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
            max_token_ttl_secs: DEFAULT_MAX_TOKEN_TTL_SECS,
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
            max_skew_secs: DEFAULT_MAX_SKEW_SECS,
            admin_rate_limit_requests: DEFAULT_ADMIN_RATE_LIMIT_REQUESTS,
            admin_rate_limit_window_secs: DEFAULT_ADMIN_RATE_LIMIT_WINDOW_SECS,
            admin_body_limit_bytes: DEFAULT_ADMIN_BODY_LIMIT_BYTES,
        }
    }

    fn test_state() -> Arc<ResponderState> {
        ResponderState::shared(test_settings())
    }

    #[tokio::test]
    async fn test_fetch_key_authorization_returns_active_token() {
        let state = test_state();
        let token = "token-1".to_string();
        let key_auth = "token-1.key".to_string();
        let expires_at = tokio::time::Instant::now() + Duration::from_secs(60);
        {
            let mut tokens = state.tokens.write().await;
            tokens.insert(
                token.clone(),
                TokenEntry {
                    key_authorization: key_auth.clone(),
                    expires_at,
                },
            );
        }

        let body = state.fetch_key_authorization(&token).await;
        assert_eq!(body, Some(key_auth));
    }

    #[tokio::test]
    async fn test_fetch_key_authorization_removes_expired_token() {
        let state = test_state();
        let token = "token-expired".to_string();
        {
            let mut tokens = state.tokens.write().await;
            tokens.insert(
                token.clone(),
                TokenEntry {
                    key_authorization: "expired.key".to_string(),
                    expires_at: tokio::time::Instant::now() - Duration::from_secs(1),
                },
            );
        }

        let body = state.fetch_key_authorization(&token).await;
        let stored = state.tokens.read().await;

        assert!(body.is_none());
        assert!(!stored.contains_key(&token));
    }

    #[tokio::test]
    async fn test_register_request_accepts_valid_signature() {
        let state = test_state();
        let request = RegisterRequest {
            token: "token-2".to_string(),
            key_authorization: "token-2.key".to_string(),
            ttl_secs: Some(60),
        };
        let signer = Http01HmacSigner::new("test-secret");
        let signature = signer.sign_request(123, &request.token, &request.key_authorization, 60);

        state
            .register_request(123, &signature, request)
            .await
            .expect("register request should succeed");

        let stored = state.tokens.read().await;
        assert!(stored.contains_key("token-2"));
    }

    #[test]
    fn test_admin_rate_limiter_expires_old_entries() {
        let mut limiter = AdminRateLimiter::default();
        let window = Duration::from_secs(5);
        let now = tokio::time::Instant::now();

        assert!(limiter.allow_registration_at(now, 1, window));
        assert!(
            !limiter.allow_registration_at(now + Duration::from_secs(4), 1, window),
            "requests inside the window must be rejected once the limit is reached"
        );
        assert!(
            limiter.allow_registration_at(now + Duration::from_secs(5), 1, window),
            "requests after the window must be accepted again"
        );
    }

    #[tokio::test]
    async fn test_register_request_clamps_ttl_to_max_token_ttl() {
        let state = ResponderState::shared(ResponderSettings {
            max_token_ttl_secs: 30,
            ..test_settings()
        });
        let request = RegisterRequest {
            token: "token-clamped".to_string(),
            key_authorization: "token-clamped.key".to_string(),
            ttl_secs: Some(90),
        };
        let signer = Http01HmacSigner::new("test-secret");
        let signature = signer.sign_request(123, &request.token, &request.key_authorization, 90);
        let now = tokio::time::Instant::now();

        state
            .register_request(123, &signature, request)
            .await
            .expect("register request should succeed");

        let stored = state.tokens.read().await;
        let entry = stored
            .get("token-clamped")
            .expect("stored token must exist after successful registration");
        let remaining = entry.expires_at.saturating_duration_since(now);

        assert!(
            remaining <= Duration::from_secs(31),
            "token expiry must not exceed the configured max token TTL"
        );
        assert!(
            remaining >= Duration::from_secs(29),
            "token expiry must use the configured max token TTL rather than the requested value"
        );
    }

    #[tokio::test]
    async fn test_register_request_rejects_zero_ttl() {
        let state = test_state();
        let request = RegisterRequest {
            token: "token-zero-ttl".to_string(),
            key_authorization: "token-zero-ttl.key".to_string(),
            ttl_secs: Some(0),
        };
        let signer = Http01HmacSigner::new("test-secret");
        let signature = signer.sign_request(123, &request.token, &request.key_authorization, 0);

        let err = state
            .register_request(123, &signature, request)
            .await
            .expect_err("zero ttl must be rejected");
        assert_eq!(err, RegisterError::InvalidTtl);
    }

    #[tokio::test]
    async fn test_register_request_rate_limits_successful_registrations() {
        let state = ResponderState::shared(ResponderSettings {
            admin_rate_limit_requests: 1,
            ..test_settings()
        });
        let signer = Http01HmacSigner::new("test-secret");

        let first = RegisterRequest {
            token: "token-rate-limit-1".to_string(),
            key_authorization: "token-rate-limit-1.key".to_string(),
            ttl_secs: Some(60),
        };
        let first_signature = signer.sign_request(123, &first.token, &first.key_authorization, 60);
        state
            .register_request(123, &first_signature, first)
            .await
            .expect("first request should succeed");

        let second = RegisterRequest {
            token: "token-rate-limit-2".to_string(),
            key_authorization: "token-rate-limit-2.key".to_string(),
            ttl_secs: Some(60),
        };
        let second_signature =
            signer.sign_request(124, &second.token, &second.key_authorization, 60);
        let err = state
            .register_request(124, &second_signature, second)
            .await
            .expect_err("second request in the same rate limit window must be rejected");

        assert_eq!(err, RegisterError::RateLimited);
    }
}
