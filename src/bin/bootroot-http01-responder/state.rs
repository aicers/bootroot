//! Defines the in-memory HTTP-01 token state and mutation helpers.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use ring::hmac;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::config::ResponderSettings;
use super::signature::{payload_for_request, verify_signature};

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

#[derive(Debug)]
pub(super) struct ResponderState {
    settings: RwLock<ResponderSettings>,
    hmac_key: RwLock<hmac::Key>,
    tokens: RwLock<HashMap<String, TokenEntry>>,
}

impl ResponderState {
    pub(super) fn shared(settings: ResponderSettings) -> Arc<Self> {
        Arc::new(Self::new(settings))
    }

    fn new(settings: ResponderSettings) -> Self {
        let hmac_key = settings.build_hmac_key();
        Self {
            settings: RwLock::new(settings),
            hmac_key: RwLock::new(hmac_key),
            tokens: RwLock::new(HashMap::new()),
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
    ) -> Result<(), String> {
        let ttl_secs = {
            let settings = self.settings.read().await;
            request.ttl_secs.unwrap_or(settings.token_ttl_secs)
        };
        let payload = payload_for_request(
            timestamp,
            &request.token,
            &request.key_authorization,
            ttl_secs,
        );
        let key = { self.hmac_key.read().await.clone() };
        if !verify_signature(&key, signature, &payload) {
            return Err("Invalid signature".to_string());
        }

        let expires_at = tokio::time::Instant::now() + Duration::from_secs(ttl_secs);
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

    pub(super) async fn cleanup_interval(&self) -> Duration {
        Duration::from_secs(self.settings.read().await.cleanup_interval_secs)
    }

    pub(super) async fn update_settings(&self, settings: ResponderSettings) {
        let hmac_key = settings.build_hmac_key();
        {
            let mut settings_lock = self.settings.write().await;
            *settings_lock = settings;
        }
        {
            let mut key_lock = self.hmac_key.write().await;
            *key_lock = hmac_key;
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
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use super::*;
    use crate::config::{
        DEFAULT_ADMIN_ADDR, DEFAULT_CLEANUP_INTERVAL_SECS, DEFAULT_LISTEN_ADDR,
        DEFAULT_MAX_SKEW_SECS, DEFAULT_TOKEN_TTL_SECS,
    };

    fn test_state() -> Arc<ResponderState> {
        ResponderState::shared(ResponderSettings {
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
            admin_addr: DEFAULT_ADMIN_ADDR.to_string(),
            hmac_secret: "test-secret".to_string(),
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
            max_skew_secs: DEFAULT_MAX_SKEW_SECS,
        })
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
        let payload = payload_for_request(123, &request.token, &request.key_authorization, 60);
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"test-secret");
        let signature = STANDARD.encode(hmac::sign(&key, payload.as_bytes()).as_ref());

        state
            .register_request(123, &signature, request)
            .await
            .expect("register request should succeed");

        let stored = state.tokens.read().await;
        assert!(stored.contains_key("token-2"));
    }
}
