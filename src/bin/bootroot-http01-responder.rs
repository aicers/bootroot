use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::Parser;
use config::{Config, ConfigError, Environment, File};
use poem::http::StatusCode;
use poem::listener::TcpListener;
use poem::web::{Data, Json, Path};
use poem::{EndpointExt, Route, Server, handler};
use ring::hmac;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

const HEADER_TIMESTAMP: &str = "x-bootroot-timestamp";
const HEADER_SIGNATURE: &str = "x-bootroot-signature";
const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:80";
const DEFAULT_ADMIN_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_TOKEN_TTL_SECS: u64 = 300;
const DEFAULT_CLEANUP_INTERVAL_SECS: u64 = 30;
const DEFAULT_MAX_SKEW_SECS: u64 = 60;

#[derive(Parser, Debug)]
#[command(author, version, about = "Bootroot HTTP-01 responder")]
struct Args {
    /// Path to responder configuration file (default: responder.toml)
    #[arg(long, short)]
    config: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
struct ResponderSettings {
    listen_addr: String,
    admin_addr: String,
    hmac_secret: String,
    token_ttl_secs: u64,
    cleanup_interval_secs: u64,
    max_skew_secs: u64,
}

impl ResponderSettings {
    fn new(config_path: Option<PathBuf>) -> Result<Self, ConfigError> {
        let mut s = Config::builder();
        s = s
            .set_default("listen_addr", DEFAULT_LISTEN_ADDR)?
            .set_default("admin_addr", DEFAULT_ADMIN_ADDR)?
            .set_default("token_ttl_secs", DEFAULT_TOKEN_TTL_SECS)?
            .set_default("cleanup_interval_secs", DEFAULT_CLEANUP_INTERVAL_SECS)?
            .set_default("max_skew_secs", DEFAULT_MAX_SKEW_SECS)?;

        let path = config_path.unwrap_or_else(|| PathBuf::from("responder.toml"));
        s = s.add_source(File::from(path).required(false));

        s = s.add_source(
            Environment::with_prefix("BOOTROOT_RESPONDER")
                .separator("__")
                .try_parsing(true)
                .ignore_empty(true),
        );

        s.build()?.try_deserialize()
    }

    fn validate(&self) -> Result<()> {
        if self.hmac_secret.trim().is_empty() {
            anyhow::bail!("hmac_secret must not be empty");
        }
        if self.token_ttl_secs == 0 {
            anyhow::bail!("token_ttl_secs must be greater than 0");
        }
        if self.cleanup_interval_secs == 0 {
            anyhow::bail!("cleanup_interval_secs must be greater than 0");
        }
        if self.max_skew_secs == 0 {
            anyhow::bail!("max_skew_secs must be greater than 0");
        }
        self.listen_addr
            .parse::<SocketAddr>()
            .map_err(|e| anyhow::anyhow!("listen_addr invalid: {e}"))?;
        self.admin_addr
            .parse::<SocketAddr>()
            .map_err(|e| anyhow::anyhow!("admin_addr invalid: {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TokenEntry {
    key_authorization: String,
    expires_at: tokio::time::Instant,
}

#[derive(Debug)]
struct ResponderState {
    settings: RwLock<ResponderSettings>,
    hmac_key: RwLock<hmac::Key>,
    tokens: RwLock<HashMap<String, TokenEntry>>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RegisterRequest {
    token: String,
    key_authorization: String,
    ttl_secs: Option<u64>,
}

async fn fetch_key_authorization(state: &ResponderState, token: &str) -> Option<String> {
    let mut tokens = state.tokens.write().await;
    if let Some(entry) = tokens.get(token) {
        if tokio::time::Instant::now() <= entry.expires_at {
            return Some(entry.key_authorization.clone());
        }
        tokens.remove(token);
    }
    None
}

async fn register_token_inner(
    state: &ResponderState,
    timestamp: i64,
    signature: &str,
    request: RegisterRequest,
) -> Result<(), String> {
    let ttl_secs = {
        let settings = state.settings.read().await;
        request.ttl_secs.unwrap_or(settings.token_ttl_secs)
    };
    let payload = signature_payload(timestamp, &request, ttl_secs);
    let key = { state.hmac_key.read().await.clone() };
    if !verify_signature(&key, signature, &payload) {
        return Err("Invalid signature".to_string());
    }

    let expires_at = tokio::time::Instant::now() + Duration::from_secs(ttl_secs);
    let mut tokens = state.tokens.write().await;
    tokens.insert(
        request.token,
        TokenEntry {
            key_authorization: request.key_authorization,
            expires_at,
        },
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> Arc<ResponderState> {
        let settings = ResponderSettings {
            listen_addr: DEFAULT_LISTEN_ADDR.to_string(),
            admin_addr: DEFAULT_ADMIN_ADDR.to_string(),
            hmac_secret: "test-secret".to_string(),
            token_ttl_secs: DEFAULT_TOKEN_TTL_SECS,
            cleanup_interval_secs: DEFAULT_CLEANUP_INTERVAL_SECS,
            max_skew_secs: DEFAULT_MAX_SKEW_SECS,
        };

        Arc::new(ResponderState {
            hmac_key: RwLock::new(hmac::Key::new(
                hmac::HMAC_SHA256,
                settings.hmac_secret.as_bytes(),
            )),
            settings: RwLock::new(settings),
            tokens: RwLock::new(HashMap::new()),
        })
    }

    #[test]
    fn test_signature_verification_round_trip() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, b"test-secret");
        let request = RegisterRequest {
            token: "token".to_string(),
            key_authorization: "key-auth".to_string(),
            ttl_secs: Some(60),
        };
        let payload = signature_payload(123, &request, 60);
        let signature = STANDARD.encode(hmac::sign(&key, payload.as_bytes()).as_ref());
        assert!(verify_signature(&key, &signature, &payload));
        assert!(!verify_signature(&key, "invalid", &payload));
    }

    #[test]
    fn test_within_skew_rejects_out_of_range() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time must be after UNIX_EPOCH")
            .as_secs();
        let now = i64::try_from(now).expect("System time must fit in i64");
        assert!(within_skew(now, 60));
        assert!(!within_skew(now - 3600, 60));
    }

    #[tokio::test]
    async fn test_http01_challenge_returns_token() {
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

        let body = fetch_key_authorization(&state, &token).await;
        assert_eq!(body, Some(key_auth));
    }

    #[tokio::test]
    async fn test_register_token_with_valid_signature() {
        let state = test_state();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("System time must be after UNIX_EPOCH")
            .as_secs();
        let timestamp = i64::try_from(timestamp).expect("System time must fit in i64");
        let request = RegisterRequest {
            token: "token-2".to_string(),
            key_authorization: "token-2.key".to_string(),
            ttl_secs: Some(60),
        };
        let payload = signature_payload(timestamp, &request, 60);
        let key = state.hmac_key.read().await;
        let signature = STANDARD.encode(hmac::sign(&key, payload.as_bytes()).as_ref());

        register_token_inner(&state, timestamp, &signature, request)
            .await
            .expect("register token should succeed");

        let stored = state.tokens.read().await;
        assert!(stored.contains_key("token-2"));
    }
}

#[handler]
async fn http01_challenge(
    Path(token): Path<String>,
    Data(state): Data<&Arc<ResponderState>>,
) -> (StatusCode, String) {
    match fetch_key_authorization(state, &token).await {
        Some(value) => (StatusCode::OK, value),
        None => (StatusCode::NOT_FOUND, "Not Found".to_string()),
    }
}

#[handler]
async fn register_token(
    req: &poem::Request,
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

    let max_skew = {
        let settings = state.settings.read().await;
        settings.max_skew_secs
    };
    if !within_skew(timestamp, max_skew) {
        return (
            StatusCode::UNAUTHORIZED,
            "Timestamp out of range".to_string(),
        );
    }

    match register_token_inner(state, timestamp, &signature, request).await {
        Ok(()) => (StatusCode::OK, "ok".to_string()),
        Err(err) => (StatusCode::UNAUTHORIZED, err),
    }
}

fn header_value(req: &poem::Request, key: &str) -> Result<String, String> {
    req.headers()
        .get(key)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .ok_or_else(|| format!("Missing header: {key}"))
}

fn within_skew(timestamp: i64, max_skew_secs: u64) -> bool {
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(value) => match i64::try_from(value.as_secs()) {
            Ok(secs) => secs,
            Err(_) => return false,
        },
        Err(_) => return false,
    };
    (now - timestamp).unsigned_abs() <= max_skew_secs
}

fn signature_payload(timestamp: i64, request: &RegisterRequest, ttl_secs: u64) -> String {
    format!(
        "{timestamp}.{}.{}.{}",
        request.token, request.key_authorization, ttl_secs
    )
}

fn verify_signature(key: &hmac::Key, signature: &str, payload: &str) -> bool {
    let Ok(decoded) = STANDARD.decode(signature.as_bytes()) else {
        return false;
    };
    hmac::verify(key, payload.as_bytes(), &decoded).is_ok()
}

async fn cleanup_expired_tokens(state: Arc<ResponderState>) {
    loop {
        let interval = {
            let settings = state.settings.read().await;
            Duration::from_secs(settings.cleanup_interval_secs)
        };
        tokio::time::sleep(interval).await;
        let mut tokens = state.tokens.write().await;
        let now = tokio::time::Instant::now();
        let before = tokens.len();
        tokens.retain(|_, entry| entry.expires_at > now);
        let removed = before.saturating_sub(tokens.len());
        if removed > 0 {
            info!("Removed {removed} expired HTTP-01 tokens");
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let config_path = args.config.clone();
    let settings = load_settings(config_path.clone())?;

    let state = Arc::new(ResponderState {
        hmac_key: RwLock::new(hmac::Key::new(
            hmac::HMAC_SHA256,
            settings.hmac_secret.as_bytes(),
        )),
        settings: RwLock::new(settings.clone()),
        tokens: RwLock::new(HashMap::new()),
    });

    tokio::spawn(cleanup_expired_tokens(Arc::clone(&state)));

    let challenge_app = Route::new()
        .at(
            "/.well-known/acme-challenge/:token",
            poem::get(http01_challenge),
        )
        .data(Arc::clone(&state));

    let admin_app = Route::new()
        .at("/admin/http01", poem::post(register_token))
        .data(Arc::clone(&state));

    let listen_addr: SocketAddr = settings.listen_addr.parse().map_err(|e| {
        anyhow::anyhow!("Failed to parse listen_addr {}: {e}", settings.listen_addr)
    })?;
    let admin_addr: SocketAddr = settings
        .admin_addr
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse admin_addr {}: {e}", settings.admin_addr))?;

    info!("Starting HTTP-01 responder on {}", listen_addr);
    info!("Starting HTTP-01 admin API on {}", admin_addr);

    let mut challenge =
        tokio::spawn(Server::new(TcpListener::bind(listen_addr)).run(challenge_app));
    let mut admin = tokio::spawn(Server::new(TcpListener::bind(admin_addr)).run(admin_app));
    #[cfg(unix)]
    {
        let mut hup = signal(SignalKind::hangup())?;
        loop {
            tokio::select! {
                result = &mut challenge => {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => error!("Challenge server failed: {err}"),
                        Err(err) => error!("Challenge server task failed: {err}"),
                    }
                    break;
                }
                result = &mut admin => {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => error!("Admin server failed: {err}"),
                        Err(err) => error!("Admin server task failed: {err}"),
                    }
                    break;
                }
                _ = tokio::signal::ctrl_c() => {
                    warn!("Shutdown signal received");
                    break;
                }
                _ = hup.recv() => {
                    match reload_settings(&state, config_path.clone()).await {
                        Ok(()) => info!("Reloaded responder configuration"),
                        Err(err) => error!("Reload failed: {err}"),
                    }
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        loop {
            tokio::select! {
                result = &mut challenge => {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => error!("Challenge server failed: {err}"),
                        Err(err) => error!("Challenge server task failed: {err}"),
                    }
                    break;
                }
                result = &mut admin => {
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => error!("Admin server failed: {err}"),
                        Err(err) => error!("Admin server task failed: {err}"),
                    }
                    break;
                }
                _ = tokio::signal::ctrl_c() => {
                    warn!("Shutdown signal received");
                    break;
                }
            }
        }
    }

    Ok(())
}

fn load_settings(config_path: Option<PathBuf>) -> Result<ResponderSettings> {
    let settings = ResponderSettings::new(config_path)?;
    settings.validate()?;
    Ok(settings)
}

async fn reload_settings(state: &ResponderState, config_path: Option<PathBuf>) -> Result<()> {
    let settings = load_settings(config_path)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, settings.hmac_secret.as_bytes());
    {
        let mut settings_lock = state.settings.write().await;
        *settings_lock = settings;
    }
    {
        let mut key_lock = state.hmac_key.write().await;
        *key_lock = key;
    }
    Ok(())
}
