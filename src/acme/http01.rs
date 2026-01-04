use std::collections::HashMap;
use std::sync::Arc;

use poem::http::StatusCode;
use poem::listener::TcpListener;
use poem::web::{Data, Path};
use poem::{EndpointExt, Route, Server, handler};
use tokio::sync::Mutex;
use tracing::{error, info};

pub type ChallengeStore = Arc<Mutex<HashMap<String, String>>>;

async fn resolve_http01(token: &str, state: &ChallengeStore) -> (StatusCode, String) {
    let guard = state.lock().await;
    if let Some(key_auth) = guard.get(token) {
        return (StatusCode::OK, key_auth.clone());
    }
    (StatusCode::NOT_FOUND, "Not Found".to_string())
}

#[handler]
async fn http01_challenge(
    Path(token): Path<String>,
    Data(state): Data<&ChallengeStore>,
) -> (StatusCode, String) {
    resolve_http01(&token, state).await
}

pub fn start_http01_server(challenges: ChallengeStore, port: u16) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let app = Route::new()
            .at(
                "/.well-known/acme-challenge/:token",
                poem::get(http01_challenge),
            )
            .data(challenges);

        let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
        info!("Starting HTTP-01 Challenge Server on {}", addr);
        if let Err(err) = Server::new(TcpListener::bind(addr)).run(app).await {
            error!("HTTP server failed: {}", err);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http01_challenge_hit() {
        let challenges: ChallengeStore = Arc::new(Mutex::new(HashMap::new()));
        {
            let mut guard = challenges.lock().await;
            guard.insert("token-1".to_string(), "key-auth-1".to_string());
        }

        let (status, body) = resolve_http01("token-1", &challenges).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "key-auth-1");
    }

    #[tokio::test]
    async fn test_http01_challenge_miss() {
        let challenges: ChallengeStore = Arc::new(Mutex::new(HashMap::new()));
        let (status, body) = resolve_http01("missing", &challenges).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body, "Not Found");
    }
}
