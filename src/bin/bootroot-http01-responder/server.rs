//! Builds the responder routes and drives the server lifecycle.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use poem::listener::TcpListener;
use poem::{Endpoint, EndpointExt, Route, Server};
#[cfg(unix)]
use tokio::signal::unix::{Signal, SignalKind, signal};
use tokio::task::{JoinError, JoinHandle};
use tracing::{error, info, warn};

use super::cleanup::cleanup_expired_tokens;
use super::config::{Args, load_settings, reload_settings};
use super::handlers::{http01_challenge, register_token};
use super::state::ResponderState;

type ServerTask = JoinHandle<std::io::Result<()>>;

pub(super) async fn run(args: Args) -> Result<()> {
    let config_path = args.config;
    let settings = load_settings(config_path.as_deref())?;
    let listen_addr = parse_socket_addr(&settings.listen_addr, "listen_addr")?;
    let admin_addr = parse_socket_addr(&settings.admin_addr, "admin_addr")?;
    let state = ResponderState::shared(settings);

    tokio::spawn(cleanup_expired_tokens(Arc::clone(&state)));

    info!("Starting HTTP-01 responder on {listen_addr}");
    info!("Starting HTTP-01 admin API on {admin_addr}");

    let mut challenge = tokio::spawn(
        Server::new(TcpListener::bind(listen_addr)).run(challenge_app(Arc::clone(&state))),
    );
    let mut admin =
        tokio::spawn(Server::new(TcpListener::bind(admin_addr)).run(admin_app(Arc::clone(&state))));

    wait_for_shutdown(
        &mut challenge,
        &mut admin,
        state.as_ref(),
        config_path.as_deref(),
    )
    .await
}

fn challenge_app(state: Arc<ResponderState>) -> impl Endpoint {
    Route::new()
        .at(
            "/.well-known/acme-challenge/:token",
            poem::get(http01_challenge),
        )
        .data(state)
}

fn admin_app(state: Arc<ResponderState>) -> impl Endpoint {
    Route::new()
        .at("/admin/http01", poem::post(register_token))
        .data(state)
}

async fn wait_for_shutdown(
    challenge: &mut ServerTask,
    admin: &mut ServerTask,
    state: &ResponderState,
    config_path: Option<&Path>,
) -> Result<()> {
    let mut reload_signal = ReloadSignal::new()?;

    loop {
        tokio::select! {
            result = &mut *challenge => {
                log_server_exit("Challenge", result);
                break;
            }
            result = &mut *admin => {
                log_server_exit("Admin", result);
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                warn!("Shutdown signal received");
                break;
            }
            () = reload_signal.recv() => {
                match reload_settings(state, config_path).await {
                    Ok(()) => info!("Reloaded responder configuration"),
                    Err(err) => error!("Reload failed: {err}"),
                }
            }
        }
    }

    Ok(())
}

fn parse_socket_addr(value: &str, field_name: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .with_context(|| format!("Failed to parse {field_name} {value}"))
}

fn log_server_exit(name: &str, result: std::result::Result<std::io::Result<()>, JoinError>) {
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => error!("{name} server failed: {err}"),
        Err(err) => error!("{name} server task failed: {err}"),
    }
}

struct ReloadSignal {
    #[cfg(unix)]
    signal: Signal,
}

impl ReloadSignal {
    fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self {
                signal: signal(SignalKind::hangup())?,
            })
        }

        #[cfg(not(unix))]
        {
            Ok(Self {})
        }
    }

    async fn recv(&mut self) {
        #[cfg(unix)]
        {
            let _ = self.signal.recv().await;
        }

        #[cfg(not(unix))]
        {
            std::future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_socket_addr_rejects_invalid_value() {
        let err = parse_socket_addr("invalid", "listen_addr")
            .expect_err("invalid socket address must be rejected");
        assert!(err.to_string().contains("listen_addr"));
    }
}
