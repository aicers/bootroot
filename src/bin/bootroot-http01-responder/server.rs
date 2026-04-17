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
use super::tls::{ReloadableCertResolver, TlsListener, build_tls_config, load_certified_key};

type ServerTask = JoinHandle<std::io::Result<()>>;

pub(super) async fn run(args: Args) -> Result<()> {
    let config_path = args.config;
    let settings = load_settings(config_path.as_deref())?;
    let listen_addr = parse_socket_addr(&settings.listen_addr, "listen_addr")?;
    let admin_addr = parse_socket_addr(&settings.admin_addr, "admin_addr")?;

    let tls = if settings.tls_enabled() {
        let cert = settings
            .tls_cert_path
            .as_deref()
            .expect("validated tls_cert_path");
        let key = settings
            .tls_key_path
            .as_deref()
            .expect("validated tls_key_path");
        let (resolver, server_config) = build_tls_config(Path::new(cert), Path::new(key))
            .context("failed to initialise TLS for admin API")?;
        Some((resolver, server_config))
    } else {
        None
    };

    let state = ResponderState::shared(settings);

    tokio::spawn(cleanup_expired_tokens(Arc::clone(&state)));

    info!("Starting HTTP-01 responder on {listen_addr}");
    if tls.is_some() {
        info!("Starting HTTP-01 admin API on {admin_addr} (TLS)");
    } else {
        info!("Starting HTTP-01 admin API on {admin_addr}");
    }

    let mut challenge = tokio::spawn(
        Server::new(TcpListener::bind(listen_addr)).run(challenge_app(Arc::clone(&state))),
    );

    let cert_resolver = tls.as_ref().map(|(r, _)| Arc::clone(r));
    let mut admin = if let Some((_, ref server_config)) = tls {
        let listener = TlsListener::new(admin_addr, Arc::clone(server_config));
        let admin_state = Arc::clone(&state);
        tokio::spawn(async move { Server::new(listener).run(admin_app(admin_state)).await })
    } else {
        let admin_state = Arc::clone(&state);
        tokio::spawn(async move {
            Server::new(TcpListener::bind(admin_addr))
                .run(admin_app(admin_state))
                .await
        })
    };

    wait_for_shutdown(
        &mut challenge,
        &mut admin,
        state.as_ref(),
        config_path.as_deref(),
        cert_resolver.as_ref(),
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
    cert_resolver: Option<&Arc<ReloadableCertResolver>>,
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
                if let Some(resolver) = cert_resolver {
                    reload_tls_certs(state, resolver).await;
                }
            }
        }
    }

    Ok(())
}

async fn reload_tls_certs(state: &ResponderState, resolver: &Arc<ReloadableCertResolver>) {
    let settings = state.settings().await;
    let (Some(cert_path), Some(key_path)) = (
        settings.tls_cert_path.clone(),
        settings.tls_key_path.clone(),
    ) else {
        warn!("TLS cert reload skipped: paths not configured after reload");
        return;
    };
    drop(settings);
    match load_certified_key(Path::new(&cert_path), Path::new(&key_path)) {
        Ok(new_key) => {
            resolver.swap(new_key);
            info!("Reloaded TLS certificate from {cert_path}");
        }
        Err(err) => {
            error!("TLS cert reload failed (keeping previous cert): {err}");
        }
    }
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
