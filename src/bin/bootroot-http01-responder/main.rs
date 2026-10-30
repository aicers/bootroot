//! Runs the Bootroot HTTP-01 responder through focused internal modules.

mod cleanup;
mod config;
mod handlers;
mod server;
mod signature;
mod state;
mod tls;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::LevelFilter;

use self::config::Args;

#[tokio::main]
async fn main() -> Result<()> {
    bootroot::tls::install_crypto_provider();
    // WARN by default, so a refused TLS handshake reaches the container log
    // without configuration. `RUST_LOG` still overrides.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::WARN.into())
                .from_env_lossy(),
        )
        .init();
    server::run(Args::parse()).await
}
