//! Runs the Bootroot HTTP-01 responder through focused internal modules.

mod cleanup;
mod config;
mod handlers;
mod server;
mod signature;
mod state;

use anyhow::Result;
use clap::Parser;

use self::config::Args;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    server::run(Args::parse()).await
}
