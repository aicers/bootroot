use std::path::PathBuf;

use clap::Parser;
use tracing::{error, info};

pub mod acme;
pub mod config;
pub mod eab;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to configuration file (default: agent.toml)
    #[arg(long, short)]
    config: Option<PathBuf>,

    /// Support email address
    #[arg(long)]
    email: Option<String>,

    /// Domain to request certificate for
    #[arg(long)]
    domain: Option<String>,

    /// ACME Directory URL
    #[arg(long)]
    ca_url: Option<String>,

    /// EAB Key ID (optional, overrides file/config)
    #[arg(long = "eab-kid")]
    eab_kid: Option<String>,

    /// EAB HMAC Key (optional, overrides file/config)
    #[arg(long = "eab-hmac")]
    eab_hmac: Option<String>,

    /// Path to EAB JSON file (optional)
    #[arg(long = "eab-file")]
    eab_file: Option<PathBuf>,

    /// Path to save the certificate
    #[arg(long)]
    cert_path: Option<PathBuf>,

    /// Path to save the private key
    #[arg(long)]
    key_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    info!("Starting Bootroot Agent (Rust)");

    // 1. Load Settings
    let mut settings = config::Settings::new(args.config.clone())?;

    // 2. Override Config with CLI Args
    settings.merge_with_args(&args);

    // 3. Resolve EAB Credentials
    // Priority: CLI Args > Config File
    let cli_eab = eab::load_credentials(
        args.eab_kid.clone(),
        args.eab_hmac.clone(),
        args.eab_file.clone(),
    )
    .await?;

    let final_eab = cli_eab.or_else(|| {
        settings
            .eab
            .as_ref()
            .map(|cfg_eab| crate::eab::EabCredentials {
                kid: cfg_eab.kid.clone(),
                hmac: cfg_eab.hmac.clone(),
            })
    });

    info!("Target Domains: {:?}", settings.domains);
    info!("CA URL: {}", settings.server);

    if let Some(ref creds) = final_eab {
        info!("Using EAB Credentials for Key ID: {}", creds.kid);
    } else {
        info!("No EAB credentials provided. Attempting open enrollment.");
    }

    // 4. Run ACME Flow
    match acme::issue_certificate(&settings, final_eab).await {
        Ok(()) => info!("Successfully issued certificate!"),
        Err(e) => {
            error!("Failed to issue certificate: {:?}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
