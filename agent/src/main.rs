use std::path::PathBuf;

use clap::Parser;
use tracing::{error, info};

pub mod acme;
pub mod eab;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Support email address
    #[arg(long, default_value = "admin@example.com")]
    email: String,

    /// Domain to request certificate for
    #[arg(long, default_value = "bootroot-agent")]
    domain: String,

    /// ACME Directory URL
    #[arg(long, default_value = "https://localhost:9000/acme/acme/directory")]
    ca_url: String,

    /// EAB Key ID (optional, overrides file)
    #[arg(long = "eab-kid")]
    eab_kid: Option<String>,

    /// EAB HMAC Key (optional, overrides file)
    #[arg(long = "eab-hmac")]
    eab_hmac: Option<String>,

    /// Path to EAB JSON file
    #[arg(long = "eab-file")]
    eab_file: Option<PathBuf>,

    /// Path to save the certificate
    #[arg(long, default_value = "certs/cert.pem")]
    cert_path: PathBuf,

    /// Path to save the private key
    #[arg(long, default_value = "certs/key.pem")]
    key_path: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    info!("Starting Bootroot Agent (Rust)");
    info!("Target Domain: {}", args.domain);
    info!("CA URL: {}", args.ca_url);

    // 1. Load EAB Credentials
    let eab_creds = eab::load_credentials(
        args.eab_kid.clone(),
        args.eab_hmac.clone(),
        args.eab_file.clone(),
    )
    .await?;

    if let Some(ref creds) = eab_creds {
        info!("Loaded EAB Credentials for Key ID: {}", creds.kid);
    } else {
        info!("No EAB credentials provided. Attempting open enrollment.");
    }

    // 2. Run ACME Flow
    match acme::issue_certificate(&args, eab_creds).await {
        Ok(()) => info!("Successfully issued certificate!"),
        Err(e) => {
            error!("Failed to issue certificate: {:?}", e);
            std::process::exit(1);
        }
    }

    Ok(())
}
