use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to configuration file (default: agent.toml)
    #[arg(long, short)]
    pub config: Option<PathBuf>,

    /// Support email address
    #[arg(long)]
    pub email: Option<String>,

    /// ACME Directory URL
    #[arg(long)]
    pub ca_url: Option<String>,

    /// HTTP-01 responder base URL
    #[arg(long, env = "BOOTROOT_HTTP_RESPONDER_URL")]
    pub http_responder_url: Option<String>,

    /// HTTP-01 responder HMAC secret
    #[arg(long, env = "BOOTROOT_HTTP_RESPONDER_HMAC")]
    pub http_responder_hmac: Option<String>,

    /// EAB Key ID (optional, overrides file/config)
    #[arg(long = "eab-kid")]
    pub eab_kid: Option<String>,

    /// EAB HMAC Key (optional, overrides file/config)
    #[arg(long = "eab-hmac")]
    pub eab_hmac: Option<String>,

    /// Path to EAB JSON file (optional)
    #[arg(long = "eab-file")]
    pub eab_file: Option<PathBuf>,

    /// Run once and exit (disable daemon loop)
    #[arg(long)]
    pub oneshot: bool,
}
