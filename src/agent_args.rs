use std::path::PathBuf;

use clap::{ArgAction, Parser};

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

    /// Force ACME server TLS verification for this run
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "insecure")]
    pub verify_certificates: bool,

    /// Disable TLS certificate verification for this run only (INSECURE break-glass override)
    #[arg(long, action = ArgAction::SetTrue, conflicts_with = "verify_certificates")]
    pub insecure: bool,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    #[test]
    fn help_describes_tls_override_semantics() {
        let mut command = Args::command();
        let mut help = Vec::new();
        command.write_long_help(&mut help).expect("write help");
        let help = String::from_utf8(help).expect("help is utf-8");

        assert!(help.contains("Force ACME server TLS verification for this run"));
        assert!(help.contains("for this run only"));
        assert!(help.contains("break-glass override"));
    }
}
