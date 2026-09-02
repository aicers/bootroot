use std::path::PathBuf;

use clap::Parser;

use crate::secret::HmacSecret;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Daemon that renews service TLS certificates via ACME and reloads their consumers",
    long_about = None,
)]
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
    pub http_responder_hmac: Option<HmacSecret>,

    /// EAB Key ID (optional, overrides file/config)
    #[arg(long = "eab-kid")]
    pub eab_kid: Option<String>,

    /// EAB HMAC Key (optional, overrides file/config)
    #[arg(long = "eab-hmac")]
    pub eab_hmac: Option<HmacSecret>,

    /// Path to EAB JSON file (optional)
    #[arg(long = "eab-file")]
    pub eab_file: Option<PathBuf>,

    /// Run once and exit (disable daemon loop)
    #[arg(long)]
    pub oneshot: bool,
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;

    /// No supported runtime mode accepts an unverifiable certificate.
    ///
    /// The daemon's TLS trust comes from `[trust]` alone — the
    /// configured CA bundle, its optional pins, or the system roots.
    /// There is no flag that relaxes it, so neither the help text nor
    /// the parser may offer one.
    #[test]
    fn no_flag_disables_certificate_verification() {
        let mut command = Args::command();
        let mut help = Vec::new();
        command.write_long_help(&mut help).expect("write help");
        let help = String::from_utf8(help).expect("help is utf-8");

        assert!(!help.contains("--insecure"));
        assert!(!help.contains("--verify-certificates"));
        assert!(!help.to_lowercase().contains("break-glass"));
    }

    #[test]
    fn insecure_flag_is_rejected() {
        let error = Args::command()
            .try_get_matches_from(["bootroot-agent", "--oneshot", "--insecure"])
            .expect_err("--insecure must not parse");
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}
