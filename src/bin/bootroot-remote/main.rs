mod agent_config;
mod apply_secret_id;
mod bootstrap;
mod io;
mod summary;
mod validation;

use std::path::PathBuf;

use anyhow::Result;
use bootroot::locale::Locale;
use clap::{Parser, ValueEnum};

const SERVICE_KV_BASE: &str = "bootroot/services";
const SECRET_ID_KEY: &str = "secret_id";
const HMAC_KEY: &str = "hmac";
const EAB_KID_KEY: &str = "kid";
const EAB_HMAC_KEY: &str = "hmac";
const TRUSTED_CA_KEY: &str = "trusted_ca_sha256";
const CA_BUNDLE_PEM_KEY: &str = "ca_bundle_pem";
const MANAGED_PROFILE_BEGIN_PREFIX: &str = "# BEGIN BOOTROOT REMOTE PROFILE";
const MANAGED_PROFILE_END_PREFIX: &str = "# END BOOTROOT REMOTE PROFILE";
const DEFAULT_AGENT_EMAIL: &str = "admin@example.com";
const DEFAULT_AGENT_SERVER: &str = "https://localhost:9000/acme/acme/directory";
const DEFAULT_AGENT_DOMAIN: &str = "trusted.domain";
const DEFAULT_AGENT_RESPONDER_URL: &str = "http://127.0.0.1:8080";

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "One-shot bootstrap and secret_id handoff for remote services"
)]
struct Args {
    /// Language for CLI output (en or ko)
    #[arg(long, env = "BOOTROOT_LANG", default_value = "en", global = true)]
    lang: String,

    #[command(subcommand)]
    command: Command,
}

fn localized(lang: Locale, en: &str, ko: &str) -> String {
    match lang {
        Locale::En => en.to_string(),
        Locale::Ko => ko.to_string(),
    }
}

fn summary_header(lang: Locale) -> &'static str {
    match lang {
        Locale::En => "bootroot-remote bootstrap summary",
        Locale::Ko => "bootroot-remote 부트스트랩 요약",
    }
}

fn redacted_error_label(lang: Locale) -> &'static str {
    match lang {
        Locale::En => "error",
        Locale::Ko => "오류",
    }
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// One-shot bootstrap: pull and apply all service secrets from `OpenBao`
    Bootstrap(Box<BootstrapArgs>),
    /// Apply a rotated `secret_id` from `OpenBao` KV to the local file
    ApplySecretId(ApplySecretIdArgs),
}

#[derive(clap::Args, Debug)]
struct BootstrapArgs {
    /// `OpenBao` base URL
    #[arg(long, env = "OPENBAO_URL")]
    openbao_url: String,

    /// `OpenBao` KV mount (v2)
    #[arg(long, default_value = "secret", env = "OPENBAO_KV_MOUNT")]
    kv_mount: String,

    /// Service name
    #[arg(long)]
    service_name: String,

    /// `AppRole` `role_id` file path used for `OpenBao` login
    #[arg(long)]
    role_id_path: PathBuf,

    /// Destination path for rotated `secret_id`
    #[arg(long)]
    secret_id_path: PathBuf,

    /// Destination path for EAB JSON (kid/hmac)
    #[arg(long)]
    eab_file_path: PathBuf,

    /// bootroot-agent config path to update
    #[arg(long)]
    agent_config_path: PathBuf,

    /// bootroot-agent email for baseline config generation
    #[arg(long, default_value = DEFAULT_AGENT_EMAIL)]
    agent_email: String,

    /// bootroot-agent ACME server URL for baseline config generation
    #[arg(long, default_value = DEFAULT_AGENT_SERVER)]
    agent_server: String,

    /// bootroot-agent domain for baseline config generation
    #[arg(long, default_value = DEFAULT_AGENT_DOMAIN)]
    agent_domain: String,

    /// HTTP-01 responder admin URL for baseline config generation
    #[arg(long, default_value = DEFAULT_AGENT_RESPONDER_URL)]
    agent_responder_url: String,

    /// Service profile hostname for baseline generation
    #[arg(long, default_value = "localhost")]
    profile_hostname: String,

    /// Service profile `instance_id` for baseline generation
    #[arg(long)]
    profile_instance_id: Option<String>,

    /// Service profile cert path for baseline generation
    #[arg(long)]
    profile_cert_path: Option<PathBuf>,

    /// Service profile key path for baseline generation
    #[arg(long)]
    profile_key_path: Option<PathBuf>,

    /// CA bundle output path (required when trust data includes `ca_bundle_pem`)
    #[arg(long)]
    ca_bundle_path: Option<PathBuf>,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(clap::Args, Debug)]
struct ApplySecretIdArgs {
    /// `OpenBao` base URL
    #[arg(long, env = "OPENBAO_URL")]
    openbao_url: String,

    /// `OpenBao` KV mount (v2)
    #[arg(long, default_value = "secret", env = "OPENBAO_KV_MOUNT")]
    kv_mount: String,

    /// Service name
    #[arg(long)]
    service_name: String,

    /// `AppRole` `role_id` file path used for `OpenBao` login
    #[arg(long)]
    role_id_path: PathBuf,

    /// Destination path for `secret_id`
    #[arg(long)]
    secret_id_path: PathBuf,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let lang = match Locale::parse(&args.lang) {
        Ok(lang) => lang,
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(2);
        }
    };
    match run(args, lang).await {
        Ok(exit_code) => {
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Err(err) => {
            eprintln!(
                "{}: {err}",
                localized(lang, "bootroot-remote failed", "bootroot-remote 실행 실패")
            );
            if let Some(detail) = err.chain().nth(1) {
                eprintln!("{}: {detail}", localized(lang, "details", "상세 정보"));
            }
            std::process::exit(1);
        }
    }
}

async fn run(args: Args, lang: Locale) -> Result<i32> {
    match args.command {
        Command::Bootstrap(args) => bootstrap::run_bootstrap(*args, lang).await,
        Command::ApplySecretId(args) => apply_secret_id::run_apply_secret_id(args, lang).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_lang_parse_en_and_ko() {
        assert_eq!(Locale::parse("en").expect("parse en"), Locale::En);
        assert_eq!(Locale::parse("ko").expect("parse ko"), Locale::Ko);
        assert_eq!(Locale::parse("EN").expect("parse EN"), Locale::En);
    }

    #[test]
    fn cli_lang_parse_invalid_fails() {
        let err = Locale::parse("jp").expect_err("invalid lang should fail");
        assert!(
            err.to_string().contains("Unsupported language"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn summary_header_localization() {
        assert_eq!(
            summary_header(Locale::En),
            "bootroot-remote bootstrap summary"
        );
        assert_eq!(
            summary_header(Locale::Ko),
            "bootroot-remote 부트스트랩 요약"
        );
    }
}
