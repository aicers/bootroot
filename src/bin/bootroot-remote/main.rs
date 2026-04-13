mod agent_config;
mod apply_secret_id;
mod bootstrap;
mod io;
mod summary;
mod validation;

use std::path::PathBuf;

use anyhow::{Context, Result};
use bootroot::locale::Locale;
use bootroot::trust_bootstrap::{
    CA_BUNDLE_PEM_KEY, EAB_HMAC_KEY, EAB_KID_KEY, HMAC_KEY, SECRET_ID_KEY, SERVICE_KV_BASE,
    TRUSTED_CA_KEY,
};
use clap::{Parser, ValueEnum};

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
    /// Bootstrap artifact JSON file (overrides per-field flags)
    #[arg(long)]
    artifact: Option<PathBuf>,

    /// `OpenBao` base URL
    #[arg(long, env = "OPENBAO_URL", default_value = "")]
    openbao_url: String,

    /// `OpenBao` KV mount (v2)
    #[arg(long, default_value = "secret", env = "OPENBAO_KV_MOUNT")]
    kv_mount: String,

    /// Service name
    #[arg(long, default_value = "")]
    service_name: String,

    /// `AppRole` `role_id` file path used for `OpenBao` login
    #[arg(long)]
    role_id_path: Option<PathBuf>,

    /// Destination path for rotated `secret_id`
    #[arg(long)]
    secret_id_path: Option<PathBuf>,

    /// Destination path for EAB JSON (kid/hmac)
    #[arg(long)]
    eab_file_path: Option<PathBuf>,

    /// bootroot-agent config path to update
    #[arg(long)]
    agent_config_path: Option<PathBuf>,

    /// bootroot-agent email for baseline config generation
    #[arg(long, default_value = DEFAULT_AGENT_EMAIL)]
    agent_email: String,

    /// bootroot-agent ACME server URL for baseline config generation
    ///
    /// The default points to same-host step-ca and should be treated as a
    /// placeholder on true remote service machines.
    #[arg(long, default_value = DEFAULT_AGENT_SERVER)]
    agent_server: String,

    /// bootroot-agent domain for baseline config generation
    #[arg(long, default_value = DEFAULT_AGENT_DOMAIN)]
    agent_domain: String,

    /// HTTP-01 responder admin URL for baseline config generation
    ///
    /// The default points to a same-host responder and should be treated as a
    /// placeholder on true remote service machines.
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

    /// CA bundle output path for the managed step-ca trust bundle
    #[arg(long)]
    ca_bundle_path: Option<PathBuf>,

    /// Post-renew success hook command
    #[arg(long)]
    post_renew_command: Option<String>,

    /// Post-renew success hook argument (repeatable)
    #[arg(long)]
    post_renew_arg: Vec<String>,

    /// Post-renew success hook timeout in seconds
    #[arg(long)]
    post_renew_timeout_secs: Option<u64>,

    /// Post-renew success hook failure policy (continue or stop)
    #[arg(long, value_enum)]
    post_renew_on_failure: Option<HookFailurePolicy>,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    output: OutputFormat,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum HookFailurePolicy {
    Continue,
    Stop,
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

/// Resolved bootstrap args where all required fields are present.
struct ResolvedBootstrapArgs {
    openbao_url: String,
    kv_mount: String,
    service_name: String,
    role_id_path: PathBuf,
    secret_id_path: PathBuf,
    eab_file_path: PathBuf,
    agent_config_path: PathBuf,
    agent_email: String,
    agent_server: String,
    agent_domain: String,
    agent_responder_url: String,
    profile_hostname: String,
    profile_instance_id: Option<String>,
    profile_cert_path: Option<PathBuf>,
    profile_key_path: Option<PathBuf>,
    ca_bundle_path: PathBuf,
    post_renew_command: Option<String>,
    post_renew_arg: Vec<String>,
    post_renew_timeout_secs: Option<u64>,
    post_renew_on_failure: Option<HookFailurePolicy>,
    output: OutputFormat,
    wrap_token: Option<String>,
    wrap_expires_at: Option<String>,
}

async fn run(args: Args, lang: Locale) -> Result<i32> {
    match args.command {
        Command::Bootstrap(args) => {
            let resolved = resolve_bootstrap_args(*args, lang)?;
            bootstrap::run_bootstrap(resolved, lang).await
        }
        Command::ApplySecretId(args) => apply_secret_id::run_apply_secret_id(args, lang).await,
    }
}

/// Parsed bootstrap artifact for loading from `--artifact <path>`.
#[derive(serde::Deserialize)]
struct ParsedArtifact {
    openbao_url: String,
    #[serde(default)]
    kv_mount: String,
    service_name: String,
    role_id_path: String,
    secret_id_path: String,
    eab_file_path: String,
    agent_config_path: String,
    ca_bundle_path: String,
    #[serde(default)]
    agent_email: String,
    #[serde(default)]
    agent_server: String,
    #[serde(default)]
    agent_domain: String,
    #[serde(default)]
    agent_responder_url: String,
    #[serde(default)]
    profile_hostname: String,
    #[serde(default)]
    profile_instance_id: Option<String>,
    #[serde(default)]
    profile_cert_path: Option<String>,
    #[serde(default)]
    profile_key_path: Option<String>,
    #[serde(default)]
    post_renew_hooks: Vec<ParsedHook>,
    #[serde(default)]
    wrap_token: Option<String>,
    #[serde(default)]
    wrap_expires_at: Option<String>,
}

#[derive(serde::Deserialize)]
struct ParsedHook {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_hook_timeout")]
    timeout_secs: u64,
    #[serde(default)]
    on_failure: String,
}

fn default_hook_timeout() -> u64 {
    30
}

#[allow(clippy::too_many_lines)]
fn resolve_bootstrap_args(args: BootstrapArgs, lang: Locale) -> Result<ResolvedBootstrapArgs> {
    let err_required = || {
        localized(
            lang,
            "Required field missing (provide --artifact or individual flags)",
            "필수 필드가 누락되었습니다 (--artifact 또는 개별 플래그를 제공하세요)",
        )
    };

    if let Some(artifact_path) = &args.artifact {
        let content = std::fs::read_to_string(artifact_path).with_context(|| {
            localized(
                lang,
                &format!("Failed to read artifact: {}", artifact_path.display()),
                &format!(
                    "아티팩트 파일을 읽지 못했습니다: {}",
                    artifact_path.display()
                ),
            )
        })?;
        let p: ParsedArtifact = serde_json::from_str(&content).with_context(|| {
            localized(
                lang,
                "Failed to parse bootstrap artifact JSON",
                "부트스트랩 아티팩트 JSON 파싱에 실패했습니다",
            )
        })?;
        let mut resolved = ResolvedBootstrapArgs {
            openbao_url: p.openbao_url,
            kv_mount: if p.kv_mount.is_empty() {
                args.kv_mount
            } else {
                p.kv_mount
            },
            service_name: p.service_name,
            role_id_path: PathBuf::from(p.role_id_path),
            secret_id_path: PathBuf::from(p.secret_id_path),
            eab_file_path: PathBuf::from(p.eab_file_path),
            agent_config_path: PathBuf::from(p.agent_config_path),
            ca_bundle_path: PathBuf::from(p.ca_bundle_path),
            agent_email: if p.agent_email.is_empty() {
                args.agent_email
            } else {
                p.agent_email
            },
            agent_server: if p.agent_server.is_empty() {
                args.agent_server
            } else {
                p.agent_server
            },
            agent_domain: if p.agent_domain.is_empty() {
                args.agent_domain
            } else {
                p.agent_domain
            },
            agent_responder_url: if p.agent_responder_url.is_empty() {
                args.agent_responder_url
            } else {
                p.agent_responder_url
            },
            profile_hostname: if p.profile_hostname.is_empty() {
                args.profile_hostname
            } else {
                p.profile_hostname
            },
            profile_instance_id: p.profile_instance_id.or(args.profile_instance_id),
            profile_cert_path: p
                .profile_cert_path
                .map(PathBuf::from)
                .or(args.profile_cert_path),
            profile_key_path: p
                .profile_key_path
                .map(PathBuf::from)
                .or(args.profile_key_path),
            post_renew_command: args.post_renew_command,
            post_renew_arg: args.post_renew_arg,
            post_renew_timeout_secs: args.post_renew_timeout_secs,
            post_renew_on_failure: args.post_renew_on_failure,
            output: args.output,
            wrap_token: p.wrap_token,
            wrap_expires_at: p.wrap_expires_at,
        };
        if let Some(hook) = p.post_renew_hooks.first() {
            resolved.post_renew_command = Some(hook.command.clone());
            resolved.post_renew_arg.clone_from(&hook.args);
            resolved.post_renew_timeout_secs = Some(hook.timeout_secs);
            if hook.on_failure == "stop" {
                resolved.post_renew_on_failure = Some(HookFailurePolicy::Stop);
            }
        }
        return Ok(resolved);
    }

    Ok(ResolvedBootstrapArgs {
        openbao_url: args.openbao_url,
        kv_mount: args.kv_mount,
        service_name: args.service_name,
        role_id_path: args
            .role_id_path
            .ok_or_else(|| anyhow::anyhow!("{}", err_required()))?,
        secret_id_path: args
            .secret_id_path
            .ok_or_else(|| anyhow::anyhow!("{}", err_required()))?,
        eab_file_path: args
            .eab_file_path
            .ok_or_else(|| anyhow::anyhow!("{}", err_required()))?,
        agent_config_path: args
            .agent_config_path
            .ok_or_else(|| anyhow::anyhow!("{}", err_required()))?,
        ca_bundle_path: args
            .ca_bundle_path
            .ok_or_else(|| anyhow::anyhow!("{}", err_required()))?,
        agent_email: args.agent_email,
        agent_server: args.agent_server,
        agent_domain: args.agent_domain,
        agent_responder_url: args.agent_responder_url,
        profile_hostname: args.profile_hostname,
        profile_instance_id: args.profile_instance_id,
        profile_cert_path: args.profile_cert_path,
        profile_key_path: args.profile_key_path,
        post_renew_command: args.post_renew_command,
        post_renew_arg: args.post_renew_arg,
        post_renew_timeout_secs: args.post_renew_timeout_secs,
        post_renew_on_failure: args.post_renew_on_failure,
        output: args.output,
        wrap_token: None,
        wrap_expires_at: None,
    })
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

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

    #[test]
    fn bootstrap_help_describes_localhost_defaults_as_placeholders() {
        let mut command = Args::command();
        let bootstrap = command
            .find_subcommand_mut("bootstrap")
            .expect("bootstrap subcommand");
        let mut help = Vec::new();
        bootstrap
            .write_long_help(&mut help)
            .expect("write long help");
        let help = String::from_utf8(help).expect("help is utf-8");

        assert!(help.contains("same-host step-ca"));
        assert!(help.contains("placeholder on true remote service machines"));
        assert!(help.contains("--agent-server"));
        assert!(help.contains("--agent-responder-url"));
    }
}
