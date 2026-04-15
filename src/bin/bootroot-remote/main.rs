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
    /// Path to the bootstrap artifact JSON file.
    ///
    /// When provided, artifact values take precedence over per-field CLI
    /// flags. CLI flags serve as fallbacks for fields absent from the
    /// artifact. This avoids exposing sensitive wrap tokens in shell
    /// command lines.
    #[arg(long)]
    artifact: Option<PathBuf>,

    /// `OpenBao` base URL
    #[arg(long, env = "OPENBAO_URL", required_unless_present = "artifact")]
    openbao_url: Option<String>,

    /// `OpenBao` KV mount (v2)
    #[arg(long, default_value = "secret", env = "OPENBAO_KV_MOUNT")]
    kv_mount: String,

    /// Service name
    #[arg(long, required_unless_present = "artifact")]
    service_name: Option<String>,

    /// `AppRole` `role_id` file path used for `OpenBao` login
    #[arg(long, required_unless_present = "artifact")]
    role_id_path: Option<PathBuf>,

    /// Destination path for rotated `secret_id`
    #[arg(long, required_unless_present = "artifact")]
    secret_id_path: Option<PathBuf>,

    /// Destination path for EAB JSON (kid/hmac)
    #[arg(long, required_unless_present = "artifact")]
    eab_file_path: Option<PathBuf>,

    /// bootroot-agent config path to update
    #[arg(long, required_unless_present = "artifact")]
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
    #[arg(long, required_unless_present = "artifact")]
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

/// Resolved bootstrap arguments with all required fields populated
/// from either CLI flags or the artifact file.
#[derive(Debug)]
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
    ca_bundle_pem: Option<String>,
    post_renew_command: Option<String>,
    post_renew_arg: Vec<String>,
    post_renew_timeout_secs: Option<u64>,
    post_renew_on_failure: Option<HookFailurePolicy>,
    output: OutputFormat,
    wrap_token: Option<String>,
    wrap_expires_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
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

async fn run(args: Args, lang: Locale) -> Result<i32> {
    match args.command {
        Command::Bootstrap(args) => {
            let resolved = resolve_bootstrap_args(*args).await?;
            bootstrap::run_bootstrap(resolved, lang).await
        }
        Command::ApplySecretId(args) => apply_secret_id::run_apply_secret_id(args, lang).await,
    }
}

/// Lowest `schema_version` that this binary understands.
const MIN_SUPPORTED_SCHEMA_VERSION: u32 = 1;

/// Highest `schema_version` that this binary understands.
const MAX_SUPPORTED_SCHEMA_VERSION: u32 = 2;

/// Minimal header used for the first stage of artifact parsing so that
/// `schema_version` can be validated before attempting full deserialization.
#[derive(serde::Deserialize)]
struct ArtifactHeader {
    schema_version: u32,
}

/// Bootstrap artifact JSON schema (subset relevant to bootroot-remote).
#[derive(serde::Deserialize)]
#[allow(dead_code)] // Fields parsed from JSON; not all read directly
struct BootstrapArtifact {
    schema_version: u32,
    openbao_url: String,
    kv_mount: String,
    service_name: String,
    role_id_path: String,
    secret_id_path: String,
    eab_file_path: String,
    agent_config_path: String,
    #[serde(default)]
    agent_email: Option<String>,
    #[serde(default)]
    agent_server: Option<String>,
    #[serde(default)]
    agent_domain: Option<String>,
    #[serde(default)]
    agent_responder_url: Option<String>,
    #[serde(default)]
    profile_hostname: Option<String>,
    #[serde(default)]
    profile_instance_id: Option<String>,
    #[serde(default)]
    profile_cert_path: Option<String>,
    #[serde(default)]
    profile_key_path: Option<String>,
    #[serde(default)]
    ca_bundle_path: Option<String>,
    #[serde(default)]
    ca_bundle_pem: Option<String>,
    #[serde(default)]
    post_renew_hooks: Vec<ArtifactHookEntry>,
    #[serde(default)]
    wrap_token: Option<String>,
    #[serde(default)]
    wrap_expires_at: Option<String>,
}

/// Hook entry as serialized in the bootstrap artifact JSON.
#[derive(serde::Deserialize)]
struct ArtifactHookEntry {
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default = "default_artifact_hook_timeout")]
    timeout_secs: u64,
    #[serde(default)]
    on_failure: ArtifactHookFailurePolicy,
}

#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "snake_case")]
enum ArtifactHookFailurePolicy {
    #[default]
    Continue,
    Stop,
}

fn default_artifact_hook_timeout() -> u64 {
    30
}

#[allow(clippy::too_many_lines)]
async fn resolve_bootstrap_args(args: BootstrapArgs) -> Result<ResolvedBootstrapArgs> {
    let artifact = if let Some(path) = &args.artifact {
        let contents = tokio::fs::read_to_string(path)
            .await
            .with_context(|| format!("Failed to read artifact file: {}", path.display()))?;

        // Stage 1: extract only schema_version so we can reject unsupported
        // versions before full deserialization (a future schema may remove or
        // rename fields, causing a confusing serde error).
        let header: ArtifactHeader = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse artifact file: {}", path.display()))?;
        if header.schema_version < MIN_SUPPORTED_SCHEMA_VERSION
            || header.schema_version > MAX_SUPPORTED_SCHEMA_VERSION
        {
            anyhow::bail!(
                "Artifact schema_version {} is not supported \
                 (supported range: {}..={}). \
                 Upgrade bootroot-remote to a newer version.",
                header.schema_version,
                MIN_SUPPORTED_SCHEMA_VERSION,
                MAX_SUPPORTED_SCHEMA_VERSION,
            );
        }

        // Stage 2: deserialize the full artifact now that the version is known
        // to be supported.
        let parsed: BootstrapArtifact = serde_json::from_str(&contents)
            .with_context(|| format!("Failed to parse artifact file: {}", path.display()))?;
        Some(parsed)
    } else {
        None
    };

    // Artifact values take precedence when `--artifact` is provided.
    // CLI flags serve as fallbacks for fields absent from the artifact.
    let openbao_url = artifact
        .as_ref()
        .map(|a| a.openbao_url.clone())
        .or(args.openbao_url)
        .ok_or_else(|| anyhow::anyhow!("--openbao-url is required"))?;
    let service_name = artifact
        .as_ref()
        .map(|a| a.service_name.clone())
        .or(args.service_name)
        .ok_or_else(|| anyhow::anyhow!("--service-name is required"))?;
    let role_id_path = artifact
        .as_ref()
        .map(|a| PathBuf::from(&a.role_id_path))
        .or(args.role_id_path)
        .ok_or_else(|| anyhow::anyhow!("--role-id-path is required"))?;
    let secret_id_path = artifact
        .as_ref()
        .map(|a| PathBuf::from(&a.secret_id_path))
        .or(args.secret_id_path)
        .ok_or_else(|| anyhow::anyhow!("--secret-id-path is required"))?;
    let eab_file_path = artifact
        .as_ref()
        .map(|a| PathBuf::from(&a.eab_file_path))
        .or(args.eab_file_path)
        .ok_or_else(|| anyhow::anyhow!("--eab-file-path is required"))?;
    let agent_config_path = artifact
        .as_ref()
        .map(|a| PathBuf::from(&a.agent_config_path))
        .or(args.agent_config_path)
        .ok_or_else(|| anyhow::anyhow!("--agent-config-path is required"))?;
    let ca_bundle_path = artifact
        .as_ref()
        .and_then(|a| a.ca_bundle_path.as_ref().map(PathBuf::from))
        .or(args.ca_bundle_path)
        .ok_or_else(|| anyhow::anyhow!("--ca-bundle-path is required"))?;

    let kv_mount = artifact
        .as_ref()
        .map(|a| a.kv_mount.clone())
        .unwrap_or(args.kv_mount);
    let agent_email = artifact
        .as_ref()
        .and_then(|a| a.agent_email.clone())
        .unwrap_or(args.agent_email);
    let agent_server = artifact
        .as_ref()
        .and_then(|a| a.agent_server.clone())
        .unwrap_or(args.agent_server);
    let agent_domain = artifact
        .as_ref()
        .and_then(|a| a.agent_domain.clone())
        .unwrap_or(args.agent_domain);
    let agent_responder_url = artifact
        .as_ref()
        .and_then(|a| a.agent_responder_url.clone())
        .unwrap_or(args.agent_responder_url);
    let profile_hostname = artifact
        .as_ref()
        .and_then(|a| a.profile_hostname.clone())
        .unwrap_or(args.profile_hostname);
    let profile_instance_id = artifact
        .as_ref()
        .and_then(|a| a.profile_instance_id.clone())
        .or(args.profile_instance_id);
    let profile_cert_path = artifact
        .as_ref()
        .and_then(|a| a.profile_cert_path.as_ref().map(PathBuf::from))
        .or(args.profile_cert_path);
    let profile_key_path = artifact
        .as_ref()
        .and_then(|a| a.profile_key_path.as_ref().map(PathBuf::from))
        .or(args.profile_key_path);

    let ca_bundle_pem = artifact.as_ref().and_then(|a| a.ca_bundle_pem.clone());

    let wrap_token = artifact.as_ref().and_then(|a| a.wrap_token.clone());
    let wrap_expires_at = artifact.as_ref().and_then(|a| a.wrap_expires_at.clone());

    // When an artifact is provided, its `post_renew_hooks` array is
    // authoritative — even if empty (an explicit "no hooks" choice).
    // CLI hook flags are used only when no artifact is given.
    let (post_renew_command, post_renew_arg, post_renew_timeout_secs, post_renew_on_failure) =
        if let Some(a) = artifact.as_ref() {
            if let Some(hook) = a.post_renew_hooks.first() {
                (
                    Some(hook.command.clone()),
                    hook.args.clone(),
                    Some(hook.timeout_secs),
                    Some(match hook.on_failure {
                        ArtifactHookFailurePolicy::Continue => HookFailurePolicy::Continue,
                        ArtifactHookFailurePolicy::Stop => HookFailurePolicy::Stop,
                    }),
                )
            } else {
                (None, Vec::new(), None, None)
            }
        } else {
            (
                args.post_renew_command,
                args.post_renew_arg,
                args.post_renew_timeout_secs,
                args.post_renew_on_failure,
            )
        };

    Ok(ResolvedBootstrapArgs {
        openbao_url,
        kv_mount,
        service_name,
        role_id_path,
        secret_id_path,
        eab_file_path,
        agent_config_path,
        agent_email,
        agent_server,
        agent_domain,
        agent_responder_url,
        profile_hostname,
        profile_instance_id,
        profile_cert_path,
        profile_key_path,
        ca_bundle_path,
        ca_bundle_pem,
        post_renew_command,
        post_renew_arg,
        post_renew_timeout_secs,
        post_renew_on_failure,
        output: args.output,
        wrap_token,
        wrap_expires_at,
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

    /// Writes a minimal artifact JSON to a temp file and returns the path.
    fn write_artifact_file(dir: &std::path::Path, json: &str) -> std::path::PathBuf {
        let path = dir.join("bootstrap.json");
        std::fs::write(&path, json).expect("write artifact");
        path
    }

    #[tokio::test]
    async fn resolve_bootstrap_args_artifact_overrides_cli_flags() {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact_json = serde_json::json!({
            "schema_version": 1,
            "openbao_url": "https://artifact-url:8200",
            "kv_mount": "artifact-kv",
            "service_name": "artifact-svc",
            "role_id_path": "/artifact/role_id",
            "secret_id_path": "/artifact/secret_id",
            "eab_file_path": "/artifact/eab.json",
            "agent_config_path": "/artifact/agent.toml",
            "ca_bundle_path": "/artifact/ca-bundle.pem",
        });
        let artifact_path = write_artifact_file(dir.path(), &artifact_json.to_string());

        let args = BootstrapArgs {
            artifact: Some(artifact_path),
            openbao_url: Some("https://cli-url:8200".to_string()),
            kv_mount: "cli-kv".to_string(),
            service_name: Some("cli-svc".to_string()),
            role_id_path: Some(PathBuf::from("/cli/role_id")),
            secret_id_path: Some(PathBuf::from("/cli/secret_id")),
            eab_file_path: Some(PathBuf::from("/cli/eab.json")),
            agent_config_path: Some(PathBuf::from("/cli/agent.toml")),
            agent_email: "cli@example.com".to_string(),
            agent_server: "https://cli-server".to_string(),
            agent_domain: "cli.domain".to_string(),
            agent_responder_url: "http://cli:8080".to_string(),
            profile_hostname: "cli-host".to_string(),
            profile_instance_id: None,
            profile_cert_path: None,
            profile_key_path: None,
            ca_bundle_path: Some(PathBuf::from("/cli/ca-bundle.pem")),
            post_renew_command: None,
            post_renew_arg: Vec::new(),
            post_renew_timeout_secs: None,
            post_renew_on_failure: None,
            output: OutputFormat::Text,
        };

        let resolved = resolve_bootstrap_args(args).await.expect("resolve");

        // Artifact values must win over CLI flags.
        assert_eq!(resolved.openbao_url, "https://artifact-url:8200");
        assert_eq!(resolved.kv_mount, "artifact-kv");
        assert_eq!(resolved.service_name, "artifact-svc");
        assert_eq!(resolved.role_id_path, PathBuf::from("/artifact/role_id"));
        assert_eq!(
            resolved.secret_id_path,
            PathBuf::from("/artifact/secret_id")
        );
        assert_eq!(resolved.eab_file_path, PathBuf::from("/artifact/eab.json"));
        assert_eq!(
            resolved.agent_config_path,
            PathBuf::from("/artifact/agent.toml")
        );
        assert_eq!(
            resolved.ca_bundle_path,
            PathBuf::from("/artifact/ca-bundle.pem")
        );
    }

    #[tokio::test]
    async fn resolve_bootstrap_args_artifact_hooks_override_cli_hooks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact_json = serde_json::json!({
            "schema_version": 1,
            "openbao_url": "https://ob:8200",
            "kv_mount": "kv",
            "service_name": "svc",
            "role_id_path": "/r",
            "secret_id_path": "/s",
            "eab_file_path": "/e",
            "agent_config_path": "/a",
            "ca_bundle_path": "/ca",
            "post_renew_hooks": [{
                "command": "artifact-cmd",
                "args": ["artifact-arg"],
                "timeout_secs": 120,
                "on_failure": "stop"
            }],
        });
        let artifact_path = write_artifact_file(dir.path(), &artifact_json.to_string());

        let args = BootstrapArgs {
            artifact: Some(artifact_path),
            openbao_url: None,
            kv_mount: "secret".to_string(),
            service_name: None,
            role_id_path: None,
            secret_id_path: None,
            eab_file_path: None,
            agent_config_path: None,
            agent_email: DEFAULT_AGENT_EMAIL.to_string(),
            agent_server: DEFAULT_AGENT_SERVER.to_string(),
            agent_domain: DEFAULT_AGENT_DOMAIN.to_string(),
            agent_responder_url: DEFAULT_AGENT_RESPONDER_URL.to_string(),
            profile_hostname: "localhost".to_string(),
            profile_instance_id: None,
            profile_cert_path: None,
            profile_key_path: None,
            ca_bundle_path: None,
            post_renew_command: Some("cli-cmd".to_string()),
            post_renew_arg: vec!["cli-arg".to_string()],
            post_renew_timeout_secs: Some(30),
            post_renew_on_failure: Some(HookFailurePolicy::Continue),
            output: OutputFormat::Text,
        };

        let resolved = resolve_bootstrap_args(args).await.expect("resolve");

        // Artifact hooks must win over CLI hook flags.
        assert_eq!(resolved.post_renew_command.as_deref(), Some("artifact-cmd"));
        assert_eq!(resolved.post_renew_arg, vec!["artifact-arg".to_string()]);
        assert_eq!(resolved.post_renew_timeout_secs, Some(120));
        assert_eq!(
            resolved.post_renew_on_failure,
            Some(HookFailurePolicy::Stop)
        );
    }

    #[tokio::test]
    async fn resolve_bootstrap_args_artifact_empty_hooks_override_cli_hooks() {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact_json = serde_json::json!({
            "schema_version": 1,
            "openbao_url": "https://ob:8200",
            "kv_mount": "kv",
            "service_name": "svc",
            "role_id_path": "/r",
            "secret_id_path": "/s",
            "eab_file_path": "/e",
            "agent_config_path": "/a",
            "ca_bundle_path": "/ca",
            "post_renew_hooks": [],
        });
        let artifact_path = write_artifact_file(dir.path(), &artifact_json.to_string());

        let args = BootstrapArgs {
            artifact: Some(artifact_path),
            openbao_url: None,
            kv_mount: "secret".to_string(),
            service_name: None,
            role_id_path: None,
            secret_id_path: None,
            eab_file_path: None,
            agent_config_path: None,
            agent_email: DEFAULT_AGENT_EMAIL.to_string(),
            agent_server: DEFAULT_AGENT_SERVER.to_string(),
            agent_domain: DEFAULT_AGENT_DOMAIN.to_string(),
            agent_responder_url: DEFAULT_AGENT_RESPONDER_URL.to_string(),
            profile_hostname: "localhost".to_string(),
            profile_instance_id: None,
            profile_cert_path: None,
            profile_key_path: None,
            ca_bundle_path: None,
            post_renew_command: Some("cli-cmd".to_string()),
            post_renew_arg: vec!["cli-arg".to_string()],
            post_renew_timeout_secs: Some(30),
            post_renew_on_failure: Some(HookFailurePolicy::Continue),
            output: OutputFormat::Text,
        };

        let resolved = resolve_bootstrap_args(args).await.expect("resolve");

        // Artifact explicitly sets empty hooks — CLI hooks must NOT leak
        // through, even though the artifact array is empty.
        assert_eq!(resolved.post_renew_command, None);
        assert!(resolved.post_renew_arg.is_empty());
        assert_eq!(resolved.post_renew_timeout_secs, None);
        assert_eq!(resolved.post_renew_on_failure, None);
    }

    /// Returns `BootstrapArgs` pointing at the given artifact file with all
    /// other fields set to defaults.
    fn default_bootstrap_args(artifact_path: PathBuf) -> BootstrapArgs {
        BootstrapArgs {
            artifact: Some(artifact_path),
            openbao_url: None,
            kv_mount: "secret".to_string(),
            service_name: None,
            role_id_path: None,
            secret_id_path: None,
            eab_file_path: None,
            agent_config_path: None,
            agent_email: DEFAULT_AGENT_EMAIL.to_string(),
            agent_server: DEFAULT_AGENT_SERVER.to_string(),
            agent_domain: DEFAULT_AGENT_DOMAIN.to_string(),
            agent_responder_url: DEFAULT_AGENT_RESPONDER_URL.to_string(),
            profile_hostname: "localhost".to_string(),
            profile_instance_id: None,
            profile_cert_path: None,
            profile_key_path: None,
            ca_bundle_path: None,
            post_renew_command: None,
            post_renew_arg: Vec::new(),
            post_renew_timeout_secs: None,
            post_renew_on_failure: None,
            output: OutputFormat::Text,
        }
    }

    /// Asserts that `resolve_bootstrap_args` rejects the given artifact JSON
    /// with the schema-version error message containing the given version.
    async fn assert_rejects_schema_version(artifact_json: &serde_json::Value, version: u32) {
        let dir = tempfile::tempdir().expect("tempdir");
        let artifact_path = write_artifact_file(dir.path(), &artifact_json.to_string());
        let args = default_bootstrap_args(artifact_path);

        let err = resolve_bootstrap_args(args)
            .await
            .expect_err("should reject unsupported schema");
        let msg = err.to_string();
        let expected = format!("schema_version {version} is not supported");
        assert!(msg.contains(&expected), "unexpected error: {msg}");
        assert!(
            msg.contains("Upgrade bootroot-remote"),
            "should suggest upgrade: {msg}"
        );
    }

    #[tokio::test]
    async fn resolve_bootstrap_args_rejects_future_schema_version() {
        // Artifact with a future schema version whose shape matches today's
        // struct — ensures the header-stage check fires before full parse.
        let artifact_json = serde_json::json!({
            "schema_version": 99,
            "openbao_url": "https://ob:8200",
            "kv_mount": "kv",
            "service_name": "svc",
            "role_id_path": "/r",
            "secret_id_path": "/s",
            "eab_file_path": "/e",
            "agent_config_path": "/a",
        });
        assert_rejects_schema_version(&artifact_json, 99).await;
    }

    #[tokio::test]
    async fn resolve_bootstrap_args_rejects_schema_version_zero() {
        let artifact_json = serde_json::json!({
            "schema_version": 0,
            "openbao_url": "https://ob:8200",
            "kv_mount": "kv",
            "service_name": "svc",
            "role_id_path": "/r",
            "secret_id_path": "/s",
            "eab_file_path": "/e",
            "agent_config_path": "/a",
        });
        assert_rejects_schema_version(&artifact_json, 0).await;
    }

    #[tokio::test]
    async fn resolve_bootstrap_args_rejects_future_schema_with_unknown_fields() {
        // A future v3 artifact that has completely different fields.  Without
        // two-stage parsing, serde would fail with a confusing missing-field
        // error instead of the explicit version rejection.
        let artifact_json = serde_json::json!({
            "schema_version": 3,
            "completely_new_field": true,
        });
        assert_rejects_schema_version(&artifact_json, 3).await;
    }
}
