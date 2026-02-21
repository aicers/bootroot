use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;
use clap::{Parser, ValueEnum};
use serde::Serialize;
use tokio::fs;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CliLang {
    En,
    Ko,
}

impl CliLang {
    fn parse(input: &str) -> Result<Self> {
        match input.trim().to_ascii_lowercase().as_str() {
            "en" => Ok(Self::En),
            "ko" => Ok(Self::Ko),
            _ => anyhow::bail!("Unsupported language code '{input}'. Supported values: en, ko"),
        }
    }
}

fn localized(lang: CliLang, en: &str, ko: &str) -> String {
    match lang {
        CliLang::En => en.to_string(),
        CliLang::Ko => ko.to_string(),
    }
}

fn summary_header(lang: CliLang) -> &'static str {
    match lang {
        CliLang::En => "bootroot-remote bootstrap summary",
        CliLang::Ko => "bootroot-remote 부트스트랩 요약",
    }
}

fn redacted_error_label(lang: CliLang) -> &'static str {
    match lang {
        CliLang::En => "error",
        CliLang::Ko => "오류",
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
    #[arg(long, default_value = "")]
    profile_instance_id: String,

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

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum ApplyStatus {
    Applied,
    Unchanged,
    Failed,
}

#[derive(Debug, Serialize)]
struct ApplyItemSummary {
    status: ApplyStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl ApplyItemSummary {
    fn applied(status: ApplyStatus) -> Self {
        Self {
            status,
            error: None,
        }
    }

    fn failed(error: String) -> Self {
        Self {
            status: ApplyStatus::Failed,
            error: Some(error),
        }
    }
}

#[derive(Debug, Serialize)]
struct ApplySummary {
    secret_id: ApplyItemSummary,
    eab: ApplyItemSummary,
    responder_hmac: ApplyItemSummary,
    trust_sync: ApplyItemSummary,
}

impl ApplySummary {
    fn has_failures(&self) -> bool {
        [
            self.secret_id.status,
            self.eab.status,
            self.responder_hmac.status,
            self.trust_sync.status,
        ]
        .into_iter()
        .any(|status| matches!(status, ApplyStatus::Failed))
    }
}

#[derive(Debug)]
struct PulledSecrets {
    secret_id: String,
    eab_kid: String,
    eab_hmac: String,
    responder_hmac: String,
    trusted_ca_sha256: Vec<String>,
    ca_bundle_pem: Option<String>,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let lang = match CliLang::parse(&args.lang) {
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

async fn run(args: Args, lang: CliLang) -> Result<i32> {
    match args.command {
        Command::Bootstrap(args) => run_bootstrap(*args, lang).await,
        Command::ApplySecretId(args) => run_apply_secret_id(args, lang).await,
    }
}

// This function intentionally keeps end-to-end bootstrap orchestration in one place
// so status aggregation and exit-code semantics stay easy to audit.
#[allow(clippy::too_many_lines)]
async fn run_bootstrap(args: BootstrapArgs, lang: CliLang) -> Result<i32> {
    validate_bootstrap_args(&args, lang)?;

    let role_id = read_secret_file(&args.role_id_path, lang)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to read role_id from {}",
                    args.role_id_path.display()
                ),
                &format!(
                    "role_id 파일을 읽지 못했습니다: {}",
                    args.role_id_path.display()
                ),
            )
        })?;
    let current_secret_id = read_secret_file(&args.secret_id_path, lang)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to read current secret_id from {}",
                    args.secret_id_path.display()
                ),
                &format!(
                    "현재 secret_id 파일을 읽지 못했습니다: {}",
                    args.secret_id_path.display()
                ),
            )
        })?;

    let mut client = OpenBaoClient::new(&args.openbao_url).with_context(|| {
        localized(
            lang,
            "Failed to create OpenBao client",
            "OpenBao 클라이언트를 생성하지 못했습니다",
        )
    })?;
    let token = client
        .login_approle(&role_id, &current_secret_id)
        .await
        .with_context(|| {
            localized(
                lang,
                "OpenBao AppRole login failed",
                "OpenBao AppRole 로그인에 실패했습니다",
            )
        })?;
    client.set_token(token);

    let pulled = pull_secrets(&client, &args.kv_mount, &args.service_name, lang).await?;
    let secret_id_status = match write_secret_file(&args.secret_id_path, &pulled.secret_id).await {
        Ok(status) => ApplyItemSummary::applied(status),
        Err(err) => ApplyItemSummary::failed(localized(
            lang,
            &format!("secret_id apply failed: {err}"),
            &format!("secret_id 반영 실패: {err}"),
        )),
    };
    let eab_status =
        match write_eab_file(&args.eab_file_path, &pulled.eab_kid, &pulled.eab_hmac).await {
            Ok(status) => ApplyItemSummary::applied(status),
            Err(err) => ApplyItemSummary::failed(localized(
                lang,
                &format!("eab apply failed: {err}"),
                &format!("eab 반영 실패: {err}"),
            )),
        };

    let (responder_hmac_status, mut trust_sync_status) =
        apply_agent_config_updates(&args, &pulled, lang).await;

    if let Some(bundle_path) = args.ca_bundle_path.as_deref() {
        match pulled.ca_bundle_pem.as_deref() {
            Some(pem) => match write_secret_file(bundle_path, pem).await {
                Ok(bundle_status) => {
                    trust_sync_status = merge_apply_status(trust_sync_status, bundle_status, None);
                }
                Err(err) => {
                    trust_sync_status = ApplyItemSummary::failed(localized(
                        lang,
                        &format!("ca bundle apply failed ({}): {err}", bundle_path.display()),
                        &format!("ca bundle 반영 실패 ({}): {err}", bundle_path.display()),
                    ));
                }
            },
            None => {
                trust_sync_status = ApplyItemSummary::failed(localized(
                    lang,
                    &format!(
                        "trust data missing {CA_BUNDLE_PEM_KEY} while --ca-bundle-path was provided"
                    ),
                    &format!(
                        "--ca-bundle-path가 지정되었지만 trust 데이터에 {CA_BUNDLE_PEM_KEY}가 없습니다"
                    ),
                ));
            }
        }
    }

    let summary = ApplySummary {
        secret_id: secret_id_status,
        eab: eab_status,
        responder_hmac: responder_hmac_status,
        trust_sync: trust_sync_status,
    };
    print_summary(&summary, args.output, lang)?;
    if summary.has_failures() {
        return Ok(1);
    }
    Ok(0)
}

#[allow(clippy::too_many_lines)]
async fn run_apply_secret_id(args: ApplySecretIdArgs, lang: CliLang) -> Result<i32> {
    if args.service_name.trim().is_empty() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                "--service-name must not be empty",
                "--service-name 값은 비어 있으면 안 됩니다",
            )
        );
    }
    let role_id = read_secret_file(&args.role_id_path, lang)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to read role_id from {}",
                    args.role_id_path.display()
                ),
                &format!(
                    "role_id 파일을 읽지 못했습니다: {}",
                    args.role_id_path.display()
                ),
            )
        })?;
    let current_secret_id = read_secret_file(&args.secret_id_path, lang)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to read current secret_id from {}",
                    args.secret_id_path.display()
                ),
                &format!(
                    "현재 secret_id 파일을 읽지 못했습니다: {}",
                    args.secret_id_path.display()
                ),
            )
        })?;

    let mut client = OpenBaoClient::new(&args.openbao_url).with_context(|| {
        localized(
            lang,
            "Failed to create OpenBao client",
            "OpenBao 클라이언트를 생성하지 못했습니다",
        )
    })?;
    let token = client
        .login_approle(&role_id, &current_secret_id)
        .await
        .with_context(|| {
            localized(
                lang,
                "OpenBao AppRole login failed",
                "OpenBao AppRole 로그인에 실패했습니다",
            )
        })?;
    client.set_token(token);

    let kv_path = format!("{SERVICE_KV_BASE}/{}/secret_id", args.service_name);
    let data = client
        .read_kv(&args.kv_mount, &kv_path)
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service secret_id from OpenBao",
                "OpenBao에서 서비스 secret_id를 읽지 못했습니다",
            )
        })?;
    let new_secret_id = read_required_string(&data, &[SECRET_ID_KEY, "value"], lang)?;
    let status = write_secret_file(&args.secret_id_path, &new_secret_id)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to write secret_id to {}",
                    args.secret_id_path.display()
                ),
                &format!(
                    "secret_id 파일을 쓰지 못했습니다: {}",
                    args.secret_id_path.display()
                ),
            )
        })?;

    match args.output {
        OutputFormat::Text => {
            let label = match status {
                ApplyStatus::Applied => "applied",
                ApplyStatus::Unchanged => "unchanged",
                ApplyStatus::Failed => "failed",
            };
            println!(
                "{}",
                localized(
                    lang,
                    &format!("secret_id: {label}"),
                    &format!("secret_id: {label}"),
                )
            );
        }
        OutputFormat::Json => {
            let payload = serde_json::to_string_pretty(
                &serde_json::json!({ "secret_id": status_to_str(status) }),
            )?;
            println!("{payload}");
        }
    }
    Ok(0)
}

// This function intentionally centralizes agent config mutation flow so
// per-item status/error mapping remains consistent for summary JSON contracts.
#[allow(clippy::too_many_lines)]
async fn apply_agent_config_updates(
    args: &BootstrapArgs,
    pulled: &PulledSecrets,
    lang: CliLang,
) -> (ApplyItemSummary, ApplyItemSummary) {
    let profile_paths = resolve_profile_paths(args);
    let agent_config = match fs::read_to_string(&args.agent_config_path).await {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            render_agent_config_baseline(args, &profile_paths.cert_path, &profile_paths.key_path)
        }
        Err(err) => {
            let message = localized(
                lang,
                &format!(
                    "agent config read failed ({}): {err}",
                    args.agent_config_path.display()
                ),
                &format!(
                    "agent.toml 읽기 실패 ({}): {err}",
                    args.agent_config_path.display()
                ),
            );
            return (
                ApplyItemSummary::failed(message.clone()),
                ApplyItemSummary::failed(message),
            );
        }
    };
    let with_profile = upsert_managed_profile_block(
        &agent_config,
        &args.service_name,
        &render_managed_profile_block(
            &args.service_name,
            &args.profile_instance_id,
            &args.profile_hostname,
            &profile_paths.cert_path,
            &profile_paths.key_path,
        ),
    );

    let acme_pairs = vec![("http_responder_hmac", pulled.responder_hmac.clone())];
    let hmac_updated = upsert_toml_section_keys(&with_profile, "acme", &acme_pairs);
    let trust_pairs =
        build_trust_updates(&pulled.trusted_ca_sha256, args.ca_bundle_path.as_deref());
    let trust_updated = upsert_toml_section_keys(&hmac_updated, "trust", &trust_pairs);

    let responder_changed = hmac_updated != with_profile;
    let trust_changed = trust_updated != hmac_updated;
    let profile_changed = with_profile != agent_config;

    let mut responder_hmac_status = ApplyItemSummary::applied(if responder_changed {
        ApplyStatus::Applied
    } else {
        ApplyStatus::Unchanged
    });
    let mut trust_sync_status = ApplyItemSummary::applied(if trust_changed {
        ApplyStatus::Applied
    } else {
        ApplyStatus::Unchanged
    });

    if trust_updated != agent_config {
        if let Some(parent) = args.agent_config_path.parent()
            && let Err(err) = fs_util::ensure_secrets_dir(parent).await
        {
            let message = localized(
                lang,
                &format!(
                    "agent config parent mkdir failed ({}): {err}",
                    parent.display()
                ),
                &format!(
                    "agent.toml 상위 디렉터리 생성 실패 ({}): {err}",
                    parent.display()
                ),
            );
            return (
                ApplyItemSummary::failed(message.clone()),
                ApplyItemSummary::failed(message),
            );
        }
        if let Err(err) = fs::write(&args.agent_config_path, &trust_updated).await {
            let message = localized(
                lang,
                &format!(
                    "agent config write failed ({}): {err}",
                    args.agent_config_path.display()
                ),
                &format!(
                    "agent.toml 쓰기 실패 ({}): {err}",
                    args.agent_config_path.display()
                ),
            );
            if responder_changed {
                responder_hmac_status = ApplyItemSummary::failed(message.clone());
            }
            if trust_changed {
                trust_sync_status = ApplyItemSummary::failed(message);
            }
            return (responder_hmac_status, trust_sync_status);
        }
        if let Err(err) = fs_util::set_key_permissions(&args.agent_config_path).await {
            let message = localized(
                lang,
                &format!(
                    "agent config chmod failed ({}): {err}",
                    args.agent_config_path.display()
                ),
                &format!(
                    "agent.toml 권한 설정 실패 ({}): {err}",
                    args.agent_config_path.display()
                ),
            );
            if responder_changed {
                responder_hmac_status = ApplyItemSummary::failed(message.clone());
            }
            if trust_changed {
                trust_sync_status = ApplyItemSummary::failed(message);
            }
            return (responder_hmac_status, trust_sync_status);
        }
    }
    if let Err(err) = write_openbao_agent_artifacts(args, &trust_updated, lang).await {
        let message = localized(
            lang,
            &format!("openbao agent setup failed: {err}"),
            &format!("OpenBao Agent 설정 준비 실패: {err}"),
        );
        if responder_changed || profile_changed {
            responder_hmac_status = ApplyItemSummary::failed(message.clone());
        }
        if trust_changed || profile_changed {
            trust_sync_status = ApplyItemSummary::failed(message);
        }
    }

    (responder_hmac_status, trust_sync_status)
}

fn merge_apply_status(
    current: ApplyItemSummary,
    next: ApplyStatus,
    next_error: Option<String>,
) -> ApplyItemSummary {
    if matches!(current.status, ApplyStatus::Failed) {
        return current;
    }
    if matches!(next, ApplyStatus::Failed) {
        return ApplyItemSummary {
            status: next,
            error: next_error,
        };
    }
    if matches!(current.status, ApplyStatus::Applied) || matches!(next, ApplyStatus::Applied) {
        return ApplyItemSummary::applied(ApplyStatus::Applied);
    }
    ApplyItemSummary::applied(ApplyStatus::Unchanged)
}

fn validate_bootstrap_args(args: &BootstrapArgs, lang: CliLang) -> Result<()> {
    if args.service_name.trim().is_empty() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                "--service-name must not be empty",
                "--service-name 값은 비어 있으면 안 됩니다",
            )
        );
    }
    for path in [
        &args.role_id_path,
        &args.secret_id_path,
        &args.eab_file_path,
    ] {
        let parent = path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                localized(
                    lang,
                    &format!("Path {} has no parent directory", path.display()),
                    &format!("경로의 상위 디렉터리가 없습니다: {}", path.display()),
                )
            )
        })?;
        if !parent.exists() {
            anyhow::bail!(
                "{}",
                localized(
                    lang,
                    &format!("Parent directory not found: {}", parent.display()),
                    &format!("상위 디렉터리를 찾을 수 없습니다: {}", parent.display()),
                )
            );
        }
    }
    if !args.role_id_path.exists() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                &format!("role_id file not found: {}", args.role_id_path.display()),
                &format!(
                    "role_id 파일을 찾을 수 없습니다: {}",
                    args.role_id_path.display()
                ),
            )
        );
    }
    if !args.secret_id_path.exists() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                &format!(
                    "secret_id file not found: {}",
                    args.secret_id_path.display()
                ),
                &format!(
                    "secret_id 파일을 찾을 수 없습니다: {}",
                    args.secret_id_path.display()
                ),
            )
        );
    }
    Ok(())
}

async fn read_secret_file(path: &Path, lang: CliLang) -> Result<String> {
    let value = fs::read_to_string(path).await?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                &format!("Secret file is empty: {}", path.display()),
                &format!("시크릿 파일이 비어 있습니다: {}", path.display()),
            )
        );
    }
    Ok(trimmed.to_string())
}

async fn pull_secrets(
    client: &OpenBaoClient,
    mount: &str,
    service: &str,
    lang: CliLang,
) -> Result<PulledSecrets> {
    let base = format!("{SERVICE_KV_BASE}/{service}");
    let secret_id_data = client
        .read_kv(mount, &format!("{base}/secret_id"))
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service secret_id from OpenBao",
                "OpenBao에서 서비스 secret_id를 읽지 못했습니다",
            )
        })?;
    let eab_data = client
        .read_kv(mount, &format!("{base}/eab"))
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service eab from OpenBao",
                "OpenBao에서 서비스 eab를 읽지 못했습니다",
            )
        })?;
    let hmac_data = client
        .read_kv(mount, &format!("{base}/http_responder_hmac"))
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service responder hmac from OpenBao",
                "OpenBao에서 서비스 responder hmac를 읽지 못했습니다",
            )
        })?;
    let trust_data = client
        .read_kv(mount, &format!("{base}/trust"))
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service trust data from OpenBao",
                "OpenBao에서 서비스 trust 데이터를 읽지 못했습니다",
            )
        })?;

    let secret_id = read_required_string(&secret_id_data, &[SECRET_ID_KEY, "value"], lang)?;
    let eab_kid = read_required_string(&eab_data, &[EAB_KID_KEY], lang)?;
    let eab_hmac = read_required_string(&eab_data, &[EAB_HMAC_KEY], lang)?;
    let responder_hmac =
        read_required_string(&hmac_data, &[HMAC_KEY, "http_responder_hmac"], lang)?;
    let trusted_ca_sha256 = read_required_fingerprints(&trust_data, lang)?;
    let ca_bundle_pem = trust_data
        .get(CA_BUNDLE_PEM_KEY)
        .and_then(serde_json::Value::as_str)
        .map(ToString::to_string);

    Ok(PulledSecrets {
        secret_id,
        eab_kid,
        eab_hmac,
        responder_hmac,
        trusted_ca_sha256,
        ca_bundle_pem,
    })
}

fn read_required_string(data: &serde_json::Value, keys: &[&str], lang: CliLang) -> Result<String> {
    for key in keys {
        if let Some(value) = data.get(key).and_then(serde_json::Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    anyhow::bail!(
        "{}",
        localized(
            lang,
            &format!("Missing required string key: {}", keys.join("|")),
            &format!("필수 문자열 키가 없습니다: {}", keys.join("|")),
        )
    )
}

fn read_required_fingerprints(data: &serde_json::Value, lang: CliLang) -> Result<Vec<String>> {
    let values = data
        .get(TRUSTED_CA_KEY)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                localized(
                    lang,
                    &format!("Missing required array key: {TRUSTED_CA_KEY}"),
                    &format!("필수 배열 키가 없습니다: {TRUSTED_CA_KEY}"),
                )
            )
        })?;
    if values.is_empty() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                &format!("{TRUSTED_CA_KEY} must not be empty"),
                &format!("{TRUSTED_CA_KEY} 값은 비어 있으면 안 됩니다"),
            )
        );
    }
    let mut fingerprints = Vec::with_capacity(values.len());
    for value in values {
        let fingerprint = value.as_str().ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                localized(
                    lang,
                    &format!("{TRUSTED_CA_KEY} must contain strings"),
                    &format!("{TRUSTED_CA_KEY} 배열은 문자열만 포함해야 합니다"),
                )
            )
        })?;
        if fingerprint.len() != 64 || !fingerprint.chars().all(|ch| ch.is_ascii_hexdigit()) {
            anyhow::bail!(
                "{}",
                localized(
                    lang,
                    &format!("{TRUSTED_CA_KEY} must be 64 hex chars"),
                    &format!("{TRUSTED_CA_KEY} 값은 64자리 hex여야 합니다"),
                )
            );
        }
        fingerprints.push(fingerprint.to_string());
    }
    Ok(fingerprints)
}

fn build_trust_updates(
    fingerprints: &[String],
    ca_bundle_path: Option<&Path>,
) -> Vec<(&'static str, String)> {
    let mut updates = Vec::new();
    if let Some(path) = ca_bundle_path {
        updates.push(("ca_bundle_path", path.display().to_string()));
    }
    updates.push((
        TRUSTED_CA_KEY,
        format!(
            "[{}]",
            fingerprints
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ));
    updates
}

async fn write_secret_file(path: &Path, contents: &str) -> Result<ApplyStatus> {
    if let Some(parent) = path.parent() {
        fs_util::ensure_secrets_dir(parent).await?;
    }
    let next = if contents.ends_with('\n') {
        contents.to_string()
    } else {
        format!("{contents}\n")
    };
    let current = if path.exists() {
        fs::read_to_string(path).await.unwrap_or_default()
    } else {
        String::new()
    };
    if current == next {
        fs_util::set_key_permissions(path).await?;
        return Ok(ApplyStatus::Unchanged);
    }
    fs::write(path, next).await?;
    fs_util::set_key_permissions(path).await?;
    Ok(ApplyStatus::Applied)
}

async fn write_eab_file(path: &Path, kid: &str, hmac: &str) -> Result<ApplyStatus> {
    let payload = serde_json::to_string_pretty(&serde_json::json!({
        "kid": kid,
        "hmac": hmac
    }))?;
    write_secret_file(path, &payload).await
}

fn upsert_toml_section_keys(contents: &str, section: &str, pairs: &[(&str, String)]) -> String {
    let mut output = String::new();
    let mut section_found = false;
    let mut in_section = false;
    let mut seen_keys = std::collections::BTreeSet::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if is_section_header(trimmed) {
            if in_section {
                output.push_str(&render_missing_keys(pairs, &seen_keys));
            }
            in_section = trimmed == format!("[{section}]");
            if in_section {
                section_found = true;
                seen_keys.clear();
            }
            output.push_str(line);
            output.push('\n');
            continue;
        }

        if in_section
            && let Some((key, indent)) = parse_key_line(line, pairs)
            && let Some(value) = pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| value.as_str())
        {
            output.push_str(&format_key_line(&indent, key, value));
            seen_keys.insert(key.to_string());
            continue;
        }

        output.push_str(line);
        output.push('\n');
    }

    if in_section {
        output.push_str(&render_missing_keys(pairs, &seen_keys));
    }

    if !section_found {
        if !output.ends_with('\n') {
            output.push('\n');
        }
        output.push('[');
        output.push_str(section);
        output.push_str("]\n");
        for (key, value) in pairs {
            output.push_str(&format_key_line("", key, value));
        }
    }

    output
}

struct ProfilePaths {
    cert_path: PathBuf,
    key_path: PathBuf,
}

fn resolve_profile_paths(args: &BootstrapArgs) -> ProfilePaths {
    let fallback_dir = args
        .agent_config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("certs");
    let cert_path = args
        .profile_cert_path
        .clone()
        .unwrap_or_else(|| fallback_dir.join(format!("{}.crt", args.service_name)));
    let key_path = args
        .profile_key_path
        .clone()
        .unwrap_or_else(|| fallback_dir.join(format!("{}.key", args.service_name)));
    ProfilePaths {
        cert_path,
        key_path,
    }
}

fn render_agent_config_baseline(args: &BootstrapArgs, cert_path: &Path, key_path: &Path) -> String {
    let profile_block = render_managed_profile_block(
        &args.service_name,
        &args.profile_instance_id,
        &args.profile_hostname,
        cert_path,
        key_path,
    );
    format!(
        "email = \"{email}\"\n\
server = \"{server}\"\n\
domain = \"{domain}\"\n\n\
[acme]\n\
directory_fetch_attempts = 10\n\
directory_fetch_base_delay_secs = 1\n\
directory_fetch_max_delay_secs = 10\n\
poll_attempts = 15\n\
poll_interval_secs = 2\n\
http_responder_url = \"{responder_url}\"\n\
http_responder_hmac = \"\"\n\
http_responder_timeout_secs = 5\n\
http_responder_token_ttl_secs = 300\n\n\
{profile_block}",
        email = args.agent_email,
        server = args.agent_server,
        domain = args.agent_domain,
        responder_url = args.agent_responder_url,
    )
}

fn render_managed_profile_block(
    service_name: &str,
    instance_id: &str,
    hostname: &str,
    cert_path: &Path,
    key_path: &Path,
) -> String {
    format!(
        "{MANAGED_PROFILE_BEGIN_PREFIX} {service_name}\n\
[[profiles]]\n\
service_name = \"{service_name}\"\n\
instance_id = \"{instance_id}\"\n\
hostname = \"{hostname}\"\n\n\
[profiles.paths]\n\
cert = \"{cert}\"\n\
key = \"{key}\"\n\
{MANAGED_PROFILE_END_PREFIX} {service_name}\n",
        cert = cert_path.display(),
        key = key_path.display(),
    )
}

fn upsert_managed_profile_block(contents: &str, service_name: &str, replacement: &str) -> String {
    let begin_marker = format!("{MANAGED_PROFILE_BEGIN_PREFIX} {service_name}");
    let end_marker = format!("{MANAGED_PROFILE_END_PREFIX} {service_name}");
    if let Some(begin) = contents.find(&begin_marker)
        && let Some(end_relative) = contents[begin..].find(&end_marker)
    {
        let end = begin + end_relative + end_marker.len();
        let suffix = contents[end..]
            .strip_prefix('\n')
            .unwrap_or(&contents[end..]);
        let mut updated = String::new();
        updated.push_str(&contents[..begin]);
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(replacement);
        if !suffix.is_empty() && !replacement.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(suffix);
        return updated;
    }
    let mut updated = contents.trim_end().to_string();
    if !updated.is_empty() {
        updated.push_str("\n\n");
    }
    updated.push_str(replacement);
    updated
}

async fn write_openbao_agent_artifacts(
    args: &BootstrapArgs,
    agent_template: &str,
    lang: CliLang,
) -> Result<()> {
    let secret_service_dir = args.secret_id_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "secret_id path has no parent",
                "secret_id 경로에 상위 디렉터리가 없습니다",
            )
        )
    })?;
    let secrets_services_dir = secret_service_dir.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "secret_id path missing services directory",
                "secret_id 경로에 services 디렉터리가 없습니다",
            )
        )
    })?;
    let secrets_dir = secrets_services_dir.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "secret_id path missing secrets root",
                "secret_id 경로에 secrets 루트가 없습니다",
            )
        )
    })?;
    let openbao_service_dir = secrets_dir
        .join("openbao")
        .join("services")
        .join(&args.service_name);
    fs_util::ensure_secrets_dir(&openbao_service_dir).await?;

    let template_path = openbao_service_dir.join("agent.toml.ctmpl");
    let token_path = openbao_service_dir.join("token");
    let config_path = openbao_service_dir.join("agent.hcl");

    fs::write(&template_path, agent_template).await?;
    fs_util::set_key_permissions(&template_path).await?;
    if !token_path.exists() {
        fs::write(&token_path, "").await?;
    }
    fs_util::set_key_permissions(&token_path).await?;
    let config = render_openbao_agent_config(
        &args.role_id_path,
        &args.secret_id_path,
        &token_path,
        &template_path,
        &args.agent_config_path,
    );
    fs::write(&config_path, config).await?;
    fs_util::set_key_permissions(&config_path).await?;
    Ok(())
}

fn render_openbao_agent_config(
    role_id_path: &Path,
    secret_id_path: &Path,
    token_path: &Path,
    template_path: &Path,
    destination_path: &Path,
) -> String {
    format!(
        r#"auto_auth {{
  method "approle" {{
    mount_path = "auth/approle"
    config = {{
      role_id_file_path = "{role_id_path}"
      secret_id_file_path = "{secret_id_path}"
    }}
  }}
  sink "file" {{
    config = {{
      path = "{token_path}"
    }}
  }}
}}

template {{
  source = "{template_path}"
  destination = "{destination_path}"
  perms = "0600"
}}
"#,
        role_id_path = role_id_path.display(),
        secret_id_path = secret_id_path.display(),
        token_path = token_path.display(),
        template_path = template_path.display(),
        destination_path = destination_path.display(),
    )
}

fn parse_key_line<'a>(line: &'a str, pairs: &[(&'a str, String)]) -> Option<(&'a str, String)> {
    for (key, _) in pairs {
        let trimmed = line.trim_start();
        if trimmed.starts_with(&format!("{key} =")) || trimmed.starts_with(&format!("{key}=")) {
            let indent = line
                .chars()
                .take_while(|ch| ch.is_whitespace())
                .collect::<String>();
            return Some((key, indent));
        }
    }
    None
}

fn render_missing_keys(
    pairs: &[(&str, String)],
    seen_keys: &std::collections::BTreeSet<String>,
) -> String {
    let mut output = String::new();
    for (key, value) in pairs {
        if !seen_keys.contains(*key) {
            output.push_str(&format_key_line("", key, value));
        }
    }
    output
}

fn format_key_line(indent: &str, key: &str, value: &str) -> String {
    if value.starts_with('[') {
        format!("{indent}{key} = {value}\n")
    } else {
        format!("{indent}{key} = \"{value}\"\n")
    }
}

fn is_section_header(value: &str) -> bool {
    value.starts_with('[') && value.ends_with(']')
}

fn print_text_summary(summary: &ApplySummary, lang: CliLang) {
    println!("{}", summary_header(lang));
    println!("- secret_id: {}", status_to_str(summary.secret_id.status));
    print_optional_error("secret_id", summary.secret_id.error.as_deref(), lang);
    println!("- eab: {}", status_to_str(summary.eab.status));
    print_optional_error("eab", summary.eab.error.as_deref(), lang);
    println!(
        "- responder_hmac: {}",
        status_to_str(summary.responder_hmac.status)
    );
    print_optional_error(
        "responder_hmac",
        summary.responder_hmac.error.as_deref(),
        lang,
    );
    println!("- trust_sync: {}", status_to_str(summary.trust_sync.status));
    print_optional_error("trust_sync", summary.trust_sync.error.as_deref(), lang);
}

fn status_to_str(status: ApplyStatus) -> &'static str {
    match status {
        ApplyStatus::Applied => "applied",
        ApplyStatus::Unchanged => "unchanged",
        ApplyStatus::Failed => "failed",
    }
}

fn print_optional_error(name: &str, error: Option<&str>, lang: CliLang) {
    if let Some(_value) = error {
        println!("  {}({name}): <redacted>", redacted_error_label(lang));
    }
}

fn print_summary(summary: &ApplySummary, output: OutputFormat, lang: CliLang) -> Result<()> {
    match output {
        OutputFormat::Text => {
            print_text_summary(summary, lang);
            Ok(())
        }
        OutputFormat::Json => {
            let payload = serde_json::to_string_pretty(summary)?;
            println!("{payload}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_required_fingerprints_accepts_valid_values() {
        let data = serde_json::json!({
            "trusted_ca_sha256": ["a".repeat(64), "b".repeat(64)]
        });
        let parsed =
            read_required_fingerprints(&data, CliLang::En).expect("parse trust fingerprints");
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn test_cli_lang_parse_en_and_ko() {
        assert_eq!(CliLang::parse("en").expect("parse en"), CliLang::En);
        assert_eq!(CliLang::parse("ko").expect("parse ko"), CliLang::Ko);
        assert_eq!(CliLang::parse("EN").expect("parse EN"), CliLang::En);
    }

    #[test]
    fn test_cli_lang_parse_invalid_fails() {
        let err = CliLang::parse("jp").expect_err("invalid lang should fail");
        assert!(
            err.to_string().contains("Unsupported language code"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_summary_header_localization() {
        assert_eq!(
            summary_header(CliLang::En),
            "bootroot-remote bootstrap summary"
        );
        assert_eq!(
            summary_header(CliLang::Ko),
            "bootroot-remote 부트스트랩 요약"
        );
    }

    #[test]
    fn test_upsert_toml_section_keys_updates_existing_section() {
        let input = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let output =
            upsert_toml_section_keys(input, "acme", &[("http_responder_hmac", "new".to_string())]);
        assert!(output.contains("http_responder_hmac = \"new\""));
    }

    #[test]
    fn test_upsert_toml_section_keys_adds_new_section() {
        let input = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let output = upsert_toml_section_keys(
            input,
            "trust",
            &[("ca_bundle_path", "certs/ca.pem".to_string())],
        );
        assert!(output.contains("[trust]"));
        assert!(output.contains("ca_bundle_path = \"certs/ca.pem\""));
    }

    #[test]
    fn test_merge_apply_status_prefers_failed_state() {
        let current = ApplyItemSummary::failed("failed".to_string());
        let merged = merge_apply_status(current, ApplyStatus::Applied, None);
        assert!(matches!(merged.status, ApplyStatus::Failed));
    }
}
