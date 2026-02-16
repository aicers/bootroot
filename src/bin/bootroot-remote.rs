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

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Pull/apply remote service secrets from OpenBao"
)]
struct Args {
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

    /// CA bundle output path (required when trust data includes `ca_bundle_pem`)
    #[arg(long)]
    ca_bundle_path: Option<PathBuf>,

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
    agent_config_path: String,
    secret_id_path: String,
    eab_file_path: String,
    ca_bundle_path: Option<String>,
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
    match run(args).await {
        Ok(summary) if summary.summary.has_failures() => {
            match summary.output {
                OutputFormat::Text => print_text_summary(&summary.summary),
                OutputFormat::Json => match serde_json::to_string_pretty(&summary.summary) {
                    Ok(payload) => println!("{payload}"),
                    Err(err) => {
                        eprintln!("Failed to serialize summary: {err}");
                    }
                },
            }
            std::process::exit(1);
        }
        Ok(summary) => match summary.output {
            OutputFormat::Text => print_text_summary(&summary.summary),
            OutputFormat::Json => match serde_json::to_string_pretty(&summary.summary) {
                Ok(payload) => println!("{payload}"),
                Err(err) => {
                    eprintln!("Failed to serialize summary: {err}");
                    std::process::exit(1);
                }
            },
        },
        Err(err) => {
            eprintln!("bootroot-remote failed: {err}");
            if let Some(detail) = err.chain().nth(1) {
                eprintln!("details: {detail}");
            }
            std::process::exit(1);
        }
    }
}

struct RunResult {
    summary: ApplySummary,
    output: OutputFormat,
}

async fn run(args: Args) -> Result<RunResult> {
    validate_args(&args)?;

    let role_id = read_secret_file(&args.role_id_path)
        .await
        .with_context(|| {
            format!(
                "Failed to read role_id from {}",
                args.role_id_path.display()
            )
        })?;
    let current_secret_id = read_secret_file(&args.secret_id_path)
        .await
        .with_context(|| {
            format!(
                "Failed to read current secret_id from {}",
                args.secret_id_path.display()
            )
        })?;

    let mut client = OpenBaoClient::new(&args.openbao_url)
        .with_context(|| "Failed to create OpenBao client".to_string())?;
    let token = client
        .login_approle(&role_id, &current_secret_id)
        .await
        .with_context(|| "OpenBao AppRole login failed".to_string())?;
    client.set_token(token);

    let pulled = pull_secrets(&client, &args.kv_mount, &args.service_name).await?;
    let secret_id_status = match write_secret_file(&args.secret_id_path, &pulled.secret_id).await {
        Ok(status) => ApplyItemSummary::applied(status),
        Err(err) => ApplyItemSummary::failed(format!("secret_id apply failed: {err}")),
    };
    let eab_status =
        match write_eab_file(&args.eab_file_path, &pulled.eab_kid, &pulled.eab_hmac).await {
            Ok(status) => ApplyItemSummary::applied(status),
            Err(err) => ApplyItemSummary::failed(format!("eab apply failed: {err}")),
        };

    let (responder_hmac_status, mut trust_sync_status) =
        apply_agent_config_updates(&args, &pulled).await;

    if let Some(bundle_path) = args.ca_bundle_path.as_deref() {
        match pulled.ca_bundle_pem.as_deref() {
            Some(pem) => match write_secret_file(bundle_path, pem).await {
                Ok(bundle_status) => {
                    trust_sync_status = merge_apply_status(trust_sync_status, bundle_status, None);
                }
                Err(err) => {
                    trust_sync_status = ApplyItemSummary::failed(format!(
                        "ca bundle apply failed ({}): {err}",
                        bundle_path.display()
                    ));
                }
            },
            None => {
                trust_sync_status = ApplyItemSummary::failed(format!(
                    "trust data missing {CA_BUNDLE_PEM_KEY} while --ca-bundle-path was provided"
                ));
            }
        }
    }

    let summary = ApplySummary {
        secret_id: secret_id_status,
        eab: eab_status,
        responder_hmac: responder_hmac_status,
        trust_sync: trust_sync_status,
        agent_config_path: args.agent_config_path.display().to_string(),
        secret_id_path: args.secret_id_path.display().to_string(),
        eab_file_path: args.eab_file_path.display().to_string(),
        ca_bundle_path: args.ca_bundle_path.map(|path| path.display().to_string()),
    };

    Ok(RunResult {
        summary,
        output: args.output,
    })
}

async fn apply_agent_config_updates(
    args: &Args,
    pulled: &PulledSecrets,
) -> (ApplyItemSummary, ApplyItemSummary) {
    let agent_config = match fs::read_to_string(&args.agent_config_path).await {
        Ok(contents) => contents,
        Err(err) => {
            let message = format!(
                "agent config read failed ({}): {err}",
                args.agent_config_path.display()
            );
            return (
                ApplyItemSummary::failed(message.clone()),
                ApplyItemSummary::failed(message),
            );
        }
    };

    let acme_pairs = vec![("http_responder_hmac", pulled.responder_hmac.clone())];
    let hmac_updated = upsert_toml_section_keys(&agent_config, "acme", &acme_pairs);
    let trust_pairs =
        build_trust_updates(&pulled.trusted_ca_sha256, args.ca_bundle_path.as_deref());
    let trust_updated = upsert_toml_section_keys(&hmac_updated, "trust", &trust_pairs);

    let responder_changed = hmac_updated != agent_config;
    let trust_changed = trust_updated != hmac_updated;

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
        if let Err(err) = fs::write(&args.agent_config_path, &trust_updated).await {
            let message = format!(
                "agent config write failed ({}): {err}",
                args.agent_config_path.display()
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
            let message = format!(
                "agent config chmod failed ({}): {err}",
                args.agent_config_path.display()
            );
            if responder_changed {
                responder_hmac_status = ApplyItemSummary::failed(message.clone());
            }
            if trust_changed {
                trust_sync_status = ApplyItemSummary::failed(message);
            }
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

fn validate_args(args: &Args) -> Result<()> {
    if args.service_name.trim().is_empty() {
        anyhow::bail!("--service-name must not be empty");
    }
    for path in [
        &args.role_id_path,
        &args.secret_id_path,
        &args.eab_file_path,
        &args.agent_config_path,
    ] {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("Path {} has no parent directory", path.display()))?;
        if !parent.exists() {
            anyhow::bail!("Parent directory not found: {}", parent.display());
        }
    }
    if !args.role_id_path.exists() {
        anyhow::bail!("role_id file not found: {}", args.role_id_path.display());
    }
    if !args.secret_id_path.exists() {
        anyhow::bail!(
            "secret_id file not found: {}",
            args.secret_id_path.display()
        );
    }
    if !args.agent_config_path.exists() {
        anyhow::bail!(
            "agent config file not found: {}",
            args.agent_config_path.display()
        );
    }
    Ok(())
}

async fn read_secret_file(path: &Path) -> Result<String> {
    let value = fs::read_to_string(path).await?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("Secret file is empty: {}", path.display());
    }
    Ok(trimmed.to_string())
}

async fn pull_secrets(client: &OpenBaoClient, mount: &str, service: &str) -> Result<PulledSecrets> {
    let base = format!("{SERVICE_KV_BASE}/{service}");
    let secret_id_data = client
        .read_kv(mount, &format!("{base}/secret_id"))
        .await
        .with_context(|| "Failed to read service secret_id from OpenBao".to_string())?;
    let eab_data = client
        .read_kv(mount, &format!("{base}/eab"))
        .await
        .with_context(|| "Failed to read service eab from OpenBao".to_string())?;
    let hmac_data = client
        .read_kv(mount, &format!("{base}/http_responder_hmac"))
        .await
        .with_context(|| "Failed to read service responder hmac from OpenBao".to_string())?;
    let trust_data = client
        .read_kv(mount, &format!("{base}/trust"))
        .await
        .with_context(|| "Failed to read service trust data from OpenBao".to_string())?;

    let secret_id = read_required_string(&secret_id_data, &[SECRET_ID_KEY, "value"])?;
    let eab_kid = read_required_string(&eab_data, &[EAB_KID_KEY])?;
    let eab_hmac = read_required_string(&eab_data, &[EAB_HMAC_KEY])?;
    let responder_hmac = read_required_string(&hmac_data, &[HMAC_KEY, "http_responder_hmac"])?;
    let trusted_ca_sha256 = read_required_fingerprints(&trust_data)?;
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

fn read_required_string(data: &serde_json::Value, keys: &[&str]) -> Result<String> {
    for key in keys {
        if let Some(value) = data.get(key).and_then(serde_json::Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed.to_string());
            }
        }
    }
    anyhow::bail!("Missing required string key: {}", keys.join("|"))
}

fn read_required_fingerprints(data: &serde_json::Value) -> Result<Vec<String>> {
    let values = data
        .get(TRUSTED_CA_KEY)
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("Missing required array key: {TRUSTED_CA_KEY}"))?;
    if values.is_empty() {
        anyhow::bail!("{TRUSTED_CA_KEY} must not be empty");
    }
    let mut fingerprints = Vec::with_capacity(values.len());
    for value in values {
        let fingerprint = value
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("{TRUSTED_CA_KEY} must contain strings"))?;
        if fingerprint.len() != 64 || !fingerprint.chars().all(|ch| ch.is_ascii_hexdigit()) {
            anyhow::bail!("{TRUSTED_CA_KEY} must be 64 hex chars");
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

fn print_text_summary(summary: &ApplySummary) {
    println!("bootroot-remote sync summary");
    println!("- secret_id: {}", status_to_str(summary.secret_id.status));
    print_optional_error("secret_id", summary.secret_id.error.as_deref());
    println!("- eab: {}", status_to_str(summary.eab.status));
    print_optional_error("eab", summary.eab.error.as_deref());
    println!(
        "- responder_hmac: {}",
        status_to_str(summary.responder_hmac.status)
    );
    print_optional_error("responder_hmac", summary.responder_hmac.error.as_deref());
    println!("- trust_sync: {}", status_to_str(summary.trust_sync.status));
    print_optional_error("trust_sync", summary.trust_sync.error.as_deref());
    println!(
        "- agent_config_path: {}",
        redacted_path_state(&summary.agent_config_path)
    );
    println!(
        "- secret_id_path: {}",
        redacted_path_state(&summary.secret_id_path)
    );
    println!(
        "- eab_file_path: {}",
        redacted_path_state(&summary.eab_file_path)
    );
    println!(
        "- ca_bundle_path: {}",
        if summary.ca_bundle_path.is_some() {
            "<configured>"
        } else {
            "<not configured>"
        }
    );
}

fn status_to_str(status: ApplyStatus) -> &'static str {
    match status {
        ApplyStatus::Applied => "applied",
        ApplyStatus::Unchanged => "unchanged",
        ApplyStatus::Failed => "failed",
    }
}

fn print_optional_error(name: &str, error: Option<&str>) {
    if let Some(_value) = error {
        println!("  error({name}): <redacted>");
    }
}

fn redacted_path_state(value: &str) -> &'static str {
    if value.is_empty() {
        "<not set>"
    } else {
        "<redacted>"
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
        let parsed = read_required_fingerprints(&data).expect("parse trust fingerprints");
        assert_eq!(parsed.len(), 2);
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
