use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use bootroot::db::{check_tcp_sync, parse_db_dsn};

use crate::VerifyArgs;
use crate::cli::output::print_verify_plan;
use crate::cli::prompt::Prompt;
use crate::i18n::Messages;
use crate::state::StateFile;

const STATE_FILE_NAME: &str = "state.json";

pub(crate) fn run_verify(args: &VerifyArgs, messages: &Messages) -> Result<()> {
    let state_path = Path::new(STATE_FILE_NAME);
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let state = StateFile::load(state_path)?;
    let service_name = resolve_verify_service_name(args, messages)?;
    let entry = state
        .apps
        .get(&service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_app_not_found(&service_name)))?;

    let agent_config = args
        .agent_config
        .as_ref()
        .unwrap_or(&entry.agent_config_path);

    print_verify_plan(&entry.service_name, agent_config, messages);

    let status = Command::new("bootroot-agent")
        .args([
            "--config",
            agent_config.to_string_lossy().as_ref(),
            "--oneshot",
        ])
        .status()
        .context("Failed to run bootroot-agent")?;

    if !status.success() {
        anyhow::bail!(messages.verify_agent_failed());
    }

    if !entry.cert_path.exists() {
        anyhow::bail!(messages.verify_missing_cert(&entry.cert_path.display().to_string()));
    }
    if !entry.key_path.exists() {
        anyhow::bail!(messages.verify_missing_key(&entry.key_path.display().to_string()));
    }

    if args.db_check {
        verify_db_connectivity(&state, args.db_timeout_secs, messages)?;
    }

    println!("{}", messages.verify_summary_title());
    println!("{}", messages.verify_service_name(&entry.service_name));
    println!(
        "{}",
        messages.verify_agent_config(&agent_config.display().to_string())
    );
    println!(
        "{}",
        messages.verify_cert_path(&entry.cert_path.display().to_string())
    );
    println!(
        "{}",
        messages.verify_key_path(&entry.key_path.display().to_string())
    );
    if args.db_check {
        println!("{}", messages.summary_db_check_ok());
    }
    println!("{}", messages.verify_result_ok());
    Ok(())
}

fn verify_db_connectivity(state: &StateFile, timeout_secs: u64, messages: &Messages) -> Result<()> {
    let secrets_dir = state
        .secrets_dir()
        .canonicalize()
        .context("Failed to resolve secrets dir")?;
    let ca_path = secrets_dir.join("config").join("ca.json");
    let contents = std::fs::read_to_string(&ca_path)
        .with_context(|| format!("Failed to read {}", ca_path.display()))?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).context("Failed to parse ca.json")?;
    let db_type = value["db"]["type"].as_str().unwrap_or_default();
    if db_type != "postgresql" {
        anyhow::bail!(messages.error_db_type_unsupported());
    }
    let dsn = value["db"]["dataSource"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let parsed =
        parse_db_dsn(&dsn).map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
    let timeout = std::time::Duration::from_secs(timeout_secs);
    check_tcp_sync(&parsed.host, parsed.port, timeout)
        .with_context(|| messages.error_db_check_failed())?;
    Ok(())
}

fn resolve_verify_service_name(args: &VerifyArgs, messages: &Messages) -> Result<String> {
    if let Some(value) = args.service_name.clone() {
        if value.trim().is_empty() {
            anyhow::bail!(messages.error_value_required());
        }
        return Ok(value);
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout().lock();
    let mut prompt = Prompt::new(&mut input, &mut output);
    prompt.prompt_with_validation(messages.prompt_service_name(), None, |value| {
        if value.trim().is_empty() {
            anyhow::bail!(messages.error_value_required());
        }
        Ok(value.trim().to_string())
    })
}
