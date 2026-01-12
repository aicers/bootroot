use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};

use crate::VerifyArgs;
use crate::i18n::Messages;
use crate::state::StateFile;

const STATE_FILE_NAME: &str = "state.json";

pub(crate) fn run_verify(args: &VerifyArgs, messages: &Messages) -> Result<()> {
    let state_path = Path::new(STATE_FILE_NAME);
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let state = StateFile::load(state_path)?;
    let entry = state
        .apps
        .get(&args.app_kind)
        .ok_or_else(|| anyhow::anyhow!(messages.error_app_not_found(&args.app_kind)))?;

    let agent_config = args
        .agent_config
        .as_ref()
        .unwrap_or(&entry.agent_config_path);

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

    println!("{}", messages.verify_summary_title());
    println!("{}", messages.verify_app_kind(&entry.app_kind));
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
    println!("{}", messages.verify_result_ok());
    Ok(())
}
