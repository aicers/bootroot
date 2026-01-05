use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{debug, error, info};

use crate::config::{HookCommand, HookFailurePolicy, Settings};

const DEFAULT_RETRY_LOG_LABEL: &str = "post_renew";
const ENV_CERT_PATH: &str = "CERT_PATH";
const ENV_KEY_PATH: &str = "KEY_PATH";
const ENV_DOMAINS: &str = "DOMAINS";
const ENV_PRIMARY_DOMAIN: &str = "PRIMARY_DOMAIN";
const ENV_RENEWED_AT: &str = "RENEWED_AT";
const ENV_RENEW_STATUS: &str = "RENEW_STATUS";
const ENV_RENEW_ERROR: &str = "RENEW_ERROR";
const ENV_SERVER_URL: &str = "ACME_SERVER_URL";

#[derive(Debug, Clone, Copy)]
pub enum HookStatus {
    Success,
    Failure,
}

impl HookStatus {
    fn as_str(self) -> &'static str {
        match self {
            HookStatus::Success => "success",
            HookStatus::Failure => "failure",
        }
    }
}

/// Runs post-renew hooks for the selected status.
///
/// # Errors
/// Returns error when a hook fails and its policy is set to stop.
pub async fn run_post_renew_hooks(
    settings: &Settings,
    status: HookStatus,
    error_message: Option<String>,
) -> anyhow::Result<()> {
    let hooks = match status {
        HookStatus::Success => &settings.hooks.post_renew.success,
        HookStatus::Failure => &settings.hooks.post_renew.failure,
    };

    if hooks.is_empty() {
        return Ok(());
    }

    let renewed_at = time::OffsetDateTime::now_utc();
    let context = HookContext {
        status,
        error_message,
        renewed_at,
    };

    for hook in hooks {
        match run_hook_with_retry(hook, &context, settings).await {
            Ok(()) => {}
            Err(err) => {
                error!("Post-renew hook failed (command='{}'): {err}", hook.command);
                if hook.on_failure == HookFailurePolicy::Stop {
                    return Err(err);
                }
            }
        }
    }

    Ok(())
}

struct HookContext {
    status: HookStatus,
    error_message: Option<String>,
    renewed_at: time::OffsetDateTime,
}

impl HookContext {
    fn envs(&self, settings: &Settings) -> Vec<(String, String)> {
        let primary_domain = settings.domains.first().map_or("", String::as_str);
        vec![
            (
                ENV_CERT_PATH.to_string(),
                settings.paths.cert.display().to_string(),
            ),
            (
                ENV_KEY_PATH.to_string(),
                settings.paths.key.display().to_string(),
            ),
            (ENV_DOMAINS.to_string(), settings.domains.join(",")),
            (ENV_PRIMARY_DOMAIN.to_string(), primary_domain.to_string()),
            (
                ENV_RENEWED_AT.to_string(),
                self.renewed_at
                    .format(&time::format_description::well_known::Rfc3339)
                    .unwrap_or_else(|_| self.renewed_at.to_string()),
            ),
            (
                ENV_RENEW_STATUS.to_string(),
                self.status.as_str().to_string(),
            ),
            (
                ENV_RENEW_ERROR.to_string(),
                self.error_message.clone().unwrap_or_default(),
            ),
            (ENV_SERVER_URL.to_string(), settings.server.clone()),
        ]
    }
}

async fn run_hook_with_retry(
    hook: &HookCommand,
    context: &HookContext,
    settings: &Settings,
) -> anyhow::Result<()> {
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let result = run_hook_command(hook, context, settings).await;
        match result {
            Ok(()) => return Ok(()),
            Err(err) => {
                let remaining = hook.retry_backoff_secs.len().saturating_sub(attempt - 1);
                error!(
                    "Hook attempt {attempt} failed (command='{}', remaining_retries={}): {err}",
                    hook.command, remaining
                );
                if attempt > hook.retry_backoff_secs.len() {
                    return Err(err);
                }
                let delay = hook.retry_backoff_secs[attempt - 1];
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        }
    }
}

async fn run_hook_command(
    hook: &HookCommand,
    context: &HookContext,
    settings: &Settings,
) -> anyhow::Result<()> {
    info!(
        "Running post-renew hook ({}): {} {:?}",
        DEFAULT_RETRY_LOG_LABEL, hook.command, hook.args
    );

    let mut command = Command::new(&hook.command);
    command
        .args(&hook.args)
        .envs(context.envs(settings))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn hook command '{}': {e}", hook.command))?;

    let timeout = Duration::from_secs(hook.timeout_secs);
    let stdout_handle = tokio::spawn(read_stream(child.stdout.take()));
    let stderr_handle = tokio::spawn(read_stream(child.stderr.take()));

    let status = tokio::time::timeout(timeout, child.wait()).await;
    if let Ok(result) = status {
        let status = result.map_err(|e| anyhow::anyhow!("Hook command failed: {e}"))?;
        let stdout = stdout_handle
            .await
            .map_err(|e| anyhow::anyhow!("Hook stdout task failed: {e}"))??;
        let stderr = stderr_handle
            .await
            .map_err(|e| anyhow::anyhow!("Hook stderr task failed: {e}"))??;
        if !stdout.trim().is_empty() {
            debug!("Hook stdout: {}", stdout.trim());
        }
        if !stderr.trim().is_empty() {
            debug!("Hook stderr: {}", stderr.trim());
        }
        if status.success() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Hook exited with status: {status}"))
        }
    } else {
        child
            .kill()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to kill timed out hook: {e}"))?;
        let _ = child.wait().await;
        let _ = stdout_handle.await;
        let _ = stderr_handle.await;
        Err(anyhow::anyhow!(
            "Hook timed out after {} seconds",
            hook.timeout_secs
        ))
    }
}

async fn read_stream<R>(stream: Option<R>) -> anyhow::Result<String>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let Some(mut stream) = stream else {
        return Ok(String::new());
    };

    let mut buffer = String::new();
    stream
        .read_to_string(&mut buffer)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read hook output: {e}"))?;
    Ok(buffer)
}
