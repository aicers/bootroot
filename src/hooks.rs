use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tracing::{debug, error, info};

use crate::config::{HookCommand, HookFailurePolicy, ProfileSettings, Settings};

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
    profile: &ProfileSettings,
    status: HookStatus,
    error_message: Option<String>,
) -> anyhow::Result<()> {
    let hooks = match status {
        HookStatus::Success => &profile.hooks.post_renew.success,
        HookStatus::Failure => &profile.hooks.post_renew.failure,
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
        match run_hook_with_retry(hook, &context, settings, profile).await {
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
    fn envs(&self, settings: &Settings, profile: &ProfileSettings) -> Vec<(String, String)> {
        let primary_domain = profile.domains.first().map_or("", String::as_str);
        vec![
            (
                ENV_CERT_PATH.to_string(),
                profile.paths.cert.display().to_string(),
            ),
            (
                ENV_KEY_PATH.to_string(),
                profile.paths.key.display().to_string(),
            ),
            (ENV_DOMAINS.to_string(), profile.domains.join(",")),
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
    profile: &ProfileSettings,
) -> anyhow::Result<()> {
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let result = run_hook_command(hook, context, settings, profile).await;
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
    profile: &ProfileSettings,
) -> anyhow::Result<()> {
    info!(
        "Running post-renew hook ({}): {} {:?}",
        DEFAULT_RETRY_LOG_LABEL, hook.command, hook.args
    );

    let mut command = Command::new(&hook.command);
    command
        .args(&hook.args)
        .envs(context.envs(settings, profile))
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;

    use super::*;
    use crate::config::{
        AcmeSettings, DaemonSettings, HookCommand, HookSettings, Paths, PostRenewHooks,
        ProfileSettings, RetrySettings, SchedulerSettings, Settings,
    };

    const TEST_DOMAIN: &str = "example.com";
    const TEST_SERVER_URL: &str = "https://example.com/acme/directory";
    const TEST_KEY_PATH: &str = "unused.key";

    fn build_settings(cert_path: PathBuf, hooks: HookSettings) -> (Settings, ProfileSettings) {
        let profile = ProfileSettings {
            name: "edge-proxy-a".to_string(),
            daemon_name: "edge-proxy".to_string(),
            instance_id: "001".to_string(),
            hostname: "edge-node-01".to_string(),
            domains: vec![TEST_DOMAIN.to_string()],
            paths: Paths {
                cert: cert_path,
                key: PathBuf::from(TEST_KEY_PATH),
            },
            daemon: DaemonSettings {
                check_interval: "1h".to_string(),
                renew_before: "720h".to_string(),
                check_jitter: "0s".to_string(),
            },
            hooks,
            eab: None,
        };

        let settings = Settings {
            email: "test@example.com".to_string(),
            server: TEST_SERVER_URL.to_string(),
            spiffe_trust_domain: "trusted.domain".to_string(),
            eab: None,
            acme: AcmeSettings {
                http_challenge_port: 80,
                directory_fetch_attempts: 10,
                directory_fetch_base_delay_secs: 1,
                directory_fetch_max_delay_secs: 10,
                poll_attempts: 15,
                poll_interval_secs: 2,
            },
            retry: RetrySettings {
                backoff_secs: vec![1, 2, 3],
            },
            scheduler: SchedulerSettings {
                max_concurrent_issuances: 1,
            },
            profiles: vec![profile.clone()],
        };

        (settings, profile)
    }

    #[tokio::test]
    async fn test_post_renew_success_hook_writes_status() {
        let dir = tempdir().unwrap();
        let output_path = dir.path().join("hook.txt");
        let cert_path = dir.path().join("cert.pem");

        let hook = HookCommand {
            command: "sh".to_string(),
            args: vec![
                "-c".to_string(),
                format!(
                    "printf \"%s\" \"$RENEW_STATUS\" > \"{}\"",
                    output_path.display()
                ),
            ],
            timeout_secs: 5,
            retry_backoff_secs: Vec::new(),
            on_failure: HookFailurePolicy::Stop,
        };

        let hooks = HookSettings {
            post_renew: PostRenewHooks {
                success: vec![hook],
                failure: Vec::new(),
            },
        };

        let (settings, profile) = build_settings(cert_path, hooks);
        run_post_renew_hooks(&settings, &profile, HookStatus::Success, None)
            .await
            .unwrap();

        let contents = fs::read_to_string(output_path).unwrap();
        assert_eq!(contents, "success");
    }

    #[tokio::test]
    async fn test_post_renew_failure_hook_stop_propagates_error() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");

        let hook = HookCommand {
            command: "false".to_string(),
            args: Vec::new(),
            timeout_secs: 5,
            retry_backoff_secs: Vec::new(),
            on_failure: HookFailurePolicy::Stop,
        };

        let hooks = HookSettings {
            post_renew: PostRenewHooks {
                success: Vec::new(),
                failure: vec![hook],
            },
        };

        let (settings, profile) = build_settings(cert_path, hooks);
        let err = run_post_renew_hooks(
            &settings,
            &profile,
            HookStatus::Failure,
            Some("boom".to_string()),
        )
        .await
        .unwrap_err();

        assert!(err.to_string().contains("Hook exited with status"));
    }

    #[tokio::test]
    async fn test_post_renew_failure_hook_continue_ignores_error() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");

        let hook = HookCommand {
            command: "false".to_string(),
            args: Vec::new(),
            timeout_secs: 5,
            retry_backoff_secs: Vec::new(),
            on_failure: HookFailurePolicy::Continue,
        };

        let hooks = HookSettings {
            post_renew: PostRenewHooks {
                success: Vec::new(),
                failure: vec![hook],
            },
        };

        let (settings, profile) = build_settings(cert_path, hooks);
        run_post_renew_hooks(
            &settings,
            &profile,
            HookStatus::Failure,
            Some("boom".to_string()),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn test_post_renew_hook_timeout_returns_error() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");

        let hook = HookCommand {
            command: "sleep".to_string(),
            args: vec!["2".to_string()],
            timeout_secs: 1,
            retry_backoff_secs: Vec::new(),
            on_failure: HookFailurePolicy::Stop,
        };

        let hooks = HookSettings {
            post_renew: PostRenewHooks {
                success: vec![hook],
                failure: Vec::new(),
            },
        };

        let (settings, profile) = build_settings(cert_path, hooks);
        let err = run_post_renew_hooks(&settings, &profile, HookStatus::Success, None)
            .await
            .unwrap_err();

        assert!(err.to_string().contains("timed out"));
    }
}
