use std::future::Future;
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
        let mut envs = base_envs(settings, profile);
        envs.extend(self.context_envs());
        envs
    }

    fn context_envs(&self) -> Vec<(String, String)> {
        vec![
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
        ]
    }
}

fn base_envs(settings: &Settings, profile: &ProfileSettings) -> Vec<(String, String)> {
    let primary_domain = crate::config::profile_domain(settings, profile);
    vec![
        (
            ENV_CERT_PATH.to_string(),
            profile.paths.cert.display().to_string(),
        ),
        (
            ENV_KEY_PATH.to_string(),
            profile.paths.key.display().to_string(),
        ),
        (ENV_DOMAINS.to_string(), primary_domain.clone()),
        (ENV_PRIMARY_DOMAIN.to_string(), primary_domain),
        (ENV_SERVER_URL.to_string(), settings.server.clone()),
    ]
}

async fn run_hook_with_retry(
    hook: &HookCommand,
    context: &HookContext,
    settings: &Settings,
    profile: &ProfileSettings,
) -> anyhow::Result<()> {
    run_with_retry(&hook.retry_backoff_secs, |attempt, remaining| async move {
        let result = run_hook_command(hook, context, settings, profile).await;
        match result {
            Ok(()) => Ok(()),
            Err(err) => {
                error!(
                    "Hook attempt {attempt} failed (command='{}', remaining_retries={}): {err}",
                    hook.command, remaining
                );
                Err(err)
            }
        }
    })
    .await
}

async fn run_with_retry<F, Fut>(backoff: &[u64], mut operation: F) -> anyhow::Result<()>
where
    F: FnMut(usize, usize) -> Fut,
    Fut: Future<Output = anyhow::Result<()>>,
{
    let mut attempt = 0usize;
    loop {
        attempt += 1;
        let remaining = backoff.len().saturating_sub(attempt - 1);
        match operation(attempt, remaining).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                if attempt > backoff.len() {
                    return Err(err);
                }
                let delay = backoff[attempt - 1];
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
    if let Some(working_dir) = &hook.working_dir {
        command.current_dir(working_dir);
    }

    let mut child = command
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn hook command '{}': {e}", hook.command))?;

    let timeout = Duration::from_secs(hook.timeout_secs);
    let stdout_handle = tokio::spawn(read_stream_limited(
        child.stdout.take(),
        hook.max_output_bytes,
    ));
    let stderr_handle = tokio::spawn(read_stream_limited(
        child.stderr.take(),
        hook.max_output_bytes,
    ));

    let status = tokio::time::timeout(timeout, child.wait()).await;
    if let Ok(result) = status {
        let status = result.map_err(|e| anyhow::anyhow!("Hook command failed: {e}"))?;
        let stdout = stdout_handle
            .await
            .map_err(|e| anyhow::anyhow!("Hook stdout task failed: {e}"))??;
        let stderr = stderr_handle
            .await
            .map_err(|e| anyhow::anyhow!("Hook stderr task failed: {e}"))??;
        log_hook_output("stdout", &stdout);
        log_hook_output("stderr", &stderr);
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

fn log_hook_output(label: &str, output: &HookOutput) {
    if !output.text.trim().is_empty() || output.truncated {
        debug!(
            "Hook {label} (bytes={}, truncated={}): {}",
            output.bytes,
            output.truncated,
            output.text.trim()
        );
    }
}

struct HookOutput {
    text: String,
    bytes: usize,
    truncated: bool,
}

async fn read_stream_limited<R>(
    stream: Option<R>,
    max_output_bytes: Option<u64>,
) -> anyhow::Result<HookOutput>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let Some(mut stream) = stream else {
        return Ok(HookOutput {
            text: String::new(),
            bytes: 0,
            truncated: false,
        });
    };

    let max_bytes = max_output_bytes.map_or(usize::MAX, |value| {
        usize::try_from(value).unwrap_or(usize::MAX)
    });
    let mut buf = Vec::new();
    let mut total = 0usize;
    let mut truncated = false;
    let mut chunk = [0u8; 4096];

    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read hook output: {e}"))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read);
        let remaining = max_bytes.saturating_sub(buf.len());
        if remaining == 0 {
            truncated = true;
            break;
        }
        let to_copy = read.min(remaining);
        buf.extend_from_slice(&chunk[..to_copy]);
        if to_copy < read {
            truncated = true;
            break;
        }
    }

    Ok(HookOutput {
        text: String::from_utf8_lossy(&buf).to_string(),
        bytes: total,
        truncated,
    })
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;
    use tokio::io::{AsyncWriteExt, duplex};

    use super::*;
    use crate::config::{
        AcmeSettings, DaemonSettings, HookCommand, HookSettings, Paths, PostRenewHooks,
        ProfileSettings, RetrySettings, SchedulerSettings, Settings,
    };

    const TEST_DOMAIN: &str = "trusted.domain";
    const TEST_SERVER_URL: &str = "https://example.com/acme/directory";
    const TEST_KEY_PATH: &str = "unused.key";
    const EXPECTED_DOMAIN: &str = "001.edge-proxy.edge-node-01.trusted.domain";

    fn build_settings(cert_path: PathBuf, hooks: HookSettings) -> (Settings, ProfileSettings) {
        let profile = ProfileSettings {
            daemon_name: "edge-proxy".to_string(),
            instance_id: "001".to_string(),
            hostname: "edge-node-01".to_string(),
            paths: Paths {
                cert: cert_path,
                key: PathBuf::from(TEST_KEY_PATH),
            },
            daemon: DaemonSettings {
                check_interval: Duration::from_secs(60 * 60),
                renew_before: Duration::from_secs(720 * 60 * 60),
                check_jitter: Duration::from_secs(0),
            },
            retry: None,
            hooks,
            eab: None,
        };

        let settings = Settings {
            email: "test@example.com".to_string(),
            server: TEST_SERVER_URL.to_string(),
            domain: TEST_DOMAIN.to_string(),
            eab: None,
            acme: AcmeSettings {
                directory_fetch_attempts: 10,
                directory_fetch_base_delay_secs: 1,
                directory_fetch_max_delay_secs: 10,
                poll_attempts: 15,
                poll_interval_secs: 2,
                http_responder_url: "http://localhost:8080".to_string(),
                http_responder_hmac: "dev-hmac".to_string(),
                http_responder_timeout_secs: 5,
                http_responder_token_ttl_secs: 300,
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

    #[test]
    fn test_hook_envs_include_generated_domains() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("cert.pem");
        let hooks = HookSettings::default();
        let (settings, profile) = build_settings(cert_path, hooks);

        let envs = super::base_envs(&settings, &profile);
        let domains = envs
            .iter()
            .find(|(key, _)| key == ENV_DOMAINS)
            .map(|(_, value)| value.as_str())
            .unwrap();
        let primary_domain = envs
            .iter()
            .find(|(key, _)| key == ENV_PRIMARY_DOMAIN)
            .map(|(_, value)| value.as_str())
            .unwrap();

        assert_eq!(domains, EXPECTED_DOMAIN);
        assert_eq!(primary_domain, EXPECTED_DOMAIN);
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
            working_dir: None,
            timeout_secs: 5,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
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
            working_dir: None,
            timeout_secs: 5,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
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
            working_dir: None,
            timeout_secs: 5,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
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
            working_dir: None,
            timeout_secs: 1,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
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

    #[tokio::test]
    async fn test_post_renew_hook_respects_working_dir() {
        let dir = tempdir().unwrap();
        let work_dir = dir.path().join("work");
        fs::create_dir_all(&work_dir).unwrap();
        let output_path = work_dir.join("pwd.txt");
        let cert_path = dir.path().join("cert.pem");

        let hook = HookCommand {
            command: "sh".to_string(),
            args: vec!["-c".to_string(), "pwd > pwd.txt".to_string()],
            working_dir: Some(work_dir.clone()),
            timeout_secs: 5,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
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
        let output_dir = PathBuf::from(contents.trim());
        let output_dir = fs::canonicalize(output_dir).unwrap();
        let work_dir = fs::canonicalize(work_dir).unwrap();
        assert_eq!(output_dir, work_dir);
    }

    #[tokio::test]
    async fn test_read_stream_limited_truncates_output() {
        let (mut writer, reader) = duplex(64);
        writer.write_all(b"1234567890").await.unwrap();
        writer.shutdown().await.unwrap();

        let output = read_stream_limited(Some(reader), Some(5)).await.unwrap();

        assert_eq!(output.text, "12345");
        assert!(output.truncated);
        assert_eq!(output.bytes, 10);
    }
}
