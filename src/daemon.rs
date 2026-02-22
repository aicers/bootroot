use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use tokio::sync::{Semaphore, watch};
use tracing::{error, info};

use crate::{acme, config, eab, hooks, profile, utils};

pub const MIN_DAEMON_CHECK_DELAY_NANOS: i128 = utils::MIN_JITTER_DELAY_NANOS;
const DEFAULT_AGENT_CONFIG_PATH: &str = "agent.toml";
const TRUST_SECTION: &str = "trust";
const VERIFY_CERTIFICATES_KEY: &str = "verify_certificates";
const VERIFY_CERTIFICATES_TRUE: &str = "true";

#[derive(Clone)]
struct HardeningPolicy {
    config_path: PathBuf,
    insecure_mode: bool,
}

/// Runs the agent daemon loop for all profiles.
///
/// # Errors
/// Returns an error if issuance or shutdown handling fails.
pub async fn run_daemon(
    settings: Arc<config::Settings>,
    default_eab: Option<eab::EabCredentials>,
    config_path: Option<PathBuf>,
    insecure_mode: bool,
) -> anyhow::Result<()> {
    let max_concurrent = profile::max_concurrent_issuances(&settings)?;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let hardening = HardeningPolicy {
        config_path: resolve_config_path(config_path.as_deref()),
        insecure_mode,
    };

    let shutdown_handle = tokio::spawn(async move {
        if let Err(err) = wait_for_shutdown().await {
            error!("Shutdown signal handler error: {err}");
        }
        let _ = shutdown_tx.send(true);
    });

    let mut handles = Vec::new();
    for profile in settings.profiles.clone() {
        let settings = Arc::clone(&settings);
        let semaphore = Arc::clone(&semaphore);
        let shutdown_rx = shutdown_rx.clone();
        let default_eab = default_eab.clone();
        let hardening = hardening.clone();

        handles.push(tokio::spawn(async move {
            run_profile_daemon(
                settings,
                profile,
                default_eab,
                semaphore,
                shutdown_rx,
                hardening,
            )
            .await
        }));
    }

    let _ = shutdown_handle.await;
    let mut first_error = None;
    for handle in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                error!("Profile daemon exited with error: {err}");
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
            Err(err) => {
                error!("Profile daemon task join error: {err}");
                if first_error.is_none() {
                    first_error = Some(anyhow::anyhow!("Profile daemon task join error: {err}"));
                }
            }
        }
    }

    first_error.map_or(Ok(()), Err)
}

async fn run_profile_daemon(
    settings: Arc<config::Settings>,
    profile: config::DaemonProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    semaphore: Arc<Semaphore>,
    mut shutdown: watch::Receiver<bool>,
    hardening: HardeningPolicy,
) -> anyhow::Result<()> {
    let check_interval = profile.daemon.check_interval;
    let renew_before = profile.daemon.renew_before;
    let check_jitter = profile.daemon.check_jitter;
    let profile_label = config::profile_domain(&settings, &profile);

    info!(
        "Profile '{}' daemon enabled. check_interval={:?}, renew_before={:?}, check_jitter={:?}",
        profile_label, check_interval, renew_before, check_jitter
    );

    let mut first_tick = true;
    loop {
        if *shutdown.borrow() {
            info!(
                "Shutdown signal received. Exiting profile '{}'.",
                profile_label
            );
            break;
        }

        let delay = if first_tick {
            first_tick = false;
            Duration::from_secs(0)
        } else {
            utils::jittered_delay(check_interval, check_jitter)
        };

        tokio::select! {
            _ = shutdown.changed() => {
                info!("Shutdown signal received. Exiting profile '{}'.", profile_label);
                break;
            }
            () = tokio::time::sleep(delay) => {
                check_and_renew_profile(
                    &settings,
                    &profile,
                    default_eab.clone(),
                    Arc::clone(&semaphore),
                    renew_before,
                    &profile_label,
                    &hardening,
                )
                .await?;
            }
        }
    }

    Ok(())
}

/// Runs a single issuance pass for all profiles.
///
/// # Errors
/// Returns an error if any profile issuance fails.
pub async fn run_oneshot(
    settings: Arc<config::Settings>,
    default_eab: Option<eab::EabCredentials>,
    config_path: Option<PathBuf>,
    insecure_mode: bool,
) -> anyhow::Result<()> {
    let max_concurrent = profile::max_concurrent_issuances(&settings)?;
    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let hardening = HardeningPolicy {
        config_path: resolve_config_path(config_path.as_deref()),
        insecure_mode,
    };
    let mut handles = Vec::new();

    for profile in settings.profiles.clone() {
        let settings = Arc::clone(&settings);
        let semaphore = Arc::clone(&semaphore);
        let default_eab = default_eab.clone();
        let hardening = hardening.clone();

        handles.push(tokio::spawn(async move {
            run_profile_oneshot(settings, profile, default_eab, semaphore, hardening).await
        }));
    }

    let mut first_error = None;
    for handle in handles {
        match handle.await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => {
                error!("Profile oneshot failed: {err}");
                if first_error.is_none() {
                    first_error = Some(err);
                }
            }
            Err(err) => {
                error!("Profile oneshot task join error: {err}");
                if first_error.is_none() {
                    first_error = Some(anyhow::anyhow!("Profile task join error: {err}"));
                }
            }
        }
    }

    if let Some(err) = first_error {
        Err(err)
    } else {
        Ok(())
    }
}

async fn run_profile_oneshot(
    settings: Arc<config::Settings>,
    profile: config::DaemonProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    semaphore: Arc<Semaphore>,
    hardening: HardeningPolicy,
) -> anyhow::Result<()> {
    let _permit = semaphore.acquire().await?;
    let profile_eab = profile::resolve_profile_eab(&profile, default_eab);
    let profile_label = config::profile_domain(&settings, &profile);

    match acme::issue_certificate(&settings, &profile, profile_eab).await {
        Ok(()) => {
            maybe_harden_tls_verify(
                &settings,
                &hardening.config_path,
                &profile_label,
                hardening.insecure_mode,
            )
            .await?;
            if let Err(err) =
                hooks::run_post_renew_hooks(&settings, &profile, hooks::HookStatus::Success, None)
                    .await
            {
                error!(
                    "Post-renew success hooks failed for '{}': {err}",
                    profile_label
                );
            }
            Ok(())
        }
        Err(err) => {
            if let Err(hook_err) = hooks::run_post_renew_hooks(
                &settings,
                &profile,
                hooks::HookStatus::Failure,
                Some(err.to_string()),
            )
            .await
            {
                error!(
                    "Post-renew failure hooks failed for '{}': {hook_err}",
                    profile_label
                );
            }
            Err(err)
        }
    }
}

async fn issue_with_retry(
    settings: &config::Settings,
    profile: &config::DaemonProfileSettings,
    eab: Option<eab::EabCredentials>,
    config_path: &Path,
) -> anyhow::Result<()> {
    let backoff = select_retry_backoff(settings, profile);
    let profile_domain = config::profile_domain(settings, profile);
    let config_path_owned = config_path.to_path_buf();
    issue_with_retry_inner(
        || {
            let path = config_path_owned.clone();
            let domain = profile_domain.clone();
            let eab = eab.clone();
            async move {
                let fresh = config::Settings::new(Some(path))?;
                let fresh_profile = fresh
                    .profiles
                    .iter()
                    .find(|p| config::profile_domain(&fresh, p) == domain)
                    .ok_or_else(|| {
                        anyhow::anyhow!("Profile '{domain}' not found in reloaded config")
                    })?
                    .clone();
                let fresh_eab = profile::resolve_profile_eab(&fresh_profile, eab);
                acme::issue_certificate(&fresh, &fresh_profile, fresh_eab).await
            }
        },
        |duration| tokio::time::sleep(duration),
        backoff,
    )
    .await
}

fn select_retry_backoff<'a>(
    settings: &'a config::Settings,
    profile: &'a config::DaemonProfileSettings,
) -> &'a [u64] {
    profile
        .retry
        .as_ref()
        .map_or(settings.retry.backoff_secs.as_slice(), |retry| {
            retry.backoff_secs.as_slice()
        })
}

/// Issues a certificate with retry and backoff.
///
/// # Errors
/// Returns an error if all retries fail.
pub async fn issue_with_retry_inner<IssueFn, IssueFut, SleepFn, SleepFut>(
    mut issue_fn: IssueFn,
    mut sleep_fn: SleepFn,
    delays: &[u64],
) -> anyhow::Result<()>
where
    IssueFn: FnMut() -> IssueFut,
    IssueFut: Future<Output = anyhow::Result<()>>,
    SleepFn: FnMut(Duration) -> SleepFut,
    SleepFut: Future<Output = ()>,
{
    let result = utils::retry_with_backoff_and_sleep(
        &mut issue_fn,
        &mut sleep_fn,
        |attempt, err| {
            error!("Certificate issuance failed (attempt {}): {err}", attempt);
        },
        delays,
    )
    .await;
    if result.is_ok() {
        info!("Certificate issuance succeeded.");
    }
    result
}

/// Determines whether a certificate should be renewed.
///
/// # Errors
/// Returns an error if the certificate cannot be parsed or read.
pub async fn should_renew(
    profile: &config::DaemonProfileSettings,
    renew_before: Duration,
) -> anyhow::Result<bool> {
    let cert_bytes = match tokio::fs::read(&profile.paths.cert).await {
        Ok(bytes) => bytes,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            info!("Certificate file not found. Issuing a new certificate.");
            return Ok(true);
        }
        Err(err) => {
            return Err(anyhow::anyhow!(
                "Failed to read certificate file {}: {err}",
                profile.paths.cert.display()
            ));
        }
    };

    let not_after = parse_cert_not_after(&cert_bytes)?;

    let renew_before = time::Duration::try_from(renew_before)
        .map_err(|_| anyhow::anyhow!("renew_before duration is too large"))?;
    let now = time::OffsetDateTime::now_utc();
    let renew_at = now + renew_before;

    Ok(not_after <= renew_at)
}

/// Parses the certificate expiration timestamp.
///
/// # Errors
/// Returns an error if the certificate cannot be parsed.
pub fn parse_cert_not_after(cert_bytes: &[u8]) -> anyhow::Result<time::OffsetDateTime> {
    let pem = x509_parser::pem::parse_x509_pem(cert_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to parse PEM certificate: {e}"))?
        .1;
    let (_, cert) = x509_parser::parse_x509_certificate(&pem.contents)
        .map_err(|e| anyhow::anyhow!("Failed to parse X509 certificate: {e}"))?;
    Ok(cert.validity().not_after.to_datetime())
}

#[must_use]
pub fn jittered_delay_with_seed(base: Duration, jitter: Duration, now_ns: i128) -> Duration {
    utils::jittered_delay_with_seed(base, jitter, now_ns)
}

async fn check_and_renew_profile(
    settings: &config::Settings,
    profile: &config::DaemonProfileSettings,
    default_eab: Option<eab::EabCredentials>,
    semaphore: Arc<Semaphore>,
    renew_before: Duration,
    profile_label: &str,
    hardening: &HardeningPolicy,
) -> anyhow::Result<()> {
    tracing::debug!("Profile '{}' checking renewal status...", profile_label);
    match should_renew(profile, renew_before).await {
        Ok(true) => {
            info!(
                "Profile '{}' renewal required. Starting ACME issuance...",
                profile_label
            );
            let _permit = semaphore.acquire().await?;
            let profile_eab = profile::resolve_profile_eab(profile, default_eab);
            match issue_with_retry(settings, profile, profile_eab, &hardening.config_path).await {
                Ok(()) => {
                    maybe_harden_tls_verify(
                        settings,
                        &hardening.config_path,
                        profile_label,
                        hardening.insecure_mode,
                    )
                    .await?;
                    if let Err(err) = hooks::run_post_renew_hooks(
                        settings,
                        profile,
                        hooks::HookStatus::Success,
                        None,
                    )
                    .await
                    {
                        error!(
                            "Post-renew success hooks failed for '{}': {err}",
                            profile_label
                        );
                    }
                }
                Err(err) => {
                    error!(
                        "Profile '{}' renewal failed after retries: {err}",
                        profile_label
                    );
                    if let Err(hook_err) = hooks::run_post_renew_hooks(
                        settings,
                        profile,
                        hooks::HookStatus::Failure,
                        Some(err.to_string()),
                    )
                    .await
                    {
                        error!(
                            "Post-renew failure hooks failed for '{}': {hook_err}",
                            profile_label
                        );
                    }
                }
            }
        }
        Ok(false) => {
            tracing::debug!("Profile '{}' certificate still valid.", profile_label);
        }
        Err(err) => {
            error!("Profile '{}' renewal check failed: {err}", profile_label);
        }
    }
    Ok(())
}

fn resolve_config_path(config_path: Option<&Path>) -> PathBuf {
    config_path.map_or_else(
        || PathBuf::from(DEFAULT_AGENT_CONFIG_PATH),
        Path::to_path_buf,
    )
}

async fn maybe_harden_tls_verify(
    settings: &config::Settings,
    config_path: &Path,
    profile_label: &str,
    insecure_mode: bool,
) -> anyhow::Result<()> {
    if settings.trust.verify_certificates {
        return Ok(());
    }

    if insecure_mode {
        info!(
            "Profile '{}' issued in --insecure mode. \
verify_certificates stays false for this run.",
            profile_label
        );
        return Ok(());
    }

    set_verify_certificates_true(config_path, profile_label).await
}

async fn set_verify_certificates_true(
    config_path: &Path,
    profile_label: &str,
) -> anyhow::Result<()> {
    let current = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|err| {
            anyhow::anyhow!(
                "Profile '{}' failed to read config {} for TLS hardening: {err}",
                profile_label,
                config_path.display()
            )
        })?;

    let updated = upsert_toml_section_keys(
        &current,
        TRUST_SECTION,
        &[(
            VERIFY_CERTIFICATES_KEY,
            VERIFY_CERTIFICATES_TRUE.to_string(),
        )],
    );
    if updated != current {
        tokio::fs::write(config_path, updated)
            .await
            .with_context(|| {
                format!(
                    "Profile '{}' failed to write TLS hardening config: {}",
                    profile_label,
                    config_path.display()
                )
            })?;
    }

    let reloaded = config::Settings::new(Some(config_path.to_path_buf())).with_context(|| {
        format!(
            "Profile '{}' failed to reload hardening config: {}",
            profile_label,
            config_path.display()
        )
    })?;
    if !reloaded.trust.verify_certificates {
        anyhow::bail!(
            "Profile '{}' TLS hardening check failed: trust.verify_certificates is still false ({})",
            profile_label,
            config_path.display()
        );
    }

    info!(
        "Profile '{}' hardened TLS verify to true in {}",
        profile_label,
        config_path.display()
    );
    Ok(())
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
    if value.starts_with('[') || value == VERIFY_CERTIFICATES_TRUE {
        format!("{indent}{key} = {value}\n")
    } else {
        format!("{indent}{key} = \"{value}\"\n")
    }
}

fn is_section_header(value: &str) -> bool {
    value.starts_with('[') && value.ends_with(']')
}

async fn wait_for_shutdown() -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut term = signal(SignalKind::terminate())
            .map_err(|e| anyhow::anyhow!("Failed to install SIGTERM handler: {e}"))?;

        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|e| anyhow::anyhow!("Failed to listen for Ctrl+C: {e}"))?;
            }
            _ = term.recv() => {}
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to listen for Ctrl+C: {e}"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::config::{
        AcmeSettings, DaemonRuntimeSettings, Paths, RetrySettings, SchedulerSettings,
    };

    fn build_profile() -> config::DaemonProfileSettings {
        config::DaemonProfileSettings {
            service_name: "edge-proxy".to_string(),
            instance_id: "001".to_string(),
            hostname: "edge-node-01".to_string(),
            paths: Paths {
                cert: PathBuf::from("unused.pem"),
                key: PathBuf::from("unused.key"),
            },
            daemon: DaemonRuntimeSettings {
                check_interval: Duration::from_secs(60 * 60),
                renew_before: Duration::from_secs(720 * 60 * 60),
                check_jitter: Duration::from_secs(0),
            },
            retry: None,
            hooks: config::HookSettings::default(),
            eab: None,
        }
    }

    fn build_settings(backoff: Vec<u64>) -> config::Settings {
        config::Settings {
            email: "test@example.com".to_string(),
            server: "https://example.com/acme/directory".to_string(),
            domain: "trusted.domain".to_string(),
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
                backoff_secs: backoff,
            },
            trust: config::TrustSettings::default(),
            scheduler: SchedulerSettings {
                max_concurrent_issuances: 1,
            },
            profiles: Vec::new(),
        }
    }

    #[test]
    fn test_select_retry_backoff_uses_profile_override() {
        let settings = build_settings(vec![5, 10, 30]);
        let mut profile = build_profile();
        profile.retry = Some(RetrySettings {
            backoff_secs: vec![1, 2],
        });

        let selected = select_retry_backoff(&settings, &profile);

        assert_eq!(selected, profile.retry.as_ref().unwrap().backoff_secs);
    }

    #[test]
    fn test_select_retry_backoff_falls_back_to_global() {
        let settings = build_settings(vec![5, 10, 30]);
        let profile = build_profile();

        let selected = select_retry_backoff(&settings, &profile);

        assert_eq!(selected, settings.retry.backoff_secs);
    }

    #[test]
    fn test_upsert_toml_section_keys_updates_existing_trust_flag() {
        let input = "[trust]\nverify_certificates = false\n";
        let output = upsert_toml_section_keys(
            input,
            TRUST_SECTION,
            &[(
                VERIFY_CERTIFICATES_KEY,
                VERIFY_CERTIFICATES_TRUE.to_string(),
            )],
        );
        assert!(output.contains("verify_certificates = true"));
    }

    #[test]
    fn test_upsert_toml_section_keys_adds_trust_section() {
        let input = "email = \"admin@example.com\"\n";
        let output = upsert_toml_section_keys(
            input,
            TRUST_SECTION,
            &[(
                VERIFY_CERTIFICATES_KEY,
                VERIFY_CERTIFICATES_TRUE.to_string(),
            )],
        );
        assert!(output.contains("[trust]"));
        assert!(output.contains("verify_certificates = true"));
    }

    #[tokio::test]
    async fn test_set_verify_certificates_true_updates_config_file() {
        let dir = tempfile::tempdir().expect("creates temp dir");
        let config_path = dir.path().join("agent.toml");
        fs::write(
            &config_path,
            r#"
email = "admin@example.com"
server = "https://localhost:9000/acme/acme/directory"
domain = "example.internal"

[acme]
http_responder_url = "http://localhost:8080"
http_responder_hmac = "dev-hmac"
"#,
        )
        .expect("writes config fixture");

        set_verify_certificates_true(&config_path, "test-profile")
            .await
            .expect("hardens config");

        let updated = fs::read_to_string(&config_path).expect("reads updated config");
        assert!(updated.contains("[trust]"));
        assert!(updated.contains("verify_certificates = true"));
    }

    #[tokio::test]
    async fn test_set_verify_certificates_true_fails_on_unwritable_path() {
        let dir = tempfile::tempdir().expect("creates temp dir");
        let config_path = dir.path().join("agent.toml");
        fs::create_dir(&config_path).expect("creates directory path");

        let err = set_verify_certificates_true(&config_path, "test-profile")
            .await
            .expect_err("must fail");
        assert!(err.to_string().contains("failed to read config"));
    }

    #[tokio::test]
    async fn test_set_verify_certificates_true_fails_when_config_missing() {
        let dir = tempfile::tempdir().expect("creates temp dir");
        let config_path = dir.path().join("missing-agent.toml");

        let err = set_verify_certificates_true(&config_path, "test-profile")
            .await
            .expect_err("must fail when config file does not exist");
        assert!(err.to_string().contains("failed to read config"));
    }

    #[tokio::test]
    async fn test_maybe_harden_tls_verify_skips_when_insecure() {
        let dir = tempfile::tempdir().expect("creates temp dir");
        let config_path = dir.path().join("agent.toml");
        fs::write(&config_path, "[trust]\nverify_certificates = false\n")
            .expect("writes config fixture");
        let settings = build_settings(vec![5, 10, 30]);

        maybe_harden_tls_verify(&settings, &config_path, "test-profile", true)
            .await
            .expect("must skip hardening in insecure mode");

        let updated = fs::read_to_string(&config_path).expect("reads config after skip");
        assert!(updated.contains("verify_certificates = false"));
    }

    #[tokio::test]
    async fn test_maybe_harden_tls_verify_retries_after_insecure_run() {
        let dir = tempfile::tempdir().expect("creates temp dir");
        let config_path = dir.path().join("agent.toml");
        fs::write(
            &config_path,
            r#"
email = "admin@example.com"
server = "https://localhost:9000/acme/acme/directory"
domain = "example.internal"

[acme]
http_responder_url = "http://localhost:8080"
http_responder_hmac = "dev-hmac"
[trust]
verify_certificates = false
"#,
        )
        .expect("writes config fixture");
        let settings = build_settings(vec![5, 10, 30]);

        maybe_harden_tls_verify(&settings, &config_path, "test-profile", true)
            .await
            .expect("insecure run skips hardening");
        let skipped = fs::read_to_string(&config_path).expect("reads skipped config");
        assert!(skipped.contains("verify_certificates = false"));

        maybe_harden_tls_verify(&settings, &config_path, "test-profile", false)
            .await
            .expect("normal run hardens");
        let hardened = fs::read_to_string(&config_path).expect("reads hardened config");
        assert!(hardened.contains("verify_certificates = true"));
    }

    #[tokio::test]
    async fn test_set_verify_certificates_true_fails_on_malformed_toml() {
        let dir = tempfile::tempdir().expect("creates temp dir");
        let config_path = dir.path().join("agent.toml");
        fs::write(
            &config_path,
            r#"
email = "admin@example.com"
server = "https://localhost:9000/acme/acme/directory"
domain = "example.internal"
[acme
http_responder_url = "http://localhost:8080"
http_responder_hmac = "dev-hmac"
"#,
        )
        .expect("writes malformed config fixture");

        let err = set_verify_certificates_true(&config_path, "test-profile")
            .await
            .expect_err("must fail when config remains invalid");
        assert!(
            err.to_string()
                .contains("failed to reload hardening config")
        );
    }

    #[tokio::test]
    async fn test_maybe_harden_tls_verify_noop_when_already_true() {
        let dir = tempfile::tempdir().expect("creates temp dir");
        let config_path = dir.path().join("agent.toml");
        fs::write(&config_path, "[trust]\nverify_certificates = false\n")
            .expect("writes config fixture");
        let mut settings = build_settings(vec![5, 10, 30]);
        settings.trust.verify_certificates = true;

        maybe_harden_tls_verify(&settings, &config_path, "test-profile", false)
            .await
            .expect("already true should be no-op");

        let updated = fs::read_to_string(&config_path).expect("reads config");
        assert!(updated.contains("verify_certificates = false"));
    }

    #[tokio::test]
    async fn test_set_verify_certificates_true_preserves_other_trust_fields() {
        let dir = tempfile::tempdir().expect("creates temp dir");
        let config_path = dir.path().join("agent.toml");
        fs::write(
            &config_path,
            r#"
email = "admin@example.com"
server = "https://localhost:9000/acme/acme/directory"
domain = "example.internal"

[acme]
http_responder_url = "http://localhost:8080"
http_responder_hmac = "dev-hmac"

[trust]
verify_certificates = false
ca_bundle_path = "certs/ca-bundle.pem"
trusted_ca_sha256 = ["aa11"]
"#,
        )
        .expect("writes config fixture");

        set_verify_certificates_true(&config_path, "test-profile")
            .await
            .expect("hardens config");

        let updated = fs::read_to_string(&config_path).expect("reads updated config");
        assert!(updated.contains("verify_certificates = true"));
        assert!(updated.contains("ca_bundle_path = \"certs/ca-bundle.pem\""));
        assert!(updated.contains("trusted_ca_sha256 = [\"aa11\"]"));
    }

    #[test]
    fn test_resolve_config_path_uses_default_when_none() {
        let resolved = resolve_config_path(None);
        assert_eq!(resolved, PathBuf::from(DEFAULT_AGENT_CONFIG_PATH));
    }

    #[test]
    fn test_resolve_config_path_prefers_provided_path() {
        let provided = PathBuf::from("/tmp/custom-agent.toml");
        let resolved = resolve_config_path(Some(&provided));
        assert_eq!(resolved, provided);
    }
}
