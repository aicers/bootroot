use anyhow::Result;

use super::{DaemonProfileSettings, HookCommand, Settings, TrustSettings};

pub(crate) fn validate_settings(settings: &Settings) -> Result<()> {
    if settings.domain.trim().is_empty() {
        anyhow::bail!("domain must not be empty");
    }
    if !settings.domain.is_ascii() {
        anyhow::bail!("domain must be ASCII");
    }
    if settings.acme.directory_fetch_attempts == 0 {
        anyhow::bail!("acme.directory_fetch_attempts must be greater than 0");
    }
    if settings.acme.http_responder_url.trim().is_empty() {
        anyhow::bail!("acme.http_responder_url must not be empty");
    }
    if settings.acme.http_responder_hmac.trim().is_empty() {
        anyhow::bail!("acme.http_responder_hmac must not be empty");
    }
    if settings.acme.http_responder_timeout_secs == 0 {
        anyhow::bail!("acme.http_responder_timeout_secs must be greater than 0");
    }
    if settings.acme.http_responder_token_ttl_secs == 0 {
        anyhow::bail!("acme.http_responder_token_ttl_secs must be greater than 0");
    }
    if settings.acme.poll_attempts == 0 {
        anyhow::bail!("acme.poll_attempts must be greater than 0");
    }
    if settings.acme.poll_interval_secs == 0 {
        anyhow::bail!("acme.poll_interval_secs must be greater than 0");
    }
    if settings.acme.directory_fetch_base_delay_secs == 0 {
        anyhow::bail!("acme.directory_fetch_base_delay_secs must be greater than 0");
    }
    if settings.acme.directory_fetch_max_delay_secs == 0 {
        anyhow::bail!("acme.directory_fetch_max_delay_secs must be greater than 0");
    }
    if settings.acme.directory_fetch_base_delay_secs > settings.acme.directory_fetch_max_delay_secs
    {
        anyhow::bail!(
            "acme.directory_fetch_base_delay_secs must be <= acme.directory_fetch_max_delay_secs"
        );
    }
    if settings.retry.backoff_secs.is_empty() {
        anyhow::bail!("retry.backoff_secs must not be empty");
    }
    validate_retry_settings(&settings.retry.backoff_secs, "retry.backoff_secs")?;
    validate_trust_settings(&settings.trust)?;
    if settings.scheduler.max_concurrent_issuances == 0 {
        anyhow::bail!("scheduler.max_concurrent_issuances must be greater than 0");
    }
    if settings.profiles.is_empty() {
        anyhow::bail!("profiles must not be empty");
    }
    for profile in &settings.profiles {
        validate_profile(profile)?;
    }
    Ok(())
}

fn validate_trust_settings(trust: &TrustSettings) -> Result<()> {
    if trust.ca_bundle_path.is_some() || !trust.trusted_ca_sha256.is_empty() {
        if trust.ca_bundle_path.is_none() {
            anyhow::bail!("trust.ca_bundle_path must be set when trust is configured");
        }
        if trust.trusted_ca_sha256.is_empty() {
            anyhow::bail!("trust.trusted_ca_sha256 must not be empty when trust is configured");
        }
    }
    if let Some(path) = &trust.ca_bundle_path
        && path.as_os_str().is_empty()
    {
        anyhow::bail!("trust.ca_bundle_path must not be empty");
    }
    for fingerprint in &trust.trusted_ca_sha256 {
        validate_sha256_fingerprint(fingerprint)?;
    }
    Ok(())
}

fn validate_sha256_fingerprint(value: &str) -> Result<()> {
    if value.len() != 64 {
        anyhow::bail!("trust.trusted_ca_sha256 must be 64 hex chars");
    }
    if !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        anyhow::bail!("trust.trusted_ca_sha256 must be hex");
    }
    Ok(())
}

fn validate_profile(profile: &DaemonProfileSettings) -> Result<()> {
    if profile.service_name.trim().is_empty() {
        anyhow::bail!("profiles.service_name must not be empty");
    }
    if profile.hostname.trim().is_empty() {
        anyhow::bail!("profiles.hostname must not be empty");
    }
    if !profile.service_name.is_ascii() {
        anyhow::bail!("profiles.service_name must be ASCII");
    }
    if !profile.hostname.is_ascii() {
        anyhow::bail!("profiles.hostname must be ASCII");
    }
    if profile.instance_id.trim().is_empty() {
        anyhow::bail!("profiles.instance_id must not be empty");
    }
    if !profile.instance_id.chars().all(|ch| ch.is_ascii_digit()) {
        anyhow::bail!("profiles.instance_id must be numeric");
    }
    if profile.paths.cert.as_os_str().is_empty() {
        anyhow::bail!("profiles.paths.cert must not be empty");
    }
    if profile.paths.key.as_os_str().is_empty() {
        anyhow::bail!("profiles.paths.key must not be empty");
    }
    if let Some(retry) = &profile.retry {
        validate_retry_settings(&retry.backoff_secs, "profiles.retry.backoff_secs")?;
    }
    validate_hook_commands(
        &profile.hooks.post_renew.success,
        "profiles.hooks.post_renew.success",
    )?;
    validate_hook_commands(
        &profile.hooks.post_renew.failure,
        "profiles.hooks.post_renew.failure",
    )?;
    Ok(())
}

fn validate_hook_commands(hooks: &[HookCommand], label: &str) -> Result<()> {
    for hook in hooks {
        if hook.command.trim().is_empty() {
            anyhow::bail!("{label} hook command must not be empty");
        }
        if let Some(working_dir) = &hook.working_dir
            && working_dir.as_os_str().is_empty()
        {
            anyhow::bail!("{label} hook working_dir must not be empty");
        }
        if hook.timeout_secs == 0 {
            anyhow::bail!("{label} hook timeout_secs must be greater than 0");
        }
        validate_retry_settings(
            &hook.retry_backoff_secs,
            &format!("{label} hook retry_backoff_secs"),
        )?;
        if let Some(max_output_bytes) = hook.max_output_bytes
            && max_output_bytes == 0
        {
            anyhow::bail!("{label} hook max_output_bytes must be greater than 0");
        }
    }
    Ok(())
}

fn validate_retry_settings(backoff_secs: &[u64], label: &str) -> Result<()> {
    if backoff_secs.contains(&0) {
        anyhow::bail!("{label} values must be greater than 0");
    }
    Ok(())
}
