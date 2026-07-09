use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Url;

use super::defaults::default_renew_before;
use super::{DaemonProfileSettings, HookCommand, OpenBaoSettings, Settings, TrustSettings};

/// Validates that `cert_duration` is strictly greater than the default
/// daemon `renew_before` interval.
///
/// Used at `bootroot init` time, where `agent.toml` is not available on
/// the control plane, so the default `renew_before` (16h) is used as a
/// conservative proxy.
///
/// # Errors
///
/// Returns an error if `cert_duration` cannot be parsed as a duration
/// or is not strictly greater than the default `renew_before`.
pub fn validate_cert_duration_vs_default_renew_before(cert_duration: &str) -> Result<()> {
    let duration = humantime::parse_duration(cert_duration.trim())
        .with_context(|| format!("invalid cert-duration: {cert_duration}"))?;
    let renew_before = default_renew_before();
    if duration <= renew_before {
        anyhow::bail!(
            "cert-duration ({cert_duration}) must exceed the default renew_before ({}); \
             otherwise the daemon will flag every newly issued certificate for immediate renewal",
            humantime::format_duration(renew_before)
        );
    }
    Ok(())
}

/// Parses a duration string as accepted by `defaultTLSCertDuration`.
///
/// # Errors
///
/// Returns an error if the value cannot be parsed as a duration.
pub fn parse_cert_duration(value: &str) -> Result<Duration> {
    humantime::parse_duration(value.trim())
        .with_context(|| format!("invalid cert-duration: {value}"))
}

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
    if let Some(openbao) = &settings.openbao {
        validate_openbao_settings(openbao)?;
    }
    Ok(())
}

/// Reports whether an `openbao.url` uses the `https://` scheme.
///
/// URL schemes are case-insensitive (RFC 3986 §3.1), so `HTTPS://host`
/// designates the same TLS endpoint as `https://host` and must route
/// through the CA-bundle-anchored client path identically. Comparing the
/// parsed scheme case-insensitively — rather than a raw `starts_with` —
/// keeps a mixed-case scheme from silently falling back to the plaintext
/// client (issue #695). A URL that fails to parse returns `false`.
#[must_use]
pub fn openbao_url_is_https(url: &str) -> bool {
    Url::parse(url.trim()).is_ok_and(|parsed| parsed.scheme().eq_ignore_ascii_case("https"))
}

/// Reports whether an `openbao.url` is a non-loopback plaintext
/// `http://` endpoint — the case that exposes `AppRole` credentials and
/// delivered secrets on the wire and therefore requires the explicit
/// `allow_plaintext_http` opt-in.
///
/// Loopback plaintext (`localhost`, `127.0.0.0/8`, `[::1]`) and any
/// `https://` URL return `false`. A URL whose scheme is not `http`
/// (compared case-insensitively, so `HTTP://` counts), or one whose host
/// cannot be parsed, also returns `false`: the scheme check confines this
/// to plaintext HTTP, and a host that fails to parse is left for other
/// validation to reject.
#[must_use]
pub fn openbao_url_is_non_loopback_plaintext(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    if !parsed.scheme().eq_ignore_ascii_case("http") {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    !host_is_loopback(host)
}

/// Reports whether a URL host string designates the loopback interface.
fn host_is_loopback(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    // `Url::host_str` keeps the brackets around an IPv6 literal; strip
    // them before parsing.
    let candidate = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    candidate.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn validate_openbao_settings(settings: &OpenBaoSettings) -> Result<()> {
    if settings.url.trim().is_empty() {
        anyhow::bail!("openbao.url must not be empty");
    }
    if openbao_url_is_non_loopback_plaintext(&settings.url) && !settings.allow_plaintext_http {
        anyhow::bail!(
            "openbao.url ({}) is a non-loopback plaintext http:// endpoint; AppRole \
             credentials and delivered secrets would cross the network unencrypted. Use \
             https://, point at a loopback address, or set [openbao] allow_plaintext_http = \
             true to opt in explicitly",
            settings.url
        );
    }
    if settings.kv_mount.trim().is_empty() {
        anyhow::bail!("openbao.kv_mount must not be empty");
    }
    if settings.role_id_path.as_os_str().is_empty() {
        anyhow::bail!("openbao.role_id_path must not be empty");
    }
    if settings.secret_id_path.as_os_str().is_empty() {
        anyhow::bail!("openbao.secret_id_path must not be empty");
    }
    if settings.fast_poll_interval < Duration::from_secs(1) {
        anyhow::bail!("openbao.fast_poll_interval must be at least 1 second");
    }
    if openbao_url_is_https(&settings.url) && settings.ca_bundle_path.is_none() {
        anyhow::bail!("openbao.ca_bundle_path must be set when openbao.url uses https://");
    }
    if let Some(path) = &settings.ca_bundle_path
        && path.as_os_str().is_empty()
    {
        anyhow::bail!("openbao.ca_bundle_path must not be empty");
    }
    if settings.state_path.as_os_str().is_empty() {
        anyhow::bail!("openbao.state_path must not be empty");
    }
    if !settings.state_path.is_absolute() {
        // A relative state_path is resolved against the agent process
        // cwd, which is not contracted to be stable or writable under
        // systemd-style supervisors. If the cwd changes between
        // restarts, the persisted `last_reissue_seen_version` /
        // `in_flight_renewals` / `pending_completion_writes` map is
        // lost, defeating duplicate-suppression and completion-retry.
        // `bootroot-remote bootstrap` auto-provisions an absolute path
        // adjacent to `agent.toml`; operator-written configs must do
        // the same.
        anyhow::bail!(
            "openbao.state_path must be an absolute path ({} is relative); \
             rerun `bootroot-remote bootstrap` or set an absolute path explicitly",
            settings.state_path.display()
        );
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
    if let Some(gid) = profile.cert_group_gid {
        // gid 0 is `root`. The default agent identity already has
        // root or operator-only access; granting "the root group"
        // would be a no-op and is an obvious misconfiguration.
        // The presence check (getgrgid_r) catches the orphan-gid
        // case where the gid exists on a different host (e.g. the
        // container image's runtime user) but not on this
        // cert-writing host, where `chown(-1, gid)` would silently
        // succeed and the consumer would still hit EACCES. Issue
        // #593 review.
        crate::cert_group::validate_cert_writing_host_gid(gid)
            .map_err(|err| anyhow::anyhow!("profiles.cert_group_gid: {err}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_duration_accepts_value_greater_than_default_renew_before() {
        // default renew_before is 16h; 24h is the step-ca default
        assert!(validate_cert_duration_vs_default_renew_before("24h").is_ok());
        assert!(validate_cert_duration_vs_default_renew_before("48h").is_ok());
    }

    #[test]
    fn cert_duration_rejects_value_less_than_or_equal_to_renew_before() {
        assert!(validate_cert_duration_vs_default_renew_before("16h").is_err());
        assert!(validate_cert_duration_vs_default_renew_before("8h").is_err());
    }

    #[test]
    fn cert_duration_rejects_invalid_value() {
        assert!(validate_cert_duration_vs_default_renew_before("bogus").is_err());
        assert!(validate_cert_duration_vs_default_renew_before("").is_err());
    }

    fn openbao_settings(url: &str, allow_plaintext_http: bool) -> OpenBaoSettings {
        OpenBaoSettings {
            url: url.to_string(),
            allow_plaintext_http,
            kv_mount: "secret".to_string(),
            role_id_path: std::path::PathBuf::from("/etc/bootroot/role_id"),
            secret_id_path: std::path::PathBuf::from("/etc/bootroot/secret_id"),
            ca_bundle_path: None,
            fast_poll_interval: Duration::from_secs(5),
            state_path: std::path::PathBuf::from("/var/lib/bootroot/state.json"),
        }
    }

    #[test]
    fn openbao_allows_loopback_plaintext_without_opt_in() {
        for url in [
            "http://localhost:8200",
            "http://127.0.0.1:8200",
            "http://127.5.6.7:8200",
            "http://[::1]:8200",
        ] {
            assert!(
                validate_openbao_settings(&openbao_settings(url, false)).is_ok(),
                "loopback plaintext {url} should validate without opt-in"
            );
        }
    }

    #[test]
    fn openbao_allows_https_without_opt_in() {
        let mut settings = openbao_settings("https://openbao.example:8200", false);
        settings.ca_bundle_path = Some(std::path::PathBuf::from("/etc/bootroot/ca-bundle.pem"));
        assert!(validate_openbao_settings(&settings).is_ok());
    }

    #[test]
    fn openbao_rejects_non_loopback_plaintext_without_opt_in() {
        let err = validate_openbao_settings(&openbao_settings("http://10.0.0.5:8200", false))
            .expect_err("non-loopback plaintext without opt-in must fail");
        let message = format!("{err}");
        assert!(
            message.contains("allow_plaintext_http"),
            "error should point at the opt-in: {message}"
        );
    }

    #[test]
    fn openbao_allows_non_loopback_plaintext_with_opt_in() {
        assert!(validate_openbao_settings(&openbao_settings("http://10.0.0.5:8200", true)).is_ok());
    }

    #[test]
    fn non_loopback_plaintext_classifier_matches_expectations() {
        assert!(openbao_url_is_non_loopback_plaintext(
            "http://10.0.0.5:8200"
        ));
        assert!(openbao_url_is_non_loopback_plaintext(
            "http://openbao.example:8200"
        ));
        assert!(!openbao_url_is_non_loopback_plaintext(
            "http://localhost:8200"
        ));
        assert!(!openbao_url_is_non_loopback_plaintext(
            "http://127.0.0.1:8200"
        ));
        assert!(!openbao_url_is_non_loopback_plaintext("http://[::1]:8200"));
        assert!(!openbao_url_is_non_loopback_plaintext(
            "https://openbao.example:8200"
        ));
    }

    #[test]
    fn non_loopback_plaintext_classifier_is_scheme_case_insensitive() {
        // URL schemes are case-insensitive, so a mixed-case plaintext
        // scheme must still be gated (issue #695).
        assert!(openbao_url_is_non_loopback_plaintext(
            "HTTP://10.0.0.5:8200"
        ));
        assert!(openbao_url_is_non_loopback_plaintext(
            "HtTp://openbao.example:8200"
        ));
        assert!(!openbao_url_is_non_loopback_plaintext(
            "HTTP://127.0.0.1:8200"
        ));
        assert!(!openbao_url_is_non_loopback_plaintext(
            "HTTPS://openbao.example:8200"
        ));
    }

    #[test]
    fn https_classifier_is_scheme_case_insensitive() {
        assert!(openbao_url_is_https("https://openbao.example:8200"));
        assert!(openbao_url_is_https("HTTPS://openbao.example:8200"));
        assert!(openbao_url_is_https("HtTpS://openbao.example:8200"));
        assert!(!openbao_url_is_https("http://openbao.example:8200"));
        assert!(!openbao_url_is_https("HTTP://openbao.example:8200"));
        assert!(!openbao_url_is_https("not a url"));
    }

    #[test]
    fn openbao_rejects_mixed_case_non_loopback_plaintext_without_opt_in() {
        let err = validate_openbao_settings(&openbao_settings("HTTP://10.0.0.5:8200", false))
            .expect_err("mixed-case non-loopback plaintext without opt-in must fail");
        assert!(
            format!("{err}").contains("allow_plaintext_http"),
            "error should point at the opt-in: {err}"
        );
    }

    #[test]
    fn openbao_requires_ca_bundle_for_mixed_case_https() {
        let err =
            validate_openbao_settings(&openbao_settings("HTTPS://openbao.example:8200", false))
                .expect_err("mixed-case https without a CA bundle must fail");
        assert!(
            format!("{err}").contains("ca_bundle_path"),
            "error should require the CA bundle: {err}"
        );
    }
}
