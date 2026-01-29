use std::time::Duration;

use config::{ConfigBuilder, ConfigError, builder::DefaultState};

const DEFAULT_SERVER: &str = "https://localhost:9000/acme/acme/directory";
const DEFAULT_EMAIL: &str = "admin@example.com";
const DEFAULT_DOMAIN: &str = "trusted.domain";
const DEFAULT_CHECK_INTERVAL_SECS: u64 = 60 * 60;
const DEFAULT_RENEW_BEFORE_SECS: u64 = 720 * 60 * 60;
const DEFAULT_CHECK_JITTER_SECS: u64 = 0;
const DEFAULT_HTTP_RESPONDER_URL: &str = "http://localhost:8080";
const DEFAULT_HTTP_RESPONDER_HMAC: &str = "";
const DEFAULT_HTTP_RESPONDER_TIMEOUT_SECS: u64 = 5;
const DEFAULT_HTTP_RESPONDER_TOKEN_TTL_SECS: u64 = 300;
const DEFAULT_DIRECTORY_FETCH_ATTEMPTS: u64 = 10;
const DEFAULT_DIRECTORY_FETCH_BASE_DELAY_SECS: u64 = 1;
const DEFAULT_DIRECTORY_FETCH_MAX_DELAY_SECS: u64 = 10;
const DEFAULT_POLL_ATTEMPTS: u64 = 15;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 2;
const DEFAULT_RETRY_BACKOFF_SECS: [u64; 3] = [5, 10, 30];
const DEFAULT_HOOK_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_CONCURRENT_ISSUANCES: u64 = 3;
const DEFAULT_VERIFY_CERTIFICATES: bool = false;

pub(crate) fn apply_defaults(
    builder: ConfigBuilder<DefaultState>,
) -> Result<ConfigBuilder<DefaultState>, ConfigError> {
    builder
        .set_default("server", DEFAULT_SERVER)?
        .set_default("email", DEFAULT_EMAIL)?
        .set_default("domain", DEFAULT_DOMAIN)?
        .set_default("acme.http_responder_url", DEFAULT_HTTP_RESPONDER_URL)?
        .set_default("acme.http_responder_hmac", DEFAULT_HTTP_RESPONDER_HMAC)?
        .set_default(
            "acme.http_responder_timeout_secs",
            DEFAULT_HTTP_RESPONDER_TIMEOUT_SECS,
        )?
        .set_default(
            "acme.http_responder_token_ttl_secs",
            DEFAULT_HTTP_RESPONDER_TOKEN_TTL_SECS,
        )?
        .set_default(
            "acme.directory_fetch_attempts",
            DEFAULT_DIRECTORY_FETCH_ATTEMPTS,
        )?
        .set_default(
            "acme.directory_fetch_base_delay_secs",
            DEFAULT_DIRECTORY_FETCH_BASE_DELAY_SECS,
        )?
        .set_default(
            "acme.directory_fetch_max_delay_secs",
            DEFAULT_DIRECTORY_FETCH_MAX_DELAY_SECS,
        )?
        .set_default("acme.poll_attempts", DEFAULT_POLL_ATTEMPTS)?
        .set_default("acme.poll_interval_secs", DEFAULT_POLL_INTERVAL_SECS)?
        .set_default("retry.backoff_secs", DEFAULT_RETRY_BACKOFF_SECS.to_vec())?
        .set_default(
            "scheduler.max_concurrent_issuances",
            DEFAULT_MAX_CONCURRENT_ISSUANCES,
        )?
        .set_default("trust.verify_certificates", DEFAULT_VERIFY_CERTIFICATES)
}

pub(crate) fn default_hook_timeout_secs() -> u64 {
    DEFAULT_HOOK_TIMEOUT_SECS
}

pub(crate) fn default_check_interval() -> Duration {
    Duration::from_secs(DEFAULT_CHECK_INTERVAL_SECS)
}

pub(crate) fn default_renew_before() -> Duration {
    Duration::from_secs(DEFAULT_RENEW_BEFORE_SECS)
}

pub(crate) fn default_check_jitter() -> Duration {
    Duration::from_secs(DEFAULT_CHECK_JITTER_SECS)
}

pub(crate) fn default_max_concurrent_issuances() -> u64 {
    DEFAULT_MAX_CONCURRENT_ISSUANCES
}

pub(crate) fn default_verify_certificates() -> bool {
    DEFAULT_VERIFY_CERTIFICATES
}
