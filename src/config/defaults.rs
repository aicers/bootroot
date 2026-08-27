use std::path::PathBuf;
use std::time::Duration;

use config::{ConfigBuilder, ConfigError, builder::DefaultState};

use crate::registrar::audit::{
    DEFAULT_AUDIT_MAX_FILE_BYTES, DEFAULT_AUDIT_MAX_RETAINED_FILES, DEFAULT_AUDIT_MIN_RETAIN_DAYS,
};
use crate::registrar::openbao_audit::{
    DEFAULT_OPENBAO_AUDIT_MAX_FILE_BYTES, DEFAULT_OPENBAO_AUDIT_MAX_RETAINED_FILES,
    DEFAULT_OPENBAO_AUDIT_MIN_RETAIN_DAYS,
};
use crate::registrar::verbs::limiter::{
    DEFAULT_RATE_LIMIT_ADMISSION_BURST, DEFAULT_RATE_LIMIT_ADMISSION_REFILL_INTERVAL_MS,
    DEFAULT_RATE_LIMIT_PREDECISION_REFUSAL_BURST,
    DEFAULT_RATE_LIMIT_PREDECISION_REFUSAL_REFILL_INTERVAL_MS,
};

const DEFAULT_SERVER: &str = "https://localhost:9000/acme/acme/directory";
const DEFAULT_EMAIL: &str = "admin@example.com";
const DEFAULT_DOMAIN: &str = "trusted.domain";
const DEFAULT_CHECK_INTERVAL_SECS: u64 = 60 * 60;
const DEFAULT_RENEW_BEFORE_SECS: u64 = 16 * 60 * 60;
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
const DEFAULT_RETRY_BACKOFF_SECS: [u64; 4] = [5, 10, 30, 60];
const DEFAULT_HOOK_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_CONCURRENT_ISSUANCES: u64 = 3;
const DEFAULT_FAST_POLL_INTERVAL_SECS: u64 = 30;
const DEFAULT_KV_MOUNT: &str = "secret";
const DEFAULT_FAST_POLL_STATE_PATH: &str = "bootroot-agent-state.json";
const DEFAULT_AUDIT_STORE_DIR: &str = "/var/lib/bootroot/audit-store";
const AUDIT_RECORDS_SUBDIR: &str = "records";
const DEFAULT_AUDIT_STORE_RESERVE_BYTES: u64 = 2_147_483_648;
const DEFAULT_AUDIT_STORE_LOW_WATER_BYTES: u64 = 536_870_912;
/// Ceiling the registrar grants a requested `wrap_ttl` under.
///
/// The same 30 minutes the rest of bootroot already wraps a `secret_id`
/// for — `DEFAULT_SECRET_ID_WRAP_TTL` in `src/commands/constants.rs`.
/// That constant is in the binary crate and this one is in the library,
/// so the value is restated here rather than imported across the crate
/// boundary. A test in that crate, over `RegistrarSettings::default()`,
/// fails if the two ever disagree.
const DEFAULT_REGISTRAR_MAX_WRAP_TTL_SECS: u64 = 30 * 60;
/// Role-level `token_ttl` the registrar creates its `AppRole`s with.
///
/// The same hour `openbao_constants::TOKEN_TTL`
/// (`src/commands/init/constants.rs`) issues under, restated for the
/// same crate-boundary reason as the wrap TTL above.
const DEFAULT_REGISTRAR_ROLE_TOKEN_TTL_SECS: u64 = 60 * 60;
/// Role-level `secret_id_ttl` the registrar creates its `AppRole`s with.
///
/// The same day `openbao_constants::SECRET_ID_TTL`
/// (`src/commands/init/constants.rs`) issues under, restated for the
/// same crate-boundary reason as the wrap TTL above.
const DEFAULT_REGISTRAR_ROLE_SECRET_ID_TTL_SECS: u64 = 24 * 60 * 60;
/// Uses a registrar-minted `secret_id` is good for.
///
/// Zero means unlimited within the TTL, which is what
/// `build_secret_id_options` (`src/commands/service.rs`) already sets
/// for a service `AppRole`: the enrolled host re-authenticates by
/// `AppRole` login on every renewal and every fast-poll cycle, so a
/// single-use credential would work once and then strand the service.
const DEFAULT_REGISTRAR_SECRET_ID_NUM_USES: u32 = 0;

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
        )
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

pub(crate) fn default_fast_poll_interval() -> Duration {
    Duration::from_secs(DEFAULT_FAST_POLL_INTERVAL_SECS)
}

pub(crate) fn default_kv_mount() -> String {
    DEFAULT_KV_MOUNT.to_string()
}

pub(crate) fn default_fast_poll_state_path() -> PathBuf {
    PathBuf::from(DEFAULT_FAST_POLL_STATE_PATH)
}

pub(crate) fn default_audit_store_dir() -> PathBuf {
    PathBuf::from(DEFAULT_AUDIT_STORE_DIR)
}

pub(crate) fn audit_record_dir_for(audit_store_dir: &std::path::Path) -> PathBuf {
    audit_store_dir.join(AUDIT_RECORDS_SUBDIR)
}

pub(crate) fn default_audit_store_reserve_bytes() -> u64 {
    DEFAULT_AUDIT_STORE_RESERVE_BYTES
}

pub(crate) fn default_audit_store_low_water_bytes() -> u64 {
    DEFAULT_AUDIT_STORE_LOW_WATER_BYTES
}

pub(crate) fn default_rate_limit_admission_burst() -> u32 {
    DEFAULT_RATE_LIMIT_ADMISSION_BURST
}

pub(crate) fn default_rate_limit_admission_refill_interval_ms() -> u32 {
    DEFAULT_RATE_LIMIT_ADMISSION_REFILL_INTERVAL_MS
}

pub(crate) fn default_rate_limit_predecision_refusal_burst() -> u32 {
    DEFAULT_RATE_LIMIT_PREDECISION_REFUSAL_BURST
}

pub(crate) fn default_rate_limit_predecision_refusal_refill_interval_ms() -> u32 {
    DEFAULT_RATE_LIMIT_PREDECISION_REFUSAL_REFILL_INTERVAL_MS
}

pub(crate) fn default_rate_limit_coalesce_window_seconds() -> u32 {
    60
}

pub(crate) fn default_audit_max_file_bytes() -> u64 {
    DEFAULT_AUDIT_MAX_FILE_BYTES
}

pub(crate) fn default_audit_max_retained_files() -> u32 {
    DEFAULT_AUDIT_MAX_RETAINED_FILES
}

pub(crate) fn default_audit_min_retain_days() -> u32 {
    DEFAULT_AUDIT_MIN_RETAIN_DAYS
}

pub(crate) fn default_openbao_audit_max_file_bytes() -> u64 {
    DEFAULT_OPENBAO_AUDIT_MAX_FILE_BYTES
}

pub(crate) fn default_openbao_audit_max_retained_files() -> u32 {
    DEFAULT_OPENBAO_AUDIT_MAX_RETAINED_FILES
}

pub(crate) fn default_openbao_audit_min_retain_days() -> u32 {
    DEFAULT_OPENBAO_AUDIT_MIN_RETAIN_DAYS
}

pub(crate) fn default_provisioning_config_path() -> PathBuf {
    PathBuf::from(crate::registrar::config::DEFAULT_CONFIG_PATH)
}

pub(crate) fn default_max_wrap_ttl() -> Duration {
    Duration::from_secs(DEFAULT_REGISTRAR_MAX_WRAP_TTL_SECS)
}

pub(crate) fn default_role_token_ttl() -> Duration {
    Duration::from_secs(DEFAULT_REGISTRAR_ROLE_TOKEN_TTL_SECS)
}

pub(crate) fn default_role_secret_id_ttl() -> Duration {
    Duration::from_secs(DEFAULT_REGISTRAR_ROLE_SECRET_ID_TTL_SECS)
}

pub(crate) fn default_secret_id_num_uses() -> u32 {
    DEFAULT_REGISTRAR_SECRET_ID_NUM_USES
}
