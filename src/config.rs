use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Result;
use config::builder::DefaultState;
use config::{Config, ConfigBuilder, ConfigError, Environment, File, FileFormat, FileStoredFormat};
use serde::Deserialize;
use serde::de::{Deserializer, Unexpected, Visitor};

use crate::secret::HmacSecret;

mod defaults;
mod validation;

pub use validation::{
    openbao_url_is_https, openbao_url_is_non_loopback_plaintext, parse_cert_duration,
    validate_cert_duration_vs_default_renew_before, validate_registrar_settings,
};

/// CLI-provided overrides that must survive config reloads in daemon mode.
///
/// Fields mirror the subset of [`crate::Args`] that [`Settings::merge_with_args`]
/// applies. Storing them separately lets the daemon re-apply overrides after
/// every file-based reload without depending on the CLI parser.
#[derive(Clone, Debug, Default)]
pub struct CliOverrides {
    pub email: Option<String>,
    pub ca_url: Option<String>,
    pub http_responder_url: Option<String>,
    pub http_responder_hmac: Option<HmacSecret>,
}

impl From<&crate::Args> for CliOverrides {
    fn from(args: &crate::Args) -> Self {
        Self {
            email: args.email.clone(),
            ca_url: args.ca_url.clone(),
            http_responder_url: args.http_responder_url.clone(),
            http_responder_hmac: args.http_responder_hmac.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    pub email: String,
    pub server: String,
    pub domain: String,
    pub eab: Option<Eab>,
    pub acme: AcmeSettings,
    pub retry: RetrySettings,
    #[serde(default)]
    pub trust: TrustSettings,
    #[serde(default)]
    pub scheduler: SchedulerSettings,
    #[serde(default)]
    pub profiles: Vec<DaemonProfileSettings>,
    /// Optional `OpenBao` client configuration. When present, the daemon
    /// spawns a fast-poll task that watches for `rotate force-reissue`
    /// requests on the KV v2 `reissue` path for each registered service.
    #[serde(default)]
    pub openbao: Option<OpenBaoSettings>,
    /// The host-local registrar endpoint. An absent `[registrar_endpoint]`
    /// table leaves it disabled, which is what every deployment but a
    /// bootroot-host wants.
    #[serde(default)]
    pub registrar_endpoint: RegistrarEndpointSettings,
    /// The daemon-owned registrar audit record store and the verb rate
    /// limiter. An absent `[registrar]` table leaves every key at its
    /// documented default.
    #[serde(default)]
    pub registrar: RegistrarSettings,
}

/// The daemon's own settings for the registrar audit record store and
/// the rate limiter that bounds what reaches it.
///
/// These are deliberately **not** in the bootler-rendered
/// `/etc/clumit-security/provisioning.toml`
/// ([`crate::registrar::RegistrarConfig`]). That file is a
/// cross-repository contract bootroot only reads; where this host keeps
/// its audit records, how large they grow and how many it retains are
/// this daemon's operational choices, and putting them there would make
/// every change to them a change to another repository's renderer.
///
/// Nothing here is reachable from a registrar request. Once a writer is
/// wired in, it will open the store from these values and pass the verbs
/// an already-opened handle, and build their limiter from the four
/// `rate_limit_*` keys the same way.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(from = "RawRegistrarSettings")]
pub struct RegistrarSettings {
    /// Absolute directory the `registrar-audit.jsonl` family lives in,
    /// defaulting to `<audit_store_dir>/records`.
    /// A relative path is rejected: the daemon's cwd is not contracted
    /// to be stable under a systemd-style supervisor, so a relative
    /// path would scatter the audit trail across whatever directory the
    /// unit happened to start in.
    pub audit_record_dir: PathBuf,
    /// Size at which the active file is rotated. Held to a floor large
    /// enough for one maximum-size record.
    pub audit_max_file_bytes: u64,
    /// How many rotated generations are retained beside the active
    /// file. This is the hard capacity ceiling.
    pub audit_max_retained_files: u32,
    /// The retention target in days reported by `bootroot status`.
    /// Where the two disagree, `audit_max_retained_files` wins.
    pub audit_min_retain_days: u32,
    /// Absolute directory containing the daemon's records and `OpenBao`'s
    /// file audit output.
    pub audit_store_dir: PathBuf,
    /// Bytes the operator sets aside for the shared audit store. Nothing
    /// enforces this budget in this build.
    pub audit_store_reserve_bytes: u64,
    /// Remaining bytes at which a future capacity alarm fires.
    pub audit_store_low_water_bytes: u64,
    /// Operator-selected enforcement for the audit store reserve.
    pub audit_store_enforcement: AuditStoreEnforcement,
    /// Tokens an idle registrar `admission` bucket holds — the largest
    /// legitimate bring-up wave one client identity may drive at once.
    ///
    /// Size it as `wave_hosts × modules_per_host`. The default assumes
    /// the reference deployment's 64 hosts × 8 modules = 512 mints in
    /// one wave. A wave larger than the burst still completes rather
    /// than being refused; it takes `(mints − burst) ×
    /// rate_limit_admission_refill_interval_ms / 1000` extra seconds.
    pub rate_limit_admission_burst: u32,
    /// Milliseconds per token accrued into a registrar `admission`
    /// bucket, which is the sustained mint rate.
    ///
    /// An interval rather than a rate so the whole configuration
    /// surface stays free of floating-point values: a rate would have to
    /// be fractional to express "one token per second or slower".
    pub rate_limit_admission_refill_interval_ms: u32,
    /// Tokens an idle registrar `predecision_refusal` bucket holds.
    ///
    /// Much smaller than the admission burst: legitimate refusals on
    /// this path are operator typos arriving one at a time.
    pub rate_limit_predecision_refusal_burst: u32,
    /// Milliseconds per token accrued into a registrar
    /// `predecision_refusal` bucket.
    pub rate_limit_predecision_refusal_refill_interval_ms: u32,
}

/// A `[registrar]` rate-limit value: an unsigned integer, and nothing a
/// configuration file can be coerced into one from.
///
/// The configuration layer's own `u32` conversion is permissive: it turns
/// `0.5` into `1` and `"512"` into `512` and reports nothing. For a
/// limiter's sizing that is a silently wrong bound rather than a typo the
/// operator gets told about — a burst of `1` throttles the first
/// legitimate mint of every bring-up, and nothing in the running daemon
/// says why. Reading the value's *own* type first and refusing everything
/// that is not a non-negative integer is what turns each of those into a
/// load error naming the offending key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateLimitValue(u32);

impl<'de> Deserialize<'de> for RateLimitValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_any(RateLimitValueVisitor)
            .map(Self)
    }
}

struct RateLimitValueVisitor;

impl Visitor<'_> for RateLimitValueVisitor {
    type Value = u32;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("an unsigned integer")
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<u32, E> {
        u32::try_from(value).map_err(|_| E::custom(format!("{value} exceeds {}", u32::MAX)))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<u32, E> {
        u32::try_from(value).map_err(|_| {
            if value < 0 {
                E::invalid_value(Unexpected::Signed(value), &self)
            } else {
                E::custom(format!("{value} exceeds {}", u32::MAX))
            }
        })
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<u32, E> {
        Err(E::invalid_type(Unexpected::Float(value), &self))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<u32, E> {
        Err(E::invalid_type(Unexpected::Str(value), &self))
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<u32, E> {
        Err(E::invalid_type(Unexpected::Bool(value), &self))
    }
}

fn default_rate_limit_admission_burst() -> RateLimitValue {
    RateLimitValue(defaults::default_rate_limit_admission_burst())
}

fn default_rate_limit_admission_refill_interval_ms() -> RateLimitValue {
    RateLimitValue(defaults::default_rate_limit_admission_refill_interval_ms())
}

fn default_rate_limit_predecision_refusal_burst() -> RateLimitValue {
    RateLimitValue(defaults::default_rate_limit_predecision_refusal_burst())
}

fn default_rate_limit_predecision_refusal_refill_interval_ms() -> RateLimitValue {
    RateLimitValue(defaults::default_rate_limit_predecision_refusal_refill_interval_ms())
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
// The raw representation mirrors the TOML contract so key names do not
// depend on separate serde rename strings.
#[allow(clippy::struct_field_names)]
struct RawRegistrarSettings {
    #[serde(default)]
    audit_record_dir: Option<PathBuf>,
    #[serde(default = "defaults::default_audit_max_file_bytes")]
    audit_max_file_bytes: u64,
    #[serde(default = "defaults::default_audit_max_retained_files")]
    audit_max_retained_files: u32,
    #[serde(default = "defaults::default_audit_min_retain_days")]
    audit_min_retain_days: u32,
    #[serde(default = "defaults::default_audit_store_dir")]
    audit_store_dir: PathBuf,
    #[serde(default = "defaults::default_audit_store_reserve_bytes")]
    audit_store_reserve_bytes: u64,
    #[serde(default = "defaults::default_audit_store_low_water_bytes")]
    audit_store_low_water_bytes: u64,
    #[serde(default)]
    audit_store_enforcement: AuditStoreEnforcement,
    #[serde(default = "default_rate_limit_admission_burst")]
    rate_limit_admission_burst: RateLimitValue,
    #[serde(default = "default_rate_limit_admission_refill_interval_ms")]
    rate_limit_admission_refill_interval_ms: RateLimitValue,
    #[serde(default = "default_rate_limit_predecision_refusal_burst")]
    rate_limit_predecision_refusal_burst: RateLimitValue,
    #[serde(default = "default_rate_limit_predecision_refusal_refill_interval_ms")]
    rate_limit_predecision_refusal_refill_interval_ms: RateLimitValue,
}

impl From<RawRegistrarSettings> for RegistrarSettings {
    fn from(raw: RawRegistrarSettings) -> Self {
        let RawRegistrarSettings {
            audit_record_dir,
            audit_max_file_bytes,
            audit_max_retained_files,
            audit_min_retain_days,
            audit_store_dir,
            audit_store_reserve_bytes,
            audit_store_low_water_bytes,
            audit_store_enforcement,
            rate_limit_admission_burst,
            rate_limit_admission_refill_interval_ms,
            rate_limit_predecision_refusal_burst,
            rate_limit_predecision_refusal_refill_interval_ms,
        } = raw;
        let audit_record_dir =
            audit_record_dir.unwrap_or_else(|| defaults::audit_record_dir_for(&audit_store_dir));
        Self {
            audit_record_dir,
            audit_max_file_bytes,
            audit_max_retained_files,
            audit_min_retain_days,
            audit_store_dir,
            audit_store_reserve_bytes,
            audit_store_low_water_bytes,
            audit_store_enforcement,
            rate_limit_admission_burst: rate_limit_admission_burst.0,
            rate_limit_admission_refill_interval_ms: rate_limit_admission_refill_interval_ms.0,
            rate_limit_predecision_refusal_burst: rate_limit_predecision_refusal_burst.0,
            rate_limit_predecision_refusal_refill_interval_ms:
                rate_limit_predecision_refusal_refill_interval_ms.0,
        }
    }
}

/// An audit store reserve enforcement mode.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuditStoreEnforcement {
    /// A filesystem-provided ceiling, supplied by separate work and not
    /// yet in place in this build.
    #[default]
    Filesystem,
    /// A plain directory with an unenforced configured reserve.
    Directory,
}

impl Default for RegistrarSettings {
    fn default() -> Self {
        let audit_store_dir = defaults::default_audit_store_dir();
        Self {
            audit_record_dir: defaults::audit_record_dir_for(&audit_store_dir),
            audit_max_file_bytes: defaults::default_audit_max_file_bytes(),
            audit_max_retained_files: defaults::default_audit_max_retained_files(),
            audit_min_retain_days: defaults::default_audit_min_retain_days(),
            audit_store_dir,
            audit_store_reserve_bytes: defaults::default_audit_store_reserve_bytes(),
            audit_store_low_water_bytes: defaults::default_audit_store_low_water_bytes(),
            audit_store_enforcement: AuditStoreEnforcement::default(),
            rate_limit_admission_burst: defaults::default_rate_limit_admission_burst(),
            rate_limit_admission_refill_interval_ms:
                defaults::default_rate_limit_admission_refill_interval_ms(),
            rate_limit_predecision_refusal_burst:
                defaults::default_rate_limit_predecision_refusal_burst(),
            rate_limit_predecision_refusal_refill_interval_ms:
                defaults::default_rate_limit_predecision_refusal_refill_interval_ms(),
        }
    }
}

/// The host-local registrar endpoint's only setting.
///
/// The endpoint is a Linux-only, systemd-socket-activated `AF_UNIX`
/// listener. There is deliberately no socket path here: the pathname is
/// the socket unit's, and a daemon that could be pointed at a path of
/// its own would be a daemon that could be pointed at an unprotected
/// one.
///
/// `enabled` is fixed for a process lifetime. The listening descriptor is
/// inherited once, before the reload loop, so a `SIGHUP` cannot conjure
/// one that was never passed in, and cannot drop one whose socket unit
/// still holds the pathname open. A reload whose value differs from the
/// running one is rejected outright and the running daemon is left
/// undisturbed; changing it takes a service restart.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistrarEndpointSettings {
    /// Whether the daemon serves the registrar verbs on the activated
    /// socket. Defaults to `false`, including when the table is absent.
    #[serde(default)]
    pub enabled: bool,
}

/// Checks that a reloaded configuration keeps `[registrar_endpoint]
/// enabled` at the value the running process started with.
///
/// The activation contract is consumed once, above the reload loop, so
/// this value is not a reloadable one: enabling it on a `SIGHUP` would
/// have no descriptor to serve, and disabling it would leave the socket
/// unit holding a pathname nothing accepts on. Both are rejected here
/// rather than half-applied.
///
/// # Errors
///
/// Returns an error naming both values when they differ.
pub fn check_registrar_endpoint_reload(running: bool, reloaded: bool) -> Result<()> {
    if running == reloaded {
        return Ok(());
    }
    anyhow::bail!(
        "registrar_endpoint.enabled changed from {running} to {reloaded}; \
         it is fixed for the process lifetime because the listening socket is \
         inherited once at startup, so this reload is rejected and the running \
         daemon is left as it is. Restart the service to apply the change"
    )
}

/// `OpenBao` connection settings for the remote-agent fast-poll loop.
///
/// The remote `bootroot-agent` authenticates directly via `AppRole` and
/// polls `{kv_mount}/data/bootroot/services/<registration_id>/reissue` on
/// the configured `fast_poll_interval` to pick up force-reissue requests
/// issued by the control plane.
#[derive(Debug, Deserialize, Clone)]
pub struct OpenBaoSettings {
    pub url: String,
    /// Opt-in that allows a non-loopback plaintext `http://` `url`.
    ///
    /// Over plaintext the `AppRole` login POSTs `role_id` + `secret_id`
    /// as cleartext and every KV poll response carries `secret_id`,
    /// responder HMAC, and EAB in cleartext, so a non-loopback plaintext
    /// URL exposes live credentials on the wire. Validation rejects such
    /// a URL unless the operator sets this flag; loopback plaintext and
    /// `https://` never require it. See issue #695.
    #[serde(default)]
    pub allow_plaintext_http: bool,
    #[serde(default = "defaults::default_kv_mount")]
    pub kv_mount: String,
    pub role_id_path: PathBuf,
    pub secret_id_path: PathBuf,
    #[serde(default)]
    pub ca_bundle_path: Option<PathBuf>,
    #[serde(
        default = "defaults::default_fast_poll_interval",
        with = "duration_serde"
    )]
    pub fast_poll_interval: Duration,
    /// On-disk path where the agent persists its `last_reissue_seen_version`,
    /// `in_flight_renewals`, and `pending_completion_writes` maps across
    /// restarts. Must be absolute — a cwd-relative path is rejected by
    /// validation because the agent process cwd is not contracted to be
    /// stable or writable under systemd-style supervisors.
    /// `bootroot-remote bootstrap` auto-provisions an absolute path
    /// adjacent to `agent.toml`.
    #[serde(default = "defaults::default_fast_poll_state_path")]
    pub state_path: PathBuf,
}

#[must_use]
pub fn profile_domain(settings: &Settings, profile: &DaemonProfileSettings) -> String {
    format!(
        "{}.{}.{}.{}",
        profile.instance_id, profile.service_name, profile.hostname, settings.domain
    )
}

#[derive(Debug, Deserialize, Clone)]
pub struct Paths {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Eab {
    pub kid: String,
    pub hmac: HmacSecret,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DaemonProfileSettings {
    /// Deployment-wide unique key naming the namespaces this profile
    /// polls: the `bootroot/services/<key>` KV subtree and the
    /// per-profile fast-poll state filename. Required — a `[[profiles]]`
    /// block that omits it is an invalid config and fails to
    /// deserialize.
    pub registration_id: String,
    /// Second label of the certificate SAN this profile requests. Never
    /// a namespace key; see [`DaemonProfileSettings::registration_id`].
    pub service_name: String,
    pub instance_id: String,
    pub hostname: String,
    pub paths: Paths,
    #[serde(default)]
    pub daemon: DaemonRuntimeSettings,
    #[serde(default)]
    pub retry: Option<RetrySettings>,
    #[serde(default)]
    pub hooks: HookSettings,
    pub eab: Option<Eab>,
    /// Numeric gid that owns the issued cert/key files and their
    /// parent directories under the `--cert-group` policy.
    /// `None` (the default) preserves the host-local default mode
    /// and operator-only ownership. See issue #593.
    #[serde(default)]
    pub cert_group_gid: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DaemonRuntimeSettings {
    #[serde(default = "defaults::default_check_interval", with = "duration_serde")]
    pub check_interval: Duration,
    #[serde(default = "defaults::default_renew_before", with = "duration_serde")]
    pub renew_before: Duration,
    #[serde(default = "defaults::default_check_jitter", with = "duration_serde")]
    pub check_jitter: Duration,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AcmeSettings {
    pub http_responder_url: String,
    pub http_responder_hmac: HmacSecret,
    pub http_responder_timeout_secs: u64,
    pub http_responder_token_ttl_secs: u64,
    pub directory_fetch_attempts: u64,
    pub directory_fetch_base_delay_secs: u64,
    pub directory_fetch_max_delay_secs: u64,
    pub poll_attempts: u64,
    pub poll_interval_secs: u64,
    /// Where the ACME **account** signing key is persisted.
    ///
    /// Absent — the default, and what every existing configuration has
    /// — keeps the historical behaviour: a fresh account key is
    /// generated per issuance and the account is re-registered under it.
    /// Set, the key is loaded from that path, or created there once with
    /// restrictive permissions, so the profile keeps one stable ACME
    /// account across renewals. The bootroot-internal registrar
    /// credential is the one profile that sets it.
    #[serde(default)]
    pub account_key_path: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RetrySettings {
    pub backoff_secs: Vec<u64>,
}

#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct TrustSettings {
    #[serde(default)]
    pub ca_bundle_path: Option<PathBuf>,
    #[serde(default)]
    pub trusted_ca_sha256: Vec<String>,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct SchedulerSettings {
    #[serde(default = "defaults::default_max_concurrent_issuances")]
    pub max_concurrent_issuances: u64,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct HookSettings {
    #[serde(default)]
    pub post_renew: PostRenewHooks,
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PostRenewHooks {
    #[serde(default)]
    pub success: Vec<HookCommand>,
    #[serde(default)]
    pub failure: Vec<HookCommand>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HookCommand {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub working_dir: Option<PathBuf>,
    #[serde(default = "defaults::default_hook_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub retry_backoff_secs: Vec<u64>,
    #[serde(default)]
    pub max_output_bytes: Option<u64>,
    #[serde(default)]
    pub on_failure: HookFailurePolicy,
}

#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HookFailurePolicy {
    #[default]
    Continue,
    Stop,
}

impl Default for DaemonRuntimeSettings {
    fn default() -> Self {
        Self {
            check_interval: defaults::default_check_interval(),
            renew_before: defaults::default_renew_before(),
            check_jitter: defaults::default_check_jitter(),
        }
    }
}

mod duration_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        humantime::parse_duration(&value).map_err(serde::de::Error::custom)
    }
}

impl Settings {
    /// Creates a new `Settings` instance.
    ///
    /// # Errors
    /// Returns error if configuration parsing fails (e.g. file not found, invalid format).
    pub fn new(config_path: Option<PathBuf>) -> Result<Self, ConfigError> {
        // 3. Environment Variables (double-underscore for nesting)
        // e.g. BOOTROOT_EMAIL, BOOTROOT_PATHS__CERT, BOOTROOT_DAEMON__RENEW_BEFORE
        let s = Self::file_builder(config_path)?.add_source(
            Environment::with_prefix("BOOTROOT")
                .separator("__")
                .try_parsing(true)
                .ignore_empty(true)
                .list_separator(",")
                .with_list_parse_key("retry.backoff_secs")
                .with_list_parse_key("trust.trusted_ca_sha256"),
        );

        // 4. Build
        s.build()?.try_deserialize()
    }

    /// Creates a new `Settings` instance from `config_path` alone, without
    /// the `BOOTROOT_*` environment overlay that [`Settings::new`] applies.
    ///
    /// Use this to assert on what a file actually contains. Reading through
    /// `new` would let a `BOOTROOT_*` variable in the caller's environment
    /// replace the value under test, and the only way to rule that out
    /// there is to empty the environment first — which no process running a
    /// tokio runtime, an HTTP client, or an env-filtered subscriber can do
    /// soundly, since `set_var` requires that nothing else be reading.
    ///
    /// # Errors
    /// Returns error if configuration parsing fails (e.g. file not found, invalid format).
    pub fn from_file(config_path: Option<PathBuf>) -> Result<Self, ConfigError> {
        Self::file_builder(config_path)?.build()?.try_deserialize()
    }

    /// Creates settings from one required configuration file without an
    /// environment overlay.
    ///
    /// Unlike [`Settings::from_file`], this refuses an absent, unreadable,
    /// or unsupported-format file instead of silently deserializing defaults.
    ///
    /// # Errors
    /// Returns an error if the file cannot be read, its format is unsupported,
    /// or its configuration cannot be deserialized.
    pub fn from_required_file(config_path: &Path) -> Result<Self, ConfigError> {
        let format = required_file_format(config_path)?;
        let contents =
            std::fs::read(config_path).map_err(|error| ConfigError::Foreign(Box::new(error)))?;
        // Match `config::File`'s lossy decoding so invalid UTF-8 retains its
        // previous behavior instead of becoming a new load failure.
        let contents = String::from_utf8_lossy(strip_utf8_bom(&contents));

        defaults::apply_defaults(Config::builder())?
            .add_source(File::from_str(&contents, format))
            .build()?
            .try_deserialize()
    }

    /// Builds the defaults-plus-optional-file layers used by [`Settings::new`]
    /// and [`Settings::from_file`].
    fn file_builder(
        config_path: Option<PathBuf>,
    ) -> Result<ConfigBuilder<DefaultState>, ConfigError> {
        let mut s = Config::builder();

        // 1. Set Defaults
        s = defaults::apply_defaults(s)?;

        // 2. Merge File (optional)
        // If config_path is provided, use it. Otherwise look for "agent.toml"
        let path = config_path.unwrap_or_else(|| PathBuf::from("agent.toml"));

        // Add file source (required = false, so it doesn't panic if missing)
        Ok(s.add_source(File::from(path).required(false)))
    }

    /// Merges CLI arguments into the settings, overriding values if present.
    pub fn merge_with_args(&mut self, args: &crate::Args) {
        self.apply_overrides(&CliOverrides::from(args));
    }

    /// Re-applies CLI-provided overrides on top of these settings.
    pub fn apply_overrides(&mut self, overrides: &CliOverrides) {
        if let Some(email) = &overrides.email {
            email.clone_into(&mut self.email);
        }
        if let Some(ca_url) = &overrides.ca_url {
            ca_url.clone_into(&mut self.server);
        }
        if let Some(responder_url) = &overrides.http_responder_url {
            responder_url.clone_into(&mut self.acme.http_responder_url);
        }
        if let Some(responder_hmac) = &overrides.http_responder_hmac {
            self.acme.http_responder_hmac = responder_hmac.clone();
        }
    }

    /// Validates configuration values for correctness.
    ///
    /// # Errors
    /// Returns error if any setting is invalid or out of range.
    pub fn validate(&self) -> Result<()> {
        validation::validate_settings(self)
    }
}

/// Returns the supported format for one strict configuration path.
///
/// This deliberately examines only the exact supplied path. `config::File`
/// performs filename discovery when its source path is absent, which is useful
/// for optional configuration but unsafe for an explicitly selected file.
fn required_file_format(config_path: &Path) -> Result<FileFormat, ConfigError> {
    // `Cargo.toml` enables only config's `toml` feature. Add a branch for
    // each subsequently enabled file format so strict and optional sources
    // continue to accept the same extensions.
    let format = FileFormat::Toml;
    if config_path
        .extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| format.file_extensions().contains(&extension))
    {
        Ok(format)
    } else {
        Err(ConfigError::Message(format!(
            "configuration file \"{}\" is not of a supported file format",
            config_path.display()
        )))
    }
}

/// Removes a UTF-8 byte-order mark before parsing.
///
/// This retains `config::File` source behavior should a future supported
/// format not tolerate a byte-order mark itself.
fn strip_utf8_bom(contents: &[u8]) -> &[u8] {
    const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

    if contents.starts_with(UTF8_BOM) {
        &contents[UTF8_BOM.len()..]
    } else {
        contents
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::time::Duration;

    use super::*;

    fn write_minimal_profile_config(file: &mut tempfile::NamedTempFile) {
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            registration_id = "edge-proxy"
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"
        "#
        )
        .unwrap();
        file.flush().unwrap();
    }

    #[test]
    fn test_load_settings_defaults() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();

        assert_eq!(settings.email, "admin@example.com");
        assert_eq!(
            settings.server,
            "https://localhost:9000/acme/acme/directory"
        );
        assert_eq!(settings.domain, "trusted.domain");
        assert_eq!(settings.acme.http_responder_url, "http://localhost:8080");
        assert_eq!(settings.acme.http_responder_hmac.expose(), "dev-hmac");
        assert_eq!(settings.acme.http_responder_timeout_secs, 5);
        assert_eq!(settings.acme.http_responder_token_ttl_secs, 300);
        assert_eq!(settings.acme.directory_fetch_attempts, 10);
        assert_eq!(settings.acme.directory_fetch_base_delay_secs, 1);
        assert_eq!(settings.acme.directory_fetch_max_delay_secs, 10);
        assert_eq!(settings.acme.poll_attempts, 15);
        assert_eq!(settings.acme.poll_interval_secs, 2);
        assert_eq!(settings.retry.backoff_secs, vec![5, 10, 30, 60]);
        assert_eq!(settings.scheduler.max_concurrent_issuances, 3);
        assert!(settings.trust.ca_bundle_path.is_none());
        assert!(settings.trust.trusted_ca_sha256.is_empty());

        let profile = &settings.profiles[0];
        assert_eq!(profile.daemon.check_interval, Duration::from_hours(1));
        assert_eq!(profile.daemon.renew_before, Duration::from_hours(16));
        assert_eq!(profile.daemon.check_jitter, Duration::from_secs(0));
        assert!(profile.hooks.post_renew.success.is_empty());
        assert!(profile.hooks.post_renew.failure.is_empty());
    }

    #[test]
    fn optional_file_loading_accepts_a_missing_path_but_required_loading_rejects_it() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("missing-agent.toml");

        let optional = Settings::from_file(Some(missing.clone())).unwrap();
        assert_eq!(optional.email, "admin@example.com");
        assert!(Settings::from_required_file(&missing).is_err());
    }

    #[test]
    fn required_file_loading_never_discovers_a_toml_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let supplied = dir.path().join("agent");
        let sibling = dir.path().join("agent.toml");
        std::fs::write(&sibling, "email = \"sibling@example.com\"\n").unwrap();

        let error = Settings::from_required_file(&supplied).expect_err(
            "an extension-less supplied path must be rejected before reading a sibling",
        );
        assert!(
            error
                .to_string()
                .contains("is not of a supported file format")
        );
    }

    #[test]
    fn required_file_loading_rejects_unsupported_and_extensionless_files() {
        let dir = tempfile::tempdir().unwrap();
        let unsupported = dir.path().join("agent.unsupported");
        let extensionless = dir.path().join("agent-config");
        std::fs::write(&unsupported, "[registrar]\n").unwrap();
        std::fs::write(&extensionless, "[registrar]\n").unwrap();

        assert!(Settings::from_required_file(&unsupported).is_err());
        assert!(Settings::from_required_file(&extensionless).is_err());
    }

    #[test]
    fn strip_utf8_bom_removes_only_a_leading_marker() {
        assert_eq!(
            strip_utf8_bom(b"\xEF\xBB\xBFemail = \"admin@example.com\""),
            b"email = \"admin@example.com\""
        );
        assert_eq!(
            strip_utf8_bom(b"email = \"admin@example.com\""),
            b"email = \"admin@example.com\""
        );
    }

    #[test]
    fn test_load_settings_rejects_invalid_duration() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            email = "file@example.com"
            server = "http://file-server"
            domain = "example.internal"

            [[profiles]]
            registration_id = "edge-proxy"
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "file/cert.pem"
            key = "file/key.pem"

            [profiles.daemon]
            check_interval = "nope"
        "#
        )
        .unwrap();
        file.flush().unwrap();

        let err = Settings::new(Some(file.path().to_path_buf())).unwrap_err();
        assert!(err.to_string().contains("check_interval"));
    }

    #[test]
    fn test_load_settings_rejects_removed_trust_verify_key() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            r"
            [trust]
            verify_certificates = false
        "
        )
        .unwrap();
        file.flush().unwrap();

        let err = Settings::new(Some(file.path().to_path_buf())).unwrap_err();
        assert!(err.to_string().contains("verify_certificates"));
    }

    #[test]
    fn test_load_settings_file_override() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            email = "file@example.com"
            server = "http://file-server"
            domain = "example.internal"

            [[profiles]]
            registration_id = "edge-proxy"
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "file/cert.pem"
            key = "file/key.pem"
        "#
        )
        .unwrap();
        // File::flush is important to ensure content is on disk
        file.flush().unwrap();

        let path = file.path().to_path_buf();
        let settings = Settings::new(Some(path)).unwrap();

        assert_eq!(settings.email, "file@example.com");
        assert_eq!(settings.server, "http://file-server");
        assert_eq!(settings.domain, "example.internal");
    }

    #[test]
    fn test_merge_with_args() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();

        let args = crate::Args {
            config: None,
            email: Some("cli@example.com".to_string()),
            ca_url: None, // Keep default/config
            http_responder_url: None,
            http_responder_hmac: None,
            eab_kid: None,
            eab_hmac: None,
            eab_file: None,
            oneshot: false,
            insecure: false,
        };

        settings.merge_with_args(&args);

        // Should be overridden
        assert_eq!(settings.email, "cli@example.com");
        // Should remain default
        assert_eq!(
            settings.server,
            "https://localhost:9000/acme/acme/directory"
        );
    }

    #[test]
    fn test_apply_overrides_replaces_all_fields() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();

        let overrides = CliOverrides {
            email: Some("override@example.com".to_string()),
            ca_url: Some("https://override-ca".to_string()),
            http_responder_url: Some("http://override-responder".to_string()),
            http_responder_hmac: Some("override-hmac".into()),
        };

        settings.apply_overrides(&overrides);

        assert_eq!(settings.email, "override@example.com");
        assert_eq!(settings.server, "https://override-ca");
        assert_eq!(
            settings.acme.http_responder_url,
            "http://override-responder"
        );
        assert_eq!(settings.acme.http_responder_hmac.expose(), "override-hmac");
    }

    #[test]
    fn test_apply_overrides_skips_none_fields() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        let original_email = settings.email.clone();
        let original_server = settings.server.clone();

        let overrides = CliOverrides::default();
        settings.apply_overrides(&overrides);

        assert_eq!(settings.email, original_email);
        assert_eq!(settings.server, original_server);
    }

    /// Regression test for #475: reloading the config from disk then applying
    /// CLI overrides must produce the CLI value, not the file/default value.
    #[test]
    fn test_reload_then_apply_overrides_preserves_cli_values() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        // Config deliberately omits http_responder_hmac so it falls back to
        // the compiled default (empty string).
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            email = "file@example.com"

            [acme]
            http_responder_url = "http://localhost:8080"

            [[profiles]]
            registration_id = "edge-proxy"
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"
        "#
        )
        .unwrap();
        file.flush().unwrap();

        let overrides = CliOverrides {
            email: None,
            ca_url: Some("https://cli-ca".to_string()),
            http_responder_url: None,
            http_responder_hmac: Some("cli-hmac-secret".into()),
        };

        // Simulate the daemon retry path: reload from disk, then apply overrides.
        let mut fresh = Settings::new(Some(file.path().to_path_buf())).unwrap();
        fresh.apply_overrides(&overrides);

        // CLI-provided values must win.
        assert_eq!(fresh.server, "https://cli-ca");
        assert_eq!(fresh.acme.http_responder_hmac.expose(), "cli-hmac-secret");
        // File-provided values stay when CLI has no override.
        assert_eq!(fresh.email, "file@example.com");
        assert_eq!(fresh.acme.http_responder_url, "http://localhost:8080");
    }

    #[test]
    fn test_validate_rejects_invalid_acme_settings() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.acme.directory_fetch_attempts = 0;
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("directory_fetch_attempts"));
    }

    #[test]
    fn test_validate_rejects_empty_domain() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.domain = "  ".to_string();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("domain must not be empty"));
    }

    #[test]
    fn test_validate_rejects_non_ascii_domain() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.domain = "예시.local".to_string();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("domain must be ASCII"));
    }

    #[test]
    fn test_profile_domain_uses_settings_domain() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.domain = "example.internal".to_string();
        let profile = &settings.profiles[0];
        let domain = profile_domain(&settings, profile);
        assert_eq!(domain, "001.edge-proxy.edge-node-01.example.internal");
    }

    #[test]
    fn test_validate_rejects_empty_retry_backoff() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.retry.backoff_secs = Vec::new();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("retry.backoff_secs"));
    }

    #[test]
    fn test_validate_rejects_empty_hook_command() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hooks.post_renew.success = vec![HookCommand {
            command: "   ".to_string(),
            args: Vec::new(),
            working_dir: None,
            timeout_secs: 30,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
            on_failure: HookFailurePolicy::Continue,
        }];

        let err = settings.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("profiles.hooks.post_renew.success")
        );
    }

    #[test]
    fn test_validate_rejects_hook_timeout_zero() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hooks.post_renew.failure = vec![HookCommand {
            command: "true".to_string(),
            args: Vec::new(),
            working_dir: None,
            timeout_secs: 0,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
            on_failure: HookFailurePolicy::Continue,
        }];

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("timeout_secs"));
    }

    #[test]
    fn test_validate_rejects_hook_retry_backoff_zero() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hooks.post_renew.success = vec![HookCommand {
            command: "true".to_string(),
            args: Vec::new(),
            working_dir: None,
            timeout_secs: 30,
            retry_backoff_secs: vec![0],
            max_output_bytes: None,
            on_failure: HookFailurePolicy::Continue,
        }];

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("retry_backoff_secs"));
    }

    #[test]
    fn test_validate_rejects_empty_profiles() {
        let mut settings = Settings::new(None).unwrap();
        settings.acme.http_responder_hmac = "test".into();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("profiles must not be empty"));
    }

    #[test]
    fn test_validate_rejects_hook_working_dir_empty() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hooks.post_renew.success = vec![HookCommand {
            command: "true".to_string(),
            args: Vec::new(),
            working_dir: Some(PathBuf::new()),
            timeout_secs: 30,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: None,
            on_failure: HookFailurePolicy::Continue,
        }];

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("working_dir"));
    }

    #[test]
    fn test_validate_rejects_hook_max_output_zero() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hooks.post_renew.success = vec![HookCommand {
            command: "true".to_string(),
            args: Vec::new(),
            working_dir: None,
            timeout_secs: 30,
            retry_backoff_secs: Vec::new(),
            max_output_bytes: Some(0),
            on_failure: HookFailurePolicy::Continue,
        }];

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("max_output_bytes"));
    }

    #[test]
    fn test_validate_rejects_profile_retry_backoff_zero() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].retry = Some(RetrySettings {
            backoff_secs: vec![0],
        });

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("profiles.retry.backoff_secs"));
    }

    /// Regression test: an `[openbao]` section whose `state_path` is
    /// relative (including the in-tree default `bootroot-agent-state.json`)
    /// must fail validation. This is the same restart-persistence hazard
    /// called out in Round 5 — under a systemd-style supervisor the
    /// agent process cwd is not contracted to be stable or writable, so
    /// a cwd-relative state file can be silently lost across restarts.
    #[test]
    fn validate_rejects_relative_openbao_state_path() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            registration_id = "edge-proxy"
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"

            [openbao]
            url = "http://localhost:8200"
            role_id_path = "/etc/bootroot/role_id"
            secret_id_path = "/etc/bootroot/secret_id"
            state_path = "bootroot-agent-state.json"
        "#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        let err = settings.validate().unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("openbao.state_path"), "{msg}");
        assert!(msg.contains("absolute"), "{msg}");
    }

    /// When `[openbao]` is present but `state_path` is omitted entirely,
    /// the parser fills in the in-tree default (a bare relative
    /// filename). Validation must still reject it — i.e. an omitted
    /// `state_path` surfaces the same error rather than silently
    /// entrenching a cwd-relative path. This mirrors the scenario where
    /// `bootroot-remote bootstrap` ran with a relative `agent_config_path`
    /// and therefore skipped provisioning `state_path`.
    #[test]
    fn validate_rejects_omitted_openbao_state_path_via_default() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            registration_id = "edge-proxy"
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"

            [openbao]
            url = "http://localhost:8200"
            role_id_path = "/etc/bootroot/role_id"
            secret_id_path = "/etc/bootroot/secret_id"
        "#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("openbao.state_path"));
    }

    /// Round-trip test for the `--cert-group` policy on a profile:
    /// the daemon must parse `cert_group_gid = N` from the rendered
    /// `agent.toml` and surface it on the in-memory profile, so the
    /// issuance/rotation path can apply the group ownership policy.
    /// Without this, every rotation reverts to operator-only and the
    /// original issue #593 reproduces.
    #[test]
    fn settings_parses_profile_cert_group_gid() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            registration_id = "edge-proxy"
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"
            cert_group_gid = 5001

            [profiles.paths]
            cert = "certs/edge-proxy.pem"
            key = "certs/edge-proxy.key"
        "#
        )
        .unwrap();
        file.flush().unwrap();

        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        let profile = &settings.profiles[0];
        assert_eq!(profile.cert_group_gid, Some(5001));
    }

    #[test]
    fn settings_defaults_profile_cert_group_gid_to_none() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        let profile = &settings.profiles[0];
        assert!(profile.cert_group_gid.is_none());
    }

    /// `cert_group_gid = 0` is rejected at validation: gid 0 is root
    /// and granting it would be a no-op against the operator-only
    /// default, while masking an obvious misconfiguration.
    #[test]
    fn validate_rejects_cert_group_gid_zero() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            registration_id = "edge-proxy"
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"
            cert_group_gid = 0

            [profiles.paths]
            cert = "certs/edge-proxy.pem"
            key = "certs/edge-proxy.key"
        "#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("cert_group_gid"));
    }

    /// `cert_group_gid` set to a value not present in the host's group
    /// database is rejected at validation. This is the orphan-gid case
    /// called out in the issue #593 review: a numeric gid that exists
    /// on a different host (e.g. the container image's runtime user)
    /// but not on the cert-writing host. Without this check the kernel
    /// would silently accept `chown(-1, gid)` and the consumer would
    /// still hit EACCES because the gid resolves to no real group.
    #[test]
    fn validate_rejects_cert_group_gid_unknown_on_host() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            registration_id = "edge-proxy"
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"
            cert_group_gid = 4000000000

            [profiles.paths]
            cert = "certs/edge-proxy.pem"
            key = "certs/edge-proxy.key"
        "#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        let err = settings.validate().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("cert_group_gid") && msg.contains("4000000000"),
            "expected unknown-gid error, got: {msg}",
        );
    }

    /// Accepts the common case where `[openbao]` carries an absolute
    /// `state_path` — this is what `bootroot-remote bootstrap`
    /// auto-provisions when `agent_config_path` is absolute.
    #[test]
    fn validate_accepts_absolute_openbao_state_path() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            registration_id = "edge-proxy"
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"

            [openbao]
            url = "http://localhost:8200"
            role_id_path = "/etc/bootroot/role_id"
            secret_id_path = "/etc/bootroot/secret_id"
            state_path = "/var/lib/bootroot/bootroot-agent-state.json"
        "#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings
            .validate()
            .expect("absolute state_path must validate");
    }

    /// `registration_id` is required, not defaulted: a `[[profiles]]`
    /// block that omits it is an invalid config and must fail at
    /// deserialization, before any validation runs. There is no
    /// fall-back to `service_name` anywhere.
    #[test]
    fn settings_reject_profile_without_registration_id() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        writeln!(
            file,
            r#"
            domain = "trusted.domain"
            [acme]
            http_responder_url = "http://localhost:8080"
            http_responder_hmac = "dev-hmac"

            [[profiles]]
            service_name = "edge-proxy"
            instance_id = "001"
            hostname = "edge-node-01"

            [profiles.paths]
            cert = "certs/edge-proxy-a.pem"
            key = "certs/edge-proxy-a.key"
        "#
        )
        .unwrap();
        file.flush().unwrap();

        let err = Settings::new(Some(file.path().to_path_buf())).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("registration_id"), "{msg}");
    }

    /// The path-safe rule is enforced at config load, so a bad key never
    /// reaches the polling loop as a KV path or a state filename.
    #[test]
    fn validate_rejects_non_path_safe_registration_id() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].registration_id = "a".repeat(132);
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("profiles.registration_id"));

        settings.profiles[0].registration_id = "H1-Piglet".to_string();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("profiles.registration_id"));

        // The structural maximum is accepted, so the wider key the
        // derivation rule can compose is not rejected here.
        settings.profiles[0].registration_id = "a".repeat(131);
        settings
            .validate()
            .expect("a 131-octet registration_id must validate");
    }

    /// `service_name` is the SAN's second label, so it is held to the
    /// DNS-label rule at config load rather than at CSR time.
    #[test]
    fn validate_rejects_non_dns_label_service_name() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].service_name = "a".repeat(64);
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("profiles.service_name"), "{err}");

        settings.profiles[0].service_name = "edge.proxy".to_string();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("profiles.service_name"), "{err}");
    }

    /// `hostname` is the SAN's third label, held to the same DNS-label
    /// rule as `service_name` so a dotted or over-long value fails at
    /// config load rather than at CSR time.
    #[test]
    fn validate_rejects_non_dns_label_hostname() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.profiles[0].hostname = "a".repeat(64);
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("profiles.hostname"), "{err}");

        settings.profiles[0].hostname = "edge.proxy".to_string();
        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("profiles.hostname"), "{err}");

        settings.profiles[0].hostname = String::new();
        let err = settings.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("profiles.hostname must not be empty"),
            "{err}"
        );
    }

    /// The SAN keeps reading `service_name`: a `registration_id` that
    /// differs from it must not leak into any name the certificate
    /// carries.
    #[test]
    fn profile_domain_never_carries_the_registration_id() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
        settings.domain = "example.internal".to_string();
        settings.profiles[0].registration_id = "edge-node-01-edge-proxy-001".to_string();

        let domain = profile_domain(&settings, &settings.profiles[0]);
        assert_eq!(domain, "001.edge-proxy.edge-node-01.example.internal");
        assert!(!domain.contains("edge-node-01-edge-proxy-001"));
    }

    /// An absent `[registrar_endpoint]` table leaves the endpoint
    /// disabled. That is what keeps every deployment that never asked
    /// for it from inspecting an activation variable or opening a
    /// listener.
    #[test]
    fn an_absent_registrar_endpoint_table_leaves_the_endpoint_disabled() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert!(!settings.registrar_endpoint.enabled);
        assert_eq!(
            settings.registrar_endpoint,
            RegistrarEndpointSettings::default()
        );
    }

    /// An empty table is the same as an absent one: `enabled` defaults
    /// to `false` on its own, not only through the table's default.
    #[test]
    fn an_empty_registrar_endpoint_table_leaves_the_endpoint_disabled() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar_endpoint]").unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert!(!settings.registrar_endpoint.enabled);
    }

    #[test]
    fn the_registrar_endpoint_table_reads_an_explicit_value() {
        for (rendered, expected) in [("true", true), ("false", false)] {
            let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
            write_minimal_profile_config(&mut file);
            writeln!(file, "\n[registrar_endpoint]\nenabled = {rendered}").unwrap();
            file.flush().unwrap();
            let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
            assert_eq!(settings.registrar_endpoint.enabled, expected, "{rendered}");
        }
    }

    /// The table takes exactly one key, so a misspelled one is a config
    /// error rather than a setting that silently does nothing.
    #[test]
    fn the_registrar_endpoint_table_rejects_an_unknown_key() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar_endpoint]\nenable = true").unwrap();
        file.flush().unwrap();
        assert!(Settings::from_file(Some(file.path().to_path_buf())).is_err());
    }

    /// An absent `[registrar]` table gives every audit-store key the
    /// value the documentation states.
    #[test]
    fn an_absent_registrar_table_loads_the_documented_audit_defaults() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert_eq!(
            settings.registrar.audit_record_dir,
            PathBuf::from("/var/lib/bootroot/audit-store/records")
        );
        assert_eq!(
            settings.registrar.audit_store_dir,
            PathBuf::from("/var/lib/bootroot/audit-store")
        );
        assert_eq!(settings.registrar.audit_store_reserve_bytes, 2_147_483_648);
        assert_eq!(settings.registrar.audit_store_low_water_bytes, 536_870_912);
        assert_eq!(
            settings.registrar.audit_store_enforcement,
            AuditStoreEnforcement::Filesystem
        );
        assert_eq!(settings.registrar.audit_max_file_bytes, 8_388_608);
        assert_eq!(settings.registrar.audit_max_retained_files, 16);
        assert_eq!(settings.registrar.audit_min_retain_days, 90);
        assert_eq!(settings.registrar.rate_limit_admission_burst, 512);
        assert_eq!(
            settings.registrar.rate_limit_admission_refill_interval_ms,
            500
        );
        assert_eq!(settings.registrar.rate_limit_predecision_refusal_burst, 32);
        assert_eq!(
            settings
                .registrar
                .rate_limit_predecision_refusal_refill_interval_ms,
            1000
        );
        assert_eq!(settings.registrar, RegistrarSettings::default());
        settings.validate().unwrap();
    }

    /// A `[registrar]` table that sets only the pre-existing keys leaves
    /// every one of their values unchanged and takes the limiter
    /// defaults. This is what keeps adding the four `rate_limit_*` keys
    /// invisible to a deployment that never asked for them.
    #[test]
    fn a_registrar_table_without_the_rate_limit_keys_keeps_every_other_value() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            r#"
[registrar]
audit_store_dir = "/srv/bootroot/audit-store"
audit_record_dir = "/srv/bootroot/audit-store/records"
audit_max_file_bytes = 131072
audit_max_retained_files = 4
audit_min_retain_days = 30
audit_store_reserve_bytes = 4294967296
audit_store_low_water_bytes = 1073741824
audit_store_enforcement = "directory"
"#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        let registrar = &settings.registrar;
        assert_eq!(
            registrar.audit_record_dir,
            PathBuf::from("/srv/bootroot/audit-store/records")
        );
        assert_eq!(
            registrar.audit_store_dir,
            PathBuf::from("/srv/bootroot/audit-store")
        );
        assert_eq!(registrar.audit_max_file_bytes, 131_072);
        assert_eq!(registrar.audit_max_retained_files, 4);
        assert_eq!(registrar.audit_min_retain_days, 30);
        assert_eq!(registrar.audit_store_reserve_bytes, 4_294_967_296);
        assert_eq!(registrar.audit_store_low_water_bytes, 1_073_741_824);
        assert_eq!(
            registrar.audit_store_enforcement,
            AuditStoreEnforcement::Directory
        );
        let defaults = RegistrarSettings::default();
        assert_eq!(
            registrar.rate_limit_admission_burst,
            defaults.rate_limit_admission_burst
        );
        assert_eq!(
            registrar.rate_limit_admission_refill_interval_ms,
            defaults.rate_limit_admission_refill_interval_ms
        );
        assert_eq!(
            registrar.rate_limit_predecision_refusal_burst,
            defaults.rate_limit_predecision_refusal_burst
        );
        assert_eq!(
            registrar.rate_limit_predecision_refusal_refill_interval_ms,
            defaults.rate_limit_predecision_refusal_refill_interval_ms
        );
        settings.validate().unwrap();
    }

    #[test]
    fn the_registrar_table_reads_explicit_rate_limit_values() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            r"
[registrar]
rate_limit_admission_burst = 1024
rate_limit_admission_refill_interval_ms = 250
rate_limit_predecision_refusal_burst = 8
rate_limit_predecision_refusal_refill_interval_ms = 2000
"
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert_eq!(settings.registrar.rate_limit_admission_burst, 1024);
        assert_eq!(
            settings.registrar.rate_limit_admission_refill_interval_ms,
            250
        );
        assert_eq!(settings.registrar.rate_limit_predecision_refusal_burst, 8);
        assert_eq!(
            settings
                .registrar
                .rate_limit_predecision_refusal_refill_interval_ms,
            2000
        );
        settings.validate().unwrap();
    }

    /// The whole `[registrar]` table, exactly as the configuration
    /// manual shows it, loads with every key reaching its own field.
    ///
    /// The manual prints all twelve keys in **one** TOML block, because
    /// TOML refuses a table declared twice and a reader pastes what the
    /// page shows. `deny_unknown_fields` is what makes that block a
    /// promise rather than a hope: a key renamed here without the page
    /// following fails this test rather than silently doing nothing in
    /// an operator's file.
    #[test]
    fn the_documented_registrar_table_loads_as_one_block() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            r#"
[registrar]
audit_store_dir = "/var/lib/bootroot/audit-store"
audit_store_reserve_bytes = 2147483648
audit_store_low_water_bytes = 536870912
audit_store_enforcement = "filesystem"
audit_record_dir = "/var/lib/bootroot/audit-store/records"
audit_max_file_bytes = 8388608
audit_max_retained_files = 16
audit_min_retain_days = 90
rate_limit_admission_burst = 512
rate_limit_admission_refill_interval_ms = 500
rate_limit_predecision_refusal_burst = 32
rate_limit_predecision_refusal_refill_interval_ms = 1000
"#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        // The documented block is the shipped defaults written out, so
        // stating it explicitly must land exactly where leaving the
        // table out does.
        assert_eq!(settings.registrar, RegistrarSettings::default());
        settings.validate().unwrap();
    }

    /// Zero disables or inverts the limiter, so each of the four keys
    /// rejects it by name.
    #[test]
    fn a_zero_rate_limit_key_fails_validation_naming_the_key() {
        for key in [
            "rate_limit_admission_burst",
            "rate_limit_admission_refill_interval_ms",
            "rate_limit_predecision_refusal_burst",
            "rate_limit_predecision_refusal_refill_interval_ms",
        ] {
            let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
            write_minimal_profile_config(&mut file);
            writeln!(
                file,
                "
[registrar]
{key} = 0"
            )
            .unwrap();
            file.flush().unwrap();
            let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
            let error = settings
                .validate()
                .expect_err("a zero {key} must be rejected");
            assert!(
                format!("{error:#}").contains(&format!("registrar.{key}")),
                "the {key} failure must name registrar.{key}: {error:#}"
            );
        }
    }

    /// A value an unsigned integer cannot hold is a load error naming
    /// the key, not a panic and not a raw serde message with no key in
    /// it.
    #[test]
    fn a_negative_or_fractional_rate_limit_value_fails_the_load_naming_the_key() {
        for rendered in ["-1", "0.5", r#""512""#] {
            let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
            write_minimal_profile_config(&mut file);
            writeln!(
                file,
                "
[registrar]
rate_limit_admission_burst = {rendered}"
            )
            .unwrap();
            file.flush().unwrap();
            let error = Settings::from_file(Some(file.path().to_path_buf())).expect_err(
                "a rate_limit_admission_burst that is not an unsigned integer must not load",
            );
            let rendered_error = format!("{error:#}");
            assert!(
                rendered_error.contains("registrar.rate_limit_admission_burst"),
                "the {rendered} failure must name registrar.rate_limit_admission_burst: \
                 {rendered_error}"
            );
            assert!(
                rendered_error.contains("expected an unsigned integer"),
                "the {rendered} failure must say what was expected: {rendered_error}"
            );
        }
    }

    /// An empty table is the same as an absent one: every key defaults
    /// on its own, not only through the table's default.
    #[test]
    fn an_empty_registrar_table_loads_the_documented_audit_defaults() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar]").unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert_eq!(settings.registrar, RegistrarSettings::default());
    }

    #[test]
    fn the_registrar_table_reads_explicit_audit_values() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            r#"
[registrar]
audit_store_dir = "/srv/bootroot/audit-store"
audit_record_dir = "/srv/bootroot/audit-store/records"
audit_max_file_bytes = 131072
audit_max_retained_files = 4
audit_min_retain_days = 30
audit_store_reserve_bytes = 4294967296
audit_store_low_water_bytes = 1073741824
audit_store_enforcement = "directory"
"#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert_eq!(
            settings.registrar.audit_record_dir,
            PathBuf::from("/srv/bootroot/audit-store/records")
        );
        assert_eq!(settings.registrar.audit_max_file_bytes, 131_072);
        assert_eq!(settings.registrar.audit_max_retained_files, 4);
        assert_eq!(settings.registrar.audit_min_retain_days, 30);
        assert_eq!(
            settings.registrar.audit_store_dir,
            PathBuf::from("/srv/bootroot/audit-store")
        );
        assert_eq!(settings.registrar.audit_store_reserve_bytes, 4_294_967_296);
        assert_eq!(
            settings.registrar.audit_store_low_water_bytes,
            1_073_741_824
        );
        assert_eq!(
            settings.registrar.audit_store_enforcement,
            AuditStoreEnforcement::Directory
        );
        settings.validate().unwrap();
    }

    #[test]
    fn an_omitted_audit_record_dir_derives_from_a_custom_store() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            "\n[registrar]\naudit_store_dir = \"/srv/bootroot/audit-store\""
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert_eq!(
            settings.registrar.audit_record_dir,
            PathBuf::from("/srv/bootroot/audit-store/records")
        );
        settings.validate().unwrap();
    }

    #[test]
    fn a_file_supplied_relative_audit_store_dir_names_the_store_key() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar]\naudit_store_dir = \"audit-store\"").unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        let err = settings
            .validate()
            .expect_err("relative audit stores are refused");
        assert!(
            err.to_string().contains("registrar.audit_store_dir"),
            "{err}"
        );
    }

    #[test]
    fn an_explicit_derived_audit_record_dir_is_accepted() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            "\n[registrar]\naudit_store_dir = \"/srv/bootroot/audit-store\"\naudit_record_dir = \"/srv/bootroot/audit-store/records\""
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        settings.validate().unwrap();
    }

    #[test]
    fn an_explicit_audit_record_dir_inside_the_store_is_accepted() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            "\n[registrar]\naudit_store_dir = \"/srv/bootroot/audit-store\"\naudit_record_dir = \"/srv/bootroot/audit-store/alternate-records\""
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert_eq!(
            settings.registrar.audit_record_dir,
            PathBuf::from("/srv/bootroot/audit-store/alternate-records")
        );
        settings.validate().unwrap();
    }

    /// A misspelled key is a configuration error rather than a setting
    /// that silently does nothing.
    #[test]
    fn the_registrar_table_rejects_an_unknown_key() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar]\naudit_record_directory = \"/srv\"").unwrap();
        file.flush().unwrap();
        assert!(Settings::from_file(Some(file.path().to_path_buf())).is_err());
    }

    /// Every audit-store value a store could not be opened from is
    /// refused at load time, naming the key at fault.
    #[test]
    fn validation_rejects_every_unusable_audit_setting() {
        for (mutate, expected) in [
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.audit_record_dir = PathBuf::from("registrar-audit");
                }) as Box<dyn Fn(&mut Settings)>,
                "registrar.audit_record_dir",
            ),
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.audit_store_dir = PathBuf::from("audit-store");
                }),
                "registrar.audit_store_dir",
            ),
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.audit_store_reserve_bytes =
                        u64::try_from(i64::MAX).expect("i64::MAX fits in u64") + 1;
                }),
                "registrar.audit_store_reserve_bytes",
            ),
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.audit_store_low_water_bytes =
                        settings.registrar.audit_store_reserve_bytes;
                }),
                "registrar.audit_store_low_water_bytes",
            ),
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.audit_store_low_water_bytes =
                        settings.registrar.audit_store_reserve_bytes + 1;
                }),
                "registrar.audit_store_low_water_bytes",
            ),
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.audit_max_file_bytes = 65_535;
                }),
                "registrar.audit_max_file_bytes",
            ),
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.audit_max_retained_files = 0;
                }),
                "registrar.audit_max_retained_files",
            ),
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.audit_min_retain_days = 0;
                }),
                "registrar.audit_min_retain_days",
            ),
        ] {
            let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
            write_minimal_profile_config(&mut file);
            let mut settings = Settings::new(Some(file.path().to_path_buf())).unwrap();
            mutate(&mut settings);
            let err = settings.validate().unwrap_err();
            assert!(err.to_string().contains(expected), "{expected}: {err}");
        }
    }

    #[test]
    fn validation_rejects_an_audit_record_dir_outside_the_store() {
        for audit_record_dir in [
            "/srv/bootroot/other/records",
            "/var/lib/bootroot/audit-store/records/../../other/records",
            "/var/lib/bootroot/registrar-audit",
        ] {
            let settings = RegistrarSettings {
                audit_record_dir: PathBuf::from(audit_record_dir),
                ..RegistrarSettings::default()
            };
            let err = validate_registrar_settings(&settings).unwrap_err();
            assert!(
                err.to_string().contains("registrar.audit_record_dir"),
                "{err}"
            );
            assert!(
                err.to_string().contains("registrar.audit_store_dir"),
                "{err}"
            );
        }
    }

    #[test]
    fn a_relative_audit_record_dir_is_rejected_before_containment() {
        let settings = RegistrarSettings {
            audit_record_dir: PathBuf::from("registrar-audit"),
            ..RegistrarSettings::default()
        };
        let err = validate_registrar_settings(&settings).unwrap_err();
        assert!(
            err.to_string().contains("must be an absolute path"),
            "{err}"
        );
        assert!(
            !err.to_string().contains("registrar.audit_store_dir"),
            "{err}"
        );
    }

    #[test]
    fn an_unrecognized_audit_store_enforcement_string_fails_to_load() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar]\naudit_store_enforcement = \"quota\"").unwrap();
        file.flush().unwrap();
        let err = Settings::from_file(Some(file.path().to_path_buf())).unwrap_err();
        assert!(
            err.to_string()
                .contains("registrar.audit_store_enforcement"),
            "{err}"
        );
        assert!(err.to_string().contains("quota"), "{err}");
    }

    #[test]
    fn a_non_enum_representation_for_audit_store_enforcement_fails_to_load() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar]\naudit_store_enforcement = 1").unwrap();
        file.flush().unwrap();
        let err = Settings::from_file(Some(file.path().to_path_buf())).unwrap_err();
        assert!(
            err.to_string()
                .contains("registrar.audit_store_enforcement"),
            "{err}"
        );
        assert!(
            err.to_string()
                .contains("represented by either string or table with exactly one key"),
            "{err}"
        );
        assert!(!err.to_string().contains('1'), "{err}");
    }

    #[test]
    fn validation_accepts_an_audit_store_reserve_at_i64_max() {
        let settings = RegistrarSettings {
            audit_store_reserve_bytes: u64::try_from(i64::MAX).expect("i64::MAX fits in u64"),
            ..RegistrarSettings::default()
        };
        validate_registrar_settings(&settings).expect("i64::MAX is an accepted reserve");
    }

    /// A reload may not change the endpoint's enablement in either
    /// direction: the listening descriptor is inherited once, above the
    /// reload loop.
    #[test]
    fn a_reload_that_changes_the_endpoints_enablement_is_rejected() {
        assert!(check_registrar_endpoint_reload(false, false).is_ok());
        assert!(check_registrar_endpoint_reload(true, true).is_ok());

        let err = check_registrar_endpoint_reload(false, true).unwrap_err();
        assert!(
            err.to_string().contains("registrar_endpoint.enabled"),
            "{err}"
        );
        assert!(err.to_string().contains("Restart the service"), "{err}");

        let err = check_registrar_endpoint_reload(true, false).unwrap_err();
        assert!(
            err.to_string().contains("registrar_endpoint.enabled"),
            "{err}"
        );
    }

    /// The endpoint is Linux-only, and an enabled setting is refused
    /// where it cannot be served — before anything looks at an
    /// activation variable.
    #[test]
    #[cfg(not(target_os = "linux"))]
    fn an_enabled_endpoint_is_refused_on_a_non_linux_target() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar_endpoint]\nenabled = true").unwrap();
        file.flush().unwrap();
        // The table still parses: only validation refuses it.
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert!(settings.registrar_endpoint.enabled);

        let err = settings.validate().unwrap_err();
        assert!(err.to_string().contains("Linux only"), "{err}");
        assert!(
            !err.to_string().contains("LISTEN_PID"),
            "the refusal must be about the platform, not the contract: {err}"
        );
    }

    /// A disabled endpoint validates everywhere, including where it
    /// could not be served.
    #[test]
    fn a_disabled_endpoint_validates_on_every_target() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar_endpoint]\nenabled = false").unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        settings.validate().unwrap();
    }
}
