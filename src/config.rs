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
    /// Size at which `OpenBao`'s **own** file audit device is rotated in
    /// place, in bytes. Deliberately not
    /// [`RegistrarSettings::audit_max_file_bytes`]: the two writers have
    /// unrelated volumes — one bounded line per registrar invocation
    /// against one entry per `OpenBao` request across the deployment —
    /// so one pair of bounds cannot serve both.
    pub openbao_audit_max_file_bytes: u64,
    /// How many rotated `OpenBao` audit generations are retained beside
    /// the device's active log. With
    /// [`RegistrarSettings::openbao_audit_max_file_bytes`] this is the
    /// hard byte ceiling on the set bootroot owns.
    pub openbao_audit_max_retained_files: u32,
    /// The retention target in days for those generations. The ceiling
    /// always wins, so nothing reads this at runtime.
    pub openbao_audit_min_retain_days: u32,
    /// Absolute directory containing the daemon's records and `OpenBao`'s
    /// file audit output.
    pub audit_store_dir: PathBuf,
    /// Bytes the operator sets aside for the shared audit store.
    ///
    /// Under the default `filesystem` enforcement this is the size of
    /// the loopback image `bootroot init` provisions and mounts at
    /// `audit_store_dir`, so it is a ceiling the kernel enforces
    /// against both writers. Under `directory` it stays a recorded
    /// budget with nothing behind it.
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
    /// Seconds in each arrival-anchored limited-invocation audit window.
    pub rate_limit_coalesce_window_seconds: u64,
    /// Absolute path to the provisioning tool's rendered registrar
    /// config. Only read; nothing in this repository writes it.
    pub provisioning_config_path: PathBuf,
    /// Ceiling a requested `wrap_ttl` is granted under. Held to the
    /// same rules a request is, by `WrapTtlPolicy::new`.
    pub max_wrap_ttl: Duration,
    /// Role-level `token_ttl` the minted `AppRole` carries.
    pub role_token_ttl: Duration,
    /// Role-level `secret_id_ttl` the minted `AppRole` carries.
    pub role_secret_id_ttl: Duration,
    /// Uses one issued `secret_id` is good for. `0` is unlimited
    /// within the TTL, which is what an enrolled host needs: it logs in
    /// again on every renewal and every fast-poll cycle.
    pub secret_id_num_uses: u32,
    /// Per-issuance `secret_id` TTL. Absent leaves the role-level
    /// [`RegistrarSettings::role_secret_id_ttl`] governing.
    pub secret_id_ttl: Option<Duration>,
    /// Per-issuance `token_bound_cidrs`. Absent binds the issued
    /// credential to no CIDR.
    pub secret_id_token_bound_cidrs: Option<Vec<String>>,
    /// Absolute path to the deployment's `state.json`, where `bootroot
    /// init` recorded the `OpenBao` URL, the KV mount and the secrets
    /// directory.
    ///
    /// It has no default: no absolute path is a defensible guess at
    /// where a deployment keeps its state, and a host that serves no
    /// verbs must not be made to name one. Required exactly when
    /// `[registrar_endpoint] enabled` is true, which the settings-level
    /// validation enforces because it is the one level that sees both
    /// tables.
    pub state_file: Option<PathBuf>,
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

/// A positive coalescing window may be longer than the limiter's
/// `u32`-sized bursts and refill intervals.
#[derive(Debug)]
struct CoalescingWindowValue(u64);

impl<'de> Deserialize<'de> for CoalescingWindowValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = u64;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an unsigned integer")
            }

            fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Self::Value, E> {
                Ok(value)
            }

            fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Self::Value, E> {
                u64::try_from(value).map_err(|_| E::invalid_value(Unexpected::Signed(value), &self))
            }

            fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
                Err(E::invalid_type(Unexpected::Float(value), &self))
            }

            fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
                Err(E::invalid_type(Unexpected::Str(value), &self))
            }

            fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Self::Value, E> {
                Err(E::invalid_type(Unexpected::Bool(value), &self))
            }
        }

        deserializer.deserialize_any(Visitor).map(Self)
    }
}

fn default_rate_limit_coalesce_window_seconds() -> CoalescingWindowValue {
    CoalescingWindowValue(u64::from(
        defaults::default_rate_limit_coalesce_window_seconds(),
    ))
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
    #[serde(default = "defaults::default_openbao_audit_max_file_bytes")]
    openbao_audit_max_file_bytes: u64,
    #[serde(default = "defaults::default_openbao_audit_max_retained_files")]
    openbao_audit_max_retained_files: u32,
    #[serde(default = "defaults::default_openbao_audit_min_retain_days")]
    openbao_audit_min_retain_days: u32,
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
    #[serde(default = "default_rate_limit_coalesce_window_seconds")]
    rate_limit_coalesce_window_seconds: CoalescingWindowValue,
    #[serde(default = "defaults::default_provisioning_config_path")]
    provisioning_config_path: PathBuf,
    #[serde(default = "defaults::default_max_wrap_ttl", with = "duration_serde")]
    max_wrap_ttl: Duration,
    #[serde(default = "defaults::default_role_token_ttl", with = "duration_serde")]
    role_token_ttl: Duration,
    #[serde(
        default = "defaults::default_role_secret_id_ttl",
        with = "duration_serde"
    )]
    role_secret_id_ttl: Duration,
    #[serde(default = "defaults::default_secret_id_num_uses")]
    secret_id_num_uses: u32,
    #[serde(default, with = "optional_duration_serde")]
    secret_id_ttl: Option<Duration>,
    #[serde(default)]
    secret_id_token_bound_cidrs: Option<Vec<String>>,
    #[serde(default)]
    state_file: Option<PathBuf>,
}

impl From<RawRegistrarSettings> for RegistrarSettings {
    fn from(raw: RawRegistrarSettings) -> Self {
        let RawRegistrarSettings {
            audit_record_dir,
            audit_max_file_bytes,
            audit_max_retained_files,
            audit_min_retain_days,
            openbao_audit_max_file_bytes,
            openbao_audit_max_retained_files,
            openbao_audit_min_retain_days,
            audit_store_dir,
            audit_store_reserve_bytes,
            audit_store_low_water_bytes,
            audit_store_enforcement,
            rate_limit_admission_burst,
            rate_limit_admission_refill_interval_ms,
            rate_limit_predecision_refusal_burst,
            rate_limit_predecision_refusal_refill_interval_ms,
            rate_limit_coalesce_window_seconds,
            provisioning_config_path,
            max_wrap_ttl,
            role_token_ttl,
            role_secret_id_ttl,
            secret_id_num_uses,
            secret_id_ttl,
            secret_id_token_bound_cidrs,
            state_file,
        } = raw;
        let audit_record_dir =
            audit_record_dir.unwrap_or_else(|| defaults::audit_record_dir_for(&audit_store_dir));
        Self {
            audit_record_dir,
            audit_max_file_bytes,
            audit_max_retained_files,
            audit_min_retain_days,
            openbao_audit_max_file_bytes,
            openbao_audit_max_retained_files,
            openbao_audit_min_retain_days,
            audit_store_dir,
            audit_store_reserve_bytes,
            audit_store_low_water_bytes,
            audit_store_enforcement,
            rate_limit_admission_burst: rate_limit_admission_burst.0,
            rate_limit_admission_refill_interval_ms: rate_limit_admission_refill_interval_ms.0,
            rate_limit_predecision_refusal_burst: rate_limit_predecision_refusal_burst.0,
            rate_limit_predecision_refusal_refill_interval_ms:
                rate_limit_predecision_refusal_refill_interval_ms.0,
            rate_limit_coalesce_window_seconds: rate_limit_coalesce_window_seconds.0,
            provisioning_config_path,
            max_wrap_ttl,
            role_token_ttl,
            role_secret_id_ttl,
            secret_id_num_uses,
            secret_id_ttl,
            secret_id_token_bound_cidrs,
            state_file,
        }
    }
}

/// An audit store reserve enforcement mode.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuditStoreEnforcement {
    /// A filesystem-provided ceiling: a fully allocated loopback image
    /// of exactly `audit_store_reserve_bytes`, carrying an ext4
    /// filesystem, mounted at `audit_store_dir` through a generated
    /// systemd mount unit that is restored on boot.
    ///
    /// `bootroot init` derives, preflights, renders and verifies that
    /// chain on an endpoint-enabled host; the steps that change the
    /// host are the operator's, rendered as exact commands and run by
    /// nobody else.
    #[default]
    Filesystem,
    /// A plain directory with an unenforced configured reserve, for a
    /// host that cannot mount one. Reachable only by explicit
    /// configuration — never inferred, and never fallen back to.
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
            openbao_audit_max_file_bytes: defaults::default_openbao_audit_max_file_bytes(),
            openbao_audit_max_retained_files: defaults::default_openbao_audit_max_retained_files(),
            openbao_audit_min_retain_days: defaults::default_openbao_audit_min_retain_days(),
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
            rate_limit_coalesce_window_seconds: u64::from(
                defaults::default_rate_limit_coalesce_window_seconds(),
            ),
            provisioning_config_path: defaults::default_provisioning_config_path(),
            max_wrap_ttl: defaults::default_max_wrap_ttl(),
            role_token_ttl: defaults::default_role_token_ttl(),
            role_secret_id_ttl: defaults::default_role_secret_id_ttl(),
            secret_id_num_uses: defaults::default_secret_id_num_uses(),
            secret_id_ttl: None,
            secret_id_token_bound_cidrs: None,
            state_file: None,
        }
    }
}

/// The host-local registrar endpoint's settings.
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
///
/// The four certificate paths are fixed for the same reason and by the
/// same argument: the material at them is loaded once, above the reload
/// loop, so a path a `SIGHUP` changed would be read by nothing. What
/// remains re-readable is the *content* at those paths, through the
/// endpoint's certificate resolver, which is what certificate renewal
/// drives.
///
/// Two of the four name the *client* material rather than the
/// endpoint's own: the leaf the co-located registrar authenticates to
/// this endpoint with, and its key. They live here because they are one
/// surface with the server pair — the daemon issues all four at start,
/// and the provisioning tool places the initial client certificate at
/// them — and because the directory holding `client_cert_path` is where
/// the endpoint's anchor pin file
/// ([`crate::registrar::endpoint_pin::REGISTRAR_ENDPOINT_ANCHORS_FILE`])
/// is looked for.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistrarEndpointSettings {
    /// Whether the daemon serves the registrar verbs on the activated
    /// socket. Defaults to `false`, including when the table is absent.
    #[serde(default)]
    pub enabled: bool,
    /// PEM file holding the endpoint's server leaf **followed by its
    /// issuer chain** up to a certificate pinned in
    /// `trust.trusted_ca_sha256`. Required when the endpoint is
    /// enabled; there is no fallback and nothing is self-signed.
    #[serde(default)]
    pub server_cert_path: Option<PathBuf>,
    /// PEM file holding the private key of the leaf at
    /// `server_cert_path`. Required when the endpoint is enabled.
    #[serde(default)]
    pub server_key_path: Option<PathBuf>,
    /// PEM file holding the registrar's client leaf,
    /// `<instance>.bootroot-registrar.<host>.<domain>`, **followed by
    /// its issuer chain**. Required when the endpoint is enabled.
    ///
    /// A published contract rather than an internal detail: the
    /// co-located registrar process reads this file, the provisioning
    /// tool places the *initial* certificate at it, and the daemon
    /// re-issues it whenever the material there is unusable. Its parent
    /// directory is also where the endpoint anchor pin file
    /// `registrar-endpoint-anchors.sha256` is looked for.
    #[serde(default)]
    pub client_cert_path: Option<PathBuf>,
    /// PEM file holding the private key of the leaf at
    /// `client_cert_path`. Required when the endpoint is enabled.
    #[serde(default)]
    pub client_key_path: Option<PathBuf>,
}

/// Checks that a reloaded configuration keeps the whole
/// `[registrar_endpoint]` table at the values the running process
/// started with.
///
/// None of the five keys is reloadable, and each for the same reason:
/// what it configures is consumed once, above the reload loop. The
/// activation contract is — enabling it on a `SIGHUP` would have no
/// descriptor to serve, and disabling it would leave the socket unit
/// holding a pathname nothing accepts on — and so is the certificate
/// material, whose four paths are read at startup, before activation
/// and before the endpoint's own TLS load, and would be read by nothing
/// if one of them changed later. All five are rejected here rather than
/// half-applied.
///
/// The *contents* at the four paths stay re-readable through the
/// endpoint's certificate resolver; only the paths themselves are
/// fixed.
///
/// # Errors
///
/// Returns an error naming the first key that changed, and both of its
/// values.
pub fn check_registrar_endpoint_reload(
    running: &RegistrarEndpointSettings,
    reloaded: &RegistrarEndpointSettings,
) -> Result<()> {
    if running.enabled != reloaded.enabled {
        return Err(registrar_endpoint_reload_rejected(
            "enabled",
            &running.enabled.to_string(),
            &reloaded.enabled.to_string(),
        ));
    }
    if running.server_cert_path != reloaded.server_cert_path {
        return Err(registrar_endpoint_reload_rejected(
            "server_cert_path",
            &render_optional_path(running.server_cert_path.as_deref()),
            &render_optional_path(reloaded.server_cert_path.as_deref()),
        ));
    }
    if running.server_key_path != reloaded.server_key_path {
        return Err(registrar_endpoint_reload_rejected(
            "server_key_path",
            &render_optional_path(running.server_key_path.as_deref()),
            &render_optional_path(reloaded.server_key_path.as_deref()),
        ));
    }
    if running.client_cert_path != reloaded.client_cert_path {
        return Err(registrar_endpoint_reload_rejected(
            "client_cert_path",
            &render_optional_path(running.client_cert_path.as_deref()),
            &render_optional_path(reloaded.client_cert_path.as_deref()),
        ));
    }
    if running.client_key_path != reloaded.client_key_path {
        return Err(registrar_endpoint_reload_rejected(
            "client_key_path",
            &render_optional_path(running.client_key_path.as_deref()),
            &render_optional_path(reloaded.client_key_path.as_deref()),
        ));
    }
    Ok(())
}

/// What an absent optional path is spelled as in a reload diagnostic.
/// Never an empty string, which would read as a path of no characters.
const UNSET_SETTING: &str = "<unset>";

fn render_optional_path(path: Option<&std::path::Path>) -> String {
    path.map_or_else(
        || UNSET_SETTING.to_string(),
        |path| path.display().to_string(),
    )
}

fn registrar_endpoint_reload_rejected(key: &str, running: &str, reloaded: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "registrar_endpoint.{key} changed from {running} to {reloaded}; \
         the whole [registrar_endpoint] table is fixed for the process lifetime \
         because the listening socket is inherited and the certificate \
         material at all four paths is loaded once at startup, so this reload is \
         rejected and the running daemon is left as it is. Restart the service to \
         apply the change"
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

/// The [`duration_serde`] spelling for a key that may be absent.
///
/// An absent key stays `None`; a present one is the same humantime
/// string every other duration key takes, never a bare integer and never
/// `OpenBao`'s own spelling. It exists because `serde`'s `with` cannot
/// lift a `Duration` deserializer through `Option` on its own.
mod optional_duration_serde {
    use std::time::Duration;

    use serde::{Deserialize, Deserializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Duration>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let Some(value) = Option::<String>::deserialize(deserializer)? else {
            return Ok(None);
        };
        humantime::parse_duration(&value)
            .map(Some)
            .map_err(serde::de::Error::custom)
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

    /// Every `[registrar]` key but `state_file` carries a default, and
    /// the two ways of reaching it — `#[serde(default = ...)]` on the raw
    /// shape and the hand-written `Default` impl — must agree, or a table
    /// that is absent and a table that is empty would load differently.
    #[test]
    fn the_registrar_defaults_agree_between_serde_and_the_default_impl() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar]\n").unwrap();
        file.flush().unwrap();

        let with_empty_table = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert_eq!(with_empty_table.registrar, RegistrarSettings::default());
    }

    /// An absent `[registrar]` table leaves every key at its documented
    /// default, `state_file` included — which has none and stays `None`.
    #[test]
    fn an_absent_registrar_table_leaves_every_key_at_its_default() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();

        let registrar = &settings.registrar;
        assert_eq!(
            registrar.provisioning_config_path,
            PathBuf::from("/etc/clumit-security/provisioning.toml")
        );
        assert_eq!(registrar.max_wrap_ttl, Duration::from_mins(30));
        assert_eq!(registrar.role_token_ttl, Duration::from_hours(1));
        assert_eq!(registrar.role_secret_id_ttl, Duration::from_hours(24));
        assert_eq!(registrar.secret_id_num_uses, 0);
        assert!(registrar.secret_id_ttl.is_none());
        assert!(registrar.secret_id_token_bound_cidrs.is_none());
        assert!(
            registrar.state_file.is_none(),
            "state_file has no default, so an absent key stays absent"
        );
        settings
            .validate()
            .expect("a disabled endpoint with no state_file loads cleanly");
    }

    /// Every key is read at the spelling the documented table fixes:
    /// humantime duration strings, never bare integers and never
    /// `OpenBao`'s own spelling.
    #[test]
    fn every_registrar_key_is_read_at_its_documented_spelling() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            r#"
            [registrar]
            provisioning_config_path = "/etc/clumit-security/other.toml"
            max_wrap_ttl = "45m"
            role_token_ttl = "2h"
            role_secret_id_ttl = "36h"
            secret_id_num_uses = 7
            secret_id_ttl = "90m"
            secret_id_token_bound_cidrs = ["10.0.0.0/8", "192.168.1.0/24"]
            state_file = "/var/lib/bootroot/state.json"
        "#
        )
        .unwrap();
        file.flush().unwrap();

        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        let registrar = &settings.registrar;
        assert_eq!(
            registrar.provisioning_config_path,
            PathBuf::from("/etc/clumit-security/other.toml")
        );
        assert_eq!(registrar.max_wrap_ttl, Duration::from_mins(45));
        assert_eq!(registrar.role_token_ttl, Duration::from_hours(2));
        assert_eq!(registrar.role_secret_id_ttl, Duration::from_hours(36));
        assert_eq!(registrar.secret_id_num_uses, 7);
        assert_eq!(registrar.secret_id_ttl, Some(Duration::from_mins(90)));
        assert_eq!(
            registrar.secret_id_token_bound_cidrs.as_deref(),
            Some(["10.0.0.0/8".to_string(), "192.168.1.0/24".to_string()].as_slice())
        );
        assert_eq!(
            registrar.state_file,
            Some(PathBuf::from("/var/lib/bootroot/state.json"))
        );
    }

    /// A duration key is a humantime string, never a bare integer of
    /// seconds — which is how `OpenBao` itself would take it, and is
    /// exactly the spelling a reader would then have to guess the unit
    /// of.
    ///
    /// Both keys, because they are two deserializers rather than one:
    /// `serde`'s `with` cannot lift a `Duration` deserializer through
    /// `Option`, so the optional key goes through
    /// [`optional_duration_serde`] and would not be covered by a case
    /// over `max_wrap_ttl` alone.
    #[test]
    fn a_registrar_duration_is_never_a_bare_integer_of_seconds() {
        for key in ["max_wrap_ttl", "secret_id_ttl"] {
            for value in ["1800", "\"1800\"", "\"half an hour\"", "true"] {
                let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
                write_minimal_profile_config(&mut file);
                writeln!(file, "\n[registrar]\n{key} = {value}\n").unwrap();
                file.flush().unwrap();
                assert!(
                    Settings::from_file(Some(file.path().to_path_buf())).is_err(),
                    "{key} = {value} must not deserialize"
                );
            }
        }
    }

    /// `[registrar]` already carries `deny_unknown_fields`, so this
    /// asserts the mechanism rather than adding one.
    #[test]
    fn an_unknown_registrar_key_is_rejected() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar]\nwrap_ttl_maximum = \"30m\"\n").unwrap();
        file.flush().unwrap();

        let error = Settings::from_file(Some(file.path().to_path_buf()))
            .expect_err("an unknown [registrar] key is a configuration error");
        assert!(
            format!("{error}").contains("wrap_ttl_maximum"),
            "the error must name the key it did not know: {error}"
        );
    }

    /// No configuration key can set `SecretIdOptions::metadata`.
    #[test]
    fn no_registrar_key_sets_secret_id_metadata() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar]\nsecret_id_metadata = \"who=me\"\n").unwrap();
        file.flush().unwrap();
        assert!(
            Settings::from_file(Some(file.path().to_path_buf())).is_err(),
            "metadata is fixed to None and has no key"
        );
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

    /// The table's five keys all deserialize, and the four paths land
    /// on `Settings` as the `PathBuf`s the loader will read. The client
    /// pair is in the same shape and the same spelling as the server
    /// pair, because the four are one surface.
    #[test]
    fn the_registrar_endpoint_table_reads_the_four_certificate_paths() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            "\n[registrar_endpoint]\nenabled = true\n\
             server_cert_path = \"/etc/bootroot/registrar-endpoint.crt\"\n\
             server_key_path = \"/etc/bootroot/registrar-endpoint.key\"\n\
             client_cert_path = \"/etc/bootroot/registrar-client.crt\"\n\
             client_key_path = \"/etc/bootroot/registrar-client.key\""
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert!(settings.registrar_endpoint.enabled);
        assert_eq!(
            settings.registrar_endpoint.server_cert_path.as_deref(),
            Some(Path::new("/etc/bootroot/registrar-endpoint.crt"))
        );
        assert_eq!(
            settings.registrar_endpoint.server_key_path.as_deref(),
            Some(Path::new("/etc/bootroot/registrar-endpoint.key"))
        );
        assert_eq!(
            settings.registrar_endpoint.client_cert_path.as_deref(),
            Some(Path::new("/etc/bootroot/registrar-client.crt"))
        );
        assert_eq!(
            settings.registrar_endpoint.client_key_path.as_deref(),
            Some(Path::new("/etc/bootroot/registrar-client.key"))
        );
    }

    /// All four paths are optional to the *deserializer*, so a table
    /// naming only `enabled` still parses — the refusal for an unset
    /// path is validation's, a step later, and only on Linux.
    #[test]
    fn the_registrar_endpoint_certificate_paths_are_optional() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar_endpoint]\nenabled = true").unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        assert!(settings.registrar_endpoint.server_cert_path.is_none());
        assert!(settings.registrar_endpoint.server_key_path.is_none());
        assert!(settings.registrar_endpoint.client_cert_path.is_none());
        assert!(settings.registrar_endpoint.client_key_path.is_none());
    }

    /// The table takes exactly five keys, so a misspelled one is a
    /// config error rather than a setting that silently does nothing.
    #[test]
    fn the_registrar_endpoint_table_rejects_an_unknown_key() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n[registrar_endpoint]\nenable = true").unwrap();
        file.flush().unwrap();
        assert!(Settings::from_file(Some(file.path().to_path_buf())).is_err());

        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            "\n[registrar_endpoint]\nenabled = true\nserver_cert = \"/etc/a.crt\""
        )
        .unwrap();
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
        assert_eq!(settings.registrar.openbao_audit_max_file_bytes, 67_108_864);
        assert_eq!(settings.registrar.openbao_audit_max_retained_files, 7);
        assert_eq!(settings.registrar.openbao_audit_min_retain_days, 90);
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
        assert_eq!(settings.registrar.rate_limit_coalesce_window_seconds, 60);
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
        assert_eq!(
            registrar.rate_limit_coalesce_window_seconds,
            defaults.rate_limit_coalesce_window_seconds
        );
        settings.validate().unwrap();
    }

    /// The device-rotation keys load beside the record store's own,
    /// which they neither reuse nor disturb.
    #[test]
    fn the_registrar_table_reads_the_openbao_audit_rotation_keys() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            r#"
[registrar]
audit_store_dir = "/srv/bootroot/audit-store"
audit_max_file_bytes = 131072
audit_max_retained_files = 4
audit_min_retain_days = 30
openbao_audit_max_file_bytes = 2097152
openbao_audit_max_retained_files = 3
openbao_audit_min_retain_days = 45
"#
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        let registrar = &settings.registrar;
        assert_eq!(registrar.openbao_audit_max_file_bytes, 2_097_152);
        assert_eq!(registrar.openbao_audit_max_retained_files, 3);
        assert_eq!(registrar.openbao_audit_min_retain_days, 45);
        // The record store's neighbouring keys are untouched by them:
        // the two writers have unrelated volumes and unrelated bounds.
        assert_eq!(registrar.audit_max_file_bytes, 131_072);
        assert_eq!(registrar.audit_max_retained_files, 4);
        assert_eq!(registrar.audit_min_retain_days, 30);
        assert_eq!(
            registrar.audit_store_dir,
            PathBuf::from("/srv/bootroot/audit-store")
        );
        settings.validate().unwrap();
    }

    /// Nothing selects which rotation mechanism the daemon uses.
    ///
    /// The choice is made at runtime from what the filesystem shows
    /// after the signal, once per pass, and a key that could pin it
    /// would let a deployment sit silently on the lossy form. So the
    /// `[registrar]` table refuses one, like any other unknown key.
    #[test]
    fn no_registrar_key_selects_the_openbao_audit_rotation_mechanism() {
        for key in [
            "openbao_audit_rotation_mechanism = \"truncate\"",
            "openbao_audit_signal_rotation = false",
            "openbao_audit_container = \"bootroot-openbao\"",
        ] {
            let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
            write_minimal_profile_config(&mut file);
            writeln!(
                file,
                r#"
[registrar]
audit_store_dir = "/srv/bootroot/audit-store"
{key}
"#
            )
            .unwrap();
            file.flush().unwrap();
            let error = Settings::from_file(Some(file.path().to_path_buf()))
                .expect_err("a mechanism selector is not a configuration key");
            let rendered = format!("{error:#}");
            assert!(
                rendered.contains("unknown field"),
                "{key} must be refused as an unknown field, got: {rendered}"
            );
        }
    }

    /// A retained family whose byte budget does not fit in `u64` is
    /// refused at load, naming both keys, so the rotation's own
    /// arithmetic can be total.
    #[test]
    fn validation_rejects_an_openbao_audit_budget_that_cannot_be_computed() {
        for (max_file_bytes, max_retained_files) in
            [(u64::MAX, 1_u32), (u64::MAX, u32::MAX), (u64::MAX / 4, 7)]
        {
            let settings = RegistrarSettings {
                openbao_audit_max_file_bytes: max_file_bytes,
                openbao_audit_max_retained_files: max_retained_files,
                ..RegistrarSettings::default()
            };
            let err = validate_registrar_settings(&settings).unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("registrar.openbao_audit_max_file_bytes"),
                "{message}"
            );
            assert!(
                message.contains("registrar.openbao_audit_max_retained_files"),
                "{message}"
            );
        }

        // And the largest budget that does fit is accepted.
        let settings = RegistrarSettings {
            openbao_audit_max_file_bytes: u64::MAX / 8,
            openbao_audit_max_retained_files: 7,
            ..RegistrarSettings::default()
        };
        validate_registrar_settings(&settings).unwrap();
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

    /// The configuration manuals whose documented `[registrar]` table
    /// the tests below read, relative to the crate root.
    const CONFIGURATION_MANUALS: [&str; 2] =
        ["docs/en/configuration.md", "docs/ko/configuration.md"];

    /// The heading anchor of the manual section holding the audit-record
    /// and rate-limit `[registrar]` block.
    ///
    /// Both manuals carry a second `[registrar]` block further down —
    /// the verb-provisioning one, which sets `state_file` and the TTLs
    /// and is deliberately not a statement of defaults. Selecting by
    /// section rather than by a key inside the block is what keeps the
    /// two apart without naming a key that a rename could move: the
    /// English heading slugifies to this anchor, and the Korean heading
    /// declares it explicitly.
    const REGISTRAR_AUDIT_SECTION_ANCHOR: &str = "registrar-audit-records";

    fn manual_path(relative: &str) -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
    }

    /// Returns the anchor a Markdown heading line resolves to: the
    /// explicit `{#anchor}` where one is written, and the slug `MkDocs`
    /// derives from the heading text otherwise.
    fn heading_anchor(line: &str) -> String {
        let text = line.trim_start_matches('#').trim();
        if let Some(rest) = text.strip_suffix('}')
            && let Some((_, anchor)) = rest.rsplit_once("{#")
        {
            return anchor.to_string();
        }
        let mut anchor = String::new();
        for character in text.chars() {
            if character.is_alphanumeric() {
                anchor.extend(character.to_lowercase());
            } else if character.is_whitespace() && !anchor.ends_with('-') {
                anchor.push('-');
            }
        }
        anchor.trim_matches('-').to_string()
    }

    /// Reads the first fenced TOML block of the section `anchor` names
    /// out of the manual at `path`, stripping the fence delimiters and
    /// nothing else.
    ///
    /// Comments and blank lines are part of what an operator would
    /// paste, so they stay in: what this returns is the page's bytes,
    /// not a transcription of them.
    fn documented_toml_block(path: &std::path::Path, anchor: &str) -> String {
        let manual = std::fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("reading {}: {err}", path.display()));
        let mut lines = manual.lines();
        lines
            .by_ref()
            .find(|line| line.starts_with('#') && heading_anchor(line) == anchor)
            .unwrap_or_else(|| panic!("{} has no section anchored #{anchor}", path.display()));

        let mut block = String::new();
        let mut inside = false;
        for line in lines {
            if inside {
                if line.trim_end() == "```" {
                    return block;
                }
                block.push_str(line);
                block.push('\n');
            } else if line.trim_end() == "```toml" {
                inside = true;
            } else {
                assert!(
                    !line.starts_with('#'),
                    "{}: section #{anchor} ends before any TOML block",
                    path.display()
                );
            }
        }
        panic!(
            "{}: the TOML block under #{anchor} is unterminated",
            path.display()
        );
    }

    /// The keys a documented TOML block assigns, in the order the page
    /// prints them, ignoring the commented-out ones.
    fn assigned_keys(block: &str) -> Vec<&str> {
        block
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                (!line.starts_with('#'))
                    .then(|| line.split_once(" = "))
                    .flatten()
                    .map(|(key, _)| key)
            })
            .collect()
    }

    /// Writes `block` into a fresh configuration file beneath a minimal
    /// profile and loads it.
    fn load_with_registrar_block(block: &str) -> Result<Settings, ConfigError> {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(file, "\n{block}").unwrap();
        file.flush().unwrap();
        Settings::from_file(Some(file.path().to_path_buf()))
    }

    /// The whole audit-record and rate-limit `[registrar]` table, read
    /// out of each configuration manual rather than transcribed here,
    /// loads with every key reaching its own field.
    ///
    /// Each manual prints all sixteen keys in **one** TOML block, because
    /// TOML refuses a table declared twice and a reader pastes what the
    /// page shows. Parsing the page itself is what makes that block a
    /// promise rather than a hope: with the block copied into this file,
    /// a rename could leave either manual stale and nothing would notice.
    #[test]
    fn the_documented_registrar_table_loads_as_one_block() {
        for manual in CONFIGURATION_MANUALS {
            let block = documented_toml_block(&manual_path(manual), REGISTRAR_AUDIT_SECTION_ANCHOR);
            assert!(
                block.starts_with("[registrar]\n"),
                "{manual}: the documented block must open the [registrar] table"
            );
            assert!(
                !assigned_keys(&block).contains(&"state_file"),
                "{manual}: this is the provisioning block, not the audit-record one"
            );
            let settings = load_with_registrar_block(&block)
                .unwrap_or_else(|err| panic!("{manual}: the documented block must load: {err}"));
            // The documented block is the shipped defaults written out,
            // so stating it explicitly must land exactly where leaving
            // the table out does.
            assert_eq!(
                settings.registrar,
                RegistrarSettings::default(),
                "{manual}: the documented values are the defaults"
            );
            settings.validate().unwrap();
        }
    }

    /// The manual is the input, key by key: renaming one in a temporary
    /// copy of the page changes what this test parses, and the load then
    /// fails through the `deny_unknown_fields` handling naming the key
    /// the page invented.
    #[test]
    fn a_key_renamed_in_a_documented_registrar_table_fails_the_load() {
        const RENAMED_SUFFIX: &str = "_renamed";

        for manual in CONFIGURATION_MANUALS {
            let source = std::fs::read_to_string(manual_path(manual)).unwrap();
            let published =
                documented_toml_block(&manual_path(manual), REGISTRAR_AUDIT_SECTION_ANCHOR);
            let keys = assigned_keys(&published);
            assert_eq!(
                keys.len(),
                16,
                "{manual}: the block prints all sixteen keys"
            );

            for key in keys {
                let edited_block = published.replace(
                    &format!("\n{key} = "),
                    &format!("\n{key}{RENAMED_SUFFIX} = "),
                );
                assert_ne!(edited_block, published, "{manual}: {key} must have moved");
                let dir = tempfile::tempdir().unwrap();
                let edited_manual = dir.path().join("configuration.md");
                std::fs::write(&edited_manual, source.replace(&published, &edited_block)).unwrap();

                // Reading the edited copy back proves the extraction is
                // what feeds the load: the block this test parses is the
                // one on the page in front of it.
                let extracted =
                    documented_toml_block(&edited_manual, REGISTRAR_AUDIT_SECTION_ANCHOR);
                assert_eq!(
                    extracted, edited_block,
                    "{manual}: {key} edit must be read back"
                );

                let error = load_with_registrar_block(&extracted)
                    .err()
                    .unwrap_or_else(|| panic!("{manual}: a renamed {key} must not load"));
                assert!(
                    format!("{error}").contains(&format!("{key}{RENAMED_SUFFIX}")),
                    "{manual}: the error must name the key the page invented: {error}"
                );
            }
        }
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
            "rate_limit_coalesce_window_seconds",
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
    fn a_rate_limit_value_of_the_wrong_type_fails_the_load_naming_the_key() {
        for rendered in ["-1", "0.5", r#""512""#, "true"] {
            let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
            write_minimal_profile_config(&mut file);
            writeln!(
                file,
                "
[registrar]
rate_limit_coalesce_window_seconds = {rendered}"
            )
            .unwrap();
            file.flush().unwrap();
            let error = Settings::from_file(Some(file.path().to_path_buf())).expect_err(
                "a coalescing-window value that is not an unsigned integer must not load",
            );
            let rendered_error = format!("{error:#}");
            assert!(
                rendered_error.contains("registrar.rate_limit_coalesce_window_seconds"),
                "the {rendered} failure must name registrar.rate_limit_coalesce_window_seconds: \
                 {rendered_error}"
            );
            assert!(
                rendered_error.contains("expected an unsigned integer"),
                "the {rendered} failure must say what was expected: {rendered_error}"
            );
        }
    }

    /// A whole number too large for the key's `u32` is the same kind of
    /// load error, naming the key and the bound it passed.
    ///
    /// It is a digit's slip away from a sizing an operator meant, and
    /// the configuration layer's own conversion would have taken it
    /// silently, so the bound is asserted rather than assumed.
    #[test]
    fn a_rate_limit_value_past_u32_max_fails_the_load_naming_the_key() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            "
[registrar]
rate_limit_admission_burst = 4294967296"
        )
        .unwrap();
        file.flush().unwrap();
        let error = Settings::from_file(Some(file.path().to_path_buf()))
            .expect_err("a burst past u32::MAX must not load");
        let rendered_error = format!("{error:#}");
        assert!(
            rendered_error.contains("registrar.rate_limit_admission_burst"),
            "the failure must name registrar.rate_limit_admission_burst: {rendered_error}"
        );
        assert!(
            rendered_error.contains("4294967296 exceeds 4294967295"),
            "the failure must say which bound was passed: {rendered_error}"
        );
    }

    #[test]
    fn a_coalescing_window_uses_its_documented_u64_range() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            "
[registrar]
rate_limit_coalesce_window_seconds = 4294967296"
        )
        .unwrap();
        file.flush().unwrap();

        let settings = Settings::from_file(Some(file.path().to_path_buf()))
            .expect("a u64 coalescing window loads");
        assert_eq!(
            settings.registrar.rate_limit_coalesce_window_seconds,
            4_294_967_296
        );
        settings.validate().expect("a nonzero window validates");
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
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.openbao_audit_max_file_bytes = 1_048_575;
                }),
                "registrar.openbao_audit_max_file_bytes",
            ),
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.openbao_audit_max_retained_files = 0;
                }),
                "registrar.openbao_audit_max_retained_files",
            ),
            (
                Box::new(|settings: &mut Settings| {
                    settings.registrar.openbao_audit_min_retain_days = 0;
                }),
                "registrar.openbao_audit_min_retain_days",
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

    fn endpoint_settings(
        enabled: bool,
        cert: Option<&str>,
        key: Option<&str>,
    ) -> RegistrarEndpointSettings {
        RegistrarEndpointSettings {
            enabled,
            server_cert_path: cert.map(PathBuf::from),
            server_key_path: key.map(PathBuf::from),
            ..RegistrarEndpointSettings::default()
        }
    }

    /// Every one of the four material paths, so a reload test can move
    /// exactly one of them and leave the other three where they were.
    fn full_endpoint_settings(
        server_cert: Option<&str>,
        server_key: Option<&str>,
        client_cert: Option<&str>,
        client_key: Option<&str>,
    ) -> RegistrarEndpointSettings {
        RegistrarEndpointSettings {
            enabled: true,
            server_cert_path: server_cert.map(PathBuf::from),
            server_key_path: server_key.map(PathBuf::from),
            client_cert_path: client_cert.map(PathBuf::from),
            client_key_path: client_key.map(PathBuf::from),
        }
    }

    /// A reload may not change the endpoint's enablement in either
    /// direction: the listening descriptor is inherited once, above the
    /// reload loop.
    #[test]
    fn a_reload_that_changes_the_endpoints_enablement_is_rejected() {
        let off = endpoint_settings(false, None, None);
        let on = endpoint_settings(true, None, None);
        assert!(check_registrar_endpoint_reload(&off, &off).is_ok());
        assert!(check_registrar_endpoint_reload(&on, &on).is_ok());

        let err = check_registrar_endpoint_reload(&off, &on).unwrap_err();
        assert!(
            err.to_string().contains("registrar_endpoint.enabled"),
            "{err}"
        );
        assert!(err.to_string().contains("Restart the service"), "{err}");

        let err = check_registrar_endpoint_reload(&on, &off).unwrap_err();
        assert!(
            err.to_string().contains("registrar_endpoint.enabled"),
            "{err}"
        );
    }

    /// All four certificate paths are fixed for the same reason, so a
    /// reload that changes any of them is rejected and the diagnostic
    /// names the key that changed — not merely "the table".
    #[test]
    fn a_reload_that_changes_any_certificate_path_is_rejected_and_names_the_key() {
        let running = full_endpoint_settings(
            Some("/etc/a.crt"),
            Some("/etc/a.key"),
            Some("/etc/c.crt"),
            Some("/etc/c.key"),
        );
        assert!(check_registrar_endpoint_reload(&running, &running.clone()).is_ok());

        for (reloaded, expected) in [
            (
                full_endpoint_settings(
                    Some("/etc/b.crt"),
                    Some("/etc/a.key"),
                    Some("/etc/c.crt"),
                    Some("/etc/c.key"),
                ),
                "registrar_endpoint.server_cert_path",
            ),
            (
                full_endpoint_settings(
                    Some("/etc/a.crt"),
                    Some("/etc/b.key"),
                    Some("/etc/c.crt"),
                    Some("/etc/c.key"),
                ),
                "registrar_endpoint.server_key_path",
            ),
            (
                full_endpoint_settings(
                    Some("/etc/a.crt"),
                    Some("/etc/a.key"),
                    Some("/etc/d.crt"),
                    Some("/etc/c.key"),
                ),
                "registrar_endpoint.client_cert_path",
            ),
            (
                full_endpoint_settings(
                    Some("/etc/a.crt"),
                    Some("/etc/a.key"),
                    Some("/etc/c.crt"),
                    Some("/etc/d.key"),
                ),
                "registrar_endpoint.client_key_path",
            ),
            (
                full_endpoint_settings(
                    None,
                    Some("/etc/a.key"),
                    Some("/etc/c.crt"),
                    Some("/etc/c.key"),
                ),
                "registrar_endpoint.server_cert_path",
            ),
            (
                full_endpoint_settings(
                    Some("/etc/a.crt"),
                    None,
                    Some("/etc/c.crt"),
                    Some("/etc/c.key"),
                ),
                "registrar_endpoint.server_key_path",
            ),
            (
                full_endpoint_settings(
                    Some("/etc/a.crt"),
                    Some("/etc/a.key"),
                    None,
                    Some("/etc/c.key"),
                ),
                "registrar_endpoint.client_cert_path",
            ),
            (
                full_endpoint_settings(
                    Some("/etc/a.crt"),
                    Some("/etc/a.key"),
                    Some("/etc/c.crt"),
                    None,
                ),
                "registrar_endpoint.client_key_path",
            ),
        ] {
            let err = check_registrar_endpoint_reload(&running, &reloaded).unwrap_err();
            let rendered = err.to_string();
            assert!(rendered.contains(expected), "{rendered}");
            assert!(rendered.contains("Restart the service"), "{rendered}");
        }
    }

    /// An absent optional path is spelled explicitly, never as an empty
    /// string a reader would take for a path of no characters.
    #[test]
    fn an_absent_certificate_path_is_named_in_a_reload_diagnostic() {
        let running = endpoint_settings(true, None, None);
        let reloaded = endpoint_settings(true, Some("/etc/a.crt"), None);
        let err = check_registrar_endpoint_reload(&running, &reloaded).unwrap_err();
        let rendered = err.to_string();
        assert!(
            rendered.contains(&format!("from {UNSET_SETTING} to /etc/a.crt")),
            "{rendered}"
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

    /// With the endpoint enabled, every one of the four material paths
    /// is required and an unset one is refused at configuration
    /// validation — before any state file is read, any `OpenBao` request
    /// is made, any certificate is requested and any activation is
    /// attempted.
    ///
    /// Gated on Linux because `validate_registrar_endpoint_settings`
    /// runs first and refuses an enabled endpoint outright everywhere
    /// else, with a diagnostic about the platform rather than about a
    /// key. A test that ignored that would pass in CI and fail on a
    /// developer's machine.
    #[test]
    #[cfg(target_os = "linux")]
    fn an_enabled_endpoint_with_an_unset_material_path_is_refused_by_validation() {
        const PATHS: [(&str, &str); 4] = [
            ("server_cert_path", "/etc/bootroot/registrar-endpoint.crt"),
            ("server_key_path", "/etc/bootroot/registrar-endpoint.key"),
            ("client_cert_path", "/etc/bootroot/registrar-client.crt"),
            ("client_key_path", "/etc/bootroot/registrar-client.key"),
        ];
        for omitted in 0..PATHS.len() {
            let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
            write_minimal_profile_config(&mut file);
            writeln!(file, "\n[registrar_endpoint]\nenabled = true").unwrap();
            for (index, (key, value)) in PATHS.iter().enumerate() {
                if index != omitted {
                    writeln!(file, "{key} = \"{value}\"").unwrap();
                }
            }
            writeln!(
                file,
                "\n[registrar]\nstate_file = \"/var/lib/bootroot/state.json\""
            )
            .unwrap();
            file.flush().unwrap();
            let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
            let err = settings.validate().unwrap_err();
            let rendered = err.to_string();
            let missing = PATHS.get(omitted).expect("index is inside the array").0;
            assert!(
                rendered.contains(missing),
                "the diagnostic must name {missing}: {rendered}"
            );
            for (present, _) in PATHS
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| (index != omitted).then_some((entry.0, entry.1)))
            {
                assert!(
                    !rendered.contains(&format!("{present} is unset")),
                    "a configured key must not be reported as unset: {rendered}"
                );
            }
        }
    }

    /// All four configured, and the enabled endpoint's configuration
    /// validates. The refusal above is about the keys and nothing else.
    #[test]
    #[cfg(target_os = "linux")]
    fn an_enabled_endpoint_with_all_four_material_paths_validates() {
        let mut file = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        write_minimal_profile_config(&mut file);
        writeln!(
            file,
            "\n[registrar_endpoint]\nenabled = true\n\
             server_cert_path = \"/etc/bootroot/registrar-endpoint.crt\"\n\
             server_key_path = \"/etc/bootroot/registrar-endpoint.key\"\n\
             client_cert_path = \"/etc/bootroot/registrar-client.crt\"\n\
             client_key_path = \"/etc/bootroot/registrar-client.key\"\n\
             \n[registrar]\nstate_file = \"/var/lib/bootroot/state.json\""
        )
        .unwrap();
        file.flush().unwrap();
        let settings = Settings::from_file(Some(file.path().to_path_buf())).unwrap();
        settings.validate().unwrap();
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
