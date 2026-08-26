use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result};
use reqwest::Url;

use super::defaults::default_renew_before;
use super::{
    DaemonProfileSettings, HookCommand, OpenBaoSettings, RegistrarEndpointSettings,
    RegistrarSettings, Settings, TrustSettings,
};
use crate::fs_util::path_is_within;
use crate::input_validation::{ValidationError, validate_dns_label, validate_registration_id};
use crate::registrar::audit::MIN_AUDIT_MAX_FILE_BYTES;
use crate::registrar::verbs::wrap_ttl::{WrapTtlPolicy, WrapTtlRefusal};

const MAX_SIGNED_AUDIT_STORE_RESERVE_BYTES: u64 = i64::MAX.unsigned_abs();

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
    if settings.acme.http_responder_hmac.is_blank() {
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
    validate_registrar_endpoint_settings(&settings.registrar_endpoint)?;
    validate_registrar_endpoint_material_paths(&settings.registrar_endpoint)?;
    validate_registrar_settings(&settings.registrar)?;
    validate_registrar_state_file_requirement(&settings.registrar, &settings.registrar_endpoint)?;
    Ok(())
}

/// The four `[registrar_endpoint]` keys that must carry a path once the
/// endpoint is enabled, in the order a diagnostic lists them.
const REGISTRAR_ENDPOINT_MATERIAL_KEYS: [&str; 4] = [
    "server_cert_path",
    "server_key_path",
    "client_cert_path",
    "client_key_path",
];

/// Requires all four `[registrar_endpoint]` material paths when the
/// endpoint is enabled.
///
/// There are no defaults, and an unset path is not a repairable state:
/// start-time issuance repairs *material at a configured path*, and it
/// has nowhere to write when there is no path at all. So this is decided
/// here — before any state file is read, any `OpenBao` request is made,
/// any certificate is requested and any activation is attempted — rather
/// than being discovered by whatever would have used the path.
///
/// Ordered deliberately **after** [`validate_registrar_endpoint_settings`]:
/// off Linux an enabled endpoint is refused outright as an unsupported
/// platform, and that diagnostic must not be displaced by one about a
/// missing key on a target that could never serve the endpoint anyway.
fn validate_registrar_endpoint_material_paths(settings: &RegistrarEndpointSettings) -> Result<()> {
    if !settings.enabled {
        return Ok(());
    }
    let configured = [
        settings.server_cert_path.as_deref(),
        settings.server_key_path.as_deref(),
        settings.client_cert_path.as_deref(),
        settings.client_key_path.as_deref(),
    ];
    let missing: Vec<&str> = REGISTRAR_ENDPOINT_MATERIAL_KEYS
        .iter()
        .zip(configured)
        .filter_map(|(key, value)| value.is_none().then_some(*key))
        .collect();
    if missing.is_empty() {
        return Ok(());
    }
    anyhow::bail!(
        "registrar_endpoint.enabled is true, but [registrar_endpoint] {} unset; there is no \
         default for either certificate pair and the daemon has nowhere to write the material \
         it issues. Configure server_cert_path, server_key_path, client_cert_path and \
         client_key_path",
        render_missing_keys(&missing)
    );
}

/// Renders the missing-key list as the subject of the diagnostic above,
/// so one missing key does not read as a plural.
fn render_missing_keys(missing: &[&str]) -> String {
    match missing {
        [only] => format!("{only} is"),
        _ => format!("{} are", missing.join(", ")),
    }
}

/// Requires `[registrar] state_file` exactly when the endpoint is
/// enabled.
///
/// The key's own rule — absolute when present — belongs with the other
/// range checks in [`validate_registrar_settings`], which sees only its
/// own table. *Required when the endpoint is enabled* relates two
/// tables, so it is decided here, where both are visible. It stays a
/// pure check: whether the path exists is decided when the daemon opens
/// the file, on the enabled path.
fn validate_registrar_state_file_requirement(
    registrar: &RegistrarSettings,
    endpoint: &RegistrarEndpointSettings,
) -> Result<()> {
    if endpoint.enabled && registrar.state_file.is_none() {
        anyhow::bail!(
            "registrar.state_file is required when registrar_endpoint.enabled is true: the \
             daemon reads the deployment's OpenBao URL, KV mount and secrets directory out of \
             the state.json that key names, and has no other source for them"
        );
    }
    Ok(())
}

/// Rejects a `[registrar]` table that could not open a usable audit
/// record store.
///
/// Refused here, at load time, rather than at the first append: an
/// audit artifact whose directory turns out to be unusable after the
/// registrar surface is already answering requests is a hole in the
/// trail nobody notices until they go looking for a record that was
/// never written.
/// This is public because the binary crate validates the same settings
/// before install-side work consumes them.
///
/// # Errors
///
/// Returns an error when an audit path is invalid, the record directory
/// escapes the store, or a reserve or retention setting is out of range.
pub fn validate_registrar_settings(settings: &RegistrarSettings) -> Result<()> {
    if !settings.audit_store_dir.is_absolute() {
        anyhow::bail!(
            "registrar.audit_store_dir ({}) must be an absolute path; the daemon's working \
             directory is not contracted to be stable under a service supervisor",
            settings.audit_store_dir.display()
        );
    }
    if !settings.audit_record_dir.is_absolute() {
        anyhow::bail!(
            "registrar.audit_record_dir ({}) must be an absolute path; the daemon's working \
             directory is not contracted to be stable under a service supervisor",
            settings.audit_record_dir.display()
        );
    }
    if !path_is_within(&settings.audit_record_dir, &settings.audit_store_dir).with_context(
        || "checking whether registrar.audit_record_dir is inside registrar.audit_store_dir",
    )? {
        anyhow::bail!(
            "registrar.audit_record_dir ({}) must resolve inside registrar.audit_store_dir ({})",
            settings.audit_record_dir.display(),
            settings.audit_store_dir.display()
        );
    }
    if settings.audit_store_reserve_bytes > MAX_SIGNED_AUDIT_STORE_RESERVE_BYTES {
        anyhow::bail!(
            "registrar.audit_store_reserve_bytes ({}) must not exceed i64::MAX",
            settings.audit_store_reserve_bytes
        );
    }
    if settings.audit_store_low_water_bytes >= settings.audit_store_reserve_bytes {
        anyhow::bail!(
            "registrar.audit_store_low_water_bytes ({}) must be less than \
             registrar.audit_store_reserve_bytes ({})",
            settings.audit_store_low_water_bytes,
            settings.audit_store_reserve_bytes
        );
    }
    if settings.audit_max_file_bytes < MIN_AUDIT_MAX_FILE_BYTES {
        anyhow::bail!(
            "registrar.audit_max_file_bytes ({}) must be at least {MIN_AUDIT_MAX_FILE_BYTES}, \
             which is what guarantees one maximum-size audit record fits in a freshly \
             rotated file",
            settings.audit_max_file_bytes
        );
    }
    if settings.audit_max_retained_files == 0 {
        anyhow::bail!(
            "registrar.audit_max_retained_files must be greater than 0; retaining no rotated \
             generation would discard the whole trail at every rotation"
        );
    }
    if settings.audit_min_retain_days == 0 {
        anyhow::bail!("registrar.audit_min_retain_days must be greater than 0");
    }
    validate_rate_limit_sizing(settings)?;
    if !settings.provisioning_config_path.is_absolute() {
        anyhow::bail!(
            "registrar.provisioning_config_path ({}) must be an absolute path; the daemon's \
             working directory is not contracted to be stable under a service supervisor",
            settings.provisioning_config_path.display()
        );
    }
    validate_max_wrap_ttl(settings.max_wrap_ttl)?;
    validate_whole_second_duration("registrar.role_token_ttl", settings.role_token_ttl)?;
    validate_whole_second_duration("registrar.role_secret_id_ttl", settings.role_secret_id_ttl)?;
    if let Some(ttl) = settings.secret_id_ttl {
        validate_whole_second_duration("registrar.secret_id_ttl", ttl)?;
    }
    if let Some(cidrs) = &settings.secret_id_token_bound_cidrs {
        for cidr in cidrs {
            if cidr.trim().is_empty() {
                anyhow::bail!(
                    "registrar.secret_id_token_bound_cidrs must not contain an empty entry"
                );
            }
        }
    }
    if let Some(state_file) = &settings.state_file
        && !state_file.is_absolute()
    {
        anyhow::bail!(
            "registrar.state_file ({}) must be an absolute path; the daemon's working directory \
             is not contracted to be stable under a service supervisor",
            state_file.display()
        );
    }
    Ok(())
}

/// Rejects a rate-limit sizing that would disable the limiter or
/// throttle a legitimate caller.
///
/// A zero burst throttles the first legitimate mint, and a zero refill
/// interval is an unbounded token supply that disables the limiter
/// silently. Both are rejected rather than clamped, so an operator who
/// meant to change the sizing finds out at load time.
fn validate_rate_limit_sizing(settings: &RegistrarSettings) -> Result<()> {
    if settings.rate_limit_admission_burst == 0 {
        anyhow::bail!(
            "registrar.rate_limit_admission_burst must be greater than 0; a zero burst \
             throttles the first legitimate mint"
        );
    }
    if settings.rate_limit_admission_refill_interval_ms == 0 {
        anyhow::bail!(
            "registrar.rate_limit_admission_refill_interval_ms must be greater than 0; a zero \
             interval is an unbounded token supply that disables the limiter silently"
        );
    }
    if settings.rate_limit_predecision_refusal_burst == 0 {
        anyhow::bail!(
            "registrar.rate_limit_predecision_refusal_burst must be greater than 0; a zero burst \
             limits the first legitimate refusal"
        );
    }
    if settings.rate_limit_predecision_refusal_refill_interval_ms == 0 {
        anyhow::bail!(
            "registrar.rate_limit_predecision_refusal_refill_interval_ms must be greater than 0; \
             a zero interval is an unbounded token supply that disables the limiter silently"
        );
    }
    Ok(())
}

/// Rejects a `max_wrap_ttl` the registrar could not grant under.
///
/// The ceiling is validated by handing it to `WrapTtlPolicy::new` rather
/// than by a second copy of its rules, so it is held to exactly what a
/// requested `wrap_ttl` is held to and the policy's own refusal names
/// the fault.
fn validate_max_wrap_ttl(value: Duration) -> Result<()> {
    let maximum = time::Duration::try_from(value).map_err(|_| {
        anyhow::anyhow!(
            "registrar.max_wrap_ttl ({}) is outside the range a duration can carry",
            humantime::format_duration(value)
        )
    })?;
    WrapTtlPolicy::new(maximum).map_err(|refusal| {
        anyhow::anyhow!(
            "registrar.max_wrap_ttl ({}) is not a wrap TTL the registrar can grant under: {}",
            humantime::format_duration(value),
            wrap_ttl_fault(refusal)
        )
    })?;
    Ok(())
}

/// Restates a [`WrapTtlRefusal`] about the configured ceiling.
///
/// The refusal's own `Display` is written about a *requested* value, so
/// it would read as though a caller were at fault for an operator's key.
fn wrap_ttl_fault(refusal: WrapTtlRefusal) -> &'static str {
    match refusal {
        WrapTtlRefusal::Zero => "it is zero",
        WrapTtlRefusal::Negative => "it is negative",
        WrapTtlRefusal::NotWholeSeconds => "it is not a whole number of seconds",
        WrapTtlRefusal::ExceedsOpenBaoRange => "it exceeds the largest OpenBao duration",
    }
}

/// Rejects a duration `OpenBao` has no spelling for.
///
/// `OpenBao` counts whole seconds, so a sub-second remainder has no
/// representation and truncating it would issue a lifetime nobody chose.
fn validate_whole_second_duration(key: &str, value: Duration) -> Result<()> {
    if value.subsec_nanos() != 0 {
        anyhow::bail!(
            "{key} ({}) must be a whole number of seconds; OpenBao durations carry no \
             sub-second remainder",
            humantime::format_duration(value)
        );
    }
    if value.as_secs() == 0 {
        anyhow::bail!(
            "{key} ({}) must be greater than zero",
            humantime::format_duration(value)
        );
    }
    Ok(())
}

/// Rejects an enabled registrar endpoint on a target that cannot serve
/// one.
///
/// The endpoint is systemd socket activation and nothing else: there is
/// no bind path, so there is no degraded mode to fall back to on a
/// platform without it. Refusing here — before the composition boundary
/// looks at `LISTEN_PID` or `LISTEN_FDS` at all — is what keeps the
/// diagnostic "this platform has no such endpoint" rather than "no
/// descriptor was passed", which would send an operator looking for a
/// unit file that could never have run.
#[cfg_attr(target_os = "linux", allow(clippy::unnecessary_wraps))]
fn validate_registrar_endpoint_settings(settings: &RegistrarEndpointSettings) -> Result<()> {
    #[cfg(not(target_os = "linux"))]
    if settings.enabled {
        anyhow::bail!(
            "registrar_endpoint.enabled is true, but the registrar endpoint is \
             supported on Linux only: it is served on a systemd-activated \
             AF_UNIX socket and the daemon never creates one itself"
        );
    }
    #[cfg(target_os = "linux")]
    let _ = settings;
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
    // `registration_id` names the KV subtree the fast-poll loop reads
    // and the state filename it writes, so it goes through the shared
    // path-safe rule rather than a local spelling of it.
    validate_registration_id(&profile.registration_id).map_err(|err| match err {
        ValidationError::Empty => anyhow::anyhow!("profiles.registration_id must not be empty"),
        _ => anyhow::anyhow!(
            "profiles.registration_id must be lowercase alphanumeric and hyphens, \
             starting and ending alphanumeric, at most 131 octets"
        ),
    })?;
    // `service_name` is the SAN's second label, so it is held to the
    // DNS-label rule here rather than at CSR time, where the failure
    // would surface as a rejected order instead of a bad config.
    validate_dns_label(&profile.service_name).map_err(|err| match err {
        ValidationError::Empty => anyhow::anyhow!("profiles.service_name must not be empty"),
        _ => anyhow::anyhow!(
            "profiles.service_name must be a DNS label \
             (letters, digits, hyphens only; max 63 octets)"
        ),
    })?;
    // `hostname` is the SAN's third label, and every writer of a
    // `[[profiles]]` block already validates it as one. Only a
    // hand-edited config can reach here with a dotted or over-long
    // value, and it is rejected for the same reason `service_name` is.
    validate_dns_label(&profile.hostname).map_err(|err| match err {
        ValidationError::Empty => anyhow::anyhow!("profiles.hostname must not be empty"),
        _ => anyhow::anyhow!(
            "profiles.hostname must be a DNS label \
             (letters, digits, hyphens only; max 63 octets)"
        ),
    })?;
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

    /// Every range rule the documented table fixes, each rejection
    /// naming the key it is about.
    #[test]
    fn each_registrar_range_rule_names_the_key_it_rejected() {
        let cases: Vec<(&str, RegistrarSettings)> = vec![
            (
                "registrar.provisioning_config_path",
                RegistrarSettings {
                    provisioning_config_path: std::path::PathBuf::from("provisioning.toml"),
                    ..RegistrarSettings::default()
                },
            ),
            (
                "registrar.max_wrap_ttl",
                RegistrarSettings {
                    max_wrap_ttl: Duration::from_secs(0),
                    ..RegistrarSettings::default()
                },
            ),
            (
                // The whole-second rule comes from `WrapTtlPolicy`
                // rather than from a comparison written here, so it is
                // exercised rather than assumed.
                "registrar.max_wrap_ttl",
                RegistrarSettings {
                    max_wrap_ttl: Duration::from_millis(1_500),
                    ..RegistrarSettings::default()
                },
            ),
            (
                "registrar.role_token_ttl",
                RegistrarSettings {
                    role_token_ttl: Duration::from_secs(0),
                    ..RegistrarSettings::default()
                },
            ),
            (
                "registrar.role_token_ttl",
                RegistrarSettings {
                    role_token_ttl: Duration::from_millis(900),
                    ..RegistrarSettings::default()
                },
            ),
            (
                "registrar.role_secret_id_ttl",
                RegistrarSettings {
                    role_secret_id_ttl: Duration::from_secs(0),
                    ..RegistrarSettings::default()
                },
            ),
            (
                "registrar.secret_id_ttl",
                RegistrarSettings {
                    secret_id_ttl: Some(Duration::from_millis(1)),
                    ..RegistrarSettings::default()
                },
            ),
            (
                "registrar.secret_id_token_bound_cidrs",
                RegistrarSettings {
                    secret_id_token_bound_cidrs: Some(vec![
                        "10.0.0.0/8".to_string(),
                        "  ".to_string(),
                    ]),
                    ..RegistrarSettings::default()
                },
            ),
            (
                "registrar.state_file",
                RegistrarSettings {
                    state_file: Some(std::path::PathBuf::from("state.json")),
                    ..RegistrarSettings::default()
                },
            ),
        ];

        for (key, settings) in cases {
            let error = validate_registrar_settings(&settings)
                .expect_err(&format!("{key} must be rejected"));
            assert!(
                format!("{error:#}").contains(key),
                "the rejection must name {key}: {error:#}"
            );
        }
    }

    /// `max_wrap_ttl` is validated by handing it to `WrapTtlPolicy::new`
    /// rather than by a second copy of its rules, so a value the policy
    /// accepts is a value the validator accepts and no other.
    #[test]
    fn the_wrap_ttl_ceiling_is_validated_by_the_policy_itself() {
        for value in [
            Duration::from_secs(1),
            Duration::from_mins(30),
            Duration::from_hours(24),
        ] {
            let settings = RegistrarSettings {
                max_wrap_ttl: value,
                ..RegistrarSettings::default()
            };
            assert!(
                validate_registrar_settings(&settings).is_ok(),
                "the policy accepts {value:?}, so the validator must too"
            );
        }
    }

    /// Every check above is a pure comparison, so a host that will never
    /// serve a verb still rejects a nonsense value rather than carrying
    /// it until somebody enables the endpoint.
    #[test]
    fn a_registrar_range_violation_is_rejected_with_the_endpoint_disabled() {
        let settings = RegistrarSettings {
            role_token_ttl: Duration::from_secs(0),
            ..RegistrarSettings::default()
        };
        let disabled = RegistrarEndpointSettings::default();

        assert!(validate_registrar_settings(&settings).is_err());
        validate_registrar_state_file_requirement(&RegistrarSettings::default(), &disabled)
            .expect("a disabled endpoint needs no state_file");
    }

    /// The cross-table rule: `state_file` is required exactly when the
    /// endpoint is enabled, and the refusal names both the key and the
    /// enablement that made it required.
    #[test]
    fn state_file_is_required_exactly_when_the_endpoint_is_enabled() {
        let absent = RegistrarSettings::default();
        let present = RegistrarSettings {
            state_file: Some(std::path::PathBuf::from("/var/lib/bootroot/state.json")),
            ..RegistrarSettings::default()
        };

        validate_registrar_state_file_requirement(
            &absent,
            &RegistrarEndpointSettings {
                enabled: false,
                ..RegistrarEndpointSettings::default()
            },
        )
        .expect("a disabled endpoint loads cleanly with no state_file");
        validate_registrar_state_file_requirement(
            &present,
            &RegistrarEndpointSettings {
                enabled: true,
                ..RegistrarEndpointSettings::default()
            },
        )
        .expect("an enabled endpoint with a state_file is accepted");

        let error = validate_registrar_state_file_requirement(
            &absent,
            &RegistrarEndpointSettings {
                enabled: true,
                ..RegistrarEndpointSettings::default()
            },
        )
        .expect_err("an enabled endpoint with no state_file is refused");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("registrar.state_file"),
            "the refusal must name the key: {rendered}"
        );
        assert!(
            rendered.contains("registrar_endpoint.enabled"),
            "the refusal must name the enablement that made it required: {rendered}"
        );
    }

    /// An absolute `state_file` is accepted and carried through
    /// unchanged.
    #[test]
    fn an_absolute_state_file_is_accepted_and_carried_through() {
        let path = std::path::PathBuf::from("/var/lib/bootroot/state.json");
        let settings = RegistrarSettings {
            state_file: Some(path.clone()),
            ..RegistrarSettings::default()
        };
        validate_registrar_settings(&settings).expect("an absolute state_file validates");
        assert_eq!(settings.state_file.as_deref(), Some(path.as_path()));
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

    /// Every shipped `[[profiles]]` template must deserialize and pass
    /// `validate_profile`. The templates are what an operator copies, so
    /// one that omits the now-required `registration_id` would hand them
    /// a config the agent refuses to load.
    #[test]
    fn shipped_agent_config_templates_carry_a_valid_profile() {
        for name in ["agent.toml.example", "agent.toml.compose"] {
            let source = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(name);
            let contents =
                std::fs::read_to_string(&source).unwrap_or_else(|err| panic!("read {name}: {err}"));
            // The templates ship under `.example` / `.compose` suffixes,
            // which the config loader cannot infer a format from; stage a
            // byte-identical copy at a `.toml` name so this reads exactly
            // what an operator would copy into place.
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("agent.toml");
            std::fs::write(&path, &contents).expect("stage template");
            let settings = crate::config::Settings::from_file(Some(path))
                .unwrap_or_else(|err| panic!("{name} must deserialize: {err}"));
            assert!(!settings.profiles.is_empty(), "{name} must ship a profile");
            for profile in &settings.profiles {
                assert!(
                    !profile.registration_id.is_empty(),
                    "{name} must set registration_id"
                );
                validate_profile(profile)
                    .unwrap_or_else(|err| panic!("{name} profile must validate: {err}"));
            }
        }
    }
}
