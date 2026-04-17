use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use x509_parser::pem::parse_x509_pem;

use crate::commands::init::{
    CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME,
    HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_HCL_PATH,
    RESPONDER_CONFIG_DIR, RESPONDER_CONFIG_NAME,
};
use crate::i18n::Messages;

const LOCAL_DB_HOSTS: [&str; 4] = ["postgres", "localhost", "127.0.0.1", "::1"];

/// Compose service names that must bind their published ports to localhost.
/// Note: `grafana:` and `grafana-public:` are behind compose profiles
/// (`lan`/`public`) and are not started by default `infra up`, so they are
/// excluded from this guardrail.
const GUARDED_SERVICES: [&str; 3] = ["postgres:", "openbao:", "bootroot-http01:"];

/// Container mount prefix for the `OpenBao` config directory.
/// Per `docker-compose.yml`: `./openbao:/openbao/config:ro`
const OPENBAO_CONTAINER_CONFIG_PREFIX: &str = "/openbao/config/";

/// Container mount prefix for the responder config directory.
/// Per compose override: `{secrets_dir}/responder:/app/responder:ro`
const RESPONDER_CONTAINER_CONFIG_PREFIX: &str = "/app/responder/";

/// Container mount prefix for the HTTP-01 admin TLS directory.
/// Per compose override: `{secrets_dir}/bootroot-http01/tls:/app/bootroot-http01/tls:ro`
const HTTP01_TLS_CONTAINER_PREFIX: &str = "/app/bootroot-http01/";

/// Default `OpenBao` API port used to identify the API listener block.
const OPENBAO_API_PORT: &str = ":8200";

/// Returns whether a DB host is allowed under the single-host guardrail.
#[must_use]
pub(crate) fn is_single_host_db_host(host: &str) -> bool {
    LOCAL_DB_HOSTS
        .iter()
        .any(|allowed| host.eq_ignore_ascii_case(allowed))
}

/// Ensures the DB host stays within the single-host deployment boundary.
///
/// # Errors
///
/// Returns an error when the host points outside the local/same-host boundary.
pub(crate) fn ensure_single_host_db_host(host: &str, messages: &Messages) -> Result<()> {
    if is_single_host_db_host(host) {
        Ok(())
    } else {
        anyhow::bail!(messages.error_db_host_not_single_host(host))
    }
}

/// Ensures `PostgreSQL` is not published to non-localhost host interfaces.
///
/// # Errors
///
/// Returns an error when the compose file publishes postgres with an unsafe
/// host bind, such as `0.0.0.0:5432:5432` or `5432:5432`.
pub(crate) fn ensure_postgres_localhost_binding(
    compose_file: &Path,
    messages: &Messages,
) -> Result<()> {
    let compose_contents = fs::read_to_string(compose_file)
        .with_context(|| messages.error_read_file_failed(&compose_file.display().to_string()))?;
    if has_unsafe_port_binding_for_service(&compose_contents, "postgres:") {
        anyhow::bail!(messages.error_postgres_port_binding_unsafe());
    }
    Ok(())
}

/// Ensures all guarded compose services publish ports only to localhost.
///
/// # Errors
///
/// Returns an error naming the first service that publishes a port to a
/// non-localhost host interface.
pub(crate) fn ensure_all_services_localhost_binding(
    compose_file: &Path,
    messages: &Messages,
) -> Result<()> {
    let compose_contents = fs::read_to_string(compose_file)
        .with_context(|| messages.error_read_file_failed(&compose_file.display().to_string()))?;
    for service in GUARDED_SERVICES {
        if has_unsafe_port_binding_for_service(&compose_contents, service) {
            let name = service.trim_end_matches(':');
            anyhow::bail!(messages.error_service_port_binding_unsafe(name));
        }
    }
    Ok(())
}

/// Validates the `--openbao-bind` CLI flag value.
///
/// # Errors
///
/// Returns an error when the format is invalid or `0.0.0.0` is used
/// without `--openbao-bind-wildcard`.
pub(crate) fn validate_openbao_bind(
    bind_addr: &str,
    wildcard_confirmed: bool,
    messages: &Messages,
) -> Result<()> {
    let Some((ip_raw, port_str)) = bind_addr.rsplit_once(':') else {
        anyhow::bail!(messages.error_openbao_bind_invalid_format());
    };
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!(messages.error_openbao_bind_invalid_format()))?;
    if port == 0 {
        anyhow::bail!(messages.error_openbao_bind_invalid_format());
    }
    if ip_raw.is_empty() {
        anyhow::bail!(messages.error_openbao_bind_invalid_format());
    }
    // Reject bare IPv6 literals (e.g. `::1:8200`) — require brackets
    // so the address is unambiguous and compatible with Docker Compose
    // port-mapping syntax.
    if ip_raw.contains(':') && !(ip_raw.starts_with('[') && ip_raw.ends_with(']')) {
        anyhow::bail!(messages.error_openbao_bind_ipv6_requires_brackets());
    }
    // Strip brackets for IPv6 (e.g. "[::1]" → "::1").
    let ip_str = ip_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(ip_raw);
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| anyhow::anyhow!(messages.error_openbao_bind_invalid_format()))?;
    if ip.is_unspecified() && !wildcard_confirmed {
        anyhow::bail!(messages.error_openbao_bind_wildcard_required());
    }
    Ok(())
}

/// Returns whether a bind address targets loopback (no TLS or override needed).
#[must_use]
pub(crate) fn is_loopback_bind(addr: &str) -> bool {
    let Some((ip, _)) = addr.rsplit_once(':') else {
        return false;
    };
    ip == "127.0.0.1" || ip.eq_ignore_ascii_case("localhost") || ip == "[::1]"
}

/// Returns whether a bind address targets a wildcard / unspecified IP.
#[must_use]
pub(crate) fn is_wildcard_bind(addr: &str) -> bool {
    let Some((ip, _)) = addr.rsplit_once(':') else {
        return false;
    };
    ip == "0.0.0.0" || ip == "[::]" || ip == "[::0]"
}

/// Validates a `--openbao-advertise-addr` value.
///
/// The address must be a valid `IP:port` that is neither wildcard nor
/// loopback, because remote nodes need to reach this address.
///
/// # Errors
///
/// Returns an error when the format is invalid or the address is
/// wildcard / loopback.
pub(crate) fn validate_openbao_advertise_addr(addr: &str, messages: &Messages) -> Result<()> {
    let Some((ip_raw, port_str)) = addr.rsplit_once(':') else {
        anyhow::bail!(messages.error_openbao_advertise_addr_invalid());
    };
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!(messages.error_openbao_advertise_addr_invalid()))?;
    if port == 0 {
        anyhow::bail!(messages.error_openbao_advertise_addr_invalid());
    }
    if ip_raw.is_empty() {
        anyhow::bail!(messages.error_openbao_advertise_addr_invalid());
    }
    // Reject bare IPv6 literals — require brackets for URL compatibility.
    if ip_raw.contains(':') && !(ip_raw.starts_with('[') && ip_raw.ends_with(']')) {
        anyhow::bail!(messages.error_openbao_advertise_addr_ipv6_requires_brackets());
    }
    let ip_str = ip_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(ip_raw);
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| anyhow::anyhow!(messages.error_openbao_advertise_addr_invalid()))?;
    if ip.is_unspecified() || ip.is_loopback() {
        anyhow::bail!(messages.error_openbao_advertise_addr_not_reachable());
    }
    Ok(())
}

/// Rejects `--openbao-advertise-addr` when the bind address is a
/// specific IP rather than a wildcard.
///
/// The advertise address exists so that remote bootstrap artifacts contain
/// a routable endpoint when `OpenBao` is bound to `0.0.0.0` / `[::]`.
/// For specific-IP binds the bind address itself is routable, making an
/// explicit advertise address redundant and potentially contradictory.
///
/// # Errors
///
/// Returns an error when `advertise_addr` is `Some` and `bind_addr` is
/// not a wildcard.
pub(crate) fn reject_advertise_addr_for_specific_bind(
    bind_addr: &str,
    advertise_addr: Option<&str>,
    messages: &Messages,
) -> Result<()> {
    if !is_wildcard_bind(bind_addr) && advertise_addr.is_some() {
        anyhow::bail!(messages.error_openbao_advertise_addr_specific_bind_rejected());
    }
    Ok(())
}

/// Derives a usable HTTPS client URL from a bind address.
///
/// Wildcard addresses (`0.0.0.0`, `[::]`) are mapped to their loopback
/// counterparts (`127.0.0.1`, `[::1]`) because `bootroot` commands run
/// on the CN and can always reach `OpenBao` via loopback.  Specific IPs
/// are used as-is.
#[must_use]
pub(crate) fn client_url_from_bind_addr(bind_addr: &str) -> String {
    let Some((ip, port)) = bind_addr.rsplit_once(':') else {
        return format!("https://{bind_addr}");
    };
    let client_ip = match ip {
        "0.0.0.0" => "127.0.0.1",
        "[::0]" | "[::]" => "[::1]",
        other => other,
    };
    format!("https://{client_ip}:{port}")
}

/// Validates the `--http01-admin-bind` CLI flag value.
///
/// Reuses the same IP:port format and wildcard rules as `OpenBao` binding.
///
/// # Errors
///
/// Returns an error when the format is invalid or `0.0.0.0` is used
/// without `--http01-admin-bind-wildcard`.
pub(crate) fn validate_http01_admin_bind(
    bind_addr: &str,
    wildcard_confirmed: bool,
    messages: &Messages,
) -> Result<()> {
    let Some((ip_raw, port_str)) = bind_addr.rsplit_once(':') else {
        anyhow::bail!(messages.error_http01_admin_bind_invalid_format());
    };
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!(messages.error_http01_admin_bind_invalid_format()))?;
    if port == 0 {
        anyhow::bail!(messages.error_http01_admin_bind_invalid_format());
    }
    if ip_raw.is_empty() {
        anyhow::bail!(messages.error_http01_admin_bind_invalid_format());
    }
    if ip_raw.contains(':') && !(ip_raw.starts_with('[') && ip_raw.ends_with(']')) {
        anyhow::bail!(messages.error_http01_admin_bind_ipv6_requires_brackets());
    }
    let ip_str = ip_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(ip_raw);
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| anyhow::anyhow!(messages.error_http01_admin_bind_invalid_format()))?;
    if ip.is_unspecified() && !wildcard_confirmed {
        anyhow::bail!(messages.error_http01_admin_bind_wildcard_required());
    }
    Ok(())
}

/// Validates the HTTP-01 admin advertise address format.
///
/// Rejects wildcard, loopback, malformed, and port-zero values because
/// clients need to reach this address.
///
/// # Errors
///
/// Returns an error when the format is invalid or the address is
/// wildcard / loopback.
pub(crate) fn validate_http01_admin_advertise_addr(addr: &str, messages: &Messages) -> Result<()> {
    let Some((ip_raw, port_str)) = addr.rsplit_once(':') else {
        anyhow::bail!(messages.error_http01_admin_advertise_addr_invalid());
    };
    let port: u16 = port_str
        .parse()
        .map_err(|_| anyhow::anyhow!(messages.error_http01_admin_advertise_addr_invalid()))?;
    if port == 0 {
        anyhow::bail!(messages.error_http01_admin_advertise_addr_invalid());
    }
    if ip_raw.is_empty() {
        anyhow::bail!(messages.error_http01_admin_advertise_addr_invalid());
    }
    if ip_raw.contains(':') && !(ip_raw.starts_with('[') && ip_raw.ends_with(']')) {
        anyhow::bail!(messages.error_http01_admin_advertise_addr_ipv6_requires_brackets());
    }
    let ip_str = ip_raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(ip_raw);
    let ip: IpAddr = ip_str
        .parse()
        .map_err(|_| anyhow::anyhow!(messages.error_http01_admin_advertise_addr_invalid()))?;
    if ip.is_unspecified() || ip.is_loopback() {
        anyhow::bail!(messages.error_http01_admin_advertise_addr_not_reachable());
    }
    Ok(())
}

/// Rejects `--http01-admin-advertise-addr` when the bind address is a
/// specific IP rather than a wildcard.
///
/// # Errors
///
/// Returns an error when `advertise_addr` is `Some` and `bind_addr` is
/// not a wildcard.
pub(crate) fn reject_http01_admin_advertise_addr_for_specific_bind(
    bind_addr: &str,
    advertise_addr: Option<&str>,
    messages: &Messages,
) -> Result<()> {
    if !is_wildcard_bind(bind_addr) && advertise_addr.is_some() {
        anyhow::bail!(messages.error_http01_admin_advertise_addr_specific_bind_rejected());
    }
    Ok(())
}

/// Generates the compose override file that exposes the HTTP-01 admin API
/// on a non-loopback address.
///
/// # Errors
///
/// Returns an error if the override file cannot be written.
pub(crate) fn write_http01_exposed_override(
    compose_dir: &Path,
    bind_addr: &str,
    messages: &Messages,
) -> Result<PathBuf> {
    let override_dir = compose_dir.join("secrets").join("responder");
    if !override_dir.exists() {
        fs::create_dir_all(&override_dir).with_context(|| {
            messages.error_write_file_failed(&override_dir.display().to_string())
        })?;
    }
    let override_path = override_dir.join(HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME);
    let content = format!(
        "\
services:
  bootroot-http01:
    ports: !reset
      - \"{bind_addr}:8080\"
"
    );
    fs::write(&override_path, content)
        .with_context(|| messages.error_write_file_failed(&override_path.display().to_string()))?;
    Ok(override_path)
}

/// Validates that the HTTP-01 admin compose override port mapping matches
/// the bind address stored in `StateFile`.
///
/// # Errors
///
/// Returns an error when the override contains no responder port mapping,
/// more than one mapping, or a mapping that does not match the expected
/// `{bind_addr}:8080` value.
pub(crate) fn validate_http01_override_binding(
    override_path: &Path,
    expected_bind_addr: &str,
    messages: &Messages,
) -> Result<()> {
    let content = fs::read_to_string(override_path)
        .with_context(|| messages.error_read_file_failed(&override_path.display().to_string()))?;
    let mappings = collect_port_mappings_for_service(&content, "bootroot-http01:");
    let expected = format!("{expected_bind_addr}:8080");
    if mappings.len() != 1 || mappings.first().map(String::as_str) != Some(expected.as_str()) {
        let actual = if mappings.is_empty() {
            "(none)".to_string()
        } else {
            mappings.join(", ")
        };
        anyhow::bail!(messages.error_http01_admin_override_binding_mismatch(&expected, &actual));
    }
    Ok(())
}

/// Validates that the HTTP-01 admin compose override does not introduce
/// non-loopback port bindings for services other than `bootroot-http01`.
///
/// # Errors
///
/// Returns an error naming the first non-responder service that publishes
/// a non-loopback port.
pub(crate) fn validate_http01_override_scope(
    override_path: &Path,
    messages: &Messages,
) -> Result<()> {
    let content = fs::read_to_string(override_path)
        .with_context(|| messages.error_read_file_failed(&override_path.display().to_string()))?;
    for service in GUARDED_SERVICES {
        if service == "bootroot-http01:" {
            continue;
        }
        if has_unsafe_port_binding_for_service(&content, service) {
            let name = service.trim_end_matches(':');
            anyhow::bail!(messages.error_service_port_binding_unsafe(name));
        }
    }
    Ok(())
}

/// Validates that `OpenBao` TLS is configured for non-loopback binding.
///
/// Parses `tls_cert_file` and `tls_key_file` from `openbao.hcl` to
/// determine which files `OpenBao` is actually configured to serve, then
/// verifies those files are readable, TLS is enabled (no
/// `tls_disable = 1`), and the server certificate chains to the local
/// step-ca root.
///
/// # Errors
///
/// Returns an error describing which TLS prerequisites are missing.
pub(crate) fn validate_openbao_tls(
    compose_dir: &Path,
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let hcl_path = compose_dir.join(OPENBAO_HCL_PATH);
    let mut issues = Vec::new();

    // Read openbao.hcl first to determine the configured cert/key paths.
    let hcl_content =
        if hcl_path.exists() {
            Some(fs::read_to_string(&hcl_path).with_context(|| {
                messages.error_read_file_failed(&hcl_path.display().to_string())
            })?)
        } else {
            issues.push(format!("{OPENBAO_HCL_PATH} not found"));
            None
        };

    let mut cert_host_path: Option<PathBuf> = None;
    let mut key_host_path: Option<PathBuf> = None;

    if let Some(ref content) = hcl_content {
        // Scope TLS checks to the API listener block — the one that
        // serves on `:8200` (or the sole/default listener when no
        // explicit address is configured).  Other listeners (e.g.
        // telemetry on `:9101`) may legitimately have `tls_disable = 1`
        // without affecting TLS on the API port.
        let listener_blocks = extract_listener_blocks(content);
        let api_block = find_api_listener_block(&listener_blocks);
        let tls_content = api_block.map_or(content.as_str(), String::as_str);

        // Parse configured TLS paths and resolve container→host.
        match parse_hcl_string_value(tls_content, "tls_cert_file") {
            Some(cp) => match resolve_container_path_to_host(cp, compose_dir) {
                Some(hp) => cert_host_path = Some(hp),
                None => issues.push(format!(
                    "tls_cert_file container path cannot be resolved to host: {cp}"
                )),
            },
            None => issues.push("openbao.hcl does not reference tls_cert_file".to_string()),
        }

        match parse_hcl_string_value(tls_content, "tls_key_file") {
            Some(cp) => match resolve_container_path_to_host(cp, compose_dir) {
                Some(hp) => key_host_path = Some(hp),
                None => issues.push(format!(
                    "tls_key_file container path cannot be resolved to host: {cp}"
                )),
            },
            None => issues.push("openbao.hcl does not reference tls_key_file".to_string()),
        }

        if has_tls_disabled(tls_content) {
            issues.push("openbao.hcl has tls_disable enabled".to_string());
        }
    }

    // Verify cert and key are readable at the resolved host paths.
    let cert_bytes = if let Some(ref path) = cert_host_path {
        if let Ok(bytes) = fs::read(path) {
            Some(bytes)
        } else {
            issues.push(format!(
                "cert not found or not readable: {}",
                path.display()
            ));
            None
        }
    } else {
        None
    };
    if let Some(ref path) = key_host_path
        && fs::read(path).is_err()
    {
        issues.push(format!("key not found or not readable: {}", path.display()));
    }

    // Validate certificate chains to the local step-ca root.
    if let Some(ref cert_bytes) = cert_bytes
        && let Err(chain_err) = validate_cert_chain_to_stepca_root(secrets_dir, cert_bytes)
    {
        issues.push(format!("certificate chain validation failed: {chain_err}"));
    }

    if !issues.is_empty() {
        anyhow::bail!(messages.error_openbao_bind_tls_missing(&issues.join("; ")));
    }
    Ok(())
}

/// Validates that HTTP-01 admin API TLS is configured for non-loopback
/// binding.
///
/// Reads `responder.toml` from the secrets directory and checks that
/// `tls_cert_path` and `tls_key_path` are configured, that the
/// referenced cert/key files are readable on the host, and that the
/// server certificate chains to the local step-ca root.
///
/// # Errors
///
/// Returns an error describing which TLS prerequisites are missing.
pub(crate) fn validate_http01_admin_tls(secrets_dir: &Path, messages: &Messages) -> Result<()> {
    let responder_config_path = secrets_dir
        .join(RESPONDER_CONFIG_DIR)
        .join(RESPONDER_CONFIG_NAME);
    let mut issues = Vec::new();

    let config_content = if responder_config_path.exists() {
        Some(fs::read_to_string(&responder_config_path).with_context(|| {
            messages.error_read_file_failed(&responder_config_path.display().to_string())
        })?)
    } else {
        issues.push(format!(
            "responder config not found: {}",
            responder_config_path.display()
        ));
        None
    };

    let mut cert_host_path: Option<PathBuf> = None;
    let mut key_host_path: Option<PathBuf> = None;

    if let Some(ref content) = config_content {
        // `parse_hcl_string_value` works for flat TOML `key = "value"`
        // lines because HCL and TOML share the same assignment syntax
        // and `#` comment marker.
        match parse_hcl_string_value(content, "tls_cert_path") {
            Some(cp) => match resolve_responder_container_path(cp, secrets_dir) {
                Some(hp) => cert_host_path = Some(hp),
                None => issues.push(format!(
                    "tls_cert_path container path cannot be resolved to host: {cp}"
                )),
            },
            None => issues.push("responder.toml does not set tls_cert_path".to_string()),
        }

        match parse_hcl_string_value(content, "tls_key_path") {
            Some(kp) => match resolve_responder_container_path(kp, secrets_dir) {
                Some(hp) => key_host_path = Some(hp),
                None => issues.push(format!(
                    "tls_key_path container path cannot be resolved to host: {kp}"
                )),
            },
            None => issues.push("responder.toml does not set tls_key_path".to_string()),
        }
    }

    let cert_bytes = if let Some(ref path) = cert_host_path {
        if let Ok(bytes) = fs::read(path) {
            Some(bytes)
        } else {
            issues.push(format!(
                "cert not found or not readable: {}",
                path.display()
            ));
            None
        }
    } else {
        None
    };
    let key_bytes = if let Some(ref path) = key_host_path {
        if let Ok(bytes) = fs::read(path) {
            Some(bytes)
        } else {
            issues.push(format!("key not found or not readable: {}", path.display()));
            None
        }
    } else {
        None
    };

    if let Some(ref cert_bytes) = cert_bytes
        && let Err(chain_err) = validate_cert_chain_to_stepca_root(secrets_dir, cert_bytes)
    {
        issues.push(format!("certificate chain validation failed: {chain_err}"));
    }

    if let (Some(cb), Some(kb)) = (&cert_bytes, &key_bytes)
        && let Err(load_err) = validate_tls_key_material(cb, kb)
    {
        issues.push(format!("TLS key material not loadable: {load_err}"));
    }

    if !issues.is_empty() {
        anyhow::bail!(messages.error_http01_admin_bind_tls_missing(&issues.join("; ")));
    }
    Ok(())
}

/// Maps a responder container path to a host path.
///
/// Handles two volume mount conventions:
/// - `{secrets_dir}/responder:/app/responder:ro` for config files
/// - `{secrets_dir}/bootroot-http01:/app/bootroot-http01:ro` for TLS certs
fn resolve_responder_container_path(container_path: &str, secrets_dir: &Path) -> Option<PathBuf> {
    container_path
        .strip_prefix(RESPONDER_CONTAINER_CONFIG_PREFIX)
        .map(|relative| secrets_dir.join("responder").join(relative))
        .or_else(|| {
            container_path
                .strip_prefix(HTTP01_TLS_CONTAINER_PREFIX)
                .map(|relative| secrets_dir.join("bootroot-http01").join(relative))
        })
}

/// Strips a trailing HCL comment (`#` or `//`) from a line, preserving
/// comment markers that appear inside double-quoted strings.
fn strip_hcl_line_comment(line: &str) -> &str {
    let mut in_quote = false;
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'"' => in_quote = !in_quote,
            b'#' if !in_quote => return &line[..i],
            b'/' if !in_quote && bytes.get(i + 1) == Some(&b'/') => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Finds `key` in `line` at a word boundary (not preceded or followed by
/// an ASCII identifier character).
fn find_hcl_key(line: &str, key: &str) -> Option<usize> {
    let is_ident = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let mut start = 0;
    while let Some(rel) = line[start..].find(key) {
        let abs = start + rel;
        let end = abs + key.len();
        let before_ok = abs == 0 || !is_ident(line.as_bytes()[abs - 1]);
        let after_ok = end >= line.len() || !is_ident(line.as_bytes()[end]);
        if before_ok && after_ok {
            return Some(abs);
        }
        start = abs + 1;
    }
    None
}

/// Returns whether `openbao.hcl` content has TLS explicitly disabled.
fn has_tls_disabled(hcl_content: &str) -> bool {
    for line in hcl_content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let active = strip_hcl_line_comment(trimmed);
        // Match `tls_disable = 1` / `tls_disable = true` / `tls_disable = "1"`
        // anywhere in the active (non-comment) portion of the line.
        if let Some(offset) = find_hcl_key(active, "tls_disable") {
            let rest = &active[offset + "tls_disable".len()..];
            let value = rest.trim().trim_start_matches('=').trim();
            // Take only the first whitespace-delimited token to avoid
            // matching subsequent keys on the same line.
            let value = value.split_whitespace().next().unwrap_or("");
            let value = value.trim_matches('"');
            if value == "1" || value.eq_ignore_ascii_case("true") {
                return true;
            }
        }
    }
    false
}

/// Extracts a quoted string value for a given key from HCL-like content.
///
/// Returns the first unquoted value matching `key = "value"`, ignoring
/// trailing comments and requiring whole-key matches.
pub(crate) fn parse_hcl_string_value<'a>(content: &'a str, key: &str) -> Option<&'a str> {
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }
        let active = strip_hcl_line_comment(trimmed);
        if let Some(offset) = find_hcl_key(active, key) {
            let rest = &active[offset + key.len()..];
            let rest = rest.trim().trim_start_matches('=').trim();
            if let Some(inner) = rest.strip_prefix('"')
                && let Some(end) = inner.find('"')
            {
                return Some(&inner[..end]);
            }
        }
    }
    None
}

/// Extracts the content of each `listener` block from HCL text.
///
/// Uses brace-depth counting to delimit blocks, handling both
/// multi-line and single-line `listener "tcp" { ... }` forms and
/// nested sub-blocks (e.g. `telemetry { ... }`).
fn extract_listener_blocks(content: &str) -> Vec<String> {
    let mut blocks = Vec::new();
    let mut current_block = String::new();
    let mut in_listener = false;
    let mut brace_depth: u32 = 0;

    for line in content.lines() {
        let trimmed = line.trim();

        if !in_listener {
            if trimmed.starts_with("listener") && !trimmed.starts_with('#') {
                in_listener = true;
                brace_depth = 0;
                current_block.clear();
            } else {
                continue;
            }
        }

        for ch in line.chars() {
            match ch {
                '{' => brace_depth += 1,
                '}' => brace_depth = brace_depth.saturating_sub(1),
                _ => {}
            }
        }
        current_block.push_str(line);
        current_block.push('\n');

        if brace_depth == 0 && current_block.contains('{') {
            blocks.push(std::mem::take(&mut current_block));
            in_listener = false;
        }
    }

    blocks
}

/// Finds the API listener block among extracted listener blocks.
///
/// The API listener is identified by its `address` field containing
/// `:8200`.  When no explicit `:8200` address is found, a listener
/// without an `address` field is assumed to be the API listener
/// (`OpenBao` defaults to `0.0.0.0:8200`), even when other listeners
/// (e.g. telemetry) exist alongside it.  Returns `None` if no match is
/// found, which causes the caller to fall back to the full HCL content.
fn find_api_listener_block(blocks: &[String]) -> Option<&String> {
    // Prefer an explicit `:8200` address match.
    if let Some(block) = blocks
        .iter()
        .find(|b| matches!(parse_hcl_string_value(b, "address"), Some(addr) if addr.ends_with(OPENBAO_API_PORT)))
    {
        return Some(block);
    }
    // A listener without an explicit `address` defaults to `:8200` in
    // OpenBao, so treat it as the API listener even when other listeners
    // (e.g. telemetry on `:9101`) exist alongside it.
    if let Some(block) = blocks
        .iter()
        .find(|b| parse_hcl_string_value(b, "address").is_none())
    {
        return Some(block);
    }
    None
}

/// Maps an `OpenBao` container path to a host path.
///
/// Uses the volume mount convention `./openbao:/openbao/config:ro` to
/// resolve container paths (e.g. `/openbao/config/tls/server.crt`) to
/// host paths (e.g. `compose_dir/openbao/tls/server.crt`).
fn resolve_container_path_to_host(container_path: &str, compose_dir: &Path) -> Option<PathBuf> {
    container_path
        .strip_prefix(OPENBAO_CONTAINER_CONFIG_PREFIX)
        .map(|relative| compose_dir.join("openbao").join(relative))
}

/// Validates that the cert and key PEM bytes can be parsed and loaded as
/// a `rustls` `CertifiedKey`, and that the private key matches the leaf
/// certificate.
///
/// Mirrors the same load path the responder uses at startup
/// (`load_certified_key` in the responder's `tls` module), so a failure
/// here means the responder would also fail to start.
fn validate_tls_key_material(cert_bytes: &[u8], key_bytes: &[u8]) -> Result<()> {
    use std::io::BufReader;

    let _ = rustls::crypto::ring::default_provider().install_default();

    let certs: Vec<_> = rustls_pemfile::certs(&mut BufReader::new(cert_bytes))
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("failed to parse PEM certificates")?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in cert file");
    }

    let key = rustls_pemfile::private_key(&mut BufReader::new(key_bytes))
        .context("failed to parse PEM private key")?
        .ok_or_else(|| anyhow::anyhow!("no private key found in key file"))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| anyhow::anyhow!("unsupported private key type: {e}"))?;

    verify_cert_key_match(certs.first().expect("non-empty certs"), &*signing_key)?;

    Ok(())
}

/// Verifies that a private key matches the leaf certificate by signing a
/// test payload and verifying the signature against the certificate's
/// public key.
fn verify_cert_key_match(
    leaf_cert: &rustls::pki_types::CertificateDer<'_>,
    signing_key: &dyn rustls::sign::SigningKey,
) -> Result<()> {
    let schemes = [
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
        rustls::SignatureScheme::RSA_PSS_SHA256,
        rustls::SignatureScheme::ED25519,
    ];
    let signer = signing_key
        .choose_scheme(&schemes)
        .ok_or_else(|| anyhow::anyhow!("no supported signature scheme for cert/key match"))?;
    let scheme = signer.scheme();

    let test_message = b"bootroot-cert-key-match-check";
    let signature = signer
        .sign(test_message)
        .map_err(|e| anyhow::anyhow!("test signature for cert/key match failed: {e}"))?;

    let (_, cert) = x509_parser::parse_x509_certificate(leaf_cert.as_ref())
        .map_err(|e| anyhow::anyhow!("parse leaf certificate for key match: {e}"))?;
    let public_key_bytes: &[u8] = cert.public_key().subject_public_key.as_ref();

    let ring_alg: &dyn ring::signature::VerificationAlgorithm = match scheme {
        rustls::SignatureScheme::ECDSA_NISTP256_SHA256 => &ring::signature::ECDSA_P256_SHA256_ASN1,
        rustls::SignatureScheme::ECDSA_NISTP384_SHA384 => &ring::signature::ECDSA_P384_SHA384_ASN1,
        rustls::SignatureScheme::RSA_PSS_SHA256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
        rustls::SignatureScheme::ED25519 => &ring::signature::ED25519,
        other => anyhow::bail!("unsupported scheme for cert/key match: {other:?}"),
    };
    let verifier = ring::signature::UnparsedPublicKey::new(ring_alg, public_key_bytes);
    verifier
        .verify(test_message, &signature)
        .map_err(|_| anyhow::anyhow!("private key does not match the leaf certificate"))?;

    Ok(())
}

/// Validates that the server certificate chains to the local step-ca root.
///
/// Performs cryptographic signature verification — not just DN comparison —
/// so a certificate that copies the root's subject DN but is signed by a
/// different key will be rejected.
fn validate_cert_chain_to_stepca_root(secrets_dir: &Path, cert_bytes: &[u8]) -> Result<()> {
    let certs_dir = secrets_dir.join(CA_CERTS_DIR);
    let root_path = certs_dir.join(CA_ROOT_CERT_FILENAME);

    let root_bytes = fs::read(&root_path)
        .with_context(|| format!("step-ca root CA not found: {}", root_path.display()))?;

    // Parse PEM → DER.  The `Pem` structs own the DER bytes that the
    // parsed `X509Certificate` references, so they must stay alive.
    let (_, server_pem) =
        parse_x509_pem(cert_bytes).map_err(|e| anyhow::anyhow!("invalid server PEM: {e}"))?;
    let (_, server_cert) = x509_parser::parse_x509_certificate(&server_pem.contents)
        .map_err(|e| anyhow::anyhow!("invalid server X.509: {e}"))?;

    let (_, root_pem) =
        parse_x509_pem(&root_bytes).map_err(|e| anyhow::anyhow!("invalid root CA PEM: {e}"))?;
    let (_, root_cert) = x509_parser::parse_x509_certificate(&root_pem.contents)
        .map_err(|e| anyhow::anyhow!("invalid root CA X.509: {e}"))?;

    // Direct chain: server cert signed by root CA key.
    if server_cert
        .verify_signature(Some(root_cert.public_key()))
        .is_ok()
    {
        return Ok(());
    }

    // Indirect chain through intermediate CA: server → intermediate → root.
    let intermediate_path = certs_dir.join(CA_INTERMEDIATE_CERT_FILENAME);
    if let Ok(intermediate_bytes) = fs::read(&intermediate_path)
        && let Ok((_, intermediate_pem)) = parse_x509_pem(&intermediate_bytes)
        && let Ok((_, intermediate_cert)) =
            x509_parser::parse_x509_certificate(&intermediate_pem.contents)
        && server_cert
            .verify_signature(Some(intermediate_cert.public_key()))
            .is_ok()
        && intermediate_cert
            .verify_signature(Some(root_cert.public_key()))
            .is_ok()
    {
        return Ok(());
    }

    anyhow::bail!("server certificate does not chain to the local step-ca root CA")
}

/// Generates the compose override file that exposes `OpenBao` on a
/// non-loopback address.
///
/// The override uses Docker Compose `!reset` to replace the base port
/// mapping with the operator-specified bind address.
///
/// # Errors
///
/// Returns an error if the override file cannot be written.
pub(crate) fn write_openbao_exposed_override(
    compose_dir: &Path,
    bind_addr: &str,
    messages: &Messages,
) -> Result<std::path::PathBuf> {
    let override_dir = compose_dir.join("secrets").join("openbao");
    if !override_dir.exists() {
        std::fs::create_dir_all(&override_dir).with_context(|| {
            messages.error_write_file_failed(&override_dir.display().to_string())
        })?;
    }
    let override_path = override_dir.join(OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME);
    let content = format!(
        "\
services:
  openbao:
    ports: !reset
      - \"{bind_addr}:8200\"
"
    );
    std::fs::write(&override_path, content)
        .with_context(|| messages.error_write_file_failed(&override_path.display().to_string()))?;
    Ok(override_path)
}

/// Validates that the `OpenBao` compose override does not introduce
/// non-loopback port bindings for services other than `OpenBao`.
///
/// Prevents a tampered override from exposing guarded services
/// (postgres, bootroot-http01) to non-loopback interfaces.
///
/// # Errors
///
/// Returns an error naming the first non-`OpenBao` service that
/// publishes a non-loopback port.
pub(crate) fn validate_openbao_override_scope(
    override_path: &Path,
    messages: &Messages,
) -> Result<()> {
    let content = fs::read_to_string(override_path)
        .with_context(|| messages.error_read_file_failed(&override_path.display().to_string()))?;
    for service in GUARDED_SERVICES {
        if service == "openbao:" {
            continue;
        }
        if has_unsafe_port_binding_for_service(&content, service) {
            let name = service.trim_end_matches(':');
            anyhow::bail!(messages.error_service_port_binding_unsafe(name));
        }
    }
    Ok(())
}

/// Validates that the `OpenBao` compose override port mapping matches the
/// bind address stored in `StateFile`.
///
/// Prevents a manually edited override from widening the binding (e.g.
/// `0.0.0.0`) or changing the host port without re-running `infra install`
/// with the appropriate flags.
///
/// # Errors
///
/// Returns an error when the override contains no openbao port mapping,
/// more than one mapping, or a mapping that does not match the expected
/// `{bind_addr}:8200` value.
pub(crate) fn validate_openbao_override_binding(
    override_path: &Path,
    expected_bind_addr: &str,
    messages: &Messages,
) -> Result<()> {
    let content = fs::read_to_string(override_path)
        .with_context(|| messages.error_read_file_failed(&override_path.display().to_string()))?;
    let mappings = collect_port_mappings_for_service(&content, "openbao:");
    let expected = format!("{expected_bind_addr}:8200");
    if mappings.len() != 1 || mappings.first().map(String::as_str) != Some(expected.as_str()) {
        let actual = if mappings.is_empty() {
            "(none)".to_string()
        } else {
            mappings.join(", ")
        };
        anyhow::bail!(messages.error_openbao_override_binding_mismatch(&expected, &actual));
    }
    Ok(())
}

/// Collects raw port mapping values for a compose service.
///
/// Returns each `- "host:container"` value with surrounding quotes
/// stripped.
fn collect_port_mappings_for_service(compose: &str, service_key: &str) -> Vec<String> {
    let mut mappings = Vec::new();
    let mut in_service = false;
    let mut service_indent = 0usize;
    let mut in_ports = false;
    let mut ports_indent = 0usize;

    for line in compose.lines() {
        let indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if in_service && indent <= service_indent && !trimmed.starts_with('-') {
            in_service = false;
            in_ports = false;
        }

        if !in_service && trimmed == service_key {
            in_service = true;
            service_indent = indent;
            in_ports = false;
            continue;
        }

        if !in_service {
            continue;
        }

        if !in_ports && (trimmed == "ports:" || trimmed.starts_with("ports: ")) {
            let rest = trimmed.strip_prefix("ports:").unwrap_or("").trim();
            if let Some(values) = parse_inline_yaml_port_values(rest) {
                mappings.extend(values);
            } else {
                in_ports = true;
                ports_indent = indent;
            }
            continue;
        }

        if in_ports && indent <= ports_indent {
            in_ports = false;
            continue;
        }

        if in_ports && trimmed.starts_with('-') {
            let value = trimmed.trim_start_matches('-').trim();
            let mapping = value.trim_matches('"').trim_matches('\'');
            if !mapping.is_empty() {
                mappings.push(mapping.to_string());
            }
        }
    }

    mappings
}

fn has_unsafe_port_binding_for_service(compose: &str, service_key: &str) -> bool {
    let mut in_service = false;
    let mut service_indent = 0usize;
    let mut in_ports = false;
    let mut ports_indent = 0usize;

    for line in compose.lines() {
        let indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if in_service && indent <= service_indent && !trimmed.starts_with('-') {
            in_service = false;
            in_ports = false;
        }

        if !in_service && trimmed == service_key {
            in_service = true;
            service_indent = indent;
            in_ports = false;
            continue;
        }

        if !in_service {
            continue;
        }

        // Match `ports:` with optional YAML tags like `!reset`.
        if !in_ports && (trimmed == "ports:" || trimmed.starts_with("ports: ")) {
            let rest = trimmed.strip_prefix("ports:").unwrap_or("").trim();
            if let Some(values) = parse_inline_yaml_port_values(rest) {
                for v in &values {
                    if is_unsafe_port_mapping(v) {
                        return true;
                    }
                }
            } else {
                in_ports = true;
                ports_indent = indent;
            }
            continue;
        }

        if in_ports && indent <= ports_indent {
            in_ports = false;
            continue;
        }

        if in_ports && trimmed.starts_with('-') {
            let value = trimmed.trim_start_matches('-').trim();
            if is_unsafe_port_mapping(value) {
                return true;
            }
        }
    }

    false
}

/// Extracts port values from an inline YAML array on a `ports:` line.
///
/// Handles forms like `ports: ["5432"]`, `ports: ["0.0.0.0:5432:5432"]`,
/// and `ports: !reset ["5432"]`.  Returns `None` when the remainder does
/// not contain an inline array.
fn parse_inline_yaml_port_values(rest: &str) -> Option<Vec<String>> {
    let s = rest.trim();
    // Skip optional YAML tags (e.g., `!reset`).
    let s = if let Some(after_tag) = s.strip_prefix('!') {
        after_tag
            .split_once(char::is_whitespace)
            .map_or("", |(_, after)| after.trim())
    } else {
        s
    };
    let inner = s.strip_prefix('[')?.strip_suffix(']')?;
    Some(
        inner
            .split(',')
            .map(|v| v.trim().trim_matches('"').trim_matches('\'').to_string())
            .filter(|v| !v.is_empty())
            .collect(),
    )
}

fn is_unsafe_port_mapping(raw: &str) -> bool {
    let mapping = raw.trim_matches('"').trim_matches('\'');
    if mapping.is_empty() {
        return false;
    }
    // A mapping that starts with a loopback address is safe.
    if mapping.starts_with("127.0.0.1:")
        || mapping.starts_with("localhost:")
        || mapping.starts_with("[::1]:")
    {
        return false;
    }

    // Any other non-empty mapping is unsafe.  This includes:
    //  - host:container forms without a loopback prefix (`5432:5432`,
    //    `0.0.0.0:5432:5432`)
    //  - bare container-port forms (`5432`, `5432-5434`) which Docker
    //    publishes on `0.0.0.0` with a random host port.
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_single_host_db_host_accepts_local_values() {
        assert!(is_single_host_db_host("postgres"));
        assert!(is_single_host_db_host("localhost"));
        assert!(is_single_host_db_host("127.0.0.1"));
        assert!(is_single_host_db_host("::1"));
    }

    #[test]
    fn is_single_host_db_host_rejects_remote_values() {
        assert!(!is_single_host_db_host("db.internal"));
        assert!(!is_single_host_db_host("10.0.0.15"));
    }

    #[test]
    fn has_unsafe_postgres_port_binding_accepts_localhost_bind() {
        let compose = r#"
services:
  postgres:
    image: postgres:18
    ports:
      - "127.0.0.1:5432:5432"
"#;
        assert!(!has_unsafe_port_binding_for_service(compose, "postgres:"));
    }

    #[test]
    fn has_unsafe_postgres_port_binding_rejects_all_interfaces() {
        let compose = r#"
services:
  postgres:
    image: postgres:18
    ports:
      - "5432:5432"
"#;
        assert!(has_unsafe_port_binding_for_service(compose, "postgres:"));
    }

    #[test]
    fn has_unsafe_postgres_port_binding_rejects_explicit_non_localhost_bind() {
        let compose = r#"
services:
  postgres:
    image: postgres:18
    ports:
      - "0.0.0.0:5432:5432"
"#;
        assert!(has_unsafe_port_binding_for_service(compose, "postgres:"));
    }

    #[test]
    fn has_unsafe_postgres_port_binding_rejects_bare_container_port() {
        let compose = r#"
services:
  postgres:
    image: postgres:18
    ports:
      - "5432"
"#;
        assert!(has_unsafe_port_binding_for_service(compose, "postgres:"));
    }

    /// Regression: inline YAML array `ports: ["5432"]` must be detected
    /// as unsafe even though the parser normally expects block-style lists.
    #[test]
    fn has_unsafe_port_binding_rejects_inline_array_bare_port() {
        let compose = r#"
services:
  postgres:
    ports: ["5432"]
"#;
        assert!(has_unsafe_port_binding_for_service(compose, "postgres:"));
    }

    /// Regression: inline YAML array with a non-loopback host mapping.
    #[test]
    fn has_unsafe_port_binding_rejects_inline_array_non_loopback() {
        let compose = r#"
services:
  postgres:
    ports: ["0.0.0.0:5432:5432"]
"#;
        assert!(has_unsafe_port_binding_for_service(compose, "postgres:"));
    }

    #[test]
    fn has_unsafe_port_binding_accepts_inline_array_loopback() {
        let compose = r#"
services:
  postgres:
    ports: ["127.0.0.1:5432:5432"]
"#;
        assert!(!has_unsafe_port_binding_for_service(compose, "postgres:"));
    }

    /// Regression: `collect_port_mappings_for_service` must extract values
    /// from inline YAML arrays.
    #[test]
    fn collect_port_mappings_handles_inline_array() {
        let compose = r#"
services:
  openbao:
    ports: ["192.168.1.10:8200:8200"]
"#;
        let mappings = collect_port_mappings_for_service(compose, "openbao:");
        assert_eq!(mappings, vec!["192.168.1.10:8200:8200"]);
    }

    #[test]
    fn detects_unsafe_openbao_port_binding() {
        let compose = r#"
services:
  openbao:
    image: openbao/openbao:latest
    ports:
      - "8200:8200"
"#;
        assert!(has_unsafe_port_binding_for_service(compose, "openbao:"));
    }

    #[test]
    fn accepts_safe_openbao_port_binding() {
        let compose = r#"
services:
  openbao:
    image: openbao/openbao:latest
    ports:
      - "127.0.0.1:8200:8200"
"#;
        assert!(!has_unsafe_port_binding_for_service(compose, "openbao:"));
    }

    #[test]
    fn detects_unsafe_responder_port_binding() {
        let compose = r#"
services:
  bootroot-http01:
    image: bootroot-http01-responder:latest
    ports:
      - "8080:8080"
"#;
        assert!(has_unsafe_port_binding_for_service(
            compose,
            "bootroot-http01:"
        ));
    }

    #[test]
    fn validate_openbao_bind_accepts_specific_ip() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("192.168.1.10:8200", false, &messages).is_ok());
    }

    #[test]
    fn validate_openbao_bind_rejects_missing_port() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("192.168.1.10", false, &messages).is_err());
    }

    #[test]
    fn validate_openbao_bind_rejects_empty_ip() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind(":8200", false, &messages).is_err());
    }

    #[test]
    fn validate_openbao_bind_rejects_invalid_port() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("192.168.1.10:abc", false, &messages).is_err());
    }

    /// Regression: port 0 parses as valid `u16` but produces an unusable
    /// endpoint (`https://1.2.3.4:0`), so the validator must reject it.
    #[test]
    fn validate_openbao_bind_rejects_port_zero() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("192.168.1.10:0", false, &messages).is_err());
        assert!(validate_openbao_bind("0.0.0.0:0", true, &messages).is_err());
    }

    #[test]
    fn validate_openbao_bind_rejects_wildcard_without_flag() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("0.0.0.0:8200", false, &messages).is_err());
    }

    #[test]
    fn validate_openbao_bind_accepts_wildcard_with_flag() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("0.0.0.0:8200", true, &messages).is_ok());
    }

    #[test]
    fn validate_openbao_bind_rejects_non_ip_hostname() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("foo:8200", false, &messages).is_err());
        assert!(validate_openbao_bind("not-an-ip:8200", false, &messages).is_err());
    }

    #[test]
    fn validate_openbao_bind_accepts_bracketed_ipv6() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("[::1]:8200", false, &messages).is_ok());
        assert!(validate_openbao_bind("[fd12::1]:8200", false, &messages).is_ok());
    }

    #[test]
    fn validate_openbao_bind_rejects_ipv6_wildcard_without_flag() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("[::]:8200", false, &messages).is_err());
    }

    #[test]
    fn validate_openbao_bind_accepts_ipv6_wildcard_with_flag() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("[::]:8200", true, &messages).is_ok());
    }

    #[test]
    fn validate_openbao_bind_rejects_bare_ipv6_loopback() {
        let messages = crate::i18n::test_messages();
        // Bare `::1:8200` is ambiguous and incompatible with Docker
        // Compose syntax — must use `[::1]:8200`.
        assert!(validate_openbao_bind("::1:8200", false, &messages).is_err());
    }

    #[test]
    fn validate_openbao_bind_rejects_bare_ipv6_non_loopback() {
        let messages = crate::i18n::test_messages();
        // Bare `2001:db8::10:8200` must be rejected — use
        // `[2001:db8::10]:8200`.
        assert!(validate_openbao_bind("2001:db8::10:8200", false, &messages).is_err());
    }

    #[test]
    fn validate_openbao_bind_rejects_malformed_ipv6() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_bind("[:::bad]:8200", false, &messages).is_err());
    }

    #[test]
    fn is_loopback_bind_detects_loopback_addresses() {
        assert!(is_loopback_bind("127.0.0.1:8200"));
        assert!(is_loopback_bind("localhost:8200"));
        assert!(is_loopback_bind("[::1]:8200"));
    }

    #[test]
    fn is_loopback_bind_rejects_non_loopback() {
        assert!(!is_loopback_bind("192.168.1.10:8200"));
        assert!(!is_loopback_bind("0.0.0.0:8200"));
        assert!(!is_loopback_bind("10.0.0.1:8200"));
    }

    #[test]
    fn client_url_maps_specific_ip() {
        assert_eq!(
            client_url_from_bind_addr("192.168.1.10:8200"),
            "https://192.168.1.10:8200"
        );
    }

    #[test]
    fn client_url_maps_wildcard_to_loopback() {
        assert_eq!(
            client_url_from_bind_addr("0.0.0.0:8200"),
            "https://127.0.0.1:8200"
        );
    }

    #[test]
    fn client_url_maps_ipv6_wildcard_to_loopback() {
        assert_eq!(client_url_from_bind_addr("[::]:8200"), "https://[::1]:8200");
        assert_eq!(
            client_url_from_bind_addr("[::0]:8200"),
            "https://[::1]:8200"
        );
    }

    #[test]
    fn client_url_maps_ipv6_specific() {
        assert_eq!(
            client_url_from_bind_addr("[fd12::1]:8200"),
            "https://[fd12::1]:8200"
        );
    }

    /// Generates a CA-signed server cert and root CA cert PEM pair.
    fn gen_ca_signed_cert_pair() -> (String, String, String) {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params =
            CertificateParams::new(vec!["root.test".to_string()]).expect("ca params");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Bootroot Root CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.clone().self_signed(&ca_key).expect("self signed");
        let root_pem = ca_cert.pem();
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let server_key = KeyPair::generate().expect("server key");
        let mut server_params =
            CertificateParams::new(vec!["server.test".to_string()]).expect("server params");
        server_params
            .distinguished_name
            .push(DnType::CommonName, "server.test");
        let server_cert = server_params
            .signed_by(&server_key, &ca_issuer)
            .expect("signed");

        (server_cert.pem(), server_key.serialize_pem(), root_pem)
    }

    /// Sets up a valid TLS test environment with proper cert chain.
    fn setup_tls_env(dir: &std::path::Path) {
        let (server_pem, server_key_pem, root_pem) = gen_ca_signed_cert_pair();

        let openbao_dir = dir.join("openbao");
        let tls_dir = openbao_dir.join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("server.crt"), &server_pem).unwrap();
        std::fs::write(tls_dir.join("server.key"), &server_key_pem).unwrap();
        std::fs::write(
            openbao_dir.join("openbao.hcl"),
            r#"listener "tcp" { tls_cert_file = "/openbao/config/tls/server.crt" tls_key_file = "/openbao/config/tls/server.key" }"#,
        )
        .unwrap();

        let certs_dir = dir.join("secrets").join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join("root_ca.crt"), &root_pem).unwrap();
    }

    #[test]
    fn validate_openbao_tls_fails_without_cert_files() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let openbao_dir = dir.path().join("openbao");
        std::fs::create_dir_all(&openbao_dir).unwrap();
        // HCL references cert/key paths but the files don't exist.
        std::fs::write(
            openbao_dir.join("openbao.hcl"),
            r#"listener "tcp" { tls_cert_file = "/openbao/config/tls/server.crt" tls_key_file = "/openbao/config/tls/server.key" }"#,
        )
        .unwrap();
        let result = validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cert not found"), "error: {err}");
    }

    #[test]
    fn validate_openbao_tls_fails_without_tls_cert_file_reference() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        setup_tls_env(dir.path());
        // Overwrite openbao.hcl without TLS references.
        std::fs::write(
            dir.path().join("openbao").join("openbao.hcl"),
            "listener \"tcp\" { tls_disable = 1 }",
        )
        .unwrap();
        let result = validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("tls_cert_file"), "error: {err}");
    }

    #[test]
    fn validate_openbao_tls_fails_without_tls_key_file_reference() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        setup_tls_env(dir.path());
        // Overwrite openbao.hcl with only tls_cert_file (missing tls_key_file).
        std::fs::write(
            dir.path().join("openbao").join("openbao.hcl"),
            r#"listener "tcp" { tls_cert_file = "/openbao/config/tls/server.crt" }"#,
        )
        .unwrap();
        let result = validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("tls_key_file"), "error: {err}");
    }

    #[test]
    fn validate_openbao_tls_fails_with_tls_disabled() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        setup_tls_env(dir.path());
        // Overwrite openbao.hcl with tls_disable = 1 alongside cert references.
        std::fs::write(
            dir.path().join("openbao").join("openbao.hcl"),
            r#"listener "tcp" { tls_disable = 1 tls_cert_file = "/openbao/config/tls/server.crt" tls_key_file = "/openbao/config/tls/server.key" }"#,
        )
        .unwrap();
        let result = validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("tls_disable"), "error: {err}");
    }

    #[test]
    fn validate_openbao_tls_fails_with_cert_from_wrong_ca() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        setup_tls_env(dir.path());

        // Generate a server cert from a different (unrelated) CA.
        let (wrong_server_pem, wrong_server_key_pem) = {
            use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
            let wrong_ca_key = KeyPair::generate().expect("wrong ca key");
            let mut wrong_ca_params =
                CertificateParams::new(vec!["wrong.test".to_string()]).expect("params");
            wrong_ca_params
                .distinguished_name
                .push(DnType::CommonName, "Wrong CA");
            wrong_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let _wrong_ca_cert = wrong_ca_params
                .clone()
                .self_signed(&wrong_ca_key)
                .expect("wrong ca self signed");
            let wrong_ca_issuer = Issuer::new(wrong_ca_params, wrong_ca_key);

            let server_key = KeyPair::generate().expect("server key");
            let mut server_params =
                CertificateParams::new(vec!["server.test".to_string()]).expect("params");
            server_params
                .distinguished_name
                .push(DnType::CommonName, "server.test");
            let server_cert = server_params
                .signed_by(&server_key, &wrong_ca_issuer)
                .expect("signed by wrong ca");
            (server_cert.pem(), server_key.serialize_pem())
        };

        // Overwrite the server cert with the wrong-CA cert.
        let tls_dir = dir.path().join("openbao").join("tls");
        std::fs::write(tls_dir.join("server.crt"), &wrong_server_pem).unwrap();
        std::fs::write(tls_dir.join("server.key"), &wrong_server_key_pem).unwrap();

        let result = validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("chain validation failed"), "error: {err}");
    }

    /// Regression: a cert whose issuer DN matches the root's subject DN but
    /// was signed by a different key must be rejected.  Before cryptographic
    /// signature verification was added, DN-only comparison let this through.
    #[test]
    fn validate_openbao_tls_rejects_same_dn_wrong_key_cert() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        setup_tls_env(dir.path());

        // Read the real root CA's subject DN so the impostor can copy it.
        let real_root_pem =
            std::fs::read(dir.path().join("secrets").join("certs").join("root_ca.crt")).unwrap();
        let (_, real_root_parsed) = parse_x509_pem(&real_root_pem).unwrap();
        let (_, real_root_cert) =
            x509_parser::parse_x509_certificate(&real_root_parsed.contents).unwrap();
        let real_cn = real_root_cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .unwrap();

        // Build an impostor root CA with the same CN but a different key.
        let impostor_key = KeyPair::generate().expect("impostor key");
        let mut impostor_params =
            CertificateParams::new(vec!["impostor.test".to_string()]).expect("params");
        impostor_params
            .distinguished_name
            .push(DnType::CommonName, real_cn);
        impostor_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let _impostor_ca = impostor_params
            .clone()
            .self_signed(&impostor_key)
            .expect("self signed");
        let impostor_issuer = Issuer::new(impostor_params, impostor_key);

        // Sign a server cert with the impostor CA.
        let server_key = KeyPair::generate().expect("server key");
        let mut server_params =
            CertificateParams::new(vec!["server.test".to_string()]).expect("params");
        server_params
            .distinguished_name
            .push(DnType::CommonName, "server.test");
        let server_cert = server_params
            .signed_by(&server_key, &impostor_issuer)
            .expect("signed");

        let tls_dir = dir.path().join("openbao").join("tls");
        std::fs::write(tls_dir.join("server.crt"), server_cert.pem()).unwrap();
        std::fs::write(tls_dir.join("server.key"), server_key.serialize_pem()).unwrap();

        let result = validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("chain validation failed"), "error: {err}");
    }

    #[test]
    fn validate_openbao_tls_passes_with_all_prerequisites() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        setup_tls_env(dir.path());
        assert!(validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages).is_ok());
    }

    /// Regression: a TLS-enabled `:8200` API listener plus a plaintext
    /// `:9101` telemetry listener must not be rejected.  The telemetry
    /// port is only `expose`d inside Compose, not published on the host.
    #[test]
    fn validate_openbao_tls_passes_with_plaintext_telemetry_listener() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();

        let (server_pem, server_key_pem, root_pem) = gen_ca_signed_cert_pair();

        let openbao_dir = dir.path().join("openbao");
        let tls_dir = openbao_dir.join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("server.crt"), &server_pem).unwrap();
        std::fs::write(tls_dir.join("server.key"), &server_key_pem).unwrap();

        std::fs::write(
            openbao_dir.join("openbao.hcl"),
            r#"listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/openbao/config/tls/server.crt"
  tls_key_file  = "/openbao/config/tls/server.key"
}

listener "tcp" {
  address = "0.0.0.0:9101"
  tls_disable = 1
  telemetry {
    metrics_only = true
  }
}
"#,
        )
        .unwrap();

        let certs_dir = dir.path().join("secrets").join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join("root_ca.crt"), &root_pem).unwrap();

        assert!(
            validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages).is_ok(),
            "TLS-enabled API listener with plaintext telemetry listener must pass"
        );
    }

    /// Regression: a plaintext `:8200` API listener plus a TLS-enabled
    /// listener on a different port must be rejected.  The TLS gate must
    /// check the listener actually serving the API port, not just the
    /// first block that happens to have `tls_cert_file`.
    #[test]
    fn validate_openbao_tls_rejects_plaintext_api_with_tls_on_other_port() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();

        let (server_pem, server_key_pem, root_pem) = gen_ca_signed_cert_pair();

        let openbao_dir = dir.path().join("openbao");
        let tls_dir = openbao_dir.join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("server.crt"), &server_pem).unwrap();
        std::fs::write(tls_dir.join("server.key"), &server_key_pem).unwrap();

        // API listener on :8200 is plaintext, TLS only on :9443.
        std::fs::write(
            openbao_dir.join("openbao.hcl"),
            r#"listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = 1
}

listener "tcp" {
  address = "0.0.0.0:9443"
  tls_cert_file = "/openbao/config/tls/server.crt"
  tls_key_file  = "/openbao/config/tls/server.key"
}
"#,
        )
        .unwrap();

        let certs_dir = dir.path().join("secrets").join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join("root_ca.crt"), &root_pem).unwrap();

        let result = validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages);
        assert!(
            result.is_err(),
            "plaintext API listener on :8200 must be rejected even when another port has TLS"
        );
    }

    #[test]
    fn has_tls_disabled_detects_variants() {
        assert!(has_tls_disabled("tls_disable = 1"));
        assert!(has_tls_disabled("  tls_disable = 1"));
        assert!(has_tls_disabled("tls_disable = true"));
        assert!(has_tls_disabled("tls_disable = \"1\""));
        assert!(has_tls_disabled("tls_disable = TRUE"));
    }

    #[test]
    fn has_tls_disabled_ignores_disabled_tls_disable() {
        assert!(!has_tls_disabled("tls_disable = 0"));
        assert!(!has_tls_disabled("tls_disable = false"));
        assert!(!has_tls_disabled("# tls_disable = 1"));
        assert!(!has_tls_disabled("// tls_disable = 1"));
    }

    /// Regression: `tls_disable = 1` inside a trailing comment must not
    /// trip the disable check.
    #[test]
    fn has_tls_disabled_ignores_trailing_comment() {
        assert!(!has_tls_disabled(
            r#"address = "0.0.0.0:8200" # tls_disable = 1"#
        ));
        assert!(!has_tls_disabled(
            r#"address = "0.0.0.0:8200" // tls_disable = 1"#
        ));
    }

    /// Regression: a real `tls_disable = 1` with an unrelated trailing
    /// comment must still be detected.
    #[test]
    fn has_tls_disabled_real_key_with_trailing_comment() {
        assert!(has_tls_disabled("tls_disable = 1 # some note"));
        assert!(has_tls_disabled("tls_disable = true // legacy"));
    }

    /// Regression: `tls_cert_file` inside a trailing comment must not
    /// satisfy the cert-path check.
    #[test]
    fn parse_hcl_string_value_ignores_trailing_comment() {
        let content =
            r#"address = "0.0.0.0:8200" # tls_cert_file = "/openbao/config/tls/server.crt""#;
        assert!(parse_hcl_string_value(content, "tls_cert_file").is_none());
    }

    /// Regression: a real `tls_cert_file` with a trailing comment must
    /// still be parsed correctly.
    #[test]
    fn parse_hcl_string_value_real_key_with_trailing_comment() {
        let content = r#"tls_cert_file = "/openbao/config/tls/server.crt" # path to cert"#;
        assert_eq!(
            parse_hcl_string_value(content, "tls_cert_file"),
            Some("/openbao/config/tls/server.crt")
        );
    }

    #[test]
    fn write_openbao_exposed_override_creates_file() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let result = write_openbao_exposed_override(dir.path(), "192.168.1.10:8200", &messages);
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("192.168.1.10:8200:8200"));
        assert!(content.contains("!reset"));
    }

    #[test]
    fn validate_openbao_tls_fails_when_hcl_points_to_different_cert() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        setup_tls_env(dir.path());
        // Point HCL at a different cert path that doesn't exist on host.
        std::fs::write(
            dir.path().join("openbao").join("openbao.hcl"),
            r#"listener "tcp" { tls_cert_file = "/openbao/config/tls/other.crt" tls_key_file = "/openbao/config/tls/other.key" }"#,
        )
        .unwrap();
        let result = validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cert not found"), "error: {err}");
    }

    #[test]
    fn validate_openbao_tls_fails_when_hcl_has_unmappable_cert_path() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        setup_tls_env(dir.path());
        // Point HCL at a path that can't be mapped to host.
        std::fs::write(
            dir.path().join("openbao").join("openbao.hcl"),
            r#"listener "tcp" { tls_cert_file = "/some/other/cert.pem" tls_key_file = "/some/other/key.pem" }"#,
        )
        .unwrap();
        let result = validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cannot be resolved to host"), "error: {err}");
    }

    #[test]
    fn detects_unsafe_port_binding_with_reset_tag() {
        let compose = "\
services:
  postgres:
    ports: !reset
      - \"0.0.0.0:5432:5432\"
";
        assert!(has_unsafe_port_binding_for_service(compose, "postgres:"));
    }

    /// Regression: an inline YAML array in an override must also be
    /// caught by `validate_openbao_override_scope`.
    #[test]
    fn validate_override_scope_rejects_inline_array_postgres() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let override_path = dir.path().join("override.yml");
        std::fs::write(
            &override_path,
            "\
services:
  openbao:
    ports: !reset
      - \"192.168.1.10:8200:8200\"
  postgres:
    ports: [\"5432\"]
",
        )
        .unwrap();
        let result = validate_openbao_override_scope(&override_path, &messages);
        assert!(result.is_err());
    }

    #[test]
    fn validate_override_scope_rejects_postgres_non_loopback() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let override_path = dir.path().join("override.yml");
        std::fs::write(
            &override_path,
            "\
services:
  openbao:
    ports: !reset
      - \"192.168.1.10:8200:8200\"
  postgres:
    ports: !reset
      - \"0.0.0.0:5432:5432\"
",
        )
        .unwrap();
        let result = validate_openbao_override_scope(&override_path, &messages);
        assert!(result.is_err());
    }

    #[test]
    fn validate_override_scope_accepts_openbao_only() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let override_path = dir.path().join("override.yml");
        std::fs::write(
            &override_path,
            "\
services:
  openbao:
    ports: !reset
      - \"192.168.1.10:8200:8200\"
",
        )
        .unwrap();
        let result = validate_openbao_override_scope(&override_path, &messages);
        assert!(result.is_ok());
    }

    #[test]
    fn validate_override_binding_accepts_matching_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let override_path = dir.path().join("override.yml");
        std::fs::write(
            &override_path,
            "\
services:
  openbao:
    ports: !reset
      - \"192.168.1.10:8200:8200\"
",
        )
        .unwrap();
        assert!(
            validate_openbao_override_binding(&override_path, "192.168.1.10:8200", &messages)
                .is_ok()
        );
    }

    /// Regression: an override manually edited to widen the binding to
    /// `0.0.0.0` must be rejected when state records a specific IP,
    /// preventing wildcard-confirmation bypass.
    #[test]
    fn validate_override_binding_rejects_widened_wildcard() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let override_path = dir.path().join("override.yml");
        std::fs::write(
            &override_path,
            "\
services:
  openbao:
    ports: !reset
      - \"0.0.0.0:8200:8200\"
",
        )
        .unwrap();
        let result =
            validate_openbao_override_binding(&override_path, "192.168.1.10:8200", &messages);
        assert!(result.is_err(), "widened wildcard must be rejected");
    }

    /// Regression: an override edited to change the host port must be
    /// rejected.
    #[test]
    fn validate_override_binding_rejects_changed_port() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let override_path = dir.path().join("override.yml");
        std::fs::write(
            &override_path,
            "\
services:
  openbao:
    ports: !reset
      - \"192.168.1.10:9200:8200\"
",
        )
        .unwrap();
        let result =
            validate_openbao_override_binding(&override_path, "192.168.1.10:8200", &messages);
        assert!(result.is_err(), "changed host port must be rejected");
    }

    #[test]
    fn validate_override_binding_rejects_empty_ports() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let override_path = dir.path().join("override.yml");
        std::fs::write(
            &override_path,
            "\
services:
  openbao:
    ports: !reset
",
        )
        .unwrap();
        let result =
            validate_openbao_override_binding(&override_path, "192.168.1.10:8200", &messages);
        assert!(result.is_err(), "override with no port mappings must fail");
    }

    #[test]
    fn validate_override_binding_accepts_ipv6() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let override_path = dir.path().join("override.yml");
        std::fs::write(
            &override_path,
            "\
services:
  openbao:
    ports: !reset
      - \"[fd12::1]:8200:8200\"
",
        )
        .unwrap();
        assert!(
            validate_openbao_override_binding(&override_path, "[fd12::1]:8200", &messages).is_ok()
        );
    }

    /// Regression: `validate_openbao_tls` must find the step-ca root CA
    /// under the actual secrets directory, not a hardcoded
    /// `compose_dir/secrets` path.
    #[test]
    fn validate_openbao_tls_custom_secrets_dir() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();

        // Place TLS cert/key and openbao.hcl under compose_dir as usual.
        let (server_pem, server_key_pem, root_pem) = gen_ca_signed_cert_pair();
        let openbao_dir = dir.path().join("openbao");
        let tls_dir = openbao_dir.join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("server.crt"), &server_pem).unwrap();
        std::fs::write(tls_dir.join("server.key"), &server_key_pem).unwrap();
        std::fs::write(
            openbao_dir.join("openbao.hcl"),
            r#"listener "tcp" { tls_cert_file = "/openbao/config/tls/server.crt" tls_key_file = "/openbao/config/tls/server.key" }"#,
        )
        .unwrap();

        // Place the step-ca root CA under a CUSTOM secrets directory,
        // NOT under compose_dir/secrets.
        let custom_secrets = dir.path().join("custom-secrets");
        let certs_dir = custom_secrets.join(CA_CERTS_DIR);
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join(CA_ROOT_CERT_FILENAME), &root_pem).unwrap();

        // Validation must pass with the custom secrets dir.
        assert!(
            validate_openbao_tls(dir.path(), &custom_secrets, &messages).is_ok(),
            "TLS validation must succeed with custom secrets dir"
        );

        // Validation must FAIL when using the default (compose_dir/secrets)
        // because the root CA is not there.
        let result = validate_openbao_tls(dir.path(), &dir.path().join("secrets"), &messages);
        assert!(
            result.is_err(),
            "must fail when root CA is at custom path but secrets_dir points to default"
        );
    }

    #[test]
    fn extract_listener_blocks_handles_multiple_blocks() {
        let content = r#"
storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_cert_file = "/openbao/config/tls/server.crt"
}

listener "tcp" {
  address = "0.0.0.0:9101"
  tls_disable = 1
  telemetry {
    metrics_only = true
  }
}
"#;
        let blocks = extract_listener_blocks(content);
        assert_eq!(blocks.len(), 2);
        assert!(blocks.first().unwrap().contains("8200"));
        assert!(blocks.get(1).unwrap().contains("9101"));
    }

    #[test]
    fn extract_listener_blocks_handles_single_line() {
        let content = r#"listener "tcp" { tls_cert_file = "/openbao/config/tls/server.crt" tls_key_file = "/openbao/config/tls/server.key" }"#;
        let blocks = extract_listener_blocks(content);
        assert_eq!(blocks.len(), 1);
        assert!(blocks.first().unwrap().contains("tls_cert_file"));
    }

    #[test]
    fn find_api_listener_selects_port_8200() {
        let blocks = vec![
            "listener \"tcp\" {\n  address = \"0.0.0.0:9101\"\n  tls_disable = 1\n}\n"
                .to_string(),
            "listener \"tcp\" {\n  address = \"0.0.0.0:8200\"\n  tls_cert_file = \"/openbao/config/tls/server.crt\"\n}\n".to_string(),
        ];
        let found = find_api_listener_block(&blocks);
        assert!(found.is_some());
        assert!(found.unwrap().contains("8200"));
    }

    #[test]
    fn find_api_listener_falls_back_to_sole_block_without_address() {
        let blocks = vec![
            "listener \"tcp\" { tls_cert_file = \"/openbao/config/tls/server.crt\" }".to_string(),
        ];
        let found = find_api_listener_block(&blocks);
        assert!(found.is_some());
        assert!(found.unwrap().contains("tls_cert_file"));
    }

    /// Regression: a default API listener (no explicit `address`) alongside
    /// a plaintext telemetry listener must be identified as the API block,
    /// so `validate_openbao_tls` does not false-reject the telemetry
    /// listener's `tls_disable = 1`.
    #[test]
    fn find_api_listener_selects_default_addr_alongside_telemetry() {
        let blocks = vec![
            "listener \"tcp\" {\n  tls_cert_file = \"/openbao/config/tls/server.crt\"\n}\n"
                .to_string(),
            "listener \"tcp\" {\n  address = \"0.0.0.0:9101\"\n  tls_disable = 1\n}\n".to_string(),
        ];
        let found = find_api_listener_block(&blocks);
        assert!(
            found.is_some(),
            "default listener must be selected as API block"
        );
        assert!(
            found.unwrap().contains("tls_cert_file"),
            "must select the no-address block, not the telemetry block"
        );
    }

    #[test]
    fn find_api_listener_returns_none_when_no_8200() {
        let blocks = vec![
            "listener \"tcp\" {\n  address = \"0.0.0.0:9101\"\n  tls_disable = 1\n}\n"
                .to_string(),
            "listener \"tcp\" {\n  address = \"0.0.0.0:9443\"\n  tls_cert_file = \"/openbao/config/tls/server.crt\"\n}\n".to_string(),
        ];
        let found = find_api_listener_block(&blocks);
        assert!(found.is_none());
    }

    #[test]
    fn is_wildcard_bind_detects_wildcard_addresses() {
        assert!(is_wildcard_bind("0.0.0.0:8200"));
        assert!(is_wildcard_bind("[::]:8200"));
        assert!(is_wildcard_bind("[::0]:8200"));
    }

    #[test]
    fn is_wildcard_bind_rejects_non_wildcard() {
        assert!(!is_wildcard_bind("192.168.1.10:8200"));
        assert!(!is_wildcard_bind("127.0.0.1:8200"));
        assert!(!is_wildcard_bind("[::1]:8200"));
        assert!(!is_wildcard_bind("[fd12::1]:8200"));
    }

    #[test]
    fn validate_advertise_addr_accepts_specific_ip() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_advertise_addr("192.168.1.10:8200", &messages).is_ok());
        assert!(validate_openbao_advertise_addr("[fd12::1]:8200", &messages).is_ok());
    }

    #[test]
    fn validate_advertise_addr_rejects_wildcard() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_advertise_addr("0.0.0.0:8200", &messages).is_err());
        assert!(validate_openbao_advertise_addr("[::]:8200", &messages).is_err());
    }

    #[test]
    fn validate_advertise_addr_rejects_loopback() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_advertise_addr("127.0.0.1:8200", &messages).is_err());
        assert!(validate_openbao_advertise_addr("[::1]:8200", &messages).is_err());
    }

    #[test]
    fn validate_advertise_addr_rejects_malformed() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_advertise_addr("not-an-addr", &messages).is_err());
        assert!(validate_openbao_advertise_addr(":8200", &messages).is_err());
        assert!(validate_openbao_advertise_addr("192.168.1.10:", &messages).is_err());
    }

    /// Regression: port 0 parses as valid `u16` but produces an unusable
    /// endpoint, so the advertise-addr validator must reject it.
    #[test]
    fn validate_advertise_addr_rejects_port_zero() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_advertise_addr("192.168.1.10:0", &messages).is_err());
        assert!(validate_openbao_advertise_addr("[fd12::1]:0", &messages).is_err());
    }

    /// Regression: bare IPv6 like `fd12::1:8200` is ambiguous and
    /// produces an invalid URL (`https://fd12::1:8200`).  The validator
    /// must require brackets like `[fd12::1]:8200`.
    #[test]
    fn validate_advertise_addr_rejects_bare_ipv6() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_advertise_addr("fd12::1:8200", &messages).is_err());
        assert!(validate_openbao_advertise_addr("2001:db8::10:8200", &messages).is_err());
    }

    #[test]
    fn validate_advertise_addr_accepts_bracketed_ipv6() {
        let messages = crate::i18n::test_messages();
        assert!(validate_openbao_advertise_addr("[fd12::1]:8200", &messages).is_ok());
        assert!(validate_openbao_advertise_addr("[2001:db8::10]:8200", &messages).is_ok());
    }

    /// Regression (#508): `--openbao-advertise-addr` must be rejected
    /// for specific-IP binds so that a bogus advertise value cannot
    /// sneak into `StateFile` and later corrupt remote bootstrap
    /// artifacts.
    #[test]
    fn reject_advertise_addr_for_specific_ip_bind() {
        let messages = crate::i18n::test_messages();
        assert!(
            reject_advertise_addr_for_specific_bind(
                "10.0.0.5:8200",
                Some("not-an-addr"),
                &messages,
            )
            .is_err()
        );
        assert!(
            reject_advertise_addr_for_specific_bind(
                "192.168.1.10:8200",
                Some("192.168.1.20:8200"),
                &messages,
            )
            .is_err()
        );
        assert!(
            reject_advertise_addr_for_specific_bind(
                "[fd12::1]:8200",
                Some("10.0.0.5:8200"),
                &messages,
            )
            .is_err()
        );
    }

    #[test]
    fn allow_advertise_addr_for_wildcard_bind() {
        let messages = crate::i18n::test_messages();
        assert!(
            reject_advertise_addr_for_specific_bind(
                "0.0.0.0:8200",
                Some("10.0.0.5:8200"),
                &messages,
            )
            .is_ok()
        );
        assert!(
            reject_advertise_addr_for_specific_bind(
                "[::]:8200",
                Some("[fd12::1]:8200"),
                &messages,
            )
            .is_ok()
        );
    }

    #[test]
    fn allow_no_advertise_addr_for_specific_bind() {
        let messages = crate::i18n::test_messages();
        assert!(reject_advertise_addr_for_specific_bind("10.0.0.5:8200", None, &messages).is_ok());
    }

    /// Explicit loopback binds are specific-IP binds, so
    /// `--openbao-advertise-addr` must be rejected for them too.
    #[test]
    fn reject_advertise_addr_for_explicit_loopback_bind() {
        let messages = crate::i18n::test_messages();
        assert!(
            reject_advertise_addr_for_specific_bind(
                "127.0.0.1:8200",
                Some("192.168.1.10:8200"),
                &messages,
            )
            .is_err()
        );
        assert!(
            reject_advertise_addr_for_specific_bind(
                "[::1]:8200",
                Some("[fd12::1]:8200"),
                &messages,
            )
            .is_err()
        );
    }

    // --- HTTP-01 admin bind validation ---

    #[test]
    fn validate_http01_admin_bind_accepts_specific_ip() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_bind("192.168.1.10:8080", false, &messages).is_ok());
    }

    #[test]
    fn validate_http01_admin_bind_rejects_missing_port() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_bind("192.168.1.10", false, &messages).is_err());
    }

    #[test]
    fn validate_http01_admin_bind_rejects_port_zero() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_bind("192.168.1.10:0", false, &messages).is_err());
    }

    #[test]
    fn validate_http01_admin_bind_rejects_wildcard_without_flag() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_bind("0.0.0.0:8080", false, &messages).is_err());
    }

    #[test]
    fn validate_http01_admin_bind_accepts_wildcard_with_flag() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_bind("0.0.0.0:8080", true, &messages).is_ok());
    }

    #[test]
    fn validate_http01_admin_bind_rejects_bare_ipv6() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_bind("::1:8080", false, &messages).is_err());
    }

    #[test]
    fn validate_http01_admin_bind_accepts_bracketed_ipv6() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_bind("[::1]:8080", false, &messages).is_ok());
    }

    // --- HTTP-01 admin advertise-addr validation ---

    #[test]
    fn validate_http01_admin_advertise_addr_accepts_specific_ip() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_advertise_addr("192.168.1.10:8080", &messages).is_ok());
        assert!(validate_http01_admin_advertise_addr("[fd12::1]:8080", &messages).is_ok());
    }

    #[test]
    fn validate_http01_admin_advertise_addr_rejects_wildcard() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_advertise_addr("0.0.0.0:8080", &messages).is_err());
        assert!(validate_http01_admin_advertise_addr("[::]:8080", &messages).is_err());
    }

    #[test]
    fn validate_http01_admin_advertise_addr_rejects_loopback() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_advertise_addr("127.0.0.1:8080", &messages).is_err());
        assert!(validate_http01_admin_advertise_addr("[::1]:8080", &messages).is_err());
    }

    #[test]
    fn validate_http01_admin_advertise_addr_rejects_malformed() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_advertise_addr("not-an-addr", &messages).is_err());
        assert!(validate_http01_admin_advertise_addr(":8080", &messages).is_err());
        assert!(validate_http01_admin_advertise_addr("192.168.1.10:", &messages).is_err());
    }

    #[test]
    fn validate_http01_admin_advertise_addr_rejects_port_zero() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_advertise_addr("192.168.1.10:0", &messages).is_err());
    }

    #[test]
    fn validate_http01_admin_advertise_addr_rejects_bare_ipv6() {
        let messages = crate::i18n::test_messages();
        assert!(validate_http01_admin_advertise_addr("fd12::1:8080", &messages).is_err());
    }

    #[test]
    fn reject_http01_admin_advertise_addr_for_specific_ip_bind() {
        let messages = crate::i18n::test_messages();
        assert!(
            reject_http01_admin_advertise_addr_for_specific_bind(
                "192.168.1.10:8080",
                Some("10.0.0.5:8080"),
                &messages,
            )
            .is_err()
        );
    }

    #[test]
    fn allow_http01_admin_advertise_addr_for_wildcard_bind() {
        let messages = crate::i18n::test_messages();
        assert!(
            reject_http01_admin_advertise_addr_for_specific_bind(
                "0.0.0.0:8080",
                Some("10.0.0.5:8080"),
                &messages,
            )
            .is_ok()
        );
    }

    #[test]
    fn allow_no_http01_admin_advertise_addr_for_specific_bind() {
        let messages = crate::i18n::test_messages();
        assert!(
            reject_http01_admin_advertise_addr_for_specific_bind("10.0.0.5:8080", None, &messages,)
                .is_ok()
        );
    }

    // --- HTTP-01 override writing and validation ---

    #[test]
    fn write_http01_override_creates_file() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let path =
            write_http01_exposed_override(dir.path(), "192.168.1.10:8080", &messages).unwrap();
        assert!(path.exists());
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("192.168.1.10:8080:8080"));
        assert!(content.contains("bootroot-http01"));
    }

    #[test]
    fn validate_http01_override_binding_accepts_matching_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let path =
            write_http01_exposed_override(dir.path(), "192.168.1.10:8080", &messages).unwrap();
        assert!(validate_http01_override_binding(&path, "192.168.1.10:8080", &messages).is_ok());
    }

    #[test]
    fn validate_http01_override_binding_rejects_mismatched_addr() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let path =
            write_http01_exposed_override(dir.path(), "192.168.1.10:8080", &messages).unwrap();
        let result = validate_http01_override_binding(&path, "10.0.0.5:8080", &messages);
        assert!(result.is_err());
    }

    #[test]
    fn validate_http01_override_scope_rejects_extra_services() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let override_dir = dir.path().join("secrets").join("responder");
        std::fs::create_dir_all(&override_dir).unwrap();
        let path = override_dir.join(HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME);
        std::fs::write(
            &path,
            "\
services:
  bootroot-http01:
    ports: !reset
      - \"192.168.1.10:8080:8080\"
  openbao:
    ports:
      - \"0.0.0.0:8200:8200\"
",
        )
        .unwrap();
        assert!(validate_http01_override_scope(&path, &messages).is_err());
    }

    // --- HTTP-01 admin TLS validation ---

    #[test]
    fn validate_http01_admin_tls_fails_without_config() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();
        let result = validate_http01_admin_tls(&secrets_dir, &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("responder config not found"), "error: {err}");
    }

    #[test]
    fn validate_http01_admin_tls_fails_without_tls_paths() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let responder_dir = secrets_dir.join("responder");
        std::fs::create_dir_all(&responder_dir).unwrap();
        std::fs::write(
            responder_dir.join("responder.toml"),
            "hmac_secret = \"test\"\n",
        )
        .unwrap();
        let result = validate_http01_admin_tls(&secrets_dir, &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("tls_cert_path"), "error: {err}");
    }

    #[test]
    fn validate_http01_admin_tls_fails_with_missing_cert_files() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let responder_dir = secrets_dir.join("responder");
        std::fs::create_dir_all(&responder_dir).unwrap();
        std::fs::write(
            responder_dir.join("responder.toml"),
            "\
hmac_secret = \"test\"
tls_cert_path = \"/app/bootroot-http01/tls/server.crt\"
tls_key_path = \"/app/bootroot-http01/tls/server.key\"
",
        )
        .unwrap();
        let result = validate_http01_admin_tls(&secrets_dir, &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("cert not found"), "error: {err}");
    }

    #[test]
    fn validate_http01_admin_tls_passes_with_valid_certs() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let responder_dir = secrets_dir.join("responder");
        let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::create_dir_all(&responder_dir).unwrap();

        let (server_pem, server_key_pem, root_pem) = gen_ca_signed_cert_pair();
        std::fs::write(tls_dir.join("server.crt"), &server_pem).unwrap();
        std::fs::write(tls_dir.join("server.key"), &server_key_pem).unwrap();

        let certs_dir = secrets_dir.join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join("root_ca.crt"), &root_pem).unwrap();

        std::fs::write(
            responder_dir.join("responder.toml"),
            "\
hmac_secret = \"test\"
tls_cert_path = \"/app/bootroot-http01/tls/server.crt\"
tls_key_path = \"/app/bootroot-http01/tls/server.key\"
",
        )
        .unwrap();
        assert!(validate_http01_admin_tls(&secrets_dir, &messages).is_ok());
    }

    #[test]
    fn validate_http01_admin_tls_fails_with_cert_from_wrong_ca() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let responder_dir = secrets_dir.join("responder");
        let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::create_dir_all(&responder_dir).unwrap();

        // Generate a CA and its root cert for the step-ca trust anchor.
        let real_ca_key = KeyPair::generate().unwrap();
        let mut real_ca_params = CertificateParams::new(vec!["root.test".to_string()]).unwrap();
        real_ca_params
            .distinguished_name
            .push(DnType::CommonName, "Bootroot Root CA");
        real_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let real_ca_cert = real_ca_params.self_signed(&real_ca_key).unwrap();

        // Generate a server cert from a DIFFERENT CA (not the step-ca root).
        let wrong_ca_key = KeyPair::generate().unwrap();
        let mut wrong_ca_params = CertificateParams::new(vec!["wrong.test".to_string()]).unwrap();
        wrong_ca_params
            .distinguished_name
            .push(DnType::CommonName, "Wrong CA");
        wrong_ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let _wrong_ca_cert = wrong_ca_params.clone().self_signed(&wrong_ca_key).unwrap();
        let wrong_ca_issuer = Issuer::new(wrong_ca_params, wrong_ca_key);

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["server.test".to_string()]).unwrap();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "server.test");
        let server_cert = server_params
            .signed_by(&server_key, &wrong_ca_issuer)
            .unwrap();

        std::fs::write(tls_dir.join("server.crt"), server_cert.pem()).unwrap();
        std::fs::write(tls_dir.join("server.key"), server_key.serialize_pem()).unwrap();

        // Write step-ca root CA cert (the real one).
        let certs_dir = secrets_dir.join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join("root_ca.crt"), real_ca_cert.pem()).unwrap();

        std::fs::write(
            responder_dir.join("responder.toml"),
            "\
hmac_secret = \"test\"
tls_cert_path = \"/app/bootroot-http01/tls/server.crt\"
tls_key_path = \"/app/bootroot-http01/tls/server.key\"
",
        )
        .unwrap();

        let result = validate_http01_admin_tls(&secrets_dir, &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("chain validation failed"), "error: {err}");
    }

    #[test]
    fn validate_http01_admin_tls_fails_with_garbage_key_material() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let responder_dir = secrets_dir.join("responder");
        let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::create_dir_all(&responder_dir).unwrap();

        let (server_pem, _, root_pem) = gen_ca_signed_cert_pair();
        std::fs::write(tls_dir.join("server.crt"), &server_pem).unwrap();
        std::fs::write(tls_dir.join("server.key"), b"NOT A VALID PEM KEY").unwrap();

        let certs_dir = secrets_dir.join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join("root_ca.crt"), &root_pem).unwrap();

        std::fs::write(
            responder_dir.join("responder.toml"),
            "\
hmac_secret = \"test\"
tls_cert_path = \"/app/bootroot-http01/tls/server.crt\"
tls_key_path = \"/app/bootroot-http01/tls/server.key\"
",
        )
        .unwrap();
        let result = validate_http01_admin_tls(&secrets_dir, &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("TLS key material not loadable"),
            "error: {err}"
        );
    }

    #[test]
    fn validate_http01_admin_tls_fails_with_mismatched_cert_and_key() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let responder_dir = secrets_dir.join("responder");
        let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::create_dir_all(&responder_dir).unwrap();

        // Generate a CA and a server cert signed by it.
        let ca_key = KeyPair::generate().unwrap();
        let mut ca_params = CertificateParams::new(vec!["root.test".to_string()]).unwrap();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Bootroot Root CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params.clone().self_signed(&ca_key).unwrap();
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let server_key = KeyPair::generate().unwrap();
        let mut server_params = CertificateParams::new(vec!["server.test".to_string()]).unwrap();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "server.test");
        let server_cert = server_params.signed_by(&server_key, &ca_issuer).unwrap();

        // Generate a DIFFERENT key that does NOT match the cert.
        let wrong_key = KeyPair::generate().unwrap();

        std::fs::write(tls_dir.join("server.crt"), server_cert.pem()).unwrap();
        std::fs::write(tls_dir.join("server.key"), wrong_key.serialize_pem()).unwrap();

        let certs_dir = secrets_dir.join("certs");
        std::fs::create_dir_all(&certs_dir).unwrap();
        std::fs::write(certs_dir.join("root_ca.crt"), ca_cert.pem()).unwrap();

        std::fs::write(
            responder_dir.join("responder.toml"),
            "\
hmac_secret = \"test\"
tls_cert_path = \"/app/bootroot-http01/tls/server.crt\"
tls_key_path = \"/app/bootroot-http01/tls/server.key\"
",
        )
        .unwrap();
        let result = validate_http01_admin_tls(&secrets_dir, &messages);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("does not match the leaf certificate"),
            "error: {err}"
        );
    }

    #[test]
    fn resolve_responder_container_path_strips_config_prefix() {
        let secrets = Path::new("/tmp/secrets");
        let result = resolve_responder_container_path("/app/responder/responder.toml", secrets);
        assert_eq!(
            result,
            Some(PathBuf::from("/tmp/secrets/responder/responder.toml"))
        );
    }

    #[test]
    fn resolve_responder_container_path_strips_http01_tls_prefix() {
        let secrets = Path::new("/tmp/secrets");
        let result =
            resolve_responder_container_path("/app/bootroot-http01/tls/server.crt", secrets);
        assert_eq!(
            result,
            Some(PathBuf::from("/tmp/secrets/bootroot-http01/tls/server.crt"))
        );
    }

    #[test]
    fn resolve_responder_container_path_returns_none_for_other_prefix() {
        let secrets = Path::new("/tmp/secrets");
        assert!(resolve_responder_container_path("/other/path", secrets).is_none());
    }
}
