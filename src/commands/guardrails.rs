use std::fs;
use std::path::Path;

use anyhow::{Context, Result};

use crate::i18n::Messages;

const LOCAL_DB_HOSTS: [&str; 4] = ["postgres", "localhost", "127.0.0.1", "::1"];

/// Compose service names that must bind their published ports to localhost.
const GUARDED_SERVICES: [&str; 4] = ["postgres:", "openbao:", "bootroot-http01:", "grafana:"];

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

        if !in_ports && trimmed == "ports:" {
            in_ports = true;
            ports_indent = indent;
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

fn is_unsafe_port_mapping(raw: &str) -> bool {
    let mapping = raw.trim_matches('"').trim_matches('\'');
    if mapping.is_empty() {
        return false;
    }
    if mapping.starts_with("127.0.0.1:")
        || mapping.starts_with("localhost:")
        || mapping.starts_with("[::1]:")
    {
        return false;
    }

    // If a mapping has at least one `:` separator but does not begin with a
    // localhost bind, it is unsafe for this guardrail.
    let colon_count = mapping.matches(':').count();
    colon_count >= 1
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
    image: postgres:16
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
    image: postgres:16
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
    image: postgres:16
    ports:
      - "0.0.0.0:5432:5432"
"#;
        assert!(has_unsafe_port_binding_for_service(compose, "postgres:"));
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
    fn detects_unsafe_grafana_port_binding() {
        let compose = r#"
services:
  grafana:
    image: grafana/grafana:latest
    ports:
      - "0.0.0.0:3000:3000"
"#;
        assert!(has_unsafe_port_binding_for_service(compose, "grafana:"));
    }

    #[test]
    fn accepts_safe_grafana_with_env_var_bind() {
        let compose = r#"
services:
  grafana:
    image: grafana/grafana:latest
    ports:
      - "127.0.0.1:3000:3000"
"#;
        assert!(!has_unsafe_port_binding_for_service(compose, "grafana:"));
    }
}
