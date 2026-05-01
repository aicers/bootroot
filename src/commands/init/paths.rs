use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::constants::{
    DEFAULT_RESPONDER_ADMIN_URL, OPENBAO_CONTAINER_NAME, RESPONDER_CONFIG_DIR,
    RESPONDER_CONFIG_NAME,
};
use crate::cli::args::InitArgs;
use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::guardrails::parse_hcl_string_value;
use crate::i18n::Messages;

pub(crate) struct ResponderPaths {
    pub(crate) template_path: PathBuf,
    pub(crate) config_path: PathBuf,
}

pub(crate) struct StepCaTemplatePaths {
    pub(crate) password_template_path: PathBuf,
    pub(crate) ca_json_template_path: PathBuf,
}

pub(crate) struct OpenBaoAgentPaths {
    pub(crate) stepca_agent_config: PathBuf,
    pub(crate) responder_agent_config: PathBuf,
    pub(crate) compose_override_path: Option<PathBuf>,
}

/// Resolves a host path to its container-internal equivalent.
///
/// Strips the `secrets_dir` prefix and prepends `container_mount`.
pub(crate) fn to_container_path(
    secrets_dir: &Path,
    path: &Path,
    container_mount: &str,
) -> Result<String> {
    let relative = path.strip_prefix(secrets_dir).with_context(|| {
        format!(
            "path {} is not under secrets dir {}",
            path.display(),
            secrets_dir.display()
        )
    })?;
    Ok(format!("{container_mount}/{}", relative.to_string_lossy()))
}

pub(crate) fn compose_has_responder(compose_file: &Path, messages: &Messages) -> Result<bool> {
    let compose_contents = std::fs::read_to_string(compose_file)
        .with_context(|| messages.error_read_file_failed(&compose_file.display().to_string()))?;
    Ok(compose_contents.contains(RESPONDER_SERVICE_NAME))
}

pub(crate) fn compose_has_openbao(compose_file: &Path, messages: &Messages) -> Result<bool> {
    let compose_contents = std::fs::read_to_string(compose_file)
        .with_context(|| messages.error_read_file_failed(&compose_file.display().to_string()))?;
    Ok(compose_has_top_level_service(&compose_contents, "openbao"))
}

/// Returns true when the compose document declares a top-level service
/// whose mapping key is exactly `service_name`.
///
/// Avoids substring matching on the raw file so that occurrences of the
/// name in container names, hostnames, secret names, comments, image
/// tags, or volume paths do not produce false positives. This matters
/// for `openbao` specifically because external-OpenBao deployments may
/// reference the name without declaring an `openbao:` service.
fn compose_has_top_level_service(yaml: &str, service_name: &str) -> bool {
    let mut in_services = false;
    let mut child_indent: Option<usize> = None;
    for raw_line in yaml.lines() {
        // Strip end-of-line comments. A `#` inside quoted scalars would
        // be misclassified, but compose service keys are bare
        // identifiers, so this is safe for the structural scan.
        let line = raw_line.split('#').next().unwrap_or("");
        if line.trim().is_empty() {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent == 0 {
            in_services = line.trim_start().starts_with("services:");
            child_indent = None;
            continue;
        }
        if !in_services {
            continue;
        }
        let key_indent = *child_indent.get_or_insert(indent);
        if indent != key_indent {
            continue;
        }
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix(service_name)
            && rest.starts_with(':')
        {
            return true;
        }
    }
    false
}

/// Resolves the responder admin URL, selecting `https://` when TLS is
/// configured in the responder's `responder.toml`.
///
/// Uses the init-time `secrets_dir` from `InitArgs` to locate the
/// responder config, so the scheme decision is correct even on first
/// init with a non-default `--secrets-dir` (where the state file may
/// not yet carry the final `secrets_dir` value).
pub(crate) fn resolve_responder_url(
    args: &InitArgs,
    compose_has_responder: bool,
) -> Result<Option<String>> {
    if let Some(responder_url) = args.responder_url.as_ref() {
        return Ok(Some(responder_url.clone()));
    }
    if !compose_has_responder {
        return Ok(None);
    }
    // When the responder has TLS paths configured, the admin API must
    // be reached via HTTPS.
    if responder_tls_configured(&args.secrets_dir.secrets_dir)? {
        Ok(Some(
            DEFAULT_RESPONDER_ADMIN_URL.replace("http://", "https://"),
        ))
    } else {
        Ok(Some(DEFAULT_RESPONDER_ADMIN_URL.to_string()))
    }
}

/// Returns whether the responder's `responder.toml` has TLS paths set.
///
/// Reads `{secrets_dir}/responder/responder.toml` and checks that both
/// `tls_cert_path` and `tls_key_path` are present.  Uses the init-time
/// secrets directory directly so the check works on first init before
/// `write_state_file` persists the final `secrets_dir`.
fn responder_tls_configured(secrets_dir: &Path) -> Result<bool> {
    let config_path = secrets_dir
        .join(RESPONDER_CONFIG_DIR)
        .join(RESPONDER_CONFIG_NAME);
    if !config_path.exists() {
        return Ok(false);
    }
    let content = std::fs::read_to_string(&config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    Ok(parse_hcl_string_value(&content, "tls_cert_path").is_some()
        && parse_hcl_string_value(&content, "tls_key_path").is_some())
}

/// Rewrites an `OpenBao` URL so that Docker-network containers can reach
/// the server via its container name.
///
/// When `compose_has_openbao` is `true`, the host portion of `openbao_url`
/// is unconditionally replaced with [`OPENBAO_CONTAINER_NAME`] while the
/// scheme and port are preserved.  This covers loopback addresses
/// (`localhost`, `127.0.0.1`) as well as specific bind IPs
/// (`192.168.1.10`) that the host uses but that are unreachable from
/// sibling containers on the Docker bridge network.
pub(crate) fn resolve_openbao_agent_addr(openbao_url: &str, compose_has_openbao: bool) -> String {
    if !compose_has_openbao {
        return openbao_url.to_string();
    }
    let Some((scheme, after_scheme)) = openbao_url.split_once("://") else {
        return openbao_url.to_string();
    };
    // For IPv6 addresses like [::1]:8200 the port follows ']:', for
    // IPv4 / hostnames like 192.168.1.10:8200 it follows ':'.
    let port = if let Some(bracket_pos) = after_scheme.find(']') {
        after_scheme.get(bracket_pos + 2..)
    } else {
        after_scheme.split_once(':').map(|(_, p)| p)
    };
    match port {
        Some(p) => format!("{scheme}://{OPENBAO_CONTAINER_NAME}:{p}"),
        None => format!("{scheme}://{OPENBAO_CONTAINER_NAME}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responder_tls_configured_returns_true_when_config_has_tls_paths() {
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
        assert!(responder_tls_configured(&secrets_dir).unwrap());
    }

    #[test]
    fn responder_tls_configured_returns_false_when_config_has_no_tls() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let responder_dir = secrets_dir.join("responder");
        std::fs::create_dir_all(&responder_dir).unwrap();
        std::fs::write(
            responder_dir.join("responder.toml"),
            "hmac_secret = \"test\"\n",
        )
        .unwrap();
        assert!(!responder_tls_configured(&secrets_dir).unwrap());
    }

    #[test]
    fn responder_tls_configured_returns_false_without_config() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        assert!(!responder_tls_configured(&secrets_dir).unwrap());
    }

    #[test]
    fn compose_has_top_level_service_detects_openbao_key() {
        let yaml = "services:\n  openbao:\n    image: openbao/openbao:latest\n";
        assert!(compose_has_top_level_service(yaml, "openbao"));
    }

    #[test]
    fn compose_has_top_level_service_ignores_substring_in_other_fields() {
        // `openbao` appears only as a hostname / image name / volume
        // path / comment / container_name — never as a service key.
        let yaml = "\
# uses an external openbao instance
services:
  app:
    image: example/app:latest
    container_name: my-openbao-client
    environment:
      - VAULT_ADDR=https://openbao.example.com:8200
    volumes:
      - ./openbao-secrets:/secrets:ro
volumes:
  openbao-data:
";
        assert!(!compose_has_top_level_service(yaml, "openbao"));
    }

    #[test]
    fn compose_has_top_level_service_rejects_prefixed_service_key() {
        let yaml = "services:\n  my-openbao:\n    image: x:latest\n";
        assert!(!compose_has_top_level_service(yaml, "openbao"));
    }

    #[test]
    fn compose_has_top_level_service_skips_volumes_block_with_same_key() {
        // A top-level `volumes:` block that defines an `openbao:` volume
        // must not satisfy the predicate.
        let yaml = "\
services:
  app:
    image: example/app:latest
volumes:
  openbao:
    driver: local
";
        assert!(!compose_has_top_level_service(yaml, "openbao"));
    }

    #[test]
    fn url_scheme_switches_to_https_when_tls_configured() {
        let https_url = DEFAULT_RESPONDER_ADMIN_URL.replace("http://", "https://");
        assert_eq!(https_url, "https://bootroot-http01:8080");
    }
}
