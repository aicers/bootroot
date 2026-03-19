use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;
use tokio::fs;

use super::resolve::ResolvedServiceAdd;
use super::{
    LocalApplyResult, MANAGED_PROFILE_BEGIN_PREFIX, MANAGED_PROFILE_END_PREFIX,
    OPENBAO_AGENT_CA_BUNDLE_TEMPLATE_FILENAME, OPENBAO_AGENT_CONFIG_FILENAME,
    OPENBAO_AGENT_TEMPLATE_FILENAME, OPENBAO_AGENT_TOKEN_FILENAME, OPENBAO_SERVICE_CONFIG_DIR,
    SERVICE_ROLE_ID_FILENAME, ServiceSyncMaterial,
};
use crate::commands::constants::{CA_TRUST_KEY, SERVICE_KV_BASE};
use crate::i18n::Messages;

pub(super) async fn apply_local_service_configs(
    secrets_dir: &Path,
    resolved: &ResolvedServiceAdd,
    secret_id_path: &Path,
    sync_material: &ServiceSyncMaterial,
    kv_mount: &str,
    openbao_url: &str,
    messages: &Messages,
) -> Result<LocalApplyResult> {
    let profile = render_managed_profile_block(resolved);
    let ca_bundle_path = resolved
        .cert_path
        .parent()
        .unwrap_or(Path::new("certs"))
        .join("ca-bundle.pem");
    let current = if resolved.agent_config.exists() {
        fs::read_to_string(&resolved.agent_config)
            .await
            .with_context(|| {
                messages.error_read_file_failed(&resolved.agent_config.display().to_string())
            })?
    } else {
        String::new()
    };
    let with_profile = upsert_managed_profile(&current, &resolved.service_name, &profile);
    let mut next = with_profile;
    let trust_updates = build_trust_updates(&sync_material.trusted_ca_sha256, &ca_bundle_path);
    next = bootroot::toml_util::upsert_section_keys(&next, "trust", &trust_updates)?;
    write_local_ca_bundle(&ca_bundle_path, &sync_material.ca_bundle_pem, messages).await?;
    fs::write(&resolved.agent_config, &next)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&resolved.agent_config.display().to_string())
        })?;
    fs_util::set_key_permissions(&resolved.agent_config).await?;

    let openbao_service_dir = secrets_dir
        .join(OPENBAO_SERVICE_CONFIG_DIR)
        .join(&resolved.service_name);
    fs_util::ensure_secrets_dir(&openbao_service_dir).await?;

    let ctmpl = build_ctmpl_content(&next, kv_mount, &resolved.service_name);
    let template_path = openbao_service_dir.join(OPENBAO_AGENT_TEMPLATE_FILENAME);
    fs::write(&template_path, &ctmpl)
        .await
        .with_context(|| messages.error_write_file_failed(&template_path.display().to_string()))?;
    fs_util::set_key_permissions(&template_path).await?;
    let bundle_template_path = openbao_service_dir.join(OPENBAO_AGENT_CA_BUNDLE_TEMPLATE_FILENAME);
    let bundle_template = build_ca_bundle_ctmpl_content(kv_mount, &resolved.service_name);
    fs::write(&bundle_template_path, &bundle_template)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&bundle_template_path.display().to_string())
        })?;
    fs_util::set_key_permissions(&bundle_template_path).await?;
    let template_specs = [
        (
            template_path.display().to_string(),
            resolved.agent_config.display().to_string(),
        ),
        (
            bundle_template_path.display().to_string(),
            ca_bundle_path.display().to_string(),
        ),
    ];

    let role_id_path = secret_id_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(SERVICE_ROLE_ID_FILENAME);
    let token_path = openbao_service_dir.join(OPENBAO_AGENT_TOKEN_FILENAME);
    if !token_path.exists() {
        fs::write(&token_path, "")
            .await
            .with_context(|| messages.error_write_file_failed(&token_path.display().to_string()))?;
    }
    fs_util::set_key_permissions(&token_path).await?;
    let agent_config_path = openbao_service_dir.join(OPENBAO_AGENT_CONFIG_FILENAME);
    let templates = template_specs
        .iter()
        .map(|(source, destination)| (source.as_str(), destination.as_str()))
        .collect::<Vec<_>>();
    let agent_hcl = render_openbao_agent_config(
        openbao_url,
        &role_id_path,
        secret_id_path,
        &token_path,
        &templates,
    );
    fs::write(&agent_config_path, agent_hcl)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&agent_config_path.display().to_string())
        })?;
    fs_util::set_key_permissions(&agent_config_path).await?;

    Ok(LocalApplyResult {
        agent_config: resolved.agent_config.display().to_string(),
        openbao_agent_config: agent_config_path.display().to_string(),
        openbao_agent_template: template_path.display().to_string(),
    })
}

async fn write_local_ca_bundle(path: &Path, bundle_pem: &str, messages: &Messages) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs_util::ensure_secrets_dir(parent).await?;
    }
    let contents = if bundle_pem.ends_with('\n') {
        bundle_pem.to_string()
    } else {
        format!("{bundle_pem}\n")
    };
    fs::write(path, contents)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    fs_util::set_key_permissions(path).await?;
    Ok(())
}

fn render_managed_profile_block(args: &ResolvedServiceAdd) -> String {
    let instance_id = args.instance_id.as_deref().unwrap_or_default();
    let mut lines = Vec::new();
    lines.push(format!(
        "{MANAGED_PROFILE_BEGIN_PREFIX} {}",
        args.service_name
    ));
    lines.push("[[profiles]]".to_string());
    lines.push(format!("service_name = \"{}\"", args.service_name));
    lines.push(format!("instance_id = \"{instance_id}\""));
    lines.push(format!("hostname = \"{}\"", args.hostname));
    lines.push(String::new());
    lines.push("[profiles.paths]".to_string());
    lines.push(format!("cert = \"{}\"", args.cert_path.display()));
    lines.push(format!("key = \"{}\"", args.key_path.display()));
    lines.push(format!(
        "{MANAGED_PROFILE_END_PREFIX} {}",
        args.service_name
    ));
    format!("{}\n", lines.join("\n"))
}

fn upsert_managed_profile(contents: &str, service_name: &str, replacement: &str) -> String {
    let begin_marker = format!("{MANAGED_PROFILE_BEGIN_PREFIX} {service_name}");
    let end_marker = format!("{MANAGED_PROFILE_END_PREFIX} {service_name}");
    if let Some(begin) = contents.find(&begin_marker)
        && let Some(end_relative) = contents[begin..].find(&end_marker)
    {
        let end = begin + end_relative + end_marker.len();
        let suffix = contents[end..]
            .strip_prefix('\n')
            .unwrap_or(&contents[end..]);
        let mut updated = String::new();
        updated.push_str(&contents[..begin]);
        if !updated.is_empty() && !updated.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(replacement);
        if !suffix.is_empty() && !replacement.ends_with('\n') {
            updated.push('\n');
        }
        updated.push_str(suffix);
        return updated;
    }

    let mut updated = contents.trim_end().to_string();
    if !updated.is_empty() {
        updated.push_str("\n\n");
    }
    updated.push_str(replacement);
    updated
}

fn build_trust_updates(
    fingerprints: &[String],
    ca_bundle_path: &Path,
) -> Vec<(&'static str, String)> {
    let mut updates = Vec::with_capacity(2);
    updates.push(("ca_bundle_path", ca_bundle_path.display().to_string()));
    updates.push((
        CA_TRUST_KEY,
        format!(
            "[{}]",
            fingerprints
                .iter()
                .map(|value| format!("\"{value}\""))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ));
    updates
}

fn is_section_header(line: &str) -> bool {
    line.starts_with('[') && line.ends_with(']')
}

fn render_openbao_agent_config(
    openbao_url: &str,
    role_id_path: &Path,
    secret_id_path: &Path,
    token_path: &Path,
    templates: &[(&str, &str)],
) -> String {
    let role_id = role_id_path.display().to_string();
    let secret_id = secret_id_path.display().to_string();
    let token = token_path.display().to_string();
    bootroot::openbao::build_agent_config(
        openbao_url,
        &role_id,
        &secret_id,
        &token,
        Some("auth/approle"),
        bootroot::openbao::STATIC_SECRET_RENDER_INTERVAL,
        templates,
    )
}

fn build_ctmpl_content(contents: &str, kv_mount: &str, service_name: &str) -> String {
    let base = format!("{SERVICE_KV_BASE}/{service_name}");

    let hmac_template = format!(
        "{{{{ with secret \"{kv_mount}/data/{base}/http_responder_hmac\" }}}}\
         {{{{ .Data.data.hmac }}}}\
         {{{{ end }}}}"
    );
    let with_hmac = replace_key_line_in_section(
        contents,
        "acme",
        "http_responder_hmac",
        &format!("http_responder_hmac = \"{hmac_template}\""),
    );

    let without_eab = remove_line_sections(&with_hmac, &["eab", "profiles.eab"]);

    let trust_template_line = format!(
        "{{{{ with secret \"{kv_mount}/data/{base}/trust\" }}}}\
         trusted_ca_sha256 = {{{{ .Data.data.trusted_ca_sha256 | toJSON }}}}\
         {{{{ end }}}}"
    );
    let with_trust = replace_key_line_in_section(
        &without_eab,
        "trust",
        "trusted_ca_sha256",
        &trust_template_line,
    );

    let eab_block = format!(
        "\n{{{{ with secret \"{kv_mount}/data/{base}/eab\" }}}}{{{{ if .Data.data.kid }}}}\n\
         [eab]\n\
         kid = \"{{{{ .Data.data.kid }}}}\"\n\
         hmac = \"{{{{ .Data.data.hmac }}}}\"\n\
         \n\
         [profiles.eab]\n\
         kid = \"{{{{ .Data.data.kid }}}}\"\n\
         hmac = \"{{{{ .Data.data.hmac }}}}\"\n\
         {{{{ end }}}}{{{{ end }}}}\n"
    );

    let mut result = with_trust;
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&eab_block);
    result
}

fn build_ca_bundle_ctmpl_content(kv_mount: &str, service_name: &str) -> String {
    let base = format!("{SERVICE_KV_BASE}/{service_name}");
    format!(
        "{{{{ with secret \"{kv_mount}/data/{base}/trust\" }}}}\
         {{{{ .Data.data.ca_bundle_pem }}}}\
         {{{{ end }}}}\n"
    )
}

/// Removes sections from pseudo-TOML content using line-based matching.
///
/// Used for Go template (ctmpl) files where the content is not valid
/// TOML and cannot be parsed by `toml_edit`.
fn remove_line_sections(contents: &str, sections: &[&str]) -> String {
    let mut output = String::new();
    let mut skip = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if is_section_header(trimmed) {
            let section_name = &trimmed[1..trimmed.len() - 1];
            skip = sections.contains(&section_name);
            if skip {
                continue;
            }
        }
        if skip {
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output
}

fn replace_key_line_in_section(
    contents: &str,
    section: &str,
    key: &str,
    replacement: &str,
) -> String {
    let mut output = String::new();
    let mut in_section = false;
    let mut replaced = false;

    for line in contents.lines() {
        let trimmed = line.trim();
        if is_section_header(trimmed) {
            in_section = trimmed == format!("[{section}]");
        }
        if in_section
            && !replaced
            && (trimmed.starts_with(&format!("{key} =")) || trimmed.starts_with(&format!("{key}=")))
        {
            output.push_str(replacement);
            output.push('\n');
            replaced = true;
            continue;
        }
        output.push_str(line);
        output.push('\n');
    }
    output
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::super::resolve::ResolvedServiceAdd;
    use super::*;
    use crate::state::{DeliveryMode, DeployType};

    fn test_resolved() -> ResolvedServiceAdd {
        ResolvedServiceAdd {
            service_name: "edge-proxy".to_string(),
            deploy_type: DeployType::Daemon,
            delivery_mode: DeliveryMode::LocalFile,
            hostname: "edge-node-01".to_string(),
            domain: "trusted.domain".to_string(),
            agent_config: PathBuf::from("agent.toml"),
            cert_path: PathBuf::from("certs/edge-proxy.crt"),
            key_path: PathBuf::from("certs/edge-proxy.key"),
            instance_id: Some("001".to_string()),
            container_name: None,
            runtime_auth: None,
            notes: None,
        }
    }

    #[test]
    fn test_upsert_managed_profile_is_idempotent() {
        let args = test_resolved();
        let block = render_managed_profile_block(&args);
        let once = upsert_managed_profile("", "edge-proxy", &block);
        let twice = upsert_managed_profile(&once, "edge-proxy", &block);
        assert_eq!(once, twice);
    }

    #[test]
    fn test_upsert_toml_section_keys_adds_and_updates_trust_section_idempotently() {
        let updates = build_trust_updates(
            &["a".repeat(64), "b".repeat(64)],
            Path::new("certs/ca-bundle.pem"),
        );
        let original = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let once = bootroot::toml_util::upsert_section_keys(original, "trust", &updates).unwrap();
        let twice = bootroot::toml_util::upsert_section_keys(&once, "trust", &updates).unwrap();

        assert_eq!(once, twice);
        assert!(once.contains("[trust]"));
        assert!(once.contains("ca_bundle_path = \"certs/ca-bundle.pem\""));
        assert!(once.contains("trusted_ca_sha256 = ["));
    }

    #[test]
    fn test_upsert_toml_section_keys_preserves_existing_unmanaged_lines() {
        let updates = vec![("ca_bundle_path", "certs/ca.pem".to_string())];
        let original = "[trust]\nextra = true\n";
        let output = bootroot::toml_util::upsert_section_keys(original, "trust", &updates).unwrap();

        assert!(output.contains("extra = true"));
        assert!(output.contains("ca_bundle_path = \"certs/ca.pem\""));
    }

    #[test]
    fn test_build_trust_updates_writes_bundle_and_pins_only() {
        let updates = build_trust_updates(&["a".repeat(64)], Path::new("certs/ca-bundle.pem"));

        assert_eq!(updates.len(), 2);
        assert!(updates.iter().any(|(key, _)| *key == "ca_bundle_path"));
        assert!(updates.iter().any(|(key, _)| *key == CA_TRUST_KEY));
    }

    #[test]
    fn test_build_ctmpl_replaces_http_responder_hmac() {
        let input = "[acme]\nhttp_responder_hmac = \"old-hmac\"\n";
        let output = build_ctmpl_content(input, "secret", "edge-proxy");
        assert!(output.contains(
            r#"http_responder_hmac = "{{ with secret "secret/data/bootroot/services/edge-proxy/http_responder_hmac" }}{{ .Data.data.hmac }}{{ end }}"#
        ));
        assert!(!output.contains("old-hmac"));
    }

    #[test]
    fn test_build_ctmpl_injects_eab_block() {
        let input = "[acme]\nhttp_responder_hmac = \"hmac\"\n";
        let output = build_ctmpl_content(input, "secret", "edge-proxy");
        assert!(output.contains(
            r#"{{ with secret "secret/data/bootroot/services/edge-proxy/eab" }}{{ if .Data.data.kid }}"#
        ));
        assert!(output.contains("[eab]"));
        assert!(output.contains("[profiles.eab]"));
    }

    #[test]
    fn test_build_ctmpl_removes_existing_eab_section() {
        let input =
            "[acme]\nhttp_responder_hmac = \"hmac\"\n\n[eab]\nkid = \"old\"\nhmac = \"old\"\n";
        let output = build_ctmpl_content(input, "secret", "edge-proxy");
        assert!(!output.contains("kid = \"old\""));
        assert!(
            output.contains(r#"{{ with secret "secret/data/bootroot/services/edge-proxy/eab" }}"#)
        );
    }

    #[test]
    fn test_build_ctmpl_replaces_trusted_ca_sha256() {
        let fp = "a".repeat(64);
        let input =
            format!("[trust]\nca_bundle_path = \"certs/ca.pem\"\ntrusted_ca_sha256 = [\"{fp}\"]\n");
        let output = build_ctmpl_content(&input, "secret", "edge-proxy");
        assert!(output.contains(
            r#"{{ with secret "secret/data/bootroot/services/edge-proxy/trust" }}trusted_ca_sha256 = {{ .Data.data.trusted_ca_sha256 | toJSON }}{{ end }}"#
        ));
        assert!(!output.contains(&fp));
    }

    #[test]
    fn test_build_ca_bundle_ctmpl_reads_service_trust_bundle() {
        let output = build_ca_bundle_ctmpl_content("secret", "edge-proxy");
        assert!(
            output
                .contains(r#"{{ with secret "secret/data/bootroot/services/edge-proxy/trust" }}"#)
        );
        assert!(output.contains(r"{{ .Data.data.ca_bundle_pem }}"));
    }

    #[test]
    fn test_build_ctmpl_preserves_static_content() {
        let input = "email = \"admin@example.com\"\nserver = \"https://localhost\"\n\n\
                     [acme]\nhttp_responder_hmac = \"hmac\"\n\n\
                     [[profiles]]\nservice_name = \"edge-proxy\"\n";
        let output = build_ctmpl_content(input, "secret", "edge-proxy");
        assert!(output.contains("email = \"admin@example.com\""));
        assert!(output.contains("server = \"https://localhost\""));
        assert!(output.contains("[[profiles]]"));
        assert!(output.contains("service_name = \"edge-proxy\""));
    }
}
