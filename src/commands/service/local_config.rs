use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::trust_bootstrap::{
    build_ca_bundle_ctmpl, build_managed_agent_ctmpl, build_trust_updates,
    render_managed_profile_block as render_managed_profile, upsert_managed_profile_block,
};
use tokio::fs;

use super::resolve::ResolvedServiceAdd;
use super::{
    LocalApplyResult, MANAGED_PROFILE_BEGIN_PREFIX, MANAGED_PROFILE_END_PREFIX,
    OPENBAO_AGENT_CA_BUNDLE_TEMPLATE_FILENAME, OPENBAO_AGENT_CONFIG_FILENAME,
    OPENBAO_AGENT_TEMPLATE_FILENAME, OPENBAO_AGENT_TOKEN_FILENAME, OPENBAO_SERVICE_CONFIG_DIR,
    SERVICE_ROLE_ID_FILENAME, ServiceSyncMaterial,
};
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
    render_managed_profile(
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        &args.service_name,
        args.instance_id.as_deref().unwrap_or_default(),
        &args.hostname,
        &args.cert_path,
        &args.key_path,
    )
}

fn upsert_managed_profile(contents: &str, service_name: &str, replacement: &str) -> String {
    upsert_managed_profile_block(
        contents,
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        service_name,
        replacement,
    )
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
    build_managed_agent_ctmpl(contents, kv_mount, service_name)
}

fn build_ca_bundle_ctmpl_content(kv_mount: &str, service_name: &str) -> String {
    build_ca_bundle_ctmpl(kv_mount, service_name)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::super::resolve::ResolvedServiceAdd;
    use super::*;
    use crate::commands::constants::CA_TRUST_KEY;
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
