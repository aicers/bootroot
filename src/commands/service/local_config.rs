use std::fmt::Write as _;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::toml_util::toml_encode_string;
use bootroot::trust_bootstrap::{
    build_ca_bundle_ctmpl, build_managed_agent_ctmpl, build_trust_updates,
    render_managed_profile_block as render_managed_profile, upsert_managed_profile_block,
};
use tokio::fs;

use super::resolve::ResolvedServiceAdd;
use super::{
    LocalApplyResult, MANAGED_PROFILE_BEGIN_PREFIX, MANAGED_PROFILE_END_PREFIX,
    OPENBAO_AGENT_CA_BUNDLE_TEMPLATE_FILENAME, OPENBAO_AGENT_CONFIG_FILENAME,
    OPENBAO_AGENT_DOCKER_CONFIG_FILENAME, OPENBAO_AGENT_TEMPLATE_FILENAME,
    OPENBAO_AGENT_TOKEN_FILENAME, OPENBAO_SERVICE_CONFIG_DIR, SERVICE_ROLE_ID_FILENAME,
    ServiceSyncMaterial,
};
use crate::commands::init::{resolve_openbao_agent_addr, to_container_path};
use crate::i18n::Messages;
use crate::state::{DeployType, PostRenewHookEntry};

/// Mount point inside service sidecar containers where the host
/// `secrets_dir` is bind-mounted.
const SIDECAR_CONTAINER_MOUNT: &str = "/openbao/secrets";

/// Mount point inside daemon-mode sidecar containers where the host
/// parent directory of `agent_config_path` is bind-mounted.  Used to
/// land the rendered `agent.toml` directly at the host path the
/// bootroot-agent daemon is configured to read.
pub(super) const SIDECAR_DAEMON_CONFIG_MOUNT: &str = "/sidecar-config";

/// Mount point inside daemon-mode sidecar containers where the host
/// parent directory of the daemon's certificates / CA bundle is
/// bind-mounted.
pub(super) const SIDECAR_DAEMON_CERTS_MOUNT: &str = "/sidecar-certs";

#[allow(clippy::too_many_lines)]
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
    let domain_updates = vec![("domain", resolved.domain.clone())];
    next = bootroot::toml_util::upsert_top_level_keys(&next, &domain_updates)?;
    let acme_updates = vec![("http_responder_hmac", sync_material.responder_hmac.clone())];
    next = bootroot::toml_util::upsert_section_keys(&next, "acme", &acme_updates)?;
    write_local_ca_bundle(&ca_bundle_path, &sync_material.ca_bundle_pem, messages).await?;
    let svc_cred_dir = secret_id_path.parent().unwrap_or(secrets_dir);
    // Pre-seed the same ca-bundle.pem path that the agent template
    // renders to, so the sidecar can verify TLS on first boot and
    // then track live trust updates from KV after the template runs.
    let docker_ca_bundle_path = svc_cred_dir.join(DOCKER_RENDERED_CA_BUNDLE);
    write_local_ca_bundle(
        &docker_ca_bundle_path,
        &sync_material.ca_bundle_pem,
        messages,
    )
    .await?;
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

    let docker_config_path = openbao_service_dir.join(OPENBAO_AGENT_DOCKER_CONFIG_FILENAME);
    let docker_hcl = render_docker_agent_config(&DockerAgentConfigInputs {
        secrets_dir,
        openbao_url,
        role_id_path: &role_id_path,
        secret_id_path,
        token_path: &token_path,
        agent_template_path: &template_path,
        ca_bundle_template_path: &bundle_template_path,
        deploy_type: resolved.deploy_type,
        host_agent_config_path: &resolved.agent_config,
        host_ca_bundle_path: &ca_bundle_path,
    })?;
    fs::write(&docker_config_path, docker_hcl)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&docker_config_path.display().to_string())
        })?;
    fs_util::set_key_permissions(&docker_config_path).await?;

    Ok(LocalApplyResult {
        agent_config: resolved.agent_config.display().to_string(),
        openbao_agent_config: agent_config_path.display().to_string(),
        openbao_agent_docker_config: docker_config_path.display().to_string(),
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
    let base = render_managed_profile(
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        &args.service_name,
        args.instance_id.as_deref().unwrap_or_default(),
        &args.hostname,
        &args.cert_path,
        &args.key_path,
    );
    inject_hooks_into_profile_block(&base, &args.post_renew_hooks)
}

fn inject_hooks_into_profile_block(block: &str, hooks: &[PostRenewHookEntry]) -> String {
    if hooks.is_empty() {
        return block.to_string();
    }
    let hooks_toml = render_hooks_toml(hooks);
    if let Some(end_pos) = block.rfind(MANAGED_PROFILE_END_PREFIX) {
        let mut result = block[..end_pos].to_string();
        result.push_str(&hooks_toml);
        result.push_str(&block[end_pos..]);
        result
    } else {
        let mut result = block.to_string();
        result.push_str(&hooks_toml);
        result
    }
}

fn render_hooks_toml(hooks: &[PostRenewHookEntry]) -> String {
    let mut output = String::new();
    for hook in hooks {
        output.push_str("\n[[profiles.hooks.post_renew.success]]\n");
        let _ = writeln!(output, "command = {}", toml_encode_string(&hook.command));
        if !hook.args.is_empty() {
            let args = hook
                .args
                .iter()
                .map(|a| toml_encode_string(a))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(output, "args = [{args}]");
        }
        let _ = writeln!(output, "timeout_secs = {}", hook.timeout_secs);
        let _ = writeln!(output, "on_failure = \"{}\"", hook.on_failure);
    }
    output
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
    bootroot::openbao::build_agent_config(&bootroot::openbao::AgentConfigParams {
        openbao_addr: openbao_url,
        role_id_path: &role_id,
        secret_id_path: &secret_id,
        token_path: &token,
        mount_path: Some("auth/approle"),
        render_interval: bootroot::openbao::STATIC_SECRET_RENDER_INTERVAL,
        templates,
        ca_cert: None,
    })
}

/// Name used for the rendered agent config inside the Docker container.
const DOCKER_RENDERED_AGENT_CONFIG: &str = "agent.toml";

/// Name used for the rendered CA bundle inside the Docker container.
pub(super) const DOCKER_RENDERED_CA_BUNDLE: &str = "ca-bundle.pem";

/// Inputs for [`render_docker_agent_config`].
struct DockerAgentConfigInputs<'a> {
    secrets_dir: &'a Path,
    openbao_url: &'a str,
    role_id_path: &'a Path,
    secret_id_path: &'a Path,
    token_path: &'a Path,
    agent_template_path: &'a Path,
    ca_bundle_template_path: &'a Path,
    deploy_type: DeployType,
    /// Host-side path the operator supplied via `--agent-config`.  For
    /// `DeployType::Daemon`, the sidecar is instructed to render the
    /// agent config file directly to this path via a dedicated
    /// bind-mount, so that `bootroot-agent` and `rotate` both see the
    /// same file.
    host_agent_config_path: &'a Path,
    /// Host-side path where the daemon's CA bundle lives (sits next to
    /// `cert_path`).  Same rationale as `host_agent_config_path`.
    host_ca_bundle_path: &'a Path,
}

/// Renders an `OpenBao` agent config for use inside a Docker sidecar
/// container.  Translates all host paths to their container-side
/// equivalents under [`SIDECAR_CONTAINER_MOUNT`] and replaces the
/// `OpenBao` address with the Docker-internal hostname.
///
/// Template sources (`.ctmpl` files) are mapped via [`to_container_path`]
/// since they reside under `secrets_dir`.  Template destinations
/// depend on `deploy_type`:
/// - `DeployType::Docker`: the sidecar and the service container share
///   the `secrets_dir` bind-mount, so rendered files are placed at
///   well-known names inside the service's credential directory.
/// - `DeployType::Daemon`: the host-side `agent_config_path` typically
///   sits outside `secrets_dir`; the sidecar gets dedicated bind-mounts
///   ([`SIDECAR_DAEMON_CONFIG_MOUNT`] and [`SIDECAR_DAEMON_CERTS_MOUNT`])
///   onto that path's parent and the CA bundle's parent, so rendered
///   files land exactly at the host paths that `bootroot-agent` reads
///   and that `rotate` waits on.
///
/// When the `openbao_url` scheme is `https`, includes the `ca_cert`
/// field pointing to the same container-side CA bundle that the agent
/// template renders.  The caller pre-seeds this file during
/// `service add` so the agent can verify TLS on its very first
/// connection; subsequent template renders then keep the file in sync
/// with the live trust bundle from KV.
fn render_docker_agent_config(inputs: &DockerAgentConfigInputs<'_>) -> Result<String> {
    let sd = inputs.secrets_dir;
    let docker_addr = resolve_openbao_agent_addr(inputs.openbao_url, true);
    let role_id = to_container_path(sd, inputs.role_id_path, SIDECAR_CONTAINER_MOUNT)?;
    let secret_id = to_container_path(sd, inputs.secret_id_path, SIDECAR_CONTAINER_MOUNT)?;
    let token = to_container_path(sd, inputs.token_path, SIDECAR_CONTAINER_MOUNT)?;

    let tpl_source = to_container_path(sd, inputs.agent_template_path, SIDECAR_CONTAINER_MOUNT)?;
    let ca_tpl_source =
        to_container_path(sd, inputs.ca_bundle_template_path, SIDECAR_CONTAINER_MOUNT)?;

    let (tpl_dest, ca_tpl_dest) = match inputs.deploy_type {
        DeployType::Docker => {
            let svc_cred_dir = inputs.secret_id_path.parent().unwrap_or(inputs.secrets_dir);
            let tpl_dest = to_container_path(
                sd,
                &svc_cred_dir.join(DOCKER_RENDERED_AGENT_CONFIG),
                SIDECAR_CONTAINER_MOUNT,
            )?;
            let ca_tpl_dest = to_container_path(
                sd,
                &svc_cred_dir.join(DOCKER_RENDERED_CA_BUNDLE),
                SIDECAR_CONTAINER_MOUNT,
            )?;
            (tpl_dest, ca_tpl_dest)
        }
        DeployType::Daemon => {
            let cfg_name = inputs.host_agent_config_path.file_name().map_or_else(
                || DOCKER_RENDERED_AGENT_CONFIG.to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            let ca_name = inputs.host_ca_bundle_path.file_name().map_or_else(
                || DOCKER_RENDERED_CA_BUNDLE.to_string(),
                |n| n.to_string_lossy().into_owned(),
            );
            (
                format!("{SIDECAR_DAEMON_CONFIG_MOUNT}/{cfg_name}"),
                format!("{SIDECAR_DAEMON_CERTS_MOUNT}/{ca_name}"),
            )
        }
    };

    // Point ca_cert at the same path the CA bundle template renders
    // to.  The caller pre-seeds this file during `service add`, so
    // the agent can verify TLS on its very first connection.  Once the
    // agent renders the template, the file is overwritten with the
    // live bundle from KV, keeping trust in sync across CA rotations.
    let ca_cert = if docker_addr.starts_with("https://") {
        Some(ca_tpl_dest.clone())
    } else {
        None
    };

    let templates = [(tpl_source, tpl_dest), (ca_tpl_source, ca_tpl_dest)];
    let tpl_refs: Vec<(&str, &str)> = templates
        .iter()
        .map(|(s, d)| (s.as_str(), d.as_str()))
        .collect();

    Ok(bootroot::openbao::build_agent_config(
        &bootroot::openbao::AgentConfigParams {
            openbao_addr: &docker_addr,
            role_id_path: &role_id,
            secret_id_path: &secret_id,
            token_path: &token,
            mount_path: Some("auth/approle"),
            render_interval: bootroot::openbao::STATIC_SECRET_RENDER_INTERVAL,
            templates: &tpl_refs,
            ca_cert: ca_cert.as_deref(),
        },
    ))
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
            post_renew_hooks: Vec::new(),
            secret_id_ttl: None,
            secret_id_wrap_ttl: None,
            token_bound_cidrs: None,
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

    #[test]
    fn test_generated_config_includes_domain_and_acme() {
        let args = test_resolved();
        let fp = "a".repeat(64);
        let profile = render_managed_profile_block(&args);
        let with_profile = upsert_managed_profile("", "edge-proxy", &profile);
        let trust_updates = build_trust_updates(&[fp], Path::new("certs/ca-bundle.pem"));
        let with_trust =
            bootroot::toml_util::upsert_section_keys(&with_profile, "trust", &trust_updates)
                .unwrap();
        let domain_updates = vec![("domain", "trusted.domain".to_string())];
        let with_domain =
            bootroot::toml_util::upsert_top_level_keys(&with_trust, &domain_updates).unwrap();
        let acme_updates = vec![("http_responder_hmac", "test-hmac-value".to_string())];
        let output =
            bootroot::toml_util::upsert_section_keys(&with_domain, "acme", &acme_updates).unwrap();

        assert!(
            output.contains("domain = \"trusted.domain\""),
            "missing domain: {output}"
        );
        assert!(
            output.contains("[acme]"),
            "missing [acme] section: {output}"
        );
        assert!(
            output.contains("http_responder_hmac = \"test-hmac-value\""),
            "missing http_responder_hmac: {output}"
        );
        assert!(output.contains("[[profiles]]"), "missing profile: {output}");
        assert!(output.contains("[trust]"), "missing trust: {output}");
    }

    #[test]
    fn test_generated_config_ctmpl_replaces_hmac_from_full_config() {
        let args = test_resolved();
        let fp = "a".repeat(64);
        let profile = render_managed_profile_block(&args);
        let with_profile = upsert_managed_profile("", "edge-proxy", &profile);
        let trust_updates = build_trust_updates(&[fp], Path::new("certs/ca-bundle.pem"));
        let with_trust =
            bootroot::toml_util::upsert_section_keys(&with_profile, "trust", &trust_updates)
                .unwrap();
        let domain_updates = vec![("domain", "trusted.domain".to_string())];
        let with_domain =
            bootroot::toml_util::upsert_top_level_keys(&with_trust, &domain_updates).unwrap();
        let acme_updates = vec![("http_responder_hmac", "test-hmac-value".to_string())];
        let config =
            bootroot::toml_util::upsert_section_keys(&with_domain, "acme", &acme_updates).unwrap();

        let ctmpl = build_ctmpl_content(&config, "secret", "edge-proxy");

        assert!(
            ctmpl.contains("domain = \"trusted.domain\""),
            "ctmpl missing domain: {ctmpl}"
        );
        assert!(
            ctmpl.contains(
                r#"http_responder_hmac = "{{ with secret "secret/data/bootroot/services/edge-proxy/http_responder_hmac" }}{{ .Data.data.hmac }}{{ end }}"#
            ),
            "ctmpl missing hmac template: {ctmpl}"
        );
        assert!(
            !ctmpl.contains("test-hmac-value"),
            "ctmpl should not contain literal hmac: {ctmpl}"
        );
    }

    #[test]
    fn test_domain_and_acme_upsert_is_idempotent() {
        let args = test_resolved();
        let profile = render_managed_profile_block(&args);
        let with_profile = upsert_managed_profile("", "edge-proxy", &profile);
        let trust_updates =
            build_trust_updates(&["a".repeat(64)], Path::new("certs/ca-bundle.pem"));
        let with_trust =
            bootroot::toml_util::upsert_section_keys(&with_profile, "trust", &trust_updates)
                .unwrap();
        let domain_updates = vec![("domain", "trusted.domain".to_string())];
        let acme_updates = vec![("http_responder_hmac", "hmac-val".to_string())];

        let once =
            bootroot::toml_util::upsert_top_level_keys(&with_trust, &domain_updates).unwrap();
        let once = bootroot::toml_util::upsert_section_keys(&once, "acme", &acme_updates).unwrap();

        let twice = bootroot::toml_util::upsert_top_level_keys(&once, &domain_updates).unwrap();
        let twice =
            bootroot::toml_util::upsert_section_keys(&twice, "acme", &acme_updates).unwrap();

        assert_eq!(once, twice);
    }

    #[test]
    fn test_render_hooks_toml_single_hook() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let hooks = vec![PostRenewHookEntry {
            command: "systemctl".to_string(),
            args: vec!["reload".to_string(), "nginx".to_string()],
            timeout_secs: 30,
            on_failure: HookFailurePolicyEntry::Continue,
        }];
        let toml = render_hooks_toml(&hooks);
        assert!(toml.contains("[[profiles.hooks.post_renew.success]]"));
        assert!(toml.contains("command = \"systemctl\""));
        assert!(toml.contains("args = [\"reload\", \"nginx\"]"));
        assert!(toml.contains("timeout_secs = 30"));
        assert!(toml.contains("on_failure = \"continue\""));
    }

    #[test]
    fn test_render_hooks_toml_empty() {
        let toml = render_hooks_toml(&[]);
        assert!(toml.is_empty());
    }

    #[test]
    fn test_inject_hooks_into_profile_block() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let mut args = test_resolved();
        args.post_renew_hooks = vec![PostRenewHookEntry {
            command: "systemctl".to_string(),
            args: vec!["reload".to_string(), "nginx".to_string()],
            timeout_secs: 30,
            on_failure: HookFailurePolicyEntry::Continue,
        }];
        let block = render_managed_profile_block(&args);
        assert!(block.contains("[[profiles.hooks.post_renew.success]]"));
        assert!(block.contains("command = \"systemctl\""));
        assert!(block.contains(MANAGED_PROFILE_END_PREFIX));
    }

    #[test]
    fn test_inject_hooks_preserves_end_marker() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let mut args = test_resolved();
        args.post_renew_hooks = vec![PostRenewHookEntry {
            command: "pkill".to_string(),
            args: vec!["-HUP".to_string(), "myproc".to_string()],
            timeout_secs: 15,
            on_failure: HookFailurePolicyEntry::Stop,
        }];
        let block = render_managed_profile_block(&args);

        let end_pos = block
            .find(MANAGED_PROFILE_END_PREFIX)
            .expect("end marker must exist");
        let hook_pos = block
            .find("[[profiles.hooks.post_renew.success]]")
            .expect("hook must exist");
        assert!(hook_pos < end_pos, "hook should appear before end marker");
        assert!(block.contains("on_failure = \"stop\""));
    }

    #[test]
    fn test_managed_profile_with_hooks_is_idempotent() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let mut args = test_resolved();
        args.post_renew_hooks = vec![PostRenewHookEntry {
            command: "systemctl".to_string(),
            args: vec!["reload".to_string(), "nginx".to_string()],
            timeout_secs: 30,
            on_failure: HookFailurePolicyEntry::Continue,
        }];
        let block = render_managed_profile_block(&args);
        let once = upsert_managed_profile("", "edge-proxy", &block);
        let twice = upsert_managed_profile(&once, "edge-proxy", &block);
        assert_eq!(once, twice);
    }

    #[test]
    fn test_render_hooks_toml_escapes_control_characters() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let hooks = vec![PostRenewHookEntry {
            command: "echo\nnext".to_string(),
            args: vec!["line1\tline2".to_string(), "back\\slash".to_string()],
            timeout_secs: 10,
            on_failure: HookFailurePolicyEntry::Continue,
        }];
        let toml = render_hooks_toml(&hooks);

        // The output must be valid TOML — parse it to confirm.
        let wrapped = format!("[profiles]\n[profiles.hooks]\n[profiles.hooks.post_renew]{toml}");
        let doc: toml_edit::DocumentMut = wrapped
            .parse()
            .expect("rendered hook TOML with control chars must be parseable");

        let success = doc["profiles"]["hooks"]["post_renew"]["success"]
            .as_array_of_tables()
            .expect("success must be an array of tables");
        let hook = success.get(0).expect("must have one hook entry");
        assert_eq!(
            hook["command"].as_str().unwrap(),
            "echo\nnext",
            "command must round-trip through TOML"
        );
        let args = hook["args"].as_array().expect("args must be an array");
        assert_eq!(args.get(0).unwrap().as_str().unwrap(), "line1\tline2");
        assert_eq!(args.get(1).unwrap().as_str().unwrap(), "back\\slash");
    }

    #[test]
    fn docker_config_uses_container_paths_and_openbao_hostname() {
        let secrets_dir = Path::new("/project/secrets");
        let svc_dir = secrets_dir.join("openbao/services/edge");
        let cred_dir = secrets_dir.join("services/edge");
        let hcl = render_docker_agent_config(&DockerAgentConfigInputs {
            secrets_dir,
            openbao_url: "http://localhost:8200",
            role_id_path: &cred_dir.join("role_id"),
            secret_id_path: &cred_dir.join("secret_id"),
            token_path: &svc_dir.join("token"),
            agent_template_path: &svc_dir.join("agent.toml.ctmpl"),
            ca_bundle_template_path: &svc_dir.join("ca-bundle.pem.ctmpl"),
            deploy_type: DeployType::Docker,
            host_agent_config_path: Path::new("agent.toml"),
            host_ca_bundle_path: Path::new("ca-bundle.pem"),
        })
        .unwrap();

        assert!(
            hcl.contains(r#"address = "http://bootroot-openbao:8200""#),
            "must use Docker-internal address"
        );
        assert!(
            hcl.contains("/openbao/secrets/services/edge/role_id"),
            "role_id must be container path"
        );
        assert!(
            hcl.contains("/openbao/secrets/services/edge/secret_id"),
            "secret_id must be container path"
        );
        assert!(
            hcl.contains("/openbao/secrets/openbao/services/edge/token"),
            "token must be container path"
        );
        assert!(
            hcl.contains("/openbao/secrets/openbao/services/edge/agent.toml.ctmpl"),
            "template source must be container path"
        );
        assert!(
            hcl.contains("/openbao/secrets/services/edge/agent.toml"),
            "template dest must be container path"
        );
        assert!(
            hcl.contains("/openbao/secrets/openbao/services/edge/ca-bundle.pem.ctmpl"),
            "ca bundle template source must be container path"
        );
        assert!(
            hcl.contains("/openbao/secrets/services/edge/ca-bundle.pem"),
            "ca bundle dest must be container path"
        );
        assert!(
            !hcl.contains("ca_cert"),
            "http address must not include ca_cert"
        );
    }

    #[test]
    fn docker_config_includes_ca_cert_when_tls_enabled() {
        let secrets_dir = Path::new("/project/secrets");
        let svc_dir = secrets_dir.join("openbao/services/edge");
        let cred_dir = secrets_dir.join("services/edge");
        let hcl = render_docker_agent_config(&DockerAgentConfigInputs {
            secrets_dir,
            openbao_url: "https://localhost:8200",
            role_id_path: &cred_dir.join("role_id"),
            secret_id_path: &cred_dir.join("secret_id"),
            token_path: &svc_dir.join("token"),
            agent_template_path: &svc_dir.join("agent.toml.ctmpl"),
            ca_bundle_template_path: &svc_dir.join("ca-bundle.pem.ctmpl"),
            deploy_type: DeployType::Docker,
            host_agent_config_path: Path::new("agent.toml"),
            host_ca_bundle_path: Path::new("ca-bundle.pem"),
        })
        .unwrap();

        assert!(
            hcl.contains(r#"address = "https://bootroot-openbao:8200""#),
            "must use https Docker-internal address"
        );
        assert!(
            hcl.contains(r#"ca_cert = "/openbao/secrets/services/edge/ca-bundle.pem""#),
            "ca_cert must point at template-rendered bundle for live trust updates"
        );
    }

    #[test]
    fn docker_config_omits_ca_cert_when_http() {
        let secrets_dir = Path::new("/project/secrets");
        let svc_dir = secrets_dir.join("openbao/services/edge");
        let cred_dir = secrets_dir.join("services/edge");
        let hcl = render_docker_agent_config(&DockerAgentConfigInputs {
            secrets_dir,
            openbao_url: "http://127.0.0.1:8200",
            role_id_path: &cred_dir.join("role_id"),
            secret_id_path: &cred_dir.join("secret_id"),
            token_path: &svc_dir.join("token"),
            agent_template_path: &svc_dir.join("agent.toml.ctmpl"),
            ca_bundle_template_path: &svc_dir.join("ca-bundle.pem.ctmpl"),
            deploy_type: DeployType::Docker,
            host_agent_config_path: Path::new("agent.toml"),
            host_ca_bundle_path: Path::new("ca-bundle.pem"),
        })
        .unwrap();

        assert!(
            hcl.contains(r#"address = "http://bootroot-openbao:8200""#),
            "127.0.0.1 must be replaced with bootroot-openbao"
        );
        assert!(!hcl.contains("ca_cert"), "http must not include ca_cert");
    }

    #[test]
    fn docker_config_rewrites_specific_ip_to_container_name() {
        let secrets_dir = Path::new("/project/secrets");
        let svc_dir = secrets_dir.join("openbao/services/edge");
        let cred_dir = secrets_dir.join("services/edge");
        let hcl = render_docker_agent_config(&DockerAgentConfigInputs {
            secrets_dir,
            openbao_url: "https://192.168.1.10:8200",
            role_id_path: &cred_dir.join("role_id"),
            secret_id_path: &cred_dir.join("secret_id"),
            token_path: &svc_dir.join("token"),
            agent_template_path: &svc_dir.join("agent.toml.ctmpl"),
            ca_bundle_template_path: &svc_dir.join("ca-bundle.pem.ctmpl"),
            deploy_type: DeployType::Docker,
            host_agent_config_path: Path::new("agent.toml"),
            host_ca_bundle_path: Path::new("ca-bundle.pem"),
        })
        .unwrap();

        assert!(
            hcl.contains(r#"address = "https://bootroot-openbao:8200""#),
            "specific IP must be replaced with Docker-internal hostname"
        );
        assert!(
            hcl.contains(r#"ca_cert = "/openbao/secrets/services/edge/ca-bundle.pem""#),
            "https with specific IP must use template-rendered ca_cert"
        );
    }

    #[test]
    fn docker_config_daemon_targets_host_paths_via_sidecar_mounts() {
        let secrets_dir = Path::new("/project/secrets");
        let svc_dir = secrets_dir.join("openbao/services/review");
        let cred_dir = secrets_dir.join("services/review");
        let hcl = render_docker_agent_config(&DockerAgentConfigInputs {
            secrets_dir,
            openbao_url: "http://localhost:8200",
            role_id_path: &cred_dir.join("role_id"),
            secret_id_path: &cred_dir.join("secret_id"),
            token_path: &svc_dir.join("token"),
            agent_template_path: &svc_dir.join("agent.toml.ctmpl"),
            ca_bundle_template_path: &svc_dir.join("ca-bundle.pem.ctmpl"),
            deploy_type: DeployType::Daemon,
            host_agent_config_path: Path::new("/abs/config/review-agent.toml"),
            host_ca_bundle_path: Path::new("/abs/certs/ca-bundle.pem"),
        })
        .unwrap();

        assert!(
            hcl.contains(&format!(
                "destination = \"{SIDECAR_DAEMON_CONFIG_MOUNT}/review-agent.toml\""
            )),
            "daemon agent.toml must render through {SIDECAR_DAEMON_CONFIG_MOUNT}"
        );
        assert!(
            hcl.contains(&format!(
                "destination = \"{SIDECAR_DAEMON_CERTS_MOUNT}/ca-bundle.pem\""
            )),
            "daemon ca-bundle.pem must render through {SIDECAR_DAEMON_CERTS_MOUNT}"
        );
        assert!(
            !hcl.contains("/openbao/secrets/services/review/agent.toml"),
            "daemon deploy must not reuse the docker credential-dir destination"
        );
    }

    #[test]
    fn docker_config_daemon_ca_cert_points_at_sidecar_mount_when_https() {
        let secrets_dir = Path::new("/project/secrets");
        let svc_dir = secrets_dir.join("openbao/services/review");
        let cred_dir = secrets_dir.join("services/review");
        let hcl = render_docker_agent_config(&DockerAgentConfigInputs {
            secrets_dir,
            openbao_url: "https://localhost:8200",
            role_id_path: &cred_dir.join("role_id"),
            secret_id_path: &cred_dir.join("secret_id"),
            token_path: &svc_dir.join("token"),
            agent_template_path: &svc_dir.join("agent.toml.ctmpl"),
            ca_bundle_template_path: &svc_dir.join("ca-bundle.pem.ctmpl"),
            deploy_type: DeployType::Daemon,
            host_agent_config_path: Path::new("/abs/config/review-agent.toml"),
            host_ca_bundle_path: Path::new("/abs/certs/ca-bundle.pem"),
        })
        .unwrap();

        assert!(
            hcl.contains(&format!(
                "ca_cert = \"{SIDECAR_DAEMON_CERTS_MOUNT}/ca-bundle.pem\""
            )),
            "daemon https must point ca_cert at the bind-mounted bundle"
        );
    }

    #[test]
    fn host_agent_config_unchanged_by_docker_additions() {
        let hcl = render_openbao_agent_config(
            "http://localhost:8200",
            Path::new("/secrets/services/edge/role_id"),
            Path::new("/secrets/services/edge/secret_id"),
            Path::new("/secrets/openbao/services/edge/token"),
            &[("/tpl.ctmpl", "/out.toml")],
        );

        assert!(
            hcl.contains(r#"address = "http://localhost:8200""#),
            "host config must keep original address"
        );
        assert!(
            hcl.contains(r#"role_id_file_path = "/secrets/services/edge/role_id""#),
            "host config must keep host paths"
        );
        assert!(
            !hcl.contains("ca_cert"),
            "host config must not include ca_cert"
        );
    }
}
