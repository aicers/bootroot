use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use bootroot::fs_util;
use bootroot::openbao::{AgentConfigParams, STATIC_SECRET_RENDER_INTERVAL, build_agent_config};
use bootroot::trust_bootstrap::{
    build_ca_bundle_ctmpl, build_managed_agent_ctmpl,
    build_trust_updates as build_shared_trust_updates,
    render_managed_profile_block as render_profile,
    upsert_managed_profile_block as upsert_shared_managed_profile_block,
};
use tokio::fs;

use super::io::PulledSecrets;
use super::summary::{ApplyItemSummary, ApplyStatus};
use super::{
    HookFailurePolicy, Locale, MANAGED_PROFILE_BEGIN_PREFIX, MANAGED_PROFILE_END_PREFIX,
    ResolvedBootstrapArgs, localized,
};

struct ProfilePaths {
    cert_path: PathBuf,
    key_path: PathBuf,
}

// This function intentionally centralizes agent config mutation flow so
// per-item status/error mapping remains consistent for summary JSON contracts.
#[allow(clippy::too_many_lines)]
pub(super) async fn apply_agent_config_updates(
    args: &ResolvedBootstrapArgs,
    pulled: &PulledSecrets,
    lang: Locale,
) -> (ApplyItemSummary, ApplyItemSummary) {
    let profile_paths = resolve_profile_paths(args);
    let agent_config = match fs::read_to_string(&args.agent_config_path).await {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            render_agent_config_baseline(args)
        }
        Err(err) => {
            let message = localized(
                lang,
                &format!(
                    "agent config read failed ({}): {err}",
                    args.agent_config_path.display()
                ),
                &format!(
                    "agent.toml 읽기 실패 ({}): {err}",
                    args.agent_config_path.display()
                ),
            );
            return (
                ApplyItemSummary::failed(message.clone()),
                ApplyItemSummary::failed(message),
            );
        }
    };
    let acme_pairs = vec![("http_responder_hmac", pulled.responder_hmac.clone())];
    let hmac_updated =
        match bootroot::toml_util::upsert_section_keys(&agent_config, "acme", &acme_pairs) {
            Ok(output) => output,
            Err(err) => {
                let msg = format!("agent config TOML parse error: {err}");
                return (
                    ApplyItemSummary::failed(msg.clone()),
                    ApplyItemSummary::failed(msg),
                );
            }
        };
    let trust_pairs = build_trust_updates(&pulled.trusted_ca_sha256, &args.ca_bundle_path);
    let trust_updated =
        match bootroot::toml_util::upsert_section_keys(&hmac_updated, "trust", &trust_pairs) {
            Ok(output) => output,
            Err(err) => {
                let msg = format!("agent config TOML parse error: {err}");
                return (
                    ApplyItemSummary::failed(msg.clone()),
                    ApplyItemSummary::failed(msg),
                );
            }
        };
    let profile_block = render_managed_profile_block(
        &args.service_name,
        args.profile_instance_id
            .as_deref()
            .expect("validate_bootstrap_args requires profile_instance_id"),
        &args.profile_hostname,
        &profile_paths.cert_path,
        &profile_paths.key_path,
    );
    let profile_block = inject_hooks_into_profile_block(&profile_block, args);
    let with_profile =
        upsert_managed_profile_block(&trust_updated, &args.service_name, &profile_block);

    let responder_changed = hmac_updated != agent_config;
    let trust_changed = trust_updated != hmac_updated;
    let profile_changed = with_profile != trust_updated;

    let mut responder_hmac_status = ApplyItemSummary::applied(if responder_changed {
        ApplyStatus::Applied
    } else {
        ApplyStatus::Unchanged
    });
    let mut trust_sync_status = ApplyItemSummary::applied(if trust_changed {
        ApplyStatus::Applied
    } else {
        ApplyStatus::Unchanged
    });

    if with_profile != agent_config {
        if let Some(parent) = args.agent_config_path.parent()
            && let Err(err) = fs_util::ensure_secrets_dir(parent).await
        {
            let message = localized(
                lang,
                &format!(
                    "agent config parent mkdir failed ({}): {err}",
                    parent.display()
                ),
                &format!(
                    "agent.toml 상위 디렉터리 생성 실패 ({}): {err}",
                    parent.display()
                ),
            );
            return (
                ApplyItemSummary::failed(message.clone()),
                ApplyItemSummary::failed(message),
            );
        }
        if let Err(err) = fs::write(&args.agent_config_path, &with_profile).await {
            let message = localized(
                lang,
                &format!(
                    "agent config write failed ({}): {err}",
                    args.agent_config_path.display()
                ),
                &format!(
                    "agent.toml 쓰기 실패 ({}): {err}",
                    args.agent_config_path.display()
                ),
            );
            if responder_changed {
                responder_hmac_status = ApplyItemSummary::failed(message.clone());
            }
            if trust_changed {
                trust_sync_status = ApplyItemSummary::failed(message);
            }
            return (responder_hmac_status, trust_sync_status);
        }
        if let Err(err) = fs_util::set_key_permissions(&args.agent_config_path).await {
            let message = localized(
                lang,
                &format!(
                    "agent config chmod failed ({}): {err}",
                    args.agent_config_path.display()
                ),
                &format!(
                    "agent.toml 권한 설정 실패 ({}): {err}",
                    args.agent_config_path.display()
                ),
            );
            if responder_changed {
                responder_hmac_status = ApplyItemSummary::failed(message.clone());
            }
            if trust_changed {
                trust_sync_status = ApplyItemSummary::failed(message);
            }
            return (responder_hmac_status, trust_sync_status);
        }
    }
    if let Err(err) = write_openbao_agent_artifacts(args, &with_profile, lang).await {
        let message = localized(
            lang,
            &format!("openbao agent setup failed: {err}"),
            &format!("OpenBao Agent 설정 준비 실패: {err}"),
        );
        if responder_changed || profile_changed {
            responder_hmac_status = ApplyItemSummary::failed(message.clone());
        }
        if trust_changed || profile_changed {
            trust_sync_status = ApplyItemSummary::failed(message);
        }
    }

    (responder_hmac_status, trust_sync_status)
}

fn resolve_profile_paths(args: &ResolvedBootstrapArgs) -> ProfilePaths {
    let fallback_dir = args
        .agent_config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("certs");
    let cert_path = args
        .profile_cert_path
        .clone()
        .unwrap_or_else(|| fallback_dir.join(format!("{}.crt", args.service_name)));
    let key_path = args
        .profile_key_path
        .clone()
        .unwrap_or_else(|| fallback_dir.join(format!("{}.key", args.service_name)));
    ProfilePaths {
        cert_path,
        key_path,
    }
}

fn inject_hooks_into_profile_block(block: &str, args: &ResolvedBootstrapArgs) -> String {
    let Some(command) = args.post_renew_command.as_deref() else {
        return block.to_string();
    };
    let timeout_secs = args.post_renew_timeout_secs.unwrap_or(30);
    let on_failure = match args.post_renew_on_failure {
        Some(HookFailurePolicy::Stop) => "stop",
        _ => "continue",
    };
    let mut hook_toml = String::from("\n[[profiles.hooks.post_renew.success]]\n");
    let _ = writeln!(
        hook_toml,
        "command = {}",
        bootroot::toml_util::toml_encode_string(command)
    );
    if !args.post_renew_arg.is_empty() {
        let formatted_args = args
            .post_renew_arg
            .iter()
            .map(|a| bootroot::toml_util::toml_encode_string(a))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(hook_toml, "args = [{formatted_args}]");
    }
    let _ = writeln!(hook_toml, "timeout_secs = {timeout_secs}");
    let _ = writeln!(hook_toml, "on_failure = \"{on_failure}\"");

    if let Some(end_pos) = block.rfind(MANAGED_PROFILE_END_PREFIX) {
        let mut result = block[..end_pos].to_string();
        result.push_str(&hook_toml);
        result.push_str(&block[end_pos..]);
        result
    } else {
        let mut result = block.to_string();
        result.push_str(&hook_toml);
        result
    }
}

fn render_agent_config_baseline(args: &ResolvedBootstrapArgs) -> String {
    format!(
        "email = \"{email}\"\n\
server = \"{server}\"\n\
domain = \"{domain}\"\n\n\
[acme]\n\
directory_fetch_attempts = 10\n\
directory_fetch_base_delay_secs = 1\n\
directory_fetch_max_delay_secs = 10\n\
poll_attempts = 15\n\
poll_interval_secs = 2\n\
http_responder_url = \"{responder_url}\"\n\
http_responder_hmac = \"\"\n\
http_responder_timeout_secs = 5\n\
http_responder_token_ttl_secs = 300\n",
        email = args.agent_email,
        server = args.agent_server,
        domain = args.agent_domain,
        responder_url = args.agent_responder_url,
    )
}

fn render_managed_profile_block(
    service_name: &str,
    instance_id: &str,
    hostname: &str,
    cert_path: &Path,
    key_path: &Path,
) -> String {
    render_profile(
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        service_name,
        instance_id,
        hostname,
        cert_path,
        key_path,
    )
}

fn upsert_managed_profile_block(contents: &str, service_name: &str, replacement: &str) -> String {
    upsert_shared_managed_profile_block(
        contents,
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        service_name,
        replacement,
    )
}

pub(super) fn build_ctmpl_content(contents: &str, kv_mount: &str, service_name: &str) -> String {
    build_managed_agent_ctmpl(contents, kv_mount, service_name)
}

fn build_trust_updates(
    fingerprints: &[String],
    ca_bundle_path: &Path,
) -> Vec<(&'static str, String)> {
    build_shared_trust_updates(fingerprints, ca_bundle_path)
}

async fn write_openbao_agent_artifacts(
    args: &ResolvedBootstrapArgs,
    agent_template: &str,
    lang: Locale,
) -> Result<()> {
    let secret_service_dir = args.secret_id_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "secret_id path has no parent",
                "secret_id 경로에 상위 디렉터리가 없습니다",
            )
        )
    })?;
    let secrets_services_dir = secret_service_dir.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "secret_id path missing services directory",
                "secret_id 경로에 services 디렉터리가 없습니다",
            )
        )
    })?;
    let secrets_dir = secrets_services_dir.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "secret_id path missing secrets root",
                "secret_id 경로에 secrets 루트가 없습니다",
            )
        )
    })?;
    let openbao_service_dir = secrets_dir
        .join("openbao")
        .join("services")
        .join(&args.service_name);
    fs_util::ensure_secrets_dir(&openbao_service_dir).await?;

    let template_path = openbao_service_dir.join("agent.toml.ctmpl");
    let bundle_template_path = openbao_service_dir.join("ca-bundle.pem.ctmpl");
    let token_path = openbao_service_dir.join("token");
    let config_path = openbao_service_dir.join("agent.hcl");

    let ctmpl = build_ctmpl_content(agent_template, &args.kv_mount, &args.service_name);
    fs::write(&template_path, ctmpl).await?;
    fs_util::set_key_permissions(&template_path).await?;
    let bundle_ctmpl = build_ca_bundle_ctmpl(&args.kv_mount, &args.service_name);
    fs::write(&bundle_template_path, bundle_ctmpl).await?;
    fs_util::set_key_permissions(&bundle_template_path).await?;
    if !token_path.exists() {
        fs::write(&token_path, "").await?;
    }
    fs_util::set_key_permissions(&token_path).await?;
    let config = render_openbao_agent_config(
        &args.openbao_url,
        &args.role_id_path,
        &args.secret_id_path,
        &token_path,
        &[
            (&template_path, &args.agent_config_path),
            (&bundle_template_path, &args.ca_bundle_path),
        ],
    );
    fs::write(&config_path, config).await?;
    fs_util::set_key_permissions(&config_path).await?;
    Ok(())
}

fn render_openbao_agent_config(
    openbao_url: &str,
    role_id_path: &Path,
    secret_id_path: &Path,
    token_path: &Path,
    template_specs: &[(&Path, &Path)],
) -> String {
    let role_id = role_id_path.display().to_string();
    let secret_id = secret_id_path.display().to_string();
    let token = token_path.display().to_string();
    let template_strings = template_specs
        .iter()
        .map(|(source, destination)| {
            (
                source.display().to_string(),
                destination.display().to_string(),
            )
        })
        .collect::<Vec<_>>();
    let templates = template_strings
        .iter()
        .map(|(source, destination)| (source.as_str(), destination.as_str()))
        .collect::<Vec<_>>();
    build_agent_config(&AgentConfigParams {
        openbao_addr: openbao_url,
        role_id_path: &role_id,
        secret_id_path: &secret_id,
        token_path: &token,
        mount_path: Some("auth/approle"),
        render_interval: STATIC_SECRET_RENDER_INTERVAL,
        templates: &templates,
        ca_cert: None,
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::*;
    use crate::OutputFormat;

    #[test]
    fn upsert_toml_section_keys_updates_existing_section() {
        let input = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let output = bootroot::toml_util::upsert_section_keys(
            input,
            "acme",
            &[("http_responder_hmac", "new".to_string())],
        )
        .unwrap();
        assert!(output.contains("http_responder_hmac = \"new\""));
    }

    #[test]
    fn upsert_toml_section_keys_adds_new_section() {
        let input = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let updates = build_trust_updates(&["a".repeat(64)], Path::new("certs/ca.pem"));
        let output = bootroot::toml_util::upsert_section_keys(input, "trust", &updates).unwrap();
        assert!(output.contains("[trust]"));
        assert!(output.contains("ca_bundle_path = \"certs/ca.pem\""));
        assert!(output.contains("trusted_ca_sha256 = ["));
    }

    fn test_bootstrap_args() -> ResolvedBootstrapArgs {
        ResolvedBootstrapArgs {
            openbao_url: "https://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            service_name: "edge-proxy".to_string(),
            role_id_path: PathBuf::from("/tmp/role_id"),
            secret_id_path: PathBuf::from("/tmp/secrets/services/edge-proxy/secret_id"),
            eab_file_path: PathBuf::from("/tmp/eab.json"),
            agent_config_path: PathBuf::from("/tmp/agent.toml"),
            agent_email: "admin@example.com".to_string(),
            agent_server: "https://localhost:9443".to_string(),
            agent_domain: "example.com".to_string(),
            agent_responder_url: "http://localhost:8080".to_string(),
            profile_hostname: "localhost".to_string(),
            profile_instance_id: Some("001".to_string()),
            profile_cert_path: None,
            profile_key_path: None,
            ca_bundle_path: PathBuf::from("/tmp/ca-bundle.pem"),
            ca_bundle_pem: None,
            post_renew_command: None,
            post_renew_arg: Vec::new(),
            post_renew_timeout_secs: None,
            post_renew_on_failure: None,
            output: OutputFormat::Text,
            wrap_token: None,
            wrap_expires_at: None,
        }
    }

    #[test]
    fn inject_hooks_escapes_control_characters() {
        let mut args = test_bootstrap_args();
        args.post_renew_command = Some("echo\nnext".to_string());
        args.post_renew_arg = vec!["line1\tline2".to_string()];
        args.post_renew_timeout_secs = Some(10);

        let prefix = MANAGED_PROFILE_BEGIN_PREFIX;
        let suffix = MANAGED_PROFILE_END_PREFIX;
        let block = format!(
            "{prefix} edge-proxy\n[[profiles]]\nservice_name = \"edge-proxy\"\n{suffix} edge-proxy\n",
        );
        let result = inject_hooks_into_profile_block(&block, &args);

        // Extract just the hook section and parse it as TOML.
        let wrapped = format!(
            "[profiles]\n[profiles.hooks]\n[profiles.hooks.post_renew]{}",
            &result[result
                .find("\n[[profiles.hooks.post_renew.success]]")
                .expect("hook header must exist")..]
                .split(MANAGED_PROFILE_END_PREFIX)
                .next()
                .unwrap()
        );
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
        let args_arr = hook["args"].as_array().expect("args must be an array");
        assert_eq!(args_arr.get(0).unwrap().as_str().unwrap(), "line1\tline2");
    }

    #[test]
    fn render_openbao_agent_config_emits_durable_secret_id_and_both_templates() {
        let role_id_path = PathBuf::from("/secrets/services/edge/role_id");
        let secret_id_path = PathBuf::from("/secrets/services/edge/secret_id");
        let token_path = PathBuf::from("/secrets/openbao/services/edge/token");
        let agent_template = PathBuf::from("/secrets/openbao/services/edge/agent.toml.ctmpl");
        let agent_dest = PathBuf::from("/etc/bootroot-agent/agent.toml");
        let bundle_template = PathBuf::from("/secrets/openbao/services/edge/ca-bundle.pem.ctmpl");
        let bundle_dest = PathBuf::from("/etc/bootroot-agent/ca-bundle.pem");

        let hcl = render_openbao_agent_config(
            "https://openbao.example.com:8200",
            &role_id_path,
            &secret_id_path,
            &token_path,
            &[
                (&agent_template, &agent_dest),
                (&bundle_template, &bundle_dest),
            ],
        );

        assert!(
            hcl.contains("remove_secret_id_file_after_reading = false"),
            "remote HCL must keep secret_id file across agent restarts"
        );
        assert_eq!(
            hcl.matches("template {").count(),
            2,
            "remote HCL must emit both template blocks"
        );
        assert!(
            hcl.contains(r#"source = "/secrets/openbao/services/edge/agent.toml.ctmpl""#),
            "missing agent template source"
        );
        assert!(
            hcl.contains(r#"destination = "/etc/bootroot-agent/agent.toml""#),
            "missing agent template destination"
        );
        assert!(
            hcl.contains(r#"source = "/secrets/openbao/services/edge/ca-bundle.pem.ctmpl""#),
            "missing ca-bundle template source"
        );
        assert!(
            hcl.contains(r#"destination = "/etc/bootroot-agent/ca-bundle.pem""#),
            "missing ca-bundle template destination"
        );
    }

    /// Pins the remote-bootstrap renderer to the same shared primitive
    /// the local-file renderer uses, so future additions to one side
    /// cannot silently drop from the other.
    #[test]
    fn render_openbao_agent_config_matches_shared_primitive_output() {
        let role_id_path = PathBuf::from("/secrets/services/edge/role_id");
        let secret_id_path = PathBuf::from("/secrets/services/edge/secret_id");
        let token_path = PathBuf::from("/secrets/openbao/services/edge/token");
        let agent_template = PathBuf::from("/secrets/openbao/services/edge/agent.toml.ctmpl");
        let agent_dest = PathBuf::from("/etc/bootroot-agent/agent.toml");
        let bundle_template = PathBuf::from("/secrets/openbao/services/edge/ca-bundle.pem.ctmpl");
        let bundle_dest = PathBuf::from("/etc/bootroot-agent/ca-bundle.pem");

        let remote = render_openbao_agent_config(
            "http://localhost:8200",
            &role_id_path,
            &secret_id_path,
            &token_path,
            &[
                (&agent_template, &agent_dest),
                (&bundle_template, &bundle_dest),
            ],
        );

        let agent_template_str = agent_template.display().to_string();
        let agent_dest_str = agent_dest.display().to_string();
        let bundle_template_str = bundle_template.display().to_string();
        let bundle_dest_str = bundle_dest.display().to_string();
        let role_id_str = role_id_path.display().to_string();
        let secret_id_path_str = secret_id_path.display().to_string();
        let token_str = token_path.display().to_string();
        let templates = [
            (agent_template_str.as_str(), agent_dest_str.as_str()),
            (bundle_template_str.as_str(), bundle_dest_str.as_str()),
        ];
        let canonical = build_agent_config(&AgentConfigParams {
            openbao_addr: "http://localhost:8200",
            role_id_path: &role_id_str,
            secret_id_path: &secret_id_path_str,
            token_path: &token_str,
            mount_path: Some("auth/approle"),
            render_interval: STATIC_SECRET_RENDER_INTERVAL,
            templates: &templates,
            ca_cert: None,
        });

        assert_eq!(
            remote, canonical,
            "remote-bootstrap HCL must equal the shared primitive output for the same input"
        );
    }
}
