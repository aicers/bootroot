use std::path::{Path, PathBuf};

use anyhow::Result;
use bootroot::fs_util;
use tokio::fs;

use super::io::PulledSecrets;
use super::summary::{ApplyItemSummary, ApplyStatus};
use super::{
    BootstrapArgs, Locale, MANAGED_PROFILE_BEGIN_PREFIX, MANAGED_PROFILE_END_PREFIX,
    SERVICE_KV_BASE, TRUSTED_CA_KEY, localized,
};

struct ProfilePaths {
    cert_path: PathBuf,
    key_path: PathBuf,
}

// This function intentionally centralizes agent config mutation flow so
// per-item status/error mapping remains consistent for summary JSON contracts.
#[allow(clippy::too_many_lines)]
pub(super) async fn apply_agent_config_updates(
    args: &BootstrapArgs,
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
    let trust_pairs =
        build_trust_updates(&pulled.trusted_ca_sha256, args.ca_bundle_path.as_deref());
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
    let with_profile = upsert_managed_profile_block(
        &trust_updated,
        &args.service_name,
        &render_managed_profile_block(
            &args.service_name,
            args.profile_instance_id
                .as_deref()
                .expect("validate_bootstrap_args requires profile_instance_id"),
            &args.profile_hostname,
            &profile_paths.cert_path,
            &profile_paths.key_path,
        ),
    );

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

fn resolve_profile_paths(args: &BootstrapArgs) -> ProfilePaths {
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

fn render_agent_config_baseline(args: &BootstrapArgs) -> String {
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
    format!(
        "{MANAGED_PROFILE_BEGIN_PREFIX} {service_name}\n\
[[profiles]]\n\
service_name = \"{service_name}\"\n\
instance_id = \"{instance_id}\"\n\
hostname = \"{hostname}\"\n\n\
[profiles.paths]\n\
cert = \"{cert}\"\n\
key = \"{key}\"\n\
{MANAGED_PROFILE_END_PREFIX} {service_name}\n",
        cert = cert_path.display(),
        key = key_path.display(),
    )
}

fn upsert_managed_profile_block(contents: &str, service_name: &str, replacement: &str) -> String {
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

pub(super) fn build_ctmpl_content(contents: &str, kv_mount: &str, service_name: &str) -> String {
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
    let with_trust =
        replace_key_line_in_section(&without_eab, "trust", TRUSTED_CA_KEY, &trust_template_line);

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

fn build_trust_updates(
    fingerprints: &[String],
    ca_bundle_path: Option<&Path>,
) -> Vec<(&'static str, String)> {
    let mut updates = Vec::new();
    if let Some(path) = ca_bundle_path {
        updates.push(("ca_bundle_path", path.display().to_string()));
    }
    updates.push((
        TRUSTED_CA_KEY,
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

async fn write_openbao_agent_artifacts(
    args: &BootstrapArgs,
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
    let token_path = openbao_service_dir.join("token");
    let config_path = openbao_service_dir.join("agent.hcl");

    let ctmpl = build_ctmpl_content(agent_template, &args.kv_mount, &args.service_name);
    fs::write(&template_path, ctmpl).await?;
    fs_util::set_key_permissions(&template_path).await?;
    if !token_path.exists() {
        fs::write(&token_path, "").await?;
    }
    fs_util::set_key_permissions(&token_path).await?;
    let config = render_openbao_agent_config(
        &args.openbao_url,
        &args.role_id_path,
        &args.secret_id_path,
        &token_path,
        &template_path,
        &args.agent_config_path,
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
    template_path: &Path,
    destination_path: &Path,
) -> String {
    format!(
        r#"vault {{
  address = "{openbao_url}"
}}

auto_auth {{
  method "approle" {{
    mount_path = "auth/approle"
    config = {{
      role_id_file_path = "{role_id_path}"
      secret_id_file_path = "{secret_id_path}"
    }}
  }}
  sink "file" {{
    config = {{
      path = "{token_path}"
    }}
  }}
}}

template {{
  source = "{template_path}"
  destination = "{destination_path}"
  perms = "0600"
}}
"#,
        openbao_url = openbao_url,
        role_id_path = role_id_path.display(),
        secret_id_path = secret_id_path.display(),
        token_path = token_path.display(),
        template_path = template_path.display(),
        destination_path = destination_path.display(),
    )
}

fn is_section_header(value: &str) -> bool {
    value.starts_with('[') && value.ends_with(']')
}

#[cfg(test)]
mod tests {
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
        let output = bootroot::toml_util::upsert_section_keys(
            input,
            "trust",
            &[("ca_bundle_path", "certs/ca.pem".to_string())],
        )
        .unwrap();
        assert!(output.contains("[trust]"));
        assert!(output.contains("ca_bundle_path = \"certs/ca.pem\""));
    }
}
