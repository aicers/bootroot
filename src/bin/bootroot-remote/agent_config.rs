use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::Result;
use bootroot::fs_util;
use bootroot::trust_bootstrap::{
    build_managed_agent_ctmpl, build_trust_updates as build_shared_trust_updates,
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
    let openbao_pairs = build_openbao_updates(args, &trust_updated);
    let openbao_updated =
        match bootroot::toml_util::upsert_section_keys(&trust_updated, "openbao", &openbao_pairs) {
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
        upsert_managed_profile_block(&openbao_updated, &args.service_name, &profile_block);

    let responder_changed = hmac_updated != agent_config;
    let trust_changed = trust_updated != hmac_updated;
    let profile_changed = with_profile != openbao_updated;

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

/// Builds the `[openbao]` key-value pairs that `bootroot-remote bootstrap`
/// upserts into `agent.toml`. This provisions the fast-poll loop on every
/// remote-bootstrap host so `bootroot rotate force-reissue` has a
/// guaranteed consumer — otherwise the control-plane KV write would land
/// in a section nobody reads. Connection-level fields are always
/// refreshed. A stable absolute `state_path` adjacent to `agent.toml` is
/// provisioned only when the operator has not already set one — the
/// in-tree default is a bare relative filename resolved against the
/// agent process cwd, which is unsafe under systemd-style supervisors
/// where the cwd can change or be unwritable. Operator-tuned
/// `fast_poll_interval` or `state_path` entries are preserved.
fn build_openbao_updates(
    args: &ResolvedBootstrapArgs,
    current_contents: &str,
) -> Vec<(&'static str, String)> {
    let mut pairs = vec![
        ("url", args.openbao_url.clone()),
        ("kv_mount", args.kv_mount.clone()),
        ("role_id_path", args.role_id_path.display().to_string()),
        ("secret_id_path", args.secret_id_path.display().to_string()),
        ("ca_bundle_path", args.ca_bundle_path.display().to_string()),
    ];
    // Provision an absolute `state_path` when either (a) the key is
    // missing, or (b) the existing value is relative. Case (b) catches
    // legacy configs (written before bootstrap provisioned the key) and
    // operator-edited configs that accidentally left the default
    // relative filename in place — rerunning `bootroot-remote bootstrap`
    // must be able to repair them, otherwise the validation hint
    // pointing operators at bootstrap would be misleading.
    if needs_absolute_state_path_provisioning(current_contents)
        && let Some(path) = default_state_path_for(args)
    {
        pairs.push(("state_path", path));
    }
    pairs
}

fn needs_absolute_state_path_provisioning(contents: &str) -> bool {
    let Ok(doc) = contents.parse::<toml_edit::DocumentMut>() else {
        return true;
    };
    let Some(table) = doc.get("openbao").and_then(toml_edit::Item::as_table) else {
        return true;
    };
    let Some(item) = table.get("state_path") else {
        return true;
    };
    let Some(value) = item.as_str() else {
        // A non-string `state_path` is malformed; overwrite with the
        // provisioned absolute default rather than leaving it invalid.
        return true;
    };
    !Path::new(value).is_absolute()
}

/// Returns an absolute `state_path` adjacent to `agent.toml` when the
/// agent config path is absolute, or `None` when it is relative. A
/// relative agent config path would yield an equally-cwd-dependent
/// state path, which is exactly what this provisioning is meant to
/// avoid; leaving `state_path` unset lets the existing validation
/// surface the issue instead of silently entrenching a fragile path.
fn default_state_path_for(args: &ResolvedBootstrapArgs) -> Option<String> {
    let parent = args.agent_config_path.parent()?;
    if !parent.is_absolute() {
        return None;
    }
    Some(
        parent
            .join("bootroot-agent-state.json")
            .display()
            .to_string(),
    )
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
    fn build_openbao_updates_covers_connection_fields() {
        let args = test_bootstrap_args();
        let pairs = build_openbao_updates(&args, "");
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            keys,
            vec![
                "url",
                "kv_mount",
                "role_id_path",
                "secret_id_path",
                "ca_bundle_path",
                "state_path",
            ]
        );
    }

    #[test]
    fn build_openbao_updates_render_upserts_into_empty_config() {
        let args = test_bootstrap_args();
        let pairs = build_openbao_updates(&args, "");
        let output = bootroot::toml_util::upsert_section_keys("", "openbao", &pairs).unwrap();
        assert!(output.contains("[openbao]"), "{output}");
        assert!(
            output.contains("url = \"https://localhost:8200\""),
            "{output}"
        );
        assert!(output.contains("kv_mount = \"secret\""), "{output}");
        assert!(
            output.contains("role_id_path = \"/tmp/role_id\""),
            "{output}"
        );
        assert!(
            output.contains("secret_id_path = \"/tmp/secrets/services/edge-proxy/secret_id\""),
            "{output}"
        );
        assert!(
            output.contains("ca_bundle_path = \"/tmp/ca-bundle.pem\""),
            "{output}"
        );
    }

    #[test]
    fn build_openbao_updates_provisions_absolute_state_path_when_missing() {
        // Agent config has [openbao] but no state_path — bootstrap must
        // provision an absolute path adjacent to agent.toml so the
        // fast-poll restart-persistence guarantee does not depend on
        // the agent process cwd. This is the no-state_path case
        // flagged in Round 5 review.
        let args = test_bootstrap_args();
        let input = "[openbao]\nurl = \"https://stale:8200\"\n";
        let pairs = build_openbao_updates(&args, input);
        let state_path_pair = pairs
            .iter()
            .find(|(k, _)| *k == "state_path")
            .expect("state_path must be provisioned when missing");
        let rendered = &state_path_pair.1;
        assert!(
            std::path::Path::new(rendered).is_absolute(),
            "state_path should be absolute: {rendered}"
        );
        assert_eq!(rendered, "/tmp/bootroot-agent-state.json");

        let output = bootroot::toml_util::upsert_section_keys(input, "openbao", &pairs).unwrap();
        assert!(
            output.contains("state_path = \"/tmp/bootroot-agent-state.json\""),
            "{output}"
        );
    }

    #[test]
    fn build_openbao_updates_skips_state_path_when_agent_config_relative() {
        // If agent_config_path is relative, derive-and-provision would
        // produce a cwd-relative state_path, which is the failure mode
        // we're avoiding. Leave state_path unset so validation surfaces
        // the issue rather than entrenching a fragile path.
        let mut args = test_bootstrap_args();
        args.agent_config_path = PathBuf::from("agent.toml");
        let pairs = build_openbao_updates(&args, "");
        let keys: Vec<&str> = pairs.iter().map(|(k, _)| *k).collect();
        assert!(
            !keys.contains(&"state_path"),
            "state_path must not be provisioned when agent_config_path is relative: {keys:?}"
        );
    }

    /// End-to-end regression test for Round 6: a bootstrap run where
    /// `agent_config_path` is relative must not produce a valid config.
    /// `build_openbao_updates` deliberately skips provisioning
    /// `state_path` in that case to avoid entrenching a cwd-relative
    /// path; the config layer then falls back to a cwd-relative default,
    /// which `validate_openbao_settings` must reject. Before the
    /// validation guardrail, the resulting config would load and run
    /// with an unsafe state file.
    #[test]
    fn config_built_from_relative_agent_config_path_fails_validation() {
        let mut args = test_bootstrap_args();
        args.agent_config_path = PathBuf::from("agent.toml");
        // Round out the remaining required-field surface so the only
        // thing under test is the state_path absolute-path invariant.
        let pairs = build_openbao_updates(&args, "");
        let rendered = bootroot::toml_util::upsert_section_keys("", "openbao", &pairs).unwrap();
        assert!(
            !rendered.contains("state_path"),
            "bootstrap must skip state_path when agent_config_path is relative: {rendered}"
        );

        let config = format!(
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

            {rendered}
            "#
        );

        let tmp = tempfile::Builder::new().suffix(".toml").tempfile().unwrap();
        std::fs::write(tmp.path(), config).unwrap();
        let settings = bootroot::config::Settings::new(Some(tmp.path().to_path_buf())).unwrap();
        let err = settings
            .validate()
            .expect_err("validation must reject cwd-relative state_path");
        let msg = err.to_string();
        assert!(msg.contains("openbao.state_path"), "{msg}");
        assert!(msg.contains("absolute"), "{msg}");
    }

    #[test]
    fn build_openbao_updates_preserves_operator_tuned_keys() {
        let args = test_bootstrap_args();
        let input = "[openbao]\n\
            url = \"https://stale:8200\"\n\
            fast_poll_interval = \"5s\"\n\
            state_path = \"/var/lib/bootroot/custom-state.json\"\n";
        let output = bootroot::toml_util::upsert_section_keys(
            input,
            "openbao",
            &build_openbao_updates(&args, input),
        )
        .unwrap();
        // Connection fields are overwritten with fresh bootstrap values.
        assert!(
            output.contains("url = \"https://localhost:8200\""),
            "{output}"
        );
        // Operator-tuned keys stay untouched.
        assert!(output.contains("fast_poll_interval = \"5s\""), "{output}");
        assert!(
            output.contains("state_path = \"/var/lib/bootroot/custom-state.json\""),
            "{output}"
        );
    }

    #[test]
    fn build_openbao_updates_repairs_relative_state_path() {
        // Round 8 regression: a legacy config may already carry a
        // relative `state_path` (e.g. the in-tree default filename, or
        // an operator edit). Rerunning `bootroot-remote bootstrap` must
        // repair it in place, otherwise the validation hint pointing
        // operators at bootstrap is misleading.
        let args = test_bootstrap_args();
        let input = "[openbao]\n\
            url = \"https://stale:8200\"\n\
            state_path = \"bootroot-agent-state.json\"\n";
        let pairs = build_openbao_updates(&args, input);
        let state_path_pair = pairs
            .iter()
            .find(|(k, _)| *k == "state_path")
            .expect("state_path must be repaired when existing value is relative");
        assert!(
            std::path::Path::new(&state_path_pair.1).is_absolute(),
            "state_path should be absolute after repair: {}",
            state_path_pair.1
        );
        let output = bootroot::toml_util::upsert_section_keys(input, "openbao", &pairs).unwrap();
        assert!(
            output.contains("state_path = \"/tmp/bootroot-agent-state.json\""),
            "{output}"
        );
        assert!(
            !output.contains("state_path = \"bootroot-agent-state.json\""),
            "relative value must be replaced, not kept alongside the absolute one: {output}"
        );
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
}
