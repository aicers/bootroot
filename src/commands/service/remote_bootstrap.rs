use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use tokio::fs;

use super::resolve::ResolvedServiceAdd;
use super::{
    DEFAULT_AGENT_EMAIL, DEFAULT_AGENT_RESPONDER_URL, DEFAULT_AGENT_SERVER,
    OPENBAO_AGENT_CONFIG_FILENAME, OPENBAO_AGENT_TEMPLATE_FILENAME, OPENBAO_AGENT_TOKEN_FILENAME,
    OPENBAO_SERVICE_CONFIG_DIR, REMOTE_BOOTSTRAP_DIR, REMOTE_BOOTSTRAP_FILENAME,
    RemoteBootstrapResult, SERVICE_ROLE_ID_FILENAME,
};
use crate::i18n::Messages;
use crate::state::{PostRenewHookEntry, ServiceEntry, StateFile};

/// Machine-readable bootstrap artifact written to
/// `secrets/remote-bootstrap/services/<service>/bootstrap.json`.
///
/// Downstream automation (shell scripts, Ansible, CI pipelines) can parse
/// this JSON to drive `bootroot-remote bootstrap` invocations.
///
/// # `schema_version` contract
///
/// * The field starts at `1` and is bumped whenever the struct gains,
///   removes, or renames a field in a way that would break existing
///   parsers.
/// * Additive changes that only append new *optional* fields (i.e.
///   fields with `#[serde(default)]` or `skip_serializing_if`) do **not**
///   require a bump — existing parsers will simply ignore unknown keys.
/// * Consumers should check `schema_version` before accessing fields and
///   fail explicitly if the version is higher than what they support.
#[derive(serde::Serialize)]
struct RemoteBootstrapArtifact {
    schema_version: u32,
    openbao_url: String,
    kv_mount: String,
    service_name: String,
    role_id_path: String,
    secret_id_path: String,
    eab_file_path: String,
    agent_config_path: String,
    ca_bundle_path: String,
    openbao_agent_config_path: String,
    openbao_agent_template_path: String,
    openbao_agent_token_path: String,
    agent_email: String,
    agent_server: String,
    agent_domain: String,
    agent_responder_url: String,
    profile_hostname: String,
    profile_instance_id: String,
    profile_cert_path: String,
    profile_key_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    post_renew_hooks: Vec<PostRenewHookEntry>,
}

/// Builds a `RemoteBootstrapArtifact` from common inputs shared by both
/// the initial service-add and the idempotent re-run paths.
#[allow(clippy::too_many_arguments)] // mirrors the many fields of RemoteBootstrapArtifact
fn build_artifact(
    openbao_url: &str,
    kv_mount: &str,
    service_name: &str,
    secret_id_path: &Path,
    agent_config_path: &Path,
    cert_path: &Path,
    key_path: &Path,
    domain: &str,
    hostname: &str,
    instance_id: Option<&str>,
    post_renew_hooks: &[PostRenewHookEntry],
) -> RemoteBootstrapArtifact {
    let secret_id_parent = secret_id_path.parent().unwrap_or(Path::new("."));
    let role_id_path = secret_id_parent.join(SERVICE_ROLE_ID_FILENAME);
    let eab_path = secret_id_parent.join("eab.json");
    let ca_bundle_path = cert_path
        .parent()
        .unwrap_or(Path::new("certs"))
        .join("ca-bundle.pem");
    let (openbao_agent_config_path, openbao_agent_template_path, openbao_agent_token_path) =
        remote_openbao_agent_paths(secret_id_path, service_name);

    RemoteBootstrapArtifact {
        schema_version: 1,
        openbao_url: openbao_url.to_string(),
        kv_mount: kv_mount.to_string(),
        service_name: service_name.to_string(),
        role_id_path: role_id_path.display().to_string(),
        secret_id_path: secret_id_path.display().to_string(),
        eab_file_path: eab_path.display().to_string(),
        agent_config_path: agent_config_path.display().to_string(),
        ca_bundle_path: ca_bundle_path.display().to_string(),
        openbao_agent_config_path: openbao_agent_config_path.display().to_string(),
        openbao_agent_template_path: openbao_agent_template_path.display().to_string(),
        openbao_agent_token_path: openbao_agent_token_path.display().to_string(),
        agent_email: DEFAULT_AGENT_EMAIL.to_string(),
        agent_server: DEFAULT_AGENT_SERVER.to_string(),
        agent_domain: domain.to_string(),
        agent_responder_url: DEFAULT_AGENT_RESPONDER_URL.to_string(),
        profile_hostname: hostname.to_string(),
        profile_instance_id: instance_id.unwrap_or_default().to_string(),
        profile_cert_path: cert_path.display().to_string(),
        profile_key_path: key_path.display().to_string(),
        post_renew_hooks: post_renew_hooks.to_vec(),
    }
}

pub(super) async fn write_remote_bootstrap_artifact(
    state: &StateFile,
    secrets_dir: &Path,
    resolved: &ResolvedServiceAdd,
    secret_id_path: &Path,
    messages: &Messages,
) -> Result<RemoteBootstrapResult> {
    let artifact = build_artifact(
        &state.openbao_url,
        &state.kv_mount,
        &resolved.service_name,
        secret_id_path,
        &resolved.agent_config,
        &resolved.cert_path,
        &resolved.key_path,
        &resolved.domain,
        &resolved.hostname,
        resolved.instance_id.as_deref(),
        &resolved.post_renew_hooks,
    );
    write_remote_bootstrap_artifact_file(secrets_dir, &resolved.service_name, &artifact, messages)
        .await
}

pub(super) async fn write_remote_bootstrap_artifact_from_entry(
    state: &StateFile,
    secrets_dir: &Path,
    entry: &ServiceEntry,
    messages: &Messages,
) -> Result<RemoteBootstrapResult> {
    let artifact = build_artifact(
        &state.openbao_url,
        &state.kv_mount,
        &entry.service_name,
        &entry.approle.secret_id_path,
        &entry.agent_config_path,
        &entry.cert_path,
        &entry.key_path,
        &entry.domain,
        &entry.hostname,
        entry.instance_id.as_deref(),
        &entry.post_renew_hooks,
    );
    write_remote_bootstrap_artifact_file(secrets_dir, &entry.service_name, &artifact, messages)
        .await
}

async fn write_remote_bootstrap_artifact_file(
    secrets_dir: &Path,
    service_name: &str,
    artifact: &RemoteBootstrapArtifact,
    messages: &Messages,
) -> Result<RemoteBootstrapResult> {
    let artifact_dir = secrets_dir.join(REMOTE_BOOTSTRAP_DIR).join(service_name);
    fs_util::ensure_secrets_dir(&artifact_dir).await?;
    let artifact_path = artifact_dir.join(REMOTE_BOOTSTRAP_FILENAME);
    let payload = serde_json::to_string_pretty(artifact)
        .with_context(|| "Failed to serialize remote bootstrap artifact".to_string())?;
    fs::write(&artifact_path, payload)
        .await
        .with_context(|| messages.error_write_file_failed(&artifact_path.display().to_string()))?;
    fs_util::set_key_permissions(&artifact_path).await?;
    let remote_run_command = render_remote_run_command(artifact);
    Ok(RemoteBootstrapResult {
        bootstrap_file: artifact_path.display().to_string(),
        remote_run_command,
    })
}

fn render_remote_run_command(artifact: &RemoteBootstrapArtifact) -> String {
    let mut cmd = format!(
        "bootroot-remote bootstrap --openbao-url '{}' --kv-mount '{}' --service-name '{}' --role-id-path '{}' --secret-id-path '{}' --eab-file-path '{}' --agent-config-path '{}' --agent-email '{}' --agent-server '{}' --agent-domain '{}' --agent-responder-url '{}' --profile-hostname '{}' --profile-instance-id '{}' --profile-cert-path '{}' --profile-key-path '{}' --ca-bundle-path '{}'",
        artifact.openbao_url,
        artifact.kv_mount,
        artifact.service_name,
        artifact.role_id_path,
        artifact.secret_id_path,
        artifact.eab_file_path,
        artifact.agent_config_path,
        artifact.agent_email,
        artifact.agent_server,
        artifact.agent_domain,
        artifact.agent_responder_url,
        artifact.profile_hostname,
        artifact.profile_instance_id,
        artifact.profile_cert_path,
        artifact.profile_key_path,
        artifact.ca_bundle_path,
    );
    if let Some(hook) = artifact.post_renew_hooks.first() {
        let _ = write!(
            cmd,
            " --post-renew-command '{}'",
            shell_escape_single_quoted(&hook.command)
        );
        for arg in &hook.args {
            let _ = write!(
                cmd,
                " --post-renew-arg '{}'",
                shell_escape_single_quoted(arg)
            );
        }
        let _ = write!(cmd, " --post-renew-timeout-secs {}", hook.timeout_secs);
        let _ = write!(
            cmd,
            " --post-renew-on-failure '{}'",
            shell_escape_single_quoted(&hook.on_failure.to_string())
        );
    }
    cmd.push_str(" --output json");
    cmd
}

/// Escapes a string for embedding inside single quotes in a POSIX shell
/// command. Replaces each `'` with `'\''` (end quote, literal quote,
/// resume quote).
fn shell_escape_single_quoted(value: &str) -> String {
    value.replace('\'', "'\\''")
}

fn remote_openbao_agent_paths(
    secret_id_path: &Path,
    service_name: &str,
) -> (PathBuf, PathBuf, PathBuf) {
    let secret_service_dir = secret_id_path.parent().unwrap_or_else(|| Path::new("."));
    let services_dir = secret_service_dir
        .parent()
        .unwrap_or_else(|| Path::new("."));
    let secrets_dir = services_dir.parent().unwrap_or_else(|| Path::new("."));
    let openbao_service_dir = secrets_dir
        .join(OPENBAO_SERVICE_CONFIG_DIR)
        .join(service_name);
    (
        openbao_service_dir.join(OPENBAO_AGENT_CONFIG_FILENAME),
        openbao_service_dir.join(OPENBAO_AGENT_TEMPLATE_FILENAME),
        openbao_service_dir.join(OPENBAO_AGENT_TOKEN_FILENAME),
    )
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::build_artifact;

    #[test]
    fn build_artifact_typical_case() {
        let artifact = build_artifact(
            "https://openbao.example.com:8200",
            "secret",
            "my-service",
            Path::new("/secrets/services/my-service/secret_id"),
            Path::new("/etc/my-service/agent.toml"),
            Path::new("/certs/my-service/cert.pem"),
            Path::new("/certs/my-service/key.pem"),
            "example.com",
            "host1",
            Some("instance-42"),
            &[],
        );

        assert_eq!(artifact.schema_version, 1);
        assert_eq!(artifact.openbao_url, "https://openbao.example.com:8200");
        assert_eq!(artifact.kv_mount, "secret");
        assert_eq!(artifact.service_name, "my-service");
        assert_eq!(
            artifact.role_id_path,
            "/secrets/services/my-service/role_id"
        );
        assert_eq!(
            artifact.secret_id_path,
            "/secrets/services/my-service/secret_id"
        );
        assert_eq!(
            artifact.eab_file_path,
            "/secrets/services/my-service/eab.json"
        );
        assert_eq!(artifact.agent_config_path, "/etc/my-service/agent.toml");
        assert_eq!(artifact.ca_bundle_path, "/certs/my-service/ca-bundle.pem");
        assert_eq!(
            artifact.openbao_agent_config_path,
            "/secrets/openbao/services/my-service/agent.hcl"
        );
        assert_eq!(
            artifact.openbao_agent_template_path,
            "/secrets/openbao/services/my-service/agent.toml.ctmpl"
        );
        assert_eq!(
            artifact.openbao_agent_token_path,
            "/secrets/openbao/services/my-service/token"
        );
        assert_eq!(artifact.agent_domain, "example.com");
        assert_eq!(artifact.profile_hostname, "host1");
        assert_eq!(artifact.profile_instance_id, "instance-42");
        assert_eq!(artifact.profile_cert_path, "/certs/my-service/cert.pem");
        assert_eq!(artifact.profile_key_path, "/certs/my-service/key.pem");
    }

    #[test]
    fn build_artifact_no_instance_id() {
        let artifact = build_artifact(
            "https://openbao.local",
            "kv",
            "svc",
            Path::new("/s/services/svc/secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("/certs/svc/cert.pem"),
            Path::new("/certs/svc/key.pem"),
            "local.dev",
            "node-a",
            None,
            &[],
        );

        assert_eq!(artifact.profile_instance_id, "");
    }

    #[test]
    fn build_artifact_different_service_names_produce_different_paths() {
        let a = build_artifact(
            "https://ob",
            "kv",
            "alpha",
            Path::new("/secrets/services/alpha/secret_id"),
            Path::new("/etc/alpha/agent.toml"),
            Path::new("/certs/alpha/cert.pem"),
            Path::new("/certs/alpha/key.pem"),
            "a.com",
            "h1",
            None,
            &[],
        );
        let b = build_artifact(
            "https://ob",
            "kv",
            "beta",
            Path::new("/secrets/services/beta/secret_id"),
            Path::new("/etc/beta/agent.toml"),
            Path::new("/certs/beta/cert.pem"),
            Path::new("/certs/beta/key.pem"),
            "b.com",
            "h2",
            None,
            &[],
        );

        assert_ne!(a.role_id_path, b.role_id_path);
        assert_ne!(a.openbao_agent_config_path, b.openbao_agent_config_path);
        assert_ne!(a.ca_bundle_path, b.ca_bundle_path);
    }

    #[test]
    fn build_artifact_secret_id_path_without_parent() {
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
            Path::new("secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("/certs/cert.pem"),
            Path::new("/certs/key.pem"),
            "d.com",
            "h",
            None,
            &[],
        );

        // Path::new("secret_id").parent() returns Some(""), not None
        assert_eq!(artifact.role_id_path, "role_id");
        assert_eq!(artifact.eab_file_path, "eab.json");
    }

    #[test]
    fn build_artifact_cert_path_without_parent() {
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
            Path::new("/secrets/services/svc/secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("cert.pem"),
            Path::new("key.pem"),
            "d.com",
            "h",
            None,
            &[],
        );

        // Path::new("cert.pem").parent() returns Some(""), not None
        assert_eq!(artifact.ca_bundle_path, "ca-bundle.pem");
    }

    #[test]
    fn build_artifact_includes_hooks() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let hooks = vec![PostRenewHookEntry {
            command: "systemctl".to_string(),
            args: vec!["reload".to_string(), "nginx".to_string()],
            timeout_secs: 30,
            on_failure: HookFailurePolicyEntry::Continue,
        }];
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
            Path::new("/s/services/svc/secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("/certs/cert.pem"),
            Path::new("/certs/key.pem"),
            "d.com",
            "h",
            None,
            &hooks,
        );

        assert_eq!(artifact.post_renew_hooks.len(), 1);
        assert_eq!(artifact.post_renew_hooks[0].command, "systemctl");
        assert_eq!(artifact.post_renew_hooks[0].args, vec!["reload", "nginx"]);
    }

    #[test]
    fn render_remote_run_command_includes_hook_flags() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let hooks = vec![PostRenewHookEntry {
            command: "systemctl".to_string(),
            args: vec!["reload".to_string(), "nginx".to_string()],
            timeout_secs: 60,
            on_failure: HookFailurePolicyEntry::Stop,
        }];
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
            Path::new("/s/services/svc/secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("/certs/cert.pem"),
            Path::new("/certs/key.pem"),
            "d.com",
            "h",
            None,
            &hooks,
        );
        let cmd = super::render_remote_run_command(&artifact);

        assert!(
            cmd.contains("--post-renew-command 'systemctl'"),
            "missing --post-renew-command: {cmd}"
        );
        assert!(
            cmd.contains("--post-renew-arg 'reload'"),
            "missing first --post-renew-arg: {cmd}"
        );
        assert!(
            cmd.contains("--post-renew-arg 'nginx'"),
            "missing second --post-renew-arg: {cmd}"
        );
        assert!(
            cmd.contains("--post-renew-timeout-secs 60"),
            "missing --post-renew-timeout-secs: {cmd}"
        );
        assert!(
            cmd.contains("--post-renew-on-failure 'stop'"),
            "missing --post-renew-on-failure: {cmd}"
        );
    }

    #[test]
    fn render_remote_run_command_shell_escapes_single_quotes() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let hooks = vec![PostRenewHookEntry {
            command: "/usr/bin/notify-O'Brien".to_string(),
            args: vec!["it's".to_string(), "done".to_string()],
            timeout_secs: 30,
            on_failure: HookFailurePolicyEntry::Continue,
        }];
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
            Path::new("/s/services/svc/secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("/certs/cert.pem"),
            Path::new("/certs/key.pem"),
            "d.com",
            "h",
            None,
            &hooks,
        );
        let cmd = super::render_remote_run_command(&artifact);

        assert!(
            cmd.contains("--post-renew-command '/usr/bin/notify-O'\\''Brien'"),
            "single quote in command not escaped: {cmd}"
        );
        assert!(
            cmd.contains("--post-renew-arg 'it'\\''s'"),
            "single quote in arg not escaped: {cmd}"
        );
    }

    #[test]
    fn render_remote_run_command_omits_hook_flags_when_empty() {
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
            Path::new("/s/services/svc/secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("/certs/cert.pem"),
            Path::new("/certs/key.pem"),
            "d.com",
            "h",
            None,
            &[],
        );
        let cmd = super::render_remote_run_command(&artifact);

        assert!(
            !cmd.contains("--post-renew"),
            "should not contain hook flags: {cmd}"
        );
    }

    #[test]
    fn build_artifact_empty_instance_id_same_as_none() {
        let with_empty = build_artifact(
            "https://ob",
            "kv",
            "svc",
            Path::new("/s/services/svc/secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("/certs/cert.pem"),
            Path::new("/certs/key.pem"),
            "d.com",
            "h",
            Some(""),
            &[],
        );
        let with_none = build_artifact(
            "https://ob",
            "kv",
            "svc",
            Path::new("/s/services/svc/secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("/certs/cert.pem"),
            Path::new("/certs/key.pem"),
            "d.com",
            "h",
            None,
            &[],
        );

        assert_eq!(
            with_empty.profile_instance_id,
            with_none.profile_instance_id
        );
    }

    #[test]
    fn shell_escape_single_quoted_no_quotes_unchanged() {
        assert_eq!(super::shell_escape_single_quoted("hello"), "hello");
    }

    #[test]
    fn shell_escape_single_quoted_replaces_single_quotes() {
        assert_eq!(super::shell_escape_single_quoted("it's"), "it'\\''s");
    }

    #[test]
    fn shell_escape_single_quoted_multiple_quotes() {
        assert_eq!(super::shell_escape_single_quoted("a'b'c"), "a'\\''b'\\''c");
    }
}
