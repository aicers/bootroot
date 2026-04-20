use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use tokio::fs;

use super::resolve::ResolvedServiceAdd;
use super::{
    OPENBAO_AGENT_CONFIG_FILENAME, OPENBAO_AGENT_TEMPLATE_FILENAME, OPENBAO_AGENT_TOKEN_FILENAME,
    OPENBAO_SERVICE_CONFIG_DIR, REMOTE_BOOTSTRAP_DIR, REMOTE_BOOTSTRAP_FILENAME,
    RemoteBootstrapResult, SERVICE_ROLE_ID_FILENAME,
};
use crate::commands::guardrails::client_url_from_bind_addr;
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
    ca_bundle_pem: String,
    openbao_agent_config_path: String,
    openbao_agent_template_path: String,
    openbao_agent_token_path: String,
    /// Operator-supplied override for `email`, carried from
    /// `bootroot service add --agent-email` so that `bootroot-remote
    /// bootstrap` can distinguish "explicit override, clobber remote
    /// value" from "no override, preserve remote operator value".
    /// `None` is serialized as a missing key so the downstream parser's
    /// `#[serde(default)]` yields `Option::None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_server: Option<String>,
    agent_domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    agent_responder_url: Option<String>,
    profile_hostname: String,
    profile_instance_id: String,
    profile_cert_path: String,
    profile_key_path: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    post_renew_hooks: Vec<PostRenewHookEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrap_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wrap_expires_at: Option<String>,
}

/// Wrap-token metadata to embed in the bootstrap artifact.
pub(super) struct ArtifactWrapInfo {
    pub(super) token: String,
    pub(super) expires_at: String,
}

impl ArtifactWrapInfo {
    /// Builds from [`bootroot::openbao::WrapInfo`] by computing the
    /// expiry timestamp from `creation_time + ttl`.
    pub(super) fn from_wrap_info(info: &bootroot::openbao::WrapInfo) -> Self {
        use time::format_description::well_known::Rfc3339;
        use time::{Duration, OffsetDateTime};

        let expires_at = OffsetDateTime::parse(&info.creation_time, &Rfc3339)
            .ok()
            .and_then(|created| {
                i64::try_from(info.ttl)
                    .ok()
                    .and_then(|secs| created.checked_add(Duration::seconds(secs)))
            })
            .and_then(|dt| dt.format(&Rfc3339).ok())
            .unwrap_or_else(|| info.creation_time.clone());
        Self {
            token: info.token.clone(),
            expires_at,
        }
    }
}

/// Returns the `OpenBao` URL to embed in remote bootstrap artifacts.
///
/// Prefers `openbao_advertise_addr` (set for wildcard binds) so that
/// artifacts contain a routable address that remote nodes can reach.
/// Falls back to `openbao_url` (the CN-side URL) for non-wildcard
/// binds where the bind address is directly reachable.
fn artifact_openbao_url(state: &StateFile) -> String {
    state.openbao_advertise_addr.as_ref().map_or_else(
        || state.openbao_url.clone(),
        |addr| client_url_from_bind_addr(addr),
    )
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
    wrap_info: Option<&ArtifactWrapInfo>,
    ca_bundle_pem: &str,
    agent_email: Option<&str>,
    agent_server: Option<&str>,
    agent_responder_url: Option<&str>,
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
        schema_version: 3,
        openbao_url: openbao_url.to_string(),
        kv_mount: kv_mount.to_string(),
        service_name: service_name.to_string(),
        role_id_path: role_id_path.display().to_string(),
        secret_id_path: secret_id_path.display().to_string(),
        eab_file_path: eab_path.display().to_string(),
        agent_config_path: agent_config_path.display().to_string(),
        ca_bundle_path: ca_bundle_path.display().to_string(),
        ca_bundle_pem: ca_bundle_pem.to_string(),
        openbao_agent_config_path: openbao_agent_config_path.display().to_string(),
        openbao_agent_template_path: openbao_agent_template_path.display().to_string(),
        openbao_agent_token_path: openbao_agent_token_path.display().to_string(),
        agent_email: agent_email.map(str::to_string),
        agent_server: agent_server.map(str::to_string),
        agent_domain: domain.to_string(),
        agent_responder_url: agent_responder_url.map(str::to_string),
        profile_hostname: hostname.to_string(),
        profile_instance_id: instance_id.unwrap_or_default().to_string(),
        profile_cert_path: cert_path.display().to_string(),
        profile_key_path: key_path.display().to_string(),
        post_renew_hooks: post_renew_hooks.to_vec(),
        wrap_token: wrap_info.map(|w| w.token.clone()),
        wrap_expires_at: wrap_info.map(|w| w.expires_at.clone()),
    }
}

pub(super) async fn write_remote_bootstrap_artifact(
    state: &StateFile,
    secrets_dir: &Path,
    resolved: &ResolvedServiceAdd,
    secret_id_path: &Path,
    wrap_info: Option<&ArtifactWrapInfo>,
    ca_bundle_pem: &str,
    messages: &Messages,
) -> Result<RemoteBootstrapResult> {
    let artifact_url = artifact_openbao_url(state);
    let artifact = build_artifact(
        &artifact_url,
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
        wrap_info,
        ca_bundle_pem,
        resolved.agent_email.as_deref(),
        resolved.agent_server.as_deref(),
        resolved.agent_responder_url.as_deref(),
    );
    write_remote_bootstrap_artifact_file(secrets_dir, &resolved.service_name, &artifact, messages)
        .await
}

pub(super) async fn write_remote_bootstrap_artifact_from_entry(
    state: &StateFile,
    secrets_dir: &Path,
    entry: &ServiceEntry,
    wrap_info: Option<&ArtifactWrapInfo>,
    ca_bundle_pem: &str,
    messages: &Messages,
) -> Result<RemoteBootstrapResult> {
    let artifact_url = artifact_openbao_url(state);
    let artifact = build_artifact(
        &artifact_url,
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
        wrap_info,
        ca_bundle_pem,
        entry.agent_email.as_deref(),
        entry.agent_server.as_deref(),
        entry.agent_responder_url.as_deref(),
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
        wrapped: artifact.wrap_token.is_some(),
    })
}

/// Placeholder used in the printed command template. The operator must
/// replace it with the actual path where `bootstrap.json` lands on the
/// remote host.
const ARTIFACT_PATH_PLACEHOLDER: &str = "<REMOTE_ARTIFACT_PATH>";

fn render_remote_run_command(_artifact: &RemoteBootstrapArtifact) -> String {
    format!("bootroot-remote bootstrap --artifact '{ARTIFACT_PATH_PLACEHOLDER}' --output json")
}

/// Escapes a string for embedding inside single quotes in a POSIX shell
/// command. Replaces each `'` with `'\''` (end quote, literal quote,
/// resume quote). Only used by the legacy renderer kept for tests.
#[cfg(test)]
fn shell_escape_single_quoted(value: &str) -> String {
    value.replace('\'', "'\\''")
}

/// Renders the legacy per-flag command. Kept for test coverage of the
/// per-flag format used in backward-compatible manual invocations.
#[cfg(test)]
fn render_remote_run_command_legacy(artifact: &RemoteBootstrapArtifact) -> String {
    use std::fmt::Write as _;

    let mut cmd = format!(
        "bootroot-remote bootstrap --openbao-url '{}' --kv-mount '{}' --service-name '{}' --role-id-path '{}' --secret-id-path '{}' --eab-file-path '{}' --agent-config-path '{}' --agent-email '{}' --agent-server '{}' --agent-domain '{}' --agent-responder-url '{}' --profile-hostname '{}' --profile-instance-id '{}' --profile-cert-path '{}' --profile-key-path '{}' --ca-bundle-path '{}'",
        artifact.openbao_url,
        artifact.kv_mount,
        artifact.service_name,
        artifact.role_id_path,
        artifact.secret_id_path,
        artifact.eab_file_path,
        artifact.agent_config_path,
        artifact.agent_email.as_deref().unwrap_or(""),
        artifact.agent_server.as_deref().unwrap_or(""),
        artifact.agent_domain,
        artifact.agent_responder_url.as_deref().unwrap_or(""),
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

    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";
    const TEST_AGENT_EMAIL: &str = "test@example.com";
    const TEST_AGENT_SERVER: &str = "https://step-ca.test:9000/acme/acme/directory";
    const TEST_AGENT_RESPONDER_URL: &str = "http://127.0.0.1:8080";

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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
        );

        assert_eq!(artifact.schema_version, 3);
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
        assert_eq!(artifact.agent_email.as_deref(), Some(TEST_AGENT_EMAIL));
        assert_eq!(artifact.agent_server.as_deref(), Some(TEST_AGENT_SERVER));
        assert_eq!(
            artifact.agent_responder_url.as_deref(),
            Some(TEST_AGENT_RESPONDER_URL)
        );
        assert_eq!(artifact.profile_hostname, "host1");
        assert_eq!(artifact.profile_instance_id, "instance-42");
        assert_eq!(artifact.profile_cert_path, "/certs/my-service/cert.pem");
        assert_eq!(artifact.profile_key_path, "/certs/my-service/key.pem");
    }

    /// Locks in that operator-supplied `--agent-email` /
    /// `--agent-server` / `--agent-responder-url` values flow through
    /// to the remote-bootstrap artifact instead of getting clobbered
    /// by the compose-topology defaults.  Regression guard for
    /// issue #549 on the `remote-bootstrap` delivery path.
    #[test]
    fn build_artifact_embeds_non_default_agent_overrides() {
        const OVERRIDE_EMAIL: &str = "ops@example.org";
        const OVERRIDE_SERVER: &str = "https://step-ca.example.org:9443/acme/acme/directory";
        const OVERRIDE_RESPONDER: &str = "http://responder.internal:18080";

        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
            Path::new("/s/services/svc/secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("/certs/cert.pem"),
            Path::new("/certs/key.pem"),
            "example.org",
            "h",
            None,
            &[],
            None,
            TEST_CA_PEM,
            Some(OVERRIDE_EMAIL),
            Some(OVERRIDE_SERVER),
            Some(OVERRIDE_RESPONDER),
        );

        assert_eq!(artifact.agent_email.as_deref(), Some(OVERRIDE_EMAIL));
        assert_eq!(artifact.agent_server.as_deref(), Some(OVERRIDE_SERVER));
        assert_eq!(
            artifact.agent_responder_url.as_deref(),
            Some(OVERRIDE_RESPONDER)
        );
        // The compose-topology localhost defaults must NOT leak
        // through when the operator supplied overrides.
        assert_ne!(
            artifact.agent_server.as_deref(),
            Some(super::super::DEFAULT_AGENT_SERVER)
        );
        assert_ne!(
            artifact.agent_responder_url.as_deref(),
            Some(super::super::DEFAULT_AGENT_RESPONDER_URL)
        );
    }

    /// Pins down that when `bootroot service add` did not receive any
    /// `--agent-*` overrides (i.e. `resolved.agent_* == None`), the
    /// generated artifact omits the `agent_email` / `agent_server` /
    /// `agent_responder_url` keys rather than serializing the compiled-in
    /// localhost defaults.  This preserves the "no explicit override"
    /// signal so that `bootroot-remote bootstrap` can take the
    /// backfill-only path against a pre-existing remote `agent.toml`.
    #[test]
    fn build_artifact_omits_agent_keys_when_no_override() {
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
            Path::new("/s/services/svc/secret_id"),
            Path::new("/etc/svc/agent.toml"),
            Path::new("/certs/cert.pem"),
            Path::new("/certs/key.pem"),
            "example.org",
            "h",
            None,
            &[],
            None,
            TEST_CA_PEM,
            None,
            None,
            None,
        );

        assert!(artifact.agent_email.is_none());
        assert!(artifact.agent_server.is_none());
        assert!(artifact.agent_responder_url.is_none());

        let serialized = serde_json::to_string(&artifact).unwrap();
        assert!(
            !serialized.contains("\"agent_email\""),
            "agent_email must be omitted from serialized artifact: {serialized}"
        );
        assert!(
            !serialized.contains("\"agent_server\""),
            "agent_server must be omitted from serialized artifact: {serialized}"
        );
        assert!(
            !serialized.contains("\"agent_responder_url\""),
            "agent_responder_url must be omitted from serialized artifact: {serialized}"
        );
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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
        );
        let cmd = super::render_remote_run_command_legacy(&artifact);

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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
        );
        let cmd = super::render_remote_run_command_legacy(&artifact);

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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
        );
        let cmd = super::render_remote_run_command_legacy(&artifact);

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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
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

    #[test]
    fn build_artifact_with_wrap_info() {
        let wrap = super::ArtifactWrapInfo {
            token: "hvs.wrap-token-123".to_string(),
            expires_at: "2026-04-12T00:30:00Z".to_string(),
        };
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
            Some(&wrap),
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
        );

        assert_eq!(artifact.wrap_token.as_deref(), Some("hvs.wrap-token-123"));
        assert_eq!(
            artifact.wrap_expires_at.as_deref(),
            Some("2026-04-12T00:30:00Z")
        );
    }

    #[test]
    fn render_remote_run_command_uses_artifact_flag() {
        let wrap = super::ArtifactWrapInfo {
            token: "hvs.tok".to_string(),
            expires_at: "2026-04-12T01:00:00Z".to_string(),
        };
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
            Some(&wrap),
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
        );
        let cmd = super::render_remote_run_command(&artifact);

        assert!(
            cmd.contains("--artifact '<REMOTE_ARTIFACT_PATH>'"),
            "missing --artifact placeholder: {cmd}"
        );
        assert!(
            !cmd.contains("--openbao-url"),
            "should not contain legacy flags: {cmd}"
        );
    }

    #[test]
    fn render_remote_run_command_uses_artifact_flag_without_wrap() {
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
            None,
            TEST_CA_PEM,
            Some(TEST_AGENT_EMAIL),
            Some(TEST_AGENT_SERVER),
            Some(TEST_AGENT_RESPONDER_URL),
        );
        let cmd = super::render_remote_run_command(&artifact);

        assert!(
            cmd.contains("--artifact '<REMOTE_ARTIFACT_PATH>'"),
            "non-wrapped artifact should still use --artifact placeholder: {cmd}"
        );
        assert!(
            !cmd.contains("--openbao-url"),
            "should not contain legacy flags: {cmd}"
        );
    }

    #[test]
    fn artifact_url_prefers_advertise_addr() {
        use std::collections::BTreeMap;

        use crate::state::StateFile;

        let state = StateFile {
            openbao_url: "https://127.0.0.1:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: Some("0.0.0.0:8200".to_string()),
            openbao_advertise_addr: Some("192.168.1.10:8200".to_string()),
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: BTreeMap::new(),
        };
        assert_eq!(
            super::artifact_openbao_url(&state),
            "https://192.168.1.10:8200",
            "artifact URL must use the advertise address for remote reachability"
        );
    }

    #[test]
    fn artifact_url_falls_back_to_openbao_url() {
        use std::collections::BTreeMap;

        use crate::state::StateFile;

        let state = StateFile {
            openbao_url: "https://10.0.0.5:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: Some("10.0.0.5:8200".to_string()),
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: BTreeMap::new(),
        };
        assert_eq!(
            super::artifact_openbao_url(&state),
            "https://10.0.0.5:8200",
            "without advertise addr, artifact URL must fall back to openbao_url"
        );
    }
}
