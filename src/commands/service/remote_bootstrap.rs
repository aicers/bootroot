use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;
#[cfg(test)]
use bootroot::remote_bootstrap::fingerprints_from_bundle;
use bootroot::remote_bootstrap::{
    self, ArtifactInputs, ArtifactPaths, ArtifactWrap, RemoteBootstrapArtifact,
};

use super::resolve::ResolvedServiceAdd;
use super::{
    REMOTE_BOOTSTRAP_DIR, REMOTE_BOOTSTRAP_FILENAME, RemoteBootstrapResult, SERVICE_EAB_FILENAME,
    SERVICE_ROLE_ID_FILENAME,
};
use crate::i18n::Messages;
use crate::state::{PostRenewHookEntry, ServiceEntry, StateFile};

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

/// Returns the `OpenBao` URL to embed in remote bootstrap artifacts, by
/// the library rule the registrar mint applies to the same two members.
fn artifact_openbao_url(state: &StateFile) -> String {
    remote_bootstrap::artifact_openbao_url(
        &state.openbao_url,
        state.openbao_advertise_addr.as_deref(),
    )
}

/// Builds a `RemoteBootstrapArtifact` from common inputs shared by both
/// the initial service-add and the idempotent re-run paths.
///
/// The artifact itself comes from the library builder the registrar mint
/// also calls. What stays here is `service add`'s own placement rule for
/// the three paths it does not take from a flag: `role_id` and
/// `eab.json` beside `secret_id`, and `ca-bundle.pem` beside the
/// certificate.
#[allow(clippy::too_many_arguments)] // mirrors the many fields of RemoteBootstrapArtifact
fn build_artifact(
    openbao_url: &str,
    kv_mount: &str,
    registration_id: &str,
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
    cert_group_gid: Option<u32>,
) -> RemoteBootstrapArtifact {
    let secret_id_parent = secret_id_path.parent().unwrap_or(Path::new("."));
    let role_id_path = secret_id_parent.join(SERVICE_ROLE_ID_FILENAME);
    let eab_path = secret_id_parent.join(SERVICE_EAB_FILENAME);
    let ca_bundle_path = cert_path
        .parent()
        .unwrap_or(Path::new("certs"))
        .join("ca-bundle.pem");

    let agent_config_path = agent_config_path.display().to_string();
    let role_id_path = role_id_path.display().to_string();
    let secret_id_path = secret_id_path.display().to_string();
    let eab_file_path = eab_path.display().to_string();
    let profile_cert_path = cert_path.display().to_string();
    let profile_key_path = key_path.display().to_string();
    let ca_bundle_path = ca_bundle_path.display().to_string();
    remote_bootstrap::build_artifact(&ArtifactInputs {
        openbao_url,
        kv_mount,
        registration_id,
        service_name,
        paths: ArtifactPaths {
            agent_config_path: &agent_config_path,
            role_id_path: &role_id_path,
            secret_id_path: &secret_id_path,
            eab_file_path: &eab_file_path,
            profile_cert_path: &profile_cert_path,
            profile_key_path: &profile_key_path,
            ca_bundle_path: &ca_bundle_path,
        },
        ca_bundle_pem,
        agent_email,
        agent_server,
        agent_responder_url,
        agent_domain: domain,
        profile_hostname: hostname,
        profile_instance_id: instance_id.unwrap_or_default(),
        post_renew_hooks,
        wrap: wrap_info.map(|wrap| ArtifactWrap {
            token: &wrap.token,
            expires_at: &wrap.expires_at,
        }),
        cert_group_gid,
    })
}

/// Writes the bootstrap artifact for a fresh remote-bootstrap add.
///
/// The artifact's credential paths follow the target-host
/// `--secret-id-path` when one was given, and `control_secret_id_path`
/// (where the control node keeps its own copy) otherwise.
pub(super) async fn write_remote_bootstrap_artifact(
    state: &StateFile,
    secrets_dir: &Path,
    resolved: &ResolvedServiceAdd,
    control_secret_id_path: &Path,
    wrap_info: Option<&ArtifactWrapInfo>,
    ca_bundle_pem: &str,
    messages: &Messages,
) -> Result<RemoteBootstrapResult> {
    let artifact_url = artifact_openbao_url(state);
    let artifact = build_artifact(
        &artifact_url,
        &state.kv_mount,
        &resolved.registration_id,
        &resolved.service_name,
        resolved
            .remote_secret_id_path
            .as_deref()
            .unwrap_or(control_secret_id_path),
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
        resolved.cert_group_gid,
    );
    write_remote_bootstrap_artifact_file(
        secrets_dir,
        &resolved.registration_id,
        &artifact,
        messages,
    )
    .await
}

/// Reissues the bootstrap artifact for a recorded remote-bootstrap
/// registration, from the recorded target-host `secret_id` path when one
/// was given at add time and from the control-side path otherwise, so a
/// re-run carries the same credential paths the first artifact did.
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
        &entry.registration_id,
        &entry.service_name,
        entry
            .remote_secret_id_path
            .as_deref()
            .unwrap_or(&entry.approle.secret_id_path),
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
        entry.cert_group_gid,
    );
    write_remote_bootstrap_artifact_file(secrets_dir, &entry.registration_id, &artifact, messages)
        .await
}

async fn write_remote_bootstrap_artifact_file(
    secrets_dir: &Path,
    registration_id: &str,
    artifact: &RemoteBootstrapArtifact,
    messages: &Messages,
) -> Result<RemoteBootstrapResult> {
    let artifact_dir = secrets_dir.join(REMOTE_BOOTSTRAP_DIR).join(registration_id);
    fs_util::ensure_secrets_dir(&artifact_dir).await?;
    let artifact_path = artifact_dir.join(REMOTE_BOOTSTRAP_FILENAME);
    let payload = remote_bootstrap::serialize_artifact(artifact)
        .with_context(|| "Failed to serialize remote bootstrap artifact".to_string())?;
    // Published by rename at the policy's `0600`, applied while the file
    // is still at its temporary name so the wrapped token it may carry
    // is never readable at the final path under a wider mode.
    //
    // It takes the directory flush. The artifact holds a single-use
    // response-wrapping token that `OpenBao` has already issued and that
    // expires on its own clock; losing the directory entry means the
    // operator cannot run the bootstrap and cannot get that token back
    // either, so `service add --remote` has to be re-run against a
    // freshly issued one.
    fs_util::atomic_write(
        fs_util::Destination::bootroot_owned(&artifact_path),
        payload.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&artifact_path.display().to_string()))?;
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
/// resume quote). Only used by the per-field renderer kept for tests.
#[cfg(test)]
fn shell_escape_single_quoted(value: &str) -> String {
    value.replace('\'', "'\\''")
}

/// Renders the per-field flag command. Kept for test coverage of the
/// per-field invocation shape, a supported alternative to `--artifact`.
#[cfg(test)]
fn render_remote_run_command_per_field(artifact: &RemoteBootstrapArtifact) -> String {
    use std::fmt::Write as _;

    let mut cmd = format!(
        "bootroot-remote bootstrap --openbao-url '{}' --kv-mount '{}' --registration-id '{}' --service-name '{}' --role-id-path '{}' --secret-id-path '{}' --eab-file-path '{}' --agent-config-path '{}' --agent-email '{}' --agent-server '{}' --agent-domain '{}' --agent-responder-url '{}' --profile-hostname '{}' --profile-instance-id '{}' --profile-cert-path '{}' --profile-key-path '{}' --ca-bundle-path '{}'",
        artifact.openbao_url,
        artifact.kv_mount,
        artifact.registration_id,
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

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{build_artifact, fingerprints_from_bundle};

    const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n";

    /// The artifact must advertise the bundle's real trust-anchor
    /// fingerprints so `bootroot-remote bootstrap` can pin its `OpenBao`
    /// TLS connection (issue #695); an unparseable bundle yields no pins.
    #[test]
    fn fingerprints_from_bundle_computes_ca_fingerprints() {
        use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair};

        let key = KeyPair::generate().expect("generate CA key");
        let mut params = CertificateParams::new(Vec::new()).expect("certificate params");
        params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let cert = params.self_signed(&key).expect("self-signed CA");
        let pem = cert.pem();

        let expected = bootroot::tls::ca_bundle_fingerprints(&pem).expect("fingerprints");
        assert_eq!(fingerprints_from_bundle(&pem), expected);
        assert_eq!(expected.len(), 1);

        assert_eq!(
            fingerprints_from_bundle("not a certificate"),
            Vec::<String>::new()
        );
        assert_eq!(fingerprints_from_bundle(""), Vec::<String>::new());
    }
    const TEST_AGENT_EMAIL: &str = "test@example.com";
    const TEST_AGENT_SERVER: &str = "https://step-ca.test:9000/acme/acme/directory";
    const TEST_AGENT_RESPONDER_URL: &str = "http://127.0.0.1:8080";

    /// `--cert-group` flows through the bootstrap artifact as
    /// `cert_group_gid`, so the remote agent picks up the policy on
    /// every rotation. Guards issue #593 on the remote-bootstrap path.
    #[test]
    fn build_artifact_carries_cert_group_gid() {
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
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
            None,
            None,
            None,
            Some(5001),
        );
        assert_eq!(artifact.cert_group_gid, Some(5001));

        let serialized = serde_json::to_string(&artifact).unwrap();
        assert!(
            serialized.contains("\"cert_group_gid\":5001"),
            "cert_group_gid must be serialized: {serialized}"
        );
    }

    #[test]
    fn build_artifact_omits_cert_group_gid_when_unset() {
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
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
            None,
            None,
            None,
            None,
        );
        assert!(artifact.cert_group_gid.is_none());

        let serialized = serde_json::to_string(&artifact).unwrap();
        assert!(
            !serialized.contains("cert_group_gid"),
            "cert_group_gid must be omitted from artifact when None: {serialized}"
        );
    }

    #[test]
    fn build_artifact_typical_case() {
        let artifact = build_artifact(
            "https://openbao.example.com:8200",
            "secret",
            "my-service",
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
            None,
        );

        assert_eq!(artifact.schema_version, 5);
        assert_eq!(artifact.openbao_url, "https://openbao.example.com:8200");
        assert_eq!(artifact.kv_mount, "secret");
        assert_eq!(artifact.registration_id, "my-service");
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
            None,
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
            None,
        );

        assert_eq!(artifact.profile_instance_id, "");
    }

    #[test]
    fn build_artifact_different_registration_ids_produce_different_paths() {
        let a = build_artifact(
            "https://ob",
            "kv",
            "alpha",
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
            None,
        );
        let b = build_artifact(
            "https://ob",
            "kv",
            "beta",
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
            None,
        );

        assert_ne!(a.role_id_path, b.role_id_path);
        assert_ne!(a.secret_id_path, b.secret_id_path);
        assert_ne!(a.ca_bundle_path, b.ca_bundle_path);
    }

    #[test]
    fn build_artifact_secret_id_path_without_parent() {
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
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
            None,
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
            None,
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
            None,
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
            None,
        );
        let cmd = super::render_remote_run_command_per_field(&artifact);

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
            None,
        );
        let cmd = super::render_remote_run_command_per_field(&artifact);

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
            None,
        );
        let cmd = super::render_remote_run_command_per_field(&artifact);

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
            None,
        );
        let with_none = build_artifact(
            "https://ob",
            "kv",
            "svc",
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
            None,
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
            None,
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
            None,
        );
        let cmd = super::render_remote_run_command(&artifact);

        assert!(
            cmd.contains("--artifact '<REMOTE_ARTIFACT_PATH>'"),
            "missing --artifact placeholder: {cmd}"
        );
        assert!(
            !cmd.contains("--openbao-url"),
            "should not contain per-field flags: {cmd}"
        );
    }

    #[test]
    fn render_remote_run_command_uses_artifact_flag_without_wrap() {
        let artifact = build_artifact(
            "https://ob",
            "kv",
            "svc",
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
            None,
        );
        let cmd = super::render_remote_run_command(&artifact);

        assert!(
            cmd.contains("--artifact '<REMOTE_ARTIFACT_PATH>'"),
            "non-wrapped artifact should still use --artifact placeholder: {cmd}"
        );
        assert!(
            !cmd.contains("--openbao-url"),
            "should not contain per-field flags: {cmd}"
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
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
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
        };
        assert_eq!(
            super::artifact_openbao_url(&state),
            "https://10.0.0.5:8200",
            "without advertise addr, artifact URL must fall back to openbao_url"
        );
    }

    fn remote_entry(remote_secret_id_path: Option<&str>) -> crate::state::ServiceEntry {
        use std::path::PathBuf;

        use crate::state::{DeliveryMode, ServiceEntry, ServiceRoleEntry};

        ServiceEntry {
            registration_id: "edge-svc-001".to_string(),
            service_name: "edge-svc".to_string(),
            delivery_mode: DeliveryMode::RemoteBootstrap,
            hostname: "edge".to_string(),
            domain: "example.com".to_string(),
            agent_config_path: PathBuf::from("/srv/agent/agent.toml"),
            cert_path: PathBuf::from("/srv/agent/certs/cert.pem"),
            key_path: PathBuf::from("/srv/agent/certs/key.pem"),
            instance_id: Some("001".to_string()),
            notes: None,
            post_renew_hooks: Vec::new(),
            approle: ServiceRoleEntry {
                role_name: "bootroot-service-edge-svc-001".to_string(),
                role_id: "role".to_string(),
                secret_id_path: PathBuf::from("secrets/services/edge-svc-001/secret_id"),
                policy_name: "bootroot-service-edge-svc-001".to_string(),
                secret_id_ttl: None,
                secret_id_wrap_ttl: None,
                token_bound_cidrs: None,
            },
            agent_email: None,
            agent_server: None,
            agent_responder_url: None,
            cert_group_gid: None,
            remote_secret_id_path: remote_secret_id_path.map(PathBuf::from),
        }
    }

    /// Reissues the artifact for `entry` into a temporary secrets dir and
    /// returns its `(secret_id_path, role_id_path, eab_file_path)`.
    async fn reissue_from_entry(entry: &crate::state::ServiceEntry) -> (String, String, String) {
        use crate::i18n::Messages;
        use crate::state::StateFile;

        let dir = tempfile::tempdir().unwrap();
        let state = StateFile {
            openbao_url: "https://127.0.0.1:8200".to_string(),
            kv_mount: "secret".to_string(),
            ..Default::default()
        };
        let messages = Messages::new("en").unwrap();
        let result = super::write_remote_bootstrap_artifact_from_entry(
            &state,
            dir.path(),
            entry,
            None,
            TEST_CA_PEM,
            &messages,
        )
        .await
        .unwrap();
        let written = std::fs::read_to_string(&result.bootstrap_file).unwrap();
        let artifact: serde_json::Value = serde_json::from_str(&written).unwrap();
        let field = |name: &str| {
            artifact
                .get(name)
                .and_then(serde_json::Value::as_str)
                .unwrap()
                .to_string()
        };
        (
            field("secret_id_path"),
            field("role_id_path"),
            field("eab_file_path"),
        )
    }

    /// A re-run of a registration added with a target `--secret-id-path`
    /// reissues the artifact from the recorded target path, with `role_id`
    /// and `eab.json` beside it — never the control node's own copies.
    #[tokio::test]
    async fn write_from_entry_uses_recorded_remote_secret_id_path() {
        let paths = reissue_from_entry(&remote_entry(Some("/srv/agent/svc/secret_id"))).await;
        assert_eq!(
            paths,
            (
                "/srv/agent/svc/secret_id".to_string(),
                "/srv/agent/svc/role_id".to_string(),
                "/srv/agent/svc/eab.json".to_string(),
            )
        );
    }

    /// Without a recorded target path the artifact keeps carrying the
    /// control-side path, exactly as before the flag was accepted.
    #[tokio::test]
    async fn write_from_entry_falls_back_to_control_secret_id_path() {
        let paths = reissue_from_entry(&remote_entry(None)).await;
        assert_eq!(
            paths,
            (
                "secrets/services/edge-svc-001/secret_id".to_string(),
                "secrets/services/edge-svc-001/role_id".to_string(),
                "secrets/services/edge-svc-001/eab.json".to_string(),
            )
        );
    }
}
