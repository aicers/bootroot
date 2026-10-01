//! The remote-bootstrap artifact and the one builder that produces it.
//!
//! `bootroot-remote bootstrap --artifact <bootstrap.json>` enrolls a
//! service on a target host from a single JSON document. Two producers
//! hand that document out: `bootroot service add --delivery-mode
//! remote-bootstrap`, which writes it under the control host's secrets
//! tree, and the registrar endpoint's mint, which returns it in the
//! response for a caller to relay byte for byte. Both call
//! [`build_artifact`] and serialize through [`serialize_artifact`], so
//! the two cannot drift on a member's spelling, its presence rule or the
//! byte form of the document.
//!
//! The pieces the two producers share beside the builder live here as
//! well, for the same reason: the post-renew hook entry both the state
//! file and the artifact carry ([`PostRenewHookEntry`]), the reload
//! preset mapping a reload style and target become hooks through
//! ([`reload_preset_hooks`]), the fingerprint rule for the CA bundle
//! ([`fingerprints_from_bundle`]) and the rule that picks the `OpenBao`
//! URL a remote host is told to reach ([`artifact_openbao_url`]).
//!
//! Nothing here reads a file, a state inventory or a request. Each
//! producer resolves its own sources and passes plain values in.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::registrar::config::ReloadKind;

/// The artifact `schema_version` this build writes, and the one
/// `bootroot-remote` accepts.
///
/// Version 5 split the registry key out of `service_name` into the
/// required `registration_id`: every namespace the remote agent derives
/// comes from that key, while `service_name` stays the SAN label. A new
/// required member is breaking, so it took a bump.
pub const ARTIFACT_SCHEMA_VERSION: u32 = 5;

/// The timeout a post-renew hook runs under when none was chosen.
pub const DEFAULT_HOOK_TIMEOUT_SECS: u64 = 30;

/// What happens to the remaining hooks when one fails.
#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum HookFailurePolicyEntry {
    /// Run the remaining hooks.
    #[default]
    Continue,
    /// Stop at the failed hook.
    Stop,
}

impl fmt::Display for HookFailurePolicyEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Continue => "continue",
            Self::Stop => "stop",
        })
    }
}

/// One post-renew hook, in the form the state file and the artifact
/// both serialize.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct PostRenewHookEntry {
    /// The program run after a renewal.
    pub command: String,
    /// Its arguments, in order.
    #[serde(default)]
    pub args: Vec<String>,
    /// How long it may run, in seconds.
    #[serde(default = "default_hook_timeout_secs")]
    pub timeout_secs: u64,
    /// What a failure of this hook does to the ones after it.
    #[serde(default)]
    pub on_failure: HookFailurePolicyEntry,
}

fn default_hook_timeout_secs() -> u64 {
    DEFAULT_HOOK_TIMEOUT_SECS
}

/// Why a reload style and target do not map onto a preset hook.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReloadPresetError {
    /// A style that acts on a target was given none.
    #[error("the {kind} reload style requires a target")]
    TargetRequired {
        /// The style that needed the target.
        kind: ReloadKind,
    },
    /// A `sighup` target names a path, not a process.
    #[error("a sighup reload target must be a process name, not a path")]
    SighupTargetIsPath {
        /// The rejected target.
        target: String,
    },
}

/// Maps a reload style and its target onto the post-renew hooks it
/// installs.
///
/// `none` installs no hook, and `systemd`, `sighup` and `docker-restart`
/// install one entry each, acting on `target` with the default timeout
/// and failure policy.
///
/// # Errors
///
/// Returns [`ReloadPresetError::TargetRequired`] when a style other than
/// `none` has no target, and [`ReloadPresetError::SighupTargetIsPath`]
/// when a `sighup` target contains `/`: `pkill` matches a process name,
/// and a path there would silently match nothing.
pub fn reload_preset_hooks(
    kind: ReloadKind,
    target: Option<&str>,
) -> Result<Vec<PostRenewHookEntry>, ReloadPresetError> {
    let (command, verb) = match kind {
        ReloadKind::None => return Ok(Vec::new()),
        ReloadKind::Systemd => ("systemctl", "reload"),
        ReloadKind::Sighup => ("pkill", "-HUP"),
        ReloadKind::DockerRestart => ("docker", "restart"),
    };
    let target = target.ok_or(ReloadPresetError::TargetRequired { kind })?;
    if kind == ReloadKind::Sighup && target.contains('/') {
        return Err(ReloadPresetError::SighupTargetIsPath {
            target: target.to_string(),
        });
    }
    Ok(vec![PostRenewHookEntry {
        command: command.to_string(),
        args: vec![verb.to_string(), target.to_string()],
        timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
        on_failure: HookFailurePolicyEntry::default(),
    }])
}

/// Derives a usable HTTPS client URL from a bind address.
///
/// Wildcard addresses (`0.0.0.0`, `[::]`) are mapped to their loopback
/// counterparts (`127.0.0.1`, `[::1]`) because `bootroot` commands run
/// on the CN and can always reach `OpenBao` via loopback.  Specific IPs
/// are used as-is.
#[must_use]
pub fn client_url_from_bind_addr(bind_addr: &str) -> String {
    let Some((ip, port)) = bind_addr.rsplit_once(':') else {
        return format!("https://{bind_addr}");
    };
    let client_ip = match ip {
        "0.0.0.0" => "127.0.0.1",
        "[::0]" | "[::]" => "[::1]",
        other => other,
    };
    format!("https://{client_ip}:{port}")
}

/// Returns the `OpenBao` URL a remote-bootstrap artifact carries.
///
/// Prefers the recorded advertise address (set for wildcard binds) so
/// that the artifact carries a routable address a remote host can
/// reach, and falls back to the recorded `openbao_url` for a
/// non-wildcard bind, whose address is directly reachable.
#[must_use]
pub fn artifact_openbao_url(openbao_url: &str, advertise_addr: Option<&str>) -> String {
    advertise_addr.map_or_else(|| openbao_url.to_string(), client_url_from_bind_addr)
}

/// Computes the `trusted_ca_sha256` fingerprints (lowercase hex SHA-256
/// of each certificate's DER) for the certificates in a CA bundle PEM.
///
/// Returns an empty list when the bundle is empty or unparseable — the
/// remote bootstrap then falls back to bundle-anchored TLS (no pins).
#[must_use]
pub fn fingerprints_from_bundle(ca_bundle_pem: &str) -> Vec<String> {
    if ca_bundle_pem.trim().is_empty() {
        return Vec::new();
    }
    crate::tls::ca_bundle_fingerprints(ca_bundle_pem).unwrap_or_default()
}

/// Machine-readable bootstrap artifact consumed by `bootroot-remote
/// bootstrap --artifact`.
///
/// Downstream automation (shell scripts, Ansible, CI pipelines, the
/// registrar's caller) can parse this JSON to drive `bootroot-remote
/// bootstrap` invocations.
///
/// It derives `Serialize` and deliberately not `Debug`: `wrap_token` is
/// a single-use response-wrapping token, and a derived `Debug` is how a
/// diagnostic comes to print it.
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
#[derive(Serialize)]
pub struct RemoteBootstrapArtifact {
    /// Always [`ARTIFACT_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The `OpenBao` URL the remote host reaches.
    pub openbao_url: String,
    /// The KV v2 mount the remote agent reads under.
    pub kv_mount: String,
    /// Deployment-wide unique key the remote agent derives its KV
    /// namespace, managed-block markers and state filename from.
    pub registration_id: String,
    /// SAN label the remote profile requests certificates under. Not a
    /// namespace key.
    pub service_name: String,
    /// Where the remote host writes the `AppRole` `role_id`.
    pub role_id_path: String,
    /// Where the remote host writes the `AppRole` `secret_id`.
    pub secret_id_path: String,
    /// Where the remote host writes the EAB credentials.
    pub eab_file_path: String,
    /// Where the remote host's agent configuration lives.
    pub agent_config_path: String,
    /// Where the remote host writes the CA bundle.
    pub ca_bundle_path: String,
    /// The CA bundle, as PEM text.
    pub ca_bundle_pem: String,
    /// SHA-256 fingerprints of the certificates in `ca_bundle_pem`, in the
    /// `trusted_ca_sha256` form. The remote `bootstrap` pins its `OpenBao`
    /// TLS connection to these anchors (issue #695). Serialized only when
    /// non-empty; a remote that pre-dates the field ignores it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_ca_sha256: Vec<String>,
    /// Operator-supplied override for `email`, carried from
    /// `bootroot service add --agent-email` so that `bootroot-remote
    /// bootstrap` can distinguish "explicit override, clobber remote
    /// value" from "no override, preserve remote operator value".
    /// `None` is serialized as a missing key so the downstream parser's
    /// `#[serde(default)]` yields `Option::None`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_email: Option<String>,
    /// The ACME directory URL the remote agent uses, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_server: Option<String>,
    /// The deployment domain the remote agent composes names under.
    pub agent_domain: String,
    /// The HTTP-01 responder admin URL the remote agent uses, when set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_responder_url: Option<String>,
    /// The host label of the remote profile.
    pub profile_hostname: String,
    /// The instance label of the remote profile.
    pub profile_instance_id: String,
    /// Where the remote host writes the issued certificate.
    pub profile_cert_path: String,
    /// Where the remote host writes the issued private key.
    pub profile_key_path: String,
    /// The hooks the remote agent runs after a renewal, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub post_renew_hooks: Vec<PostRenewHookEntry>,
    /// The response-wrapping token the remote host unwraps its
    /// `secret_id` from, when the material was wrapped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap_token: Option<String>,
    /// When `wrap_token` expires, as an RFC 3339 string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wrap_expires_at: Option<String>,
    /// Numeric gid that owns the issued cert/key files and their
    /// parent directories under `--cert-group`. `None` is serialized
    /// as a missing key so a downstream remote agent that pre-dates
    /// the field continues to work without the policy. See
    /// issue #593.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert_group_gid: Option<u32>,
}

/// The seven target-host paths an artifact names.
///
/// Each is copied into the artifact unchanged. Where they come from is
/// the producer's decision: `service add` derives some of them from
/// others, and the registrar mint takes all seven from its caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArtifactPaths<'a> {
    /// `agent_config_path`.
    pub agent_config_path: &'a str,
    /// `role_id_path`.
    pub role_id_path: &'a str,
    /// `secret_id_path`.
    pub secret_id_path: &'a str,
    /// `eab_file_path`.
    pub eab_file_path: &'a str,
    /// `profile_cert_path`.
    pub profile_cert_path: &'a str,
    /// `profile_key_path`.
    pub profile_key_path: &'a str,
    /// `ca_bundle_path`.
    pub ca_bundle_path: &'a str,
}

/// The response-wrapping token an artifact carries, and its expiry.
#[derive(Clone, Copy)]
pub struct ArtifactWrap<'a> {
    /// The wrapping token.
    pub token: &'a str,
    /// Its expiry, as an RFC 3339 string.
    pub expires_at: &'a str,
}

impl fmt::Debug for ArtifactWrap<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ArtifactWrap")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Everything [`build_artifact`] is built from, already resolved.
#[derive(Debug, Clone, Copy)]
pub struct ArtifactInputs<'a> {
    /// `openbao_url`, already chosen by [`artifact_openbao_url`].
    pub openbao_url: &'a str,
    /// `kv_mount`.
    pub kv_mount: &'a str,
    /// `registration_id`.
    pub registration_id: &'a str,
    /// `service_name`.
    pub service_name: &'a str,
    /// The seven target-host paths.
    pub paths: ArtifactPaths<'a>,
    /// `ca_bundle_pem`; `trusted_ca_sha256` is computed from it.
    pub ca_bundle_pem: &'a str,
    /// `agent_email`, omitted when `None`.
    pub agent_email: Option<&'a str>,
    /// `agent_server`, omitted when `None`.
    pub agent_server: Option<&'a str>,
    /// `agent_responder_url`, omitted when `None`.
    pub agent_responder_url: Option<&'a str>,
    /// `agent_domain`.
    pub agent_domain: &'a str,
    /// `profile_hostname`.
    pub profile_hostname: &'a str,
    /// `profile_instance_id`.
    pub profile_instance_id: &'a str,
    /// `post_renew_hooks`.
    pub post_renew_hooks: &'a [PostRenewHookEntry],
    /// `wrap_token` and `wrap_expires_at`, both omitted when `None`.
    pub wrap: Option<ArtifactWrap<'a>>,
    /// `cert_group_gid`, omitted when `None`.
    pub cert_group_gid: Option<u32>,
}

/// Builds the artifact from already-resolved inputs.
///
/// Every member is copied from its input, apart from `schema_version`,
/// which is always [`ARTIFACT_SCHEMA_VERSION`], and `trusted_ca_sha256`,
/// which [`fingerprints_from_bundle`] computes from `ca_bundle_pem`.
#[must_use]
pub fn build_artifact(inputs: &ArtifactInputs<'_>) -> RemoteBootstrapArtifact {
    let paths = &inputs.paths;
    RemoteBootstrapArtifact {
        schema_version: ARTIFACT_SCHEMA_VERSION,
        openbao_url: inputs.openbao_url.to_string(),
        kv_mount: inputs.kv_mount.to_string(),
        registration_id: inputs.registration_id.to_string(),
        service_name: inputs.service_name.to_string(),
        role_id_path: paths.role_id_path.to_string(),
        secret_id_path: paths.secret_id_path.to_string(),
        eab_file_path: paths.eab_file_path.to_string(),
        agent_config_path: paths.agent_config_path.to_string(),
        ca_bundle_path: paths.ca_bundle_path.to_string(),
        trusted_ca_sha256: fingerprints_from_bundle(inputs.ca_bundle_pem),
        ca_bundle_pem: inputs.ca_bundle_pem.to_string(),
        agent_email: inputs.agent_email.map(str::to_string),
        agent_server: inputs.agent_server.map(str::to_string),
        agent_domain: inputs.agent_domain.to_string(),
        agent_responder_url: inputs.agent_responder_url.map(str::to_string),
        profile_hostname: inputs.profile_hostname.to_string(),
        profile_instance_id: inputs.profile_instance_id.to_string(),
        profile_cert_path: paths.profile_cert_path.to_string(),
        profile_key_path: paths.profile_key_path.to_string(),
        post_renew_hooks: inputs.post_renew_hooks.to_vec(),
        wrap_token: inputs.wrap.map(|wrap| wrap.token.to_string()),
        wrap_expires_at: inputs.wrap.map(|wrap| wrap.expires_at.to_string()),
        cert_group_gid: inputs.cert_group_gid,
    }
}

/// Serializes an artifact in the one byte form both producers hand out:
/// pretty-printed JSON, members in declaration order.
///
/// # Errors
///
/// Returns the serializer's error; with the member types above none is
/// expected.
pub fn serialize_artifact(artifact: &RemoteBootstrapArtifact) -> serde_json::Result<String> {
    serde_json::to_string_pretty(artifact)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PATHS: ArtifactPaths<'static> = ArtifactPaths {
        agent_config_path: "/t/agent.toml",
        role_id_path: "/t/role_id",
        secret_id_path: "/t/secret_id",
        eab_file_path: "/t/eab.json",
        profile_cert_path: "/t/cert.pem",
        profile_key_path: "/t/key.pem",
        ca_bundle_path: "/t/ca-bundle.pem",
    };

    fn sample_inputs(wrap: Option<ArtifactWrap<'static>>) -> ArtifactInputs<'static> {
        ArtifactInputs {
            openbao_url: "https://ob",
            kv_mount: "kv",
            registration_id: "reg",
            service_name: "svc",
            paths: SAMPLE_PATHS,
            ca_bundle_pem: "",
            agent_email: None,
            agent_server: Some("https://ca/acme/acme/directory"),
            agent_responder_url: Some("http://responder:8080"),
            agent_domain: "d.test",
            profile_hostname: "h",
            profile_instance_id: "001",
            post_renew_hooks: &[],
            wrap,
            cert_group_gid: None,
        }
    }

    /// Every path is copied unchanged into the member of the same name,
    /// so seven distinct inputs come back as seven distinct members.
    #[test]
    fn build_artifact_copies_each_path_into_its_own_member() {
        let artifact = build_artifact(&sample_inputs(None));
        assert_eq!(artifact.agent_config_path, SAMPLE_PATHS.agent_config_path);
        assert_eq!(artifact.role_id_path, SAMPLE_PATHS.role_id_path);
        assert_eq!(artifact.secret_id_path, SAMPLE_PATHS.secret_id_path);
        assert_eq!(artifact.eab_file_path, SAMPLE_PATHS.eab_file_path);
        assert_eq!(artifact.profile_cert_path, SAMPLE_PATHS.profile_cert_path);
        assert_eq!(artifact.profile_key_path, SAMPLE_PATHS.profile_key_path);
        assert_eq!(artifact.ca_bundle_path, SAMPLE_PATHS.ca_bundle_path);
        assert_eq!(artifact.schema_version, ARTIFACT_SCHEMA_VERSION);
    }

    #[test]
    fn the_wrap_token_never_reaches_debug_output() {
        let wrap = ArtifactWrap {
            token: "hvs.secret-wrap",
            expires_at: "2026-01-01T00:00:00Z",
        };
        let rendered = format!("{:?}", sample_inputs(Some(wrap)));
        assert!(!rendered.contains("hvs.secret-wrap"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    #[test]
    fn the_artifact_serializes_pretty_printed() {
        let text = serialize_artifact(&build_artifact(&sample_inputs(None))).expect("serializes");
        assert!(text.starts_with("{\n  \"schema_version\": 5,\n"), "{text}");
    }

    #[test]
    fn each_reload_kind_maps_to_its_preset() {
        assert_eq!(
            reload_preset_hooks(ReloadKind::None, None).expect("none"),
            [] as [PostRenewHookEntry; 0]
        );
        for (kind, command, verb) in [
            (ReloadKind::Systemd, "systemctl", "reload"),
            (ReloadKind::Sighup, "pkill", "-HUP"),
            (ReloadKind::DockerRestart, "docker", "restart"),
        ] {
            let hooks = reload_preset_hooks(kind, Some("target")).expect("a preset");
            assert_eq!(
                hooks,
                vec![PostRenewHookEntry {
                    command: command.to_string(),
                    args: vec![verb.to_string(), "target".to_string()],
                    timeout_secs: DEFAULT_HOOK_TIMEOUT_SECS,
                    on_failure: HookFailurePolicyEntry::Continue,
                }]
            );
            assert_eq!(
                reload_preset_hooks(kind, None),
                Err(ReloadPresetError::TargetRequired { kind })
            );
        }
        assert_eq!(
            reload_preset_hooks(ReloadKind::Sighup, Some("/usr/bin/x")),
            Err(ReloadPresetError::SighupTargetIsPath {
                target: "/usr/bin/x".to_string()
            })
        );
        assert!(reload_preset_hooks(ReloadKind::Systemd, Some("a/b")).is_ok());
    }

    #[test]
    fn artifact_openbao_url_prefers_the_advertise_address() {
        assert_eq!(
            artifact_openbao_url("https://127.0.0.1:8200", Some("192.168.1.10:8200")),
            "https://192.168.1.10:8200"
        );
        assert_eq!(
            artifact_openbao_url("https://10.0.0.5:8200", None),
            "https://10.0.0.5:8200"
        );
    }

    #[test]
    fn hook_failure_policy_displays_its_serialized_spelling() {
        for policy in [
            HookFailurePolicyEntry::Continue,
            HookFailurePolicyEntry::Stop,
        ] {
            assert_eq!(
                serde_json::to_value(policy).expect("serializes"),
                serde_json::Value::String(policy.to_string())
            );
        }
    }
}
