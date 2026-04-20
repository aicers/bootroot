use std::path::Path;

use anyhow::Result;

use crate::toml_util;

pub const SERVICE_KV_BASE: &str = "bootroot/services";
pub const SECRET_ID_KEY: &str = "secret_id";
pub const HMAC_KEY: &str = "hmac";
pub const EAB_KID_KEY: &str = "kid";
pub const EAB_HMAC_KEY: &str = "hmac";
pub const TRUSTED_CA_KEY: &str = "trusted_ca_sha256";
pub const CA_BUNDLE_PEM_KEY: &str = "ca_bundle_pem";
pub const CA_BUNDLE_PATH_KEY: &str = "ca_bundle_path";

/// KV v2 path suffix carrying the force-reissue request for a service.
///
/// Full path: `{kv_mount}/data/bootroot/services/<service>/reissue`.
/// The control plane writes this on `rotate force-reissue` for
/// remote-bootstrap services, and the remote `bootroot-agent` polls it on
/// its fast-poll interval to trigger an immediate renewal.
pub const SERVICE_REISSUE_KV_SUFFIX: &str = "reissue";
/// Payload field holding the RFC3339 UTC timestamp of the request.
pub const REISSUE_REQUESTED_AT_KEY: &str = "requested_at";
/// Payload field describing who issued the request (operator label).
pub const REISSUE_REQUESTER_KEY: &str = "requester";
/// Payload field written back by the agent once renewal completes.
pub const REISSUE_COMPLETED_AT_KEY: &str = "completed_at";
/// Payload field written back by the agent with the applied version.
pub const REISSUE_COMPLETED_VERSION_KEY: &str = "completed_version";

const ACME_SECTION_NAME: &str = "acme";
const TRUST_SECTION_NAME: &str = "trust";
const EAB_SECTION_NAME: &str = "eab";
const PROFILE_EAB_SECTION_NAME: &str = "profiles.eab";
const HTTP_RESPONDER_HMAC_KEY: &str = "http_responder_hmac";

/// Parameters for [`render_agent_config_baseline`].
pub struct AgentConfigBaselineParams<'a> {
    pub email: &'a str,
    pub server: &'a str,
    pub domain: &'a str,
    pub http_responder_url: &'a str,
}

/// Renders the baseline `agent.toml` content for a freshly provisioned
/// service: `email`, `server`, `domain`, and the full `[acme]` section
/// including `http_responder_url` plus retry/timeout tunables.
///
/// Both the local-file and remote-bootstrap service-add paths feed this
/// into their managed-profile upserts so the generated `.ctmpl` carries
/// every field operators commonly need to customise.  Without the
/// baseline, re-renders on KV rotation reset the file to
/// `bootroot-agent`'s compiled-in defaults, silently overwriting
/// operator edits to `server` or `[acme].http_responder_url`.
#[must_use]
pub fn render_agent_config_baseline(params: &AgentConfigBaselineParams<'_>) -> String {
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
        email = params.email,
        server = params.server,
        domain = params.domain,
        responder_url = params.http_responder_url,
    )
}

/// Backfills any missing baseline fields from [`render_agent_config_baseline`]
/// into `contents` without clobbering operator-customised values.
///
/// Used by the local-file `service add` path to fix #549 for both fresh
/// and pre-existing `agent.toml` files: any field missing from the file
/// (for example `email`, `server`, `[acme].http_responder_url`, or the
/// retry/timeout tunables) is inserted so the sidecar's re-render from
/// the generated `.ctmpl` does not silently revert to bootroot-agent's
/// compiled-in defaults.  Existing keys are left alone so this is safe
/// to apply to an operator-edited file.
///
/// # Errors
///
/// Returns an error if `contents` is not valid TOML.
pub fn apply_agent_config_baseline_defaults(
    contents: &str,
    params: &AgentConfigBaselineParams<'_>,
) -> Result<String> {
    let mut next = toml_util::insert_missing_top_level_keys(
        contents,
        &[
            ("email", params.email.to_string()),
            ("server", params.server.to_string()),
            ("domain", params.domain.to_string()),
        ],
    )?;
    next = toml_util::insert_missing_section_keys(
        &next,
        ACME_SECTION_NAME,
        &[
            ("directory_fetch_attempts", "10".to_string()),
            ("directory_fetch_base_delay_secs", "1".to_string()),
            ("directory_fetch_max_delay_secs", "10".to_string()),
            ("poll_attempts", "15".to_string()),
            ("poll_interval_secs", "2".to_string()),
            ("http_responder_url", params.http_responder_url.to_string()),
            (HTTP_RESPONDER_HMAC_KEY, String::new()),
            ("http_responder_timeout_secs", "5".to_string()),
            ("http_responder_token_ttl_secs", "300".to_string()),
        ],
    )?;
    Ok(next)
}

/// Renders a managed profile block for `agent.toml`.
#[must_use]
pub fn render_managed_profile_block(
    begin_prefix: &str,
    end_prefix: &str,
    service_name: &str,
    instance_id: &str,
    hostname: &str,
    cert_path: &Path,
    key_path: &Path,
) -> String {
    format!(
        "{begin_prefix} {service_name}\n\
[[profiles]]\n\
service_name = \"{service_name}\"\n\
instance_id = \"{instance_id}\"\n\
hostname = \"{hostname}\"\n\n\
[profiles.paths]\n\
cert = \"{cert}\"\n\
key = \"{key}\"\n\
{end_prefix} {service_name}\n",
        cert = cert_path.display(),
        key = key_path.display(),
    )
}

/// Upserts a managed profile block in `agent.toml`.
#[must_use]
pub fn upsert_managed_profile_block(
    contents: &str,
    begin_prefix: &str,
    end_prefix: &str,
    service_name: &str,
    replacement: &str,
) -> String {
    let begin_marker = format!("{begin_prefix} {service_name}");
    let end_marker = format!("{end_prefix} {service_name}");
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

/// Builds trust section updates for a managed service profile.
#[must_use]
pub fn build_trust_updates(
    fingerprints: &[String],
    ca_bundle_path: &Path,
) -> Vec<(&'static str, String)> {
    let rendered_fingerprints = format!(
        "[{}]",
        fingerprints
            .iter()
            .map(|value| format!("\"{value}\""))
            .collect::<Vec<_>>()
            .join(", ")
    );
    vec![
        (CA_BUNDLE_PATH_KEY, ca_bundle_path.display().to_string()),
        (TRUSTED_CA_KEY, rendered_fingerprints),
    ]
}

/// Builds an `OpenBao` Agent ctmpl for managed `agent.toml` updates.
#[must_use]
pub fn build_managed_agent_ctmpl(contents: &str, kv_mount: &str, service_name: &str) -> String {
    let base = format!("{SERVICE_KV_BASE}/{service_name}");

    let hmac_template = format!(
        "{{{{ with secret \"{kv_mount}/data/{base}/http_responder_hmac\" }}}}\
         {{{{ .Data.data.hmac }}}}\
         {{{{ end }}}}"
    );
    let with_hmac = replace_key_line_in_section(
        contents,
        ACME_SECTION_NAME,
        HTTP_RESPONDER_HMAC_KEY,
        &format!("{HTTP_RESPONDER_HMAC_KEY} = \"{hmac_template}\""),
    );

    let without_eab =
        remove_line_sections(&with_hmac, &[EAB_SECTION_NAME, PROFILE_EAB_SECTION_NAME]);

    let trust_template_line = format!(
        "{{{{ with secret \"{kv_mount}/data/{base}/trust\" }}}}\
         {TRUSTED_CA_KEY} = {{{{ .Data.data.{TRUSTED_CA_KEY} | toJSON }}}}\
         {{{{ end }}}}"
    );
    let with_trust = replace_key_line_in_section(
        &without_eab,
        TRUST_SECTION_NAME,
        TRUSTED_CA_KEY,
        &trust_template_line,
    );

    let eab_block = format!(
        "\n{{{{ with secret \"{kv_mount}/data/{base}/eab\" }}}}{{{{ if .Data.data.{EAB_KID_KEY} }}}}\n\
         [eab]\n\
         kid = \"{{{{ .Data.data.{EAB_KID_KEY} }}}}\"\n\
         hmac = \"{{{{ .Data.data.{EAB_HMAC_KEY} }}}}\"\n\
         \n\
         [profiles.eab]\n\
         kid = \"{{{{ .Data.data.{EAB_KID_KEY} }}}}\"\n\
         hmac = \"{{{{ .Data.data.{EAB_HMAC_KEY} }}}}\"\n\
         {{{{ end }}}}{{{{ end }}}}\n"
    );

    let mut result = with_trust;
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str(&eab_block);
    result
}

/// Builds an `OpenBao` Agent ctmpl for a rendered CA bundle file.
#[must_use]
pub fn build_ca_bundle_ctmpl(kv_mount: &str, service_name: &str) -> String {
    let base = format!("{SERVICE_KV_BASE}/{service_name}");
    format!(
        "{{{{ with secret \"{kv_mount}/data/{base}/trust\" }}}}\
         {{{{ .Data.data.{CA_BUNDLE_PEM_KEY} }}}}\
         {{{{ end }}}}\n"
    )
}

fn is_section_header(value: &str) -> bool {
    value.starts_with('[') && value.ends_with(']')
}

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
    use std::path::Path;

    use super::*;

    const BEGIN_PREFIX: &str = "# BEGIN managed profile:";
    const END_PREFIX: &str = "# END managed profile:";

    #[test]
    fn upsert_managed_profile_block_is_idempotent() {
        let block = render_managed_profile_block(
            BEGIN_PREFIX,
            END_PREFIX,
            "edge-proxy",
            "001",
            "edge-node-01",
            Path::new("certs/edge-proxy.crt"),
            Path::new("certs/edge-proxy.key"),
        );
        let once = upsert_managed_profile_block("", BEGIN_PREFIX, END_PREFIX, "edge-proxy", &block);
        let twice =
            upsert_managed_profile_block(&once, BEGIN_PREFIX, END_PREFIX, "edge-proxy", &block);
        assert_eq!(once, twice);
    }

    #[test]
    fn build_trust_updates_writes_bundle_and_pins_only() {
        let updates = build_trust_updates(&["a".repeat(64)], Path::new("certs/ca-bundle.pem"));

        assert_eq!(updates.len(), 2);
        assert!(updates.iter().any(|(key, _)| *key == CA_BUNDLE_PATH_KEY));
        assert!(updates.iter().any(|(key, _)| *key == TRUSTED_CA_KEY));
    }

    #[test]
    fn build_managed_agent_ctmpl_replaces_hmac_and_trust() {
        let input = "[acme]\nhttp_responder_hmac = \"old-hmac\"\n\n[trust]\ntrusted_ca_sha256 = [\"old\"]\n";
        let output = build_managed_agent_ctmpl(input, "secret", "edge-proxy");

        assert!(output.contains(
            "{{ with secret \"secret/data/bootroot/services/edge-proxy/http_responder_hmac\" }}"
        ));
        assert!(output.contains("trusted_ca_sha256 = {{ .Data.data.trusted_ca_sha256 | toJSON }}"));
        assert!(output.contains("[profiles.eab]"));
        assert!(!output.contains("\"old-hmac\""));
    }

    #[test]
    fn render_agent_config_baseline_includes_all_documented_fields() {
        let output = render_agent_config_baseline(&AgentConfigBaselineParams {
            email: "admin@example.com",
            server: "https://step-ca.example.com:9000/acme/acme/directory",
            domain: "test.local",
            http_responder_url: "http://responder.example.com:8080",
        });

        assert!(output.contains("email = \"admin@example.com\""));
        assert!(
            output.contains("server = \"https://step-ca.example.com:9000/acme/acme/directory\"")
        );
        assert!(output.contains("domain = \"test.local\""));
        assert!(output.contains("[acme]"));
        assert!(output.contains("http_responder_url = \"http://responder.example.com:8080\""));
        assert!(output.contains("http_responder_hmac = \"\""));
        assert!(output.contains("directory_fetch_attempts = 10"));
        assert!(output.contains("poll_attempts = 15"));
        assert!(output.contains("http_responder_timeout_secs = 5"));
        assert!(output.contains("http_responder_token_ttl_secs = 300"));
    }

    #[test]
    fn build_ca_bundle_ctmpl_reads_service_trust_bundle() {
        let output = build_ca_bundle_ctmpl("secret", "edge-proxy");

        assert!(
            output.contains("{{ with secret \"secret/data/bootroot/services/edge-proxy/trust\" }}")
        );
        assert!(output.contains("{{ .Data.data.ca_bundle_pem }}"));
    }
}
