use std::path::Path;

pub const SERVICE_KV_BASE: &str = "bootroot/services";
pub const SECRET_ID_KEY: &str = "secret_id";
pub const HMAC_KEY: &str = "hmac";
pub const EAB_KID_KEY: &str = "kid";
pub const EAB_HMAC_KEY: &str = "hmac";
pub const TRUSTED_CA_KEY: &str = "trusted_ca_sha256";
pub const CA_BUNDLE_PEM_KEY: &str = "ca_bundle_pem";
pub const CA_BUNDLE_PATH_KEY: &str = "ca_bundle_path";

const ACME_SECTION_NAME: &str = "acme";
const TRUST_SECTION_NAME: &str = "trust";
const EAB_SECTION_NAME: &str = "eab";
const PROFILE_EAB_SECTION_NAME: &str = "profiles.eab";
const HTTP_RESPONDER_HMAC_KEY: &str = "http_responder_hmac";

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
    fn build_ca_bundle_ctmpl_reads_service_trust_bundle() {
        let output = build_ca_bundle_ctmpl("secret", "edge-proxy");

        assert!(
            output.contains("{{ with secret \"secret/data/bootroot/services/edge-proxy/trust\" }}")
        );
        assert!(output.contains("{{ .Data.data.ca_bundle_pem }}"));
    }
}
