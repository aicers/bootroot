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

/// Begin/end marker prefixes delimiting one code path's managed profile
/// block in `agent.toml`.
///
/// The local-file `service add` path and the `bootroot-remote bootstrap`
/// path each write their block under a distinct marker pair. Keeping both
/// pairs here — and pairing every upsert with a strip of the *other*
/// path's markers via [`strip_foreign_managed_profiles`] — is what stops a
/// delivery-mode transition from leaving two profile blocks for the same
/// service (issue #662).
#[derive(Clone, Copy)]
pub struct ManagedProfileMarkers {
    pub begin_prefix: &'static str,
    pub end_prefix: &'static str,
}

/// Markers written by the local-file `service add` path.
pub const LOCAL_FILE_PROFILE_MARKERS: ManagedProfileMarkers = ManagedProfileMarkers {
    begin_prefix: "# BEGIN bootroot managed profile:",
    end_prefix: "# END bootroot managed profile:",
};

/// Markers written by the `bootroot-remote bootstrap` path.
pub const REMOTE_BOOTSTRAP_PROFILE_MARKERS: ManagedProfileMarkers = ManagedProfileMarkers {
    begin_prefix: "# BEGIN BOOTROOT REMOTE PROFILE",
    end_prefix: "# END BOOTROOT REMOTE PROFILE",
};

/// Every managed-profile marker pair a bootroot code path may have written.
pub const ALL_MANAGED_PROFILE_MARKERS: [ManagedProfileMarkers; 2] =
    [LOCAL_FILE_PROFILE_MARKERS, REMOTE_BOOTSTRAP_PROFILE_MARKERS];

/// Renders a managed profile block for `agent.toml`.
///
/// When `cert_group_gid` is `Some`, the rendered block contains a
/// `cert_group_gid = N` line so that the agent applies the
/// `--cert-group` policy on every issuance and rotation. `None`
/// preserves the host-local default (operator-only mode/owner) and
/// emits no line.
#[must_use]
#[allow(clippy::too_many_arguments)] // adding cert_group_gid pushes the count to 8; see issue #593
pub fn render_managed_profile_block(
    begin_prefix: &str,
    end_prefix: &str,
    service_name: &str,
    instance_id: &str,
    hostname: &str,
    cert_path: &Path,
    key_path: &Path,
    cert_group_gid: Option<u32>,
) -> String {
    let group_line = match cert_group_gid {
        Some(gid) => format!("cert_group_gid = {gid}\n"),
        None => String::new(),
    };
    format!(
        "{begin_prefix} {service_name}\n\
[[profiles]]\n\
service_name = \"{service_name}\"\n\
instance_id = \"{instance_id}\"\n\
hostname = \"{hostname}\"\n\
{group_line}\n\
[profiles.paths]\n\
cert = \"{cert}\"\n\
key = \"{key}\"\n\
{end_prefix} {service_name}\n",
        cert = cert_path.display(),
        key = key_path.display(),
    )
}

/// Locates a marker occupying a complete line at or after `from`.
///
/// Returns the byte offset where `marker` begins only when it starts a
/// line (file start or right after `\n`) and ends a line (`\n`, `\r`, or
/// EOF). Requiring full-line equality prevents a service name that is a
/// prefix of another (`api` vs `api-v2`) from matching the wrong block.
fn find_marker_line(contents: &str, marker: &str, from: usize) -> Option<usize> {
    let bytes = contents.as_bytes();
    let mut search = from;
    while let Some(relative) = contents.get(search..).and_then(|rest| rest.find(marker)) {
        let start = search + relative;
        let at_line_start = start == 0 || bytes.get(start - 1) == Some(&b'\n');
        let at_line_end = matches!(bytes.get(start + marker.len()), None | Some(b'\n' | b'\r'));
        if at_line_start && at_line_end {
            return Some(start);
        }
        search = start + marker.len();
    }
    None
}

/// Locates the byte span of a managed profile block by its marker lines.
///
/// Returns `(begin, end)` where `begin` is the start of the begin-marker
/// line and `end` is the offset just past the end-marker text. Both
/// markers must match as complete lines via [`find_marker_line`].
fn managed_block_span(
    contents: &str,
    begin_marker: &str,
    end_marker: &str,
) -> Option<(usize, usize)> {
    let begin = find_marker_line(contents, begin_marker, 0)?;
    let end_line = find_marker_line(contents, end_marker, begin)?;
    Some((begin, end_line + end_marker.len()))
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
    if let Some((begin, end)) = managed_block_span(contents, &begin_marker, &end_marker) {
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

/// Strips every managed profile block written under a marker pair *other*
/// than `own` for `service_name`, leaving the caller's own block (if any)
/// untouched.
///
/// A delivery-mode transition (`service remove` + `service add
/// --delivery-mode <other>`, then re-bootstrap on the service host) runs
/// one code path over an `agent.toml` the other path previously wrote.
/// Because each path's upsert recognises only its own markers, without
/// this strip the pre-existing block is never matched and
/// [`upsert_managed_profile_block`] falls through to its append branch,
/// leaving a second `[[profiles]]` for the same service.
///
/// Callers must run this on the **raw** `agent.toml` contents before
/// applying their own `[trust]`/`[openbao]`/profile sections. The end
/// marker of a block is a trailing comment that `toml_edit` floats past
/// any table inserted afterwards, so stripping only stays contained to the
/// intended `[[profiles]]` block while the file is still as the other path
/// last wrote it. The stripped `[trust]` collateral a floated marker may
/// carry is re-emitted authoritatively by the caller's own trust sync.
/// See issue #662.
#[must_use]
pub fn strip_foreign_managed_profiles(
    contents: &str,
    own: ManagedProfileMarkers,
    service_name: &str,
) -> String {
    let mut next = contents.to_string();
    for markers in ALL_MANAGED_PROFILE_MARKERS {
        if markers.begin_prefix == own.begin_prefix {
            continue;
        }
        next = remove_managed_profile_block(
            &next,
            markers.begin_prefix,
            markers.end_prefix,
            service_name,
        );
    }
    next
}

/// Removes a managed profile block from `agent.toml` contents.
///
/// Deletes the `begin_prefix <service_name> … end_prefix <service_name>`
/// span, collapsing the surrounding blank lines so the file stays
/// well-formed. Returns the input unchanged when no matching block is
/// present, so calling it a second time (after the block is already
/// gone) is a no-op. This is the teardown counterpart to
/// [`upsert_managed_profile_block`] and lets `service remove
/// --delete-artifacts` strip bootroot's managed profile from an
/// operator-owned `agent.toml` without deleting the whole file.
#[must_use]
pub fn remove_managed_profile_block(
    contents: &str,
    begin_prefix: &str,
    end_prefix: &str,
    service_name: &str,
) -> String {
    let begin_marker = format!("{begin_prefix} {service_name}");
    let end_marker = format!("{end_prefix} {service_name}");
    let Some((begin, end)) = managed_block_span(contents, &begin_marker, &end_marker) else {
        return contents.to_string();
    };
    let prefix = contents[..begin].trim_end();
    let suffix = contents[end..].trim_start_matches('\n');
    let mut updated = prefix.to_string();
    if !updated.is_empty() && !suffix.is_empty() {
        updated.push_str("\n\n");
    }
    updated.push_str(suffix);
    updated
}

/// Removes only the managed `[[profiles]]` entry for `service_name` and
/// its marker comment lines, leaving every other table untouched.
///
/// Unlike [`remove_managed_profile_block`], which deletes the whole byte
/// span between the begin and end markers, this preserves global tables
/// (`[trust]`, `[openbao]`, `[acme]`, …) that `toml_edit` floats *inside*
/// that span when they are appended after the profile block (see the
/// floating note on [`strip_foreign_managed_profiles`]).
///
/// The whole-span strip is correct only where the caller re-emits those
/// tables afterwards — the delivery-mode transition paths do. `service
/// remove --strip-config` does **not** re-sync: it clears a stale profile
/// from a still-serving host, so dropping the `[trust]`/`[openbao]` config
/// the running agent depends on would be a regression. This surgical
/// variant removes the array element via `toml_edit` (which owns exactly
/// the profile and its `[profiles.*]` sub-tables) and then sweeps the
/// begin/end marker comments, which survive as trailing decor. It matches
/// either code path's markers.
///
/// # Errors
///
/// Returns an error if `contents` is not valid TOML.
pub fn remove_managed_service_profile(contents: &str, service_name: &str) -> Result<String> {
    let (rendered, removed) = toml_util::remove_array_of_tables_entry(
        contents,
        "profiles",
        "service_name",
        service_name,
    )?;
    let base = if removed { &rendered } else { contents };
    Ok(strip_profile_marker_lines(base, service_name))
}

/// Drops any line that exactly matches a begin/end marker for
/// `service_name`, under either code path's marker pair.
///
/// Removing the `[[profiles]]` array element leaves its marker comments
/// behind as document decor, so they must be swept textually. Full-line
/// equality (mirroring [`find_marker_line`]) keeps a service name that is
/// a prefix of another from matching the wrong marker.
fn strip_profile_marker_lines(contents: &str, service_name: &str) -> String {
    let mut out = String::with_capacity(contents.len());
    for line in contents.split_inclusive('\n') {
        let body = line.strip_suffix('\n').unwrap_or(line);
        let body = body.strip_suffix('\r').unwrap_or(body);
        let is_marker = ALL_MANAGED_PROFILE_MARKERS.iter().any(|markers| {
            body == format!("{} {service_name}", markers.begin_prefix)
                || body == format!("{} {service_name}", markers.end_prefix)
        });
        if !is_marker {
            out.push_str(line);
        }
    }
    out
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
            None,
        );
        let once = upsert_managed_profile_block("", BEGIN_PREFIX, END_PREFIX, "edge-proxy", &block);
        let twice =
            upsert_managed_profile_block(&once, BEGIN_PREFIX, END_PREFIX, "edge-proxy", &block);
        assert_eq!(once, twice);
    }

    fn render_profile_for(markers: ManagedProfileMarkers, service: &str) -> String {
        render_managed_profile_block(
            markers.begin_prefix,
            markers.end_prefix,
            service,
            "001",
            "node-01",
            Path::new(&format!("certs/{service}.crt")),
            Path::new(&format!("certs/{service}.key")),
            None,
        )
    }

    /// A delivery-mode transition runs one code path over an `agent.toml`
    /// the other path wrote. Stripping foreign blocks before upserting the
    /// own block must leave exactly one `[[profiles]]`, not a duplicate.
    #[test]
    fn strip_foreign_managed_profiles_removes_opposite_marker() {
        let legacy_local = render_profile_for(LOCAL_FILE_PROFILE_MARKERS, "giganto");
        let existing =
            format!("email = \"a@b.c\"\n\n{legacy_local}\n\n[trust]\nca_bundle_path = \"c\"\n");

        let stripped =
            strip_foreign_managed_profiles(&existing, REMOTE_BOOTSTRAP_PROFILE_MARKERS, "giganto");
        assert!(
            !stripped.contains(LOCAL_FILE_PROFILE_MARKERS.begin_prefix),
            "the foreign local-file block must be stripped: {stripped}"
        );

        let remote = render_profile_for(REMOTE_BOOTSTRAP_PROFILE_MARKERS, "giganto");
        let updated = upsert_managed_profile_block(
            &stripped,
            REMOTE_BOOTSTRAP_PROFILE_MARKERS.begin_prefix,
            REMOTE_BOOTSTRAP_PROFILE_MARKERS.end_prefix,
            "giganto",
            &remote,
        );

        assert_eq!(
            updated.matches("[[profiles]]").count(),
            1,
            "exactly one profile block must remain: {updated}"
        );
        assert!(
            updated.contains(REMOTE_BOOTSTRAP_PROFILE_MARKERS.begin_prefix),
            "the new remote marker must be present: {updated}"
        );
        assert!(
            updated.contains("email = \"a@b.c\""),
            "operator content must survive: {updated}"
        );
    }

    /// Leaves the caller's own block alone — stripping foreign markers is a
    /// no-op when only the own-path block is present.
    #[test]
    fn strip_foreign_managed_profiles_keeps_own_block() {
        let own = render_profile_for(REMOTE_BOOTSTRAP_PROFILE_MARKERS, "giganto");
        let existing = format!("email = \"a@b.c\"\n\n{own}\n");
        let stripped =
            strip_foreign_managed_profiles(&existing, REMOTE_BOOTSTRAP_PROFILE_MARKERS, "giganto");
        assert_eq!(stripped, existing);
    }

    #[test]
    fn remove_managed_profile_block_strips_span_and_preserves_surroundings() {
        let block = render_managed_profile_block(
            BEGIN_PREFIX,
            END_PREFIX,
            "edge-proxy",
            "001",
            "edge-node-01",
            Path::new("certs/edge-proxy.crt"),
            Path::new("certs/edge-proxy.key"),
            None,
        );
        let original = "email = \"admin@example.com\"\n";
        let with_block = upsert_managed_profile_block(
            &format!("{original}\n[trust]\nca_bundle_path = \"certs/ca.pem\"\n"),
            BEGIN_PREFIX,
            END_PREFIX,
            "edge-proxy",
            &block,
        );
        assert!(with_block.contains("[[profiles]]"));

        let removed =
            remove_managed_profile_block(&with_block, BEGIN_PREFIX, END_PREFIX, "edge-proxy");
        assert!(
            !removed.contains("[[profiles]]"),
            "managed block must be gone: {removed}"
        );
        assert!(
            removed.contains("email = \"admin@example.com\""),
            "operator content before the block must survive: {removed}"
        );
        assert!(
            removed.contains("[trust]"),
            "operator content after the block must survive: {removed}"
        );
        assert!(
            !removed.contains(BEGIN_PREFIX) && !removed.contains(END_PREFIX),
            "no managed markers must remain: {removed}"
        );
    }

    #[test]
    fn remove_managed_profile_block_is_idempotent_when_absent() {
        let contents = "email = \"admin@example.com\"\n\n[trust]\nca_bundle_path = \"c\"\n";
        let once = remove_managed_profile_block(contents, BEGIN_PREFIX, END_PREFIX, "edge-proxy");
        assert_eq!(once, contents);
        let twice = remove_managed_profile_block(&once, BEGIN_PREFIX, END_PREFIX, "edge-proxy");
        assert_eq!(twice, contents);
    }

    /// The surgical variant removes only the `[[profiles]]` entry and its
    /// marker comments, preserving global tables that floated inside the
    /// marker span (unlike the whole-span [`remove_managed_profile_block`]).
    #[test]
    fn remove_managed_service_profile_preserves_floated_tables() {
        let block = render_profile_for(LOCAL_FILE_PROFILE_MARKERS, "giganto");
        let with_block = upsert_managed_profile_block(
            "email = \"a@b.c\"\n",
            LOCAL_FILE_PROFILE_MARKERS.begin_prefix,
            LOCAL_FILE_PROFILE_MARKERS.end_prefix,
            "giganto",
            &block,
        );
        // Upsert global tables so they float inside the marker span, as the
        // real pipeline does.
        let with_block =
            toml_util::upsert_section_keys(&with_block, "trust", &[("ca_bundle_path", "c".into())])
                .expect("trust");
        let with_block =
            toml_util::upsert_section_keys(&with_block, "openbao", &[("addr", "u".into())])
                .expect("openbao");

        let removed = remove_managed_service_profile(&with_block, "giganto").expect("remove ok");
        assert!(
            !removed.contains("[[profiles]]"),
            "profile must be gone: {removed}"
        );
        assert!(
            !removed.contains(LOCAL_FILE_PROFILE_MARKERS.begin_prefix)
                && !removed.contains(LOCAL_FILE_PROFILE_MARKERS.end_prefix),
            "markers must be gone: {removed}"
        );
        assert!(removed.contains("[trust]"), "trust must survive: {removed}");
        assert!(
            removed.contains("[openbao]"),
            "openbao must survive: {removed}"
        );
        assert!(
            removed.contains("email = \"a@b.c\""),
            "operator content must survive: {removed}"
        );
        removed
            .parse::<toml_edit::DocumentMut>()
            .expect("valid TOML after strip");
    }

    /// Returns the input unchanged (no reflow) when the service has no
    /// managed profile, so an idempotent re-run is a true no-op.
    #[test]
    fn remove_managed_service_profile_is_noop_when_absent() {
        let contents = "email = \"a@b.c\"\n\n[trust]\nca_bundle_path = \"c\"\n";
        let out = remove_managed_service_profile(contents, "giganto").expect("remove ok");
        assert_eq!(out, contents);
    }

    /// Service names are DNS labels and can be prefixes of one another
    /// (`api` vs `api-v2`). Substring marker matching would let a remove
    /// of `api` strip `api-v2`'s block; full-line matching must target
    /// only the exact service's block and leave the sibling intact.
    #[test]
    fn remove_managed_profile_block_ignores_prefix_named_siblings() {
        let make_block = |name: &str| {
            render_managed_profile_block(
                BEGIN_PREFIX,
                END_PREFIX,
                name,
                "001",
                "node-01",
                Path::new(&format!("certs/{name}.crt")),
                Path::new(&format!("certs/{name}.key")),
                None,
            )
        };
        let contents = format!("{}\n{}", make_block("api-v2"), make_block("apifoobar"));

        let removed = remove_managed_profile_block(&contents, BEGIN_PREFIX, END_PREFIX, "api");
        assert_eq!(
            removed, contents,
            "removing absent `api` must not touch prefix-sharing siblings: {removed}"
        );

        let removed_v2 =
            remove_managed_profile_block(&contents, BEGIN_PREFIX, END_PREFIX, "api-v2");
        assert!(
            !removed_v2.contains("api-v2.crt"),
            "the exact `api-v2` block must be removed: {removed_v2}"
        );
        assert!(
            removed_v2.contains("apifoobar.crt")
                && removed_v2.contains(&format!("{END_PREFIX} apifoobar")),
            "the prefix-sharing sibling `apifoobar` must survive intact: {removed_v2}"
        );
    }

    #[test]
    fn remove_managed_profile_block_only_content_yields_empty() {
        let block = render_managed_profile_block(
            BEGIN_PREFIX,
            END_PREFIX,
            "edge-proxy",
            "001",
            "edge-node-01",
            Path::new("certs/edge-proxy.crt"),
            Path::new("certs/edge-proxy.key"),
            None,
        );
        let removed = remove_managed_profile_block(&block, BEGIN_PREFIX, END_PREFIX, "edge-proxy");
        assert!(removed.is_empty(), "file with only the block becomes empty");
    }

    /// `--cert-group` opts the rendered profile into a `cert_group_gid`
    /// line that survives across re-renders. Without it, rotation
    /// loses the policy and the original issue #593 reproduces.
    #[test]
    fn render_managed_profile_block_includes_cert_group_gid() {
        let block = render_managed_profile_block(
            BEGIN_PREFIX,
            END_PREFIX,
            "edge-proxy",
            "001",
            "edge-node-01",
            Path::new("certs/edge-proxy.crt"),
            Path::new("certs/edge-proxy.key"),
            Some(5001),
        );
        let has_policy_line = block.contains("cert_group_gid = 5001");
        assert!(
            has_policy_line,
            "rendered profile must include the policy line"
        );
    }

    #[test]
    fn render_managed_profile_block_omits_cert_group_gid_when_none() {
        let block = render_managed_profile_block(
            BEGIN_PREFIX,
            END_PREFIX,
            "edge-proxy",
            "001",
            "edge-node-01",
            Path::new("certs/edge-proxy.crt"),
            Path::new("certs/edge-proxy.key"),
            None,
        );
        let has_policy_line = block.contains("cert_group_gid");
        assert!(
            !has_policy_line,
            "rendered profile must omit the policy line when unset"
        );
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
