use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::cert_group::CertGroupPolicy;
use bootroot::fs_util;
use bootroot::toml_util::toml_encode_string;
use bootroot::trust_bootstrap::{
    AgentConfigBaselineParams, LOCAL_FILE_PROFILE_MARKERS, apply_agent_config_baseline_defaults,
    build_trust_updates, render_managed_profile_block as render_managed_profile,
    strip_foreign_managed_profiles, upsert_managed_profile_block,
};
use tokio::fs;

use super::resolve::ResolvedServiceAdd;
use super::{
    LocalApplyResult, MANAGED_PROFILE_BEGIN_PREFIX, MANAGED_PROFILE_END_PREFIX,
    SERVICE_EAB_FILENAME, SERVICE_ROLE_ID_FILENAME, ServiceSyncMaterial, effective_agent_email,
    effective_agent_responder_url, effective_agent_server,
};
use crate::i18n::Messages;
use crate::state::PostRenewHookEntry;

#[allow(clippy::too_many_lines)]
pub(super) async fn apply_local_service_configs(
    secrets_dir: &Path,
    resolved: &ResolvedServiceAdd,
    secret_id_path: &Path,
    sync_material: &ServiceSyncMaterial,
    kv_mount: &str,
    openbao_url: &str,
    messages: &Messages,
) -> Result<LocalApplyResult> {
    // The relocation flag is fully determined by whether the operator
    // supplied `--secret-id-path`; `secret_id_path` is the matching
    // resolved value, so deriving it here keeps the two in lock-step.
    let is_override = resolved.secret_id_path_override.is_some();
    let profile = render_managed_profile_block(resolved);
    let ca_bundle_path = resolved
        .cert_path
        .parent()
        .unwrap_or(Path::new("certs"))
        .join("ca-bundle.pem");
    let current = if resolved.agent_config.exists() {
        fs::read_to_string(&resolved.agent_config)
            .await
            .with_context(|| {
                messages.error_read_file_failed(&resolved.agent_config.display().to_string())
            })?
    } else {
        String::new()
    };
    // Strip any managed profile block the remote-bootstrap path left for
    // this service on a prior delivery mode, before any table is appended.
    // Done on the raw file so the strip stays contained to the intended
    // `[[profiles]]` block (the end marker floats past tables added later).
    // Without this, a remote→local transition would append a duplicate
    // block for the service (#662).
    let current = strip_foreign_managed_profiles(
        &current,
        LOCAL_FILE_PROFILE_MARKERS,
        &resolved.service_name,
    );
    // Backfill any baseline fields missing from the operator-facing
    // `agent.toml` — both for a fresh file and for an existing file that
    // lacks `email` / `server` / `[acme].http_responder_url` or the
    // retry/timeout tunables.  Without this, #549 recurs when the KV
    // re-render loses those fields.  `insert_missing_*` preserves any
    // value the operator already set.
    let mut next = apply_agent_config_baseline_defaults(
        &current,
        &AgentConfigBaselineParams {
            email: effective_agent_email(resolved.agent_email.as_deref()),
            server: effective_agent_server(resolved.agent_server.as_deref()),
            domain: &resolved.domain,
            http_responder_url: effective_agent_responder_url(
                resolved.agent_responder_url.as_deref(),
            ),
        },
    )?;
    // Explicit `--agent-*` overrides take precedence over whatever was
    // in the pre-existing file, so operators can re-bake a changed ACME
    // topology without hand-editing.
    if let Some(email) = resolved.agent_email.as_deref() {
        next = bootroot::toml_util::upsert_top_level_keys(&next, &[("email", email.to_string())])?;
    }
    if let Some(server) = resolved.agent_server.as_deref() {
        next =
            bootroot::toml_util::upsert_top_level_keys(&next, &[("server", server.to_string())])?;
    }
    if let Some(responder_url) = resolved.agent_responder_url.as_deref() {
        next = bootroot::toml_util::upsert_section_keys(
            &next,
            "acme",
            &[("http_responder_url", responder_url.to_string())],
        )?;
    }
    let with_profile = upsert_managed_profile(&next, &resolved.service_name, &profile);
    let mut next = with_profile;
    let trust_updates = build_trust_updates(&sync_material.trusted_ca_sha256, &ca_bundle_path);
    next = bootroot::toml_util::upsert_section_keys(&next, "trust", &trust_updates)?;
    let domain_updates = vec![("domain", resolved.domain.clone())];
    next = bootroot::toml_util::upsert_top_level_keys(&next, &domain_updates)?;
    let acme_updates = vec![("http_responder_hmac", sync_material.responder_hmac.clone())];
    next = bootroot::toml_util::upsert_section_keys(&next, "acme", &acme_updates)?;
    // The `[openbao]` section activates the agent's fast-poll loop — the
    // single secret-delivery mechanism for local-file services.  The
    // host-daemon agent self-authenticates via AppRole and keeps trust,
    // `secret_id`, the responder HMAC, and EAB current from KV, exactly
    // like `bootroot-remote bootstrap` provisions for remote hosts.
    // All paths are host-relative because the agent runs as a host
    // daemon; no container-perspective rewriting exists anymore.
    let role_id_path = secret_id_path
        .parent()
        .unwrap_or(Path::new("."))
        .join(SERVICE_ROLE_ID_FILENAME);
    let openbao_updates = build_local_openbao_updates(&LocalOpenBaoUpdateInputs {
        openbao_url,
        kv_mount,
        role_id_path: &role_id_path,
        secret_id_path,
        ca_bundle_path: &ca_bundle_path,
        agent_config_path: &resolved.agent_config,
        service_name: &resolved.service_name,
        current_contents: &next,
    })?;
    next = bootroot::toml_util::upsert_section_keys(&next, "openbao", &openbao_updates)?;
    // The CA bundle is public trust material: write it 0644 and pick up
    // the `--cert-group` gid when a policy is set, so cert-group members
    // and non-root consumers in separate containers can read it.
    let cert_group_policy = CertGroupPolicy {
        gid: resolved.cert_group_gid,
    };
    write_local_ca_bundle(
        &ca_bundle_path,
        &sync_material.ca_bundle_pem,
        cert_group_policy,
        messages,
    )
    .await?;
    let eab_path = provision_local_eab_file(
        secrets_dir,
        secret_id_path,
        is_override,
        sync_material,
        messages,
    )
    .await?;
    // `service add` is the authoritative writer for the operator's
    // `agent.toml`; create its parent chain if missing so callers do not
    // have to keep a separate `mkdir -p` in sync with `--agent-config`.
    // `create_dir_all` leaves pre-existing components untouched (mode
    // and ownership), so an operator-tightened directory is not widened.
    // Newly created components use process umask (0755 by default).
    if let Some(parent) = resolved.agent_config.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).await.with_context(|| {
            messages.error_write_file_failed(&resolved.agent_config.display().to_string())
        })?;
    }
    // `agent.toml` is hot-read by `bootroot-agent`'s daemon retry loop
    // on every ACME attempt. Routing the write through a temp file +
    // atomic rename closes the truncate/write race that surfaced in
    // #613 as renewals failing with "profile not found in reloaded
    // config" and exhausting the retry budget against a transient
    // partial file.
    fs_util::atomic_write(
        &resolved.agent_config,
        next.as_bytes(),
        fs_util::KEY_FILE_MODE,
    )
    .await
    .with_context(|| {
        messages.error_write_file_failed(&resolved.agent_config.display().to_string())
    })?;

    Ok(LocalApplyResult {
        agent_config: resolved.agent_config.display().to_string(),
        eab_file: eab_path.display().to_string(),
    })
}

/// Inputs for [`build_local_openbao_updates`].
struct LocalOpenBaoUpdateInputs<'a> {
    openbao_url: &'a str,
    kv_mount: &'a str,
    role_id_path: &'a Path,
    secret_id_path: &'a Path,
    ca_bundle_path: &'a Path,
    agent_config_path: &'a Path,
    service_name: &'a str,
    current_contents: &'a str,
}

/// Builds the `[openbao]` key-value pairs local `service add` upserts
/// into `agent.toml`, mirroring what `bootroot-remote bootstrap` writes
/// on remote hosts (`build_openbao_updates`).  Connection-level fields
/// are always refreshed.  A stable absolute `state_path` (service-keyed
/// so per-service agent configs sharing one directory do not contend
/// over a single state file) is provisioned adjacent to `agent.toml`
/// when the operator has not already set an absolute one — config
/// validation rejects a relative or defaulted `state_path` because the
/// daemon cwd is not contracted to be stable under systemd-style
/// supervisors.
fn build_local_openbao_updates(
    inputs: &LocalOpenBaoUpdateInputs<'_>,
) -> Result<Vec<(&'static str, String)>> {
    let mut pairs = vec![
        ("url", inputs.openbao_url.to_string()),
        ("kv_mount", inputs.kv_mount.to_string()),
        ("role_id_path", inputs.role_id_path.display().to_string()),
        (
            "secret_id_path",
            inputs.secret_id_path.display().to_string(),
        ),
        (
            "ca_bundle_path",
            inputs.ca_bundle_path.display().to_string(),
        ),
    ];
    // A non-loopback plaintext URL fails config validation without the
    // explicit opt-in. The local `url` defaults to loopback
    // `http://localhost:8200`, but an operator can point `bootroot init`
    // at a non-loopback address, so apply the same rule as the remote
    // writer. Loopback plaintext and https:// never need it.
    if bootroot::config::openbao_url_is_non_loopback_plaintext(inputs.openbao_url) {
        pairs.push(("allow_plaintext_http", "true".to_string()));
    }
    if needs_absolute_state_path_provisioning(inputs.current_contents) {
        pairs.push((
            "state_path",
            default_state_path_for(inputs.agent_config_path, inputs.service_name)?,
        ));
    }
    Ok(pairs)
}

/// Reports whether `state_path` must be (re)provisioned: the key is
/// missing, malformed, or holds a relative path that would resolve
/// against the daemon process cwd.
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

/// Returns the absolute, service-keyed fast-poll `state_path` adjacent
/// to `agent.toml`.  Unlike the remote provisioning (which bails out on
/// relative agent-config paths), the co-located CLI can resolve a
/// relative `--agent-config` against its own cwd — the resulting
/// absolute path names the same file the operator pointed at.
fn default_state_path_for(agent_config_path: &Path, service_name: &str) -> Result<String> {
    let absolute_config = std::path::absolute(agent_config_path).with_context(|| {
        format!(
            "failed to resolve absolute path for {}",
            agent_config_path.display()
        )
    })?;
    let parent = absolute_config
        .parent()
        .unwrap_or_else(|| Path::new("/"))
        .to_path_buf();
    Ok(parent
        .join(state_path_basename(service_name))
        .display()
        .to_string())
}

/// Derives the per-service fast-poll state filename.  `service_name` is
/// a validated DNS label (`validate_service_name` → `validate_dns_label`),
/// so it can never introduce a path separator or `..`.
fn state_path_basename(service_name: &str) -> String {
    debug_assert!(
        !service_name.is_empty()
            && !service_name.contains(['/', '\\'])
            && !service_name.contains(".."),
        "service_name must be a validated DNS label, got {service_name:?}"
    );
    format!("bootroot-agent-state-{service_name}.json")
}

/// Provisions the service's `eab.json` next to its `secret_id` so the
/// documented daemon run command can pass `--eab-file` — without that
/// flag the fast-poll EAB refresh is a silent no-op.  Mirrors the remote
/// bootstrap semantics: credentials present in KV are written to disk,
/// and a stale file is removed when KV holds no EAB (an absent file is
/// the durable "open enrollment" representation `--eab-file` expects).
/// Returns the `eab.json` path either way.
async fn provision_local_eab_file(
    secrets_dir: &Path,
    secret_id_path: &Path,
    is_override: bool,
    sync_material: &ServiceSyncMaterial,
    messages: &Messages,
) -> Result<PathBuf> {
    let svc_cred_dir = secret_id_path.parent().unwrap_or(secrets_dir);
    let eab_path = svc_cred_dir.join(SERVICE_EAB_FILENAME);
    match (
        sync_material.eab_kid.as_deref(),
        sync_material.eab_hmac.as_deref(),
    ) {
        (Some(kid), Some(hmac)) if !kid.is_empty() && !hmac.is_empty() => {
            write_local_eab_file(&eab_path, kid, hmac, is_override, messages).await?;
        }
        _ => {
            bootroot::eab::remove_eab_file(&eab_path)
                .await
                .with_context(|| {
                    messages.error_write_file_failed(&eab_path.display().to_string())
                })?;
        }
    }
    Ok(eab_path)
}

/// Writes the service `eab.json` at `path`.
///
/// For the default secrets-tree location this delegates to the shared
/// [`bootroot::eab::write_eab_file`]. For a relocated (override) path,
/// which lives in the operator-provisioned, agent-owned directory, the
/// same byte-identical payload is written through
/// [`fs_util::write_owned_file_replace`] so the fresh file is chowned to
/// the agent-owning parent, stays `0600` and symlink-safe, and — unlike
/// `secret_id`/`role_id` — is legitimately overwritten on every sync.
/// The shared writer's ownership/`ensure_secrets_dir` semantics are left
/// intact for remote and agent callers.
async fn write_local_eab_file(
    path: &Path,
    kid: &str,
    hmac: &str,
    is_override: bool,
    messages: &Messages,
) -> Result<()> {
    if is_override {
        let payload = bootroot::eab::serialize_eab_payload(kid, hmac)
            .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
        fs_util::write_owned_file_replace(path, payload.as_bytes(), fs_util::KEY_FILE_MODE)
            .await
            .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    } else {
        bootroot::eab::write_eab_file(path, kid, hmac)
            .await
            .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    }
    Ok(())
}

/// Pre-seeds the public CA bundle on disk so the agent can verify TLS
/// against `OpenBao` on first boot; the fast-poll loop keeps it current
/// from KV afterwards.
///
/// The bundle is public trust material, so it is written at
/// [`fs_util::write_ca_bundle`]'s `0644` mode (not the operator-only
/// `0600` used for secrets) and, when a `--cert-group` policy is active,
/// `chown`ed to the policy gid. This lets a non-root consumer in a
/// separate container read the bind-mounted file.
///
/// The PEM is normalized to end in a trailing newline before writing to
/// preserve the historical on-disk shape (`write_ca_bundle` itself writes
/// bytes verbatim).
async fn write_local_ca_bundle(
    path: &Path,
    bundle_pem: &str,
    policy: CertGroupPolicy,
    messages: &Messages,
) -> Result<()> {
    let contents = if bundle_pem.ends_with('\n') {
        bundle_pem.to_string()
    } else {
        format!("{bundle_pem}\n")
    };
    fs_util::write_ca_bundle(path, &contents, policy)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

fn render_managed_profile_block(args: &ResolvedServiceAdd) -> String {
    let base = render_managed_profile(
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        &args.service_name,
        args.instance_id.as_deref().unwrap_or_default(),
        &args.hostname,
        &args.cert_path,
        &args.key_path,
        args.cert_group_gid,
    );
    inject_hooks_into_profile_block(&base, &args.post_renew_hooks)
}

fn inject_hooks_into_profile_block(block: &str, hooks: &[PostRenewHookEntry]) -> String {
    if hooks.is_empty() {
        return block.to_string();
    }
    let hooks_toml = render_hooks_toml(hooks);
    if let Some(end_pos) = block.rfind(MANAGED_PROFILE_END_PREFIX) {
        let mut result = block[..end_pos].to_string();
        result.push_str(&hooks_toml);
        result.push_str(&block[end_pos..]);
        result
    } else {
        let mut result = block.to_string();
        result.push_str(&hooks_toml);
        result
    }
}

fn render_hooks_toml(hooks: &[PostRenewHookEntry]) -> String {
    let mut output = String::new();
    for hook in hooks {
        output.push_str("\n[[profiles.hooks.post_renew.success]]\n");
        let _ = writeln!(output, "command = {}", toml_encode_string(&hook.command));
        if !hook.args.is_empty() {
            let args = hook
                .args
                .iter()
                .map(|a| toml_encode_string(a))
                .collect::<Vec<_>>()
                .join(", ");
            let _ = writeln!(output, "args = [{args}]");
        }
        let _ = writeln!(output, "timeout_secs = {}", hook.timeout_secs);
        let _ = writeln!(output, "on_failure = \"{}\"", hook.on_failure);
    }
    output
}

fn upsert_managed_profile(contents: &str, service_name: &str, replacement: &str) -> String {
    upsert_managed_profile_block(
        contents,
        MANAGED_PROFILE_BEGIN_PREFIX,
        MANAGED_PROFILE_END_PREFIX,
        service_name,
        replacement,
    )
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use bootroot::trust_bootstrap::render_agent_config_baseline;

    use super::super::resolve::ResolvedServiceAdd;
    use super::super::{DEFAULT_AGENT_EMAIL, DEFAULT_AGENT_RESPONDER_URL, DEFAULT_AGENT_SERVER};
    use super::*;
    use crate::commands::constants::CA_TRUST_KEY;
    use crate::state::DeliveryMode;

    fn test_resolved() -> ResolvedServiceAdd {
        ResolvedServiceAdd {
            service_name: "edge-proxy".to_string(),
            delivery_mode: DeliveryMode::LocalFile,
            hostname: "edge-node-01".to_string(),
            domain: "trusted.domain".to_string(),
            agent_config: PathBuf::from("agent.toml"),
            cert_path: PathBuf::from("certs/edge-proxy.crt"),
            key_path: PathBuf::from("certs/edge-proxy.key"),
            instance_id: Some("001".to_string()),
            runtime_auth: None,
            notes: None,
            post_renew_hooks: Vec::new(),
            secret_id_ttl: None,
            secret_id_wrap_ttl: None,
            token_bound_cidrs: None,
            agent_email: None,
            agent_server: None,
            agent_responder_url: None,
            cert_group_gid: None,
            secret_id_path_override: None,
        }
    }

    fn test_sync_material() -> ServiceSyncMaterial {
        ServiceSyncMaterial {
            eab_kid: None,
            eab_hmac: None,
            responder_hmac: "hmac-val".to_string(),
            trusted_ca_sha256: vec!["a".repeat(64)],
            ca_bundle_pem: "PEM".to_string(),
        }
    }

    #[test]
    fn test_upsert_managed_profile_is_idempotent() {
        let args = test_resolved();
        let block = render_managed_profile_block(&args);
        let once = upsert_managed_profile("", "edge-proxy", &block);
        let twice = upsert_managed_profile(&once, "edge-proxy", &block);
        assert_eq!(once, twice);
    }

    /// remote-bootstrap → local-file transition: local-file `service add`
    /// runs over an `agent.toml` that already carries a `BOOTROOT REMOTE
    /// PROFILE` block. Stripping foreign blocks before upserting the local
    /// block must leave exactly one `[[profiles]]`, not a duplicate (#662).
    #[test]
    fn test_local_add_strips_pre_existing_remote_block() {
        let args = test_resolved();
        let remote_block = render_managed_profile(
            bootroot::trust_bootstrap::REMOTE_BOOTSTRAP_PROFILE_MARKERS.begin_prefix,
            bootroot::trust_bootstrap::REMOTE_BOOTSTRAP_PROFILE_MARKERS.end_prefix,
            &args.service_name,
            args.instance_id.as_deref().unwrap_or_default(),
            &args.hostname,
            &args.cert_path,
            &args.key_path,
            args.cert_group_gid,
        );
        let existing = format!("email = \"admin@example.com\"\n\n{remote_block}\n");

        let stripped = strip_foreign_managed_profiles(
            &existing,
            LOCAL_FILE_PROFILE_MARKERS,
            &args.service_name,
        );
        let local_block = render_managed_profile_block(&args);
        let updated = upsert_managed_profile(&stripped, &args.service_name, &local_block);

        assert_eq!(
            updated.matches("[[profiles]]").count(),
            1,
            "exactly one profile block must remain: {updated}"
        );
        assert!(
            !updated
                .contains(bootroot::trust_bootstrap::REMOTE_BOOTSTRAP_PROFILE_MARKERS.begin_prefix),
            "the stale remote block must be stripped: {updated}"
        );
        assert!(
            updated.contains(LOCAL_FILE_PROFILE_MARKERS.begin_prefix),
            "the local-file marker must be present: {updated}"
        );
    }

    #[test]
    fn test_upsert_toml_section_keys_adds_and_updates_trust_section_idempotently() {
        let updates = build_trust_updates(
            &["a".repeat(64), "b".repeat(64)],
            Path::new("certs/ca-bundle.pem"),
        );
        let original = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let once = bootroot::toml_util::upsert_section_keys(original, "trust", &updates).unwrap();
        let twice = bootroot::toml_util::upsert_section_keys(&once, "trust", &updates).unwrap();

        assert_eq!(once, twice);
        assert!(once.contains("[trust]"));
        assert!(once.contains("ca_bundle_path = \"certs/ca-bundle.pem\""));
        assert!(once.contains("trusted_ca_sha256 = ["));
    }

    #[test]
    fn test_upsert_toml_section_keys_preserves_existing_unmanaged_lines() {
        let updates = vec![("ca_bundle_path", "certs/ca.pem".to_string())];
        let original = "[trust]\nextra = true\n";
        let output = bootroot::toml_util::upsert_section_keys(original, "trust", &updates).unwrap();

        assert!(output.contains("extra = true"));
        assert!(output.contains("ca_bundle_path = \"certs/ca.pem\""));
    }

    #[test]
    fn test_build_trust_updates_writes_bundle_and_pins_only() {
        let updates = build_trust_updates(&["a".repeat(64)], Path::new("certs/ca-bundle.pem"));

        assert_eq!(updates.len(), 2);
        assert!(updates.iter().any(|(key, _)| *key == "ca_bundle_path"));
        assert!(updates.iter().any(|(key, _)| *key == CA_TRUST_KEY));
    }

    /// Exercises the fresh-file path of [`apply_local_service_configs`]:
    /// seeds the managed-profile upserts over the shared baseline and
    /// confirms the rendered `agent.toml` preserves every field an
    /// operator might need to customise.  Guards against the regression
    /// in #549 where rotation re-renders overwrote hand-edited `server` /
    /// `http_responder_url` lines because the render lost them.
    #[test]
    fn test_fresh_agent_config_carries_full_baseline() {
        let args = test_resolved();
        let baseline = render_agent_config_baseline(&AgentConfigBaselineParams {
            email: DEFAULT_AGENT_EMAIL,
            server: DEFAULT_AGENT_SERVER,
            domain: &args.domain,
            http_responder_url: DEFAULT_AGENT_RESPONDER_URL,
        });
        let profile = render_managed_profile_block(&args);
        let with_profile = upsert_managed_profile(&baseline, "edge-proxy", &profile);
        let trust_updates =
            build_trust_updates(&["a".repeat(64)], Path::new("certs/ca-bundle.pem"));
        let with_trust =
            bootroot::toml_util::upsert_section_keys(&with_profile, "trust", &trust_updates)
                .unwrap();
        let domain_updates = vec![("domain", args.domain.clone())];
        let with_domain =
            bootroot::toml_util::upsert_top_level_keys(&with_trust, &domain_updates).unwrap();
        let acme_updates = vec![("http_responder_hmac", "hmac-val".to_string())];
        let rendered =
            bootroot::toml_util::upsert_section_keys(&with_domain, "acme", &acme_updates).unwrap();

        assert!(
            rendered.contains(&format!("email = \"{DEFAULT_AGENT_EMAIL}\"")),
            "rendered config must embed email: {rendered}"
        );
        assert!(
            rendered.contains(&format!("server = \"{DEFAULT_AGENT_SERVER}\"")),
            "rendered config must embed server: {rendered}"
        );
        assert!(
            rendered.contains(&format!(
                "http_responder_url = \"{DEFAULT_AGENT_RESPONDER_URL}\""
            )),
            "rendered config must embed http_responder_url: {rendered}"
        );
        assert!(
            rendered.contains("directory_fetch_attempts = 10"),
            "rendered config must preserve [acme] retry tunables: {rendered}"
        );
        assert!(
            rendered.contains("http_responder_timeout_secs = 5"),
            "rendered config must preserve [acme] timeout tunables: {rendered}"
        );
    }

    #[test]
    fn test_generated_config_includes_domain_and_acme() {
        let args = test_resolved();
        let fp = "a".repeat(64);
        let profile = render_managed_profile_block(&args);
        let with_profile = upsert_managed_profile("", "edge-proxy", &profile);
        let trust_updates = build_trust_updates(&[fp], Path::new("certs/ca-bundle.pem"));
        let with_trust =
            bootroot::toml_util::upsert_section_keys(&with_profile, "trust", &trust_updates)
                .unwrap();
        let domain_updates = vec![("domain", "trusted.domain".to_string())];
        let with_domain =
            bootroot::toml_util::upsert_top_level_keys(&with_trust, &domain_updates).unwrap();
        let acme_updates = vec![("http_responder_hmac", "test-hmac-value".to_string())];
        let output =
            bootroot::toml_util::upsert_section_keys(&with_domain, "acme", &acme_updates).unwrap();

        assert!(
            output.contains("domain = \"trusted.domain\""),
            "missing domain: {output}"
        );
        assert!(
            output.contains("[acme]"),
            "missing [acme] section: {output}"
        );
        assert!(
            output.contains("http_responder_hmac = \"test-hmac-value\""),
            "missing http_responder_hmac: {output}"
        );
        assert!(output.contains("[[profiles]]"), "missing profile: {output}");
        assert!(output.contains("[trust]"), "missing trust: {output}");
    }

    #[test]
    fn test_domain_and_acme_upsert_is_idempotent() {
        let args = test_resolved();
        let profile = render_managed_profile_block(&args);
        let with_profile = upsert_managed_profile("", "edge-proxy", &profile);
        let trust_updates =
            build_trust_updates(&["a".repeat(64)], Path::new("certs/ca-bundle.pem"));
        let with_trust =
            bootroot::toml_util::upsert_section_keys(&with_profile, "trust", &trust_updates)
                .unwrap();
        let domain_updates = vec![("domain", "trusted.domain".to_string())];
        let acme_updates = vec![("http_responder_hmac", "hmac-val".to_string())];

        let once =
            bootroot::toml_util::upsert_top_level_keys(&with_trust, &domain_updates).unwrap();
        let once = bootroot::toml_util::upsert_section_keys(&once, "acme", &acme_updates).unwrap();

        let twice = bootroot::toml_util::upsert_top_level_keys(&once, &domain_updates).unwrap();
        let twice =
            bootroot::toml_util::upsert_section_keys(&twice, "acme", &acme_updates).unwrap();

        assert_eq!(once, twice);
    }

    /// The `[openbao]` section is what activates the local fast-poll
    /// loop; it must carry the same keys `bootroot-remote bootstrap`
    /// writes, with host-relative paths and an absolute, service-keyed
    /// `state_path` adjacent to `agent.toml`.
    #[test]
    fn test_local_openbao_updates_provision_fast_poll_section() {
        let updates = build_local_openbao_updates(&LocalOpenBaoUpdateInputs {
            openbao_url: "https://localhost:8200",
            kv_mount: "secret",
            role_id_path: Path::new("secrets/services/edge-proxy/role_id"),
            secret_id_path: Path::new("secrets/services/edge-proxy/secret_id"),
            ca_bundle_path: Path::new("certs/ca-bundle.pem"),
            agent_config_path: Path::new("/etc/bootroot/agent.toml"),
            service_name: "edge-proxy",
            current_contents: "",
        })
        .unwrap();

        let get = |key: &str| {
            updates
                .iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("url"), Some("https://localhost:8200"));
        assert_eq!(get("kv_mount"), Some("secret"));
        assert_eq!(
            get("role_id_path"),
            Some("secrets/services/edge-proxy/role_id")
        );
        assert_eq!(
            get("secret_id_path"),
            Some("secrets/services/edge-proxy/secret_id")
        );
        assert_eq!(get("ca_bundle_path"), Some("certs/ca-bundle.pem"));
        assert_eq!(
            get("state_path"),
            Some("/etc/bootroot/bootroot-agent-state-edge-proxy.json"),
            "state_path must be absolute and service-keyed"
        );
    }

    fn openbao_updates_for_url(url: &str) -> Vec<(&'static str, String)> {
        build_local_openbao_updates(&LocalOpenBaoUpdateInputs {
            openbao_url: url,
            kv_mount: "secret",
            role_id_path: Path::new("secrets/services/edge-proxy/role_id"),
            secret_id_path: Path::new("secrets/services/edge-proxy/secret_id"),
            ca_bundle_path: Path::new("certs/ca-bundle.pem"),
            agent_config_path: Path::new("/etc/bootroot/agent.toml"),
            service_name: "edge-proxy",
            current_contents: "",
        })
        .unwrap()
    }

    #[test]
    fn test_local_openbao_updates_emit_opt_in_for_non_loopback_plaintext() {
        let updates = openbao_updates_for_url("http://10.0.0.5:8200");
        assert!(
            updates
                .iter()
                .any(|(k, v)| *k == "allow_plaintext_http" && v == "true"),
            "non-loopback plaintext must upsert the opt-in: {updates:?}"
        );
    }

    #[test]
    fn test_local_openbao_updates_omit_opt_in_for_loopback_plaintext() {
        let updates = openbao_updates_for_url("http://localhost:8200");
        assert!(
            !updates.iter().any(|(k, _)| *k == "allow_plaintext_http"),
            "loopback plaintext must not emit the opt-in: {updates:?}"
        );
    }

    #[test]
    fn test_local_openbao_updates_omit_opt_in_for_https() {
        let updates = openbao_updates_for_url("https://openbao.example:8200");
        assert!(
            !updates.iter().any(|(k, _)| *k == "allow_plaintext_http"),
            "https must not emit the opt-in: {updates:?}"
        );
    }

    /// A relative `--agent-config` still yields an absolute `state_path`
    /// (resolved against the CLI cwd) — config validation rejects
    /// relative `state_path` values, so provisioning must never emit one.
    #[test]
    fn test_local_state_path_is_absolute_for_relative_agent_config() {
        let updates = build_local_openbao_updates(&LocalOpenBaoUpdateInputs {
            openbao_url: "http://localhost:8200",
            kv_mount: "secret",
            role_id_path: Path::new("secrets/services/edge-proxy/role_id"),
            secret_id_path: Path::new("secrets/services/edge-proxy/secret_id"),
            ca_bundle_path: Path::new("certs/ca-bundle.pem"),
            agent_config_path: Path::new("agent.toml"),
            service_name: "edge-proxy",
            current_contents: "",
        })
        .unwrap();
        let state_path = updates
            .iter()
            .find(|(k, _)| *k == "state_path")
            .map(|(_, v)| v.as_str())
            .expect("state_path must be provisioned");
        assert!(
            Path::new(state_path).is_absolute(),
            "state_path must be absolute, got: {state_path}"
        );
        assert!(
            state_path.ends_with("bootroot-agent-state-edge-proxy.json"),
            "state_path must be service-keyed, got: {state_path}"
        );
    }

    /// An operator-tuned absolute `state_path` is preserved; a relative
    /// or missing one is (re)provisioned.
    #[test]
    fn test_local_state_path_preserves_operator_absolute_value() {
        let with_absolute = "[openbao]\nurl = \"http://localhost:8200\"\nstate_path = \"/var/lib/bootroot/state.json\"\n";
        assert!(!needs_absolute_state_path_provisioning(with_absolute));

        let with_relative =
            "[openbao]\nurl = \"http://localhost:8200\"\nstate_path = \"state.json\"\n";
        assert!(needs_absolute_state_path_provisioning(with_relative));

        assert!(needs_absolute_state_path_provisioning(""));
        assert!(needs_absolute_state_path_provisioning(
            "[openbao]\nurl = \"http://localhost:8200\"\n"
        ));
    }

    /// EAB material present in KV must land in `eab.json` next to the
    /// service `secret_id` so the daemon run command's `--eab-file`
    /// picks it up; absent material must remove a stale file (the
    /// durable "open enrollment" representation).
    #[tokio::test]
    async fn test_provision_local_eab_file_writes_and_clears() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path();
        let secret_id_path = secrets_dir.join("services/edge-proxy/secret_id");
        std::fs::create_dir_all(secret_id_path.parent().unwrap()).unwrap();
        let messages = crate::i18n::test_messages();

        let mut material = test_sync_material();
        material.eab_kid = Some("kid-1".to_string());
        material.eab_hmac = Some("hmac-1".to_string());
        let eab_path =
            provision_local_eab_file(secrets_dir, &secret_id_path, false, &material, &messages)
                .await
                .unwrap();
        assert_eq!(
            eab_path,
            secrets_dir.join("services/edge-proxy/eab.json"),
            "eab.json must sit next to secret_id"
        );
        let creds = bootroot::eab::load_credentials(None, None, Some(eab_path.clone()))
            .await
            .unwrap()
            .expect("credentials must round-trip");
        assert_eq!(creds.kid, "kid-1");
        assert_eq!(creds.hmac, "hmac-1");

        let cleared = test_sync_material();
        provision_local_eab_file(secrets_dir, &secret_id_path, false, &cleared, &messages)
            .await
            .unwrap();
        assert!(
            !eab_path.exists(),
            "stale eab.json must be removed when KV holds no EAB"
        );
    }

    /// An override (relocated) `secret_id_path` places `eab.json` in the
    /// operator-provisioned, agent-owned directory, chowned to that
    /// account and `0600`, without re-moding the directory. Gated on a
    /// supplementary gid being available, like the other ownership tests.
    #[tokio::test]
    async fn test_provision_local_eab_file_override_is_agent_owned() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let Some(gid) = bootroot::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let agent_dir = dir.path().join("agent").join("edge-proxy");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::os::unix::fs::chown(&agent_dir, None, Some(gid))
            .expect("test process must be able to chgrp the override dir");
        std::fs::set_permissions(&agent_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        let secret_id_path = agent_dir.join("secret_id");
        let messages = crate::i18n::test_messages();

        let mut material = test_sync_material();
        material.eab_kid = Some("kid-1".to_string());
        material.eab_hmac = Some("hmac-1".to_string());
        let eab_path =
            provision_local_eab_file(&secrets_dir, &secret_id_path, true, &material, &messages)
                .await
                .unwrap();

        assert_eq!(eab_path, agent_dir.join("eab.json"));
        let meta = std::fs::metadata(&eab_path).unwrap();
        assert_eq!(
            meta.gid(),
            gid,
            "override eab.json must be chowned to the agent gid"
        );
        assert_eq!(meta.permissions().mode() & 0o777, fs_util::KEY_FILE_MODE);
        assert_eq!(
            std::fs::metadata(&agent_dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "override eab provisioning must not re-mode the operator directory"
        );
        let creds = bootroot::eab::load_credentials(None, None, Some(eab_path))
            .await
            .unwrap()
            .expect("credentials must round-trip");
        assert_eq!(creds.kid, "kid-1");
        assert_eq!(creds.hmac, "hmac-1");
    }

    /// Empty-string EAB values (the KV "cleared" shape written by
    /// `rotate eab-clear`) must be treated as no credentials.
    #[tokio::test]
    async fn test_provision_local_eab_file_treats_empty_strings_as_cleared() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path();
        let secret_id_path = secrets_dir.join("services/edge-proxy/secret_id");
        std::fs::create_dir_all(secret_id_path.parent().unwrap()).unwrap();
        let messages = crate::i18n::test_messages();

        let mut material = test_sync_material();
        material.eab_kid = Some(String::new());
        material.eab_hmac = Some(String::new());
        let eab_path =
            provision_local_eab_file(secrets_dir, &secret_id_path, false, &material, &messages)
                .await
                .unwrap();
        assert!(
            !eab_path.exists(),
            "empty-string EAB must not produce an eab.json"
        );
    }

    #[test]
    fn test_render_hooks_toml_single_hook() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let hooks = vec![PostRenewHookEntry {
            command: "systemctl".to_string(),
            args: vec!["reload".to_string(), "nginx".to_string()],
            timeout_secs: 30,
            on_failure: HookFailurePolicyEntry::Continue,
        }];
        let toml = render_hooks_toml(&hooks);
        assert!(toml.contains("[[profiles.hooks.post_renew.success]]"));
        assert!(toml.contains("command = \"systemctl\""));
        assert!(toml.contains("args = [\"reload\", \"nginx\"]"));
        assert!(toml.contains("timeout_secs = 30"));
        assert!(toml.contains("on_failure = \"continue\""));
    }

    #[test]
    fn test_render_hooks_toml_empty() {
        let toml = render_hooks_toml(&[]);
        assert!(toml.is_empty());
    }

    #[test]
    fn test_inject_hooks_into_profile_block() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let mut args = test_resolved();
        args.post_renew_hooks = vec![PostRenewHookEntry {
            command: "systemctl".to_string(),
            args: vec!["reload".to_string(), "nginx".to_string()],
            timeout_secs: 30,
            on_failure: HookFailurePolicyEntry::Continue,
        }];
        let block = render_managed_profile_block(&args);
        assert!(block.contains("[[profiles.hooks.post_renew.success]]"));
        assert!(block.contains("command = \"systemctl\""));
        assert!(block.contains(MANAGED_PROFILE_END_PREFIX));
    }

    #[test]
    fn test_inject_hooks_preserves_end_marker() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let mut args = test_resolved();
        args.post_renew_hooks = vec![PostRenewHookEntry {
            command: "pkill".to_string(),
            args: vec!["-HUP".to_string(), "myproc".to_string()],
            timeout_secs: 15,
            on_failure: HookFailurePolicyEntry::Stop,
        }];
        let block = render_managed_profile_block(&args);

        let end_pos = block
            .find(MANAGED_PROFILE_END_PREFIX)
            .expect("end marker must exist");
        let hook_pos = block
            .find("[[profiles.hooks.post_renew.success]]")
            .expect("hook must exist");
        assert!(hook_pos < end_pos, "hook should appear before end marker");
        assert!(block.contains("on_failure = \"stop\""));
    }

    #[test]
    fn test_managed_profile_with_hooks_is_idempotent() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let mut args = test_resolved();
        args.post_renew_hooks = vec![PostRenewHookEntry {
            command: "systemctl".to_string(),
            args: vec!["reload".to_string(), "nginx".to_string()],
            timeout_secs: 30,
            on_failure: HookFailurePolicyEntry::Continue,
        }];
        let block = render_managed_profile_block(&args);
        let once = upsert_managed_profile("", "edge-proxy", &block);
        let twice = upsert_managed_profile(&once, "edge-proxy", &block);
        assert_eq!(once, twice);
    }

    #[test]
    fn test_render_hooks_toml_escapes_control_characters() {
        use crate::state::{HookFailurePolicyEntry, PostRenewHookEntry};

        let hooks = vec![PostRenewHookEntry {
            command: "echo\nnext".to_string(),
            args: vec!["line1\tline2".to_string(), "back\\slash".to_string()],
            timeout_secs: 10,
            on_failure: HookFailurePolicyEntry::Continue,
        }];
        let toml = render_hooks_toml(&hooks);

        // The output must be valid TOML — parse it to confirm.
        let wrapped = format!("[profiles]\n[profiles.hooks]\n[profiles.hooks.post_renew]{toml}");
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
        let args = hook["args"].as_array().expect("args must be an array");
        assert_eq!(args.get(0).unwrap().as_str().unwrap(), "line1\tline2");
        assert_eq!(args.get(1).unwrap().as_str().unwrap(), "back\\slash");
    }

    #[tokio::test]
    async fn write_local_ca_bundle_is_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ca-bundle.pem");
        write_local_ca_bundle(
            &path,
            "PEM",
            CertGroupPolicy::none(),
            &crate::i18n::test_messages(),
        )
        .await
        .expect("write pre-seeded CA bundle");

        let mode = std::fs::metadata(&path)
            .expect("bundle metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode, 0o644,
            "pre-seeded CA bundle must be world-readable (0644)"
        );
        let contents = std::fs::read_to_string(&path).expect("read bundle");
        assert_eq!(
            contents, "PEM\n",
            "bundle must be normalized to end in a trailing newline"
        );
    }

    #[tokio::test]
    async fn write_local_ca_bundle_honors_cert_group_gid() {
        use std::os::unix::fs::MetadataExt as _;
        use std::os::unix::fs::PermissionsExt as _;

        // Chown against a gid the caller already has membership in, so
        // the test exercises the policy path without needing root.
        let Some(gid) = bootroot::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("ca-bundle.pem");
        write_local_ca_bundle(
            &path,
            "PEM\n",
            CertGroupPolicy::with_gid(gid),
            &crate::i18n::test_messages(),
        )
        .await
        .expect("write pre-seeded CA bundle with policy");

        let meta = std::fs::metadata(&path).expect("bundle metadata");
        assert_eq!(
            meta.permissions().mode() & 0o777,
            0o644,
            "cert-group pre-seeded CA bundle must still be 0644"
        );
        assert_eq!(meta.gid(), gid, "bundle must be chowned to the policy gid");
    }
}
