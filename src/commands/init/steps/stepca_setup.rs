use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;

use super::super::constants::openbao_constants::{PATH_STEPCA_DB, PATH_STEPCA_PASSWORD};
use super::super::constants::{
    DEFAULT_CA_ADDRESS, DEFAULT_CA_NAME, DEFAULT_CA_PROVISIONER, RESPONDER_TEMPLATE_DIR,
    STEPCA_CA_JSON_TEMPLATE_NAME, STEPCA_PASSWORD_TEMPLATE_NAME, default_ca_dns_names,
};
use super::super::paths::StepCaTemplatePaths;
use super::super::types::StepCaInitResult;
use super::RollbackFile;
use crate::commands::infra::run_docker;
use crate::i18n::Messages;
use crate::state::StateFile;

/// Wildcard bind literals that must never reach step-ca's `dnsNames`:
/// they name every local interface rather than a routable peer, and a
/// certificate carrying them satisfies no client's verification.
const WILDCARD_IPV4: &str = "0.0.0.0";
const WILDCARD_IPV6: &str = "::";
const WILDCARD_IPV6_ZERO: &str = "::0";

/// Loopback literals substituted for a wildcard bind, mirroring
/// `build_openbao_tls_sans`.
const LOOPBACK_IPV4: &str = "127.0.0.1";
const LOOPBACK_IPV6: &str = "::1";

/// Top-level `ca.json` key holding step-ca's own serving-certificate
/// name set.  step-ca splits the array at boot: entries that parse as
/// an IP become `iPAddress` SANs, the rest become `dNSName` SANs.
const CA_JSON_DNS_NAMES_KEY: &str = "dnsNames";

/// Top-level `ca.json` key naming the address step-ca serves its
/// Prometheus metrics on.  step-ca starts that listener only when the
/// key is present, and the pinned image accepts the address through no
/// command-line flag and no environment variable — so the configuration
/// file is the only place it can come from, and the fixed Compose
/// `command` cannot supply it.
const CA_JSON_METRICS_ADDRESS_KEY: &str = "metricsAddress";

/// The address step-ca serves `/metrics` on.
///
/// Fixed rather than operator-selectable: `monitoring/prometheus.yml`
/// scrapes `step-ca:9102` as a static target and both bundled Compose
/// files declare `expose: "9102"` on the service, so any other value
/// here would simply take the listener away from the scraper.
///
/// SECURITY: the listener is unauthenticated and plaintext — step-ca
/// offers no authentication for it — and the empty host part binds it
/// on every interface *inside the container*, which is what lets
/// Prometheus reach it as `step-ca:9102`.  The boundary is therefore
/// the Compose network alone: 9102 is `expose`d and never published as
/// a host port.  Publishing it, or otherwise widening that boundary,
/// puts unauthenticated internal telemetry on the host's network.
const STEPCA_METRICS_ADDRESS: &str = ":9102";

/// Writes the `OpenBao` Agent templates step-ca renders its runtime
/// configuration from.
///
/// `dns_names` and the metrics address are stamped into the generated
/// `ca.json.ctmpl` rather than inherited from whatever `ca.json` holds
/// when this runs: the step-ca agent sidecar re-renders `ca.json` from
/// the *previous* template on its own schedule, so a render landing
/// between the reconciliation and this call would otherwise bake the
/// stale value back into the new template and make the regression
/// permanent (issue #733).
pub(super) async fn write_stepca_templates(
    secrets_dir: &Path,
    kv_mount: &str,
    cert_duration: &str,
    provisioner: &str,
    dns_names: &[String],
    messages: &Messages,
) -> Result<StepCaTemplatePaths> {
    let templates_dir = secrets_dir.join(RESPONDER_TEMPLATE_DIR);
    fs_util::ensure_secrets_dir(&templates_dir).await?;

    let password_template_path = templates_dir.join(STEPCA_PASSWORD_TEMPLATE_NAME);
    let password_template = build_password_template(kv_mount);
    // Both templates below publish by rename at `0600` and decline the
    // directory flush. The `OpenBao` Agent sidecar re-reads them on a
    // fixed interval and re-renders `password.txt` and `ca.json` from
    // them, so a torn template is a render failure in a running
    // container — but the templates are themselves regenerated in full
    // by this function on the next `init`, so losing a directory entry
    // to a crash costs that re-run and nothing more.
    fs_util::atomic_replace(
        fs_util::Destination::operator_named(&password_template_path),
        password_template.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| {
        messages.error_write_file_failed(&password_template_path.display().to_string())
    })?;

    let ca_json_path = secrets_dir.join("config").join("ca.json");
    let ca_json_contents = tokio::fs::read_to_string(&ca_json_path)
        .await
        .with_context(|| messages.error_read_file_failed(&ca_json_path.display().to_string()))?;
    let ca_json_template = build_ca_json_template(
        &ca_json_contents,
        kv_mount,
        cert_duration,
        provisioner,
        dns_names,
        messages,
    )?;
    let ca_json_template_path = templates_dir.join(STEPCA_CA_JSON_TEMPLATE_NAME);
    fs_util::atomic_replace(
        fs_util::Destination::operator_named(&ca_json_template_path),
        ca_json_template.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| {
        messages.error_write_file_failed(&ca_json_template_path.display().to_string())
    })?;

    Ok(StepCaTemplatePaths {
        password_template_path,
        ca_json_template_path,
    })
}

/// Publishes a patched `ca.json` by rename, at the mode it already
/// carries.
///
/// step-ca reads this file at boot and the `OpenBao` Agent sidecar
/// re-renders it from `ca.json.ctmpl` on a fixed interval, so both
/// callers below are writing a file with a live reader. Truncating in
/// place let step-ca boot against half a JSON document and refuse to
/// start; the rename leaves the previous document or the complete new
/// one.
///
/// The directory is not flushed. `ca.json` is a rendered file — the
/// sidecar rebuilds it from the template, and `init` rebuilds the
/// template — so a crash that loses the entry costs the next render
/// rather than anything unrecoverable. This mirrors the decision
/// `crate::commands::ca`'s patcher records for the same file.
///
/// `step ca init` is what creates `ca.json`, and every publisher here
/// reads it before writing, so the mode is always the destination's own
/// and [`fs_util::StagedMode::PreserveOrUmask`]'s create arm never runs.
async fn publish_ca_json(path: &Path, contents: &str, messages: &Messages) -> Result<()> {
    fs_util::atomic_replace(
        fs_util::Destination::operator_named(path),
        contents.as_bytes(),
        fs_util::StagedMode::PreserveOrUmask,
    )
    .await
    .with_context(|| messages.error_write_file_failed(&path.display().to_string()))
}

/// Snapshots `templates/ca.json.ctmpl` for the `init` rollback.
///
/// Must be called before `write_stepca_templates` regenerates the file.
/// `ca.json` is co-owned with the step-ca `OpenBao` Agent sidecar, which
/// re-renders it from this template, so the rollback entry for `ca.json`
/// is only durable when the template is restored alongside it.  A
/// missing template yields `original: None`, which rolls back to "no
/// template" — the correct pre-`init` state on a fresh install.
pub(super) async fn snapshot_stepca_ca_json_template(
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<RollbackFile> {
    let path = secrets_dir
        .join(RESPONDER_TEMPLATE_DIR)
        .join(STEPCA_CA_JSON_TEMPLATE_NAME);
    let original = match tokio::fs::read_to_string(&path).await {
        Ok(contents) => Some(contents),
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err)
                .with_context(|| messages.error_read_file_failed(&path.display().to_string()));
        }
    };
    Ok(RollbackFile { path, original })
}

fn build_password_template(kv_mount: &str) -> String {
    format!(
        r#"{{{{ with secret "{kv_mount}/data/{PATH_STEPCA_PASSWORD}" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}"#
    )
}

fn build_ca_json_template(
    contents: &str,
    kv_mount: &str,
    cert_duration: &str,
    provisioner: &str,
    dns_names: &[String],
    messages: &Messages,
) -> Result<String> {
    const PLACEHOLDER: &str = "__BOOTROOT_CTMPL_DB__";

    let mut value: serde_json::Value =
        serde_json::from_str(contents).context(messages.error_parse_ca_json_failed())?;
    set_ca_json_dns_names(&mut value, dns_names);
    set_ca_json_metrics_address(&mut value);
    let db = value
        .get_mut("db")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    let data_source = db
        .get_mut("dataSource")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    *data_source = serde_json::Value::String(PLACEHOLDER.to_string());

    if !set_acme_cert_duration(&mut value, cert_duration, Some(provisioner)) {
        anyhow::bail!(
            "ca.json does not contain an ACME provisioner named {provisioner:?} — \
             cannot set defaultTLSCertDuration in template"
        );
    }

    let serialized =
        serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())?;

    // serde_json escapes double quotes inside strings, but the Go template
    // engine in OpenBao Agent requires unescaped quotes within {{ }} blocks.
    // Replace the JSON-quoted placeholder with a raw Go template directive
    // so the .ctmpl file is parseable by the template engine.
    let directive = format!(
        "\"{{{{ with secret \"{kv_mount}/data/{PATH_STEPCA_DB}\" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}\""
    );
    Ok(serialized.replace(&format!("\"{PLACEHOLDER}\""), &directive))
}

/// Sets `claims.defaultTLSCertDuration` on ACME provisioners in the
/// parsed ca.json value.
///
/// When `provisioner_name` is `Some`, only the ACME provisioner whose
/// `name` matches is patched. When `None`, every ACME provisioner is
/// patched.
///
/// Accepts both the on-disk shape (`authority.provisioners`) and the
/// flat `provisioners` shape emitted by older `step ca init` builds.
pub(crate) fn set_acme_cert_duration(
    value: &mut serde_json::Value,
    cert_duration: &str,
    provisioner_name: Option<&str>,
) -> bool {
    let Some(provisioners) = locate_provisioners_mut(value) else {
        return false;
    };
    let mut patched = false;
    for provisioner in provisioners {
        if !is_acme_provisioner(provisioner) {
            continue;
        }
        if let Some(name) = provisioner_name
            && !provisioner_name_matches(provisioner, name)
        {
            continue;
        }
        let claims = provisioner
            .as_object_mut()
            .expect("is_acme_provisioner guarantees object")
            .entry("claims".to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let Some(obj) = claims.as_object_mut() {
            obj.insert(
                "defaultTLSCertDuration".to_string(),
                serde_json::Value::String(cert_duration.to_string()),
            );
            patched = true;
        }
    }
    patched
}

fn provisioner_name_matches(provisioner: &serde_json::Value, name: &str) -> bool {
    provisioner
        .get("name")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|n| n == name)
}

fn locate_provisioners_mut(value: &mut serde_json::Value) -> Option<&mut Vec<serde_json::Value>> {
    if value.get("authority").is_some() {
        return value
            .get_mut("authority")
            .and_then(|authority| authority.get_mut("provisioners"))
            .and_then(serde_json::Value::as_array_mut);
    }
    value
        .get_mut("provisioners")
        .and_then(serde_json::Value::as_array_mut)
}

fn is_acme_provisioner(provisioner: &serde_json::Value) -> bool {
    provisioner
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|t| t.eq_ignore_ascii_case("ACME"))
}

/// Extracts the IP component of a `host:port` address, unwrapping the
/// brackets that surround an IPv6 literal.
///
/// Returns `None` when the value carries no port separator or the host
/// part is empty.  The bind and advertise addresses reaching this point
/// have already been validated by `validate_stepca_bind` /
/// `validate_stepca_advertise_addr`, so this parser only has to survive
/// a malformed `state.json` without panicking.
fn addr_ip(addr: &str) -> Option<&str> {
    let (host_raw, _port) = addr.rsplit_once(':')?;
    let host = host_raw
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host_raw);
    if host.is_empty() { None } else { Some(host) }
}

fn push_unique(names: &mut Vec<String>, name: &str) {
    if !names.iter().any(|existing| existing == name) {
        names.push(name.to_string());
    }
}

fn is_wildcard(ip: &str) -> bool {
    matches!(ip, WILDCARD_IPV4 | WILDCARD_IPV6 | WILDCARD_IPV6_ZERO)
}

/// Builds the name set for step-ca's own serving certificate.
///
/// Always carries the three `default_ca_dns_names` entries — `localhost`,
/// this install's own step-ca container name and `stepca.internal` — so
/// that in-network consumers keep verifying by container name.  Only the
/// container name follows the install identity; the other two are not
/// container names.  A specific bind address
/// contributes its IP; an IPv4 wildcard bind maps to `127.0.0.1` and an
/// IPv6 wildcard to `::1` plus `127.0.0.1`; a recorded advertise
/// address contributes its IP too.  Wildcard literals are never emitted
/// and no name appears twice.
///
/// Mirrors `build_openbao_tls_sans` (`openbao_tls.rs`), which does the
/// same job for the `OpenBao` listener certificate.  The names are fed
/// to `step ca init --dns` on a fresh install and reconciled into
/// `ca.json`'s top-level `dnsNames` on every subsequent `init`.
pub(super) fn build_stepca_ca_dns_names(
    bind_addr: Option<&str>,
    advertise_addr: Option<&str>,
    ca_container: &str,
) -> Vec<String> {
    let mut names: Vec<String> = default_ca_dns_names(ca_container);

    if let Some(ip) = bind_addr.and_then(addr_ip) {
        match ip {
            WILDCARD_IPV4 => push_unique(&mut names, LOOPBACK_IPV4),
            WILDCARD_IPV6 | WILDCARD_IPV6_ZERO => {
                push_unique(&mut names, LOOPBACK_IPV6);
                push_unique(&mut names, LOOPBACK_IPV4);
            }
            specific => push_unique(&mut names, specific),
        }
    }

    if let Some(ip) = advertise_addr.and_then(addr_ip)
        && !is_wildcard(ip)
    {
        push_unique(&mut names, ip);
    }

    names
}

/// Reads the recorded step-ca bind intent from `state_path` and derives
/// the certificate name set from it.
///
/// Falls back to the three default names when no state file exists or
/// no bind intent is recorded — including after a loopback reinstall
/// cleared a previous intent, which is what makes the reconciliation
/// below shrink `dnsNames` back to the defaults.
pub(super) fn resolve_stepca_ca_dns_names(
    state_path: &Path,
    ca_container: &str,
) -> Result<Vec<String>> {
    if !state_path.exists() {
        return Ok(build_stepca_ca_dns_names(None, None, ca_container));
    }
    let state = StateFile::load(state_path)?;
    Ok(build_stepca_ca_dns_names(
        state.stepca_bind_addr.as_deref(),
        state.stepca_advertise_addr.as_deref(),
        ca_container,
    ))
}

/// Sets one top-level key on a parsed `ca.json`, returning whether the
/// value actually changed.
///
/// Inserts into the parsed document rather than rebuilding it: every
/// other key — `db`, `authority.provisioners`, and anything step-ca or
/// an operator added that bootroot does not model — is left untouched,
/// so the caller can re-serialise the same document, and the key ends up
/// present exactly once whether or not it was there before.
fn set_ca_json_key(value: &mut serde_json::Value, key: &str, desired: serde_json::Value) -> bool {
    if value.get(key) == Some(&desired) {
        return false;
    }
    if let Some(object) = value.as_object_mut() {
        object.insert(key.to_string(), desired);
        return true;
    }
    false
}

/// Sets the top-level `dnsNames` array on a parsed `ca.json`, returning
/// whether the value actually changed.
fn set_ca_json_dns_names(value: &mut serde_json::Value, dns_names: &[String]) -> bool {
    let desired = dns_names
        .iter()
        .map(|name| serde_json::Value::String(name.clone()))
        .collect();
    set_ca_json_key(value, CA_JSON_DNS_NAMES_KEY, desired)
}

/// Sets the top-level `metricsAddress` on a parsed `ca.json` to
/// [`STEPCA_METRICS_ADDRESS`], returning whether the value actually
/// changed.
///
/// Takes no argument for the same reason the constant is fixed: the
/// scrape target is a compile-time constant on the Prometheus side.
fn set_ca_json_metrics_address(value: &mut serde_json::Value) -> bool {
    let desired = serde_json::Value::String(STEPCA_METRICS_ADDRESS.to_string());
    set_ca_json_key(value, CA_JSON_METRICS_ADDRESS_KEY, desired)
}

/// Outcome of `update_ca_json_with_backup`.
pub(super) struct CaJsonUpdate {
    /// Snapshot of the pre-update `ca.json` for the init rollback.
    pub(super) rollback: RollbackFile,
    /// Whether the reconciliation moved the top-level `dnsNames`.
    ///
    /// The caller restarts step-ca when this is set: step-ca derives its
    /// serving leaf from `dnsNames` at boot and holds it in memory, so
    /// only a restart re-issues it with the new name set.
    dns_names_changed: bool,
    /// Whether the reconciliation moved the top-level `metricsAddress`.
    ///
    /// Set on every installation that predates the setting, whose
    /// `dnsNames` are by definition unchanged — which is why the caller
    /// gates on [`CaJsonUpdate::stepca_reload_required`] rather than on
    /// `dns_names_changed` alone.
    metrics_address_changed: bool,
}

impl CaJsonUpdate {
    /// Whether the co-owned `ca.json` has to be carried through the rest
    /// of the sequence: regenerate the template, restart the sidecar
    /// onto it, re-assert the file, and restart step-ca.
    ///
    /// Both keys are read by step-ca at boot only — the name set decides
    /// its serving leaf, the metrics address decides whether the
    /// listener exists at all — so neither takes effect in a running
    /// container, and a sidecar still holding the previous template
    /// would render either of them back out.
    #[must_use]
    pub(super) fn stepca_reload_required(&self) -> bool {
        self.dns_names_changed || self.metrics_address_changed
    }
}

pub(super) async fn write_password_file_with_backup(
    secrets_dir: &Path,
    password: &str,
    messages: &Messages,
) -> Result<RollbackFile> {
    fs_util::ensure_secrets_dir(secrets_dir).await?;
    let password_path = secrets_dir.join("password.txt");
    let original = match tokio::fs::read_to_string(&password_path).await {
        Ok(contents) => Some(contents),
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| {
                messages.error_read_file_failed(&password_path.display().to_string())
            });
        }
    };
    // Published by rename at the policy's `0600`, applied to the staged
    // temporary so the CA password is never readable at its final path
    // under a wider mode — the window the `write` +
    // `set_key_permissions` pair this replaced left open.
    //
    // It takes the directory flush. This password decrypts the root and
    // intermediate CA keys sitting beside it; a crash that loses the
    // directory entry after step-ca has been handed it leaves keys
    // nobody can open, which no re-run of `init` reconstructs.
    fs_util::atomic_write(
        fs_util::Destination::bootroot_owned(&password_path),
        password.as_bytes(),
        fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&password_path.display().to_string()))?;
    Ok(RollbackFile {
        path: password_path,
        original,
    })
}

/// Patches `ca.json` in place, backing the original up for rollback.
///
/// Rewrites the `db` section, the ACME provisioner's
/// `claims.defaultTLSCertDuration`, the top-level `dnsNames` — what
/// gives step-ca's own serving certificate the address
/// `--stepca-bind` publishes it on — and the top-level
/// `metricsAddress`, which is what starts the listener
/// `monitoring/prometheus.yml` already scrapes.  The document is parsed
/// and re-serialised rather than regenerated, so keys bootroot does not
/// model survive untouched.
pub(super) async fn update_ca_json_with_backup(
    secrets_dir: &Path,
    db_dsn: &str,
    cert_duration: &str,
    provisioner: &str,
    dns_names: &[String],
    messages: &Messages,
) -> Result<CaJsonUpdate> {
    let path = secrets_dir.join("config").join("ca.json");
    let contents = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&contents).context(messages.error_parse_ca_json_failed())?;
    value["db"]["type"] = serde_json::Value::String("postgresql".to_string());
    value["db"]["dataSource"] = serde_json::Value::String(db_dsn.to_string());
    if !set_acme_cert_duration(&mut value, cert_duration, Some(provisioner)) {
        anyhow::bail!(
            "ca.json does not contain an ACME provisioner named {provisioner:?} — \
             cannot set defaultTLSCertDuration"
        );
    }
    let dns_names_changed = set_ca_json_dns_names(&mut value, dns_names);
    let metrics_address_changed = set_ca_json_metrics_address(&mut value);
    let updated =
        serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())?;
    publish_ca_json(&path, &updated, messages).await?;
    Ok(CaJsonUpdate {
        rollback: RollbackFile {
            path,
            original: Some(contents),
        },
        dns_names_changed,
        metrics_address_changed,
    })
}

/// Re-applies `dns_names` to `ca.json`'s top-level `dnsNames` and the
/// fixed metrics address to its `metricsAddress`, returning whether the
/// file had drifted.
///
/// `update_ca_json_with_backup` already writes both, but the step-ca
/// `OpenBao` Agent sidecar re-renders `ca.json` from its template on a
/// fixed interval and can clobber that write moments later.  The
/// orchestrator calls this once the sidecar has been restarted onto the
/// regenerated template, so the file `init` leaves behind — and every
/// later render — carries the same values.  No backup is taken: the
/// rollback entry from `update_ca_json_with_backup` already holds the
/// pre-`init` document.
pub(super) async fn reconcile_ca_json_managed_keys(
    secrets_dir: &Path,
    dns_names: &[String],
    messages: &Messages,
) -> Result<bool> {
    let path = secrets_dir.join("config").join("ca.json");
    let contents = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&contents).context(messages.error_parse_ca_json_failed())?;
    // Both keys are re-asserted before the early return is decided:
    // combining the two calls into one `||` would skip the metrics
    // address on exactly the runs where the name set had drifted.
    let dns_names_changed = set_ca_json_dns_names(&mut value, dns_names);
    let metrics_address_changed = set_ca_json_metrics_address(&mut value);
    if !dns_names_changed && !metrics_address_changed {
        return Ok(false);
    }
    let updated =
        serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())?;
    publish_ca_json(&path, &updated, messages).await?;
    Ok(true)
}

/// Restarts the step-ca `OpenBao` Agent sidecar so it loads the
/// regenerated `ca.json.ctmpl`.
///
/// The sidecar reads its templates at start-up and then re-renders
/// `ca.json` from them every render interval, so a sidecar left running
/// across an `init` that changed `dnsNames` would keep writing the
/// pre-`init` name set back over the reconciled file.
///
/// `container` is this install's own sidecar, so a second install on the
/// same host is never restarted from here.
///
/// Returns `false` when the container is absent — a fresh install has no
/// sidecar yet, and that is not a failure.  Output is discarded so the
/// absent-container case adds no noise to the `init` transcript.
pub(super) fn restart_stepca_openbao_agent(container: &str, docker: &Path) -> bool {
    std::process::Command::new(docker)
        .args(["restart", container])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Runs `step ca init` when the CA does not exist yet.
///
/// `dns_names` becomes the `--dns` value, so a freshly created CA
/// serves a certificate that already covers the recorded step-ca bind
/// and advertise addresses.  An existing CA short-circuits with
/// `Skipped`; its name set is reconciled by `update_ca_json_with_backup`
/// instead, because re-running `step ca init` would replace the root
/// and intermediate keys and invalidate every issued certificate.
pub(super) fn ensure_step_ca_initialized(
    secrets_dir: &Path,
    dns_names: &[String],
    messages: &Messages,
) -> Result<StepCaInitResult> {
    let config_path = secrets_dir.join("config").join("ca.json");
    let ca_key = secrets_dir.join("secrets").join("root_ca_key");
    let intermediate_key = secrets_dir.join("secrets").join("intermediate_ca_key");
    if config_path.exists() && ca_key.exists() && intermediate_key.exists() {
        return Ok(StepCaInitResult::Skipped);
    }

    let password_path = secrets_dir.join("password.txt");
    if !password_path.exists() {
        anyhow::bail!(messages.error_stepca_password_missing(&password_path.display().to_string()));
    }
    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let mount = format!("{}:/home/step", mount_root.display());
    // Run as the owner of secrets_dir so generated files match the
    // host ownership, avoiding permission errors when fixing modes.
    let meta = std::fs::metadata(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let user_arg = format!("{}:{}", meta.uid(), meta.gid());
    // `step ca init --dns` takes one comma-separated value (unlike
    // `step certificate create --san`, which must be repeated).  IP
    // literals in this list land in `ca.json`'s `dnsNames`, which
    // step-ca splits into `dNSName` and `iPAddress` SANs at boot.
    let dns_arg = dns_names.join(",");
    let args = vec![
        "run",
        "--user",
        &user_arg,
        "--rm",
        "-v",
        &*mount,
        "smallstep/step-ca:0.30.2",
        "step",
        "ca",
        "init",
        "--name",
        DEFAULT_CA_NAME,
        "--provisioner",
        DEFAULT_CA_PROVISIONER,
        "--dns",
        &dns_arg,
        "--address",
        DEFAULT_CA_ADDRESS,
        "--password-file",
        "/home/step/password.txt",
        "--provisioner-password-file",
        "/home/step/password.txt",
        "--acme",
    ];
    run_docker(&args, "docker step-ca init", messages)?;
    Ok(StepCaInitResult::Initialized)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::super::test_support::{test_messages, write_self_contained_fake_docker};
    use super::*;

    /// The step-ca container name a default install renders.
    const DEFAULT_CA_CONTAINER: &str = "bootroot-ca";

    /// Only the container-name element follows the install identity;
    /// `localhost` and `stepca.internal` are not container names.
    #[test]
    fn dns_names_scope_only_the_container_name_to_the_instance() {
        let names = build_stepca_ca_dns_names(None, None, "insight-ca");
        assert_eq!(names, vec!["localhost", "insight-ca", "stepca.internal"]);
        assert!(!names.contains(&DEFAULT_CA_CONTAINER.to_string()));
    }

    /// The executable seam: the caller names the program, and the child
    /// that runs is the one it named.
    ///
    /// The restart bypasses Compose, so nothing but the name it is
    /// handed decides which install's sidecar goes down.  It used to
    /// inline a default-instance literal, which on a non-default
    /// instance restarted a co-located default install's sidecar.
    ///
    /// The fake carries its own argv-log path in its script text, so
    /// nothing here sets a variable on this process or edits `PATH` —
    /// which is the whole point of taking the executable as a value.
    #[test]
    fn restarting_the_stepca_sidecar_runs_the_supplied_executable() {
        let dir = tempdir().expect("tempdir");
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        assert!(restart_stepca_openbao_agent(
            "insight-openbao-agent-stepca",
            &fake
        ));

        let logged = fs::read_to_string(&args_log).expect("read docker args");
        assert_eq!(
            logged.lines().collect::<Vec<&str>>(),
            vec!["restart insight-openbao-agent-stepca "]
        );
    }

    #[tokio::test]
    async fn test_write_stepca_templates_writes_templates() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(secrets_dir.join("config")).unwrap();
        fs::write(
            secrets_dir.join("config").join("ca.json"),
            r#"{
                "authority":{"provisioners":[{"type":"ACME","name":"acme"}]},
                "db":{"type":"postgresql","dataSource":"old"}
            }"#,
        )
        .unwrap();

        let messages = test_messages();
        let dns_names = build_stepca_ca_dns_names(None, None, DEFAULT_CA_CONTAINER);
        let paths =
            write_stepca_templates(&secrets_dir, "secret", "48h", "acme", &dns_names, &messages)
                .await
                .unwrap();
        let password_template = fs::read_to_string(&paths.password_template_path).unwrap();
        let ca_json_template = fs::read_to_string(&paths.ca_json_template_path).unwrap();

        assert!(password_template.contains("secret/data/bootroot/stepca/password"));
        assert!(ca_json_template.contains("secret/data/bootroot/stepca/db"));
    }

    #[test]
    fn test_set_acme_cert_duration_patches_nested_provisioner() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"authority":{"provisioners":[{"type":"ACME","name":"acme"}]}}"#,
        )
        .unwrap();
        let patched = set_acme_cert_duration(&mut value, "48h", None);
        assert!(patched);
        let duration = value["authority"]["provisioners"][0]["claims"]["defaultTLSCertDuration"]
            .as_str()
            .unwrap();
        assert_eq!(duration, "48h");
    }

    #[test]
    fn test_set_acme_cert_duration_skips_non_acme() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"authority":{"provisioners":[{"type":"JWK","name":"admin"}]}}"#,
        )
        .unwrap();
        let patched = set_acme_cert_duration(&mut value, "48h", None);
        assert!(!patched);
    }

    #[test]
    fn test_set_acme_cert_duration_matches_by_name() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"authority":{"provisioners":[
                {"type":"ACME","name":"acme"},
                {"type":"ACME","name":"staging"}
            ]}}"#,
        )
        .unwrap();
        let patched = set_acme_cert_duration(&mut value, "72h", Some("staging"));
        assert!(patched);
        assert!(
            value["authority"]["provisioners"][0]
                .get("claims")
                .is_none()
        );
        assert_eq!(
            value["authority"]["provisioners"][1]["claims"]["defaultTLSCertDuration"]
                .as_str()
                .unwrap(),
            "72h"
        );
    }

    #[test]
    fn test_set_acme_cert_duration_name_filter_misses_return_false() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"authority":{"provisioners":[{"type":"ACME","name":"acme"}]}}"#,
        )
        .unwrap();
        let patched = set_acme_cert_duration(&mut value, "48h", Some("nonexistent"));
        assert!(!patched);
    }

    #[test]
    fn test_step_ca_init_skips_when_files_present() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(secrets_dir.join("config")).unwrap();
        fs::create_dir_all(secrets_dir.join("secrets")).unwrap();
        fs::write(
            secrets_dir.join("config").join("ca.json"),
            r#"{"db":{"type":"","dataSource":""}}"#,
        )
        .unwrap();
        fs::write(secrets_dir.join("secrets").join("root_ca_key"), "").unwrap();
        fs::write(secrets_dir.join("secrets").join("intermediate_ca_key"), "").unwrap();

        let dns_names = build_stepca_ca_dns_names(None, None, DEFAULT_CA_CONTAINER);
        let result =
            ensure_step_ca_initialized(&secrets_dir, &dns_names, &test_messages()).unwrap();
        assert_eq!(result, StepCaInitResult::Skipped);
    }

    #[test]
    fn test_step_ca_init_requires_password_when_missing_files() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();

        let dns_names = build_stepca_ca_dns_names(None, None, DEFAULT_CA_CONTAINER);
        let err =
            ensure_step_ca_initialized(&secrets_dir, &dns_names, &test_messages()).unwrap_err();
        assert!(err.to_string().contains("step-ca password file not found"));
    }

    const CA_JSON_FIXTURE: &str = r#"{
        "root": "/home/step/certs/root_ca.crt",
        "dnsNames": ["localhost", "bootroot-ca", "stepca.internal"],
        "db": {"type": "badger", "dataSource": "/home/step/db"},
        "authority": {"provisioners": [
            {"type": "JWK", "name": "admin"},
            {"type": "ACME", "name": "acme", "claims": {"defaultTLSCertDuration": "24h"}}
        ]},
        "bootrootUnknownKey": {"nested": [1, 2, 3]}
    }"#;

    fn write_ca_json(secrets_dir: &Path, contents: &str) {
        fs::create_dir_all(secrets_dir.join("config")).unwrap();
        fs::write(secrets_dir.join("config").join("ca.json"), contents).unwrap();
    }

    fn read_ca_json(secrets_dir: &Path) -> serde_json::Value {
        let raw = fs::read_to_string(secrets_dir.join("config").join("ca.json")).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn dns_names_of(value: &serde_json::Value) -> Vec<String> {
        value
            .get("dnsNames")
            .and_then(serde_json::Value::as_array)
            .expect("dnsNames must be an array")
            .iter()
            .map(|entry| entry.as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[test]
    fn build_ca_dns_names_defaults_without_bind_intent() {
        let names = build_stepca_ca_dns_names(None, None, DEFAULT_CA_CONTAINER);
        assert_eq!(names, vec!["localhost", "bootroot-ca", "stepca.internal"]);
    }

    #[test]
    fn build_ca_dns_names_includes_specific_ipv4() {
        let names =
            build_stepca_ca_dns_names(Some("192.168.139.144:9000"), None, DEFAULT_CA_CONTAINER);
        assert!(names.contains(&"localhost".to_string()));
        assert!(names.contains(&"bootroot-ca".to_string()));
        assert!(names.contains(&"stepca.internal".to_string()));
        assert!(names.contains(&"192.168.139.144".to_string()));
    }

    #[test]
    fn build_ca_dns_names_includes_specific_ipv6() {
        let names = build_stepca_ca_dns_names(Some("[fd12::1]:9000"), None, DEFAULT_CA_CONTAINER);
        assert!(names.contains(&"fd12::1".to_string()));
    }

    #[test]
    fn build_ca_dns_names_ipv4_wildcard_maps_to_loopback() {
        let names = build_stepca_ca_dns_names(Some("0.0.0.0:9000"), None, DEFAULT_CA_CONTAINER);
        assert!(names.contains(&"127.0.0.1".to_string()));
        assert!(!names.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_ca_dns_names_ipv6_wildcard_maps_to_both_loopbacks() {
        let names = build_stepca_ca_dns_names(Some("[::]:9000"), None, DEFAULT_CA_CONTAINER);
        assert!(
            names.contains(&"::1".to_string()),
            "IPv6 wildcard must include the IPv6 loopback"
        );
        assert!(
            names.contains(&"127.0.0.1".to_string()),
            "IPv6 wildcard must also include the IPv4 loopback for dual-stack"
        );
        assert!(!names.contains(&"::".to_string()));
    }

    #[test]
    fn build_ca_dns_names_ipv6_zero_wildcard_maps_to_both_loopbacks() {
        let names = build_stepca_ca_dns_names(Some("[::0]:9000"), None, DEFAULT_CA_CONTAINER);
        assert!(names.contains(&"::1".to_string()));
        assert!(names.contains(&"127.0.0.1".to_string()));
        assert!(!names.contains(&"::0".to_string()));
    }

    #[test]
    fn build_ca_dns_names_wildcard_with_advertise_addr() {
        let names = build_stepca_ca_dns_names(
            Some("0.0.0.0:9000"),
            Some("192.168.139.144:9000"),
            DEFAULT_CA_CONTAINER,
        );
        assert!(names.contains(&"127.0.0.1".to_string()));
        assert!(
            names.contains(&"192.168.139.144".to_string()),
            "advertise IP must be present for off-host hostname verification"
        );
        assert!(!names.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_ca_dns_names_advertise_equal_to_bind_is_not_duplicated() {
        let names = build_stepca_ca_dns_names(
            Some("192.168.139.144:9000"),
            Some("192.168.139.144:9000"),
            DEFAULT_CA_CONTAINER,
        );
        let count = names.iter().filter(|n| *n == "192.168.139.144").count();
        assert_eq!(count, 1, "advertise IP must not be duplicated");
    }

    /// `validate_stepca_bind` gates what reaches `state.json`, but a
    /// hand-edited or truncated file must not panic or smuggle a
    /// nonsense name into the certificate — it degrades to the defaults.
    #[test]
    fn build_ca_dns_names_ignores_malformed_addresses() {
        let defaults = vec!["localhost", "bootroot-ca", "stepca.internal"];
        for malformed in ["", "192.168.139.144", ":9000", "[]:9000"] {
            assert_eq!(
                build_stepca_ca_dns_names(Some(malformed), None, DEFAULT_CA_CONTAINER),
                defaults,
                "malformed bind {malformed:?} must contribute no name"
            );
            assert_eq!(
                build_stepca_ca_dns_names(None, Some(malformed), DEFAULT_CA_CONTAINER),
                defaults,
                "malformed advertise {malformed:?} must contribute no name"
            );
        }
    }

    /// A wildcard recorded as the *advertise* address names no routable
    /// peer, so it must be dropped rather than written into the
    /// certificate.
    #[test]
    fn build_ca_dns_names_drops_wildcard_advertise_addr() {
        for wildcard in ["0.0.0.0:9000", "[::]:9000", "[::0]:9000"] {
            let names = build_stepca_ca_dns_names(
                Some("192.168.139.144:9000"),
                Some(wildcard),
                DEFAULT_CA_CONTAINER,
            );
            assert!(
                !names
                    .iter()
                    .any(|n| n == "0.0.0.0" || n == "::" || n == "::0")
            );
            assert!(names.contains(&"192.168.139.144".to_string()));
        }
    }

    #[test]
    fn resolve_ca_dns_names_defaults_when_state_missing() {
        let temp_dir = tempdir().unwrap();
        let names =
            resolve_stepca_ca_dns_names(&temp_dir.path().join("state.json"), DEFAULT_CA_CONTAINER)
                .unwrap();
        assert_eq!(names, vec!["localhost", "bootroot-ca", "stepca.internal"]);
    }

    #[test]
    fn resolve_ca_dns_names_reads_recorded_intent() {
        let temp_dir = tempdir().unwrap();
        let state_path = temp_dir.path().join("state.json");
        let state = StateFile {
            stepca_bind_addr: Some("0.0.0.0:9000".to_string()),
            stepca_advertise_addr: Some("192.168.139.144:9000".to_string()),
            ..Default::default()
        };
        state.save(&state_path).unwrap();

        let names = resolve_stepca_ca_dns_names(&state_path, DEFAULT_CA_CONTAINER).unwrap();
        assert!(names.contains(&"127.0.0.1".to_string()));
        assert!(names.contains(&"192.168.139.144".to_string()));
    }

    #[tokio::test]
    async fn update_ca_json_rewrites_only_dns_names_and_is_idempotent() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(&secrets_dir, CA_JSON_FIXTURE);
        let messages = test_messages();
        let dns_names =
            build_stepca_ca_dns_names(Some("192.168.139.144:9000"), None, DEFAULT_CA_CONTAINER);

        let first = update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "48h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        assert!(first.dns_names_changed);

        let after_first = read_ca_json(&secrets_dir);
        assert_eq!(dns_names_of(&after_first), dns_names);
        assert_eq!(after_first["db"]["type"].as_str().unwrap(), "postgresql");
        assert_eq!(
            after_first["db"]["dataSource"].as_str().unwrap(),
            "postgresql://step@postgres:5432/stepca"
        );
        assert_eq!(
            after_first["authority"]["provisioners"][1]["claims"]["defaultTLSCertDuration"]
                .as_str()
                .unwrap(),
            "48h"
        );
        // The JWK admin provisioner and unmodelled keys survive.
        assert_eq!(
            after_first["authority"]["provisioners"][0]["name"]
                .as_str()
                .unwrap(),
            "admin"
        );
        assert!(
            after_first["authority"]["provisioners"][0]
                .get("claims")
                .is_none()
        );
        assert_eq!(
            after_first["bootrootUnknownKey"]["nested"],
            serde_json::json!([1, 2, 3])
        );
        assert_eq!(
            after_first["root"].as_str().unwrap(),
            "/home/step/certs/root_ca.crt"
        );

        let second = update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "48h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        assert!(
            !second.dns_names_changed,
            "a second init with the same recorded intent must not move dnsNames"
        );
        let after_second = read_ca_json(&secrets_dir);
        assert_eq!(after_first, after_second, "second run must be a no-op");
    }

    #[tokio::test]
    async fn update_ca_json_restores_defaults_without_bind_intent() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(
            &secrets_dir,
            r#"{
                "dnsNames": ["localhost", "bootroot-ca", "stepca.internal", "192.168.139.144"],
                "db": {"type": "postgresql", "dataSource": "old"},
                "authority": {"provisioners": [{"type": "ACME", "name": "acme"}]}
            }"#,
        );
        let messages = test_messages();
        let dns_names = build_stepca_ca_dns_names(None, None, DEFAULT_CA_CONTAINER);

        let update = update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "24h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        assert!(update.dns_names_changed);
        assert_eq!(
            dns_names_of(&read_ca_json(&secrets_dir)),
            vec!["localhost", "bootroot-ca", "stepca.internal"],
            "clearing the bind intent must shrink dnsNames back to the defaults"
        );
    }

    #[tokio::test]
    async fn stepca_template_carries_reconciled_dns_names() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(&secrets_dir, CA_JSON_FIXTURE);
        let messages = test_messages();
        let dns_names = build_stepca_ca_dns_names(
            Some("0.0.0.0:9000"),
            Some("10.1.2.3:9000"),
            DEFAULT_CA_CONTAINER,
        );

        update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "48h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        let paths =
            write_stepca_templates(&secrets_dir, "secret", "48h", "acme", &dns_names, &messages)
                .await
                .unwrap();

        // The .ctmpl embeds a raw Go template directive in place of the
        // DSN string, so it is not valid JSON — compare the rendered
        // `dnsNames` array textually against the on-disk ca.json.
        let template = fs::read_to_string(&paths.ca_json_template_path).unwrap();
        let on_disk = read_ca_json(&secrets_dir);
        assert_eq!(dns_names_of(&on_disk), dns_names);
        for name in &dns_names {
            assert!(
                template.contains(&format!("\"{name}\"")),
                "ca.json.ctmpl must carry the reconciled name {name}"
            );
        }
        let rendered_dns = serde_json::to_string_pretty(&serde_json::json!({
            "dnsNames": on_disk.get("dnsNames").cloned().unwrap_or_default()
        }))
        .unwrap();
        let dns_block = rendered_dns
            .trim_start_matches('{')
            .trim_end_matches('}')
            .trim();
        assert!(
            template.contains(dns_block),
            "ca.json.ctmpl dnsNames must match the on-disk ca.json exactly"
        );
    }

    /// The step-ca `OpenBao` Agent sidecar re-renders `ca.json` from the
    /// previous template on its own schedule, so the reconciled file can
    /// be clobbered between `update_ca_json_with_backup` and the template
    /// write.  The regenerated template must still carry the derived name
    /// set, or the stale one would be baked back in permanently.
    #[tokio::test]
    async fn stepca_template_carries_dns_names_when_ca_json_was_clobbered() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        // Stands in for an agent render that landed after the
        // reconciliation: the pre-#733 name set is back on disk.
        write_ca_json(&secrets_dir, CA_JSON_FIXTURE);
        let messages = test_messages();
        let dns_names =
            build_stepca_ca_dns_names(Some("192.168.139.144:9000"), None, DEFAULT_CA_CONTAINER);

        let paths =
            write_stepca_templates(&secrets_dir, "secret", "48h", "acme", &dns_names, &messages)
                .await
                .unwrap();

        let template = fs::read_to_string(&paths.ca_json_template_path).unwrap();
        assert!(
            template.contains("\"192.168.139.144\""),
            "the template must carry the derived name set, not the on-disk one"
        );
    }

    #[tokio::test]
    async fn reconcile_ca_json_dns_names_repairs_a_clobbered_file() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(&secrets_dir, CA_JSON_FIXTURE);
        let messages = test_messages();
        let dns_names =
            build_stepca_ca_dns_names(Some("192.168.139.144:9000"), None, DEFAULT_CA_CONTAINER);

        let changed = reconcile_ca_json_managed_keys(&secrets_dir, &dns_names, &messages)
            .await
            .unwrap();
        assert!(changed);
        let after = read_ca_json(&secrets_dir);
        assert_eq!(dns_names_of(&after), dns_names);
        // Only `dnsNames` moves: the `db` section and unmodelled keys are
        // left exactly as the caller's earlier ca.json patch produced them.
        assert_eq!(after["db"]["type"].as_str().unwrap(), "badger");
        assert_eq!(after["db"]["dataSource"].as_str().unwrap(), "/home/step/db");
        assert_eq!(
            after["bootrootUnknownKey"]["nested"],
            serde_json::json!([1, 2, 3])
        );

        let changed_again = reconcile_ca_json_managed_keys(&secrets_dir, &dns_names, &messages)
            .await
            .unwrap();
        assert!(
            !changed_again,
            "an already-reconciled ca.json must not be rewritten"
        );
        assert_eq!(read_ca_json(&secrets_dir), after);
    }

    /// The direct reconciliation owns `metricsAddress`: step-ca serves
    /// `/metrics` only when `ca.json` carries it, and
    /// `monitoring/prometheus.yml` scrapes that listener as a static
    /// target.
    #[tokio::test]
    async fn update_ca_json_writes_one_metrics_address_and_is_idempotent() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(&secrets_dir, CA_JSON_FIXTURE);
        let messages = test_messages();
        let dns_names = build_stepca_ca_dns_names(None, None, DEFAULT_CA_CONTAINER);

        let first = update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "48h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        assert!(first.metrics_address_changed);
        assert!(first.stepca_reload_required());
        assert_eq!(
            read_ca_json(&secrets_dir)["metricsAddress"]
                .as_str()
                .unwrap(),
            ":9102"
        );
        let raw = fs::read_to_string(secrets_dir.join("config").join("ca.json")).unwrap();
        assert_eq!(
            raw.matches("\"metricsAddress\"").count(),
            1,
            "ca.json must carry exactly one top-level metricsAddress"
        );

        let second = update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "48h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        assert!(
            !second.metrics_address_changed,
            "a settled metricsAddress must not be rewritten"
        );
        assert!(
            !second.stepca_reload_required(),
            "a repeat init on a settled document must not restart step-ca"
        );
        assert_eq!(
            fs::read_to_string(secrets_dir.join("config").join("ca.json")).unwrap(),
            raw,
            "second run must be a no-op"
        );
    }

    /// The upgrade path the issue names: an installation whose
    /// `dnsNames` are already correct and whose `ca.json` predates the
    /// metrics setting.  Gating the template, sidecar and step-ca
    /// restart on `dnsNames` alone would leave it without a listener.
    #[tokio::test]
    async fn update_ca_json_requires_reload_when_only_the_metrics_address_moves() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        // `dnsNames` already carries exactly what the defaults derive.
        write_ca_json(&secrets_dir, CA_JSON_FIXTURE);
        let messages = test_messages();
        let dns_names = build_stepca_ca_dns_names(None, None, DEFAULT_CA_CONTAINER);

        let update = update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "48h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        assert!(
            !update.dns_names_changed,
            "the fixture already carries the derived name set"
        );
        assert!(update.metrics_address_changed);
        assert!(update.stepca_reload_required());
    }

    /// An operator (or a stale render) leaving another address behind
    /// must not survive: the value has to match the scrape target
    /// `monitoring/prometheus.yml` declares, so the reconciliation
    /// overwrites rather than inherits.
    #[tokio::test]
    async fn reconcile_ca_json_managed_keys_repairs_a_clobbered_metrics_address() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(
            &secrets_dir,
            r#"{
                "dnsNames": ["localhost", "bootroot-ca", "stepca.internal"],
                "metricsAddress": ":9999",
                "db": {"type": "postgresql", "dataSource": "dsn"},
                "authority": {"provisioners": [{"type": "ACME", "name": "acme"}]}
            }"#,
        );
        let messages = test_messages();
        let dns_names = build_stepca_ca_dns_names(None, None, DEFAULT_CA_CONTAINER);

        let changed = reconcile_ca_json_managed_keys(&secrets_dir, &dns_names, &messages)
            .await
            .unwrap();
        assert!(
            changed,
            "an unchanged name set must not mask a drifted metrics address"
        );
        let after = read_ca_json(&secrets_dir);
        assert_eq!(after["metricsAddress"].as_str().unwrap(), ":9102");
        assert_eq!(dns_names_of(&after), dns_names);
        assert_eq!(after["db"]["dataSource"].as_str().unwrap(), "dsn");

        let changed_again = reconcile_ca_json_managed_keys(&secrets_dir, &dns_names, &messages)
            .await
            .unwrap();
        assert!(!changed_again);
        assert_eq!(read_ca_json(&secrets_dir), after);
    }

    /// The template is stamped, not inherited: the sidecar can re-render
    /// `ca.json` from the previous template between the reconciliation
    /// and the template write, so a `ca.json` without the key must still
    /// produce a template that carries it (the #733 hazard, applied to
    /// `metricsAddress`).
    #[tokio::test]
    async fn stepca_template_stamps_metrics_address_absent_from_ca_json() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(&secrets_dir, CA_JSON_FIXTURE);
        let messages = test_messages();
        let dns_names = build_stepca_ca_dns_names(None, None, DEFAULT_CA_CONTAINER);

        assert!(
            read_ca_json(&secrets_dir).get("metricsAddress").is_none(),
            "the fixture stands in for a pre-metrics ca.json"
        );
        let paths =
            write_stepca_templates(&secrets_dir, "secret", "48h", "acme", &dns_names, &messages)
                .await
                .unwrap();

        // The .ctmpl embeds a raw Go directive in place of the DSN, so it
        // is not valid JSON — match the serialised key/value textually.
        let template = fs::read_to_string(&paths.ca_json_template_path).unwrap();
        assert!(
            template.contains("\"metricsAddress\": \":9102\""),
            "ca.json.ctmpl must carry the metrics address: {template}"
        );
        assert_eq!(
            template.matches("\"metricsAddress\"").count(),
            1,
            "ca.json.ctmpl must carry exactly one metricsAddress"
        );
    }

    /// The snapshot feeding the init rollback must capture the template
    /// as it stood *before* `write_stepca_templates` regenerates it, and
    /// must report "no template" rather than failing on a fresh install.
    #[tokio::test]
    async fn snapshot_stepca_ca_json_template_captures_pre_init_state() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(&secrets_dir, CA_JSON_FIXTURE);
        let messages = test_messages();

        let fresh = snapshot_stepca_ca_json_template(&secrets_dir, &messages)
            .await
            .unwrap();
        assert!(
            fresh.original.is_none(),
            "a fresh install has no template to restore"
        );

        let dns_names =
            build_stepca_ca_dns_names(Some("192.168.139.144:9000"), None, DEFAULT_CA_CONTAINER);
        write_stepca_templates(&secrets_dir, "secret", "24h", "acme", &dns_names, &messages)
            .await
            .unwrap();
        let existing = tokio::fs::read_to_string(&fresh.path).await.unwrap();

        // A second init snapshots the template the sidecar is currently
        // rendering from, which is what rollback has to put back.
        let before_rewrite = snapshot_stepca_ca_json_template(&secrets_dir, &messages)
            .await
            .unwrap();
        assert_eq!(before_rewrite.original.as_deref(), Some(existing.as_str()));
    }
}
