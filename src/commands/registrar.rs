//! The registrar **provisioning** surface: the two operator-facing verbs
//! a deployment tool drives before the host-local endpoint can be used.
//!
//! This is not the endpoint. The endpoint's restricted `registrar.mint`
//! and `registrar.deregister` verbs are served over a
//! mutually-authenticated host-local socket and are reachable only
//! there. What this module adds is the step in front of them: reporting
//! that the surface exists, and issuing the one credential that can
//! reach it.
//!
//! # `capabilities`
//!
//! Read-only, side-effect free, and deliberately independent of the
//! runtime. It answers on a host where `registrar_endpoint.enabled` is
//! false and on one where no daemon has ever run, because it describes
//! the surface this build carries rather than what is listening right
//! now.
//!
//! Its `socket_path` is read from the **installed socket unit**, in
//! systemd's own unit-directory precedence order, and falls back to the
//! `ListenStream=` of the unit this repository ships — embedded here at
//! compile time by [`SHIPPED_SOCKET_UNIT`], so the reported value cannot
//! drift from the file an operator installs. It is never read from
//! configuration and never from a running daemon: no configuration key
//! names the endpoint's path, and the daemon learns its own from the
//! descriptor systemd hands it
//! (`bootroot::registrar::endpoint::activation`).
//!
//! # `issue`
//!
//! Issues the registrar client leaf,
//! `001.bootroot-registrar.<host>.<domain>`, into the caller's paths,
//! with the CA bundle as the certificate path's sibling — the placement
//! `service add --cert-path/--key-path` gives it, at the same modes.
//!
//! The identity is **composed here** from the host label and the domain,
//! at [`REGISTRAR_SURFACE_INSTANCE`] and under
//! [`REGISTRAR_CLIENT_LABEL`]. No flag accepts a composed name, and the
//! response reports what was composed, so the caller learns the identity
//! rather than asserting it. A caller that passes a composed name in
//! `--host` is refused by the DNS-label rule, before anything is issued.
//!
//! The material is issued into a staging directory and published only
//! once every byte of it is in hand, so a failed run leaves no
//! half-written pair at the caller's paths. Re-invocation re-issues into
//! the same paths.
//!
//! Only the **initial** credential is issued here. Renewal stays the
//! daemon's, under its own bootroot-internal credential
//! (`bootroot::registrar_certs`), and nothing in this module registers a
//! timer, an `AppRole` or an agent profile.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::cert_group::CertGroupPolicy;
use bootroot::config::{DaemonProfileSettings, Paths, Settings};
use bootroot::input_validation::{validate_dns_label, validate_domain_name};
use bootroot::registrar::internal::{InternalPaths, PrivateKeyPem, load_internal_config};
use bootroot::registrar::{
    REGISTRAR_CLIENT_LABEL, REGISTRAR_SURFACE_INSTANCE, registrar_client_identity,
};
use bootroot::{acme, fs_util};
use serde::Serialize;

use crate::cli::args::{RegistrarCapabilitiesArgs, RegistrarIssueArgs};
use crate::commands::init::{compute_ca_bundle_pem, compute_ca_fingerprints};
use crate::i18n::Messages;

/// The wire identifier every response on this surface carries, exactly.
///
/// A wire token rather than prose: it is never translated, never
/// prefixed and never matched as a prefix.
const REGISTRAR_API_VERSION: &str = "bootroot.registrar.v1";

/// The wire name of the provisioning issuance verb — this CLI's `issue`.
const VERB_ISSUE: &str = "registrar.issue";

/// The wire name of the endpoint's restricted mint verb.
const VERB_MINT: &str = "registrar.mint";

/// The wire name of the endpoint's restricted deregister verb.
const VERB_DEREGISTER: &str = "registrar.deregister";

/// Every verb this surface carries, in the contract's fixed order.
///
/// The order is part of the contract, not an implementation detail: a
/// caller reporting what a bootroot is missing names them in this order,
/// so two runs against the same bootroot word the same gap identically.
/// It is a fixed-length array rather than a `Vec` so a verb removed here
/// fails to compile the assertions that pin it, instead of quietly
/// answering a shorter list.
const SURFACE_VERBS: [&str; 3] = [VERB_ISSUE, VERB_MINT, VERB_DEREGISTER];

/// The basename of the socket unit `socket_path` is read from.
const SOCKET_UNIT_FILE: &str = "bootroot-registrar.socket";

/// The socket unit this repository ships, embedded at compile time.
///
/// The fallback when no unit is installed anywhere the search covers.
/// Embedding the file rather than restating its pathname is what makes
/// `capabilities` answer the shipped unit's `ListenStream=` and not a
/// literal that could drift from it: change the unit and this answer
/// changes with it, in the same commit.
const SHIPPED_SOCKET_UNIT: &str = include_str!("../../systemd/bootroot-registrar.socket");

/// The systemd unit directories searched for [`SOCKET_UNIT_FILE`], in
/// systemd's own precedence order — an operator-installed unit under
/// `/etc` outranks a packaged one under `/usr`.
const UNIT_DIRECTORIES: [&str; 5] = [
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/local/lib/systemd/system",
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
];

/// The prefix of the staging directory one issuance runs in, below the
/// secrets directory.
///
/// The material is written here first and published only once all of it
/// exists, so a run that fails part-way never leaves a half-written pair
/// at the caller's paths. Removed on both outcomes: it holds a private
/// key that was never published.
const STAGING_DIR_PREFIX: &str = "registrar-client-staging";

/// The basename the CA bundle takes beside the issued certificate.
///
/// The same sibling placement `service add --cert-path` gives it, so a
/// registrar's material directory and a service's look alike.
const CA_BUNDLE_FILE: &str = "ca-bundle.pem";

/// The `capabilities` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct CapabilitiesResponse {
    /// [`REGISTRAR_API_VERSION`], exactly.
    api_version: &'static str,
    /// The pathname the host-local endpoint is served on.
    socket_path: String,
    /// [`SURFACE_VERBS`], in that order.
    verbs: Vec<&'static str>,
}

/// The `issue` response body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct IssueResponse {
    /// [`REGISTRAR_API_VERSION`], exactly.
    api_version: &'static str,
    /// The composed identity the leaf was issued for.
    identity: String,
    /// The leaf's expiry, as an RFC 3339 instant.
    not_after: String,
}

/// Reports the registrar surface this build carries.
///
/// # Errors
///
/// Returns an error when `--socket-unit` names a file that cannot be
/// read or carries no `ListenStream=`, or when the response cannot be
/// serialized. A host with no unit installed is not an error: the
/// shipped unit answers.
pub(crate) fn run_registrar_capabilities(
    args: &RegistrarCapabilitiesArgs,
    messages: &Messages,
) -> Result<()> {
    let unit_dirs: Vec<PathBuf> = UNIT_DIRECTORIES.iter().map(PathBuf::from).collect();
    let response = capabilities(args.socket_unit.as_deref(), &unit_dirs)?;
    if args.json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        println!(
            "{}",
            messages.registrar_capabilities_summary(
                response.api_version,
                &response.socket_path,
                &response.verbs.join(", "),
            )
        );
    }
    Ok(())
}

/// Builds the `capabilities` body against an explicit unit path or a
/// unit-directory search list.
///
/// Split from the command so every branch is exercisable against a
/// fixture unit rather than against this host's `/etc`.
///
/// # Errors
///
/// Returns an error when `explicit` cannot be read or carries no
/// `ListenStream=` in its `[Socket]` section.
fn capabilities(explicit: Option<&Path>, unit_dirs: &[PathBuf]) -> Result<CapabilitiesResponse> {
    Ok(CapabilitiesResponse {
        api_version: REGISTRAR_API_VERSION,
        socket_path: resolve_socket_path(explicit, unit_dirs)?,
        verbs: SURFACE_VERBS.to_vec(),
    })
}

/// Resolves the pathname the endpoint is served on from the installed
/// socket unit.
///
/// An explicitly named unit is authoritative and its failures are
/// refusals — an operator who named a file meant that file. The search
/// is not: a directory with no unit in it, or a unit that does not parse
/// as one, is passed over, and the shipped unit answers when nothing in
/// the search does. That is what keeps the verb answering on a host
/// where bootroot's units have not been installed yet, which is exactly
/// the host a provisioning tool probes.
fn resolve_socket_path(explicit: Option<&Path>, unit_dirs: &[PathBuf]) -> Result<String> {
    if let Some(path) = explicit {
        let unit = std::fs::read_to_string(path)
            .with_context(|| format!("reading the registrar socket unit at {}", path.display()))?;
        return listen_stream(&unit).ok_or_else(|| {
            anyhow::anyhow!(
                "the registrar socket unit at {} carries no [Socket] ListenStream=",
                path.display()
            )
        });
    }
    for dir in unit_dirs {
        let candidate = dir.join(SOCKET_UNIT_FILE);
        let Ok(unit) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        if let Some(value) = listen_stream(&unit) {
            return Ok(value);
        }
    }
    listen_stream(SHIPPED_SOCKET_UNIT).ok_or_else(|| {
        anyhow::anyhow!("the socket unit this build ships carries no [Socket] ListenStream=")
    })
}

/// Reads `[Socket] ListenStream=` out of a systemd unit.
///
/// Parsed the way systemd reads a unit: `[Section]` headers, `Key=Value`
/// lines, `#` and `;` comments, and a key that may legally repeat. An
/// **empty** assignment resets the list, which is systemd's own
/// semantics — the form a drop-in cancels an earlier value with; the
/// first value still standing afterwards is the one the endpoint is
/// served on.
///
/// The unit file alone, which is what this surface reports: `.d/`
/// drop-ins beside it are not read. A deployment that moves the socket
/// moves it in the unit, and a caller is told what that unit binds.
fn listen_stream(unit: &str) -> Option<String> {
    let mut section = String::new();
    let mut values: Vec<String> = Vec::new();
    for line in unit.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(header) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            section = header.to_string();
            continue;
        }
        if !section.eq_ignore_ascii_case("Socket") {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if !key.trim().eq_ignore_ascii_case("ListenStream") {
            continue;
        }
        let value = value.trim();
        if value.is_empty() {
            values.clear();
        } else {
            values.push(value.to_string());
        }
    }
    values.into_iter().next()
}

/// Composes the registrar client identity from the identity's parts.
///
/// The verb never takes a composed name, so this is the only place one
/// exists. `host` is held to the single-DNS-label rule and `domain` to
/// the DNS-name rule, which is what refuses a caller that tried to pass
/// a composed identity through `--host`: `registrar.h1` and
/// `001.bootroot-registrar.h1` both carry a dot and are not labels.
///
/// # Errors
///
/// Returns an error naming the offending part when `host` is not a
/// single DNS label or `domain` is not a DNS name.
fn compose_identity(host: &str, domain: &str) -> Result<String> {
    validate_dns_label(host).map_err(|err| {
        anyhow::anyhow!(
            "--host must be the bootroot host's single DNS label, never a composed name: `{host}` \
             is invalid ({err:?})"
        )
    })?;
    validate_domain_name(domain).map_err(|err| {
        anyhow::anyhow!("--domain is not a valid DNS name: `{domain}` is invalid ({err:?})")
    })?;
    Ok(registrar_client_identity(
        REGISTRAR_SURFACE_INSTANCE,
        host,
        domain,
    ))
}

/// Returns the staging directory this run issues into.
///
/// Named per process rather than at one fixed path, because two
/// invocations racing in the same directory would read back each
/// other's material: the leaf of one published beside the key of the
/// other is a pair that is neither half-written nor usable, and nothing
/// downstream would say so. A run also sweeps its own directory alone,
/// so it cannot delete another's mid-issuance.
fn staging_dir(secrets_dir: &Path) -> PathBuf {
    secrets_dir.join(format!("{STAGING_DIR_PREFIX}.{}", std::process::id()))
}

/// Returns the CA bundle path for a certificate path: its sibling
/// `ca-bundle.pem`.
///
/// The placement `service add --cert-path` gives it, so the registrar's
/// material directory and a service's are laid out alike.
fn ca_bundle_path_for(cert_path: &Path) -> PathBuf {
    cert_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(CA_BUNDLE_FILE)
}

/// Issues the registrar client leaf into the caller's paths.
///
/// # Errors
///
/// Returns an error when the identity's parts are invalid, when this
/// host carries no bootroot-internal registrar configuration to take the
/// ACME inputs from, when the deployment's CA certificates cannot be
/// read, when the issuance fails, or when the material cannot be
/// published. Nothing is written at the caller's paths unless every one
/// of those steps succeeded.
pub(crate) async fn run_registrar_issue(
    args: &RegistrarIssueArgs,
    messages: &Messages,
) -> Result<()> {
    let identity = compose_identity(&args.host, &args.domain)?;
    let secrets_dir = args.secrets_dir.secrets_dir.as_path();

    let staging = staging_dir(secrets_dir);
    let outcome = issue_into_staging(secrets_dir, &staging, args, &identity, messages).await;
    sweep_staging(&staging).await;
    let material = outcome?;

    publish_material(args, &material, messages).await?;

    let response = IssueResponse {
        api_version: REGISTRAR_API_VERSION,
        identity,
        not_after: material.not_after,
    };
    if args.json {
        println!("{}", serde_json::to_string(&response)?);
    } else {
        println!(
            "{}",
            messages.registrar_issue_complete(&response.identity, &response.not_after)
        );
    }
    Ok(())
}

/// Everything one issuance produced, read back out of the staging
/// directory before a byte of it reaches the caller's paths.
struct StagedMaterial {
    /// The leaf followed by its issuer chain.
    cert_pem: String,
    /// The freshly generated private key, redacted in `Debug` at the
    /// boundary it is read back in on, exactly as the issuance itself
    /// carries it.
    key_pem: PrivateKeyPem,
    /// The merged CA bundle the issuance verified and wrote.
    bundle_pem: String,
    /// The leaf's expiry, as an RFC 3339 instant.
    not_after: String,
}

/// Runs the issuance into `staging` and reads back what it produced.
///
/// The ACME inputs come from the rendered bootroot-internal agent config
/// — the one file on an endpoint-enabled host that carries the directory
/// URL, the contact email, the HTTP-01 responder endpoint and its HMAC,
/// and the account EAB, all as `bootroot init` resolved them. Reading
/// them from there is what keeps this verb credential-free: it needs no
/// `OpenBao` token, which is what lets a provisioning tool drive it as
/// root on the bootroot host with nothing else in hand.
///
/// The trust anchors are the deployment's own root and intermediate,
/// read from `<secrets-dir>/certs/` by the same two helpers `init`
/// issues the internal leaf with, so there is one source of anchors and
/// not two.
async fn issue_into_staging(
    secrets_dir: &Path,
    staging: &Path,
    args: &RegistrarIssueArgs,
    identity: &str,
    messages: &Messages,
) -> Result<StagedMaterial> {
    let internal_paths = InternalPaths::new(secrets_dir);
    // Absence is its own refusal, and is separated from malformation
    // here because `load_internal_config` cannot tell them apart: a
    // config source that is not there deserializes as an empty one, so
    // an unprovisioned host is reported as a file "expected exactly one
    // profile, found 0" — a diagnostic about the contents of a file that
    // does not exist. This is the state a provisioning tool finds when
    // it probes before `bootroot init` has enabled the endpoint, and it
    // is the one it must be able to act on.
    let config_path = internal_paths.agent_config();
    if !config_path.exists() {
        anyhow::bail!(
            "this host carries no bootroot-internal registrar configuration at {}, so there are \
             no ACME inputs to issue {identity} from; run `bootroot init` with \
             `[registrar_endpoint] enabled = true` first",
            config_path.display()
        );
    }
    let internal = load_internal_config(&internal_paths).with_context(|| {
        format!(
            "reading the ACME inputs for {identity} from the bootroot-internal registrar \
             configuration below {}",
            secrets_dir.display()
        )
    })?;

    fs_util::ensure_secrets_dir(staging)
        .await
        .with_context(|| messages.error_write_file_failed(&staging.display().to_string()))?;

    let fingerprints = compute_ca_fingerprints(secrets_dir, messages).await?;
    let bundle_pem = compute_ca_bundle_pem(secrets_dir, messages).await?;
    let staged_bundle = staging.join(CA_BUNDLE_FILE);
    // Seeded before the issuance rather than after it: this file is the
    // trust store the outbound ACME connection to step-ca is built from,
    // *and* the destination the returned chain is merged into. The
    // caller's sibling bundle cannot serve as either — on a first
    // provisioning it does not exist yet.
    fs_util::write_ca_bundle(&staged_bundle, &bundle_pem, CertGroupPolicy::none())
        .await
        .with_context(|| messages.error_write_file_failed(&staged_bundle.display().to_string()))?;

    let staged_cert = staging.join("leaf.pem");
    let staged_key = staging.join("key.pem");
    let settings = issuance_settings(
        &internal,
        args,
        &staged_bundle,
        &fingerprints,
        &staged_cert,
        &staged_key,
    );
    let profile = settings
        .profiles
        .first()
        .ok_or_else(|| anyhow::anyhow!("the registrar client issuance profile was not built"))?;
    let eab = internal
        .eab
        .as_ref()
        .map(|eab| bootroot::eab::EabCredentials {
            kid: eab.kid.clone(),
            hmac: eab.hmac.clone(),
        });
    acme::issue_registrar_client_certificate(&settings, profile, eab)
        .await
        .with_context(|| format!("issuing {identity} through step-ca's ACME endpoint"))?;

    let cert_pem = tokio::fs::read_to_string(&staged_cert)
        .await
        .with_context(|| messages.error_read_file_failed(&staged_cert.display().to_string()))?;
    let key_pem = PrivateKeyPem::new(
        tokio::fs::read_to_string(&staged_key)
            .await
            .with_context(|| messages.error_read_file_failed(&staged_key.display().to_string()))?,
    );
    let bundle_pem = tokio::fs::read_to_string(&staged_bundle)
        .await
        .with_context(|| messages.error_read_file_failed(&staged_bundle.display().to_string()))?;
    let not_after = leaf_not_after(&cert_pem)
        .with_context(|| format!("reading the expiry of the leaf issued for {identity}"))?;

    Ok(StagedMaterial {
        cert_pem,
        key_pem,
        bundle_pem,
        not_after,
    })
}

/// Publishes the staged material at the caller's paths.
///
/// The bundle first, then the pair, which is the order the daemon's own
/// publication uses: a leaf whose issuer this host cannot verify is of
/// no use to the process that reads it. `write_cert_and_key` and
/// `write_ca_bundle` establish the modes — `0644` certificate, `0600`
/// key, `0644` bundle — so this path and `service add`'s cannot disagree
/// about them.
async fn publish_material(
    args: &RegistrarIssueArgs,
    material: &StagedMaterial,
    messages: &Messages,
) -> Result<()> {
    let bundle_path = ca_bundle_path_for(&args.cert_path);
    fs_util::write_ca_bundle(&bundle_path, &material.bundle_pem, CertGroupPolicy::none())
        .await
        .with_context(|| messages.error_write_file_failed(&bundle_path.display().to_string()))?;
    fs_util::write_cert_and_key(
        &args.cert_path,
        &args.key_path,
        &material.cert_pem,
        material.key_pem.expose(),
        CertGroupPolicy::none(),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&args.cert_path.display().to_string()))?;
    Ok(())
}

/// Removes the staging directory, warning rather than failing.
///
/// It holds a private key that was never published, so it is swept on
/// both outcomes. A sweep that cannot run is reported and does not turn
/// a successful issuance into a failure.
async fn sweep_staging(staging: &Path) {
    if !staging.exists() {
        return;
    }
    if let Err(err) = tokio::fs::remove_dir_all(staging).await {
        eprintln!(
            "Warning: failed to remove the staging directory {}: {err}",
            staging.display()
        );
    }
}

/// Builds the settings one registrar client issuance runs under.
///
/// The bootroot-internal config with four substitutions and nothing
/// else: the domain is the caller's, the trust table is the staged
/// bundle and the deployment's anchors, the account key is not the
/// internal credential's, and the single profile is the reserved-name
/// one this leaf needs. `[eab]` is dropped from the settings and passed
/// as an argument instead, so there is one source for it rather than a
/// second that could go stale invisibly.
fn issuance_settings(
    internal: &Settings,
    args: &RegistrarIssueArgs,
    bundle: &Path,
    fingerprints: &[String],
    cert: &Path,
    key: &Path,
) -> Settings {
    let mut settings = internal.clone();
    settings.domain.clone_from(&args.domain);
    settings.eab = None;
    // A fresh account key per issuance, which is what every ordinary
    // service issuance does. The internal credential's persistent
    // account key belongs to its own all-or-none file set and is not
    // borrowed for another identity's orders.
    settings.acme.account_key_path = None;
    settings.trust.ca_bundle_path = Some(bundle.to_path_buf());
    settings.trust.trusted_ca_sha256 = fingerprints.to_vec();
    settings.profiles = vec![DaemonProfileSettings {
        registration_id: format!("{REGISTRAR_CLIENT_LABEL}-{}", args.host),
        service_name: REGISTRAR_CLIENT_LABEL.to_string(),
        instance_id: REGISTRAR_SURFACE_INSTANCE.to_string(),
        hostname: args.host.clone(),
        paths: Paths {
            cert: cert.to_path_buf(),
            key: key.to_path_buf(),
        },
        daemon: bootroot::config::DaemonRuntimeSettings::default(),
        retry: None,
        hooks: bootroot::config::HookSettings::default(),
        eab: None,
        // Root-owned material with no cert group, exactly as the
        // daemon's own issuance of this pair writes it: the key is
        // `0600` and the certificate beside it is public.
        cert_group_gid: None,
    }];
    settings
}

/// Reads the leaf's `not_after` out of an issued certificate file and
/// renders it as an RFC 3339 instant.
///
/// The **leaf**, which is the first certificate in the file: this
/// publication writes the issuer chain after it, and an expiry read off
/// the issuer would report a CA's lifetime as the credential's.
fn leaf_not_after(cert_pem: &str) -> Result<String> {
    let (_, pem) = x509_parser::pem::parse_x509_pem(cert_pem.as_bytes())
        .map_err(|err| anyhow::anyhow!("the issued certificate does not parse as PEM: {err}"))?;
    let leaf = pem
        .parse_x509()
        .map_err(|err| anyhow::anyhow!("the issued certificate does not parse as X.509: {err}"))?;
    Ok(bootroot::registrar::audit::format_millisecond_rfc3339(
        leaf.validity().not_after.to_datetime(),
    ))
}

#[cfg(test)]
mod tests;
