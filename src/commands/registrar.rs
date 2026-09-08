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
//! Its `socket_path` is read from the **installed socket unit** and the
//! drop-ins that override it, resolved the way systemd resolves them:
//! the highest-precedence unit file masks the ones below it, and the
//! `.d/` drop-ins from every unit directory are merged on top. With no
//! unit installed anywhere, it falls back to the `ListenStream=` of the
//! unit this repository ships — embedded here at compile time by
//! [`SHIPPED_SOCKET_UNIT`], so the reported value cannot drift from the
//! file an operator installs. It is never read from configuration and
//! never from a running daemon: no configuration key names the
//! endpoint's path, and the daemon learns its own from the descriptor
//! systemd hands it (`bootroot::registrar::endpoint::activation`).
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
//! half-written pair at the caller's paths. Publication itself is
//! reversible: the three destinations are read back before the first is
//! replaced — their bytes, their modes and their ownership — and a
//! failure part-way through puts every one that was already replaced
//! back as it was, so a run that fails does not leave a new certificate
//! beside the previous key, nor a file an operator had tightened
//! reopened at this surface's own mode. The three destinations
//! are also held to being distinct before anything is issued, because a
//! caller that passed one path twice would otherwise be told the
//! issuance succeeded while the key sat where the certificate should
//! be. Re-invocation re-issues into the same paths.
//!
//! Only the **initial** credential is issued here. Renewal stays the
//! daemon's, under its own bootroot-internal credential
//! (`bootroot::registrar_certs`), and nothing in this module registers a
//! timer, an `AppRole` or an agent profile.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::cert_group::CertGroupPolicy;
use bootroot::config::{DaemonProfileSettings, Paths, Settings};
use bootroot::fs_util::{StagedDurability, StagedMode, StagedOwner};
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

/// The suffix of the drop-in directory beside a unit —
/// `bootroot-registrar.socket.d`, which is where
/// `systemctl edit bootroot-registrar.socket` writes its override.
const DROPIN_DIR_SUFFIX: &str = ".d";

/// The extension a drop-in file must carry to be read at all. systemd
/// ignores every other name in a `.d` directory, so a `.conf.bak` left
/// behind by an editor overrides nothing and is not merged here either.
const DROPIN_FILE_SUFFIX: &str = ".conf";

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
/// read or carries no `ListenStream=`, when the installed unit or one
/// of its drop-ins cannot be read, when the installed unit binds
/// nothing once its drop-ins are merged, or when the response cannot be
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
/// `ListenStream=` in its `[Socket]` section, or when the installed
/// unit found by the search — or one of its drop-ins — cannot be read
/// or binds nothing.
fn capabilities(explicit: Option<&Path>, unit_dirs: &[PathBuf]) -> Result<CapabilitiesResponse> {
    Ok(CapabilitiesResponse {
        api_version: REGISTRAR_API_VERSION,
        socket_path: resolve_socket_path(explicit, unit_dirs)?,
        verbs: SURFACE_VERBS.to_vec(),
    })
}

/// Resolves the pathname the endpoint is served on from the installed
/// socket unit and the drop-ins that override it.
///
/// An explicitly named unit is authoritative and its failures are
/// refusals — an operator who named a file meant that file, and only
/// that file: a path handed in directly is not a unit systemd has
/// loaded, so nothing is merged onto it.
///
/// The search is systemd's. The first directory in
/// [`UNIT_DIRECTORIES`] carrying [`SOCKET_UNIT_FILE`] provides the
/// unit, and that file **masks** the ones below it rather than being
/// passed over when it binds nothing: systemd loads exactly one unit
/// file, so falling through to a lower-precedence one would report a
/// pathname this host does not bind. On top of it go the `.d/`
/// drop-ins from every unit directory, which is how an override written
/// by `systemctl edit` reaches the answer — without them a deployment
/// that moved the socket in a drop-in would be told the packaged path
/// while systemd bound another, and the caller would connect to a
/// socket that is not there.
///
/// Only a host with no unit file anywhere falls back to the shipped
/// unit. That is what keeps the verb answering on a host where
/// bootroot's units have not been installed yet, which is exactly the
/// host a provisioning tool probes; drop-ins are not merged onto it,
/// because a drop-in with no unit to extend is inert in systemd too.
///
/// # Errors
///
/// Returns an error when `explicit` cannot be read, when a unit
/// directory or a drop-in that is present cannot be read, or when the
/// resolved unit carries no `ListenStream=` once its drop-ins are
/// merged.
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
    let Some((unit_path, unit)) = installed_unit(unit_dirs)? else {
        return listen_stream(SHIPPED_SOCKET_UNIT).ok_or_else(|| {
            anyhow::anyhow!("the socket unit this build ships carries no [Socket] ListenStream=")
        });
    };
    let mut texts = vec![unit];
    for dropin in dropin_paths(unit_dirs)? {
        texts.push(std::fs::read_to_string(&dropin).with_context(|| {
            format!(
                "reading the registrar socket drop-in at {}",
                dropin.display()
            )
        })?);
    }
    let merged: Vec<&str> = texts.iter().map(String::as_str).collect();
    listen_stream_merged(&merged).ok_or_else(|| {
        anyhow::anyhow!(
            "the installed registrar socket unit at {} carries no [Socket] ListenStream= once \
             its drop-ins are merged",
            unit_path.display()
        )
    })
}

/// Returns the unit file systemd would load, with its path, or `None`
/// when no unit directory carries one.
///
/// The first directory carrying the name wins outright. A file that is
/// there and cannot be read is a refusal rather than an absence: it is
/// the unit systemd loads, and guessing past it answers for a host this
/// is not.
fn installed_unit(unit_dirs: &[PathBuf]) -> Result<Option<(PathBuf, String)>> {
    for dir in unit_dirs {
        let candidate = dir.join(SOCKET_UNIT_FILE);
        match std::fs::read_to_string(&candidate) {
            Ok(unit) => return Ok(Some((candidate, unit))),
            // The one directory of the five that simply does not carry
            // the unit: the search moves on to the next.
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(anyhow::Error::new(err).context(format!(
                    "reading the installed registrar socket unit at {}",
                    candidate.display()
                )));
            }
        }
    }
    Ok(None)
}

/// Returns the drop-in files that apply to the socket unit, in the
/// order systemd applies them.
///
/// systemd collects `*.conf` from every `<unit-dir>/<unit>.d/`, keeps
/// the highest-precedence directory's copy of a given filename and
/// discards the rest, then applies what is left sorted by that
/// filename. Both halves matter: the dedup is what lets an operator
/// neutralise a packaged drop-in by putting an empty file of the same
/// name under `/etc`, and the sort is what makes `10-` land before
/// `20-` wherever each came from.
///
/// The unit-specific directory alone. systemd also honours the
/// type-wide `socket.d/`, which every socket unit on the host shares;
/// a `ListenStream=` there would bind every one of them to the same
/// path, so it is not a configuration this reports for.
///
/// # Errors
///
/// Returns an error when a drop-in directory that exists cannot be
/// listed.
fn dropin_paths(unit_dirs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let dropin_dir_name = format!("{SOCKET_UNIT_FILE}{DROPIN_DIR_SUFFIX}");
    let mut found: Vec<(std::ffi::OsString, PathBuf)> = Vec::new();
    for dir in unit_dirs {
        let dropin_dir = dir.join(&dropin_dir_name);
        let entries = match std::fs::read_dir(&dropin_dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(anyhow::Error::new(err).context(format!(
                    "reading the registrar socket drop-in directory {}",
                    dropin_dir.display()
                )));
            }
        };
        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "reading the registrar socket drop-in directory {}",
                    dropin_dir.display()
                )
            })?;
            let name = entry.file_name();
            if !name.to_string_lossy().ends_with(DROPIN_FILE_SUFFIX) {
                continue;
            }
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if found.iter().any(|(seen, _)| *seen == name) {
                continue;
            }
            found.push((name, path));
        }
    }
    found.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    Ok(found.into_iter().map(|(_, path)| path).collect())
}

/// Reads `[Socket] ListenStream=` out of a single systemd unit file.
///
/// The one-file case of [`listen_stream_merged`]: an explicitly named
/// unit and the shipped fallback, neither of which any drop-in extends.
fn listen_stream(unit: &str) -> Option<String> {
    listen_stream_merged(&[unit])
}

/// Reads `[Socket] ListenStream=` out of a unit file followed by the
/// drop-ins that override it.
///
/// Parsed the way systemd reads a unit: `[Section]` headers, `Key=Value`
/// lines, `#` and `;` comments, and a key that may legally repeat. An
/// **empty** assignment resets the list, which is systemd's own
/// semantics — the form a drop-in cancels an earlier value with; the
/// first value still standing afterwards is the one the endpoint is
/// served on.
///
/// The drop-ins are appended to the same list rather than parsed apart,
/// because that is what makes the reset work across files: a drop-in
/// that opens with a bare `ListenStream=` drops everything the unit
/// bound and the value it assigns next is the only one left.
fn listen_stream_merged(units: &[&str]) -> Option<String> {
    let mut values: Vec<String> = Vec::new();
    for unit in units {
        collect_listen_streams(unit, &mut values);
    }
    values.into_iter().next()
}

/// Folds one unit file's `[Socket] ListenStream=` assignments into
/// `values`, honouring the empty assignment as a reset.
fn collect_listen_streams(unit: &str, values: &mut Vec<String>) {
    let mut section = String::new();
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

/// Reduces an output path to the form two destinations are compared in.
///
/// Absolute, with the containing directory resolved through symlinks
/// when it already exists, so `certs/leaf.pem` and
/// `/srv/certs/../certs/leaf.pem` are recognised as the one file they
/// are. The leaf name is joined back on afterwards rather than
/// canonicalised with the rest: these paths routinely do not exist yet,
/// and a destination that is a symlink is the file it points at only
/// after it has been published, not before.
///
/// # Errors
///
/// Returns an error when `path` names no file — a filesystem root, or a
/// path ending in `..`.
fn output_identity(label: &str, path: &Path) -> Result<PathBuf> {
    let absolute = std::path::absolute(path)
        .with_context(|| format!("resolving {label} {}", path.display()))?;
    let (parent, name) = absolute.parent().zip(absolute.file_name()).ok_or_else(|| {
        anyhow::anyhow!("{label} must name a file: `{}` does not", path.display())
    })?;
    let parent = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
    Ok(parent.join(name))
}

/// Holds the three destinations one issuance publishes to distinct
/// files.
///
/// Checked before anything is issued, because every one of these writes
/// replaces whatever is at its path: `--cert-path` and `--key-path`
/// given the same value publish the certificate and then overwrite it
/// with the private key, and the run reports success. The derived
/// bundle is in the check for the same reason — a `--key-path` of
/// `ca-bundle.pem` beside the certificate is a private key written
/// world-readable into the deployment's trust store.
///
/// # Errors
///
/// Returns an error naming the two flags that collided, and the path
/// they both resolve to.
fn ensure_distinct_outputs(cert_path: &Path, key_path: &Path, bundle_path: &Path) -> Result<()> {
    let destinations = [
        ("--cert-path", cert_path),
        ("--key-path", key_path),
        ("the CA bundle derived beside --cert-path", bundle_path),
    ];
    let mut resolved: Vec<(&str, PathBuf)> = Vec::with_capacity(destinations.len());
    for (label, path) in destinations {
        resolved.push((label, output_identity(label, path)?));
    }
    for (index, (label, path)) in resolved.iter().enumerate() {
        for (other_label, other_path) in resolved.iter().skip(index + 1) {
            if path == other_path {
                anyhow::bail!(
                    "{label} and {other_label} must name different files: both resolve to {}",
                    path.display()
                );
            }
        }
    }
    Ok(())
}

/// Issues the registrar client leaf into the caller's paths.
///
/// # Errors
///
/// Returns an error when the identity's parts are invalid, when two of
/// the three output destinations are the same file, when this host
/// carries no bootroot-internal registrar configuration to take the
/// ACME inputs from, when the deployment's CA certificates cannot be
/// read, when the issuance fails, or when the material cannot be
/// published. Nothing is written at the caller's paths unless every one
/// of those steps succeeded: the destinations that a failed publication
/// had already replaced are put back as they were, at the modes and
/// under the ownership they carried.
pub(crate) async fn run_registrar_issue(
    args: &RegistrarIssueArgs,
    messages: &Messages,
) -> Result<()> {
    let identity = compose_identity(&args.host, &args.domain)?;
    // Before the issuance, not after it: a caller that passed one path
    // twice is refused without a certificate having been minted for an
    // identity whose material cannot be published.
    ensure_distinct_outputs(
        &args.cert_path,
        &args.key_path,
        &ca_bundle_path_for(&args.cert_path),
    )?;
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

/// The three destinations one issuance publishes to.
struct Destinations {
    /// The CA bundle, the certificate path's sibling.
    bundle: PathBuf,
    /// The leaf followed by its issuer chain.
    cert: PathBuf,
    /// The private key.
    key: PathBuf,
}

impl Destinations {
    /// Derives the three destinations from the caller's flags.
    fn from_args(args: &RegistrarIssueArgs) -> Self {
        Self {
            bundle: ca_bundle_path_for(&args.cert_path),
            cert: args.cert_path.clone(),
            key: args.key_path.clone(),
        }
    }
}

/// A future one publication step runs as.
///
/// Boxed so a step can be held as an ordinary function pointer, which
/// is what lets [`publish_with_steps`] be driven with a step that fails
/// on purpose.
type PublishFuture<'a> = std::pin::Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// One step of a publication: everything it writes, or nothing.
type PublishStep = for<'a> fn(&'a Destinations, &'a StagedMaterial) -> PublishFuture<'a>;

/// The publication, in order.
///
/// The bundle first, then the pair, which is the order the daemon's own
/// publication uses: a leaf whose issuer this host cannot verify is of
/// no use to the process that reads it.
const PUBLISH_STEPS: [PublishStep; 2] = [publish_bundle, publish_pair];

/// Writes the CA bundle at the certificate path's sibling.
fn publish_bundle<'a>(dest: &'a Destinations, material: &'a StagedMaterial) -> PublishFuture<'a> {
    Box::pin(async move {
        fs_util::write_ca_bundle(&dest.bundle, &material.bundle_pem, CertGroupPolicy::none())
            .await
            .with_context(|| format!("writing the CA bundle to {}", dest.bundle.display()))
    })
}

/// Writes the certificate and the key at the caller's paths.
///
/// `write_cert_and_key` establishes the modes — `0644` certificate,
/// `0600` key — so this path and `service add`'s cannot disagree about
/// them.
fn publish_pair<'a>(dest: &'a Destinations, material: &'a StagedMaterial) -> PublishFuture<'a> {
    Box::pin(async move {
        fs_util::write_cert_and_key(
            &dest.cert,
            &dest.key,
            &material.cert_pem,
            material.key_pem.expose(),
            CertGroupPolicy::none(),
        )
        .await
        .with_context(|| {
            format!(
                "writing the certificate and key to {} and {}",
                dest.cert.display(),
                dest.key.display()
            )
        })
    })
}

/// What was at a destination before this run replaced it.
enum PriorState {
    /// Nothing was there. A rollback removes what this run published.
    Absent,
    /// The file that was there. A rollback puts it back.
    Present(PriorFile),
}

/// The file one destination held, captured whole.
///
/// The bytes alone are not the file. A rollback that wrote them back
/// through this surface's own writers would republish them at *this
/// surface's* modes and under the invoking process's ownership, which
/// is a change and not a restoration: a certificate an operator had
/// tightened to `0640` comes back world-readable, and a key a service
/// account owned comes back owned by root. The mode and the ownership
/// are captured beside the contents so what a failed run puts back is
/// the file that was there.
struct PriorFile {
    /// The bytes that were there.
    ///
    /// Held as [`PrivateKeyPem`] for all three destinations and not
    /// only for the key: the wrapper's hand-written `Debug` is what
    /// keeps a snapshot of a private key out of any formatted value,
    /// and one type for the three means a destination added later
    /// cannot quietly be the one that is not wrapped.
    contents: PrivateKeyPem,
    /// The permission bits it carried.
    mode: u32,
    /// The uid that owned it.
    uid: u32,
    /// The gid that owned it.
    gid: u32,
}

/// A destination and what it held.
struct Restorable {
    /// The destination this run replaces.
    path: PathBuf,
    /// What it held beforehand.
    prior: PriorState,
}

/// Puts one captured file back: its bytes at its own mode, then its own
/// ownership.
///
/// The mode travels with the staged inode and lands with the rename, so
/// the destination is never observable at a mode wider than the one it
/// is being restored to. The ownership is re-established afterwards —
/// the staging publisher's arm that states a uid and a gid is the
/// library's protected-file policy and is not reachable from here — and
/// a chown that would change nothing is skipped, so a root run putting
/// back a root-owned file makes no privileged call at all. The window
/// in between carries this process's own ownership at the file's own
/// mode, which is what a rollback that did not restore ownership would
/// leave behind permanently.
///
/// # Errors
///
/// Returns an error when the bytes cannot be republished or when the
/// ownership cannot be put back — the `EPERM` an unprivileged run gets
/// for a file some other account owned. Either leaves the path named in
/// the rollback's own diagnostic.
async fn restore_prior(path: &Path, prior: &PriorFile) -> Result<()> {
    let dest = path.to_path_buf();
    let contents = prior.contents.clone();
    let (mode, uid, gid) = (prior.mode, prior.uid, prior.gid);
    tokio::task::spawn_blocking(move || {
        fs_util::publish_staged_blocking(
            &dest,
            contents.expose().as_bytes(),
            StagedMode::Policy(mode),
            StagedOwner::WritingProcess,
            StagedDurability::RenameOnly,
        )
        .with_context(|| format!("restoring {} from its snapshot", dest.display()))?;
        restore_ownership(&dest, uid, gid)
    })
    .await
    .context("the rollback restore task panicked")?
}

/// Puts a restored file back under the uid and gid it was owned by.
///
/// # Errors
///
/// Returns an error when the restored file cannot be stat'ed, or when
/// the `chown` is refused.
fn restore_ownership(path: &Path, uid: u32, gid: u32) -> Result<()> {
    let current = std::fs::metadata(path).with_context(|| {
        format!(
            "reading the ownership back off the restored {}",
            path.display()
        )
    })?;
    if current.uid() == uid && current.gid() == gid {
        return Ok(());
    }
    std::os::unix::fs::chown(path, Some(uid), Some(gid)).with_context(|| {
        format!(
            "restoring the ownership of {} to uid {uid} gid {gid}",
            path.display()
        )
    })
}

/// Reads a destination back before it is replaced.
///
/// # Errors
///
/// Returns an error when the path is there and its contents, mode or
/// ownership cannot be read. A destination that does not exist is not
/// an error — it is the first provisioning, and the rollback for it is
/// a removal.
async fn snapshot_destination(path: &Path) -> Result<PriorState> {
    let contents = match tokio::fs::read_to_string(path).await {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(PriorState::Absent),
        Err(err) => {
            return Err(anyhow::Error::new(err).context(format!(
                "reading the existing {} back before replacing it",
                path.display()
            )));
        }
    };
    let metadata = tokio::fs::metadata(path).await.with_context(|| {
        format!(
            "reading the mode and ownership of the existing {} before replacing it",
            path.display()
        )
    })?;
    Ok(PriorState::Present(PriorFile {
        contents: PrivateKeyPem::new(contents),
        mode: metadata.mode() & 0o7777,
        uid: metadata.uid(),
        gid: metadata.gid(),
    }))
}

/// Publishes the staged material at the caller's paths, or leaves them
/// as they were.
///
/// Every destination is read back before the first is written, so a
/// step that fails part-way can be undone: the issue requires that a
/// run never leave a half-written pair, and three independent writes
/// satisfy that only if the ones that already landed can be taken back.
/// Without it, a key write that fails after the certificate write
/// succeeded leaves the new leaf beside the previous key — a pair that
/// is complete, readable and useless, with nothing on disk saying so.
async fn publish_material(
    args: &RegistrarIssueArgs,
    material: &StagedMaterial,
    messages: &Messages,
) -> Result<()> {
    publish_with_steps(
        &Destinations::from_args(args),
        material,
        &PUBLISH_STEPS,
        messages,
    )
    .await
}

/// Runs `steps` over the destinations, rolling back on the first
/// failure.
///
/// Split from [`publish_material`] so a test can append a step that
/// fails after the real writers have run, which is the failure the
/// rollback exists for and the one no fixture path can provoke.
async fn publish_with_steps(
    dest: &Destinations,
    material: &StagedMaterial,
    steps: &[PublishStep],
    messages: &Messages,
) -> Result<()> {
    let prior = vec![
        Restorable {
            prior: snapshot_destination(&dest.bundle).await?,
            path: dest.bundle.clone(),
        },
        Restorable {
            prior: snapshot_destination(&dest.cert).await?,
            path: dest.cert.clone(),
        },
        Restorable {
            prior: snapshot_destination(&dest.key).await?,
            path: dest.key.clone(),
        },
    ];

    for step in steps {
        if let Err(err) = step(dest, material).await {
            let err =
                err.context(messages.error_write_file_failed(&dest.cert.display().to_string()));
            return Err(roll_back(&prior, err).await);
        }
    }
    Ok(())
}

/// Puts every destination back as it was and returns the failure that
/// triggered it.
///
/// Reverse publication order — key, certificate, bundle — so the pair
/// is consistent again before the trust material it is verified against
/// is. A restore that itself fails is attached to the returned error
/// rather than replacing it: the caller needs the reason the run
/// failed, and the list of files that could not be put back is what
/// tells an operator which ones to look at by hand.
async fn roll_back(prior: &[Restorable], err: anyhow::Error) -> anyhow::Error {
    let mut stranded: Vec<String> = Vec::new();
    for entry in prior.iter().rev() {
        let outcome = match &entry.prior {
            PriorState::Present(prior) => restore_prior(&entry.path, prior).await,
            PriorState::Absent => match tokio::fs::remove_file(&entry.path).await {
                Err(remove) if remove.kind() != std::io::ErrorKind::NotFound => {
                    Err(anyhow::Error::new(remove))
                }
                _ => Ok(()),
            },
        };
        if outcome.is_err() {
            stranded.push(entry.path.display().to_string());
        }
    }
    if stranded.is_empty() {
        return err.context("the caller's paths were left as they were before this run");
    }
    err.context(format!(
        "the caller's paths could not all be put back; check by hand: {}",
        stranded.join(", ")
    ))
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
        // codeql[rust/cleartext-logging]: output is a filesystem path
        // below `--secrets-dir`, not a secret value. The path is the
        // point of the warning: it names the directory whose unpublished
        // key an operator has to remove by hand.
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
