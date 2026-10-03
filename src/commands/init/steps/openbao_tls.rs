use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;

use crate::commands::infra::run_docker_with_exec;
use crate::commands::init::{
    CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, OPENBAO_HCL_PATH, OPENBAO_INFRA_CERT_KEY,
    OPENBAO_TLS_CERT_PATH, OPENBAO_TLS_CONTAINER_CERT_PATH, OPENBAO_TLS_CONTAINER_KEY_PATH,
    OPENBAO_TLS_DEFAULT_NOT_AFTER, OPENBAO_TLS_DEFAULT_RENEW_BEFORE, OPENBAO_TLS_KEY_PATH,
};
use crate::commands::rotate::STEP_CA_HELPER_IMAGE;
use crate::i18n::Messages;
use crate::state::{InfraCertEntry, ReloadStrategy, StateFile};

/// Container-side mount point of a TLS output directory — `openbao/tls`
/// here, `bootroot-http01/tls` for the HTTP-01 admin API.
///
/// `step certificate create` writes `server.{crt,key}` under it, and the
/// chown that precedes it re-owns exactly this path.
pub(super) const TLS_OUTPUT_MOUNT: &str = "/output";

/// The value `OpenBao`'s file audit device takes for both `path` and
/// `file_path` to write to standard output.
const OPENBAO_AUDIT_STDOUT: &str = "stdout";

/// Mount path of the store-backed file audit device. Unchanged from the
/// device every endpoint host has carried, so its audit table entry
/// survives.
const OPENBAO_AUDIT_STORE_MOUNT_PATH: &str = "file";

/// The file the store-backed device writes: `audit.log` under the
/// directory the audit override binds the store at.
const OPENBAO_AUDIT_STORE_FILE_PATH: &str = "/openbao/audit/audit.log";

/// Issues an `OpenBao` TLS server certificate signed by the local
/// step-ca intermediate CA.
///
/// Writes the certificate to `compose_dir/openbao/tls/server.{crt,key}`.
/// `step certificate create` runs via Docker (no step CLI required on
/// the host).  After provisioning, the files are set to `0644` so the
/// `OpenBao` container's `openbao` user can read them (see
/// `set_openbao_readable_permissions` for the rationale).
pub(in crate::commands::init) fn issue_openbao_tls_cert(
    compose_dir: &Path,
    secrets_dir: &Path,
    sans: &[&str],
    docker: &Path,
    messages: &Messages,
) -> Result<()> {
    let cert_path = compose_dir.join(OPENBAO_TLS_CERT_PATH);
    let key_path = compose_dir.join(OPENBAO_TLS_KEY_PATH);

    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let secrets_mount = format!("{}:/home/step", mount_root.display());

    let tls_dir = compose_dir.join("openbao").join("tls");
    reject_symlinked_tls_output_dir(
        &tls_dir,
        |path| messages.error_openbao_tls_output_dir_symlink(path),
        messages,
    )?;
    std::fs::create_dir_all(&tls_dir)
        .with_context(|| messages.error_write_file_failed(&tls_dir.display().to_string()))?;
    let tls_mount_root = std::fs::canonicalize(&tls_dir)
        .with_context(|| messages.error_resolve_path_failed(&tls_dir.display().to_string()))?;
    let tls_mount = format!("{}:{TLS_OUTPUT_MOUNT}", tls_mount_root.display());

    let meta = std::fs::metadata(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let user_arg = format!("{}:{}", meta.uid(), meta.gid());

    chown_tls_output_dir(
        &tls_mount,
        &user_arg,
        docker,
        "docker openbao tls output chown",
        messages.error_openbao_tls_provision_failed(),
        messages,
    )?;

    let intermediate_cert = format!("/home/step/{CA_CERTS_DIR}/{CA_INTERMEDIATE_CERT_FILENAME}");
    let output_cert = format!("{TLS_OUTPUT_MOUNT}/server.crt");
    let output_key = format!("{TLS_OUTPUT_MOUNT}/server.key");
    let mut args: Vec<&str> = vec![
        "run",
        "--user",
        &user_arg,
        "--rm",
        "-v",
        &secrets_mount,
        "-v",
        &tls_mount,
        STEP_CA_HELPER_IMAGE,
        "step",
        "certificate",
        "create",
        "openbao.internal",
        &output_cert,
        &output_key,
        "--ca",
        &intermediate_cert,
        "--ca-key",
        "/home/step/secrets/intermediate_ca_key",
        "--ca-password-file",
        "/home/step/password.txt",
        "--no-password",
        "--insecure",
    ];
    // `step certificate create --san` accepts a single value and must
    // be repeated per SAN; comma-joining yields one literal SAN whose
    // DnsName is the joined string (e.g. "openbao.internal,localhost,
    // bootroot-openbao,172.17.0.1"), which fails hostname verification
    // for every individual name.  step also infers DNS vs IP from the
    // value shape, so passing IP literals via --san produces IP SANs.
    for san in sans {
        args.push("--san");
        args.push(san);
    }
    args.extend(["--not-after", OPENBAO_TLS_DEFAULT_NOT_AFTER, "--force"]);

    run_docker_with_exec(
        &args,
        "docker step certificate create (openbao tls)",
        docker,
        messages,
    )
    .with_context(|| messages.error_openbao_tls_provision_failed())?;

    set_openbao_readable_permissions(&cert_path, &key_path)?;

    println!(
        "{}",
        messages.info_openbao_tls_provisioned(&cert_path.display().to_string())
    );
    Ok(())
}

/// Refuses to proceed when a TLS output directory (`openbao/tls`,
/// `bootroot-http01/tls`) is itself a symlink, with the refusal
/// `refusal` renders for its path.
///
/// The bind-mount source is produced with `std::fs::canonicalize`, which
/// resolves the final component too, so a symlink planted at the output
/// directory would make both containers act on the link target instead:
/// the root helper would `chown -R` that target, and `step certificate
/// create` would write `server.{crt,key}` into it. `--no-dereference`
/// guards links found *inside* the mounted tree; it cannot guard a mount
/// root that was already resolved elsewhere. bootroot only ever creates
/// these paths as directories, so a symlink here is never a shape it
/// produces, and refusing it keeps the mount pinned to the directory
/// itself while still allowing legitimate symlinks anywhere above it (a
/// symlinked state directory, `/var` on macOS) to resolve as before.
pub(super) fn reject_symlinked_tls_output_dir(
    tls_dir: &Path,
    refusal: impl FnOnce(&str) -> String,
    messages: &Messages,
) -> Result<()> {
    // `symlink_metadata` does not follow the final component; a missing
    // path is the normal first-issuance case and is left to
    // `create_dir_all`.
    match std::fs::symlink_metadata(tls_dir) {
        Ok(meta) if meta.file_type().is_symlink() => {
            anyhow::bail!(refusal(&tls_dir.display().to_string()))
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err)
            .with_context(|| messages.error_resolve_path_failed(&tls_dir.display().to_string())),
    }
}

/// Builds the `docker run` argv for the TLS output-directory chown.
///
/// Kept pure so tests can assert it mounts ONLY the TLS output
/// directory and uses `--no-dereference`, so `chown -R` never follows a
/// symlink out of that mount.  Mirrors `build_ownership_sweep_args` in
/// `crate::commands::infra`.
fn build_tls_output_chown_args<'a>(
    mount: &'a str,
    user_arg: &'a str,
    image: &'a str,
) -> Vec<&'a str> {
    vec![
        "run",
        "--rm",
        // Intentional root: this container runs `chown`, NOT a `step`
        // subcommand.  Only root can re-own a directory a previous
        // root-running bootroot created, and only root can chown to an
        // arbitrary uid at all, so an in-process chown cannot do this job
        // when bootroot runs as the (non-root) secrets owner.
        "--user",
        "root",
        // Run `chown` directly instead of through the image's default
        // entrypoint, which would otherwise print a spurious "there is no
        // ca.json config file" warning: this container deliberately
        // mounts only the TLS output directory, not `/home/step`.
        "--entrypoint",
        "chown",
        "-v",
        mount,
        image,
        "-R",
        // Change the symlink itself rather than its referent, so the
        // chown never follows a link out of the mounted directory.
        "--no-dereference",
        user_arg,
        TLS_OUTPUT_MOUNT,
    ]
}

/// Re-owns a TLS output directory and everything in it to `user_arg`
/// via a one-shot root container, so the `step` helper that runs next as
/// that same uid can write `server.{crt,key}` into it.
///
/// The directory is created by the host bootroot process and its files
/// are written inside the step container, so both freeze the owner of
/// the process that first created them, and nothing re-owns them before
/// the next issuance:
///
/// - `openbao/tls` is a sibling of `secrets/`, not a child, so the
///   secrets-ownership sweep never reaches it: once `secrets/` is
///   re-owned to a different uid, a re-issuance runs as the new uid
///   against a directory and files still owned by the old one and fails
///   with `permission denied` (issue #739).
/// - `bootroot-http01/tls` is inside `secrets/`, but an endpoint-enabled
///   `init` runs as root, creates it root-owned while writing the
///   responder override, and issues into it in the same run, before any
///   sweep; with `secrets/` owned by another user the write is refused
///   the same way (issue #1054).
///
/// Reuses the image the `step certificate create` container runs in the
/// very next statement, so no extra image or pull is introduced.  The
/// chown is a no-op when ownership is already correct. `label` names the
/// docker command, and `failure` is the issuance error the chown's
/// failure is reported under: the chown is part of the issuance, so a
/// failure here has to name the step that failed and not just the docker
/// command.
pub(super) fn chown_tls_output_dir(
    tls_mount: &str,
    user_arg: &str,
    docker: &Path,
    label: &str,
    failure: &'static str,
    messages: &Messages,
) -> Result<()> {
    let args = build_tls_output_chown_args(tls_mount, user_arg, STEP_CA_HELPER_IMAGE);
    run_docker_with_exec(&args, label, docker, messages).context(failure)
}

/// Sets cert + key to modes the `OpenBao` container can read.
///
/// `docker-compose.yml` mounts `./openbao` as `:ro`, so the `OpenBao`
/// image's standard entrypoint cannot chown its config dir to the
/// `openbao` user — the chown silently fails and the container then
/// fails to load the TLS material with `permission denied`.  The
/// `step` CLI writes the cert and key as the runner UID with mode
/// `0600`, which the `openbao` user inside the container can not
/// read.
///
/// Loosen the modes so the openbao user can read the files via the
/// "other" permission bits.  The cert is public (`0644`).  The key
/// is set to `0644` too because the openbao user is in neither the
/// runner's primary group nor any shared group, so `0640` would not
/// help.  The host is a single-tenant operator host (the only other
/// reader is root, who can read anything anyway); the key never
/// leaves this directory and is renewed on a 30-day cadence, so the
/// expanded read scope is acceptable in this deployment model.
fn set_openbao_readable_permissions(cert_path: &Path, key_path: &Path) -> Result<()> {
    std::fs::set_permissions(cert_path, std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("Failed to set permissions on {}", cert_path.display()))?;
    std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o644))
        .with_context(|| format!("Failed to set permissions on {}", key_path.display()))?;
    Ok(())
}

/// Publishes `openbao.hcl` by rename.
///
/// `OpenBao` reads this file at start and on `SIGHUP`, from inside a
/// container that may already be running when the enable/revert pair
/// below rewrites it. A truncating write let that read land on a
/// half-written HCL document, which `OpenBao` answers by refusing to
/// come up — the failure the operator sees is a container restart loop
/// with a parse error, not a write error from bootroot.
///
/// The directory is not flushed. Both callers regenerate the whole file
/// from a constant template plus the mount paths, so a crash that loses
/// the entry leaves the previous configuration in place and costs a
/// re-run of the `init` step that produced it.
///
/// The file has no mode of its own to assert: it is bind-mounted into
/// the `OpenBao` container and read by a process that is not the writing
/// operator, so it is neither narrowed nor widened here.
/// [`fs_util::StagedMode::PreserveOrUmask`] leaves an existing
/// `openbao.hcl` at whatever mode it carries and gives a fresh one what
/// the process umask would have given the truncating write this
/// replaced.
fn publish_openbao_hcl(path: &Path, content: &str, messages: &Messages) -> Result<()> {
    fs_util::atomic_replace_blocking(
        fs_util::Destination::operator_named(path),
        content.as_bytes(),
        fs_util::StagedMode::PreserveOrUmask,
    )
    .with_context(|| messages.error_openbao_hcl_write_failed())
}

/// Rewrites `openbao.hcl` to enable TLS on the API listener.
///
/// Replaces `tls_disable = 1` on the `:8200` listener with
/// `tls_cert_file` and `tls_key_file` pointing to the container
/// mount paths.  The telemetry listener on `:9101` keeps plaintext.
fn write_openbao_hcl_with_tls(compose_dir: &Path, messages: &Messages) -> Result<()> {
    let hcl_path = compose_dir.join(OPENBAO_HCL_PATH);
    // The `audit` stanza must match the canonical openbao/openbao.hcl shipped
    // with the repo: the `stdout` device, which audits to the container log.
    // OpenBao >= 2.5 requires audit devices to be declared in the server
    // configuration rather than enabled via the API, and `init` verifies
    // that a file audit backend is present (see
    // `OpenBaoClient::verify_audit_file`). Where the audit override applies,
    // `sync_openbao_audit_device` switches the stanza to the store-backed
    // `file` device afterwards.
    let content = format!(
        r#"storage "file" {{
  path = "/openbao/file"
}}

listener "tcp" {{
  address = "0.0.0.0:8200"
  tls_cert_file = "{OPENBAO_TLS_CONTAINER_CERT_PATH}"
  tls_key_file  = "{OPENBAO_TLS_CONTAINER_KEY_PATH}"
  telemetry {{
    disallow_metrics = true
  }}
}}

listener "tcp" {{
  address = "0.0.0.0:9101"
  tls_disable = 1
  telemetry {{
    metrics_only = true
    unauthenticated_metrics_access = true
  }}
}}

telemetry {{
  prometheus_retention_time = "30s"
  disable_hostname = true
}}

audit {{
  type = "file"
  path = "stdout"
  options {{
    file_path = "stdout"
  }}
}}

disable_mlock = true
ui = true
"#,
    );

    publish_openbao_hcl(&hcl_path, &content, messages)?;

    println!("{}", messages.info_openbao_hcl_tls_written());
    Ok(())
}

/// Rewrites `openbao.hcl` for the TLS recreate `init` runs, with the
/// audit device that recreate's mounts need.
///
/// [`write_openbao_hcl_with_tls`] renders the canonical `stdout` device;
/// when the recreate carries the audit override, passed as
/// `audit_override`, [`sync_openbao_audit_device`] then switches it to
/// the store-backed `file` device.
pub(in crate::commands::init) fn write_openbao_hcl_for_tls_recreate(
    compose_dir: &Path,
    audit_override: Option<&Path>,
    messages: &Messages,
) -> Result<()> {
    write_openbao_hcl_with_tls(compose_dir, messages)?;
    sync_openbao_audit_device(
        compose_dir,
        OpenBaoAuditDevice::for_audit_override(audit_override.is_some()),
        messages,
    )
}

/// Builds the SANs list for the `OpenBao` TLS certificate.
///
/// Always includes `openbao.internal`, `localhost` and
/// `openbao_container` — the install's own container name, which is the
/// server's in-network DNS name and therefore has to validate.  When a
/// bind address is configured, its IP component is added as well.  When
/// an advertise address is provided (wildcard bind), its IP is included
/// so that remote nodes connecting via the advertised endpoint pass
/// hostname verification.
pub(in crate::commands::init) fn build_openbao_tls_sans(
    bind_addr: &str,
    advertise_addr: Option<&str>,
    openbao_container: &str,
) -> Vec<String> {
    let mut sans = vec![
        "openbao.internal".to_string(),
        "localhost".to_string(),
        openbao_container.to_string(),
    ];

    if let Some((ip_raw, _port)) = bind_addr.rsplit_once(':') {
        let ip = ip_raw
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(ip_raw);
        if !ip.is_empty() && ip != "0.0.0.0" && ip != "::" && ip != "::0" {
            sans.push(ip.to_string());
        }
        if ip == "0.0.0.0" {
            sans.push("127.0.0.1".to_string());
        } else if ip == "::" || ip == "::0" {
            sans.push("::1".to_string());
            sans.push("127.0.0.1".to_string());
        }
    }

    if let Some(addr) = advertise_addr
        && let Some((ip_raw, _port)) = addr.rsplit_once(':')
    {
        let ip = ip_raw
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(ip_raw);
        if !ip.is_empty() && !sans.contains(&ip.to_string()) {
            sans.push(ip.to_string());
        }
    }

    sans
}

/// Records the `OpenBao` TLS certificate in `StateFile::infra_certs`.
///
/// Stores the computed `sans` so that `reissue_openbao_tls_cert` can
/// reproduce the same SANs (including the bind-address IP) on renewal.
pub(in crate::commands::init) fn record_openbao_infra_cert(
    state: &mut StateFile,
    compose_dir: &Path,
    sans: Vec<String>,
    openbao_container: &str,
) {
    let cert_path = compose_dir.join(OPENBAO_TLS_CERT_PATH);
    let key_path = compose_dir.join(OPENBAO_TLS_KEY_PATH);

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let entry = InfraCertEntry {
        cert_path,
        key_path,
        sans,
        renew_before: OPENBAO_TLS_DEFAULT_RENEW_BEFORE.to_string(),
        // SIGHUP reloads the listener cert in place; a restart would bring
        // the container back sealed (Shamir seal, in-memory master key)
        // and the rotate path never unseals. See issue #727.
        reload_strategy: ReloadStrategy::ContainerSignal {
            container_name: openbao_container.to_string(),
            signal: "SIGHUP".to_string(),
        },
        issued_at: Some(now),
        expires_at: None,
    };

    state
        .infra_certs
        .insert(OPENBAO_INFRA_CERT_KEY.to_string(), entry);
}

/// Restores `openbao.hcl` to the default plaintext form with
/// `tls_disable = 1` on the API listener.
///
/// Called when a loopback reinstall clears a previous non-loopback
/// bind intent, ensuring `OpenBao` no longer expects TLS certificates
/// that are no longer being issued or renewed.
pub(crate) fn write_openbao_hcl_plaintext(compose_dir: &Path, messages: &Messages) -> Result<()> {
    let hcl_path = compose_dir.join(OPENBAO_HCL_PATH);
    if !hcl_path.exists() {
        return Ok(());
    }
    // The `audit` stanza must match the canonical openbao/openbao.hcl shipped
    // with the repo: the `stdout` device, which audits to the container log.
    // OpenBao >= 2.5 requires audit devices to be declared in the server
    // configuration rather than enabled via the API, and `init` verifies
    // that a file audit backend is present (see
    // `OpenBaoClient::verify_audit_file`). Where the audit override applies,
    // `sync_openbao_audit_device` switches the stanza to the store-backed
    // `file` device afterwards.
    let content = r#"storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = 1
  telemetry {
    disallow_metrics = true
  }
}

listener "tcp" {
  address = "0.0.0.0:9101"
  tls_disable = 1
  telemetry {
    metrics_only = true
    unauthenticated_metrics_access = true
  }
}

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}

audit {
  type = "file"
  path = "stdout"
  options {
    file_path = "stdout"
  }
}

disable_mlock = true
ui = true
"#;

    publish_openbao_hcl(&hcl_path, content, messages)?;

    println!("{}", messages.info_openbao_hcl_tls_reverted());
    Ok(())
}

/// An audit device the `audit` stanza of `openbao.hcl` can declare.
///
/// `OpenBao` keeps each declared device's options in its audit table and
/// refuses to unseal when the configuration changes an existing device's
/// options, so the two destinations are two devices at two paths rather
/// than one device whose `file_path` moves. A switch disables one and
/// enables the other at the next unseal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OpenBaoAuditDevice {
    /// `path = "stdout"`, `file_path = "stdout"`: audits to the
    /// container's standard output, retained by the Docker logging
    /// driver. Used whenever `OpenBao` runs without the audit override.
    Stdout,
    /// `path = "file"`, `file_path = "/openbao/audit/audit.log"`: audits
    /// to the registrar endpoint's audit store, which the audit override
    /// bind-mounts at `/openbao/audit`. Used exactly when the Compose
    /// invocation that creates the container includes that override.
    StoreFile,
}

impl OpenBaoAuditDevice {
    /// Returns the device a Compose invocation needs: the store-backed
    /// file device when it includes the audit override, the `stdout`
    /// device otherwise.
    #[must_use]
    pub(crate) fn for_audit_override(override_applied: bool) -> Self {
        if override_applied {
            Self::StoreFile
        } else {
            Self::Stdout
        }
    }

    /// The device's mount path, its `path` attribute.
    fn mount_path(self) -> &'static str {
        match self {
            Self::Stdout => OPENBAO_AUDIT_STDOUT,
            Self::StoreFile => OPENBAO_AUDIT_STORE_MOUNT_PATH,
        }
    }

    /// The device's `file_path` option.
    fn file_path(self) -> &'static str {
        match self {
            Self::Stdout => OPENBAO_AUDIT_STDOUT,
            Self::StoreFile => OPENBAO_AUDIT_STORE_FILE_PATH,
        }
    }

    /// Returns the device a `path` / `file_path` pair declares, if it is
    /// one of the two.
    fn from_pair(mount_path: &str, file_path: &str) -> Option<Self> {
        [Self::Stdout, Self::StoreFile]
            .into_iter()
            .find(|device| device.mount_path() == mount_path && device.file_path() == file_path)
    }
}

/// Where the attributes [`sync_openbao_audit_device`] rewrites sit in
/// `openbao.hcl`.
struct AuditStanzaLines {
    path_line: usize,
    file_path_line: usize,
    device: OpenBaoAuditDevice,
}

/// Splits `key = "value"` into its key and unquoted value.
///
/// Returns `None` for a line that is not a single attribute with a
/// plain quoted string value.
fn hcl_string_attribute(active: &str) -> Option<(&str, &str)> {
    let (key, value) = active.split_once('=')?;
    let inner = value.trim().strip_prefix('"')?.strip_suffix('"')?;
    if inner.contains('"') {
        return None;
    }
    Some((key.trim(), inner))
}

/// The active text of one HCL line, with its comments removed.
struct ActiveHclLine {
    text: String,
    /// Whether any part of the line sat inside a `/* ... */` comment.
    touches_block_comment: bool,
}

/// Removes the comments from `line`, continuing a `/* ... */` comment
/// that an earlier line opened when `in_block_comment` is set.
///
/// HCL treats a block comment as whitespace, so each one becomes a
/// single space; `#` and `//` end the line's active text. Comment
/// markers inside a quoted string are part of the string.
fn strip_hcl_comments(line: &str, in_block_comment: &mut bool) -> ActiveHclLine {
    let mut text = String::with_capacity(line.len());
    let mut touches_block_comment = *in_block_comment;
    let mut in_quote = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        if *in_block_comment {
            if c == '*' && chars.peek() == Some(&'/') {
                chars.next();
                *in_block_comment = false;
                text.push(' ');
            }
            continue;
        }
        if in_quote {
            text.push(c);
            match c {
                '\\' => {
                    if let Some(escaped) = chars.next() {
                        text.push(escaped);
                    }
                }
                '"' => in_quote = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_quote = true;
                text.push(c);
            }
            '#' => break,
            '/' if chars.peek() == Some(&'/') => break,
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                *in_block_comment = true;
                touches_block_comment = true;
            }
            _ => text.push(c),
        }
    }
    ActiveHclLine {
        text,
        touches_block_comment,
    }
}

/// Locates the single `audit` stanza of `lines` and its `path` and
/// `file_path` lines.
///
/// Returns `None` unless the content holds exactly one top-level
/// `audit` stanza with exactly one `path` attribute directly inside it
/// and exactly one `file_path` attribute anywhere inside it, each on a
/// line of its own with no `/* ... */` comment on it, and the two
/// values form one of the two devices. Commented-out text, line or
/// block, is not part of the stanza.
fn locate_audit_stanza(lines: &[&str]) -> Option<AuditStanzaLines> {
    let mut depth: usize = 0;
    let mut stanzas = 0usize;
    let mut in_audit = false;
    let mut in_block_comment = false;
    let mut path_lines: Vec<(usize, String)> = Vec::new();
    let mut file_path_lines: Vec<(usize, String)> = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let stripped = strip_hcl_comments(line, &mut in_block_comment);
        let active = stripped.text.trim();
        // A rewritten line's value is located on the raw line, which a
        // block comment on it would confuse; such a line declares no
        // value the sync can rewrite.
        let value_of = |attribute: Option<(&str, &str)>| {
            if stripped.touches_block_comment {
                String::new()
            } else {
                attribute.map_or_else(String::new, |(_, value)| value.to_string())
            }
        };
        if depth == 0 {
            let rest = active.strip_prefix("audit");
            if rest.is_some_and(|rest| {
                let rest = rest.trim_start();
                rest.starts_with('{') || rest.starts_with('"')
            }) {
                stanzas += 1;
                in_audit = true;
            }
        } else if in_audit {
            let attribute = hcl_string_attribute(active);
            let key = active.split_once('=').map(|(key, _)| key.trim());
            if key == Some("path") {
                // Directly inside the stanza only; a nested block's own
                // `path` would not be the device's mount path.
                if depth == 1 {
                    path_lines.push((index, value_of(attribute)));
                }
            } else if key == Some("file_path") {
                file_path_lines.push((index, value_of(attribute)));
            }
        }
        for byte in active.bytes() {
            match byte {
                b'{' => depth += 1,
                b'}' => depth = depth.checked_sub(1)?,
                _ => {}
            }
        }
        if depth == 0 {
            in_audit = false;
        }
    }
    if stanzas != 1 || depth != 0 || in_block_comment {
        return None;
    }
    let [(path_line, mount_path)] = path_lines.as_slice() else {
        return None;
    };
    let [(file_path_line, file_path)] = file_path_lines.as_slice() else {
        return None;
    };
    Some(AuditStanzaLines {
        path_line: *path_line,
        file_path_line: *file_path_line,
        device: OpenBaoAuditDevice::from_pair(mount_path, file_path)?,
    })
}

/// Replaces the quoted value of the attribute on `line`, keeping its
/// indentation, spacing and any trailing comment.
fn replace_attribute_value(line: &str, value: &str) -> Option<String> {
    let equals = line.find('=')?;
    let open = equals + 1 + line.get(equals + 1..)?.find('"')?;
    let close = open + 1 + line.get(open + 1..)?.find('"')?;
    Some(format!(
        "{}\"{value}\"{}",
        line.get(..open)?,
        line.get(close + 1..)?
    ))
}

/// Sets the audit stanza of `<compose_dir>/openbao/openbao.hcl` to
/// `device`.
///
/// Every bootroot path that brings up or recreates the `openbao` service
/// calls this first, so the device always matches the mounts that
/// invocation creates the container with: the store-backed file device
/// would otherwise start with no `/openbao/audit`, fail post-unseal
/// setup and leave `OpenBao` sealed.
///
/// Only the values of the stanza's `path` line and its `file_path` line
/// are rewritten. A stanza that already declares `device` is left
/// unwritten, so the file's inode and mtime do not change. An absent
/// `openbao.hcl` is not an error, the same as
/// [`write_openbao_hcl_plaintext`].
///
/// # Errors
///
/// Returns an error, before writing anything, when the file does not
/// hold exactly one audit stanza whose `path` and `file_path` lines
/// declare one of the two devices — for example after a hand edit — or
/// when reading or publishing the file fails.
pub(crate) fn sync_openbao_audit_device(
    compose_dir: &Path,
    device: OpenBaoAuditDevice,
    messages: &Messages,
) -> Result<()> {
    let hcl_path = compose_dir.join(OPENBAO_HCL_PATH);
    if !hcl_path.exists() {
        return Ok(());
    }
    let display = hcl_path.display().to_string();
    let content = std::fs::read_to_string(&hcl_path)
        .with_context(|| messages.error_read_file_failed(&display))?;
    let unrecognized =
        || anyhow::anyhow!(messages.error_openbao_hcl_audit_stanza_unrecognized(&display));
    let lines: Vec<&str> = content.split_inclusive('\n').collect();
    let stanza = locate_audit_stanza(&lines).ok_or_else(unrecognized)?;
    if stanza.device == device {
        return Ok(());
    }
    let mut rewritten = String::with_capacity(content.len());
    for (index, line) in lines.iter().enumerate() {
        let value = if index == stanza.path_line {
            Some(device.mount_path())
        } else if index == stanza.file_path_line {
            Some(device.file_path())
        } else {
            None
        };
        match value {
            Some(value) => {
                let replaced = replace_attribute_value(line, value).ok_or_else(unrecognized)?;
                rewritten.push_str(&replaced);
            }
            None => rewritten.push_str(line),
        }
    }
    publish_openbao_hcl(&hcl_path, &rewritten, messages)?;
    println!(
        "{}",
        messages.info_openbao_audit_device_set(device.mount_path(), &display)
    );
    Ok(())
}

/// Re-issues an existing `OpenBao` infrastructure certificate.
///
/// Used by the rotation pipeline to renew the cert before expiry.
pub(crate) fn reissue_openbao_tls_cert(
    compose_dir: &Path,
    secrets_dir: &Path,
    entry: &InfraCertEntry,
    openbao_container: &str,
    docker: &Path,
    messages: &Messages,
) -> Result<()> {
    let san_refs: Vec<&str> = entry.sans.iter().map(String::as_str).collect();
    let sans = if san_refs.is_empty() {
        vec!["openbao.internal", "localhost", openbao_container]
    } else {
        san_refs
    };
    issue_openbao_tls_cert(compose_dir, secrets_dir, &sans, docker, messages)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use super::super::test_support::{
        write_self_contained_fake_docker, write_self_contained_fake_docker_exiting,
    };
    use super::*;

    /// The `OpenBao` container name a default install renders.
    const DEFAULT_OPENBAO_CONTAINER: &str = "bootroot-openbao";

    #[test]
    fn build_sans_includes_specific_ip() {
        let sans = build_openbao_tls_sans("192.168.1.10:8200", None, DEFAULT_OPENBAO_CONTAINER);
        assert!(sans.contains(&"openbao.internal".to_string()));
        assert!(sans.contains(&"localhost".to_string()));
        assert!(sans.contains(&DEFAULT_OPENBAO_CONTAINER.to_string()));
        assert!(sans.contains(&"192.168.1.10".to_string()));
    }

    /// The `OpenBao` server certificate has to validate for the DNS name
    /// its own container answers to inside the compose network.
    #[test]
    fn build_sans_carry_the_instance_container_name() {
        let sans = build_openbao_tls_sans("192.168.1.10:8200", None, "insight-openbao");
        assert!(sans.contains(&"insight-openbao".to_string()));
        assert!(
            !sans.contains(&DEFAULT_OPENBAO_CONTAINER.to_string()),
            "a non-default instance must not carry the default container name: {sans:?}"
        );
        // The names that are not container names are untouched.
        assert!(sans.contains(&"openbao.internal".to_string()));
        assert!(sans.contains(&"localhost".to_string()));
    }

    /// The renewal path has its own SAN fallback, reached when the
    /// recorded entry carries none; it must scope the container name too.
    #[test]
    fn reissue_falls_back_to_instance_scoped_sans() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        let compose_dir = dir.path().join("compose");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();
        let tls_dir = compose_dir.join("openbao").join("tls");
        fs::create_dir_all(&tls_dir).unwrap();
        fs::write(tls_dir.join("server.crt"), "cert").unwrap();
        fs::write(tls_dir.join("server.key"), "key").unwrap();

        let entry = InfraCertEntry {
            cert_path: tls_dir.join("server.crt"),
            key_path: tls_dir.join("server.key"),
            sans: Vec::new(),
            renew_before: OPENBAO_TLS_DEFAULT_RENEW_BEFORE.to_string(),
            reload_strategy: ReloadStrategy::ContainerSignal {
                container_name: "insight-openbao".to_string(),
                signal: "SIGHUP".to_string(),
            },
            issued_at: None,
            expires_at: None,
        };

        let messages = crate::i18n::test_messages();

        reissue_openbao_tls_cert(
            &compose_dir,
            &secrets_dir,
            &entry,
            "insight-openbao",
            &fake,
            &messages,
        )
        .expect("re-issuance must succeed against the fake docker");

        let log = fs::read_to_string(&args_log).unwrap_or_default();
        assert!(
            log.contains("--san insight-openbao"),
            "the fallback SAN list must name the instance's container, got: {log}"
        );
        assert!(
            !log.contains(&format!("--san {DEFAULT_OPENBAO_CONTAINER}")),
            "the fallback must not carry the default container name, got: {log}"
        );
    }

    #[test]
    fn build_sans_wildcard_adds_loopback() {
        let sans = build_openbao_tls_sans("0.0.0.0:8200", None, DEFAULT_OPENBAO_CONTAINER);
        assert!(sans.contains(&"127.0.0.1".to_string()));
        assert!(!sans.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_sans_ipv6_specific() {
        let sans = build_openbao_tls_sans("[fd12::1]:8200", None, DEFAULT_OPENBAO_CONTAINER);
        assert!(sans.contains(&"fd12::1".to_string()));
    }

    #[test]
    fn build_sans_ipv6_wildcard() {
        let sans = build_openbao_tls_sans("[::]:8200", None, DEFAULT_OPENBAO_CONTAINER);
        assert!(
            sans.contains(&"::1".to_string()),
            "IPv6 wildcard must include IPv6 loopback"
        );
        assert!(
            sans.contains(&"127.0.0.1".to_string()),
            "IPv6 wildcard must also include IPv4 loopback for dual-stack"
        );
        assert!(!sans.contains(&"::".to_string()));
    }

    #[test]
    fn build_sans_ipv6_zero_wildcard() {
        let sans = build_openbao_tls_sans("[::0]:8200", None, DEFAULT_OPENBAO_CONTAINER);
        assert!(
            sans.contains(&"::1".to_string()),
            "[::0] wildcard must include IPv6 loopback"
        );
        assert!(
            sans.contains(&"127.0.0.1".to_string()),
            "[::0] wildcard must also include IPv4 loopback for dual-stack"
        );
        assert!(!sans.contains(&"::0".to_string()));
    }

    #[test]
    fn build_sans_wildcard_with_advertise_addr() {
        let sans = build_openbao_tls_sans(
            "0.0.0.0:8200",
            Some("192.168.1.10:8200"),
            DEFAULT_OPENBAO_CONTAINER,
        );
        assert!(
            sans.contains(&"127.0.0.1".to_string()),
            "wildcard must include loopback"
        );
        assert!(
            sans.contains(&"192.168.1.10".to_string()),
            "advertise IP must be in SANs for remote hostname verification"
        );
        assert!(!sans.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_sans_wildcard_with_ipv6_advertise_addr() {
        let sans = build_openbao_tls_sans(
            "[::]:8200",
            Some("[fd12::1]:8200"),
            DEFAULT_OPENBAO_CONTAINER,
        );
        assert!(sans.contains(&"::1".to_string()));
        assert!(sans.contains(&"127.0.0.1".to_string()));
        assert!(
            sans.contains(&"fd12::1".to_string()),
            "IPv6 advertise IP must be in SANs"
        );
    }

    #[test]
    fn build_sans_advertise_addr_not_duplicated() {
        let sans = build_openbao_tls_sans(
            "192.168.1.10:8200",
            Some("192.168.1.10:8200"),
            DEFAULT_OPENBAO_CONTAINER,
        );
        let count = sans.iter().filter(|s| *s == "192.168.1.10").count();
        assert_eq!(count, 1, "advertise IP must not be duplicated");
    }

    #[test]
    fn record_openbao_infra_cert_inserts_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            stepca_bind_addr: None,
            stepca_advertise_addr: None,
            infra_certs: BTreeMap::new(),
            ..Default::default()
        };
        let sans = vec!["openbao.internal".to_string(), "localhost".to_string()];
        record_openbao_infra_cert(&mut state, dir.path(), sans, "insight-openbao");
        assert!(state.infra_certs.contains_key(OPENBAO_INFRA_CERT_KEY));
        let entry = &state.infra_certs[OPENBAO_INFRA_CERT_KEY];
        assert_eq!(
            entry.reload_strategy,
            ReloadStrategy::ContainerSignal {
                container_name: "insight-openbao".to_string(),
                signal: "SIGHUP".to_string(),
            }
        );
        assert!(entry.issued_at.is_some());
    }

    #[test]
    fn write_openbao_hcl_with_tls_creates_valid_hcl() {
        let dir = tempfile::tempdir().unwrap();
        let openbao_dir = dir.path().join("openbao");
        std::fs::create_dir_all(&openbao_dir).unwrap();
        let messages = crate::i18n::test_messages();
        write_openbao_hcl_with_tls(dir.path(), &messages).unwrap();
        let content = std::fs::read_to_string(dir.path().join(OPENBAO_HCL_PATH)).unwrap();
        assert!(content.contains("tls_cert_file"));
        assert!(content.contains("tls_key_file"));
        // API listener on :8200 must not have tls_disable.
        assert!(content.contains("address = \"0.0.0.0:8200\""));
        let api_block_start = content.find("address = \"0.0.0.0:8200\"").unwrap();
        let api_block = &content[..api_block_start + 200];
        assert!(!api_block.contains("tls_disable"));
        // Telemetry listener should still have tls_disable.
        assert!(content.contains("tls_disable = 1"));
        // File audit backend must be declared so init's
        // `verify_audit_file` succeeds after the TLS rewrite.
        assert!(content.contains("audit {"));
        assert!(content.contains("type = \"file\""));
        assert!(content.contains("file_path = \"stdout\""));
    }

    /// The bootroot-internal registrar credential authenticates at
    /// `auth/cert`, which validates the presented chain against its own
    /// trusted entry. The *listener* therefore stays as it is: a TLS
    /// listener already requests client certificates by default, and
    /// requiring or forbidding them here would break the
    /// certificate-less `AppRole` agents and every token-authenticated
    /// command against the same port.
    #[test]
    fn the_tls_listener_introduces_no_client_certificate_option() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("openbao")).unwrap();
        let messages = crate::i18n::test_messages();
        write_openbao_hcl_with_tls(dir.path(), &messages).unwrap();
        let content = std::fs::read_to_string(dir.path().join(OPENBAO_HCL_PATH)).unwrap();
        for option in [
            "tls_client_ca_file",
            "tls_require_and_verify_client_cert",
            "tls_disable_client_certs",
        ] {
            assert!(!content.contains(option), "{option} must not be set");
        }
    }

    #[test]
    fn write_openbao_hcl_plaintext_restores_tls_disable() {
        let dir = tempfile::tempdir().unwrap();
        let openbao_dir = dir.path().join("openbao");
        std::fs::create_dir_all(&openbao_dir).unwrap();
        let messages = crate::i18n::test_messages();
        // Start with TLS-enabled HCL.
        write_openbao_hcl_with_tls(dir.path(), &messages).unwrap();
        // Restore plaintext.
        write_openbao_hcl_plaintext(dir.path(), &messages).unwrap();
        let content = std::fs::read_to_string(dir.path().join(OPENBAO_HCL_PATH)).unwrap();
        assert!(
            !content.contains("tls_cert_file"),
            "plaintext HCL must not contain tls_cert_file"
        );
        // Both listeners must have tls_disable = 1.
        let tls_disable_count = content.matches("tls_disable = 1").count();
        assert_eq!(
            tls_disable_count, 2,
            "both listeners must have tls_disable = 1"
        );
        // Plaintext rewrite must preserve the file audit backend so init
        // can run after a subsequent `--openbao-bind` reinstall cycle.
        assert!(content.contains("audit {"));
        assert!(content.contains("type = \"file\""));
        assert!(content.contains("file_path = \"stdout\""));
    }

    /// The chown container must mount ONLY the `openbao/tls` directory and
    /// chown with `--no-dereference` so it never follows a symlink out of
    /// the mount.  It is deliberately the one root container on this path.
    #[test]
    fn build_tls_output_chown_args_scoped_and_no_symlink_following() {
        let mount = "/host/bootroot/openbao/tls:/output";
        let args = build_tls_output_chown_args(mount, "100:1000", STEP_CA_HELPER_IMAGE);
        let image_pos = args
            .iter()
            .position(|a| *a == STEP_CA_HELPER_IMAGE)
            .expect("image");

        // Exactly one bind mount, and it is the TLS output directory.
        let mounts: Vec<&&str> = args
            .iter()
            .zip(args.iter().skip(1))
            .filter_map(|(a, b)| (*a == "-v").then_some(b))
            .collect();
        assert_eq!(mounts, vec![&mount]);
        assert!(
            !args
                .iter()
                .any(|a| a.contains(":/home/step") || a.contains(":/secrets") || *a == "/"),
            "nothing above openbao/tls is reachable from inside the container"
        );

        // The chown overrides the image entrypoint so it runs `chown`
        // directly, never the step-ca init path that would warn about a
        // missing ca.json under the (deliberately unmounted) /home/step.
        let ep_pos = args
            .iter()
            .position(|a| *a == "--entrypoint")
            .expect("--entrypoint");
        assert_eq!(args.get(ep_pos + 1), Some(&"chown"));
        assert!(ep_pos < image_pos, "--entrypoint precedes the image");

        // chown recurses but does not dereference symlinks.
        assert!(args.contains(&"-R"));
        assert!(args.contains(&"--no-dereference"));

        // The ownership is the resolved secrets owner, never a fixed uid.
        assert!(args.contains(&"100:1000"));

        // Only root can chown to an arbitrary uid.
        let user_pos = args.iter().position(|a| *a == "--user").expect("--user");
        assert_eq!(args.get(user_pos + 1), Some(&"root"));

        // The chown target is the container-side mount point, nothing
        // outside it.
        assert_eq!(args.last(), Some(&TLS_OUTPUT_MOUNT));
    }

    /// The same wiring, reached through the executable seam instead of
    /// `PATH`: `issue_openbao_tls_cert` runs whichever program its
    /// caller named, all the way down through `run_docker`.
    ///
    /// This test mutates nothing process-global — no `PATH` edit, no
    /// variable set, no lock — because the fake it writes carries its
    /// own argv-log path in its script text.  It is therefore also proof
    /// that the seam needs no environment mechanism to be usable.
    #[test]
    fn issue_openbao_tls_cert_runs_the_supplied_executable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        let compose_dir = dir.path().join("compose");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("create secrets dir");
        // The fake no-ops `step certificate create`, so the files the
        // host-side chmod expects have to exist up front.
        let tls_dir = compose_dir.join("openbao").join("tls");
        fs::create_dir_all(&tls_dir).expect("create tls dir");
        fs::write(tls_dir.join("server.crt"), "cert").expect("write cert");
        fs::write(tls_dir.join("server.key"), "key").expect("write key");

        issue_openbao_tls_cert(
            &compose_dir,
            &secrets_dir,
            &["openbao.internal"],
            &fake,
            &crate::i18n::test_messages(),
        )
        .expect("issuing the certificate must succeed against the supplied executable");

        let log = fs::read_to_string(&args_log).expect("read docker args");
        let invocations: Vec<&str> = log.lines().collect();
        assert_eq!(
            invocations.len(),
            2,
            "the supplied executable must have run the chown and the certificate write, got: {log}"
        );
        assert!(
            invocations
                .get(1)
                .is_some_and(|create| create.contains("certificate create")),
            "the second invocation must be the certificate write, got: {log}"
        );
    }

    /// The argv builder is only worth anything if the certificate write
    /// actually runs it, and runs it *first*: a chown that landed after
    /// `step certificate create` would repair the ownership of files the
    /// container was never able to write. See issue #739.
    #[test]
    fn issue_openbao_tls_cert_chowns_output_dir_before_creating_the_cert() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        let compose_dir = dir.path().join("compose");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();
        // The fake docker no-ops `step certificate create`, so the files
        // the host-side chmod expects have to exist up front.
        let tls_dir = compose_dir.join("openbao").join("tls");
        fs::create_dir_all(&tls_dir).unwrap();
        fs::write(tls_dir.join("server.crt"), "cert").unwrap();
        fs::write(tls_dir.join("server.key"), "key").unwrap();

        let messages = crate::i18n::test_messages();

        issue_openbao_tls_cert(
            &compose_dir,
            &secrets_dir,
            &["openbao.internal"],
            &fake,
            &messages,
        )
        .expect("issuing the certificate must succeed against the fake docker");

        let log = fs::read_to_string(&args_log).unwrap_or_default();
        let invocations: Vec<&str> = log.lines().collect();
        assert_eq!(
            invocations.len(),
            2,
            "expected the chown and the certificate write, got: {log}"
        );
        let chown = invocations.first().expect("chown invocation");
        let create = invocations.get(1).expect("certificate create invocation");
        assert!(
            chown.contains("--entrypoint chown ") && chown.contains("--no-dereference"),
            "the first container must be the scoped chown, got: {chown}"
        );
        let expected_mount = format!(
            "{}:{TLS_OUTPUT_MOUNT}",
            std::fs::canonicalize(&tls_dir).unwrap().display()
        );
        assert!(
            chown.contains(&expected_mount),
            "the chown must mount the TLS output directory, got: {chown}"
        );
        assert!(
            create.contains("certificate create"),
            "the second container must be the certificate write, got: {create}"
        );

        // The 0644 outcome the OpenBao container's `:ro` mount depends on
        // must survive the added chown.
        for file in ["server.crt", "server.key"] {
            let mode = fs::metadata(tls_dir.join(file))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o644, "{file} must stay world-readable");
        }
    }

    /// A chown that failed must abort the issuance rather than let the
    /// `step` container run into the very `permission denied` the chown
    /// exists to prevent, and the error has to name the failing step —
    /// a bare docker-command failure would leave an operator guessing.
    /// See issue #739.
    #[test]
    fn issue_openbao_tls_cert_aborts_when_the_chown_fails() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker_exiting(&fake, &args_log, 1);

        let compose_dir = dir.path().join("compose");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();

        let messages = crate::i18n::test_messages();

        let error = issue_openbao_tls_cert(
            &compose_dir,
            &secrets_dir,
            &["openbao.internal"],
            &fake,
            &messages,
        )
        .expect_err("a failing chown must fail the issuance");
        let chain = format!("{error:#}");
        assert!(
            chain.contains(messages.error_openbao_tls_provision_failed()),
            "the chown failure must be reported as a failed issuance, got: {chain}"
        );

        // Exactly one container ran: the certificate write never started.
        let log = fs::read_to_string(&args_log).unwrap_or_default();
        assert_eq!(
            log.lines().count(),
            1,
            "the certificate write must not run after a failed chown, got: {log}"
        );
        assert!(
            !log.contains("certificate create"),
            "the certificate write must not run after a failed chown, got: {log}"
        );
    }

    /// `canonicalize` resolves the final component, so a symlink at
    /// `openbao/tls` would silently relocate the bind-mount source: the
    /// root helper would `chown -R` the link target and `step certificate
    /// create` would write the key into it, both outside the directory
    /// the mount is supposed to be pinned to.  `--no-dereference` only
    /// covers links *inside* the mount, so the path itself has to be
    /// refused before anything is mounted.
    #[test]
    fn issue_openbao_tls_cert_refuses_a_symlinked_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        // The fake would log any invocation it received, so the empty
        // log below is evidence that nothing ran rather than evidence
        // that nothing could.
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        let compose_dir = dir.path().join("compose");
        let secrets_dir = dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();

        // Somewhere a chown -R must never reach.
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        let tls_dir = compose_dir.join("openbao").join("tls");
        fs::create_dir_all(tls_dir.parent().expect("openbao dir")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &tls_dir).unwrap();

        let messages = crate::i18n::test_messages();

        let error = issue_openbao_tls_cert(
            &compose_dir,
            &secrets_dir,
            &["openbao.internal"],
            &fake,
            &messages,
        )
        .expect_err("a symlinked output directory must fail the issuance");
        let chain = format!("{error:#}");
        assert!(
            chain.contains(&tls_dir.display().to_string()),
            "the error must name the refused path, got: {chain}"
        );

        // No container ran at all: neither the chown nor the write.
        let log = fs::read_to_string(&args_log).unwrap_or_default();
        assert!(
            log.trim().is_empty(),
            "nothing may be mounted for a symlinked output directory, got: {log}"
        );
        // The symlink target is untouched.
        assert!(elsewhere.read_dir().unwrap().next().is_none());
    }

    /// The audit stanza every renderer emits, and the canonical file
    /// ships: the `stdout` device, with no option beyond `file_path` —
    /// in particular nothing that weakens the default HMAC.
    const STDOUT_AUDIT_STANZA: &str = "audit {
  type = \"file\"
  path = \"stdout\"
  options {
    file_path = \"stdout\"
  }
}
";

    /// Returns the text of the single top-level `audit` stanza.
    fn audit_stanza(content: &str) -> String {
        let start = content.find("\naudit {").expect("audit stanza") + 1;
        let rest = &content[start..];
        let end = rest.find("\n}\n").expect("stanza end") + 3;
        rest[..end].to_string()
    }

    fn canonical_hcl() -> String {
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("openbao/openbao.hcl"))
            .expect("read canonical openbao.hcl")
    }

    /// A compose directory holding `openbao/openbao.hcl` with `content`.
    fn compose_dir_with_hcl(content: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("openbao")).unwrap();
        let hcl = dir.path().join(OPENBAO_HCL_PATH);
        fs::write(&hcl, content).unwrap();
        (dir, hcl)
    }

    fn store_file_hcl() -> String {
        canonical_hcl()
            .replace("\n  path = \"stdout\"", "\n  path = \"file\"")
            .replace(
                "file_path = \"stdout\"",
                "file_path = \"/openbao/audit/audit.log\"",
            )
    }

    #[test]
    fn canonical_and_rendered_hcl_declare_the_stdout_device() {
        let messages = crate::i18n::test_messages();
        let tls = tempfile::tempdir().unwrap();
        fs::create_dir_all(tls.path().join("openbao")).unwrap();
        write_openbao_hcl_with_tls(tls.path(), &messages).unwrap();
        let (plaintext, hcl) = compose_dir_with_hcl("placeholder");
        write_openbao_hcl_plaintext(plaintext.path(), &messages).unwrap();

        for (name, content) in [
            ("canonical", canonical_hcl()),
            (
                "tls",
                fs::read_to_string(tls.path().join(OPENBAO_HCL_PATH)).unwrap(),
            ),
            ("plaintext", fs::read_to_string(&hcl).unwrap()),
        ] {
            assert_eq!(audit_stanza(&content), STDOUT_AUDIT_STANZA, "{name}");
            assert_eq!(content.matches("audit {").count(), 1, "{name}");
            for weakening in ["log_raw", "hmac_accessor", "elide_list_responses"] {
                assert!(!content.contains(weakening), "{name} sets {weakening}");
            }
            let lines: Vec<&str> = content.split_inclusive('\n').collect();
            assert_eq!(
                locate_audit_stanza(&lines).map(|stanza| stanza.device),
                Some(OpenBaoAuditDevice::Stdout),
                "{name}"
            );
        }
    }

    /// The store-backed device's `file_path` is the active file the
    /// daemon's rotator renames, under the directory the audit override
    /// binds the store at.
    #[test]
    fn the_store_file_path_is_the_rotated_file_under_the_bind_target() {
        assert_eq!(
            OPENBAO_AUDIT_STORE_FILE_PATH,
            format!(
                "{}/{}",
                bootroot::registrar::audit_store::OPENBAO_CONTAINER_AUDIT_DIR,
                bootroot::registrar::openbao_audit::ACTIVE_FILE_NAME
            )
        );
    }

    #[test]
    fn sync_switches_between_the_two_devices_in_both_directions() {
        let messages = crate::i18n::test_messages();
        let canonical = canonical_hcl();
        let (dir, hcl) = compose_dir_with_hcl(&canonical);

        sync_openbao_audit_device(dir.path(), OpenBaoAuditDevice::StoreFile, &messages).unwrap();
        let store = fs::read_to_string(&hcl).unwrap();
        assert_eq!(store, store_file_hcl());
        assert!(store.contains("  type = \"file\"\n  path = \"file\"\n"));
        assert!(store.contains("    file_path = \"/openbao/audit/audit.log\"\n"));

        sync_openbao_audit_device(dir.path(), OpenBaoAuditDevice::Stdout, &messages).unwrap();
        assert_eq!(fs::read_to_string(&hcl).unwrap(), canonical);
    }

    /// Only the two values change: the TLS listener, a trailing comment
    /// and the line layout around them survive the rewrite.
    #[test]
    fn sync_rewrites_only_the_two_values() {
        let messages = crate::i18n::test_messages();
        let tls = tempfile::tempdir().unwrap();
        fs::create_dir_all(tls.path().join("openbao")).unwrap();
        write_openbao_hcl_with_tls(tls.path(), &messages).unwrap();
        let hcl = tls.path().join(OPENBAO_HCL_PATH);
        let original = fs::read_to_string(&hcl)
            .unwrap()
            .replace("\n  path = \"stdout\"", "\n  path   =   \"stdout\" # mount");
        fs::write(&hcl, &original).unwrap();

        sync_openbao_audit_device(tls.path(), OpenBaoAuditDevice::StoreFile, &messages).unwrap();
        let rewritten = fs::read_to_string(&hcl).unwrap();
        assert_eq!(
            rewritten,
            original
                .replace(
                    "path   =   \"stdout\" # mount",
                    "path   =   \"file\" # mount"
                )
                .replace(
                    "file_path = \"stdout\"",
                    "file_path = \"/openbao/audit/audit.log\""
                )
        );
        assert!(rewritten.contains("tls_cert_file"));
    }

    #[test]
    fn sync_does_not_write_when_the_device_already_matches() {
        let messages = crate::i18n::test_messages();
        for (content, device) in [
            (canonical_hcl(), OpenBaoAuditDevice::Stdout),
            (store_file_hcl(), OpenBaoAuditDevice::StoreFile),
        ] {
            let (dir, hcl) = compose_dir_with_hcl(&content);
            let past =
                std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
            fs::File::options()
                .write(true)
                .open(&hcl)
                .unwrap()
                .set_modified(past)
                .unwrap();
            let before = fs::metadata(&hcl).unwrap();

            sync_openbao_audit_device(dir.path(), device, &messages).unwrap();

            let after = fs::metadata(&hcl).unwrap();
            assert_eq!(
                after.ino(),
                before.ino(),
                "{device:?}: the file was replaced"
            );
            assert_eq!(
                after.modified().unwrap(),
                past,
                "{device:?}: the file was written"
            );
            assert_eq!(fs::read_to_string(&hcl).unwrap(), content);
        }
    }

    #[test]
    fn sync_is_ok_without_an_hcl() {
        let messages = crate::i18n::test_messages();
        let dir = tempfile::tempdir().unwrap();
        for device in [OpenBaoAuditDevice::Stdout, OpenBaoAuditDevice::StoreFile] {
            sync_openbao_audit_device(dir.path(), device, &messages).unwrap();
        }
        assert!(!dir.path().join(OPENBAO_HCL_PATH).exists());
        assert!(!dir.path().join("openbao").exists());
    }

    #[test]
    fn sync_refuses_an_unrecognised_audit_stanza_in_both_locales() {
        let canonical = canonical_hcl();
        let stanza = audit_stanza(&canonical);
        let refused = [
            ("no audit stanza", canonical.replace(&stanza, "")),
            (
                "two audit stanzas",
                canonical.replace(&stanza, &format!("{stanza}\n{stanza}")),
            ),
            (
                "no file_path line",
                canonical.replace("    file_path = \"stdout\"\n", ""),
            ),
            (
                "two file_path lines",
                canonical.replace(
                    "    file_path = \"stdout\"\n",
                    "    file_path = \"stdout\"\n    file_path = \"stdout\"\n",
                ),
            ),
            ("no path line", canonical.replace("  path = \"stdout\"\n", "")),
            (
                "stdout path with the store file",
                canonical.replace(
                    "file_path = \"stdout\"",
                    "file_path = \"/openbao/audit/audit.log\"",
                ),
            ),
            (
                "file path writing to stdout",
                canonical.replace("\n  path = \"stdout\"", "\n  path = \"file\""),
            ),
            (
                "another file",
                canonical.replace("file_path = \"stdout\"", "file_path = \"/var/log/x.log\""),
            ),
            (
                "single-line stanza",
                canonical.replace(
                    &stanza,
                    "audit { type = \"file\" path = \"stdout\" options { file_path = \"stdout\" } }\n",
                ),
            ),
            // HCL reads a block comment as whitespace, so each of these
            // has no active stanza or attribute where the text shows one.
            (
                "block-commented stanza",
                canonical.replace(&stanza, &format!("/*\n{stanza}*/\n")),
            ),
            (
                "stanza commented from a line of its own",
                canonical.replace(&stanza, &format!("/* disabled\n{stanza}   */\n")),
            ),
            (
                "block-commented file_path line",
                canonical.replace(
                    "    file_path = \"stdout\"\n",
                    "    /* file_path = \"stdout\" */\n",
                ),
            ),
            (
                "file_path inside a multi-line block comment",
                canonical.replace(
                    "    file_path = \"stdout\"\n",
                    "    /*\n    file_path = \"stdout\"\n    */\n",
                ),
            ),
            (
                "block-commented path line",
                canonical.replace("  path = \"stdout\"\n", "  /* path = \"stdout\" */\n"),
            ),
            (
                "path inside a multi-line block comment",
                canonical.replace(
                    "  path = \"stdout\"\n",
                    "  /*\n  path = \"stdout\"\n  */\n",
                ),
            ),
            (
                "block comment on a rewritten line",
                canonical.replace("  path = \"stdout\"\n", "  path = /* mount */ \"stdout\"\n"),
            ),
            (
                "unterminated block comment",
                format!("{canonical}/*\n"),
            ),
        ];
        for (case, content) in refused {
            for (locale, marker) in [
                ("en", "refusing to rewrite"),
                ("ko", "다시 쓰기를 거부합니다"),
            ] {
                let messages = crate::i18n::Messages::new(locale).unwrap();
                let (dir, hcl) = compose_dir_with_hcl(&content);
                for device in [OpenBaoAuditDevice::Stdout, OpenBaoAuditDevice::StoreFile] {
                    let err = sync_openbao_audit_device(dir.path(), device, &messages)
                        .expect_err(case)
                        .to_string();
                    assert!(
                        err.contains(&hcl.display().to_string()),
                        "{case} {locale}: {err}"
                    );
                    assert!(err.contains(marker), "{case} {locale}: {err}");
                    assert_eq!(fs::read_to_string(&hcl).unwrap(), content, "{case}");
                }
            }
        }
    }

    /// Comments around the stanza, line or block, and comment markers
    /// inside a quoted string, leave the one active stanza recognised —
    /// and only the active lines are rewritten.
    #[test]
    fn sync_reads_past_comments_to_the_active_stanza() {
        let messages = crate::i18n::test_messages();
        let canonical = canonical_hcl();
        let stanza = audit_stanza(&canonical);
        let store_stanza = audit_stanza(&store_file_hcl());
        let commented = canonical.replace(
            &stanza,
            &format!(
                "/* an older device:\n{store_stanza}*/\n\
                 # audit {{ path = \"file\" }}\n\
                 // audit {{\n\
                 api_addr = \"http://x/*y*/\" /* note */\n\
                 {stanza}"
            ),
        );
        let (dir, hcl) = compose_dir_with_hcl(&commented);
        sync_openbao_audit_device(dir.path(), OpenBaoAuditDevice::StoreFile, &messages).unwrap();
        let content = fs::read_to_string(&hcl).unwrap();
        assert_eq!(
            content,
            commented.replacen(&stanza, &store_stanza, 1),
            "only the active stanza is rewritten"
        );
        let lines: Vec<&str> = content.split_inclusive('\n').collect();
        assert_eq!(
            locate_audit_stanza(&lines).map(|stanza| stanza.device),
            Some(OpenBaoAuditDevice::StoreFile)
        );
    }

    /// `init`'s TLS rewrite lands on the device its recreate's mounts
    /// need: the store-backed file device with the audit override, the
    /// `stdout` device without it.
    #[test]
    fn init_tls_rewrite_follows_the_audit_override() {
        let messages = crate::i18n::test_messages();
        let override_path = Path::new("secrets/openbao/docker-compose.openbao-audit.yml");
        for (audit_override, start, expected) in [
            (
                Some(override_path),
                canonical_hcl(),
                OpenBaoAuditDevice::StoreFile,
            ),
            (
                Some(override_path),
                store_file_hcl(),
                OpenBaoAuditDevice::StoreFile,
            ),
            (None, store_file_hcl(), OpenBaoAuditDevice::Stdout),
            (None, canonical_hcl(), OpenBaoAuditDevice::Stdout),
        ] {
            let (dir, hcl) = compose_dir_with_hcl(&start);
            write_openbao_hcl_for_tls_recreate(dir.path(), audit_override, &messages).unwrap();
            let content = fs::read_to_string(&hcl).unwrap();
            assert!(content.contains("tls_cert_file"));
            let lines: Vec<&str> = content.split_inclusive('\n').collect();
            assert_eq!(
                locate_audit_stanza(&lines).map(|stanza| stanza.device),
                Some(expected),
                "{audit_override:?}"
            );
        }
    }

    #[test]
    fn write_openbao_hcl_plaintext_noop_when_no_hcl() {
        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();
        // No openbao.hcl exists — must be a no-op, not an error.
        write_openbao_hcl_plaintext(dir.path(), &messages).unwrap();
        assert!(!dir.path().join(OPENBAO_HCL_PATH).exists());
    }
}
