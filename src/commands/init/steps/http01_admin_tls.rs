use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;

use super::super::constants::{
    RESPONDER_CONFIG_DIR, RESPONDER_CONFIG_NAME, RESPONDER_TEMPLATE_DIR, RESPONDER_TEMPLATE_NAME,
};
use super::openbao_tls::{
    StepScratch, TLS_OUTPUT_MOUNT, chown_tls_output_dir, reject_symlinked_tls_output_dir,
};
use crate::commands::infra::run_docker_with_exec;
use crate::commands::init::{
    CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, HTTP01_ADMIN_INFRA_CERT_KEY,
    HTTP01_ADMIN_TLS_CERT_REL_PATH, HTTP01_ADMIN_TLS_DEFAULT_NOT_AFTER,
    HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE, HTTP01_ADMIN_TLS_KEY_REL_PATH,
};
use crate::commands::rotate::STEP_CA_HELPER_IMAGE;
use crate::i18n::Messages;
use crate::state::{InfraCertEntry, ReloadStrategy, StateFile};

/// The certificate's file name under `bootroot-http01/tls/`, as `step`
/// writes it.
const HTTP01_ADMIN_TLS_CERT_NAME: &str = "server.crt";

/// The key's file name under `bootroot-http01/tls/`, as `step` writes it.
const HTTP01_ADMIN_TLS_KEY_NAME: &str = "server.key";

/// Issues an HTTP-01 admin API TLS server certificate signed by the
/// local step-ca intermediate CA.
///
/// Writes the certificate to `secrets_dir/bootroot-http01/tls/{server.crt,server.key}`
/// with `0600` permissions, where `secrets_dir` is `tree`'s anchor.
/// `step certificate create` runs via Docker (no step CLI required on
/// the host), as the owner of `secrets/`.
///
/// Path-based, a scoped root chown first hands that owner the output
/// directory — which a root-run `init` has already created root-owned
/// (see `chown_tls_output_dir`) — and the helper writes into it through
/// a mount. Rooted, neither runs: the helper writes into a
/// [`StepScratch`] beside `secrets/`, and the two files are read back
/// from it and published under `tls/` through the tree handle.
pub(in crate::commands::init) fn issue_http01_admin_tls_cert(
    tree: &fs_util::SecretsTree,
    sans: &[&str],
    docker: &Path,
    messages: &Messages,
) -> Result<()> {
    if tree.is_rooted() {
        return issue_http01_admin_tls_cert_rooted(tree, sans, docker, messages);
    }
    let secrets_dir = tree.anchor();
    let cert_path = secrets_dir.join(HTTP01_ADMIN_TLS_CERT_REL_PATH);
    let key_path = secrets_dir.join(HTTP01_ADMIN_TLS_KEY_REL_PATH);

    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let secrets_mount = format!("{}:/home/step", mount_root.display());

    let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
    reject_symlinked_tls_output_dir(
        &tls_dir,
        |path| messages.error_http01_admin_tls_output_dir_symlink(path),
        messages,
    )?;
    // Both levels `0700` under the tree's owner, through the tree
    // handle. The `canonicalize` below resolves `tls/` by name for the
    // docker mounts, which take a path.
    tree.ensure_dir(&tls_dir)
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
        "docker http01 admin tls output chown",
        messages.error_http01_admin_tls_provision_failed(),
        messages,
    )?;

    run_http01_admin_step(
        &user_arg,
        &secrets_mount,
        &tls_mount,
        sans,
        docker,
        messages,
    )?;

    tree.set_file_mode(&key_path, fs_util::KEY_FILE_MODE)?;
    tree.set_file_mode(&cert_path, fs_util::KEY_FILE_MODE)?;

    println!(
        "{}",
        messages.info_http01_admin_tls_provisioned(&cert_path.display().to_string())
    );
    Ok(())
}

/// [`issue_http01_admin_tls_cert`] for a root process over a `secrets/`
/// another account owns.
///
/// No root container runs and nothing below the anchor is mounted but
/// the anchor itself: the helper's output goes to a [`StepScratch`]
/// beside `secrets/`, is read back without following a link, and is
/// published as `server.{crt,key}` through the handle, at `0600` and
/// under the owner of `tls/`, which [`fs_util::SecretsTree::adopt_dir`]
/// has made the owner of `secrets/` — what the path-based `chown -R`
/// left. The scratch directory is gone on every exit path.
fn issue_http01_admin_tls_cert_rooted(
    tree: &fs_util::SecretsTree,
    sans: &[&str],
    docker: &Path,
    messages: &Messages,
) -> Result<()> {
    let secrets_dir = tree.anchor();
    let cert_path = secrets_dir.join(HTTP01_ADMIN_TLS_CERT_REL_PATH);
    let key_path = secrets_dir.join(HTTP01_ADMIN_TLS_KEY_REL_PATH);

    // The anchor and everything above it are outside what the owner of
    // `secrets/` can rename, so this mount source is root's to resolve.
    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let secrets_mount = format!("{}:/home/step", mount_root.display());

    let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
    tree.ensure_dir(&tls_dir)
        .with_context(|| messages.error_write_file_failed(&tls_dir.display().to_string()))?;
    tree.adopt_dir(&tls_dir)
        .with_context(|| messages.error_write_file_failed(&tls_dir.display().to_string()))?;

    let meta = std::fs::metadata(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let user_arg = format!("{}:{}", meta.uid(), meta.gid());

    let scratch = StepScratch::create(secrets_dir, (meta.uid(), meta.gid()), messages)?;
    let output_mount = scratch.output_mount();
    run_http01_admin_step(
        &user_arg,
        &secrets_mount,
        &output_mount,
        sans,
        docker,
        messages,
    )?;
    let cert = scratch.read_output(HTTP01_ADMIN_TLS_CERT_NAME, messages)?;
    let key = scratch.read_output(HTTP01_ADMIN_TLS_KEY_NAME, messages)?;
    for (path, contents) in [(&key_path, &key), (&cert_path, &cert)] {
        tree.publish(
            fs_util::Destination::bootroot_owned(path),
            contents,
            fs_util::StagedMode::Policy(fs_util::KEY_FILE_MODE),
            fs_util::RootedOwner::ContainingDir,
            fs_util::StagedDurability::FlushDirectory,
        )
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    }
    scratch.finish();

    println!(
        "{}",
        messages.info_http01_admin_tls_provisioned(&cert_path.display().to_string())
    );
    Ok(())
}

/// Runs `step certificate create` for the HTTP-01 admin certificate as
/// `user_arg`, with the CA inputs at `secrets_mount` and the output
/// mount `output_mount`.
fn run_http01_admin_step(
    user_arg: &str,
    secrets_mount: &str,
    output_mount: &str,
    sans: &[&str],
    docker: &Path,
    messages: &Messages,
) -> Result<()> {
    let intermediate_cert = format!("/home/step/{CA_CERTS_DIR}/{CA_INTERMEDIATE_CERT_FILENAME}");
    let output_cert = format!("{TLS_OUTPUT_MOUNT}/{HTTP01_ADMIN_TLS_CERT_NAME}");
    let output_key = format!("{TLS_OUTPUT_MOUNT}/{HTTP01_ADMIN_TLS_KEY_NAME}");
    let mut args: Vec<&str> = vec![
        "run",
        "--user",
        user_arg,
        "--rm",
        "-v",
        secrets_mount,
        "-v",
        output_mount,
        STEP_CA_HELPER_IMAGE,
        "step",
        "certificate",
        "create",
        "responder.internal",
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
    // `step certificate create --san` accepts a single value per flag
    // and must be repeated per SAN; comma-joining yields one literal
    // SAN whose DnsName is the joined string (failing hostname
    // verification for every individual name).  step infers DNS vs IP
    // from the value shape.
    for san in sans {
        args.push("--san");
        args.push(san);
    }
    args.extend(["--not-after", HTTP01_ADMIN_TLS_DEFAULT_NOT_AFTER, "--force"]);

    run_docker_with_exec(
        &args,
        "docker step certificate create (http01 admin tls)",
        docker,
        messages,
    )
    .with_context(|| messages.error_http01_admin_tls_provision_failed())
}

/// Builds the SANs list for the HTTP-01 admin API TLS certificate.
///
/// Always includes `responder.internal`, `localhost`, and
/// `responder_container` — the install's own responder container name,
/// which is what the admin API is reached by inside the compose network.
/// It is deliberately not `RESPONDER_SERVICE_NAME`: that constant is the
/// compose *service* name, which does not follow the install identity,
/// so on a non-default instance the certificate would not validate for
/// the container's own DNS name.  When a bind address is configured, its
/// IP component is added as well.  When an advertise address is provided
/// (wildcard bind), its IP is included so that clients connecting via
/// the advertised endpoint pass hostname verification.
pub(in crate::commands::init) fn build_http01_admin_tls_sans(
    bind_addr: &str,
    advertise_addr: Option<&str>,
    responder_container: &str,
) -> Vec<String> {
    let mut sans = vec![
        "responder.internal".to_string(),
        "localhost".to_string(),
        responder_container.to_string(),
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

/// Records the HTTP-01 admin API TLS certificate in
/// `StateFile::infra_certs`.
///
/// Stores the computed `sans` so that `reissue_http01_admin_tls_cert`
/// can reproduce the same SANs on renewal.
pub(in crate::commands::init) fn record_http01_admin_infra_cert(
    state: &mut StateFile,
    secrets_dir: &Path,
    sans: Vec<String>,
    responder_container: &str,
) {
    let cert_path = secrets_dir.join(HTTP01_ADMIN_TLS_CERT_REL_PATH);
    let key_path = secrets_dir.join(HTTP01_ADMIN_TLS_KEY_REL_PATH);

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let entry = InfraCertEntry {
        cert_path,
        key_path,
        sans,
        renew_before: HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE.to_string(),
        // The container name, not the compose service name: `docker kill
        // -s` addresses the container directly, so on a non-default
        // instance a service-named strategy would signal nothing.
        reload_strategy: ReloadStrategy::ContainerSignal {
            container_name: responder_container.to_string(),
            signal: "SIGHUP".to_string(),
        },
        issued_at: Some(now),
        expires_at: None,
    };

    state
        .infra_certs
        .insert(HTTP01_ADMIN_INFRA_CERT_KEY.to_string(), entry);
}

/// Re-issues an existing HTTP-01 admin API infrastructure certificate.
///
/// Used by the rotation pipeline to renew the cert before expiry.
pub(crate) fn reissue_http01_admin_tls_cert(
    tree: &fs_util::SecretsTree,
    entry: &InfraCertEntry,
    responder_container: &str,
    docker: &Path,
    messages: &Messages,
) -> Result<()> {
    let san_refs: Vec<&str> = entry.sans.iter().map(String::as_str).collect();
    let sans = if san_refs.is_empty() {
        vec!["responder.internal", "localhost", responder_container]
    } else {
        san_refs
    };
    issue_http01_admin_tls_cert(tree, &sans, docker, messages)
}

/// Strips `tls_cert_path` and `tls_key_path` lines from the responder
/// config and template files so that the responder does not start with
/// TLS enabled until the next `bootroot init` issues a fresh certificate.
///
/// No-ops when neither file exists (fresh install before first `init`).
///
/// Each stripped file is published by rename at the mode it already
/// carries — `0600`, set by `responder_setup` when it wrote them — which
/// the `path.exists()` guard below has established is readable. A rooted
/// `tree` reads and publishes both through its descriptors instead. The
/// responder container reads its config at start and the `OpenBao` Agent
/// sidecar re-renders it from the template on a fixed interval, so a
/// truncating rewrite could hand either one a half-stripped file.
///
/// The directory is not flushed: the next `bootroot init` regenerates
/// both files in full, so a crash that loses the entry costs that re-run
/// and leaves the previous config, with TLS still configured, in place.
pub(crate) fn strip_responder_tls_config(
    tree: &fs_util::SecretsTree,
    messages: &Messages,
) -> Result<()> {
    let secrets_dir = tree.anchor();
    let configs = [
        secrets_dir
            .join(RESPONDER_CONFIG_DIR)
            .join(RESPONDER_CONFIG_NAME),
        secrets_dir
            .join(RESPONDER_TEMPLATE_DIR)
            .join(RESPONDER_TEMPLATE_NAME),
    ];
    let mut stripped = false;
    for path in &configs {
        let content = if tree.is_rooted() {
            // Read and republished through the handle: as root over a
            // `secrets/` another account owns, a link at either level is
            // refused rather than followed.
            match tree.read(path) {
                Ok(bytes) => String::from_utf8(bytes)
                    .map_err(|err| anyhow::anyhow!(err))
                    .with_context(|| {
                        messages.error_read_file_failed(&path.display().to_string())
                    })?,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(anyhow::Error::new(err)
                        .context(messages.error_read_file_failed(&path.display().to_string())));
                }
            }
        } else {
            if !path.exists() {
                continue;
            }
            std::fs::read_to_string(path)
                .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?
        };
        let filtered: String = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.starts_with("tls_cert_path") && !trimmed.starts_with("tls_key_path")
            })
            .collect::<Vec<_>>()
            .join("\n");
        if filtered.len() != content.len() {
            let to_write = if content.ends_with('\n') && !filtered.ends_with('\n') {
                format!("{filtered}\n")
            } else {
                filtered
            };
            if tree.is_rooted() {
                tree.publish(
                    fs_util::Destination::operator_named(path),
                    to_write.as_bytes(),
                    fs_util::StagedMode::PreserveOrCreate(fs_util::KEY_FILE_MODE),
                    fs_util::RootedOwner::Destination,
                    fs_util::StagedDurability::RenameOnly,
                )
                .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
            } else {
                fs_util::atomic_replace_blocking(
                    fs_util::Destination::operator_named(path),
                    to_write.as_bytes(),
                    fs_util::StagedMode::PreserveOrCreate(fs_util::KEY_FILE_MODE),
                )
                .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
            }
            stripped = true;
        }
    }
    if stripped {
        println!("{}", messages.info_http01_admin_tls_reverted());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::fs::PermissionsExt;

    use super::super::test_support::{
        FakeOutput, step_scratch_dirs, volume_sources, write_output_fake_docker,
        write_self_contained_fake_docker, write_self_contained_fake_docker_exiting,
    };
    use super::*;
    use crate::test_support::SwapRoot;

    /// Asserts the one logged `step` run mounted the anchor and a
    /// `.bootroot-step-*/out` beside it, and nothing else, and that no
    /// chown container ran.
    fn assert_rooted_mounts(log: &str, root: &SwapRoot) {
        assert!(!log.contains("--entrypoint"), "no chown container: {log}");
        assert!(!log.contains("chown"), "no chown container: {log}");
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 1, "exactly the step run: {log}");
        let volumes = volume_sources(lines.first().expect("the step run"));
        let anchor = std::fs::canonicalize(&root.secrets).expect("canonical anchor");
        assert_eq!(volumes.len(), 2, "{volumes:?}");
        assert_eq!(
            volumes.first().map(String::as_str),
            Some(format!("{}:/home/step", anchor.display()).as_str())
        );
        let output = volumes
            .get(1)
            .and_then(|volume| volume.strip_suffix(":/output"))
            .map(Path::new)
            .expect("the output mount");
        assert!(output.is_absolute(), "{}", output.display());
        assert_eq!(output.file_name().and_then(|n| n.to_str()), Some("out"));
        let scratch = output.parent().expect("scratch dir");
        assert!(
            scratch
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".bootroot-step-")),
            "{}",
            scratch.display()
        );
        assert_eq!(
            scratch.parent(),
            Some(
                std::fs::canonicalize(root.root())
                    .expect("canonical root")
                    .as_path()
            ),
            "the scratch directory sits beside the anchor"
        );
    }

    #[test]
    fn rooted_issuance_runs_no_chown_and_publishes_from_a_scratch_dir() {
        let root = SwapRoot::new();
        let args_log = root.root().join("docker_args.log");
        let fake = write_output_fake_docker(
            root.root(),
            &args_log,
            &[
                ("server.crt", FakeOutput::File("CERT\n")),
                ("server.key", FakeOutput::File("KEY\n")),
            ],
        );
        let tree = root.rooted();

        issue_http01_admin_tls_cert(&tree, &["localhost"], &fake, &crate::i18n::test_messages())
            .expect("rooted issuance");

        assert_rooted_mounts(&std::fs::read_to_string(&args_log).expect("log"), &root);
        let tls_dir = root.secrets.join("bootroot-http01").join("tls");
        let tls_meta = std::fs::metadata(&tls_dir).expect("tls dir");
        for (name, contents) in [("server.crt", "CERT\n"), ("server.key", "KEY\n")] {
            let path = tls_dir.join(name);
            assert_eq!(std::fs::read_to_string(&path).expect("published"), contents);
            let meta = std::fs::symlink_metadata(&path).expect("stat");
            assert!(meta.is_file());
            assert_eq!(meta.permissions().mode() & 0o7777, 0o600, "{name}");
            assert_eq!((meta.uid(), meta.gid()), (tls_meta.uid(), tls_meta.gid()));
        }
        assert_eq!(
            step_scratch_dirs(root.root()),
            Vec::<std::path::PathBuf>::new()
        );

        // A second issuance over the existing `tls/` re-adopts it and
        // replaces both files.
        issue_http01_admin_tls_cert(&tree, &["localhost"], &fake, &crate::i18n::test_messages())
            .expect("second rooted issuance");
        assert_eq!(
            step_scratch_dirs(root.root()),
            Vec::<std::path::PathBuf>::new()
        );
    }

    #[test]
    fn rooted_issuance_refuses_a_linked_output_and_publishes_nothing() {
        let root = SwapRoot::new();
        let args_log = root.root().join("docker_args.log");
        let fake = write_output_fake_docker(
            root.root(),
            &args_log,
            &[
                ("server.crt", FakeOutput::File("CERT\n")),
                ("server.key", FakeOutput::Link(&root.outside.join("secret"))),
            ],
        );
        let before = root.outside_snapshot();
        let tree = root.rooted();

        let err = issue_http01_admin_tls_cert(
            &tree,
            &["localhost"],
            &fake,
            &crate::i18n::test_messages(),
        )
        .expect_err("a linked output is refused");

        assert!(format!("{err:#}").contains("server.key"), "{err:#}");
        let tls_dir = root.secrets.join("bootroot-http01").join("tls");
        assert!(!tls_dir.join("server.crt").exists());
        assert!(!tls_dir.join("server.key").exists());
        assert_eq!(
            step_scratch_dirs(root.root()),
            Vec::<std::path::PathBuf>::new()
        );
        assert_eq!(root.outside_snapshot(), before);
    }

    #[test]
    fn rooted_issuance_removes_the_scratch_dir_when_the_helper_fails() {
        let root = SwapRoot::new();
        let fake = root.root().join("fake-docker");
        let args_log = root.root().join("docker_args.log");
        write_self_contained_fake_docker_exiting(&fake, &args_log, 1);
        let tree = root.rooted();

        issue_http01_admin_tls_cert(&tree, &["localhost"], &fake, &crate::i18n::test_messages())
            .expect_err("a failing helper fails the issuance");

        assert_eq!(
            step_scratch_dirs(root.root()),
            Vec::<std::path::PathBuf>::new()
        );
    }

    #[test]
    fn rooted_issuance_refuses_a_swapped_output_parent() {
        let root = SwapRoot::new();
        std::fs::create_dir_all(root.secrets.join("bootroot-http01").join("tls")).unwrap();
        std::fs::create_dir_all(root.outside.join("tls")).unwrap();
        let args_log = root.root().join("docker_args.log");
        let fake = write_output_fake_docker(root.root(), &args_log, &[]);
        let tree = root.rooted();
        let before = root.outside_snapshot();
        let link = root.swap("bootroot-http01", &root.outside);

        let err = issue_http01_admin_tls_cert(
            &tree,
            &["localhost"],
            &fake,
            &crate::i18n::test_messages(),
        )
        .expect_err("a swapped bootroot-http01 is refused");

        crate::test_support::assert_error_names(&err, &link);
        assert_eq!(std::fs::read_to_string(&args_log).unwrap_or_default(), "");
        assert_eq!(root.outside_snapshot(), before);
    }

    #[test]
    fn the_scratch_parent_of_a_relative_anchor_is_absolute() {
        let parent = super::super::openbao_tls::step_scratch_parent(Path::new("secrets"))
            .expect("scratch parent");
        assert_eq!(
            parent,
            std::fs::canonicalize(std::env::current_dir().expect("cwd")).expect("canonical cwd")
        );
        assert!(parent.is_absolute());
    }

    #[test]
    fn rooted_strip_refuses_a_swapped_responder_dir() {
        let root = SwapRoot::new();
        root.write(
            "responder/responder.toml",
            "listen = \"x\"\ntls_cert_path = \"/a\"\ntls_key_path = \"/b\"\n",
        );
        std::fs::write(
            root.outside.join("responder.toml"),
            "tls_cert_path = \"/outside\"\n",
        )
        .unwrap();
        let tree = root.rooted();
        let before = root.outside_snapshot();
        let link = root.swap("responder", &root.outside);

        let err = strip_responder_tls_config(&tree, &crate::i18n::test_messages())
            .expect_err("a swapped responder dir is refused");

        crate::test_support::assert_error_names(&err, &link);
        assert_eq!(root.outside_snapshot(), before);
    }

    #[test]
    fn rooted_strip_rewrites_what_the_path_based_strip_does() {
        let mut results = Vec::new();
        for rooted in [false, true] {
            let root = SwapRoot::new();
            let path = root.write(
                "responder/responder.toml",
                "listen = \"x\"\ntls_cert_path = \"/a\"\ntls_key_path = \"/b\"\n",
            );
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
            let tree = if rooted {
                root.rooted()
            } else {
                fs_util::SecretsTree::open(&root.secrets).unwrap()
            };
            strip_responder_tls_config(&tree, &crate::i18n::test_messages()).unwrap();
            let meta = std::fs::metadata(&path).unwrap();
            results.push((
                std::fs::read_to_string(&path).unwrap(),
                meta.permissions().mode() & 0o7777,
            ));
        }
        assert_eq!(results.first(), results.get(1));
        assert_eq!(
            results.first().map(|r| r.0.as_str()),
            Some("listen = \"x\"\n")
        );
    }

    /// The responder container name a default install renders.
    const DEFAULT_RESPONDER_CONTAINER: &str = "bootroot-http01";

    #[test]
    fn build_sans_includes_specific_ip() {
        let sans =
            build_http01_admin_tls_sans("192.168.1.10:8080", None, DEFAULT_RESPONDER_CONTAINER);
        assert!(sans.contains(&"responder.internal".to_string()));
        assert!(sans.contains(&"localhost".to_string()));
        assert!(sans.contains(&DEFAULT_RESPONDER_CONTAINER.to_string()));
        assert!(sans.contains(&"192.168.1.10".to_string()));
    }

    /// The admin certificate has to validate for the responder
    /// container's own DNS name, which follows the install identity —
    /// unlike the compose service name, which does not.
    #[test]
    fn build_sans_carry_the_instance_container_name() {
        let sans = build_http01_admin_tls_sans("192.168.1.10:8080", None, "insight-http01");
        assert!(sans.contains(&"insight-http01".to_string()));
        assert!(
            !sans.contains(&DEFAULT_RESPONDER_CONTAINER.to_string()),
            "a non-default instance must not carry the default container name: {sans:?}"
        );
        assert!(sans.contains(&"responder.internal".to_string()));
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

        let secrets_dir = dir.path().join("secrets");
        let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("server.crt"), "cert").unwrap();
        std::fs::write(tls_dir.join("server.key"), "key").unwrap();

        let entry = InfraCertEntry {
            cert_path: tls_dir.join("server.crt"),
            key_path: tls_dir.join("server.key"),
            sans: Vec::new(),
            renew_before: HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE.to_string(),
            reload_strategy: ReloadStrategy::ContainerSignal {
                container_name: "insight-http01".to_string(),
                signal: "SIGHUP".to_string(),
            },
            issued_at: None,
            expires_at: None,
        };

        let messages = crate::i18n::test_messages();

        reissue_http01_admin_tls_cert(
            &fs_util::SecretsTree::open(&secrets_dir).expect("open"),
            &entry,
            "insight-http01",
            &fake,
            &messages,
        )
        .expect("re-issuance must succeed against the fake docker");

        let log = std::fs::read_to_string(&args_log).unwrap_or_default();
        assert!(
            log.contains("insight-http01"),
            "the fallback SAN list must name the instance's container, got: {log}"
        );
    }

    /// The certificate-issuing helper container runs the step-ca image
    /// the runtime declaration approves.
    #[test]
    fn issuance_runs_the_declared_step_ca_image() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        let secrets_dir = dir.path().join("secrets");
        let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("server.crt"), "cert").unwrap();
        std::fs::write(tls_dir.join("server.key"), "key").unwrap();

        let messages = crate::i18n::test_messages();
        issue_http01_admin_tls_cert(
            &fs_util::SecretsTree::open(&secrets_dir).expect("open"),
            &["localhost"],
            &fake,
            &messages,
        )
        .expect("issuance must succeed against the fake docker");

        let log = std::fs::read_to_string(&args_log).unwrap();
        let args: Vec<&str> = log.split_whitespace().collect();
        let image = args
            .iter()
            .position(|arg| *arg == "step")
            .and_then(|step| step.checked_sub(1))
            .and_then(|index| args.get(index))
            .expect("the image precedes the `step` command");
        crate::runtime_image_declaration::assert_declared_image(
            "step-ca",
            image,
            "init http01 admin TLS issuance",
        );
    }

    /// An endpoint-enabled `init` runs as root and has already created
    /// the output directory root-owned while writing the responder
    /// override, while `step` runs as the owner of `secrets/`; so the
    /// scoped root chown has to run first, over the output directory and
    /// nothing else, or the certificate write is refused (issue #1054).
    #[test]
    fn issuance_chowns_the_output_dir_before_creating_the_cert() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        let secrets_dir = dir.path().join("secrets");
        let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
        std::fs::create_dir_all(&tls_dir).unwrap();
        std::fs::write(tls_dir.join("server.crt"), "cert").unwrap();
        std::fs::write(tls_dir.join("server.key"), "key").unwrap();

        let messages = crate::i18n::test_messages();
        issue_http01_admin_tls_cert(
            &fs_util::SecretsTree::open(&secrets_dir).expect("open"),
            &["localhost"],
            &fake,
            &messages,
        )
        .expect("issuance must succeed against the fake docker");

        let log = std::fs::read_to_string(&args_log).unwrap_or_default();
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
            !chown.contains(":/home/step"),
            "the chown must not mount the secrets directory, got: {chown}"
        );
        assert!(
            create.contains("certificate create"),
            "the second container must be the certificate write, got: {create}"
        );
    }

    /// A failed chown aborts the issuance under the HTTP-01 admin TLS
    /// error, before the certificate write runs into the very
    /// `permission denied` the chown exists to prevent.
    #[test]
    fn issuance_aborts_when_the_chown_fails() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker_exiting(&fake, &args_log, 1);

        let secrets_dir = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets_dir).unwrap();

        let messages = crate::i18n::test_messages();
        let error = issue_http01_admin_tls_cert(
            &fs_util::SecretsTree::open(&secrets_dir).expect("open"),
            &["localhost"],
            &fake,
            &messages,
        )
        .expect_err("a failing chown must fail the issuance");
        let chain = format!("{error:#}");
        assert!(
            chain.contains(messages.error_http01_admin_tls_provision_failed()),
            "the chown failure must be reported as a failed issuance, got: {chain}"
        );

        let log = std::fs::read_to_string(&args_log).unwrap_or_default();
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

    /// A symlink at the output directory would relocate both the root
    /// chown and the key write to its target, so it is refused before
    /// any container runs.
    #[test]
    fn issuance_refuses_a_symlinked_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("fake-docker");
        let args_log = dir.path().join("docker_args.log");
        write_self_contained_fake_docker(&fake, &args_log);

        let secrets_dir = dir.path().join("secrets");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
        std::fs::create_dir_all(tls_dir.parent().expect("responder dir")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &tls_dir).unwrap();

        let messages = crate::i18n::test_messages();
        let error = issue_http01_admin_tls_cert(
            &fs_util::SecretsTree::open(&secrets_dir).expect("open"),
            &["localhost"],
            &fake,
            &messages,
        )
        .expect_err("a symlinked output directory must fail the issuance");
        let chain = format!("{error:#}");
        assert!(
            chain.contains(
                &messages.error_http01_admin_tls_output_dir_symlink(&tls_dir.display().to_string())
            ),
            "the error must name the refused HTTP-01 admin output path, got: {chain}"
        );

        let log = std::fs::read_to_string(&args_log).unwrap_or_default();
        assert!(
            log.trim().is_empty(),
            "nothing may be mounted for a symlinked output directory, got: {log}"
        );
        assert!(elsewhere.read_dir().unwrap().next().is_none());
    }

    #[test]
    fn build_sans_wildcard_adds_loopback() {
        let sans = build_http01_admin_tls_sans("0.0.0.0:8080", None, DEFAULT_RESPONDER_CONTAINER);
        assert!(sans.contains(&"127.0.0.1".to_string()));
        assert!(!sans.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_sans_wildcard_with_advertise_addr() {
        let sans = build_http01_admin_tls_sans(
            "0.0.0.0:8080",
            Some("192.168.1.10:8080"),
            DEFAULT_RESPONDER_CONTAINER,
        );
        assert!(
            sans.contains(&"192.168.1.10".to_string()),
            "advertise addr IP must be included in SANs"
        );
        assert!(
            sans.contains(&"127.0.0.1".to_string()),
            "loopback must still be present for wildcard"
        );
        assert!(!sans.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_sans_ipv6_wildcard_with_advertise_addr() {
        let sans = build_http01_admin_tls_sans(
            "[::]:8080",
            Some("[fd12::1]:8080"),
            DEFAULT_RESPONDER_CONTAINER,
        );
        assert!(
            sans.contains(&"fd12::1".to_string()),
            "advertise addr IPv6 must be included in SANs"
        );
        assert!(sans.contains(&"::1".to_string()));
        assert!(sans.contains(&"127.0.0.1".to_string()));
    }

    #[test]
    fn build_sans_advertise_addr_dedup() {
        let sans = build_http01_admin_tls_sans(
            "192.168.1.10:8080",
            Some("192.168.1.10:8080"),
            DEFAULT_RESPONDER_CONTAINER,
        );
        let count = sans.iter().filter(|s| *s == "192.168.1.10").count();
        assert_eq!(count, 1, "duplicate SANs must not be added");
    }

    #[test]
    fn build_sans_ipv6_specific() {
        let sans = build_http01_admin_tls_sans("[fd12::1]:8080", None, DEFAULT_RESPONDER_CONTAINER);
        assert!(sans.contains(&"fd12::1".to_string()));
    }

    #[test]
    fn build_sans_ipv6_wildcard() {
        let sans = build_http01_admin_tls_sans("[::]:8080", None, DEFAULT_RESPONDER_CONTAINER);
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
        let sans = build_http01_admin_tls_sans("[::0]:8080", None, DEFAULT_RESPONDER_CONTAINER);
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
    fn record_http01_admin_infra_cert_inserts_entry() {
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
        let sans = vec!["responder.internal".to_string(), "localhost".to_string()];
        record_http01_admin_infra_cert(&mut state, dir.path(), sans, "insight-http01");
        assert!(state.infra_certs.contains_key(HTTP01_ADMIN_INFRA_CERT_KEY));
        let entry = &state.infra_certs[HTTP01_ADMIN_INFRA_CERT_KEY];
        assert_eq!(
            entry.reload_strategy,
            ReloadStrategy::ContainerSignal {
                container_name: "insight-http01".to_string(),
                signal: "SIGHUP".to_string(),
            }
        );
        assert!(entry.issued_at.is_some());
    }

    #[test]
    fn strip_responder_tls_config_removes_tls_lines() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let config_dir = secrets_dir.join(RESPONDER_CONFIG_DIR);
        let template_dir = secrets_dir.join(RESPONDER_TEMPLATE_DIR);
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&template_dir).unwrap();

        let config_with_tls = "\
listen_addr = \"0.0.0.0:80\"\n\
admin_addr = \"0.0.0.0:8080\"\n\
hmac_secret = \"test-hmac\"\n\
tls_cert_path = \"/app/bootroot-http01/tls/server.crt\"\n\
tls_key_path = \"/app/bootroot-http01/tls/server.key\"\n";

        std::fs::write(config_dir.join(RESPONDER_CONFIG_NAME), config_with_tls).unwrap();
        std::fs::write(template_dir.join(RESPONDER_TEMPLATE_NAME), config_with_tls).unwrap();

        let messages = crate::i18n::test_messages();
        strip_responder_tls_config(
            &fs_util::SecretsTree::open(&secrets_dir).expect("open"),
            &messages,
        )
        .unwrap();

        let config = std::fs::read_to_string(config_dir.join(RESPONDER_CONFIG_NAME)).unwrap();
        let template = std::fs::read_to_string(template_dir.join(RESPONDER_TEMPLATE_NAME)).unwrap();

        assert!(
            !config.contains("tls_cert_path"),
            "tls_cert_path must be removed from config: {config}"
        );
        assert!(
            !config.contains("tls_key_path"),
            "tls_key_path must be removed from config: {config}"
        );
        assert!(
            config.contains("hmac_secret"),
            "non-TLS fields must be preserved: {config}"
        );
        assert!(
            !template.contains("tls_cert_path"),
            "tls_cert_path must be removed from template: {template}"
        );
    }

    #[test]
    fn strip_responder_tls_config_noop_without_files() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let messages = crate::i18n::test_messages();
        strip_responder_tls_config(
            &fs_util::SecretsTree::open(&secrets_dir).expect("open"),
            &messages,
        )
        .unwrap();
    }

    #[test]
    fn strip_responder_tls_config_noop_without_tls_lines() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let config_dir = secrets_dir.join(RESPONDER_CONFIG_DIR);
        std::fs::create_dir_all(&config_dir).unwrap();

        let config_no_tls = "\
listen_addr = \"0.0.0.0:80\"\n\
admin_addr = \"0.0.0.0:8080\"\n\
hmac_secret = \"test-hmac\"\n";

        let config_path = config_dir.join(RESPONDER_CONFIG_NAME);
        std::fs::write(&config_path, config_no_tls).unwrap();

        let messages = crate::i18n::test_messages();
        strip_responder_tls_config(
            &fs_util::SecretsTree::open(&secrets_dir).expect("open"),
            &messages,
        )
        .unwrap();

        let after = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(after, config_no_tls, "file must not be modified");
    }
}
