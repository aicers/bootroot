use std::fmt::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::db::DB_COMPOSE_HOST;
use bootroot::fs_util;

use super::openbao_tls::{TLS_OUTPUT_MOUNT, chown_tls_output_dir, reject_symlinked_tls_output_dir};
use crate::commands::compose_project::{ComposeIdentity, ComposeInvocation};
use crate::commands::infra::{run_compose, run_docker_with_exec};
use crate::commands::init::{
    CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, OPENBAO_TLS_DEFAULT_NOT_AFTER,
    OPENBAO_TLS_DEFAULT_RENEW_BEFORE, POSTGRES_HBA_CONF_PATH, POSTGRES_INFRA_CERT_KEY,
    POSTGRES_TLS_CERT_PATH, POSTGRES_TLS_COMPOSE_OVERRIDE_DIR, POSTGRES_TLS_COMPOSE_OVERRIDE_NAME,
    POSTGRES_TLS_DIR, POSTGRES_TLS_KEY_PATH,
};
use crate::commands::rotate::STEP_CA_HELPER_IMAGE;
use crate::i18n::Messages;
use crate::state::{InfraCertEntry, ReloadStrategy, StateFile};

/// The owner the private key is handed to: uid 999, the `postgres` user
/// of the Debian-based official image, and group 0.
///
/// `PostgreSQL` accepts a key its own user owns only with no group or
/// world access. Group 0 grants nothing at `0600` and keeps the file out
/// of any host group: on Ubuntu hosts gid 999 often belongs to one, such
/// as `systemd-journal`, whose members a key in that group would admit
/// should its mode ever be widened.
const POSTGRES_TLS_KEY_OWNER: &str = "999:0";

/// Mode of the output directory, so the container's `postgres` user can
/// traverse it.
const POSTGRES_TLS_DIR_MODE: u32 = 0o755;
/// Mode of the certificate and its chain, which are public.
const POSTGRES_TLS_CERT_MODE: u32 = 0o644;
/// Mode of the private key, unlike the deliberate `0644` of the other
/// offline infra keys: `PostgreSQL` refuses to start on anything wider
/// for a key its own user owns.
const POSTGRES_TLS_KEY_MODE: u32 = 0o600;

/// Signal that reloads `PostgreSQL`'s certificate files and keeps its
/// open sessions.
const POSTGRES_RELOAD_SIGNAL: &str = "SIGHUP";

/// Mode of `pg_hba.conf`: the server reads it as uid 999, which does not
/// own it, and it holds no secret.
const POSTGRES_HBA_CONF_MODE: u32 = 0o644;
/// Where the container sees the certificate directory.
const POSTGRES_TLS_CONTAINER_DIR: &str = "/tls";
/// Where the container sees `pg_hba.conf`; outside `PGDATA`, so nothing
/// is written into the data volume.
const POSTGRES_HBA_CONTAINER_PATH: &str = "/etc/postgresql/pg_hba.conf";

/// The server's command line under the override: TLS 1.3 only, with
/// the hybrid post-quantum group alone, on the certificate `init` issues
/// and with bootroot's `pg_hba.conf`. `PostgreSQL` 18 offers
/// `X25519:prime256v1` unless told otherwise.
const POSTGRES_TLS_SETTINGS: [&str; 6] = [
    "ssl=on",
    "ssl_cert_file=/tls/server.crt",
    "ssl_key_file=/tls/server.key",
    "ssl_min_protocol_version=TLSv1.3",
    "ssl_groups=X25519MLKEM768",
    "hba_file=/etc/postgresql/pg_hba.conf",
];

/// `pg_hba.conf`: the Unix socket inside the container stays `trust`, as
/// in the image's own default, so its init scripts and `docker compose
/// exec postgres psql` keep working; every TCP connection must be TLS and
/// authenticate with `scram-sha-256`, and plaintext TCP is rejected.
const POSTGRES_HBA_CONF: &str = "\
local     all  all        trust
hostssl   all  all  all   scram-sha-256
host      all  all  all   reject
";

/// Builds the SANs list for the `PostgreSQL` TLS certificate: the compose
/// service name alone.
///
/// step-ca's stored DSN names that host, and bootroot's own connections
/// verify that name while dialling the published loopback port. No
/// `localhost` or `127.0.0.1`: the `OpenBao` certificate already carries
/// those names, so they would let it pass for `PostgreSQL` on loopback.
pub(in crate::commands::init) fn build_postgres_tls_sans() -> Vec<String> {
    vec![DB_COMPOSE_HOST.to_string()]
}

/// Issues the `PostgreSQL` TLS server certificate, signed by the local
/// step-ca intermediate CA, and hands its key to the server's user.
///
/// Writes `compose_dir/postgres/tls/server.{crt,key}`. The directory is
/// outside `secrets/` because the ownership sweep holds that tree
/// operator-owned, and `PostgreSQL` refuses a key it does not own. The
/// certificate is bundled with the intermediate: `PostgreSQL` sends the
/// whole file as its chain, and its clients anchor on the root alone.
///
/// Every issuance runs the same way, because a previous one left the key
/// owned by uid 999: the directory goes back to the secrets-directory
/// owner first, so `step`, running as that owner, can overwrite the key.
///
/// # Errors
///
/// Returns an error when the output directory is a symlink or cannot be
/// created, when one of the helper containers fails, or when a mode
/// cannot be set.
pub(crate) fn issue_postgres_tls_cert(
    compose_dir: &Path,
    secrets_dir: &Path,
    docker: &Path,
    messages: &Messages,
) -> Result<()> {
    let tls_dir = compose_dir.join(POSTGRES_TLS_DIR);
    let cert_path = compose_dir.join(POSTGRES_TLS_CERT_PATH);
    let key_path = compose_dir.join(POSTGRES_TLS_KEY_PATH);

    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let secrets_mount = format!("{}:/home/step", mount_root.display());
    let meta = std::fs::metadata(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let user_arg = format!("{}:{}", meta.uid(), meta.gid());

    reject_symlinked_tls_output_dir(
        &tls_dir,
        |path| messages.error_postgres_tls_output_dir_symlink(path),
        messages,
    )?;
    let parent = tls_dir.parent().filter(|parent| !parent.exists());
    std::fs::create_dir_all(&tls_dir)
        .with_context(|| messages.error_write_file_failed(&tls_dir.display().to_string()))?;
    if let Some(parent) = parent {
        own_new_parent_dir(parent, meta.uid(), meta.gid())?;
    }
    let tls_mount_root = std::fs::canonicalize(&tls_dir)
        .with_context(|| messages.error_resolve_path_failed(&tls_dir.display().to_string()))?;
    let tls_mount = format!("{}:{TLS_OUTPUT_MOUNT}", tls_mount_root.display());

    chown_tls_output_dir(
        &tls_mount,
        &user_arg,
        docker,
        "docker postgres tls output chown",
        messages.error_postgres_tls_provision_failed(),
        messages,
    )?;
    // After the chown and not before: a directory left behind by a
    // previous secrets owner belongs to this process only once the chown
    // has run, and until then a non-root bootroot may not change its mode.
    std::fs::set_permissions(
        &tls_dir,
        std::fs::Permissions::from_mode(POSTGRES_TLS_DIR_MODE),
    )
    .with_context(|| format!("Failed to set permissions on {}", tls_dir.display()))?;

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
        DB_COMPOSE_HOST,
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
    let sans = build_postgres_tls_sans();
    for san in &sans {
        args.push("--san");
        args.push(san);
    }
    args.extend([
        "--bundle",
        "--not-after",
        OPENBAO_TLS_DEFAULT_NOT_AFTER,
        "--force",
    ]);
    run_docker_with_exec(
        &args,
        "docker step certificate create (postgres tls)",
        docker,
        messages,
    )
    .with_context(|| messages.error_postgres_tls_provision_failed())?;

    set_postgres_tls_file_modes(&cert_path, &key_path)?;

    run_docker_with_exec(
        &build_postgres_key_chown_args(&tls_mount, &output_key, STEP_CA_HELPER_IMAGE),
        "docker postgres tls key chown",
        docker,
        messages,
    )
    .with_context(|| messages.error_postgres_tls_provision_failed())?;

    println!(
        "{}",
        messages.info_postgres_tls_provisioned(&cert_path.display().to_string())
    );
    Ok(())
}

/// Sets the certificate to `0644` and the key to `0600`, while the
/// secrets-directory owner still owns both.
///
/// `step` already writes the key `0600`; it is set here so the mode the
/// server depends on does not rest on `step`'s default.
fn set_postgres_tls_file_modes(cert_path: &Path, key_path: &Path) -> Result<()> {
    std::fs::set_permissions(
        cert_path,
        std::fs::Permissions::from_mode(POSTGRES_TLS_CERT_MODE),
    )
    .with_context(|| format!("Failed to set permissions on {}", cert_path.display()))?;
    std::fs::set_permissions(
        key_path,
        std::fs::Permissions::from_mode(POSTGRES_TLS_KEY_MODE),
    )
    .with_context(|| format!("Failed to set permissions on {}", key_path.display()))
}

/// Gives a `postgres/` directory this issuance has just created to the
/// secrets-directory owner.
///
/// `chown_tls_output_dir` reaches only `postgres/tls`, the mount it is
/// given. When bootroot runs as root, `create_dir_all` leaves the parent
/// root-owned, and the operator's `bootroot clean` could then remove the
/// directory's contents but not `postgres/tls` itself. Otherwise this
/// process is that owner already, and there is nothing to change.
fn own_new_parent_dir(parent: &Path, uid: u32, gid: u32) -> Result<()> {
    let current = std::fs::metadata(parent)
        .with_context(|| format!("Failed to read metadata of {}", parent.display()))?;
    if current.uid() == uid {
        return Ok(());
    }
    std::os::unix::fs::chown(parent, Some(uid), Some(gid))
        .with_context(|| format!("Failed to set owner of {}", parent.display()))
}

/// Builds the `docker run` argv that hands the private key to
/// `PostgreSQL`'s user.
///
/// Kept pure so tests can assert it mounts ONLY the output directory and
/// uses `--no-dereference`, like the output-directory chown it mirrors.
/// `chown` keeps the `0600` mode.
fn build_postgres_key_chown_args<'a>(mount: &'a str, key: &'a str, image: &'a str) -> Vec<&'a str> {
    vec![
        "run",
        "--rm",
        // Intentional root: only root can chown to an arbitrary uid.
        "--user",
        "root",
        // Run `chown` directly: the image's default entrypoint warns
        // about a `ca.json` this container deliberately does not mount.
        "--entrypoint",
        "chown",
        "-v",
        mount,
        image,
        "--no-dereference",
        POSTGRES_TLS_KEY_OWNER,
        key,
    ]
}

/// Records the `PostgreSQL` TLS certificate in `StateFile::infra_certs`.
///
/// The paths are absolute, from the compose directory canonicalized as
/// the issuance does for its mount. The recorded `sans` are informational:
/// a renewal issues with [`build_postgres_tls_sans`].
///
/// # Errors
///
/// Returns an error when the compose directory cannot be resolved.
pub(in crate::commands::init) fn record_postgres_infra_cert(
    state: &mut StateFile,
    compose_dir: &Path,
    postgres_container: &str,
    messages: &Messages,
) -> Result<()> {
    let compose_root = std::fs::canonicalize(compose_dir)
        .with_context(|| messages.error_resolve_path_failed(&compose_dir.display().to_string()))?;

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let entry = InfraCertEntry {
        cert_path: compose_root.join(POSTGRES_TLS_CERT_PATH),
        key_path: compose_root.join(POSTGRES_TLS_KEY_PATH),
        sans: build_postgres_tls_sans(),
        renew_before: OPENBAO_TLS_DEFAULT_RENEW_BEFORE.to_string(),
        reload_strategy: ReloadStrategy::ContainerSignal {
            container_name: postgres_container.to_string(),
            signal: POSTGRES_RELOAD_SIGNAL.to_string(),
        },
        issued_at: Some(now),
        expires_at: None,
    };

    state
        .infra_certs
        .insert(POSTGRES_INFRA_CERT_KEY.to_string(), entry);
    Ok(())
}

/// Writes `<compose dir>/postgres/pg_hba.conf` and the compose override
/// that starts `PostgreSQL` with its TLS settings, returning the
/// override's path.
///
/// The override, `<secrets dir>/postgres/docker-compose.postgres-tls.yml`,
/// carries the server's command line and mounts the certificate
/// directory [`issue_postgres_tls_cert`] fills and `pg_hba.conf`, by
/// absolute host paths. Both files are rewritten on every `init`, and
/// published by rename without a flush: `init` regenerates them.
///
/// # Errors
///
/// Returns an error when the compose directory cannot be resolved, or
/// either file or the override's directory cannot be written.
pub(in crate::commands::init) async fn write_postgres_tls_files(
    compose_dir: &Path,
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<PathBuf> {
    let hba_path = compose_dir.join(POSTGRES_HBA_CONF_PATH);
    // `PreserveOrUmask` would leave the file `0600` under a `077` umask,
    // which uid 999 cannot read.
    fs_util::atomic_replace(
        fs_util::Destination::operator_named(&hba_path),
        POSTGRES_HBA_CONF.as_bytes(),
        fs_util::StagedMode::Policy(POSTGRES_HBA_CONF_MODE),
    )
    .await
    .with_context(|| messages.error_write_file_failed(&hba_path.display().to_string()))?;

    let compose_root = std::fs::canonicalize(compose_dir)
        .with_context(|| messages.error_resolve_path_failed(&compose_dir.display().to_string()))?;
    let override_dir = secrets_dir.join(POSTGRES_TLS_COMPOSE_OVERRIDE_DIR);
    fs_util::ensure_shared_secrets_dir(&override_dir).await?;
    let override_path = override_dir.join(POSTGRES_TLS_COMPOSE_OVERRIDE_NAME);
    // The same three decisions as the responder override: published by
    // rename, not flushed, at the destination's mode or the umask's
    // answer on a create.
    fs_util::atomic_replace(
        fs_util::Destination::operator_named(&override_path),
        postgres_tls_override_contents(&compose_root).as_bytes(),
        fs_util::StagedMode::PreserveOrUmask,
    )
    .await
    .with_context(|| messages.error_write_file_failed(&override_path.display().to_string()))?;

    println!(
        "{}",
        messages.info_postgres_tls_config_written(
            &override_path.display().to_string(),
            &hba_path.display().to_string(),
        )
    );
    Ok(override_path)
}

/// Builds the override's contents for a canonical compose directory.
///
/// The `volumes` entries merge with the base file's `postgres-data`
/// mount; `command` replaces the image's default.
fn postgres_tls_override_contents(compose_root: &Path) -> String {
    let mut contents =
        format!("services:\n  {DB_COMPOSE_HOST}:\n    command:\n      - \"postgres\"\n");
    for setting in POSTGRES_TLS_SETTINGS {
        let _ = write!(contents, "      - \"-c\"\n      - \"{setting}\"\n");
    }
    let _ = write!(
        contents,
        "    volumes:\n      - \"{tls}:{POSTGRES_TLS_CONTAINER_DIR}:ro\"\n      - \"{hba}:{POSTGRES_HBA_CONTAINER_PATH}:ro\"\n",
        tls = compose_root.join(POSTGRES_TLS_DIR).display(),
        hba = compose_root.join(POSTGRES_HBA_CONF_PATH).display(),
    );
    contents
}

/// Builds the invocation that recreates `PostgreSQL` with its TLS
/// override: `-f <compose file> -f <override> up -d --no-deps
/// --force-recreate postgres`, under the install's project.
///
/// `--force-recreate` so a re-run of `init`, and `reinit`, load a
/// re-issued leaf even when Compose sees no change in the service;
/// `--no-deps` so no other service is touched with a file set that
/// lacks its own overrides.
fn postgres_tls_recreate_invocation(
    identity: &ComposeIdentity,
    compose_file: &Path,
    override_path: &Path,
) -> ComposeInvocation {
    identity.compose(
        &[
            &compose_file.to_string_lossy(),
            &override_path.to_string_lossy(),
        ],
        None,
        &["up", "-d", "--no-deps", "--force-recreate", DB_COMPOSE_HOST],
    )
}

/// Recreates `PostgreSQL` with its TLS override.
///
/// # Errors
///
/// Returns an error when `docker compose` fails.
pub(in crate::commands::init) fn recreate_postgres_with_tls(
    identity: &ComposeIdentity,
    compose_file: &Path,
    override_path: &Path,
    messages: &Messages,
) -> Result<()> {
    run_compose(
        &postgres_tls_recreate_invocation(identity, compose_file, override_path),
        "docker compose up -d --force-recreate postgres (tls)",
        messages,
    )
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::test_support::{test_messages, write_self_contained_fake_docker_exiting};
    use super::*;
    use crate::commands::compose_project::DOCKER_COMPOSE_SUBCOMMAND;
    use crate::test_support::write_executable;

    /// A compose and a secrets directory under `base`, as `init` finds
    /// them, and the output directory the issuance writes into.
    fn issuance_dirs(base: &Path) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let compose_dir = base.join("compose");
        let secrets_dir = base.join("secrets");
        fs::create_dir_all(&compose_dir).unwrap();
        fs::create_dir_all(&secrets_dir).unwrap();
        let tls_dir = compose_dir.join(POSTGRES_TLS_DIR);
        (compose_dir, secrets_dir, tls_dir)
    }

    /// Writes a fake `docker` that logs one line of argv per invocation
    /// and, under it, the `ls -ld` of the output directory and its files
    /// as that invocation found them, then acts like `step certificate
    /// create` by writing both files `0600`.
    ///
    /// The modes are read from inside the fake because that is the only
    /// way to tell a mode set before the key's chown from one set after.
    fn write_mode_logging_fake(path: &Path, log: &Path, tls_dir: &Path) {
        let (log, tls) = (log.display(), tls_dir.display());
        let script = format!(
            r#"#!/bin/sh
set -eu
printf 'argv %s\n' "$*" >> '{log}'
ls -ld '{tls}' >> '{log}'
ls -ld '{tls}/server.crt' '{tls}/server.key' >> '{log}' 2>/dev/null || true
case "$*" in
  *"certificate create"*)
    : > '{tls}/server.crt'
    : > '{tls}/server.key'
    chmod 600 '{tls}/server.crt' '{tls}/server.key'
    ;;
esac
"#
        );
        write_executable(path, script.as_bytes());
    }

    /// The log's records, one per invocation: the argv line, then the
    /// `ls -ld` lines that followed it.
    fn invocation_records(log: &str) -> Vec<String> {
        log.split("argv ")
            .filter(|record| !record.is_empty())
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn sans_are_the_compose_service_name_alone() {
        assert_eq!(build_postgres_tls_sans(), vec!["postgres".to_string()]);
    }

    /// The whole contract of the issuance, in order: the directory goes
    /// back to the secrets owner as root, `step` writes as that owner,
    /// and only then, with both modes set, does the key go to uid 999.
    #[test]
    fn issuance_runs_chown_create_then_key_chown() {
        let dir = tempfile::tempdir().unwrap();
        let (compose_dir, secrets_dir, tls_dir) = issuance_dirs(dir.path());
        let fake = dir.path().join("fake-docker");
        let log_path = dir.path().join("docker.log");
        write_mode_logging_fake(&fake, &log_path, &tls_dir);
        // A directory from a previous issuance whose mode has to be set.
        fs::create_dir_all(&tls_dir).unwrap();
        fs::set_permissions(&tls_dir, fs::Permissions::from_mode(0o700)).unwrap();

        issue_postgres_tls_cert(&compose_dir, &secrets_dir, &fake, &test_messages())
            .expect("the issuance must succeed against the fake docker");

        let log = fs::read_to_string(&log_path).unwrap();
        let records = invocation_records(&log);
        assert_eq!(records.len(), 3, "expected three containers, got: {log}");

        let meta = fs::metadata(&secrets_dir).unwrap();
        let owner = format!("{}:{}", meta.uid(), meta.gid());
        let mount = format!(
            "{}:{TLS_OUTPUT_MOUNT}",
            fs::canonicalize(&tls_dir).unwrap().display()
        );

        let chown = records.first().unwrap();
        let chown_argv = chown.lines().next().unwrap();
        assert!(
            chown_argv.contains("--user root --entrypoint chown")
                && chown_argv.contains(&format!("-R --no-dereference {owner} {TLS_OUTPUT_MOUNT}"))
                && chown_argv.contains(&mount),
            "the first container must re-own the output directory as root: {chown_argv}"
        );
        assert!(
            chown.lines().nth(1).unwrap().starts_with("drwx------"),
            "the directory's mode must not be set before the chown, which is what lets a \
             non-root bootroot change a directory a previous owner left: {chown}"
        );

        let create = records.get(1).unwrap();
        let create_argv = create.lines().next().unwrap();
        assert!(
            create_argv.contains(&format!("--user {owner} "))
                && create_argv
                    .contains("certificate create postgres /output/server.crt /output/server.key")
                && create_argv.contains("--ca /home/step/certs/intermediate_ca.crt")
                && create_argv.contains("--ca-key /home/step/secrets/intermediate_ca_key")
                && create_argv.contains("--ca-password-file /home/step/password.txt")
                && create_argv.contains("--no-password --insecure")
                && create_argv.contains("--bundle --not-after 8760h --force"),
            "the second container must be the certificate write: {create_argv}"
        );
        assert_eq!(
            create_argv.matches("--san").count(),
            1,
            "exactly one SAN: {create_argv}"
        );
        assert!(
            create_argv.contains("--san postgres "),
            "the SAN must be postgres: {create_argv}"
        );

        let key_chown = records.get(2).unwrap();
        let key_chown_argv = key_chown.lines().next().unwrap().trim_end();
        assert_eq!(
            key_chown_argv,
            format!(
                "run --rm --user root --entrypoint chown -v {mount} {STEP_CA_HELPER_IMAGE} \
                 --no-dereference 999:0 {TLS_OUTPUT_MOUNT}/server.key"
            ),
            "the third container must hand over the key and mount nothing else"
        );
        let modes: Vec<&str> = key_chown.lines().skip(1).collect();
        assert!(
            modes.iter().any(|line| line.starts_with("drwxr-xr-x")),
            "the directory is 0755 by the key's chown: {modes:?}"
        );
        assert!(
            modes
                .iter()
                .any(|line| line.starts_with("-rw-r--r--") && line.ends_with("server.crt")),
            "server.crt is 0644 before the key's chown: {modes:?}"
        );
        assert!(
            modes
                .iter()
                .any(|line| line.starts_with("-rw-------") && line.ends_with("server.key")),
            "server.key is 0600 before the key's chown: {modes:?}"
        );

        let mode_of = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode_of(&tls_dir), 0o755);
        assert_eq!(mode_of(&tls_dir.join("server.crt")), 0o644);
        assert_eq!(mode_of(&tls_dir.join("server.key")), 0o600);
    }

    /// The key's mode is set by bootroot and does not rest on `step`'s
    /// default, so a key left wider than `0600` does not stay that way.
    #[test]
    fn issuance_narrows_a_wider_key() {
        let dir = tempfile::tempdir().unwrap();
        let (compose_dir, secrets_dir, tls_dir) = issuance_dirs(dir.path());
        let fake = dir.path().join("fake-docker");
        let log = dir.path().join("docker.log");
        write_self_contained_fake_docker_exiting(&fake, &log, 0);
        fs::create_dir_all(&tls_dir).unwrap();
        let key = tls_dir.join("server.key");
        fs::write(tls_dir.join("server.crt"), "cert").unwrap();
        fs::write(&key, "key").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();

        issue_postgres_tls_cert(&compose_dir, &secrets_dir, &fake, &test_messages()).unwrap();

        assert_eq!(
            fs::metadata(&key).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    /// A helper that failed aborts with the issuance's own error, and
    /// nothing runs after it.
    #[test]
    fn a_failing_helper_aborts_with_the_issuance_error() {
        let dir = tempfile::tempdir().unwrap();
        let (compose_dir, secrets_dir, _) = issuance_dirs(dir.path());
        let fake = dir.path().join("fake-docker");
        let log = dir.path().join("docker.log");
        write_self_contained_fake_docker_exiting(&fake, &log, 1);
        let messages = test_messages();

        let error = issue_postgres_tls_cert(&compose_dir, &secrets_dir, &fake, &messages)
            .expect_err("a failing helper must fail the issuance");

        let chain = format!("{error:#}");
        assert!(
            chain.contains(messages.error_postgres_tls_provision_failed()),
            "the failure must be reported as a failed issuance, got: {chain}"
        );
        assert_eq!(fs::read_to_string(&log).unwrap().lines().count(), 1);
    }

    /// A key chown that failed is still the issuance failing: a key left
    /// with the secrets owner is one `PostgreSQL` refuses to start on.
    #[test]
    fn a_failing_key_chown_aborts_with_the_issuance_error() {
        let dir = tempfile::tempdir().unwrap();
        let (compose_dir, secrets_dir, tls_dir) = issuance_dirs(dir.path());
        fs::create_dir_all(&tls_dir).unwrap();
        fs::write(tls_dir.join("server.crt"), "cert").unwrap();
        fs::write(tls_dir.join("server.key"), "key").unwrap();
        let fake = dir.path().join("fake-docker");
        let script = "#!/bin/sh\ncase \"$*\" in *999:0*) exit 1 ;; esac\n";
        write_executable(&fake, script.as_bytes());
        let messages = test_messages();

        let error = issue_postgres_tls_cert(&compose_dir, &secrets_dir, &fake, &messages)
            .expect_err("a failing key chown must fail the issuance");

        let chain = format!("{error:#}");
        assert!(
            chain.contains(messages.error_postgres_tls_provision_failed()),
            "the failure must be reported as a failed issuance, got: {chain}"
        );
    }

    /// `canonicalize` resolves the final component, so a symlink at
    /// `postgres/tls` would move both the chown and the private key onto
    /// its target.
    #[test]
    fn a_symlinked_output_dir_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let (compose_dir, secrets_dir, tls_dir) = issuance_dirs(dir.path());
        let fake = dir.path().join("fake-docker");
        let log = dir.path().join("docker.log");
        write_self_contained_fake_docker_exiting(&fake, &log, 0);
        let elsewhere = dir.path().join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::create_dir_all(tls_dir.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &tls_dir).unwrap();
        let messages = test_messages();

        let error = issue_postgres_tls_cert(&compose_dir, &secrets_dir, &fake, &messages)
            .expect_err("a symlinked output directory must fail the issuance");

        assert_eq!(
            error.to_string(),
            messages.error_postgres_tls_output_dir_symlink(&tls_dir.display().to_string())
        );
        assert!(!log.exists(), "nothing may be mounted for a symlink");
        assert!(elsewhere.read_dir().unwrap().next().is_none());
    }

    #[test]
    fn record_carries_the_entry_for_an_instance_scoped_container() {
        let dir = tempfile::tempdir().unwrap();
        let compose_root = fs::canonicalize(dir.path()).unwrap();
        let mut state = StateFile::default();

        record_postgres_infra_cert(&mut state, dir.path(), "insight-postgres", &test_messages())
            .unwrap();

        let entry = state.infra_certs.get(POSTGRES_INFRA_CERT_KEY).unwrap();
        assert_eq!(POSTGRES_INFRA_CERT_KEY, "postgres");
        assert_eq!(
            entry.cert_path,
            compose_root.join("postgres/tls/server.crt")
        );
        assert_eq!(entry.key_path, compose_root.join("postgres/tls/server.key"));
        assert_eq!(entry.sans, vec!["postgres".to_string()]);
        assert_eq!(entry.renew_before, "720h");
        assert_eq!(
            entry.reload_strategy,
            ReloadStrategy::ContainerSignal {
                container_name: "insight-postgres".to_string(),
                signal: "SIGHUP".to_string(),
            }
        );
        assert!(entry.issued_at.is_some());
        assert!(entry.expires_at.is_none());
    }

    /// A relative compose directory is what `--compose-file
    /// docker-compose.yml` gives; what is recorded is absolute regardless.
    #[test]
    fn record_paths_are_absolute_for_a_relative_compose_dir() {
        let mut state = StateFile::default();
        record_postgres_infra_cert(&mut state, Path::new("."), "c", &test_messages()).unwrap();
        let entry = state.infra_certs.get(POSTGRES_INFRA_CERT_KEY).unwrap();
        assert!(entry.cert_path.is_absolute());
        assert!(entry.key_path.is_absolute());
    }

    /// The exact override: absolute paths from the canonical compose
    /// directory, and every setting of the server's command line.
    #[test]
    fn the_override_carries_the_command_and_both_mounts() {
        let contents = postgres_tls_override_contents(Path::new("/srv/bootroot"));
        assert_eq!(
            contents,
            "\
services:
  postgres:
    command:
      - \"postgres\"
      - \"-c\"
      - \"ssl=on\"
      - \"-c\"
      - \"ssl_cert_file=/tls/server.crt\"
      - \"-c\"
      - \"ssl_key_file=/tls/server.key\"
      - \"-c\"
      - \"ssl_min_protocol_version=TLSv1.3\"
      - \"-c\"
      - \"ssl_groups=X25519MLKEM768\"
      - \"-c\"
      - \"hba_file=/etc/postgresql/pg_hba.conf\"
    volumes:
      - \"/srv/bootroot/postgres/tls:/tls:ro\"
      - \"/srv/bootroot/postgres/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro\"
"
        );
    }

    /// Both files land where the override's mounts and `infra up` look
    /// for them; `pg_hba.conf` is `0644` whatever the umask, and the
    /// override passes the scope check `init` and `infra up` run.
    #[tokio::test]
    async fn writing_the_files_publishes_pg_hba_and_the_override() {
        let dir = tempfile::tempdir().unwrap();
        let (compose_dir, secrets_dir, tls_dir) = issuance_dirs(dir.path());
        fs::create_dir_all(&tls_dir).unwrap();
        let messages = test_messages();

        let override_path = write_postgres_tls_files(&compose_dir, &secrets_dir, &messages)
            .await
            .unwrap();

        assert_eq!(
            override_path,
            secrets_dir.join("postgres/docker-compose.postgres-tls.yml")
        );
        let compose_root = fs::canonicalize(&compose_dir).unwrap();
        assert_eq!(
            fs::read_to_string(&override_path).unwrap(),
            postgres_tls_override_contents(&compose_root)
        );
        let hba = compose_dir.join("postgres/pg_hba.conf");
        assert_eq!(
            fs::read_to_string(&hba).unwrap(),
            "\
local     all  all        trust
hostssl   all  all  all   scram-sha-256
host      all  all  all   reject
"
        );
        assert_eq!(
            fs::metadata(&hba).unwrap().permissions().mode() & 0o777,
            0o644
        );
        crate::commands::guardrails::validate_postgres_tls_override_scope(
            &override_path,
            &messages,
        )
        .expect("the generated override publishes no port");
    }

    /// A `pg_hba.conf` narrowed by hand is put back to `0644`, which the
    /// server needs to read it.
    #[tokio::test]
    async fn writing_the_files_resets_pg_hba_mode() {
        let dir = tempfile::tempdir().unwrap();
        let (compose_dir, secrets_dir, tls_dir) = issuance_dirs(dir.path());
        fs::create_dir_all(&tls_dir).unwrap();
        let hba = compose_dir.join("postgres/pg_hba.conf");
        fs::write(&hba, "stale").unwrap();
        fs::set_permissions(&hba, fs::Permissions::from_mode(0o600)).unwrap();

        write_postgres_tls_files(&compose_dir, &secrets_dir, &test_messages())
            .await
            .unwrap();

        assert_eq!(
            fs::metadata(&hba).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn the_recreate_applies_the_override_to_postgres_alone() {
        let identity = ComposeIdentity::for_instance("insight");
        let invocation = postgres_tls_recreate_invocation(
            &identity,
            Path::new("/srv/bootroot/docker-compose.yml"),
            Path::new("/srv/bootroot/secrets/postgres/docker-compose.postgres-tls.yml"),
        );
        let args: Vec<String> = invocation
            .command(&[])
            .get_args()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            [
                DOCKER_COMPOSE_SUBCOMMAND,
                "-f",
                "/srv/bootroot/docker-compose.yml",
                "-f",
                "/srv/bootroot/secrets/postgres/docker-compose.postgres-tls.yml",
                "-p",
                "insight",
                "up",
                "-d",
                "--no-deps",
                "--force-recreate",
                "postgres",
            ]
        );
    }
}
