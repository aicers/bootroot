//! The Docker Compose override files bootroot writes and passes to
//! `docker compose -f`, kept in one directory outside `secrets/`.
//!
//! Every override lives at `<compose dir>/compose-overrides/<file name>`,
//! where `<compose dir>` is the directory of the compose file the command
//! was handed. Nothing mounts that directory into a container, unlike
//! `secrets/`, which step-ca and both `OpenBao` Agent sidecars mount
//! read-write and which an installer may hand to another account. A root
//! process passes these paths to Compose by name, so the directory and
//! every file in it must be writable only by accounts that could already
//! change what root starts:
//!
//! - root;
//! - the process's effective uid;
//! - the owner of `<compose dir>`, which can already replace the compose
//!   file and the `.env` root passes to Compose.
//!
//! [`read`] is the only way a command obtains the path of an override it
//! did not just write. It checks `<compose dir>`, `compose-overrides/`
//! and the file through descriptors, refusing a link, a wrong type, an
//! untrusted owner and a group- or world-writable mode, and refuses a
//! `compose-overrides/` at or below the secrets directory. The guarantee
//! rests on `<compose dir>`'s parents being writable by no one outside
//! the trusted accounts; those are not checked.
//!
//! Releases up to `0.7.0` kept the overrides below `secrets/`. Nothing
//! is migrated and no old file is read: [`read`] only `lstat`s the old
//! location, when its caller asks it to, so that a command needing an
//! override that exists only there stops and says how to recreate it.

use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use rustix::fs::{AtFlags, FileType, Mode, OFlags, Stat};
use rustix::io::Errno;

use crate::commands::init::{
    HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME, OPENBAO_AGENT_COMPOSE_OVERRIDE_NAME,
    OPENBAO_AUDIT_COMPOSE_OVERRIDE_NAME, OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME,
    POSTGRES_TLS_COMPOSE_OVERRIDE_NAME, RESPONDER_COMPOSE_OVERRIDE_NAME,
    STEPCA_EXPOSED_COMPOSE_OVERRIDE_NAME,
};
use crate::i18n::Messages;
use crate::state::StateFile;

/// The directory, beside the compose file, that holds every override.
pub(crate) const COMPOSE_OVERRIDES_DIR: &str = "compose-overrides";

/// The mode `compose-overrides/` is created with, whatever the umask.
const DIR_MODE: u32 = 0o755;

/// The mode every override is published with, whatever the umask. The
/// files carry host paths and bind addresses and nothing secret.
const FILE_MODE: u32 = 0o644;

/// The permission bits that let anyone but the owner write.
const GROUP_OR_WORLD_WRITABLE: u32 = 0o022;

/// One of the overrides bootroot writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ComposeOverride {
    /// `infra install --openbao-bind`: `OpenBao`'s published port.
    OpenBaoExposed,
    /// `init` on a registrar endpoint host: `OpenBao`'s audit mount.
    OpenBaoAudit,
    /// `init`: the two `OpenBao` Agent sidecars.
    OpenBaoAgent,
    /// `infra install --http01-admin-bind`: the responder's admin port.
    Http01Exposed,
    /// `infra install --stepca-bind`: step-ca's published port.
    StepCaExposed,
    /// `init`: the responder's rendered configuration.
    Responder,
    /// `init`: `PostgreSQL`'s TLS settings and mounts.
    PostgresTls,
}

/// Where a `0.7.0` override was anchored.
enum LegacyAnchor {
    /// `<compose dir>/secrets`, whatever secrets directory was in use.
    ComposeSecrets,
    /// The secrets directory `state.json` or `--secrets-dir` named.
    SecretsDir,
}

impl ComposeOverride {
    /// Returns the override's file name, unchanged from earlier releases.
    #[must_use]
    pub(crate) fn file_name(self) -> &'static str {
        match self {
            Self::OpenBaoExposed => OPENBAO_EXPOSED_COMPOSE_OVERRIDE_NAME,
            Self::OpenBaoAudit => OPENBAO_AUDIT_COMPOSE_OVERRIDE_NAME,
            Self::OpenBaoAgent => OPENBAO_AGENT_COMPOSE_OVERRIDE_NAME,
            Self::Http01Exposed => HTTP01_EXPOSED_COMPOSE_OVERRIDE_NAME,
            Self::StepCaExposed => STEPCA_EXPOSED_COMPOSE_OVERRIDE_NAME,
            Self::Responder => RESPONDER_COMPOSE_OVERRIDE_NAME,
            Self::PostgresTls => POSTGRES_TLS_COMPOSE_OVERRIDE_NAME,
        }
    }

    /// Reports whether `infra install` writes this override from a bind
    /// option, as opposed to `init`.
    #[must_use]
    fn is_exposure(self) -> bool {
        matches!(
            self,
            Self::OpenBaoExposed | Self::Http01Exposed | Self::StepCaExposed
        )
    }

    /// The `0.7.0` location's anchor and the directory below it.
    fn legacy_location(self) -> (LegacyAnchor, &'static str) {
        match self {
            Self::OpenBaoExposed | Self::OpenBaoAudit => (LegacyAnchor::ComposeSecrets, "openbao"),
            Self::Http01Exposed => (LegacyAnchor::ComposeSecrets, "responder"),
            Self::StepCaExposed => (LegacyAnchor::ComposeSecrets, "step-ca"),
            Self::OpenBaoAgent => (LegacyAnchor::SecretsDir, "openbao"),
            Self::Responder => (LegacyAnchor::SecretsDir, "responder"),
            Self::PostgresTls => (LegacyAnchor::SecretsDir, "postgres"),
        }
    }

    /// Returns where `0.7.0` kept this override: below
    /// `<compose dir>/secrets` for the exposure and audit overrides, and
    /// below `secrets_dir` for the others.
    ///
    /// Used only to probe for a file the command will not read; see
    /// [`read`].
    #[must_use]
    pub(crate) fn legacy_path(self, compose_dir: &Path, secrets_dir: &Path) -> PathBuf {
        let (anchor, dir) = self.legacy_location();
        let base = match anchor {
            LegacyAnchor::ComposeSecrets => compose_dir.join("secrets"),
            LegacyAnchor::SecretsDir => secrets_dir.to_path_buf(),
        };
        base.join(dir).join(self.file_name())
    }
}

/// Returns the override's path below `compose_dir`, without checking it.
#[must_use]
pub(crate) fn path(compose_dir: &Path, which: ComposeOverride) -> PathBuf {
    overrides_dir(compose_dir).join(which.file_name())
}

/// Returns `compose_dir/compose-overrides`.
#[must_use]
pub(crate) fn overrides_dir(compose_dir: &Path) -> PathBuf {
    compose_dir.join(COMPOSE_OVERRIDES_DIR)
}

/// Returns the secrets directory `state` records, resolved against
/// `compose_dir` when relative: the directory an override read for that
/// deployment must not sit inside.
#[must_use]
pub(crate) fn recorded_secrets_dir(state: &StateFile, compose_dir: &Path) -> PathBuf {
    let secrets_dir = state.secrets_dir();
    if secrets_dir.is_absolute() {
        secrets_dir.to_path_buf()
    } else {
        compose_dir.join(secrets_dir)
    }
}

/// Publishes `content` as the override `which` below `compose_dir`, and
/// returns its path.
///
/// A missing `compose-overrides/` is created `0755` under the writing
/// process; an existing one must pass the owner, mode and type checks
/// [`read`] applies. The secrets-directory check is the command's, made
/// once through [`refuse_inside_secrets`] before its first write. The
/// file is published by rename at `0644`, owned by the writing process,
/// without flushing the directory: every override is regenerated by the
/// command that writes it. A link at the file's name is replaced, not
/// followed.
///
/// # Errors
///
/// Returns an error when `compose_dir` is group- or world-writable, when
/// an existing `compose-overrides/` fails a check, or when the directory
/// or the file cannot be written.
pub(crate) fn write(
    compose_dir: &Path,
    which: ComposeOverride,
    content: &str,
    messages: &Messages,
) -> Result<PathBuf> {
    let euid = fs_util::current_process_euid();
    let (compose_fd, compose_owner) = open_compose_dir(compose_dir, messages)?;
    let dir_path = overrides_dir(compose_dir);
    let dir_display = dir_path.display().to_string();
    match rustix::fs::mkdirat(
        &compose_fd,
        COMPOSE_OVERRIDES_DIR,
        Mode::from_raw_mode(raw_mode(DIR_MODE)),
    ) {
        Ok(()) => {
            let fd = open_overrides_dir(&compose_fd, &dir_path, messages)?
                .ok_or_else(|| anyhow::anyhow!(messages.error_write_file_failed(&dir_display)))?;
            // `mkdirat` applied the umask; the descriptor gets the mode
            // every reader requires.
            rustix::fs::fchmod(&fd, Mode::from_raw_mode(raw_mode(DIR_MODE)))
                .map_err(std::io::Error::from)
                .with_context(|| messages.error_write_file_failed(&dir_display))?;
            check_trusted(
                &fd,
                &dir_path,
                Expect::Directory,
                euid,
                compose_owner,
                messages,
            )?;
        }
        Err(Errno::EXIST) => {
            let fd = open_overrides_dir(&compose_fd, &dir_path, messages)?
                .ok_or_else(|| anyhow::anyhow!(messages.error_write_file_failed(&dir_display)))?;
            check_trusted(
                &fd,
                &dir_path,
                Expect::Directory,
                euid,
                compose_owner,
                messages,
            )?;
        }
        Err(err) => {
            return Err(std::io::Error::from(err))
                .with_context(|| messages.error_write_file_failed(&dir_display));
        }
    }
    let file_path = dir_path.join(which.file_name());
    fs_util::publish_staged_blocking(
        &file_path,
        content.as_bytes(),
        fs_util::StagedMode::Policy(FILE_MODE),
        fs_util::StagedOwner::WritingProcess,
        fs_util::StagedDurability::RenameOnly,
    )
    .with_context(|| messages.error_write_file_failed(&file_path.display().to_string()))?;
    Ok(file_path)
}

/// [`write`], run on a blocking thread for an async caller.
///
/// # Errors
///
/// Returns every error [`write`] returns.
pub(crate) async fn write_async(
    compose_dir: &Path,
    which: ComposeOverride,
    content: String,
    messages: &Messages,
) -> Result<PathBuf> {
    let compose_dir = compose_dir.to_path_buf();
    let messages = messages.clone();
    tokio::task::spawn_blocking(move || write(&compose_dir, which, &content, &messages))
        .await
        .context("compose override write task panicked")?
}

/// Returns the checked path of the override `which` below
/// `compose_dir`, or `None` when it does not exist.
///
/// `secrets_dir` is the secrets directory the command uses: a
/// `compose-overrides/` at or below it is refused. `legacy`, when given,
/// is the `0.7.0` location to probe when the override is missing (see
/// [`ComposeOverride::legacy_path`]); an entry of any kind there stops
/// the command with an error naming both paths. Nothing at `legacy` is
/// ever read or followed.
///
/// # Errors
///
/// Returns an error naming the path and the failed rule when
/// `compose_dir`, `compose-overrides/` or the file fails a check, when
/// `compose-overrides/` is inside `secrets_dir`, when only the legacy
/// file exists, or when a path cannot be opened or inspected.
pub(crate) fn read(
    compose_dir: &Path,
    secrets_dir: &Path,
    which: ComposeOverride,
    legacy: Option<&Path>,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    read_as(
        compose_dir,
        secrets_dir,
        which,
        legacy,
        fs_util::current_process_euid(),
        messages,
    )
}

/// Returns the checked path of an override the command requires, such
/// as an exposure override whose bind intent `state.json` records.
///
/// [`read`] with its `0.7.0` location probed, failing with `missing`
/// when the override exists at neither location.
///
/// # Errors
///
/// Returns every error [`read`] returns, and `missing` when nothing is
/// at either location.
pub(crate) fn read_required(
    compose_dir: &Path,
    secrets_dir: &Path,
    which: ComposeOverride,
    missing: &str,
    messages: &Messages,
) -> Result<PathBuf> {
    let legacy = which.legacy_path(compose_dir, secrets_dir);
    read(compose_dir, secrets_dir, which, Some(&legacy), messages)?
        .ok_or_else(|| anyhow::anyhow!(missing.to_string()))
}

/// [`read`], with the effective uid passed in so a test can cover a
/// file another uid owns without running as root.
fn read_as(
    compose_dir: &Path,
    secrets_dir: &Path,
    which: ComposeOverride,
    legacy: Option<&Path>,
    euid: u32,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    let (compose_fd, compose_owner) = open_compose_dir(compose_dir, messages)?;
    let dir_path = overrides_dir(compose_dir);
    let file_path = dir_path.join(which.file_name());
    let Some(dir_fd) = open_overrides_dir(&compose_fd, &dir_path, messages)? else {
        return missing(which, &file_path, legacy, messages);
    };
    check_trusted(
        &dir_fd,
        &dir_path,
        Expect::Directory,
        euid,
        compose_owner,
        messages,
    )?;
    refuse_inside_secrets(compose_dir, secrets_dir, messages)?;
    let file_fd = match rustix::fs::openat(
        &dir_fd,
        which.file_name(),
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return missing(which, &file_path, legacy, messages),
        Err(err) => {
            return Err(refused_open(
                &dir_fd,
                which.file_name(),
                err,
                &file_path,
                messages,
            ));
        }
    };
    check_trusted(
        &file_fd,
        &file_path,
        Expect::RegularFile,
        euid,
        compose_owner,
        messages,
    )?;
    Ok(Some(file_path))
}

/// Removes the override `which` below `compose_dir`. A file, a
/// directory level or a `compose-overrides/` that does not exist is not
/// an error.
///
/// The file is unlinked through the descriptor of `compose-overrides/`,
/// opened without following a link, so a link at that name is refused
/// rather than followed into another directory.
///
/// # Errors
///
/// Returns an error when `compose-overrides/` is not a directory, or the
/// file cannot be removed.
pub(crate) fn remove(
    compose_dir: &Path,
    which: ComposeOverride,
    messages: &Messages,
) -> Result<()> {
    let dir_path = overrides_dir(compose_dir);
    let compose_fd = match rustix::fs::openat(
        rustix::fs::CWD,
        openable(compose_dir),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(()),
        Err(err) => {
            return Err(std::io::Error::from(err)).with_context(|| {
                messages.error_read_file_failed(&compose_dir.display().to_string())
            });
        }
    };
    let Some(dir_fd) = open_overrides_dir(&compose_fd, &dir_path, messages)? else {
        return Ok(());
    };
    let file_path = dir_path.join(which.file_name());
    match rustix::fs::unlinkat(&dir_fd, which.file_name(), AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(err) => Err(std::io::Error::from(err))
            .with_context(|| messages.error_write_file_failed(&file_path.display().to_string())),
    }
}

/// Removes `compose_dir/compose-overrides` and everything in it. A
/// missing directory is not an error, and a link at its name is removed
/// rather than followed.
///
/// # Errors
///
/// Returns an error when the directory or an entry in it cannot be
/// removed.
pub(crate) fn remove_all(compose_dir: &Path, messages: &Messages) -> Result<()> {
    let dir_path = overrides_dir(compose_dir);
    let display = dir_path.display().to_string();
    match std::fs::symlink_metadata(&dir_path) {
        Ok(meta) if meta.is_dir() => std::fs::remove_dir_all(&dir_path)
            .with_context(|| messages.error_remove_file_failed(&display)),
        Ok(_) => std::fs::remove_file(&dir_path)
            .with_context(|| messages.error_remove_file_failed(&display)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| messages.error_read_file_failed(&display)),
    }
}

/// What a checked descriptor must be.
#[derive(Clone, Copy)]
enum Expect {
    Directory,
    RegularFile,
}

/// Returns `compose_dir`, or `.` for the empty path `Path::parent`
/// gives a bare file name, which `openat` would not find.
fn openable(compose_dir: &Path) -> &Path {
    if compose_dir.as_os_str().is_empty() {
        Path::new(".")
    } else {
        compose_dir
    }
}

/// Opens `compose_dir` by name, as `SecretsTree::open` opens its anchor,
/// and requires it to be a directory nobody but its owner can write.
/// Returns the descriptor and the directory's owner.
fn open_compose_dir(compose_dir: &Path, messages: &Messages) -> Result<(OwnedFd, u32)> {
    let display = compose_dir.display().to_string();
    let fd = rustix::fs::openat(
        rustix::fs::CWD,
        openable(compose_dir),
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)
    .with_context(|| messages.error_read_file_failed(&display))?;
    let stat = fstat(&fd, compose_dir, messages)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        anyhow::bail!(messages.error_compose_override_not_directory(&display));
    }
    let mode = permission_bits(&stat);
    if mode & GROUP_OR_WORLD_WRITABLE != 0 {
        anyhow::bail!(messages.error_compose_override_writable(&display, &format!("{mode:04o}")));
    }
    Ok((fd, stat.st_uid))
}

/// Opens `compose-overrides` on `compose_fd` without following a link.
/// Returns `None` when nothing is at the name.
fn open_overrides_dir(
    compose_fd: &OwnedFd,
    dir_path: &Path,
    messages: &Messages,
) -> Result<Option<OwnedFd>> {
    match rustix::fs::openat(
        compose_fd,
        COMPOSE_OVERRIDES_DIR,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    ) {
        Ok(fd) => Ok(Some(fd)),
        Err(Errno::NOENT) => Ok(None),
        Err(err) => Err(refused_open(
            compose_fd,
            COMPOSE_OVERRIDES_DIR,
            err,
            dir_path,
            messages,
        )),
    }
}

/// The error for an `openat` that failed for anything but `ENOENT`,
/// naming the rule when the entry is a link or of the wrong type.
///
/// `O_NOFOLLOW` reports a link as `ELOOP` on Linux and macOS, and
/// `O_DIRECTORY` a non-directory as `ENOTDIR`; which one a link opened
/// with both reports differs between kernels, so the entry is looked at
/// again, without following it, to name the rule.
fn refused_open(
    dir_fd: &OwnedFd,
    name: &str,
    err: Errno,
    path: &Path,
    messages: &Messages,
) -> anyhow::Error {
    let display = path.display().to_string();
    if matches!(err, Errno::LOOP | Errno::NOTDIR | Errno::MLINK)
        && let Ok(stat) = rustix::fs::statat(dir_fd, name, AtFlags::SYMLINK_NOFOLLOW)
    {
        return match FileType::from_raw_mode(stat.st_mode) {
            FileType::Symlink => anyhow::anyhow!(messages.error_compose_override_symlink(&display)),
            FileType::Directory => {
                anyhow::anyhow!(messages.error_compose_override_not_regular_file(&display))
            }
            _ if name == COMPOSE_OVERRIDES_DIR => {
                anyhow::anyhow!(messages.error_compose_override_not_directory(&display))
            }
            _ => anyhow::anyhow!(messages.error_compose_override_not_regular_file(&display)),
        };
    }
    anyhow::Error::from(std::io::Error::from(err))
        .context(messages.error_read_file_failed(&display))
}

/// Requires the opened `fd` to be of the expected type, owned by a
/// trusted account and writable by nobody else.
fn check_trusted(
    fd: &OwnedFd,
    path: &Path,
    expect: Expect,
    euid: u32,
    compose_owner: u32,
    messages: &Messages,
) -> Result<()> {
    let display = path.display().to_string();
    let stat = fstat(fd, path, messages)?;
    let file_type = FileType::from_raw_mode(stat.st_mode);
    match expect {
        Expect::Directory if file_type != FileType::Directory => {
            anyhow::bail!(messages.error_compose_override_not_directory(&display));
        }
        Expect::RegularFile if file_type != FileType::RegularFile => {
            anyhow::bail!(messages.error_compose_override_not_regular_file(&display));
        }
        Expect::Directory | Expect::RegularFile => {}
    }
    if !is_trusted_owner(stat.st_uid, euid, compose_owner) {
        anyhow::bail!(messages.error_compose_override_untrusted_owner(
            &display,
            stat.st_uid,
            euid,
            compose_owner
        ));
    }
    let mode = permission_bits(&stat);
    if mode & GROUP_OR_WORLD_WRITABLE != 0 {
        anyhow::bail!(messages.error_compose_override_writable(&display, &format!("{mode:04o}")));
    }
    Ok(())
}

/// Reports whether `uid` may own the overrides: root, the running
/// process, or the owner of the compose directory.
fn is_trusted_owner(uid: u32, euid: u32, compose_owner: u32) -> bool {
    uid == 0 || uid == euid || uid == compose_owner
}

/// Refuses a `compose_dir/compose-overrides` at or below `secrets_dir`,
/// comparing canonical paths, whether or not it exists yet.
///
/// [`read`] applies it to every override; a command that writes
/// overrides calls it before its first write, so an override it
/// publishes and hands Compose in the same run is never inside the tree
/// the containers mount. A secrets directory that does not exist yet is
/// compared as the path it will have once created.
///
/// # Errors
///
/// Returns an error naming both paths when `compose-overrides/` is at
/// or below `secrets_dir`, or when either cannot be resolved.
pub(crate) fn refuse_inside_secrets(
    compose_dir: &Path,
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let dir_path = overrides_dir(compose_dir);
    let display = dir_path.display().to_string();
    // `compose-overrides` itself is never followed as a link, so its
    // canonical path is the compose directory's with the name appended.
    let canonical_dir = std::fs::canonicalize(openable(compose_dir))
        .with_context(|| messages.error_resolve_path_failed(&compose_dir.display().to_string()))?
        .join(COMPOSE_OVERRIDES_DIR);
    let canonical_secrets = canonicalize_prospective(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let inside = fs_util::path_is_within(&canonical_dir, &canonical_secrets)
        .with_context(|| messages.error_resolve_path_failed(&display))?;
    if inside {
        anyhow::bail!(messages.error_compose_override_inside_secrets(
            &display,
            &canonical_secrets.display().to_string()
        ));
    }
    Ok(())
}

/// Resolves `path` as it will be once created: its deepest existing
/// ancestor canonically, with the components below it appended and
/// normalized lexically.
///
/// A secrets directory that a command creates later must be compared as
/// that directory, or naming `compose-overrides/` itself before it
/// exists would pass and the command would then create the secrets tree
/// there.
fn canonicalize_prospective(path: &Path) -> std::io::Result<PathBuf> {
    for ancestor in path.ancestors() {
        let existing = if ancestor.as_os_str().is_empty() {
            Path::new(".")
        } else {
            ancestor
        };
        match std::fs::canonicalize(existing) {
            Ok(canonical) => {
                let rest = path
                    .strip_prefix(ancestor)
                    .expect("every ancestor of a path is a prefix of it");
                return fs_util::absolute_lexical(&canonical.join(rest));
            }
            // A dangling link is not absent: where it leads is not known
            // until something creates its target.
            Err(err)
                if err.kind() == std::io::ErrorKind::NotFound
                    && std::fs::symlink_metadata(existing).is_err() => {}
            Err(err) => return Err(err),
        }
    }
    // Only a relative path's last ancestor is empty, and `.` exists; an
    // absolute path ends at `/`. Either resolves above.
    Err(std::io::Error::from(std::io::ErrorKind::NotFound))
}

/// Answers for an override missing from `compose-overrides/`: `None`,
/// unless `legacy` is given and an entry of any kind is there.
fn missing(
    which: ComposeOverride,
    file_path: &Path,
    legacy: Option<&Path>,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    let Some(legacy) = legacy else {
        return Ok(None);
    };
    let legacy_display = legacy.display().to_string();
    match std::fs::symlink_metadata(legacy) {
        Ok(_) => {
            let path = file_path.display().to_string();
            if which.is_exposure() {
                anyhow::bail!(
                    messages.error_compose_override_legacy_exposure(&path, &legacy_display)
                );
            }
            anyhow::bail!(messages.error_compose_override_legacy_init(&path, &legacy_display));
        }
        Err(err)
            if matches!(
                err.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(None)
        }
        Err(err) => Err(err).with_context(|| messages.error_read_file_failed(&legacy_display)),
    }
}

fn fstat(fd: &OwnedFd, path: &Path, messages: &Messages) -> Result<Stat> {
    rustix::fs::fstat(fd)
        .map_err(std::io::Error::from)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))
}

/// The permission bits of `stat`.
// `st_mode` is a `u32` on Linux and a `u16` on macOS, so the widening
// is a real conversion on one platform and an identity on the other.
#[cfg_attr(target_os = "linux", allow(clippy::useless_conversion))]
fn permission_bits(stat: &Stat) -> u32 {
    u32::from(stat.st_mode) & 0o7777
}

fn raw_mode(mode: u32) -> rustix::fs::RawMode {
    rustix::fs::RawMode::try_from(mode).expect("the fixed modes here fit every platform's mode_t")
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    use super::*;
    use crate::i18n::test_messages;

    const BODY: &str = "services: {}\n";

    fn mode_of(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    /// A compose directory the checks accept: the tempdir itself is
    /// `0700`, owned by the test's uid.
    fn compose_dir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn secrets_of(dir: &Path) -> PathBuf {
        dir.join("secrets")
    }

    fn euid() -> u32 {
        fs_util::current_process_euid()
    }

    /// Sets `umask` in this process, runs `body`, and restores it.
    fn under_umask(umask: libc::mode_t, body: impl FnOnce()) {
        // SAFETY: `umask` is a libc call with no memory effects, and the
        // previous value is restored before this returns. The process it
        // changes is the child `umask_test_ran_in_child` spawned for the
        // one test calling this, so no other test runs beside it.
        let prev = unsafe { libc::umask(umask) };
        body();
        // SAFETY: as above.
        unsafe { libc::umask(prev) };
    }

    #[test]
    fn write_sets_the_modes_whatever_the_umask() {
        if fs_util::umask_test_ran_in_child(
            "commands::compose_overrides::tests::write_sets_the_modes_whatever_the_umask",
        ) {
            return;
        }
        for umask in [0o077, 0o000] {
            let dir = compose_dir();
            under_umask(umask, || {
                let path = write(
                    dir.path(),
                    ComposeOverride::Responder,
                    BODY,
                    &test_messages(),
                )
                .unwrap();
                assert_eq!(
                    path,
                    dir.path()
                        .join(COMPOSE_OVERRIDES_DIR)
                        .join(ComposeOverride::Responder.file_name())
                );
                assert_eq!(
                    mode_of(&dir.path().join(COMPOSE_OVERRIDES_DIR)),
                    DIR_MODE,
                    "umask {umask:o}"
                );
                assert_eq!(mode_of(&path), FILE_MODE, "umask {umask:o}");
                let meta = std::fs::metadata(&path).unwrap();
                assert_eq!(meta.uid(), euid());
            });
        }
    }

    #[test]
    fn a_second_write_replaces_the_file_and_a_link_at_its_name() {
        let dir = compose_dir();
        let messages = test_messages();
        let first = write(
            dir.path(),
            ComposeOverride::PostgresTls,
            "a: 1\n",
            &messages,
        )
        .unwrap();
        let inode = std::fs::metadata(&first).unwrap().ino();
        let second = write(
            dir.path(),
            ComposeOverride::PostgresTls,
            "a: 2\n",
            &messages,
        )
        .unwrap();
        assert_eq!(first, second);
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "a: 2\n");
        assert_ne!(
            std::fs::metadata(&second).unwrap().ino(),
            inode,
            "published by rename"
        );

        let target = dir.path().join("elsewhere.yml");
        std::fs::write(&target, "kept\n").unwrap();
        std::fs::remove_file(&second).unwrap();
        symlink(&target, &second).unwrap();
        write(
            dir.path(),
            ComposeOverride::PostgresTls,
            "a: 3\n",
            &messages,
        )
        .unwrap();
        assert!(
            !std::fs::symlink_metadata(&second)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "a: 3\n");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "kept\n");
    }

    #[test]
    fn write_refuses_an_existing_untrusted_directory() {
        let dir = compose_dir();
        let overrides = overrides_dir(dir.path());
        std::fs::create_dir(&overrides).unwrap();
        std::fs::set_permissions(&overrides, std::fs::Permissions::from_mode(0o775)).unwrap();
        let err = write(
            dir.path(),
            ComposeOverride::Responder,
            BODY,
            &test_messages(),
        )
        .unwrap_err();
        assert!(
            format!("{err:#}").contains(&overrides.display().to_string()),
            "{err:#}"
        );
        assert!(!path(dir.path(), ComposeOverride::Responder).exists());
    }

    #[test]
    fn read_returns_none_when_nothing_exists_at_either_location() {
        let dir = compose_dir();
        let secrets = secrets_of(dir.path());
        let messages = test_messages();
        for which in [ComposeOverride::OpenBaoExposed, ComposeOverride::Responder] {
            let legacy = which.legacy_path(dir.path(), &secrets);
            assert!(
                read(dir.path(), &secrets, which, Some(&legacy), &messages)
                    .unwrap()
                    .is_none()
            );
            assert!(
                read(dir.path(), &secrets, which, None, &messages)
                    .unwrap()
                    .is_none()
            );
        }
        // An empty `compose-overrides/` reads the same.
        std::fs::create_dir(overrides_dir(dir.path())).unwrap();
        assert!(
            read(
                dir.path(),
                &secrets,
                ComposeOverride::Responder,
                None,
                &messages
            )
            .unwrap()
            .is_none()
        );
    }

    #[test]
    fn read_accepts_root_the_euid_and_the_compose_dir_owner() {
        let dir = compose_dir();
        let secrets = secrets_of(dir.path());
        let messages = test_messages();
        let written = write(dir.path(), ComposeOverride::Http01Exposed, BODY, &messages).unwrap();
        let owner = euid();
        // The files are this uid's, which is the compose directory's
        // owner too. Each injected euid makes the file "owned by" a
        // different trusted account in turn.
        for injected in [owner, owner.wrapping_add(1)] {
            let read = read_as(
                dir.path(),
                &secrets,
                ComposeOverride::Http01Exposed,
                None,
                injected,
                &messages,
            )
            .unwrap();
            assert_eq!(read.as_deref(), Some(written.as_path()));
        }
        assert!(is_trusted_owner(0, 1000, 1001));
        assert!(is_trusted_owner(1000, 1000, 1001));
        assert!(is_trusted_owner(1001, 1000, 1001));
        assert!(!is_trusted_owner(1002, 1000, 1001));
    }

    /// A file owned by an account other than root, the injected euid and
    /// the compose directory's owner. Unprivileged, the test cannot
    /// create one, so it checks the rule on an opened descriptor of a
    /// file it owns against a compose owner and euid that are not it.
    #[test]
    fn read_refuses_a_foreign_owned_directory_and_file() {
        let dir = compose_dir();
        let messages = test_messages();
        let written = write(dir.path(), ComposeOverride::Responder, BODY, &messages).unwrap();
        let me = euid();
        if me == 0 {
            // Root is always trusted; the rule has no foreign owner to
            // refuse here.
            return;
        }
        let other = me + 1;
        let dir_fd = OwnedFd::from(File::open(overrides_dir(dir.path())).unwrap());
        let err = check_trusted(
            &dir_fd,
            &overrides_dir(dir.path()),
            Expect::Directory,
            other,
            other,
            &messages,
        )
        .unwrap_err();
        assert!(err.to_string().contains(&format!("uid {me}")), "{err}");
        let file_fd = OwnedFd::from(File::open(&written).unwrap());
        let err = check_trusted(
            &file_fd,
            &written,
            Expect::RegularFile,
            other,
            other,
            &messages,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(&written.display().to_string()),
            "{err}"
        );
    }

    #[test]
    fn read_refuses_a_group_writable_compose_directory() {
        let dir = compose_dir();
        let messages = test_messages();
        write(dir.path(), ComposeOverride::Responder, BODY, &messages).unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o770)).unwrap();
        let err = read(
            dir.path(),
            &secrets_of(dir.path()),
            ComposeOverride::Responder,
            None,
            &messages,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains(&dir.path().display().to_string()),
            "{err}"
        );
        assert!(err.to_string().contains("0770"), "{err}");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn read_refuses_a_linked_or_writable_overrides_directory() {
        let messages = test_messages();
        // A link at `compose-overrides`.
        let dir = compose_dir();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::write(real.join(ComposeOverride::Responder.file_name()), BODY).unwrap();
        symlink(&real, overrides_dir(dir.path())).unwrap();
        let err = read(
            dir.path(),
            &secrets_of(dir.path()),
            ComposeOverride::Responder,
            None,
            &messages,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            messages
                .error_compose_override_symlink(&overrides_dir(dir.path()).display().to_string())
        );

        // A file at `compose-overrides`.
        let dir = compose_dir();
        std::fs::write(overrides_dir(dir.path()), BODY).unwrap();
        let err = read(
            dir.path(),
            &secrets_of(dir.path()),
            ComposeOverride::Responder,
            None,
            &messages,
        )
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            messages.error_compose_override_not_directory(
                &overrides_dir(dir.path()).display().to_string()
            )
        );

        // Group- and world-writable.
        for mode in [0o775, 0o757] {
            let dir = compose_dir();
            write(dir.path(), ComposeOverride::Responder, BODY, &messages).unwrap();
            std::fs::set_permissions(
                overrides_dir(dir.path()),
                std::fs::Permissions::from_mode(mode),
            )
            .unwrap();
            let err = read(
                dir.path(),
                &secrets_of(dir.path()),
                ComposeOverride::Responder,
                None,
                &messages,
            )
            .unwrap_err();
            assert_eq!(
                err.to_string(),
                messages.error_compose_override_writable(
                    &overrides_dir(dir.path()).display().to_string(),
                    &format!("{mode:04o}")
                )
            );
        }
    }

    #[test]
    fn read_refuses_a_linked_fifo_or_writable_file() {
        let messages = test_messages();
        let which = ComposeOverride::OpenBaoAgent;

        let dir = compose_dir();
        let file = write(dir.path(), which, BODY, &messages).unwrap();
        let target = dir.path().join("target.yml");
        std::fs::write(&target, BODY).unwrap();
        std::fs::remove_file(&file).unwrap();
        symlink(&target, &file).unwrap();
        let err = read(dir.path(), &secrets_of(dir.path()), which, None, &messages).unwrap_err();
        assert_eq!(
            err.to_string(),
            messages.error_compose_override_symlink(&file.display().to_string())
        );

        // A FIFO is opened with `O_NONBLOCK`, so the check returns
        // rather than waiting for a writer.
        let dir = compose_dir();
        let file = write(dir.path(), which, BODY, &messages).unwrap();
        std::fs::remove_file(&file).unwrap();
        let status = std::process::Command::new("mkfifo")
            .args(["-m", "644"])
            .arg(&file)
            .status()
            .unwrap();
        assert!(status.success());
        let err = read(dir.path(), &secrets_of(dir.path()), which, None, &messages).unwrap_err();
        assert_eq!(
            err.to_string(),
            messages.error_compose_override_not_regular_file(&file.display().to_string())
        );

        for mode in [0o664, 0o646] {
            let dir = compose_dir();
            let file = write(dir.path(), which, BODY, &messages).unwrap();
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            let err =
                read(dir.path(), &secrets_of(dir.path()), which, None, &messages).unwrap_err();
            assert_eq!(
                err.to_string(),
                messages.error_compose_override_writable(
                    &file.display().to_string(),
                    &format!("{mode:04o}")
                )
            );
        }
    }

    #[test]
    fn read_refuses_overrides_inside_the_secrets_directory() {
        let messages = test_messages();
        let dir = compose_dir();
        write(dir.path(), ComposeOverride::Responder, BODY, &messages).unwrap();
        // The compose directory itself, and its parent, as the secrets
        // directory.
        for secrets in [dir.path().to_path_buf(), dir.path().join("..")] {
            let err = read(
                dir.path(),
                &secrets,
                ComposeOverride::Responder,
                None,
                &messages,
            )
            .unwrap_err();
            assert!(
                err.to_string()
                    .contains(&overrides_dir(dir.path()).display().to_string()),
                "{err}"
            );
        }
        // A sibling secrets directory, existing or not, is fine.
        std::fs::create_dir(secrets_of(dir.path())).unwrap();
        assert!(
            read(
                dir.path(),
                &secrets_of(dir.path()),
                ComposeOverride::Responder,
                None,
                &messages
            )
            .unwrap()
            .is_some()
        );
        assert!(
            read(
                dir.path(),
                &dir.path().join("absent"),
                ComposeOverride::Responder,
                None,
                &messages
            )
            .unwrap()
            .is_some()
        );
    }

    /// The check a writing command makes before its first write refuses
    /// a secrets directory at or above the compose directory before
    /// `compose-overrides/` exists, and accepts a sibling or absent one.
    #[test]
    fn refuse_inside_secrets_holds_before_the_directory_exists() {
        let messages = test_messages();
        let dir = compose_dir();
        for secrets in [dir.path().to_path_buf(), dir.path().join("..")] {
            let err = refuse_inside_secrets(dir.path(), &secrets, &messages).unwrap_err();
            assert_eq!(
                err.to_string(),
                messages.error_compose_override_inside_secrets(
                    &overrides_dir(dir.path()).display().to_string(),
                    &std::fs::canonicalize(&secrets)
                        .unwrap()
                        .display()
                        .to_string()
                )
            );
        }
        assert!(!overrides_dir(dir.path()).exists());
        refuse_inside_secrets(dir.path(), &secrets_of(dir.path()), &messages).unwrap();
        std::fs::create_dir(secrets_of(dir.path())).unwrap();
        refuse_inside_secrets(dir.path(), &secrets_of(dir.path()), &messages).unwrap();
        // A secrets directory that does not exist yet is compared as
        // the path it will have: `compose-overrides/` itself, before
        // either exists, is refused, as is an absent parent of it.
        let absent = dir.path().join("absent");
        for secrets in [
            overrides_dir(dir.path()),
            absent.join("..").join(COMPOSE_OVERRIDES_DIR),
        ] {
            let err = refuse_inside_secrets(dir.path(), &secrets, &messages).unwrap_err();
            assert_eq!(
                err.to_string(),
                messages.error_compose_override_inside_secrets(
                    &overrides_dir(dir.path()).display().to_string(),
                    &std::fs::canonicalize(dir.path())
                        .unwrap()
                        .join(COMPOSE_OVERRIDES_DIR)
                        .display()
                        .to_string()
                )
            );
        }
        assert!(!overrides_dir(dir.path()).exists());
        // Nor is a dangling link resolved as if it were absent.
        let dangling = dir.path().join("dangling");
        symlink(overrides_dir(dir.path()), &dangling).unwrap();
        let err = refuse_inside_secrets(dir.path(), &dangling, &messages).unwrap_err();
        assert_eq!(
            err.to_string(),
            messages.error_resolve_path_failed(&dangling.display().to_string())
        );
        std::fs::remove_file(&dangling).unwrap();
        // A secrets directory below `compose-overrides/` itself is not
        // its parent.
        refuse_inside_secrets(
            dir.path(),
            &overrides_dir(dir.path()).join("nested"),
            &messages,
        )
        .unwrap();
    }

    #[test]
    fn the_probe_stops_on_a_legacy_only_override() {
        let messages = test_messages();
        for which in [ComposeOverride::StepCaExposed, ComposeOverride::PostgresTls] {
            let dir = compose_dir();
            let secrets = secrets_of(dir.path());
            let legacy = which.legacy_path(dir.path(), &secrets);
            std::fs::create_dir_all(legacy.parent().unwrap()).unwrap();
            // A dangling link counts: the probe does not follow it.
            symlink(dir.path().join("nowhere"), &legacy).unwrap();
            let err = read(dir.path(), &secrets, which, Some(&legacy), &messages).unwrap_err();
            let new = path(dir.path(), which).display().to_string();
            let old = legacy.display().to_string();
            let expected = if which == ComposeOverride::StepCaExposed {
                messages.error_compose_override_legacy_exposure(&new, &old)
            } else {
                messages.error_compose_override_legacy_init(&new, &old)
            };
            assert_eq!(err.to_string(), expected);
            // Without a probe path the old location is ignored.
            assert!(
                read(dir.path(), &secrets, which, None, &messages)
                    .unwrap()
                    .is_none()
            );
            // With the new file present the old one is ignored too.
            let written = write(dir.path(), which, BODY, &messages).unwrap();
            assert_eq!(
                read(dir.path(), &secrets, which, Some(&legacy), &messages).unwrap(),
                Some(written)
            );
        }
    }

    #[test]
    fn legacy_paths_match_the_former_layout() {
        let compose = Path::new("/srv/bootroot");
        let secrets = Path::new("/var/lib/secrets");
        let cases = [
            (
                ComposeOverride::OpenBaoExposed,
                "/srv/bootroot/secrets/openbao/docker-compose.openbao-exposed.yml",
            ),
            (
                ComposeOverride::OpenBaoAudit,
                "/srv/bootroot/secrets/openbao/docker-compose.openbao-audit.yml",
            ),
            (
                ComposeOverride::Http01Exposed,
                "/srv/bootroot/secrets/responder/docker-compose.http01-exposed.yml",
            ),
            (
                ComposeOverride::StepCaExposed,
                "/srv/bootroot/secrets/step-ca/docker-compose.stepca-exposed.yml",
            ),
            (
                ComposeOverride::OpenBaoAgent,
                "/var/lib/secrets/openbao/docker-compose.openbao-agent.override.yml",
            ),
            (
                ComposeOverride::Responder,
                "/var/lib/secrets/responder/docker-compose.responder.override.yml",
            ),
            (
                ComposeOverride::PostgresTls,
                "/var/lib/secrets/postgres/docker-compose.postgres-tls.yml",
            ),
        ];
        for (which, expected) in cases {
            assert_eq!(which.legacy_path(compose, secrets), PathBuf::from(expected));
        }
    }

    #[test]
    fn remove_tolerates_absence_and_removes_the_file() {
        let dir = compose_dir();
        let messages = test_messages();
        remove(dir.path(), ComposeOverride::Responder, &messages).unwrap();
        std::fs::create_dir(overrides_dir(dir.path())).unwrap();
        remove(dir.path(), ComposeOverride::Responder, &messages).unwrap();
        let file = write(dir.path(), ComposeOverride::Responder, BODY, &messages).unwrap();
        remove(dir.path(), ComposeOverride::Responder, &messages).unwrap();
        assert!(!file.exists());
        assert!(overrides_dir(dir.path()).is_dir());
    }

    #[test]
    fn remove_does_not_follow_a_linked_directory() {
        let dir = compose_dir();
        let messages = test_messages();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let victim = real.join(ComposeOverride::Responder.file_name());
        std::fs::write(&victim, BODY).unwrap();
        symlink(&real, overrides_dir(dir.path())).unwrap();
        assert!(remove(dir.path(), ComposeOverride::Responder, &messages).is_err());
        assert!(victim.exists());
    }

    #[test]
    fn remove_all_removes_the_directory_and_tolerates_absence() {
        let dir = compose_dir();
        let messages = test_messages();
        remove_all(dir.path(), &messages).unwrap();
        write(dir.path(), ComposeOverride::Responder, BODY, &messages).unwrap();
        remove_all(dir.path(), &messages).unwrap();
        assert!(!overrides_dir(dir.path()).exists());
    }
}
