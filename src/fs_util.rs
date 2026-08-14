use std::io::Write as _;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs;

use crate::cert_group::{self, CertGroupPolicy};

pub const KEY_FILE_MODE: u32 = 0o600;
const SECRETS_DIR_MODE: u32 = 0o700;

/// Returns the absolute, lexically-normalized form of `path`: it is made
/// absolute against the process cwd and its `.`/`..` components are
/// resolved textually, without touching the filesystem or following
/// symlinks.
///
/// Used to compare an operator-supplied `--secret-id-path` override
/// against the secrets-tree prefix so equivalent spellings classify
/// identically.
///
/// # Errors
/// Returns an error if the current directory cannot be resolved (needed
/// to absolutize a relative input).
pub fn absolute_lexical(path: &Path) -> std::io::Result<PathBuf> {
    let absolute = std::path::absolute(path)?;
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    Ok(normalized)
}

/// Reports whether `candidate` resolves inside `prefix`, comparing both
/// after [`absolute_lexical`] normalization. Comparison is component-wise
/// (`/a/bc` is not inside `/a/b`).
///
/// # Errors
/// Returns an error if either path cannot be absolutized (see
/// [`absolute_lexical`]).
pub fn path_is_within(candidate: &Path, prefix: &Path) -> std::io::Result<bool> {
    Ok(absolute_lexical(candidate)?.starts_with(absolute_lexical(prefix)?))
}

/// The directory holding `path`: its parent, or the process cwd when
/// `path` is a bare file name.
fn parent_dir(path: &Path) -> PathBuf {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

/// Resolves the file a staged write should land on when `path` is a
/// symlink, returning `path` unchanged when it is not.
///
/// A truncating write opens the path with `O_TRUNC`, which follows the
/// final symlink, so a destination pointed at a link has always
/// delivered its bytes to the link's target. [`atomic_write`] and
/// [`atomic_write_blocking`] `rename` over the name they are given
/// instead, which replaces the link itself: the operator's link is
/// gone and the target is left holding whatever was written last.
///
/// Writers reach this through
/// [`atomic_write_through_symlink`]/[`atomic_replace_through_symlink`]
/// and their blocking halves, which document what takes that spelling
/// and what deliberately keeps the bare rename. It is called directly
/// only where the resolved path itself is needed — `bootroot reinit`'s
/// two output preflights, which judge the target's mode before the
/// destructive step, and the two writers behind them, which narrow that
/// same target before writing a credential over it.
///
/// Not a security check. It follows whatever the link points at, so a
/// caller whose destination an untrusted user can plant must reject
/// the symlink rather than resolve it (see
/// [`atomic_rewrite_owned_no_symlink`], which does).
///
/// A dangling link is resolved from its own text rather than from the
/// filesystem, so the write still lands where the operator pointed it.
/// The truncating write's `O_CREAT` created the target through the
/// link; publishing at the link's own name instead would destroy the
/// link and put the file in a directory nobody chose, which for the
/// root token means a credential landing outside the place the
/// operator set aside for it.
///
/// # Errors
/// Returns an error if the chain does not end within `SYMLOOP_MAX`
/// hops — a cycle, which the truncating write reported as `ELOOP` and
/// which is reported here rather than resolved, since every path in a
/// loop is a link the caller would destroy by renaming over it — or if
/// a link in the chain cannot be read, which leaves the destination
/// unknown for the same reason.
pub fn resolve_symlink_destination(path: &Path) -> Result<PathBuf> {
    /// Hops allowed before a chain of dangling links is treated as a
    /// cycle, matching the kernel's own `SYMLOOP_MAX`.
    const MAX_HOPS: u32 = 40;

    fn is_symlink(path: &Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
    }

    if !is_symlink(path) {
        return Ok(path.to_path_buf());
    }
    // Resolves the whole chain, and normalises the parent components
    // with it, whenever the target exists.
    if let Ok(resolved) = std::fs::canonicalize(path) {
        return Ok(resolved);
    }
    let mut current = path.to_path_buf();
    for _ in 0..MAX_HOPS {
        let target = std::fs::read_link(&current).with_context(|| {
            format!(
                "Failed to read the symlink {} while resolving the destination {}",
                current.display(),
                path.display()
            )
        })?;
        current = if target.is_absolute() {
            target
        } else {
            parent_dir(&current).join(target)
        };
        if !is_symlink(&current) {
            return Ok(current);
        }
    }
    // A cycle: every name in it is a link, so there is nothing to
    // publish that does not destroy one. The truncating write this
    // replaces answered ELOOP here, and the caller keeps that answer —
    // returning the path the caller named would have the rename
    // silently replace the operator's link with a regular file.
    anyhow::bail!(
        "Too many levels of symbolic links resolving the destination {}: \
         followed {MAX_HOPS} links without reaching a file",
        path.display()
    )
}

/// Flushes the directory holding `path` — its entry list, not the files
/// behind it — so the name just published there survives a crash.
///
/// A `rename(2)`, or an `O_EXCL` create, is a directory operation.
/// `sync_all` on the file puts its *bytes* on disk; until the directory
/// is flushed the entry pointing at those bytes may not be, and a crash
/// in that window can leave the destination name still pointing at the
/// old inode — or at nothing — with the fully written new data sitting
/// on disk unreferenced. The file survived; the fact that it is the
/// current one did not.
///
/// Call this *after* the rename or the create, never before, and only
/// where the file has to survive a power loss rather than merely
/// replace cleanly — the flush is a disk round trip per write. One call
/// is enough per publish: a staged temporary is created in the
/// destination's own directory, so both names live in the entry list
/// being flushed here. It takes the published file rather than the
/// directory so every caller resolves the same directory the write did,
/// including the bare-file-name case that names the cwd.
///
/// What that buys is a Linux guarantee. macOS `fsync` does not flush
/// the drive's own write cache — `F_FULLFSYNC` is the call that does —
/// so on a developer machine this closes the ordering gap without
/// promising power-loss durability. Linux is the deployment target and
/// is where the guarantee has to hold.
///
/// Blocking, like the `std::fs` calls it wraps: async callers invoke it
/// inside the `spawn_blocking` that already carries their write.
///
/// # Errors
/// Returns an error if the directory cannot be opened or the flush
/// fails. A failed flush means the publish is not durable, so it is
/// reported rather than swallowed — including the `EINVAL` that a
/// filesystem outside Linux and macOS may answer a directory `fsync`
/// with.
pub fn sync_parent_dir(path: &Path) -> Result<()> {
    let dir = parent_dir(path);
    std::fs::File::open(&dir)
        .with_context(|| {
            format!(
                "Failed to open directory {} to fsync it after publishing {}",
                dir.display(),
                path.display()
            )
        })?
        .sync_all()
        .with_context(|| format!("Failed to fsync directory {}", dir.display()))
}

/// Stages `contents` into a fresh file inside the parent directory of
/// `path`, chowns it to the parent directory's owner, applies mode
/// `0600`, and links it into place **without** following or replacing
/// anything already present at the final path component.
///
/// This is the override-path writer for a service's `secret_id` and its
/// sibling `role_id`, which live in an operator-provisioned,
/// agent-owned directory outside the root-owned secrets tree. The
/// parent must already exist — this never creates, chmods, or chowns
/// the directory. A root process creating a fresh file inside an
/// agent-owned directory would otherwise leave it root-owned (ownership
/// is not inherited), so the fresh file is chowned to the parent's
/// uid/gid, leaving the co-located non-root agent able to read
/// `role_id` and rewrite `secret_id`. A pre-existing regular file or a
/// symlink planted at the target is a hard error (no-clobber), so a
/// lower-privileged user cannot redirect the root write or have a stale
/// credential silently clobbered.
///
/// The containing directory is flushed after the link
/// ([`sync_parent_dir`]). Losing this write after `OpenBao` has already
/// accepted the new credential does not cost a rewrite: it locks the
/// agent out until an operator intervenes.
///
/// # Errors
/// Returns an error if `path` is not absolute, has no parent, the
/// parent is missing or not a directory, the temp file cannot be
/// created/written/permissioned/chowned, the target already exists, or
/// the containing directory cannot be flushed.
pub async fn create_owned_credential_noclobber(path: &Path, contents: &[u8]) -> Result<()> {
    write_owned_impl(path, contents, KEY_FILE_MODE, Publish::NoClobber).await
}

/// Like [`create_owned_credential_noclobber`] but atomically *replaces*
/// an existing file. Used for a relocated `eab.json`, which is
/// (re)written on every sync. The fresh file is still chowned to the
/// parent owner, and the rename replaces the target name rather than
/// following a symlink planted at it.
///
/// The containing directory is deliberately *not* flushed after the
/// rename. `eab.json` is rewritten on every sync, so a crash that loses
/// the new directory entry costs the next sync's rewrite and nothing
/// else — not worth a disk round trip on every write.
///
/// # Errors
/// Returns an error under the same conditions as
/// [`create_owned_credential_noclobber`], except that an existing
/// regular file at the target is replaced instead of rejected, and no
/// directory flush is attempted.
pub async fn write_owned_file_replace(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    write_owned_impl(path, contents, mode, Publish::Replace).await
}

/// Atomically rewrites an existing override credential file in place,
/// preserving its uid/gid and re-applying `mode`, while refusing to
/// follow a symlink planted at the final path component.
///
/// This is the rotation-time writer for a relocated `secret_id` that
/// still exists. It differs from [`atomic_write`] in reading the
/// destination's ownership through `symlink_metadata` (which does not
/// follow a symlink) and rejecting a symlink outright. A lower-privileged
/// user who plants a symlink at the credential path — pointing at a
/// root-owned file — must not be able to make the root rewrite either
/// follow it or copy that file's root ownership onto the replacement,
/// which would re-break the non-root agent. The atomic rename replaces
/// the target name (it never follows the link) and the ownership read is
/// taken from the real file, so a swap after the check cannot escalate.
///
/// The containing directory is flushed after the rename
/// ([`sync_parent_dir`]), for the same reason as
/// [`create_owned_credential_noclobber`]: losing the rotated
/// `secret_id` once `OpenBao` has accepted it locks the agent out until
/// an operator intervenes.
///
/// # Errors
/// Returns an error if the destination is a symlink, is missing, its
/// metadata cannot be read, the staged file cannot be
/// created/written/permissioned/chowned/renamed, or the containing
/// directory cannot be flushed.
pub async fn atomic_rewrite_owned_no_symlink(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<()> {
    let dest = path.to_path_buf();
    let parent = parent_dir(path);
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || -> Result<()> {
        // `symlink_metadata` does not follow the final component, so it
        // both detects a planted symlink and reads the *real* file's
        // uid/gid (never a root-owned symlink target's).
        let meta = std::fs::symlink_metadata(&dest)
            .with_context(|| format!("Failed to stat override credential {}", dest.display()))?;
        if meta.file_type().is_symlink() {
            anyhow::bail!(
                "Refusing to rewrite a symlink at override credential path: {}",
                dest.display()
            );
        }
        let (uid, gid) = (meta.uid(), meta.gid());

        let mut tmp = tempfile::NamedTempFile::new_in(&parent)
            .with_context(|| format!("Failed to create temp file in {}", parent.display()))?;
        tmp.as_file_mut()
            .write_all(&payload)
            .with_context(|| format!("Failed to write temp file for {}", dest.display()))?;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode)).with_context(
            || {
                format!(
                    "Failed to set mode {mode:o} on temp file for {}",
                    dest.display()
                )
            },
        )?;
        std::os::unix::fs::chown(tmp.path(), Some(uid), Some(gid)).with_context(|| {
            format!(
                "Failed to preserve uid={uid} gid={gid} on {}",
                dest.display()
            )
        })?;
        // Flushed after the mode and the ownership, not before them: an
        // `fsync` persists the inode as it stands, so a flush taken at
        // the bytes leaves a crash able to recover this credential
        // world-readable or owned by the wrong uid. See
        // `publish_staged_blocking`, which orders the same three steps
        // for the same reason.
        tmp.as_file_mut()
            .sync_all()
            .with_context(|| format!("Failed to fsync temp file for {}", dest.display()))?;
        // `persist` replaces the target *name* via rename(2), which does
        // not traverse a symlink at the final component, so even a
        // post-check swap cannot redirect the write.
        tmp.persist(&dest).map_err(|e| {
            anyhow::anyhow!(
                "Failed to rename temp file to {}: {}",
                dest.display(),
                e.error
            )
        })?;
        sync_parent_dir(&dest)?;
        Ok(())
    })
    .await
    .context("Owned credential rewrite task panicked")?
}

/// How [`write_owned_impl`] links the staged file into place, and
/// whether the directory entry that publishes it is flushed.
enum Publish {
    /// Refuse an existing target, then flush the directory: this is a
    /// credential the agent cannot re-derive.
    NoClobber,
    /// Replace an existing target and leave the directory unflushed:
    /// the payload is rewritten on the next sync anyway.
    Replace,
}

async fn write_owned_impl(path: &Path, contents: &[u8], mode: u32, publish: Publish) -> Result<()> {
    if !path.is_absolute() {
        anyhow::bail!(
            "Override credential path must be absolute: {}",
            path.display()
        );
    }
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Override credential path has no parent directory: {}",
                path.display()
            )
        })?
        .to_path_buf();
    let dest = path.to_path_buf();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || -> Result<()> {
        let parent_meta = std::fs::metadata(&parent).with_context(|| {
            format!(
                "Override credential parent directory is missing: {}",
                parent.display()
            )
        })?;
        if !parent_meta.is_dir() {
            anyhow::bail!(
                "Override credential parent is not a directory: {}",
                parent.display()
            );
        }
        let (uid, gid) = (parent_meta.uid(), parent_meta.gid());

        let mut tmp = tempfile::NamedTempFile::new_in(&parent)
            .with_context(|| format!("Failed to create temp file in {}", parent.display()))?;
        tmp.as_file_mut()
            .write_all(&payload)
            .with_context(|| format!("Failed to write temp file for {}", dest.display()))?;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode)).with_context(
            || {
                format!(
                    "Failed to set mode {mode:o} on temp file for {}",
                    dest.display()
                )
            },
        )?;
        std::os::unix::fs::chown(tmp.path(), Some(uid), Some(gid)).with_context(|| {
            format!(
                "Failed to chown temp file for {} to uid={uid} gid={gid}",
                dest.display()
            )
        })?;
        // Flushed last, after the mode and the ownership, so the inode a
        // crash recovers is the one that was published — see
        // `publish_staged_blocking`.
        tmp.as_file_mut()
            .sync_all()
            .with_context(|| format!("Failed to fsync temp file for {}", dest.display()))?;
        match publish {
            Publish::Replace => {
                tmp.persist(&dest).map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to rename temp file to {}: {}",
                        dest.display(),
                        e.error
                    )
                })?;
                // No `sync_parent_dir` here: see
                // `write_owned_file_replace`.
            }
            Publish::NoClobber => {
                // `persist_noclobber` fails if the target name already
                // exists — a regular file *or* a planted symlink — so a
                // root write is never redirected or a stale credential
                // silently overwritten.
                tmp.persist_noclobber(&dest).map_err(|e| {
                    anyhow::anyhow!(
                        "Refusing to overwrite an existing file at {}: {}",
                        dest.display(),
                        e.error
                    )
                })?;
                sync_parent_dir(&dest)?;
            }
        }
        Ok(())
    })
    .await
    .context("Owned credential write task panicked")?
}

/// Writes `contents` to `path` atomically by staging it in a sibling
/// temp file and `rename(2)`ing into place.
///
/// `bootroot-agent`'s daemon loop re-reads `agent.toml` on every ACME
/// retry. A non-atomic `fs::write` opens the destination with
/// `O_TRUNC` and then issues `write_all`, so a concurrent reader can
/// observe a zero-byte or partially populated file in the gap. That
/// surfaced in the field (#613) as renewal retries failing with
/// "profile not found in reloaded config" and exhausting the retry
/// budget against a transient race. Routing the write through a
/// same-directory temp file + atomic rename closes the window: a
/// reader sees either the previous file or the fully written new one.
///
/// The supplied `mode` is applied to the staged file before the
/// rename so the on-disk mode never changes after the file appears at
/// `path`. When `path` already exists, the existing uid/gid is also
/// re-applied to the staged file before the rename so the caller does
/// not silently re-own the destination to the writer's effective
/// uid/gid (e.g. a `service add` run by root replacing an
/// agent-readable file with a root-owned `0600` file the long-running
/// agent process can no longer read).
///
/// The containing directory is flushed after the rename
/// ([`sync_parent_dir`]). This is the shared path for
/// `bootroot-agent`'s fast-poll state and for `rotation-state.json`,
/// both of which the program reads back to resume, so the published
/// name has to survive a power loss and not merely a clean replacement.
///
/// # Errors
/// Returns an error if the temp file cannot be created, written,
/// permissioned, chowned (when ownership preservation is needed),
/// renamed, or if the containing directory cannot be flushed.
pub async fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    // Owned once, to move into the blocking task. The blocking half
    // borrows, so this is the only copy either path makes.
    let dest = path.to_path_buf();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || atomic_write_blocking(&dest, &payload, mode))
        .await
        .context("Atomic write task panicked")?
}

/// The blocking half of [`atomic_write`], for callers that are not async.
///
/// Same guarantees, same order: staged in the destination's directory,
/// written, ownership-preserved, permissioned, `sync_all`ed, renamed,
/// and the directory flushed. Callers in an async context use
/// [`atomic_write`] instead, which runs this on a blocking thread.
///
/// One spelling of [`publish_staged_blocking`], which every staged
/// publish in the crate goes through — see there for the two decisions
/// this one makes ([`StagedOwner::Destination`] and
/// [`StagedDurability::FlushDirectory`]) and why.
///
/// # Errors
/// Returns an error under the same conditions as [`atomic_write`].
pub fn atomic_write_blocking(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    publish_staged_blocking(
        path,
        contents,
        mode,
        StagedOwner::Destination,
        StagedDurability::FlushDirectory,
    )
}

/// Publishes `contents` at `path` by rename, **without** flushing the
/// containing directory.
///
/// [`atomic_write`]'s guarantee against a torn read, without its
/// durability guarantee. This is the right writer for regenerable
/// configuration — a compose override, an `OpenBao` Agent template, a
/// patched `ca.json` — where a reader (a container mounting the file, a
/// sidecar re-rendering it) must never see half a document, but a crash
/// that loses the new directory entry leaves the previous file in place
/// and costs a re-run of the command that produced it rather than an
/// outage. The flush is a disk round trip per write and `init` performs
/// dozens of these, so it is not spent where the file can be rebuilt.
///
/// Callers whose file is read back to resume, or that hold something
/// that cannot be re-derived, use [`atomic_write`] instead.
///
/// # Errors
/// Returns an error under the same conditions as [`atomic_write`],
/// except that no directory flush is attempted.
pub async fn atomic_replace(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    // Owned once, to move into the blocking task, exactly as
    // `atomic_write` does.
    let dest = path.to_path_buf();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || atomic_replace_blocking(&dest, &payload, mode))
        .await
        .context("Atomic replace task panicked")?
}

/// The blocking half of [`atomic_replace`], for callers that are not
/// async.
///
/// One spelling of [`publish_staged_blocking`] — see there for the two
/// decisions this one makes ([`StagedOwner::Destination`] and
/// [`StagedDurability::RenameOnly`]) and why.
///
/// # Errors
/// Returns an error under the same conditions as [`atomic_replace`].
pub fn atomic_replace_blocking(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    publish_staged_blocking(
        path,
        contents,
        mode,
        StagedOwner::Destination,
        StagedDurability::RenameOnly,
    )
}

/// [`atomic_write`], resolving a symlink at the final path component
/// first.
///
/// The truncating write this pair of functions replaces opened the
/// destination with `O_TRUNC`, which follows that link and delivers the
/// bytes to its target. A bare rename replaces the link instead: the
/// operator's link is gone, and whatever it pointed at is left holding
/// the previous contents while the write reports success. Resolving
/// first keeps the file the operator arranged to be written the file
/// that is written.
///
/// This is the spelling for a destination an operator arranges: the
/// configuration bootroot renders into its own tree and an operator may
/// have pointed elsewhere (`.env`, `ca.json` and its template,
/// `openbao.hcl`, the compose overrides, the responder and `OpenBao`
/// Agent configs, `state.json`), and the output paths they name on the
/// command line (`init`'s two, `rotate openbao-recovery --output`).
///
/// Two classes deliberately keep [`atomic_write`]'s bare rename:
///
/// - **Credentials at a path bootroot chose**, inside the secrets tree.
///   A link there is a redirection vector rather than an operator
///   convenience, and the reader reads the path bootroot handed it —
///   which the rename leaves holding the current secret — so following
///   one buys nothing and costs the guarantee. The override credential
///   paths, whose directory an unprivileged user owns, go further and
///   refuse a link outright ([`atomic_rewrite_owned_no_symlink`]).
/// - **Files another writer already publishes by rename**, namely
///   `agent.toml` (since #613) and the issued cert and key (since
///   #593). A link at those paths does not survive the writer that
///   creates the file, so resolving it in the writers that *edit* the
///   file would make the two disagree rather than preserve anything.
///
/// Not a security check: see [`resolve_symlink_destination`].
///
/// # Errors
/// Returns an error under the same conditions as [`atomic_write`], or
/// if the destination's symlink chain cannot be resolved (a cycle, or
/// an unreadable link).
pub async fn atomic_write_through_symlink(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let dest = path.to_path_buf();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || {
        atomic_write_through_symlink_blocking(&dest, &payload, mode)
    })
    .await
    .context("Atomic write task panicked")?
}

/// The blocking half of [`atomic_write_through_symlink`], for callers
/// that are not async.
///
/// # Errors
/// Returns an error under the same conditions as
/// [`atomic_write_through_symlink`].
pub fn atomic_write_through_symlink_blocking(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<()> {
    atomic_write_blocking(&resolve_symlink_destination(path)?, contents, mode)
}

/// [`atomic_replace`], resolving a symlink at the final path component
/// first.
///
/// The same compatibility decision [`atomic_write_through_symlink`]
/// documents — see there for which destinations take it and which keep
/// the bare rename — without the directory flush.
///
/// # Errors
/// Returns an error under the same conditions as [`atomic_replace`], or
/// if the destination's symlink chain cannot be resolved.
pub async fn atomic_replace_through_symlink(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let dest = path.to_path_buf();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || {
        atomic_replace_through_symlink_blocking(&dest, &payload, mode)
    })
    .await
    .context("Atomic replace task panicked")?
}

/// The blocking half of [`atomic_replace_through_symlink`], for callers
/// that are not async.
///
/// # Errors
/// Returns an error under the same conditions as
/// [`atomic_replace_through_symlink`].
pub fn atomic_replace_through_symlink_blocking(
    path: &Path,
    contents: &[u8],
    mode: u32,
) -> Result<()> {
    atomic_replace_blocking(&resolve_symlink_destination(path)?, contents, mode)
}

/// The mode a staged publish should apply at `path`: the mode the file
/// already carries, or `default_mode` when there is no file to read one
/// from.
///
/// A truncating write left an existing destination's mode alone and let
/// the umask decide a fresh create's. A rename installs a *fresh* inode
/// that inherits neither, so every publish replacing such a write has to
/// state a mode — and stating a constant would silently re-widen a file
/// an operator narrowed by hand, or that a restrictive umask created
/// narrow. Reading the destination's own mode back keeps the rewrite
/// case byte-for-byte as it was; `default_mode` covers only the create,
/// which is the one case a host with a non-default umask can observe.
///
/// Not for a file with a mode policy of its own — a key, a certificate,
/// the two `init` outputs — where the policy's constant is the answer
/// and a stale mode on disk must not outlive it.
#[must_use]
pub fn preserved_mode(path: &Path, default_mode: u32) -> u32 {
    std::fs::metadata(path).map_or(default_mode, |meta| meta.permissions().mode() & 0o7777)
}

/// Who owns the inode a staged publish renames into place.
///
/// A rename installs a *fresh* inode, so ownership is never inherited
/// from the file being replaced the way a truncating write left it
/// untouched. Every staged publish therefore has to say where the
/// uid/gid comes from, and the two answers below differ because their
/// files do.
#[derive(Clone, Copy)]
pub enum StagedOwner {
    /// Carry the destination's uid and gid onto the new inode, and
    /// leave a fresh create to the writing process.
    ///
    /// For files with no ownership policy of their own — a `0600`
    /// `agent.toml`, `rotation-state.json`, the fast-poll state,
    /// `state.json` — where the operator's or an earlier writer's
    /// ownership is the only record of who may read them. Re-owning one
    /// to the writer (a `service add` run by root replacing a file the
    /// long-running agent reads) is an outage.
    Destination,
    /// Leave the uid to the writing process and set the group to the
    /// `--cert-group` policy's gid, where it names one.
    ///
    /// For the issued certificate, key and CA bundle, whose group is
    /// dictated by that policy and re-asserted on every write: reading
    /// the gid off the destination instead would let a stale group
    /// outlive the policy that replaced it. All three land world- or
    /// group-readable by the policy, so no consumer loses access to a
    /// file it could read before.
    PolicyGroup(Option<u32>),
}

/// Whether the directory entry a staged publish creates is flushed
/// before the write is reported as done.
///
/// The flush is a disk round trip on every write, so it is a decision
/// per file rather than a default — see [`sync_parent_dir`].
#[derive(Clone, Copy)]
pub enum StagedDurability {
    /// `sync_parent_dir` after the rename: the file is read back to
    /// resume, so the published name has to survive a power loss and
    /// not merely a clean replacement.
    FlushDirectory,
    /// Rename and stop: a crash that loses the new directory entry
    /// leaves the previous file in place and costs a rewrite — a
    /// reissued certificate, the next sync's `eab.json` — rather than
    /// an outage.
    RenameOnly,
}

/// Publishes `contents` at `path` by staging a temporary in the same
/// directory, applying `mode` and `owner` to it there, and `rename`ing
/// it over the destination.
///
/// This is the one staging implementation in the crate. Every
/// production file bootroot publishes reaches disk through it —
/// `state.json`, `rotation-state.json`, `agent.toml`, the fast-poll
/// state, the two `init` outputs, the issued certificate, key and CA
/// bundle, and the configuration `init` and the rotation commands
/// generate (`.env`, `ca.json` and its template, `openbao.hcl`, the
/// responder config, the `OpenBao` Agent configs and credentials, the
/// compose overrides). The destination name is only ever observed as
/// the previous file or the complete new one.
///
/// Callers reach it through one of the four wrappers rather than
/// directly: [`atomic_write`]/[`atomic_write_blocking`] for a file read
/// back to resume, [`atomic_replace`]/[`atomic_replace_blocking`] for
/// one that can be regenerated. `crate::cert_group` is the exception,
/// calling in with [`StagedOwner::PolicyGroup`] for the three files the
/// `--cert-group` policy owns.
///
/// The staged file is created by `tempfile` at `0600` and reaches
/// `mode` only while it is still at its temporary name, so a wider
/// `mode` is never observable at the destination — the property issue
/// #593 asked of the key file, and which now holds for every caller.
/// The chown runs before the chmod for the same reason: nothing may
/// sit group-readable under the writer's primary gid, even at the
/// temporary name, before the policy's gid lands. The staged file is
/// `fsync`ed last of all, once both have been applied, so a publish
/// that survives a crash carries the ownership and mode it was
/// published with rather than the temporary's defaults.
///
/// The temporary is removed if any step before the rename fails
/// (`NamedTempFile` deletes on drop), so a failed publish leaves
/// neither a torn destination nor a stray sibling.
///
/// # Errors
/// Returns an error if the temp file cannot be created, written,
/// chowned, permissioned or renamed, or if the containing directory
/// cannot be flushed under [`StagedDurability::FlushDirectory`].
pub fn publish_staged_blocking(
    path: &Path,
    contents: &[u8],
    mode: u32,
    owner: StagedOwner,
    durability: StagedDurability,
) -> Result<()> {
    let parent = parent_dir(path);
    let mut tmp = tempfile::NamedTempFile::new_in(&parent)
        .with_context(|| format!("Failed to create temp file in {}", parent.display()))?;
    tmp.as_file_mut()
        .write_all(contents)
        .with_context(|| format!("Failed to write temp file for {}", path.display()))?;
    match owner {
        StagedOwner::Destination => {
            // A destination that is missing, or cannot be stat'd,
            // leaves the staged file with the writing process's own
            // ownership rather than being chowned to a guess.
            if let Some((dest_uid, dest_gid)) =
                std::fs::metadata(path).ok().map(|m| (m.uid(), m.gid()))
            {
                let tmp_meta = std::fs::metadata(tmp.path())
                    .with_context(|| format!("Failed to stat temp file for {}", path.display()))?;
                // Skipping a chown that would change nothing keeps an
                // unprivileged writer whose ownership already matches
                // from failing on a call it did not need to make.
                if tmp_meta.uid() != dest_uid || tmp_meta.gid() != dest_gid {
                    std::os::unix::fs::chown(tmp.path(), Some(dest_uid), Some(dest_gid))
                        .with_context(|| {
                            format!(
                                "Failed to preserve existing uid={dest_uid} gid={dest_gid} on {}",
                                path.display()
                            )
                        })?;
                }
            }
        }
        StagedOwner::PolicyGroup(Some(gid)) => {
            std::os::unix::fs::chown(tmp.path(), None, Some(gid)).with_context(|| {
                format!("Failed to chown {} to gid {gid}", tmp.path().display())
            })?;
        }
        StagedOwner::PolicyGroup(None) => {}
    }
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode)).with_context(
        || {
            format!(
                "Failed to set mode {mode:o} on temp file for {}",
                path.display()
            )
        },
    )?;
    // Last of the three, after the bytes *and* the uid/gid/mode: `fsync`
    // persists the whole inode, so a flush taken before the chown and
    // the chmod leaves those two changes in memory only. A crash could
    // then recover a durably named, fully written file wearing the
    // temporary's own `0600` and the writer's primary group instead of
    // the mode and the policy gid it was published with — the directory
    // flush below makes the *name* durable and says nothing about the
    // inode it points at.
    tmp.as_file_mut()
        .sync_all()
        .with_context(|| format!("Failed to fsync temp file for {}", path.display()))?;
    tmp.persist(path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to rename temp file to {}: {}",
            path.display(),
            e.error
        )
    })?;
    match durability {
        StagedDurability::FlushDirectory => sync_parent_dir(path)?,
        StagedDurability::RenameOnly => {}
    }
    Ok(())
}

/// Ensures the secrets directory exists and has secure permissions.
///
/// This helper is for bootroot-internal config artifacts (infra
/// `OpenBao` Agent configs, template files, etc.) that must remain
/// operator-only. Cert/key parent directories on the agent's
/// issuance/rotation path go through
/// [`crate::cert_group::ensure_key_parent_dir`] /
/// [`crate::cert_group::ensure_cert_parent_dir`] instead, so the
/// `--cert-group` policy can widen the mode/owner.
///
/// # Errors
/// Returns an error if the directory cannot be created or permissions cannot be set.
pub async fn ensure_secrets_dir(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .await
        .with_context(|| format!("Failed to create secrets dir {}", path.display()))?;
    fs::set_permissions(path, std::fs::Permissions::from_mode(SECRETS_DIR_MODE))
        .await
        .context("Failed to set secrets dir permissions")?;
    Ok(())
}

/// Applies restrictive permissions (`0600`) to a file.
///
/// Used by callers that store operator-only secrets adjacent to the
/// service cert/key — `agent.toml`, `agent.hcl`, the `OpenBao` agent
/// `.ctmpl` files, etc. The issued cert/key files themselves go
/// through [`write_cert_and_key`] and pick up
/// [`crate::cert_group::CertGroupPolicy`] ownership instead.
///
/// # Errors
/// Returns an error if permissions cannot be set.
pub async fn set_key_permissions(path: &Path) -> Result<()> {
    fs::set_permissions(path, std::fs::Permissions::from_mode(KEY_FILE_MODE))
        .await
        .context("Failed to set key file permissions")?;
    Ok(())
}

/// Writes the certificate and key to disk under the given policy.
///
/// With [`CertGroupPolicy::none`] this preserves the historical
/// host-local default: `0700` parent directories, `0600` key file,
/// `0644` cert file, owned by the agent's uid/gid.
///
/// With an active policy, the parent directories become group-
/// traversable (`0750` for the key parent; `0755` for a distinct
/// cert parent, `0750` when the cert and key share a parent), the
/// key file becomes group-readable (`0640`), and group ownership of
/// all four is set to the configured gid. Mode/ownership is re-
/// applied on every call, so a rotation immediately re-asserts the
/// policy after operator-side `chmod`/`chown` interventions.
///
/// # Errors
/// Returns an error if directories cannot be created, files cannot be written,
/// or key permissions cannot be applied.
pub async fn write_cert_and_key(
    cert_path: &Path,
    key_path: &Path,
    cert_pem: &str,
    key_pem: &str,
    policy: CertGroupPolicy,
) -> Result<()> {
    let cert_dir = cert_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Cert path has no parent directory"))?;
    let key_dir = key_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Key path has no parent directory"))?;

    cert_group::ensure_key_parent_dir(key_dir, policy).await?;
    cert_group::ensure_cert_parent_dir(cert_dir, key_dir, policy).await?;

    cert_group::write_cert_file(cert_path, cert_pem, policy).await?;
    cert_group::write_key_file(key_path, key_pem, policy).await?;

    Ok(())
}

/// Writes a CA bundle to disk, creating parent directories as needed.
///
/// Always sets the mode to [`cert_group::CA_BUNDLE_FILE_MODE`] (`0o644`),
/// regardless of `policy`. CA bundles are public trust material, and
/// re-asserting the mode on every write means a rotation overrides
/// any stricter mode left behind by an earlier writer (notably
/// `bootroot-remote`'s bootstrap path, which creates the file via
/// `write_secret_file` at `0o600`). When `policy` is active, also
/// `chown`s the file to the policy's gid so cert-group members can
/// read the bundle alongside the cert and key.
///
/// The bundle itself is published by
/// [`cert_group::write_bundle_file`], which stages it beside the
/// destination and renames it into place with the mode and owner
/// already applied. The agent re-reads this file to rebuild its trust
/// store while a rotation may be rewriting it, so the destination name
/// must never hold a truncated chain.
///
/// # Errors
/// Returns an error if the directory cannot be created, the bundle
/// cannot be written, or the mode/owner cannot be applied.
pub async fn write_ca_bundle(
    bundle_path: &Path,
    bundle_pem: &str,
    policy: CertGroupPolicy,
) -> Result<()> {
    let bundle_dir = bundle_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("CA bundle path has no parent directory"))?;
    fs::create_dir_all(bundle_dir)
        .await
        .with_context(|| format!("Failed to create CA bundle dir {}", bundle_dir.display()))?;
    cert_group::write_bundle_file(bundle_path, bundle_pem, policy).await
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;
    use crate::cert_group::CA_BUNDLE_FILE_MODE;

    #[tokio::test]
    async fn test_ensure_secrets_dir_permissions() {
        let dir = tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");

        ensure_secrets_dir(&secrets_dir).await.unwrap();

        let mode = std::fs::metadata(&secrets_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, SECRETS_DIR_MODE);
    }

    #[tokio::test]
    async fn test_set_key_permissions() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("key.pem");
        fs::write(&key_path, "key-data").await.unwrap();

        set_key_permissions(&key_path).await.unwrap();

        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_FILE_MODE);
    }

    #[tokio::test]
    async fn test_write_cert_and_key_default_policy_preserves_modes() {
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("certs").join("cert.pem");
        let key_path = dir.path().join("secrets").join("key.pem");

        write_cert_and_key(
            &cert_path,
            &key_path,
            "cert-data",
            "key-data",
            CertGroupPolicy::none(),
        )
        .await
        .unwrap();

        let cert_contents = fs::read_to_string(&cert_path).await.unwrap();
        let key_contents = fs::read_to_string(&key_path).await.unwrap();
        assert_eq!(cert_contents, "cert-data");
        assert_eq!(key_contents, "key-data");

        let key_dir_mode = std::fs::metadata(key_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let cert_dir_mode = std::fs::metadata(cert_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        let cert_mode = std::fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_dir_mode, SECRETS_DIR_MODE);
        assert_eq!(cert_dir_mode, SECRETS_DIR_MODE);
        assert_eq!(key_mode, KEY_FILE_MODE);
        assert_eq!(cert_mode, 0o644);
    }

    #[tokio::test]
    async fn test_write_cert_and_key_group_policy_applies_relaxed_modes() {
        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            // Test fixtures without a supplementary gid (single-gid CI
            // runners) cannot exercise the chown path. The
            // e2e-extended job provisions a dedicated supplementary
            // group and still gets coverage.
            return;
        };
        let dir = tempdir().unwrap();
        let cert_path = dir.path().join("certs").join("cert.pem");
        let key_path = dir.path().join("secrets").join("key.pem");

        write_cert_and_key(
            &cert_path,
            &key_path,
            "cert-data",
            "key-data",
            CertGroupPolicy::with_gid(gid),
        )
        .await
        .unwrap();

        let key_dir_mode = std::fs::metadata(key_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let cert_dir_mode = std::fs::metadata(cert_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        let cert_mode = std::fs::metadata(&cert_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_dir_mode, crate::cert_group::KEY_DIR_MODE_GROUP);
        assert_eq!(cert_dir_mode, crate::cert_group::CERT_DIR_MODE_GROUP);
        assert_eq!(key_mode, crate::cert_group::KEY_FILE_MODE_GROUP);
        assert_eq!(cert_mode, 0o644);
    }

    /// Re-running `write_cert_and_key` (the rotation case) must
    /// re-assert the policy. This guards the issue #593 root cause:
    /// rotation reverting any operator-side `chmod`/`chown`.
    #[tokio::test]
    async fn test_write_cert_and_key_reapplies_policy_on_second_call() {
        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().unwrap();
        let shared = dir.path().join("certs");
        let cert_path = shared.join("svc.pem");
        let key_path = shared.join("svc.key");

        write_cert_and_key(
            &cert_path,
            &key_path,
            "c1",
            "k1",
            CertGroupPolicy::with_gid(gid),
        )
        .await
        .unwrap();

        // Operator-side regression: hand-tighten back to the default.
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Rotation re-runs write_cert_and_key with the same policy:
        write_cert_and_key(
            &cert_path,
            &key_path,
            "c2",
            "k2",
            CertGroupPolicy::with_gid(gid),
        )
        .await
        .unwrap();

        let key_mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(&shared).unwrap().permissions().mode() & 0o777;
        assert_eq!(key_mode, crate::cert_group::KEY_FILE_MODE_GROUP);
        assert_eq!(dir_mode, crate::cert_group::KEY_DIR_MODE_GROUP);
    }

    /// CA bundles are public trust material, so the mode must be
    /// `0o644` whether or not a `--cert-group` policy is in effect.
    #[tokio::test]
    async fn write_ca_bundle_no_policy_sets_world_readable_mode() {
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");

        write_ca_bundle(&bundle_path, "BUNDLE", CertGroupPolicy::none())
            .await
            .unwrap();

        let mode = std::fs::metadata(&bundle_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, CA_BUNDLE_FILE_MODE);
        let contents = fs::read_to_string(&bundle_path).await.unwrap();
        assert_eq!(contents, "BUNDLE");
    }

    /// Rotation must re-assert the mode. The issue #608 root cause:
    /// `bootroot-remote` creates the bundle at `0o600`, then the
    /// agent's rotation only rewrote the bytes without restoring the
    /// mode, leaving the container EACCES on the bundle. Seeding the
    /// file at `0o600` first locks in that the rotation widens it.
    #[tokio::test]
    async fn write_ca_bundle_re_asserts_mode_on_rotation_over_0600_seed() {
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        // Seed as a 0o600 file (the bootstrap-time `write_secret_file`
        // state described in the issue).
        fs::write(&bundle_path, "stale").await.unwrap();
        fs::set_permissions(&bundle_path, std::fs::Permissions::from_mode(0o600))
            .await
            .unwrap();

        write_ca_bundle(&bundle_path, "FRESH", CertGroupPolicy::none())
            .await
            .unwrap();

        let mode = std::fs::metadata(&bundle_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, CA_BUNDLE_FILE_MODE);
        let contents = fs::read_to_string(&bundle_path).await.unwrap();
        assert_eq!(contents, "FRESH");
    }

    /// The bundle arrives by rename from a staged temporary, so an
    /// agent rebuilding its trust store mid-rotation reads either the
    /// previous chain or the complete new one. A changed inode is what
    /// distinguishes that from the `fs::write` this replaced, and an
    /// otherwise empty directory is what proves the temporary did not
    /// survive the publish.
    #[tokio::test]
    async fn write_ca_bundle_publishes_a_new_inode_and_leaves_no_temporary() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");
        write_ca_bundle(&bundle_path, "FIRST", CertGroupPolicy::none())
            .await
            .unwrap();
        let first_inode = std::fs::metadata(&bundle_path).unwrap().ino();

        write_ca_bundle(&bundle_path, "SECOND", CertGroupPolicy::none())
            .await
            .unwrap();

        assert_eq!(
            fs::read_to_string(&bundle_path).await.unwrap(),
            "SECOND",
            "the rename must publish the new chain"
        );
        assert_ne!(std::fs::metadata(&bundle_path).unwrap().ino(), first_inode);
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("ca-bundle.pem")]);
    }

    /// `write_ca_bundle` creates the parent directory before staging,
    /// so the very first bundle of a deployment lands even though the
    /// staged temporary needs a directory to be created in.
    #[tokio::test]
    async fn write_ca_bundle_creates_a_missing_parent_directory() {
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("nested").join("ca-bundle.pem");

        write_ca_bundle(&bundle_path, "BUNDLE", CertGroupPolicy::none())
            .await
            .unwrap();

        assert_eq!(fs::read_to_string(&bundle_path).await.unwrap(), "BUNDLE");
    }

    /// The common case: nothing to resolve, so the caller stages and
    /// renames at exactly the path it was given.
    #[test]
    fn resolve_symlink_destination_passes_a_regular_file_through() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("plain.txt");
        std::fs::write(&path, "x").unwrap();

        assert_eq!(resolve_symlink_destination(&path).unwrap(), path);
        assert_eq!(
            resolve_symlink_destination(&dir.path().join("absent.txt")).unwrap(),
            dir.path().join("absent.txt"),
            "a destination that does not exist yet resolves to itself"
        );
    }

    /// A link resolves to the file behind it, so the rename that follows
    /// replaces the target and leaves the link pointing at it.
    #[test]
    fn resolve_symlink_destination_follows_a_link_to_its_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        std::fs::write(&target, "x").unwrap();
        let link = dir.path().join("link.txt");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert_eq!(
            resolve_symlink_destination(&link).unwrap(),
            std::fs::canonicalize(&target).unwrap()
        );
    }

    /// A dangling link still names where the operator wants the file.
    /// `canonicalize` cannot say so — there is nothing to resolve
    /// against — so the link text is read instead, absolute and
    /// relative alike, and the caller publishes at the target the way
    /// the truncating write's `O_CREAT` created it.
    #[test]
    fn resolve_symlink_destination_follows_a_dangling_link_to_its_target() {
        let dir = tempdir().unwrap();
        let absolute = dir.path().join("absolute.txt");
        std::os::unix::fs::symlink(dir.path().join("absent.txt"), &absolute).unwrap();
        assert_eq!(
            resolve_symlink_destination(&absolute).unwrap(),
            dir.path().join("absent.txt")
        );

        let relative = dir.path().join("relative.txt");
        std::os::unix::fs::symlink("sub/absent.txt", &relative).unwrap();
        assert_eq!(
            resolve_symlink_destination(&relative).unwrap(),
            dir.path().join("sub").join("absent.txt"),
            "a relative link is resolved against its own directory"
        );
    }

    /// A chain of dangling links is followed to its end, so the write
    /// replaces neither link on the way.
    #[test]
    fn resolve_symlink_destination_follows_a_dangling_link_chain() {
        let dir = tempdir().unwrap();
        let end = dir.path().join("absent.txt");
        let middle = dir.path().join("middle.txt");
        let head = dir.path().join("head.txt");
        std::os::unix::fs::symlink(&end, &middle).unwrap();
        std::os::unix::fs::symlink(&middle, &head).unwrap();

        assert_eq!(resolve_symlink_destination(&head).unwrap(), end);
    }

    /// A cycle has no end to follow to, and every name in it is a link
    /// a rename would destroy. The truncating write answered `ELOOP`
    /// here; resolution fails rather than handing back a path the
    /// caller would publish over.
    #[test]
    fn resolve_symlink_destination_rejects_a_symlink_cycle() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();

        let err = resolve_symlink_destination(&a).unwrap_err().to_string();
        assert!(
            err.contains("Too many levels of symbolic links"),
            "unexpected error: {err}"
        );
        assert!(
            std::fs::symlink_metadata(&a)
                .unwrap()
                .file_type()
                .is_symlink(),
            "resolution must not touch the links it refuses to follow"
        );

        let self_link = dir.path().join("self.txt");
        std::os::unix::fs::symlink(&self_link, &self_link).unwrap();
        assert!(
            resolve_symlink_destination(&self_link).is_err(),
            "a link pointing at itself is a cycle too"
        );
    }

    /// `atomic_write` must leave the destination at the supplied mode
    /// and the requested contents, both for the create case and for
    /// the overwrite case (rotation).
    #[tokio::test]
    async fn atomic_write_creates_and_overwrites_with_mode() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("agent.toml");

        super::atomic_write(&path, b"first", KEY_FILE_MODE)
            .await
            .unwrap();
        let contents = fs::read_to_string(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(contents, "first");
        assert_eq!(mode, KEY_FILE_MODE);

        super::atomic_write(&path, b"second", KEY_FILE_MODE)
            .await
            .unwrap();
        let contents = fs::read_to_string(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(contents, "second");
        assert_eq!(mode, KEY_FILE_MODE);
    }

    /// `atomic_replace` publishes the same way `atomic_write` does —
    /// fresh inode, requested mode, no torn destination — and differs
    /// only in declining the directory flush, which leaves no
    /// observable trace to assert on. Pinning the rest here keeps the
    /// no-flush spelling from drifting into a plain `fs::write` on the
    /// assumption that "not durable" means "not staged".
    #[tokio::test]
    async fn atomic_replace_creates_and_overwrites_with_mode() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("compose.override.yml");

        super::atomic_replace(&path, b"first", 0o644).await.unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "first");
        let first_ino = std::fs::metadata(&path).unwrap().ino();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        super::atomic_replace(&path, b"second", 0o644)
            .await
            .unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "second");
        assert_ne!(
            std::fs::metadata(&path).unwrap().ino(),
            first_ino,
            "a staged publish installs a new inode; an in-place write would not"
        );

        let strays: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok().map(|e| e.file_name()))
            .filter(|name| name != "compose.override.yml")
            .collect();
        assert!(
            strays.is_empty(),
            "staged temporary left behind: {strays:?}"
        );
    }

    /// The two spellings differ in exactly one observable way, and this
    /// pins both halves of it: given a symlinked destination, the
    /// `_through_symlink` wrappers deliver to the target and leave the
    /// link standing — what `O_TRUNC` did — while the bare wrappers
    /// replace the link with the published file, which is what the
    /// `agent.toml` and cert/key writers want.
    #[tokio::test]
    async fn through_symlink_wrappers_deliver_to_the_target_the_bare_ones_replace() {
        let dir = tempdir().unwrap();

        for (name, published) in [("write.env", false), ("replace.env", true)] {
            let target = dir.path().join(format!("target-{name}"));
            let link = dir.path().join(name);
            std::fs::write(&target, b"seed").unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();

            if published {
                super::atomic_replace_through_symlink(&link, b"fresh", 0o644)
                    .await
                    .unwrap();
            } else {
                super::atomic_write_through_symlink(&link, b"fresh", 0o644)
                    .await
                    .unwrap();
            }

            assert!(
                std::fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "{name}: the operator's link must survive the publish"
            );
            assert_eq!(std::fs::read_to_string(&target).unwrap(), "fresh");
            assert_eq!(
                std::fs::metadata(&link).unwrap().permissions().mode() & 0o777,
                0o644,
                "{name}: the mode lands on the target"
            );
        }

        let target = dir.path().join("target-bare");
        let link = dir.path().join("bare");
        std::fs::write(&target, b"seed").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        super::atomic_write(&link, b"fresh", 0o644).await.unwrap();

        assert!(
            !std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "the bare spelling publishes at the name, replacing the link"
        );
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "fresh");
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "seed",
            "and leaves the target alone"
        );
    }

    /// A dangling link is followed to where it points, so a first write
    /// through one creates the target rather than replacing the link —
    /// the `O_CREAT` half of the behaviour being preserved.
    #[test]
    fn through_symlink_wrappers_create_a_dangling_links_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("absent.yml");
        let link = dir.path().join("override.yml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        super::atomic_replace_through_symlink_blocking(&link, b"fresh", 0o644).unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "fresh");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// A cycle has no target to deliver to, so the publish fails the way
    /// the truncating write's `ELOOP` did rather than replacing one of
    /// the links with the file.
    #[test]
    fn through_symlink_wrappers_refuse_a_symlink_cycle() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.env");
        let b = dir.path().join("b.env");
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();

        assert!(super::atomic_write_through_symlink_blocking(&a, b"x", 0o644).is_err());
        assert!(super::atomic_replace_through_symlink_blocking(&a, b"x", 0o644).is_err());
        assert!(
            std::fs::symlink_metadata(&a)
                .unwrap()
                .file_type()
                .is_symlink(),
            "a refused publish must leave the links it would not follow"
        );
    }

    /// `preserved_mode` answers with the destination's own mode where
    /// there is one, and the caller's default only on a create. A
    /// regression here is a rename silently re-widening a file an
    /// operator narrowed — the one property the truncating writes these
    /// publishes replaced got for free.
    #[test]
    fn preserved_mode_reads_the_destination_then_falls_back() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");

        assert_eq!(
            super::preserved_mode(&path, 0o644),
            0o644,
            "a missing destination takes the caller's default"
        );

        std::fs::write(&path, b"{}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            super::preserved_mode(&path, 0o644),
            0o600,
            "an existing destination keeps the mode it carries"
        );
    }

    /// Overwriting an existing file via `atomic_write` must preserve
    /// the destination's gid. The rename otherwise replaces the inode
    /// with one owned by the writer's effective uid/gid — locking out
    /// readers in deployments that rely on group ownership (e.g.
    /// `bootroot-agent` reading an `agent.toml` originally written
    /// under a cert-group gid, then re-run by root). Requires a
    /// supplementary gid (see `one_supplementary_test_gid`).
    #[tokio::test]
    async fn atomic_write_preserves_existing_gid_on_overwrite() {
        use std::os::unix::fs::MetadataExt;

        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("agent.toml");

        super::atomic_write(&path, b"first", KEY_FILE_MODE)
            .await
            .unwrap();
        std::os::unix::fs::chown(&path, None, Some(gid))
            .expect("test process must be able to chgrp to a supplementary gid");
        let pre_meta = std::fs::metadata(&path).unwrap();
        assert_eq!(pre_meta.gid(), gid, "seed gid must take effect");
        let pre_uid = pre_meta.uid();

        super::atomic_write(&path, b"second", KEY_FILE_MODE)
            .await
            .unwrap();

        let post_meta = std::fs::metadata(&path).unwrap();
        assert_eq!(
            post_meta.gid(),
            gid,
            "atomic_write overwrite must preserve existing gid"
        );
        assert_eq!(
            post_meta.uid(),
            pre_uid,
            "atomic_write overwrite must preserve existing uid"
        );
        assert_eq!(
            post_meta.permissions().mode() & 0o777,
            KEY_FILE_MODE,
            "atomic_write overwrite must still apply the requested mode"
        );
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "second");
    }

    /// `atomic_write` must not leave the destination at an
    /// intermediate state if the rename happens to fail — but in the
    /// common success case, the temp sibling must be cleaned up
    /// (i.e. the destination's parent directory contains exactly the
    /// one file after the call).
    #[tokio::test]
    async fn atomic_write_cleans_up_temp_sibling_on_success() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("agent.toml");

        super::atomic_write(&path, b"payload", KEY_FILE_MODE)
            .await
            .unwrap();

        let mut entries = Vec::new();
        let mut rd = fs::read_dir(dir.path()).await.unwrap();
        while let Some(entry) = rd.next_entry().await.unwrap() {
            entries.push(entry.file_name());
        }
        assert_eq!(
            entries.len(),
            1,
            "expected only the final file, got {entries:?}"
        );
        assert_eq!(entries[0], "agent.toml");
    }

    /// The flush itself is not observable from a test — a crash is what
    /// would distinguish it — so this pins the two things that are: it
    /// succeeds on a real directory, and a directory that cannot be
    /// opened is reported instead of passing silently.
    #[test]
    fn sync_parent_dir_flushes_an_existing_directory_and_reports_a_missing_one() {
        let dir = tempdir().unwrap();
        sync_parent_dir(&dir.path().join("published")).unwrap();

        let err = sync_parent_dir(&dir.path().join("nope").join("published")).unwrap_err();
        assert!(
            format!("{err:#}").contains("to fsync it"),
            "a missing directory must be reported, got: {err:#}"
        );
    }

    /// A bare file name has an *empty* parent rather than none, and
    /// `File::open("")` is `ENOENT`. `rotate`'s `state_dir` is that
    /// empty string whenever the state file is given as a bare relative
    /// name, so the cwd fallback is a live path and not a nicety.
    #[test]
    fn sync_parent_dir_resolves_a_bare_file_name_to_the_cwd() {
        assert_eq!(Path::new("published").parent(), Some(Path::new("")));
        sync_parent_dir(Path::new("published")).unwrap();
    }

    /// Drops `dir` to write-and-search-only, the one mode that lets a
    /// publish stage, chown, and rename inside it while the directory
    /// open that [`sync_parent_dir`] performs fails. That makes the
    /// otherwise unobservable flush observable: a writer that skips it
    /// returns `Ok`, and one that performs it returns the `EACCES`.
    ///
    /// Returns `false` where the mode does not bite — an effective root
    /// bypasses the check, and so does a filesystem that ignores modes
    /// — leaving the caller to skip rather than assert a failure that
    /// cannot happen there.
    fn deny_directory_reads(dir: &Path) -> bool {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o300)).unwrap();
        if std::fs::File::open(dir).is_ok() {
            restore_directory_reads(dir);
            return false;
        }
        true
    }

    /// Undoes [`deny_directory_reads`] so the enclosing `TempDir` can
    /// still list the directory when it removes the tree.
    fn restore_directory_reads(dir: &Path) {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// The shared publish path must *call* the flush, not merely have
    /// one available: this is what fails if the `sync_parent_dir` line
    /// is dropped from `atomic_write_blocking`. The rename still lands
    /// — the write is published and then reported undurable, which is
    /// the honest order — so the file is asserted present too.
    #[test]
    fn atomic_write_blocking_reports_a_directory_it_cannot_flush() {
        let dir = tempdir().unwrap();
        let published = dir.path().join("published");
        std::fs::create_dir(&published).unwrap();
        let path = published.join("agent.toml");
        if !deny_directory_reads(&published) {
            return;
        }

        let result = atomic_write_blocking(&path, b"payload", KEY_FILE_MODE);
        restore_directory_reads(&published);

        let err = result.unwrap_err();
        assert!(
            format!("{err:#}").contains("to fsync it"),
            "an unflushable directory must be reported, got: {err:#}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "payload");
    }

    /// The two ownership answers must stay two answers. A destination
    /// seeded with a supplementary gid keeps it under
    /// [`StagedOwner::Destination`] — the case
    /// `atomic_write_preserves_existing_gid_on_overwrite` covers — and
    /// is re-owned to the writer's own gid under
    /// [`StagedOwner::PolicyGroup`], where the `--cert-group` policy is
    /// the authority on the group and a stale one must not outlive it.
    /// Requires a supplementary gid (see `one_supplementary_test_gid`).
    #[test]
    fn publish_staged_re_owns_under_the_policy_and_preserves_under_destination() {
        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().unwrap();
        let seed = |name: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, "first").unwrap();
            std::os::unix::fs::chown(&path, None, Some(gid))
                .expect("test process must be able to chgrp to a supplementary gid");
            path
        };
        let preserved = seed("preserved");
        let re_owned = seed("re-owned");
        let own_gid = std::fs::metadata(&preserved).unwrap().gid();
        assert_eq!(own_gid, gid, "seed gid must take effect");

        publish_staged_blocking(
            &preserved,
            b"second",
            KEY_FILE_MODE,
            StagedOwner::Destination,
            StagedDurability::RenameOnly,
        )
        .unwrap();
        publish_staged_blocking(
            &re_owned,
            b"second",
            KEY_FILE_MODE,
            StagedOwner::PolicyGroup(None),
            StagedDurability::RenameOnly,
        )
        .unwrap();

        assert_eq!(
            std::fs::metadata(&preserved).unwrap().gid(),
            gid,
            "StagedOwner::Destination must carry the destination's gid across the rename"
        );
        assert_ne!(
            std::fs::metadata(&re_owned).unwrap().gid(),
            gid,
            "StagedOwner::PolicyGroup must not inherit the destination's gid"
        );
    }

    /// Same pin for the `O_EXCL` credential writer. Its flush lives in
    /// the `NoClobber` arm of `write_owned_impl` rather than in
    /// `atomic_write_blocking`, so it regresses independently.
    #[tokio::test]
    async fn create_owned_credential_noclobber_reports_a_directory_it_cannot_flush() {
        let dir = tempdir().unwrap();
        let published = dir.path().join("published");
        std::fs::create_dir(&published).unwrap();
        let path = published.join("secret_id");
        if !deny_directory_reads(&published) {
            return;
        }

        let result = create_owned_credential_noclobber(&path, b"sid").await;
        restore_directory_reads(&published);

        let err = result.unwrap_err();
        assert!(
            format!("{err:#}").contains("to fsync it"),
            "an unflushable directory must be reported, got: {err:#}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "sid");
    }

    /// And for the rotation rewrite, whose flush is a third call site.
    #[tokio::test]
    async fn atomic_rewrite_owned_no_symlink_reports_a_directory_it_cannot_flush() {
        let dir = tempdir().unwrap();
        let published = dir.path().join("published");
        std::fs::create_dir(&published).unwrap();
        let path = published.join("secret_id");
        std::fs::write(&path, b"old").unwrap();
        if !deny_directory_reads(&published) {
            return;
        }

        let result = atomic_rewrite_owned_no_symlink(&path, b"new", KEY_FILE_MODE).await;
        restore_directory_reads(&published);

        let err = result.unwrap_err();
        assert!(
            format!("{err:#}").contains("to fsync it"),
            "an unflushable directory must be reported, got: {err:#}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    /// The counterpart: `write_owned_file_replace` declines the flush,
    /// so the same unreadable directory must *not* fail it. This is
    /// what catches the flush being added there by reflex, restoring a
    /// per-sync disk round trip the site decided against.
    #[tokio::test]
    async fn write_owned_file_replace_does_not_flush_the_directory() {
        let dir = tempdir().unwrap();
        let published = dir.path().join("published");
        std::fs::create_dir(&published).unwrap();
        let path = published.join("eab.json");
        std::fs::write(&path, b"old").unwrap();
        if !deny_directory_reads(&published) {
            return;
        }

        let result = write_owned_file_replace(&path, b"new", KEY_FILE_MODE).await;
        restore_directory_reads(&published);

        result.expect("the replace writer must not open the directory");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn path_is_within_matches_component_boundaries() {
        assert!(path_is_within(Path::new("/a/b/c"), Path::new("/a/b")).unwrap());
        assert!(path_is_within(Path::new("/a/b"), Path::new("/a/b")).unwrap());
        // `/a/bc` must not count as inside `/a/b` (component-wise).
        assert!(!path_is_within(Path::new("/a/bc"), Path::new("/a/b")).unwrap());
        // Lexical `..` is resolved before the comparison.
        assert!(!path_is_within(Path::new("/a/b/../c/secret_id"), Path::new("/a/b")).unwrap());
    }

    #[tokio::test]
    async fn create_owned_credential_noclobber_writes_0600_and_rejects_reuse() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("agent-svc").join("secret_id");
        std::fs::create_dir(target.parent().unwrap()).unwrap();

        create_owned_credential_noclobber(&target, b"sid-1")
            .await
            .unwrap();
        assert_eq!(fs::read_to_string(&target).await.unwrap(), "sid-1");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_FILE_MODE);

        // A pre-existing regular file at the target is a hard error.
        let err = create_owned_credential_noclobber(&target, b"sid-2")
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("Refusing to overwrite"),
            "no-clobber must reject an existing file, got: {err:#}"
        );
        assert_eq!(
            fs::read_to_string(&target).await.unwrap(),
            "sid-1",
            "the original file must be left untouched"
        );
    }

    #[tokio::test]
    async fn create_owned_credential_noclobber_rejects_non_absolute() {
        let err = create_owned_credential_noclobber(Path::new("relative/secret_id"), b"x")
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("must be absolute"));
    }

    #[tokio::test]
    async fn create_owned_credential_noclobber_rejects_missing_parent() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("nope").join("secret_id");
        let err = create_owned_credential_noclobber(&target, b"x")
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("parent directory is missing"));
    }

    #[tokio::test]
    async fn create_owned_credential_noclobber_refuses_symlink_at_target() {
        let dir = tempdir().unwrap();
        let parent = dir.path().join("agent-svc");
        std::fs::create_dir(&parent).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, "victim").unwrap();
        let target = parent.join("secret_id");
        std::os::unix::fs::symlink(&elsewhere, &target).unwrap();

        let err = create_owned_credential_noclobber(&target, b"sid")
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("Refusing to overwrite"),
            "a planted symlink must not be followed, got: {err:#}"
        );
        // The symlink target must be untouched (write not redirected).
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "victim");
    }

    /// Rotation's in-place rewrite must refuse a symlink planted at the
    /// credential path and never redirect the write through it.
    #[tokio::test]
    async fn atomic_rewrite_owned_no_symlink_rejects_symlink() {
        let dir = tempdir().unwrap();
        let parent = dir.path().join("agent-svc");
        std::fs::create_dir(&parent).unwrap();
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, "victim").unwrap();
        let target = parent.join("secret_id");
        std::os::unix::fs::symlink(&elsewhere, &target).unwrap();

        let err = atomic_rewrite_owned_no_symlink(&target, b"new", KEY_FILE_MODE)
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("Refusing to rewrite a symlink"),
            "a planted symlink must be rejected, got: {err:#}"
        );
        // The symlink target must be untouched (write not redirected).
        assert_eq!(std::fs::read_to_string(&elsewhere).unwrap(), "victim");
    }

    /// The in-place rewrite preserves the existing file's uid/gid and
    /// re-applies `0600`. Gated on a supplementary gid being available.
    #[tokio::test]
    async fn atomic_rewrite_owned_no_symlink_preserves_owner() {
        use std::os::unix::fs::MetadataExt;

        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().unwrap();
        let parent = dir.path().join("agent-svc");
        std::fs::create_dir(&parent).unwrap();
        let target = parent.join("secret_id");
        std::fs::write(&target, "old").unwrap();
        std::os::unix::fs::chown(&target, None, Some(gid))
            .expect("test process must be able to chgrp the seeded file");
        let pre_uid = std::fs::metadata(&target).unwrap().uid();

        atomic_rewrite_owned_no_symlink(&target, b"new", KEY_FILE_MODE)
            .await
            .unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "new");
        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(meta.gid(), gid, "rewrite must preserve the existing gid");
        assert_eq!(
            meta.uid(),
            pre_uid,
            "rewrite must preserve the existing uid"
        );
        assert_eq!(meta.permissions().mode() & 0o777, KEY_FILE_MODE);
    }

    #[tokio::test]
    async fn write_owned_file_replace_overwrites() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("agent-svc").join("eab.json");
        std::fs::create_dir(target.parent().unwrap()).unwrap();

        write_owned_file_replace(&target, b"first", KEY_FILE_MODE)
            .await
            .unwrap();
        write_owned_file_replace(&target, b"second", KEY_FILE_MODE)
            .await
            .unwrap();
        assert_eq!(fs::read_to_string(&target).await.unwrap(), "second");
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, KEY_FILE_MODE);
    }

    /// The fresh override file must be chowned to the parent directory's
    /// owner (a root-created file does not inherit directory ownership),
    /// so a co-located non-root agent can read/rewrite it. Gated on a
    /// supplementary gid being available, like the other ownership tests.
    #[tokio::test]
    async fn create_owned_credential_noclobber_chowns_to_parent_owner() {
        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().unwrap();
        let parent = dir.path().join("agent-svc");
        std::fs::create_dir(&parent).unwrap();
        std::os::unix::fs::chown(&parent, None, Some(gid))
            .expect("test process must be able to chgrp the parent to a supplementary gid");
        let target = parent.join("role_id");

        create_owned_credential_noclobber(&target, b"rid")
            .await
            .unwrap();

        let meta = std::fs::metadata(&target).unwrap();
        assert_eq!(
            meta.gid(),
            gid,
            "fresh file must be chowned to the parent gid"
        );
        assert_eq!(meta.permissions().mode() & 0o777, KEY_FILE_MODE);
    }

    /// Under an active `--cert-group` policy, the bundle file must be
    /// chgrped to the policy's gid and remain at `0o644` (cert-group
    /// members get read access via group membership, everyone else
    /// retains read access because the bundle is public material).
    #[tokio::test]
    async fn write_ca_bundle_with_policy_chowns_to_gid_and_keeps_0644() {
        use std::os::unix::fs::MetadataExt;

        let Some(gid) = crate::cert_group::one_supplementary_test_gid() else {
            return;
        };
        let dir = tempdir().unwrap();
        let bundle_path = dir.path().join("ca-bundle.pem");

        write_ca_bundle(&bundle_path, "BUNDLE", CertGroupPolicy::with_gid(gid))
            .await
            .unwrap();

        let meta = std::fs::metadata(&bundle_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, CA_BUNDLE_FILE_MODE);
        assert_eq!(meta.gid(), gid, "CA bundle gid must match policy");
    }
}
