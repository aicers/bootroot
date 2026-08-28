use std::borrow::Cow;
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
/// delivered its bytes to the link's target. A staged publish `rename`s
/// over the name it is given instead, which replaces the link itself:
/// the operator's link is gone and the target is left holding whatever
/// was written last.
///
/// Writers reach this through [`Destination::operator_named`], which
/// documents which destinations resolve a link and which publish at the
/// name. It is called directly only where the resolved path itself is
/// needed — `bootroot reinit`'s two output preflights, which judge the
/// target's mode before the destructive step, and the two writers behind
/// them, which narrow that same target before writing a credential over
/// it.
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

/// A path a staged publish is aimed at, together with where that path
/// came from — which is what decides whether a symlink at its final
/// component is followed or replaced.
///
/// A truncating write opened the destination with `O_TRUNC`, which
/// follows a link at the final component and delivers the bytes to its
/// target. A staged publish renames over the name it is given instead,
/// which replaces the link: the operator's arrangement is gone, and
/// whatever it pointed at is left holding the previous contents while
/// the write reports success. Both answers are wanted in this crate, and
/// which one a file wants is not a property of the writer that happens
/// to be publishing it. It is a property of where the path came from, so
/// it is stated once, here, by the constructor that names that origin:
///
/// - [`Destination::operator_named`] — a path from a CLI flag, a config
///   value, or a file the operator arranges in bootroot's tree. Resolves
///   a final symlink and publishes at the target.
/// - [`Destination::bootroot_owned`] — a path bootroot derived from the
///   secrets tree or another layout it controls. Publishes at the name.
///
/// There is a third answer, and this type deliberately does not express
/// it. The override credential writers —
/// [`create_owned_credential_noclobber`], [`write_owned_file_replace`]
/// and [`atomic_rewrite_owned_no_symlink`] — publish a service's
/// `role_id`, `secret_id` and `eab.json` into an operator-provisioned,
/// agent-owned directory, and refuse a link at the destination outright
/// rather than resolving it or renaming over it, because the
/// lower-privileged user who owns that directory can plant one. They
/// stage independently and take their ownership from the parent
/// directory, and folding them behind a constructor here would make one
/// of the two callers wrong.
#[derive(Clone, Copy)]
pub struct Destination<'a> {
    path: &'a Path,
    symlink: SymlinkPolicy,
}

/// What a staged publish does about a symlink at the destination's final
/// path component — [`Destination`]'s decision, spelled out.
#[derive(Clone, Copy)]
enum SymlinkPolicy {
    /// Resolve the link and publish at its target, as `O_TRUNC` did.
    Resolve,
    /// Publish at the name, replacing a link found there.
    PublishAtName,
}

impl<'a> Destination<'a> {
    /// Creates a destination the operator named: a path from a CLI flag
    /// or a config value, or a file bootroot renders into its own tree
    /// that an operator may have pointed elsewhere. A symlink at the
    /// final path component is resolved and the bytes are delivered to
    /// its target, leaving the link standing — what the truncating
    /// write these publishes replaced used to do.
    ///
    /// This is what the configuration bootroot generates takes (`.env`,
    /// `ca.json` and its template, `openbao.hcl`, the compose overrides,
    /// the responder and `OpenBao` Agent configs, `state.json`), along
    /// with the output paths named on the command line (`init`'s two,
    /// `rotate openbao-recovery --output`, and `bootroot-remote
    /// bootstrap`'s `agent.toml` destination — that command is what
    /// creates the file on a target host, so a link there is one the
    /// operator put in place and the truncating write followed).
    ///
    /// Not a security check: the link is followed wherever it points,
    /// so a destination an untrusted user can plant is not this
    /// constructor's case (see [`resolve_symlink_destination`], and
    /// [`atomic_rewrite_owned_no_symlink`], which refuses one instead).
    #[must_use]
    pub fn operator_named(path: &'a Path) -> Self {
        Self {
            path,
            symlink: SymlinkPolicy::Resolve,
        }
    }

    /// Creates a destination bootroot derived from a layout it owns:
    /// the secrets tree, or a path it hands a reader itself. The
    /// publish renames over the name, so a symlink found there is
    /// replaced by the published file.
    ///
    /// Two classes take it:
    ///
    /// - **Credentials at a path bootroot chose**, inside the secrets
    ///   tree. A link there is a redirection vector rather than an
    ///   operator convenience, and the reader reads the path bootroot
    ///   handed it — which the rename leaves holding the current secret
    ///   — so following one buys nothing and costs the guarantee.
    /// - **Files another writer already publishes by rename**, namely
    ///   the control node's `agent.toml` (since #613) and the issued
    ///   cert and key (since #593). A link at those paths does not
    ///   survive the writer that creates the file, so resolving it in
    ///   the writers that *edit* the file would make the two disagree
    ///   rather than preserve anything.
    ///
    /// The replacement is decided, not silent: `publish_staged_blocking`
    /// names the link and its former target at `warn` once the rename
    /// has actually replaced it.
    #[must_use]
    pub fn bootroot_owned(path: &'a Path) -> Self {
        Self {
            path,
            symlink: SymlinkPolicy::PublishAtName,
        }
    }

    /// The path and the policy, with the path owned so both can cross
    /// into a `spawn_blocking` closure and be re-borrowed as a
    /// [`Destination`] on the other side. The one copy either half of an
    /// async publish makes of the destination.
    fn to_owned_parts(self) -> (PathBuf, SymlinkPolicy) {
        (self.path.to_path_buf(), self.symlink)
    }

    /// The path the staged temporary is renamed onto: the destination's
    /// own name, or — under [`SymlinkPolicy::Resolve`] — the file a
    /// symlink there points at.
    ///
    /// Borrowed on the publish-at-name side, so the answer costs an
    /// allocation only where a link actually has to be resolved.
    fn publish_path(self) -> Result<Cow<'a, Path>> {
        match self.symlink {
            SymlinkPolicy::PublishAtName => Ok(Cow::Borrowed(self.path)),
            SymlinkPolicy::Resolve => Ok(Cow::Owned(resolve_symlink_destination(self.path)?)),
        }
    }
}

/// Writes `contents` to `dest` atomically by staging it in a sibling
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
/// The mode [`StagedMode`] resolves to is on the staged file before the
/// rename so the on-disk mode never changes after the file appears at
/// the destination. When the destination already exists, the existing
/// uid/gid is also re-applied to the staged file before the rename so
/// the caller does not silently re-own the destination to the writer's
/// effective uid/gid (e.g. a `service add` run by root replacing an
/// agent-readable file with a root-owned `0600` file the long-running
/// agent process can no longer read).
///
/// Whether a symlink at the destination is resolved or replaced is
/// [`Destination`]'s decision, taken by the constructor the caller
/// names, not this function's.
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
/// renamed, if the containing directory cannot be flushed, or if an
/// [`Destination::operator_named`] destination's symlink chain cannot be
/// resolved (a cycle, or an unreadable link).
pub async fn atomic_write(dest: Destination<'_>, contents: &[u8], mode: StagedMode) -> Result<()> {
    // Owned once, to move into the blocking task. The blocking half
    // borrows, so this is the only copy either path makes.
    let (path, symlink) = dest.to_owned_parts();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || {
        atomic_write_blocking(
            Destination {
                path: &path,
                symlink,
            },
            &payload,
            mode,
        )
    })
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
/// One spelling of [`publish_staged_blocking`], the crate's
/// general-purpose staging publisher — see there for the two decisions
/// this one makes ([`StagedOwner::Destination`] and
/// [`StagedDurability::FlushDirectory`]) and why, and for the staged
/// writers that publish outside it.
///
/// # Errors
/// Returns an error under the same conditions as [`atomic_write`].
pub fn atomic_write_blocking(
    dest: Destination<'_>,
    contents: &[u8],
    mode: StagedMode,
) -> Result<()> {
    publish_staged_blocking(
        &dest.publish_path()?,
        contents,
        mode,
        StagedOwner::Destination,
        StagedDurability::FlushDirectory,
    )
}

/// Writes `contents` to `dest` exactly as [`atomic_write`] does, and
/// establishes `owner` on the staged inode before the rename.
///
/// The opt-in counterpart of [`atomic_write`], for the five protected
/// registrar-internal files. Where [`atomic_write`] preserves an
/// existing destination's owner and leaves a fresh one to the writing
/// process, this asks for a stated uid and gid and *fails* if it cannot
/// get them: an unprivileged process publishes nothing rather than a
/// credential it owns itself. See [`FixedOwner`] for why that is the
/// right answer for those files and the wrong one for everything else,
/// and [`StagedOwner::Fixed`] for where in the sequence the chown runs.
///
/// A pre-existing destination owned by somebody else is converged, not
/// preserved: the published file carries `owner` whatever was there
/// before. That is deliberate for a protected file — the prior owner is
/// the misconfiguration being corrected.
///
/// # Errors
/// Returns an error under the same conditions as [`atomic_write`], and
/// additionally when the staged file cannot be given `owner` — the
/// `EPERM` a process without `CAP_CHOWN` gets. The destination is
/// untouched in that case, since the chown precedes the rename.
pub async fn atomic_write_fixed_owner(
    dest: Destination<'_>,
    contents: &[u8],
    mode: StagedMode,
    owner: FixedOwner,
) -> Result<()> {
    // Owned once, to move into the blocking task, exactly as
    // `atomic_write` does.
    let (path, symlink) = dest.to_owned_parts();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || {
        publish_staged_blocking(
            &Destination {
                path: &path,
                symlink,
            }
            .publish_path()?,
            &payload,
            mode,
            StagedOwner::Fixed(owner),
            StagedDurability::FlushDirectory,
        )
    })
    .await
    .context("Fixed-owner atomic write task panicked")?
}

/// Writes `contents` to `dest` exactly as [`atomic_write`] does, and
/// establishes the containing directory's owner on the staged inode
/// before the rename.
///
/// For a file bootroot writes into the secrets tree that an infra
/// container reads: step-ca, every `step` helper and both `OpenBao`
/// Agent sidecars are launched as the uid that owns that tree, so a
/// file they have to open carries it too. See
/// [`StagedOwner::ContainingDir`] for why this is a policy rather than
/// the destination-preserving default, and why it is a no-op whenever
/// bootroot is already that owner.
///
/// # Errors
/// Returns an error under the same conditions as [`atomic_write`], and
/// additionally when the directory cannot be stat'd or the staged file
/// cannot be given its owner. The destination is untouched in that
/// case, since the chown precedes the rename.
pub async fn atomic_write_dir_owner(
    dest: Destination<'_>,
    contents: &[u8],
    mode: StagedMode,
) -> Result<()> {
    // Owned once, to move into the blocking task, exactly as
    // `atomic_write` does.
    let (path, symlink) = dest.to_owned_parts();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || {
        publish_staged_blocking(
            &Destination {
                path: &path,
                symlink,
            }
            .publish_path()?,
            &payload,
            mode,
            StagedOwner::ContainingDir,
            StagedDurability::FlushDirectory,
        )
    })
    .await
    .context("Directory-owner atomic write task panicked")?
}

/// Publishes `contents` at `dest` by rename under the containing
/// directory's owner, **without** flushing the containing directory.
///
/// [`atomic_replace`]'s pairing of decisions with
/// [`atomic_write_dir_owner`]'s ownership: the writer for regenerable
/// configuration that an infra container reads — an `OpenBao` Agent
/// template, an `agent.hcl`, the responder's rendered config — where a
/// torn read matters and a lost directory entry costs a re-run.
///
/// # Errors
/// Returns an error under the same conditions as
/// [`atomic_write_dir_owner`], except that no directory flush is
/// attempted.
pub async fn atomic_replace_dir_owner(
    dest: Destination<'_>,
    contents: &[u8],
    mode: StagedMode,
) -> Result<()> {
    // Owned once, to move into the blocking task, exactly as
    // `atomic_write` does.
    let (path, symlink) = dest.to_owned_parts();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || {
        publish_staged_blocking(
            &Destination {
                path: &path,
                symlink,
            }
            .publish_path()?,
            &payload,
            mode,
            StagedOwner::ContainingDir,
            StagedDurability::RenameOnly,
        )
    })
    .await
    .context("Directory-owner atomic replace task panicked")?
}

/// The blocking half of [`atomic_replace_dir_owner`], for callers that
/// are not async.
///
/// One spelling of [`publish_staged_blocking`] — see there for the two
/// decisions this one makes ([`StagedOwner::ContainingDir`] and
/// [`StagedDurability::RenameOnly`]) and why.
///
/// # Errors
/// Returns an error under the same conditions as
/// [`atomic_replace_dir_owner`].
pub fn atomic_replace_dir_owner_blocking(
    dest: Destination<'_>,
    contents: &[u8],
    mode: StagedMode,
) -> Result<()> {
    publish_staged_blocking(
        &dest.publish_path()?,
        contents,
        mode,
        StagedOwner::ContainingDir,
        StagedDurability::RenameOnly,
    )
}

/// Publishes `contents` at `dest` by rename, **without** flushing the
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
pub async fn atomic_replace(
    dest: Destination<'_>,
    contents: &[u8],
    mode: StagedMode,
) -> Result<()> {
    // Owned once, to move into the blocking task, exactly as
    // `atomic_write` does.
    let (path, symlink) = dest.to_owned_parts();
    let payload = contents.to_vec();
    tokio::task::spawn_blocking(move || {
        atomic_replace_blocking(
            Destination {
                path: &path,
                symlink,
            },
            &payload,
            mode,
        )
    })
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
pub fn atomic_replace_blocking(
    dest: Destination<'_>,
    contents: &[u8],
    mode: StagedMode,
) -> Result<()> {
    publish_staged_blocking(
        &dest.publish_path()?,
        contents,
        mode,
        StagedOwner::Destination,
        StagedDurability::RenameOnly,
    )
}

/// Where the mode of the inode a staged publish renames into place
/// comes from.
///
/// A truncating write left an existing destination's mode alone and let
/// the umask decide a fresh create's: `open(2)` asks for `0666` and the
/// kernel subtracts the process umask. A rename installs a *fresh*
/// inode that inherits neither, so every publish replacing such a write
/// has to say where its mode comes from — and naming one constant would
/// silently re-widen a file an operator narrowed by hand, or that a
/// restrictive umask created narrow.
///
/// The three answers below are the three things a file in this crate
/// can have to say about its mode. Only [`StagedMode::Policy`] is a
/// decision about the file's contents; the other two exist to reproduce,
/// across a rename, what the truncating write got from the environment
/// for free.
#[derive(Clone, Copy)]
pub enum StagedMode {
    /// The file has a mode policy: apply exactly this, on create and on
    /// rewrite alike.
    ///
    /// For a key, a certificate, the two `init` outputs,
    /// `rotation-state.json` — anything whose mode is a property of what
    /// it holds rather than of the host it was created on. A stale mode
    /// on disk must not outlive the policy, so the constant is
    /// re-asserted on every publish.
    Policy(u32),
    /// No policy. An existing destination keeps its own mode; a fresh
    /// create takes what `open(2)` gives `0666` under the process umask
    /// — exactly what the truncating write this machinery replaced
    /// produced.
    ///
    /// For the files bootroot renders whose mode nobody decided:
    /// `state.json`, `ca.json`, `openbao.hcl`, the compose overrides,
    /// `init`'s rollback restore. A host with a restrictive umask
    /// created these narrow and must keep getting them narrow.
    PreserveOrUmask,
    /// No policy on rewrite, but a stated create mode: an existing
    /// destination keeps its own mode; a fresh create takes exactly
    /// this, umask or no umask.
    ///
    /// For a file whose create mode has to be at least as narrow as any
    /// umask would make it — the `0600` `agent.toml` editors, `.env`
    /// with its `POSTGRES_PASSWORD` — while an operator who widened the
    /// destination by hand keeps that choice across every later
    /// rewrite.
    PreserveOrCreate(u32),
}

/// The mode a staged temporary is created at before the destination's
/// own mode, or a stated one, is applied to it by `chmod`.
///
/// Narrow deliberately: the publish is only observable at its final
/// mode because the file spends its whole widening at a temporary name.
const STAGED_CREATE_MODE: u32 = 0o600;

/// What `open(2)` is asked for when the umask is to decide, matching
/// the truncating write this machinery replaced.
const STAGED_OPEN_MODE: u32 = 0o666;

impl StagedMode {
    /// The mode to `chmod` the staged temporary to, or `None` when the
    /// umask is the answer and the temporary must instead be *created*
    /// at [`STAGED_OPEN_MODE`].
    ///
    /// A destination that cannot be stat'd is treated as absent: the
    /// staged publish that follows reports the real error, and guessing
    /// a mode here would only replace it with a worse one.
    fn resolve(self, path: &Path) -> Option<u32> {
        let existing = || {
            std::fs::metadata(path)
                .map(|meta| meta.permissions().mode() & 0o7777)
                .ok()
        };
        match self {
            StagedMode::Policy(mode) => Some(mode),
            StagedMode::PreserveOrCreate(create_mode) => Some(existing().unwrap_or(create_mode)),
            StagedMode::PreserveOrUmask => existing(),
        }
    }
}

/// Who owns the inode a staged publish renames into place.
///
/// A rename installs a *fresh* inode, so ownership is never inherited
/// from the file being replaced the way a truncating write left it
/// untouched. A staged publish therefore has to say where the uid/gid
/// comes from, and the two answers below differ because their files
/// do.
///
/// These two are [`publish_staged_blocking`]'s answers, not the
/// crate's. The override credential writers stage independently and
/// take a third — ownership from the parent directory, or read back
/// through `symlink_metadata` — for the reason recorded there.
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
    /// Leave the new inode owned by the writing process, whatever the
    /// destination carried.
    ///
    /// For a file published into a directory an untrusted user can
    /// write, whose *provenance* is what a later reader authenticates
    /// it by. The `OpenBao` audit device's rotation-intent marker is
    /// one: `/openbao/audit` is owned and writable by the container's
    /// audit user, so that user can plant a `rotation-intent.json` of
    /// its own — and the daemon, which decides from that marker whether
    /// to rename a generation back over the live audit log, tells the
    /// two apart by the marker's owner.
    /// [`StagedOwner::Destination`] would defeat exactly that: it
    /// carries the planted file's uid onto the daemon's own marker, so
    /// the daemon's next write hands the forgery's ownership to the
    /// genuine article and the check can no longer distinguish them.
    WritingProcess,
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
    /// Establish exactly this uid and gid on the new inode, whatever the
    /// destination carried and whatever the writing process is.
    ///
    /// Opt-in, and the only arm that can fail a publish on ownership
    /// alone: the chown runs before the rename and its error is
    /// returned, so a process without the authority to create the file
    /// under that owner publishes nothing at all rather than a
    /// best-effort file under its own uid. That is the requirement the
    /// registrar-internal credential set has — see [`FixedOwner`].
    Fixed(FixedOwner),
    /// Carry the *containing directory's* uid and gid onto the new
    /// inode, whatever the writing process is.
    ///
    /// For a file the host process writes into a tree whose readers run
    /// as that tree's owner rather than as bootroot. `secrets/` is such
    /// a tree: `infra install` pins `BOOTROOT_STEPCA_USER` to its owner,
    /// every `step` helper container is launched `--user <that uid>`,
    /// the step-ca server runs as it too, and the generated compose
    /// override starts both `OpenBao` Agent sidecars under it — so a
    /// file published there under a *different* uid is one none of them
    /// can open. That was invisible while bootroot always ran as that
    /// owner; an endpoint-enabled `init`, which must run as root, is
    /// the first writer for which it is not.
    ///
    /// The in-process counterpart of the root-container `chown` that
    /// `openbao/tls` takes before its issuance. A chown that would
    /// change nothing is skipped, so the ordinary case — bootroot
    /// running as the tree's owner — makes no privileged call at all
    /// and this arm leaves exactly what [`StagedOwner::Destination`]
    /// left.
    ContainingDir,
}

/// The uid and gid a [`StagedOwner::Fixed`] publish establishes on the
/// inode it renames into place.
///
/// The five protected registrar-internal files —
/// `registrar-internal/key.pem`, `chain.pem`, `acme-account.json`,
/// `root-fingerprint` and `agent.toml` — authenticate a host to
/// `OpenBao` or configure the agent that renews that credential, and
/// they are `0600` root-owned or they are not that credential: a file
/// the invoking user owns is one that user can read the key out of and
/// one they can rewrite the trust pins of. Their mode has always been a
/// policy; this type is the same statement about their owner.
///
/// The owner is an input rather than a constant so the real staging,
/// chown and rename path can be driven in a test that is not root. It
/// is not an input an operator can reach: [`FixedOwner::root`] is the
/// only constructor outside `cfg(test)`, so no configuration key,
/// environment variable or public API can move a protected file off
/// uid 0 / gid 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixedOwner {
    uid: u32,
    gid: u32,
}

impl FixedOwner {
    /// The owner every protected file is published under: uid 0, gid 0.
    #[must_use]
    pub fn root() -> Self {
        Self { uid: 0, gid: 0 }
    }

    /// An already-observed owner that an atomic restore must re-establish.
    ///
    /// This remains crate-visible: configuration and external callers cannot
    /// select an arbitrary owner for newly created files.
    #[must_use]
    #[cfg(target_os = "linux")]
    pub(crate) const fn observed(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }

    /// The test process's own effective uid and gid.
    ///
    /// The one way a protected publish is driven under an owner other
    /// than root, and `cfg(test)`-gated so it exists in no build an
    /// operator runs. A test taking it drives the production staging,
    /// chown and rename path unchanged — the chown is the same call
    /// against the same staged inode, asking for ids the unprivileged
    /// test process is allowed to establish.
    #[cfg(test)]
    pub(crate) fn current_process() -> Self {
        Self {
            uid: current_process_euid(),
            gid: crate::cert_group::current_process_egid(),
        }
    }

    /// Whether this owner is `root:root`, which is what every
    /// production caller asks for and what the failure message names.
    fn is_root(self) -> bool {
        self.uid == 0 && self.gid == 0
    }
}

/// Returns this process's effective uid.
///
/// Reported by the failure of a fixed-owner publish, and asserted as a
/// precondition by the tests that prove an unprivileged process cannot
/// publish a protected file.
#[must_use]
pub fn current_process_euid() -> u32 {
    // SAFETY: `geteuid` takes no argument, touches no memory the caller
    // owns, and is documented as always succeeding.
    unsafe { libc::geteuid() }
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
    /// reissued certificate or regenerated `ca.json` — rather than an
    /// outage.
    RenameOnly,
}

/// The target of a symlink sitting at `path`, or `None` when `path`
/// holds a regular file, holds nothing, or cannot be read without
/// following it.
///
/// A bare staged publish renames over the name it is given, so a link
/// found at the destination is replaced by the published file and the
/// operator's arrangement is gone. That is decided behaviour for a
/// credential and for the issued cert triple — the reader reads the
/// path bootroot handed it, and following a link would redirect the
/// bytes away from it — but decided is not the same as silent, so
/// [`publish_staged_blocking`] names the link and its former target at
/// `warn`. It reads the destination before the rename, because that is
/// the last moment the link is still there to read, and warns after it,
/// so a publish that fails at the rename leaves the link standing and
/// says nothing about having replaced it.
///
/// [`Destination::operator_named`] resolves the destination before the
/// publish, so the path its callers hand the core is the link's target
/// and never a link itself. It is exempt by construction rather than by
/// a flag.
///
/// Reads the destination with `symlink_metadata`, which does not follow
/// it. Anything unreadable answers `None`: a destination the publish
/// cannot stat is a failure the publish itself reports, and guessing at
/// a link here would only add a warning about a file that is not there.
fn replaced_symlink_target(path: &Path) -> Option<PathBuf> {
    if !std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink()) {
        return None;
    }
    std::fs::read_link(path).ok()
}

/// The context a failed chown of the staged file carries: the ownership
/// it was reproducing, and the two ways out.
///
/// The failure is `EPERM` in every realistic case — re-owning the fresh
/// inode to a uid/gid the writer does not hold needs `CAP_CHOWN` — and
/// no retry gets past it, so the message says what to change instead of
/// only what was attempted.
fn chown_preserve_context(uid: u32, gid: u32, path: &Path) -> String {
    format!(
        "Failed to preserve existing uid={uid} gid={gid} on {}: re-owning the staged file \
         needs CAP_CHOWN (run as root), so either run this command as the destination's \
         owner or chown the destination to the user running it",
        path.display()
    )
}

/// The context a failed chown of a [`StagedOwner::ContainingDir`]
/// publish carries: the owner the tree has, the directory that owner
/// was read from, and the file being published into it.
///
/// Reached only when the writing process is neither that owner nor
/// root — a case in which it can neither adopt the tree nor be trusted
/// to leave a file the tree's readers can open. The chown precedes the
/// rename, so the message describes a publish that did not happen.
fn chown_containing_dir_context(uid: u32, gid: u32, parent: &Path, path: &Path) -> String {
    format!(
        "{} must be published under the owner of {} (uid {uid}, gid {gid}) \u{2014} the uid \
         step-ca, the `step` helpers and the OpenBao Agent sidecars are launched as. The staged \
         file could not be given that owner, so nothing was published",
        path.display(),
        parent.display()
    )
}

/// The context a failed chown of a [`StagedOwner::Fixed`] publish
/// carries: the owner the file must have, and the file it was being
/// published as.
///
/// Both are named because either one is what an operator has to act
/// on. The failure is `EPERM` — establishing an owner the writer does
/// not hold needs `CAP_CHOWN` — and it is reached before the rename, so
/// the message describes a publish that did not happen rather than one
/// that half did.
fn chown_fixed_context(owner: FixedOwner, path: &Path) -> String {
    let requirement = if owner.is_root() {
        "root-owned (uid 0, gid 0)".to_string()
    } else {
        format!("owned by uid {} gid {}", owner.uid, owner.gid)
    };
    format!(
        "{} must be published {requirement}: the staged file could not be given that owner, \
         which needs CAP_CHOWN, so nothing was published — run this command as root",
        path.display()
    )
}

/// Publishes `contents` at `path` by staging a temporary in the same
/// directory, applying `mode` and `owner` to it there, and `rename`ing
/// it over the destination.
///
/// This is the crate's general-purpose staging publisher, and every
/// writer of a file at a path bootroot itself owns goes through it —
/// `state.json`, `rotation-state.json`, `agent.toml`, the fast-poll
/// state, the two `init` outputs, the issued certificate, key and CA
/// bundle, the `OpenBao` unseal keys and EAB files, and the configuration
/// `init` and the rotation commands generate (`.env`, `ca.json` and its
/// template, `openbao.hcl`, the responder config, the `OpenBao` Agent
/// configs and credentials, the compose overrides). For those the
/// destination name is only ever observed as the previous file or the
/// complete new one, and the final mode holds from the moment the name
/// appears.
///
/// It is not the crate's only staged publish. The override credential
/// writers — [`create_owned_credential_noclobber`],
/// [`write_owned_file_replace`] and
/// [`atomic_rewrite_owned_no_symlink`], which write a service's
/// `role_id`, `secret_id` and `eab.json` when those are relocated into
/// an operator-provisioned, agent-owned directory — stage and rename a
/// temporary of their own. They reach the same two guarantees by the
/// same means, and differ in what this routine deliberately does not
/// offer: ownership taken from the parent directory (a root process
/// creating a file there would otherwise leave it unreadable to the
/// non-root agent) or read back through `symlink_metadata`, and a
/// publish that refuses a name already present rather than replacing
/// it. Neither policy generalises to the files above, and folding them
/// together would make one of the two callers wrong.
///
/// Callers reach it through one of the four wrappers rather than
/// directly: [`atomic_write`]/[`atomic_write_blocking`] for a file read
/// back to resume, [`atomic_replace`]/[`atomic_replace_blocking`] for
/// one that can be regenerated. Those four take a [`Destination`] and
/// have already answered the symlink question by the time they call in
/// here, so the `path` below is a name to rename onto and never a link
/// to resolve. `crate::cert_group` is the exception, calling in with
/// [`StagedOwner::PolicyGroup`] for the three files the `--cert-group`
/// policy owns.
///
/// The staged file is created at `0600` and reaches its final mode only
/// while it is still at its temporary name, so a wider mode is never
/// observable at the destination — the property issue #593 asked of the
/// key file, and which now holds for every caller. The chown runs
/// before the chmod for the same reason: nothing may sit group-readable
/// under the writer's primary gid, even at the temporary name, before
/// the policy's gid lands. The staged file is `fsync`ed last of all,
/// once both have been applied, so a publish that survives a crash
/// carries the ownership and mode it was published with rather than the
/// temporary's defaults.
///
/// [`StagedMode::PreserveOrUmask`]'s create arm is the one exception,
/// and has to be: `chmod` ignores the umask, so a mode the umask decided
/// cannot be reached by applying one afterwards. There the temporary is
/// *created* asking for `0666` — `tempfile` passes the requested
/// permissions to `OpenOptions::mode`, so the kernel subtracts the umask
/// at `open(2)` exactly as the truncating write's `O_CREAT` did — and no
/// chmod runs at all, which leaves nothing to be observed at a wider
/// mode either.
///
/// Mode bits are the only thing that crosses from the file being
/// replaced onto the fresh inode, and only under the two preserving
/// arms of [`StagedMode`], which read `& 0o7777`. ACLs, extended
/// attributes and `SELinux` contexts lived on the old inode and do not
/// survive the publish: the temporary is created clean and takes the
/// containing directory's default labeling. Preserving them would take
/// reading each one off the destination and replaying it onto the
/// temporary before the rename, which nothing here does.
///
/// The temporary is removed if any step before the rename fails
/// (`NamedTempFile` deletes on drop), so a failed publish leaves
/// neither a torn destination nor a stray sibling. A crash between the
/// create and the rename does leave one — a `.tmpXXXXXX` sibling in the
/// destination's own directory, carrying whatever mode the write had
/// reached — while the destination itself still holds the previous
/// file.
///
/// A destination that is a symlink is renamed over rather than followed,
/// which destroys the operator's link. That is the decided behaviour
/// here — a caller wanting the link resolved says so with
/// [`Destination::operator_named`], which resolves before reaching this
/// far — but it is not left silent: the destination is read with
/// `symlink_metadata` while the link is still there, and once the
/// rename has replaced it the link and the file it pointed at are
/// reported at `warn`.
///
/// # Errors
/// Returns an error if the temp file cannot be created, written,
/// chowned, permissioned or renamed, or if the containing directory
/// cannot be flushed under [`StagedDurability::FlushDirectory`].
pub fn publish_staged_blocking(
    path: &Path,
    contents: &[u8],
    mode: StagedMode,
    owner: StagedOwner,
    durability: StagedDurability,
) -> Result<()> {
    let parent = parent_dir(path);
    // Resolved before the temporary exists: the umask arm has to be
    // answered by the `open(2)` that creates it, not by a later chmod.
    let final_mode = mode.resolve(path);
    let create_mode = final_mode.map_or(STAGED_OPEN_MODE, |_| STAGED_CREATE_MODE);
    let mut tmp = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(create_mode))
        .tempfile_in(&parent)
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
                        .with_context(|| chown_preserve_context(dest_uid, dest_gid, path))?;
                }
            }
        }
        StagedOwner::PolicyGroup(Some(gid)) => {
            std::os::unix::fs::chown(tmp.path(), None, Some(gid)).with_context(|| {
                format!("Failed to chown {} to gid {gid}", tmp.path().display())
            })?;
        }
        StagedOwner::WritingProcess | StagedOwner::PolicyGroup(None) => {}
        StagedOwner::ContainingDir => {
            // The directory is guaranteed to exist: the temporary was
            // just staged inside it. Its owner is the uid every reader
            // of this tree runs as.
            let owner = std::fs::metadata(&parent)
                .map(|meta| (meta.uid(), meta.gid()))
                .with_context(|| format!("Failed to stat {}", parent.display()))?;
            let staged = std::fs::metadata(tmp.path())
                .map(|meta| (meta.uid(), meta.gid()))
                .with_context(|| format!("Failed to stat temp file for {}", path.display()))?;
            // Skipping a chown that would change nothing keeps the
            // ordinary non-root writer off a call it does not need.
            if staged != owner {
                std::os::unix::fs::chown(tmp.path(), Some(owner.0), Some(owner.1)).with_context(
                    || chown_containing_dir_context(owner.0, owner.1, &parent, path),
                )?;
            }
        }
        StagedOwner::Fixed(fixed) => {
            // Unconditional, unlike the `Destination` arm's
            // change-nothing skip: this owner is a policy re-asserted on
            // every publish, and the call is the authority check. A
            // process that cannot make the staged inode `root:root`
            // must not go on to rename it into place under its own uid.
            std::os::unix::fs::chown(tmp.path(), Some(fixed.uid), Some(fixed.gid))
                .with_context(|| chown_fixed_context(fixed, path))?;
        }
    }
    if let Some(final_mode) = final_mode {
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(final_mode))
            .with_context(|| {
                format!(
                    "Failed to set mode {final_mode:o} on temp file for {}",
                    path.display()
                )
            })?;
    }
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
    // Read while the link is still at the destination; reported only
    // once the rename has actually replaced it, so a publish that fails
    // here does not claim an arrangement it left intact.
    let replaced_link = replaced_symlink_target(path);
    tmp.persist(path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to rename temp file to {}: {}",
            path.display(),
            e.error
        )
    })?;
    if let Some(link_target) = replaced_link {
        tracing::warn!(
            "Replaced the symlink at {} with the published file; it pointed at {}",
            path.display(),
            link_target.display()
        );
    }
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
    let target = path.to_path_buf();
    tokio::task::spawn_blocking(move || ensure_secrets_dir_blocking(&target))
        .await
        .context("Secrets dir task panicked")?
}

/// Ensures a secrets directory an infra container reads exists, at the
/// same mode [`ensure_secrets_dir`] applies and under the owner of the
/// tree it is created in.
///
/// `0700` is what makes ownership decide the question: step-ca, the
/// `step` helpers and both `OpenBao` Agent sidecars run as the uid that
/// owns `secrets/`, so a directory root created there is one they
/// cannot even traverse — and the files inside it, whatever their own
/// owner, become unreachable with it. Ownership is not inherited from
/// the parent by the kernel, so it is established here, on each level
/// this call actually creates.
///
/// The owner is read from the nearest ancestor that already exists,
/// which is the tree's, and an already-present directory is left on its
/// own owner: this never re-owns what somebody else made. For a
/// bootroot running as that owner — every non-root run — the chown is
/// skipped and this is [`ensure_secrets_dir`] exactly.
///
/// # Errors
/// Returns an error if the directory cannot be created, its permissions
/// cannot be set, the tree's owner cannot be read, or a level this call
/// created cannot be given that owner.
pub async fn ensure_shared_secrets_dir(path: &Path) -> Result<()> {
    let target = path.to_path_buf();
    // One blocking task, like every other ownership-establishing write
    // here: `chown` has no async spelling, and splitting the stat that
    // reads the owner from the chown that applies it across await
    // points buys nothing.
    tokio::task::spawn_blocking(move || ensure_shared_secrets_dir_blocking(&target))
        .await
        .context("Shared secrets dir task panicked")?
}

/// The blocking half of [`ensure_shared_secrets_dir`], for callers that
/// are not async.
///
/// The `OpenBao` audit compose override's renderer is synchronous, and
/// that override lands in the very directory the sidecars run out of,
/// so it needs the same tree ownership by the same means.
///
/// # Errors
/// Returns an error under the same conditions as
/// [`ensure_shared_secrets_dir`].
pub fn ensure_shared_secrets_dir_blocking(path: &Path) -> Result<()> {
    // The levels that do not exist yet, and the owner of the nearest
    // one that does. Collected before the create, because afterwards
    // nothing distinguishes them from the directories the operator or a
    // container made.
    let mut created = Vec::new();
    let mut cursor = Some(path);
    let owner = loop {
        // No ancestor exists at all, or one of them is not a directory:
        // both are `create_dir_all`'s to report, with a better message
        // than this loop could give.
        let Some(current) = cursor else {
            return ensure_secrets_dir_blocking(path);
        };
        match std::fs::metadata(current) {
            Ok(meta) if meta.is_dir() => break (meta.uid(), meta.gid()),
            Ok(_) => return ensure_secrets_dir_blocking(path),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                created.push(current.to_path_buf());
                cursor = current.parent();
            }
            Err(err) => {
                return Err(err).with_context(|| format!("Failed to stat {}", current.display()));
            }
        }
    };

    ensure_secrets_dir_blocking(path)?;
    for dir in created {
        let meta =
            std::fs::metadata(&dir).with_context(|| format!("Failed to stat {}", dir.display()))?;
        // Skipping a chown that would change nothing keeps the ordinary
        // non-root writer off a call it does not need.
        if (meta.uid(), meta.gid()) == owner {
            continue;
        }
        std::os::unix::fs::chown(&dir, Some(owner.0), Some(owner.1)).with_context(|| {
            format!(
                "{} must be owned by the secrets tree (uid {}, gid {}) \u{2014} the uid the \
                 step-ca container and the OpenBao Agent sidecars are launched as, and a \
                 directory they cannot traverse hides every file inside it",
                dir.display(),
                owner.0,
                owner.1
            )
        })?;
    }
    Ok(())
}

/// The blocking half of [`ensure_secrets_dir`].
fn ensure_secrets_dir_blocking(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path)
        .with_context(|| format!("Failed to create secrets dir {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SECRETS_DIR_MODE))
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

/// Marker that tells a re-executed test binary it is the isolated child
/// rather than the parent that spawned it.
const UMASK_CHILD_MARKER: &str = "BOOTROOT_UMASK_TEST_CHILD";

/// Runs `test_name` — one test of the *calling* test executable — in a
/// child process of its own, and answers whether it did.
///
/// `umask` is a property of the process, not of a thread, so a test that
/// sets one sets it for every test the harness happens to be running
/// beside it: the window covers every file those tests create, and no
/// lock held by the setter can close it, since the tests it would race
/// take no such lock. Making the umask-dependent test its own process is
/// the only isolation that actually holds. Each umask-dependent test
/// re-executes its test executable and opens with
///
/// ```ignore
/// if fs_util::umask_test_ran_in_child("module::tests::the_test_name") {
///     return;
/// }
/// ```
///
/// which is `true` in the parent — the child has run the body and its
/// result has already been asserted — and `false` in the child, which
/// goes on to run it with the process to itself.
///
/// The child is asked for exactly one test and is held to it: a name
/// that has drifted from the function it was copied from matches
/// nothing, and libtest reports *success* for a run of zero tests, so
/// the count is asserted rather than the exit status alone.
///
/// # Panics
///
/// Panics if this executable's path cannot be read, if it cannot be
/// re-executed, if the child fails, or if the child did not run exactly
/// the one test it was given.
#[must_use]
pub fn umask_test_ran_in_child(test_name: &str) -> bool {
    if std::env::var_os(UMASK_CHILD_MARKER).is_some() {
        return false;
    }
    let exe = std::env::current_exe().expect("a running test binary has a path");
    let output = std::process::Command::new(&exe)
        .args(["--exact", test_name, "--test-threads=1", "--nocapture"])
        .env(UMASK_CHILD_MARKER, "1")
        .output()
        .unwrap_or_else(|err| panic!("{} must be re-executable: {err}", exe.display()));
    let report = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.status.success(),
        "{test_name} failed in its own process:\n{report}"
    );
    assert!(
        report.contains("test result: ok. 1 passed"),
        "`--exact {test_name}` must name exactly one test of this binary, \
         and libtest calls a run of none of them a success:\n{report}"
    );
    true
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

        super::atomic_write(
            Destination::bootroot_owned(&path),
            b"first",
            StagedMode::Policy(KEY_FILE_MODE),
        )
        .await
        .unwrap();
        let contents = fs::read_to_string(&path).await.unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(contents, "first");
        assert_eq!(mode, KEY_FILE_MODE);

        super::atomic_write(
            Destination::bootroot_owned(&path),
            b"second",
            StagedMode::Policy(KEY_FILE_MODE),
        )
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

        super::atomic_replace(
            Destination::bootroot_owned(&path),
            b"first",
            StagedMode::Policy(0o644),
        )
        .await
        .unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "first");
        let first_ino = std::fs::metadata(&path).unwrap().ino();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o644
        );

        super::atomic_replace(
            Destination::bootroot_owned(&path),
            b"second",
            StagedMode::Policy(0o644),
        )
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

    /// The two constructors differ in exactly one observable way, and
    /// this pins both halves of it at the primitive, over the same
    /// seeded arrangement: `operator_named` delivers to a live link's
    /// target and leaves the link standing — what `O_TRUNC` did — while
    /// `bootroot_owned` replaces the link at that same path with the
    /// published file, which is what the `agent.toml` and cert/key
    /// writers want.
    ///
    /// Runs through both durability spellings, since the symlink axis is
    /// the destination's property and must not depend on which of the
    /// two is publishing.
    #[tokio::test]
    async fn operator_named_delivers_to_the_target_and_bootroot_owned_replaces_the_link() {
        let dir = tempdir().unwrap();
        let seed = |name: &str| {
            let target = dir.path().join(format!("target-{name}"));
            let link = dir.path().join(name);
            std::fs::write(&target, b"seed").unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            (target, link)
        };

        for (name, flushes) in [("write.env", true), ("replace.env", false)] {
            let (target, link) = seed(name);

            if flushes {
                super::atomic_write(
                    Destination::operator_named(&link),
                    b"fresh",
                    StagedMode::Policy(0o644),
                )
                .await
                .unwrap();
            } else {
                super::atomic_replace(
                    Destination::operator_named(&link),
                    b"fresh",
                    StagedMode::Policy(0o644),
                )
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

        for (name, flushes) in [("bare-write.env", true), ("bare-replace.env", false)] {
            let (target, link) = seed(name);

            if flushes {
                super::atomic_write(
                    Destination::bootroot_owned(&link),
                    b"fresh",
                    StagedMode::Policy(0o644),
                )
                .await
                .unwrap();
            } else {
                super::atomic_replace(
                    Destination::bootroot_owned(&link),
                    b"fresh",
                    StagedMode::Policy(0o644),
                )
                .await
                .unwrap();
            }

            assert!(
                !std::fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "{name}: `bootroot_owned` publishes at the name, replacing the link"
            );
            assert_eq!(std::fs::read_to_string(&link).unwrap(), "fresh");
            assert_eq!(
                std::fs::read_to_string(&target).unwrap(),
                "seed",
                "{name}: and leaves the target alone"
            );
        }
    }

    /// A dangling link is followed to where it points, so a first
    /// `operator_named` write through one creates the target rather than
    /// replacing the link — the `O_CREAT` half of the behaviour being
    /// preserved.
    #[test]
    fn operator_named_creates_a_dangling_links_target() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("absent.yml");
        let link = dir.path().join("override.yml");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        super::atomic_replace_blocking(
            Destination::operator_named(&link),
            b"fresh",
            StagedMode::Policy(0o644),
        )
        .unwrap();

        assert_eq!(std::fs::read_to_string(&target).unwrap(), "fresh");
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    /// The three destination states the replaced-symlink warning turns
    /// on. The call site is unconditional on `Some`, so pinning what the
    /// helper answers pins which publishes warn: a link warns and names
    /// its target, a regular file does not, and neither does a
    /// destination that is not there yet.
    #[test]
    fn replaced_symlink_target_reports_a_link_and_nothing_else() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.env");
        let link = dir.path().join("link.env");
        std::fs::write(&target, b"seed").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        assert_eq!(replaced_symlink_target(&link).as_deref(), Some(&*target));
        assert_eq!(replaced_symlink_target(&target), None);
        assert_eq!(
            replaced_symlink_target(&dir.path().join("absent.env")),
            None
        );

        // A link whose target does not exist is still a link the publish
        // destroys, and `symlink_metadata` sees it without following it,
        // so it warns and names where it pointed.
        let dangling = dir.path().join("dangling.env");
        let nowhere = dir.path().join("nowhere.env");
        std::os::unix::fs::symlink(&nowhere, &dangling).unwrap();
        assert_eq!(
            replaced_symlink_target(&dangling).as_deref(),
            Some(&*nowhere)
        );
    }

    /// [`Destination::operator_named`] is exempt from that warning by
    /// construction rather than by a flag: what it hands the core is the
    /// resolved target, and a resolved target is never a link.
    #[test]
    fn a_resolved_destination_is_never_a_replaced_symlink() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.yml");
        let link = dir.path().join("link.yml");
        let outer = dir.path().join("outer.yml");
        std::fs::write(&target, b"seed").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        std::os::unix::fs::symlink(&link, &outer).unwrap();

        for start in [&link, &outer] {
            assert!(replaced_symlink_target(start).is_some());
            let resolved = resolve_symlink_destination(start).unwrap();
            assert_eq!(
                replaced_symlink_target(&resolved),
                None,
                "the path an `operator_named` publish lands on must not warn"
            );
        }
    }

    /// Runs `publish` with a subscriber of its own and answers what it
    /// logged. `with_default` binds the subscriber to this thread, which
    /// is where the blocking wrappers do their work, so nothing leaks
    /// between tests running in parallel.
    fn logs_from(publish: impl FnOnce()) -> String {
        use std::sync::{Arc, Mutex};

        #[derive(Clone)]
        struct Captured(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for Captured {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = Captured(Arc::clone(&buffer));
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, publish);
        let captured = buffer.lock().unwrap().clone();
        String::from_utf8(captured).unwrap()
    }

    /// The observable half of the helper tests above, through the two
    /// constructors an operator actually reaches: a `bootroot_owned`
    /// publish over a seeded link says so once and names both ends of
    /// it, and an `operator_named` publish over the same arrangement
    /// says nothing, because it never hands the core a link.
    #[test]
    fn a_bare_publish_over_a_link_warns_once_and_a_resolved_one_stays_quiet() {
        let dir = tempdir().unwrap();
        let seed = |name: &str| {
            let target = dir.path().join(format!("target-{name}"));
            let link = dir.path().join(name);
            std::fs::write(&target, b"seed").unwrap();
            std::os::unix::fs::symlink(&target, &link).unwrap();
            (target, link)
        };

        let (bare_target, bare_link) = seed("bare.env");
        let logged = logs_from(|| {
            atomic_write_blocking(
                Destination::bootroot_owned(&bare_link),
                b"fresh",
                StagedMode::Policy(0o644),
            )
            .unwrap();
        });

        assert_eq!(
            logged.matches("Replaced the symlink at").count(),
            1,
            "one warning per replaced link, got: {logged}"
        );
        assert!(logged.contains("WARN"), "{logged}");
        assert!(
            logged.contains(&bare_link.display().to_string()),
            "{logged}"
        );
        assert!(
            logged.contains(&bare_target.display().to_string()),
            "{logged}"
        );

        let (resolved_target, resolved_link) = seed("resolved.env");
        let quiet = logs_from(|| {
            atomic_write_blocking(
                Destination::operator_named(&resolved_link),
                b"fresh",
                StagedMode::Policy(0o644),
            )
            .unwrap();
        });

        assert!(
            !quiet.contains("Replaced the symlink at"),
            "a publish through a link must not report replacing one, got: {quiet}"
        );
        // The silence has to be the silence of a publish that happened.
        assert_eq!(std::fs::read_to_string(&resolved_target).unwrap(), "fresh");
    }

    /// The chown context has to survive as a whole: the uid/gid it was
    /// preserving is what identifies the failure, and the remediation is
    /// what an operator hitting `EPERM` can act on.
    #[test]
    fn chown_preserve_context_names_the_remediation() {
        let message = chown_preserve_context(1000, 2000, Path::new("/srv/bootroot/state.json"));

        assert!(message.contains("uid=1000 gid=2000"), "{message}");
        assert!(message.contains("/srv/bootroot/state.json"), "{message}");
        assert!(message.contains("CAP_CHOWN"), "{message}");
        assert!(
            message.contains("run this command as the destination's owner"),
            "{message}"
        );
        assert!(
            message.contains("chown the destination to the user running it"),
            "{message}"
        );
    }

    /// A cycle has no target to deliver to, so the publish fails the way
    /// the truncating write's `ELOOP` did rather than replacing one of
    /// the links with the file.
    #[test]
    fn operator_named_refuses_a_symlink_cycle() {
        let dir = tempdir().unwrap();
        let a = dir.path().join("a.env");
        let b = dir.path().join("b.env");
        std::os::unix::fs::symlink(&b, &a).unwrap();
        std::os::unix::fs::symlink(&a, &b).unwrap();

        assert!(
            super::atomic_write_blocking(
                Destination::operator_named(&a),
                b"x",
                StagedMode::Policy(0o644)
            )
            .is_err()
        );
        assert!(
            super::atomic_replace_blocking(
                Destination::operator_named(&a),
                b"x",
                StagedMode::Policy(0o644)
            )
            .is_err()
        );
        assert!(
            std::fs::symlink_metadata(&a)
                .unwrap()
                .file_type()
                .is_symlink(),
            "a refused publish must leave the links it would not follow"
        );
    }

    /// Publishes `contents` at `path` under `mode` and `umask`,
    /// restoring the umask before returning, and answers with the
    /// mode the destination ends up carrying.
    fn publish_under_umask(
        path: &Path,
        contents: &[u8],
        mode: StagedMode,
        umask: libc::mode_t,
    ) -> u32 {
        // SAFETY: `umask` is a libc call with no memory effects, and
        // the previous value is restored before this returns. The
        // process it changes is the child `umask_test_ran_in_child`
        // spawned for the one test calling this, so no other test is
        // running beside it to observe the change.
        let prev = unsafe { libc::umask(umask) };
        let result = publish_staged_blocking(
            path,
            contents,
            mode,
            StagedOwner::Destination,
            StagedDurability::RenameOnly,
        );
        unsafe { libc::umask(prev) };
        result.unwrap();
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    /// All three [`StagedMode`] arms, on a create and on a rewrite.
    ///
    /// Runs in a process of its own (see [`umask_test_ran_in_child`]),
    /// because it sets the umask and the umask belongs to the process:
    /// left in this one it would reach every file every test scheduled
    /// beside it creates. Covers all three [`StagedMode`] arms in one
    /// isolated run rather than splitting them across three, keeping
    /// their shared create-and-rewrite assertions together.
    ///
    /// [`StagedMode::PreserveOrUmask`]'s create arm gets its mode from
    /// `open(2)` rather than from a `chmod` afterwards — the only way a
    /// umask can be honoured at all, since `chmod` ignores it. Asserting
    /// the final mode is therefore the whole assertion: there is no
    /// chmod on that arm to leave a wider transient behind.
    #[test]
    fn staged_mode_arms_answer_the_create_and_the_rewrite() {
        if umask_test_ran_in_child(
            "fs_util::tests::staged_mode_arms_answer_the_create_and_the_rewrite",
        ) {
            return;
        }

        let dir = tempdir().unwrap();
        let umask_restrictive = dir.path().join("umask-077.json");
        let umask_permissive = dir.path().join("umask-022.json");
        let stated = dir.path().join("agent.toml");
        let policy = dir.path().join("key.pem");

        // PreserveOrUmask: a create is the umask's answer to `0666`,
        // which is what the truncating write this replaced produced.
        assert_eq!(
            publish_under_umask(
                &umask_restrictive,
                b"{}",
                StagedMode::PreserveOrUmask,
                0o077
            ),
            0o600,
            "a create under umask 077 must land 0600, not a hardcoded 0644"
        );
        assert_eq!(
            publish_under_umask(&umask_permissive, b"{}", StagedMode::PreserveOrUmask, 0o022),
            0o644,
            "a create under umask 022 must land 0644"
        );
        // And a rewrite takes the destination's mode, whatever umask is
        // in force.
        std::fs::set_permissions(&umask_permissive, std::fs::Permissions::from_mode(0o640))
            .unwrap();
        assert_eq!(
            publish_under_umask(&umask_permissive, b"{}", StagedMode::PreserveOrUmask, 0o077),
            0o640,
            "an existing destination keeps the mode it carries"
        );

        // PreserveOrCreate: the create mode is stated, so no umask
        // reaches it; the rewrite still keeps what the operator set.
        assert_eq!(
            publish_under_umask(
                &stated,
                b"first",
                StagedMode::PreserveOrCreate(0o600),
                0o000
            ),
            0o600,
            "a create must land 0600 even under a fully permissive umask"
        );
        std::fs::set_permissions(&stated, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            publish_under_umask(
                &stated,
                b"second",
                StagedMode::PreserveOrCreate(0o600),
                0o000
            ),
            0o644,
            "a rewrite must not re-narrow a destination the operator widened"
        );

        // Policy: the same answer in every case — that is what makes it
        // a policy. Neither the umask nor a mode an earlier writer left
        // on the destination may reach the published file.
        assert_eq!(
            publish_under_umask(&policy, b"first", StagedMode::Policy(KEY_FILE_MODE), 0o000),
            KEY_FILE_MODE
        );
        std::fs::set_permissions(&policy, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            publish_under_umask(&policy, b"second", StagedMode::Policy(KEY_FILE_MODE), 0o077),
            KEY_FILE_MODE,
            "a policy mode must outlive a mode left on the destination"
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

        super::atomic_write(
            Destination::bootroot_owned(&path),
            b"first",
            StagedMode::Policy(KEY_FILE_MODE),
        )
        .await
        .unwrap();
        std::os::unix::fs::chown(&path, None, Some(gid))
            .expect("test process must be able to chgrp to a supplementary gid");
        let pre_meta = std::fs::metadata(&path).unwrap();
        assert_eq!(pre_meta.gid(), gid, "seed gid must take effect");
        let pre_uid = pre_meta.uid();

        super::atomic_write(
            Destination::bootroot_owned(&path),
            b"second",
            StagedMode::Policy(KEY_FILE_MODE),
        )
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

        super::atomic_write(
            Destination::bootroot_owned(&path),
            b"payload",
            StagedMode::Policy(KEY_FILE_MODE),
        )
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

        let result = atomic_write_blocking(
            Destination::bootroot_owned(&path),
            b"payload",
            StagedMode::Policy(KEY_FILE_MODE),
        );
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
            StagedMode::Policy(KEY_FILE_MODE),
            StagedOwner::Destination,
            StagedDurability::RenameOnly,
        )
        .unwrap();
        publish_staged_blocking(
            &re_owned,
            b"second",
            StagedMode::Policy(KEY_FILE_MODE),
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

    /// A fixed-owner publish establishes the owner it was given on the
    /// inode it renames into place — on a fresh create and on a
    /// replacement alike.
    ///
    /// Driven through [`FixedOwner::current_process`] rather than
    /// [`FixedOwner::root`], because the ids an unprivileged test
    /// process can establish are its own. Everything else is the
    /// production path: the same staging in the destination's
    /// directory, the same `chown` on the staged inode, the same
    /// `chmod` after it and the same rename.
    #[tokio::test]
    async fn a_fixed_owner_publish_owns_a_create_and_a_replacement() {
        use std::os::unix::fs::MetadataExt;

        let owner = FixedOwner::current_process();
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");

        atomic_write_fixed_owner(
            Destination::bootroot_owned(&path),
            b"FIRST",
            StagedMode::Policy(KEY_FILE_MODE),
            owner,
        )
        .await
        .unwrap();
        let created = std::fs::metadata(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "FIRST");
        assert_eq!((created.uid(), created.gid()), (owner.uid, owner.gid));
        assert_eq!(created.permissions().mode() & 0o7777, KEY_FILE_MODE);

        atomic_write_fixed_owner(
            Destination::bootroot_owned(&path),
            b"SECOND",
            StagedMode::Policy(KEY_FILE_MODE),
            owner,
        )
        .await
        .unwrap();
        let replaced = std::fs::metadata(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "SECOND");
        assert_eq!((replaced.uid(), replaced.gid()), (owner.uid, owner.gid));
        assert_eq!(replaced.permissions().mode() & 0o7777, KEY_FILE_MODE);
        assert_ne!(
            replaced.ino(),
            created.ino(),
            "the replacement is a fresh inode, so its owner was established rather than inherited"
        );
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("key.pem")],
            "the staged temporary must not survive the publish"
        );
    }

    /// A process that cannot establish the required owner publishes
    /// nothing: the chown is on the staged inode, before the rename, so
    /// its failure leaves the destination exactly as it was.
    ///
    /// This is the ordering guarantee stated as a test. An unprivileged
    /// process asking for `root:root` gets `EPERM` from the kernel — no
    /// check in this crate decides it — and what matters is where in the
    /// sequence that answer arrives: an old credential still readable
    /// and a new one not published, rather than a protected file left
    /// owned by whoever ran the command.
    #[tokio::test]
    async fn a_fixed_owner_publish_that_cannot_own_the_file_publishes_nothing() {
        use std::os::unix::fs::MetadataExt;

        assert_ne!(
            current_process_euid(),
            0,
            "this test asserts what an unprivileged process cannot do, so it must not be root"
        );
        let dir = tempdir().unwrap();
        let path = dir.path().join("key.pem");
        std::fs::write(&path, "PRIOR").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let before = std::fs::metadata(&path).unwrap();

        let err = atomic_write_fixed_owner(
            Destination::bootroot_owned(&path),
            b"NEXT",
            StagedMode::Policy(KEY_FILE_MODE),
            FixedOwner::root(),
        )
        .await
        .unwrap_err();
        let report = format!("{err:#}");
        assert!(
            report.contains("root-owned") && report.contains(&path.display().to_string()),
            "the refusal must name the root-ownership requirement and the file: {report}"
        );

        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "PRIOR");
        assert_eq!(after.ino(), before.ino(), "the rename must not have run");
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(after.permissions().mode() & 0o7777, 0o640);
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("key.pem")],
            "the staged temporary is removed with the failed publish"
        );

        let absent = dir.path().join("absent.pem");
        atomic_write_fixed_owner(
            Destination::bootroot_owned(&absent),
            b"NEXT",
            StagedMode::Policy(KEY_FILE_MODE),
            FixedOwner::root(),
        )
        .await
        .unwrap_err();
        assert!(
            !absent.exists(),
            "a refused publication must not create the destination either"
        );
    }

    /// A directory-owner publish takes the containing directory's uid
    /// and gid, on a fresh create and on a replacement alike.
    ///
    /// An unprivileged test process owns the directory it just made, so
    /// what this pins is the *rule* — the published file matches the
    /// directory rather than whatever the destination happened to carry
    /// — and that the skip path leaves a correct result. The case the
    /// rule exists for, a root `init` publishing into a `secrets/` some
    /// other uid owns, needs a privilege this suite deliberately does
    /// not have; the registrar-internal init E2E is where it is
    /// observed.
    #[tokio::test]
    async fn a_dir_owner_publish_takes_the_directory_it_lands_in() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempdir().unwrap();
        let dir_meta = std::fs::metadata(dir.path()).unwrap();
        let path = dir.path().join("password.txt");

        atomic_write_dir_owner(
            Destination::bootroot_owned(&path),
            b"FIRST",
            StagedMode::Policy(KEY_FILE_MODE),
        )
        .await
        .unwrap();
        let created = std::fs::metadata(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "FIRST");
        assert_eq!(
            (created.uid(), created.gid()),
            (dir_meta.uid(), dir_meta.gid())
        );
        assert_eq!(created.permissions().mode() & 0o7777, KEY_FILE_MODE);

        atomic_write_dir_owner(
            Destination::bootroot_owned(&path),
            b"SECOND",
            StagedMode::Policy(KEY_FILE_MODE),
        )
        .await
        .unwrap();
        let replaced = std::fs::metadata(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "SECOND");
        assert_eq!(
            (replaced.uid(), replaced.gid()),
            (dir_meta.uid(), dir_meta.gid())
        );
        assert_ne!(
            replaced.ino(),
            created.ino(),
            "the replacement is a fresh inode, so its owner was established rather than inherited"
        );
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(
            entries,
            vec![std::ffi::OsString::from("password.txt")],
            "the staged temporary must not survive the publish"
        );
    }

    /// The no-flush spelling makes the same ownership decision, and
    /// keeps [`atomic_replace`]'s: it replaces without a directory
    /// flush.
    ///
    /// This is the writer the `OpenBao` Agent templates, the two
    /// `agent.hcl` files and the responder's config go through, so what
    /// it must not do is leave one of them behind under a uid the
    /// sidecar reading it does not have.
    #[tokio::test]
    async fn a_dir_owner_replace_takes_the_directory_and_leaves_no_temporary() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempdir().unwrap();
        let dir_meta = std::fs::metadata(dir.path()).unwrap();
        let path = dir.path().join("agent.hcl");
        std::fs::write(&path, "PRIOR").unwrap();

        atomic_replace_dir_owner(
            Destination::operator_named(&path),
            b"NEXT",
            StagedMode::Policy(KEY_FILE_MODE),
        )
        .await
        .unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(fs::read_to_string(&path).await.unwrap(), "NEXT");
        assert_eq!((meta.uid(), meta.gid()), (dir_meta.uid(), dir_meta.gid()));
        assert_eq!(meta.permissions().mode() & 0o7777, KEY_FILE_MODE);
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, vec![std::ffi::OsString::from("agent.hcl")]);
    }

    /// A shared secrets directory is created at `0700` under the owner
    /// of the tree it lands in, every level of it, and an existing
    /// directory keeps the owner it already had.
    ///
    /// The mode is what makes the owner load-bearing: `0700` under a
    /// uid the sidecar does not have hides every file inside it,
    /// however those files are themselves owned. An unprivileged test
    /// owns the tree it just made, so what is pinned here is the rule
    /// and the levels it reaches; a root `init` writing into a
    /// `secrets/` somebody else owns is the registrar-internal init
    /// E2E's to observe.
    #[tokio::test]
    async fn a_shared_secrets_dir_takes_the_owner_of_the_tree_at_every_level() {
        use std::os::unix::fs::MetadataExt;

        let root = tempdir().unwrap();
        let tree = std::fs::metadata(root.path()).unwrap();
        let nested = root.path().join("openbao").join("stepca");

        ensure_shared_secrets_dir(&nested).await.unwrap();

        for level in [root.path().join("openbao"), nested.clone()] {
            let meta = std::fs::metadata(&level).unwrap();
            assert_eq!(
                (meta.uid(), meta.gid()),
                (tree.uid(), tree.gid()),
                "{}",
                level.display()
            );
        }
        assert_eq!(
            std::fs::metadata(&nested).unwrap().permissions().mode() & 0o7777,
            SECRETS_DIR_MODE
        );

        // Idempotent, and not a re-own: a second call finds the
        // directory present and leaves it alone.
        let before = std::fs::metadata(&nested).unwrap();
        ensure_shared_secrets_dir(&nested).await.unwrap();
        let after = std::fs::metadata(&nested).unwrap();
        assert_eq!((after.uid(), after.gid()), (before.uid(), before.gid()));
        assert_eq!(after.ino(), before.ino());
    }

    /// The general wrappers are untouched by the fixed-owner arm: they
    /// still leave a fresh create to the writing process, which is what
    /// every file without an ownership policy of its own depends on.
    #[tokio::test]
    async fn atomic_write_still_leaves_a_fresh_create_to_the_writer() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write(
            Destination::bootroot_owned(&path),
            b"{}",
            StagedMode::Policy(0o644),
        )
        .await
        .unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (meta.uid(), meta.gid()),
            (
                current_process_euid(),
                crate::cert_group::current_process_egid()
            )
        );
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
