//! Moving an existing audit store onto the reserve, and the state that
//! says a move is half-done.
//!
//! A store that has ever been written to cannot simply have a
//! filesystem mounted over it: the mount hides every byte underneath
//! it, and what is hidden may be the only copy of records written
//! before the reserve existed. The provisioning surface therefore
//! refuses such a store rather than activating it. This module is the
//! way out of that refusal — the holding directory the contents are
//! moved aside into, the checks that decide whether they can be copied
//! onto the mounted reserve, and the exact commands the operator runs
//! to copy and verify them.
//!
//! # Two derived paths, no configuration key
//!
//! `<audit_store_dir>.pre-mount` is the holding directory and
//! `<audit_store_dir>.migrated` is what it is renamed to once the copy
//! has been verified. Both are siblings of the store in the store's own
//! parent — like the image, and outside the filesystem about to be
//! mounted — so both stay nameable while the mount is up, which the
//! directory underneath a mount point is not.
//!
//! # bootroot changes nothing here
//!
//! Every step that touches the store's contents is rendered for the
//! operator and performed by them: the aside rename, the type guard,
//! the copy, the three verification comparisons, the closing rename and
//! the rollback. Nothing in this module renames, copies, deletes or
//! unmounts, whatever uid the run has. What it does is read metadata
//! and `/proc/self/mountinfo` and decide what to render.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::Result;

use super::reserve::{
    FileKind, MeasureError, Phase2Step, Phase2StepKind, ReserveProbe, decode_mount_field,
    display_path, kind_text, lstat_named, measure_underlying, sh_quote_path,
};
use crate::i18n::Messages;

/// Suffix appended to `audit_store_dir` to derive the holding
/// directory the store's contents are renamed aside into.
const HOLDING_SUFFIX: &str = ".pre-mount";

/// Suffix the holding directory is renamed to once the copy has passed
/// the type guard and all three comparisons. A rename rather than a
/// delete: what it holds is still the only verified-against copy, and
/// reclaiming it is later operator housekeeping.
const MIGRATED_SUFFIX: &str = ".migrated";

/// The bytes the capacity check requires **above** the source figure.
///
/// A copy can legitimately allocate more than the source did: block
/// rounding differs between two filesystems, and each directory the
/// copy creates costs metadata of its own. Sixteen mebibytes is far
/// above what that slack can reach for a store of any realistic shape
/// and far below the shipped default reserve, so it never turns a copy
/// that would have fitted into a refusal on its own.
pub(super) const COPY_MARGIN_BYTES: u64 = 16 * 1024 * 1024;

/// The mount table this module reads.
///
/// `/proc/self/mountinfo` rather than `/proc/self/mounts`, because only
/// the former answers the question asked here. A `mount --bind` of a
/// directory on the same filesystem has the same `st_dev` as the tree
/// it sits in, so an `st_dev` comparison passes it and both
/// `find -xdev` and `cp --one-file-system` walk straight into it — and
/// the bind source's contents are then measured, copied into the
/// reserve as if they were audit data, and duplicated on the host. One
/// read of this file answers it for every mount regardless of device,
/// and needs nothing beyond the standard library.
const PROC_SELF_MOUNTINFO: &str = "/proc/self/mountinfo";

/// The zero-based index of the mount-point field in a `mountinfo`
/// record. The four before it are the mount id, the parent id, the
/// device `major:minor` and the root of the mount within its
/// filesystem, all fixed-position and none of them holding a space.
const MOUNTINFO_MOUNT_POINT_FIELD: usize = 4;

/// The scratch shell variable the rendered verification stages stage
/// their manifests under. A `mktemp -d` directory, outside both trees:
/// inside either, the manifests would describe themselves.
const SCRATCH_VARIABLE: &str = "SCRATCH";

/// The `find` expression that keeps `mkfs.ext4`'s own directory out of
/// the metadata manifests.
///
/// Every reserve is a freshly made ext4 filesystem, and `mke2fs`
/// creates `lost+found` in its root. That root is the *destination* of
/// the relocation copy and both sides of the replacement one, so the
/// entry stands on a side the copy did not put it on and the metadata
/// comparison faults every correct migration — the destination
/// carrying one record the source does not.
///
/// Only the entry itself is exempt, and only where it is a directory at
/// the tree's own root. Anything *underneath* it still appears in all
/// three manifests under its `lost+found/…` path and is compared as
/// usual, so nothing can be smuggled past the verification by being put
/// there; and a regular file or a symbolic link that merely bears the
/// name is matched by neither `-path` nor `-type d` together, so it is
/// compared in full and, being a link, refused by the type guard.
const LOST_AND_FOUND_EXCLUSION: &str = "! \\( -path './lost+found' -type d \\)";

/// The two derived siblings of the store this procedure uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MigrationPaths {
    /// `<audit_store_dir>.pre-mount`.
    pub(crate) holding: PathBuf,
    /// `<audit_store_dir>.migrated`.
    pub(crate) migrated: PathBuf,
}

/// What the two derived paths hold, read before any other verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MigrationPresence {
    /// Where the two paths are.
    pub(crate) paths: MigrationPaths,
    /// Whether a holding directory exists. Its presence means a
    /// migration is in progress and overrides every other verdict.
    pub(crate) holding: bool,
    /// Whether a `.migrated` path already exists. It blocks the
    /// closing rename, so the sequence is refused rather than started
    /// against it.
    pub(crate) migrated: bool,
}

impl MigrationPresence {
    /// The presence a host with neither path has, for the fixtures and
    /// the call sites that establish the paths without reading them.
    #[cfg(test)]
    pub(super) fn none(store_dir: &Path) -> Self {
        Self {
            paths: derive_paths(store_dir),
            holding: false,
            migrated: false,
        }
    }
}

/// Returns the two paths `store_dir` derives.
///
/// Derived by appending to the store's own bytes rather than by
/// joining, so a store whose name is not valid UTF-8 keeps its bytes.
pub(super) fn derive_paths(store_dir: &Path) -> MigrationPaths {
    MigrationPaths {
        holding: with_suffix(store_dir, HOLDING_SUFFIX),
        migrated: with_suffix(store_dir, MIGRATED_SUFFIX),
    }
}

/// Appends `suffix` to `path`'s own bytes.
///
/// A sibling is derived by appending rather than by joining, so a path
/// that is not valid UTF-8 keeps its bytes.
pub(super) fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut bytes = path.as_os_str().as_bytes().to_vec();
    bytes.extend_from_slice(suffix.as_bytes());
    PathBuf::from(OsStr::from_bytes(&bytes).to_os_string())
}

/// Reads the two derived paths.
///
/// This is the first read the reserve makes on either mode's path, and
/// it is an ordinary `lstat` of a plain path. It stays answerable
/// throughout the migration, unlike the directory beneath a mount
/// point, which cannot be named once the filesystem is mounted.
///
/// # Errors
///
/// Returns the reserve's unreadable-path error when either `lstat`
/// fails for anything but `ENOENT`.
pub(super) fn detect(
    store_dir: &Path,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<MigrationPresence> {
    let paths = derive_paths(store_dir);
    let holding = lstat_named(probe, &paths.holding, messages)?.is_some();
    let migrated = lstat_named(probe, &paths.migrated, messages)?.is_some();
    Ok(MigrationPresence {
        paths,
        holding,
        migrated,
    })
}

/// What the run may render for the copy, decided fresh on every pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CopyVerdict {
    /// The reserve is not mounted yet, so there is no destination
    /// filesystem to measure and no copy to render. What the outcome
    /// renders instead is the outstanding activation.
    MountAbsent,
    /// A mount point is at or under the holding directory. Refused: the
    /// measurement, the copy and the verification would cover
    /// different sets.
    MountPoint { path: String },
    /// The holding path is not a directory. Refused before anything is
    /// walked, measured or rendered: `cp -a <holding>/. <store>/`
    /// resolves the `/.` suffix, so a symbolic link there is the one
    /// entry the type guard cannot catch — `find <link> -mindepth 1`
    /// does not descend it and exits zero — and the copy would move
    /// whatever it points at into the reserve as audit data.
    HoldingNotDirectory { path: String, kind: &'static str },
    /// The holding directory holds a symbolic link, a device node, a
    /// FIFO or a socket. Refused.
    ForbiddenEntry { path: String, kind: &'static str },
    /// A byte figure that cannot be represented as a `u64`. Refused,
    /// naming the figure.
    Arithmetic { figure: String },
    /// The contents do not fit on the mounted filesystem.
    DoesNotFit {
        available: u64,
        source: u64,
        margin: u64,
    },
    /// The contents fit, and the copy is rendered.
    Fits {
        available: u64,
        source: u64,
        margin: u64,
    },
}

impl CopyVerdict {
    /// Whether the copy, the verification and the closing rename may
    /// be rendered at all.
    pub(super) fn renders_copy(&self) -> bool {
        matches!(self, Self::Fits { .. })
    }
}

/// Decides what may be rendered for a migration that is in progress.
///
/// The order is normative. The migration-set refusals come first,
/// because the capacity figure describes the same entries as the copy
/// only if they hold; the capacity comparison comes last and only once
/// there is a mounted filesystem to compare against.
///
/// **The set-identity guarantee is conditional.** `find -xdev` excludes
/// a different-device mount from the measurement, the copy and all
/// three comparisons alike, so those cannot disagree over one. A
/// same-device bind mount is caught only by the mountinfo read here,
/// and bootroot reads mountinfo when it *renders* while the operator
/// copies afterwards — so one that appears and disappears between two
/// passes is inside none of these checks and inside all of the
/// operator's operations. The guarantee therefore holds provided no
/// privileged mount change is made between a rendering pass and the
/// operator running what it rendered.
///
/// # Errors
///
/// Returns the reserve's unreadable-path error when a metadata read or
/// the mount-table read fails.
pub(super) fn assess_copy(
    store_dir: &Path,
    holding: &Path,
    mount_up: bool,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<CopyVerdict> {
    // The holding path itself, before anything below walks, measures
    // or renders from it. `lstat` rather than `stat`, so a symbolic
    // link is seen as one: the walk here would follow it, and the
    // rendered copy's `/.` suffix would too.
    if let Some(kind) = holding_root_kind(holding, probe, messages)? {
        return Ok(CopyVerdict::HoldingNotDirectory {
            path: display_path(holding),
            kind: kind_text(kind, messages),
        });
    }
    if let Some(path) = mount_point_at_or_under(holding, probe, messages)? {
        return Ok(CopyVerdict::MountPoint {
            path: display_path(&path),
        });
    }
    if let Some((path, kind)) = first_forbidden_entry(holding, probe, messages)? {
        return Ok(CopyVerdict::ForbiddenEntry {
            path: display_path(&path),
            kind: kind_text(kind, messages),
        });
    }
    if !mount_up {
        return Ok(CopyVerdict::MountAbsent);
    }
    // `f_bavail` rather than `f_bfree`: what the copy may use is what
    // is available to an unprivileged writer, not the blocks the
    // filesystem holds back for root.
    let space = probe.space(store_dir).map_err(|err| {
        anyhow::anyhow!(
            messages.error_audit_reserve_unreadable(&display_path(store_dir), &err.to_string())
        )
    })?;
    let Some(available) = space.blocks_available.checked_mul(space.fragment_size) else {
        return Ok(CopyVerdict::Arithmetic {
            figure: messages.audit_reserve_figure_available(&display_path(store_dir)),
        });
    };
    let source = match measure_underlying(holding, probe, messages) {
        Ok(bytes) => bytes,
        Err(MeasureError::Arithmetic(figure)) => return Ok(CopyVerdict::Arithmetic { figure }),
        Err(other) => return Err(other.into_error(messages)),
    };
    let Some(needed) = source.checked_add(COPY_MARGIN_BYTES) else {
        return Ok(CopyVerdict::Arithmetic {
            figure: messages.audit_reserve_figure_source_plus_margin(&display_path(holding)),
        });
    };
    if needed > available {
        return Ok(CopyVerdict::DoesNotFit {
            available,
            source,
            margin: COPY_MARGIN_BYTES,
        });
    }
    Ok(CopyVerdict::Fits {
        available,
        source,
        margin: COPY_MARGIN_BYTES,
    })
}

/// Returns the allocated size of `<audit_store_dir>.migrated`, for the
/// normal outcome to report as reclaimable.
///
/// A figure that cannot be represented is not a refusal here — nothing
/// gates on it — so it is simply not reported.
///
/// # Errors
///
/// Returns the reserve's unreadable-path error when a metadata read
/// fails.
pub(super) fn migrated_size(
    migrated: &Path,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<Option<u64>> {
    match measure_underlying(migrated, probe, messages) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(MeasureError::Arithmetic(_)) => Ok(None),
        Err(other) => Err(other.into_error(messages)),
    }
}

/// Returns the first mount point that is the holding directory or lies
/// underneath it.
///
/// The comparison is by path component rather than by string prefix, so
/// a sibling like `<store>.pre-mount-other` is not read as being
/// underneath `<store>.pre-mount`. The mount-point field is unescaped
/// first: `mountinfo` writes space, tab, newline and backslash as
/// `\040`, `\011`, `\012` and `\134`, and comparing the raw field
/// against a real path silently fails to match exactly the names that
/// matter here.
fn mount_point_at_or_under(
    holding: &Path,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    let text = probe.mountinfo().map_err(|err| {
        anyhow::anyhow!(
            messages.error_audit_reserve_unreadable(PROC_SELF_MOUNTINFO, &err.to_string())
        )
    })?;
    Ok(mount_points(&text)
        .into_iter()
        .find(|point| point.starts_with(holding)))
}

/// Reads every record's mount-point field out of `mountinfo`.
fn mount_points(text: &str) -> Vec<PathBuf> {
    text.lines()
        .filter_map(|line| line.split(' ').nth(MOUNTINFO_MOUNT_POINT_FIELD))
        .map(|field| PathBuf::from(OsStr::from_bytes(&decode_mount_field(field)).to_os_string()))
        .collect()
}

/// Returns the holding path's kind when it is not a real directory.
///
/// The rendered copy is `cp -a --one-file-system <holding>/. <store>/`,
/// and the `/.` suffix is resolved by `cp` however the path before it
/// is spelled — so a symbolic link at the holding path is followed and
/// whatever tree it names is copied into the reserve as audit data.
/// The rendered type guard cannot close that: `find <link> -xdev
/// -mindepth 1` neither descends a link given on its command line nor
/// reports the link itself, so it exits zero over exactly the entry
/// that must be refused. The refusal therefore has to be made here,
/// against `lstat` of the path itself, before the walk below follows
/// it and before any figure is measured through it.
fn holding_root_kind(
    root: &Path,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<Option<FileKind>> {
    let Some(facts) = lstat_named(probe, root, messages)? else {
        return Ok(None);
    };
    Ok((facts.kind != FileKind::Directory).then_some(facts.kind))
}

/// Returns the first entry under `root` that is neither a directory nor
/// a regular file.
///
/// **A migration rule of this work's own, stricter than anything the
/// store enforces today.** The store refuses a symbolic link at a named
/// path; nothing walks arbitrary entries, so a link at
/// `openbao/audit.log` — inside the one directory the layout contract
/// leaves to the container's entrypoint — is refused by nothing
/// otherwise. Migration refuses it for two reasons of its own. It is
/// the one entry that can put audit bytes **outside** the ceiling this
/// effort imposes, `cp -a` recreating a link pointing wherever it
/// pointed before. And carrying one is not verifiable at acceptable
/// cost: a manifest recording path and target as two variable-length
/// fields cannot tell `a b` linked to `c` from `a` linked to `b c`.
/// Nothing in the deployment creates one, so the rule costs a correct
/// deployment nothing.
///
/// The walk does not cross a device boundary, matching the
/// `find -xdev` the rendered commands enumerate with, so the refusal
/// and the copy cover the same entries.
fn first_forbidden_entry(
    root: &Path,
    probe: &dyn ReserveProbe,
    messages: &Messages,
) -> Result<Option<(PathBuf, FileKind)>> {
    let Some(root_facts) = lstat_named(probe, root, messages)? else {
        return Ok(None);
    };
    // The root is refused by [`holding_root_kind`] before this is
    // reached, and it is refused here too rather than assumed: the
    // listing below follows a symbolic link at `root`, so the walk
    // must not depend on a caller having checked first.
    if root_facts.kind != FileKind::Directory {
        return Ok(Some((root.to_path_buf(), root_facts.kind)));
    }
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let mut entries = probe
            .list_dir(&dir)
            .map_err(|err| {
                anyhow::anyhow!(
                    messages.error_audit_reserve_unreadable(&display_path(&dir), &err.to_string())
                )
            })?
            .unwrap_or_default();
        // A directory listing is in whatever order the filesystem
        // returns it, and the entry this names is the one an operator
        // has to go and look at. Sorting makes two runs over one host
        // name the same entry.
        entries.sort();
        for entry in entries {
            let Some(facts) = lstat_named(probe, &entry, messages)? else {
                continue;
            };
            if facts.dev != root_facts.dev {
                continue;
            }
            match facts.kind {
                FileKind::Directory => pending.push(entry),
                FileKind::Regular => {}
                other => return Ok(Some((entry, other))),
            }
        }
    }
    Ok(None)
}

/// Renders the step that opens the migration: both writers already
/// stopped, the store renamed aside, and an empty root-owned mount
/// point in its place.
pub(super) fn aside_rename_step(
    store_dir: &Path,
    holding: &Path,
    mount_point_mode: u32,
    messages: &Messages,
) -> Phase2Step {
    Phase2Step {
        kind: Phase2StepKind::AsideRename,
        title: messages.audit_reserve_step_aside_rename().to_string(),
        commands: vec![
            format!("mv {} {}", sh_quote_path(store_dir), sh_quote_path(holding)),
            format!(
                "install -d -m {mount_point_mode:04o} -o root -g root {}",
                sh_quote_path(store_dir)
            ),
        ],
    }
}

/// The type guard, rendered over one tree.
///
/// It exits non-zero both when it finds a disallowed entry and when the
/// walk itself fails, and exits 0 only over a **fully walked** tree of
/// directories and regular files. It reports by exit status alone; the
/// path is named by the next bootroot pass.
fn type_guard_command(tree: &Path) -> String {
    format!(
        "find {} -xdev -mindepth 1 ! -type d ! -type f -exec false {{}} +",
        sh_quote_path(tree)
    )
}

/// The guard run immediately before the copy, so a long copy is not
/// spent on a set that will be rejected.
pub(super) fn type_guard_step(holding: &Path, messages: &Messages) -> Phase2Step {
    Phase2Step {
        kind: Phase2StepKind::TypeGuard,
        title: messages.audit_reserve_step_type_guard().to_string(),
        commands: vec![type_guard_command(holding)],
    }
}

/// The copy: one whole-subtree operation.
///
/// `-a` is `-dR --preserve=all`, and the `-d` in it is
/// `--no-dereference --preserve=links`: nothing is followed and hard
/// links stay shared, which is what the measurement counted when it
/// counted each `(st_dev, st_ino)` once. The trailing `/.` copies the
/// directory's *contents*, so `records/` and `openbao/` are recreated
/// on the destination with their original ownership and modes in one
/// operation — which is why no rendered step creates either by hand
/// ahead of it.
pub(super) fn copy_step(store_dir: &Path, holding: &Path, messages: &Messages) -> Phase2Step {
    Phase2Step {
        kind: Phase2StepKind::Copy,
        title: messages.audit_reserve_step_copy().to_string(),
        commands: vec![format!(
            "cp -a --one-file-system {} {}",
            sh_quote_path(&with_suffix(holding, "/.")),
            sh_quote_path(&with_suffix(store_dir, "/")),
        )],
    }
}

/// Stages one NUL-delimited manifest: the `find` into its own raw file,
/// then a `sort -z` into its own sorted file.
///
/// **No stage is a pipeline, and that is a correctness rule rather than
/// a style one.** A pipeline's exit status is its last command's, so
/// `find … | sort -z` reports success when the *walk* failed and the
/// consumer merely saw a short or empty stream — an incomplete tree
/// read as a clean one, which is the single direction this sequence
/// must never fail in.
fn manifest_commands(name: &str, side: &str, find_arguments: &str) -> Vec<String> {
    let raw = scratch(&format!("{name}.{side}.raw"));
    let sorted = scratch(&format!("{name}.{side}"));
    vec![
        format!("find . -xdev -mindepth 1 {find_arguments} > {raw}"),
        format!("sort -z -o {sorted} {raw}"),
    ]
}

/// One path under the scratch directory, as the rendered shell spells
/// it.
fn scratch(name: &str) -> String {
    format!("\"${SCRATCH_VARIABLE}\"/{name}")
}

/// Every manifest for one side, produced after a `cd` into that side so
/// the recorded paths are relative and directly comparable.
fn side_commands(tree: &Path, side: &str) -> Vec<String> {
    let mut commands = vec![format!("cd {}", sh_quote_path(tree))];
    // Type, octal mode, numeric uid and gid, hard-link count and the
    // relative path — over every entry, directories included except
    // the one below. The path is the only variable-length field and it
    // is last, so the record's own NUL delimits it and no name the
    // container wrote can be read as ending elsewhere. A second
    // variable-length field after it would destroy that.
    commands.extend(manifest_commands(
        "meta",
        side,
        &format!("{LOST_AND_FOUND_EXCLUSION} -printf '%y %m %U %G %n %P\\0'"),
    ));
    // Sizes are their own pass because a *directory's* size legitimately
    // differs between two filesystems and would fail every correct
    // migration. Modification times are excluded for the same reason:
    // `cp -a` preserves them, but timestamp granularity does not carry
    // across filesystems.
    commands.extend(manifest_commands(
        "size",
        side,
        "-type f -printf '%s %P\\0'",
    ));
    commands.extend(manifest_commands("files", side, "-type f -print0"));
    // `--zero` is not optional: without it `sha256sum` newline-terminates
    // each record and escapes a filename holding a newline or a
    // backslash, which is a line-delimited manifest whatever fed it.
    commands.push(format!(
        "xargs -0 -r sha256sum --binary --zero < {} > {}",
        scratch(&format!("files.{side}")),
        scratch(&format!("content.{side}")),
    ));
    commands
}

/// The whole verification: the type guard over **both** trees, then the
/// three staged comparisons. All four must exit zero, and the sequence
/// stops at the first that does not.
///
/// The second run of the guard is the one that carries the guarantee.
/// bootroot's own refusal is a render-time verdict and the operator's
/// `cp -a` comes later, `-a` carrying `--no-dereference`; an entry
/// planted in between is copied as itself and then stands *identically
/// on both sides*, which the metadata comparison cannot fault and the
/// other two passes skip, both being `-type f`. Running the guard over
/// both trees before the comparisons catches it whenever it was
/// planted, and before the closing rename.
pub(super) fn verification_step(
    store_dir: &Path,
    holding: &Path,
    messages: &Messages,
) -> Phase2Step {
    let mut commands = vec![format!("{SCRATCH_VARIABLE}=\"$(mktemp -d)\"")];
    commands.push(type_guard_command(holding));
    commands.push(type_guard_command(store_dir));
    commands.extend(side_commands(holding, "source"));
    commands.extend(side_commands(store_dir, "destination"));
    for name in ["meta", "size", "content"] {
        commands.push(format!(
            "cmp {} {}",
            scratch(&format!("{name}.source")),
            scratch(&format!("{name}.destination")),
        ));
    }
    Phase2Step {
        kind: Phase2StepKind::Verify,
        title: messages.audit_reserve_step_verify().to_string(),
        commands,
    }
}

/// The step that closes the migration: a rename, never a deletion, and
/// never chained onto the copy or the verification.
///
/// It is safe under every condition here. `rename` is atomic, traverses
/// nothing, opens nothing and destroys nothing, so a mount appearing
/// between the check and the command cannot turn it into data loss. A
/// directory that *contains* a mount renames with it intact; one that
/// *is* a mount fails `EBUSY`.
pub(super) fn closing_rename_step(
    holding: &Path,
    migrated: &Path,
    messages: &Messages,
) -> Phase2Step {
    Phase2Step {
        kind: Phase2StepKind::ClosingRename,
        title: messages.audit_reserve_step_closing_rename().to_string(),
        commands: vec![format!(
            "mv {} {}",
            sh_quote_path(holding),
            sh_quote_path(migrated)
        )],
    }
}

/// The way back out, offered only while the holding directory still
/// carries its `.pre-mount` name.
///
/// The partial copy on the mounted filesystem is discarded with the
/// unmount, which is safe precisely because the source was never
/// modified. The `rmdir` is non-recursive by choice: it removes the
/// mount point only if the unmount left it empty.
///
/// **Every command is guarded on the holding path still being there**,
/// which is what makes the step idempotent: running it a second time
/// over a store already restored is three skipped commands and an exit
/// 0, where an unguarded list stops at a `rmdir` of a directory that
/// now holds the records it just put back. The predicate is the same
/// one bootroot renders the rollback from at all, so the guard says
/// exactly what the step says — a migration that is still open. The
/// `rmdir` carries a second guard for the mount point's own existence:
/// between the aside rename and the mount coming up nothing has
/// recreated it on a bring-up path, and `rmdir` over an absent
/// directory would stop the sequence before the restoring rename.
///
/// That guard is `[ -e … ] || [ -L … ]` rather than `-e` alone because
/// bootroot decides the migration is open from an `lstat` of the path,
/// and `test -e` answers for the *target* of a symbolic link. A dangling
/// link at the holding path is therefore a migration this step is
/// rendered for and a guard `-e` would read as closed: all three
/// commands would skip, the list would exit 0 having restored nothing,
/// and the next run would report **migration incomplete** again. `-L`
/// answers from the link itself, so the two agree on every entry.
///
/// The unmount is rendered only where the store is a mount point. A
/// migration is open from the aside rename onward, which is two
/// `bootroot infra up` passes before the mount comes up, and there
/// `umount <store>` exits non-zero over a store nothing is mounted on —
/// stopping a sequence run verbatim before the `rmdir` and the
/// restoring rename, which are the two commands that carry the
/// rollback. So the step is the whole way back out from whichever state
/// it is rendered in, rather than a list whose first line is a failure
/// the operator has to know to ignore.
///
/// The predicate is the mount table naming the store at all rather than
/// the reserve being what is mounted: a foreign mount there is still
/// something the `rmdir` cannot get past. What is *not* rendered from
/// here is the rollback for a foreign mount — that verdict withholds
/// the step outright, an `umount` of a filesystem this migration never
/// put there being nothing the operator should be handed.
pub(super) fn rollback_step(
    store_dir: &Path,
    holding: &Path,
    mount_present: bool,
    messages: &Messages,
) -> Phase2Step {
    let store = sh_quote_path(store_dir);
    let holding = sh_quote_path(holding);
    // Not `-d`: the rollback is also rendered where the holding path is
    // not a directory, and that state is exactly the one whose entry has
    // to be moved back rather than skipped. Not `-e` alone either — it
    // dereferences, so a dangling link is an open migration bootroot
    // detects by `lstat` and a bare `-e` guard would skip. `-L` answers
    // from the link itself and closes that gap.
    let open = format!("[ -e {holding} ] || [ -L {holding} ]");
    let mut commands = Vec::with_capacity(3);
    if mount_present {
        commands.push(format!("if {open}; then umount {store}; fi"));
    }
    // The brace group says the grouping rather than leaving it to be
    // derived: `&&` and `||` have equal precedence and associate left,
    // so the bare form means the same thing — but this line is read by
    // an operator deciding whether to paste it over their only copy of
    // the records, and "the holding path is there *and* the mount point
    // is" should not be something they have to work out.
    commands.push(format!(
        "if {{ {open}; }} && [ -d {store} ]; then rmdir {store}; fi"
    ));
    commands.push(format!("if {open}; then mv {holding} {store}; fi"));
    Phase2Step {
        kind: Phase2StepKind::Rollback,
        title: messages.audit_reserve_step_rollback().to_string(),
        commands,
    }
}

/// The findings one [`CopyVerdict`] raises.
pub(super) fn verdict_findings(verdict: &CopyVerdict, messages: &Messages) -> Vec<String> {
    match verdict {
        CopyVerdict::MountAbsent => {
            vec![messages.audit_reserve_finding_migration_mount_absent()]
        }
        CopyVerdict::MountPoint { path } => {
            vec![messages.audit_reserve_finding_migration_mount_point(path)]
        }
        CopyVerdict::HoldingNotDirectory { path, kind } => {
            vec![messages.audit_reserve_finding_migration_holding_kind(path, kind)]
        }
        CopyVerdict::ForbiddenEntry { path, kind } => {
            vec![messages.audit_reserve_finding_migration_forbidden_entry(path, kind)]
        }
        CopyVerdict::Arithmetic { figure } => {
            vec![messages.audit_reserve_finding_migration_arithmetic(figure)]
        }
        CopyVerdict::DoesNotFit {
            available,
            source,
            margin,
        } => vec![
            messages.audit_reserve_finding_migration_capacity_short(*available, *source, *margin),
        ],
        CopyVerdict::Fits {
            available,
            source,
            margin,
        } => vec![
            messages.audit_reserve_finding_migration_capacity_fits(*available, *source, *margin),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_two_paths_are_siblings_of_the_store_with_no_configuration_key() {
        let paths = derive_paths(Path::new("/var/lib/bootroot/audit-store"));
        assert_eq!(
            paths.holding,
            Path::new("/var/lib/bootroot/audit-store.pre-mount")
        );
        assert_eq!(
            paths.migrated,
            Path::new("/var/lib/bootroot/audit-store.migrated")
        );
        // Siblings in the store's own parent, so both stay nameable
        // while a filesystem is mounted over the store.
        assert_eq!(
            paths.holding.parent(),
            Path::new("/var/lib/bootroot").into()
        );
    }

    #[test]
    fn mountinfo_fields_are_unescaped_before_they_are_compared() {
        let text = concat!(
            "36 35 98:0 / /var/lib/bootroot/audit\\040store.pre-mount rw - ext4 /dev/loop0 rw\n",
            "37 35 98:0 / /var/lib/bootroot/audit\\012store rw - ext4 /dev/loop1 rw\n",
        );
        let points = mount_points(text);
        assert_eq!(
            points,
            vec![
                PathBuf::from("/var/lib/bootroot/audit store.pre-mount"),
                PathBuf::from("/var/lib/bootroot/audit\nstore"),
            ]
        );
    }

    #[test]
    fn a_textual_sibling_is_not_read_as_being_under_the_holding_directory() {
        let holding = Path::new("/var/lib/bootroot/audit-store.pre-mount");
        let text =
            "36 35 98:0 / /var/lib/bootroot/audit-store.pre-mount-other rw - ext4 /dev/sda rw\n";
        assert!(
            !mount_points(text)
                .iter()
                .any(|point| point.starts_with(holding))
        );
    }
}

/// The rendered sequence, actually run.
///
/// Everything here is Linux-only on purpose: `find -printf`,
/// `sort -z`, `sha256sum --zero` and `du --block-size=1` are GNU
/// spellings, and the bootroot host is GNU/Linux — systemd units,
/// ext4, loop devices. On any other platform these commands are not the
/// ones an operator would run, so asserting them there would prove
/// nothing about the host they are rendered for.
#[cfg(all(test, target_os = "linux"))]
mod rendered_sequence {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::Path;
    use std::process::Command;

    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::commands::audit_store::reserve::HostProbe;
    use crate::i18n::test_messages;

    /// Runs a rendered step's commands as one `sh` script, stopping at
    /// the first non-zero exit exactly as the operator is told to.
    fn run(scratch_root: &Path, steps: &[&Phase2Step]) -> bool {
        let script: Vec<&str> = steps
            .iter()
            .flat_map(|step| step.commands.iter().map(String::as_str))
            .collect();
        Command::new("/bin/sh")
            .arg("-e")
            .arg("-c")
            .arg(script.join("\n"))
            // The `mktemp -d` scratch directory lands here rather than
            // in a fixed path, and goes away with the fixture.
            .env("TMPDIR", scratch_root)
            .status()
            .expect("run the rendered sequence")
            .success()
    }

    struct Fixture {
        _root: TempDir,
        source: PathBuf,
        destination: PathBuf,
        scratch: PathBuf,
    }

    /// A store holding both writers' content, including the two names
    /// a line-delimited manifest cannot represent: a filename with a
    /// newline in it, and two paths sharing one inode.
    fn fixture() -> Fixture {
        let root = tempdir().expect("a temporary directory");
        let source = root.path().join("audit-store.pre-mount");
        let destination = root.path().join("audit-store");
        let scratch = root.path().join("scratch");
        for dir in [
            &source,
            &source.join("records"),
            &source.join("openbao"),
            &destination,
            &scratch,
        ] {
            fs::create_dir(dir).expect("a fixture directory");
        }
        fs::write(source.join("records").join("verbs.log"), b"one\ntwo\n").expect("a record file");
        fs::write(source.join("openbao").join("audit.log"), b"{}\n").expect("an audit log");
        fs::write(source.join("openbao").join("weird\nname"), b"newline\n")
            .expect("a file whose name holds a newline");
        fs::hard_link(
            source.join("records").join("verbs.log"),
            source.join("records").join("verbs.log.1"),
        )
        .expect("a second path to one inode");
        Fixture {
            _root: root,
            source,
            destination,
            scratch,
        }
    }

    fn copy_and_verify(fixture: &Fixture) -> (Phase2Step, Phase2Step, Phase2Step) {
        let messages = test_messages();
        (
            type_guard_step(&fixture.source, &messages),
            copy_step(&fixture.destination, &fixture.source, &messages),
            verification_step(&fixture.destination, &fixture.source, &messages),
        )
    }

    #[test]
    fn a_faithful_copy_passes_the_guard_and_all_three_comparisons() {
        let fixture = fixture();
        let (guard, copy, verify) = copy_and_verify(&fixture);
        assert!(run(&fixture.scratch, &[&guard, &copy, &verify]));
        // Every byte arrived, the newline-named file included.
        assert_eq!(
            fs::read(fixture.destination.join("openbao").join("weird\nname"))
                .expect("the newline-named file"),
            b"newline\n"
        );
    }

    /// `mkfs.ext4` creates `lost+found` in every filesystem it makes, so
    /// the destination of a real relocation carries one before the copy
    /// starts. Made here at the mode and ownership `mke2fs` gives it.
    fn plant_lost_and_found(root: &Path) -> PathBuf {
        let dir = root.join("lost+found");
        fs::create_dir(&dir).expect("the filesystem's own directory");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .expect("the mode mke2fs gives it");
        dir
    }

    #[test]
    fn the_reserves_own_lost_and_found_does_not_fail_the_verification() {
        let fixture = fixture();
        // Before the copy, as the real sequence has it: the mount is up
        // and the filesystem's root already holds this one directory
        // that no source ever put there.
        plant_lost_and_found(&fixture.destination);
        let (guard, copy, verify) = copy_and_verify(&fixture);
        assert!(run(&fixture.scratch, &[&guard, &copy, &verify]));
    }

    #[test]
    fn content_under_lost_and_found_is_still_compared() {
        let fixture = fixture();
        let stray = plant_lost_and_found(&fixture.source).join("stray.log");
        fs::write(&stray, b"stray\n").expect("a file under lost+found");
        plant_lost_and_found(&fixture.destination);
        let (guard, copy, verify) = copy_and_verify(&fixture);
        assert!(run(&fixture.scratch, &[&guard, &copy, &verify]));
        // Only the directory entry is exempt. What it holds carries its
        // `lost+found/…` path into all three manifests, so a same-sized
        // difference underneath it is caught exactly as anywhere else.
        fs::write(
            fixture.destination.join("lost+found").join("stray.log"),
            b"other\n",
        )
        .expect("rewrite the entry under lost+found");
        assert!(!run(&fixture.scratch, &[&verify]));
    }

    #[test]
    fn a_regular_file_merely_bearing_the_name_is_not_exempt() {
        let fixture = fixture();
        let (guard, copy, verify) = copy_and_verify(&fixture);
        fs::write(fixture.source.join("lost+found"), b"not the filesystem's\n")
            .expect("a regular file bearing the name");
        assert!(run(&fixture.scratch, &[&guard, &copy, &verify]));
        // The exemption is `-path` *and* `-type d` together, so this one
        // is in the metadata manifest and a changed mode fails it.
        fs::set_permissions(
            fixture.destination.join("lost+found"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("change the mode on the destination");
        assert!(!run(&fixture.scratch, &[&verify]));
    }

    #[test]
    fn a_destination_missing_an_entry_fails_the_verification() {
        let fixture = fixture();
        let (guard, copy, verify) = copy_and_verify(&fixture);
        assert!(run(&fixture.scratch, &[&guard, &copy]));
        fs::remove_file(fixture.destination.join("openbao").join("weird\nname"))
            .expect("remove one entry");
        assert!(!run(&fixture.scratch, &[&verify]));
    }

    #[test]
    fn a_right_sized_entry_with_different_content_fails_the_verification() {
        let fixture = fixture();
        let (guard, copy, verify) = copy_and_verify(&fixture);
        assert!(run(&fixture.scratch, &[&guard, &copy]));
        // Same length, different bytes: exactly what a size comparison
        // misses and the content pass catches.
        fs::write(
            fixture.destination.join("openbao").join("audit.log"),
            b"[]\n",
        )
        .expect("rewrite one entry");
        assert!(!run(&fixture.scratch, &[&verify]));
    }

    #[test]
    fn a_hard_link_expanded_into_two_files_fails_on_the_link_count() {
        let fixture = fixture();
        let (guard, copy, verify) = copy_and_verify(&fixture);
        assert!(run(&fixture.scratch, &[&guard, &copy]));
        // Type, mode, ownership, size and content all still match; only
        // `%n` differs.
        let linked = fixture.destination.join("records").join("verbs.log.1");
        let bytes = fs::read(&linked).expect("the linked file");
        fs::remove_file(&linked).expect("break the link");
        fs::write(&linked, &bytes).expect("an independent copy");
        assert!(!run(&fixture.scratch, &[&verify]));
    }

    #[test]
    fn a_name_and_a_target_that_collide_are_refused_before_any_comparison_runs() {
        let fixture = fixture();
        // The pair a manifest carrying a path and a link target as two
        // variable-length fields cannot tell apart: `a b` linked to `c`
        // and `a` linked to `b c` are one byte sequence. Neither side
        // ever reaches a comparison. bootroot refuses the entry when it
        // renders, over the real filesystem the operator's `cp -a`
        // would read, and the guard refuses it again immediately before
        // the copy — this one pointing *inside* the store, where the
        // rendered-sequence guard fixture points outside it.
        let colliding = fixture.source.join("openbao").join("a b");
        symlink("c", &colliding).expect("plant the colliding link");
        let messages = test_messages();
        let refused = first_forbidden_entry(&fixture.source, &HostProbe, &messages)
            .expect("walk the holding directory")
            .expect("the colliding link is refused");
        assert_eq!(refused, (colliding, FileKind::Symlink));

        let (guard, copy, verify) = copy_and_verify(&fixture);
        assert!(
            !run(&fixture.scratch, &[&guard]),
            "the guard before the copy must refuse the colliding link"
        );
        // And nothing downstream of it runs: the sequence stops at the
        // first non-zero exit, so the copy and the three comparisons
        // are never reached.
        assert!(!run(&fixture.scratch, &[&guard, &copy, &verify]));
        assert!(!fixture.destination.join("openbao").exists());
    }

    #[test]
    fn a_symlink_planted_after_the_copy_is_caught_by_the_post_copy_guard() {
        let fixture = fixture();
        let (guard, copy, verify) = copy_and_verify(&fixture);
        assert!(run(&fixture.scratch, &[&guard, &copy]));
        // Planted on *both* sides, so it stands identically and the
        // three comparisons cannot fault it. The guard over both trees,
        // which the verification runs first, is what stops the sequence
        // before the closing rename.
        for tree in [&fixture.source, &fixture.destination] {
            symlink("/etc/shadow", tree.join("openbao").join("planted"))
                .expect("plant a symbolic link");
        }
        assert!(!run(&fixture.scratch, &[&verify]));
    }

    #[test]
    fn an_incomplete_walk_fails_closed_while_the_piped_form_would_not() {
        // The permission bits do nothing for root, so the fixtures
        // would pass vacuously there.
        if bootroot::fs_util::current_process_euid() == 0 {
            return;
        }
        // 0o111: the entries cannot be listed at all, so even the type
        // guard's walk fails. 0o444: they can be listed but not
        // `stat`ed — and GNU `find` answers `-type` from the directory
        // entry's own `d_type` where the filesystem fills it in, so the
        // guard alone can still exit 0 there. What cannot is any
        // manifest step: `%m`, `%U`, `%G` and `%n` are `stat` fields,
        // and the verification carries all three manifests, so the
        // sequence stops before the closing rename under both.
        for (mode, guard_fails) in [(0o111, true), (0o444, false)] {
            let fixture = fixture();
            let (guard, copy, verify) = copy_and_verify(&fixture);
            assert!(run(&fixture.scratch, &[&guard, &copy]));
            let blocked = fixture.source.join("records");
            fs::set_permissions(&blocked, fs::Permissions::from_mode(mode))
                .expect("restrict the subdirectory");

            if guard_fails {
                assert!(
                    !run(&fixture.scratch, &[&guard]),
                    "mode {mode:o}: the type guard must fail on a walk it cannot complete"
                );
            }
            assert!(
                !run(&fixture.scratch, &[&verify]),
                "mode {mode:o}: the verification must fail on a walk it cannot complete"
            );
            // The same walk behind a pipe reports the *consumer's*
            // status and passes, which is the implementation this
            // rendering exists to avoid.
            let piped = Command::new("/bin/sh")
                .arg("-c")
                .arg(format!(
                    "cd {} && find . -xdev -mindepth 1 -printf '%y %m %U %G %n %P\\0' | sort -z > /dev/null",
                    sh_quote_path(&fixture.source)
                ))
                .status()
                .expect("run the piped form");
            assert!(
                piped.success(),
                "mode {mode:o}: a pipeline reports only its last command's status"
            );

            fs::set_permissions(&blocked, fs::Permissions::from_mode(0o700))
                .expect("restore the subdirectory so the fixture can be removed");
        }
    }

    /// The state the aside rename leaves: a holding directory beside an
    /// empty mount point nothing is mounted on. The rollback rendered
    /// there has to run to completion as it stands, because an operator
    /// pasting it is the only thing that performs it.
    #[test]
    fn the_mount_absent_rollback_runs_to_completion() {
        let empty = fixture();
        let occupied = fixture();
        let step = rollback_step(&empty.destination, &empty.source, false, &test_messages());
        assert!(
            step.commands
                .iter()
                .all(|command| !command.contains("umount")),
            "{:?}",
            step.commands
        );
        assert!(run(&empty.scratch, &[&step]));
        // The holding directory is back under the store's own name,
        // with its contents, and nothing is left at the aside path.
        assert!(!empty.source.exists());
        assert_eq!(
            fs::read(empty.destination.join("records").join("verbs.log"))
                .expect("the records survived the rollback"),
            b"one\ntwo\n"
        );
        // And the same state's rollback still stops where the mount
        // point is not empty: the `rmdir` is non-recursive.
        fs::write(occupied.destination.join("stray"), b"x").expect("a stray entry");
        let step = rollback_step(
            &occupied.destination,
            &occupied.source,
            false,
            &test_messages(),
        );
        assert!(!run(&occupied.scratch, &[&step]));
        assert!(occupied.source.exists(), "the holding directory was moved");
    }

    /// The rollback is one of the two operations the issue requires to
    /// be idempotent, and the operator is the only thing that performs
    /// it — so a second paste of the same list has to be a no-op rather
    /// than a `rmdir` of the records the first one put back.
    #[test]
    fn a_second_run_of_the_rendered_rollback_changes_nothing() {
        let fixture = fixture();
        let step = rollback_step(
            &fixture.destination,
            &fixture.source,
            false,
            &test_messages(),
        );
        assert!(run(&fixture.scratch, &[&step]));
        let restored = fixture.destination.join("records").join("verbs.log");
        assert_eq!(
            fs::read(&restored).expect("the records are back"),
            b"one\ntwo\n"
        );

        // Run verbatim a second time: every command is skipped, the
        // list exits 0, and the restored store is untouched.
        assert!(run(&fixture.scratch, &[&step]));
        assert!(fixture.destination.is_dir());
        assert!(!fixture.source.exists());
        assert_eq!(
            fs::read(&restored).expect("the records survived"),
            b"one\ntwo\n"
        );

        // And the same list run where the mount point was never
        // recreated — the state a bring-up pass leaves between the
        // aside rename and the mount — still restores the store,
        // rather than stopping at a `rmdir` of a directory that is not
        // there.
        let absent = fixture_with_no_mount_point();
        let step = rollback_step(&absent.destination, &absent.source, false, &test_messages());
        assert!(run(&absent.scratch, &[&step]));
        assert_eq!(
            fs::read(absent.destination.join("records").join("verbs.log"))
                .expect("the records are back"),
            b"one\ntwo\n"
        );
    }

    /// bootroot decides the migration is open from an `lstat` of the
    /// holding path, and `lstat` sees a dangling symbolic link — so the
    /// rollback is rendered for one, as the way back out of a state the
    /// type guard refuses. `test -e` does not see it: it answers for the
    /// link's absent target. A guard spelled `-e` alone would skip all
    /// three commands and exit 0 having restored nothing, leaving the
    /// next run reporting **migration incomplete** over a rollback that
    /// reported success.
    #[test]
    fn a_dangling_holding_symlink_is_rolled_back_rather_than_skipped() {
        let root = tempdir().expect("a temporary directory");
        let store = root.path().join("audit-store");
        let holding = root.path().join("audit-store.pre-mount");
        fs::create_dir(&store).expect("the empty mount point");
        symlink(root.path().join("nowhere"), &holding).expect("a dangling holding link");
        assert!(
            fs::symlink_metadata(&holding).is_ok() && !holding.exists(),
            "the fixture has to be a link whose target is absent"
        );

        let step = rollback_step(&store, &holding, false, &test_messages());
        assert!(run(root.path(), &[&step]));
        // The entry `lstat` saw was moved back under the store's own
        // name rather than skipped, and nothing is left at the aside
        // path.
        assert!(fs::symlink_metadata(&holding).is_err());
        assert!(
            fs::symlink_metadata(&store)
                .expect("the entry is back at the store's name")
                .file_type()
                .is_symlink()
        );

        // And the same list run a second time is the no-op the
        // directory case is: the holding path is gone, so all three
        // skip.
        assert!(run(root.path(), &[&step]));
        assert!(
            fs::symlink_metadata(&store)
                .expect("the entry survived the second run")
                .file_type()
                .is_symlink()
        );
    }

    /// The fixture with the mount point removed: the aside rename has
    /// run and nothing has recreated `<audit_store_dir>` yet.
    fn fixture_with_no_mount_point() -> Fixture {
        let fixture = fixture();
        fs::remove_dir(&fixture.destination).expect("remove the empty mount point");
        fixture
    }
}

/// The two manual passages, asserted rather than left to review.
///
/// Both procedures move the same irreplaceable data, and two copy
/// procedures that disagree are how records are lost — so the pinned
/// forms are checked in both languages, and the forms that must never
/// appear are checked too.
#[cfg(test)]
mod manuals {
    use std::fs;
    use std::path::Path;

    /// (page, the relocation section's heading, the replacement
    /// section's heading, the heading that follows it).
    const PAGES: [(&str, &str, &str, &str); 2] = [
        (
            "docs/en/operations.md",
            "#### Relocating a store that already holds records",
            "#### Changing the reserve",
            "#### Removing the reserve",
        ),
        (
            "docs/ko/operations.md",
            "#### 이미 레코드를 담고 있는 저장소 옮기기",
            "#### 예약량을 바꿀 때",
            "#### 예약량을 제거할 때",
        ),
    ];

    fn read(page: &str) -> String {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(page);
        fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("reading {}: {error}", path.display()))
    }

    fn section<'a>(source: &'a str, heading: &str, next: &str) -> &'a str {
        let (_, after) = source
            .split_once(heading)
            .unwrap_or_else(|| panic!("{heading} is absent"));
        after
            .split_once(next)
            .unwrap_or_else(|| panic!("{next} does not follow {heading}"))
            .0
    }

    /// Every fenced block in `passage`, joined.
    fn command_blocks(passage: &str) -> String {
        passage
            .split("```")
            .skip(1)
            .step_by(2)
            .collect::<Vec<&str>>()
            .join("\n")
    }

    #[test]
    fn both_manuals_pin_the_relocation_sequence() {
        for (page, heading, next, _) in PAGES {
            let source = read(page);
            let passage = section(&source, heading, next);
            for required in [
                // The nine steps' own commands.
                "systemctl stop bootroot-registrar.service",
                "mv <audit_store_dir> <audit_store_dir>.pre-mount",
                "install -d -m 0700 -o root -g root <audit_store_dir>",
                "! -type d ! -type f -exec false {} +",
                "cp -a --one-file-system <audit_store_dir>.pre-mount/. <audit_store_dir>/",
                "SCRATCH=\"$(mktemp -d)\"",
                "! \\( -path './lost+found' -type d \\)",
                "-printf '%y %m %U %G %n %P\\0'",
                "-printf '%s %P\\0'",
                "-type f -print0",
                "sort -z -o",
                "xargs -0 -r sha256sum --binary --zero",
                "cmp \"$SCRATCH\"/meta.source \"$SCRATCH\"/meta.destination",
                "cmp \"$SCRATCH\"/size.source \"$SCRATCH\"/size.destination",
                "cmp \"$SCRATCH\"/content.source \"$SCRATCH\"/content.destination",
                "mv <audit_store_dir>.pre-mount <audit_store_dir>.migrated",
                // Rollback: an unmount, a non-recursive rmdir and the
                // reverse rename, every line guarded on the holding
                // path by the two tests that together answer for a
                // dangling link as well as a directory.
                "umount <audit_store_dir>",
                "rmdir <audit_store_dir>",
                "mv <audit_store_dir>.pre-mount <audit_store_dir>",
                "[ -e <audit_store_dir>.pre-mount ] || [ -L <audit_store_dir>.pre-mount ]",
                // The window, the figures and the prerequisites.
                "create_host_path: false",
                "16 MiB",
                "diffutils",
                "coreutils 8.25",
                "/proc/self/mountinfo",
                ".pre-mount-other",
            ] {
                assert!(passage.contains(required), "{page}: missing {required:?}");
            }
        }
    }

    #[test]
    fn both_manuals_pin_the_replacement_procedure() {
        for (page, _, heading, next) in PAGES {
            let source = read(page);
            let passage = section(&source, heading, next);
            for required in [
                "<audit_store_dir>.img.new",
                "<audit_store_dir>.img.old",
                "mkfs.ext4 -m 0 -E nodiscard,lazy_itable_init=0",
                "du -s -x --block-size=1 <audit_store_dir>",
                "df --block-size=1 --output=avail",
                "! -type d ! -type f -exec false {} +",
                "/proc/self/mountinfo",
                "16 MiB",
                // `-x` documented as required and `--apparent-size` as
                // excluded, both in prose beside the pinned form.
                "--apparent-size",
            ] {
                assert!(passage.contains(required), "{page}: missing {required:?}");
            }
            // The guard, the copy and the three comparisons are reused
            // from the relocation passage rather than re-spelled, so
            // there is one contract rather than two that can drift.
            for forbidden in ["sha256sum", "sort -z", "cmp \""] {
                assert!(
                    !passage.contains(forbidden),
                    "{page}: the replacement procedure re-spells {forbidden:?}"
                );
            }
        }
    }

    #[test]
    fn neither_procedure_carries_a_forbidden_form() {
        for (page, relocation, replacement, next) in PAGES {
            let source = read(page);
            for (heading, following) in [(relocation, replacement), (replacement, next)] {
                let passage = section(&source, heading, following);
                // Nowhere in the passage, prose included: an
                // in-place resize of the image is never a route, and
                // `diff -r` is never the verification.
                for forbidden in ["resize2fs", "truncate", "diff -r"] {
                    assert!(
                        !passage.contains(forbidden),
                        "{page}/{heading}: carries {forbidden:?}"
                    );
                }
                // In a command an operator runs: no `--apparent-size`
                // and no `du` without `-x`, both of which would gate a
                // `--one-file-system` copy on a figure for a different
                // set; no recursive delete; and no pipeline, whose
                // status is its last command's, so a failed walk would
                // read as a clean tree.
                let blocks = command_blocks(passage);
                for line in blocks.lines() {
                    for forbidden in ["--apparent-size", "rm -r", "rm -f"] {
                        assert!(
                            !line.contains(forbidden),
                            "{page}/{heading}: {forbidden:?} in {line:?}"
                        );
                    }
                    // The pipeline ban is on `|`, and the rollback's
                    // guard spells `[ -e … ] || [ -L … ]`. `||` is a
                    // short-circuit between two commands and carries
                    // none of what the ban exists for: nothing runs in
                    // a subshell, and the status is the last command
                    // that actually ran. So it is removed before the
                    // check rather than exempting the whole line, which
                    // would let a real pipeline in beside it.
                    let piped = line.replace("||", "");
                    assert!(
                        !piped.contains('|'),
                        "{page}/{heading}: a pipeline in {line:?}"
                    );
                    if line.contains("du ") {
                        assert!(line.contains(" -x "), "{page}/{heading}: du without -x");
                    }
                }
            }
        }
    }
}
