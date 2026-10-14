//! The per-profile generation tree: one consistent snapshot of a
//! profile's certificate, key and CA bundle, published atomically.
//!
//! The configured `paths.cert` and `paths.key` are two separate
//! `rename(2)`s, each preceded by that file's whole staged write and
//! `fsync`, so a reader that takes the pair between them holds a new
//! certificate beside an old key. Nothing done to those two paths can
//! close that window without changing what they are, and every consumer
//! that reads them today must keep working.
//!
//! So the snapshot is published *beside* them. Each publication writes
//! a fresh directory holding all three files and then swaps one symlink
//! onto it:
//!
//! ```text
//! <keydir>/.bootroot-generations/<registration_id>/
//! ├── .bootroot-registrar-publish.lock
//! ├── current -> gen-<n>
//! ├── gen-<n-1>/
//! └── gen-<n>/
//!     ├── <basename of paths.cert>
//!     ├── <basename of paths.key>
//!     └── <basename of [trust].ca_bundle_path>
//! ```
//!
//! The swap of `current` is the commit point and the only moment a
//! consumer has to watch: before it `current` names the previous
//! complete generation, after it the new one, and there is no state in
//! between. One previous generation is kept, so a reader that resolved
//! `current` just before a swap finishes reading what it resolved.
//!
//! # The reader contract
//!
//! Resolve `current` **once** — `readlink`, or open it as a directory —
//! and read every file from that one generation. Two path lookups
//! through `current/…` can straddle a swap and are exactly the torn
//! read this tree exists to remove.
//!
//! # What takes the lock
//!
//! Two writers publish into one tree: a renewal, and the fast-poll
//! trust apply, which republishes the pair `current` already names
//! beside a new bundle. Both hold [`crate::publication_lock`] on the
//! tree's root from before the generation number is chosen until the
//! tree is pruned, and both read every input only once it is held. The
//! bundle is read under `crate::ca_bundle_lock`, always taken second.
//! The lock file is opened without following a link, so `current`
//! stays the only symlink in the tree anything follows.

use std::ffi::{OsStr, OsString};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};

use super::parent_dir;
use crate::cert_group::{
    self, CA_BUNDLE_FILE_MODE, CERT_FILE_MODE, CertGroupPolicy, DIR_MODE_DEFAULT,
    KEY_DIR_MODE_GROUP, KEY_FILE_MODE_DEFAULT, KEY_FILE_MODE_GROUP,
};
use crate::config::{DaemonProfileSettings, Settings};
use crate::registrar::internal::PrivateKeyPem;

/// The directory, beside a profile's key, that holds every generation
/// tree published into that key directory.
pub const GENERATIONS_DIR_NAME: &str = ".bootroot-generations";

/// The symlink naming a tree's latest complete generation.
pub const CURRENT_LINK_NAME: &str = "current";

/// What every generation directory's name starts with; the rest is its
/// number in decimal.
const GENERATION_PREFIX: &str = "gen-";

/// What a name still being staged ends with.
const STAGING_SUFFIX: &str = ".tmp";

/// The mode every directory in the tree is created at, before the
/// policy's group and mode are applied to it.
const STAGED_DIR_MODE: u32 = 0o700;

/// The mode every file in a generation is created at, before the
/// policy's group and its final mode are applied to it.
const STAGED_FILE_MODE: u32 = 0o600;

/// Returns the directory holding every generation tree of the profiles
/// whose key lives beside `key_path`.
#[must_use]
pub fn generations_dir(key_path: &Path) -> PathBuf {
    parent_dir(key_path).join(GENERATIONS_DIR_NAME)
}

/// Returns the root of the generation tree for the profile registered as
/// `registration_id` whose key is published at `key_path`.
#[must_use]
pub fn generation_root(key_path: &Path, registration_id: &str) -> PathBuf {
    generations_dir(key_path).join(registration_id)
}

/// A place in a publication a test can observe or fail.
///
/// Named after what has just happened, so a probe that fails at one
/// leaves the tree exactly as a crash there would.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicationPoint {
    /// The tree exists and the generation lock is about to be taken;
    /// nothing has been read.
    LockRequested,
    /// `gen-<n>.tmp` holds every file; `gen-<n>` does not exist yet.
    Staged,
    /// `gen-<n>` exists; `current` still names the previous generation.
    Renamed,
    /// `current.tmp` names `gen-<n>`; `current` still names the previous
    /// generation.
    LinkStaged,
    /// `current` names `gen-<n>`, the root has not been flushed, and the
    /// configured pair is unwritten. A failure injected here stands in
    /// for that flush failing, which does not fail the publication.
    Swapped,
    /// The configured certificate is written and the configured key is
    /// not.
    CertificateWritten,
}

/// What a publication reports its progress to.
///
/// The default reports to nothing and is what every production caller
/// passes. A test substitutes a function that inspects the tree, blocks
/// until it is told to go on, or returns the failure it wants injected.
#[derive(Clone, Default)]
pub(crate) struct Probe(Option<Arc<dyn Fn(PublicationPoint) -> Result<()> + Send + Sync>>);

impl Probe {
    /// A probe that calls `observe` at every point reached.
    #[cfg(test)]
    pub(crate) fn new(
        observe: impl Fn(PublicationPoint) -> Result<()> + Send + Sync + 'static,
    ) -> Self {
        Self(Some(Arc::new(observe)))
    }

    /// Reports `point`, returning whatever the probe decided about it.
    pub(crate) fn reach(&self, point: PublicationPoint) -> Result<()> {
        self.0.as_ref().map_or(Ok(()), |observe| observe(point))
    }
}

/// Where one profile's generations are published, and as what.
#[derive(Debug, Clone)]
pub(crate) struct GenerationTarget {
    /// The directory the profile's key is published into.
    key_dir: PathBuf,
    /// `<key_dir>/.bootroot-generations/<registration_id>`.
    root: PathBuf,
    /// The `--cert-group` policy the tree and its files are owned under.
    policy: CertGroupPolicy,
    /// The certificate's name inside a generation.
    cert_name: OsString,
    /// The key's name inside a generation.
    key_name: OsString,
    /// `[trust].ca_bundle_path` and the bundle's name inside a
    /// generation, when a bundle is configured.
    bundle: Option<(PathBuf, OsString)>,
}

/// Whether a profile's publications get a generation.
#[derive(Debug, Clone)]
pub(crate) enum GenerationPlan {
    /// Publish into this tree.
    Publish(GenerationTarget),
    /// Publish no generation, for the reason given. The configured paths
    /// are written exactly as they always were.
    Skip(String),
}

impl GenerationTarget {
    /// Decides whether `profile`'s publications get a generation, and
    /// where.
    ///
    /// Never an error: a configuration that issued before this tree
    /// existed must keep issuing, so one the tree cannot represent is
    /// skipped and left to its configured paths.
    ///
    /// Two shapes cannot be represented. A generation is a flat
    /// directory of the configured basenames, so two of them coinciding
    /// would make one file overwrite another. And a tree is keyed on the
    /// key's directory and the `registration_id`, so two profiles
    /// agreeing on both would publish into one tree and each `current`
    /// would hold only whichever profile published last.
    pub(crate) fn plan(settings: &Settings, profile: &DaemonProfileSettings) -> GenerationPlan {
        let (Some(cert_name), Some(key_name)) = (
            profile.paths.cert.file_name(),
            profile.paths.key.file_name(),
        ) else {
            return GenerationPlan::Skip(
                "its certificate or key path does not end in a file name".to_string(),
            );
        };
        let bundle = match &settings.trust.ca_bundle_path {
            Some(path) => match path.file_name() {
                Some(name) => Some((path.clone(), name.to_os_string())),
                None => {
                    return GenerationPlan::Skip(
                        "[trust].ca_bundle_path does not end in a file name".to_string(),
                    );
                }
            },
            None => None,
        };
        let bundle_name = bundle.as_ref().map(|(_, name)| name.as_os_str());
        if cert_name == key_name || bundle_name == Some(cert_name) || bundle_name == Some(key_name)
        {
            return GenerationPlan::Skip(
                "two of its certificate, key and CA bundle paths share a file name, and a \
                 generation holds all three in one directory"
                    .to_string(),
            );
        }
        let root = generation_root(&profile.paths.key, &profile.registration_id);
        let sharing = settings
            .profiles
            .iter()
            .filter(|other| generation_root(&other.paths.key, &other.registration_id) == root)
            .count();
        if sharing > 1 {
            return GenerationPlan::Skip(format!(
                "{sharing} profiles share registration_id '{}' and one key directory, and so \
                 one generation tree",
                profile.registration_id
            ));
        }
        GenerationPlan::Publish(Self {
            key_dir: parent_dir(&profile.paths.key),
            root,
            policy: CertGroupPolicy {
                gid: profile.cert_group_gid,
            },
            cert_name: cert_name.to_os_string(),
            key_name: key_name.to_os_string(),
            bundle,
        })
    }

    /// The tree's root, `<key_dir>/.bootroot-generations/<registration_id>`.
    #[cfg(test)]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    /// The symlink naming the latest complete generation.
    fn current(&self) -> PathBuf {
        self.root.join(CURRENT_LINK_NAME)
    }
}

/// Where a generation's certificate and key come from.
pub(crate) enum PairSource {
    /// A renewal: the bytes about to be written at the configured paths.
    Issued {
        /// The certificate file's PEM.
        cert_pem: String,
        /// The private key's PEM.
        key_pem: PrivateKeyPem,
    },
    /// A trust update: the pair of the generation `current` names,
    /// resolved only once the generation lock is held. Never the
    /// configured paths, which a renewal may be halfway through.
    Current,
}

/// What a call to [`publish_generation`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GenerationOutcome {
    /// `current` now names `gen-<generation>`.
    Published {
        /// The number of the generation `current` now names.
        generation: u64,
    },
    /// [`PairSource::Current`] found no `current` to copy a pair from,
    /// and no generation was created. The profile's next issuance publishes
    /// its first generation.
    NoCurrent,
    /// [`PairSource::Current`] found a `current` whose generation does
    /// not hold the profile's certificate and key under their configured
    /// names, and nothing was published. The profile's next issuance
    /// publishes one that does.
    StalePair,
}

/// Publishes one generation into `target`'s tree and swaps `current`
/// onto it.
///
/// The steps, and the order they run in:
///
/// 0. Create `.bootroot-generations/` and the tree's root under the key
///    directory's policy, refusing either one that exists as anything
///    but a directory.
/// 1. Take the generation lock, held through step 6.
/// 2. Choose `n`, one past the largest `gen-<k>` present, and remove
///    what an aborted run left staged. Read every input — the bundle
///    under [`crate::ca_bundle_lock`], and for
///    [`PairSource::Current`] the pair `current` names.
/// 3. Write `gen-<n>.tmp/` and `fsync` each file.
/// 4. `fsync` it, rename it to `gen-<n>`, `fsync` the root.
/// 5. Rename a `current.tmp` symlink over `current`, `fsync` the root.
/// 6. Remove every generation but `gen-<n>` and the one `current` named
///    before step 5.
///
/// The rename of `current` in step 5 is the commit point. A failure
/// before it leaves `current` naming the generation it named before, or
/// absent, and whatever was staged is removed by the next publication's
/// step 2 or step 6. Nothing after it fails the publication — neither
/// the flush that makes the swap durable nor step 6 — and each only
/// warns: `current` already names the new generation and a consumer may
/// have acted on it, so reporting a failure would announce as lost a
/// snapshot consumers are already reading, and would leave the
/// configured pair unwritten behind it.
///
/// # Errors
///
/// Returns an error when the tree cannot be created or is not made of
/// directories, when the lock cannot be taken, when an input cannot be
/// read, or when a file, directory or the `current` link cannot be
/// written, renamed or flushed.
pub(crate) async fn publish_generation(
    target: &GenerationTarget,
    source: PairSource,
    probe: &Probe,
) -> Result<GenerationOutcome> {
    let republish = matches!(source, PairSource::Current);
    if !republish {
        // A first issuance reaches here before the configured pair's
        // writer has created the key directory this tree lives in.
        cert_group::ensure_key_parent_dir(&target.key_dir, target.policy).await?;
    }
    let tree = target.clone();
    let exists = tokio::task::spawn_blocking(move || ensure_tree(&tree, !republish))
        .await
        .context("the generation tree task panicked")??;
    // A trust update does not give a profile with no tree an empty one.
    // That needs no lock: an issuance creates the tree before it takes
    // the lock and reads the bundle only once it holds it, so one that
    // has not created the tree yet reads the bundle this update already
    // wrote. A tree that does exist may have its first issuance under
    // way, holding the lock with an older bundle read, so whether there
    // is a `current` to carry forward is answered under the lock, in
    // `commit`, once that issuance has swapped it.
    if !exists {
        return Ok(GenerationOutcome::NoCurrent);
    }

    probe.reach(PublicationPoint::LockRequested)?;
    let lock = crate::publication_lock::hold_refusing_links(&[&target.current()]).await?;
    // Read with the generation lock held, so a trust update that landed
    // after this renewal merged the bundle is in the snapshot; and under
    // the bundle's own lock, so it is never read out of the middle of
    // another writer's read-merge-write span. Always in this order.
    let bundle = match &target.bundle {
        Some((path, _)) => {
            let _bundle = crate::ca_bundle_lock::hold(path).await;
            match tokio::fs::read(path).await {
                Ok(bytes) => Some(bytes),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
                Err(err) => {
                    return Err(anyhow::Error::new(err).context(format!(
                        "reading the CA bundle {} for a generation",
                        path.display()
                    )));
                }
            }
        }
        None => None,
    };

    let tree = target.clone();
    let probe = probe.clone();
    tokio::task::spawn_blocking(move || {
        // Owned by the blocking task rather than by the future awaiting
        // it: a caller that is cancelled mid-publication drops that
        // future, and the lock must outlast the writes, not the wait.
        let _lock = lock;
        commit(&tree, source, bundle.as_deref(), &probe)
    })
    .await
    .context("the generation publication task panicked")?
}

/// Republishes, for every profile that already has a `current`, the
/// pair it names beside the CA bundle now on disk.
///
/// What a trust update calls once it has replaced the bundle. No
/// post-renew hook runs for one, so without this a consumer watching
/// `current` would keep the superseded bundle until the next renewal.
/// The caller must have released [`crate::ca_bundle_lock`] first: the
/// generation lock is always taken before it.
///
/// A profile with no `current` is left without a tree, and one whose
/// configuration [`GenerationTarget::plan`] cannot represent is left
/// alone as its renewals leave it. Every profile is attempted; the first
/// failure is the one returned.
///
/// # Errors
///
/// Returns an error when a profile's generation cannot be published.
pub(crate) async fn republish_for_trust(settings: &Settings, probe: &Probe) -> Result<()> {
    let mut first_failure = None;
    for profile in &settings.profiles {
        let label = crate::config::profile_domain(settings, profile);
        let GenerationPlan::Publish(target) = GenerationTarget::plan(settings, profile) else {
            continue;
        };
        match publish_generation(&target, PairSource::Current, probe).await {
            Ok(GenerationOutcome::Published { .. } | GenerationOutcome::NoCurrent) => {}
            Ok(GenerationOutcome::StalePair) => tracing::warn!(
                "The current generation of profile '{label}' does not hold its certificate \
                 and key under their configured names, so the new CA bundle was not \
                 republished beside them; the profile's next renewal publishes all three."
            ),
            Err(err) => {
                let err = err.context(format!(
                    "republishing the generation of profile '{label}' with the new CA bundle"
                ));
                tracing::error!("{err:#}");
                first_failure.get_or_insert(err);
            }
        }
    }
    first_failure.map_or(Ok(()), Err)
}

/// Step 0: the two directories above every generation. Returns whether
/// the tree exists, which is always so when `create` is set.
fn ensure_tree(target: &GenerationTarget, create: bool) -> Result<bool> {
    let generations = target
        .root
        .parent()
        .expect("a generation root is always <key_dir>/.bootroot-generations/<id>");
    Ok(ensure_tree_dir(generations, target.policy, create)?
        && ensure_tree_dir(&target.root, target.policy, create)?)
}

/// Creates `path` under the key directory's policy, or re-asserts the
/// policy on the directory already there. Returns whether the directory
/// exists: without `create`, an absent one is left absent.
///
/// Anything else already there — a symlink, a regular file — is refused
/// and not followed: the tree holds a copy of the private key, and a
/// link here would have it written wherever the link points.
fn ensure_tree_dir(path: &Path, policy: CertGroupPolicy, create: bool) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => {}
        Ok(_) => anyhow::bail!(
            "{} must be a directory, but a symlink or another kind of file is in its place; \
             it was not followed and no certificate was published. Remove it, and the next \
             renewal recreates the generation tree",
            path.display()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && !create => return Ok(false),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            match DirBuilder::new().mode(STAGED_DIR_MODE).create(path) {
                Ok(()) => {}
                // Another profile sharing the key directory created the
                // shared level first; the policy below is applied to it
                // either way.
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => {
                    return Err(err).with_context(|| format!("creating {}", path.display()));
                }
            }
        }
        Err(err) => return Err(err).with_context(|| format!("inspecting {}", path.display())),
    }
    apply_dir_policy(path, policy)?;
    Ok(true)
}

/// Gives a directory of the tree the key directory's policy: `0700`, or
/// `0750` and the policy's group.
fn apply_dir_policy(path: &Path, policy: CertGroupPolicy) -> Result<()> {
    let mode = if policy.is_active() {
        KEY_DIR_MODE_GROUP
    } else {
        DIR_MODE_DEFAULT
    };
    apply_owner_and_mode(path, policy, mode)
}

/// Applies the policy's group and then `mode`, in that order, so nothing
/// is group-readable under the writer's primary group first. A call that
/// would change nothing is not made.
fn apply_owner_and_mode(path: &Path, policy: CertGroupPolicy, mode: u32) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("inspecting {}", path.display()))?;
    if meta.file_type().is_symlink() {
        anyhow::bail!(
            "{} became a symlink while it was being published; it was not followed",
            path.display()
        );
    }
    if let Some(gid) = policy.gid
        && meta.gid() != gid
    {
        std::os::unix::fs::chown(path, None, Some(gid))
            .with_context(|| format!("giving {} to gid {gid}", path.display()))?;
    }
    if meta.permissions().mode() & 0o7777 != mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("setting mode {mode:o} on {}", path.display()))?;
    }
    Ok(())
}

/// Steps 2 to 6, with the generation lock held by the caller.
fn commit(
    target: &GenerationTarget,
    source: PairSource,
    bundle: Option<&[u8]>,
    probe: &Probe,
) -> Result<GenerationOutcome> {
    let root = &target.root;
    let current = target.current();
    let previous = current_generation(&current)?;

    let (cert_pem, key_pem) = match source {
        PairSource::Issued { cert_pem, key_pem } => (cert_pem, key_pem),
        PairSource::Current => {
            // Resolved here, under the lock, and not by the caller
            // before it: a renewal that held the lock while this waited
            // has swapped `current` since, and the pair to carry forward
            // is the one it published.
            let Some(previous) = previous else {
                return Ok(GenerationOutcome::NoCurrent);
            };
            let from = root.join(generation_name(previous));
            if !is_generation_dir(&from)? {
                return Ok(GenerationOutcome::StalePair);
            }
            let Some(cert_pem) = read_member(&from.join(&target.cert_name))? else {
                return Ok(GenerationOutcome::StalePair);
            };
            let Some(key_pem) = read_member(&from.join(&target.key_name))? else {
                return Ok(GenerationOutcome::StalePair);
            };
            (cert_pem, PrivateKeyPem::new(key_pem))
        }
    };

    let generation = next_generation(root)?;
    let name = generation_name(generation);
    let staged = root.join(staging_name(&name));
    let staged_link = root.join(staging_name(CURRENT_LINK_NAME));
    remove_entry(&staged)?;
    remove_entry(&staged_link)?;

    DirBuilder::new()
        .mode(STAGED_DIR_MODE)
        .create(&staged)
        .with_context(|| format!("creating {}", staged.display()))?;
    apply_dir_policy(&staged, target.policy)?;
    let key_mode = if target.policy.is_active() {
        KEY_FILE_MODE_GROUP
    } else {
        KEY_FILE_MODE_DEFAULT
    };
    write_member(
        &staged.join(&target.cert_name),
        cert_pem.as_bytes(),
        CERT_FILE_MODE,
        target.policy,
    )?;
    write_member(
        &staged.join(&target.key_name),
        key_pem.expose().as_bytes(),
        key_mode,
        target.policy,
    )?;
    if let (Some((_, bundle_name)), Some(bundle)) = (&target.bundle, bundle) {
        write_member(
            &staged.join(bundle_name),
            bundle,
            CA_BUNDLE_FILE_MODE,
            target.policy,
        )?;
    }
    probe.reach(PublicationPoint::Staged)?;

    // The generation has to be whole on disk before `current` can name
    // it: a consumer acts on the swap, and a power loss must not leave
    // it pointing at a directory whose entries never reached the disk.
    sync_dir(&staged)?;
    let published = root.join(&name);
    std::fs::rename(&staged, &published)
        .with_context(|| format!("renaming {} into place", published.display()))?;
    sync_dir(root)?;
    probe.reach(PublicationPoint::Renamed)?;

    // Relative, so the tree also resolves inside a container that
    // bind-mounts the key directory somewhere else.
    std::os::unix::fs::symlink(&name, &staged_link)
        .with_context(|| format!("creating {}", staged_link.display()))?;
    probe.reach(PublicationPoint::LinkStaged)?;
    std::fs::rename(&staged_link, &current)
        .with_context(|| format!("swapping {} onto {name}", current.display()))?;
    // The commit point: `current` names the new generation, and a
    // consumer watching it may already be reading it. A failure from
    // here on is not reported as a failed publication. The flush only
    // makes the swap durable; without it a crash can bring back the
    // previous generation, which is complete and is replaced by the
    // profile's next publication.
    if let Err(err) = probe
        .reach(PublicationPoint::Swapped)
        .and_then(|()| sync_dir(root))
    {
        tracing::warn!(
            "Swapped {} onto {name} but could not flush the swap to disk, so a crash may \
             bring back the previous generation until the next publication: {err:#}",
            current.display()
        );
    }

    if let Err(err) = prune(root, generation, previous) {
        tracing::warn!(
            "Published {} but could not remove older generations beside it: {err:#}",
            published.display()
        );
    }
    Ok(GenerationOutcome::Published { generation })
}

/// The generation `current` names, or `None` when there is no `current`
/// or it does not name one.
///
/// A `current` that is not a symlink is an error: step 5 renames a link
/// over it, and replacing a directory or a file someone put there is
/// not this publication's to decide.
fn current_generation(current: &Path) -> Result<Option<u64>> {
    match std::fs::symlink_metadata(current) {
        Ok(meta) if meta.file_type().is_symlink() => {}
        Ok(_) => anyhow::bail!(
            "{} must be a symlink to a generation, but another kind of file is in its place; \
             remove it, and the next renewal recreates it",
            current.display()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(err).with_context(|| format!("inspecting {}", current.display()));
        }
    }
    let named = std::fs::read_link(current)
        .with_context(|| format!("reading the link {}", current.display()))?;
    let generation = parse_generation(named.as_os_str());
    if generation.is_none() {
        tracing::warn!(
            "{} names {}, which is not a generation; it is replaced by this publication",
            current.display(),
            named.display()
        );
    }
    Ok(generation)
}

/// One past the largest generation number present in `root`.
fn next_generation(root: &Path) -> Result<u64> {
    let mut largest = 0;
    for entry in read_root(root)? {
        if let Some(generation) = parse_generation(&entry) {
            largest = largest.max(generation);
        }
    }
    largest
        .checked_add(1)
        .with_context(|| format!("{} has run out of generation numbers", root.display()))
}

/// Step 6: removes every generation but the one just published and the
/// one `current` named before it, and everything left staged.
///
/// Every other entry is left alone — the lock file among them, whose
/// inode is the lock.
fn prune(root: &Path, published: u64, previous: Option<u64>) -> Result<()> {
    for entry in read_root(root)? {
        let stale = match parse_generation(&entry) {
            Some(generation) => generation != published && Some(generation) != previous,
            None => is_staged_generation(&entry),
        };
        if stale {
            remove_entry(&root.join(&entry))?;
        }
    }
    Ok(())
}

/// The names of the entries in `root`.
fn read_root(root: &Path) -> Result<Vec<OsString>> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(root).with_context(|| format!("listing {}", root.display()))? {
        names.push(
            entry
                .with_context(|| format!("listing {}", root.display()))?
                .file_name(),
        );
    }
    Ok(names)
}

/// `gen-<generation>`.
fn generation_name(generation: u64) -> String {
    format!("{GENERATION_PREFIX}{generation}")
}

/// The name `name` is staged under before it is renamed into place.
fn staging_name(name: &str) -> String {
    format!("{name}{STAGING_SUFFIX}")
}

/// The number of a canonically named generation: `gen-` followed by a
/// decimal number from 1 up with no leading zero. Anything else —
/// `gen-01`, `gen-0`, `gen-3.tmp` — is not a generation.
fn parse_generation(name: &OsStr) -> Option<u64> {
    let digits = name.to_str()?.strip_prefix(GENERATION_PREFIX)?;
    if digits.starts_with('0') || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

/// Whether `name` is a generation an aborted run left staged.
fn is_staged_generation(name: &OsStr) -> bool {
    name.to_str()
        .is_some_and(|name| name.starts_with(GENERATION_PREFIX) && name.ends_with(STAGING_SUFFIX))
}

/// Whether the generation `current` names is there to copy a pair from.
///
/// A symlink or anything but a directory in its place is refused and not
/// followed: `current` is the only link in the tree ever followed, and
/// following another would carry whatever it points at into a snapshot.
fn is_generation_dir(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => Ok(true),
        Ok(_) => Err(refusal(path, "a directory")),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err).with_context(|| format!("inspecting {}", path.display())),
    }
}

/// The error for an entry of a generation that is not what a
/// publication writes there.
fn refusal(path: &Path, expected: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "{} must be {expected} in the generation tree, but a symlink or another kind of file \
         is in its place; it was not followed and nothing was republished from it. Remove it, \
         and the profile's next renewal publishes a generation that does not use it",
        path.display()
    )
}

/// Removes whatever is at `path`, a directory with its contents, and
/// follows no symlink doing it. Nothing there is not an error.
fn remove_entry(path: &Path) -> Result<()> {
    let removed = match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => std::fs::remove_dir_all(path),
        Ok(_) => std::fs::remove_file(path),
        Err(err) => Err(err),
    };
    match removed {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("removing {}", path.display())),
    }
}

/// Reads one file of a generation, or `None` when the generation does
/// not hold it.
///
/// A symlink in its place is refused rather than followed, as
/// [`is_generation_dir`] refuses one in place of the generation, and so
/// is anything but a regular file. `O_NONBLOCK` keeps a FIFO planted
/// there from stalling the open; it changes nothing for a regular file.
fn read_member(path: &Path) -> Result<Option<String>> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => {
            return Err(refusal(path, "a regular file"));
        }
        Err(err) => return Err(err).with_context(|| format!("opening {}", path.display())),
    };
    let meta = file
        .metadata()
        .with_context(|| format!("inspecting {}", path.display()))?;
    if !meta.file_type().is_file() {
        return Err(refusal(path, "a regular file"));
    }
    let mut contents = String::new();
    file.read_to_string(&mut contents)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(Some(contents))
}

/// Writes one file of a staged generation at its final owner and mode,
/// and flushes it.
///
/// Created `0600` and widened only after the policy's group is on it,
/// exactly as the configured files are staged; flushed last, so the
/// owner and mode are as durable as the bytes.
fn write_member(path: &Path, contents: &[u8], mode: u32, policy: CertGroupPolicy) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(STAGED_FILE_MODE)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))?;
    apply_owner_and_mode(path, policy, mode)?;
    file.sync_all()
        .with_context(|| format!("flushing {}", path.display()))
}

/// Flushes a directory's entry list.
fn sync_dir(dir: &Path) -> Result<()> {
    File::open(dir)
        .with_context(|| format!("opening {} to flush it", dir.display()))?
        .sync_all()
        .with_context(|| format!("flushing {}", dir.display()))
}

#[cfg(test)]
mod tests;
