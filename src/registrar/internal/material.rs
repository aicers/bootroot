//! The four fixed credential files, loaded and published as one set.
//!
//! Missing, partial or invalid material is a typed failure rather than a
//! degraded credential: a chain without its key, or a key whose root
//! fingerprint was never recorded, cannot log in and must not be allowed
//! to look as though it might.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::cert_group::CertGroupPolicy;
use crate::fs_util::{self, Destination, KEY_FILE_MODE, StagedMode};
use crate::registrar::internal::{
    ACME_ACCOUNT_FILE, AGENT_CONFIG_FILE, CA_BUNDLE_FILE, CHAIN_FILE, InternalCredentialError,
    InternalPaths, KEY_FILE, ROOT_FINGERPRINT_FILE,
};

/// Length of a hex-encoded SHA-256 fingerprint.
const FINGERPRINT_HEX_LEN: usize = 64;

/// The opening of every PEM block header.
const PEM_OPENING: &str = "-----BEGIN ";

/// The internal leaf's private key, in PEM.
///
/// A newtype whose `Debug` prints `<redacted>`, following the verb
/// layer's `WrappedSecretIdToken`: a `#[derive(Debug)]` on anything that
/// holds one cannot leak it into a log line, a trace field or an error.
///
/// It derives no `PartialEq` either, for the same reason that one does
/// not: a derived comparison on a secret-bearing type is a
/// byte-at-a-time timing oracle. Nothing compares two private keys —
/// the credential is proved by using it, not by matching it.
#[derive(Clone)]
pub struct PrivateKeyPem(String);

impl PrivateKeyPem {
    /// Wraps a PEM private key at the boundary it enters the program.
    #[must_use]
    pub fn new(pem: String) -> Self {
        Self(pem)
    }

    /// Borrows the raw PEM, for the one writer and the one TLS builder
    /// that need it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for PrivateKeyPem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// The internal profile's persistent ACME account signing key.
///
/// Redacted, and un-comparable, for the same reasons as
/// [`PrivateKeyPem`]: an ACME account key is the credential the CA
/// identifies the account by.
#[derive(Clone)]
pub struct AcmeAccountKey(String);

impl AcmeAccountKey {
    /// Wraps an account key at the boundary it enters the program.
    #[must_use]
    pub fn new(contents: String) -> Self {
        Self(contents)
    }

    /// Borrows the raw contents.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AcmeAccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

/// One host's loaded internal credential.
///
/// `Debug` is derivable precisely because both secret members redact
/// themselves; the chain and the fingerprint are public certificate
/// data and are printed as they are. `PartialEq` is not derivable, and
/// deliberately: it would reach the secret members' bytes.
#[derive(Debug, Clone)]
pub struct InternalMaterial {
    /// The leaf's private key.
    pub key: PrivateKeyPem,
    /// The leaf and the chain it was issued with, in PEM.
    pub chain: String,
    /// The persistent ACME account signing key.
    pub acme_account: AcmeAccountKey,
    /// Hex SHA-256 of the root the `auth/cert` entry trusts.
    pub root_fingerprint: String,
}

/// Whether an endpoint-enabled host's internal artifact set is there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterialStatus {
    /// Not one of the six files exists — the endpoint-disabled case, and
    /// the pre-provisioning case.
    Absent,
    /// Some exist and some do not, naming the absent ones in layout
    /// order.
    Partial(Vec<String>),
    /// All six exist.
    Present,
}

/// Every file name the all-or-none set covers, in layout order.
const SET_FILES: [&str; 6] = [
    KEY_FILE,
    CHAIN_FILE,
    ACME_ACCOUNT_FILE,
    ROOT_FINGERPRINT_FILE,
    AGENT_CONFIG_FILE,
    CA_BUNDLE_FILE,
];

/// Reports whether the six-file set is absent, partial or complete.
///
/// The config and the private bundle are in the set with the four
/// credential files because they are provisioned, rotated and repaired
/// together: a credential whose config was never written renews nothing,
/// and a config whose bundle is missing fails every trust check.
#[must_use]
pub fn material_status(paths: &InternalPaths) -> MaterialStatus {
    let dir = paths.dir();
    let missing: Vec<String> = SET_FILES
        .iter()
        .filter(|name| !dir.join(name).exists())
        .map(|name| (*name).to_string())
        .collect();
    if missing.is_empty() {
        MaterialStatus::Present
    } else if missing.len() == SET_FILES.len() {
        MaterialStatus::Absent
    } else {
        MaterialStatus::Partial(missing)
    }
}

/// Loads the four credential files, after proving the whole six-file
/// set is usable.
///
/// The shared loader every caller reaches the credential through — the
/// verb factory, the rotation's up-to-date check and the repair — so
/// the all-or-none rule is enforced in one place. Presence alone is not
/// enough: the two members this function does not return are validated
/// here too, because a private bundle that holds no certificate and a
/// generated config that no longer describes this identity both leave a
/// host whose credential cannot be renewed, and neither is something a
/// caller should have to remember to check for itself.
///
/// # Errors
///
/// Returns [`InternalCredentialError::Absent`] when nothing is
/// provisioned, [`InternalCredentialError::Partial`] when the set is
/// incomplete, [`InternalCredentialError::Invalid`] when a file does not
/// hold what it must, and [`InternalCredentialError::Io`] when one
/// cannot be read.
pub fn load_material(paths: &InternalPaths) -> Result<InternalMaterial, InternalCredentialError> {
    match material_status(paths) {
        MaterialStatus::Absent => return Err(InternalCredentialError::Absent(paths.dir().into())),
        MaterialStatus::Partial(missing) => {
            return Err(InternalCredentialError::Partial {
                dir: paths.dir().into(),
                missing,
            });
        }
        MaterialStatus::Present => {}
    }

    let key = read_file(&paths.key(), "reading")?;
    let chain = read_file(&paths.chain(), "reading")?;
    let acme_account = read_file(&paths.acme_account(), "reading")?;
    let root_fingerprint = read_file(&paths.root_fingerprint(), "reading")?;

    validate_pem_label(&paths.key(), &key, "PRIVATE KEY")?;
    validate_pem_label(&paths.chain(), &chain, "CERTIFICATE")?;
    if acme_account.trim().is_empty() {
        return Err(InternalCredentialError::Invalid {
            path: paths.acme_account(),
            reason: "the ACME account key is empty".to_string(),
        });
    }
    let root_fingerprint = normalize_fingerprint(&paths.root_fingerprint(), &root_fingerprint)?;

    let bundle = read_file(&paths.ca_bundle(), "reading")?;
    validate_pem_label(&paths.ca_bundle(), &bundle, "CERTIFICATE")?;
    crate::registrar::internal::load_internal_config(paths)?;

    Ok(InternalMaterial {
        key: PrivateKeyPem::new(key),
        chain,
        acme_account: AcmeAccountKey::new(acme_account),
        root_fingerprint,
    })
}

/// Publishes the four credential files atomically.
///
/// The key and the ACME account key are staged and renamed at
/// [`KEY_FILE_MODE`], so neither is ever observable at the final path
/// under a wider mode. The chain and the fingerprint are public
/// certificate data and take the same publish for atomicity rather than
/// for secrecy.
///
/// # Errors
///
/// Returns [`InternalCredentialError::Io`] when the directory cannot be
/// created or a file cannot be published.
pub async fn publish_material(
    paths: &InternalPaths,
    material: &InternalMaterial,
) -> Result<(), InternalCredentialError> {
    fs_util::ensure_secrets_dir(paths.dir())
        .await
        .map_err(|err| InternalCredentialError::Io {
            operation: "creating",
            path: paths.dir().into(),
            source: std::io::Error::other(err.to_string()),
        })?;

    write_atomic(&paths.key(), material.key.expose().as_bytes()).await?;
    write_atomic(&paths.chain(), material.chain.as_bytes()).await?;
    write_atomic(
        &paths.acme_account(),
        material.acme_account.expose().as_bytes(),
    )
    .await?;
    write_atomic(
        &paths.root_fingerprint(),
        format!("{}\n", material.root_fingerprint).as_bytes(),
    )
    .await?;
    Ok(())
}

/// The directory a publication snapshots the prior set into.
///
/// A sibling of the published names, like the staging directory: the
/// snapshot of a secret stays inside the directory whose permissions
/// already protect it, and a restore is a rename within one filesystem.
pub const PRIOR_DIR: &str = ".prior";

/// What a publication found at one member of the set before it wrote
/// over it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PriorMember {
    /// Nothing was there. A restore removes whatever the failed
    /// publication managed to write, leaving the host as bare as it
    /// found it.
    Missing,
    /// A regular file, whose bytes are in the snapshot directory.
    Snapshotted,
    /// Something that is not a regular file — a directory a broken host
    /// left at a credential name. It cannot be copied, and it is not
    /// this publication's to delete, so a restore leaves it exactly as
    /// found.
    Irregular,
}

/// The prior state of the six-file set, held while a publication
/// replaces it.
///
/// Each of the six files publishes atomically on its own, but the *set*
/// does not: a failure part-way through leaves some members replaced and
/// the rest as they were, and a new key beside an old chain is a
/// credential that still reads as complete and can no longer log in.
/// That is exactly the state a re-run of `init` must not create, since
/// its rollback deliberately leaves an already-provisioned directory
/// alone rather than deleting the working credential it found.
///
/// So a publication captures the prior set first, writes, and on any
/// failure puts back what it captured: every member that existed
/// returns to its own bytes and its own mode, and every member that did
/// not is removed again. Only a publication that completed discards the
/// snapshot.
pub struct SetSnapshot {
    paths: InternalPaths,
    prior: PathBuf,
    members: Vec<(&'static str, PriorMember)>,
}

/// Captures the prior state of the whole set, before a publication
/// begins replacing it.
///
/// Copies rather than moves: the published names keep their current
/// contents until the publication overwrites them, so a concurrent
/// reader never sees a member vanish.
///
/// # Errors
///
/// Returns [`InternalCredentialError::Io`] when a stale snapshot cannot
/// be cleared, when a member cannot be inspected or read, or when the
/// snapshot cannot be written. A publication that cannot be undone does
/// not start.
pub async fn capture_set(paths: &InternalPaths) -> Result<SetSnapshot, InternalCredentialError> {
    capture_members(paths, &SET_FILES).await
}

/// Captures the prior state of `names`, a subset of the set.
///
/// The same guarantee [`capture_set`] gives, for a caller that replaces
/// part of the set rather than all of it: a rotation rewrites only the
/// private bundle and the config's pins, and copying the private key
/// beside them would put a second copy of it on disk for no reason.
///
/// # Errors
///
/// Returns [`InternalCredentialError::Io`] under the same conditions as
/// [`capture_set`].
pub async fn capture_members(
    paths: &InternalPaths,
    names: &[&'static str],
) -> Result<SetSnapshot, InternalCredentialError> {
    let prior = paths.dir().join(PRIOR_DIR);
    if prior.exists() {
        // A snapshot that survived is one an earlier run could not
        // clear; the set beside it is the state to preserve now.
        tokio::fs::remove_dir_all(&prior)
            .await
            .map_err(|source| InternalCredentialError::Io {
                operation: "removing",
                path: prior.clone(),
                source,
            })?;
    }

    let mut members = Vec::with_capacity(names.len());
    let mut prior_dir_ready = false;
    for name in names.iter().copied() {
        let path = paths.dir().join(name);
        let state = match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() => {
                if !prior_dir_ready {
                    fs_util::ensure_secrets_dir(&prior).await.map_err(|err| {
                        InternalCredentialError::Io {
                            operation: "creating",
                            path: prior.clone(),
                            source: std::io::Error::other(err.to_string()),
                        }
                    })?;
                    prior_dir_ready = true;
                }
                let contents =
                    tokio::fs::read(&path)
                        .await
                        .map_err(|source| InternalCredentialError::Io {
                            operation: "reading",
                            path: path.clone(),
                            source,
                        })?;
                write_atomic(&prior.join(name), &contents).await?;
                PriorMember::Snapshotted
            }
            Ok(_) => PriorMember::Irregular,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => PriorMember::Missing,
            Err(source) => {
                return Err(InternalCredentialError::Io {
                    operation: "inspecting",
                    path,
                    source,
                });
            }
        };
        members.push((name, state));
    }

    Ok(SetSnapshot {
        paths: paths.clone(),
        prior,
        members,
    })
}

impl SetSnapshot {
    /// The directory the captured bytes are held in, for a caller that
    /// has to name it after a restore failed.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.prior
    }

    /// Puts the captured set back, member by member.
    ///
    /// Every member is attempted even after one fails, so a restore that
    /// cannot repair one file still repairs the other five, and the
    /// first failure is what it reports. The snapshot is kept on
    /// failure — see [`SetSnapshot::discard`].
    ///
    /// # Errors
    ///
    /// Returns the first [`InternalCredentialError::Io`] a member's
    /// restore produced.
    pub async fn restore(&self) -> Result<(), InternalCredentialError> {
        let mut first_error = None;
        for (name, state) in &self.members {
            let path = self.paths.dir().join(name);
            let outcome = match state {
                PriorMember::Snapshotted => self.restore_member(name, &path).await,
                PriorMember::Missing => remove_if_present(&path).await,
                PriorMember::Irregular => Ok(()),
            };
            if let Err(err) = outcome
                && first_error.is_none()
            {
                first_error = Some(err);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    /// Removes the captured bytes.
    ///
    /// Called once the set is either published whole or restored whole —
    /// never while the snapshot is still the only copy of the prior
    /// credential.
    ///
    /// # Errors
    ///
    /// Returns [`InternalCredentialError::Io`] when the snapshot
    /// directory cannot be removed.
    pub async fn discard(self) -> Result<(), InternalCredentialError> {
        if !self.prior.exists() {
            return Ok(());
        }
        tokio::fs::remove_dir_all(&self.prior)
            .await
            .map_err(|source| InternalCredentialError::Io {
                operation: "removing",
                path: self.prior.clone(),
                source,
            })
    }

    /// Republishes one captured member through the same writer that
    /// publishes it normally, so the restored file carries the mode the
    /// layout gives it rather than the snapshot's.
    async fn restore_member(&self, name: &str, path: &Path) -> Result<(), InternalCredentialError> {
        let backup = self.prior.join(name);
        if name == CA_BUNDLE_FILE {
            let pem = tokio::fs::read_to_string(&backup).await.map_err(|source| {
                InternalCredentialError::Io {
                    operation: "reading",
                    path: backup.clone(),
                    source,
                }
            })?;
            return fs_util::write_ca_bundle(path, &pem, CertGroupPolicy::none())
                .await
                .map_err(|err| InternalCredentialError::Io {
                    operation: "writing",
                    path: path.to_path_buf(),
                    source: std::io::Error::other(err.to_string()),
                });
        }
        let contents =
            tokio::fs::read(&backup)
                .await
                .map_err(|source| InternalCredentialError::Io {
                    operation: "reading",
                    path: backup,
                    source,
                })?;
        write_atomic(path, &contents).await
    }
}

/// Removes a member a failed publication created where nothing was.
async fn remove_if_present(path: &Path) -> Result<(), InternalCredentialError> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(InternalCredentialError::Io {
            operation: "removing",
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Publishes one internal file by rename at `0600`.
///
/// `Destination::bootroot_owned` because every path here is one bootroot
/// derived from the state-recorded secrets directory: a symlink at one
/// of them is a redirection vector, not an operator convenience.
pub(crate) async fn write_atomic(
    path: &Path,
    contents: &[u8],
) -> Result<(), InternalCredentialError> {
    fs_util::atomic_write(
        Destination::bootroot_owned(path),
        contents,
        StagedMode::Policy(KEY_FILE_MODE),
    )
    .await
    .map_err(|err| InternalCredentialError::Io {
        operation: "writing",
        path: path.to_path_buf(),
        source: std::io::Error::other(err.to_string()),
    })
}

fn read_file(path: &Path, operation: &'static str) -> Result<String, InternalCredentialError> {
    std::fs::read_to_string(path).map_err(|source| InternalCredentialError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    })
}

/// Confirms `contents` holds at least one PEM block whose label ends in
/// `label`.
///
/// The suffix match is what admits `EC PRIVATE KEY` and `RSA PRIVATE
/// KEY` alongside the PKCS#8 `PRIVATE KEY` this code writes, without
/// admitting a certificate where a key belongs.
fn validate_pem_label(
    path: &Path,
    contents: &str,
    label: &str,
) -> Result<(), InternalCredentialError> {
    let matched = contents.lines().any(|line| {
        let line = line.trim();
        line.starts_with(PEM_OPENING) && line.trim_end_matches('-').trim_end().ends_with(label)
    });
    if matched {
        return Ok(());
    }
    Err(InternalCredentialError::Invalid {
        path: path.to_path_buf(),
        reason: format!("no PEM block labelled `{label}` was found"),
    })
}

/// Normalizes a stored fingerprint to lowercase hex and rejects
/// anything that is not one.
fn normalize_fingerprint(path: &Path, contents: &str) -> Result<String, InternalCredentialError> {
    let trimmed = contents.trim();
    if trimmed.len() != FINGERPRINT_HEX_LEN || !trimmed.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(InternalCredentialError::Invalid {
            path: path.to_path_buf(),
            reason: format!("expected {FINGERPRINT_HEX_LEN} hex digits"),
        });
    }
    Ok(trimmed.to_ascii_lowercase())
}
