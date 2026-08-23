//! The four fixed credential files, loaded and published as one set.
//!
//! Missing, partial or invalid material is a typed failure rather than a
//! degraded credential: a chain without its key, or a key whose root
//! fingerprint was never recorded, cannot log in and must not be allowed
//! to look as though it might.

use std::fmt;
use std::path::Path;

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

/// Loads the four credential files as one set.
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
