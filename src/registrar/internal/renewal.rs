//! The fail-closed guard the internal profile's ordinary renewal runs
//! before it issues.
//!
//! The `auth/cert` entry trusts a *root*, and the fingerprint of that
//! root is recorded beside the credential. A full CA rotation replaces
//! the root in Phase 2 and only replaces the entry, the leaf and the
//! stored fingerprint in the mandatory tail after Phase 4 — so between
//! Phase 3, which publishes the additive trust set and reloads this
//! daemon, and that tail, the stored fingerprint deliberately still
//! names the *old* root while the active one is already the new one.
//!
//! An internal leaf that fell due for renewal inside that window would
//! otherwise be reissued by the ordinary loop, replacing a leaf the
//! entry still trusts with one chained to a root it does not, and doing
//! it through an ACME run and an atomic write that the repair then has
//! to unpick. The credential's rule is the same everywhere it is
//! reached from: compare the stored root with the active one *before*
//! any ACME request, login or write, and refuse with a typed
//! repair-required error on a mismatch.
//!
//! This is a precondition on the existing loop and nothing more. It adds
//! no scheduler, no registration point, no lead-time constant, no retry
//! policy and no failure-reporting path: the refusal travels out through
//! the same post-renew failure hooks every other issuance failure takes,
//! and the daemon keeps ticking, so the tick after the repair renews
//! normally.

use std::path::{Path, PathBuf};

use x509_parser::pem::parse_x509_pem;

use crate::config::DaemonProfileSettings;
use crate::registrar::REGISTRAR_INTERNAL_LABEL;
use crate::registrar::internal::agent_config::INTERNAL_INSTANCE_ID;
use crate::registrar::internal::client::compare_root;
use crate::registrar::internal::{InternalCredentialError, InternalPaths, load_material};

/// The directory `init` writes the deployment CA certificates into,
/// below the state-recorded secrets directory.
const CA_CERTS_DIR: &str = "certs";

/// The deployment root certificate in that directory. The one file the
/// active root is read from, by this guard and by the rotation's own
/// root-fingerprint helper alike.
const CA_ROOT_CERT_FILENAME: &str = "root_ca.crt";

/// Returns the fixed internal layout when `profile` is the
/// bootroot-internal profile, and `None` for every other profile.
///
/// Recognised by the whole of what the generator fixes rather than by
/// the reserved label alone: the label, the instance, and both file
/// paths resolving to the ones [`InternalPaths`] gives the secrets
/// directory the certificate sits under. The staging profile a
/// provisioning or a repair issues through carries the same identity but
/// writes to `registrar-internal/staging`, so it is deliberately not
/// matched — a repair issues its replacement leaf exactly when the
/// stored root no longer matches, and a guard that caught it there could
/// never be satisfied.
#[must_use]
pub fn internal_profile_paths(profile: &DaemonProfileSettings) -> Option<InternalPaths> {
    if profile.service_name != REGISTRAR_INTERNAL_LABEL
        || profile.instance_id != INTERNAL_INSTANCE_ID
    {
        return None;
    }
    let secrets_dir = profile
        .paths
        .cert
        .parent()
        .filter(|dir| dir.file_name() == Some(crate::registrar::internal::INTERNAL_DIR.as_ref()))
        .and_then(Path::parent)?;
    let paths = InternalPaths::new(secrets_dir);
    (paths.chain() == profile.paths.cert && paths.key() == profile.paths.key).then_some(paths)
}

/// The one file the deployment's active root is read from.
///
/// Named in one place because three callers now re-read it — this
/// guard, the rotation's own root-fingerprint helper, and the
/// certificate-login boundary in [`crate::registrar::internal::client`]
/// — and a second spelling of the path would be a second thing to keep
/// in step.
#[must_use]
pub fn active_root_cert_path(secrets_dir: &Path) -> PathBuf {
    secrets_dir.join(CA_CERTS_DIR).join(CA_ROOT_CERT_FILENAME)
}

/// Reads the fingerprint of the deployment root currently on disk.
///
/// # Errors
///
/// Returns [`InternalCredentialError::Io`] when the certificate cannot
/// be read and [`InternalCredentialError::Invalid`] when it is not a
/// PEM certificate.
pub fn active_root_fingerprint(secrets_dir: &Path) -> Result<String, InternalCredentialError> {
    let path = active_root_cert_path(secrets_dir);
    let contents = std::fs::read(&path).map_err(|source| InternalCredentialError::Io {
        operation: "reading",
        path: path.clone(),
        source,
    })?;
    fingerprint_of_root_pem(&path, &contents)
}

/// The same read, without blocking the runtime.
///
/// The certificate-login boundary re-reads the active root on every
/// acquisition of the internal token, and that boundary is async: a
/// synchronous read there would block a worker thread on every verb.
///
/// # Errors
///
/// The same two as [`active_root_fingerprint`].
pub async fn active_root_fingerprint_async(
    secrets_dir: &Path,
) -> Result<String, InternalCredentialError> {
    let path = active_root_cert_path(secrets_dir);
    let contents = tokio::fs::read(&path)
        .await
        .map_err(|source| InternalCredentialError::Io {
            operation: "reading",
            path: path.clone(),
            source,
        })?;
    fingerprint_of_root_pem(&path, &contents)
}

/// Hashes the DER inside a root certificate's PEM, refusing anything
/// that is not one.
fn fingerprint_of_root_pem(
    path: &Path,
    contents: &[u8],
) -> Result<String, InternalCredentialError> {
    let (_, pem) = parse_x509_pem(contents).map_err(|_| InternalCredentialError::Invalid {
        path: path.to_path_buf(),
        reason: "the active root certificate is not a PEM certificate".to_string(),
    })?;
    if pem.label != "CERTIFICATE" {
        return Err(InternalCredentialError::Invalid {
            path: path.to_path_buf(),
            reason: format!("expected a CERTIFICATE PEM block, found {}", pem.label),
        });
    }
    Ok(crate::tls::sha256_hex(&pem.contents))
}

/// Refuses renewal of the bootroot-internal profile while its stored
/// root fingerprint disagrees with the active root.
///
/// A no-op for every other profile: a service leaf is not bound to an
/// `auth/cert` entry, and its renewal across a rotation is exactly what
/// the rotation wants.
///
/// # Errors
///
/// Returns [`InternalCredentialError::RepairRequired`] on a mismatch,
/// and the shared loader's own errors — `Absent`, `Partial`, `Invalid`,
/// `Io` — when the credential the profile names cannot be read. All of
/// them are refusals reached before any ACME request, login or write.
pub fn check_renewal_allowed(
    profile: &DaemonProfileSettings,
) -> Result<(), InternalCredentialError> {
    let Some(paths) = internal_profile_paths(profile) else {
        return Ok(());
    };
    let secrets_dir = paths
        .dir()
        .parent()
        .ok_or_else(|| InternalCredentialError::Invalid {
            path: paths.dir().into(),
            reason: "the internal layout has no parent secrets directory".to_string(),
        })?;
    let material = load_material(&paths)?;
    let active = active_root_fingerprint(secrets_dir)?;
    compare_root(&material.root_fingerprint, &active)
}
