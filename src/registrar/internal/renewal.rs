//! Where the bootroot-internal profile and the deployment's active root
//! are recognised.
//!
//! The internal leaf is signed offline by `bootroot init` and replaced
//! only under the `OpenBao` root token, so the daemon issues nothing for
//! the profile that names it: [`internal_profile_paths`] is how each of
//! its issuance paths tells that profile from every other one, and skips
//! it.
//!
//! The fingerprint of the root the leaf was signed under is recorded
//! beside the credential. A full CA rotation replaces the root in Phase
//! 2 and only replaces the entry, the leaf and the stored fingerprint in
//! the mandatory tail after Phase 4, so in between the stored
//! fingerprint deliberately still names the *old* root while the active
//! one is already the new one. The readers of the active root below are
//! what the certificate-login boundary and the rotation compare it
//! with.

use std::path::{Path, PathBuf};

use x509_parser::pem::parse_x509_pem;

use crate::config::DaemonProfileSettings;
use crate::registrar::REGISTRAR_INTERNAL_LABEL;
use crate::registrar::internal::agent_config::INTERNAL_INSTANCE_ID;
use crate::registrar::internal::{InternalCredentialError, InternalPaths};

/// The directory `init` writes the deployment CA certificates into,
/// below the state-recorded secrets directory.
const CA_CERTS_DIR: &str = "certs";

/// The deployment root certificate in that directory. The one file the
/// active root is read from, by the certificate-login boundary and by
/// the rotation's own root-fingerprint helper alike.
const CA_ROOT_CERT_FILENAME: &str = "root_ca.crt";

/// Returns the fixed internal layout when `profile` is the
/// bootroot-internal profile, and `None` for every other profile.
///
/// Recognised by the whole of what the generator fixes rather than by
/// the reserved label alone: the label, the instance, and both file
/// paths resolving to the ones [`InternalPaths`] gives the secrets
/// directory the certificate sits under. A profile carrying the same
/// identity at other paths is an ordinary profile, and is issued for
/// like one: what the daemon must not do is replace the leaf the
/// `auth/cert` entry is pinned to, and that leaf is at these paths and
/// nowhere else.
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
/// Named in one place because more than one caller re-reads it — the
/// rotation's own root-fingerprint helper and the certificate-login
/// boundary in [`crate::registrar::internal::client`] — and a second
/// spelling of the path would be a second thing to keep in step.
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
