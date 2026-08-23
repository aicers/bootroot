//! The bootroot-internal `OpenBao` client: certificate login, refresh
//! before expiry, and the root-authority check every repair runs first.
//!
//! Nothing here reads a `role_id` or a `secret_id`. The credential is
//! the TLS client certificate, and the only login it performs is
//! `auth/cert/login` over TLS. A plaintext `OpenBao` URL is refused
//! before a socket is opened: the login itself carries no bearer secret,
//! but every request the resulting token then makes does, and a
//! certificate login over plaintext is exactly the mistake this refusal
//! exists to make impossible.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use time::OffsetDateTime;
use tokio::sync::Mutex;

use crate::openbao::OpenBaoClient;
use crate::registrar::internal::material::{InternalMaterial, load_material};
use crate::registrar::internal::renewal::active_root_fingerprint_async;
use crate::registrar::internal::{
    CERT_AUTH_MOUNT, CERT_AUTH_ROLE, InternalCredentialError, InternalPaths,
};
use crate::secret::ClientToken;

/// How long before a token's reported expiry the client re-authenticates.
///
/// A whole minute, deliberately generously: the login is one cheap TLS
/// request and the alternative — discovering the expiry mid-verb — costs
/// a refusal the caller has to retry.
const REFRESH_LEAD: time::Duration = time::Duration::seconds(60);

/// The floor applied to a reported lease duration.
///
/// `OpenBao` reports `0` for a token with no expiry. Treating that as an
/// immediate expiry would re-authenticate on every call, so it is read
/// as "no scheduled refresh" instead.
const NO_EXPIRY: u64 = 0;

/// A cached login: the token and, when the backend gave it one, the
/// moment it stops being usable.
///
/// The token is a [`ClientToken`], the same redacting type
/// `login_cert` returns, so `Debug` is derived here rather than
/// hand-written: nothing in this file ever holds the bytes.
#[derive(Clone, Debug)]
struct CachedLogin {
    token: ClientToken,
    expires_at: Option<OffsetDateTime>,
}

impl CachedLogin {
    /// Whether this login should be replaced before it is used again.
    fn is_stale(&self, now: OffsetDateTime) -> bool {
        self.expires_at
            .is_some_and(|expiry| expiry - REFRESH_LEAD <= now)
    }
}

/// Whether an `OpenBao` failure looks like a rejected or expired token.
///
/// Matched on the status the client renders into its error text, because
/// `OpenBao` answers both cases with 403 and the crate's client surface
/// is `anyhow`. A false positive costs one extra login; a false negative
/// costs a refusal the next call would have to retry anyway.
#[must_use]
pub fn is_expired_token_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.to_string().contains("OpenBao API error (403"))
}

/// The token authority a mutation of the internal credential ran under.
///
/// Constructed only by [`require_root_authority`],
/// so a repair path cannot claim it without having checked.
#[derive(Debug, Clone, Copy)]
pub struct RootAuthority(());

/// The bootroot-internal privileged credential, live.
///
/// Holds the material, the transport that presents it, the cached login
/// and the one piece of fixed deployment state the credential needs to
/// stay honest: the secrets directory it re-reads the *active* root from
/// before every use. Cloning shares one cache — the `reqwest` client
/// underneath is an `Arc` and so is the cache — so two holders never log
/// in twice for the same window.
///
/// A credential is long-lived; the root under it is not. A full CA
/// rotation replaces the root in Phase 2 and only replaces this
/// credential in the mandatory tail after Phase 4, so a verbs object
/// built before that window is still in hand after the root has changed
/// beneath it. Comparing the roots once, at construction, would leave
/// that object logging in — or worse, writing under a still-valid
/// cached token — against an `auth/cert` entry that no longer trusts its
/// leaf. So the comparison is a precondition of *use*, not of
/// construction.
#[derive(Clone)]
pub struct InternalCredential {
    base_url: String,
    client: OpenBaoClient,
    login: Arc<Mutex<Option<CachedLogin>>>,
    root_fingerprint: String,
    secrets_dir: PathBuf,
}

impl fmt::Debug for InternalCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InternalCredential")
            .field("base_url", &self.base_url)
            .field("root_fingerprint", &self.root_fingerprint)
            .field("secrets_dir", &self.secrets_dir)
            .finish_non_exhaustive()
    }
}

impl InternalCredential {
    /// Loads the internal credential from the fixed layout below
    /// `secrets_dir` and builds the client-authenticated transport for
    /// it.
    ///
    /// The three refusals happen in cost order, and each one is reached
    /// before the work the next would do: a plaintext URL before the
    /// credential is read, an absent or partial set before the root is
    /// compared, and a superseded root before a transport is built.
    /// Performs no network request at all — the login happens on first
    /// use — so none of them costs a request either.
    ///
    /// # Errors
    ///
    /// Returns [`InternalCredentialError::PlaintextOpenBaoUrl`] when
    /// `openbao_url` is not `https://`, the loader's own errors when the
    /// material is absent, partial or invalid, and
    /// [`InternalCredentialError::RepairRequired`] when the stored root
    /// fingerprint is not `active_root_fingerprint`. That comparison is
    /// a fail-fast, not the enduring one: every acquisition of the login
    /// re-reads the active root from `secrets_dir` and compares again.
    pub fn load(
        secrets_dir: &Path,
        openbao_url: &str,
        active_root_fingerprint: &str,
    ) -> Result<Self, InternalCredentialError> {
        require_https(openbao_url)?;
        let paths = InternalPaths::new(secrets_dir);
        let material = load_material(&paths)?;
        compare_root(&material.root_fingerprint, active_root_fingerprint)?;
        let bundle = std::fs::read_to_string(paths.ca_bundle()).map_err(|source| {
            InternalCredentialError::Io {
                operation: "reading",
                path: paths.ca_bundle(),
                source,
            }
        })?;
        Self::from_parts(secrets_dir, openbao_url, &material, &bundle)
    }

    /// Builds the credential from already-loaded parts.
    ///
    /// The provisioning path takes this: it holds the freshly issued
    /// material in memory and must prove a certificate login works
    /// *before* any of it is published. `secrets_dir` is the same fixed
    /// location the published credential will sit below, so the staged
    /// credential is held to the same active-root comparison as a loaded
    /// one — a leaf staged against a root that has since been replaced
    /// is refused rather than proved.
    ///
    /// # Errors
    ///
    /// Returns [`InternalCredentialError::PlaintextOpenBaoUrl`] for a
    /// non-HTTPS URL, and [`InternalCredentialError::OpenBao`] when the
    /// transport cannot be built from the supplied PEMs.
    pub fn from_parts(
        secrets_dir: &Path,
        openbao_url: &str,
        material: &InternalMaterial,
        ca_bundle_pem: &str,
    ) -> Result<Self, InternalCredentialError> {
        require_https(openbao_url)?;
        let http = crate::tls::build_http_client_with_identity(
            ca_bundle_pem,
            &material.chain,
            material.key.expose(),
        )
        .map_err(|source| InternalCredentialError::OpenBao {
            operation: "building the client-authenticated OpenBao transport",
            source,
        })?;
        Ok(Self {
            base_url: openbao_url.to_string(),
            client: OpenBaoClient::with_client(openbao_url, http),
            login: Arc::new(Mutex::new(None)),
            root_fingerprint: material.root_fingerprint.clone(),
            secrets_dir: secrets_dir.to_path_buf(),
        })
    }

    /// Builds a credential over a caller-supplied transport, for tests.
    ///
    /// The one construction that skips [`require_https`], so the login
    /// cache and the re-authentication rules can be driven against a
    /// plain-HTTP mock. Production has no path to it: the two public
    /// constructors both go through the TLS refusal.
    #[cfg(test)]
    pub(crate) fn for_test(
        openbao_url: &str,
        secrets_dir: &Path,
        root_fingerprint: &str,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            base_url: openbao_url.to_string(),
            client: OpenBaoClient::new(openbao_url)?,
            login: Arc::new(Mutex::new(None)),
            root_fingerprint: root_fingerprint.to_string(),
            secrets_dir: secrets_dir.to_path_buf(),
        })
    }

    /// The fingerprint of the root this credential was issued under.
    #[must_use]
    pub fn root_fingerprint(&self) -> &str {
        &self.root_fingerprint
    }

    /// Refuses to proceed when the root on disk is no longer the one
    /// the `auth/cert` entry trusts.
    ///
    /// Re-reads the deployment root from the fixed path below the
    /// state-recorded secrets directory rather than trusting a value
    /// captured earlier, because "earlier" is exactly when it was still
    /// right. Called *before* any login or write: a mismatched root
    /// means the entry no longer trusts this leaf, so every one of those
    /// would fail anyway, and attempting them would turn a clean
    /// repair-required into a partial change.
    ///
    /// # Errors
    ///
    /// Returns [`InternalCredentialError::RepairRequired`] on a
    /// mismatch, and the reader's own `Io`/`Invalid` errors when the
    /// active root cannot be read — an unreadable root is a refusal too,
    /// never an assumption that it still matches.
    pub async fn check_active_root(&self) -> Result<(), InternalCredentialError> {
        let active = active_root_fingerprint_async(&self.secrets_dir).await?;
        compare_root(&self.root_fingerprint, &active)
    }

    /// Returns an `OpenBao` client carrying a live token, logging in
    /// again when the cached one is absent, stale or was invalidated.
    ///
    /// The active-root comparison runs first, ahead of the cache: a
    /// mismatch must stop a *cached* token being handed out just as
    /// firmly as it stops a fresh login, or the window between a root
    /// change and a lease expiry would be one in which verb writes
    /// continue unchecked.
    ///
    /// # Errors
    ///
    /// Returns [`InternalCredentialError::RepairRequired`] when the
    /// active root is no longer the one this credential was issued
    /// under, and [`InternalCredentialError::OpenBao`] when the
    /// certificate login fails.
    pub async fn authenticated(&self) -> Result<OpenBaoClient, InternalCredentialError> {
        self.check_active_root().await?;
        let mut guard = self.login.lock().await;
        let now = OffsetDateTime::now_utc();
        let fresh = match guard.as_ref() {
            Some(cached) if !cached.is_stale(now) => cached.clone(),
            _ => {
                let login = self
                    .client
                    .login_cert(CERT_AUTH_MOUNT, CERT_AUTH_ROLE)
                    .await
                    .map_err(|source| InternalCredentialError::OpenBao {
                        operation: "authenticating to OpenBao with the internal certificate",
                        source,
                    })?;
                let expires_at = (login.lease_duration_secs != NO_EXPIRY)
                    .then(|| {
                        i64::try_from(login.lease_duration_secs)
                            .ok()
                            .map(|secs| now + time::Duration::seconds(secs))
                    })
                    .flatten();
                let cached = CachedLogin {
                    token: login.client_token,
                    expires_at,
                };
                *guard = Some(cached.clone());
                cached
            }
        };
        let mut client = self.client.clone();
        client.set_token(fresh.token);
        Ok(client)
    }

    /// Drops the cached login so the next acquisition authenticates
    /// again.
    ///
    /// Called when a request comes back with an expired-token response:
    /// the token is gone as far as this process is concerned, and the
    /// next verb re-authenticates rather than replaying a token
    /// `OpenBao` has already rejected.
    pub async fn invalidate(&self) {
        *self.login.lock().await = None;
    }

    /// Records a failed request, invalidating the cached login when it
    /// looks like the token was the reason.
    pub async fn note_failure(&self, error: &anyhow::Error) {
        if is_expired_token_error(error) {
            self.invalidate().await;
        }
    }
}

/// Confirms an already-authenticated client carries the `root` policy.
///
/// Every repair of the internal credential runs this first. An `AppRole`
/// token — even the runtime-rotate one — is refused with a typed error
/// rather than allowed to fail part-way through a mutation.
///
/// # Errors
///
/// Returns [`InternalCredentialError::RootAuthorityRequired`] naming the
/// policies the token actually carries, and
/// [`InternalCredentialError::OpenBao`] when the lookup itself fails.
pub async fn require_root_authority(
    client: &OpenBaoClient,
) -> Result<RootAuthority, InternalCredentialError> {
    let policies =
        client
            .token_self_policies()
            .await
            .map_err(|source| InternalCredentialError::OpenBao {
                operation: "looking the supplied OpenBao token up",
                source,
            })?;
    if policies.iter().any(|policy| policy == "root") {
        return Ok(RootAuthority(()));
    }
    Err(InternalCredentialError::RootAuthorityRequired { policies })
}

/// The one root-comparison rule, shared by the loader and by
/// [`InternalCredential::check_active_root`].
///
/// Case-insensitive because a fingerprint is hex and both spellings name
/// the same certificate; a second implementation of that would be a
/// second chance to get it wrong.
pub(crate) fn compare_root(stored: &str, active: &str) -> Result<(), InternalCredentialError> {
    if stored.eq_ignore_ascii_case(active) {
        return Ok(());
    }
    Err(InternalCredentialError::RepairRequired {
        stored: stored.to_string(),
        active: active.to_ascii_lowercase(),
    })
}

/// Refuses a non-HTTPS `OpenBao` URL.
///
/// # Errors
///
/// Returns [`InternalCredentialError::PlaintextOpenBaoUrl`] for
/// anything that is not `https://`.
pub fn require_https(openbao_url: &str) -> Result<(), InternalCredentialError> {
    if openbao_url.starts_with("https://") {
        return Ok(());
    }
    Err(InternalCredentialError::PlaintextOpenBaoUrl {
        url: openbao_url.to_string(),
    })
}
