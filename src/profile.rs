use crate::{config, eab};

/// Resolves the effective EAB credentials for a profile.
pub fn resolve_profile_eab(
    profile: &config::ProfileSettings,
    default_eab: Option<eab::EabCredentials>,
) -> Option<eab::EabCredentials> {
    profile.eab.as_ref().map(to_eab_credentials).or(default_eab)
}

#[must_use]
pub fn to_eab_credentials(eab: &config::Eab) -> eab::EabCredentials {
    eab::EabCredentials {
        kid: eab.kid.clone(),
        hmac: eab.hmac.clone(),
    }
}

/// Calculates the maximum concurrent issuances.
///
/// # Errors
/// Returns an error if the configured limit is invalid.
pub fn max_concurrent_issuances(settings: &config::Settings) -> anyhow::Result<usize> {
    usize::try_from(settings.scheduler.max_concurrent_issuances).map_err(|_| {
        anyhow::anyhow!("scheduler.max_concurrent_issuances is too large for this platform")
    })
}
