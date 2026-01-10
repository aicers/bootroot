use crate::{config, eab};

pub(crate) fn resolve_profile_eab(
    profile: &config::ProfileSettings,
    default_eab: Option<eab::EabCredentials>,
) -> Option<eab::EabCredentials> {
    profile.eab.as_ref().map(to_eab_credentials).or(default_eab)
}

pub(crate) fn to_eab_credentials(eab: &config::Eab) -> eab::EabCredentials {
    eab::EabCredentials {
        kid: eab.kid.clone(),
        hmac: eab.hmac.clone(),
    }
}

pub(crate) fn max_concurrent_issuances(settings: &config::Settings) -> anyhow::Result<usize> {
    usize::try_from(settings.scheduler.max_concurrent_issuances).map_err(|_| {
        anyhow::anyhow!("scheduler.max_concurrent_issuances is too large for this platform")
    })
}
