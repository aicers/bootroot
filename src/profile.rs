use crate::{config, eab};

pub(crate) const SPIFFE_URI_FORMAT: &str =
    "spiffe://{trust_domain}/{hostname}/{daemon_name}/{instance_id}";

pub(crate) fn build_spiffe_uri(
    settings: &config::Settings,
    profile: &config::ProfileSettings,
) -> String {
    SPIFFE_URI_FORMAT
        .replace("{trust_domain}", &settings.spiffe_trust_domain)
        .replace("{hostname}", &profile.hostname)
        .replace("{daemon_name}", &profile.daemon_name)
        .replace("{instance_id}", &profile.instance_id)
}

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
