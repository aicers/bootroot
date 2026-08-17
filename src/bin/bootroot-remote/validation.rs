use anyhow::Result;
use bootroot::input_validation::{
    ValidationError, validate_dns_label, validate_domain_name, validate_numeric_instance_id,
    validate_registration_id,
};

use super::{Locale, localized};

/// Validates the `--registration-id` this bootstrap namespaces itself
/// under, through the shared path-safe rule the control plane applies to
/// the same value. One implementation decides which keys are legal, so
/// the two ends of the artifact cannot disagree about a key.
pub(super) fn validate_registration_id_arg(value: &str, lang: Locale) -> Result<()> {
    validate_registration_id(value).map_err(|err| registration_id_error(err, lang))
}

pub(super) fn validate_service_name(value: &str, lang: Locale) -> Result<()> {
    validate_dns_label(value).map_err(|err| service_name_error(err, lang))
}

pub(super) fn validate_profile_hostname(value: &str, lang: Locale) -> Result<()> {
    validate_dns_label(value).map_err(|err| profile_hostname_error(err, lang))
}

pub(super) fn validate_agent_domain(value: &str, lang: Locale) -> Result<()> {
    validate_domain_name(value).map_err(|err| agent_domain_error(err, lang))
}

pub(super) fn validate_profile_instance_id(value: Option<&str>, lang: Locale) -> Result<()> {
    validate_numeric_instance_id(value.unwrap_or_default())
        .map_err(|err| profile_instance_id_error(err, lang))
}

fn registration_id_error(err: ValidationError, lang: Locale) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--registration-id must not be empty",
                "--registration-id 값은 비어 있으면 안 됩니다",
            )
        ),
        ValidationError::InvalidRegistrationId
        | ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::InvalidCidr
        | ValidationError::CidrClearConflict
        | ValidationError::NonNumeric => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--registration-id must be lowercase letters, digits and hyphens, \
                 starting and ending with a letter or digit (max 131 chars)",
                "--registration-id는 영소문자, 숫자, 하이픈만 허용되며 영숫자로 시작하고 \
                 끝나야 합니다(최대 131자)",
            )
        ),
    }
}

fn service_name_error(err: ValidationError, lang: Locale) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--service-name must not be empty",
                "--service-name 값은 비어 있으면 안 됩니다",
            )
        ),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::InvalidCidr
        | ValidationError::CidrClearConflict
        | ValidationError::NonNumeric
        | ValidationError::InvalidRegistrationId => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--service-name must be a DNS label (letters, digits, hyphens only; max 63 chars)",
                "--service-name은 DNS label이어야 합니다(영문자, 숫자, 하이픈만 허용, 최대 63자)",
            )
        ),
    }
}

fn profile_hostname_error(err: ValidationError, lang: Locale) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--profile-hostname must not be empty",
                "--profile-hostname 값은 비어 있으면 안 됩니다",
            )
        ),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::InvalidCidr
        | ValidationError::CidrClearConflict
        | ValidationError::NonNumeric
        | ValidationError::InvalidRegistrationId => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--profile-hostname must be a DNS label (letters, digits, hyphens only; max 63 chars)",
                "--profile-hostname은 DNS label이어야 합니다(영문자, 숫자, 하이픈만 허용, 최대 63자)",
            )
        ),
    }
}

fn agent_domain_error(err: ValidationError, lang: Locale) -> anyhow::Error {
    match err {
        ValidationError::Empty => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--agent-domain must not be empty",
                "--agent-domain 값은 비어 있으면 안 됩니다",
            )
        ),
        ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::InvalidCidr
        | ValidationError::CidrClearConflict
        | ValidationError::NonNumeric
        | ValidationError::InvalidRegistrationId => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--agent-domain must be a DNS name with dot-separated labels (letters, digits, hyphens only)",
                "--agent-domain은 점으로 구분된 DNS label들로 구성된 DNS 이름이어야 합니다(영문자, 숫자, 하이픈만 허용)",
            )
        ),
    }
}

fn profile_instance_id_error(err: ValidationError, lang: Locale) -> anyhow::Error {
    match err {
        ValidationError::Empty
        | ValidationError::InvalidDnsLabel
        | ValidationError::InvalidDomainName
        | ValidationError::InvalidCidr
        | ValidationError::CidrClearConflict
        | ValidationError::NonNumeric
        | ValidationError::InvalidRegistrationId => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--profile-instance-id must be numeric",
                "--profile-instance-id는 숫자만 허용됩니다",
            )
        ),
    }
}
