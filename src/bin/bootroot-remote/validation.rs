use anyhow::Result;
use bootroot::input_validation::{
    ValidationError, validate_dns_label, validate_domain_name, validate_numeric_instance_id,
    validate_registration_id,
};
use bootroot::registrar::{RESERVED_SERVICE_NAME_PREFIX, is_reserved_service_name};

use super::{Locale, localized};

/// Validates the `--registration-id` this bootstrap namespaces itself
/// under, through the shared path-safe rule the control plane applies to
/// the same value. One implementation decides which keys are legal, so
/// the two ends of the artifact cannot disagree about a key.
pub(super) fn validate_registration_id_arg(value: &str, lang: Locale) -> Result<()> {
    validate_registration_id(value).map_err(|err| registration_id_error(err, lang))
}

/// Validates the `--service-name` this bootstrap writes into the
/// profile: a DNS label that is not inside bootroot's own reserved
/// namespace.
///
/// The reserved half is the library's shared predicate
/// ([`bootroot::registrar::is_reserved_service_name`]), the same one
/// `bootroot service add` applies, because this flag lands in the same
/// place: it becomes `[[profiles]].service_name`, which is the second
/// label of the SAN the agent then orders. A bootstrap run without
/// `--artifact` takes the value straight from the command line rather
/// than from a control-plane artifact `service add` already vetted, so
/// leaving the check out here would let a reserved name be minted
/// around that guard.
pub(super) fn validate_service_name(value: &str, lang: Locale) -> Result<()> {
    validate_dns_label(value).map_err(|err| service_name_error(err, lang))?;
    if is_reserved_service_name(value) {
        return Err(service_name_error(
            ValidationError::ReservedServiceName,
            lang,
        ));
    }
    Ok(())
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
        | ValidationError::NonNumeric
        | ValidationError::ReservedServiceName => anyhow::anyhow!(
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
        // Its own message, not the DNS-label one: `bootroot-registrar`
        // is a perfectly well-formed label, and an operator told it is
        // not one would go looking for the wrong problem.
        ValidationError::ReservedServiceName => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                &format!(
                    "--service-name must not start with `{RESERVED_SERVICE_NAME_PREFIX}`: \
                     that prefix is reserved for bootroot's own certificate identities",
                ),
                &format!(
                    "--service-name은 `{RESERVED_SERVICE_NAME_PREFIX}`로 시작할 수 없습니다. \
                     해당 접두사는 bootroot 자체 인증서 identity 전용으로 예약되어 있습니다",
                ),
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
        | ValidationError::InvalidRegistrationId
        | ValidationError::ReservedServiceName => anyhow::anyhow!(
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
        | ValidationError::InvalidRegistrationId
        | ValidationError::ReservedServiceName => anyhow::anyhow!(
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
        | ValidationError::InvalidRegistrationId
        | ValidationError::ReservedServiceName => anyhow::anyhow!(
            "{}",
            localized(
                lang,
                "--profile-instance-id must be numeric",
                "--profile-instance-id는 숫자만 허용됩니다",
            )
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bootstrap run without `--artifact` takes `--service-name`
    /// straight from the command line, so the reserved-namespace guard
    /// has to hold here as well as on `bootroot service add`. The rule
    /// reached is the library's shared predicate — this file defines no
    /// reserved name of its own, so there is no second list to drift
    /// from `bootroot::registrar::RESERVED_SERVICE_NAME_PREFIX`.
    #[test]
    fn service_name_refuses_the_reserved_bootroot_prefix() {
        for value in [
            "bootroot-registrar",
            "BOOTROOT-Registrar",
            "bootroot-registrar-endpoint",
            "bootroot-anything",
        ] {
            for lang in [Locale::En, Locale::Ko] {
                let err = validate_service_name(value, lang)
                    .expect_err(&format!("{value} must be refused"));
                assert!(
                    err.to_string().contains(RESERVED_SERVICE_NAME_PREFIX),
                    "{value}: {err}"
                );
            }
        }
    }

    #[test]
    fn service_name_accepts_ordinary_component_keywords() {
        for value in ["roxyd", "piglet", "edge-proxy", "bootroot"] {
            assert!(validate_service_name(value, Locale::En).is_ok(), "{value}");
        }
    }

    /// The reserved refusal is its own message, not the DNS-label one:
    /// `bootroot-registrar` is a well-formed label, and an operator told
    /// it is not one would go looking for the wrong problem.
    #[test]
    fn reserved_and_malformed_service_names_are_refused_differently() {
        let reserved = validate_service_name("bootroot-registrar", Locale::En)
            .expect_err("reserved name")
            .to_string();
        let malformed = validate_service_name("edge_proxy", Locale::En)
            .expect_err("malformed label")
            .to_string();
        assert_ne!(reserved, malformed);
        assert!(!reserved.contains("must be a DNS label"), "{reserved}");
    }
}
