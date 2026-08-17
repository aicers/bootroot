use std::net::IpAddr;

const DNS_LABEL_MAX_LEN: usize = 63;
/// Structural maximum of a `registration_id`: `<63-octet host>-<63-octet
/// component>-<3-digit instance>`, i.e. `63 + 1 + 63 + 1 + 3`.
///
/// A `registration_id` is not a DNS label — it never reaches a
/// certificate name — so it is bounded by the widest key the derivation
/// rule can compose rather than by the 63-octet label limit.
const REGISTRATION_ID_MAX_LEN: usize = 131;
const IPV4_MAX_PREFIX: u8 = 32;
const IPV6_MAX_PREFIX: u8 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    Empty,
    InvalidDnsLabel,
    InvalidDomainName,
    InvalidCidr,
    CidrClearConflict,
    NonNumeric,
    /// The value is not a path-safe registration key: it carries a
    /// character outside `[a-z0-9-]`, does not start and end
    /// alphanumeric, or exceeds [`REGISTRATION_ID_MAX_LEN`] octets.
    /// Distinct from [`ValidationError::InvalidDnsLabel`] because a
    /// registration key may legitimately be longer than a DNS label.
    InvalidRegistrationId,
}

/// Validates a DNS label used for service names and hostnames.
///
/// # Errors
/// Returns an error when the label is empty or not a valid ASCII DNS label.
pub fn validate_dns_label(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty);
    }
    if !is_dns_label(value) {
        return Err(ValidationError::InvalidDnsLabel);
    }
    Ok(())
}

/// Validates a `registration_id`, the deployment-wide unique key every
/// bootroot namespace is derived from (registry entry, `AppRole` and
/// policy names, the `bootroot/services/<key>` KV subtree, the managed
/// `agent.toml` block markers, the per-service fast-poll state
/// filename).
///
/// The rule is path-safe rather than DNS-label-safe: lowercase
/// alphanumeric and hyphen, starting and ending alphanumeric, non-empty,
/// at most 131 octets. A `registration_id` never appears in a
/// certificate, so it is not bound by the 63-octet DNS label limit that
/// [`validate_dns_label`] enforces for `service_name`, `hostname`, and
/// every `domain` label.
///
/// This is the single implementation of that rule. The registrar's
/// derivation library validates the key it composes from parts with this
/// same function, so a key accepted here and a key accepted there can
/// never disagree.
///
/// # Errors
/// Returns [`ValidationError::Empty`] when the value is empty, and
/// [`ValidationError::InvalidRegistrationId`] when it is not path-safe
/// or exceeds 131 octets.
pub fn validate_registration_id(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty);
    }
    if !is_registration_id(value) {
        return Err(ValidationError::InvalidRegistrationId);
    }
    Ok(())
}

/// Validates a dot-separated DNS name used as the root domain.
///
/// # Errors
/// Returns an error when the domain is empty or contains invalid DNS labels.
pub fn validate_domain_name(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty);
    }
    if !value.is_ascii() {
        return Err(ValidationError::InvalidDomainName);
    }
    for label in value.split('.') {
        validate_dns_label(label).map_err(|_| ValidationError::InvalidDomainName)?;
    }
    Ok(())
}

/// Validates a numeric instance identifier.
///
/// # Errors
/// Returns an error when the value is empty or contains non-digit characters.
pub fn validate_numeric_instance_id(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() {
        return Err(ValidationError::Empty);
    }
    if !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(ValidationError::NonNumeric);
    }
    Ok(())
}

/// Validates a single CIDR notation string (e.g. `10.0.0.0/24`, `fd00::/64`).
///
/// # Errors
/// Returns an error when the value is not a valid CIDR block.
pub fn validate_cidr(value: &str) -> Result<(), ValidationError> {
    let Some((addr_str, prefix_str)) = value.split_once('/') else {
        return Err(ValidationError::InvalidCidr);
    };
    let addr: IpAddr = addr_str.parse().map_err(|_| ValidationError::InvalidCidr)?;
    let prefix: u8 = prefix_str
        .parse()
        .map_err(|_| ValidationError::InvalidCidr)?;
    let max = match addr {
        IpAddr::V4(_) => IPV4_MAX_PREFIX,
        IpAddr::V6(_) => IPV6_MAX_PREFIX,
    };
    if prefix > max {
        return Err(ValidationError::InvalidCidr);
    }
    Ok(())
}

/// Validates a list of CIDR values from `--rn-cidrs`.
///
/// # Errors
/// Returns an error when any value is not a valid CIDR block, or when
/// `"clear"` is mixed with real CIDR values.
pub fn validate_cidr_list(values: &[String]) -> Result<(), ValidationError> {
    if values.is_empty() {
        return Ok(());
    }
    let has_clear = values.iter().any(|v| v == "clear");
    if has_clear {
        if values.len() > 1 {
            return Err(ValidationError::CidrClearConflict);
        }
        return Ok(());
    }
    for v in values {
        validate_cidr(v)?;
    }
    Ok(())
}

/// The charset and shape half of [`validate_registration_id`]. The
/// length bound is in octets, matching how the key is spent — as a path
/// component and an `OpenBao` role name — rather than in `char`s.
fn is_registration_id(value: &str) -> bool {
    if !value.is_ascii() || value.len() > REGISTRATION_ID_MAX_LEN {
        return false;
    }
    let Some(first) = value.chars().next() else {
        return false;
    };
    let Some(last) = value.chars().last() else {
        return false;
    };
    if !is_lower_alphanumeric(first) || !is_lower_alphanumeric(last) {
        return false;
    }
    value
        .chars()
        .all(|ch| is_lower_alphanumeric(ch) || ch == '-')
}

fn is_lower_alphanumeric(ch: char) -> bool {
    ch.is_ascii_digit() || ch.is_ascii_lowercase()
}

fn is_dns_label(value: &str) -> bool {
    if !value.is_ascii() || value.len() > DNS_LABEL_MAX_LEN {
        return false;
    }
    let Some(first) = value.chars().next() else {
        return false;
    };
    let Some(last) = value.chars().last() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() || !last.is_ascii_alphanumeric() {
        return false;
    }
    value
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_dns_label_accepts_ascii_label() {
        assert_eq!(validate_dns_label("edge-proxy"), Ok(()));
        assert_eq!(validate_dns_label("Node01"), Ok(()));
    }

    #[test]
    fn validate_dns_label_rejects_invalid_labels() {
        for value in [
            "",
            "edge.proxy",
            "edge_proxy",
            "-edge",
            "edge-",
            "ed ge",
            "é", // non-ASCII
        ] {
            assert!(validate_dns_label(value).is_err(), "{value}");
        }
    }

    #[test]
    fn validate_dns_label_rejects_overlong_labels() {
        let too_long = "a".repeat(DNS_LABEL_MAX_LEN + 1);
        assert_eq!(
            validate_dns_label(&too_long),
            Err(ValidationError::InvalidDnsLabel)
        );
    }

    #[test]
    fn validate_registration_id_accepts_path_safe_keys() {
        for value in [
            "review",
            "h1-roxyd",
            "h1-piglet-001",
            "a",
            "0",
            "aice-web-next",
        ] {
            assert_eq!(validate_registration_id(value), Ok(()), "{value}");
        }
    }

    /// The bound is the structural maximum of
    /// `<63-octet host>-<63-octet component>-<3-digit instance>`: 131
    /// octets are accepted, 132 are not.
    #[test]
    fn validate_registration_id_boundary_is_131_octets() {
        let at_limit = format!(
            "{}-{}-001",
            "h".repeat(DNS_LABEL_MAX_LEN),
            "c".repeat(DNS_LABEL_MAX_LEN)
        );
        assert_eq!(at_limit.len(), REGISTRATION_ID_MAX_LEN);
        assert_eq!(validate_registration_id(&at_limit), Ok(()));

        let over_limit = "a".repeat(REGISTRATION_ID_MAX_LEN + 1);
        assert_eq!(
            validate_registration_id(&over_limit),
            Err(ValidationError::InvalidRegistrationId)
        );
    }

    /// A `registration_id` is deliberately wider than a DNS label: a key
    /// of 64 octets is legal here and rejected by `validate_dns_label`.
    #[test]
    fn validate_registration_id_accepts_keys_longer_than_a_dns_label() {
        let long = "a".repeat(DNS_LABEL_MAX_LEN + 1);
        assert_eq!(validate_registration_id(&long), Ok(()));
        assert!(validate_dns_label(&long).is_err());
    }

    #[test]
    fn validate_registration_id_rejects_empty() {
        assert_eq!(validate_registration_id(""), Err(ValidationError::Empty));
    }

    #[test]
    fn validate_registration_id_rejects_invalid_charset_and_shape() {
        for value in [
            "H1-piglet",  // uppercase
            "h1_piglet",  // underscore
            "-h1-piglet", // leading hyphen
            "h1-piglet-", // trailing hyphen
            "h1.piglet",  // dot
            "h1 piglet",  // space
            "h1/piglet",  // path separator
            "..",         // traversal
            "piglét",     // non-ASCII
        ] {
            assert_eq!(
                validate_registration_id(value),
                Err(ValidationError::InvalidRegistrationId),
                "{value}"
            );
        }
    }

    #[test]
    fn validate_domain_name_accepts_multiple_labels() {
        assert_eq!(validate_domain_name("trusted.domain"), Ok(()));
        assert_eq!(validate_domain_name("EXAMPLE.internal"), Ok(()));
    }

    #[test]
    fn validate_domain_name_rejects_invalid_names() {
        assert_eq!(validate_domain_name(""), Err(ValidationError::Empty));
        for value in [
            "trusted_domain",
            "trusted..domain",
            ".trusted.domain",
            "trusted.domain.",
            "trüsted.domain",
        ] {
            assert_eq!(
                validate_domain_name(value),
                Err(ValidationError::InvalidDomainName),
                "{value}"
            );
        }
    }

    #[test]
    fn validate_numeric_instance_id_accepts_digits() {
        assert_eq!(validate_numeric_instance_id("001"), Ok(()));
    }

    #[test]
    fn validate_numeric_instance_id_rejects_non_numeric_values() {
        assert_eq!(
            validate_numeric_instance_id(""),
            Err(ValidationError::Empty)
        );
        assert_eq!(
            validate_numeric_instance_id("node-01"),
            Err(ValidationError::NonNumeric)
        );
    }

    #[test]
    fn validate_cidr_accepts_valid_ipv4() {
        assert_eq!(validate_cidr("10.0.0.0/24"), Ok(()));
        assert_eq!(validate_cidr("192.168.1.0/32"), Ok(()));
        assert_eq!(validate_cidr("0.0.0.0/0"), Ok(()));
    }

    #[test]
    fn validate_cidr_accepts_valid_ipv6() {
        assert_eq!(validate_cidr("fd00::/64"), Ok(()));
        assert_eq!(validate_cidr("::1/128"), Ok(()));
    }

    #[test]
    fn validate_cidr_rejects_invalid_values() {
        for value in [
            "not-a-cidr",
            "10.0.0.0",
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/abc",
            "/24",
            "",
        ] {
            assert!(validate_cidr(value).is_err(), "{value}");
        }
    }

    #[test]
    fn validate_cidr_list_accepts_valid_list() {
        let values = vec!["10.0.0.0/24".to_string(), "192.168.0.0/16".to_string()];
        assert_eq!(validate_cidr_list(&values), Ok(()));
    }

    #[test]
    fn validate_cidr_list_accepts_clear_alone() {
        let values = vec!["clear".to_string()];
        assert_eq!(validate_cidr_list(&values), Ok(()));
    }

    #[test]
    fn validate_cidr_list_rejects_clear_with_cidrs() {
        let values = vec!["clear".to_string(), "10.0.0.0/24".to_string()];
        assert_eq!(
            validate_cidr_list(&values),
            Err(ValidationError::CidrClearConflict)
        );
    }

    #[test]
    fn validate_cidr_list_rejects_invalid_entry() {
        let values = vec!["10.0.0.0/24".to_string(), "not-a-cidr".to_string()];
        assert_eq!(
            validate_cidr_list(&values),
            Err(ValidationError::InvalidCidr)
        );
    }

    #[test]
    fn validate_cidr_list_accepts_empty() {
        let values: Vec<String> = vec![];
        assert_eq!(validate_cidr_list(&values), Ok(()));
    }
}
