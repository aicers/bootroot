use std::net::IpAddr;

const DNS_LABEL_MAX_LEN: usize = 63;
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
