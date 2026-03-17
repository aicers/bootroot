const DNS_LABEL_MAX_LEN: usize = 63;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    Empty,
    InvalidDnsLabel,
    InvalidDomainName,
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
}
