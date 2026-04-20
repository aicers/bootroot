use anyhow::{Context, Result};
use toml_edit::{DocumentMut, Item, Value};

/// Updates or inserts top-level key-value pairs in a TOML document.
///
/// Each value string is interpreted as a TOML literal first (handling
/// booleans and arrays), then falls back to a quoted string.
///
/// # Errors
///
/// Returns an error if `contents` is not valid TOML.
pub fn upsert_top_level_keys(contents: &str, pairs: &[(&str, String)]) -> Result<String> {
    let mut doc: DocumentMut = contents.parse().context("failed to parse TOML content")?;
    for (key, raw) in pairs {
        doc[key] = Item::Value(parse_value(raw));
    }
    Ok(doc.to_string())
}

/// Updates or inserts key-value pairs in a TOML section, preserving
/// existing formatting and comments.
///
/// Each value string is interpreted as a TOML literal first (handling
/// booleans and arrays), then falls back to a quoted string.
///
/// # Errors
///
/// Returns an error if `contents` is not valid TOML.
pub fn upsert_section_keys(
    contents: &str,
    section: &str,
    pairs: &[(&str, String)],
) -> Result<String> {
    let mut doc: DocumentMut = contents.parse().context("failed to parse TOML content")?;

    if doc.get(section).is_none() {
        doc[section] = Item::Table(toml_edit::Table::new());
    }

    if let Some(table) = doc[section].as_table_mut() {
        for (key, raw) in pairs {
            table[key] = Item::Value(parse_value(raw));
        }
    }

    Ok(doc.to_string())
}

/// Inserts top-level key-value pairs only when the key is missing.
///
/// Unlike [`upsert_top_level_keys`], pre-existing operator-customised
/// values are preserved.  Use this to backfill baseline fields (for
/// example `email` / `server`) into an `agent.toml` the operator
/// pointed `--agent-config` at, without clobbering values the operator
/// already set.
///
/// # Errors
///
/// Returns an error if `contents` is not valid TOML.
pub fn insert_missing_top_level_keys(contents: &str, pairs: &[(&str, String)]) -> Result<String> {
    let mut doc: DocumentMut = contents.parse().context("failed to parse TOML content")?;
    for (key, raw) in pairs {
        if doc.get(key).is_none() {
            doc[key] = Item::Value(parse_value(raw));
        }
    }
    Ok(doc.to_string())
}

/// Inserts section key-value pairs only when the key is missing within
/// the section (creating the section if needed).
///
/// Same rationale as [`insert_missing_top_level_keys`]: lets us backfill
/// a full baseline `[acme]` block into a pre-existing `agent.toml`
/// without overwriting operator-customised values.
///
/// # Errors
///
/// Returns an error if `contents` is not valid TOML.
pub fn insert_missing_section_keys(
    contents: &str,
    section: &str,
    pairs: &[(&str, String)],
) -> Result<String> {
    let mut doc: DocumentMut = contents.parse().context("failed to parse TOML content")?;

    if doc.get(section).is_none() {
        doc[section] = Item::Table(toml_edit::Table::new());
    }

    if let Some(table) = doc[section].as_table_mut() {
        for (key, raw) in pairs {
            if table.get(key).is_none() {
                table[key] = Item::Value(parse_value(raw));
            }
        }
    }

    Ok(doc.to_string())
}

/// Removes one or more TOML sections by name.
///
/// Handles both top-level (`"eab"`) and dotted (`"profiles.eab"`)
/// section names.
///
/// # Errors
///
/// Returns an error if `contents` is not valid TOML.
pub fn remove_sections(contents: &str, sections: &[&str]) -> Result<String> {
    let mut doc: DocumentMut = contents.parse().context("failed to parse TOML content")?;

    for section in sections {
        if let Some((parent, child)) = section.split_once('.') {
            if let Some(table) = doc.get_mut(parent).and_then(Item::as_table_mut) {
                table.remove(child);
            }
        } else {
            doc.remove(section);
        }
    }

    Ok(doc.to_string())
}

/// Encodes a string as a TOML basic string with proper escaping.
///
/// Returns the value including surrounding double quotes, with all
/// special characters (backslash, double quote, control characters
/// such as newline and tab) properly escaped via `toml_edit`.
#[must_use]
pub fn toml_encode_string(s: &str) -> String {
    Value::from(s).to_string()
}

/// Parses a raw string as a typed TOML value.
///
/// Tries the TOML literal parser first to handle booleans (`true`,
/// `false`) and arrays (`["a", "b"]`).  Falls back to a plain quoted
/// string for everything else.
fn parse_value(raw: &str) -> Value {
    raw.parse::<Value>().unwrap_or_else(|_| Value::from(raw))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_updates_existing_key() {
        let input = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let output =
            upsert_section_keys(input, "acme", &[("http_responder_hmac", "new".into())]).unwrap();
        assert!(output.contains("http_responder_hmac = \"new\""), "{output}");
    }

    #[test]
    fn upsert_adds_missing_section() {
        let input = "email = \"admin@example.com\"\n";
        let output =
            upsert_section_keys(input, "trust", &[("ca_bundle_path", "certs/ca.pem".into())])
                .unwrap();
        assert!(output.contains("[trust]"), "{output}");
        assert!(
            output.contains("ca_bundle_path = \"certs/ca.pem\""),
            "{output}"
        );
    }

    #[test]
    fn upsert_preserves_unmanaged_keys() {
        let input = "[trust]\nextra = true\n";
        let output =
            upsert_section_keys(input, "trust", &[("ca_bundle_path", "certs/ca.pem".into())])
                .unwrap();
        assert!(output.contains("extra = true"), "{output}");
        assert!(
            output.contains("ca_bundle_path = \"certs/ca.pem\""),
            "{output}"
        );
    }

    #[test]
    fn upsert_is_idempotent() {
        let input = "email = \"admin@example.com\"\n";
        let pairs = vec![("ca_bundle_path", "certs/ca.pem".into())];
        let once = upsert_section_keys(input, "trust", &pairs).unwrap();
        let twice = upsert_section_keys(&once, "trust", &pairs).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn upsert_handles_array_value() {
        let array = r#"["abc", "def"]"#;
        let output =
            upsert_section_keys("", "trust", &[("trusted_ca_sha256", array.into())]).unwrap();
        assert!(
            output.contains("trusted_ca_sha256 = [\"abc\", \"def\"]"),
            "{output}"
        );
    }

    #[test]
    fn upsert_quotes_string_values() {
        let output =
            upsert_section_keys("", "acme", &[("http_responder_hmac", "my-secret".into())])
                .unwrap();
        assert!(
            output.contains("http_responder_hmac = \"my-secret\""),
            "{output}"
        );
    }

    #[test]
    fn upsert_rejects_malformed_toml() {
        let input = "[broken\nkey = \"value\"\n";
        let result = upsert_section_keys(input, "trust", &[("key", "val".into())]);
        assert!(result.is_err());
    }

    #[test]
    fn upsert_top_level_adds_key() {
        let input = "[acme]\nurl = \"x\"\n";
        let output = upsert_top_level_keys(input, &[("domain", "test.local".into())]).unwrap();
        assert!(output.contains("domain = \"test.local\""), "{output}");
        assert!(output.contains("[acme]"), "{output}");
    }

    #[test]
    fn upsert_top_level_updates_existing_key() {
        let input = "domain = \"old.domain\"\n";
        let output = upsert_top_level_keys(input, &[("domain", "new.domain".into())]).unwrap();
        assert!(output.contains("domain = \"new.domain\""), "{output}");
        assert!(!output.contains("old.domain"), "{output}");
    }

    #[test]
    fn upsert_top_level_is_idempotent() {
        let input = "domain = \"test.local\"\n";
        let pairs = vec![("domain", "test.local".into())];
        let once = upsert_top_level_keys(input, &pairs).unwrap();
        let twice = upsert_top_level_keys(&once, &pairs).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn remove_top_level_section() {
        let input = "[acme]\nurl = \"x\"\n\n[eab]\nkid = \"y\"\n";
        let output = remove_sections(input, &["eab"]).unwrap();
        assert!(output.contains("[acme]"), "{output}");
        assert!(!output.contains("[eab]"), "{output}");
    }

    #[test]
    fn remove_dotted_section() {
        let input = "[profiles]\n\n[profiles.eab]\nkid = \"y\"\n";
        let output = remove_sections(input, &["profiles.eab"]).unwrap();
        assert!(output.contains("[profiles]"), "{output}");
        assert!(!output.contains("kid"), "{output}");
    }
}
