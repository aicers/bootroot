use std::str::FromStr;

use anyhow::{Context, Result};

/// Represents a supported display language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Locale {
    En,
    Ko,
}

impl Locale {
    /// Parses a locale string, accepting forms like `"en"`, `"en-US"`, `"ko"`, `"ko-KR"`.
    ///
    /// The comparison is case-insensitive and the region subtag is ignored.
    ///
    /// # Errors
    ///
    /// Returns an error if the language code is not supported.
    pub fn parse(input: &str) -> Result<Self> {
        let normalized = input.trim().to_ascii_lowercase();
        let base = normalized
            .split('-')
            .next()
            .context("Missing language code")?;
        match base {
            "en" => Ok(Locale::En),
            "ko" => Ok(Locale::Ko),
            _ => anyhow::bail!("Unsupported language: {input}"),
        }
    }
}

impl FromStr for Locale {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_en_variants() {
        assert_eq!(Locale::parse("en").unwrap(), Locale::En);
        assert_eq!(Locale::parse("EN").unwrap(), Locale::En);
        assert_eq!(Locale::parse("en-US").unwrap(), Locale::En);
    }

    #[test]
    fn parse_ko_variants() {
        assert_eq!(Locale::parse("ko").unwrap(), Locale::Ko);
        assert_eq!(Locale::parse("ko-KR").unwrap(), Locale::Ko);
    }

    #[test]
    fn parse_invalid_returns_error() {
        let err = Locale::parse("fr").unwrap_err();
        assert!(err.to_string().contains("Unsupported language"));
    }

    #[test]
    fn from_str_delegates_to_parse() {
        assert_eq!("en".parse::<Locale>().unwrap(), Locale::En);
        assert_eq!("ko".parse::<Locale>().unwrap(), Locale::Ko);
    }
}
