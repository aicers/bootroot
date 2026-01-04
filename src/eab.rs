use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;
use tokio::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct EabCredentials {
    pub kid: String,
    #[serde(alias = "key")]
    pub hmac: String,
}

/// Loads EAB credentials from CLI arguments or a JSON file.
///
/// # Errors
///
/// Returns an error if:
/// - The file path is provided but cannot be read.
/// - The file content is not valid JSON.
pub async fn load_credentials(
    cli_kid: Option<String>,
    cli_hmac: Option<String>,
    file_path: Option<PathBuf>,
) -> anyhow::Result<Option<EabCredentials>> {
    // 1. CLI args take precedence
    if let (Some(kid), Some(hmac)) = (cli_kid, cli_hmac) {
        return Ok(Some(EabCredentials { kid, hmac }));
    }

    // 2. Try loading from file
    if let Some(path) = file_path {
        // Read file directly. If it fails (e.g. not found), we return Error.
        // This fixes "collapsible_if" and improves UX (explicit failure).
        let content = fs::read_to_string(&path)
            .await
            .context("Failed to read EAB file")?;

        if content.trim().is_empty() {
            return Ok(None);
        }

        let creds: EabCredentials =
            serde_json::from_str(&content).context("Failed to parse EAB JSON")?;

        if creds.kid.is_empty() || creds.hmac.is_empty() {
            return Ok(None);
        }

        return Ok(Some(creds));
    }

    Ok(None)
}
#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;
    #[tokio::test]
    async fn test_load_credentials_cli_precedence() {
        let cli_kid = Some("cli-kid".to_string());
        let cli_hmac = Some("cli-hmac".to_string());
        // Create a dummy file that has DIFFERENT credentials
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"kid": "file-kid", "key": "file-hmac"}}"#).unwrap();
        let file_path = Some(file.path().to_path_buf());
        // Action
        let result = load_credentials(cli_kid, cli_hmac, file_path).await;
        // Assert
        let creds = result.unwrap().unwrap();
        assert_eq!(creds.kid, "cli-kid");
        assert_eq!(creds.hmac, "cli-hmac");
    }
    #[tokio::test]
    async fn test_load_credentials_from_file_valid() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, r#"{{"kid": "test-kid", "key": "test-hmac"}}"#).unwrap();
        let path = file.path().to_path_buf();
        let result = load_credentials(None, None, Some(path)).await;
        let creds = result.unwrap().unwrap();
        assert_eq!(creds.kid, "test-kid");
        assert_eq!(creds.hmac, "test-hmac");
    }
    #[tokio::test]
    async fn test_load_credentials_file_malformed() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "not json content").unwrap();
        let path = file.path().to_path_buf();
        let result = load_credentials(None, None, Some(path)).await;
        // Should be an error
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to parse EAB JSON")
        );
    }
    #[tokio::test]
    async fn test_load_credentials_file_not_found() {
        // Path that definitely doesn't exist
        let path = PathBuf::from("/non/existent/path/for/bootroot/test.json");
        let result = load_credentials(None, None, Some(path)).await;
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to read EAB file")
        );
    }
    #[tokio::test]
    async fn test_load_credentials_none() {
        let result = load_credentials(None, None, None).await;
        let creds = result.unwrap();
        assert!(creds.is_none());
    }
}
