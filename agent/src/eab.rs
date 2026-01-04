use std::path::PathBuf;

use anyhow::Context;
use serde::Deserialize;
use tokio::fs;

#[derive(Debug, Clone, Deserialize)]
pub struct EabCredentials {
    pub kid: String,
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
