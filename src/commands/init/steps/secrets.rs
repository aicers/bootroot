use anyhow::{Context, Result};
use base64::Engine;
use bootroot::openbao::OpenBaoClient;

use super::super::constants::SECRET_BYTES;
use super::super::constants::openbao_constants::PATH_AGENT_EAB;
use super::super::types::EabCredentials;
use super::prompts::{prompt_text, prompt_yes_no};
use super::{InitRollback, InitSecrets};
use crate::cli::args::{InitArgs, InitFeature};
use crate::i18n::Messages;

/// Minimum decoded length for an ACME EAB HMAC (typical step-ca / Boulder
/// HMACs are 32 bytes; we accept down to 16 to tolerate other CAs).
const MIN_EAB_HMAC_BYTES: usize = 16;

pub(super) fn resolve_init_secrets(
    args: &InitArgs,
    messages: &Messages,
    db_dsn: String,
) -> Result<InitSecrets> {
    let stepca_password = resolve_secret(
        messages.prompt_stepca_password(),
        args.stepca_password.as_deref(),
        args.has_feature(InitFeature::AutoGenerate),
        messages,
    )?;
    let http_hmac = resolve_secret(
        messages.prompt_http_hmac(),
        args.http_hmac.as_deref(),
        args.has_feature(InitFeature::AutoGenerate),
        messages,
    )?;
    let eab = resolve_eab(args, messages)?;

    Ok(InitSecrets {
        stepca_password,
        db_dsn,
        http_hmac,
        eab,
    })
}

fn resolve_secret(
    label: &str,
    value: Option<&str>,
    auto_generate: bool,
    messages: &Messages,
) -> Result<String> {
    if let Some(value) = value {
        return Ok(value.to_string());
    }
    if auto_generate {
        return bootroot::utils::generate_secret(SECRET_BYTES)
            .with_context(|| messages.error_generate_secret_failed());
    }
    prompt_text(&format!("{label}: "), messages)
}

fn resolve_eab(args: &InitArgs, messages: &Messages) -> Result<Option<EabCredentials>> {
    if args.no_eab {
        return Ok(None);
    }
    match (&args.eab_kid, &args.eab_hmac) {
        (Some(kid), Some(hmac)) => {
            let validated = validate_eab(kid, hmac)?;
            Ok(Some(validated))
        }
        (None, None) => Ok(None),
        _ => anyhow::bail!(messages.error_eab_requires_both()),
    }
}

pub(super) async fn maybe_register_eab(
    client: &OpenBaoClient,
    args: &InitArgs,
    messages: &Messages,
    rollback: &mut InitRollback,
    secrets: &InitSecrets,
) -> Result<Option<EabCredentials>> {
    if secrets.eab.is_some() {
        return Ok(None);
    }
    if args.no_eab {
        return Ok(None);
    }
    if !prompt_yes_no(messages.prompt_eab_register_now(), messages)? {
        return Ok(None);
    }
    println!("{}", messages.eab_prompt_instructions());
    let credentials = prompt_eab_with_validation(messages)?;
    register_eab_secret(
        client,
        &args.openbao.kv_mount,
        rollback,
        &credentials,
        messages,
    )
    .await?;
    Ok(Some(credentials))
}

/// Re-prompts the operator until both `kid` and `hmac` validate. The
/// operator who realises mid-prompt that they don't have EAB material
/// aborts with Ctrl-C and re-runs `init` (eventually with `--no-eab`).
/// Coercing blank-to-"no EAB" silently here would leak the same garbage
/// (kid="", hmac="") into KV that issue #588 §3 closes.
fn prompt_eab_with_validation(messages: &Messages) -> Result<EabCredentials> {
    loop {
        let kid = prompt_text(messages.prompt_eab_kid(), messages)?;
        let hmac = prompt_text(messages.prompt_eab_hmac(), messages)?;
        match validate_eab(&kid, &hmac) {
            Ok(creds) => return Ok(creds),
            Err(err) => {
                eprintln!("{err}");
            }
        }
    }
}

/// Validates EAB inputs to close the symptom from issue #588 §3a:
/// today's parser silently accepts `y` of length 1 as the HMAC, and
/// step-ca only fails at first issuance with `Failed to decode EAB key:
/// Invalid input length: 1`. Validation: `kid` non-empty after trim;
/// `hmac` base64url-decodable to >= 16 bytes.
fn validate_eab(kid: &str, hmac: &str) -> Result<EabCredentials> {
    let kid = kid.trim();
    let hmac = hmac.trim();
    if kid.is_empty() {
        anyhow::bail!("EAB kid must not be empty");
    }
    if hmac.is_empty() {
        anyhow::bail!("EAB hmac must not be empty");
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(hmac)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(hmac))
        .map_err(|err| anyhow::anyhow!("EAB hmac must be base64url-encoded: {err}"))?;
    if decoded.len() < MIN_EAB_HMAC_BYTES {
        anyhow::bail!(
            "EAB hmac decodes to {} bytes; expected at least {MIN_EAB_HMAC_BYTES}",
            decoded.len()
        );
    }
    Ok(EabCredentials {
        kid: kid.to_string(),
        hmac: hmac.to_string(),
    })
}

async fn register_eab_secret(
    client: &OpenBaoClient,
    kv_mount: &str,
    rollback: &mut InitRollback,
    credentials: &EabCredentials,
    messages: &Messages,
) -> Result<()> {
    if !client
        .kv_exists(kv_mount, PATH_AGENT_EAB)
        .await
        .with_context(|| messages.error_openbao_kv_exists_failed())?
    {
        rollback.written_kv_paths.push(PATH_AGENT_EAB.to_string());
    }
    client
        .write_kv(
            kv_mount,
            PATH_AGENT_EAB,
            serde_json::json!({ "kid": credentials.kid, "hmac": credentials.hmac }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::test_support::test_messages;
    use super::*;

    #[test]
    fn test_resolve_secret_prefers_value() {
        let messages = test_messages();
        let value = resolve_secret("step-ca password", Some("value"), false, &messages).unwrap();
        assert_eq!(value, "value");
    }

    #[test]
    fn test_resolve_secret_auto_generates() {
        let messages = test_messages();
        let value = resolve_secret("HTTP-01 HMAC", None, true, &messages).unwrap();
        assert!(!value.is_empty());
    }

    #[test]
    fn validate_eab_rejects_single_char_hmac() {
        let err = validate_eab("kid-1", "y").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("base64url") || msg.contains("at least"),
            "expected validation message, got: {msg}"
        );
    }

    #[test]
    fn validate_eab_rejects_empty_kid() {
        let err = validate_eab("   ", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap_err();
        assert!(err.to_string().contains("kid"));
    }

    #[test]
    fn validate_eab_accepts_32_byte_base64url() {
        // 32 bytes → 43 base64url-no-pad chars.
        let bytes = [0xAB; 32];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let creds = validate_eab("kid-1", &encoded).expect("valid EAB");
        assert_eq!(creds.kid, "kid-1");
        assert_eq!(creds.hmac, encoded);
    }
}
