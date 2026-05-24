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
    // In reinit mode, if `password.txt` already exists, prefer the
    // stored password so that step-ca CA material (encrypted with that
    // password) remains usable.  Without this, the auto-gen path below
    // would overwrite the existing password and lock the operator out
    // of the preserved root_ca_key / intermediate_ca_key.
    let preserved_stepca_password = if args.reinit_mode {
        let password_path = args.secrets_dir.secrets_dir.join("password.txt");
        if password_path.exists() {
            Some(
                std::fs::read_to_string(&password_path)
                    .with_context(|| {
                        messages.error_read_file_failed(&password_path.display().to_string())
                    })?
                    .trim_end_matches('\n')
                    .to_string(),
            )
        } else {
            None
        }
    } else {
        None
    };
    // Under reinit mode the previous step-ca password and HTTP-01 HMAC
    // are either preserved from the source tree (`password.txt`) or are
    // gone with the wiped OpenBao KV (`http_hmac`, previously at
    // PATH_AGENT_HTTP01). Reinit does not re-prompt operators for fresh
    // secrets, so when a secret cannot be preserved verbatim, generate a
    // replacement non-interactively even without the operator opting
    // into the global `auto-generate` feature.  For the step-ca
    // password this matters specifically when `password.txt` is absent
    // (rsync-clone path or operator-removed): without the reinit_mode
    // bypass, `reinit --yes` would stall on the interactive step-ca
    // password prompt.  An existing `password.txt` still wins above so
    // the preserved CA material remains decryptable.
    let auto_generate_secret = args.has_feature(InitFeature::AutoGenerate) || args.reinit_mode;
    let stepca_password = if let Some(existing) = preserved_stepca_password {
        existing
    } else {
        resolve_secret(
            messages.prompt_stepca_password(),
            args.stepca_password.as_deref(),
            auto_generate_secret,
            messages,
        )?
    };
    let http_hmac = resolve_secret(
        messages.prompt_http_hmac(),
        args.http_hmac.as_deref(),
        auto_generate_secret,
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
    // Reinit does not re-prompt for EAB credentials: the previous EAB
    // material was wiped with OpenBao's KV mount, and `bootroot reinit`
    // intentionally has no EAB CLI surface.  Operators who want to
    // re-register EAB run a follow-up step out of band.
    if args.reinit_mode {
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

    /// Regression: when `reinit_mode` is set and `password.txt` already
    /// exists, `resolve_init_secrets` must return the stored password
    /// verbatim — auto-gen would lock the operator out of the preserved
    /// step-ca CA material that's encrypted with the old password.
    #[test]
    fn resolve_init_secrets_preserves_password_in_reinit_mode() {
        use std::fs;

        use tempfile::tempdir;

        use crate::cli::args::InitFeature;

        let messages = test_messages();
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("password.txt"), "preserved-secret\n").unwrap();

        let mut args = super::super::test_support::default_init_args();
        args.secrets_dir.secrets_dir = secrets;
        args.reinit_mode = true;
        // Auto-generate would normally win — assert it does NOT.
        args.enable = vec![InitFeature::AutoGenerate];
        args.no_eab = true;
        args.http_hmac = Some("provided-hmac".to_string());

        let resolved =
            resolve_init_secrets(&args, &messages, "ignored-dsn".to_string()).expect("resolve");
        assert_eq!(
            resolved.stepca_password, "preserved-secret",
            "reinit_mode must preserve existing password.txt verbatim"
        );
    }

    /// Regression: outside of reinit mode the preserve-password
    /// fast-path must not engage; auto-generation should produce a
    /// fresh secret as before.
    #[test]
    fn resolve_init_secrets_auto_generates_when_not_reinit_mode() {
        use std::fs;

        use tempfile::tempdir;

        use crate::cli::args::InitFeature;

        let messages = test_messages();
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("password.txt"), "should-be-ignored\n").unwrap();

        let mut args = super::super::test_support::default_init_args();
        args.secrets_dir.secrets_dir = secrets;
        args.reinit_mode = false;
        args.enable = vec![InitFeature::AutoGenerate];
        args.no_eab = true;
        args.http_hmac = Some("provided-hmac".to_string());

        let resolved = resolve_init_secrets(&args, &messages, "dsn".to_string()).expect("resolve");
        assert_ne!(
            resolved.stepca_password, "should-be-ignored",
            "outside reinit_mode, auto-generate must run"
        );
        assert!(!resolved.stepca_password.is_empty());
    }

    /// Regression: in reinit mode the previous HTTP-01 HMAC was wiped
    /// along with `OpenBao`'s KV mount, and `bootroot reinit` does not
    /// re-prompt operators for fresh secrets.  Without auto-generating
    /// the HMAC, `reinit --yes` would stall on `prompt_text` for HTTP
    /// HMAC even though the caller has opted into the non-interactive
    /// recovery flow.
    #[test]
    fn resolve_init_secrets_auto_generates_http_hmac_in_reinit_mode() {
        use std::fs;

        use tempfile::tempdir;

        let messages = test_messages();
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        fs::create_dir_all(&secrets).unwrap();
        fs::write(secrets.join("password.txt"), "preserved\n").unwrap();

        let mut args = super::super::test_support::default_init_args();
        args.secrets_dir.secrets_dir = secrets;
        args.reinit_mode = true;
        args.no_eab = true;
        // Crucially: no --http-hmac on the CLI, no AutoGenerate feature
        // — only reinit_mode should drive the auto-gen branch.
        args.http_hmac = None;
        args.enable = Vec::new();

        let resolved =
            resolve_init_secrets(&args, &messages, "ignored-dsn".to_string()).expect("resolve");
        assert!(
            !resolved.http_hmac.is_empty(),
            "reinit_mode must auto-generate a fresh HTTP HMAC instead of prompting"
        );
    }

    /// Regression for #601 §2: under `reinit_mode`, when
    /// `secrets/password.txt` is absent (rsync-clone path or operator
    /// removed it), the step-ca password generation must NOT fall back
    /// to an interactive prompt. The existing `http_hmac`
    /// `|| args.reinit_mode` pattern is mirrored here so `reinit --yes`
    /// without `--enable auto-generate` produces a fresh step-ca
    /// password non-interactively.
    #[test]
    fn resolve_init_secrets_auto_generates_stepca_password_when_missing_in_reinit_mode() {
        use tempfile::tempdir;

        let messages = test_messages();
        let dir = tempdir().unwrap();
        let secrets = dir.path().join("secrets");
        std::fs::create_dir_all(&secrets).unwrap();
        // Crucially: NO password.txt exists.
        assert!(!secrets.join("password.txt").exists());

        let mut args = super::super::test_support::default_init_args();
        args.secrets_dir.secrets_dir = secrets;
        args.reinit_mode = true;
        args.no_eab = true;
        // No --stepca-password, no --enable auto-generate. Only
        // reinit_mode should drive the auto-gen branch.
        args.stepca_password = None;
        args.enable = Vec::new();
        args.http_hmac = Some("provided-hmac".to_string());

        let resolved =
            resolve_init_secrets(&args, &messages, "ignored-dsn".to_string()).expect("resolve");
        assert!(
            !resolved.stepca_password.is_empty(),
            "reinit_mode must auto-generate a fresh step-ca password instead of prompting"
        );
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
