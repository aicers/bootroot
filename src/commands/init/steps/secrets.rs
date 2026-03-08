use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::super::constants::openbao_constants::PATH_AGENT_EAB;
use super::super::constants::{DEFAULT_EAB_ENDPOINT_PATH, SECRET_BYTES};
use super::super::types::EabCredentials;
use super::prompts::{prompt_text, prompt_yes_no};
use super::{InitRollback, InitSecrets};
use crate::cli::args::{InitArgs, InitFeature};
use crate::i18n::Messages;

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
    match (&args.eab_kid, &args.eab_hmac) {
        (Some(kid), Some(hmac)) => Ok(Some(EabCredentials {
            kid: kid.clone(),
            hmac: hmac.clone(),
        })),
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
    if args.has_feature(InitFeature::EabAuto) {
        let credentials = issue_eab_via_stepca(args, messages)
            .await
            .with_context(|| messages.error_eab_auto_failed())?;
        register_eab_secret(
            client,
            &args.openbao.kv_mount,
            rollback,
            &credentials,
            messages,
        )
        .await?;
        return Ok(Some(credentials));
    }
    if !prompt_yes_no(messages.prompt_eab_register_now(), messages)? {
        return Ok(None);
    }
    if prompt_yes_no(messages.prompt_eab_auto_now(), messages)? {
        let credentials = issue_eab_via_stepca(args, messages)
            .await
            .with_context(|| messages.error_eab_auto_failed())?;
        register_eab_secret(
            client,
            &args.openbao.kv_mount,
            rollback,
            &credentials,
            messages,
        )
        .await?;
        return Ok(Some(credentials));
    }
    println!("{}", messages.eab_prompt_instructions());
    let kid = prompt_text(messages.prompt_eab_kid(), messages)?;
    let hmac = prompt_text(messages.prompt_eab_hmac(), messages)?;
    let credentials = EabCredentials { kid, hmac };
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

async fn issue_eab_via_stepca(args: &InitArgs, messages: &Messages) -> Result<EabCredentials> {
    bootroot::eab::issue_eab_via_stepca(
        &args.stepca_url,
        &args.stepca_provisioner,
        DEFAULT_EAB_ENDPOINT_PATH,
    )
    .await
    .with_context(|| messages.error_eab_auto_failed())
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
}
