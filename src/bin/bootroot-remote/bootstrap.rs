use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::agent_config::apply_agent_config_updates;
use super::io::{pull_secrets, read_secret_file, write_eab_file, write_secret_file};
use super::summary::{ApplyItemSummary, ApplySummary, merge_apply_status, print_summary};
use super::validation::{
    validate_agent_domain, validate_profile_hostname, validate_profile_instance_id,
    validate_service_name,
};
use super::{BootstrapArgs, Locale, localized};

// This function intentionally keeps end-to-end bootstrap orchestration in one place
// so status aggregation and exit-code semantics stay easy to audit.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_bootstrap(args: BootstrapArgs, lang: Locale) -> Result<i32> {
    validate_bootstrap_args(&args, lang)?;

    let role_id = read_secret_file(&args.role_id_path, lang)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to read role_id from {}",
                    args.role_id_path.display()
                ),
                &format!(
                    "role_id 파일을 읽지 못했습니다: {}",
                    args.role_id_path.display()
                ),
            )
        })?;
    let current_secret_id = read_secret_file(&args.secret_id_path, lang)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to read current secret_id from {}",
                    args.secret_id_path.display()
                ),
                &format!(
                    "현재 secret_id 파일을 읽지 못했습니다: {}",
                    args.secret_id_path.display()
                ),
            )
        })?;

    let mut client = OpenBaoClient::new(&args.openbao_url).with_context(|| {
        localized(
            lang,
            "Failed to create OpenBao client",
            "OpenBao 클라이언트를 생성하지 못했습니다",
        )
    })?;
    let token = client
        .login_approle(&role_id, &current_secret_id)
        .await
        .with_context(|| {
            localized(
                lang,
                "OpenBao AppRole login failed",
                "OpenBao AppRole 로그인에 실패했습니다",
            )
        })?;
    client.set_token(token);

    let pulled = pull_secrets(&client, &args.kv_mount, &args.service_name, lang).await?;
    let secret_id_status = match write_secret_file(&args.secret_id_path, &pulled.secret_id).await {
        Ok(status) => ApplyItemSummary::applied(status),
        Err(err) => ApplyItemSummary::failed(localized(
            lang,
            &format!("secret_id apply failed: {err}"),
            &format!("secret_id 반영 실패: {err}"),
        )),
    };
    let eab_status =
        match write_eab_file(&args.eab_file_path, &pulled.eab_kid, &pulled.eab_hmac).await {
            Ok(status) => ApplyItemSummary::applied(status),
            Err(err) => ApplyItemSummary::failed(localized(
                lang,
                &format!("eab apply failed: {err}"),
                &format!("eab 반영 실패: {err}"),
            )),
        };

    let (responder_hmac_status, mut trust_sync_status) =
        apply_agent_config_updates(&args, &pulled, lang).await;

    match write_secret_file(&args.ca_bundle_path, &pulled.ca_bundle_pem).await {
        Ok(bundle_status) => {
            trust_sync_status = merge_apply_status(trust_sync_status, bundle_status, None);
        }
        Err(err) => {
            trust_sync_status = ApplyItemSummary::failed(localized(
                lang,
                &format!(
                    "ca bundle apply failed ({}): {err}",
                    args.ca_bundle_path.display()
                ),
                &format!(
                    "ca bundle 반영 실패 ({}): {err}",
                    args.ca_bundle_path.display()
                ),
            ));
        }
    }

    let summary = ApplySummary {
        secret_id: secret_id_status,
        eab: eab_status,
        responder_hmac: responder_hmac_status,
        trust_sync: trust_sync_status,
    };
    print_summary(&summary, args.output, lang)?;
    if summary.has_failures() {
        return Ok(1);
    }
    Ok(0)
}

fn validate_hook_flags(args: &BootstrapArgs) -> Result<()> {
    if args.post_renew_command.is_none()
        && (!args.post_renew_arg.is_empty()
            || args.post_renew_timeout_secs.is_some()
            || args.post_renew_on_failure.is_some())
    {
        anyhow::bail!(
            "--post-renew-arg, --post-renew-timeout-secs, and \
             --post-renew-on-failure require --post-renew-command"
        );
    }
    if let Some(cmd) = args.post_renew_command.as_deref()
        && cmd.trim().is_empty()
    {
        anyhow::bail!("--post-renew-command must not be empty");
    }
    if let Some(0) = args.post_renew_timeout_secs {
        anyhow::bail!("--post-renew-timeout-secs must be greater than 0");
    }
    Ok(())
}

fn validate_bootstrap_args(args: &BootstrapArgs, lang: Locale) -> Result<()> {
    validate_hook_flags(args)?;
    validate_service_name(&args.service_name, lang)?;
    validate_profile_hostname(&args.profile_hostname, lang)?;
    validate_agent_domain(&args.agent_domain, lang)?;
    validate_profile_instance_id(args.profile_instance_id.as_deref(), lang)?;
    for path in [
        &args.role_id_path,
        &args.secret_id_path,
        &args.eab_file_path,
    ] {
        let parent = path.parent().ok_or_else(|| {
            anyhow::anyhow!(
                "{}",
                localized(
                    lang,
                    &format!("Path {} has no parent directory", path.display()),
                    &format!("경로의 상위 디렉터리가 없습니다: {}", path.display()),
                )
            )
        })?;
        if !parent.exists() {
            anyhow::bail!(
                "{}",
                localized(
                    lang,
                    &format!("Parent directory not found: {}", parent.display()),
                    &format!("상위 디렉터리를 찾을 수 없습니다: {}", parent.display()),
                )
            );
        }
    }
    if !args.role_id_path.exists() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                &format!("role_id file not found: {}", args.role_id_path.display()),
                &format!(
                    "role_id 파일을 찾을 수 없습니다: {}",
                    args.role_id_path.display()
                ),
            )
        );
    }
    if !args.secret_id_path.exists() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                &format!(
                    "secret_id file not found: {}",
                    args.secret_id_path.display()
                ),
                &format!(
                    "secret_id 파일을 찾을 수 없습니다: {}",
                    args.secret_id_path.display()
                ),
            )
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{HookFailurePolicy, OutputFormat};

    /// Builds a `BootstrapArgs` with dummy values.  Only hook-related fields
    /// are meaningful — `validate_hook_flags` runs before any other check, so
    /// the remaining fields are never inspected in these tests.
    fn dummy_args() -> BootstrapArgs {
        BootstrapArgs {
            openbao_url: String::new(),
            kv_mount: String::new(),
            service_name: String::new(),
            role_id_path: PathBuf::new(),
            secret_id_path: PathBuf::new(),
            eab_file_path: PathBuf::new(),
            agent_config_path: PathBuf::new(),
            agent_email: String::new(),
            agent_server: String::new(),
            agent_domain: String::new(),
            agent_responder_url: String::new(),
            profile_hostname: String::new(),
            profile_instance_id: None,
            profile_cert_path: None,
            profile_key_path: None,
            ca_bundle_path: PathBuf::new(),
            post_renew_command: None,
            post_renew_arg: Vec::new(),
            post_renew_timeout_secs: None,
            post_renew_on_failure: None,
            output: OutputFormat::Text,
        }
    }

    #[test]
    fn hook_flags_without_command_are_rejected() {
        let mut args = dummy_args();
        args.post_renew_arg = vec!["reload".to_string()];
        args.post_renew_timeout_secs = Some(60);

        let err = validate_hook_flags(&args).unwrap_err();
        assert!(
            err.to_string().contains("--post-renew-command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn hook_timeout_alone_without_command_is_rejected() {
        let mut args = dummy_args();
        args.post_renew_timeout_secs = Some(60);

        let err = validate_hook_flags(&args).unwrap_err();
        assert!(
            err.to_string().contains("--post-renew-command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn hook_on_failure_alone_without_command_is_rejected() {
        let mut args = dummy_args();
        args.post_renew_on_failure = Some(HookFailurePolicy::Stop);

        let err = validate_hook_flags(&args).unwrap_err();
        assert!(
            err.to_string().contains("--post-renew-command"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn hook_flags_with_command_are_accepted() {
        let mut args = dummy_args();
        args.post_renew_command = Some("/usr/bin/reload.sh".to_string());
        args.post_renew_arg = vec!["--fast".to_string()];
        args.post_renew_timeout_secs = Some(60);

        assert!(validate_hook_flags(&args).is_ok());
    }

    #[test]
    fn no_hook_flags_are_accepted() {
        let args = dummy_args();
        assert!(validate_hook_flags(&args).is_ok());
    }

    #[test]
    fn empty_command_is_rejected() {
        let mut args = dummy_args();
        args.post_renew_command = Some(String::new());

        let err = validate_hook_flags(&args).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn whitespace_only_command_is_rejected() {
        let mut args = dummy_args();
        args.post_renew_command = Some("   ".to_string());

        let err = validate_hook_flags(&args).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn zero_timeout_is_rejected() {
        let mut args = dummy_args();
        args.post_renew_command = Some("reload.sh".to_string());
        args.post_renew_timeout_secs = Some(0);

        let err = validate_hook_flags(&args).unwrap_err();
        assert!(
            err.to_string().contains("greater than 0"),
            "unexpected error: {err}"
        );
    }
}
