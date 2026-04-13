use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;
use serde::Deserialize;

use super::agent_config::apply_agent_config_updates;
use super::io::{pull_secrets, read_secret_file, write_eab_file, write_secret_file};
use super::summary::{ApplyItemSummary, ApplySummary, merge_apply_status, print_summary};
use super::validation::{
    validate_agent_domain, validate_profile_hostname, validate_profile_instance_id,
    validate_service_name,
};
use super::{Locale, ResolvedBootstrapArgs, localized};

// This function intentionally keeps end-to-end bootstrap orchestration in one place
// so status aggregation and exit-code semantics stay easy to audit.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_bootstrap(args: ResolvedBootstrapArgs, lang: Locale) -> Result<i32> {
    let wrapped = args.wrap_token.is_some();

    if let Some(wrap_token) = &args.wrap_token {
        unwrap_and_write_secret_id(
            &args.openbao_url,
            wrap_token,
            &args.secret_id_path,
            args.wrap_expires_at.as_deref(),
            &args.service_name,
            lang,
        )
        .await?;
    }

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

    let pulled = pull_secrets(&client, &args.kv_mount, &args.service_name, wrapped, lang).await?;
    let secret_id_status = if wrapped {
        ApplyItemSummary::applied(super::summary::ApplyStatus::Applied)
    } else {
        match write_secret_file(&args.secret_id_path, &pulled.secret_id).await {
            Ok(status) => ApplyItemSummary::applied(status),
            Err(err) => ApplyItemSummary::failed(localized(
                lang,
                &format!("secret_id apply failed: {err}"),
                &format!("secret_id 반영 실패: {err}"),
            )),
        }
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

fn validate_hook_flags(args: &ResolvedBootstrapArgs) -> Result<()> {
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

fn validate_bootstrap_args(args: &ResolvedBootstrapArgs, lang: Locale) -> Result<()> {
    validate_hook_flags(args)?;
    if args.service_name.is_empty() {
        anyhow::bail!(localized(
            lang,
            "service-name is required",
            "service-name 값이 필요합니다",
        ));
    }
    validate_service_name(&args.service_name, lang)?;
    validate_profile_hostname(&args.profile_hostname, lang)?;
    validate_agent_domain(&args.agent_domain, lang)?;
    validate_profile_instance_id(args.profile_instance_id.as_deref(), lang)?;
    for path in [
        &args.role_id_path,
        &args.secret_id_path,
        &args.eab_file_path,
    ] {
        if path.as_os_str().is_empty() {
            anyhow::bail!(localized(
                lang,
                "Required path argument is missing (provide --artifact or individual flags)",
                "필수 경로 인수가 누락되었습니다 (--artifact 또는 개별 플래그를 제공하세요)",
            ));
        }
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
    if args.wrap_token.is_none() && !args.secret_id_path.exists() {
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

/// Response from `sys/wrapping/unwrap` for `AppRole` `secret_id`.
#[derive(Deserialize)]
struct UnwrapSecretIdResponse {
    data: UnwrapSecretIdData,
}

#[derive(Deserialize)]
struct UnwrapSecretIdData {
    secret_id: String,
}

async fn unwrap_and_write_secret_id(
    openbao_url: &str,
    wrap_token: &str,
    secret_id_path: &std::path::Path,
    wrap_expires_at: Option<&str>,
    service_name: &str,
    lang: Locale,
) -> Result<()> {
    if let Some(parent) = secret_id_path.parent() {
        fs_util::ensure_secrets_dir(parent).await?;
    }
    let client = OpenBaoClient::new(openbao_url).with_context(|| {
        localized(
            lang,
            "Failed to create OpenBao client for unwrap",
            "unwrap을 위한 OpenBao 클라이언트를 생성하지 못했습니다",
        )
    })?;
    let result: Result<UnwrapSecretIdResponse> = client.unwrap_secret(wrap_token).await;
    match result {
        Ok(response) => {
            tokio::fs::write(secret_id_path, &response.data.secret_id)
                .await
                .with_context(|| {
                    localized(
                        lang,
                        &format!(
                            "Failed to write unwrapped secret_id to {}",
                            secret_id_path.display()
                        ),
                        &format!(
                            "unwrap된 secret_id를 쓰지 못했습니다: {}",
                            secret_id_path.display()
                        ),
                    )
                })?;
            fs_util::set_key_permissions(secret_id_path).await?;
            Ok(())
        }
        Err(err) => {
            if is_wrap_token_expired(wrap_expires_at) {
                anyhow::bail!(
                    "{}",
                    localized(
                        lang,
                        &format!(
                            "Wrap token has expired. To recover, re-run on the control node:\n\n  \
                             bootroot rotate approle-secret-id --service-name {service_name}\n\n\
                             Then transfer the new artifact and retry bootstrap."
                        ),
                        &format!(
                            "Wrap 토큰이 만료되었습니다. 복구하려면 제어 노드에서 다시 실행하세요:\n\n  \
                             bootroot rotate approle-secret-id --service-name {service_name}\n\n\
                             새 아티팩트를 전송한 후 부트스트랩을 다시 시도하세요."
                        ),
                    )
                );
            }
            anyhow::bail!(
                "{}",
                localized(
                    lang,
                    &format!(
                        "SECURITY WARNING: Wrap token has already been unwrapped.\n\
                         This may indicate the secret_id for service '{service_name}' has been \
                         compromised by an unauthorized party.\n\
                         Investigate immediately and consider rotating credentials:\n\n  \
                         bootroot rotate approle-secret-id --service-name {service_name}\n\n\
                         Original error: {err}"
                    ),
                    &format!(
                        "보안 경고: Wrap 토큰이 이미 unwrap되었습니다.\n\
                         서비스 '{service_name}'의 secret_id가 무단 접근으로 유출되었을 수 있습니다.\n\
                         즉시 조사하고 자격 증명을 교체하세요:\n\n  \
                         bootroot rotate approle-secret-id --service-name {service_name}\n\n\
                         원본 오류: {err}"
                    ),
                )
            );
        }
    }
}

fn is_wrap_token_expired(wrap_expires_at: Option<&str>) -> bool {
    let Some(expires_str) = wrap_expires_at else {
        return false;
    };
    let Ok(expires_epoch) = expires_str.parse::<u64>() else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    now > expires_epoch
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{HookFailurePolicy, OutputFormat, ResolvedBootstrapArgs};

    fn dummy_args() -> ResolvedBootstrapArgs {
        ResolvedBootstrapArgs {
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
            wrap_token: None,
            wrap_expires_at: None,
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

    #[test]
    fn is_wrap_token_expired_returns_true_for_past_epoch() {
        assert!(super::is_wrap_token_expired(Some("1000000000")));
    }

    #[test]
    fn is_wrap_token_expired_returns_false_for_future_epoch() {
        let future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        assert!(!super::is_wrap_token_expired(Some(&future.to_string())));
    }

    #[test]
    fn is_wrap_token_expired_returns_false_for_none() {
        assert!(!super::is_wrap_token_expired(None));
    }

    #[test]
    fn is_wrap_token_expired_returns_false_for_invalid() {
        assert!(!super::is_wrap_token_expired(Some("not-a-number")));
    }

    #[test]
    fn secret_id_file_check_skipped_when_wrap_token_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let role_id = dir.path().join("role_id");
        std::fs::write(&role_id, "rid").expect("write role_id");
        let secret_id = dir.path().join("secret_id");
        let eab = dir.path().join("eab.json");

        let mut args = dummy_args();
        args.service_name = "svc".to_string();
        args.role_id_path = role_id;
        args.secret_id_path = secret_id;
        args.eab_file_path = eab;
        args.profile_hostname = "host".to_string();
        args.profile_instance_id = Some("1".to_string());
        args.agent_domain = "d.com".to_string();
        args.wrap_token = Some("tok".to_string());

        let result = validate_bootstrap_args(&args, Locale::En);
        assert!(
            result.is_ok(),
            "should pass when wrap_token present: {result:?}"
        );
    }
}
