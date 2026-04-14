use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::agent_config::apply_agent_config_updates;
use super::io::{pull_secrets, read_secret_file, write_eab_file, write_secret_file};
use super::summary::{ApplyItemSummary, ApplySummary, merge_apply_status, print_summary};
use super::validation::{
    validate_agent_domain, validate_profile_hostname, validate_profile_instance_id,
    validate_service_name,
};
use super::{Locale, ResolvedBootstrapArgs, localized};

/// Errors specific to wrap-token unwrapping.
#[derive(Debug)]
enum UnwrapError {
    /// The wrap token has expired. Operator must re-run `bootroot service add`
    /// on the control node to mint a fresh wrap token and ship the updated artifact.
    Expired { service_name: String },
    /// The wrap token was already consumed. This indicates the `secret_id`
    /// may have been intercepted by a third party.
    AlreadyUnwrapped { service_name: String },
}

/// Substring present in `OpenBao` API errors returned by `parse_response`.
/// Used to distinguish token-related failures from unrelated errors (TLS,
/// network, server 500, etc.) so that unrelated errors bubble through
/// without being misclassified.
const OPENBAO_API_ERROR_PREFIX: &str = "OpenBao API error";

// This function intentionally keeps end-to-end bootstrap orchestration in one place
// so status aggregation and exit-code semantics stay easy to audit.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_bootstrap(args: ResolvedBootstrapArgs, lang: Locale) -> Result<i32> {
    validate_bootstrap_args(&args, lang)?;

    // When a wrap_token is present in the artifact, unwrap it to obtain
    // the secret_id and write it to the expected file path before login.
    if let Some(wrap_token) = &args.wrap_token {
        match unwrap_and_write_secret_id(
            &args.openbao_url,
            wrap_token,
            args.wrap_expires_at.as_deref(),
            &args.secret_id_path,
            &args.service_name,
            lang,
        )
        .await
        {
            Ok(()) => {}
            Err(err) => return Err(err),
        }
    }

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

/// Unwraps a response-wrapped `secret_id` and writes it to the
/// expected file path. Classifies failures as expired or
/// already-unwrapped tokens with appropriate error messages.
async fn unwrap_and_write_secret_id(
    openbao_url: &str,
    wrap_token: &str,
    wrap_expires_at: Option<&str>,
    secret_id_path: &std::path::Path,
    service_name: &str,
    lang: Locale,
) -> Result<()> {
    let client = OpenBaoClient::new(openbao_url).with_context(|| {
        localized(
            lang,
            "Failed to create OpenBao client for unwrap",
            "언래핑을 위한 OpenBao 클라이언트를 생성하지 못했습니다",
        )
    })?;
    match client.unwrap_secret_id(wrap_token).await {
        Ok(secret_id) => {
            write_secret_file(secret_id_path, &secret_id)
                .await
                .with_context(|| {
                    localized(
                        lang,
                        &format!(
                            "Failed to write unwrapped secret_id to {}",
                            secret_id_path.display()
                        ),
                        &format!(
                            "언래핑된 secret_id를 기록하지 못했습니다: {}",
                            secret_id_path.display()
                        ),
                    )
                })?;
            Ok(())
        }
        Err(err) => {
            let Some(unwrap_err) = classify_unwrap_error(&err, wrap_expires_at, service_name)
            else {
                return Err(err).with_context(|| {
                    localized(
                        lang,
                        "Failed to unwrap secret_id from OpenBao",
                        "OpenBao에서 secret_id를 언래핑하지 못했습니다",
                    )
                });
            };
            match unwrap_err {
                UnwrapError::Expired { service_name } => {
                    let msg = localized(
                        lang,
                        &format!(
                            "Wrap token for service '{service_name}' has expired. To recover:\n\n  \
                             1. Re-run `bootroot service add` with the same arguments on the control node.\n     \
                                The idempotent rerun issues a fresh wrap token.\n  \
                             2. Ship the updated bootstrap.json to this node.\n  \
                             3. Re-run `bootroot-remote bootstrap --artifact <path>`."
                        ),
                        &format!(
                            "서비스 '{service_name}'의 래핑 토큰이 만료되었습니다. 복구 절차:\n\n  \
                             1. control node에서 동일한 인자로 `bootroot service add`를 다시 실행하세요.\n     \
                                멱등 재실행으로 새 wrap token을 발급합니다.\n  \
                             2. 갱신된 bootstrap.json을 이 노드로 전송하세요.\n  \
                             3. `bootroot-remote bootstrap --artifact <경로>`를 다시 실행하세요."
                        ),
                    );
                    anyhow::bail!("{msg}");
                }
                UnwrapError::AlreadyUnwrapped { service_name } => {
                    let msg = localized(
                        lang,
                        &format!(
                            "SECURITY INCIDENT: Wrap token was already unwrapped.\n\
                             The secret_id for service '{service_name}' may have been \
                             intercepted by a third party.\n\n\
                             Recommended actions:\n  \
                             1. Investigate who or what consumed the token.\n  \
                             2. Rotate the compromised secret_id:\n     \
                                bootroot rotate approle-secret-id --service-name {service_name}\n  \
                             3. Re-run `bootroot service add` to generate a new wrap token.\n  \
                             4. Ship the updated bootstrap.json and retry bootstrap."
                        ),
                        &format!(
                            "보안 사고: 래핑 토큰이 이미 언래핑되었습니다.\n\
                             서비스 '{service_name}'의 secret_id가 제3자에 의해 \
                             가로채졌을 수 있습니다.\n\n\
                             권장 조치:\n  \
                             1. 토큰을 소비한 주체를 조사하세요.\n  \
                             2. 노출된 secret_id를 교체하세요:\n     \
                                bootroot rotate approle-secret-id --service-name {service_name}\n  \
                             3. `bootroot service add`를 다시 실행해 새 wrap token을 생성하세요.\n  \
                             4. 갱신된 bootstrap.json을 전송하고 부트스트랩을 재시도하세요."
                        ),
                    );
                    anyhow::bail!("{msg}");
                }
            }
        }
    }
}

/// Classifies an unwrap failure as either expired or already-unwrapped.
///
/// Returns `None` when the error is not an `OpenBao` API rejection
/// (e.g. TLS failure, HTTP 500, network timeout) so the caller can
/// propagate it without misreporting it as a token issue.
fn classify_unwrap_error(
    err: &anyhow::Error,
    wrap_expires_at: Option<&str>,
    service_name: &str,
) -> Option<UnwrapError> {
    use time::OffsetDateTime;
    use time::format_description::well_known::Rfc3339;

    if !is_openbao_token_rejection(err) {
        return None;
    }

    if let Some(expires_at) = wrap_expires_at
        && let Ok(expires) = OffsetDateTime::parse(expires_at, &Rfc3339)
        && OffsetDateTime::now_utc() > expires
    {
        return Some(UnwrapError::Expired {
            service_name: service_name.to_string(),
        });
    }
    // Token hasn't expired but unwrap was rejected — it was already
    // consumed by someone else, a potential security incident.
    Some(UnwrapError::AlreadyUnwrapped {
        service_name: service_name.to_string(),
    })
}

/// Returns `true` when the error chain contains an `OpenBao` API error
/// indicative of a bad/used/expired wrap token (HTTP 400-class).
///
/// Non-API errors (network failures, TLS errors, server 500s, parse
/// errors) return `false` so they are not misclassified.
fn is_openbao_token_rejection(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        let msg = cause.to_string();
        if msg.contains(OPENBAO_API_ERROR_PREFIX) && msg.contains("400") {
            return true;
        }
    }
    false
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
    // When a wrap_token is present, secret_id is obtained by unwrapping
    // and written to secret_id_path at runtime — the file does not need
    // to exist beforehand.
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

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;
    use crate::{HookFailurePolicy, OutputFormat};

    /// Builds a `ResolvedBootstrapArgs` with dummy values.  Only hook-related
    /// fields are meaningful — `validate_hook_flags` runs before any other
    /// check, so the remaining fields are never inspected in these tests.
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

    /// Builds an error that resembles a real `OpenBao` 400 rejection
    /// for an invalid/expired/used wrap token.
    fn openbao_400_error() -> anyhow::Error {
        anyhow::anyhow!(
            "OpenBao API error (400 Bad Request): \
             {{\"errors\":[\"wrapping token is not valid or does not exist\"]}}"
        )
    }

    #[test]
    fn classify_unwrap_error_returns_expired_when_past_expiry() {
        let err = openbao_400_error();
        let result = classify_unwrap_error(&err, Some("2020-01-01T00:00:00Z"), "my-svc");
        assert!(
            matches!(result, Some(UnwrapError::Expired { .. })),
            "expected Some(Expired)"
        );
    }

    #[test]
    fn classify_unwrap_error_returns_already_unwrapped_when_not_expired() {
        let err = openbao_400_error();
        let result = classify_unwrap_error(&err, Some("2099-01-01T00:00:00Z"), "my-svc");
        assert!(
            matches!(result, Some(UnwrapError::AlreadyUnwrapped { .. })),
            "expected Some(AlreadyUnwrapped)"
        );
    }

    #[test]
    fn classify_unwrap_error_returns_already_unwrapped_when_no_expiry() {
        let err = openbao_400_error();
        let result = classify_unwrap_error(&err, None, "my-svc");
        assert!(
            matches!(result, Some(UnwrapError::AlreadyUnwrapped { .. })),
            "expected Some(AlreadyUnwrapped) when no expires_at"
        );
    }

    #[test]
    fn classify_unwrap_expired_message_includes_rotate_command() {
        let err = openbao_400_error();
        let result = classify_unwrap_error(&err, Some("2020-01-01T00:00:00Z"), "edge-proxy");
        match result {
            Some(UnwrapError::Expired { service_name }) => {
                assert_eq!(service_name, "edge-proxy");
            }
            other => panic!("expected Some(Expired), got {other:?}"),
        }
    }

    #[test]
    fn classify_unwrap_already_unwrapped_includes_service_name() {
        let err = openbao_400_error();
        let result = classify_unwrap_error(&err, Some("2099-01-01T00:00:00Z"), "edge-proxy");
        match result {
            Some(UnwrapError::AlreadyUnwrapped { service_name }) => {
                assert_eq!(service_name, "edge-proxy");
            }
            other => panic!("expected Some(AlreadyUnwrapped), got {other:?}"),
        }
    }

    #[test]
    fn classify_unwrap_error_returns_none_for_non_token_errors() {
        let tls_err = anyhow::anyhow!("OpenBao request failed: sys/wrapping/unwrap")
            .context("TLS handshake failed");
        assert!(
            classify_unwrap_error(&tls_err, Some("2099-01-01T00:00:00Z"), "svc").is_none(),
            "TLS failure should not be classified as a token error"
        );

        let server_err =
            anyhow::anyhow!("OpenBao API error (500 Internal Server Error): internal error");
        assert!(
            classify_unwrap_error(&server_err, Some("2099-01-01T00:00:00Z"), "svc").is_none(),
            "500 error should not be classified as a token error"
        );

        let network_err = anyhow::anyhow!("connection refused");
        assert!(
            classify_unwrap_error(&network_err, None, "svc").is_none(),
            "network error should not be classified as a token error"
        );
    }

    #[test]
    fn is_openbao_token_rejection_matches_400() {
        let err = openbao_400_error();
        assert!(
            super::is_openbao_token_rejection(&err),
            "400 error should be recognized as token rejection"
        );
    }

    #[test]
    fn is_openbao_token_rejection_ignores_500() {
        let err = anyhow::anyhow!("OpenBao API error (500 Internal Server Error): something broke");
        assert!(
            !super::is_openbao_token_rejection(&err),
            "500 should not be classified as token rejection"
        );
    }

    #[test]
    fn validate_bootstrap_args_skips_secret_id_file_check_when_wrap_token_present() {
        use tempfile::tempdir;
        let dir = tempdir().expect("tempdir");
        let role_id_path = dir.path().join("role_id");
        std::fs::write(&role_id_path, "rid").expect("write role_id");

        let mut args = dummy_args();
        args.service_name = "svc".to_string();
        args.profile_hostname = "host".to_string();
        args.agent_domain = "example.com".to_string();
        args.profile_instance_id = Some("1".to_string());
        args.role_id_path = role_id_path;
        args.secret_id_path = dir.path().join("secret_id");
        args.eab_file_path = dir.path().join("eab.json");
        args.wrap_token = Some("hvs.tok".to_string());

        // secret_id file does NOT exist, but validation should pass
        // because wrap_token is present.
        assert!(
            validate_bootstrap_args(&args, Locale::En).is_ok(),
            "wrap_token present should skip secret_id file check"
        );
    }
}
