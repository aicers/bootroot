use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::agent_config::apply_agent_config_updates;
use super::io::{pull_secrets, read_secret_file, write_eab_file, write_secret_file};
use super::summary::{ApplyItemSummary, ApplySummary, merge_apply_status, print_summary};
use super::validation::{
    validate_agent_domain, validate_profile_hostname, validate_profile_instance_id,
    validate_service_name,
};
use super::{BootstrapArgs, CA_BUNDLE_PEM_KEY, Locale, localized};

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

    if let Some(bundle_path) = args.ca_bundle_path.as_deref() {
        match pulled.ca_bundle_pem.as_deref() {
            Some(pem) => match write_secret_file(bundle_path, pem).await {
                Ok(bundle_status) => {
                    trust_sync_status = merge_apply_status(trust_sync_status, bundle_status, None);
                }
                Err(err) => {
                    trust_sync_status = ApplyItemSummary::failed(localized(
                        lang,
                        &format!("ca bundle apply failed ({}): {err}", bundle_path.display()),
                        &format!("ca bundle 반영 실패 ({}): {err}", bundle_path.display()),
                    ));
                }
            },
            None => {
                trust_sync_status = ApplyItemSummary::failed(localized(
                    lang,
                    &format!(
                        "trust data missing {CA_BUNDLE_PEM_KEY} while --ca-bundle-path was provided"
                    ),
                    &format!(
                        "--ca-bundle-path가 지정되었지만 trust 데이터에 {CA_BUNDLE_PEM_KEY}가 없습니다"
                    ),
                ));
            }
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

fn validate_bootstrap_args(args: &BootstrapArgs, lang: Locale) -> Result<()> {
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
