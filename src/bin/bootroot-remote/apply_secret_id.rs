use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;

use super::io::{read_required_string, read_secret_file, write_secret_file};
use super::summary::{ApplyStatus, status_to_str};
use super::{ApplySecretIdArgs, CliLang, OutputFormat, SECRET_ID_KEY, SERVICE_KV_BASE, localized};

// This function intentionally keeps all apply-secret-id logic in one place
// so the single-value variant stays easy to audit and modify separately.
#[allow(clippy::too_many_lines)]
pub(super) async fn run_apply_secret_id(args: ApplySecretIdArgs, lang: CliLang) -> Result<i32> {
    if args.service_name.trim().is_empty() {
        anyhow::bail!(
            "{}",
            localized(
                lang,
                "--service-name must not be empty",
                "--service-name 값은 비어 있으면 안 됩니다",
            )
        );
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

    let kv_path = format!("{SERVICE_KV_BASE}/{}/secret_id", args.service_name);
    let data = client
        .read_kv(&args.kv_mount, &kv_path)
        .await
        .with_context(|| {
            localized(
                lang,
                "Failed to read service secret_id from OpenBao",
                "OpenBao에서 서비스 secret_id를 읽지 못했습니다",
            )
        })?;
    let new_secret_id = read_required_string(&data, &[SECRET_ID_KEY, "value"], lang)?;
    let status = write_secret_file(&args.secret_id_path, &new_secret_id)
        .await
        .with_context(|| {
            localized(
                lang,
                &format!(
                    "Failed to write secret_id to {}",
                    args.secret_id_path.display()
                ),
                &format!(
                    "secret_id 파일을 쓰지 못했습니다: {}",
                    args.secret_id_path.display()
                ),
            )
        })?;

    match args.output {
        OutputFormat::Text => {
            let label = match status {
                ApplyStatus::Applied => "applied",
                ApplyStatus::Unchanged => "unchanged",
                ApplyStatus::Failed => "failed",
            };
            println!(
                "{}",
                localized(
                    lang,
                    &format!("secret_id: {label}"),
                    &format!("secret_id: {label}"),
                )
            );
        }
        OutputFormat::Json => {
            let payload = serde_json::to_string_pretty(
                &serde_json::json!({ "secret_id": status_to_str(status) }),
            )?;
            println!("{payload}");
        }
    }
    Ok(0)
}
