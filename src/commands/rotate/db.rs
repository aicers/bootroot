use std::fs;
use std::io;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::db;
use bootroot::openbao::OpenBaoClient;

use super::helpers::{
    confirm_action, ensure_non_empty, restart_compose_service, restart_container,
    wait_for_rendered_file,
};
use super::{OPENBAO_AGENT_STEPCA_CONTAINER, RENDERED_FILE_TIMEOUT, RotateContext};
use crate::cli::args::RotateDbArgs;
use crate::cli::prompt::Prompt;
use crate::commands::guardrails::{ensure_postgres_localhost_binding, ensure_single_host_db_host};
use crate::commands::init::{PATH_STEPCA_DB, SECRET_BYTES};
use crate::i18n::Messages;

pub(super) async fn rotate_db(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateDbArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(messages.prompt_rotate_db(), auto_confirm, messages)?;
    ensure_postgres_localhost_binding(&ctx.compose_file, messages)?;

    let ca_json_path = ctx.paths.ca_json();
    let admin_dsn = resolve_db_admin_dsn(args, &ca_json_path, messages)?;
    let admin = db::parse_db_dsn(&admin_dsn).with_context(|| messages.error_invalid_db_dsn())?;
    ensure_single_host_db_host(&admin.host, messages)?;
    let db_password = match &args.password {
        Some(value) => value.clone(),
        None => bootroot::utils::generate_secret(SECRET_BYTES)
            .with_context(|| messages.error_generate_secret_failed())?,
    };
    let current_dsn = read_ca_json_dsn(&ca_json_path, messages)?;
    let parsed = db::parse_db_dsn(&current_dsn).with_context(|| messages.error_invalid_db_dsn())?;
    ensure_single_host_db_host(&parsed.host, messages)?;
    let timeout = Duration::from_secs(args.timeout.timeout_secs);

    // Run the synchronous postgres client on a blocking thread to avoid
    // "Cannot start a runtime from within a runtime" panic. The postgres
    // crate internally calls block_on, which conflicts with the existing
    // tokio runtime when called from an async context.
    let user_clone = parsed.user.clone();
    let password_clone = db_password.clone();
    let database_clone = parsed.database.clone();
    tokio::task::spawn_blocking(move || {
        db::provision_db_sync(
            &admin_dsn,
            &user_clone,
            &password_clone,
            &database_clone,
            timeout,
        )
    })
    .await
    .context("DB provisioning task panicked")?
    .with_context(|| messages.error_db_provision_task_failed())?;
    let new_dsn = db::build_db_dsn(
        &parsed.user,
        &db_password,
        &parsed.host,
        parsed.port,
        &parsed.database,
        parsed.sslmode.as_deref(),
    );

    client
        .write_kv(
            &ctx.kv_mount,
            PATH_STEPCA_DB,
            serde_json::json!({ "value": new_dsn }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    restart_container(OPENBAO_AGENT_STEPCA_CONTAINER, messages)?;
    wait_for_rendered_file(&ca_json_path, &new_dsn, RENDERED_FILE_TIMEOUT, messages).await?;

    restart_compose_service(&ctx.compose_file, "step-ca", messages)?;

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_db_dsn(&ca_json_path.display().to_string())
    );
    println!("{}", messages.rotate_summary_restart_stepca());
    Ok(())
}

fn resolve_db_admin_dsn(
    args: &RotateDbArgs,
    ca_json_path: &Path,
    messages: &Messages,
) -> Result<String> {
    if let Some(value) = &args.admin_dsn.admin_dsn {
        return Ok(value.clone());
    }
    // Only fall through to the interactive prompt when ca.json is
    // definitively absent. Any other I/O failure (permission denied,
    // unreadable parent, malformed contents, missing fields) is surfaced
    // as a hard error so a broken environment does not silently prompt
    // for a DSN that would likely be wrong — and cannot trigger the
    // non-interactive EOF loop in `Prompt::prompt_with_validation`.
    if let Some(dsn) = read_ca_json_dsn_if_present(ca_json_path, messages)? {
        return Ok(dsn);
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout();
    let mut prompt = Prompt::new(&mut input, &mut output, messages);
    prompt.prompt_with_validation(messages.prompt_db_admin_dsn(), None, |value| {
        ensure_non_empty(value, messages)
    })
}

fn read_ca_json_dsn_if_present(path: &Path, messages: &Messages) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(contents) => parse_ca_json_dsn(&contents, messages).map(Some),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(anyhow::Error::new(err)
            .context(messages.error_read_file_failed(&path.display().to_string()))),
    }
}

fn read_ca_json_dsn(path: &Path, messages: &Messages) -> Result<String> {
    let contents = fs::read_to_string(path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    parse_ca_json_dsn(&contents, messages)
}

fn parse_ca_json_dsn(contents: &str, messages: &Messages) -> Result<String> {
    let value: serde_json::Value =
        serde_json::from_str(contents).context(messages.error_parse_ca_json_failed())?;
    let db = value
        .get("db")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    let data_source = db
        .get("dataSource")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    Ok(data_source.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::super::test_support::test_messages;
    use super::*;
    use crate::cli::args::{DbAdminDsnArgs, DbTimeoutArgs};

    #[test]
    fn resolve_db_admin_dsn_uses_cli_arg() {
        let messages = test_messages();
        let dir = tempdir().expect("tempdir");
        let ca_json = dir.path().join("ca.json");
        fs::write(
            &ca_json,
            r#"{"db":{"type":"postgresql","dataSource":"postgresql://step:other@postgres:5432/stepca"}}"#,
        )
        .expect("write ca.json");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs {
                admin_dsn: Some("postgresql://admin:pass@127.0.0.1:15432/postgres".to_string()),
            },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let resolved = resolve_db_admin_dsn(&args, &ca_json, &messages).expect("resolve dsn");
        assert_eq!(resolved, "postgresql://admin:pass@127.0.0.1:15432/postgres");
    }

    #[test]
    fn resolve_db_admin_dsn_reads_from_ca_json_when_flag_absent() {
        let messages = test_messages();
        let dir = tempdir().expect("tempdir");
        let ca_json = dir.path().join("ca.json");
        fs::write(
            &ca_json,
            r#"{"db":{"type":"postgresql","dataSource":"postgresql://step:current@postgres:5432/stepca?sslmode=disable"}}"#,
        )
        .expect("write ca.json");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs { admin_dsn: None },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let resolved = resolve_db_admin_dsn(&args, &ca_json, &messages).expect("resolve dsn");
        assert_eq!(
            resolved,
            "postgresql://step:current@postgres:5432/stepca?sslmode=disable"
        );
    }

    #[test]
    fn resolve_db_admin_dsn_errors_when_ca_json_malformed() {
        let messages = test_messages();
        let dir = tempdir().expect("tempdir");
        let ca_json = dir.path().join("ca.json");
        fs::write(&ca_json, "not valid json").expect("write ca.json");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs { admin_dsn: None },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let err = resolve_db_admin_dsn(&args, &ca_json, &messages)
            .expect_err("expected error on malformed ca.json");
        assert!(
            err.to_string().contains("ca.json")
                || err
                    .chain()
                    .any(|cause| cause.to_string().contains("ca.json"))
        );
    }

    #[test]
    fn resolve_db_admin_dsn_errors_when_ca_json_unreadable() {
        // Regression test for the `exists()` vs. `NotFound` distinction:
        // a present-but-unreadable ca.json must surface as a hard error
        // rather than falling through to the interactive prompt. We
        // simulate an I/O failure other than NotFound by pointing at a
        // directory entry, which makes `read_to_string` fail without
        // returning `ErrorKind::NotFound`.
        let messages = test_messages();
        let dir = tempdir().expect("tempdir");
        let ca_json = dir.path().join("ca.json");
        fs::create_dir(&ca_json).expect("create ca.json as directory");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs { admin_dsn: None },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let err = resolve_db_admin_dsn(&args, &ca_json, &messages)
            .expect_err("expected error when ca.json is unreadable");
        assert!(
            err.to_string().contains("ca.json")
                || err
                    .chain()
                    .any(|cause| cause.to_string().contains("ca.json")),
            "error should mention ca.json: {err}"
        );
    }

    #[test]
    fn resolve_db_admin_dsn_errors_when_ca_json_missing_data_source() {
        let messages = test_messages();
        let dir = tempdir().expect("tempdir");
        let ca_json = dir.path().join("ca.json");
        fs::write(&ca_json, r#"{"db":{"type":"postgresql"}}"#).expect("write ca.json");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs { admin_dsn: None },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let err = resolve_db_admin_dsn(&args, &ca_json, &messages)
            .expect_err("expected error when dataSource missing");
        assert!(err.to_string().contains("ca.json"));
    }

    #[test]
    fn read_ca_json_dsn_reads_data_source() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("ca.json");
        let messages = test_messages();
        fs::write(
            &path,
            r#"{"db":{"type":"postgresql","dataSource":"postgresql://step:old@postgres:5432/stepca?sslmode=disable"}}"#,
        )
        .expect("write ca.json");

        let dsn = read_ca_json_dsn(&path, &messages).expect("read dataSource");
        assert_eq!(
            dsn,
            "postgresql://step:old@postgres:5432/stepca?sslmode=disable"
        );
    }

    #[test]
    fn read_ca_json_dsn_rejects_missing_data_source() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("ca.json");
        let messages = test_messages();
        fs::write(&path, r#"{"db":{"type":"postgresql"}}"#).expect("write ca.json");

        let err = read_ca_json_dsn(&path, &messages).expect_err("expected missing dataSource");
        assert!(err.to_string().contains("ca.json"));
    }
}
