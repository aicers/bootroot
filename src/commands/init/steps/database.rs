use std::env;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::db::{
    DbDsn, build_db_dsn, check_auth_sync, check_tcp, parse_db_dsn, provision_db_sync,
    validate_db_identifier,
};

use super::super::constants::{DEFAULT_DB_NAME, DEFAULT_DB_USER, SECRET_BYTES};
use super::DbDsnNormalization;
use super::prompts::{prompt_text, prompt_text_with_default};
use crate::cli::args::{InitArgs, InitFeature};
use crate::commands::guardrails::is_single_host_db_host;
use crate::i18n::Messages;

const DB_COMPOSE_HOST: &str = "postgres";

pub(super) async fn resolve_db_dsn_for_init(
    args: &InitArgs,
    messages: &Messages,
) -> Result<(String, DbDsnNormalization)> {
    if args.has_feature(InitFeature::DbProvision) && args.db_dsn.is_some() {
        anyhow::bail!(messages.error_db_provision_conflict());
    }
    if args.has_feature(InitFeature::DbProvision) {
        let inputs = resolve_db_provision_inputs(args, messages)?;
        let admin = parse_db_dsn(&inputs.admin_dsn)
            .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
        let effective_host = normalize_db_host_for_compose_runtime(&admin.host, messages)?;
        let dsn = build_db_dsn(
            &inputs.db_user,
            &inputs.db_password,
            &effective_host,
            admin.port,
            &inputs.db_name,
            admin.sslmode.as_deref(),
        );
        let timeout = Duration::from_secs(args.db_timeout.timeout_secs);
        tokio::task::spawn_blocking(move || {
            provision_db_sync(
                &inputs.admin_dsn,
                &inputs.db_user,
                &inputs.db_password,
                &inputs.db_name,
                timeout,
            )
        })
        .await
        .with_context(|| messages.error_db_provision_task_failed())??;
        return Ok((
            dsn,
            DbDsnNormalization {
                original_host: admin.host,
                effective_host,
            },
        ));
    }
    let dsn = resolve_db_dsn(args, messages)?;
    let parsed =
        parse_db_dsn(&dsn).map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
    let effective_host = normalize_db_host_for_compose_runtime(&parsed.host, messages)?;
    let effective_dsn = if parsed.host == effective_host {
        dsn
    } else {
        build_db_dsn(
            &parsed.user,
            &parsed.password,
            &effective_host,
            parsed.port,
            &parsed.database,
            parsed.sslmode.as_deref(),
        )
    };
    Ok((
        effective_dsn,
        DbDsnNormalization {
            original_host: parsed.host,
            effective_host,
        },
    ))
}

#[derive(Debug)]
struct DbProvisionInputs {
    admin_dsn: String,
    db_user: String,
    db_password: String,
    db_name: String,
}

fn resolve_db_provision_inputs(args: &InitArgs, messages: &Messages) -> Result<DbProvisionInputs> {
    let admin_dsn = if let Some(value) = &args.db_admin.admin_dsn {
        value.clone()
    } else if let Some(value) = build_admin_dsn_from_env() {
        value
    } else {
        prompt_text(&format!("{}: ", messages.prompt_db_admin_dsn()), messages)?
    };
    let default_db_name = args
        .db_name
        .clone()
        .or_else(|| env::var("POSTGRES_DB").ok())
        .unwrap_or_else(|| DEFAULT_DB_NAME.to_string());
    let db_user = if let Some(value) = &args.db_user {
        value.clone()
    } else {
        let prompt = format!("{} [{}]: ", messages.prompt_db_user(), DEFAULT_DB_USER);
        prompt_text_with_default(&prompt, DEFAULT_DB_USER, messages)?
    };
    let db_name = if let Some(value) = &args.db_name {
        value.clone()
    } else {
        let prompt = format!("{} [{}]: ", messages.prompt_db_name(), default_db_name);
        prompt_text_with_default(&prompt, &default_db_name, messages)?
    };
    let db_password = if let Some(value) = &args.db_password {
        value.clone()
    } else if args.has_feature(InitFeature::AutoGenerate) {
        bootroot::utils::generate_secret(SECRET_BYTES)
            .with_context(|| messages.error_generate_secret_failed())?
    } else {
        prompt_text(&format!("{}: ", messages.prompt_db_password()), messages)?
    };

    validate_db_identifier(&db_user)
        .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_identifier(&db_user)))?;
    validate_db_identifier(&db_name)
        .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_identifier(&db_name)))?;

    Ok(DbProvisionInputs {
        admin_dsn,
        db_user,
        db_password,
        db_name,
    })
}

fn build_admin_dsn_from_env() -> Option<String> {
    let Ok(user) = env::var("POSTGRES_USER") else {
        return None;
    };
    let Ok(password) = env::var("POSTGRES_PASSWORD") else {
        return None;
    };
    let host = env::var("POSTGRES_HOST").unwrap_or_else(|_| "postgres".to_string());
    let port = env::var("POSTGRES_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(5432);
    // Always connect to the "postgres" database for admin operations.
    // POSTGRES_DB names the application database that will be created,
    // not the admin database used for provisioning.
    let sslmode = env::var("POSTGRES_SSLMODE").ok();
    Some(build_db_dsn(
        &user,
        &password,
        &host,
        port,
        "postgres",
        sslmode.as_deref(),
    ))
}

fn resolve_db_dsn(args: &InitArgs, messages: &Messages) -> Result<String> {
    if let Some(dsn) = &args.db_dsn {
        return Ok(dsn.clone());
    }
    if let Some(dsn) = build_dsn_from_env() {
        return Ok(dsn);
    }
    prompt_text(&format!("{}: ", messages.prompt_db_dsn()), messages)
}

fn build_dsn_from_env() -> Option<String> {
    let Ok(user) = env::var("POSTGRES_USER") else {
        return None;
    };
    let Ok(password) = env::var("POSTGRES_PASSWORD") else {
        return None;
    };
    let Ok(db) = env::var("POSTGRES_DB") else {
        return None;
    };
    let host = env::var("POSTGRES_HOST").unwrap_or_else(|_| "postgres".to_string());
    let port = env::var("POSTGRES_PORT").unwrap_or_else(|_| "5432".to_string());
    let dsn = format!("postgresql://{user}:{password}@{host}:{port}/{db}?sslmode=disable");
    Some(dsn)
}

pub(super) async fn check_db_connectivity(
    db: &DbDsn,
    dsn: &str,
    timeout_secs: u64,
    messages: &Messages,
) -> Result<()> {
    let timeout = Duration::from_secs(timeout_secs);
    check_tcp(&db.host, db.port, timeout)
        .await
        .with_context(|| messages.error_db_check_failed())?;
    let dsn_value = dsn.to_string();
    tokio::task::spawn_blocking(move || check_auth_sync(&dsn_value, timeout))
        .await
        .with_context(|| messages.error_db_auth_task_failed())?
        .with_context(|| messages.error_db_auth_failed())?;
    Ok(())
}

fn normalize_db_host_for_compose_runtime(host: &str, messages: &Messages) -> Result<String> {
    if host.eq_ignore_ascii_case(DB_COMPOSE_HOST) {
        return Ok(DB_COMPOSE_HOST.to_string());
    }
    if host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1" {
        return Ok(DB_COMPOSE_HOST.to_string());
    }
    if is_single_host_db_host(host) {
        return Ok(host.to_string());
    }
    anyhow::bail!(messages.error_db_host_compose_runtime(host, DB_COMPOSE_HOST));
}

#[cfg(test)]
mod tests {
    use std::env;

    use super::super::test_support::{default_init_args, env_lock, test_messages};
    use super::*;

    #[test]
    fn test_resolve_db_dsn_prefers_cli() {
        let _guard = env_lock();
        // SAFETY: tests run single-threaded for this scope; vars are restored below.
        unsafe {
            env::set_var("POSTGRES_USER", "envuser");
            env::set_var("POSTGRES_PASSWORD", "envpass");
            env::set_var("POSTGRES_DB", "envdb");
        }
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://cliuser:clipass@localhost/db".to_string());
        let dsn = resolve_db_dsn(&args, &test_messages()).unwrap();
        unsafe {
            env::remove_var("POSTGRES_USER");
            env::remove_var("POSTGRES_PASSWORD");
            env::remove_var("POSTGRES_DB");
        }
        assert_eq!(dsn, "postgresql://cliuser:clipass@localhost/db");
    }

    #[test]
    fn test_resolve_db_dsn_for_init_rejects_remote_host() {
        let _guard = env_lock();
        let mut args = default_init_args();
        args.db_dsn =
            Some("postgresql://user:pass@db.internal:5432/stepca?sslmode=disable".to_string());

        let err = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(&args, &test_messages()))
            .expect_err("remote db host should fail single-host guardrail");
        assert!(
            err.to_string()
                .contains("not reachable from step-ca container")
        );
    }

    #[test]
    fn test_resolve_db_dsn_for_init_normalizes_localhost_to_postgres() {
        let _guard = env_lock();
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://user:pass@localhost:5432/stepca".to_string());

        let (dsn, normalization) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(&args, &test_messages()))
            .expect("dsn should resolve");
        assert_eq!(
            dsn,
            "postgresql://user:pass@postgres:5432/stepca?sslmode=disable"
        );
        assert_eq!(normalization.original_host, "localhost");
        assert_eq!(normalization.effective_host, "postgres");
    }

    #[test]
    fn test_resolve_db_dsn_for_init_keeps_postgres_host() {
        let _guard = env_lock();
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://user:pass@postgres:5432/stepca".to_string());

        let (dsn, normalization) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(&args, &test_messages()))
            .expect("dsn should resolve");
        assert_eq!(dsn, "postgresql://user:pass@postgres:5432/stepca");
        assert_eq!(normalization.original_host, "postgres");
        assert_eq!(normalization.effective_host, "postgres");
    }

    #[test]
    fn test_normalize_db_host_for_compose_runtime_localhost() {
        let normalized =
            normalize_db_host_for_compose_runtime("127.0.0.1", &test_messages()).unwrap();
        assert_eq!(normalized, "postgres");
    }

    #[test]
    fn test_resolve_db_dsn_uses_env() {
        let _guard = env_lock();
        // SAFETY: tests run single-threaded for this scope; vars are restored below.
        // CodeQL flags "secret" as a hard-coded credential, but this is a test-only
        // fixture value with no relation to any real credential. Dismiss as false positive.
        unsafe {
            env::set_var("POSTGRES_USER", "step");
            env::set_var("POSTGRES_PASSWORD", "secret");
            env::set_var("POSTGRES_DB", "stepca");
            env::set_var("POSTGRES_HOST", "postgres");
            env::set_var("POSTGRES_PORT", "5432");
        }
        let args = default_init_args();
        let dsn = resolve_db_dsn(&args, &test_messages()).unwrap();
        unsafe {
            env::remove_var("POSTGRES_USER");
            env::remove_var("POSTGRES_PASSWORD");
            env::remove_var("POSTGRES_DB");
            env::remove_var("POSTGRES_HOST");
            env::remove_var("POSTGRES_PORT");
        }
        assert_eq!(
            dsn,
            "postgresql://step:secret@postgres:5432/stepca?sslmode=disable"
        );
    }

    #[test]
    fn test_resolve_db_provision_inputs_with_args() {
        let _guard = env_lock();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let admin_password = format!("admin-{nonce}");
        let db_password = format!("step-{nonce}");
        let mut args = default_init_args();
        args.enable.push(InitFeature::DbProvision);
        args.db_admin.admin_dsn = Some(format!(
            "postgresql://admin:{admin_password}@localhost:5432/postgres?sslmode=disable"
        ));
        args.db_user = Some("stepuser".to_string());
        args.db_password = Some(db_password.clone());
        args.db_name = Some("stepdb".to_string());

        let inputs = resolve_db_provision_inputs(&args, &test_messages()).unwrap();
        assert_eq!(
            inputs.admin_dsn,
            format!("postgresql://admin:{admin_password}@localhost:5432/postgres?sslmode=disable")
        );
        assert_eq!(inputs.db_user, "stepuser");
        assert_eq!(inputs.db_password, db_password);
        assert_eq!(inputs.db_name, "stepdb");
    }

    #[test]
    fn test_resolve_db_provision_inputs_rejects_invalid_identifier() {
        let _guard = env_lock();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let admin_password = format!("admin-{nonce}");
        let db_password = format!("step-{nonce}");
        let mut args = default_init_args();
        args.enable.push(InitFeature::DbProvision);
        args.db_admin.admin_dsn = Some(format!(
            "postgresql://admin:{admin_password}@localhost:5432/postgres?sslmode=disable"
        ));
        args.db_user = Some("bad-name".to_string());
        args.db_password = Some(db_password);
        args.db_name = Some("stepdb".to_string());

        let err = resolve_db_provision_inputs(&args, &test_messages()).unwrap_err();
        assert!(err.to_string().contains("Invalid DB identifier"));
    }

    #[test]
    fn test_resolve_db_dsn_for_init_rejects_conflict() {
        let _guard = env_lock();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let admin_password = format!("admin-{nonce}");
        let db_password = format!("step-{nonce}");
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://user:pass@localhost/db".to_string());
        args.enable.push(InitFeature::DbProvision);
        args.db_admin.admin_dsn = Some(format!(
            "postgresql://admin:{admin_password}@localhost:5432/postgres?sslmode=disable"
        ));
        args.db_user = Some("stepuser".to_string());
        args.db_password = Some(db_password);
        args.db_name = Some("stepdb".to_string());

        let err = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(&args, &test_messages()))
            .unwrap_err();
        assert!(err.to_string().contains("db-provision"));
    }
}
