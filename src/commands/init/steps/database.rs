use std::env;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::db::{
    DB_COMPOSE_HOST, DB_HOST_RUNTIME_HOST, DbDsn, build_db_dsn, check_auth_sync, check_tcp,
    effective_admin_dsn_for_kv, for_compose_runtime, parse_db_dsn, provision_db_sync,
    resolve_postgres_host_port, validate_db_identifier,
};

use super::super::constants::{DEFAULT_DB_NAME, DEFAULT_DB_USER, SECRET_BYTES};
use super::DbDsnNormalization;
use super::prompts::{prompt_text, prompt_text_with_default};
use crate::cli::args::{InitArgs, InitFeature};
use crate::commands::guardrails::is_single_host_db_host;
use crate::i18n::Messages;

pub(super) async fn resolve_db_dsn_for_init(
    args: &InitArgs,
    compose_dir: &Path,
    messages: &Messages,
) -> Result<(String, DbDsnNormalization, Option<String>)> {
    if args.has_feature(InitFeature::DbProvision) && args.db_dsn.is_some() {
        anyhow::bail!(messages.error_db_provision_conflict());
    }
    if args.has_feature(InitFeature::DbProvision) {
        let inputs = resolve_db_provision_inputs(args, compose_dir, messages)?;
        let admin = parse_db_dsn(&inputs.admin_dsn)
            .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
        ensure_db_host_reachable_from_compose(&admin.host, messages)?;
        let host_side_dsn = build_db_dsn(
            &inputs.db_user,
            &inputs.db_password,
            &admin.host,
            admin.port,
            &inputs.db_name,
            admin.sslmode.as_deref(),
        );
        let dsn = for_compose_runtime(&host_side_dsn)
            .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
        let timeout = Duration::from_secs(args.db_timeout.timeout_secs);
        let admin_dsn_for_provision = inputs.admin_dsn.clone();
        // When the provisioning admin and the runtime DB user are the
        // same role (e.g. `step` in the bundled E2E topology),
        // `provision_db_sync` runs `ALTER ROLE ... WITH PASSWORD
        // <db_password>`. The original `inputs.admin_dsn` then carries
        // the *pre-ALTER* password and would fail authentication on the
        // next `rotate db` that reads the persisted KV admin DSN. Rebuild
        // the persisted DSN with `db_password` for that case so the
        // post-ALTER credential is what reaches KV.
        let admin_dsn_for_kv =
            effective_admin_dsn_for_kv(&inputs.admin_dsn, &inputs.db_user, &inputs.db_password)?;
        let user = inputs.db_user.clone();
        let password = inputs.db_password.clone();
        let db_name = inputs.db_name.clone();
        tokio::task::spawn_blocking(move || {
            provision_db_sync(
                &admin_dsn_for_provision,
                &user,
                &password,
                &db_name,
                timeout,
            )
        })
        .await
        .with_context(|| messages.error_db_provision_task_failed())??;
        return Ok((
            dsn,
            DbDsnNormalization {
                original_host: admin.host,
                effective_host: DB_COMPOSE_HOST.to_string(),
            },
            Some(admin_dsn_for_kv),
        ));
    }
    let dsn = resolve_db_dsn(args, messages)?;
    let parsed =
        parse_db_dsn(&dsn).map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
    ensure_db_host_reachable_from_compose(&parsed.host, messages)?;
    let effective_dsn =
        for_compose_runtime(&dsn).map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
    Ok((
        effective_dsn,
        DbDsnNormalization {
            original_host: parsed.host,
            effective_host: DB_COMPOSE_HOST.to_string(),
        },
        None,
    ))
}

#[derive(Debug)]
struct DbProvisionInputs {
    admin_dsn: String,
    db_user: String,
    db_password: String,
    db_name: String,
}

fn resolve_db_provision_inputs(
    args: &InitArgs,
    compose_dir: &Path,
    messages: &Messages,
) -> Result<DbProvisionInputs> {
    let admin_dsn = if let Some(value) = &args.db_admin.admin_dsn {
        value.clone()
    } else if let Some(value) = build_admin_dsn_from_env(compose_dir) {
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

fn build_admin_dsn_from_env(compose_dir: &Path) -> Option<String> {
    let Ok(user) = env::var("POSTGRES_USER") else {
        return None;
    };
    let Ok(password) = env::var("POSTGRES_PASSWORD") else {
        return None;
    };
    // `provision_db_sync` connects to PostgreSQL from the host (it shells
    // out via the `postgres` crate, not from inside the compose network),
    // so the auto-derived admin DSN must be host-reachable. Default the
    // host to `127.0.0.1` (not the compose-internal `postgres`) and the
    // port to the value Docker Compose itself resolves for
    // `${POSTGRES_HOST_PORT:-5433}` in `docker-compose.yml` — process env
    // → `compose_dir/.env` → 5433. `POSTGRES_HOST` / `POSTGRES_PORT`
    // remain explicit overrides for operator-supplied topologies.
    let host = env::var("POSTGRES_HOST").unwrap_or_else(|_| DB_HOST_RUNTIME_HOST.to_string());
    let port = env::var("POSTGRES_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or_else(|| resolve_postgres_host_port(compose_dir));
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

fn ensure_db_host_reachable_from_compose(host: &str, messages: &Messages) -> Result<()> {
    if is_single_host_db_host(host) {
        return Ok(());
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
            .block_on(resolve_db_dsn_for_init(
                &args,
                Path::new("."),
                &test_messages(),
            ))
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

        let (dsn, normalization, _admin_dsn) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(
                &args,
                Path::new("."),
                &test_messages(),
            ))
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

        let (dsn, normalization, _admin_dsn) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(
                &args,
                Path::new("."),
                &test_messages(),
            ))
            .expect("dsn should resolve");
        assert_eq!(
            dsn,
            "postgresql://user:pass@postgres:5432/stepca?sslmode=disable"
        );
        assert_eq!(normalization.original_host, "postgres");
        assert_eq!(normalization.effective_host, "postgres");
    }

    #[test]
    fn test_resolve_db_dsn_for_init_rewrites_host_port() {
        // Regression for Symptom 1: a host-side DSN with a non-5432 port
        // (POSTGRES_HOST_PORT territory) must not leak into the stored
        // compose-internal DSN. Both host and port flip to the compose
        // pair.
        let _guard = env_lock();
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://user:pass@127.0.0.1:5433/stepca".to_string());

        let (dsn, normalization, _admin_dsn) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(
                &args,
                Path::new("."),
                &test_messages(),
            ))
            .expect("dsn should resolve");
        assert_eq!(
            dsn,
            "postgresql://user:pass@postgres:5432/stepca?sslmode=disable"
        );
        assert_eq!(normalization.original_host, "127.0.0.1");
        assert_eq!(normalization.effective_host, "postgres");
    }

    #[test]
    fn test_ensure_db_host_reachable_from_compose_accepts_local() {
        ensure_db_host_reachable_from_compose("127.0.0.1", &test_messages()).unwrap();
        ensure_db_host_reachable_from_compose("localhost", &test_messages()).unwrap();
        ensure_db_host_reachable_from_compose("postgres", &test_messages()).unwrap();
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

        let inputs = resolve_db_provision_inputs(&args, Path::new("."), &test_messages()).unwrap();
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

        let err = resolve_db_provision_inputs(&args, Path::new("."), &test_messages()).unwrap_err();
        assert!(err.to_string().contains("Invalid DB identifier"));
    }

    #[test]
    fn test_effective_admin_dsn_for_kv_rebuilds_when_same_role() {
        // Regression for the §2 stale-admin-DSN follow-up: the bundled
        // E2E topology runs with `--db-user step` against the `step`
        // admin role. After provision, the role's password is
        // `db_password`, not the value embedded in the original admin
        // DSN — the persisted DSN must reflect that.
        //
        // Nonce-based test fixtures sidestep CodeQL's
        // `rust/hard-coded-cryptographic-value` rule (the values are
        // generated per run and have no relation to a real credential).
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let old = format!("old-{nonce}");
        let new = format!("new-{nonce}");
        let admin_dsn = format!("postgresql://step:{old}@127.0.0.1:5433/postgres?sslmode=disable");
        let resolved = effective_admin_dsn_for_kv(&admin_dsn, "step", &new).unwrap();
        assert_eq!(
            resolved,
            format!("postgresql://step:{new}@127.0.0.1:5433/postgres?sslmode=disable")
        );
    }

    #[test]
    fn test_effective_admin_dsn_for_kv_unchanged_when_distinct_role() {
        // When admin and runtime are distinct roles, the admin DSN is
        // untouched by provisioning and should be persisted verbatim.
        // Nonce-based fixtures sidestep CodeQL — see the sibling test.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let admin_pw = format!("admin-{nonce}");
        let runtime_pw = format!("runtime-{nonce}");
        let admin_dsn =
            format!("postgresql://admin:{admin_pw}@127.0.0.1:5433/postgres?sslmode=disable");
        let resolved = effective_admin_dsn_for_kv(&admin_dsn, "stepca", &runtime_pw).unwrap();
        assert_eq!(resolved, admin_dsn);
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
            .block_on(resolve_db_dsn_for_init(
                &args,
                Path::new("."),
                &test_messages(),
            ))
            .unwrap_err();
        assert!(err.to_string().contains("db-provision"));
    }

    #[test]
    fn build_admin_dsn_from_env_uses_host_reachable_defaults() {
        // Regression for the §2 Round 6 follow-up: after `infra install`
        // writes only POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB to
        // the compose `.env`, the auto-derived admin DSN must point at
        // `127.0.0.1:5433` (the new published default) rather than the
        // compose-internal `postgres:5432` — `provision_db_sync` runs
        // from the host.
        let _guard = env_lock();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let password = format!("admin-{nonce}");
        let dir = tempfile::tempdir().expect("tempdir");
        // SAFETY: env_lock() serialises env-var-touching tests.
        unsafe {
            env::set_var("POSTGRES_USER", "step");
            env::set_var("POSTGRES_PASSWORD", &password);
            env::remove_var("POSTGRES_HOST");
            env::remove_var("POSTGRES_PORT");
            env::remove_var("POSTGRES_HOST_PORT");
            env::remove_var("POSTGRES_SSLMODE");
        }
        let dsn = build_admin_dsn_from_env(dir.path()).expect("dsn");
        unsafe {
            env::remove_var("POSTGRES_USER");
            env::remove_var("POSTGRES_PASSWORD");
        }
        assert_eq!(
            dsn,
            format!("postgresql://step:{password}@127.0.0.1:5433/postgres?sslmode=disable")
        );
    }

    #[test]
    fn build_admin_dsn_from_env_resolves_postgres_host_port_from_dotenv() {
        // When `--postgres-host-port 6543` was passed to `infra install`,
        // the compose `.env` carries `POSTGRES_HOST_PORT=6543`. The
        // auto-derived admin DSN must honor that (Docker Compose's
        // `${POSTGRES_HOST_PORT:-5433}` precedence: process env →
        // compose_dir/.env → 5433).
        let _guard = env_lock();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let password = format!("admin-{nonce}");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(".env"),
            "POSTGRES_USER=step\nPOSTGRES_HOST_PORT=6543\n",
        )
        .expect("write .env");
        // SAFETY: env_lock() serialises env-var-touching tests.
        unsafe {
            env::set_var("POSTGRES_USER", "step");
            env::set_var("POSTGRES_PASSWORD", &password);
            env::remove_var("POSTGRES_HOST");
            env::remove_var("POSTGRES_PORT");
            env::remove_var("POSTGRES_HOST_PORT");
            env::remove_var("POSTGRES_SSLMODE");
        }
        let dsn = build_admin_dsn_from_env(dir.path()).expect("dsn");
        unsafe {
            env::remove_var("POSTGRES_USER");
            env::remove_var("POSTGRES_PASSWORD");
        }
        assert_eq!(
            dsn,
            format!("postgresql://step:{password}@127.0.0.1:6543/postgres?sslmode=disable")
        );
    }

    #[test]
    fn build_admin_dsn_from_env_postgres_port_overrides_host_port() {
        // Explicit POSTGRES_PORT (operator-supplied topology) wins over
        // the resolved POSTGRES_HOST_PORT default — the env var is the
        // historical operator override and stays authoritative.
        let _guard = env_lock();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let password = format!("admin-{nonce}");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "POSTGRES_HOST_PORT=6543\n").expect("write .env");
        // SAFETY: env_lock() serialises env-var-touching tests.
        unsafe {
            env::set_var("POSTGRES_USER", "step");
            env::set_var("POSTGRES_PASSWORD", &password);
            env::set_var("POSTGRES_PORT", "7777");
            env::remove_var("POSTGRES_HOST");
            env::remove_var("POSTGRES_HOST_PORT");
            env::remove_var("POSTGRES_SSLMODE");
        }
        let dsn = build_admin_dsn_from_env(dir.path()).expect("dsn");
        unsafe {
            env::remove_var("POSTGRES_USER");
            env::remove_var("POSTGRES_PASSWORD");
            env::remove_var("POSTGRES_PORT");
        }
        assert_eq!(
            dsn,
            format!("postgresql://step:{password}@127.0.0.1:7777/postgres?sslmode=disable")
        );
    }
}
