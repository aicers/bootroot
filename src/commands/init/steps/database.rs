use std::env;
use std::fmt;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::db::{
    DB_COMPOSE_HOST, DB_HOST_RUNTIME_HOST, DbDsn, build_db_dsn, check_auth_sync, check_tcp,
    effective_admin_dsn_for_kv, for_compose_runtime, parse_db_dsn, provision_db_sync,
    resolve_postgres_host_port_with_env, validate_db_identifier,
};

use super::super::constants::{DEFAULT_DB_NAME, DEFAULT_DB_USER, SECRET_BYTES};
use super::DbDsnNormalization;
use super::prompts::{prompt_text, prompt_text_with_default};
use crate::cli::args::{InitArgs, InitFeature};
use crate::commands::guardrails::is_single_host_db_host;
use crate::i18n::Messages;

const POSTGRES_USER_ENV: &str = "POSTGRES_USER";
const POSTGRES_PASSWORD_ENV: &str = "POSTGRES_PASSWORD";
const POSTGRES_DB_ENV: &str = "POSTGRES_DB";
const POSTGRES_HOST_ENV: &str = "POSTGRES_HOST";
const POSTGRES_PORT_ENV: &str = "POSTGRES_PORT";
const POSTGRES_SSLMODE_ENV: &str = "POSTGRES_SSLMODE";

/// The `POSTGRES_*` variables the DSN builders below consult.
///
/// Read once, at the point `init` has finished loading the compose
/// `.env` into the process environment, and passed down from there —
/// so every builder underneath is steered by a value a caller supplies
/// rather than by process-global state.
#[derive(Clone, Default)]
pub(super) struct PostgresEnv {
    user: Option<String>,
    password: Option<String>,
    database: Option<String>,
    host: Option<String>,
    port: Option<String>,
    sslmode: Option<String>,
    host_port: Option<String>,
}

impl PostgresEnv {
    /// Reads the `POSTGRES_*` variables from the process environment.
    ///
    /// `init` calls this after `load_dotenv_into_env` has promoted the
    /// compose `.env`, which is where the `PostgreSQL` credentials
    /// `infra install` generated live.
    pub(super) fn from_process_env() -> Self {
        Self {
            user: env::var(POSTGRES_USER_ENV).ok(),
            password: env::var(POSTGRES_PASSWORD_ENV).ok(),
            database: env::var(POSTGRES_DB_ENV).ok(),
            host: env::var(POSTGRES_HOST_ENV).ok(),
            port: env::var(POSTGRES_PORT_ENV).ok(),
            sslmode: env::var(POSTGRES_SSLMODE_ENV).ok(),
            host_port: env::var(bootroot::db::POSTGRES_HOST_PORT_ENV).ok(),
        }
    }
}

/// Hand-written so a `#[derive(Debug)]` on anything holding one cannot
/// print the `PostgreSQL` password.
impl fmt::Debug for PostgresEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PostgresEnv")
            .field("user", &self.user)
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("database", &self.database)
            .field("host", &self.host)
            .field("port", &self.port)
            .field("sslmode", &self.sslmode)
            .field("host_port", &self.host_port)
            .finish()
    }
}

pub(super) async fn resolve_db_dsn_for_init(
    args: &InitArgs,
    compose_dir: &Path,
    postgres_env: &PostgresEnv,
    messages: &Messages,
) -> Result<(String, DbDsnNormalization, Option<String>)> {
    // Under reinit mode the preserved `ca.json` runtime DSN is threaded
    // into `args.db_dsn` by `init_args_for_reinit`. The PostgreSQL role
    // it points at already exists with that password (Postgres state is
    // preserved across reinit), so the snapshot-derived DSN is *not* a
    // user-supplied conflict with `--enable db-provision` — it is the
    // authoritative credential the second init pass must thread back
    // into the freshly reinitialised OpenBao KV. Honor it verbatim and
    // skip the provisioning path; re-running `ALTER ROLE ... WITH
    // PASSWORD` would rotate the already-good password to whatever
    // inputs `db-provision` synthesised and break the next rotate cycle.
    // Analogous to how `resolve_init_secrets` special-cases `http_hmac`
    // / `password.txt` under `reinit_mode`.
    let reinit_preserved_db_dsn =
        args.reinit_mode && args.has_feature(InitFeature::DbProvision) && args.db_dsn.is_some();
    if args.has_feature(InitFeature::DbProvision)
        && args.db_dsn.is_some()
        && !reinit_preserved_db_dsn
    {
        anyhow::bail!(messages.error_db_provision_conflict());
    }
    if args.has_feature(InitFeature::DbProvision) && !reinit_preserved_db_dsn {
        let inputs = resolve_db_provision_inputs(args, compose_dir, postgres_env, messages)?;
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
    let dsn = resolve_db_dsn(args, postgres_env, messages)?;
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
    postgres_env: &PostgresEnv,
    messages: &Messages,
) -> Result<DbProvisionInputs> {
    let admin_dsn = if let Some(value) = &args.db_admin.admin_dsn {
        value.clone()
    } else if let Some(value) = build_admin_dsn_from_env(compose_dir, postgres_env) {
        value
    } else {
        prompt_text(&format!("{}: ", messages.prompt_db_admin_dsn()), messages)?
    };
    let default_db_name = args
        .db_name
        .clone()
        .or_else(|| postgres_env.database.clone())
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

fn build_admin_dsn_from_env(compose_dir: &Path, postgres_env: &PostgresEnv) -> Option<String> {
    let user = postgres_env.user.as_deref()?;
    let password = postgres_env.password.as_deref()?;
    // `provision_db_sync` connects to PostgreSQL from the host (it shells
    // out via the `postgres` crate, not from inside the compose network),
    // so the auto-derived admin DSN must be host-reachable. Default the
    // host to `127.0.0.1` (not the compose-internal `postgres`) and the
    // port to the value Docker Compose itself resolves for
    // `${POSTGRES_HOST_PORT:-5433}` in `docker-compose.yml` — process env
    // → `compose_dir/.env` → 5433. `POSTGRES_HOST` / `POSTGRES_PORT`
    // remain explicit overrides for operator-supplied topologies.
    let host = postgres_env.host.as_deref().unwrap_or(DB_HOST_RUNTIME_HOST);
    let port = postgres_env
        .port
        .as_deref()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or_else(|| {
            resolve_postgres_host_port_with_env(postgres_env.host_port.as_deref(), compose_dir)
        });
    // Always connect to the "postgres" database for admin operations.
    // POSTGRES_DB names the application database that will be created,
    // not the admin database used for provisioning.
    Some(build_db_dsn(
        user,
        password,
        host,
        port,
        "postgres",
        postgres_env.sslmode.as_deref(),
    ))
}

fn resolve_db_dsn(
    args: &InitArgs,
    postgres_env: &PostgresEnv,
    messages: &Messages,
) -> Result<String> {
    if let Some(dsn) = &args.db_dsn {
        return Ok(dsn.clone());
    }
    if let Some(dsn) = build_dsn_from_env(postgres_env) {
        return Ok(dsn);
    }
    prompt_text(&format!("{}: ", messages.prompt_db_dsn()), messages)
}

fn build_dsn_from_env(postgres_env: &PostgresEnv) -> Option<String> {
    let user = postgres_env.user.as_deref()?;
    let password = postgres_env.password.as_deref()?;
    let db = postgres_env.database.as_deref()?;
    let host = postgres_env.host.as_deref().unwrap_or(DB_COMPOSE_HOST);
    let port = postgres_env.port.as_deref().unwrap_or("5432");
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
    use bootroot::db::DEFAULT_POSTGRES_HOST_PORT;

    use super::super::test_support::{default_init_args, test_messages};
    use super::*;

    /// The `POSTGRES_*` set an `infra install`-provisioned `.env`
    /// leaves behind, which is what the builders below see in practice.
    fn postgres_env(pairs: &[(&str, &str)]) -> PostgresEnv {
        let mut env = PostgresEnv::default();
        for (key, value) in pairs {
            let slot = match *key {
                POSTGRES_USER_ENV => &mut env.user,
                POSTGRES_PASSWORD_ENV => &mut env.password,
                POSTGRES_DB_ENV => &mut env.database,
                POSTGRES_HOST_ENV => &mut env.host,
                POSTGRES_PORT_ENV => &mut env.port,
                POSTGRES_SSLMODE_ENV => &mut env.sslmode,
                bootroot::db::POSTGRES_HOST_PORT_ENV => &mut env.host_port,
                other => panic!("{other} is not a POSTGRES_* variable these builders read"),
            };
            *slot = Some((*value).to_string());
        }
        env
    }

    /// A nonce-based fixture password.  `CodeQL` flags a literal as a
    /// hard-coded credential; a per-run value has no relation to a real
    /// one.
    fn nonce_password(prefix: &str) -> String {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        format!("{prefix}-{nonce}")
    }

    #[test]
    fn test_resolve_db_dsn_prefers_cli() {
        let env = postgres_env(&[
            (POSTGRES_USER_ENV, "envuser"),
            (POSTGRES_PASSWORD_ENV, "envpass"),
            (POSTGRES_DB_ENV, "envdb"),
        ]);
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://cliuser:clipass@localhost/db".to_string());
        let dsn = resolve_db_dsn(&args, &env, &test_messages()).unwrap();
        assert_eq!(dsn, "postgresql://cliuser:clipass@localhost/db");
    }

    #[test]
    fn test_resolve_db_dsn_for_init_rejects_remote_host() {
        let mut args = default_init_args();
        args.db_dsn =
            Some("postgresql://user:pass@db.internal:5432/stepca?sslmode=disable".to_string());

        let err = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(
                &args,
                Path::new("."),
                &PostgresEnv::default(),
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
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://user:pass@localhost:5432/stepca".to_string());

        let (dsn, normalization, _admin_dsn) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(
                &args,
                Path::new("."),
                &PostgresEnv::default(),
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
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://user:pass@postgres:5432/stepca".to_string());

        let (dsn, normalization, _admin_dsn) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(
                &args,
                Path::new("."),
                &PostgresEnv::default(),
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
        let mut args = default_init_args();
        args.db_dsn = Some("postgresql://user:pass@127.0.0.1:5433/stepca".to_string());

        let (dsn, normalization, _admin_dsn) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(
                &args,
                Path::new("."),
                &PostgresEnv::default(),
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
        // CodeQL flags "secret" as a hard-coded credential, but this is a
        // test-only fixture value with no relation to any real credential.
        // Dismiss as false positive.
        let env = postgres_env(&[
            (POSTGRES_USER_ENV, "step"),
            (POSTGRES_PASSWORD_ENV, "secret"),
            (POSTGRES_DB_ENV, "stepca"),
            (POSTGRES_HOST_ENV, "postgres"),
            (POSTGRES_PORT_ENV, "5432"),
        ]);
        let args = default_init_args();
        let dsn = resolve_db_dsn(&args, &env, &test_messages()).unwrap();
        assert_eq!(
            dsn,
            "postgresql://step:secret@postgres:5432/stepca?sslmode=disable"
        );
    }

    /// Without a user, a password and a database name there is nothing
    /// to build a DSN from, and the resolver must fall through to the
    /// prompt rather than synthesising one out of the defaults.
    #[test]
    fn build_dsn_from_env_needs_the_three_required_variables() {
        assert!(build_dsn_from_env(&PostgresEnv::default()).is_none());
        assert!(
            build_dsn_from_env(&postgres_env(&[
                (POSTGRES_USER_ENV, "step"),
                (POSTGRES_PASSWORD_ENV, "secret"),
            ]))
            .is_none(),
            "a missing POSTGRES_DB must not fall back to a default database"
        );
    }

    #[test]
    fn test_resolve_db_provision_inputs_with_args() {
        let admin_password = nonce_password("admin");
        let db_password = nonce_password("step");
        let mut args = default_init_args();
        args.enable.push(InitFeature::DbProvision);
        args.db_admin.admin_dsn = Some(format!(
            "postgresql://admin:{admin_password}@localhost:5432/postgres?sslmode=disable"
        ));
        args.db_user = Some("stepuser".to_string());
        args.db_password = Some(db_password.clone());
        args.db_name = Some("stepdb".to_string());

        let inputs = resolve_db_provision_inputs(
            &args,
            Path::new("."),
            &PostgresEnv::default(),
            &test_messages(),
        )
        .unwrap();
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
        let admin_password = nonce_password("admin");
        let db_password = nonce_password("step");
        let mut args = default_init_args();
        args.enable.push(InitFeature::DbProvision);
        args.db_admin.admin_dsn = Some(format!(
            "postgresql://admin:{admin_password}@localhost:5432/postgres?sslmode=disable"
        ));
        args.db_user = Some("bad-name".to_string());
        args.db_password = Some(db_password);
        args.db_name = Some("stepdb".to_string());

        let err = resolve_db_provision_inputs(
            &args,
            Path::new("."),
            &PostgresEnv::default(),
            &test_messages(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("Invalid DB identifier"));
    }

    #[test]
    fn test_effective_admin_dsn_for_kv_rebuilds_when_same_role() {
        // Regression for the §2 stale-admin-DSN follow-up: the bundled
        // E2E topology runs with `--db-user step` against the `step`
        // admin role. After provision, the role's password is
        // `db_password`, not the value embedded in the original admin
        // DSN — the persisted DSN must reflect that.
        let old = nonce_password("old");
        let new = nonce_password("new");
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
        let admin_pw = nonce_password("admin");
        let runtime_pw = nonce_password("runtime");
        let admin_dsn =
            format!("postgresql://admin:{admin_pw}@127.0.0.1:5433/postgres?sslmode=disable");
        let resolved = effective_admin_dsn_for_kv(&admin_dsn, "stepca", &runtime_pw).unwrap();
        assert_eq!(resolved, admin_dsn);
    }

    #[test]
    fn test_resolve_db_dsn_for_init_rejects_conflict() {
        let admin_password = nonce_password("admin");
        let db_password = nonce_password("step");
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
                &PostgresEnv::default(),
                &test_messages(),
            ))
            .unwrap_err();
        assert!(err.to_string().contains("db-provision"));
    }

    /// Regression for #601 §1: under reinit mode the preserved `ca.json`
    /// runtime DSN is threaded into `args.db_dsn` and must not trip the
    /// db-provision conflict check. The resolver returns the preserved
    /// DSN verbatim (compose-normalised) and skips re-provisioning so
    /// the already-good `PostgreSQL` role's password is not rotated.
    #[test]
    fn test_resolve_db_dsn_for_init_accepts_preserved_dsn_in_reinit_mode() {
        let preserved_password = nonce_password("preserved");
        let mut args = default_init_args();
        args.reinit_mode = true;
        args.db_dsn = Some(format!(
            "postgresql://step:{preserved_password}@127.0.0.1:5433/stepca?sslmode=disable"
        ));
        args.enable.push(InitFeature::DbProvision);
        // Provisioning inputs that would normally drive `ALTER ROLE` —
        // these must be ignored under reinit_mode because the preserved
        // DSN is authoritative.
        args.db_admin.admin_dsn = Some(
            "postgresql://admin:should-not-be-used@127.0.0.1:5433/postgres?sslmode=disable"
                .to_string(),
        );
        args.db_user = Some("step".to_string());
        args.db_password = Some("would-rotate-the-good-password".to_string());
        args.db_name = Some("stepca".to_string());

        let (dsn, normalization, admin_dsn_for_kv) = tokio::runtime::Runtime::new()
            .expect("runtime")
            .block_on(resolve_db_dsn_for_init(
                &args,
                Path::new("."),
                &PostgresEnv::default(),
                &test_messages(),
            ))
            .expect("preserved DSN must be accepted under reinit_mode");
        assert_eq!(
            dsn,
            format!("postgresql://step:{preserved_password}@postgres:5432/stepca?sslmode=disable"),
            "preserved DSN must reach KV verbatim (compose-normalised)"
        );
        assert_eq!(normalization.original_host, "127.0.0.1");
        assert_eq!(normalization.effective_host, "postgres");
        assert!(
            admin_dsn_for_kv.is_none(),
            "reinit must not synthesise an admin DSN; the preserved DSN is authoritative"
        );
    }

    #[test]
    fn build_admin_dsn_from_env_uses_host_reachable_defaults() {
        // Regression for the §2 Round 6 follow-up: after `infra install`
        // writes only POSTGRES_USER / POSTGRES_PASSWORD / POSTGRES_DB to
        // the compose `.env`, the auto-derived admin DSN must point at
        // `127.0.0.1:5433` (the new published default) rather than the
        // compose-internal `postgres:5432` — `provision_db_sync` runs
        // from the host.
        let password = nonce_password("admin");
        let dir = tempfile::tempdir().expect("tempdir");
        let env = postgres_env(&[
            (POSTGRES_USER_ENV, "step"),
            (POSTGRES_PASSWORD_ENV, &password),
        ]);
        let dsn = build_admin_dsn_from_env(dir.path(), &env).expect("dsn");
        let host = DB_HOST_RUNTIME_HOST;
        let port = DEFAULT_POSTGRES_HOST_PORT;
        assert_eq!(
            dsn,
            format!("postgresql://step:{password}@{host}:{port}/postgres?sslmode=disable")
        );
        assert_eq!((host, port), ("127.0.0.1", 5433));
    }

    #[test]
    fn build_admin_dsn_from_env_resolves_postgres_host_port_from_dotenv() {
        // When `--postgres-host-port 6543` was passed to `infra install`,
        // the compose `.env` carries `POSTGRES_HOST_PORT=6543`. The
        // auto-derived admin DSN must honor that (Docker Compose's
        // `${POSTGRES_HOST_PORT:-5433}` precedence: process env →
        // compose_dir/.env → 5433).
        let password = nonce_password("admin");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join(".env"),
            "POSTGRES_USER=step\nPOSTGRES_HOST_PORT=6543\n",
        )
        .expect("write .env");
        let env = postgres_env(&[
            (POSTGRES_USER_ENV, "step"),
            (POSTGRES_PASSWORD_ENV, &password),
        ]);
        let dsn = build_admin_dsn_from_env(dir.path(), &env).expect("dsn");
        assert_eq!(
            dsn,
            format!("postgresql://step:{password}@127.0.0.1:6543/postgres?sslmode=disable")
        );
    }

    /// The process environment still outranks the compose `.env`, which
    /// is the first step of the `${POSTGRES_HOST_PORT:-5433}`
    /// precedence.
    #[test]
    fn build_admin_dsn_from_env_prefers_the_host_port_variable_over_dotenv() {
        let password = nonce_password("admin");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "POSTGRES_HOST_PORT=6543\n").expect("write .env");
        let env = postgres_env(&[
            (POSTGRES_USER_ENV, "step"),
            (POSTGRES_PASSWORD_ENV, &password),
            (bootroot::db::POSTGRES_HOST_PORT_ENV, "6544"),
        ]);
        let dsn = build_admin_dsn_from_env(dir.path(), &env).expect("dsn");
        assert_eq!(
            dsn,
            format!("postgresql://step:{password}@127.0.0.1:6544/postgres?sslmode=disable")
        );
    }

    #[test]
    fn build_admin_dsn_from_env_postgres_port_overrides_host_port() {
        // Explicit POSTGRES_PORT (operator-supplied topology) wins over
        // the resolved POSTGRES_HOST_PORT default — the env var is the
        // historical operator override and stays authoritative.
        let password = nonce_password("admin");
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join(".env"), "POSTGRES_HOST_PORT=6543\n").expect("write .env");
        let env = postgres_env(&[
            (POSTGRES_USER_ENV, "step"),
            (POSTGRES_PASSWORD_ENV, &password),
            (POSTGRES_PORT_ENV, "7777"),
        ]);
        let dsn = build_admin_dsn_from_env(dir.path(), &env).expect("dsn");
        assert_eq!(
            dsn,
            format!("postgresql://step:{password}@127.0.0.1:7777/postgres?sslmode=disable")
        );
    }

    /// The password never reaches a `Debug` rendering, so a struct that
    /// derives `Debug` around one cannot leak the credential
    /// `infra install` generated.
    #[test]
    fn postgres_env_debug_redacts_the_password() {
        let password = nonce_password("admin");
        let env = postgres_env(&[
            (POSTGRES_USER_ENV, "step"),
            (POSTGRES_PASSWORD_ENV, &password),
        ]);
        let rendered = format!("{env:?}");
        assert!(!rendered.contains(&password), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }
}
