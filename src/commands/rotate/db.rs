use std::fs;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::db::{self, effective_admin_dsn_for_kv, for_compose_runtime, for_host_runtime};
use bootroot::openbao::OpenBaoClient;

use super::helpers::{
    confirm_action, restart_compose_service, restart_container, wait_for_rendered_file,
};
use super::{OPENBAO_AGENT_STEPCA_CONTAINER, RENDERED_FILE_TIMEOUT, RotateContext};
use crate::cli::args::RotateDbArgs;
use crate::commands::guardrails::{ensure_postgres_localhost_binding, ensure_single_host_db_host};
use crate::commands::init::{PATH_STEPCA_DB, PATH_STEPCA_DB_ADMIN, SECRET_BYTES};
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
    let compose_dir = ctx
        .compose_file
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    // Skip the KV lookup when `--db-admin-dsn` is supplied: the flag
    // wins regardless, and avoiding the call sidesteps a 403 from
    // AppRole tokens whose policy intentionally excludes
    // `bootroot/stepca/db_admin` (per #588 §2 — the admin DSN must
    // not be readable by the runtime AppRole policy).
    let kv_admin_dsn = if args.admin_dsn.admin_dsn.is_some() {
        None
    } else {
        read_admin_dsn_from_kv(client, &ctx.kv_mount).await?
    };
    let admin_dsn = resolve_db_admin_dsn(args, &compose_dir, kv_admin_dsn.as_deref(), messages)?;
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
    // Rebuild with the new password then force the stored DSN back to its
    // compose-internal form. Routing through `for_compose_runtime` also
    // self-heals a DSN that was previously written with a bad host/port
    // pair (e.g. `postgres:5433` from Symptom 1 of issue #542).
    let rebuilt_dsn = db::build_db_dsn(
        &parsed.user,
        &db_password,
        &parsed.host,
        parsed.port,
        &parsed.database,
        parsed.sslmode.as_deref(),
    );
    let new_dsn =
        for_compose_runtime(&rebuilt_dsn).with_context(|| messages.error_invalid_db_dsn())?;

    client
        .write_kv(
            &ctx.kv_mount,
            PATH_STEPCA_DB,
            serde_json::json!({ "value": new_dsn }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    // Same-role topology (admin DSN's user equals the runtime user that
    // was just ALTERed): the persisted KV admin DSN now carries the
    // pre-ALTER password and would fail authentication on the next
    // `rotate db`. Rewrite it with the post-ALTER credential, preserving
    // the original (compose-internal) host/port form so the value matches
    // what `init --enable db-provision` would have written. Only update
    // when the KV path was actually used for this rotation — `--db-admin-dsn`
    // overrides do not touch KV (operators with externally-managed admin
    // credentials should not have their KV value rewritten).
    if let Some(new_admin_dsn) =
        kv_admin_dsn_to_persist(args, kv_admin_dsn.as_deref(), &parsed.user, &db_password)?
    {
        client
            .write_kv(
                &ctx.kv_mount,
                PATH_STEPCA_DB_ADMIN,
                serde_json::json!({ "value": new_admin_dsn }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }
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
    compose_dir: &Path,
    kv_admin_dsn: Option<&str>,
    messages: &Messages,
) -> Result<String> {
    // `--db-admin-dsn` is an override for operators with non-standard
    // topologies. Its value is used verbatim and bypasses the host-side
    // translation below.
    if let Some(value) = &args.admin_dsn.admin_dsn {
        return Ok(value.clone());
    }
    // Persisted admin DSN from `init --enable db-provision`. Translate
    // through `for_host_runtime` so a value that was stored in
    // compose-internal form (host `postgres`) becomes reachable from
    // the host where `rotate db` runs.
    if let Some(value) = kv_admin_dsn {
        return for_host_runtime(value, compose_dir)
            .with_context(|| messages.error_invalid_db_dsn());
    }
    // Per issue #588 §2: do NOT fall back to `ca.json.db.dataSource`.
    // That field stores the runtime (`stepca`) DSN, not an admin DSN, and
    // attempting to ALTER ROLE as the role itself is the original bug.
    // Operators using AppRole tokens (whose policy excludes `db_admin`)
    // or pre-existing installs without the KV key must supply
    // `--db-admin-dsn` explicitly.
    anyhow::bail!(
        "no admin DSN available: pass --db-admin-dsn, or re-run \
         `bootroot init --enable db-provision` so the admin DSN is \
         persisted to KV at bootroot/stepca/db_admin"
    )
}

/// Returns the admin DSN to persist back to `bootroot/stepca/db_admin`
/// after a successful rotation, or `None` when no rewrite is needed.
///
/// Triggers only for the KV-backed path (no `--db-admin-dsn` override)
/// where the persisted admin DSN's user matches the runtime user being
/// rotated. In that same-role topology, `provision_db_sync` has just
/// rewritten the role's password and the persisted DSN is now stale.
fn kv_admin_dsn_to_persist(
    args: &RotateDbArgs,
    kv_admin_dsn: Option<&str>,
    runtime_user: &str,
    new_password: &str,
) -> Result<Option<String>> {
    if args.admin_dsn.admin_dsn.is_some() {
        return Ok(None);
    }
    let Some(kv_admin) = kv_admin_dsn else {
        return Ok(None);
    };
    let parsed_kv = db::parse_db_dsn(kv_admin).context("Failed to parse persisted admin DSN")?;
    if parsed_kv.user != runtime_user {
        return Ok(None);
    }
    Ok(Some(effective_admin_dsn_for_kv(
        kv_admin,
        runtime_user,
        new_password,
    )?))
}

async fn read_admin_dsn_from_kv(client: &OpenBaoClient, kv_mount: &str) -> Result<Option<String>> {
    // Treat permission denied as "not present to this token". The
    // runtime AppRole policy intentionally excludes `db_admin`, so a
    // 403 here means the caller is using AppRole auth and must supply
    // `--db-admin-dsn` explicitly.
    let exists = match client.kv_exists(kv_mount, PATH_STEPCA_DB_ADMIN).await {
        Ok(v) => v,
        Err(err) if err.to_string().contains("403") => return Ok(None),
        Err(err) => return Err(err).context("failed to check OpenBao KV for persisted admin DSN"),
    };
    if !exists {
        return Ok(None);
    }
    let value = match client.read_kv(kv_mount, PATH_STEPCA_DB_ADMIN).await {
        Ok(v) => v,
        Err(err) if err.to_string().contains("403") => return Ok(None),
        Err(err) => return Err(err).context("failed to read OpenBao KV for persisted admin DSN"),
    };
    Ok(value
        .get("value")
        .and_then(|v| v.as_str())
        .map(str::to_string))
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

    use super::super::test_support::{ScopedEnvVar, env_lock, test_messages};
    use super::*;
    use crate::cli::args::{DbAdminDsnArgs, DbTimeoutArgs};

    #[test]
    fn resolve_db_admin_dsn_uses_cli_arg() {
        let messages = test_messages();
        let dir = tempdir().expect("tempdir");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs {
                admin_dsn: Some("postgresql://admin:pass@127.0.0.1:15432/postgres".to_string()),
            },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let resolved =
            resolve_db_admin_dsn(&args, dir.path(), None, &messages).expect("resolve dsn");
        assert_eq!(resolved, "postgresql://admin:pass@127.0.0.1:15432/postgres");
    }

    #[test]
    fn resolve_db_admin_dsn_errors_when_neither_flag_nor_kv_present() {
        // Closes issue #588 Round 1: ca.json must NOT be a fallback
        // source. ca.json.db.dataSource holds the *runtime* (`stepca`)
        // DSN; using it as an admin DSN reproduces the original
        // self-ALTER failure. With no flag and no KV value, fail fast
        // with a message naming the available recovery paths.
        let _lock = env_lock();
        let _port_guard = ScopedEnvVar::set("POSTGRES_HOST_PORT", "");
        let messages = test_messages();
        let dir = tempdir().expect("tempdir");
        // Even an existing ca.json must not be silently consumed as an
        // admin DSN — the file is left in place to confirm no fallthrough.
        let ca_json = dir.path().join("ca.json");
        fs::write(
            &ca_json,
            r#"{"db":{"type":"postgresql","dataSource":"postgresql://stepca:runtime@postgres:5432/stepca?sslmode=disable"}}"#,
        )
        .expect("write ca.json");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs { admin_dsn: None },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let err = resolve_db_admin_dsn(&args, dir.path(), None, &messages)
            .expect_err("must error when no admin DSN source is available");
        let chained = err
            .chain()
            .map(std::string::ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            chained.contains("--db-admin-dsn") && chained.contains("db_admin"),
            "error must name --db-admin-dsn and the KV path: {chained}"
        );
    }

    #[test]
    fn resolve_db_admin_dsn_prefers_kv_admin() {
        // Closes issue #588 §2: when init persisted the admin DSN to
        // KV, `rotate db` must use it instead of erroring out.
        let _lock = env_lock();
        let _port_guard = ScopedEnvVar::set("POSTGRES_HOST_PORT", "");
        let messages = test_messages();
        let dir = tempdir().expect("tempdir");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs { admin_dsn: None },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let kv_admin = "postgresql://step:admin@postgres:5432/postgres?sslmode=disable";
        let resolved = resolve_db_admin_dsn(&args, dir.path(), Some(kv_admin), &messages)
            .expect("resolve dsn");
        assert_eq!(
            resolved, "postgresql://step:admin@127.0.0.1:5433/postgres?sslmode=disable",
            "must use the persisted admin DSN, translated to host-side"
        );
    }

    #[test]
    fn resolve_db_admin_dsn_cli_flag_overrides_kv() {
        let messages = test_messages();
        let dir = tempdir().expect("tempdir");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs {
                admin_dsn: Some("postgresql://flag:pass@127.0.0.1:9999/postgres".to_string()),
            },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let resolved = resolve_db_admin_dsn(
            &args,
            dir.path(),
            Some("postgresql://kv:kv@postgres:5432/postgres"),
            &messages,
        )
        .expect("resolve dsn");
        assert_eq!(resolved, "postgresql://flag:pass@127.0.0.1:9999/postgres");
    }

    #[test]
    fn kv_admin_dsn_to_persist_rebuilds_for_same_role() {
        // Round 3 regression: in the bundled E2E topology the admin DSN
        // and the runtime DSN are both user `step`. After
        // `provision_db_sync` runs `ALTER ROLE step WITH PASSWORD <new>`,
        // the persisted KV admin DSN at `bootroot/stepca/db_admin` is
        // stale until rotate writes it back with the new password.
        // Without this rewrite the *next* `rotate db` (no
        // `--db-admin-dsn`) reads a stale DSN and fails authentication.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let new = format!("new-{nonce}");
        let old = format!("old-{nonce}");
        let kv_admin = format!("postgresql://step:{old}@postgres:5432/postgres?sslmode=disable");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs { admin_dsn: None },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let resolved = kv_admin_dsn_to_persist(&args, Some(&kv_admin), "step", &new)
            .expect("kv_admin_dsn_to_persist must succeed for same-role topology")
            .expect("must return Some for same-role topology");
        // Host/port preserved from the original KV value (compose-internal
        // form), only the password swapped — matches what
        // `init --enable db-provision` would have written.
        assert_eq!(
            resolved,
            format!("postgresql://step:{new}@postgres:5432/postgres?sslmode=disable")
        );
    }

    #[test]
    fn kv_admin_dsn_to_persist_returns_none_for_distinct_role() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let new = format!("new-{nonce}");
        // Distinct roles: admin DSN is `step`, runtime user is `stepca`.
        // `provision_db_sync` ALTERs `stepca` only, so the admin DSN is
        // not stale and KV must not be rewritten.
        let kv_admin =
            format!("postgresql://step:adminpass-{nonce}@postgres:5432/postgres?sslmode=disable");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs { admin_dsn: None },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let resolved = kv_admin_dsn_to_persist(&args, Some(&kv_admin), "stepca", &new)
            .expect("kv_admin_dsn_to_persist must succeed for distinct-role topology");
        assert!(
            resolved.is_none(),
            "distinct-role topology must not rewrite KV: got {resolved:?}"
        );
    }

    #[test]
    fn kv_admin_dsn_to_persist_returns_none_when_flag_supplied() {
        // `--db-admin-dsn` operators manage admin credentials externally;
        // bootroot must not rewrite their persisted KV admin DSN even when
        // the flag user happens to match the runtime user.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        let new = format!("new-{nonce}");
        let kv_admin =
            format!("postgresql://step:kvpass-{nonce}@postgres:5432/postgres?sslmode=disable");
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs {
                admin_dsn: Some(format!(
                    "postgresql://step:flagpass-{nonce}@127.0.0.1:5432/postgres"
                )),
            },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let resolved = kv_admin_dsn_to_persist(&args, Some(&kv_admin), "step", &new)
            .expect("kv_admin_dsn_to_persist must succeed");
        assert!(resolved.is_none());
    }

    #[tokio::test]
    async fn read_admin_dsn_from_kv_returns_none_on_403() {
        // Regression for the AppRole `runtime_rotate` policy which
        // intentionally excludes `bootroot/stepca/db_admin` (#588 §2).
        // A 403 from `kv_exists` must be treated as "not present to
        // this token" so the caller can fall through to
        // `--db-admin-dsn` instead of failing with an opaque error.
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/v1/secret/metadata/bootroot/stepca/db_admin"))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(r#"{"errors":["permission denied"]}"#),
            )
            .mount(&server)
            .await;

        let mut client = bootroot::openbao::OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("not-a-root-token".to_string());
        let result = read_admin_dsn_from_kv(&client, "secret").await;
        assert!(
            matches!(result, Ok(None)),
            "403 must be treated as None, got: {result:?}"
        );
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
