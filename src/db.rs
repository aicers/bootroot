use std::net::ToSocketAddrs;
use std::time::Duration;

use anyhow::{Context, Result};
use postgres::NoTls;

#[derive(Debug, Clone)]
pub struct DbDsn {
    pub user: String,
    pub password: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub sslmode: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DbProvisionReport {
    pub role_created: bool,
    pub role_updated: bool,
    pub db_created: bool,
}

/// Parses a `PostgreSQL` DSN into structured fields.
///
/// # Errors
///
/// Returns an error when the DSN is malformed or missing required fields.
pub fn parse_db_dsn(input: &str) -> Result<DbDsn> {
    const PREFIX: &str = "postgresql://";
    let trimmed = input.trim();
    if !trimmed.starts_with(PREFIX) {
        anyhow::bail!("DSN must start with {PREFIX}");
    }
    let rest = &trimmed[PREFIX.len()..];
    let (auth_host, path) = rest.split_once('/').context("DSN must include /<db>")?;
    let (auth, host_part) = auth_host
        .split_once('@')
        .context("DSN must include user:pass@host")?;
    let (user, password) = auth
        .split_once(':')
        .context("DSN must include user:password")?;
    let (database, query) = path.split_once('?').unwrap_or((path, ""));
    let (host, port) = match host_part.split_once(':') {
        Some((host, port)) => (host, port),
        None => (host_part, "5432"),
    };
    let port = port.parse::<u16>().context("Invalid port")?;
    if user.trim().is_empty()
        || password.trim().is_empty()
        || host.trim().is_empty()
        || database.trim().is_empty()
    {
        anyhow::bail!("DSN contains empty fields");
    }
    let sslmode = query
        .split('&')
        .find_map(|pair| pair.split_once('='))
        .filter(|(key, _)| *key == "sslmode")
        .map(|(_, value)| value.to_string());
    Ok(DbDsn {
        user: user.to_string(),
        password: password.to_string(),
        host: host.to_string(),
        port,
        database: database.to_string(),
        sslmode,
    })
}

/// Builds a `PostgreSQL` DSN from structured components.
#[must_use]
pub fn build_db_dsn(
    user: &str,
    password: &str,
    host: &str,
    port: u16,
    database: &str,
    sslmode: Option<&str>,
) -> String {
    let sslmode = sslmode.unwrap_or("disable");
    format!("postgresql://{user}:{password}@{host}:{port}/{database}?sslmode={sslmode}")
}

/// Validates that a DB identifier is safe to embed in SQL.
///
/// # Errors
///
/// Returns an error when the identifier is empty or contains invalid
/// characters.
pub fn validate_db_identifier(value: &str) -> Result<()> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("DB identifier must not be empty");
    }
    let mut chars = trimmed.chars();
    let Some(first) = chars.next() else {
        anyhow::bail!("DB identifier must not be empty");
    };
    if !first.is_ascii_alphabetic() {
        anyhow::bail!("DB identifier must start with a letter");
    }
    if !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        anyhow::bail!("DB identifier must be alphanumeric or underscore");
    }
    Ok(())
}

/// Checks DB auth by connecting and running a lightweight query.
///
/// # Errors
///
/// Returns an error when the DSN is invalid, authentication fails, or the
/// query cannot be executed.
pub fn check_auth_sync(dsn: &str, timeout: Duration) -> Result<()> {
    let dsn = dsn.to_string();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = (|| {
            let mut config = dsn
                .parse::<postgres::Config>()
                .context("Failed to parse PostgreSQL DSN")?;
            config.connect_timeout(timeout);
            let mut client = config
                .connect(NoTls)
                .context("Failed to authenticate to PostgreSQL")?;
            client
                .simple_query("SELECT 1")
                .context("Failed to execute auth check query")?;
            Ok(())
        })();
        let _ = sender.send(result);
    });
    match receiver.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            anyhow::bail!("Timed out while authenticating to PostgreSQL")
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            anyhow::bail!("DB auth check thread disconnected")
        }
    }
}

/// Provisions a DB role and database using the provided admin DSN.
///
/// # Errors
///
/// Returns an error if the admin DSN is invalid or the provisioning statements
/// fail to execute.
pub fn provision_db_sync(
    admin_dsn: &str,
    db_user: &str,
    db_password: &str,
    db_name: &str,
    timeout: Duration,
) -> Result<DbProvisionReport> {
    let mut config = admin_dsn
        .parse::<postgres::Config>()
        .context("Failed to parse PostgreSQL admin DSN")?;
    config.connect_timeout(timeout);
    let mut client = config
        .connect(NoTls)
        .context("Failed to connect to PostgreSQL as admin")?;

    let mut report = DbProvisionReport::default();
    let role_exists = client
        .query_opt("SELECT 1 FROM pg_roles WHERE rolname = $1", &[&db_user])?
        .is_some();

    let role_ident = quote_ident(db_user);
    let password_literal = quote_literal(db_password);
    if role_exists {
        client.execute(&format!("ALTER ROLE {role_ident} WITH LOGIN"), &[])?;
        client.execute(
            &alter_role_password_sql(&role_ident, &password_literal),
            &[],
        )?;
        report.role_updated = true;
    } else {
        client.execute(
            &create_role_with_password_sql(&role_ident, &password_literal),
            &[],
        )?;
        report.role_created = true;
    }

    let db_exists = client
        .query_opt("SELECT 1 FROM pg_database WHERE datname = $1", &[&db_name])?
        .is_some();
    let db_ident = quote_ident(db_name);
    if !db_exists {
        client.execute(
            &format!("CREATE DATABASE {db_ident} OWNER {role_ident}"),
            &[],
        )?;
        report.db_created = true;
    }
    client.execute(
        &format!("GRANT ALL PRIVILEGES ON DATABASE {db_ident} TO {role_ident}"),
        &[],
    )?;
    Ok(report)
}

/// Quotes an SQL identifier by wrapping it in double quotes and escaping
/// any embedded double quotes by doubling them.
fn quote_ident(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

/// Quotes an SQL string literal by wrapping it in single quotes and escaping
/// any embedded single quotes by doubling them. This is necessary for DDL
/// statements like `ALTER ROLE ... WITH PASSWORD` and `CREATE ROLE ... WITH
/// PASSWORD` that do not support parameterized queries.
fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Builds SQL that sets a role password using a pre-quoted literal.
fn alter_role_password_sql(role_ident: &str, password_literal: &str) -> String {
    format!("ALTER ROLE {role_ident} WITH PASSWORD {password_literal}")
}

/// Builds SQL that creates a role with login and password using a pre-quoted
/// literal.
fn create_role_with_password_sql(role_ident: &str, password_literal: &str) -> String {
    format!("CREATE ROLE {role_ident} WITH LOGIN PASSWORD {password_literal}")
}

/// Checks TCP connectivity to the database host.
///
/// # Errors
///
/// Returns an error when the connection fails or times out.
pub async fn check_tcp(host: &str, port: u16, timeout: Duration) -> Result<()> {
    let target = format!("{host}:{port}");
    let connect = tokio::net::TcpStream::connect(&target);
    tokio::time::timeout(timeout, connect)
        .await
        .context("Timed out connecting to database host")?
        .with_context(|| format!("Failed to connect to {target}"))?;
    Ok(())
}

/// Checks TCP connectivity to the database host synchronously.
///
/// # Errors
///
/// Returns an error when the connection fails or times out.
pub fn check_tcp_sync(host: &str, port: u16, timeout: Duration) -> Result<()> {
    let target = format!("{host}:{port}");
    let mut addrs = target
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve {target}"))?;
    let addr = addrs.next().context("No socket addresses resolved")?;
    std::net::TcpStream::connect_timeout(&addr, timeout)
        .with_context(|| format!("Failed to connect to {addr}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn test_password() -> String {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before UNIX_EPOCH")
            .as_nanos();
        format!("pass-{nonce}")
    }

    #[test]
    fn parse_db_dsn_success() {
        let password = test_password();
        let dsn = format!("postgresql://user:{password}@localhost:5432/db?sslmode=disable");
        let parsed = parse_db_dsn(&dsn).unwrap();
        assert_eq!(parsed.user, "user");
        assert_eq!(parsed.password, password);
        assert_eq!(parsed.host, "localhost");
        assert_eq!(parsed.port, 5432);
        assert_eq!(parsed.database, "db");
        assert_eq!(parsed.sslmode.as_deref(), Some("disable"));
    }

    #[test]
    fn parse_db_dsn_rejects_missing_prefix() {
        let password = test_password();
        let err = parse_db_dsn(&format!("postgres://user:{password}@localhost/db")).unwrap_err();
        assert!(err.to_string().contains("postgresql://"));
    }

    #[test]
    fn parse_db_dsn_rejects_missing_password() {
        let err = parse_db_dsn("postgresql://user@localhost/db").unwrap_err();
        assert!(err.to_string().contains("user:password"));
    }

    #[test]
    fn build_db_dsn_includes_sslmode() {
        let password = test_password();
        let dsn = build_db_dsn("user", &password, "localhost", 5432, "db", Some("require"));
        assert!(dsn.contains("sslmode=require"));
    }

    #[test]
    fn validate_db_identifier_rejects_invalid() {
        let err = validate_db_identifier("123bad").unwrap_err();
        assert!(err.to_string().contains("start with a letter"));
        let err = validate_db_identifier("bad-name").unwrap_err();
        assert!(err.to_string().contains("underscore"));
    }

    #[test]
    fn validate_db_identifier_accepts_valid() {
        validate_db_identifier("stepca_user").unwrap();
    }

    #[test]
    fn check_auth_sync_fails_on_closed_port() {
        let password = test_password();
        let dsn = format!("postgresql://user:{password}@127.0.0.1:9/db?sslmode=disable");
        let err = check_auth_sync(&dsn, Duration::from_millis(100)).unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("authenticate") || message.contains("Timed out"),
            "{message}"
        );
    }

    #[test]
    fn quote_ident_handles_simple_name() {
        assert_eq!(quote_ident("my_table"), "\"my_table\"");
    }

    #[test]
    fn quote_ident_escapes_double_quotes() {
        assert_eq!(quote_ident("my\"table"), "\"my\"\"table\"");
        assert_eq!(quote_ident("a\"b\"c"), "\"a\"\"b\"\"c\"");
    }

    #[test]
    fn quote_literal_handles_simple_string() {
        assert_eq!(quote_literal("password123"), "'password123'");
    }

    #[test]
    fn quote_literal_escapes_single_quotes() {
        assert_eq!(quote_literal("pass'word"), "'pass''word'");
        assert_eq!(quote_literal("a'b'c"), "'a''b''c'");
    }

    #[test]
    fn quote_literal_handles_complex_passwords() {
        // Password with multiple special characters
        assert_eq!(quote_literal("p@ss'w0rd!"), "'p@ss''w0rd!'");
        // Password with consecutive single quotes
        assert_eq!(quote_literal("test''value"), "'test''''value'");
    }

    #[test]
    fn quote_literal_handles_empty_string() {
        assert_eq!(quote_literal(""), "''");
    }

    #[test]
    fn quote_literal_preserves_newlines_and_backslashes() {
        assert_eq!(quote_literal("line1\nline2\\path"), "'line1\nline2\\path'");
    }

    #[test]
    fn alter_role_password_sql_uses_escaped_literal_without_placeholder() {
        let sql =
            alter_role_password_sql(&quote_ident("step"), &quote_literal("x';DROP ROLE step;--"));
        assert_eq!(
            sql,
            "ALTER ROLE \"step\" WITH PASSWORD 'x'';DROP ROLE step;--'"
        );
        assert!(!sql.contains("$1"));
    }

    #[test]
    fn create_role_with_password_sql_uses_escaped_literal_without_placeholder() {
        let sql = create_role_with_password_sql(&quote_ident("step"), &quote_literal("pass'word"));
        assert_eq!(sql, "CREATE ROLE \"step\" WITH LOGIN PASSWORD 'pass''word'");
        assert!(!sql.contains("$1"));
    }
}
