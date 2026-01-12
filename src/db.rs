use std::net::ToSocketAddrs;
use std::time::Duration;

use anyhow::{Context, Result};

#[derive(Debug, Clone)]
pub struct DbDsn {
    pub user: String,
    pub password: String,
    pub host: String,
    pub port: u16,
    pub database: String,
    pub sslmode: Option<String>,
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
    use super::*;

    #[test]
    fn parse_db_dsn_success() {
        let dsn = "postgresql://user:pass@localhost:5432/db?sslmode=disable";
        let parsed = parse_db_dsn(dsn).unwrap();
        assert_eq!(parsed.user, "user");
        assert_eq!(parsed.password, "pass");
        assert_eq!(parsed.host, "localhost");
        assert_eq!(parsed.port, 5432);
        assert_eq!(parsed.database, "db");
        assert_eq!(parsed.sslmode.as_deref(), Some("disable"));
    }

    #[test]
    fn parse_db_dsn_rejects_missing_prefix() {
        let err = parse_db_dsn("postgres://user:pass@localhost/db").unwrap_err();
        assert!(err.to_string().contains("postgresql://"));
    }

    #[test]
    fn parse_db_dsn_rejects_missing_password() {
        let err = parse_db_dsn("postgresql://user@localhost/db").unwrap_err();
        assert!(err.to_string().contains("user:password"));
    }
}
