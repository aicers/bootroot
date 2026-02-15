#![cfg(unix)]

mod unix_integration {
    use std::net::TcpListener;
    use std::process::{Command, Output};
    use std::thread::sleep;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result};
    use bootroot::db::{DbProvisionReport, provision_db_sync};
    use postgres::NoTls;

    const DB_USER: &str = "itest";
    const DB_PASSWORD: &str = "itest-pass";
    const DB_NAME: &str = "postgres";
    const PROVISION_DB_USER: &str = "stepca_user";
    const PROVISION_DB_NAME: &str = "stepca_db";
    const INITIAL_ROLE_PASSWORD: &str = "first'pass";
    const UPDATED_ROLE_PASSWORD: &str = "second'pass";

    fn run_command(mut command: Command) -> Result<Output> {
        command.output().context("Failed to run command")
    }

    fn docker_command(args: &[&str]) -> Command {
        let mut command = Command::new("docker");
        command.args(args);
        command
    }

    fn unique_suffix() -> String {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        nanos.to_string()
    }

    fn reserve_local_port() -> Result<u16> {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).context("Failed to reserve local port")?;
        let port = listener
            .local_addr()
            .context("Failed to read reserved local address")?
            .port();
        Ok(port)
    }

    struct PostgresContainer {
        name: String,
        port: u16,
    }

    impl Drop for PostgresContainer {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .args(["rm", "-f", &self.name])
                .output();
        }
    }

    impl PostgresContainer {
        fn start() -> Result<Self> {
            let name = format!("bootroot-db-provision-itest-{}", unique_suffix());
            let port = reserve_local_port()?;
            let port_mapping = format!("127.0.0.1:{port}:5432");
            let output = run_command(docker_command(&[
                "run",
                "--rm",
                "-d",
                "--name",
                &name,
                "-e",
                &format!("POSTGRES_USER={DB_USER}"),
                "-e",
                &format!("POSTGRES_PASSWORD={DB_PASSWORD}"),
                "-e",
                &format!("POSTGRES_DB={DB_NAME}"),
                "-p",
                &port_mapping,
                "postgres:16",
            ]))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Failed to start postgres container: {stderr}");
            }
            let container = Self { name, port };
            container.wait_until_ready()?;
            Ok(container)
        }

        fn admin_dsn(&self) -> String {
            format!(
                "postgresql://{DB_USER}:{DB_PASSWORD}@127.0.0.1:{}/{}?sslmode=disable",
                self.port, DB_NAME
            )
        }

        fn wait_until_ready(&self) -> Result<()> {
            let start = SystemTime::now();
            let admin_dsn = self.admin_dsn();
            loop {
                let output = run_command(docker_command(&[
                    "exec",
                    &self.name,
                    "pg_isready",
                    "-U",
                    DB_USER,
                    "-d",
                    DB_NAME,
                ]))?;
                if output.status.success() && connect_with_dsn(&admin_dsn).is_ok() {
                    return Ok(());
                }
                if start.elapsed().unwrap_or_default() > Duration::from_secs(30) {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("Timed out waiting for postgres readiness: {stderr}");
                }
                sleep(Duration::from_millis(300));
            }
        }
    }

    fn assert_report(
        report: DbProvisionReport,
        role_created: bool,
        role_updated: bool,
        db_created: bool,
    ) {
        assert_eq!(report.role_created, role_created);
        assert_eq!(report.role_updated, role_updated);
        assert_eq!(report.db_created, db_created);
    }

    fn connect_with_dsn(dsn: &str) -> Result<postgres::Client> {
        dsn.parse::<postgres::Config>()
            .context("Failed to parse DSN")?
            .connect(NoTls)
            .context("Failed to connect with DSN")
    }

    fn role_and_database_exist(admin_dsn: &str) -> Result<(bool, bool)> {
        let mut client = connect_with_dsn(admin_dsn)?;
        let role_exists = client
            .query_opt(
                "SELECT 1 FROM pg_roles WHERE rolname = $1",
                &[&PROVISION_DB_USER],
            )?
            .is_some();
        let db_exists = client
            .query_opt(
                "SELECT 1 FROM pg_database WHERE datname = $1",
                &[&PROVISION_DB_NAME],
            )?
            .is_some();
        Ok((role_exists, db_exists))
    }

    fn role_auth_succeeds(port: u16, role_password: &str) -> bool {
        let role_dsn = format!(
            "postgresql://{PROVISION_DB_USER}:{role_password}@127.0.0.1:{port}/{PROVISION_DB_NAME}?sslmode=disable"
        );
        connect_with_dsn(&role_dsn).is_ok()
    }

    #[test]
    #[ignore = "Requires local Docker and postgres:16 image"]
    fn provision_db_sync_creates_and_updates_role_password() -> Result<()> {
        let container = PostgresContainer::start()?;
        let admin_dsn = container.admin_dsn();
        let timeout = Duration::from_secs(10);

        let create_report = provision_db_sync(
            &admin_dsn,
            PROVISION_DB_USER,
            INITIAL_ROLE_PASSWORD,
            PROVISION_DB_NAME,
            timeout,
        )?;
        assert_report(create_report, true, false, true);

        let (role_exists, db_exists) = role_and_database_exist(&admin_dsn)?;
        assert!(role_exists);
        assert!(db_exists);
        assert!(role_auth_succeeds(container.port, INITIAL_ROLE_PASSWORD));

        let update_report = provision_db_sync(
            &admin_dsn,
            PROVISION_DB_USER,
            UPDATED_ROLE_PASSWORD,
            PROVISION_DB_NAME,
            timeout,
        )?;
        assert_report(update_report, false, true, false);

        assert!(!role_auth_succeeds(container.port, INITIAL_ROLE_PASSWORD));
        assert!(role_auth_succeeds(container.port, UPDATED_ROLE_PASSWORD));
        Ok(())
    }
}
