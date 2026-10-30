#![cfg(unix)]

#[path = "../src/runtime_image_declaration.rs"]
mod runtime_image_declaration;

mod unix_integration {
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread::sleep;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use anyhow::{Context, Result};
    use bootroot::db::{
        DbProvisionReport, check_auth_sync, for_host_runtime_with_port, provision_db_sync,
    };
    use bootroot::utils::generate_secret;
    use postgres::NoTls;
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

    /// The `PostgreSQL` image step-ca's database runs, per the runtime
    /// declaration.
    const POSTGRES_IMAGE: &str = "postgres:18.4";
    const DB_USER: &str = "itest";
    const DB_NAME: &str = "postgres";
    const PROVISION_DB_USER: &str = "stepca_user";
    const PROVISION_DB_NAME: &str = "stepca_db";
    const INITIAL_ROLE_PASSWORD: &str = "first'pass";
    const UPDATED_ROLE_PASSWORD: &str = "second'pass";
    /// The name bootroot verifies the `PostgreSQL` server's certificate for.
    const SERVER_NAME: &str = "postgres";
    /// A name the server's certificate must carry for bootroot to refuse it.
    const OTHER_SERVER_NAME: &str = "openbao.internal";
    /// Where the TLS container's command finds the test's files, and where
    /// it installs them for the server.
    const TLS_SOURCE_DIR: &str = "/bootroot-tls-src";
    const TLS_DIR: &str = "/etc/bootroot-tls";
    /// Local connections stay open for the image's own initialisation;
    /// over TCP the server accepts TLS only.
    const TLS_PG_HBA: &str = "local all all trust\n\
        hostssl all all all scram-sha-256\n\
        host all all all reject\n";
    /// The `sslrootcert` a DSN carries: bootroot keeps it in the DSN but
    /// verifies against the root file it is handed.
    const IRRELEVANT_SSLROOTCERT: &str = "/irrelevant";

    fn run_command(mut command: Command) -> Result<Output> {
        command.output().context("Failed to run command")
    }

    fn docker_command(args: &[&str]) -> Command {
        let mut command = Command::new("docker");
        command.args(args);
        command
    }

    fn unique_suffix() -> String {
        // Tests start containers concurrently, and the clock alone can
        // hand two of them the same value.
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        format!("{}-{nanos}-{count}", std::process::id())
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
        admin_password: String,
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
            let admin_password =
                generate_secret(16).context("Failed to generate test admin password")?;
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
                &format!("POSTGRES_PASSWORD={admin_password}"),
                "-e",
                &format!("POSTGRES_DB={DB_NAME}"),
                "-p",
                &port_mapping,
                POSTGRES_IMAGE,
            ]))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Failed to start postgres container: {stderr}");
            }
            let container = Self {
                name,
                port,
                admin_password,
            };
            container.wait_until_ready()?;
            Ok(container)
        }

        fn admin_dsn(&self) -> String {
            format!(
                "postgresql://{DB_USER}:{}@127.0.0.1:{}/{}?sslmode=disable",
                self.admin_password, self.port, DB_NAME
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

    /// A CA and a server leaf it issued.
    struct TestPki {
        root: String,
        leaf: String,
        leaf_key: String,
    }

    fn generate_ca(common_name: &str) -> Result<(String, Issuer<'static, KeyPair>)> {
        let ca_key = KeyPair::generate().context("Failed to generate CA key")?;
        let mut ca_params =
            CertificateParams::new(Vec::<String>::new()).context("Failed to build CA params")?;
        ca_params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_cert = ca_params
            .clone()
            .self_signed(&ca_key)
            .context("Failed to self-sign CA")?;
        Ok((ca_cert.pem(), Issuer::new(ca_params, ca_key)))
    }

    fn generate_pki(leaf_san: &str) -> Result<TestPki> {
        let (root_pem, issuer) = generate_ca("bootroot test PostgreSQL CA")?;
        let leaf_key = KeyPair::generate().context("Failed to generate leaf key")?;
        let mut leaf_params = CertificateParams::new(vec![leaf_san.to_string()])
            .context("Failed to build leaf params")?;
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, leaf_san);
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .context("Failed to sign leaf")?;
        Ok(TestPki {
            root: root_pem,
            leaf: leaf.pem(),
            leaf_key: leaf_key.serialize_pem(),
        })
    }

    /// A `PostgreSQL` container that accepts only `hostssl` connections,
    /// only over TLS 1.3, and only with the X25519MLKEM768 group.
    struct TlsPostgresContainer {
        name: String,
        port: u16,
        admin_password: String,
        dir: tempfile::TempDir,
    }

    impl Drop for TlsPostgresContainer {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .args(["rm", "-f", &self.name])
                .output();
        }
    }

    impl TlsPostgresContainer {
        fn start(pki: &TestPki) -> Result<Self> {
            let name = format!("bootroot-db-tls-itest-{}", unique_suffix());
            let port = reserve_local_port()?;
            let admin_password =
                generate_secret(16).context("Failed to generate test admin password")?;
            let dir = tempfile::tempdir().context("Failed to create TLS fixture dir")?;
            std::fs::write(dir.path().join("server.crt"), &pki.leaf)
                .context("Failed to write server certificate")?;
            std::fs::write(dir.path().join("server.key"), &pki.leaf_key)
                .context("Failed to write server key")?;
            std::fs::write(dir.path().join("pg_hba.conf"), TLS_PG_HBA)
                .context("Failed to write pg_hba.conf")?;
            // The test runs unprivileged and the server refuses a key that
            // is not its own with mode 0600, so the container's command
            // installs the files as `postgres` before starting the server.
            let script = format!(
                "set -e\n\
                 mkdir -p {TLS_DIR}\n\
                 install -o postgres -g postgres -m 0600 {TLS_SOURCE_DIR}/server.key {TLS_DIR}/server.key\n\
                 install -o postgres -g postgres -m 0644 {TLS_SOURCE_DIR}/server.crt {TLS_DIR}/server.crt\n\
                 install -o postgres -g postgres -m 0644 {TLS_SOURCE_DIR}/pg_hba.conf {TLS_DIR}/pg_hba.conf\n\
                 exec docker-entrypoint.sh postgres \
                 -c ssl=on \
                 -c ssl_cert_file={TLS_DIR}/server.crt \
                 -c ssl_key_file={TLS_DIR}/server.key \
                 -c ssl_min_protocol_version=TLSv1.3 \
                 -c ssl_groups=X25519MLKEM768 \
                 -c hba_file={TLS_DIR}/pg_hba.conf\n"
            );
            let port_mapping = format!("127.0.0.1:{port}:5432");
            let mount = format!("{}:{TLS_SOURCE_DIR}:ro", dir.path().display());
            let output = run_command(docker_command(&[
                "run",
                "--rm",
                "-d",
                "--name",
                &name,
                "-e",
                &format!("POSTGRES_USER={DB_USER}"),
                "-e",
                &format!("POSTGRES_PASSWORD={admin_password}"),
                "-e",
                &format!("POSTGRES_DB={DB_NAME}"),
                "-p",
                &port_mapping,
                "-v",
                &mount,
                "--entrypoint",
                "bash",
                POSTGRES_IMAGE,
                "-c",
                &script,
            ]))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("Failed to start TLS postgres container: {stderr}");
            }
            let container = Self {
                name,
                port,
                admin_password,
                dir,
            };
            container.wait_until_ready()?;
            Ok(container)
        }

        /// The admin DSN at `host`, asking for full verification.
        fn admin_dsn(&self, host: &str) -> String {
            format!(
                "postgresql://{DB_USER}:{}@{host}:{}/{DB_NAME}?sslmode=verify-full&sslrootcert={IRRELEVANT_SSLROOTCERT}",
                self.admin_password, self.port
            )
        }

        /// Writes `pem` as a root file beside the server's fixtures.
        fn write_root(&self, file_name: &str, pem: &str) -> Result<PathBuf> {
            let path = self.dir.path().join(file_name);
            std::fs::write(&path, pem).context("Failed to write root file")?;
            Ok(path)
        }

        /// Waits for the final server, not the image's socket-only
        /// initialisation server, to accept TCP connections.
        fn wait_until_ready(&self) -> Result<()> {
            let start = SystemTime::now();
            loop {
                let output = run_command(docker_command(&[
                    "exec",
                    &self.name,
                    "pg_isready",
                    "-h",
                    "127.0.0.1",
                    "-U",
                    DB_USER,
                    "-d",
                    DB_NAME,
                ]))?;
                if output.status.success() {
                    return Ok(());
                }
                if start.elapsed().unwrap_or_default() > Duration::from_secs(30) {
                    let logs = run_command(docker_command(&["logs", &self.name]))?;
                    anyhow::bail!(
                        "Timed out waiting for TLS postgres readiness: {}{}",
                        String::from_utf8_lossy(&logs.stdout),
                        String::from_utf8_lossy(&logs.stderr)
                    );
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

    fn tls_role_dsn(host: &str, port: u16, role_password: &str) -> String {
        format!(
            "postgresql://{PROVISION_DB_USER}:{role_password}@{host}:{port}/{PROVISION_DB_NAME}?sslmode=verify-full&sslrootcert={IRRELEVANT_SSLROOTCERT}"
        )
    }

    fn assert_tls_failure(err: &anyhow::Error, expected: &str, password: &str) {
        let message = format!("{err:#}");
        assert!(message.contains(expected), "{message}");
        assert!(!message.contains(password), "{message}");
    }

    #[test]
    fn the_test_image_is_the_declared_postgres_image() {
        super::runtime_image_declaration::assert_declared_image(
            "postgres",
            POSTGRES_IMAGE,
            "tests/db_provision_integration.rs POSTGRES_IMAGE",
        );
    }

    #[test]
    #[ignore = "Requires local Docker and the declared PostgreSQL image"]
    fn provision_db_sync_creates_and_updates_role_password() -> Result<()> {
        let container = PostgresContainer::start()?;
        let admin_dsn = container.admin_dsn();
        let timeout = Duration::from_secs(10);

        // `sslmode=disable` never reads the root file.
        let root_ca = Path::new("/nonexistent/root_ca.crt");

        let create_report = provision_db_sync(
            &admin_dsn,
            root_ca,
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
            root_ca,
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

    #[test]
    #[ignore = "Requires local Docker and the declared PostgreSQL image"]
    fn tls_connections_verify_the_server_and_offer_x25519mlkem768() -> Result<()> {
        let pki = generate_pki(SERVER_NAME)?;
        let container = TlsPostgresContainer::start(&pki)?;
        let root_ca = container.write_root("root_ca.crt", &pki.root)?;
        let timeout = Duration::from_secs(10);

        // The server accepts only X25519MLKEM768, so every success below
        // also shows the client offers it.
        for (host, role_password) in [
            ("127.0.0.1", INITIAL_ROLE_PASSWORD),
            ("localhost", UPDATED_ROLE_PASSWORD),
        ] {
            let admin_dsn = container.admin_dsn(host);
            check_auth_sync(&admin_dsn, &root_ca, timeout)
                .with_context(|| format!("auth check over TLS to {host}"))?;
            provision_db_sync(
                &admin_dsn,
                &root_ca,
                PROVISION_DB_USER,
                role_password,
                PROVISION_DB_NAME,
                timeout,
            )
            .with_context(|| format!("provisioning over TLS to {host}"))?;
            check_auth_sync(
                &tls_role_dsn(host, container.port, role_password),
                &root_ca,
                timeout,
            )
            .with_context(|| format!("provisioned role over TLS to {host}"))?;
        }

        // `verify --db-check` translates the stored compose-form DSN to
        // the host form before checking it.
        let stored_dsn = format!(
            "postgresql://{PROVISION_DB_USER}:{UPDATED_ROLE_PASSWORD}@postgres:5432/{PROVISION_DB_NAME}?sslmode=verify-full&sslrootcert={IRRELEVANT_SSLROOTCERT}"
        );
        let host_dsn = for_host_runtime_with_port(&stored_dsn, container.port)?;
        check_auth_sync(&host_dsn, &root_ca, timeout).context("verify --db-check path over TLS")?;
        Ok(())
    }

    #[test]
    #[ignore = "Requires local Docker and the declared PostgreSQL image"]
    fn tls_connections_refuse_plaintext_other_roots_and_host_names() -> Result<()> {
        let pki = generate_pki(SERVER_NAME)?;
        let container = TlsPostgresContainer::start(&pki)?;
        let root_ca = container.write_root("root_ca.crt", &pki.root)?;
        let (other_root_pem, _) = generate_ca("bootroot test other CA")?;
        let other_root = container.write_root("other_root_ca.crt", &other_root_pem)?;
        let timeout = Duration::from_secs(10);
        let admin_dsn = container.admin_dsn("127.0.0.1");

        let plaintext_dsn = format!(
            "postgresql://{DB_USER}:{}@127.0.0.1:{}/{DB_NAME}?sslmode=disable",
            container.admin_password, container.port
        );
        let err = check_auth_sync(&plaintext_dsn, &root_ca, timeout)
            .expect_err("the server must refuse a plaintext connection");
        assert_tls_failure(&err, "pg_hba.conf", &container.admin_password);

        let err = check_auth_sync(&admin_dsn, &other_root, timeout)
            .expect_err("a server under another CA must fail verification");
        assert_tls_failure(&err, "UnknownIssuer", &container.admin_password);
        let err = provision_db_sync(
            &admin_dsn,
            &other_root,
            PROVISION_DB_USER,
            INITIAL_ROLE_PASSWORD,
            PROVISION_DB_NAME,
            timeout,
        )
        .expect_err("provisioning under another CA must fail verification");
        assert_tls_failure(&err, "UnknownIssuer", &container.admin_password);

        for host in ["postgres", "db.internal"] {
            let err = check_auth_sync(&container.admin_dsn(host), &root_ca, timeout)
                .expect_err("a TLS DSN naming a host must be refused");
            assert_tls_failure(
                &err,
                "verify the name `postgres`",
                &container.admin_password,
            );
        }

        // Mid CA rotation the root file holds two roots; a server under
        // either verifies.
        let both_roots =
            container.write_root("both_roots.crt", &format!("{other_root_pem}{}", pki.root))?;
        check_auth_sync(&admin_dsn, &both_roots, timeout)
            .context("auth check with two roots in the root file")?;
        Ok(())
    }

    #[test]
    #[ignore = "Requires local Docker and the declared PostgreSQL image"]
    fn tls_connections_refuse_a_certificate_for_another_name() -> Result<()> {
        let pki = generate_pki(OTHER_SERVER_NAME)?;
        let container = TlsPostgresContainer::start(&pki)?;
        let root_ca = container.write_root("root_ca.crt", &pki.root)?;
        let timeout = Duration::from_secs(10);
        let admin_dsn = container.admin_dsn("127.0.0.1");

        let err = check_auth_sync(&admin_dsn, &root_ca, timeout)
            .expect_err("a certificate for another name must fail verification");
        assert_tls_failure(
            &err,
            "certificate not valid for name \"postgres\"",
            &container.admin_password,
        );
        let err = provision_db_sync(
            &admin_dsn,
            &root_ca,
            PROVISION_DB_USER,
            INITIAL_ROLE_PASSWORD,
            PROVISION_DB_NAME,
            timeout,
        )
        .expect_err("provisioning to a certificate for another name must fail");
        assert_tls_failure(
            &err,
            "certificate not valid for name \"postgres\"",
            &container.admin_password,
        );
        Ok(())
    }
}
