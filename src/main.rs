mod openbao;

use std::collections::BTreeMap;
use std::env;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Command as ProcessCommand;

use anyhow::{Context, Result};
use bootroot::fs_util;
use clap::{Args, Parser, Subcommand};
use openbao::{InitResponse, OpenBaoClient};
use serde::Serialize;

const DEFAULT_OPENBAO_URL: &str = "http://localhost:8200";
const DEFAULT_KV_MOUNT: &str = "secret";
const DEFAULT_SECRETS_DIR: &str = "secrets";
const DEFAULT_COMPOSE_FILE: &str = "docker-compose.yml";
const DEFAULT_CA_NAME: &str = "Bootroot CA";
const DEFAULT_CA_PROVISIONER: &str = "admin";
const DEFAULT_CA_DNS: &str = "localhost,bootroot-ca";
const DEFAULT_CA_ADDRESS: &str = ":9000";
const INIT_SECRET_SHARES: u8 = 3;
const INIT_SECRET_THRESHOLD: u8 = 2;
const TOKEN_TTL: &str = "1h";
const SECRET_ID_TTL: &str = "24h";
const SECRET_BYTES: usize = 32;

const POLICY_BOOTROOT_AGENT: &str = "bootroot-agent";
const POLICY_BOOTROOT_RESPONDER: &str = "bootroot-responder";
const POLICY_BOOTROOT_STEPCA: &str = "bootroot-stepca";

const APPROLE_BOOTROOT_AGENT: &str = "bootroot-agent-role";
const APPROLE_BOOTROOT_RESPONDER: &str = "bootroot-responder-role";
const APPROLE_BOOTROOT_STEPCA: &str = "bootroot-stepca-role";

const PATH_STEPCA_PASSWORD: &str = "bootroot/stepca/password";
const PATH_STEPCA_DB: &str = "bootroot/stepca/db";
const PATH_RESPONDER_HMAC: &str = "bootroot/responder/hmac";
const PATH_AGENT_EAB: &str = "bootroot/agent/eab";

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand, Debug)]
enum CliCommand {
    #[command(subcommand)]
    Infra(InfraCommand),
    Init(InitArgs),
    Status,
    #[command(subcommand)]
    App(AppCommand),
    Verify,
}

#[derive(Subcommand, Debug)]
enum InfraCommand {
    Up(InfraUpArgs),
}

#[derive(Subcommand, Debug)]
enum AppCommand {
    Add,
    Info,
}

#[derive(Args, Debug)]
struct InfraUpArgs {
    /// Path to docker-compose.yml
    #[arg(long, default_value = "docker-compose.yml")]
    compose_file: PathBuf,

    /// Comma-separated list of services to start
    #[arg(
        long,
        default_value = "openbao,postgres,step-ca,bootroot-http01",
        value_delimiter = ','
    )]
    services: Vec<String>,

    /// Directory containing local image archives (optional)
    #[arg(long)]
    image_archive_dir: Option<PathBuf>,

    /// Docker restart policy to apply after containers start
    #[arg(long, default_value = "unless-stopped")]
    restart_policy: String,
}

#[derive(Args, Debug)]
struct InitArgs {
    /// `OpenBao` API URL
    #[arg(long, default_value = DEFAULT_OPENBAO_URL)]
    openbao_url: String,

    /// `OpenBao` KV mount path (KV v2)
    #[arg(long, default_value = DEFAULT_KV_MOUNT)]
    kv_mount: String,

    /// Secrets directory to render files into
    #[arg(long, default_value = DEFAULT_SECRETS_DIR)]
    secrets_dir: PathBuf,

    /// Docker compose file for infra health checks
    #[arg(long, default_value = DEFAULT_COMPOSE_FILE)]
    compose_file: PathBuf,

    /// Auto-generate secrets where possible
    #[arg(long)]
    auto_generate: bool,

    /// Show secrets in output summaries
    #[arg(long)]
    show_secrets: bool,

    /// `OpenBao` root token (required if already initialized)
    #[arg(long, env = "OPENBAO_ROOT_TOKEN")]
    root_token: Option<String>,

    /// `OpenBao` unseal key (repeatable)
    #[arg(long, env = "OPENBAO_UNSEAL_KEYS", value_delimiter = ',')]
    unseal_key: Vec<String>,

    /// step-ca password (password.txt)
    #[arg(long, env = "STEPCA_PASSWORD")]
    stepca_password: Option<String>,

    /// `PostgreSQL` DSN for step-ca
    #[arg(long)]
    db_dsn: Option<String>,

    /// HTTP-01 responder HMAC secret
    #[arg(long, env = "HTTP01_HMAC")]
    http_hmac: Option<String>,

    /// ACME EAB key ID (optional)
    #[arg(long, env = "EAB_KID")]
    eab_kid: Option<String>,

    /// ACME EAB HMAC (optional)
    #[arg(long, env = "EAB_HMAC")]
    eab_hmac: Option<String>,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("bootroot error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        CliCommand::Infra(InfraCommand::Up(args)) => run_infra_up(&args)?,
        CliCommand::Init(args) => {
            let runtime = tokio::runtime::Runtime::new()
                .context("Failed to initialize async runtime for init")?;
            runtime.block_on(run_init(&args))?;
        }
        CliCommand::Status => {
            println!("bootroot status: not yet implemented");
        }
        CliCommand::App(AppCommand::Add) => {
            println!("bootroot app add: not yet implemented");
        }
        CliCommand::App(AppCommand::Info) => {
            println!("bootroot app info: not yet implemented");
        }
        CliCommand::Verify => {
            println!("bootroot verify: not yet implemented");
        }
    }
    Ok(())
}

fn run_infra_up(args: &InfraUpArgs) -> Result<()> {
    let loaded_archives = if let Some(dir) = args.image_archive_dir.as_deref() {
        load_local_images(dir)?
    } else {
        0
    };

    if loaded_archives == 0 {
        let pull_args = compose_pull_args(&args.compose_file, &args.services);
        let pull_args_ref: Vec<&str> = pull_args.iter().map(String::as_str).collect();
        run_docker(&pull_args_ref, "docker compose pull")?;
    }

    let compose_args = compose_up_args(&args.compose_file, &args.services);

    let compose_args_ref: Vec<&str> = compose_args.iter().map(String::as_str).collect();
    run_docker(&compose_args_ref, "docker compose up")?;

    let readiness = collect_readiness(&args.compose_file, &args.services)?;

    for entry in &readiness {
        let update_args = docker_update_args(&args.restart_policy, &entry.container_id);
        let update_args_ref: Vec<&str> = update_args.iter().map(String::as_str).collect();
        run_docker(&update_args_ref, "docker update")?;
    }

    print_readiness_summary(&readiness);
    ensure_all_healthy(&readiness)?;

    println!("bootroot infra up: completed");
    Ok(())
}

async fn run_init(args: &InitArgs) -> Result<()> {
    ensure_infra_ready(&args.compose_file)?;

    let mut client = OpenBaoClient::new(&args.openbao_url)?;
    client.health_check().await?;

    let mut rollback = InitRollback::default();
    let result: Result<InitSummary> = async {
        let bootstrap = bootstrap_openbao(&mut client, args).await?;
        let secrets = resolve_init_secrets(args)?;
        let (role_outputs, _policies, approles) =
            configure_openbao(&client, args, &secrets, &mut rollback).await?;

        let secrets_dir = args.secrets_dir.clone();
        rollback.password_backup =
            Some(write_password_file_with_backup(&secrets_dir, &secrets.stepca_password).await?);
        rollback.ca_json_backup =
            Some(update_ca_json_with_backup(&secrets_dir, &secrets.db_dsn).await?);

        let step_ca_result = ensure_step_ca_initialized(&secrets_dir)?;

        write_state_file(&args.openbao_url, &args.kv_mount, &approles)?;

        Ok(InitSummary {
            openbao_url: args.openbao_url.clone(),
            kv_mount: args.kv_mount.clone(),
            secrets_dir: args.secrets_dir.clone(),
            show_secrets: args.show_secrets,
            init_response: bootstrap.init_response.is_some(),
            root_token: bootstrap.root_token,
            unseal_keys: bootstrap.unseal_keys,
            approles: role_outputs,
            stepca_password: secrets.stepca_password,
            db_dsn: secrets.db_dsn,
            http_hmac: secrets.http_hmac,
            eab: secrets.eab,
            step_ca_result,
        })
    }
    .await;

    match result {
        Ok(summary) => {
            print_init_summary(&summary);
            Ok(())
        }
        Err(err) => {
            eprintln!("bootroot init: failed, attempting rollback");
            rollback.rollback(&client, &args.kv_mount).await;
            Err(err)
        }
    }
}

fn compose_up_args(compose_file: &Path, services: &[String]) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "up".to_string(),
        "-d".to_string(),
    ];
    args.extend(services.iter().cloned());
    args
}

fn compose_pull_args(compose_file: &Path, services: &[String]) -> Vec<String> {
    let mut args = vec![
        "compose".to_string(),
        "-f".to_string(),
        compose_file.to_string_lossy().to_string(),
        "pull".to_string(),
        "--ignore-pull-failures".to_string(),
    ];
    args.extend(services.iter().cloned());
    args
}

#[derive(Debug, Clone)]
struct AppRoleOutput {
    label: String,
    role_name: String,
    role_id: String,
    secret_id: String,
}

#[derive(Debug, Clone)]
struct EabCredentials {
    kid: String,
    hmac: String,
}

#[derive(Debug, Clone, Copy)]
enum StepCaInitResult {
    Initialized,
    Skipped,
}

#[derive(Debug, Serialize)]
struct StateFile {
    openbao_url: String,
    kv_mount: String,
    policies: BTreeMap<String, String>,
    approles: BTreeMap<String, String>,
    apps: BTreeMap<String, serde_json::Value>,
}

fn docker_update_args(restart_policy: &str, container_id: &str) -> Vec<String> {
    vec![
        "update".to_string(),
        "--restart".to_string(),
        restart_policy.to_string(),
        container_id.to_string(),
    ]
}

fn ensure_infra_ready(compose_file: &Path) -> Result<()> {
    let services = default_infra_services();
    let readiness = collect_readiness(compose_file, &services)?;
    ensure_all_healthy(&readiness)?;
    Ok(())
}

fn default_infra_services() -> Vec<String> {
    vec![
        "openbao".to_string(),
        "postgres".to_string(),
        "step-ca".to_string(),
        "bootroot-http01".to_string(),
    ]
}

struct InitBootstrap {
    init_response: Option<InitResponse>,
    root_token: String,
    unseal_keys: Vec<String>,
}

struct InitSecrets {
    stepca_password: String,
    db_dsn: String,
    http_hmac: String,
    eab: Option<EabCredentials>,
}

async fn bootstrap_openbao(client: &mut OpenBaoClient, args: &InitArgs) -> Result<InitBootstrap> {
    let (init_response, mut root_token, mut unseal_keys) =
        ensure_openbao_initialized(client, args).await?;

    let seal_status = client.seal_status().await?;
    if seal_status.sealed {
        if unseal_keys.is_empty() {
            unseal_keys = prompt_unseal_keys(seal_status.t)?;
        }
        unseal_openbao(client, &unseal_keys).await?;
    }

    if root_token.is_none() {
        root_token = Some(prompt_text("OpenBao root token: ")?);
    }
    let root_token = root_token.ok_or_else(|| anyhow::anyhow!("OpenBao root token is required"))?;

    client.set_token(root_token.clone());

    Ok(InitBootstrap {
        init_response,
        root_token,
        unseal_keys,
    })
}

fn resolve_init_secrets(args: &InitArgs) -> Result<InitSecrets> {
    let stepca_password = resolve_secret(
        "step-ca password",
        args.stepca_password.clone(),
        args.auto_generate,
    )?;
    let db_dsn = resolve_db_dsn(args)?;
    let http_hmac = resolve_secret(
        "HTTP-01 responder HMAC",
        args.http_hmac.clone(),
        args.auto_generate,
    )?;
    let eab = resolve_eab(args)?;

    Ok(InitSecrets {
        stepca_password,
        db_dsn,
        http_hmac,
        eab,
    })
}

async fn configure_openbao(
    client: &OpenBaoClient,
    args: &InitArgs,
    secrets: &InitSecrets,
    rollback: &mut InitRollback,
) -> Result<(
    Vec<AppRoleOutput>,
    BTreeMap<String, String>,
    BTreeMap<String, String>,
)> {
    client.ensure_kv_v2(&args.kv_mount).await?;
    client.ensure_approle_auth().await?;

    let policies = build_policy_map(&args.kv_mount);
    for (name, policy) in &policies {
        if !client.policy_exists(name).await? {
            rollback.created_policies.push(name.clone());
        }
        client.write_policy(name, policy).await?;
    }

    let approles = build_approle_map();
    for (label, role_name) in &approles {
        let policy_name = match label.as_str() {
            "bootroot_agent" => POLICY_BOOTROOT_AGENT,
            "responder" => POLICY_BOOTROOT_RESPONDER,
            "stepca" => POLICY_BOOTROOT_STEPCA,
            _ => continue,
        };
        if !client.approle_exists(role_name).await? {
            rollback.created_approles.push(role_name.clone());
        }
        client
            .create_approle(
                role_name,
                &[policy_name.to_string()],
                TOKEN_TTL,
                SECRET_ID_TTL,
                true,
            )
            .await?;
    }

    let mut role_outputs = Vec::new();
    for (label, role_name) in &approles {
        let role_id = client.read_role_id(role_name).await?;
        let secret_id = client.create_secret_id(role_name).await?;
        role_outputs.push(AppRoleOutput {
            label: label.clone(),
            role_name: role_name.clone(),
            role_id,
            secret_id,
        });
    }

    let mut kv_paths = vec![PATH_STEPCA_PASSWORD, PATH_STEPCA_DB, PATH_RESPONDER_HMAC];
    if secrets.eab.is_some() {
        kv_paths.push(PATH_AGENT_EAB);
    }
    for path in kv_paths {
        if !client.kv_exists(&args.kv_mount, path).await? {
            rollback.written_kv_paths.push(path.to_string());
        }
    }

    write_openbao_secrets_with_retry(client, &args.kv_mount, secrets).await?;

    Ok((role_outputs, policies, approles))
}

async fn write_openbao_secrets_with_retry(
    client: &OpenBaoClient,
    kv_mount: &str,
    secrets: &InitSecrets,
) -> Result<()> {
    let attempt = write_openbao_secrets(
        client,
        kv_mount,
        &secrets.stepca_password,
        &secrets.db_dsn,
        &secrets.http_hmac,
        secrets.eab.as_ref(),
    )
    .await;
    if let Err(err) = attempt {
        let message = err.to_string();
        if message.contains("No secret engine mount") {
            client.ensure_kv_v2(kv_mount).await?;
            write_openbao_secrets(
                client,
                kv_mount,
                &secrets.stepca_password,
                &secrets.db_dsn,
                &secrets.http_hmac,
                secrets.eab.as_ref(),
            )
            .await?;
        } else {
            return Err(err);
        }
    }
    Ok(())
}

async fn ensure_openbao_initialized(
    client: &OpenBaoClient,
    args: &InitArgs,
) -> Result<(Option<InitResponse>, Option<String>, Vec<String>)> {
    let initialized = client.is_initialized().await?;
    if initialized {
        return Ok((None, args.root_token.clone(), args.unseal_key.clone()));
    }

    let response = client
        .init(INIT_SECRET_SHARES, INIT_SECRET_THRESHOLD)
        .await?;
    let root_token = response.root_token.clone();
    let keys = if response.keys.is_empty() {
        response.keys_base64.clone()
    } else {
        response.keys.clone()
    };
    Ok((Some(response), Some(root_token), keys))
}

async fn unseal_openbao(client: &OpenBaoClient, keys: &[String]) -> Result<()> {
    for key in keys {
        let status = client.unseal(key).await?;
        if !status.sealed {
            return Ok(());
        }
    }
    let status = client.seal_status().await?;
    if status.sealed {
        anyhow::bail!("OpenBao remains sealed after applying unseal keys");
    }
    Ok(())
}

fn prompt_unseal_keys(threshold: Option<u32>) -> Result<Vec<String>> {
    let count = match threshold {
        Some(value) if value > 0 => value,
        _ => {
            let input = prompt_text("Unseal key threshold (t): ")?;
            input
                .parse::<u32>()
                .context("Invalid unseal threshold value")?
        }
    };
    let mut keys = Vec::with_capacity(count as usize);
    for index in 1..=count {
        let key = prompt_text(&format!("Unseal key {index}/{count}: "))?;
        keys.push(key);
    }
    Ok(keys)
}

fn prompt_text(prompt: &str) -> Result<String> {
    use std::io::{self, Write};
    print!("{prompt}");
    io::stdout().flush().context("Failed to flush stdout")?;
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .context("Failed to read input")?;
    Ok(input.trim().to_string())
}

fn resolve_secret(label: &str, value: Option<String>, auto_generate: bool) -> Result<String> {
    if let Some(value) = value {
        return Ok(value);
    }
    if auto_generate {
        return generate_secret();
    }
    prompt_text(&format!("{label}: "))
}

fn resolve_eab(args: &InitArgs) -> Result<Option<EabCredentials>> {
    match (&args.eab_kid, &args.eab_hmac) {
        (Some(kid), Some(hmac)) => Ok(Some(EabCredentials {
            kid: kid.clone(),
            hmac: hmac.clone(),
        })),
        (None, None) => Ok(None),
        _ => anyhow::bail!("EAB requires both kid and hmac"),
    }
}

fn resolve_db_dsn(args: &InitArgs) -> Result<String> {
    if let Some(dsn) = args.db_dsn.clone() {
        return Ok(dsn);
    }
    if let Some(dsn) = build_dsn_from_env() {
        return Ok(dsn);
    }
    prompt_text("PostgreSQL DSN: ")
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

fn generate_secret() -> Result<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::{SecureRandom, SystemRandom};

    let mut buffer = vec![0u8; SECRET_BYTES];
    let rng = SystemRandom::new();
    rng.fill(&mut buffer)
        .map_err(|_| anyhow::anyhow!("Failed to generate random secret"))?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

fn build_policy_map(kv_mount: &str) -> BTreeMap<String, String> {
    let mut policies = BTreeMap::new();
    policies.insert(
        POLICY_BOOTROOT_AGENT.to_string(),
        format!(
            r#"path "{kv_mount}/data/{PATH_AGENT_EAB}" {{
  capabilities = ["read"]
}}
path "{kv_mount}/data/{PATH_RESPONDER_HMAC}" {{
  capabilities = ["read"]
}}
"#
        ),
    );
    policies.insert(
        POLICY_BOOTROOT_RESPONDER.to_string(),
        format!(
            r#"path "{kv_mount}/data/{PATH_RESPONDER_HMAC}" {{
  capabilities = ["read"]
}}
"#
        ),
    );
    policies.insert(
        POLICY_BOOTROOT_STEPCA.to_string(),
        format!(
            r#"path "{kv_mount}/data/{PATH_STEPCA_PASSWORD}" {{
  capabilities = ["read"]
}}
path "{kv_mount}/data/{PATH_STEPCA_DB}" {{
  capabilities = ["read"]
}}
"#
        ),
    );
    policies
}

fn build_approle_map() -> BTreeMap<String, String> {
    let mut approles = BTreeMap::new();
    approles.insert(
        "bootroot_agent".to_string(),
        APPROLE_BOOTROOT_AGENT.to_string(),
    );
    approles.insert(
        "responder".to_string(),
        APPROLE_BOOTROOT_RESPONDER.to_string(),
    );
    approles.insert("stepca".to_string(), APPROLE_BOOTROOT_STEPCA.to_string());
    approles
}

async fn write_openbao_secrets(
    client: &OpenBaoClient,
    kv_mount: &str,
    stepca_password: &str,
    db_dsn: &str,
    http_hmac: &str,
    eab: Option<&EabCredentials>,
) -> Result<()> {
    client
        .write_kv(
            kv_mount,
            PATH_STEPCA_PASSWORD,
            serde_json::json!({ "value": stepca_password }),
        )
        .await?;
    client
        .write_kv(
            kv_mount,
            PATH_STEPCA_DB,
            serde_json::json!({ "dsn": db_dsn }),
        )
        .await?;
    client
        .write_kv(
            kv_mount,
            PATH_RESPONDER_HMAC,
            serde_json::json!({ "value": http_hmac }),
        )
        .await?;
    if let Some(eab) = eab {
        client
            .write_kv(
                kv_mount,
                PATH_AGENT_EAB,
                serde_json::json!({ "kid": eab.kid, "hmac": eab.hmac }),
            )
            .await?;
    }
    Ok(())
}

async fn write_password_file_with_backup(
    secrets_dir: &Path,
    password: &str,
) -> Result<RollbackFile> {
    fs_util::ensure_secrets_dir(secrets_dir).await?;
    let password_path = secrets_dir.join("password.txt");
    let original = match tokio::fs::read_to_string(&password_path).await {
        Ok(contents) => Some(contents),
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| format!("Failed to read {}", password_path.display()));
        }
    };
    tokio::fs::write(&password_path, password)
        .await
        .with_context(|| format!("Failed to write {}", password_path.display()))?;
    fs_util::set_key_permissions(&password_path).await?;
    Ok(RollbackFile {
        path: password_path,
        original,
    })
}

async fn update_ca_json_with_backup(secrets_dir: &Path, db_dsn: &str) -> Result<RollbackFile> {
    let path = secrets_dir.join("config").join("ca.json");
    let contents = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("Failed to read {}", path.display()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&contents).context("Failed to parse ca.json")?;
    value["db"]["type"] = serde_json::Value::String("postgresql".to_string());
    value["db"]["dataSource"] = serde_json::Value::String(db_dsn.to_string());
    let updated = serde_json::to_string_pretty(&value).context("Failed to serialize ca.json")?;
    tokio::fs::write(&path, updated)
        .await
        .with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(RollbackFile {
        path,
        original: Some(contents),
    })
}

fn ensure_step_ca_initialized(secrets_dir: &Path) -> Result<StepCaInitResult> {
    let config_path = secrets_dir.join("config").join("ca.json");
    let ca_key = secrets_dir.join("secrets").join("root_ca_key");
    let intermediate_key = secrets_dir.join("secrets").join("intermediate_ca_key");
    if config_path.exists() && ca_key.exists() && intermediate_key.exists() {
        return Ok(StepCaInitResult::Skipped);
    }

    let password_path = secrets_dir.join("password.txt");
    if !password_path.exists() {
        anyhow::bail!(
            "step-ca password file not found at {}",
            password_path.display()
        );
    }
    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| format!("Failed to resolve {}", secrets_dir.display()))?;
    let mount = format!("{}:/home/step", mount_root.display());
    let args = vec![
        "run".to_string(),
        "--user".to_string(),
        "root".to_string(),
        "--rm".to_string(),
        "-v".to_string(),
        mount,
        "smallstep/step-ca".to_string(),
        "step".to_string(),
        "ca".to_string(),
        "init".to_string(),
        "--name".to_string(),
        DEFAULT_CA_NAME.to_string(),
        "--provisioner".to_string(),
        DEFAULT_CA_PROVISIONER.to_string(),
        "--dns".to_string(),
        DEFAULT_CA_DNS.to_string(),
        "--address".to_string(),
        DEFAULT_CA_ADDRESS.to_string(),
        "--password-file".to_string(),
        "/home/step/password.txt".to_string(),
        "--provisioner-password-file".to_string(),
        "/home/step/password.txt".to_string(),
        "--acme".to_string(),
    ];
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run_docker(&args_ref, "docker step-ca init")?;
    Ok(StepCaInitResult::Initialized)
}

fn write_state_file(
    openbao_url: &str,
    kv_mount: &str,
    approles: &BTreeMap<String, String>,
) -> Result<()> {
    let policy_map = [
        (
            "bootroot_agent".to_string(),
            POLICY_BOOTROOT_AGENT.to_string(),
        ),
        (
            "responder".to_string(),
            POLICY_BOOTROOT_RESPONDER.to_string(),
        ),
        ("stepca".to_string(), POLICY_BOOTROOT_STEPCA.to_string()),
    ]
    .into_iter()
    .collect::<BTreeMap<_, _>>();
    let state = StateFile {
        openbao_url: openbao_url.to_string(),
        kv_mount: kv_mount.to_string(),
        policies: policy_map,
        approles: approles
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        apps: BTreeMap::new(),
    };
    let contents =
        serde_json::to_string_pretty(&state).context("Failed to serialize state.json")?;
    std::fs::write("state.json", contents).context("Failed to write state.json")?;
    Ok(())
}

#[derive(Debug)]
struct RollbackFile {
    path: PathBuf,
    original: Option<String>,
}

#[derive(Default)]
struct InitRollback {
    created_policies: Vec<String>,
    created_approles: Vec<String>,
    written_kv_paths: Vec<String>,
    password_backup: Option<RollbackFile>,
    ca_json_backup: Option<RollbackFile>,
}

impl InitRollback {
    async fn rollback(&self, client: &OpenBaoClient, kv_mount: &str) {
        for path in &self.written_kv_paths {
            if let Err(err) = client.delete_kv(kv_mount, path).await {
                eprintln!("Rollback: failed to delete KV path {path}: {err}");
            }
        }
        for role in &self.created_approles {
            if let Err(err) = client.delete_approle(role).await {
                eprintln!("Rollback: failed to delete AppRole {role}: {err}");
            }
        }
        for policy in &self.created_policies {
            if let Err(err) = client.delete_policy(policy).await {
                eprintln!("Rollback: failed to delete policy {policy}: {err}");
            }
        }
        if let Some(file) = &self.password_backup
            && let Err(err) = rollback_file(file)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
        }
        if let Some(file) = &self.ca_json_backup
            && let Err(err) = rollback_file(file)
        {
            eprintln!("Rollback: failed to restore {}: {err}", file.path.display());
        }
    }
}

fn rollback_file(file: &RollbackFile) -> Result<()> {
    if let Some(contents) = &file.original {
        std::fs::write(&file.path, contents)
            .with_context(|| format!("Failed to restore {}", file.path.display()))?;
    } else if file.path.exists() {
        std::fs::remove_file(&file.path)
            .with_context(|| format!("Failed to remove {}", file.path.display()))?;
    }
    Ok(())
}

struct InitSummary {
    openbao_url: String,
    kv_mount: String,
    secrets_dir: PathBuf,
    show_secrets: bool,
    init_response: bool,
    root_token: String,
    unseal_keys: Vec<String>,
    approles: Vec<AppRoleOutput>,
    stepca_password: String,
    db_dsn: String,
    http_hmac: String,
    eab: Option<EabCredentials>,
    step_ca_result: StepCaInitResult,
}

fn print_init_summary(summary: &InitSummary) {
    println!("bootroot init: summary");
    println!("- OpenBao URL: {}", summary.openbao_url);
    println!("- KV mount: {}", summary.kv_mount);
    println!("- Secrets dir: {}", summary.secrets_dir.display());
    match summary.step_ca_result {
        StepCaInitResult::Initialized => println!("- step-ca init: completed"),
        StepCaInitResult::Skipped => println!("- step-ca init: skipped (already initialized)"),
    }

    if summary.init_response {
        println!(
            "- OpenBao init: completed (shares={INIT_SECRET_SHARES}, threshold={INIT_SECRET_THRESHOLD})",
        );
    } else {
        println!("- OpenBao init: skipped (already initialized)");
    }

    println!(
        "- root token: {}",
        display_secret(&summary.root_token, summary.show_secrets)
    );

    if !summary.unseal_keys.is_empty() {
        for (idx, key) in summary.unseal_keys.iter().enumerate() {
            println!(
                "- unseal key {}: {}",
                idx + 1,
                display_secret(key, summary.show_secrets)
            );
        }
    }

    println!(
        "- step-ca password: {}",
        display_secret(&summary.stepca_password, summary.show_secrets)
    );
    println!(
        "- db dsn: {}",
        display_secret(&summary.db_dsn, summary.show_secrets)
    );
    println!(
        "- responder hmac: {}",
        display_secret(&summary.http_hmac, summary.show_secrets)
    );
    if let Some(eab) = summary.eab.as_ref() {
        println!(
            "- eab kid: {}",
            display_secret(&eab.kid, summary.show_secrets)
        );
        println!(
            "- eab hmac: {}",
            display_secret(&eab.hmac, summary.show_secrets)
        );
    } else {
        println!("- eab: not configured");
    }

    println!("- OpenBao KV paths:");
    println!("  - {PATH_STEPCA_PASSWORD}");
    println!("  - {PATH_STEPCA_DB}");
    println!("  - {PATH_RESPONDER_HMAC}");
    println!("  - {PATH_AGENT_EAB}");

    println!("- AppRoles:");
    for role in &summary.approles {
        println!("  - {} ({})", role.label, role.role_name);
        println!(
            "    role_id: {}",
            display_secret(&role.role_id, summary.show_secrets)
        );
        println!(
            "    secret_id: {}",
            display_secret(&role.secret_id, summary.show_secrets)
        );
    }

    println!("next steps:");
    println!("  - Configure OpenBao Agent templates for step-ca, responder, and bootroot-agent.");
    println!("  - Start or reload step-ca and responder to consume rendered secrets.");
    println!("  - Run `bootroot status` to verify services.");
    if summary.eab.is_none() {
        println!(
            "  - If you need ACME EAB, store kid/hmac at {PATH_AGENT_EAB} or rerun with --eab-kid/--eab-hmac."
        );
    }
}

fn display_secret(value: &str, show_secrets: bool) -> String {
    if show_secrets {
        value.to_string()
    } else {
        mask_value(value)
    }
}

fn mask_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() <= 4 {
        "****".to_string()
    } else {
        format!("****{}", &trimmed[trimmed.len() - 4..])
    }
}

fn load_local_images(dir: &Path) -> Result<usize> {
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("Failed to read image archive dir: {}", dir.display()))?;
    let mut loaded = 0;
    for entry in entries {
        let entry = entry.context("Failed to read image archive entry")?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if !is_image_archive(&path) {
            continue;
        }
        println!("Loading image archive: {}", path.display());
        run_docker(
            &["load", "-i", path.to_string_lossy().as_ref()],
            "docker load",
        )?;
        loaded += 1;
    }
    Ok(loaded)
}

fn is_image_archive(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let ext = Path::new(name).extension().and_then(|ext| ext.to_str());
    if let Some(ext) = ext
        && (ext.eq_ignore_ascii_case("tar") || ext.eq_ignore_ascii_case("tgz"))
    {
        return true;
    }
    name.to_ascii_lowercase().ends_with(".tar.gz")
}

fn run_docker(args: &[&str], context: &str) -> Result<()> {
    let status = ProcessCommand::new("docker")
        .args(args)
        .status()
        .with_context(|| format!("Failed to run {context}"))?;
    if !status.success() {
        anyhow::bail!("{context} failed with status: {status}");
    }
    Ok(())
}

fn docker_compose_output(args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new("docker")
        .args(["compose"])
        .args(args)
        .output()
        .context("Failed to run docker compose")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker compose failed: {stderr}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ContainerReadiness {
    service: String,
    container_id: String,
    status: String,
    health: Option<String>,
}

fn collect_readiness(compose_file: &Path, services: &[String]) -> Result<Vec<ContainerReadiness>> {
    let mut readiness = Vec::with_capacity(services.len());
    for service in services {
        let container_id = docker_compose_output(&[
            "-f",
            compose_file.to_string_lossy().as_ref(),
            "ps",
            "-q",
            service,
        ])?;
        let container_id = container_id.trim().to_string();
        if container_id.is_empty() {
            anyhow::bail!("Service has no running container: {service}");
        }
        let inspect_output = docker_output(&[
            "inspect",
            "--format",
            "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}",
            &container_id,
        ])?;
        let (status, health) = parse_container_state(&inspect_output);
        readiness.push(ContainerReadiness {
            service: service.clone(),
            container_id,
            status,
            health,
        });
    }
    Ok(readiness)
}

fn parse_container_state(raw: &str) -> (String, Option<String>) {
    let trimmed = raw.trim();
    let mut parts = trimmed.splitn(2, '|');
    let status = parts.next().unwrap_or_default().to_string();
    let health = parts.next().and_then(|value| {
        let value = value.trim();
        if value.is_empty() {
            None
        } else {
            Some(value.to_string())
        }
    });
    (status, health)
}

fn print_readiness_summary(readiness: &[ContainerReadiness]) {
    println!("bootroot infra up: readiness summary");
    for entry in readiness {
        match entry.health.as_deref() {
            Some(health) => println!("- {}: {} (health: {})", entry.service, entry.status, health),
            None => println!("- {}: {}", entry.service, entry.status),
        }
    }
}

fn ensure_all_healthy(readiness: &[ContainerReadiness]) -> Result<()> {
    let mut failures = Vec::new();
    for entry in readiness {
        if entry.status != "running" {
            failures.push(format!("{} status={}", entry.service, entry.status));
            continue;
        }
        if let Some(health) = entry.health.as_deref()
            && health != "healthy"
        {
            failures.push(format!("{} health={}", entry.service, health));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        anyhow::bail!("Infrastructure not healthy: {}", failures.join(", "))
    }
}

fn docker_output(args: &[&str]) -> Result<String> {
    let output = ProcessCommand::new("docker")
        .args(args)
        .output()
        .with_context(|| format!("Failed to run docker {}", args.join(" ")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("docker command failed: {stderr}");
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_image_archive_extensions() {
        assert!(is_image_archive(Path::new("image.tar")));
        assert!(is_image_archive(Path::new("image.TAR")));
        assert!(is_image_archive(Path::new("image.tgz")));
        assert!(is_image_archive(Path::new("image.TGZ")));
        assert!(is_image_archive(Path::new("image.tar.gz")));
        assert!(is_image_archive(Path::new("image.TAR.GZ")));
        assert!(!is_image_archive(Path::new("image.zip")));
        assert!(!is_image_archive(Path::new("image")));
    }

    #[test]
    fn test_compose_up_args_includes_services() {
        let compose_file = PathBuf::from("compose.yml");
        let services = vec!["openbao".to_string(), "postgres".to_string()];
        let args = compose_up_args(&compose_file, &services);
        assert_eq!(
            args,
            vec![
                "compose",
                "-f",
                "compose.yml",
                "up",
                "-d",
                "openbao",
                "postgres"
            ]
        );
    }

    #[test]
    fn test_docker_update_args() {
        let args = docker_update_args("unless-stopped", "container123");
        assert_eq!(
            args,
            vec!["update", "--restart", "unless-stopped", "container123"]
        );
    }

    #[test]
    fn test_compose_pull_args_includes_services() {
        let compose_file = PathBuf::from("docker-compose.yml");
        let services = vec!["openbao".to_string(), "postgres".to_string()];
        let args = compose_pull_args(&compose_file, &services);
        assert_eq!(
            args,
            vec![
                "compose",
                "-f",
                "docker-compose.yml",
                "pull",
                "--ignore-pull-failures",
                "openbao",
                "postgres"
            ]
        );
    }

    #[test]
    fn test_parse_container_state_with_health() {
        let (status, health) = parse_container_state("running|healthy\n");
        assert_eq!(status, "running");
        assert_eq!(health.as_deref(), Some("healthy"));
    }

    #[test]
    fn test_parse_container_state_without_health() {
        let (status, health) = parse_container_state("exited|\n");
        assert_eq!(status, "exited");
        assert!(health.is_none());
    }

    #[test]
    fn test_parse_container_state_missing_delimiter() {
        let (status, health) = parse_container_state("running");
        assert_eq!(status, "running");
        assert!(health.is_none());
    }

    #[test]
    fn test_cli_parses_services_list() {
        let cli = Cli::parse_from(["bootroot", "infra", "up", "--services", "openbao,postgres"]);
        match cli.command {
            CliCommand::Infra(InfraCommand::Up(args)) => {
                assert_eq!(args.services, vec!["openbao", "postgres"]);
            }
            _ => panic!("expected infra up"),
        }
    }

    #[test]
    fn test_mask_value_short() {
        assert_eq!(mask_value("abc"), "****");
    }

    #[test]
    fn test_mask_value_long() {
        assert_eq!(mask_value("secretvalue"), "****alue");
    }

    #[test]
    fn test_build_policy_map_contains_paths() {
        let policies = build_policy_map("secret");
        let agent_policy = policies.get(POLICY_BOOTROOT_AGENT).unwrap();
        assert!(agent_policy.contains("secret/data/bootroot/agent/eab"));
        assert!(agent_policy.contains("secret/data/bootroot/responder/hmac"));
    }
}
