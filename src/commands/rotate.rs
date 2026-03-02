use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;
use bootroot::{db, fs_util};
use reqwest::StatusCode;

use crate::cli::args::{
    RotateAppRoleSecretIdArgs, RotateArgs, RotateCaKeyArgs, RotateCommand, RotateDbArgs,
    RotateEabArgs, RotateForceReissueArgs, RotateResponderHmacArgs, RotateStepcaPasswordArgs,
};
use crate::cli::prompt::Prompt;
use crate::commands::guardrails::{ensure_postgres_localhost_binding, ensure_single_host_db_host};
use crate::commands::infra::run_docker;
use crate::commands::init::{
    CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, CA_ROOT_CERT_FILENAME, PATH_AGENT_EAB,
    PATH_RESPONDER_HMAC, PATH_STEPCA_DB, PATH_STEPCA_PASSWORD, compute_ca_bundle_pem,
    compute_ca_fingerprints, read_ca_cert_fingerprint,
};
use crate::commands::openbao_auth::{authenticate_openbao_client, resolve_runtime_auth};
use crate::commands::trust::{
    self, RotationMode, RotationState, create_rotation_state, delete_rotation_state,
    load_rotation_state, update_rotation_state,
};
use crate::i18n::Messages;
use crate::state::{DeliveryMode, DeployType, ServiceEntry, StateFile};
const SECRET_BYTES: usize = 32;
const OPENBAO_AGENT_CONTAINER_PREFIX: &str = "bootroot-openbao-agent";
const ROLE_ID_FILENAME: &str = "role_id";
const SERVICE_KV_BASE: &str = "bootroot/services";
const SERVICE_SECRET_ID_KEY: &str = "secret_id";
const SERVICE_EAB_KID_KEY: &str = "kid";
const SERVICE_EAB_HMAC_KEY: &str = "hmac";
const SERVICE_RESPONDER_HMAC_KEY: &str = "hmac";
const OPENBAO_AGENT_STEPCA_CONTAINER: &str = "bootroot-openbao-agent-stepca";
const OPENBAO_AGENT_RESPONDER_CONTAINER: &str = "bootroot-openbao-agent-responder";
const INTERMEDIATE_CA_COMMON_NAME: &str = "Bootroot Intermediate CA";
const RENDERED_FILE_POLL_INTERVAL: Duration = Duration::from_secs(1);
const RENDERED_FILE_TIMEOUT: Duration = Duration::from_secs(60);
const BOOTROOT_AGENT_CONTAINER_PREFIX: &str = "bootroot-agent";

#[derive(Debug, Clone)]
struct StatePaths {
    secrets_dir: PathBuf,
}

impl StatePaths {
    fn new(secrets_dir: PathBuf) -> Self {
        Self { secrets_dir }
    }

    fn secrets_dir(&self) -> &Path {
        &self.secrets_dir
    }

    fn stepca_password(&self) -> PathBuf {
        self.secrets_dir.join("password.txt")
    }

    fn stepca_password_new(&self) -> PathBuf {
        self.secrets_dir.join("password.txt.new")
    }

    fn stepca_root_key(&self) -> PathBuf {
        self.secrets_dir.join("secrets").join("root_ca_key")
    }

    fn stepca_intermediate_key(&self) -> PathBuf {
        self.secrets_dir.join("secrets").join("intermediate_ca_key")
    }

    fn responder_config(&self) -> PathBuf {
        self.secrets_dir.join("responder").join("responder.toml")
    }

    fn ca_json(&self) -> PathBuf {
        self.secrets_dir.join("config").join("ca.json")
    }

    fn ca_certs_dir(&self) -> PathBuf {
        self.secrets_dir.join(CA_CERTS_DIR)
    }

    fn root_cert(&self) -> PathBuf {
        self.ca_certs_dir().join(CA_ROOT_CERT_FILENAME)
    }

    fn intermediate_cert(&self) -> PathBuf {
        self.ca_certs_dir().join(CA_INTERMEDIATE_CERT_FILENAME)
    }

    fn intermediate_cert_bak(&self) -> PathBuf {
        self.ca_certs_dir()
            .join(format!("{CA_INTERMEDIATE_CERT_FILENAME}.bak"))
    }

    fn intermediate_key_bak(&self) -> PathBuf {
        self.secrets_dir
            .join("secrets")
            .join("intermediate_ca_key.bak")
    }
}

#[derive(Debug)]
struct RotateContext {
    openbao_url: String,
    kv_mount: String,
    compose_file: PathBuf,
    state: StateFile,
    paths: StatePaths,
    state_dir: PathBuf,
}

pub(crate) async fn run_rotate(args: &RotateArgs, messages: &Messages) -> Result<()> {
    let state_path = args
        .state_file
        .clone()
        .unwrap_or_else(StateFile::default_path);
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let state =
        StateFile::load(&state_path).with_context(|| messages.error_parse_state_failed())?;

    let openbao_url = args
        .openbao
        .openbao_url
        .clone()
        .unwrap_or_else(|| state.openbao_url.clone());
    let kv_mount = args
        .openbao
        .kv_mount
        .clone()
        .unwrap_or_else(|| state.kv_mount.clone());
    let secrets_dir = args
        .secrets_dir
        .secrets_dir
        .clone()
        .unwrap_or_else(|| state.secrets_dir());
    let paths = StatePaths::new(secrets_dir.clone());
    let state_dir = state_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let runtime_auth = resolve_runtime_auth(&args.runtime_auth, true, messages)?;
    let mut ctx = RotateContext {
        openbao_url,
        kv_mount,
        compose_file: args.compose.compose_file.clone(),
        state,
        paths,
        state_dir,
    };
    let mut client = OpenBaoClient::new(&ctx.openbao_url)
        .with_context(|| messages.error_openbao_client_create_failed())?;
    authenticate_openbao_client(&mut client, &runtime_auth, messages).await?;
    client
        .health_check()
        .await
        .with_context(|| messages.error_openbao_health_check_failed())?;

    match &args.command {
        RotateCommand::StepcaPassword(step_args) => {
            rotate_stepca_password(&mut ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::Eab(step_args) => {
            rotate_eab(&mut ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::Db(step_args) => {
            rotate_db(&mut ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::ResponderHmac(step_args) => {
            rotate_responder_hmac(&mut ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::AppRoleSecretId(step_args) => {
            rotate_approle_secret_id(&mut ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::TrustSync(_) => {
            rotate_trust_sync(&mut ctx, &client, args.yes, messages).await?;
        }
        RotateCommand::ForceReissue(step_args) => {
            rotate_force_reissue(&mut ctx, step_args, args.yes, messages)?;
        }
        RotateCommand::CaKey(step_args) => {
            rotate_ca_key(&mut ctx, &client, step_args, args.yes, messages).await?;
        }
    }

    Ok(())
}

async fn rotate_stepca_password(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateStepcaPasswordArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    let new_password = match args.new_password.clone() {
        Some(value) => value,
        None => generate_secret(messages)?,
    };
    confirm_action(
        messages.prompt_rotate_stepca_password(),
        auto_confirm,
        messages,
    )?;

    let secrets_dir = ctx.paths.secrets_dir();
    let password_path = ctx.paths.stepca_password();
    let new_password_path = ctx.paths.stepca_password_new();
    let root_key = ctx.paths.stepca_root_key();
    let intermediate_key = ctx.paths.stepca_intermediate_key();

    ensure_file_exists(&password_path, messages)?;
    ensure_file_exists(&root_key, messages)?;
    ensure_file_exists(&intermediate_key, messages)?;

    fs_util::ensure_secrets_dir(secrets_dir).await?;
    write_secret_file(&new_password_path, &new_password, messages).await?;

    change_stepca_passphrase(
        secrets_dir,
        &password_path,
        &new_password_path,
        &root_key,
        messages,
    )?;
    change_stepca_passphrase(
        secrets_dir,
        &password_path,
        &new_password_path,
        &intermediate_key,
        messages,
    )?;

    client
        .write_kv(
            &ctx.kv_mount,
            PATH_STEPCA_PASSWORD,
            serde_json::json!({ "value": new_password }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    restart_container(OPENBAO_AGENT_STEPCA_CONTAINER, messages)?;
    wait_for_rendered_file(
        &password_path,
        &new_password,
        RENDERED_FILE_TIMEOUT,
        messages,
    )
    .await?;

    restart_compose_service(&ctx.compose_file, "step-ca", messages)?;

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_stepca_password(&password_path.display().to_string())
    );
    println!("{}", messages.rotate_summary_restart_stepca());
    Ok(())
}

async fn rotate_eab(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateEabArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(messages.prompt_rotate_eab(), auto_confirm, messages)?;

    let credentials = issue_eab_via_stepca(args, messages).await?;
    client
        .write_kv(
            &ctx.kv_mount,
            PATH_AGENT_EAB,
            serde_json::json!({ "kid": credentials.kid, "hmac": credentials.hmac }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    sync_service_eab_payloads(ctx, client, &credentials.kid, &credentials.hmac, messages).await?;

    println!("{}", messages.rotate_summary_title());
    println!("{}", messages.summary_eab_kid(&credentials.kid));
    println!("{}", messages.summary_eab_hmac(&credentials.hmac));
    Ok(())
}

async fn rotate_db(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateDbArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(messages.prompt_rotate_db(), auto_confirm, messages)?;
    ensure_postgres_localhost_binding(&ctx.compose_file, messages)?;

    let admin_dsn = resolve_db_admin_dsn(args, messages)?;
    let admin = db::parse_db_dsn(&admin_dsn).with_context(|| messages.error_invalid_db_dsn())?;
    ensure_single_host_db_host(&admin.host, messages)?;
    let db_password = match args.password.clone() {
        Some(value) => value,
        None => generate_secret(messages)?,
    };
    let ca_json_path = ctx.paths.ca_json();
    let current_dsn = read_ca_json_dsn(&ca_json_path, messages)?;
    let parsed = db::parse_db_dsn(&current_dsn).with_context(|| messages.error_invalid_db_dsn())?;
    ensure_single_host_db_host(&parsed.host, messages)?;
    let timeout = Duration::from_secs(args.timeout.timeout_secs);

    // Run the synchronous postgres client on a blocking thread to avoid
    // "Cannot start a runtime from within a runtime" panic. The postgres
    // crate internally calls block_on, which conflicts with the existing
    // tokio runtime when called from an async context.
    let admin_dsn_clone = admin_dsn.clone();
    let user_clone = parsed.user.clone();
    let password_clone = db_password.clone();
    let database_clone = parsed.database.clone();
    tokio::task::spawn_blocking(move || {
        db::provision_db_sync(
            &admin_dsn_clone,
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

async fn rotate_responder_hmac(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateResponderHmacArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(
        messages.prompt_rotate_responder_hmac(),
        auto_confirm,
        messages,
    )?;

    let hmac = match args.hmac.clone() {
        Some(value) => value,
        None => generate_secret(messages)?,
    };
    client
        .write_kv(
            &ctx.kv_mount,
            PATH_RESPONDER_HMAC,
            serde_json::json!({ "value": hmac }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    sync_service_responder_hmac_payloads(ctx, client, &hmac, messages).await?;

    let responder_path = ctx.paths.responder_config();
    restart_container(OPENBAO_AGENT_RESPONDER_CONTAINER, messages)?;
    wait_for_rendered_file(&responder_path, &hmac, RENDERED_FILE_TIMEOUT, messages).await?;

    restart_service_sidecar_agents(ctx, &hmac, messages).await?;

    let mut reloaded = false;
    if compose_has_responder(&ctx.compose_file, messages)? {
        reload_compose_service(&ctx.compose_file, "bootroot-http01", messages)?;
        reloaded = true;
    }

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_responder_config(&responder_path.display().to_string())
    );
    if reloaded {
        println!("{}", messages.rotate_summary_reload_responder());
    }
    Ok(())
}

async fn rotate_approle_secret_id(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateAppRoleSecretIdArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(
        &messages.prompt_rotate_approle_secret_id(&args.service_name),
        auto_confirm,
        messages,
    )?;

    let entry = ctx
        .state
        .services
        .get(&args.service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(&args.service_name)))?
        .clone();
    let is_remote = matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap);
    if !is_remote {
        ensure_role_id_file(&entry, client, messages).await?;
    }
    let new_secret_id = client
        .create_secret_id(&entry.approle.role_name)
        .await
        .with_context(|| messages.error_openbao_secret_id_failed())?;
    if !is_remote {
        write_secret_id_atomic(&entry.approle.secret_id_path, &new_secret_id, messages).await?;
        reload_openbao_agent(&entry, messages)?;
    }
    client
        .login_approle(&entry.approle.role_id, &new_secret_id)
        .await
        .with_context(|| messages.error_openbao_approle_login_failed())?;
    if is_remote {
        write_remote_service_secret_id(
            client,
            &ctx.kv_mount,
            &args.service_name,
            &new_secret_id,
            messages,
        )
        .await?;
    }

    println!("{}", messages.rotate_summary_title());
    // codeql[rust/cleartext-logging]: output is a secret_id file path, not the secret value.
    println!(
        "{}",
        messages.rotate_summary_approle_secret_id(
            &args.service_name,
            &entry.approle.secret_id_path.display().to_string()
        )
    );
    if !is_remote {
        println!("{}", messages.rotate_summary_reload_openbao_agent());
    }
    println!(
        "{}",
        messages.rotate_summary_approle_login_ok(&args.service_name)
    );
    Ok(())
}

async fn ensure_role_id_file(
    entry: &ServiceEntry,
    client: &OpenBaoClient,
    messages: &Messages,
) -> Result<()> {
    let service_dir = entry
        .approle
        .secret_id_path
        .parent()
        .unwrap_or(Path::new("."));
    let role_id_path = service_dir.join(ROLE_ID_FILENAME);
    if role_id_path.exists() {
        return Ok(());
    }
    let role_id = client
        .read_role_id(&entry.approle.role_name)
        .await
        .with_context(|| messages.error_openbao_role_id_failed())?;
    fs_util::ensure_secrets_dir(service_dir).await?;
    tokio::fs::write(&role_id_path, role_id)
        .await
        .with_context(|| messages.error_write_file_failed(&role_id_path.display().to_string()))?;
    fs_util::set_key_permissions(&role_id_path).await?;
    Ok(())
}

async fn write_remote_service_secret_id(
    client: &OpenBaoClient,
    kv_mount: &str,
    service_name: &str,
    secret_id: &str,
    messages: &Messages,
) -> Result<()> {
    client
        .write_kv(
            kv_mount,
            &format!("{SERVICE_KV_BASE}/{service_name}/secret_id"),
            serde_json::json!({ SERVICE_SECRET_ID_KEY: secret_id }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())
}

async fn sync_service_eab_payloads(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    kid: &str,
    hmac: &str,
    messages: &Messages,
) -> Result<()> {
    for service_name in ctx
        .state
        .services
        .values()
        .map(|entry| entry.service_name.as_str())
    {
        client
            .write_kv(
                &ctx.kv_mount,
                &format!("{SERVICE_KV_BASE}/{service_name}/eab"),
                serde_json::json!({ SERVICE_EAB_KID_KEY: kid, SERVICE_EAB_HMAC_KEY: hmac }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }
    Ok(())
}

async fn sync_service_responder_hmac_payloads(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    hmac: &str,
    messages: &Messages,
) -> Result<()> {
    for service_name in ctx
        .state
        .services
        .values()
        .map(|entry| entry.service_name.as_str())
    {
        client
            .write_kv(
                &ctx.kv_mount,
                &format!("{SERVICE_KV_BASE}/{service_name}/http_responder_hmac"),
                serde_json::json!({ SERVICE_RESPONDER_HMAC_KEY: hmac }),
            )
            .await
            .with_context(|| messages.error_openbao_kv_write_failed())?;
    }
    Ok(())
}

fn resolve_db_admin_dsn(args: &RotateDbArgs, messages: &Messages) -> Result<String> {
    if let Some(value) = args.admin_dsn.admin_dsn.clone() {
        return Ok(value);
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout();
    let mut prompt = Prompt::new(&mut input, &mut output, messages);
    prompt.prompt_with_validation(messages.prompt_db_admin_dsn(), None, |value| {
        ensure_non_empty(value, messages)
    })
}

fn ensure_non_empty(value: &str, messages: &Messages) -> Result<String> {
    if value.trim().is_empty() {
        anyhow::bail!(messages.error_value_required());
    }
    Ok(value.trim().to_string())
}

fn confirm_action(prompt: &str, auto_confirm: bool, messages: &Messages) -> Result<()> {
    if auto_confirm {
        return Ok(());
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout();
    let mut prompt_reader = Prompt::new(&mut input, &mut output, messages);
    let response = prompt_reader.prompt_text(prompt, None)?;
    let normalized = response.trim().to_ascii_lowercase();
    if normalized == "y" || normalized == "yes" {
        Ok(())
    } else {
        anyhow::bail!(messages.error_operation_cancelled());
    }
}

fn ensure_file_exists(path: &Path, messages: &Messages) -> Result<()> {
    if path.exists() {
        Ok(())
    } else {
        anyhow::bail!(messages.error_file_missing(&path.display().to_string()));
    }
}

fn change_stepca_passphrase(
    secrets_dir: &Path,
    current_password: &Path,
    new_password: &Path,
    key_path: &Path,
    messages: &Messages,
) -> Result<()> {
    let mount_root = fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
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
        "crypto".to_string(),
        "change-pass".to_string(),
        to_container_path(secrets_dir, key_path)?,
        "--password-file".to_string(),
        to_container_path(secrets_dir, current_password)?,
        "--new-password-file".to_string(),
        to_container_path(secrets_dir, new_password)?,
        "-f".to_string(),
    ];
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run_docker(&args_ref, "docker step-ca change-pass", messages)?;
    Ok(())
}

fn restart_container(container: &str, messages: &Messages) -> Result<()> {
    let args = ["restart", container];
    run_docker(&args, "docker restart", messages)
}

async fn wait_for_rendered_file(
    path: &Path,
    expected: &str,
    timeout: Duration,
    messages: &Messages,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(contents) = tokio::fs::read_to_string(path).await
            && contents.contains(expected)
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(messages.error_rendered_file_timeout(&path.display().to_string()));
        }
        tokio::time::sleep(RENDERED_FILE_POLL_INTERVAL).await;
    }
}

fn restart_compose_service(compose_file: &Path, service: &str, messages: &Messages) -> Result<()> {
    let compose_file = compose_file.to_string_lossy();
    let args = ["compose", "-f", compose_file.as_ref(), "restart", service];
    run_docker(&args, "docker compose restart", messages)
}

fn reload_compose_service(compose_file: &Path, service: &str, messages: &Messages) -> Result<()> {
    let compose_file = compose_file.to_string_lossy();
    let args = [
        "compose",
        "-f",
        compose_file.as_ref(),
        "kill",
        "-s",
        "HUP",
        service,
    ];
    run_docker(&args, "docker compose kill", messages)
}

fn read_ca_json_dsn(path: &Path, messages: &Messages) -> Result<String> {
    let contents = fs::read_to_string(path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let value: serde_json::Value =
        serde_json::from_str(&contents).context(messages.error_parse_ca_json_failed())?;
    let db = value
        .get("db")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    let data_source = db
        .get("dataSource")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    Ok(data_source.to_string())
}

async fn write_secret_file(path: &Path, contents: &str, messages: &Messages) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs_util::ensure_secrets_dir(parent).await?;
    }
    tokio::fs::write(path, contents)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    fs_util::set_key_permissions(path).await?;
    Ok(())
}

fn generate_secret(messages: &Messages) -> Result<String> {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ring::rand::{SecureRandom, SystemRandom};

    let mut buffer = vec![0u8; SECRET_BYTES];
    let rng = SystemRandom::new();
    rng.fill(&mut buffer)
        .map_err(|_| anyhow::anyhow!(messages.error_generate_secret_failed()))?;
    Ok(URL_SAFE_NO_PAD.encode(buffer))
}

fn to_container_path(secrets_dir: &Path, path: &Path) -> Result<String> {
    let relative = path
        .strip_prefix(secrets_dir)
        .with_context(|| format!("Path {} is not under secrets dir", path.display()))?;
    Ok(format!("/home/step/{}", relative.to_string_lossy()))
}

async fn write_secret_id_atomic(path: &Path, value: &str, messages: &Messages) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!(messages.error_parent_not_found(&path.display().to_string()))
    })?;
    if parent.as_os_str().is_empty() {
        anyhow::bail!(messages.error_parent_not_found(&path.display().to_string()));
    }
    fs_util::ensure_secrets_dir(parent).await?;
    let temp_path = temp_secret_path(path);
    tokio::fs::write(&temp_path, value)
        .await
        .with_context(|| messages.error_write_file_failed(&temp_path.display().to_string()))?;
    fs_util::set_key_permissions(&temp_path).await?;
    tokio::fs::rename(&temp_path, path)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

fn temp_secret_path(path: &Path) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let file_name = path.file_name().map_or_else(
        || "secret_id".to_string(),
        |name| name.to_string_lossy().to_string(),
    );
    let temp_name = format!("{file_name}.tmp.{pid}.{nanos}");
    path.with_file_name(temp_name)
}

fn reload_openbao_agent(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    match entry.deploy_type {
        crate::state::DeployType::Docker => {
            let container = openbao_agent_container_name(&entry.service_name);
            run_docker(
                &["restart", &container],
                "docker restart OpenBao Agent",
                messages,
            )
        }
        crate::state::DeployType::Daemon => reload_openbao_agent_daemon(entry, messages),
    }
}

#[cfg(unix)]
fn reload_openbao_agent_daemon(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    let config_path = entry.agent_config_path.display().to_string();
    let status = std::process::Command::new("pkill")
        .args(["-HUP", "-f", &config_path])
        .status()
        .with_context(|| messages.error_command_run_failed("pkill -HUP"))?;
    if !status.success() {
        anyhow::bail!(messages.error_command_failed_status("pkill -HUP", &status.to_string()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reload_openbao_agent_daemon(_entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    anyhow::bail!(messages.error_command_run_failed("pkill -HUP"));
}

async fn restart_service_sidecar_agents(
    ctx: &RotateContext,
    expected_hmac: &str,
    messages: &Messages,
) -> Result<()> {
    let mut agent_config_paths = std::collections::BTreeSet::new();
    for entry in ctx.state.services.values() {
        if !matches!(entry.delivery_mode, DeliveryMode::LocalFile) {
            continue;
        }
        let container = openbao_agent_container_name(&entry.service_name);
        let _ = try_restart_container(&container);
        agent_config_paths.insert(entry.agent_config_path.clone());
    }
    for path in &agent_config_paths {
        wait_for_rendered_file(path, expected_hmac, RENDERED_FILE_TIMEOUT, messages).await?;
    }
    Ok(())
}

fn try_restart_container(container: &str) -> Result<()> {
    let status = std::process::Command::new("docker")
        .args(["restart", container])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()?;
    if !status.success() {
        anyhow::bail!("container {container} not found or restart failed");
    }
    Ok(())
}

fn openbao_agent_container_name(service_name: &str) -> String {
    format!("{OPENBAO_AGENT_CONTAINER_PREFIX}-{service_name}")
}

fn compose_has_responder(compose_file: &Path, messages: &Messages) -> Result<bool> {
    let compose_contents = fs::read_to_string(compose_file)
        .with_context(|| messages.error_read_file_failed(&compose_file.display().to_string()))?;
    Ok(compose_contents.contains("bootroot-http01"))
}

async fn issue_eab_via_stepca(args: &RotateEabArgs, messages: &Messages) -> Result<EabCredentials> {
    let base = args.stepca_url.trim_end_matches('/');
    let provisioner = args.stepca_provisioner.trim();
    let endpoint = format!("{base}/acme/{provisioner}/eab");
    let client = reqwest::Client::new();

    let response = client
        .post(&endpoint)
        .send()
        .await
        .with_context(|| messages.error_eab_request_failed())?;
    let response = if response.status() == StatusCode::METHOD_NOT_ALLOWED {
        client
            .get(&endpoint)
            .send()
            .await
            .with_context(|| messages.error_eab_request_failed())?
    } else {
        response
    };
    let response = response
        .error_for_status()
        .with_context(|| messages.error_eab_request_failed())?;

    let payload: EabAutoResponse = response
        .json()
        .await
        .with_context(|| messages.error_eab_response_parse_failed())?;
    Ok(EabCredentials {
        kid: payload.kid,
        hmac: payload.hmac,
    })
}

#[derive(Debug, serde::Deserialize)]
struct EabAutoResponse {
    kid: String,
    hmac: String,
}

#[derive(Debug)]
struct EabCredentials {
    kid: String,
    hmac: String,
}

async fn rotate_trust_sync(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(messages.prompt_rotate_trust_sync(), auto_confirm, messages)?;

    if crate::commands::trust::rotation_in_progress(&ctx.state_dir) {
        eprintln!("{}", messages.warning_rotation_in_progress());
        anyhow::bail!(messages.error_trust_sync_blocked_by_rotation());
    }

    let secrets_dir = ctx.paths.secrets_dir();
    let fingerprints = compute_ca_fingerprints(secrets_dir, messages).await?;
    let ca_bundle_pem = compute_ca_bundle_pem(secrets_dir, messages).await?;

    crate::commands::trust::write_trust_to_openbao(
        client,
        &ctx.kv_mount,
        &ctx.state.services,
        &fingerprints,
        &ca_bundle_pem,
        messages,
    )
    .await?;

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_trust_sync_global(&fingerprints.join(", "))
    );
    let service_names: Vec<String> = ctx
        .state
        .services
        .values()
        .map(|entry| entry.service_name.clone())
        .collect();
    for service_name in &service_names {
        println!(
            "{}",
            messages.rotate_summary_trust_sync_service(service_name)
        );
    }
    Ok(())
}

fn rotate_force_reissue(
    ctx: &mut RotateContext,
    args: &RotateForceReissueArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    let entry = ctx
        .state
        .services
        .get(&args.service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(&args.service_name)))?
        .clone();

    confirm_action(
        &messages.prompt_rotate_force_reissue(&args.service_name),
        auto_confirm,
        messages,
    )?;

    // Delete cert and key files (ignore if already missing)
    let cert_path = &entry.cert_path;
    let key_path = &entry.key_path;
    let _ = fs::remove_file(cert_path);
    let _ = fs::remove_file(key_path);

    println!("{}", messages.rotate_summary_title());
    println!(
        "{}",
        messages.rotate_summary_force_reissue_deleted(
            &args.service_name,
            &cert_path.display().to_string(),
            &key_path.display().to_string(),
        )
    );

    if matches!(entry.delivery_mode, DeliveryMode::LocalFile) {
        signal_bootroot_agent(&entry, messages)?;
        println!(
            "{}",
            messages.rotate_summary_force_reissue_local_signal(&args.service_name)
        );
    } else {
        println!(
            "{}",
            messages.rotate_summary_force_reissue_remote_hint(&args.service_name)
        );
    }
    Ok(())
}

fn signal_bootroot_agent(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    match entry.deploy_type {
        DeployType::Docker => {
            let container = format!("{BOOTROOT_AGENT_CONTAINER_PREFIX}-{}", entry.service_name);
            run_docker(
                &["restart", &container],
                "docker restart bootroot-agent",
                messages,
            )
        }
        DeployType::Daemon => signal_bootroot_agent_daemon(entry, messages),
    }
}

#[cfg(unix)]
fn signal_bootroot_agent_daemon(entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    let config_path = entry.agent_config_path.display().to_string();
    let status = std::process::Command::new("pkill")
        .args(["-HUP", "-f", &config_path])
        .status()
        .with_context(|| messages.error_command_run_failed("pkill -HUP"))?;
    if !status.success() {
        anyhow::bail!(messages.error_command_failed_status("pkill -HUP", &status.to_string()));
    }
    Ok(())
}

#[cfg(not(unix))]
fn signal_bootroot_agent_daemon(_entry: &ServiceEntry, messages: &Messages) -> Result<()> {
    anyhow::bail!(messages.error_command_run_failed("pkill -HUP"));
}

// Phases 0–7 form a single logical workflow; splitting would harm readability.
#[allow(clippy::too_many_lines)]
async fn rotate_ca_key(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateCaKeyArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    // Phase 0 — Pre-flight
    if args.full {
        anyhow::bail!(messages.error_ca_key_full_not_implemented());
    }

    ensure_file_exists(&ctx.paths.root_cert(), messages)?;
    ensure_file_exists(&ctx.paths.intermediate_cert(), messages)?;
    ensure_file_exists(&ctx.paths.stepca_intermediate_key(), messages)?;
    ensure_file_exists(&ctx.paths.stepca_password(), messages)?;

    let root_fp = read_ca_cert_fingerprint(&ctx.paths.root_cert(), messages).await?;
    let current_inter_fp =
        read_ca_cert_fingerprint(&ctx.paths.intermediate_cert(), messages).await?;

    println!(
        "{}",
        messages.rotate_ca_key_current_fingerprints(&root_fp, &current_inter_fp)
    );

    let mut start_phase: u8 = 0;
    let mut rot_state = if let Some(state) = load_rotation_state(&ctx.state_dir, messages)? {
        println!(
            "{}",
            messages.rotate_ca_key_resuming(&state.phase.to_string())
        );
        start_phase = state.phase;
        state
    } else {
        if ctx.paths.intermediate_cert_bak().exists() || ctx.paths.intermediate_key_bak().exists() {
            eprintln!("{}", messages.warning_stale_backup());
        }
        confirm_action(
            messages
                .prompt_rotate_ca_key(&root_fp, &current_inter_fp)
                .as_str(),
            auto_confirm,
            messages,
        )?;
        RotationState {
            mode: RotationMode::IntermediateOnly,
            started_at: time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
            old_root_fp: root_fp.clone(),
            new_root_fp: root_fp.clone(),
            old_intermediate_fp: current_inter_fp.clone(),
            new_intermediate_fp: String::new(),
            phase: 0,
        }
    };

    // Phase 1 — Backup
    if start_phase < 1 {
        println!("{}", messages.rotate_ca_key_phase_backup());
        backup_file(
            &ctx.paths.intermediate_cert(),
            &ctx.paths.intermediate_cert_bak(),
            messages,
        )?;
        backup_file(
            &ctx.paths.stepca_intermediate_key(),
            &ctx.paths.intermediate_key_bak(),
            messages,
        )?;
        rot_state.phase = 1;
        if start_phase == 0 && rot_state.new_intermediate_fp.is_empty() {
            create_rotation_state(&ctx.state_dir, &rot_state, messages)?;
        } else {
            update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
        }
    } else {
        println!("{}", messages.rotate_ca_key_phase_skipped("1"));
    }

    // Phase 2 — Generate new intermediate
    if start_phase < 2 {
        println!("{}", messages.rotate_ca_key_phase_generate());

        // Check if already regenerated (idempotency)
        let pre_fp = read_ca_cert_fingerprint(&ctx.paths.intermediate_cert(), messages).await?;
        if pre_fp != rot_state.old_intermediate_fp && !rot_state.old_intermediate_fp.is_empty() {
            // Already regenerated in a previous partial run
            rot_state.new_intermediate_fp = pre_fp;
        } else {
            generate_new_intermediate(ctx, messages)?;
            let new_fp = read_ca_cert_fingerprint(&ctx.paths.intermediate_cert(), messages).await?;
            rot_state.new_intermediate_fp = new_fp;
        }

        rot_state.phase = 2;
        update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
    } else {
        println!("{}", messages.rotate_ca_key_phase_skipped("2"));
    }

    // Phase 3 — Distribute transitional trust (additive)
    if start_phase < 3 {
        println!("{}", messages.rotate_ca_key_phase_trust_additive());

        let transitional_fps = vec![
            rot_state.old_root_fp.clone(),
            rot_state.old_intermediate_fp.clone(),
            rot_state.new_intermediate_fp.clone(),
        ];
        let ca_bundle_pem = compute_ca_bundle_pem(ctx.paths.secrets_dir(), messages).await?;
        trust::write_trust_to_openbao(
            client,
            &ctx.kv_mount,
            &ctx.state.services,
            &transitional_fps,
            &ca_bundle_pem,
            messages,
        )
        .await?;

        // Restart OpenBao Agent sidecars so they pick up new trust
        restart_openbao_agent_sidecars(ctx, messages);

        rot_state.phase = 3;
        update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
    } else {
        println!("{}", messages.rotate_ca_key_phase_skipped("3"));
    }

    // Phase 4 — Restart step-ca
    if start_phase < 4 {
        println!("{}", messages.rotate_ca_key_phase_restart_stepca());
        restart_compose_service(&ctx.compose_file, "step-ca", messages)?;

        rot_state.phase = 4;
        update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
    } else {
        println!("{}", messages.rotate_ca_key_phase_skipped("4"));
    }

    // Phase 5 — Re-issue service certificates
    if start_phase < 5 && !args.skip_reissue {
        println!("{}", messages.rotate_ca_key_phase_reissue());

        let new_inter_cert_path = ctx.paths.intermediate_cert();
        for entry in ctx.state.services.values() {
            let cert_path = &entry.cert_path;
            if cert_path.exists()
                && cert_issued_by_new_intermediate(cert_path, &new_inter_cert_path, messages)
                    .unwrap_or(false)
            {
                println!(
                    "{}",
                    messages.rotate_ca_key_skip_migrated(&entry.service_name)
                );
                continue;
            }

            if matches!(entry.delivery_mode, DeliveryMode::LocalFile) {
                let _ = fs::remove_file(cert_path);
                let _ = fs::remove_file(&entry.key_path);
                signal_bootroot_agent(entry, messages)?;
            } else {
                println!(
                    "{}",
                    messages.rotate_ca_key_reissue_remote_hint(&entry.service_name)
                );
            }
        }

        rot_state.phase = 5;
        update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
    } else if start_phase < 5 {
        println!("{}", messages.rotate_ca_key_phase_skipped("5"));
    }

    // Phase 6 — Finalize trust (subtractive)
    if start_phase < 6 && !args.skip_finalize {
        println!("{}", messages.rotate_ca_key_phase_finalize());

        let new_inter_cert_path = ctx.paths.intermediate_cert();
        let mut unmigrated = Vec::new();
        for entry in ctx.state.services.values() {
            if matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap) {
                continue;
            }
            let cert_path = &entry.cert_path;
            match cert_issued_by_new_intermediate(cert_path, &new_inter_cert_path, messages) {
                Ok(true) => {}
                _ => unmigrated.push(entry.service_name.clone()),
            }
        }

        if !unmigrated.is_empty() {
            let list = unmigrated.join(", ");
            if !args.force {
                anyhow::bail!(messages.rotate_ca_key_finalize_blocked(&list));
            }
            eprintln!("{}", messages.warning_force_finalize());
            if !auto_confirm {
                confirm_action(
                    messages.rotate_ca_key_finalize_blocked(&list).as_str(),
                    false,
                    messages,
                )?;
            }
        }

        let final_fps = vec![
            rot_state.new_root_fp.clone(),
            rot_state.new_intermediate_fp.clone(),
        ];
        let ca_bundle_pem = compute_ca_bundle_pem(ctx.paths.secrets_dir(), messages).await?;
        trust::write_trust_to_openbao(
            client,
            &ctx.kv_mount,
            &ctx.state.services,
            &final_fps,
            &ca_bundle_pem,
            messages,
        )
        .await?;

        rot_state.phase = 6;
        update_rotation_state(&ctx.state_dir, &rot_state, messages)?;
    } else if start_phase < 6 {
        println!("{}", messages.rotate_ca_key_phase_skipped("6"));
    }

    // Phase 7 — Cleanup
    println!("{}", messages.rotate_ca_key_phase_cleanup());
    if args.cleanup {
        let _ = fs::remove_file(ctx.paths.intermediate_cert_bak());
        let _ = fs::remove_file(ctx.paths.intermediate_key_bak());
    }
    delete_rotation_state(&ctx.state_dir, messages)?;

    println!(
        "{}",
        messages.rotate_ca_key_complete(
            &rot_state.old_intermediate_fp,
            &rot_state.new_intermediate_fp,
        )
    );

    Ok(())
}

fn generate_new_intermediate(ctx: &RotateContext, messages: &Messages) -> Result<()> {
    let mount_root = fs::canonicalize(ctx.paths.secrets_dir()).with_context(|| {
        messages.error_resolve_path_failed(&ctx.paths.secrets_dir().display().to_string())
    })?;
    let mount = format!("{}:/home/step", mount_root.display());
    let args = vec![
        "run",
        "--user",
        "root",
        "--rm",
        "-v",
        &mount,
        "smallstep/step-ca",
        "step",
        "certificate",
        "create",
        INTERMEDIATE_CA_COMMON_NAME,
        "/home/step/certs/intermediate_ca.crt",
        "/home/step/secrets/intermediate_ca_key",
        "--profile",
        "intermediate-ca",
        "--ca",
        "/home/step/certs/root_ca.crt",
        "--ca-key",
        "/home/step/secrets/root_ca_key",
        "--password-file",
        "/home/step/password.txt",
        "--ca-password-file",
        "/home/step/password.txt",
        "--force",
    ];
    run_docker(&args, "docker step certificate create", messages)?;
    Ok(())
}

fn backup_file(src: &Path, dst: &Path, messages: &Messages) -> Result<()> {
    if dst.exists() {
        // Already backed up — skip
        return Ok(());
    }
    fs::copy(src, dst)
        .with_context(|| messages.error_write_file_failed(&dst.display().to_string()))?;
    Ok(())
}

fn restart_openbao_agent_sidecars(ctx: &RotateContext, _messages: &Messages) {
    for entry in ctx.state.services.values() {
        if !matches!(entry.delivery_mode, DeliveryMode::LocalFile) {
            continue;
        }
        let container = openbao_agent_container_name(&entry.service_name);
        let _ = try_restart_container(&container);
    }
    // Also restart core infrastructure agents so they pick up new trust
    let _ = try_restart_container(OPENBAO_AGENT_STEPCA_CONTAINER);
    let _ = try_restart_container(OPENBAO_AGENT_RESPONDER_CONTAINER);
}

/// Checks whether a leaf certificate was issued by the new intermediate CA
/// by comparing the leaf's Issuer DN with the intermediate's Subject DN.
fn cert_issued_by_new_intermediate(
    cert_path: &Path,
    new_inter_cert_path: &Path,
    messages: &Messages,
) -> Result<bool> {
    use x509_parser::pem::parse_x509_pem;

    let leaf_display = cert_path.display().to_string();
    let leaf_pem_bytes =
        fs::read(cert_path).with_context(|| messages.error_read_file_failed(&leaf_display))?;
    let (_, leaf_pem) = parse_x509_pem(&leaf_pem_bytes).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            messages.error_parse_cert_failed(&leaf_display, &format!("{e:?}"))
        )
    })?;
    let leaf_cert = leaf_pem.parse_x509().map_err(|e| {
        anyhow::anyhow!(
            "{}",
            messages.error_parse_cert_failed(&leaf_display, &format!("{e:?}"))
        )
    })?;

    let inter_display = new_inter_cert_path.display().to_string();
    let inter_pem_bytes = fs::read(new_inter_cert_path)
        .with_context(|| messages.error_read_file_failed(&inter_display))?;
    let (_, inter_pem) = parse_x509_pem(&inter_pem_bytes).map_err(|e| {
        anyhow::anyhow!(
            "{}",
            messages.error_parse_cert_failed(&inter_display, &format!("{e:?}"))
        )
    })?;
    let inter_cert = inter_pem.parse_x509().map_err(|e| {
        anyhow::anyhow!(
            "{}",
            messages.error_parse_cert_failed(&inter_display, &format!("{e:?}"))
        )
    })?;

    Ok(leaf_cert.issuer() == inter_cert.subject())
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::ffi::{OsStr, OsString};
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::sync::{LazyLock, Mutex, MutexGuard};

    use tempfile::tempdir;

    use super::*;
    use crate::cli::args::{DbAdminDsnArgs, DbTimeoutArgs};

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));
    const TEST_DOCKER_ARGS_ENV: &str = "BOOTROOT_TEST_DOCKER_ARGS";
    const TEST_DOCKER_EXIT_ENV: &str = "BOOTROOT_TEST_DOCKER_EXIT";

    struct ScopedEnvVar {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl ScopedEnvVar {
        fn set(key: &'static str, value: impl AsRef<OsStr>) -> Self {
            let previous = env::var_os(key);
            // SAFETY: Tests hold ENV_LOCK while mutating process environment.
            unsafe {
                env::set_var(key, value);
            }
            Self { key, previous }
        }
    }

    impl Drop for ScopedEnvVar {
        fn drop(&mut self) {
            // SAFETY: Tests hold ENV_LOCK while mutating process environment.
            unsafe {
                if let Some(previous) = &self.previous {
                    env::set_var(self.key, previous);
                } else {
                    env::remove_var(self.key);
                }
            }
        }
    }

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .lock()
            .expect("environment lock must not be poisoned")
    }

    fn write_fake_docker_script(path: &Path) {
        let script = r#"#!/bin/sh
set -eu
printf '%s\n' "$@" > "${BOOTROOT_TEST_DOCKER_ARGS:?missing log path}"
if [ -n "${BOOTROOT_TEST_DOCKER_EXIT:-}" ]; then
  exit "${BOOTROOT_TEST_DOCKER_EXIT}"
fi
exit 0
"#;
        fs::write(path, script).expect("fake docker script should be written");
        #[cfg(unix)]
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .expect("fake docker script should be executable");
    }

    fn path_with_prepend(bin_dir: &Path) -> OsString {
        let mut paths = vec![bin_dir.to_path_buf()];
        if let Some(existing) = env::var_os("PATH") {
            paths.extend(env::split_paths(&existing));
        }
        env::join_paths(paths).expect("PATH components should be valid")
    }

    fn test_messages() -> Messages {
        Messages::new("en").expect("valid language")
    }

    #[test]
    fn change_stepca_passphrase_invokes_docker_with_force_and_expected_paths() {
        let _lock = env_lock();
        let temp = tempdir().expect("tempdir");
        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        let docker_path = bin_dir.join("docker");
        write_fake_docker_script(&docker_path);

        let args_log_path = temp.path().join("docker-args.log");
        let _path_guard = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args_guard = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log_path.as_os_str());
        let _exit_guard = ScopedEnvVar::set(TEST_DOCKER_EXIT_ENV, "0");

        let secrets_dir = temp.path().join("secrets");
        fs::create_dir_all(secrets_dir.join("secrets")).expect("create secrets key dir");
        let current_password = secrets_dir.join("password.txt");
        let new_password = secrets_dir.join("password.txt.new");
        let key_path = secrets_dir.join("secrets").join("root_ca_key");
        fs::write(&current_password, "old").expect("write current password");
        fs::write(&new_password, "new").expect("write new password");
        fs::write(&key_path, "key").expect("write key");

        change_stepca_passphrase(
            &secrets_dir,
            &current_password,
            &new_password,
            &key_path,
            &test_messages(),
        )
        .expect("change passphrase should succeed");

        let logged_args = fs::read_to_string(&args_log_path).expect("read logged args");
        let args: Vec<&str> = logged_args.lines().collect();
        let mount_root = fs::canonicalize(&secrets_dir).expect("canonicalize secrets dir");
        let expected_mount = format!("{}:/home/step", mount_root.display());
        let expected = vec![
            "run",
            "--user",
            "root",
            "--rm",
            "-v",
            expected_mount.as_str(),
            "smallstep/step-ca",
            "step",
            "crypto",
            "change-pass",
            "/home/step/secrets/root_ca_key",
            "--password-file",
            "/home/step/password.txt",
            "--new-password-file",
            "/home/step/password.txt.new",
            "-f",
        ];
        assert_eq!(args, expected);
    }

    #[test]
    fn change_stepca_passphrase_fails_when_key_is_outside_secrets_dir() {
        let temp = tempdir().expect("tempdir");
        let secrets_dir = temp.path().join("secrets");
        fs::create_dir_all(&secrets_dir).expect("create secrets dir");
        let current_password = secrets_dir.join("password.txt");
        let new_password = secrets_dir.join("password.txt.new");
        fs::write(&current_password, "old").expect("write current password");
        fs::write(&new_password, "new").expect("write new password");
        let external_key = temp.path().join("external.key");
        fs::write(&external_key, "key").expect("write key");

        let err = change_stepca_passphrase(
            &secrets_dir,
            &current_password,
            &new_password,
            &external_key,
            &test_messages(),
        )
        .expect_err("key outside secrets dir must fail");
        assert!(err.to_string().contains("is not under secrets dir"));
    }

    #[test]
    fn change_stepca_passphrase_surfaces_docker_failure_status() {
        let _lock = env_lock();
        let temp = tempdir().expect("tempdir");
        let bin_dir = temp.path().join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        let docker_path = bin_dir.join("docker");
        write_fake_docker_script(&docker_path);

        let args_log_path = temp.path().join("docker-args.log");
        let _path_guard = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args_guard = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log_path.as_os_str());
        let _exit_guard = ScopedEnvVar::set(TEST_DOCKER_EXIT_ENV, "7");

        let secrets_dir = temp.path().join("secrets");
        fs::create_dir_all(secrets_dir.join("secrets")).expect("create secrets key dir");
        let current_password = secrets_dir.join("password.txt");
        let new_password = secrets_dir.join("password.txt.new");
        let key_path = secrets_dir.join("secrets").join("root_ca_key");
        fs::write(&current_password, "old").expect("write current password");
        fs::write(&new_password, "new").expect("write new password");
        fs::write(&key_path, "key").expect("write key");

        let err = change_stepca_passphrase(
            &secrets_dir,
            &current_password,
            &new_password,
            &key_path,
            &test_messages(),
        )
        .expect_err("docker failure should bubble up");
        let message = err.to_string();
        assert!(message.contains("docker step-ca change-pass"));
    }

    #[test]
    fn openbao_agent_container_name_uses_prefix() {
        let name = openbao_agent_container_name("api");
        assert_eq!(name, "bootroot-openbao-agent-api");
    }

    #[tokio::test]
    async fn write_secret_id_atomic_overwrites_contents() {
        let dir = tempdir().expect("tempdir");
        let secret_path = dir.path().join("app").join("secret_id");
        let messages = test_messages();

        write_secret_id_atomic(&secret_path, "old", &messages)
            .await
            .expect("initial write");
        write_secret_id_atomic(&secret_path, "new", &messages)
            .await
            .expect("overwrite");

        let contents = tokio::fs::read_to_string(&secret_path)
            .await
            .expect("read secret_id");
        assert_eq!(contents, "new");
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&secret_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    #[tokio::test]
    async fn write_secret_id_atomic_requires_parent_dir() {
        let messages = test_messages();
        let err = write_secret_id_atomic(Path::new("secret_id"), "value", &messages)
            .await
            .expect_err("expected parent error");
        let err = err.to_string();
        assert!(err.contains("Parent directory not found"));
    }

    #[test]
    fn temp_secret_path_adds_suffix() {
        let path = Path::new("/tmp/secret_id");
        let temp = temp_secret_path(path);
        let name = temp.file_name().expect("filename").to_string_lossy();
        assert!(name.starts_with("secret_id.tmp."));
    }

    #[test]
    fn resolve_db_admin_dsn_uses_cli_arg() {
        let messages = test_messages();
        let args = RotateDbArgs {
            admin_dsn: DbAdminDsnArgs {
                admin_dsn: Some("postgresql://admin:pass@127.0.0.1:15432/postgres".to_string()),
            },
            password: None,
            timeout: DbTimeoutArgs { timeout_secs: 30 },
        };
        let resolved = resolve_db_admin_dsn(&args, &messages).expect("resolve dsn");
        assert_eq!(resolved, "postgresql://admin:pass@127.0.0.1:15432/postgres");
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

    #[tokio::test]
    async fn wait_for_rendered_file_immediate() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("rendered.txt");
        fs::write(&path, "expected-value").expect("write file");
        let messages = test_messages();

        wait_for_rendered_file(
            &path,
            "expected-value",
            Duration::from_millis(500),
            &messages,
        )
        .await
        .expect("should return immediately when file already contains expected content");
    }

    #[tokio::test]
    async fn wait_for_rendered_file_timeout() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("never.txt");
        fs::write(&path, "wrong-content").expect("write file");
        let messages = test_messages();

        let err = wait_for_rendered_file(
            &path,
            "expected-value",
            Duration::from_millis(100),
            &messages,
        )
        .await
        .expect_err("should timeout when content never matches");
        assert!(err.to_string().contains("Timed out"));
    }

    #[test]
    fn cert_issued_by_self_signed_matches() {
        use rcgen::{CertificateParams, DnType, Issuer, KeyPair};

        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        let ca_key = KeyPair::generate().expect("ca key");
        let mut ca_params = CertificateParams::new(vec!["Test CA".to_string()]).expect("ca params");
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Test CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert = ca_params
            .clone()
            .self_signed(&ca_key)
            .expect("self-signed CA");
        let ca_issuer = Issuer::new(ca_params, ca_key);

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["leaf.example.com".to_string()]).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "leaf.example.com");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca_issuer)
            .expect("signed leaf");

        let ca_path = dir.path().join("ca.crt");
        let leaf_path = dir.path().join("leaf.crt");
        fs::write(&ca_path, ca_cert.pem()).expect("write ca cert");
        fs::write(&leaf_path, leaf_cert.pem()).expect("write leaf cert");

        assert!(
            cert_issued_by_new_intermediate(&leaf_path, &ca_path, &messages).expect("check issuer"),
            "leaf should be recognized as issued by the CA"
        );
    }

    #[test]
    fn cert_issued_by_different_ca_does_not_match() {
        use rcgen::{CertificateParams, DnType, Issuer, KeyPair};

        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        let ca1_key = KeyPair::generate().expect("ca1 key");
        let mut ca1_params =
            CertificateParams::new(vec!["CA One".to_string()]).expect("ca1 params");
        ca1_params
            .distinguished_name
            .push(DnType::CommonName, "CA One");
        ca1_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca1_issuer = Issuer::new(ca1_params, ca1_key);

        let ca2_key = KeyPair::generate().expect("ca2 key");
        let mut ca2_params =
            CertificateParams::new(vec!["CA Two".to_string()]).expect("ca2 params");
        ca2_params
            .distinguished_name
            .push(DnType::CommonName, "CA Two");
        ca2_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca2_cert = ca2_params.self_signed(&ca2_key).expect("self-signed CA2");

        let leaf_key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["leaf.example.com".to_string()]).expect("leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "leaf.example.com");
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &ca1_issuer)
            .expect("signed leaf");

        let ca2_path = dir.path().join("ca2.crt");
        let leaf_path = dir.path().join("leaf.crt");
        fs::write(&ca2_path, ca2_cert.pem()).expect("write ca2 cert");
        fs::write(&leaf_path, leaf_cert.pem()).expect("write leaf cert");

        assert!(
            !cert_issued_by_new_intermediate(&leaf_path, &ca2_path, &messages)
                .expect("check issuer"),
            "leaf should NOT be recognized as issued by a different CA"
        );
    }

    #[test]
    fn cert_issued_by_invalid_pem_returns_error() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        let bad_cert = dir.path().join("bad.crt");
        let good_cert = dir.path().join("good.crt");
        fs::write(&bad_cert, "NOT A PEM FILE").expect("write bad cert");
        fs::write(&good_cert, "ALSO NOT PEM").expect("write good cert");

        let result = cert_issued_by_new_intermediate(&bad_cert, &good_cert, &messages);
        assert!(result.is_err(), "invalid PEM should return error");
    }

    #[test]
    fn cert_issued_by_missing_file_returns_error() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        let missing = dir.path().join("nonexistent.crt");
        let also_missing = dir.path().join("also_missing.crt");

        let result = cert_issued_by_new_intermediate(&missing, &also_missing, &messages);
        assert!(result.is_err(), "missing file should return error");
    }
}
