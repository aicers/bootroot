use std::collections::BTreeMap;
use std::env;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::acme::responder_client;
use bootroot::db::{DbDsn, check_tcp, parse_db_dsn};
use bootroot::fs_util;
use bootroot::openbao::{InitResponse, OpenBaoClient};
use reqwest::StatusCode;

use crate::InitArgs;
use crate::cli::output::{print_init_plan, print_init_summary};
use crate::commands::infra::{ensure_infra_ready, run_docker};
use crate::i18n::Messages;
use crate::state::StateFile;

pub(crate) const DEFAULT_OPENBAO_URL: &str = "http://localhost:8200";
pub(crate) const DEFAULT_KV_MOUNT: &str = "secret";
pub(crate) const DEFAULT_SECRETS_DIR: &str = "secrets";
pub(crate) const DEFAULT_COMPOSE_FILE: &str = "docker-compose.yml";
pub(crate) const DEFAULT_STEPCA_URL: &str = "https://localhost:9000";
pub(crate) const DEFAULT_STEPCA_PROVISIONER: &str = "acme";

const DEFAULT_CA_NAME: &str = "Bootroot CA";
const DEFAULT_CA_PROVISIONER: &str = "admin";
const DEFAULT_CA_DNS: &str = "localhost,bootroot-ca";
const DEFAULT_CA_ADDRESS: &str = ":9000";
const SECRET_BYTES: usize = 32;
const DEFAULT_RESPONDER_TOKEN_TTL_SECS: u64 = 60;
const DEFAULT_EAB_ENDPOINT_PATH: &str = "eab";

mod openbao_constants {
    pub(crate) const INIT_SECRET_SHARES: u8 = 3;
    pub(crate) const INIT_SECRET_THRESHOLD: u8 = 2;
    pub(crate) const TOKEN_TTL: &str = "1h";
    pub(crate) const SECRET_ID_TTL: &str = "24h";

    pub(crate) const POLICY_BOOTROOT_AGENT: &str = "bootroot-agent";
    pub(crate) const POLICY_BOOTROOT_RESPONDER: &str = "bootroot-responder";
    pub(crate) const POLICY_BOOTROOT_STEPCA: &str = "bootroot-stepca";

    pub(crate) const APPROLE_BOOTROOT_AGENT: &str = "bootroot-agent-role";
    pub(crate) const APPROLE_BOOTROOT_RESPONDER: &str = "bootroot-responder-role";
    pub(crate) const APPROLE_BOOTROOT_STEPCA: &str = "bootroot-stepca-role";

    pub(crate) const PATH_STEPCA_PASSWORD: &str = "bootroot/stepca/password";
    pub(crate) const PATH_STEPCA_DB: &str = "bootroot/stepca/db";
    pub(crate) const PATH_RESPONDER_HMAC: &str = "bootroot/responder/hmac";
    pub(crate) const PATH_AGENT_EAB: &str = "bootroot/agent/eab";
}

pub(crate) use openbao_constants::{
    APPROLE_BOOTROOT_AGENT, APPROLE_BOOTROOT_RESPONDER, APPROLE_BOOTROOT_STEPCA,
    INIT_SECRET_SHARES, INIT_SECRET_THRESHOLD, PATH_AGENT_EAB, PATH_RESPONDER_HMAC, PATH_STEPCA_DB,
    PATH_STEPCA_PASSWORD, POLICY_BOOTROOT_AGENT, POLICY_BOOTROOT_RESPONDER, POLICY_BOOTROOT_STEPCA,
    SECRET_ID_TTL, TOKEN_TTL,
};

pub(crate) async fn run_init(args: &InitArgs, messages: &Messages) -> Result<()> {
    ensure_infra_ready(&args.compose_file, messages)?;

    let mut client = OpenBaoClient::new(&args.openbao_url)?;
    client.health_check().await?;

    let mut rollback = InitRollback::default();
    let result: Result<InitSummary> = async {
        let bootstrap = bootstrap_openbao(&mut client, args, messages).await?;
        let mut secrets = resolve_init_secrets(args, messages)?;
        let db_info = parse_db_dsn(&secrets.db_dsn)
            .map_err(|_| anyhow::anyhow!(messages.error_invalid_db_dsn()))?;
        let db_check = if args.db_check {
            check_db_connectivity(&db_info, args.db_timeout_secs, messages).await?;
            DbCheckStatus::Ok
        } else {
            DbCheckStatus::Skipped
        };
        let overwrite_password = args.secrets_dir.join("password.txt").exists();
        let overwrite_ca_json = args.secrets_dir.join("config").join("ca.json").exists();
        let overwrite_state = Path::new("state.json").exists();
        let plan = InitPlan {
            openbao_url: args.openbao_url.clone(),
            kv_mount: args.kv_mount.clone(),
            secrets_dir: args.secrets_dir.clone(),
            overwrite_password,
            overwrite_ca_json,
            overwrite_state,
        };
        print_init_plan(&plan, messages);
        if overwrite_password {
            confirm_overwrite(messages.prompt_confirm_overwrite_password(), messages)?;
        }
        if overwrite_ca_json {
            confirm_overwrite(messages.prompt_confirm_overwrite_ca_json(), messages)?;
        }
        if overwrite_state {
            confirm_overwrite(messages.prompt_confirm_overwrite_state(), messages)?;
        }

        let (role_outputs, _policies, approles) =
            configure_openbao(&client, args, &secrets, &mut rollback).await?;

        let secrets_dir = args.secrets_dir.clone();
        rollback.password_backup =
            Some(write_password_file_with_backup(&secrets_dir, &secrets.stepca_password).await?);
        rollback.ca_json_backup =
            Some(update_ca_json_with_backup(&secrets_dir, &secrets.db_dsn).await?);

        let step_ca_result = ensure_step_ca_initialized(&secrets_dir)?;
        let responder_check = verify_responder(args, messages, &secrets).await?;
        let eab_update =
            maybe_register_eab(&client, args, messages, &mut rollback, &secrets).await?;
        if let Some(eab) = eab_update {
            secrets.eab = Some(eab);
        }

        write_state_file(
            &args.openbao_url,
            &args.kv_mount,
            &approles,
            &args.secrets_dir,
        )?;

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
            responder_check,
            db_check,
        })
    }
    .await;

    match result {
        Ok(summary) => {
            print_init_summary(&summary, messages);
            Ok(())
        }
        Err(err) => {
            eprintln!("{}", messages.init_failed_rollback());
            rollback.rollback(&client, &args.kv_mount).await;
            Err(err)
        }
    }
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

#[derive(serde::Deserialize)]
struct EabAutoResponse {
    #[serde(alias = "keyId", alias = "kid")]
    kid: String,
    #[serde(alias = "hmacKey", alias = "hmac")]
    hmac: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum ResponderCheck {
    Skipped,
    Ok,
}

async fn bootstrap_openbao(
    client: &mut OpenBaoClient,
    args: &InitArgs,
    messages: &Messages,
) -> Result<InitBootstrap> {
    let (init_response, mut root_token, mut unseal_keys) =
        ensure_openbao_initialized(client, args).await?;

    let seal_status = client.seal_status().await?;
    if seal_status.sealed {
        if unseal_keys.is_empty() {
            unseal_keys = prompt_unseal_keys(seal_status.t, messages)?;
        }
        unseal_openbao(client, &unseal_keys, messages).await?;
    }

    if root_token.is_none() {
        root_token = Some(prompt_text(messages.prompt_openbao_root_token())?);
    }
    let root_token =
        root_token.ok_or_else(|| anyhow::anyhow!(messages.error_openbao_root_token_required()))?;

    client.set_token(root_token.clone());

    Ok(InitBootstrap {
        init_response,
        root_token,
        unseal_keys,
    })
}

fn resolve_init_secrets(args: &InitArgs, messages: &Messages) -> Result<InitSecrets> {
    let stepca_password = resolve_secret(
        messages.prompt_stepca_password(),
        args.stepca_password.clone(),
        args.auto_generate,
    )?;
    let db_dsn = resolve_db_dsn(args, messages)?;
    let http_hmac = resolve_secret(
        messages.prompt_http_hmac(),
        args.http_hmac.clone(),
        args.auto_generate,
    )?;
    let eab = resolve_eab(args, messages)?;

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

async fn unseal_openbao(
    client: &OpenBaoClient,
    keys: &[String],
    messages: &Messages,
) -> Result<()> {
    for key in keys {
        let status = client.unseal(key).await?;
        if !status.sealed {
            return Ok(());
        }
    }
    let status = client.seal_status().await?;
    if status.sealed {
        anyhow::bail!(messages.error_openbao_sealed());
    }
    Ok(())
}

fn prompt_unseal_keys(threshold: Option<u32>, messages: &Messages) -> Result<Vec<String>> {
    let count = match threshold {
        Some(value) if value > 0 => value,
        _ => {
            let input = prompt_text(messages.prompt_unseal_threshold())?;
            input
                .parse::<u32>()
                .context(messages.error_invalid_unseal_threshold())?
        }
    };
    let mut keys = Vec::with_capacity(count as usize);
    for index in 1..=count {
        let key = prompt_text(&messages.prompt_unseal_key(index, count))?;
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

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    let input = prompt_text(prompt)?;
    let trimmed = input.trim().to_ascii_lowercase();
    Ok(trimmed == "y" || trimmed == "yes")
}

fn confirm_overwrite(prompt: &str, messages: &Messages) -> Result<()> {
    if prompt_yes_no(prompt)? {
        return Ok(());
    }
    anyhow::bail!(messages.error_operation_cancelled());
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

fn resolve_eab(args: &InitArgs, messages: &Messages) -> Result<Option<EabCredentials>> {
    match (&args.eab_kid, &args.eab_hmac) {
        (Some(kid), Some(hmac)) => Ok(Some(EabCredentials {
            kid: kid.clone(),
            hmac: hmac.clone(),
        })),
        (None, None) => Ok(None),
        _ => anyhow::bail!(messages.error_eab_requires_both()),
    }
}

async fn verify_responder(
    args: &InitArgs,
    messages: &Messages,
    secrets: &InitSecrets,
) -> Result<ResponderCheck> {
    let Some(responder_url) = args.responder_url.as_deref() else {
        return Ok(ResponderCheck::Skipped);
    };
    responder_client::register_http01_token_with(
        responder_url,
        &secrets.http_hmac,
        args.responder_timeout_secs,
        "bootroot-init-check",
        "bootroot-init-check.key",
        DEFAULT_RESPONDER_TOKEN_TTL_SECS,
    )
    .await
    .with_context(|| messages.error_responder_check_failed())?;
    Ok(ResponderCheck::Ok)
}

async fn check_db_connectivity(db: &DbDsn, timeout_secs: u64, messages: &Messages) -> Result<()> {
    let timeout = std::time::Duration::from_secs(timeout_secs);
    check_tcp(&db.host, db.port, timeout)
        .await
        .with_context(|| messages.error_db_check_failed())?;
    Ok(())
}

async fn maybe_register_eab(
    client: &OpenBaoClient,
    args: &InitArgs,
    messages: &Messages,
    rollback: &mut InitRollback,
    secrets: &InitSecrets,
) -> Result<Option<EabCredentials>> {
    if secrets.eab.is_some() {
        return Ok(None);
    }
    if args.eab_auto {
        let credentials = issue_eab_via_stepca(args)
            .await
            .with_context(|| messages.error_eab_auto_failed())?;
        register_eab_secret(client, &args.kv_mount, rollback, &credentials).await?;
        return Ok(Some(credentials));
    }
    if !prompt_yes_no(messages.prompt_eab_register_now())? {
        return Ok(None);
    }
    if prompt_yes_no(messages.prompt_eab_auto_now())? {
        let credentials = issue_eab_via_stepca(args)
            .await
            .with_context(|| messages.error_eab_auto_failed())?;
        register_eab_secret(client, &args.kv_mount, rollback, &credentials).await?;
        return Ok(Some(credentials));
    }
    println!("{}", messages.eab_prompt_instructions());
    let kid = prompt_text(messages.prompt_eab_kid())?;
    let hmac = prompt_text(messages.prompt_eab_hmac())?;
    let credentials = EabCredentials { kid, hmac };
    register_eab_secret(client, &args.kv_mount, rollback, &credentials).await?;
    Ok(Some(credentials))
}

async fn register_eab_secret(
    client: &OpenBaoClient,
    kv_mount: &str,
    rollback: &mut InitRollback,
    credentials: &EabCredentials,
) -> Result<()> {
    if !client.kv_exists(kv_mount, PATH_AGENT_EAB).await? {
        rollback.written_kv_paths.push(PATH_AGENT_EAB.to_string());
    }
    client
        .write_kv(
            kv_mount,
            PATH_AGENT_EAB,
            serde_json::json!({ "kid": credentials.kid, "hmac": credentials.hmac }),
        )
        .await?;
    Ok(())
}

async fn issue_eab_via_stepca(args: &InitArgs) -> Result<EabCredentials> {
    let base = args.stepca_url.trim_end_matches('/');
    let provisioner = args.stepca_provisioner.trim();
    let endpoint = format!("{base}/acme/{provisioner}/{DEFAULT_EAB_ENDPOINT_PATH}");
    let client = reqwest::Client::new();

    let response = client.post(&endpoint).send().await?;
    let response = if response.status() == StatusCode::METHOD_NOT_ALLOWED {
        client.get(&endpoint).send().await?
    } else {
        response
    };
    let response = response.error_for_status()?;

    let payload: EabAutoResponse = response.json().await?;
    Ok(EabCredentials {
        kid: payload.kid,
        hmac: payload.hmac,
    })
}

fn resolve_db_dsn(args: &InitArgs, messages: &Messages) -> Result<String> {
    if let Some(dsn) = args.db_dsn.clone() {
        return Ok(dsn);
    }
    if let Some(dsn) = build_dsn_from_env() {
        return Ok(dsn);
    }
    prompt_text(&format!("{}: ", messages.prompt_db_dsn()))
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
    secrets_dir: &Path,
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
        secrets_dir: Some(secrets_dir.to_path_buf()),
        policies: policy_map,
        approles: approles
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
        apps: BTreeMap::new(),
    };
    state.save(Path::new("state.json"))?;
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

pub(crate) struct InitSummary {
    pub(crate) openbao_url: String,
    pub(crate) kv_mount: String,
    pub(crate) secrets_dir: PathBuf,
    pub(crate) show_secrets: bool,
    pub(crate) init_response: bool,
    pub(crate) root_token: String,
    pub(crate) unseal_keys: Vec<String>,
    pub(crate) approles: Vec<AppRoleOutput>,
    pub(crate) stepca_password: String,
    pub(crate) db_dsn: String,
    pub(crate) http_hmac: String,
    pub(crate) eab: Option<EabCredentials>,
    pub(crate) step_ca_result: StepCaInitResult,
    pub(crate) responder_check: ResponderCheck,
    pub(crate) db_check: DbCheckStatus,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum DbCheckStatus {
    Skipped,
    Ok,
}

pub(crate) struct InitPlan {
    pub(crate) openbao_url: String,
    pub(crate) kv_mount: String,
    pub(crate) secrets_dir: PathBuf,
    pub(crate) overwrite_password: bool,
    pub(crate) overwrite_ca_json: bool,
    pub(crate) overwrite_state: bool,
}

pub(crate) struct AppRoleOutput {
    pub(crate) label: String,
    pub(crate) role_name: String,
    pub(crate) role_id: String,
    pub(crate) secret_id: String,
}

#[derive(Debug, Clone)]
pub(crate) struct EabCredentials {
    pub(crate) kid: String,
    pub(crate) hmac: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StepCaInitResult {
    Initialized,
    Skipped,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    use tempfile::tempdir;

    use super::*;
    use crate::i18n::Messages;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock")
    }

    fn default_init_args() -> InitArgs {
        InitArgs {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: PathBuf::from("secrets"),
            compose_file: PathBuf::from("docker-compose.yml"),
            auto_generate: false,
            show_secrets: false,
            root_token: None,
            unseal_key: Vec::new(),
            stepca_password: None,
            db_dsn: None,
            db_check: false,
            db_timeout_secs: 2,
            http_hmac: None,
            responder_url: None,
            responder_timeout_secs: 5,
            eab_auto: false,
            stepca_url: DEFAULT_STEPCA_URL.to_string(),
            stepca_provisioner: DEFAULT_STEPCA_PROVISIONER.to_string(),
            eab_kid: None,
            eab_hmac: None,
        }
    }

    fn test_messages() -> Messages {
        Messages::new("en").expect("valid language")
    }

    #[test]
    fn test_resolve_secret_prefers_value() {
        let value = resolve_secret("step-ca password", Some("value".to_string()), false).unwrap();
        assert_eq!(value, "value");
    }

    #[test]
    fn test_resolve_secret_auto_generates() {
        let value = resolve_secret("HTTP-01 HMAC", None, true).unwrap();
        assert!(!value.is_empty());
    }

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
    fn test_resolve_db_dsn_uses_env() {
        let _guard = env_lock();
        // SAFETY: tests run single-threaded for this scope; vars are restored below.
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
    fn test_step_ca_init_skips_when_files_present() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(secrets_dir.join("config")).unwrap();
        fs::create_dir_all(secrets_dir.join("secrets")).unwrap();
        fs::write(
            secrets_dir.join("config").join("ca.json"),
            r#"{"db":{"type":"","dataSource":""}}"#,
        )
        .unwrap();
        fs::write(secrets_dir.join("secrets").join("root_ca_key"), "").unwrap();
        fs::write(secrets_dir.join("secrets").join("intermediate_ca_key"), "").unwrap();

        let result = ensure_step_ca_initialized(&secrets_dir).unwrap();
        assert_eq!(result, StepCaInitResult::Skipped);
    }

    #[test]
    fn test_step_ca_init_requires_password_when_missing_files() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();

        let err = ensure_step_ca_initialized(&secrets_dir).unwrap_err();
        assert!(err.to_string().contains("step-ca password file not found"));
    }

    #[test]
    fn test_build_policy_map_contains_paths() {
        let policies = build_policy_map("secret");
        let agent_policy = policies.get(POLICY_BOOTROOT_AGENT).unwrap();
        assert!(agent_policy.contains("secret/data/bootroot/agent/eab"));
        assert!(agent_policy.contains("secret/data/bootroot/responder/hmac"));
    }
}
