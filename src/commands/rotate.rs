use std::collections::HashSet;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;
use bootroot::{db, fs_util};
use reqwest::StatusCode;
use tracing::warn;

use crate::cli::args::{
    RotateAppRoleSecretIdArgs, RotateArgs, RotateCommand, RotateDbArgs, RotateEabArgs,
    RotateResponderHmacArgs, RotateStepcaPasswordArgs,
};
use crate::cli::prompt::Prompt;
use crate::commands::infra::run_docker;
use crate::commands::init::{
    PATH_AGENT_EAB, PATH_RESPONDER_HMAC, PATH_STEPCA_DB, PATH_STEPCA_PASSWORD,
};
use crate::i18n::Messages;
use crate::state::{AppEntry, StateFile};
const SECRET_BYTES: usize = 32;
const OPENBAO_AGENT_CONTAINER_PREFIX: &str = "bootroot-openbao-agent";
const ROLE_ID_FILENAME: &str = "role_id";

#[derive(Debug, Clone)]
struct StatePaths {
    state_file: PathBuf,
    secrets_dir: PathBuf,
}

impl StatePaths {
    fn new(state_file: PathBuf, secrets_dir: PathBuf) -> Self {
        Self {
            state_file,
            secrets_dir,
        }
    }

    fn state_file(&self) -> &Path {
        &self.state_file
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
}

#[derive(Debug)]
struct RotateContext {
    openbao_url: String,
    kv_mount: String,
    compose_file: PathBuf,
    root_token: String,
    state: StateFile,
    paths: StatePaths,
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
    let paths = StatePaths::new(state_path, secrets_dir.clone());
    let root_token = resolve_root_token(args.root_token.root_token.clone(), messages)?;
    let ctx = RotateContext {
        openbao_url,
        kv_mount,
        compose_file: args.compose.compose_file.clone(),
        root_token,
        state,
        paths,
    };
    let _state_file = ctx.paths.state_file();

    let mut client = OpenBaoClient::new(&ctx.openbao_url)
        .with_context(|| messages.error_openbao_client_create_failed())?;
    client.set_token(ctx.root_token.clone());
    client
        .health_check()
        .await
        .with_context(|| messages.error_openbao_health_check_failed())?;

    match &args.command {
        RotateCommand::StepcaPassword(step_args) => {
            rotate_stepca_password(&ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::Eab(step_args) => {
            rotate_eab(&ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::Db(step_args) => {
            rotate_db(&ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::ResponderHmac(step_args) => {
            rotate_responder_hmac(&ctx, &client, step_args, args.yes, messages).await?;
        }
        RotateCommand::AppRoleSecretId(step_args) => {
            rotate_approle_secret_id(&ctx, &client, step_args, args.yes, messages).await?;
        }
    }

    Ok(())
}

async fn rotate_stepca_password(
    ctx: &RotateContext,
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

    write_secret_file(&password_path, &new_password, messages).await?;
    client
        .write_kv(
            &ctx.kv_mount,
            PATH_STEPCA_PASSWORD,
            serde_json::json!({ "value": new_password }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;

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
    ctx: &RotateContext,
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

    let updated = update_agent_configs(&ctx.state.apps, messages, |contents| {
        let updated = upsert_toml_section_keys(
            contents,
            "eab",
            &[("kid", &credentials.kid), ("hmac", &credentials.hmac)],
        );
        upsert_toml_section_keys(
            &updated,
            "profiles.eab",
            &[("kid", &credentials.kid), ("hmac", &credentials.hmac)],
        )
    })?;

    println!("{}", messages.rotate_summary_title());
    println!("{}", messages.summary_eab_kid(&credentials.kid));
    println!("{}", messages.summary_eab_hmac(&credentials.hmac));
    if updated.is_empty() {
        println!("{}", messages.rotate_summary_agent_configs_skipped());
    } else {
        println!(
            "{}",
            messages.rotate_summary_agent_configs_updated(&updated.join(", "))
        );
    }
    println!("{}", messages.rotate_summary_reload_agent());
    Ok(())
}

async fn rotate_db(
    ctx: &RotateContext,
    client: &OpenBaoClient,
    args: &RotateDbArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(messages.prompt_rotate_db(), auto_confirm, messages)?;

    let admin_dsn = resolve_db_admin_dsn(args, messages)?;
    let db_password = match args.password.clone() {
        Some(value) => value,
        None => generate_secret(messages)?,
    };
    let ca_json_path = ctx.paths.ca_json();
    let current_dsn = read_ca_json_dsn(&ca_json_path, messages)?;
    let parsed = db::parse_db_dsn(&current_dsn).with_context(|| messages.error_invalid_db_dsn())?;
    let timeout = Duration::from_secs(args.timeout.timeout_secs);
    db::provision_db_sync(
        &admin_dsn,
        &parsed.user,
        &db_password,
        &parsed.database,
        timeout,
    )
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
            serde_json::json!({ "dsn": new_dsn }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;
    write_ca_json_dsn(&ca_json_path, &new_dsn, messages)?;

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
    ctx: &RotateContext,
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

    let responder_path = ctx.paths.responder_config();
    let config = if responder_path.exists() {
        let contents = fs::read_to_string(&responder_path).with_context(|| {
            messages.error_read_file_failed(&responder_path.display().to_string())
        })?;
        update_responder_hmac(&contents, &hmac)
    } else {
        build_responder_config(&hmac)
    };
    write_secret_file(&responder_path, &config, messages).await?;

    let updated = update_agent_configs(&ctx.state.apps, messages, |contents| {
        upsert_toml_section_keys(contents, "acme", &[("http_responder_hmac", &hmac)])
    })?;

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
    if updated.is_empty() {
        println!("{}", messages.rotate_summary_agent_configs_skipped());
    } else {
        println!(
            "{}",
            messages.rotate_summary_agent_configs_updated(&updated.join(", "))
        );
    }
    if reloaded {
        println!("{}", messages.rotate_summary_reload_responder());
    }
    Ok(())
}

async fn rotate_approle_secret_id(
    ctx: &RotateContext,
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
        .apps
        .get(&args.service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_app_not_found(&args.service_name)))?;
    ensure_role_id_file(entry, client, messages).await?;
    let new_secret_id = client
        .create_secret_id(&entry.approle.role_name)
        .await
        .with_context(|| messages.error_openbao_secret_id_failed())?;
    write_secret_id_atomic(&entry.approle.secret_id_path, &new_secret_id, messages).await?;
    reload_openbao_agent(entry, messages)?;
    client
        .login_approle(&entry.approle.role_id, &new_secret_id)
        .await
        .with_context(|| messages.error_openbao_approle_login_failed())?;

    println!("{}", messages.rotate_summary_title());
    // codeql[rust/cleartext-logging]: output is a secret_id file path, not the secret value.
    println!(
        "{}",
        messages.rotate_summary_approle_secret_id(
            &args.service_name,
            &entry.approle.secret_id_path.display().to_string()
        )
    );
    println!("{}", messages.rotate_summary_reload_openbao_agent());
    println!(
        "{}",
        messages.rotate_summary_approle_login_ok(&args.service_name)
    );
    Ok(())
}

async fn ensure_role_id_file(
    entry: &AppEntry,
    client: &OpenBaoClient,
    messages: &Messages,
) -> Result<()> {
    let app_dir = entry
        .approle
        .secret_id_path
        .parent()
        .unwrap_or(Path::new("."));
    let role_id_path = app_dir.join(ROLE_ID_FILENAME);
    if role_id_path.exists() {
        return Ok(());
    }
    let role_id = client
        .read_role_id(&entry.approle.role_name)
        .await
        .with_context(|| messages.error_openbao_role_id_failed())?;
    fs_util::ensure_secrets_dir(app_dir).await?;
    tokio::fs::write(&role_id_path, role_id)
        .await
        .with_context(|| messages.error_write_file_failed(&role_id_path.display().to_string()))?;
    fs_util::set_key_permissions(&role_id_path).await?;
    Ok(())
}

fn resolve_root_token(value: Option<String>, messages: &Messages) -> Result<String> {
    if let Some(value) = value {
        return Ok(value);
    }
    let mut input = std::io::stdin().lock();
    let mut output = std::io::stdout();
    let mut prompt = Prompt::new(&mut input, &mut output, messages);
    let label = messages.prompt_openbao_root_token().trim_end_matches(": ");
    prompt.prompt_with_validation(label, None, |value| ensure_non_empty(value, messages))
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
    ];
    let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
    run_docker(&args_ref, "docker step-ca change-pass", messages)?;
    Ok(())
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

fn write_ca_json_dsn(path: &Path, dsn: &str, messages: &Messages) -> Result<()> {
    let contents = fs::read_to_string(path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&contents).context(messages.error_parse_ca_json_failed())?;
    let db = value
        .get_mut("db")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    let data_source = db
        .get_mut("dataSource")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    *data_source = serde_json::Value::String(dsn.to_string());
    let updated =
        serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())?;
    fs::write(path, updated)
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))
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

fn build_responder_config(hmac: &str) -> String {
    format!(
        r#"# HTTP-01 responder config (rendered)

listen_addr = "0.0.0.0:80"
admin_addr = "0.0.0.0:8080"
hmac_secret = "{hmac}"
token_ttl_secs = 300
cleanup_interval_secs = 30
max_skew_secs = 60
"#
    )
}

fn update_responder_hmac(contents: &str, hmac: &str) -> String {
    let mut output = String::new();
    let mut updated = false;
    for line in contents.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("hmac_secret") && trimmed.contains('=') {
            let indent = line
                .chars()
                .take_while(|ch| ch.is_whitespace())
                .collect::<String>();
            let _ = writeln!(output, "{indent}hmac_secret = \"{hmac}\"");
            updated = true;
        } else {
            output.push_str(line);
            output.push('\n');
        }
    }
    if !updated {
        let _ = writeln!(output, "hmac_secret = \"{hmac}\"");
    }
    output
}

fn update_agent_configs<F>(
    apps: &std::collections::BTreeMap<String, AppEntry>,
    messages: &Messages,
    mut update: F,
) -> Result<Vec<String>>
where
    F: FnMut(&str) -> String,
{
    let mut updated = Vec::new();
    let mut seen = HashSet::new();
    for entry in apps.values() {
        if !seen.insert(entry.agent_config_path.clone()) {
            continue;
        }
        let contents = fs::read_to_string(&entry.agent_config_path).with_context(|| {
            messages.error_read_file_failed(&entry.agent_config_path.display().to_string())
        })?;
        let next = update(&contents);
        if next != contents {
            fs::write(&entry.agent_config_path, next).with_context(|| {
                messages.error_write_file_failed(&entry.agent_config_path.display().to_string())
            })?;
            updated.push(entry.agent_config_path.display().to_string());
        }
    }
    Ok(updated)
}

fn upsert_toml_section_keys(contents: &str, section: &str, pairs: &[(&str, &str)]) -> String {
    let mut output = String::new();
    let mut section_found = false;
    let mut in_section = false;
    let mut seen_keys = HashSet::new();

    for line in contents.lines() {
        let trimmed = line.trim();
        if is_section_header(trimmed) {
            if in_section {
                output.push_str(&render_missing_keys(pairs, &seen_keys));
            }
            in_section = trimmed == format!("[{section}]");
            if in_section {
                section_found = true;
                seen_keys.clear();
            }
            output.push_str(line);
            output.push('\n');
            continue;
        }

        if in_section && let Some((key, indent)) = parse_key_line(line, pairs) {
            let value = pairs.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
            if let Some(value) = value {
                let _ = writeln!(output, "{indent}{key} = \"{value}\"");
                seen_keys.insert(key.to_string());
                continue;
            }
        }
        output.push_str(line);
        output.push('\n');
    }

    if in_section {
        output.push_str(&render_missing_keys(pairs, &seen_keys));
    }

    if !section_found {
        output.push('\n');
        let _ = writeln!(output, "[{section}]");
        for (key, value) in pairs {
            let _ = writeln!(output, "{key} = \"{value}\"");
        }
    }
    output
}

fn parse_key_line<'a>(line: &'a str, pairs: &[(&'a str, &str)]) -> Option<(&'a str, String)> {
    for (key, _) in pairs {
        let prefix = format!("{key} ");
        let trimmed = line.trim_start();
        if trimmed.starts_with(&prefix) || trimmed.starts_with(&format!("{key}=")) {
            let indent = line
                .chars()
                .take_while(|ch| ch.is_whitespace())
                .collect::<String>();
            return Some((key, indent));
        }
    }
    None
}

fn render_missing_keys(pairs: &[(&str, &str)], seen: &HashSet<String>) -> String {
    let mut rendered = String::new();
    for (key, value) in pairs {
        if !seen.contains(*key) {
            let _ = writeln!(rendered, "{key} = \"{value}\"");
        }
    }
    rendered
}

fn is_section_header(line: &str) -> bool {
    line.starts_with('[') && line.ends_with(']')
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

fn reload_openbao_agent(entry: &AppEntry, messages: &Messages) -> Result<()> {
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
fn reload_openbao_agent_daemon(entry: &AppEntry, messages: &Messages) -> Result<()> {
    let config_path = entry.agent_config_path.display().to_string();
    let status = std::process::Command::new("pkill")
        .args(["-HUP", "-f", &config_path])
        .status()
        .with_context(|| messages.error_command_run_failed("pkill -HUP"))?;
    if !status.success() {
        // Exit code 1 means no processes matched (agent not running).
        // Treat this as a warning since the secret_id rotation itself succeeded.
        if status.code() == Some(1) {
            warn!("{}", messages.warning_openbao_agent_not_running());
        } else {
            anyhow::bail!(messages.error_command_failed_status("pkill -HUP", &status.to_string()));
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn reload_openbao_agent_daemon(_entry: &AppEntry, messages: &Messages) -> Result<()> {
    anyhow::bail!(messages.error_command_run_failed("pkill -HUP"));
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

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    use tempfile::tempdir;

    use super::*;

    fn test_messages() -> Messages {
        Messages::new("en").expect("valid language")
    }

    #[test]
    fn upsert_toml_section_keys_updates_existing() {
        let input = "[acme]\nhttp_responder_hmac = \"old\"\n";
        let updated = upsert_toml_section_keys(input, "acme", &[("http_responder_hmac", "new")]);
        assert!(updated.contains("http_responder_hmac = \"new\""));
    }

    #[test]
    fn upsert_toml_section_keys_adds_missing_section() {
        let input = "email = \"a@b\"";
        let updated = upsert_toml_section_keys(input, "eab", &[("kid", "k"), ("hmac", "h")]);
        assert!(updated.contains("[eab]"));
        assert!(updated.contains("kid = \"k\""));
        assert!(updated.contains("hmac = \"h\""));
    }

    #[test]
    fn update_responder_hmac_replaces_value() {
        let input = "listen_addr = \"0.0.0.0:80\"\nhmac_secret = \"old\"\n";
        let updated = update_responder_hmac(input, "new");
        assert!(updated.contains("hmac_secret = \"new\""));
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
}
