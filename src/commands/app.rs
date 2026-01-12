use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::fs;

use crate::AppAddArgs;
use crate::AppInfoArgs;
use crate::commands::init::{SECRET_ID_TTL, TOKEN_TTL};
use crate::i18n::Messages;
use crate::state::{AppEntry, AppRoleEntry, DeployType, StateFile};
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;

const STATE_FILE_NAME: &str = "state.json";
const APPROLE_PREFIX: &str = "bootroot-app-";

pub(crate) async fn run_app_add(args: &AppAddArgs, messages: &Messages) -> Result<()> {
    let state_path = Path::new(STATE_FILE_NAME);
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let mut state = StateFile::load(state_path)?;

    if state.apps.contains_key(&args.app_kind) {
        anyhow::bail!(messages.error_app_duplicate(&args.app_kind));
    }

    let root_token = args
        .root_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!(messages.error_root_token_required()))?;

    let mut client = OpenBaoClient::new(&state.openbao_url)?;
    client.set_token(root_token);
    client.ensure_approle_auth().await?;

    let policy_name = format!("{APPROLE_PREFIX}{}", args.app_kind);
    let policy = build_app_policy(&state.kv_mount, &args.app_kind);
    client.write_policy(&policy_name, &policy).await?;

    let role_name = format!("{APPROLE_PREFIX}{}", args.app_kind);
    client
        .create_approle(
            &role_name,
            &[policy_name.clone()],
            TOKEN_TTL,
            SECRET_ID_TTL,
            true,
        )
        .await?;
    let role_id = client.read_role_id(&role_name).await?;
    let secret_id = client.create_secret_id(&role_name).await?;

    let secrets_dir = state.secrets_dir();
    let secret_id_path = write_secret_id_file(&secrets_dir, &args.app_kind, &secret_id).await?;

    let entry = AppEntry {
        app_kind: args.app_kind.clone(),
        deploy_type: args.deploy_type,
        hostname: args.hostname.clone(),
        notes: args.notes.clone(),
        approle: AppRoleEntry {
            role_name,
            role_id: role_id.clone(),
            secret_id_path: secret_id_path.clone(),
            policy_name,
        },
    };

    state.apps.insert(args.app_kind.clone(), entry.clone());
    state.save(state_path)?;

    print_app_add_summary(&entry, &secret_id_path, messages);
    Ok(())
}

pub(crate) async fn run_app_info(args: &AppInfoArgs, messages: &Messages) -> Result<()> {
    let state_path = Path::new(STATE_FILE_NAME);
    if !state_path.exists() {
        anyhow::bail!(messages.error_state_missing());
    }
    let state = StateFile::load(state_path)?;
    let entry = state
        .apps
        .get(&args.app_kind)
        .ok_or_else(|| anyhow::anyhow!(messages.error_app_not_found(&args.app_kind)))?;
    print_app_info_summary(entry, messages);
    Ok(())
}

fn build_app_policy(kv_mount: &str, app_kind: &str) -> String {
    let base = format!("bootroot/apps/{app_kind}");
    format!(
        r#"path "{kv_mount}/data/{base}/*" {{
  capabilities = ["read"]
}}
path "{kv_mount}/metadata/{base}/*" {{
  capabilities = ["list"]
}}
"#
    )
}

async fn write_secret_id_file(
    secrets_dir: &Path,
    app_kind: &str,
    secret_id: &str,
) -> Result<PathBuf> {
    let app_dir = secrets_dir.join("apps").join(app_kind);
    fs_util::ensure_secrets_dir(&app_dir).await?;
    let secret_path = app_dir.join("secret_id");
    fs::write(&secret_path, secret_id)
        .await
        .with_context(|| format!("Failed to write {}", secret_path.display()))?;
    fs_util::set_key_permissions(&secret_path).await?;
    Ok(secret_path)
}

fn print_app_add_summary(entry: &AppEntry, secret_id_path: &Path, messages: &Messages) {
    println!("{}", messages.app_add_summary());
    print_app_fields(entry, messages);
    println!("{}", messages.app_summary_policy(&entry.approle.policy_name));
    println!("{}", messages.app_summary_approle(&entry.approle.role_name));
    println!("{}", messages.summary_role_id(&entry.approle.role_id));
    println!("{}", messages.app_summary_secret_path(&secret_id_path.display().to_string()));
    println!("{}", messages.app_summary_next_steps());
    println!(
        "{}",
        messages.app_next_steps_use_approle(&entry.approle.role_name)
    );
}

fn print_app_info_summary(entry: &AppEntry, messages: &Messages) {
    println!("{}", messages.app_info_summary());
    print_app_fields(entry, messages);
    println!("{}", messages.app_summary_policy(&entry.approle.policy_name));
    println!("{}", messages.app_summary_approle(&entry.approle.role_name));
    println!("{}", messages.summary_role_id(&entry.approle.role_id));
    println!("{}", messages.app_summary_secret_path_hidden());
}

fn print_app_fields(entry: &AppEntry, messages: &Messages) {
    println!("{}", messages.app_summary_kind(&entry.app_kind));
    println!(
        "{}",
        messages.app_summary_deploy_type(match entry.deploy_type {
            DeployType::Daemon => "daemon",
            DeployType::Docker => "docker",
        })
    );
    println!("{}", messages.app_summary_hostname(&entry.hostname));
    if let Some(notes) = entry.notes.as_deref() {
        println!("{}", messages.app_summary_notes(notes));
    }
}
