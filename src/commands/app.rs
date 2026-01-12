use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;
use tokio::fs;

use crate::AppAddArgs;
use crate::AppInfoArgs;
use crate::cli::output::{print_app_add_summary, print_app_info_summary};
use crate::commands::init::{SECRET_ID_TTL, TOKEN_TTL};
use crate::i18n::Messages;
use crate::state::{AppEntry, AppRoleEntry, StateFile};

const STATE_FILE_NAME: &str = "state.json";
const APPROLE_PREFIX: &str = "bootroot-app-";
const APP_KV_BASE: &str = "bootroot/apps";
const APP_SECRET_DIR: &str = "apps";
const APP_SECRET_ID_FILENAME: &str = "secret_id";

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
        .ok_or_else(|| anyhow::anyhow!(messages.error_openbao_root_token_required()))?;

    let mut client = OpenBaoClient::new(&state.openbao_url)?;
    client.set_token(root_token);
    client.ensure_approle_auth().await?;

    let approle = ensure_app_approle(&client, &state, &args.app_kind).await?;
    let secrets_dir = state.secrets_dir();
    let secret_id_path =
        write_secret_id_file(&secrets_dir, &args.app_kind, &approle.secret_id).await?;

    let entry = AppEntry {
        app_kind: args.app_kind.clone(),
        deploy_type: args.deploy_type,
        hostname: args.hostname.clone(),
        notes: args.notes.clone(),
        approle: AppRoleEntry {
            role_name: approle.role_name,
            role_id: approle.role_id,
            secret_id_path: secret_id_path.clone(),
            policy_name: approle.policy_name,
        },
    };

    state.apps.insert(args.app_kind.clone(), entry.clone());
    state.save(state_path)?;

    print_app_add_summary(&entry, &secret_id_path, messages);
    Ok(())
}

pub(crate) fn run_app_info(args: &AppInfoArgs, messages: &Messages) -> Result<()> {
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
    let base = format!("{APP_KV_BASE}/{app_kind}");
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
    let app_dir = secrets_dir.join(APP_SECRET_DIR).join(app_kind);
    fs_util::ensure_secrets_dir(&app_dir).await?;
    let secret_path = app_dir.join(APP_SECRET_ID_FILENAME);
    fs::write(&secret_path, secret_id)
        .await
        .with_context(|| format!("Failed to write {}", secret_path.display()))?;
    fs_util::set_key_permissions(&secret_path).await?;
    Ok(secret_path)
}

struct AppRoleMaterialized {
    role_name: String,
    role_id: String,
    secret_id: String,
    policy_name: String,
}

async fn ensure_app_approle(
    client: &OpenBaoClient,
    state: &StateFile,
    app_kind: &str,
) -> Result<AppRoleMaterialized> {
    let policy_name = app_policy_name(app_kind);
    let policy = build_app_policy(&state.kv_mount, app_kind);
    client.write_policy(&policy_name, &policy).await?;

    let role_name = app_role_name(app_kind);
    client
        .create_approle(
            &role_name,
            std::slice::from_ref(&policy_name),
            TOKEN_TTL,
            SECRET_ID_TTL,
            true,
        )
        .await?;
    let role_id = client.read_role_id(&role_name).await?;
    let secret_id = client.create_secret_id(&role_name).await?;
    Ok(AppRoleMaterialized {
        role_name,
        role_id,
        secret_id,
        policy_name,
    })
}

fn app_role_name(app_kind: &str) -> String {
    format!("{APPROLE_PREFIX}{app_kind}")
}

fn app_policy_name(app_kind: &str) -> String {
    format!("{APPROLE_PREFIX}{app_kind}")
}
