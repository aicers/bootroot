use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::{OpenBaoClient, SecretIdOptions};

use super::helpers::{
    confirm_action, reload_openbao_agent, restart_container, write_secret_id_atomic,
};
use super::{
    OPENBAO_AGENT_RESPONDER_CONTAINER, OPENBAO_AGENT_STEPCA_CONTAINER, ROLE_ID_FILENAME,
    RotateContext,
};
use crate::cli::args::{InfraRoleTarget, RotateAppRoleSecretIdArgs};
use crate::cli::output::display_secret;
use crate::commands::constants::{SERVICE_KV_BASE, SERVICE_SECRET_ID_KEY};
use crate::commands::init::{
    APPROLE_BOOTROOT_INFRA_ROTATE, APPROLE_BOOTROOT_RESPONDER, APPROLE_BOOTROOT_STEPCA,
    AppRoleLabel, OPENBAO_AGENT_DIR, OPENBAO_AGENT_RESPONDER_DIR, OPENBAO_AGENT_ROLE_ID_NAME,
    OPENBAO_AGENT_SECRET_ID_NAME, OPENBAO_AGENT_STEPCA_DIR, POLICY_BOOTROOT_INFRA_ROTATE,
    SECRET_ID_TTL, TOKEN_TTL, infra_rotate_policy,
};
use crate::commands::service::resolve::effective_wrap_ttl;
use crate::i18n::Messages;
use crate::state::{DeliveryMode, ServiceEntry};

pub(super) async fn rotate_approle_secret_id(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateAppRoleSecretIdArgs,
    auto_confirm: bool,
    is_root_auth: bool,
    show_secrets: bool,
    messages: &Messages,
) -> Result<()> {
    if let Some(target) = args.infra {
        return rotate_infra_approle_secret_id(
            ctx,
            client,
            target,
            auto_confirm,
            is_root_auth,
            show_secrets,
            messages,
        )
        .await;
    }
    let service_name = args.service_name.as_deref().ok_or_else(|| {
        // clap's ArgGroup guarantees one selector is present; guard for
        // callers that construct the args directly.
        anyhow::anyhow!(messages.error_value_required())
    })?;
    rotate_service_approle_secret_id(ctx, client, service_name, auto_confirm, messages).await
}

async fn rotate_service_approle_secret_id(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    service_name: &str,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    confirm_action(
        &messages.prompt_rotate_approle_secret_id(service_name),
        auto_confirm,
        messages,
    )?;

    let entry = ctx
        .state
        .services
        .get(service_name)
        .ok_or_else(|| anyhow::anyhow!(messages.error_service_not_found(service_name)))?
        .clone();
    let is_remote = matches!(entry.delivery_mode, DeliveryMode::RemoteBootstrap);
    if !is_remote {
        ensure_role_id_file(&entry, client, messages).await?;
    }
    let secret_id_options = SecretIdOptions {
        ttl: entry.approle.secret_id_ttl.clone(),
        num_uses: Some(0),
        metadata: None,
        token_bound_cidrs: entry.approle.token_bound_cidrs.clone(),
    };
    let wrap_ttl = effective_wrap_ttl(entry.approle.secret_id_wrap_ttl.as_deref());
    let new_secret_id = match wrap_ttl {
        Some(ttl) => {
            client
                .create_secret_id_wrapped(&entry.approle.role_name, &secret_id_options, ttl)
                .await
        }
        None => {
            client
                .create_secret_id(&entry.approle.role_name, &secret_id_options)
                .await
        }
    }
    .with_context(|| messages.error_openbao_secret_id_failed())?;
    if !is_remote {
        write_secret_id_atomic(&entry.approle.secret_id_path, &new_secret_id, messages).await?;
        reload_openbao_agent(&entry, messages)?;
    }
    let has_cidr_binding = entry.approle.token_bound_cidrs.is_some();
    if !has_cidr_binding {
        client
            .login_approle(&entry.approle.role_id, &new_secret_id)
            .await
            .with_context(|| messages.error_openbao_approle_login_failed())?;
    }
    if is_remote {
        write_remote_service_secret_id(
            client,
            &ctx.kv_mount,
            service_name,
            &new_secret_id,
            messages,
        )
        .await?;
    }

    println!("{}", messages.rotate_summary_title());
    // CodeQL flags this as cleartext-logging, but the second argument is
    // `secret_id_path` (a file path), not the secret_id value. Dismiss as false positive.
    println!(
        "{}",
        messages.rotate_summary_approle_secret_id(
            service_name,
            &entry.approle.secret_id_path.display().to_string()
        )
    );
    if !is_remote {
        println!("{}", messages.rotate_summary_reload_openbao_agent());
    }
    if !has_cidr_binding {
        println!("{}", messages.rotate_summary_approle_login_ok(service_name));
    }
    Ok(())
}

fn infra_role_name(target: InfraRoleTarget) -> &'static str {
    match target {
        InfraRoleTarget::Stepca => APPROLE_BOOTROOT_STEPCA,
        InfraRoleTarget::Responder => APPROLE_BOOTROOT_RESPONDER,
    }
}

fn infra_agent_dir(ctx: &RotateContext, target: InfraRoleTarget) -> PathBuf {
    let agent_dir = match target {
        InfraRoleTarget::Stepca => OPENBAO_AGENT_STEPCA_DIR,
        InfraRoleTarget::Responder => OPENBAO_AGENT_RESPONDER_DIR,
    };
    ctx.paths
        .secrets_dir()
        .join(OPENBAO_AGENT_DIR)
        .join(agent_dir)
}

fn infra_agent_container(target: InfraRoleTarget) -> &'static str {
    match target {
        InfraRoleTarget::Stepca => OPENBAO_AGENT_STEPCA_CONTAINER,
        InfraRoleTarget::Responder => OPENBAO_AGENT_RESPONDER_CONTAINER,
    }
}

async fn rotate_infra_approle_secret_id(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    target: InfraRoleTarget,
    auto_confirm: bool,
    is_root_auth: bool,
    show_secrets: bool,
    messages: &Messages,
) -> Result<()> {
    let role_name = infra_role_name(target);
    confirm_action(
        &messages.prompt_rotate_infra_approle_secret_id(role_name),
        auto_confirm,
        messages,
    )?;

    // Upgrade path: deployments initialized before the dedicated
    // infra-rotate credential existed can provision it by running this
    // command with the root token. The provisioning is idempotent, so
    // re-running recovers a partial earlier attempt and reissues the
    // operator credential. AppRole-authenticated runs skip this entirely
    // (single-auth model: the resolved credential is the only one the
    // command ever uses).
    if is_root_auth {
        provision_infra_rotate_role(ctx, client, show_secrets, messages).await?;
    }

    let agent_dir = infra_agent_dir(ctx, target);
    let secret_id_path = agent_dir.join(OPENBAO_AGENT_SECRET_ID_NAME);
    let role_id = ensure_infra_role_id_file(&agent_dir, role_name, client, messages).await?;

    let secret_id_options = SecretIdOptions {
        ttl: None,
        num_uses: Some(0),
        metadata: None,
        token_bound_cidrs: None,
    };
    let new_secret_id = client
        .create_secret_id(role_name, &secret_id_options)
        .await
        .with_context(|| messages.error_infra_secret_id_mint_failed(role_name))?;
    write_secret_id_atomic(&secret_id_path, &new_secret_id, messages).await?;
    let container = infra_agent_container(target);
    restart_container(container, messages)?;
    // The infra roles carry no CIDR binding, so the post-rotation login
    // verification is unconditional (unlike the service flow).
    client
        .login_approle(&role_id, &new_secret_id)
        .await
        .with_context(|| messages.error_openbao_approle_login_failed())?;

    println!("{}", messages.rotate_summary_title());
    // The second argument is the secret_id file path, not the secret value.
    println!(
        "{}",
        messages.rotate_summary_infra_approle_secret_id(
            role_name,
            &secret_id_path.display().to_string()
        )
    );
    println!(
        "{}",
        messages.rotate_summary_infra_agent_restarted(container)
    );
    println!(
        "{}",
        messages.rotate_summary_infra_approle_login_ok(role_name)
    );
    Ok(())
}

/// Reads the infra agent's on-disk `role_id`, backfilling the file from
/// `OpenBao` when it is missing (mirrors the service flow's
/// `ensure_role_id_file`).
async fn ensure_infra_role_id_file(
    agent_dir: &Path,
    role_name: &str,
    client: &OpenBaoClient,
    messages: &Messages,
) -> Result<String> {
    let role_id_path = agent_dir.join(OPENBAO_AGENT_ROLE_ID_NAME);
    if let Ok(existing) = tokio::fs::read_to_string(&role_id_path).await {
        let trimmed = existing.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    let role_id = client
        .read_role_id(role_name)
        .await
        .with_context(|| messages.error_openbao_role_id_failed())?;
    fs_util::ensure_secrets_dir(agent_dir).await?;
    tokio::fs::write(&role_id_path, &role_id)
        .await
        .with_context(|| messages.error_write_file_failed(&role_id_path.display().to_string()))?;
    fs_util::set_key_permissions(&role_id_path).await?;
    Ok(role_id)
}

/// Ensures the `bootroot-infra-rotate` policy and `AppRole` are present
/// and current, backfills missing `state.json` entries, and prints a
/// freshly minted operator credential (masked unless `--show-secrets`).
///
/// Every step is idempotent (`write_policy` and `create_approle` are
/// create-or-update), so a partial earlier provisioning — role created
/// but policy/state/credential lost before the run completed — is
/// recovered by simply re-running the root-token path. A fresh
/// `secret_id` is minted on every run, which also serves as the recovery
/// path for a lost operator credential.
async fn provision_infra_rotate_role(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    show_secrets: bool,
    messages: &Messages,
) -> Result<()> {
    client
        .write_policy(POLICY_BOOTROOT_INFRA_ROTATE, &infra_rotate_policy())
        .await
        .with_context(|| messages.error_openbao_policy_write_failed())?;
    client
        .create_approle(
            APPROLE_BOOTROOT_INFRA_ROTATE,
            &[POLICY_BOOTROOT_INFRA_ROTATE],
            TOKEN_TTL,
            SECRET_ID_TTL,
            true,
        )
        .await
        .with_context(|| messages.error_openbao_approle_create_failed())?;
    let role_id = client
        .read_role_id(APPROLE_BOOTROOT_INFRA_ROTATE)
        .await
        .with_context(|| messages.error_openbao_role_id_failed())?;
    let secret_id = client
        .create_secret_id(APPROLE_BOOTROOT_INFRA_ROTATE, &SecretIdOptions::default())
        .await
        .with_context(|| messages.error_openbao_secret_id_failed())?;

    let label = AppRoleLabel::InfraRotate.to_string();
    let prev_approle = ctx
        .state
        .approles
        .insert(label.clone(), APPROLE_BOOTROOT_INFRA_ROTATE.to_string());
    let prev_policy = ctx
        .state
        .policies
        .insert(label, POLICY_BOOTROOT_INFRA_ROTATE.to_string());
    if prev_approle.as_deref() != Some(APPROLE_BOOTROOT_INFRA_ROTATE)
        || prev_policy.as_deref() != Some(POLICY_BOOTROOT_INFRA_ROTATE)
    {
        ctx.state
            .save(&ctx.state_file)
            .with_context(|| messages.error_serialize_state_failed())?;
    }

    println!(
        "{}",
        messages.rotate_infra_provisioned_role(
            APPROLE_BOOTROOT_INFRA_ROTATE,
            POLICY_BOOTROOT_INFRA_ROTATE
        )
    );
    println!(
        "{}",
        messages.rotate_infra_provisioned_role_id(APPROLE_BOOTROOT_INFRA_ROTATE, &role_id)
    );
    println!(
        "{}",
        messages.rotate_infra_provisioned_secret_id(
            APPROLE_BOOTROOT_INFRA_ROTATE,
            &display_secret(&secret_id, show_secrets)
        )
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

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::PathBuf;

    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::super::test_support::{
        ScopedEnvVar, TEST_DOCKER_ARGS_ENV, env_lock, path_with_prepend, test_messages,
        write_fake_docker_script,
    };
    use super::*;
    use crate::state::StateFile;

    fn make_ctx(dir: &std::path::Path) -> RotateContext {
        RotateContext {
            openbao_url: String::new(),
            kv_mount: "secret".to_string(),
            compose_file: PathBuf::new(),
            state: StateFile {
                openbao_url: String::new(),
                kv_mount: "secret".to_string(),
                secrets_dir: None,
                policies: BTreeMap::new(),
                approles: BTreeMap::new(),
                services: BTreeMap::new(),
                openbao_bind_addr: None,
                openbao_advertise_addr: None,
                http01_admin_bind_addr: None,
                http01_admin_advertise_addr: None,
                stepca_bind_addr: None,
                stepca_advertise_addr: None,
                infra_certs: BTreeMap::new(),
            },
            paths: super::super::StatePaths::new(dir.join("secrets")),
            state_dir: dir.to_path_buf(),
            state_file: dir.join("state.json"),
        }
    }

    fn mount_secret_id_mock(role: &str) -> Mock {
        Mock::given(method("POST"))
            .and(path(format!("/v1/auth/approle/role/{role}/secret-id")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "secret_id": "fresh-secret-id" }
            })))
    }

    fn mount_login_mock() -> Mock {
        Mock::given(method("POST"))
            .and(path("/v1/auth/approle/login"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "auth": { "client_token": "verified-token" }
            })))
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn rotate_infra_writes_secret_id_restarts_agent_and_verifies_login() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        mount_secret_id_mock(APPROLE_BOOTROOT_STEPCA)
            .expect(1)
            .mount(&server)
            .await;
        mount_login_mock().expect(1).mount(&server).await;

        let mut ctx = make_ctx(dir.path());
        let stepca_dir = ctx
            .paths
            .secrets_dir()
            .join(OPENBAO_AGENT_DIR)
            .join(OPENBAO_AGENT_STEPCA_DIR);
        fs::create_dir_all(&stepca_dir).expect("create agent dir");
        fs::write(
            stepca_dir.join(OPENBAO_AGENT_ROLE_ID_NAME),
            "stepca-role-id\n",
        )
        .expect("write role_id");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("scoped-token".to_string());
        let messages = test_messages();
        rotate_infra_approle_secret_id(
            &mut ctx,
            &client,
            InfraRoleTarget::Stepca,
            true,
            false,
            false,
            &messages,
        )
        .await
        .expect("infra rotation should succeed");

        let secret_id_path = stepca_dir.join(OPENBAO_AGENT_SECRET_ID_NAME);
        let contents = fs::read_to_string(&secret_id_path).expect("read secret_id");
        assert_eq!(contents, "fresh-secret-id");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&secret_id_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
        let logged = fs::read_to_string(&args_log).expect("read docker args");
        let args: Vec<&str> = logged.lines().collect();
        assert_eq!(args, vec!["restart", OPENBAO_AGENT_STEPCA_CONTAINER]);
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn rotate_infra_backfills_missing_role_id_file() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_RESPONDER}/role-id"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "role_id": "responder-role-id" }
            })))
            .expect(1)
            .mount(&server)
            .await;
        mount_secret_id_mock(APPROLE_BOOTROOT_RESPONDER)
            .mount(&server)
            .await;
        mount_login_mock().mount(&server).await;

        let mut ctx = make_ctx(dir.path());
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("scoped-token".to_string());
        let messages = test_messages();
        rotate_infra_approle_secret_id(
            &mut ctx,
            &client,
            InfraRoleTarget::Responder,
            true,
            false,
            false,
            &messages,
        )
        .await
        .expect("infra rotation should succeed");

        let responder_dir = ctx
            .paths
            .secrets_dir()
            .join(OPENBAO_AGENT_DIR)
            .join(OPENBAO_AGENT_RESPONDER_DIR);
        let role_id = fs::read_to_string(responder_dir.join(OPENBAO_AGENT_ROLE_ID_NAME))
            .expect("role_id backfilled");
        assert_eq!(role_id, "responder-role-id");
        let logged = fs::read_to_string(&args_log).expect("read docker args");
        let args: Vec<&str> = logged.lines().collect();
        assert_eq!(args, vec!["restart", OPENBAO_AGENT_RESPONDER_CONTAINER]);
    }

    // The env-var lock must be held across the `.await` to prevent
    // parallel tests from seeing a corrupted PATH.
    #[allow(clippy::await_holding_lock)]
    #[tokio::test]
    async fn rotate_infra_permission_denied_hints_at_infra_credential() {
        let dir = tempdir().expect("tempdir");
        let bin_dir = dir.path().join("bin");
        fs::create_dir(&bin_dir).expect("create bin dir");
        write_fake_docker_script(&bin_dir.join("docker"));
        let args_log = dir.path().join("docker_args.log");
        let _lock = env_lock();
        let _path = ScopedEnvVar::set("PATH", path_with_prepend(&bin_dir));
        let _args = ScopedEnvVar::set(TEST_DOCKER_ARGS_ENV, args_log.as_os_str());

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_STEPCA}/secret-id"
            )))
            .respond_with(
                ResponseTemplate::new(403).set_body_string(r#"{"errors":["permission denied"]}"#),
            )
            .mount(&server)
            .await;

        let mut ctx = make_ctx(dir.path());
        let stepca_dir = ctx
            .paths
            .secrets_dir()
            .join(OPENBAO_AGENT_DIR)
            .join(OPENBAO_AGENT_STEPCA_DIR);
        fs::create_dir_all(&stepca_dir).expect("create agent dir");
        fs::write(
            stepca_dir.join(OPENBAO_AGENT_ROLE_ID_NAME),
            "stepca-role-id",
        )
        .expect("write role_id");

        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("runtime-rotate-token".to_string());
        let messages = test_messages();
        let err = rotate_infra_approle_secret_id(
            &mut ctx,
            &client,
            InfraRoleTarget::Stepca,
            true,
            false,
            false,
            &messages,
        )
        .await
        .expect_err("permission denied must fail the rotation");

        let msg = format!("{err:#}");
        assert!(
            msg.contains(APPROLE_BOOTROOT_INFRA_ROTATE),
            "error must name the expected credential, got: {msg}"
        );
        assert!(
            !stepca_dir.join(OPENBAO_AGENT_SECRET_ID_NAME).exists(),
            "secret_id file must not be touched on mint failure"
        );
        assert!(
            !args_log.exists(),
            "the sidecar must not be restarted on mint failure"
        );
    }

    // Because every provisioning step is an unconditional
    // create-or-update (no exists gate), this same path also recovers a
    // partial earlier attempt: role created in OpenBao but state entries
    // or the operator credential lost before the run completed.
    #[tokio::test]
    async fn provision_infra_rotate_role_creates_policy_role_and_saves_state() {
        let dir = tempdir().expect("tempdir");
        let server = MockServer::start().await;
        mount_provisioning_mocks(&server).await;

        let mut ctx = make_ctx(dir.path());
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let messages = test_messages();
        provision_infra_rotate_role(&mut ctx, &client, false, &messages)
            .await
            .expect("provisioning should succeed");

        assert_eq!(
            ctx.state.approles.get("infra_rotate").map(String::as_str),
            Some(APPROLE_BOOTROOT_INFRA_ROTATE)
        );
        assert_eq!(
            ctx.state.policies.get("infra_rotate").map(String::as_str),
            Some(POLICY_BOOTROOT_INFRA_ROTATE)
        );
        let saved = fs::read_to_string(&ctx.state_file).expect("state.json saved");
        assert!(saved.contains(APPROLE_BOOTROOT_INFRA_ROTATE));
    }

    /// Mounts the full set of provisioning mocks: policy write, role
    /// create-or-update, `role_id` read, and `secret_id` mint — each
    /// expected exactly once.
    async fn mount_provisioning_mocks(server: &MockServer) {
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/sys/policies/acl/{POLICY_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}"
            )))
            .respond_with(ResponseTemplate::new(204))
            .expect(1)
            .mount(server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!(
                "/v1/auth/approle/role/{APPROLE_BOOTROOT_INFRA_ROTATE}/role-id"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "data": { "role_id": "infra-rotate-role-id" }
            })))
            .expect(1)
            .mount(server)
            .await;
        mount_secret_id_mock(APPROLE_BOOTROOT_INFRA_ROTATE)
            .expect(1)
            .mount(server)
            .await;
    }

    // A fully provisioned deployment still gets the policy/role
    // refreshed and a fresh operator credential, but state.json is not
    // rewritten when its entries are already current.
    #[tokio::test]
    async fn provision_infra_rotate_role_skips_state_save_when_entries_current() {
        let dir = tempdir().expect("tempdir");
        let server = MockServer::start().await;
        mount_provisioning_mocks(&server).await;

        let mut ctx = make_ctx(dir.path());
        let label = AppRoleLabel::InfraRotate.to_string();
        ctx.state
            .approles
            .insert(label.clone(), APPROLE_BOOTROOT_INFRA_ROTATE.to_string());
        ctx.state
            .policies
            .insert(label, POLICY_BOOTROOT_INFRA_ROTATE.to_string());
        let mut client = OpenBaoClient::new(&server.uri()).expect("client");
        client.set_token("root-token".to_string());
        let messages = test_messages();
        provision_infra_rotate_role(&mut ctx, &client, false, &messages)
            .await
            .expect("re-provisioning must succeed on a current deployment");

        assert!(
            !ctx.state_file.exists(),
            "state.json must not be rewritten when its entries are already current"
        );
    }
}
