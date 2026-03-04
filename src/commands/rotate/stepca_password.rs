use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;

use super::helpers::{
    confirm_action, ensure_file_exists, restart_compose_service, restart_container,
    wait_for_rendered_file, write_secret_file,
};
use super::{OPENBAO_AGENT_STEPCA_CONTAINER, RENDERED_FILE_TIMEOUT, RotateContext};
use crate::cli::args::RotateStepcaPasswordArgs;
use crate::commands::infra::run_docker;
use crate::commands::init::{PATH_STEPCA_PASSWORD, SECRET_BYTES, to_container_path};
use crate::i18n::Messages;

pub(super) async fn rotate_stepca_password(
    ctx: &mut RotateContext,
    client: &OpenBaoClient,
    args: &RotateStepcaPasswordArgs,
    auto_confirm: bool,
    messages: &Messages,
) -> Result<()> {
    let new_password = match args.new_password.clone() {
        Some(value) => value,
        None => bootroot::utils::generate_secret(SECRET_BYTES)
            .with_context(|| messages.error_generate_secret_failed())?,
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
    // CodeQL flags this as cleartext-logging, but `password_path` is a file
    // path, not the password value. Dismiss as false positive.
    println!(
        "{}",
        messages.rotate_summary_stepca_password(&password_path.display().to_string())
    );
    println!("{}", messages.rotate_summary_restart_stepca());
    Ok(())
}

pub(super) fn change_stepca_passphrase(
    secrets_dir: &Path,
    current_password: &Path,
    new_password: &Path,
    key_path: &Path,
    messages: &Messages,
) -> Result<()> {
    let mount_root = fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let mount = format!("{}:/home/step", mount_root.display());
    let key_container = to_container_path(secrets_dir, key_path, "/home/step")?;
    let pwd_container = to_container_path(secrets_dir, current_password, "/home/step")?;
    let new_pwd_container = to_container_path(secrets_dir, new_password, "/home/step")?;
    let args = vec![
        "run",
        "--user",
        "root",
        "--rm",
        "-v",
        &*mount,
        "smallstep/step-ca",
        "step",
        "crypto",
        "change-pass",
        &*key_container,
        "--password-file",
        &*pwd_container,
        "--new-password-file",
        &*new_pwd_container,
        "-f",
    ];
    run_docker(&args, "docker step-ca change-pass", messages)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::super::test_support::*;
    use super::*;

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
}
