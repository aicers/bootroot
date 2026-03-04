use std::io::ErrorKind;
use std::path::Path;

use anyhow::{Context, Result};
use bootroot::fs_util;

use super::super::constants::openbao_constants::{PATH_STEPCA_DB, PATH_STEPCA_PASSWORD};
use super::super::constants::{
    DEFAULT_CA_ADDRESS, DEFAULT_CA_DNS, DEFAULT_CA_NAME, DEFAULT_CA_PROVISIONER,
    RESPONDER_TEMPLATE_DIR, STEPCA_CA_JSON_TEMPLATE_NAME, STEPCA_PASSWORD_TEMPLATE_NAME,
};
use super::super::paths::StepCaTemplatePaths;
use super::super::types::StepCaInitResult;
use super::RollbackFile;
use crate::commands::infra::run_docker;
use crate::i18n::Messages;

pub(super) async fn write_stepca_templates(
    secrets_dir: &Path,
    kv_mount: &str,
    messages: &Messages,
) -> Result<StepCaTemplatePaths> {
    let templates_dir = secrets_dir.join(RESPONDER_TEMPLATE_DIR);
    fs_util::ensure_secrets_dir(&templates_dir).await?;

    let password_template_path = templates_dir.join(STEPCA_PASSWORD_TEMPLATE_NAME);
    let password_template = build_password_template(kv_mount);
    tokio::fs::write(&password_template_path, password_template)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&password_template_path.display().to_string())
        })?;
    fs_util::set_key_permissions(&password_template_path).await?;

    let ca_json_path = secrets_dir.join("config").join("ca.json");
    let ca_json_contents = tokio::fs::read_to_string(&ca_json_path)
        .await
        .with_context(|| messages.error_read_file_failed(&ca_json_path.display().to_string()))?;
    let ca_json_template = build_ca_json_template(&ca_json_contents, kv_mount, messages)?;
    let ca_json_template_path = templates_dir.join(STEPCA_CA_JSON_TEMPLATE_NAME);
    tokio::fs::write(&ca_json_template_path, ca_json_template)
        .await
        .with_context(|| {
            messages.error_write_file_failed(&ca_json_template_path.display().to_string())
        })?;
    fs_util::set_key_permissions(&ca_json_template_path).await?;

    Ok(StepCaTemplatePaths {
        password_template_path,
        ca_json_template_path,
    })
}

fn build_password_template(kv_mount: &str) -> String {
    format!(
        r#"{{{{ with secret "{kv_mount}/data/{PATH_STEPCA_PASSWORD}" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}"#
    )
}

fn build_ca_json_template(contents: &str, kv_mount: &str, messages: &Messages) -> Result<String> {
    const PLACEHOLDER: &str = "__BOOTROOT_CTMPL_DB__";

    let mut value: serde_json::Value =
        serde_json::from_str(contents).context(messages.error_parse_ca_json_failed())?;
    let db = value
        .get_mut("db")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    let data_source = db
        .get_mut("dataSource")
        .ok_or_else(|| anyhow::anyhow!(messages.error_ca_json_db_missing()))?;
    *data_source = serde_json::Value::String(PLACEHOLDER.to_string());

    let serialized =
        serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())?;

    // serde_json escapes double quotes inside strings, but the Go template
    // engine in OpenBao Agent requires unescaped quotes within {{ }} blocks.
    // Replace the JSON-quoted placeholder with a raw Go template directive
    // so the .ctmpl file is parseable by the template engine.
    let directive = format!(
        "\"{{{{ with secret \"{kv_mount}/data/{PATH_STEPCA_DB}\" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}\""
    );
    Ok(serialized.replace(&format!("\"{PLACEHOLDER}\""), &directive))
}

pub(super) async fn write_password_file_with_backup(
    secrets_dir: &Path,
    password: &str,
    messages: &Messages,
) -> Result<RollbackFile> {
    fs_util::ensure_secrets_dir(secrets_dir).await?;
    let password_path = secrets_dir.join("password.txt");
    let original = match tokio::fs::read_to_string(&password_path).await {
        Ok(contents) => Some(contents),
        Err(err) if err.kind() == ErrorKind::NotFound => None,
        Err(err) => {
            return Err(err).with_context(|| {
                messages.error_read_file_failed(&password_path.display().to_string())
            });
        }
    };
    tokio::fs::write(&password_path, password)
        .await
        .with_context(|| messages.error_write_file_failed(&password_path.display().to_string()))?;
    fs_util::set_key_permissions(&password_path).await?;
    Ok(RollbackFile {
        path: password_path,
        original,
    })
}

pub(super) async fn update_ca_json_with_backup(
    secrets_dir: &Path,
    db_dsn: &str,
    messages: &Messages,
) -> Result<RollbackFile> {
    let path = secrets_dir.join("config").join("ca.json");
    let contents = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&contents).context(messages.error_parse_ca_json_failed())?;
    value["db"]["type"] = serde_json::Value::String("postgresql".to_string());
    value["db"]["dataSource"] = serde_json::Value::String(db_dsn.to_string());
    let updated =
        serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())?;
    tokio::fs::write(&path, updated)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(RollbackFile {
        path,
        original: Some(contents),
    })
}

pub(super) fn ensure_step_ca_initialized(
    secrets_dir: &Path,
    messages: &Messages,
) -> Result<StepCaInitResult> {
    let config_path = secrets_dir.join("config").join("ca.json");
    let ca_key = secrets_dir.join("secrets").join("root_ca_key");
    let intermediate_key = secrets_dir.join("secrets").join("intermediate_ca_key");
    if config_path.exists() && ca_key.exists() && intermediate_key.exists() {
        return Ok(StepCaInitResult::Skipped);
    }

    let password_path = secrets_dir.join("password.txt");
    if !password_path.exists() {
        anyhow::bail!(messages.error_stepca_password_missing(&password_path.display().to_string()));
    }
    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let mount = format!("{}:/home/step", mount_root.display());
    let args = vec![
        "run",
        "--user",
        "root",
        "--rm",
        "-v",
        &*mount,
        "smallstep/step-ca",
        "step",
        "ca",
        "init",
        "--name",
        DEFAULT_CA_NAME,
        "--provisioner",
        DEFAULT_CA_PROVISIONER,
        "--dns",
        DEFAULT_CA_DNS,
        "--address",
        DEFAULT_CA_ADDRESS,
        "--password-file",
        "/home/step/password.txt",
        "--provisioner-password-file",
        "/home/step/password.txt",
        "--acme",
    ];
    run_docker(&args, "docker step-ca init", messages)?;
    Ok(StepCaInitResult::Initialized)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::super::test_support::test_messages;
    use super::*;

    #[tokio::test]
    async fn test_write_stepca_templates_writes_templates() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(secrets_dir.join("config")).unwrap();
        fs::write(
            secrets_dir.join("config").join("ca.json"),
            r#"{"db":{"type":"postgresql","dataSource":"old"}}"#,
        )
        .unwrap();

        let messages = test_messages();
        let paths = write_stepca_templates(&secrets_dir, "secret", &messages)
            .await
            .unwrap();
        let password_template = fs::read_to_string(&paths.password_template_path).unwrap();
        let ca_json_template = fs::read_to_string(&paths.ca_json_template_path).unwrap();

        assert!(password_template.contains("secret/data/bootroot/stepca/password"));
        assert!(ca_json_template.contains("secret/data/bootroot/stepca/db"));
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

        let result = ensure_step_ca_initialized(&secrets_dir, &test_messages()).unwrap();
        assert_eq!(result, StepCaInitResult::Skipped);
    }

    #[test]
    fn test_step_ca_init_requires_password_when_missing_files() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();

        let err = ensure_step_ca_initialized(&secrets_dir, &test_messages()).unwrap_err();
        assert!(err.to_string().contains("step-ca password file not found"));
    }
}
