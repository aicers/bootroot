use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::acme::responder_client;
use bootroot::fs_util;

use super::super::constants::openbao_constants::PATH_RESPONDER_HMAC;
use super::super::constants::{
    DEFAULT_RESPONDER_TOKEN_TTL_SECS, RESPONDER_COMPOSE_OVERRIDE_NAME, RESPONDER_CONFIG_DIR,
    RESPONDER_CONFIG_NAME, RESPONDER_TEMPLATE_DIR, RESPONDER_TEMPLATE_NAME,
    RESPONDER_TLS_CERT_CONTAINER_PATH, RESPONDER_TLS_KEY_CONTAINER_PATH,
};
use super::super::paths::{ResponderPaths, compose_has_responder};
use super::super::types::ResponderCheck;
use super::InitSecrets;
use crate::cli::args::{InitArgs, InitSkipPhase};
use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::infra::run_docker;
use crate::i18n::Messages;

pub(super) async fn write_responder_files(
    secrets_dir: &Path,
    kv_mount: &str,
    hmac: &str,
    tls_enabled: bool,
    messages: &Messages,
) -> Result<ResponderPaths> {
    let templates_dir = secrets_dir.join(RESPONDER_TEMPLATE_DIR);
    fs_util::ensure_secrets_dir(&templates_dir).await?;
    let responder_dir = secrets_dir.join(RESPONDER_CONFIG_DIR);
    fs_util::ensure_secrets_dir(&responder_dir).await?;

    let template_path = templates_dir.join(RESPONDER_TEMPLATE_NAME);
    let template = build_responder_template(kv_mount, tls_enabled);
    tokio::fs::write(&template_path, template)
        .await
        .with_context(|| messages.error_write_file_failed(&template_path.display().to_string()))?;
    fs_util::set_key_permissions(&template_path).await?;

    let config_path = responder_dir.join(RESPONDER_CONFIG_NAME);
    let config = build_responder_config(hmac, tls_enabled);
    tokio::fs::write(&config_path, config)
        .await
        .with_context(|| messages.error_write_file_failed(&config_path.display().to_string()))?;
    fs_util::set_key_permissions(&config_path).await?;

    Ok(ResponderPaths {
        template_path,
        config_path,
    })
}

fn build_responder_template(kv_mount: &str, tls_enabled: bool) -> String {
    use std::fmt::Write;

    let mut config = format!(
        r#"# HTTP-01 responder config (OpenBao Agent template)

listen_addr = "0.0.0.0:80"
admin_addr = "0.0.0.0:8080"
hmac_secret = "{{{{ with secret "{kv_mount}/data/{PATH_RESPONDER_HMAC}" }}}}{{{{ .Data.data.value }}}}{{{{ end }}}}"
token_ttl_secs = 300
max_token_ttl_secs = 900
cleanup_interval_secs = 30
max_skew_secs = 60
admin_rate_limit_requests = 300
admin_rate_limit_window_secs = 60
admin_body_limit_bytes = 8192
"#
    );
    if tls_enabled {
        let _ = write!(
            config,
            "tls_cert_path = \"{RESPONDER_TLS_CERT_CONTAINER_PATH}\"\ntls_key_path = \"{RESPONDER_TLS_KEY_CONTAINER_PATH}\"\n"
        );
    }
    config
}

fn build_responder_config(hmac: &str, tls_enabled: bool) -> String {
    use std::fmt::Write;

    let mut config = format!(
        r#"# HTTP-01 responder config (rendered)

listen_addr = "0.0.0.0:80"
admin_addr = "0.0.0.0:8080"
hmac_secret = "{hmac}"
token_ttl_secs = 300
max_token_ttl_secs = 900
cleanup_interval_secs = 30
max_skew_secs = 60
admin_rate_limit_requests = 300
admin_rate_limit_window_secs = 60
admin_body_limit_bytes = 8192
"#
    );
    if tls_enabled {
        let _ = write!(
            config,
            "tls_cert_path = \"{RESPONDER_TLS_CERT_CONTAINER_PATH}\"\ntls_key_path = \"{RESPONDER_TLS_KEY_CONTAINER_PATH}\"\n"
        );
    }
    config
}

pub(super) async fn write_responder_compose_override(
    compose_file: &Path,
    secrets_dir: &Path,
    config_path: &Path,
    messages: &Messages,
) -> Result<Option<PathBuf>> {
    if !compose_has_responder(compose_file, messages)? {
        return Ok(None);
    }
    let responder_dir = secrets_dir.join(RESPONDER_CONFIG_DIR);
    fs_util::ensure_secrets_dir(&responder_dir).await?;
    let override_path = responder_dir.join(RESPONDER_COMPOSE_OVERRIDE_NAME);
    let config_dir = config_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("responder config has no parent directory"))?;
    let config_dir = std::fs::canonicalize(config_dir)
        .with_context(|| messages.error_resolve_path_failed(&config_dir.display().to_string()))?;
    let file_name = config_path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("responder config has no file name"))?
        .to_string_lossy();
    let contents = format!(
        r#"version: "3.8"
services:
  {RESPONDER_SERVICE_NAME}:
    volumes:
      - {dir}:/app/responder:ro
    command:
      - --config=/app/responder/{file_name}
"#,
        dir = config_dir.display(),
        file_name = file_name,
    );
    tokio::fs::write(&override_path, contents)
        .await
        .with_context(|| messages.error_write_file_failed(&override_path.display().to_string()))?;
    Ok(Some(override_path))
}

pub(super) fn apply_responder_compose_override(
    compose_file: &Path,
    override_path: &Path,
    messages: &Messages,
) -> Result<()> {
    let compose_str = compose_file.to_string_lossy();
    let override_str = override_path.to_string_lossy();
    let args = [
        "compose",
        "-f",
        &*compose_str,
        "-f",
        &*override_str,
        "up",
        "-d",
        RESPONDER_SERVICE_NAME,
    ];
    run_docker(&args, "docker compose responder override", messages)?;
    Ok(())
}

pub(super) async fn verify_responder(
    responder_url: Option<&str>,
    args: &InitArgs,
    messages: &Messages,
    secrets: &InitSecrets,
    secrets_dir: &Path,
) -> Result<ResponderCheck> {
    if args.has_skip(InitSkipPhase::ResponderCheck) {
        return Ok(ResponderCheck::Skipped);
    }
    let Some(responder_url) = responder_url else {
        return Ok(ResponderCheck::Skipped);
    };
    let ca_pem = if responder_url.starts_with("https://") {
        Some(
            super::ca_certs::compute_ca_bundle_pem(secrets_dir, messages)
                .await
                .context("Failed to read step-ca root for responder TLS verification")?,
        )
    } else {
        None
    };
    let trust = ca_pem
        .as_deref()
        .map(|pem| responder_client::ResponderTrust {
            ca_pem: pem,
            ca_pins: &[],
        });
    responder_client::register_http01_token_with(
        responder_url,
        &secrets.http_hmac,
        args.responder_timeout_secs,
        "bootroot-init-check",
        "bootroot-init-check.key",
        DEFAULT_RESPONDER_TOKEN_TTL_SECS,
        trust.as_ref(),
    )
    .await
    .with_context(|| messages.error_responder_check_failed())?;
    Ok(ResponderCheck::Ok)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::super::super::constants::DEFAULT_RESPONDER_ADMIN_URL;
    use super::super::super::paths::{compose_has_responder, resolve_responder_url};
    use super::super::test_support::{default_init_args, test_messages};
    use super::*;

    #[tokio::test]
    async fn test_write_responder_files_writes_template_and_config() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");

        let messages = test_messages();
        let paths = write_responder_files(&secrets_dir, "secret", "hmac-123", false, &messages)
            .await
            .unwrap();
        let template = fs::read_to_string(&paths.template_path).unwrap();
        let config = fs::read_to_string(&paths.config_path).unwrap();

        assert!(template.contains("secret/data/bootroot/responder/hmac"));
        assert!(template.contains("max_token_ttl_secs = 900"));
        assert!(template.contains("admin_rate_limit_requests = 300"));
        assert!(template.contains("admin_body_limit_bytes = 8192"));
        assert!(!template.contains("tls_cert_path"));
        assert!(config.contains("hmac-123"));
        assert!(config.contains("max_token_ttl_secs = 900"));
        assert!(config.contains("admin_rate_limit_requests = 300"));
        assert!(config.contains("admin_body_limit_bytes = 8192"));
        assert!(!config.contains("tls_cert_path"));
    }

    #[tokio::test]
    async fn test_write_responder_files_includes_tls_paths_when_enabled() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");

        let messages = test_messages();
        let paths = write_responder_files(&secrets_dir, "secret", "hmac-123", true, &messages)
            .await
            .unwrap();
        let template = fs::read_to_string(&paths.template_path).unwrap();
        let config = fs::read_to_string(&paths.config_path).unwrap();

        assert!(
            template.contains("tls_cert_path = \"/app/responder/tls/cert.pem\""),
            "template must include tls_cert_path: {template}"
        );
        assert!(
            template.contains("tls_key_path = \"/app/responder/tls/key.pem\""),
            "template must include tls_key_path: {template}"
        );
        assert!(
            config.contains("tls_cert_path = \"/app/responder/tls/cert.pem\""),
            "config must include tls_cert_path: {config}"
        );
        assert!(
            config.contains("tls_key_path = \"/app/responder/tls/key.pem\""),
            "config must include tls_key_path: {config}"
        );
    }

    #[tokio::test]
    async fn test_write_responder_compose_override_skips_when_missing_service() {
        let temp_dir = tempdir().unwrap();
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").unwrap();

        let secrets_dir = temp_dir.path().join("secrets");
        let messages = test_messages();
        let paths = write_responder_files(&secrets_dir, "secret", "hmac-123", false, &messages)
            .await
            .unwrap();

        let override_path = write_responder_compose_override(
            &compose_file,
            &secrets_dir,
            &paths.config_path,
            &messages,
        )
        .await
        .unwrap();

        assert!(override_path.is_none());
    }

    #[tokio::test]
    async fn test_write_responder_compose_override_writes_mount() {
        let temp_dir = tempdir().unwrap();
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(
            &compose_file,
            r"
services:
  bootroot-http01:
    image: bootroot-http01-responder:latest
",
        )
        .unwrap();

        let secrets_dir = temp_dir.path().join("secrets");
        let messages = test_messages();
        let paths = write_responder_files(&secrets_dir, "secret", "hmac-123", false, &messages)
            .await
            .unwrap();

        let override_path = write_responder_compose_override(
            &compose_file,
            &secrets_dir,
            &paths.config_path,
            &messages,
        )
        .await
        .unwrap()
        .expect("override path");
        let contents = fs::read_to_string(&override_path).unwrap();
        let config_dir = std::fs::canonicalize(paths.config_path.parent().unwrap()).unwrap();

        assert!(contents.contains(RESPONDER_SERVICE_NAME));
        assert!(
            contents.contains(&format!("{}:/app/responder:ro", config_dir.display())),
            "should mount responder directory: {contents}"
        );
        assert!(
            contents.contains("--config=/app/responder/responder.toml"),
            "should set config path to directory-based path: {contents}"
        );
    }

    #[test]
    fn test_resolve_responder_url_skips_when_missing() {
        let temp_dir = tempdir().unwrap();
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(&compose_file, "services: {}").unwrap();
        let mut args = default_init_args();
        args.compose.compose_file = compose_file;

        let compose_has_responder =
            compose_has_responder(&args.compose.compose_file, &test_messages())
                .expect("compose check");
        let responder_url =
            resolve_responder_url(&args, compose_has_responder).expect("resolve responder url");
        assert!(responder_url.is_none());
    }

    #[test]
    fn test_resolve_responder_url_uses_default_when_present() {
        let temp_dir = tempdir().unwrap();
        let compose_file = temp_dir.path().join("docker-compose.yml");
        fs::write(
            &compose_file,
            r"
services:
  bootroot-http01:
    image: bootroot-http01-responder:latest
",
        )
        .unwrap();
        let mut args = default_init_args();
        args.compose.compose_file = compose_file;

        let compose_has_responder =
            compose_has_responder(&args.compose.compose_file, &test_messages())
                .expect("compose check");
        let responder_url =
            resolve_responder_url(&args, compose_has_responder).expect("resolve responder url");
        assert_eq!(responder_url.as_deref(), Some(DEFAULT_RESPONDER_ADMIN_URL));
    }
}
