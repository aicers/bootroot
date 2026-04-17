use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};

use super::super::constants::{
    RESPONDER_CONFIG_DIR, RESPONDER_CONFIG_NAME, RESPONDER_TEMPLATE_DIR, RESPONDER_TEMPLATE_NAME,
};
use crate::commands::constants::RESPONDER_SERVICE_NAME;
use crate::commands::infra::run_docker;
use crate::commands::init::{
    CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, HTTP01_ADMIN_INFRA_CERT_KEY,
    HTTP01_ADMIN_TLS_CERT_REL_PATH, HTTP01_ADMIN_TLS_DEFAULT_NOT_AFTER,
    HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE, HTTP01_ADMIN_TLS_KEY_REL_PATH,
};
use crate::i18n::Messages;
use crate::state::{InfraCertEntry, ReloadStrategy, StateFile};

/// Issues an HTTP-01 admin API TLS server certificate signed by the
/// local step-ca intermediate CA.
///
/// Writes the certificate to `secrets_dir/bootroot-http01/tls/{server.crt,server.key}`
/// with `0600` permissions.  `step certificate create` runs via Docker
/// (no step CLI required on the host).
pub(in crate::commands::init) fn issue_http01_admin_tls_cert(
    secrets_dir: &Path,
    sans: &[&str],
    messages: &Messages,
) -> Result<()> {
    let cert_path = secrets_dir.join(HTTP01_ADMIN_TLS_CERT_REL_PATH);
    let key_path = secrets_dir.join(HTTP01_ADMIN_TLS_KEY_REL_PATH);

    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let secrets_mount = format!("{}:/home/step", mount_root.display());

    let tls_dir = secrets_dir.join("bootroot-http01").join("tls");
    std::fs::create_dir_all(&tls_dir)
        .with_context(|| messages.error_write_file_failed(&tls_dir.display().to_string()))?;
    let tls_mount_root = std::fs::canonicalize(&tls_dir)
        .with_context(|| messages.error_resolve_path_failed(&tls_dir.display().to_string()))?;
    let tls_mount = format!("{}:/output", tls_mount_root.display());

    let meta = std::fs::metadata(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let user_arg = format!("{}:{}", meta.uid(), meta.gid());

    let san_arg = sans.join(",");

    let intermediate_cert = format!("/home/step/{CA_CERTS_DIR}/{CA_INTERMEDIATE_CERT_FILENAME}");
    let args: Vec<&str> = vec![
        "run",
        "--user",
        &user_arg,
        "--rm",
        "-v",
        &secrets_mount,
        "-v",
        &tls_mount,
        "smallstep/step-ca",
        "step",
        "certificate",
        "create",
        "responder.internal",
        "/output/server.crt",
        "/output/server.key",
        "--ca",
        &intermediate_cert,
        "--ca-key",
        "/home/step/secrets/intermediate_ca_key",
        "--ca-password-file",
        "/home/step/password.txt",
        "--no-password",
        "--insecure",
        "--san",
        &san_arg,
        "--not-after",
        HTTP01_ADMIN_TLS_DEFAULT_NOT_AFTER,
        "--force",
    ];

    run_docker(
        &args,
        "docker step certificate create (http01 admin tls)",
        messages,
    )
    .with_context(|| messages.error_http01_admin_tls_provision_failed())?;

    set_key_permissions_sync(&key_path)?;
    set_key_permissions_sync(&cert_path)?;

    println!(
        "{}",
        messages.info_http01_admin_tls_provisioned(&cert_path.display().to_string())
    );
    Ok(())
}

/// Builds the SANs list for the HTTP-01 admin API TLS certificate.
///
/// Always includes `responder.internal`, `localhost`, and the Docker
/// service name.  When a bind address is configured, its IP component
/// is added as well.  When an advertise address is provided (wildcard
/// bind), its IP is included so that clients connecting via the
/// advertised endpoint pass hostname verification.
pub(in crate::commands::init) fn build_http01_admin_tls_sans(
    bind_addr: &str,
    advertise_addr: Option<&str>,
) -> Vec<String> {
    let mut sans = vec![
        "responder.internal".to_string(),
        "localhost".to_string(),
        RESPONDER_SERVICE_NAME.to_string(),
    ];

    if let Some((ip_raw, _port)) = bind_addr.rsplit_once(':') {
        let ip = ip_raw
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(ip_raw);
        if !ip.is_empty() && ip != "0.0.0.0" && ip != "::" && ip != "::0" {
            sans.push(ip.to_string());
        }
        if ip == "0.0.0.0" {
            sans.push("127.0.0.1".to_string());
        } else if ip == "::" || ip == "::0" {
            sans.push("::1".to_string());
            sans.push("127.0.0.1".to_string());
        }
    }

    if let Some(addr) = advertise_addr
        && let Some((ip_raw, _port)) = addr.rsplit_once(':')
    {
        let ip = ip_raw
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(ip_raw);
        if !ip.is_empty() && !sans.contains(&ip.to_string()) {
            sans.push(ip.to_string());
        }
    }

    sans
}

/// Records the HTTP-01 admin API TLS certificate in
/// `StateFile::infra_certs`.
///
/// Stores the computed `sans` so that `reissue_http01_admin_tls_cert`
/// can reproduce the same SANs on renewal.
pub(in crate::commands::init) fn record_http01_admin_infra_cert(
    state: &mut StateFile,
    secrets_dir: &Path,
    sans: Vec<String>,
) {
    let cert_path = secrets_dir.join(HTTP01_ADMIN_TLS_CERT_REL_PATH);
    let key_path = secrets_dir.join(HTTP01_ADMIN_TLS_KEY_REL_PATH);

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let entry = InfraCertEntry {
        cert_path,
        key_path,
        sans,
        renew_before: HTTP01_ADMIN_TLS_DEFAULT_RENEW_BEFORE.to_string(),
        reload_strategy: ReloadStrategy::ContainerSignal {
            container_name: RESPONDER_SERVICE_NAME.to_string(),
            signal: "SIGHUP".to_string(),
        },
        issued_at: Some(now),
        expires_at: None,
    };

    state
        .infra_certs
        .insert(HTTP01_ADMIN_INFRA_CERT_KEY.to_string(), entry);
}

fn set_key_permissions_sync(path: &Path) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set permissions on {}", path.display()))
}

/// Re-issues an existing HTTP-01 admin API infrastructure certificate.
///
/// Used by the rotation pipeline to renew the cert before expiry.
pub(crate) fn reissue_http01_admin_tls_cert(
    secrets_dir: &Path,
    entry: &InfraCertEntry,
    messages: &Messages,
) -> Result<()> {
    let san_refs: Vec<&str> = entry.sans.iter().map(String::as_str).collect();
    let sans = if san_refs.is_empty() {
        vec!["responder.internal", "localhost", RESPONDER_SERVICE_NAME]
    } else {
        san_refs
    };
    issue_http01_admin_tls_cert(secrets_dir, &sans, messages)
}

/// Strips `tls_cert_path` and `tls_key_path` lines from the responder
/// config and template files so that the responder does not start with
/// TLS enabled until the next `bootroot init` issues a fresh certificate.
///
/// No-ops when neither file exists (fresh install before first `init`).
pub(crate) fn strip_responder_tls_config(secrets_dir: &Path, messages: &Messages) -> Result<()> {
    let configs = [
        secrets_dir
            .join(RESPONDER_CONFIG_DIR)
            .join(RESPONDER_CONFIG_NAME),
        secrets_dir
            .join(RESPONDER_TEMPLATE_DIR)
            .join(RESPONDER_TEMPLATE_NAME),
    ];
    let mut stripped = false;
    for path in &configs {
        if !path.exists() {
            continue;
        }
        let content = std::fs::read_to_string(path)
            .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
        let filtered: String = content
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.starts_with("tls_cert_path") && !trimmed.starts_with("tls_key_path")
            })
            .collect::<Vec<_>>()
            .join("\n");
        if filtered.len() != content.len() {
            let to_write = if content.ends_with('\n') && !filtered.ends_with('\n') {
                format!("{filtered}\n")
            } else {
                filtered
            };
            std::fs::write(path, to_write)
                .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
            stripped = true;
        }
    }
    if stripped {
        println!("{}", messages.info_http01_admin_tls_reverted());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn build_sans_includes_specific_ip() {
        let sans = build_http01_admin_tls_sans("192.168.1.10:8080", None);
        assert!(sans.contains(&"responder.internal".to_string()));
        assert!(sans.contains(&"localhost".to_string()));
        assert!(sans.contains(&RESPONDER_SERVICE_NAME.to_string()));
        assert!(sans.contains(&"192.168.1.10".to_string()));
    }

    #[test]
    fn build_sans_wildcard_adds_loopback() {
        let sans = build_http01_admin_tls_sans("0.0.0.0:8080", None);
        assert!(sans.contains(&"127.0.0.1".to_string()));
        assert!(!sans.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_sans_wildcard_with_advertise_addr() {
        let sans = build_http01_admin_tls_sans("0.0.0.0:8080", Some("192.168.1.10:8080"));
        assert!(
            sans.contains(&"192.168.1.10".to_string()),
            "advertise addr IP must be included in SANs"
        );
        assert!(
            sans.contains(&"127.0.0.1".to_string()),
            "loopback must still be present for wildcard"
        );
        assert!(!sans.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_sans_ipv6_wildcard_with_advertise_addr() {
        let sans = build_http01_admin_tls_sans("[::]:8080", Some("[fd12::1]:8080"));
        assert!(
            sans.contains(&"fd12::1".to_string()),
            "advertise addr IPv6 must be included in SANs"
        );
        assert!(sans.contains(&"::1".to_string()));
        assert!(sans.contains(&"127.0.0.1".to_string()));
    }

    #[test]
    fn build_sans_advertise_addr_dedup() {
        let sans = build_http01_admin_tls_sans("192.168.1.10:8080", Some("192.168.1.10:8080"));
        let count = sans.iter().filter(|s| *s == "192.168.1.10").count();
        assert_eq!(count, 1, "duplicate SANs must not be added");
    }

    #[test]
    fn build_sans_ipv6_specific() {
        let sans = build_http01_admin_tls_sans("[fd12::1]:8080", None);
        assert!(sans.contains(&"fd12::1".to_string()));
    }

    #[test]
    fn build_sans_ipv6_wildcard() {
        let sans = build_http01_admin_tls_sans("[::]:8080", None);
        assert!(
            sans.contains(&"::1".to_string()),
            "IPv6 wildcard must include IPv6 loopback"
        );
        assert!(
            sans.contains(&"127.0.0.1".to_string()),
            "IPv6 wildcard must also include IPv4 loopback for dual-stack"
        );
        assert!(!sans.contains(&"::".to_string()));
    }

    #[test]
    fn build_sans_ipv6_zero_wildcard() {
        let sans = build_http01_admin_tls_sans("[::0]:8080", None);
        assert!(
            sans.contains(&"::1".to_string()),
            "[::0] wildcard must include IPv6 loopback"
        );
        assert!(
            sans.contains(&"127.0.0.1".to_string()),
            "[::0] wildcard must also include IPv4 loopback for dual-stack"
        );
        assert!(!sans.contains(&"::0".to_string()));
    }

    #[test]
    fn record_http01_admin_infra_cert_inserts_entry() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = StateFile {
            openbao_url: "http://localhost:8200".to_string(),
            kv_mount: "secret".to_string(),
            secrets_dir: None,
            policies: BTreeMap::new(),
            approles: BTreeMap::new(),
            services: BTreeMap::new(),
            openbao_bind_addr: None,
            openbao_advertise_addr: None,
            http01_admin_bind_addr: None,
            http01_admin_advertise_addr: None,
            infra_certs: BTreeMap::new(),
        };
        let sans = vec!["responder.internal".to_string(), "localhost".to_string()];
        record_http01_admin_infra_cert(&mut state, dir.path(), sans);
        assert!(state.infra_certs.contains_key(HTTP01_ADMIN_INFRA_CERT_KEY));
        let entry = &state.infra_certs[HTTP01_ADMIN_INFRA_CERT_KEY];
        assert_eq!(
            entry.reload_strategy,
            ReloadStrategy::ContainerSignal {
                container_name: RESPONDER_SERVICE_NAME.to_string(),
                signal: "SIGHUP".to_string(),
            }
        );
        assert!(entry.issued_at.is_some());
    }

    #[test]
    fn strip_responder_tls_config_removes_tls_lines() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let config_dir = secrets_dir.join(RESPONDER_CONFIG_DIR);
        let template_dir = secrets_dir.join(RESPONDER_TEMPLATE_DIR);
        std::fs::create_dir_all(&config_dir).unwrap();
        std::fs::create_dir_all(&template_dir).unwrap();

        let config_with_tls = "\
listen_addr = \"0.0.0.0:80\"\n\
admin_addr = \"0.0.0.0:8080\"\n\
hmac_secret = \"test-hmac\"\n\
tls_cert_path = \"/app/bootroot-http01/tls/server.crt\"\n\
tls_key_path = \"/app/bootroot-http01/tls/server.key\"\n";

        std::fs::write(config_dir.join(RESPONDER_CONFIG_NAME), config_with_tls).unwrap();
        std::fs::write(template_dir.join(RESPONDER_TEMPLATE_NAME), config_with_tls).unwrap();

        let messages = crate::i18n::test_messages();
        strip_responder_tls_config(&secrets_dir, &messages).unwrap();

        let config = std::fs::read_to_string(config_dir.join(RESPONDER_CONFIG_NAME)).unwrap();
        let template = std::fs::read_to_string(template_dir.join(RESPONDER_TEMPLATE_NAME)).unwrap();

        assert!(
            !config.contains("tls_cert_path"),
            "tls_cert_path must be removed from config: {config}"
        );
        assert!(
            !config.contains("tls_key_path"),
            "tls_key_path must be removed from config: {config}"
        );
        assert!(
            config.contains("hmac_secret"),
            "non-TLS fields must be preserved: {config}"
        );
        assert!(
            !template.contains("tls_cert_path"),
            "tls_cert_path must be removed from template: {template}"
        );
    }

    #[test]
    fn strip_responder_tls_config_noop_without_files() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let messages = crate::i18n::test_messages();
        strip_responder_tls_config(&secrets_dir, &messages).unwrap();
    }

    #[test]
    fn strip_responder_tls_config_noop_without_tls_lines() {
        let dir = tempfile::tempdir().unwrap();
        let secrets_dir = dir.path().join("secrets");
        let config_dir = secrets_dir.join(RESPONDER_CONFIG_DIR);
        std::fs::create_dir_all(&config_dir).unwrap();

        let config_no_tls = "\
listen_addr = \"0.0.0.0:80\"\n\
admin_addr = \"0.0.0.0:8080\"\n\
hmac_secret = \"test-hmac\"\n";

        let config_path = config_dir.join(RESPONDER_CONFIG_NAME);
        std::fs::write(&config_path, config_no_tls).unwrap();

        let messages = crate::i18n::test_messages();
        strip_responder_tls_config(&secrets_dir, &messages).unwrap();

        let after = std::fs::read_to_string(&config_path).unwrap();
        assert_eq!(after, config_no_tls, "file must not be modified");
    }
}
