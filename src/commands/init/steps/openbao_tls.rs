use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, Result};

use crate::commands::infra::run_docker;
use crate::commands::init::{
    CA_CERTS_DIR, CA_INTERMEDIATE_CERT_FILENAME, OPENBAO_CONTAINER_NAME, OPENBAO_HCL_PATH,
    OPENBAO_INFRA_CERT_KEY, OPENBAO_TLS_CERT_PATH, OPENBAO_TLS_CONTAINER_CERT_PATH,
    OPENBAO_TLS_CONTAINER_KEY_PATH, OPENBAO_TLS_DEFAULT_NOT_AFTER,
    OPENBAO_TLS_DEFAULT_RENEW_BEFORE, OPENBAO_TLS_KEY_PATH,
};
use crate::i18n::Messages;
use crate::state::{InfraCertEntry, ReloadStrategy, StateFile};

/// Issues an `OpenBao` TLS server certificate signed by the local
/// step-ca intermediate CA.
///
/// Writes the certificate to `compose_dir/openbao/tls/server.{crt,key}`
/// with `0600` permissions.  `step certificate create` runs via Docker
/// (no step CLI required on the host).
pub(in crate::commands::init) fn issue_openbao_tls_cert(
    compose_dir: &Path,
    secrets_dir: &Path,
    sans: &[&str],
    messages: &Messages,
) -> Result<()> {
    let cert_path = compose_dir.join(OPENBAO_TLS_CERT_PATH);
    let key_path = compose_dir.join(OPENBAO_TLS_KEY_PATH);

    let mount_root = std::fs::canonicalize(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let secrets_mount = format!("{}:/home/step", mount_root.display());

    let tls_dir = compose_dir.join("openbao").join("tls");
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
        "openbao.internal",
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
        OPENBAO_TLS_DEFAULT_NOT_AFTER,
        "--force",
    ];

    run_docker(
        &args,
        "docker step certificate create (openbao tls)",
        messages,
    )
    .with_context(|| messages.error_openbao_tls_provision_failed())?;

    set_key_permissions_sync(&key_path)?;
    set_key_permissions_sync(&cert_path)?;

    println!(
        "{}",
        messages.info_openbao_tls_provisioned(&cert_path.display().to_string())
    );
    Ok(())
}

/// Rewrites `openbao.hcl` to enable TLS on the API listener.
///
/// Replaces `tls_disable = 1` on the `:8200` listener with
/// `tls_cert_file` and `tls_key_file` pointing to the container
/// mount paths.  The telemetry listener on `:9101` keeps plaintext.
pub(in crate::commands::init) fn write_openbao_hcl_with_tls(
    compose_dir: &Path,
    messages: &Messages,
) -> Result<()> {
    let hcl_path = compose_dir.join(OPENBAO_HCL_PATH);
    let content = format!(
        r#"storage "file" {{
  path = "/openbao/file"
}}

listener "tcp" {{
  address = "0.0.0.0:8200"
  tls_cert_file = "{OPENBAO_TLS_CONTAINER_CERT_PATH}"
  tls_key_file  = "{OPENBAO_TLS_CONTAINER_KEY_PATH}"
  telemetry {{
    disallow_metrics = true
  }}
}}

listener "tcp" {{
  address = "0.0.0.0:9101"
  tls_disable = 1
  telemetry {{
    metrics_only = true
    unauthenticated_metrics_access = true
  }}
}}

telemetry {{
  prometheus_retention_time = "30s"
  disable_hostname = true
}}

disable_mlock = true
ui = true
"#,
    );

    std::fs::write(&hcl_path, content)
        .with_context(|| messages.error_openbao_hcl_write_failed())?;

    println!("{}", messages.info_openbao_hcl_tls_written());
    Ok(())
}

/// Builds the SANs list for the `OpenBao` TLS certificate.
///
/// Always includes `openbao.internal` and `localhost`.  When a bind
/// address is configured, its IP component is added as well.  When an
/// advertise address is provided (wildcard bind), its IP is included
/// so that remote nodes connecting via the advertised endpoint pass
/// hostname verification.
pub(in crate::commands::init) fn build_openbao_tls_sans(
    bind_addr: &str,
    advertise_addr: Option<&str>,
) -> Vec<String> {
    let mut sans = vec![
        "openbao.internal".to_string(),
        "localhost".to_string(),
        "bootroot-openbao".to_string(),
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

/// Records the `OpenBao` TLS certificate in `StateFile::infra_certs`.
///
/// Stores the computed `sans` so that `reissue_openbao_tls_cert` can
/// reproduce the same SANs (including the bind-address IP) on renewal.
pub(in crate::commands::init) fn record_openbao_infra_cert(
    state: &mut StateFile,
    compose_dir: &Path,
    sans: Vec<String>,
) {
    let cert_path = compose_dir.join(OPENBAO_TLS_CERT_PATH);
    let key_path = compose_dir.join(OPENBAO_TLS_KEY_PATH);

    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default();

    let entry = InfraCertEntry {
        cert_path,
        key_path,
        sans,
        renew_before: OPENBAO_TLS_DEFAULT_RENEW_BEFORE.to_string(),
        reload_strategy: ReloadStrategy::ContainerRestart {
            container_name: OPENBAO_CONTAINER_NAME.to_string(),
        },
        issued_at: Some(now),
        expires_at: None,
    };

    state
        .infra_certs
        .insert(OPENBAO_INFRA_CERT_KEY.to_string(), entry);
}

/// Restores `openbao.hcl` to the default plaintext form with
/// `tls_disable = 1` on the API listener.
///
/// Called when a loopback reinstall clears a previous non-loopback
/// bind intent, ensuring `OpenBao` no longer expects TLS certificates
/// that are no longer being issued or renewed.
pub(crate) fn write_openbao_hcl_plaintext(compose_dir: &Path, messages: &Messages) -> Result<()> {
    let hcl_path = compose_dir.join(OPENBAO_HCL_PATH);
    if !hcl_path.exists() {
        return Ok(());
    }
    let content = r#"storage "file" {
  path = "/openbao/file"
}

listener "tcp" {
  address = "0.0.0.0:8200"
  tls_disable = 1
  telemetry {
    disallow_metrics = true
  }
}

listener "tcp" {
  address = "0.0.0.0:9101"
  tls_disable = 1
  telemetry {
    metrics_only = true
    unauthenticated_metrics_access = true
  }
}

telemetry {
  prometheus_retention_time = "30s"
  disable_hostname = true
}

disable_mlock = true
ui = true
"#;

    std::fs::write(&hcl_path, content)
        .with_context(|| messages.error_openbao_hcl_write_failed())?;

    println!("{}", messages.info_openbao_hcl_tls_reverted());
    Ok(())
}

fn set_key_permissions_sync(path: &Path) -> Result<()> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("Failed to set permissions on {}", path.display()))
}

/// Re-issues an existing `OpenBao` infrastructure certificate.
///
/// Used by the rotation pipeline to renew the cert before expiry.
pub(crate) fn reissue_openbao_tls_cert(
    compose_dir: &Path,
    secrets_dir: &Path,
    entry: &InfraCertEntry,
    messages: &Messages,
) -> Result<()> {
    let san_refs: Vec<&str> = entry.sans.iter().map(String::as_str).collect();
    let sans = if san_refs.is_empty() {
        vec!["openbao.internal", "localhost", "bootroot-openbao"]
    } else {
        san_refs
    };
    issue_openbao_tls_cert(compose_dir, secrets_dir, &sans, messages)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn build_sans_includes_specific_ip() {
        let sans = build_openbao_tls_sans("192.168.1.10:8200", None);
        assert!(sans.contains(&"openbao.internal".to_string()));
        assert!(sans.contains(&"localhost".to_string()));
        assert!(sans.contains(&"bootroot-openbao".to_string()));
        assert!(sans.contains(&"192.168.1.10".to_string()));
    }

    #[test]
    fn build_sans_wildcard_adds_loopback() {
        let sans = build_openbao_tls_sans("0.0.0.0:8200", None);
        assert!(sans.contains(&"127.0.0.1".to_string()));
        assert!(!sans.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_sans_ipv6_specific() {
        let sans = build_openbao_tls_sans("[fd12::1]:8200", None);
        assert!(sans.contains(&"fd12::1".to_string()));
    }

    #[test]
    fn build_sans_ipv6_wildcard() {
        let sans = build_openbao_tls_sans("[::]:8200", None);
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
        let sans = build_openbao_tls_sans("[::0]:8200", None);
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
    fn build_sans_wildcard_with_advertise_addr() {
        let sans = build_openbao_tls_sans("0.0.0.0:8200", Some("192.168.1.10:8200"));
        assert!(
            sans.contains(&"127.0.0.1".to_string()),
            "wildcard must include loopback"
        );
        assert!(
            sans.contains(&"192.168.1.10".to_string()),
            "advertise IP must be in SANs for remote hostname verification"
        );
        assert!(!sans.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_sans_wildcard_with_ipv6_advertise_addr() {
        let sans = build_openbao_tls_sans("[::]:8200", Some("[fd12::1]:8200"));
        assert!(sans.contains(&"::1".to_string()));
        assert!(sans.contains(&"127.0.0.1".to_string()));
        assert!(
            sans.contains(&"fd12::1".to_string()),
            "IPv6 advertise IP must be in SANs"
        );
    }

    #[test]
    fn build_sans_advertise_addr_not_duplicated() {
        let sans = build_openbao_tls_sans("192.168.1.10:8200", Some("192.168.1.10:8200"));
        let count = sans.iter().filter(|s| *s == "192.168.1.10").count();
        assert_eq!(count, 1, "advertise IP must not be duplicated");
    }

    #[test]
    fn record_openbao_infra_cert_inserts_entry() {
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
            infra_certs: BTreeMap::new(),
        };
        let sans = vec!["openbao.internal".to_string(), "localhost".to_string()];
        record_openbao_infra_cert(&mut state, dir.path(), sans);
        assert!(state.infra_certs.contains_key(OPENBAO_INFRA_CERT_KEY));
        let entry = &state.infra_certs[OPENBAO_INFRA_CERT_KEY];
        assert_eq!(
            entry.reload_strategy,
            ReloadStrategy::ContainerRestart {
                container_name: OPENBAO_CONTAINER_NAME.to_string(),
            }
        );
        assert!(entry.issued_at.is_some());
    }

    #[test]
    fn write_openbao_hcl_with_tls_creates_valid_hcl() {
        let dir = tempfile::tempdir().unwrap();
        let openbao_dir = dir.path().join("openbao");
        std::fs::create_dir_all(&openbao_dir).unwrap();
        let messages = crate::i18n::test_messages();
        write_openbao_hcl_with_tls(dir.path(), &messages).unwrap();
        let content = std::fs::read_to_string(dir.path().join(OPENBAO_HCL_PATH)).unwrap();
        assert!(content.contains("tls_cert_file"));
        assert!(content.contains("tls_key_file"));
        // API listener on :8200 must not have tls_disable.
        assert!(content.contains("address = \"0.0.0.0:8200\""));
        let api_block_start = content.find("address = \"0.0.0.0:8200\"").unwrap();
        let api_block = &content[..api_block_start + 200];
        assert!(!api_block.contains("tls_disable"));
        // Telemetry listener should still have tls_disable.
        assert!(content.contains("tls_disable = 1"));
    }

    #[test]
    fn write_openbao_hcl_plaintext_restores_tls_disable() {
        let dir = tempfile::tempdir().unwrap();
        let openbao_dir = dir.path().join("openbao");
        std::fs::create_dir_all(&openbao_dir).unwrap();
        let messages = crate::i18n::test_messages();
        // Start with TLS-enabled HCL.
        write_openbao_hcl_with_tls(dir.path(), &messages).unwrap();
        // Restore plaintext.
        write_openbao_hcl_plaintext(dir.path(), &messages).unwrap();
        let content = std::fs::read_to_string(dir.path().join(OPENBAO_HCL_PATH)).unwrap();
        assert!(
            !content.contains("tls_cert_file"),
            "plaintext HCL must not contain tls_cert_file"
        );
        // Both listeners must have tls_disable = 1.
        let tls_disable_count = content.matches("tls_disable = 1").count();
        assert_eq!(
            tls_disable_count, 2,
            "both listeners must have tls_disable = 1"
        );
    }

    #[test]
    fn write_openbao_hcl_plaintext_noop_when_no_hcl() {
        let dir = tempfile::tempdir().unwrap();
        let messages = crate::i18n::test_messages();
        // No openbao.hcl exists — must be a no-op, not an error.
        write_openbao_hcl_plaintext(dir.path(), &messages).unwrap();
        assert!(!dir.path().join(OPENBAO_HCL_PATH).exists());
    }
}
