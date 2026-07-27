use std::io::ErrorKind;
use std::os::unix::fs::MetadataExt;
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
use crate::state::StateFile;

/// Wildcard bind literals that must never reach step-ca's `dnsNames`:
/// they name every local interface rather than a routable peer, and a
/// certificate carrying them satisfies no client's verification.
const WILDCARD_IPV4: &str = "0.0.0.0";
const WILDCARD_IPV6: &str = "::";
const WILDCARD_IPV6_ZERO: &str = "::0";

/// Loopback literals substituted for a wildcard bind, mirroring
/// `build_openbao_tls_sans`.
const LOOPBACK_IPV4: &str = "127.0.0.1";
const LOOPBACK_IPV6: &str = "::1";

/// Top-level `ca.json` key holding step-ca's own serving-certificate
/// name set.  step-ca splits the array at boot: entries that parse as
/// an IP become `iPAddress` SANs, the rest become `dNSName` SANs.
const CA_JSON_DNS_NAMES_KEY: &str = "dnsNames";

pub(super) async fn write_stepca_templates(
    secrets_dir: &Path,
    kv_mount: &str,
    cert_duration: &str,
    provisioner: &str,
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
    let ca_json_template = build_ca_json_template(
        &ca_json_contents,
        kv_mount,
        cert_duration,
        provisioner,
        messages,
    )?;
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

fn build_ca_json_template(
    contents: &str,
    kv_mount: &str,
    cert_duration: &str,
    provisioner: &str,
    messages: &Messages,
) -> Result<String> {
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

    if !set_acme_cert_duration(&mut value, cert_duration, Some(provisioner)) {
        anyhow::bail!(
            "ca.json does not contain an ACME provisioner named {provisioner:?} — \
             cannot set defaultTLSCertDuration in template"
        );
    }

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

/// Sets `claims.defaultTLSCertDuration` on ACME provisioners in the
/// parsed ca.json value.
///
/// When `provisioner_name` is `Some`, only the ACME provisioner whose
/// `name` matches is patched. When `None`, every ACME provisioner is
/// patched.
///
/// Accepts both the on-disk shape (`authority.provisioners`) and the
/// flat `provisioners` shape emitted by older `step ca init` builds.
pub(crate) fn set_acme_cert_duration(
    value: &mut serde_json::Value,
    cert_duration: &str,
    provisioner_name: Option<&str>,
) -> bool {
    let Some(provisioners) = locate_provisioners_mut(value) else {
        return false;
    };
    let mut patched = false;
    for provisioner in provisioners {
        if !is_acme_provisioner(provisioner) {
            continue;
        }
        if let Some(name) = provisioner_name
            && !provisioner_name_matches(provisioner, name)
        {
            continue;
        }
        let claims = provisioner
            .as_object_mut()
            .expect("is_acme_provisioner guarantees object")
            .entry("claims".to_string())
            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
        if let Some(obj) = claims.as_object_mut() {
            obj.insert(
                "defaultTLSCertDuration".to_string(),
                serde_json::Value::String(cert_duration.to_string()),
            );
            patched = true;
        }
    }
    patched
}

fn provisioner_name_matches(provisioner: &serde_json::Value, name: &str) -> bool {
    provisioner
        .get("name")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|n| n == name)
}

fn locate_provisioners_mut(value: &mut serde_json::Value) -> Option<&mut Vec<serde_json::Value>> {
    if value.get("authority").is_some() {
        return value
            .get_mut("authority")
            .and_then(|authority| authority.get_mut("provisioners"))
            .and_then(serde_json::Value::as_array_mut);
    }
    value
        .get_mut("provisioners")
        .and_then(serde_json::Value::as_array_mut)
}

fn is_acme_provisioner(provisioner: &serde_json::Value) -> bool {
    provisioner
        .get("type")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|t| t.eq_ignore_ascii_case("ACME"))
}

/// Extracts the IP component of a `host:port` address, unwrapping the
/// brackets that surround an IPv6 literal.
///
/// Returns `None` when the value carries no port separator or the host
/// part is empty.  The bind and advertise addresses reaching this point
/// have already been validated by `validate_stepca_bind` /
/// `validate_stepca_advertise_addr`, so this parser only has to survive
/// a malformed `state.json` without panicking.
fn addr_ip(addr: &str) -> Option<&str> {
    let (host_raw, _port) = addr.rsplit_once(':')?;
    let host = host_raw
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host_raw);
    if host.is_empty() { None } else { Some(host) }
}

fn push_unique(names: &mut Vec<String>, name: &str) {
    if !names.iter().any(|existing| existing == name) {
        names.push(name.to_string());
    }
}

fn is_wildcard(ip: &str) -> bool {
    matches!(ip, WILDCARD_IPV4 | WILDCARD_IPV6 | WILDCARD_IPV6_ZERO)
}

/// Builds the name set for step-ca's own serving certificate.
///
/// Always carries the three `DEFAULT_CA_DNS` names so that in-network
/// consumers keep verifying by container name.  A specific bind address
/// contributes its IP; an IPv4 wildcard bind maps to `127.0.0.1` and an
/// IPv6 wildcard to `::1` plus `127.0.0.1`; a recorded advertise
/// address contributes its IP too.  Wildcard literals are never emitted
/// and no name appears twice.
///
/// Mirrors `build_openbao_tls_sans` (`openbao_tls.rs`), which does the
/// same job for the `OpenBao` listener certificate.  The names are fed
/// to `step ca init --dns` on a fresh install and reconciled into
/// `ca.json`'s top-level `dnsNames` on every subsequent `init`.
pub(super) fn build_stepca_ca_dns_names(
    bind_addr: Option<&str>,
    advertise_addr: Option<&str>,
) -> Vec<String> {
    let mut names: Vec<String> = DEFAULT_CA_DNS.split(',').map(str::to_string).collect();

    if let Some(ip) = bind_addr.and_then(addr_ip) {
        match ip {
            WILDCARD_IPV4 => push_unique(&mut names, LOOPBACK_IPV4),
            WILDCARD_IPV6 | WILDCARD_IPV6_ZERO => {
                push_unique(&mut names, LOOPBACK_IPV6);
                push_unique(&mut names, LOOPBACK_IPV4);
            }
            specific => push_unique(&mut names, specific),
        }
    }

    if let Some(ip) = advertise_addr.and_then(addr_ip)
        && !is_wildcard(ip)
    {
        push_unique(&mut names, ip);
    }

    names
}

/// Reads the recorded step-ca bind intent from `state_path` and derives
/// the certificate name set from it.
///
/// Falls back to the three default names when no state file exists or
/// no bind intent is recorded — including after a loopback reinstall
/// cleared a previous intent, which is what makes the reconciliation
/// below shrink `dnsNames` back to the defaults.
pub(super) fn resolve_stepca_ca_dns_names(state_path: &Path) -> Result<Vec<String>> {
    if !state_path.exists() {
        return Ok(build_stepca_ca_dns_names(None, None));
    }
    let state = StateFile::load(state_path)?;
    Ok(build_stepca_ca_dns_names(
        state.stepca_bind_addr.as_deref(),
        state.stepca_advertise_addr.as_deref(),
    ))
}

/// Sets the top-level `dnsNames` array on a parsed `ca.json`, returning
/// whether the value actually changed.
///
/// Every other key — `db`, `authority.provisioners`, and anything
/// step-ca or an operator added that bootroot does not model — is left
/// untouched, so the caller can re-serialise the same document.
fn set_ca_json_dns_names(value: &mut serde_json::Value, dns_names: &[String]) -> bool {
    let desired = serde_json::Value::Array(
        dns_names
            .iter()
            .map(|name| serde_json::Value::String(name.clone()))
            .collect(),
    );
    if value.get(CA_JSON_DNS_NAMES_KEY) == Some(&desired) {
        return false;
    }
    if let Some(object) = value.as_object_mut() {
        object.insert(CA_JSON_DNS_NAMES_KEY.to_string(), desired);
        return true;
    }
    false
}

/// Outcome of `update_ca_json_with_backup`.
pub(super) struct CaJsonUpdate {
    /// Snapshot of the pre-update `ca.json` for the init rollback.
    pub(super) rollback: RollbackFile,
    /// Whether the reconciliation moved the top-level `dnsNames`.
    ///
    /// The caller restarts step-ca when this is set: step-ca derives its
    /// serving leaf from `dnsNames` at boot and holds it in memory, so
    /// only a restart re-issues it with the new name set.
    pub(super) dns_names_changed: bool,
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

/// Patches `ca.json` in place, backing the original up for rollback.
///
/// Rewrites the `db` section, the ACME provisioner's
/// `claims.defaultTLSCertDuration`, and the top-level `dnsNames` — the
/// last of these is what gives step-ca's own serving certificate the
/// address `--stepca-bind` publishes it on.  The document is parsed and
/// re-serialised rather than regenerated, so keys bootroot does not
/// model survive untouched.
pub(super) async fn update_ca_json_with_backup(
    secrets_dir: &Path,
    db_dsn: &str,
    cert_duration: &str,
    provisioner: &str,
    dns_names: &[String],
    messages: &Messages,
) -> Result<CaJsonUpdate> {
    let path = secrets_dir.join("config").join("ca.json");
    let contents = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&contents).context(messages.error_parse_ca_json_failed())?;
    value["db"]["type"] = serde_json::Value::String("postgresql".to_string());
    value["db"]["dataSource"] = serde_json::Value::String(db_dsn.to_string());
    if !set_acme_cert_duration(&mut value, cert_duration, Some(provisioner)) {
        anyhow::bail!(
            "ca.json does not contain an ACME provisioner named {provisioner:?} — \
             cannot set defaultTLSCertDuration"
        );
    }
    let dns_names_changed = set_ca_json_dns_names(&mut value, dns_names);
    let updated =
        serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())?;
    tokio::fs::write(&path, updated)
        .await
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(CaJsonUpdate {
        rollback: RollbackFile {
            path,
            original: Some(contents),
        },
        dns_names_changed,
    })
}

/// Runs `step ca init` when the CA does not exist yet.
///
/// `dns_names` becomes the `--dns` value, so a freshly created CA
/// serves a certificate that already covers the recorded step-ca bind
/// and advertise addresses.  An existing CA short-circuits with
/// `Skipped`; its name set is reconciled by `update_ca_json_with_backup`
/// instead, because re-running `step ca init` would replace the root
/// and intermediate keys and invalidate every issued certificate.
pub(super) fn ensure_step_ca_initialized(
    secrets_dir: &Path,
    dns_names: &[String],
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
    // Run as the owner of secrets_dir so generated files match the
    // host ownership, avoiding permission errors when fixing modes.
    let meta = std::fs::metadata(secrets_dir)
        .with_context(|| messages.error_resolve_path_failed(&secrets_dir.display().to_string()))?;
    let user_arg = format!("{}:{}", meta.uid(), meta.gid());
    // `step ca init --dns` takes one comma-separated value (unlike
    // `step certificate create --san`, which must be repeated).  IP
    // literals in this list land in `ca.json`'s `dnsNames`, which
    // step-ca splits into `dNSName` and `iPAddress` SANs at boot.
    let dns_arg = dns_names.join(",");
    let args = vec![
        "run",
        "--user",
        &user_arg,
        "--rm",
        "-v",
        &*mount,
        "smallstep/step-ca:0.30.2",
        "step",
        "ca",
        "init",
        "--name",
        DEFAULT_CA_NAME,
        "--provisioner",
        DEFAULT_CA_PROVISIONER,
        "--dns",
        &dns_arg,
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
            r#"{
                "authority":{"provisioners":[{"type":"ACME","name":"acme"}]},
                "db":{"type":"postgresql","dataSource":"old"}
            }"#,
        )
        .unwrap();

        let messages = test_messages();
        let paths = write_stepca_templates(&secrets_dir, "secret", "48h", "acme", &messages)
            .await
            .unwrap();
        let password_template = fs::read_to_string(&paths.password_template_path).unwrap();
        let ca_json_template = fs::read_to_string(&paths.ca_json_template_path).unwrap();

        assert!(password_template.contains("secret/data/bootroot/stepca/password"));
        assert!(ca_json_template.contains("secret/data/bootroot/stepca/db"));
    }

    #[test]
    fn test_set_acme_cert_duration_patches_nested_provisioner() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"authority":{"provisioners":[{"type":"ACME","name":"acme"}]}}"#,
        )
        .unwrap();
        let patched = set_acme_cert_duration(&mut value, "48h", None);
        assert!(patched);
        let duration = value["authority"]["provisioners"][0]["claims"]["defaultTLSCertDuration"]
            .as_str()
            .unwrap();
        assert_eq!(duration, "48h");
    }

    #[test]
    fn test_set_acme_cert_duration_skips_non_acme() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"authority":{"provisioners":[{"type":"JWK","name":"admin"}]}}"#,
        )
        .unwrap();
        let patched = set_acme_cert_duration(&mut value, "48h", None);
        assert!(!patched);
    }

    #[test]
    fn test_set_acme_cert_duration_matches_by_name() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"authority":{"provisioners":[
                {"type":"ACME","name":"acme"},
                {"type":"ACME","name":"staging"}
            ]}}"#,
        )
        .unwrap();
        let patched = set_acme_cert_duration(&mut value, "72h", Some("staging"));
        assert!(patched);
        assert!(
            value["authority"]["provisioners"][0]
                .get("claims")
                .is_none()
        );
        assert_eq!(
            value["authority"]["provisioners"][1]["claims"]["defaultTLSCertDuration"]
                .as_str()
                .unwrap(),
            "72h"
        );
    }

    #[test]
    fn test_set_acme_cert_duration_name_filter_misses_return_false() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"authority":{"provisioners":[{"type":"ACME","name":"acme"}]}}"#,
        )
        .unwrap();
        let patched = set_acme_cert_duration(&mut value, "48h", Some("nonexistent"));
        assert!(!patched);
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

        let dns_names = build_stepca_ca_dns_names(None, None);
        let result =
            ensure_step_ca_initialized(&secrets_dir, &dns_names, &test_messages()).unwrap();
        assert_eq!(result, StepCaInitResult::Skipped);
    }

    #[test]
    fn test_step_ca_init_requires_password_when_missing_files() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        fs::create_dir_all(&secrets_dir).unwrap();

        let dns_names = build_stepca_ca_dns_names(None, None);
        let err =
            ensure_step_ca_initialized(&secrets_dir, &dns_names, &test_messages()).unwrap_err();
        assert!(err.to_string().contains("step-ca password file not found"));
    }

    const CA_JSON_FIXTURE: &str = r#"{
        "root": "/home/step/certs/root_ca.crt",
        "dnsNames": ["localhost", "bootroot-ca", "stepca.internal"],
        "db": {"type": "badger", "dataSource": "/home/step/db"},
        "authority": {"provisioners": [
            {"type": "JWK", "name": "admin"},
            {"type": "ACME", "name": "acme", "claims": {"defaultTLSCertDuration": "24h"}}
        ]},
        "bootrootUnknownKey": {"nested": [1, 2, 3]}
    }"#;

    fn write_ca_json(secrets_dir: &Path, contents: &str) {
        fs::create_dir_all(secrets_dir.join("config")).unwrap();
        fs::write(secrets_dir.join("config").join("ca.json"), contents).unwrap();
    }

    fn read_ca_json(secrets_dir: &Path) -> serde_json::Value {
        let raw = fs::read_to_string(secrets_dir.join("config").join("ca.json")).unwrap();
        serde_json::from_str(&raw).unwrap()
    }

    fn dns_names_of(value: &serde_json::Value) -> Vec<String> {
        value
            .get("dnsNames")
            .and_then(serde_json::Value::as_array)
            .expect("dnsNames must be an array")
            .iter()
            .map(|entry| entry.as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[test]
    fn build_ca_dns_names_defaults_without_bind_intent() {
        let names = build_stepca_ca_dns_names(None, None);
        assert_eq!(names, vec!["localhost", "bootroot-ca", "stepca.internal"]);
    }

    #[test]
    fn build_ca_dns_names_includes_specific_ipv4() {
        let names = build_stepca_ca_dns_names(Some("192.168.139.144:9000"), None);
        assert!(names.contains(&"localhost".to_string()));
        assert!(names.contains(&"bootroot-ca".to_string()));
        assert!(names.contains(&"stepca.internal".to_string()));
        assert!(names.contains(&"192.168.139.144".to_string()));
    }

    #[test]
    fn build_ca_dns_names_includes_specific_ipv6() {
        let names = build_stepca_ca_dns_names(Some("[fd12::1]:9000"), None);
        assert!(names.contains(&"fd12::1".to_string()));
    }

    #[test]
    fn build_ca_dns_names_ipv4_wildcard_maps_to_loopback() {
        let names = build_stepca_ca_dns_names(Some("0.0.0.0:9000"), None);
        assert!(names.contains(&"127.0.0.1".to_string()));
        assert!(!names.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_ca_dns_names_ipv6_wildcard_maps_to_both_loopbacks() {
        let names = build_stepca_ca_dns_names(Some("[::]:9000"), None);
        assert!(
            names.contains(&"::1".to_string()),
            "IPv6 wildcard must include the IPv6 loopback"
        );
        assert!(
            names.contains(&"127.0.0.1".to_string()),
            "IPv6 wildcard must also include the IPv4 loopback for dual-stack"
        );
        assert!(!names.contains(&"::".to_string()));
    }

    #[test]
    fn build_ca_dns_names_ipv6_zero_wildcard_maps_to_both_loopbacks() {
        let names = build_stepca_ca_dns_names(Some("[::0]:9000"), None);
        assert!(names.contains(&"::1".to_string()));
        assert!(names.contains(&"127.0.0.1".to_string()));
        assert!(!names.contains(&"::0".to_string()));
    }

    #[test]
    fn build_ca_dns_names_wildcard_with_advertise_addr() {
        let names = build_stepca_ca_dns_names(Some("0.0.0.0:9000"), Some("192.168.139.144:9000"));
        assert!(names.contains(&"127.0.0.1".to_string()));
        assert!(
            names.contains(&"192.168.139.144".to_string()),
            "advertise IP must be present for off-host hostname verification"
        );
        assert!(!names.contains(&"0.0.0.0".to_string()));
    }

    #[test]
    fn build_ca_dns_names_advertise_equal_to_bind_is_not_duplicated() {
        let names =
            build_stepca_ca_dns_names(Some("192.168.139.144:9000"), Some("192.168.139.144:9000"));
        let count = names.iter().filter(|n| *n == "192.168.139.144").count();
        assert_eq!(count, 1, "advertise IP must not be duplicated");
    }

    /// `validate_stepca_bind` gates what reaches `state.json`, but a
    /// hand-edited or truncated file must not panic or smuggle a
    /// nonsense name into the certificate — it degrades to the defaults.
    #[test]
    fn build_ca_dns_names_ignores_malformed_addresses() {
        let defaults = vec!["localhost", "bootroot-ca", "stepca.internal"];
        for malformed in ["", "192.168.139.144", ":9000", "[]:9000"] {
            assert_eq!(
                build_stepca_ca_dns_names(Some(malformed), None),
                defaults,
                "malformed bind {malformed:?} must contribute no name"
            );
            assert_eq!(
                build_stepca_ca_dns_names(None, Some(malformed)),
                defaults,
                "malformed advertise {malformed:?} must contribute no name"
            );
        }
    }

    /// A wildcard recorded as the *advertise* address names no routable
    /// peer, so it must be dropped rather than written into the
    /// certificate.
    #[test]
    fn build_ca_dns_names_drops_wildcard_advertise_addr() {
        for wildcard in ["0.0.0.0:9000", "[::]:9000", "[::0]:9000"] {
            let names = build_stepca_ca_dns_names(Some("192.168.139.144:9000"), Some(wildcard));
            assert!(
                !names
                    .iter()
                    .any(|n| n == "0.0.0.0" || n == "::" || n == "::0")
            );
            assert!(names.contains(&"192.168.139.144".to_string()));
        }
    }

    #[test]
    fn resolve_ca_dns_names_defaults_when_state_missing() {
        let temp_dir = tempdir().unwrap();
        let names = resolve_stepca_ca_dns_names(&temp_dir.path().join("state.json")).unwrap();
        assert_eq!(names, vec!["localhost", "bootroot-ca", "stepca.internal"]);
    }

    #[test]
    fn resolve_ca_dns_names_reads_recorded_intent() {
        let temp_dir = tempdir().unwrap();
        let state_path = temp_dir.path().join("state.json");
        let state = StateFile {
            stepca_bind_addr: Some("0.0.0.0:9000".to_string()),
            stepca_advertise_addr: Some("192.168.139.144:9000".to_string()),
            ..Default::default()
        };
        state.save(&state_path).unwrap();

        let names = resolve_stepca_ca_dns_names(&state_path).unwrap();
        assert!(names.contains(&"127.0.0.1".to_string()));
        assert!(names.contains(&"192.168.139.144".to_string()));
    }

    #[tokio::test]
    async fn update_ca_json_rewrites_only_dns_names_and_is_idempotent() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(&secrets_dir, CA_JSON_FIXTURE);
        let messages = test_messages();
        let dns_names = build_stepca_ca_dns_names(Some("192.168.139.144:9000"), None);

        let first = update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "48h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        assert!(first.dns_names_changed);

        let after_first = read_ca_json(&secrets_dir);
        assert_eq!(dns_names_of(&after_first), dns_names);
        assert_eq!(after_first["db"]["type"].as_str().unwrap(), "postgresql");
        assert_eq!(
            after_first["db"]["dataSource"].as_str().unwrap(),
            "postgresql://step@postgres:5432/stepca"
        );
        assert_eq!(
            after_first["authority"]["provisioners"][1]["claims"]["defaultTLSCertDuration"]
                .as_str()
                .unwrap(),
            "48h"
        );
        // The JWK admin provisioner and unmodelled keys survive.
        assert_eq!(
            after_first["authority"]["provisioners"][0]["name"]
                .as_str()
                .unwrap(),
            "admin"
        );
        assert!(
            after_first["authority"]["provisioners"][0]
                .get("claims")
                .is_none()
        );
        assert_eq!(
            after_first["bootrootUnknownKey"]["nested"],
            serde_json::json!([1, 2, 3])
        );
        assert_eq!(
            after_first["root"].as_str().unwrap(),
            "/home/step/certs/root_ca.crt"
        );

        let second = update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "48h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        assert!(
            !second.dns_names_changed,
            "a second init with the same recorded intent must not move dnsNames"
        );
        let after_second = read_ca_json(&secrets_dir);
        assert_eq!(after_first, after_second, "second run must be a no-op");
    }

    #[tokio::test]
    async fn update_ca_json_restores_defaults_without_bind_intent() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(
            &secrets_dir,
            r#"{
                "dnsNames": ["localhost", "bootroot-ca", "stepca.internal", "192.168.139.144"],
                "db": {"type": "postgresql", "dataSource": "old"},
                "authority": {"provisioners": [{"type": "ACME", "name": "acme"}]}
            }"#,
        );
        let messages = test_messages();
        let dns_names = build_stepca_ca_dns_names(None, None);

        let update = update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "24h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        assert!(update.dns_names_changed);
        assert_eq!(
            dns_names_of(&read_ca_json(&secrets_dir)),
            vec!["localhost", "bootroot-ca", "stepca.internal"],
            "clearing the bind intent must shrink dnsNames back to the defaults"
        );
    }

    #[tokio::test]
    async fn stepca_template_carries_reconciled_dns_names() {
        let temp_dir = tempdir().unwrap();
        let secrets_dir = temp_dir.path().join("secrets");
        write_ca_json(&secrets_dir, CA_JSON_FIXTURE);
        let messages = test_messages();
        let dns_names = build_stepca_ca_dns_names(Some("0.0.0.0:9000"), Some("10.1.2.3:9000"));

        update_ca_json_with_backup(
            &secrets_dir,
            "postgresql://step@postgres:5432/stepca",
            "48h",
            "acme",
            &dns_names,
            &messages,
        )
        .await
        .unwrap();
        let paths = write_stepca_templates(&secrets_dir, "secret", "48h", "acme", &messages)
            .await
            .unwrap();

        // The .ctmpl embeds a raw Go template directive in place of the
        // DSN string, so it is not valid JSON — compare the rendered
        // `dnsNames` array textually against the on-disk ca.json.
        let template = fs::read_to_string(&paths.ca_json_template_path).unwrap();
        let on_disk = read_ca_json(&secrets_dir);
        assert_eq!(dns_names_of(&on_disk), dns_names);
        for name in &dns_names {
            assert!(
                template.contains(&format!("\"{name}\"")),
                "ca.json.ctmpl must carry the reconciled name {name}"
            );
        }
        let rendered_dns = serde_json::to_string_pretty(&serde_json::json!({
            "dnsNames": on_disk.get("dnsNames").cloned().unwrap_or_default()
        }))
        .unwrap();
        let dns_block = rendered_dns
            .trim_start_matches('{')
            .trim_end_matches('}')
            .trim();
        assert!(
            template.contains(dns_block),
            "ca.json.ctmpl dnsNames must match the on-disk ca.json exactly"
        );
    }
}
