use std::fmt::Write as _;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::cli::args::{CaRestartArgs, CaUpdateArgs};
use crate::commands::infra::{collect_container_failures, collect_readiness, run_docker};
use crate::commands::init::{
    RESPONDER_TEMPLATE_DIR, STEPCA_CA_JSON_TEMPLATE_NAME, set_acme_cert_duration,
};
use crate::i18n::Messages;

const CTMPL_PLACEHOLDER_PREFIX: &str = "__BOOTROOT_CTMPL_";
const CTMPL_PLACEHOLDER_SUFFIX: &str = "__";
const STEP_CA_SERVICE: &str = "step-ca";
const READINESS_TIMEOUT: Duration = Duration::from_secs(30);
const READINESS_POLL_INTERVAL: Duration = Duration::from_millis(500);

pub(crate) fn run_ca_update(args: &CaUpdateArgs, messages: &Messages) -> Result<()> {
    bootroot::config::validate_cert_duration_vs_default_renew_before(&args.cert_duration)?;

    let secrets_dir = &args.secrets_dir.secrets_dir;
    let ca_json_path = secrets_dir.join("config").join("ca.json");
    let ctmpl_path = secrets_dir
        .join(RESPONDER_TEMPLATE_DIR)
        .join(STEPCA_CA_JSON_TEMPLATE_NAME);

    patch_ca_json_ctmpl(
        &ctmpl_path,
        &args.cert_duration,
        &args.stepca_provisioner,
        messages,
    )
    .with_context(|| format!("failed to patch {}", ctmpl_path.display()))?;

    patch_ca_json(
        &ca_json_path,
        &args.cert_duration,
        &args.stepca_provisioner,
        messages,
    )
    .with_context(|| format!("failed to patch {}", ca_json_path.display()))?;

    println!(
        "Updated defaultTLSCertDuration in {} and {}.",
        ctmpl_path.display(),
        ca_json_path.display()
    );
    println!(
        "step-ca must be restarted for the change to take effect. \
         Run `bootroot ca restart` to restart the container."
    );
    Ok(())
}

pub(crate) fn run_ca_restart(args: &CaRestartArgs, messages: &Messages) -> Result<()> {
    let compose_str = args.compose_file.compose_file.to_string_lossy();
    let restart_args = ["compose", "-f", &*compose_str, "restart", STEP_CA_SERVICE];
    run_docker(&restart_args, "docker compose restart step-ca", messages)?;
    wait_for_stepca_ready(&args.compose_file.compose_file, messages)?;
    println!("step-ca has been restarted.");
    Ok(())
}

fn wait_for_stepca_ready(compose_file: &Path, messages: &Messages) -> Result<()> {
    let services = [STEP_CA_SERVICE.to_string()];
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        let failures = match collect_readiness(compose_file, None, &services, messages) {
            Ok(readiness) => collect_container_failures(&readiness),
            Err(err) => vec![err.to_string()],
        };
        if failures.is_empty() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "step-ca did not become ready within {}s after restart: {}",
                READINESS_TIMEOUT.as_secs(),
                failures.join(", "),
            );
        }
        sleep(READINESS_POLL_INTERVAL);
    }
}

fn patch_ca_json(
    path: &Path,
    cert_duration: &str,
    provisioner: &str,
    messages: &Messages,
) -> Result<()> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let mut value: serde_json::Value =
        serde_json::from_str(&contents).context(messages.error_parse_ca_json_failed())?;
    if !set_acme_cert_duration(&mut value, cert_duration, Some(provisioner)) {
        anyhow::bail!(
            "ca.json does not contain an ACME provisioner named {provisioner:?} — \
             cannot set defaultTLSCertDuration"
        );
    }
    let updated =
        serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())?;
    std::fs::write(path, updated)
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

fn patch_ca_json_ctmpl(
    path: &Path,
    cert_duration: &str,
    provisioner: &str,
    messages: &Messages,
) -> Result<()> {
    let contents = std::fs::read_to_string(path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let (masked, directives) = mask_go_template_directives(&contents);
    let mut value: serde_json::Value =
        serde_json::from_str(&masked).context(messages.error_parse_ca_json_failed())?;
    if !set_acme_cert_duration(&mut value, cert_duration, Some(provisioner)) {
        anyhow::bail!(
            "ca.json.ctmpl does not contain an ACME provisioner named {provisioner:?} — \
             cannot set defaultTLSCertDuration"
        );
    }
    let serialized =
        serde_json::to_string_pretty(&value).context(messages.error_serialize_ca_json_failed())?;
    let restored = unmask_go_template_directives(&serialized, &directives);
    std::fs::write(path, restored)
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

/// Replaces each `"{{ ... }}"` JSON-quoted Go template directive in
/// `contents` with a JSON-safe placeholder string.
///
/// The `OpenBao` Agent `ca.json.ctmpl` file embeds Go directives inside
/// quoted strings, which contain unescaped double quotes and therefore
/// cannot be parsed directly as JSON. Masking the directives yields
/// valid JSON that can be parsed, patched, and serialised.
fn mask_go_template_directives(contents: &str) -> (String, Vec<String>) {
    let mut result = String::with_capacity(contents.len());
    let mut directives: Vec<String> = Vec::new();
    let mut cursor = 0;
    while cursor < contents.len() {
        let Some(rel_start) = contents[cursor..].find("\"{{") else {
            result.push_str(&contents[cursor..]);
            break;
        };
        let start = cursor + rel_start;
        result.push_str(&contents[cursor..start]);
        // Find the closing `}}"` that terminates the directive's JSON string.
        let Some(rel_end) = contents[start + 1..].find("}}\"") else {
            result.push_str(&contents[start..]);
            break;
        };
        let end = start + 1 + rel_end + 3;
        let directive = contents[start..end].to_string();
        let idx = directives.len();
        directives.push(directive);
        let _ = write!(
            result,
            "\"{CTMPL_PLACEHOLDER_PREFIX}{idx}{CTMPL_PLACEHOLDER_SUFFIX}\""
        );
        cursor = end;
    }
    (result, directives)
}

fn unmask_go_template_directives(contents: &str, directives: &[String]) -> String {
    let mut result = contents.to_string();
    for (idx, directive) in directives.iter().enumerate() {
        let marker = format!("\"{CTMPL_PLACEHOLDER_PREFIX}{idx}{CTMPL_PLACEHOLDER_SUFFIX}\"");
        result = result.replace(&marker, directive);
    }
    result
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::cli::args::SecretsDirArgs;

    fn test_messages() -> Messages {
        crate::i18n::test_messages()
    }

    fn ca_update_args(secrets_dir: std::path::PathBuf, cert_duration: &str) -> CaUpdateArgs {
        CaUpdateArgs {
            secrets_dir: SecretsDirArgs { secrets_dir },
            stepca_provisioner: "acme".to_string(),
            cert_duration: cert_duration.to_string(),
        }
    }

    #[test]
    fn test_run_ca_update_rejects_duration_below_default_renew_before() {
        let dir = tempdir().unwrap();
        // Files intentionally not created: validation must fail before any I/O.
        let args = ca_update_args(dir.path().to_path_buf(), "1m");
        let err = run_ca_update(&args, &test_messages()).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("must exceed the default renew_before"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn test_run_ca_update_rejects_duration_equal_to_default_renew_before() {
        let dir = tempdir().unwrap();
        let args = ca_update_args(dir.path().to_path_buf(), "16h");
        let err = run_ca_update(&args, &test_messages()).unwrap_err();
        assert!(
            err.to_string()
                .contains("must exceed the default renew_before")
        );
    }

    fn sample_ctmpl() -> String {
        // Mimics the shape produced by `build_ca_json_template`: a
        // Go-template directive in the `dataSource` field surrounded by
        // otherwise valid JSON.
        r#"{
  "authority": {
    "provisioners": [
      {
        "type": "ACME",
        "name": "acme"
      }
    ]
  },
  "db": {
    "type": "postgresql",
    "dataSource": "{{ with secret "secret/data/bootroot/stepca/db" }}{{ .Data.data.value }}{{ end }}"
  }
}
"#
        .to_string()
    }

    #[test]
    fn test_mask_and_unmask_roundtrip() {
        let contents = sample_ctmpl();
        let (masked, directives) = mask_go_template_directives(&contents);
        assert_eq!(directives.len(), 1);
        assert!(!masked.contains("{{"));
        let restored = unmask_go_template_directives(&masked, &directives);
        assert_eq!(restored, contents);
    }

    #[test]
    fn test_patch_ca_json_ctmpl_inserts_cert_duration() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ca.json.ctmpl");
        std::fs::write(&path, sample_ctmpl()).unwrap();

        patch_ca_json_ctmpl(&path, "48h", "acme", &test_messages()).unwrap();

        let patched = std::fs::read_to_string(&path).unwrap();
        assert!(
            patched.contains("\"defaultTLSCertDuration\": \"48h\""),
            "patched ctmpl should contain the new duration: {patched}"
        );
        // Go directive should be preserved verbatim.
        assert!(patched.contains(
            "\"{{ with secret \"secret/data/bootroot/stepca/db\" }}{{ .Data.data.value }}{{ end }}\""
        ));
    }

    #[test]
    fn test_patch_ca_json_inserts_cert_duration() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ca.json");
        std::fs::write(
            &path,
            r#"{"authority":{"provisioners":[{"type":"ACME","name":"acme"}]}}"#,
        )
        .unwrap();

        patch_ca_json(&path, "72h", "acme", &test_messages()).unwrap();

        let patched = std::fs::read_to_string(&path).unwrap();
        assert!(patched.contains("\"defaultTLSCertDuration\": \"72h\""));
    }

    #[test]
    fn test_patch_ca_json_errors_without_acme_provisioner() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ca.json");
        std::fs::write(
            &path,
            r#"{"authority":{"provisioners":[{"type":"JWK","name":"admin"}]}}"#,
        )
        .unwrap();

        let err = patch_ca_json(&path, "48h", "acme", &test_messages()).unwrap_err();
        assert!(err.to_string().contains("ACME provisioner"));
    }

    #[test]
    fn test_patch_ca_json_errors_when_provisioner_name_mismatches() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("ca.json");
        std::fs::write(
            &path,
            r#"{"authority":{"provisioners":[{"type":"ACME","name":"staging"}]}}"#,
        )
        .unwrap();

        let err = patch_ca_json(&path, "48h", "acme", &test_messages()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ACME provisioner"), "unexpected error: {msg}");
    }
}
