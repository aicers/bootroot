use std::fmt::Write as _;
use std::path::Path;
use std::thread::sleep;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::fs_util::{RootedOwner, SecretsTree};

use crate::cli::args::{CaRestartArgs, CaUpdateArgs};
use crate::commands::compose_project::ComposeIdentity;
use crate::commands::infra::{collect_container_failures, collect_readiness, run_compose};
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
    let tree = SecretsTree::open(secrets_dir)?;
    let ca_json_path = secrets_dir.join("config").join("ca.json");
    let ctmpl_path = secrets_dir
        .join(RESPONDER_TEMPLATE_DIR)
        .join(STEPCA_CA_JSON_TEMPLATE_NAME);

    patch_ca_json_ctmpl(
        &tree,
        &ctmpl_path,
        &args.cert_duration,
        &args.stepca_provisioner,
        messages,
    )
    .with_context(|| format!("failed to patch {}", ctmpl_path.display()))?;

    patch_ca_json(
        &tree,
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
    let identity = ComposeIdentity::resolve(&args.compose_file.compose_file, None, messages)?;
    let restart = identity.compose(&[&compose_str], None, &["restart", STEP_CA_SERVICE]);
    run_compose(&restart, "docker compose restart step-ca", messages)?;
    wait_for_stepca_ready(&args.compose_file.compose_file, &identity, messages)?;
    println!("step-ca has been restarted.");
    Ok(())
}

fn wait_for_stepca_ready(
    compose_file: &Path,
    identity: &ComposeIdentity,
    messages: &Messages,
) -> Result<()> {
    let services = [STEP_CA_SERVICE.to_string()];
    let deadline = Instant::now() + READINESS_TIMEOUT;
    loop {
        let failures = match collect_readiness(compose_file, identity, None, &services, messages) {
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
    tree: &SecretsTree,
    path: &Path,
    cert_duration: &str,
    provisioner: &str,
    messages: &Messages,
) -> Result<()> {
    let contents = read_ca_json_text(tree, path, messages)?;
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
    publish_ca_json(tree, path, &updated, messages)
}

fn patch_ca_json_ctmpl(
    tree: &SecretsTree,
    path: &Path,
    cert_duration: &str,
    provisioner: &str,
    messages: &Messages,
) -> Result<()> {
    let contents = read_ca_json_text(tree, path, messages)?;
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
    publish_ca_json(tree, path, &restored, messages)
}

/// Reads `ca.json` or its template below the secrets directory: through
/// a rooted `tree` without following a name, by path otherwise.
fn read_ca_json_text(tree: &SecretsTree, path: &Path, messages: &Messages) -> Result<String> {
    if tree.is_rooted() {
        let bytes = tree
            .read(path)
            .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
        return String::from_utf8(bytes)
            .with_context(|| messages.error_read_file_failed(&path.display().to_string()));
    }
    std::fs::read_to_string(path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))
}

/// Publishes a patched `ca.json` — or its `.ctmpl` template — by rename.
///
/// step-ca reads `ca.json` at boot and the `OpenBao` Agent sidecar
/// re-renders it from the template on a fixed interval, so both files
/// have a reader that can arrive mid-write. Truncating in place let
/// either observe half a JSON document, which step-ca answers by
/// refusing to start; the rename leaves the previous document or the
/// complete new one.
///
/// The mode comes off the destination. Both files are read here before
/// they are written, so one always exists, and `init` — not this patch
/// — is what decides their mode. The create arm
/// [`fs_util::StagedMode::PreserveOrUmask`] carries is therefore
/// unreachable here; it is the right answer anyway, since a `ca.json`
/// this command found missing has no mode this crate gets to decide.
///
/// The directory is not flushed. Both are derived files: `ca.json` is
/// re-rendered from `ca.json.ctmpl` by the sidecar, and the template is
/// rebuilt from `ca.json` by `init`. A crash that loses the entry leaves
/// the previous document in place and costs the next render or a re-run
/// of `bootroot ca update`, not an unrecoverable state.
///
/// On a rooted `tree` the same publish goes through the handle: the
/// directories are walked without following a link, and a link at the
/// file itself is refused, since following it is what an operator-named
/// destination asks for and root must not.
fn publish_ca_json(
    tree: &SecretsTree,
    path: &Path,
    contents: &str,
    messages: &Messages,
) -> Result<()> {
    if tree.is_rooted() {
        return tree
            .publish(
                fs_util::Destination::operator_named(path),
                contents.as_bytes(),
                fs_util::StagedMode::PreserveOrUmask,
                RootedOwner::Destination,
                fs_util::StagedDurability::RenameOnly,
            )
            .with_context(|| messages.error_write_file_failed(&path.display().to_string()));
    }
    fs_util::atomic_replace_blocking(
        fs_util::Destination::operator_named(path),
        contents.as_bytes(),
        fs_util::StagedMode::PreserveOrUmask,
    )
    .with_context(|| messages.error_write_file_failed(&path.display().to_string()))
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

        patch_ca_json_ctmpl(
            &SecretsTree::open(dir.path()).unwrap(),
            &path,
            "48h",
            "acme",
            &test_messages(),
        )
        .unwrap();

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

        patch_ca_json(
            &SecretsTree::open(dir.path()).unwrap(),
            &path,
            "72h",
            "acme",
            &test_messages(),
        )
        .unwrap();

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

        let err = patch_ca_json(
            &SecretsTree::open(dir.path()).unwrap(),
            &path,
            "48h",
            "acme",
            &test_messages(),
        )
        .unwrap_err();
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

        let err = patch_ca_json(
            &SecretsTree::open(dir.path()).unwrap(),
            &path,
            "48h",
            "acme",
            &test_messages(),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ACME provisioner"), "unexpected error: {msg}");
    }

    const CA_JSON: &str = r#"{"authority":{"provisioners":[{"type":"ACME","name":"acme"}]}}"#;

    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    }

    /// Both patches refuse a link at the directory they walk, and at the
    /// file itself, and write nothing outside `secrets/`.
    #[test]
    fn rooted_patches_refuse_a_swapped_level_or_file() {
        let messages = test_messages();
        for (rel, dir_name) in [
            ("config/ca.json", "config"),
            ("templates/ca.json.ctmpl", "templates"),
        ] {
            let run_patch = |tree: &SecretsTree, path: &Path| {
                if dir_name == "config" {
                    patch_ca_json(tree, path, "48h", "acme", &messages)
                } else {
                    patch_ca_json_ctmpl(tree, path, "48h", "acme", &messages)
                }
            };
            let root = crate::test_support::SwapRoot::new();
            let contents = if dir_name == "config" {
                CA_JSON.to_string()
            } else {
                sample_ctmpl()
            };
            let path = root.write(rel, &contents);
            std::fs::write(root.outside.join(path.file_name().unwrap()), &contents).unwrap();
            let tree = root.rooted();
            let before = root.outside_snapshot();

            root.swap(rel, &root.outside.join(path.file_name().unwrap()));
            let err = run_patch(&tree, &path).expect_err("a link at the file");
            crate::test_support::assert_error_names(&err, &path);
            assert_eq!(root.outside_snapshot(), before, "{rel}");

            let link = root.swap(dir_name, &root.outside);
            let err = run_patch(&tree, &path).expect_err("a link at the directory");
            crate::test_support::assert_error_names(&err, &link);
            assert_eq!(root.outside_snapshot(), before, "{rel}");
        }
    }

    /// Over a tree the test's user owns, the rooted patch gives the bytes,
    /// the mode and the owner the path-based one gives.
    #[test]
    fn rooted_patches_match_the_path_based_patches() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let owner_of = |path: &Path| {
            let meta = std::fs::symlink_metadata(path).unwrap();
            (meta.uid(), meta.gid())
        };

        let messages = test_messages();
        let mut results = Vec::new();
        for rooted in [false, true] {
            let root = crate::test_support::SwapRoot::new();
            let ca_json = root.write("config/ca.json", CA_JSON);
            let ctmpl = root.write("templates/ca.json.ctmpl", &sample_ctmpl());
            std::fs::set_permissions(&ca_json, std::fs::Permissions::from_mode(0o640)).unwrap();
            let tree = if rooted {
                root.rooted()
            } else {
                SecretsTree::open(&root.secrets).unwrap()
            };
            patch_ca_json(&tree, &ca_json, "72h", "acme", &messages).unwrap();
            patch_ca_json_ctmpl(&tree, &ctmpl, "72h", "acme", &messages).unwrap();
            results.push((
                std::fs::read(&ca_json).unwrap(),
                mode_of(&ca_json),
                std::fs::read(&ctmpl).unwrap(),
                mode_of(&ctmpl),
                owner_of(&ca_json),
                owner_of(&ctmpl),
            ));
        }
        assert_eq!(results[0], results[1]);
        assert_eq!(results[1].1, 0o640, "the destination's mode is kept");
    }
}
