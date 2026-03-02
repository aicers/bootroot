use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::openbao::OpenBaoClient;
use serde::{Deserialize, Serialize};

use crate::commands::init::{CA_TRUST_KEY, PATH_CA_TRUST};
use crate::i18n::Messages;
use crate::state::ServiceEntry;

const CA_BUNDLE_PEM_KEY: &str = "ca_bundle_pem";
const SERVICE_KV_BASE: &str = "bootroot/services";
const SERVICE_TRUST_KV_SUFFIX: &str = "trust";
const ROTATION_STATE_FILENAME: &str = "rotation-state.json";

/// Describes which CA components are included in the rotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum RotationMode {
    /// Rotates only the intermediate CA key (root CA stays unchanged).
    #[serde(rename = "intermediate-only")]
    IntermediateOnly,
    /// Rotates both root and intermediate CA keys.
    #[serde(rename = "full")]
    Full,
}

/// Tracks CA key rotation progress for idempotency and concurrency control.
#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct RotationState {
    pub(crate) mode: RotationMode,
    pub(crate) started_at: String,
    pub(crate) old_root_fp: String,
    pub(crate) new_root_fp: String,
    pub(crate) old_intermediate_fp: String,
    pub(crate) new_intermediate_fp: String,
    pub(crate) phase: u8,
}

/// Returns the path to `rotation-state.json` in the given directory.
pub(crate) fn rotation_state_path(state_dir: &Path) -> PathBuf {
    state_dir.join(ROTATION_STATE_FILENAME)
}

/// Creates `rotation-state.json` atomically using `O_EXCL`.
///
/// Returns `Ok(())` if the file was created, or an error if it already exists.
pub(crate) fn create_rotation_state(
    state_dir: &Path,
    state: &RotationState,
    messages: &Messages,
) -> Result<()> {
    let path = rotation_state_path(state_dir);
    let json = serde_json::to_string_pretty(state)
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    file.write_all(json.as_bytes())
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

/// Updates `rotation-state.json` via temp-file + rename for crash safety.
pub(crate) fn update_rotation_state(
    state_dir: &Path,
    state: &RotationState,
    messages: &Messages,
) -> Result<()> {
    let path = rotation_state_path(state_dir);
    let json = serde_json::to_string_pretty(state)
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    let temp_path = state_dir.join(format!(
        "{ROTATION_STATE_FILENAME}.tmp.{}.{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::write(&temp_path, json.as_bytes())
        .with_context(|| messages.error_write_file_failed(&temp_path.display().to_string()))?;
    fs::rename(&temp_path, &path)
        .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    Ok(())
}

/// Loads `rotation-state.json` if it exists. Returns `None` if absent.
pub(crate) fn load_rotation_state(
    state_dir: &Path,
    messages: &Messages,
) -> Result<Option<RotationState>> {
    let path = rotation_state_path(state_dir);
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)
        .with_context(|| messages.error_read_file_failed(&path.display().to_string()))?;
    let state: RotationState = serde_json::from_str(&contents)
        .with_context(|| messages.error_rotation_state_corrupt(&path.display().to_string()))?;
    Ok(Some(state))
}

/// Deletes `rotation-state.json`.
pub(crate) fn delete_rotation_state(state_dir: &Path, messages: &Messages) -> Result<()> {
    let path = rotation_state_path(state_dir);
    if path.exists() {
        fs::remove_file(&path)
            .with_context(|| messages.error_write_file_failed(&path.display().to_string()))?;
    }
    Ok(())
}

/// Writes trust payload (fingerprints and CA bundle PEM) to the `OpenBao`
/// global CA path and all per-service trust paths.
pub(crate) async fn write_trust_to_openbao(
    client: &OpenBaoClient,
    kv_mount: &str,
    services: &BTreeMap<String, ServiceEntry>,
    fingerprints: &[String],
    ca_bundle_pem: &str,
    messages: &Messages,
) -> Result<()> {
    client
        .write_kv(
            kv_mount,
            PATH_CA_TRUST,
            serde_json::json!({
                CA_TRUST_KEY: fingerprints,
                CA_BUNDLE_PEM_KEY: ca_bundle_pem,
            }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())?;

    for entry in services.values() {
        write_service_trust(
            client,
            kv_mount,
            &entry.service_name,
            fingerprints,
            ca_bundle_pem,
            messages,
        )
        .await?;
    }

    Ok(())
}

/// Writes trust payload to a single service's trust path in `OpenBao`.
pub(crate) async fn write_service_trust(
    client: &OpenBaoClient,
    kv_mount: &str,
    service_name: &str,
    fingerprints: &[String],
    ca_bundle_pem: &str,
    messages: &Messages,
) -> Result<()> {
    client
        .write_kv(
            kv_mount,
            &format!("{SERVICE_KV_BASE}/{service_name}/{SERVICE_TRUST_KV_SUFFIX}"),
            serde_json::json!({
                CA_TRUST_KEY: fingerprints,
                CA_BUNDLE_PEM_KEY: ca_bundle_pem,
            }),
        )
        .await
        .with_context(|| messages.error_openbao_kv_write_failed())
}

/// Returns `true` if `rotation-state.json` exists in the given directory,
/// indicating that a CA key rotation is in progress.
pub(crate) fn rotation_in_progress(state_dir: &Path) -> bool {
    state_dir.join(ROTATION_STATE_FILENAME).exists()
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::i18n::Messages;

    fn test_messages() -> Messages {
        Messages::new("en").expect("valid language")
    }

    fn sample_state() -> RotationState {
        RotationState {
            mode: RotationMode::IntermediateOnly,
            started_at: "2026-03-01T10:00:00Z".to_string(),
            old_root_fp: "aaa".to_string(),
            new_root_fp: "aaa".to_string(),
            old_intermediate_fp: "bbb".to_string(),
            new_intermediate_fp: String::new(),
            phase: 0,
        }
    }

    #[test]
    fn create_and_load_rotation_state_round_trips() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let state = sample_state();

        create_rotation_state(dir.path(), &state, &messages).expect("create");
        let loaded = load_rotation_state(dir.path(), &messages)
            .expect("load")
            .expect("should be Some");

        assert_eq!(loaded.mode, RotationMode::IntermediateOnly);
        assert_eq!(loaded.phase, 0);
        assert_eq!(loaded.old_root_fp, "aaa");
    }

    #[test]
    fn create_rotation_state_conflict_returns_error() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let state = sample_state();

        create_rotation_state(dir.path(), &state, &messages).expect("first create");
        let result = create_rotation_state(dir.path(), &state, &messages);
        assert!(result.is_err(), "second create should fail with O_EXCL");
    }

    #[test]
    fn load_rotation_state_missing_returns_none() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        let loaded = load_rotation_state(dir.path(), &messages).expect("load");
        assert!(loaded.is_none(), "missing file should return None");
    }

    #[test]
    fn load_rotation_state_corrupt_json_returns_error() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        fs::write(rotation_state_path(dir.path()), "NOT VALID JSON").expect("write corrupt");
        let result = load_rotation_state(dir.path(), &messages);
        assert!(result.is_err(), "corrupt JSON should return error");
    }

    #[test]
    fn update_rotation_state_advances_phase() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let mut state = sample_state();

        create_rotation_state(dir.path(), &state, &messages).expect("create");

        state.phase = 3;
        state.new_intermediate_fp = "ddd".to_string();
        update_rotation_state(dir.path(), &state, &messages).expect("update");

        let loaded = load_rotation_state(dir.path(), &messages)
            .expect("load")
            .expect("should be Some");
        assert_eq!(loaded.phase, 3);
        assert_eq!(loaded.new_intermediate_fp, "ddd");
    }

    #[test]
    fn delete_rotation_state_removes_file() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let state = sample_state();

        create_rotation_state(dir.path(), &state, &messages).expect("create");
        assert!(rotation_state_path(dir.path()).exists());

        delete_rotation_state(dir.path(), &messages).expect("delete");
        assert!(!rotation_state_path(dir.path()).exists());
    }

    #[test]
    fn delete_rotation_state_noop_when_absent() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();

        let result = delete_rotation_state(dir.path(), &messages);
        assert!(result.is_ok(), "deleting absent file should succeed");
    }

    #[test]
    fn rotation_in_progress_reflects_file_presence() {
        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let state = sample_state();

        assert!(!rotation_in_progress(dir.path()));

        create_rotation_state(dir.path(), &state, &messages).expect("create");
        assert!(rotation_in_progress(dir.path()));

        delete_rotation_state(dir.path(), &messages).expect("delete");
        assert!(!rotation_in_progress(dir.path()));
    }

    #[test]
    fn rotation_mode_serializes_to_intermediate_only_string() {
        let json = serde_json::to_string(&RotationMode::IntermediateOnly).expect("serialize");
        assert_eq!(json, "\"intermediate-only\"");

        let mode: RotationMode =
            serde_json::from_str("\"intermediate-only\"").expect("deserialize");
        assert_eq!(mode, RotationMode::IntermediateOnly);
    }

    #[test]
    fn rotation_mode_serializes_to_full_string() {
        let json = serde_json::to_string(&RotationMode::Full).expect("serialize");
        assert_eq!(json, "\"full\"");

        let mode: RotationMode = serde_json::from_str("\"full\"").expect("deserialize");
        assert_eq!(mode, RotationMode::Full);
    }
}
