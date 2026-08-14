use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use bootroot::fs_util;
use bootroot::openbao::OpenBaoClient;
use bootroot::trust_bootstrap::CA_BUNDLE_PEM_KEY;
use serde::{Deserialize, Serialize};

use crate::commands::constants::{CA_TRUST_KEY, SERVICE_KV_BASE};
use crate::commands::init::PATH_CA_TRUST;
use crate::i18n::Messages;
use crate::state::ServiceEntry;

pub(crate) const SERVICE_TRUST_KV_SUFFIX: &str = "trust";
const ROTATION_STATE_FILENAME: &str = "rotation-state.json";

/// Mode for `rotation-state.json`. Only the rotation command writes
/// and reads it, so it is created owner-only rather than at whatever
/// the umask happens to be — and the same mode on both write paths,
/// so the file does not change permissions depending on which one ran.
const ROTATION_STATE_MODE: u32 = 0o600;

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
/// Publishing by creation leaves the new directory entry unflushed
/// exactly as a rename does, so the containing directory is flushed
/// after the create — otherwise phase 0 of a rotation would be the one
/// record in the file's life that a power loss can erase, while
/// [`update_rotation_state`] carries every later one through
/// `atomic_write_blocking`'s own flush.
///
/// Callers in an async context use [`create_rotation_state_async`]
/// instead, which runs the same blocking core on a blocking thread —
/// the create, the file flush and the directory flush are each a disk
/// round trip and must not run on a runtime thread.
///
/// Returns `Ok(())` if the file was created, or an error if it already exists.
// The only production caller of a rotation-state writer is
// `rotate_ca_key`, which is async and so goes through the wrapper
// below. This is the entry point for a synchronous one, and is what the
// unit tests below call; keeping it means a future non-async caller does
// not have to unpick the wrapper to find the blocking core.
#[allow(dead_code)]
pub(crate) fn create_rotation_state(
    state_dir: &Path,
    state: &RotationState,
    messages: &Messages,
) -> Result<()> {
    let path = rotation_state_path(state_dir);
    let write_failed = messages.error_write_file_failed(&path.display().to_string());
    let json = serialize_rotation_state(state, &write_failed)?;
    create_rotation_state_file(&path, &json, &write_failed)
}

/// Async entry point for [`create_rotation_state`].
///
/// The JSON and the failure message are built here, on the async side,
/// so neither `&Messages` nor `&RotationState` has to cross into the
/// `'static` closure: only the owned path, payload and message do.
///
/// # Errors
/// Returns an error under the same conditions as
/// [`create_rotation_state`], or if the blocking task cannot be joined.
pub(crate) async fn create_rotation_state_async(
    state_dir: &Path,
    state: &RotationState,
    messages: &Messages,
) -> Result<()> {
    let path = rotation_state_path(state_dir);
    let write_failed = messages.error_write_file_failed(&path.display().to_string());
    let json = serialize_rotation_state(state, &write_failed)?;
    tokio::task::spawn_blocking(move || create_rotation_state_file(&path, &json, &write_failed))
        .await
        .context("Rotation state create task panicked")?
}

/// The blocking core shared by both entry points: create, write, flush
/// the file, then flush the directory that now names it.
fn create_rotation_state_file(path: &Path, json: &str, write_failed: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(ROTATION_STATE_MODE)
        .open(path)
        .with_context(|| write_failed.to_string())?;
    file.write_all(json.as_bytes())
        .with_context(|| write_failed.to_string())?;
    file.sync_all().with_context(|| write_failed.to_string())?;
    fs_util::sync_parent_dir(path).with_context(|| write_failed.to_string())?;
    Ok(())
}

/// Updates `rotation-state.json` via temp-file + rename for crash safety.
///
/// Callers in an async context use [`update_rotation_state_async`]
/// instead, which runs the same blocking core on a blocking thread.
// Test-only today, for the same reason as `create_rotation_state`.
#[allow(dead_code)]
pub(crate) fn update_rotation_state(
    state_dir: &Path,
    state: &RotationState,
    messages: &Messages,
) -> Result<()> {
    let path = rotation_state_path(state_dir);
    let write_failed = messages.error_write_file_failed(&path.display().to_string());
    let json = serialize_rotation_state(state, &write_failed)?;
    update_rotation_state_file(&path, &json, &write_failed)
}

/// Async entry point for [`update_rotation_state`].
///
/// Moves only owned data into the blocking closure, exactly as
/// [`create_rotation_state_async`] does.
///
/// # Errors
/// Returns an error under the same conditions as
/// [`update_rotation_state`], or if the blocking task cannot be joined.
pub(crate) async fn update_rotation_state_async(
    state_dir: &Path,
    state: &RotationState,
    messages: &Messages,
) -> Result<()> {
    let path = rotation_state_path(state_dir);
    let write_failed = messages.error_write_file_failed(&path.display().to_string());
    let json = serialize_rotation_state(state, &write_failed)?;
    tokio::task::spawn_blocking(move || update_rotation_state_file(&path, &json, &write_failed))
        .await
        .context("Rotation state update task panicked")?
}

/// The blocking core shared by both entry points; the file flush, the
/// rename and the directory flush all live in `atomic_write_blocking`.
fn update_rotation_state_file(path: &Path, json: &str, write_failed: &str) -> Result<()> {
    fs_util::atomic_write_blocking(path, json.as_bytes(), ROTATION_STATE_MODE)
        .with_context(|| write_failed.to_string())
}

/// Renders the state as the pretty-printed JSON both writers publish,
/// on the caller's thread: it touches no disk and the async wrappers
/// need the result before the blocking boundary anyway, since
/// `RotationState` is not `Clone` and cannot be moved into the closure.
fn serialize_rotation_state(state: &RotationState, write_failed: &str) -> Result<String> {
    serde_json::to_string_pretty(state).with_context(|| write_failed.to_string())
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
    use crate::i18n::test_messages;

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

    /// Phase 0 is published by `O_EXCL` creation rather than by rename,
    /// so its directory flush is its own call and not the one inside
    /// `atomic_write_blocking` that carries every later phase. Dropping
    /// it would leave the first record the only undurable one, which is
    /// exactly the shape this pins: with the state directory
    /// write-and-search-only the create still lands and only the flush's
    /// directory open fails.
    #[test]
    fn create_rotation_state_reports_a_directory_it_cannot_flush() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let state = sample_state();
        let restrict = |mode| {
            fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).expect("chmod");
        };

        restrict(0o300);
        if std::fs::File::open(dir.path()).is_ok() {
            // Effective root, or a filesystem that ignores the mode:
            // the flush cannot be made to fail here.
            restrict(0o700);
            return;
        }
        let result = create_rotation_state(dir.path(), &state, &messages);
        restrict(0o700);

        let err = result.expect_err("an unflushable directory must be reported");
        assert!(
            format!("{err:#}").contains("to fsync it"),
            "the directory flush must be the reported failure, got: {err:#}"
        );
        assert!(
            rotation_state_path(dir.path()).exists(),
            "the create landed; only its durability was not established"
        );
    }

    /// The async wrapper must carry the same failure the synchronous
    /// writer does: the closure runs on a blocking thread, and both the
    /// create and the directory flush it reports have to survive the
    /// join rather than being swallowed there.
    #[tokio::test]
    async fn create_rotation_state_async_reports_a_directory_it_cannot_flush() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let state = sample_state();
        let restrict = |mode| {
            fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).expect("chmod");
        };

        restrict(0o300);
        if std::fs::File::open(dir.path()).is_ok() {
            // Effective root, or a filesystem that ignores the mode:
            // the flush cannot be made to fail here.
            restrict(0o700);
            return;
        }
        let result = create_rotation_state_async(dir.path(), &state, &messages).await;
        restrict(0o700);

        let err = result.expect_err("an unflushable directory must be reported");
        assert!(
            format!("{err:#}").contains("to fsync it"),
            "the directory flush must be the reported failure, got: {err:#}"
        );
        assert!(
            rotation_state_path(dir.path()).exists(),
            "the create landed; only its durability was not established"
        );
    }

    /// Same for the update wrapper, whose flush comes from
    /// `atomic_write_blocking` rather than from a call of its own.
    #[tokio::test]
    async fn update_rotation_state_async_reports_a_directory_it_cannot_flush() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let mut state = sample_state();
        let restrict = |mode| {
            fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).expect("chmod");
        };

        create_rotation_state(dir.path(), &state, &messages).expect("create");

        restrict(0o300);
        if std::fs::File::open(dir.path()).is_ok() {
            restrict(0o700);
            return;
        }
        state.phase = 2;
        let result = update_rotation_state_async(dir.path(), &state, &messages).await;
        restrict(0o700);

        let err = result.expect_err("an unflushable directory must be reported");
        assert!(
            format!("{err:#}").contains("to fsync it"),
            "the directory flush must be the reported failure, got: {err:#}"
        );
        let loaded = load_rotation_state(dir.path(), &messages)
            .expect("load")
            .expect("should be Some");
        assert_eq!(
            loaded.phase, 2,
            "the rename landed; only its durability was not established"
        );
    }

    /// The happy path through both wrappers, which the failure tests
    /// above cannot reach: what the blocking thread publishes has to be
    /// what the synchronous writers publish — the same payload, the same
    /// `O_EXCL` create, and owner-only on both the create and the
    /// republish that follows it.
    #[tokio::test]
    async fn rotation_state_async_wrappers_round_trip_at_the_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().expect("tempdir");
        let messages = test_messages();
        let mut state = sample_state();
        let published_mode = || {
            fs::metadata(rotation_state_path(dir.path()))
                .expect("stat")
                .permissions()
                .mode()
                & 0o777
        };

        create_rotation_state_async(dir.path(), &state, &messages)
            .await
            .expect("create");
        assert_eq!(published_mode(), ROTATION_STATE_MODE);

        state.phase = 3;
        update_rotation_state_async(dir.path(), &state, &messages)
            .await
            .expect("update");
        assert_eq!(
            published_mode(),
            ROTATION_STATE_MODE,
            "the rename must not leave the state file at the umask's mode"
        );

        let loaded = load_rotation_state(dir.path(), &messages)
            .expect("load")
            .expect("should be Some");
        assert_eq!(loaded.phase, 3);
        assert_eq!(loaded.mode, RotationMode::IntermediateOnly);
        assert_eq!(loaded.old_intermediate_fp, "bbb");

        let conflict = create_rotation_state_async(dir.path(), &state, &messages).await;
        assert!(
            conflict.is_err(),
            "the wrapper keeps the create's O_EXCL: a second one must fail"
        );
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
