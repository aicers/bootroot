use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn unique_scenario_id(prefix: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("{prefix}-{now}")
}

pub(crate) fn smoke_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("impl")
        .join("run-harness-smoke.sh")
}

pub(crate) fn baseline_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("impl")
        .join("run-baseline.sh")
}

pub(crate) fn local_lifecycle_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("impl")
        .join("run-local-lifecycle.sh")
}

pub(crate) fn remote_lifecycle_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("impl")
        .join("run-remote-lifecycle.sh")
}

pub(crate) fn ca_key_rotation_recovery_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("impl")
        .join("run-ca-key-rotation-recovery.sh")
}

pub(crate) fn reinit_recovery_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("impl")
        .join("run-reinit-recovery.sh")
}

pub(crate) fn stepca_san_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("impl")
        .join("run-stepca-san.sh")
}

pub(crate) fn openbao_tls_no_delta_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("impl")
        .join("run-openbao-tls-no-delta.sh")
}

pub(crate) fn baseline_scenario_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("e2e")
        .join("docker_harness")
        .join("scenarios")
        .join(file_name)
}
