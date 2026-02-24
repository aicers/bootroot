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

pub(crate) fn main_lifecycle_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("impl")
        .join("run-main-lifecycle.sh")
}

pub(crate) fn main_remote_lifecycle_script_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("impl")
        .join("run-main-remote-lifecycle.sh")
}

pub(crate) fn baseline_scenario_path(file_name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("e2e")
        .join("docker_harness")
        .join("scenarios")
        .join(file_name)
}
