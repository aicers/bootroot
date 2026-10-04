//! Every sample under `tests/fixtures/formats/` loads through the
//! production loader of its format.
//!
//! The samples are what an installed deployment holds, written by the
//! code of the release that added them, and a new release updates that
//! deployment in place only when it still reads them. So a sample is
//! never edited: an additive change keeps every one passing, and a
//! change that stops one loading has to modify or delete it to pass,
//! which is what the release maker's
//! `git diff --no-renames --diff-filter=MD -- tests/fixtures/formats/`
//! finds. See `ARCHITECTURE.md` §11.
//!
//! `state.json` and `responder.toml` are loaded beside their loaders,
//! in the `bootroot` and `bootroot-http01-responder` binaries; the
//! formats the library reads are loaded here.

use std::fs;
use std::path::{Path, PathBuf};

use bootroot::config::Settings;
use bootroot::registrar::registrar_binding_state;
use bootroot::remote_bootstrap::ARTIFACT_SCHEMA_VERSION;

const FORMATS_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/formats");

/// The version directory every format has a sample in.
const FIRST_VERSION: &str = "v1";

const SERVICE_AGENT_CONFIG: &str = "agent.toml";
const INTERNAL_AGENT_CONFIG: &str = "registrar-internal-agent.toml";
const BINDING_RECORD: &str = "registrar-binding.json";
const ARTIFACT: &str = "remote-bootstrap.json";

/// Returns `formats/*/<file>` for every version directory holding a
/// sample of `file`, after asserting the first one does.
fn samples(file: &str) -> Vec<PathBuf> {
    let first = Path::new(FORMATS_DIR).join(FIRST_VERSION).join(file);
    assert!(first.is_file(), "missing sample {}", first.display());
    let mut paths: Vec<PathBuf> = fs::read_dir(FORMATS_DIR)
        .expect("read the formats directory")
        .map(|entry| entry.expect("a formats directory entry").path().join(file))
        .filter(|path| path.is_file())
        .collect();
    paths.sort_unstable();
    paths
}

/// Loads `path` the way `bootroot-agent --config` does: strictly, with
/// no environment overlay and no fall-back to defaults.
fn load_agent_config(path: &Path) -> Settings {
    Settings::from_required_file(path)
        .unwrap_or_else(|err| panic!("{} does not load: {err}", path.display()))
}

#[test]
fn every_service_agent_config_sample_loads_and_validates() {
    for path in samples(SERVICE_AGENT_CONFIG) {
        load_agent_config(&path)
            .validate()
            .unwrap_or_else(|err| panic!("{} does not validate: {err}", path.display()));
    }
}

/// `Settings::validate` refuses an enabled endpoint off Linux — the
/// platform rule, which belongs to the listening process — so there the
/// rest of it runs with the endpoint switched off, and the two tables
/// are held to the daemon's own table checks separately.
#[test]
fn every_internal_agent_config_sample_loads_and_validates() {
    for path in samples(INTERNAL_AGENT_CONFIG) {
        let settings = load_agent_config(&path);
        bootroot::config::validate_registrar_tables(
            &settings.registrar,
            &settings.registrar_endpoint,
        )
        .unwrap_or_else(|err| panic!("{} tables do not validate: {err}", path.display()));
        if cfg!(target_os = "linux") {
            settings
                .validate()
                .unwrap_or_else(|err| panic!("{} does not validate: {err}", path.display()));
        } else {
            let mut portable = settings.clone();
            portable.registrar_endpoint.enabled = false;
            portable.validate().unwrap_or_else(|err| {
                panic!(
                    "{} does not validate apart from the platform rule: {err}",
                    path.display()
                )
            });
        }
    }
}

/// `decode` gates on `schema_version` first, so a bump fails here until
/// the sample is edited.
#[test]
fn every_binding_record_sample_decodes() {
    for path in samples(BINDING_RECORD) {
        let text = fs::read_to_string(&path).expect("read the sample");
        let value: serde_json::Value = serde_json::from_str(&text).expect("the sample is JSON");
        registrar_binding_state(&value)
            .unwrap_or_else(|err| panic!("{} does not decode: {err}", path.display()));
    }
}

/// `bootroot-remote` accepts exactly [`ARTIFACT_SCHEMA_VERSION`], so a
/// change to it fails here until the sample is edited.
#[test]
fn every_artifact_sample_declares_the_accepted_schema_version() {
    for path in samples(ARTIFACT) {
        let text = fs::read_to_string(&path).expect("read the sample");
        let value: serde_json::Value = serde_json::from_str(&text).expect("the sample is JSON");
        assert_eq!(
            value
                .get("schema_version")
                .and_then(serde_json::Value::as_u64),
            Some(u64::from(ARTIFACT_SCHEMA_VERSION)),
            "{} declares a schema_version bootroot-remote refuses",
            path.display()
        );
    }
}
