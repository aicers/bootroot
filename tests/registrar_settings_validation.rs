use std::path::PathBuf;

use bootroot::config::{RegistrarSettings, validate_registrar_settings};

#[test]
fn the_registrar_validator_is_reachable_outside_the_library_crate() {
    let settings = RegistrarSettings::default();
    validate_registrar_settings(&settings).expect("default registrar settings validate");

    let settings = RegistrarSettings {
        audit_store_dir: PathBuf::from("audit-store"),
        ..settings
    };
    let err = validate_registrar_settings(&settings).expect_err("relative stores are refused");
    assert!(
        err.to_string().contains("registrar.audit_store_dir"),
        "{err}"
    );
}
