use std::path::PathBuf;
use std::time::Duration;

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

/// The verb-layer keys are part of the same public surface, and their
/// range rules are enforced by the same reachable validator.
#[test]
fn the_verb_layer_keys_are_validated_outside_the_library_crate() {
    let defaults = RegistrarSettings::default();
    assert_eq!(defaults.max_wrap_ttl, Duration::from_mins(30));
    assert_eq!(defaults.role_token_ttl, Duration::from_hours(1));
    assert_eq!(defaults.role_secret_id_ttl, Duration::from_hours(24));
    assert_eq!(defaults.secret_id_num_uses, 0);
    assert!(defaults.secret_id_ttl.is_none());
    assert!(defaults.secret_id_token_bound_cidrs.is_none());
    assert!(
        defaults.state_file.is_none(),
        "state_file has no default, so a host that serves no verbs need not name one"
    );

    let settings = RegistrarSettings {
        role_token_ttl: Duration::from_millis(1),
        ..RegistrarSettings::default()
    };
    let err = validate_registrar_settings(&settings)
        .expect_err("a duration OpenBao cannot spell is refused");
    assert!(
        err.to_string().contains("registrar.role_token_ttl"),
        "{err}"
    );
}
