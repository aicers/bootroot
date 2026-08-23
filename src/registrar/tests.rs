//! Tests for the registrar config loader and the derivation library.
//!
//! The three derived literals asserted in [`derives_the_three_arms`] are
//! a contract with the `registration_id` split, whose own fixtures use
//! the same namespace keys. They are written out rather than
//! round-tripped against the derivation, because a derivation that
//! round-trips against itself agrees with itself no matter what it
//! emits.

use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::TempDir;

use crate::config::{
    AcmeSettings, DaemonProfileSettings, DaemonRuntimeSettings, HookSettings, Paths,
    RegistrarEndpointSettings, RetrySettings, SchedulerSettings, Settings, TrustSettings,
    profile_domain,
};
use crate::input_validation::ValidationError;
use crate::registrar::config::{
    CONFIG_FILE_NAME, DEFAULT_CONFIG_PATH, Multiplicity, RegistrarConfig, RegistrationSpec,
    ReloadKind, ReloadSpec, SUPPORTED_SCHEMA_VERSION,
};
use crate::registrar::error::{RegistrarError, SpecIdentityField};
use crate::registrar::fixture::{ComponentFixture, FIXTURE_DOMAIN, RegistrarConfigFixture};
use crate::registrar::identity::{
    RequestedSpec, check_instance_shape, check_spec_identity, compose_san, derive_registration_id,
    validate_request_labels,
};

const EXAMPLE_FILE: &str = "docs/reference/provisioning.toml.example";
const SCHEMA_DOC_FILE: &str = "docs/reference/registrar-provisioning-config.md";
/// The structural maximum of a derived key, per `input_validation`.
const REGISTRATION_ID_MAX_LEN: usize = 131;

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Writes `contents` verbatim as the rendered config inside a fresh
/// temporary directory, so no test ever touches [`DEFAULT_CONFIG_PATH`].
fn write_raw(contents: &str) -> (TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join(CONFIG_FILE_NAME);
    std::fs::write(&path, contents).expect("the fixture file must be writable");
    (dir, path)
}

fn load_fixture(
    fixture: &RegistrarConfigFixture,
) -> (TempDir, Result<RegistrarConfig, RegistrarError>) {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = fixture
        .write_to(dir.path())
        .expect("the fixture must write");
    let loaded = RegistrarConfig::load(&path);
    (dir, loaded)
}

fn loaded_default() -> (TempDir, RegistrarConfig) {
    let (dir, loaded) = load_fixture(&RegistrarConfigFixture::new());
    (dir, loaded.expect("the default fixture must load"))
}

fn piglet_spec() -> RequestedSpec {
    RequestedSpec::new(
        ReloadSpec::new(ReloadKind::DockerRestart, "piglet"),
        Some(3001),
    )
}

// ---------------------------------------------------------------------
// The documented example and the shipped documentation
// ---------------------------------------------------------------------

#[test]
fn loads_the_shipped_example_through_the_production_loader() {
    let config = RegistrarConfig::load(&repo_path(EXAMPLE_FILE))
        .expect("the shipped example must load through the production loader");

    assert_eq!(config.domain(), "trusted.domain");
    assert_eq!(config.schema_version(), SUPPORTED_SCHEMA_VERSION);
    assert_eq!(
        config.component_names().collect::<Vec<_>>(),
        vec!["piglet", "review", "roxyd"]
    );

    let review = config.component("review").expect("review resolves");
    assert_eq!(review.multiplicity(), Multiplicity::OnePerDeployment);
    assert_eq!(review.spec().cert_group, Some(3000));
    assert_eq!(
        review.spec().reload,
        ReloadSpec::new(ReloadKind::DockerRestart, "review")
    );

    let roxyd = config.component("roxyd").expect("roxyd resolves");
    assert_eq!(roxyd.multiplicity(), Multiplicity::OnePerHost);
    assert_eq!(roxyd.spec().cert_group, None);
    assert_eq!(
        roxyd.spec().reload,
        ReloadSpec::new(ReloadKind::Systemd, "roxyd.service")
    );

    let piglet = config.component("piglet").expect("piglet resolves");
    assert_eq!(piglet.multiplicity(), Multiplicity::ManyPerHost);
    assert_eq!(piglet.spec().cert_group, Some(3001));
    assert_eq!(
        piglet.spec().reload,
        ReloadSpec::new(ReloadKind::DockerRestart, "piglet")
    );
}

/// The schema description quotes the example file. Quoting it is only
/// worth anything while the quote is the file.
#[test]
fn schema_documentation_quotes_the_example_verbatim() {
    let example = std::fs::read_to_string(repo_path(EXAMPLE_FILE)).expect("the example is shipped");
    let doc =
        std::fs::read_to_string(repo_path(SCHEMA_DOC_FILE)).expect("the schema doc is shipped");
    assert!(
        doc.contains(&example),
        "{SCHEMA_DOC_FILE} no longer quotes {EXAMPLE_FILE} verbatim"
    );
}

#[test]
fn default_path_is_the_writers_product_namespaced_one() {
    assert_eq!(
        DEFAULT_CONFIG_PATH,
        "/etc/clumit-security/provisioning.toml"
    );
}

// ---------------------------------------------------------------------
// Loader: hard failures
// ---------------------------------------------------------------------

#[test]
fn a_missing_file_is_a_hard_failure() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let err = RegistrarConfig::load(&dir.path().join("absent.toml"))
        .expect_err("a missing config must not load");
    assert!(
        matches!(err, RegistrarError::ConfigUnreadable { .. }),
        "{err:?}"
    );
}

/// A directory standing where the file should be is unreadable for the
/// same reason a mode-000 file is, and stays unreadable when the test
/// suite happens to run as root.
#[test]
fn an_unreadable_file_is_a_hard_failure() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let path = dir.path().join(CONFIG_FILE_NAME);
    std::fs::create_dir(&path).expect("the placeholder directory must be creatable");
    let err = RegistrarConfig::load(&path).expect_err("an unreadable config must not load");
    assert!(
        matches!(err, RegistrarError::ConfigUnreadable { .. }),
        "{err:?}"
    );
}

#[test]
fn a_malformed_body_is_a_typed_failure() {
    let body = "this is not toml\n";
    let (_dir, path) = write_raw(&format!(
        "fingerprint = \"{}\"\n{body}",
        crate::tls::sha256_hex(body.as_bytes())
    ));
    let err = RegistrarConfig::load(&path).expect_err("a malformed body must not load");
    assert!(
        matches!(err, RegistrarError::ConfigMalformed { .. }),
        "{err:?}"
    );
}

#[test]
fn a_missing_domain_is_a_typed_failure() {
    let body = "schema_version = 1\n";
    let (_dir, path) = write_raw(&format!(
        "fingerprint = \"{}\"\n{body}",
        crate::tls::sha256_hex(body.as_bytes())
    ));
    let err = RegistrarConfig::load(&path).expect_err("a config with no domain must not load");
    assert!(
        matches!(err, RegistrarError::ConfigMalformed { .. }),
        "{err:?}"
    );
}

#[test]
fn an_invalid_domain_is_a_typed_failure() {
    let (_dir, loaded) = load_fixture(&RegistrarConfigFixture::new().with_domain("trusted_domain"));
    let err = loaded.expect_err("an invalid domain must not load");
    assert!(
        matches!(err, RegistrarError::InvalidDomain { ref domain, .. } if domain == "trusted_domain"),
        "{err:?}"
    );
}

#[test]
fn an_unrecognised_multiplicity_carries_the_offending_value() {
    let fixture = RegistrarConfigFixture::new().with_raw_component(
        "piglet",
        ComponentFixture {
            multiplicity: "sometimes".to_string(),
            cert_group: Some(3001),
            reload_kind: "docker-restart".to_string(),
            reload_target: Some("piglet".to_string()),
        },
    );
    let (_dir, loaded) = load_fixture(&fixture);
    let err = loaded.expect_err("an unrecognised multiplicity must not load");
    match err {
        RegistrarError::UnknownMultiplicity { component, value } => {
            assert_eq!(component, "piglet");
            assert_eq!(value, "sometimes");
        }
        other => panic!("expected UnknownMultiplicity, got {other:?}"),
    }
}

#[test]
fn an_unrecognised_reload_kind_carries_the_offending_value() {
    let fixture = RegistrarConfigFixture::new().with_raw_component(
        "piglet",
        ComponentFixture {
            multiplicity: "many-per-host".to_string(),
            cert_group: Some(3001),
            reload_kind: "container-restart".to_string(),
            reload_target: Some("piglet".to_string()),
        },
    );
    let (_dir, loaded) = load_fixture(&fixture);
    let err = loaded.expect_err("an unrecognised reload kind must not load");
    match err {
        RegistrarError::UnknownReloadKind { component, value } => {
            assert_eq!(component, "piglet");
            // The infrastructure-certificate vocabulary is not this
            // file's, and reaching for it is a load failure rather than
            // a silently accepted synonym.
            assert_eq!(value, "container-restart");
        }
        other => panic!("expected UnknownReloadKind, got {other:?}"),
    }
}

#[test]
fn every_reload_kind_the_writer_renders_is_accepted() {
    for (kind, target) in [
        (ReloadKind::Sighup, Some("roxyd")),
        (ReloadKind::Systemd, Some("roxyd.service")),
        (ReloadKind::DockerRestart, Some("roxyd")),
        (ReloadKind::None, None),
    ] {
        let reload = match target {
            Some(target) => ReloadSpec::new(kind, target),
            None => ReloadSpec::none(),
        };
        let fixture = RegistrarConfigFixture::new().with_component(
            "roxyd",
            Multiplicity::OnePerHost,
            &RegistrationSpec {
                cert_group: None,
                reload: reload.clone(),
            },
        );
        let (_dir, loaded) = load_fixture(&fixture);
        let config = loaded.unwrap_or_else(|err| panic!("{kind} must load: {err:?}"));
        assert_eq!(
            config
                .component("roxyd")
                .expect("roxyd resolves")
                .spec()
                .reload,
            reload
        );
    }
}

/// `target` must be absent for `none` and non-empty for the other three.
/// An empty string is still `Some`, so accepting one would leave a `none`
/// component holding `Some("")` — a spec no request built from
/// [`ReloadSpec::none`] can equal, and therefore every registration of
/// that component refused one at a time rather than the file refused
/// once.
#[test]
fn a_reload_target_that_contradicts_its_kind_is_refused() {
    for (kind, target) in [
        ("none", Some("roxyd")),
        ("none", Some("")),
        ("systemd", None),
        ("systemd", Some("")),
    ] {
        let fixture = RegistrarConfigFixture::new().with_raw_component(
            "roxyd",
            ComponentFixture {
                multiplicity: "one-per-host".to_string(),
                cert_group: None,
                reload_kind: kind.to_string(),
                reload_target: target.map(str::to_string),
            },
        );
        let (_dir, loaded) = load_fixture(&fixture);
        let err = loaded.expect_err("a contradictory reload target must not load");
        assert!(
            matches!(err, RegistrarError::InvalidReloadTarget { .. }),
            "{kind} with {target:?}: {err:?}"
        );
    }
}

/// The `none` style's whole safe-set is [`ReloadSpec::none`], so a
/// component the writer renders it for must accept exactly that value
/// and nothing else.
#[test]
fn a_none_reload_component_matches_the_target_free_spec() {
    let spec = RegistrationSpec {
        cert_group: None,
        reload: ReloadSpec::none(),
    };
    let (_dir, loaded) = load_fixture(&RegistrarConfigFixture::new().with_spec("roxyd", &spec));
    let config = loaded.expect("the fixture must load");

    assert_eq!(
        config
            .component("roxyd")
            .expect("roxyd is configured")
            .spec()
            .reload,
        ReloadSpec::none()
    );
    assert!(
        config
            .validate_spec("roxyd", &RequestedSpec::new(ReloadSpec::none(), None))
            .is_ok()
    );
}

// ---------------------------------------------------------------------
// Loader: the two integrity gates
// ---------------------------------------------------------------------

#[test]
fn the_first_line_must_be_the_exact_fingerprint_form() {
    let digest = "a".repeat(64);
    for contents in [
        // No newline at all.
        format!("fingerprint = \"{digest}\""),
        // The key is not the fingerprint.
        "schema_version = 1\ndomain = \"trusted.domain\"\n".to_string(),
        // Too short.
        format!("fingerprint = \"{}\"\n", "a".repeat(63)),
        // Too long.
        format!("fingerprint = \"{}\"\n", "a".repeat(65)),
        // Uppercase hex.
        format!("fingerprint = \"{}\"\n", "A".repeat(64)),
        // Not hex.
        format!("fingerprint = \"{}\"\n", "z".repeat(64)),
        // Unquoted.
        format!("fingerprint = {digest}\n"),
        // Extra whitespace around the assignment.
        format!("fingerprint  =  \"{digest}\"\n"),
        // A trailing comment on the fingerprint line.
        format!("fingerprint = \"{digest}\" # rendered\n"),
        // An empty file.
        String::new(),
    ] {
        let (_dir, path) = write_raw(&contents);
        let err = RegistrarConfig::load(&path).expect_err("a malformed first line must not load");
        assert!(
            matches!(err, RegistrarError::FingerprintLineMalformed { .. }),
            "{contents:?}: {err:?}"
        );
    }
}

#[test]
fn a_digest_that_does_not_match_the_body_is_refused() {
    let declared = "0".repeat(64);
    let fixture = RegistrarConfigFixture::new().with_fingerprint(&declared);
    let (_dir, loaded) = load_fixture(&fixture);
    let err = loaded.expect_err("a mismatched digest must not load");
    match err {
        RegistrarError::FingerprintMismatch {
            declared: found,
            computed,
            ..
        } => {
            assert_eq!(found, declared);
            assert_eq!(
                computed,
                crate::tls::sha256_hex(fixture.render_body().as_bytes())
            );
        }
        other => panic!("expected FingerprintMismatch, got {other:?}"),
    }
}

/// The regression the digest gate exists for: a body cut at a
/// `[components.*]` boundary is still valid TOML with entries missing,
/// so without the gate the load would succeed and the dropped components
/// would be refused one request at a time — a silent per-component
/// enrollment outage indistinguishable from a component that was never
/// provisioned.
#[test]
fn a_body_truncated_at_a_component_boundary_fails_on_the_digest() {
    let fixture = RegistrarConfigFixture::new();
    let whole = fixture.render();
    let cut = whole
        .find("\n[components.review]")
        .expect("the rendered file has a review table");
    let truncated = whole.get(..cut + 1).expect("the cut is on a char boundary");

    // The truncated body really does still parse, so the digest is the
    // only thing standing between it and a short component table.
    assert!(truncated.parse::<toml_edit::DocumentMut>().is_ok());

    let (_dir, path) = write_raw(truncated);
    let err = RegistrarConfig::load(&path).expect_err("a truncated config must not load");
    assert!(
        matches!(err, RegistrarError::FingerprintMismatch { .. }),
        "expected the digest failure rather than a per-component refusal, got {err:?}"
    );
}

/// The declared fingerprint has no reader outside a validated load: the
/// field is private and `load` is the only constructor, so a caller
/// holding a `RegistrarConfig` holds a digest that was checked.
#[test]
fn the_declared_fingerprint_is_reachable_only_from_a_validated_load() {
    let fixture = RegistrarConfigFixture::new();
    let (_dir, config) = {
        let (dir, loaded) = load_fixture(&fixture);
        (dir, loaded.expect("the fixture must load"))
    };
    assert_eq!(
        config.fingerprint(),
        crate::tls::sha256_hex(fixture.render_body().as_bytes())
    );
}

#[test]
fn an_unsupported_schema_version_carries_both_versions() {
    let (_dir, loaded) = load_fixture(&RegistrarConfigFixture::new().with_schema_version(2));
    let err = loaded.expect_err("a newer schema must not load");
    match err {
        RegistrarError::UnsupportedSchemaVersion {
            found, supported, ..
        } => {
            assert_eq!(found, 2);
            assert_eq!(supported, SUPPORTED_SCHEMA_VERSION);
        }
        other => panic!("expected UnsupportedSchemaVersion, got {other:?}"),
    }
}

/// The body's shape is closed. An extra key means the file was written
/// against a shape this build does not implement, and a `schema_version`
/// that failed to say so is not a reason to read it anyway.
#[test]
fn an_unknown_key_in_the_body_is_refused() {
    for body in [
        "schema_version = 1\ndomain = \"trusted.domain\"\nregion = \"eu\"\n",
        // A second fingerprint, inside the digested body this time.
        "schema_version = 1\ndomain = \"trusted.domain\"\nfingerprint = \"x\"\n",
        "schema_version = 1\ndomain = \"trusted.domain\"\n\n[components.review]\nmultiplicity = \"one-per-deployment\"\nreload = { kind = \"none\" }\nprivilege = \"root\"\n",
    ] {
        let (_dir, path) = write_raw(&format!(
            "fingerprint = \"{}\"\n{body}",
            crate::tls::sha256_hex(body.as_bytes())
        ));
        let err = RegistrarConfig::load(&path).expect_err("an unknown key must not load");
        assert!(
            matches!(err, RegistrarError::ConfigMalformed { .. }),
            "{body:?}: {err:?}"
        );
    }
}

/// A `[components.<key>]` that no registration could ever use is a
/// rendering error, not an entry to carry around unreachable. The key is
/// spent twice — a wire `service_name` selects the entry, and the same
/// value is the `<component>` segment of every derived id — so both
/// rules apply. `Review` is the case only the second rule catches: it is
/// a legal DNS label, so it *is* selectable, but it is not path-safe, so
/// every enrollment of it would be refused at the derivation step one
/// request at a time rather than the file refused once.
#[test]
fn a_component_key_no_registration_could_use_is_refused() {
    for (key, kind) in [
        ("review_eu", ValidationError::InvalidDnsLabel),
        ("-review", ValidationError::InvalidDnsLabel),
        ("review-", ValidationError::InvalidDnsLabel),
        ("Review", ValidationError::InvalidRegistrationId),
    ] {
        let fixture = RegistrarConfigFixture::empty().with_raw_component(
            key,
            ComponentFixture {
                multiplicity: "one-per-deployment".to_string(),
                cert_group: None,
                reload_kind: "none".to_string(),
                reload_target: None,
            },
        );
        let (_dir, loaded) = load_fixture(&fixture);
        let err = loaded.expect_err("an unusable component key must not load");
        match err {
            RegistrarError::InvalidComponentKey {
                component,
                kind: found,
            } => {
                assert_eq!(component, key);
                assert_eq!(found, kind, "{key}");
            }
            other => panic!("{key}: expected InvalidComponentKey, got {other:?}"),
        }
    }
}

#[test]
fn an_absent_schema_version_is_refused_rather_than_defaulted() {
    let body = "domain = \"trusted.domain\"\n\n[components.review]\nmultiplicity = \"one-per-deployment\"\nreload = { kind = \"none\" }\n";
    let (_dir, path) = write_raw(&format!(
        "fingerprint = \"{}\"\n{body}",
        crate::tls::sha256_hex(body.as_bytes())
    ));
    let err = RegistrarConfig::load(&path).expect_err("an absent schema_version must not load");
    assert!(
        matches!(err, RegistrarError::ConfigMalformed { .. }),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------

/// These three literals are a contract with the `registration_id` split
/// issue, which asserts the same strings as namespace keys in its own
/// fixtures.
#[test]
fn derives_the_three_arms() {
    let cases: [(Multiplicity, &str, &str, Option<u32>, &str); 7] = [
        (
            Multiplicity::ManyPerHost,
            "piglet",
            "h1",
            Some(1),
            "h1-piglet-001",
        ),
        (Multiplicity::OnePerHost, "roxyd", "h1", None, "h1-roxyd"),
        (
            Multiplicity::OnePerDeployment,
            "review",
            "h1",
            None,
            "review",
        ),
        // Hyphenated component and host names.
        (
            Multiplicity::OnePerDeployment,
            "aice-web-next",
            "edge-01",
            None,
            "aice-web-next",
        ),
        (
            Multiplicity::OnePerHost,
            "aice-web-next",
            "edge-01",
            None,
            "edge-01-aice-web-next",
        ),
        (
            Multiplicity::ManyPerHost,
            "aice-web-next",
            "edge-01",
            Some(12),
            "edge-01-aice-web-next-012",
        ),
        (
            Multiplicity::ManyPerHost,
            "piglet",
            "h1",
            Some(999),
            "h1-piglet-999",
        ),
    ];
    for (multiplicity, service_name, host, instance, expected) in cases {
        let derived = derive_registration_id(multiplicity, service_name, host, instance)
            .unwrap_or_else(|err| panic!("{expected} must derive: {err:?}"));
        assert_eq!(derived, expected);
    }
}

/// The derivation is not injective in general: component names and host
/// labels both admit hyphens. A uniqueness check against durable state
/// is therefore required, and it is the caller's — nothing in this
/// library reads registration state.
#[test]
fn the_derivation_is_not_injective() {
    let web_on_h1_aimer =
        derive_registration_id(Multiplicity::ManyPerHost, "web", "h1-aimer", Some(1))
            .expect("web on h1-aimer derives");
    let aimer_web_on_h1 =
        derive_registration_id(Multiplicity::ManyPerHost, "aimer-web", "h1", Some(1))
            .expect("aimer-web on h1 derives");
    assert_eq!(web_on_h1_aimer, "h1-aimer-web-001");
    assert_eq!(aimer_web_on_h1, "h1-aimer-web-001");
}

#[test]
fn the_derived_key_is_bounded_at_the_structural_maximum() {
    let host = "h".repeat(63);
    let component = "c".repeat(63);

    let at_limit = derive_registration_id(Multiplicity::ManyPerHost, &component, &host, Some(1))
        .expect("the structural maximum is legal");
    assert_eq!(at_limit.len(), REGISTRATION_ID_MAX_LEN);

    // One octet past it, reached the only way the derivation can: an
    // instance whose three-digit rendering needs a fourth digit.
    let err = derive_registration_id(Multiplicity::ManyPerHost, &component, &host, Some(1000))
        .expect_err("one octet past the maximum is refused");
    match err {
        RegistrarError::DerivedKeyInvalid { key, kind } => {
            assert_eq!(key.len(), REGISTRATION_ID_MAX_LEN + 1);
            // The refusal comes from the shared validator, not from a
            // length check written locally in this library.
            assert_eq!(kind, ValidationError::InvalidRegistrationId);
        }
        other => panic!("expected DerivedKeyInvalid, got {other:?}"),
    }
}

// ---------------------------------------------------------------------
// SAN composition
// ---------------------------------------------------------------------

#[test]
fn the_san_always_has_four_segments() {
    assert_eq!(
        compose_san(None, "roxyd", "h1", FIXTURE_DOMAIN),
        "001.roxyd.h1.trusted.domain"
    );
    assert_eq!(
        compose_san(None, "review", "h1", FIXTURE_DOMAIN),
        "001.review.h1.trusted.domain"
    );
    assert_eq!(
        compose_san(Some(1), "piglet", "h1", FIXTURE_DOMAIN),
        "001.piglet.h1.trusted.domain"
    );
    assert_eq!(
        compose_san(Some(12), "piglet", "h1", FIXTURE_DOMAIN),
        "012.piglet.h1.trusted.domain"
    );
}

/// The `001` default is SAN-only. Applying it before the derivation arm
/// is selected would collapse the two-part/three-part distinction the
/// identity-shape check exists to enforce.
#[test]
fn the_default_instance_reaches_the_san_and_never_the_id() {
    let (_dir, config) = loaded_default();
    let cases: [(&str, Option<u32>, &str, &str); 3] = [
        ("review", None, "review", "001.review.h1.trusted.domain"),
        ("roxyd", None, "h1-roxyd", "001.roxyd.h1.trusted.domain"),
        (
            "piglet",
            Some(1),
            "h1-piglet-001",
            "001.piglet.h1.trusted.domain",
        ),
    ];
    for (service_name, instance, expected_id, expected_san) in cases {
        let derived = config
            .resolve_end_to_end(service_name, "h1", instance, None)
            .unwrap_or_else(|err| panic!("{service_name} must resolve: {err:?}"));
        assert_eq!(derived.registration_id, expected_id);
        assert_eq!(derived.san, expected_san);
    }
    // Spelled out, because it is the regression that would catch the
    // default being applied before arm selection.
    let roxyd = config
        .resolve_end_to_end("roxyd", "h1", None, None)
        .expect("roxyd resolves");
    assert!(!roxyd.registration_id.contains("001"));
    let review = config
        .resolve_end_to_end("review", "h1", None, None)
        .expect("review resolves");
    assert!(!review.registration_id.contains("001"));
}

/// A loaded config composes under its own domain, never one a caller
/// could have supplied.
#[test]
fn san_for_takes_the_domain_from_the_loaded_file() {
    let (_dir, loaded) = load_fixture(&RegistrarConfigFixture::new().with_domain("other.domain"));
    let config = loaded.expect("the fixture must load");
    assert_eq!(
        config.san_for(Some(1), "piglet", "h1"),
        "001.piglet.h1.other.domain"
    );
    assert_eq!(
        config.san_for(None, "roxyd", "h1"),
        compose_san(None, "roxyd", "h1", config.domain())
    );
}

/// The four sites that compose `<instance>.<service>.<host>.<domain>`
/// must agree byte for byte. This pins the two a test in this crate can
/// reach; `commands::verify::expected_dns_name` and
/// `commands::dns_alias::dns_alias_for_entry` are private to the binary
/// crate and are named in the schema documentation instead.
#[test]
fn the_composer_agrees_with_profile_domain() {
    for (instance, service_name, host) in [
        (Some(1), "piglet", "h1"),
        (Some(12), "piglet", "h1"),
        (None, "roxyd", "h1"),
        (None, "review", "h1"),
    ] {
        let settings = settings_with_domain(FIXTURE_DOMAIN);
        let rendered_instance = format!("{:03}", instance.unwrap_or(1));
        let profile = profile_with(&rendered_instance, service_name, host);
        assert_eq!(
            compose_san(instance, service_name, host, FIXTURE_DOMAIN),
            profile_domain(&settings, &profile),
            "{service_name} on {host} instance {instance:?}"
        );
    }
}

// ---------------------------------------------------------------------
// Label validation and the identity-shape check
// ---------------------------------------------------------------------

#[test]
fn a_label_that_is_not_a_single_dns_label_is_refused_with_its_raw_value() {
    let err = validate_request_labels("piglet.h1", "h1").expect_err("a dotted service_name");
    match err {
        RegistrarError::InvalidServiceName { value, kind } => {
            assert_eq!(value, "piglet.h1");
            assert_eq!(kind, ValidationError::InvalidDnsLabel);
        }
        other => panic!("expected InvalidServiceName, got {other:?}"),
    }

    let err = validate_request_labels("piglet", "h1_a").expect_err("an underscored host");
    match err {
        RegistrarError::InvalidHost { value, kind } => {
            assert_eq!(value, "h1_a");
            assert_eq!(kind, ValidationError::InvalidDnsLabel);
        }
        other => panic!("expected InvalidHost, got {other:?}"),
    }

    assert!(validate_request_labels("piglet", "h1").is_ok());
}

/// The one-per-deployment arm ignores `host`, but the SAN's third
/// segment does not, so "not used by the id arm" is not "optional".
#[test]
fn a_one_per_deployment_request_still_needs_a_valid_host() {
    let (_dir, config) = loaded_default();
    for host in ["", "h1.example", "-h1"] {
        let err = config
            .resolve_end_to_end("review", host, None, None)
            .expect_err("a one-per-deployment request with a bad host must be refused");
        assert!(
            matches!(err, RegistrarError::InvalidHost { .. }),
            "{host:?}: {err:?}"
        );
    }
}

#[test]
fn the_identity_shape_check_refuses_both_directions() {
    let (_dir, config) = loaded_default();

    // An instance for a class with no instance dimension.
    for service_name in ["review", "roxyd"] {
        let err = config
            .check_identity_shape(service_name, Some(1))
            .expect_err("a supplied instance must be refused");
        assert!(
            matches!(
                err,
                RegistrarError::ServiceInstanceMismatch {
                    instance_supplied: true,
                    ..
                }
            ),
            "{service_name}: {err:?}"
        );
    }

    // No instance for the class that has one.
    let err = config
        .check_identity_shape("piglet", None)
        .expect_err("an omitted instance must be refused");
    assert!(
        matches!(
            err,
            RegistrarError::ServiceInstanceMismatch {
                instance_supplied: false,
                ..
            }
        ),
        "{err:?}"
    );

    // The matching shapes.
    assert_eq!(
        config.check_identity_shape("review", None).expect("review"),
        Multiplicity::OnePerDeployment
    );
    assert_eq!(
        config.check_identity_shape("roxyd", None).expect("roxyd"),
        Multiplicity::OnePerHost
    );
    assert_eq!(
        config
            .check_identity_shape("piglet", Some(1))
            .expect("piglet"),
        Multiplicity::ManyPerHost
    );
}

/// The endpoint maps both onto one caller-facing identifier, but the
/// audit record stores the internal variant, so collapsing them here
/// would erase the difference between a wrong `instance` shape and a
/// caller probing component names that do not exist.
#[test]
fn an_absent_component_is_a_distinct_variant_from_an_instance_mismatch() {
    let (_dir, config) = loaded_default();
    let absent = config
        .check_identity_shape("giganto", None)
        .expect_err("an unconfigured component must be refused");
    let mismatch = config
        .check_identity_shape("piglet", None)
        .expect_err("an omitted instance must be refused");

    assert!(
        matches!(absent, RegistrarError::ComponentNotConfigured { ref component } if component == "giganto"),
        "{absent:?}"
    );
    assert!(
        matches!(mismatch, RegistrarError::ServiceInstanceMismatch { .. }),
        "{mismatch:?}"
    );
    assert_ne!(
        std::mem::discriminant(&absent),
        std::mem::discriminant(&mismatch)
    );
}

#[test]
fn a_component_removed_from_the_config_is_refused_rather_than_defaulted() {
    let (_dir, loaded) = load_fixture(&RegistrarConfigFixture::new().without_component("piglet"));
    let config = loaded.expect("the fixture must load");
    let err = config
        .resolve_end_to_end("piglet", "h1", Some(1), None)
        .expect_err("an absent component must be refused");
    assert!(
        matches!(err, RegistrarError::ComponentNotConfigured { .. }),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------
// Safe-set validation
// ---------------------------------------------------------------------

#[test]
fn the_safe_set_accepts_only_the_single_rendered_spec() {
    let (_dir, config) = loaded_default();
    assert!(config.validate_spec("piglet", &piglet_spec()).is_ok());

    let rejected = [
        // Differs only in cert_group.
        RequestedSpec::new(
            ReloadSpec::new(ReloadKind::DockerRestart, "piglet"),
            Some(0),
        ),
        // Differs only in reload.kind.
        RequestedSpec::new(ReloadSpec::new(ReloadKind::Systemd, "piglet"), Some(3001)),
        // Differs only in reload.target.
        RequestedSpec::new(
            ReloadSpec::new(ReloadKind::DockerRestart, "piglet-attacker"),
            Some(3001),
        ),
        // Omits the cert_group the component's spec renders.
        RequestedSpec::new(ReloadSpec::new(ReloadKind::DockerRestart, "piglet"), None),
    ];
    for spec in rejected {
        let err = config
            .validate_spec("piglet", &spec)
            .expect_err("a spec outside the safe-set must be refused");
        assert!(
            matches!(err, RegistrarError::ServiceSpecOutsideSafeSet { ref component } if component == "piglet"),
            "{spec:?}: {err:?}"
        );
    }
}

/// An omitted `cert_group` in the rendered spec means the component's
/// registrations must carry none — not that any gid is allowed.
#[test]
fn a_component_rendering_no_cert_group_refuses_a_request_that_supplies_one() {
    let (_dir, config) = loaded_default();
    let reload = ReloadSpec::new(ReloadKind::Systemd, "roxyd.service");

    assert!(
        config
            .validate_spec("roxyd", &RequestedSpec::new(reload.clone(), None))
            .is_ok()
    );
    let err = config
        .validate_spec("roxyd", &RequestedSpec::new(reload, Some(3000)))
        .expect_err("a supplied cert_group must be refused");
    assert!(
        matches!(err, RegistrarError::ServiceSpecOutsideSafeSet { .. }),
        "{err:?}"
    );
}

/// There is no template language. A rendered token that looks like a
/// placeholder is a literal string, and a matcher that tolerated a
/// varying segment would silently widen what one rendered line
/// authorises.
#[test]
fn a_placeholder_looking_token_is_not_expanded() {
    let spec = RegistrationSpec {
        cert_group: Some(3001),
        reload: ReloadSpec::new(ReloadKind::DockerRestart, "piglet-{instance}"),
    };
    let (_dir, loaded) = load_fixture(&RegistrarConfigFixture::new().with_spec("piglet", &spec));
    let config = loaded.expect("the fixture must load");

    let err = config
        .validate_spec(
            "piglet",
            &RequestedSpec::new(
                ReloadSpec::new(ReloadKind::DockerRestart, "piglet-001"),
                Some(3001),
            ),
        )
        .expect_err("the expanded form must be refused");
    assert!(
        matches!(err, RegistrarError::ServiceSpecOutsideSafeSet { .. }),
        "{err:?}"
    );

    assert!(
        config
            .validate_spec(
                "piglet",
                &RequestedSpec::new(
                    ReloadSpec::new(ReloadKind::DockerRestart, "piglet-{instance}"),
                    Some(3001),
                ),
            )
            .is_ok()
    );
}

// ---------------------------------------------------------------------
// Spec identity agreement
// ---------------------------------------------------------------------

#[test]
fn a_spec_component_that_disagrees_is_refused_before_anything_else() {
    let (_dir, config) = loaded_default();
    // The spec is otherwise inside the safe-set, and the component it
    // names is itself configured — so nothing but the identity check
    // stops it being validated against `review`'s rendered entry.
    let spec = piglet_spec().with_component("review");

    let err = config
        .resolve_end_to_end("piglet", "h1", Some(1), Some(&spec))
        .expect_err("a disagreeing spec.component must be refused");
    match err {
        RegistrarError::SpecIdentityDisagreement {
            field,
            expected,
            spec_component,
            spec_service_name,
        } => {
            assert_eq!(field, SpecIdentityField::Component);
            assert_eq!(expected, "piglet");
            assert_eq!(spec_component.as_deref(), Some("review"));
            assert_eq!(spec_service_name, None);
        }
        other => panic!("expected SpecIdentityDisagreement, got {other:?}"),
    }

    // An unrelated string is refused the same way.
    let err = check_spec_identity("piglet", &piglet_spec().with_component("not-a-component"))
        .expect_err("an unrelated spec.component must be refused");
    assert!(
        matches!(err, RegistrarError::SpecIdentityDisagreement { .. }),
        "{err:?}"
    );
}

#[test]
fn a_spec_service_name_that_disagrees_is_refused_even_inside_the_safe_set() {
    let (_dir, config) = loaded_default();
    for name in ["review", "not-a-component", "roxyd-h1"] {
        let spec = piglet_spec().with_service_name(name);
        let err = config
            .resolve_end_to_end("piglet", "h1", Some(1), Some(&spec))
            .expect_err("a disagreeing spec.service_name must be refused");
        match err {
            RegistrarError::SpecIdentityDisagreement {
                field,
                spec_service_name,
                ..
            } => {
                assert_eq!(field, SpecIdentityField::ServiceName);
                assert_eq!(spec_service_name.as_deref(), Some(name));
            }
            other => panic!("{name}: expected SpecIdentityDisagreement, got {other:?}"),
        }
    }
}

/// The post-split contract: the spec's identity fields carry the plain
/// keyword, never a composed name. There is no compatibility path that
/// strips a host suffix — and the derivation never reads the field, so
/// the id and the SAN a matching request produces are the wire's alone.
#[test]
fn a_composed_name_in_the_spec_is_refused_and_never_read() {
    let (_dir, config) = loaded_default();
    let err = check_spec_identity(
        "roxyd",
        &RequestedSpec::new(ReloadSpec::new(ReloadKind::Systemd, "roxyd.service"), None)
            .with_service_name("roxyd-h1"),
    )
    .expect_err("a composed spec.service_name must be refused");
    assert!(
        matches!(err, RegistrarError::SpecIdentityDisagreement { .. }),
        "{err:?}"
    );

    // The same request with the spec's identity fields absent, and with
    // them agreeing, derives the same id and SAN — so neither is a
    // source for either.
    let plain = RequestedSpec::new(ReloadSpec::new(ReloadKind::Systemd, "roxyd.service"), None);
    let restated = plain
        .clone()
        .with_component("roxyd")
        .with_service_name("roxyd");
    let from_plain = config
        .resolve_end_to_end("roxyd", "h1", None, Some(&plain))
        .expect("the plain spec resolves");
    let from_restated = config
        .resolve_end_to_end("roxyd", "h1", None, Some(&restated))
        .expect("the restated spec resolves");
    assert_eq!(from_plain, from_restated);
    assert_eq!(from_plain.registration_id, "h1-roxyd");
    assert_eq!(from_plain.san, "001.roxyd.h1.trusted.domain");
}

#[test]
fn the_disagreeing_field_is_recorded_behind_the_single_variant() {
    let base = piglet_spec();
    let cases = [
        (
            base.clone().with_component("review"),
            SpecIdentityField::Component,
        ),
        (
            base.clone().with_service_name("review"),
            SpecIdentityField::ServiceName,
        ),
        (
            base.clone()
                .with_component("review")
                .with_service_name("roxyd"),
            SpecIdentityField::Both,
        ),
    ];
    for (spec, expected) in cases {
        let err = check_spec_identity("piglet", &spec).expect_err("a disagreement");
        match err {
            RegistrarError::SpecIdentityDisagreement { field, .. } => assert_eq!(field, expected),
            other => panic!("expected SpecIdentityDisagreement, got {other:?}"),
        }
    }

    // Absent and equal both pass.
    assert!(check_spec_identity("piglet", &base).is_ok());
    assert!(
        check_spec_identity(
            "piglet",
            &base.with_component("piglet").with_service_name("piglet")
        )
        .is_ok()
    );
}

// ---------------------------------------------------------------------
// One keyword, and separately callable steps
// ---------------------------------------------------------------------

/// One and the same wire `service_name` selects the config entry,
/// supplies the `<component>` segment of the id and supplies the
/// `<service>` segment of the SAN. Asserted together rather than each in
/// isolation, because a second selector would only show up as a
/// disagreement between them.
#[test]
fn one_service_name_does_all_three_jobs() {
    let (_dir, config) = loaded_default();
    let service_name = "piglet";

    let entry = config
        .component(service_name)
        .expect("the entry is selected");
    assert_eq!(entry.multiplicity(), Multiplicity::ManyPerHost);

    let derived = config
        .resolve_end_to_end(service_name, "h1", Some(1), Some(&piglet_spec()))
        .expect("the request resolves");
    assert_eq!(derived.registration_id, "h1-piglet-001");
    assert_eq!(derived.san, "001.piglet.h1.trusted.domain");

    // The one keyword is literally present in all three places.
    assert!(config.component_names().any(|name| name == service_name));
    assert!(derived.registration_id.contains(service_name));
    assert!(derived.san.contains(&format!(".{service_name}.")));
}

/// The pre-derivation arm is reachable without deriving anything, so a
/// refusal there has no `registration_id` to report and none is computed
/// as a side effect.
#[test]
fn the_pre_derivation_steps_are_callable_without_deriving() {
    let (_dir, config) = loaded_default();

    // Labels, on their own.
    assert!(validate_request_labels("piglet", "h1").is_ok());

    // Class resolution, on its own.
    assert_eq!(
        config.multiplicity("piglet").expect("piglet is configured"),
        Multiplicity::ManyPerHost
    );

    // The shape check, on its own — and its refusal is an error with no
    // id field at all, because the derivation was never reached.
    let err = check_instance_shape("piglet", Multiplicity::ManyPerHost, None)
        .expect_err("an omitted instance must be refused");
    match err {
        RegistrarError::ServiceInstanceMismatch {
            component,
            multiplicity,
            instance_supplied,
        } => {
            assert_eq!(component, "piglet");
            assert_eq!(multiplicity, Multiplicity::ManyPerHost);
            assert!(!instance_supplied);
        }
        other => panic!("expected ServiceInstanceMismatch, got {other:?}"),
    }
}

/// Derivation and safe-set validation are two calls with the caller's
/// own collision check between them. Neither takes, reads or requires
/// registration state.
#[test]
fn derivation_and_safe_set_validation_are_separate_calls() {
    let (_dir, config) = loaded_default();

    let multiplicity = config
        .check_identity_shape("piglet", Some(1))
        .expect("the shape is valid");
    let registration_id =
        derive_registration_id(multiplicity, "piglet", "h1", Some(1)).expect("the key derives");
    assert_eq!(registration_id, "h1-piglet-001");

    // Here is where the verb layer takes its per-identity mutex and
    // consults its durable binding. This library has nothing to
    // contribute, which is the point.

    config
        .validate_spec("piglet", &piglet_spec())
        .expect("the spec is inside the safe-set");
}

// ---------------------------------------------------------------------
// The fixture builder
// ---------------------------------------------------------------------

#[test]
fn the_fixture_builder_produces_a_config_the_loader_accepts() {
    let (_dir, loaded) = load_fixture(&RegistrarConfigFixture::new());
    let config = loaded.expect("the default fixture must load");
    assert_eq!(config.domain(), FIXTURE_DOMAIN);
    assert_eq!(config.component_names().count(), 3);
}

#[test]
fn every_fixture_override_takes_effect() {
    let spec = RegistrationSpec {
        cert_group: Some(4242),
        reload: ReloadSpec::new(ReloadKind::Sighup, "hog"),
    };
    let fixture = RegistrarConfigFixture::new()
        .with_domain("other.domain")
        .with_multiplicity("review", Multiplicity::OnePerHost)
        .with_spec("piglet", &spec)
        .with_component("hog", Multiplicity::ManyPerHost, &spec)
        .without_component("roxyd");
    let (_dir, loaded) = load_fixture(&fixture);
    let config = loaded.expect("the overridden fixture must load");

    assert_eq!(config.domain(), "other.domain");
    assert_eq!(
        config.multiplicity("review").expect("review is configured"),
        Multiplicity::OnePerHost
    );
    assert_eq!(
        config
            .component("piglet")
            .expect("piglet is configured")
            .spec(),
        &spec
    );
    assert_eq!(
        config
            .component("hog")
            .expect("hog is configured")
            .multiplicity(),
        Multiplicity::ManyPerHost
    );
    assert!(matches!(
        config.multiplicity("roxyd"),
        Err(RegistrarError::ComponentNotConfigured { .. })
    ));

    // An empty fixture still loads: it is a config with no components,
    // and every request against it is refused individually.
    let (_dir, loaded) = load_fixture(&RegistrarConfigFixture::empty());
    let config = loaded.expect("an empty fixture must load");
    assert_eq!(config.component_names().count(), 0);
}

// ---------------------------------------------------------------------
// Helpers for the composer-agreement test
// ---------------------------------------------------------------------

fn settings_with_domain(domain: &str) -> Settings {
    Settings {
        email: "ops@example.invalid".to_string(),
        server: "https://ca.example.invalid/acme/directory".to_string(),
        domain: domain.to_string(),
        eab: None,
        acme: AcmeSettings {
            http_responder_url: "http://127.0.0.1:0".to_string(),
            http_responder_hmac: "hmac".into(),
            http_responder_timeout_secs: 5,
            http_responder_token_ttl_secs: 5,
            directory_fetch_attempts: 1,
            directory_fetch_base_delay_secs: 1,
            directory_fetch_max_delay_secs: 1,
            poll_attempts: 1,
            poll_interval_secs: 1,
            account_key_path: None,
        },
        retry: RetrySettings {
            backoff_secs: vec![1],
        },
        trust: TrustSettings::default(),
        scheduler: SchedulerSettings::default(),
        profiles: Vec::new(),
        openbao: None,
        registrar_endpoint: RegistrarEndpointSettings::default(),
    }
}

fn profile_with(instance_id: &str, service_name: &str, hostname: &str) -> DaemonProfileSettings {
    DaemonProfileSettings {
        // `profile_domain` never reads this field, and this test is the
        // one place that must not look like a second derivation site.
        registration_id: "unread-by-profile-domain".to_string(),
        service_name: service_name.to_string(),
        instance_id: instance_id.to_string(),
        hostname: hostname.to_string(),
        paths: Paths {
            cert: PathBuf::from("/tmp/cert.pem"),
            key: PathBuf::from("/tmp/key.pem"),
        },
        daemon: DaemonRuntimeSettings {
            check_interval: Duration::from_secs(1),
            renew_before: Duration::from_secs(1),
            check_jitter: Duration::from_secs(0),
        },
        retry: None,
        hooks: HookSettings::default(),
        eab: None,
        cert_group_gid: None,
    }
}
