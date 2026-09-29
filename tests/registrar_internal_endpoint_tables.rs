//! The operator's `[registrar]` and `[registrar_endpoint]` tables in the
//! bootroot-internal agent config: copied as written, alone, and kept by
//! a rotation.
//!
//! An integration test rather than a unit test beside the renderer:
//! nothing under `src/registrar/` may name the deployment state file, and
//! a complete endpoint table has to.

use std::sync::LazyLock;

use bootroot::config::{RegistrarEndpointSettings, RegistrarSettings, Settings};
use bootroot::registrar::internal::{
    EndpointTables, InternalAgentConfigParams, InternalPaths, REGISTRAR_ENDPOINT_TABLE,
    REGISTRAR_TABLE, load_internal_config, render_internal_agent_config, upsert_internal_trust,
};
use bootroot::secret::HmacSecret;
use tempfile::TempDir;

const DOMAIN: &str = "example.internal";
const HOST: &str = "bootroot-01";
const ROOT_FP: &str = "aa11bb22cc33dd44ee55ff6677889900aa11bb22cc33dd44ee55ff6677889900";
const OTHER_FP: &str = "1111111111111111111111111111111111111111111111111111111111111111";

/// The responder HMAC the params borrow; a `static` because a temporary
/// cannot outlive the function that returns the borrow.
static RESPONDER_HMAC: LazyLock<HmacSecret> = LazyLock::new(|| HmacSecret::from("hmac-value"));

fn config_params(pins: &[String]) -> InternalAgentConfigParams<'_> {
    InternalAgentConfigParams {
        email: "ops@example.internal",
        server: "https://bootroot-ca:9000/acme/acme/directory",
        domain: DOMAIN,
        hostname: HOST,
        responder_url: "http://bootroot-http01:8080",
        responder_hmac: &RESPONDER_HMAC,
        eab_kid: None,
        eab_hmac: None,
        trusted_ca_sha256: pins,
        endpoint_tables: None,
    }
}

/// Parses a rendered config the way `bootroot-agent` does.
fn toml_settings(rendered: &str) -> Settings {
    let dir = TempDir::new().expect("tempdir");
    let path = dir.path().join("agent.toml");
    std::fs::write(&path, rendered).expect("write the rendered config");
    Settings::from_file(Some(path)).expect("the rendered config must deserialize")
}

/// An operator `--agent-config` file for an enabled endpoint: the
/// seven required keys, one optional override, and every table
/// `init` owns — each holding a value `init` never renders, so a
/// leak of any of them is visible.
const OPERATOR_FILE: &str = r#"email = "operator@example.invalid"
server = "https://operator.invalid/acme/directory"
domain = "operator.invalid"

[acme]
http_responder_url = "http://operator.invalid:8080"
http_responder_hmac = "operator-hmac"

[trust]
trusted_ca_sha256 = ["ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"]

# The verb-layer settings the daemon serves the endpoint with.
[registrar]
state_file = "/var/lib/bootroot/state.json"
agent_server = "https://bootroot-ca.example.internal:9000/acme/acme/directory"
agent_responder_url = "http://bootroot-http01.example.internal:8080"
rate_limit_admission_burst = 7

[registrar_endpoint]
enabled = true
server_cert_path = "/etc/bootroot/registrar/server.crt"
server_key_path = "/etc/bootroot/registrar/server.key"
client_cert_path = "/etc/bootroot/registrar/client.crt"
client_key_path = "/etc/bootroot/registrar/client.key"

[[profiles]]
registration_id = "operator-profile"
service_name = "operator"
instance_id = "009"
hostname = "operator-host"

[profiles.paths]
cert = "/tmp/operator.crt"
key = "/tmp/operator.key"
"#;

fn operator_tables() -> EndpointTables {
    EndpointTables::extract(OPERATOR_FILE).expect("the operator file parses")
}

fn render_with(paths: &InternalPaths, tables: Option<&EndpointTables>) -> String {
    let pins = [ROOT_FP.to_string(), OTHER_FP.to_string()];
    render_internal_agent_config(
        paths,
        &InternalAgentConfigParams {
            endpoint_tables: tables,
            ..config_params(&pins)
        },
    )
}

/// The two tables as the daemon deserializes them out of `contents`.
fn parsed_tables(contents: &str) -> (RegistrarSettings, RegistrarEndpointSettings) {
    let settings = toml_settings(contents);
    (settings.registrar, settings.registrar_endpoint)
}

/// The keys one top-level table of `contents` spells, in order.
fn table_keys(contents: &str, name: &str) -> Vec<String> {
    let doc: toml_edit::DocumentMut = contents.parse().expect("TOML");
    doc.get(name)
        .and_then(toml_edit::Item::as_table)
        .map(|table| table.iter().map(|(key, _)| key.to_string()).collect())
        .unwrap_or_default()
}

/// The text of one top-level table of `contents`, from its header up
/// to the next header.
fn table_text(contents: &str, name: &str) -> String {
    let header = format!("[{name}]\n");
    let start = contents.find(&header).expect("the table header");
    let rest = &contents[start + header.len()..];
    let end = rest.find("\n[").map_or(rest.len(), |at| at + 1);
    format!("{header}{}", &rest[..end])
}

/// The rendered file carries the operator's two tables with the
/// same keys and values — and only the keys the operator wrote, so
/// every other key keeps its default.
#[test]
fn the_rendered_config_carries_the_operator_tables_verbatim() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let rendered = render_with(&paths, Some(&operator_tables()));

    assert_eq!(parsed_tables(&rendered), parsed_tables(OPERATOR_FILE));
    for name in [REGISTRAR_TABLE, REGISTRAR_ENDPOINT_TABLE] {
        assert_eq!(
            table_keys(&rendered, name),
            table_keys(OPERATOR_FILE, name),
            "[{name}] carries exactly the operator's keys: {rendered}"
        );
    }
    let (registrar, endpoint) = parsed_tables(&rendered);
    assert!(endpoint.enabled);
    assert_eq!(registrar.rate_limit_admission_burst, 7);
    assert_eq!(
        registrar.audit_store_dir,
        RegistrarSettings::default().audit_store_dir,
        "a key the operator left out keeps its default"
    );
}

/// Nothing else in the operator's file reaches the rendered config:
/// the top-level keys, `[acme]`, `[trust]` and `[[profiles]]` are
/// exactly what `init` renders without the tables.
#[test]
fn nothing_but_the_two_tables_is_copied() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let without = render_with(&paths, None);
    let with = render_with(&paths, Some(&operator_tables()));

    assert!(
        with.starts_with(&without),
        "the tables are appended after everything init renders"
    );
    for leaked in [
        "operator@example.invalid",
        "operator.invalid",
        "operator-hmac",
        "operator-profile",
        "ffffffff",
    ] {
        assert!(!with.contains(leaked), "{leaked} leaked: {with}");
    }

    let plain = toml_settings(&without);
    let carried = toml_settings(&with);
    assert_eq!(carried.email, plain.email);
    assert_eq!(carried.server, plain.server);
    assert_eq!(carried.domain, plain.domain);
    assert_eq!(
        carried.acme.http_responder_url,
        plain.acme.http_responder_url
    );
    assert_eq!(
        carried.acme.http_responder_hmac.expose(),
        plain.acme.http_responder_hmac.expose()
    );
    assert_eq!(carried.acme.account_key_path, plain.acme.account_key_path);
    assert_eq!(carried.trust.ca_bundle_path, plain.trust.ca_bundle_path);
    assert_eq!(
        carried.trust.trusted_ca_sha256,
        plain.trust.trusted_ca_sha256
    );
    assert_eq!(carried.profiles.len(), 1);
    let (carried_profile, plain_profile) = (
        carried.profiles.first().expect("one profile"),
        plain.profiles.first().expect("one profile"),
    );
    assert_eq!(
        carried_profile.registration_id,
        plain_profile.registration_id
    );
    assert_eq!(carried_profile.service_name, plain_profile.service_name);
    assert_eq!(carried_profile.paths.cert, plain_profile.paths.cert);
    assert_eq!(carried_profile.paths.key, plain_profile.paths.key);
}

/// The published file is still the internal credential's config and
/// is a configuration the endpoint daemon accepts.
///
/// `Settings::validate` refuses an enabled endpoint off Linux — the
/// platform rule, which belongs to the listening process — so there
/// the rest of it is exercised with the endpoint switched off and
/// the two tables are held to the daemon's own table checks
/// separately.
#[test]
fn the_rendered_config_loads_and_validates() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let rendered = render_with(&paths, Some(&operator_tables()));
    std::fs::create_dir_all(paths.dir()).expect("create the credential directory");
    std::fs::write(paths.agent_config(), &rendered).expect("write the config");

    let settings: Settings = load_internal_config(&paths).expect("the rendered config must load");
    bootroot::config::validate_registrar_tables(&settings.registrar, &settings.registrar_endpoint)
        .expect("the tables satisfy every requirement an enabled endpoint has");
    if cfg!(target_os = "linux") {
        settings.validate().expect("the daemon accepts the config");
    } else {
        let mut portable = settings.clone();
        portable.registrar_endpoint.enabled = false;
        portable
            .validate()
            .expect("the daemon accepts the config apart from the platform rule");
    }
}

/// An endpoint-disabled host renders exactly what it rendered before
/// the tables existed.
#[test]
fn no_tables_render_nothing_extra() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let without = render_with(&paths, None);
    let empty = render_with(&paths, Some(&EndpointTables::default()));
    assert_eq!(without, empty);
    assert!(!without.contains("\n[registrar"), "{without}");
}

/// A rotation's in-place `[trust]` upsert leaves both tables
/// byte-identical.
#[test]
fn a_trust_upsert_leaves_the_tables_byte_identical() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let before = render_with(&paths, Some(&operator_tables()));
    let additive = vec![
        ROOT_FP.to_string(),
        OTHER_FP.to_string(),
        "2".repeat(64),
        "3".repeat(64),
    ];
    let after = upsert_internal_trust(&before, &paths, &additive).expect("upsert");
    assert_ne!(before, after, "the pins really did change");
    for name in [REGISTRAR_TABLE, REGISTRAR_ENDPOINT_TABLE] {
        assert_eq!(table_text(&after, name), table_text(&before, name));
    }
    assert_eq!(toml_settings(&after).trust.trusted_ca_sha256, additive);
}

/// Re-extracting the tables from a rendered config and rendering
/// again — what every rebuild outside `init` does — reproduces the
/// same file.
#[test]
fn a_carried_over_rebuild_reproduces_the_tables() {
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let first = render_with(&paths, Some(&operator_tables()));
    let carried = EndpointTables::extract(&first).expect("the rendered config parses");
    assert_eq!(render_with(&paths, Some(&carried)), first);

    let plain = render_with(&paths, None);
    let nothing = EndpointTables::extract(&plain).expect("parses");
    assert!(
        nothing.is_empty(),
        "a disabled host's config carries no tables"
    );
}

/// An inline table or dotted keys are the same tables to the daemon,
/// and render as standard ones with the same values.
#[test]
fn inline_and_dotted_spellings_are_normalized() {
    let inline = concat!(
        "registrar = { state_file = \"/var/lib/bootroot/state.json\" }\n",
        "registrar_endpoint.enabled = true\n",
        "registrar_endpoint.server_cert_path = \"/etc/bootroot/registrar/server.crt\"\n",
    );
    let tables = EndpointTables::extract(inline).expect("parses");
    let dir = TempDir::new().expect("tempdir");
    let paths = InternalPaths::new(dir.path());
    let rendered = render_with(&paths, Some(&tables));
    assert!(rendered.contains("\n[registrar]\n"), "{rendered}");
    assert!(rendered.contains("\n[registrar_endpoint]\n"), "{rendered}");
    let settings = toml_settings(&rendered);
    assert_eq!(
        settings.registrar.state_file.as_deref(),
        Some(std::path::Path::new("/var/lib/bootroot/state.json"))
    );
    assert!(settings.registrar_endpoint.enabled);
    assert_eq!(
        settings.registrar_endpoint.server_cert_path.as_deref(),
        Some(std::path::Path::new("/etc/bootroot/registrar/server.crt"))
    );
}

/// A key that holds something other than a table, or a file that is
/// not TOML, is refused rather than read as "no tables".
#[test]
fn a_non_table_or_malformed_document_is_refused() {
    let err = EndpointTables::extract("registrar = 5\n").expect_err("not a table");
    assert!(err.to_string().contains("registrar"), "{err}");
    EndpointTables::extract("[registrar\n").expect_err("not TOML");
}
