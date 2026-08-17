use std::fs;
use std::path::Path;

#[test]
fn postgres_port_is_bound_to_localhost_by_default() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.yml");
    assert!(
        compose.contains(r#""127.0.0.1:${POSTGRES_HOST_PORT:-5433}:5432""#),
        "postgres port mapping must default to localhost binding on port 5433 (issue #588 §4c)"
    );
}

/// The host-side port of every core service is interpolated so two
/// bootroot instances can share a host (issue #731), and `infra install`'s
/// preflight resolves the same `(variable, default)` pairs rather than
/// parsing the YAML. Drift between the two silently reintroduces the
/// collision the preflight is meant to diagnose.
const INTERPOLATED_PORT_MAPPINGS: [&str; 3] = [
    r#""127.0.0.1:${OPENBAO_HOST_PORT:-8200}:8200""#,
    r#""127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000""#,
    r#""127.0.0.1:${HTTP01_ADMIN_HOST_PORT:-8080}:8080""#,
];

#[test]
fn core_service_host_ports_are_interpolated_with_todays_defaults() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.yml");
    for mapping in INTERPOLATED_PORT_MAPPINGS {
        assert!(
            compose.contains(mapping),
            "docker-compose.yml must publish {mapping} verbatim (issue #731)"
        );
    }
}

#[test]
fn deploy_core_service_host_ports_are_interpolated_with_todays_defaults() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.deploy.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.deploy.yml");
    for mapping in INTERPOLATED_PORT_MAPPINGS {
        assert!(
            compose.contains(mapping),
            "docker-compose.deploy.yml must publish {mapping} verbatim (issue #731)"
        );
    }
}

const METRICS_PORT: &str = "9102";

fn line_indent(line: &str) -> usize {
    line.len() - line.trim_start().len()
}

/// The value of `services.<service>.<key>`, classified by the YAML form
/// it is written in. A guard that judges entries has to know when it is
/// looking at all of them: a form it cannot enumerate is not an empty
/// section.
#[derive(Debug, PartialEq)]
enum SectionValue<'a> {
    /// A block sequence — one entry per line nested under the key.
    Block(Vec<&'a str>),
    /// A flow sequence written on the key's own line: `ports: ["9102"]`.
    Flow(Vec<&'a str>),
    /// Anything else on the key's own line: an alias (`ports: *shared`),
    /// a flow mapping, a scalar. The entries live elsewhere in the
    /// document, or nowhere this reader can follow.
    Unreadable(&'a str),
}

impl<'a> SectionValue<'a> {
    /// Returns the section's entries, or `None` when the form does not
    /// carry them.
    fn entries(&self) -> Option<&[&'a str]> {
        match self {
            SectionValue::Block(entries) | SectionValue::Flow(entries) => Some(entries),
            SectionValue::Unreadable(_) => None,
        }
    }
}

/// An anchor declared on a block value (`ports: &stepca_ports`) leaves
/// the entries where they were, on the lines below.
fn is_bare_anchor(rest: &str) -> bool {
    rest.strip_prefix('&')
        .is_some_and(|name| !name.is_empty() && !name.contains(char::is_whitespace))
}

/// Returns the value of `services.<service>.<key>`, or `None` when the
/// service declares no such key. Compose is read structurally rather
/// than by substring so a mapping can be judged by the section it sits
/// in: the same `- "9102"` entry is the wanted exposure under `expose:`
/// and a host publication under `ports:`.
fn service_key_value<'a>(compose: &'a str, service: &str, key: &str) -> Option<SectionValue<'a>> {
    let significant = |line: &&str| {
        let trimmed = line.trim();
        !trimmed.is_empty() && !trimmed.starts_with('#')
    };
    let mut lines = compose.lines().filter(significant).peekable();
    let mut in_services = false;
    let mut in_service = false;
    while let Some(line) = lines.next() {
        let indent = line_indent(line);
        let trimmed = line.trim();
        match indent {
            0 => {
                in_services = trimmed == "services:";
                in_service = false;
            }
            2 => in_service = in_services && trimmed == format!("{service}:"),
            4 if in_service => {
                let Some(rest) = trimmed
                    .strip_prefix(key)
                    .and_then(|rest| rest.strip_prefix(':'))
                    .map(str::trim)
                else {
                    continue;
                };
                if !rest.is_empty() && !is_bare_anchor(rest) {
                    let flow = rest
                        .strip_prefix('[')
                        .and_then(|inner| inner.strip_suffix(']'));
                    return Some(flow.map_or(SectionValue::Unreadable(rest), |inner| {
                        SectionValue::Flow(
                            inner
                                .split(',')
                                .map(str::trim)
                                .filter(|entry| !entry.is_empty())
                                .collect(),
                        )
                    }));
                }
                let mut block = Vec::new();
                while let Some(entry) = lines.peek() {
                    if line_indent(entry) <= 4 {
                        break;
                    }
                    block.push(entry.trim());
                    lines.next();
                }
                return Some(SectionValue::Block(block));
            }
            _ => {}
        }
    }
    None
}

/// Strips the block sequence's `- ` and the quoting either form may
/// carry, leaving the entry's text.
fn entry_text(entry: &str) -> &str {
    entry
        .strip_prefix("- ")
        .unwrap_or(entry)
        .trim()
        .trim_matches(['"', '\''])
}

/// step-ca's Prometheus metrics listener (issue #864). `bootroot init`
/// writes `metricsAddress: ":9102"` into `ca.json`, which starts an
/// unauthenticated, plaintext endpoint; the only boundary it has is the
/// Compose network. The port is therefore `expose`d — so Prometheus can
/// reach `step-ca:9102` — and must never appear under `ports:`, which
/// would put internal telemetry on the host's network.
///
/// Every `ports:` syntax that names the port is rejected by looking for
/// it anywhere in the section: the short `- "9102:9102"` and
/// `- "127.0.0.1:9102:9102"`, the short `- "9102"` that Compose
/// publishes to an ephemeral host port on every interface, the long
/// `- target: 9102` mapping, and the flow `ports: ["9102"]`. A `ports:`
/// whose entries this reader cannot enumerate — an alias, a scalar — is
/// rejected outright rather than read as an absent section, because a
/// guard that cannot see the entries cannot clear them.
fn assert_metrics_port_exposed_never_published(compose: &str, file_name: &str) {
    let exposed = service_key_value(compose, "step-ca", "expose")
        .unwrap_or_else(|| panic!("{file_name} must declare expose: on step-ca"));
    let exposed = exposed.entries().unwrap_or_else(|| {
        panic!(
            "{file_name} writes step-ca's expose: in a form this guard cannot read: {exposed:?}. \
             Write it as a list, or teach the reader the form."
        )
    });
    assert!(
        exposed
            .iter()
            .copied()
            .map(entry_text)
            .any(|entry| entry == METRICS_PORT),
        "{file_name} must expose {METRICS_PORT} on step-ca so Prometheus can scrape it, found: {exposed:?}"
    );
    let Some(published) = service_key_value(compose, "step-ca", "ports") else {
        return;
    };
    let entries = published.entries().unwrap_or_else(|| {
        panic!(
            "{file_name} writes step-ca's ports: in a form this guard cannot read: {published:?}. \
             Write it as a list, or teach the reader the form — an unreadable ports: cannot be \
             cleared of {METRICS_PORT}."
        )
    });
    for entry in entries {
        assert!(
            !entry.contains(METRICS_PORT),
            "{file_name} must not publish step-ca's metrics port to the host, \
             found under step-ca ports: {entry}"
        );
    }
}

/// The guard above judges a mapping by the section it sits in, so a
/// reader that silently found the wrong section — or none — would let
/// every publication pass. Pin it against a document that puts the port
/// under a neighbouring service's `ports:` and under step-ca's `expose:`.
const SECTION_FIXTURE: &str = concat!(
    "services:\n",
    "  openbao:\n",
    "    ports:\n",
    "      # a neighbour publishing 9102 says nothing about step-ca\n",
    "      - \"127.0.0.1:9102:9102\"\n",
    "\n",
    "  step-ca:\n",
    "    ports:\n",
    "      - \"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\"\n",
    "    expose:\n",
    "      - \"9102\"\n",
    "    volumes:\n",
    "      - ./secrets:/home/step\n",
    "volumes:\n",
    "  openbao-data:\n",
);

#[test]
fn service_key_value_reads_the_named_section_only() {
    assert_eq!(
        service_key_value(SECTION_FIXTURE, "step-ca", "ports"),
        Some(SectionValue::Block(vec![
            "- \"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\""
        ]))
    );
    assert_eq!(
        service_key_value(SECTION_FIXTURE, "step-ca", "expose"),
        Some(SectionValue::Block(vec!["- \"9102\""]))
    );
    assert_eq!(
        service_key_value(SECTION_FIXTURE, "step-ca", "healthcheck"),
        None
    );
    assert_metrics_port_exposed_never_published(SECTION_FIXTURE, "fixture");
}

/// A key whose value shares its line is a different YAML form, not a
/// missing key: the flow sequence carries its entries there, and an
/// alias carries them somewhere this reader does not follow. An anchor
/// alone still leaves a block underneath.
#[test]
fn service_key_value_classifies_the_forms_that_share_the_keys_line() {
    let flow = SECTION_FIXTURE.replace(
        "    ports:\n      - \"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\"\n",
        "    ports: [\"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\", \"9102\"]\n",
    );
    assert_eq!(
        service_key_value(&flow, "step-ca", "ports"),
        Some(SectionValue::Flow(vec![
            "\"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\"",
            "\"9102\""
        ]))
    );

    let aliased = SECTION_FIXTURE.replace(
        "    ports:\n      - \"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\"\n",
        "    ports: *shared_ports\n",
    );
    assert_eq!(
        service_key_value(&aliased, "step-ca", "ports"),
        Some(SectionValue::Unreadable("*shared_ports"))
    );

    let anchored = SECTION_FIXTURE.replace(
        "    ports:\n      - \"127",
        "    ports: &shared_ports\n      - \"127",
    );
    assert_eq!(
        service_key_value(&anchored, "step-ca", "ports"),
        Some(SectionValue::Block(vec![
            "- \"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\""
        ]))
    );
}

/// Compose publishes a bare `- "9102"` under `ports:` to an ephemeral
/// host port on every interface — the same entry the exposure needs.
#[test]
#[should_panic(expected = "must not publish step-ca's metrics port")]
fn short_form_publication_of_the_metrics_port_is_rejected() {
    let published = SECTION_FIXTURE.replace(
        "    ports:\n      - \"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\"\n",
        "    ports:\n      - \"9102\"\n",
    );
    assert_metrics_port_exposed_never_published(&published, "fixture");
}

/// The long syntax names the container port under `target:`, so nothing
/// in the entry looks like a `host:container` mapping.
#[test]
#[should_panic(expected = "must not publish step-ca's metrics port")]
fn long_form_publication_of_the_metrics_port_is_rejected() {
    let published = SECTION_FIXTURE.replace(
        "      - \"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\"\n",
        "      - target: 9102\n        published: \"19102\"\n",
    );
    assert_metrics_port_exposed_never_published(&published, "fixture");
}

/// The flow sequence is the same publication written on the key's own
/// line; the section reader has to carry its entries out, not report the
/// key missing.
#[test]
#[should_panic(expected = "must not publish step-ca's metrics port")]
fn flow_sequence_publication_of_the_metrics_port_is_rejected() {
    let published = SECTION_FIXTURE.replace(
        "    ports:\n      - \"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\"\n",
        "    ports: [\"9102\"]\n",
    );
    assert_metrics_port_exposed_never_published(&published, "fixture");
}

/// An alias puts the entries in an anchor elsewhere in the document. The
/// guard cannot tell whether they name the metrics port, so it fails
/// rather than clearing a section it never read.
#[test]
#[should_panic(expected = "ports: in a form this guard cannot read")]
fn aliased_ports_are_rejected() {
    let published = SECTION_FIXTURE.replace(
        "    ports:\n      - \"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\"\n",
        "    ports: *shared_ports\n",
    );
    assert_metrics_port_exposed_never_published(&published, "fixture");
}

#[test]
fn stepca_metrics_port_is_exposed_but_never_published() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.yml");
    assert_metrics_port_exposed_never_published(&compose, "docker-compose.yml");
}

#[test]
fn deploy_stepca_metrics_port_is_exposed_but_never_published() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.deploy.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.deploy.yml");
    assert_metrics_port_exposed_never_published(&compose, "docker-compose.deploy.yml");
}

#[test]
fn postgres_volume_uses_postgresql_root_for_postgres_18() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.yml");
    assert!(
        compose.contains("- postgres-data:/var/lib/postgresql"),
        "postgres volume must mount /var/lib/postgresql for PostgreSQL 18"
    );
}

// The deploy compose (issue #704) drops build contexts but must keep the
// same secure/correct runtime config as the stock compose, so a prebuilt /
// air-gapped install is not silently less safe. Guard against drift.
#[test]
fn deploy_postgres_port_is_bound_to_localhost_by_default() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.deploy.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.deploy.yml");
    assert!(
        compose.contains(r#""127.0.0.1:${POSTGRES_HOST_PORT:-5433}:5432""#),
        "deploy postgres port mapping must default to localhost binding on port 5433"
    );
}

#[test]
fn deploy_postgres_volume_uses_postgresql_root_for_postgres_18() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.deploy.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.deploy.yml");
    assert!(
        compose.contains("- postgres-data:/var/lib/postgresql"),
        "deploy postgres volume must mount /var/lib/postgresql for PostgreSQL 18"
    );
}

// The deploy compose exists precisely so a prebuilt payload never rebuilds
// from source; a stray `build:` key would reintroduce the source-tree /
// network dependency the deploy path is meant to remove.
#[test]
fn deploy_compose_has_no_build_contexts() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.deploy.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.deploy.yml");
    for line in compose.lines() {
        assert!(
            !line.trim_start().starts_with("build:"),
            "deploy compose must carry no build: contexts, found: {line}"
        );
    }
}

// The test overlay (issue #746) is layered as a second `-f` over
// docker-compose.yml and adds network aliases only. A `container_name:`
// here would override the base file's `${BOOTROOT_INSTANCE:-bootroot}-*`
// interpolation with a literal, so the E2E stacks that always layer it
// would stop following the install identity — silently, because the
// derivation checks in `src/commands/init/constants.rs` read only the two
// base compose files.
#[test]
fn test_overlay_pins_no_container_name() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.test.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.test.yml");
    for line in compose.lines() {
        assert!(
            !line.trim_start().starts_with("container_name:"),
            "the test overlay must declare no container_name:, found: {line}"
        );
    }
}
