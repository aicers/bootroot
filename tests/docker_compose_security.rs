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

/// Returns the lines nested under `services.<service>.<key>`, or `None`
/// when the service declares no such key. Compose is read structurally
/// rather than by substring so a mapping can be judged by the section it
/// sits in: the same `- "9102"` entry is the wanted exposure under
/// `expose:` and a host publication under `ports:`.
fn service_key_block<'a>(compose: &'a str, service: &str, key: &str) -> Option<Vec<&'a str>> {
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
            0 => in_services = trimmed == "services:",
            2 if in_services => in_service = trimmed == format!("{service}:"),
            4 if in_service && trimmed == format!("{key}:") => {
                let mut block = Vec::new();
                while let Some(entry) = lines.peek() {
                    if line_indent(entry) <= 4 {
                        break;
                    }
                    block.push(entry.trim());
                    lines.next();
                }
                return Some(block);
            }
            _ => {}
        }
    }
    None
}

/// step-ca's Prometheus metrics listener (issue #864). `bootroot init`
/// writes `metricsAddress: ":9102"` into `ca.json`, which starts an
/// unauthenticated, plaintext endpoint; the only boundary it has is the
/// Compose network. The port is therefore `expose`d — so Prometheus can
/// reach `step-ca:9102` — and must never appear under `ports:`, which
/// would put internal telemetry on the host's network.
///
/// Every `ports:` syntax is rejected by looking for the port anywhere in
/// the section: the short `- "9102:9102"` and `- "127.0.0.1:9102:9102"`,
/// the short `- "9102"` that Compose publishes to an ephemeral host port
/// on every interface, and the long `- target: 9102` mapping.
fn assert_metrics_port_exposed_never_published(compose: &str, file_name: &str) {
    let exposed = service_key_block(compose, "step-ca", "expose")
        .unwrap_or_else(|| panic!("{file_name} must declare expose: on step-ca"));
    assert!(
        exposed
            .iter()
            .any(|entry| entry.trim_start_matches("- ").trim_matches('"') == METRICS_PORT),
        "{file_name} must expose {METRICS_PORT} on step-ca so Prometheus can scrape it, found: {exposed:?}"
    );
    let published = service_key_block(compose, "step-ca", "ports").unwrap_or_default();
    for entry in published {
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
fn service_key_block_reads_the_named_section_only() {
    assert_eq!(
        service_key_block(SECTION_FIXTURE, "step-ca", "ports"),
        Some(vec!["- \"127.0.0.1:${STEPCA_HOST_PORT:-9000}:9000\""])
    );
    assert_eq!(
        service_key_block(SECTION_FIXTURE, "step-ca", "expose"),
        Some(vec!["- \"9102\""])
    );
    assert_eq!(
        service_key_block(SECTION_FIXTURE, "step-ca", "healthcheck"),
        None
    );
    assert_metrics_port_exposed_never_published(SECTION_FIXTURE, "fixture");
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
