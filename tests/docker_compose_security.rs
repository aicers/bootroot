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

/// step-ca's Prometheus metrics listener (issue #864). `bootroot init`
/// writes `metricsAddress: ":9102"` into `ca.json`, which starts an
/// unauthenticated, plaintext endpoint; the only boundary it has is the
/// Compose network. The port is therefore `expose`d — so Prometheus can
/// reach `step-ca:9102` — and must never appear in a `ports:` mapping,
/// which would put internal telemetry on the host's network.
///
/// A publish is `- "9102:9102"` or `- "127.0.0.1:9102:9102"`; the
/// expose is the bare `- "9102"`. Any other quoted list entry carrying
/// the port is therefore a publish, whichever key it sits under.
fn assert_metrics_port_exposed_never_published(compose: &str, file_name: &str) {
    assert!(
        compose.contains("    expose:\n      - \"9102\"\n"),
        "{file_name} must expose 9102 on step-ca so Prometheus can scrape it"
    );
    for line in compose.lines() {
        let entry = line.trim();
        assert!(
            !(entry.starts_with("- \"") && entry.contains("9102") && entry != "- \"9102\""),
            "{file_name} must not publish step-ca's metrics port to the host, found: {line}"
        );
    }
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
