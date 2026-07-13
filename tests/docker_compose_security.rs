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
