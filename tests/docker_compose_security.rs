use std::fs;
use std::path::Path;

#[test]
fn postgres_port_is_bound_to_localhost_by_default() {
    let compose_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docker-compose.yml");
    let compose = fs::read_to_string(compose_path).expect("read docker-compose.yml");
    assert!(
        compose.contains(r#""127.0.0.1:${POSTGRES_HOST_PORT:-5432}:5432""#),
        "postgres port mapping must default to localhost binding"
    );
}
