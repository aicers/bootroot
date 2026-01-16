#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

log() {
  printf "[%s] %s\n" "$(date +%H:%M:%S)" "$*"
}

fail() {
  printf "Error: %s\n" "$*" >&2
  exit 1
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing command: $1"
}

run_cli_tests() {
  log "Running CLI unit tests"
  cargo test --bin bootroot

  log "Running CLI integration tests"
  cargo test --test bootroot_cli
}

reset_openbao() {
  log "Resetting OpenBao state"
  docker compose stop openbao >/dev/null 2>&1 || true
  docker rm bootroot-openbao >/dev/null 2>&1 || true
  docker volume rm bootroot_openbao-data >/dev/null 2>&1 || true
}

run_init_scenario() {
  log "Running init scenario"
  reset_openbao

  log "Starting infra"
  if [[ "${BUILD_IMAGES:-0}" == "1" ]]; then
    log "Building local images"
    docker compose build step-ca bootroot-http01
  else
    log "Skipping local image build (set BUILD_IMAGES=1 to enable)"
  fi
  cargo run --bin bootroot -- infra up

  log "Running bootroot init"
  BOOTROOT_LANG=en printf "y\ny\ny\nn\n" | cargo run --bin bootroot -- init \
    --auto-generate \
    --show-secrets \
    --http-hmac "dev-hmac" \
    --db-dsn "postgresql://step:step@127.0.0.1:5432/step" \
    --responder-url "http://localhost:8080" | tee "$ROOT_DIR/tmp/cli-init.log"
}

add_stepca_host_aliases() {
  local responder_ip
  responder_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bootroot-http01)"
  if [[ -z "${responder_ip:-}" ]]; then
    fail "Failed to read responder container IP"
  fi

  log "Injecting responder host aliases into step-ca"
  docker exec bootroot-ca sh -c "printf '%s %s\n' '$responder_ip' '001.edge-proxy.edge-node-01.trusted.domain' >> /etc/hosts"
  docker exec bootroot-ca sh -c "printf '%s %s\n' '$responder_ip' '001.web-app.web-01.trusted.domain' >> /etc/hosts"
}

write_agent_config() {
  local output_path="$1"
  cat >"$output_path" <<'EOF'
email = "admin@example.com"
server = "https://localhost:9000/acme/acme/directory"
domain = "trusted.domain"

[scheduler]
max_concurrent_issuances = 1

[acme]
directory_fetch_attempts = 10
directory_fetch_base_delay_secs = 1
directory_fetch_max_delay_secs = 10
poll_attempts = 15
poll_interval_secs = 2
http_responder_url = "http://localhost:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

[[profiles]]
service_name = "edge-proxy"
instance_id = "001"
hostname = "edge-node-01"

[profiles.paths]
cert = "certs/edge-proxy.crt"
key = "certs/edge-proxy.key"

[profiles.daemon]
check_interval = "1h"
renew_before = "720h"
check_jitter = "0s"

[[profiles]]
service_name = "web-app"
instance_id = "001"
hostname = "web-01"

[profiles.paths]
cert = "certs/web-app.crt"
key = "certs/web-app.key"

[profiles.daemon]
check_interval = "1h"
renew_before = "720h"
check_jitter = "0s"
EOF
}

run_app_scenarios() {
  log "Running app add + verify scenarios"
  log "Building bootroot-agent for verify"
  cargo build --bin bootroot-agent
  export PATH="$ROOT_DIR/target/debug:$PATH"

  mkdir -p "$ROOT_DIR/tmp" "$ROOT_DIR/certs"
  write_agent_config "$ROOT_DIR/tmp/agent.toml"

  local root_token
  root_token="$(awk -F': ' '/root token:/ {print $2; exit}' "$ROOT_DIR/tmp/cli-init.log")"
  if [[ -z "${root_token:-}" ]]; then
    fail "Failed to read root token from init output"
  fi

  cargo run --bin bootroot -- app add \
    --service-name edge-proxy \
    --deploy-type daemon \
    --hostname edge-node-01 \
    --domain trusted.domain \
    --agent-config "$ROOT_DIR/tmp/agent.toml" \
    --cert-path "$ROOT_DIR/certs/edge-proxy.crt" \
    --key-path "$ROOT_DIR/certs/edge-proxy.key" \
    --instance-id 001 \
    --root-token "$root_token"

  cargo run --bin bootroot -- app add \
    --service-name web-app \
    --deploy-type docker \
    --hostname web-01 \
    --domain trusted.domain \
    --agent-config "$ROOT_DIR/tmp/agent.toml" \
    --cert-path "$ROOT_DIR/certs/web-app.crt" \
    --key-path "$ROOT_DIR/certs/web-app.key" \
    --instance-id 001 \
    --container-name web-app \
    --root-token "$root_token"

  add_stepca_host_aliases

  cargo run --bin bootroot -- verify \
    --service-name edge-proxy \
    --agent-config "$ROOT_DIR/tmp/agent.toml"

  cargo run --bin bootroot -- verify \
    --service-name web-app \
    --agent-config "$ROOT_DIR/tmp/agent.toml"
}

require_cmd cargo
require_cmd docker
run_cli_tests
run_init_scenario
run_app_scenarios
