#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"
INIT_SUMMARY_JSON="$ROOT_DIR/tmp/cli-init-summary.json"
# Pin POSTGRES_HOST_PORT for the compose stack: docker-compose.yml's
# default moved from 5432 to 5433 in #588 §4c; this preflight assumes
# 5432, so pin it explicitly to keep the compose port mapping aligned
# with wait_for_postgres_admin.
export POSTGRES_HOST_PORT="${POSTGRES_HOST_PORT:-5432}"
export POSTGRES_HOST="127.0.0.1"
export POSTGRES_PORT="$POSTGRES_HOST_PORT"

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

wait_for_postgres_admin() {
  local host_port="${POSTGRES_HOST_PORT:-5432}"
  local admin_user="${POSTGRES_USER:-step}"
  local attempt
  for attempt in $(seq 1 30); do
    if docker exec bootroot-postgres pg_isready -U "$admin_user" -d postgres >/dev/null 2>&1 &&
      bash -lc ": >/dev/tcp/127.0.0.1/${host_port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs bootroot-postgres >&2 || true
  fail "PostgreSQL admin endpoint did not become reachable before init"
}

current_responder_hmac() {
  if [ -f "$ROOT_DIR/responder.toml.compose" ]; then
    awk -F'"' '/^hmac_secret = / {print $2; exit}' "$ROOT_DIR/responder.toml.compose"
    return
  fi
  if [ -f "$ROOT_DIR/secrets/responder/responder.toml" ]; then
    awk -F'"' '/^hmac_secret = / {print $2; exit}' "$ROOT_DIR/secrets/responder/responder.toml"
    return
  fi
  printf '%s\n' "dev-hmac"
}

run_cli_tests() {
  log "Running CLI unit tests"
  cargo test --bin bootroot

  log "Running CLI integration tests"
  cargo test --test bootroot_cli
}

reset_openbao() {
  log "Resetting OpenBao state"
  docker compose -f docker-compose.yml -f docker-compose.test.yml down -v --remove-orphans \
    >/dev/null 2>&1 || true
}

run_init_scenario() {
  log "Running init scenario"
  reset_openbao

  log "Cleaning local secrets and outputs"
  rm -rf "$ROOT_DIR/secrets" "$ROOT_DIR/certs" "$ROOT_DIR/tmp" "$ROOT_DIR/state.json" "$ROOT_DIR/.env"
  mkdir -p "$ROOT_DIR/tmp"

  local responder_hmac
  responder_hmac="$(current_responder_hmac)"

  log "Installing infrastructure"
  cargo run --bin bootroot -- infra install

  wait_for_postgres_admin
  log "Running bootroot init"
  BOOTROOT_LANG=en printf "y\ny\ny\nn\n" | cargo run --bin bootroot -- init \
    --enable auto-generate,show-secrets,db-provision \
    --summary-json "$INIT_SUMMARY_JSON" \
    --http-hmac "$responder_hmac" \
    --db-user "step" \
    --db-name "stepca" \
    --responder-url "http://localhost:8080" \
    --skip responder-check | tee "$ROOT_DIR/tmp/cli-init.log"

  if [ ! -f "$INIT_SUMMARY_JSON" ]; then
    fail "Init summary JSON not found: $INIT_SUMMARY_JSON"
  fi

  log "Validating full infra"
  cargo run --bin bootroot -- infra up

  # step-ca may have started before db-provision rotated the PostgreSQL role
  # password. Restart it so new DB connections use the provisioned DSN.
  log "Restarting step-ca with provisioned DB credentials"
  docker restart bootroot-ca >/dev/null
  wait_for_stepca_directory
}

verify_dns_aliases() {
  log "Verifying DNS aliases registered by service add"
  local container_id
  container_id="$(docker ps -q -f label=com.docker.compose.service=bootroot-http01)"
  if [[ -z "$container_id" ]]; then
    fail "bootroot-http01 container not running"
  fi
  local aliases
  aliases="$(docker inspect --format '{{range $k, $v := (index .NetworkSettings.Networks)}}{{range $v.Aliases}}{{.}} {{end}}{{end}}' "$container_id")"
  log "Current aliases on bootroot-http01: $aliases"
  for expected in "001.edge-proxy.edge-node-01.trusted.domain" "001.web-app.web-01.trusted.domain"; do
    if [[ "$aliases" != *"$expected"* ]]; then
      fail "Missing expected DNS alias: $expected"
    fi
  done
  log "All expected DNS aliases present"
}

wait_for_responder_http01() {
  local host="001.edge-proxy.edge-node-01.trusted.domain"
  local attempt
  for attempt in {1..15}; do
    if docker exec bootroot-ca bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${host}/80'" >/dev/null 2>&1; then
      log "Responder HTTP-01 is reachable from step-ca"
      return 0
    fi
    log "Waiting for responder HTTP-01 (attempt ${attempt}/15)"
    sleep 1
  done
  fail "Responder HTTP-01 is not reachable from step-ca"
}

wait_for_stepca_directory() {
  local attempt
  for attempt in {1..30}; do
    if curl --silent --show-error --fail --insecure --max-time 2 \
      https://localhost:9000/acme/acme/directory >/dev/null 2>&1; then
      log "step-ca ACME directory is reachable"
      return 0
    fi
    log "Waiting for step-ca ACME directory (attempt ${attempt}/30)"
    sleep 1
  done
  fail "step-ca ACME directory is not reachable"
}

write_agent_config() {
  local output_path="$1"
  local responder_hmac
  responder_hmac="$(current_responder_hmac)"
  cat >"$output_path" <<EOF
email = "admin@example.com"
server = "https://localhost:9000/acme/acme/directory"
domain = "trusted.domain"

[acme]
directory_fetch_attempts = 10
directory_fetch_base_delay_secs = 1
directory_fetch_max_delay_secs = 10
poll_attempts = 15
poll_interval_secs = 2
http_responder_url = "http://localhost:8080"
http_responder_hmac = "$responder_hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300
EOF
}

run_service_scenarios() {
  log "Running service add + verify scenarios"
  log "Building bootroot-agent for verify"
  cargo build --bin bootroot-agent
  export PATH="$ROOT_DIR/target/debug:$PATH"

  mkdir -p "$ROOT_DIR/tmp" "$ROOT_DIR/certs"
  write_agent_config "$ROOT_DIR/tmp/agent.toml"

  local runtime_service_add_role_id runtime_service_add_secret_id
  runtime_service_add_role_id="$(
    jq -r '.approles[] | select(.label == "runtime_service_add") | .role_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  runtime_service_add_secret_id="$(
    jq -r '.approles[] | select(.label == "runtime_service_add") | .secret_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  if [[ -z "${runtime_service_add_role_id:-}" ]]; then
    fail "Missing runtime_service_add role_id in init summary JSON: $INIT_SUMMARY_JSON"
  fi
  if [[ -z "${runtime_service_add_secret_id:-}" ]]; then
    fail "Missing runtime_service_add secret_id in init summary JSON: $INIT_SUMMARY_JSON"
  fi

  cargo run --bin bootroot -- service add \
    --service-name edge-proxy \
    --deploy-type daemon \
    --hostname edge-node-01 \
    --domain trusted.domain \
    --agent-config "$ROOT_DIR/tmp/agent.toml" \
    --cert-path "$ROOT_DIR/certs/edge-proxy.crt" \
    --key-path "$ROOT_DIR/certs/edge-proxy.key" \
    --instance-id 001 \
    --auth-mode approle \
    --approle-role-id "$runtime_service_add_role_id" \
    --approle-secret-id "$runtime_service_add_secret_id"

  cargo run --bin bootroot -- service add \
    --service-name web-app \
    --deploy-type docker \
    --hostname web-01 \
    --domain trusted.domain \
    --agent-config "$ROOT_DIR/tmp/agent.toml" \
    --cert-path "$ROOT_DIR/certs/web-app.crt" \
    --key-path "$ROOT_DIR/certs/web-app.key" \
    --instance-id 001 \
    --container-name web-app \
    --auth-mode approle \
    --approle-role-id "$runtime_service_add_role_id" \
    --approle-secret-id "$runtime_service_add_secret_id"

  verify_dns_aliases
  wait_for_responder_http01
  wait_for_stepca_directory

  run_verify edge-proxy

  run_verify web-app
}

run_verify() {
  local service_name="$1"
  local attempt
  for attempt in {1..3}; do
    if cargo run --bin bootroot -- verify \
      --service-name "$service_name" \
      --agent-config "$ROOT_DIR/tmp/agent.toml"; then
      return 0
    fi
    log "Retrying bootroot verify for ${service_name} (attempt ${attempt}/3)"
    sleep 2
  done
  fail "bootroot verify failed for ${service_name}"
}

require_cmd cargo
require_cmd docker
require_cmd curl
require_cmd jq
run_cli_tests
run_init_scenario
run_service_scenarios
