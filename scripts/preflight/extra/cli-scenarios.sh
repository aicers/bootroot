#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"
INIT_SUMMARY_JSON="$ROOT_DIR/tmp/cli-init-summary.json"

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
  docker compose -f docker-compose.yml -f docker-compose.test.yml stop openbao >/dev/null 2>&1 || true
  docker rm bootroot-openbao >/dev/null 2>&1 || true
  docker volume rm bootroot_openbao-data >/dev/null 2>&1 || true
}

run_init_scenario() {
  log "Running init scenario"
  reset_openbao

  log "Cleaning local secrets and outputs"
  rm -rf "$ROOT_DIR/secrets" "$ROOT_DIR/certs" "$ROOT_DIR/tmp" "$ROOT_DIR/state.json"

  log "Preparing step-ca config"
  mkdir -p "$ROOT_DIR/secrets/config" "$ROOT_DIR/secrets/secrets" "$ROOT_DIR/tmp"
  chmod 700 "$ROOT_DIR/secrets" "$ROOT_DIR/secrets/config" "$ROOT_DIR/secrets/secrets"
  if [ ! -f "$ROOT_DIR/secrets/password.txt" ]; then
    openssl rand -base64 32 > "$ROOT_DIR/secrets/password.txt"
    chmod 600 "$ROOT_DIR/secrets/password.txt"
  fi
  local stepca_password
  stepca_password="$(cat "$ROOT_DIR/secrets/password.txt")"
  docker run --rm --user root \
    -v "$ROOT_DIR/secrets:/home/step" \
    smallstep/step-ca \
    step ca init \
    --name "Bootroot CA" \
    --provisioner "admin" \
    --dns "localhost,bootroot-ca" \
    --address ":9000" \
    --password-file /home/step/password.txt \
    --provisioner-password-file /home/step/password.txt \
    --acme

  log "Starting infra"
  log "Building local images"
  docker compose -f docker-compose.yml -f docker-compose.test.yml build step-ca bootroot-http01
  if [ -x "$ROOT_DIR/scripts/impl/update-ca-db-dsn.sh" ]; then
    log "Updating ca.json DB DSN"
    "$ROOT_DIR/scripts/impl/update-ca-db-dsn.sh"
  fi
  log "Starting minimal infra (openbao/postgres/responder)"
  docker compose -f docker-compose.yml -f docker-compose.test.yml up -d openbao postgres bootroot-http01

  log "Running bootroot init"
  BOOTROOT_LANG=en printf "y\ny\nn\n" | cargo run --bin bootroot -- init \
    --auto-generate \
    --show-secrets \
    --summary-json "$INIT_SUMMARY_JSON" \
    --http-hmac "dev-hmac" \
    --stepca-password "$stepca_password" \
    --db-dsn "postgresql://step:step-pass@postgres:5432/stepca?sslmode=disable" \
    --responder-url "http://localhost:8080" \
    --skip-responder-check | tee "$ROOT_DIR/tmp/cli-init.log"

  if [ ! -f "$INIT_SUMMARY_JSON" ]; then
    fail "Init summary JSON not found: $INIT_SUMMARY_JSON"
  fi

  log "Validating full infra"
  cargo run --bin bootroot -- infra up
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
  cat >"$output_path" <<'EOF'
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

  add_stepca_host_aliases
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
