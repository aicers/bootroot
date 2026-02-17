#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-main-lifecycle-$(date +%s)}"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$ARTIFACT_DIR/workspace}"
SECRETS_DIR="${SECRETS_DIR:-$WORKSPACE_DIR/secrets}"
AGENT_CONFIG_PATH="${AGENT_CONFIG_PATH:-$WORKSPACE_DIR/agent.toml}"
CERTS_DIR="${CERTS_DIR:-$WORKSPACE_DIR/certs}"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"
INFRA_UP_ATTEMPTS="${INFRA_UP_ATTEMPTS:-6}"
INFRA_UP_DELAY_SECS="${INFRA_UP_DELAY_SECS:-5}"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"
BOOTROOT_AGENT_BIN="${BOOTROOT_AGENT_BIN:-$ROOT_DIR/target/debug/bootroot-agent}"
RESOLUTION_MODE="${RESOLUTION_MODE:-fqdn-only-hosts}"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
CERT_META_DIR="$ARTIFACT_DIR/cert-meta"
HOSTS_MARKER="# bootroot-e2e-main-lifecycle"

EDGE_SERVICE="edge-proxy"
EDGE_HOSTNAME="edge-node-01"
WEB_SERVICE="web-app"
WEB_HOSTNAME="web-01"
DOMAIN="trusted.domain"
INSTANCE_ID="001"

STEPCA_HOST_IP="127.0.0.1"
RESPONDER_HOST_IP="127.0.0.1"
STEPCA_HOST_NAME="stepca.internal"
RESPONDER_HOST_NAME="responder.internal"

STEPCA_SERVER_URL=""
STEPCA_EAB_URL=""
RESPONDER_URL=""
OPENBAO_ROOT_TOKEN=""

log_phase() {
  local phase="$1"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"ts":"%s","phase":"%s","mode":"%s"}\n' \
    "$now" "$phase" "$RESOLUTION_MODE" >>"$PHASE_LOG"
}

fail() {
  local message="$1"
  echo "$message" >&2
  exit 1
}

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required"
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  [ -x "$BOOTROOT_REMOTE_BIN" ] || fail "bootroot-remote binary not executable: $BOOTROOT_REMOTE_BIN"
}

run_bootroot() {
  (
    cd "$WORKSPACE_DIR"
    "$BOOTROOT_BIN" "$@"
  )
}

compose_down() {
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}

capture_artifacts() {
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
}

cleanup_hosts() {
  if [ "$RESOLUTION_MODE" != "hosts-all" ]; then
    return 0
  fi
  if ! command -v sudo >/dev/null 2>&1; then
    return 0
  fi
  local tmp_file
  tmp_file="$(mktemp)"
  sudo awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' /etc/hosts >"$tmp_file"
  sudo cp "$tmp_file" /etc/hosts
  rm -f "$tmp_file"
}

cleanup() {
  log_phase "cleanup"
  cleanup_hosts
  capture_artifacts
  compose_down
}

add_hosts_entry() {
  local ip="$1"
  local host="$2"
  if grep -qE "[[:space:]]${host}([[:space:]]|\$)" /etc/hosts; then
    return 0
  fi
  echo "${ip} ${host} ${HOSTS_MARKER}" | sudo tee -a /etc/hosts >/dev/null
}

configure_resolution_mode() {
  case "$RESOLUTION_MODE" in
    hosts-all)
      command -v sudo >/dev/null 2>&1 || fail "hosts-all mode requires sudo"
      add_hosts_entry "$STEPCA_HOST_IP" "$STEPCA_HOST_NAME"
      add_hosts_entry "$RESPONDER_HOST_IP" "$RESPONDER_HOST_NAME"
      STEPCA_SERVER_URL="https://${STEPCA_HOST_NAME}:9000/acme/acme/directory"
      STEPCA_EAB_URL="https://${STEPCA_HOST_NAME}:9000"
      RESPONDER_URL="http://${RESPONDER_HOST_NAME}:8080"
      ;;
    fqdn-only-hosts)
      STEPCA_SERVER_URL="https://localhost:9000/acme/acme/directory"
      STEPCA_EAB_URL="https://localhost:9000"
      RESPONDER_URL="http://${RESPONDER_HOST_IP}:8080"
      ;;
    *)
      fail "Unsupported RESOLUTION_MODE: $RESOLUTION_MODE"
      ;;
  esac
}

write_agent_config() {
  mkdir -p "$(dirname "$AGENT_CONFIG_PATH")" "$CERTS_DIR"
  cat >"$AGENT_CONFIG_PATH" <<EOF
email = "admin@example.com"
server = "${STEPCA_SERVER_URL}"
domain = "${DOMAIN}"

[acme]
directory_fetch_attempts = 10
directory_fetch_base_delay_secs = 1
directory_fetch_max_delay_secs = 10
poll_attempts = 15
poll_interval_secs = 2
http_responder_url = "${RESPONDER_URL}"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300
EOF
}

prepare_test_ca_materials() {
  mkdir -p "$SECRETS_DIR" "$CERTS_DIR"
  chmod 700 "$SECRETS_DIR" "$CERTS_DIR"
  if [ ! -f "$SECRETS_DIR/password.txt" ]; then
    printf '%s\n' "password" >"$SECRETS_DIR/password.txt"
    chmod 600 "$SECRETS_DIR/password.txt"
  fi

  if [ ! -f "$SECRETS_DIR/config/ca.json" ]; then
    docker run --user root --rm -v "$SECRETS_DIR:/home/step" smallstep/step-ca \
      step ca init \
      --name "Bootroot E2E CA" \
      --provisioner "acme" \
      --dns "localhost,bootroot-ca,stepca.internal" \
      --address ":9000" \
      --password-file /home/step/password.txt \
      --provisioner-password-file /home/step/password.txt \
      --acme >>"$RUN_LOG" 2>&1
  fi
}

run_bootstrap_chain() {
  log_phase "infra-up"
  local attempt
  for attempt in $(seq 1 "$INFRA_UP_ATTEMPTS"); do
    if run_bootroot infra up --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1; then
      break
    fi
    if [ "$attempt" -eq "$INFRA_UP_ATTEMPTS" ]; then
      fail "bootroot infra up failed after ${INFRA_UP_ATTEMPTS} attempts"
    fi
    sleep "$INFRA_UP_DELAY_SECS"
  done

  log_phase "init"
  BOOTROOT_LANG=en printf "y\ny\nn\n" | run_bootroot init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --auto-generate \
    --show-secrets \
    --stepca-url "$STEPCA_EAB_URL" \
    --stepca-provisioner "acme" \
    --stepca-password "password" \
    --http-hmac "dev-hmac" \
    --db-dsn "postgresql://step:step@127.0.0.1:5432/step" \
    --responder-url "$RESPONDER_URL" \
    --skip-responder-check >"$INIT_RAW_LOG" 2>&1

  OPENBAO_ROOT_TOKEN="$(awk -F': ' '/root token:/ {print $2; exit}' "$INIT_RAW_LOG")"
  [ -n "${OPENBAO_ROOT_TOKEN:-}" ] || fail "Failed to parse root token from init output"
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$INIT_LOG"

  log_phase "service-add"
  run_bootroot service add \
    --service-name "$EDGE_SERVICE" \
    --deploy-type daemon \
    --delivery-mode local-file \
    --hostname "$EDGE_HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$AGENT_CONFIG_PATH" \
    --cert-path "$CERTS_DIR/${EDGE_SERVICE}.crt" \
    --key-path "$CERTS_DIR/${EDGE_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" \
    --root-token "$OPENBAO_ROOT_TOKEN" >>"$RUN_LOG" 2>&1

  run_bootroot service add \
    --service-name "$WEB_SERVICE" \
    --deploy-type docker \
    --delivery-mode local-file \
    --hostname "$WEB_HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$AGENT_CONFIG_PATH" \
    --cert-path "$CERTS_DIR/${WEB_SERVICE}.crt" \
    --key-path "$CERTS_DIR/${WEB_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" \
    --container-name "$WEB_SERVICE" \
    --root-token "$OPENBAO_ROOT_TOKEN" >>"$RUN_LOG" 2>&1
}

wire_stepca_hosts() {
  local responder_ip
  responder_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bootroot-http01)"
  [ -n "${responder_ip:-}" ] || fail "Failed to resolve responder container IP"
  docker exec bootroot-ca sh -c \
    "printf '%s %s\n' '$responder_ip' '${INSTANCE_ID}.${EDGE_SERVICE}.${EDGE_HOSTNAME}.${DOMAIN}' >> /etc/hosts"
  docker exec bootroot-ca sh -c \
    "printf '%s %s\n' '$responder_ip' '${INSTANCE_ID}.${WEB_SERVICE}.${WEB_HOSTNAME}.${DOMAIN}' >> /etc/hosts"
}

snapshot_cert_meta() {
  local service="$1"
  local label="$2"
  local cert_path="$CERTS_DIR/${service}.crt"
  local meta_file="$CERT_META_DIR/${service}-${label}.txt"
  [ -f "$cert_path" ] || fail "Missing certificate: $cert_path"
  openssl x509 -in "$cert_path" -noout -serial -startdate -enddate -fingerprint -sha256 >"$meta_file"
}

fingerprint_of() {
  local service="$1"
  local label="$2"
  local meta_file="$CERT_META_DIR/${service}-${label}.txt"
  awk -F= '/^sha256 Fingerprint=/{print $2}' "$meta_file"
}

run_verify_pair() {
  local label="$1"
  log_phase "verify-${label}"
  run_bootroot verify --service-name "$EDGE_SERVICE" --agent-config "$AGENT_CONFIG_PATH" >>"$RUN_LOG" 2>&1
  run_bootroot verify --service-name "$WEB_SERVICE" --agent-config "$AGENT_CONFIG_PATH" >>"$RUN_LOG" 2>&1
  snapshot_cert_meta "$EDGE_SERVICE" "$label"
  snapshot_cert_meta "$WEB_SERVICE" "$label"
}

assert_fingerprint_changed() {
  local service="$1"
  local before_label="$2"
  local after_label="$3"
  local before_fp after_fp
  before_fp="$(fingerprint_of "$service" "$before_label")"
  after_fp="$(fingerprint_of "$service" "$after_label")"
  [ -n "$before_fp" ] || fail "Missing fingerprint for $service/$before_label"
  [ -n "$after_fp" ] || fail "Missing fingerprint for $service/$after_label"
  if [ "$before_fp" = "$after_fp" ]; then
    fail "Fingerprint did not change for $service ($before_label -> $after_label)"
  fi
}

run_rotations_with_verification() {
  log_phase "rotate-responder-hmac"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --root-token "$OPENBAO_ROOT_TOKEN" \
    --yes \
    responder-hmac >>"$RUN_LOG" 2>&1
  run_verify_pair "after-responder-hmac"
  assert_fingerprint_changed "$EDGE_SERVICE" "initial" "after-responder-hmac"
  assert_fingerprint_changed "$WEB_SERVICE" "initial" "after-responder-hmac"
}

write_manifest() {
  cat >"$ARTIFACT_DIR/manifest.json" <<EOF
{
  "mode": "${RESOLUTION_MODE}",
  "compose_file": "${COMPOSE_FILE}",
  "state_file": "${ROOT_DIR}/state.json",
  "agent_config_path": "${AGENT_CONFIG_PATH}",
  "services": ["${EDGE_SERVICE}", "${WEB_SERVICE}"]
}
EOF
}

main() {
  mkdir -p "$ARTIFACT_DIR" "$WORKSPACE_DIR" "$CERT_META_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  trap cleanup EXIT

  ensure_prerequisites
  configure_resolution_mode
  compose_down
  prepare_test_ca_materials
  write_agent_config
  run_bootstrap_chain
  wire_stepca_hosts

  [ -x "$BOOTROOT_AGENT_BIN" ] || cargo build --bin bootroot-agent >>"$RUN_LOG" 2>&1
  export PATH="$(dirname "$BOOTROOT_AGENT_BIN"):$PATH"

  run_verify_pair "initial"
  run_rotations_with_verification
  write_manifest
}

main "$@"
