#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-ca-key-recovery-$(date +%s)}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$ARTIFACT_DIR/workspace}"
SECRETS_DIR="${SECRETS_DIR:-$ROOT_DIR/secrets}"
AGENT_CONFIG_PATH="${AGENT_CONFIG_PATH:-$WORKSPACE_DIR/agent.toml}"
CERTS_DIR="${CERTS_DIR:-$WORKSPACE_DIR/certs}"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"
INFRA_UP_ATTEMPTS="${INFRA_UP_ATTEMPTS:-6}"
INFRA_UP_DELAY_SECS="${INFRA_UP_DELAY_SECS:-5}"
INFRA_READY_ATTEMPTS="${INFRA_READY_ATTEMPTS:-30}"
INFRA_READY_DELAY_SECS="${INFRA_READY_DELAY_SECS:-4}"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"
BOOTROOT_AGENT_BIN="${BOOTROOT_AGENT_BIN:-$ROOT_DIR/target/debug/bootroot-agent}"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-summary.json"
CERT_META_DIR="$ARTIFACT_DIR/cert-meta"
VERIFY_ATTEMPTS="${VERIFY_ATTEMPTS:-3}"
VERIFY_DELAY_SECS="${VERIFY_DELAY_SECS:-3}"
HTTP01_TARGET_ATTEMPTS="${HTTP01_TARGET_ATTEMPTS:-40}"
HTTP01_TARGET_DELAY_SECS="${HTTP01_TARGET_DELAY_SECS:-2}"
RESPONDER_READY_ATTEMPTS="${RESPONDER_READY_ATTEMPTS:-30}"
RESPONDER_READY_DELAY_SECS="${RESPONDER_READY_DELAY_SECS:-1}"
SIDECAR_OBA_READY_ATTEMPTS="${SIDECAR_OBA_READY_ATTEMPTS:-30}"
SIDECAR_OBA_READY_DELAY_SECS="${SIDECAR_OBA_READY_DELAY_SECS:-2}"

EDGE_SERVICE="edge-proxy"
EDGE_HOSTNAME="edge-node-01"
WEB_SERVICE="web-app"
WEB_HOSTNAME="web-01"
DOMAIN="trusted.domain"
INSTANCE_ID="001"
REMOTE_SERVICE="api-gw"
REMOTE_HOSTNAME="api-01"
REMOTE_INSTANCE_ID="002"
REMOTE_DIR="$ARTIFACT_DIR/remote-workspace"
REMOTE_AGENT_CONFIG="$REMOTE_DIR/agent.toml"
REMOTE_CERTS_DIR="$REMOTE_DIR/certs"

STEPCA_HOST_IP="127.0.0.1"
RESPONDER_HOST_IP="127.0.0.1"
STEPCA_SERVER_URL="https://localhost:9000/acme/acme/directory"
STEPCA_EAB_URL="https://localhost:9000"
RESPONDER_URL="http://${RESPONDER_HOST_IP}:8080"

RUNTIME_SERVICE_ADD_ROLE_ID=""
RUNTIME_SERVICE_ADD_SECRET_ID=""
RUNTIME_ROTATE_ROLE_ID=""
RUNTIME_ROTATE_SECRET_ID=""
SIDECAR_OBA_SERVICE="$WEB_SERVICE"
SIDECAR_OBA_CONTAINER="bootroot-openbao-agent-${SIDECAR_OBA_SERVICE}"
CURRENT_PHASE="init"
POSTGRES_ADMIN_PASSWORD="${POSTGRES_PASSWORD:?POSTGRES_PASSWORD must be set}"

# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

log_phase() {
  local phase="$1"
  CURRENT_PHASE="$phase"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"ts":"%s","phase":"%s"}\n' "$now" "$phase" >>"$PHASE_LOG"
}

fail() {
  local message="$1"
  printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$message" >>"$RUN_LOG" 2>/dev/null || true
  echo "$message" >&2
  exit 1
}

compose() {
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" "$@"
}

run_bootroot() {
  ( cd "$WORKSPACE_DIR" && "$BOOTROOT_BIN" "$@" )
}

on_error() {
  local line="$1"
  echo "run-ca-key-rotation-recovery failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "artifact dir: ${ARTIFACT_DIR}" >&2
  if [ -f "$RUN_LOG" ]; then
    echo "--- run.log (tail) ---" >&2
    tail -n 80 "$RUN_LOG" >&2 || true
  fi
  if [ -f "$INIT_RAW_LOG" ]; then
    echo "--- init.raw.log (tail) ---" >&2
    tail -n 120 "$INIT_RAW_LOG" >&2 || true
  fi
}

# ---------------------------------------------------------------------------
# Infrastructure helpers
# ---------------------------------------------------------------------------

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required"
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  [ -x "$BOOTROOT_REMOTE_BIN" ] || fail "bootroot-remote binary not executable: $BOOTROOT_REMOTE_BIN"
}

infra_services() {
  printf '%s\n' "openbao" "postgres" "step-ca" "bootroot-http01"
}

service_container_id() {
  compose ps -q "$1" | tr -d '\n'
}

is_service_ready() {
  local service="$1"
  local cid
  cid="$(service_container_id "$service")"
  [ -n "$cid" ] || return 1
  local state
  state="$(docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$cid" 2>/dev/null || true)"
  [ -n "$state" ] || return 1
  local status="${state%%|*}" health="${state#*|}"
  [ "$status" = "running" ] || return 1
  if [ -n "$health" ] && [ "$health" != "healthy" ]; then return 1; fi
  return 0
}

wait_for_infra_ready() {
  local attempt
  for attempt in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    local all_ready=1 service
    while IFS= read -r service; do
      if ! is_service_ready "$service"; then all_ready=0; break; fi
    done < <(infra_services)
    if [ "$all_ready" -eq 1 ]; then return 0; fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  return 1
}

compose_down() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}

capture_artifacts() {
  compose ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
  compose logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs bootroot-openbao-agent-stepca >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs bootroot-openbao-agent-responder >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs "$SIDECAR_OBA_CONTAINER" >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
}

start_service_sidecar_oba() {
  local service="$1"
  local container="bootroot-openbao-agent-${service}"
  local agent_hcl="$SECRETS_DIR/openbao/services/${service}/agent.hcl"
  # Remove the pre-seeded config so readiness waits for sidecar-rendered content.
  rm -f "$AGENT_CONFIG_PATH"
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker run -d \
    --name "$container" \
    --user "$(id -u):$(id -g)" \
    --network "container:bootroot-openbao" \
    -v "$ROOT_DIR:$ROOT_DIR" \
    -v "$ARTIFACT_DIR:$ARTIFACT_DIR" \
    openbao/openbao:latest \
    agent -config="$agent_hcl" >>"$RUN_LOG" 2>&1
  local attempt
  for attempt in $(seq 1 "$SIDECAR_OBA_READY_ATTEMPTS"); do
    if [ -f "$AGENT_CONFIG_PATH" ] &&
      grep -Eq '^[[:space:]]*http_responder_hmac[[:space:]]*=[[:space:]]*"[^"]+"' \
        "$AGENT_CONFIG_PATH" 2>/dev/null; then
      return 0
    fi
    sleep "$SIDECAR_OBA_READY_DELAY_SECS"
  done
  docker logs "$container" >>"$RUN_LOG" 2>&1 || true
  fail "sidecar OBA ($container) did not render agent config within timeout"
}

stop_service_sidecar_oba() {
  docker rm -f "$SIDECAR_OBA_CONTAINER" >/dev/null 2>&1 || true
}

cleanup() {
  log_phase "cleanup"
  capture_artifacts
  stop_service_sidecar_oba
  compose_down
}

wait_for_openbao_api() {
  local attempt
  for attempt in $(seq 1 30); do
    local code
    code="$(curl -sS -o /dev/null -w '%{http_code}' "http://${STEPCA_HOST_IP}:8200/v1/sys/health" || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then return 0; fi
    sleep 1
  done
  docker logs bootroot-openbao >>"$RUN_LOG" 2>&1 || true
  fail "openbao API did not become reachable"
}

wait_for_postgres_admin() {
  local host_port="${POSTGRES_HOST_PORT:-5432}"
  local admin_user="${POSTGRES_USER:-step}"
  local attempt
  for attempt in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    if docker exec bootroot-postgres pg_isready -U "$admin_user" -d postgres >/dev/null 2>&1 &&
      bash -lc ": >/dev/tcp/127.0.0.1/${host_port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  docker logs bootroot-postgres >>"$RUN_LOG" 2>&1 || true
  fail "postgres admin endpoint did not become reachable before init"
}

unseal_openbao() {
  local threshold=2
  local i
  for i in $(seq 0 $((threshold - 1))); do
    local key
    key="$(jq -r ".unseal_keys[$i]" "$INIT_SUMMARY_JSON")"
    [ -n "$key" ] && [ "$key" != "null" ] || fail "Missing unseal key $i in $INIT_SUMMARY_JSON"
    curl -sS -X PUT "http://${STEPCA_HOST_IP}:8200/v1/sys/unseal" \
      -d "{\"key\":\"${key}\"}" >/dev/null 2>&1
  done
  local attempt
  for attempt in $(seq 1 15); do
    local sealed
    sealed="$(curl -sS "http://${STEPCA_HOST_IP}:8200/v1/sys/seal-status" 2>/dev/null | jq -r '.sealed' 2>/dev/null || echo "true")"
    if [ "$sealed" = "false" ]; then return 0; fi
    sleep 1
  done
  fail "OpenBao did not unseal within timeout"
}

wait_for_responder_admin() {
  local admin_url="${RESPONDER_URL%/}/admin/http01"
  local attempt
  for attempt in $(seq 1 "$RESPONDER_READY_ATTEMPTS"); do
    local code
    code="$(curl -sS -m 2 -o /dev/null -w '%{http_code}' "$admin_url" || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then return 0; fi
    sleep "$RESPONDER_READY_DELAY_SECS"
  done
  fail "responder admin endpoint did not become reachable: $admin_url"
}

wait_for_stepca_health() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl -kfsS https://127.0.0.1:9000/health >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  fail "step-ca health endpoint did not become ready"
}

wire_stepca_hosts() {
  local responder_ip
  responder_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bootroot-http01)"
  [ -n "${responder_ip:-}" ] || fail "Failed to resolve responder container IP"
  docker exec bootroot-ca sh -c \
    "printf '%s %s\n' '$responder_ip' '${INSTANCE_ID}.${EDGE_SERVICE}.${EDGE_HOSTNAME}.${DOMAIN}' >> /etc/hosts"
  docker exec bootroot-ca sh -c \
    "printf '%s %s\n' '$responder_ip' '${INSTANCE_ID}.${WEB_SERVICE}.${WEB_HOSTNAME}.${DOMAIN}' >> /etc/hosts"
  docker exec bootroot-ca sh -c \
    "printf '%s %s\n' '$responder_ip' '${REMOTE_INSTANCE_ID}.${REMOTE_SERVICE}.${REMOTE_HOSTNAME}.${DOMAIN}' >> /etc/hosts"
}

wait_for_stepca_http01_targets() {
  local hosts=(
    "${INSTANCE_ID}.${EDGE_SERVICE}.${EDGE_HOSTNAME}.${DOMAIN}"
    "${INSTANCE_ID}.${WEB_SERVICE}.${WEB_HOSTNAME}.${DOMAIN}"
    "${REMOTE_INSTANCE_ID}.${REMOTE_SERVICE}.${REMOTE_HOSTNAME}.${DOMAIN}"
  )
  local host
  for host in "${hosts[@]}"; do
    local attempt
    for attempt in $(seq 1 "$HTTP01_TARGET_ATTEMPTS"); do
      if docker exec bootroot-ca bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${host}/80'" >/dev/null 2>&1; then
        break
      fi
      if [ "$attempt" -eq "$HTTP01_TARGET_ATTEMPTS" ]; then
        fail "step-ca cannot reach HTTP-01 target: ${host}:80"
      fi
      sleep "$HTTP01_TARGET_DELAY_SECS"
    done
  done
}

# ---------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------

snapshot_cert_meta() {
  local service="$1" label="$2" certs_dir="${3:-$CERTS_DIR}"
  local cert_path="$certs_dir/${service}.crt"
  local meta_file="$CERT_META_DIR/${service}-${label}.txt"
  [ -f "$cert_path" ] || fail "Missing certificate: $cert_path"
  openssl x509 -in "$cert_path" -noout -serial -startdate -enddate -fingerprint -sha256 >"$meta_file"
}

fingerprint_of() {
  local service="$1" label="$2"
  awk -F= '/^sha256 Fingerprint=/{print $2}' "$CERT_META_DIR/${service}-${label}.txt"
}

assert_fingerprint_changed() {
  local service="$1" before_label="$2" after_label="$3"
  local before_fp after_fp
  before_fp="$(fingerprint_of "$service" "$before_label")"
  after_fp="$(fingerprint_of "$service" "$after_label")"
  [ -n "$before_fp" ] || fail "Missing fingerprint for $service/$before_label"
  [ -n "$after_fp" ] || fail "Missing fingerprint for $service/$after_label"
  if [ "$before_fp" = "$after_fp" ]; then
    fail "Fingerprint did not change for $service ($before_label -> $after_label)"
  fi
}

verify_service_with_retry() {
  local service="$1" agent_config="${2:-$AGENT_CONFIG_PATH}"
  local attempt
  for attempt in $(seq 1 "$VERIFY_ATTEMPTS"); do
    if run_bootroot verify --service-name "$service" --agent-config "$agent_config" >>"$RUN_LOG" 2>&1; then
      return 0
    fi
    if [ "$attempt" -eq "$VERIFY_ATTEMPTS" ]; then
      fail "verify failed for ${service} after ${VERIFY_ATTEMPTS} attempts"
    fi
    sleep "$VERIFY_DELAY_SECS"
  done
}

force_reissue_for_service() {
  rm -f "$CERTS_DIR/${1}.crt" "$CERTS_DIR/${1}.key"
}

force_reissue_remote() {
  rm -f "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.crt" "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.key"
}

force_reissue_all_services() {
  force_reissue_for_service "$EDGE_SERVICE"
  force_reissue_for_service "$WEB_SERVICE"
  force_reissue_remote
}

run_verify_pair() {
  local label="$1"
  log_phase "verify-${label}"
  verify_service_with_retry "$EDGE_SERVICE"
  verify_service_with_retry "$WEB_SERVICE"
  verify_service_with_retry "$REMOTE_SERVICE" "$REMOTE_AGENT_CONFIG"
  snapshot_cert_meta "$EDGE_SERVICE" "$label"
  snapshot_cert_meta "$WEB_SERVICE" "$label"
  snapshot_cert_meta "$REMOTE_SERVICE" "$label" "$REMOTE_CERTS_DIR"
}

# ---------------------------------------------------------------------------
# Remote bootstrap
# ---------------------------------------------------------------------------

copy_remote_materials() {
  local control_dir="$SECRETS_DIR/services/$REMOTE_SERVICE"
  local remote_dir="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE"
  mkdir -p "$remote_dir"
  cp "$control_dir/role_id" "$remote_dir/role_id"
  cp "$control_dir/secret_id" "$remote_dir/secret_id"
  chmod 600 "$remote_dir/role_id" "$remote_dir/secret_id"
}

run_remote_bootstrap() {
  local role_id_path="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE/role_id"
  local secret_id_path="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE/secret_id"
  local eab_path="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE/eab.json"
  local ca_bundle_path="$REMOTE_CERTS_DIR/ca-bundle.pem"
  ( cd "$REMOTE_DIR" && "$BOOTROOT_REMOTE_BIN" bootstrap \
      --openbao-url "http://${STEPCA_HOST_IP}:8200" \
      --kv-mount "secret" \
      --service-name "$REMOTE_SERVICE" \
      --role-id-path "$role_id_path" \
      --secret-id-path "$secret_id_path" \
      --eab-file-path "$eab_path" \
      --agent-config-path "$REMOTE_AGENT_CONFIG" \
      --agent-email "admin@example.com" \
      --agent-server "$STEPCA_SERVER_URL" \
      --agent-domain "$DOMAIN" \
      --agent-responder-url "$RESPONDER_URL" \
      --profile-hostname "$REMOTE_HOSTNAME" \
      --profile-instance-id "$REMOTE_INSTANCE_ID" \
      --profile-cert-path "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.crt" \
      --profile-key-path "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.key" \
      --ca-bundle-path "$ca_bundle_path" \
      --output json >>"$RUN_LOG" 2>&1 )
}

# ---------------------------------------------------------------------------
# Rotation helpers
# ---------------------------------------------------------------------------

run_rotate_ca_key() {
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    ca-key "$@"
}

# ---------------------------------------------------------------------------
# Bootstrap: infra-up, init, service-add, initial verify
# ---------------------------------------------------------------------------

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

install_infra() {
  mkdir -p "$CERTS_DIR"
  chmod 700 "$CERTS_DIR"
  run_bootroot infra install --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1
}

reset_stepca_materials_for_e2e() {
  if [ "${RESET_STEPCA_MATERIALS:-1}" != "1" ]; then return 0; fi
  rm -rf "$SECRETS_DIR/config" "$SECRETS_DIR/certs" "$SECRETS_DIR/db" \
    "$SECRETS_DIR/secrets" "$SECRETS_DIR/password.txt" "$SECRETS_DIR/password.txt.new"
}

run_bootstrap_chain() {
  log_phase "infra-up"
  if ! run_bootroot infra up --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1; then
    if ! wait_for_infra_ready; then
      local attempt
      for attempt in $(seq 1 "$INFRA_UP_ATTEMPTS"); do
        if run_bootroot infra up --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1; then break; fi
        if [ "$attempt" -eq "$INFRA_UP_ATTEMPTS" ]; then
          fail "bootroot infra up failed after ${INFRA_UP_ATTEMPTS} attempts"
        fi
        sleep "$INFRA_UP_DELAY_SECS"
      done
    fi
  fi

  wait_for_postgres_admin
  wait_for_openbao_api
  wait_for_responder_admin

  log_phase "init"
  rm -f "$WORKSPACE_DIR/state.json"
  if ! BOOTROOT_LANG=en printf "y\ny\ny\n" | run_bootroot init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$INIT_SUMMARY_JSON" \
    --enable auto-generate,show-secrets,db-provision \
    --stepca-url "$STEPCA_EAB_URL" \
    --stepca-provisioner "admin" \
    --stepca-password "password" \
    --http-hmac "dev-hmac" \
    --eab-kid "dev-kid" \
    --eab-hmac "dev-hmac" \
    --db-admin-dsn "postgresql://step:${POSTGRES_ADMIN_PASSWORD}@127.0.0.1:${POSTGRES_HOST_PORT:-5432}/postgres?sslmode=disable" \
    --db-user "step" \
    --db-password "step-pass" \
    --db-name "stepca" \
    --responder-url "$RESPONDER_URL" >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 160 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
    fail "bootroot init failed"
  fi

  RUNTIME_SERVICE_ADD_ROLE_ID="$(jq -r '.approles[] | select(.label == "runtime_service_add") | .role_id // empty' "$INIT_SUMMARY_JSON")"
  RUNTIME_SERVICE_ADD_SECRET_ID="$(jq -r '.approles[] | select(.label == "runtime_service_add") | .secret_id // empty' "$INIT_SUMMARY_JSON")"
  RUNTIME_ROTATE_ROLE_ID="$(jq -r '.approles[] | select(.label == "runtime_rotate") | .role_id // empty' "$INIT_SUMMARY_JSON")"
  RUNTIME_ROTATE_SECRET_ID="$(jq -r '.approles[] | select(.label == "runtime_rotate") | .secret_id // empty' "$INIT_SUMMARY_JSON")"
  [ -n "${RUNTIME_SERVICE_ADD_ROLE_ID:-}" ] || fail "Failed to parse runtime_service_add role_id"
  [ -n "${RUNTIME_SERVICE_ADD_SECRET_ID:-}" ] || fail "Failed to parse runtime_service_add secret_id"
  [ -n "${RUNTIME_ROTATE_ROLE_ID:-}" ] || fail "Failed to parse runtime_rotate role_id"
  [ -n "${RUNTIME_ROTATE_SECRET_ID:-}" ] || fail "Failed to parse runtime_rotate secret_id"
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$INIT_LOG"

  log_phase "service-add"
  run_bootroot service add \
    --service-name "$EDGE_SERVICE" --deploy-type daemon --delivery-mode local-file \
    --hostname "$EDGE_HOSTNAME" --domain "$DOMAIN" \
    --agent-config "$AGENT_CONFIG_PATH" \
    --cert-path "$CERTS_DIR/${EDGE_SERVICE}.crt" --key-path "$CERTS_DIR/${EDGE_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

  run_bootroot service add \
    --service-name "$WEB_SERVICE" --deploy-type docker --delivery-mode local-file \
    --hostname "$WEB_HOSTNAME" --domain "$DOMAIN" \
    --agent-config "$AGENT_CONFIG_PATH" \
    --cert-path "$CERTS_DIR/${WEB_SERVICE}.crt" --key-path "$CERTS_DIR/${WEB_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" --container-name "$WEB_SERVICE" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

  run_bootroot service add \
    --service-name "$REMOTE_SERVICE" --deploy-type daemon --delivery-mode remote-bootstrap \
    --hostname "$REMOTE_HOSTNAME" --domain "$DOMAIN" \
    --agent-config "$REMOTE_AGENT_CONFIG" \
    --cert-path "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.crt" --key-path "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.key" \
    --instance-id "$REMOTE_INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1
}

# ---------------------------------------------------------------------------
# Scenario 1: Phase 3 failure — OpenBao unreachable
# ---------------------------------------------------------------------------

scenario_1_phase3_failure() {
  log_phase "scenario-1-phase3"
  snapshot_cert_meta "$EDGE_SERVICE" "s1-before"
  snapshot_cert_meta "$WEB_SERVICE" "s1-before"
  snapshot_cert_meta "$REMOTE_SERVICE" "s1-before" "$REMOTE_CERTS_DIR"

  # Run rotation in background so we can stop OpenBao mid-execution.
  # Phase 0 (auth) completes while OpenBao is still up; Phase 1-2 are
  # local-only ops; Phase 3 writes trust to OpenBao and will fail.
  run_rotate_ca_key --skip reissue --force --cleanup >>"$RUN_LOG" 2>&1 &
  local rot_pid=$!

  # Wait for Phase 1 to complete (state file appears)
  local attempt
  for attempt in $(seq 1 120); do
    if [ -f "$WORKSPACE_DIR/rotation-state.json" ]; then
      local phase
      phase="$(jq -r '.phase' "$WORKSPACE_DIR/rotation-state.json" 2>/dev/null || echo "-1")"
      if [ "$phase" -ge 1 ]; then break; fi
    fi
    sleep 0.5
  done
  [ -f "$WORKSPACE_DIR/rotation-state.json" ] || {
    wait "$rot_pid" 2>/dev/null || true
    fail "S1: rotation-state.json never appeared (Phase 1 did not complete)"
  }

  # Stop OpenBao so Phase 3 (trust write) will fail
  compose stop openbao >>"$RUN_LOG" 2>&1

  # Wait for the rotation process to exit (it should fail)
  if wait "$rot_pid"; then
    fail "S1: Expected rotation to fail with OpenBao down"
  fi

  [ -f "$CERTS_DIR/${EDGE_SERVICE}.crt" ] || fail "S1: edge-proxy cert should still exist"
  [ -f "$CERTS_DIR/${WEB_SERVICE}.crt" ] || fail "S1: web-app cert should still exist"
  [ -f "$WORKSPACE_DIR/rotation-state.json" ] || fail "S1: rotation-state.json missing after failure"

  local saved_phase
  saved_phase="$(jq -r '.phase' "$WORKSPACE_DIR/rotation-state.json")"
  [ "$saved_phase" -ge 1 ] && [ "$saved_phase" -lt 7 ] \
    || fail "S1: unexpected saved phase: $saved_phase (expected 1..6)"

  # Restart OpenBao, unseal, then resume rotation.
  # Also restart the OBA sidecar which died when OpenBao went down.
  compose start openbao >>"$RUN_LOG" 2>&1
  wait_for_openbao_api
  unseal_openbao
  stop_service_sidecar_oba
  start_service_sidecar_oba "$SIDECAR_OBA_SERVICE"

  run_rotate_ca_key --skip reissue --force --cleanup >>"$RUN_LOG" 2>&1

  wire_stepca_hosts
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "s1-after"
  assert_fingerprint_changed "$EDGE_SERVICE" "s1-before" "s1-after"
  assert_fingerprint_changed "$WEB_SERVICE" "s1-before" "s1-after"
  assert_fingerprint_changed "$REMOTE_SERVICE" "s1-before" "s1-after"
}

# ---------------------------------------------------------------------------
# Scenario 2: Process crash mid-rotation (SIGKILL)
# ---------------------------------------------------------------------------

scenario_2_phase4_failure() {
  log_phase "scenario-2-phase4"
  snapshot_cert_meta "$EDGE_SERVICE" "s2-before"
  snapshot_cert_meta "$WEB_SERVICE" "s2-before"
  snapshot_cert_meta "$REMOTE_SERVICE" "s2-before" "$REMOTE_CERTS_DIR"

  # Run rotation in background and kill it after Phase 2+ completes.
  # This simulates a process crash mid-rotation.
  run_rotate_ca_key --skip reissue --force --cleanup >>"$RUN_LOG" 2>&1 &
  local rot_pid=$!

  local attempt
  for attempt in $(seq 1 120); do
    if [ -f "$WORKSPACE_DIR/rotation-state.json" ]; then
      local phase
      phase="$(jq -r '.phase' "$WORKSPACE_DIR/rotation-state.json" 2>/dev/null || echo "-1")"
      if [ "$phase" -ge 2 ]; then
        # Kill child bootroot process first, then the bash subshell.
        # kill -9 on the subshell alone orphans the bootroot binary.
        pkill -9 -P "$rot_pid" 2>/dev/null || true
        kill -9 "$rot_pid" 2>/dev/null || true
        sleep 0.5
        break
      fi
    fi
    sleep 0.2
  done
  wait "$rot_pid" 2>/dev/null || true

  [ -f "$CERTS_DIR/${EDGE_SERVICE}.crt" ] || fail "S2: edge-proxy cert should still exist"
  [ -f "$WORKSPACE_DIR/rotation-state.json" ] || fail "S2: rotation-state.json missing after crash"

  local saved_phase
  saved_phase="$(jq -r '.phase' "$WORKSPACE_DIR/rotation-state.json")"
  [ "$saved_phase" -ge 2 ] && [ "$saved_phase" -lt 7 ] \
    || fail "S2: unexpected saved phase: $saved_phase (expected 2..6)"

  # Resume rotation from the crashed state
  run_rotate_ca_key --skip reissue --force --cleanup >>"$RUN_LOG" 2>&1

  wire_stepca_hosts
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "s2-after"
  assert_fingerprint_changed "$EDGE_SERVICE" "s2-before" "s2-after"
  assert_fingerprint_changed "$WEB_SERVICE" "s2-before" "s2-after"
  assert_fingerprint_changed "$REMOTE_SERVICE" "s2-before" "s2-after"
}

# ---------------------------------------------------------------------------
# Scenario 3: Phase 5 partial re-issuance
# ---------------------------------------------------------------------------

scenario_3_partial_reissuance() {
  log_phase "scenario-3-partial"
  snapshot_cert_meta "$EDGE_SERVICE" "s3-before"
  snapshot_cert_meta "$WEB_SERVICE" "s3-before"
  snapshot_cert_meta "$REMOTE_SERVICE" "s3-before" "$REMOTE_CERTS_DIR"

  # Delete one service cert to simulate a partially-migrated state.
  # Phase 6 will detect the missing cert as unmigrated and bail.
  rm -f "$CERTS_DIR/${EDGE_SERVICE}.crt" "$CERTS_DIR/${EDGE_SERVICE}.key"

  if run_rotate_ca_key --skip reissue >>"$RUN_LOG" 2>&1; then
    fail "S3: Expected Phase 6 to bail on unmigrated services"
  fi

  [ -f "$WORKSPACE_DIR/rotation-state.json" ] || fail "S3: rotation-state.json should exist"

  # Manually reissue only edge-proxy (1 of 2 LocalFile services)
  wire_stepca_hosts
  force_reissue_for_service "$EDGE_SERVICE"
  verify_service_with_retry "$EDGE_SERVICE"

  snapshot_cert_meta "$EDGE_SERVICE" "s3-partial"
  [ -f "$CERTS_DIR/${WEB_SERVICE}.crt" ] || fail "S3: web-app old cert should still exist"

  # Reissue remaining services
  force_reissue_for_service "$WEB_SERVICE"
  verify_service_with_retry "$WEB_SERVICE"
  run_remote_bootstrap
  force_reissue_remote
  verify_service_with_retry "$REMOTE_SERVICE" "$REMOTE_AGENT_CONFIG"

  # Resume rotation — Phase 6 succeeds now (all certs present)
  run_rotate_ca_key --cleanup >>"$RUN_LOG" 2>&1

  run_verify_pair "s3-after"
  assert_fingerprint_changed "$EDGE_SERVICE" "s3-before" "s3-after"
  assert_fingerprint_changed "$WEB_SERVICE" "s3-before" "s3-after"
  assert_fingerprint_changed "$REMOTE_SERVICE" "s3-before" "s3-after"
}

# ---------------------------------------------------------------------------
# Scenario 4: Phase 6 entry condition — blocked + --force override
# ---------------------------------------------------------------------------

scenario_4_finalize_blocked() {
  log_phase "scenario-4-blocked"
  snapshot_cert_meta "$EDGE_SERVICE" "s4-before"
  snapshot_cert_meta "$WEB_SERVICE" "s4-before"
  snapshot_cert_meta "$REMOTE_SERVICE" "s4-before" "$REMOTE_CERTS_DIR"

  # Delete a service cert so Phase 6 detects unmigrated services.
  rm -f "$CERTS_DIR/${EDGE_SERVICE}.crt" "$CERTS_DIR/${EDGE_SERVICE}.key"

  if run_rotate_ca_key --skip reissue 2>"$ARTIFACT_DIR/s4-blocked-stderr.log" >>"$RUN_LOG"; then
    fail "S4: Expected Phase 6 to block on unmigrated services"
  fi

  grep -q "$EDGE_SERVICE" "$ARTIFACT_DIR/s4-blocked-stderr.log" \
    || fail "S4: blocked error should mention $EDGE_SERVICE"

  # Re-run with --force → Phase 6 forces despite unmigrated services
  run_rotate_ca_key --skip reissue --force --cleanup >>"$RUN_LOG" 2>&1

  wire_stepca_hosts
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "s4-after"
  assert_fingerprint_changed "$EDGE_SERVICE" "s4-before" "s4-after"
  assert_fingerprint_changed "$WEB_SERVICE" "s4-before" "s4-after"
  assert_fingerprint_changed "$REMOTE_SERVICE" "s4-before" "s4-after"
}

# ---------------------------------------------------------------------------
# Scenario 5: trust-sync conflict during active rotation
# ---------------------------------------------------------------------------

scenario_5_trustsync_conflict() {
  log_phase "scenario-5-trustsync"

  # Create active rotation by deleting a cert and running with --skip reissue
  # (Phase 6 bails on the missing cert, leaving rotation-state.json behind).
  rm -f "$CERTS_DIR/${EDGE_SERVICE}.crt" "$CERTS_DIR/${EDGE_SERVICE}.key"

  if run_rotate_ca_key --skip reissue >>"$RUN_LOG" 2>&1; then
    fail "S5: Expected Phase 6 to bail on unmigrated services"
  fi

  [ -f "$WORKSPACE_DIR/rotation-state.json" ] || fail "S5: rotation-state.json should exist (active rotation)"

  # trust-sync should abort because rotation is in progress
  if run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    trust-sync >>"$RUN_LOG" 2>"$ARTIFACT_DIR/s5-trustsync-stderr.log"; then
    fail "S5: Expected trust-sync to abort during active rotation"
  fi

  grep -qi "rotation" "$ARTIFACT_DIR/s5-trustsync-stderr.log" \
    || fail "S5: trust-sync error should mention active rotation"

  # Complete the rotation with --force --cleanup (skip-reissue because
  # there is no running daemon for the Daemon-type service).
  wire_stepca_hosts
  run_rotate_ca_key --skip reissue --force --cleanup >>"$RUN_LOG" 2>&1

  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "s5-after"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  mkdir -p "$ARTIFACT_DIR" "$WORKSPACE_DIR" "$CERT_META_DIR" "$REMOTE_DIR" "$REMOTE_CERTS_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  ensure_prerequisites
  compose_down
  reset_stepca_materials_for_e2e
  install_infra
  write_agent_config
  run_bootstrap_chain
  wire_stepca_hosts
  wait_for_stepca_http01_targets
  wait_for_stepca_health

  [ -x "$BOOTROOT_AGENT_BIN" ] || cargo build --bin bootroot-agent >>"$RUN_LOG" 2>&1
  export PATH="$(dirname "$BOOTROOT_AGENT_BIN"):$PATH"

  # Remove the manual agent.toml so the sidecar readiness check actually
  # waits for the OBA template render (not the stale write_agent_config
  # output which already contains http_responder_hmac).
  rm -f "$AGENT_CONFIG_PATH"
  start_service_sidecar_oba "$SIDECAR_OBA_SERVICE"

  copy_remote_materials
  log_phase "remote-bootstrap-initial"
  run_remote_bootstrap

  run_verify_pair "initial"

  scenario_1_phase3_failure
  scenario_2_phase4_failure
  scenario_3_partial_reissuance
  scenario_4_finalize_blocked
  scenario_5_trustsync_conflict
}

main "$@"
