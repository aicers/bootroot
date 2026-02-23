#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-main-lifecycle-$(date +%s)}"
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
RESOLUTION_MODE="${RESOLUTION_MODE:-fqdn-only-hosts}"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-summary.json"
CERT_META_DIR="$ARTIFACT_DIR/cert-meta"
HOSTS_MARKER="# bootroot-e2e-main-lifecycle"
VERIFY_ATTEMPTS="${VERIFY_ATTEMPTS:-3}"
VERIFY_DELAY_SECS="${VERIFY_DELAY_SECS:-3}"
HTTP01_TARGET_ATTEMPTS="${HTTP01_TARGET_ATTEMPTS:-40}"
HTTP01_TARGET_DELAY_SECS="${HTTP01_TARGET_DELAY_SECS:-2}"
RESPONDER_READY_ATTEMPTS="${RESPONDER_READY_ATTEMPTS:-30}"
RESPONDER_READY_DELAY_SECS="${RESPONDER_READY_DELAY_SECS:-1}"

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
STEPCA_HOST_NAME="stepca.internal"
RESPONDER_HOST_NAME="responder.internal"

STEPCA_SERVER_URL=""
STEPCA_EAB_URL=""
RESPONDER_URL=""
RUNTIME_SERVICE_ADD_ROLE_ID=""
RUNTIME_SERVICE_ADD_SECRET_ID=""
RUNTIME_ROTATE_ROLE_ID=""
RUNTIME_ROTATE_SECRET_ID=""
SIDECAR_OBA_SERVICE="$WEB_SERVICE"
SIDECAR_OBA_CONTAINER="bootroot-openbao-agent-${SIDECAR_OBA_SERVICE}"
SIDECAR_OBA_READY_ATTEMPTS="${SIDECAR_OBA_READY_ATTEMPTS:-30}"
SIDECAR_OBA_READY_DELAY_SECS="${SIDECAR_OBA_READY_DELAY_SECS:-2}"
CURRENT_PHASE="init"

log_phase() {
  local phase="$1"
  CURRENT_PHASE="$phase"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"ts":"%s","phase":"%s","mode":"%s"}\n' \
    "$now" "$phase" "$RESOLUTION_MODE" >>"$PHASE_LOG"
}

fail() {
  local message="$1"
  if [ -n "${RUN_LOG:-}" ]; then
    printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$message" >>"$RUN_LOG" || true
  fi
  echo "$message" >&2
  exit 1
}

run_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi
  sudo -n "$@"
}

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required"
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  [ -x "$BOOTROOT_REMOTE_BIN" ] || fail "bootroot-remote binary not executable: $BOOTROOT_REMOTE_BIN"
}

ensure_compose_images() {
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" build step-ca bootroot-http01 >>"$RUN_LOG" 2>&1
}

run_bootroot() {
  (
    cd "$WORKSPACE_DIR"
    "$BOOTROOT_BIN" "$@"
  )
}

infra_services() {
  printf '%s\n' "openbao" "postgres" "step-ca" "bootroot-http01"
}

service_container_id() {
  local service="$1"
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" ps -q "$service" | tr -d '\n'
}

is_service_ready() {
  local service="$1"
  local container_id
  container_id="$(service_container_id "$service")"
  if [ -z "$container_id" ]; then
    return 1
  fi

  local state
  state="$(docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
  if [ -z "$state" ]; then
    return 1
  fi

  local status health
  status="${state%%|*}"
  health="${state#*|}"
  if [ "$status" != "running" ]; then
    return 1
  fi
  if [ -n "$health" ] && [ "$health" != "healthy" ]; then
    return 1
  fi
  return 0
}

wait_for_infra_ready() {
  local attempt
  for attempt in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    local all_ready=1
    local service
    while IFS= read -r service; do
      if ! is_service_ready "$service"; then
        all_ready=0
        break
      fi
    done < <(infra_services)

    if [ "$all_ready" -eq 1 ]; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  return 1
}

compose_down() {
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}

capture_artifacts() {
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs bootroot-openbao-agent-stepca >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs bootroot-openbao-agent-responder >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs "$SIDECAR_OBA_CONTAINER" >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
}

start_service_sidecar_oba() {
  local service="$1"
  local container="bootroot-openbao-agent-${service}"
  local agent_hcl="$SECRETS_DIR/openbao/services/${service}/agent.hcl"

  docker rm -f "$container" >/dev/null 2>&1 || true

  # Run sidecar OBA sharing the OpenBao container network so that
  # localhost:8200 in agent.hcl resolves to the OpenBao server.
  # --user ensures the container can read secrets/ (0700, owned by runner).
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
    if [ -f "$AGENT_CONFIG_PATH" ] && grep -q 'http_responder_hmac' "$AGENT_CONFIG_PATH" 2>/dev/null; then
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

cleanup_hosts() {
  if [ "$RESOLUTION_MODE" != "hosts-all" ]; then
    return 0
  fi
  if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
    return 0
  fi
  local tmp_file
  tmp_file="$(mktemp)"
  run_sudo awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' /etc/hosts >"$tmp_file"
  run_sudo cp "$tmp_file" /etc/hosts
  rm -f "$tmp_file"
}

cleanup() {
  log_phase "cleanup"
  cleanup_hosts
  capture_artifacts
  stop_service_sidecar_oba
  compose_down
}

on_error() {
  local line="$1"
  echo "run-main-lifecycle failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "artifact dir: ${ARTIFACT_DIR}" >&2
  if [ -f "$RUN_LOG" ]; then
    echo "--- run.log (tail) ---" >&2
    tail -n 80 "$RUN_LOG" >&2 || true
  fi
  if [ -f "$INIT_RAW_LOG" ]; then
    echo "--- init.raw.log (tail) ---" >&2
    tail -n 120 "$INIT_RAW_LOG" >&2 || true
  fi
  if [ -f "$INIT_LOG" ]; then
    echo "--- init.log (tail) ---" >&2
    tail -n 80 "$INIT_LOG" >&2 || true
  fi
}

add_hosts_entry() {
  local ip="$1"
  local host="$2"
  if grep -qE "[[:space:]]${host}([[:space:]]|\$)" /etc/hosts; then
    return 0
  fi
  echo "${ip} ${host} ${HOSTS_MARKER}" | run_sudo tee -a /etc/hosts >/dev/null
}

configure_resolution_mode() {
  case "$RESOLUTION_MODE" in
    hosts-all)
      if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 || fail "hosts-all mode requires sudo"
        run_sudo true || fail "hosts-all mode requires non-interactive sudo (sudo -n)"
      fi
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
  local uid gid
  uid="$(id -u)"
  gid="$(id -g)"
  if [ ! -f "$SECRETS_DIR/password.txt" ]; then
    printf '%s\n' "password" >"$SECRETS_DIR/password.txt"
    chmod 600 "$SECRETS_DIR/password.txt"
  fi

  if [ ! -f "$SECRETS_DIR/config/ca.json" ]; then
    docker run --user "${uid}:${gid}" --rm -v "$SECRETS_DIR:/home/step" smallstep/step-ca \
      step ca init \
      --name "Bootroot E2E CA" \
      --provisioner "admin" \
      --dns "localhost,bootroot-ca,stepca.internal" \
      --address ":9000" \
      --password-file /home/step/password.txt \
      --provisioner-password-file /home/step/password.txt \
      --acme >>"$RUN_LOG" 2>&1
  fi

  [ -r "$SECRETS_DIR/config/ca.json" ] || fail "secrets/config/ca.json is not readable"
}

reset_stepca_materials_for_e2e() {
  if [ "${RESET_STEPCA_MATERIALS:-1}" != "1" ]; then
    return 0
  fi
  rm -rf \
    "$SECRETS_DIR/config" \
    "$SECRETS_DIR/certs" \
    "$SECRETS_DIR/db" \
    "$SECRETS_DIR/secrets"
}

run_bootstrap_chain() {
  log_phase "infra-up"
  if ! run_bootroot infra up --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1; then
    if ! wait_for_infra_ready; then
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
    fi
  fi

  wait_for_openbao_api
  wait_for_responder_admin

  log_phase "init"
  rm -f "$WORKSPACE_DIR/state.json"
  if ! BOOTROOT_LANG=en printf "y\ny\nn\n" | run_bootroot init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$INIT_SUMMARY_JSON" \
    --auto-generate \
    --show-secrets \
    --stepca-url "$STEPCA_EAB_URL" \
    --stepca-provisioner "admin" \
    --stepca-password "password" \
    --http-hmac "dev-hmac" \
    --eab-kid "dev-kid" \
    --eab-hmac "dev-hmac" \
    --db-dsn "postgresql://step:step-pass@postgres:5432/step?sslmode=disable" \
    --responder-url "$RESPONDER_URL" >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 160 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
    docker logs bootroot-openbao >>"$RUN_LOG" 2>&1 || true
    docker logs bootroot-postgres >>"$RUN_LOG" 2>&1 || true
    fail "bootroot init failed"
  fi

  RUNTIME_SERVICE_ADD_ROLE_ID="$(
    jq -r '.approles[] | select(.label == "runtime_service_add") | .role_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  RUNTIME_SERVICE_ADD_SECRET_ID="$(
    jq -r '.approles[] | select(.label == "runtime_service_add") | .secret_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  RUNTIME_ROTATE_ROLE_ID="$(
    jq -r '.approles[] | select(.label == "runtime_rotate") | .role_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  RUNTIME_ROTATE_SECRET_ID="$(
    jq -r '.approles[] | select(.label == "runtime_rotate") | .secret_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  [ -n "${RUNTIME_SERVICE_ADD_ROLE_ID:-}" ] || fail "Failed to parse runtime_service_add role_id"
  [ -n "${RUNTIME_SERVICE_ADD_SECRET_ID:-}" ] || fail "Failed to parse runtime_service_add secret_id"
  [ -n "${RUNTIME_ROTATE_ROLE_ID:-}" ] || fail "Failed to parse runtime_rotate role_id"
  [ -n "${RUNTIME_ROTATE_SECRET_ID:-}" ] || fail "Failed to parse runtime_rotate secret_id"
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
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

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
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

  run_bootroot service add \
    --service-name "$REMOTE_SERVICE" \
    --deploy-type daemon \
    --delivery-mode remote-bootstrap \
    --hostname "$REMOTE_HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$REMOTE_AGENT_CONFIG" \
    --cert-path "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.crt" \
    --key-path "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.key" \
    --instance-id "$REMOTE_INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1
}

wait_for_openbao_api() {
  local attempt
  for attempt in $(seq 1 30); do
    local code
    code="$(curl -sS -o /dev/null -w '%{http_code}' "http://${STEPCA_HOST_IP}:8200/v1/sys/health" || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      return 0
    fi
    sleep 1
  done
  docker logs bootroot-openbao >>"$RUN_LOG" 2>&1 || true
  fail "openbao API did not become reachable before init"
}

wait_for_responder_admin() {
  local admin_url="${RESPONDER_URL%/}/admin/http01"
  local attempt
  for attempt in $(seq 1 "$RESPONDER_READY_ATTEMPTS"); do
    local code
    code="$(curl -sS -m 2 -o /dev/null -w '%{http_code}' "$admin_url" || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      return 0
    fi
    sleep "$RESPONDER_READY_DELAY_SECS"
  done
  docker logs bootroot-http01 >>"$RUN_LOG" 2>&1 || true
  fail "responder admin endpoint did not become reachable before init: $admin_url"
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
  local hosts
  hosts=(
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
        docker exec bootroot-ca sh -c "cat /etc/hosts | tail -n 20" >>"$RUN_LOG" 2>&1 || true
        docker logs bootroot-http01 >>"$RUN_LOG" 2>&1 || true
        fail "step-ca cannot reach HTTP-01 target: ${host}:80"
      fi
      sleep "$HTTP01_TARGET_DELAY_SECS"
    done
  done
}

wait_for_stepca_health() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl -kfsS https://127.0.0.1:9000/health >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "step-ca health endpoint did not become ready"
}

snapshot_cert_meta() {
  local service="$1"
  local label="$2"
  local certs_dir="${3:-$CERTS_DIR}"
  local cert_path="$certs_dir/${service}.crt"
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
  verify_service_with_retry "$EDGE_SERVICE"
  verify_service_with_retry "$WEB_SERVICE"
  verify_service_with_retry "$REMOTE_SERVICE" "$REMOTE_AGENT_CONFIG"
  snapshot_cert_meta "$EDGE_SERVICE" "$label"
  snapshot_cert_meta "$WEB_SERVICE" "$label"
  snapshot_cert_meta "$REMOTE_SERVICE" "$label" "$REMOTE_CERTS_DIR"
}

force_reissue_for_service() {
  local service="$1"
  rm -f "$CERTS_DIR/${service}.crt" "$CERTS_DIR/${service}.key"
}

force_reissue_remote() {
  rm -f "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.crt" "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.key"
}

force_reissue_all_services() {
  force_reissue_for_service "$EDGE_SERVICE"
  force_reissue_for_service "$WEB_SERVICE"
  force_reissue_remote
}

verify_service_with_retry() {
  local service="$1"
  local agent_config="${2:-$AGENT_CONFIG_PATH}"
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

copy_remote_materials() {
  local control_service_dir="$SECRETS_DIR/services/$REMOTE_SERVICE"
  local remote_service_dir="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE"
  mkdir -p "$remote_service_dir"
  cp "$control_service_dir/role_id" "$remote_service_dir/role_id"
  cp "$control_service_dir/secret_id" "$remote_service_dir/secret_id"
  chmod 600 "$remote_service_dir/role_id" "$remote_service_dir/secret_id"
}

run_remote_bootstrap() {
  local role_id_path="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE/role_id"
  local secret_id_path="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE/secret_id"
  local eab_path="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE/eab.json"
  local ca_bundle_path="$REMOTE_CERTS_DIR/ca-bundle.pem"

  (
    cd "$REMOTE_DIR"
    "$BOOTROOT_REMOTE_BIN" bootstrap \
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
      --output json >>"$RUN_LOG" 2>&1
  )
}

run_rotations_with_verification() {
  log_phase "rotate-responder-hmac"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    responder-hmac >>"$RUN_LOG" 2>&1
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-responder-hmac"
  assert_fingerprint_changed "$EDGE_SERVICE" "initial" "after-responder-hmac"
  assert_fingerprint_changed "$WEB_SERVICE" "initial" "after-responder-hmac"
  assert_fingerprint_changed "$REMOTE_SERVICE" "initial" "after-responder-hmac"

  log_phase "rotate-stepca-password"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    stepca-password >>"$RUN_LOG" 2>&1
  wire_stepca_hosts
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-stepca-password"
  assert_fingerprint_changed "$EDGE_SERVICE" "after-responder-hmac" "after-stepca-password"
  assert_fingerprint_changed "$WEB_SERVICE" "after-responder-hmac" "after-stepca-password"
  assert_fingerprint_changed "$REMOTE_SERVICE" "after-responder-hmac" "after-stepca-password"

  log_phase "rotate-db"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    db \
    --db-admin-dsn "postgresql://step:step-pass@127.0.0.1:${POSTGRES_HOST_PORT:-5432}/stepca?sslmode=disable" >>"$RUN_LOG" 2>&1
  wire_stepca_hosts
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-db"
  assert_fingerprint_changed "$EDGE_SERVICE" "after-stepca-password" "after-db"
  assert_fingerprint_changed "$WEB_SERVICE" "after-stepca-password" "after-db"
  assert_fingerprint_changed "$REMOTE_SERVICE" "after-stepca-password" "after-db"
}

write_manifest() {
  cat >"$ARTIFACT_DIR/manifest.json" <<EOF
{
  "mode": "${RESOLUTION_MODE}",
  "compose_file": "${COMPOSE_FILE}",
  "state_file": "${ROOT_DIR}/state.json",
  "agent_config_path": "${AGENT_CONFIG_PATH}",
  "services": ["${EDGE_SERVICE}", "${WEB_SERVICE}", "${REMOTE_SERVICE}"]
}
EOF
}

main() {
  mkdir -p "$ARTIFACT_DIR" "$WORKSPACE_DIR" "$CERT_META_DIR" "$REMOTE_DIR" "$REMOTE_CERTS_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  ensure_prerequisites
  ensure_compose_images
  configure_resolution_mode
  compose_down
  reset_stepca_materials_for_e2e
  prepare_test_ca_materials
  write_agent_config
  run_bootstrap_chain
  wire_stepca_hosts
  wait_for_stepca_http01_targets
  wait_for_stepca_health

  [ -x "$BOOTROOT_AGENT_BIN" ] || cargo build --bin bootroot-agent >>"$RUN_LOG" 2>&1
  export PATH="$(dirname "$BOOTROOT_AGENT_BIN"):$PATH"

  start_service_sidecar_oba "$SIDECAR_OBA_SERVICE"

  copy_remote_materials
  log_phase "remote-bootstrap-initial"
  run_remote_bootstrap

  run_verify_pair "initial"
  run_rotations_with_verification
  write_manifest
}

main "$@"
