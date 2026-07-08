#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# shellcheck source=lib/audit-log.sh
. "$SCRIPT_DIR/lib/audit-log.sh"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-local-lifecycle-$(date +%s)}"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$ARTIFACT_DIR/workspace}"
SECRETS_DIR="${SECRETS_DIR:-$ROOT_DIR/secrets}"
CERTS_DIR="${CERTS_DIR:-$WORKSPACE_DIR/certs}"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"
INFRA_UP_ATTEMPTS="${INFRA_UP_ATTEMPTS:-6}"
INFRA_UP_DELAY_SECS="${INFRA_UP_DELAY_SECS:-5}"
INFRA_READY_ATTEMPTS="${INFRA_READY_ATTEMPTS:-30}"
INFRA_READY_DELAY_SECS="${INFRA_READY_DELAY_SECS:-4}"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"
BOOTROOT_AGENT_BIN="${BOOTROOT_AGENT_BIN:-$ROOT_DIR/target/debug/bootroot-agent}"
RESOLUTION_MODE="${RESOLUTION_MODE:-no-hosts}"
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
# Each distinct local service gets its own agent config (and with it
# its own `[openbao]` AppRole identity, service-keyed state file,
# eab.json, and daemon process).  The `[openbao]` section holds a
# single AppRole identity whose policy only reads that service's KV
# subtree, so sharing one agent config across distinct services is an
# unsupported topology.
EDGE_AGENT_CONFIG="$WORKSPACE_DIR/agent-${EDGE_SERVICE}.toml"
WEB_AGENT_CONFIG="$WORKSPACE_DIR/agent-${WEB_SERVICE}.toml"
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
RESPONDER_URL=""
RUNTIME_SERVICE_ADD_ROLE_ID=""
RUNTIME_SERVICE_ADD_SECRET_ID=""
RUNTIME_ROTATE_ROLE_ID=""
RUNTIME_ROTATE_SECRET_ID=""
INFRA_ROTATE_ROLE_ID=""
INFRA_ROTATE_SECRET_ID=""
INIT_ROOT_TOKEN=""
OPENBAO_RECOVERY_OUTPUT_FILE="$ARTIFACT_DIR/openbao-recovery.json"
# Each host-daemon bootroot-agent's fast-poll loop (default
# fast_poll_interval = 30s) is the only propagation route for rotated
# per-service secrets.  After `rotate responder-hmac` the harness waits
# for each running daemon to upsert the new HMAC into its own agent
# config before driving verification; allow one full poll interval
# plus generous margin for slow CI runners.
RESPONDER_HMAC_PROPAGATION_ATTEMPTS="${RESPONDER_HMAC_PROPAGATION_ATTEMPTS:-45}"
RESPONDER_HMAC_PROPAGATION_DELAY_SECS="${RESPONDER_HMAC_PROPAGATION_DELAY_SECS:-2}"
CURRENT_PHASE="init"
# PIDs of the long-running per-service bootroot-agent daemons (one per
# distinct local service, each bound to its own agent config).
# Required so `bootroot rotate force-reissue --wait` can deliver SIGHUP
# to a real process — without it, pkill -HUP exits 1 ("no processes
# matched") and the rotate fails before the wait path runs.
LOCAL_AGENT_DAEMON_PIDS=""
# Pin POSTGRES_HOST_PORT for the compose stack: docker-compose.yml's
# default moved from 5432 to 5433 in #588 §4c; the e2e harness
# expects 5432 (CI runners free that port before the matrix), so
# pin it explicitly here to keep compose port mapping aligned with
# wait_for_postgres_admin and the host-side admin DSN.
export POSTGRES_HOST_PORT="${POSTGRES_HOST_PORT:-5432}"
export POSTGRES_HOST="127.0.0.1"
export POSTGRES_PORT="$POSTGRES_HOST_PORT"

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
}

cleanup_hosts() {
  if [ "$RESOLUTION_MODE" != "hosts" ]; then
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
  stop_local_bootroot_agent_daemons
  capture_artifacts
  compose_down
}

on_error() {
  local line="$1"
  echo "run-local-lifecycle failed at phase=${CURRENT_PHASE} line=${line}" >&2
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
    hosts)
      if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 || fail "hosts mode requires sudo"
        run_sudo true || fail "hosts mode requires non-interactive sudo (sudo -n)"
      fi
      add_hosts_entry "$STEPCA_HOST_IP" "$STEPCA_HOST_NAME"
      add_hosts_entry "$RESPONDER_HOST_IP" "$RESPONDER_HOST_NAME"
      STEPCA_SERVER_URL="https://${STEPCA_HOST_NAME}:9000/acme/acme/directory"
      RESPONDER_URL="http://${RESPONDER_HOST_NAME}:8080"
      ;;
    no-hosts)
      STEPCA_SERVER_URL="https://localhost:9000/acme/acme/directory"
      RESPONDER_URL="http://${RESPONDER_HOST_IP}:8080"
      ;;
    *)
      fail "Unsupported RESOLUTION_MODE: $RESOLUTION_MODE"
      ;;
  esac
}

write_agent_config() {
  local config_path="$1"
  mkdir -p "$(dirname "$config_path")" "$CERTS_DIR"
  cat >"$config_path" <<EOF
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
  # Remove stale .env so infra install generates a fresh bootstrap password.
  rm -f "$ROOT_DIR/.env"
  run_bootroot infra install --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1
}

reset_stepca_materials_for_e2e() {
  if [ "${RESET_STEPCA_MATERIALS:-1}" != "1" ]; then
    return 0
  fi
  rm -rf \
    "$SECRETS_DIR/config" \
    "$SECRETS_DIR/certs" \
    "$SECRETS_DIR/db" \
    "$SECRETS_DIR/secrets" \
    "$SECRETS_DIR/password.txt" \
    "$SECRETS_DIR/password.txt.new"
}

run_bootstrap_chain() {
  # Containers are already running from install_infra().  step-ca is
  # expected to be restarting (no ca.json yet); init will bootstrap it.
  # Only wait for the services that init needs.
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
    --stepca-provisioner "acme" \
    --stepca-password "password" \
    --http-hmac "dev-hmac" \
    --no-eab \
    --db-user "step" \
    --db-name "stepca" \
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
  INFRA_ROTATE_ROLE_ID="$(
    jq -r '.approles[] | select(.label == "infra_rotate") | .role_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  INFRA_ROTATE_SECRET_ID="$(
    jq -r '.approles[] | select(.label == "infra_rotate") | .secret_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  INIT_ROOT_TOKEN="$(jq -r '.root_token // empty' "$INIT_SUMMARY_JSON")"
  [ -n "${RUNTIME_SERVICE_ADD_ROLE_ID:-}" ] || fail "Failed to parse runtime_service_add role_id"
  [ -n "${RUNTIME_SERVICE_ADD_SECRET_ID:-}" ] || fail "Failed to parse runtime_service_add secret_id"
  [ -n "${RUNTIME_ROTATE_ROLE_ID:-}" ] || fail "Failed to parse runtime_rotate role_id"
  [ -n "${RUNTIME_ROTATE_SECRET_ID:-}" ] || fail "Failed to parse runtime_rotate secret_id"
  [ -n "${INFRA_ROTATE_ROLE_ID:-}" ] || fail "Failed to parse infra_rotate role_id"
  [ -n "${INFRA_ROTATE_SECRET_ID:-}" ] || fail "Failed to parse infra_rotate secret_id"
  [ -n "${INIT_ROOT_TOKEN:-}" ] || fail "Failed to parse init root token"
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$INIT_LOG"

  log_phase "service-add"
  # Each distinct local service registers its own agent config, so the
  # `[openbao]` fast-poll section `service add` upserts carries that
  # service's own AppRole paths and a service-keyed state_path — one
  # daemon and one identity per service, the supported topology.
  run_bootroot service add \
    --service-name "$WEB_SERVICE" \
    --delivery-mode local-file \
    --hostname "$WEB_HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$WEB_AGENT_CONFIG" \
    --cert-path "$CERTS_DIR/${WEB_SERVICE}.crt" \
    --key-path "$CERTS_DIR/${WEB_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

  run_bootroot service add \
    --service-name "$REMOTE_SERVICE" \
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

  run_bootroot service add \
    --service-name "$EDGE_SERVICE" \
    --delivery-mode local-file \
    --hostname "$EDGE_HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$EDGE_AGENT_CONFIG" \
    --cert-path "$CERTS_DIR/${EDGE_SERVICE}.crt" \
    --key-path "$CERTS_DIR/${EDGE_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" \
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

wait_for_postgres_admin() {
  local host_port="${POSTGRES_HOST_PORT:-5432}"
  local admin_user="${POSTGRES_USER:-step}"
  local attempt
  for attempt in $(seq 1 30); do
    # Probe over TCP: the initdb bootstrap server listens only on the Unix
    # socket, so a socket-based pg_isready reports ready before the final
    # server (the one init connects to over TCP) is up.
    if docker exec bootroot-postgres pg_isready -h 127.0.0.1 -U "$admin_user" -d postgres >/dev/null 2>&1 &&
      bash -lc ": >/dev/tcp/127.0.0.1/${host_port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs bootroot-postgres >>"$RUN_LOG" 2>&1 || true
  fail "postgres admin endpoint did not become reachable before init"
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

apply_dns_aliases() {
  local override="$ARTIFACT_DIR/docker-compose.dns-aliases.yml"
  cat >"$override" <<YAML
services:
  bootroot-http01:
    networks:
      default:
        aliases:
          - ${INSTANCE_ID}.${EDGE_SERVICE}.${EDGE_HOSTNAME}.${DOMAIN}
          - ${INSTANCE_ID}.${WEB_SERVICE}.${WEB_HOSTNAME}.${DOMAIN}
          - ${REMOTE_INSTANCE_ID}.${REMOTE_SERVICE}.${REMOTE_HOSTNAME}.${DOMAIN}
YAML
  # Include the responder compose override (written by bootroot init) so
  # that recreating bootroot-http01 preserves both the rendered config
  # mount and the DNS aliases.
  local responder_override="$SECRETS_DIR/responder/docker-compose.responder.override.yml"
  local -a compose_args=(-f "$COMPOSE_FILE" -f "$override")
  if [ -f "$responder_override" ]; then
    compose_args+=(-f "$responder_override")
  fi
  docker compose "${compose_args[@]}" up -d bootroot-http01 >>"$RUN_LOG" 2>&1
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

prepare_stepca_validation_targets() {
  wait_for_stepca_health
  wait_for_stepca_http01_targets
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
  prepare_stepca_validation_targets
  verify_service_with_retry "$EDGE_SERVICE" "$EDGE_AGENT_CONFIG"
  verify_service_with_retry "$WEB_SERVICE" "$WEB_AGENT_CONFIG"
  verify_service_with_retry "$REMOTE_SERVICE" "$REMOTE_AGENT_CONFIG"
  snapshot_cert_meta "$EDGE_SERVICE" "$label"
  snapshot_cert_meta "$WEB_SERVICE" "$label"
  snapshot_cert_meta "$REMOTE_SERVICE" "$label" "$REMOTE_CERTS_DIR"
}

# Daemon-deploy local-file path: drives `bootroot rotate force-reissue
# --wait` end-to-end so the in-binary signal+wait code path runs in CI.
force_reissue_for_service() {
  local service="$1"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    force-reissue \
    --service-name "$service" \
    --wait \
    >>"$RUN_LOG" 2>&1
}

# Missing-cert path: web-app's own host bootroot-agent daemon owns its
# cert, so deleting the files and letting that daemon's missing-cert
# check pick them up is the right reissue trigger here.  The `bootroot
# rotate force-reissue` wait-path is exercised by the edge-proxy call
# above.
force_reissue_via_missing_cert() {
  local service="$1"
  rm -f "$CERTS_DIR/${service}.crt" "$CERTS_DIR/${service}.key"
}

# Starts one bootroot-agent host daemon bound to a single service's own
# agent config, eab.json, and AppRole identity.
start_local_agent_daemon() {
  local service="$1"
  local config="$2"
  local log="$ARTIFACT_DIR/bootroot-agent-${service}.log"
  # EAB artifact provisioned by `service add` next to the service
  # secret_id when EAB exists in KV.  Init runs with --no-eab, so the
  # file is normally absent; the agent treats a missing --eab-file as
  # open enrollment.
  local eab_file="$SECRETS_DIR/services/${service}/eab.json"
  [ -f "$config" ] || fail "agent config missing at $config"
  printf '[lifecycle] starting bootroot-agent daemon for %s: --config %s --eab-file %s\n' \
    "$service" "$config" "$eab_file" >>"$RUN_LOG"
  # bootroot-agent uses tracing_subscriber::fmt::init(), whose default
  # filter is ERROR.  The readiness probe below greps for an info-level
  # message, so we have to opt into info output explicitly.
  RUST_LOG="${RUST_LOG:-info}" \
    "$BOOTROOT_AGENT_BIN" --config "$config" \
    --eab-file "$eab_file" \
    >>"$log" 2>&1 &
  local pid=$!
  LOCAL_AGENT_DAEMON_PIDS="$LOCAL_AGENT_DAEMON_PIDS $pid"
  # Give the daemon time to load config and install its SIGHUP handler;
  # otherwise the first force_reissue may signal it before the handler
  # is ready, masking the wait-path coverage we are trying to add.
  local attempt
  for attempt in $(seq 1 20); do
    if ! kill -0 "$pid" 2>/dev/null; then
      tail -n 80 "$log" >>"$RUN_LOG" 2>&1 || true
      fail "bootroot-agent daemon for ${service} exited during startup; see $log"
    fi
    if grep -q "Profile .* daemon enabled" "$log" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  tail -n 80 "$log" >>"$RUN_LOG" 2>&1 || true
  fail "bootroot-agent daemon for ${service} failed to become ready; see $log"
}

start_local_bootroot_agent_daemons() {
  start_local_agent_daemon "$EDGE_SERVICE" "$EDGE_AGENT_CONFIG"
  start_local_agent_daemon "$WEB_SERVICE" "$WEB_AGENT_CONFIG"
}

stop_local_bootroot_agent_daemons() {
  local pid attempt
  for pid in $LOCAL_AGENT_DAEMON_PIDS; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      for attempt in $(seq 1 10); do
        if ! kill -0 "$pid" 2>/dev/null; then
          break
        fi
        sleep 0.2
      done
      kill -9 "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
  done
  LOCAL_AGENT_DAEMON_PIDS=""
}

force_reissue_remote() {
  rm -f "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.crt" "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.key"
}

force_reissue_all_services() {
  force_reissue_for_service "$EDGE_SERVICE"
  force_reissue_via_missing_cert "$WEB_SERVICE"
  force_reissue_remote
}

verify_service_with_retry() {
  local service="$1"
  local agent_config="$2"
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

# Reads the current `[acme].http_responder_hmac` value from the given
# agent config.
current_agent_responder_hmac() {
  awk -F'"' '/^[[:space:]]*http_responder_hmac[[:space:]]*=/ {print $2; exit}' \
    "$1"
}

# Waits for one service daemon's fast-poll loop to upsert the rotated
# responder HMAC into that service's own agent config.  `bootroot
# rotate responder-hmac` only writes the new HMAC to per-service KV
# (plus the infra agents); propagation is each daemon's own fast-poll
# tick (default fast_poll_interval = 30s) under its own AppRole
# identity, so the on-disk value changing is the end-to-end proof that
# the loop observed and applied the rotation for that service.
wait_for_responder_hmac_propagation() {
  local service="$1"
  local config="$2"
  local before="$3"
  local attempt current
  for attempt in $(seq 1 "$RESPONDER_HMAC_PROPAGATION_ATTEMPTS"); do
    current="$(current_agent_responder_hmac "$config")"
    if [ -n "$current" ] && [ "$current" != "$before" ]; then
      printf '[lifecycle] fast-poll propagated rotated responder HMAC for %s within ~%ss\n' \
        "$service" "$((attempt * RESPONDER_HMAC_PROPAGATION_DELAY_SECS))" >>"$RUN_LOG"
      return 0
    fi
    sleep "$RESPONDER_HMAC_PROPAGATION_DELAY_SECS"
  done
  tail -n 80 "$ARTIFACT_DIR/bootroot-agent-${service}.log" >>"$RUN_LOG" 2>&1 || true
  fail "bootroot-agent fast-poll did not propagate the rotated responder HMAC into $config within $((RESPONDER_HMAC_PROPAGATION_ATTEMPTS * RESPONDER_HMAC_PROPAGATION_DELAY_SECS))s"
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

rotate_infra_secret_id() {
  local target="$1"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
    --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
    --yes \
    approle-secret-id \
    --infra "$target" >>"$RUN_LOG" 2>&1
}

run_rotation_infra_secret_id() {
  log_phase "rotate-infra-secret-id"
  local target before after
  for target in stepca responder; do
    before="$(cat "$SECRETS_DIR/openbao/${target}/secret_id")"
    rotate_infra_secret_id "$target"
    after="$(cat "$SECRETS_DIR/openbao/${target}/secret_id")"
    [ -n "$after" ] || fail "infra secret_id for ${target} is empty after rotation"
    [ "$before" != "$after" ] || fail "infra secret_id for ${target} did not change"
  done

  # Privilege-separation boundary (#667): the general runtime-rotate
  # credential must NOT be able to mint infra secret_ids — that would
  # let it log in as the stepca role and read CA core secrets.
  log_phase "rotate-infra-secret-id-denied-for-runtime-rotate"
  if run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    approle-secret-id \
    --infra stepca >>"$RUN_LOG" 2>&1; then
    fail "runtime-rotate credential must not mint infra secret_ids"
  fi
}

# Self-mint of the rotate credentials' own secret_ids (#672): a
# file-based rotate credential re-mints itself as the final step of a
# fully successful invocation and atomically replaces the file the
# scheduler reads. Exercises the runtime-rotate self-mint over two
# consecutive single-service invocations (the second authenticates with
# the credential file replaced by the first) and the infra-rotate
# two-invocation flow (stepca replaces the file, responder reads it
# fresh). The inline credentials used elsewhere in this script stay
# valid: self-mint never revokes the previous secret_id.
run_rotation_secret_id_self_mint() {
  log_phase "rotate-secret-id-self-mint"
  local cred_dir="$ARTIFACT_DIR/rotate-creds"
  mkdir -p "$cred_dir/runtime" "$cred_dir/infra"
  printf '%s' "$RUNTIME_ROTATE_SECRET_ID" >"$cred_dir/runtime/secret_id"
  printf '%s' "$INFRA_ROTATE_SECRET_ID" >"$cred_dir/infra/secret_id"
  chmod 600 "$cred_dir/runtime/secret_id" "$cred_dir/infra/secret_id"

  local pass before after
  for pass in first second; do
    before="$(cat "$cred_dir/runtime/secret_id")"
    run_bootroot rotate \
      --compose-file "$COMPOSE_FILE" \
      --openbao-url "http://${STEPCA_HOST_IP}:8200" \
      --auth-mode approle \
      --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
      --approle-secret-id-file "$cred_dir/runtime/secret_id" \
      --yes \
      approle-secret-id \
      --service-name "$EDGE_SERVICE" >>"$RUN_LOG" 2>&1 ||
      fail "runtime-rotate self-mint rotation (${pass} pass) failed"
    after="$(cat "$cred_dir/runtime/secret_id")"
    [ -n "$after" ] || fail "runtime-rotate credential file is empty after self-mint (${pass} pass)"
    [ "$before" != "$after" ] || fail "runtime-rotate credential file was not replaced by the self-mint (${pass} pass)"
  done

  local target
  for target in stepca responder; do
    before="$(cat "$cred_dir/infra/secret_id")"
    run_bootroot rotate \
      --compose-file "$COMPOSE_FILE" \
      --openbao-url "http://${STEPCA_HOST_IP}:8200" \
      --auth-mode approle \
      --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
      --approle-secret-id-file "$cred_dir/infra/secret_id" \
      --yes \
      approle-secret-id \
      --infra "$target" >>"$RUN_LOG" 2>&1 ||
      fail "infra-rotate self-mint rotation (--infra ${target}) failed"
    after="$(cat "$cred_dir/infra/secret_id")"
    [ -n "$after" ] || fail "infra-rotate credential file is empty after self-mint (--infra ${target})"
    [ "$before" != "$after" ] || fail "infra-rotate credential file was not replaced by the self-mint (--infra ${target})"
  done
}

run_rotations_with_verification() {
  # Rotate the infra secret_ids first: the stepca-password and
  # responder-hmac phases below drive the restarted infra OpenBao
  # Agents (stepca / responder) through real template renders,
  # verifying they re-authenticated with the rotated credentials.
  run_rotation_infra_secret_id
  run_rotation_secret_id_self_mint

  log_phase "rotate-openbao-recovery"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --root-token "$INIT_ROOT_TOKEN" \
    --yes \
    openbao-recovery \
    --rotate-root-token \
    --output "$OPENBAO_RECOVERY_OUTPUT_FILE" >>"$RUN_LOG" 2>&1
  [ -s "$OPENBAO_RECOVERY_OUTPUT_FILE" ] || fail "openbao recovery output not written"
  log_phase "bootstrap-after-openbao-recovery"
  run_remote_bootstrap
  run_verify_pair "after-openbao-recovery"

  log_phase "rotate-responder-hmac"
  local edge_hmac_before web_hmac_before
  edge_hmac_before="$(current_agent_responder_hmac "$EDGE_AGENT_CONFIG")"
  web_hmac_before="$(current_agent_responder_hmac "$WEB_AGENT_CONFIG")"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    responder-hmac >>"$RUN_LOG" 2>&1
  # Both per-service daemons must observe the rotation independently:
  # each reads only its own service's KV subtree.
  wait_for_responder_hmac_propagation "$EDGE_SERVICE" "$EDGE_AGENT_CONFIG" "$edge_hmac_before"
  wait_for_responder_hmac_propagation "$WEB_SERVICE" "$WEB_AGENT_CONFIG" "$web_hmac_before"
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
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-stepca-password"
  assert_fingerprint_changed "$EDGE_SERVICE" "after-responder-hmac" "after-stepca-password"
  assert_fingerprint_changed "$WEB_SERVICE" "after-responder-hmac" "after-stepca-password"
  assert_fingerprint_changed "$REMOTE_SERVICE" "after-responder-hmac" "after-stepca-password"

  log_phase "rotate-db"
  # Build admin DSN from ca.json so the password matches the current
  # state (it may have been rotated by `init`).
  local db_admin_dsn
  db_admin_dsn="$(jq -r '.db.dataSource // empty' "$SECRETS_DIR/config/ca.json")"
  if [ -z "${db_admin_dsn:-}" ]; then
    db_admin_dsn="postgresql://step:step-pass@127.0.0.1:${POSTGRES_HOST_PORT:-5432}/stepca?sslmode=disable"
  else
    # Replace the Docker-internal host:port with the host-side mapping.
    db_admin_dsn="$(echo "$db_admin_dsn" \
      | sed "s|@postgres:5432|@127.0.0.1:${POSTGRES_HOST_PORT:-5432}|")"
  fi
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    db \
    --db-admin-dsn "$db_admin_dsn" >>"$RUN_LOG" 2>&1
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-db"
  assert_fingerprint_changed "$EDGE_SERVICE" "after-stepca-password" "after-db"
  assert_fingerprint_changed "$WEB_SERVICE" "after-stepca-password" "after-db"
  assert_fingerprint_changed "$REMOTE_SERVICE" "after-stepca-password" "after-db"

  log_phase "rotate-ca-key"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    ca-key --skip reissue --force --cleanup >>"$RUN_LOG" 2>&1
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-ca-key"
  assert_fingerprint_changed "$EDGE_SERVICE" "after-db" "after-ca-key"
  assert_fingerprint_changed "$WEB_SERVICE" "after-db" "after-ca-key"
  assert_fingerprint_changed "$REMOTE_SERVICE" "after-db" "after-ca-key"

  log_phase "rotate-ca-key-full"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    ca-key --full --skip reissue --force --cleanup >>"$RUN_LOG" 2>&1
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-ca-key-full"
  assert_fingerprint_changed "$EDGE_SERVICE" "after-ca-key" "after-ca-key-full"
  assert_fingerprint_changed "$WEB_SERVICE" "after-ca-key" "after-ca-key-full"
  assert_fingerprint_changed "$REMOTE_SERVICE" "after-ca-key" "after-ca-key-full"
}

write_manifest() {
  cat >"$ARTIFACT_DIR/manifest.json" <<EOF
{
  "mode": "${RESOLUTION_MODE}",
  "compose_file": "${COMPOSE_FILE}",
  "state_file": "${ROOT_DIR}/state.json",
  "agent_config_paths": ["${EDGE_AGENT_CONFIG}", "${WEB_AGENT_CONFIG}"],
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
  configure_resolution_mode
  compose_down
  reset_stepca_materials_for_e2e
  install_infra
  write_agent_config "$EDGE_AGENT_CONFIG"
  write_agent_config "$WEB_AGENT_CONFIG"
  run_bootstrap_chain

  [ -x "$BOOTROOT_AGENT_BIN" ] || cargo build --bin bootroot-agent >>"$RUN_LOG" 2>&1
  export PATH="$(dirname "$BOOTROOT_AGENT_BIN"):$PATH"

  apply_dns_aliases
  prepare_stepca_validation_targets

  copy_remote_materials
  log_phase "remote-bootstrap-initial"
  run_remote_bootstrap

  run_verify_pair "initial"
  start_local_bootroot_agent_daemons
  run_rotations_with_verification
  stop_local_bootroot_agent_daemons

  log_phase "assert-openbao-audit-log"
  assert_openbao_audit_log

  write_manifest
}

main "$@"
