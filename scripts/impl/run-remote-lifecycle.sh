#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# shellcheck source=lib/audit-log.sh
. "$SCRIPT_DIR/lib/audit-log.sh"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-remote-lifecycle-$(date +%s)}"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
SECRETS_DIR="${SECRETS_DIR:-$ROOT_DIR/secrets}"
CONTROL_DIR="${CONTROL_DIR:-$ARTIFACT_DIR/control-node}"
REMOTE_DIR="${REMOTE_DIR:-$ARTIFACT_DIR/remote-node}"
REMOTE_AGENT_CONFIG_PATH="${REMOTE_AGENT_CONFIG_PATH:-$REMOTE_DIR/agent.toml}"
REMOTE_CERTS_DIR="${REMOTE_CERTS_DIR:-$REMOTE_DIR/certs}"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"
INFRA_UP_ATTEMPTS="${INFRA_UP_ATTEMPTS:-12}"
INFRA_UP_DELAY_SECS="${INFRA_UP_DELAY_SECS:-10}"
VERIFY_ATTEMPTS="${VERIFY_ATTEMPTS:-5}"
VERIFY_DELAY_SECS="${VERIFY_DELAY_SECS:-5}"
HTTP01_TARGET_ATTEMPTS="${HTTP01_TARGET_ATTEMPTS:-40}"
HTTP01_TARGET_DELAY_SECS="${HTTP01_TARGET_DELAY_SECS:-2}"
RESPONDER_READY_ATTEMPTS="${RESPONDER_READY_ATTEMPTS:-30}"
RESPONDER_READY_DELAY_SECS="${RESPONDER_READY_DELAY_SECS:-1}"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"
BOOTROOT_AGENT_BIN="${BOOTROOT_AGENT_BIN:-$ROOT_DIR/target/debug/bootroot-agent}"
RESOLUTION_MODE="${RESOLUTION_MODE:-no-hosts}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-summary.json"
CERT_META_DIR="$ARTIFACT_DIR/cert-meta"
HOSTS_MARKER="# bootroot-e2e-main-remote-lifecycle"

SERVICE_NAME="edge-proxy"
HOSTNAME="edge-node-02"
DOMAIN="trusted.domain"
INSTANCE_ID="101"
SERVICE_NAME_2="web-app"
HOSTNAME_2="web-02"
INSTANCE_ID_2="102"
REMOTE_AGENT_CONFIG_PATH_2="$REMOTE_DIR/agent-${SERVICE_NAME_2}.toml"
SERVICE_KV_PATH_BASE="bootroot/services/${SERVICE_NAME}"
SERVICE_KV_PATH_BASE_2="bootroot/services/${SERVICE_NAME_2}"

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
CURRENT_PHASE="init"
# PID of the background bootroot-agent daemon started for the genuine
# KV force-reissue round-trip. Empty when no daemon is running; the
# cleanup trap kills it so a failed run never leaks the process.
REMOTE_AGENT_PID=""
# Bounds the genuine force-reissue --wait round-trip. The agent's default
# fast_poll_interval is 30s, so allow generous margin over one poll plus an
# ACME renewal for slow CI runners.
FORCE_REISSUE_WAIT_TIMEOUT="${FORCE_REISSUE_WAIT_TIMEOUT:-120s}"
# Bounds how long the self-heal phase waits for a *running* agent's
# fast-poll loop to refresh the on-disk secret_id and re-render
# [trust]+ca-bundle after a control-plane rotation. Must exceed one
# fast_poll_interval (default 30s); 30 * 2s = 60s of margin.
SELFHEAL_ATTEMPTS="${SELFHEAL_ATTEMPTS:-30}"
SELFHEAL_DELAY_SECS="${SELFHEAL_DELAY_SECS:-2}"
# The extra trust anchor's fingerprint appended by run_rotation_trust_sync,
# exported so the self-heal assertion can confirm the running agent wrote it
# into the remote agent.toml [trust] pins via fast-poll.
TRUST_SYNC_EXTRA_FINGERPRINT=""
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
  printf '{"ts":"%s","phase":"%s","mode":"%s"}\n' "$now" "$phase" "$RESOLUTION_MODE" >>"$PHASE_LOG"
}

fail() {
  local message="$1"
  printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$message" >>"$RUN_LOG" || true
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

run_bootroot_control() {
  (
    cd "$CONTROL_DIR"
    "$BOOTROOT_BIN" "$@"
  )
}

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v python3 >/dev/null 2>&1 || fail "python3 is required"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required"
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  [ -x "$BOOTROOT_REMOTE_BIN" ] || fail "bootroot-remote binary not executable: $BOOTROOT_REMOTE_BIN"
  [ -x "$BOOTROOT_AGENT_BIN" ] || fail "bootroot-agent binary not executable: $BOOTROOT_AGENT_BIN"
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

stop_remote_agent() {
  [ -n "$REMOTE_AGENT_PID" ] || return 0
  kill "$REMOTE_AGENT_PID" >/dev/null 2>&1 || true
  wait "$REMOTE_AGENT_PID" 2>/dev/null || true
  REMOTE_AGENT_PID=""
}

cleanup() {
  log_phase "cleanup"
  stop_remote_agent
  cleanup_hosts
  capture_artifacts
  compose_down
}

on_error() {
  local line="$1"
  echo "run-remote-lifecycle failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "artifact dir: ${ARTIFACT_DIR}" >&2
  [ -f "$RUN_LOG" ] && tail -n 120 "$RUN_LOG" >&2 || true
  [ -f "$INIT_RAW_LOG" ] && tail -n 120 "$INIT_RAW_LOG" >&2 || true
  [ -f "$INIT_LOG" ] && tail -n 120 "$INIT_LOG" >&2 || true
}

add_hosts_entry() {
  local ip="$1"
  local host="$2"
  if grep -qE "[[:space:]]${host}([[:space:]]|$)" /etc/hosts; then
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

reset_stepca_materials_for_e2e() {
  if [ "${RESET_STEPCA_MATERIALS:-1}" != "1" ]; then
    return 0
  fi
  rm -rf "$SECRETS_DIR/config" "$SECRETS_DIR/certs" "$SECRETS_DIR/db" "$SECRETS_DIR/secrets"
}

install_infra() {
  mkdir -p "$REMOTE_CERTS_DIR"
  chmod 700 "$REMOTE_CERTS_DIR"
  # Remove stale .env so infra install generates a fresh bootstrap password.
  rm -f "$ROOT_DIR/.env"
  run_bootroot_control infra install --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1
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
    if docker exec bootroot-postgres pg_isready -U "$admin_user" -d postgres >/dev/null 2>&1 &&
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

run_bootstrap_chain() {
  # Containers are already running from install_infra().  step-ca is
  # expected to be restarting (no ca.json yet); init will bootstrap it.
  # Only wait for the services that init needs.
  wait_for_postgres_admin
  wait_for_openbao_api
  wait_for_responder_admin

  log_phase "init"
  rm -f "$CONTROL_DIR/state.json"
  if ! BOOTROOT_LANG=en printf "y\ny\ny\n" | run_bootroot_control init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$INIT_SUMMARY_JSON" \
    --enable auto-generate,show-secrets,db-provision \
    --stepca-provisioner "acme" \
    --stepca-password "password" \
    --no-eab \
    --http-hmac "dev-hmac" \
    --db-user "step" \
    --db-name "stepca" \
    --responder-url "$RESPONDER_URL" >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 160 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
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
  run_bootroot_control service add \
    --service-name "$SERVICE_NAME" \
    --deploy-type daemon \
    --delivery-mode remote-bootstrap \
    --hostname "$HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$REMOTE_AGENT_CONFIG_PATH" \
    --cert-path "$REMOTE_CERTS_DIR/${SERVICE_NAME}.crt" \
    --key-path "$REMOTE_CERTS_DIR/${SERVICE_NAME}.key" \
    --instance-id "$INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

  run_bootroot_control service add \
    --service-name "$SERVICE_NAME_2" \
    --deploy-type docker \
    --delivery-mode remote-bootstrap \
    --hostname "$HOSTNAME_2" \
    --domain "$DOMAIN" \
    --agent-config "$REMOTE_AGENT_CONFIG_PATH_2" \
    --cert-path "$REMOTE_CERTS_DIR/${SERVICE_NAME_2}.crt" \
    --key-path "$REMOTE_CERTS_DIR/${SERVICE_NAME_2}.key" \
    --instance-id "$INSTANCE_ID_2" \
    --container-name "$SERVICE_NAME_2" \
    --no-validate-agent \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1
}

copy_remote_bootstrap_materials() {
  local service="$1"
  local control_service_dir="$SECRETS_DIR/services/$service"
  local remote_service_dir="$REMOTE_DIR/secrets/services/$service"
  mkdir -p "$remote_service_dir"
  cp "$control_service_dir/role_id" "$remote_service_dir/role_id"
  cp "$control_service_dir/secret_id" "$remote_service_dir/secret_id"
  chmod 600 "$remote_service_dir/role_id" "$remote_service_dir/secret_id"
}

apply_dns_aliases() {
  local override="$ARTIFACT_DIR/docker-compose.dns-aliases.yml"
  cat >"$override" <<YAML
services:
  bootroot-http01:
    networks:
      default:
        aliases:
          - ${INSTANCE_ID}.${SERVICE_NAME}.${HOSTNAME}.${DOMAIN}
          - ${INSTANCE_ID_2}.${SERVICE_NAME_2}.${HOSTNAME_2}.${DOMAIN}
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
    "${INSTANCE_ID}.${SERVICE_NAME}.${HOSTNAME}.${DOMAIN}"
    "${INSTANCE_ID_2}.${SERVICE_NAME_2}.${HOSTNAME_2}.${DOMAIN}"
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

run_remote_bootstrap() {
  local service="$1"
  local agent_config="$2"
  local hostname_val="$3"
  local instance_id="$4"
  local role_id_path="$REMOTE_DIR/secrets/services/$service/role_id"
  local secret_id_path="$REMOTE_DIR/secrets/services/$service/secret_id"
  local eab_path="$REMOTE_DIR/secrets/services/$service/eab.json"
  local ca_bundle_path="$REMOTE_CERTS_DIR/ca-bundle.pem"

  (
    cd "$REMOTE_DIR"
    "$BOOTROOT_REMOTE_BIN" bootstrap \
      --openbao-url "http://${STEPCA_HOST_IP}:8200" \
      --kv-mount "secret" \
      --service-name "$service" \
      --role-id-path "$role_id_path" \
      --secret-id-path "$secret_id_path" \
      --eab-file-path "$eab_path" \
      --agent-config-path "$agent_config" \
      --agent-email "admin@example.com" \
      --agent-server "$STEPCA_SERVER_URL" \
      --agent-domain "$DOMAIN" \
      --agent-responder-url "$RESPONDER_URL" \
      --profile-hostname "$hostname_val" \
      --profile-instance-id "$instance_id" \
      --profile-cert-path "$REMOTE_CERTS_DIR/${service}.crt" \
      --profile-key-path "$REMOTE_CERTS_DIR/${service}.key" \
      --ca-bundle-path "$ca_bundle_path" \
      --output json >>"$RUN_LOG" 2>&1
  )
}

verify_with_retry() {
  local service="$1"
  local agent_config="$2"
  local attempt
  for attempt in $(seq 1 "$VERIFY_ATTEMPTS"); do
    if run_bootroot_control verify --service-name "$service" --agent-config "$agent_config" --agent-binary "$BOOTROOT_AGENT_BIN" >>"$RUN_LOG" 2>&1; then
      return 0
    fi
    if [ "$attempt" -eq "$VERIFY_ATTEMPTS" ]; then
      fail "verify failed for ${service} after ${VERIFY_ATTEMPTS} attempts"
    fi
    sleep "$VERIFY_DELAY_SECS"
  done
}

snapshot_cert_meta() {
  local service="$1"
  local label="$2"
  local cert_path="$REMOTE_CERTS_DIR/${service}.crt"
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

assert_fingerprint_changed() {
  local service="$1"
  local before_label="$2"
  local after_label="$3"
  local before_fp after_fp
  before_fp="$(fingerprint_of "$service" "$before_label")"
  after_fp="$(fingerprint_of "$service" "$after_label")"
  [ -n "$before_fp" ] || fail "Missing fingerprint for ${service}/${before_label}"
  [ -n "$after_fp" ] || fail "Missing fingerprint for ${service}/${after_label}"
  [ "$before_fp" != "$after_fp" ] || fail "Fingerprint did not change for ${service} (${before_label} -> ${after_label})"
}

run_verify_pair() {
  local label="$1"
  log_phase "verify-${label}"
  verify_with_retry "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH"
  verify_with_retry "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2"
  snapshot_cert_meta "$SERVICE_NAME" "$label"
  snapshot_cert_meta "$SERVICE_NAME_2" "$label"
}

openbao_write_service_kv() {
  local kv_path_base="$1"
  local item="$2"
  local payload="$3"
  local runtime_token
  runtime_token="$(
    curl -fsS \
      -X POST \
      -H "Content-Type: application/json" \
      "http://${STEPCA_HOST_IP}:8200/v1/auth/approle/login" \
      -d "$(jq -n \
        --arg role_id "$RUNTIME_ROTATE_ROLE_ID" \
        --arg secret_id "$RUNTIME_ROTATE_SECRET_ID" \
        '{role_id:$role_id,secret_id:$secret_id}')" \
      | jq -r '.auth.client_token // empty'
  )"
  [ -n "${runtime_token:-}" ] || fail "Failed to obtain runtime AppRole client token"
  curl -fsS \
    -X POST \
    -H "X-Vault-Token: ${runtime_token}" \
    -H "Content-Type: application/json" \
    "http://${STEPCA_HOST_IP}:8200/v1/secret/data/${kv_path_base}/${item}" \
    -d "$payload" >/dev/null
}

force_reissue_remote_service() {
  local service="$1"
  rm -f "$REMOTE_CERTS_DIR/${service}.crt" "$REMOTE_CERTS_DIR/${service}.key"
}

# Exercises the genuine KV force-reissue round-trip for a remote-bootstrap
# service. Unlike force_reissue_remote_service (which fakes reissue by
# deleting cert files), this runs a real bootroot-agent daemon so its
# fast-poll loop observes the control-plane's `rotate force-reissue --wait`
# KV request, renews via ACME, and writes the completion markers back to
# KV. That write-back requires the service AppRole to hold create/update on
# its reissue KV path; without it, `--wait` blocks until timeout. This is
# the coverage that would have caught issue #677.
# Drives a `rotate force-reissue --wait` against an *already-running* agent
# (tracked in REMOTE_AGENT_PID) and asserts the KV round-trip completed and
# the certificate was actually reissued on disk. Stops the agent before
# returning. Shared by the fresh-bootstrap round-trip and the self-heal
# round-trip so both exercise the identical completion path.
drive_force_reissue_wait() {
  local service="$1"
  local before_label="$2"
  local after_label="$3"
  local reissue_log="$ARTIFACT_DIR/force-reissue-${service}.log"
  local status=0
  run_bootroot_control rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    force-reissue \
    --service-name "$service" \
    --wait \
    --wait-timeout "$FORCE_REISSUE_WAIT_TIMEOUT" >"$reissue_log" 2>&1 || status=$?

  cat "$reissue_log" >>"$RUN_LOG"
  stop_remote_agent

  # Exit code 124 is the --wait timeout convention; any non-zero here means
  # the round-trip did not complete, which is exactly the #677 regression.
  [ "$status" -eq 0 ] \
    || fail "rotate force-reissue --wait exited ${status} for ${service} (expected completion, not timeout)"
  grep -q "reported completion" "$reissue_log" \
    || fail "rotate force-reissue --wait for ${service} did not observe agent completion"

  # The agent must have actually reissued the certificate on disk.
  snapshot_cert_meta "$service" "$after_label"
  assert_fingerprint_changed "$service" "$before_label" "$after_label"
}

run_force_reissue_wait_roundtrip() {
  local service="$1"
  local agent_config="$2"
  local hostname_val="$3"
  local instance_id="$4"
  log_phase "force-reissue-wait-${service}"

  # Re-bootstrap so the agent config, credentials and initial cert are
  # fresh, then snapshot the cert to detect the reissue.
  run_remote_bootstrap "$service" "$agent_config" "$hostname_val" "$instance_id"
  snapshot_cert_meta "$service" "before-force-reissue"

  # Start the long-lived agent so its fast-poll loop is the consumer of the
  # KV force-reissue request. It authenticates via the service AppRole from
  # the [openbao] section that bootstrap wrote into the agent config.
  local agent_log="$ARTIFACT_DIR/remote-agent-${service}.log"
  "$BOOTROOT_AGENT_BIN" --config "$agent_config" >>"$agent_log" 2>&1 &
  REMOTE_AGENT_PID=$!
  # Give the daemon a moment to load config and complete its initial login
  # before the request lands, so the next fast-poll tick observes it.
  sleep 3

  drive_force_reissue_wait "$service" "before-force-reissue" "after-force-reissue"
}

# Proves a *running* remote agent stays self-sufficient across control-plane
# secret_id and trust rotations with NO manual re-bootstrap on the remote
# host — the whole point of approach C. Deterministic (does not wait out
# secret_id_ttl): starts the long-lived agent, then confirms its fast-poll
# loop (1) refreshed the on-disk secret_id file to the freshly rotated
# credential and (2) re-rendered the agent.toml [trust] pins + ca-bundle with
# the new anchor, and finally that the loop is still operating by completing a
# genuine force-reissue --wait round-trip through it (which requires it to be
# authenticated with the refreshed credential).
run_selfheal_roundtrip() {
  local service="$1"
  local agent_config="$2"
  log_phase "selfheal-${service}"

  local secret_id_path="$REMOTE_DIR/secrets/services/$service/secret_id"
  local secret_id_before
  secret_id_before="$(cat "$secret_id_path")"
  snapshot_cert_meta "$service" "before-selfheal"

  local agent_log="$ARTIFACT_DIR/selfheal-agent-${service}.log"
  "$BOOTROOT_AGENT_BIN" --config "$agent_config" >>"$agent_log" 2>&1 &
  REMOTE_AGENT_PID=$!

  # Wait for the secret_id + trust polls to apply on disk. The secret_id
  # file must change to the rotated value and the new trust anchor must
  # appear in the agent.toml [trust] pins the daemon rewrote.
  local applied="" attempt
  for attempt in $(seq 1 "$SELFHEAL_ATTEMPTS"); do
    if [ "$(cat "$secret_id_path")" != "$secret_id_before" ] \
      && grep -qi "$TRUST_SYNC_EXTRA_FINGERPRINT" "$agent_config"; then
      applied="yes"
      break
    fi
    sleep "$SELFHEAL_DELAY_SECS"
  done
  if [ -z "$applied" ]; then
    stop_remote_agent
    fail "running agent did not self-heal secret_id/trust for ${service} within $((SELFHEAL_ATTEMPTS * SELFHEAL_DELAY_SECS))s"
  fi

  # The loop kept operating on the refreshed credential: drive a genuine
  # force-reissue --wait round-trip through the same running agent.
  drive_force_reissue_wait "$service" "before-selfheal" "after-selfheal"
}

run_rotation_secret_id() {
  log_phase "rotate-secret-id"
  run_bootroot_control rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    approle-secret-id \
    --service-name "$SERVICE_NAME" >>"$RUN_LOG" 2>&1
  # Batch selector (#669): --all-services follows state.json, so this
  # single invocation covers $SERVICE_NAME_2 and re-rotates
  # $SERVICE_NAME, doubling as re-run idempotence coverage.
  run_bootroot_control rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    approle-secret-id \
    --all-services >>"$RUN_LOG" 2>&1
  grep -q "services rotated: 2 succeeded, 0 failed (total 2)" "$RUN_LOG" \
    || fail "batch secret_id rotation summary missing from run log"
}

run_rotation_trust_sync() {
  log_phase "rotate-trust-sync"
  local current_trust_json extra_cert_pem extra_fingerprint ca_bundle_pem payload tmp_dir
  current_trust_json="$(python3 - "$REMOTE_AGENT_CONFIG_PATH" <<'PY'
import json
import sys
import tomllib

with open(sys.argv[1], "rb") as fh:
    data = tomllib.load(fh)
trusted = data.get("trust", {}).get("trusted_ca_sha256", [])
if not trusted:
    raise SystemExit("missing trust.trusted_ca_sha256")
print(json.dumps(trusted))
PY
)"
  # The extra trust anchor must be a real cert: issue #622 made
  # `bootroot verify` fail when any fingerprint in
  # `trust.trusted_ca_sha256` is absent from `trust.ca_bundle_path`,
  # so a random `openssl rand -hex 32` fingerprint would trip the
  # post-rotation renewal the self-heal phase drives.
  tmp_dir="$(mktemp -d)"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$tmp_dir/key.pem" \
    -out "$tmp_dir/cert.pem" \
    -days 1 \
    -subj "/CN=trust-sync-extra-$(date +%s%N)" \
    >/dev/null 2>&1
  extra_cert_pem="$(cat "$tmp_dir/cert.pem")"
  extra_fingerprint="$(openssl x509 -in "$tmp_dir/cert.pem" -outform DER \
    | openssl dgst -sha256 -hex \
    | awk '{print $NF}')"
  rm -rf "$tmp_dir"
  # Export so the self-heal phase can confirm the running agent picked up
  # this new anchor via fast-poll (no manual re-bootstrap).
  TRUST_SYNC_EXTRA_FINGERPRINT="$extra_fingerprint"
  ca_bundle_pem="$(cat "$REMOTE_CERTS_DIR/ca-bundle.pem")
$extra_cert_pem"
  payload="$(jq -n --argjson current "$current_trust_json" --arg extra "$extra_fingerprint" --arg pem "$ca_bundle_pem" '{data:{trusted_ca_sha256:($current + [$extra]),ca_bundle_pem:$pem}}')"
  openbao_write_service_kv "$SERVICE_KV_PATH_BASE" "trust" "$payload"
  openbao_write_service_kv "$SERVICE_KV_PATH_BASE_2" "trust" "$payload"
}

run_rotation_responder_hmac() {
  log_phase "rotate-responder-hmac"
  run_bootroot_control rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    responder-hmac >>"$RUN_LOG" 2>&1
}

main() {
  mkdir -p "$ARTIFACT_DIR" "$CONTROL_DIR" "$REMOTE_DIR" "$REMOTE_CERTS_DIR" "$CERT_META_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  ensure_prerequisites
  configure_resolution_mode
  compose_down
  reset_stepca_materials_for_e2e
  install_infra

  run_bootstrap_chain
  copy_remote_bootstrap_materials "$SERVICE_NAME"
  copy_remote_bootstrap_materials "$SERVICE_NAME_2"
  apply_dns_aliases
  wait_for_stepca_http01_targets

  log_phase "bootstrap-initial"
  run_remote_bootstrap "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"
  run_remote_bootstrap "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2" "$HOSTNAME_2" "$INSTANCE_ID_2"

  run_verify_pair "initial"

  # Approach C: a running remote agent must stay self-sufficient across
  # secret_id AND trust rotation with NO manual re-bootstrap on the remote.
  # Rotate both in the control plane, then prove each running agent's
  # fast-poll loop self-heals (refreshes its own secret_id, re-renders
  # trust) and keeps operating.
  run_rotation_secret_id
  run_rotation_trust_sync
  run_selfheal_roundtrip "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH"
  run_selfheal_roundtrip "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2"
  assert_fingerprint_changed "$SERVICE_NAME" "initial" "after-selfheal"
  assert_fingerprint_changed "$SERVICE_NAME_2" "initial" "after-selfheal"

  run_rotation_responder_hmac
  log_phase "bootstrap-after-responder-hmac"
  run_remote_bootstrap "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"
  run_remote_bootstrap "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2" "$HOSTNAME_2" "$INSTANCE_ID_2"
  force_reissue_remote_service "$SERVICE_NAME"
  force_reissue_remote_service "$SERVICE_NAME_2"
  run_verify_pair "after-responder-hmac"
  assert_fingerprint_changed "$SERVICE_NAME" "after-selfheal" "after-responder-hmac"
  assert_fingerprint_changed "$SERVICE_NAME_2" "after-selfheal" "after-responder-hmac"

  run_force_reissue_wait_roundtrip \
    "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"

  log_phase "assert-openbao-audit-log"
  assert_openbao_audit_log
}

main "$@"
