#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

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
RESOLUTION_MODE="${RESOLUTION_MODE:-fqdn-only-hosts}"

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
INIT_EAB_KID="${INIT_EAB_KID:-dev-kid}"
INIT_EAB_HMAC="${INIT_EAB_HMAC:-dev-hmac}"
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
STEPCA_EAB_URL=""
RESPONDER_URL=""
RUNTIME_SERVICE_ADD_ROLE_ID=""
RUNTIME_SERVICE_ADD_SECRET_ID=""
RUNTIME_ROTATE_ROLE_ID=""
RUNTIME_ROTATE_SECRET_ID=""
CURRENT_PHASE="init"

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

ensure_compose_images() {
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" build step-ca bootroot-http01 >>"$RUN_LOG" 2>&1
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

reset_stepca_materials_for_e2e() {
  if [ "${RESET_STEPCA_MATERIALS:-1}" != "1" ]; then
    return 0
  fi
  rm -rf "$SECRETS_DIR/config" "$SECRETS_DIR/certs" "$SECRETS_DIR/db" "$SECRETS_DIR/secrets"
}

prepare_test_ca_materials() {
  mkdir -p "$SECRETS_DIR" "$REMOTE_CERTS_DIR"
  chmod 700 "$SECRETS_DIR" "$REMOTE_CERTS_DIR"
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

run_bootstrap_chain() {
  log_phase "infra-up"
  local attempt
  for attempt in $(seq 1 "$INFRA_UP_ATTEMPTS"); do
    if run_bootroot_control infra up --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1; then
      break
    fi
    if [ "$attempt" -eq "$INFRA_UP_ATTEMPTS" ]; then
      fail "bootroot infra up failed after ${INFRA_UP_ATTEMPTS} attempts"
    fi
    sleep "$INFRA_UP_DELAY_SECS"
  done

  wait_for_openbao_api
  wait_for_responder_admin

  log_phase "init"
  rm -f "$CONTROL_DIR/state.json"
  if ! BOOTROOT_LANG=en printf "y\ny\nn\n" | run_bootroot_control init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$INIT_SUMMARY_JSON" \
    --auto-generate \
    --show-secrets \
    --stepca-url "$STEPCA_EAB_URL" \
    --stepca-provisioner "acme" \
    --stepca-password "password" \
    --eab-kid "$INIT_EAB_KID" \
    --eab-hmac "$INIT_EAB_HMAC" \
    --http-hmac "dev-hmac" \
    --db-dsn "postgresql://step:step-pass@postgres:5432/step?sslmode=disable" \
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

wire_stepca_hosts() {
  local responder_ip
  responder_ip="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bootroot-http01)"
  [ -n "${responder_ip:-}" ] || fail "Failed to resolve responder container IP"
  docker exec bootroot-ca sh -c \
    "printf '%s %s\n' '$responder_ip' '${INSTANCE_ID}.${SERVICE_NAME}.${HOSTNAME}.${DOMAIN}' >> /etc/hosts"
  docker exec bootroot-ca sh -c \
    "printf '%s %s\n' '$responder_ip' '${INSTANCE_ID_2}.${SERVICE_NAME_2}.${HOSTNAME_2}.${DOMAIN}' >> /etc/hosts"
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
  local agent_bin_dir
  agent_bin_dir="$(dirname "$BOOTROOT_AGENT_BIN")"
  for attempt in $(seq 1 "$VERIFY_ATTEMPTS"); do
    if PATH="${agent_bin_dir}:$PATH" run_bootroot_control verify --service-name "$service" --agent-config "$agent_config" >>"$RUN_LOG" 2>&1; then
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
  run_bootroot_control rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    approle-secret-id \
    --service-name "$SERVICE_NAME_2" >>"$RUN_LOG" 2>&1
}

run_rotation_eab() {
  log_phase "rotate-eab"
  local kid hmac payload
  kid="remote-kid-$(date +%s)"
  hmac="remote-hmac-$(date +%s)"
  payload="$(jq -n --arg kid "$kid" --arg hmac "$hmac" '{data:{kid:$kid,hmac:$hmac}}')"
  openbao_write_service_kv "$SERVICE_KV_PATH_BASE" "eab" "$payload"
  openbao_write_service_kv "$SERVICE_KV_PATH_BASE_2" "eab" "$payload"
}

run_rotation_trust_sync() {
  log_phase "rotate-trust-sync"
  local current_trust_json extra_fingerprint ca_bundle_pem payload
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
  extra_fingerprint="$(openssl rand -hex 32)"
  ca_bundle_pem="$(cat "$REMOTE_CERTS_DIR/ca-bundle.pem")"
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
  ensure_compose_images
  configure_resolution_mode
  compose_down
  reset_stepca_materials_for_e2e
  prepare_test_ca_materials

  run_bootstrap_chain
  copy_remote_bootstrap_materials "$SERVICE_NAME"
  copy_remote_bootstrap_materials "$SERVICE_NAME_2"
  wire_stepca_hosts
  wait_for_stepca_http01_targets

  log_phase "bootstrap-initial"
  run_remote_bootstrap "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"
  run_remote_bootstrap "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2" "$HOSTNAME_2" "$INSTANCE_ID_2"

  run_verify_pair "initial"

  run_rotation_secret_id
  log_phase "bootstrap-after-secret-id"
  run_remote_bootstrap "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"
  run_remote_bootstrap "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2" "$HOSTNAME_2" "$INSTANCE_ID_2"
  force_reissue_remote_service "$SERVICE_NAME"
  force_reissue_remote_service "$SERVICE_NAME_2"
  run_verify_pair "after-secret-id"
  assert_fingerprint_changed "$SERVICE_NAME" "initial" "after-secret-id"
  assert_fingerprint_changed "$SERVICE_NAME_2" "initial" "after-secret-id"

  run_rotation_eab
  log_phase "bootstrap-after-eab"
  run_remote_bootstrap "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"
  run_remote_bootstrap "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2" "$HOSTNAME_2" "$INSTANCE_ID_2"
  force_reissue_remote_service "$SERVICE_NAME"
  force_reissue_remote_service "$SERVICE_NAME_2"
  run_verify_pair "after-eab"
  assert_fingerprint_changed "$SERVICE_NAME" "after-secret-id" "after-eab"
  assert_fingerprint_changed "$SERVICE_NAME_2" "after-secret-id" "after-eab"

  run_rotation_trust_sync
  log_phase "bootstrap-after-trust-sync"
  run_remote_bootstrap "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"
  run_remote_bootstrap "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2" "$HOSTNAME_2" "$INSTANCE_ID_2"
  force_reissue_remote_service "$SERVICE_NAME"
  force_reissue_remote_service "$SERVICE_NAME_2"
  run_verify_pair "after-trust-sync"
  assert_fingerprint_changed "$SERVICE_NAME" "after-eab" "after-trust-sync"
  assert_fingerprint_changed "$SERVICE_NAME_2" "after-eab" "after-trust-sync"

  run_rotation_responder_hmac
  log_phase "bootstrap-after-responder-hmac"
  run_remote_bootstrap "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"
  run_remote_bootstrap "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2" "$HOSTNAME_2" "$INSTANCE_ID_2"
  force_reissue_remote_service "$SERVICE_NAME"
  force_reissue_remote_service "$SERVICE_NAME_2"
  run_verify_pair "after-responder-hmac"
  assert_fingerprint_changed "$SERVICE_NAME" "after-trust-sync" "after-responder-hmac"
  assert_fingerprint_changed "$SERVICE_NAME_2" "after-trust-sync" "after-responder-hmac"
}

main "$@"
