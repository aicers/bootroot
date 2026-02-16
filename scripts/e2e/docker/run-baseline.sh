#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

DEFAULT_SCENARIO_FILE="$ROOT_DIR/tests/e2e/docker_harness/scenarios/scenario-a-single-node-mixed.json"
SCENARIO_FILE="${SCENARIO_FILE:-$DEFAULT_SCENARIO_FILE}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-baseline-$(date +%s)}"
PROJECT_NAME="${PROJECT_NAME:-bootroot-e2e-baseline-$$}"
INTERVAL_SECS="${INTERVAL_SECS:-1}"
MAX_CYCLES="${MAX_CYCLES:-2}"
TIMEOUT_SECS="${TIMEOUT_SECS:-45}"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
COMPOSE_TEST_FILE="$ROOT_DIR/docker-compose.test.yml"
COMPOSE_SERVICES="openbao postgres step-ca bootroot-http01"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"
MOCK_OPENBAO_PORT="${MOCK_OPENBAO_PORT:-18200}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUNNER_LOG="$ARTIFACT_DIR/runner.log"
SERVICES_TSV="$ARTIFACT_DIR/services.tsv"
RUNNER_PIDS_FILE="$ARTIFACT_DIR/runner-pids.txt"
SCENARIO_ID=""
LAST_PHASE="init"
LAST_NODE="n/a"
LAST_SERVICE="n/a"
LAST_PATHS=""
MOCK_OPENBAO_PID=""

set_context() {
  LAST_PHASE="$1"
  LAST_NODE="$2"
  LAST_SERVICE="$3"
  LAST_PATHS="${4:-}"
}

log_phase() {
  local phase="$1"
  local node="$2"
  local service="$3"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"ts":"%s","phase":"%s","scenario":"%s","node":"%s","service":"%s"}\n' \
    "$now" "$phase" "$SCENARIO_ID" "$node" "$service" >>"$PHASE_LOG"
}

fail_with_context() {
  local message="$1"
  printf '%s\n' "$message" >&2
  printf 'failure_context: phase=%s node=%s service=%s paths=%s\n' \
    "$LAST_PHASE" "$LAST_NODE" "$LAST_SERVICE" "$LAST_PATHS" >&2
  exit 1
}

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail_with_context "docker is required"
  docker compose version >/dev/null 2>&1 || fail_with_context "docker compose is required"
  command -v python3 >/dev/null 2>&1 || fail_with_context "python3 is required"
  command -v curl >/dev/null 2>&1 || fail_with_context "curl is required"
  [ -x "$BOOTROOT_BIN" ] || fail_with_context "bootroot binary not executable: $BOOTROOT_BIN"
  [ -x "$BOOTROOT_REMOTE_BIN" ] || fail_with_context "bootroot-remote binary not executable: $BOOTROOT_REMOTE_BIN"
}

compose_up() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" up -d $COMPOSE_SERVICES
}

compose_down() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}

capture_artifacts() {
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
  docker compose -p "$PROJECT_NAME" -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
}

wait_for_mock_openbao() {
  local health_url
  health_url="http://127.0.0.1:$MOCK_OPENBAO_PORT/v1/sys/health"
  local start
  start="$(date +%s)"
  while true; do
    if curl -fsS "$health_url" >/dev/null 2>&1; then
      return 0
    fi
    if [ $(( $(date +%s) - start )) -ge "$TIMEOUT_SECS" ]; then
      return 1
    fi
    sleep 1
  done
}

generate_workspace() {
  python3 "$ROOT_DIR/scripts/e2e/docker/generate-baseline-workspace.py" \
    --scenario-file "$SCENARIO_FILE" \
    --artifact-dir "$ARTIFACT_DIR"

  SCENARIO_ID="$(python3 - "$ARTIFACT_DIR/layout.json" <<'PY'
import json
import sys
with open(sys.argv[1], encoding='utf-8') as fh:
    layout = json.load(fh)
print(layout['scenario_id'])
PY
)"

  python3 - "$ARTIFACT_DIR/layout.json" >"$SERVICES_TSV" <<'PY'
import json
import sys
with open(sys.argv[1], encoding='utf-8') as fh:
    layout = json.load(fh)
for svc in layout['services']:
    fields = [
        svc['node_id'],
        svc['service_name'],
        svc['work_dir'],
        svc['role_id_path'],
        svc['secret_id_path'],
        svc['eab_file_path'],
        svc['agent_config_path'],
        svc['ca_bundle_path'],
        svc['summary_json_path'],
        svc['state_path'],
        svc['deploy_type'],
    ]
    print("\t".join(fields))
PY
}

start_mock_openbao() {
  python3 "$ROOT_DIR/scripts/e2e/docker/mock-openbao-server.py" >/dev/null 2>&1 &
  MOCK_OPENBAO_PID="$!"
  if ! wait_for_mock_openbao; then
    fail_with_context "mock OpenBao did not become healthy"
  fi
}

start_runners() {
  mkdir -p "$ARTIFACT_DIR/ticks"
  : >"$RUNNER_PIDS_FILE"
  while IFS=$'\t' read -r node service work_dir role_id_path secret_id_path eab_file_path agent_config_path ca_bundle_path summary_json_path state_path deploy_type; do
    local tick_file
    tick_file="$ARTIFACT_DIR/ticks/${node}__${service}.log"
    : >"$tick_file"
    set_context "runner-start" "$node" "$service" "$state_path"
    log_phase "runner-start" "$node" "$service"

    local sync_command
    sync_command="WORK_DIR='$work_dir' SERVICE_NAME='$service' BOOTROOT_REMOTE_BIN='$BOOTROOT_REMOTE_BIN' BOOTROOT_BIN='$BOOTROOT_BIN' OPENBAO_URL='http://127.0.0.1:$MOCK_OPENBAO_PORT' ROLE_ID_PATH='$role_id_path' SECRET_ID_PATH='$secret_id_path' EAB_FILE_PATH='$eab_file_path' AGENT_CONFIG_PATH='$agent_config_path' CA_BUNDLE_PATH='$ca_bundle_path' SUMMARY_JSON_PATH='$summary_json_path' TICK_FILE='$tick_file' '$ROOT_DIR/scripts/e2e/docker/run-sync-once.sh'"

    SCENARIO_ID="$SCENARIO_ID" \
    NODE_ID="$node" \
    SERVICE_ID="$service" \
    INTERVAL_SECS="$INTERVAL_SECS" \
    MAX_CYCLES="$MAX_CYCLES" \
    RUNNER_LOG="$RUNNER_LOG" \
    SYNC_COMMAND="$sync_command" \
    "$ROOT_DIR/scripts/e2e/docker/sync-runner-loop.sh" &

    printf '%s\t%s\t%s\t%s\n' "$!" "$tick_file" "$node" "$service" >>"$RUNNER_PIDS_FILE"
  done <"$SERVICES_TSV"
}

wait_for_runners() {
  local start
  start="$(date +%s)"
  while IFS=$'\t' read -r pid tick_file node service; do
    while true; do
      local line_count
      line_count=0
      if [ -f "$tick_file" ]; then
        line_count="$(wc -l <"$tick_file" | tr -d ' ')"
      fi
      if [ "$line_count" -ge "$MAX_CYCLES" ]; then
        set_context "sync-loop" "$node" "$service" "$tick_file"
        log_phase "sync-loop" "$node" "$service"
        break
      fi
      if [ $(( $(date +%s) - start )) -ge "$TIMEOUT_SECS" ]; then
        fail_with_context "runner did not complete expected cycles"
      fi
      sleep 1
    done
    if ! wait "$pid"; then
      fail_with_context "sync runner failed"
    fi
  done <"$RUNNER_PIDS_FILE"
}

assert_state_and_isolation() {
  python3 - "$SERVICES_TSV" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

services = []
for line in Path(sys.argv[1]).read_text(encoding='utf-8').splitlines():
    if not line.strip():
        continue
    node, service, work_dir, role_id_path, secret_id_path, eab_file_path, agent_config_path, ca_bundle_path, summary_json_path, state_path, deploy_type = line.split('\t')
    services.append(
        {
            "node": node,
            "service": service,
            "work_dir": Path(work_dir),
            "secret_id_path": Path(secret_id_path),
            "eab_file_path": Path(eab_file_path),
            "agent_config_path": Path(agent_config_path),
            "ca_bundle_path": Path(ca_bundle_path),
            "summary_json_path": Path(summary_json_path),
            "state_path": Path(state_path),
        }
    )

secret_paths = set()
eab_paths = set()
config_paths = set()
for item in services:
    service = item["service"]
    state = json.loads(item["state_path"].read_text(encoding='utf-8'))
    entry = state["services"][service]
    expected = {
        "secret_id": "applied",
        "eab": "applied",
        "responder_hmac": "applied",
        "trust_sync": "applied",
    }
    for key, value in expected.items():
        actual = entry["sync_status"][key]
        if actual != value:
            raise SystemExit(f"sync_status mismatch for {service}:{key} => {actual}")
    if entry["delivery_mode"] != "remote-bootstrap":
        raise SystemExit(f"delivery_mode mismatch for {service}: {entry['delivery_mode']}")

    secret_value = item["secret_id_path"].read_text(encoding='utf-8').strip()
    if secret_value != f"synced-secret-id-{service}":
        raise SystemExit(f"secret_id mismatch for {service}: {secret_value}")

    eab = json.loads(item["eab_file_path"].read_text(encoding='utf-8'))
    if eab.get("kid") != f"synced-kid-{service}" or eab.get("hmac") != f"synced-hmac-{service}":
        raise SystemExit(f"eab mismatch for {service}")

    agent_config = item["agent_config_path"].read_text(encoding='utf-8')
    expected_hmac = f"synced-responder-hmac-{service}"
    if expected_hmac not in agent_config:
        raise SystemExit(f"responder hmac missing in agent config for {service}")
    expected_fp = hashlib.sha256(service.encode('utf-8')).hexdigest()
    if expected_fp not in agent_config:
        raise SystemExit(f"trusted_ca_sha256 missing in agent config for {service}")

    ca_bundle_contents = item["ca_bundle_path"].read_text(encoding='utf-8')
    if f"SMOKE-{service}" not in ca_bundle_contents:
        raise SystemExit(f"ca_bundle mismatch for {service}")

    summary = json.loads(item["summary_json_path"].read_text(encoding='utf-8'))
    for key in ["secret_id", "eab", "responder_hmac", "trust_sync"]:
        status = summary[key]["status"]
        if status not in ("applied", "unchanged"):
            raise SystemExit(f"summary status mismatch for {service}:{key} => {status}")

    secret_paths.add(str(item["secret_id_path"]))
    eab_paths.add(str(item["eab_file_path"]))
    config_paths.add(str(item["agent_config_path"]))

if len(secret_paths) != len(services):
    raise SystemExit("secret_id path collision detected")
if len(eab_paths) != len(services):
    raise SystemExit("eab path collision detected")
if len(config_paths) != len(services):
    raise SystemExit("agent_config path collision detected")
PY
}

run_verify_all() {
  while IFS=$'\t' read -r node service work_dir role_id_path secret_id_path eab_file_path agent_config_path ca_bundle_path summary_json_path state_path deploy_type; do
    set_context "verify" "$node" "$service" "$agent_config_path"
    log_phase "verify" "$node" "$service"
    (
      cd "$work_dir"
      PATH="$work_dir/bin:$PATH" \
      "$BOOTROOT_BIN" verify \
        --service-name "$service" \
        --agent-config "$agent_config_path" \
        >/dev/null
    )
  done <"$SERVICES_TSV"
}

cleanup() {
  if [ -f "$RUNNER_PIDS_FILE" ]; then
    while IFS=$'\t' read -r pid tick_file node service; do
      kill "$pid" >/dev/null 2>&1 || true
      wait "$pid" 2>/dev/null || true
      log_phase "cleanup" "$node" "$service"
    done <"$RUNNER_PIDS_FILE"
  fi

  if [ -n "$MOCK_OPENBAO_PID" ]; then
    kill "$MOCK_OPENBAO_PID" >/dev/null 2>&1 || true
    wait "$MOCK_OPENBAO_PID" 2>/dev/null || true
  fi

  capture_artifacts
  compose_down
}

main() {
  mkdir -p "$ARTIFACT_DIR"
  : >"$PHASE_LOG"
  : >"$RUNNER_LOG"

  trap cleanup EXIT

  ensure_prerequisites
  generate_workspace

  while IFS=$'\t' read -r node service work_dir role_id_path secret_id_path eab_file_path agent_config_path ca_bundle_path summary_json_path state_path deploy_type; do
    set_context "bootstrap" "$node" "$service" "$state_path"
    log_phase "bootstrap" "$node" "$service"
  done <"$SERVICES_TSV"

  compose_up
  start_mock_openbao
  start_runners
  wait_for_runners

  while IFS=$'\t' read -r node service work_dir role_id_path secret_id_path eab_file_path agent_config_path ca_bundle_path summary_json_path state_path deploy_type; do
    set_context "ack" "$node" "$service" "$summary_json_path"
    log_phase "ack" "$node" "$service"
  done <"$SERVICES_TSV"

  assert_state_and_isolation
  run_verify_all

  cp -f "$ARTIFACT_DIR/layout.json" "$ARTIFACT_DIR/layout-final.json"
}

main "$@"
