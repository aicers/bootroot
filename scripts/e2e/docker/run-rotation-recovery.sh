#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

DEFAULT_SCENARIO_FILE="$ROOT_DIR/tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json"
SCENARIO_FILE="${SCENARIO_FILE:-$DEFAULT_SCENARIO_FILE}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-rotation-$(date +%s)}"
PROJECT_NAME="${PROJECT_NAME:-bootroot-e2e-rotation-$$}"
TIMEOUT_SECS="${TIMEOUT_SECS:-60}"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
COMPOSE_TEST_FILE="$ROOT_DIR/docker-compose.test.yml"
COMPOSE_SERVICES="openbao postgres step-ca bootroot-http01"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"
MOCK_OPENBAO_PORT="${MOCK_OPENBAO_PORT:-18200}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUNNER_LOG="$ARTIFACT_DIR/runner.log"
SERVICES_TSV="$ARTIFACT_DIR/services.tsv"
SCENARIO_ID=""
LAST_PHASE="init"
LAST_NODE="n/a"
LAST_SERVICE="n/a"
LAST_PATHS=""
EXPECTED_TRANSITION=""
OBSERVED_TRANSITION=""
MOCK_OPENBAO_PID=""

ROTATION_ITEMS_CSV="${ROTATION_ITEMS:-secret_id,eab,responder_hmac,trust_sync}"
IFS=',' read -r -a ITEMS <<<"$ROTATION_ITEMS_CSV"

set_context() {
  LAST_PHASE="$1"
  LAST_NODE="$2"
  LAST_SERVICE="$3"
  LAST_PATHS="${4:-}"
}

set_transition() {
  EXPECTED_TRANSITION="$1"
  OBSERVED_TRANSITION="$2"
}

log_phase() {
  local phase="$1"
  local node="$2"
  local service="$3"
  local cycle="$4"
  local item="$5"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"ts":"%s","phase":"%s","scenario":"%s","node":"%s","service":"%s","cycle":%s,"rotation_item":"%s"}\n' \
    "$now" "$phase" "$SCENARIO_ID" "$node" "$service" "$cycle" "$item" >>"$PHASE_LOG"
}

fail_with_context() {
  local message="$1"
  printf '%s\n' "$message" >&2
  printf 'failure_context: phase=%s node=%s service=%s paths=%s expected=%s observed=%s\n' \
    "$LAST_PHASE" "$LAST_NODE" "$LAST_SERVICE" "$LAST_PATHS" "$EXPECTED_TRANSITION" "$OBSERVED_TRANSITION" >&2
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

snapshot_state() {
  local label="$1"
  mkdir -p "$ARTIFACT_DIR/snapshots/$label"
  while IFS=$'\t' read -r node service work_dir role_id_path secret_id_path eab_file_path agent_config_path ca_bundle_path summary_json_path state_path deploy_type; do
    cp -f "$state_path" "$ARTIFACT_DIR/snapshots/$label/state-${node}-${service}.json" 2>/dev/null || true
    cp -f "$summary_json_path" "$ARTIFACT_DIR/snapshots/$label/summary-${node}-${service}.json" 2>/dev/null || true
  done <"$SERVICES_TSV"
}

wait_for_mock_openbao() {
  local health_url="http://127.0.0.1:$MOCK_OPENBAO_PORT/v1/sys/health"
  local start="$(date +%s)"
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
import json, sys
with open(sys.argv[1], encoding='utf-8') as fh:
    layout = json.load(fh)
print(layout['scenario_id'])
PY
)"

  python3 - "$ARTIFACT_DIR/layout.json" >"$SERVICES_TSV" <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as fh:
    layout = json.load(fh)
for svc in layout['services']:
    fields = [svc['node_id'], svc['service_name'], svc['work_dir'], svc['role_id_path'], svc['secret_id_path'], svc['eab_file_path'], svc['agent_config_path'], svc['ca_bundle_path'], svc['summary_json_path'], svc['state_path'], svc['deploy_type']]
    print("\t".join(fields))
PY
}

control_mock() {
  local action="$1"
  local payload="$2"
  curl -fsS -X POST "http://127.0.0.1:$MOCK_OPENBAO_PORT/control/$action" \
    -H 'Content-Type: application/json' \
    -d "$payload" >/dev/null
}

start_mock_openbao() {
  python3 "$ROOT_DIR/scripts/e2e/docker/mock-openbao-server.py" >/dev/null 2>&1 &
  MOCK_OPENBAO_PID="$!"
  wait_for_mock_openbao || fail_with_context "mock OpenBao did not become healthy"
}

bootstrap_all() {
  local cycle="$1"
  local item="$2"
  while IFS=$'\t' read -r node service work_dir role_id_path secret_id_path eab_file_path agent_config_path ca_bundle_path summary_json_path state_path deploy_type; do
    set_context "bootstrap" "$node" "$service" "$work_dir"
    log_phase "bootstrap" "$node" "$service" "$cycle" "$item"
    local output_file="$ARTIFACT_DIR/bootstrap-output-${node}-${service}.json"
    (
      cd "$work_dir"
      "$BOOTROOT_REMOTE_BIN" bootstrap \
        --openbao-url "http://127.0.0.1:$MOCK_OPENBAO_PORT" \
        --service-name "$service" \
        --role-id-path "$role_id_path" \
        --secret-id-path "$secret_id_path" \
        --eab-file-path "$eab_file_path" \
        --agent-config-path "$agent_config_path" \
        --ca-bundle-path "$ca_bundle_path" \
        --output json
    ) >"$output_file" 2>>"$RUNNER_LOG" || true
  done <"$SERVICES_TSV"
}

assert_bootstrap_status() {
  local item="$1"
  local expected="$2"
  local service_filter="${3:-}"
  python3 - "$SERVICES_TSV" "$ARTIFACT_DIR" "$item" "$expected" "$service_filter" <<'PY'
import json
import sys
from pathlib import Path

_, tsv_path, artifact_dir, item, expected, service_filter = sys.argv
artifact = Path(artifact_dir)
for line in Path(tsv_path).read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    parts = line.split("\t")
    node, service = parts[0], parts[1]
    if service_filter and service != service_filter:
        continue
    output_file = artifact / f"bootstrap-output-{node}-{service}.json"
    if not output_file.exists():
        raise SystemExit(f"no bootstrap output for {service} (expected {expected})")
    text = output_file.read_text(encoding="utf-8").strip()
    if not text:
        raise SystemExit(f"empty bootstrap output for {service} (expected {expected})")
    data = json.loads(text)
    actual = data[item]["status"]
    if actual != expected:
        raise SystemExit(
            f"status mismatch for {service}:{item} expected={expected} actual={actual}"
        )
PY
}

assert_bootstrap_other_not_failed() {
  local item="$1"
  local excluded_service="$2"
  python3 - "$SERVICES_TSV" "$ARTIFACT_DIR" "$item" "$excluded_service" <<'PY'
import json
import sys
from pathlib import Path

_, tsv_path, artifact_dir, item, excluded = sys.argv
artifact = Path(artifact_dir)
for line in Path(tsv_path).read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    parts = line.split("\t")
    node, service = parts[0], parts[1]
    if service == excluded:
        continue
    output_file = artifact / f"bootstrap-output-{node}-{service}.json"
    if not output_file.exists():
        raise SystemExit(f"no bootstrap output for {service}")
    text = output_file.read_text(encoding="utf-8").strip()
    if not text:
        raise SystemExit(f"empty bootstrap output for {service}")
    data = json.loads(text)
    actual = data[item]["status"]
    if actual == "failed":
        raise SystemExit(f"unexpected failed status for {service}:{item}")
PY
}

assert_bootstrap_failed() {
  local service_name="$1"
  python3 - "$SERVICES_TSV" "$ARTIFACT_DIR" "$service_name" <<'PY'
import json
import sys
from pathlib import Path

_, tsv_path, artifact_dir, target = sys.argv
artifact = Path(artifact_dir)
found = False
for line in Path(tsv_path).read_text(encoding="utf-8").splitlines():
    if not line.strip():
        continue
    parts = line.split("\t")
    node, service = parts[0], parts[1]
    if service != target:
        continue
    found = True
    output_file = artifact / f"bootstrap-output-{node}-{service}.json"
    if output_file.exists() and output_file.read_text(encoding="utf-8").strip():
        data = json.loads(output_file.read_text(encoding="utf-8"))
        has_failure = any(
            v.get("status") == "failed"
            for v in data.values()
            if isinstance(v, dict)
        )
        if not has_failure:
            raise SystemExit(
                f"expected bootstrap failure for {service} but all items succeeded"
            )
    # Empty or absent output means bootstrap failed before producing JSON
    break
if not found:
    raise SystemExit(f"service {target} not found in services")
PY
}

set_versions_all() {
  local mock_item="$1"
  local version="$2"
  while IFS=$'\t' read -r node service work_dir role_id_path secret_id_path eab_file_path agent_config_path ca_bundle_path summary_json_path state_path deploy_type; do
    control_mock "set-version" "{\"service\":\"$service\",\"item\":\"$mock_item\",\"version\":$version}"
  done <"$SERVICES_TSV"
}

run_verify_all() {
  local cycle="$1"
  local item="$2"
  while IFS=$'\t' read -r node service work_dir role_id_path secret_id_path eab_file_path agent_config_path ca_bundle_path summary_json_path state_path deploy_type; do
    set_context "renew" "$node" "$service" "$agent_config_path"
    log_phase "renew" "$node" "$service" "$cycle" "$item"
    set_context "verify" "$node" "$service" "$agent_config_path"
    log_phase "verify" "$node" "$service" "$cycle" "$item"
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
  if [ -n "$MOCK_OPENBAO_PID" ]; then
    kill "$MOCK_OPENBAO_PID" >/dev/null 2>&1 || true
    wait "$MOCK_OPENBAO_PID" 2>/dev/null || true
  fi
  while IFS=$'\t' read -r node service work_dir role_id_path secret_id_path eab_file_path agent_config_path ca_bundle_path summary_json_path state_path deploy_type; do
    log_phase "cleanup" "$node" "$service" 0 "all"
  done <"$SERVICES_TSV" 2>/dev/null || true
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
    log_phase "bootstrap" "$node" "$service" 0 "all"
  done <"$SERVICES_TSV"

  compose_up
  start_mock_openbao
  run_verify_all 0 "none"
  snapshot_state "pre-rotation"

  local first_service
  first_service="$(awk -F '\t' 'NR==1{print $2}' "$SERVICES_TSV")"

  for item in "${ITEMS[@]}"; do
    local mock_item
    case "$item" in
      secret_id) mock_item="secret_id" ;;
      eab) mock_item="eab" ;;
      responder_hmac) mock_item="http_responder_hmac" ;;
      trust_sync) mock_item="trust" ;;
      *) fail_with_context "unsupported item $item" ;;
    esac

    # Cycle 1: normal rotation
    log_phase "rotate" "control-plane" "$first_service" 1 "$item"
    set_versions_all "$mock_item" 10
    bootstrap_all 1 "$item"
    set_transition "applied" "cycle1"
    assert_bootstrap_status "$item" "applied"
    run_verify_all 1 "$item"
    snapshot_state "${item}-cycle1"

    # Cycle 2: re-rotation
    log_phase "rotate" "control-plane" "$first_service" 2 "$item"
    set_versions_all "$mock_item" 20
    bootstrap_all 2 "$item"
    set_transition "applied" "cycle2"
    assert_bootstrap_status "$item" "applied"
    run_verify_all 2 "$item"
    snapshot_state "${item}-cycle2"

    # Cycle 3: targeted failure + recovery
    log_phase "rotate" "control-plane" "$first_service" 3 "$item"
    set_versions_all "$mock_item" 30
    control_mock "fail-next" "{\"service\":\"$first_service\",\"item\":\"$mock_item\",\"count\":1}"
    bootstrap_all 3 "$item"
    set_transition "targeted failed + others ok" "cycle3-failure"
    assert_bootstrap_failed "$first_service"
    assert_bootstrap_other_not_failed "$item" "$first_service"

    bootstrap_all 4 "$item"
    set_transition "recovered" "cycle3-recovery"
    assert_bootstrap_status "$item" "applied" "$first_service"
    run_verify_all 4 "$item"
    snapshot_state "${item}-cycle3-recovery"
  done

  # Transient secret_id failure and recovery
  log_phase "rotate" "control-plane" "$first_service" 99 "secret_id"
  set_versions_all "secret_id" 99
  control_mock "fail-next" "{\"service\":\"$first_service\",\"item\":\"secret_id\",\"count\":1}"
  bootstrap_all 99 "secret_id"
  assert_bootstrap_failed "$first_service"

  bootstrap_all 100 "secret_id"
  assert_bootstrap_status "secret_id" "applied" "$first_service"
  snapshot_state "secret-id-transient-recovery"

  cat >"$ARTIFACT_DIR/rotation-manifest.json" <<JSON
{
  "scenario": "$SCENARIO_ID",
  "scenario_file": "$SCENARIO_FILE",
  "rotation_items_csv": "$ROTATION_ITEMS_CSV",
  "cycles": {
    "normal": 1,
    "rerotation": 2,
    "failure_recovery": [3, 4],
    "transient_failure": 99,
    "transient_recovery": 100
  }
}
JSON
}

main "$@"
