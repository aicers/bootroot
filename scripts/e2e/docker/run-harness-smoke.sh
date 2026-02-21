#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

SCENARIO_ID="${SCENARIO_ID:-docker-harness-smoke}"
PROJECT_NAME="${PROJECT_NAME:-bootroot-e2e-smoke-$$}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-smoke-$PROJECT_NAME}"
MAX_CYCLES="${MAX_CYCLES:-3}"
TIMEOUT_SECS="${TIMEOUT_SECS:-30}"
SERVICE_NAME="${SERVICE_NAME:-edge-proxy}"
RUNNER_MODE="${RUNNER_MODE:-systemd-timer}"
WORK_DIR="$ARTIFACT_DIR/service-node"
RUNNER_LOG="$ARTIFACT_DIR/runner.log"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
MANIFEST_FILE="$ARTIFACT_DIR/manifest.json"
MOCK_OPENBAO_PID_FILE="$ARTIFACT_DIR/mock-openbao.pid"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
COMPOSE_TEST_FILE="$ROOT_DIR/docker-compose.test.yml"
COMPOSE_SERVICES="openbao postgres step-ca bootroot-http01"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"
MOCK_OPENBAO_PORT="${MOCK_OPENBAO_PORT:-18200}"

BOOTSTRAP_OUTPUT="$ARTIFACT_DIR/bootstrap-output.json"

log_phase() {
  local phase="$1"
  local node="$2"
  local service="$3"
  local cycle="${4:-0}"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"ts":"%s","phase":"%s","scenario":"%s","node":"%s","service":"%s","cycle":%s}\n' \
    "$now" "$phase" "$SCENARIO_ID" "$node" "$service" "$cycle" >>"$PHASE_LOG"
}

ensure_compose() {
  if docker compose version >/dev/null 2>&1; then
    return 0
  fi
  printf "docker compose is required\n" >&2
  exit 1
}

ensure_bins() {
  if [ ! -x "$BOOTROOT_BIN" ]; then
    printf "bootroot binary not executable: %s\n" "$BOOTROOT_BIN" >&2
    exit 1
  fi
  if [ ! -x "$BOOTROOT_REMOTE_BIN" ]; then
    printf "bootroot-remote binary not executable: %s\n" "$BOOTROOT_REMOTE_BIN" >&2
    exit 1
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    printf "python3 is required for mock OpenBao server\n" >&2
    exit 1
  fi
  if ! command -v curl >/dev/null 2>&1; then
    printf "curl is required for mock OpenBao health checks\n" >&2
    exit 1
  fi
}

compose_up() {
  docker compose \
    -p "$PROJECT_NAME" \
    -f "$COMPOSE_FILE" \
    -f "$COMPOSE_TEST_FILE" \
    up -d $COMPOSE_SERVICES
}

compose_down() {
  docker compose \
    -p "$PROJECT_NAME" \
    -f "$COMPOSE_FILE" \
    -f "$COMPOSE_TEST_FILE" \
    down -v --remove-orphans >/dev/null 2>&1 || true
}

capture_artifacts() {
  docker compose \
    -p "$PROJECT_NAME" \
    -f "$COMPOSE_FILE" \
    -f "$COMPOSE_TEST_FILE" \
    ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true

  docker compose \
    -p "$PROJECT_NAME" \
    -f "$COMPOSE_FILE" \
    -f "$COMPOSE_TEST_FILE" \
    logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true

  cp -f "$WORK_DIR/state.json" "$ARTIFACT_DIR/state-final.json" 2>/dev/null || true
  cp -f "$BOOTSTRAP_OUTPUT" "$ARTIFACT_DIR/summary-final.json" 2>/dev/null || true
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

cleanup() {
  log_phase "cleanup" "control-plane" "all"
  if [ -f "$MOCK_OPENBAO_PID_FILE" ]; then
    local mock_pid
    mock_pid="$(cat "$MOCK_OPENBAO_PID_FILE")"
    kill "$mock_pid" >/dev/null 2>&1 || true
    wait "$mock_pid" 2>/dev/null || true
  fi
  capture_artifacts
  compose_down
}

run_bootstrap() {
  local cycle="$1"
  log_phase "bootstrap" "service-node-01" "$SERVICE_NAME" "$cycle"
  local role_id_path="$WORK_DIR/secrets/services/$SERVICE_NAME/role_id"
  local secret_id_path="$WORK_DIR/secrets/services/$SERVICE_NAME/secret_id"
  local eab_file_path="$WORK_DIR/secrets/services/$SERVICE_NAME/eab.json"
  local agent_config_path="$WORK_DIR/agent.toml"
  local ca_bundle_path="$WORK_DIR/certs/ca-bundle.pem"
  (
    cd "$WORK_DIR"
    "$BOOTROOT_REMOTE_BIN" bootstrap \
      --openbao-url "http://127.0.0.1:$MOCK_OPENBAO_PORT" \
      --service-name "$SERVICE_NAME" \
      --role-id-path "$role_id_path" \
      --secret-id-path "$secret_id_path" \
      --eab-file-path "$eab_file_path" \
      --agent-config-path "$agent_config_path" \
      --ca-bundle-path "$ca_bundle_path" \
      --output json
  ) >"$BOOTSTRAP_OUTPUT" 2>>"$RUNNER_LOG"
}

assert_bootstrap_applied() {
  local output_file="$1"
  python3 - "$output_file" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
for key in ["secret_id", "eab", "responder_hmac", "trust_sync"]:
    status = data[key]["status"]
    if status not in ("applied", "unchanged"):
        raise SystemExit(f"bootstrap status mismatch for {key}: {status}")
PY
}

run_verify() {
  (
    cd "$WORK_DIR"
    PATH="$WORK_DIR/bin:$PATH" \
      "$BOOTROOT_BIN" verify \
        --service-name "$SERVICE_NAME" \
        --agent-config "agent.toml" \
        >/dev/null
  )
}

main() {
  ensure_compose
  ensure_bins
  mkdir -p "$ARTIFACT_DIR"
  : >"$RUNNER_LOG"
  : >"$PHASE_LOG"

  trap cleanup EXIT

  log_phase "bootstrap" "control-plane" "all"
  compose_up

  "$ROOT_DIR/scripts/e2e/docker/bootstrap-smoke-node.sh" "$WORK_DIR"

  SERVICE_NAME="$SERVICE_NAME" MOCK_OPENBAO_PORT="$MOCK_OPENBAO_PORT" \
    python3 "$ROOT_DIR/scripts/e2e/docker/mock-openbao-server.py" >/dev/null 2>&1 &
  printf "%s" "$!" >"$MOCK_OPENBAO_PID_FILE"
  if ! wait_for_mock_openbao; then
    printf "mock OpenBao did not become healthy\n" >&2
    exit 1
  fi

  local cycle
  for cycle in $(seq 1 "$MAX_CYCLES"); do
    run_bootstrap "$cycle"
  done

  assert_bootstrap_applied "$BOOTSTRAP_OUTPUT"

  log_phase "verify" "service-node-01" "$SERVICE_NAME"
  run_verify

  cat >"$MANIFEST_FILE" <<JSON
{
  "scenario": "$SCENARIO_ID",
  "project": "$PROJECT_NAME",
  "artifact_dir": "$ARTIFACT_DIR",
  "runner_mode": "$RUNNER_MODE",
  "topology": {
    "control_plane": 1,
    "service_nodes": 1,
    "services": {
      "daemon": 1,
      "docker": 0
    }
  },
  "runner": {
    "max_cycles": $MAX_CYCLES
  }
}
JSON
}

main "$@"
