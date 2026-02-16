#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

SCENARIO_ID="${SCENARIO_ID:-docker-harness-smoke}"
PROJECT_NAME="${PROJECT_NAME:-bootroot-e2e-smoke-$$}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-smoke-$PROJECT_NAME}"
INTERVAL_SECS="${INTERVAL_SECS:-1}"
MAX_CYCLES="${MAX_CYCLES:-3}"
TIMEOUT_SECS="${TIMEOUT_SECS:-30}"
SERVICE_NAME="${SERVICE_NAME:-edge-proxy}"
WORK_DIR="$ARTIFACT_DIR/service-node"
RUNNER_TICKS_FILE="$ARTIFACT_DIR/runner-ticks.log"
RUNNER_LOG="$ARTIFACT_DIR/runner.log"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
MANIFEST_FILE="$ARTIFACT_DIR/manifest.json"
RUNNER_PID_FILE="$ARTIFACT_DIR/runner.pid"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
COMPOSE_TEST_FILE="$ROOT_DIR/docker-compose.test.yml"
COMPOSE_SERVICES="openbao postgres step-ca bootroot-http01"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"

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
  cp -f "$WORK_DIR/remote-summary.json" "$ARTIFACT_DIR/summary-final.json" 2>/dev/null || true
}

wait_for_runner_cycles() {
  local start
  start="$(date +%s)"
  while true; do
    local line_count
    line_count=0
    if [ -f "$RUNNER_TICKS_FILE" ]; then
      line_count="$(wc -l <"$RUNNER_TICKS_FILE" | tr -d ' ')"
    fi
    if [ "$line_count" -ge "$MAX_CYCLES" ]; then
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
  if [ -f "$RUNNER_PID_FILE" ]; then
    local pid
    pid="$(cat "$RUNNER_PID_FILE")"
    kill "$pid" >/dev/null 2>&1 || true
    wait "$pid" 2>/dev/null || true
  fi
  capture_artifacts
  compose_down
}

assert_state_applied() {
  local state_file="$1"
  grep -q '"secret_id": "applied"' "$state_file"
  grep -q '"eab": "applied"' "$state_file"
  grep -q '"responder_hmac": "applied"' "$state_file"
  grep -q '"trust_sync": "applied"' "$state_file"
}

run_verify() {
  PATH="$WORK_DIR/bin:$PATH" \
    "$BOOTROOT_BIN" verify \
      --service-name "$SERVICE_NAME" \
      --agent-config "$WORK_DIR/agent.toml" \
      >/dev/null
}

main() {
  ensure_compose
  ensure_bins
  mkdir -p "$ARTIFACT_DIR"
  : >"$RUNNER_TICKS_FILE"
  : >"$RUNNER_LOG"
  : >"$PHASE_LOG"

  trap cleanup EXIT

  log_phase "bootstrap" "control-plane" "all"
  compose_up

  "$ROOT_DIR/scripts/e2e/docker/bootstrap-smoke-node.sh" "$WORK_DIR"

  log_phase "runner-start" "service-node-01" "$SERVICE_NAME"
  local sync_command
  sync_command="cd '$WORK_DIR' && '$BOOTROOT_REMOTE_BIN' ack --service-name '$SERVICE_NAME' --summary-json '$WORK_DIR/remote-summary.json' --bootroot-bin '$BOOTROOT_BIN' >/dev/null && printf '{\"tick\":%s}\n' \"\$(date +%s)\" >> '$RUNNER_TICKS_FILE'"
  SCENARIO_ID="$SCENARIO_ID" \
  NODE_ID="service-node-01" \
  SERVICE_ID="$SERVICE_NAME" \
  INTERVAL_SECS="$INTERVAL_SECS" \
  MAX_CYCLES="$MAX_CYCLES" \
  RUNNER_LOG="$RUNNER_LOG" \
  SYNC_COMMAND="$sync_command" \
  "$ROOT_DIR/scripts/e2e/docker/sync-runner-loop.sh" &
  local runner_pid="$!"
  printf "%s" "$runner_pid" >"$RUNNER_PID_FILE"

  log_phase "sync-loop" "service-node-01" "$SERVICE_NAME"
  if ! wait_for_runner_cycles; then
    printf "runner did not complete expected cycles\n" >&2
    exit 1
  fi

  log_phase "ack" "control-plane" "$SERVICE_NAME"
  if ! assert_state_applied "$WORK_DIR/state.json"; then
    printf "state did not converge to applied\n" >&2
    exit 1
  fi

  log_phase "verify" "service-node-01" "$SERVICE_NAME"
  run_verify

  cat >"$MANIFEST_FILE" <<JSON
{
  "scenario": "$SCENARIO_ID",
  "project": "$PROJECT_NAME",
  "artifact_dir": "$ARTIFACT_DIR",
  "topology": {
    "control_plane": 1,
    "service_nodes": 1,
    "services": {
      "daemon": 1,
      "docker": 0
    }
  },
  "runner": {
    "interval_secs": $INTERVAL_SECS,
    "max_cycles": $MAX_CYCLES
  }
}
JSON
}

main "$@"
