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
RUNNER_TICKS_FILE="$ARTIFACT_DIR/runner-ticks.log"
RUNNER_LOG="$ARTIFACT_DIR/runner.log"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
MANIFEST_FILE="$ARTIFACT_DIR/manifest.json"
RUNNER_PID_FILE="$ARTIFACT_DIR/runner.pid"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"
COMPOSE_TEST_FILE="$ROOT_DIR/docker-compose.test.yml"
COMPOSE_SERVICES="openbao postgres step-ca bootroot-http01"

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

main() {
  ensure_compose
  mkdir -p "$ARTIFACT_DIR"
  : >"$RUNNER_TICKS_FILE"
  : >"$RUNNER_LOG"
  : >"$PHASE_LOG"

  trap cleanup EXIT

  log_phase "bootstrap" "control-plane" "all"
  compose_up

  log_phase "runner-start" "service-node-01" "edge-proxy"
  local sync_command
  sync_command="printf '{\"tick\":%s}\n' \"\$(date +%s)\" >> '$RUNNER_TICKS_FILE'"
  SCENARIO_ID="$SCENARIO_ID" \
  NODE_ID="service-node-01" \
  SERVICE_ID="edge-proxy" \
  INTERVAL_SECS="$INTERVAL_SECS" \
  MAX_CYCLES="$MAX_CYCLES" \
  RUNNER_LOG="$RUNNER_LOG" \
  SYNC_COMMAND="$sync_command" \
  "$ROOT_DIR/scripts/e2e/docker/sync-runner-loop.sh" &
  local runner_pid="$!"
  printf "%s" "$runner_pid" >"$RUNNER_PID_FILE"

  log_phase "sync-loop" "service-node-01" "edge-proxy"
  if ! wait_for_runner_cycles; then
    printf "runner did not complete expected cycles\n" >&2
    exit 1
  fi

  log_phase "ack" "control-plane" "edge-proxy"
  log_phase "verify" "service-node-01" "edge-proxy"

  cat >"$MANIFEST_FILE" <<EOF
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
EOF
}

main "$@"
