#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

SCENARIO_FILE="${SCENARIO_FILE:-$ROOT_DIR/tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-extended-$(date +%s)}"
PROJECT_PREFIX="${PROJECT_PREFIX:-bootroot-e2e-extended}"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"
MAX_CYCLES_SCALE="${MAX_CYCLES_SCALE:-8}"
INTERVAL_SECS_SCALE="${INTERVAL_SECS_SCALE:-1}"
TIMEOUT_SECS_SCALE="${TIMEOUT_SECS_SCALE:-90}"
TIMEOUT_SECS_ROTATION="${TIMEOUT_SECS_ROTATION:-90}"
TIMEOUT_SECS_RUNNER="${TIMEOUT_SECS_RUNNER:-45}"
TIMEOUT_SECS_LIFECYCLE="${TIMEOUT_SECS_LIFECYCLE:-600}"
MAX_CYCLES_RUNNER="${MAX_CYCLES_RUNNER:-4}"
INTERVAL_SECS_RUNNER="${INTERVAL_SECS_RUNNER:-1}"

mkdir -p "$ARTIFACT_DIR"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
SUMMARY_JSON="$ARTIFACT_DIR/extended-summary.json"
: >"$PHASE_LOG"

log_phase() {
  local phase="$1"
  local status="$2"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"ts":"%s","phase":"%s","status":"%s"}\n' "$now" "$phase" "$status" >>"$PHASE_LOG"
}

run_case() {
  local case_id="$1"
  shift
  local case_dir="$ARTIFACT_DIR/$case_id"
  local run_log="$case_dir/run.log"
  mkdir -p "$case_dir"
  log_phase "$case_id" "start"
  if "$@" >"$run_log" 2>&1; then
    log_phase "$case_id" "pass"
    printf '{"case":"%s","status":"pass","artifact_dir":"%s"}\n' "$case_id" "$case_dir"
    return 0
  fi
  log_phase "$case_id" "fail"
  printf '{"case":"%s","status":"fail","artifact_dir":"%s"}\n' "$case_id" "$case_dir"
  return 1
}

case_scale_contention() {
  local case_dir="$ARTIFACT_DIR/scale-contention"
  ARTIFACT_DIR="$case_dir" \
  SCENARIO_FILE="$SCENARIO_FILE" \
  PROJECT_NAME="${PROJECT_PREFIX}-scale-$$" \
  MAX_CYCLES="$MAX_CYCLES_SCALE" \
  INTERVAL_SECS="$INTERVAL_SECS_SCALE" \
  TIMEOUT_SECS="$TIMEOUT_SECS_SCALE" \
  BOOTROOT_BIN="$BOOTROOT_BIN" \
  BOOTROOT_REMOTE_BIN="$BOOTROOT_REMOTE_BIN" \
  "$ROOT_DIR/scripts/impl/run-baseline.sh"
}

case_failure_recovery() {
  local case_dir="$ARTIFACT_DIR/failure-recovery"
  ARTIFACT_DIR="$case_dir" \
  SCENARIO_FILE="$SCENARIO_FILE" \
  PROJECT_NAME="${PROJECT_PREFIX}-recovery-$$" \
  TIMEOUT_SECS="$TIMEOUT_SECS_ROTATION" \
  ROTATION_ITEMS="secret_id,eab,responder_hmac,trust_sync" \
  BOOTROOT_BIN="$BOOTROOT_BIN" \
  BOOTROOT_REMOTE_BIN="$BOOTROOT_REMOTE_BIN" \
  "$ROOT_DIR/scripts/impl/run-rotation-recovery.sh"
}

case_runner_timer() {
  local case_dir="$ARTIFACT_DIR/runner-timer"
  ARTIFACT_DIR="$case_dir" \
  PROJECT_NAME="${PROJECT_PREFIX}-timer-$$" \
  SCENARIO_ID="extended-runner-timer" \
  RUNNER_MODE="systemd-timer" \
  TIMEOUT_SECS="$TIMEOUT_SECS_RUNNER" \
  MAX_CYCLES="$MAX_CYCLES_RUNNER" \
  INTERVAL_SECS="$INTERVAL_SECS_RUNNER" \
  BOOTROOT_BIN="$BOOTROOT_BIN" \
  BOOTROOT_REMOTE_BIN="$BOOTROOT_REMOTE_BIN" \
  "$ROOT_DIR/scripts/impl/run-harness-smoke.sh"
}

case_infra_lifecycle() {
  local case_dir="$ARTIFACT_DIR/infra-lifecycle"
  ARTIFACT_DIR="$case_dir" \
  PROJECT_NAME="${PROJECT_PREFIX}-lifecycle-$$" \
  TIMEOUT_SECS="$TIMEOUT_SECS_LIFECYCLE" \
  BOOTROOT_BIN="$BOOTROOT_BIN" \
  BOOTROOT_REMOTE_BIN="$BOOTROOT_REMOTE_BIN" \
  "$ROOT_DIR/scripts/impl/run-main-lifecycle.sh"
}

case_runner_cron() {
  local case_dir="$ARTIFACT_DIR/runner-cron"
  ARTIFACT_DIR="$case_dir" \
  PROJECT_NAME="${PROJECT_PREFIX}-cron-$$" \
  SCENARIO_ID="extended-runner-cron" \
  RUNNER_MODE="cron" \
  TIMEOUT_SECS="$TIMEOUT_SECS_RUNNER" \
  MAX_CYCLES="$MAX_CYCLES_RUNNER" \
  INTERVAL_SECS="$INTERVAL_SECS_RUNNER" \
  BOOTROOT_BIN="$BOOTROOT_BIN" \
  BOOTROOT_REMOTE_BIN="$BOOTROOT_REMOTE_BIN" \
  "$ROOT_DIR/scripts/impl/run-harness-smoke.sh"
}

main() {
  local overall_status="pass"
  local lines=()

  if line="$(run_case "scale-contention" case_scale_contention)"; then
    lines+=("$line")
  else
    lines+=("$line")
    overall_status="fail"
  fi

  if line="$(run_case "failure-recovery" case_failure_recovery)"; then
    lines+=("$line")
  else
    lines+=("$line")
    overall_status="fail"
  fi

  if line="$(run_case "runner-timer" case_runner_timer)"; then
    lines+=("$line")
  else
    lines+=("$line")
    overall_status="fail"
  fi

  if line="$(run_case "runner-cron" case_runner_cron)"; then
    lines+=("$line")
  else
    lines+=("$line")
    overall_status="fail"
  fi

  if line="$(run_case "infra-lifecycle" case_infra_lifecycle)"; then
    lines+=("$line")
  else
    lines+=("$line")
    overall_status="fail"
  fi

  {
    printf '{\n'
    printf '  "scenario_file": "%s",\n' "$SCENARIO_FILE"
    printf '  "artifact_dir": "%s",\n' "$ARTIFACT_DIR"
    printf '  "overall_status": "%s",\n' "$overall_status"
    printf '  "cases": [\n'
    local i
    for i in "${!lines[@]}"; do
      printf '    %s' "${lines[$i]}"
      if [ "$i" -lt $((${#lines[@]} - 1)) ]; then
        printf ','
      fi
      printf '\n'
    done
    printf '  ]\n'
    printf '}\n'
  } >"$SUMMARY_JSON"

  if [ "$overall_status" != "pass" ]; then
    echo "extended suite failed; see $SUMMARY_JSON"
    exit 1
  fi
}

main "$@"
