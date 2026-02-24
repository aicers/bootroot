#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)}"

echo "[e2e-extended] run id: $RUN_ID"
echo "[e2e-extended] building bootroot binaries"
cargo build --bin bootroot --bin bootroot-remote --bin bootroot-agent

echo "[e2e-extended] running extended Docker E2E suite"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/extended-${RUN_ID}" \
PROJECT_PREFIX="bootroot-e2e-extended-${RUN_ID}" \
SCENARIO_FILE="$ROOT_DIR/tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json" \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
"$ROOT_DIR/scripts/impl/run-extended-suite.sh"

echo "[e2e-extended] done"
echo "[e2e-extended] artifacts: $ROOT_DIR/tmp/e2e/extended-${RUN_ID}"
