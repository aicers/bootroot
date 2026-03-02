#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)}"
SKIP_HOSTS=0
FRESH_SECRETS=0
SECRETS_BACKUP_DIR=""

usage() {
  cat <<'EOF'
Usage: scripts/preflight/ci/e2e-matrix.sh [--skip-hosts] [--fresh-secrets]

Runs the same Docker E2E matrix steps used in CI:
1) local lifecycle (no-hosts)
2) local lifecycle (hosts)
3) remote lifecycle (no-hosts)
4) remote lifecycle (hosts)
5) rotation/recovery full matrix

Options:
  --skip-hosts  Skip hosts steps (useful when sudo -n is unavailable locally)
  --fresh-secrets   Temporarily replace ./secrets with a clean directory and restore it on exit
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-hosts)
      SKIP_HOSTS=1
      shift
      ;;
    --fresh-secrets)
      FRESH_SECRETS=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage
      exit 1
      ;;
  esac
done

restore_secrets() {
  if [ -n "$SECRETS_BACKUP_DIR" ] && [ -d "$SECRETS_BACKUP_DIR/secrets" ]; then
    rm -rf "$ROOT_DIR/secrets"
    mv "$SECRETS_BACKUP_DIR/secrets" "$ROOT_DIR/secrets"
    rm -rf "$SECRETS_BACKUP_DIR"
  fi
}

if [ "$FRESH_SECRETS" -eq 1 ]; then
  SECRETS_BACKUP_DIR="/tmp/bootroot-secrets-backup-${RUN_ID}"
  mkdir -p "$SECRETS_BACKUP_DIR"
  if [ -d "$ROOT_DIR/secrets" ]; then
    mv "$ROOT_DIR/secrets" "$SECRETS_BACKUP_DIR/secrets"
  fi
  mkdir -p "$ROOT_DIR/secrets"
  chmod 700 "$ROOT_DIR/secrets" || true
  trap restore_secrets EXIT
fi

echo "[ci-local-e2e] run id: $RUN_ID"
echo "[ci-local-e2e] building bootroot binaries"
cargo build --bin bootroot --bin bootroot-remote --bin bootroot-agent

echo "[ci-local-e2e] run local lifecycle (no-hosts)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-local-no-hosts-${RUN_ID}" \
PROJECT_NAME="bootroot-e2e-ci-local-no-hosts-${RUN_ID}" \
RESOLUTION_MODE="no-hosts" \
SECRETS_DIR="$ROOT_DIR/secrets" \
TIMEOUT_SECS=120 \
INFRA_UP_ATTEMPTS=12 \
INFRA_UP_DELAY_SECS=10 \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
BOOTROOT_AGENT_BIN="$ROOT_DIR/target/debug/bootroot-agent" \
"$ROOT_DIR/scripts/impl/run-local-lifecycle.sh"

if [ "$SKIP_HOSTS" -eq 0 ]; then
  echo "[ci-local-e2e] run local lifecycle (hosts)"
  ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-local-hosts-${RUN_ID}" \
  PROJECT_NAME="bootroot-e2e-ci-local-hosts-${RUN_ID}" \
  RESOLUTION_MODE="hosts" \
  SECRETS_DIR="$ROOT_DIR/secrets" \
  TIMEOUT_SECS=120 \
  INFRA_UP_ATTEMPTS=12 \
  INFRA_UP_DELAY_SECS=10 \
  BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
  BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
  BOOTROOT_AGENT_BIN="$ROOT_DIR/target/debug/bootroot-agent" \
  "$ROOT_DIR/scripts/impl/run-local-lifecycle.sh"
else
  echo "[ci-local-e2e] skip local lifecycle (hosts)"
fi

echo "[ci-local-e2e] run remote lifecycle (no-hosts)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-remote-no-hosts-${RUN_ID}" \
PROJECT_NAME="bootroot-e2e-ci-remote-no-hosts-${RUN_ID}" \
RESOLUTION_MODE="no-hosts" \
SECRETS_DIR="$ROOT_DIR/secrets" \
TIMEOUT_SECS=120 \
INFRA_UP_ATTEMPTS=12 \
INFRA_UP_DELAY_SECS=10 \
VERIFY_ATTEMPTS=5 \
VERIFY_DELAY_SECS=5 \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
BOOTROOT_AGENT_BIN="$ROOT_DIR/target/debug/bootroot-agent" \
"$ROOT_DIR/scripts/impl/run-remote-lifecycle.sh"

if [ "$SKIP_HOSTS" -eq 0 ]; then
  echo "[ci-local-e2e] run remote lifecycle (hosts)"
  ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-remote-hosts-${RUN_ID}" \
  PROJECT_NAME="bootroot-e2e-ci-remote-hosts-${RUN_ID}" \
  RESOLUTION_MODE="hosts" \
  SECRETS_DIR="$ROOT_DIR/secrets" \
  TIMEOUT_SECS=120 \
  INFRA_UP_ATTEMPTS=12 \
  INFRA_UP_DELAY_SECS=10 \
  VERIFY_ATTEMPTS=5 \
  VERIFY_DELAY_SECS=5 \
  BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
  BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
  BOOTROOT_AGENT_BIN="$ROOT_DIR/target/debug/bootroot-agent" \
  "$ROOT_DIR/scripts/impl/run-remote-lifecycle.sh"
else
  echo "[ci-local-e2e] skip remote lifecycle (hosts)"
fi

echo "[ci-local-e2e] run rotation/recovery full matrix"
SCENARIO_FILE="$ROOT_DIR/tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json" \
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-rotation-${RUN_ID}" \
PROJECT_NAME="bootroot-e2e-ci-rotation-${RUN_ID}" \
ROTATION_ITEMS="secret_id,eab,responder_hmac,trust_sync" \
TIMEOUT_SECS=90 \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
"$ROOT_DIR/scripts/impl/run-rotation-recovery.sh"

echo "[ci-local-e2e] done"
echo "[ci-local-e2e] artifacts:"
echo "  - $ROOT_DIR/tmp/e2e/ci-local-no-hosts-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-local-hosts-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-remote-no-hosts-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-remote-hosts-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-rotation-${RUN_ID}"
