#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)}"
SKIP_HOSTS_ALL=0
FRESH_SECRETS=0
SECRETS_BACKUP_DIR=""

usage() {
  cat <<'EOF'
Usage: scripts/ci-local-e2e.sh [--skip-hosts-all] [--fresh-secrets]

Runs the same Docker E2E matrix steps used in CI:
1) main lifecycle (fqdn-only-hosts)
2) main lifecycle (hosts-all)
3) rotation/recovery full matrix

Options:
  --skip-hosts-all  Skip hosts-all lifecycle step (useful when sudo -n is unavailable locally)
  --fresh-secrets   Temporarily replace ./secrets with a clean directory and restore it on exit
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-hosts-all)
      SKIP_HOSTS_ALL=1
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

echo "[ci-local-e2e] run main lifecycle (fqdn-only-hosts)"
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-main-fqdn-${RUN_ID}" \
PROJECT_NAME="bootroot-e2e-ci-main-fqdn-${RUN_ID}" \
RESOLUTION_MODE="fqdn-only-hosts" \
SECRETS_DIR="$ROOT_DIR/secrets" \
TIMEOUT_SECS=120 \
INFRA_UP_ATTEMPTS=12 \
INFRA_UP_DELAY_SECS=10 \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
BOOTROOT_AGENT_BIN="$ROOT_DIR/target/debug/bootroot-agent" \
"$ROOT_DIR/scripts/e2e/docker/run-main-lifecycle.sh"

if [ "$SKIP_HOSTS_ALL" -eq 0 ]; then
  echo "[ci-local-e2e] run main lifecycle (hosts-all)"
  ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-main-hosts-${RUN_ID}" \
  PROJECT_NAME="bootroot-e2e-ci-main-hosts-${RUN_ID}" \
  RESOLUTION_MODE="hosts-all" \
  SECRETS_DIR="$ROOT_DIR/secrets" \
  TIMEOUT_SECS=120 \
  INFRA_UP_ATTEMPTS=12 \
  INFRA_UP_DELAY_SECS=10 \
  BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
  BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
  BOOTROOT_AGENT_BIN="$ROOT_DIR/target/debug/bootroot-agent" \
  "$ROOT_DIR/scripts/e2e/docker/run-main-lifecycle.sh"
else
  echo "[ci-local-e2e] skip main lifecycle (hosts-all)"
fi

echo "[ci-local-e2e] run rotation/recovery full matrix"
SCENARIO_FILE="$ROOT_DIR/tests/e2e/docker_harness/scenarios/scenario-c-multi-node-uneven.json" \
ARTIFACT_DIR="$ROOT_DIR/tmp/e2e/ci-rotation-${RUN_ID}" \
PROJECT_NAME="bootroot-e2e-ci-rotation-${RUN_ID}" \
ROTATION_ITEMS="secret_id,eab,responder_hmac,trust_sync" \
TIMEOUT_SECS=90 \
BOOTROOT_BIN="$ROOT_DIR/target/debug/bootroot" \
BOOTROOT_REMOTE_BIN="$ROOT_DIR/target/debug/bootroot-remote" \
"$ROOT_DIR/scripts/e2e/docker/run-rotation-recovery.sh"

echo "[ci-local-e2e] done"
echo "[ci-local-e2e] artifacts:"
echo "  - $ROOT_DIR/tmp/e2e/ci-main-fqdn-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-main-hosts-${RUN_ID}"
echo "  - $ROOT_DIR/tmp/e2e/ci-rotation-${RUN_ID}"
