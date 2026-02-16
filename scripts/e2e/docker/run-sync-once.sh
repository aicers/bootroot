#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="${WORK_DIR:?WORK_DIR is required}"
SERVICE_NAME="${SERVICE_NAME:?SERVICE_NAME is required}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:?BOOTROOT_REMOTE_BIN is required}"
BOOTROOT_BIN="${BOOTROOT_BIN:?BOOTROOT_BIN is required}"
OPENBAO_URL="${OPENBAO_URL:?OPENBAO_URL is required}"
TICK_FILE="${TICK_FILE:?TICK_FILE is required}"

cd "$WORK_DIR"

"$BOOTROOT_REMOTE_BIN" sync \
  --openbao-url "$OPENBAO_URL" \
  --kv-mount "secret" \
  --service-name "$SERVICE_NAME" \
  --role-id-path "$WORK_DIR/secrets/services/$SERVICE_NAME/role_id" \
  --secret-id-path "$WORK_DIR/secrets/services/$SERVICE_NAME/secret_id" \
  --eab-file-path "$WORK_DIR/secrets/services/$SERVICE_NAME/eab.json" \
  --agent-config-path "$WORK_DIR/agent.toml" \
  --ca-bundle-path "$WORK_DIR/certs/ca-bundle.pem" \
  --summary-json "$WORK_DIR/remote-summary.json" \
  --bootroot-bin "$BOOTROOT_BIN" \
  --retry-attempts 1 \
  --retry-backoff-secs 1 \
  --retry-jitter-secs 0 \
  >/dev/null

printf '{"tick":%s}\n' "$(date +%s)" >>"$TICK_FILE"
