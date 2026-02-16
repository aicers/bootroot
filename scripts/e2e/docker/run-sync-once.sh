#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="${WORK_DIR:?WORK_DIR is required}"
SERVICE_NAME="${SERVICE_NAME:?SERVICE_NAME is required}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:?BOOTROOT_REMOTE_BIN is required}"
BOOTROOT_BIN="${BOOTROOT_BIN:?BOOTROOT_BIN is required}"
OPENBAO_URL="${OPENBAO_URL:?OPENBAO_URL is required}"
TICK_FILE="${TICK_FILE:?TICK_FILE is required}"
ROLE_ID_PATH="${ROLE_ID_PATH:-$WORK_DIR/secrets/services/$SERVICE_NAME/role_id}"
SECRET_ID_PATH="${SECRET_ID_PATH:-$WORK_DIR/secrets/services/$SERVICE_NAME/secret_id}"
EAB_FILE_PATH="${EAB_FILE_PATH:-$WORK_DIR/secrets/services/$SERVICE_NAME/eab.json}"
AGENT_CONFIG_PATH="${AGENT_CONFIG_PATH:-$WORK_DIR/agent.toml}"
CA_BUNDLE_PATH="${CA_BUNDLE_PATH:-$WORK_DIR/certs/ca-bundle.pem}"
SUMMARY_JSON_PATH="${SUMMARY_JSON_PATH:-$WORK_DIR/remote-summary-$SERVICE_NAME.json}"
STATE_LOCK_DIR="${STATE_LOCK_DIR:-$WORK_DIR/.sync-status-lock}"

acquire_lock() {
  local start
  start="$(date +%s)"
  while ! mkdir "$STATE_LOCK_DIR" >/dev/null 2>&1; do
    if [ $(( $(date +%s) - start )) -ge 30 ]; then
      printf "failed to acquire sync lock for %s\\n" "$SERVICE_NAME" >&2
      return 1
    fi
    sleep 1
  done
}

release_lock() {
  rmdir "$STATE_LOCK_DIR" >/dev/null 2>&1 || true
}

cd "$WORK_DIR"
acquire_lock
trap release_lock EXIT

"$BOOTROOT_REMOTE_BIN" sync \
  --openbao-url "$OPENBAO_URL" \
  --kv-mount "secret" \
  --service-name "$SERVICE_NAME" \
  --role-id-path "$ROLE_ID_PATH" \
  --secret-id-path "$SECRET_ID_PATH" \
  --eab-file-path "$EAB_FILE_PATH" \
  --agent-config-path "$AGENT_CONFIG_PATH" \
  --ca-bundle-path "$CA_BUNDLE_PATH" \
  --summary-json "$SUMMARY_JSON_PATH" \
  --bootroot-bin "$BOOTROOT_BIN" \
  --retry-attempts 3 \
  --retry-backoff-secs 1 \
  --retry-jitter-secs 0 \
  >/dev/null

printf '{"tick":%s}\n' "$(date +%s)" >>"$TICK_FILE"
