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
STATE_FILE="${STATE_FILE:-$WORK_DIR/state.json}"
RETRY_ATTEMPTS="${RETRY_ATTEMPTS:-3}"
RETRY_BACKOFF_SECS="${RETRY_BACKOFF_SECS:-1}"
RETRY_JITTER_SECS="${RETRY_JITTER_SECS:-0}"
AGENT_EMAIL="${AGENT_EMAIL:-admin@example.com}"
AGENT_SERVER="${AGENT_SERVER:-https://localhost:9000/acme/acme/directory}"
AGENT_RESPONDER_URL="${AGENT_RESPONDER_URL:-http://127.0.0.1:8080}"

read_state_field() {
  local key="$1"
  python3 - "$STATE_FILE" "$SERVICE_NAME" "$key" <<'PY'
import json
import sys
from pathlib import Path

state_path, service_name, key = sys.argv[1:4]
state = json.loads(Path(state_path).read_text(encoding="utf-8"))
service = state.get("services", {}).get(service_name, {})
value = service.get(key)
if value is None:
    print("")
else:
    print(value)
PY
}

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

AGENT_DOMAIN="${AGENT_DOMAIN:-$(read_state_field domain)}"
PROFILE_HOSTNAME="${PROFILE_HOSTNAME:-$(read_state_field hostname)}"
PROFILE_INSTANCE_ID="${PROFILE_INSTANCE_ID:-$(read_state_field instance_id)}"
PROFILE_CERT_PATH="${PROFILE_CERT_PATH:-$(read_state_field cert_path)}"
PROFILE_KEY_PATH="${PROFILE_KEY_PATH:-$(read_state_field key_path)}"

"$BOOTROOT_REMOTE_BIN" sync \
  --openbao-url "$OPENBAO_URL" \
  --kv-mount "secret" \
  --service-name "$SERVICE_NAME" \
  --role-id-path "$ROLE_ID_PATH" \
  --secret-id-path "$SECRET_ID_PATH" \
  --eab-file-path "$EAB_FILE_PATH" \
  --agent-config-path "$AGENT_CONFIG_PATH" \
  --agent-email "$AGENT_EMAIL" \
  --agent-server "$AGENT_SERVER" \
  --agent-domain "$AGENT_DOMAIN" \
  --agent-responder-url "$AGENT_RESPONDER_URL" \
  --profile-hostname "$PROFILE_HOSTNAME" \
  --profile-instance-id "$PROFILE_INSTANCE_ID" \
  --profile-cert-path "$PROFILE_CERT_PATH" \
  --profile-key-path "$PROFILE_KEY_PATH" \
  --ca-bundle-path "$CA_BUNDLE_PATH" \
  --summary-json "$SUMMARY_JSON_PATH" \
  --bootroot-bin "$BOOTROOT_BIN" \
  --state-file "$STATE_FILE" \
  --retry-attempts "$RETRY_ATTEMPTS" \
  --retry-backoff-secs "$RETRY_BACKOFF_SECS" \
  --retry-jitter-secs "$RETRY_JITTER_SECS" \
  >/dev/null

printf '{"tick":%s}\n' "$(date +%s)" >>"$TICK_FILE"
