#!/usr/bin/env bash
set -euo pipefail

WORK_DIR="${1:-}"
SERVICE_NAME="${SERVICE_NAME:-edge-proxy}"
HOSTNAME="${HOSTNAME:-edge-node-01}"
DOMAIN="${DOMAIN:-trusted.domain}"
INSTANCE_ID="${INSTANCE_ID:-001}"

if [ -z "$WORK_DIR" ]; then
  printf "usage: %s <work_dir>\n" "$0" >&2
  exit 1
fi

mkdir -p "$WORK_DIR/certs" "$WORK_DIR/secrets/services/$SERVICE_NAME" "$WORK_DIR/bin"

cat >"$WORK_DIR/state.json" <<JSON
{
  "openbao_url": "http://127.0.0.1:8200",
  "kv_mount": "secret",
  "secrets_dir": "secrets",
  "policies": {},
  "approles": {},
  "services": {
    "$SERVICE_NAME": {
      "service_name": "$SERVICE_NAME",
      "deploy_type": "daemon",
      "delivery_mode": "remote-bootstrap",
      "sync_status": {
        "secret_id": "pending",
        "eab": "pending",
        "responder_hmac": "pending",
        "trust_sync": "pending"
      },
      "hostname": "$HOSTNAME",
      "domain": "$DOMAIN",
      "agent_config_path": "agent.toml",
      "cert_path": "certs/$SERVICE_NAME.crt",
      "key_path": "certs/$SERVICE_NAME.key",
      "instance_id": "$INSTANCE_ID",
      "container_name": null,
      "notes": null,
      "approle": {
        "role_name": "bootroot-service-$SERVICE_NAME",
        "role_id": "role-$SERVICE_NAME",
        "secret_id_path": "secrets/services/$SERVICE_NAME/secret_id",
        "policy_name": "bootroot-service-$SERVICE_NAME"
      }
    }
  }
}
JSON

cat >"$WORK_DIR/remote-summary.json" <<JSON
{
  "secret_id": {"status": "applied"},
  "eab": {"status": "applied"},
  "responder_hmac": {"status": "applied"},
  "trust_sync": {"status": "applied"}
}
JSON

printf "seed-secret\n" >"$WORK_DIR/secrets/services/$SERVICE_NAME/secret_id"
printf "role-$SERVICE_NAME\n" >"$WORK_DIR/secrets/services/$SERVICE_NAME/role_id"
cat >"$WORK_DIR/secrets/services/$SERVICE_NAME/eab.json" <<JSON
{"kid":"seed-kid","hmac":"seed-hmac"}
JSON

cat >"$WORK_DIR/bin/bootroot-agent" <<'SH'
#!/usr/bin/env sh
exit 0
SH
chmod 700 "$WORK_DIR/bin/bootroot-agent"

openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "$WORK_DIR/certs/$SERVICE_NAME.key" \
  -out "$WORK_DIR/certs/$SERVICE_NAME.crt" \
  -days 1 \
  -subj "/CN=$INSTANCE_ID.$SERVICE_NAME.$HOSTNAME.$DOMAIN" \
  -addext "subjectAltName=DNS:$INSTANCE_ID.$SERVICE_NAME.$HOSTNAME.$DOMAIN" \
  >/dev/null 2>&1

chmod 600 "$WORK_DIR/certs/$SERVICE_NAME.key" "$WORK_DIR/certs/$SERVICE_NAME.crt"
