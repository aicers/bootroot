#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.test.yml)
BOOTROOT_SECRETS_DIR="$ROOT_DIR/secrets"

cleanup() {
  echo "[test-core] cleanup"
  docker compose "${COMPOSE_FILES[@]}" down 2>/dev/null || true
}
trap cleanup EXIT

# --- Unit Tests ---
echo "[test-core] running unit tests"
cargo test

# --- Monitoring Integration Test ---
echo "[test-core] monitoring integration test"
cargo test --test monitoring_integration

# --- Install Infrastructure ---
echo "[test-core] installing infrastructure"
cargo run --bin bootroot -- infra install

# --- Zero-config Init (answer n, no show-secrets) ---
echo "[test-core] zero-config init (answer n, no show-secrets)"
BOOTROOT_LANG=en printf "n\n" | cargo run --bin bootroot -- init \
  --enable auto-generate \
  --http-hmac "dev-hmac" \
  --secrets-dir "$BOOTROOT_SECRETS_DIR" \
  --responder-url "http://localhost:8080" \
  --skip responder-check 2>&1 | tee zero-config-init.log

if ! grep -q "unseal key" zero-config-init.log; then
  echo "FAIL: unseal keys not shown when declining save"
  exit 1
fi
echo "PASS: unseal keys displayed in cleartext after declining save"

# --- Clean and Reinstall ---
echo "[test-core] clean and reinstall"
cargo run --bin bootroot -- clean -y
cargo run --bin bootroot -- infra install

# --- CLI Init ---
echo "[test-core] CLI init (smoke)"
BOOTROOT_LANG=en printf "y\ny\ny\nn\n" | cargo run --bin bootroot -- init \
  --enable auto-generate,show-secrets \
  --http-hmac "dev-hmac" \
  --secrets-dir "$BOOTROOT_SECRETS_DIR" \
  --responder-url "http://localhost:8080" \
  --skip responder-check | tee cli-init.log

ROOT_TOKEN="$(awk -F': ' '/root token:/ {print $2; exit}' cli-init.log)"
if [ -z "${ROOT_TOKEN:-}" ]; then
  echo "Failed to read root token from init output"
  exit 1
fi

# --- CLI Service Add + Verify ---
echo "[test-core] CLI service add + verify (smoke)"
mkdir -p tmp certs
cat > tmp/agent.toml <<'EOF'
email = "admin@example.com"
server = "https://localhost:9000/acme/acme/directory"
domain = "trusted.domain"

[acme]
directory_fetch_attempts = 10
directory_fetch_base_delay_secs = 1
directory_fetch_max_delay_secs = 10
poll_attempts = 15
poll_interval_secs = 2
http_responder_url = "http://localhost:8080"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300

EOF

cargo run --bin bootroot -- service add \
  --service-name edge-proxy \
  --deploy-type daemon \
  --hostname edge-node-01 \
  --domain trusted.domain \
  --agent-config "$(pwd)/tmp/agent.toml" \
  --cert-path "$(pwd)/certs/edge-proxy.crt" \
  --key-path "$(pwd)/certs/edge-proxy.key" \
  --instance-id 001 \
  --root-token "$ROOT_TOKEN"

cargo run --bin bootroot -- service add \
  --service-name web-app \
  --deploy-type docker \
  --hostname web-01 \
  --domain trusted.domain \
  --agent-config "$(pwd)/tmp/agent.toml" \
  --cert-path "$(pwd)/certs/web-app.crt" \
  --key-path "$(pwd)/certs/web-app.key" \
  --instance-id 001 \
  --container-name web-app \
  --root-token "$ROOT_TOKEN"

RESPONDER_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' bootroot-http01)"
if [ -z "${RESPONDER_IP:-}" ]; then
  echo "Failed to read responder container IP"
  exit 1
fi
docker exec bootroot-ca sh -c "printf '%s %s\n' '$RESPONDER_IP' '001.edge-proxy.edge-node-01.trusted.domain' >> /etc/hosts"
docker exec bootroot-ca sh -c "printf '%s %s\n' '$RESPONDER_IP' '001.web-app.web-01.trusted.domain' >> /etc/hosts"

host="001.edge-proxy.edge-node-01.trusted.domain"
for attempt in {1..15}; do
  if docker exec bootroot-ca bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${host}/80'" >/dev/null 2>&1; then
    echo "Responder HTTP-01 is reachable from step-ca"
    break
  fi
  echo "Waiting for responder HTTP-01 (attempt ${attempt}/15)"
  sleep 1
done
if ! docker exec bootroot-ca bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${host}/80'" >/dev/null 2>&1; then
  echo "Responder HTTP-01 is not reachable from step-ca"
  docker logs bootroot-http01
  exit 1
fi

cargo build --bin bootroot-agent
export PATH="$(pwd)/target/debug:$PATH"

cargo run --bin bootroot -- verify \
  --service-name edge-proxy \
  --agent-config "$(pwd)/tmp/agent.toml"

cargo run --bin bootroot -- verify \
  --service-name web-app \
  --agent-config "$(pwd)/tmp/agent.toml"

# --- Verify CA Health ---
echo "[test-core] verifying CA health"
for i in {1..10}; do
  if curl -k --fail https://localhost:9000/health; then
    break
  fi
  echo "Waiting for CA health..."
  sleep 3
  if [ "$i" -eq 10 ]; then
    docker logs bootroot-ca
    exit 1
  fi
done

# --- Verify Agent Success ---
echo "[test-core] verifying agent success"
for i in {1..6}; do
  if docker logs bootroot-agent 2>&1 | grep -q "Successfully issued certificate"; then
    echo "PASS: Certificate issued successfully"
    break
  fi
  if docker logs bootroot-agent 2>&1 | grep -q "Certificate issuance succeeded"; then
    echo "PASS: Certificate issued successfully"
    break
  fi
  if [ -s certs/bootroot-agent.crt ] && [ -s certs/bootroot-agent.key ]; then
    echo "PASS: Certificate files created"
    break
  fi
  echo "Waiting for certificate issuance..."
  sleep 5
  if [ "$i" -eq 6 ]; then
    echo "FAIL: Certificate issue message not found"
    echo "=== Agent Logs ==="
    docker logs bootroot-agent
    exit 1
  fi
done

echo "[test-core] done"
