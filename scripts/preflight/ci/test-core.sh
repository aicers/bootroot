#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$ROOT_DIR"

COMPOSE_FILES=(-f docker-compose.yml -f docker-compose.test.yml)
BOOTROOT_SECRETS_DIR="$ROOT_DIR/secrets"

cleanup() {
  echo "[test-core] cleanup"
  # `--remove-orphans` because the OpenBao Agent sidecars are defined in
  # the overlay `init` writes under `secrets/`, not in the two compose
  # files above, so a plain `down` treats them as orphans and leaves them
  # running.  `-v` is deliberately not passed: the named volumes are not
  # what this teardown is failing to reach.
  #
  # The two variables for the same reason the `Cleanup` step in
  # .github/workflows/ci.yml carries them: `down` interpolates the whole
  # compose file, docker-compose.yml declares both in the fail-if-unset
  # form, and they only arrive with the `.env` that `infra install`
  # writes further down.  A run that stops before that -- the monitoring
  # test above is the first that can -- would otherwise have this
  # teardown die on the guard and remove nothing, silently, because of
  # the `|| true`.  They are placeholders; `down` reads neither.
  POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-teardown}" \
    GRAFANA_ADMIN_PASSWORD="${GRAFANA_ADMIN_PASSWORD:-teardown}" \
    docker compose -p "${COMPOSE_PROJECT_NAME:-bootroot}" "${COMPOSE_FILES[@]}" down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# --- Unit Tests ---
# CI runs this same `cargo test` under a fixture this script deliberately
# does not reproduce: a dedicated group created with `groupadd`, the
# runner added to it with `usermod`, and `cargo test` re-executed under
# `sudo setpriv --init-groups` so the fixture gid arrives as a
# non-primary supplementary group.  Doing that here would mean a
# preflight script running `sudo groupadd` on a developer's machine.
# The consequence is stated rather than hidden: without the fixture,
# `tests/e2e_cert_group_chown.rs` runs in dev mode, where it either
# falls back to whatever supplementary gid this account happens to have
# or skips outright -- and both report as a pass.
echo "[test-core] NOTICE: the cert-group regression in"
echo "[test-core]   tests/e2e_cert_group_chown.rs is NOT exercised here the"
echo "[test-core]   way CI exercises it.  CI exports"
echo "[test-core]   BOOTROOT_E2E_REQUIRE_CERT_GROUP=1 and"
echo "[test-core]   BOOTROOT_E2E_CERT_GROUP_GID=<gid of a group this user is"
echo "[test-core]   in as a non-primary supplementary group>, then runs cargo"
echo "[test-core]   test under 'setpriv --init-groups'.  A green run below"
echo "[test-core]   does not mean that regression was verified."
echo "[test-core] running unit tests"
cargo test

# --- Monitoring Integration Test ---
# `--include-ignored` because the only test in this file is `#[ignore]`;
# without it this runs zero tests and reports success.  Keep the
# arguments identical to the `Monitoring Integration Test (E2E)` step in
# .github/workflows/ci.yml, and keep this ahead of the install below:
# the test needs 8200, 9000, 8080, 3000 and 5433 free on the host.
echo "[test-core] monitoring integration test"
cargo test --test monitoring_integration -- --include-ignored

# --- Install Infrastructure ---
echo "[test-core] installing infrastructure"
cargo run --bin bootroot -- infra install

# --- Zero-config Init (decline saving the unseal keys, no show-secrets) ---
# Every prompt but one is answered by its own flag, so the run cannot
# depend on which of password.txt, ca.json and state.json a previous run
# left behind.  The single piped `n` answers the save-unseal-keys
# prompt, and it stays an answer on purpose: only the declined branch of
# that prompt echoes the keys in cleartext, which is what the assertion
# below reads.  `--no-save-unseal-keys` suppresses that echo, so it must
# not replace this answer.  `init` fails on EOF rather than reading an
# unanswered prompt as "no".
echo "[test-core] zero-config init (decline saving the unseal keys, no show-secrets)"
printf "n\n" | BOOTROOT_LANG=en cargo run --bin bootroot -- init \
  --enable auto-generate \
  --http-hmac "dev-hmac" \
  --secrets-dir "$BOOTROOT_SECRETS_DIR" \
  --no-eab \
  --overwrite-password \
  --overwrite-ca-json \
  --overwrite-state \
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
# The overwrite prompts are answered by their own flags rather than by
# relying on `clean -y` above having removed password.txt, ca.json and
# state.json, and `--no-eab` answers the EAB prompt.  The piped `n`
# answers the save-unseal-keys prompt: declining it needs no flag here
# because `--no-save-unseal-keys` requires `--summary-json`, which this
# smoke run does not write.
echo "[test-core] CLI init (smoke)"
printf "n\n" | BOOTROOT_LANG=en cargo run --bin bootroot -- init \
  --enable auto-generate,show-secrets \
  --http-hmac "dev-hmac" \
  --secrets-dir "$BOOTROOT_SECRETS_DIR" \
  --no-eab \
  --overwrite-password \
  --overwrite-ca-json \
  --overwrite-state \
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
# One agent.toml per distinct service: the [openbao] section holds a
# single AppRole identity, so `service add` rejects a config path
# shared across services.
for svc in edge-proxy web-app bootroot-agent; do
  cat > "tmp/agent-${svc}.toml" <<'EOF'
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
done

cargo run --bin bootroot -- service add \
  --service-name edge-proxy \
  --hostname edge-node-01 \
  --domain trusted.domain \
  --agent-config "$(pwd)/tmp/agent-edge-proxy.toml" \
  --cert-path "$(pwd)/certs/edge-proxy.crt" \
  --key-path "$(pwd)/certs/edge-proxy.key" \
  --instance-id 001 \
  --root-token "$ROOT_TOKEN"

cargo run --bin bootroot -- service add \
  --service-name web-app \
  --hostname web-01 \
  --domain trusted.domain \
  --agent-config "$(pwd)/tmp/agent-web-app.toml" \
  --cert-path "$(pwd)/certs/web-app.crt" \
  --key-path "$(pwd)/certs/web-app.key" \
  --instance-id 001 \
  --root-token "$ROOT_TOKEN"

cargo run --bin bootroot -- service add \
  --service-name bootroot-agent \
  --hostname bootroot-agent \
  --domain trusted.domain \
  --agent-config "$(pwd)/tmp/agent-bootroot-agent.toml" \
  --cert-path "$(pwd)/certs/bootroot-agent.crt" \
  --key-path "$(pwd)/certs/bootroot-agent.key" \
  --instance-id 001 \
  --root-token "$ROOT_TOKEN"

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
  --agent-config "$(pwd)/tmp/agent-edge-proxy.toml"

cargo run --bin bootroot -- verify \
  --service-name web-app \
  --agent-config "$(pwd)/tmp/agent-web-app.toml"

cargo run --bin bootroot -- verify \
  --service-name bootroot-agent \
  --agent-config "$(pwd)/tmp/agent-bootroot-agent.toml"

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
  if [ -s certs/bootroot-agent.crt ] && [ -s certs/bootroot-agent.key ]; then
    echo "PASS: Certificate files created"
    break
  fi
  echo "Waiting for certificate issuance..."
  sleep 5
  if [ "$i" -eq 6 ]; then
    echo "FAIL: Certificate files not created"
    exit 1
  fi
done

echo "[test-core] done"
