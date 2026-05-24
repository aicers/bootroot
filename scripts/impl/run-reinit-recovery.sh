#!/usr/bin/env bash
set -euo pipefail

# Docker-backed E2E recovery harness for `bootroot reinit` (#600).
#
# Builds a real partial-init OpenBao state on Docker, then drives
# `bootroot reinit --yes` against three #598-derived failure modes
# and asserts the recovery contracts every time:
#
#   - step-ca root/intermediate fingerprint unchanged before vs. after
#   - secrets/password.txt not overwritten
#   - non-loopback OpenBao bind survives (compose override survives,
#     intent persists in rewritten state.json, post-reinit OpenBao
#     listens on the bind, the second init pass reaches it)
#   - service registry intentionally empty after reinit
#
# The scenarios are chained against a single bootstrap so the full
# recovery sequence can be observed end-to-end:
#
#   scenario-a  stuck after `bootroot clean --openbao-only`
#   scenario-b  initialized-OpenBao-without-root-token (operator
#               lost summary-json; OpenBao volume still initialised)
#   scenario-c  stale-local-state-only rsync-clone (OpenBao volume
#               wiped manually; state.json + secrets/ survive)
#
# After each scenario reinit must recover and the four contracts
# above must hold against the snapshot taken at bootstrap time.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-reinit-recovery-$(date +%s)}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$ARTIFACT_DIR/workspace}"
SECRETS_DIR="${SECRETS_DIR:-$ROOT_DIR/secrets}"
AGENT_CONFIG_PATH="${AGENT_CONFIG_PATH:-$WORKSPACE_DIR/agent.toml}"
CERTS_DIR="${CERTS_DIR:-$WORKSPACE_DIR/certs}"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
INFRA_READY_ATTEMPTS="${INFRA_READY_ATTEMPTS:-40}"
INFRA_READY_DELAY_SECS="${INFRA_READY_DELAY_SECS:-3}"
OPENBAO_READY_ATTEMPTS="${OPENBAO_READY_ATTEMPTS:-40}"
OPENBAO_READY_DELAY_SECS="${OPENBAO_READY_DELAY_SECS:-2}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-summary.json"
SNAPSHOT_DIR="$ARTIFACT_DIR/snapshots"

OPENBAO_CONTAINER_NAME="bootroot-openbao"
# Non-loopback bind exercised by the harness.  Defaults to the docker
# bridge gateway because every host that can run this harness already
# has the `docker0` interface (created by docker the moment it starts)
# and the address is non-loopback for the purposes of
# `validate_openbao_bind` / `validate_openbao_advertise_addr`.  A
# specific (non-wildcard) bind sidesteps the
# `--openbao-advertise-addr` requirement that wildcard binds carry,
# and `client_url_from_bind_addr` returns the bind as-is so the
# second init pass reaches OpenBao through the same address the
# preserved compose override publishes on.
OPENBAO_BIND_HOST_DEFAULT="172.17.0.1"
OPENBAO_BIND_HOST="${OPENBAO_BIND_HOST:-$OPENBAO_BIND_HOST_DEFAULT}"
OPENBAO_BIND_ADDR="${OPENBAO_BIND_ADDR:-${OPENBAO_BIND_HOST}:8200}"
EXPOSED_OVERRIDE_PATH="$SECRETS_DIR/openbao/docker-compose.openbao-exposed.yml"
EDGE_SERVICE="edge-proxy"
EDGE_HOSTNAME="edge-node-01"
DOMAIN="trusted.domain"
INSTANCE_ID="001"
DEFAULT_STEPCA_PASSWORD="reinit-recovery"
RUNTIME_SERVICE_ADD_ROLE_ID=""
RUNTIME_SERVICE_ADD_SECRET_ID=""
CURRENT_PHASE="bootstrap"

# Pin POSTGRES_HOST_PORT for the compose stack: docker-compose.yml's
# default moved from 5432 to 5433 in #588 §4c; the harness expects
# 5432 (CI runners free that port before the matrix) so pin it
# explicitly here to keep compose port mapping aligned with admin
# probes and the host-side admin DSN.
export POSTGRES_HOST_PORT="${POSTGRES_HOST_PORT:-5432}"
export POSTGRES_HOST="127.0.0.1"
export POSTGRES_PORT="$POSTGRES_HOST_PORT"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------

log_phase() {
  local phase="$1"
  CURRENT_PHASE="$phase"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"ts":"%s","phase":"%s"}\n' "$now" "$phase" >>"$PHASE_LOG"
}

fail() {
  local message="$1"
  printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$message" >>"$RUN_LOG" 2>/dev/null || true
  echo "[reinit-recovery][${CURRENT_PHASE}] $message" >&2
  exit 1
}

on_error() {
  local line="$1"
  echo "[reinit-recovery] failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "[reinit-recovery] artifact dir: ${ARTIFACT_DIR}" >&2
  if [ -f "$RUN_LOG" ]; then
    echo "--- run.log (tail) ---" >&2
    tail -n 120 "$RUN_LOG" >&2 || true
  fi
  if [ -f "$INIT_RAW_LOG" ]; then
    echo "--- init.raw.log (tail) ---" >&2
    tail -n 80 "$INIT_RAW_LOG" >&2 || true
  fi
}

# ---------------------------------------------------------------------------
# Docker / compose helpers
# ---------------------------------------------------------------------------

compose() {
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" "$@"
}

compose_down() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}

run_bootroot() {
  ( cd "$WORKSPACE_DIR" && "$BOOTROOT_BIN" "$@" )
}

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required"
  command -v curl >/dev/null 2>&1 || fail "curl is required"
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
}

capture_artifacts() {
  compose ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
  compose logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  # Container-level OpenBao state, captured straight from inside the
  # container so the diagnostic is unaffected by host networking flakes
  # that may have caused the failure in the first place.
  docker port "$OPENBAO_CONTAINER_NAME" >"$ARTIFACT_DIR/openbao-port.log" 2>&1 || true
  docker exec -e BAO_ADDR="https://127.0.0.1:8200" -e BAO_SKIP_VERIFY=true \
    "$OPENBAO_CONTAINER_NAME" bao status -format=json \
    >"$ARTIFACT_DIR/openbao-bao-status.log" 2>&1 || true
}

cleanup() {
  log_phase "cleanup"
  capture_artifacts
  compose_down
}

# Use the public sys/seal-status endpoint (always available, even
# when OpenBao is sealed) so the readiness probe does not require a
# valid root token.  Works over both http and https because the
# probe always uses the host-published HTTP port — TLS for
# non-loopback binds is layered on later by `init`'s certificate
# issuance, after this probe.
wait_for_openbao_listening() {
  local url="$1"
  local attempt
  for attempt in $(seq 1 "$OPENBAO_READY_ATTEMPTS"); do
    local code
    code="$(curl -kSs -o /dev/null -w '%{http_code}' -m 3 "$url/v1/sys/seal-status" || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      return 0
    fi
    sleep "$OPENBAO_READY_DELAY_SECS"
  done
  fail "OpenBao did not become reachable at $url"
}

# Unseals via `docker exec` against the in-container CLI so the helper
# does not depend on the host-published port being routable.  The
# `--openbao-bind` flow publishes OpenBao on a non-loopback host IP
# (docker0 gateway by default), and CI runners have occasionally
# proven unreliable about reaching that host IP between port
# rebinds during `init`'s TLS recreate.  Talking to OpenBao from
# inside the container sidesteps that flake entirely.
unseal_openbao_from_summary() {
  local container="${OPENBAO_CONTAINER_NAME}"
  # Wait for the OpenBao API inside the container to become responsive
  # before submitting unseal keys.  `init`'s TLS recreate leaves the
  # container Started before the OpenBao process is fully listening.
  # `bao status` exits 0 when unsealed and 2 when sealed-but-reachable;
  # both states mean the listener is up and the unseal call is safe.
  local probe_attempt
  for probe_attempt in $(seq 1 "$OPENBAO_READY_ATTEMPTS"); do
    local probe_rc=0
    docker exec -e BAO_ADDR="https://127.0.0.1:8200" \
      -e BAO_SKIP_VERIFY=true "$container" \
      bao status -format=json >/dev/null 2>&1 || probe_rc=$?
    if [ "$probe_rc" = "0" ] || [ "$probe_rc" = "2" ]; then
      break
    fi
    sleep "$OPENBAO_READY_DELAY_SECS"
  done
  # `bootroot init` always uses Shamir threshold=2; the summary JSON
  # does not record the threshold so feed the first two keys.
  local threshold=2
  local i
  for i in $(seq 0 $((threshold - 1))); do
    local key
    key="$(jq -r ".unseal_keys[$i] // empty" "$INIT_SUMMARY_JSON")"
    [ -n "$key" ] || fail "missing unseal key $i in $INIT_SUMMARY_JSON"
    if ! docker exec -e BAO_ADDR="https://127.0.0.1:8200" \
        -e BAO_SKIP_VERIFY=true "$container" \
        bao operator unseal "$key" >/dev/null 2>>"$RUN_LOG"; then
      fail "bao operator unseal failed (key $i)"
    fi
  done
  local attempt
  for attempt in $(seq 1 "$OPENBAO_READY_ATTEMPTS"); do
    # `bao status` exits 0 when unsealed, 2 when sealed-but-reachable.
    # Use the exit code directly: jq's `//` alternative operator treats
    # boolean `false` as nullish, so `.sealed // "true"` would return
    # "true" for both sealed and unsealed states and the loop would
    # never break.
    local status_rc=0
    docker exec -e BAO_ADDR="https://127.0.0.1:8200" \
      -e BAO_SKIP_VERIFY=true "$container" \
      bao status -format=json >/dev/null 2>&1 || status_rc=$?
    if [ "$status_rc" = "0" ]; then
      return 0
    fi
    sleep "$OPENBAO_READY_DELAY_SECS"
  done
  fail "OpenBao did not unseal within timeout via docker exec"
}

wait_for_postgres_admin() {
  local host_port="${POSTGRES_HOST_PORT:-5432}"
  local admin_user="${POSTGRES_USER:-step}"
  local attempt
  for attempt in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    if docker exec bootroot-postgres pg_isready -U "$admin_user" -d postgres >/dev/null 2>&1 &&
      bash -lc ": >/dev/tcp/127.0.0.1/${host_port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  fail "postgres admin endpoint did not become reachable"
}

# ---------------------------------------------------------------------------
# Snapshot helpers
# ---------------------------------------------------------------------------

snapshot_pre_reinit() {
  local label="$1"
  local dir="$SNAPSHOT_DIR/$label"
  mkdir -p "$dir"
  cp "$SECRETS_DIR/password.txt" "$dir/password.txt"
  openssl x509 -in "$SECRETS_DIR/certs/root_ca.crt" -noout -fingerprint -sha256 \
    >"$dir/root_ca.fingerprint"
  openssl x509 -in "$SECRETS_DIR/certs/intermediate_ca.crt" -noout -fingerprint -sha256 \
    >"$dir/intermediate_ca.fingerprint"
  cp "$WORKSPACE_DIR/state.json" "$dir/state.json"
  if [ -f "$EXPOSED_OVERRIDE_PATH" ]; then
    cp "$EXPOSED_OVERRIDE_PATH" "$dir/docker-compose.openbao-exposed.yml"
  fi
}

assert_post_reinit_contracts() {
  local label="$1"
  local dir="$SNAPSHOT_DIR/$label"

  # 1. step-ca CA fingerprints unchanged.
  local before_root after_root
  before_root="$(cat "$dir/root_ca.fingerprint")"
  after_root="$(openssl x509 -in "$SECRETS_DIR/certs/root_ca.crt" -noout -fingerprint -sha256)"
  if [ "$before_root" != "$after_root" ]; then
    fail "[$label] root_ca.crt fingerprint changed across reinit (before='$before_root' after='$after_root')"
  fi
  local before_int after_int
  before_int="$(cat "$dir/intermediate_ca.fingerprint")"
  after_int="$(openssl x509 -in "$SECRETS_DIR/certs/intermediate_ca.crt" -noout -fingerprint -sha256)"
  if [ "$before_int" != "$after_int" ]; then
    fail "[$label] intermediate_ca.crt fingerprint changed across reinit"
  fi

  # 2. password.txt unchanged (byte-for-byte).
  if ! cmp -s "$dir/password.txt" "$SECRETS_DIR/password.txt"; then
    fail "[$label] secrets/password.txt was overwritten across reinit"
  fi

  # 3. Non-loopback bind survives.
  [ -f "$EXPOSED_OVERRIDE_PATH" ] \
    || fail "[$label] expected compose override $EXPOSED_OVERRIDE_PATH to survive reinit"
  local bind
  bind="$(jq -r '.openbao_bind_addr // empty' "$WORKSPACE_DIR/state.json")"
  if [ "$bind" != "$OPENBAO_BIND_ADDR" ]; then
    fail "[$label] post-reinit state.json openbao_bind_addr='$bind' expected '$OPENBAO_BIND_ADDR'"
  fi
  # No advertise_addr was set at install time (specific bind, not
  # wildcard) so the post-reinit state should also leave it empty.
  local advertise
  advertise="$(jq -r '.openbao_advertise_addr // empty' "$WORKSPACE_DIR/state.json")"
  if [ -n "$advertise" ]; then
    fail "[$label] post-reinit state.json openbao_advertise_addr should be empty, got '$advertise'"
  fi
  wait_for_openbao_listening "https://${OPENBAO_BIND_ADDR}"

  # 4. Service registry intentionally empty.
  local svc_count approles policies
  svc_count="$(jq -r '.services | length' "$WORKSPACE_DIR/state.json")"
  approles="$(jq -r '.approles | length' "$WORKSPACE_DIR/state.json")"
  policies="$(jq -r '.policies | length' "$WORKSPACE_DIR/state.json")"
  if [ "$svc_count" != "0" ]; then
    fail "[$label] post-reinit services registry is not empty (count=$svc_count)"
  fi
  if [ "$approles" != "0" ]; then
    fail "[$label] post-reinit approles registry is not empty (count=$approles)"
  fi
  if [ "$policies" != "0" ]; then
    fail "[$label] post-reinit policies registry is not empty (count=$policies)"
  fi
}

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

write_agent_config() {
  mkdir -p "$(dirname "$AGENT_CONFIG_PATH")" "$CERTS_DIR"
  cat >"$AGENT_CONFIG_PATH" <<EOF
email = "admin@example.com"
server = "https://localhost:9000/acme/acme/directory"
domain = "${DOMAIN}"

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
}

reset_workspace() {
  # Wipe the workspace's state file so the bootstrap init starts from
  # a clean slate; preserve $SECRETS_DIR which holds Postgres/step-ca
  # material refreshed below.
  rm -f "$WORKSPACE_DIR/state.json"
  rm -rf "$SECRETS_DIR/config" "$SECRETS_DIR/certs" "$SECRETS_DIR/db" \
    "$SECRETS_DIR/secrets" "$SECRETS_DIR/openbao" \
    "$SECRETS_DIR/password.txt" "$SECRETS_DIR/password.txt.new"
  rm -f "$ROOT_DIR/.env"
}

ensure_bind_host_available() {
  # Verify the configured non-loopback bind host actually exists on
  # this machine; otherwise compose will refuse to publish the port
  # and reinit will look broken when the real cause is a missing
  # docker0 interface.
  if ! ip -4 -o addr show 2>/dev/null | awk '{print $4}' | sed 's|/.*||' \
      | grep -qx "$OPENBAO_BIND_HOST"; then
    fail "non-loopback bind host $OPENBAO_BIND_HOST is not assigned to any local interface (set OPENBAO_BIND_HOST to an address that is)"
  fi
}

install_infra_with_bind() {
  reset_workspace
  run_bootroot infra install \
    --compose-file "$COMPOSE_FILE" \
    --openbao-bind "$OPENBAO_BIND_ADDR" \
    --openbao-tls-required >>"$RUN_LOG" 2>&1
}

run_bootstrap_init() {
  wait_for_postgres_admin
  # The very first init pass talks to the loopback URL because TLS has
  # not been issued for the bind yet.  `infra install --openbao-bind`
  # writes openbao.hcl as plaintext; `init` will switch it to TLS after
  # issuing the OpenBao server cert.
  wait_for_openbao_listening "http://127.0.0.1:8200"

  log_phase "bootstrap-init"
  # `infra install` writes state.json (to capture the openbao_bind_addr
  # intent) before init runs, so init's overwrite-state prompt fires
  # under default-yes-no semantics.  Pipe `y` answers to clear that
  # prompt (and any future ca.json / password.txt overwrite prompts
  # that may appear on rerun) so the bootstrap pass stays
  # non-interactive.
  if ! printf 'y\ny\ny\n' | BOOTROOT_LANG=en run_bootroot init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$INIT_SUMMARY_JSON" \
    --enable auto-generate,show-secrets,db-provision \
    --stepca-password "$DEFAULT_STEPCA_PASSWORD" \
    --http-hmac "dev-hmac" \
    --no-eab \
    --save-unseal-keys \
    --db-user "step" \
    --db-name "stepca" \
    --responder-url "http://localhost:8080" \
    --skip responder-check >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 200 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
    fail "bootroot init failed"
  fi
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$INIT_LOG"

  RUNTIME_SERVICE_ADD_ROLE_ID="$(jq -r '.approles[] | select(.label == "runtime_service_add") | .role_id // empty' "$INIT_SUMMARY_JSON")"
  RUNTIME_SERVICE_ADD_SECRET_ID="$(jq -r '.approles[] | select(.label == "runtime_service_add") | .secret_id // empty' "$INIT_SUMMARY_JSON")"
  [ -n "$RUNTIME_SERVICE_ADD_ROLE_ID" ] || fail "failed to parse runtime_service_add role_id"
  [ -n "$RUNTIME_SERVICE_ADD_SECRET_ID" ] || fail "failed to parse runtime_service_add secret_id"

  # The TLS post-processing step recreates the OpenBao container, which
  # comes back sealed; `init` does not auto-unseal afterwards.  Without
  # this `service add` would fail with "Vault is sealed" on AppRole
  # login.  Replay the unseal keys captured in the bootstrap summary.
  # Talks to OpenBao via `docker exec` so the unseal does not race
  # against the host-side port publish coming back up after the
  # recreate.
  unseal_openbao_from_summary

  # `service add` connects to OpenBao via state.openbao_url, which
  # `bootroot init` set to `https://${OPENBAO_BIND_ADDR}`.  Make sure
  # the host-published port is actually reachable before invoking the
  # next bootroot command; otherwise the AppRole login fails with
  # `Connection refused` rather than a clear diagnostic.
  wait_for_openbao_listening "https://${OPENBAO_BIND_ADDR}"

  log_phase "bootstrap-service-add"
  run_bootroot service add \
    --service-name "$EDGE_SERVICE" --deploy-type daemon --delivery-mode local-file \
    --hostname "$EDGE_HOSTNAME" --domain "$DOMAIN" \
    --agent-config "$AGENT_CONFIG_PATH" \
    --cert-path "$CERTS_DIR/${EDGE_SERVICE}.crt" \
    --key-path "$CERTS_DIR/${EDGE_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

  # Sanity: the bootstrap state.json must carry the service we just
  # added, so the empty-registry assertion after reinit proves the
  # registry actually shrank rather than starting empty.
  local pre_svc_count
  pre_svc_count="$(jq -r '.services | length' "$WORKSPACE_DIR/state.json")"
  if [ "$pre_svc_count" -lt 1 ]; then
    fail "bootstrap state.json should contain at least one registered service (got $pre_svc_count)"
  fi
}

run_reinit() {
  local tag="$1"
  log_phase "reinit-${tag}"
  if ! BOOTROOT_LANG=en run_bootroot reinit \
    --yes \
    --no-eab \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$ARTIFACT_DIR/reinit-summary-${tag}.json" \
    --enable auto-generate,show-secrets \
    >"$ARTIFACT_DIR/reinit-${tag}.raw.log" 2>&1; then
    {
      echo "bootroot reinit failed (tag=${tag}, raw tail):"
      tail -n 200 "$ARTIFACT_DIR/reinit-${tag}.raw.log" || true
    } >>"$RUN_LOG"
    fail "bootroot reinit failed (tag=${tag})"
  fi
}

# ---------------------------------------------------------------------------
# Scenario A: stuck after `bootroot clean --openbao-only`
# ---------------------------------------------------------------------------

scenario_a_stuck_after_clean() {
  log_phase "scenario-a-clean-openbao-only"
  snapshot_pre_reinit "scenario-a"
  run_bootroot clean --openbao-only -y \
    --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1
  if docker inspect "$OPENBAO_CONTAINER_NAME" >/dev/null 2>&1; then
    fail "[scenario-a] expected $OPENBAO_CONTAINER_NAME to be removed by clean --openbao-only"
  fi
  run_reinit "scenario-a"
  assert_post_reinit_contracts "scenario-a"
}

# ---------------------------------------------------------------------------
# Scenario B: initialized-OpenBao-without-root-token
# ---------------------------------------------------------------------------
#
# After a previous init the OpenBao volume is initialised but the
# operator has lost the only on-disk channel to the root token (the
# summary-json the bootstrap wrote).  state.json never carries the
# root token, so dropping summary-json + unseal-keys.txt is sufficient
# to put the deployment into the partial-init trap reinit recovers
# from: `init` would refuse with "already initialised but no root
# token available", and the operator has no way forward except wiping
# OpenBao.  Reinit's atomic wipe + re-init is exactly that recovery.

scenario_b_initialized_without_root_token() {
  log_phase "scenario-b-no-root-token"
  snapshot_pre_reinit "scenario-b"
  # Confirm the starting state actually has an initialised OpenBao —
  # the previous scenario's reinit must have left it that way.
  local init_status
  init_status="$(curl -kSs -m 3 "https://${OPENBAO_BIND_ADDR}/v1/sys/init" \
    | jq -r '.initialized // empty' 2>/dev/null || true)"
  if [ "$init_status" != "true" ]; then
    fail "[scenario-b] expected OpenBao to be initialised before dropping the root-token channel"
  fi
  rm -f "$INIT_SUMMARY_JSON" "$SECRETS_DIR/openbao/unseal-keys.txt"
  run_reinit "scenario-b"
  assert_post_reinit_contracts "scenario-b"
}

# ---------------------------------------------------------------------------
# Scenario C: stale-local-state-only (rsync clone)
# ---------------------------------------------------------------------------
#
# Simulates the rsync-clone-to-new-host case: state.json + secrets/
# exist (rsynced from the original host) but the destination's
# OpenBao volume is fresh.  We model the "destination OpenBao is
# fresh" half by removing the container and its data volume
# manually, then bringing the container back up with `docker
# compose up openbao` so reinit sees an uninitialised OpenBao
# alongside the carried-over local state.

scenario_c_rsync_clone_stale_state() {
  log_phase "scenario-c-rsync-clone"
  snapshot_pre_reinit "scenario-c"
  # Remove the container + named volume out-of-band so the carried-over
  # state.json keeps pointing at a "previous-host" OpenBao that no
  # longer exists locally — the canonical rsync-clone trap.
  docker rm -f "$OPENBAO_CONTAINER_NAME" >/dev/null 2>&1 || true
  local project_basename
  project_basename="$(basename "$ROOT_DIR" | tr -c 'a-zA-Z0-9_-' '_' | tr '[:upper:]' '[:lower:]')"
  # `docker compose` derives the project name from the work-dir
  # basename when COMPOSE_PROJECT_NAME is unset; the volume is named
  # <project>_openbao-data.  Honour COMPOSE_PROJECT_NAME when set so
  # the harness can run under a custom project.
  local project="${COMPOSE_PROJECT_NAME:-$project_basename}"
  for vol in "${project}_openbao-data" "${project}_openbao-audit"; do
    docker volume rm "$vol" >/dev/null 2>&1 || true
  done
  run_reinit "scenario-c"
  assert_post_reinit_contracts "scenario-c"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  mkdir -p "$ARTIFACT_DIR" "$WORKSPACE_DIR" "$CERTS_DIR" "$SNAPSHOT_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  ensure_prerequisites
  ensure_bind_host_available
  compose_down

  log_phase "bootstrap-install"
  write_agent_config
  install_infra_with_bind
  run_bootstrap_init

  scenario_a_stuck_after_clean
  scenario_b_initialized_without_root_token
  scenario_c_rsync_clone_stale_state

  log_phase "done"
}

main "$@"
