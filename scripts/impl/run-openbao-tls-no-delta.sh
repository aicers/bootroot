#!/usr/bin/env bash
set -euo pipefail

# Docker-backed E2E harness for the OpenBao plaintext -> TLS transition
# when `init` has no compose-configuration delta to ride on (#737).
#
# `infra install --openbao-bind` deliberately writes the
# `openbao-exposed` override without applying it and leaves that to
# `init`.  Any caller that needs the published port live before `init`
# (for example to verify control-plane reachability from another host)
# applies the override itself — and thereby disarms the only reason
# `init`'s `docker compose up -d openbao` recreated the container.
# `openbao.hcl` is a bind-mounted file, so Compose does not hash its
# contents: with the override already applied there is no delta, `up -d`
# is a no-op, the container keeps serving plaintext from its old
# configuration, and `state.json` is advanced to `https://` regardless.
#
# This harness reproduces exactly that precondition:
#
#   1. `infra install --openbao-bind <ip>:8200 --openbao-tls-required`
#   2. apply the `openbao-exposed` override by hand while
#      `openbao/openbao.hcl` is still plaintext
#   3. `bootroot init`
#
# and then asserts the contracts #737 introduces:
#
#   - the OpenBao container was actually recreated by `init`
#   - an HTTPS request to the bind address succeeds, verifying against
#     the local step-ca bundle (no `-k`)
#   - plain HTTP to the same address does *not* succeed
#   - `state.json` records the HTTPS URL
#   - the vault is unsealed when `init` returns
#   - a following `service add` succeeds with no manual unseal

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# shellcheck source=lib/leftovers.sh
. "$SCRIPT_DIR/lib/leftovers.sh"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-openbao-tls-no-delta-$(date +%s)}"
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
# `init` returns only after its own TLS probe answered on this address,
# so the assertion needs no real wait.  A couple of retries only absorb
# a host-side port-publish blip on a loaded runner.
HTTPS_ASSERT_ATTEMPTS="${HTTPS_ASSERT_ATTEMPTS:-3}"
HTTPS_ASSERT_DELAY_SECS="${HTTPS_ASSERT_DELAY_SECS:-2}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-summary.json"
CA_BUNDLE_PATH="$ARTIFACT_DIR/ca-bundle.pem"

OPENBAO_CONTAINER_NAME="bootroot-openbao"
# Non-loopback bind exercised by the harness.  Defaults to the docker
# bridge gateway for the same reason `run-reinit-recovery.sh` does:
# every host that can run this harness already has the `docker0`
# interface, and a specific (non-wildcard) bind sidesteps the
# `--openbao-advertise-addr` requirement wildcard binds carry.
OPENBAO_BIND_HOST_DEFAULT="172.17.0.1"
OPENBAO_BIND_HOST="${OPENBAO_BIND_HOST:-$OPENBAO_BIND_HOST_DEFAULT}"
OPENBAO_BIND_ADDR="${OPENBAO_BIND_ADDR:-${OPENBAO_BIND_HOST}:8200}"
EXPOSED_OVERRIDE_PATH="$SECRETS_DIR/openbao/docker-compose.openbao-exposed.yml"
OPENBAO_REPO_DIR="$ROOT_DIR/openbao"
OPENBAO_REPO_HCL="$OPENBAO_REPO_DIR/openbao.hcl"
OPENBAO_REPO_CONFIG_DIR="$OPENBAO_REPO_DIR/config"
OPENBAO_REPO_TLS_DIR="$OPENBAO_REPO_DIR/tls"
OPENBAO_HCL_SNAPSHOT="$ARTIFACT_DIR/openbao.hcl.pristine"
OPENBAO_CONFIG_SNAPSHOT="$ARTIFACT_DIR/openbao-config.pristine"
OPENBAO_TLS_SNAPSHOT="$ARTIFACT_DIR/openbao-tls.pristine"
EDGE_SERVICE="edge-proxy"
EDGE_HOSTNAME="edge-node-01"
DOMAIN="trusted.domain"
INSTANCE_ID="001"
DEFAULT_STEPCA_PASSWORD="openbao-tls-no-delta"
DEFAULT_HTTP_HMAC="dev-hmac"
CURRENT_PHASE="startup"
REPO_OPENBAO_SNAPSHOT_TAKEN=0
OPENBAO_CONTAINER_ID_BEFORE_INIT=""

# Pin POSTGRES_HOST_PORT for the compose stack: docker-compose.yml's
# default moved from 5432 to 5433 in #588 §4c; the harness expects 5432
# (CI runners free that port before the matrix) so pin it explicitly
# here to keep compose port mapping aligned with the admin probes.
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
  echo "[openbao-tls-no-delta][${CURRENT_PHASE}] $message" >&2
  exit 1
}

on_error() {
  local line="$1"
  echo "[openbao-tls-no-delta] failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "[openbao-tls-no-delta] artifact dir: ${ARTIFACT_DIR}" >&2
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
  docker compose -p "${COMPOSE_PROJECT_NAME:-bootroot}" -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" "$@"
}

# Teardown output goes to the run log rather than to `/dev/null`: a
# teardown that removed nothing has to be distinguishable from one that
# removed everything.  The status is the caller's to decide — the
# start-of-run call tolerates a failure, `cleanup` does not.
compose_down() {
  compose down -v --remove-orphans >>"$RUN_LOG" 2>&1
}

run_bootroot() {
  ( cd "$WORKSPACE_DIR" && "$BOOTROOT_BIN" "$@" )
}

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v curl >/dev/null 2>&1 || fail "curl is required"
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
}

list_local_ipv4() {
  if command -v ip >/dev/null 2>&1; then
    ip -4 -o addr show | awk '{print $4}' | sed 's|/.*||'
  elif command -v ifconfig >/dev/null 2>&1; then
    ifconfig -a | awk '/inet /{print $2}' | sed 's/^addr://'
  else
    return 1
  fi
}

ensure_bind_host_available() {
  # Verify the configured non-loopback bind host actually exists on this
  # machine; otherwise compose refuses to publish the port and the run
  # fails for a reason that has nothing to do with what it exercises.
  #
  # Not being able to enumerate at all is a different condition from the
  # address being absent, and it has a different fix: no value of the bind
  # host variable helps a host that cannot list its own addresses, so that
  # case must not tell the operator to change the variable.  `pipefail`
  # also routes a present-but-failing `ip` here, whose own stderr now
  # reaches the operator, so the message covers both.
  local bind_host="$1" bind_var="$2" local_addrs
  if ! local_addrs="$(list_local_ipv4)"; then
    fail "cannot enumerate local IPv4 addresses: neither ip (iproute2) nor ifconfig is installed and working"
  fi
  # -F: the bind host is data, not a pattern, so a value carrying regex
  # metacharacters cannot match an address it is not.  `--` for the same
  # reason one argument earlier: the value arrives from the environment, and
  # one beginning with a dash is an option to grep rather than the pattern.
  # `-e127.0.0.1` would otherwise be read as a second pattern and match a
  # host holding 127.0.0.1, which is not the address that was configured.
  if ! printf '%s\n' "$local_addrs" | grep -qFx -- "$bind_host"; then
    fail "non-loopback bind host $bind_host is not assigned to any local interface (set $bind_var to an address that is)"
  fi
}

capture_artifacts() {
  compose ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
  compose logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker port "$OPENBAO_CONTAINER_NAME" >"$ARTIFACT_DIR/openbao-port.log" 2>&1 || true
  docker exec -e BAO_ADDR="https://127.0.0.1:8200" -e BAO_SKIP_VERIFY=true \
    "$OPENBAO_CONTAINER_NAME" bao status -format=json \
    >"$ARTIFACT_DIR/openbao-bao-status.log" 2>&1 || true
  if [ -f "$OPENBAO_REPO_HCL" ]; then
    cp "$OPENBAO_REPO_HCL" "$ARTIFACT_DIR/openbao.hcl.post-init" || true
  fi
}

cleanup() {
  local status=$?
  local cleanup_status=0
  log_phase "cleanup"
  capture_artifacts
  # Nothing is torn down before the startup assertion passed: what is on
  # this host then belongs to whoever put it there, and removing it is
  # exactly what the assertion refused to do.
  if stack_owned; then
    if ! compose_down; then
      echo "run-openbao-tls-no-delta: teardown failed; see ${RUN_LOG}" >&2
      cleanup_status=1
    fi
    report_leftover_containers "$COMPOSE_FILE" "run-openbao-tls-no-delta cleanup" || cleanup_status=1
  fi
  restore_repo_openbao_config
  exit_with_cleanup_status "$status" "$cleanup_status"
}

# See `run-reinit-recovery.sh`: `init` rewrites the repo-level
# `openbao/openbao.hcl` (mounted `:ro`) to a TLS listener and drops the
# issued server cert under `openbao/tls/`.  Both persist after the
# script exits, so restore the checkout to its pre-run state.
snapshot_repo_openbao_config() {
  if [ -f "$OPENBAO_REPO_HCL" ]; then
    cp "$OPENBAO_REPO_HCL" "$OPENBAO_HCL_SNAPSHOT"
  fi
  if [ -d "$OPENBAO_REPO_CONFIG_DIR" ]; then
    cp -a "$OPENBAO_REPO_CONFIG_DIR" "$OPENBAO_CONFIG_SNAPSHOT"
  fi
  if [ -d "$OPENBAO_REPO_TLS_DIR" ]; then
    cp -a "$OPENBAO_REPO_TLS_DIR" "$OPENBAO_TLS_SNAPSHOT"
  fi
  REPO_OPENBAO_SNAPSHOT_TAKEN=1
}

restore_repo_openbao_config() {
  if [ "$REPO_OPENBAO_SNAPSHOT_TAKEN" != "1" ]; then
    return 0
  fi
  if [ -f "$OPENBAO_HCL_SNAPSHOT" ]; then
    cp "$OPENBAO_HCL_SNAPSHOT" "$OPENBAO_REPO_HCL"
  fi
  rm -rf "$OPENBAO_REPO_CONFIG_DIR"
  if [ -d "$OPENBAO_CONFIG_SNAPSHOT" ]; then
    cp -a "$OPENBAO_CONFIG_SNAPSHOT" "$OPENBAO_REPO_CONFIG_DIR"
  fi
  rm -rf "$OPENBAO_REPO_TLS_DIR"
  if [ -d "$OPENBAO_TLS_SNAPSHOT" ]; then
    cp -a "$OPENBAO_TLS_SNAPSHOT" "$OPENBAO_REPO_TLS_DIR"
  fi
}

# Uses the public sys/seal-status endpoint, which answers even while the
# vault is sealed, so the probe needs no token.  `-k` is deliberate: the
# probe runs before and across the TLS transition and only proves the
# listener answers at all.  The assertions below are the ones that
# verify the certificate.
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

wait_for_postgres_admin() {
  local host_port="${POSTGRES_HOST_PORT:-5432}"
  local admin_user="${POSTGRES_USER:-step}"
  local attempt
  for attempt in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    if docker exec bootroot-postgres pg_isready -h 127.0.0.1 -U "$admin_user" -d postgres >/dev/null 2>&1 &&
      bash -lc ": >/dev/tcp/127.0.0.1/${host_port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  fail "postgres admin endpoint did not become reachable"
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
http_responder_hmac = "${DEFAULT_HTTP_HMAC}"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300
EOF
}

reset_workspace() {
  rm -f "$WORKSPACE_DIR/state.json"
  rm -rf "$SECRETS_DIR/config" "$SECRETS_DIR/certs" "$SECRETS_DIR/db" \
    "$SECRETS_DIR/secrets" "$SECRETS_DIR/openbao" "$SECRETS_DIR/step-ca" \
    "$SECRETS_DIR/templates" "$SECRETS_DIR/responder" \
    "$SECRETS_DIR/password.txt" "$SECRETS_DIR/password.txt.new"
  rm -f "$ROOT_DIR/.env"
}

install_infra_with_bind() {
  reset_workspace
  run_bootroot infra install \
    --compose-file "$COMPOSE_FILE" \
    --openbao-bind "$OPENBAO_BIND_ADDR" \
    --openbao-tls-required >>"$RUN_LOG" 2>&1
}

# The precondition #737 is about: the override is applied by someone
# other than `init`, so `init`'s own bring-up has no compose delta to
# ride on.  Applied with the same file set `init` uses (base compose +
# override, no test overlay) so the merged `openbao` service config is
# byte-identical to the one `init` would compute — which is exactly what
# makes a plain `up -d` a no-op.
apply_exposed_override_by_hand() {
  log_phase "apply-override-by-hand"
  [ -f "$EXPOSED_OVERRIDE_PATH" ] \
    || fail "expected infra install to write $EXPOSED_OVERRIDE_PATH"
  # The API listener must still be plaintext at this point, otherwise
  # the scenario is not reproducing the no-delta case at all.  Keyed on
  # `tls_cert_file`, which only the TLS rewrite emits: the telemetry
  # listener keeps `tls_disable = 1` in both variants.
  if grep -q 'tls_cert_file' "$OPENBAO_REPO_HCL"; then
    fail "openbao.hcl already carries a TLS listener before init (see $OPENBAO_REPO_HCL)"
  fi
  docker compose -p "${COMPOSE_PROJECT_NAME:-bootroot}" -f "$COMPOSE_FILE" -f "$EXPOSED_OVERRIDE_PATH" up -d openbao \
    >>"$RUN_LOG" 2>&1 || fail "failed to apply the openbao-exposed override by hand"
  # The override replaces the base compose port list (`ports: !override`),
  # so from here on OpenBao is published only on the bind address — which
  # is why `init` below is pointed at it with `--openbao-url`.
  wait_for_openbao_listening "http://${OPENBAO_BIND_ADDR}"
  OPENBAO_CONTAINER_ID_BEFORE_INIT="$(docker inspect -f '{{.Id}}' "$OPENBAO_CONTAINER_NAME")"
  [ -n "$OPENBAO_CONTAINER_ID_BEFORE_INIT" ] \
    || fail "failed to read the pre-init OpenBao container id"
}

run_init() {
  log_phase "init"
  wait_for_postgres_admin
  # `infra install` writes state.json (to record the bind intent) before
  # init runs, so init's overwrite prompts fire.  Answer them with their
  # per-prompt flags and run with stdin closed: the run must stay
  # non-interactive, which also proves the post-recreate unseal takes
  # its keys from the ones init itself generated rather than a prompt.
  if ! BOOTROOT_LANG=en run_bootroot init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --openbao-url "http://${OPENBAO_BIND_ADDR}" \
    --summary-json "$INIT_SUMMARY_JSON" \
    --enable auto-generate,show-secrets,db-provision \
    --stepca-password "$DEFAULT_STEPCA_PASSWORD" \
    --http-hmac "$DEFAULT_HTTP_HMAC" \
    --no-eab \
    --save-unseal-keys \
    --overwrite-password \
    --overwrite-ca-json \
    --overwrite-state \
    --confirm-db-provision \
    --db-user "step" \
    --db-name "stepca" \
    --responder-url "http://localhost:8080" \
    --skip responder-check </dev/null >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 200 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
    fail "bootroot init failed"
  fi
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$INIT_LOG"
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

build_ca_bundle() {
  [ -f "$SECRETS_DIR/certs/root_ca.crt" ] || fail "missing $SECRETS_DIR/certs/root_ca.crt"
  [ -f "$SECRETS_DIR/certs/intermediate_ca.crt" ] \
    || fail "missing $SECRETS_DIR/certs/intermediate_ca.crt"
  cat "$SECRETS_DIR/certs/root_ca.crt" "$SECRETS_DIR/certs/intermediate_ca.crt" \
    >"$CA_BUNDLE_PATH"
}

# The container must have been replaced: `openbao.hcl` is bind-mounted,
# so the only way the running process loads the TLS listener config is a
# recreate.  Before #737 this was a no-op whenever the override was
# already applied, and the old plaintext process kept serving.
assert_openbao_container_recreated() {
  local after
  after="$(docker inspect -f '{{.Id}}' "$OPENBAO_CONTAINER_NAME")"
  if [ "$after" = "$OPENBAO_CONTAINER_ID_BEFORE_INIT" ]; then
    fail "init did not recreate the OpenBao container (id still ${after}); the process is still running the pre-init plaintext configuration"
  fi
}

# Verifies against the local step-ca bundle — no `-k`, so this fails
# both for a plaintext listener and for a certificate the bundle does
# not chain to.  The response doubles as the seal-status assertion.
assert_https_bind_serves_tls() {
  build_ca_bundle
  local out="$ARTIFACT_DIR/seal-status-https.json"
  local attempt
  for attempt in $(seq 1 "$HTTPS_ASSERT_ATTEMPTS"); do
    if curl --cacert "$CA_BUNDLE_PATH" -fsS -m 10 \
        "https://${OPENBAO_BIND_ADDR}/v1/sys/seal-status" >"$out" 2>>"$RUN_LOG"; then
      return 0
    fi
    sleep "$HTTPS_ASSERT_DELAY_SECS"
  done
  fail "https://${OPENBAO_BIND_ADDR}/v1/sys/seal-status did not answer over TLS (see $RUN_LOG)"
}

# The transition has to be a transition: a listener that still serves
# the OpenBao API over plain HTTP at the recorded address would mean
# `state.json` is lying about the scheme.
#
# A TLS listener does answer a plaintext request — Go replies
# `400 Client sent an HTTP request to an HTTPS server` — so the
# assertion is on the API response, not on the connection failing: only
# a real `200` carrying a `sealed` field means the listener is still
# plaintext.
assert_plain_http_bind_rejected() {
  local out="$ARTIFACT_DIR/seal-status-plain-http.txt"
  local code
  code="$(curl -sS -o "$out" -w '%{http_code}' -m 5 \
    "http://${OPENBAO_BIND_ADDR}/v1/sys/seal-status" 2>>"$RUN_LOG" || true)"
  {
    echo "plain-http probe: status=${code}"
    cat "$out" 2>/dev/null || true
  } >>"$RUN_LOG"
  if [ "$code" = "200" ] && jq -e 'has("sealed")' "$out" >/dev/null 2>&1; then
    fail "http://${OPENBAO_BIND_ADDR} still serves the OpenBao API over plain HTTP; the listener never switched to TLS"
  fi
}

assert_state_records_https_url() {
  local url
  url="$(jq -r '.openbao_url // empty' "$WORKSPACE_DIR/state.json")"
  if [ "$url" != "https://${OPENBAO_BIND_ADDR}" ]; then
    fail "state.json openbao_url='${url}' expected 'https://${OPENBAO_BIND_ADDR}'"
  fi
}

# `init` recreates the container, which brings the Shamir-sealed vault
# back sealed.  It has to unseal it again before returning, otherwise
# every command that consumes `state.openbao_url` fails on AppRole login.
assert_openbao_unsealed() {
  local sealed
  sealed="$(jq -r '.sealed' "$ARTIFACT_DIR/seal-status-https.json")"
  if [ "$sealed" != "false" ]; then
    fail "OpenBao is still sealed after init returned (sealed=${sealed}); init must unseal after the TLS recreate"
  fi
}

# The end-to-end contract: a state-backed command works immediately,
# with no manual unseal and no scheme fix-up.
assert_service_add_succeeds() {
  log_phase "service-add"
  local role_id secret_id
  role_id="$(jq -r '.approles[] | select(.label == "runtime_service_add") | .role_id // empty' "$INIT_SUMMARY_JSON")"
  secret_id="$(jq -r '.approles[] | select(.label == "runtime_service_add") | .secret_id // empty' "$INIT_SUMMARY_JSON")"
  [ -n "$role_id" ] || fail "failed to parse runtime_service_add role_id"
  [ -n "$secret_id" ] || fail "failed to parse runtime_service_add secret_id"

  if ! run_bootroot service add \
    --service-name "$EDGE_SERVICE" --delivery-mode local-file \
    --hostname "$EDGE_HOSTNAME" --domain "$DOMAIN" \
    --agent-config "$AGENT_CONFIG_PATH" \
    --cert-path "$CERTS_DIR/${EDGE_SERVICE}.crt" \
    --key-path "$CERTS_DIR/${EDGE_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$role_id" \
    --approle-secret-id "$secret_id" >"$ARTIFACT_DIR/service-add.log" 2>&1; then
    {
      echo "service add failed (tail):"
      tail -n 120 "$ARTIFACT_DIR/service-add.log" || true
    } >>"$RUN_LOG"
    fail "service add failed immediately after init; the vault is sealed or state.openbao_url is wrong"
  fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  mkdir -p "$ARTIFACT_DIR" "$WORKSPACE_DIR" "$CERTS_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  ensure_prerequisites
  ensure_bind_host_available "$OPENBAO_BIND_HOST" OPENBAO_BIND_HOST
  # The assertion comes first, before the teardown and before anything
  # else that could remove a container.  A `down -v` at this project
  # would take a real install on this host with it, volumes and all, and
  # leave the check reading a daemon it had just cleaned — and a killed
  # run's leftovers, which the check exists to report, are
  # indistinguishable from that install to everything but an operator.
  assert_no_leftover_containers "$COMPOSE_FILE" "run-openbao-tls-no-delta startup"
  # Past the assertion nothing here is anyone else's, so the stack
  # becomes this run's to remove.  The teardown takes the volumes,
  # networks and orphans the assertion does not look at, and may
  # legitimately find nothing to do, so its status is not fatal.
  mark_stack_owned
  compose_down || true
  snapshot_repo_openbao_config

  log_phase "install"
  write_agent_config
  install_infra_with_bind
  # `infra install` brings the stack up on the base compose file, so
  # OpenBao is still published on loopback at this point.
  wait_for_openbao_listening "http://127.0.0.1:8200"

  apply_exposed_override_by_hand
  run_init

  log_phase "assert"
  assert_openbao_container_recreated
  assert_https_bind_serves_tls
  assert_plain_http_bind_rejected
  assert_state_records_https_url
  assert_openbao_unsealed
  assert_service_add_succeeds

  log_phase "done"
}

main "$@"
