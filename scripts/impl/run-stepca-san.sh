#!/usr/bin/env bash
set -euo pipefail

# Docker-backed E2E harness for step-ca's certificate SANs (#733).
#
# `step ca init` used to be invoked with a compile-time `--dns`
# constant, so step-ca's own serving certificate carried no SAN for the
# address `--stepca-bind` publishes it on.  Any consumer that is not on
# the bootroot host had to reach the ACME directory by that address and
# TLS verification failed there, which is a hard stop for every off-host
# consumer installed through the remote-bootstrap path.
#
# Two scenarios, each against its own stack:
#
#   scenario-a  fresh path — `infra install --stepca-bind <ip>:9000`
#               then `bootroot init` on an empty workspace
#   scenario-b  already-initialized path — `init` on loopback first,
#               then `infra install --stepca-bind <ip>:9000` and a
#               second `init`
#
# Both assert the same two contracts against the running step-ca:
#
#   - the presented certificate carries `IP Address:<ip>` (an IP SAN,
#     not a `DNS:` entry, which would not satisfy verification of a
#     connection made to that address)
#   - `curl --cacert <ca-bundle> https://<ip>:9000/acme/acme/directory`
#     returns the ACME directory with no hostname-verification error
#
# Scenario B additionally asserts that the repair is non-destructive:
# the root and intermediate fingerprints are unchanged across the
# second `init`, and the CA bundle captured *before* it still validates
# the chain afterwards.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-stepca-san-$(date +%s)}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$ARTIFACT_DIR/workspace}"
SECRETS_DIR="${SECRETS_DIR:-$ROOT_DIR/secrets}"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
INFRA_READY_ATTEMPTS="${INFRA_READY_ATTEMPTS:-40}"
INFRA_READY_DELAY_SECS="${INFRA_READY_DELAY_SECS:-3}"
OPENBAO_READY_ATTEMPTS="${OPENBAO_READY_ATTEMPTS:-40}"
OPENBAO_READY_DELAY_SECS="${OPENBAO_READY_DELAY_SECS:-2}"
STEPCA_READY_ATTEMPTS="${STEPCA_READY_ATTEMPTS:-40}"
STEPCA_READY_DELAY_SECS="${STEPCA_READY_DELAY_SECS:-3}"
CA_JSON_ATTEMPTS="${CA_JSON_ATTEMPTS:-10}"
CA_JSON_DELAY_SECS="${CA_JSON_DELAY_SECS:-2}"
# Must exceed the OpenBao Agent render interval bootroot writes into the
# sidecar config (`STATIC_SECRET_RENDER_INTERVAL`, 30s), so at least one
# full render cycle is observed before the stability re-check.
STEPCA_RENDER_STABILITY_SECS="${STEPCA_RENDER_STABILITY_SECS:-40}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
CERT_META_DIR="$ARTIFACT_DIR/cert-meta"
SNAPSHOT_DIR="$ARTIFACT_DIR/snapshots"

# Non-loopback bind exercised by the harness.  Defaults to the docker
# bridge gateway for the same reason `run-reinit-recovery.sh` does:
# every host that can run this harness already has the `docker0`
# interface, and the address is non-loopback for the purposes of
# `validate_stepca_bind`.  A specific (non-wildcard) bind sidesteps the
# `--stepca-advertise-addr` requirement that wildcard binds carry.
STEPCA_BIND_HOST_DEFAULT="172.17.0.1"
STEPCA_BIND_HOST="${STEPCA_BIND_HOST:-$STEPCA_BIND_HOST_DEFAULT}"
STEPCA_BIND_PORT="${STEPCA_BIND_PORT:-9000}"
STEPCA_BIND_ADDR="${STEPCA_BIND_ADDR:-${STEPCA_BIND_HOST}:${STEPCA_BIND_PORT}}"
STEPCA_OVERRIDE_PATH="$SECRETS_DIR/step-ca/docker-compose.stepca-exposed.yml"

DEFAULT_STEPCA_PASSWORD="stepca-san"
DEFAULT_HTTP_HMAC="dev-hmac"
CURRENT_PHASE="startup"

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
  echo "[stepca-san][${CURRENT_PHASE}] $message" >&2
  exit 1
}

on_error() {
  local line="$1"
  echo "[stepca-san] failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "[stepca-san] artifact dir: ${ARTIFACT_DIR}" >&2
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

compose_down() {
  compose down -v --remove-orphans >/dev/null 2>&1 || true
}

# Stops the stack without touching the named volumes.
#
# `infra install` pre-binds every core service's *localhost* published
# port (`preflight_compose_published_ports`) before running `docker
# compose up`, and that preflight fires even when a bind override intent
# is recorded — `infra install` always brings the stack up on the base
# compose file.  Scenario B's second install therefore has to run
# against a stopped stack, or the preflight aborts on the ports the
# first init's own containers still hold.  `down -v` is not an option
# there: it would destroy the OpenBao and PostgreSQL volumes the
# already-initialized CA path depends on.
compose_stop() {
  compose stop >/dev/null 2>&1 || true
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
  # metacharacters cannot match an address it is not.
  if ! printf '%s\n' "$local_addrs" | grep -qFx "$bind_host"; then
    fail "non-loopback bind host $bind_host is not assigned to any local interface (set $bind_var to an address that is)"
  fi
}

capture_artifacts() {
  compose ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
  compose logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  if [ -f "$SECRETS_DIR/config/ca.json" ]; then
    jq -c '.dnsNames' "$SECRETS_DIR/config/ca.json" \
      >"$ARTIFACT_DIR/ca-json-dns-names.log" 2>&1 || true
  fi
}

cleanup() {
  log_phase "cleanup"
  capture_artifacts
  compose_down
}

reset_workspace() {
  # Wipe every artefact a previous scenario left behind so each stack
  # starts from a genuinely fresh CA.
  rm -f "$WORKSPACE_DIR/state.json"
  rm -rf "$SECRETS_DIR/config" "$SECRETS_DIR/certs" "$SECRETS_DIR/db" \
    "$SECRETS_DIR/secrets" "$SECRETS_DIR/openbao" "$SECRETS_DIR/step-ca" \
    "$SECRETS_DIR/templates" "$SECRETS_DIR/responder" \
    "$SECRETS_DIR/password.txt" "$SECRETS_DIR/password.txt.new"
  rm -f "$ROOT_DIR/.env"
}

# ---------------------------------------------------------------------------
# Readiness probes
# ---------------------------------------------------------------------------

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
    # Probe over TCP: the initdb bootstrap server listens only on the Unix
    # socket, so a socket-based pg_isready reports ready before the final
    # server (the one init connects to over TCP) is up.
    if docker exec bootroot-postgres pg_isready -h 127.0.0.1 -U "$admin_user" -d postgres >/dev/null 2>&1 &&
      bash -lc ": >/dev/tcp/127.0.0.1/${host_port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  fail "postgres admin endpoint did not become reachable"
}

# Waits for step-ca to complete a TLS handshake on the published bind.
# The repair path restarts step-ca so it re-issues its serving leaf from
# the rewritten `dnsNames`; the container is Started before the ACME
# listener accepts connections.
wait_for_stepca_tls() {
  local addr="$1"
  local attempt
  for attempt in $(seq 1 "$STEPCA_READY_ATTEMPTS"); do
    if openssl s_client -connect "$addr" </dev/null >/dev/null 2>&1; then
      return 0
    fi
    sleep "$STEPCA_READY_DELAY_SECS"
  done
  fail "step-ca did not present a TLS certificate at $addr"
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

# Concatenates the root and intermediate into the same shape a consumer
# receives as its distributed CA bundle.
build_ca_bundle() {
  local out="$1"
  [ -f "$SECRETS_DIR/certs/root_ca.crt" ] || fail "missing $SECRETS_DIR/certs/root_ca.crt"
  [ -f "$SECRETS_DIR/certs/intermediate_ca.crt" ] \
    || fail "missing $SECRETS_DIR/certs/intermediate_ca.crt"
  cat "$SECRETS_DIR/certs/root_ca.crt" "$SECRETS_DIR/certs/intermediate_ca.crt" >"$out"
}

# Asserts the presented leaf carries the bind address as an `iPAddress`
# SAN.  A `DNS:<ip>` entry does NOT satisfy verification of a connection
# made to that IP, so the assertion is deliberately on `IP Address:`.
assert_stepca_ip_san() {
  local label="$1"
  mkdir -p "$CERT_META_DIR"
  local san_file="$CERT_META_DIR/${label}-stepca-san.txt"
  wait_for_stepca_tls "${STEPCA_BIND_HOST}:${STEPCA_BIND_PORT}"
  openssl s_client -connect "${STEPCA_BIND_HOST}:${STEPCA_BIND_PORT}" </dev/null 2>/dev/null \
    | openssl x509 -noout -ext subjectAltName >"$san_file" 2>&1 \
    || fail "[$label] failed to read step-ca's subjectAltName at ${STEPCA_BIND_ADDR}"
  if ! grep -q "IP Address:${STEPCA_BIND_HOST}" "$san_file"; then
    {
      echo "[$label] step-ca SAN dump:"
      cat "$san_file"
    } >>"$RUN_LOG"
    fail "[$label] step-ca certificate is missing 'IP Address:${STEPCA_BIND_HOST}' (see $san_file)"
  fi
}

# Asserts a plain hostname-verifying client reaches the ACME directory
# through the published address using only the CA bundle.
assert_acme_directory_reachable() {
  local label="$1"
  local bundle="$2"
  local out="$ARTIFACT_DIR/acme-directory-${label}.json"
  local attempt
  for attempt in $(seq 1 "$STEPCA_READY_ATTEMPTS"); do
    if curl --cacert "$bundle" -fsS -m 10 \
        "https://${STEPCA_BIND_ADDR}/acme/acme/directory" >"$out" 2>>"$RUN_LOG"; then
      if jq -e '.newNonce' "$out" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep "$STEPCA_READY_DELAY_SECS"
  done
  fail "[$label] curl --cacert could not fetch https://${STEPCA_BIND_ADDR}/acme/acme/directory (see $out)"
}

# `ca.json` is co-owned: bootroot writes it during `init`, and the
# step-ca OpenBao Agent sidecar re-renders it from `ca.json.ctmpl` every
# render interval.  A short retry absorbs a render landing between
# `init` returning and this read; it does NOT absorb a stale render,
# because a sidecar still holding the previous template would never
# produce the expected set (which is what
# `assert_ca_json_dns_names_stable` pins down).
assert_ca_json_dns_names() {
  local label="$1"
  shift
  local ca_json="$SECRETS_DIR/config/ca.json"
  local expected
  expected="$(printf '%s\n' "$@" | jq -R . | jq -s -c .)"
  local actual=""
  local attempt
  for attempt in $(seq 1 "$CA_JSON_ATTEMPTS"); do
    if [ -f "$ca_json" ]; then
      actual="$(jq -c '.dnsNames' "$ca_json" 2>/dev/null || true)"
      [ "$expected" = "$actual" ] && break
    fi
    sleep "$CA_JSON_DELAY_SECS"
  done
  [ -f "$ca_json" ] || fail "[$label] missing $ca_json"
  if [ "$expected" != "$actual" ]; then
    fail "[$label] ca.json dnsNames mismatch: expected $expected got $actual"
  fi
  # The OpenBao-Agent template must carry the same set, otherwise the
  # next agent render inside the container regresses the SAN set.
  local ctmpl="$SECRETS_DIR/templates/ca.json.ctmpl"
  [ -f "$ctmpl" ] || fail "[$label] missing $ctmpl"
  local name
  for name in "$@"; do
    grep -q "\"$name\"" "$ctmpl" \
      || fail "[$label] ca.json.ctmpl does not carry dnsNames entry '$name'"
  done
}

# Re-checks the name set after a full agent render interval has elapsed.
#
# This is the assertion that actually proves the repair sticks: the
# step-ca sidecar keeps rendering `ca.json` from the template it loaded
# at start-up, so an `init` that rewrote `ca.json` without also
# regenerating the template and restarting the sidecar would look
# correct for a few seconds and then silently regress — and step-ca
# would drop the address SAN on its next restart.
assert_ca_json_dns_names_stable() {
  local label="$1"
  shift
  sleep "$STEPCA_RENDER_STABILITY_SECS"
  assert_ca_json_dns_names "$label" "$@"
}

snapshot_ca_fingerprints() {
  local label="$1"
  local dir="$SNAPSHOT_DIR/$label"
  mkdir -p "$dir"
  openssl x509 -in "$SECRETS_DIR/certs/root_ca.crt" -noout -fingerprint -sha256 \
    >"$dir/root_ca.fingerprint"
  openssl x509 -in "$SECRETS_DIR/certs/intermediate_ca.crt" -noout -fingerprint -sha256 \
    >"$dir/intermediate_ca.fingerprint"
  build_ca_bundle "$dir/ca-bundle.pem"
}

assert_ca_fingerprints_unchanged() {
  local label="$1"
  local dir="$SNAPSHOT_DIR/$label"
  local before after
  before="$(cat "$dir/root_ca.fingerprint")"
  after="$(openssl x509 -in "$SECRETS_DIR/certs/root_ca.crt" -noout -fingerprint -sha256)"
  [ "$before" = "$after" ] \
    || fail "[$label] root_ca.crt fingerprint changed (before='$before' after='$after')"
  before="$(cat "$dir/intermediate_ca.fingerprint")"
  after="$(openssl x509 -in "$SECRETS_DIR/certs/intermediate_ca.crt" -noout -fingerprint -sha256)"
  [ "$before" = "$after" ] \
    || fail "[$label] intermediate_ca.crt fingerprint changed (before='$before' after='$after')"
}

# ---------------------------------------------------------------------------
# bootroot drivers
# ---------------------------------------------------------------------------

install_infra() {
  run_bootroot infra install --compose-file "$COMPOSE_FILE" "$@" >>"$RUN_LOG" 2>&1
}

# First `init` of a stack: OpenBao is uninitialised, so init generates
# the root token and unseal keys itself and provisions the database.
run_first_init() {
  local summary_json="$1"
  local raw_log="$2"
  wait_for_postgres_admin
  wait_for_openbao_listening "http://127.0.0.1:8200"
  # `infra install` writes state.json (to record the bind intent) before
  # init runs, so init's overwrite-state prompt fires; ca.json and
  # password.txt prompt too on a rerun, and `db-provision` adds its own
  # confirmation.  Answer all four with their per-prompt flags and run
  # with stdin closed, which proves the run needs no TTY (#735).
  if ! BOOTROOT_LANG=en run_bootroot init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$summary_json" \
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
    --skip responder-check </dev/null >"$raw_log" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 200 "$raw_log" || true
    } >>"$RUN_LOG"
    fail "bootroot init failed"
  fi
}

# Second `init` of the same stack (scenario B).  OpenBao is already
# initialised and comes back sealed after `infra install` recreates the
# container, so the root token and unseal keys captured by the first
# pass are replayed.  The runtime DSN is taken from `ca.json` — the
# first init rotated the temporary `.env` password out — and
# `db-provision` is left off so the existing role is not re-ALTERed.
run_second_init() {
  local first_summary="$1"
  local summary_json="$2"
  local raw_log="$3"
  local root_token unseal_keys db_dsn
  root_token="$(jq -r '.root_token // empty' "$first_summary")"
  [ -n "$root_token" ] || fail "failed to parse root_token from $first_summary"
  unseal_keys="$(jq -r '.unseal_keys | join(",")' "$first_summary")"
  [ -n "$unseal_keys" ] || fail "failed to parse unseal_keys from $first_summary"
  db_dsn="$(jq -r '.db.dataSource // empty' "$SECRETS_DIR/config/ca.json")"
  [ -n "$db_dsn" ] || fail "failed to parse db.dataSource from ca.json"

  wait_for_postgres_admin
  wait_for_openbao_listening "http://127.0.0.1:8200"
  # `db-provision` is off here, so `--confirm-db-provision` is
  # deliberately not passed: the three overwrite flags are enough to run
  # with stdin closed, which also shows the confirmation flag is
  # independent of the feature rather than implied by it (#735).
  if ! BOOTROOT_LANG=en run_bootroot init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$summary_json" \
    --enable auto-generate,show-secrets \
    --root-token "$root_token" \
    --unseal-key "$unseal_keys" \
    --stepca-password "$DEFAULT_STEPCA_PASSWORD" \
    --http-hmac "$DEFAULT_HTTP_HMAC" \
    --db-dsn "$db_dsn" \
    --no-eab \
    --save-unseal-keys \
    --overwrite-password \
    --overwrite-ca-json \
    --overwrite-state \
    --responder-url "http://localhost:8080" \
    --skip responder-check </dev/null >"$raw_log" 2>&1; then
    {
      echo "second bootroot init failed (raw tail):"
      tail -n 200 "$raw_log" || true
    } >>"$RUN_LOG"
    fail "second bootroot init failed"
  fi
}

# ---------------------------------------------------------------------------
# Scenario A: fresh install already carrying the bind intent
# ---------------------------------------------------------------------------

scenario_a_fresh_install_with_bind() {
  log_phase "scenario-a-install"
  compose_down
  reset_workspace
  install_infra --stepca-bind "$STEPCA_BIND_ADDR"

  local bind
  bind="$(jq -r '.stepca_bind_addr // empty' "$WORKSPACE_DIR/state.json")"
  [ "$bind" = "$STEPCA_BIND_ADDR" ] \
    || fail "[scenario-a] state.json stepca_bind_addr='$bind' expected '$STEPCA_BIND_ADDR'"
  [ -f "$STEPCA_OVERRIDE_PATH" ] \
    || fail "[scenario-a] expected compose override at $STEPCA_OVERRIDE_PATH"

  log_phase "scenario-a-init"
  run_first_init "$ARTIFACT_DIR/init-summary-a.json" "$ARTIFACT_DIR/init-a.raw.log"

  log_phase "scenario-a-assert"
  # `step ca init --dns` received the derived set, so the CA was created
  # with the bind IP in `dnsNames` — no reconciliation was needed.
  assert_ca_json_dns_names "scenario-a" \
    "localhost" "bootroot-ca" "stepca.internal" "$STEPCA_BIND_HOST"
  assert_stepca_ip_san "scenario-a"
  build_ca_bundle "$ARTIFACT_DIR/ca-bundle-a.pem"
  assert_acme_directory_reachable "scenario-a" "$ARTIFACT_DIR/ca-bundle-a.pem"
}

# ---------------------------------------------------------------------------
# Scenario B: repair an already-initialized CA
# ---------------------------------------------------------------------------

scenario_b_repair_initialized_ca() {
  log_phase "scenario-b-install-loopback"
  compose_down
  reset_workspace
  install_infra

  log_phase "scenario-b-init-loopback"
  run_first_init "$ARTIFACT_DIR/init-summary-b1.json" "$ARTIFACT_DIR/init-b1.raw.log"

  # No bind intent recorded: the name set must be exactly the three
  # defaults, i.e. today's behaviour is unchanged.
  assert_ca_json_dns_names "scenario-b-loopback" \
    "localhost" "bootroot-ca" "stepca.internal"

  # Capture the CA bundle a consumer would already hold *before* the
  # repair, so the post-repair check proves the chain survived it.
  snapshot_ca_fingerprints "scenario-b"

  log_phase "scenario-b-install-bind"
  # Free the localhost ports the running stack holds so `infra install`'s
  # published-port preflight passes; the volumes (and therefore the
  # initialized OpenBao and the provisioned database) survive.  The
  # install's own `docker compose up` starts the services again.
  compose_stop
  install_infra --stepca-bind "$STEPCA_BIND_ADDR"
  local bind
  bind="$(jq -r '.stepca_bind_addr // empty' "$WORKSPACE_DIR/state.json")"
  [ "$bind" = "$STEPCA_BIND_ADDR" ] \
    || fail "[scenario-b] state.json stepca_bind_addr='$bind' expected '$STEPCA_BIND_ADDR'"

  log_phase "scenario-b-init-repair"
  run_second_init "$ARTIFACT_DIR/init-summary-b1.json" \
    "$ARTIFACT_DIR/init-summary-b2.json" "$ARTIFACT_DIR/init-b2.raw.log"

  log_phase "scenario-b-assert"
  # `step ca init` must NOT have been re-run: the CA identity is intact.
  assert_ca_fingerprints_unchanged "scenario-b"
  assert_ca_json_dns_names "scenario-b-repaired" \
    "localhost" "bootroot-ca" "stepca.internal" "$STEPCA_BIND_HOST"
  assert_stepca_ip_san "scenario-b"
  # The bundle captured before the repair — what an already-provisioned
  # consumer holds — still validates the chain step-ca presents.
  assert_acme_directory_reachable "scenario-b" "$SNAPSHOT_DIR/scenario-b/ca-bundle.pem"

  log_phase "scenario-b-assert-stable"
  # The repair must survive the step-ca sidecar's next render: the agent
  # was already running with the pre-repair template when `init` started.
  assert_ca_json_dns_names_stable "scenario-b-stable" \
    "localhost" "bootroot-ca" "stepca.internal" "$STEPCA_BIND_HOST"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  mkdir -p "$ARTIFACT_DIR" "$WORKSPACE_DIR" "$CERT_META_DIR" "$SNAPSHOT_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  ensure_prerequisites
  ensure_bind_host_available "$STEPCA_BIND_HOST" STEPCA_BIND_HOST

  scenario_a_fresh_install_with_bind
  scenario_b_repair_initialized_ca

  log_phase "done"
}

main "$@"
