#!/usr/bin/env bash
set -euo pipefail

# Docker-backed E2E harness for re-issuing the OpenBao TLS server
# certificate after `secrets/` has been re-owned to a different uid
# (#739).
#
# `openbao/tls` is a sibling of `secrets/`, not a child.  `init` creates
# it in the host bootroot process and the `step` container writes
# `server.{crt,key}` into it as the owner of `secrets/` at that moment,
# so both freeze that first owner.  The secrets-ownership sweep mounts
# only `secrets/`, so nothing moves `openbao/tls` when an operator or an
# external installer later re-owns the secrets tree — for example to the
# uid the OpenBao Agent sidecars must run as.  The next
# `rotate infra-cert` then runs the `step` container as the new uid
# against a directory and files still owned by the old one and dies with
# `open /output/server.key: permission denied`.
#
# This harness reproduces exactly that precondition:
#
#   1. `infra install --openbao-bind <ip>:8200 --openbao-tls-required`
#      + `bootroot init`, which issues the certificate as the invoking
#      user (the current `secrets/` owner)
#   2. `chown -R` the whole `secrets/` tree to a different non-root
#      uid:gid, leaving `openbao/tls` on the old owner
#   3. `bootroot rotate infra-cert --yes` as root
#
# and then asserts the contracts #739 introduces:
#
#   - the rotation exits zero
#   - `openbao/tls` and the files inside it are owned by the *new*
#     `secrets/` owner
#   - `server.crt` carries a different serial than before the rotation
#   - the leaf the OpenBao listener serves is the one now on disk
#   - `server.{crt,key}` are still mode 0644, so the OpenBao container
#     can read them through its `:ro` mount
#   - a second rotation on the unchanged deployment still succeeds, so
#     the chown is a no-op when ownership is already correct

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-openbao-tls-reown-$(date +%s)}"
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
# `init` and `rotate infra-cert` both return only after their own TLS
# probe answered, so the assertions need no real wait.  A couple of
# retries only absorb a host-side blip on a loaded runner.
TLS_ASSERT_ATTEMPTS="${TLS_ASSERT_ATTEMPTS:-3}"
TLS_ASSERT_DELAY_SECS="${TLS_ASSERT_DELAY_SECS:-2}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-summary.json"
CA_BUNDLE_PATH="$ARTIFACT_DIR/ca-bundle.pem"

OPENBAO_CONTAINER_NAME="bootroot-openbao"
# Non-loopback bind exercised by the harness.  Defaults to the docker
# bridge gateway for the same reason `run-openbao-tls-no-delta.sh` does:
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
OPENBAO_SERVER_CRT="$OPENBAO_REPO_TLS_DIR/server.crt"
OPENBAO_SERVER_KEY="$OPENBAO_REPO_TLS_DIR/server.key"
OPENBAO_HCL_SNAPSHOT="$ARTIFACT_DIR/openbao.hcl.pristine"
OPENBAO_CONFIG_SNAPSHOT="$ARTIFACT_DIR/openbao-config.pristine"
OPENBAO_TLS_SNAPSHOT="$ARTIFACT_DIR/openbao-tls.pristine"
DOMAIN="trusted.domain"
DEFAULT_STEPCA_PASSWORD="openbao-tls-reown"
DEFAULT_HTTP_HMAC="dev-hmac"
# The uid:gid the secrets tree is handed to after `init`.  Mirrors the
# field case (#739): a non-root uid that is not the one bootroot ran as,
# and one that need not exist as a host account for `chown` to accept it.
REOWN_UID="${REOWN_UID:-100}"
REOWN_GID="${REOWN_GID:-1000}"
CURRENT_PHASE="startup"
REPO_OPENBAO_SNAPSHOT_TAKEN=0
OWNERSHIP_CHANGED=0
SERIAL_BEFORE=""
SERVED_FINGERPRINT_BEFORE=""

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
  echo "[openbao-tls-reown][${CURRENT_PHASE}] $message" >&2
  exit 1
}

on_error() {
  local line="$1"
  echo "[openbao-tls-reown] failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "[openbao-tls-reown] artifact dir: ${ARTIFACT_DIR}" >&2
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

run_bootroot() {
  ( cd "$WORKSPACE_DIR" && "$BOOTROOT_BIN" "$@" )
}

run_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi
  sudo -n "$@"
}

# Finding *an* `openssl` on PATH is not enough. macOS ships LibreSSL as
# /usr/bin/openssl, and LibreSSL 3.3.6 has no `x509 -ext` — an OpenSSL
# 1.1.1 addition, and how the harness reads a certificate's
# subjectAltName. Probe for that option rather than for the string
# `OpenSSL` in `openssl version`: the harness needs the capability, not
# a particular implementation, and a build that grows the option should
# pass. Every matrix script checks this even where it makes no `-ext`
# call, because the ten steps run against one host: a host that cannot
# serve the SAN step cannot serve the matrix, and learning that at that
# step costs every step before it.
ensure_openssl() {
  local openssl_bin x509_help
  openssl_bin="$(command -v openssl 2>/dev/null || true)"
  [ -n "$openssl_bin" ] || fail "openssl is required"
  # `x509 -help` exits non-zero on some builds (LibreSSL 3.3.6 does), so
  # capture the text and let the match alone decide.  A here-string, not
  # a pipe: `grep -q` exits on the first match, and under `pipefail` the
  # writer's SIGPIPE would then fail the very check that just passed.
  x509_help="$(openssl x509 -help 2>&1 || true)"
  grep -qE '^[[:space:]]*-ext([[:space:]]|$)' <<<"$x509_help" || fail \
    "openssl at ${openssl_bin} does not support 'x509 -ext', which this harness needs to read a certificate's subjectAltName; put a directory holding an openssl that supports it first on PATH"
}

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v curl >/dev/null 2>&1 || fail "curl is required"
  ensure_openssl
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  # Re-owning the secrets tree to a foreign uid needs CAP_CHOWN, and the
  # rotation then has to run as root because it is no longer the owner
  # of `secrets/` — the deployment shape #739 is about.
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || fail "this harness re-owns secrets/ and needs root or sudo"
    sudo -n true >/dev/null 2>&1 \
      || fail "this harness needs non-interactive sudo (sudo -n) to re-own secrets/ and run the rotation as root"
  fi
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
  run_sudo ls -ln "$OPENBAO_REPO_TLS_DIR" >"$ARTIFACT_DIR/openbao-tls-ownership.log" 2>&1 || true
  run_sudo ls -ln "$SECRETS_DIR" >"$ARTIFACT_DIR/secrets-ownership.log" 2>&1 || true
  if [ -f "$OPENBAO_REPO_HCL" ]; then
    cp "$OPENBAO_REPO_HCL" "$ARTIFACT_DIR/openbao.hcl.post-init" || true
  fi
}

cleanup() {
  log_phase "cleanup"
  capture_artifacts
  restore_ownership
  compose_down
  restore_repo_openbao_config
}

# The rotation runs as root over a secrets tree owned by a foreign uid,
# so both trees and every file root wrote (state.json, the renewed cert)
# are left unreadable/undeletable by the invoking user.  Hand them back
# before anything else in cleanup touches them.
restore_ownership() {
  if [ "$OWNERSHIP_CHANGED" != "1" ]; then
    return 0
  fi
  local owner
  owner="$(id -u):$(id -g)"
  run_sudo chown -R -h "$owner" "$SECRETS_DIR" >/dev/null 2>&1 || true
  run_sudo chown -R -h "$owner" "$OPENBAO_REPO_TLS_DIR" >/dev/null 2>&1 || true
  run_sudo chown -R -h "$owner" "$WORKSPACE_DIR" >/dev/null 2>&1 || true
  run_sudo chown -R -h "$owner" "$ARTIFACT_DIR" >/dev/null 2>&1 || true
  OWNERSHIP_CHANGED=0
}

# See `run-openbao-tls-no-delta.sh`: `init` rewrites the repo-level
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
# probe runs across the plaintext -> TLS transition and only proves the
# listener answers at all.  The assertions below verify the certificate.
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

# Applied for the same reason `run-openbao-tls-no-delta.sh` does it: the
# override republishes OpenBao on the bind address only, and `init` is
# pointed at that address below.
apply_exposed_override() {
  log_phase "apply-override"
  [ -f "$EXPOSED_OVERRIDE_PATH" ] \
    || fail "expected infra install to write $EXPOSED_OVERRIDE_PATH"
  docker compose -p "${COMPOSE_PROJECT_NAME:-bootroot}" -f "$COMPOSE_FILE" -f "$EXPOSED_OVERRIDE_PATH" up -d openbao \
    >>"$RUN_LOG" 2>&1 || fail "failed to apply the openbao-exposed override"
  wait_for_openbao_listening "http://${OPENBAO_BIND_ADDR}"
}

run_init() {
  log_phase "init"
  wait_for_postgres_admin
  # `infra install` writes state.json (to record the bind intent) before
  # init runs, so init's overwrite prompts fire.  Answer them with their
  # per-prompt flags and run with stdin closed so the run stays
  # non-interactive.
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

# Hands the whole secrets tree to a uid bootroot never ran as — the
# supported deployment shape that strands `openbao/tls` on the old
# owner.  From here on bootroot has to run as root.
reown_secrets_tree() {
  log_phase "reown-secrets"
  local before_uid
  before_uid="$(stat -c '%u' "$SECRETS_DIR")"
  if [ "$before_uid" = "$REOWN_UID" ]; then
    fail "secrets/ is already owned by uid ${REOWN_UID}; the re-own would be a no-op (set REOWN_UID to a different uid)"
  fi
  # Armed before the chown, not after: a `chown -R` that fails partway
  # has already stranded part of the tree on the foreign uid, and only
  # `restore_ownership` can hand it back.
  OWNERSHIP_CHANGED=1
  run_sudo chown -R -h "${REOWN_UID}:${REOWN_GID}" "$SECRETS_DIR" \
    || fail "failed to re-own $SECRETS_DIR to ${REOWN_UID}:${REOWN_GID}"
  {
    echo "secrets/ re-owned: ${before_uid} -> ${REOWN_UID}:${REOWN_GID}"
    ls -ln "$OPENBAO_REPO_TLS_DIR" 2>/dev/null || true
  } >>"$RUN_LOG"
  # The skew the fix is about: the certificate output directory did not
  # move with the secrets tree.  Without it the rotation below would
  # prove nothing.
  local tls_uid
  tls_uid="$(stat -c '%u' "$OPENBAO_REPO_TLS_DIR")"
  if [ "$tls_uid" = "$REOWN_UID" ]; then
    fail "openbao/tls is already owned by uid ${REOWN_UID}; the harness is not reproducing the ownership skew"
  fi
}

rotate_infra_cert() {
  local label="$1"
  local log="$ARTIFACT_DIR/rotate-${label}.log"
  # Runs as root: bootroot is no longer the owner of `secrets/`, and the
  # constraint the code relies on is that it is root or that owner.
  if ! run_sudo env BOOTROOT_LANG=en "$BOOTROOT_BIN" rotate \
    --state-file "$WORKSPACE_DIR/state.json" \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    infra-cert --yes </dev/null >"$log" 2>&1; then
    {
      echo "rotate infra-cert (${label}) failed (tail):"
      tail -n 120 "$log" || true
    } >>"$RUN_LOG"
    fail "bootroot rotate infra-cert failed (${label}); see $log"
  fi
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

file_leaf_fingerprint() {
  openssl x509 -in "$OPENBAO_SERVER_CRT" -noout -fingerprint -sha256 \
    | sed 's/^.*=//'
}

# The leaf the listener actually presents.  `-servername` mirrors what a
# real client sends; the handshake result is only used for a byte
# comparison against the file, so no trust decision rides on it.
served_leaf_fingerprint() {
  local attempt
  for attempt in $(seq 1 "$TLS_ASSERT_ATTEMPTS"); do
    local pem
    pem="$(openssl s_client -connect "$OPENBAO_BIND_ADDR" \
      -servername openbao.internal </dev/null 2>/dev/null || true)"
    if [ -n "$pem" ]; then
      local fp
      fp="$(printf '%s\n' "$pem" | openssl x509 -noout -fingerprint -sha256 2>/dev/null \
        | sed 's/^.*=//' || true)"
      if [ -n "$fp" ]; then
        printf '%s\n' "$fp"
        return 0
      fi
    fi
    sleep "$TLS_ASSERT_DELAY_SECS"
  done
  return 1
}

cert_serial() {
  openssl x509 -in "$OPENBAO_SERVER_CRT" -noout -serial | sed 's/^.*=//'
}

# `init` on a host whose `secrets/` is owned by the invoking user must
# behave exactly as before: files issued, mode 0644, owned by that user.
assert_post_init_baseline() {
  log_phase "assert-post-init"
  build_ca_bundle
  [ -f "$OPENBAO_SERVER_CRT" ] || fail "init did not write $OPENBAO_SERVER_CRT"
  [ -f "$OPENBAO_SERVER_KEY" ] || fail "init did not write $OPENBAO_SERVER_KEY"
  assert_tls_files_mode_0644 "post-init"
  local owner expected
  expected="$(id -u):$(id -g)"
  owner="$(stat -c '%u:%g' "$OPENBAO_REPO_TLS_DIR")"
  [ "$owner" = "$expected" ] \
    || fail "openbao/tls owner after init is ${owner}, expected the invoking user ${expected}"
  SERIAL_BEFORE="$(cert_serial)"
  SERVED_FINGERPRINT_BEFORE="$(served_leaf_fingerprint)" \
    || fail "OpenBao listener at ${OPENBAO_BIND_ADDR} did not present a certificate after init"
  {
    echo "post-init serial: ${SERIAL_BEFORE}"
    echo "post-init served fingerprint: ${SERVED_FINGERPRINT_BEFORE}"
  } >>"$RUN_LOG"
}

assert_tls_files_mode_0644() {
  local label="$1"
  local path mode
  for path in "$OPENBAO_SERVER_CRT" "$OPENBAO_SERVER_KEY"; do
    mode="$(stat -c '%a' "$path")"
    [ "$mode" = "644" ] \
      || fail "${label}: $(basename "$path") is mode ${mode}, expected 644 (the OpenBao container reads it through a :ro mount)"
  done
}

# The acceptance contract of #739: after the rotation the output
# directory and its contents belong to the resolved `secrets/` owner.
assert_tls_dir_owned_by_secrets_owner() {
  local label="$1"
  local expected="${REOWN_UID}:${REOWN_GID}"
  local path owner
  for path in "$OPENBAO_REPO_TLS_DIR" "$OPENBAO_SERVER_CRT" "$OPENBAO_SERVER_KEY"; do
    owner="$(stat -c '%u:%g' "$path")"
    [ "$owner" = "$expected" ] \
      || fail "${label}: $(basename "$path") is owned by ${owner}, expected the secrets owner ${expected}"
  done
}

# A rotation that silently reused the old file would keep the serial.
assert_certificate_reissued() {
  local label="$1"
  local serial_after
  serial_after="$(cert_serial)"
  echo "${label} serial: ${serial_after} (was ${SERIAL_BEFORE})" >>"$RUN_LOG"
  [ -n "$serial_after" ] || fail "${label}: failed to read the serial of $OPENBAO_SERVER_CRT"
  [ "$serial_after" != "$SERIAL_BEFORE" ] \
    || fail "${label}: server.crt still carries serial ${serial_after}; the certificate was not re-issued"
  SERIAL_BEFORE="$serial_after"
}

# The reload has to have landed: the listener must serve the leaf that
# is now on disk, and not the one it served before the rotation.
assert_listener_serves_disk_leaf() {
  local label="$1"
  local served file
  served="$(served_leaf_fingerprint)" \
    || fail "${label}: OpenBao listener at ${OPENBAO_BIND_ADDR} did not present a certificate"
  file="$(file_leaf_fingerprint)"
  echo "${label} served=${served} file=${file}" >>"$RUN_LOG"
  [ "$served" = "$file" ] \
    || fail "${label}: the listener serves ${served} but $OPENBAO_SERVER_CRT holds ${file}; the reload did not take effect"
  [ "$served" != "$SERVED_FINGERPRINT_BEFORE" ] \
    || fail "${label}: the listener still serves the pre-rotation leaf ${served}"
  SERVED_FINGERPRINT_BEFORE="$served"
}

# The renewed leaf still chains to the local CA and the vault is still
# unsealed, so the rotation did not cost availability.
assert_https_still_trusted_and_unsealed() {
  local label="$1"
  local out="$ARTIFACT_DIR/seal-status-${label}.json"
  local attempt
  for attempt in $(seq 1 "$TLS_ASSERT_ATTEMPTS"); do
    if curl --cacert "$CA_BUNDLE_PATH" -fsS -m 10 \
        "https://${OPENBAO_BIND_ADDR}/v1/sys/seal-status" >"$out" 2>>"$RUN_LOG"; then
      local sealed
      sealed="$(jq -r '.sealed' "$out")"
      [ "$sealed" = "false" ] \
        || fail "${label}: OpenBao is sealed after the rotation (sealed=${sealed})"
      return 0
    fi
    sleep "$TLS_ASSERT_DELAY_SECS"
  done
  fail "${label}: https://${OPENBAO_BIND_ADDR} did not answer over TLS against the local CA bundle"
}

assert_rotation_outcome() {
  local label="$1"
  log_phase "assert-${label}"
  assert_tls_dir_owned_by_secrets_owner "$label"
  assert_tls_files_mode_0644 "$label"
  assert_certificate_reissued "$label"
  assert_listener_serves_disk_leaf "$label"
  assert_https_still_trusted_and_unsealed "$label"
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
  compose_down
  snapshot_repo_openbao_config

  log_phase "install"
  write_agent_config
  install_infra_with_bind
  # `infra install` brings the stack up on the base compose file, so
  # OpenBao is still published on loopback at this point.
  wait_for_openbao_listening "http://127.0.0.1:8200"

  apply_exposed_override
  run_init
  assert_post_init_baseline

  reown_secrets_tree

  log_phase "rotate-first"
  rotate_infra_cert "first"
  assert_rotation_outcome "first"

  # The chown must be a no-op on a tree whose ownership is already
  # correct, so a second rotation on the unchanged deployment succeeds.
  log_phase "rotate-second"
  rotate_infra_cert "second"
  assert_rotation_outcome "second"

  log_phase "done"
}

main "$@"
