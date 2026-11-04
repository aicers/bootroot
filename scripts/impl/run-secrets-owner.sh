#!/usr/bin/env bash
set -euo pipefail

# Docker-backed E2E harness for a root-run `infra install` and `init`
# over a `secrets/` directory owned by a dedicated non-root account.
#
# bootroot is built for a `secrets/` owned by a non-root account:
# step-ca, both OpenBao Agent sidecars and every `step` helper run as
# that owner.  An installer that hands `secrets/` to such an account
# and then runs `bootroot infra install` and `init` as root expects
# every entry under `secrets/` to stay that account's and every
# directory there to be `0700`.  This harness is that installer:
#
#   1. creates a fresh system account, removed again at cleanup
#   2. creates `secrets/` owned by that account at mode `0700`, before
#      bootroot touches anything
#   3. as root, runs `infra install` with the OpenBao, step-ca and
#      HTTP-01 admin binds, and asserts at once that the three override
#      directories are the account's at `0700` and each override is the
#      account's.  This is checked before `init`: `infra install`'s
#      closing sweep re-owns but never re-modes, and `init` re-modes
#      every directory after a fresh `step ca init`, so no later check
#      shows the mode `infra install` itself leaves
#   4. as root, runs `init --save-unseal-keys` with the OpenBao exposure
#      override applied, no `infra up` in between, and checks that the
#      stack comes up healthy
#   5. asserts that `find secrets` prints no entry whose uid or gid is
#      not the account's, and no directory whose mode is not `0700`, and
#      that no `.bootroot-step-*` scratch directory the HTTP-01 admin
#      issuance used is left beside `secrets/`
#   6. as root, runs a second `init` over the stack the first left —
#      OpenBao now on TLS at the bind, the root token from the first
#      run's summary, the DSN from `ca.json` — which re-issues the
#      HTTP-01 admin certificate over the existing
#      `bootroot-http01/tls/`, and repeats the assertions of step 5
#
# Running as root over a tree another account owns is the case in
# which bootroot's writes under `secrets/` walk from the tree's
# descriptor and follow no name, so this is the arm that exercises it.
#
# The run replaces the checkout's `secrets/` with a fresh one, as every
# default-identity harness resets it, and removes it at cleanup.  It
# needs Linux (`useradd`, GNU `stat` and `find`) and non-interactive
# `sudo`.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# shellcheck source=lib/leftovers.sh
. "$SCRIPT_DIR/lib/leftovers.sh"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-secrets-owner-$(date +%s)}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$ARTIFACT_DIR/workspace}"
# Not overridable: `infra install` writes its overrides under the
# compose directory's own `secrets/`, so `init` has to be pointed at
# that same directory.
SECRETS_DIR="$(dirname "$COMPOSE_FILE")/secrets"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
INFRA_READY_ATTEMPTS="${INFRA_READY_ATTEMPTS:-40}"
INFRA_READY_DELAY_SECS="${INFRA_READY_DELAY_SECS:-3}"
OPENBAO_READY_ATTEMPTS="${OPENBAO_READY_ATTEMPTS:-40}"
OPENBAO_READY_DELAY_SECS="${OPENBAO_READY_DELAY_SECS:-2}"
HEALTH_ATTEMPTS="${HEALTH_ATTEMPTS:-10}"
HEALTH_DELAY_SECS="${HEALTH_DELAY_SECS:-3}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-summary.json"
SECOND_INIT_LOG="$ARTIFACT_DIR/init-second.log"
SECOND_INIT_RAW_LOG="$ARTIFACT_DIR/init-second.raw.log"
SECOND_INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-second-summary.json"

# Non-loopback bind for all three exposed services.  Defaults to the
# docker bridge gateway for the reason `run-openbao-tls-reown.sh` gives:
# every host that can run this harness has the `docker0` interface, and
# a specific (non-wildcard) bind needs no advertise address.
BIND_HOST_DEFAULT="172.17.0.1"
BIND_HOST="${BIND_HOST:-$BIND_HOST_DEFAULT}"
OPENBAO_BIND_ADDR="${BIND_HOST}:8200"
STEPCA_BIND_ADDR="${BIND_HOST}:9000"
HTTP01_ADMIN_BIND_ADDR="${BIND_HOST}:8080"
EXPOSED_OVERRIDE_PATH="$SECRETS_DIR/openbao/docker-compose.openbao-exposed.yml"
OPENBAO_REPO_DIR="$ROOT_DIR/openbao"
OPENBAO_REPO_HCL="$OPENBAO_REPO_DIR/openbao.hcl"
OPENBAO_REPO_CONFIG_DIR="$OPENBAO_REPO_DIR/config"
OPENBAO_REPO_TLS_DIR="$OPENBAO_REPO_DIR/tls"
POSTGRES_REPO_DIR="$ROOT_DIR/postgres"
OPENBAO_HCL_SNAPSHOT="$ARTIFACT_DIR/openbao.hcl.pristine"
OPENBAO_CONFIG_SNAPSHOT="$ARTIFACT_DIR/openbao-config.pristine"
OPENBAO_TLS_SNAPSHOT="$ARTIFACT_DIR/openbao-tls.pristine"
DEFAULT_STEPCA_PASSWORD="secrets-owner"
DEFAULT_HTTP_HMAC="dev-hmac"

# The account `secrets/` is handed to.  Run-scoped, so a killed run's
# account never collides with the next run's, and at most 32 bytes,
# the longest name `useradd` accepts.
RUN_TOKEN="$(date +%s)$$"
SECRETS_ACCOUNT="bootroot-so-${RUN_TOKEN}"
SECRETS_ACCOUNT="${SECRETS_ACCOUNT:0:32}"
SECRETS_UID=""
SECRETS_GID=""
ACCOUNT_CREATED=0
ROOT_WROTE=0
ROOT_ENV=()
# The first run's root token, set only while the second `init` runs, so
# it reaches that command through `OPENBAO_ROOT_TOKEN` in the `env` list
# below rather than through bootroot's own argument list.
SECOND_INIT_ROOT_TOKEN=""
# The first run's root token once its summary has been read, so that
# every copy of an `init` log the run leaves (the run log, the error
# handler's output, the uploaded artifact directory) has it masked.
KNOWN_ROOT_TOKEN=""
CURRENT_PHASE="startup"
REPO_OPENBAO_SNAPSHOT_TAKEN=0

# Pinned for the reason `run-openbao-tls-reown.sh` gives: the harness
# probes PostgreSQL on 5432, and Compose's default is 5433.  Passed to
# every root-run bootroot explicitly, since `sudo` drops the environment.
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
  echo "[secrets-owner][${CURRENT_PHASE}] $message" >&2
  exit 1
}

on_error() {
  local line="$1"
  echo "[secrets-owner] failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "[secrets-owner] artifact dir: ${ARTIFACT_DIR}" >&2
  if [ -f "$RUN_LOG" ]; then
    echo "--- run.log (tail) ---" >&2
    tail -n 120 "$RUN_LOG" >&2 || true
  fi
  # Only the redacted copies are printed: a raw log still on disk here
  # (the error struck before its run redacted it) is redacted first.
  redact_init_log "$INIT_RAW_LOG" "$INIT_LOG" || true
  redact_init_log "$SECOND_INIT_RAW_LOG" "$SECOND_INIT_LOG" || true
  if [ -f "$INIT_LOG" ]; then
    echo "--- init.log (redacted tail) ---" >&2
    tail -n 80 "$INIT_LOG" >&2 || true
  fi
  if [ -f "$SECOND_INIT_LOG" ]; then
    echo "--- init-second.log (redacted tail) ---" >&2
    tail -n 80 "$SECOND_INIT_LOG" >&2 || true
  fi
}

# Writes `raw` to `redacted` with the summary's root-token line masked
# (the line is `- root token: <token>`, so the pattern is not anchored)
# and, once `KNOWN_ROOT_TOKEN` is set, every other occurrence of the
# token, then removes `raw`, so only the redacted copy is left to print
# or upload.  A missing `raw` is a no-op.
redact_init_log() {
  local raw="$1" redacted="$2"
  [ -f "$raw" ] || return 0
  local args=(-e 's/\(root token: \).*/\1<redacted>/')
  if [ -n "$KNOWN_ROOT_TOKEN" ]; then
    local escaped
    escaped="$(printf '%s' "$KNOWN_ROOT_TOKEN" | sed 's/[][\.*^$|/]/\\&/g')"
    args+=(-e "s|${escaped}|<redacted>|g")
  fi
  sed "${args[@]}" "$raw" >"$redacted" && rm -f "$raw"
}

# Sets `KNOWN_ROOT_TOKEN` from the first run's summary when it exists.
# The summary is root-owned `0600` (root wrote it), so it is read
# through `sudo`.
load_known_root_token() {
  run_sudo test -f "$INIT_SUMMARY_JSON" 2>/dev/null || return 0
  KNOWN_ROOT_TOKEN="$(run_sudo jq -r '.root_token // empty' "$INIT_SUMMARY_JSON" 2>>"$RUN_LOG")" \
    || KNOWN_ROOT_TOKEN=""
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

run_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi
  sudo -n "$@"
}

# The environment a root-run command needs, as `env` arguments.  `env`
# rather than `sudo -E`: only the variables named here cross the
# boundary.  `COMPOSE_PROJECT_NAME` crosses when the caller set it, so
# the stack root brings up is the project this harness tears down.
root_env() {
  ROOT_ENV=(
    POSTGRES_HOST_PORT="$POSTGRES_HOST_PORT"
    POSTGRES_HOST="$POSTGRES_HOST"
    POSTGRES_PORT="$POSTGRES_PORT"
  )
  if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
    ROOT_ENV+=(COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT_NAME")
  fi
  if [ -n "$SECOND_INIT_ROOT_TOKEN" ]; then
    ROOT_ENV+=(OPENBAO_ROOT_TOKEN="$SECOND_INIT_ROOT_TOKEN")
  fi
}

# `bootroot` as root, from the workspace that holds `state.json`.
run_bootroot_as_root() {
  ROOT_WROTE=1
  root_env
  (cd "$WORKSPACE_DIR" && run_sudo env BOOTROOT_LANG=en "${ROOT_ENV[@]}" "$BOOTROOT_BIN" "$@")
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
  # The account is created with `useradd`, which is Linux's, and the
  # assertions read owners and modes with GNU `stat -c` and `find -printf`.
  [ "$(uname -s)" = "Linux" ] || fail "this harness needs Linux (useradd, GNU stat and find)"
  run_sudo sh -c 'command -v useradd && command -v userdel' >/dev/null 2>&1 \
    || fail "useradd and userdel are required"
  # Creating the account, handing it `secrets/` and running bootroot as
  # root over that tree all need root.
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || fail "this harness runs bootroot as root and needs root or sudo"
    sudo -n true >/dev/null 2>&1 \
      || fail "this harness needs non-interactive sudo (sudo -n) to create an account and run bootroot as root"
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
  if ! printf '%s\n' "$local_addrs" | grep -qFx -- "$bind_host"; then
    fail "non-loopback bind host $bind_host is not assigned to any local interface (set $bind_var to an address that is)"
  fi
}

capture_artifacts() {
  compose ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
  compose logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  if [ -d "$SECRETS_DIR" ]; then
    run_sudo find "$SECRETS_DIR" -printf '%U:%G %m %y %p\n' \
      >"$ARTIFACT_DIR/secrets-tree.log" 2>&1 || true
  fi
}

cleanup() {
  local status=$?
  local cleanup_status=0
  log_phase "cleanup"
  capture_artifacts
  # Before the teardown: root wrote `.env` and the state the teardown
  # reads, and `secrets/` is the account's at `0700`.
  restore_ownership
  # Nothing is torn down before the startup assertion passed: what is on
  # this host then belongs to whoever put it there, and removing it is
  # exactly what the assertion refused to do.
  if stack_owned; then
    if ! compose_down; then
      echo "run-secrets-owner: teardown failed; see ${RUN_LOG}" >&2
      cleanup_status=1
    fi
    report_leftover_containers "$COMPOSE_FILE" "run-secrets-owner cleanup" || cleanup_status=1
  fi
  restore_repo_openbao_config
  remove_secrets_dir
  # Last: the sidecars ran as this account, and they are gone only once
  # the stack is down.
  remove_account || cleanup_status=1
  exit_with_cleanup_status "$status" "$cleanup_status"
}

# Root ran `infra install` and `init`, and `secrets/` is the account's,
# so the trees root wrote (`openbao/`, `postgres/`, `.env`, the
# workspace) and `secrets/` itself are handed back to the invoking user
# before anything else in cleanup touches them.
restore_ownership() {
  if [ "$ROOT_WROTE" != "1" ]; then
    return 0
  fi
  local owner path
  owner="$(id -u):$(id -g)"
  for path in "$SECRETS_DIR" "$OPENBAO_REPO_DIR" "$POSTGRES_REPO_DIR" \
    "$ROOT_DIR/.env" "$WORKSPACE_DIR" "$ARTIFACT_DIR"; do
    if run_sudo test -e "$path"; then
      run_sudo chown -R -h "$owner" "$path" >/dev/null 2>&1 || true
    fi
  done
  ROOT_WROTE=0
}

# `secrets/` is this run's: it replaced the checkout's at the start.
remove_secrets_dir() {
  if [ "$ACCOUNT_CREATED" = "1" ]; then
    run_sudo rm -rf "$SECRETS_DIR" >/dev/null 2>&1 || true
  fi
}

remove_account() {
  if [ "$ACCOUNT_CREATED" != "1" ]; then
    return 0
  fi
  if ! run_sudo userdel "$SECRETS_ACCOUNT" >>"$RUN_LOG" 2>&1; then
    echo "run-secrets-owner: failed to remove account ${SECRETS_ACCOUNT}; see ${RUN_LOG}" >&2
    return 1
  fi
  ACCOUNT_CREATED=0
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
# probe only proves the listener answers at all.
wait_for_openbao_listening() {
  local url="$1"
  for _ in $(seq 1 "$OPENBAO_READY_ATTEMPTS"); do
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
  for _ in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    if docker exec bootroot-postgres pg_isready -h 127.0.0.1 -U "$admin_user" -d postgres >/dev/null 2>&1 &&
      bash -lc ": >/dev/tcp/127.0.0.1/${host_port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  fail "postgres admin endpoint did not become reachable"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

create_account() {
  log_phase "create-account"
  # Armed before the call: a `useradd` that fails partway may still have
  # left the account behind, and only `remove_account` can take it away.
  ACCOUNT_CREATED=1
  run_sudo useradd --system --user-group --shell /usr/sbin/nologin \
    --home-dir /nonexistent "$SECRETS_ACCOUNT" >>"$RUN_LOG" 2>&1 \
    || fail "failed to create account ${SECRETS_ACCOUNT}"
  SECRETS_UID="$(id -u "$SECRETS_ACCOUNT")"
  SECRETS_GID="$(id -g "$SECRETS_ACCOUNT")"
  [ "$SECRETS_UID" != "0" ] || fail "account ${SECRETS_ACCOUNT} resolved to uid 0"
  [ "$SECRETS_UID" != "$(id -u)" ] \
    || fail "account ${SECRETS_ACCOUNT} has the invoking user's uid ${SECRETS_UID}"
  echo "secrets account: ${SECRETS_ACCOUNT} (${SECRETS_UID}:${SECRETS_GID})" >>"$RUN_LOG"
}

# A fresh `secrets/`, the account's at `0700`, before bootroot touches
# anything: the state an installer leaves when it hands the tree to a
# dedicated account first.
prepare_secrets_dir() {
  log_phase "prepare-secrets"
  ROOT_WROTE=1
  rm -f "$WORKSPACE_DIR/state.json"
  run_sudo rm -f "$ROOT_DIR/.env"
  run_sudo rm -rf "$SECRETS_DIR"
  run_sudo install -d -m 0700 -o "$SECRETS_UID" -g "$SECRETS_GID" "$SECRETS_DIR" \
    || fail "failed to create $SECRETS_DIR for ${SECRETS_ACCOUNT}"
  assert_entry_state "$SECRETS_DIR" "${SECRETS_UID}:${SECRETS_GID} 700" "prepared"
}

install_infra_with_binds() {
  log_phase "install"
  run_bootroot_as_root infra install \
    --compose-file "$COMPOSE_FILE" \
    --openbao-bind "$OPENBAO_BIND_ADDR" \
    --openbao-tls-required \
    --stepca-bind "$STEPCA_BIND_ADDR" \
    --http01-admin-bind "$HTTP01_ADMIN_BIND_ADDR" \
    --http01-admin-tls-required >>"$RUN_LOG" 2>&1 \
    || fail "bootroot infra install failed"
}

# Applied the way `run-openbao-tls-reown.sh` applies it: the override
# republishes OpenBao on the bind address only, and `init` is pointed
# at that address below.  As root, because the override sits in a
# directory only the account and root can traverse, and root wrote the
# `.env` Compose reads.
apply_exposed_override() {
  log_phase "apply-override"
  run_sudo test -f "$EXPOSED_OVERRIDE_PATH" \
    || fail "expected infra install to write $EXPOSED_OVERRIDE_PATH"
  root_env
  run_sudo env "${ROOT_ENV[@]}" docker compose -p "${COMPOSE_PROJECT_NAME:-bootroot}" -f "$COMPOSE_FILE" \
    -f "$EXPOSED_OVERRIDE_PATH" up -d openbao >>"$RUN_LOG" 2>&1 \
    || fail "failed to apply the openbao-exposed override"
  wait_for_openbao_listening "http://${OPENBAO_BIND_ADDR}"
}

run_init() {
  log_phase "init"
  wait_for_postgres_admin
  # `infra install` writes state.json (to record the bind intents) before
  # init runs, so init's overwrite prompts fire.  Answer them with their
  # per-prompt flags and run with stdin closed so the run stays
  # non-interactive.
  local status=0
  run_bootroot_as_root init \
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
    --responder-url "https://${HTTP01_ADMIN_BIND_ADDR}" \
    --skip responder-check </dev/null >"$INIT_RAW_LOG" 2>&1 || status=$?
  load_known_root_token
  redact_init_log "$INIT_RAW_LOG" "$INIT_LOG"
  if [ "$status" -ne 0 ]; then
    {
      echo "bootroot init failed (redacted tail):"
      tail -n 200 "$INIT_LOG" || true
    } >>"$RUN_LOG"
    fail "bootroot init failed"
  fi
}

# A second `init` over the stack the first left, with the first run's
# flags except where that stack differs: OpenBao serves TLS at the bind
# now, so `--openbao-url` is `https://`; it is already initialized, so
# the root token from the first run's summary is passed (through
# `OPENBAO_ROOT_TOKEN`, as `init` has no token-file flag) or `init` stops
# at its partial-initialization check; and the database is provisioned,
# so `--db-dsn` takes the DSN `ca.json` holds in place of the
# `db-provision` flags, as `run_second_init` in `run-stepca-san.sh`
# does.  It re-issues the HTTP-01 admin certificate over the existing
# `bootroot-http01/tls/`.  The first run's summary is root-owned `0600`,
# so it is read through `sudo`.
run_second_init() {
  log_phase "second-init"
  local root_token db_dsn
  root_token="$(run_sudo jq -r '.root_token // empty' "$INIT_SUMMARY_JSON" 2>>"$RUN_LOG")" \
    || fail "failed to read the first init summary $INIT_SUMMARY_JSON"
  [ -n "$root_token" ] || fail "the first init summary carries no root_token"
  KNOWN_ROOT_TOKEN="$root_token"
  db_dsn="$(run_sudo jq -r '.db.dataSource // empty' "$SECRETS_DIR/config/ca.json" 2>>"$RUN_LOG")" \
    || fail "failed to read db.dataSource from $SECRETS_DIR/config/ca.json"
  [ -n "$db_dsn" ] || fail "ca.json carries no db.dataSource"
  wait_for_postgres_admin
  wait_for_openbao_listening "https://${OPENBAO_BIND_ADDR}"

  SECOND_INIT_ROOT_TOKEN="$root_token"
  local status=0
  run_bootroot_as_root init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --openbao-url "https://${OPENBAO_BIND_ADDR}" \
    --summary-json "$SECOND_INIT_SUMMARY_JSON" \
    --enable auto-generate,show-secrets \
    --stepca-password "$DEFAULT_STEPCA_PASSWORD" \
    --http-hmac "$DEFAULT_HTTP_HMAC" \
    --db-dsn "$db_dsn" \
    --no-eab \
    --save-unseal-keys \
    --overwrite-password \
    --overwrite-ca-json \
    --overwrite-state \
    --responder-url "https://${HTTP01_ADMIN_BIND_ADDR}" \
    --skip responder-check </dev/null >"$SECOND_INIT_RAW_LOG" 2>&1 || status=$?
  SECOND_INIT_ROOT_TOKEN=""
  redact_init_log "$SECOND_INIT_RAW_LOG" "$SECOND_INIT_LOG"
  if [ "$status" -ne 0 ]; then
    {
      echo "second bootroot init failed (redacted tail):"
      tail -n 200 "$SECOND_INIT_LOG" || true
    } >>"$RUN_LOG"
    fail "second bootroot init failed"
  fi
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

# Fails unless `path` reads as `expected`, an `uid:gid mode` string as
# GNU `stat -c '%u:%g %a'` prints it.  Through `sudo`: the tree is the
# account's at `0700`.
assert_entry_state() {
  local path="$1" expected="$2" label="$3" actual
  actual="$(run_sudo stat -c '%u:%g %a' "$path" 2>>"$RUN_LOG")" \
    || fail "${label}: ${path} does not exist"
  [ "$actual" = "$expected" ] \
    || fail "${label}: ${path} is ${actual}, expected ${expected}"
}

assert_entry_owner() {
  local path="$1" label="$2" actual
  actual="$(run_sudo stat -c '%u:%g' "$path" 2>>"$RUN_LOG")" \
    || fail "${label}: ${path} does not exist"
  [ "$actual" = "${SECRETS_UID}:${SECRETS_GID}" ] \
    || fail "${label}: ${path} is owned by ${actual}, expected the account's ${SECRETS_UID}:${SECRETS_GID}"
}

# What `infra install` itself leaves, before `init` re-modes the tree.
assert_install_ownership() {
  log_phase "assert-install"
  local expected_dir="${SECRETS_UID}:${SECRETS_GID} 700"
  assert_entry_state "$SECRETS_DIR/openbao" "$expected_dir" "after infra install"
  assert_entry_state "$SECRETS_DIR/responder" "$expected_dir" "after infra install"
  assert_entry_state "$SECRETS_DIR/step-ca" "$expected_dir" "after infra install"
  assert_entry_owner "$SECRETS_DIR/openbao/docker-compose.openbao-exposed.yml" "after infra install"
  assert_entry_owner "$SECRETS_DIR/responder/docker-compose.http01-exposed.yml" "after infra install"
  assert_entry_owner "$SECRETS_DIR/step-ca/docker-compose.stepca-exposed.yml" "after infra install"
}

# `bootroot status` fails when any core container is missing or
# unhealthy, or OpenBao cannot be reached or is sealed.  Retried for a
# container still settling into `healthy` after init's last restart.
assert_stack_healthy() {
  log_phase "assert-healthy"
  local log="$ARTIFACT_DIR/status.log"
  for _ in $(seq 1 "$HEALTH_ATTEMPTS"); do
    if run_bootroot_as_root status \
      --compose-file "$COMPOSE_FILE" \
      --openbao-url "https://${OPENBAO_BIND_ADDR}" >"$log" 2>&1; then
      return 0
    fi
    sleep "$HEALTH_DELAY_SECS"
  done
  {
    echo "bootroot status failed after init (tail):"
    tail -n 80 "$log" || true
  } >>"$RUN_LOG"
  fail "the stack is not healthy after init; see $log"
}

# The contract: every entry under `secrets/` is the account's, and
# every directory there is `0700`.
assert_secrets_tree_ownership() {
  log_phase "assert-secrets-tree"
  local expected_dir="${SECRETS_UID}:${SECRETS_GID} 700"
  # The entries this arm exists for, named so a missing one fails here
  # rather than passing the `find` below by absence.
  assert_entry_state "$SECRETS_DIR" "$expected_dir" "after init"
  assert_entry_state "$SECRETS_DIR/bootroot-http01" "$expected_dir" "after init"
  assert_entry_state "$SECRETS_DIR/bootroot-http01/tls" "$expected_dir" "after init"
  assert_entry_owner "$SECRETS_DIR/certs/ca-bundle.pem" "after init"
  assert_entry_owner "$SECRETS_DIR/openbao/unseal-keys.txt" "after init"

  local foreign wrong_mode
  foreign="$(run_sudo find "$SECRETS_DIR" \
    \( ! -uid "$SECRETS_UID" -o ! -gid "$SECRETS_GID" \) \
    -printf '%U:%G %m %p\n' 2>>"$RUN_LOG")" \
    || fail "find over $SECRETS_DIR failed"
  wrong_mode="$(run_sudo find "$SECRETS_DIR" -type d ! -perm 700 \
    -printf '%U:%G %m %p\n' 2>>"$RUN_LOG")" \
    || fail "find over $SECRETS_DIR failed"
  if [ -n "$foreign" ]; then
    printf 'entries not owned by %s:%s:\n%s\n' "$SECRETS_UID" "$SECRETS_GID" "$foreign" >>"$RUN_LOG"
  fi
  if [ -n "$wrong_mode" ]; then
    printf 'directories not at 0700:\n%s\n' "$wrong_mode" >>"$RUN_LOG"
  fi
  [ -z "$foreign" ] \
    || fail "entries under $SECRETS_DIR are not the account's: ${foreign//$'\n'/; }"
  [ -z "$wrong_mode" ] \
    || fail "directories under $SECRETS_DIR are not 0700: ${wrong_mode//$'\n'/; }"
}

# A rooted issuance of the HTTP-01 admin certificate hands the `step`
# helper a `.bootroot-step-*` scratch directory beside `secrets/` and
# removes it on every exit path; none may be left after `init`.
assert_no_step_scratch() {
  local label="$1" parent leftover
  parent="$(dirname "$SECRETS_DIR")"
  leftover="$(run_sudo find "$parent" -mindepth 1 -maxdepth 1 -name '.bootroot-step-*' \
    -printf '%p\n' 2>>"$RUN_LOG")" || fail "${label}: find over $parent failed"
  [ -z "$leftover" ] \
    || fail "${label}: step scratch directories left beside $SECRETS_DIR: ${leftover//$'\n'/; }"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  mkdir -p "$ARTIFACT_DIR" "$WORKSPACE_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  ensure_prerequisites
  ensure_bind_host_available "$BIND_HOST" BIND_HOST
  # The assertion comes first, before the teardown and before anything
  # else that could remove a container, for the reason
  # `run-openbao-tls-reown.sh` gives.
  assert_no_leftover_containers "$COMPOSE_FILE" "run-secrets-owner startup"
  mark_stack_owned
  compose_down || true
  snapshot_repo_openbao_config

  create_account
  prepare_secrets_dir

  install_infra_with_binds
  assert_install_ownership
  # `infra install` brings the stack up on the base compose file, so
  # OpenBao is still published on loopback at this point.
  wait_for_openbao_listening "http://127.0.0.1:8200"

  apply_exposed_override
  run_init
  assert_stack_healthy
  assert_secrets_tree_ownership
  assert_no_step_scratch "after init"

  run_second_init
  assert_stack_healthy
  assert_secrets_tree_ownership
  assert_no_step_scratch "after the second init"

  log_phase "done"
}

main "$@"
