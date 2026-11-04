#!/usr/bin/env bash
set -euo pipefail

# Docker-backed E2E harness for `bootroot infra install --postgres-user`.
#
# An installer that runs bootroot's containers as dedicated host
# accounts gives step-ca's PostgreSQL one of them through
# `--postgres-user`.  PostgreSQL then runs as that uid:gid, its data
# volume is re-owned to it, and its TLS key is `<uid>:0 0600` instead of
# `999:0 0600`.  This harness is that installer, set up as the
# `openbao-user` arm is — a fresh account owning `secrets/` at `0700`,
# given to `--openbao-user`, with bootroot run as root — plus a second
# fresh account for `--postgres-user`:
#
#   1. `infra install` and `init` without `--postgres-user`: every
#      PostgreSQL process is uid 999, `postgres/tls/server.key` is
#      `999:0 0600`, `.env` records no BOOTROOT_POSTGRES_USER; a marker
#      row is written through `docker compose exec postgres psql`
#   2. `infra install --postgres-user <uid>:<gid>` with the same other
#      flags, then `infra up`: every PostgreSQL process is the second
#      account's, nothing under /var/lib/postgresql has another owner,
#      the key is `<uid>:0 0600` while `postgres/tls/` and `server.crt`
#      stay the owner of `secrets/`'s, `ssl` is on, every TCP session to
#      `stepca` is encrypted, step-ca is healthy and the marker is there
#   3. recreates PostgreSQL with `docker compose` naming only the base
#      compose file and asserts it still runs as the account with the
#      marker in place, then lets `infra up` restore the TLS override
#   4. `rotate infra-cert --yes`: the PostgreSQL leaf is re-issued, its
#      key is `<uid>:0 0600` again, and PostgreSQL still runs as the
#      account with `ssl` on and the marker in place
#   5. with a malformed BOOTROOT_POSTGRES_USER, then a malformed
#      BOOTROOT_OPENBAO_USER, written into `.env` by hand, a direct
#      `docker compose run` of each service is refused by its entrypoint
#      before it re-owns anything; `.env` is restored byte for byte and
#      the running servers are untouched
#
# Every process check runs once PostgreSQL accepts connections, so the
# wrapper's root start is not what `docker top` sees.  The run replaces
# the checkout's `secrets/` with a fresh one, as every default-identity
# harness resets it, and removes it at cleanup.  It needs Linux
# (`useradd`, GNU `stat` and `find`) and non-interactive `sudo`.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# shellcheck source=lib/leftovers.sh
. "$SCRIPT_DIR/lib/leftovers.sh"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-postgres-user-$(date +%s)}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$ARTIFACT_DIR/workspace}"
# Not overridable: `infra install` writes its overrides under the
# compose directory's own `secrets/`, so `init` has to be pointed at
# that same directory.
SECRETS_DIR="$(dirname "$COMPOSE_FILE")/secrets"
COMPOSE_DIR="$(dirname "$COMPOSE_FILE")"
DOTENV_PATH="$COMPOSE_DIR/.env"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
INFRA_READY_ATTEMPTS="${INFRA_READY_ATTEMPTS:-40}"
INFRA_READY_DELAY_SECS="${INFRA_READY_DELAY_SECS:-3}"
OPENBAO_READY_ATTEMPTS="${OPENBAO_READY_ATTEMPTS:-40}"
OPENBAO_READY_DELAY_SECS="${OPENBAO_READY_DELAY_SECS:-2}"
HEALTH_ATTEMPTS="${HEALTH_ATTEMPTS:-10}"
HEALTH_DELAY_SECS="${HEALTH_DELAY_SECS:-3}"
SESSION_ATTEMPTS="${SESSION_ATTEMPTS:-20}"
SESSION_DELAY_SECS="${SESSION_DELAY_SECS:-3}"
# A direct `docker compose run` the entrypoint should refuse at once; a
# start that is not refused would otherwise run PostgreSQL in the
# foreground until the job's own timeout.
REFUSAL_TIMEOUT_SECS="${REFUSAL_TIMEOUT_SECS:-120}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-summary.json"

# Non-loopback bind for all three exposed services, as `run-openbao-user.sh`
# binds them, for the reason `run-openbao-tls-reown.sh` gives: every host
# that can run this harness has the `docker0` interface, and a specific
# (non-wildcard) bind needs no advertise address.
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
POSTGRES_TLS_DIR="$POSTGRES_REPO_DIR/tls"
POSTGRES_SERVER_CRT="$POSTGRES_TLS_DIR/server.crt"
POSTGRES_SERVER_KEY="$POSTGRES_TLS_DIR/server.key"
OPENBAO_HCL_SNAPSHOT="$ARTIFACT_DIR/openbao.hcl.pristine"
OPENBAO_CONFIG_SNAPSHOT="$ARTIFACT_DIR/openbao-config.pristine"
OPENBAO_TLS_SNAPSHOT="$ARTIFACT_DIR/openbao-tls.pristine"
DOTENV_BACKUP="$ARTIFACT_DIR/dotenv.pristine"
DEFAULT_STEPCA_PASSWORD="postgres-user"
DEFAULT_HTTP_HMAC="dev-hmac"

# The account `secrets/` is handed to, the one `--openbao-user` names,
# and the one `--postgres-user` names.  Run-scoped, so a killed run's
# accounts never collide with the next run's, and at most 32 bytes, the
# longest name `useradd` accepts.
RUN_TOKEN="$(date +%s)$$"
SECRETS_ACCOUNT="bootroot-pu-${RUN_TOKEN}"
SECRETS_ACCOUNT="${SECRETS_ACCOUNT:0:32}"
POSTGRES_ACCOUNT="bootroot-pg-${RUN_TOKEN}"
POSTGRES_ACCOUNT="${POSTGRES_ACCOUNT:0:32}"
SECRETS_UID=""
SECRETS_GID=""
POSTGRES_UID=""
POSTGRES_GID=""
SECRETS_ACCOUNT_CREATED=0
POSTGRES_ACCOUNT_CREATED=0
ROOT_WROTE=0
DOTENV_EDITED=0
ROOT_ENV=()
CURRENT_PHASE="startup"
OPENBAO_CONTAINER="bootroot-openbao"
POSTGRES_CONTAINER="bootroot-postgres"
UNSEAL_KEYS_PATH="$SECRETS_DIR/openbao/unseal-keys.txt"
REPO_OPENBAO_SNAPSHOT_TAKEN=0
POSTGRES_FINGERPRINT_BEFORE=""
MARKER_TABLE="bootroot_e2e_marker"

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
  echo "[postgres-user][${CURRENT_PHASE}] $message" >&2
  exit 1
}

on_error() {
  local line="$1"
  echo "[postgres-user] failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "[postgres-user] artifact dir: ${ARTIFACT_DIR}" >&2
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
}

# `bootroot` as root, from the workspace that holds `state.json`.
run_bootroot_as_root() {
  ROOT_WROTE=1
  root_env
  (cd "$WORKSPACE_DIR" && run_sudo env BOOTROOT_LANG=en "${ROOT_ENV[@]}" "$BOOTROOT_BIN" "$@")
}

# `docker compose` as root, under the identity the harness installed at,
# naming only the base compose file: root wrote the `.env` Compose reads.
compose_base_as_root() {
  root_env
  run_sudo env "${ROOT_ENV[@]}" docker compose -p "${COMPOSE_PROJECT_NAME:-bootroot}" \
    -f "$COMPOSE_FILE" "$@"
}

# `psql` as root over the container's local socket, which `pg_hba.conf`
# trusts, through `docker compose exec`.
psql_stepca() {
  compose_base_as_root exec -T postgres psql -U step -d stepca -v ON_ERROR_STOP=1 -Atc "$1"
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
  command -v timeout >/dev/null 2>&1 || fail "timeout is required"
  ensure_openssl
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  # The accounts are created with `useradd`, which is Linux's, and the
  # assertions read owners and modes with GNU `stat -c` and `find -printf`.
  [ "$(uname -s)" = "Linux" ] || fail "this harness needs Linux (useradd, GNU stat and find)"
  run_sudo sh -c 'command -v useradd && command -v userdel' >/dev/null 2>&1 \
    || fail "useradd and userdel are required"
  # Creating the accounts, handing one `secrets/` and running bootroot as
  # root over that tree all need root.
  if [ "$(id -u)" -ne 0 ]; then
    command -v sudo >/dev/null 2>&1 || fail "this harness runs bootroot as root and needs root or sudo"
    sudo -n true >/dev/null 2>&1 \
      || fail "this harness needs non-interactive sudo (sudo -n) to create accounts and run bootroot as root"
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
  if [ -d "$POSTGRES_REPO_DIR" ]; then
    run_sudo find "$POSTGRES_REPO_DIR" -printf '%U:%G %m %y %p\n' \
      >"$ARTIFACT_DIR/postgres-tree.log" 2>&1 || true
  fi
}

cleanup() {
  local status=$?
  local cleanup_status=0
  log_phase "cleanup"
  # First: a run that failed while `.env` held a hand-edited value must
  # not leave it for the teardown, or for the checkout.
  restore_dotenv
  capture_artifacts
  # Before the teardown: root wrote `.env` and the state the teardown
  # reads, and `secrets/` is the account's at `0700`.
  restore_ownership
  # Nothing is torn down before the startup assertion passed: what is on
  # this host then belongs to whoever put it there, and removing it is
  # exactly what the assertion refused to do.
  if stack_owned; then
    if ! compose_down; then
      echo "run-postgres-user: teardown failed; see ${RUN_LOG}" >&2
      cleanup_status=1
    fi
    report_leftover_containers "$COMPOSE_FILE" "run-postgres-user cleanup" || cleanup_status=1
  fi
  restore_repo_openbao_config
  remove_secrets_dir
  # Last: the containers ran as these accounts, and they are gone only
  # once the stack is down.
  remove_accounts || cleanup_status=1
  exit_with_cleanup_status "$status" "$cleanup_status"
}

# Root ran `infra install`, `init`, `infra up` and `rotate`, and
# `secrets/` is the account's, so the trees root wrote (`openbao/`,
# `postgres/`, `.env`, the workspace) and `secrets/` itself are handed
# back to the invoking user before anything else in cleanup touches
# them.
restore_ownership() {
  if [ "$ROOT_WROTE" != "1" ]; then
    return 0
  fi
  local owner path
  owner="$(id -u):$(id -g)"
  for path in "$SECRETS_DIR" "$OPENBAO_REPO_DIR" "$POSTGRES_REPO_DIR" \
    "$DOTENV_PATH" "$WORKSPACE_DIR" "$ARTIFACT_DIR"; do
    if run_sudo test -e "$path"; then
      run_sudo chown -R -h "$owner" "$path" >/dev/null 2>&1 || true
    fi
  done
  ROOT_WROTE=0
}

# `secrets/` is this run's: it replaced the checkout's at the start.
remove_secrets_dir() {
  if [ "$SECRETS_ACCOUNT_CREATED" = "1" ]; then
    run_sudo rm -rf "$SECRETS_DIR" >/dev/null 2>&1 || true
  fi
}

remove_accounts() {
  local status=0
  if [ "$POSTGRES_ACCOUNT_CREATED" = "1" ]; then
    if run_sudo userdel "$POSTGRES_ACCOUNT" >>"$RUN_LOG" 2>&1; then
      POSTGRES_ACCOUNT_CREATED=0
    else
      echo "run-postgres-user: failed to remove account ${POSTGRES_ACCOUNT}; see ${RUN_LOG}" >&2
      status=1
    fi
  fi
  if [ "$SECRETS_ACCOUNT_CREATED" = "1" ]; then
    if run_sudo userdel "$SECRETS_ACCOUNT" >>"$RUN_LOG" 2>&1; then
      SECRETS_ACCOUNT_CREATED=0
    else
      echo "run-postgres-user: failed to remove account ${SECRETS_ACCOUNT}; see ${RUN_LOG}" >&2
      status=1
    fi
  fi
  return "$status"
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

# Puts back the `.env` step 5 copied before editing it, preserving its
# owner and mode.
restore_dotenv() {
  if [ "$DOTENV_EDITED" != "1" ]; then
    return 0
  fi
  run_sudo cp -p "$DOTENV_BACKUP" "$DOTENV_PATH" >>"$RUN_LOG" 2>&1 || return 1
  DOTENV_EDITED=0
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
    if docker exec "$POSTGRES_CONTAINER" pg_isready -h 127.0.0.1 -U "$admin_user" -d postgres >/dev/null 2>&1 &&
      bash -lc ": >/dev/tcp/127.0.0.1/${host_port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  fail "postgres admin endpoint did not become reachable"
}

# PostgreSQL accepts connections over its local socket: the wrapper has
# dropped to the server's uid by then, so every process `docker top`
# lists is the server's.
wait_for_postgres_ready() {
  for _ in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    if docker exec "$POSTGRES_CONTAINER" pg_isready -q >/dev/null 2>&1; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  docker logs --tail 80 "$POSTGRES_CONTAINER" >>"$RUN_LOG" 2>&1 || true
  fail "PostgreSQL did not start accepting connections"
}

# The OpenBao container's process list, once the server is running: the
# entrypoint's chowns run before it, so a listed `bao server` is the
# point at which they are done.
wait_for_openbao_server() {
  local listing
  for _ in $(seq 1 "$OPENBAO_READY_ATTEMPTS"); do
    listing="$(docker top "$OPENBAO_CONTAINER" -o pid,uid,gid,args 2>/dev/null || true)"
    if grep -qE '(^|[ /])bao server' <<<"$listing"; then
      return 0
    fi
    sleep "$OPENBAO_READY_DELAY_SECS"
  done
  docker logs --tail 80 "$OPENBAO_CONTAINER" >>"$RUN_LOG" 2>&1 || true
  fail "OpenBao's server process did not start"
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------

# Creates a fresh system account and prints its `uid:gid`.  The caller
# arms its cleanup flag before the call: a `useradd` that fails partway
# may still have left the account behind.
create_system_account() {
  local name="$1" uid gid
  run_sudo useradd --system --user-group --shell /usr/sbin/nologin \
    --home-dir /nonexistent "$name" >>"$RUN_LOG" 2>&1 \
    || fail "failed to create account ${name}"
  uid="$(id -u "$name")"
  gid="$(id -g "$name")"
  [ "$uid" != "0" ] || fail "account ${name} resolved to uid 0"
  [ "$gid" != "0" ] || fail "account ${name} resolved to gid 0"
  [ "$uid" != "$(id -u)" ] || fail "account ${name} has the invoking user's uid ${uid}"
  printf '%s:%s\n' "$uid" "$gid"
}

create_accounts() {
  log_phase "create-accounts"
  local ids
  SECRETS_ACCOUNT_CREATED=1
  ids="$(create_system_account "$SECRETS_ACCOUNT")"
  SECRETS_UID="${ids%%:*}"
  SECRETS_GID="${ids#*:}"
  POSTGRES_ACCOUNT_CREATED=1
  ids="$(create_system_account "$POSTGRES_ACCOUNT")"
  POSTGRES_UID="${ids%%:*}"
  POSTGRES_GID="${ids#*:}"
  # The image's own `postgres` user is uid 999: an account that landed
  # on it would let every PostgreSQL assertion below pass without the
  # option.  The two accounts must differ for the same reason: the key's
  # owner has to tell the option apart from the owner of `secrets/`.
  [ "$POSTGRES_UID" != "999" ] \
    || fail "account ${POSTGRES_ACCOUNT} has uid 999, the image's postgres user"
  [ "$POSTGRES_UID" != "$SECRETS_UID" ] \
    || fail "accounts ${SECRETS_ACCOUNT} and ${POSTGRES_ACCOUNT} share uid ${SECRETS_UID}"
  [ "$POSTGRES_GID" != "$SECRETS_GID" ] \
    || fail "accounts ${SECRETS_ACCOUNT} and ${POSTGRES_ACCOUNT} share gid ${SECRETS_GID}"
  {
    echo "secrets account: ${SECRETS_ACCOUNT} (${SECRETS_UID}:${SECRETS_GID})"
    echo "postgres account: ${POSTGRES_ACCOUNT} (${POSTGRES_UID}:${POSTGRES_GID})"
  } >>"$RUN_LOG"
}

# A fresh `secrets/`, the secrets account's at `0700`, before bootroot
# touches anything: the state an installer leaves when it hands the tree
# to a dedicated account first.
prepare_secrets_dir() {
  log_phase "prepare-secrets"
  ROOT_WROTE=1
  rm -f "$WORKSPACE_DIR/state.json"
  run_sudo rm -f "$DOTENV_PATH"
  run_sudo rm -rf "$SECRETS_DIR"
  run_sudo install -d -m 0700 -o "$SECRETS_UID" -g "$SECRETS_GID" "$SECRETS_DIR" \
    || fail "failed to create $SECRETS_DIR for ${SECRETS_ACCOUNT}"
  assert_entry_state "$SECRETS_DIR" "${SECRETS_UID}:${SECRETS_GID} 700" "prepared"
}

# `infra install` with the flags both installs share; the second adds
# `--postgres-user`.
install_infra() {
  run_bootroot_as_root infra install \
    --compose-file "$COMPOSE_FILE" \
    --openbao-user "${SECRETS_UID}:${SECRETS_GID}" \
    --openbao-bind "$OPENBAO_BIND_ADDR" \
    --openbao-tls-required \
    --stepca-bind "$STEPCA_BIND_ADDR" \
    --http01-admin-bind "$HTTP01_ADMIN_BIND_ADDR" \
    --http01-admin-tls-required "$@" >>"$RUN_LOG" 2>&1
}

install_without_postgres_user() {
  log_phase "install"
  install_infra || fail "bootroot infra install failed"
}

# Applied the way `run-openbao-user.sh` applies it: the override
# republishes OpenBao on the bind address only, and `init` is pointed at
# that address below.
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
  if ! run_bootroot_as_root init \
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
    --skip responder-check </dev/null >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 200 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
    fail "bootroot init failed"
  fi
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$INIT_LOG"
}

# `infra up` restores every override `init` recorded — the PostgreSQL TLS
# override among them — and unseals OpenBao from the saved keys.
run_infra_up() {
  local label="$1"
  run_bootroot_as_root infra up \
    --compose-file "$COMPOSE_FILE" \
    --openbao-unseal-from-file "$UNSEAL_KEYS_PATH" >>"$RUN_LOG" 2>&1 \
    || fail "${label}: bootroot infra up failed"
  wait_for_openbao_server
  wait_for_postgres_ready
}

rotate_infra_cert() {
  local log="$ARTIFACT_DIR/rotate-infra-cert.log"
  if ! run_bootroot_as_root rotate \
    --state-file "$WORKSPACE_DIR/state.json" \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    infra-cert --yes </dev/null >"$log" 2>&1; then
    {
      echo "rotate infra-cert failed (tail):"
      tail -n 120 "$log" || true
    } >>"$RUN_LOG"
    fail "bootroot rotate infra-cert failed; see $log"
  fi
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

# Fails unless `path` reads as `expected`, an `uid:gid mode` string as
# GNU `stat -c '%u:%g %a'` prints it.  Through `sudo`: `secrets/` is the
# account's at `0700`.
assert_entry_state() {
  local path="$1" expected="$2" label="$3" actual
  actual="$(run_sudo stat -c '%u:%g %a' "$path" 2>>"$RUN_LOG")" \
    || fail "${label}: ${path} does not exist"
  [ "$actual" = "$expected" ] \
    || fail "${label}: ${path} is ${actual}, expected ${expected}"
}

# `bootroot status` fails when any core container is missing or
# unhealthy, or OpenBao cannot be reached or is sealed.  Retried for a
# container still settling into `healthy` after the last restart.
assert_stack_healthy() {
  local label="$1"
  local log="$ARTIFACT_DIR/status-${label}.log"
  for _ in $(seq 1 "$HEALTH_ATTEMPTS"); do
    if run_bootroot_as_root status \
      --compose-file "$COMPOSE_FILE" \
      --openbao-url "https://${OPENBAO_BIND_ADDR}" >"$log" 2>&1; then
      cp "$log" "$ARTIFACT_DIR/status.log"
      return 0
    fi
    sleep "$HEALTH_DELAY_SECS"
  done
  cp "$log" "$ARTIFACT_DIR/status.log" || true
  {
    echo "bootroot status failed (${label}, tail):"
    tail -n 80 "$log" || true
  } >>"$RUN_LOG"
  fail "${label}: the stack is not healthy; see $log"
}

# Every process `docker top` lists for `container` runs as `uid` and,
# when given, `gid`.
assert_container_processes() {
  local container="$1" uid="$2" gid="$3" label="$4" listing processes foreign
  listing="$(docker top "$container" -o pid,uid,gid,args 2>>"$RUN_LOG")" \
    || fail "${label}: docker top ${container} failed"
  printf '%s\n%s\n' "== ${label}: ${container}" "$listing" >>"$ARTIFACT_DIR/processes.log"
  processes="$(tail -n +2 <<<"$listing")"
  [ -n "$processes" ] || fail "${label}: ${container} lists no process"
  foreign="$(awk -v uid="$uid" -v gid="$gid" \
    '$2 != uid || (gid != "" && $3 != gid)' <<<"$processes")"
  [ -z "$foreign" ] \
    || fail "${label}: ${container} runs processes not as ${uid}${gid:+:${gid}}: ${foreign//$'\n'/; }"
}

assert_postgres_runs_as_the_account() {
  local label="$1"
  wait_for_postgres_ready
  assert_container_processes "$POSTGRES_CONTAINER" "$POSTGRES_UID" "$POSTGRES_GID" "$label"
}

# No entry under the data directory, the directory included, has another
# owner: the wrapper re-owned what an install as uid 999 left.
assert_data_dir_is_the_accounts() {
  local label="$1" foreign
  foreign="$(docker exec "$POSTGRES_CONTAINER" find /var/lib/postgresql \
    \( ! -user "$POSTGRES_UID" -o ! -group "$POSTGRES_GID" \) -printf '%U:%G %p\n' \
    2>>"$RUN_LOG")" || fail "${label}: find over /var/lib/postgresql failed"
  [ -z "$foreign" ] \
    || fail "${label}: entries under /var/lib/postgresql are not ${POSTGRES_UID}:${POSTGRES_GID}: ${foreign//$'\n'/; }"
}

assert_postgres_key_owned_by() {
  local expected_owner="$1" label="$2"
  assert_entry_state "$POSTGRES_SERVER_KEY" "${expected_owner} 600" "$label"
}

# `postgres/tls/` and the certificate stay the owner of `secrets/`'s:
# only the key is handed to the server.
assert_postgres_tls_dir_is_the_secrets_owners() {
  local label="$1"
  assert_entry_state "$POSTGRES_TLS_DIR" "${SECRETS_UID}:${SECRETS_GID} 755" "$label"
  assert_entry_state "$POSTGRES_SERVER_CRT" "${SECRETS_UID}:${SECRETS_GID} 644" "$label"
}

assert_ssl_on() {
  local label="$1" ssl
  ssl="$(psql_stepca 'show ssl' 2>>"$RUN_LOG")" \
    || fail "${label}: SHOW ssl failed"
  [ "$ssl" = "on" ] || fail "${label}: PostgreSQL ssl is '${ssl}', expected 'on'"
}

write_marker() {
  psql_stepca "CREATE TABLE ${MARKER_TABLE} (token text NOT NULL); INSERT INTO ${MARKER_TABLE} VALUES ('${RUN_TOKEN}')" \
    >>"$RUN_LOG" 2>&1 || fail "failed to write the marker row"
}

assert_marker() {
  local label="$1" token
  token="$(psql_stepca "SELECT token FROM ${MARKER_TABLE}" 2>>"$RUN_LOG")" \
    || fail "${label}: reading the marker row failed"
  [ "$token" = "$RUN_TOKEN" ] \
    || fail "${label}: the marker row reads '${token}', expected '${RUN_TOKEN}'"
}

postgres_leaf_fingerprint() {
  run_sudo cat "$POSTGRES_SERVER_CRT" | openssl x509 -noout -fingerprint -sha256 \
    | sed 's/^.*=//'
}

# Every TCP session to `stepca` that `pg_stat_activity` lists is
# encrypted in `pg_stat_ssl`.  step-ca reconnects lazily after a
# PostgreSQL restart, so an ACME `new-nonce`, which step-ca records in
# the database, is asked for first, and the check waits until step-ca's
# session shows up: with none at all it would pass vacuously.  `-k` is
# deliberate: the request only has to reach step-ca.
assert_stepca_sessions_encrypted() {
  local label="$1" counts total plaintext
  for _ in $(seq 1 "$SESSION_ATTEMPTS"); do
    curl -ksS -o /dev/null -m 5 -I "https://${STEPCA_BIND_ADDR}/acme/acme/new-nonce" \
      >>"$RUN_LOG" 2>&1 || true
    counts="$(psql_stepca "SELECT count(*), count(*) FILTER (WHERE NOT s.ssl) FROM pg_stat_activity a JOIN pg_stat_ssl s USING (pid) WHERE a.datname = 'stepca' AND a.client_addr IS NOT NULL" \
      2>>"$RUN_LOG")" || fail "${label}: reading pg_stat_activity failed"
    total="${counts%%|*}"
    plaintext="${counts#*|}"
    echo "${label}: TCP sessions to stepca: ${total}, unencrypted: ${plaintext}" >>"$RUN_LOG"
    [ "$plaintext" = "0" ] \
      || fail "${label}: ${plaintext} of ${total} TCP sessions to stepca are not encrypted"
    if [ "$total" != "0" ]; then
      return 0
    fi
    sleep "$SESSION_DELAY_SECS"
  done
  fail "${label}: no TCP session to stepca appeared"
}

# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

# Step 1: without the option, PostgreSQL runs exactly as before.
assert_default_postgres_user() {
  log_phase "assert-default-user"
  wait_for_postgres_ready
  assert_container_processes "$POSTGRES_CONTAINER" 999 "" "without --postgres-user"
  assert_postgres_key_owned_by "999:0" "without --postgres-user"
  if run_sudo grep -q '^BOOTROOT_POSTGRES_USER=' "$DOTENV_PATH"; then
    fail "without --postgres-user: .env records BOOTROOT_POSTGRES_USER"
  fi
  log_phase "write-marker"
  write_marker
  assert_marker "after writing it"
}

# Step 2: the option adopted on the installed stack.
install_with_postgres_user() {
  log_phase "install-postgres-user"
  # Free the localhost ports the running stack holds so `infra install`'s
  # published-port preflight passes, as `run-stepca-san.sh` does; the
  # volumes, and with them the initialised OpenBao and the cluster
  # `init` created as uid 999, survive.
  compose_base_as_root stop >>"$RUN_LOG" 2>&1 || fail "failed to stop the stack"
  install_infra --postgres-user "${POSTGRES_UID}:${POSTGRES_GID}" \
    || fail "bootroot infra install --postgres-user failed"
  run_sudo grep -qFx "BOOTROOT_POSTGRES_USER=${POSTGRES_UID}:${POSTGRES_GID}" "$DOTENV_PATH" \
    || fail "infra install did not record BOOTROOT_POSTGRES_USER=${POSTGRES_UID}:${POSTGRES_GID} in .env"
  log_phase "infra-up"
  run_infra_up "after --postgres-user"
}

assert_postgres_user_adopted() {
  log_phase "assert-postgres-user"
  local label="after --postgres-user"
  assert_postgres_runs_as_the_account "$label"
  assert_data_dir_is_the_accounts "$label"
  assert_postgres_key_owned_by "${POSTGRES_UID}:0" "$label"
  assert_postgres_tls_dir_is_the_secrets_owners "$label"
  assert_ssl_on "$label"
  assert_stack_healthy "after-postgres-user"
  assert_stepca_sessions_encrypted "$label"
  assert_marker "$label"
}

# Step 3: a caller that passes only the base compose file still gets the
# uid: Compose reads it from `.env`, so no override file has to be named.
recreate_base_only() {
  log_phase "recreate-base-only"
  compose_base_as_root up -d --no-deps --force-recreate postgres >>"$RUN_LOG" 2>&1 \
    || fail "failed to recreate PostgreSQL from the base compose file alone"
  assert_postgres_runs_as_the_account "after a base-only recreate"
  assert_marker "after a base-only recreate"
  log_phase "infra-up-again"
  run_infra_up "after a base-only recreate"
  assert_ssl_on "after infra up restored the TLS override"
}

# Step 4: a renewal hands the new key to the account too.
rotate_and_assert() {
  log_phase "rotate-infra-cert"
  POSTGRES_FINGERPRINT_BEFORE="$(postgres_leaf_fingerprint)"
  [ -n "$POSTGRES_FINGERPRINT_BEFORE" ] \
    || fail "failed to read the fingerprint of $POSTGRES_SERVER_CRT"
  rotate_infra_cert
  log_phase "assert-rotated"
  local label="after rotate infra-cert" fingerprint
  fingerprint="$(postgres_leaf_fingerprint)"
  [ -n "$fingerprint" ] || fail "${label}: failed to read the fingerprint of $POSTGRES_SERVER_CRT"
  [ "$fingerprint" != "$POSTGRES_FINGERPRINT_BEFORE" ] \
    || fail "${label}: the PostgreSQL leaf still has fingerprint ${fingerprint}; it was not re-issued"
  assert_postgres_key_owned_by "${POSTGRES_UID}:0" "$label"
  assert_postgres_tls_dir_is_the_secrets_owners "$label"
  assert_postgres_runs_as_the_account "$label"
  assert_ssl_on "$label"
  assert_marker "$label"
}

# Runs `service` once from the base compose file with `key` set to
# `value` in `.env`, and asserts that its entrypoint refused to start,
# naming the variable on stderr.  No bootroot command runs meanwhile.
assert_entrypoint_refuses() {
  local service="$1" key="$2" value="$3"
  local out="$ARTIFACT_DIR/refusal-${service}.out" err="$ARTIFACT_DIR/refusal-${service}.err"
  local rc=0
  run_sudo sed -i "s/^${key}=.*/${key}=${value}/" "$DOTENV_PATH" \
    || fail "failed to set ${key}=${value} in .env"
  run_sudo grep -qFx "${key}=${value}" "$DOTENV_PATH" \
    || fail "failed to set ${key}=${value} in .env"
  root_env
  run_sudo timeout "$REFUSAL_TIMEOUT_SECS" env "${ROOT_ENV[@]}" docker compose \
    -p "${COMPOSE_PROJECT_NAME:-bootroot}" -f "$COMPOSE_FILE" \
    run --rm --no-deps -T "$service" >"$out" 2>"$err" || rc=$?
  cat "$err" >>"$RUN_LOG" || true
  [ "$rc" != "0" ] || fail "${service} started with ${key}=${value}"
  [ "$rc" != "124" ] || fail "${service} was still running ${REFUSAL_TIMEOUT_SECS}s after a start with ${key}=${value}"
  grep -qF "$key" "$err" \
    || fail "${service}'s refusal of ${key}=${value} does not name ${key} on stderr; see $err"
  restore_dotenv || fail "failed to restore .env"
  DOTENV_EDITED=1
  run_sudo cmp -s "$DOTENV_BACKUP" "$DOTENV_PATH" || fail "the restored .env differs from its copy"
}

# Step 5: the entrypoints themselves refuse a malformed value.
assert_entrypoints_refuse_malformed_values() {
  log_phase "entrypoint-refusal"
  run_sudo cp -p "$DOTENV_PATH" "$DOTENV_BACKUP" || fail "failed to copy .env"
  DOTENV_EDITED=1
  assert_entrypoint_refuses postgres BOOTROOT_POSTGRES_USER "0:0"
  assert_entrypoint_refuses openbao BOOTROOT_OPENBAO_USER "openbao:openbao"
  restore_dotenv || fail "failed to restore .env"
  run_sudo cmp -s "$DOTENV_BACKUP" "$DOTENV_PATH" || fail "the restored .env differs from its copy"
  log_phase "assert-untouched"
  local label="after the refused starts"
  assert_data_dir_is_the_accounts "$label"
  assert_postgres_runs_as_the_account "$label"
  assert_container_processes "$OPENBAO_CONTAINER" "$SECRETS_UID" "$SECRETS_GID" "$label"
  assert_marker "$label"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  mkdir -p "$ARTIFACT_DIR" "$WORKSPACE_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  : >"$ARTIFACT_DIR/processes.log"
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  ensure_prerequisites
  ensure_bind_host_available "$BIND_HOST" BIND_HOST
  # The assertion comes first, before the teardown and before anything
  # else that could remove a container, for the reason
  # `run-openbao-tls-reown.sh` gives.
  assert_no_leftover_containers "$COMPOSE_FILE" "run-postgres-user startup"
  mark_stack_owned
  compose_down || true
  snapshot_repo_openbao_config

  create_accounts
  prepare_secrets_dir

  install_without_postgres_user
  # `infra install` brings the stack up on the base compose file, so
  # OpenBao is still published on loopback at this point.
  wait_for_openbao_listening "http://127.0.0.1:8200"
  apply_exposed_override
  run_init
  log_phase "assert-healthy"
  assert_stack_healthy "after-init"
  assert_default_postgres_user

  install_with_postgres_user
  assert_postgres_user_adopted

  recreate_base_only
  rotate_and_assert
  assert_entrypoints_refuse_malformed_values

  log_phase "done"
}

main "$@"
