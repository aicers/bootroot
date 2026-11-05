#!/usr/bin/env bash
set -euo pipefail

# Docker-backed E2E harness for `bootroot infra install --openbao-user`.
#
# An installer that runs bootroot's containers as dedicated host
# accounts hands `secrets/` to one such account before `infra install`
# and gives OpenBao the same account through `--openbao-user`.  OpenBao
# then runs as that uid:gid, its raft data and audit directory are the
# account's, and its TLS key is `<uid>:0 0600` instead of `0644`.  This
# harness is that installer:
#
#   1. creates a fresh system account, removed again at cleanup
#   2. creates `secrets/` owned by that account at mode `0700`, before
#      bootroot touches anything
#   3. as root, runs `infra install --openbao-user <uid>:<gid>` with the
#      OpenBao, step-ca and HTTP-01 admin binds, applies the OpenBao
#      exposure override, runs `init --save-unseal-keys` with no
#      `infra up` in between, and checks that the stack comes up healthy
#   4. asserts that every process of OpenBao, step-ca and both OpenBao
#      Agent sidecars runs as the account's uid and gid
#   5. asserts that `openbao/tls/server.key` is `<uid>:0 0600` and
#      `openbao/tls/` is `0755`
#   6. asserts that `find secrets` prints no entry whose uid or gid is
#      not the account's, and no directory whose mode is not `0700`
#   7. recreates OpenBao with `docker compose` naming only the base
#      compose file, and asserts it still runs as the account: the uid
#      reaches Compose by `.env` interpolation, not by an override file
#   8. starts OpenBao once with a harness-local override that
#      bind-mounts a scratch directory at /openbao/audit, holding an
#      `audit.log` another uid owns and a root-owned
#      `rotation-intent.json`, and asserts the entrypoint re-owned the
#      directory and the log and left the marker root's
#   9. runs `infra up` and asserts OpenBao comes up unsealed over the
#      populated raft volume, still as the account
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

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-openbao-user-$(date +%s)}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
# Where `infra install` and `init` write every compose override.
COMPOSE_OVERRIDES_DIR="$(dirname "$COMPOSE_FILE")/compose-overrides"
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

# Non-loopback bind for all three exposed services.  Defaults to the
# docker bridge gateway for the reason `run-openbao-tls-reown.sh` gives:
# every host that can run this harness has the `docker0` interface, and
# a specific (non-wildcard) bind needs no advertise address.
BIND_HOST_DEFAULT="172.17.0.1"
BIND_HOST="${BIND_HOST:-$BIND_HOST_DEFAULT}"
OPENBAO_BIND_ADDR="${BIND_HOST}:8200"
STEPCA_BIND_ADDR="${BIND_HOST}:9000"
HTTP01_ADMIN_BIND_ADDR="${BIND_HOST}:8080"
EXPOSED_OVERRIDE_PATH="$COMPOSE_OVERRIDES_DIR/docker-compose.openbao-exposed.yml"
OPENBAO_REPO_DIR="$ROOT_DIR/openbao"
OPENBAO_REPO_HCL="$OPENBAO_REPO_DIR/openbao.hcl"
OPENBAO_REPO_CONFIG_DIR="$OPENBAO_REPO_DIR/config"
OPENBAO_REPO_TLS_DIR="$OPENBAO_REPO_DIR/tls"
POSTGRES_REPO_DIR="$ROOT_DIR/postgres"
OPENBAO_HCL_SNAPSHOT="$ARTIFACT_DIR/openbao.hcl.pristine"
OPENBAO_CONFIG_SNAPSHOT="$ARTIFACT_DIR/openbao-config.pristine"
OPENBAO_TLS_SNAPSHOT="$ARTIFACT_DIR/openbao-tls.pristine"
DEFAULT_STEPCA_PASSWORD="openbao-user"
DEFAULT_HTTP_HMAC="dev-hmac"

# The account `secrets/` is handed to, and the one `--openbao-user`
# names.  Run-scoped, so a killed run's account never collides with the
# next run's, and at most 32 bytes, the longest name `useradd` accepts.
RUN_TOKEN="$(date +%s)$$"
SECRETS_ACCOUNT="bootroot-ou-${RUN_TOKEN}"
SECRETS_ACCOUNT="${SECRETS_ACCOUNT:0:32}"
SECRETS_UID=""
SECRETS_GID=""
ACCOUNT_CREATED=0
ROOT_WROTE=0
ROOT_ENV=()
CURRENT_PHASE="startup"
OPENBAO_CONTAINER="bootroot-openbao"
# The containers whose every process must be the account's: OpenBao
# through `--openbao-user`, the rest through the owner of `secrets/`.
ACCOUNT_CONTAINERS=(
  "$OPENBAO_CONTAINER"
  bootroot-ca
  bootroot-openbao-agent-stepca
  bootroot-openbao-agent-responder
)
OPENBAO_TLS_KEY="$OPENBAO_REPO_TLS_DIR/server.key"
UNSEAL_KEYS_PATH="$SECRETS_DIR/openbao/unseal-keys.txt"
# A scratch directory outside `secrets/` the harness-local override
# bind-mounts at /openbao/audit, as the registrar endpoint's audit
# override does with the store's `openbao/` directory.
AUDIT_SCRATCH_DIR="$ARTIFACT_DIR/audit-scratch"
AUDIT_OVERRIDE_PATH="$ARTIFACT_DIR/docker-compose.openbao-user-audit.yml"
AUDIT_SCRATCH_CREATED=0
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
  echo "[openbao-user][${CURRENT_PHASE}] $message" >&2
  exit 1
}

on_error() {
  local line="$1"
  echo "[openbao-user] failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "[openbao-user] artifact dir: ${ARTIFACT_DIR}" >&2
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
      echo "run-openbao-user: teardown failed; see ${RUN_LOG}" >&2
      cleanup_status=1
    fi
    report_leftover_containers "$COMPOSE_FILE" "run-openbao-user cleanup" || cleanup_status=1
  fi
  restore_repo_openbao_config
  remove_secrets_dir
  remove_audit_scratch
  # Last: the sidecars ran as this account, and they are gone only once
  # the stack is down.
  remove_account || cleanup_status=1
  exit_with_cleanup_status "$status" "$cleanup_status"
}

# Root ran `infra install`, `init` and `infra up`, and `secrets/` is the account's,
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
  # Removed rather than handed back: the overrides root wrote there,
  # left in the checkout, would be applied by the next run.
  run_sudo rm -rf "$COMPOSE_OVERRIDES_DIR" >/dev/null 2>&1 || true
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
    echo "run-openbao-user: failed to remove account ${SECRETS_ACCOUNT}; see ${RUN_LOG}" >&2
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
  [ "$SECRETS_GID" != "0" ] || fail "account ${SECRETS_ACCOUNT} resolved to gid 0"
  [ "$SECRETS_UID" != "$(id -u)" ] \
    || fail "account ${SECRETS_ACCOUNT} has the invoking user's uid ${SECRETS_UID}"
  # The image's own `openbao` user is uid 100: an account that landed on
  # it would let every OpenBao assertion below pass without the option.
  [ "$SECRETS_UID" != "100" ] \
    || fail "account ${SECRETS_ACCOUNT} has uid 100, the image's openbao user"
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
  run_sudo rm -rf "$SECRETS_DIR" "$COMPOSE_OVERRIDES_DIR"
  run_sudo install -d -m 0700 -o "$SECRETS_UID" -g "$SECRETS_GID" "$SECRETS_DIR" \
    || fail "failed to create $SECRETS_DIR for ${SECRETS_ACCOUNT}"
  assert_entry_state "$SECRETS_DIR" "${SECRETS_UID}:${SECRETS_GID} 700" "prepared"
}

install_infra_with_binds() {
  log_phase "install"
  run_bootroot_as_root infra install \
    --compose-file "$COMPOSE_FILE" \
    --openbao-user "${SECRETS_UID}:${SECRETS_GID}" \
    --openbao-bind "$OPENBAO_BIND_ADDR" \
    --openbao-tls-required \
    --stepca-bind "$STEPCA_BIND_ADDR" \
    --http01-admin-bind "$HTTP01_ADMIN_BIND_ADDR" \
    --http01-admin-tls-required >>"$RUN_LOG" 2>&1 \
    || fail "bootroot infra install failed"
  run_sudo grep -qFx "BOOTROOT_OPENBAO_USER=${SECRETS_UID}:${SECRETS_GID}" "$ROOT_DIR/.env" \
    || fail "infra install did not record BOOTROOT_OPENBAO_USER=${SECRETS_UID}:${SECRETS_GID} in .env"
}

# Applied the way `run-secrets-owner.sh` applies it: the override
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

# Recreates OpenBao through `docker compose` as root, with `-f` for each
# file given and the project the harness installed under.
recreate_openbao_with() {
  local args=() file
  for file in "$@"; do
    args+=(-f "$file")
  done
  root_env
  run_sudo env "${ROOT_ENV[@]}" docker compose -p "${COMPOSE_PROJECT_NAME:-bootroot}" \
    "${args[@]}" up -d --force-recreate --no-deps openbao >>"$RUN_LOG" 2>&1
}

# The audit store an endpoint host binds at /openbao/audit, as the
# entrypoint finds it: root's directory, an `audit.log` another uid
# owns, and the registrar daemon's root-owned `rotation-intent.json`.
prepare_audit_scratch() {
  AUDIT_SCRATCH_CREATED=1
  local other_uid=4242
  if [ "$other_uid" = "$SECRETS_UID" ]; then
    other_uid=4243
  fi
  run_sudo rm -rf "$AUDIT_SCRATCH_DIR"
  run_sudo install -d -m 0755 -o 0 -g 0 "$AUDIT_SCRATCH_DIR" \
    || fail "failed to create $AUDIT_SCRATCH_DIR"
  run_sudo install -m 0600 -o "$other_uid" -g "$other_uid" /dev/null "$AUDIT_SCRATCH_DIR/audit.log" \
    || fail "failed to create $AUDIT_SCRATCH_DIR/audit.log"
  run_sudo install -m 0600 -o 0 -g 0 /dev/null "$AUDIT_SCRATCH_DIR/rotation-intent.json" \
    || fail "failed to create $AUDIT_SCRATCH_DIR/rotation-intent.json"
  cat >"$AUDIT_OVERRIDE_PATH" <<EOF
services:
  openbao:
    volumes:
      - "${AUDIT_SCRATCH_DIR}:/openbao/audit"
EOF
}

remove_audit_scratch() {
  if [ "$AUDIT_SCRATCH_CREATED" = "1" ]; then
    run_sudo rm -rf "$AUDIT_SCRATCH_DIR" >/dev/null 2>&1 || true
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
  local path="$1" expected="$2" label="$3" actual
  actual="$(run_sudo stat -c '%u:%g' "$path" 2>>"$RUN_LOG")" \
    || fail "${label}: ${path} does not exist"
  [ "$actual" = "$expected" ] \
    || fail "${label}: ${path} is owned by ${actual}, expected ${expected}"
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

# Every process `docker top` lists for `container` runs as the
# account's uid and gid.
assert_container_processes_are_the_accounts() {
  local container="$1" label="$2" listing processes foreign
  listing="$(docker top "$container" -o pid,uid,gid,args 2>>"$RUN_LOG")" \
    || fail "${label}: docker top ${container} failed"
  printf '%s\n%s\n' "== ${label}: ${container}" "$listing" >>"$ARTIFACT_DIR/processes.log"
  processes="$(tail -n +2 <<<"$listing")"
  [ -n "$processes" ] || fail "${label}: ${container} lists no process"
  foreign="$(awk -v uid="$SECRETS_UID" -v gid="$SECRETS_GID" \
    '$2 != uid || $3 != gid' <<<"$processes")"
  [ -z "$foreign" ] \
    || fail "${label}: ${container} runs processes not as ${SECRETS_UID}:${SECRETS_GID}: ${foreign//$'\n'/; }"
}

assert_account_processes() {
  log_phase "assert-processes"
  local container
  for container in "${ACCOUNT_CONTAINERS[@]}"; do
    assert_container_processes_are_the_accounts "$container" "after init"
  done
  # A here-string, not a pipe, for the reason `ensure_openssl` gives.
  # `docker top` refuses a column list without `pid`: the daemon maps
  # each row back to the container through that column.
  local listing
  listing="$(docker top "$OPENBAO_CONTAINER" -o pid,args 2>>"$RUN_LOG")" \
    || fail "after init: docker top ${OPENBAO_CONTAINER} failed"
  grep -qE '(^|[ /])bao server' <<<"$listing" \
    || fail "after init: ${OPENBAO_CONTAINER} lists no bao server process"
}

assert_openbao_tls_key() {
  log_phase "assert-tls-key"
  assert_entry_state "$OPENBAO_TLS_KEY" "${SECRETS_UID}:0 600" "after init"
  local mode
  mode="$(run_sudo stat -c '%a' "$OPENBAO_REPO_TLS_DIR" 2>>"$RUN_LOG")" \
    || fail "after init: ${OPENBAO_REPO_TLS_DIR} does not exist"
  [ "$mode" = "755" ] \
    || fail "after init: ${OPENBAO_REPO_TLS_DIR} has mode ${mode}, expected 755"
}

# The contract: every entry under `secrets/` is the account's, and
# every directory there is `0700`.  No root-by-policy directory exists
# in this run: the registrar endpoint is not enabled.
assert_secrets_tree_ownership() {
  log_phase "assert-secrets-tree"
  local expected_dir="${SECRETS_UID}:${SECRETS_GID} 700"
  assert_entry_state "$SECRETS_DIR" "$expected_dir" "after init"
  assert_entry_owner "$UNSEAL_KEYS_PATH" "${SECRETS_UID}:${SECRETS_GID}" "after init"

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

# A caller that passes only the base compose file still gets the uid:
# Compose reads it from `.env`, so no override file has to be named.
recreate_base_only() {
  log_phase "recreate-base-only"
  recreate_openbao_with "$COMPOSE_FILE" \
    || fail "failed to recreate OpenBao from the base compose file alone"
  wait_for_openbao_server
  assert_container_processes_are_the_accounts "$OPENBAO_CONTAINER" "after a base-only recreate"
}

# The entrypoint re-owns the audit directory and the active log, and
# leaves the root-owned marker the registrar daemon authenticates by its
# owner.
assert_audit_dir_handover() {
  log_phase "audit-dir"
  prepare_audit_scratch
  recreate_openbao_with "$COMPOSE_FILE" "$AUDIT_OVERRIDE_PATH" \
    || fail "failed to start OpenBao with the audit scratch override"
  wait_for_openbao_server
  assert_container_processes_are_the_accounts "$OPENBAO_CONTAINER" "with the audit scratch mounted"
  assert_entry_state "$AUDIT_SCRATCH_DIR" "${SECRETS_UID}:${SECRETS_GID} 700" "audit directory"
  assert_entry_owner "$AUDIT_SCRATCH_DIR/audit.log" "${SECRETS_UID}:${SECRETS_GID}" "audit log"
  assert_entry_owner "$AUDIT_SCRATCH_DIR/rotation-intent.json" "0:0" "rotation intent"
}

# `infra up` recreates OpenBao on the recorded exposure override, without
# the harness's audit override, and unseals it from the saved keys over
# the raft volume `init` populated.  `bao status` exits 0 only when
# unsealed; its `Sealed false` line is asserted too.
run_infra_up_and_assert_unsealed() {
  log_phase "infra-up"
  run_bootroot_as_root infra up \
    --compose-file "$COMPOSE_FILE" \
    --openbao-unseal-from-file "$UNSEAL_KEYS_PATH" >>"$RUN_LOG" 2>&1 \
    || fail "bootroot infra up failed"
  wait_for_openbao_server
  log_phase "assert-unsealed"
  local status_log="$ARTIFACT_DIR/openbao-status-after-up.log" status_rc=0
  docker exec -e BAO_ADDR="https://127.0.0.1:8200" -e BAO_SKIP_VERIFY=true \
    "$OPENBAO_CONTAINER" bao status >"$status_log" 2>&1 || status_rc=$?
  if [ "$status_rc" != "0" ] || ! grep -qE '^Sealed[[:space:]]+false$' "$status_log"; then
    {
      echo "bao status after infra up (rc=${status_rc}):"
      cat "$status_log" || true
    } >>"$RUN_LOG"
    fail "OpenBao is not unsealed after infra up (bao status rc=${status_rc})"
  fi
  assert_container_processes_are_the_accounts "$OPENBAO_CONTAINER" "after infra up"
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
  assert_no_leftover_containers "$COMPOSE_FILE" "run-openbao-user startup"
  mark_stack_owned
  compose_down || true
  snapshot_repo_openbao_config

  create_account
  prepare_secrets_dir

  install_infra_with_binds
  # `infra install` brings the stack up on the base compose file, so
  # OpenBao is still published on loopback at this point.
  wait_for_openbao_listening "http://127.0.0.1:8200"

  apply_exposed_override
  run_init
  assert_stack_healthy
  assert_account_processes
  assert_openbao_tls_key
  assert_secrets_tree_ownership

  recreate_base_only
  assert_audit_dir_handover
  run_infra_up_and_assert_unsealed

  log_phase "done"
}

main "$@"
