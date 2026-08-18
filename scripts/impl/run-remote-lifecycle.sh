#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# shellcheck source=lib/audit-log.sh
. "$SCRIPT_DIR/lib/audit-log.sh"
# shellcheck source=lib/leftovers.sh
. "$SCRIPT_DIR/lib/leftovers.sh"
# shellcheck source=lib/ports.sh
. "$SCRIPT_DIR/lib/ports.sh"
# shellcheck source=lib/run-scope.sh
. "$SCRIPT_DIR/lib/run-scope.sh"

# Ambient environment sanitisation.
#
# `COMPOSE_PROJECT_NAME` is what this run hands the binary its own
# Compose project in, and it is exported with that value in
# `derive_run_scope`.  It is cleared first because everything before that
# point would otherwise run against an inherited one: a value from the
# invoking shell would send those calls at a different project than the
# one this run creates, and it must not survive as far as `infra
# install`, which would then record containers named after this run's
# instance in someone else's project.  The four host-port variables are
# cleared for the same reason — they outrank the `.env` the install
# writes, and an inherited value would republish this run's stack on a
# port another run already holds.  `POSTGRES_HOST`/`POSTGRES_PORT` are
# this script's own host-side wiring and are re-exported below.
# `BOOTROOT_HTTP01_IMAGE` is cleared for the third: it names the tag the
# responder build is written to and read back from, and an inherited one
# would put this run's build on another run's tag.
#
# Clearing them makes an inherited value harmless rather than fatal, and
# it is only the first of two layers: `assert_resolved_compose_project`
# reads the project the install actually resolved back off a container
# rather than assuming this worked.
unset COMPOSE_PROJECT_NAME
unset POSTGRES_HOST_PORT OPENBAO_HOST_PORT STEPCA_HOST_PORT HTTP01_ADMIN_HOST_PORT
unset BOOTROOT_HTTP01_IMAGE

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-remote-lifecycle-$(date +%s)}"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
SECRETS_DIR="${SECRETS_DIR:-$ROOT_DIR/secrets}"
CONTROL_DIR="${CONTROL_DIR:-$ARTIFACT_DIR/control-node}"
REMOTE_DIR="${REMOTE_DIR:-$ARTIFACT_DIR/remote-node}"
REMOTE_AGENT_CONFIG_PATH="${REMOTE_AGENT_CONFIG_PATH:-$REMOTE_DIR/agent.toml}"
REMOTE_CERTS_DIR="${REMOTE_CERTS_DIR:-$REMOTE_DIR/certs}"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"
INFRA_UP_ATTEMPTS="${INFRA_UP_ATTEMPTS:-12}"
INFRA_UP_DELAY_SECS="${INFRA_UP_DELAY_SECS:-10}"
VERIFY_ATTEMPTS="${VERIFY_ATTEMPTS:-5}"
VERIFY_DELAY_SECS="${VERIFY_DELAY_SECS:-5}"
HTTP01_TARGET_ATTEMPTS="${HTTP01_TARGET_ATTEMPTS:-40}"
HTTP01_TARGET_DELAY_SECS="${HTTP01_TARGET_DELAY_SECS:-2}"
RESPONDER_READY_ATTEMPTS="${RESPONDER_READY_ATTEMPTS:-30}"
RESPONDER_READY_DELAY_SECS="${RESPONDER_READY_DELAY_SECS:-1}"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"
BOOTROOT_AGENT_BIN="${BOOTROOT_AGENT_BIN:-$ROOT_DIR/target/debug/bootroot-agent}"
RESOLUTION_MODE="${RESOLUTION_MODE:-no-hosts}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-summary.json"
CERT_META_DIR="$ARTIFACT_DIR/cert-meta"
HOSTS_MARKER="# bootroot-e2e-main-remote-lifecycle"

SERVICE_NAME="edge-proxy"
HOSTNAME="edge-node-02"
DOMAIN="trusted.domain"
INSTANCE_ID="101"
SERVICE_NAME_2="web-app"
HOSTNAME_2="web-02"
INSTANCE_ID_2="102"
REMOTE_AGENT_CONFIG_PATH_2="$REMOTE_DIR/agent-${SERVICE_NAME_2}.toml"
SERVICE_KV_PATH_BASE="bootroot/services/${SERVICE_NAME}"
SERVICE_KV_PATH_BASE_2="bootroot/services/${SERVICE_NAME_2}"

STEPCA_HOST_IP="127.0.0.1"
RESPONDER_HOST_IP="127.0.0.1"
STEPCA_HOST_NAME="stepca.internal"
RESPONDER_HOST_NAME="responder.internal"

STEPCA_SERVER_URL=""
RESPONDER_URL=""
RUNTIME_SERVICE_ADD_ROLE_ID=""
RUNTIME_SERVICE_ADD_SECRET_ID=""
RUNTIME_ROTATE_ROLE_ID=""
RUNTIME_ROTATE_SECRET_ID=""
CURRENT_PHASE="init"
# PID of the background bootroot-agent daemon started for the genuine
# KV force-reissue round-trip. Empty when no daemon is running; the
# cleanup trap kills it so a failed run never leaks the process.
REMOTE_AGENT_PID=""
# Bounds the genuine force-reissue --wait round-trip. The agent's default
# fast_poll_interval is 30s, so allow generous margin over one poll plus an
# ACME renewal for slow CI runners.
FORCE_REISSUE_WAIT_TIMEOUT="${FORCE_REISSUE_WAIT_TIMEOUT:-120s}"
# Bounds how long the self-heal phase waits for a *running* agent's
# fast-poll loop to refresh the on-disk secret_id and re-render
# [trust]+ca-bundle after a control-plane rotation. Must exceed one
# fast_poll_interval (default 30s); 30 * 2s = 60s of margin.
SELFHEAL_ATTEMPTS="${SELFHEAL_ATTEMPTS:-30}"
SELFHEAL_DELAY_SECS="${SELFHEAL_DELAY_SECS:-2}"
# The extra trust anchor's fingerprint appended by run_rotation_trust_sync,
# exported so the self-heal assertion can confirm the running agent wrote it
# into the remote agent.toml [trust] pins via fast-poll.
TRUST_SYNC_EXTRA_FINGERPRINT=""

# Prefix every derived instance name starts with.  Short on purpose: the
# instance-name budget is 39 characters and what follows it is the run
# token, whose tail is the only part distinguishing two runs started in
# the same second.
RUN_INSTANCE_PREFIX="e2e-remote-"
# Prefix every derived Compose project starts with.  Long on purpose,
# and nothing like the instance prefix: the project has no length budget
# to spend, so it says in full what the truncated instance name cannot.
RUN_PROJECT_PREFIX="bootroot-e2e-remote-"
# This run's install identity, the Compose project every `docker compose`
# call is scoped to, the tag its responder image is built under, and the
# four ports it publishes on `127.0.0.1`.  All derived in
# `derive_run_scope`, which `main` runs before anything reads them.
RUN_INSTANCE=""
COMPOSE_PROJECT=""
RUN_HTTP01_IMAGE=""
POSTGRES_HOST_PORT=0
OPENBAO_HOST_PORT=0
STEPCA_HOST_PORT=0
HTTP01_ADMIN_HOST_PORT=0
OPENBAO_URL=""
RUN_IDENTITY_JSON="$ARTIFACT_DIR/run-identity.json"

log_phase() {
  local phase="$1"
  CURRENT_PHASE="$phase"
  local now
  now="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  printf '{"ts":"%s","phase":"%s","mode":"%s"}\n' "$now" "$phase" "$RESOLUTION_MODE" >>"$PHASE_LOG"
}

fail() {
  local message="$1"
  printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$message" >>"$RUN_LOG" || true
  echo "$message" >&2
  exit 1
}

run_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
    return
  fi
  sudo -n "$@"
}

run_bootroot_control() {
  (
    cd "$CONTROL_DIR"
    "$BOOTROOT_BIN" "$@"
  )
}

# Picks this run's four published ports and exports them.
#
# The exports are for this script's own raw `docker compose` calls, which
# interpolate the compose file's `ports:` themselves; `infra install`
# receives the same four values as flags, so the `.env` it writes records
# them and every later `bootroot` invocation resolves the same ports
# whether or not it inherited the exports.
allocate_run_ports() {
  pick_free_port
  POSTGRES_HOST_PORT="$PICKED_PORT"
  pick_free_port
  OPENBAO_HOST_PORT="$PICKED_PORT"
  pick_free_port
  STEPCA_HOST_PORT="$PICKED_PORT"
  pick_free_port
  HTTP01_ADMIN_HOST_PORT="$PICKED_PORT"
  export POSTGRES_HOST_PORT OPENBAO_HOST_PORT STEPCA_HOST_PORT HTTP01_ADMIN_HOST_PORT
  export POSTGRES_HOST="127.0.0.1"
  export POSTGRES_PORT="$POSTGRES_HOST_PORT"
}

# Records what this run chose, so a failed run can be read afterwards:
# which containers were its own, which project to look for, and which
# ports to probe.
write_run_identity_artifact() {
  cat >"$RUN_IDENTITY_JSON" <<EOF
{
  "instance": "${RUN_INSTANCE}",
  "compose_project": "${COMPOSE_PROJECT}",
  "http01_image": "${RUN_HTTP01_IMAGE}",
  "ports": {
    "postgres": ${POSTGRES_HOST_PORT},
    "openbao": ${OPENBAO_HOST_PORT},
    "stepca": ${STEPCA_HOST_PORT},
    "http01_admin": ${HTTP01_ADMIN_HOST_PORT}
  }
}
EOF
}

# Derives everything that makes this run's stack its own, before any of
# it is read.
derive_run_scope() {
  local token
  token="$(run_scope_token "$ARTIFACT_DIR")"
  RUN_INSTANCE="$(run_scope_instance "$RUN_INSTANCE_PREFIX" "$token")"
  run_scope_assert_valid_instance "$RUN_INSTANCE"
  COMPOSE_PROJECT="$(run_scope_project "$RUN_PROJECT_PREFIX" "$token")"
  run_scope_assert_valid_project "$COMPOSE_PROJECT"
  # Compose reads the invoking process's environment ahead of the project
  # directory's `.env`, so this is what names the containers of the raw
  # `docker compose` calls below — including the ones made before `infra
  # install` has written anything.
  export BOOTROOT_INSTANCE="$RUN_INSTANCE"
  # And this is how the derived project reaches the binary.  It outranks
  # the `--instance-name` the install declares for the project and for
  # nothing else, so `bootroot` scopes itself to the same project as the
  # raw `docker compose` calls here while still naming every container
  # after the instance.  Exported rather than recorded because that is
  # what the variable is: a per-invocation Compose override, deliberately
  # never written to `.env`.
  export COMPOSE_PROJECT_NAME="$COMPOSE_PROJECT"
  # The one image the compose file builds, and the last thing two runs
  # would still share: its `image:` is the tag `up --build` writes to and
  # every later recreate reads back, so a run left on the shipped default
  # can be handed the other run's build the moment it recreates the
  # responder to apply its DNS aliases.  Compose interpolates this for
  # the raw calls here, and `infra install` inherits it for the build
  # itself.
  RUN_HTTP01_IMAGE="$(run_scope_http01_image "$RUN_INSTANCE")"
  export BOOTROOT_HTTP01_IMAGE="$RUN_HTTP01_IMAGE"
  # `service add` resolves its identity from the directory this script
  # runs `bootroot` from rather than from the compose file's, so that
  # directory has to record the instance too.
  write_instance_dotenv "$CONTROL_DIR" "$RUN_INSTANCE"
  allocate_run_ports
  OPENBAO_URL="http://${STEPCA_HOST_IP}:${OPENBAO_HOST_PORT}"
  write_run_identity_artifact
  printf '[lifecycle] instance=%s project=%s image=%s postgres=%s openbao=%s stepca=%s http01=%s\n' \
    "$RUN_INSTANCE" "$COMPOSE_PROJECT" "$RUN_HTTP01_IMAGE" "$POSTGRES_HOST_PORT" \
    "$OPENBAO_HOST_PORT" "$STEPCA_HOST_PORT" "$HTTP01_ADMIN_HOST_PORT" >>"$RUN_LOG"
}

# Collects the containers, volumes and networks of runs that were killed
# before their own teardown.
#
# Unique naming is what makes this necessary: nothing will ever again be
# named the same as a dead run's leftovers, so no later run tears them
# down by accident, and they accumulate for as long as the machine runs.
# It is reported rather than fatal — this run's identity is its own, so
# another run's garbage cannot collide with it.
collect_dead_runs() {
  sweep_dead_run_instances "run-remote-lifecycle startup" "$RUN_LOG" \
    || echo "run-remote-lifecycle: a dead run's leftovers could not be fully collected; see ${RUN_LOG}" >&2
}

# Asserts that the project `bootroot` resolved is the one this script
# scopes its own `docker compose` calls to.
#
# Read off a container the install created rather than assumed.  The
# instance and the project are separately derived and deliberately
# different strings, so nothing about the container names proves the
# binary agreed with this script about the project — and a run whose
# binary resolved some other project would tear down a project holding
# none of its containers and leave the whole stack behind.
assert_resolved_compose_project() {
  local container="${RUN_INSTANCE}-openbao" resolved
  resolved="$(docker inspect \
    --format '{{index .Config.Labels "com.docker.compose.project"}}' \
    "$container" 2>>"$RUN_LOG" || true)"
  [ "$resolved" = "$COMPOSE_PROJECT" ] || fail \
    "the install resolved Compose project '${resolved}' for ${container}, but this run scopes its own compose calls to '${COMPOSE_PROJECT}'"
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
  command -v python3 >/dev/null 2>&1 || fail "python3 is required"
  # This harness parses the remote agent's TOML config with `tomllib`,
  # which is standard library only from 3.11.  Check it here so an older
  # interpreter stops the run before any container is started, rather
  # than at the first import several phases in.
  python3 -c 'import tomllib' >/dev/null 2>&1 \
    || fail "python3 with tomllib (3.11+) is required"
  ensure_openssl
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  [ -x "$BOOTROOT_REMOTE_BIN" ] || fail "bootroot-remote binary not executable: $BOOTROOT_REMOTE_BIN"
  [ -x "$BOOTROOT_AGENT_BIN" ] || fail "bootroot-agent binary not executable: $BOOTROOT_AGENT_BIN"
}

# Teardown output goes to the run log rather than to `/dev/null`: a
# teardown that removed nothing has to be distinguishable from one that
# removed everything.  The status is the caller's to decide — the
# start-of-run call tolerates a failure, `cleanup` does not.
compose_down() {
  docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" down -v --remove-orphans >>"$RUN_LOG" 2>&1
}

capture_artifacts() {
  docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
  docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs "${RUN_INSTANCE}-openbao-agent-stepca" >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs "${RUN_INSTANCE}-openbao-agent-responder" >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
}

cleanup_hosts() {
  if [ "$RESOLUTION_MODE" != "hosts" ]; then
    return 0
  fi
  # Only the run holding the lock has entries of its own in that file.
  # The rewrite below drops every line carrying this script's fixed
  # marker, so it cannot tell one run's lines from another's — and a run
  # refused at the lock, or one that failed before taking it, would
  # strip the live holder's entries out from under it.
  if ! hosts_lock_held; then
    return 0
  fi
  if [ "$(id -u)" -eq 0 ] || command -v sudo >/dev/null 2>&1; then
    local tmp_file
    tmp_file="$(mktemp)"
    run_sudo awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' /etc/hosts >"$tmp_file"
    run_sudo cp "$tmp_file" /etc/hosts
    rm -f "$tmp_file"
  fi
  release_hosts_lock
}

stop_remote_agent() {
  [ -n "$REMOTE_AGENT_PID" ] || return 0
  kill "$REMOTE_AGENT_PID" >/dev/null 2>&1 || true
  wait "$REMOTE_AGENT_PID" 2>/dev/null || true
  REMOTE_AGENT_PID=""
}

cleanup() {
  local status=$?
  local cleanup_status=0
  log_phase "cleanup"
  stop_remote_agent
  cleanup_hosts
  capture_artifacts
  # Nothing is torn down before the startup assertion passed: what is on
  # this host then belongs to whoever put it there, and removing it is
  # exactly what the assertion refused to do.
  if stack_owned; then
    if ! compose_down; then
      echo "run-remote-lifecycle: teardown failed; see ${RUN_LOG}" >&2
      cleanup_status=1
    fi
    report_leftover_containers "$COMPOSE_FILE" "run-remote-lifecycle cleanup" "$RUN_INSTANCE" || cleanup_status=1
    # `down` removes containers, never images, so the tag this run built
    # under is its to remove — and it is leftovers of exactly the kind
    # the marker exists for: named after this run's instance, so nothing
    # later is named the same and no sweep would ask about it once the
    # marker is gone.  A tag that survives therefore keeps the marker,
    # which is what `cleanup_status` decides below.
    if ! remove_run_image "$RUN_HTTP01_IMAGE" "$RUN_LOG"; then
      echo "run-remote-lifecycle: the responder image ${RUN_HTTP01_IMAGE} could not be removed; see ${RUN_LOG}" >&2
      cleanup_status=1
    fi
  fi
  # Last, and outside the ownership guard: the marker says this run is
  # still using its instance, and it has to outlive everything that could
  # leave a container behind.  It removes only a marker recording this
  # process's own pid, so a run that never wrote one removes nothing, and
  # only when the teardown above left nothing for the next run to
  # collect.
  remove_run_marker "$RUN_INSTANCE" "$cleanup_status"
  exit_with_cleanup_status "$status" "$cleanup_status"
}

on_error() {
  local line="$1"
  echo "run-remote-lifecycle failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "artifact dir: ${ARTIFACT_DIR}" >&2
  [ -f "$RUN_LOG" ] && tail -n 120 "$RUN_LOG" >&2 || true
  [ -f "$INIT_RAW_LOG" ] && tail -n 120 "$INIT_RAW_LOG" >&2 || true
  [ -f "$INIT_LOG" ] && tail -n 120 "$INIT_LOG" >&2 || true
}

add_hosts_entry() {
  local ip="$1"
  local host="$2"
  if grep -qE "[[:space:]]${host}([[:space:]]|$)" /etc/hosts; then
    return 0
  fi
  echo "${ip} ${host} ${HOSTS_MARKER}" | run_sudo tee -a /etc/hosts >/dev/null
}

configure_resolution_mode() {
  case "$RESOLUTION_MODE" in
    hosts)
      if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 || fail "hosts mode requires sudo"
        run_sudo true || fail "hosts mode requires non-interactive sudo (sudo -n)"
      fi
      # Before the first edit, and after the sudo checks: a run that
      # cannot write the file has no business holding the machine's turn
      # at it.  Everything else about this run is its own, so this is
      # the one thing a second run still has to wait for.  The lock is
      # one file rather than one per script, because both scripts add
      # the same two host names — a local run and a remote run overwrite
      # each other exactly as two local runs would.
      acquire_hosts_lock "run-remote-lifecycle.sh, ${ARTIFACT_DIR}"
      add_hosts_entry "$STEPCA_HOST_IP" "$STEPCA_HOST_NAME"
      add_hosts_entry "$RESPONDER_HOST_IP" "$RESPONDER_HOST_NAME"
      STEPCA_SERVER_URL="https://${STEPCA_HOST_NAME}:${STEPCA_HOST_PORT}/acme/acme/directory"
      RESPONDER_URL="http://${RESPONDER_HOST_NAME}:${HTTP01_ADMIN_HOST_PORT}"
      ;;
    no-hosts)
      STEPCA_SERVER_URL="https://localhost:${STEPCA_HOST_PORT}/acme/acme/directory"
      RESPONDER_URL="http://${RESPONDER_HOST_IP}:${HTTP01_ADMIN_HOST_PORT}"
      ;;
    *)
      fail "Unsupported RESOLUTION_MODE: $RESOLUTION_MODE"
      ;;
  esac
}

reset_stepca_materials_for_e2e() {
  if [ "${RESET_STEPCA_MATERIALS:-1}" != "1" ]; then
    return 0
  fi
  rm -rf "$SECRETS_DIR/config" "$SECRETS_DIR/certs" "$SECRETS_DIR/db" "$SECRETS_DIR/secrets"
}

install_infra() {
  mkdir -p "$REMOTE_CERTS_DIR"
  chmod 700 "$REMOTE_CERTS_DIR"
  # Remove stale .env so infra install generates a fresh bootstrap password.
  rm -f "$ROOT_DIR/.env"
  # The identity and the four ports travel as flags rather than as the
  # exported variables.  `BOOTROOT_INSTANCE` out of the process
  # environment is never consulted by bootroot, so exporting it alone
  # would split the run in two: Compose would interpolate the derived
  # name for this script's own calls while the binary installed at
  # `bootroot`.  The ports are flags for the other half of the same
  # reason — a flag is recorded in the `.env` the install writes, so
  # every later `bootroot` invocation in this run resolves the same
  # ports whether or not it inherited the exports.
  #
  # The Compose project is the one value that travels the other way, as
  # the exported `COMPOSE_PROJECT_NAME` `derive_run_scope` set.  There is
  # no flag for it and there is deliberately no `.env` key either: it is
  # Compose's own per-invocation override, and what makes it reliable
  # here is that this script exports it for every `bootroot` invocation
  # it makes, not that anything recorded it.
  run_bootroot_control infra install \
    --compose-file "$COMPOSE_FILE" \
    --instance-name "$RUN_INSTANCE" \
    --postgres-host-port "$POSTGRES_HOST_PORT" \
    --openbao-host-port "$OPENBAO_HOST_PORT" \
    --stepca-host-port "$STEPCA_HOST_PORT" \
    --http01-admin-host-port "$HTTP01_ADMIN_HOST_PORT" \
    >>"$RUN_LOG" 2>&1
}

wait_for_openbao_api() {
  local attempt
  for attempt in $(seq 1 30); do
    local code
    code="$(curl -sS -o /dev/null -w '%{http_code}' "${OPENBAO_URL}/v1/sys/health" || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      return 0
    fi
    sleep 1
  done
  docker logs "${RUN_INSTANCE}-openbao" >>"$RUN_LOG" 2>&1 || true
  fail "openbao API did not become reachable before init"
}

wait_for_postgres_admin() {
  local host_port="${POSTGRES_HOST_PORT}"
  local admin_user="${POSTGRES_USER:-step}"
  local attempt
  for attempt in $(seq 1 30); do
    # Probe over TCP: the initdb bootstrap server listens only on the Unix
    # socket, so a socket-based pg_isready reports ready before the final
    # server (the one init connects to over TCP) is up.
    if docker exec "${RUN_INSTANCE}-postgres" pg_isready -h 127.0.0.1 -U "$admin_user" -d postgres >/dev/null 2>&1 &&
      bash -lc ": >/dev/tcp/127.0.0.1/${host_port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "${RUN_INSTANCE}-postgres" >>"$RUN_LOG" 2>&1 || true
  fail "postgres admin endpoint did not become reachable before init"
}

wait_for_responder_admin() {
  local admin_url="${RESPONDER_URL%/}/admin/http01"
  local attempt
  for attempt in $(seq 1 "$RESPONDER_READY_ATTEMPTS"); do
    local code
    code="$(curl -sS -m 2 -o /dev/null -w '%{http_code}' "$admin_url" || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      return 0
    fi
    sleep "$RESPONDER_READY_DELAY_SECS"
  done
  docker logs "${RUN_INSTANCE}-http01" >>"$RUN_LOG" 2>&1 || true
  fail "responder admin endpoint did not become reachable before init: $admin_url"
}

run_bootstrap_chain() {
  # Containers are already running from install_infra().  step-ca is
  # expected to be restarting (no ca.json yet); init will bootstrap it.
  # Only wait for the services that init needs.
  wait_for_postgres_admin
  wait_for_openbao_api
  wait_for_responder_admin

  log_phase "init"
  rm -f "$CONTROL_DIR/state.json"
  # Answer every prompt with its own flag and run with stdin closed, so
  # the run neither depends on which of password.txt, ca.json and
  # state.json the cleanup above happened to leave behind nor needs a
  # TTY.  An overwrite flag whose file is absent is a silent no-op.
  if ! BOOTROOT_LANG=en run_bootroot_control init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$INIT_SUMMARY_JSON" \
    --enable auto-generate,show-secrets,db-provision \
    --stepca-provisioner "acme" \
    --stepca-password "password" \
    --no-eab \
    --save-unseal-keys \
    --overwrite-password \
    --overwrite-ca-json \
    --overwrite-state \
    --confirm-db-provision \
    --http-hmac "dev-hmac" \
    --db-user "step" \
    --db-name "stepca" \
    --responder-url "$RESPONDER_URL" </dev/null >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 160 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
    fail "bootroot init failed"
  fi

  RUNTIME_SERVICE_ADD_ROLE_ID="$(
    jq -r '.approles[] | select(.label == "runtime_service_add") | .role_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  RUNTIME_SERVICE_ADD_SECRET_ID="$(
    jq -r '.approles[] | select(.label == "runtime_service_add") | .secret_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  RUNTIME_ROTATE_ROLE_ID="$(
    jq -r '.approles[] | select(.label == "runtime_rotate") | .role_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  RUNTIME_ROTATE_SECRET_ID="$(
    jq -r '.approles[] | select(.label == "runtime_rotate") | .secret_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  [ -n "${RUNTIME_SERVICE_ADD_ROLE_ID:-}" ] || fail "Failed to parse runtime_service_add role_id"
  [ -n "${RUNTIME_SERVICE_ADD_SECRET_ID:-}" ] || fail "Failed to parse runtime_service_add secret_id"
  [ -n "${RUNTIME_ROTATE_ROLE_ID:-}" ] || fail "Failed to parse runtime_rotate role_id"
  [ -n "${RUNTIME_ROTATE_SECRET_ID:-}" ] || fail "Failed to parse runtime_rotate secret_id"
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$INIT_LOG"

  log_phase "service-add"
  run_bootroot_control service add \
    --registration-id "$SERVICE_NAME" \
    --service-name "$SERVICE_NAME" \
    --delivery-mode remote-bootstrap \
    --hostname "$HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$REMOTE_AGENT_CONFIG_PATH" \
    --cert-path "$REMOTE_CERTS_DIR/${SERVICE_NAME}.crt" \
    --key-path "$REMOTE_CERTS_DIR/${SERVICE_NAME}.key" \
    --instance-id "$INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

  run_bootroot_control service add \
    --registration-id "$SERVICE_NAME_2" \
    --service-name "$SERVICE_NAME_2" \
    --delivery-mode remote-bootstrap \
    --hostname "$HOSTNAME_2" \
    --domain "$DOMAIN" \
    --agent-config "$REMOTE_AGENT_CONFIG_PATH_2" \
    --cert-path "$REMOTE_CERTS_DIR/${SERVICE_NAME_2}.crt" \
    --key-path "$REMOTE_CERTS_DIR/${SERVICE_NAME_2}.key" \
    --instance-id "$INSTANCE_ID_2" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1
}

copy_remote_bootstrap_materials() {
  local service="$1"
  local control_service_dir="$SECRETS_DIR/services/$service"
  local remote_service_dir="$REMOTE_DIR/secrets/services/$service"
  mkdir -p "$remote_service_dir"
  cp "$control_service_dir/role_id" "$remote_service_dir/role_id"
  cp "$control_service_dir/secret_id" "$remote_service_dir/secret_id"
  chmod 600 "$remote_service_dir/role_id" "$remote_service_dir/secret_id"
}

apply_dns_aliases() {
  local override="$ARTIFACT_DIR/docker-compose.dns-aliases.yml"
  cat >"$override" <<YAML
services:
  bootroot-http01:
    networks:
      default:
        aliases:
          - ${INSTANCE_ID}.${SERVICE_NAME}.${HOSTNAME}.${DOMAIN}
          - ${INSTANCE_ID_2}.${SERVICE_NAME_2}.${HOSTNAME_2}.${DOMAIN}
YAML
  # Include the responder compose override (written by bootroot init) so
  # that recreating bootroot-http01 preserves both the rendered config
  # mount and the DNS aliases.
  local responder_override="$SECRETS_DIR/responder/docker-compose.responder.override.yml"
  local -a compose_args=(-p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" -f "$override")
  if [ -f "$responder_override" ]; then
    compose_args+=(-f "$responder_override")
  fi
  docker compose "${compose_args[@]}" up -d bootroot-http01 >>"$RUN_LOG" 2>&1
}

wait_for_stepca_http01_targets() {
  local hosts
  hosts=(
    "${INSTANCE_ID}.${SERVICE_NAME}.${HOSTNAME}.${DOMAIN}"
    "${INSTANCE_ID_2}.${SERVICE_NAME_2}.${HOSTNAME_2}.${DOMAIN}"
  )

  local host
  for host in "${hosts[@]}"; do
    local attempt
    for attempt in $(seq 1 "$HTTP01_TARGET_ATTEMPTS"); do
      if docker exec "${RUN_INSTANCE}-ca" bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${host}/80'" >/dev/null 2>&1; then
        break
      fi
      if [ "$attempt" -eq "$HTTP01_TARGET_ATTEMPTS" ]; then
        fail "step-ca cannot reach HTTP-01 target: ${host}:80"
      fi
      sleep "$HTTP01_TARGET_DELAY_SECS"
    done
  done
}

run_remote_bootstrap() {
  local service="$1"
  local agent_config="$2"
  local hostname_val="$3"
  local instance_id="$4"
  local role_id_path="$REMOTE_DIR/secrets/services/$service/role_id"
  local secret_id_path="$REMOTE_DIR/secrets/services/$service/secret_id"
  local eab_path="$REMOTE_DIR/secrets/services/$service/eab.json"
  local ca_bundle_path="$REMOTE_CERTS_DIR/ca-bundle.pem"

  (
    cd "$REMOTE_DIR"
    "$BOOTROOT_REMOTE_BIN" bootstrap \
      --openbao-url "$OPENBAO_URL" \
      --kv-mount "secret" \
      --registration-id "$service" \
      --service-name "$service" \
      --role-id-path "$role_id_path" \
      --secret-id-path "$secret_id_path" \
      --eab-file-path "$eab_path" \
      --agent-config-path "$agent_config" \
      --agent-email "admin@example.com" \
      --agent-server "$STEPCA_SERVER_URL" \
      --agent-domain "$DOMAIN" \
      --agent-responder-url "$RESPONDER_URL" \
      --profile-hostname "$hostname_val" \
      --profile-instance-id "$instance_id" \
      --profile-cert-path "$REMOTE_CERTS_DIR/${service}.crt" \
      --profile-key-path "$REMOTE_CERTS_DIR/${service}.key" \
      --ca-bundle-path "$ca_bundle_path" \
      --output json >>"$RUN_LOG" 2>&1
  )
}

verify_with_retry() {
  local service="$1"
  local agent_config="$2"
  local attempt
  for attempt in $(seq 1 "$VERIFY_ATTEMPTS"); do
    if run_bootroot_control verify --registration-id "$service" --agent-config "$agent_config" --agent-binary "$BOOTROOT_AGENT_BIN" >>"$RUN_LOG" 2>&1; then
      return 0
    fi
    if [ "$attempt" -eq "$VERIFY_ATTEMPTS" ]; then
      fail "verify failed for ${service} after ${VERIFY_ATTEMPTS} attempts"
    fi
    sleep "$VERIFY_DELAY_SECS"
  done
}

snapshot_cert_meta() {
  local service="$1"
  local label="$2"
  local cert_path="$REMOTE_CERTS_DIR/${service}.crt"
  local meta_file="$CERT_META_DIR/${service}-${label}.txt"
  [ -f "$cert_path" ] || fail "Missing certificate: $cert_path"
  openssl x509 -in "$cert_path" -noout -serial -startdate -enddate -fingerprint -sha256 >"$meta_file"
}

cert_meta_file() {
  local service="$1"
  local label="$2"
  printf '%s\n' "$CERT_META_DIR/${service}-${label}.txt"
}

# `x509 -fingerprint` does not agree with itself on the digest's case —
# OpenSSL 3.6.3 prints `sha256 Fingerprint=` here and `SHA2-256(stdin)= `
# from `dgst -sha256`, and LibreSSL prints `SHA256 Fingerprint=`. Compare
# the field case-insensitively instead of anchoring on one spelling.
# Matching the whole field still pins the digest, so a second fingerprint
# line added to `snapshot_cert_meta` later cannot satisfy this read. The
# hex holds no `=`, so `$2` is the entire value.
fingerprint_of() {
  local service="$1"
  local label="$2"
  local meta_file
  meta_file="$(cert_meta_file "$service" "$label")"
  awk -F= 'tolower($1) == "sha256 fingerprint" { print $2 }' "$meta_file"
}

# An unwritten snapshot and a snapshot this read cannot parse are
# different problems: the first points at the phase that should have
# written it, the second at the format the read expects. Reporting both
# as "Missing fingerprint" sent the reader hunting for a file that was
# there all along.
assert_cert_meta_readable() {
  local service="$1"
  local label="$2"
  local meta_file
  meta_file="$(cert_meta_file "$service" "$label")"
  [ -f "$meta_file" ] \
    || fail "Missing cert-meta file for ${service}/${label}: ${meta_file}"
  if [ -z "$(fingerprint_of "$service" "$label")" ]; then
    fail "No SHA-256 fingerprint parsed from ${meta_file} for ${service}/${label}; it holds: $(tr '\n' ' ' <"$meta_file")"
  fi
}

assert_fingerprint_changed() {
  local service="$1"
  local before_label="$2"
  local after_label="$3"
  local before_fp after_fp
  assert_cert_meta_readable "$service" "$before_label"
  assert_cert_meta_readable "$service" "$after_label"
  before_fp="$(fingerprint_of "$service" "$before_label")"
  after_fp="$(fingerprint_of "$service" "$after_label")"
  [ "$before_fp" != "$after_fp" ] || fail "Fingerprint did not change for ${service} (${before_label} -> ${after_label})"
}

run_verify_pair() {
  local label="$1"
  log_phase "verify-${label}"
  verify_with_retry "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH"
  verify_with_retry "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2"
  snapshot_cert_meta "$SERVICE_NAME" "$label"
  snapshot_cert_meta "$SERVICE_NAME_2" "$label"
}

openbao_write_service_kv() {
  local kv_path_base="$1"
  local item="$2"
  local payload="$3"
  local runtime_token
  runtime_token="$(
    curl -fsS \
      -X POST \
      -H "Content-Type: application/json" \
      "${OPENBAO_URL}/v1/auth/approle/login" \
      -d "$(jq -n \
        --arg role_id "$RUNTIME_ROTATE_ROLE_ID" \
        --arg secret_id "$RUNTIME_ROTATE_SECRET_ID" \
        '{role_id:$role_id,secret_id:$secret_id}')" \
      | jq -r '.auth.client_token // empty'
  )"
  [ -n "${runtime_token:-}" ] || fail "Failed to obtain runtime AppRole client token"
  curl -fsS \
    -X POST \
    -H "X-Vault-Token: ${runtime_token}" \
    -H "Content-Type: application/json" \
    "${OPENBAO_URL}/v1/secret/data/${kv_path_base}/${item}" \
    -d "$payload" >/dev/null
}

force_reissue_remote_service() {
  local service="$1"
  rm -f "$REMOTE_CERTS_DIR/${service}.crt" "$REMOTE_CERTS_DIR/${service}.key"
}

# Exercises the genuine KV force-reissue round-trip for a remote-bootstrap
# service. Unlike force_reissue_remote_service (which fakes reissue by
# deleting cert files), this runs a real bootroot-agent daemon so its
# fast-poll loop observes the control-plane's `rotate force-reissue --wait`
# KV request, renews via ACME, and writes the completion markers back to
# KV. That write-back requires the service AppRole to hold create/update on
# its reissue KV path; without it, `--wait` blocks until timeout. This is
# the coverage that would have caught issue #677.
# Drives a `rotate force-reissue --wait` against an *already-running* agent
# (tracked in REMOTE_AGENT_PID) and asserts the KV round-trip completed and
# the certificate was actually reissued on disk. Stops the agent before
# returning. Shared by the fresh-bootstrap round-trip and the self-heal
# round-trip so both exercise the identical completion path.
drive_force_reissue_wait() {
  local service="$1"
  local before_label="$2"
  local after_label="$3"
  local reissue_log="$ARTIFACT_DIR/force-reissue-${service}.log"
  local status=0
  run_bootroot_control rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    force-reissue \
    --registration-id "$service" \
    --wait \
    --wait-timeout "$FORCE_REISSUE_WAIT_TIMEOUT" >"$reissue_log" 2>&1 || status=$?

  cat "$reissue_log" >>"$RUN_LOG"
  stop_remote_agent

  # Exit code 124 is the --wait timeout convention; any non-zero here means
  # the round-trip did not complete, which is exactly the #677 regression.
  [ "$status" -eq 0 ] \
    || fail "rotate force-reissue --wait exited ${status} for ${service} (expected completion, not timeout)"
  grep -q "reported completion" "$reissue_log" \
    || fail "rotate force-reissue --wait for ${service} did not observe agent completion"

  # The agent must have actually reissued the certificate on disk.
  snapshot_cert_meta "$service" "$after_label"
  assert_fingerprint_changed "$service" "$before_label" "$after_label"
}

run_force_reissue_wait_roundtrip() {
  local service="$1"
  local agent_config="$2"
  local hostname_val="$3"
  local instance_id="$4"
  log_phase "force-reissue-wait-${service}"

  # Re-bootstrap so the agent config, credentials and initial cert are
  # fresh, then snapshot the cert to detect the reissue.
  run_remote_bootstrap "$service" "$agent_config" "$hostname_val" "$instance_id"
  snapshot_cert_meta "$service" "before-force-reissue"

  # Start the long-lived agent so its fast-poll loop is the consumer of the
  # KV force-reissue request. It authenticates via the service AppRole from
  # the [openbao] section that bootstrap wrote into the agent config.
  local agent_log="$ARTIFACT_DIR/remote-agent-${service}.log"
  # `9>&-` closes the `/etc/hosts` lock this run may be holding: it
  # lives on an open file descriptor, and a daemon that inherited it and
  # outlived a killed run would keep hosts mode refused on this host.
  "$BOOTROOT_AGENT_BIN" --config "$agent_config" >>"$agent_log" 2>&1 9>&- &
  REMOTE_AGENT_PID=$!
  # Give the daemon a moment to load config and complete its initial login
  # before the request lands, so the next fast-poll tick observes it.
  sleep 3

  drive_force_reissue_wait "$service" "before-force-reissue" "after-force-reissue"
}

# Proves a *running* remote agent stays self-sufficient across control-plane
# secret_id and trust rotations with NO manual re-bootstrap on the remote
# host — the whole point of approach C. Deterministic (does not wait out
# secret_id_ttl): starts the long-lived agent, then confirms its fast-poll
# loop (1) refreshed the on-disk secret_id file to the freshly rotated
# credential and (2) re-rendered the agent.toml [trust] pins + ca-bundle with
# the new anchor.
#
# The first agent authenticated with the *old* (still-valid) secret_id, so a
# force-reissue against it could succeed on that original token alone and
# would NOT prove the rotated credential is usable for a fresh login. To
# close that gap we restart the agent after the poll applies: a cold start
# performs an AppRole login reading ONLY the rotated secret_id from disk, so
# if the new credential were broken or the file held a non-working value the
# restarted loop could not authenticate and the subsequent force-reissue
# --wait would time out. The final round-trip therefore proves the loop is
# operating specifically on the refreshed credential.
run_selfheal_roundtrip() {
  local service="$1"
  local agent_config="$2"
  log_phase "selfheal-${service}"

  local secret_id_path="$REMOTE_DIR/secrets/services/$service/secret_id"
  local secret_id_before
  secret_id_before="$(cat "$secret_id_path")"
  snapshot_cert_meta "$service" "before-selfheal"

  local agent_log="$ARTIFACT_DIR/selfheal-agent-${service}.log"
  # `9>&-` closes the `/etc/hosts` lock this run may be holding: it
  # lives on an open file descriptor, and a daemon that inherited it and
  # outlived a killed run would keep hosts mode refused on this host.
  "$BOOTROOT_AGENT_BIN" --config "$agent_config" >>"$agent_log" 2>&1 9>&- &
  REMOTE_AGENT_PID=$!

  # Wait for the secret_id + trust polls to apply on disk. The secret_id
  # file must change to the rotated value and the new trust anchor must
  # appear in the agent.toml [trust] pins the daemon rewrote.
  local applied="" attempt
  for attempt in $(seq 1 "$SELFHEAL_ATTEMPTS"); do
    if [ "$(cat "$secret_id_path")" != "$secret_id_before" ] \
      && grep -qi "$TRUST_SYNC_EXTRA_FINGERPRINT" "$agent_config"; then
      applied="yes"
      break
    fi
    sleep "$SELFHEAL_DELAY_SECS"
  done
  if [ -z "$applied" ]; then
    stop_remote_agent
    fail "running agent did not self-heal secret_id/trust for ${service} within $((SELFHEAL_ATTEMPTS * SELFHEAL_DELAY_SECS))s"
  fi

  # Force a cold re-login on the rotated credential: stop the agent that is
  # still coasting on the old-secret_id token, then start a fresh process.
  # Its first act is an AppRole login that reads ONLY the on-disk (rotated)
  # secret_id, so the round-trip below can only succeed if that credential
  # actually authenticates.
  stop_remote_agent
  # `9>&-` closes the `/etc/hosts` lock this run may be holding: it
  # lives on an open file descriptor, and a daemon that inherited it and
  # outlived a killed run would keep hosts mode refused on this host.
  "$BOOTROOT_AGENT_BIN" --config "$agent_config" >>"$agent_log" 2>&1 9>&- &
  REMOTE_AGENT_PID=$!

  # The restarted loop is operating on the refreshed credential: drive a
  # genuine force-reissue --wait round-trip through it.
  drive_force_reissue_wait "$service" "before-selfheal" "after-selfheal"
}

run_rotation_secret_id() {
  log_phase "rotate-secret-id"
  run_bootroot_control rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    approle-secret-id \
    --registration-id "$SERVICE_NAME" >>"$RUN_LOG" 2>&1
  # Batch selector (#669): --all-services follows state.json, so this
  # single invocation covers $SERVICE_NAME_2 and re-rotates
  # $SERVICE_NAME, doubling as re-run idempotence coverage.
  run_bootroot_control rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    approle-secret-id \
    --all-services >>"$RUN_LOG" 2>&1
  grep -q "services rotated: 2 succeeded, 0 failed (total 2)" "$RUN_LOG" \
    || fail "batch secret_id rotation summary missing from run log"
}

run_rotation_trust_sync() {
  log_phase "rotate-trust-sync"
  local current_trust_json extra_cert_pem extra_fingerprint ca_bundle_pem payload tmp_dir
  current_trust_json="$(python3 - "$REMOTE_AGENT_CONFIG_PATH" <<'PY'
import json
import sys
import tomllib

with open(sys.argv[1], "rb") as fh:
    data = tomllib.load(fh)
trusted = data.get("trust", {}).get("trusted_ca_sha256", [])
if not trusted:
    raise SystemExit("missing trust.trusted_ca_sha256")
print(json.dumps(trusted))
PY
)"
  # The extra trust anchor must be a real cert: issue #622 made
  # `bootroot verify` fail when any fingerprint in
  # `trust.trusted_ca_sha256` is absent from `trust.ca_bundle_path`,
  # so a random `openssl rand -hex 32` fingerprint would trip the
  # post-rotation renewal the self-heal phase drives.
  tmp_dir="$(mktemp -d)"
  openssl req -x509 -nodes -newkey rsa:2048 \
    -keyout "$tmp_dir/key.pem" \
    -out "$tmp_dir/cert.pem" \
    -days 1 \
    -subj "/CN=trust-sync-extra-$(date +%s%N)" \
    >/dev/null 2>&1
  extra_cert_pem="$(cat "$tmp_dir/cert.pem")"
  extra_fingerprint="$(openssl x509 -in "$tmp_dir/cert.pem" -outform DER \
    | openssl dgst -sha256 -hex \
    | awk '{print $NF}')"
  rm -rf "$tmp_dir"
  # Export so the self-heal phase can confirm the running agent picked up
  # this new anchor via fast-poll (no manual re-bootstrap).
  TRUST_SYNC_EXTRA_FINGERPRINT="$extra_fingerprint"
  ca_bundle_pem="$(cat "$REMOTE_CERTS_DIR/ca-bundle.pem")
$extra_cert_pem"
  payload="$(jq -n --argjson current "$current_trust_json" --arg extra "$extra_fingerprint" --arg pem "$ca_bundle_pem" '{data:{trusted_ca_sha256:($current + [$extra]),ca_bundle_pem:$pem}}')"
  openbao_write_service_kv "$SERVICE_KV_PATH_BASE" "trust" "$payload"
  openbao_write_service_kv "$SERVICE_KV_PATH_BASE_2" "trust" "$payload"
}

run_rotation_responder_hmac() {
  log_phase "rotate-responder-hmac"
  run_bootroot_control rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    responder-hmac >>"$RUN_LOG" 2>&1
}

main() {
  mkdir -p "$ARTIFACT_DIR" "$CONTROL_DIR" "$REMOTE_DIR" "$REMOTE_CERTS_DIR" "$CERT_META_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  # Before the traps: the identity `cleanup` reports leftovers at, and
  # the marker it removes, are both this run's own, and until they exist
  # there is nothing for a trap to act on.
  derive_run_scope
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  ensure_prerequisites
  configure_resolution_mode
  # The assertion comes first, before the teardown and before anything
  # else that could remove a container.  A `down -v` at this project
  # would take a real install on this host with it, volumes and all, and
  # leave the check reading a daemon it had just cleaned — and a killed
  # run's leftovers, which the check exists to report, are
  # indistinguishable from that install to everything but an operator.
  assert_no_leftover_containers "$COMPOSE_FILE" "run-remote-lifecycle startup" "$RUN_INSTANCE"
  # Past the assertion nothing here is anyone else's, so the stack
  # becomes this run's to remove.  The teardown takes the volumes,
  # networks and orphans the assertion does not look at, and may
  # legitimately find nothing to do, so its status is not fatal.
  mark_stack_owned
  # Only now, with removal permitted: the sweep is what collects the runs
  # that were killed before their own teardown, whose leftovers nothing
  # else will ever be named after again.  It is driven off recorded
  # instance names, so a real default-identity install stays out of
  # reach.
  collect_dead_runs
  write_run_marker "$RUN_INSTANCE" "$COMPOSE_PROJECT"
  compose_down || true
  reset_stepca_materials_for_e2e
  install_infra
  assert_resolved_compose_project

  run_bootstrap_chain
  copy_remote_bootstrap_materials "$SERVICE_NAME"
  copy_remote_bootstrap_materials "$SERVICE_NAME_2"
  apply_dns_aliases
  wait_for_stepca_http01_targets

  log_phase "bootstrap-initial"
  run_remote_bootstrap "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"
  run_remote_bootstrap "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2" "$HOSTNAME_2" "$INSTANCE_ID_2"

  run_verify_pair "initial"

  # Approach C: a running remote agent must stay self-sufficient across
  # secret_id AND trust rotation with NO manual re-bootstrap on the remote.
  # Rotate both in the control plane, then prove each running agent's
  # fast-poll loop self-heals (refreshes its own secret_id, re-renders
  # trust) and keeps operating.
  run_rotation_secret_id
  run_rotation_trust_sync
  run_selfheal_roundtrip "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH"
  run_selfheal_roundtrip "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2"
  assert_fingerprint_changed "$SERVICE_NAME" "initial" "after-selfheal"
  assert_fingerprint_changed "$SERVICE_NAME_2" "initial" "after-selfheal"

  run_rotation_responder_hmac
  log_phase "bootstrap-after-responder-hmac"
  run_remote_bootstrap "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"
  run_remote_bootstrap "$SERVICE_NAME_2" "$REMOTE_AGENT_CONFIG_PATH_2" "$HOSTNAME_2" "$INSTANCE_ID_2"
  force_reissue_remote_service "$SERVICE_NAME"
  force_reissue_remote_service "$SERVICE_NAME_2"
  run_verify_pair "after-responder-hmac"
  assert_fingerprint_changed "$SERVICE_NAME" "after-selfheal" "after-responder-hmac"
  assert_fingerprint_changed "$SERVICE_NAME_2" "after-selfheal" "after-responder-hmac"

  run_force_reissue_wait_roundtrip \
    "$SERVICE_NAME" "$REMOTE_AGENT_CONFIG_PATH" "$HOSTNAME" "$INSTANCE_ID"

  log_phase "assert-openbao-audit-log"
  assert_openbao_audit_log "${RUN_INSTANCE}-openbao"
}

main "$@"
