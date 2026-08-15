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

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-local-lifecycle-$(date +%s)}"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$ARTIFACT_DIR/workspace}"
SECRETS_DIR="${SECRETS_DIR:-$ROOT_DIR/secrets}"
CERTS_DIR="${CERTS_DIR:-$WORKSPACE_DIR/certs}"
TIMEOUT_SECS="${TIMEOUT_SECS:-120}"
INFRA_UP_ATTEMPTS="${INFRA_UP_ATTEMPTS:-6}"
INFRA_UP_DELAY_SECS="${INFRA_UP_DELAY_SECS:-5}"
INFRA_READY_ATTEMPTS="${INFRA_READY_ATTEMPTS:-30}"
INFRA_READY_DELAY_SECS="${INFRA_READY_DELAY_SECS:-4}"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
BOOTROOT_REMOTE_BIN="${BOOTROOT_REMOTE_BIN:-$ROOT_DIR/target/debug/bootroot-remote}"
BOOTROOT_AGENT_BIN="${BOOTROOT_AGENT_BIN:-$ROOT_DIR/target/debug/bootroot-agent}"
RESOLUTION_MODE="${RESOLUTION_MODE:-no-hosts}"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_LOG="$ARTIFACT_DIR/init.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"
INIT_SUMMARY_JSON="$ARTIFACT_DIR/init-summary.json"
CERT_META_DIR="$ARTIFACT_DIR/cert-meta"
HOSTS_MARKER="# bootroot-e2e-main-lifecycle"
VERIFY_ATTEMPTS="${VERIFY_ATTEMPTS:-3}"
VERIFY_DELAY_SECS="${VERIFY_DELAY_SECS:-3}"
HTTP01_TARGET_ATTEMPTS="${HTTP01_TARGET_ATTEMPTS:-40}"
HTTP01_TARGET_DELAY_SECS="${HTTP01_TARGET_DELAY_SECS:-2}"
RESPONDER_READY_ATTEMPTS="${RESPONDER_READY_ATTEMPTS:-30}"
RESPONDER_READY_DELAY_SECS="${RESPONDER_READY_DELAY_SECS:-1}"

EDGE_SERVICE="edge-proxy"
EDGE_HOSTNAME="edge-node-01"
WEB_SERVICE="web-app"
WEB_HOSTNAME="web-01"
# Each distinct local service gets its own agent config (and with it
# its own `[openbao]` AppRole identity, service-keyed state file,
# eab.json, and daemon process).  The `[openbao]` section holds a
# single AppRole identity whose policy only reads that service's KV
# subtree, so sharing one agent config across distinct services is an
# unsupported topology.
EDGE_AGENT_CONFIG="$WORKSPACE_DIR/agent-${EDGE_SERVICE}.toml"
WEB_AGENT_CONFIG="$WORKSPACE_DIR/agent-${WEB_SERVICE}.toml"
DOMAIN="trusted.domain"
INSTANCE_ID="001"
REMOTE_SERVICE="api-gw"
REMOTE_HOSTNAME="api-01"
REMOTE_INSTANCE_ID="002"
REMOTE_DIR="$ARTIFACT_DIR/remote-workspace"
REMOTE_AGENT_CONFIG="$REMOTE_DIR/agent.toml"
REMOTE_CERTS_DIR="$REMOTE_DIR/certs"

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
INFRA_ROTATE_ROLE_ID=""
INFRA_ROTATE_SECRET_ID=""
INIT_ROOT_TOKEN=""
OPENBAO_RECOVERY_OUTPUT_FILE="$ARTIFACT_DIR/openbao-recovery.json"
# Each host-daemon bootroot-agent's fast-poll loop (default
# fast_poll_interval = 30s) is the only propagation route for rotated
# per-service secrets.  After `rotate responder-hmac` the harness waits
# for each running daemon to upsert the new HMAC into its own agent
# config before driving verification; allow one full poll interval
# plus generous margin for slow CI runners.
RESPONDER_HMAC_PROPAGATION_ATTEMPTS="${RESPONDER_HMAC_PROPAGATION_ATTEMPTS:-45}"
RESPONDER_HMAC_PROPAGATION_DELAY_SECS="${RESPONDER_HMAC_PROPAGATION_DELAY_SECS:-2}"
CURRENT_PHASE="init"
# PIDs of the long-running per-service bootroot-agent daemons (one per
# distinct local service, each bound to its own agent config).
# Required so `bootroot rotate force-reissue --wait` can deliver SIGHUP
# to a real process — without it, pkill -HUP exits 1 ("no processes
# matched") and the rotate fails before the wait path runs.
LOCAL_AGENT_DAEMON_PIDS=""

# Prefix every derived instance name starts with.  Short on purpose: the
# instance-name budget is 39 characters and what follows it is the run
# token, whose tail is the only part distinguishing two runs started in
# the same second.
RUN_INSTANCE_PREFIX="e2e-local-"
# Prefix every derived Compose project starts with.  Long on purpose,
# and nothing like the instance prefix: the project has no length budget
# to spend, so it says in full what the truncated instance name cannot.
RUN_PROJECT_PREFIX="bootroot-e2e-local-"
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
  printf '{"ts":"%s","phase":"%s","mode":"%s"}\n' \
    "$now" "$phase" "$RESOLUTION_MODE" >>"$PHASE_LOG"
}

fail() {
  local message="$1"
  if [ -n "${RUN_LOG:-}" ]; then
    printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$message" >>"$RUN_LOG" || true
  fi
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
  write_instance_dotenv "$WORKSPACE_DIR" "$RUN_INSTANCE"
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
  sweep_dead_run_instances "run-local-lifecycle startup" "$RUN_LOG" \
    || echo "run-local-lifecycle: a dead run's leftovers could not be fully collected; see ${RUN_LOG}" >&2
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
  ensure_openssl
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  [ -x "$BOOTROOT_REMOTE_BIN" ] || fail "bootroot-remote binary not executable: $BOOTROOT_REMOTE_BIN"
}

run_bootroot() {
  (
    cd "$WORKSPACE_DIR"
    "$BOOTROOT_BIN" "$@"
  )
}

infra_services() {
  printf '%s\n' "openbao" "postgres" "step-ca" "bootroot-http01"
}

service_container_id() {
  local service="$1"
  docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" ps -q "$service" | tr -d '\n'
}

is_service_ready() {
  local service="$1"
  local container_id
  container_id="$(service_container_id "$service")"
  if [ -z "$container_id" ]; then
    return 1
  fi

  local state
  state="$(docker inspect --format '{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_id" 2>/dev/null || true)"
  if [ -z "$state" ]; then
    return 1
  fi

  local status health
  status="${state%%|*}"
  health="${state#*|}"
  if [ "$status" != "running" ]; then
    return 1
  fi
  if [ -n "$health" ] && [ "$health" != "healthy" ]; then
    return 1
  fi
  return 0
}

wait_for_infra_ready() {
  local attempt
  for attempt in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    local all_ready=1
    local service
    while IFS= read -r service; do
      if ! is_service_ready "$service"; then
        all_ready=0
        break
      fi
    done < <(infra_services)

    if [ "$all_ready" -eq 1 ]; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  return 1
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

cleanup() {
  local status=$?
  local cleanup_status=0
  log_phase "cleanup"
  cleanup_hosts
  stop_local_bootroot_agent_daemons
  capture_artifacts
  # Nothing is torn down before the startup assertion passed: what is on
  # this host then belongs to whoever put it there, and removing it is
  # exactly what the assertion refused to do.
  if stack_owned; then
    if ! compose_down; then
      echo "run-local-lifecycle: teardown failed; see ${RUN_LOG}" >&2
      cleanup_status=1
    fi
    report_leftover_containers "$COMPOSE_FILE" "run-local-lifecycle cleanup" "$RUN_INSTANCE" || cleanup_status=1
    # `down` removes containers, never images, so the tag this run built
    # under is its to remove — and it is leftovers of exactly the kind
    # the marker exists for: named after this run's instance, so nothing
    # later is named the same and no sweep would ask about it once the
    # marker is gone.  A tag that survives therefore keeps the marker,
    # which is what `cleanup_status` decides below.
    if ! remove_run_image "$RUN_HTTP01_IMAGE" "$RUN_LOG"; then
      echo "run-local-lifecycle: the responder image ${RUN_HTTP01_IMAGE} could not be removed; see ${RUN_LOG}" >&2
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
  echo "run-local-lifecycle failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "artifact dir: ${ARTIFACT_DIR}" >&2
  if [ -f "$RUN_LOG" ]; then
    echo "--- run.log (tail) ---" >&2
    tail -n 80 "$RUN_LOG" >&2 || true
  fi
  if [ -f "$INIT_RAW_LOG" ]; then
    echo "--- init.raw.log (tail) ---" >&2
    tail -n 120 "$INIT_RAW_LOG" >&2 || true
  fi
  if [ -f "$INIT_LOG" ]; then
    echo "--- init.log (tail) ---" >&2
    tail -n 80 "$INIT_LOG" >&2 || true
  fi
}

add_hosts_entry() {
  local ip="$1"
  local host="$2"
  if grep -qE "[[:space:]]${host}([[:space:]]|\$)" /etc/hosts; then
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
      # the one thing a second run still has to wait for.
      acquire_hosts_lock "run-local-lifecycle.sh, ${ARTIFACT_DIR}"
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

write_agent_config() {
  local config_path="$1"
  mkdir -p "$(dirname "$config_path")" "$CERTS_DIR"
  cat >"$config_path" <<EOF
email = "admin@example.com"
server = "${STEPCA_SERVER_URL}"
domain = "${DOMAIN}"

[acme]
directory_fetch_attempts = 10
directory_fetch_base_delay_secs = 1
directory_fetch_max_delay_secs = 10
poll_attempts = 15
poll_interval_secs = 2
http_responder_url = "${RESPONDER_URL}"
http_responder_hmac = "dev-hmac"
http_responder_timeout_secs = 5
http_responder_token_ttl_secs = 300
EOF
}

install_infra() {
  mkdir -p "$CERTS_DIR"
  chmod 700 "$CERTS_DIR"
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
  run_bootroot infra install \
    --compose-file "$COMPOSE_FILE" \
    --instance-name "$RUN_INSTANCE" \
    --postgres-host-port "$POSTGRES_HOST_PORT" \
    --openbao-host-port "$OPENBAO_HOST_PORT" \
    --stepca-host-port "$STEPCA_HOST_PORT" \
    --http01-admin-host-port "$HTTP01_ADMIN_HOST_PORT" \
    >>"$RUN_LOG" 2>&1
}

reset_stepca_materials_for_e2e() {
  if [ "${RESET_STEPCA_MATERIALS:-1}" != "1" ]; then
    return 0
  fi
  rm -rf \
    "$SECRETS_DIR/config" \
    "$SECRETS_DIR/certs" \
    "$SECRETS_DIR/db" \
    "$SECRETS_DIR/secrets" \
    "$SECRETS_DIR/password.txt" \
    "$SECRETS_DIR/password.txt.new"
}

run_bootstrap_chain() {
  # Containers are already running from install_infra().  step-ca is
  # expected to be restarting (no ca.json yet); init will bootstrap it.
  # Only wait for the services that init needs.
  wait_for_postgres_admin
  wait_for_openbao_api
  wait_for_responder_admin

  log_phase "init"
  rm -f "$WORKSPACE_DIR/state.json"
  # Answer every prompt with its own flag and run with stdin closed, so
  # the run neither depends on which of password.txt, ca.json and
  # state.json the cleanup above happened to leave behind nor needs a
  # TTY.  An overwrite flag whose file is absent is a silent no-op.
  if ! BOOTROOT_LANG=en run_bootroot init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$INIT_SUMMARY_JSON" \
    --enable auto-generate,show-secrets,db-provision \
    --stepca-provisioner "acme" \
    --stepca-password "password" \
    --http-hmac "dev-hmac" \
    --no-eab \
    --save-unseal-keys \
    --overwrite-password \
    --overwrite-ca-json \
    --overwrite-state \
    --confirm-db-provision \
    --db-user "step" \
    --db-name "stepca" \
    --responder-url "$RESPONDER_URL" </dev/null >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 160 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
    docker logs "${RUN_INSTANCE}-openbao" >>"$RUN_LOG" 2>&1 || true
    docker logs "${RUN_INSTANCE}-postgres" >>"$RUN_LOG" 2>&1 || true
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
  INFRA_ROTATE_ROLE_ID="$(
    jq -r '.approles[] | select(.label == "infra_rotate") | .role_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  INFRA_ROTATE_SECRET_ID="$(
    jq -r '.approles[] | select(.label == "infra_rotate") | .secret_id // empty' \
      "$INIT_SUMMARY_JSON"
  )"
  INIT_ROOT_TOKEN="$(jq -r '.root_token // empty' "$INIT_SUMMARY_JSON")"
  [ -n "${RUNTIME_SERVICE_ADD_ROLE_ID:-}" ] || fail "Failed to parse runtime_service_add role_id"
  [ -n "${RUNTIME_SERVICE_ADD_SECRET_ID:-}" ] || fail "Failed to parse runtime_service_add secret_id"
  [ -n "${RUNTIME_ROTATE_ROLE_ID:-}" ] || fail "Failed to parse runtime_rotate role_id"
  [ -n "${RUNTIME_ROTATE_SECRET_ID:-}" ] || fail "Failed to parse runtime_rotate secret_id"
  [ -n "${INFRA_ROTATE_ROLE_ID:-}" ] || fail "Failed to parse infra_rotate role_id"
  [ -n "${INFRA_ROTATE_SECRET_ID:-}" ] || fail "Failed to parse infra_rotate secret_id"
  [ -n "${INIT_ROOT_TOKEN:-}" ] || fail "Failed to parse init root token"
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$INIT_LOG"

  log_phase "service-add"
  # Each distinct local service registers its own agent config, so the
  # `[openbao]` fast-poll section `service add` upserts carries that
  # service's own AppRole paths and a service-keyed state_path — one
  # daemon and one identity per service, the supported topology.
  run_bootroot service add \
    --service-name "$WEB_SERVICE" \
    --delivery-mode local-file \
    --hostname "$WEB_HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$WEB_AGENT_CONFIG" \
    --cert-path "$CERTS_DIR/${WEB_SERVICE}.crt" \
    --key-path "$CERTS_DIR/${WEB_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

  run_bootroot service add \
    --service-name "$REMOTE_SERVICE" \
    --delivery-mode remote-bootstrap \
    --hostname "$REMOTE_HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$REMOTE_AGENT_CONFIG" \
    --cert-path "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.crt" \
    --key-path "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.key" \
    --instance-id "$REMOTE_INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

  run_bootroot service add \
    --service-name "$EDGE_SERVICE" \
    --delivery-mode local-file \
    --hostname "$EDGE_HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$EDGE_AGENT_CONFIG" \
    --cert-path "$CERTS_DIR/${EDGE_SERVICE}.crt" \
    --key-path "$CERTS_DIR/${EDGE_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1
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

apply_dns_aliases() {
  local override="$ARTIFACT_DIR/docker-compose.dns-aliases.yml"
  cat >"$override" <<YAML
services:
  bootroot-http01:
    networks:
      default:
        aliases:
          - ${INSTANCE_ID}.${EDGE_SERVICE}.${EDGE_HOSTNAME}.${DOMAIN}
          - ${INSTANCE_ID}.${WEB_SERVICE}.${WEB_HOSTNAME}.${DOMAIN}
          - ${REMOTE_INSTANCE_ID}.${REMOTE_SERVICE}.${REMOTE_HOSTNAME}.${DOMAIN}
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
    "${INSTANCE_ID}.${EDGE_SERVICE}.${EDGE_HOSTNAME}.${DOMAIN}"
    "${INSTANCE_ID}.${WEB_SERVICE}.${WEB_HOSTNAME}.${DOMAIN}"
    "${REMOTE_INSTANCE_ID}.${REMOTE_SERVICE}.${REMOTE_HOSTNAME}.${DOMAIN}"
  )

  local host
  for host in "${hosts[@]}"; do
    local attempt
    for attempt in $(seq 1 "$HTTP01_TARGET_ATTEMPTS"); do
      if docker exec "${RUN_INSTANCE}-ca" bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${host}/80'" >/dev/null 2>&1; then
        break
      fi
      if [ "$attempt" -eq "$HTTP01_TARGET_ATTEMPTS" ]; then
        docker exec "${RUN_INSTANCE}-ca" sh -c "cat /etc/hosts | tail -n 20" >>"$RUN_LOG" 2>&1 || true
        docker logs "${RUN_INSTANCE}-http01" >>"$RUN_LOG" 2>&1 || true
        fail "step-ca cannot reach HTTP-01 target: ${host}:80"
      fi
      sleep "$HTTP01_TARGET_DELAY_SECS"
    done
  done
}

wait_for_stepca_health() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl -kfsS "https://127.0.0.1:${STEPCA_HOST_PORT}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  fail "step-ca health endpoint did not become ready"
}

prepare_stepca_validation_targets() {
  wait_for_stepca_health
  wait_for_stepca_http01_targets
}

snapshot_cert_meta() {
  local service="$1"
  local label="$2"
  local certs_dir="${3:-$CERTS_DIR}"
  local cert_path="$certs_dir/${service}.crt"
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

run_verify_pair() {
  local label="$1"
  log_phase "verify-${label}"
  prepare_stepca_validation_targets
  verify_service_with_retry "$EDGE_SERVICE" "$EDGE_AGENT_CONFIG"
  verify_service_with_retry "$WEB_SERVICE" "$WEB_AGENT_CONFIG"
  verify_service_with_retry "$REMOTE_SERVICE" "$REMOTE_AGENT_CONFIG"
  snapshot_cert_meta "$EDGE_SERVICE" "$label"
  snapshot_cert_meta "$WEB_SERVICE" "$label"
  snapshot_cert_meta "$REMOTE_SERVICE" "$label" "$REMOTE_CERTS_DIR"
}

# Daemon-deploy local-file path: drives `bootroot rotate force-reissue
# --wait` end-to-end so the in-binary signal+wait code path runs in CI.
force_reissue_for_service() {
  local service="$1"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    force-reissue \
    --service-name "$service" \
    --wait \
    >>"$RUN_LOG" 2>&1
}

# Missing-cert path: web-app's own host bootroot-agent daemon owns its
# cert, so deleting the files and letting that daemon's missing-cert
# check pick them up is the right reissue trigger here.  The `bootroot
# rotate force-reissue` wait-path is exercised by the edge-proxy call
# above.
force_reissue_via_missing_cert() {
  local service="$1"
  rm -f "$CERTS_DIR/${service}.crt" "$CERTS_DIR/${service}.key"
}

# Starts one bootroot-agent host daemon bound to a single service's own
# agent config, eab.json, and AppRole identity.
start_local_agent_daemon() {
  local service="$1"
  local config="$2"
  local log="$ARTIFACT_DIR/bootroot-agent-${service}.log"
  # EAB artifact provisioned by `service add` next to the service
  # secret_id when EAB exists in KV.  Init runs with --no-eab, so the
  # file is normally absent; the agent treats a missing --eab-file as
  # open enrollment.
  local eab_file="$SECRETS_DIR/services/${service}/eab.json"
  [ -f "$config" ] || fail "agent config missing at $config"
  printf '[lifecycle] starting bootroot-agent daemon for %s: --config %s --eab-file %s\n' \
    "$service" "$config" "$eab_file" >>"$RUN_LOG"
  # bootroot-agent uses tracing_subscriber::fmt::init(), whose default
  # filter is ERROR.  The readiness probe below greps for an info-level
  # message, so we have to opt into info output explicitly.
  RUST_LOG="${RUST_LOG:-info}" \
    "$BOOTROOT_AGENT_BIN" --config "$config" \
    --eab-file "$eab_file" \
    >>"$log" 2>&1 &
  local pid=$!
  LOCAL_AGENT_DAEMON_PIDS="$LOCAL_AGENT_DAEMON_PIDS $pid"
  # Give the daemon time to load config and install its SIGHUP handler;
  # otherwise the first force_reissue may signal it before the handler
  # is ready, masking the wait-path coverage we are trying to add.
  local attempt
  for attempt in $(seq 1 20); do
    if ! kill -0 "$pid" 2>/dev/null; then
      tail -n 80 "$log" >>"$RUN_LOG" 2>&1 || true
      fail "bootroot-agent daemon for ${service} exited during startup; see $log"
    fi
    if grep -q "Profile .* daemon enabled" "$log" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  tail -n 80 "$log" >>"$RUN_LOG" 2>&1 || true
  fail "bootroot-agent daemon for ${service} failed to become ready; see $log"
}

start_local_bootroot_agent_daemons() {
  start_local_agent_daemon "$EDGE_SERVICE" "$EDGE_AGENT_CONFIG"
  start_local_agent_daemon "$WEB_SERVICE" "$WEB_AGENT_CONFIG"
}

stop_local_bootroot_agent_daemons() {
  local pid attempt
  for pid in $LOCAL_AGENT_DAEMON_PIDS; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      for attempt in $(seq 1 10); do
        if ! kill -0 "$pid" 2>/dev/null; then
          break
        fi
        sleep 0.2
      done
      kill -9 "$pid" 2>/dev/null || true
    fi
    wait "$pid" 2>/dev/null || true
  done
  LOCAL_AGENT_DAEMON_PIDS=""
}

force_reissue_remote() {
  rm -f "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.crt" "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.key"
}

force_reissue_all_services() {
  force_reissue_for_service "$EDGE_SERVICE"
  force_reissue_via_missing_cert "$WEB_SERVICE"
  force_reissue_remote
}

verify_service_with_retry() {
  local service="$1"
  local agent_config="$2"
  local attempt
  for attempt in $(seq 1 "$VERIFY_ATTEMPTS"); do
    if run_bootroot verify --service-name "$service" --agent-config "$agent_config" >>"$RUN_LOG" 2>&1; then
      return 0
    fi
    if [ "$attempt" -eq "$VERIFY_ATTEMPTS" ]; then
      fail "verify failed for ${service} after ${VERIFY_ATTEMPTS} attempts"
    fi
    sleep "$VERIFY_DELAY_SECS"
  done
}

# Reads the current `[acme].http_responder_hmac` value from the given
# agent config.
current_agent_responder_hmac() {
  awk -F'"' '/^[[:space:]]*http_responder_hmac[[:space:]]*=/ {print $2; exit}' \
    "$1"
}

# Waits for one service daemon's fast-poll loop to upsert the rotated
# responder HMAC into that service's own agent config.  `bootroot
# rotate responder-hmac` only writes the new HMAC to per-service KV
# (plus the infra agents); propagation is each daemon's own fast-poll
# tick (default fast_poll_interval = 30s) under its own AppRole
# identity, so the on-disk value changing is the end-to-end proof that
# the loop observed and applied the rotation for that service.
wait_for_responder_hmac_propagation() {
  local service="$1"
  local config="$2"
  local before="$3"
  local attempt current
  for attempt in $(seq 1 "$RESPONDER_HMAC_PROPAGATION_ATTEMPTS"); do
    current="$(current_agent_responder_hmac "$config")"
    if [ -n "$current" ] && [ "$current" != "$before" ]; then
      printf '[lifecycle] fast-poll propagated rotated responder HMAC for %s within ~%ss\n' \
        "$service" "$((attempt * RESPONDER_HMAC_PROPAGATION_DELAY_SECS))" >>"$RUN_LOG"
      return 0
    fi
    sleep "$RESPONDER_HMAC_PROPAGATION_DELAY_SECS"
  done
  tail -n 80 "$ARTIFACT_DIR/bootroot-agent-${service}.log" >>"$RUN_LOG" 2>&1 || true
  fail "bootroot-agent fast-poll did not propagate the rotated responder HMAC into $config within $((RESPONDER_HMAC_PROPAGATION_ATTEMPTS * RESPONDER_HMAC_PROPAGATION_DELAY_SECS))s"
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
    || fail "Missing cert-meta file for $service/$label: $meta_file"
  if [ -z "$(fingerprint_of "$service" "$label")" ]; then
    fail "No SHA-256 fingerprint parsed from $meta_file for $service/$label; it holds: $(tr '\n' ' ' <"$meta_file")"
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
  if [ "$before_fp" = "$after_fp" ]; then
    fail "Fingerprint did not change for $service ($before_label -> $after_label)"
  fi
}

# Simulates a legacy host: CA keys left root-owned by a pre-#716 rotation
# (or the old `--user root` manual-init example), with the secrets/
# directory itself still host-owned. Only the keys go root-owned — the
# certs stay host-owned so the OpenBao client can still read the trust
# bundle before the rotation's ownership sweep runs. A CA-touching
# rotation must converge this back to owner-owned.
seed_root_owned_ca_keys() {
  local cid img
  cid="$(docker compose -p "$COMPOSE_PROJECT" -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" ps -a -q step-ca | tr -d '\n')"
  [ -n "$cid" ] || fail "step-ca container not found for root-owned seeding"
  img="$(docker inspect --format '{{.Config.Image}}' "$cid")"
  [ -n "$img" ] || fail "could not resolve step-ca image for root-owned seeding"
  docker run --rm --user root -v "$SECRETS_DIR:/mnt" "$img" \
    chown 0:0 /mnt/secrets/root_ca_key /mnt/secrets/intermediate_ca_key \
    >>"$RUN_LOG" 2>&1 || fail "failed to seed root-owned CA keys"
}

# Asserts that no entry under secrets/ is root-owned. Every `step` helper
# container now runs as the secrets-directory owner and the ownership
# sweep repairs any legacy root-owned material, so after a CA-touching
# rotation the tree must be fully owner-owned.
assert_no_root_owned_secrets() {
  local label="$1"
  local root_owned
  root_owned="$(find "$SECRETS_DIR" -uid 0 -print 2>/dev/null || true)"
  if [ -n "$root_owned" ]; then
    {
      echo "root-owned entries under secrets/ after ${label}:"
      echo "$root_owned"
    } >>"$RUN_LOG"
    fail "root-owned entries remain under secrets/ after ${label}"
  fi
}

copy_remote_materials() {
  local control_service_dir="$SECRETS_DIR/services/$REMOTE_SERVICE"
  local remote_service_dir="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE"
  mkdir -p "$remote_service_dir"
  cp "$control_service_dir/role_id" "$remote_service_dir/role_id"
  cp "$control_service_dir/secret_id" "$remote_service_dir/secret_id"
  chmod 600 "$remote_service_dir/role_id" "$remote_service_dir/secret_id"
}

run_remote_bootstrap() {
  local role_id_path="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE/role_id"
  local secret_id_path="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE/secret_id"
  local eab_path="$REMOTE_DIR/secrets/services/$REMOTE_SERVICE/eab.json"
  local ca_bundle_path="$REMOTE_CERTS_DIR/ca-bundle.pem"

  (
    cd "$REMOTE_DIR"
    "$BOOTROOT_REMOTE_BIN" bootstrap \
      --openbao-url "$OPENBAO_URL" \
      --kv-mount "secret" \
      --service-name "$REMOTE_SERVICE" \
      --role-id-path "$role_id_path" \
      --secret-id-path "$secret_id_path" \
      --eab-file-path "$eab_path" \
      --agent-config-path "$REMOTE_AGENT_CONFIG" \
      --agent-email "admin@example.com" \
      --agent-server "$STEPCA_SERVER_URL" \
      --agent-domain "$DOMAIN" \
      --agent-responder-url "$RESPONDER_URL" \
      --profile-hostname "$REMOTE_HOSTNAME" \
      --profile-instance-id "$REMOTE_INSTANCE_ID" \
      --profile-cert-path "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.crt" \
      --profile-key-path "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.key" \
      --ca-bundle-path "$ca_bundle_path" \
      --output json >>"$RUN_LOG" 2>&1
  )
}

rotate_infra_secret_id() {
  local target="$1"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
    --approle-secret-id "$INFRA_ROTATE_SECRET_ID" \
    --yes \
    approle-secret-id \
    --infra "$target" >>"$RUN_LOG" 2>&1
}

run_rotation_infra_secret_id() {
  log_phase "rotate-infra-secret-id"
  local target before after
  for target in stepca responder; do
    before="$(cat "$SECRETS_DIR/openbao/${target}/secret_id")"
    rotate_infra_secret_id "$target"
    after="$(cat "$SECRETS_DIR/openbao/${target}/secret_id")"
    [ -n "$after" ] || fail "infra secret_id for ${target} is empty after rotation"
    [ "$before" != "$after" ] || fail "infra secret_id for ${target} did not change"
  done

  # Privilege-separation boundary (#667): the general runtime-rotate
  # credential must NOT be able to mint infra secret_ids — that would
  # let it log in as the stepca role and read CA core secrets.
  log_phase "rotate-infra-secret-id-denied-for-runtime-rotate"
  if run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    approle-secret-id \
    --infra stepca >>"$RUN_LOG" 2>&1; then
    fail "runtime-rotate credential must not mint infra secret_ids"
  fi
}

# Self-mint of the rotate credentials' own secret_ids (#672): a
# file-based rotate credential re-mints itself as the final step of a
# fully successful invocation and atomically replaces the file the
# scheduler reads. Exercises the runtime-rotate self-mint over two
# consecutive single-service invocations (the second authenticates with
# the credential file replaced by the first) and the infra-rotate
# two-invocation flow (stepca replaces the file, responder reads it
# fresh). The inline credentials used elsewhere in this script stay
# valid: self-mint never revokes the previous secret_id.
run_rotation_secret_id_self_mint() {
  log_phase "rotate-secret-id-self-mint"
  local cred_dir="$ARTIFACT_DIR/rotate-creds"
  mkdir -p "$cred_dir/runtime" "$cred_dir/infra"
  printf '%s' "$RUNTIME_ROTATE_SECRET_ID" >"$cred_dir/runtime/secret_id"
  printf '%s' "$INFRA_ROTATE_SECRET_ID" >"$cred_dir/infra/secret_id"
  chmod 600 "$cred_dir/runtime/secret_id" "$cred_dir/infra/secret_id"

  local pass before after
  for pass in first second; do
    before="$(cat "$cred_dir/runtime/secret_id")"
    run_bootroot rotate \
      --compose-file "$COMPOSE_FILE" \
      --openbao-url "$OPENBAO_URL" \
      --auth-mode approle \
      --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
      --approle-secret-id-file "$cred_dir/runtime/secret_id" \
      --yes \
      approle-secret-id \
      --service-name "$EDGE_SERVICE" >>"$RUN_LOG" 2>&1 ||
      fail "runtime-rotate self-mint rotation (${pass} pass) failed"
    after="$(cat "$cred_dir/runtime/secret_id")"
    [ -n "$after" ] || fail "runtime-rotate credential file is empty after self-mint (${pass} pass)"
    [ "$before" != "$after" ] || fail "runtime-rotate credential file was not replaced by the self-mint (${pass} pass)"
  done

  local target
  for target in stepca responder; do
    before="$(cat "$cred_dir/infra/secret_id")"
    run_bootroot rotate \
      --compose-file "$COMPOSE_FILE" \
      --openbao-url "$OPENBAO_URL" \
      --auth-mode approle \
      --approle-role-id "$INFRA_ROTATE_ROLE_ID" \
      --approle-secret-id-file "$cred_dir/infra/secret_id" \
      --yes \
      approle-secret-id \
      --infra "$target" >>"$RUN_LOG" 2>&1 ||
      fail "infra-rotate self-mint rotation (--infra ${target}) failed"
    after="$(cat "$cred_dir/infra/secret_id")"
    [ -n "$after" ] || fail "infra-rotate credential file is empty after self-mint (--infra ${target})"
    [ "$before" != "$after" ] || fail "infra-rotate credential file was not replaced by the self-mint (--infra ${target})"
  done
}

run_rotations_with_verification() {
  # Rotate the infra secret_ids first: the stepca-password and
  # responder-hmac phases below drive the restarted infra OpenBao
  # Agents (stepca / responder) through real template renders,
  # verifying they re-authenticated with the rotated credentials.
  run_rotation_infra_secret_id
  run_rotation_secret_id_self_mint

  log_phase "rotate-openbao-recovery"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --root-token "$INIT_ROOT_TOKEN" \
    --yes \
    openbao-recovery \
    --rotate-root-token \
    --output "$OPENBAO_RECOVERY_OUTPUT_FILE" >>"$RUN_LOG" 2>&1
  [ -s "$OPENBAO_RECOVERY_OUTPUT_FILE" ] || fail "openbao recovery output not written"
  log_phase "bootstrap-after-openbao-recovery"
  run_remote_bootstrap
  run_verify_pair "after-openbao-recovery"

  log_phase "rotate-responder-hmac"
  local edge_hmac_before web_hmac_before
  edge_hmac_before="$(current_agent_responder_hmac "$EDGE_AGENT_CONFIG")"
  web_hmac_before="$(current_agent_responder_hmac "$WEB_AGENT_CONFIG")"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    responder-hmac >>"$RUN_LOG" 2>&1
  # Both per-service daemons must observe the rotation independently:
  # each reads only its own service's KV subtree.
  wait_for_responder_hmac_propagation "$EDGE_SERVICE" "$EDGE_AGENT_CONFIG" "$edge_hmac_before"
  wait_for_responder_hmac_propagation "$WEB_SERVICE" "$WEB_AGENT_CONFIG" "$web_hmac_before"
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-responder-hmac"
  assert_fingerprint_changed "$EDGE_SERVICE" "initial" "after-responder-hmac"
  assert_fingerprint_changed "$WEB_SERVICE" "initial" "after-responder-hmac"
  assert_fingerprint_changed "$REMOTE_SERVICE" "initial" "after-responder-hmac"

  # Legacy-host simulation: leave the CA keys root-owned before rotating,
  # as a host that rotated (or ran the documented manual init) before #716
  # would. The rotation must still succeed and converge ownership.
  log_phase "seed-root-owned-ca-keys"
  seed_root_owned_ca_keys

  log_phase "rotate-stepca-password"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    stepca-password >>"$RUN_LOG" 2>&1
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-stepca-password"
  assert_fingerprint_changed "$EDGE_SERVICE" "after-responder-hmac" "after-stepca-password"
  assert_fingerprint_changed "$WEB_SERVICE" "after-responder-hmac" "after-stepca-password"
  assert_fingerprint_changed "$REMOTE_SERVICE" "after-responder-hmac" "after-stepca-password"
  # step-ca password rotation re-encrypts the CA keys in place. It now
  # runs as the secrets-directory owner (after the ownership sweep), so no
  # key may be left root-owned.
  assert_no_root_owned_secrets "rotate stepca-password"

  log_phase "rotate-db"
  # Build admin DSN from ca.json so the password matches the current
  # state (it may have been rotated by `init`).
  local db_admin_dsn
  db_admin_dsn="$(jq -r '.db.dataSource // empty' "$SECRETS_DIR/config/ca.json")"
  if [ -z "${db_admin_dsn:-}" ]; then
    db_admin_dsn="postgresql://step:step-pass@127.0.0.1:${POSTGRES_HOST_PORT}/stepca?sslmode=disable"
  else
    # Replace the Docker-internal host:port with the host-side mapping.
    db_admin_dsn="$(echo "$db_admin_dsn" \
      | sed "s|@postgres:5432|@127.0.0.1:${POSTGRES_HOST_PORT}|")"
  fi
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    db \
    --db-admin-dsn "$db_admin_dsn" >>"$RUN_LOG" 2>&1
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-db"
  assert_fingerprint_changed "$EDGE_SERVICE" "after-stepca-password" "after-db"
  assert_fingerprint_changed "$WEB_SERVICE" "after-stepca-password" "after-db"
  assert_fingerprint_changed "$REMOTE_SERVICE" "after-stepca-password" "after-db"

  # Reseed root-owned CA keys before CA rotation. The earlier
  # `rotate stepca-password` already converged the tree, so without
  # reseeding here the CA rotation would run on an already-repaired tree
  # and would not exercise the sweep's placement in `rotate ca-key`
  # (before its host-side Phase 1 backup reads the keys).
  log_phase "reseed-root-owned-ca-keys"
  seed_root_owned_ca_keys

  log_phase "rotate-ca-key"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    ca-key --skip reissue --force --cleanup >>"$RUN_LOG" 2>&1
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-ca-key"
  assert_fingerprint_changed "$EDGE_SERVICE" "after-db" "after-ca-key"
  assert_fingerprint_changed "$WEB_SERVICE" "after-db" "after-ca-key"
  assert_fingerprint_changed "$REMOTE_SERVICE" "after-db" "after-ca-key"
  # CA rotation reads (Phase 1 host-side backup) and rewrites the CA keys
  # as the secrets-directory owner after the ownership sweep, so the
  # reseeded root-owned keys must be converged back to owner-owned.
  assert_no_root_owned_secrets "rotate ca-key"

  log_phase "rotate-ca-key-full"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "$OPENBAO_URL" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    ca-key --full --skip reissue --force --cleanup >>"$RUN_LOG" 2>&1
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-ca-key-full"
  assert_fingerprint_changed "$EDGE_SERVICE" "after-ca-key" "after-ca-key-full"
  assert_fingerprint_changed "$WEB_SERVICE" "after-ca-key" "after-ca-key-full"
  assert_fingerprint_changed "$REMOTE_SERVICE" "after-ca-key" "after-ca-key-full"
}

write_manifest() {
  cat >"$ARTIFACT_DIR/manifest.json" <<EOF
{
  "mode": "${RESOLUTION_MODE}",
  "compose_file": "${COMPOSE_FILE}",
  "instance": "${RUN_INSTANCE}",
  "compose_project": "${COMPOSE_PROJECT}",
  "http01_image": "${RUN_HTTP01_IMAGE}",
  "ports": {
    "postgres": ${POSTGRES_HOST_PORT},
    "openbao": ${OPENBAO_HOST_PORT},
    "stepca": ${STEPCA_HOST_PORT},
    "http01_admin": ${HTTP01_ADMIN_HOST_PORT}
  },
  "state_file": "${ROOT_DIR}/state.json",
  "agent_config_paths": ["${EDGE_AGENT_CONFIG}", "${WEB_AGENT_CONFIG}"],
  "services": ["${EDGE_SERVICE}", "${WEB_SERVICE}", "${REMOTE_SERVICE}"]
}
EOF
}

main() {
  mkdir -p "$ARTIFACT_DIR" "$WORKSPACE_DIR" "$CERT_META_DIR" "$REMOTE_DIR" "$REMOTE_CERTS_DIR"
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
  assert_no_leftover_containers "$COMPOSE_FILE" "run-local-lifecycle startup" "$RUN_INSTANCE"
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
  write_agent_config "$EDGE_AGENT_CONFIG"
  write_agent_config "$WEB_AGENT_CONFIG"
  run_bootstrap_chain

  [ -x "$BOOTROOT_AGENT_BIN" ] || cargo build --bin bootroot-agent >>"$RUN_LOG" 2>&1
  export PATH="$(dirname "$BOOTROOT_AGENT_BIN"):$PATH"

  apply_dns_aliases
  prepare_stepca_validation_targets

  copy_remote_materials
  log_phase "remote-bootstrap-initial"
  run_remote_bootstrap

  run_verify_pair "initial"
  start_local_bootroot_agent_daemons
  run_rotations_with_verification
  stop_local_bootroot_agent_daemons

  log_phase "assert-openbao-audit-log"
  assert_openbao_audit_log "${RUN_INSTANCE}-openbao"

  write_manifest
}

main "$@"
