#!/usr/bin/env bash
set -euo pipefail

# Docker-backed E2E harness proving that two bootroot installs on one
# host stay independent (#747).
#
# Before the install identity existed, a second install on the same host
# adopted the first install's containers: Compose reported the first
# instance's OpenBao Agent sidecars as "orphan containers for this
# project" and recreated its already-initialised OpenBao against the
# wrong configuration, storage volume and unseal keys.  That regression
# does not surface as a crash — it surfaces as another team's CA quietly
# losing its state — so it needs two live Compose projects on one real
# daemon, not a unit test of a naming function.
#
# The layout is deliberate: both compose directories share a basename
# (`<run-root>/a/bootroot` and `<run-root>/b/bootroot`) under different
# parents.  An identical basename is what Compose would otherwise derive
# an identical default project name from, so this is the layout that
# proves the explicit `-p` scoping — and not the directory name — is
# what separates the two installs.
#
# What it asserts:
#
#   - instance A installs, initialises and reports healthy
#   - instance B installs, initialises and reports healthy
#   - A's containers survive B's install with byte-identical container
#     IDs, and A's volumes survive with byte-identical `docker volume
#     inspect` output *and* an unchanged per-run sentinel written into
#     each volume
#   - the two instances' container names, volume names and
#     `com.docker.compose.project` labels are disjoint
#   - the container publishing each instance's OpenBao host port is that
#     instance's own `<instance-name>-openbao`, and it answers there
#   - registering a service on one instance adds that service's alias to
#     that instance's responder only, in both directions
#   - tearing instance B down leaves A healthy and still serving
#
# Safety contract.  A developer running the preflight suite may well
# have a real default-identity `bootroot` install on the same machine.
# This script must be safe there: both instance names are derived from a
# per-run token, every teardown and leftover check is driven off those
# exact names and their `com.docker.compose.project` labels — never a
# `bootroot-*` wildcard — and nothing outside the run's own `mktemp -d`
# root is written or removed.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT_DIR"

# ---------------------------------------------------------------------------
# Ambient environment sanitisation
# ---------------------------------------------------------------------------
#
# `COMPOSE_PROJECT_NAME` outranks the recorded `BOOTROOT_INSTANCE`, so a
# value inherited from the invoking shell would make both instances
# resolve to one project and quietly turn this into a single-instance run
# that still passes several assertions.  Compose likewise prefers a
# process-environment `BOOTROOT_INSTANCE` over the project directory's
# `.env`, so an ambient value would misrender container names for this
# script's own raw `docker compose` calls.  The host-port variables are
# cleared for the same reason: they outrank each compose directory's
# `.env`, and a shared inherited value would collapse both instances onto
# one published port.
#
# Clearing them makes an inherited value harmless rather than fatal.  It
# is deliberately only the first of two layers — `assert_resolved_project`
# below asserts each instance's resolved project rather than assuming it,
# which is what catches a sanitisation that is later broken or bypassed.
unset COMPOSE_PROJECT_NAME BOOTROOT_INSTANCE
unset POSTGRES_HOST_PORT OPENBAO_HOST_PORT STEPCA_HOST_PORT HTTP01_ADMIN_HOST_PORT
unset POSTGRES_HOST POSTGRES_PORT POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-two-instance-$(date +%s)}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
SNAPSHOT_DIR="$ARTIFACT_DIR/snapshots"

# Per-run token both instance names are derived from, so neither can
# collide with a pre-existing install and both stay inside the
# 39-character instance-name limit.
RUN_TOKEN="${RUN_TOKEN:-${GITHUB_RUN_ID:-$(date +%s)$$}}"
RUN_TOKEN="$(printf '%s' "$RUN_TOKEN" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
INSTANCE_A="twoinst-a-${RUN_TOKEN}"
INSTANCE_B="twoinst-b-${RUN_TOKEN}"
# `MAX_INSTANCE_NAME_LEN` in src/commands/compose_project.rs: the
# DNS-label budget left over after the longest container-name suffix.
MAX_INSTANCE_NAME_LEN=39

COMPOSE_FILE_NAME="docker-compose.deploy.yml"
# Both directories share this basename under different parents — see the
# header note on why that is the layout under test.
COMPOSE_DIR_BASENAME="bootroot"

# The `bootroot-http01` image the deploy compose file references.  The
# tag is run-scoped so the build cannot overwrite an image a co-located
# default install is running, and it is removed again on the way out.
HTTP01_IMAGE="bootroot-http01-responder:two-instance-${RUN_TOKEN}"
export BOOTROOT_HTTP01_IMAGE="$HTTP01_IMAGE"

DOMAIN="trusted.domain"
# `service add --instance-id` is a per-service replica identifier and is
# unrelated to `infra install --instance-name`.  The values are chosen to
# look nothing like the instance names so a mix-up is unmistakable in the
# failure output.
SERVICE_A="alpha-app"
HOSTNAME_A="alpha-node-01"
SERVICE_INSTANCE_ID_A="701"
SERVICE_B="beta-app"
HOSTNAME_B="beta-node-01"
SERVICE_INSTANCE_ID_B="802"

# Dotfile written at each volume's root as the content-continuity
# observable.  `CreatedAt` has one-second granularity and so cannot by
# itself distinguish a recreation that happens fast enough; the sentinel
# is what proves the *contents* survived rather than just the metadata.
SENTINEL_FILE=".bootroot-two-instance-sentinel"

HEALTH_ATTEMPTS="${HEALTH_ATTEMPTS:-40}"
HEALTH_DELAY_SECS="${HEALTH_DELAY_SECS:-3}"
SERVE_ATTEMPTS="${SERVE_ATTEMPTS:-30}"
SERVE_DELAY_SECS="${SERVE_DELAY_SECS:-2}"
INFRA_READY_ATTEMPTS="${INFRA_READY_ATTEMPTS:-60}"
INFRA_READY_DELAY_SECS="${INFRA_READY_DELAY_SECS:-2}"

CURRENT_PHASE="startup"
RUN_ROOT=""
DIR_A=""
DIR_B=""
PORTS_TAKEN=""
# Image used by the throwaway sentinel containers and by the cleanup
# chown fallback.  Resolved from a running container of the run's own
# stack so no extra image has to be present under `--no-build`.
HELPER_IMAGE=""
PYTHON_BIN=""

PORT_A_POSTGRES=0
PORT_A_OPENBAO=0
PORT_A_STEPCA=0
PORT_A_HTTP01=0
PORT_B_POSTGRES=0
PORT_B_OPENBAO=0
PORT_B_STEPCA=0
PORT_B_HTTP01=0

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

log() {
  printf '[two-instance][%s] %s\n' "$CURRENT_PHASE" "$1" | tee -a "$RUN_LOG"
}

# Reports one assertion individually so a failure names what broke — and
# so a passing run reads as a checklist rather than as silence.
pass() {
  printf '[two-instance][%s] PASS %s\n' "$CURRENT_PHASE" "$1" | tee -a "$RUN_LOG"
}

fail() {
  local message="$1"
  printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$message" >>"$RUN_LOG" 2>/dev/null || true
  echo "[two-instance][${CURRENT_PHASE}] FAIL $message" >&2
  exit 1
}

on_error() {
  local line="$1"
  echo "[two-instance] failed at phase=${CURRENT_PHASE} line=${line}" >&2
  echo "[two-instance] artifact dir: ${ARTIFACT_DIR}" >&2
  if [ -f "$RUN_LOG" ]; then
    echo "--- run.log (tail) ---" >&2
    tail -n 120 "$RUN_LOG" >&2 || true
  fi
}

assert_equal() {
  local what="$1" expected="$2" actual="$3"
  if [ "$expected" != "$actual" ]; then
    fail "${what}: expected '${expected}', got '${actual}'"
  fi
  pass "$what"
}

# ---------------------------------------------------------------------------
# Prerequisites and host-port allocation
# ---------------------------------------------------------------------------

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v curl >/dev/null 2>&1 || fail "curl is required"
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3)"
  fi
  [ -n "$RUN_TOKEN" ] || fail "RUN_TOKEN reduced to the empty string; supply a token of [a-z0-9]"
  local name
  for name in "$INSTANCE_A" "$INSTANCE_B"; do
    if [ "${#name}" -gt "$MAX_INSTANCE_NAME_LEN" ]; then
      fail "derived instance name '${name}' exceeds the ${MAX_INSTANCE_NAME_LEN}-character limit; shorten RUN_TOKEN"
    fi
  done
}

port_is_taken() {
  local port="$1" taken
  for taken in $PORTS_TAKEN; do
    [ "$taken" = "$port" ] && return 0
  done
  return 1
}

# Picks a free host port on 127.0.0.1 into `PICKED_PORT`.
#
# Prefers the bind-to-port-0 allocation `free_port` in
# tests/bootroot_cli.rs uses: the kernel hands back a port that was free
# at that instant.  Without python3 the fallback probes a randomised
# high range instead.  Either way the allocation is advisory — `infra
# install` binds every published port up front and aborts with `host
# port <addr> is already in use`, and surfacing that failure is the
# contract here rather than adding a second timeout layer.  Neither
# branch ever waits on an occupied port.
#
# The result travels through a global rather than stdout because the
# already-handed-out list has to survive the call, and a command
# substitution would keep it inside a subshell.
PICKED_PORT=0
pick_free_port() {
  local attempt port
  for attempt in $(seq 1 200); do
    if [ -n "$PYTHON_BIN" ]; then
      port="$("$PYTHON_BIN" -c 'import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()')"
    else
      port=$((20000 + RANDOM % 30000))
      if bash -c ": >/dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
        continue
      fi
    fi
    if [ -n "$port" ] && ! port_is_taken "$port"; then
      PORTS_TAKEN="$PORTS_TAKEN $port"
      PICKED_PORT="$port"
      return 0
    fi
  done
  fail "could not allocate a free host port after 200 attempts"
}

allocate_ports() {
  local var
  for var in PORT_A_POSTGRES PORT_A_OPENBAO PORT_A_STEPCA PORT_A_HTTP01 \
    PORT_B_POSTGRES PORT_B_OPENBAO PORT_B_STEPCA PORT_B_HTTP01; do
    pick_free_port
    printf -v "$var" '%s' "$PICKED_PORT"
  done
  log "instance A ports: postgres=${PORT_A_POSTGRES} openbao=${PORT_A_OPENBAO} stepca=${PORT_A_STEPCA} http01=${PORT_A_HTTP01}"
  log "instance B ports: postgres=${PORT_B_POSTGRES} openbao=${PORT_B_OPENBAO} stepca=${PORT_B_STEPCA} http01=${PORT_B_HTTP01}"
}

# ---------------------------------------------------------------------------
# Compose-directory materialisation
# ---------------------------------------------------------------------------

# `docker-compose.yml` declares `build.context: .` for `bootroot-http01`
# with a Dockerfile that copies the whole project root and builds a Rust
# binary, so a directory holding only a copy of it would not come up.
# `docker-compose.deploy.yml` carries no build context at all — every
# service references a prebuilt `image:` tag — which is why both
# instances install from it with `--no-build` against an image built once
# up front.  The only source-tree config it still resolves relative to
# the compose directory is `openbao/openbao.hcl` and
# `responder.toml.compose`; `infra install` creates `secrets/` and
# `certs/` itself.
materialise_compose_dir() {
  local dir="$1"
  mkdir -p "$dir/openbao"
  cp "$ROOT_DIR/$COMPOSE_FILE_NAME" "$dir/$COMPOSE_FILE_NAME"
  cp "$ROOT_DIR/openbao/openbao.hcl" "$dir/openbao/openbao.hcl"
  cp "$ROOT_DIR/responder.toml.compose" "$dir/responder.toml.compose"
}

build_responder_image() {
  log "building $HTTP01_IMAGE"
  # Built with `docker build` rather than `docker compose build` so the
  # repository's own `.env` and compose project are never read or
  # touched: this script has to be safe on a host that already has a
  # default `bootroot` install.
  docker build -t "$HTTP01_IMAGE" \
    -f "$ROOT_DIR/docker/http01-responder/Dockerfile" "$ROOT_DIR" \
    >>"$RUN_LOG" 2>&1 || fail "failed to build $HTTP01_IMAGE"
}

# `--no-build` implies `--pull never`, so every third-party image has to
# be on the host before either install runs.  Pulled through Compose so
# the tags come from the compose file itself rather than from a second
# copy of them here.  Scoped with `-p` like every other raw compose call
# in this script, though `pull` creates no project resources.
prepull_third_party_images() {
  log "pre-pulling third-party images"
  POSTGRES_PASSWORD=prepull-only \
    GRAFANA_ADMIN_PASSWORD=prepull-only \
    BOOTROOT_INSTANCE="$INSTANCE_A" \
    docker compose -p "$INSTANCE_A" -f "$DIR_A/$COMPOSE_FILE_NAME" \
    pull openbao postgres step-ca >>"$RUN_LOG" 2>&1 ||
    fail "failed to pre-pull the third-party images"
}

create_run_root() {
  RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/bootroot-two-instance-XXXXXX")"
  # One removal at cleanup that cannot miss a stray sibling directory.
  DIR_A="$RUN_ROOT/a/$COMPOSE_DIR_BASENAME"
  DIR_B="$RUN_ROOT/b/$COMPOSE_DIR_BASENAME"
  materialise_compose_dir "$DIR_A"
  materialise_compose_dir "$DIR_B"
  log "run root: $RUN_ROOT"
  assert_equal "both compose directories share a basename" \
    "$(basename "$DIR_A")" "$(basename "$DIR_B")"
}

# ---------------------------------------------------------------------------
# Per-instance command helpers
# ---------------------------------------------------------------------------

# Every bootroot command runs from that instance's own directory:
# `service add` and `status` resolve `state.json` against the process
# working directory and the Compose identity against `./.env`, so the
# working directory is what decides which state file is written, which
# Compose project is rewired, and which OpenBao is contacted.
run_bootroot() {
  local dir="$1"
  shift
  (cd "$dir" && BOOTROOT_LANG=en "$BOOTROOT_BIN" "$@")
}

# Raw compose invocations always carry `-p`: without it Compose would
# infer the project from the directory basename, which both instances
# share by design, and this script would inspect and tear down whatever
# that produced.
instance_compose() {
  local project="$1" dir="$2"
  shift 2
  BOOTROOT_INSTANCE="$project" docker compose -p "$project" -f "$dir/$COMPOSE_FILE_NAME" "$@"
}

dotenv_value() {
  local file="$1" key="$2"
  [ -f "$file" ] || return 0
  awk -F= -v k="$key" '$1 == k { sub(/^[^=]*=/, ""); print; exit }' "$file"
}

install_instance() {
  local name="$1" dir="$2" pg="$3" bao="$4" ca="$5" http01="$6"
  log_phase "install-${name}"
  log "installing instance ${name} in ${dir}"
  run_bootroot "$dir" infra install \
    --compose-file "$dir/$COMPOSE_FILE_NAME" \
    --instance-name "$name" \
    --postgres-host-port "$pg" \
    --openbao-host-port "$bao" \
    --stepca-host-port "$ca" \
    --http01-admin-host-port "$http01" \
    --no-build \
    >>"$RUN_LOG" 2>&1 || fail "infra install failed for instance ${name}"
}

# `infra install` returns once every container reports `running`, which
# is not the same as the servers inside them accepting connections.
# `bootroot init` opens with a single-shot `OpenBao` health check and a
# single-shot database connect — neither retries on `Connection refused`
# — so the wait belongs here, as it does in every other `scripts/impl/`
# script.  Both probes are scoped to this instance's own container and
# its own published port.
wait_for_openbao_listening() {
  local name="$1" port="$2" attempt code
  for attempt in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    code="$(curl -kSs -o /dev/null -w '%{http_code}' -m 3 \
      "http://127.0.0.1:${port}/v1/sys/seal-status" 2>/dev/null || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  docker logs "${name}-openbao" >>"$RUN_LOG" 2>&1 || true
  fail "instance ${name}'s OpenBao did not answer on port ${port} before init"
}

wait_for_postgres_admin() {
  local name="$1" port="$2" attempt
  for attempt in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    # Probe over TCP as well: the initdb bootstrap server listens only on
    # the Unix socket, so a socket-based `pg_isready` reports ready before
    # the final server — the one init connects to — is up.
    if docker exec "${name}-postgres" pg_isready -h 127.0.0.1 -U step -d postgres >/dev/null 2>&1 &&
      bash -c ": >/dev/tcp/127.0.0.1/${port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  docker logs "${name}-postgres" >>"$RUN_LOG" 2>&1 || true
  fail "instance ${name}'s PostgreSQL did not accept connections on port ${port} before init"
}

init_instance() {
  local name="$1" dir="$2" pg="$3" bao="$4" http01="$5"
  log_phase "init-${name}"
  wait_for_postgres_admin "$name" "$pg"
  wait_for_openbao_listening "$name" "$bao"
  log "initialising instance ${name}"
  local raw_log="$ARTIFACT_DIR/init-${name}.raw.log"
  # Non-interactive: every prompt has its own flag and stdin is closed.
  # `--openbao-url` is left at its default so `init` derives the endpoint
  # from this directory's own `.env` — the same derivation `status`
  # applies, and the reason each instance talks to its own OpenBao.
  if ! run_bootroot "$dir" init \
    --compose-file "$dir/$COMPOSE_FILE_NAME" \
    --secrets-dir "$dir/secrets" \
    --summary-json "$ARTIFACT_DIR/init-summary-${name}.json" \
    --enable auto-generate,show-secrets,db-provision \
    --stepca-password "two-instance-${name}" \
    --http-hmac "dev-hmac-${name}" \
    --no-eab \
    --save-unseal-keys \
    --overwrite-password \
    --overwrite-ca-json \
    --overwrite-state \
    --confirm-db-provision \
    --db-user "step" \
    --db-name "stepca" \
    --responder-url "http://127.0.0.1:${http01}" \
    </dev/null >"$raw_log" 2>&1; then
    {
      echo "bootroot init failed for instance ${name} (raw tail):"
      tail -n 200 "$raw_log" || true
    } >>"$RUN_LOG"
    fail "bootroot init failed for instance ${name}"
  fi
  sed 's/^\(root token: \).*/\1<redacted>/' "$raw_log" >"$ARTIFACT_DIR/init-${name}.log"
}

# `bootroot status` bails when any core container is missing or unhealthy
# and when OpenBao is unreachable, so a zero exit is the health report.
# It reads `state.json` from the working directory and derives the
# OpenBao endpoint from that directory's `.env`, which is exactly the
# per-instance resolution under test.
wait_for_instance_healthy() {
  local name="$1" dir="$2" label="$3"
  local attempt out="$ARTIFACT_DIR/status-${name}-${label}.log"
  for attempt in $(seq 1 "$HEALTH_ATTEMPTS"); do
    if run_bootroot "$dir" status --compose-file "$dir/$COMPOSE_FILE_NAME" \
      >"$out" 2>&1; then
      pass "instance ${name} reports healthy (${label})"
      return 0
    fi
    sleep "$HEALTH_DELAY_SECS"
  done
  {
    echo "bootroot status never succeeded for instance ${name} (${label}); tail:"
    tail -n 80 "$out" || true
  } >>"$RUN_LOG"
  fail "instance ${name} did not report healthy (${label})"
}

# ---------------------------------------------------------------------------
# Identity, port-publication and disjointness assertions
# ---------------------------------------------------------------------------

# The second sanitisation layer.  The resolved Compose project is read
# off the containers the install actually created, so a sanitisation that
# is later broken, bypassed by a newly added command, or defeated by some
# other mechanism shows up here instead of degrading the run to a silent
# single-instance pass.
assert_resolved_project() {
  local name="$1" dir="$2"
  local container="${name}-openbao"
  local project
  project="$(docker inspect \
    --format '{{index .Config.Labels "com.docker.compose.project"}}' \
    "$container" 2>/dev/null || true)"
  assert_equal "instance ${name} resolved Compose project" "$name" "$project"
  assert_equal "instance ${name} records BOOTROOT_INSTANCE in its own .env" \
    "$name" "$(dotenv_value "$dir/.env" BOOTROOT_INSTANCE)"
}

# Returns the name of the container publishing 127.0.0.1:<port>.
#
# Read-only across every running container on the host: a co-located
# default install is inspected, never touched.
container_publishing_port() {
  local port="$1" id name
  for id in $(docker ps -q); do
    if docker port "$id" 2>/dev/null | grep -q "127\.0\.0\.1:${port}\$"; then
      name="$(docker inspect --format '{{.Name}}' "$id")"
      printf '%s' "${name#/}"
      return 0
    fi
  done
}

assert_openbao_publication() {
  local name="$1" port="$2"
  assert_equal "the container publishing instance ${name}'s OpenBao port ${port}" \
    "${name}-openbao" "$(container_publishing_port "$port")"
}

assert_openbao_answers() {
  local name="$1" port="$2" label="$3"
  local attempt out="$ARTIFACT_DIR/seal-status-${name}-${label}.json"
  for attempt in $(seq 1 "$SERVE_ATTEMPTS"); do
    if curl -fsS -m 5 "http://127.0.0.1:${port}/v1/sys/seal-status" >"$out" 2>>"$RUN_LOG"; then
      local sealed
      sealed="$(jq -r '.sealed' "$out")"
      if [ "$sealed" != "false" ]; then
        fail "instance ${name}'s OpenBao on port ${port} is sealed (${label})"
      fi
      pass "instance ${name}'s OpenBao answers unsealed on port ${port} (${label})"
      return 0
    fi
    sleep "$SERVE_DELAY_SECS"
  done
  fail "instance ${name}'s OpenBao did not answer on port ${port} (${label})"
}

# "Still serving" is more than "the containers are up": each published
# endpoint has to answer on the instance's own port.
assert_instance_serving() {
  local name="$1" bao="$2" ca="$3" http01="$4" label="$5"
  assert_openbao_answers "$name" "$bao" "$label"
  local attempt
  for attempt in $(seq 1 "$SERVE_ATTEMPTS"); do
    if curl -kfsS -m 5 "https://127.0.0.1:${ca}/acme/acme/directory" >/dev/null 2>&1; then
      break
    fi
    if [ "$attempt" -eq "$SERVE_ATTEMPTS" ]; then
      fail "instance ${name}'s step-ca ACME directory did not answer on port ${ca} (${label})"
    fi
    sleep "$SERVE_DELAY_SECS"
  done
  pass "instance ${name}'s step-ca ACME directory answers on port ${ca} (${label})"
  for attempt in $(seq 1 "$SERVE_ATTEMPTS"); do
    local code
    code="$(curl -sS -m 5 -o /dev/null -w '%{http_code}' \
      "http://127.0.0.1:${http01}/admin/http01" 2>/dev/null || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      break
    fi
    if [ "$attempt" -eq "$SERVE_ATTEMPTS" ]; then
      fail "instance ${name}'s HTTP-01 admin API did not answer on port ${http01} (${label})"
    fi
    sleep "$SERVE_DELAY_SECS"
  done
  pass "instance ${name}'s HTTP-01 admin API answers on port ${http01} (${label})"
}

instance_container_names() {
  docker ps -a --filter "label=com.docker.compose.project=$1" --format '{{.Names}}' |
    LC_ALL=C sort
}

instance_volume_names() {
  docker volume ls -q --filter "label=com.docker.compose.project=$1" | LC_ALL=C sort
}

instance_project_labels() {
  local id
  for id in $(docker ps -aq --filter "label=com.docker.compose.project=$1"); do
    docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$id"
  done | LC_ALL=C sort -u
}

assert_disjoint() {
  local what="$1" left="$2" right="$3"
  local overlap
  overlap="$(LC_ALL=C comm -12 <(printf '%s\n' "$left") <(printf '%s\n' "$right") | grep -v '^$' || true)"
  if [ -n "$overlap" ]; then
    fail "${what} overlap between the two instances: $(printf '%s' "$overlap" | tr '\n' ' ')"
  fi
  pass "$what are disjoint"
}

assert_instances_disjoint() {
  log_phase "assert-disjoint"
  assert_disjoint "container names" \
    "$(instance_container_names "$INSTANCE_A")" "$(instance_container_names "$INSTANCE_B")"
  assert_disjoint "volume names" \
    "$(instance_volume_names "$INSTANCE_A")" "$(instance_volume_names "$INSTANCE_B")"
  assert_disjoint "com.docker.compose.project labels" \
    "$(instance_project_labels "$INSTANCE_A")" "$(instance_project_labels "$INSTANCE_B")"
  assert_equal "instance A carries exactly one project label" \
    "$INSTANCE_A" "$(instance_project_labels "$INSTANCE_A" | tr '\n' ' ' | sed 's/ $//')"
  assert_equal "instance B carries exactly one project label" \
    "$INSTANCE_B" "$(instance_project_labels "$INSTANCE_B" | tr '\n' ' ' | sed 's/ $//')"
}

# ---------------------------------------------------------------------------
# Container and volume continuity
# ---------------------------------------------------------------------------

# Container IDs, not names: an ID is byte-identical across the second
# install only if the container was never recreated.
snapshot_container_ids() {
  local project="$1" out="$2" id
  : >"$out"
  for id in $(docker ps -aq --filter "label=com.docker.compose.project=$project"); do
    docker inspect --format '{{.Name}} {{.Id}}' "$id"
  done | LC_ALL=C sort >"$out"
  [ -s "$out" ] || fail "no containers found for project ${project}"
}

# The full `docker volume inspect` document — `Name`, `Driver`, `Labels`,
# `Mountpoint`, `Options`, `Scope` and `CreatedAt`.  A volume *name* is
# not evidence of continuity: a volume Compose removed and recreated
# comes back under the same project-derived name, so comparing names
# alone would pass on exactly the regression this exists to catch.
snapshot_volume_metadata() {
  local project="$1" out="$2" volume
  : >"$out"
  while IFS= read -r volume; do
    [ -n "$volume" ] || continue
    docker volume inspect "$volume" >>"$out" ||
      fail "failed to inspect volume ${volume} of project ${project}"
  done < <(instance_volume_names "$project")
  [ -s "$out" ] || fail "no volumes found for project ${project}"
}

resolve_helper_image() {
  [ -n "$HELPER_IMAGE" ] && return 0
  HELPER_IMAGE="$(docker inspect --format '{{.Config.Image}}' "${INSTANCE_A}-openbao" 2>/dev/null || true)"
  [ -n "$HELPER_IMAGE" ] || fail "could not resolve an image for the sentinel containers"
}

# Writes/reads the sentinel through a throwaway container mounting the
# volume, built from an image already present on the host (the pattern
# `seed_root_owned_ca_keys` in run-local-lifecycle.sh follows), so the
# sentinel needs no image pull under the `--no-build` constraint.  The
# entrypoint is overridden rather than relied on so the helper works
# whatever image it lands on.
volume_sentinel_write() {
  local volume="$1" value="$2"
  resolve_helper_image
  docker run --rm --user root --entrypoint sh -v "${volume}:/mnt" "$HELPER_IMAGE" \
    -c "printf '%s' '${value}' > /mnt/${SENTINEL_FILE}" >>"$RUN_LOG" 2>&1 ||
    fail "failed to write the sentinel into volume ${volume}"
}

volume_sentinel_read() {
  local volume="$1"
  resolve_helper_image
  docker run --rm --user root --entrypoint sh -v "${volume}:/mnt" "$HELPER_IMAGE" \
    -c "cat /mnt/${SENTINEL_FILE} 2>/dev/null || true" 2>/dev/null
}

seed_volume_sentinels() {
  local project="$1" out="$2" volume
  # Resolved here, in the caller's own shell, so the cleanup chown
  # fallback can still reach the image after the run's containers are
  # gone; the read path resolves inside a command substitution and would
  # only ever set it in a subshell.
  resolve_helper_image
  : >"$out"
  while IFS= read -r volume; do
    [ -n "$volume" ] || continue
    volume_sentinel_write "$volume" "${volume}:${RUN_TOKEN}"
    printf '%s %s\n' "$volume" "${volume}:${RUN_TOKEN}" >>"$out"
  done < <(instance_volume_names "$project")
  [ -s "$out" ] || fail "no volumes found to seed for project ${project}"
}

assert_volume_sentinels() {
  local project="$1" expected_file="$2" label="$3" volume expected actual
  while read -r volume expected; do
    [ -n "$volume" ] || continue
    actual="$(volume_sentinel_read "$volume")"
    if [ "$actual" != "$expected" ]; then
      fail "volume ${volume} lost its sentinel ${label} (expected '${expected}', got '${actual}'); the volume was recreated"
    fi
  done <"$expected_file"
  pass "every volume of project ${project} kept its sentinel ${label}"
}

assert_containers_unchanged() {
  local project="$1" before="$2" label="$3"
  local after="$SNAPSHOT_DIR/containers-${project}-${label}.txt"
  snapshot_container_ids "$project" "$after"
  if ! diff -u "$before" "$after" >"$SNAPSHOT_DIR/containers-${project}-${label}.diff" 2>&1; then
    cat "$SNAPSHOT_DIR/containers-${project}-${label}.diff" >>"$RUN_LOG"
    fail "project ${project}'s containers were recreated, removed or relabelled ${label} (see $SNAPSHOT_DIR)"
  fi
  pass "project ${project}'s container IDs are unchanged ${label}"
}

assert_volumes_unchanged() {
  local project="$1" before="$2" sentinels="$3" label="$4"
  local after="$SNAPSHOT_DIR/volumes-${project}-${label}.json"
  snapshot_volume_metadata "$project" "$after"
  if ! diff -u "$before" "$after" >"$SNAPSHOT_DIR/volumes-${project}-${label}.diff" 2>&1; then
    cat "$SNAPSHOT_DIR/volumes-${project}-${label}.diff" >>"$RUN_LOG"
    fail "project ${project}'s volume metadata changed ${label} (see $SNAPSHOT_DIR)"
  fi
  pass "project ${project}'s volume inspect output is byte-identical ${label}"
  assert_volume_sentinels "$project" "$sentinels" "$label"
}

# ---------------------------------------------------------------------------
# DNS-alias containment
# ---------------------------------------------------------------------------

# Both instances' responders carry the same
# `com.docker.compose.service=bootroot-http01` label by design, so the
# project filter is the only thing keeping them apart.  This is the
# narrowed lookup `find_responder_container` in src/commands/dns_alias.rs
# performs — deliberately *not* the un-narrowed service-label-only lookup
# `verify_dns_aliases` in scripts/preflight/extra/cli-scenarios.sh uses,
# which is correct for a single-instance script and wrong here.
responder_container_id() {
  local project="$1" ids count
  ids="$(docker ps -q \
    -f "label=com.docker.compose.service=bootroot-http01" \
    -f "label=com.docker.compose.project=${project}")"
  count="$(printf '%s\n' "$ids" | grep -c '[^[:space:]]' || true)"
  if [ "$count" != "1" ]; then
    fail "expected exactly one responder for project ${project}, found ${count}"
  fi
  printf '%s' "$ids"
}

# The engine adds the container's own short ID to the alias set; it is
# filtered out so the comparison is over the aliases bootroot controls.
responder_aliases() {
  local cid="$1"
  docker inspect \
    --format '{{range $k, $v := .NetworkSettings.Networks}}{{range $v.Aliases}}{{.}} {{end}}{{end}}' \
    "$cid" |
    tr ' ' '\n' |
    awk -v id="$cid" 'NF && index(id, $0) != 1' |
    LC_ALL=C sort -u
}

snapshot_responder_aliases() {
  local project="$1" label="$2"
  responder_aliases "$(responder_container_id "$project")" \
    >"$SNAPSHOT_DIR/aliases-${project}-${label}.txt"
}

register_service() {
  local name="$1" dir="$2" service="$3" hostname="$4" instance_id="$5" \
    stepca_port="$6" http01_port="$7"
  local summary="$ARTIFACT_DIR/init-summary-${name}.json"
  local role_id secret_id
  role_id="$(jq -r '.approles[] | select(.label == "runtime_service_add") | .role_id // empty' "$summary")"
  secret_id="$(jq -r '.approles[] | select(.label == "runtime_service_add") | .secret_id // empty' "$summary")"
  [ -n "$role_id" ] || fail "failed to parse runtime_service_add role_id for instance ${name}"
  [ -n "$secret_id" ] || fail "failed to parse runtime_service_add secret_id for instance ${name}"

  # `service add` takes no compose-file argument at all: it resolves the
  # identity with `ComposeIdentity::resolve_for_dir(Path::new("."), ...)`,
  # loads `state.json` from the bare relative `state.json`, and reaches
  # OpenBao at the `openbao_url` recorded there.  Running it from this
  # instance's own directory is therefore what selects all three.
  run_bootroot "$dir" service add \
    --service-name "$service" \
    --delivery-mode local-file \
    --hostname "$hostname" \
    --domain "$DOMAIN" \
    --agent-config "$dir/agent-${service}.toml" \
    --cert-path "$dir/certs/${service}.crt" \
    --key-path "$dir/certs/${service}.key" \
    --instance-id "$instance_id" \
    --agent-server "https://127.0.0.1:${stepca_port}/acme/acme/directory" \
    --agent-responder-url "http://127.0.0.1:${http01_port}" \
    --auth-mode approle \
    --approle-role-id "$role_id" \
    --approle-secret-id "$secret_id" \
    >>"$RUN_LOG" 2>&1 || fail "service add failed on instance ${name}"
}

# One rewiring, both responders observed.  The rewired instance must gain
# exactly the new alias; the other instance's alias set must be
# byte-identical to its pre-registration snapshot.  This is the one
# cross-instance path that would not announce itself as a Docker name
# conflict: the service label is identical across instances by design, so
# rewiring the wrong responder would silently move another instance's
# DNS aliases.
assert_alias_containment() {
  local rewired="$1" other="$2" alias_fqdn="$3" round="$4"
  local before_rewired="$SNAPSHOT_DIR/aliases-${rewired}-before-${round}.txt"
  local before_other="$SNAPSHOT_DIR/aliases-${other}-before-${round}.txt"
  local after_rewired="$SNAPSHOT_DIR/aliases-${rewired}-after-${round}.txt"
  local after_other="$SNAPSHOT_DIR/aliases-${other}-after-${round}.txt"

  responder_aliases "$(responder_container_id "$rewired")" >"$after_rewired"
  responder_aliases "$(responder_container_id "$other")" >"$after_other"

  local gained
  gained="$(LC_ALL=C comm -13 "$before_rewired" "$after_rewired" | grep -v '^$' || true)"
  assert_equal "instance ${rewired}'s responder gained exactly the new alias (${round})" \
    "$alias_fqdn" "$gained"

  if ! diff -u "$before_other" "$after_other" >"$SNAPSHOT_DIR/aliases-${other}-${round}.diff" 2>&1; then
    cat "$SNAPSHOT_DIR/aliases-${other}-${round}.diff" >>"$RUN_LOG"
    fail "instance ${other}'s responder alias set changed while instance ${rewired} was rewired (${round})"
  fi
  pass "instance ${other}'s responder alias set is byte-identical (${round})"

  if grep -qxF "$alias_fqdn" "$after_other"; then
    fail "instance ${other}'s responder acquired instance ${rewired}'s alias ${alias_fqdn} (${round})"
  fi
  pass "instance ${other}'s responder did not acquire ${alias_fqdn} (${round})"
}

run_alias_containment() {
  log_phase "dns-alias-containment"
  local alias_a="${SERVICE_INSTANCE_ID_A}.${SERVICE_A}.${HOSTNAME_A}.${DOMAIN}"
  local alias_b="${SERVICE_INSTANCE_ID_B}.${SERVICE_B}.${HOSTNAME_B}.${DOMAIN}"

  snapshot_responder_aliases "$INSTANCE_A" "before-a-then-b"
  snapshot_responder_aliases "$INSTANCE_B" "before-a-then-b"
  register_service "$INSTANCE_A" "$DIR_A" "$SERVICE_A" "$HOSTNAME_A" \
    "$SERVICE_INSTANCE_ID_A" "$PORT_A_STEPCA" "$PORT_A_HTTP01"
  assert_alias_containment "$INSTANCE_A" "$INSTANCE_B" "$alias_a" "a-then-b"

  snapshot_responder_aliases "$INSTANCE_A" "before-b-then-a"
  snapshot_responder_aliases "$INSTANCE_B" "before-b-then-a"
  register_service "$INSTANCE_B" "$DIR_B" "$SERVICE_B" "$HOSTNAME_B" \
    "$SERVICE_INSTANCE_ID_B" "$PORT_B_STEPCA" "$PORT_B_HTTP01"
  assert_alias_containment "$INSTANCE_B" "$INSTANCE_A" "$alias_b" "b-then-a"
}

# ---------------------------------------------------------------------------
# Teardown and leftover checks
# ---------------------------------------------------------------------------

capture_artifacts() {
  local project dir
  for project in "$INSTANCE_A:$DIR_A" "$INSTANCE_B:$DIR_B"; do
    dir="${project#*:}"
    project="${project%%:*}"
    [ -n "$dir" ] && [ -d "$dir" ] || continue
    instance_compose "$project" "$dir" ps \
      >"$ARTIFACT_DIR/compose-ps-${project}.log" 2>&1 || true
    instance_compose "$project" "$dir" logs --no-color \
      >"$ARTIFACT_DIR/compose-logs-${project}.log" 2>&1 || true
  done
}

# Every teardown action is scoped to the run's own instance names and
# their `com.docker.compose.project` labels — never a `bootroot-*`
# wildcard — so a co-located default install is untouched.
teardown_instance() {
  local project="$1" dir="$2" id
  if [ -n "$dir" ] && [ -f "$dir/$COMPOSE_FILE_NAME" ]; then
    instance_compose "$project" "$dir" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  for id in $(docker ps -aq --filter "label=com.docker.compose.project=${project}" 2>/dev/null); do
    docker rm -f "$id" >/dev/null 2>&1 || true
  done
  for id in $(docker volume ls -q --filter "label=com.docker.compose.project=${project}" 2>/dev/null); do
    docker volume rm -f "$id" >/dev/null 2>&1 || true
  done
  for id in $(docker network ls -q --filter "label=com.docker.compose.project=${project}" 2>/dev/null); do
    docker network rm "$id" >/dev/null 2>&1 || true
  done
}

assert_no_leftovers() {
  local project="$1" label="$2" leftovers
  leftovers="$(docker ps -aq --filter "label=com.docker.compose.project=${project}" 2>/dev/null || true)"
  [ -z "$leftovers" ] || fail "containers of project ${project} survived ${label}"
  leftovers="$(docker volume ls -q --filter "label=com.docker.compose.project=${project}" 2>/dev/null || true)"
  [ -z "$leftovers" ] || fail "volumes of project ${project} survived ${label}"
  pass "no container or volume of project ${project} survived ${label}"
}

remove_run_root() {
  [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ] || return 0
  if rm -rf "$RUN_ROOT" 2>/dev/null; then
    return 0
  fi
  # A container may have left material under `secrets/` owned by another
  # uid.  Re-own it through the same throwaway-container route the
  # sentinels use rather than reaching for host privileges.
  if [ -n "$HELPER_IMAGE" ]; then
    docker run --rm --user root --entrypoint sh -v "${RUN_ROOT}:/mnt" "$HELPER_IMAGE" \
      -c "chown -R $(id -u):$(id -g) /mnt" >/dev/null 2>&1 || true
  fi
  rm -rf "$RUN_ROOT" 2>/dev/null || true
  [ ! -d "$RUN_ROOT" ] || fail "failed to remove the run root ${RUN_ROOT}"
}

cleanup() {
  local status=$?
  log_phase "cleanup"
  capture_artifacts
  teardown_instance "$INSTANCE_A" "$DIR_A"
  teardown_instance "$INSTANCE_B" "$DIR_B"
  docker image rm -f "$HTTP01_IMAGE" >/dev/null 2>&1 || true
  remove_run_root
  local project leftovers
  for project in "$INSTANCE_A" "$INSTANCE_B"; do
    leftovers="$(docker ps -aq --filter "label=com.docker.compose.project=${project}" 2>/dev/null || true)"
    leftovers="${leftovers}$(docker volume ls -q --filter "label=com.docker.compose.project=${project}" 2>/dev/null || true)"
    if [ -n "$leftovers" ]; then
      echo "[two-instance][cleanup] leftovers survived for project ${project}" >&2
      status=1
    fi
  done
  if [ -d "$RUN_ROOT" ]; then
    echo "[two-instance][cleanup] run root survived: ${RUN_ROOT}" >&2
    status=1
  fi
  exit "$status"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
  mkdir -p "$ARTIFACT_DIR" "$SNAPSHOT_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  log_phase "startup"
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  ensure_prerequisites
  log "instance A: ${INSTANCE_A}"
  log "instance B: ${INSTANCE_B}"

  log_phase "prepare"
  build_responder_image
  create_run_root
  prepull_third_party_images
  allocate_ports

  install_instance "$INSTANCE_A" "$DIR_A" \
    "$PORT_A_POSTGRES" "$PORT_A_OPENBAO" "$PORT_A_STEPCA" "$PORT_A_HTTP01"
  init_instance "$INSTANCE_A" "$DIR_A" \
    "$PORT_A_POSTGRES" "$PORT_A_OPENBAO" "$PORT_A_HTTP01"

  log_phase "assert-a-installed"
  wait_for_instance_healthy "$INSTANCE_A" "$DIR_A" "after-init"
  assert_resolved_project "$INSTANCE_A" "$DIR_A"
  assert_openbao_publication "$INSTANCE_A" "$PORT_A_OPENBAO"
  assert_instance_serving "$INSTANCE_A" "$PORT_A_OPENBAO" "$PORT_A_STEPCA" \
    "$PORT_A_HTTP01" "after-init"

  log_phase "snapshot-a"
  snapshot_container_ids "$INSTANCE_A" "$SNAPSHOT_DIR/containers-${INSTANCE_A}-baseline.txt"
  snapshot_volume_metadata "$INSTANCE_A" "$SNAPSHOT_DIR/volumes-${INSTANCE_A}-baseline.json"
  seed_volume_sentinels "$INSTANCE_A" "$SNAPSHOT_DIR/sentinels-${INSTANCE_A}.txt"
  # The sentinels are written into live data roots, so re-assert health
  # before treating them as a baseline: a service that rejected the
  # dotfile must surface here rather than as a confusing later failure.
  wait_for_instance_healthy "$INSTANCE_A" "$DIR_A" "after-sentinels"

  install_instance "$INSTANCE_B" "$DIR_B" \
    "$PORT_B_POSTGRES" "$PORT_B_OPENBAO" "$PORT_B_STEPCA" "$PORT_B_HTTP01"

  log_phase "assert-a-survived-b-install"
  assert_containers_unchanged "$INSTANCE_A" \
    "$SNAPSHOT_DIR/containers-${INSTANCE_A}-baseline.txt" "after-b-install"
  assert_volumes_unchanged "$INSTANCE_A" \
    "$SNAPSHOT_DIR/volumes-${INSTANCE_A}-baseline.json" \
    "$SNAPSHOT_DIR/sentinels-${INSTANCE_A}.txt" "after-b-install"
  wait_for_instance_healthy "$INSTANCE_A" "$DIR_A" "after-b-install"

  init_instance "$INSTANCE_B" "$DIR_B" \
    "$PORT_B_POSTGRES" "$PORT_B_OPENBAO" "$PORT_B_HTTP01"

  log_phase "assert-b-installed"
  wait_for_instance_healthy "$INSTANCE_B" "$DIR_B" "after-init"
  assert_resolved_project "$INSTANCE_B" "$DIR_B"
  assert_openbao_publication "$INSTANCE_B" "$PORT_B_OPENBAO"
  assert_instance_serving "$INSTANCE_B" "$PORT_B_OPENBAO" "$PORT_B_STEPCA" \
    "$PORT_B_HTTP01" "after-init"
  wait_for_instance_healthy "$INSTANCE_A" "$DIR_A" "after-b-init"

  assert_instances_disjoint

  run_alias_containment

  log_phase "teardown-b"
  teardown_instance "$INSTANCE_B" "$DIR_B"
  assert_no_leftovers "$INSTANCE_B" "instance B teardown"

  log_phase "assert-a-survived-b-teardown"
  assert_containers_unchanged "$INSTANCE_A" \
    "$SNAPSHOT_DIR/containers-${INSTANCE_A}-baseline.txt" "after-b-teardown"
  assert_volumes_unchanged "$INSTANCE_A" \
    "$SNAPSHOT_DIR/volumes-${INSTANCE_A}-baseline.json" \
    "$SNAPSHOT_DIR/sentinels-${INSTANCE_A}.txt" "after-b-teardown"
  wait_for_instance_healthy "$INSTANCE_A" "$DIR_A" "after-b-teardown"
  assert_instance_serving "$INSTANCE_A" "$PORT_A_OPENBAO" "$PORT_A_STEPCA" \
    "$PORT_A_HTTP01" "after-b-teardown"

  log_phase "done"
  log "two-instance isolation checks passed"
}

main "$@"
