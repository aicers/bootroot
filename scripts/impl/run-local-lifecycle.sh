#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# shellcheck source=lib/audit-log.sh
. "$SCRIPT_DIR/lib/audit-log.sh"

ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/docker-local-lifecycle-$(date +%s)}"
COMPOSE_FILE="${COMPOSE_FILE:-$ROOT_DIR/docker-compose.yml}"
COMPOSE_TEST_FILE="${COMPOSE_TEST_FILE:-$ROOT_DIR/docker-compose.test.yml}"
WORKSPACE_DIR="${WORKSPACE_DIR:-$ARTIFACT_DIR/workspace}"
SECRETS_DIR="${SECRETS_DIR:-$ROOT_DIR/secrets}"
AGENT_CONFIG_PATH="${AGENT_CONFIG_PATH:-$WORKSPACE_DIR/agent.toml}"
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

OPENBAO_CONTAINER_NAME="bootroot-openbao"
EDGE_SERVICE="edge-proxy"
EDGE_HOSTNAME="edge-node-01"
WEB_SERVICE="web-app"
WEB_HOSTNAME="web-01"
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
INIT_ROOT_TOKEN=""
OPENBAO_RECOVERY_OUTPUT_FILE="$ARTIFACT_DIR/openbao-recovery.json"
# Use a daemon-deploy service for the OBA exercise so the
# `bootroot service openbao-sidecar start` daemon bind-mounts land
# the rendered agent.toml at the same host path the test issues
# certs against (`$AGENT_CONFIG_PATH`).  The docker-deploy variant
# would render under `$SECRETS_DIR/services/<svc>/` instead, which
# doesn't match the per-service verify call below.
SIDECAR_OBA_SERVICE="$EDGE_SERVICE"
SIDECAR_OBA_CONTAINER="bootroot-openbao-agent-${SIDECAR_OBA_SERVICE}"
SIDECAR_OBA_READY_ATTEMPTS="${SIDECAR_OBA_READY_ATTEMPTS:-30}"
SIDECAR_OBA_READY_DELAY_SECS="${SIDECAR_OBA_READY_DELAY_SECS:-2}"
# Selects which OpenBao Agent deployment to exercise:
#   sidecar     - bootroot-managed, started via `service openbao-sidecar start`
#                 (default; active rotate-signal path)
#   host-daemon - operator-managed, started by this script via
#                 `docker run --network host` to simulate a host `bao agent`
#                 (passive rotate-signal path via static_secret_render_interval)
OBA_DEPLOYMENT="${OBA_DEPLOYMENT:-sidecar}"
HOST_DAEMON_OBA_CONTAINER="${HOST_DAEMON_OBA_CONTAINER:-bootroot-openbao-agent-host-${EDGE_SERVICE}}"
# Selects which compose-project / OpenBao topology to exercise around
# `service openbao-sidecar start`.  All values run the same install
# + init + service-add prefix; later phases differ.
#
#   default          - standard bootroot compose, default project name.
#                      Runs the full lifecycle (sidecar start + rotations).
#   custom-project   - same as default but exports
#                      COMPOSE_PROJECT_NAME=$CUSTOM_COMPOSE_PROJECT before
#                      bringing up the stack.  Asserts the sidecar lands
#                      in that project (exercises env-var → project-label
#                      discovery branch in `discover_compose_project`).
#   openbao-missing  - removes the bootroot-openbao container before
#                      invoking `service openbao-sidecar start` and
#                      asserts the command exits non-zero with the
#                      full "container not found" i18n message,
#                      including the `bootroot infra install` /
#                      `--openbao-network` remediation guidance.
#                      Skips the rotation phase (state is intentionally
#                      degraded).
#   external-openbao - swaps in a stripped compose file (no openbao
#                      service) and an external docker network for the
#                      `service openbao-sidecar start` call.  Asserts the
#                      negative path (no flag → required-flag error)
#                      and the positive path (with --openbao-network the
#                      sidecar attaches to the external network).  Skips
#                      the rotation phase.
OBA_TOPOLOGY="${OBA_TOPOLOGY:-default}"
CUSTOM_COMPOSE_PROJECT="${CUSTOM_COMPOSE_PROJECT:-myorg-prod}"
EXTERNAL_OBA_NETWORK="${EXTERNAL_OBA_NETWORK:-oba-ext}"
# Upper bound for the responder-hmac rotate's wall-clock under each
# OBA deployment.  The two thresholds together prove which propagation
# route OpenBao Agent took:
#
#   sidecar:     bootroot's active container restart hands the new
#                HMAC over instantly, so the rotate must complete
#                well below `static_secret_render_interval` (=30s).
#                If the active route silently regresses (e.g. wrong
#                container name, signal not delivered), rotate would
#                still succeed via the polling fallback — but the
#                wall-clock would jump above this threshold and we'd
#                catch the regression here instead of letting it ship
#                undetected (the gap that #577 sat in for a release).
#
#   host-daemon: bootroot has no handle on the operator-managed
#                daemon, so the active restart silently no-ops and
#                only the polling fallback (`static_secret_render_interval
#                = 30s`) propagates the new HMAC.  Allow the full
#                polling window plus jitter.
SIDECAR_ROTATE_LATENCY_LIMIT_SECS="${SIDECAR_ROTATE_LATENCY_LIMIT_SECS:-25}"
HOST_DAEMON_RENDER_TIMEOUT_SECS="${HOST_DAEMON_RENDER_TIMEOUT_SECS:-75}"
CURRENT_PHASE="init"
# PID of the long-running bootroot-agent daemon started for the local
# services (edge-proxy + web-app share AGENT_CONFIG_PATH).  Required so
# `bootroot rotate force-reissue --wait` can deliver SIGHUP to a real
# process — without it, pkill -HUP exits 1 ("no processes matched") and
# the rotate fails before the wait path runs.
LOCAL_AGENT_DAEMON_PID=""
LOCAL_AGENT_DAEMON_LOG="$ARTIFACT_DIR/bootroot-agent.log"
# Pin POSTGRES_HOST_PORT for the compose stack: docker-compose.yml's
# default moved from 5432 to 5433 in #588 §4c; the e2e harness
# expects 5432 (CI runners free that port before the matrix), so
# pin it explicitly here to keep compose port mapping aligned with
# wait_for_postgres_admin and the host-side admin DSN.
export POSTGRES_HOST_PORT="${POSTGRES_HOST_PORT:-5432}"
export POSTGRES_HOST="127.0.0.1"
export POSTGRES_PORT="$POSTGRES_HOST_PORT"

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

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v openssl >/dev/null 2>&1 || fail "openssl is required"
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
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" ps -q "$service" | tr -d '\n'
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

compose_down() {
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
}

capture_artifacts() {
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
  docker compose -f "$COMPOSE_FILE" -f "$COMPOSE_TEST_FILE" logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs bootroot-openbao-agent-stepca >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs bootroot-openbao-agent-responder >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs "$SIDECAR_OBA_CONTAINER" >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
  docker logs "$HOST_DAEMON_OBA_CONTAINER" >>"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
}

# Sidecar variant: invoke the canonical bootroot CLI so CI exercises
# the same code path operators use.  This catches regressions in the
# sidecar-management code (e.g. issue #577's hardcoded network bug)
# that an inline `docker run` shortcut would silently bypass.
start_service_sidecar_oba_via_bootroot() {
  local service="$1"
  rm -f "$AGENT_CONFIG_PATH"
  docker rm -f "bootroot-openbao-agent-${service}" >/dev/null 2>&1 || true

  run_bootroot service openbao-sidecar start \
    --service-name "$service" \
    --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1
  wait_for_oba_render "$AGENT_CONFIG_PATH" \
    "$SIDECAR_OBA_READY_ATTEMPTS" \
    "$SIDECAR_OBA_READY_DELAY_SECS" \
    "bootroot-openbao-agent-${service}" \
    "sidecar OBA"
}

# Host-daemon variant: simulate a host-managed `bao agent` by running
# the OpenBao binary in a container that shares the host network
# namespace.  agent.hcl points at 127.0.0.1:8200 (the host-published
# port), and rotate signals propagate via the polling fallback.
start_service_host_daemon_oba() {
  local service="$1"
  local agent_hcl="$SECRETS_DIR/openbao/services/${service}/agent.hcl"
  rm -f "$AGENT_CONFIG_PATH"
  docker rm -f "$HOST_DAEMON_OBA_CONTAINER" >/dev/null 2>&1 || true

  # --network host so 127.0.0.1:8200 in agent.hcl reaches the
  # bootroot-openbao port published to the host.  Bind-mount the same
  # paths the sidecar uses so agent.toml renders to AGENT_CONFIG_PATH.
  docker run -d \
    --name "$HOST_DAEMON_OBA_CONTAINER" \
    --user "$(id -u):$(id -g)" \
    --network host \
    -v "$ROOT_DIR:$ROOT_DIR" \
    -v "$ARTIFACT_DIR:$ARTIFACT_DIR" \
    openbao/openbao:latest \
    agent -config="$agent_hcl" >>"$RUN_LOG" 2>&1
  wait_for_oba_render "$AGENT_CONFIG_PATH" \
    "$SIDECAR_OBA_READY_ATTEMPTS" \
    "$SIDECAR_OBA_READY_DELAY_SECS" \
    "$HOST_DAEMON_OBA_CONTAINER" \
    "host-daemon OBA"
}

# Polls for an OBA-rendered agent.toml signature.  Centralised so
# both variants share the same readiness contract.
wait_for_oba_render() {
  local config_path="$1"
  local attempts="$2"
  local delay="$3"
  local container="$4"
  local label="$5"
  local attempt
  for attempt in $(seq 1 "$attempts"); do
    if [ -f "$config_path" ] &&
      grep -Eq '^[[:space:]]*http_responder_hmac[[:space:]]*=[[:space:]]*"[^"]+"' \
        "$config_path" 2>/dev/null; then
      return 0
    fi
    sleep "$delay"
  done
  docker logs "$container" >>"$RUN_LOG" 2>&1 || true
  fail "${label} (${container}) did not render agent config within timeout"
}

start_service_oba() {
  case "$OBA_DEPLOYMENT" in
    sidecar)
      start_service_sidecar_oba_via_bootroot "$1"
      ;;
    host-daemon)
      start_service_host_daemon_oba "$1"
      ;;
    *)
      fail "Unsupported OBA_DEPLOYMENT: $OBA_DEPLOYMENT (expected: sidecar | host-daemon)"
      ;;
  esac
}

stop_service_oba() {
  docker rm -f "$SIDECAR_OBA_CONTAINER" >/dev/null 2>&1 || true
  docker rm -f "$HOST_DAEMON_OBA_CONTAINER" >/dev/null 2>&1 || true
}

# Asserts the sidecar container's compose project label matches the
# expected value.  Catches regressions where project-label discovery
# silently falls back to a hardcoded default instead of honouring
# COMPOSE_PROJECT_NAME (issue #582 scenario 1).
assert_sidecar_compose_project() {
  local container="$1"
  local expected="$2"
  local actual
  actual="$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$container" 2>/dev/null || true)"
  if [ "$actual" != "$expected" ]; then
    docker logs "$container" >>"$RUN_LOG" 2>&1 || true
    fail "sidecar container $container has compose project label '$actual', expected '$expected' (custom-project topology)"
  fi
  printf '[lifecycle] sidecar compose project label verified: container=%s project=%s\n' \
    "$container" "$actual" >>"$RUN_LOG"
}

# Removes bootroot-openbao via `docker rm -f` (NOT `docker stop`) so
# `docker inspect` returns a "no such container" error and exercises
# the ContainerNotFound branch in `inspect_label_via_docker`.  A plain
# stop would leave the container's compose project label intact and
# trigger the Present(value) branch instead.
remove_openbao_container_for_missing_topology() {
  docker rm -f "$OPENBAO_CONTAINER_NAME" >/dev/null 2>&1 || true
  if docker inspect "$OPENBAO_CONTAINER_NAME" >/dev/null 2>&1; then
    fail "$OPENBAO_CONTAINER_NAME still exists after docker rm -f (openbao-missing topology)"
  fi
}

# Asserts `service openbao-sidecar start` fails and the captured
# stderr+stdout contains *every* expected substring.  Multiple
# substrings let us pin both the symptom and the remediation portion
# of an i18n message, so a regression that drops the remediation hint
# is caught even when the symptom string is unchanged.
#
# Usage:
#   assert_service_oba_start_fails <service> <substring> [<substring>...] \
#     -- [bootroot service openbao-sidecar start args...]
#
# The literal `--` separates expected-substring args from bootroot
# CLI args.  At least one substring is required.
assert_service_oba_start_fails() {
  local service="$1"
  shift
  local -a expected_substrings=()
  while [ "$#" -gt 0 ] && [ "$1" != "--" ]; do
    expected_substrings+=("$1")
    shift
  done
  if [ "$#" -eq 0 ]; then
    fail "assert_service_oba_start_fails: missing '--' separator before bootroot args"
  fi
  shift # discard the literal --
  if [ "${#expected_substrings[@]}" -eq 0 ]; then
    fail "assert_service_oba_start_fails: at least one expected substring is required"
  fi
  local capture_file
  capture_file="$(mktemp "$ARTIFACT_DIR/oba-start-fail.XXXXXX")"
  rm -f "$AGENT_CONFIG_PATH"
  docker rm -f "bootroot-openbao-agent-${service}" >/dev/null 2>&1 || true
  if (cd "$WORKSPACE_DIR" && "$BOOTROOT_BIN" service openbao-sidecar start \
        --service-name "$service" "$@") >"$capture_file" 2>&1; then
    cat "$capture_file" >>"$RUN_LOG" || true
    fail "service openbao-sidecar start unexpectedly succeeded for ${service} (expected failure containing: ${expected_substrings[*]})"
  fi
  cat "$capture_file" >>"$RUN_LOG" || true
  local substring
  for substring in "${expected_substrings[@]}"; do
    if ! grep -qF -e "$substring" "$capture_file"; then
      fail "service openbao-sidecar start error did not contain expected substring '${substring}' (see $capture_file)"
    fi
    printf '[lifecycle] service openbao-sidecar start failed as expected: substring=%q\n' \
      "$substring" >>"$RUN_LOG"
  done
}

# Writes a stripped compose file that has no `openbao` service,
# forcing the `compose_has_openbao() == false` branch in
# `resolve_sidecar_topology`.  Other infra services are kept so the
# stripped file still parses as a valid compose document.
write_stripped_compose_file() {
  local target="$1"
  cat >"$target" <<'YAML'
services:
  placeholder:
    image: hello-world
    profiles:
      - never-up
YAML
}

# Drives the external-OpenBao topology assertions: stripped compose
# with no openbao service + a separately-created docker network the
# sidecar must attach to via --openbao-network.
#
# Provides a reachable OpenBao endpoint on `oba-ext` by connecting the
# already-initialised `bootroot-openbao` container to that network.
# The agent.hcl rendered during `service add` always points at
# `address = "http://bootroot-openbao:8200"` (see
# `render_docker_agent_config`), so docker DNS on `oba-ext` resolves
# the address from inside the sidecar and `bao agent` can authenticate
# and render `agent.toml` end-to-end.
#
# The positive case sets COMPOSE_PROJECT_NAME to a sentinel value
# before invoking bootroot, then asserts the sidecar's
# `com.docker.compose.project` label equals that sentinel.  This
# proves no `-p <project>` was passed to docker compose: with `-p`,
# the label would equal the `-p` value (always `bootroot` or the
# discovered project under #580's logic); without `-p`, it falls
# through to COMPOSE_PROJECT_NAME == sentinel.
#
# The `wait_for_oba_render` call after the positive invocation is the
# core proof that `--openbao-network` plumbed the sidecar to a working
# OpenBao endpoint — `docker compose up -d` succeeds even when the
# agent's first connection fails (it would just keep restarting), so
# the rendered HMAC line in `agent.toml` is the only end-to-end signal
# that the sidecar actually talked to OpenBao.
run_external_openbao_topology_assertions() {
  local service="$1"
  local stripped_compose="$ARTIFACT_DIR/docker-compose.stripped.yml"
  local sidecar_container="bootroot-openbao-agent-${service}"
  local no_p_sentinel="external-no-p-sentinel"
  write_stripped_compose_file "$stripped_compose"
  if ! docker network inspect "$EXTERNAL_OBA_NETWORK" >/dev/null 2>&1; then
    docker network create "$EXTERNAL_OBA_NETWORK" >/dev/null
  fi
  # Attach the existing OpenBao container to oba-ext so the sidecar
  # (which joins oba-ext only) can resolve `bootroot-openbao` via
  # docker DNS and reach the API.  Idempotent: `docker network
  # connect` errors if the container is already attached.
  if ! docker inspect --format \
        "{{range \$k,\$v := .NetworkSettings.Networks}}{{\$k}} {{end}}" \
        "$OPENBAO_CONTAINER_NAME" 2>/dev/null | grep -qw "$EXTERNAL_OBA_NETWORK"; then
    docker network connect "$EXTERNAL_OBA_NETWORK" "$OPENBAO_CONTAINER_NAME" >>"$RUN_LOG" 2>&1
  fi

  # Align state.openbao_url with the docker-DNS name used inside the
  # sidecar.  The override generated by `service openbao-sidecar
  # start` sets `VAULT_ADDR={state.openbao_url}` verbatim when
  # `compose_has_openbao` is false (stripped compose), and OpenBao
  # Agent honours that env var over `vault.address` in the rendered
  # agent-docker.hcl.  Init left openbao_url at `http://localhost:8200`
  # which is unreachable from inside the sidecar; rewriting it to the
  # container name lets docker DNS on `oba-ext` route the request to
  # the existing bootroot-openbao container we just attached.  The
  # rendered agent-docker.hcl already addresses OpenBao by container
  # name, so config and env now agree.
  local state_file="$WORKSPACE_DIR/state.json"
  if [ -f "$state_file" ]; then
    local tmp_state
    tmp_state="$(mktemp "$ARTIFACT_DIR/state.json.XXXXXX")"
    jq '.openbao_url = "http://bootroot-openbao:8200"' "$state_file" >"$tmp_state"
    mv "$tmp_state" "$state_file"
    printf '[lifecycle] external-openbao topology: rewrote state.openbao_url=%s\n' \
      "http://bootroot-openbao:8200" >>"$RUN_LOG"
  else
    fail "state.json not found at $state_file (external-openbao topology)"
  fi

  # Negative: no --openbao-network and stripped compose → must fail
  # with the i18n message that requests the flag.
  assert_service_oba_start_fails "$service" \
    "--openbao-network" \
    -- \
    --compose-file "$stripped_compose"

  # Positive: with --openbao-network the sidecar attaches to the
  # external network and the docker compose invocation must NOT
  # include `-p <project>`.  Assert via the COMPOSE_PROJECT_NAME
  # sentinel; the matching unit test
  # (`build_compose_up_args_omits_project_when_not_supplied`)
  # backs this at the function level.
  rm -f "$AGENT_CONFIG_PATH"
  docker rm -f "$sidecar_container" >/dev/null 2>&1 || true
  (cd "$WORKSPACE_DIR" && \
      COMPOSE_PROJECT_NAME="$no_p_sentinel" \
      "$BOOTROOT_BIN" service openbao-sidecar start \
        --service-name "$service" \
        --compose-file "$stripped_compose" \
        --openbao-network "$EXTERNAL_OBA_NETWORK") >>"$RUN_LOG" 2>&1
  if ! docker inspect "$sidecar_container" >/dev/null 2>&1; then
    fail "sidecar container $sidecar_container not created in external-openbao positive case"
  fi
  local network_id
  network_id="$(docker inspect --format \
    "{{range \$k,\$v := .NetworkSettings.Networks}}{{\$k}} {{end}}" \
    "$sidecar_container" 2>/dev/null || true)"
  if ! printf '%s' "$network_id" | grep -qw "$EXTERNAL_OBA_NETWORK"; then
    fail "sidecar container $sidecar_container is not on $EXTERNAL_OBA_NETWORK (networks: $network_id)"
  fi
  local actual_project
  actual_project="$(docker inspect --format '{{ index .Config.Labels "com.docker.compose.project" }}' "$sidecar_container" 2>/dev/null || true)"
  if [ "$actual_project" != "$no_p_sentinel" ]; then
    fail "sidecar container $sidecar_container has compose project '$actual_project', expected '$no_p_sentinel' — proves docker compose was invoked WITH a -p flag instead of relying on COMPOSE_PROJECT_NAME"
  fi
  # End-to-end proof that --openbao-network reached a working OpenBao:
  # the sidecar must render agent.toml with an http_responder_hmac
  # value, which only happens after a successful auth + template
  # fetch round-trip.
  wait_for_oba_render "$AGENT_CONFIG_PATH" \
    "$SIDECAR_OBA_READY_ATTEMPTS" \
    "$SIDECAR_OBA_READY_DELAY_SECS" \
    "$sidecar_container" \
    "external-openbao sidecar"
  printf '[lifecycle] external-openbao positive case verified: container=%s networks=%q project=%s render=ok\n' \
    "$sidecar_container" "$network_id" "$actual_project" >>"$RUN_LOG"
}

cleanup_hosts() {
  if [ "$RESOLUTION_MODE" != "hosts" ]; then
    return 0
  fi
  if [ "$(id -u)" -ne 0 ] && ! command -v sudo >/dev/null 2>&1; then
    return 0
  fi
  local tmp_file
  tmp_file="$(mktemp)"
  run_sudo awk -v marker="$HOSTS_MARKER" 'index($0, marker) == 0 { print }' /etc/hosts >"$tmp_file"
  run_sudo cp "$tmp_file" /etc/hosts
  rm -f "$tmp_file"
}

cleanup() {
  log_phase "cleanup"
  cleanup_hosts
  stop_local_bootroot_agent_daemon
  capture_artifacts
  stop_service_oba
  compose_down
  if [ "$OBA_TOPOLOGY" = "external-openbao" ]; then
    docker network rm "$EXTERNAL_OBA_NETWORK" >/dev/null 2>&1 || true
  fi
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
      add_hosts_entry "$STEPCA_HOST_IP" "$STEPCA_HOST_NAME"
      add_hosts_entry "$RESPONDER_HOST_IP" "$RESPONDER_HOST_NAME"
      STEPCA_SERVER_URL="https://${STEPCA_HOST_NAME}:9000/acme/acme/directory"
      RESPONDER_URL="http://${RESPONDER_HOST_NAME}:8080"
      ;;
    no-hosts)
      STEPCA_SERVER_URL="https://localhost:9000/acme/acme/directory"
      RESPONDER_URL="http://${RESPONDER_HOST_IP}:8080"
      ;;
    *)
      fail "Unsupported RESOLUTION_MODE: $RESOLUTION_MODE"
      ;;
  esac
}

write_agent_config() {
  mkdir -p "$(dirname "$AGENT_CONFIG_PATH")" "$CERTS_DIR"
  cat >"$AGENT_CONFIG_PATH" <<EOF
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
  run_bootroot infra install --compose-file "$COMPOSE_FILE" >>"$RUN_LOG" 2>&1
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
  if ! BOOTROOT_LANG=en printf "y\ny\ny\n" | run_bootroot init \
    --compose-file "$COMPOSE_FILE" \
    --secrets-dir "$SECRETS_DIR" \
    --summary-json "$INIT_SUMMARY_JSON" \
    --enable auto-generate,show-secrets,db-provision \
    --stepca-provisioner "acme" \
    --stepca-password "password" \
    --http-hmac "dev-hmac" \
    --no-eab \
    --db-user "step" \
    --db-name "stepca" \
    --responder-url "$RESPONDER_URL" >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 160 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
    docker logs bootroot-openbao >>"$RUN_LOG" 2>&1 || true
    docker logs bootroot-postgres >>"$RUN_LOG" 2>&1 || true
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
  INIT_ROOT_TOKEN="$(jq -r '.root_token // empty' "$INIT_SUMMARY_JSON")"
  [ -n "${RUNTIME_SERVICE_ADD_ROLE_ID:-}" ] || fail "Failed to parse runtime_service_add role_id"
  [ -n "${RUNTIME_SERVICE_ADD_SECRET_ID:-}" ] || fail "Failed to parse runtime_service_add secret_id"
  [ -n "${RUNTIME_ROTATE_ROLE_ID:-}" ] || fail "Failed to parse runtime_rotate role_id"
  [ -n "${RUNTIME_ROTATE_SECRET_ID:-}" ] || fail "Failed to parse runtime_rotate secret_id"
  [ -n "${INIT_ROOT_TOKEN:-}" ] || fail "Failed to parse init root token"
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$INIT_LOG"

  log_phase "service-add"
  # Order matters: SIDECAR_OBA_SERVICE (edge-proxy) is added LAST so its
  # rendered .ctmpl picks up web-app's managed profile from
  # workspace/agent.toml.  When the daemon-deploy sidecar later renders
  # that template back to workspace/agent.toml via the bind-mount, both
  # profiles must survive — otherwise web-app verify fails because its
  # profile entry got wiped.
  run_bootroot service add \
    --service-name "$WEB_SERVICE" \
    --deploy-type docker \
    --delivery-mode local-file \
    --hostname "$WEB_HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$AGENT_CONFIG_PATH" \
    --cert-path "$CERTS_DIR/${WEB_SERVICE}.crt" \
    --key-path "$CERTS_DIR/${WEB_SERVICE}.key" \
    --instance-id "$INSTANCE_ID" \
    --container-name "$WEB_SERVICE" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_SERVICE_ADD_ROLE_ID" \
    --approle-secret-id "$RUNTIME_SERVICE_ADD_SECRET_ID" >>"$RUN_LOG" 2>&1

  run_bootroot service add \
    --service-name "$REMOTE_SERVICE" \
    --deploy-type daemon \
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
    --deploy-type daemon \
    --delivery-mode local-file \
    --hostname "$EDGE_HOSTNAME" \
    --domain "$DOMAIN" \
    --agent-config "$AGENT_CONFIG_PATH" \
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
    code="$(curl -sS -o /dev/null -w '%{http_code}' "http://${STEPCA_HOST_IP}:8200/v1/sys/health" || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      return 0
    fi
    sleep 1
  done
  docker logs bootroot-openbao >>"$RUN_LOG" 2>&1 || true
  fail "openbao API did not become reachable before init"
}

wait_for_postgres_admin() {
  local host_port="${POSTGRES_HOST_PORT:-5432}"
  local admin_user="${POSTGRES_USER:-step}"
  local attempt
  for attempt in $(seq 1 30); do
    if docker exec bootroot-postgres pg_isready -U "$admin_user" -d postgres >/dev/null 2>&1 &&
      bash -lc ": >/dev/tcp/127.0.0.1/${host_port}" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs bootroot-postgres >>"$RUN_LOG" 2>&1 || true
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
  docker logs bootroot-http01 >>"$RUN_LOG" 2>&1 || true
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
  local -a compose_args=(-f "$COMPOSE_FILE" -f "$override")
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
      if docker exec bootroot-ca bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${host}/80'" >/dev/null 2>&1; then
        break
      fi
      if [ "$attempt" -eq "$HTTP01_TARGET_ATTEMPTS" ]; then
        docker exec bootroot-ca sh -c "cat /etc/hosts | tail -n 20" >>"$RUN_LOG" 2>&1 || true
        docker logs bootroot-http01 >>"$RUN_LOG" 2>&1 || true
        fail "step-ca cannot reach HTTP-01 target: ${host}:80"
      fi
      sleep "$HTTP01_TARGET_DELAY_SECS"
    done
  done
}

wait_for_stepca_health() {
  local attempt
  for attempt in $(seq 1 30); do
    if curl -kfsS https://127.0.0.1:9000/health >/dev/null 2>&1; then
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

fingerprint_of() {
  local service="$1"
  local label="$2"
  local meta_file="$CERT_META_DIR/${service}-${label}.txt"
  awk -F= '/^sha256 Fingerprint=/{print $2}' "$meta_file"
}

run_verify_pair() {
  local label="$1"
  log_phase "verify-${label}"
  prepare_stepca_validation_targets
  verify_service_with_retry "$EDGE_SERVICE"
  verify_service_with_retry "$WEB_SERVICE"
  verify_service_with_retry "$REMOTE_SERVICE" "$REMOTE_AGENT_CONFIG"
  snapshot_cert_meta "$EDGE_SERVICE" "$label"
  snapshot_cert_meta "$WEB_SERVICE" "$label"
  snapshot_cert_meta "$REMOTE_SERVICE" "$label" "$REMOTE_CERTS_DIR"
}

force_reissue_for_service() {
  local service="$1"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    force-reissue \
    --service-name "$service" \
    --wait \
    >>"$RUN_LOG" 2>&1
}

start_local_bootroot_agent_daemon() {
  if [ -n "$LOCAL_AGENT_DAEMON_PID" ] && kill -0 "$LOCAL_AGENT_DAEMON_PID" 2>/dev/null; then
    return 0
  fi
  [ -f "$AGENT_CONFIG_PATH" ] || fail "agent config missing at $AGENT_CONFIG_PATH"
  printf '[lifecycle] starting bootroot-agent daemon: --config %s\n' \
    "$AGENT_CONFIG_PATH" >>"$RUN_LOG"
  "$BOOTROOT_AGENT_BIN" --config "$AGENT_CONFIG_PATH" \
    >>"$LOCAL_AGENT_DAEMON_LOG" 2>&1 &
  LOCAL_AGENT_DAEMON_PID=$!
  # Give the daemon time to load config and install its SIGHUP handler;
  # otherwise the first force_reissue may signal it before the handler
  # is ready, masking the wait-path coverage we are trying to add.
  local attempt
  for attempt in $(seq 1 20); do
    if ! kill -0 "$LOCAL_AGENT_DAEMON_PID" 2>/dev/null; then
      tail -n 80 "$LOCAL_AGENT_DAEMON_LOG" >>"$RUN_LOG" 2>&1 || true
      LOCAL_AGENT_DAEMON_PID=""
      fail "bootroot-agent daemon exited during startup; see $LOCAL_AGENT_DAEMON_LOG"
    fi
    if grep -q "Profile .* daemon enabled" "$LOCAL_AGENT_DAEMON_LOG" 2>/dev/null; then
      return 0
    fi
    sleep 0.5
  done
  tail -n 80 "$LOCAL_AGENT_DAEMON_LOG" >>"$RUN_LOG" 2>&1 || true
  fail "bootroot-agent daemon failed to become ready; see $LOCAL_AGENT_DAEMON_LOG"
}

stop_local_bootroot_agent_daemon() {
  if [ -z "$LOCAL_AGENT_DAEMON_PID" ]; then
    return 0
  fi
  if kill -0 "$LOCAL_AGENT_DAEMON_PID" 2>/dev/null; then
    kill "$LOCAL_AGENT_DAEMON_PID" 2>/dev/null || true
    local attempt
    for attempt in $(seq 1 10); do
      if ! kill -0 "$LOCAL_AGENT_DAEMON_PID" 2>/dev/null; then
        break
      fi
      sleep 0.2
    done
    kill -9 "$LOCAL_AGENT_DAEMON_PID" 2>/dev/null || true
  fi
  wait "$LOCAL_AGENT_DAEMON_PID" 2>/dev/null || true
  LOCAL_AGENT_DAEMON_PID=""
}

force_reissue_remote() {
  rm -f "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.crt" "$REMOTE_CERTS_DIR/${REMOTE_SERVICE}.key"
}

force_reissue_all_services() {
  force_reissue_for_service "$EDGE_SERVICE"
  force_reissue_for_service "$WEB_SERVICE"
  force_reissue_remote
}

verify_service_with_retry() {
  local service="$1"
  local agent_config="${2:-$AGENT_CONFIG_PATH}"
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

# Asserts the responder-hmac rotate completed within the wall-clock
# budget for the active OBA deployment.  The two thresholds together
# distinguish the active sidecar restart route from the host-daemon
# polling fallback and catch silent regressions in either path:
#
#   sidecar:     `bootroot rotate` actively restarts the sidecar
#                container, so the rendered file must contain the new
#                HMAC well below the polling fallback window.  A
#                threshold above `static_secret_render_interval`
#                (=30s) would let a regression where the active
#                restart silently no-ops sneak through, because rotate
#                would still succeed via polling.
#
#   host-daemon: `bootroot rotate` cannot signal the operator daemon,
#                so propagation must wait for the polling fallback.
assert_responder_hmac_rotate_latency() {
  local elapsed_secs="$1"
  local limit_secs route
  case "$OBA_DEPLOYMENT" in
    sidecar)
      limit_secs="$SIDECAR_ROTATE_LATENCY_LIMIT_SECS"
      route="active sidecar restart"
      ;;
    host-daemon)
      limit_secs="$HOST_DAEMON_RENDER_TIMEOUT_SECS"
      route="polling fallback (static_secret_render_interval)"
      ;;
    *)
      fail "assert_responder_hmac_rotate_latency: unknown OBA_DEPLOYMENT=$OBA_DEPLOYMENT"
      ;;
  esac
  printf '[lifecycle] responder-hmac rotate elapsed=%ss limit=%ss route=%s deployment=%s\n' \
    "$elapsed_secs" "$limit_secs" "$route" "$OBA_DEPLOYMENT" >>"$RUN_LOG"
  if [ "$elapsed_secs" -gt "$limit_secs" ]; then
    fail "responder-hmac rotate took ${elapsed_secs}s, exceeding the ${limit_secs}s budget for OBA_DEPLOYMENT=${OBA_DEPLOYMENT} (expected route: ${route})"
  fi
}

assert_fingerprint_changed() {
  local service="$1"
  local before_label="$2"
  local after_label="$3"
  local before_fp after_fp
  before_fp="$(fingerprint_of "$service" "$before_label")"
  after_fp="$(fingerprint_of "$service" "$after_label")"
  [ -n "$before_fp" ] || fail "Missing fingerprint for $service/$before_label"
  [ -n "$after_fp" ] || fail "Missing fingerprint for $service/$after_label"
  if [ "$before_fp" = "$after_fp" ]; then
    fail "Fingerprint did not change for $service ($before_label -> $after_label)"
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
      --openbao-url "http://${STEPCA_HOST_IP}:8200" \
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

run_rotations_with_verification() {
  log_phase "rotate-openbao-recovery"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
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
  local rotate_start_epoch rotate_end_epoch rotate_elapsed_secs
  rotate_start_epoch="$(date +%s)"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
    --auth-mode approle \
    --approle-role-id "$RUNTIME_ROTATE_ROLE_ID" \
    --approle-secret-id "$RUNTIME_ROTATE_SECRET_ID" \
    --yes \
    responder-hmac >>"$RUN_LOG" 2>&1
  rotate_end_epoch="$(date +%s)"
  rotate_elapsed_secs=$((rotate_end_epoch - rotate_start_epoch))
  assert_responder_hmac_rotate_latency "$rotate_elapsed_secs"
  run_remote_bootstrap
  force_reissue_all_services
  run_verify_pair "after-responder-hmac"
  assert_fingerprint_changed "$EDGE_SERVICE" "initial" "after-responder-hmac"
  assert_fingerprint_changed "$WEB_SERVICE" "initial" "after-responder-hmac"
  assert_fingerprint_changed "$REMOTE_SERVICE" "initial" "after-responder-hmac"

  log_phase "rotate-stepca-password"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
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

  log_phase "rotate-db"
  # Build admin DSN from ca.json so the password matches the current
  # state (it may have been rotated by `init`).
  local db_admin_dsn
  db_admin_dsn="$(jq -r '.db.dataSource // empty' "$SECRETS_DIR/config/ca.json")"
  if [ -z "${db_admin_dsn:-}" ]; then
    db_admin_dsn="postgresql://step:step-pass@127.0.0.1:${POSTGRES_HOST_PORT:-5432}/stepca?sslmode=disable"
  else
    # Replace the Docker-internal host:port with the host-side mapping.
    db_admin_dsn="$(echo "$db_admin_dsn" \
      | sed "s|@postgres:5432|@127.0.0.1:${POSTGRES_HOST_PORT:-5432}|")"
  fi
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
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

  log_phase "rotate-ca-key"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
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

  log_phase "rotate-ca-key-full"
  run_bootroot rotate \
    --compose-file "$COMPOSE_FILE" \
    --openbao-url "http://${STEPCA_HOST_IP}:8200" \
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
  "state_file": "${ROOT_DIR}/state.json",
  "agent_config_path": "${AGENT_CONFIG_PATH}",
  "services": ["${EDGE_SERVICE}", "${WEB_SERVICE}", "${REMOTE_SERVICE}"]
}
EOF
}

main() {
  mkdir -p "$ARTIFACT_DIR" "$WORKSPACE_DIR" "$CERT_META_DIR" "$REMOTE_DIR" "$REMOTE_CERTS_DIR"
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  trap cleanup EXIT
  trap 'on_error $LINENO' ERR

  case "$OBA_TOPOLOGY" in
    default|custom-project|openbao-missing|external-openbao) ;;
    *) fail "Unsupported OBA_TOPOLOGY: $OBA_TOPOLOGY (expected: default | custom-project | openbao-missing | external-openbao)" ;;
  esac

  if [ "$OBA_TOPOLOGY" = "custom-project" ]; then
    # Must be exported BEFORE install_infra so the bootroot-openbao
    # container picks up the project label this topology asserts on.
    export COMPOSE_PROJECT_NAME="$CUSTOM_COMPOSE_PROJECT"
    printf '[lifecycle] custom-project topology: COMPOSE_PROJECT_NAME=%s\n' \
      "$COMPOSE_PROJECT_NAME" >>"$RUN_LOG"
  fi

  ensure_prerequisites
  configure_resolution_mode
  compose_down
  reset_stepca_materials_for_e2e
  install_infra
  write_agent_config
  run_bootstrap_chain

  [ -x "$BOOTROOT_AGENT_BIN" ] || cargo build --bin bootroot-agent >>"$RUN_LOG" 2>&1
  export PATH="$(dirname "$BOOTROOT_AGENT_BIN"):$PATH"

  case "$OBA_TOPOLOGY" in
    openbao-missing)
      log_phase "topology-openbao-missing"
      remove_openbao_container_for_missing_topology
      # Assert the full "container not found" i18n contract: the
      # symptom (`container not found`) AND both halves of the
      # remediation hint (`bootroot infra install` and
      # `--openbao-network`).  A regression that drops either half
      # of the remediation now fails the arm.  The em-dash that
      # joins the message in en.rs is intentionally not asserted on,
      # so a future tweak to that punctuation does not break this
      # arm.
      assert_service_oba_start_fails "$SIDECAR_OBA_SERVICE" \
        "container not found" \
        "bootroot infra install" \
        "--openbao-network" \
        -- \
        --compose-file "$COMPOSE_FILE"
      write_manifest
      return 0
      ;;
    external-openbao)
      log_phase "topology-external-openbao"
      run_external_openbao_topology_assertions "$SIDECAR_OBA_SERVICE"
      write_manifest
      return 0
      ;;
  esac

  apply_dns_aliases
  prepare_stepca_validation_targets

  start_service_oba "$SIDECAR_OBA_SERVICE"

  if [ "$OBA_TOPOLOGY" = "custom-project" ] && [ "$OBA_DEPLOYMENT" = "sidecar" ]; then
    assert_sidecar_compose_project "$SIDECAR_OBA_CONTAINER" "$CUSTOM_COMPOSE_PROJECT"
  fi

  copy_remote_materials
  log_phase "remote-bootstrap-initial"
  run_remote_bootstrap

  run_verify_pair "initial"
  start_local_bootroot_agent_daemon
  run_rotations_with_verification
  stop_local_bootroot_agent_daemon

  log_phase "assert-openbao-audit-log"
  assert_openbao_audit_log

  write_manifest
}

main "$@"
