#!/usr/bin/env bash
set -euo pipefail

# Extended-tier registrar renewal scenario.  This deliberately waits beyond
# the original leaf lifetimes, so it belongs to the scheduled/manual suite
# rather than the pull-request Docker matrix.  It proves renewal and the
# absence of AppRole reads; it does not model a compromised bootroot host,
# control plane, or request handler.
#
# Launcher contract: no arguments; BOOTROOT_PROJECT_DIR, BOOTROOT_BIN, and
# ARTIFACT_DIR are absolute existing paths. RUN_TOKEN scopes every resource.

[ "$#" -eq 0 ] || { echo "run-registrar-endurance.sh takes no positional arguments" >&2; exit 2; }

# Keep setup, renewal, and post-expiry assertions inside the extended job's
# budget. On expiry, `timeout` sends TERM and the inner shell enters cleanup.
# Cleanup has a separate five-minute grace period: `compose down` alone is
# bounded at 90 seconds, and teardown must reach its leftover checks rather
# than being cut off before it can remove a failed run's resources.
if [ "${REGISTRAR_ENDURANCE_INNER:-}" != "1" ]; then
  command -v timeout >/dev/null 2>&1 || {
    echo "run-registrar-endurance.sh requires GNU timeout for its 20-minute deadline" >&2
    exit 2
  }
  exec timeout --signal=TERM --kill-after=5m 20m \
    env REGISTRAR_ENDURANCE_INNER=1 "$0"
fi

CURRENT_PHASE=startup
RUN_LOG=
PHASE_LOG=
RUN_ROOT=
WORK_DIR=
SUPERVISOR_PID=
HTTP01_IMAGE_BUILT=0
AUDIT_TMPFS_MOUNTED=0
TIMED_OUT=0

fail() { printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$1" >>"$RUN_LOG" 2>/dev/null || true; printf '[registrar-endurance][%s] FAIL %s\n' "$CURRENT_PHASE" "$1" >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/registrar-docker.sh"
# shellcheck source=lib/leftovers.sh
. "$SCRIPT_DIR/lib/leftovers.sh"
. "$SCRIPT_DIR/lib/ports.sh"

registrar_docker_require_launcher_contract
BOOTROOT_PROJECT_DIR="$(cd "$BOOTROOT_PROJECT_DIR" && pwd)"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
RUN_LOG="$ARTIFACT_DIR/run.log"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_TOKEN="$(registrar_docker_run_token)"
SCENARIO_SLUG=endurance
INSTANCE="$(registrar_docker_instance_name "registrar-${SCENARIO_SLUG}-" "$RUN_TOKEN")"
BOOTROOT_AGENT_BIN="$(dirname "$BOOTROOT_BIN")/bootroot-agent"
DRIVER="$BOOTROOT_PROJECT_DIR/tests/e2e/registrar/redteam_client.py"
ENDPOINT_NAME="001.bootroot-registrar-endpoint.endurance.trusted.domain"
CLIENT_NAME="001.bootroot-registrar.endurance.trusted.domain"

log_phase() { CURRENT_PHASE="$1"; printf '{"ts":"%s","phase":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >>"$PHASE_LOG"; printf '[registrar-endurance][%s]\n' "$1" | tee -a "$RUN_LOG"; }
pass() { printf '[registrar-endurance][%s] PASS %s\n' "$CURRENT_PHASE" "$1" | tee -a "$RUN_LOG"; }
require() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }
root_digest_file() { sudo -n sh -c 'if command -v sha256sum >/dev/null; then sha256sum "$1" | awk "{print \$1}"; else shasum -a 256 "$1" | awk "{print \$1}"; fi' _ "$1"; }
root_certificate_der_digest() { if command -v sha256sum >/dev/null; then sudo -n openssl x509 -in "$1" -outform DER | sha256sum | awk '{print $1}'; else sudo -n openssl x509 -in "$1" -outform DER | shasum -a 256 | awk '{print $1}'; fi; }
certificate_not_after_epoch() { sudo -n openssl x509 -in "$1" -noout -enddate | python3 -c 'import datetime, sys; value=sys.stdin.read().strip().split("=", 1)[1]; print(int(datetime.datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=datetime.timezone.utc).timestamp()))'; }

timeout_report() {
  TIMED_OUT=1
  printf 'registrar-endurance timed out after the 20-minute scenario deadline; retained artifacts in %s\n' "$ARTIFACT_DIR" | tee -a "$RUN_LOG" >&2
}

cleanup() {
  local status=$?
  local cleanup_status=0
  log_phase cleanup
  [ "$TIMED_OUT" -eq 0 ] || printf '{"timeout":"20m","artifacts":"%s"}\n' "$ARTIFACT_DIR" >"$ARTIFACT_DIR/timeout.json" || true
  registrar_docker_stop_supervisor
  # Keep all teardown failures visible: a test pass is not a clean scenario
  # if it leaves run-scoped Docker state, a mounted tmpfs, or its responder
  # image on the host. `teardown_instance` still tries each resource class
  # after `compose down` fails, so the following leftover queries are useful.
  if ! teardown_instance; then
    echo "[registrar-endurance][cleanup] teardown of ${INSTANCE} failed; see ${RUN_LOG}" >&2
    cleanup_status=1
  fi
  if [ "$HTTP01_IMAGE_BUILT" -eq 1 ] && ! docker image rm -f "$HTTP01_IMAGE" >>"$RUN_LOG" 2>&1; then
    echo "[registrar-endurance][cleanup] could not remove ${HTTP01_IMAGE}; see ${RUN_LOG}" >&2
    cleanup_status=1
  fi
  # shellcheck disable=SC2024 # the invoking user owns the scenario log.
  if [ "$AUDIT_TMPFS_MOUNTED" -eq 1 ] && ! sudo -n umount "$AUDIT_DIR" >>"$RUN_LOG" 2>&1; then
    echo "[registrar-endurance][cleanup] could not unmount ${AUDIT_DIR}; see ${RUN_LOG}" >&2
    cleanup_status=1
  fi
  if [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ]; then
    # shellcheck disable=SC2024 # the invoking user owns the scenario log.
    if ! sudo -n rm -rf "$RUN_ROOT" >>"$RUN_LOG" 2>&1 && ! rm -rf "$RUN_ROOT" >>"$RUN_LOG" 2>&1; then
      echo "[registrar-endurance][cleanup] could not remove ${RUN_ROOT}; see ${RUN_LOG}" >&2
      cleanup_status=1
    fi
  fi
  report_project_leftovers "$INSTANCE" "registrar-endurance cleanup" || cleanup_status=1
  report_project_network_leftovers || cleanup_status=1
  if [ "$HTTP01_IMAGE_BUILT" -eq 1 ] && ! assert_image_removed; then
    cleanup_status=1
  fi
  if [ "$AUDIT_TMPFS_MOUNTED" -eq 1 ] && [ -d "$AUDIT_DIR" ] && mountpoint -q "$AUDIT_DIR"; then
    echo "[registrar-endurance][cleanup] tmpfs remains mounted at ${AUDIT_DIR}" >&2
    cleanup_status=1
  fi
  if [ -n "$RUN_ROOT" ] && [ -e "$RUN_ROOT" ]; then
    echo "[registrar-endurance][cleanup] run root survived: ${RUN_ROOT}" >&2
    cleanup_status=1
  fi
  exit_with_cleanup_status "$status" "$cleanup_status"
}

teardown_instance() {
  local ids status=0
  if [ -n "$WORK_DIR" ] && [ -f "$WORK_DIR/docker-compose.deploy.yml" ]; then
    registrar_docker_compose ps >"$ARTIFACT_DIR/compose-ps.log" 2>&1 || true
    registrar_docker_compose logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
    # Early failures precede `init`, so its generated Compose environment is
    # absent. These values only satisfy interpolation while `down` resolves
    # the copied manifest; it never creates or reconfigures a service.
    timeout --kill-after=10 90 env BOOTROOT_INSTANCE="$INSTANCE" POSTGRES_PASSWORD=cleanup-only GRAFANA_ADMIN_PASSWORD=cleanup-only docker compose -p "$INSTANCE" -f "$WORK_DIR/docker-compose.deploy.yml" down --volumes --remove-orphans >>"$RUN_LOG" 2>&1 || status=1
  fi
  if ids="$(docker ps -aq --filter "label=com.docker.compose.project=${INSTANCE}" 2>>"$RUN_LOG")"; then
    for id in $ids; do docker rm -f "$id" >>"$RUN_LOG" 2>&1 || status=1; done
  else
    status=1
  fi
  if ids="$(docker volume ls -q --filter "label=com.docker.compose.project=${INSTANCE}" 2>>"$RUN_LOG")"; then
    for id in $ids; do docker volume rm -f "$id" >>"$RUN_LOG" 2>&1 || status=1; done
  else
    status=1
  fi
  if ids="$(docker network ls -q --filter "label=com.docker.compose.project=${INSTANCE}" 2>>"$RUN_LOG")"; then
    for id in $ids; do docker network rm "$id" >>"$RUN_LOG" 2>&1 || status=1; done
  else
    status=1
  fi
  return "$status"
}

report_project_network_leftovers() {
  local networks
  if ! networks="$(docker network ls -q --filter "label=com.docker.compose.project=${INSTANCE}" 2>>"$RUN_LOG")"; then
    echo "[registrar-endurance cleanup] cannot list networks of project ${INSTANCE}; leftovers were not checked for" >&2
    return 1
  fi
  [ -z "$networks" ] || {
    echo "[registrar-endurance cleanup] networks survived for project ${INSTANCE}: ${networks}" >&2
    return 1
  }
}

assert_image_removed() {
  local image_ids
  if ! image_ids="$(docker image ls -q "$HTTP01_IMAGE" 2>>"$RUN_LOG")"; then
    echo "[registrar-endurance cleanup] cannot check whether ${HTTP01_IMAGE} survived" >&2
    return 1
  fi
  [ -z "$image_ids" ] || {
    echo "[registrar-endurance cleanup] image survived: ${HTTP01_IMAGE}" >&2
    return 1
  }
}

on_timeout() { timeout_report; exit 124; }

prepare_workspace() {
  registrar_docker_prepare_run_root "$SCENARIO_SLUG"
  # The two root-owned AppRole control credentials the renewal trace watches
  # are this scenario's alone, and so is the payload its post-expiry
  # unknown-operation exchange sends.
  APPROLES_DIR="$RUN_ROOT/approle-control"; EMPTY_PAYLOAD="$RUN_ROOT/empty.json"
  mkdir -p "$APPROLES_DIR"
  sudo -n chown 0:0 "$APPROLES_DIR"; sudo -n chmod 0700 "$APPROLES_DIR"
}

write_configs() {
  local body="$RUN_ROOT/provisioning.body"
  cat >"$body" <<'EOF'
schema_version = 1
domain = "trusted.domain"

[components.review]
multiplicity = "one-per-deployment"
cert_group = 3000
reload = { kind = "docker-restart", target = "review" }
EOF
  registrar_docker_write_configs "$body"
}

patch_duration_template() {
  local template="$WORK_DIR/secrets/templates/ca.json.ctmpl" rendered="$WORK_DIR/secrets/config/ca.json" sidecar
  sudo -n python3 - "$template" <<'PY'
import re
import sys

path = sys.argv[1]
source = open(path, encoding="utf-8").read()
matches = list(re.finditer(r'("defaultTLSCertDuration"\s*:\s*")([^"]+)(")', source))
if len(matches) != 1:
    raise SystemExit(f"expected one ACME defaultTLSCertDuration in {path}, found {len(matches)}")
match = matches[0]
updated = source[:match.start(2)] + "6m" + source[match.end(2):]
open(path, "w", encoding="utf-8").write(updated)
PY
  sidecar="${INSTANCE}-openbao-agent-stepca"
  docker restart "$sidecar" >>"$RUN_LOG" 2>&1 || fail "could not restart run-scoped Step CA OpenBao Agent sidecar ${sidecar}"
  for _ in $(seq 1 60); do sudo -n jq -e '.authority.provisioners[] | select(.type == "ACME" and .name == "acme") | .claims.defaultTLSCertDuration == "6m"' "$rendered" >/dev/null 2>&1 && break; sleep 1; done
  sudo -n jq -e '.authority.provisioners[] | select(.type == "ACME" and .name == "acme") | .claims.defaultTLSCertDuration == "6m"' "$rendered" >/dev/null || fail "Step CA sidecar did not render the 6-minute copied template"
  registrar_docker_compose restart step-ca >>"$RUN_LOG" 2>&1 || fail "could not restart Step CA onto rendered 6-minute configuration"
  for _ in $(seq 1 60); do curl -kfsS "https://localhost:${PORT_STEPCA}/health" >/dev/null 2>&1 && break; sleep 1; done
  curl -kfsS "https://localhost:${PORT_STEPCA}/health" >/dev/null || fail "Step CA did not become ready after the template and sidecar sequence"
  sudo -n cp "$template" "$ARTIFACT_DIR/ca.json.ctmpl"; sudo -n cp "$rendered" "$ARTIFACT_DIR/ca.json"
  sudo -n chown "$(id -u):$(id -g)" "$ARTIFACT_DIR/ca.json.ctmpl" "$ARTIFACT_DIR/ca.json"
  pass "copied template, its own sidecar render, and Step CA restart use a 6-minute leaf lifetime"
}

set_internal_cadence() {
  local internal="$WORK_DIR/secrets/registrar-internal/agent.toml"
  sudo -n tee -a "$internal" >/dev/null <<'EOF'

[profiles.daemon]
check_interval = "5s"
renew_before = "4m"
check_jitter = "0s"
EOF
  sudo -n grep -q 'check_interval = "5s"' "$internal" && sudo -n grep -q 'renew_before = "4m"' "$internal" && sudo -n grep -q 'check_jitter = "0s"' "$internal" || fail "could not set the rendered internal renewal cadence"
  sudo -n cp "$internal" "$ARTIFACT_DIR/registrar-internal-agent.toml"; sudo -n chown "$(id -u):$(id -g)" "$ARTIFACT_DIR/registrar-internal-agent.toml"
}

prepare_anchor_pin() {
  PIN_FILE="$SURFACE_DIR/registrar-endpoint-anchors.sha256"
  PINNED_ANCHOR_DIGEST="$(root_certificate_der_digest "$ROOT_CA")"
  sudo -n sh -c 'printf "%s\n" "$1" >"$2"; chown 0:0 "$2"; chmod 600 "$2"' _ "$PINNED_ANCHOR_DIGEST" "$PIN_FILE"
  PIN_CONTENT_DIGEST="$(root_digest_file "$PIN_FILE")"
  printf '%s\n' "$PINNED_ANCHOR_DIGEST" >"$ARTIFACT_DIR/pinned-anchor-digest.txt"
  printf '%s\n' "$PIN_CONTENT_DIGEST" >"$ARTIFACT_DIR/pin-content-digest.txt"
}

create_approle_control() {
  local policy role policy_body role_id secret_id
  policy="registrar-endurance-control-${RUN_TOKEN}"
  role="$policy"
  printf -v policy_body 'path "%s/data/%s" { capabilities = ["read"] }\npath "%s/data/%s" { capabilities = ["read"] }' "$KV_MOUNT" "$AGENT_EAB_PATH" "$KV_MOUNT" "$RESPONDER_HMAC_PATH"
  jq -n --arg policy "$policy_body" '{policy: $policy}' >"$RUN_ROOT/approle-policy.json"
  sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" -X POST --data @"$RUN_ROOT/approle-policy.json" "$OPENBAO_URL/v1/sys/policies/acl/$policy" >/dev/null || fail "could not create the AppRole control policy"
  jq -n --arg policy "$policy" '{token_policies: [$policy]}' >"$RUN_ROOT/approle-role.json"
  sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" -X POST --data @"$RUN_ROOT/approle-role.json" "$OPENBAO_URL/v1/auth/approle/role/$role" >/dev/null || fail "could not create the AppRole control role"
  role_id="$(sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" "$OPENBAO_URL/v1/auth/approle/role/$role/role-id" | jq -er '.data.role_id')" || fail "could not read the AppRole control role_id"
  secret_id="$(sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" -X POST "$OPENBAO_URL/v1/auth/approle/role/$role/secret-id" | jq -er '.data.secret_id')" || fail "could not create the AppRole control secret_id"
  printf '%s\n' "$role_id" | sudo -n tee "$APPROLES_DIR/role_id" >/dev/null; printf '%s\n' "$secret_id" | sudo -n tee "$APPROLES_DIR/secret_id" >/dev/null
  sudo -n chown 0:0 "$APPROLES_DIR/role_id" "$APPROLES_DIR/secret_id"; sudo -n chmod 0600 "$APPROLES_DIR/role_id" "$APPROLES_DIR/secret_id"
  ROLE_ID_PATH="$APPROLES_DIR/role_id"; SECRET_ID_PATH="$APPROLES_DIR/secret_id"
}

parse_watched_opens() {
  local trace_prefix="$1" output="$2"
  python3 - "$trace_prefix" "$ROLE_ID_PATH" "$SECRET_ID_PATH" >"$output" <<'PY'
import glob
import re
import sys

prefix, role_id, secret_id = sys.argv[1:]
watched = {role_id, secret_id}
pattern = re.compile(r'(?P<syscall>open|openat|openat2)\([^\"]*\"(?P<path>(?:\\.|[^\"])*)\".*\)\s+=\s+(?P<result>-?\d+)')
for filename in sorted(glob.glob(prefix + ".*")):
    pid = filename.rsplit(".", 1)[-1]
    with open(filename, encoding="utf-8", errors="replace") as trace:
        for line in trace:
            match = pattern.search(line)
            if not match:
                continue
            pathname = bytes(match.group("path"), "utf-8").decode("unicode_escape")
            result = int(match.group("result"))
            if pathname in watched and result >= 0:
                print(f"pid={pid} syscall={match.group('syscall')} pathname={pathname} result={result}")
PY
}

assert_control_trace() {
  local prefix="$ARTIFACT_DIR/control-trace"
  sudo -n strace -ff -e trace=open,openat,openat2 -o "$prefix" python3 - "$ROLE_ID_PATH" "$SECRET_ID_PATH" <<'PY' >>"$RUN_LOG" 2>&1
import sys
for path in sys.argv[1:]:
    with open(path, "rb") as stream:
        stream.read(1)
PY
  parse_watched_opens "$prefix" "$ARTIFACT_DIR/control-trace-matches.log"
  local count role_count secret_count
  count="$(wc -l <"$ARTIFACT_DIR/control-trace-matches.log" | tr -d ' ')"; role_count="$(grep -F "pathname=$ROLE_ID_PATH " "$ARTIFACT_DIR/control-trace-matches.log" | wc -l | tr -d ' ')"; secret_count="$(grep -F "pathname=$SECRET_ID_PATH " "$ARTIFACT_DIR/control-trace-matches.log" | wc -l | tr -d ' ')"
  [ "$count" = 2 ] && [ "$role_count" = 1 ] && [ "$secret_count" = 1 ] || { cat "$ARTIFACT_DIR/control-trace-matches.log" >>"$RUN_LOG"; fail "control trace did not report exactly one successful open for each watched AppRole path"; }
  pass "shared strace parser reports exactly two watched control opens and ignores unrelated opens"
}

start_daemon_trace() {
  # This test-only value is inert in the submitted binary. It makes the
  # documented temporary AppRole-routing mutation reproducible: that variant
  # reads exactly the two root-owned control paths that this trace watches.
  registrar_docker_start_supervisor \
    env BOOTROOT_REGISTRAR_ENDURANCE_APPROLE_DIR="$APPROLES_DIR" \
    strace -ff -e trace=open,openat,openat2 -o "$ARTIFACT_DIR/daemon-trace"
  registrar_docker_await_surface_material \
    "$SURFACE_DIR/registrar-client.crt" "$SURFACE_DIR/registrar-endpoint.crt"
}

record_original_leaves() {
  CLIENT_ORIGINAL_DIGEST="$(root_certificate_der_digest "$SURFACE_DIR/registrar-client.crt")"; CLIENT_ORIGINAL_EXPIRY="$(certificate_not_after_epoch "$SURFACE_DIR/registrar-client.crt")"
  ENDPOINT_ORIGINAL_DIGEST="$(root_certificate_der_digest "$SURFACE_DIR/registrar-endpoint.crt")"; ENDPOINT_ORIGINAL_EXPIRY="$(certificate_not_after_epoch "$SURFACE_DIR/registrar-endpoint.crt")"
  jq -n --arg client_digest "$CLIENT_ORIGINAL_DIGEST" --arg endpoint_digest "$ENDPOINT_ORIGINAL_DIGEST" --argjson client_not_after "$CLIENT_ORIGINAL_EXPIRY" --argjson endpoint_not_after "$ENDPOINT_ORIGINAL_EXPIRY" '{client: {der_sha256: $client_digest, not_after_epoch: $client_not_after}, endpoint: {der_sha256: $endpoint_digest, not_after_epoch: $endpoint_not_after}}' >"$ARTIFACT_DIR/original-leaves.json"
}

wait_until_after() {
  local label="$1" expiry="$2"
  while [ "$(date +%s)" -le "$expiry" ]; do sleep 1; done
  printf '%s crossed at %s (recorded notAfter epoch %s)\n' "$label" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$expiry" >>"$ARTIFACT_DIR/expiry-boundaries.log"
}

write_mint() {
  jq -n '{protocol_version:1,service_name:"review",delivery_mode:"RemoteBootstrap",host:"endurance",spec:{component:"review",service_name:"review",reload:"{ kind = \"docker-restart\", target = \"review\" }",cert_group:"3000"},wrap_ttl:60,idempotency_key:"endurance-post-expiry-mint"}' >"$RUN_ROOT/mint.json"
}

socket_mint() {
  sudo -n python3 "$DRIVER" --socket "$SOCKET_PATH" --pins "$PIN_FILE" --ca "$ROOT_CA" --cert "$SURFACE_DIR/registrar-client.crt" --key "$SURFACE_DIR/registrar-client.key" --endpoint-name "$ENDPOINT_NAME" --operation mint --payload "$RUN_ROOT/mint.json"
}

endpoint_peer_digest() {
  sudo -n python3 - "$SOCKET_PATH" "$ROOT_CA" "$SURFACE_DIR/registrar-client.crt" "$SURFACE_DIR/registrar-client.key" "$ENDPOINT_NAME" <<'PY'
import hashlib
import socket
import ssl
import sys

sock_path, ca, cert, key, name = sys.argv[1:]
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
context.load_cert_chain(certfile=cert, keyfile=key)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
    raw.connect(sock_path)
    with context.wrap_socket(raw, server_hostname=name) as stream:
        print(hashlib.sha256(stream.getpeercert(binary_form=True)).hexdigest())
PY
}

assert_post_expiry_client() {
  wait_until_after client "$CLIENT_ORIGINAL_EXPIRY"
  local current
  current="$(root_certificate_der_digest "$SURFACE_DIR/registrar-client.crt")"
  [ "$current" != "$CLIENT_ORIGINAL_DIGEST" ] || fail "registrar client certificate did not change after its recorded original expiry"
  write_mint
  socket_mint >"$ARTIFACT_DIR/post-expiry-mint.json" 2>"$ARTIFACT_DIR/post-expiry-mint.err" || { cat "$ARTIFACT_DIR/post-expiry-mint.err" >>"$RUN_LOG"; fail "socket mint failed after the original client certificate expiry"; }
  pass "socket mint succeeds with a renewed registrar client leaf after its recorded original expiry"
}

assert_post_expiry_endpoint() {
  wait_until_after endpoint "$ENDPOINT_ORIGINAL_EXPIRY"
  local live_digest pin_content pinned_anchor
  live_digest="$(endpoint_peer_digest)"
  [ "$live_digest" != "$ENDPOINT_ORIGINAL_DIGEST" ] || fail "live endpoint leaf did not change after its recorded original expiry"
  pin_content="$(root_digest_file "$PIN_FILE")"; pinned_anchor="$(sudo -n cat "$PIN_FILE" | tr -d '[:space:]')"
  [ "$pin_content" = "$PIN_CONTENT_DIGEST" ] && [ "$pinned_anchor" = "$PINNED_ANCHOR_DIGEST" ] || fail "endpoint anchor pin changed during renewal"
  printf '{}' >"$EMPTY_PAYLOAD"
  sudo -n python3 "$DRIVER" --socket "$SOCKET_PATH" --pins "$PIN_FILE" --ca "$ROOT_CA" --cert "$SURFACE_DIR/registrar-client.crt" --key "$SURFACE_DIR/registrar-client.key" --endpoint-name "$ENDPOINT_NAME" --operation enumerate --payload "$EMPTY_PAYLOAD" --expect-unknown-operation >"$ARTIFACT_DIR/post-expiry-endpoint.out" 2>"$ARTIFACT_DIR/post-expiry-endpoint.err" || { cat "$ARTIFACT_DIR/post-expiry-endpoint.err" >>"$RUN_LOG"; fail "unchanged anchor pin did not accept the renewed endpoint leaf"; }
  jq -n --arg live_endpoint_der_sha256 "$live_digest" --arg pin_content_sha256 "$pin_content" --arg pinned_anchor_sha256 "$pinned_anchor" '{live_endpoint_der_sha256: $live_endpoint_der_sha256, pin_content_sha256: $pin_content_sha256, pinned_anchor_sha256: $pinned_anchor_sha256}' >"$ARTIFACT_DIR/post-expiry-endpoint.json"
  pass "unchanged root-anchor pin accepts the renewed endpoint leaf after its recorded original expiry"
}

assert_daemon_trace() {
  # The trace has to cover the whole renewal window and be flushed before it
  # is read, so the daemon is stopped here rather than left to cleanup.
  registrar_docker_stop_supervisor
  parse_watched_opens "$ARTIFACT_DIR/daemon-trace" "$ARTIFACT_DIR/daemon-trace-matches.log"
  if [ -s "$ARTIFACT_DIR/daemon-trace-matches.log" ]; then
    cat "$ARTIFACT_DIR/daemon-trace-matches.log" >>"$RUN_LOG"
    fail "daemon renewal trace opened an AppRole control credential path"
  fi
  pass "daemon trace covers the renewal window and contains no watched AppRole credential opens"
}

main() {
  : >"$RUN_LOG"; : >"$PHASE_LOG"; trap cleanup EXIT; trap on_timeout TERM
  log_phase validate
  for command in docker jq curl mountpoint openssl python3 sudo strace timeout; do require "$command"; done
  sudo -n true >/dev/null 2>&1 || fail "passwordless sudo is required for the root-owned registrar socket scenario"
  [ -x "$BOOTROOT_AGENT_BIN" ] || fail "bootroot-agent matching BOOTROOT_BIN is not executable"
  [ -f "$DRIVER" ] || fail "registrar external client wrapper is missing"

  log_phase deployment
  prepare_workspace
  registrar_docker_allocate_ports
  write_configs
  registrar_docker_build_and_initialize "$SCENARIO_SLUG"
  pass "initialized an isolated live TLS OpenBao deployment"
  registrar_docker_load_openbao_paths
  registrar_docker_apply_endpoint_dns_alias "$CLIENT_NAME" "$ENDPOINT_NAME"
  log_phase overrides
  patch_duration_template; set_internal_cadence
  registrar_docker_write_daemon_config
  prepare_anchor_pin; create_approle_control; assert_control_trace
  log_phase renewal-window
  start_daemon_trace; record_original_leaves; assert_post_expiry_client; assert_post_expiry_endpoint; assert_daemon_trace
  log_phase "done"
  pass "registrar endurance scenario completed"
}

main
