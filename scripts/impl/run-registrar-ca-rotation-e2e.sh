#!/usr/bin/env bash
set -euo pipefail

# Docker-backed full CA rotation on a registrar endpoint host. The endpoint
# daemon runs on the `init`-rendered internal config with the deployment root
# pinned, and `rotate ca-key --full` has to carry the endpoint across: widen
# the pin file in Phase 3, move both surface leaves in Phase 5 through the
# daemon's reload, and in Phase 6 prove the narrowed client trust took effect
# before narrowing the pin file. The first run passes `--skip finalize`, which
# on an endpoint host pauses before Phase 6 with the rotation state kept; the
# mid-rotation assertions run there, and a second run resumes and finishes.
#
# Launcher contract: no arguments; BOOTROOT_PROJECT_DIR, BOOTROOT_BIN, and
# ARTIFACT_DIR are absolute existing paths. RUN_TOKEN only scopes resources.

[ "$#" -eq 0 ] || { echo "run-registrar-ca-rotation-e2e.sh takes no positional arguments" >&2; exit 2; }

CURRENT_PHASE=startup
RUN_LOG=
PHASE_LOG=
RUN_ROOT=
WORK_DIR=
SUPERVISOR_PID=
HTTP01_IMAGE_BUILT=0
AUDIT_TMPFS_MOUNTED=0
SCENARIO_STARTED_AT=
SCENARIO_STARTED_EPOCH=

fail() { printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$1" >>"$RUN_LOG" 2>/dev/null || true; printf '[registrar-ca-rotation][%s] FAIL %s\n' "$CURRENT_PHASE" "$1" >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/registrar-docker.sh"
. "$SCRIPT_DIR/lib/ports.sh"

registrar_docker_require_launcher_contract
BOOTROOT_PROJECT_DIR="$(cd "$BOOTROOT_PROJECT_DIR" && pwd)"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
RUN_LOG="$ARTIFACT_DIR/run.log"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_TOKEN="$(registrar_docker_run_token)"
SCENARIO_SLUG=carotation
INSTANCE="$(registrar_docker_instance_name "registrar-${SCENARIO_SLUG}-" "$RUN_TOKEN")"
BOOTROOT_AGENT_BIN="$(dirname "$BOOTROOT_BIN")/bootroot-agent"
DRIVER="$BOOTROOT_PROJECT_DIR/tests/e2e/registrar/redteam_client.py"
ENDPOINT_NAME="001.bootroot-registrar-endpoint.${SCENARIO_SLUG}.trusted.domain"
CLIENT_NAME="001.bootroot-registrar.${SCENARIO_SLUG}.trusted.domain"
INTERNAL_NAME="001.bootroot-registrar-internal.${SCENARIO_SLUG}.trusted.domain"
PIN_COMMENT="# registrar endpoint anchors, pinned by the ca-rotation scenario"

log_phase() { CURRENT_PHASE="$1"; printf '{"ts":"%s","phase":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >>"$PHASE_LOG"; printf '[registrar-ca-rotation][%s]\n' "$1" | tee -a "$RUN_LOG"; }
pass() { printf '[registrar-ca-rotation][%s] PASS %s\n' "$CURRENT_PHASE" "$1" | tee -a "$RUN_LOG"; }
require() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }
root_certificate_der_digest() { if command -v sha256sum >/dev/null; then sudo -n openssl x509 -in "$1" -outform DER | sha256sum | awk '{print $1}'; else sudo -n openssl x509 -in "$1" -outform DER | shasum -a 256 | awk '{print $1}'; fi; }

record_wall_clock() {
  local finished_at finished_epoch elapsed
  [ -n "$SCENARIO_STARTED_EPOCH" ] || return
  finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  finished_epoch="$(date +%s)"
  elapsed=$((finished_epoch - SCENARIO_STARTED_EPOCH))
  jq -n --arg started_at "$SCENARIO_STARTED_AT" --arg finished_at "$finished_at" --argjson elapsed_seconds "$elapsed" \
    '{started_at: $started_at, finished_at: $finished_at, elapsed_seconds: $elapsed_seconds}' >"$ARTIFACT_DIR/wall-clock.json" || true
  printf '[registrar-ca-rotation] wall clock: %ss\n' "$elapsed" | tee -a "$RUN_LOG" || true
}

cleanup() {
  local status=$?
  log_phase cleanup
  record_wall_clock
  registrar_docker_stop_supervisor
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    registrar_docker_compose logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
    if command -v timeout >/dev/null 2>&1; then
      timeout --kill-after=10 90 env BOOTROOT_INSTANCE="$INSTANCE" docker compose -p "$INSTANCE" -f "$WORK_DIR/docker-compose.deploy.yml" down --volumes --remove-orphans >>"$RUN_LOG" 2>&1 || true
    else
      registrar_docker_compose down --volumes --remove-orphans >>"$RUN_LOG" 2>&1 || true
    fi
  fi
  [ "$HTTP01_IMAGE_BUILT" -eq 1 ] && docker image rm -f "$HTTP01_IMAGE" >>"$RUN_LOG" 2>&1 || true
  [ "$AUDIT_TMPFS_MOUNTED" -eq 1 ] && sudo -n umount "$AUDIT_DIR" >>"$RUN_LOG" 2>&1 || true
  [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ] && { sudo -n rm -rf "$RUN_ROOT" >>"$RUN_LOG" 2>&1 || rm -rf "$RUN_ROOT" 2>/dev/null || true; }
  exit "$status"
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

# The paths the rotation reads and writes, all under the run root. The socket
# unit is this scenario's own: the supervisor binds the socket at a run-scoped
# path, and the rotation dials whatever `ListenStream=` it is pointed at, just
# as `registrar capabilities --socket-unit` reports it.
set_rotation_paths() {
  SECRETS="$WORK_DIR/secrets"
  PIN_FILE="$SURFACE_DIR/registrar-endpoint-anchors.sha256"
  ROTATION_STATE="$WORK_DIR/rotation-state.json"
  RETIRED_DIR="$SECRETS/registrar-client-retired"
  SOCKET_UNIT="$RUN_ROOT/bootroot-registrar.socket"
  SCENARIO_COPY="$RUN_ROOT/scenario-client-copy"
  printf '[Socket]\nListenStream=%s\n' "$SOCKET_PATH" >"$SOCKET_UNIT"
}

# The provisioning tool's job, done here the way the endurance arm does it:
# pin the deployment root, root-owned 0600, with a comment the rotation has to
# keep.
prepare_anchor_pin() {
  OLD_ROOT_DIGEST="$(root_certificate_der_digest "$ROOT_CA")"
  sudo -n sh -c 'printf "%s\n%s\n" "$1" "$2" >"$3"; chown 0:0 "$3"; chmod 600 "$3"' _ "$PIN_COMMENT" "$OLD_ROOT_DIGEST" "$PIN_FILE"
  printf '%s\n' "$OLD_ROOT_DIGEST" >"$ARTIFACT_DIR/old-root-digest.txt"
  pass "pinned the deployment root in the endpoint pin file"
}

start_daemon() {
  registrar_docker_start_supervisor
  registrar_docker_await_surface_material \
    "$SURFACE_DIR/registrar-client.crt" "$SURFACE_DIR/registrar-endpoint.crt"
  pass "the endpoint daemon issued both surface leaves and is serving"
}

# The scenario's own copy of the pre-rotation client pair — not the rotation's
# preserved one — so the refusal after the rotation is observed independently
# of anything the rotation itself kept.
copy_scenario_client_pair() {
  sudo -n mkdir -p "$SCENARIO_COPY"
  sudo -n chmod 0700 "$SCENARIO_COPY"
  sudo -n cp "$SURFACE_DIR/registrar-client.crt" "$SCENARIO_COPY/client.crt"
  sudo -n cp "$SURFACE_DIR/registrar-client.key" "$SCENARIO_COPY/client.key"
}

# One exchange through the pin file with the named client pair. `ca` is what
# the driver verifies the presented chain with and asserts is pinned.
dial() {
  local cert="$1" key="$2" ca="$3" payload="$RUN_ROOT/empty.json"
  printf '{}' >"$payload"
  sudo -n python3 "$DRIVER" --socket "$SOCKET_PATH" --pins "$PIN_FILE" --ca "$ca" \
    --cert "$cert" --key "$key" --endpoint-name "$ENDPOINT_NAME" \
    --operation enumerate --payload "$payload" --expect-unknown-operation
}

rotate_ca_key() {
  local log="$1"; shift
  # shellcheck disable=SC2024 # the invoking user owns the artifact log.
  sudo -n env HOME="$HOME" BOOTROOT_LANG=en bash -c 'cd "$1" && shift && exec "$@"' _ "$WORK_DIR" \
    "$BOOTROOT_BIN" rotate --state-file "$WORK_DIR/state.json" \
    --compose-file "$WORK_DIR/docker-compose.deploy.yml" --openbao-url "$OPENBAO_URL" \
    --root-token-file "$TOKEN_FILE" --yes \
    ca-key --full --registrar-socket-unit "$SOCKET_UNIT" "$@" </dev/null >"$log" 2>&1
}

# One digest per newline-terminated line: grep terminates every line it
# prints, where `fold` would leave the last one bare and a single entry
# would then never equal "<digest> ".
pin_digests() { sudo -n grep -Ev '^[[:space:]]*(#|$)' "$PIN_FILE" | tr -d '[:blank:]\r'; }

assert_leaf_under_new_generation() {
  local leaf="$1" label="$2"
  # shellcheck disable=SC2024 # the invoking user owns the scenario log.
  sudo -n openssl verify -CAfile "$SECRETS/certs/root_ca.crt" \
    -untrusted "$SECRETS/certs/intermediate_ca.crt" "$leaf" >>"$RUN_LOG" 2>&1 ||
    fail "${label} does not verify under the new intermediate and root"
}

# The chain the endpoint presents on a live connection, read from the
# handshake. The connection verifies the chain against the new root alone, so
# it completes only if the presented chain is the new one.
live_presented_leaf() {
  sudo -n python3 - "$SOCKET_PATH" "$SECRETS/certs/root_ca.crt" "$SCENARIO_COPY/client.crt" "$SCENARIO_COPY/client.key" "$ENDPOINT_NAME" "$1" <<'PY'
import hashlib
import socket
import ssl
import sys

sock_path, ca, cert, key, name, out = sys.argv[1:]
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca)
context.load_cert_chain(certfile=cert, keyfile=key)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as raw:
    raw.settimeout(15)
    raw.connect(sock_path)
    with context.wrap_socket(raw, server_hostname=name) as stream:
        der = stream.getpeercert(binary_form=True)
open(out, "w", encoding="ascii").write(ssl.DER_cert_to_PEM_cert(der))
print(hashlib.sha256(der).hexdigest())
PY
}

run_paused_rotation() {
  local log="$ARTIFACT_DIR/rotate-skip-finalize.log"
  if ! rotate_ca_key "$log" --skip finalize; then
    tail -n 120 "$log" >>"$RUN_LOG" || true
    fail "rotate ca-key --full --skip finalize failed"
  fi
  grep -q "Rotation paused before Phase 6" "$log" || fail "the --skip finalize run did not pause before Phase 6"
  pass "the --skip finalize run stopped once Phase 5 was recorded"
}

assert_mid_rotation() {
  local new_root_digest digests live_digest disk_digest
  sudo -n test -s "$ROTATION_STATE" || fail "rotation-state.json was not kept by --skip finalize"
  [ "$(sudo -n jq -r '.phase' "$ROTATION_STATE")" = 5 ] || fail "the paused rotation did not record Phase 5"
  if ! sudo -n test -s "$RETIRED_DIR/client.crt" || ! sudo -n test -s "$RETIRED_DIR/client.key"; then
    fail "registrar-client-retired/ was not kept by --skip finalize"
  fi

  new_root_digest="$(root_certificate_der_digest "$SECRETS/certs/root_ca.crt")"
  [ "$new_root_digest" != "$OLD_ROOT_DIGEST" ] || fail "the full rotation did not replace the root"
  printf '%s\n' "$new_root_digest" >"$ARTIFACT_DIR/new-root-digest.txt"
  NEW_ROOT_DIGEST="$new_root_digest"
  digests="$(pin_digests | LC_ALL=C sort | tr '\n' ' ')"
  [ "$digests" = "$(printf '%s\n%s\n' "$OLD_ROOT_DIGEST" "$NEW_ROOT_DIGEST" | LC_ALL=C sort | tr '\n' ' ')" ] ||
    fail "between Phase 3 and Phase 6 the pin file must hold exactly the old and the new root: ${digests}"
  sudo -n grep -qxF "$PIN_COMMENT" "$PIN_FILE" || fail "the pin file lost its comment"
  pass "the pin file holds both roots between Phase 3 and Phase 6, with its comment"

  assert_leaf_under_new_generation "$SURFACE_DIR/registrar-endpoint.crt" "the endpoint server leaf on disk"
  assert_leaf_under_new_generation "$SURFACE_DIR/registrar-client.crt" "the registrar client leaf on disk"
  pass "both surface leaves on disk verify under the new intermediate and root"

  live_digest="$(live_presented_leaf "$RUN_ROOT/live-leaf.pem")" ||
    fail "a live connection verified against the new root alone did not complete"
  assert_leaf_under_new_generation "$RUN_ROOT/live-leaf.pem" "the leaf a live connection presents"
  disk_digest="$(root_certificate_der_digest "$SURFACE_DIR/registrar-endpoint.crt")"
  [ "$live_digest" = "$disk_digest" ] || fail "the live endpoint presents a leaf other than the one on disk"
  pass "the chain the endpoint presents on a live connection is the new one"

  dial "$SCENARIO_COPY/client.crt" "$SCENARIO_COPY/client.key" "$SECRETS/certs/root_ca.crt" \
    >"$ARTIFACT_DIR/old-pair-before-phase6.out" 2>"$ARTIFACT_DIR/old-pair-before-phase6.err" ||
    { cat "$ARTIFACT_DIR/old-pair-before-phase6.err" >>"$RUN_LOG"; fail "the pre-rotation client pair was refused before Phase 6 narrowed the trust"; }
  pass "the pre-rotation client pair is still accepted before Phase 6"
}

# OpenBao's TLS server certificate was issued under the old intermediate at
# `init`. A resumed rotation trusts the CA certificates now on disk — the new
# generation — and after Phase 6 so does the internal credential, so the
# listener certificate is re-issued under the new CA before the rotation
# resumes, as the operator documentation says to.
reissue_openbao_listener() {
  local log="$ARTIFACT_DIR/rotate-infra-cert.log"
  # shellcheck disable=SC2024 # the invoking user owns the artifact log.
  if ! sudo -n env HOME="$HOME" BOOTROOT_LANG=en bash -c 'cd "$1" && shift && exec "$@"' _ "$WORK_DIR" \
    "$BOOTROOT_BIN" rotate --state-file "$WORK_DIR/state.json" \
    --compose-file "$WORK_DIR/docker-compose.deploy.yml" --yes infra-cert </dev/null >"$log" 2>&1; then
    tail -n 80 "$log" >>"$RUN_LOG" || true
    fail "rotate infra-cert could not re-issue the OpenBao listener certificate under the new CA"
  fi
  pass "re-issued the OpenBao listener certificate under the new CA"
}

run_resumed_rotation() {
  local log="$ARTIFACT_DIR/rotate-resume.log"
  if ! rotate_ca_key "$log"; then
    tail -n 120 "$log" >>"$RUN_LOG" || true
    fail "the resumed rotate ca-key --full failed"
  fi
  grep -q "Resuming CA key rotation from phase 5" "$log" || fail "the second run did not resume after Phase 5"
  pass "the second run resumed at Phase 6 and completed"
}

write_mint() {
  jq -n '{protocol_version:1,service_name:"review",delivery_mode:"RemoteBootstrap",host:"carotation",spec:{component:"review",service_name:"review",reload:"{ kind = \"docker-restart\", target = \"review\" }",cert_group:"3000"},wrap_ttl:60,idempotency_key:"carotation-post-rotation-mint",agent_config_path:"/etc/review/agent.toml",role_id_path:"/var/lib/review/secrets/role_id",secret_id_path:"/var/lib/review/secrets/secret_id",eab_file_path:"/var/lib/review/secrets/eab.json",profile_cert_path:"/var/lib/review/certs/cert.pem",profile_key_path:"/var/lib/review/certs/key.pem",ca_bundle_path:"/var/lib/review/certs/ca-bundle.pem"}' >"$RUN_ROOT/mint.json"
}

assert_after_rotation() {
  local digests
  sudo -n test -e "$ROTATION_STATE" && fail "rotation-state.json survived Phase 7"
  sudo -n test -e "$RETIRED_DIR" && fail "registrar-client-retired/ survived Phase 7"
  pass "Phase 7 removed the rotation state and registrar-client-retired/"

  digests="$(pin_digests | tr '\n' ' ')"
  [ "$digests" = "${NEW_ROOT_DIGEST} " ] || fail "after the rotation the pin file must hold only the new root: ${digests}"
  sudo -n grep -qxF "$PIN_COMMENT" "$PIN_FILE" || fail "the pin file lost its comment"
  [ "$(sudo -n stat -c '%u:%g:%a' "$PIN_FILE")" = "0:0:600" ] || fail "the pin file's owner or mode changed"
  pass "the pin file holds only the new root, keeps its comment, owner and mode"

  write_mint
  # shellcheck disable=SC2024 # the invoking user owns the artifact files.
  sudo -n python3 "$DRIVER" --socket "$SOCKET_PATH" --pins "$PIN_FILE" --ca "$SECRETS/certs/root_ca.crt" \
    --cert "$SURFACE_DIR/registrar-client.crt" --key "$SURFACE_DIR/registrar-client.key" \
    --endpoint-name "$ENDPOINT_NAME" --operation mint --payload "$RUN_ROOT/mint.json" \
    >"$ARTIFACT_DIR/post-rotation-mint.json" 2>"$ARTIFACT_DIR/post-rotation-mint.err" ||
    { cat "$ARTIFACT_DIR/post-rotation-mint.err" >>"$RUN_LOG"; fail "a mint through the pin file with the re-issued client pair failed after the rotation"; }
  jq -e '.outcome == "first_mint"' "$ARTIFACT_DIR/post-rotation-mint.json" >/dev/null ||
    fail "the post-rotation mint did not complete: $(cat "$ARTIFACT_DIR/post-rotation-mint.json")"
  pass "a registrar client dial with the re-issued pair completes a mint after the rotation"

  if dial "$SCENARIO_COPY/client.crt" "$SCENARIO_COPY/client.key" "$SECRETS/certs/root_ca.crt" \
    >"$ARTIFACT_DIR/old-pair-after-rotation.out" 2>"$ARTIFACT_DIR/old-pair-after-rotation.err"; then
    fail "the pre-rotation client pair is still accepted after the rotation completed"
  fi
  pass "the pre-rotation client pair is refused after the rotation"
}

main() {
  : >"$RUN_LOG"; : >"$PHASE_LOG"; trap cleanup EXIT
  SCENARIO_STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  SCENARIO_STARTED_EPOCH="$(date +%s)"
  log_phase validate
  for command in docker jq curl openssl python3 sudo; do require "$command"; done
  sudo -n true >/dev/null 2>&1 || fail "passwordless sudo is required for the root-owned registrar socket scenario"
  [ -x "$BOOTROOT_AGENT_BIN" ] || fail "bootroot-agent matching BOOTROOT_BIN is not executable"
  [ -f "$DRIVER" ] || fail "registrar external client wrapper is missing"

  log_phase deployment
  registrar_docker_prepare_run_root "$SCENARIO_SLUG"
  registrar_docker_allocate_ports
  write_configs
  registrar_docker_build_and_initialize "$SCENARIO_SLUG"
  pass "initialized an isolated live TLS OpenBao deployment"
  registrar_docker_load_openbao_paths
  # Phase 4's tail re-issues the bootroot-internal credential over HTTP-01,
  # so its name is checked beside the two surface names: `init` attached all
  # three and nothing in this scenario recreates the responder.
  registrar_docker_assert_endpoint_dns_aliases "$CLIENT_NAME" "$ENDPOINT_NAME" "$INTERNAL_NAME"
  registrar_docker_prepare_daemon
  set_rotation_paths
  prepare_anchor_pin
  start_daemon
  copy_scenario_client_pair
  dial "$SCENARIO_COPY/client.crt" "$SCENARIO_COPY/client.key" "$ROOT_CA" \
    >"$ARTIFACT_DIR/old-pair-before-rotation.out" 2>"$ARTIFACT_DIR/old-pair-before-rotation.err" ||
    { cat "$ARTIFACT_DIR/old-pair-before-rotation.err" >>"$RUN_LOG"; fail "the endpoint did not accept its own client pair before the rotation"; }
  pass "the endpoint accepts its client pair before the rotation"

  log_phase rotate-skip-finalize
  run_paused_rotation
  log_phase mid-rotation
  assert_mid_rotation

  log_phase rotate-resume
  reissue_openbao_listener
  run_resumed_rotation
  log_phase after-rotation
  assert_after_rotation

  log_phase "done"; pass "registrar CA rotation scenario completed"
}
main
