#!/usr/bin/env bash
set -euo pipefail

# Docker-backed credential-boundary acceptance scenario for the registrar.
# Cargo owns ordinary wire round trips and the endurance arm owns renewal.
# This per-PR scenario owns the live OpenBao, process-boundary, audit, and
# root-owned inherited-socket assertions. The attacker receives only the
# manifest-defined read-only registrar-client bundle, never daemon material.
#
# Launcher contract: no arguments; BOOTROOT_PROJECT_DIR, BOOTROOT_BIN, and
# ARTIFACT_DIR are absolute existing paths. RUN_TOKEN only scopes resources.

[ "$#" -eq 0 ] || { echo "run-registrar-redteam.sh takes no positional arguments" >&2; exit 2; }

CURRENT_PHASE=startup
RUN_LOG=
PHASE_LOG=
RUN_ROOT=
WORK_DIR=
SUPERVISOR_PID=
HTTP01_IMAGE_BUILT=0
AUDIT_TMPFS_MOUNTED=0

fail() { printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$1" >>"$RUN_LOG" 2>/dev/null || true; printf '[registrar-redteam][%s] FAIL %s\n' "$CURRENT_PHASE" "$1" >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$SCRIPT_DIR/lib/registrar-docker.sh"
. "$SCRIPT_DIR/lib/audit-log.sh"
. "$SCRIPT_DIR/lib/ports.sh"

registrar_docker_require_launcher_contract
BOOTROOT_PROJECT_DIR="$(cd "$BOOTROOT_PROJECT_DIR" && pwd)"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
RUN_LOG="$ARTIFACT_DIR/run.log"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_TOKEN="$(registrar_docker_run_token)"
INSTANCE="registrar-redteam-${RUN_TOKEN}"
MANIFEST="$BOOTROOT_PROJECT_DIR/tests/e2e/registrar/registrar-leak-manifest.txt"
POLICIES="$BOOTROOT_PROJECT_DIR/tests/e2e/registrar/privileged-policies.txt"
DRIVER="$BOOTROOT_PROJECT_DIR/tests/e2e/registrar/redteam_client.py"
BOOTROOT_AGENT_BIN="$(dirname "$BOOTROOT_BIN")/bootroot-agent"
CERT_AUTH_ROLE=bootroot-registrar-internal
INTERNAL_IDENTITY=001.bootroot-registrar-internal.redteam.trusted.domain

log_phase() { CURRENT_PHASE="$1"; printf '{"ts":"%s","phase":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >>"$PHASE_LOG"; printf '[registrar-redteam][%s]\n' "$1" | tee -a "$RUN_LOG"; }
pass() { printf '[registrar-redteam][%s] PASS %s\n' "$CURRENT_PHASE" "$1" | tee -a "$RUN_LOG"; }
require() { command -v "$1" >/dev/null 2>&1 || fail "$1 is required"; }
stat_mode() { stat -c '%u:%g:%a' "$1" 2>/dev/null || stat -f '%u:%g:%OLp' "$1"; }
digest_file() { if command -v sha256sum >/dev/null; then sha256sum "$1" | awk '{print $1}'; else shasum -a 256 "$1" | awk '{print $1}'; fi; }
compose() { BOOTROOT_INSTANCE="$INSTANCE" docker compose -p "$INSTANCE" -f "$WORK_DIR/docker-compose.deploy.yml" "$@"; }
bootroot() { (cd "$WORK_DIR" && "$BOOTROOT_BIN" "$@"); }

cleanup() {
  local status=$?
  log_phase cleanup
  if [ -n "$SUPERVISOR_PID" ] && kill -0 "$SUPERVISOR_PID" 2>/dev/null; then
    printf 'quit\n' >"$CONTROL_FIFO" 2>/dev/null || true
    for _ in $(seq 1 15); do
      kill -0 "$SUPERVISOR_PID" 2>/dev/null || break
      sleep 1
    done
    if kill -0 "$SUPERVISOR_PID" 2>/dev/null; then
      [ -s "$RUN_ROOT/agent.pid" ] && sudo -n kill -TERM "$(cat "$RUN_ROOT/agent.pid")" 2>/dev/null || true
      kill -TERM "$SUPERVISOR_PID" 2>/dev/null || true
    fi
    wait "$SUPERVISOR_PID" 2>/dev/null || true
  fi
  if [ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ]; then
    compose logs --no-color >"$ARTIFACT_DIR/compose-logs.log" 2>&1 || true
    if command -v timeout >/dev/null 2>&1; then
      timeout --kill-after=10 90 env BOOTROOT_INSTANCE="$INSTANCE" docker compose -p "$INSTANCE" -f "$WORK_DIR/docker-compose.deploy.yml" down --volumes --remove-orphans >>"$RUN_LOG" 2>&1 || true
    else
      compose down --volumes --remove-orphans >>"$RUN_LOG" 2>&1 || true
    fi
  fi
  [ "$HTTP01_IMAGE_BUILT" -eq 1 ] && docker image rm -f "$HTTP01_IMAGE" >>"$RUN_LOG" 2>&1 || true
  [ "$AUDIT_TMPFS_MOUNTED" -eq 1 ] && sudo -n umount "$AUDIT_DIR" >>"$RUN_LOG" 2>&1 || true
  [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ] && { sudo -n rm -rf "$RUN_ROOT" >>"$RUN_LOG" 2>&1 || rm -rf "$RUN_ROOT" 2>/dev/null || true; }
  exit "$status"
}

assert_policy_fixture() {
  [ -s "$POLICIES" ] || fail "privileged policy fixture is missing"
  LC_ALL=C sort -c "$POLICIES" || fail "privileged policy fixture is not sorted"
  [ "$(sort -u "$POLICIES" | wc -l | tr -d ' ')" = "$(wc -l <"$POLICIES" | tr -d ' ')" ] || fail "privileged policy fixture contains a duplicate"
  pass "the AppRole attack uses the sole checked-in policy fixture"
}

run_policy_guard() {
  if ! (cd "$BOOTROOT_PROJECT_DIR" && cargo test --bin bootroot registrar_redteam_privileged_policy_fixture_matches_constants) >"$ARTIFACT_DIR/cargo-test.log" 2>&1; then tail -n 200 "$ARTIFACT_DIR/cargo-test.log" >>"$RUN_LOG" || true; fail "the non-Docker privileged-policy guard failed"; fi
  pass "the non-Docker privileged-policy guard passed"
}

prepare_workspace() {
  RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/bootroot-registrar-redteam-XXXXXX")"
  WORK_DIR="$RUN_ROOT/bootroot"; AUDIT_DIR="$RUN_ROOT/audit"; RECORD_DIR="$AUDIT_DIR/records"; SURFACE_DIR="$RUN_ROOT/surface"; SOCKET_DIR="$RUN_ROOT/socket"; SOCKET_PATH="$SOCKET_DIR/registrar.sock"; CONTROL_FIFO="$RUN_ROOT/agent-control"; DAEMON_CONFIG="$RUN_ROOT/registrar-agent.toml"; PROVISIONING="$RUN_ROOT/provisioning.toml"; INITIAL_CONFIG="$WORK_DIR/operator-agent.toml"; SUMMARY="$RUN_ROOT/init-summary.json"; TOKEN_FILE="$RUN_ROOT/openbao-root-token"; TOKEN_CURL="$RUN_ROOT/openbao-curl.conf"
  mkdir -p "$AUDIT_DIR" "$SURFACE_DIR" "$SOCKET_DIR" "$RUN_ROOT/registrar-client-inputs"
  registrar_docker_prepare_deployment_tree "$BOOTROOT_PROJECT_DIR" "$WORK_DIR"
  chmod 0755 "$RUN_ROOT"; sudo -n chown 0:0 "$AUDIT_DIR" "$SOCKET_DIR"; sudo -n chmod 0700 "$AUDIT_DIR"; sudo -n chmod 0755 "$SOCKET_DIR"
  sudo -n mount -t tmpfs -o size=16m,mode=0700 tmpfs "$AUDIT_DIR" || fail "could not mount the scenario-local audit tmpfs"
  AUDIT_TMPFS_MOUNTED=1
  pass "created run-scoped root-owned directories and audit tmpfs"
}

allocate_ports() { for name in POSTGRES OPENBAO STEPCA HTTP01; do pick_free_port; printf -v "PORT_${name}" '%s' "$PICKED_PORT"; done; OPENBAO_URL="https://localhost:${PORT_OPENBAO}"; }

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
  printf 'fingerprint = "%s"\n' "$(digest_file "$body")" >"$PROVISIONING"; cat "$body" >>"$PROVISIONING"; rm -f "$body"
  cat >"$INITIAL_CONFIG" <<EOF
[registrar]
audit_store_dir = "${AUDIT_DIR}"
audit_store_enforcement = "directory"

[registrar_endpoint]
enabled = true
EOF
}

prepull_third_party_images() {
  # `infra install --no-build` deliberately passes `--pull never`. Pull the
  # three non-repository images through this copied compose file so its tags
  # remain the only source of truth for the deployment under test.
  POSTGRES_PASSWORD=prepull-only GRAFANA_ADMIN_PASSWORD=prepull-only \
    compose pull openbao postgres step-ca >>"$RUN_LOG" 2>&1 ||
    fail "could not pre-pull third-party deployment images"
}

build_and_initialize() {
  HTTP01_IMAGE="bootroot-http01-responder:registrar-redteam-${RUN_TOKEN}"; export BOOTROOT_HTTP01_IMAGE="$HTTP01_IMAGE"
  docker build -t "$HTTP01_IMAGE" -f "$BOOTROOT_PROJECT_DIR/docker/http01-responder/Dockerfile" "$BOOTROOT_PROJECT_DIR" >>"$RUN_LOG" 2>&1 || fail "could not build responder image"; HTTP01_IMAGE_BUILT=1
  prepull_third_party_images
  bootroot infra install --compose-file "$WORK_DIR/docker-compose.deploy.yml" --instance-name "$INSTANCE" --postgres-host-port "$PORT_POSTGRES" --openbao-host-port "$PORT_OPENBAO" --stepca-host-port "$PORT_STEPCA" --http01-admin-host-port "$PORT_HTTP01" --no-build >>"$RUN_LOG" 2>&1 || fail "infra install failed"
  for _ in $(seq 1 60); do curl -fsS "http://localhost:${PORT_OPENBAO}/v1/sys/seal-status" >/dev/null 2>&1 && break; sleep 1; done
  curl -fsS "http://localhost:${PORT_OPENBAO}/v1/sys/seal-status" >/dev/null 2>&1 || fail "OpenBao did not become reachable"
  # A fresh `infra install` deliberately creates no state inventory. Seed
  # the one endpoint predicate `init` must preserve while it writes the
  # complete state record after provisioning.
  jq -n --arg url "http://localhost:${PORT_OPENBAO}" '{openbao_url: $url, kv_mount: "secret", registrar_endpoint: {enabled: true, domain: "trusted.domain", host: "redteam"}}' >"$WORK_DIR/state.json" || fail "could not seed endpoint predicate"
  sudo -n env HOME="$HOME" BOOTROOT_HTTP01_IMAGE="$HTTP01_IMAGE" bash -c 'cd "$1" && exec "$2" init --compose-file "$3" --secrets-dir "$4" --enable auto-generate,show-secrets,db-provision --stepca-password "$5" --http-hmac "$6" --no-eab --save-unseal-keys --overwrite-password --overwrite-ca-json --overwrite-state --confirm-db-provision --db-user step --db-name stepca --responder-url "$7" --agent-config "$8" --summary-json "$9"' _ "$WORK_DIR" "$BOOTROOT_BIN" "$WORK_DIR/docker-compose.deploy.yml" "$WORK_DIR/secrets" "redteam-${RUN_TOKEN}" "redteam-hmac-${RUN_TOKEN}" "http://127.0.0.1:${PORT_HTTP01}" "$INITIAL_CONFIG" "$SUMMARY" </dev/null >"$ARTIFACT_DIR/init.raw.log" 2>&1 || fail "bootroot init failed"
  sed 's/^\(root token: \).*/\1<redacted>/' "$ARTIFACT_DIR/init.raw.log" >"$ARTIFACT_DIR/init.log"
  sudo -n jq -r '.root_token // empty' "$SUMMARY" | sudo -n sh -c 'umask 077; cat >"$1"' _ "$TOKEN_FILE"; sudo -n test -s "$TOKEN_FILE" || fail "init did not write a root token"
  # A header file keeps the init root token out of the process arguments.
  # `curl --header @file` consumes the literal HTTP field line, unlike a
  # curl config file where an extra escape would change the field name.
  sudo -n sh -c 'printf "%s: %s\n" "X-Vault-Token" "$(cat "$1")" >"$2"; chmod 600 "$2"' _ "$TOKEN_FILE" "$TOKEN_CURL"
  OPENBAO_CA="$RUN_ROOT/openbao-ca.pem"
  sudo -n sh -c 'cat "$1" "$2" >"$3"; chmod 644 "$3"' _ "$WORK_DIR/secrets/certs/root_ca.crt" "$WORK_DIR/secrets/certs/intermediate_ca.crt" "$OPENBAO_CA"
  EMPTY_EAB_STATUS="$(sudo -n curl -sS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" -X POST --data '{"data":{"kid":"","hmac":""}}' --dump-header "$ARTIFACT_DIR/empty-eab-headers.txt" --output "$ARTIFACT_DIR/empty-eab-response.json" --write-out '%{http_code}' "$OPENBAO_URL/v1/secret/data/bootroot/agent/eab")" || EMPTY_EAB_STATUS="curl-failed"
  printf '%s\n' "$EMPTY_EAB_STATUS" >"$ARTIFACT_DIR/empty-eab-status.txt"
  if [ "$EMPTY_EAB_STATUS" != "200" ]; then
    cat "$ARTIFACT_DIR/empty-eab-status.txt" "$ARTIFACT_DIR/empty-eab-headers.txt" "$ARTIFACT_DIR/empty-eab-response.json" >>"$RUN_LOG" 2>/dev/null || true
    fail "could not record the explicit empty agent EAB"
  fi
  # `init` has already recreated the responder with its rendered HMAC and
  # started the OpenBao agents. Replaying `infra up` here races that rendered
  # configuration with the base image and leaves the registrar's pre-issued
  # HMAC unable to authenticate to the responder.
  pass "initialized an isolated live TLS OpenBao deployment"
}

apply_endpoint_dns_alias() {
  local client_alias="001.bootroot-registrar.redteam.trusted.domain"
  local endpoint_alias="001.bootroot-registrar-endpoint.redteam.trusted.domain"
  local override="$ARTIFACT_DIR/docker-compose.registrar-endpoint-alias.yml"
  local responder_override="$WORK_DIR/secrets/responder/docker-compose.responder.override.yml"
  cat >"$override" <<EOF
services:
  bootroot-http01:
    networks:
      default:
        aliases:
          - ${client_alias}
          - ${endpoint_alias}
EOF
  [ -f "$responder_override" ] || fail "init did not render the responder compose override"
  BOOTROOT_INSTANCE="$INSTANCE" docker compose -p "$INSTANCE" -f "$WORK_DIR/docker-compose.deploy.yml" -f "$override" -f "$responder_override" up -d --no-deps bootroot-http01 >>"$RUN_LOG" 2>&1 || fail "could not apply the registrar endpoint DNS alias"
  for alias in "$client_alias" "$endpoint_alias"; do
    for _ in $(seq 1 15); do
      if docker exec "${INSTANCE}-ca" bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${alias}/80'" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    docker exec "${INSTANCE}-ca" bash -lc "timeout 2 bash -lc 'echo > /dev/tcp/${alias}/80'" >/dev/null 2>&1 || fail "step-ca cannot reach registrar hostname ${alias} through its DNS alias"
  done
  pass "step-ca can reach both registrar hostnames through DNS aliases"
}

write_daemon_config() {
  INTERNAL_DIR="$WORK_DIR/secrets/registrar-internal"; ROOT_CA="$WORK_DIR/secrets/certs/root_ca.crt"
  cat >"$RUN_ROOT/endpoint.toml" <<EOF

[registrar]
state_file = "${WORK_DIR}/state.json"
provisioning_config_path = "${PROVISIONING}"
audit_store_dir = "${AUDIT_DIR}"
audit_record_dir = "${RECORD_DIR}"
audit_store_enforcement = "directory"
audit_store_reserve_bytes = 10485760
audit_store_low_water_bytes = 8388608

[registrar_endpoint]
enabled = true
server_cert_path = "${SURFACE_DIR}/registrar-endpoint.crt"
server_key_path = "${SURFACE_DIR}/registrar-endpoint.key"
client_cert_path = "${SURFACE_DIR}/registrar-client.crt"
client_key_path = "${SURFACE_DIR}/registrar-client.key"
EOF
  sudo -n sh -c 'cat "$1" "$2" >"$3"; chmod 600 "$3"; chown 0:0 "$3"' _ "$INTERNAL_DIR/agent.toml" "$RUN_ROOT/endpoint.toml" "$DAEMON_CONFIG"
  sudo -n mkdir -p "$RECORD_DIR"; sudo -n chown 0:0 "$RECORD_DIR"; sudo -n chmod 0700 "$RECORD_DIR"
}

write_supervisor() {
  cat >"$RUN_ROOT/supervisor.py" <<'PY'
import os, signal, socket, sys
sock_path, control, pid_file, agent_bin, config = sys.argv[1:]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); sock.bind(sock_path); sock.listen(32); os.chown(sock_path, 0, 0); os.chmod(sock_path, 0o700); os.mkfifo(control, 0o600); child = None
def spawn():
    global child
    child = os.fork()
    if child == 0:
        os.dup2(sock.fileno(), 3); os.set_inheritable(3, True); env = os.environ.copy(); env['LISTEN_PID'] = str(os.getpid()); env['LISTEN_FDS'] = '1'; os.execvpe(agent_bin, [agent_bin, '--config', config], env)
    open(pid_file, 'w', encoding='ascii').write(str(child))
def stop():
    global child
    if child is not None:
        try: os.kill(child, signal.SIGTERM)
        except ProcessLookupError: pass
        os.waitpid(child, 0); child = None
spawn()
while True:
    with open(control, encoding='ascii') as stream:
        for line in stream:
            if line.strip() == 'restart': stop(); spawn()
            elif line.strip() == 'stop': stop()
            elif line.strip() == 'quit': stop(); sys.exit(0)
PY
}

start_daemon() {
  write_supervisor
  sudo -n python3 "$RUN_ROOT/supervisor.py" "$SOCKET_PATH" "$CONTROL_FIFO" "$RUN_ROOT/agent.pid" "$BOOTROOT_AGENT_BIN" "$DAEMON_CONFIG" >>"$ARTIFACT_DIR/agent.log" 2>&1 &
  SUPERVISOR_PID=$!
  for _ in $(seq 1 90); do [ -S "$SOCKET_PATH" ] && [ -s "$RUN_ROOT/agent.pid" ] && [ -s "$SURFACE_DIR/registrar-client.crt" ] && break; sleep 1; done
  [ -s "$SURFACE_DIR/registrar-client.crt" ] || fail "daemon did not issue registrar surface material"
  printf '%s\n' "$(digest_file "$ROOT_CA")" >"$SURFACE_DIR/registrar-endpoint-anchors.sha256"
}

stage_bundle() {
  local source="$RUN_ROOT/registrar-client-inputs"
  sudo -n cp "$SURFACE_DIR/registrar-client.crt" "$source/registrar-client.crt"; sudo -n cp "$SURFACE_DIR/registrar-client.key" "$source/registrar-client.key"; sudo -n cp "$SURFACE_DIR/registrar-endpoint-anchors.sha256" "$source/registrar-endpoint-anchors.sha256"; sudo -n cp "$ROOT_CA" "$source/registrar-endpoint-ca.pem"
  sudo -n chown "$(id -u):$(id -g)" "$source"/*
  cat >"$source/registrar-endpoint.toml" <<EOF
socket_path = "${SOCKET_PATH}"
expected_endpoint_name = "001.bootroot-registrar-endpoint.redteam.trusted.domain"
EOF
  registrar_docker_stage_leak_bundle "$source" "$ARTIFACT_DIR/registrar-leak-bundle" "$MANIFEST"; registrar_docker_assert_no_backend_credentials "$ARTIFACT_DIR/registrar-leak-bundle"; BUNDLE="$ARTIFACT_DIR/registrar-leak-bundle"
  pass "the staged read-only bundle exactly matches its manifest and has no backend credential"
}

assert_socket_contract() {
  [ "$(stat_mode "$SOCKET_PATH")" = "0:0:700" ] || fail "socket is not root:root mode 0700"
  local data mode; data="$(stat_mode "$SOCKET_DIR")"; [ "${data%%:*}" = 0 ] || fail "socket parent is not root-owned"; mode="${data##*:}"; [ $((8#$mode & 8#022)) -eq 0 ] || fail "socket parent permits group or other writes"
  pass "socket is root:root 0700 and parent denies group/other writes by bitmask"
}

client() { python3 "$DRIVER" --socket "$SOCKET_PATH" --pins "$BUNDLE/registrar-endpoint-anchors.sha256" --ca "$BUNDLE/registrar-endpoint-ca.pem" --cert "$BUNDLE/registrar-client.crt" --key "$BUNDLE/registrar-client.key" --endpoint-name "001.bootroot-registrar-endpoint.redteam.trusted.domain" "$@"; }
write_mint() { jq -n --argjson group "$2" '{protocol_version:1,service_name:"review",delivery_mode:"RemoteBootstrap",host:"redteam",spec:{component:"review",service_name:"review",reload:"docker-restart",cert_group:$group},wrap_ttl:60,idempotency_key:"redteam-mint"}' >"$1"; }

assert_escalation_denied() {
  local status policies
  sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" "$OPENBAO_URL/v1/auth/cert/certs/$CERT_AUTH_ROLE" >"$ARTIFACT_DIR/cert-auth-entry.json" || fail "could not read the bootroot-internal cert-auth role"
  jq -e --arg identity "$INTERNAL_IDENTITY" '
    def contains_identity:
      if type == "array" then index($identity) != null else . == $identity end;
    .data.allowed_common_names | contains_identity
  ' "$ARTIFACT_DIR/cert-auth-entry.json" >/dev/null || fail "bootroot-internal cert-auth role does not constrain its common name"
  jq -e --arg identity "$INTERNAL_IDENTITY" '
    def contains_identity:
      if type == "array" then index($identity) != null else . == $identity end;
    .data.allowed_dns_sans | contains_identity
  ' "$ARTIFACT_DIR/cert-auth-entry.json" >/dev/null || fail "bootroot-internal cert-auth role does not constrain its DNS SAN"
  # The daemon's credential always names its fixed cert-auth role. Supply that
  # public role name to exercise the same privileged role explicitly.
  status="$(curl -sS -o "$ARTIFACT_DIR/cert-login.json" -w '%{http_code}' --cacert "$OPENBAO_CA" --cert "$BUNDLE/registrar-client.crt" --key "$BUNDLE/registrar-client.key" -H 'Content-Type: application/json' -X POST -d "{\"name\":\"$CERT_AUTH_ROLE\"}" "$OPENBAO_URL/v1/auth/cert/login" || true)"
  [ "$status" -ge 400 ] || fail "registrar leaf authenticated through bootroot-internal auth/cert role"
  policies="$(jq -Rsc 'split("\n") | map(select(length > 0))' "$POLICIES")"
  for endpoint in auth/approle/role/redteam-escalation sys/policies/acl/redteam-escalation; do status="$(curl -sS --cacert "$OPENBAO_CA" -o "$ARTIFACT_DIR/unauth-${endpoint//\//-}.json" -w '%{http_code}' -X POST -d "{\"token_policies\":${policies},\"policy\":\"path \\\"*\\\" { capabilities = [\\\"sudo\\\"] }\"}" "$OPENBAO_URL/v1/$endpoint" || true)"; [ "$status" -ge 400 ] || fail "unauthenticated attacker wrote $endpoint"; done
  for path in bootroot/ca bootroot/infra/responder_hmac bootroot/infra/agent_eab bootroot/services/redteam-review/secret_id; do status="$(curl -sS -o /dev/null -w '%{http_code}' --cacert "$OPENBAO_CA" --cert "$BUNDLE/registrar-client.crt" --key "$BUNDLE/registrar-client.key" "$OPENBAO_URL/v1/secret/data/$path" || true)"; [ "$status" -ge 400 ] || fail "registrar material read $path directly"; done
  pass "registrar material cannot authenticate, escalate, or read protected KV paths"
}

assert_functionality_and_audit() {
  local mint="$RUN_ROOT/mint.json" refused="$RUN_ROOT/refused.json" reserved="$RUN_ROOT/reserved.json" deregister="$RUN_ROOT/deregister.json" first second role policies before after result
  write_mint "$mint" 3000; first="$(client --operation mint --payload "$mint")" || fail "first mint failed"; second="$(client --operation mint --payload "$mint")" || fail "idempotent mint failed"; jq -e '.outcome == "first_mint"' <<<"$first" >/dev/null || fail "first mint was not first_mint"; jq -e '.outcome == "idempotent_remint"' <<<"$second" >/dev/null || fail "second mint was not idempotent_remint"
  REGISTRATION_ID="$(jq -r '.registration_id' <<<"$first")"; role="$(sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" "$OPENBAO_URL/v1/auth/approle/role/$REGISTRATION_ID")"; policies="$(jq -c '.data.token_policies | sort' <<<"$role")"; [ "$policies" = "[\"bootroot-service-${REGISTRATION_ID}\"]" ] || fail "minted role policy set is not exactly the derived service policy"
  jq '.service_name = "bootroot-registrar" | .spec.service_name = "bootroot-registrar"' "$mint" >"$reserved"; client --operation mint --payload "$reserved" >"$ARTIFACT_DIR/reserved-identity.json" || fail "reserved identity refusal exchange failed"; jq -e '.class == "permanent"' "$ARTIFACT_DIR/reserved-identity.json" >/dev/null || fail "registrar leaf was accepted as a service identity"
  write_mint "$refused" 999; before="$(find "$RECORD_DIR" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')"; client --operation mint --payload "$refused" >"$ARTIFACT_DIR/refused-mint.json" || fail "refused mint exchange failed"; jq -e '.class == "permanent"' "$ARTIFACT_DIR/refused-mint.json" >/dev/null || fail "unsafe mint was not refused"; after="$(find "$RECORD_DIR" -type f -printf '%s\n' 2>/dev/null | awk '{s+=$1} END {print s+0}')"; [ "$after" -gt "$before" ] || fail "refused mint wrote no audit record"; grep -R '"phase":"intent"' "$RECORD_DIR" >/dev/null && grep -R '"phase":"outcome"' "$RECORD_DIR" >/dev/null || fail "refused mint lacks paired audit records"
  sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" "$OPENBAO_URL/v1/auth/approle/role/redteam-review" >"$ARTIFACT_DIR/refused-role.json" 2>&1 && fail "refused mint created an AppRole"
  sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" "$OPENBAO_URL/v1/sys/policies/acl/bootroot-service-redteam-review" >"$ARTIFACT_DIR/refused-policy.json" 2>&1 && fail "refused mint created a policy"
  sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" "$OPENBAO_URL/v1/secret/data/bootroot/services/redteam-review/secret_id" >"$ARTIFACT_DIR/refused-kv.json" 2>&1 && fail "refused mint wrote service KV"
  jq -n '{protocol_version:1,service_name:"review",host:"redteam",idempotency_key:"redteam-deregister"}' >"$deregister"; for expected in identity_removed idempotent_already_absent; do result="$(client --operation deregister --payload "$deregister")" || fail "deregister failed"; jq -e --arg expected "$expected" '.outcome == $expected' <<<"$result" >/dev/null || fail "deregister was not $expected"; done
  assert_openbao_audit_log "${INSTANCE}-openbao" /openbao/audit/audit.log
  pass "mint/deregister are idempotent, refusal is audited, and OpenBao writes are contained"
}

wait_for_capacity_state() {
  local expected="$1" request="$2" response=""
  for _ in $(seq 1 75); do
    response="$(client --operation mint --payload "$request" 2>/dev/null || true)"
    if jq -e --arg expected "$expected" '.registrar_health.audit_capacity.state == $expected' <<<"$response" >/dev/null 2>&1; then
      printf '%s\n' "$response"
      return 0
    fi
    sleep 1
  done
  fail "audit capacity did not report ${expected} within its maintenance window"
}

assert_audit_capacity() {
  local mint="$RUN_ROOT/capacity-mint.json" response before after
  write_mint "$mint" 3000
  # Directory enforcement still measures the scenario-local budget.  The
  # filler is root-owned and outside records/, so it cannot masquerade as a
  # verb record while it drives the capacity signal through low-water first.
  sudo -n dd if=/dev/zero of="$AUDIT_DIR/redteam-low-water.fill" bs=1M count=4 status=none
  response="$(wait_for_capacity_state low_water "$mint")"
  jq -e '.registrar_health.audit_capacity.state == "low_water"' <<<"$response" >/dev/null || fail "low-water health response was malformed"
  before="$(sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" "$OPENBAO_URL/v1/auth/approle/role/redteam-review" 2>/dev/null || true)"
  sudo -n dd if=/dev/zero of="$AUDIT_DIR/redteam-exhausted.fill" bs=1M count=12 status=none
  wait_for_capacity_state exhausted "$mint" >/dev/null
  response="$(client --operation mint --payload "$mint")" || fail "exhausted mint exchange failed"
  jq -e '.class != null' <<<"$response" >/dev/null || fail "exhausted audit store accepted a mint"
  after="$(sudo -n curl -fsS --cacert "$OPENBAO_CA" --header @"$TOKEN_CURL" "$OPENBAO_URL/v1/auth/approle/role/redteam-review" 2>/dev/null || true)"
  [ "$before" = "$after" ] || fail "exhausted mint changed OpenBao role state"
  pass "low-water precedes exhaustion and exhausted mint creates no OpenBao state"
}

assert_post_bind_peer_fixture() {
  local uid gid fixture_dir fixture_socket fixture_pid
  uid="$(id -u nobody 2>/dev/null || printf 65534)"
  gid="$(id -g nobody 2>/dev/null || printf 65534)"
  fixture_dir="$RUN_ROOT/unprivileged-peer"
  fixture_socket="$fixture_dir/registrar.sock"
  # The sequence is intentionally ordered: the unprivileged process owns
  # the directory while it binds, then root changes both path objects. The
  # final metadata is indistinguishable from deployment, while SO_PEERCRED
  # still exposes the accepting process's real uid.
  sudo -n mkdir -p "$fixture_dir"
  sudo -n chown "$uid:$gid" "$fixture_dir"
  sudo -n chmod 0700 "$fixture_dir"
  sudo -n -u "$(id -un "$uid" 2>/dev/null || printf nobody)" python3 -c '
import socket, sys, time
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.bind(sys.argv[1]); s.listen(1)
while True:
    conn, _ = s.accept()
    time.sleep(1)
' "$fixture_socket" >>"$ARTIFACT_DIR/unprivileged-peer.log" 2>&1 &
  fixture_pid=$!
  for _ in $(seq 1 10); do [ -S "$fixture_socket" ] && break; sleep 1; done
  [ -S "$fixture_socket" ] || fail "unprivileged peer fixture did not bind"
  sudo -n chown 0:0 "$fixture_dir" "$fixture_socket"
  sudo -n chmod 0700 "$fixture_dir" "$fixture_socket"
  [ "$(stat_mode "$fixture_dir")" = "0:0:700" ] || fail "post-bind fixture directory metadata is wrong"
  [ "$(stat_mode "$fixture_socket")" = "0:0:700" ] || fail "post-bind fixture socket metadata is wrong"
  if python3 "$DRIVER" --socket "$fixture_socket" --pins "$BUNDLE/registrar-endpoint-anchors.sha256" --ca "$BUNDLE/registrar-endpoint-ca.pem" --cert "$BUNDLE/registrar-client.crt" --key "$BUNDLE/registrar-client.key" --endpoint-name "001.bootroot-registrar-endpoint.redteam.trusted.domain" --operation mint --payload "$RUN_ROOT/empty.json"; then
    kill "$fixture_pid" 2>/dev/null || true
    fail "caller accepted a root-looking socket served by an unprivileged peer"
  fi
  kill "$fixture_pid" 2>/dev/null || true
  wait "$fixture_pid" 2>/dev/null || true
  pass "post-bind peer-credential fixture is refused by the caller"
}

assert_socket_refusals() {
  local payload="$RUN_ROOT/empty.json" wrong="$RUN_ROOT/wrong-pins" before after nobody
  printf '{}' >"$payload"; client --operation enumerate --payload "$payload" --expect-empty || fail "unknown socket operation was served"
  printf '%064d\n' 0 >"$wrong"; if python3 "$DRIVER" --socket "$SOCKET_PATH" --pins "$wrong" --ca "$BUNDLE/registrar-endpoint-ca.pem" --cert "$BUNDLE/registrar-client.crt" --key "$BUNDLE/registrar-client.key" --endpoint-name "001.bootroot-registrar-endpoint.redteam.trusted.domain" --operation mint --payload "$payload"; then fail "client accepted a fingerprint mismatch"; fi
  if python3 "$DRIVER" --socket "$SOCKET_PATH" --pins "$BUNDLE/registrar-endpoint-anchors.sha256" --ca "$BUNDLE/registrar-endpoint-ca.pem" --cert "$BUNDLE/registrar-client.crt" --key "$BUNDLE/registrar-client.key" --endpoint-name "wrong.bootroot-registrar-endpoint.redteam.trusted.domain" --operation mint --payload "$payload"; then fail "client accepted a wrong-name endpoint leaf"; fi
  before="$(stat -c '%d:%i' "$SOCKET_PATH" 2>/dev/null || stat -f '%d:%i' "$SOCKET_PATH")"; printf 'restart\n' >"$CONTROL_FIFO"; sleep 2; after="$(stat -c '%d:%i' "$SOCKET_PATH" 2>/dev/null || stat -f '%d:%i' "$SOCKET_PATH")"; [ "$before" = "$after" ] || fail "daemon restart changed inherited listener inode"
  nobody="$(id -un 65534 2>/dev/null || printf nobody)"; printf 'stop\n' >"$CONTROL_FIFO"; sleep 1
  sudo -n cp "$DAEMON_CONFIG" "$RUN_ROOT/registrar-agent.good.toml"
  sudo -n python3 -c 'import pathlib,sys; p=pathlib.Path(sys.argv[1]); p.write_text(p.read_text().replace("registrar-client.key", "missing-client.key"))' "$DAEMON_CONFIG"
  printf 'restart\n' >"$CONTROL_FIFO"
  for _ in $(seq 1 10); do kill -0 "$(cat "$RUN_ROOT/agent.pid")" 2>/dev/null || break; sleep 1; done
  if kill -0 "$(cat "$RUN_ROOT/agent.pid")" 2>/dev/null; then fail "deliberately invalid daemon configuration did not fail startup"; fi
  if sudo -n -u "$nobody" python3 -c 'import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])' "$SOCKET_PATH"; then fail "unprivileged peer connected while daemon stopped"; fi
  if sudo -n -u "$nobody" python3 -c 'import os,socket,sys; os.unlink(sys.argv[1]); socket.socket(socket.AF_UNIX).bind(sys.argv[1])' "$SOCKET_PATH"; then fail "unprivileged peer occupied stopped socket path"; fi
  sudo -n mv "$RUN_ROOT/registrar-agent.good.toml" "$DAEMON_CONFIG"; printf 'restart\n' >"$CONTROL_FIFO"
  pass "all non-verbs, pin failures, restart behavior, and path occupation attempts are refused"
}

main() {
  : >"$RUN_LOG"; : >"$PHASE_LOG"; trap cleanup EXIT
  log_phase validate
  for command in docker jq curl cargo python3 sudo; do require "$command"; done
  sudo -n true >/dev/null 2>&1 || fail "passwordless sudo is required for the root-owned registrar socket scenario"
  [ -x "$BOOTROOT_AGENT_BIN" ] || fail "bootroot-agent matching BOOTROOT_BIN is not executable"; [ -f "$MANIFEST" ] && [ -f "$DRIVER" ] || fail "red-team support data is missing"
  assert_policy_fixture; run_policy_guard
  log_phase deployment; prepare_workspace; allocate_ports; write_configs; build_and_initialize; apply_endpoint_dns_alias; write_daemon_config; start_daemon; assert_socket_contract; stage_bundle
  log_phase containment; assert_escalation_denied
  log_phase functionality; assert_functionality_and_audit
  log_phase capacity; assert_audit_capacity
  log_phase socket; assert_socket_refusals
  log_phase peer-credentials; assert_post_bind_peer_fixture
  log_phase done; pass "registrar red-team scenario completed"
}
main
