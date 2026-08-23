#!/usr/bin/env bash
set -euo pipefail

# Docker-backed E2E for `bootroot init` on an endpoint-enabled loopback
# host (#766).
#
# `run-registrar-internal-e2e.sh` proves the `auth/cert` contract against
# a bare OpenBao: what the entry accepts, and what the minted token may
# do.  It says nothing about how the credential gets there.  This
# scenario covers the other half — the acceptance criterion that an
# endpoint-enabled *loopback* host completes `init` with a
# TLS-terminated `:8200`, an `https://` state URL, and a certificate
# login that works — and it needs a whole deployment to do it: step-ca
# has to sign the internal leaf through the ordinary outbound ACME path,
# and the HTTP-01 responder has to answer the challenge for it.
#
# Three things here are only observable end to end, and each one is a
# way this could be wrong while every unit test passed:
#
#   - step-ca resolves an HTTP-01 identifier through the responder's
#     Docker network aliases.  The internal identity has no
#     `ServiceEntry`, so it is not in the set `service add` maintains,
#     and without an alias of its own the challenge cannot resolve at
#     all.
#   - `init` issues the internal leaf through this install's *own*
#     published step-ca and responder ports.  On the compose defaults a
#     hard-coded `:9000`/`:8080` is indistinguishable from a derived
#     one; on moved ports it reaches nothing, and on a host that already
#     has an install it reaches the other one.
#   - the listener transition, the recorded URL and the certificate
#     login are one sequence.  Each is assertable alone and only their
#     composition is the criterion.
#
# So the ports are moved deliberately.  This scenario allocates four
# free ones and installs under a run-scoped instance name into a
# temporary directory, on the `run-two-instance-isolation.sh` model: it
# is safe on a host that already carries a default `bootroot` install,
# and it is the arrangement that exercises the derivation.
#
# The endpoint-*disabled* half of the criterion is not re-tested here.
# Every other lifecycle arm is an endpoint-disabled host — none of them
# records the predicate — and each drives its whole run over the
# plaintext `http://` URL `init` recorded, so a listener that
# transitioned when it should not have would fail them outright.
#
# The predicate is seeded into `state.json` by hand between `install`
# and `init`.  Defining and writing it belongs to the registrar endpoint
# work; `init` only consumes it, and consuming it is what is under test.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

# A `COMPOSE_PROJECT_NAME` or `BOOTROOT_INSTANCE` inherited from the
# invoking shell outranks the recorded instance name and would point
# this run at whatever that names.  The host-port variables would
# likewise override the ones allocated below, collapsing the run onto a
# co-located install's ports.
unset COMPOSE_PROJECT_NAME BOOTROOT_INSTANCE
unset OPENBAO_HOST_PORT POSTGRES_HOST_PORT STEPCA_HOST_PORT HTTP01_ADMIN_HOST_PORT
unset POSTGRES_HOST POSTGRES_PORT POSTGRES_USER POSTGRES_PASSWORD POSTGRES_DB

# shellcheck source=lib/leftovers.sh
. "$SCRIPT_DIR/lib/leftovers.sh"
# shellcheck source=lib/ports.sh
. "$SCRIPT_DIR/lib/ports.sh"

RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)-$$}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/registrar-internal-init-${RUN_ID}}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
INIT_RAW_LOG="$ARTIFACT_DIR/init.raw.log"

BOOTROOT_BIN="${BOOTROOT_BIN:-$ROOT_DIR/target/debug/bootroot}"
COMPOSE_FILE_NAME="docker-compose.deploy.yml"

RUN_TOKEN="${RUN_TOKEN:-${GITHUB_RUN_ID:-$(date +%s)$$}}"
RUN_TOKEN="$(printf '%s' "$RUN_TOKEN" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9')"
INSTANCE="regint-${RUN_TOKEN}"
# `MAX_INSTANCE_NAME_LEN` in src/commands/compose_project.rs.
MAX_INSTANCE_NAME_LEN=39

# The `bootroot-http01` image the deploy compose file references.  A
# run-scoped tag so the build cannot overwrite an image a co-located
# install is running; removed again on the way out.
HTTP01_IMAGE="${HTTP01_IMAGE:-bootroot-http01-responder:registrar-internal-${RUN_TOKEN}}"
export BOOTROOT_HTTP01_IMAGE="$HTTP01_IMAGE"
HTTP01_IMAGE_BUILT=0

# The identity the predicate composes.  The SAN below is what the
# `auth/cert` entry allows and what step-ca must resolve; it is spelled
# out rather than derived so a change to the composition fails here.
DOMAIN="trusted.domain"
HOST_LABEL="bootroot-01"
INTERNAL_SAN="001.bootroot-registrar-internal.${HOST_LABEL}.${DOMAIN}"
INTERNAL_ENTRY="bootroot-registrar-internal"

INFRA_READY_ATTEMPTS="${INFRA_READY_ATTEMPTS:-60}"
INFRA_READY_DELAY_SECS="${INFRA_READY_DELAY_SECS:-2}"

CURRENT_PHASE="startup"
RUN_ROOT=""
WORK_DIR=""
SECRETS_DIR=""
INTERNAL_DIR=""
PORT_POSTGRES=0
PORT_OPENBAO=0
PORT_STEPCA=0
PORT_HTTP01=0

log_phase() {
  CURRENT_PHASE="$1"
  printf '{"ts":"%s","phase":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >>"$PHASE_LOG"
  printf '[registrar-internal-init][%s]\n' "$1" | tee -a "$RUN_LOG"
}

log() {
  printf '[registrar-internal-init][%s] %s\n' "$CURRENT_PHASE" "$1" | tee -a "$RUN_LOG"
}

# Reports each assertion individually, so a passing run reads as a
# checklist rather than as silence.
pass() {
  printf '[registrar-internal-init][%s] PASS %s\n' "$CURRENT_PHASE" "$1" | tee -a "$RUN_LOG"
}

fail() {
  printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$1" >>"$RUN_LOG" 2>/dev/null || true
  echo "[registrar-internal-init][${CURRENT_PHASE}] FAIL $1" >&2
  exit 1
}

assert_equal() {
  local what="$1" expected="$2" actual="$3"
  [ "$expected" = "$actual" ] || fail "${what}: expected '${expected}', got '${actual}'"
  pass "$what"
}

file_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%OLp' "$1"
}

ensure_prerequisites() {
  command -v docker >/dev/null 2>&1 || fail "docker is required"
  docker compose version >/dev/null 2>&1 || fail "docker compose is required"
  command -v jq >/dev/null 2>&1 || fail "jq is required"
  command -v curl >/dev/null 2>&1 || fail "curl is required"
  # The certificate login below presents a PEM client certificate.  The
  # system curl cannot always do that (macOS ships a SecureTransport
  # build that wants a keychain identity), so the login goes through
  # python3's `ssl`, which takes the PEM pair directly on every platform
  # this runs on.
  command -v python3 >/dev/null 2>&1 || fail "python3 is required"
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  [ -n "$RUN_TOKEN" ] || fail "RUN_TOKEN reduced to the empty string; supply a token of [a-z0-9]"
  [ "${#INSTANCE}" -le "$MAX_INSTANCE_NAME_LEN" ] ||
    fail "derived instance name '${INSTANCE}' exceeds ${MAX_INSTANCE_NAME_LEN} characters"
}

run_bootroot() {
  (cd "$WORK_DIR" && BOOTROOT_LANG=en "$BOOTROOT_BIN" "$@")
}

instance_compose() {
  BOOTROOT_INSTANCE="$INSTANCE" docker compose -p "$INSTANCE" \
    -f "$WORK_DIR/$COMPOSE_FILE_NAME" "$@"
}

allocate_ports() {
  local suffix var
  for suffix in POSTGRES OPENBAO STEPCA HTTP01; do
    var="PORT_${suffix}"
    pick_free_port
    printf -v "$var" '%s' "$PICKED_PORT"
  done
  log "ports: postgres=${PORT_POSTGRES} openbao=${PORT_OPENBAO} stepca=${PORT_STEPCA} http01=${PORT_HTTP01}"
}

create_run_root() {
  RUN_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/bootroot-registrar-internal-init-XXXXXX")"
  WORK_DIR="$RUN_ROOT/bootroot"
  SECRETS_DIR="$WORK_DIR/secrets"
  INTERNAL_DIR="$SECRETS_DIR/registrar-internal"
  mkdir -p "$WORK_DIR/openbao"
  # `docker-compose.deploy.yml` carries no build context, so a directory
  # holding a copy of it plus the two configs it resolves relative to
  # itself is a complete install root.
  cp "$ROOT_DIR/$COMPOSE_FILE_NAME" "$WORK_DIR/$COMPOSE_FILE_NAME"
  cp "$ROOT_DIR/openbao/openbao.hcl" "$WORK_DIR/openbao/openbao.hcl"
  cp "$ROOT_DIR/responder.toml.compose" "$WORK_DIR/responder.toml.compose"
  log "run root: $RUN_ROOT"
}

build_responder_image() {
  if docker image inspect "$HTTP01_IMAGE" >/dev/null 2>&1; then
    log "reusing $HTTP01_IMAGE"
    return 0
  fi
  log "building $HTTP01_IMAGE"
  # `docker build` rather than `docker compose build` so the
  # repository's own `.env` and compose project are never read.
  docker build -t "$HTTP01_IMAGE" \
    -f "$ROOT_DIR/docker/http01-responder/Dockerfile" "$ROOT_DIR" \
    >>"$RUN_LOG" 2>&1 || fail "failed to build $HTTP01_IMAGE"
  HTTP01_IMAGE_BUILT=1
}

# `--no-build` implies `--pull never`, so the third-party images have to
# be on the host first.  Pulled through Compose so the tags come from the
# compose file rather than a second copy of them here.
prepull_third_party_images() {
  log "pre-pulling third-party images"
  POSTGRES_PASSWORD=prepull-only GRAFANA_ADMIN_PASSWORD=prepull-only \
    BOOTROOT_INSTANCE="$INSTANCE" \
    docker compose -p "$INSTANCE" -f "$WORK_DIR/$COMPOSE_FILE_NAME" \
    pull openbao postgres step-ca >>"$RUN_LOG" 2>&1 ||
    fail "failed to pre-pull the third-party images"
}

install_infra() {
  log "installing instance ${INSTANCE}"
  run_bootroot infra install \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --instance-name "$INSTANCE" \
    --postgres-host-port "$PORT_POSTGRES" \
    --openbao-host-port "$PORT_OPENBAO" \
    --stepca-host-port "$PORT_STEPCA" \
    --http01-admin-host-port "$PORT_HTTP01" \
    --no-build \
    >>"$RUN_LOG" 2>&1 || fail "infra install failed"
}

# `infra install` returns when every container reports `running`, which
# is not when the servers inside accept connections.  `init` opens with
# single-shot probes that do not retry, so the wait belongs here.
wait_for_openbao_listening() {
  local code
  for _ in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    code="$(curl -kSs -o /dev/null -w '%{http_code}' -m 3 \
      "http://127.0.0.1:${PORT_OPENBAO}/v1/sys/seal-status" 2>/dev/null || true)"
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  docker logs "${INSTANCE}-openbao" >>"$RUN_LOG" 2>&1 || true
  fail "OpenBao did not answer on port ${PORT_OPENBAO} before init"
}

wait_for_postgres_admin() {
  for _ in $(seq 1 "$INFRA_READY_ATTEMPTS"); do
    if docker exec "${INSTANCE}-postgres" pg_isready -h 127.0.0.1 -U step -d postgres \
      >/dev/null 2>&1 &&
      bash -c ": >/dev/tcp/127.0.0.1/${PORT_POSTGRES}" >/dev/null 2>&1; then
      return 0
    fi
    sleep "$INFRA_READY_DELAY_SECS"
  done
  docker logs "${INSTANCE}-postgres" >>"$RUN_LOG" 2>&1 || true
  fail "PostgreSQL did not accept connections on port ${PORT_POSTGRES} before init"
}

# The predicate `init` consumes.  Written here rather than by a command
# because no command writes it yet: defining and storing it belongs to
# the registrar endpoint work, and this scenario is about what `init`
# does when it finds it.
seed_registrar_endpoint_predicate() {
  local state="$WORK_DIR/state.json" tmp="$WORK_DIR/state.json.seed"
  if [ -f "$state" ]; then
    jq --arg d "$DOMAIN" --arg h "$HOST_LABEL" \
      '.registrar_endpoint = {enabled: true, domain: $d, host: $h}' \
      "$state" >"$tmp" || fail "could not seed the predicate into $state"
  else
    jq -n --arg url "http://localhost:${PORT_OPENBAO}" --arg d "$DOMAIN" --arg h "$HOST_LABEL" \
      '{openbao_url: $url, kv_mount: "secret",
        registrar_endpoint: {enabled: true, domain: $d, host: $h}}' \
      >"$tmp" || fail "could not write $state"
  fi
  mv "$tmp" "$state"
  assert_equal "the predicate is recorded as enabled" \
    "true" "$(jq -r '.registrar_endpoint.enabled' "$state")"
  # The plaintext URL is the starting point the transition has to move:
  # asserting it here is what makes the `https://` assertion afterwards
  # a change rather than a coincidence.
  case "$(jq -r '.openbao_url' "$state")" in
    http://*) pass "OpenBao is recorded on a plaintext URL before init" ;;
    *) fail "state.json does not start on a plaintext URL" ;;
  esac
}

run_init() {
  log "initialising instance ${INSTANCE}"
  if ! run_bootroot init \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --secrets-dir "$SECRETS_DIR" \
    --enable auto-generate,show-secrets,db-provision \
    --stepca-password "registrar-internal-${RUN_TOKEN}" \
    --http-hmac "dev-hmac-${RUN_TOKEN}" \
    --no-eab \
    --save-unseal-keys \
    --overwrite-password \
    --overwrite-ca-json \
    --overwrite-state \
    --confirm-db-provision \
    --db-user "step" \
    --db-name "stepca" \
    --responder-url "http://127.0.0.1:${PORT_HTTP01}" \
    </dev/null >"$INIT_RAW_LOG" 2>&1; then
    {
      echo "bootroot init failed (raw tail):"
      tail -n 200 "$INIT_RAW_LOG" || true
    } >>"$RUN_LOG"
    fail "bootroot init failed; see $INIT_RAW_LOG"
  fi
  sed 's/^\(root token: \).*/\1<redacted>/' "$INIT_RAW_LOG" >"$ARTIFACT_DIR/init.log"
}

# ---------------------------------------------------------------------------
# Assertions
# ---------------------------------------------------------------------------

assert_state_url_moved_to_https() {
  local url
  url="$(jq -r '.openbao_url' "$WORK_DIR/state.json")"
  assert_equal "the recorded OpenBao URL is this install's port over HTTPS" \
    "https://localhost:${PORT_OPENBAO}" "$url"
}

# The listener really terminates TLS: plaintext must not answer where
# HTTPS does.  Verified against the credential's *own* private bundle,
# never with `-k` — which asserts one more thing than a generic TLS
# probe would: that the bundle `init` wrote beside the credential really
# does anchor the listener the credential has to log in over.
assert_listener_serves_tls() {
  local bundle="$INTERNAL_DIR/ca-bundle.pem" code
  [ -s "$bundle" ] || fail "the internal private CA bundle is missing at $bundle"
  code="$(curl -sS -o /dev/null -w '%{http_code}' -m 10 --cacert "$bundle" \
    "https://localhost:${PORT_OPENBAO}/v1/sys/seal-status" 2>>"$RUN_LOG" || true)"
  [ "$code" = "200" ] || fail "the TLS listener did not answer 200 (got '${code}')"
  pass "the listener answers over TLS, verified against the credential's private bundle"

  # A TLS listener still accepts the TCP connection and answers a
  # plaintext request — with `400 Bad Request`, not the API. So the
  # assertion is on the status rather than on curl's exit code, which is
  # zero for any HTTP response at all.
  local plain
  plain="$(curl -sS -o /dev/null -w '%{http_code}' -m 5 \
    "http://localhost:${PORT_OPENBAO}/v1/sys/seal-status" 2>>"$RUN_LOG" || true)"
  [ "$plain" != "200" ] ||
    fail "the API still answers over plaintext on the transitioned listener"
  pass "the API no longer answers over plaintext (got '${plain}')"
}

assert_no_listener_client_cert_options() {
  local hcl="$WORK_DIR/openbao/openbao.hcl" option
  [ -f "$hcl" ] || fail "openbao.hcl is missing at $hcl"
  for option in tls_client_ca_file tls_require_and_verify_client_cert tls_disable_client_certs; do
    if grep -q "$option" "$hcl"; then
      fail "the listener configuration sets ${option}"
    fi
  done
  pass "the listener introduces no client-certificate option"
}

assert_material_is_complete_and_restrictive() {
  local name mode
  for name in key.pem chain.pem acme-account.json root-fingerprint agent.toml; do
    [ -s "$INTERNAL_DIR/$name" ] || fail "missing or empty: $INTERNAL_DIR/$name"
    mode="$(file_mode "$INTERNAL_DIR/$name")"
    [ "$mode" = "600" ] || fail "${name} is mode ${mode}, expected 600"
  done
  pass "the five secret-side artifacts exist at 0600"

  [ -s "$INTERNAL_DIR/ca-bundle.pem" ] || fail "missing the private CA bundle"
  pass "the private CA bundle exists"

  [ ! -d "$INTERNAL_DIR/.staging" ] ||
    fail "the staging directory survived a successful publication"
  pass "the staging directory was swept"
}

assert_generated_config_is_the_internal_one() {
  local config="$INTERNAL_DIR/agent.toml"
  grep -q "service_name = \"${INTERNAL_ENTRY}\"" "$config" ||
    fail "the generated config does not name the fixed identity"
  grep -q "account_key_path = \"${INTERNAL_DIR}/acme-account.json\"" "$config" ||
    fail "the generated config does not point at the persistent ACME account key"
  grep -q "ca_bundle_path = \"${INTERNAL_DIR}/ca-bundle.pem\"" "$config" ||
    fail "the generated config does not point at the private CA bundle"
  # The endpoints follow this install's published ports.  On the compose
  # defaults a hard-coded value looks identical, which is why the ports
  # were moved.
  grep -q "server = \"https://localhost:${PORT_STEPCA}/acme/acme/directory\"" "$config" ||
    fail "the generated config does not use this install's step-ca port"
  grep -q "http_responder_url = \"http://127.0.0.1:${PORT_HTTP01}\"" "$config" ||
    fail "the generated config does not use this install's responder port"
  pass "the generated config names the fixed identity, its private trust and this install's ports"
}

assert_leaf_carries_the_fixed_san() {
  local san
  san="$(python3 - "$INTERNAL_DIR/chain.pem" <<'PY'
import re, ssl, sys, tempfile
pem = open(sys.argv[1]).read()
first = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S).group(0)
with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as handle:
    handle.write(first + "\n")
    path = handle.name
names = ssl._ssl._test_decode_cert(path)
print(",".join(value for key, value in names.get("subjectAltName", ()) if key == "DNS"))
PY
  )" || fail "could not read the issued leaf"
  assert_equal "the issued leaf carries exactly the fixed internal SAN" "$INTERNAL_SAN" "$san"
}

# The criterion this scenario exists for: the credential `init` just
# published authenticates at `auth/cert` over the URL `init` just
# recorded.  Presented as a PEM client certificate through python3's
# `ssl`, which every platform this runs on supports.
assert_certificate_login_succeeds() {
  local out
  out="$(python3 - "$INTERNAL_DIR" "localhost" "$PORT_OPENBAO" "$INTERNAL_ENTRY" <<'PY'
import http.client, json, ssl, sys
cred, host, port, entry = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
context = ssl.create_default_context(cafile=f"{cred}/ca-bundle.pem")
context.load_cert_chain(certfile=f"{cred}/chain.pem", keyfile=f"{cred}/key.pem")
conn = http.client.HTTPSConnection(host, port, context=context, timeout=15)
conn.request("POST", "/v1/auth/cert/login", json.dumps({"name": entry}),
             {"Content-Type": "application/json"})
response = conn.getresponse()
body = json.loads(response.read())
auth = body.get("auth") or {}
print(json.dumps({
    "status": response.status,
    "has_token": bool(auth.get("client_token")),
    "policies": sorted(auth.get("token_policies") or auth.get("policies") or []),
}))
PY
  )" || fail "the certificate login raised; see the traceback above"
  assert_equal "the certificate login is accepted" "200" "$(jq -r .status <<<"$out")"
  assert_equal "the login returns a token" "true" "$(jq -r .has_token <<<"$out")"
  # `token_no_default_policy` is what makes the allowlist the whole
  # grant: a `default` here would widen it well past the verb paths.
  assert_equal "the minted token carries the exact allowlist and nothing else" \
    "[\"${INTERNAL_ENTRY}\"]" "$(jq -c .policies <<<"$out")"
}

# Without a client certificate the same endpoint must refuse: the
# credential is the certificate, so a login that succeeds without one
# would mean the entry is not the gate.
assert_login_without_the_certificate_is_refused() {
  local status
  status="$(python3 - "$INTERNAL_DIR" "localhost" "$PORT_OPENBAO" "$INTERNAL_ENTRY" <<'PY'
import http.client, json, ssl, sys
cred, host, port, entry = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
context = ssl.create_default_context(cafile=f"{cred}/ca-bundle.pem")
conn = http.client.HTTPSConnection(host, port, context=context, timeout=15)
conn.request("POST", "/v1/auth/cert/login", json.dumps({"name": entry}),
             {"Content-Type": "application/json"})
print(conn.getresponse().status)
PY
  )" || fail "the certificate-less login raised"
  [ "$status" != "200" ] || fail "a login with no client certificate was accepted"
  pass "a login with no client certificate is refused (${status})"
}

# The alias is why the ACME challenge above could resolve at all.
# Asserted directly so a future change that drops it fails with the
# reason rather than as an unexplained issuance timeout.
assert_the_responder_answers_to_the_internal_san() {
  local aliases
  aliases="$(docker inspect "${INSTANCE}-http01" \
    --format '{{range .NetworkSettings.Networks}}{{range .Aliases}}{{println .}}{{end}}{{end}}' \
    2>>"$RUN_LOG" || true)"
  grep -qx "$INTERNAL_SAN" <<<"$aliases" ||
    fail "the responder does not answer to ${INTERNAL_SAN}; aliases: $(tr '\n' ' ' <<<"$aliases")"
  pass "the responder answers to the internal SAN"
}

# ---------------------------------------------------------------------------
# Teardown
# ---------------------------------------------------------------------------

capture_artifacts() {
  local service
  for service in openbao step-ca http01 postgres; do
    docker logs "${INSTANCE}-${service}" >"$ARTIFACT_DIR/${service}.log" 2>&1 || true
  done
  [ -f "$WORK_DIR/state.json" ] && cp "$WORK_DIR/state.json" "$ARTIFACT_DIR/state.json" || true
  [ -f "$INTERNAL_DIR/agent.toml" ] &&
    cp "$INTERNAL_DIR/agent.toml" "$ARTIFACT_DIR/registrar-internal-agent.toml" || true
  return 0
}

teardown_instance() {
  local id ids status=0
  if [ -n "$WORK_DIR" ] && [ -f "$WORK_DIR/$COMPOSE_FILE_NAME" ]; then
    instance_compose down -v --remove-orphans >>"$RUN_LOG" 2>&1 || status=1
  fi
  if ids="$(docker ps -aq --filter "label=com.docker.compose.project=${INSTANCE}" 2>>"$RUN_LOG")"; then
    for id in $ids; do
      docker rm -f "$id" >>"$RUN_LOG" 2>&1 || status=1
    done
  else
    status=1
  fi
  if ids="$(docker volume ls -q --filter "label=com.docker.compose.project=${INSTANCE}" 2>>"$RUN_LOG")"; then
    for id in $ids; do
      docker volume rm -f "$id" >>"$RUN_LOG" 2>&1 || status=1
    done
  else
    status=1
  fi
  if ids="$(docker network ls -q --filter "label=com.docker.compose.project=${INSTANCE}" 2>>"$RUN_LOG")"; then
    for id in $ids; do
      docker network rm "$id" >>"$RUN_LOG" 2>&1 || status=1
    done
  else
    status=1
  fi
  return "$status"
}

remove_run_root() {
  [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ] || return 0
  if rm -rf "$RUN_ROOT" 2>/dev/null; then
    return 0
  fi
  # A container may have left material under `secrets/` owned by another
  # uid.  Re-own it through a throwaway container rather than reaching
  # for host privileges.
  local helper
  helper="$(docker inspect --format '{{.Config.Image}}' "${INSTANCE}-openbao" 2>/dev/null || true)"
  if [ -n "$helper" ]; then
    docker run --rm --user root --entrypoint sh -v "${RUN_ROOT}:/mnt" "$helper" \
      -c "chown -R $(id -u):$(id -g) /mnt" >/dev/null 2>&1 || true
  fi
  rm -rf "$RUN_ROOT" 2>/dev/null || true
}

cleanup() {
  local status=$?
  local cleanup_status=0
  log_phase "cleanup"
  capture_artifacts
  teardown_instance || {
    echo "[registrar-internal-init][cleanup] teardown failed; see ${RUN_LOG}" >&2
    cleanup_status=1
  }
  [ "$HTTP01_IMAGE_BUILT" -eq 1 ] &&
    { docker image rm -f "$HTTP01_IMAGE" >>"$RUN_LOG" 2>&1 || true; }
  remove_run_root
  report_project_leftovers "$INSTANCE" "registrar-internal-init cleanup" || cleanup_status=1
  if [ -n "$RUN_ROOT" ] && [ -d "$RUN_ROOT" ]; then
    echo "[registrar-internal-init][cleanup] run root survived: ${RUN_ROOT}" >&2
    cleanup_status=1
  fi
  exit_with_cleanup_status "$status" "$cleanup_status"
}

main() {
  : >"$PHASE_LOG"
  : >"$RUN_LOG"
  log_phase "startup"
  trap cleanup EXIT

  ensure_prerequisites
  log "instance: ${INSTANCE}"
  # The instance name is this run's alone, so anything already carrying
  # its project label is wreckage from a crashed run that shared the
  # token — and installing over it would inherit that state rather than
  # test a fresh one.
  assert_no_project_leftovers "$INSTANCE" "registrar-internal-init start of run"

  log_phase "prepare"
  create_run_root
  build_responder_image
  prepull_third_party_images

  log_phase "install"
  allocate_ports
  install_infra
  wait_for_postgres_admin
  wait_for_openbao_listening

  log_phase "seed-predicate"
  seed_registrar_endpoint_predicate

  log_phase "init"
  run_init

  log_phase "assert-material"
  assert_material_is_complete_and_restrictive
  assert_generated_config_is_the_internal_one
  assert_leaf_carries_the_fixed_san
  assert_the_responder_answers_to_the_internal_san

  log_phase "assert-listener"
  assert_state_url_moved_to_https
  assert_listener_serves_tls
  assert_no_listener_client_cert_options

  log_phase "assert-login"
  assert_certificate_login_succeeds
  assert_login_without_the_certificate_is_refused

  log_phase "done"
  log "endpoint-enabled init checks passed"
  echo "[registrar-internal-init] artifacts: $ARTIFACT_DIR"
}

main "$@"
