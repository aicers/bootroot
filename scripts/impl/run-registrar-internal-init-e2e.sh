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
#
# `init` itself runs as root here (#880).  The five protected artifacts
# below the internal directory are published uid 0 / gid 0, and a
# process that cannot establish that ownership publishes none of them,
# so an endpoint-enabled `init` is a privileged command and this
# scenario is the only place that is observable end to end.  Everything
# else still runs as the invoking user; the reads that touch the
# root-owned `0700` internal directory go through `sudo -n` one call at
# a time rather than the whole run being elevated.  Passwordless sudo is
# therefore a prerequisite, and a machine without it cannot run this
# scenario at all — `ensure_prerequisites` says so rather than letting
# `init` fail with a permission error two minutes in.

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
CURL_BIN=""
PYTHON_BIN=""
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

# uid, gid and mode of a file below the root-owned internal directory,
# in one probe.  GNU and BSD `stat` spell the format differently and
# both are tried, as the mode probe this replaces did.
file_owner_mode() {
  sudo -n stat -c '%u:%g:%a' "$1" 2>/dev/null || sudo -n stat -f '%u:%g:%OLp' "$1"
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
  # Resolved here and invoked by absolute path under `sudo`: sudo's
  # `secure_path` is not this shell's `PATH`, and a python3 or curl from
  # a package manager prefix is exactly what it drops.
  CURL_BIN="$(command -v curl)"
  PYTHON_BIN="$(command -v python3)"
  # Endpoint-enabled `init` publishes the five protected artifacts uid 0
  # / gid 0 and refuses to publish any of them otherwise, so this
  # scenario cannot run unprivileged.  Probed before anything is
  # installed: a prompt-free failure now beats a permission error after
  # a deployment has been brought up, and `sudo -n` is what keeps this
  # from blocking on a password nobody is there to type.
  sudo -n true >/dev/null 2>&1 ||
    fail "passwordless sudo is required: endpoint-enabled 'bootroot init' publishes the \
bootroot-internal credential as root, and this scenario runs it through 'sudo -n'"
  [ -x "$BOOTROOT_BIN" ] || fail "bootroot binary not executable: $BOOTROOT_BIN"
  [ -n "$RUN_TOKEN" ] || fail "RUN_TOKEN reduced to the empty string; supply a token of [a-z0-9]"
  [ "${#INSTANCE}" -le "$MAX_INSTANCE_NAME_LEN" ] ||
    fail "derived instance name '${INSTANCE}' exceeds ${MAX_INSTANCE_NAME_LEN} characters"
}

run_bootroot() {
  (cd "$WORK_DIR" && BOOTROOT_LANG=en "$BOOTROOT_BIN" "$@")
}

# `bootroot` as root, for the one command that has to be.
#
# `env` rather than `sudo -E`: only the three variables named here cross
# the boundary.  `BOOTROOT_LANG` keeps the run on the English strings
# every assertion below matches on, and `HOME` stays the invoking user's
# because `init` drives the Docker CLI, which reads its client
# configuration — the daemon endpoint and any credential helper — out of
# `$HOME/.docker`.  Root's own `HOME` has none of that.
#
# `BOOTROOT_HTTP01_IMAGE` is the run-scoped responder tag this scenario
# built locally, and the compose file interpolates it with a default of
# the *untagged* repository name.  Dropping it at the sudo boundary does
# not fall back to the image on this host: it names one that exists in
# no registry, and the `docker compose up` `init` performs for the
# responder override fails on a pull nobody can satisfy.
run_bootroot_as_root() {
  (cd "$WORK_DIR" && sudo -n env \
    BOOTROOT_LANG=en \
    HOME="$HOME" \
    BOOTROOT_HTTP01_IMAGE="$HTTP01_IMAGE" \
    "$BOOTROOT_BIN" "$@")
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
  if ! run_bootroot_as_root init \
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
  # Every read below is elevated because the directory these files sit
  # in is `0700` root-owned once a root-run `init` has created it — not
  # because the bundle itself is protected material, which it is not.
  sudo -n test -s "$bundle" || fail "the internal private CA bundle is missing at $bundle"
  code="$(sudo -n "$CURL_BIN" -sS -o /dev/null -w '%{http_code}' -m 10 --cacert "$bundle" \
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
  local name probe
  for name in key.pem chain.pem acme-account.json root-fingerprint agent.toml; do
    sudo -n test -s "$INTERNAL_DIR/$name" || fail "missing or empty: $INTERNAL_DIR/$name"
    # uid 0 and gid 0 are the criterion this run exists to prove: the
    # key and the ACME account key are unreadable to anyone but root,
    # and the config carrying the trust pins is unwritable to them.  The
    # mode is asserted alongside as the regression guard it has been
    # since #766.
    probe="$(file_owner_mode "$INTERNAL_DIR/$name")"
    [ "$probe" = "0:0:600" ] ||
      fail "${name} is uid:gid:mode ${probe}, expected 0:0:600"
  done
  pass "the five protected artifacts are root-owned at 0600"

  sudo -n test -s "$INTERNAL_DIR/ca-bundle.pem" || fail "missing the private CA bundle"
  pass "the private CA bundle exists"

  sudo -n test ! -d "$INTERNAL_DIR/.staging" ||
    fail "the staging directory survived a successful publication"
  pass "the staging directory was swept"

  # The prior-set snapshot the publication holds the old credential in.
  # A completed publication discards it; one that survives means the
  # publication (or the restore after it) did not finish.
  sudo -n test ! -d "$INTERNAL_DIR/.prior" ||
    fail "the prior-set snapshot survived a successful publication"
  pass "the prior-set snapshot was discarded"
}

assert_generated_config_is_the_internal_one() {
  local config="$INTERNAL_DIR/agent.toml" text
  # Read once, elevated, and matched in the shell: the config is
  # root-owned `0600` and holds the responder HMAC, so it is neither
  # readable here nor worth copying anywhere.
  text="$(sudo -n cat "$config")" || fail "the generated config could not be read at $config"
  grep -q "service_name = \"${INTERNAL_ENTRY}\"" <<<"$text" ||
    fail "the generated config does not name the fixed identity"
  grep -q "account_key_path = \"${INTERNAL_DIR}/acme-account.json\"" <<<"$text" ||
    fail "the generated config does not point at the persistent ACME account key"
  grep -q "ca_bundle_path = \"${INTERNAL_DIR}/ca-bundle.pem\"" <<<"$text" ||
    fail "the generated config does not point at the private CA bundle"
  # The endpoints follow this install's published ports.  On the compose
  # defaults a hard-coded value looks identical, which is why the ports
  # were moved.
  grep -q "server = \"https://localhost:${PORT_STEPCA}/acme/acme/directory\"" <<<"$text" ||
    fail "the generated config does not use this install's step-ca port"
  grep -q "http_responder_url = \"http://127.0.0.1:${PORT_HTTP01}\"" <<<"$text" ||
    fail "the generated config does not use this install's responder port"
  pass "the generated config names the fixed identity, its private trust and this install's ports"
}

assert_leaf_carries_the_fixed_san() {
  local san
  san="$(sudo -n "$PYTHON_BIN" - "$INTERNAL_DIR/chain.pem" <<'PY'
import re, ssl, sys, tempfile
pem = open(sys.argv[1]).read()
first = re.search(r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, re.S).group(0)
with tempfile.NamedTemporaryFile("w", suffix=".pem") as handle:
    handle.write(first + "\n")
    handle.flush()
    names = ssl._ssl._test_decode_cert(handle.name)
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
  out="$(sudo -n "$PYTHON_BIN" - "$INTERNAL_DIR" "localhost" "$PORT_OPENBAO" "$INTERNAL_ENTRY" <<'PY'
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
  status="$(sudo -n "$PYTHON_BIN" - "$INTERNAL_DIR" "localhost" "$PORT_OPENBAO" "$INTERNAL_ENTRY" <<'PY'
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

# Everything the OpenBao Agent sidecars open still belongs to the tree
# they run in, after a root-run `init` wrote all of it.
#
# They are the only containers `init` both configures and starts that
# run as an ordinary uid: the generated override launches each one as
# the owner of `secrets/`, which on this host is the invoking user and
# not the root that ran `init`.  Their `agent.hcl`, their `AppRole`
# pair, the `.ctmpl` files they render from and the `0700` directories
# all of those sit in must therefore carry that owner rather than the
# writing process's — a `0700` directory owned by root hides every file
# inside it whatever the file itself is owned by.
#
# Asserted on the tree rather than on container state, because a
# regression here is quiet from the outside: the containers still
# start, `init` still succeeds, and the renewals the sidecars exist to
# perform simply stop.
assert_the_infra_agent_tree_belongs_to_its_sidecars() {
  local owner probe path
  probe="$(file_owner_mode "$SECRETS_DIR")"
  owner="${probe%:*}"
  for path in \
    openbao \
    openbao/stepca \
    openbao/responder \
    openbao/stepca/agent.hcl \
    openbao/stepca/role_id \
    openbao/stepca/secret_id \
    openbao/responder/agent.hcl \
    openbao/responder/role_id \
    openbao/responder/secret_id \
    templates \
    templates/password.txt.ctmpl \
    templates/ca.json.ctmpl \
    templates/responder.toml.ctmpl \
    responder \
    responder/responder.toml \
    password.txt; do
    sudo -n test -e "$SECRETS_DIR/$path" || fail "missing: $SECRETS_DIR/$path"
    probe="$(file_owner_mode "$SECRETS_DIR/$path")"
    [ "${probe%:*}" = "$owner" ] ||
      fail "${path} is owned by ${probe%:*}, not by the secrets tree (${owner}) the sidecars run as"
  done
  pass "the sidecars' configuration, credentials and templates belong to the secrets tree"
}

# `bootroot infra up` over the deployment `init` just provisioned.
#
# `infra up` ends in a recursive ownership sweep: a one-shot root
# container that chowns everything below `secrets/` to that directory's
# own owner, so a `--user root` step helper cannot leave CA material
# step-ca and the sidecars are unable to read.  It is therefore the one
# routine command that could quietly undo everything asserted above —
# without any protected file being republished, and on a host where the
# operator did nothing more than restart the stack.  The same sweep is
# reached by `reinit` and by the CA and step-ca-password rotations, so
# covering it once here covers the shape of all of them.
#
# Run as the invoking user rather than through `sudo -n`, because that
# is the case that used to regress: the sweep's root container can chown
# the root-owned files whatever the invoking process could.
#
# `--openbao-url` is passed explicitly.  `init` transitioned the
# listener to TLS on this port, and `infra up`'s own derivation only
# ever replaces the port in the `http://` default, so the unseal probe
# would open a plaintext request against a TLS listener and never get an
# answer.
run_infra_up_over_the_initialised_deployment() {
  log "running 'infra up' over the initialised deployment"
  run_bootroot infra up \
    --compose-file "$WORK_DIR/$COMPOSE_FILE_NAME" \
    --openbao-url "https://localhost:${PORT_OPENBAO}" \
    >>"$RUN_LOG" 2>&1 || fail "infra up failed after init"
  pass "'infra up' completed over the initialised deployment"
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
  # Elevated, and re-owned to the invoking user afterwards: a root-owned
  # file left in the artifact directory outlives this run and the user
  # who has to read it cannot remove it.
  # Reached by the cleanup of a run that failed its prerequisites too,
  # where sudo has already been established as unavailable; its
  # complaint goes to the run log rather than on top of the refusal that
  # already explained itself.
  if sudo -n test -f "$INTERNAL_DIR/agent.toml" 2>>"$RUN_LOG"; then
    sudo -n cp "$INTERNAL_DIR/agent.toml" "$ARTIFACT_DIR/registrar-internal-agent.toml" &&
      sudo -n chown "$(id -u):$(id -g)" "$ARTIFACT_DIR/registrar-internal-agent.toml" || true
  fi
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
  [ -d "$RUN_ROOT" ] || return 0
  # What is left is this run's own root-owned output: the `0700`
  # internal directory and the five protected files a root `init`
  # published there.  The path is this run's `mktemp -d`, never an
  # operator's, and the containers that could still be holding it open
  # are gone by the time cleanup reaches here.
  sudo -n rm -rf "$RUN_ROOT" 2>>"$RUN_LOG" || true
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
  assert_the_infra_agent_tree_belongs_to_its_sidecars

  log_phase "assert-listener"
  assert_state_url_moved_to_https
  assert_listener_serves_tls
  assert_no_listener_client_cert_options

  log_phase "assert-login"
  assert_certificate_login_succeeds
  assert_login_without_the_certificate_is_refused

  # Last, because it re-runs the two ownership assertions against a
  # deployment a later command has passed over: the protected five must
  # still be root's, and the sidecar tree must still be the sweep's to
  # repair.  A sweep that swept everything would fail the first; a
  # sweep narrowed too far would fail the second.
  log_phase "assert-sweep"
  run_infra_up_over_the_initialised_deployment
  assert_material_is_complete_and_restrictive
  assert_the_infra_agent_tree_belongs_to_its_sidecars

  log_phase "done"
  log "endpoint-enabled init checks passed"
  echo "[registrar-internal-init] artifacts: $ARTIFACT_DIR"
}

main "$@"
