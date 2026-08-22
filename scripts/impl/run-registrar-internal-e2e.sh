#!/usr/bin/env bash
set -euo pipefail

# Docker-backed scenario for the bootroot-internal credential's
# `auth/cert` contract (#766).
#
# The mocked tests in `src/registrar/internal/tests.rs` prove the request
# shapes: which fields the entry is written with, and that the login
# carries no bearer token.  They cannot prove what OpenBao *does* with
# those fields.  A misspelt `allowed_dns_sans`, a
# `token_no_default_policy` the backend ignores, or a policy body whose
# paths do not mean what they look like would satisfy every one of them
# and still leave the daemon holding a credential that either cannot log
# in or can do more than it should.  Asserting that against a canned
# mock would mean reimplementing OpenBao's ACL engine, which a bug in the
# first implementation would then agree with.  So those assertions live
# as `#[ignore]`d library tests and this scenario is what runs them:
#
#   1. stand a single OpenBao container up on a free loopback port, at
#      the image tag `docker-compose.yml` already pins, serving its own
#      dev TLS certificate;
#   2. hand the child `cargo test` the HTTPS URL, the token, that
#      certificate's CA and the KV mount through the environment;
#   3. run the ignored tests.
#
# TLS is not optional here and is the whole reason this scenario is
# separate from the verbs one: `auth/cert` authenticates a *client
# certificate*, so there has to be a handshake to present it in.  The
# container's `-dev-tls` mode generates the server certificate and writes
# it to a mounted directory, which keeps the two trust anchors as
# separate as they are in a deployment: the scenario's CA verifies the
# server, and a CA each test mints is what the entry trusts for clients.
#
# The connection details travel as environment variables on the child
# process only.  The tests read them and never write them: mutating the
# process environment from a test is unsound in Rust 2024, and there is
# no reason to here.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)-$$}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/registrar-internal-${RUN_ID}}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
TEST_LOG="$ARTIFACT_DIR/cargo-test.log"
OPENBAO_LOG="$ARTIFACT_DIR/openbao.log"
TLS_DIR="$ARTIFACT_DIR/tls"

CURRENT_PHASE="startup"
CONTAINER_NAME="bootroot-registrar-internal-${RUN_ID}"
KV_MOUNT="${KV_MOUNT:-secret}"
READY_ATTEMPTS="${READY_ATTEMPTS:-60}"
READY_DELAY_SECS="${READY_DELAY_SECS:-1}"

log_phase() {
  CURRENT_PHASE="$1"
  printf '{"ts":"%s","phase":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >>"$PHASE_LOG"
  echo "[registrar-internal][$1]"
}

fail() {
  printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$1" >>"$RUN_LOG" 2>/dev/null || true
  echo "[registrar-internal][${CURRENT_PHASE}] $1" >&2
  exit 1
}

# shellcheck source=lib/ports.sh
. "$SCRIPT_DIR/lib/ports.sh"

# Collects the container's output, with the dev root token redacted.
# `server -dev` prints "Root Token: <value>" on startup, and this log is
# uploaded as a CI artifact; the token dies with the container a moment
# later, but a live credential does not belong in a build artifact on the
# way there.
collect_openbao_log() {
  docker logs "$CONTAINER_NAME" 2>&1 |
    sed "s|${OPENBAO_TOKEN}|<redacted>|g" >>"$OPENBAO_LOG" || true
}

cleanup() {
  # Best effort, but the logs are collected first: a container removed
  # before its output was read leaves a failure with nothing to read.
  if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    collect_openbao_log
    docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
  fi
  # The server key the container generated is the one secret this
  # scenario writes to disk, and the artifact directory is uploaded.
  rm -f "$TLS_DIR"/*-key.pem 2>/dev/null || true
}
trap cleanup EXIT

command -v docker >/dev/null 2>&1 || fail "docker is required"
command -v curl >/dev/null 2>&1 || fail "curl is required"
command -v cargo >/dev/null 2>&1 || fail "cargo is required"

# One pinned image for the whole repository: read it out of the compose
# file rather than restating it here, so a bump lands in both places at
# once.
OPENBAO_IMAGE="$(awk '/^  openbao:/{found=1} found && /image: openbao\//{print $2; exit}' \
  "$ROOT_DIR/docker-compose.yml")"
[ -n "$OPENBAO_IMAGE" ] || fail "could not read the OpenBao image tag from docker-compose.yml"

log_phase "allocate-port"
pick_free_port
OPENBAO_HOST_PORT="$PICKED_PORT"
OPENBAO_URL="https://127.0.0.1:${OPENBAO_HOST_PORT}"

# A throwaway root token for a throwaway container published on loopback
# only.  Drawn from the system CSPRNG all the same, because a predictable
# one would be a habit worth not forming.  Read straight from
# /dev/urandom rather than through `openssl rand`: this scenario needs no
# openssl, and a `command -v openssl` here would be the bare existence
# check `validate-e2e-openssl-compat.sh` exists to keep out of
# scripts/impl.
OPENBAO_TOKEN="root-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
[ -n "${OPENBAO_TOKEN#root-}" ] || fail "could not generate a dev root token"

# The container writes its generated certificate here as its own uid, so
# the directory has to be writable by it.  Nothing secret of ours goes in
# it, and the server key it does write is removed on the way out.
log_phase "tls-dir"
rm -rf "$TLS_DIR"
mkdir -p "$TLS_DIR"
chmod 777 "$TLS_DIR"

log_phase "openbao-up"
echo "[registrar-internal] image=$OPENBAO_IMAGE port=$OPENBAO_HOST_PORT" >>"$RUN_LOG"
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d \
  --name "$CONTAINER_NAME" \
  -p "127.0.0.1:${OPENBAO_HOST_PORT}:8200" \
  -e "BAO_DEV_ROOT_TOKEN_ID=${OPENBAO_TOKEN}" \
  -v "${TLS_DIR}:/tls" \
  "$OPENBAO_IMAGE" server -dev -dev-tls -dev-tls-cert-dir=/tls \
  -dev-listen-address=0.0.0.0:8200 >>"$RUN_LOG" 2>&1 ||
  fail "could not start $OPENBAO_IMAGE"

# The dev-TLS CA the container generates.  Named rather than globbed so a
# rename upstream fails here, with the directory listing in the log,
# instead of surfacing as an unexplained handshake failure in a test.
SERVER_CA="$TLS_DIR/vault-ca.pem"

log_phase "openbao-ready"
ready=0
for _ in $(seq 1 "$READY_ATTEMPTS"); do
  if [ -s "$SERVER_CA" ] &&
    curl -fsS --cacert "$SERVER_CA" "${OPENBAO_URL}/v1/sys/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep "$READY_DELAY_SECS"
done
[ "$ready" -eq 1 ] || {
  ls -la "$TLS_DIR" >>"$RUN_LOG" 2>&1 || true
  collect_openbao_log
  fail "OpenBao did not become ready over TLS on ${OPENBAO_URL}"
}

# Assert the mount the tests are told to use really is KV v2, so a
# misconfiguration surfaces here rather than as a puzzling 403-versus-404
# distinction inside an allow/deny assertion.
log_phase "verify-kv-mount"
curl -fsS --cacert "$SERVER_CA" -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
  "${OPENBAO_URL}/v1/sys/mounts/${KV_MOUNT}" >"$ARTIFACT_DIR/kv-mount.json" 2>>"$RUN_LOG" ||
  fail "KV mount ${KV_MOUNT} is not present"
grep -q '"version": *"2"' "$ARTIFACT_DIR/kv-mount.json" ||
  fail "KV mount ${KV_MOUNT} is not version 2"

log_phase "run-ignored-library-tests"
set +e
BOOTROOT_INTERNAL_TEST_OPENBAO_URL="$OPENBAO_URL" \
BOOTROOT_INTERNAL_TEST_OPENBAO_TOKEN="$OPENBAO_TOKEN" \
BOOTROOT_INTERNAL_TEST_SERVER_CA="$SERVER_CA" \
BOOTROOT_INTERNAL_TEST_KV_MOUNT="$KV_MOUNT" \
  cargo test --lib registrar::internal::tests::live -- --ignored 2>&1 | tee "$TEST_LOG"
status="${PIPESTATUS[0]}"
set -e
[ "$status" -eq 0 ] || fail "the ignored bootroot-internal tests failed (see $TEST_LOG)"

# A scenario that ran no test is a scenario that proved nothing, and
# `cargo test` exits 0 when a filter matches nothing at all.
grep -qE 'test result: ok\. [1-9][0-9]* passed' "$TEST_LOG" ||
  fail "the ignored bootroot-internal tests did not run (see $TEST_LOG)"

log_phase "done"
echo "[registrar-internal] artifacts: $ARTIFACT_DIR"
