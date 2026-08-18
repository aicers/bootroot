#!/usr/bin/env bash
set -euo pipefail

# Docker-backed scenario for the registrar mint/deregister verbs (#758).
#
# The verbs' write-dependent behaviour — durable bindings, the KV v2
# compare-and-set claim, re-mint, wrong-host refusal, the absent-binding
# sweep, teardown-before-unbind ordering, and both concurrency properties
# — cannot be asserted against a canned-response mock without building a
# second implementation of OpenBao's CAS semantics, which is exactly the
# thing a bug in the first one would then agree with.  So they live as
# `#[ignore]`d library tests in `src/registrar/verbs/tests.rs` and this
# scenario is what runs them:
#
#   1. stand a single OpenBao container up on a free loopback port, at
#      the image tag `docker-compose.yml` already pins;
#   2. enable the AppRole auth method the verbs provision into;
#   3. hand the child `cargo test` the URL, the token and the KV mount
#      through the environment, and run the ignored tests.
#
# The connection details travel as environment variables on the child
# process only.  The tests read them and never write them: mutating the
# process environment from a test is unsound in Rust 2024, and there is
# no reason to here.
#
# This is a self-contained OpenBao rather than the full compose stack.
# The verbs touch no step-ca, no PostgreSQL and no responder, and a
# scenario that stood them up anyway would be slower and would fail for
# reasons that have nothing to do with what it is testing.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

RUN_ID="${GITHUB_RUN_ID:-local-$(date +%s)-$$}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/tmp/e2e/registrar-verbs-${RUN_ID}}"
mkdir -p "$ARTIFACT_DIR"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"

PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
TEST_LOG="$ARTIFACT_DIR/cargo-test.log"
OPENBAO_LOG="$ARTIFACT_DIR/openbao.log"

CURRENT_PHASE="startup"
CONTAINER_NAME="bootroot-registrar-verbs-${RUN_ID}"
KV_MOUNT="${KV_MOUNT:-secret}"
READY_ATTEMPTS="${READY_ATTEMPTS:-60}"
READY_DELAY_SECS="${READY_DELAY_SECS:-1}"

log_phase() {
  CURRENT_PHASE="$1"
  printf '{"ts":"%s","phase":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >>"$PHASE_LOG"
  echo "[registrar-verbs][$1]"
}

fail() {
  printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$1" >>"$RUN_LOG" 2>/dev/null || true
  echo "[registrar-verbs][${CURRENT_PHASE}] $1" >&2
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
OPENBAO_URL="http://127.0.0.1:${OPENBAO_HOST_PORT}"

# A throwaway root token for a throwaway container published on loopback
# only.  Drawn from the system CSPRNG all the same, because a predictable
# one would be a habit worth not forming.  Read straight from
# /dev/urandom rather than through `openssl rand`: this scenario needs no
# openssl, and a `command -v openssl` here would be the bare
# existence check `validate-e2e-openssl-compat.sh` exists to keep out of
# scripts/impl.
OPENBAO_TOKEN="root-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
[ -n "${OPENBAO_TOKEN#root-}" ] || fail "could not generate a dev root token"

log_phase "openbao-up"
echo "[registrar-verbs] image=$OPENBAO_IMAGE port=$OPENBAO_HOST_PORT" >>"$RUN_LOG"
docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
docker run -d \
  --name "$CONTAINER_NAME" \
  -p "127.0.0.1:${OPENBAO_HOST_PORT}:8200" \
  -e "BAO_DEV_ROOT_TOKEN_ID=${OPENBAO_TOKEN}" \
  -e "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
  "$OPENBAO_IMAGE" server -dev >>"$RUN_LOG" 2>&1 ||
  fail "could not start $OPENBAO_IMAGE"

log_phase "openbao-ready"
ready=0
for _ in $(seq 1 "$READY_ATTEMPTS"); do
  if curl -fsS "${OPENBAO_URL}/v1/sys/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep "$READY_DELAY_SECS"
done
[ "$ready" -eq 1 ] || {
  collect_openbao_log
  fail "OpenBao did not become ready on ${OPENBAO_URL}"
}

# Dev mode mounts KV v2 at `secret/` already; AppRole is not enabled by
# default and the verbs provision roles into it.  Enabling it twice is a
# 400, so an already-enabled mount is not a failure.
log_phase "enable-approle"
enable_status="$(curl -sS -o "$ARTIFACT_DIR/enable-approle.json" -w '%{http_code}' \
  -X POST \
  -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
  -d '{"type":"approle"}' \
  "${OPENBAO_URL}/v1/sys/auth/approle" || true)"
case "$enable_status" in
  2*) ;;
  400)
    grep -q "path is already in use" "$ARTIFACT_DIR/enable-approle.json" ||
      fail "could not enable the AppRole auth method (HTTP $enable_status)"
    ;;
  *) fail "could not enable the AppRole auth method (HTTP $enable_status)" ;;
esac

# Assert the mount the tests are told to use really is KV v2, so a
# misconfiguration surfaces here rather than as a puzzling 400 inside a
# compare-and-set assertion.
log_phase "verify-kv-mount"
curl -fsS -H "X-Vault-Token: ${OPENBAO_TOKEN}" \
  "${OPENBAO_URL}/v1/sys/mounts/${KV_MOUNT}" >"$ARTIFACT_DIR/kv-mount.json" 2>>"$RUN_LOG" ||
  fail "KV mount ${KV_MOUNT} is not present"
grep -q '"version": *"2"' "$ARTIFACT_DIR/kv-mount.json" ||
  fail "KV mount ${KV_MOUNT} is not version 2"

log_phase "run-ignored-library-tests"
set +e
BOOTROOT_REGISTRAR_TEST_OPENBAO_URL="$OPENBAO_URL" \
BOOTROOT_REGISTRAR_TEST_OPENBAO_TOKEN="$OPENBAO_TOKEN" \
BOOTROOT_REGISTRAR_TEST_KV_MOUNT="$KV_MOUNT" \
  cargo test --lib registrar::verbs::tests -- --ignored 2>&1 | tee "$TEST_LOG"
status="${PIPESTATUS[0]}"
set -e
[ "$status" -eq 0 ] || fail "the ignored registrar verb tests failed (see $TEST_LOG)"

log_phase "done"
echo "[registrar-verbs] artifacts: $ARTIFACT_DIR"
