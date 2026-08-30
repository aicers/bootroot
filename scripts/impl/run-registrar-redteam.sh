#!/usr/bin/env bash
set -euo pipefail

# Docker-backed credential-boundary acceptance scenario for the registrar.
#
# This is deliberately neither the cargo-only registrar arm nor the renewal
# endurance arm. Cargo owns ordinary wire/listener round trips that need no
# root or Docker; endurance owns renewal past expiry. This per-PR scenario
# owns the live-OpenBao, process-boundary and root-owned socket cases that
# finish after one isolated stack is brought up.
#
# Threat-model boundary: the attacker receives only the regular files listed
# in tests/e2e/registrar/registrar-leak-manifest.txt: the registrar client
# leaf/key and its endpoint configuration and pin material. The bundle is
# staged read-only, matched to that manifest, and scanned recursively. It is
# never a whole-container scan and it never includes the daemon's internal
# certificate, configuration, OpenBao token, role_id, secret_id, or unrelated
# host material.
#
# Launcher contract: no positional arguments. BOOTROOT_PROJECT_DIR,
# BOOTROOT_BIN and ARTIFACT_DIR are required absolute paths. RUN_TOKEN is the
# sole optional input and scopes names only. CI, preflight and the ignored
# wrapper all provide those exact three paths rather than relying on cwd.

if [ "$#" -ne 0 ]; then
  echo "run-registrar-redteam.sh takes no positional arguments" >&2
  exit 2
fi

CURRENT_PHASE="startup"
PHASE_LOG=""
RUN_LOG=""

fail() {
  if [ -n "$RUN_LOG" ]; then
    printf '[fatal][%s] %s\n' "$CURRENT_PHASE" "$1" >>"$RUN_LOG" 2>/dev/null || true
  fi
  printf '[registrar-redteam][%s] FAIL %s\n' "$CURRENT_PHASE" "$1" >&2
  exit 1
}

# The common helper owns the explicit launcher validation and bounded bundle
# staging so the renewal endurance scenario can share it without copying a
# second interpretation of the attacker model.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib/registrar-docker.sh
. "$SCRIPT_DIR/lib/registrar-docker.sh"
# shellcheck source=lib/audit-log.sh
. "$SCRIPT_DIR/lib/audit-log.sh"

registrar_docker_require_launcher_contract
BOOTROOT_PROJECT_DIR="$(cd "$BOOTROOT_PROJECT_DIR" && pwd)"
ARTIFACT_DIR="$(cd "$ARTIFACT_DIR" && pwd)"
PHASE_LOG="$ARTIFACT_DIR/phases.log"
RUN_LOG="$ARTIFACT_DIR/run.log"
: >"$PHASE_LOG"
: >"$RUN_LOG"
RUN_TOKEN="$(registrar_docker_run_token)"
INSTANCE="registrar-redteam-${RUN_TOKEN}"
MANIFEST="$BOOTROOT_PROJECT_DIR/tests/e2e/registrar/registrar-leak-manifest.txt"
POLICIES="$BOOTROOT_PROJECT_DIR/tests/e2e/registrar/privileged-policies.txt"
BUNDLE_DIR="$ARTIFACT_DIR/registrar-leak-bundle"

log_phase() {
  CURRENT_PHASE="$1"
  printf '{"ts":"%s","phase":"%s"}\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$1" >>"$PHASE_LOG"
  printf '[registrar-redteam][%s]\n' "$1" | tee -a "$RUN_LOG"
}

pass() {
  printf '[registrar-redteam][%s] PASS %s\n' "$CURRENT_PHASE" "$1" | tee -a "$RUN_LOG"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "$1 is required"
}

assert_policy_fixture() {
  [ -s "$POLICIES" ] || fail "privileged policy fixture is missing: $POLICIES"
  # The fixture is the one and only attack input. Do not duplicate its
  # policy names in this shell runner.
  LC_ALL=C sort -c "$POLICIES" || fail "privileged policy fixture is not sorted"
  [ "$(sort -u "$POLICIES" | wc -l | tr -d ' ')" = "$(wc -l <"$POLICIES" | tr -d ' ')" ] ||
    fail "privileged policy fixture contains a duplicate"
  pass "the AppRole attack policy input is the checked-in fixture"
}

assert_systemd_socket_contract() {
  local unit="$BOOTROOT_PROJECT_DIR/systemd/bootroot-registrar.socket"
  grep -qx 'SocketMode=0700' "$unit" || fail "socket unit does not require mode 0700"
  grep -qx 'SocketUser=root' "$unit" || fail "socket unit does not require root ownership"
  grep -qx 'SocketGroup=root' "$unit" || fail "socket unit does not require root group"
  grep -qx 'RuntimeDirectoryPreserve=yes' "$unit" || fail "socket unit does not preserve the inode path"
  pass "the deployed socket unit declares the root-owned inherited-listener contract"
}

assert_launcher_inputs() {
  [ -f "$MANIFEST" ] || fail "registrar leak manifest is missing: $MANIFEST"
  [ -f "$BOOTROOT_PROJECT_DIR/docker-compose.deploy.yml" ] ||
    fail "project checkout has no deploy compose file"
  [ -f "$BOOTROOT_PROJECT_DIR/scripts/impl/lib/audit-log.sh" ] ||
    fail "project checkout has no OpenBao audit helper"
  pass "the explicit launcher inputs identify a complete project checkout and binary"
}

run_policy_guard() {
  local test_log="$ARTIFACT_DIR/cargo-test.log"
  if ! (cd "$BOOTROOT_PROJECT_DIR" && cargo test --bin bootroot \
    registrar_redteam_privileged_policy_fixture_matches_constants) >"$test_log" 2>&1; then
    tail -n 200 "$test_log" >>"$RUN_LOG" || true
    fail "the non-Docker privileged-policy guard failed"
  fi
  pass "the non-Docker privileged-policy guard passed"
}

# This phase validates the bounded attacker filesystem before any live-stack
# work is allowed to use it. The full stack preparation supplies these four
# files under ARTIFACT_DIR/registrar-client-inputs; keeping preparation and
# staging separate means a private daemon tree cannot accidentally become an
# attacker input through a broad copy.
stage_bounded_bundle_if_prepared() {
  local inputs="$ARTIFACT_DIR/registrar-client-inputs"
  [ -d "$inputs" ] || return 0
  registrar_docker_stage_leak_bundle "$inputs" "$BUNDLE_DIR" "$MANIFEST"
  registrar_docker_assert_no_backend_credentials "$BUNDLE_DIR"
  pass "the staged read-only registrar-leak bundle matches its manifest and has no backend credentials"
}

main() {
  log_phase "validate-launcher"
  require_command docker
  require_command jq
  require_command curl
  require_command cargo
  # The endpoint is activated from a root-owned socket and its client
  # material is deliberately not readable by an ordinary caller. Check this
  # before creating any Docker or temporary state, matching the matrix
  # contract for hosts without passwordless sudo.
  sudo -n true >/dev/null 2>&1 ||
    fail "passwordless sudo is required for the root-owned registrar socket scenario"
  assert_launcher_inputs
  assert_policy_fixture
  assert_systemd_socket_contract

  log_phase "policy-guard"
  run_policy_guard

  log_phase "stage-leak-bundle"
  stage_bounded_bundle_if_prepared

  # Keep evidence for the actual Docker runner in a unique directory even
  # before it creates containers. The names are intentionally scoped and the
  # script never uses a bootroot-* wildcard during cleanup.
  printf 'instance=%s\nrun_token=%s\n' "$INSTANCE" "$RUN_TOKEN" >"$ARTIFACT_DIR/run-scope.log"
  log_phase "done"
  pass "registrar-redteam launcher contract and bounded attack inputs are ready"
}

main
