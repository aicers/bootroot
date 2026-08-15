#!/usr/bin/env bash
#
# Validates the E2E harness's teardown assertions (`scripts/impl/lib/
# leftovers.sh`) without Docker and without bringing a stack up.
#
# None of it is observable from a green CI run. The checks fire only on
# a host that already carries bootroot containers, or after a teardown
# that failed to remove its own — neither of which a passing run ever
# reaches. A check that silently stopped matching, or one that started
# resolving the instance name out of the ambient environment, would
# therefore leave the whole matrix green and surface only as the
# confusing mid-run failure the checks exist to replace.
#
# The library is sourced rather than copied, so this validates the
# shipped code. `docker` is a stub on PATH: what is under test is which
# names the check asks about and what it says when they exist, not
# Docker.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LABEL="validate-e2e-leftover-check"
IMPL_DIR="$ROOT_DIR/scripts/impl"

# shellcheck source=impl/lib/leftovers.sh
. "$IMPL_DIR/lib/leftovers.sh"

# The library aborts through `fail` and reports a satisfied assertion
# through `pass`, both of which its callers define. These are this
# script's copies of that contract.
fail() {
  printf 'FAIL %s\n' "$1" >&2
  exit 1
}

pass() {
  printf 'PASS %s\n' "$1"
}

die() {
  echo "[$LABEL] FAIL: $1" >&2
  exit 1
}

ok() {
  echo "[$LABEL] ok: $1"
}

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# The harnesses installing at the default identity check for these nine
# container names and no others.
EXPECTED_SUFFIXES=(
  -openbao
  -postgres
  -ca
  -http01
  -prometheus
  -grafana
  -grafana-public
  -openbao-agent-stepca
  -openbao-agent-responder
)

# ---------------------------------------------------------------------------
# The container set matches the one bootroot itself creates
# ---------------------------------------------------------------------------
#
# The shell check cannot call `BootrootContainer::ALL`, so it carries
# the suffixes as a literal. A container added to the enum and not here
# would be created by an install and looked for by nothing.
check_suffixes_match_the_rust_enum() {
  local rust_suffixes shell_suffixes expected_suffixes
  rust_suffixes="$(sed -n 's/^ *Self::[A-Za-z0-9]* => "\(-[a-z0-9-]*\)",$/\1/p' \
    src/commands/container_name.rs)"
  [ "$(wc -l <<<"$rust_suffixes")" -eq 9 ] \
    || die "expected 9 suffixes from BootrootContainer::suffix, read: ${rust_suffixes//$'\n'/ }"

  shell_suffixes="$(printf '%s\n' "${BOOTROOT_CONTAINER_SUFFIXES[@]}")"
  [ "$shell_suffixes" = "$rust_suffixes" ] \
    || die "lib/leftovers.sh suffixes drifted from BootrootContainer::suffix"

  expected_suffixes="$(printf '%s\n' "${EXPECTED_SUFFIXES[@]}")"
  [ "$shell_suffixes" = "$expected_suffixes" ] \
    || die "lib/leftovers.sh no longer carries the nine expected suffixes"
  ok "the checked container names are exactly the ones bootroot creates"
}

# ---------------------------------------------------------------------------
# Instance-name resolution
# ---------------------------------------------------------------------------

# Runs `resolve_recorded_instance_name` over a compose directory holding
# `env_contents` (or no `.env` at all, for the literal `<none>`), with
# `BOOTROOT_INSTANCE` and `COMPOSE_PROJECT_NAME` set in the environment
# to values that must not reach the answer.
resolve_case() {
  local env_contents="$1" case_dir
  case_dir="$(mktemp -d "$WORK_DIR/compose.XXXXXX")"
  if [ "$env_contents" != "<none>" ]; then
    printf '%s' "$env_contents" >"$case_dir/.env"
  fi
  BOOTROOT_INSTANCE="ambient-instance" COMPOSE_PROJECT_NAME="ambient-project" \
    resolve_recorded_instance_name "$case_dir"
}

expect_resolved() {
  local description="$1" env_contents="$2" expected="$3" actual
  actual="$(resolve_case "$env_contents")" \
    || die "resolving ${description} failed"
  [ "$actual" = "$expected" ] \
    || die "${description}: resolved '${actual}', expected '${expected}'"
  ok "${description} resolves to '${expected}'"
}

check_instance_name_resolution() {
  expect_resolved "a compose directory with no .env" \
    "<none>" "bootroot"
  expect_resolved "an .env recording no instance" \
    $'POSTGRES_USER=step\n' "bootroot"
  expect_resolved "an .env recording an empty instance" \
    $'BOOTROOT_INSTANCE=\n' "bootroot"
  expect_resolved "a recorded instance" \
    $'POSTGRES_USER=step\nBOOTROOT_INSTANCE=insight\n' "insight"
  expect_resolved "a recorded instance among comments and blank lines" \
    $'# identity\n\n  BOOTROOT_INSTANCE = insight  \n' "insight"
  expect_resolved "a quoted recorded instance" \
    $'BOOTROOT_INSTANCE="insight"\n' "insight"
  expect_resolved "a single-quoted recorded instance" \
    $'BOOTROOT_INSTANCE=\'insight\'\n' "insight"
  # `read_dotenv` builds a map, so a repeated key keeps the last value.
  expect_resolved "a repeated recorded instance" \
    $'BOOTROOT_INSTANCE=first\nBOOTROOT_INSTANCE=second\n' "second"
  # A value carrying `=` splits on the first one, as `parse_dotenv` does.
  expect_resolved "a value carrying an equals sign" \
    $'BOOTROOT_INSTANCE=a=b\n' "a=b"

  # The property the whole resolution exists for: the ambient
  # `BOOTROOT_INSTANCE` names no install, and `COMPOSE_PROJECT_NAME`
  # selects a project rather than an identity. Neither may reach the
  # answer — both are set in every case above.
  ok "neither BOOTROOT_INSTANCE nor COMPOSE_PROJECT_NAME from the environment is consulted"

  # A `.env` bootroot itself would refuse to parse must not read as
  # "records nothing" and send the check at the wrong container names.
  local case_dir status=0
  case_dir="$(mktemp -d "$WORK_DIR/compose.XXXXXX")"
  printf 'BOOTROOT_INSTANCE=insight\nnot-an-assignment\n' >"$case_dir/.env"
  resolve_recorded_instance_name "$case_dir" >/dev/null 2>&1 || status=$?
  [ "$status" -ne 0 ] || die "a malformed .env resolved instead of failing"
  ok "a malformed .env fails the resolution rather than defaulting"
}

# ---------------------------------------------------------------------------
# The container check itself
# ---------------------------------------------------------------------------

# Puts a `docker` on PATH that reports exactly the container names in
# `PRESENT_CONTAINERS` as existing, and records every name it was asked
# about in `INSPECTED_LOG`.
install_docker_stub() {
  local stub_dir="$WORK_DIR/bin"
  mkdir -p "$stub_dir"
  cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Only `container inspect <name>` is stubbed; anything else is a bug in
# the check under test.
if [ "${1:-}" != "container" ] || [ "${2:-}" != "inspect" ]; then
  echo "docker stub: unexpected invocation: $*" >&2
  exit 125
fi
printf '%s\n' "$3" >>"$INSPECTED_LOG"
for present in $PRESENT_CONTAINERS; do
  if [ "$present" = "$3" ]; then
    exit 0
  fi
done
exit 1
STUB
  chmod +x "$stub_dir/docker"
  PATH="$stub_dir:$PATH"
  export PATH
}

# Runs one of the library's checks under the stub and prints its status
# on the first line, followed by everything it wrote.
run_check() {
  local present="$1" compose_file="$2"
  shift 2
  local status=0 output
  : >"$WORK_DIR/inspected.log"
  output="$(PRESENT_CONTAINERS="$present" INSPECTED_LOG="$WORK_DIR/inspected.log" \
    "$@" "$compose_file" "a-label" 2>&1)" || status=$?
  printf '%s\n%s\n' "$status" "$output"
}

check_container_check() {
  local compose_dir compose_file result status output
  compose_dir="$(mktemp -d "$WORK_DIR/compose.XXXXXX")"
  compose_file="$compose_dir/docker-compose.yml"
  : >"$compose_file"
  printf 'BOOTROOT_INSTANCE=insight\n' >"$compose_dir/.env"

  # A clean host: every one of the nine names is asked about, and
  # nothing is reported.
  result="$(run_check "" "$compose_file" assert_no_leftover_containers)"
  status="$(head -n 1 <<<"$result")"
  [ "$status" -eq 0 ] || die "the check failed on a host carrying no containers"
  local asked expected_asked
  asked="$(sort "$WORK_DIR/inspected.log")"
  expected_asked="$(printf 'insight%s\n' "${EXPECTED_SUFFIXES[@]}" | sort)"
  [ "$asked" = "$expected_asked" ] \
    || die "the check asked about ${asked//$'\n'/ }, expected the nine insight-* names"
  ok "a clean host passes, and every name asked about is derived from the recorded instance"

  # The names come from the recorded identity, so they are not
  # `bootroot-*` here — a leftover from an install under a different
  # identity is not this run's to remove.
  result="$(run_check "bootroot-openbao bootroot-ca" "$compose_file" assert_no_leftover_containers)"
  [ "$(head -n 1 <<<"$result")" -eq 0 ] \
    || die "the check reported containers of an install it does not own"
  ok "containers of another instance's install are not reported"

  # A prefix match would catch this; an exact-name check does not.
  result="$(run_check "insight-openbao-secondary insightful-ca" "$compose_file" \
    assert_no_leftover_containers)"
  [ "$(head -n 1 <<<"$result")" -eq 0 ] \
    || die "the check matched a container name by prefix"
  ok "a name that merely starts with the instance name is not reported"

  # The leftovers a killed run leaves: the failure has to name them and
  # give the command that removes them, and say what they might be.
  result="$(run_check "insight-ca insight-openbao-agent-responder" "$compose_file" \
    assert_no_leftover_containers)"
  status="$(head -n 1 <<<"$result")"
  output="$(tail -n +2 <<<"$result")"
  [ "$status" -ne 0 ] || die "the check passed on a host carrying leftover containers"
  grep -q 'insight-ca' <<<"$output" || die "the failure does not name insight-ca"
  grep -q 'insight-openbao-agent-responder' <<<"$output" \
    || die "the failure does not name insight-openbao-agent-responder"
  grep -q 'docker rm -f insight-ca insight-openbao-agent-responder' <<<"$output" \
    || die "the failure does not give the docker rm -f line that removes them"
  grep -qi 'killed' <<<"$output" || die "the failure does not offer the killed-run reading"
  grep -qi 'real bootroot install' <<<"$output" \
    || die "the failure does not offer the real-install reading"
  ok "a leftover fails the start-of-run check, naming it and how to remove it"

  # The end-of-run half reports the same thing without aborting, so an
  # EXIT trap keeps the status the run already carried.
  result="$(run_check "insight-postgres" "$compose_file" report_leftover_containers)"
  status="$(head -n 1 <<<"$result")"
  output="$(tail -n +2 <<<"$result")"
  [ "$status" -eq 1 ] || die "the end-of-run report returned ${status}, expected 1"
  grep -q 'insight-postgres' <<<"$output" || die "the end-of-run report names nothing"
  result="$(run_check "" "$compose_file" report_leftover_containers)"
  [ "$(head -n 1 <<<"$result")" -eq 0 ] \
    || die "the end-of-run report failed on a clean teardown"
  ok "the end-of-run report returns non-zero on a leftover and zero on a clean teardown"
}

# ---------------------------------------------------------------------------
# The status-preserving cleanup shape
# ---------------------------------------------------------------------------

expect_cleanup_status() {
  local entry="$1" cleanup="$2" expected="$3" actual=0
  ( exit_with_cleanup_status "$entry" "$cleanup" ) || actual=$?
  [ "$actual" -eq "$expected" ] \
    || die "entry=${entry} cleanup=${cleanup} exited ${actual}, expected ${expected}"
}

check_cleanup_status() {
  expect_cleanup_status 0 0 0
  expect_cleanup_status 0 1 1
  # The failure that ended the run is the reason worth reporting, so a
  # leftover found afterwards must not replace it.
  expect_cleanup_status 3 1 3
  expect_cleanup_status 3 0 3
  ok "a leftover fails a passing run and never overwrites a failing one's status"
}

# ---------------------------------------------------------------------------
# Every harness is wired to the checks
# ---------------------------------------------------------------------------
#
# The library is worth nothing in a script that does not call it, and a
# script added later is exactly the one that will not.

# The harnesses that install at the default identity, and so check by
# container name.
DEFAULT_IDENTITY_SCRIPTS=(
  run-baseline.sh
  run-ca-key-rotation-recovery.sh
  run-harness-smoke.sh
  run-local-lifecycle.sh
  run-openbao-tls-no-delta.sh
  run-openbao-tls-reown.sh
  run-reinit-recovery.sh
  run-remote-lifecycle.sh
  run-rotation-recovery.sh
  run-stepca-san.sh
)

# The one harness installing under run-scoped instance names of its own,
# which checks by Compose project label instead.
RUN_SCOPED_SCRIPT="run-two-instance-isolation.sh"

check_harness_wiring() {
  local script
  for script in "${DEFAULT_IDENTITY_SCRIPTS[@]}"; do
    grep -q 'lib/leftovers.sh' "$IMPL_DIR/$script" \
      || die "${script} does not source lib/leftovers.sh"
    grep -q '^  assert_no_leftover_containers ' "$IMPL_DIR/$script" \
      || die "${script} has no start-of-run leftover check"
    grep -q 'report_leftover_containers ' "$IMPL_DIR/$script" \
      || die "${script} does not report leftovers at the end of a run"
    grep -q 'exit_with_cleanup_status ' "$IMPL_DIR/$script" \
      || die "${script} does not end its cleanup with the run's own status"
    grep -q '^  compose_down || true$' "$IMPL_DIR/$script" \
      || die "${script} has no start-of-run teardown"
  done
  ok "every default-identity harness tears down and checks at the start, and reports at the end"

  grep -q 'assert_no_project_leftovers ' "$IMPL_DIR/$RUN_SCOPED_SCRIPT" \
    || die "${RUN_SCOPED_SCRIPT} does not use the shared label-scoped check"
  grep -q 'report_project_leftovers ' "$IMPL_DIR/$RUN_SCOPED_SCRIPT" \
    || die "${RUN_SCOPED_SCRIPT} does not report project leftovers at the end of a run"
  # Its containers are named after its own per-run instances, so the
  # container-name check would be both wrong and redundant there.
  ! grep -q 'assert_no_leftover_containers' "$IMPL_DIR/$RUN_SCOPED_SCRIPT" \
    || die "${RUN_SCOPED_SCRIPT} must not run the default-identity container check"
  ok "the run-scoped harness uses the label-scoped check and only that one"

  # A teardown that removed nothing has to be distinguishable from one
  # that removed everything, which is what discarding its output loses.
  local offenders
  offenders="$(grep -n 'down -v --remove-orphans >/dev/null' \
    "$IMPL_DIR"/run-*.sh || true)"
  [ -z "$offenders" ] \
    || die "a teardown still discards its output: ${offenders//$'\n'/; }"
  ok "no teardown sends its output to /dev/null"
}

check_suffixes_match_the_rust_enum
check_instance_name_resolution
install_docker_stub
check_container_check
check_cleanup_status
check_harness_wiring

echo "[$LABEL] OK: the E2E teardown assertions hold"
