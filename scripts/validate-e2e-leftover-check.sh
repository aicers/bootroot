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
  local env_contents="$1" explicit="${2:-}" case_dir
  case_dir="$(mktemp -d "$WORK_DIR/compose.XXXXXX")"
  if [ "$env_contents" != "<none>" ]; then
    printf '%s' "$env_contents" >"$case_dir/.env"
  fi
  BOOTROOT_INSTANCE="ambient-instance" COMPOSE_PROJECT_NAME="ambient-project" \
    resolve_recorded_instance_name "$case_dir" "$explicit"
}

expect_resolved() {
  local description="$1" env_contents="$2" expected="$3" actual
  actual="$(resolve_case "$env_contents")" \
    || die "resolving ${description} failed"
  [ "$actual" = "$expected" ] \
    || die "${description}: resolved '${actual}', expected '${expected}'"
  ok "${description} resolves to '${expected}'"
}

# The same, for the `--instance-name` the install may have been given.
expect_resolved_explicit() {
  local description="$1" env_contents="$2" explicit="$3" expected="$4" actual
  actual="$(resolve_case "$env_contents" "$explicit")" \
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

  # `--instance-name` outranks both, exactly as it does in
  # `resolve_recorded_instance_name`.  No harness passes one today, so
  # nothing but this exercises the branch — and the harness that first
  # does would otherwise have the check read the identity of an install
  # it did not make.
  expect_resolved_explicit "an explicit instance over a recorded one" \
    $'BOOTROOT_INSTANCE=recorded\n' "explicit" "explicit"
  expect_resolved_explicit "an explicit instance with no .env" \
    "<none>" "explicit" "explicit"
  expect_resolved_explicit "an empty explicit instance falling through to the recorded one" \
    $'BOOTROOT_INSTANCE=recorded\n' "" "recorded"

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

# Puts a `docker` on PATH that answers the three queries the library
# makes and nothing else.
#
#   * `container inspect <name>` reports the names in
#     `PRESENT_CONTAINERS` as existing, and records every name it was
#     asked about in `INSPECTED_LOG`.
#   * `ps -aq --filter <f>` and `volume ls -q --filter <f>` print
#     `PROJECT_CONTAINERS` and `PROJECT_VOLUMES`, and record the filter
#     they were given in `FILTERED_LOG`.  The filter is recorded because
#     the safety contract the run-scoped harness states in its header is
#     about which resources the query can reach, and that is decided by
#     the filter rather than by what the daemon happens to hold.
install_docker_stub() {
  local stub_dir="$WORK_DIR/bin"
  mkdir -p "$stub_dir"
  cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Anything not answered here is a bug in the check under test.
case "${1:-}:${2:-}" in
  container:inspect)
    printf '%s\n' "$3" >>"$INSPECTED_LOG"
    for present in ${PRESENT_CONTAINERS:-}; do
      if [ "$present" = "$3" ]; then
        exit 0
      fi
    done
    exit 1
    ;;
  ps:-aq)
    [ "${3:-}" = "--filter" ] || { echo "docker stub: unfiltered ps: $*" >&2; exit 125; }
    printf 'ps %s\n' "$4" >>"$FILTERED_LOG"
    [ -z "${PROJECT_CONTAINERS:-}" ] || printf '%s\n' ${PROJECT_CONTAINERS}
    exit 0
    ;;
  volume:ls)
    [ "${4:-}" = "--filter" ] || { echo "docker stub: unfiltered volume ls: $*" >&2; exit 125; }
    printf 'volume %s\n' "$5" >>"$FILTERED_LOG"
    [ -z "${PROJECT_VOLUMES:-}" ] || printf '%s\n' ${PROJECT_VOLUMES}
    exit 0
    ;;
esac
echo "docker stub: unexpected invocation: $*" >&2
exit 125
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

  # An install given `--instance-name` creates its containers at that
  # name and not at the recorded one, so both checks have to ask about
  # it when the harness hands it over.
  local check
  for check in assert_no_leftover_containers report_leftover_containers; do
    status=0
    : >"$WORK_DIR/inspected.log"
    output="$(PRESENT_CONTAINERS="explicit-ca" INSPECTED_LOG="$WORK_DIR/inspected.log" \
      "$check" "$compose_file" "a-label" "explicit" 2>&1)" || status=$?
    [ "$status" -ne 0 ] \
      || die "${check} ignored the explicit instance name it was given"
    grep -q 'explicit-ca' <<<"$output" \
      || die "${check} did not report the explicit instance's container"
    if grep -q '^insight-' "$WORK_DIR/inspected.log"; then
      die "${check} asked about the recorded identity despite an explicit instance name"
    fi
  done
  ok "an explicit instance name outranks the recorded one in both checks"
}

# ---------------------------------------------------------------------------
# The label-scoped check
# ---------------------------------------------------------------------------
#
# The half `run-two-instance-isolation.sh` uses.  It is no more
# observable from a green run than the other one: it fires only after a
# teardown that failed to remove what it owns.

# Runs one of the library's label-scoped checks under the stub, with the
# daemon holding `containers` and `volumes` for the queried project.
# Prints its status on the first line, followed by everything it wrote.
run_project_check() {
  local containers="$1" volumes="$2"
  shift 2
  local status=0 output
  : >"$WORK_DIR/filtered.log"
  output="$(PROJECT_CONTAINERS="$containers" PROJECT_VOLUMES="$volumes" \
    FILTERED_LOG="$WORK_DIR/filtered.log" \
    "$@" "twoinst-a-t0k3n" "a-teardown" 2>&1)" || status=$?
  printf '%s\n%s\n' "$status" "$output"
}

check_project_check() {
  local result status output filtered

  # A teardown that removed what it owns.  `assert_no_project_leftovers`
  # reports the satisfied assertion through `pass`, which is how the
  # run-scoped harness logs it mid-run.
  result="$(run_project_check "" "" assert_no_project_leftovers)"
  status="$(head -n 1 <<<"$result")"
  output="$(tail -n +2 <<<"$result")"
  [ "$status" -eq 0 ] || die "the label-scoped check failed after a clean teardown"
  grep -q '^PASS ' <<<"$output" || die "a clean teardown is not reported as a pass"

  # Both resource kinds are asked about by `com.docker.compose.project`
  # at the exact project, never by a `bootroot-*` name: the run-scoped
  # harness's safety contract is that a co-located default install is
  # out of reach, and the filter is what puts it there.
  filtered="$(sort -u "$WORK_DIR/filtered.log")"
  [ "$filtered" = "$(printf 'ps label=com.docker.compose.project=twoinst-a-t0k3n\nvolume label=com.docker.compose.project=twoinst-a-t0k3n\n' | sort -u)" ] \
    || die "the label-scoped check queried ${filtered//$'\n'/; }"
  ok "the label-scoped check asks only by com.docker.compose.project, for containers and volumes"

  # A surviving container and a surviving volume are separate failures,
  # so the message names which kind survived.
  result="$(run_project_check "c0ffee" "" assert_no_project_leftovers)"
  [ "$(head -n 1 <<<"$result")" -ne 0 ] || die "a surviving container passed the label-scoped check"
  grep -q 'containers of project twoinst-a-t0k3n survived a-teardown' <<<"$result" \
    || die "a surviving container is not reported as a container"

  result="$(run_project_check "" "v01" assert_no_project_leftovers)"
  [ "$(head -n 1 <<<"$result")" -ne 0 ] || die "a surviving volume passed the label-scoped check"
  grep -q 'volumes of project twoinst-a-t0k3n survived a-teardown' <<<"$result" \
    || die "a surviving volume is not reported as a volume"
  ok "a surviving container and a surviving volume each fail, naming which kind survived"

  # The end-of-run half returns rather than aborting, for the same
  # reason its container-name counterpart does.
  local kind
  for kind in "c0ffee:" ":v01" "c0ffee:v01"; do
    result="$(run_project_check "${kind%%:*}" "${kind##*:}" report_project_leftovers)"
    [ "$(head -n 1 <<<"$result")" -eq 1 ] \
      || die "the end-of-run project report did not return 1 for ${kind}"
    grep -q 'leftovers survived for project twoinst-a-t0k3n' <<<"$result" \
      || die "the end-of-run project report names nothing for ${kind}"
  done
  result="$(run_project_check "" "" report_project_leftovers)"
  [ "$(head -n 1 <<<"$result")" -eq 0 ] \
    || die "the end-of-run project report failed after a clean teardown"
  ok "the end-of-run project report returns non-zero for either kind and zero for neither"
}

# ---------------------------------------------------------------------------
# The ownership boundary
# ---------------------------------------------------------------------------
#
# A default-identity harness shares its Compose project, and every
# container name it uses, with a real install on the same host.  Until
# the startup assertion has said there was nothing here, nothing the
# harness runs may remove a container — an EXIT trap firing on that very
# assertion least of all.

check_ownership_flag() {
  ( stack_owned ) \
    && die "the stack reads as owned before the startup assertion has run"
  ( mark_stack_owned && stack_owned ) \
    || die "the stack does not read as owned after mark_stack_owned"
  # A subshell cannot mark it for its parent, which is why the harnesses
  # call it from `main` rather than from anything `main` calls.
  ( mark_stack_owned ) >/dev/null 2>&1
  ( stack_owned ) && die "mark_stack_owned leaked out of a subshell"
  ok "the stack reads as unowned until mark_stack_owned runs"
}

# Runs the cleanup shape every harness now carries, with `owned`
# deciding whether the run had got past its startup assertion.  Records
# what the teardown did, and prints the status the trap exited with.
simulate_cleanup() {
  local owned="$1" entry_status="$2" teardown_status="$3" leftover="$4"
  : >"$WORK_DIR/teardown.log"
  (
    compose_down() {
      echo "compose_down" >>"$WORK_DIR/teardown.log"
      return "$teardown_status"
    }
    report_leftover_containers() {
      echo "report" >>"$WORK_DIR/teardown.log"
      return "$leftover"
    }
    if [ "$owned" = "owned" ]; then
      mark_stack_owned
    fi
    local cleanup_status=0
    if stack_owned; then
      compose_down || cleanup_status=1
      report_leftover_containers "a-compose-file" "a-label" || cleanup_status=1
    fi
    exit_with_cleanup_status "$entry_status" "$cleanup_status"
  )
}

expect_simulated_cleanup() {
  local description="$1" owned="$2" entry="$3" teardown="$4" leftover="$5"
  local expected_status="$6" expected_log="$7" actual=0 actual_log
  simulate_cleanup "$owned" "$entry" "$teardown" "$leftover" || actual=$?
  actual_log="$(tr '\n' ' ' <"$WORK_DIR/teardown.log" | sed 's/ *$//')"
  [ "$actual" -eq "$expected_status" ] \
    || die "${description}: exited ${actual}, expected ${expected_status}"
  [ "$actual_log" = "$expected_log" ] \
    || die "${description}: teardown did '${actual_log}', expected '${expected_log}'"
  ok "${description}"
}

check_cleanup_ownership() {
  # The case the boundary exists for: the startup assertion aborted
  # because a real install is on this host, and the trap it fires must
  # not remove on the way out what the assertion refused to touch on the
  # way in.
  expect_simulated_cleanup \
    "a cleanup before the startup assertion passed tears nothing down" \
    unowned 1 0 0 1 ""
  expect_simulated_cleanup \
    "a cleanup after it tears down and checks what the teardown left" \
    owned 0 0 0 0 "compose_down report"
  expect_simulated_cleanup \
    "a failed teardown fails a run that had passed" \
    owned 0 1 0 1 "compose_down report"
  expect_simulated_cleanup \
    "a leftover fails a run that had passed" \
    owned 0 0 1 1 "compose_down report"
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
    grep -q 'down -v --remove-orphans >>"\$RUN\(NER\)\?_LOG" 2>&1' "$IMPL_DIR/$script" \
      || die "${script}'s teardown does not send its output to the run log"
    grep -q '^    if ! compose_down; then$' "$IMPL_DIR/$script" \
      || die "${script}'s cleanup does not fail the run on a failed teardown"
  done
  ok "every default-identity harness tears down and checks at the start, and reports at the end"
  ok "every teardown reaches the run log, and a failed one at the end fails the run"

  grep -q 'assert_no_project_leftovers ' "$IMPL_DIR/$RUN_SCOPED_SCRIPT" \
    || die "${RUN_SCOPED_SCRIPT} does not use the shared label-scoped check"
  grep -q 'report_project_leftovers ' "$IMPL_DIR/$RUN_SCOPED_SCRIPT" \
    || die "${RUN_SCOPED_SCRIPT} does not report project leftovers at the end of a run"
  # Its containers are named after its own per-run instances, so the
  # container-name check would be both wrong and redundant there.
  ! grep -q 'assert_no_leftover_containers' "$IMPL_DIR/$RUN_SCOPED_SCRIPT" \
    || die "${RUN_SCOPED_SCRIPT} must not run the default-identity container check"
  grep -q 'exit_with_cleanup_status ' "$IMPL_DIR/$RUN_SCOPED_SCRIPT" \
    || die "${RUN_SCOPED_SCRIPT} does not end its cleanup with the run's own status"
  # Its teardown is `teardown_instance` rather than a `compose_down`, so
  # the `/dev/null` sweep below does not reach it.
  ! grep -q 'docker \(rm -f\|volume rm -f\|network rm\) "\$id" >/dev/null' \
    "$IMPL_DIR/$RUN_SCOPED_SCRIPT" \
    || die "${RUN_SCOPED_SCRIPT}'s teardown still discards its output"
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

# ---------------------------------------------------------------------------
# The assertion runs before anything can remove a container
# ---------------------------------------------------------------------------
#
# That the two calls exist says nothing about their order, and the order
# is the whole safety property.  A default-identity harness tears down
# with `down -v --remove-orphans` at a Compose project a real install on
# the host holds too; run before the assertion, it deletes that install,
# volumes and all, and the assertion then reads a daemon it had just
# cleaned and lets the run proceed.  The containers the check exists to
# report — a killed run's — carry that same project label, so nothing
# can spare one while removing the other.
#
# What is checked is therefore reachability, not just line order: no
# function `main` calls ahead of the assertion may remove a container,
# however deep.  `trap` lines are exempt and checked separately, because
# an EXIT trap firing before the assertion is what the ownership flag
# governs.

# Anything that can remove a container or a volume.
DESTRUCTIVE_RE='compose_down|down -v|docker[[:space:]]+(rm|kill)|docker[[:space:]]+(volume|network)[[:space:]]+rm'

# Prints the body of the shell function `name` defines in `file`.
function_body() {
  awk -v want="$1() {" '
    $0 == want { inside = 1; next }
    inside && $0 == "}" { inside = 0 }
    inside { print }
  ' "$2"
}

# Prints every function name `file` defines.
defined_functions() {
  sed -n 's/^\([A-Za-z_][A-Za-z0-9_]*\)() {$/\1/p' "$1"
}

# Prints `chunk` with comment and `trap` lines removed.
executable_lines() {
  grep -vE '^[[:space:]]*(#|trap )' <<<"$1" || true
}

# True when `chunk` invokes the function `name`.
calls_function() {
  executable_lines "$1" \
    | grep -qE "(^|[^[:alnum:]_./\"-])${2}([[:space:]]|\)|;|\"|$)"
}

# Prints every function of `file` that `chunk` can reach, transitively.
reachable_functions() {
  local file="$1" chunk="$2" all name candidate body pending="" seen=" "
  all="$(defined_functions "$file")"
  while IFS= read -r name; do
    [ -n "$name" ] || continue
    if calls_function "$chunk" "$name"; then
      pending="$pending $name"
    fi
  done <<<"$all"
  while [ -n "${pending// /}" ]; do
    # shellcheck disable=SC2086 # a worklist of shell identifiers
    set -- $pending
    name="$1"
    shift
    pending="$*"
    case "$seen" in *" $name "*) continue ;; esac
    seen="$seen$name "
    body="$(function_body "$name" "$file")"
    while IFS= read -r candidate; do
      [ -n "$candidate" ] || continue
      case "$seen" in *" $candidate "*) continue ;; esac
      if calls_function "$body" "$candidate"; then
        pending="$pending $candidate"
      fi
    done <<<"$all"
  done
  printf '%s\n' "$seen"
}

check_startup_ordering() {
  local script path main_body assert_line mark_line down_line prefix name
  for script in "${DEFAULT_IDENTITY_SCRIPTS[@]}"; do
    path="$IMPL_DIR/$script"
    main_body="$(function_body main "$path")"
    [ -n "$main_body" ] || die "${script} defines no main"

    # Each `|| true` keeps a missing call reportable: without it the
    # failing `grep` would take the whole script down under `set -e`,
    # before the `die` below could say which call is gone.
    assert_line="$(grep -n '^  assert_no_leftover_containers ' <<<"$main_body" \
      | head -n 1 | cut -d: -f1)" || true
    mark_line="$(grep -n '^  mark_stack_owned$' <<<"$main_body" \
      | head -n 1 | cut -d: -f1)" || true
    down_line="$(grep -n '^  compose_down || true$' <<<"$main_body" \
      | head -n 1 | cut -d: -f1)" || true
    [ -n "$assert_line" ] || die "${script}: main does not run the startup check"
    [ -n "$mark_line" ] || die "${script}: main never takes the stack over"
    [ -n "$down_line" ] || die "${script}: main has no start-of-run teardown"
    [ "$assert_line" -lt "$mark_line" ] \
      || die "${script}: the stack is taken over before the startup check"
    [ "$mark_line" -lt "$down_line" ] \
      || die "${script}: the start-of-run teardown runs unowned"

    prefix="$(head -n "$((assert_line - 1))" <<<"$main_body")"
    if executable_lines "$prefix" | grep -qE "$DESTRUCTIVE_RE"; then
      die "${script}: main removes a container before the startup check"
    fi
    for name in $(reachable_functions "$path" "$prefix"); do
      if executable_lines "$(function_body "$name" "$path")" \
        | grep -qE "$DESTRUCTIVE_RE"; then
        die "${script}: ${name}, reached before the startup check, removes a container"
      fi
    done
  done
  ok "the startup check runs before the teardown, and before anything main reaches can remove a container"
}

# ---------------------------------------------------------------------------
# An explicit instance name reaches the checks
# ---------------------------------------------------------------------------
#
# No default-identity harness passes `--instance-name` today, so every
# one of them leaves the checks' explicit argument empty and the
# recorded `.env` decides.  The first one to take an instance name would
# create its containers at that name while the checks kept asking about
# the recorded identity — a run passing its own startup check on a host
# carrying exactly the leftovers it exists to report.  That is what this
# makes impossible to land quietly.

check_explicit_instance_wiring() {
  local script path call normalized checked=0
  for script in "${DEFAULT_IDENTITY_SCRIPTS[@]}"; do
    path="$IMPL_DIR/$script"
    # Comments stripped first: one of these scripts discusses
    # `--instance-name` without passing one.
    grep -vE '^[[:space:]]*#' "$path" | grep -q -- '--instance-name' || continue
    checked=1
    while IFS= read -r call; do
      # `<check> <compose-file> <label> [<instance-name>]`, with quoted
      # arguments collapsed so a label carrying a space counts as one.
      normalized="$(sed 's/"[^"]*"/ARG/g' <<<"$call")"
      [ "$(wc -w <<<"$normalized")" -ge 4 ] \
        || die "${script} installs at an explicit instance name but does not hand it to the leftover check: ${call}"
    done < <(grep -hE '^[[:space:]]*(assert_no_leftover_containers|report_leftover_containers) ' "$path")
  done
  if [ "$checked" -eq 1 ]; then
    ok "every harness installing at an explicit instance name hands it to the checks"
  else
    ok "no default-identity harness passes --instance-name, so the checks resolve from .env"
  fi
}

# ---------------------------------------------------------------------------
# The run-scoped teardown reports its own failures
# ---------------------------------------------------------------------------
#
# `teardown_instance` sweeps four resource kinds, and no one failure may
# stop the ones after it — a Compose `down` that errored is precisely
# when the per-resource removals are worth running.  What it must not do
# is return success anyway.  The leftover assertion that follows each
# call site cannot cover for that: it reports what the label query
# returns, and a query that could not reach the daemon returns nothing,
# which reads there as a clean teardown.
#
# The function is `eval`'d out of the shipped script rather than
# reimplemented here, so what is exercised is the code that runs.

# Runs the shipped `teardown_instance` with the docker operations named
# in `failing` returning non-zero.  Prints its status on the first line
# and the operations it attempted on the second.
run_teardown_instance() {
  local failing="$1" status=0 dir
  dir="$(mktemp -d "$WORK_DIR/teardown.XXXXXX")"
  : >"$dir/docker-compose.yml"
  : >"$WORK_DIR/teardown-ops.log"
  (
    RUN_LOG="$WORK_DIR/teardown-run.log"
    COMPOSE_FILE_NAME="docker-compose.yml"
    OPS_LOG="$WORK_DIR/teardown-ops.log"
    FAILING_OPS=" $failing "

    record_op() {
      printf '%s\n' "$1" >>"$OPS_LOG"
      case "$FAILING_OPS" in *" $1 "*) return 1 ;; esac
      return 0
    }

    instance_compose() {
      record_op compose
    }

    # A shell function outranks the `docker` stub on PATH, which answers
    # only the queries the library itself makes.
    docker() {
      local op
      case "${1:-}:${2:-}" in
        ps:-aq) op=ps ;;
        rm:*) op=rm ;;
        volume:ls) op=volume-ls ;;
        volume:rm) op=volume-rm ;;
        network:ls) op=network-ls ;;
        network:rm) op=network-rm ;;
        *)
          echo "unexpected docker call: $*" >&2
          return 125
          ;;
      esac
      record_op "$op" || return 1
      case "$op" in
        ps) printf 'c0ffee\n' ;;
        volume-ls) printf 'v01\n' ;;
        network-ls) printf 'n01\n' ;;
      esac
    }

    eval "teardown_instance() {
$(function_body teardown_instance "$IMPL_DIR/$RUN_SCOPED_SCRIPT")
}"
    teardown_instance "twoinst-a-t0k3n" "$dir"
  ) || status=$?
  printf '%s\n%s\n' "$status" "$(tr '\n' ' ' <"$WORK_DIR/teardown-ops.log" | sed 's/ *$//')"
}

ALL_TEARDOWN_OPS="compose ps rm volume-ls volume-rm network-ls network-rm"

check_run_scoped_teardown() {
  local result status ops failing
  result="$(run_teardown_instance "")"
  status="$(head -n 1 <<<"$result")"
  ops="$(tail -n +2 <<<"$result")"
  [ "$status" -eq 0 ] || die "a teardown whose every step succeeded returned ${status}"
  [ "$ops" = "$ALL_TEARDOWN_OPS" ] \
    || die "the teardown attempted '${ops}', expected '${ALL_TEARDOWN_OPS}'"
  ok "a teardown whose every step succeeded returns 0, having swept all four resource kinds"

  # Each removal failing on its own: the status has to come back
  # non-zero, and the kinds after it have to have been attempted anyway.
  for failing in compose rm volume-rm network-rm; do
    result="$(run_teardown_instance "$failing")"
    status="$(head -n 1 <<<"$result")"
    ops="$(tail -n +2 <<<"$result")"
    [ "$status" -ne 0 ] \
      || die "a teardown whose ${failing} failed returned 0"
    [ "$ops" = "$ALL_TEARDOWN_OPS" ] \
      || die "a failed ${failing} stopped the sweep: attempted '${ops}'"
  done
  ok "a failed removal returns non-zero and does not stop the kinds after it"

  # A query that cannot reach the daemon reports no resources, which is
  # indistinguishable from a clean sweep to everything except this.
  result="$(run_teardown_instance "ps")"
  [ "$(head -n 1 <<<"$result")" -ne 0 ] \
    || die "a teardown whose container query failed returned 0"
  [ "$(tail -n +2 <<<"$result")" = "compose ps volume-ls volume-rm network-ls network-rm" ] \
    || die "a failed container query did not leave the later kinds attempted"
  ok "a failed label query fails the teardown rather than reading as nothing to remove"
}

# Every call site has to act on that status, which is not visible in the
# function merely returning it.
check_run_scoped_teardown_wiring() {
  local path="$IMPL_DIR/$RUN_SCOPED_SCRIPT" call handled
  while IFS= read -r call; do
    case "$call" in
      *'|| {' | *'\') ;;
      *) die "${RUN_SCOPED_SCRIPT}: a teardown_instance call ignores its status: ${call}" ;;
    esac
    handled="$(grep -A3 -F "$call" "$path" | tail -n +2)"
    grep -qE 'cleanup_status=1|fail ' <<<"$handled" \
      || die "${RUN_SCOPED_SCRIPT}: a failed teardown_instance neither fails the run nor folds into the cleanup status: ${call}"
  done < <(grep -E '^[[:space:]]+teardown_instance ' "$path")
  ok "every teardown_instance call fails the run or folds into the cleanup status"
}

check_cleanup_guard() {
  local script path cleanup_body guard_line line
  for script in "${DEFAULT_IDENTITY_SCRIPTS[@]}"; do
    path="$IMPL_DIR/$script"
    cleanup_body="$(function_body cleanup "$path")"
    [ -n "$cleanup_body" ] || die "${script} defines no cleanup"
    guard_line="$(grep -n '^  if stack_owned; then$' <<<"$cleanup_body" \
      | head -n 1 | cut -d: -f1)" || true
    [ -n "$guard_line" ] \
      || die "${script}: cleanup tears down whether or not the run owns the stack"
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      [ "$line" -gt "$guard_line" ] \
        || die "${script}: cleanup removes a container outside the ownership guard"
    done < <(grep -nE "$DESTRUCTIVE_RE" <<<"$cleanup_body" | cut -d: -f1)
    grep -q '^    report_leftover_containers ' <<<"$cleanup_body" \
      || die "${script}: cleanup checks for leftovers outside the ownership guard"
  done
  ok "no cleanup tears anything down before the startup check has passed"

  # The run-scoped harness needs no such guard: its instances, its
  # containers and its Compose projects all carry a per-run token, so
  # there is nothing of anyone else's for its teardown to reach.
  ! grep -q 'stack_owned' "$IMPL_DIR/$RUN_SCOPED_SCRIPT" \
    || die "${RUN_SCOPED_SCRIPT} took on an ownership guard it does not need"
  ok "the run-scoped harness needs no ownership guard, and has none"
}

check_suffixes_match_the_rust_enum
check_instance_name_resolution
install_docker_stub
check_container_check
check_project_check
check_ownership_flag
check_cleanup_ownership
check_cleanup_status
check_harness_wiring
check_explicit_instance_wiring
check_run_scoped_teardown
check_run_scoped_teardown_wiring
check_startup_ordering
check_cleanup_guard

echo "[$LABEL] OK: the E2E teardown assertions hold"
