#!/usr/bin/env bash
#
# Validates the per-run identity the lifecycle E2E harnesses install at
# (`scripts/impl/lib/run-scope.sh`), without Docker and without bringing
# a stack up.
#
# Almost none of it is observable from a green CI run. Each CI runner
# gets one run on an empty host, so a derivation that started colliding,
# a marker that stopped being written, or a sweep that began reaching
# past the runs it recorded would all leave the matrix green — and
# surface as one developer's run deleting another's containers, or as a
# host quietly filling with the leftovers of runs that were killed.
#
# The library is sourced rather than copied, so this validates the
# shipped code. `docker` is a stub on PATH holding a container, volume
# and network inventory in a file: what is under test is which resources
# the sweep asks about and which it removes, not Docker.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LABEL="validate-e2e-run-scope"
IMPL_DIR="$ROOT_DIR/scripts/impl"

# shellcheck source=impl/lib/leftovers.sh
. "$IMPL_DIR/lib/leftovers.sh"

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# The marker directory has to be this run's own, never the real one: the
# sweep under test removes containers, and a developer's live E2E run
# must not be a fixture here.
export BOOTROOT_E2E_RUN_MARKER_DIR="$WORK_DIR/markers"

# shellcheck source=impl/lib/run-scope.sh
. "$IMPL_DIR/lib/run-scope.sh"

# The library aborts through `fail`, which its callers define. Here it
# raises a status the checks can catch, so a derivation that is supposed
# to be rejected can be asserted on rather than taking this script down.
fail() {
  printf 'library-fail: %s\n' "$1" >&2
  exit 9
}

die() {
  echo "[$LABEL] FAIL: $1" >&2
  exit 1
}

ok() {
  echo "[$LABEL] ok: $1"
}

# The marker directory's permission bits, in octal. BSD `stat` first,
# GNU second: the harness runs on both.
marker_dir_mode() {
  stat -f '%OLp' "$BOOTROOT_E2E_RUN_MARKER_DIR" 2>/dev/null \
    || stat -c '%a' "$BOOTROOT_E2E_RUN_MARKER_DIR"
}

# The lifecycle harnesses, and the instance-name prefix each derives
# under. Both are asserted against the shipped scripts below, so a
# renamed prefix cannot leave this file validating a value nothing uses.
LIFECYCLE_SCRIPTS=(
  run-local-lifecycle.sh
  run-remote-lifecycle.sh
)

# The artifact-directory basenames the callers actually pass, with a
# CI-length `GITHUB_RUN_ID` substituted: `scripts/preflight/ci/
# e2e-matrix.sh` and `.github/workflows/ci.yml` for the matrix arms,
# `scripts/impl/run-extended-suite.sh` for the fixed-basename case, and
# each script's own default.
CI_RUN_ID="19283746501"
ARTIFACT_BASENAMES=(
  "ci-local-no-hosts-${CI_RUN_ID}"
  "ci-local-hosts-${CI_RUN_ID}"
  "ci-remote-no-hosts-${CI_RUN_ID}"
  "ci-remote-hosts-${CI_RUN_ID}"
  "infra-lifecycle"
  "docker-local-lifecycle-1770000000"
  "docker-remote-lifecycle-1770000000"
)

# ---------------------------------------------------------------------------
# The length limit is the one the binary enforces
# ---------------------------------------------------------------------------
#
# `BOOTROOT_MAX_INSTANCE_NAME_LEN` is a literal here and derived in
# `src/commands/compose_project.rs`. A suffix added to the container set,
# or a DNS-label constant that moved, would leave the harness deriving
# names `infra install` rejects — several minutes into a run, after the
# stack is already up.
check_limit_matches_the_rust_derivation() {
  local dns_limit longest suffix derived
  dns_limit="$(sed -n 's/^pub(crate) const DNS_LABEL_LIMIT: usize = \([0-9]*\);$/\1/p' \
    src/commands/compose_project.rs)"
  [ -n "$dns_limit" ] \
    || die "could not read DNS_LABEL_LIMIT from src/commands/compose_project.rs"
  longest=0
  for suffix in "${BOOTROOT_CONTAINER_SUFFIXES[@]}"; do
    [ "${#suffix}" -gt "$longest" ] && longest="${#suffix}"
  done
  derived=$((dns_limit - longest))
  [ "$BOOTROOT_MAX_INSTANCE_NAME_LEN" -eq "$derived" ] \
    || die "lib/run-scope.sh caps instance names at ${BOOTROOT_MAX_INSTANCE_NAME_LEN}, but the binary derives ${derived} (${dns_limit} - ${longest})"
  ok "the instance-name limit matches the one the binary derives (${derived})"
}

# ---------------------------------------------------------------------------
# Derivation
# ---------------------------------------------------------------------------

# `validate_instance_name` in src/commands/compose_project.rs, in shell:
# lowercase ASCII letters, digits and `-`, starting with a letter or a
# digit, within the limit.
instance_name_is_valid() {
  local name="$1"
  [ -n "$name" ] || return 1
  [ "${#name}" -le "$BOOTROOT_MAX_INSTANCE_NAME_LEN" ] || return 1
  case "$name" in
    ["$RUN_SCOPE_INSTANCE_ALPHABET"]*) ;;
    *) return 1 ;;
  esac
  case "$name" in
    *[!"$RUN_SCOPE_INSTANCE_ALPHABET"-]*) return 1 ;;
  esac
  return 0
}

check_derived_instances_are_installable() {
  local script prefix basename token instance project
  for script in "${LIFECYCLE_SCRIPTS[@]}"; do
    prefix="$(sed -n 's/^RUN_INSTANCE_PREFIX="\(.*\)"$/\1/p' "$IMPL_DIR/$script")"
    [ -n "$prefix" ] || die "${script} declares no RUN_INSTANCE_PREFIX"
    for basename in "${ARTIFACT_BASENAMES[@]}"; do
      token="$(run_scope_token "/tmp/e2e/$basename")"
      instance="$(run_scope_instance "$prefix" "$token")"
      instance_name_is_valid "$instance" \
        || die "${script} derives '${instance}' from ${basename}, which infra install would reject"
      project="$(run_scope_project_for_instance "$instance")"
      [ "$project" = "$instance" ] \
        || die "${script} derives project '${project}' for instance '${instance}'; --instance-name makes them one string"
    done
  done
  ok "every matrix step's derived instance is one infra install accepts, under a CI-length run id"
  ok "the derived project is the project --instance-name makes the install resolve"
}

# The pid sits at the end of the token, so it is the part truncation must
# keep. Two runs sharing an artifact basename — which
# `run-extended-suite.sh` guarantees for its lifecycle case — are
# otherwise given the same instance name and collide on every container.
check_truncation_keeps_the_discriminating_tail() {
  local prefix="e2e-local-" long_basename first second
  long_basename="$(printf 'a%.0s' $(seq 1 120))"
  first="$(run_scope_instance "$prefix" "${long_basename}-4242")"
  second="$(run_scope_instance "$prefix" "${long_basename}-4243")"
  instance_name_is_valid "$first" || die "a long identifier derived the invalid name '${first}'"
  [ "$first" != "$second" ] \
    || die "two identifiers differing only in their tail derived the same instance '${first}'"
  case "$first" in
    *4242) ;;
    *) die "truncation dropped the tail: '${first}' does not end in the pid" ;;
  esac
  ok "a truncated identifier keeps its tail, so runs differing only there stay distinct"
}

check_derivation_rejects_what_it_cannot_derive() {
  local status=0
  ( run_scope_instance "e2e-local-" "..." ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "an identifier holding no [a-z0-9] derived a name instead of failing"
  status=0
  ( run_scope_assert_valid_instance "E2E-Local" ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "the guard accepted an instance name carrying uppercase"
  status=0
  ( run_scope_assert_valid_instance "-leading-dash" ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "the guard accepted an instance name starting with a dash"
  status=0
  ( run_scope_assert_valid_instance "$(printf 'a%.0s' $(seq 1 40))" ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "the guard accepted an over-long instance name"
  ok "the derivation and its guard reject what infra install would reject"
}

# ---------------------------------------------------------------------------
# Liveness markers
# ---------------------------------------------------------------------------

check_markers() {
  local instance="e2e-local-marker" path
  path="$(run_marker_path "$instance")"
  write_run_marker "$instance" "$instance"
  [ -f "$path" ] || die "write_run_marker wrote no marker at ${path}"
  [ "$(run_marker_field "$path" pid)" = "$$" ] \
    || die "the marker does not record this process's pid"
  [ "$(run_marker_field "$path" project)" = "$instance" ] \
    || die "the marker does not record the compose project"
  # A `.tmp` left behind by an interrupted write must not read as a run.
  [ -z "$(find "$BOOTROOT_E2E_RUN_MARKER_DIR" -name '*.tmp' -print -quit)" ] \
    || die "write_run_marker left its temporary file behind"
  ok "a marker records this run's pid and project, published under the instance name"

  # The directory holds the names the sweep hands to `docker rm -f`, so a
  # world-writable one at a predictable `/tmp` path would let anyone who
  # can write there choose them.  A pre-existing directory is re-moded
  # rather than trusted, and the sweep applies the same rule because it
  # runs before any marker is written.
  chmod 777 "$BOOTROOT_E2E_RUN_MARKER_DIR"
  write_run_marker "$instance" "$instance"
  [ "$(marker_dir_mode)" = "700" ] \
    || die "write_run_marker left the marker directory at mode $(marker_dir_mode)"
  chmod 777 "$BOOTROOT_E2E_RUN_MARKER_DIR"
  sweep_dead_run_instances "$LABEL" /dev/null >/dev/null 2>&1 || true
  [ "$(marker_dir_mode)" = "700" ] \
    || die "the sweep read a marker directory at mode $(marker_dir_mode)"
  rm -f "$path"
  ok "a pre-existing marker directory is restricted to its owner before it is read or written"

  # Another run's marker is not this run's to remove: dropping it would
  # hide that run's containers from every later sweep.
  printf 'pid=%s\nproject=%s\n' "999999" "$instance" >"$path"
  remove_run_marker "$instance"
  [ -f "$path" ] || die "remove_run_marker removed a marker recording another pid"
  ok "a marker recording another pid survives this run's cleanup"

  write_run_marker "$instance" "$instance"
  remove_run_marker "$instance"
  [ ! -f "$path" ] || die "remove_run_marker left this run's own marker behind"
  remove_run_marker ""
  remove_run_marker "$instance"
  ok "a run removes its own marker, and removing an absent one is not an error"

  # A teardown that failed, or that left a container the end-of-run check
  # reported, is the one case where this run's instance still holds
  # resources once the run is gone.  Dropping the marker there strands
  # them under a name no later sweep knows to ask about — precisely the
  # accumulation the marker exists to stop.
  write_run_marker "$instance" "$instance"
  remove_run_marker "$instance" 1 2>/dev/null
  [ -f "$path" ] \
    || die "remove_run_marker dropped the marker of a run whose teardown left containers behind"
  remove_run_marker "$instance" 0
  [ ! -f "$path" ] || die "remove_run_marker kept the marker of a clean teardown"
  ok "a marker survives a teardown that did not finish, and goes with one that did"
}

# The default marker directory has to be per-user, and this is the only
# check that can see it: everything else here runs under an override so
# the sweep cannot reach a developer's live run.
#
# `ensure_run_marker_dir` refuses a directory this user does not own, so
# a path shared by the whole machine would let the first user to run the
# harness lock every other one out of it — the same serialisation the
# per-run identity exists to remove, arriving as a hard failure.
check_default_marker_dir_is_per_user() {
  local resolved
  resolved="$(
    unset BOOTROOT_E2E_RUN_MARKER_DIR
    # shellcheck source=impl/lib/run-scope.sh
    . "$IMPL_DIR/lib/run-scope.sh"
    printf '%s' "$BOOTROOT_E2E_RUN_MARKER_DIR"
  )"
  case "$resolved" in
    "${TMPDIR:-/tmp}"/*) ;;
    *) die "the default marker directory '${resolved}' is not under \${TMPDIR:-/tmp}" ;;
  esac
  case "$resolved" in
    *"-$(id -u)") ;;
    *) die "the default marker directory '${resolved}' is not per-user; two users on one host would contend for it" ;;
  esac
  ok "the default marker directory is per-user, so two users can run the harness on one host"
}

check_liveness() {
  run_pid_is_alive "$$" || die "this process reads as dead"
  # A pid past the kernel's maximum can never name a live process.
  ! run_pid_is_alive 4194305 || die "an impossible pid reads as alive"
  ! run_pid_is_alive "" || die "an empty pid reads as alive"
  ! run_pid_is_alive "not-a-pid" || die "a non-numeric pid reads as alive"
  ok "liveness follows the recorded pid, and a marker naming no pid is not alive"
}

# ---------------------------------------------------------------------------
# The sweep
# ---------------------------------------------------------------------------
#
# Puts a `docker` on PATH backed by an inventory file, so a `rm` that the
# sweep issues is visible to the listing it makes afterwards. Every
# filter it is given is recorded, because the safety property is about
# which resources the queries can reach, and that is decided by the
# filter rather than by what the daemon happens to hold.
install_docker_stub() {
  local stub_dir="$WORK_DIR/bin"
  mkdir -p "$stub_dir"
  cat >"$stub_dir/docker" <<'STUB'
#!/usr/bin/env bash
# Inventory files: one resource per line, volumes and networks as
# `<project> <id>`.
CONTAINERS="${STUB_STATE}/containers"
VOLUMES="${STUB_STATE}/volumes"
NETWORKS="${STUB_STATE}/networks"

refuse_if_failing() {
  case " ${FAILING_QUERIES:-} " in
    *" $1 "*)
      echo "Cannot connect to the Docker daemon at unix:///var/run/docker.sock." >&2
      exit 1
      ;;
  esac
}

drop_line() {
  local file="$1" pattern="$2" kept
  kept="$(grep -vxF "$pattern" "$file" || true)"
  printf '%s\n' "$kept" | grep -v '^$' >"${file}.new" || true
  mv "${file}.new" "$file"
}

project_ids() {
  local file="$1" filter="$2" project="${2#label=com.docker.compose.project=}"
  [ "$filter" != "$project" ] || { echo "docker stub: unscoped filter: $filter" >&2; exit 125; }
  awk -v p="$project" '$1 == p { print $2 }' "$file"
}

case "${1:-}:${2:-}" in
  ps:-a)
    [ "${3:-}" = "--format" ] || { echo "docker stub: unformatted ps: $*" >&2; exit 125; }
    printf 'list %s\n' "$4" >>"${QUERY_LOG:-/dev/null}"
    refuse_if_failing list
    cat "$CONTAINERS"
    exit 0
    ;;
  rm:-f)
    printf 'rm %s\n' "$3" >>"${QUERY_LOG:-/dev/null}"
    refuse_if_failing rm
    grep -qxF "$3" "$CONTAINERS" || { echo "Error: No such container: $3" >&2; exit 1; }
    drop_line "$CONTAINERS" "$3"
    exit 0
    ;;
  volume:ls)
    [ "${4:-}" = "--filter" ] || { echo "docker stub: unfiltered volume ls: $*" >&2; exit 125; }
    printf 'volume-ls %s\n' "$5" >>"${QUERY_LOG:-/dev/null}"
    refuse_if_failing volume-ls
    project_ids "$VOLUMES" "$5"
    exit 0
    ;;
  volume:rm)
    printf 'volume-rm %s\n' "$4" >>"${QUERY_LOG:-/dev/null}"
    refuse_if_failing volume-rm
    drop_line "$VOLUMES" "$(awk -v id="$4" '$2 == id { print; exit }' "$VOLUMES")"
    exit 0
    ;;
  network:ls)
    [ "${4:-}" = "--filter" ] || { echo "docker stub: unfiltered network ls: $*" >&2; exit 125; }
    printf 'network-ls %s\n' "$5" >>"${QUERY_LOG:-/dev/null}"
    refuse_if_failing network-ls
    project_ids "$NETWORKS" "$5"
    exit 0
    ;;
  network:rm)
    printf 'network-rm %s\n' "$3" >>"${QUERY_LOG:-/dev/null}"
    refuse_if_failing network-rm
    drop_line "$NETWORKS" "$(awk -v id="$3" '$2 == id { print; exit }' "$NETWORKS")"
    exit 0
    ;;
esac
echo "docker stub: unexpected invocation: $*" >&2
exit 125
STUB
  chmod +x "$stub_dir/docker"
  PATH="$stub_dir:$PATH"
  export PATH
  STUB_STATE="$WORK_DIR/docker-state"
  QUERY_LOG="$WORK_DIR/query.log"
  export STUB_STATE QUERY_LOG
  mkdir -p "$STUB_STATE"
}

# Loads the stub daemon's inventory, and clears the marker directory and
# the query log.
seed_daemon() {
  local containers="$1" volumes="$2" networks="$3"
  printf '%s\n' $containers | grep -v '^$' >"$STUB_STATE/containers" || : >"$STUB_STATE/containers"
  printf '%s\n' "$volumes" | grep -v '^$' >"$STUB_STATE/volumes" || : >"$STUB_STATE/volumes"
  printf '%s\n' "$networks" | grep -v '^$' >"$STUB_STATE/networks" || : >"$STUB_STATE/networks"
  rm -rf "$BOOTROOT_E2E_RUN_MARKER_DIR"
  mkdir -p "$BOOTROOT_E2E_RUN_MARKER_DIR"
  : >"$WORK_DIR/query.log"
  : >"$WORK_DIR/sweep.log"
}

seed_marker() {
  local instance="$1" pid="$2"
  printf 'pid=%s\nproject=%s\n' "$pid" "$instance" \
    >"$BOOTROOT_E2E_RUN_MARKER_DIR/$instance"
}

daemon_containers() {
  LC_ALL=C sort "$STUB_STATE/containers" | tr '\n' ' ' | sed 's/ *$//'
}

# Nine containers, one volume and one network for the instance named.
instance_containers() {
  local instance="$1" suffix out=""
  for suffix in "${BOOTROOT_CONTAINER_SUFFIXES[@]}"; do
    out="$out ${instance}${suffix}"
  done
  printf '%s' "${out# }"
}

DEAD="e2e-local-dead"
LIVE="e2e-local-live"

check_sweep_collects_only_dead_runs() {
  local status=0
  seed_daemon \
    "$(instance_containers "$DEAD") $(instance_containers "$LIVE") bootroot-openbao bootroot-ca" \
    "$(printf '%s vol-dead\n%s vol-live\n' "$DEAD" "$LIVE")" \
    "$(printf '%s net-dead\n%s net-live\n' "$DEAD" "$LIVE")"
  seed_marker "$DEAD" 4194305
  seed_marker "$LIVE" "$$"

  sweep_dead_run_instances "a-label" "$WORK_DIR/sweep.log" || status=$?
  [ "$status" -eq 0 ] || die "the sweep returned ${status} on a daemon it could fully collect"

  [ ! -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$DEAD" ] \
    || die "the sweep left the dead run's marker behind"
  [ -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$LIVE" ] \
    || die "the sweep removed a live run's marker"

  local expected
  expected="$(printf '%s\n' bootroot-ca bootroot-openbao $(instance_containers "$LIVE") \
    | LC_ALL=C sort | tr '\n' ' ' | sed 's/ *$//')"
  [ "$(daemon_containers)" = "$expected" ] \
    || die "the sweep left '$(daemon_containers)', expected '${expected}'"
  ok "a dead run's nine containers are removed, and a live run's are not"
  ok "a co-located default-identity install is untouched"

  [ "$(awk -v p="$DEAD" '$1 == p' "$STUB_STATE/volumes")" = "" ] \
    || die "the dead run's volume survived"
  [ "$(awk -v p="$LIVE" '$1 == p { print $2 }' "$STUB_STATE/volumes")" = "vol-live" ] \
    || die "the live run's volume did not survive"
  [ "$(awk -v p="$LIVE" '$1 == p { print $2 }' "$STUB_STATE/networks")" = "net-live" ] \
    || die "the live run's network did not survive"
  ok "the dead run's volumes and networks go with it, and the live run's stay"

  # Every removal is by an exact name the marker's instance produces, and
  # every label query names one project in full. A prefix or a wildcard
  # would reach into a real default-identity install on the same host —
  # which is the reason `lib/leftovers.sh` rules them out too.
  local removed asked
  removed="$(awk '$1 == "rm" { print $2 }' "$WORK_DIR/query.log" | LC_ALL=C sort -u)"
  [ "$removed" = "$(printf '%s\n' $(instance_containers "$DEAD") | LC_ALL=C sort)" ] \
    || die "the sweep removed ${removed//$'\n'/ }"
  asked="$(awk '$1 ~ /-ls$/ { print $2 }' "$WORK_DIR/query.log" | LC_ALL=C sort -u)"
  [ "$asked" = "label=com.docker.compose.project=${DEAD}" ] \
    || die "the sweep's label queries were: ${asked//$'\n'/; }"
  ok "the sweep removes exact names and queries one exact project label, never a wildcard"
}

check_sweep_keeps_a_marker_it_could_not_clear() {
  local status=0
  seed_daemon "$(instance_containers "$DEAD")" "" ""
  seed_marker "$DEAD" 4194305
  FAILING_QUERIES="rm" sweep_dead_run_instances "a-label" "$WORK_DIR/sweep.log" 2>/dev/null || status=$?
  [ "$status" -ne 0 ] || die "a sweep that removed nothing returned 0"
  [ -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$DEAD" ] \
    || die "a sweep that could not collect a dead run dropped its marker anyway"
  ok "a collection that failed keeps the marker, so the next run retries it"

  status=0
  seed_daemon "$(instance_containers "$DEAD")" "" ""
  seed_marker "$DEAD" 4194305
  FAILING_QUERIES="list" sweep_dead_run_instances "a-label" "$WORK_DIR/sweep.log" 2>/dev/null || status=$?
  [ "$status" -ne 0 ] || die "a sweep whose container listing failed returned 0"
  [ -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$DEAD" ] \
    || die "a sweep whose listing failed dropped the marker anyway"
  ok "a listing that could not be run fails the sweep rather than reading as nothing to collect"

  # Two runs starting at once sweep the same marker. The one that loses
  # the race sees its `rm` fail on a container that is already gone, and
  # that must not read as a collection that failed.
  status=0
  seed_daemon "" "" ""
  seed_marker "$DEAD" 4194305
  sweep_dead_run_instances "a-label" "$WORK_DIR/sweep.log" || status=$?
  [ "$status" -eq 0 ] || die "a sweep of an already-collected dead run returned ${status}"
  [ ! -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$DEAD" ] \
    || die "a sweep of an already-collected dead run kept the marker"
  ok "a dead run another sweep already collected is not reported as a failure"
}

# ---------------------------------------------------------------------------
# The harnesses are wired to all of it
# ---------------------------------------------------------------------------
#
# The library is worth nothing in a script that does not call it, and the
# hardcoded names and ports it replaces are the kind that grow back one
# call site at a time.

check_harness_wiring() {
  local script path
  for script in "${LIFECYCLE_SCRIPTS[@]}"; do
    path="$IMPL_DIR/$script"
    grep -q 'lib/run-scope.sh' "$path" || die "${script} does not source lib/run-scope.sh"
    grep -q 'lib/ports.sh' "$path" || die "${script} does not source lib/ports.sh"
    grep -q '^  derive_run_scope$' "$path" \
      || die "${script}'s main does not derive a per-run scope"
    grep -q '^  collect_dead_runs$' "$path" \
      || die "${script}'s main does not sweep the instances of dead runs"
    grep -q '^  write_run_marker "\$RUN_INSTANCE" "\$COMPOSE_PROJECT"$' "$path" \
      || die "${script}'s main records no liveness marker"
    # With the teardown's status, so a teardown that left something
    # behind keeps the marker the next run collects it by.
    grep -q '^  remove_run_marker "\$RUN_INSTANCE" "\$cleanup_status"$' "$path" \
      || die "${script}'s cleanup does not remove its own marker against the teardown's status"
    grep -q '^  assert_resolved_compose_project$' "$path" \
      || die "${script} does not assert the project its install resolved"
    grep -qF -- '--instance-name "$RUN_INSTANCE"' "$path" \
      || die "${script} does not install at the derived instance"
    # `service add` resolves its identity from the working directory
    # rather than from the compose file's, and skips the DNS-alias
    # rewiring with a warning — not a failure — when it resolves an
    # identity whose responder is not running.
    grep -q '^  write_instance_dotenv ' "$path" \
      || die "${script} does not record the instance where it runs bootroot from"
    local flag
    for flag in postgres openbao stepca http01-admin; do
      grep -qF -- "--${flag}-host-port \"\$" "$path" \
        || die "${script} does not hand infra install a chosen --${flag}-host-port"
    done
  done
  ok "both lifecycle harnesses derive, record, sweep and install at a per-run scope"
}

# The marker has to outlive everything that could leave a container
# behind, or a run killed during its own teardown is collected while its
# containers are still being removed.
check_marker_removal_is_last() {
  local script path cleanup_body remove_line last_line
  for script in "${LIFECYCLE_SCRIPTS[@]}"; do
    path="$IMPL_DIR/$script"
    cleanup_body="$(awk '/^cleanup\(\) \{$/ { inside = 1; next }
      inside && $0 == "}" { inside = 0 }
      inside { print }' "$path")"
    remove_line="$(grep -n '^  remove_run_marker ' <<<"$cleanup_body" | head -n 1 | cut -d: -f1)"
    last_line="$(grep -n '^  exit_with_cleanup_status ' <<<"$cleanup_body" | head -n 1 | cut -d: -f1)"
    [ -n "$remove_line" ] && [ -n "$last_line" ] \
      || die "${script}: cleanup does not both remove the marker and end with the run's status"
    [ "$remove_line" -lt "$last_line" ] \
      || die "${script}: cleanup removes its marker after it has already exited"
    # Inside the ownership guard it would be skipped on exactly the run
    # that aborted before taking the stack over — which still wrote no
    # marker, but whose successor would then be reading a guard rather
    # than a fact.  `lib/leftovers.sh`'s own validation covers what does
    # belong inside that guard.
    grep -q '^  remove_run_marker ' <<<"$cleanup_body" \
      || die "${script}: the marker is removed from inside the ownership guard"
  done
  ok "the marker is removed on the way out, after the teardown it has to outlive"
}

# Every published port a lifecycle script addresses is one this run
# chose, and every container it addresses is named after this run's
# instance. Both grow back one call site at a time, and a single one is
# enough to make two concurrent runs collide.
check_no_hardcoded_identity() {
  local script path offenders
  for script in "${LIFECYCLE_SCRIPTS[@]}"; do
    path="$IMPL_DIR/$script"
    # Compose *service* names are keys in the compose file and are not
    # container names: `bootroot-http01` is a service, and the four
    # `docker compose` subcommands that name one are left alone.
    offenders="$(grep -nE '^[^#]*docker (logs|exec|inspect|rm|kill|port|cp) +bootroot-' "$path" || true)"
    [ -z "$offenders" ] \
      || die "${script} addresses a container by a hardcoded name: ${offenders//$'\n'/; }"
    offenders="$(grep -nE '^[^#]*(127\.0\.0\.1|localhost|\$\{STEPCA_HOST_IP\}|\$\{RESPONDER_HOST_IP\}|\$\{STEPCA_HOST_NAME\}|\$\{RESPONDER_HOST_NAME\}):(8200|9000|8080|5432|5433)\b' "$path" || true)"
    [ -z "$offenders" ] \
      || die "${script} addresses a published port by a hardcoded number: ${offenders//$'\n'/; }"
    offenders="$(grep -n 'COMPOSE_PROJECT_NAME:-bootroot' "$path" || true)"
    [ -z "$offenders" ] \
      || die "${script} still scopes a compose call to the default project: ${offenders//$'\n'/; }"
  done
  ok "no lifecycle harness addresses a container, a port or a project by a hardcoded default"
}

check_limit_matches_the_rust_derivation
check_derived_instances_are_installable
check_truncation_keeps_the_discriminating_tail
check_derivation_rejects_what_it_cannot_derive
check_markers
check_default_marker_dir_is_per_user
check_liveness
install_docker_stub
check_sweep_collects_only_dead_runs
check_sweep_keeps_a_marker_it_could_not_clear
check_harness_wiring
check_marker_removal_is_last
check_no_hardcoded_identity

echo "[$LABEL] OK: the per-run E2E identity holds"
