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
# And the hosts lock for the same reason, one step further: the real one
# is `/etc/hosts` itself, machine-wide, so locking it here would refuse
# a live `hosts`-mode run's turn at the file it is editing. Every path
# below stands in for that file, and is created like it — the lock opens
# what is there and never creates it.
export BOOTROOT_E2E_HOSTS_LOCK="$WORK_DIR/hosts.lock"

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

# A path's permission bits, in octal. The harness runs on
# both stats, and GNU has to be tried first — the order is the whole
# point rather than a preference.
#
# The two spell the same job with the same letters and opposite meanings:
# `-f` is BSD's format string, and GNU's *filesystem* status. So a
# BSD-first probe does not fail over on Linux, it succeeds — GNU `stat
# -f` happily prints a block-and-inode report for the format string, the
# `||` never fires, and the mode comparison is left holding a multi-line
# filesystem dump that is never going to equal `700`. GNU-first has no
# such trap: BSD `stat` rejects `-c` outright, so the fallback runs.
path_mode() {
  local dir="${1:-$BOOTROOT_E2E_RUN_MARKER_DIR}"
  stat -c '%a' "$dir" 2>/dev/null \
    || stat -f '%OLp' "$dir"
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

# Compose's own rule for a project name: a lowercase letter or a digit
# first, then lowercase letters, digits, `-` and `_`. No length limit —
# that is the whole difference from an instance name.
compose_project_is_valid() {
  local name="$1"
  [ -n "$name" ] || return 1
  case "$name" in
    ["$RUN_SCOPE_INSTANCE_ALPHABET"]*) ;;
    *) return 1 ;;
  esac
  case "$name" in
    *[!"$RUN_SCOPE_PROJECT_ALPHABET"]*) return 1 ;;
  esac
  return 0
}

# Reads the prefix a harness declares for one half of its identity.
harness_prefix() {
  local script="$1" var="$2" value
  value="$(sed -n "s/^${var}=\"\(.*\)\"\$/\1/p" "$IMPL_DIR/$script")"
  [ -n "$value" ] || die "${script} declares no ${var}"
  printf '%s' "$value"
}

check_derived_instances_are_installable() {
  local script prefix basename token instance
  for script in "${LIFECYCLE_SCRIPTS[@]}"; do
    prefix="$(harness_prefix "$script" RUN_INSTANCE_PREFIX)"
    for basename in "${ARTIFACT_BASENAMES[@]}"; do
      token="$(run_scope_token "/tmp/e2e/$basename")"
      instance="$(run_scope_instance "$prefix" "$token")"
      instance_name_is_valid "$instance" \
        || die "${script} derives '${instance}' from ${basename}, which infra install would reject"
    done
  done
  ok "every matrix step's derived instance is one infra install accepts, under a CI-length run id"
}

# The instance and the project are two values, derived separately from
# one token under two different rules. Deriving one from the other is
# what the issue rules out, and the visible consequence is length: an
# instance name is cut to 39 characters, and for a CI-length
# `GITHUB_RUN_ID` the project the same run derives is longer than an
# instance name is ever allowed to be.
check_instance_and_project_are_derived_separately() {
  local script instance_prefix project_prefix basename token instance project
  for script in "${LIFECYCLE_SCRIPTS[@]}"; do
    instance_prefix="$(harness_prefix "$script" RUN_INSTANCE_PREFIX)"
    project_prefix="$(harness_prefix "$script" RUN_PROJECT_PREFIX)"
    for basename in "${ARTIFACT_BASENAMES[@]}"; do
      token="$(run_scope_token "/tmp/e2e/$basename")"
      instance="$(run_scope_instance "$instance_prefix" "$token")"
      project="$(run_scope_project "$project_prefix" "$token")"
      compose_project_is_valid "$project" \
        || die "${script} derives the project '${project}' from ${basename}, which Compose would reject"
      [ "$project" != "$instance" ] \
        || die "${script} derives one string for both halves of its identity from ${basename}: '${instance}'"
      case "$basename" in
        ci-*)
          [ "${#project}" -gt "$BOOTROOT_MAX_INSTANCE_NAME_LEN" ] \
            || die "${script} derives the project '${project}' (${#project} characters) from ${basename}; under a CI-length run id it must outgrow the ${BOOTROOT_MAX_INSTANCE_NAME_LEN}-character instance limit that proves the two are derived apart"
          ;;
      esac
    done
  done
  ok "the instance and the project are separate derivations, and the project outgrows the instance limit under a CI-length run id"
}

# The sweep honours a marker only when both halves sit in one of the
# library's declared namespaces, and each harness declares its own two
# prefixes as literals of its own. Those are two statements of one fact,
# and this is what keeps them the same fact.
#
# Drift here is silent in the direction that matters. A harness given a
# prefix the table does not carry still runs, still installs and still
# writes a marker — and then no sweep will ever honour that marker, so
# every run of that harness that is killed strands its stack on the host
# for good. Nothing in a green matrix can see it, because a refused
# marker is kept, and a kept marker is indistinguishable from one waiting
# to be retried.
check_harness_namespaces_are_declared() {
  local script instance_prefix project_prefix pair found
  for script in "${LIFECYCLE_SCRIPTS[@]}"; do
    instance_prefix="$(harness_prefix "$script" RUN_INSTANCE_PREFIX)"
    project_prefix="$(harness_prefix "$script" RUN_PROJECT_PREFIX)"
    found=0
    for pair in "${BOOTROOT_E2E_RUN_NAMESPACES[@]}"; do
      [ "$pair" = "${instance_prefix}:${project_prefix}" ] || continue
      found=1
      break
    done
    [ "$found" -eq 1 ] \
      || die "${script} derives its identity under '${instance_prefix}' and '${project_prefix}', a pair BOOTROOT_E2E_RUN_NAMESPACES does not carry (${BOOTROOT_E2E_RUN_NAMESPACES[*]}); the sweep refuses every marker outside that table, so this harness's killed runs would never be collected"
    # Round trip: what the harness actually derives has to be honoured,
    # not merely the prefixes it declares.
    run_scope_marker_is_derived \
      "$(run_scope_instance "$instance_prefix" "$(run_scope_token /tmp/e2e/ci-run-12345678901)")" \
      "$(run_scope_project "$project_prefix" "$(run_scope_token /tmp/e2e/ci-run-12345678901)")" \
      || die "${script}'s own derived instance and project are not a pair the sweep would honour"
  done
  ok "each harness's declared prefixes are a namespace the sweep honours, and what it derives from them round-trips"
}

# The default identity has to be unreachable by construction, not by the
# absence of a marker naming it. A sweep confined to a table of prefixes
# is only confined if `bootroot` cannot be spelled with them.
check_no_namespace_can_name_the_default_identity() {
  local default="bootroot" pair instance_prefix project_prefix
  for pair in "${BOOTROOT_E2E_RUN_NAMESPACES[@]}"; do
    instance_prefix="${pair%%:*}"
    project_prefix="${pair#*:}"
    case "$default" in
      "$instance_prefix"*)
        die "the instance prefix '${instance_prefix}' admits the default identity '${default}'"
        ;;
    esac
    case "$default" in
      "$project_prefix"*)
        die "the project prefix '${project_prefix}' admits the default project '${default}'"
        ;;
    esac
  done
  if run_scope_marker_is_derived "$default" "$default"; then
    die "a marker naming the default identity is one the sweep would collect"
  fi
  ok "no declared namespace can spell the default identity, so the sweep cannot reach a real install"
}

check_project_derivation_rejects_what_compose_would() {
  local status=0
  ( run_scope_project "bootroot-e2e-local-" "..." ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "an identifier holding nothing a project may use derived a project instead of failing"
  status=0
  ( run_scope_assert_valid_project "-leading-dash" ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "the guard accepted a project name starting with a dash"
  status=0
  ( run_scope_assert_valid_project "Bootroot-E2E" ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "the guard accepted a project name carrying uppercase"
  status=0
  ( run_scope_assert_valid_project "bootroot e2e" ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "the guard accepted a project name carrying a space"
  # An over-long project is the case the instance guard rejects and this
  # one must not: the absence of a length limit is the difference.
  run_scope_assert_valid_project "$(printf 'a%.0s' $(seq 1 120))" \
    || die "the guard rejected a long project name; only instance names are length-bounded"
  ok "the project guard rejects what Compose would, and imposes no instance-name length limit"
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

# The separation only holds because the binary ranks the exported
# project above the declared instance, and applies it to the project
# alone. That ranking lives in `src/commands/compose_project.rs`, is
# pinned there by a unit test, and is invisible from here — a harness run
# under a reordered resolver would install into one project while
# scoping its own `docker compose` calls to another, and only a
# concurrent run would notice.
#
# So this asserts the pin is still in place rather than re-deriving the
# behaviour: the test named below is what fails if the ranking moves, and
# a rename that leaves this check unadjusted is a deliberate act rather
# than an oversight.
RANKING_TEST="compose_project_name_wins_over_the_flag_for_the_project_only"

check_the_binary_ranks_the_override_above_the_flag() {
  grep -q "fn ${RANKING_TEST}(" src/commands/compose_project.rs \
    || die "src/commands/compose_project.rs no longer pins the ranking this harness depends on (${RANKING_TEST}); the derived project reaches the binary as COMPOSE_PROJECT_NAME, which must outrank --instance-name for the project and nothing else"
  ok "the ranking the derived project depends on is pinned by the binary's own tests"
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
  # A pair from one derived namespace, because that is all a marker may
  # hold: the instance and the project are two different strings, as a
  # real run's are, and both sit inside the local harness's namespace.
  local instance="e2e-local-marker" project="bootroot-e2e-local-marker" path
  path="$(run_marker_path "$instance")"
  write_run_marker "$instance" "$project"
  [ -f "$path" ] || die "write_run_marker wrote no marker at ${path}"
  [ "$(run_marker_field "$path" pid)" = "$$" ] \
    || die "the marker does not record this process's pid"
  [ "$(run_marker_field "$path" project)" = "$project" ] \
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
  write_run_marker "$instance" "$project"
  [ "$(path_mode)" = "700" ] \
    || die "write_run_marker left the marker directory at mode $(path_mode)"
  chmod 777 "$BOOTROOT_E2E_RUN_MARKER_DIR"
  sweep_dead_run_instances "$LABEL" /dev/null >/dev/null 2>&1 || true
  [ "$(path_mode)" = "700" ] \
    || die "the sweep read a marker directory at mode $(path_mode)"
  rm -f "$path"
  ok "a pre-existing marker directory is restricted to its owner before it is read or written"

  # Another run's marker is not this run's to remove: dropping it would
  # hide that run's containers from every later sweep.
  printf 'pid=%s\nproject=%s\n' "999999" "$project" >"$path"
  remove_run_marker "$instance"
  [ -f "$path" ] || die "remove_run_marker removed a marker recording another pid"
  ok "a marker recording another pid survives this run's cleanup"

  write_run_marker "$instance" "$project"
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
  write_run_marker "$instance" "$project"
  remove_run_marker "$instance" 1 2>/dev/null
  [ -f "$path" ] \
    || die "remove_run_marker dropped the marker of a run whose teardown left containers behind"
  remove_run_marker "$instance" 0
  [ ! -f "$path" ] || die "remove_run_marker kept the marker of a clean teardown"
  ok "a marker survives a teardown that did not finish, and goes with one that did"
}

# Ownership cannot see a symbolic link: every test operator but `-L`
# follows one, so `-O` reports on the target. A link planted at this
# predictable `/tmp` path and pointed at a directory this user owns
# therefore passes the ownership check while handing the sweep a
# directory that was never the harness's — whose filenames it reads as
# instance names and whose files it then removes.
check_marker_dir_refuses_a_symlink() {
  local victim="$WORK_DIR/symlink-victim" link="$WORK_DIR/symlink-markers"
  local bystander status=0
  rm -rf "$victim" "$link"
  mkdir -p "$victim"
  chmod 755 "$victim"
  bystander="$victim/e2e-local-not-a-marker"
  : >"$bystander"
  ln -s "$victim" "$link"

  (BOOTROOT_E2E_RUN_MARKER_DIR="$link" sweep_dead_run_instances "$LABEL" /dev/null) \
    >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] \
    || die "the sweep read a marker directory reached through a symbolic link"
  # A pair the namespace check accepts, so what refuses this write can
  # only be the link. Handing it an out-of-namespace pair would abort
  # with the same status for the other reason and leave the link
  # untested.
  status=0
  (BOOTROOT_E2E_RUN_MARKER_DIR="$link" write_run_marker "e2e-local-link" "bootroot-e2e-local-link") \
    >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] \
    || die "a marker was written into a directory reached through a symbolic link"

  [ -f "$bystander" ] \
    || die "the refused symbolic link's target had a file removed from it"
  [ "$(path_mode "$victim")" = "755" ] \
    || die "the refused symbolic link's target was re-moded to $(path_mode "$victim")"
  rm -rf "$victim" "$link"
  ok "a marker directory reached through a symbolic link is refused, not followed"
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

# ---------------------------------------------------------------------------
# The /etc/hosts mutex
# ---------------------------------------------------------------------------
#
# `hosts` mode was serialised by accident until every run got its own
# project, container names and ports: the second run failed at `up` long
# before it reached `/etc/hosts`. Nothing stops the two from reaching
# that file together now, and what they do to each other there is silent
# — the second finds the host names already present and adds nothing,
# then the first's cleanup strips both marker lines while the second is
# still resolving through them. So the serialisation is stated instead,
# and this is what says it still holds.
#
# What holds the lock is `flock(2)` on an open descriptor for
# `/etc/hosts` itself, so almost everything below is about two
# properties. Ownership is the kernel's, which is what makes the
# contention here real rather than simulated — a lock the library judged
# by reading a pid out of a file could be driven with `printf`, and this
# one cannot be; it takes a live process holding a descriptor, and a
# `kill -9` to end it. And the inode is the file the run edits, which no
# unprivileged user can put a different one in the place of: a lock file
# of the harness's own, at a predictable name in a world-writable `/tmp`,
# can be swapped between the check that refuses a link and the open that
# follows it, leaving two runs holding locks on two inodes and both
# editing the file. So the checks below drive a lock that creates
# nothing, writes nothing and re-modes nothing.

# A process that takes the lock and holds it until it is killed, or until
# something is written to its fifo.
#
# It waits on a `read` builtin rather than a `sleep`, and this is not a
# preference: `sleep` is a child, it would inherit the descriptor the
# lock lives on, and it would go on holding the lock for up to a second
# after the holder was killed. That is the same inheritance the harnesses
# close fd 9 for, arriving here as a flaky check.
install_hosts_lock_helpers() {
  cat >"$WORK_DIR/hold-hosts-lock.sh" <<'HOLDER'
#!/usr/bin/env bash
set -euo pipefail
fail() { printf 'holder-fail: %s\n' "$1" >&2; exit 9; }
# shellcheck source=impl/lib/leftovers.sh
. "$1/lib/leftovers.sh"
# shellcheck source=impl/lib/run-scope.sh
. "$1/lib/run-scope.sh"
acquire_hosts_lock "the run that got there first"
: >"$2"
read -r _ <"$3" || true
release_hosts_lock
HOLDER
  cat >"$WORK_DIR/take-hosts-lock.sh" <<'TAKER'
#!/usr/bin/env bash
set -euo pipefail
fail() { printf 'library-fail: %s\n' "$1" >&2; exit 9; }
# shellcheck source=impl/lib/leftovers.sh
. "$1/lib/leftovers.sh"
# shellcheck source=impl/lib/run-scope.sh
. "$1/lib/run-scope.sh"
acquire_hosts_lock "${2:-a contender}"
hosts_lock_held || exit 1
release_hosts_lock
TAKER
  chmod 755 "$WORK_DIR/hold-hosts-lock.sh" "$WORK_DIR/take-hosts-lock.sh"
}

HOSTS_LOCK_HOLDER_PID=""
HOSTS_LOCK_HOLDER_FIFO=""

# Starts the holder and returns once it has the lock. Every child here is
# started with `9>&-`, for the reason the harnesses do it: a descriptor
# this process holds would otherwise be held by its children too.
start_hosts_lock_holder() {
  local lock="$1" ready="$WORK_DIR/holder.ready"
  HOSTS_LOCK_HOLDER_FIFO="$WORK_DIR/holder.fifo"
  rm -f "$ready" "$HOSTS_LOCK_HOLDER_FIFO"
  mkfifo "$HOSTS_LOCK_HOLDER_FIFO"
  BOOTROOT_E2E_HOSTS_LOCK="$lock" \
    "$WORK_DIR/hold-hosts-lock.sh" "$IMPL_DIR" "$ready" "$HOSTS_LOCK_HOLDER_FIFO" 9>&- &
  HOSTS_LOCK_HOLDER_PID=$!
  for _ in $(seq 1 100); do
    [ -f "$ready" ] && return 0
    kill -0 "$HOSTS_LOCK_HOLDER_PID" 2>/dev/null \
      || die "the background hosts-lock holder died before it took the lock"
    sleep 0.1
  done
  die "the background hosts-lock holder never took the lock"
}

# Ends the holder the way a `SIGKILL`ed run ends: no release, no cleanup,
# nothing left to recover.
kill_hosts_lock_holder() {
  [ -n "$HOSTS_LOCK_HOLDER_PID" ] || return 0
  kill -9 "$HOSTS_LOCK_HOLDER_PID" 2>/dev/null || true
  wait "$HOSTS_LOCK_HOLDER_PID" 2>/dev/null || true
  HOSTS_LOCK_HOLDER_PID=""
  rm -f "$HOSTS_LOCK_HOLDER_FIFO"
}

# Runs one contender in a process of its own and prints its status. What
# it said on the way out is left in `$CONTENDER_ERR`, because a refusal
# that names the wrong run is a refusal an operator acts on. The path is
# fixed rather than set here: the status is read through a command
# substitution, so nothing this assigns would outlive the subshell.
CONTENDER_ERR="$WORK_DIR/contender.err"

hosts_lock_contender() {
  local lock="$1" label="${2:-a contender}" impl="${3:-auto}" status=0
  BOOTROOT_E2E_HOSTS_LOCK="$lock" BOOTROOT_E2E_HOSTS_LOCK_IMPL="$impl" \
    "$WORK_DIR/take-hosts-lock.sh" "$IMPL_DIR" "$label" >/dev/null 2>"$CONTENDER_ERR" 9>&- \
    || status=$?
  printf '%s' "$status"
}

# A stand-in for `/etc/hosts`. The lock opens what is already there and
# never creates it, so every path locked below has to exist first — and
# carries contents the lock must be seen not to disturb.
make_hosts_file() {
  local path="$1"
  rm -f "$path"
  printf '127.0.0.1\tlocalhost\n::1\tlocalhost\n' >"$path"
}

check_hosts_lock() {
  local lock="$BOOTROOT_E2E_HOSTS_LOCK" label status=0 contents mode
  make_hosts_file "$lock"
  contents="$(cat "$lock")"
  mode="$(path_mode "$lock")"
  label="$(hosts_lock_label_path)"
  rm -f "$label"
  BOOTROOT_HOSTS_LOCK_HELD=0

  acquire_hosts_lock "validator"
  hosts_lock_held || die "acquire_hosts_lock returned without recording that it holds the lock"
  # The lock is the file the run is about to edit, so what it must not do
  # to it is anything: a lock that truncated, appended to or re-moded
  # `/etc/hosts` would be doing the damage it exists to serialise.
  [ "$(cat "$lock")" = "$contents" ] \
    || die "taking the hosts lock changed the contents of the file it locks"
  [ "$(path_mode "$lock")" = "$mode" ] \
    || die "taking the hosts lock re-moded the file it locks"
  [ "$(run_marker_field "$label" pid)" = "$$" ] \
    || die "the holder recorded no pid of its own for the next run to name"
  ok "a hosts-mode run locks the file it is about to edit, writes nothing to it, and records itself elsewhere"

  # A second run is refused, and leaves the holder's label untouched: the
  # whole point is that it stops before it can edit the file.
  status="$(hosts_lock_contender "$lock" "the second run")"
  [ "$status" -eq 9 ] \
    || die "a second hosts-mode run was not refused while a live run held the lock (status ${status})"
  [ "$(run_marker_field "$label" pid)" = "$$" ] \
    || die "the refused run overwrote the live holder's label"
  grep -q "pid $$" "$CONTENDER_ERR" \
    || die "the refusal does not name the run holding the lock: $(cat "$CONTENDER_ERR")"
  ok "a second hosts-mode run is refused while a live one holds the lock, and told which run holds it"

  # A label is a record of a live holder or it is nothing. One left
  # behind by a run that was killed names a process that released the
  # lock the moment it died, so a run refused afterwards is being refused
  # by somebody else — and naming the dead run would send its operator
  # after a process that is not there.
  printf 'pid=%s\nholder=%s\n' 4194305 "a run that was killed" >"${label}.stale.tmp"
  mv "${label}.stale.tmp" "$label"
  status="$(hosts_lock_contender "$lock" "the run refused by somebody else")"
  [ "$status" -eq 9 ] \
    || die "a run was admitted while this process held the lock (status ${status})"
  ! grep -q "pid 4194305" "$CONTENDER_ERR" \
    || die "the refusal named a dead run's label as the holder: $(cat "$CONTENDER_ERR")"
  ok "a label left by a killed run is not named as the holder of a lock it no longer has"
  printf 'pid=%s\nholder=%s\n' "$$" "validator" >"${label}.ours.tmp"
  mv "${label}.ours.tmp" "$label"

  release_hosts_lock
  ! hosts_lock_held || die "release_hosts_lock still reads as holding the lock"
  [ "$(cat "$lock")" = "$contents" ] \
    || die "releasing the hosts lock changed the contents of the file it locked"
  [ ! -f "$label" ] \
    || die "release_hosts_lock left this run's label behind for the next run to name"
  status="$(hosts_lock_contender "$lock" "the next run")"
  [ "$status" -eq 0 ] \
    || die "the lock could not be taken after it was released (status ${status})"
  ok "a run releases the lock on the way out, and leaves the file exactly as it found it"
}

# The one property everything else rests on: a run that is killed leaves
# no lock behind, because the lock was never the file. There is nothing
# to reclaim, nothing to judge, and no window in which a recovery has a
# live owner's lock out of the path — which is where a pid file fails,
# whatever the recovery does with what it read.
check_hosts_lock_dies_with_the_run() {
  local lock="$WORK_DIR/killed-hosts.lock" status
  make_hosts_file "$lock"
  start_hosts_lock_holder "$lock"
  status="$(hosts_lock_contender "$lock" "the run that arrived second")"
  [ "$status" -eq 9 ] \
    || die "a run was admitted while a live holder had the lock (status ${status})"
  kill_hosts_lock_holder
  [ -f "$lock" ] || die "the killed holder's lock file vanished with it"
  status="$(hosts_lock_contender "$lock" "the run after the killed one")"
  [ "$status" -eq 0 ] \
    || die "the lock a killed run held was not free afterwards (status ${status}); a run that is killed must leave nothing to reclaim"
  rm -f "$lock"
  ok "a killed run's lock is released by the kernel, so there is no stale lock and nothing to recover"
}

# And the label is not what decides, in either direction. One naming a
# live process does not make the lock held, and none at all does not make
# it free. Anything else is a lock that can be taken twice by writing a
# file, or refused for ever by planting one.
check_hosts_lock_is_the_kernels() {
  local lock="$WORK_DIR/label-hosts.lock" label status
  label="$(hosts_lock_label_path)"
  make_hosts_file "$lock"
  ensure_run_marker_dir
  printf 'pid=%s\nholder=%s\n' "$$" "a process that is alive and holds nothing" >"$label"
  status="$(hosts_lock_contender "$lock" "the run that read the label")"
  [ "$status" -eq 0 ] \
    || die "a label naming a live process was treated as the lock being held (status ${status}); the label is a message, not the lock"

  rm -f "$label"
  start_hosts_lock_holder "$lock"
  rm -f "$label"
  status="$(hosts_lock_contender "$lock" "the run that found no label")"
  [ "$status" -eq 9 ] \
    || die "the lock was taken from a live holder because no label named it (status ${status})"
  kill_hosts_lock_holder
  rm -f "$lock" "$label"
  ok "the lock is the kernel's: a label naming a live pid does not hold it, and no label does not free it"
}

# The file this locks is root's, and every run that takes the lock is not
# — `/etc/hosts` is `0644 root:wheel`, which is exactly why the mode a
# run may edit it in is `sudo`. `flock(2)` locks a descriptor however it
# was opened, so a read-only open is enough, and it has to be: a lock
# needing write access would be one no ordinary run could take, on the
# one file `hosts` mode exists to serialise.
#
# One uid owns everything this script creates, so what stands in for that
# file is a mode this user's own `open` for writing cannot pass.
check_hosts_lock_needs_no_write_access() {
  local lock="$WORK_DIR/readonly-hosts.lock" status=0 contents
  if [ "$(id -u)" -eq 0 ]; then
    ok "skipped as root, which opens a file for writing whoever owns it"
    return 0
  fi
  make_hosts_file "$lock"
  contents="$(cat "$lock")"
  chmod 444 "$lock"
  (
    export BOOTROOT_E2E_HOSTS_LOCK="$lock"
    "$WORK_DIR/take-hosts-lock.sh" "$IMPL_DIR" "a run locking a file it may not write" 9>&-
  ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 0 ] \
    || die "a file this user cannot write could not be locked (status ${status}); that is what /etc/hosts is to every run that takes this lock"
  [ "$(path_mode "$lock")" = "444" ] \
    || die "the lock re-moded the file it locked; /etc/hosts is not a harness's to re-mode"
  [ "$(cat "$lock")" = "$contents" ] \
    || die "the lock wrote to a file it was only supposed to lock"
  chmod 644 "$lock"
  rm -f "$lock"
  ok "a file this run may read and not write is still lockable, and is left exactly as it was"
}

# Every way of calling `flock(2)` this host has, driven both ways. They
# are interchangeable by construction — each locks the descriptor it is
# handed rather than a path of its own — and a mismatch would show up
# only where the harness and a concurrent run picked different tools.
check_hosts_lock_backends() {
  local lock="$WORK_DIR/impl-hosts.lock" impl status tried=""
  for impl in flock perl python3; do
    command -v "$impl" >/dev/null 2>&1 || continue
    tried="$tried $impl"
    make_hosts_file "$lock"
    status="$(hosts_lock_contender "$lock" "a run using ${impl}" "$impl")"
    [ "$status" -eq 0 ] \
      || die "the hosts lock could not be taken through ${impl} (status ${status})"
    start_hosts_lock_holder "$lock"
    status="$(hosts_lock_contender "$lock" "a run using ${impl}" "$impl")"
    [ "$status" -eq 9 ] \
      || die "${impl} did not see the lock a live holder had (status ${status})"
    kill_hosts_lock_holder
  done
  rm -f "$lock"
  [ -n "$tried" ] \
    || die "this host has none of flock, perl or python3, so nothing can take the hosts lock"
  ok "every flock(2) caller this host has takes the lock when it is free and refuses it when it is held:${tried}"
}

# A lock that creates what it locks is a lock on an inode of its own
# making, which is the whole of what a lock file in a shared directory
# gets wrong: whoever gets to that path first decides what every run
# afterwards locks, and can put a different inode there between one run's
# open and the next's. So a path that resolves to nothing is refused —
# and the run is refused with it, rather than going on to edit the file
# it never locked.
check_hosts_lock_creates_nothing() {
  local missing="$WORK_DIR/hosts-that-is-not-there"
  local target="$WORK_DIR/hosts-lock-target" link="$WORK_DIR/hosts-lock-link"
  local status
  rm -f "$missing" "$target" "$link"
  status="$(hosts_lock_contender "$missing" "the run with nothing to lock")"
  [ "$status" -eq 9 ] \
    || die "a run was admitted after locking a file that was not there (status ${status})"
  [ ! -e "$missing" ] \
    || die "the hosts lock created the file it was supposed to be locking"
  ln -s "$target" "$link"
  status="$(hosts_lock_contender "$link" "the linked run")"
  [ "$status" -eq 9 ] \
    || die "a run was admitted through a symbolic link that pointed at nothing"
  [ ! -e "$target" ] \
    || die "the hosts lock created a dangling link's target"
  rm -f "$target" "$link"
  ok "the hosts lock opens what is there and creates nothing, so no path it is pointed at becomes a lock of its own"
}

# The lock is the file, and the file is `/etc/hosts`: it must not become
# a file of the harness's own at a shared path again, where an inode can
# be swapped in between the check that vets it and the open that locks
# it. The default is asserted against what both harnesses edit, and the
# library is held to opening it and nothing more.
check_default_hosts_lock_is_the_file_it_protects() {
  local resolved script path offenders
  resolved="$(
    unset BOOTROOT_E2E_HOSTS_LOCK
    # shellcheck source=impl/lib/run-scope.sh
    . "$IMPL_DIR/lib/run-scope.sh"
    printf '%s' "$BOOTROOT_E2E_HOSTS_LOCK"
  )"
  [ "$resolved" = "/etc/hosts" ] \
    || die "the default hosts lock is '${resolved}' rather than /etc/hosts; a lock at a path of the harness's own can be swapped for another inode between the check and the open, and one under \$TMPDIR is not even machine-wide"
  for script in "${LIFECYCLE_SCRIPTS[@]}"; do
    path="$IMPL_DIR/$script"
    grep -q 'run_sudo cp "\$tmp_file" /etc/hosts' "$path" \
      || die "${script} no longer rewrites /etc/hosts the way the lock assumes; the lock is that file's inode, so an edit that renames over it locks one inode and edits another"
  done
  # The open is read-only, and there is no second one. `>` or `>>` on fd 9
  # would create the file at a path that resolved to nothing and truncate
  # one that did not — on `/etc/hosts`.
  offenders="$(grep -nE 'exec 9>' "$IMPL_DIR/lib/run-scope.sh" | grep -v 'exec 9>&-' || true)"
  [ -z "$offenders" ] \
    || die "run-scope.sh opens the hosts lock for writing: ${offenders//$'\n'/; }"
  offenders="$(grep -n '"\$BOOTROOT_E2E_HOSTS_LOCK"' "$IMPL_DIR/lib/run-scope.sh" \
    | grep -v 'exec 9<"\$BOOTROOT_E2E_HOSTS_LOCK"' || true)"
  [ -z "$offenders" ] \
    || die "run-scope.sh hands the file it locks to something other than that one read-only open: ${offenders//$'\n'/; }"
  ok "the hosts lock is /etc/hosts itself, opened read-only, and the file both harnesses edit in place"
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
IMAGES="${STUB_STATE}/images"

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
  image:inspect)
    printf 'image-inspect %s\n' "$3" >>"${QUERY_LOG:-/dev/null}"
    refuse_if_failing image-inspect
    grep -qxF "$3" "$IMAGES" || { echo "Error: No such image: $3" >&2; exit 1; }
    exit 0
    ;;
  image:rm)
    [ "${3:-}" = "-f" ] || { echo "docker stub: unforced image rm: $*" >&2; exit 125; }
    printf 'image-rm %s\n' "$4" >>"${QUERY_LOG:-/dev/null}"
    refuse_if_failing image-rm
    grep -qxF "$4" "$IMAGES" || { echo "Error: No such image: $4" >&2; exit 1; }
    drop_line "$IMAGES" "$4"
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
  local containers="$1" volumes="$2" networks="$3" images="${4:-}"
  printf '%s\n' $containers | grep -v '^$' >"$STUB_STATE/containers" || : >"$STUB_STATE/containers"
  printf '%s\n' "$volumes" | grep -v '^$' >"$STUB_STATE/volumes" || : >"$STUB_STATE/volumes"
  printf '%s\n' "$networks" | grep -v '^$' >"$STUB_STATE/networks" || : >"$STUB_STATE/networks"
  printf '%s\n' $images | grep -v '^$' >"$STUB_STATE/images" || : >"$STUB_STATE/images"
  rm -rf "$BOOTROOT_E2E_RUN_MARKER_DIR"
  mkdir -p "$BOOTROOT_E2E_RUN_MARKER_DIR"
  : >"$WORK_DIR/query.log"
  : >"$WORK_DIR/sweep.log"
}

# The project is a separate argument because it is a separate value: a
# run's project is derived apart from its instance and is a different
# string, so a sweep that reconstructed it from the marker's filename
# would query a label no volume of that run carries.
seed_marker() {
  local instance="$1" pid="$2" project="$3"
  printf 'pid=%s\nproject=%s\n' "$pid" "$project" \
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
DEAD_PROJECT="bootroot-e2e-local-dead-run-1770000000-4242"
LIVE="e2e-local-live"
LIVE_PROJECT="bootroot-e2e-local-live-run-1770000000-4243"

check_sweep_collects_only_dead_runs() {
  local status=0
  seed_daemon \
    "$(instance_containers "$DEAD") $(instance_containers "$LIVE") bootroot-openbao bootroot-ca" \
    "$(printf '%s vol-dead\n%s vol-live\n' "$DEAD_PROJECT" "$LIVE_PROJECT")" \
    "$(printf '%s net-dead\n%s net-live\n' "$DEAD_PROJECT" "$LIVE_PROJECT")" \
    "$(run_scope_http01_image "$DEAD") $(run_scope_http01_image "$LIVE") ${BOOTROOT_HTTP01_IMAGE_REPO}:latest"
  seed_marker "$DEAD" 4194305 "$DEAD_PROJECT"
  seed_marker "$LIVE" "$$" "$LIVE_PROJECT"
  # The `hosts` lock's holder label shares this directory, which is the
  # one directory whose ownership is already established. Its name is one
  # no instance can carry, and the sweep has to read it as such — the pid
  # here is a dead one, as a killed holder's label carries, which is
  # exactly when a sweep that read the filename as an instance would
  # collect it.
  printf 'pid=%s\nholder=%s\n' 4194305 "a hosts-mode run that was killed" \
    >"$(hosts_lock_label_path)"

  sweep_dead_run_instances "a-label" "$WORK_DIR/sweep.log" || status=$?
  [ "$status" -eq 0 ] || die "the sweep returned ${status} on a daemon it could fully collect"

  [ ! -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$DEAD" ] \
    || die "the sweep left the dead run's marker behind"
  [ -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$LIVE" ] \
    || die "the sweep removed a live run's marker"
  [ -f "$(hosts_lock_label_path)" ] \
    || die "the sweep read the hosts lock's holder label as a run and collected it"

  local expected
  expected="$(printf '%s\n' bootroot-ca bootroot-openbao $(instance_containers "$LIVE") \
    | LC_ALL=C sort | tr '\n' ' ' | sed 's/ *$//')"
  [ "$(daemon_containers)" = "$expected" ] \
    || die "the sweep left '$(daemon_containers)', expected '${expected}'"
  ok "a dead run's nine containers are removed, and a live run's are not"
  ok "a co-located default-identity install is untouched"

  [ "$(awk -v p="$DEAD_PROJECT" '$1 == p' "$STUB_STATE/volumes")" = "" ] \
    || die "the dead run's volume survived"
  [ "$(awk -v p="$LIVE_PROJECT" '$1 == p { print $2 }' "$STUB_STATE/volumes")" = "vol-live" ] \
    || die "the live run's volume did not survive"
  [ "$(awk -v p="$LIVE_PROJECT" '$1 == p { print $2 }' "$STUB_STATE/networks")" = "net-live" ] \
    || die "the live run's network did not survive"
  ok "the dead run's volumes and networks go with it, and the live run's stay"

  # The responder image is the one thing `down` never removes, so a
  # killed run's tag outlives its containers.  It carries the dead run's
  # instance name and nothing else does, which is what keeps the shipped
  # `:latest` a real install built out of reach.
  ! grep -qxF "$(run_scope_http01_image "$DEAD")" "$STUB_STATE/images" \
    || die "the dead run's responder image survived the sweep"
  grep -qxF "$(run_scope_http01_image "$LIVE")" "$STUB_STATE/images" \
    || die "the sweep removed a live run's responder image"
  grep -qxF "${BOOTROOT_HTTP01_IMAGE_REPO}:latest" "$STUB_STATE/images" \
    || die "the sweep removed the default-identity responder image a real install builds"
  ok "the dead run's responder image goes with it, and neither a live run's nor the shipped :latest does"

  # Every removal is by an exact name the marker's instance produces, and
  # every label query names one project in full. A prefix or a wildcard
  # would reach into a real default-identity install on the same host —
  # which is the reason `lib/leftovers.sh` rules them out too.
  local removed asked
  removed="$(awk '$1 == "rm" { print $2 }' "$WORK_DIR/query.log" | LC_ALL=C sort -u)"
  [ "$removed" = "$(printf '%s\n' $(instance_containers "$DEAD") | LC_ALL=C sort)" ] \
    || die "the sweep removed ${removed//$'\n'/ }"
  asked="$(awk '$1 ~ /-ls$/ { print $2 }' "$WORK_DIR/query.log" | LC_ALL=C sort -u)"
  [ "$asked" = "label=com.docker.compose.project=${DEAD_PROJECT}" ] \
    || die "the sweep's label queries were: ${asked//$'\n'/; }"
  ok "the sweep removes exact names and queries one exact project label, never a wildcard"
}

# Everything the sweep does is read out of a marker, so what confines it
# is which markers it acts on. The directory being mode 0700 says no
# other user wrote one; it says nothing about what this user's own host
# left there — an older harness's marker under a naming rule since
# changed, a file made by hand while debugging, a half-written record
# from some other tool that picked the same path.
#
# A file named `bootroot` recording `project=bootroot` and a dead pid is
# the worst of those, and the one that has to be proved harmless: acted
# on as a run, it would remove the nine default-identity containers, then
# every volume and network labelled with the default project, then the
# `:latest` responder image a real install builds. That is the whole of a
# developer's install on the same machine.
check_sweep_refuses_a_marker_outside_the_derived_namespaces() {
  local status=0 defaults foreign
  defaults="$(instance_containers bootroot)"
  seed_daemon \
    "$defaults $(instance_containers "$DEAD")" \
    "$(printf 'bootroot vol-real\n%s vol-dead\n' "$DEAD_PROJECT")" \
    "$(printf 'bootroot net-real\n%s net-dead\n' "$DEAD_PROJECT")" \
    "$(run_scope_http01_image bootroot) $(run_scope_http01_image "$DEAD") ${BOOTROOT_HTTP01_IMAGE_REPO}:latest"

  # The default identity, spelled the way a stale or malformed marker
  # would spell it, with a pid no longer alive.
  seed_marker "bootroot" 4194305 "bootroot"
  # An instance in a derived namespace paired with the default project:
  # half-valid is still not a pair this harness ever wrote, and honouring
  # the project field alone would take the real install's volumes and
  # networks.
  seed_marker "e2e-local-halfway" 4194305 "bootroot"
  # And the mirror of it — a project in a derived namespace under an
  # instance name that is not.
  seed_marker "postgres" 4194305 "$DEAD_PROJECT"
  # A real dead run alongside them, so this proves the sweep still works
  # rather than merely that it did nothing.
  seed_marker "$DEAD" 4194305 "$DEAD_PROJECT"

  sweep_dead_run_instances "a-label" "$WORK_DIR/sweep.log" 2>/dev/null || status=$?
  # Not a failed collection: a marker this harness did not write names
  # nothing a later run could ever collect, so asking every one of them
  # to retry it forever would be reporting a fault that has no fix.
  [ "$status" -eq 0 ] \
    || die "the sweep reported ${status} over markers it correctly refused, which asks every later run to retry something none of them will ever do"

  for foreign in bootroot e2e-local-halfway postgres; do
    [ -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$foreign" ] \
      || die "the sweep removed the marker '${foreign}', which it refused to act on; a marker it does not understand is not its to delete either"
  done
  [ ! -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$DEAD" ] \
    || die "the sweep stopped collecting a genuine dead run"
  ok "a marker outside the derived namespaces is refused and kept, and a real dead run beside it is still collected"

  local expected
  expected="$(printf '%s\n' $defaults | LC_ALL=C sort | tr '\n' ' ' | sed 's/ *$//')"
  [ "$(daemon_containers)" = "$expected" ] \
    || die "the sweep left '$(daemon_containers)', expected the nine default-identity containers '${expected}'"
  [ "$(awk '$1 == "bootroot" { print $2 }' "$STUB_STATE/volumes")" = "vol-real" ] \
    || die "the sweep removed the default-identity install's volume"
  [ "$(awk '$1 == "bootroot" { print $2 }' "$STUB_STATE/networks")" = "net-real" ] \
    || die "the sweep removed the default-identity install's network"
  grep -qxF "$(run_scope_http01_image bootroot)" "$STUB_STATE/images" \
    || die "the sweep removed the default-identity responder image"
  grep -qxF "${BOOTROOT_HTTP01_IMAGE_REPO}:latest" "$STUB_STATE/images" \
    || die "the sweep removed the shipped :latest responder image"
  ok "a co-located default-identity install keeps its containers, volumes, networks and images"

  # Nothing was even asked about outside the one real dead run: a refused
  # marker must not reach the daemon at all, since a query is one
  # `docker rm -f` away from being an removal.
  local removed asked
  removed="$(awk '$1 == "rm" { print $2 }' "$WORK_DIR/query.log" | LC_ALL=C sort -u)"
  [ "$removed" = "$(printf '%s\n' $(instance_containers "$DEAD") | LC_ALL=C sort)" ] \
    || die "the sweep removed ${removed//$'\n'/ }"
  asked="$(awk '$1 ~ /-ls$/ { print $2 }' "$WORK_DIR/query.log" | LC_ALL=C sort -u)"
  [ "$asked" = "label=com.docker.compose.project=${DEAD_PROJECT}" ] \
    || die "the sweep's label queries were: ${asked//$'\n'/; }"
  ok "a refused marker reaches the daemon with no query at all"
}

# The invariant is enforced where markers are written as well as where
# they are read, so a run whose identity fell outside the table is
# stopped before it installs anything a sweep would then never collect.
check_marker_write_refuses_an_undeclared_pair() {
  local status=0
  seed_daemon "" "" ""
  ( write_run_marker "bootroot" "bootroot" ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "a marker naming the default identity was written"
  status=0
  ( write_run_marker "e2e-local-x" "bootroot" ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "a marker pairing a derived instance with the default project was written"
  status=0
  ( write_run_marker "e2e-local-x" "bootroot-e2e-remote-x" ) >/dev/null 2>&1 || status=$?
  [ "$status" -eq 9 ] || die "a marker pairing one harness's instance with the other's project was written"
  [ -z "$(find "$BOOTROOT_E2E_RUN_MARKER_DIR" -type f -print -quit)" ] \
    || die "a refused marker write left a file behind"
  ok "a marker outside the derived namespaces is refused at write time too"
}

check_sweep_keeps_a_marker_it_could_not_clear() {
  local status=0
  seed_daemon "$(instance_containers "$DEAD")" "" ""
  seed_marker "$DEAD" 4194305 "$DEAD_PROJECT"
  FAILING_QUERIES="rm" sweep_dead_run_instances "a-label" "$WORK_DIR/sweep.log" 2>/dev/null || status=$?
  [ "$status" -ne 0 ] || die "a sweep that removed nothing returned 0"
  [ -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$DEAD" ] \
    || die "a sweep that could not collect a dead run dropped its marker anyway"
  ok "a collection that failed keeps the marker, so the next run retries it"

  status=0
  seed_daemon "$(instance_containers "$DEAD")" "" ""
  seed_marker "$DEAD" 4194305 "$DEAD_PROJECT"
  FAILING_QUERIES="list" sweep_dead_run_instances "a-label" "$WORK_DIR/sweep.log" 2>/dev/null || status=$?
  [ "$status" -ne 0 ] || die "a sweep whose container listing failed returned 0"
  [ -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$DEAD" ] \
    || die "a sweep whose listing failed dropped the marker anyway"
  ok "a listing that could not be run fails the sweep rather than reading as nothing to collect"

  # An image that could not be removed is a collection that did not
  # finish, for the same reason a container is: it carries a name only
  # this derivation produces, so once the marker is gone nothing later
  # asks about it.
  status=0
  seed_daemon "" "" "" "$(run_scope_http01_image "$DEAD")"
  seed_marker "$DEAD" 4194305 "$DEAD_PROJECT"
  FAILING_QUERIES="image-rm" sweep_dead_run_instances "a-label" "$WORK_DIR/sweep.log" 2>/dev/null || status=$?
  [ "$status" -ne 0 ] || die "a sweep that could not remove a dead run's image returned 0"
  [ -f "$BOOTROOT_E2E_RUN_MARKER_DIR/$DEAD" ] \
    || die "a sweep that left a dead run's image behind dropped its marker anyway"
  ok "an image the sweep could not remove keeps the marker, like a container it could not remove"

  # Two runs starting at once sweep the same marker. The one that loses
  # the race sees its `rm` fail on a container that is already gone, and
  # that must not read as a collection that failed.
  status=0
  seed_daemon "" "" ""
  seed_marker "$DEAD" 4194305 "$DEAD_PROJECT"
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
    # The instance reaches the binary as a flag; the project reaches it
    # as Compose's own override, which outranks that flag for the
    # project and for nothing else.  Without the export the binary would
    # resolve the instance name as its project and this script's own
    # `docker compose -p` calls would address a project holding none of
    # its containers.
    grep -q '^  export COMPOSE_PROJECT_NAME="\$COMPOSE_PROJECT"$' "$path" \
      || die "${script} does not hand the binary the project it derived"
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

# The compose file builds exactly one image, and its `image:` is the tag
# that build is written to and every later recreate reads back. Two runs
# left on one tag do not collide until one of them recreates the
# responder — which both lifecycle harnesses do, to apply their DNS
# aliases — and what they get then is the other run's build. Nothing
# fails; the run just verifies against an image it did not build.
#
# So the tag is per run, and that has three halves: the compose file has
# to interpolate it, each harness has to export one derived from its own
# instance, and each has to remove it afterwards, because `down` never
# does.
check_responder_image_is_run_scoped() {
  local script path first second
  grep -qF 'image: ${BOOTROOT_HTTP01_IMAGE:-bootroot-http01-responder:latest}' \
    docker-compose.yml \
    || die "docker-compose.yml no longer interpolates the responder image from BOOTROOT_HTTP01_IMAGE at its shipped default; two concurrent runs would build and recreate against one tag"
  for script in "${LIFECYCLE_SCRIPTS[@]}"; do
    path="$IMPL_DIR/$script"
    # Cleared before anything reads it, like the project and the ports:
    # an inherited tag would put this run's build on another run's name.
    grep -q '^unset BOOTROOT_HTTP01_IMAGE$' "$path" \
      || die "${script} does not clear an inherited BOOTROOT_HTTP01_IMAGE"
    grep -qF -- 'RUN_HTTP01_IMAGE="$(run_scope_http01_image "$RUN_INSTANCE")"' "$path" \
      || die "${script} does not derive its responder image from its own instance"
    grep -q '^  export BOOTROOT_HTTP01_IMAGE="\$RUN_HTTP01_IMAGE"$' "$path" \
      || die "${script} does not hand Compose and infra install the image tag it derived"
    grep -qF -- 'remove_run_image "$RUN_HTTP01_IMAGE" "$RUN_LOG"' "$path" \
      || die "${script} never removes the image it built; \`down\` removes containers, never images"
  done
  # One tag per instance, and a tag Docker will accept: the instance
  # alphabet is a subset of what a tag may hold, so this holds as long as
  # the two derivations stay in step.
  first="$(run_scope_http01_image "e2e-local-a4242")"
  second="$(run_scope_http01_image "e2e-local-a4243")"
  [ "$first" != "$second" ] \
    || die "two instances derived the same responder image tag '${first}'"
  case "${first#*:}" in
    [a-zA-Z0-9_]*) ;;
    *) die "the derived image tag '${first}' does not start with a character a Docker tag may open with" ;;
  esac
  case "${first#*:}" in
    *[!a-zA-Z0-9._-]*) die "the derived image tag '${first}' holds a character outside [a-zA-Z0-9._-]" ;;
  esac
  ok "the responder image is one tag per run, derived from the instance and removed with it"
}

# Both harnesses have to take the lock before their first edit and let
# it go after their last one, and neither may name a lock of its own:
# they add the same two host names, so a local run and a remote run
# overwrite each other exactly as two local runs would.
check_hosts_mode_is_serialised_in_the_harnesses() {
  local script path body acquire_line add_line held_line edit_line release_line offenders
  for script in "${LIFECYCLE_SCRIPTS[@]}"; do
    path="$IMPL_DIR/$script"
    ! grep -q 'BOOTROOT_E2E_HOSTS_LOCK=' "$path" \
      || die "${script} names a hosts lock of its own; both scripts edit the same two entries, so there is one lock"

    body="$(awk '/^configure_resolution_mode\(\) \{$/ { inside = 1; next }
      inside && $0 == "}" { inside = 0 }
      inside { print }' "$path")"
    acquire_line="$(grep -n 'acquire_hosts_lock ' <<<"$body" | head -n 1 | cut -d: -f1)"
    add_line="$(grep -n 'add_hosts_entry ' <<<"$body" | head -n 1 | cut -d: -f1)"
    [ -n "$add_line" ] \
      || die "${script}: configure_resolution_mode no longer adds the /etc/hosts entries this check is about"
    [ -n "$acquire_line" ] \
      || die "${script} edits /etc/hosts without taking the lock that keeps hosts mode serialised"
    [ "$acquire_line" -lt "$add_line" ] \
      || die "${script} takes the hosts lock after it has already edited /etc/hosts"

    body="$(awk '/^cleanup_hosts\(\) \{$/ { inside = 1; next }
      inside && $0 == "}" { inside = 0 }
      inside { print }' "$path")"
    held_line="$(grep -n 'hosts_lock_held' <<<"$body" | head -n 1 | cut -d: -f1)"
    edit_line="$(grep -n 'run_sudo ' <<<"$body" | head -n 1 | cut -d: -f1)"
    release_line="$(grep -n 'release_hosts_lock' <<<"$body" | head -n 1 | cut -d: -f1)"
    [ -n "$edit_line" ] \
      || die "${script}: cleanup_hosts no longer rewrites /etc/hosts"
    [ -n "$held_line" ] && [ -n "$release_line" ] \
      || die "${script}: cleanup_hosts neither checks that it holds the hosts lock nor releases it"
    # The rewrite drops every line carrying this script's fixed marker,
    # so it cannot tell one run's entries from another's: a run refused
    # at the lock would take the live holder's with it.
    [ "$held_line" -lt "$edit_line" ] \
      || die "${script}: cleanup_hosts rewrites /etc/hosts before checking whether this run holds the lock"
    # And the release comes after that rewrite, or the next run adds its
    # entries while this one's are still there — which `add_hosts_entry`
    # reads as nothing to do.
    [ "$release_line" -gt "$edit_line" ] \
      || die "${script}: cleanup_hosts releases the hosts lock before it has removed this run's entries"

    # The lock lives on an open file descriptor, which every child
    # inherits. A daemon that inherited it and outlived a killed run
    # would go on holding it — hosts mode refused on that host for as
    # long as that process ran, which is precisely the stale lock this
    # design does not otherwise have. So every process a harness leaves
    # running behind it closes fd 9.
    offenders="$(grep -nE '^[^#]*[^&]& *$' "$path" | grep -v '9>&-' || true)"
    [ -z "$offenders" ] \
      || die "${script} starts a background process without closing the hosts-lock descriptor (9>&-): ${offenders//$'\n'/; }"
  done
  ok "both harnesses serialise hosts mode on one lock, taken before the first edit, released after the last, and never inherited by a daemon"
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
check_instance_and_project_are_derived_separately
check_harness_namespaces_are_declared
check_no_namespace_can_name_the_default_identity
check_project_derivation_rejects_what_compose_would
check_truncation_keeps_the_discriminating_tail
check_derivation_rejects_what_it_cannot_derive
check_the_binary_ranks_the_override_above_the_flag
check_markers
check_marker_dir_refuses_a_symlink
check_default_marker_dir_is_per_user
install_hosts_lock_helpers
check_hosts_lock
check_hosts_lock_dies_with_the_run
check_hosts_lock_is_the_kernels
check_hosts_lock_needs_no_write_access
check_hosts_lock_backends
check_hosts_lock_creates_nothing
check_default_hosts_lock_is_the_file_it_protects
check_liveness
install_docker_stub
check_sweep_collects_only_dead_runs
check_sweep_refuses_a_marker_outside_the_derived_namespaces
check_marker_write_refuses_an_undeclared_pair
check_sweep_keeps_a_marker_it_could_not_clear
check_harness_wiring
check_responder_image_is_run_scoped
check_hosts_mode_is_serialised_in_the_harnesses
check_marker_removal_is_last
check_no_hardcoded_identity

echo "[$LABEL] OK: the per-run E2E identity holds"
