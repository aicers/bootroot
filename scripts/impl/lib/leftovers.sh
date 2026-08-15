# shellcheck shell=bash
# Shared teardown assertions for the Docker E2E harness.
#
# A `docker compose down` that removed nothing is indistinguishable from
# one that removed everything: it is best-effort by design, and it used
# to send every byte to `/dev/null`.  A run killed with `SIGKILL` never
# reaches its teardown at all, and the containers bootroot creates are
# named after the install identity rather than after the Compose
# project, so they collide with the next run's on `up` whichever project
# either run used.
#
# The checks here are what turn both into a message at the point the
# harness can still say something useful.  There are two, and which one
# a script wants follows from the identity it installs at:
#
#   * `assert_no_leftover_containers` / `report_leftover_containers`
#     check for the exact container names bootroot creates at the
#     identity recorded beside a compose file.  Every harness that
#     installs at the default identity uses these.  Exact names, never a
#     `bootroot-*` wildcard: a wildcard would reach past the run's own
#     containers and into a co-located install's.
#
#   * `assert_no_project_leftovers` / `report_project_leftovers` check
#     containers and volumes by `com.docker.compose.project` label.
#     `run-two-instance-isolation.sh` uses these, being the one harness
#     that installs under run-scoped instance names of its own, whose
#     containers are therefore not named `bootroot-*` at all.
#
# Callers must define `fail`, which aborts the harness with a message;
# `assert_no_project_leftovers` additionally needs `pass`, which reports
# a satisfied assertion.
#
# A query that could not run is never read as a clean host.  Every check
# below distinguishes "the daemon holds none of these" from "the daemon
# could not be asked", and treats the second as a failure of the check
# itself: a stopped daemon, a socket the run cannot reach, or a refused
# authorization would otherwise pass the startup assertion, hide behind
# the start-of-run teardown's deliberate `|| true`, and surface as the
# confusing mid-run failure all of this exists to replace.  Docker's own
# diagnostics are left on stderr, where the harness's log picks them up
# alongside the message saying which check could not run.
#
# The start-of-run assertion runs *before* the start-of-run teardown,
# and before anything else that could remove a container.  A harness
# tears down with `down -v --remove-orphans` at the Compose project it
# was given, which for a default-identity harness is the same project a
# real install on this host holds; running it first would delete that
# install, volumes and all, and leave the assertion looking at a daemon
# it had just cleaned.  The one case the reversed order would have
# handled silently — a killed run's leftovers under the project this run
# happens to use — is precisely the one the assertion exists to report,
# because nothing can tell those apart from an install.  The teardown
# still follows, for the volumes, networks and orphans the assertion
# does not look at.
#
# Which side of that assertion a harness is on is what `mark_stack_owned`
# records.  Until it is called, the harness has taken nothing over, and
# its EXIT trap must not tear anything down: a startup assertion that
# aborted because a real install is here would otherwise have `cleanup`
# remove on the way out exactly what it refused to touch on the way in.
#
# The end-of-run half is deliberately split into `report_*` functions
# that print and return non-zero rather than aborting, so an EXIT trap
# can fold the result into the status the run already carried:
#
#   cleanup() {
#     local status=$?
#     local teardown_status=0
#     capture_artifacts
#     if stack_owned; then
#       compose_down || teardown_status=1
#       report_leftover_containers "$COMPOSE_FILE" cleanup || teardown_status=1
#     fi
#     exit_with_cleanup_status "$status" "$teardown_status"
#   }
#
# A harness that leaves its own garbage behind is broken and has to
# fail, but it must not overwrite the failure that ended the run — that
# one is the more useful reason to report.

# Identity an install takes when it declares none —
# `DEFAULT_INSTANCE_NAME` in `src/commands/compose_project.rs`.
BOOTROOT_DEFAULT_INSTANCE_NAME="bootroot"

# The suffix bootroot appends to the install identity, one per container
# it creates.  The set mirrors `BootrootContainer::ALL` in
# `src/commands/container_name.rs`; a container added there and not here
# would escape every check below.
BOOTROOT_CONTAINER_SUFFIXES=(
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

# Returns the directory a compose file's `.env` sits in.
#
# Mirrors `compose_file_dir` in `src/commands/compose_file.rs`, down to
# a bare filename resolving to `.` rather than to an empty path.
compose_file_dir() {
  local compose_file="$1" dir
  dir="$(dirname "$compose_file")"
  [ -n "$dir" ] || dir="."
  printf '%s\n' "$dir"
}

# Prints the value one `.env` key holds, the way `read_dotenv`
# (`src/commands/dotenv.rs`) reads it: blank and `#` lines skipped, the
# split on the *first* `=`, key and value trimmed, one layer of matching
# surrounding quotes stripped, and the last assignment winning.
#
# Exits 2 on a line carrying no `=`, where `read_dotenv` errors rather
# than reading the file as recording nothing: a `.env` bootroot itself
# will refuse to parse must not resolve here to the default identity and
# have the check look at the wrong container names.
dotenv_lookup() {
  local file="$1" key="$2"
  awk -v want="$key" -v squote="'" '
    {
      line = $0
      sub(/^[ \t\r]+/, "", line)
      sub(/[ \t\r]+$/, "", line)
      if (line == "" || substr(line, 1, 1) == "#") next
      eq = index(line, "=")
      if (eq == 0) { malformed = 1; exit 2 }
      name = substr(line, 1, eq - 1)
      value = substr(line, eq + 1)
      sub(/^[ \t\r]+/, "", name)
      sub(/[ \t\r]+$/, "", name)
      sub(/^[ \t\r]+/, "", value)
      sub(/[ \t\r]+$/, "", value)
      if (length(value) >= 2) {
        first = substr(value, 1, 1)
        last = substr(value, length(value), 1)
        if ((first == "\"" && last == "\"") || (first == squote && last == squote)) {
          value = substr(value, 2, length(value) - 2)
        }
      }
      if (name == want) { found = 1; result = value }
    }
    END { if (!malformed && found) print result }
  ' "$file"
}

# Prints the instance name every container bootroot creates is named
# after, for the install the given compose file belongs to.
#
# Resolved as `resolve_recorded_instance_name`
# (`src/commands/compose_project.rs`) resolves it, in the same order:
# the `--instance-name` the install was given, passed here as the
# optional second argument and empty where there was none, then
# `BOOTROOT_INSTANCE` as recorded in the compose directory's `.env`,
# then the default identity.
#
# The two lifecycle harnesses pass their derived `--instance-name` here;
# every other one installs at the default identity and leaves the
# argument empty.  Without the precedence a harness taking an instance
# name would have the check read the identity of an install it did not
# make, and pass on a host carrying exactly the leftovers it exists to
# report.  The wiring is enforced from the other side too:
# `validate-e2e-leftover-check.sh` fails a harness that passes
# `--instance-name` without handing the same value to the checks.
#
# Deliberately not `${BOOTROOT_INSTANCE:-bootroot}` out of the invoking
# environment.  That expansion gives the right answer only for a harness
# running at the default identity, and an explicit name belongs to the
# install invocation carrying it, not to whatever the invoking shell
# happened to export.
# `COMPOSE_PROJECT_NAME` is not consulted at all: it selects a project
# for one invocation and is not an identity, and the harness sets it to
# values that are not valid instance names.
#
# Returns non-zero, printing nothing, when the `.env` cannot be parsed.
resolve_recorded_instance_name() {
  local compose_dir="$1" explicit="${2:-}" env_file recorded
  if [ -n "$explicit" ]; then
    printf '%s\n' "$explicit"
    return 0
  fi
  env_file="$compose_dir/.env"
  if [ -f "$env_file" ]; then
    recorded="$(dotenv_lookup "$env_file" BOOTROOT_INSTANCE)" || return 1
    if [ -n "$recorded" ]; then
      printf '%s\n' "$recorded"
      return 0
    fi
  fi
  printf '%s\n' "$BOOTROOT_DEFAULT_INSTANCE_NAME"
}

# Prints the name of every container this daemon holds, one per line.
#
# One listing rather than a `docker container inspect` per name, because
# an inspect cannot say which of the two answers it gave: a container
# that is absent and a daemon that could not be reached both come back
# non-zero, so a per-name check reads an unreachable daemon as a clean
# host.  A listing separates them — the names on stdout are the answer,
# and a non-zero status means there was none.
#
# Not `docker ps --filter name=` either: that filter matches substrings,
# and the whole point of the check is that it is exact.  The names are
# matched here instead, in full.  `{{.Names}}` joins the names of a
# container that carries more than one with commas, so they are split
# back apart.
docker_container_names() {
  local listed
  listed="$(docker ps -a --format '{{.Names}}')" || return 1
  printf '%s\n' "$listed" | tr ',' '\n'
}

# Prints every container bootroot creates at `instance`, one per line,
# that exists on this daemon right now.
#
# Returns non-zero, printing nothing, when the daemon could not be
# asked.
bootroot_leftover_containers() {
  local instance="$1" listed suffix name
  listed="$(docker_container_names)" || return 1
  listed=$'\n'"${listed}"$'\n'
  for suffix in "${BOOTROOT_CONTAINER_SUFFIXES[@]}"; do
    name="${instance}${suffix}"
    case "$listed" in
      *$'\n'"$name"$'\n'*) printf '%s\n' "$name" ;;
    esac
  done
  return 0
}

# Prints the leftover containers as one space-separated line, and
# returns non-zero when the daemon could not be asked.
_bootroot_leftovers_line() {
  local names
  names="$(bootroot_leftover_containers "$1")" || return 1
  printf '%s\n' "$names" | tr '\n' ' ' | sed 's/[[:space:]]*$//'
}

# Whether the harness has taken the stack over.
#
# A default-identity harness shares its Compose project, and every
# container name it uses, with any real install on the host.  Nothing it
# runs may remove a container until the startup assertion has said there
# was none to begin with — which is exactly what this records.
BOOTROOT_STACK_OWNED=0

# Declares the stack the harness's to remove, from here to the end of
# the run.  Called once, immediately after the startup assertion passes.
mark_stack_owned() {
  BOOTROOT_STACK_OWNED=1
}

# True once `mark_stack_owned` has run.  An EXIT trap firing before that
# must leave every container on the host alone: the run created none, and
# what is here is someone else's.
stack_owned() {
  [ "${BOOTROOT_STACK_OWNED:-0}" -eq 1 ]
}

# Aborts the run when any container bootroot creates at the resolved
# identity already exists.
#
# Called at the start of a run, before the start-of-run teardown and
# before anything else that could remove a container: what is here is
# either a killed run's leftovers, whose Compose project no later run
# knows to ask about, or a real install on this host, and the two are
# indistinguishable to anything but the operator.  Either way the run
# cannot proceed — container names are global to the daemon, so `up`
# would collide — and failing here costs a message instead of a
# confusing failure twenty minutes in, or a deleted install.
#
# The optional third argument is the `--instance-name` the harness
# installs at, empty where it declares none.
assert_no_leftover_containers() {
  local compose_file="$1" label="$2" explicit="${3:-}" compose_dir instance leftovers
  compose_dir="$(compose_file_dir "$compose_file")"
  if ! instance="$(resolve_recorded_instance_name "$compose_dir" "$explicit")"; then
    fail "cannot read the instance name from ${compose_dir}/.env; it records the identity every bootroot container is named after"
  fi
  if ! leftovers="$(_bootroot_leftovers_line "$instance")"; then
    fail "[${label}] cannot list this daemon's containers, so whether a bootroot install at instance name '${instance}' is already here is unknown; see the docker error above"
  fi
  [ -n "$leftovers" ] || return 0
  fail "$(printf '%s\n%s\n%s\n%s\n  docker rm -f %s' \
    "[${label}] containers of a bootroot install at instance name '${instance}' are already present:" \
    "  ${leftovers}" \
    "They are either what an E2E run killed before its teardown left behind, or a real bootroot install on this host." \
    "This harness installs at that same identity and cannot run beside either, so remove them once you have established which:" \
    "${leftovers}")"
}

# Reports containers surviving the end-of-run teardown, without
# aborting.
#
# Returns non-zero when there are any, so an EXIT trap can fold that
# into its status rather than exiting from inside itself and dropping
# the reason the run failed.
#
# Takes the same optional explicit instance name its start-of-run
# counterpart does, and has to be given the same value: a run that
# checked one identity on the way in and another on the way out would
# report neither.
report_leftover_containers() {
  local compose_file="$1" label="$2" explicit="${3:-}" compose_dir instance leftovers
  compose_dir="$(compose_file_dir "$compose_file")"
  if ! instance="$(resolve_recorded_instance_name "$compose_dir" "$explicit")"; then
    echo "[${label}] cannot read the instance name from ${compose_dir}/.env; leftover containers were not checked for" >&2
    return 1
  fi
  if ! leftovers="$(_bootroot_leftovers_line "$instance")"; then
    echo "[${label}] cannot list this daemon's containers, so what the teardown left behind at instance name '${instance}' was not checked; see the docker error above" >&2
    return 1
  fi
  [ -n "$leftovers" ] || return 0
  echo "[${label}] the teardown left containers behind at instance name '${instance}': ${leftovers}" >&2
  echo "[${label}] remove them with: docker rm -f ${leftovers}" >&2
  return 1
}

# Prints the id of every container labelled with `project`, and returns
# non-zero, printing nothing, when the daemon could not be asked.
#
# Neither this nor `project_volume_ids` swallows that status.  An empty
# list is the answer the caller acts on, and a query that failed
# produces one too — which is how an unreachable daemon used to read
# here as a teardown that had removed everything it owned.
project_container_ids() {
  docker ps -aq --filter "label=com.docker.compose.project=$1"
}

# Prints the name of every volume labelled with `project`, and returns
# non-zero, printing nothing, when the daemon could not be asked.
project_volume_ids() {
  docker volume ls -q --filter "label=com.docker.compose.project=$1"
}

# Aborts the run when a container or volume of `project` survived the
# teardown named by `label`, or when the daemon could not be asked.
#
# The label-scoped counterpart of `assert_no_leftover_containers`, for
# the harness whose instance names are its own rather than the default
# identity's.  Reports the two resource kinds separately, so a failure
# names which survived.
assert_no_project_leftovers() {
  local project="$1" label="$2" leftovers
  if ! leftovers="$(project_container_ids "$project")"; then
    fail "cannot list containers of project ${project}, so what ${label} left behind is unknown; see the docker error above"
  fi
  [ -z "$leftovers" ] || fail "containers of project ${project} survived ${label}"
  if ! leftovers="$(project_volume_ids "$project")"; then
    fail "cannot list volumes of project ${project}, so what ${label} left behind is unknown; see the docker error above"
  fi
  [ -z "$leftovers" ] || fail "volumes of project ${project} survived ${label}"
  pass "no container or volume of project ${project} survived ${label}"
}

# Reports containers or volumes of `project` surviving the end-of-run
# teardown, without aborting.  Returns non-zero when there are any, and
# when either query could not be run.
#
# Both queries are attempted whichever fails: a run whose daemon went
# away wants to be told about the volumes as well as the containers.
report_project_leftovers() {
  local project="$1" label="$2" containers="" volumes="" status=0
  if ! containers="$(project_container_ids "$project")"; then
    echo "[${label}] cannot list containers of project ${project}; leftovers were not checked for, see the docker error above" >&2
    containers=""
    status=1
  fi
  if ! volumes="$(project_volume_ids "$project")"; then
    echo "[${label}] cannot list volumes of project ${project}; leftovers were not checked for, see the docker error above" >&2
    volumes=""
    status=1
  fi
  if [ -n "${containers}${volumes}" ]; then
    echo "[${label}] leftovers survived for project ${project}" >&2
    status=1
  fi
  return "$status"
}

# Ends an EXIT trap with the status the run must carry.
#
# `entry_status` is `$?` as captured on the trap's first line, before
# anything the trap itself runs can overwrite it.  A failed teardown or
# leftover check turns a run that had passed into a failure; where the
# run had already failed, that original status is what the harness exits
# with, because what ended the run is a more useful reason than the
# garbage it then failed to clear.
exit_with_cleanup_status() {
  local entry_status="$1" cleanup_status="$2"
  if [ "$entry_status" -ne 0 ]; then
    exit "$entry_status"
  fi
  exit "$cleanup_status"
}
